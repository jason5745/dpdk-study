/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <assert.h>
#include <getopt.h>
#include <signal.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include "dhcp.h"
#include "eth.h"


#define RING_SIZE			512
#define NUM_MBUFS 			8192 
#define MBUF_CACHE_SIZE		0
#define BURST_SIZE			1024


#define ARP_TABLE_SIZE		10

struct arp_info
{
	uint64_t timestamp;
	in_addr_t ipv4;
	struct rte_ether_addr mac;
};

struct eth_info
{
	uint32_t eth_id;
	in_addr_t eth_ipv4;
	struct rte_ether_addr eth_mac;
	struct arp_info arp_table[ARP_TABLE_SIZE];
	dhcp_client_t dhcp_client;
};

struct eth_info_list{
	uint16_t nb_items;
	uint16_t zero;
	struct eth_info *items;
};

static void port_init(struct rte_mempool *mbuf_pool,struct eth_info_list* eth_list) {
	static const struct rte_eth_conf port_conf_default;
	eth_list->nb_items  = rte_eth_dev_count_avail();
	if (eth_list->nb_items == 0) {
		rte_exit(EXIT_FAILURE,"No Support eth found\n");
	}

	eth_list->items = calloc(sizeof(struct eth_info *),eth_list->nb_items);
	if (!eth_list->items) {
		rte_exit(EXIT_FAILURE,"No Mem calloc\n");
	}

	for (int i = 0;i < eth_list->nb_items;i++) {
		const int num_rx_queues = 1;
		const int num_tx_queues = 1;

		eth_list->items[i].eth_id = i;
		rte_eth_macaddr_get(i,&eth_list->items[i].eth_mac);

		if (0 > rte_eth_dev_configure(i,num_rx_queues,num_tx_queues,&port_conf_default)) {
			rte_exit(EXIT_FAILURE,"rte_eth_dev_configure(): Failed\n");
		}
		if (0 > rte_eth_rx_queue_setup(i,0,RING_SIZE,rte_eth_dev_socket_id(i), NULL, mbuf_pool)) {
			rte_exit(EXIT_FAILURE,"rte_eth_rx_queue_setup(): Failed\n");
		}
		if (0 > rte_eth_tx_queue_setup(i,0,RING_SIZE,rte_eth_dev_socket_id(i), NULL)) {
			rte_exit(EXIT_FAILURE,"rte_eth_tx_queue_setup(): Failed\n");
		}
		if (0 > rte_eth_dev_start(i)) {
			rte_exit(EXIT_FAILURE,"rte_eth_dev_start(): Failed\n");
		}
	}
}

static void mbuf_icmp_pkt(struct rte_mbuf *mbuf, uint32_t dip,uint32_t sip, 
												uint16_t id, uint16_t seqnb) 
{
	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	struct rte_ether_addr tmp;
	rte_ether_addr_copy(&eth->src_addr, &tmp);
	rte_ether_addr_copy(&eth->dst_addr, &eth->src_addr);
	rte_ether_addr_copy(&tmp, &eth->dst_addr);

	// 2 ip
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
	ip->src_addr = sip;
	ip->dst_addr = dip;

	// ip->hdr_checksum = 0;
	// ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 icmp
	struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(ip + 1);

	uint16_t cksum = 0;
	icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
	cksum = ~icmp->icmp_cksum & 0xffff;
	cksum += ~RTE_BE16(RTE_IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
	cksum += RTE_BE16(RTE_IP_ICMP_ECHO_REPLY << 8);
	cksum = (cksum & 0xffff) + (cksum >> 16);
	cksum = (cksum & 0xffff) + (cksum >> 16);
	icmp->icmp_cksum = ~cksum;
	icmp->icmp_cksum = icmp->icmp_cksum - 0x01;
	return;
}

static void mbuf_arp_pkt(struct rte_mbuf *mbuf,struct rte_ether_addr *dst_mac, uint32_t dip,struct rte_ether_addr *src_mac,uint32_t sip) {
	struct rte_ether_hdr *eth_h = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	rte_ether_addr_copy(dst_mac,&eth_h->dst_addr);
	rte_ether_addr_copy(src_mac,&eth_h->src_addr);

	eth_h->ether_type = htons(RTE_ETHER_TYPE_ARP);

	// 2 arp 
	struct rte_arp_hdr *arp_h = (struct rte_arp_hdr *)(eth_h + 1);
	arp_h->arp_hardware = htons(1);
	arp_h->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp_h->arp_hlen = RTE_ETHER_ADDR_LEN;
	arp_h->arp_plen = sizeof(uint32_t);
	arp_h->arp_opcode = htons(2);

	rte_ether_addr_copy(&eth_h->src_addr, &arp_h->arp_data.arp_sha);
	rte_ether_addr_copy(&eth_h->dst_addr, &arp_h->arp_data.arp_tha);

	arp_h->arp_data.arp_sip = sip;
	arp_h->arp_data.arp_tip = dip;
}

inline
static void mbuf_ether_pkt(struct rte_mbuf *mbuf,struct rte_ether_addr *src,struct rte_ether_addr *dst,uint16_t type) {
	struct rte_ether_hdr *eth_h = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	rte_ether_addr_copy(src, &eth_h->src_addr);
	rte_ether_addr_copy(dst, &eth_h->dst_addr);
	eth_h->ether_type = rte_cpu_to_be_16(type);
}

inline
static void mbuf_ipv4_pkt(struct rte_mbuf *mbuf,uint32_t src,uint32_t dst,uint8_t proto_id,uint16_t payload_len) {
	struct rte_ipv4_hdr *ipv4_h = rte_pktmbuf_mtod_offset(mbuf,struct rte_ipv4_hdr *,sizeof(struct rte_ether_hdr));
	ipv4_h->version_ihl = 0x45;
	ipv4_h->src_addr = rte_cpu_to_be_32(src);
	ipv4_h->dst_addr = rte_cpu_to_be_32(dst);
	ipv4_h->time_to_live = 64;
	ipv4_h->next_proto_id = proto_id;
	ipv4_h->fragment_offset = rte_cpu_to_be_16(0x4000);
	ipv4_h->total_length = rte_cpu_to_be_16(payload_len + sizeof(struct rte_ipv4_hdr));
	ipv4_h->hdr_checksum = 0;
	ipv4_h->hdr_checksum = rte_ipv4_cksum(ipv4_h);

	mbuf->pkt_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + payload_len;
	mbuf->data_len = mbuf->pkt_len;
}
inline
static void mbuf_udp_pkt(struct rte_mbuf *mbuf,uint16_t src_port,uint16_t dst_port) {
	struct rte_udp_hdr *udp_h = rte_pktmbuf_mtod_offset(mbuf,struct rte_udp_hdr *,sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	udp_h->dst_port = rte_cpu_to_be_16(src_port);
	udp_h->src_port = rte_cpu_to_be_16(dst_port);
	struct rte_ipv4_hdr *ipv4_h = rte_pktmbuf_mtod_offset(mbuf,struct rte_ipv4_hdr *,sizeof(struct rte_ether_hdr));
	udp_h->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_h,udp_h);
	return;
}

inline
static void mbuf_udp_pkt_final(struct rte_mbuf *mbuf) {
	
}


static void dhcp_client_update_eth_info(dhcp_client_t *client,void *arg) {
	struct eth_info *eth = arg;
	if (eth) {
		eth->eth_ipv4 = client->client;
		struct in_addr ip;
        ip.s_addr = eth->eth_ipv4;
	    printf("dhcp_client->client: %s\n",inet_ntoa(ip));
	}
}

int main(int argc, char **argv)
{
	//必要步骤
	if (rte_eal_init(argc,argv) < 0) {
		rte_exit(EXIT_FAILURE,"rte_eal_init(): Failed\n");
	}
	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
		NUM_MBUFS,MBUF_CACHE_SIZE,0,RTE_MBUF_DEFAULT_BUF_SIZE,rte_socket_id());
	if (!mbuf_pool) {
		rte_exit(EXIT_FAILURE,"rte_pktmbuf_pool_create(): Failed\n");
	}
	struct eth_info_list eth_list;
	port_init(mbuf_pool,&eth_list);
	eth_list.items[0].eth_ipv4 = inet_addr("192.168.0.105");
	eth_list.items[1].eth_ipv4 = inet_addr("192.168.0.104");

	dhcp_client_init(&eth_list.items[0].dhcp_client,
					eth_list.items[0].eth_ipv4,eth_list.items[0].eth_mac,
					dhcp_client_update_eth_info,&eth_list.items[0]);
	
	dhcp_client_init(&eth_list.items[1].dhcp_client,
					eth_list.items[1].eth_ipv4,eth_list.items[1].eth_mac,
					dhcp_client_update_eth_info,&eth_list.items[1]);
	

	while (1)
	{
		struct rte_mbuf *mbufs[BURST_SIZE];
		for (int i = 0;i < eth_list.nb_items;i++) {
			struct eth_info *eth = &eth_list.items[i];

			dhcp_client_loop(&eth->dhcp_client,mbuf_pool,eth->eth_id);

			unsigned recved = rte_eth_rx_burst(i,0,mbufs,BURST_SIZE);
			for (unsigned j = 0;j < recved; j++) {
				struct rte_mbuf *mbuf = mbufs[j];
				struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbuf,struct rte_ether_hdr *);
				if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
					struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbuf,struct rte_ipv4_hdr *,sizeof(struct rte_ether_hdr));
					if (iphdr->next_proto_id == IPPROTO_UDP) {
						struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
						if (rte_be_to_cpu_16(udphdr->dst_port) == 68) {
							dhcp_client_recv(&eth->dhcp_client,udphdr);
						}
					} else if (iphdr->next_proto_id == IPPROTO_ICMP) {
						struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);
						if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
							mbuf_icmp_pkt(mbuf,iphdr->src_addr,iphdr->dst_addr,
											icmphdr->icmp_ident, icmphdr->icmp_seq_nb);
							rte_eth_tx_burst(i, 0, &mbuf, 1);
						}
					} else if (iphdr->next_proto_id == IPPROTO_TCP) {

					}
				} else if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
					struct rte_arp_hdr *arphdr = rte_pktmbuf_mtod_offset(mbuf,struct rte_arp_hdr *,sizeof(struct rte_ether_hdr));
					if (arphdr->arp_data.arp_tip == eth_list.items[i].eth_ipv4) {						//如果请求的是自己
						mbuf_arp_pkt(mbuf,
							&arphdr->arp_data.arp_sha,arphdr->arp_data.arp_sip,
							&eth_list.items[i].eth_mac,eth_list.items[i].eth_ipv4);
						rte_eth_tx_burst(i, 0, &mbuf, 1);
					}
				}
				rte_pktmbuf_free(mbuf);
			}
		}
	}
	return 0;
}