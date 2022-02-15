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
	int eth_id;
	in_addr_t eth_ipv4;
	struct rte_ether_addr eth_mac;
	struct arp_info arp_table[ARP_TABLE_SIZE];

};

struct dhcp_hdr
{
	uint8_t mtype;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	in_addr_t cipv4;
	in_addr_t yipv4;
	in_addr_t nipv4;
	in_addr_t ripv4;
	uint8_t cmac[16];
	uint8_t sname[64];
	uint8_t file[128];
	uint32_t magic_cookie;
};

struct eth_info_list{
	uint16_t nb_items;
	uint16_t zero;
	struct eth_info *items;
};

const struct rte_ether_addr broadcast_mac = {.addr_bytes = {0xff,0xff,0xff,0xff,0xff,0xff}};

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
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
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


static int
fill_dhcp_option(uint8_t *packet, uint8_t code, uint8_t *data, uint8_t len)
{
    packet[0] = code;
    packet[1] = len;
    memcpy(&packet[2], data, len);

    return len + (sizeof(uint8_t) * 2);
}

static void mbuf_dhcp_pkt_discover(struct rte_mbuf *mbuf,struct eth_info *eth) {
	struct rte_ether_hdr *eth_h = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	rte_ether_addr_copy(&eth->eth_mac, &eth_h->src_addr);
	rte_ether_addr_copy(&broadcast_mac, &eth_h->dst_addr);
	eth_h->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	struct rte_ipv4_hdr *ipv4_h = (struct rte_ipv4_hdr *)(eth_h + 1);
	ipv4_h->version_ihl = 0x45;
	ipv4_h->src_addr = 0;
	ipv4_h->dst_addr = 0xFFFFFFFF;
	ipv4_h->time_to_live = 64;
	ipv4_h->next_proto_id = IPPROTO_UDP;
	ipv4_h->fragment_offset = 0;
	
	struct rte_udp_hdr *udp_h = (struct rte_udp_hdr *)(ipv4_h + 1);	
	udp_h->src_port = rte_cpu_to_be_16(68);
	udp_h->dst_port = rte_cpu_to_be_16(67);

	struct dhcp_hdr *dhcp_h = (struct dhcp_hdr *)(udp_h + 1);
	dhcp_h->mtype = 1;
	dhcp_h->htype = 1;
	dhcp_h->hlen = 6;
	dhcp_h->hops = 0;
	dhcp_h->flags = rte_cpu_to_be_16(0x8000);
	dhcp_h->cipv4 = 0;
	dhcp_h->yipv4 = eth->eth_ipv4;
	dhcp_h->nipv4 = 0;
	dhcp_h->ripv4 = 0;
	rte_memcpy(dhcp_h->cmac,eth->eth_mac.addr_bytes,6);
	dhcp_h->xid = rte_cpu_to_be_32(0x5F5E000);
	dhcp_h->secs = rte_cpu_to_be_16(0);
	dhcp_h->magic_cookie = rte_cpu_to_be_32(0x63825363);

	uint8_t *packet = (uint8_t *)(dhcp_h + 1);
	uint8_t discover = 1;
	uint8_t parameter_request_list[8] = {1,3,6,12,15,28,42,121};
	uint8_t *identifler = "dhcp";
	uint8_t *hostname = "DPDK Demo";
	int len = 0;
	len += fill_dhcp_option(&packet[len],53,&discover,1);
	// len += fill_dhcp_option(&packet[len],55,parameter_request_list,8);
	// len += fill_dhcp_option(&packet[len],60,identifler,strlen(identifler));
	// len += fill_dhcp_option(&packet[len],12,hostname,strlen(hostname));
	packet[len++] = 0xff;

	ipv4_h->hdr_checksum = 0;
	ipv4_h->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(struct dhcp_hdr) + len);
	ipv4_h->hdr_checksum = rte_ipv4_cksum(ipv4_h);

	udp_h->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + sizeof(struct dhcp_hdr) + len);
	udp_h->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_h,udp_h);
	mbuf->pkt_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(struct dhcp_hdr) + len;
	mbuf->data_len = mbuf->pkt_len;
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
	eth_list.items[0].eth_ipv4 = inet_addr("192.168.100.206");
	eth_list.items[1].eth_ipv4 = inet_addr("192.168.199.181");

	struct rte_mbuf *dhcp_mbuf =  rte_pktmbuf_alloc(mbuf_pool);
	mbuf_dhcp_pkt_discover(dhcp_mbuf,&eth_list.items[0]);
	rte_eth_tx_burst(eth_list.items[0].eth_id, 0, &dhcp_mbuf, 1);
	rte_pktmbuf_free(dhcp_mbuf);

	while (1)
	{
		struct rte_mbuf *mbufs[BURST_SIZE];
		for (int i = 0;i < eth_list.nb_items;i++) {
			if (!eth_list.items[i].eth_ipv4) {

			}
			unsigned recved = rte_eth_rx_burst(i,0,mbufs,BURST_SIZE);
			for (unsigned j = 0;j < recved; j++) {
				struct rte_mbuf *mbuf = mbufs[j];
				struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbuf,struct rte_ether_hdr *);
				if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
					struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbuf,struct rte_ipv4_hdr *,sizeof(struct rte_ether_hdr));
					if (iphdr->next_proto_id == IPPROTO_UDP) {
						struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
						uint16_t length = ntohs(udphdr->dgram_len);
						if (rte_be_to_cpu_16(udphdr->dst_port) == 68) {
							printf("udp: %u->%u\n",ntohs(udphdr->src_port),ntohs(udphdr->dst_port));
							for (int z = 0;z < length;z++) {
								printf("%02x ",((uint8_t *)(udphdr + 1))[z]);
							}
							printf("\n");
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