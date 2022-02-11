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

const int gDpdkPortId = 0;
static void port_init(struct rte_mempool *mbuf_pool) {
	static const struct rte_eth_conf port_conf_default;
	uint16_t nb_sys_ports  = rte_eth_dev_count_avail();
	if (nb_sys_ports == 0) {
		rte_exit(EXIT_FAILURE,"No Support eth found\n");
	}

	const int num_rx_queues = 1;
	const int num_tx_queues = 1;
	if (0 > rte_eth_dev_configure(gDpdkPortId,num_rx_queues,num_tx_queues,&port_conf_default)) {
		rte_exit(EXIT_FAILURE,"rte_eth_dev_configure(): Failed\n");
	}
	if (0 > rte_eth_rx_queue_setup(gDpdkPortId,0,RING_SIZE,rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool)) {
		rte_exit(EXIT_FAILURE,"rte_eth_rx_queue_setup(): Failed\n");
	}
	if (0 > rte_eth_tx_queue_setup(gDpdkPortId,0,RING_SIZE,rte_eth_dev_socket_id(gDpdkPortId), NULL)) {
		rte_exit(EXIT_FAILURE,"rte_eth_tx_queue_setup(): Failed\n");
	}
	if (0 > rte_eth_dev_start(gDpdkPortId)) {
		rte_exit(EXIT_FAILURE,"rte_eth_dev_start(): Failed\n");
	}
}

static uint16_t checksum_16(uint16_t *addr, int count)
{
    uint32_t cksum=0;
    while(count>1)
    {
        cksum+=*addr++;
        count-=sizeof(uint16_t);
    }
    if(count)
    {
        cksum+=*(uint16_t*)addr;
    }
    cksum=(cksum>>16)+(cksum&0xffff);
    return(uint16_t)(~cksum);
}

static struct rte_mbuf *rebuild_icmp_pkt(struct rte_mbuf *mbuf, uint32_t dip,uint32_t sip, 
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
	return mbuf;
}

static struct rte_mbuf *create_arp_response(struct rte_mempool *mbuf_pool, uint8_t *dst_mac, uint32_t dip,uint8_t *src_mac,uint32_t sip) {
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
	mbuf->data_len = mbuf->pkt_len;
	
	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

	rte_memcpy(eth->src_addr.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->dst_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

	// 2 arp 
	struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
	arp->arp_hardware = htons(1);
	arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp->arp_hlen = RTE_ETHER_ADDR_LEN;
	arp->arp_plen = sizeof(uint32_t);
	arp->arp_opcode = htons(2);

	rte_memcpy(arp->arp_data.arp_sha.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);
	rte_memcpy( arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	arp->arp_data.arp_sip = sip;
	arp->arp_data.arp_tip = dip;
	
	return mbuf;
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
	port_init(mbuf_pool);
	struct rte_ether_addr eth_macaddr;
	in_addr_t eth_ipv4 = inet_addr("192.168.199.202");
	rte_eth_macaddr_get(gDpdkPortId,&eth_macaddr);
	printf("local mac: \"%02x:%02x:%02x:%02x:%02x:%02x\"\n",
										eth_macaddr.addr_bytes[0],
										eth_macaddr.addr_bytes[1],
										eth_macaddr.addr_bytes[2],
										eth_macaddr.addr_bytes[3],
										eth_macaddr.addr_bytes[4],
										eth_macaddr.addr_bytes[5]);
	while (1)
	{
		struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned recved = rte_eth_rx_burst(gDpdkPortId,0,mbufs,BURST_SIZE);
		if (recved > BURST_SIZE) {
			rte_exit(EXIT_FAILURE,"recved > BURST_SIZE: Failed\n");
		}
		for (unsigned i = 0;i < recved; i++) {
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i],struct rte_ether_hdr *);
			if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i],struct rte_ipv4_hdr *,sizeof(struct rte_ether_hdr));
				if (iphdr->next_proto_id == IPPROTO_UDP) {
					struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
					uint16_t length = ntohs(udphdr->dgram_len);
					*(char *)(udphdr + length) = '\0';
				} else if (iphdr->next_proto_id == IPPROTO_ICMP) {
					struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);
					if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
						struct rte_mbuf *response = rebuild_icmp_pkt(mbufs[i],iphdr->src_addr,iphdr->dst_addr,
																	icmphdr->icmp_ident, icmphdr->icmp_seq_nb);
						rte_eth_tx_burst(gDpdkPortId, 0, &response, 1);
						printf("rte_eth_tx_burst icmp %d,%d\n",icmphdr->icmp_ident, icmphdr->icmp_seq_nb);
					}
				}
			} else if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
				struct rte_arp_hdr *arphdr = rte_pktmbuf_mtod_offset(mbufs[i],struct rte_arp_hdr *,sizeof(struct rte_ether_hdr));
				struct rte_mbuf *response = create_arp_response(mbuf_pool,
					ehdr->src_addr.addr_bytes,arphdr->arp_data.arp_tip,
					eth_macaddr.addr_bytes,eth_ipv4);
				rte_eth_tx_burst(gDpdkPortId, 0, &response, 1); // 将数据send出去
				rte_pktmbuf_free(response);
				printf("RTE_ETHER_TYPE_ARP\n");
			}
			rte_pktmbuf_free(mbufs[i]);
		}
	}
	return 0;
}