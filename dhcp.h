#ifndef __DHCP_H_
#define __DHCP_H_

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include "eth.h"

typedef enum {
	DHCP_STATUS_IDLE = 0,
	DHCP_STATUS_DISCOVER,
	DHCP_STATUS_OFFER,
	DHCP_STATUS_REQUEST,
	DHCP_STATUS_ACK = 5,
	DHCP_STATUS_RESULT,
	DHCP_STATUS_TIMEOUT,
} dhcp_status_t;

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

typedef struct __dhcp_client_t{
    dhcp_status_t dhcp_status;
	uint32_t xid;
    uint32_t update_time;
    in_addr_t client;
    in_addr_t server;
    in_addr_t submask;
    in_addr_t broadcast;
    in_addr_t route;
	struct rte_ether_addr mac;
	uint64_t second_cycles;
	uint64_t prev_tsc;
	void (*dhcp_client_result_cb)(struct __dhcp_client_t *dhcp_client,void *arg);
	void *dhcp_client_result_arg;
}dhcp_client_t;

int dhcp_client_init(dhcp_client_t *dhcp_client,in_addr_t ipv4,struct rte_ether_addr mac,
						void (*cb)(dhcp_client_t *dhcp_client,void *arg),void *arg);
void dhcp_client_recv(dhcp_client_t *dhcp_client,struct rte_udp_hdr *udp);
void dhcp_client_loop(dhcp_client_t *dhcp_client,struct rte_mempool *mp,uint16_t port_id);

#endif