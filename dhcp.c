

#include "dhcp.h"


const struct rte_ether_addr broadcast_mac = {.addr_bytes = {0xff,0xff,0xff,0xff,0xff,0xff}};
static int
add_dhcp_option(uint8_t *packet, uint8_t code, uint8_t *data, uint8_t len)
{
    packet[0] = code;
    packet[1] = len;
    memcpy(&packet[2], data, len);

    return len + (sizeof(uint8_t) * 2);
}


#define DHCP_MESSAGE_TYPE           53
#define DHCP_RENEWAL_TIME_VALUE     58
#define DHCP_SUBNET_MASK            1
#define DHCP_BROADCAST_ADDRESS      28
#define DHCP_ROUTER                 3
#define DHCP_DOMAIN_NAME_SERVER     6

void mbuf_dhcp_pkt_discover(dhcp_client_t *dhcp_client,struct rte_mbuf *mbuf) {
	struct rte_ether_hdr *eth_h = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	rte_ether_addr_copy(&dhcp_client->mac, &eth_h->src_addr);
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
	dhcp_h->yipv4 = dhcp_client->client;
	dhcp_h->nipv4 = 0;
	dhcp_h->ripv4 = 0;
	rte_memcpy(dhcp_h->cmac,dhcp_client->mac.addr_bytes,6);
	dhcp_h->xid = rte_cpu_to_be_32(0x5F5E000);
	dhcp_h->secs = rte_cpu_to_be_16(0);
	dhcp_h->magic_cookie = rte_cpu_to_be_32(0x63825363);

	uint8_t *packet = (uint8_t *)(dhcp_h + 1);
	uint8_t discover = 1;
	uint8_t parameter_request_list[8] = {1,3,6,12,15,28,42,121};
	uint8_t *identifler = "dhcp";
	uint8_t *hostname = "DPDK Demo";
	int len = 0;
	len += add_dhcp_option(&packet[len],DHCP_MESSAGE_TYPE,&discover,1);
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

void mbuf_dhcp_offer_pkt_decode(dhcp_client_t *dhcp_client,struct rte_udp_hdr *udp) {
    struct dhcp_hdr *dhcp = (struct dhcp_hdr *)(udp + 1);
    int32_t lenght = (int32_t)rte_be_to_cpu_16(udp->dgram_len) - sizeof(struct rte_udp_hdr) - sizeof(struct dhcp_hdr);
    uint8_t *options = (uint8_t *)(dhcp + 1);
    
    while (lenght > 0) {
        uint8_t code =  options[0];
        uint8_t size =  options[1];
        uint8_t *opt = &options[2];
        switch (options[0])
        {
        case DHCP_MESSAGE_TYPE:
            if (options[2] != 0x02) return;
            break;
        case DHCP_RENEWAL_TIME_VALUE:
            dhcp_client->update_time = rte_be_to_cpu_32(*(uint32_t *)opt);
            break;
        case DHCP_SUBNET_MASK:
            dhcp_client->submask = (*(uint32_t *)opt);
            break;
        case DHCP_BROADCAST_ADDRESS:
            dhcp_client->broadcast = (*(uint32_t *)opt);
            break;
        case DHCP_ROUTER:
            dhcp_client->route = (*(uint32_t *)opt);
            break;
        case DHCP_DOMAIN_NAME_SERVER:
            dhcp_client->server = (*(uint32_t *)opt);
            break;
        default:
            break;
        }
        lenght -= 2 + options[1];
        options += 2 + options[1];

        if (options[0] == 0xff) {
            printf("final code\n");
            break;
        }
    }
    dhcp_client->client = dhcp->yipv4;
    dhcp_client->dhcp_status = DHCP_REQUEST;
}

int dhcp_client_init(dhcp_client_t *dhcp_client,in_addr_t ipv4,struct rte_ether_addr mac) {
    if (dhcp_client) {
        dhcp_client->client = ipv4;
        dhcp_client->mac = mac;
        dhcp_client->dhcp_status = DHCP_DISCOVER;
        return 0;
    }
    return -1;
}

void dhcp_client_recv(dhcp_client_t *dhcp_client,struct rte_udp_hdr *udp) {
    switch (dhcp_client->dhcp_status) {
        case DHCP_OFFER:
            mbuf_dhcp_offer_pkt_decode(dhcp_client,udp);
            break;
        case DHCP_ACK:
        break;
    }
}

void dhcp_client_loop(dhcp_client_t *dhcp_client,struct rte_mempool *mp,uint16_t port_id) {
    switch (dhcp_client->dhcp_status)
    {
    case DHCP_DISCOVER:
    {
        struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mp);
        mbuf_dhcp_pkt_discover(dhcp_client,mbuf);
        rte_eth_tx_burst(port_id, 0, &mbuf, 1);
        rte_pktmbuf_free(mbuf);
        dhcp_client->dhcp_status = DHCP_OFFER;
        break;
    }        
    case DHCP_OFFER:
        break;
    case DHCP_REQUEST:
    {
        struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mp);
        mbuf_dhcp_pkt_discover(dhcp_client,mbuf);
        rte_eth_tx_burst(port_id, 0, &mbuf, 1);
        rte_pktmbuf_free(mbuf);
        dhcp_client->dhcp_status = DHCP_OFFER;

        struct in_addr ip;
        ip.s_addr = dhcp_client->client;
	    printf("dhcp_client->client: %s\n",inet_ntoa(ip));
        dhcp_client->dhcp_status = DHCP_ACK;
        break;
    }
    case DHCP_ACK:
        break;
    default:
        break;
    }
}