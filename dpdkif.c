
#include "lwip/opt.h"
#include "lwip/snmp.h"
#include "lwip/pbuf.h"
#include "lwip/ethip6.h"

#include "netif/etharp.h"
#include "dpdkif.h"

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

static void dpdk_net_input(struct netif *netif);

struct rte_mempool *g_MemPool = NULL;

#define RING_SIZE			512
#define NUM_MBUFS 			8192 
#define MBUF_CACHE_SIZE		0
#define BURST_SIZE			1024

/*-----------------------------------------------------------------------------------*/
static void low_level_init(struct netif *netif)
{
    static const struct rte_eth_conf port_conf_default = {
        .rxmode.mtu = 1500,
    };
    
    const struct dpdkif *eth = (const struct dpdkif *)netif->state;
    rte_eth_macaddr_get(eth->id,(struct rte_ether_addr *)netif->hwaddr);

    netif->hwaddr_len = 6;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;

    if (0 > rte_eth_dev_configure(eth->id,eth->nb_rx_queue,eth->nb_tx_queue,&port_conf_default)) {
        rte_exit(EXIT_FAILURE,"rte_eth_dev_configure(): Failed\n");
    }
    for (uint8_t i = 0; i < eth->nb_rx_queue ; i++) {
        if (0 > rte_eth_rx_queue_setup(eth->id,i,RING_SIZE,rte_eth_dev_socket_id(eth->id), NULL, g_MemPool)) {
            rte_exit(EXIT_FAILURE,"rte_eth_rx_queue_setup(): Failed\n");
        }
    }
    for (uint8_t i = 0; i < eth->nb_tx_queue ; i++) {
        if (0 > rte_eth_tx_queue_setup(eth->id,i,RING_SIZE,rte_eth_dev_socket_id(eth->id), NULL)) {
            rte_exit(EXIT_FAILURE,"rte_eth_tx_queue_setup(): Failed\n");
        }
    }
    if (0 > rte_eth_dev_start(eth->id)) {
        rte_exit(EXIT_FAILURE,"rte_eth_dev_start(): Failed\n");
    }
    netif_set_link_up(netif);
}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_output():
 *
 * Should do the actual transmission of the packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * might be chained.
 *
 */
/*-----------------------------------------------------------------------------------*/

static err_t
low_level_output(struct netif *netif, struct pbuf *p)
{
    const struct dpdkif *eth = (const struct dpdkif *)netif->state;
    uint32_t pbuf_count = 0;

    for (struct pbuf *_p = p; _p != NULL; _p = _p->next) {
        pbuf_count++;
    }

    struct rte_mbuf *mbufs[pbuf_count];
    rte_pktmbuf_alloc_bulk(g_MemPool,mbufs,pbuf_count);
    pbuf_count = 0;
    for (struct pbuf *_p = p; _p != NULL; _p = _p->next) {
        struct rte_mbuf *mbuf = mbufs[pbuf_count];
        void *buf = rte_pktmbuf_mtod(mbuf, void *);
        memcpy(buf,_p->payload,_p->len);
        mbuf->data_len = _p->len;
        mbuf->pkt_len = _p->len;
        pbuf_count++;
    }

    rte_eth_tx_burst(eth->id, 0, mbufs, pbuf_count);
    rte_pktmbuf_free_bulk(mbufs, pbuf_count);
    MIB2_STATS_NETIF_ADD(netif, ifoutoctets, (u32_t)p->tot_len);
    return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_input():
 *
 * Should allocate a pbuf and transfer the bytes of the incoming
 * packet from the interface into the pbuf.
 *
 */
/*-----------------------------------------------------------------------------------*/
static struct pbuf *low_level_input(struct netif *netif,struct rte_mbuf *mbuf)
{
    struct pbuf *p;
    u16_t len = (u16_t)mbuf->pkt_len;
    void *buf = rte_pktmbuf_mtod(mbuf,void *);

    MIB2_STATS_NETIF_ADD(netif, ifinoctets, len);
  
    p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if (p != NULL) {
        pbuf_take(p, buf, len);
    } else {
        MIB2_STATS_NETIF_INC(netif, ifindiscards);
        LWIP_DEBUGF(NETIF_DEBUG, ("dpdk_net_input: could not allocate pbuf\n"));
    }
    return p;
}

static void dpdk_net_input(struct netif *netif)
{
    struct rte_mbuf *mbufs[BURST_SIZE];
    const struct dpdkif *eth = (const struct dpdkif *)netif->state;

    for (uint8_t i = 0; i < eth->nb_rx_queue ; i++) {
        uint32_t nfs = rte_eth_rx_burst(eth->id,i,mbufs,BURST_SIZE);
        for (uint32_t i = 0;i < nfs; i++) {
            struct rte_mbuf *mbuf = mbufs[i];
            struct pbuf *p = low_level_input(netif,mbuf);
            rte_pktmbuf_free(mbuf);
            if (p == NULL) {
    #if LINK_STATS
                LINK_STATS_INC(link.recv);
    #endif /* LINK_STATS */
                LWIP_DEBUGF(LWIP_DBG_OFF, ("dpdk_net_input: low_level_input returned NULL\n"));
                return;
            }

            if (netif->input(p, netif) != ERR_OK) {
                LWIP_DEBUGF(NETIF_DEBUG, ("dpdk_net_input: netif input error\n"));
                pbuf_free(p);
            }
        }
    }
}

err_t dpdk_mp_init(int argc, char **argv) {
    if (rte_eal_init(argc,argv) < 0) {
		rte_exit(EXIT_FAILURE,"rte_eal_init(): Failed\n");
	}
	g_MemPool = rte_pktmbuf_pool_create("MBUF_POOL",
		NUM_MBUFS,MBUF_CACHE_SIZE,0,RTE_MBUF_DEFAULT_BUF_SIZE,rte_socket_id());
	if (!g_MemPool) {
		rte_exit(EXIT_FAILURE,"rte_pktmbuf_pool_create(): Failed\n");
	}
    return ERR_OK;
}

const char char_table[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
err_t dpdk_netif_init(struct netif *netif)
{
    static const struct rte_eth_conf port_conf_default;
    const struct dpdkif *eth = (const struct dpdkif *)netif->state;

    if (eth == NULL) {
        LWIP_DEBUGF(NETIF_DEBUG, ("dpdk port num empty\n"));
        return ERR_MEM;
    }

    if (eth->id >= rte_eth_dev_count_avail()) {
        LWIP_DEBUGF(NETIF_DEBUG, ("dpdk can not fond port\n"));
        return ERR_MEM;
    }
    MIB2_INIT_NETIF(netif, snmp_ifType_other, 100000000);

    netif->name[0] = char_table[eth->id >> 4 & 0xf];
    netif->name[1] = char_table[eth->id & 0xf];

#if LWIP_IPV4
    netif->output = etharp_output;
#endif /* LWIP_IPV4 */
#if LWIP_IPV6
    netif->output_ip6 = ethip6_output;
#endif /* LWIP_IPV6 */
    netif->linkoutput = low_level_output;
    netif->mtu = 1500;

    low_level_init(netif);
    return ERR_OK;
}

void dpdk_netif_poll(struct netif *netif)
{
    dpdk_net_input(netif);
}
