/*
 * Copyright (c) 2001,2002 Florian Schulze.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the authors nor the names of the contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * test.c - This file is part of lwIP test
 *
 */

/* C runtime includes */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

/* lwIP core includes */
#include "lwip/opt.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/init.h"
#include "lwip/tcpip.h"
#include "lwip/netif.h"
#include "lwip/api.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/dns.h"
#include "lwip/dhcp.h"
#include "lwip/autoip.h"
#include "lwip/etharp.h"
#include "lwip/sockets.h"
#include "lwip/opt.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/tcpip.h"
/* lwIP netif includes */
#include "netif/ethernet.h"
#include "dpdkif.h"
#include "tcpecho.h"

static struct dhcp netif_dhcp1;
static struct dhcp netif_dhcp2;

#if LWIP_NETIF_STATUS_CALLBACK
static void status_callback(struct netif *state_netif)
{
    if(netif_is_up(state_netif)) {
#if LWIP_IPV4
    printf("netif %s == UP, local interface IP is %s\n", state_netif->name, ip4addr_ntoa(netif_ip4_addr(state_netif)));
#else
    printf("status_callback == UP\n");
#endif
  } else {
    printf("status_callback == DOWN\n");
  }
}
#endif /* LWIP_NETIF_STATUS_CALLBACK */

#if LWIP_NETIF_LINK_CALLBACK
static void link_callback(struct netif *state_netif)
{
    if (netif_is_link_up(state_netif)) {
        printf("link_callback == UP\n");
    } else {
        printf("link_callback == DOWN\n");
    }
}
#endif /* LWIP_NETIF_LINK_CALLBACK */

static uint32_t fd1 = 0;
static uint32_t fd2 = 1;

static struct netif netif1;
static struct netif netif2;

static const struct dpdkif dpdk_if_1 = {
    .id = 0,
    .nb_rx_queue = 1,
    .nb_tx_queue = 1,
}; 

static const struct dpdkif dpdk_if_2 = {
    .id = 1,
    .nb_rx_queue = 1,
    .nb_tx_queue = 1,
};

static void tcpip_init_done(void *arg)
{
    sys_sem_t *init_sem = (sys_sem_t*)arg;
    srand((unsigned int)time(NULL));

    netif_add_noaddr(&netif1, (void *)&dpdk_if_1, dpdk_netif_init, tcpip_input);
    netif_add_noaddr(&netif2, (void *)&dpdk_if_2, dpdk_netif_init, tcpip_input);
    netif_set_default(&netif1);

    netif_set_status_callback(&netif1, status_callback);
    netif_set_status_callback(&netif2, status_callback);

	dhcp_set_struct(&netif1, &netif_dhcp1);
	netif_set_up(&netif1);
	dhcp_start(&netif1);

	dhcp_set_struct(&netif2, &netif_dhcp2);
	netif_set_up(&netif2);
	dhcp_start(&netif2);

    sys_sem_signal(init_sem);
}

int main(int argc, char **argv)
{
    err_t err;
    sys_sem_t init_sem;
    dpdk_mp_init(argc,argv);
    lwip_socket_init();
    setvbuf(stdout, NULL,_IONBF, 0);

    sys_sem_new(&init_sem, 0);
    LWIP_ASSERT("failed to create init_sem", err == ERR_OK);
    LWIP_UNUSED_ARG(err);
    tcpip_init(tcpip_init_done, &init_sem);
    sys_sem_wait(&init_sem);
    sys_sem_free(&init_sem);
    
    tcpecho_init();

    lwip_socket_thread_init();
    while (1) {
        dpdk_netif_poll(&netif1);
        dpdk_netif_poll(&netif2);
    }
    lwip_socket_thread_cleanup();
    return 0;
}
