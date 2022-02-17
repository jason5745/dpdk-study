
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

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

/* lwIP netif includes */
#include "lwip/etharp.h"
#include "netif/ethernet.h"

#include "lwip/opt.h"

#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/tcpip.h"
#include "netif/tapif.h"

#ifndef LWIP_EXAMPLE_APP_ABORT
#define LWIP_EXAMPLE_APP_ABORT() 0
#endif

/** Define this to 1 to enable a port-specific ethernet interface as default interface. */
#ifndef USE_DEFAULT_ETH_NETIF
#define USE_DEFAULT_ETH_NETIF 1
#endif

/** Define this to 1 to enable a PPP interface. */
#ifndef USE_PPP
#define USE_PPP 0
#endif

/** Define this to 1 or 2 to support 1 or 2 SLIP interfaces. */
#ifndef USE_SLIPIF
#define USE_SLIPIF 0
#endif

/** Use an ethernet adapter? Default to enabled if port-specific ethernet netif or PPPoE are used. */
#ifndef USE_ETHERNET
#define USE_ETHERNET  (USE_DEFAULT_ETH_NETIF || PPPOE_SUPPORT)
#endif

/** Use an ethernet adapter for TCP/IP? By default only if port-specific ethernet netif is used. */
#ifndef USE_ETHERNET_TCPIP
#define USE_ETHERNET_TCPIP  (USE_DEFAULT_ETH_NETIF)
#endif

#ifndef USE_DHCP
#define USE_DHCP    LWIP_DHCP
#endif

static struct dhcp netif_dhcp;
static struct netif netif;

#define NETIF_ADDRS ipaddr, netmask, gw,
void init_default_netif(const ip4_addr_t *ipaddr, const ip4_addr_t *netmask, const ip4_addr_t *gw)
{
  netif_add(&netif, NETIF_ADDRS NULL, tapif_init, tcpip_input);
  netif_set_default(&netif);
}

void
default_netif_poll(void)
{
  tapif_poll(&netif);
}

void
default_netif_shutdown(void)
{
}

#if LWIP_NETIF_STATUS_CALLBACK
static void
status_callback(struct netif *state_netif)
{
  if (netif_is_up(state_netif)) {
#if LWIP_IPV4
    printf("status_callback==UP, local interface IP is %s\n", ip4addr_ntoa(netif_ip4_addr(state_netif)));
#else
    printf("status_callback==UP\n");
#endif
  } else {
    printf("status_callback==DOWN\n");
  }
}
#endif /* LWIP_NETIF_STATUS_CALLBACK */

#if LWIP_NETIF_LINK_CALLBACK
static void
link_callback(struct netif *state_netif)
{
  if (netif_is_link_up(state_netif)) {
    printf("link_callback==UP\n");
  } else {
    printf("link_callback==DOWN\n");
  }
}
#endif /* LWIP_NETIF_LINK_CALLBACK */

static void
test_netif_init(void)
{
  ip4_addr_t ipaddr, netmask, gw;
  err_t err;

  ip4_addr_set_zero(&gw);
  ip4_addr_set_zero(&ipaddr);
  ip4_addr_set_zero(&netmask);
  printf("Starting lwIP, local interface IP is dhcp-enabled\n");
  init_default_netif(&ipaddr, &netmask, &gw);

#if LWIP_NETIF_STATUS_CALLBACK
  netif_set_status_callback(netif_default, status_callback);
#endif /* LWIP_NETIF_STATUS_CALLBACK */
#if LWIP_NETIF_LINK_CALLBACK
  netif_set_link_callback(netif_default, link_callback);
#endif /* LWIP_NETIF_LINK_CALLBACK */

  dhcp_set_struct(netif_default, &netif_dhcp);
  netif_set_up(netif_default);
  err = dhcp_start(netif_default);
  LWIP_ASSERT("dhcp_start failed", err == ERR_OK);
}


#if LWIP_DNS_APP && LWIP_DNS
static void
dns_found(const char *name, const ip_addr_t *addr, void *arg)
{
  LWIP_UNUSED_ARG(arg);
  printf("%s: %s\n", name, addr ? ipaddr_ntoa(addr) : "<not found>");
}

static void
dns_dorequest(void *arg)
{
  const char* dnsname = "3com.com";
  ip_addr_t dnsresp;
  LWIP_UNUSED_ARG(arg);

  if (dns_gethostbyname(dnsname, &dnsresp, dns_found, NULL) == ERR_OK) {
    dns_found(dnsname, &dnsresp, NULL);
  }
}
#endif /* LWIP_DNS_APP && LWIP_DNS */

static void
test_init(void * arg)
{
  sys_sem_t *init_sem;
  LWIP_ASSERT("arg != NULL", arg != NULL);
  init_sem = (sys_sem_t*)arg;
  srand((unsigned int)time(NULL));
  test_netif_init();
  sys_sem_signal(init_sem);
}

int main(void)
{
    setvbuf(stdout, NULL,_IONBF, 0);
    err_t err;
    sys_sem_t init_sem;
    err = sys_sem_new(&init_sem, 0);
    LWIP_ASSERT("failed to create init_sem", err == ERR_OK);
    LWIP_UNUSED_ARG(err);
    tcpip_init(test_init, &init_sem);
    sys_sem_wait(&init_sem);
    sys_sem_free(&init_sem);
    
#if (LWIP_SOCKET || LWIP_NETCONN) && LWIP_NETCONN_SEM_PER_THREAD
    netconn_thread_init();
#endif

  /* MAIN LOOP for driver update (and timers if NO_SYS) */
    while (!LWIP_EXAMPLE_APP_ABORT()) {

        default_netif_poll();

#if ENABLE_LOOPBACK && !LWIP_NETIF_LOOPBACK_MULTITHREADING
    /* check for loopback packets on all netifs */
        netif_poll_all();
#endif /* ENABLE_LOOPBACK && !LWIP_NETIF_LOOPBACK_MULTITHREADING */
    }
#if (LWIP_SOCKET || LWIP_NETCONN) && LWIP_NETCONN_SEM_PER_THREAD
    netconn_thread_cleanup();
#endif
    default_netif_shutdown();
    return 0;
}
