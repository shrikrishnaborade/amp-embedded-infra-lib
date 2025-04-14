#ifndef LWIP_LWIPOPTS_H
#define LWIP_LWIPOPTS_H

#include "stdint.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define NO_SYS 1
#define LWIP_IPV6 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define LWIP_DHCP 1
#define LWIP_DHCP_CHECK_LINK_UP 1
#define LWIP_AUTOIP 1
#define LWIP_DHCP_AUTOIP_COOP 1
#define LWIP_DNS 1
#define LWIP_RAW 1
#define LWIP_IGMP 1
    uint32_t StaticLwIpRand();
#define LWIP_RAND() StaticLwIpRand()
#define MEM_ALIGNMENT 4
#define LWIP_STATS 0

#define LWIP_DNS_SECURE 0

#define MEM_SIZE 3200

#define CHECKSUM_GEN_IP 1
#define CHECKSUM_GEN_UDP 1
#define CHECKSUM_GEN_TCP 1
#define CHECKSUM_GEN_ICMP 1
#define CHECKSUM_CHECK_IP 1
#define CHECKSUM_CHECK_UDP 1
#define CHECKSUM_CHECK_TCP 1

#define LWIP_NETIF_HOSTNAME 1
#define LWIP_NETIF_EXT_STATUS_CALLBACK 1
#define SO_REUSE 1

#define LWIP_TCP_PCB_NUM_EXT_ARGS 1

// PPP
#define PPP_SUPPORT 1
#define PAP_SUPPORT 1  /* Set > 0 for PAP. */
#define CHAP_SUPPORT 1 /* Set > 0 for CHAP. */
#define PPP_SERVER 1
#define PPP_NOTIFY_PHASE 1
#define LWIP_NETIF_STATUS_CALLBACK 1
#define LWIP_NETIF_LINK_CALLBACK 1
// debug traces
#define LWIP_DEBUG 0
#define PPP_DEBUG LWIP_DBG_OFF
#define NETIF_DEBUG LWIP_DBG_OFF
#define SLIP_DEBUG LWIP_DBG_OFF
#define IP6_DEBUG LWIP_DBG_OFF
#define DHCP6_DEBUG LWIP_DBG_OFF
#define PRINTPKT_SUPPORT 0

#ifdef __cplusplus
}
#endif

#endif
