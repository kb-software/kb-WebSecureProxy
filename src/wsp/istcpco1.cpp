#ifndef HL_UNIX
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#endif
#include <stdio.h>
#include <process.h>
#define HL_EXT_TAB_850_TO_819
#include <hob-tab-ascii-ansi-1.h>
#include "hob-netw-01.h"

#include <hob-tcpco1.hpp>

#ifdef DEF_TC_OWN_NS
namespace ns_tcpcomp_mh {
#endif

dsd_tcpthread_p dsd_tcpcomp::ads_thranc = NULL;      // anchor for tcp threads
CRITICAL_SECTION dsd_tcpcomp::ds_critsect;           // critical section for safe access to ressources
md_at_thr_start dsd_tcpthread_t::amc_at_thread_start;      // thread callback address

#ifdef DEF_TC_OWN_NS
}
#endif
