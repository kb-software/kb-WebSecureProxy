//#define TRY_INSURE_121003_01 120            /* timeout in seconds - for insure++ */
//#define TRACEHL1
//#define TRY_090121
//#define TRACEHL1
//#define TRACEHL_LOAD
//#define CHECK_QUALITY_DOUBLE
//#define DEBUG_120912_01                     /* receiving loops         */
#define INCL_GW_L2TP
#define D_INCL_HOB_TUN
#ifdef TRACEHL_CS1
#define TRACEHL_CO_OUT
#endif
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xs-gw-cluster                                       |*/
/*| -------------                                                     |*/
/*|  Subroutine which manages the cluster of gateways                 |*/
/*|  KB 17.09.07                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|  Copyright (C) HOB Germany 2017                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifdef TRACEHL1
#ifndef TRACEHL_LOAD
#define TRACEHL_LOAD
#endif
#endif

#ifndef HL_UNIX
#ifdef HL_LINUX
#define HL_UNIX
#endif
#ifdef HL_FREEBSD
#define HL_UNIX
#endif
#endif
#ifndef HL_UNIX
#define HL_THRID GetCurrentThreadId()
#else
#ifndef HL_LINUX
#define HL_THRID m_gettid()
#include <sys/thr.h>
extern "C" pid_t m_gettid( void );
#else
#define HL_THRID syscall( __NR_gettid )
#endif
#endif

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#ifdef XYZ1
#include <iostream>
#include <ostream>
#include <fstream>

using namespace std;
#endif

#ifdef TRACEHL1
#define TRACEHL_CO_OUT
#endif

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef HL_SOLARIS
#include <stdarg.h>
#endif
#include <string.h>
#ifdef XYZ2
#include <conio.h>
#endif
#include <time.h>
#ifdef HL_UNIX
#include <fcntl.h>
#include <poll.h>
#ifdef B120306
#ifdef HL_LINUX
#include <pth.h>
#endif
#endif
#include <sys/socket.h>
#include <sys/un.h>
//#include <sys/stropts.h>
#ifdef D_INCL_HOB_TUN
#include <net/if.h>
#endif
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
//#include <xti.h>
#ifdef HL_LINUX
#include <sys/syscall.h>
#endif
#ifndef HL_LINUX
#include <unistd.h>
#endif
#include <sys/types.h>
#ifdef HL_OPENUNIX
#include <rpc/types.h>
#endif
#include <sys/ipc.h>
#include <sys/sem.h>
#ifdef HL_LINUX
#include <sys/time.h>
//#include <LiS/sys/xti_ip.h>
#include <netinet/in.h>
#endif
#ifdef HL_FREEBSD
#include <net/if_dl.h>
#endif
#include <limits.h>
#include <dlfcn.h>
/* start header-files for TCPCOMP                                      */
#include <sys/uio.h>
#include <netinet/tcp.h>
/* end header-files for TCPCOMP                                        */
#include "hob-unix01.h"
#include "hob-xslhcla1.hpp"
#include "hob-thread.hpp"
#include "hob-li-gw-01.h"
#endif
#ifndef HL_UNIX
#include <wchar.h>
#include <winsock2.h>
#include <ws2tcpip.h>
//#include <wspiapi.h>
#include <hob-wtspo1.h>
#endif
#include <hob-xslunic1.h>
#ifndef HL_UNIX
#include <hob-thread.hpp>
#include <iswcord1.h>
#endif
//#include "hob-hlwspat2.h"
#include <hob-wspsu1.h>
#include <hob-netw-01.h>
#include <hob-nblock_acc.hpp>
#ifndef TCPCOMP_V02
#include <hob-tcpco1.hpp>
#endif
#ifdef TCPCOMP_V02
#include <hob-tcpcomp-multi-v02.hpp>
#endif
#ifdef INCL_GW_L2TP
#ifdef D_INCL_HOB_TUN
#include "hob-tun01.h"
#include <hob-avl03.h>
#endif
#endif

#define DOMNode void

#define DEF_HL_INCL_DOM
#include "hob-xsclib01.h"

#include "hob-wsppriv.h"                    /* privileges              */
#define HOB_CONTR_TIMER
#include <hob-xslcontr.h>                   /* HOB Control             */
#define INCL_GW_ALL
#include "hob-xbipgw08-1.h"
#include "hob-xbipgw08-2.h"
#include "hob-wsp-admin-1.h"
#include "hob-perf-data-1.h"

#ifndef HL_UNIX
#define D_TCP_ERROR WSAGetLastError()
#define D_TCP_CLOSE closesocket
#define M_GET_PID GetCurrentProcessId()
#else
#define D_TCP_ERROR errno
#define D_TCP_CLOSE close
#define M_GET_PID getpid()
#endif

#define IP_socket socket
#define IP_bind bind
#define IP_listen listen
#define IP_htons htons
#define IP_getnameinfo getnameinfo

/**
   load-balancing
   blocks are exchanged with 4 bytes net data.
   the first byte is the state of this WSP
   the following three bytes are the load (0 till 10,000) in big endian
   With a timer the current status is sent to all connected WSPs.
   The state is only checked if a load-balancing packet has been
   received from another WSP.
*/
#define DEF_CLUSTER_NO_BL      2            /* number of blocks for flow control */
#ifndef TRY_INSURE_121003_01                /* timeout in seconds - for insure++ */
#define DEF_CLUSTER_INIT_W     20           /* wait time when init received, in seconds */
#else
#define DEF_CLUSTER_INIT_W TRY_INSURE_121003_01 /* wait time when init received, in seconds */
#endif
#define DEF_CLUSTER_WAIT_FREE  120          /* wait time free control blocks */
#define DEF_CLUSTER_SEND_ROUNDED 2          /* seconds for rounded     */
#define DEF_LBAL_NET_DATA      4            /* length data received load-balancing */

/* loaded configurations that are in use now                           */
extern "C" struct dsd_loconf_1 *adsg_loconf_1_inuse;

extern "C" int img_wsp_trace_core_flags1;   /* WSP trace core flags    */

extern "C" int m_get_load( void );
#ifdef TRACEHL_CO_OUT
extern "C" void m_console_out( char *, int );
#endif

/*+-------------------------------------------------------------------+*/
/*| Internal used structures.                                         |*/
/*+-------------------------------------------------------------------+*/

struct dsd_cluster_timer_1 {                /* cluster timer one       */
   struct dsd_cluster_active *adsc_clact;   /* active cluster          */
   struct dsd_timer_ele dsc_timer_ele;      /* timer element           */
};

struct dsd_cluster_timer_lbal {             /* cluster timer load-balancing */
   struct dsd_timer_ele dsc_timer_ele;      /* timer element           */
};

struct dsd_cluster_timer_reco {             /* cluster timer reconnect */
   struct dsd_timer_ele dsc_timer_ele;      /* timer element           */
};

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

#ifdef OLD01
static void m_do_connect( struct dsd_cluster_active * );
#endif

static void m_acc_errorcallback( class dsd_nblock_acc *, void *, char *, int, int );  /* error callback function */
static void m_acceptcallback( class dsd_nblock_acc *, void *, int, struct sockaddr *, int );
static void m_cb_conn_err( class dsd_tcpcomp *, void *, struct sockaddr *, socklen_t, int, int, int );
#ifdef B121120
static void m_conncallback( class dsd_tcpcomp *, void *, struct sockaddr *, socklen_t, int );  /* connect callback function */
#else
static void m_conncallback( class dsd_tcpcomp *, void *, struct dsd_target_ineta_1 *, void *, struct sockaddr *, socklen_t, int );  /* connect callback function */
#endif
static void m_sendcallback( class dsd_tcpcomp *, void * );  /* send callback function */
static int m_getrecvbuf( class dsd_tcpcomp *, void *, void **, char **, int ** );  /* get receive buffer callback function */
#ifdef TCPCOMP_V02
static void m_cl_tcpc_freebuf( class dsd_tcpcomp *, void *, void * );
#endif
static BOOL m_recvcallback( class dsd_tcpcomp *, void *, void * );  /* receive callback function */
static void m_errorcallback( class dsd_tcpcomp *, void *, char *, int, int );  /* error callback function */
static void m_cleanup( class dsd_tcpcomp *, void * );  /* cleanup callback function */
static void m_send_control_init( struct dsd_cluster_active * );
static void m_cluster_free_send( struct dsd_cluster_send * );
static htfunc1_t m_recv_block( void * );
static void m_recv_control( struct dsd_cluster_active *,
                            struct dsd_cluster_recv *, char *, int );
static void m_recv_redirect( struct dsd_cluster_active *,
                             struct dsd_cluster_recv *, char *, int );
static void m_recv_cluster_lbal( struct dsd_cluster_active *, char * );
#ifdef XYZ1
static BOOL m_status_cluster_lbal( void );
#endif
static void m_send_cluster_lbal( struct dsd_cluster_active * );
static void m_cluster_redirect_conn( struct dsd_cluster_active *, char *, int );
#ifndef B120827
static void m_timer_free_clact( struct dsd_timer_ele * );
#endif
static void m_timeout_init_1( struct dsd_timer_ele * );
static void m_check_cluster_member_double( struct dsd_cluster_active *, BOOL );
static void m_set_clact_chain( struct dsd_cluster_active * );
static void m_send_end_clact( struct dsd_cluster_active * );
static void m_cluster_lbal_timer( struct dsd_timer_ele * );
static void m_cluster_reco_timer( struct dsd_timer_ele * );
static void m_check_reco_cluster( void );

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

static struct dsd_acccallback dss_acccb = {
   &m_acceptcallback,                       /* accept callback routine */
   &m_acc_errorcallback                     /* error callback routine  */
};

static struct dsd_tcpcallback dss_tcpco1_cb1 = {
   &m_cb_conn_err,                          /* connect error callback function */
   &m_conncallback,                         /* connect callback function */
   &m_sendcallback,                         /* send callback function  */
   &m_getrecvbuf,                           /* get receive buffer callback function */
#ifdef TCPCOMP_V02
   &m_cl_tcpc_freebuf,
#endif
   &m_recvcallback,                         /* receive callback function */
   &m_errorcallback,                        /* error callback function */
   &m_cleanup,                              /* cleanup callback function */
   &m_get_random_number
};

#ifdef TRACEHL_CS1
static char   chrs_eyecatcher_cs_start[ 8 ] = { '1', '1', '1', '1', '1', '1', '1', '1' };
#endif
static class dsd_hcla_critsect_1 dss_critsect_cluster;  /* critical section for cluster */
#ifdef TRACEHL_CS1
static char   chrs_eyecatcher_cs_end[ 8 ] = { '2', '2', '2', '2', '2', '2', '2', '2' };
#endif
static class dsd_hcthread dss_thread_cluster;  /* thread for cluster   */
static class dsd_hcla_event_1 dss_event_cluster;  /* event for cluster */
static struct dsd_cluster_timer_lbal dss_cluster_timer_lbal;  /* cluster timer load-balancing */
static struct dsd_cluster_timer_reco dss_cluster_timer_reco;  /* cluster timer reconnect */
static struct dsd_cluster_main *adss_cluster_main = NULL;
extern struct dsd_cluster_active *adsg_clact_ch = NULL;
extern struct dsd_sys_state_1 dsg_sys_state_1;  /* system state        */
static struct dsd_cluster_active *adss_clact_proc_ch = NULL;  /* chain to get processed */
#ifndef HL_UNIX
static BOOL   bos_cluster_init = FALSE;     /* state initialization    */
#endif
#ifdef HL_UNIX
static struct dsd_cluster_listen *adss_clli_uds = NULL;  /* cluster structure listen Unix domain socket */
#endif
#ifndef NO_LOCK_1110
static BOOL   bos_lbal_lock = FALSE;        /* load-balancing lock     */
#endif

static const unsigned char ucrs_cluster_eye_catcher[] = {
   'H', 'O', 'B', ' ', 'W', 'S', 'P', ' ',
   'C', 'L', 'U', 'S', 'T', 'E', 'R', 0
};

/*+-------------------------------------------------------------------+*/
/*| Procedure division.                                               |*/
/*+-------------------------------------------------------------------+*/

/** start cluster subsystem, called when the WSP starts
    or in IBIPGW08 when the configuration is reloaded                  */
extern "C" void m_cluster_start( struct dsd_cluster_main *adsp_cluster_main ) {
#ifndef HL_UNIX
   int        iml1;                         /* working variable        */
#else
   int        iml1, iml2;                   /* working variables       */
#endif
// BOOL       bol1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   int        iml_listen_socket;            /* socket to be used       */
   int        iml_listen_port;              /* port of listen          */
   socklen_t  iml_soadlen;                  /* length of sockaddr      */
   unsigned short int usl_port_listen;      /* port of listen          */
#ifdef HL_UNIX
   unsigned short int usl_port_main;        /* port of listen          */
   char       *achl1, *achl2;               /* working variables       */
   int        *aimrl_ligw_cluster;          /* structure listen-gateway cluster */
#endif
   struct dsd_ineta_single_1 *adsl_ineta_s_w1;  /* single INETA target */
   struct dsd_cluster_remote *adsl_clrem_w1;  /* cluster remote structure */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster structure */
   struct sockaddr_storage dsl_soa_listen;  /* server address information */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_cluster_start( 0X%p ) called",
                   __LINE__, adsp_cluster_main );
#endif
// 04.10.07 KB to-do reload-configuration
#ifndef HL_UNIX
   if (adss_cluster_main == NULL) {         /* no old configuration    */
     if (adsp_cluster_main == NULL) return;
     goto p_start_60;                       /* after close old listen  */
   }
   if (dss_cluster_timer_lbal.dsc_timer_ele.vpc_chain_2) {  /* timer set */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster dss_cluster_timer_lbal m_time_rel() m_cluster_start()",
                     __LINE__ );
#endif
     m_time_rel( &dss_cluster_timer_lbal.dsc_timer_ele );  /* release timer */
   }
   if (dss_cluster_timer_reco.dsc_timer_ele.vpc_chain_2) {  /* timer set */
     m_time_rel( &dss_cluster_timer_reco.dsc_timer_ele );  /* release timer */
   }
   /* close old listen                                                 */
   iml1 = 0;                                /* clear index             */
   while (iml1 < adss_cluster_main->adsc_listen_ineta->imc_no_ineta) {
     adss_cluster_main->adsc_clli[ iml1 ].dsc_acc_listen.mc_stoplistener_fix();
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T listen stopped successfully", __LINE__ );
#endif
     iml1++;                                /* count listen            */
   }
   adsl_clact_w1 = adsg_clact_ch;           /* get chain of active cluster entries */
   while (adsl_clact_w1) {                  /* loop over all active cluster entries */
     adsl_clact_w1->adsc_clrem = NULL;      /* clear cluster remote structure */
     adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
   }
   if (adsp_cluster_main == NULL) return;

   p_start_60:                              /* after close old listen  */
   if (bos_cluster_init) goto p_start_80;   /* initialization complete */
#endif
#ifdef HL_UNIX
   if (adsp_cluster_main == NULL) {         /* no cluster configured   */
     if (adsg_loconf_1_inuse->boc_listen_gw == FALSE) {  /* do use listen-gateway */
       return;
     }
     goto p_start_68;                       /* create critical section */
   }
#endif
   memset( &dss_cluster_timer_lbal, 0, sizeof(struct dsd_cluster_timer_lbal) );  /* cluster timer load-balancing */
   dss_cluster_timer_lbal.dsc_timer_ele.amc_compl = &m_cluster_lbal_timer;   /* set routine when timer elapsed */
   memset( &dss_cluster_timer_reco, 0, sizeof(struct dsd_cluster_timer_reco) );  /* cluster timer reconnect */
   dss_cluster_timer_reco.dsc_timer_ele.amc_compl = &m_cluster_reco_timer;   /* set routine when timer elapsed */

#ifdef HL_UNIX
   p_start_68:                              /* create critical section */
#endif
   iml_rc = dss_critsect_cluster.m_create();
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cluster_start() dss_critsect_cluster m_create Return Code %d.",
                     __LINE__, iml_rc );
   }
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX1T l%05d m_create() after", __LINE__ );
   m_console_out( (char *) &dss_critsect_cluster, sizeof(dss_critsect_cluster) );
#endif
   iml_rc = dss_event_cluster.m_create( &iml_error );  /* event for serial thread */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0010W xs-gw-cluster l%05d event m_create Return Code %d Error %d.",
                     __LINE__, iml_rc, iml_error );
   }
   iml_rc = dss_thread_cluster.mc_create( &m_recv_block, NULL );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0011W xs-gw-cluster l%05d CreateThread Error", __LINE__ );
   }
#ifndef HL_UNIX
   bos_cluster_init = TRUE;                 /* initialization complete */
#endif

   p_start_80:                              /* initialization complete */
#ifdef HL_UNIX
   if (adsp_cluster_main == NULL) {         /* no cluster configured   */
     goto p_uds_00;                         /* start Unix domain socket */
   }
#endif
   m_set_lb_formula( adsp_cluster_main->achc_lbal_formula, adsp_cluster_main->imc_lbal_len_formula );  /* load-balancing-formula UTF-8 */
   if (adsp_cluster_main->imc_lbal_intv) {  /* <interval-load-balancing-probe> */
     dsg_sys_state_1.imc_load_balancing_value = m_get_load();  /* last value returned by load-balancing */
#ifdef TRACEHL_LOAD
     m_hlnew_printf( HLOG_TRACE1, "p%06d l%05d xs-gw-cluster m_cluster_start() m_get_load() returned %d listen %d.",
                     M_GET_PID, __LINE__, dsg_sys_state_1.imc_load_balancing_value, dsg_sys_state_1.boc_listen_active );
#endif
     dsg_sys_state_1.imc_load_balancing_epoch = m_get_time();  /* time last load-balancing query was done */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster dss_cluster_timer_lbal m_time_set( time=%lld ) m_cluster_start()",
                     __LINE__, (HL_LONGLONG) (adsp_cluster_main->imc_lbal_intv * 1000) );
#ifdef XYZ1
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster dss_cluster_timer_lbal m_time_set( time=%d ) m_cluster_start()",
                     __LINE__, (int) (adsp_cluster_main->imc_lbal_intv * 1000) );
#endif
#endif
     dss_cluster_timer_lbal.dsc_timer_ele.ilcwaitmsec = adsp_cluster_main->imc_lbal_intv * 1000;  /* wait in milliseconds */
     m_time_set( &dss_cluster_timer_lbal.dsc_timer_ele, FALSE );  /* set timer now */
     if (adsp_cluster_main->boc_display_load) {  /* display load every time calculated */
       m_hlnew_printf( HLOG_INFO1, "HWSPCL0030I Cluster current load %d (calculated l%05d)",
                       dsg_sys_state_1.imc_load_balancing_value, __LINE__ );
     }
   }
// ds_acccb.am_acceptcallback = &m_acceptcallback; // accept callback routine
// ds_acccb.am_errorcallback = &m_errorcallback;   // error callback routine
   adss_cluster_main = adsp_cluster_main;   /* save configuration      */
   iml_listen_port = adsp_cluster_main->imc_port;  /* port of listen   */
   usl_port_listen = IP_htons( adsp_cluster_main->imc_port );  /* port of listen */
#ifdef HL_UNIX
   aimrl_ligw_cluster = NULL;               /* structure listen-gateway cluster */
   if (adsg_loconf_1_inuse->boc_listen_gw) {  /* do use listen-gateway */
     iml1 = iml2 = 0;                       /* clear count             */
     adsl_ineta_s_w1 = (struct dsd_ineta_single_1 *) (adsp_cluster_main->adsc_listen_ineta + 1);
     do {                                   /* loop over all listen INETA */
       iml2 += 1 + 2 + 2 + 4;               /* add length structure    */
       if (adsl_ineta_s_w1->usc_family == AF_INET6) {
         iml2 += 16 - 4;                    /* add length structure    */
       }
       adsl_ineta_s_w1
         = (struct dsd_ineta_single_1 *)
             ((char *) (adsl_ineta_s_w1 + 1) + adsl_ineta_s_w1->usc_length);
       iml1++;                              /* count listen            */
     } while (iml1 < adsp_cluster_main->adsc_listen_ineta->imc_no_ineta);
     aimrl_ligw_cluster = (int *) malloc( 2 * sizeof(int) + iml2 );  /* structure listen-gateway cluster */
//   *(aimrl_ligw_cluster + 0) = iml2;      /* set length              */
     achl1 = (char *) (aimrl_ligw_cluster + 2);  /* here first structure */
     usl_port_main = usl_port_listen;       /* port of listen          */
   }
#endif
   iml1 = 0;                                /* clear count             */
   adsl_ineta_s_w1 = (struct dsd_ineta_single_1 *) (adsp_cluster_main->adsc_listen_ineta + 1);

   p_listen_00:                             /* listen next INETA       */
#ifdef HL_UNIX
   adsp_cluster_main->adsc_clli[ iml1 ].boc_unix_socket = FALSE;  /* is not Unix domain socket */
   iml2 = -1;                               /* take original port      */
   if (aimrl_ligw_cluster) {                /* structure listen-gateway cluster */
     memcpy( achl1 + 1, &usl_port_main, 2 );  /* fill structure with original port */
     iml2 = 0;                              /* take other port         */
   }
#endif
   memset( &dsl_soa_listen, 0, sizeof(struct sockaddr_storage) );  /* server address information */
   ((struct sockaddr *) &dsl_soa_listen)->sa_family = adsl_ineta_s_w1->usc_family;
#ifndef B110920

   p_listen_08:                             /* set INETA               */
#endif
   switch (adsl_ineta_s_w1->usc_family) {
     case AF_INET:
       *((UNSIG_MED *) &(((struct sockaddr_in *) &dsl_soa_listen)->sin_addr))
         = *((UNSIG_MED *) (adsl_ineta_s_w1 + 1));
       iml_soadlen = sizeof(struct sockaddr_in);
       ((struct sockaddr_in *) &dsl_soa_listen)->sin_port = usl_port_listen;
#ifdef HL_UNIX
       if (aimrl_ligw_cluster == NULL) break;  /* structure listen-gateway cluster */
       *(achl1 + 0) = (unsigned char) (1 + 2 + 2 + 4);  /* set length structure */
#ifdef B110920
       memcpy( achl1 + 1 + 2 + 2,
               adsl_ineta_s_w1 + 1,
               4 );
#endif
#endif
       break;
     case AF_INET6:
       memcpy( &((struct sockaddr_in6 *) &dsl_soa_listen)->sin6_addr,
               adsl_ineta_s_w1 + 1,
               16 );
       iml_soadlen = sizeof(struct sockaddr_in6);
       ((struct sockaddr_in6 *) &dsl_soa_listen)->sin6_port = usl_port_listen;
#ifdef HL_UNIX
       if (aimrl_ligw_cluster == NULL) break;  /* structure listen-gateway cluster */
       *(achl1 + 0) = (unsigned char) (1 + 2 + 2 + 16);  /* set length structure */
#ifdef B110920
       memcpy( achl1 + 1 + 2 + 2,
               adsl_ineta_s_w1 + 1,
               16 );
#endif
#endif
       break;
     default:
       m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cluster_start( 0X%p ) invalid family",
                       __LINE__, adsp_cluster_main );
       goto p_listen_80;                    /* end of listen           */
   }
#ifdef HL_UNIX
   if (iml2 < 0) {                          /* we use the original port */
     goto p_listen_24;                      /* INETA and port have been set */
   }

   p_listen_20:                             /* try with other port     */
   usl_port_listen = 0;                     /* take any port           */
   if (iml2 < adsp_cluster_main->imc_no_alternate_ports) {  /* number of alternate ports */
     usl_port_listen = IP_htons( adsp_cluster_main->aimc_alternate_ports[ iml2 ] );  /* alternate ports */
#ifdef B110920
     memcpy( achl1 + 1 + 2, &usl_port_listen, 2 );  /* fill structure with real port used */
#endif
   }
   switch (adsl_ineta_s_w1->usc_family) {
     case AF_INET:
       ((struct sockaddr_in *) &dsl_soa_listen)->sin_port = usl_port_listen;
       break;
     case AF_INET6:
       ((struct sockaddr_in6 *) &dsl_soa_listen)->sin6_port = usl_port_listen;
       break;
   }

   p_listen_24:                             /* INETA and port have been set */
#endif
   iml_listen_socket = IP_socket( ((struct sockaddr *) &dsl_soa_listen)->sa_family, SOCK_STREAM, 0 );
   if (iml_listen_socket < 0) {             /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cluster_start() socket Error %d %d.",
                     __LINE__, iml_listen_socket, D_TCP_ERROR );
     goto p_listen_80;                      /* end of listen           */
   }
   /* Bind the socket to the address returned                          */
   iml_rc = IP_bind( iml_listen_socket, (struct sockaddr *) &dsl_soa_listen, iml_soadlen );
   if (iml_rc != 0) {                       /* error occured           */
// to-do 18.09.11 KB sometimes no error message
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cluster_start() bind GW-IN Error %d %d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
     D_TCP_CLOSE( iml_listen_socket );      /* close socket again      */
#ifndef HL_UNIX
     goto p_listen_80;                      /* end of listen           */
#else
     if (iml2 < 0) {                        /* we use the original port */
       goto p_listen_80;                    /* end of listen           */
     }
     if (iml2 >= adsp_cluster_main->imc_no_alternate_ports) {  /* number of alternate ports */
       goto p_listen_80;                    /* end of listen           */
     }
     iml2++;                                /* this port cannot be used */
     goto p_listen_20;                      /* try with other port     */
#endif
   }
#ifdef HL_UNIX
#ifdef B110920
   if (iml2 < adsp_cluster_main->imc_no_alternate_ports) {  /* number of alternate ports */
     goto p_listen_40;                      /* port has been set       */
   }
#endif
#ifndef B110920
   if (iml2 < 0) {                          /* we use the original port */
     goto p_listen_40;                      /* port has been set       */
   }
#endif

   /* we need to retrieve the port is use                              */
   iml_rc = getsockname( iml_listen_socket, (struct sockaddr *) &dsl_soa_listen, &iml_soadlen );
   if (iml_rc != 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cluster_start() getsockname() GW-IN Error %d %d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
     goto p_listen_80;                      /* end of listen           */
   }
   switch (adsl_ineta_s_w1->usc_family) {
     case AF_INET:
       memcpy( achl1 + 1 + 2,
               &((struct sockaddr_in *) &dsl_soa_listen)->sin_port,
               2 );
#ifndef B110920
       memcpy( achl1 + 1 + 2 + 2,
               adsl_ineta_s_w1 + 1,
               4 );
#endif
       break;
     case AF_INET6:
       memcpy( achl1 + 1 + 2,
               &((struct sockaddr_in6 *) &dsl_soa_listen)->sin6_port,
               2 );
#ifndef B110920
       memcpy( achl1 + 1 + 2 + 2,
               adsl_ineta_s_w1 + 1,
               16 );
#endif
       break;
   }
   if (!memcmp( achl1 + 1 + 2, &usl_port_main, 2 )) {  /* compare with original port */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cluster_start() bind port any returned configured port - try again",
                     __LINE__ );
     D_TCP_CLOSE( iml_listen_socket );      /* close socket again      */
#ifndef B110920
     goto p_listen_20;                      /* try again               */
#endif
#ifdef B110920
     goto p_listen_08;                      /* set INETA               */
#endif
   }
   iml_listen_port = (*((unsigned char *) achl1 + 1 + 2 + 0) << 8)
                       | *((unsigned char *) achl1 + 1 + 2 + 1);
#ifdef B170704
   iml_listen_port = ntohs( iml_listen_port );  /* port of listen      */
#endif

   p_listen_40:                             /* port has been set       */
#endif
   iml_rc = IP_listen( iml_listen_socket, adsp_cluster_main->imc_backlog );
   if (iml_rc != 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cluster_start() listen GW-IN Error %d %d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
     D_TCP_CLOSE( iml_listen_socket );      /* close socket again      */
     goto p_listen_80;                      /* end of listen           */
   }
   adsp_cluster_main->adsc_clli[ iml1 ].adsc_cl_main = adsp_cluster_main;
   iml_rc = adsp_cluster_main->adsc_clli[ iml1 ].dsc_acc_listen.mc_startlisten_fix( iml_listen_socket, &dss_acccb, &adsp_cluster_main->adsc_clli[ iml1 ] );
   if (iml_rc != 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cluster_start() mc_startlisten_fix() GW-IN Error %d.",
                     __LINE__, iml_rc );
     D_TCP_CLOSE( iml_listen_socket );      /* close socket again      */
     goto p_listen_80;                      /* end of listen           */
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T listen (IPV6?) started successfully", __LINE__ );
#endif
   m_hlnew_printf( HLOG_INFO1, "HWSPCL0020I Cluster listen started on port %d.",
                   iml_listen_port );       /* port of listen          */
#ifdef HL_UNIX
   if (iml2 >= 0) {                         /* we do not use the original port */
     achl1 += *((unsigned char *) achl1);   /* end of this structure   */
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T listen on port %d started successfully",
                   __LINE__, ntohs( usl_port_listen ) );
#endif
#endif

   p_listen_80:                             /* end of listen           */
   adsl_ineta_s_w1
     = (struct dsd_ineta_single_1 *)
         ((char *) (adsl_ineta_s_w1 + 1) + adsl_ineta_s_w1->usc_length);
   iml1++;                                  /* count listen            */
   if (iml1 < adsp_cluster_main->adsc_listen_ineta->imc_no_ineta) {
     goto p_listen_00;                      /* listen next INETA       */
   }
#ifdef HL_UNIX
   if (aimrl_ligw_cluster == NULL) {        /* structure listen-gateway cluster */
     goto p_uds_00;                         /* start Unix domain socket */
   }
#ifdef XYZ1
   iml1 = achl1 - ((char *) (aimrl_ligw_cluster + 3));
   aimrl_ligw_cluster[ 0 ] = iml1;          /* set length              */
   iml1++;                                  /* add length tag          */
   *((char *) (aimrl_ligw_cluster + 3) - 1) = (unsigned char) ied_ligwq_cluster;  /* cluster message */
   *((char *) (aimrl_ligw_cluster + 3) - 2) = (unsigned char) iml1;  /* length in one byte */
   aimrl_ligw_cluster[ 1 ] = 2;             /* set length prefix       */
   if (iml1 >= 0X0080) {                    /* length in two bytes     */
     *((char *) (aimrl_ligw_cluster + 3) - 3) = (unsigned char) ((iml1 >> 7) | 0X80);  /* first byte length */
     *((char *) (aimrl_ligw_cluster + 3) - 2) = (unsigned char) (iml1 & 0X7F);  /* second byte length */
     aimrl_ligw_cluster[ 1 ] = 3;           /* set length prefix       */
   }
// to-do 18.09.11 KB send to main
#endif
   iml1 = achl1 - ((char *) (aimrl_ligw_cluster + 2));
   aimrl_ligw_cluster[ 0 ] = iml1;          /* set length              */
   *((char *) (aimrl_ligw_cluster + 2) - 1) = (unsigned char) ied_ligwq_cluster;  /* cluster message */
   m_ligw_cluster_struct( aimrl_ligw_cluster );

   p_uds_00:                                /* start Unix domain socket */
   if (adsg_loconf_1_inuse->boc_listen_gw == FALSE) {  /* do use listen-gateway */
     goto p_uds_80;                         /* end of Unix domain socket */
   }
   if (adsp_cluster_main == NULL) {         /* no cluster configured   */
     adss_cluster_main = (struct dsd_cluster_main *) malloc( sizeof(struct dsd_cluster_main) );
     memset( adss_cluster_main, 0, sizeof(struct dsd_cluster_main) );
   }
   adss_clli_uds = (struct dsd_cluster_listen *) malloc( sizeof(struct dsd_cluster_listen) );  /* cluster structure listen Unix domain socket */
   memset( adss_clli_uds, 0,  sizeof(struct dsd_cluster_listen) );  /* clear memory */
   adss_clli_uds->boc_unix_socket = TRUE;   /* is Unix domain socket   */
   memset( &dsl_soa_listen, 0, sizeof(struct sockaddr_storage) );  /* server address information */

#define ADSL_SOA_UN ((struct sockaddr_un *) &dsl_soa_listen)

   ADSL_SOA_UN->sun_family = AF_LOCAL;
   achl1 = stpcpy( ADSL_SOA_UN->sun_path, D_NAME_UDS_WSP );
   iml1 = sizeof(ADSL_SOA_UN->sun_path) - (sizeof(D_NAME_UDS_WSP) - 1) - D_LENGTH_UDS_TAIL - 1;
   if (iml1 > D_LENGTH_UDS_MAX) iml1 = D_LENGTH_UDS_MAX;
   achl2 = ADSL_SOA_UN->sun_path + iml1;
   memcpy( achl2, D_NAME_UDS_TAIL, D_LENGTH_UDS_TAIL + 1 );
   iml1 = getpid();                         /* get our process ID      */
   iml2 = 10;                               /* maximum number of digits */
   do {                                     /* loop output digits      */
     *(--achl2) = (iml1 % 10) + '0';        /* one digit               */
     iml1 /= 10;                            /* divide value            */
     iml2--;                                /* decrement index         */
   } while (iml2 > 0);
   iml1 = achl2 - achl1;
   if (iml1 > 0) {                          /* we need more characters */
     memset( achl1, '$', iml1 );
   }
   iml_listen_socket = IP_socket( AF_LOCAL, SOCK_STREAM, 0 );
   if (iml_listen_socket < 0) {             /* could not create socket */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cluster_start() Unix domain socket Error %d %d.",
                     __LINE__, iml_listen_socket, D_TCP_ERROR );
     free( adss_clli_uds );                 /* free memory again       */
     adss_clli_uds = NULL;                  /* no listen               */
     goto p_uds_80;                         /* end of Unix domain socket */
   }
   iml_rc = unlink( ADSL_SOA_UN->sun_path );
   if (iml_rc < 0) {                        /* error occured           */
     if (errno != ENOENT) {                 /* not No such file or directory */
       m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cluster_start() unlink Unix socket domain name \"%s\" returned %d %d.",
                       __LINE__, ADSL_SOA_UN->sun_path, iml_rc, D_TCP_ERROR );
     }
   }
   iml_rc = IP_bind( iml_listen_socket, (struct sockaddr *) &dsl_soa_listen, sizeof(struct sockaddr_un) );
   if (iml_rc != 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cluster_start() bind Unix domain socket Error %d %d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
     D_TCP_CLOSE( iml_listen_socket );      /* close socket again      */
     free( adss_clli_uds );                 /* free memory again       */
     adss_clli_uds = NULL;                  /* no listen               */
     goto p_uds_80;                         /* end of Unix domain socket */
   }
   iml_rc = IP_listen( iml_listen_socket, D_LIGW_UDS_WSP_BACKLOG );
   if (iml_rc != 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cluster_start() listen Unix domain socket Error %d %d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
     D_TCP_CLOSE( iml_listen_socket );      /* close socket again      */
     free( adss_clli_uds );                 /* free memory again       */
     adss_clli_uds = NULL;                  /* no listen               */
     goto p_uds_80;                         /* end of Unix domain socket */
   }
   iml_rc = adss_clli_uds->dsc_acc_listen.mc_startlisten_fix( iml_listen_socket, &dss_acccb, adss_clli_uds );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T listen Unix domain socket started successfully", __LINE__ );
#endif

#undef ADSL_SOA_UN

   p_uds_80:                                /* end of Unix domain socket */
   if (adsp_cluster_main == NULL) return;   /* no cluster configured   */
#endif

#ifdef CHECK_QUALITY_DOUBLE
#ifndef HL_UNIX
   Sleep( 5 * 1000 );                       /* wait for other cluster member */
#else
   sleep( 5 );                              /* wait for other cluster member */
#endif
#endif

   /* connect all remote WSPs                                          */
   adsl_clrem_w1 = adsp_cluster_main->adsc_clre;  /* chain of remote WSPs */

   pconn_00:                                /* start connect           */
   if (adsl_clrem_w1 == NULL) return;       /* all done                */
   adsl_clact_w1 = adsg_clact_ch;           /* get chain of active cluster entries */
   while (adsl_clact_w1) {                  /* loop over all active cluster entries */
     if (   (adsl_clact_w1->adsc_clrem == NULL)
         && (adsl_clrem_w1->imc_len_name == adsl_clact_w1->imc_len_config_name)
         && (!memcmp( adsl_clrem_w1->achc_name,
                      adsl_clact_w1->achc_config_name,
                      adsl_clrem_w1->imc_len_name ))) {
       adsl_clact_w1->adsc_clrem = adsl_clrem_w1;  /* found cluster remote structure */
       goto pconn_20;                       /* connect to next remote WSP */
     }
     adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
   }
   adsl_clact_w1 = (struct dsd_cluster_active *) malloc( sizeof(struct dsd_cluster_active) );
   memset( adsl_clact_w1, 0, sizeof(struct dsd_cluster_active) );
   adsl_clact_w1->imc_time_start = m_get_time();  /* time connection started */
   adsl_clact_w1->imc_time_recv = m_get_time();  /* time last received data */
   adsl_clact_w1->imc_lbal_load = -1;       /* no load received yet    */
   m_set_clact_chain( adsl_clact_w1 );      /* put in chain            */
   adsl_clact_w1->adsc_clrem = adsl_clrem_w1;  /* cluster remote structure */
#ifdef OLD01
   m_do_connect( adsl_clact_w1 );           /* do connect now          */
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T m_cluster_start() call m_startco_mh() &dsc_tcpcomp=%p vpp_userfld=%p.",
                   __LINE__, &adsl_clact_w1->dsc_tcpcomp, adsl_clact_w1 );
#endif
   iml_rc = adsl_clact_w1->dsc_tcpcomp.m_startco_mh(
              &dss_tcpco1_cb1,
              adsl_clact_w1,
              &adsl_clact_w1->adsc_clrem->dsc_bind_multih,  /* for bind multihomed */
              adsl_clact_w1->adsc_clrem->adsc_remote_ineta,  /* remote INETA */
#ifndef B121120
              NULL,                         /* INETA to free           */
#endif
              adsl_clact_w1->adsc_clrem->imc_port,  /* port of remote WSP */
              TRUE );                       /* do connect round-robin <connect-round-robin> */
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cluster_start() m_startco_mh() failed %d.",
                     __LINE__, iml_rc );
//   goto p_conn_80;                        /* close session to client */
// 29.09.07 KB - to-do
   }

   pconn_20:                                /* connect to next remote WSP */
   adsl_clrem_w1 = adsl_clrem_w1->adsc_next;  /* get next in chain     */
   goto pconn_00;                           /* start next connect      */
} /* end m_cluster_start()                                             */

/** non-blocking accept error callback routine                         */
static void m_acc_errorcallback( class dsd_nblock_acc *, void *, char *, int, int ) // Error callback function.
{
   m_hlnew_printf( HLOG_WARN1, "HWSPCL0nnnW xs-gw-cluster-l%05d Cluster m_acc_errorcallback() called",
                   __LINE__ );
} /* end m_acc_errorcallback()                                         */

/** non-blocking accept - accept callback routine                      */
static void m_acceptcallback( class dsd_nblock_acc * dsp_nbacc, void * vpp_userfld, int imp_socket, struct sockaddr *adsp_soa, int imp_len_soa ) {
   int        iml_rc;                       /* return code             */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster structure */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_acceptcallback() called",
                   __LINE__ );
#endif
#ifdef HL_UNIX
#define ADSL_CLLI_G ((struct dsd_cluster_listen *) vpp_userfld)
#endif
   adsl_clact_w1 = (struct dsd_cluster_active *) malloc( sizeof(struct dsd_cluster_active) );
   memset( adsl_clact_w1, 0, sizeof(struct dsd_cluster_active) );
   adsl_clact_w1->imc_time_start = m_get_time();  /* time connection started */
   adsl_clact_w1->imc_time_recv = m_get_time();  /* time last received data */
   adsl_clact_w1->imc_lbal_load = -1;       /* no load received yet    */
#ifdef HL_UNIX
   adsl_clact_w1->boc_unix_socket = ADSL_CLLI_G->boc_unix_socket;  /* is Unix domain socket */
#endif
#ifdef OLD01
   adsl_clact_w1->imc_ind_conn = -1;        /* not connect active      */
#endif
   m_set_clact_chain( adsl_clact_w1 );      /* put in chain            */
#ifdef HL_UNIX
   if (adsl_clact_w1->boc_unix_socket) {    /* is Unix domain socket   */
     adsl_clact_w1->boc_same_group = TRUE;  /* is in same group as main */
     strcpy( adsl_clact_w1->chrc_ineta, "local" );
     goto p_cb_acc_20;                      /* display connect in      */
   }
#endif
   memcpy( &adsl_clact_w1->dsc_soa, adsp_soa, imp_len_soa );
   iml_rc = IP_getnameinfo( (struct sockaddr *) adsp_soa, imp_len_soa,
                            adsl_clact_w1->chrc_ineta, sizeof(adsl_clact_w1->chrc_ineta), 0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0nnnW xs-gw-cluster-l%05d Cluster acceptcallback getnameinfo() returned %d %d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
     strcpy( adsl_clact_w1->chrc_ineta, "XXX" );
   }

#ifdef HL_UNIX
   p_cb_acc_20:                             /* display connect in      */
#endif
   m_hlnew_printf( HLOG_INFO1, "HWSPCL0040I Cluster INETA=%s connect in",
                   adsl_clact_w1->chrc_ineta );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T m_acceptcallback() call m_startco_fb() &dsc_tcpcomp=%p vpp_userfld=%p.",
                   __LINE__, &adsl_clact_w1->dsc_tcpcomp, adsl_clact_w1 );
#endif
   iml_rc = adsl_clact_w1->dsc_tcpcomp.m_startco_fb( imp_socket,
                                                     &dss_tcpco1_cb1,
                                                     adsl_clact_w1 );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-cluster-l%05d-E m_startco_fb() failed",
                     __LINE__ );
     D_TCP_CLOSE( imp_socket );             /* close socket again */
//   goto p_conn_80;                        /* close session to client */
// 29.09.07 KB - to-do
     return;                                /* all done                */
   }
#ifdef HL_UNIX
   if (adsl_clact_w1->boc_unix_socket == FALSE) {  /* is not Unix domain socket */
#endif
#ifndef NO_DISABLE_NAEGLE
   adsl_clact_w1->dsc_tcpcomp.mc_set_nodelay( 1 );
#endif
   if (adsg_loconf_1_inuse->imc_tcp_sndbuf) {  /* set TCP SNDBUF   */
     adsl_clact_w1->dsc_tcpcomp.mc_set_sndbuf( adsg_loconf_1_inuse->imc_tcp_sndbuf );
   }
   if (adsg_loconf_1_inuse->imc_tcp_rcvbuf) {  /* set TCP RCVBUF   */
     adsl_clact_w1->dsc_tcpcomp.mc_set_rcvbuf( adsg_loconf_1_inuse->imc_tcp_rcvbuf );
   }
   if (adsg_loconf_1_inuse->boc_tcp_keepalive) {  /* set TCP KEEPALIVE */
     adsl_clact_w1->dsc_tcpcomp.mc_set_keepalive( TRUE );
   }
#ifdef HL_UNIX
   }
#endif
   adsl_clact_w1->iec_clr_stat = ied_clrs_acc_recv_st;  /* after accept start receive */
   adsl_clact_w1->boc_recv_active = TRUE;   /* receive is active       */
   adsl_clact_w1->dsc_tcpcomp.m_recv();     /* start receiving         */
   return;
} /* end m_acceptcallback()                                            */

/** error message when TCPCOMP connect failed                          */
static void m_cb_conn_err( class dsd_tcpcomp *adsp_tcpco, void * vpp_userfld,
   struct sockaddr *adsp_soa, socklen_t imp_len_soa, int imp_current_index, int imp_total_index, int imp_errno ) {
   int        iml_rc;                       /* return code             */
   char       *achl1;                       /* working variable        */
   char       chrl_ineta[ LEN_DISP_INETA ];  /* internet-address char  */

#define ADSL_CLACT_G ((struct dsd_cluster_active *) vpp_userfld)
   iml_rc = getnameinfo( adsp_soa, imp_len_soa,
                         chrl_ineta, sizeof(chrl_ineta),
                         0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cb_conn_err() target cluster %.*(u8)s getnameinfo() returned %d %d.",
                     __LINE__,
                     ADSL_CLACT_G->adsc_clrem->imc_len_name,
                     ADSL_CLACT_G->adsc_clrem->achc_name,
                     iml_rc, D_TCP_ERROR );
     strcpy( chrl_ineta, "???" );
   }
   achl1 = ".";
   if ((imp_current_index + 1) < imp_total_index) {
     achl1 = " - try next INETA from DNS";  /* set additional text     */
   } else if (imp_total_index > 1) {
     achl1 = " - was last INETA from DNS";  /* set additional text     */
   }
   m_hlnew_printf( HLOG_WARN1, "HWSPCL0002W xs-gw-cluster l%05d connect to target cluster %.*(u8)s INETA %s failed %d%s",
                   __LINE__,
                   ADSL_CLACT_G->adsc_clrem->imc_len_name,
                   ADSL_CLACT_G->adsc_clrem->achc_name,
                   chrl_ineta, imp_errno, achl1 );
   m_check_reco_cluster();                  /* set timer for reconnect */
   return;
#undef ADSL_CLACT_G
} /* end m_cb_conn_err()                                               */

/** TCPCOMP connect callback function                                  */
static void m_conncallback( class dsd_tcpcomp *adsp_tcpco, void *vpp_userfld,
#ifndef B121120
                            struct dsd_target_ineta_1 *, void *,
#endif
                            struct sockaddr *adsp_soa, socklen_t imp_len_soa, int imp_error ) {
   int        iml_rc;                       /* return code             */
   struct dsd_cluster_active *adsl_clact;   /* active cluster entry    */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_conncallback( 0X%p 0X%p 0X%p %d %d ) called",
                   __LINE__, adsp_tcpco, vpp_userfld, adsp_soa, imp_len_soa, imp_error );
#endif
   if (imp_error) return;                   /* connect was not successful */
#ifndef NO_DISABLE_NAEGLE
   adsp_tcpco->mc_set_nodelay( 1 );
#endif
   adsl_clact = (struct dsd_cluster_active *) vpp_userfld;
   memcpy( &adsl_clact->dsc_soa, adsp_soa, imp_len_soa );
   iml_rc = getnameinfo( adsp_soa, imp_len_soa,
                         adsl_clact->chrc_ineta, sizeof(adsl_clact->chrc_ineta),
                         0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d getnameinfo() returned %d %d.",
             __LINE__, iml_rc, D_TCP_ERROR );
     strcpy( adsl_clact->chrc_ineta, "???" );
   }
#ifdef OLD01
   adsl_clact->imc_ind_conn = -1;           /* connect successful      */
#endif
#ifndef NO_DISABLE_NAEGLE
   adsl_clact->dsc_tcpcomp.mc_set_nodelay( 1 );
#endif
   if (adsg_loconf_1_inuse->imc_tcp_sndbuf) {  /* set TCP SNDBUF   */
     adsl_clact->dsc_tcpcomp.mc_set_sndbuf( adsg_loconf_1_inuse->imc_tcp_sndbuf );
   }
   if (adsg_loconf_1_inuse->imc_tcp_rcvbuf) {  /* set TCP RCVBUF   */
     adsl_clact->dsc_tcpcomp.mc_set_rcvbuf( adsg_loconf_1_inuse->imc_tcp_rcvbuf );
   }
   if (adsg_loconf_1_inuse->boc_tcp_keepalive) {  /* set TCP KEEPALIVE */
     adsl_clact->dsc_tcpcomp.mc_set_keepalive( TRUE );
   }
   adsl_clact->iec_clr_stat = ied_clrs_conn_recv_st;  /* after connect start receive */
   adsl_clact->boc_recv_active = TRUE;      /* receive is active       */
   adsl_clact->dsc_tcpcomp.m_recv();        /* start receiving         */
   m_send_control_init( adsl_clact );
} /* end m_conncallback()                                              */

/** TCPCOMP send callback function                                     */
static void m_sendcallback( class dsd_tcpcomp *adsp_tcpco, void *vpp_userfld ) {
   int        iml1;                         /* working variable        */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster structure */
   struct dsd_cluster_send *adsl_clsend_cur;  /* current in chain      */
   struct dsd_cluster_send *adsl_clsend_last;  /* last in chain        */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* gather input data       */

   adsl_clact_w1 = (struct dsd_cluster_active *) vpp_userfld;  /* active cluster structure */
// if (adsl_clact_w1->iec_clr_stat != ied_clrs_open) {  /* state is not open */
//   return;
// }
#ifndef B130408
   if (adsl_clact_w1->iec_clr_stat == ied_clrs_closed) return;  /* state is closed */
#endif
   if (adsl_clact_w1->adsc_send_ch == NULL) return;

   p_send:                                  /* send data to cluster member */
   iml1 = adsl_clact_w1->dsc_tcpcomp.m_send_gather(
            (struct dsd_gather_i_1 *) adsl_clact_w1->adsc_send_ch->vprc_work_area,
            &adsl_gai1_w1 );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_sendcallback() m_send_gather() returned %d adsl_gai1_w1=%p adsl_clact_w1->adsc_send_ch->vprc_work_area=%p.",
                   __LINE__, iml1, adsl_gai1_w1, adsl_clact_w1->adsc_send_ch->vprc_work_area );
   if ((struct dsd_gather_i_1 *) adsl_clact_w1->adsc_send_ch->vprc_work_area) {
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_sendcallback() m_send_gather() returned %d adsl_gai1_w1=%p achc_ginp_cur=%p achc_ginp_end=%p.",
                     __LINE__, iml1,
                     ((struct dsd_gather_i_1 *) adsl_clact_w1->adsc_send_ch->vprc_work_area)->achc_ginp_cur,
                     ((struct dsd_gather_i_1 *) adsl_clact_w1->adsc_send_ch->vprc_work_area)->achc_ginp_end );
   }
#endif
   if (iml1 > 0) {                          /* data sent               */
     adsl_clact_w1->imc_stat_no_send++;     /* statistic number of sends */
     adsl_clact_w1->ilc_stat_len_send += iml1;  /* statistic length of sends */
   }
   if (adsl_gai1_w1) {
     adsl_clact_w1->dsc_tcpcomp.m_sendnotify();
     return;
   }
   adsl_clsend_cur = adsl_clact_w1->adsc_send_ch;  /* get anchor of chain */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX2T l%05d m_enter() before", __LINE__ );
#endif
   dss_critsect_cluster.m_enter();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX3T l%05d m_enter() after", __LINE__ );
#endif
   adsl_clsend_last = adsl_clsend_cur->adsc_next;  /* get next in chain */
   adsl_clact_w1->adsc_send_ch = adsl_clsend_last;  /* remove from chain */
   dss_critsect_cluster.m_leave();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX4T l%05d m_leave() after", __LINE__ );
#endif
   adsl_clsend_cur->amc_compl( adsl_clsend_cur );   /* call completition routine */
   if (adsl_clsend_last) {                  /* more data to send       */
     goto p_send;                           /* send data to cluster member */
   }
} /* end m_sendcallback()                                              */

/** TCPCOMP get receive buffer callback function                       */
static int m_getrecvbuf( class dsd_tcpcomp *adsp_tcpco, void *vpp_userfld, void **aap_handle, char **aachp_buffer, int **aimp_len_recv ) {
   struct dsd_cluster_recv *adsl_clrecv_w1;  /* block received from cluster member */

   adsl_clrecv_w1 = (struct dsd_cluster_recv *) m_proc_alloc();  /* acquire memory */
   adsl_clrecv_w1->adsc_clact = (struct dsd_cluster_active *) vpp_userfld;
   adsl_clrecv_w1->imc_usage_count = 0;     /* clear usage count       */
   *aap_handle = adsl_clrecv_w1;            /* return handle           */
   *aachp_buffer = (char *) (adsl_clrecv_w1 + 1);
   *aimp_len_recv = &adsl_clrecv_w1->imc_len_recv;  /* length received */
   return LEN_TCP_RECV - sizeof(struct dsd_cluster_recv);
} /* end m_getrecvbuf()                                                */

#ifdef TCPCOMP_V02
static void m_cl_tcpc_freebuf( class dsd_tcpcomp *adsp_tcpco,
                               void * vpp_userfld,
                               void * avop_handle ) {
   m_proc_free( avop_handle );
} /* end m_cl_tcpc_freebuf()                                           */
#endif

/** TCPCOMP receive callback function                                  */
static BOOL m_recvcallback( class dsd_tcpcomp *adsp_tcpco, void *vpp_userfld, void *ap_handle ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working variables       */
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_cluster_recv *adsl_clrecv_cur;  /* current in chain      */
   struct dsd_cluster_recv *adsl_clrecv_last;  /* last in chain        */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster entry  */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_recvcallback( 0X%p , 0X%p , 0X%p ) called",
                   __LINE__, adsp_tcpco, vpp_userfld, ap_handle );
#endif

#define ADSL_CLRECV_G ((struct dsd_cluster_recv *) ap_handle)

   if (ADSL_CLRECV_G == NULL) return FALSE;  /* no data received       */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_recvcallback() ADSL_CLRECV_G=%p imc_len_recv=%d.",
                   __LINE__, ADSL_CLRECV_G, ADSL_CLRECV_G->imc_len_recv );
   if (ADSL_CLRECV_G->imc_len_recv > 0) {
     m_console_out( (char *) (ADSL_CLRECV_G + 1), ADSL_CLRECV_G->imc_len_recv );
   }
#endif

#define ADSL_CLACT_G ((struct dsd_cluster_active *) vpp_userfld)

#ifdef DEBUG_120912_01                      /* receiving loops         */
   if (ADSL_CLACT_G->boc_recv_active == FALSE) {  /* receive is not active */
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_recvcallback() boc_recv_active == FALSE ADSL_CLRECV_G->imc_len_recv=%d.",
                     __LINE__, ADSL_CLRECV_G->imc_len_recv );
   }
#endif
   ADSL_CLACT_G->imc_time_recv = m_get_time();  /* time last received data */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_CLUSTER) {  /* core cluster */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CCLURECV", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
//   adsl_wt1_w1->imc_wtrt_sno = 0;         /* WSP session number      */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "data received from cluster-member %s length %d/0X%X.",
                     ADSL_CLACT_G->chrc_ineta, ADSL_CLRECV_G->imc_len_recv, ADSL_CLRECV_G->imc_len_recv );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (   (ADSL_CLRECV_G->imc_len_recv > 0)  /* data received        */
         && (img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2))) {  /* generate WSP trace record */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml1 = ADSL_CLRECV_G->imc_len_recv;  /* length of data received */
       achl_w3 = (char *) (ADSL_CLRECV_G + 1);  /* start of data       */
       adsl_wt1_w2 = adsl_wt1_w1;           /* in this piece of memory */
       adsl_wtr_w1 = ADSL_WTR_G1;           /* set last in chain       */
       bol1 = FALSE;                        /* clear more flag         */
       do {                                 /* loop always with new struct dsd_wsp_trace_record */
         achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
         if ((achl_w1 + sizeof(struct dsd_wsp_trace_record)) >= achl_w2) {
           adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
           memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
           adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
           adsl_wt1_w2 = adsl_wt1_w3;       /* this is current network */
           achl_w1 = (char *) (adsl_wt1_w2 + 1);
           achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
         }
         memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
         ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
         achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
         ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
         adsl_wtr_w1->boc_more = bol1;      /* more data to follow     */
         adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain     */
         adsl_wtr_w1 = ADSL_WTR_G2;         /* this is last in chain now */
         iml2 = achl_w2 - achl_w4;
         if (iml2 > iml1) iml2 = iml1;
         memcpy( achl_w4, achl_w3, iml2 );
         achl_w4 += iml2;
         achl_w3 += iml2;
         ADSL_WTR_G2->imc_length = iml2;    /* length of text / data   */
         iml1 -= iml2;                      /* length to be copied     */
         achl_w1 = achl_w2;                 /* set end of this area    */
         bol1 = TRUE;                       /* set more flag           */
       } while (iml1 > 0);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (ADSL_CLRECV_G->imc_len_recv <= 0) {
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_recvcallback() length %d.",
                     __LINE__, ADSL_CLRECV_G->imc_len_recv );
// 09.10.07 KB to-do CMA close
     m_proc_free( ADSL_CLRECV_G );          /* free block used         */
     ADSL_CLACT_G->iec_clr_stat = ied_clrs_closed;  /* state is closed */
     bol1 = FALSE;                          /* no data to append to chain */
   } else {
     ADSL_CLACT_G->imc_stat_no_recv++;      /* increment statistic number of receives */
     ADSL_CLACT_G->ilc_stat_len_recv += ADSL_CLRECV_G->imc_len_recv;  /* statistic length of receives */
     if (ADSL_CLACT_G->iec_clr_stat == ied_clrs_closed) {  /* state is closed */
       m_proc_free( ADSL_CLRECV_G );        /* free block used         */
       return FALSE;
     }
     ADSL_CLRECV_G->adsc_next = NULL;       /* clear chain             */
     bol1 = TRUE;                           /* append to chain         */
   }
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX2T l%05d m_enter() before", __LINE__ );
#endif
   dss_critsect_cluster.m_enter();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX3T l%05d m_enter() after", __LINE__ );
#endif
   if (bol1) {                              /* append to chain         */
     if (ADSL_CLACT_G->adsc_recv_ch == NULL) {  /* chain of received buffers */
       ADSL_CLACT_G->adsc_recv_ch = ADSL_CLRECV_G;  /* set only in chain */
     } else {                               /* append to chain         */
       adsl_clrecv_cur = ADSL_CLACT_G->adsc_recv_ch;  /* get first in chain */
       do {                                 /* loop over chain         */
         adsl_clrecv_last = adsl_clrecv_cur;  /* save current entry    */
         adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
       } while (adsl_clrecv_cur);
       adsl_clrecv_last->adsc_next = ADSL_CLRECV_G;  /* append to chain */
     }
   }
   ADSL_CLACT_G->boc_recv_active = FALSE;   /* receive is active       */
   bol1 = ADSL_CLACT_G->boc_proc_active;    /* processing is active    */
   if (bol1 == FALSE) {                     /* not yet in chain to get processed */
     ADSL_CLACT_G->boc_proc_active = TRUE;  /* processing is active    */
     ADSL_CLACT_G->adsc_proc_ch = NULL;     /* next in chain to get processed */
     if (adss_clact_proc_ch == NULL) {      /* chain to get processed */
       adss_clact_proc_ch = ADSL_CLACT_G;   /* set chain to get processed */
     } else {                               /* append to chain         */
       adsl_clact_w1 = adss_clact_proc_ch;  /* get chain to get processed */
       while (adsl_clact_w1->adsc_proc_ch) adsl_clact_w1 = adsl_clact_w1->adsc_proc_ch;
       adsl_clact_w1->adsc_proc_ch = ADSL_CLACT_G;  /* append to chain to get processed */
       bol1 = TRUE;                         /* thread already active   */
     }
   }
   dss_critsect_cluster.m_leave();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX4T l%05d m_leave() after", __LINE__ );
#endif
   if (bol1) return FALSE;                  /* do not start processing */
   iml_rc = dss_event_cluster.m_post( &iml_error );  /* event for cluster thread */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0012W xs-gw-cluster l%05d event m_post Return Code %d Error %d.",
                     __LINE__, iml_rc, iml_error );
   }
   return FALSE;
#undef ADSL_CLACT_G
#undef ADSL_CLRECV_G
} /* end m_recvcallback()                                              */

/** TCPCOMP error callback function                                    */
static void m_errorcallback( dsd_tcpcomp *adsp_tcpco, void *vpp_userfld, char *achp_errmsg, int imp_error, int imp_where ) {
   char       *achl1;                       /* working-variable        */
   struct dsd_cluster_active *adsl_clact;   /* active cluster entry    */
#ifdef OLD01
   int        iml_rc;                       /* return code             */
   char       *achl1;                       /* working variable        */
   socklen_t  iml_namelen;                  /* length of name          */
   struct sockaddr_storage dsl_soa_conn;    /* address information for connect */
   char       chrl_server_ineta[ LEN_DISP_INETA ];  /* for server INETA */
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T m_errorcallback() called imp_error=%d",
                   __LINE__, imp_error );
#endif
   adsl_clact = (struct dsd_cluster_active *) vpp_userfld;
   achl1 = "???";
   if (adsl_clact) achl1 = adsl_clact->chrc_ineta;
// m_hl1_printf("%s\nError number: %d. At Location %d", str_error, imp_error, im_where );
   m_hlnew_printf( HLOG_WARN1, "HWSPCL0003W Cluster INETA=%s TCP error %d at %d / %s.",
                   achl1, imp_error, imp_where, achp_errmsg );
} /* m_errorcallback()                                                 */

/** TCPCOMP cleanup callback function                                  */
static void m_cleanup( dsd_tcpcomp *adsp_tcpco, void *vpp_userfld ) {
   int        iml1, iml2, iml3, iml4, iml5;  /* working variables      */
   enum ied_clr_stat iel_clr_stat;          /* state of connection     */
   char       *achl1;                       /* working variable        */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster entry  */
   struct dsd_cluster_active *adsl_clact_cur;  /* active cluster entry */
   struct dsd_cluster_active *adsl_clact_last;  /* active cluster entry */
#ifdef B120911
   struct dsd_cluster_recv *adsl_clrecv_w1;  /* block received from cluster member */
   struct dsd_cluster_send *adsl_clsend_w1;  /* send buffer            */
#endif
   char       chrl_ns_1[320];               /* for network-statistic   */
   char       chrl_ns_num[16];              /* for number              */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T m_cleanup() called",
                   __LINE__ );
#endif
   adsl_clact_w1 = (struct dsd_cluster_active *) vpp_userfld;
   iel_clr_stat = adsl_clact_w1->iec_clr_stat;  /* save status         */
   adsl_clact_w1->iec_clr_stat = ied_clrs_closed;  /* state is closed  */
   if (adsl_clact_w1->vpc_cma_entry) {      /* field for CMA entry     */
     m_cma1_cluster_close( adsl_clact_w1 );  /* connection closed      */
   }
   if (iel_clr_stat != ied_clrs_invalid) {  /* state is not invalid    */
     achl1 = "";                            /* empty string            */
     if (adsg_loconf_1_inuse->inc_network_stat >= 3) {  /* give network statistic */
       iml2 = m_get_time() - adsl_clact_w1->imc_time_start;
       iml3 = iml2 / 3600;
       iml5 = iml2 - iml3 * 3600;
       iml4 = iml5 / 60;
       iml5 -= iml4 * 60;
       iml1 = sprintf( chrl_ns_1, " / duration: %d h %d min %d sec", iml3, iml4, iml5 );
       achl1 = m_edit_dec_int( chrl_ns_num, adsl_clact_w1->imc_stat_no_recv );
       iml1 += sprintf( chrl_ns_1 + iml1, " / rec %s", achl1 );
       achl1 = m_edit_dec_long( chrl_ns_num, adsl_clact_w1->ilc_stat_len_recv );
       iml1 += sprintf( chrl_ns_1 + iml1, " - %s bytes", achl1 );
       achl1 = m_edit_dec_int( chrl_ns_num, adsl_clact_w1->imc_stat_no_send );
       iml1 += sprintf( chrl_ns_1 + iml1, " + send %s", achl1 );
       achl1 = m_edit_dec_long( chrl_ns_num, adsl_clact_w1->ilc_stat_len_send );
       iml1 += sprintf( chrl_ns_1 + iml1, " - %s bytes", achl1 );
       achl1 = chrl_ns_1;                   /* string with statistic   */
     }
     m_hlnew_printf( HLOG_INFO1, "HWSPCL0050I Cluster INETA=%s session ended%s",
                     adsl_clact_w1->chrc_ineta, achl1 );
   }
   /* remove from chain                                                */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX2T l%05d m_enter() before", __LINE__ );
#endif
   dss_critsect_cluster.m_enter();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX3T l%05d m_enter() after", __LINE__ );
#endif
   adsl_clact_cur = adsg_clact_ch;          /* get anchor of chain     */
   if (adsg_clact_ch == adsl_clact_w1) {    /* is at anchor of chain   */
     adsg_clact_ch = adsl_clact_w1->adsc_next;  /* remove from chain   */
   } else {                                 /* middle in chain         */
     do {                                   /* loop over chain active cluster */
       adsl_clact_last = adsl_clact_cur;    /* save entry              */
       adsl_clact_cur = adsl_clact_cur->adsc_next;  /* get next in chain */
       if (adsl_clact_cur == adsl_clact_w1) break;  /* element found   */
     } while (adsl_clact_cur);
     if (adsl_clact_cur) {                  /* element found           */
       adsl_clact_last->adsc_next = adsl_clact_w1->adsc_next;  /* remove from chain */
     }
   }
   dss_critsect_cluster.m_leave();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX4T l%05d m_leave() after", __LINE__ );
#endif
   if (adsl_clact_cur == NULL) {            /* element not found in chain */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cleanup() session not found in chain",
                     __LINE__ );
   }
#ifdef B120911
// to-do 19.06.12 KB - free after timer has elapsed
   if (adsl_clact_w1->imc_len_server_name) {  /* length server name    */
     free( adsl_clact_w1->achc_server_name );  /* free old memory      */
   }
   if (adsl_clact_w1->imc_len_query_main) {  /* length query main      */
     free( adsl_clact_w1->achc_query_main );  /* free old memory       */
   }
   if (adsl_clact_w1->imc_len_config_name) {  /* length configuration name */
     free( adsl_clact_w1->achc_config_name );  /* free old memory      */
   }
   if (adsl_clact_w1->imc_len_group) {      /* length configuration group */
     free( adsl_clact_w1->achc_group );     /* free old memory         */
   }
   if (adsl_clact_w1->imc_len_location) {   /* length configuration location */
     free( adsl_clact_w1->achc_location );  /* free old memory         */
   }
   if (adsl_clact_w1->imc_len_url) {        /* length configuration URL */
     free( adsl_clact_w1->achc_url );       /* free old memory         */
   }
   while (adsl_clact_w1->adsc_recv_ch) {    /* chain of received buffers */
     adsl_clrecv_w1 = adsl_clact_w1->adsc_recv_ch;  /* get old chain of received buffers */
     adsl_clact_w1->adsc_recv_ch = adsl_clact_w1->adsc_recv_ch->adsc_next;  /* set new chain of received buffers */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_cleanup() m_proc_free %p.",
                     __LINE__, adsl_clrecv_w1 );
#endif
     m_proc_free( adsl_clrecv_w1 );         /* free this block         */
   }
   while (adsl_clact_w1->adsc_send_ch) {    /* chain of send buffers   */
     adsl_clsend_w1 = adsl_clact_w1->adsc_send_ch;  /* get old chain of send buffers */
     adsl_clact_w1->adsc_send_ch = adsl_clact_w1->adsc_send_ch->adsc_next;  /* set new chain of send buffers */
     m_proc_free( adsl_clsend_w1 );         /* free this block         */
   }
// 09.10.07 KB to-do free all buffers
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_cleanup() free( adsl_clact_w1=%p )",
                   __LINE__, adsl_clact_w1 );
#endif
#ifdef B120827
   free( adsl_clact_w1 );                   /* free memory active cluster */
#else
#define ADSL_TIMER_ELE_G (&adsl_clact_w1->dsc_timer_ele)
   memset( ADSL_TIMER_ELE_G, 0, sizeof(struct dsd_timer_ele) );
   ADSL_TIMER_ELE_G->amc_compl = &m_timer_free_clact;   /* set routine for free memory */
   ADSL_TIMER_ELE_G->ilcwaitmsec = DEF_CLUSTER_WAIT_FREE * 1000;  /* wait in milliseconds */
   m_time_set( ADSL_TIMER_ELE_G, FALSE );   /* set timeout now */
#undef ADSL_TIMER_ELE_G
#endif
#ifdef B120910
#ifdef B120830
   if (iel_clr_stat != ied_clrs_open) return;  /* state was not open   */
#else
   if (   (iel_clr_stat != ied_clrs_open)   /* state was not open      */
       && (iel_clr_stat != ied_clrs_timed_out)) {  /* state is timed out */
     return;
   }
#endif
   m_status_cluster_lbal();                 /* do load-balancing again */
   m_check_reco_cluster();                  /* set timer for reconnect */
#else
   if (   (iel_clr_stat == ied_clrs_open)   /* state was open          */
       || (iel_clr_stat == ied_clrs_timed_out)) {  /* state is timed out */
     m_status_cluster_lbal( FALSE );        /* do load-balancing again */
   }
   m_check_reco_cluster();                  /* set timer for reconnect */
#endif
} /* end m_cleanup()                                                   */

/** send first (init) message to other cluster member                  */
static void m_send_control_init( struct dsd_cluster_active *adsp_clact ) {
   int        iml1, iml2;                   /* working variables       */
// struct dsd_gather_i_1 *adsl_gai1_start;  /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   char       *achl_w1, *achl_w2;           /* working variables       */
   struct dsd_cluster_send *adsl_clsend_w1;  /* send buffer            */

   adsl_clsend_w1 = (struct dsd_cluster_send *) m_proc_alloc();
   achl_w1 = (char *) adsl_clsend_w1 + LEN_TCP_RECV - 8;
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsl_clsend_w1 + 1))
   ADSL_GAI1_W1->achc_ginp_cur = achl_w1;
   iml1 = dsg_this_server.imc_len_server_name + 1;  /* length server name plus tag */
   if (iml1 >= 0X0080) iml1++;              /* needs two bytes length  */
   *(achl_w1 + 0) = (unsigned char) iml1;
   if (iml1 >= 0X0080) {                    /* needs two bytes length  */
     *(achl_w1 + 0) = (unsigned char) ((iml1 >> 7) | 0X80);
     *(achl_w1 + 1) = (unsigned char) (iml1 & 0X7F);
     achl_w1++;                             /* needs more space        */
   }
   *(achl_w1 + 1) = 0;                      /* tag computer name       */
   ADSL_GAI1_W1->achc_ginp_end = achl_w1 + 2;
   ADSL_GAI1_W1->adsc_next = ADSL_GAI1_W1 + 1;
#undef ADSL_GAI1_W1
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsl_clsend_w1 + 1) + 1)
   ADSL_GAI1_W1->achc_ginp_cur = dsg_this_server.chrc_server_name;
   ADSL_GAI1_W1->achc_ginp_end
     = dsg_this_server.chrc_server_name + dsg_this_server.imc_len_server_name;
   ADSL_GAI1_W1->adsc_next = ADSL_GAI1_W1 + 1;
#undef ADSL_GAI1_W1
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsl_clsend_w1 + 1) + 2)
   achl_w1 = (char *) adsl_clsend_w1 + LEN_TCP_RECV - 8 - 26 - DEF_LEN_FINGERPRINT;
   ADSL_GAI1_W1->achc_ginp_cur = achl_w1;
   *(achl_w1 + 0) = 1 + 4;                  /* length PID              */
   *(achl_w1 + 1) = 1;                      /* tag PID                 */
   *(achl_w1 + 2 + 0) = (unsigned char) (dsg_this_server.imc_pid >> 24);
   *(achl_w1 + 2 + 1) = (unsigned char) (dsg_this_server.imc_pid >> 16);
   *(achl_w1 + 2 + 2) = (unsigned char) (dsg_this_server.imc_pid >> 8);
   *(achl_w1 + 2 + 3) = (unsigned char) dsg_this_server.imc_pid;
   *(achl_w1 + 6) = 1 + 8;                  /* length epoch started    */
   *(achl_w1 + 7) = 2;                      /* tag epoch started       */
   *(achl_w1 + 8 + 0) = (unsigned char) (dsg_this_server.ilc_epoch_started >> 56);
   *(achl_w1 + 8 + 1) = (unsigned char) (dsg_this_server.ilc_epoch_started >> 48);
   *(achl_w1 + 8 + 2) = (unsigned char) (dsg_this_server.ilc_epoch_started >> 40);
   *(achl_w1 + 8 + 3) = (unsigned char) (dsg_this_server.ilc_epoch_started >> 32);
   *(achl_w1 + 8 + 4) = (unsigned char) (dsg_this_server.ilc_epoch_started >> 24);
   *(achl_w1 + 8 + 5) = (unsigned char) (dsg_this_server.ilc_epoch_started >> 16);
   *(achl_w1 + 8 + 6) = (unsigned char) (dsg_this_server.ilc_epoch_started >> 8);
   *(achl_w1 + 8 + 7) = (unsigned char) dsg_this_server.ilc_epoch_started;
   *(achl_w1 + 16 + 0) = 1 + DEF_LEN_FINGERPRINT;  /* length fingerprint */
   *(achl_w1 + 16 + 1) = 3;                 /* tag fingerprint         */
   memcpy( achl_w1 + 16 + 2, dsg_this_server.chrc_fingerprint, DEF_LEN_FINGERPRINT );
   *(achl_w1 + 18 + DEF_LEN_FINGERPRINT + 0) = 1 + 1;  /* length endian-ness */
   *(achl_w1 + 18 + DEF_LEN_FINGERPRINT + 1) = 4;  /* tag endian-ness  */
   *(achl_w1 + 18 + DEF_LEN_FINGERPRINT + 2) = (unsigned char) dsg_this_server.boc_endian_big;
   *(achl_w1 + 18 + DEF_LEN_FINGERPRINT + 3 + 0) = 1 + 1;  /* length alignment */
   *(achl_w1 + 18 + DEF_LEN_FINGERPRINT + 3 + 1) = 5;  /* tag alignment */
   *(achl_w1 + 18 + DEF_LEN_FINGERPRINT + 3 + 2) = (unsigned char) dsg_this_server.imc_aligment;
   achl_w1 += 6 + 10 + 2 + DEF_LEN_FINGERPRINT + 3 + 3;
// to-do 05.09.08 KB
// 6 = send name entry local
// 7 = send name entry remote
// 8 = send query main
   achl_w2 = (char *) m_get_query_main();   /* get name, version of WSP etc. */
   iml2 = strlen( achl_w2 );
   iml1 = iml2 + 1;
   *(achl_w1 + 0) = (unsigned char) iml1;   /* length this cluster entry ´*/
   if (iml1 >= 0X0080) {                    /* needs two bytes length  */
     *(achl_w1 + 0) = (unsigned char) ((iml1 >> 7) | 0X80);
     *(achl_w1 + 1) = (unsigned char) (iml1 & 0X7F);
     achl_w1++;                             /* needs more space        */
   }
   *(achl_w1 + 1) = (unsigned char) 6;      /* tag this cluster entry ´*/
   ADSL_GAI1_W1->achc_ginp_end = achl_w1 + 2;
   ADSL_GAI1_W1->adsc_next = ADSL_GAI1_W1 + 1;
#undef ADSL_GAI1_W1
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsl_clsend_w1 + 1) + 3)
   ADSL_GAI1_W1->achc_ginp_cur = achl_w2;
   ADSL_GAI1_W1->achc_ginp_end = achl_w2 + iml2;
   ADSL_GAI1_W1->adsc_next = ADSL_GAI1_W1 + 1;
#ifdef B170630
   if (adss_cluster_main == NULL) {         /* cluster not configured  */
     ADSL_GAI1_W1->adsc_next = NULL;        /* end of data             */
     goto p_send_02;                        /* send packet             */
   }
#endif
#undef ADSL_GAI1_W1
#define ADSL_GAI1_G1 ((struct dsd_gather_i_1 *) (adsl_clsend_w1 + 1) + 4)
// achl_w1 = (char *) adsl_clsend_w1 + LEN_TCP_RECV - 8 - 26 - DEF_LEN_FINGERPRINT - 8;
   achl_w1 = (char *) adsl_clsend_w1 + LEN_TCP_RECV - 8 - 26 - DEF_LEN_FINGERPRINT - 8 - 14;
   adsl_gai1_w1 = ADSL_GAI1_G1;             /* save last gather        */
   ADSL_GAI1_G1->achc_ginp_cur = achl_w1;
   if (    (adss_cluster_main)              /* cluster configured      */
       &&  (adss_cluster_main->imc_this_len_name > 0)) {
     iml1 = adss_cluster_main->imc_this_len_name + 1;  /* length configuration name plus tag */
     *(achl_w1 + 0) = (unsigned char) iml1;  /* length this cluster entry */
     if (iml1 >= 0X0080) {                  /* needs two bytes length  */
       *(achl_w1 + 0) = (unsigned char) ((iml1 >> 7) | 0X80);
       *(achl_w1 + 1) = (unsigned char) (iml1 & 0X7F);
       achl_w1++;                           /* needs more space        */
     }
     *(achl_w1 + 1) = (unsigned char) 7;    /* tag this cluster entry  */
     ADSL_GAI1_G1->achc_ginp_end = achl_w1 + 2;
     adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;  /* set chain         */
     adsl_gai1_w1++;                        /* next gather             */
     adsl_gai1_w1->achc_ginp_cur = adss_cluster_main->achc_this_name;
     adsl_gai1_w1->achc_ginp_end
       = adss_cluster_main->achc_this_name + adss_cluster_main->imc_this_len_name;
   } else {
     *(achl_w1 + 0) = (unsigned char) 1 + 4 + 10;  /* length this name */
     *(achl_w1 + 1) = (unsigned char) 7;    /* tag this cluster entry  */
     memcpy( achl_w1 + 2, "PID-", 4 );
     achl_w1 += 2 + 4 + 10;                 /* after the digits        */
     ADSL_GAI1_G1->achc_ginp_end = achl_w1;
     iml1 = 10;                             /* length of digits        */
     iml2 = dsg_this_server.imc_pid;
     do {
       *(--achl_w1) = (unsigned char) ((iml2 % 10) + '0');
       iml2 /= 10;
       iml1--;
     } while (iml1 > 0);
   }
#undef ADSL_GAI1_G1
   if (adss_cluster_main == NULL) {         /* cluster not configured  */
     goto p_send_02;                        /* send packet             */
   }
   if (adss_cluster_main->imc_this_len_group > 0) {  /* length of group in bytes */
     adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;  /* set chain         */
     adsl_gai1_w1++;                        /* next gather             */
     achl_w1 = (char *) adsl_clsend_w1 + LEN_TCP_RECV - 8 - 26 - DEF_LEN_FINGERPRINT - 8 - 14 - 4;
     adsl_gai1_w1->achc_ginp_cur = achl_w1;
     iml1 = adss_cluster_main->imc_this_len_group + 1;  /* length configuration group plus tag */
     *(achl_w1 + 0) = (unsigned char) iml1;  /* length this cluster entry ´*/
     if (iml1 >= 0X0080) {                  /* needs two bytes length  */
       *(achl_w1 + 0) = (unsigned char) ((iml1 >> 7) | 0X80);
       *(achl_w1 + 1) = (unsigned char) (iml1 & 0X7F);
       achl_w1++;                           /* needs more space        */
     }
     *(achl_w1 + 1) = (unsigned char) 8;    /* tag this cluster group  */
     adsl_gai1_w1->achc_ginp_end = achl_w1 + 2;
     adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;  /* set chain         */
     adsl_gai1_w1++;                        /* next gather             */
     adsl_gai1_w1->achc_ginp_cur = adss_cluster_main->achc_this_group;
     adsl_gai1_w1->achc_ginp_end
       = adss_cluster_main->achc_this_group + adss_cluster_main->imc_this_len_group;
   }
   if (adss_cluster_main->imc_this_len_location > 0) {  /* length of location in bytes */
     adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;  /* set chain         */
     adsl_gai1_w1++;                        /* next gather             */
     achl_w1 = (char *) adsl_clsend_w1 + LEN_TCP_RECV - 8 - 26 - DEF_LEN_FINGERPRINT - 8 - 14 - 4 - 4;
     adsl_gai1_w1->achc_ginp_cur = achl_w1;
     iml1 = adss_cluster_main->imc_this_len_location + 1;  /* length configuration location plus tag */
     *(achl_w1 + 0) = (unsigned char) iml1;   /* length this cluster entry ´*/
     if (iml1 >= 0X0080) {                  /* needs two bytes length  */
       *(achl_w1 + 0) = (unsigned char) ((iml1 >> 7) | 0X80);
       *(achl_w1 + 1) = (unsigned char) (iml1 & 0X7F);
       achl_w1++;                           /* needs more space        */
     }
     *(achl_w1 + 1) = (unsigned char) 9;    /* tag this cluster location */
     adsl_gai1_w1->achc_ginp_end = achl_w1 + 2;
     adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;
     adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;  /* set chain         */
     adsl_gai1_w1++;                        /* next gather             */
     adsl_gai1_w1->achc_ginp_cur = adss_cluster_main->achc_this_location;
     adsl_gai1_w1->achc_ginp_end
       = adss_cluster_main->achc_this_location + adss_cluster_main->imc_this_len_location;
   }
   if (adss_cluster_main->imc_this_len_url > 0) {  /* length of URL in bytes */
     adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;  /* set chain         */
     adsl_gai1_w1++;                        /* next gather             */
     achl_w1 = (char *) adsl_clsend_w1 + LEN_TCP_RECV - 8 - 26 - DEF_LEN_FINGERPRINT - 8 - 14 - 4 - 4 - 4;
     adsl_gai1_w1->achc_ginp_cur = achl_w1;
     iml1 = adss_cluster_main->imc_this_len_url + 1;  /* length configuration URL plus tag */
     *(achl_w1 + 0) = (unsigned char) iml1;  /* length this cluster entry */
     if (iml1 >= 0X0080) {                  /* needs two bytes length  */
       *(achl_w1 + 0) = (unsigned char) ((iml1 >> 7) | 0X80);
       *(achl_w1 + 1) = (unsigned char) (iml1 & 0X7F);
       achl_w1++;                           /* needs more space        */
     }
     *(achl_w1 + 1) = (unsigned char) 10;   /* tag this cluster URL    */
     adsl_gai1_w1->achc_ginp_end = achl_w1 + 2;
     adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;
     adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;  /* set chain         */
     adsl_gai1_w1++;                        /* next gather             */
     adsl_gai1_w1->achc_ginp_cur = adss_cluster_main->achc_this_url;
     adsl_gai1_w1->achc_ginp_end
       = adss_cluster_main->achc_this_url + adss_cluster_main->imc_this_len_url;
   }

   p_send_02:                               /* send packet             */
   adsl_gai1_w1->adsc_next = NULL;          /* end of chain            */
#ifdef OLD01
   iml1 = adsp_clact->dsc_tcpcomp.m_send_gather( adsl_gai1_start, &adsl_gai1_w1 );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_send_control_init() m_send_gather() returned %d",
                   __LINE__, iml1 );
#endif
#endif
   adsl_clsend_w1->adsc_clact = adsp_clact;  /* active cluster         */
   adsl_clsend_w1->amc_compl = &m_cluster_free_send;  /* completition routine */
   adsl_clsend_w1->iec_cl_type = ied_clty_control;  /* type is control */
   adsl_clsend_w1->adsc_gai1_send = (struct dsd_gather_i_1 *) (adsl_clsend_w1 + 1);
   iml1 = m_cluster_send( adsl_clsend_w1 );
   if (iml1) {                              /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_send_control_init() m_cluster_send() returned %d.",
                     __LINE__, iml1 );
     m_proc_free( adsl_clsend_w1 );
   }
} /* end m_send_control_init()                                         */

/** free buffer sent                                                   */
static void m_cluster_free_send( struct dsd_cluster_send *adsp_clsend ) {
   m_proc_free( adsp_clsend );              /* free memory             */
} /* end m_cluster_free_send()                                         */

#ifndef B120827
/** process block received from other cluster member                   */
static htfunc1_t m_recv_block( void * ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3;             /* working variables       */
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   int        iml_pos;                      /* position scan received block */
   int        iml_len_data;                 /* save length of data     */
#ifdef DEBUG_120912_01                      /* receiving loops         */
   int        iml_loop;                     /* number of passes        */
#endif
#ifdef XYZ1
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
#endif
   char       *achl_w1;                     /* working variables       */
   void       **avpl_w1;                    /* working variable        */
   char       *achl_st_data;                /* start of data           */
   char       chl_main_tag;                 /* main tag of received packet */
   struct dsd_cluster_recv *adsl_clrecv_w1;  /* block received from cluster member */
   struct dsd_cluster_recv *adsl_clrecv_cur;  /* current in chain      */
   struct dsd_cluster_recv *adsl_clrecv_last;  /* last in chain        */
   struct dsd_cluster_recv *adsl_clrecv_data;  /* start data in this block */
   struct dsd_cluster_proc_recv *adsl_clprr_w1;  /* process block received from cluster member */
   struct dsd_cluster_active *adsl_clact_c_recv;  /* active cluster entry continue receive */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* gather input data       */
#ifdef XYZ1
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
#endif
   char        chrl_work1[32];              /* work-area               */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_recv_block( 0X%p ) called",
                   __LINE__, ap_param_1 );
#endif
   if (adss_clact_proc_ch == NULL) {        /* chain to get processed */
     goto p_wait_00;                        /* wait for next received data */
   }

   p_proc_start:                            /* start processing this active cluster */
#ifdef DEBUG_120912_01                      /* receiving loops         */
   iml_loop = 0;                            /* number of passes        */
#endif
   if (adss_clact_proc_ch->iec_clr_stat == ied_clrs_closed) {  /* state is closed */
     m_recv_cluster_lbal( adss_clact_proc_ch, NULL );  /* process with no data received */
     adsl_clrecv_last = NULL;               /* clear last in chain - no data */
     goto p_cont_recv;                      /* continue receiving      */
   }
   if (adss_clact_proc_ch->adsc_recv_ch == NULL) {
     adsl_clrecv_last = NULL;               /* clear last in chain - no data */
     goto p_cont_recv;                      /* continue receiving      */
   }

   p_scan_recv_00:                          /* scan received block     */
#ifdef DEBUG_120912_01                      /* receiving loops         */
#ifndef HL_UNIX
   iml_loop++;                              /* number of passes        */
   if (iml_loop > 1) {                      /* number of passes        */
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_recv_block() adss_clact_proc_ch=%p iml_loop=%d thread=%d.",
                     __LINE__, adss_clact_proc_ch, iml_loop, GetCurrentThreadId() );
   }
#endif
#endif
   /* check if block complete                                          */
   iml_pos = 0;                             /* start from position zero */
   adsl_clrecv_cur = adss_clact_proc_ch->adsc_recv_ch;  /* chain of received buffers */
   iml2 = adss_clact_proc_ch->imc_skip_recv_data;  /* length to skip received data */

   p_scan_eyec_00:                          /* scan for eye-catcher    */
   achl_w1 = (char *) (adsl_clrecv_cur + 1) + iml2;  /* data from here */
   iml1 = ((char *) (adsl_clrecv_cur + 1) + adsl_clrecv_cur->imc_len_recv) - achl_w1;
   if ((iml_pos + iml1) > sizeof(ucrs_cluster_eye_catcher)) {
     iml1 = sizeof(ucrs_cluster_eye_catcher) - iml_pos;
   }
   if (memcmp( achl_w1, ucrs_cluster_eye_catcher + iml_pos, iml1 )) {
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_recvcallback() received eye-catcher invalid",
                     __LINE__ );
     goto p_recv_err_00;                    /* received invalid packet */
   }
   iml_pos += iml1;                         /* checked till here       */
   if (iml_pos < sizeof(ucrs_cluster_eye_catcher)) {  /* part of eye-catcher missing */
     adsl_clrecv_last = adsl_clrecv_cur;    /* last in chain           */
     adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next part   */
     if (adsl_clrecv_cur == NULL) {         /* needs more data         */
       goto p_cont_recv;                    /* continue receiving      */
     }
     iml2 = 0;                              /* from beginning of data  */
     goto p_scan_eyec_00;                   /* scan for eye-catcher    */
   }
   achl_w1 += iml1;                         /* checked till here       */
   if (achl_w1 >= ((char *) (adsl_clrecv_cur + 1) + adsl_clrecv_cur->imc_len_recv)) {  /* at end of received block */
     adsl_clrecv_last = adsl_clrecv_cur;    /* last in chain           */
     adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next part   */
     if (adsl_clrecv_cur == NULL) {         /* needs more data         */
       goto p_cont_recv;                    /* continue receiving      */
     }
     achl_w1 = (char *) (adsl_clrecv_cur + 1);  /* data from here      */
   }
   chl_main_tag = *achl_w1++;               /* get main tag            */
   /* get length of the following data in NHASN                        */
   iml1 = 0;                                /* clear length value      */
   iml2 = 4;                                /* maximum number of digits */
   while (TRUE) {                           /* loop to get length      */
     if (achl_w1 >= ((char *) (adsl_clrecv_cur + 1) + adsl_clrecv_cur->imc_len_recv)) {  /* at end of received block */
       adsl_clrecv_last = adsl_clrecv_cur;  /* last in chain           */
       adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next part */
       if (adsl_clrecv_cur == NULL) {       /* needs more data         */
         goto p_cont_recv;                  /* continue receiving      */
       }
       achl_w1 = (char *) (adsl_clrecv_cur + 1);  /* data from here    */
     }
     iml1 <<= 7;                            /* shift old value         */
     iml1 |= *achl_w1 & 0X7F;               /* apply new bits          */
     if ((*achl_w1 & 0X80) == 0) break;     /* more bit not set        */
     iml2--;                                /* count this digit        */
     if (iml2 <= 0) {                       /* too many digits length  */
       m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW cluster l%05d too many digits length packet",
                       __LINE__ );
       goto p_recv_err_00;                  /* received invalid packet */
     }
     achl_w1++;                             /* after last digit        */
   }
   if (iml1 <= 0) {                         /* length value invalid    */
     if ((iml1 == 0) && (chl_main_tag == '1')) {  /* end received      */
       achl_w1++;                           /* after last digit        */
//     adsl_clrecv_cur = NULL;              /* no data in this block   */
       iml_len_data = 0;                    /* set length of data      */
       goto p_scan_data_20;                 /* data have been scanned  */
     }
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW cluster l%05d length packet received zero - not valid",
                     __LINE__ );
     goto p_recv_err_00;                    /* received invalid packet */
   }
   achl_w1++;                               /* after last digit        */
   if (achl_w1 >= ((char *) (adsl_clrecv_cur + 1) + adsl_clrecv_cur->imc_len_recv)) {  /* at end of received block */
     adsl_clrecv_last = adsl_clrecv_cur;    /* last in chain           */
     adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next part   */
     if (adsl_clrecv_cur == NULL) {         /* needs more data         */
       goto p_cont_recv;                    /* continue receiving      */
     }
     achl_w1 = (char *) (adsl_clrecv_cur + 1);  /* data from here      */
   }
   /* check if all data received                                       */
   adsl_clrecv_data = adsl_clrecv_cur;      /* start data in this block */
   achl_st_data = achl_w1;                  /* start of data           */
   iml_len_data = iml1;                     /* save length of data     */

   p_scan_data_00:                          /* scan the data           */
   iml2 = ((char *) (adsl_clrecv_cur + 1) + adsl_clrecv_cur->imc_len_recv) - achl_w1;
   achl_w1 += iml1;                         /* pointer to end of data  */
   iml1 -= iml2;                            /* subtruct from length needed */
   if (iml1 > 0) {                          /* needs more data         */
     adsl_clrecv_last = adsl_clrecv_cur;    /* last in chain           */
     adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next part   */
     if (adsl_clrecv_cur == NULL) {         /* needs more data         */
       goto p_cont_recv;                    /* continue receiving      */
     }
     achl_w1 = (char *) (adsl_clrecv_cur + 1);  /* data from here      */
     goto p_scan_data_00;                   /* scan the data           */
   }

   p_scan_data_20:                          /* data have been scanned  */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_recvcallback() complete block main tag 0X%02X iml_len_data = %d.",
                   __LINE__, (unsigned char) chl_main_tag, iml_len_data );
#endif
   bol1 = FALSE;                            /* do not free buffers     */
   switch (chl_main_tag) {                  /* depending on tag        */
     case '0':                              /* control                 */
       m_recv_control( adss_clact_proc_ch, adsl_clrecv_data, achl_st_data, iml_len_data );
       bol1 = TRUE;                         /* do free buffers         */
       break;
     case '1':                              /* end session             */
       if (iml_len_data > 0) {              /* data received           */
         m_hlnew_printf( HLOG_WARN1, "HWSPCLnnnnW Cluster INETA=%s xs-gw-cluster l%05d m_recvcallback() received end session and iml_len_data = %d.",
                         adss_clact_proc_ch->chrc_ineta, __LINE__, iml_len_data );
       }
       bol1 = TRUE;                         /* do free buffers         */
       break;
     case '2':                              /* redirect                */
       m_recv_redirect( adss_clact_proc_ch, adsl_clrecv_data, achl_st_data, iml_len_data );
       bol1 = TRUE;                         /* do free buffers         */
       break;
     case '3':                              /* load-balancing          */
       bol1 = TRUE;                         /* do free buffers         */
       if (iml_len_data != DEF_LBAL_NET_DATA) {
         m_hlnew_printf( HLOG_WARN1, "HWSPCLnnnnW Cluster INETA=%s xs-gw-cluster l%05d m_recvcallback() received block load-balancing invalid length - iml_len_data = %d.",
                         adss_clact_proc_ch->chrc_ineta, __LINE__, iml_len_data );
         break;
       }
       adsl_clrecv_cur = adsl_clrecv_data;  /* get current position    */
       achl_w1 = achl_st_data;              /* current data area       */
       iml1 = 0;                            /* displacement in output area */
       iml2 = iml_len_data;                 /* length of data          */
       while (TRUE) {
         iml3 = ((char *) (adsl_clrecv_cur + 1) + adsl_clrecv_cur->imc_len_recv) - achl_w1;
         if (iml3 > iml2) iml3 = iml2;      /* only remaining data     */
         memcpy( chrl_work1 + iml1, achl_w1, iml3 );
         achl_w1 += iml3;                   /* add length processed    */
         iml2 -= iml3;
         if (iml2 <= 0) break;              /* output filled           */
         iml1 += iml3;                      /* increment position output */
         adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next part */
         if (adsl_clrecv_cur == NULL) {     /* needs more data - illogic */
           goto p_cont_recv;                /* continue receiving      */
         }
         achl_w1 = (char *) (adsl_clrecv_cur + 1);  /* data from here  */
       }
       m_recv_cluster_lbal( adss_clact_proc_ch, chrl_work1 );  /* process data received */
       break;
     case '4':                              /* CMA common memory area  */
       break;
     case '5':                              /* type is VDI-WSP         */
       bol1 = TRUE;                         /* do free buffers         */
       if (iml_len_data > (16 + 2)) {       /* not INETA IPV4 / IPV6 + port */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_recvcallback() received block VDI-WSP too long - iml_len_data = %d.",
                         __LINE__, iml_len_data );
         break;
       }
       adsl_clrecv_cur = adsl_clrecv_data;  /* get current position    */
       achl_w1 = achl_st_data;              /* current data area       */
       iml1 = 0;                            /* displacement in output area */
       iml2 = iml_len_data;                 /* length of data          */
       while (TRUE) {
         iml3 = ((char *) (adsl_clrecv_cur + 1) + adsl_clrecv_cur->imc_len_recv) - achl_w1;
         if (iml3 > iml2) iml3 = iml2;      /* only remaining data     */
         memcpy( chrl_work1 + iml1, achl_w1, iml3 );
         achl_w1 += iml3;                   /* add length processed    */
         iml2 -= iml3;
         if (iml2 <= 0) break;              /* output filled           */
         iml1 += iml3;                      /* increment position output */
         adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next part */
         if (adsl_clrecv_cur == NULL) {     /* needs more data - illogic */
           goto p_cont_recv;                /* continue receiving      */
         }
         achl_w1 = (char *) (adsl_clrecv_cur + 1);  /* data from here  */
       }
       m_recv_cluster_vdi( chrl_work1, iml_len_data );  /* process data received */
       break;
     case '6':                              /* type is administration  */
       break;
#ifdef D_INCL_HOB_TUN
     case 'A':                              /* ied_clty_ineta_req_ipv4 - type is request with INETAs IPV4 */
       break;
     case 'B':                              /* ied_clty_ineta_resp_ipv4 - type is response with INETAs IPV4 */
       break;
     case 'C':                              /* ied_clty_ineta_rej_ipv4 - type is reject for INETAs IPV4 */
       break;
     case 'D':                              /* ied_clty_ineta_req_ipv6 - type is request with INETAs IPV6 */
       break;
     case 'E':                              /* ied_clty_ineta_resp_ipv6 - type is response with INETAs IPV6 */
       break;
     case 'F':                              /* ied_clty_ineta_rej_ipv6 - type is reject for INETAs IPV6 */
       break;
#endif
     default:                               /* invalid tag received    */
       m_hlnew_printf( HLOG_WARN1, "HWSPCLnnnnW Cluster INETA=%s xs-gw-cluster l%05d m_recvcallback() received block main tag 0X%02X invalid - iml_len_data = %d.",
                       adss_clact_proc_ch->chrc_ineta, __LINE__, (unsigned char) chl_main_tag, iml_len_data );
       bol1 = TRUE;                         /* do free buffers         */
       break;
   }
   if (bol1) {                              /* do free buffers         */
#ifdef TRACEHL_CS1
     m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX2T l%05d m_enter() before", __LINE__ );
#endif
     dss_critsect_cluster.m_enter();
#ifdef TRACEHL_CS1
     m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX3T l%05d m_enter() after", __LINE__ );
#endif
     if (adss_clact_proc_ch->iec_clr_stat != ied_clrs_closed) {  /* state is not closed */
       if (achl_w1 >= ((char *) (adsl_clrecv_cur + 1) + adsl_clrecv_cur->imc_len_recv)) {  /* at end of received block */
         adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next part */
       }
       while (TRUE) {                       /* loop over buffers received */
         adsl_clrecv_w1 = adss_clact_proc_ch->adsc_recv_ch;  /* chain of received buffers */
         if (adsl_clrecv_w1 == adsl_clrecv_cur) break;  /* was last block */
         adss_clact_proc_ch->adsc_recv_ch = adsl_clrecv_w1->adsc_next;  /* remove from chain */
#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_recvcallback() -1- adsl_clrecv_w1->imc_usage_count=%d m_proc_free %p adsc_next=%p ???",
                         __LINE__, adsl_clrecv_w1->imc_usage_count, adsl_clrecv_w1, adsl_clrecv_w1->adsc_next );
#endif
         if (adsl_clrecv_w1->imc_usage_count == 0) {
           m_proc_free( adsl_clrecv_w1 );   /* free block used         */
         }
       }
     } else {                               /* no more blocks          */
       adsl_clrecv_w1 = NULL;               /* set no more data        */
     }
     dss_critsect_cluster.m_leave();
#ifdef TRACEHL_CS1
     m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX4T l%05d m_leave() after", __LINE__ );
#endif
     adss_clact_proc_ch->imc_skip_recv_data = 0;  /* length to skip received data */
     if (adsl_clrecv_w1) {                  /* still chain of blocks   */
       adss_clact_proc_ch->imc_skip_recv_data = achl_w1 - ((char *) (adsl_clrecv_cur + 1));  /* length to skip received data */
     }
     goto p_bl_end_00;                      /* end of received block   */
   }
   /* build block with the data to be processed                        */
   adsl_clprr_w1 = (struct dsd_cluster_proc_recv *) m_proc_alloc();  /* get storage to fill */
   memset( adsl_clprr_w1, 0, sizeof(struct dsd_cluster_proc_recv) );
   avpl_w1 = (void **) (adsl_clprr_w1 + 1);  /* fill in structure to free here */
   adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_clprr_w1 + LEN_TCP_RECV);  /* gather input data */
   adsl_clprr_w1->adsc_clact = adss_clact_proc_ch;  /* active cluster  */
   adsl_clprr_w1->adsc_gai1_data = adsl_gai1_w1 - 1;  /* gather input data */
   adsl_clprr_w1->imc_data_length = iml_len_data;  /* length of received data */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX2T l%05d m_enter() before", __LINE__ );
#endif
   dss_critsect_cluster.m_enter();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX3T l%05d m_enter() after", __LINE__ );
#endif
   /* block with header, no data in this blocks                        */
   while (TRUE) {                           /* loop over buffers received */
     adsl_clrecv_w1 = adss_clact_proc_ch->adsc_recv_ch;  /* chain of received buffers */
     if (   (achl_st_data > (char *) adsl_clrecv_w1)
         && (achl_st_data < ((char *) adsl_clrecv_w1 + LEN_TCP_RECV))) {
       break;
     }
     adss_clact_proc_ch->adsc_recv_ch = adsl_clrecv_w1->adsc_next;  /* remove from chain */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_recvcallback() -2- adsl_clrecv_w1->imc_usage_count=%d m_proc_free %p ???",
                     __LINE__, adsl_clrecv_w1->imc_usage_count, adsl_clrecv_w1 );
#endif
     if (adsl_clrecv_w1->imc_usage_count == 0) {
       m_proc_free( adsl_clrecv_w1 );       /* free block used         */
     }
   }
   /* first block with data                                            */
   *avpl_w1++ = adsl_clrecv_w1;             /* save block to be freed later */
   adsl_clprr_w1->imc_no_recv_bl++;         /* count number of receive blocks */
   adsl_clrecv_w1->imc_usage_count++;       /* count block in use      */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_recvcallback() -1- adsl_clrecv_w1=%p adsl_clrecv_w1->imc_usage_count=%d (++)",
                   __LINE__, adsl_clrecv_w1, adsl_clrecv_w1->imc_usage_count );
#endif
   adsl_gai1_w1--;                          /* get gather structure    */
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain gather    */
   adsl_gai1_w1->achc_ginp_cur = achl_st_data;  /* here start data     */
   adsl_gai1_w1->achc_ginp_end = (char *) (adsl_clrecv_w1 + 1) + adsl_clrecv_w1->imc_len_recv;  /* here is end of data */
   if (adsl_clrecv_w1 != adsl_clrecv_cur) {  /* not last block         */
     adss_clact_proc_ch->adsc_recv_ch = adsl_clrecv_w1->adsc_next;  /* remove from chain */
     while (TRUE) {                         /* loop over buffers received */
       adsl_clrecv_w1 = adss_clact_proc_ch->adsc_recv_ch;  /* chain of received buffers */
       *avpl_w1++ = adsl_clrecv_w1;         /* save block to be freed later */
       adsl_clprr_w1->imc_no_recv_bl++;     /* count number of receive blocks */
       adsl_clrecv_w1->imc_usage_count++;   /* count block in use      */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_recvcallback() -2- adsl_clrecv_w1=%p adsl_clrecv_w1->imc_usage_count=%d (++)",
                       __LINE__, adsl_clrecv_w1, adsl_clrecv_w1->imc_usage_count );
#endif
       adsl_gai1_w1--;                      /* get gather structure    */
       adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain gather  */
       adsl_gai1_w1->achc_ginp_cur = (char *) (adsl_clrecv_w1 + 1);  /* here start data */
       adsl_gai1_w1->achc_ginp_end = (char *) (adsl_clrecv_w1 + 1) + adsl_clrecv_w1->imc_len_recv;  /* here is end of data */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-W m_recvcallback() make gather achc_ginp_cur=%p achc_ginp_end=%p len=%d/0x%p.",
                       __LINE__,
                       adsl_gai1_w1->achc_ginp_cur, adsl_gai1_w1->achc_ginp_end,
                       adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur,
                       adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur );
#endif
       if (adsl_clrecv_w1 == adsl_clrecv_cur) break;  /* was last block  */
       adss_clact_proc_ch->adsc_recv_ch = adsl_clrecv_w1->adsc_next;  /* remove from chain */
     }
   }
   adsl_gai1_w1->adsc_next = NULL;          /* is last in chain        */
   if ((char *) avpl_w1 > (char *) adsl_gai1_w1) {  /* overflow        */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster-l%05d-E overflow",
                     __LINE__ );
   }
   if (adsl_clrecv_w1) {                    /* more data in this block */
     adsl_gai1_w1->achc_ginp_end = achl_w1;  /* here is end of data    */
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T m_recvcallback() end make gather adsl_clrecv_w1=%p achl_w1=%p adsl_gai1_w1->achc_ginp_end=%p.",
                   __LINE__, adsl_clrecv_w1, achl_w1, adsl_gai1_w1->achc_ginp_end );
#endif
   if (achl_w1 >= ((char *) (adsl_clrecv_cur + 1) + adsl_clrecv_cur->imc_len_recv)) {  /* at end of received block */
     adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next part   */
     achl_w1 = (char *) (adsl_clrecv_cur + 1);  /* data from here      */
     adss_clact_proc_ch->adsc_recv_ch = adsl_clrecv_cur;  /* remove from chain */
   }
   adss_clact_proc_ch->imc_skip_recv_data = 0;  /* length to skip received data */
   if (adsl_clrecv_cur) {                   /* still chain of blocks   */
     adss_clact_proc_ch->imc_skip_recv_data = achl_w1 - ((char *) (adsl_clrecv_cur + 1));  /* length to skip received data */
   }
   adss_clact_proc_ch->imc_count_recv_b++;  /* count block received    */
   dss_critsect_cluster.m_leave();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX4T l%05d m_leave() after", __LINE__ );
#endif
   switch (chl_main_tag) {                  /* depending on tag        */
     case '4':                              /* CMA common memory area  */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-W m_recvcallback() CMA received adsl_clprr_w1=%p adsl_clprr_w1->imc_data_length=%d.",
                       __LINE__, adsl_clprr_w1, adsl_clprr_w1->imc_data_length );
       adsl_gai1_w1 = adsl_clprr_w1->adsc_gai1_data;
       iml1 = adsl_clprr_w1->imc_data_length;
       while ((adsl_gai1_w1) && (iml1 > 0)) {
         iml2 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         if (iml2 > iml1) iml2 = iml1;
         m_console_out( adsl_gai1_w1->achc_ginp_cur, iml2 );
         iml1 -= iml2;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
#endif
       m_cma1_cluster_recv( adsl_clprr_w1 );
       break;
     case '6':                              /* type is administration  */
       m_admin_cluster_recv( adsl_clprr_w1 );
       break;
//#ifdef D_HPPPT1_1  changed 10.08.11 KB
#ifdef D_INCL_HOB_TUN
     case 'A':                              /* ied_clty_ineta_req_ipv4 - type is request with INETAs IPV4 */
       m_ineta_req_cluster_recv( adsl_clprr_w1, AF_INET );
       m_cluster_proc_recv_done( adsl_clprr_w1 );  /* free data that we received */
       break;
     case 'B':                              /* ied_clty_ineta_resp_ipv4 - type is response with INETAs IPV4 */
       m_ineta_resp_cluster_recv( adsl_clprr_w1, AF_INET );
       m_cluster_proc_recv_done( adsl_clprr_w1 );  /* free data that we received */
       break;
     case 'C':                              /* ied_clty_ineta_rej_ipv4 - type is reject for INETAs IPV4 */
       m_ineta_rej_cluster_recv( adsl_clprr_w1, AF_INET );
       m_cluster_proc_recv_done( adsl_clprr_w1 );  /* free data that we received */
       break;
     case 'D':                              /* ied_clty_ineta_req_ipv6 - type is request with INETAs IPV6 */
       m_ineta_req_cluster_recv( adsl_clprr_w1, AF_INET6 );
       m_cluster_proc_recv_done( adsl_clprr_w1 );  /* free data that we received */
       break;
     case 'E':                              /* ied_clty_ineta_resp_ipv6 - type is response with INETAs IPV6 */
       m_ineta_resp_cluster_recv( adsl_clprr_w1, AF_INET6 );
       m_cluster_proc_recv_done( adsl_clprr_w1 );  /* free data that we received */
       break;
     case 'F':                              /* ied_clty_ineta_rej_ipv6 - type is reject for INETAs IPV6 */
       m_ineta_rej_cluster_recv( adsl_clprr_w1, AF_INET6 );
       m_cluster_proc_recv_done( adsl_clprr_w1 );  /* free data that we received */
       break;
#endif
   }

   p_bl_end_00:                             /* end of received block   */
   if (adss_clact_proc_ch->iec_clr_stat == ied_clrs_closed) {  /* state is closed */
     adsl_clrecv_last = NULL;               /* clear last in chain - no data */
     goto p_cont_recv;                      /* continue receiving      */
   }
   if (adss_clact_proc_ch->adsc_recv_ch) {  /* chain received data     */
     iml1 = adss_clact_proc_ch->imc_skip_recv_data;  /* data to skip   */
#ifdef B130611
     do {                                   /* loop if we have enough data */
       iml1 -= adsl_clrecv_cur->imc_len_recv;  /* subtract length in this block */
       if (iml1 < 0) {                      /* we have data to process */
         goto p_scan_recv_00;               /* scan received block     */
       }
       adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
     } while (adsl_clrecv_cur);
#else
     while (adsl_clrecv_cur) {              /* loop if we have enough data */
       iml1 -= adsl_clrecv_cur->imc_len_recv;  /* subtract length in this block */
       if (iml1 < 0) {                      /* we have data to process */
         goto p_scan_recv_00;               /* scan received block     */
       }
       adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
     }
#endif
   }
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX2T l%05d m_enter() before", __LINE__ );
#endif
   dss_critsect_cluster.m_enter();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX3T l%05d m_enter() after", __LINE__ );
#endif
   adsl_clrecv_cur = adss_clact_proc_ch->adsc_recv_ch;  /* chain of received buffers */
   if (adsl_clrecv_cur) {                   /* we have data to be processed */
     iml1 = adss_clact_proc_ch->imc_skip_recv_data;  /* data to skip   */
     do {                                   /* loop if we have enough data */
       iml1 -= adsl_clrecv_cur->imc_len_recv;  /* subtract length in this block */
       if (iml1 < 0) {                      /* we have data to process */
#ifdef B130626
         goto p_scan_recv_00;               /* scan received block     */
#else
         break;
#endif
       }
       adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
     } while (adsl_clrecv_cur);
   }
   if (adsl_clrecv_cur == NULL) {           /* we don't have data to be processed */
     adsl_clact_c_recv = NULL;              /* do not start receiving  */
     if (   (adss_clact_proc_ch->imc_count_recv_b < DEF_CLUSTER_NO_BL)  /* number of blocks for flow control */
         && (adss_clact_proc_ch->boc_recv_active == FALSE)) {  /* receive is not active */
       adsl_clact_c_recv = adss_clact_proc_ch;  /* do start receiving  */
     }
     adss_clact_proc_ch->boc_proc_active = FALSE;  /* processing is not active */
     adss_clact_proc_ch = adss_clact_proc_ch->adsc_proc_ch;  /* next in chain to get processed */
   }
   dss_critsect_cluster.m_leave();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX4T l%05d m_leave() after", __LINE__ );
#endif
   if (adsl_clrecv_cur) {                   /* we have data to be processed */
     goto p_scan_recv_00;                   /* scan received block     */
   }
   goto p_start_recv;                       /* start receiving again   */

   p_cont_recv:                             /* continue receiving      */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX2T l%05d m_enter() before", __LINE__ );
#endif
   dss_critsect_cluster.m_enter();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX3T l%05d m_enter() after", __LINE__ );
#endif
   adsl_clrecv_cur = NULL;                  /* we don't have data to be processed */
   if (adsl_clrecv_last) {                  /* check last in chain - no data */
     adsl_clrecv_cur = adsl_clrecv_last->adsc_next;  /* get new block received */
   }
   if (adsl_clrecv_cur == NULL) {           /* we don't have data to be processed */
     adsl_clact_c_recv = NULL;              /* do not start receiving  */
     if (adss_clact_proc_ch->boc_recv_active == FALSE) {  /* receive is not active */
       adsl_clact_c_recv = adss_clact_proc_ch;  /* do start receiving  */
     }
     adss_clact_proc_ch->boc_proc_active = FALSE;  /* processing is not active */
     adss_clact_proc_ch = adss_clact_proc_ch->adsc_proc_ch;  /* next in chain to get processed */
   }
   dss_critsect_cluster.m_leave();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX4T l%05d m_leave() after", __LINE__ );
#endif
   if (adsl_clrecv_cur) {                   /* we have data to be processed */
     goto p_scan_recv_00;                   /* scan received block     */
   }

   p_start_recv:                            /* start receiving again   */
   if (adsl_clact_c_recv) {                 /* active cluster entry continue receive */
     adsl_clact_c_recv->boc_recv_active = TRUE;  /* receive is active  */
     adsl_clact_c_recv->dsc_tcpcomp.m_recv();  /* start receiving      */
   }
   if (adss_clact_proc_ch) {                /* chain to get processed */
     goto p_proc_start;                     /* start processing this active cluster */
   }

   p_wait_00:                               /* wait for next received data */
   iml_rc = dss_event_cluster.m_wait( &iml_error );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0013W xs-gw-cluster l%05d event m_wait Return Code %d Error %d.",
                     __LINE__, iml_rc, iml_error );
   }
   if (adss_clact_proc_ch) {                /* chain to get processed */
     goto p_proc_start;                     /* start processing this active cluster */
   }
   goto p_wait_00;                          /* wait for next received data */

   p_recv_err_00:                           /* received invalid packet */
   m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_recvcallback() p_recv_err_00",
                   __LINE__ );
   while (adss_clact_proc_ch->adsc_recv_ch) {  /* loop over buffers received */
     adsl_clrecv_w1 = adss_clact_proc_ch->adsc_recv_ch;  /* chain of received buffers */
     adss_clact_proc_ch->adsc_recv_ch = adsl_clrecv_w1->adsc_next;  /* remove from chain */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_recvcallback() -1- adsl_clrecv_w1->imc_usage_count=%d m_proc_free %p ???",
                     __LINE__, adsl_clrecv_w1->imc_usage_count, adsl_clrecv_w1 );
#endif
     if (adsl_clrecv_w1->imc_usage_count == 0) {
       m_proc_free( adsl_clrecv_w1 );       /* free block used         */
     }
   }
   adsl_clrecv_last = NULL;                 /* clear last in chain - no data */
   goto p_cont_recv;                        /* continue receiving      */
} /* end m_recv_block()                                                */

#endif

/** process control message received from other cluster member         */
static void m_recv_control( struct dsd_cluster_active *adsp_clact,
                            struct dsd_cluster_recv *adsp_clrecv, char * achp_data, int imp_length ) {
   BOOL       bol_no_start;                 /* is not start connection */
   BOOL       bol_server;                   /* server name received    */
   BOOL       bol_pid;                      /* PID received            */
   BOOL       bol_epoch_started;            /* epoch started received  */
   BOOL       bol_fingerprint;              /* fingerprint received    */
   BOOL       bol_endian;                   /* endian received         */
   BOOL       bol_alignment;                /* alignment received      */
   BOOL       bol_query_main;               /* query main received     */
   BOOL       bol_config_name;              /* configuration name received */
   BOOL       bol_config_group;             /* configuration group received */
   BOOL       bol_config_location;          /* configuration location received */
   BOOL       bol_config_url;               /* configuration URL received */
   int        iml1, iml2;                   /* working variables       */
   int        iml_rem;                      /* remaining input         */
   char       *achl_w1;                     /* working variable        */
   char       *achl_target;                 /* target of insert value  */
   char       chl_tag;                      /* tag of field            */
   time_t     dsl_time;
   HL_LONGLONG ill_value;                   /* value decoding          */
   struct dsd_cluster_recv *adsl_clrecv_w1;  /* block received from cluster member */
   struct dsd_cluster_remote *adsl_clrem_w1;  /* cluster remote structure */
   struct dsd_ineta_single_1 *adsl_ineta_s_w1;  /* single INETA target */
   char       chrl_disp_fp[ DEF_LEN_FINGERPRINT * 2 + DEF_LEN_FINGERPRINT / 2 - 1 ];
   char       chrl_work1[32];               /* work area               */

   bol_no_start = FALSE;                    /* is start connection     */
   bol_server = FALSE;                      /* server name received    */
   bol_pid = FALSE;                         /* PID received            */
   bol_epoch_started = FALSE;               /* epoch started received  */
   bol_fingerprint = FALSE;                 /* fingerprint received    */
   bol_endian = FALSE;                      /* endian received         */
   bol_alignment = FALSE;                   /* alignment received      */
   bol_query_main = FALSE;                  /* query main received     */
   bol_config_name = FALSE;                 /* configuration name received */
   bol_config_group = FALSE;                /* configuration group received */
   bol_config_location = FALSE;             /* configuration location received */
   bol_config_url = FALSE;                  /* configuration URL received */
   iml_rem = imp_length;                    /* remaining input         */
   achl_w1 = achp_data;                     /* data start here         */
   adsl_clrecv_w1 = adsp_clrecv;            /* first received block    */

   p_len_00:                                /* decode length           */
   if (iml_rem <= 0) {                      /* at end of data          */
     goto p_end_00;                         /* process end data        */
   }
   iml1 = 0;                                /* clear akkumulator       */
   iml2 = iml_rem - 4;                      /* maximum number of digits */
   if (iml2 < 0) iml2 = 0;                  /* minumum length          */
   while (TRUE) {                           /* loop to get length      */
     if (achl_w1 >= ((char *) (adsl_clrecv_w1 + 1) + adsl_clrecv_w1->imc_len_recv)) {  /* at end of received block */
       adsl_clrecv_w1 = adsl_clrecv_w1->adsc_next;  /* get next part   */
       if (adsl_clrecv_w1 == NULL) {        /* end of data reached     */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0200W l%05d Cluster INETA=%s control end of data but length set",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       achl_w1 = (char *) (adsl_clrecv_w1 + 1);  /* data from here     */
     }
     iml1 <<= 7;                            /* shift old value         */
     iml1 |= *achl_w1 & 0X7F;               /* apply new bits          */
     iml_rem--;                             /* one byte processed      */
     if ((*achl_w1 & 0X80) == 0) break;     /* more bit not set        */
     if (iml_rem <= iml2) {                 /* too many digits length  */
       m_hlnew_printf( HLOG_WARN1, "HWSPCL0201W l%05d Cluster INETA=%s control too many digits in length of field",
                       __LINE__, adsp_clact->chrc_ineta );
       goto p_error_00;                     /* error in datastream     */
     }
     achl_w1++;                             /* after last digit        */
   }
   achl_w1++;                               /* after last digit        */
   if (iml1 <= 0) {                         /* length value invalid    */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0202W l%05d Cluster INETA=%s control length of field zero - invalid",
                     __LINE__, adsp_clact->chrc_ineta );
     goto p_error_00;                       /* error in datastream     */
   }
   if (iml1 > MAX_LEN_RECV_FIELD) {         /* maximum length received field */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0203W l%05d Cluster INETA=%s control length of field %d - too high",
                     __LINE__, adsp_clact->chrc_ineta, iml1 );
     goto p_error_00;                       /* error in datastream     */
   }
   iml1 = iml_rem - iml1;                   /* position end of value   */
   if (iml1 < 0) {                          /* length too high         */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0204W l%05d Cluster INETA=%s control length of field longer than remaining data",
                     __LINE__, adsp_clact->chrc_ineta );
     goto p_error_00;                       /* error in datastream     */
   }
   chl_tag = *achl_w1++;                    /* tag of field            */
   iml_rem--;                               /* one byte processed      */
   achl_target = NULL;                      /* clear target of insert value */
   iml2 = iml_rem - iml1;                   /* length remaining field  */
   switch (chl_tag) {                       /* depend on tag           */
     case 0:                                /* server name received    */
       if (bol_server) {                    /* server name received double */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0210W l%05d Cluster INETA=%s control tag 0 server name double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0211W l%05d Cluster INETA=%s control tag 0 server name but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0212W l%05d Cluster INETA=%s control tag 0 server name length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (adsp_clact->imc_len_server_name) {  /* length server name   */
         free( adsp_clact->achc_server_name );  /* free old memory     */
       }
       achl_target = (char *) malloc( iml2 );  /* get new storage      */
       if (achl_target == NULL) {           /* no memory available     */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0213W l%05d Cluster INETA=%s control tag 0 server name malloc() failed - out of memory",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       adsp_clact->achc_server_name = achl_target;  /* server name in UTF-8 */
       adsp_clact->imc_len_server_name = iml2;  /* length server name  */
       bol_server = TRUE;                   /* server name received    */
       break;
     case 1:                                /* PID received            */
       if (bol_pid) {                       /* PID received double     */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0214W l%05d Cluster INETA=%s control tag 1 PID double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0215W l%05d Cluster INETA=%s control tag 1 PID but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0216W l%05d Cluster INETA=%s control tag 1 PID length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 > sizeof(adsp_clact->imc_pid)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0217W l%05d Cluster INETA=%s control tag 1 PID length %d too high",
                         __LINE__, adsp_clact->chrc_ineta, iml2 );
         goto p_error_00;                   /* error in datastream     */
       }
       bol_pid = TRUE;                      /* PID received            */
       ill_value = 0;                       /* clear value decoding    */
       break;
     case 2:                                /* epoch started received  */
       if (bol_epoch_started) {             /* epoch started received double */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0218W l%05d Cluster INETA=%s control tag 2 epoch started double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0219W l%05d Cluster INETA=%s control tag 2 epoch started but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0220W l%05d Cluster INETA=%s control tag 2 epoch started length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 > sizeof(adsp_clact->ilc_epoch_started)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0221W l%05d Cluster INETA=%s control tag 2 epoch started length %d too high",
                         __LINE__, adsp_clact->chrc_ineta, iml2 );
         goto p_error_00;                   /* error in datastream     */
       }
       bol_epoch_started = TRUE;            /* epoch started received  */
       ill_value = 0;                       /* clear value decoding    */
       break;
     case 3:                                /* fingerprint received    */
       if (bol_fingerprint) {               /* fingerprint received double */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0222W l%05d Cluster INETA=%s control tag 3 fingerprint double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0223W l%05d Cluster INETA=%s control tag 3 fingerprint but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0224W l%05d Cluster INETA=%s control tag 3 fingerprint length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 != DEF_LEN_FINGERPRINT) {   /* length not like required */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0225W l%05d Cluster INETA=%s control tag 3 fingerprint length %d invalid",
                         __LINE__, adsp_clact->chrc_ineta, iml2 );
         goto p_error_00;                   /* error in datastream     */
       }
       achl_target = adsp_clact->chrc_fingerprint;  /* address where to put fingerprint */
       bol_fingerprint = TRUE;              /* fingerprint received    */
       break;
     case 4:                                /* endian-ness received    */
       if (bol_endian) {                    /* endian received double  */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0226W l%05d Cluster INETA=%s control tag 4 endian double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0227W l%05d Cluster INETA=%s control tag 4 endian but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0228W l%05d Cluster INETA=%s control tag 4 endian length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 > sizeof(adsp_clact->boc_endian_big)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0229W l%05d Cluster INETA=%s control tag 4 endian length %d too high",
                         __LINE__, adsp_clact->chrc_ineta, iml2 );
         goto p_error_00;                   /* error in datastream     */
       }
       bol_endian = TRUE;                   /* endian received         */
       ill_value = 0;                       /* clear value decoding    */
       break;
     case 5:                                /* alignment received      */
       if (bol_alignment) {                 /* epoch started received double */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0230W l%05d Cluster INETA=%s control tag 5 alignment double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0231W l%05d Cluster INETA=%s control tag 5 alignment but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0232W l%05d Cluster INETA=%s control tag 5 aligment length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 > sizeof(adsp_clact->imc_aligment)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0233W l%05d Cluster INETA=%s control tag 5 alignment length %d too high",
                         __LINE__, adsp_clact->chrc_ineta, iml2 );
         goto p_error_00;                   /* error in datastream     */
       }
       bol_alignment = TRUE;                /* alignment received      */
       ill_value = 0;                       /* clear value decoding    */
       break;
     case 6:                                /* query main received     */
       if (bol_query_main) {                /* query main received double */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0234W l%05d Cluster INETA=%s control tag 6 query main double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0235W l%05d Cluster INETA=%s control tag 6 query main but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0236W l%05d Cluster INETA=%s control tag 6 query main length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (adsp_clact->imc_len_query_main) {  /* length query main     */
         free( adsp_clact->achc_query_main );  /* free old memory      */
       }
       achl_target = (char *) malloc( iml2 );  /* get new storage      */
       if (achl_target == NULL) {           /* no memory available     */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0237W l%05d Cluster INETA=%s control tag 6 query main malloc() failed - out of memory",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       adsp_clact->achc_query_main = achl_target;  /* query main in UTF-8 */
       adsp_clact->imc_len_query_main = iml2;  /* length query main    */
       bol_query_main = TRUE;               /* query main received     */
       break;
     case 7:                                /* configuration name received */
       if (bol_config_name) {               /* configuration name received double */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0238W l%05d Cluster INETA=%s control tag 7 configuration name double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0239W l%05d Cluster INETA=%s control tag 7 configuration name but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0240W l%05d Cluster INETA=%s control tag 7 configuration name length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (adsp_clact->imc_len_config_name) {  /* length configuration name */
         free( adsp_clact->achc_config_name );  /* free old memory     */
       }
       achl_target = (char *) malloc( iml2 );  /* get new storage      */
       if (achl_target == NULL) {           /* no memory available     */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0241W l%05d Cluster INETA=%s control tag 7 configuration name malloc() failed - out of memory",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       adsp_clact->achc_config_name = achl_target;  /* configuration name in UTF-8 */
       adsp_clact->imc_len_config_name = iml2;  /* length configuration name */
       bol_config_name = TRUE;                /* configuration name received */
       break;
     case 8:                                /* configuration group received */
       if (bol_config_group) {              /* configuration group received double */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0242W l%05d Cluster INETA=%s control tag 8 configuration group double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0243W l%05d Cluster INETA=%s control tag 8 configuration group but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0244W l%05d Cluster INETA=%s control tag 8 configuration group length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (adsp_clact->imc_len_group) {     /* length configuration group */
         free( adsp_clact->achc_group );    /* free old memory         */
       }
       achl_target = (char *) malloc( iml2 );  /* get new storage      */
       if (achl_target == NULL) {           /* no memory available     */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0245W l%05d Cluster INETA=%s control tag 8 configuration group malloc() failed - out of memory",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       adsp_clact->achc_group = achl_target;  /* configuration group in UTF-8 */
       adsp_clact->imc_len_group = iml2;    /* length configuration group */
       bol_config_group = TRUE;             /* configuration group received */
       break;
     case 9:                                /* configuration location received */
       if (bol_config_location) {           /* configuration location received double */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0246W l%05d Cluster INETA=%s control tag 9 configuration location double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0247W l%05d Cluster INETA=%s control tag 9 configuration location but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0248W l%05d Cluster INETA=%s control tag 9 configuration location length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (adsp_clact->imc_len_location) {  /* length configuration location */
         free( adsp_clact->achc_location );  /* free old memory        */
       }
       achl_target = (char *) malloc( iml2 );  /* get new storage      */
       if (achl_target == NULL) {           /* no memory available     */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0249W l%05d Cluster INETA=%s control tag 9 configuration location malloc() failed - out of memory",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       adsp_clact->achc_location = achl_target;  /* configuration location in UTF-8 */
       adsp_clact->imc_len_location = iml2;  /* length configuration location */
       bol_config_location = TRUE;          /* configuration location received */
       break;
     case 10:                               /* configuration URL received */
       if (bol_config_url) {                /* configuration URL received double */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0250W l%05d Cluster INETA=%s control tag 10 configuration URL double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0251W l%05d Cluster INETA=%s control tag 10 configuration URL but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0252W l%05d Cluster INETA=%s control tag 10 configuration URL length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (adsp_clact->imc_len_url) {       /* length configuration URL */
         free( adsp_clact->achc_url );      /* free old memory         */
       }
       achl_target = (char *) malloc( iml2 );  /* get new storage      */
       if (achl_target == NULL) {           /* no memory available     */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0253W l%05d Cluster INETA=%s control tag 10 configuration URL malloc() failed - out of memory",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       adsp_clact->achc_url = achl_target;  /* configuration URL in UTF-8 */
       adsp_clact->imc_len_url = iml2;      /* length configuration URL */
       bol_config_url = TRUE;               /* configuration URL received */
       break;
     default:
       m_hlnew_printf( HLOG_WARN1, "HWSPCL0260W l%05d Cluster INETA=%s control tag 0X%02X received - not defined",
                       __LINE__, adsp_clact->chrc_ineta, (unsigned char) chl_tag );
       break;
   }
   if (iml_rem <= iml1) {
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0261W l%05d Cluster INETA=%s control tag 0X%02X length %d less than remaining data %d.",
                     __LINE__, adsp_clact->chrc_ineta, (unsigned char) chl_tag, iml1, iml_rem );
     goto p_error_00;                       /* error in datastream     */
   }
   do {                                     /* loop to process value   */
     if (achl_w1 >= ((char *) (adsl_clrecv_w1 + 1) + adsl_clrecv_w1->imc_len_recv)) {  /* at end of received block */
       adsl_clrecv_w1 = adsl_clrecv_w1->adsc_next;  /* get next part   */
       if (adsl_clrecv_w1 == NULL) {        /* end of data reached     */
         return;                            /* needs more data         */
       }
       achl_w1 = (char *) (adsl_clrecv_w1 + 1);  /* data from here     */
     }
     if (achl_target) {                     /* alpha-numeric field     */
       *achl_target++ = *achl_w1;           /* apply character         */
     } else {                               /* numeric field           */
       ill_value <<= 8;                     /* shift old value         */
       ill_value |= (unsigned char) *achl_w1;  /* apply new bits       */
     }
     achl_w1++;                             /* after last digit        */
     iml_rem--;                             /* one byte processed      */
   } while (iml_rem > iml1);
   switch (chl_tag) {                       /* depend on tag           */
     case 1:                                /* PID received            */
       adsp_clact->imc_pid = (int) ill_value;  /* PID                  */
       break;
     case 2:                                /* epoch started received  */
       adsp_clact->ilc_epoch_started = ill_value;  /* set epoch started */
       break;
     case 4:                                /* endian-ness received    */
       adsp_clact->boc_endian_big = (BOOL) ill_value;  /* set endian   */
       break;
     case 5:                                /* alignment received      */
       adsp_clact->imc_aligment = (int) ill_value;  /* set alignment   */
       break;
   }
   goto p_len_00;                           /* decode length           */

   p_error_00:                              /* error in datastream     */
   m_hlnew_printf( HLOG_WARN1, "HWSPCL0262W xs-gw-cluster-l%05d-W p_error_00",
                   __LINE__ );
   return;

   p_end_00:                                /* process end data        */
   if (bol_server == FALSE) {               /* server name missing     */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0270W l%05d Cluster INETA=%s tag received start - tag 0 server name missing",
                     __LINE__, adsp_clact->chrc_ineta );
     if (adsp_clact->imc_len_server_name) {  /* length server name     */
       free( adsp_clact->achc_server_name );  /* free old memory       */
     }
     adsp_clact->achc_server_name = (char *) malloc( 3 );  /* server name in UTF-8 */
     if (adsp_clact->achc_server_name == NULL) {  /* malloc() failed   */
       goto p_error_00;                     /* process error           */
     }
     memcpy( adsp_clact->achc_server_name, "???", 3 );  /* server name in UTF-8 */
     adsp_clact->imc_len_server_name = 3;   /* length server name      */
   }
   if (bol_pid == FALSE) {                  /* PID missing             */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0271W l%05d Cluster INETA=%s tag received start - tag 1 PID missing",
                     __LINE__, adsp_clact->chrc_ineta );
   }
   if (bol_epoch_started == FALSE) {        /* epoch started missing   */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0272W l%05d Cluster INETA=%s tag received start - tag 2 epoch started missing",
                     __LINE__, adsp_clact->chrc_ineta );
   }
   if (bol_fingerprint == FALSE) {          /* fingerprint missing     */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0273W l%05d Cluster INETA=%s tag received start - tag 3 fingerprint missing",
                     __LINE__, adsp_clact->chrc_ineta );
   }
   if (bol_endian == FALSE) {               /* endian missing          */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0274W l%05d Cluster INETA=%s tag received start - tag 4 endian missing",
                     __LINE__, adsp_clact->chrc_ineta );
   }
   if (bol_alignment == FALSE) {            /* alignment missing       */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0275W l%05d Cluster INETA=%s tag received start - tag 5 alignment missing",
                     __LINE__, adsp_clact->chrc_ineta );
   }
   if (bol_query_main == FALSE) {           /* query main received     */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0276W l%05d Cluster INETA=%s tag received start - tag 6 query-main missing",
                     __LINE__, adsp_clact->chrc_ineta );
   }
   if (bol_config_name == FALSE) {          /* configuration name missing */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0277W l%05d Cluster INETA=%s tag received start - tag 7 configuration name missing",
                     __LINE__, adsp_clact->chrc_ineta );
     if (adsp_clact->imc_len_config_name) {  /* length configuration name */
       free( adsp_clact->achc_config_name );  /* free old memory       */
     }
     adsp_clact->achc_config_name = (char *) malloc( 3 );  /* configuration name in UTF-8 */
     if (adsp_clact->achc_config_name == NULL) {  /* malloc() failed   */
       goto p_error_00;                     /* process error           */
     }
     memcpy( adsp_clact->achc_config_name, "???", 3 );  /* configuration name in UTF-8 */
     adsp_clact->imc_len_config_name = 3;   /* length configuration name */
   }
   adsp_clact->imc_epoch_conn = m_get_time();  /* time/epoch connected */
   m_hlnew_printf( HLOG_INFO1, "HWSPCL0041I Cluster INETA=%s contacted by server name %.*(u8)s PID %d.",
                   adsp_clact->chrc_ineta,
                   adsp_clact->imc_len_server_name, adsp_clact->achc_server_name,
                   adsp_clact->imc_pid );
   dsl_time = adsp_clact->ilc_epoch_started / 1000;  /* time in seconds */
   strftime( chrl_work1, sizeof(chrl_work1), "%d.%m.%y %H:%M:%S", localtime( &dsl_time ) );
   m_hlnew_printf( HLOG_INFO1, "HWSPCL0042I Cluster INETA=%s contacted by other configuration name %.*(u8)s started time %s.",
                   adsp_clact->chrc_ineta,
                   adsp_clact->imc_len_config_name, adsp_clact->achc_config_name,
                   chrl_work1 );
   m_edit_fingerprint( chrl_disp_fp, adsp_clact->chrc_fingerprint );
   m_hlnew_printf( HLOG_INFO1, "HWSPCL0043I Cluster INETA=%s contacted by WSP fingerprint %.*s.",
                   adsp_clact->chrc_ineta,
                   sizeof(chrl_disp_fp), chrl_disp_fp );
   if (adsp_clact->imc_len_query_main > 0) {  /* length query main     */
     m_hlnew_printf( HLOG_INFO1, "HWSPCL0044I Cluster INETA=%s contacted by other WSP version %.*(u8)s.",
                     adsp_clact->chrc_ineta,
                     adsp_clact->imc_len_query_main, adsp_clact->achc_query_main );
   }
   if (adsp_clact->imc_len_group > 0) {     /* length configuration group */
     m_hlnew_printf( HLOG_INFO1, "HWSPCL0045I Cluster INETA=%s contacted by other WSP group %.*(u8)s.",
                     adsp_clact->chrc_ineta,
                     adsp_clact->imc_len_group, adsp_clact->achc_group );
   }
   if (adsp_clact->imc_len_location > 0) {  /* length configuration location */
     m_hlnew_printf( HLOG_INFO1, "HWSPCL0046I Cluster INETA=%s contacted by other WSP location %.*(u8)s.",
                     adsp_clact->chrc_ineta,
                     adsp_clact->imc_len_location, adsp_clact->achc_location );
   }
   if (adsp_clact->imc_len_url > 0) {       /* length configuration URL */
     m_hlnew_printf( HLOG_INFO1, "HWSPCL0047I Cluster INETA=%s contacted by other WSP URL %.*(u8)s.",
                     adsp_clact->chrc_ineta,
                     adsp_clact->imc_len_url, adsp_clact->achc_url );
   }
   if (adsp_clact->adsc_clrem) {            /* remote structure set    */
     goto p_end_80;                         /* entry is valid          */
   }
#ifdef HL_UNIX
   if (adsp_clact->boc_unix_socket) {       /* is Unix domain socket   */
     goto p_end_80;                         /* entry is valid          */
   }
#endif
   if (adss_cluster_main == NULL) {         /* nothing configured      */
     if (adss_cluster_main->boc_deny_not_configured == FALSE) {  /* deny connect in from not configured WSP */
       goto p_end_80;                       /* entry is valid          */
     }
     goto p_end_40;                         /* entry is invalid        */
   }

   /* check if this cluster entry is configured                        */
   adsl_clrem_w1 = adss_cluster_main->adsc_clre;  /* chain of remote WSPs */
   while (adsl_clrem_w1) {                  /* loop over chain of remote WSPs */
     while (TRUE) {                         /* pseudo-loop             */
       if (adsl_clrem_w1->imc_len_name != adsp_clact->imc_len_config_name) break;
       if (memcmp( adsl_clrem_w1->achc_name,
                   adsp_clact->achc_config_name,
                   adsl_clrem_w1->imc_len_name )) {
         break;
       }
       iml1 = 0;                            /* search INETA from connect */
       adsl_ineta_s_w1 = (struct dsd_ineta_single_1 *) (adsl_clrem_w1->adsc_remote_ineta + 1);
       while (iml1 < adsl_clrem_w1->adsc_remote_ineta->imc_no_ineta) {
         while (TRUE) {                     /* pseudo-loop             */
           if (adsl_ineta_s_w1->usc_family != ((struct sockaddr *) &adsp_clact->dsc_soa)->sa_family) break;
           switch (adsl_ineta_s_w1->usc_family) {
             case AF_INET:
               if (*((UNSIG_MED *) &(((struct sockaddr_in *) &adsp_clact->dsc_soa)->sin_addr))
                    == *((UNSIG_MED *) (adsl_ineta_s_w1 + 1))) {
                 adsl_ineta_s_w1 = NULL;    /* entry found             */
               }
               break;
             case AF_INET6:
               if (!memcmp( &((struct sockaddr_in6 *) &adsp_clact->dsc_soa)->sin6_addr,
                            adsl_ineta_s_w1 + 1,
                            16 )) {
                 adsl_ineta_s_w1 = NULL;    /* entry found             */
               }
               break;
           }
           if (adsl_ineta_s_w1) break;      /* entry not found         */
           adsp_clact->adsc_clrem = adsl_clrem_w1;  /* set corresponding remote WSP */
           goto p_end_80;                   /* entry is valid          */
         }
         adsl_ineta_s_w1
           = (struct dsd_ineta_single_1 *)
               ((char *) (adsl_ineta_s_w1 + 1) + adsl_ineta_s_w1->usc_length);
         iml1++;                            /* increment index         */
       }
       break;                               /* entry not found         */
     }
     adsl_clrem_w1 = adsl_clrem_w1->adsc_next;  /* get next in chain   */
   }
   if (adss_cluster_main->boc_deny_not_configured == FALSE) {  /* deny connect in from not configured WSP */
     goto p_end_80;                         /* entry is valid          */
   }

   p_end_40:                                /* entry is invalid        */
   m_hlnew_printf( HLOG_WARN1, "HWSPCL0047W Cluster INETA=%s not configured - refused",
                   adsp_clact->chrc_ineta );
   m_send_end_clact( adsp_clact );          /* send end to partner     */
   return;

   p_end_80:                                /* entry is valid          */
   if (adsp_clact->imc_len_group == adss_cluster_main->imc_this_len_group) {  /* length of group in bytes */
     if (adsp_clact->imc_len_group == 0) {  /* no group configured     */
       adsp_clact->boc_same_group = TRUE;   /* is in same group as main */
     } else {
       if (!memcmp( adsp_clact->achc_group,
                    adss_cluster_main->achc_this_group,
                    adsp_clact->imc_len_group )) {
         adsp_clact->boc_same_group = TRUE;  /* is in same group as main */
       }
     }
   }
   if (adsp_clact->iec_clr_stat == ied_clrs_acc_recv_st) {  /* after accept start receive */
     m_send_control_init( adsp_clact );     /* send control init now   */
     adsp_clact->iec_clr_stat = ied_clrs_acc_init_sent;  /* after control init has been sent */
   }
   m_check_cluster_member_double( adsp_clact, FALSE );
   return;
} /* end m_recv_control()                                              */

/** process message redirect, received from other cluster member       */
static void m_recv_redirect( struct dsd_cluster_active *adsp_clact,
                             struct dsd_cluster_recv *adsp_clrecv, char * achp_data, int imp_length ) {
   int        iml1, iml2;                   /* working variables       */
   int        iml_rem;                      /* remaining input         */
   int        iml_len_part;                 /* length of part          */
   char       *achl_w1, *achl_w2;           /* working variable        */
   char       *achl_part;                   /* here is part            */
   struct dsd_cluster_recv *adsl_clrecv_w1;  /* block received from cluster member */
   char       chrl_work1[ 512 ];            /* work area               */

   iml_rem = imp_length;                    /* remaining input         */
   achl_w1 = achp_data;                     /* data start here         */
   adsl_clrecv_w1 = adsp_clrecv;            /* first received block    */

   p_len_00:                                /* decode length           */
   if (iml_rem <= 0) {                      /* at end of data          */
     return;                                /* all done                */
   }
   iml_len_part = 0;                        /* clear akkumulator       */
   iml1 = iml_rem - 4;                      /* maximum number of digits */
   if (iml1 < 0) iml1 = 0;                  /* minimum length          */
   while (TRUE) {                           /* loop to get length      */
     if (achl_w1 >= ((char *) (adsl_clrecv_w1 + 1) + adsl_clrecv_w1->imc_len_recv)) {  /* at end of received block */
       adsl_clrecv_w1 = adsl_clrecv_w1->adsc_next;  /* get next part   */
       if (adsl_clrecv_w1 == NULL) {        /* end of data reached     */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0200W l%05d Cluster INETA=%s redirect end of data but length set",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       achl_w1 = (char *) (adsl_clrecv_w1 + 1);  /* data from here     */
     }
     iml_len_part <<= 7;                    /* shift old value         */
     iml_len_part |= *achl_w1 & 0X7F;       /* apply new bits          */
     iml_rem--;                             /* one byte processed      */
     if ((*achl_w1 & 0X80) == 0) break;     /* more bit not set        */
     if (iml_rem <= iml1) {                 /* too many digits length  */
       m_hlnew_printf( HLOG_WARN1, "HWSPCL0201W l%05d Cluster INETA=%s redirect too many digits in length of field",
                       __LINE__, adsp_clact->chrc_ineta );
       goto p_error_00;                     /* error in datastream     */
     }
     achl_w1++;                             /* after last digit        */
   }
   achl_w1++;                               /* after last digit        */
   if (iml_len_part <= 0) {                 /* length value invalid    */
     m_hlnew_printf( HLOG_WARN1, "HWSPCLnnnnW l%05d Cluster INETA=%s redirect length of field zero - invalid",
                     __LINE__, adsp_clact->chrc_ineta );
     goto p_error_00;                       /* error in datastream     */
   }
   if (iml_len_part > sizeof(chrl_work1)) {  /* maximum length received field */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0203W l%05d Cluster INETA=%s redirect length of field %d - too high",
                     __LINE__, adsp_clact->chrc_ineta, iml_len_part );
     goto p_error_00;                       /* error in datastream     */
   }
#ifdef XYZ1
   iml1 = iml_rem - iml1;                   /* position end of value   */
   if (iml1 < 0) {                          /* length too high         */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0204W l%05d Cluster INETA=%s redirect length of field longer than remaining data",
                     __LINE__, adsp_clact->chrc_ineta );
     goto p_error_00;                       /* error in datastream     */
   }
#endif
   if (iml_len_part > iml_rem) {            /* length too high         */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0204W l%05d Cluster INETA=%s redirect length of field longer than remaining data",
                     __LINE__, adsp_clact->chrc_ineta );
     goto p_error_00;                       /* error in datastream     */
   }
   if ((achl_w1 + iml_len_part) <= ((char *) (adsl_clrecv_w1 + 1) + adsl_clrecv_w1->imc_len_recv)) {  /* not end of received block */
     achl_part = achl_w1;                   /* here is part            */
     achl_w1 += iml_len_part;               /* input consumed          */
     iml_rem -= iml_len_part;               /* input consumed          */
     goto p_part_00;                        /* part decoded            */
   }
   iml1 = iml_len_part;                     /* decode this part        */
   achl_part = achl_w2 = chrl_work1;        /* here is part            */
   do {                                     /* loop to process value   */
     if (achl_w1 >= ((char *) (adsl_clrecv_w1 + 1) + adsl_clrecv_w1->imc_len_recv)) {  /* at end of received block */
       adsl_clrecv_w1 = adsl_clrecv_w1->adsc_next;  /* get next part   */
       if (adsl_clrecv_w1 == NULL) {        /* end of data reached     */
         return;                            /* needs more data         */
       }
       achl_w1 = (char *) (adsl_clrecv_w1 + 1);  /* data from here     */
     }
     iml2 = ((char *) (adsl_clrecv_w1 + 1) + adsl_clrecv_w1->imc_len_recv) - achl_w1;  /* length in this block */
     if (iml2 > iml1) iml2 = iml1;          /* only as much as needed  */
     memcpy( achl_w2, achl_w1, iml2 );      /* copy part of part       */
     achl_w1 += iml2;                       /* after this area         */
     achl_w2 += iml2;                       /* after this area         */
     iml_rem -= iml2;                       /* bytes processed         */
     iml1 -= iml2;                          /* bytes processed         */
   } while (iml1 > 0);

   p_part_00:                               /* part decoded            */
   m_cluster_redirect_conn( adsp_clact, achl_part, iml_len_part );
   goto p_len_00;                           /* decode length           */

   p_error_00:                              /* error in datastream     */
   m_hlnew_printf( HLOG_WARN1, "HWSPCL0252W xs-gw-cluster-l%05d-W p_error_00",
                   __LINE__ );
   return;
} /* end m_recv_redirect()                                             */

/** process load-balancing message, received from other cluster member */
static void m_recv_cluster_lbal( struct dsd_cluster_active *adsp_clact, char *achp_data ) {
   BOOL       bol1;                         /* working-variable        */
   int        iml1;                         /* working-variable        */
#ifndef B111210
   BOOL       bol_send;                     /* send status             */
   BOOL       iml_trace_line;               /* line of trace           */
   char       *achl_status;                 /* text with status        */
   char       *achl_send;                   /* text send               */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
#endif
#ifdef XYZ1
   char       chc_lbal_status;              /* status received in load-balancing */
   int        imc_lbal_load;                /* load reported in load-balancing */
   int        imc_lbal_epoch_recv;          /* epoch last report load-balancing received */
   int        imc_lbal_epoch_sent;          /* epoch last report load-balancing sent */
#endif

   adsp_clact->imc_lbal_epoch_recv = m_get_time();  /* epoch last report load-balancing received */
#ifdef B120906
   adsp_clact->chc_lbal_status = *(achp_data + 0);  /* status received in load-balancing */
   adsp_clact->imc_lbal_load                /* load reported in load-balancing */
     = (*((unsigned char *) achp_data + 1) << 16)
         | (*((unsigned char *) achp_data + 2) << 8)
         | *((unsigned char *) achp_data + 3);
#else
   if (achp_data) {                         /* data passed             */
     adsp_clact->chc_lbal_status = *(achp_data + 0);  /* status received in load-balancing */
     adsp_clact->imc_lbal_load              /* load reported in load-balancing */
       = (*((unsigned char *) achp_data + 1) << 16)
           | (*((unsigned char *) achp_data + 2) << 8)
           | *((unsigned char *) achp_data + 3);
   }
#endif
#ifdef TRACEHL_LOAD
#ifndef HL_UNIX
   m_hlnew_printf( HLOG_TRACE1, "p%06d l%05d xs-gw-cluster m_recv_cluster_lbal( 0X%p , . ) load %d.",
                   GetCurrentProcessId(), __LINE__, adsp_clact, adsp_clact->imc_lbal_load );
#else
   m_hlnew_printf( HLOG_TRACE1, "p%06d l%05d xs-gw-cluster m_recv_cluster_lbal( 0X%p , . ) load %d.",
                   getpid(), __LINE__, adsp_clact, adsp_clact->imc_lbal_load );
#endif
#endif
#ifdef B111210
   if (adss_cluster_main->imc_lbal_intv == 0) return;  /* <interval-load-balancing-probe> */
   if (adsp_clact->chc_lbal_status & DEF_SYS_STATE_LISTEN_ENDED) return;  /* listen has already ended */
   iml1 = (adsp_clact->imc_lbal_epoch_recv - adsp_clact->imc_lbal_epoch_sent) * 10;
   bol1 = m_status_cluster_lbal();
   if (bol1) return;                        /* status already sent to all connected WSPs */
   if (iml1 <= adss_cluster_main->imc_lbal_intv) return;
   m_send_cluster_lbal( adsp_clact );       /* send status to this active WSP */
#endif
#ifndef B111210
   bol_send = FALSE;                        /* send status             */
   achl_send = "do not send message";       /* text send               */
   achl_status = "01 interval zero";        /* text with status        */
   iml_trace_line = __LINE__;               /* line of trace           */
   if (adss_cluster_main->imc_lbal_intv == 0) {  /* <interval-load-balancing-probe> */
     goto p_lbal_40;                        /* status set              */
   }
   achl_status = "02 listen ended";         /* text with status        */
   iml_trace_line = __LINE__;               /* line of trace           */
   if (adsp_clact->chc_lbal_status & DEF_SYS_STATE_LISTEN_ENDED) {  /* listen has already ended */
     goto p_lbal_40;                        /* status set              */
   }
   iml1 = (adsp_clact->imc_lbal_epoch_recv - adsp_clact->imc_lbal_epoch_sent) * 10;
   bol1 = m_status_cluster_lbal( FALSE );
   achl_status = "03 status already set";   /* text with status        */
   iml_trace_line = __LINE__;               /* line of trace           */
   if (bol1) {                              /* status already sent to all connected WSPs */
     goto p_lbal_40;                        /* status set              */
   }
   achl_status = "04 time not elapsed";     /* text with status        */
   iml_trace_line = __LINE__;               /* line of trace           */
   if (iml1 <= adss_cluster_main->imc_lbal_intv) {
     goto p_lbal_40;                        /* status set              */
   }
   bol_send = FALSE;                        /* send status             */
   achl_send = "send message now";          /* text send               */
   achl_status = "05 send message";         /* text with status        */
   iml_trace_line = __LINE__;               /* line of trace           */

   p_lbal_40:                               /* status set              */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_CLUSTER) {  /* core cluster */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CCLULBRE", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
//   adsl_wt1_w1->imc_wtrt_sno = 0;         /* WSP session number      */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "continue received %s - line %05d - action %s",
                     achl_status, iml_trace_line, achl_send );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (bol_send == FALSE) return;           /* send status             */
#ifndef B120906
   if (adsp_clact->iec_clr_stat != ied_clrs_open) return;  /* state is not open */
#endif
   m_send_cluster_lbal( adsp_clact );       /* send status to this active WSP */
#endif
} /* end m_recv_cluster_lbal()                                         */

/** calculate the new state of load-balancing                          */
extern "C" BOOL m_status_cluster_lbal( BOOL bop_listen_started ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
#ifdef TRACEHL1
   int        iml2;                         /* working variable        */
#endif
   BOOL       bol_ret;                      /* return value            */
   BOOL       bol_listen_active;            /* listen is currently active */
   char       *achl1, *achl2;               /* working variables       */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster entry  */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */

   if (adss_cluster_main == NULL) {         /* no cluster configured   */
     return FALSE;                          /* nothing done            */
   }
#ifndef NO_LOCK_1110
   bol1 = FALSE;                            /* no access               */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX2T l%05d m_enter() before", __LINE__ );
#endif
   dss_critsect_cluster.m_enter();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX3T l%05d m_enter() after", __LINE__ );
#endif
   if (bos_lbal_lock == FALSE) {            /* load-balancing lock     */
     bos_lbal_lock = TRUE;                  /* load-balancing lock     */
     bol1 = TRUE;                           /* with access             */
   }
   dss_critsect_cluster.m_leave();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX4T l%05d m_leave() after", __LINE__ );
#endif
   if (bol1 == FALSE) {                     /* no access               */
     return FALSE;                          /* reply if necessary      */
   }
#endif
   if (dss_cluster_timer_lbal.dsc_timer_ele.vpc_chain_2) {  /* timer set */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster dss_cluster_timer_lbal m_time_rel() m_status_cluster_lbal()",
                     __LINE__ );
#endif
     m_time_rel( &dss_cluster_timer_lbal.dsc_timer_ele );  /* release timer */
   }
   dsg_sys_state_1.imc_load_balancing_value = m_get_load();  /* last value returned by load-balancing */
#ifdef TRACEHL_LOAD
#ifndef HL_UNIX
   m_hlnew_printf( HLOG_TRACE1, "p%06d l%05d xs-gw-cluster m_status_cluster_lbal() m_get_load() returned %d listen %d.",
                   GetCurrentProcessId(), __LINE__, dsg_sys_state_1.imc_load_balancing_value, dsg_sys_state_1.boc_listen_active );
#else
   m_hlnew_printf( HLOG_TRACE1, "p%06d l%05d xs-gw-cluster m_status_cluster_lbal() m_get_load() returned %d listen %d.",
                   getpid(), __LINE__, dsg_sys_state_1.imc_load_balancing_value, dsg_sys_state_1.boc_listen_active );
#endif
#endif
   dsg_sys_state_1.imc_load_balancing_epoch = m_get_time();  /* time last load-balancing query was done */
   if (adss_cluster_main->boc_display_load) {  /* display load every time calculated */
     m_hlnew_printf( HLOG_INFO1, "HWSPCL0030I Cluster current load %d (calculated l%05d)",
                     dsg_sys_state_1.imc_load_balancing_value, __LINE__ );
   }
   bol_listen_active = TRUE;                /* listen is currently active */
   if (dsg_sys_state_1.imc_epoch_listen_act) {  /* epoch until which listen keeps active */
     if (dsg_sys_state_1.imc_epoch_listen_act > dsg_sys_state_1.imc_load_balancing_epoch) {  /* keep listen active */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-W m_status_cluster_lbal() dsg_sys_state_1.imc_epoch_listen_act=%d dsg_sys_state_1.imc_load_balancing_epoch=%d.",
                       __LINE__, dsg_sys_state_1.imc_epoch_listen_act, dsg_sys_state_1.imc_load_balancing_epoch );
#endif
       goto p_stat_20;                      /* do not check load-balancing */
     }
     dsg_sys_state_1.imc_epoch_listen_act = 0;  /* reset epoch until which listen keeps active */
   }
#ifdef TRACEHL1
   iml1 = iml2 = 0;                         /* clear counters          */
   adsl_clact_w1 = adsg_clact_ch;           /* get chain of active cluster entries */
   while (adsl_clact_w1) {                  /* loop over all active cluster entries */
     iml1++;                                /* increase counter active cluster entry */
     if (   (adsl_clact_w1->iec_clr_stat == ied_clrs_open)  /* state is open */
         && (adsl_clact_w1->boc_same_group)) {  /* is in same group as main */
       iml2++;                              /* increase counter open   */
     }
     adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
   }
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T m_status_cluster_lbal() chain of active cluster entries %d open %d.",
                       __LINE__, iml1, iml2 );
#endif
   adsl_clact_w1 = adsg_clact_ch;           /* get chain of active cluster entries */
   while (adsl_clact_w1) {                  /* loop over all active cluster entries */
     if (   (adsl_clact_w1->iec_clr_stat == ied_clrs_open)  /* state is open */
         && (adsl_clact_w1->boc_same_group)  /* is in same group as main */
         && (adsl_clact_w1->imc_lbal_load >= 0)  /* load already received */
         && ((adsl_clact_w1->chc_lbal_status
                & (DEF_SYS_STATE_LISTEN_INACTIVE | DEF_SYS_STATE_LISTEN_ENDED)) == 0)  /* listen all active */
         && ((adsl_clact_w1->imc_lbal_load + adss_cluster_main->imc_lbal_diff)
               < dsg_sys_state_1.imc_load_balancing_value)) {
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-W m_status_cluster_lbal() -1- adsl_clact_w1=%p chc_lbal_status=0X%X.",
                       __LINE__, adsl_clact_w1, adsl_clact_w1->chc_lbal_status );
       m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-W m_status_cluster_lbal() -2- imc_lbal_load=%d adss_cluster_main->imc_lbal_diff=%d dsg_sys_state_1.imc_load_balancing_value=%d.",
                       __LINE__, adsl_clact_w1->imc_lbal_load, adss_cluster_main->imc_lbal_diff, dsg_sys_state_1.imc_load_balancing_value );
#endif
       bol_listen_active = FALSE;           /* listen should not be active */
       break;                               /* stop searching          */
     }
     adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
   }

   p_stat_20:                               /* load-balancing has been checked */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_CLUSTER) {  /* core cluster */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CCLULOAD", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
//   adsl_wt1_w1->imc_wtrt_sno = 0;         /* WSP session number      */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
     achl1 = achl2 = "OPEN";
     if (dsg_sys_state_1.boc_listen_active == FALSE) {
       achl1 = "CLOSED";
     }
     if (bol_listen_active == FALSE) {      /* stop listening          */
       achl2 = "CLOSED";
     }
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "current load %d listen state old:%s new:%s",
                     dsg_sys_state_1.imc_load_balancing_value, achl1, achl2 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   bol_ret = FALSE;                         /* return value            */
#ifdef B121107
   bol1 = FALSE;                            /* state did not change    */
#else
   bol1 = bop_listen_started;               /* set if state changed    */
#endif
   if (bol_listen_active == dsg_sys_state_1.boc_listen_active) goto p_stat_40;  /* nothing changed */
#ifndef HL_UNIX
   bol1 = TRUE;                             /* state did change        */
#endif
// dsg_sys_state_1.boc_listen_active = bol_listen_active;  /* set new state */
   if (bol_listen_active) {                 /* start listening         */
     iml1 = m_start_all_listen( TRUE );
#ifdef HL_UNIX
     if (iml1 < 0) {                        /* listen-gateway - already started */
       goto p_stat_40;                      /* all done - restart timer */
     }
#endif
     m_hlnew_printf( HLOG_INFO1, "HWSPCL0053I Cluster load %d listen started ports %d.",
                     dsg_sys_state_1.imc_load_balancing_value, iml1 );
#ifdef HL_UNIX
     bol1 = dsg_sys_state_1.boc_listen_active;  /* state did change    */
#endif
   } else {                                 /* stop listening          */
     iml1 = m_stop_all_listen( TRUE );
     m_hlnew_printf( HLOG_INFO1, "HWSPCL0052I Cluster load %d listen stopped ports %d.",
                     dsg_sys_state_1.imc_load_balancing_value, iml1 );
#ifdef HL_UNIX
     bol1 = TRUE;                           /* state did change        */
#endif
   }
#ifdef B120829
   adsl_clact_w1 = adsg_clact_ch;           /* get chain of active cluster entries */
   while (adsl_clact_w1) {                  /* loop over all active cluster entries */
     if (   (adsl_clact_w1->iec_clr_stat == ied_clrs_open)  /* state is open */
         && ((adsl_clact_w1->chc_lbal_status & DEF_SYS_STATE_LISTEN_ENDED) == 0)) {  /* listen has not yet ended */
       m_send_cluster_lbal( adsl_clact_w1 );
     }
     adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
   }
   bol_ret = TRUE;                          /* all entries notified    */

   p_stat_40:                               /* all done - restart timer */
#endif
#ifndef B120829

   p_stat_40:                               /* all done - restart timer */
   adsl_clact_w1 = adsg_clact_ch;           /* get chain of active cluster entries */
#ifdef B120910
   while (adsl_clact_w1) {                  /* loop over all active cluster entries */
     if (   (adsl_clact_w1->iec_clr_stat == ied_clrs_open)  /* state is open */
         && ((adsl_clact_w1->chc_lbal_status & DEF_SYS_STATE_LISTEN_ENDED) == 0)  /* listen has not yet ended */
         && (   (bol1)                      /* state did change        */
             || (adsl_clact_w1->imc_lbal_epoch_sent < (dsg_sys_state_1.imc_load_balancing_epoch - adss_cluster_main->imc_lbal_intv)))) {
       m_send_cluster_lbal( adsl_clact_w1 );
     }
     adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
   }
#else
   iml1 = adss_cluster_main->imc_lbal_intv - DEF_CLUSTER_SEND_ROUNDED;
   if (iml1 < DEF_CLUSTER_SEND_ROUNDED) iml1 = DEF_CLUSTER_SEND_ROUNDED;
   while (adsl_clact_w1) {                  /* loop over all active cluster entries */
     if (   (adsl_clact_w1->iec_clr_stat == ied_clrs_open)  /* state is open */
         && ((adsl_clact_w1->chc_lbal_status & DEF_SYS_STATE_LISTEN_ENDED) == 0)  /* listen has not yet ended */
         && (   (bol1)                      /* state did change        */
             || (adsl_clact_w1->imc_lbal_epoch_sent < (dsg_sys_state_1.imc_load_balancing_epoch - iml1)))) {
       m_send_cluster_lbal( adsl_clact_w1 );
     }
     adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
   }
#endif
   bol_ret = TRUE;                          /* all entries notified    */
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster dss_cluster_timer_lbal m_time_set( time=%lld ) m_status_cluster_lbal()",
                   __LINE__, (HL_LONGLONG) (adss_cluster_main->imc_lbal_intv * 1000) );
#ifdef XYZ1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster dss_cluster_timer_lbal m_time_set( time=%d ) m_status_cluster_lbal()",
                   __LINE__, (int) (adss_cluster_main->imc_lbal_intv * 1000) );
#endif
#endif
   dss_cluster_timer_lbal.dsc_timer_ele.ilcwaitmsec = adss_cluster_main->imc_lbal_intv * 1000;  /* wait in milliseconds */
   m_time_set( &dss_cluster_timer_lbal.dsc_timer_ele, FALSE );  /* set timer now */
#ifndef NO_LOCK_1110
   bos_lbal_lock = FALSE;                   /* load-balancing lock     */
#endif
   return bol_ret;                          /* return as set           */
} /* end m_status_cluster_lbal()                                       */

/** send load-balancing message to other cluster member                */
static void m_send_cluster_lbal( struct dsd_cluster_active *adsp_clact ) {
   int        iml1;                         /* working variable        */
   char       *achl_w1;                     /* working variable        */
   struct dsd_cluster_send *adsl_clsend_w1;  /* send buffer            */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_send_cluster_lbal() called",
                   __LINE__ );
#endif
   adsp_clact->imc_lbal_epoch_sent = m_get_time();  /* epoch last report load-balancing sent */
   adsl_clsend_w1 = (struct dsd_cluster_send *) m_proc_alloc();
   achl_w1 = (char *) adsl_clsend_w1 + LEN_TCP_RECV - 8;
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsl_clsend_w1 + 1))
   ADSL_GAI1_W1->achc_ginp_cur = achl_w1;
   *(achl_w1 + 0) = 0;                      /* state                   */
   if (dsg_sys_state_1.boc_listen_active == FALSE) {
     *(achl_w1 + 0) = DEF_SYS_STATE_LISTEN_INACTIVE;  /* state         */
   }
   if (dsg_sys_state_1.boc_listen_ended) {  /* listen has already ended */
     *(achl_w1 + 0) |= DEF_SYS_STATE_LISTEN_ENDED;  /* listen has already ended */
   }
   *(achl_w1 + 0 + 1) = (unsigned char) (dsg_sys_state_1.imc_load_balancing_value >> 16);
   *(achl_w1 + 0 + 2) = (unsigned char) (dsg_sys_state_1.imc_load_balancing_value >> 8);
   *(achl_w1 + 0 + 3) = (unsigned char) dsg_sys_state_1.imc_load_balancing_value;
   ADSL_GAI1_W1->achc_ginp_end = achl_w1 + DEF_LBAL_NET_DATA;
   ADSL_GAI1_W1->adsc_next = NULL;          /* end of chain            */
#undef ADSL_GAI1_W1
   adsl_clsend_w1->adsc_clact = adsp_clact;  /* active cluster         */
   adsl_clsend_w1->amc_compl = &m_cluster_free_send;  /* completition routine */
   adsl_clsend_w1->iec_cl_type = ied_clty_lbal;  /* type is load-balancing */
   adsl_clsend_w1->adsc_gai1_send = (struct dsd_gather_i_1 *) (adsl_clsend_w1 + 1);
   iml1 = m_cluster_send( adsl_clsend_w1 );
   if (iml1) {                              /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_send_cluster_lbal() m_cluster_send() returned %d.",
                     __LINE__, iml1 );
     m_proc_free( adsl_clsend_w1 );
   }
} /* end m_send_cluster_lbal()                                         */

/** connect to other cluster member after receiving redirect message   */
static void m_cluster_redirect_conn( struct dsd_cluster_active *adsp_clact, char * achp_data, int imp_length ) {
   int        iml_rc;                       /* return code             */
   int        iml_len;                      /* length structure        */
   int        iml_family;                   /* family                  */
   socklen_t  iml_soal_bind;                /* length of bind          */
   socklen_t  iml_soal_connect;             /* length of connect       */
   char       *achl_inp;                    /* input processed         */
   char       *achl_end;                    /* end of input            */
   struct dsd_cluster_remote *adsl_clrem_w1;  /* cluster remote structure */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster structure */
   struct sockaddr *adsl_soa_bind;          /* area for bind           */
   struct sockaddr_storage dsl_soa_connect;  /* area for connect        */

   adsl_clrem_w1 = adsp_clact->adsc_clrem;  /* cluster remote structure */
   if (adsl_clrem_w1 == NULL) {             /* not configured          */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T m_cluster_redirect_conn() adsl_clrem_w1 == NULL",
                     __LINE__ );
#endif
     return;                                /* all done                */
   }
   adsl_clact_w1 = (struct dsd_cluster_active *) malloc( sizeof(struct dsd_cluster_active) );
   memset( adsl_clact_w1, 0, sizeof(struct dsd_cluster_active) );
   adsl_clact_w1->imc_time_start = m_get_time();  /* time connection started */
   adsl_clact_w1->imc_time_recv = adsl_clact_w1->imc_time_start;  /* time last received data */
   adsl_clact_w1->imc_lbal_load = -1;       /* no load received yet    */
   adsl_clact_w1->adsc_clrem = adsl_clrem_w1;  /* cluster remote structure */
   adsl_clact_w1->boc_redirect = TRUE;      /* is redirected           */
   achl_inp = achp_data;                    /* input processed         */
   achl_end = achp_data + imp_length;       /* end of input            */

   p_struct_00:                             /* process structure       */
   iml_len = *((unsigned char *) achl_inp);  /* get length             */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T m_cluster_redirect_conn() p_struct_00: iml_len=%d.",
                   __LINE__, iml_len );
#endif
   switch (iml_len) {                       /* depending on length     */
     case 1 + 2 + 2 + 4:                    /* IPV4                    */
       iml_family = AF_INET;                /* family                  */
       break;
     case 1 + 2 + 2 + 16:                   /* IPV6                    */
       iml_family = AF_INET6;               /* family                  */
       break;
     default:                               /* other value             */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T m_cluster_redirect_conn() wrong length",
                       __LINE__ );
#endif
       free( adsl_clact_w1 );               /* free memory again       */
       return;                              /* all done                */
   }
   if ((achl_inp + iml_len) > achl_end) {   /* length longer than area */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T m_cluster_redirect_conn() length after end",
                     __LINE__ );
#endif
     free( adsl_clact_w1 );                 /* free memory again       */
     return;                                /* all done                */
   }
   if (iml_family == adsp_clact->dsc_soa.ss_family) {  /* same family  */
     goto p_struct_40;                      /* parameters set          */
   }
   achl_inp += iml_len;                     /* next structure          */
   if (achl_inp < achl_end) {               /* more structures         */
     goto p_struct_00;                      /* process structure       */
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T m_cluster_redirect_conn() free buffer",
                   __LINE__ );
#endif
   free( adsl_clact_w1 );                   /* free memory again       */
   return;                                  /* all done                */

   p_struct_40:                             /* parameters set          */
   memset( &dsl_soa_connect, 0, sizeof(struct sockaddr_storage) );
   dsl_soa_connect.ss_family = iml_family;  /* family                  */
   switch (iml_family) {                    /* family                  */
     case AF_INET:                          /* IPV4                    */
       *((UNSIG_MED *) &(((struct sockaddr_in *) &dsl_soa_connect)->sin_addr))
         = *((UNSIG_MED *) &(((struct sockaddr_in *) &adsp_clact->dsc_soa)->sin_addr));
       memcpy( &((struct sockaddr_in *) &dsl_soa_connect)->sin_port,
               achl_inp + 1 + 2,
               2 );
       iml_soal_connect = sizeof(struct sockaddr_in);
       break;
     case AF_INET6:                         /* IPV6                    */
       memcpy( &(((struct sockaddr_in6 *) &dsl_soa_connect)->sin6_addr),
               &((struct sockaddr_in6 *) &adsp_clact->dsc_soa)->sin6_addr,
               16 );
       memcpy( &((struct sockaddr_in6 *) &dsl_soa_connect)->sin6_port,
               achl_inp + 1 + 2,
               2 );
       iml_soal_connect = sizeof(struct sockaddr_in6);
       break;
   }
   adsl_soa_bind = NULL;
   iml_soal_bind = 0;
   if (adsl_clrem_w1->dsc_bind_multih.boc_bind_needed) {
     switch (iml_family) {                  /* family                  */
       case AF_INET:                        /* IPV4                    */
         if (adsl_clrem_w1->dsc_bind_multih.boc_ipv4 == FALSE) {
         }
         adsl_soa_bind = (struct sockaddr *) &adsl_clrem_w1->dsc_bind_multih.dsc_soai4;
         iml_soal_bind = sizeof(struct sockaddr_in);
         break;
       case AF_INET6:                       /* IPV6                    */
         if (adsl_clrem_w1->dsc_bind_multih.boc_ipv6 == FALSE) {
         }
         adsl_soa_bind = (struct sockaddr *) &adsl_clrem_w1->dsc_bind_multih.dsc_soai6;
         iml_soal_bind = sizeof(struct sockaddr_in6);
         break;
     }
   }
   m_set_clact_chain( adsl_clact_w1 );      /* put in chain            */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T m_cluster_redirect_conn() call m_startco_bind_conn_fix() &dsc_tcpcomp=%p vpp_userfld=%p.",
                   __LINE__, &adsl_clact_w1->dsc_tcpcomp, adsl_clact_w1 );
#endif
   iml_rc = adsl_clact_w1->dsc_tcpcomp.m_startco_bind_conn_fix(
              &dss_tcpco1_cb1,
              adsl_clact_w1,
              adsl_soa_bind, iml_soal_bind,
              (struct sockaddr *) &dsl_soa_connect, iml_soal_connect );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cluster_redirect_conn() call m_startco_bind_conn_fix() failed %d.",
                     __LINE__, iml_rc );
//   goto p_conn_80;                        /* close session to client */
// 29.09.07 KB - to-do
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T m_cluster_redirect_conn() end",
                   __LINE__ );
#endif
} /* end m_cluster_redirect_conn()                                     */

/** send INETAs to all other cluster members                           */
extern "C" int m_send_cluster_ineta( struct dsd_cluster_ineta_this *adsp_clint ) {
   int        iml1, iml2;                   /* working variables       */
   unsigned char ucl_more;                  /* more bit                */
   enum ied_cl_type iel_clty;               /* cluster data type       */
   char       *achl1, *achl2;               /* working variables       */
   void *     al_ineta_buffer;              /* buffer with INETAs      */
   char       *achl_inbuf_cur;              /* current in buffer with INETAs */
   char       *achl_inbuf_end;              /* end of buffer with INETAs */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster structure */
   struct dsd_cluster_send *adsl_clsend_w1;  /* send buffer            */

   switch (adsp_clint->usc_ineta_family) {  /* family IPV4 / IPV6      */
     case AF_INET:                          /* IPV4                    */
       iel_clty = ied_clty_ineta_req_ipv4;  /* type is request with INETAs IPV4 */
       break;
     case AF_INET6:                         /* IPV6                    */
       iel_clty = ied_clty_ineta_req_ipv6;  /* type is request with INETAs IPV6 */
       break;
     default:
       return -1;                           /* return error            */
   }

   al_ineta_buffer = m_proc_alloc();        /* acquire buffer with INETAs */
   achl_inbuf_end = (char *) al_ineta_buffer + LEN_TCP_RECV;  /* end of buffer with INETAs */
   memcpy( al_ineta_buffer, &adsp_clint->imc_sequ, sizeof(adsp_clint->imc_sequ) );  /* sequence number */
   achl_inbuf_cur = (char *) al_ineta_buffer + sizeof(adsp_clint->imc_sequ);  /* current in buffer with INETAs */
   achl1 = (char *) (adsp_clint + 1);       /* pairs of INETAs input   */

   p_seclin_20:                             /* prepare next pair of INETAs */
   iml1 = m_ineta_op_diff( achl1 + adsp_clint->usc_ineta_length, achl1, adsp_clint->usc_ineta_length )
            + 1;
   /* first pass only to compute length of count NHASN                 */
   achl2 = achl_inbuf_cur;                  /* save current in buffer with INETAs */
   iml2 = iml1;                             /* get number for output   */
   do {
     achl_inbuf_cur++;                      /* increment current in buffer with INETAs */
     iml2 >>= 7;                            /* remove digits           */
   } while (iml2 > 0);
   if ((achl_inbuf_cur + adsp_clint->usc_ineta_length) > achl_inbuf_end) {
// to-do 08.05.10 KB error message
     achl_inbuf_cur = achl2;                /* restore current in buffer with INETAs */
     goto p_seclin_40;                      /* INETAs to send have been prepared */
   }
   achl2 = achl_inbuf_cur;                  /* get current in buffer with INETAs */
   ucl_more = 0;                            /* clear more bit          */
   do {                                     /* loop output length NHASN */
     *(--achl2) = (unsigned char) ((iml1 & 0X7F) | ucl_more);
     iml1 >>= 7;                            /* remove these bits       */
     ucl_more = 0X80;                       /* set more bit            */
   } while (iml1 > 0);
   memcpy( achl_inbuf_cur, achl1, adsp_clint->usc_ineta_length );
   achl_inbuf_cur += adsp_clint->usc_ineta_length;  /* increment current in buffer with INETAs */
   achl1 += 2 * adsp_clint->usc_ineta_length;  /* increment input      */
   if (achl1 < adsp_clint->achc_end_used) {  /* check address used till here */
     goto p_seclin_20;                      /* prepare next pair of INETAs */
   }

   p_seclin_40:                             /* INETAs to send have been prepared */
   adsp_clint->ac_ineta_buffer = al_ineta_buffer;  /* buffer with INETAs */
   adsl_clact_w1 = adsg_clact_ch;           /* get chain of active cluster entries */
   iml1 = 0;                                /* count packets sent      */
   while (adsl_clact_w1) {                  /* loop over all active cluster entries */
//   if (adsl_clact_w1->iec_clr_stat == ied_clrs_open) {  /* state is open */
     if (   (adsl_clact_w1->iec_clr_stat == ied_clrs_open)  /* state is open */
         && (adsl_clact_w1->boc_same_group)) {  /* is in same group as main */
       adsl_clsend_w1 = (struct dsd_cluster_send *) m_proc_alloc();
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsl_clsend_w1 + 1))
       ADSL_GAI1_W1->achc_ginp_cur = (char *) al_ineta_buffer;
       ADSL_GAI1_W1->achc_ginp_end = achl_inbuf_cur;
       ADSL_GAI1_W1->adsc_next = NULL;      /* end of chain            */
#undef ADSL_GAI1_W1
       adsl_clsend_w1->adsc_clact = adsl_clact_w1;  /* active cluster  */
       adsl_clsend_w1->amc_compl = &m_cluster_free_send;  /* completition routine */
       adsl_clsend_w1->iec_cl_type = iel_clty;  /* cluster data type   */
       adsl_clsend_w1->adsc_gai1_send = (struct dsd_gather_i_1 *) (adsl_clsend_w1 + 1);
       iml2 = m_cluster_send( adsl_clsend_w1 );
       if (iml2) {                          /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_send_cluster_ineta() m_cluster_send() returned %d.",
                         __LINE__, iml2 );
         m_proc_free( adsl_clsend_w1 );
       } else {                             /* no error occured        */
         iml1++;                            /* count packets sent      */
         iml2 = DEF_INETA_CLUSTER_WAIT;     /* default cluster timeout value in milliseconds */
         if (   (adsl_clact_w1->adsc_clrem)  /* get configured value   */
             && (adsl_clact_w1->adsc_clrem->imc_timeout_msec > 0)) {
           iml2 = adsl_clact_w1->adsc_clrem->imc_timeout_msec;
         }
         if (iml2 > adsp_clint->imc_timeout_msec) {
           adsp_clint->imc_timeout_msec = iml2;  /* timeout in milliseconds */
         }
       }
     }
     adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
   }
   return iml1;                             /* return packets sent     */
} /* end m_send_cluster_ineta()                                        */

/** count active cluster connections                                   */
extern "C" int m_cluster_count_active( void ) {
   int        iml_count_cluster;            /* count the cluster members */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster structure */

   iml_count_cluster = 0;                   /* clear count the cluster members */
   adsl_clact_w1 = adsg_clact_ch;           /* get chain of active cluster entries */
   while (adsl_clact_w1) {                  /* loop over all active cluster entries */
     if (   (adsl_clact_w1->iec_clr_stat == ied_clrs_open)  /* state is open */
         && (adsl_clact_w1->boc_same_group)) {  /* is in same group as main */
       iml_count_cluster++;                 /* count the cluster members */
     }
     adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
   }
   return iml_count_cluster;                /* return the cluster members */
} /* end m_cluster_count_active()                                      */

/** report cluster                                                     */
extern "C" void m_cluster_report( struct dsd_cluster_report *adsp_cluster_report ) {
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster structure */

   memset( adsp_cluster_report, 0, sizeof(struct dsd_cluster_report) );
   if (   (adss_cluster_main == NULL)       /* no configuration        */
       && (adsg_clact_ch == NULL)) {        /* check chain of active cluster entries */
     return;
   }
   adsp_cluster_report->boc_cluster_active = TRUE;  /* cluster is active */
   adsl_clact_w1 = adsg_clact_ch;           /* get chain of active cluster entries */
   while (adsl_clact_w1) {                  /* loop over all active cluster entries */
     if (adsl_clact_w1->iec_clr_stat == ied_clrs_open) {  /* state is open */
       adsp_cluster_report->imc_no_cluster_active++;  /* number of active cluster connections */
       if (adsl_clact_w1->boc_same_group) {  /* is in same group as main */
         adsp_cluster_report->imc_no_same_group++;  /* number of active cluster connections same group */
       }
     }
     adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
   }
   return;
} /* end m_cluster_count_active()                                      */

/** free memory that was received before                               */
extern "C" void m_cluster_proc_recv_done( struct dsd_cluster_proc_recv *adsp_clprr ) {
   BOOL       bol_start_recv;               /* start receive           */
   void       **avpl_w1;                    /* working variable        */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster structure */
   struct dsd_cluster_recv *adsl_clrecv_w1;  /* block received from cluster member */
   struct dsd_cluster_recv *adsl_clrecv_w2;  /* block received from cluster member */

   adsl_clact_w1 = adsp_clprr->adsc_clact;  /* active cluster structure */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_cluster_proc_recv_done( %p ) called adsl_clact_w1=%p.",
                   __LINE__, adsp_clprr, adsl_clact_w1 );
#endif
   avpl_w1 = (void **) (adsp_clprr + 1);    /* structures to free      */
   bol_start_recv = FALSE;                  /* reset start receive     */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX2T l%05d m_enter() before", __LINE__ );
#endif
   dss_critsect_cluster.m_enter();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX3T l%05d m_enter() after", __LINE__ );
#endif
   do {                                     /* loop over blocks to free */
     adsl_clrecv_w1 = (struct dsd_cluster_recv *) *avpl_w1++;
     adsp_clprr->imc_no_recv_bl--;          /* number of receive blocks */
     adsl_clrecv_w1->imc_usage_count--;     /* block no more in use    */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_cluster_proc_recv_done() adsl_clrecv_w1=%p adsl_clrecv_w1->imc_usage_count=%d (--)",
                     __LINE__, adsl_clrecv_w1, adsl_clrecv_w1->imc_usage_count );
#endif
     /* check if still in chain of received blocks                     */
     adsl_clrecv_w2 = adsl_clact_w1->adsc_recv_ch;  /* get first in chain */
     while (adsl_clrecv_w2) {               /* loop over chain         */
       if (adsl_clrecv_w2 == adsl_clrecv_w1) {  /* this block found    */
         adsl_clrecv_w1 = NULL;             /* do not free this block  */
         break;                             /* block found             */
       }
       adsl_clrecv_w2 = adsl_clrecv_w2->adsc_next;  /* get next in chain */
     }
#ifdef TRACEHL1
     if (adsl_clrecv_w1) {
       m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_cluster_proc_recv_done() adsl_clrecv_w1->imc_usage_count=%d m_proc_free %p ???",
                       __LINE__, adsl_clrecv_w1->imc_usage_count, adsl_clrecv_w1 );
     }
#endif
     if (   (adsl_clrecv_w1)
         && (adsl_clrecv_w1->imc_usage_count <= 0)) {
       m_proc_free( adsl_clrecv_w1 );       /* free this block         */
     }
   } while (adsp_clprr->imc_no_recv_bl > 0);  /* number of receive blocks */
   if (adsl_clact_w1->imc_count_recv_b >= DEF_CLUSTER_NO_BL) {  /* number of blocks for flow control */
     bol_start_recv = TRUE;                 /* set start receive       */
   }
   adsl_clact_w1->imc_count_recv_b--;       /* count block received    */
   dss_critsect_cluster.m_leave();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX4T l%05d m_leave() after", __LINE__ );
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_cluster_proc_recv_done() m_proc_free %p adsl_clact_w1->imc_count_recv_b=%d.",
                   __LINE__, adsp_clprr, adsl_clact_w1->imc_count_recv_b );
#endif
   m_proc_free( adsp_clprr );               /* free memory of receive block */
   if (   (bol_start_recv)                  /* start receive           */
       && (adsl_clact_w1->iec_clr_stat == ied_clrs_open)) {  /* state is open */
     adsl_clact_w1->boc_recv_active = TRUE;  /* receive is active      */
     adsl_clact_w1->dsc_tcpcomp.m_recv();   /* start receiving         */
   }
} /* end m_cluster_proc_recv_done()                                    */

/** routine to send something to cluster member                        */
extern "C" int m_cluster_send( struct dsd_cluster_send *adsp_clsend ) {
   int        iml1, iml2, iml3, iml4;       /* working variables       */
   BOOL       bol1;                         /* working variable        */
   BOOL       bol_send;                     /* send this time          */
   unsigned char ucl_more;                  /* more bit                */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster structure */
   struct dsd_cluster_send *adsl_clsend_cur;  /* current in chain      */
   struct dsd_cluster_send *adsl_clsend_last;  /* last in chain        */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* gather input data       */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_cluster_send( %p ) called",
                   __LINE__, adsp_clsend );
#endif
   adsl_clact_w1 = adsp_clsend->adsc_clact;  /* active cluster         */
   while (adsl_clact_w1->iec_clr_stat != ied_clrs_open) {  /* state is not open */
#ifndef B120911
     if (adsp_clsend->iec_cl_type == ied_clty_end) break;  /* type is end */
#endif
     if (   (adsp_clsend->iec_cl_type == ied_clty_control)  /* type is control */
         && (   (adsl_clact_w1->iec_clr_stat != ied_clrs_closed)  /* state is not closed */
             || (adsl_clact_w1->iec_clr_stat != ied_clrs_timed_out))) {  /* state is not timed out */
       break;                               /* request is valid        */
     }
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_cluster_send( %p ) iec_clr_stat=%d iec_cl_type=%d - error",
                     __LINE__, adsp_clsend, adsl_clact_w1->iec_clr_stat, adsp_clsend->iec_cl_type );
#endif
     return 1;                              /* return error            */
   }
   /* count length to send                                             */
   adsl_gai1_w1 = adsp_clsend->adsc_gai1_send;  /* gather input data to send */
#ifdef B110926
   if (adsl_gai1_w1 == NULL) return 2;      /* no data to send         */
   iml1 = 0;                                /* clear length            */
   do {                                     /* loop to count length    */
     iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   } while (adsl_gai1_w1);
#else
   iml1 = 0;                                /* clear length            */
   if (adsl_gai1_w1) {                      /* with data to send       */
     do {                                   /* loop to count length    */
       iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     } while (adsl_gai1_w1);
   }
#endif
   ucl_more = 0;                            /* clear more bit          */
   achl_w1 = (char *) adsp_clsend->vprc_work_area + sizeof(adsp_clsend->vprc_work_area);
   do {                                     /* loop output length NHASN */
     *(--achl_w1) = (unsigned char) ((iml1 & 0X7F) | ucl_more);
     iml1 >>= 7;                            /* remove these bits       */
     ucl_more = 0X80;                       /* set more bit            */
   } while (iml1);
   switch (adsp_clsend->iec_cl_type) {      /* cluster data type       */
     case ied_clty_control:                 /* type is control         */
       *(--achl_w1) = '0';
       break;
#ifndef B110926
     case ied_clty_end:                     /* type is end             */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_cluster_send() called ied_clty_end",
                       __LINE__ );
#endif
       *(--achl_w1) = '1';
       break;
#endif
     case ied_clty_lbal:                    /* type is load-balancing  */
       *(--achl_w1) = '3';
       break;
     case ied_clty_cma:                     /* type is common memory area */
       *(--achl_w1) = '4';
       break;
     case ied_clty_vdi:                     /* type is VDI-WSP         */
       *(--achl_w1) = '5';
       break;
     case ied_clty_admin:                   /* type is administration  */
       *(--achl_w1) = '6';
       break;
     case ied_clty_ineta_req_ipv4:          /* type is request with INETAs IPV4 */
       *(--achl_w1) = 'A';
       break;
     case ied_clty_ineta_resp_ipv4:         /* type is response with INETAs IPV4 */
       *(--achl_w1) = 'B';
       break;
     case ied_clty_ineta_rej_ipv4:          /* type is reject for INETAs IPV4 */
       *(--achl_w1) = 'C';
       break;
     case ied_clty_ineta_req_ipv6:          /* type is request with INETAs IPV6 */
       *(--achl_w1) = 'D';
       break;
     case ied_clty_ineta_resp_ipv6:         /* type is response with INETAs IPV6 */
       *(--achl_w1) = 'E';
       break;
     case ied_clty_ineta_rej_ipv6:          /* type is reject for INETAs IPV6 */
       *(--achl_w1) = 'F';
       break;
     default:
       return 3;                            /* invalid data type       */
   }
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) adsp_clsend->vprc_work_area)
   ADSL_GAI1_W1->achc_ginp_cur = (char *) ucrs_cluster_eye_catcher;  /* here start data */
   ADSL_GAI1_W1->achc_ginp_end = (char *) ucrs_cluster_eye_catcher + sizeof(ucrs_cluster_eye_catcher);
   ADSL_GAI1_W1->adsc_next = ADSL_GAI1_W1 + 1;
#undef ADSL_GAI1_W1
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) adsp_clsend->vprc_work_area + 1)
   ADSL_GAI1_W1->achc_ginp_cur = achl_w1;   /* here start data         */
   ADSL_GAI1_W1->achc_ginp_end = (char *) adsp_clsend->vprc_work_area + sizeof(adsp_clsend->vprc_work_area);
   ADSL_GAI1_W1->adsc_next = adsp_clsend->adsc_gai1_send;  /* gather input data to send */
#undef ADSL_GAI1_W1
   adsp_clsend->adsc_next = NULL;           /* clear chain to send     */
   if (adsp_clsend->amc_compl == NULL) {    /* completition routine not set */
     adsp_clsend->amc_compl = &m_cluster_free_send;  /* set completition routine */
   }
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_CLUSTER) {  /* core cluster */
     adsl_gai1_w1 = (struct dsd_gather_i_1 *) adsp_clsend->vprc_work_area;
     iml1 = iml2 = 0;
     do {                                   /* loop over all gather structures */
       iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       iml2++;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     } while (adsl_gai1_w1);
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CCLUSEND", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
//   adsl_wt1_w1->imc_wtrt_sno = 0;         /* WSP session number      */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml2 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "data send to cluster-member %s length %d/0X%X gather %d.",
                     adsl_clact_w1->chrc_ineta, iml1, iml1, iml2 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml2;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (   (iml1 > 0)                      /* data to send            */
         && (img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2))) {  /* generate WSP trace record */
       adsl_gai1_w1 = (struct dsd_gather_i_1 *) adsp_clsend->vprc_work_area;
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* start of data        */
       adsl_wt1_w2 = adsl_wt1_w1;           /* in this piece of memory */
       adsl_wtr_w1 = ADSL_WTR_G1;           /* set last in chain       */
       bol1 = FALSE;                        /* clear more flag         */
       do {                                 /* loop always with new struct dsd_wsp_trace_record */
         achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
         if ((achl_w1 + sizeof(struct dsd_wsp_trace_record)) >= achl_w2) {
           adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
           memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
           adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
           adsl_wt1_w2 = adsl_wt1_w3;       /* this is current network */
           achl_w1 = (char *) (adsl_wt1_w2 + 1);
           achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
         }
         memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
         ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
         achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
         ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
         adsl_wtr_w1->boc_more = bol1;      /* more data to follow     */
         adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain     */
         adsl_wtr_w1 = ADSL_WTR_G2;         /* this is last in chain now */
         while (TRUE) {                     /* loop over data sent     */
           iml3 = adsl_gai1_w1->achc_ginp_end - achl_w3;
           if (iml3 > iml1) iml3 = iml1;
           iml4 = achl_w2 - achl_w4;
           if (iml4 > iml3) iml4 = iml3;
           memcpy( achl_w4, achl_w3, iml4 );
           achl_w4 += iml4;
           achl_w3 += iml4;
           ADSL_WTR_G2->imc_length += iml4;  /* length of text / data  */
           iml1 -= iml4;                    /* length to be copied     */
           if (iml1 <= 0) break;
           if (achl_w3 < adsl_gai1_w1->achc_ginp_end) break;
           adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* next part to be copied  */
           achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* start of data    */
           if (achl_w4 >= achl_w2) break;
         }
         achl_w1 = achl_w2;                 /* set end of this area    */
         bol1 = TRUE;                       /* set more flag           */
       } while (iml1 > 0);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   bol_send = FALSE;                        /* reset send this time    */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX2T l%05d m_enter() before", __LINE__ );
#endif
   dss_critsect_cluster.m_enter();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX3T l%05d m_enter() after", __LINE__ );
#endif
   if (adsl_clact_w1->adsc_send_ch == NULL) {  /* chain of send buffers empty */
     adsl_clact_w1->adsc_send_ch = adsp_clsend;  /* is first in chain  */
     bol_send = TRUE;                       /* send this time          */
   } else {                                 /* append to chain         */
     adsl_clsend_cur = adsl_clact_w1->adsc_send_ch;  /* get anchor of chain */
     do {                                   /* loop over chain to send */
       adsl_clsend_last = adsl_clsend_cur;  /* save last entry         */
       adsl_clsend_cur = adsl_clsend_cur->adsc_next;  /* get next in chain */
     } while (adsl_clsend_cur);
     adsl_clsend_last->adsc_next = adsp_clsend;  /* append new entry to chain */
   }
   dss_critsect_cluster.m_leave();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX4T l%05d m_leave() after", __LINE__ );
#endif
   if (bol_send == FALSE) return 0;         /* do not send this time   */

   p_send:                                  /* send data to cluster member */
   iml1 = adsl_clact_w1->dsc_tcpcomp.m_send_gather(
            (struct dsd_gather_i_1 *) adsl_clact_w1->adsc_send_ch->vprc_work_area,
            &adsl_gai1_w1 );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_cluster_send() m_send_gather() returned %d",
                   __LINE__, iml1 );
#endif
   if (iml1 > 0) {                          /* data sent               */
     adsl_clact_w1->imc_stat_no_send++;     /* statistic number of sends */
     adsl_clact_w1->ilc_stat_len_send += iml1;  /* statistic length of sends */
   }
   if (adsl_gai1_w1) {
     adsl_clact_w1->dsc_tcpcomp.m_sendnotify();
     return 0;
   }
   adsl_clsend_cur = adsl_clact_w1->adsc_send_ch;  /* get anchor of chain */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX2T l%05d m_enter() before", __LINE__ );
#endif
   dss_critsect_cluster.m_enter();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX3T l%05d m_enter() after", __LINE__ );
#endif
   adsl_clsend_last = adsl_clsend_cur->adsc_next;  /* get next in chain */
   adsl_clact_w1->adsc_send_ch = adsl_clsend_last;  /* remove from chain */
   dss_critsect_cluster.m_leave();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX4T l%05d m_leave() after", __LINE__ );
#endif
   adsl_clsend_cur->amc_compl( adsl_clsend_cur );   /* call completition routine */
   if (adsl_clsend_last) {                  /* more data to send       */
     goto p_send;                           /* send data to cluster member */
   }
   if (adsl_clact_w1->iec_clr_stat == ied_clrs_send_end) {  /* state is send end */
     adsl_clact_w1->iec_clr_stat = ied_clrs_closed;  /* state is closed now */
     adsl_clact_w1->dsc_tcpcomp.m_end_session();
   }
   return 0;
} /* end m_cluster_send()                                              */

/** send VDI-WSP INETA to other members of the cluster                 */
extern "C" void m_cluster_vdi_send( char *achp_ineta, int imp_len_ineta ) {
   int        iml1;                         /* working variable        */
   struct dsd_cluster_active *adsl_clact_w1;  /* working-variable      */
   struct dsd_cluster_send *adsl_clsend_w1;  /* send buffer            */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_cluster_vdi_send( %p , %d ) called",
                   __LINE__, achp_ineta, imp_len_ineta );
#endif
   adsl_clact_w1 = adsg_clact_ch;           /* get chain of active cluster members */

   p_vdis_00:                               /* send to this one        */
   if (adsl_clact_w1 == NULL) return;       /* sent to all members     */
   if (adsl_clact_w1->iec_clr_stat != ied_clrs_open) {  /* state of connection */
     goto p_vdis_80;                        /* end send to this one    */
   }
   adsl_clsend_w1 = (struct dsd_cluster_send *) m_proc_alloc();
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsl_clsend_w1 + 1))
   memcpy( ADSL_GAI1_W1 + 1, achp_ineta, imp_len_ineta );
   ADSL_GAI1_W1->achc_ginp_cur = (char *) (ADSL_GAI1_W1 + 1);
   ADSL_GAI1_W1->achc_ginp_end = (char *) (ADSL_GAI1_W1 + 1) + imp_len_ineta;
   ADSL_GAI1_W1->adsc_next = NULL;
   adsl_clsend_w1->adsc_clact = adsl_clact_w1;  /* active cluster      */
   adsl_clsend_w1->amc_compl = &m_cluster_free_send;  /* completition routine */
   adsl_clsend_w1->iec_cl_type = ied_clty_vdi;  /* type is VDI-WSP     */
   adsl_clsend_w1->adsc_gai1_send = ADSL_GAI1_W1;
#undef ADSL_GAI1_W1
   iml1 = m_cluster_send( adsl_clsend_w1 );
   if (iml1) {                              /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cluster_vdi_send() m_cluster_send() returned %d.",
                     __LINE__, iml1 );
     m_proc_free( adsl_clsend_w1 );
   }

   p_vdis_80:                               /* end send to this one    */
   adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain     */
   goto p_vdis_00;                          /* send to this one        */
} /* end m_cluster_vdi_send()                                          */

#ifdef HL_UNIX
/** connect to other cluster member over Unix socket
    when Listen-Gateway is used                                        */
extern "C" void m_cluster_ligw_conn( int imp_uds_pid ) {
   int        iml_rc;                       /* return code             */
   int        iml1, iml2;                   /* working variables       */
   int        iml_sockfd;                   /* socket for connection   */
   char       *achl1, *achl2;               /* working variables       */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster structure */
   struct sockaddr_un dsl_soa_un;           /* address of domain socket */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T m_cluster_ligw_conn( imp_uds_pid=%d ) called",
                   __LINE__, imp_uds_pid );
#endif
   adsl_clact_w1 = adsg_clact_ch;           /* get chain of active cluster entries */
   while (adsl_clact_w1) {                  /* loop over all active cluster entries */
     if (   (adsl_clact_w1->boc_unix_socket)  /* is Unix domain socket */
         && (adsl_clact_w1->imc_uds_pid == imp_uds_pid)) {  /* process id Unix domain socket */
       return;                              /* already connected       */
     }
     adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
   }
   memset( &dsl_soa_un, 0, sizeof(struct sockaddr_un) );
   dsl_soa_un.sun_family = AF_LOCAL;
   achl1 = stpcpy( dsl_soa_un.sun_path, D_NAME_UDS_WSP );
   achl1 = stpcpy( dsl_soa_un.sun_path, D_NAME_UDS_WSP );
   iml1 = sizeof(dsl_soa_un.sun_path) - (sizeof(D_NAME_UDS_WSP) - 1) - D_LENGTH_UDS_TAIL - 1;
   if (iml1 > D_LENGTH_UDS_MAX) iml1 = D_LENGTH_UDS_MAX;
   achl2 = dsl_soa_un.sun_path + iml1;
#ifdef B170628
   achl2 = dsl_soa_un.sun_path + sizeof(dsl_soa_un.sun_path) - 1 - D_LENGTH_UDS_TAIL;
#endif
   memcpy( achl2, D_NAME_UDS_TAIL, D_LENGTH_UDS_TAIL + 1 );
   iml1 = imp_uds_pid;                      /* get process ID of other WSP */
   iml2 = 10;                               /* maximum number of digits */
   do {                                     /* loop output digits      */
     *(--achl2) = (iml1 % 10) + '0';        /* one digit               */
     iml1 /= 10;                            /* divide value            */
     iml2--;                                /* decrement index         */
   } while (iml2 > 0);
   iml1 = achl2 - achl1;
   if (iml1 > 0) {                          /* we need more characters */
     memset( achl1, '$', iml1 );
   }
   iml_sockfd = socket( AF_LOCAL, SOCK_STREAM, 0 );
   if (iml_sockfd < 0) {                    /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cluster_ligw_conn() socket() failed %d / %d.",
                     __LINE__, iml_sockfd, errno );
     return;                                /* could not connect to other WSP */
   }
   iml_rc = connect( iml_sockfd,
                     (struct sockaddr *) &dsl_soa_un,
                     sizeof(struct sockaddr_un) );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d pipe-name \"%(u8)s\" connect() failed %d / %d.",
                     __LINE__, dsl_soa_un.sun_path, iml_rc, errno );
     close( iml_sockfd );
     return;                                /* could not connect to other WSP */
   }
   adsl_clact_w1 = (struct dsd_cluster_active *) malloc( sizeof(struct dsd_cluster_active) );
   memset( adsl_clact_w1, 0, sizeof(struct dsd_cluster_active) );
   adsl_clact_w1->imc_time_start = m_get_time();  /* time connection started */
   adsl_clact_w1->imc_time_recv = m_get_time();  /* time last received data */
   adsl_clact_w1->imc_lbal_load = -1;       /* no load received yet    */
   adsl_clact_w1->boc_same_group = TRUE;    /* is in same group as main */
   adsl_clact_w1->boc_unix_socket = TRUE;   /* is Unix domain socket   */
   adsl_clact_w1->imc_uds_pid = imp_uds_pid;  /* process id Unix domain socket */
   strcpy( adsl_clact_w1->chrc_ineta, "local" );
   m_set_clact_chain( adsl_clact_w1 );      /* put in chain            */
   iml_rc = adsl_clact_w1->dsc_tcpcomp.m_startco_fb( iml_sockfd,
                                                     &dss_tcpco1_cb1,
                                                     adsl_clact_w1 );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cluster_start() m_startco_fb() failed %d.",
                     __LINE__, iml_rc );
//   goto p_conn_80;                        /* close session to client */
// 29.09.07 KB - to-do
     return;
   }
   adsl_clact_w1->iec_clr_stat = ied_clrs_conn_recv_st;  /* after connect start receive */
   adsl_clact_w1->boc_recv_active = TRUE;   /* receive is active       */
   adsl_clact_w1->dsc_tcpcomp.m_recv();     /* start receiving         */
   m_send_control_init( adsl_clact_w1 );
} /* end m_cluster_ligw_conn()                                         */
#endif

/** end the processing of cluster connections                          */
extern "C" void m_cluster_end( void ) {
   int        iml1;                         /* working variable        */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster structure */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_cluster_end() called",
                   __LINE__ );
#endif
   if (adss_cluster_main == NULL) {         /* no configuration        */
     goto p_end_20;                         /* after close listen      */
   }
   iml1 = 0;                                /* clear index             */
   while (iml1 < adss_cluster_main->adsc_listen_ineta->imc_no_ineta) {
     adss_cluster_main->adsc_clli[ iml1 ].dsc_acc_listen.mc_stoplistener_fix();
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T listen stopped successfully", __LINE__ );
#endif
     iml1++;                                /* count listen            */
   }

   p_end_20:                                /* after close listen      */
   adsl_clact_w1 = adsg_clact_ch;           /* get chain of active cluster entries */
   while (adsl_clact_w1) {                  /* loop over all active cluster entries */
     adsl_clact_w1->dsc_tcpcomp.m_end_session();  /* end session       */
     adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
   }
} /* end m_cluster_end()                                               */

#ifndef B120827
/** routine called by timer thread to free active cluster structure    */
static void m_timer_free_clact( struct dsd_timer_ele *adsp_timer_ele ) {
   struct dsd_cluster_recv *adsl_clrecv_w1;  /* block received from cluster member */
   struct dsd_cluster_send *adsl_clsend_w1;  /* send buffer            */

#define ADSL_CLACT_G ((struct dsd_cluster_active *) ((char *) adsp_timer_ele - offsetof( struct dsd_cluster_active, dsc_timer_ele )))

   if (ADSL_CLACT_G->imc_len_server_name) {  /* length server name     */
     free( ADSL_CLACT_G->achc_server_name );  /* free old memory       */
   }
   if (ADSL_CLACT_G->imc_len_query_main) {  /* length query main       */
     free( ADSL_CLACT_G->achc_query_main );  /* free old memory        */
   }
   if (ADSL_CLACT_G->imc_len_config_name) {  /* length configuration name */
     free( ADSL_CLACT_G->achc_config_name );  /* free old memory       */
   }
   if (ADSL_CLACT_G->imc_len_group) {       /* length configuration group */
     free( ADSL_CLACT_G->achc_group );      /* free old memory         */
   }
   if (ADSL_CLACT_G->imc_len_location) {    /* length configuration location */
     free( ADSL_CLACT_G->achc_location );   /* free old memory         */
   }
   if (ADSL_CLACT_G->imc_len_url) {         /* length configuration URL */
     free( ADSL_CLACT_G->achc_url );        /* free old memory         */
   }
   while (ADSL_CLACT_G->adsc_recv_ch) {    /* chain of received buffers */
     adsl_clrecv_w1 = ADSL_CLACT_G->adsc_recv_ch;  /* get old chain of received buffers */
     ADSL_CLACT_G->adsc_recv_ch = ADSL_CLACT_G->adsc_recv_ch->adsc_next;  /* set new chain of received buffers */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_cleanup() m_proc_free %p.",
                     __LINE__, adsl_clrecv_w1 );
#endif
     m_proc_free( adsl_clrecv_w1 );         /* free this block         */
   }
   while (ADSL_CLACT_G->adsc_send_ch) {    /* chain of send buffers   */
     adsl_clsend_w1 = ADSL_CLACT_G->adsc_send_ch;  /* get old chain of send buffers */
     ADSL_CLACT_G->adsc_send_ch = ADSL_CLACT_G->adsc_send_ch->adsc_next;  /* set new chain of send buffers */
     m_proc_free( adsl_clsend_w1 );         /* free this block         */
   }
   free( ADSL_CLACT_G );
#undef ADSL_CLACT_G
} /* end m_timer_free_clact()                                          */
#endif

/** routine called by timer thread when a certain time after init has been elapsed */
static void m_timeout_init_1( struct dsd_timer_ele *adsp_timer_ele ) {
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster structure */
   struct dsd_cluster_active *adsl_clact_w2;  /* active cluster structure */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_timeout_init_1() called adsp_timer_ele=%p.",
                   __LINE__, adsp_timer_ele );
#endif
#define ADSL_CLTIM1 ((struct dsd_cluster_timer_1 *) ((char *) adsp_timer_ele - offsetof( struct dsd_cluster_timer_1, dsc_timer_ele )))
#ifdef B090419
   adsl_clact_w1 = ADSL_CLTIM1->adsc_clact;  /* active cluster         */
#ifdef B081118
   free( adsl_clact_w1->vpc_special_1 );
#endif
   adsl_clact_w1->vpc_special_1 = NULL;
#endif
   adsl_clact_w1 = ADSL_CLTIM1->adsc_clact;  /* active cluster         */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_timeout_init_1() free( ADSL_CLTIM1=%p )",
                   __LINE__, ADSL_CLTIM1 );
#endif
   free( ADSL_CLTIM1 );                     /* free timer entry        */
#ifndef B120911
   if (adsl_clact_w1->iec_clr_stat == ied_clrs_closed) return;  /* state is closed */
#endif
   adsl_clact_w2 = adsg_clact_ch;           /* get chain of active cluster entries */
   while (adsl_clact_w2) {                  /* loop over all active cluster entries */
#ifdef B120911
     if (adsl_clact_w2 == adsl_clact_w1) {  /* this entry is in chain  */
       m_check_cluster_member_double( adsl_clact_w1, TRUE );
       return;                              /* all done                */
     }
#else
     if (   (adsl_clact_w2 == adsl_clact_w1)  /* this entry is in chain */
         && (adsl_clact_w2->iec_clr_stat != ied_clrs_closed)) {  /* state is not closed */
       m_check_cluster_member_double( adsl_clact_w1, TRUE );
       return;                              /* all done                */
     }
#endif
     adsl_clact_w2 = adsl_clact_w2->adsc_next;  /* get next in chain   */
   }
#undef ADSL_CLTIM1
#ifdef B090419
   m_check_cluster_member_double( adsl_clact_w1, TRUE );
#endif
} /* end m_timeout_init_1()                                            */

/** routine to check if a cluster member is double                     */
static void m_check_cluster_member_double( struct dsd_cluster_active *adsp_clact,
                                           BOOL bop_after_sleep ) {
   BOOL       bol_delete;                   /* set what to delete      */
   struct dsd_cluster_timer_1 *adsl_cltim1;  /* cluster timer one      */
   struct dsd_cluster_active *adsl_clact_cur;  /* current position active cluster */
   struct dsd_cluster_active *adsl_clact_end;  /* send end to this active cluster */
//#ifdef B110917
   struct dsd_cluster_remote *adsl_clrem_w1;  /* cluster remote structure */
//#endif

// to-do 02.06.10 KB - compare fingerprint
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_check_cluster_member_double() called iec_clr_stat=%d bop_after_sleep=%d.",
                   __LINE__, adsp_clact->iec_clr_stat, bop_after_sleep );
#endif
   bol_delete = FALSE;                      /* reset what to delete    */

   p_loop_00:                               /* loop to compare active clusters */
   adsl_clact_end = NULL;                   /* clear send end to this active cluster */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX2T l%05d m_enter() before", __LINE__ );
#endif
   dss_critsect_cluster.m_enter();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX3T l%05d m_enter() after", __LINE__ );
#endif
   adsl_clact_cur = adsg_clact_ch;          /* get anchor of chain     */
   while (adsl_clact_cur) {                 /* loop over all active clusters */
     if (adsl_clact_cur != adsp_clact) {    /* is other entry          */
       if (   (adsl_clact_cur->imc_pid == adsp_clact->imc_pid)
#ifndef B120911
           && (!memcmp( adsl_clact_cur->chrc_fingerprint, adsp_clact->chrc_fingerprint, DEF_LEN_FINGERPRINT ))
#endif
           && (adsl_clact_cur->imc_len_server_name == adsp_clact->imc_len_server_name)
           && (!memcmp( adsl_clact_cur->achc_server_name,
                        adsp_clact->achc_server_name,
                        adsp_clact->imc_len_server_name ))) {
         /* same member found               */
#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_check_cluster_member_double() adsp_clact->iec_clr_stat=%d adsl_clact_cur->iec_clr_stat=%d.",
                         __LINE__, adsp_clact->iec_clr_stat, adsl_clact_cur->iec_clr_stat );
#endif
         if (adsl_clact_cur->iec_clr_stat == ied_clrs_open) {  /* state is already open */
           bol_delete = TRUE;               /* delete this entry       */
           break;                           /* nothing more to do      */
         }
         /* state not yet open                                         */
         if (   (adsl_clact_cur->iec_clr_stat != ied_clrs_send_end)  /* state is not send end */
             && (adsl_clact_cur->iec_clr_stat != ied_clrs_closed)  /* state is not closed */
             && (adsl_clact_cur->iec_clr_stat != ied_clrs_timed_out)) {  /* state is not timed out */
           /* decide which one will be ended                           */
#ifdef B120911
           if (adsl_clact_cur->ilc_epoch_started < adsp_clact->ilc_epoch_started) {
#ifdef FORKEDIT
           }
#endif
#else
           /* member with higher hash is closed                        */
           if (memcmp( adsp_clact->chrc_fingerprint, dsg_this_server.chrc_fingerprint, DEF_LEN_FINGERPRINT ) > 0) {
#endif
#ifdef TRACEHL1
             m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_check_cluster_member_double() memcmp greater adsp_clact->iec_clr_stat=%d.",
                             __LINE__, adsp_clact->iec_clr_stat );
#endif
#ifdef B120911
             if (adsp_clact->iec_clr_stat == ied_clrs_acc_recv_st) {  /* after accept start receive */
               bol_delete = TRUE;           /* delete this entry       */
               break;                       /* nothing more to do      */
             }
#else
             if (adsp_clact->iec_clr_stat == ied_clrs_acc_init_sent) {  /* after control init has been sent */
               bol_delete = TRUE;           /* delete this entry       */
               break;                       /* nothing more to do      */
             }
#endif
             adsl_clact_end = adsl_clact_cur;  /* send end to this active cluster */
             break;                         /* process loop once more  */
           } else {
#ifdef TRACEHL1
             m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_check_cluster_member_double() memcmp lower adsp_clact->iec_clr_stat=%d.",
                             __LINE__, adsp_clact->iec_clr_stat );
#endif
#ifdef B120911
             if (adsp_clact->iec_clr_stat == ied_clrs_acc_recv_st) {  /* after accept start receive */
               adsl_clact_end = adsl_clact_cur;  /* send end to this active cluster */
               break;                       /* process loop once more  */
             }
#else
             if (adsp_clact->iec_clr_stat == ied_clrs_acc_init_sent) {  /* after control init has been sent */
               adsl_clact_end = adsl_clact_cur;  /* send end to this active cluster */
               break;                       /* process loop once more  */
             }
#endif
             bol_delete = TRUE;             /* delete this entry       */
             break;                         /* nothing more to do      */
           }
         }
       }
     }
     adsl_clact_cur = adsl_clact_cur->adsc_next;  /* get next in chain */
   }
   dss_critsect_cluster.m_leave();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX4T l%05d m_leave() after", __LINE__ );
#endif
   if (adsl_clact_end) {                    /* send end to this active cluster */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_check_cluster_member_double() adsl_clact_end set adsl_clact_end->iec_clr_stat=%d.",
                     __LINE__, adsl_clact_end->iec_clr_stat );
#endif
     m_send_end_clact( adsl_clact_cur );    /* send end to partner     */
     goto p_loop_00;                        /* loop to compare active clusters */
   }
   if (bol_delete) {                        /* delete this entry       */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_check_cluster_member_double() bol_delete set adsp_clact->iec_clr_stat=%d.",
                     __LINE__, adsp_clact->iec_clr_stat );
#endif
     m_send_end_clact( adsp_clact );        /* send end to partner     */
     return;
   }
// 09.10.07 KB to-do CMA search cluster member adsc_clrem
//#ifdef B110917
   if (   (adsp_clact->adsc_clrem == NULL)  /* no cluster remote structure */
       && (adss_cluster_main)) {
     adsl_clrem_w1 = adss_cluster_main->adsc_clre;  /* chain of remote WSPs */
     while (adsl_clrem_w1) {                /* loop over all remote WSPs */
       if (   (adsl_clrem_w1->imc_len_name == adsp_clact->imc_len_config_name)
           && (!memcmp( adsl_clrem_w1->achc_name,
                        adsp_clact->achc_config_name,
                        adsl_clrem_w1->imc_len_name ))) {
         adsp_clact->adsc_clrem = adsl_clrem_w1;  /* set corresponding remote WSP */
         break;
       }
       adsl_clrem_w1 = adsl_clrem_w1->adsc_next;  /* get next in chain */
     }
   }
//#endif
   if (bop_after_sleep) {                   /* already all checked     */
     adsp_clact->iec_clr_stat = ied_clrs_open;  /* state is now open   */
     dsg_sys_state_1.imc_load_balancing_value = m_get_load();  /* last value returned by load-balancing */
#ifdef TRACEHL_LOAD
     m_hlnew_printf( HLOG_TRACE1, "p%06d l%05d xs-gw-cluster m_check_cluster_member_double() m_get_load() returned %d listen %d.",
                     M_GET_PID, __LINE__, dsg_sys_state_1.imc_load_balancing_value, dsg_sys_state_1.boc_listen_active );
#endif
     dsg_sys_state_1.imc_load_balancing_epoch = m_get_time();  /* time last load-balancing query was done */
     if (adss_cluster_main->boc_display_load) {  /* display load every time calculated */
       m_hlnew_printf( HLOG_INFO1, "HWSPCL0030I Cluster current load %d (calculated l%05d)",
                       dsg_sys_state_1.imc_load_balancing_value, __LINE__ );
     }
#ifndef B121004
     adsp_clact->imc_time_recv = dsg_sys_state_1.imc_load_balancing_epoch;  /* time last received data */
#endif
     m_send_cluster_lbal( adsp_clact );     /* send load-balancing     */
#ifdef B120210
     m_cma1_cluster_open( adsp_clact );     /* connection open now     */
#endif
#ifndef B120210
     if (adsp_clact->boc_same_group) {      /* is in same group as main */
       m_cma1_cluster_open( adsp_clact );   /* connection open now     */
     }
#endif
     return;
   }
   adsl_cltim1 = (struct dsd_cluster_timer_1 *) malloc( sizeof(struct dsd_cluster_timer_1) );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_check_cluster_member_double() allocated adsl_cltim1=%p.",
                   __LINE__, adsl_cltim1 );
#endif
   adsl_cltim1->adsc_clact = adsp_clact;    /* active cluster          */
   memset( &adsl_cltim1->dsc_timer_ele, 0, sizeof(struct dsd_timer_ele) );
   adsl_cltim1->dsc_timer_ele.amc_compl = &m_timeout_init_1;   /* set routine for timeout */
   adsl_cltim1->dsc_timer_ele.ilcwaitmsec = DEF_CLUSTER_INIT_W * 1000;  /* wait in milliseconds */
#ifdef B090419
   adsp_clact->vpc_special_1 = adsl_cltim1;  /* save timer structure   */
#endif
   m_time_set( &adsl_cltim1->dsc_timer_ele, FALSE );  /* set timeout now */
} /* end m_check_cluster_member_double()                               */

/** put active cluster in chain                                        */
static void m_set_clact_chain( struct dsd_cluster_active *adsp_clact ) {
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX2T l%05d m_enter() before", __LINE__ );
#endif
   dss_critsect_cluster.m_enter();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX3T l%05d m_enter() after", __LINE__ );
#endif
   adsp_clact->adsc_next = adsg_clact_ch;   /* get old chain           */
   adsg_clact_ch = adsp_clact;              /* set new chain           */
   dss_critsect_cluster.m_leave();          /* critical section        */
#ifdef TRACEHL_CS1
   m_hlnew_printf( HLOG_TRACE1, "HWSPCLXXX4T l%05d m_leave() after", __LINE__ );
#endif
} /* end m_set_clact_chain()                                                 */

/** send end connection to other side                                  */
static void m_send_end_clact( struct dsd_cluster_active *adsp_clact ) {
   int        iml1;                         /* working variable        */
   char       *achl_w1;                     /* working variable        */
   struct dsd_cluster_send *adsl_clsend_w1;  /* send buffer            */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_send_end_clact() called",
                   __LINE__ );
#endif
   adsp_clact->iec_clr_stat = ied_clrs_send_end;  /* state is send end */
   adsl_clsend_w1 = (struct dsd_cluster_send *) m_proc_alloc();
#ifdef B110926
   achl_w1 = (char *) adsl_clsend_w1 + LEN_TCP_RECV - 4;
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsl_clsend_w1 + 1))
   ADSL_GAI1_W1->achc_ginp_cur = achl_w1;
   *(achl_w1 + 0) = 1;                      /* length                  */
   *(achl_w1 + 1) = (unsigned char) '1';    /* tag end session         */
   ADSL_GAI1_W1->achc_ginp_end = achl_w1 + 2;
   ADSL_GAI1_W1->adsc_next = NULL;          /* end of chain            */
#undef ADSL_GAI1_W1
#endif
   adsl_clsend_w1->adsc_clact = adsp_clact;  /* active cluster         */
   adsl_clsend_w1->amc_compl = &m_cluster_free_send;  /* completition routine */
#ifdef B110926
   adsl_clsend_w1->iec_cl_type = ied_clty_control;  /* type is control */
   adsl_clsend_w1->adsc_gai1_send = (struct dsd_gather_i_1 *) (adsl_clsend_w1 + 1);
#else
   adsl_clsend_w1->iec_cl_type = ied_clty_end;  /* type is end         */
   adsl_clsend_w1->adsc_gai1_send = NULL;   /* no data to send         */
#endif
   iml1 = m_cluster_send( adsl_clsend_w1 );
   if (iml1) {                              /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_send_end_clact() m_cluster_send() returned %d.",
                     __LINE__, iml1 );
     m_proc_free( adsl_clsend_w1 );
   }
} /* end m_send_end_clact()                                            */

/** WSP Administrator - retrieve information about cluster             */
extern "C" struct dsd_sdh_control_1 * m_get_wspadm1_cluster( void ) {
   int        iml1, iml2, iml3;             /* working variables       */
#ifdef XYZ1
   int        iml_len_ineta;                /* length of INETAs        */
   char       *achl_ineta;                  /* address of INETA        */
#endif
   char       *achl_out;                    /* output of values        */
   const char *achl_query_main;             /* version of WSP etc.     */
   int        iml_len_query_main;           /* length version of WSP etc. */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster structure */
   struct dsd_cluster_remote *adsl_clrem_w1;  /* cluster remote structure */
   struct dsd_wspadm1_cluster_main *adsl_o_c_main;
   struct dsd_wspadm1_cluster_remote *adsl_o_c_remote;  /* WSP Administration Cluster remote WSP */
#ifdef XYZ1
   struct dsd_wspadm1_listen_ineta *adsl_o_l_ineta;
#endif
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working-variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_first;  /* first structure     */
   struct dsd_sdh_control_1 *adsl_sdhc1_last;  /* last structure       */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* output data             */
#ifdef XYZ1
   struct dsd_loconf_1 *adsl_loconf_1_w1;   /* working var loaded conf */
   struct dsd_gate_1 *adsl_gate_1_w1;       /* gateway                 */
   struct dsd_gate_listen_1 *adsl_gate_listen_1_w1;  /* listen part of gateway */
#endif

   /* get first buffer                                                 */
   adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
   memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
   achl_out = (char *) (adsl_sdhc1_w1 + 1) + 4 + 1 + sizeof(void *) - 1;  /* output of values */
   achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
   adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - sizeof(struct dsd_gather_i_1));
   adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_gai1_w1;  /* gather input data */
   adsl_sdhc1_first = adsl_sdhc1_w1;        /* first structure now present */
   adsl_sdhc1_last = adsl_sdhc1_w1;         /* set last structure      */
   adsl_gai1_w1->adsc_next = NULL;
   achl_query_main = m_get_query_main();    /* get version of WSP etc. */
   iml_len_query_main = strlen( achl_query_main );  /* length version of WSP etc. */
   iml3 = dsg_this_server.imc_len_server_name  /* length server name   */
            + iml_len_query_main;
   if (adss_cluster_main) {                 /* cluster configured      */
     iml3 += adss_cluster_main->imc_this_len_name;  /* length configuration name */
#ifndef B110926
     iml3 += adss_cluster_main->imc_this_len_group;  /* length of group in bytes */
     iml3 += adss_cluster_main->imc_this_len_location;  /* length of location in bytes */
     iml3 += adss_cluster_main->imc_this_len_url;  /* length of URL in bytes */
#endif
   }
   iml1 = 1 + sizeof(struct dsd_wspadm1_cluster_main) + iml3;
   adsl_o_c_main = (struct dsd_wspadm1_cluster_main *) achl_out;
   *(--achl_out) = 0;                       /* record type             */
   iml2 = 0;                                /* clear more bit          */
   while (TRUE) {                           /* output length NHASN     */
     *(--achl_out) = (unsigned char) ((iml1 & 0X7F) | iml2);  /* output of digit */
     iml1 >>= 7;                            /* remove digit            */
     if (iml1 == 0) break;                  /* end of output           */
     iml2 = 0X80;                           /* set more bit            */
   }
   adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
   memset( adsl_o_c_main, 0, sizeof(struct dsd_wspadm1_cluster_main) );
   adsl_o_c_main->ilc_epoch_started = dsg_this_server.ilc_epoch_started;  /* time WSP started */
   adsl_o_c_main->imc_len_server_name = dsg_this_server.imc_len_server_name;  /* length server name */
   adsl_o_c_main->imc_len_query_main = iml_len_query_main;  /* length WSP version etc. UTF-8 */
   if (adss_cluster_main) {                 /* cluster configured      */
     adsl_o_c_main->imc_len_wsp_name = adss_cluster_main->imc_this_len_name;  /* length cluster WSP name UTF-8 */
#ifndef B110926
     adsl_o_c_main->imc_len_group = adss_cluster_main->imc_this_len_group;  /* length of group in bytes */
     adsl_o_c_main->imc_len_location = adss_cluster_main->imc_this_len_location;  /* length of location in bytes */
     adsl_o_c_main->imc_len_url = adss_cluster_main->imc_this_len_url;  /* length of URL in bytes */
     adsl_o_c_main->boc_deny_not_configured = adss_cluster_main->boc_deny_not_configured;  /* deny connect in from not configured WSP */
#endif
   }
   adsl_o_c_main->imc_pid = dsg_this_server.imc_pid;  /* process id    */
#ifndef B130212
   adsl_o_c_main->imc_lb_load = dsg_sys_state_1.imc_load_balancing_value;  /* load reported in load-balancing */
   adsl_o_c_main->imc_lb_epoch = dsg_sys_state_1.imc_load_balancing_epoch;  /* epoch last report load-balancing */
   adsl_o_c_main->boc_listen_stopped = !dsg_sys_state_1.boc_listen_active;  /* listen has been stopped */
#endif
   memcpy( &adsl_o_c_main->chrc_wsp_fingerprint,
           &dsg_this_server.chrc_fingerprint,
           DEF_LEN_FINGERPRINT );           /* hash over WSP           */
   memcpy( &adsl_o_c_main->chrc_conf_file_fingerprint,
           &adsg_loconf_1_inuse->chrc_fingerprint,
           DEF_LEN_FINGERPRINT );           /* hash over current configuration-file */
   achl_out = (char *) (adsl_o_c_main + 1);  /* after this structure   */
   memcpy( achl_out, dsg_this_server.chrc_server_name, dsg_this_server.imc_len_server_name );
   achl_out += dsg_this_server.imc_len_server_name;  /* after this field */
   memcpy( achl_out, achl_query_main, iml_len_query_main );
   achl_out += iml_len_query_main;          /* after this field        */
   if (adss_cluster_main) {                 /* cluster configured      */
     memcpy( achl_out, adss_cluster_main->achc_this_name, adss_cluster_main->imc_this_len_name );
     achl_out += adss_cluster_main->imc_this_len_name;  /* after this field */
#ifndef B110926
     memcpy( achl_out, adss_cluster_main->achc_this_group, adss_cluster_main->imc_this_len_group );
     achl_out += adss_cluster_main->imc_this_len_group;  /* length of group in bytes */
     memcpy( achl_out, adss_cluster_main->achc_this_location, adss_cluster_main->imc_this_len_location );
     achl_out += adss_cluster_main->imc_this_len_location;  /* length of location in bytes */
     memcpy( achl_out, adss_cluster_main->achc_this_url, adss_cluster_main->imc_this_len_url );
     achl_out += adss_cluster_main->imc_this_len_url;  /* length of URL in bytes */
#endif
   }
   adsl_gai1_w1->achc_ginp_end = achl_out;  /* end of this structure   */
   /* we process all remote clusters that are currently active         */
   adsl_clact_w1 = adsg_clact_ch;           /* get chain of active clusters */
// to-do 02.06.10 KB - put also fingerprint
   while (adsl_clact_w1) {                  /* loop over all active clusters */
     if (adsl_clact_w1->iec_clr_stat == ied_clrs_open) {  /* state is open */
#ifdef B110926
       iml1 = sizeof(struct dsd_wspadm1_cluster_remote)
                + adsl_clact_w1->imc_len_config_name  /* length configuration name */
                + adsl_clact_w1->imc_len_server_name  /* length server name */
                + adsl_clact_w1->imc_len_query_main;  /* length WSP name, version etc. */
#else
       iml1 = sizeof(struct dsd_wspadm1_cluster_remote)
                + adsl_clact_w1->imc_len_config_name  /* length configuration name */
                + adsl_clact_w1->imc_len_server_name  /* length server name */
                + adsl_clact_w1->imc_len_query_main  /* length WSP name, version etc. */
                + adsl_clact_w1->imc_len_group  /* length of group in bytes */
                + adsl_clact_w1->imc_len_location  /* length of location in bytes */
                + adsl_clact_w1->imc_len_url;  /* length of URL in bytes */
#endif
       /* find space in output area                                    */
       do {                                 /* pseudo-loop             */
         achl_out += 4 + 1 + sizeof(void *) - 1;  /* output of values  */
         achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
         if ((achl_out + iml1 + sizeof(struct dsd_gather_i_1))
               <= ((char *) adsl_gai1_w1)) {
           adsl_gai1_w1--;                  /* here is gather output   */
           (adsl_gai1_w1 + 1)->adsc_next = adsl_gai1_w1;  /* set next in chain */
           break;
         }
         adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
         memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
         achl_out = (char *) (adsl_sdhc1_w1 + 1) + 4 + 1 + sizeof(void *) - 1;  /* output of values */
         achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
         adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - sizeof(struct dsd_gather_i_1));
         adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_gai1_w1;  /* gather input data */
         adsl_sdhc1_last->adsc_next = adsl_sdhc1_w1;  /* append to chain */
         adsl_sdhc1_last = adsl_sdhc1_w1;   /* set last structure      */
       } while (FALSE);
       adsl_gai1_w1->adsc_next = NULL;
       adsl_o_c_remote = (struct dsd_wspadm1_cluster_remote *) achl_out;
       iml1++;                              /* add length record type  */
       *(--achl_out) = 1;                   /* record type             */
       iml2 = 0;                            /* clear more bit          */
       while (TRUE) {                       /* output length NHASN     */
         *(--achl_out) = (unsigned char) ((iml1 & 0X7F) | iml2);  /* output of digit */
         iml1 >>= 7;                        /* remove digit            */
         if (iml1 == 0) break;              /* end of output           */
         iml2 = 0X80;                       /* set more bit            */
       }
       adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
       memset( adsl_o_c_remote, 0, sizeof(struct dsd_wspadm1_cluster_remote) );
       adsl_o_c_remote->ilc_handle_cluster = (HL_LONGLONG) adsl_clact_w1;  /* select cluster */
       adsl_o_c_remote->ilc_epoch_started = adsl_clact_w1->ilc_epoch_started;  /* time WSP started */
       adsl_o_c_remote->imc_len_config_name = adsl_clact_w1->imc_len_config_name;  /* length configuration name */
       adsl_o_c_remote->imc_len_server_name = adsl_clact_w1->imc_len_server_name;  /* length server name */
       adsl_o_c_remote->imc_len_query_main = adsl_clact_w1->imc_len_query_main;  /* length WSP version etc. UTF-8 */
#ifndef B110926
       adsl_o_c_remote->imc_len_group = adsl_clact_w1->imc_len_group;  /* length of group in bytes */
       adsl_o_c_remote->imc_len_location = adsl_clact_w1->imc_len_location;  /* length of location in bytes */
       adsl_o_c_remote->imc_len_url = adsl_clact_w1->imc_len_url;  /* length of URL in bytes */
#endif
       adsl_o_c_remote->imc_pid = adsl_clact_w1->imc_pid;  /* process id */
       adsl_o_c_remote->imc_epoch_conn = adsl_clact_w1->imc_epoch_conn;  /* time/epoch connected */
       adsl_o_c_remote->imc_lb_load = adsl_clact_w1->imc_lbal_load;  /* load reported in load-balancing */
       adsl_o_c_remote->imc_lb_epoch = adsl_clact_w1->imc_lbal_epoch_recv;  /* epoch last report load-balancing received */
       adsl_o_c_remote->boc_listen_stopped = adsl_clact_w1->boc_listen_stopped;  /* listen has been stopped */
#ifndef B110926
       adsl_o_c_remote->boc_same_group = adsl_clact_w1->boc_same_group;  /* is in same group as main */
       adsl_o_c_remote->boc_redirect = adsl_clact_w1->boc_redirect;  /* is redirected */
#ifdef HL_UNIX
       adsl_o_c_remote->boc_unix_socket = adsl_clact_w1->boc_unix_socket;  /* is Unix domain socket */
       adsl_o_c_remote->imc_uds_pid = adsl_clact_w1->imc_uds_pid;  /* process id Unix domain socket */
#endif
#endif
       adsl_o_c_remote->imc_time_start = adsl_clact_w1->imc_time_start;  /* time connection started */
       adsl_o_c_remote->imc_stat_no_recv = adsl_clact_w1->imc_stat_no_recv;  /* statistic number of receives */
       adsl_o_c_remote->imc_stat_no_send = adsl_clact_w1->imc_stat_no_send;  /* statistic number of sends */
       adsl_o_c_remote->ilc_stat_len_recv = adsl_clact_w1->ilc_stat_len_recv;  /* statistic length of receives */
       adsl_o_c_remote->ilc_stat_len_send = adsl_clact_w1->ilc_stat_len_send;  /* statistic length of sends */
       memcpy( &adsl_o_c_remote->chrc_wsp_fingerprint,
               &adsl_clact_w1->chrc_fingerprint,
               DEF_LEN_FINGERPRINT );       /* hash over WSP           */
#ifdef NOT_YET
       adsl_o_l_main->imc_len_gate_name = iml3;  /* length gate name UTF-8 */
       adsl_o_l_main->imc_epoch_conf_loaded = adsl_gate_1_w1->adsc_loconf_1->imc_epoch_loaded;  /* time / epoch configuration loaded */
       if (adsl_gate_1_w1->adsc_loconf_1 == adsg_loconf_1_inuse) {  /* in use now */
         adsl_o_l_main->boc_active_conf = TRUE;  /* listen is from active configuration */
       }
       adsl_o_l_main->imc_gateport = adsl_gate_1_w1->imc_gateport;  /* TCP/IP port listen */
       adsl_o_l_main->imc_backlog = adsl_gate_1_w1->imc_backlog;  /* TCP/IP backlog listen */
       adsl_o_l_main->imc_timeout = adsl_gate_1_w1->itimeout;  /* timeout in seconds */
#ifdef NOT_YET
       adsl_o_l_main->imc_thresh_session;           /* threshold-session       */
       adsl_o_l_main->boc_cur_thresh_session;       /* currently over threshold-session */
       adsl_o_l_main->imc_epoch_thresh_se_notify;   /* last time of threshold-session notify */
#endif
       adsl_o_l_main->imc_session_max = adsl_gate_1_w1->i_session_max;  /* maximum number of sess */
       adsl_o_l_main->imc_session_cos = adsl_gate_1_w1->i_session_cos;  /* count start of session */
       adsl_o_l_main->imc_session_cur = adsl_gate_1_w1->i_session_cur;  /* current number of sess */
       adsl_o_l_main->imc_session_mre = adsl_gate_1_w1->i_session_mre;  /* maximum no sess reached */
       adsl_o_l_main->imc_session_exc = adsl_gate_1_w1->i_session_exc;  /* number max session exce */
#endif
       achl_out = (char *) (adsl_o_c_remote + 1);  /* after this structure */
       if (adsl_o_c_remote->imc_len_config_name) {  /* length configuration name */
         memcpy( achl_out,
                 adsl_clact_w1->achc_config_name,
                 adsl_o_c_remote->imc_len_config_name );
         achl_out += adsl_o_c_remote->imc_len_config_name;  /* add length configuration name */
       }
       if (adsl_o_c_remote->imc_len_server_name) {  /* length server name */
         memcpy( achl_out,
                 adsl_clact_w1->achc_server_name,
                 adsl_o_c_remote->imc_len_server_name );
         achl_out += adsl_o_c_remote->imc_len_server_name;  /* add length server name */
       }
       if (adsl_o_c_remote->imc_len_query_main) {  /* length WSP name, version etc. */
         memcpy( achl_out,
                 adsl_clact_w1->achc_query_main,
                 adsl_o_c_remote->imc_len_query_main );
         achl_out += adsl_o_c_remote->imc_len_query_main;  /* add length WSP name, version etc. */
       }
#ifndef B110926
       if (adsl_o_c_remote->imc_len_group) {  /* length of group in bytes */
         memcpy( achl_out,
                 adsl_clact_w1->achc_group,  /* group of WSP, UTF-8    */
                 adsl_o_c_remote->imc_len_group );
         achl_out += adsl_o_c_remote->imc_len_group;  /* add length group */
       }
       if (adsl_o_c_remote->imc_len_location) {  /* length of location in bytes */
         memcpy( achl_out,
                 adsl_clact_w1->achc_location,  /* location of WSP, UTF-8 */
                 adsl_o_c_remote->imc_len_location );
         achl_out += adsl_o_c_remote->imc_len_location;  /* add length location */
       }
       if (adsl_o_c_remote->imc_len_url) {  /* length of URL in bytes  */
         memcpy( achl_out,
                 adsl_clact_w1->achc_url,   /* URL of WSP, UTF-8       */
                 adsl_o_c_remote->imc_len_url );
         achl_out += adsl_o_c_remote->imc_len_url;  /* add length URL  */
       }
#endif
       adsl_gai1_w1->achc_ginp_end = achl_out;  /* end of this structure */
     }
     adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
   }
   /* we process all remote clusters that are currently inactive       */
   if (adss_cluster_main) {                 /* cluster configured      */
     adsl_clrem_w1 = adss_cluster_main->adsc_clre;  /* chain of remote WSPs */
     while (adsl_clrem_w1) {                /* loop over all configured remote WSPs */
       do {                                 /* pseudo-loop             */
         adsl_clact_w1 = adsg_clact_ch;     /* get chain of active cluster entries */
         while (adsl_clact_w1) {            /* loop over all active cluster entries */
           if (   (adsl_clact_w1->iec_clr_stat == ied_clrs_open)  /* state is open */
               && (adsl_clact_w1->adsc_clrem == adsl_clrem_w1)) {  /* found cluster remote structure */
             break;
           }
           adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
         }
         if (adsl_clact_w1) break;          /* entry already processed */
         /* we process this cluster entry                              */
         iml1 = sizeof(struct dsd_wspadm1_cluster_remote)
                  + adsl_clrem_w1->imc_len_name;  /* length of name in bytes */
         /* find space in output area                                  */
         do {                               /* pseudo-loop             */
           achl_out += 4 + 1 + sizeof(void *) - 1;  /* output of values */
           achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
           if ((achl_out + iml1 + sizeof(struct dsd_gather_i_1))
                 <= ((char *) adsl_gai1_w1)) {
             adsl_gai1_w1--;                /* here is gather output   */
             (adsl_gai1_w1 + 1)->adsc_next = adsl_gai1_w1;  /* set next in chain */
             break;
           }
           adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
           memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
           achl_out = (char *) (adsl_sdhc1_w1 + 1) + 4 + 1 + sizeof(void *) - 1;  /* output of values */
           achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
           adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - sizeof(struct dsd_gather_i_1));
           adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_gai1_w1;  /* gather input data */
           adsl_sdhc1_last->adsc_next = adsl_sdhc1_w1;  /* append to chain */
           adsl_sdhc1_last = adsl_sdhc1_w1;  /* set last structure     */
         } while (FALSE);
         adsl_gai1_w1->adsc_next = NULL;
         adsl_o_c_remote = (struct dsd_wspadm1_cluster_remote *) achl_out;
         iml1++;                            /* add length record type  */
         *(--achl_out) = 1;                 /* record type             */
         iml2 = 0;                          /* clear more bit          */
         while (TRUE) {                     /* output length NHASN     */
           *(--achl_out) = (unsigned char) ((iml1 & 0X7F) | iml2);  /* output of digit */
           iml1 >>= 7;                      /* remove digit            */
           if (iml1 == 0) break;            /* end of output           */
           iml2 = 0X80;                     /* set more bit            */
         }
         adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
         memset( adsl_o_c_remote, 0, sizeof(struct dsd_wspadm1_cluster_remote) );
         adsl_o_c_remote->imc_len_config_name = adsl_clrem_w1->imc_len_name;  /* length of name in bytes */
         achl_out = (char *) (adsl_o_c_remote + 1);  /* after this structure */
         if (adsl_clrem_w1->imc_len_name) {  /* length of name in bytes */
           memcpy( achl_out,
                   adsl_clrem_w1->achc_name,
                   adsl_clrem_w1->imc_len_name );
           achl_out += adsl_o_c_remote->imc_len_config_name;  /* add length configuration name */
         }
         adsl_gai1_w1->achc_ginp_end = achl_out;  /* end of this structure */
       } while (FALSE);
       adsl_clrem_w1 = adsl_clrem_w1->adsc_next;  /* get next in chain */
     }
   }
#ifdef XYZ1
   adsl_loconf_1_w1 = adss_loconf_1_anchor;  /* get anchor loaded conf  */
   do {
#ifdef XYZ1
     m_hlnew_printf( HLOG_INFO1, "HWSPR003I configuration loaded %s", adsl_loconf_1_w1->byrc_time );
#endif
     adsl_gate_1_w1 = adsl_loconf_1_w1->adsc_gate_anchor;  /* get anchor gate */
     while (adsl_gate_1_w1) {
#ifdef XYZ1
       iml_len_ineta = sizeof(struct dsd_wspadm1_listen_main);  /* clear length of INETAs */
       adsl_gate_listen_1_w1 = adsl_gate_1_w1->adsc_gate_listen_1_ch;  /* get chain listen part of gateway */
       while (adsl_gate_listen_1_w1) {      /* loop over all listen parts */
         iml_len_ineta += 1 + 1 + sizeof(struct dsd_wspadm1_listen_ineta) + adsl_gate_listen_1_w1->imc_len_ineta;
         adsl_gate_listen_1_w1 = adsl_gate_listen_1_w1->adsc_next;  /* get next in chain */
       }
#endif
       iml3 = m_len_vx_vx( ied_chs_utf_8,
                           adsl_gate_1_w1 + 1, -1, ied_chs_utf_16 );
       iml1 = sizeof(struct dsd_wspadm1_listen_main) + iml3;
       /* find space in output area                                    */
       do {                                 /* pseudo-loop             */
         if (adsl_sdhc1_first) {            /* first structure present */
           achl_out += 4 + 1 + sizeof(void *) - 1;  /* output of values */
           achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
           if ((achl_out + iml1 + sizeof(struct dsd_gather_i_1))
                 <= ((char *) adsl_gai1_w1)) {
             adsl_gai1_w1--;                /* here is gather output   */
             (adsl_gai1_w1 + 1)->adsc_next = adsl_gai1_w1;  /* set next in chain */
             break;
           }
         }
         adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
         memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
         achl_out = (char *) (adsl_sdhc1_w1 + 1) + 4 + 1 + sizeof(void *) - 1;  /* output of values */
         achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
         adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - sizeof(struct dsd_gather_i_1));
         adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_gai1_w1;  /* gather input data */
         if (adsl_sdhc1_first == NULL) {    /* first structure not present */
           adsl_sdhc1_first = adsl_sdhc1_w1;  /* first structure now present */
           adsl_sdhc1_last = adsl_sdhc1_w1;  /* set last structure     */
           break;
         }
         adsl_sdhc1_last->adsc_next = adsl_sdhc1_w1;  /* append to chain */
         adsl_sdhc1_last = adsl_sdhc1_w1;   /* set last structure      */
       } while (FALSE);
       adsl_gai1_w1->adsc_next = NULL;
       adsl_o_l_main = (struct dsd_wspadm1_listen_main *) achl_out;
       iml1++;                              /* add length record type  */
       *(--achl_out) = 0;                   /* record type             */
       iml2 = 0;                            /* clear more bit          */
       while (TRUE) {                       /* output length NHASN     */
         *(--achl_out) = (unsigned char) ((iml1 & 0X7F) | iml2);  /* output of digit */
         iml1 >>= 7;                        /* remove digit            */
         if (iml1 == 0) break;              /* end of output           */
         iml2 = 0X80;                       /* set more bit            */
       }
       adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
       memset( adsl_o_l_main, 0, sizeof(struct dsd_wspadm1_listen_main) );
       adsl_o_l_main->imc_len_gate_name = iml3;  /* length gate name UTF-8 */
       adsl_o_l_main->imc_epoch_conf_loaded = adsl_gate_1_w1->adsc_loconf_1->imc_epoch_loaded;  /* time / epoch configuration loaded */
       if (adsl_gate_1_w1->adsc_loconf_1 == adsg_loconf_1_inuse) {  /* in use now */
         adsl_o_l_main->boc_active_conf = TRUE;  /* listen is from active configuration */
       }
#ifdef NOT_YET
       adsl_o_l_main->boc_use_listen_gw;            /* listen over listen gateway */
#endif
       adsl_o_l_main->imc_gateport = adsl_gate_1_w1->imc_gateport;  /* TCP/IP port listen */
       adsl_o_l_main->imc_backlog = adsl_gate_1_w1->imc_backlog;  /* TCP/IP backlog listen */
       adsl_o_l_main->imc_timeout = adsl_gate_1_w1->itimeout;  /* timeout in seconds */
#ifdef NOT_YET
       adsl_o_l_main->imc_thresh_session;           /* threshold-session       */
       adsl_o_l_main->boc_cur_thresh_session;       /* currently over threshold-session */
       adsl_o_l_main->imc_epoch_thresh_se_notify;   /* last time of threshold-session notify */
#endif
       adsl_o_l_main->imc_session_max = adsl_gate_1_w1->i_session_max;  /* maximum number of sess */
       adsl_o_l_main->imc_session_cos = adsl_gate_1_w1->i_session_cos;  /* count start of session */
       adsl_o_l_main->imc_session_cur = adsl_gate_1_w1->i_session_cur;  /* current number of sess */
       adsl_o_l_main->imc_session_mre = adsl_gate_1_w1->i_session_mre;  /* maximum no sess reached */
       adsl_o_l_main->imc_session_exc = adsl_gate_1_w1->i_session_exc;  /* number max session exce */
       achl_out = (char *) (adsl_o_l_main + 1);  /* after this structure */
       m_cpy_vx_vx( achl_out, iml3, ied_chs_utf_8,
                    adsl_gate_1_w1 + 1, -1, ied_chs_utf_16 );
       achl_out += iml3;                    /* after name              */
       adsl_gai1_w1->achc_ginp_end = achl_out;  /* end of this structure */
       adsl_gate_listen_1_w1 = adsl_gate_1_w1->adsc_gate_listen_1_ch;  /* get chain listen part of gateway */
       while (adsl_gate_listen_1_w1) {      /* loop over all listen parts */
         iml_len_ineta = 0;                 /* clear length            */
         switch (adsl_gate_listen_1_w1->dsc_soa.ss_family) {
           case AF_INET:                    /* IPV4                    */
             achl_ineta = (char *) &((struct sockaddr_in *) &adsl_gate_listen_1_w1->dsc_soa)->sin_addr;
             iml_len_ineta = 4;
             break;
           case AF_INET6:                   /* IPV6                    */
             achl_ineta = (char *) &((struct sockaddr_in6 *) &adsl_gate_listen_1_w1->dsc_soa)->sin6_addr;
             iml_len_ineta = 16;
             break;
         }
         if (iml_len_ineta) {               /* address family valid    */
           iml1 = sizeof(struct dsd_wspadm1_listen_ineta) + iml_len_ineta;
           /* find space in output area                                */
           do {                             /* pseudo-loop             */
             achl_out += 4 + 1 + sizeof(void *) - 1;  /* output of values */
             achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
             if ((achl_out + iml1 + sizeof(struct dsd_gather_i_1))
                   <= ((char *) adsl_gai1_w1)) {
               adsl_gai1_w1--;              /* here is gather output   */
               (adsl_gai1_w1 + 1)->adsc_next = adsl_gai1_w1;  /* set next in chain */
               break;
             }
             adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
             memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
             achl_out = (char *) (adsl_sdhc1_w1 + 1) + 4 + 1 + sizeof(void *) - 1;  /* output of values */
             achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
             adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - sizeof(struct dsd_gather_i_1));
             adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_gai1_w1;  /* gather input data */
             adsl_sdhc1_last->adsc_next = adsl_sdhc1_w1;  /* append to chain */
             adsl_sdhc1_last = adsl_sdhc1_w1;  /* set last structure   */
           } while (FALSE);
           adsl_gai1_w1->adsc_next = NULL;
           adsl_o_l_ineta = (struct dsd_wspadm1_listen_ineta *) achl_out;
           iml1++;                          /* add length record type  */
           *(--achl_out) = 0;               /* record type             */
           iml2 = 0;                        /* clear more bit          */
           while (TRUE) {                   /* output length NHASN     */
             *(--achl_out) = (unsigned char) ((iml1 & 0X7F) | iml2);  /* output of digit */
             iml1 >>= 7;                    /* remove digit            */
             if (iml1 == 0) break;          /* end of output           */
             iml2 = 0X80;                   /* set more bit            */
           }
           adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
           memset( adsl_o_l_ineta, 0, sizeof(struct dsd_wspadm1_listen_ineta) );
           achl_out = (char *) (adsl_o_l_ineta + 1);  /* after this structure */
           memcpy( achl_out, achl_ineta, iml_len_ineta );
           achl_out += iml_len_ineta;
         }
         adsl_gate_listen_1_w1 = adsl_gate_listen_1_w1->adsc_next;  /* get next in chain */
       }
       adsl_gate_1_w1 = adsl_gate_1_w1->adsc_next;
     }
     adsl_loconf_1_w1 = adsl_loconf_1_w1->adsc_next;  /* get next in chain */
   } while (adsl_loconf_1_w1);              /* over all configurations */
#endif
   return adsl_sdhc1_first;
} /* end m_get_wspadm1_cluster()                                       */

/** routine called by timer thread when load-balancing has to be done  */
static void m_cluster_lbal_timer( struct dsd_timer_ele *adsp_timer_ele ) {
#ifdef XYZ1
   BOOL       bol1;                         /* working variable        */
#endif
   int        iml1, iml2;                   /* working variables       */
   int        iml_time;                     /* current time            */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster entry  */
#ifdef XYZ1
   int        iml_load;
#endif
#ifdef TRACEHL1
   int        iml_count_h;
   HL_LONGLONG ill_current_time;            /* current time            */
#endif

   if (adss_cluster_main == NULL) return;   /* no active cluster configuration */
   if (adss_cluster_main->imc_lbal_intv == 0) return;  /* <interval-load-balancing-probe> */
#ifndef D_CLUSTER_NO_CHECK_RECV
   /* check if all connected cluster members if they did send something */
   iml1 = adss_cluster_main->imc_recv_timeout;  /* receive timeout     */
// if (iml1 == 0) iml1 = adss_cluster_main->imc_lbal_intv * 2;  /* <interval-load-balancing-probe> twice */
   if (iml1 == 0) iml1 = adss_cluster_main->imc_lbal_intv + DEF_CLUSTER_INIT_W;  /* <interval-load-balancing-probe> plus ... */
   iml_time = m_get_time();                 /* current time            */
   adsl_clact_w1 = adsg_clact_ch;           /* get chain of active cluster entries */
   while (adsl_clact_w1) {                  /* loop over all active cluster entries */
     do {                                   /* pseudo-loop             */
#ifdef HL_UNIX
       if (adsl_clact_w1->boc_unix_socket) break;  /* is Unix domain socket */
#endif
       if (adsl_clact_w1->iec_clr_stat == ied_clrs_closed) break;  /* state is closed now */
       if (adsl_clact_w1->iec_clr_stat == ied_clrs_timed_out) break;  /* state is timed out */
       if (adsl_clact_w1->iec_clr_stat == ied_clrs_send_end) break;  /* state is send end */
       iml2 = iml1;                         /* get timeout seconds     */
       if (   (adsl_clact_w1->adsc_clrem)   /* with cluster remote structure */
           && (adsl_clact_w1->adsc_clrem->imc_recv_timeout > 0)) {  /* receive timeout set */
         iml2 = adsl_clact_w1->adsc_clrem->imc_recv_timeout;  /* get receive timeout */
       }
       if (   (adsl_clact_w1->iec_clr_stat == ied_clrs_acc_init_sent)  /* after control init has been sent */
           || (adsl_clact_w1->iec_clr_stat == ied_clrs_acc_recv_st)  /* after accept start receive */
           || (adsl_clact_w1->iec_clr_stat == ied_clrs_conn_recv_st)) {  /* after connect start receive */
         iml2 = DEF_CLUSTER_INIT_W * 4;     /* wait for init           */
       }
       if (adsl_clact_w1->imc_time_recv >= (iml_time - iml2)) break;  /* time last received data */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_cluster_lbal_timer() received timed out iml_time=%d adsl_clact_w1->imc_time_recv=%d allowed=%d current-intv=%d.",
                       __LINE__, iml_time, adsl_clact_w1->imc_time_recv, iml2, iml_time - adsl_clact_w1->imc_time_recv );
#endif
       m_hlnew_printf( HLOG_WARN1, "HWSPCL0051W Cluster INETA=%s receive timed out state %d l%05d.",
                       adsl_clact_w1->chrc_ineta, (int) adsl_clact_w1->iec_clr_stat, __LINE__ );
       adsl_clact_w1->iec_clr_stat = ied_clrs_timed_out;  /* state is timed out now */
       adsl_clact_w1->dsc_tcpcomp.m_end_session();
     } while (FALSE);
     adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
   }
#endif
   dsg_sys_state_1.imc_load_balancing_value = m_get_load();  /* last value returned by load-balancing */
#ifdef TRACEHL_LOAD
#ifndef HL_UNIX
   m_hlnew_printf( HLOG_TRACE1, "p%06d l%05d xs-gw-cluster m_cluster_lbal_timer() m_get_load() returned %d listen %d.",
                   GetCurrentProcessId(),  __LINE__, dsg_sys_state_1.imc_load_balancing_value, dsg_sys_state_1.boc_listen_active );
#else
   m_hlnew_printf( HLOG_TRACE1, "p%06d l%05d xs-gw-cluster m_cluster_lbal_timer() m_get_load() returned %d listen %d.",
                   getpid(),  __LINE__, dsg_sys_state_1.imc_load_balancing_value, dsg_sys_state_1.boc_listen_active );
#endif
#endif
   dsg_sys_state_1.imc_load_balancing_epoch = m_get_time();  /* time last load-balancing query was done */
#ifdef TRACEHL1
   ill_current_time = m_get_epoch_ms();
#ifdef XYZ1
   iml_load = m_get_load();
#endif
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_cluster_lbal_timer( 0X%p ) called load=%d time=%lld.",
                   __LINE__, adsp_timer_ele, dsg_sys_state_1.imc_load_balancing_value, ill_current_time );
#endif
#ifdef XYZ1
   bol1 = m_status_cluster_lbal();          /* check status            */
   if (bol1) goto p_timer_20;
#endif
   adsl_clact_w1 = adsg_clact_ch;           /* get chain of active cluster entries */
#ifdef TRACEHL1
   iml_count_h = 0;
#endif
   while (adsl_clact_w1) {                  /* loop over all active cluster entries */
     if (   (adsl_clact_w1->iec_clr_stat == ied_clrs_open)  /* state is open */
         && (((dsg_sys_state_1.imc_load_balancing_epoch - adsl_clact_w1->imc_lbal_epoch_sent) * 10)
                > adss_cluster_main->imc_lbal_intv)) {
#ifdef TRACEHL1
       iml_count_h++;
#endif
       m_send_cluster_lbal( adsl_clact_w1 );
     }
     adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster m_cluster_lbal_timer() sent %d.",
                   __LINE__, iml_count_h );
#endif
#ifdef XYZ1

   p_timer_20:
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster dss_cluster_timer_lbal m_time_set( time=%lld ) m_cluster_lbal_timer()",
                   __LINE__, (HL_LONGLONG) (adss_cluster_main->imc_lbal_intv * 1000) );
#ifdef XYZ1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-cluster dss_cluster_timer_lbal m_time_set( time=%d ) m_cluster_lbal_timer()",
                   __LINE__, (int) (adss_cluster_main->imc_lbal_intv * 1000) );
#endif
#endif
   dss_cluster_timer_lbal.dsc_timer_ele.ilcwaitmsec = adss_cluster_main->imc_lbal_intv * 1000;  /* wait in milliseconds */
   m_time_set( &dss_cluster_timer_lbal.dsc_timer_ele, FALSE );  /* set timer now */
} /* end m_cluster_lbal_timer()                                        */

/** routine called by timer thread when reconnect has to be done       */
static void m_cluster_reco_timer( struct dsd_timer_ele *adsp_timer_ele ) {
   int        iml_rc;                       /* return code             */
   struct dsd_cluster_remote *adsl_clrem_w1;  /* cluster remote structure */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster structure */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T m_cluster_reco_timer( %p ) called",
                   __LINE__ , adsp_timer_ele );
#endif
   if (adss_cluster_main == NULL) return;   /* no active cluster configuration */
   if (adss_cluster_main->imc_time_retry_conn == 0) return;  /* time retry connect */

   /* connect all remote WSPs where we have no active connection       */
   adsl_clrem_w1 = adss_cluster_main->adsc_clre;  /* chain of remote WSPs */

   pconn_00:                                /* start connect           */
   if (adsl_clrem_w1 == NULL) return;       /* all done                */
   adsl_clact_w1 = adsg_clact_ch;           /* get chain of active cluster entries */
   while (adsl_clact_w1) {                  /* loop over all active cluster entries */
     if (adsl_clact_w1->adsc_clrem == adsl_clrem_w1) {  /* found cluster remote structure */
       goto pconn_20;                       /* connect to next remote WSP */
     }
     adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
   }
   adsl_clact_w1 = (struct dsd_cluster_active *) malloc( sizeof(struct dsd_cluster_active) );
   memset( adsl_clact_w1, 0, sizeof(struct dsd_cluster_active) );
   adsl_clact_w1->imc_time_start = m_get_time();  /* time connection started */
   adsl_clact_w1->imc_time_recv = m_get_time();  /* time last received data */
   adsl_clact_w1->imc_lbal_load = -1;       /* no load received yet    */
   m_set_clact_chain( adsl_clact_w1 );      /* put in chain            */
   adsl_clact_w1->adsc_clrem = adsl_clrem_w1;  /* cluster remote structure */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-cluster-l%05d-T m_cluster_reco_timer() call m_startco_mh() &dsc_tcpcomp=%p vpp_userfld=%p.",
                   __LINE__, &adsl_clact_w1->dsc_tcpcomp, adsl_clact_w1 );
#endif
   iml_rc = adsl_clact_w1->dsc_tcpcomp.m_startco_mh(
              &dss_tcpco1_cb1,
              adsl_clact_w1,
              &adsl_clact_w1->adsc_clrem->dsc_bind_multih,  /* for bind multihomed */
              adsl_clact_w1->adsc_clrem->adsc_remote_ineta,  /* remote INETA */
#ifndef B121120
              NULL,                         /* INETA to free           */
#endif
              adsl_clact_w1->adsc_clrem->imc_port,  /* port of remote WSP */
              TRUE );                       /* do connect round-robin <connect-round-robin> */
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0001W xs-gw-cluster l%05d m_cluster_reco_timer() m_startco_mh() failed %d.",
                     __LINE__, iml_rc );
//   goto p_conn_80;                        /* close session to client */
// 19.04.09 KB - to-do
   }

   pconn_20:                                /* connect to next remote WSP */
   adsl_clrem_w1 = adsl_clrem_w1->adsc_next;  /* get next in chain     */
   goto pconn_00;                           /* start next connect      */
} /* end m_cluster_reco_timer()                                        */

/** check if we need to reconnect to another WSP                       */
static void m_check_reco_cluster( void ) {
   struct dsd_cluster_remote *adsl_clrem_w1;  /* cluster remote structure */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster structure */

   if (adss_cluster_main == NULL) return;   /* no active cluster configuration */
   if (adss_cluster_main->imc_time_retry_conn == 0) return;  /* time retry connect */
   /* check connect to all remote WSPs                                 */
   adsl_clrem_w1 = adss_cluster_main->adsc_clre;  /* chain of remote WSPs */
   if (adsl_clrem_w1 == NULL) goto pconn_40;  /* all WSPs are connected */

   pconn_00:                                /* start connect           */
   adsl_clact_w1 = adsg_clact_ch;           /* get chain of active cluster entries */
   while (adsl_clact_w1) {                  /* loop over all active cluster entries */
     if (adsl_clact_w1->adsc_clrem == adsl_clrem_w1) {  /* found cluster remote structure */
       goto pconn_20;                       /* connect to next remote WSP */
     }
     adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
   }
   /* set timer now                                                    */
   if (dss_cluster_timer_reco.dsc_timer_ele.vpc_chain_2) return;  /* timer set */
   dss_cluster_timer_reco.dsc_timer_ele.ilcwaitmsec = adss_cluster_main->imc_time_retry_conn * 1000;  /* wait in milliseconds */
   m_time_set( &dss_cluster_timer_reco.dsc_timer_ele, FALSE );  /* set timer now */
   return;                                  /* all done                */

   pconn_20:                                /* connect to next remote WSP */
   adsl_clrem_w1 = adsl_clrem_w1->adsc_next;  /* get next in chain     */
   if (adsl_clrem_w1) goto pconn_00;        /* start next connect      */

   pconn_40:                                /* all WSPs are connected  */
   if (dss_cluster_timer_reco.dsc_timer_ele.vpc_chain_2) {  /* timer set */
     m_time_rel( &dss_cluster_timer_reco.dsc_timer_ele );  /* release timer */
   }
   return;                                  /* all done                */
} /* end m_check_reco_cluster()                                        */
