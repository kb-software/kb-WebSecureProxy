//#define DEBUG_141102_01                     /* crash Radius            */
//#define TRACEHL1
#define MS_CHAP_V2_ACCESS
#ifdef DEBUG_141102_01                      /* crash Radius            */
#define TRY_PROBLEM_TIMER_141028 500
#endif
#ifdef DO_TO
- 23.09.15 KB -
https://tools.ietf.org/html/rfc2865#page-41
5.18.  Reply-Message


   Description

      This Attribute indicates text which MAY be displayed to the user.

      When used in an Access-Accept, it is the success message.

      When used in an Access-Reject, it is the failure message.  It MAY
      indicate a dialog message to prompt the user before another
      Access-Request attempt.

      When used in an Access-Challenge, it MAY indicate a dialog message
      to prompt the user for a response.

      Multiple Reply-Message's MAY be included and if any are displayed,
      they MUST be displayed in the same order as they appear in the
      packet.

   A summary of the Reply-Message Attribute format is shown below.  The
   fields are transmitted from left to right.

    0                   1                   2
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
   |     Type      |    Length     |  Text ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

   Type

      18 for Reply-Message.

   Length

      >= 3

   Text

      The Text field is one or more octets, and its contents are
      implementation dependent.  It is intended to be human readable,
      and MUST NOT affect operation of the protocol.  It is recommended
      that the message contain UTF-8 encoded 10646 [7] characters.
-
display in error message to console
? pass to aux-call ?
#endif
//#define DEBUG_140329 10
//#define HL_NO_RANDOM
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xs-gw-radius-01                                     |*/
/*| -------------                                                     |*/
/*|  Subroutine which manages Radius for gateways                     |*/
/*|  KB 28.12.11                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2017                                   |*/
/*|                                                                   |*/
/*| EXPECTED INPUT:                                                   |*/
/*| ---------------                                                   |*/
/*|                                                                   |*/
/*| EXPECTED OUTPUT:                                                  |*/
/*| ----------------                                                  |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/**
   RFC 2865 Remote Authentication Dial In User Service (RADIUS)
   RFC 2759 Microsoft PPP CHAP Extensions, Version 2
   RFC 2548 Microsoft Vendor-specific RADIUS Attributes
   RFC 2869 RADIUS Support For Extensible Authentication Protocol (EAP)
*/

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#ifdef TRACEHL1
#define TRACEHL_CO_OUT
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

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#ifdef XYZ2
#include <conio.h>
#endif
#include <time.h>
#ifdef HL_UNIX
#include <fcntl.h>
#include <poll.h>
#ifdef B150815
#ifdef HL_LINUX
#include <pth.h>
#endif
#endif
#include <sys/socket.h>
//#include <sys/stropts.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
//#include <xti.h>
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
#include <linux/unistd.h>
#include <sys/time.h>
//#include <LiS/sys/xti_ip.h>
#endif
#include <limits.h>
#include <dlfcn.h>
#include "hob-unix01.h"
#include "hob-xslhcla1.hpp"
#include "hob-thread.hpp"
#endif
#ifndef HL_UNIX
#include <wchar.h>
#include <winsock2.h>
//#ifdef HL_IPV6
#include <ws2tcpip.h>
//#include <wspiapi.h>
//#endif
#include <hob-wtspo1.h>
#endif
#define EXT_BASE64
#include <hob-tab-mime-base64.h>
#include <hob-xslunic1.h>
#ifndef HL_UNIX
#include <hob-thread.hpp>
#include <iswcord1.h>
#endif
#ifdef XYZ1
//#include "hob-hlwspat2.h"
#include <hob-wspsu1.h>
#include <hob-avl03.h>
#endif
#include <hob-encry-1.h>

#define DOMNode void

#define DEF_HL_INCL_DOM
#include "hob-xsclib01.h"

#include <hob-netw-01.h>
#include "hob-wsppriv.h"                    /* privileges              */
#define HOB_CONTR_TIMER
#include <hob-xslcontr.h>                   /* HOB Control             */
//#define INCL_GW_ALL
#define D_INCL_AUX_UDP
#define NOT_INCLUDED_CLIB
#include "hob-xbipgw08-1.h"
#include "hob-xbipgw08-2.h"

#define NO_MEMORY_RADIUS_NETW  16
#define MAX_LEN_RADIUS_PACKET  (8 * 1024)
//#define LEN_RADIUS_MSG_AUTH    16           /* length Radius MD5 message authenticator */

#define DEF_RADIUS_AVP_TYPE_EAP 0X4F
#define DEF_RADIUS_AVP_TYPE_MSG_AUTH 0X50
#ifndef B171207
#define DEF_RADIUS_AVP_TYPE_REPLY_MESSAGE 0X12
#endif

#define D_AVSMS_CHCH           11           /* attribute vendor-specific MS MS-CHAP-Challenge */
#define LEN_AVSMS_CHCH         16           /* attribute vendor-specific MS MS-CHAP-Challenge */
#define D_AVSMS_CHRE           25           /* attribute vendor-specific MS MS-CHAP-Response */
#define LEN_AVSMS_CHRE         (2 + 16 + 8 + 24)  /* attribute vendor-specific MS MS-CHAP-Response */
#define LEN_AVSMS_NEW_PWD      512          /* attribute vendor-specific MS password UTF-16 bytes */

#ifdef XYZ1
#define IP_socket socket
#define IP_bind bind
#define IP_listen listen
#define IP_htons htons
#define IP_getnameinfo getnameinfo

//#define DEF_CLUSTER_NO_BL    2              /* number of blocks for flow control */
//#define DEF_CLUSTER_INIT_W   20             /* wait time when init received, in seconds */
#define D_PORT_SIP             5060         /* port of SIP             */
#define DEF_SEND_IOV           32           /* for WSASendTo() or sendmsg() */
#define MAX_LEN_SIP_IDENT      128          /* maximum length SIP ident */
#define DEF_RETRY_START_SIP    120          /* seconds retry start SIP */
#define WSP_HPUPD_MSG_0_CH     0X3F         /* function / subchannel ? */
#define WSP_HPUPD_MSG_1_CH     0X21         /* function / subchannel ! */
#ifdef XYZ1
#ifndef HL_UNIX
#define DEF_MAX_MULT_TH (WSA_MAXIMUM_WAIT_EVENTS - 1)  /* maximum in t */
#else
#define DEF_MAX_MULT_TH        128          /* maximum in poll()       */
#endif
#endif
#endif

#define CHAR_CR                0X0D         /* carriage-return         */
#define CHAR_LF                0X0A         /* line-feed               */

#ifndef HL_UNIX
#define D_TCP_ERROR WSAGetLastError()
#define D_TCP_CLOSE closesocket
#else
#define D_TCP_ERROR errno
#define D_TCP_CLOSE close
#endif

#ifndef HL_UNIX
//typedef unsigned int UNSIG_MED;
typedef int socklen_t;
#else
#define UNSIG_MED unsigned int
#endif

#ifndef DSD_CONN_G
#ifndef HL_UNIX
#define DSD_CONN_G class clconn1
#else
#define DSD_CONN_G struct dsd_conn1
#endif
#endif

#define m_ip_socket socket
#define m_ip_closesocket closesocket
#define m_ip_bind bind
#define m_ip_htons htons
#define m_ip_getsockname getsockname
#define m_ip_wsawaitm WSAWaitForMultipleEvents
#define m_ip_wsa_enum_net_events WSAEnumNetworkEvents
#define m_ip_wsaevent WSACreateEvent
#define m_ip_recvfrom recvfrom
#define m_ip_sendto sendto
#define m_ip_wsaglerr WSAGetLastError

/* loaded configurations that are in use now                           */
extern "C" struct dsd_loconf_1 *adsg_loconf_1_inuse;

extern "C" int img_wsp_trace_core_flags1;   /* WSP trace core flags    */

extern class dsd_hcla_critsect_1 dsg_global_lock;  /* global lock      */

/*+-------------------------------------------------------------------+*/
/*| Internal used structures.                                         |*/
/*+-------------------------------------------------------------------+*/

struct dsd_radius_netw_1 {                  /* radius networking       */
   struct dsd_radius_netw_1 *adsc_next;     /* for chaining            */
   struct dsd_radius_entry *adsc_re_chain;  /* chain radius entry / single radius server */
   struct dsd_udp_multiw_1 dsc_udp_multiw_1;  /* structure for multiple wait */
};

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

static BOOL m_radius_send( struct dsd_radius_control_1 * );
static void m_cb_radius_recv( struct dsd_udp_multiw_1 *, struct dsd_sdh_control_1 * );
static void m_timeout_radius( struct dsd_timer_ele * );
static void m_radius_queued( struct dsd_radius_group * );

#ifndef HL_UNIX
#ifdef TRACEHL1
#define D_CONSOLE_OUT
#endif
#ifdef TRY_PROBLEM_TIMER_141028
#define D_CONSOLE_OUT
#endif
#ifdef D_CONSOLE_OUT
static void m_console_out( char *achp_buff, int implength );
static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
#endif
#endif

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

static struct dsd_radius_netw_1 *adss_rn1_anchor = NULL;  /* radius networking */

static const unsigned char ucrs_send_avp_ms_01[ 6 ] = {
   0X1A, 0X00,
   0X00, 0X00, 0X01, 0X37
};

#ifdef MS_CHAP_V2_ACCESS
/* http://msdn.microsoft.com/en-us/library/cc243442(v=prot.10).aspx    */
/* 0x00000002 Remote Access Service (RAS) server (VPN or dial-in)      */
static const unsigned char ucrs_send_avp_ms_02[ 12 ] = {
   0X1A, 0X0C,
   0X00, 0X00, 0X01, 0X37,
   0X2F, 0X06,
   0X00, 0X00, 0X00, 0X02
};
#endif

static unsigned char ucrs_vendor_s_ms_numbers[ 3 ] = {
   'E', 'R', 'V'
};

static const char byrs_sixteen_zeros[ 16 ] = {
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00
};

/*+-------------------------------------------------------------------+*/
/*| Procedure division.                                               |*/
/*+-------------------------------------------------------------------+*/

/**
* open a Radius server connection
*/
extern "C" BOOL m_radius_server_open( char *achp_work, int imp_len_work,
                                      amd_msgprog amp_msgproc, void * vpp_userfld,
                                      struct dsd_radius_entry *adsp_re ) {
   int        iml1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
   struct dsd_radius_netw_1 *adsl_rn1_w1;   /* radius networking       */
   struct dsd_radius_netw_1 *adsl_rn1_w2;   /* radius networking       */
   struct dsd_radius_netw_1 *adsl_rn1_w3;   /* radius networking       */

   adsl_rn1_w1 = adss_rn1_anchor;           /* get anchor              */
   adsl_rn1_w2 = NULL;                      /* clear unused entry      */
   while (adsl_rn1_w1) {                    /* loop over defined entries */
     if (adsl_rn1_w1->adsc_re_chain == NULL) {  /* unused entry        */
       if (adsl_rn1_w2 == NULL) adsl_rn1_w2 = adsl_rn1_w1;  /* save unused entry */
     } else if (!memcmp( &adsp_re->dsc_udp_param_1.dsc_soa_bind,
                         &adsl_rn1_w1->adsc_re_chain->dsc_udp_param_1.dsc_soa_bind,
                         sizeof(struct sockaddr_storage) )) {
       /* we can use the same socket                                   */
       adsp_re->adsc_udp_multiw_1 = &adsl_rn1_w1->dsc_udp_multiw_1;  /* structure for multiple wait */
       adsp_re->adsc_re_chain = adsl_rn1_w1->adsc_re_chain;  /* get old chain of networking */
       adsl_rn1_w1->adsc_re_chain = adsp_re;  /* set new chain of networking */
       return TRUE;                         /* all done                */
     }
     adsl_rn1_w1 = adsl_rn1_w1->adsc_next;  /* get next in chain       */
   }
   /* we need to create a new entry                                    */
   if (adsl_rn1_w2 == NULL) {               /* no unused entry         */
     adsl_rn1_w2 = (struct dsd_radius_netw_1 *) malloc( NO_MEMORY_RADIUS_NETW * sizeof(struct dsd_radius_netw_1) );
     memset( adsl_rn1_w2, 0, NO_MEMORY_RADIUS_NETW * sizeof(struct dsd_radius_netw_1) );
     iml1 = NO_MEMORY_RADIUS_NETW - 1;      /* entries to fill         */
     adsl_rn1_w1 = adsl_rn1_w2;             /* get first entry         */
     while (iml1 > 0) {                     /* prepare all entries     */
       adsl_rn1_w1->adsc_next = adsl_rn1_w1 + 1;  /* set chain         */
       adsl_rn1_w1++;                       /* next structure          */
       iml1--;                              /* decrement index         */
     }
     adsl_rn1_w1->adsc_next = adss_rn1_anchor;  /* get anchor / old chain */
     adss_rn1_anchor = adsl_rn1_w2;         /* set anchor / new chain  */
   }
   adsl_rn1_w2->dsc_udp_multiw_1.imc_socket = socket( adsp_re->dsc_udp_param_1.dsc_soa_bind.ss_family, SOCK_DGRAM, 0 );
   if (adsl_rn1_w2->dsc_udp_multiw_1.imc_socket < 0) {  /* error occured */
#ifndef HL_UNIX
     _snprintf( achp_work, imp_len_work, "m_radius_server_open() l%05d socket() Error %d.",
                __LINE__, D_TCP_ERROR );
#else
     snprintf( achp_work, imp_len_work, "m_radius_server_open() l%05d socket() Error %d.",
               __LINE__, D_TCP_ERROR );
#endif
     amp_msgproc( vpp_userfld, achp_work, 0 );
     return FALSE;                          /* all done                */
   }
   iml_rc = bind( adsl_rn1_w2->dsc_udp_multiw_1.imc_socket,
                  (struct sockaddr *) &adsp_re->dsc_udp_param_1.dsc_soa_bind, adsp_re->dsc_udp_param_1.imc_len_soa_bind );
   if (iml_rc) {                            /* error occured           */
#ifndef HL_UNIX
     _snprintf( achp_work, imp_len_work, "m_radius_server_open() l%05d bind() Error %d %d.",
                __LINE__, iml_rc, D_TCP_ERROR );
#else
     snprintf( achp_work, imp_len_work, "m_radius_server_open() l%05d bind() Error %d %d.",
               __LINE__, iml_rc, D_TCP_ERROR );
#endif
     amp_msgproc( vpp_userfld, achp_work, 1 );
     D_TCP_CLOSE( adsl_rn1_w2->dsc_udp_multiw_1.imc_socket );
     return FALSE;                          /* all done                */
   }
#ifndef HL_UNIX
   adsl_rn1_w2->dsc_udp_multiw_1.dsc_event = WSACreateEvent();  /* create event for recv */
   if (adsl_rn1_w2->dsc_udp_multiw_1.dsc_event == WSA_INVALID_EVENT) {  /* error occured */
//   m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-%05d-W m_aux_udp_requ_1() 0X%p WSAEvent Return Code %d.",
//                   __LINE__, ADSL_UDP_MULTIW_1_G, m_ip_wsaglerr() );
     _snprintf( achp_work, imp_len_work, "m_radius_server_open() l%05d WSACreateEvent() Error %d.",
                __LINE__, D_TCP_ERROR );
     amp_msgproc( vpp_userfld, achp_work, 2 );
     D_TCP_CLOSE( adsl_rn1_w2->dsc_udp_multiw_1.imc_socket );
     return FALSE;                          /* all done                */
   }
   iml_rc = WSAEventSelect( adsl_rn1_w2->dsc_udp_multiw_1.imc_socket,
                            adsl_rn1_w2->dsc_udp_multiw_1.dsc_event,
                            FD_WRITE | FD_READ | FD_CLOSE );
   if (iml_rc) {                            /* error occured           */
//   m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-%05d-W m_aux_udp_requ_1() 0X%p WSAEventSelect Return Code %d/%d.",
//                   __LINE__, ADSL_UDP_MULTIW_1_G, iml_rc, m_ip_wsaglerr() );
     _snprintf( achp_work, imp_len_work, "m_radius_server_open() l%05d WSAEventSelect() Error %d %d.",
                __LINE__, iml_rc, m_ip_wsaglerr() );
     amp_msgproc( vpp_userfld, achp_work, 3 );
     D_TCP_CLOSE( adsl_rn1_w2->dsc_udp_multiw_1.imc_socket );
     WSACloseEvent( adsl_rn1_w2->dsc_udp_multiw_1.dsc_event );
     return FALSE;                          /* all done                */
   }
#endif
#ifdef HL_UNIX
   /* set the UDP socket to non-blocking                               */
   iml1 = fcntl( adsl_rn1_w2->dsc_udp_multiw_1.imc_socket, F_GETFL, 0 );
   iml_rc = fcntl( adsl_rn1_w2->dsc_udp_multiw_1.imc_socket, F_SETFL, iml1 | O_NONBLOCK );
   if (iml_rc) {                            /* error occured           */
     snprintf( achp_work, imp_len_work, "m_radius_server_open() l%05d fcntl() Error %d.",
               __LINE__, D_TCP_ERROR );
     amp_msgproc( vpp_userfld, achp_work, 4 );
     D_TCP_CLOSE( adsl_rn1_w2->dsc_udp_multiw_1.imc_socket );
     return FALSE;                          /* all done                */
   }
#endif
   adsl_rn1_w2->dsc_udp_multiw_1.amc_udp_recv_compl = &m_cb_radius_recv;  /* callback when receive complete */
   adsp_re->adsc_udp_multiw_1 = &adsl_rn1_w2->dsc_udp_multiw_1;  /* structure for multiple wait */
   adsl_rn1_w2->adsc_re_chain = adsp_re;    /* set new chain of networking */
   m_start_udp_recv( &adsl_rn1_w2->dsc_udp_multiw_1 );
   return TRUE;                             /* return success          */
} /* end m_radius_server_open()                                        */

/** called at starting the radius request or multiple requests         */
extern "C" void m_radius_init( struct dsd_radius_control_1 *adsp_rctrl1,
                               struct dsd_radius_group *adsp_radius_group,
                               void * ap_conn1,  /* address connection */
                               struct sockaddr *adsp_soa_client,  /* sockaddr of client */
                               amd_radius_query_compl amp_radius_query_compl ) {  /* callback when radius request complete */
   struct dsd_radius_entry *adsl_radius_entry_act;  /* active radius entry / single radius server */

#ifdef DEBUG_141102_01                      /* crash Radius            */
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_radius_init() HL_THRID=%d adsp_rctrl1=%p ->dsc_timer.vpc_chain_2=%p.",
                   __LINE__, HL_THRID, adsp_rctrl1, adsp_rctrl1->dsc_timer.vpc_chain_2 );
#endif
   memset( adsp_rctrl1, 0, sizeof(struct dsd_radius_control_1) );
   adsp_rctrl1->adsc_radius_group = adsp_radius_group;
   adsl_radius_entry_act = adsp_radius_group->adsc_radius_entry;  /* chain radius entry / single radius server */
   do {                                     /* loop to count radius-servers */
     adsp_rctrl1->imc_no_radius_server++;   /* number of radius-server */
     adsl_radius_entry_act = adsl_radius_entry_act->adsc_next;  /* get next in chain */
   } while (adsl_radius_entry_act);
   adsp_rctrl1->ac_conn1 = ap_conn1;        /* address connection      */
   adsp_rctrl1->adsc_soa_client = adsp_soa_client;  /* sockaddr of client */
   adsp_rctrl1->amc_radius_query_compl = amp_radius_query_compl;  /* callback when radius request complete */
} /* end m_radius_init()                                               */

/** process Radius request, check which Radius server or queue request */
extern "C" BOOL m_radius_request( struct dsd_radius_control_1 *adsp_rctrl1,
                                  struct dsd_hl_aux_radius_1 *adsp_rreq ) {
   BOOL       bol1;                         /* working-variable        */
   int        iml_count;                    /* count entries           */
   int        iml_locked;                   /* count locked entries    */
   int        iml_time;                     /* current time            */
   int        iml1;                         /* working variable        */
   HL_LONGLONG ill_mask;                    /* mask of entry           */
   HL_LONGLONG ill_valid;                   /* mask of valid entries   */
   HL_LONGLONG ill_w1;                      /* mask of entry           */
   struct dsd_radius_group *adsl_radius_group;  /* radius group        */
   struct dsd_radius_entry *adsl_raent_act;  /* active radius entry / single radius server */
   struct dsd_radius_entry *adsl_raent_w1;  /* active radius entry / single radius server */
   struct dsd_radius_control_1 *adsl_rctrl1_w1;  /* working-variable   */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace area          */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_radius_request( %p , %p )",
                   __LINE__, adsp_rctrl1, adsp_rreq );
#endif
   adsp_rreq->iec_radius_resp = ied_rar_invalid;  /* parameter is invalid, request active */
   adsp_rreq->achc_radius_msg_auth = NULL;  /* address message authenticator output */
#ifndef B171207
   adsp_rreq->imc_len_reply_message = 0;    /* length reply message    */
#endif
   adsp_rctrl1->adsc_rreq = adsp_rreq;      /* set active radius request */
   adsl_radius_group = adsp_rctrl1->adsc_radius_group;  /* radius group */
   iml_time = (int) time( NULL );           /* current time            */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_RADIUS) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CRADIUS1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "m_radius_request( rctrl1=%p , rreq=%p )",
                     adsp_rctrl1, adsp_rreq );
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }

   p_req_00:                                /* start select radius server */
   adsl_raent_act = adsp_rctrl1->adsc_radius_entry_act;  /* active radius entry / single radius server */
   if (adsl_raent_act == NULL) {            /* no active radius entry / single radius server */
     goto p_req_08;                         /* begin select radius server */
   }
   if (   (adsl_raent_act->imc_epoch_locked != 0)  /* epoch radius server locked until */
       && (adsl_raent_act->imc_epoch_locked <= iml_time)) {  /* no more locked */
     adsl_raent_act->imc_epoch_locked = 0;  /* unlock radius server    */
   }
   if (adsl_raent_act->imc_epoch_locked != 0) {  /* epoch radius server locked until */
     adsp_rctrl1->adsc_radius_entry_act = NULL;  /* we try all radius servers */
     adsp_rctrl1->ilc_marked = 0;           /* marked radius-servers   */
     goto p_req_08;                         /* begin select radius server */
   }
   if (adsl_raent_act->adsc_rc1_active) {   /* currently active radius control */
     goto p_queue_00;                       /* queue the radius request */
   }
   ill_mask = 0;                            /* mask of entry           */
   goto p_send_00;                          /* send radius packet to selected server */

   p_req_08:                                /* begin select radius server */
   adsl_raent_act = adsl_radius_group->adsc_radius_entry;  /* chain radius entry / single radius server */
   if (adsp_rctrl1->imc_no_radius_server > 1) {  /* number of radius-server */
     goto p_req_20;                         /* check chain             */
   }
   if (   (adsl_raent_act->imc_epoch_locked != 0)  /* epoch radius server locked until */
       && (adsl_raent_act->imc_epoch_locked <= iml_time)) {  /* no more locked */
     adsl_raent_act->imc_epoch_locked = 0;  /* unlock radius server    */
   }
   if (adsl_raent_act->imc_epoch_locked != 0) {  /* epoch radius server locked until */
#ifndef B140329
     adsp_rctrl1->adsc_rreq = NULL;         /* no more active radius request */
#endif
     return FALSE;                          /* cannot send radius packet */
   }
   if (adsl_raent_act->adsc_rc1_active) {   /* currently active radius control */
     goto p_queue_00;                       /* queue the radius request */
   }
   ill_mask = 1;                            /* mask of entry           */
   goto p_send_00;                          /* send radius packet to selected server */

   p_req_20:                                /* check chain             */
   iml_count = 0;                           /* count entries           */
   iml_locked = 0;                          /* count locked entries    */
   ill_mask = 1;                            /* mask of entry           */
   ill_valid = 0;                           /* mask of valid entries   */

   p_req_24:                                /* check radius server     */
   if (   (adsl_raent_act->imc_epoch_locked != 0)  /* epoch radius server locked until */
       && (adsl_raent_act->imc_epoch_locked <= iml_time)) {  /* no more locked */
     adsl_raent_act->imc_epoch_locked = 0;  /* unlock radius server    */
   }
   if (adsl_raent_act->imc_epoch_locked != 0) {  /* epoch radius server locked until */
     iml_locked++;                          /* count locked entries    */
     goto p_req_32;                         /* next radius server      */
   }
   if (adsl_raent_act->adsc_rc1_active) {   /* currently active radius control */
     goto p_req_32;                         /* next radius server      */
   }
   if (ill_mask & adsp_rctrl1->ilc_marked) {  /* marked radius-servers */
     goto p_req_32;                         /* next radius server      */
   }
   ill_valid |= ill_mask;                   /* mask of valid entries   */
   iml_count++;                             /* count entries           */
   adsl_raent_w1 = adsl_raent_act;          /* save current radius server */
   ill_w1 = ill_mask;                       /* mask of entry           */
// if (adsl_raent_act->imc_epoch_locked != 0)             /* epoch radius server locked until */

   p_req_32:                                /* next radius server      */
   adsl_raent_act = adsl_raent_act->adsc_next;  /* get next in chain   */
   if (adsl_raent_act) {                    /* not last one            */
     ill_mask <<= 1;                        /* mask of entry           */
     goto p_req_24;                         /* check radius server     */
   }
   if (iml_locked >= adsp_rctrl1->imc_no_radius_server) {  /* all servers locked */
#ifndef B140329
     adsp_rctrl1->adsc_rreq = NULL;         /* no more active radius request */
#endif
     return FALSE;                          /* cannot send radius packet */
   }
   if (iml_count == 0) {                    /* no radius server free   */
     goto p_queue_00;                       /* queue the radius request */
   }
   if (iml_count == 1) {                    /* only one radius server free */
     adsl_raent_act = adsl_raent_w1;        /* restore saved radius server */
     ill_mask = ill_w1;                     /* mask of entry           */
     goto p_send_00;                        /* send radius packet to selected server */
   }
   iml_count = m_get_random_number( iml_count );
   adsl_raent_act = adsl_radius_group->adsc_radius_entry;  /* chain radius entry / single radius server */
   ill_mask = 1;                            /* mask of entry           */

   p_req_40:                                /* search selected radius server */
   if (ill_mask & ill_valid) {              /* mask of valid entries   */
     if (iml_count <= 0) {                  /* found the selected radius server */
       goto p_send_00;                      /* send radius packet to selected server */
     }
     iml_count--;                           /* decrement entry we search for */
   }
   adsl_raent_act = adsl_raent_act->adsc_next;  /* get next in chain   */
   if (adsl_raent_act == NULL) {            /* was last one            */
// to-do 04.02.12 KB error message - illogic
     m_hlnew_printf( HLOG_WARN1, "HWSPRA030W l%05d radius-group %.*(u8)s search selected radius-server illogic",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1 );
#ifndef B140329
     adsp_rctrl1->adsc_rreq = NULL;         /* no more active radius request */
#endif
     return FALSE;
   }
   ill_mask <<= 1;                          /* mask of entry           */
   goto p_req_40;                           /* search selected radius server */


   p_send_00:                               /* send radius packet to selected server */
   bol1 = FALSE;                            /* no problem              */
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
   if (adsl_raent_act->adsc_rc1_active) {   /* inbetween currently active radius control */
     bol1 = TRUE;                           /* we have a problem       */
   } else {
     adsl_raent_act->adsc_rc1_active = adsp_rctrl1;  /* currently active radius control */
#ifdef DEBUG_141102_01                      /* crash Radius            */
     m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_radius_request() p_send_00: HL_THRID=%d adsp_rctrl1=%p adsl_raent_act=%p adsl_radius_group=%p ->adsc_rctrl1_queued=%p.",
                     __LINE__, HL_THRID, adsp_rctrl1, adsl_raent_act, adsl_radius_group, adsl_radius_group->adsc_rctrl1_queued );
#endif
#ifdef XYZ1
#ifndef B141104
     if (adsp_rctrl1 == adsl_radius_group->adsc_rctrl1_queued) {
       adsl_radius_group->adsc_rctrl1_queued = adsp_rctrl1->adsc_rctrl1_queued;
#ifdef DEBUG_141102_01                      /* crash Radius            */
       m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_radius_request() p_send_00: HL_THRID=%d remove current entry from adsc_rctrl1_queued",
                       __LINE__, HL_THRID );
#endif
     }
#endif
#endif
   }
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
   if (bol1) {                              /* could not set this radius server */
     goto p_req_00;                         /* start select radius server */
   }
   adsp_rctrl1->adsc_radius_entry_act = adsl_raent_act;  /* active radius entry / single radius server */
   adsp_rctrl1->ilc_marked |= ill_mask;     /* marked radius-servers   */
   bol1 = m_radius_send( adsp_rctrl1 );
   if (bol1) return TRUE;                   /* was successful          */
   adsl_raent_act->adsc_rc1_active = NULL;  /* currently active radius control */
   adsp_rctrl1->adsc_radius_entry_act = NULL;  /* active radius entry / single radius server */
   adsp_rctrl1->adsc_rreq = NULL;           /* set active radius request */
   adsp_rctrl1->ilc_marked = 0;             /* marked radius-servers   */
   m_radius_queued( adsl_radius_group );    /* activate queued entries */
   return FALSE;

   p_queue_00:                              /* queue the radius request */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_radius_request( %p , %p ) p_queue_00",
                   __LINE__, adsp_rctrl1, adsp_rreq );
#endif
   adsp_rctrl1->adsc_rctrl1_queued = NULL;  /* radius control queued   */
   bol1 = FALSE;                            /* no problem              */
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
   if (adsp_rctrl1->adsc_radius_entry_act) {  /* active radius entry / single radius server */
     if (   (adsp_rctrl1->adsc_radius_entry_act->imc_epoch_locked == 0)  /* epoch radius server locked until */
         && (adsp_rctrl1->adsc_radius_entry_act->adsc_rc1_active == NULL)) {   /* currently active radius control */
       bol1 = TRUE;                         /* we have a problem       */
     }
   } else {
     adsl_raent_act = adsl_radius_group->adsc_radius_entry;  /* chain radius entry / single radius server */
     ill_mask = 1;                          /* mask of entry           */
     do {                                   /* loop over all radius servers */
       if (   (adsl_raent_act->imc_epoch_locked == 0)  /* epoch radius server locked until */
           && (adsl_raent_act->adsc_rc1_active == NULL)  /* currently active radius control */
           && ((ill_mask & adsp_rctrl1->ilc_marked) == 0)) {  /* marked radius-servers */
         bol1 = TRUE;                       /* we have a problem       */
         break;
       }
       adsl_raent_act = adsl_raent_act->adsc_next;  /* get next in chain */
       ill_mask <<= 1;                      /* mask of entry           */
     } while (adsl_raent_act);
   }
   if (bol1 == FALSE) {                     /* we queue the radius request */
     if (adsl_radius_group->adsc_rctrl1_queued == NULL) {  /* no radius control queued */
       adsl_radius_group->adsc_rctrl1_queued = adsp_rctrl1;  /* radius control queued */
     } else {
       adsl_rctrl1_w1 = adsl_radius_group->adsc_rctrl1_queued;  /* radius control queued */
#ifdef TRACEHL1
       if (adsl_rctrl1_w1 == adsl_rctrl1_w1->adsc_rctrl1_queued) {
         m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_radius_request( %p , %p ) adsl_rctrl1_w1=%p in circle",
                         __LINE__, adsp_rctrl1, adsp_rreq, adsl_rctrl1_w1 );
       }
#endif
       while (adsl_rctrl1_w1->adsc_rctrl1_queued) adsl_rctrl1_w1 = adsl_rctrl1_w1->adsc_rctrl1_queued;
       adsl_rctrl1_w1->adsc_rctrl1_queued = adsp_rctrl1;  /* radius control queued */
     }
   }
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
   if (bol1) {                              /* could not queue this radius request */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_radius_request( %p , %p ) adsl_rctrl1_w1=%p could not be queued ->adsc_radius_entry_act=%p.",
                     __LINE__, adsp_rctrl1, adsp_rreq, adsp_rctrl1->adsc_radius_entry_act );
#endif
     goto p_req_00;                         /* start select radius server */
   }
   return TRUE;
} /* end m_radius_request()                                            */

/** send Radius request UDP packet                                     */
static BOOL m_radius_send( struct dsd_radius_control_1 *adsp_rctrl1 ) {
   int        iml1, iml2, iml3, iml4, iml5;  /* working variables      */
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   int        iml_pos_mchv2_chch;           /* position of attribute vendor-specific MS MS-CHAP-Challenge */
   int        iml_pos_mchv2_chre;           /* position of attribute vendor-specific MS MS-CHAP-Response */
   int        iml_pos_md5_hash;             /* position MD5 hash       */
   int        iml_len_unicode_new_password;  /* length new password    */
   HL_LONGLONG ill1;                        /* working variable        */
   char       *achl_md5_hash;               /* position array hash     */
   char       *achl_w1, *achl_w2;           /* working variables       */
   struct dsd_hl_aux_radius_1 *adsl_rreq;   /* radius request          */
   struct dsd_radius_entry *adsl_radius_entry_act;  /* active radius entry / single radius server */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace area          */
#ifdef XYZ1
   char       byrl_hmac_1[ 64 ];            /* for HMAC                */
   char       byrl_hmac_2[ 64 ];            /* for HMAC                */
#endif
   int        imrl_md5_array[ MD5_ARRAY_SIZE ];  /* for MD5            */
   int        imrl_md4_array[ MD4_ARRAY_SIZE ];  /* for MD4            */
   int        imrl_sha1[ SHA_ARRAY_SIZE ];  /* for hash                */
   unsigned int umrl_des_subkeytab[ DES_SUBKEY_ARRAY_SIZE ];  /* for DES */
   char       chrl_work1[ 21 ];             /* work area MD5 / MD4 + nulls */
   char       chrl_work2[ SHA_DIGEST_LEN ];  /* work area SHA-1        */
   char       chrl_old_pwd_hash[ MD4_DIGEST_LEN ];  /* old password hash */
   unsigned char ucrl_work3[ 8 ];           /* work area DES           */
   char       chrl_pwd[ LEN_AVSMS_NEW_PWD + 4 ];  /* work area password */
   char       chrl_radius_p[ MAX_LEN_RADIUS_PACKET ];

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_radius_send( %p )",
                   __LINE__, adsp_rctrl1 );
#endif
   adsl_rreq = adsp_rctrl1->adsc_rreq;      /* get active radius request */
   adsl_radius_entry_act = adsp_rctrl1->adsc_radius_entry_act;  /* active radius entry / single radius server */

   /* make the request                                                 */
   *((int *) &adsp_rctrl1->chrc_req_auth[0]) = (int) m_get_time();  /* get time */
   for ( iml1 = 4; iml1 < DEF_RADIUS_LEN_REQ_AUTH; iml1 += 2 ) {
     *((short int *) &adsp_rctrl1->chrc_req_auth[ iml1 ]) = (short int) m_get_random_number( 0X010000 );
#ifdef HL_NO_RANDOM
     *((short int *) &adsp_rctrl1->chrc_req_auth[ iml1 ]) = 0;
#endif
   }
   chrl_radius_p[0] = 1;                    /* code access request     */
   adsp_rctrl1->chc_identifier = adsl_radius_entry_act->chc_identifier;  /* identifier of query */
   adsl_radius_entry_act->chc_identifier++;  /* increment identifier   */
   chrl_radius_p[1] = adsp_rctrl1->chc_identifier;  /* set identifier  */
   memcpy( &chrl_radius_p[4], adsp_rctrl1->chrc_req_auth, DEF_RADIUS_LEN_REQ_AUTH );
   chrl_radius_p[ 4 + DEF_RADIUS_LEN_REQ_AUTH + 0 ] = (unsigned char) 1;  /* user name */
   iml1 = m_cpy_vx_ucs( &chrl_radius_p[ 4 + DEF_RADIUS_LEN_REQ_AUTH + 2 ],
                        MAX_LEN_RADIUS_PACKET - 4 - DEF_RADIUS_LEN_REQ_AUTH - 2,
                        adsp_rctrl1->adsc_radius_group->iec_chs,  /* define character set */
                        &adsl_rreq->dsc_ucs_userid );  /* userid       */
   if (iml1 <= 0) goto p_inv_req_00;        /* invalid request         */
#ifdef B140326
   if (iml1 >= (256 - 2)) goto p_inv_req_00;  /* invalid request       */
#endif
   if (iml1 >= (256 - 2)) {                 /* userid too long         */
     m_hlnew_printf( HLOG_WARN1, "HWSPRA040W l%05d radius-server %.*(u8)s userid too long",
                     __LINE__,
                     adsl_radius_entry_act->imc_len_name, adsl_radius_entry_act + 1 );
     goto p_inv_req_00;                     /* invalid request         */
   }
   chrl_radius_p[ 4 + DEF_RADIUS_LEN_REQ_AUTH + 1 ] = (unsigned char) (2 + iml1);  /* length user name */
   iml1 += 4 + DEF_RADIUS_LEN_REQ_AUTH + 2;  /* current position       */
   if (adsl_rreq->boc_radius_eap) {         /* Radius EAP message      */
     goto p_make_req_60;                    /* fields have been set    */
   }
   if (adsp_rctrl1->adsc_radius_group->imc_options & DEF_RADIUS_GROUP_OPTION_MS_CHAP_V2) {
     goto p_make_req_20;                    /* MS-CHAP-V2              */
   }
   iml2 = 0;                                /* default length of password */
   if (adsl_rreq->dsc_ucs_password.imc_len_str != 0) {
     iml2 = m_cpy_vx_ucs( &chrl_radius_p[ iml1 + 2 ],
                          MAX_LEN_RADIUS_PACKET - iml1 - 2,
                          adsp_rctrl1->adsc_radius_group->iec_chs,  /* define character set */
                          &adsl_rreq->dsc_ucs_password );  /* password   */
     if (iml2 <= 0) goto p_inv_req_00;      /* invalid request         */
   }
   iml3 = (iml2 + 16 - 1) & (0 - 16);       /* round up to multiple of 16 */
   if (iml3 <= 0) iml3 = 16;                /* minimum length          */
#ifdef B140326
   if (iml3 >= (256 - 2)) goto p_inv_req_00;  /* invalid request       */
#endif
   if (iml3 >= (256 - 2)) {                 /* password too long       */
     m_hlnew_printf( HLOG_WARN1, "HWSPRA041W l%05d radius-server %.*(u8)s password too long",
                     __LINE__,
                     adsl_radius_entry_act->imc_len_name, adsl_radius_entry_act + 1 );
     goto p_inv_req_00;                     /* invalid request         */
   }
   if ((iml1 + 2 + iml3) > MAX_LEN_RADIUS_PACKET) goto p_inv_req_00;  /* invalid request */
   if (iml2 < iml3) {                       /* fill with zeroes        */
     memset( &chrl_radius_p[ iml1 + 2 + iml2 ], 0, iml3 - iml2 );  /* clear bytes */
   }
   achl_md5_hash = adsp_rctrl1->chrc_req_auth;  /* array hash          */
   iml_pos_md5_hash = 0;                    /* position MD5 hash       */
   iml2 = iml1 + 2;                         /* start XOR here          */
   chrl_radius_p[ iml1 + 0 ] = (unsigned char) 2;  /* password         */
   chrl_radius_p[ iml1 + 1 ] = (unsigned char) (2 + iml3);  /* length password */
   iml1 += 2 + iml3;                        /* after password          */
   do {                                     /* loop to encrypt the password */
//#ifdef WORK051113_MD5
     MD5_Init( imrl_md5_array );
     MD5_Update( imrl_md5_array,
                 adsl_radius_entry_act->achc_shasec,  /* address shared secret */
                 0,
                 adsl_radius_entry_act->imc_len_shasec );  /* length of shared secret */
     MD5_Update( imrl_md5_array, achl_md5_hash + iml_pos_md5_hash, 0, 16 );
     MD5_Final( imrl_md5_array, chrl_work1, 0 );
//#endif
     iml3 = 16;                             /* length one part         */
     do {
       iml3--;
       chrl_radius_p[ iml2 + iml3 ] ^= chrl_work1[ iml3 ];
     } while (iml3 > 0);
     achl_md5_hash = chrl_radius_p;         /* array hash              */
     iml_pos_md5_hash = iml2;               /* position MD5 hash       */
     iml2 += 16;
   } while (iml2 < iml1);
   goto p_make_req_60;                      /* password has been set   */

   p_make_req_20:                           /* MS-CHAP-V2              */
// to-do 10.01.12 KB check length
#ifdef MS_CHAP_V2_ACCESS
   if ((iml1 + sizeof(ucrs_send_avp_ms_02)) > MAX_LEN_RADIUS_PACKET) goto p_inv_req_00;  /* invalid request */
   memcpy( &chrl_radius_p[ iml1 ], ucrs_send_avp_ms_02, sizeof(ucrs_send_avp_ms_02) );
   iml1 += sizeof(ucrs_send_avp_ms_02);
#endif
   if (adsl_rreq->dsc_ucs_password.imc_len_str == 0) {  /* no password, only attributes */
     goto p_make_req_60;                    /* password has been set   */
   }
   /* MS-CHAP-Challenge                                                */
   if ((iml1 + (sizeof(ucrs_send_avp_ms_01) + 2 + LEN_AVSMS_CHCH)) > MAX_LEN_RADIUS_PACKET) goto p_inv_req_00;  /* invalid request */
   memcpy( &chrl_radius_p[ iml1 ], ucrs_send_avp_ms_01, sizeof(ucrs_send_avp_ms_01) );
   chrl_radius_p[ iml1 + 1 ] = (unsigned char) (sizeof(ucrs_send_avp_ms_01) + 2 + LEN_AVSMS_CHCH);  /* set length attribute */
   chrl_radius_p[ iml1 + sizeof(ucrs_send_avp_ms_01) + 0 ] = (unsigned char) D_AVSMS_CHCH;  /* attribute vendor-specific MS MS-CHAP-Challenge */
   chrl_radius_p[ iml1 + sizeof(ucrs_send_avp_ms_01) + 1 ] = (unsigned char) (2 + LEN_AVSMS_CHCH);  /* attribute vendor-specific MS MS-CHAP-Challenge */
   iml_pos_mchv2_chch = iml2 = iml1 + sizeof(ucrs_send_avp_ms_01) + 2;  /* position of attribute vendor-specific MS MS-CHAP-Challenge */
   iml1 = iml_pos_mchv2_chch + LEN_AVSMS_CHCH;  /* end of challenge    */
   do {                                     /* loop to generate random */
#ifndef HL_NO_RANDOM
     chrl_radius_p[ iml2++ ] = (unsigned char) m_get_random_number( 0X0100 );
#else
     chrl_radius_p[ iml2++ ] = 0;
#endif
   } while (iml2 < iml1);
   if (adsl_rreq->dsc_ucs_new_password.imc_len_str != 0) {  /* length set */
     goto p_make_req_40;                    /* MS-CHAP-V2 with change password */
   }
// to-do 10.01.12 KB check length
   if ((iml1 + (sizeof(ucrs_send_avp_ms_01) + 2 + LEN_AVSMS_CHRE)) > MAX_LEN_RADIUS_PACKET) goto p_inv_req_00;  /* invalid request */
   /* MS-CHAP-Response                                                 */
   memcpy( &chrl_radius_p[ iml1 ], ucrs_send_avp_ms_01, sizeof(ucrs_send_avp_ms_01) );
   chrl_radius_p[ iml1 + 1 ] = (unsigned char) (sizeof(ucrs_send_avp_ms_01) + 2 + LEN_AVSMS_CHRE);  /* attribute vendor-specific MS MS-CHAP-Response */
   chrl_radius_p[ iml1 + sizeof(ucrs_send_avp_ms_01) + 0 ] = (unsigned char) D_AVSMS_CHRE;  /* attribute vendor-specific MS MS-CHAP-Response */
   chrl_radius_p[ iml1 + sizeof(ucrs_send_avp_ms_01) + 1 ] = (unsigned char) (2 + LEN_AVSMS_CHRE);  /* attribute vendor-specific MS MS-CHAP-Response */
   chrl_radius_p[ iml1 + sizeof(ucrs_send_avp_ms_01) + 2 ] = 0;
   chrl_radius_p[ iml1 + sizeof(ucrs_send_avp_ms_01) + 3 ] = 0;
   iml_pos_mchv2_chre = iml1 + sizeof(ucrs_send_avp_ms_01) + 2;  /* position of attribute vendor-specific MS MS-CHAP-Response */
   iml2 = iml_pos_mchv2_chre + 2;           /* start random here       */
   iml3 = iml2 + 16;                        /* end of random           */
   do {                                     /* loop to generate random */
#ifndef HL_NO_RANDOM
     chrl_radius_p[ iml2++ ] = (unsigned char) m_get_random_number( 0X0100 );
#else
     chrl_radius_p[ iml2++ ] = 0;
#endif
   } while (iml2 < iml3);
   memset( &chrl_radius_p[ iml2 ], 0, 8 );  /* clear bytes             */
   /* generate ChallengeHash                                           */
   SHA1_Init( imrl_sha1 );
   SHA1_Update( imrl_sha1, &chrl_radius_p[ iml_pos_mchv2_chre + 2 ], 0, 16 );
   SHA1_Update( imrl_sha1, &chrl_radius_p[ iml_pos_mchv2_chch ], 0, LEN_AVSMS_CHCH );
   SHA1_Update( imrl_sha1, &chrl_radius_p[ 4 + DEF_RADIUS_LEN_REQ_AUTH + 2 ], 0, (unsigned char) chrl_radius_p[ 4 + DEF_RADIUS_LEN_REQ_AUTH + 1 ] - 2 );
   SHA1_Final( imrl_sha1, chrl_work2, 0 );
#ifdef TRACEHL1
   m_console_out( chrl_work2, SHA_DIGEST_LEN );
#endif
   /* generate NtPasswordHash                                          */
   iml2 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsl_rreq->dsc_ucs_password )  /* password    */
            * sizeof(HL_WCHAR);
#ifdef B120130
   if (iml2 > sizeof(chrl_pwd)) {           /* password too long       */
     goto p_inv_req_00;                     /* invalid request         */
   }
#endif
#ifndef B120130
   if (iml2 > LEN_AVSMS_NEW_PWD) {          /* password too long       */
     goto p_inv_req_00;                     /* invalid request         */
   }
#endif
   m_cpy_vx_ucs( chrl_pwd,
                 sizeof(chrl_pwd) / sizeof(HL_WCHAR),
                 ied_chs_le_utf_16,         /* Unicode UTF-16 little endian */
                 &adsl_rreq->dsc_ucs_password );  /* password          */
   MD4_Init( imrl_md4_array );
   MD4_Update( imrl_md4_array, chrl_pwd, 0, iml2 );
   MD4_Final( imrl_md4_array, chrl_work1, 0 );
#ifdef TRACEHL1
   m_console_out( chrl_work1, MD4_DIGEST_LEN );
#endif
   memset( chrl_work1 + MD4_DIGEST_LEN, 0, sizeof(chrl_work1) - MD4_DIGEST_LEN );
   /* do DesEncrypt                                                    */
   iml2 = 3;
// ill1 = 0;                                /* for compiler only       */
   iml3 = 0;                                /* index in chrl_work1 = ZPasswordHash */
   do {
     iml4 = 7;
     do {
       ill1 <<= 8;
       ill1 |= (unsigned char) chrl_work1[ iml3++ ];
       iml4--;                              /* decrement index         */
     } while (iml4 > 0);
     iml4 = 8;
     ill1 <<= 1;                            /* we need also last bit   */
     do {
       iml4--;                              /* decrement index         */
       ucrl_work3[ iml4 ] = ill1 & 0XFE;
       ill1 >>= 7;
     } while (iml4 > 0);
     GenDESSubKeys( ucrl_work3, umrl_des_subkeytab );
     DES_ecb_encrypt_decrypt( (unsigned char *) chrl_work2,
                              (unsigned char *) &chrl_radius_p[ iml_pos_mchv2_chre + 2 + 16 + 8 + (3 - iml2) * 8 ],
                              umrl_des_subkeytab,
                              1,
                              DES_ENCRYPT );
     iml2--;                            /* decrement index         */
   } while (iml2 > 0);
#ifdef TRACEHL1
   m_console_out( &chrl_radius_p[ iml_pos_mchv2_chre + 2 + 16 + 8 ], 24 );
#endif
   iml1 += sizeof(ucrs_send_avp_ms_01) + 2 + LEN_AVSMS_CHRE;  /* attribute vendor-specific MS MS-CHAP-Response */
   goto p_make_req_60;                      /* password has been set   */

   p_make_req_40:                           /* MS-CHAP-V2 with change password */
// to-do 29.01.12 KB check length
   if ((iml1 + (76 + 255 + 255 + 42)) > MAX_LEN_RADIUS_PACKET) goto p_inv_req_00;  /* invalid request */
   /* MD4 hash old password                                            */
   iml2 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsl_rreq->dsc_ucs_password )  /* password    */
            * sizeof(HL_WCHAR);
#ifdef B120130
   if (iml2 > sizeof(chrl_pwd)) {           /* password too long       */
     goto p_inv_req_00;                     /* invalid request         */
   }
#endif
#ifndef B120130
   if (iml2 > LEN_AVSMS_NEW_PWD) {          /* password too long       */
     goto p_inv_req_00;                     /* invalid request         */
   }
#endif
   m_cpy_vx_ucs( chrl_pwd,
                 sizeof(chrl_pwd) / sizeof(HL_WCHAR),
                 ied_chs_le_utf_16,         /* Unicode UTF-16 little endian */
                 &adsl_rreq->dsc_ucs_password );  /* password          */
   MD4_Init( imrl_md4_array );
   MD4_Update( imrl_md4_array, chrl_pwd, 0, iml2 );
   MD4_Final( imrl_md4_array, chrl_old_pwd_hash, 0 );
#ifdef TRACEHL1
   m_console_out( chrl_old_pwd_hash, MD4_DIGEST_LEN );
#endif
   /* MD4 hash new password                                            */
   iml_len_unicode_new_password = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                                                &adsl_rreq->dsc_ucs_new_password )  /* new password */
                                    * sizeof(HL_WCHAR);
#ifdef B120130
   if (iml_len_unicode_new_password > sizeof(chrl_pwd)) {  /* new password too long */
     goto p_inv_req_00;                     /* invalid request         */
   }
   m_cpy_vx_ucs( chrl_pwd,
                 sizeof(chrl_pwd) / sizeof(HL_WCHAR),
                 ied_chs_le_utf_16,         /* Unicode UTF-16 little endian */
                 adsl_rreq->adsc_ucs_new_password );  /* new password */
   MD4_Init( imrl_md4_array );
   MD4_Update( imrl_md4_array, chrl_pwd, 0, iml_len_unicode_new_password );
#endif
#ifndef B120130
   if (iml_len_unicode_new_password > LEN_AVSMS_NEW_PWD) {  /* new password too long */
     goto p_inv_req_00;                     /* invalid request         */
   }
   m_cpy_vx_ucs( chrl_pwd + LEN_AVSMS_NEW_PWD - iml_len_unicode_new_password,
                 iml_len_unicode_new_password / sizeof(HL_WCHAR),
                 ied_chs_le_utf_16,         /* Unicode UTF-16 little endian */
                 &adsl_rreq->dsc_ucs_new_password );  /* new password */
   MD4_Init( imrl_md4_array );
   MD4_Update( imrl_md4_array,
               chrl_pwd + LEN_AVSMS_NEW_PWD - iml_len_unicode_new_password,
               0,
               iml_len_unicode_new_password );
#endif
   MD4_Final( imrl_md4_array, chrl_work1, 0 );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T MD4 hash of new password",
                   __LINE__ );
   m_console_out( chrl_work1, MD4_DIGEST_LEN );
#endif
   /* do DesEncrypt                                                    */
   iml2 = 2;
// ill1 = 0;                                /* for compiler only       */
   iml3 = 0;                                /* index in chrl_work1 = ZPasswordHash */
   do {
     iml4 = 7;
     do {
       ill1 <<= 8;
       ill1 |= (unsigned char) chrl_work1[ iml3++ ];
       iml4--;                              /* decrement index         */
     } while (iml4 > 0);
     iml4 = 8;
     ill1 <<= 1;                            /* we need also last bit   */
     do {
       iml4--;                              /* decrement index         */
       ucrl_work3[ iml4 ] = ill1 & 0XFE;
       ill1 >>= 7;
     } while (iml4 > 0);
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T input to DES - from new password",
                     __LINE__ );
     m_console_out( (char *) ucrl_work3, 8 );
#endif
     GenDESSubKeys( ucrl_work3, umrl_des_subkeytab );
     DES_ecb_encrypt_decrypt( (unsigned char *) chrl_old_pwd_hash + (2 - iml2) * 8,
                              (unsigned char *) &chrl_radius_p[ iml1 + 2 + 4 + 2 + 2 + (2 - iml2) * 8 ],
                              umrl_des_subkeytab,
                              1,
                              DES_ENCRYPT );
     iml2--;                                /* decrement index         */
   } while (iml2 > 0);
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T after DES 16 bytes",
                   __LINE__ );
   m_console_out( &chrl_radius_p[ iml1 + 2 + 4 + 2 + 2 ], 16 );
#endif
#ifdef HL_JAVA
   /* second Peer-Challenge, 24 bytes                                  */
#endif
   /* second Peer-Challenge, 16 bytes                                  */
#ifdef HL_JAVA
   m_gen_random( byrl_send, iml1 + 2 + 4 + 2 + 2 + 16, 16 );
#endif
   iml2 = iml1 + 2 + 4 + 2 + 2 + 16;        /* start random here       */
   iml3 = iml2 + 16;                        /* end of random           */
   do {                                     /* loop to generate random */
#ifndef HL_NO_RANDOM
     chrl_radius_p[ iml2++ ] = (unsigned char) m_get_random_number( 0X0100 );
#else
     chrl_radius_p[ iml2++ ] = 0;
#endif
   } while (iml2 < iml3);
#ifdef HL_JAVA
   memset( &chrl_radius_p[ iml2 ], 0, 8 );
#endif
// to-do 31.05.12 KB clear 8 bytes not only in Java
#ifndef B140324
   memset( &chrl_radius_p[ iml2 ], 0, 8 );
#endif
   /* third NT-Response, GenerateNTResponse(), 24 bytes                */
   /* generate ChallengeHash                                           */
#ifdef HL_JAVA
   imrl_sha1_array = new int[ %int:SHA_ARRAY_SIZE; ];  /* for SHA1 */
   byrlwork1 = new byte[ %int:SHA1_DIGEST_LEN; ];
   s1.S1I( imrl_sha1_array );
%IF DEF TRACEHL1;
   System.out.println( "first input to SHA1" );
   m_console_out( byrl_send, iml1 + 2 + 4 + 2 + 2 + 16, 16 );  /* show on console */
   System.out.println( "second input to SHA1" );
   m_console_out( byrl_send, iml_pos_mchv2_chch + 2 + 4 + 2, 16 );  /* show on console */
%CEND;
#endif
   SHA1_Init( imrl_sha1 );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T first input to SHA1 - Peer-Challenge",
                   __LINE__ );
   m_console_out( &chrl_radius_p[ iml1 + 2 + 4 + 2 + 2 + 16 ], 16 );
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T second input to SHA1",
                   __LINE__ );
   m_console_out( &chrl_radius_p[ iml_pos_mchv2_chch ], 16 );
#endif
#ifdef HL_JAVA
   s1.S1U( imrl_sha1_array, byrl_send, iml1 + 2 + 4 + 2 + 2 + 16, 16 );
   s1.S1U( imrl_sha1_array, byrl_send, iml_pos_mchv2_chch + 2 + 4 + 2, 16 );
%IF DEF TRACEHL1;
   System.out.println( "third input to SHA1 - userid" );
   m_console_out( byrl_send, iml_pos_userid, iml_len_userid );  /* show on console */
%CEND;
#endif
   SHA1_Update( imrl_sha1, &chrl_radius_p[ iml1 + 2 + 4 + 2 + 2 + 16 ], 0, 16 );
   SHA1_Update( imrl_sha1, &chrl_radius_p[ iml_pos_mchv2_chch ], 0, LEN_AVSMS_CHCH );
#ifdef HL_JAVA
   s1.S1U( imrl_sha1_array, byrl_send, iml_pos_userid, iml_len_userid );
   s1.S1F( imrl_sha1_array, byrlwork1, 0 );
%IF DEF TRACEHL1;
   System.out.println( "after SHA1 of userid - ChallengeHash" );
   m_console_out( byrlwork1, 0, %int:SHA1_DIGEST_LEN; );  /* show on console */
%CEND;
#endif
   SHA1_Update( imrl_sha1,
                &chrl_radius_p[ 4 + DEF_RADIUS_LEN_REQ_AUTH + 2 ],
                0,
                ((unsigned char) chrl_radius_p[ 4 + DEF_RADIUS_LEN_REQ_AUTH + 1 ]) - 2 );
   SHA1_Final( imrl_sha1, chrl_work2, 0 );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T after SHA1 of userid - ChallengeHash",
                   __LINE__ );
   m_console_out( chrl_work2, SHA_DIGEST_LEN );
#endif
#ifdef HL_JAVA
   m4.M4I( imrl_md4_state );
   m4.M4U( imrl_md4_state, byrl_unicode_new_password, 0, iml_len_unicode_new_password );
   byrlwork2 = new byte[ %int:MD4_DIGEST_LEN; + 5 ];
   m4.M4F( imrl_md4_state, byrlwork2, 0 );
%IF DEF TRACEHL1;
   System.out.println( "after MD4 of new password - NtPasswordHash" );
   m_console_out( byrlwork2, 0, 16 );   /* show on console         */
%CEND;
#endif
   memset( chrl_work1 + MD4_DIGEST_LEN, 0, sizeof(chrl_work1) - MD4_DIGEST_LEN );
   /* do DesEncrypt                                                    */
   iml2 = 3;
// ill1 = 0;                                /* for compiler only       */
   iml3 = 0;                                /* index in chrl_work1 = ZPasswordHash */
   do {
     iml4 = 7;
     do {
       ill1 <<= 8;
       ill1 |= (unsigned char) chrl_work1[ iml3++ ];
       iml4--;                              /* decrement index         */
     } while (iml4 > 0);
     iml4 = 8;
     ill1 <<= 1;                            /* we need also last bit   */
     do {
       iml4--;                              /* decrement index         */
       ucrl_work3[ iml4 ] = ill1 & 0XFE;
       ill1 >>= 7;
     } while (iml4 > 0);
     GenDESSubKeys( ucrl_work3, umrl_des_subkeytab );
     DES_ecb_encrypt_decrypt( (unsigned char *) chrl_work2,
                              (unsigned char *) &chrl_radius_p[ iml1 + 2 + 4 + 2 + 2 + 16 + 24 + (3 - iml2) * 8 ],
                              umrl_des_subkeytab,
                              1,
                              DES_ENCRYPT );
     iml2--;                            /* decrement index         */
   } while (iml2 > 0);
#ifdef HL_JAVA
%IF DEF TRACEHL1;
       System.out.println( "after DES" );
       m_console_out( byrl_send, iml1 + 2 + 4 + 2 + 2 + 16 + 24, 24 );   /* show on console         */
%CEND;
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T after DES",
                   __LINE__ );
   m_console_out( &chrl_radius_p[ iml1 + 2 + 4 + 2 + 2 + 16 + 24 ], 24 );
#endif
   iml2 = iml1;                             /* get current position    */
   iml1 += 2 + 4 + 2 + 2 + 16 + 24 + 24 + 2;  /* end of this attribute */
   memcpy( &chrl_radius_p[ iml2 ], ucrs_send_avp_ms_01, sizeof(ucrs_send_avp_ms_01) );
   chrl_radius_p[ iml2 + 1 ] = (unsigned char) iml1 - iml2;  /* set length */
#ifdef HL_JAVA
       byrl_send[ iml3 ] = (byte) 0X1B;     /* 27 for MS-CHAP2-PW      */
       byrl_send[ iml3 + 1 ] = (byte) (iml1 - iml3);  /* length this part */
       byrl_send[ iml3 + 2 + 0 ] = (byte) 7;  /* Code 7                */
       byrl_send[ iml3 + 2 + 1 ] = byl_ident;  /* ident used           */
#endif
   chrl_radius_p[ iml2 + sizeof(ucrs_send_avp_ms_01) + 0 ] = (unsigned char) 0X1B;  /* 27 for MS-CHAP2-PW */
   chrl_radius_p[ iml2 + sizeof(ucrs_send_avp_ms_01) + 1 ]
      = (unsigned char) (iml1 - (iml2 + sizeof(ucrs_send_avp_ms_01)));  /* length this part */
   chrl_radius_p[ iml2 + sizeof(ucrs_send_avp_ms_01) + 2 + 0 ] = (unsigned char) 7;  /* Code 7 */
   chrl_radius_p[ iml2 + sizeof(ucrs_send_avp_ms_01) + 2 + 1 ] = adsp_rctrl1->chc_identifier;  /* identifier used */
   /* generate MS-CHAP-NT-Enc-PW                                       */
   /* NewPasswordEncryptedWithOldNtPasswordHash()                      */
#ifdef HL_JAVA
   byrl_nt_enc_pw = new byte[ 512 + 4 ];  /* MS-CHAP-NT-Enc-PW     */
   /* with Mr. Oed 21.11.11 KB                                     */
   byrl_nt_enc_pw[ 512 + 0 ] = (byte) iml_len_unicode_new_password;
   byrl_nt_enc_pw[ 512 + 1 ] = (byte) (iml_len_unicode_new_password >> 8);
   byrl_nt_enc_pw[ 512 + 2 ] = (byte) (iml_len_unicode_new_password >> 16);
   byrl_nt_enc_pw[ 512 + 3 ] = (byte) (iml_len_unicode_new_password >> 24);
   m_gen_random( byrl_nt_enc_pw, 0, 512 - iml_len_unicode_new_password );
#endif
   chrl_pwd[ LEN_AVSMS_NEW_PWD + 0 ] = (unsigned char) iml_len_unicode_new_password;
   chrl_pwd[ LEN_AVSMS_NEW_PWD + 1 ] = (unsigned char) (iml_len_unicode_new_password >> 8);
   chrl_pwd[ LEN_AVSMS_NEW_PWD + 2 ] = (unsigned char) (iml_len_unicode_new_password >> 16);
   chrl_pwd[ LEN_AVSMS_NEW_PWD + 3 ] = (unsigned char) (iml_len_unicode_new_password >> 24);
#ifdef B120130
   /* copy the new password to the end of the array                    */
   memmove( chrl_pwd + LEN_AVSMS_NEW_PWD - iml_len_unicode_new_password,
            chrl_pwd,
            iml_len_unicode_new_password );
#endif
   iml2 = 0;                                /* start random here       */
   do {                                     /* loop to generate random */
#ifndef HL_NO_RANDOM
     chrl_pwd[ iml2++ ] = (unsigned char) m_get_random_number( 0X0100 );
#else
     chrl_pwd[ iml2++ ] = 0;
#endif
   } while (iml2 < LEN_AVSMS_NEW_PWD - iml_len_unicode_new_password);
#ifdef HL_JAVA
   /* copy new password                                            */
   iml2 = 512 - iml_len_unicode_new_password;  /* position output  */
   iml3 = 0;                            /* position input          */
   iml4 = iml_len_unicode_new_password;  /* length to copy         */
   do {
     byrl_nt_enc_pw[ iml2++ ] = byrl_unicode_new_password[ iml3++ ];
   } while (iml3 < iml4);
   rc4.m_rc4_singlepass( byrl_nt_enc_pw, 0, 512 + 4,
                         byrl_old_password_hash, 0, 16,
                         byrl_nt_enc_pw, 0 );
#endif
   m_rc4_singlepass( chrl_pwd, 0, LEN_AVSMS_NEW_PWD + 4,
                     chrl_old_pwd_hash, 0, MD4_DIGEST_LEN,
                     chrl_pwd, 0 );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T after RC4",
                   __LINE__ );
   m_console_out( chrl_pwd, LEN_AVSMS_NEW_PWD + 4 );
#endif
#ifdef HL_JAVA
   iml2 = 0;                            /* clear displacement      */
   iml3 = 0;                            /* clear sequence number   */
   do {                                 /* loop to copy array      */
     iml6 = iml1;                       /* save start of attribute */
     iml4 = 6;                          /* length of first part    */
     iml5 = 0;                          /* clear index             */
     do {
       byrl_send[ iml1++ ] = byrlwork1[ iml5++ ];  /* copy content */
     } while (iml5 < iml4);
     iml4 = (512 + 4) - iml2;           /* length remaining        */
     if (iml4 > (0X00FF - 6 - 2 - 4)) iml4 = 0X00FF - 6 - 2 - 4;
     byrl_send[ iml1++ ] = (byte) 6;    /* 6 for MS-CHAP-NT-Enc-PW */
     byrl_send[ iml1++ ] = (byte) ((iml4 + 2 + 4) & 0XFF);  /* vendor-length */
     byrl_send[ iml1++ ] = (byte) 6;    /* Code is the same as for the MS-CHAP-PW-2 attribute */
     byrl_send[ iml1++ ] = byl_ident;   /* ident used              */
     iml3++;                            /* increment sequence number */
     byrl_send[ iml1++ ] = (byte) ((iml3 >> 8) & 0XFF);  /* sequence number big endian */
     byrl_send[ iml1++ ] = (byte) (iml3 & 0XFF);  /* sequence number big endian */
     do {                               /* loop to copy content    */
       byrl_send[ iml1++ ] = byrl_nt_enc_pw[ iml2++ ];  /* copy    */
       iml4--;                          /* decrement index         */
     } while (iml4 > 0);
     byrl_send[ iml6 + 1 ] = (byte) (iml1 - iml6);  /* length attribute vendor-specific MS MS-CHAP-NT-Enc-PW */
   } while (iml2 < (512 + 4));
#endif
   iml2 = 0;                                /* clear displacement      */
   iml3 = 0;                                /* clear sequence number   */
   do {                                     /* loop to copy array      */
     iml5 = (LEN_AVSMS_NEW_PWD + 4) - iml2;  /* length remaining       */
     if (iml5 > (0X00FF - sizeof(ucrs_send_avp_ms_01) - 2 - 4)) {
       iml5 = 0X00FF - sizeof(ucrs_send_avp_ms_01) - 2 - 4;
     }
//   if ((iml1 + (iml5 + 2 + 4)) > MAX_LEN_RADIUS_PACKET) goto p_inv_req_00;  /* invalid request */
     iml4 = iml1;                           /* save start of attribute */
     memcpy( &chrl_radius_p[ iml1 ], ucrs_send_avp_ms_01, sizeof(ucrs_send_avp_ms_01) );
     iml1 += sizeof(ucrs_send_avp_ms_01);
     chrl_radius_p[ iml1++ ] = (unsigned char) 6;  /* 6 for MS-CHAP-NT-Enc-PW */
     chrl_radius_p[ iml1++ ] = (unsigned char) ((iml5 + 2 + 4) & 0XFF);  /* vendor-length */
     chrl_radius_p[ iml1++ ] = (unsigned char) 6;  /* Code is the same as for the MS-CHAP-PW-2 attribute */
     chrl_radius_p[ iml1++ ] = adsp_rctrl1->chc_identifier;  /* identifier used */
     iml3++;                                /* increment sequence number */
     chrl_radius_p[ iml1++ ] = (unsigned char) ((iml3 >> 8) & 0XFF);  /* sequence number big endian */
     chrl_radius_p[ iml1++ ] = (unsigned char) (iml3 & 0XFF);  /* sequence number big endian */
     memcpy( &chrl_radius_p[ iml1 ], &chrl_pwd[ iml2 ], iml5 );  /* copy part */
     iml1 += iml5;                          /* increment output        */
     iml2 += iml5;                          /* increment input         */
     chrl_radius_p[ iml4 + 1 ] = (unsigned char) (iml1 - iml4);  /* length attribute vendor-specific MS MS-CHAP-NT-Enc-PW */
   } while (iml2 < (LEN_AVSMS_NEW_PWD + 4));

   p_make_req_60:                           /* password has been set   */
   if ((iml1 + 6) > MAX_LEN_RADIUS_PACKET) goto p_inv_req_00;  /* invalid request */
   chrl_radius_p[ iml1++ ] = (unsigned char) 6;  /* attribute Service-Type */
   chrl_radius_p[ iml1++ ] = (unsigned char) 6;  /* length             */
   chrl_radius_p[ iml1++ ] = 0;
   chrl_radius_p[ iml1++ ] = 0;
   chrl_radius_p[ iml1++ ] = 0;
   chrl_radius_p[ iml1++ ] = (unsigned char) 8;  /* Authenticate Only  */
   /* state                                                            */
   if (adsp_rctrl1->imc_len_server_state) {
     if ((iml1 + adsp_rctrl1->imc_len_server_state) > MAX_LEN_RADIUS_PACKET) goto p_inv_req_00;  /* invalid request */
     memcpy( &chrl_radius_p[ iml1 ], adsp_rctrl1->chrc_server_state, adsp_rctrl1->imc_len_server_state );
     iml1 += adsp_rctrl1->imc_len_server_state;
   }
   /* NAS-IP-Address                                                   */
   if (   (adsl_rreq->boc_send_nas_ineta)
       && (adsp_rctrl1->adsc_soa_client)) {
     switch (adsp_rctrl1->adsc_soa_client->sa_family) {  /* type of client netaddr */
       case AF_INET:                        /* type IPV4               */
         if ((iml1 + 2 + 4) > MAX_LEN_RADIUS_PACKET) goto p_inv_req_00;  /* invalid request */
         chrl_radius_p[ iml1++ ] = (unsigned char) 4;  /* type NAS-IP-Address */
         chrl_radius_p[ iml1++ ] = (unsigned char) (2 + 4);  /* length attribute */
         memcpy( &chrl_radius_p[ iml1 ],
                 &((struct sockaddr_in *) adsp_rctrl1->adsc_soa_client)->sin_addr,
                 4 );
         iml1 += 4;
         break;
       case AF_INET6:                       /* type IPV6               */
         if ((iml1 + 2 + 16) > MAX_LEN_RADIUS_PACKET) goto p_inv_req_00;  /* invalid request */
         chrl_radius_p[ iml1++ ] = (unsigned char) 0X5F;  /* type NAS-IP-Address IPV6 RFC 3162 */
         chrl_radius_p[ iml1++ ] = (unsigned char) (2 + 16);  /* length attribute */
         memcpy( &chrl_radius_p[ iml1 ],
                 &((struct sockaddr_in6 *) adsp_rctrl1->adsc_soa_client)->sin6_addr,
                 16 );
         iml1 += 16;
         break;
//   default:
//     break;
     }
   }
   /* attributes passed from calling program                           */
   if (adsl_rreq->imc_len_attr_out > 0) {   /* length attributes output */
     if ((iml1 + adsl_rreq->imc_len_attr_out) > MAX_LEN_RADIUS_PACKET) goto p_inv_req_00;  /* invalid request */
     memcpy( chrl_radius_p + iml1, adsl_rreq->achc_attr_out, adsl_rreq->imc_len_attr_out );
     /* set in identifier, where requested                             */
     iml2 = 0;                              /* clear index             */
     do {
       if (adsl_rreq->imrc_pos_identifier[ iml2 ] <= 0) break;  /* end of position identifier */
       if (adsl_rreq->imrc_pos_identifier[ iml2 ] < adsl_rreq->imc_len_attr_out) {
         chrl_radius_p[ iml1 + adsl_rreq->imrc_pos_identifier[ iml2 ] ]
           = adsp_rctrl1->chc_identifier;   /* identifier used         */
       }
       iml2++;                              /* increment index         */
     } while (iml2 < (sizeof(adsl_rreq->imrc_pos_identifier) / sizeof(adsl_rreq->imrc_pos_identifier[0])));
     iml1 += adsl_rreq->imc_len_attr_out;   /* add length extra attributes */
   }
   if (adsl_rreq->boc_radius_msg_auth) {    /* with Radius message authentication */
     iml1 += 2 + LEN_RADIUS_MSG_AUTH;       /* length Radius MD5 message authenticator */
     if (iml1 > MAX_LEN_RADIUS_PACKET) goto p_inv_req_00;  /* invalid request */
   }
   /* put length of packet                                             */
   chrl_radius_p[2] = (unsigned char) (iml1 >> 8);
   chrl_radius_p[3] = (unsigned char) iml1;
   if (adsl_rreq->boc_radius_msg_auth == FALSE) {  /* without Radius message authentication */
     goto p_make_req_80;                    /* Radius packet has been prepared */
   }
   chrl_radius_p[ iml1 - (2 + LEN_RADIUS_MSG_AUTH) + 0 ] = DEF_RADIUS_AVP_TYPE_MSG_AUTH;
   chrl_radius_p[ iml1 - (2 + LEN_RADIUS_MSG_AUTH) + 1 ] = (unsigned char) (2 + LEN_RADIUS_MSG_AUTH);
   memset( &chrl_radius_p[ iml1 - (2 + LEN_RADIUS_MSG_AUTH) + 2 ], 0, LEN_RADIUS_MSG_AUTH );
   /* HMAC-MD5 [RFC2104] hash                                          */
#ifdef XYZ1
// to-do 23.03.14 KB - first part of HMAC-MD5 is done in configuration program
   memset( byrl_hmac_1, 0X36, sizeof(byrl_hmac_1) );  /* for HMAC      */
   memset( byrl_hmac_2, 0X5C, sizeof(byrl_hmac_2) );  /* for HMAC      */
   iml2 = 0;                                /* clear index             */
   do {
     byrl_hmac_1[ iml2 ] ^= *((unsigned char *) adsl_radius_entry_act->achc_shasec + iml2);
     byrl_hmac_2[ iml2 ] ^= *((unsigned char *) adsl_radius_entry_act->achc_shasec + iml2);
     iml2++;                                /* increment index         */
   } while (iml2 < adsl_radius_entry_act->imc_len_shasec);  /* length of string to apply */
   MD5_Init( imrl_md5_array );
   MD5_Update( imrl_md5_array, byrl_hmac_1, 0, sizeof(byrl_hmac_1) );
   MD5_Update( imrl_md5_array, chrl_radius_p, 0, iml1 );
   MD5_Final( imrl_md5_array, chrl_work1, 0 );
   MD5_Init( imrl_md5_array );
   MD5_Update( imrl_md5_array, byrl_hmac_2, 0, sizeof(byrl_hmac_2) );
   MD5_Update( imrl_md5_array, chrl_work1, 0, MD5_DIGEST_LEN );
   MD5_Final( imrl_md5_array, &chrl_radius_p[ iml1 - (2 + LEN_RADIUS_MSG_AUTH) + 2 ], 0 );
#endif
   /* first part of HMAC-MD5 is done in configuration program          */
   MD5_Init( imrl_md5_array );
   MD5_Update( imrl_md5_array, adsl_radius_entry_act->byrc_hmac_1, 0, sizeof(adsl_radius_entry_act->byrc_hmac_1) );
   MD5_Update( imrl_md5_array, chrl_radius_p, 0, iml1 );
   MD5_Final( imrl_md5_array, chrl_work1, 0 );
   MD5_Init( imrl_md5_array );
   MD5_Update( imrl_md5_array, adsl_radius_entry_act->byrc_hmac_2, 0, sizeof(adsl_radius_entry_act->byrc_hmac_2) );
   MD5_Update( imrl_md5_array, chrl_work1, 0, MD5_DIGEST_LEN );
   MD5_Final( imrl_md5_array, &chrl_radius_p[ iml1 - (2 + LEN_RADIUS_MSG_AUTH) + 2 ], 0 );
   /* save message authenticator output                                */
   memcpy( adsp_rctrl1->chrc_radius_msg_auth,
           &chrl_radius_p[ iml1 - (2 + LEN_RADIUS_MSG_AUTH) + 2 ],
           LEN_RADIUS_MSG_AUTH );
   adsl_rreq->achc_radius_msg_auth = adsp_rctrl1->chrc_radius_msg_auth;  /* address message authenticator output */

   p_make_req_80:                           /* Radius packet has been prepared */
#ifdef DEBUG_141102_01                      /* crash Radius            */
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T p_make_req_80: HL_THRID=%d adsp_rctrl1=%p ->dsc_timer.vpc_chain_2=%p.",
                   __LINE__, HL_THRID, adsp_rctrl1, adsp_rctrl1->dsc_timer.vpc_chain_2 );
   m_console_out( (char *) adsp_rctrl1, sizeof(struct dsd_radius_control_1) );
#endif
#ifdef B141112
#ifndef B141028
   memset( &adsp_rctrl1->dsc_timer, 0, sizeof(struct dsd_timer_ele) );
#endif
#else
   if (adsp_rctrl1->dsc_timer.vpc_chain_2) {  /* timer still set       */
     m_time_rel( &adsp_rctrl1->dsc_timer );  /* release timer          */
   }
#endif
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_RADIUS) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CRADIUSS", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
//   adsl_wt1_w1->imc_wtrt_sno = 0;         /* WSP session number      */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml2 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "send data to radius server length %d/0X%X.",
                     iml1, iml1 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml2;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2)) {  /* generate WSP trace record */
       iml3 = iml1;                         /* length of data received */
       if ((img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2)) == HL_WT_CORE_DATA1) {  /* shorted data */
         iml3 = HL_WT_DATA_SIZE_1;          /* size of data when 01 is given */
       } else if ((img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2)) == HL_WT_CORE_DATA2) {  /* shorted data */
         iml3 = HL_WT_DATA_SIZE_2;          /* size of data when 10 is given */
       }
       if (iml3 > iml1) {                   /* length of data to send  */
         iml3 = iml1;                       /* length of data to send  */
       }
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed   */
       achl_w2 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content   */
       ADSL_WTR_G2->achc_content = achl_w2;  /* content of text / data */
       ADSL_WTR_G2->imc_length = iml3;      /* length of text / data   */
       ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;  /* append to chain       */
       memcpy( achl_w2, chrl_radius_p, iml3 );
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   iml_rc = m_udp_sendto( adsl_radius_entry_act->adsc_udp_multiw_1,  /* structure for multiple wait */
                          chrl_radius_p, iml1,
                          (struct sockaddr *) &adsl_radius_entry_act->dsc_udp_param_1.dsc_soa_target,
                          adsl_radius_entry_act->dsc_udp_param_1.imc_len_soa_target,
                          &iml_error );
   if (iml_rc != iml1) {                    /* send did return error   */
     m_radius_warning( adsp_rctrl1->ac_conn1, 101, "Radius packet UDP sendto returned %d.", iml_rc );
     return FALSE;
   }
#ifdef TRY_PROBLEM_TIMER_141028
#ifndef HL_UNIX
   Sleep( TRY_PROBLEM_TIMER_141028 );
#endif
#endif
#ifndef B141103
   if (adsl_rreq->iec_radius_resp != ied_rar_invalid) {  /* parameter is invalid, request active */
#ifdef DEBUG_141102_01                      /* crash Radius            */
     m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_radius_send() request active HL_THRID=%d adsp_rctrl1=%p ->dsc_timer.vpc_chain_2=%p adsl_rreq->iec_radius_resp=%d.",
                     __LINE__, HL_THRID, adsp_rctrl1, adsp_rctrl1->dsc_timer.vpc_chain_2, adsl_rreq->iec_radius_resp );
#endif
     return TRUE;                           /* all done                */
   }
#endif
   /* set the timer                                                    */
#ifdef B141028
// adsp_rctrl1->dsc_timer.vpc_chain_2 = NULL;  /* timer not set        */
   memset( &adsp_rctrl1->dsc_timer, 0, sizeof(struct dsd_timer_ele) );
#endif
   adsp_rctrl1->dsc_timer.amc_compl = &m_timeout_radius;  /* set routine for timeout */
   iml1 = adsp_rctrl1->adsc_radius_group->imc_timeout;  /* timeout in seconds / wait for radius response */
   if (iml1 <= 0) iml1 = DEF_RADIUS_TIMEOUT;  /* standard radius receive timeout */
   adsp_rctrl1->dsc_timer.ilcwaitmsec = iml1 * 1000;  /* wait in milliseconds */
   m_time_set( &adsp_rctrl1->dsc_timer, FALSE );  /* set timeout now   */
#ifndef B141029
   /* in the mean time, the response already can have arrived.         */
   if (   (adsl_rreq->iec_radius_resp != ied_rar_invalid)  /* parameter is invalid, request active */
       && (adsp_rctrl1->dsc_timer.vpc_chain_2)) {  /* timer still set  */
     m_time_rel( &adsp_rctrl1->dsc_timer );  /* release timer          */
#ifdef DEBUG_141102_01                      /* crash Radius            */
     m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_radius_send() after timer set - timer has been released",
                     __LINE__, adsp_rctrl1 );
#endif
   }
#endif
#ifdef DEBUG_141102_01                      /* crash Radius            */
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_radius_send() before return HL_THRID=%d adsp_rctrl1=%p ->dsc_timer.vpc_chain_2=%p adsl_rreq->iec_radius_resp=%d.",
                   __LINE__, HL_THRID, adsp_rctrl1, adsp_rctrl1->dsc_timer.vpc_chain_2, adsl_rreq->iec_radius_resp );
#endif
   return TRUE;                             /* all done                */

   p_inv_req_00:                            /* invalid request         */
   m_radius_warning( adsp_rctrl1->ac_conn1, 100, "invalid Radius request" );
   return FALSE;
} /* end m_radius_send()                                               */

/** callback for receiving radius packets on a UDP socket              */
static void m_cb_radius_recv( struct dsd_udp_multiw_1 *adsp_udp_multiw_1,
                              struct dsd_sdh_control_1 *adsp_sdhc1_rb ) {
   BOOL       bol1;                         /* working-variable        */
   BOOL       bol_overflow_attr;            /* overflow of attribute storage */
   BOOL       bol_overflow_server_state;    /* overflow of server state storage */
   BOOL       bol_avp_eap;                  /* AVP EAP found           */
   int        iml1, iml2, iml3, iml4;       /* working variables       */
   int        iml_a1;                       /* working variable        */
   int        imrl_a[ 3 ];                  /* numbers attributes      */
   char       *achl_a1, *achl_a2, *achl_a3, *achl_a4;  /* working variables */
   char       *achl_w1, *achl_w2;           /* working variables       */
   char       *achl_packet_sta;             /* start of packet         */
   char       *achl_packet_end;             /* end of packet           */
   char       *achl_attr;                   /* pass attributes         */
   char       *achl_server_state;           /* save server state       */
   char       *achl_msg_auth;               /* Radius message authenticator */
#ifndef B171207
   char       *achl_reply_message;          /* save Radius reply message */
#endif
   struct dsd_radius_netw_1 *adsl_rn1;      /* radius networking       */
   struct dsd_radius_group *adsl_radius_group;  /* radius group        */
   struct dsd_radius_entry *adsl_re_w1;     /* radius-server           */
   struct dsd_radius_control_1 *adsl_rctrl1;  /* radius control        */
   struct dsd_hl_aux_radius_1 *adsl_rreq;   /* radius request          */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace area          */
#ifdef XYZ1
   char       byrl_hmac_1[ 64 ];            /* for HMAC                */
   char       byrl_hmac_2[ 64 ];            /* for HMAC                */
#endif
#ifdef XYZ1
   int        imrl_md5_array[ 24 ];         /* for MD5                 */
#endif
   int        imrl_md5_array[ MD5_ARRAY_SIZE ];  /* for MD5            */
   char       chrl_work1[ 16 ];             /* work area MD5           */

#define ADSL_RECB_1_G ((struct dsd_sdh_udp_recbuf_1 *) (adsp_sdhc1_rb + 1))

#ifdef DEBUG_140329
   Sleep( DEBUG_140329 * 1000 );
#endif
   adsl_rn1 = (struct dsd_radius_netw_1 *) ((char *) adsp_udp_multiw_1
                                              - offsetof( struct dsd_radius_netw_1, dsc_udp_multiw_1 ));
   adsl_re_w1 = adsl_rn1->adsc_re_chain;    /* chain radius entry / single radius server */
   do {                                     /* loop to search current radius-server */
     adsl_rctrl1 = adsl_re_w1->adsc_rc1_active;  /* currently active radius control */
     if (   (adsl_rctrl1)                   /* currently active radius control */
         && (!memcmp( &adsl_re_w1->dsc_udp_param_1.dsc_soa_target,
                      ADSL_RECB_1_G->achc_sockaddr,
                      ADSL_RECB_1_G->imc_len_sockaddr ))) {
       goto p_radse_00;                     /* radius-server found     */
     }
     adsl_re_w1 = adsl_re_w1->adsc_re_chain;  /* next in chain of networking */
   } while (adsl_re_w1);
   goto p_free_received;                    /* free received memory    */

   p_radse_00:                              /* radius-server found     */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_cb_radius_recv() l%05d p_radse_00: len-received=%d/0X%X.",
                   __LINE__, ADSL_RECB_1_G->imc_len_data, ADSL_RECB_1_G->imc_len_data );
#endif
#ifdef DEBUG_141102_01                      /* crash Radius            */
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_cb_radius_recv() p_radse_00: HL_THRID=%d adsl_rctrl1=%p ->dsc_timer.vpc_chain_2=%p.",
                   __LINE__, HL_THRID, adsl_rctrl1, adsl_rctrl1->dsc_timer.vpc_chain_2 );
#endif
   adsl_radius_group = adsl_rctrl1->adsc_radius_group;  /* radius group */
   iml1 = ADSL_RECB_1_G->imc_len_data;      /* get length of packet    */
   if (iml1 <= 0) {                         /* received timeout        */
     goto p_free_received;                  /* free received memory    */
   }
   achl_packet_sta = ADSL_RECB_1_G->achc_data;  /* start of packet     */
   achl_packet_end = ADSL_RECB_1_G->achc_data + iml1;  /* end of packet */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_RADIUS) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CRADIUSR", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
//   adsl_wt1_w1->imc_wtrt_sno = 0;         /* WSP session number      */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml2 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "rctrl1=%p received data from radius server length %d/0X%X.",
                     adsl_rctrl1, iml1, iml1 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml2;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2)) {  /* generate WSP trace record */
       iml3 = iml1;                         /* length of data received */
       if ((img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2)) == HL_WT_CORE_DATA1) {  /* shorted data */
         iml3 = HL_WT_DATA_SIZE_1;          /* size of data when 01 is given */
       } else if ((img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2)) == HL_WT_CORE_DATA2) {  /* shorted data */
         iml3 = HL_WT_DATA_SIZE_2;          /* size of data when 10 is given */
       }
       if (iml3 > iml1) {                   /* length of data to send  */
         iml3 = iml1;                       /* length of data to send  */
       }
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed   */
       achl_w2 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content   */
       ADSL_WTR_G2->achc_content = achl_w2;  /* content of text / data */
       ADSL_WTR_G2->imc_length = iml3;      /* length of text / data   */
       ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;  /* append to chain       */
       memcpy( achl_w2, achl_packet_sta, iml3 );
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (*(achl_packet_sta + 1) != adsl_rctrl1->chc_identifier) {  /* check identifier used */
// 29.12.11 KB error message
     m_hlnew_printf( HLOG_WARN1, "HWSPRA003W l%05d radius-group %.*(u8)s radius-server %.*(u8)s received wrong identifier",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1 );
     goto p_free_received;                  /* free received memory    */
   }
#ifdef XYZ1
   iml_len_server_state = 0;                /* clear len server state  */
   if (imc_len_received == 0) {             /* length radius received  */
     goto prece80;                          /* received timed out      */
   }
#endif
   iml2 = (*((unsigned char *) (achl_packet_sta + 2)) << 8)
            | *((unsigned char *) (achl_packet_sta + 3));
   if (iml2 != iml1) {                      /* length radius received  */
// 29.12.11 KB error message
#ifdef XYZ1
     achl_error = "xsradiq1-e012 radius packet received length not equal length in packet";
     goto prece88;                          /* display error message   */
#endif
     m_hlnew_printf( HLOG_WARN1, "HWSPRA004W l%05d radius-group %.*(u8)s radius-server %.*(u8)s received wrong length %d %d.",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1,
                     iml2, iml1 );
     goto p_free_received;                  /* free received memory    */
   }
   if (    (*achl_packet_sta != 2)          /* access-accept           */
        && (*achl_packet_sta != 3)          /* access-reject           */
        && (*achl_packet_sta != 11)) {      /* challenge               */
// 29.12.11 KB error message
#ifdef XYZ1
     achl_error = "xsradiq1-e013 radius packet received invalid code";
     goto prece88;                          /* display error message   */
#endif
     m_hlnew_printf( HLOG_WARN1, "HWSPRA005W l%05d radius-group %.*(u8)s radius-server %.*(u8)s received invalid code 0X%02X.",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1,
                     (unsigned char) *achl_packet_sta );
     goto p_free_received;                  /* free received memory    */
   }
#ifdef DEBUG_141102_01                      /* crash Radius            */
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_cb_radius_recv() before m_time_rel() HL_THRID=%d adsl_rctrl1=%p ->dsc_timer.vpc_chain_2=%p.",
                   __LINE__, HL_THRID, adsl_rctrl1, adsl_rctrl1->dsc_timer.vpc_chain_2 );
#endif
   /* release the timer                                                */
   m_time_rel( &adsl_rctrl1->dsc_timer );   /* release timer           */
#ifdef DEBUG_141102_01                      /* crash Radius            */
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_cb_radius_recv() after  m_time_rel() HL_THRID=%d adsl_rctrl1=%p ->dsc_timer.vpc_chain_2=%p.",
                   __LINE__, HL_THRID, adsl_rctrl1, adsl_rctrl1->dsc_timer.vpc_chain_2 );
#endif

   adsl_re_w1->adsc_rc1_active = NULL;      /* currently active radius control */
   adsl_rctrl1->ilc_marked = 0;             /* marked radius-servers   */
   m_radius_queued( adsl_radius_group );    /* can send other radius packet */
   adsl_rreq = adsl_rctrl1->adsc_rreq;      /* radius request          */
   if (*achl_packet_sta != 11) {            /* not challenge           */
     adsl_rctrl1->adsc_radius_entry_act = NULL;  /* no active radius entry / single radius server */
   }
#ifndef B171207
   achl_reply_message = NULL;               /* save Radius reply message */
#endif

   /* check response authenticator                                     */
//#ifdef WORK051113_MD5
   MD5_Init( imrl_md5_array );
   MD5_Update( imrl_md5_array, achl_packet_sta, 0, 4 );
   MD5_Update( imrl_md5_array, adsl_rctrl1->chrc_req_auth, 0, DEF_RADIUS_LEN_REQ_AUTH );
   MD5_Update( imrl_md5_array, achl_packet_sta, 4 + 16, iml1 - (4 + 16) );
   MD5_Update( imrl_md5_array,
               adsl_re_w1->achc_shasec,     /* address shared secret   */
               0,
               adsl_re_w1->imc_len_shasec );  /* length of shared secret */
   MD5_Final( imrl_md5_array, chrl_work1, 0 );
//#endif
   iml2 = 16;
   do {
     iml2--;
     if (chrl_work1[iml2] != *(achl_packet_sta + 4 + iml2)) {
// 29.12.11 KB error message
#ifdef XYZ1
       achl_error = "xsradiq1-e014 radius packet received Response Authenticator invalid";
       goto prece88;                        /* display error message   */
#endif
       if (adsl_rreq) {                     /* radius request          */
         adsl_rreq->achc_attr_in = NULL;    /* attributes input        */
         adsl_rreq->imc_attr_in = 0;        /* length attributes input */
         adsl_rreq->imc_ms_chap_v2_error = 0;   /* error from MS-CHAP-V2   */
         adsl_rreq->iec_radius_resp = ied_rar_error;  /* error, no valid response */
         if (img_wsp_trace_core_flags1 & HL_WT_CORE_RADIUS) {  /* generate WSP trace record */
           adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
           memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
           adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
           adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
           memcpy( adsl_wt1_w1->chrc_wtrt_id, "CRADIUS3", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
           adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id         */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
           adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
           ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed      */
           iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                           "l%05d call amc_radius_query_compl( rctrl1=%p , 1 ) rreq=%p.",
                           __LINE__, adsl_rctrl1, adsl_rreq );
           ADSL_WTR_G1->achc_content        /* content of text / data  */
             = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
           ADSL_WTR_G1->imc_length = iml1;  /* length of text / data   */
#undef ADSL_WTR_G1
           m_wsp_trace_out( adsl_wt1_w1 );  /* output of WSP trace record */
         }
         adsl_rctrl1->amc_radius_query_compl( adsl_rctrl1, 1 );  /* callback when radius request complete */
       }
       adsl_rctrl1->adsc_radius_entry_act = NULL;  /* no active radius entry / single radius server */
       m_hlnew_printf( HLOG_WARN1, "HWSPRA006W l%05d radius-group %.*(u8)s radius-server %.*(u8)s received Response Authenticator invalid",
                       __LINE__,
                       adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                       adsl_re_w1->imc_len_name, adsl_re_w1 + 1 );
       goto p_free_received;                /* free received memory    */
     }
   } while (iml2 > 0);

   /* process the attributes                                           */
   iml2 = 4 + 16;                           /* start attributes        */
   bol_overflow_attr = FALSE;               /* overflow of attribute storage */
   bol_overflow_server_state = FALSE;       /* overflow of server state storage */
   bol_avp_eap = FALSE;                     /* AVP EAP found           */
// char       chrc_attr[ DEF_RADIUS_LEN_ATTR ];  /* pass attributes    */
// char       chrc_server_state[ DEF_RADIUS_LEN_STATE ];  /* save server state */
   achl_attr = adsl_rctrl1->chrc_attr;      /* pass attributes         */
   achl_server_state = adsl_rctrl1->chrc_server_state;  /* save server state */
#ifdef B120128
   while (iml2 < iml1) {                    /* loop over attribute bytes */
     iml3 = iml1 - iml2;                    /* length remaining        */
     if (iml3 < 3) {
#ifdef XYZ1
       achl_error = "xsradiq1-e015 radius packet received length remaining in attributes invalid";
       goto prece88;                        /* display error message   */
#endif
       break;
     }
     iml4 = *((unsigned char *) (achl_packet_sta + iml2 + 1));
     if (iml4 < 3) {
#ifdef XYZ1
       achl_error = "xsradiq1-e016 radius packet received length attribute invalid";
       goto prece88;                        /* display error message   */
#endif
       m_hlnew_printf( HLOG_WARN1, "HWSPRA007W l%05d radius-group %.*(u8)s radius-server %.*(u8)s length attribute %d too short",
                       __LINE__,
                       adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                       adsl_re_w1->imc_len_name, adsl_re_w1 + 1,
                       iml4 );
       break;
     }
     if (iml4 > iml3) {                     /* behind end of record    */
#ifdef XYZ1
       achl_error = "xsradiq1-e017 radius packet received length attribute behind end";
       goto prece88;                        /* display error message   */
#endif
       m_hlnew_printf( HLOG_WARN1, "HWSPRA008W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute length %d beyond end of packet",
                       __LINE__,
                       adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                       adsl_re_w1->imc_len_name, adsl_re_w1 + 1,
                       iml4 );
       break;
     }
     iml3 = iml2;                           /* save position           */
     iml2 += iml4;                          /* after this attribute    */
     bol1 = TRUE;                           /* copy attribute          */
     switch (*((unsigned char *) (achl_packet_sta + iml3))) {
       case 0X18:                           /* State                   */
         bol1 = FALSE;                      /* do not copy to attributes */
         if ((achl_server_state + iml4) > (adsl_rctrl1->chrc_server_state + DEF_RADIUS_LEN_STATE)) {
           bol_overflow_server_state = TRUE;  /* overflow of server state storage */
           break;
         }
         memcpy( achl_server_state,
                 achl_packet_sta + iml3,
                 iml4 );
         achl_server_state += iml4;
         break;
       case 0X1A:                           /* Vendor-Specific         */
         break;
     }
     while (bol1) {                         /* copy attributes         */
       if ((achl_attr + iml4) > (adsl_rctrl1->chrc_attr + DEF_RADIUS_LEN_ATTR)) {
         bol_overflow_attr = TRUE;          /* overflow of attribute storage */
         break;
       }
       memcpy( achl_attr,
               achl_packet_sta + iml3,
               iml4 );
       achl_attr += iml4;
       break;
     }
   }
#endif
#ifndef B120128
   iml_a1 = 0;                              /* reset numbers attributes */
   achl_msg_auth = NULL;                    /* Radius message authenticator */

   p_attr_00:                               /* start processing radius attributes */
   if (iml2 >= iml1) {                      /* at end of attributes    */
     goto p_attr_80;                        /* end of processing radius attributes */
   }
   iml3 = iml1 - iml2;                      /* length remaining        */
   if (iml3 < 3) {                          /* too short for attribute */
// to-do 28.01.12 KB process error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA007W l%05d radius-group %.*(u8)s radius-server %.*(u8)s space for attribute %d too short",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1,
                     iml3 );
     goto p_attr_80;                        /* end of processing radius attributes */
   }
//---
   iml4 = *((unsigned char *) (achl_packet_sta + iml2 + 1));
   if (iml4 < 3) {                          /* too short for attribute */
#ifdef XYZ1
       achl_error = "xsradiq1-e016 radius packet received length attribute invalid";
       goto prece88;                        /* display error message   */
#endif
// to-do 28.01.12 KB process error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA008W l%05d radius-group %.*(u8)s radius-server %.*(u8)s length attribute %d too short",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1,
                     iml4 );
     goto p_attr_80;                        /* end of processing radius attributes */
   }
   if (iml4 > iml3) {                       /* behind end of record    */
#ifdef XYZ1
       achl_error = "xsradiq1-e017 radius packet received length attribute behind end";
       goto prece88;                        /* display error message   */
#endif
// to-do 28.01.12 KB process error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA009W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute length %d beyond end of packet",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1,
                     iml4 );
     goto p_attr_80;                        /* end of processing radius attributes */
   }
   iml3 = iml2;                             /* save position           */
   iml2 += iml4;                            /* after this attribute    */
   bol1 = TRUE;                             /* copy attribute          */
   switch (*((unsigned char *) (achl_packet_sta + iml3))) {
#ifndef B171207
     case DEF_RADIUS_AVP_TYPE_REPLY_MESSAGE:
       if (achl_reply_message) {            /* Radius reply message    */
         m_hlnew_printf( HLOG_WARN1, "HWSPRA025W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute 0X12 reply message double",
                         __LINE__,
                         adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                         adsl_re_w1->imc_len_name, adsl_re_w1 + 1 );
         goto p_attr_60;                    /* radius attribute has been processed */
       }
       achl_reply_message = achl_packet_sta + iml3;  /* save Radius reply message */
       goto p_attr_60;                      /* radius attribute has been processed */
#endif
     case 0X18:                             /* State                   */
       bol1 = FALSE;                        /* do not copy to attributes */
       if ((achl_server_state + iml4) > (adsl_rctrl1->chrc_server_state + DEF_RADIUS_LEN_STATE)) {
         bol_overflow_server_state = TRUE;  /* overflow of server state storage */
         break;
       }
       memcpy( achl_server_state,
               achl_packet_sta + iml3,
               iml4 );
       achl_server_state += iml4;
       goto p_attr_60;                      /* radius attribute has been processed */
     case 0X1A:                             /* Vendor-Specific         */
       break;                               /* check attribute         */
     case DEF_RADIUS_AVP_TYPE_EAP:
       bol_avp_eap = TRUE;                  /* AVP EAP found           */
       goto p_attr_60;                      /* radius attribute has been processed */
     case DEF_RADIUS_AVP_TYPE_MSG_AUTH:
       bol1 = FALSE;                        /* do not copy to attributes */
       if (achl_msg_auth) {                 /* Radius message authenticator */
         m_hlnew_printf( HLOG_WARN1, "HWSPRA020W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute 0X50 message authenticator double",
                         __LINE__,
                         adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                         adsl_re_w1->imc_len_name, adsl_re_w1 + 1 );
//       goto p_attr_60;                    /* radius attribute has been processed */
         goto p_free_received;              /* free received memory    */
       }
       if (iml4 != (2 + LEN_RADIUS_MSG_AUTH)) {  /* length Radius MD5 message authenticator */
         m_hlnew_printf( HLOG_WARN1, "HWSPRA021W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute 0X50 message authenticator length %d invalid",
                         __LINE__,
                         adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                         adsl_re_w1->imc_len_name, adsl_re_w1 + 1,
                         iml4 );
//       goto p_attr_60;                    /* radius attribute has been processed */
         goto p_free_received;              /* free received memory    */
       }
       achl_msg_auth = achl_packet_sta + iml3 + 2;  /* Radius message authenticator */
       goto p_attr_60;                      /* radius attribute has been processed */
     default:                               /* other values            */
       goto p_attr_60;                      /* radius attribute has been processed */
   }
   /* Vendor-Specific - check if Microsoft                             */
   if (iml4 < (sizeof(ucrs_send_avp_ms_01)) + 2) {  /* too short       */
     goto p_attr_60;                        /* radius attribute has been processed */
   }
   if (memcmp( achl_packet_sta + iml3 + 2,
               ucrs_send_avp_ms_01 + 2,
               sizeof(ucrs_send_avp_ms_01) - 2)) {
     goto p_attr_60;                        /* radius attribute has been processed */
   }
   if (*((unsigned char *) achl_packet_sta + iml3 + sizeof(ucrs_send_avp_ms_01) + 1)
         != (iml4 - sizeof(ucrs_send_avp_ms_01))) {
     goto p_attr_60;                        /* radius attribute has been processed */
   }
   /* 2 = MS-CHAP-Error                                                */
   if (*((unsigned char *) achl_packet_sta + iml3 + sizeof(ucrs_send_avp_ms_01)) != 2) {
     goto p_attr_60;                        /* radius attribute has been processed */
   }
   if (iml_a1 != 0) {                       /* numbers attributes already set */
// to-do 28.01.12 KB error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA010W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute MS-CHAP-Error double",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1 );
     goto p_attr_60;                        /* radius attribute has been processed */
   }
   achl_a1 = achl_packet_sta + iml3 + sizeof(ucrs_send_avp_ms_01) + 3;  /* start of numbers */
   achl_a2 = achl_packet_sta + iml2;        /* end of numbers          */
   if (achl_a1 >= achl_a2) {                /* numbers missing         */
// to-do 28.01.12 KB error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA011W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute MS-CHAP-Error length invalid",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1 );
     goto p_attr_60;                        /* radius attribute has been processed */
   }

   p_attr_num_00:                           /* process numbers         */
   if ((achl_a1 + 3) > achl_a2) {           /* no space for numbers    */
// to-do 28.01.12 KB error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA012W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute MS-CHAP-Error space for number too short",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1 );
     goto p_attr_60;                        /* radius attribute has been processed */
   }
   if (*(achl_a1 + 0) != ucrs_vendor_s_ms_numbers[ iml_a1 ]) {
// to-do 28.01.12 KB error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA013W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute MS-CHAP-Error number %c / 0X%02X out of sequence",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1,
                     *(achl_a1 + 0), (unsigned char) *(achl_a1 + 0) );
     goto p_attr_60;                        /* radius attribute has been processed */
   }
   if (*(achl_a1 + 1) != '=') {             /* no equals follows       */
// to-do 28.01.12 KB error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA014W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute MS-CHAP-Error number %c / 0X%02X no equals follows",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1,
                     *(achl_a1 + 0), (unsigned char) *(achl_a1 + 0) );
     goto p_attr_60;                        /* radius attribute has been processed */
   }
   achl_a1 += 2;                            /* start ASCII number here */
   achl_a3 = achl_a1 + 4;                   /* maximum end of number   */
   achl_a4 = achl_a1;                       /* save beginning of number */
   imrl_a[ iml_a1 ] = 0;                    /* reset number            */

   p_attr_num_20:                           /* process digit of number */
   if (achl_a1 >= achl_a2) {                /* end of number           */
     goto p_attr_num_40;                    /* end of number           */
   }
   if (*achl_a1 == ' ') {                   /* followed by space       */
     goto p_attr_num_40;                    /* end of number           */
   }
   if (achl_a1 >= achl_a3) {                /* number too big          */
// to-do 28.01.12 KB error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA015W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute MS-CHAP-Error number %c / 0X%02X too big",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1,
                     ucrs_vendor_s_ms_numbers[ iml_a1 ], ucrs_vendor_s_ms_numbers[ iml_a1 ] );
     goto p_attr_60;                        /* radius attribute has been processed */
   }
   if ((*achl_a1 < '0') || (*achl_a1 > '9')) {  /* is not digit        */
// to-do 28.01.12 KB error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA016W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute MS-CHAP-Error number %c / 0X%02X invalid digit 0X%02X.",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1,
                     ucrs_vendor_s_ms_numbers[ iml_a1 ], ucrs_vendor_s_ms_numbers[ iml_a1 ],
                     (unsigned char) *achl_a1 );
     goto p_attr_60;                        /* radius attribute has been processed */
   }
   imrl_a[ iml_a1 ] *= 10;                  /* shift old number        */
   imrl_a[ iml_a1 ] += *achl_a1 - '0';      /* add new digit           */
   achl_a1++;                               /* after this digit        */
   goto p_attr_num_20;                      /* process digit of number */

   p_attr_num_40:                           /* end of number           */
   if (achl_a1 <= achl_a4) {                /* no digit found          */
// to-do 28.01.12 KB error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA017W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute MS-CHAP-Error number %c / 0X%02X no digit found",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1,
                     ucrs_vendor_s_ms_numbers[ iml_a1 ], ucrs_vendor_s_ms_numbers[ iml_a1 ] );
     goto p_attr_60;                        /* radius attribute has been processed */
   }
   iml_a1++;                                /* this digit processed    */
   if (achl_a1 >= achl_a2) {                /* end of numbers          */
     goto p_attr_60;                        /* radius attribute has been processed */
   }
   if (iml_a1 >= (sizeof(imrl_a)/sizeof(imrl_a[0]))) {  /* too many numbers */
// to-do 28.01.12 KB error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA018W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute MS-CHAP-Error too many numbers",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1 );
     goto p_attr_60;                        /* radius attribute has been processed */
   }
   achl_a1++;                               /* after space             */
   goto p_attr_num_00;                      /* process next number     */

   p_attr_60:                               /* radius attribute has been processed */
   while (bol1) {                           /* copy attributes         */
     if ((achl_attr + iml4) > (adsl_rctrl1->chrc_attr + DEF_RADIUS_LEN_ATTR)) {
       bol_overflow_attr = TRUE;            /* overflow of attribute storage */
       break;
     }
     memcpy( achl_attr,
             achl_packet_sta + iml3,
             iml4 );
     achl_attr += iml4;
     break;
   }
   goto p_attr_00;                          /* start processing radius attributes */
//---

   p_attr_80:                               /* end of processing radius attributes */
#endif
   if (achl_msg_auth == NULL) {             /* Radius message authenticator */
     if (bol_avp_eap) {                     /* AVP EAP found           */
       m_hlnew_printf( HLOG_WARN1, "HWSPRA022W l%05d radius-group %.*(u8)s radius-server %.*(u8)s EAP attribute received but no message authenticator",
                       __LINE__,
                       adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                       adsl_re_w1->imc_len_name, adsl_re_w1 + 1 );
       goto p_free_received;                /* free received memory    */
     }
     if (   (adsl_rreq)
         && (adsl_rreq->boc_radius_msg_auth)) {  /* with Radius message authentication */
       m_hlnew_printf( HLOG_WARN1, "HWSPRA023W l%05d radius-group %.*(u8)s radius-server %.*(u8)s message sent with message authenticator but no message authenticator received",
                       __LINE__,
                       adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                       adsl_re_w1->imc_len_name, adsl_re_w1 + 1 );
       goto p_free_received;                /* free received memory    */
     }
     goto p_compl_20;                       /* all complete            */
   }
   /* HMAC-MD5 [RFC2104] hash                                          */
//#ifdef XYZ1
   /* first part of HMAC-MD5 is done in configuration program          */
   MD5_Init( imrl_md5_array );
   MD5_Update( imrl_md5_array, adsl_re_w1->byrc_hmac_1, 0, sizeof(adsl_re_w1->byrc_hmac_1) );
#ifdef XYZ1
   MD5_Update( imrl_md5_array, achl_packet_sta, 0, achl_msg_auth - achl_packet_sta );
#endif
   MD5_Update( imrl_md5_array, achl_packet_sta, 0, 4 );
   MD5_Update( imrl_md5_array, adsl_rctrl1->chrc_req_auth, 0, DEF_RADIUS_LEN_REQ_AUTH );
   MD5_Update( imrl_md5_array, achl_packet_sta + 4 + 16, 0, achl_msg_auth - (achl_packet_sta + 4 + 16) );
   MD5_Update( imrl_md5_array, (char *) byrs_sixteen_zeros, 0, LEN_RADIUS_MSG_AUTH );
   if ((achl_msg_auth + LEN_RADIUS_MSG_AUTH) < achl_packet_end) {
     MD5_Update( imrl_md5_array, achl_msg_auth + LEN_RADIUS_MSG_AUTH, 0, achl_packet_end - (achl_msg_auth + LEN_RADIUS_MSG_AUTH) );
   }
   MD5_Final( imrl_md5_array, chrl_work1, 0 );
   MD5_Init( imrl_md5_array );
   MD5_Update( imrl_md5_array, adsl_re_w1->byrc_hmac_2, 0, sizeof(adsl_re_w1->byrc_hmac_2) );
   MD5_Update( imrl_md5_array, chrl_work1, 0, MD5_DIGEST_LEN );
   MD5_Final( imrl_md5_array, chrl_work1, 0 );
//#endif
#ifdef XYZ1
   memset( byrl_hmac_1, 0X36, sizeof(byrl_hmac_1) );  /* for HMAC      */
   memset( byrl_hmac_2, 0X5C, sizeof(byrl_hmac_2) );  /* for HMAC      */
   iml1 = 0;                                /* clear index             */
   do {
     byrl_hmac_1[ iml1 ] ^= *((unsigned char *) adsl_rctrl1->chrc_req_auth + iml1);
     byrl_hmac_2[ iml1 ] ^= *((unsigned char *) adsl_rctrl1->chrc_req_auth + iml1);
     iml1++;                                /* increment index         */
   } while (iml1 < DEF_RADIUS_LEN_REQ_AUTH);  /* length of string to apply */
   MD5_Init( imrl_md5_array );
   MD5_Update( imrl_md5_array, byrl_hmac_1, 0, sizeof(byrl_hmac_1) );
   MD5_Update( imrl_md5_array, achl_packet_sta, 0, achl_msg_auth - achl_packet_sta );
   MD5_Update( imrl_md5_array, (char *) byrs_sixteen_zeros, 0, LEN_RADIUS_MSG_AUTH );
   if ((achl_msg_auth + LEN_RADIUS_MSG_AUTH) < achl_packet_end) {
     MD5_Update( imrl_md5_array, achl_msg_auth + LEN_RADIUS_MSG_AUTH, 0, achl_packet_end - (achl_msg_auth + LEN_RADIUS_MSG_AUTH) );
   }
   MD5_Final( imrl_md5_array, chrl_work1, 0 );
   MD5_Init( imrl_md5_array );
   MD5_Update( imrl_md5_array, byrl_hmac_2, 0, sizeof(byrl_hmac_2) );
   MD5_Update( imrl_md5_array, chrl_work1, 0, MD5_DIGEST_LEN );
   MD5_Final( imrl_md5_array, chrl_work1, 0 );
#endif
   if (memcmp( achl_msg_auth, chrl_work1, LEN_RADIUS_MSG_AUTH )) {
     m_hlnew_printf( HLOG_WARN1, "HWSPRA024W l%05d radius-group %.*(u8)s radius-server %.*(u8)s message authenticator invalid",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1 );
     goto p_free_received;                  /* free received memory    */
   }

   p_compl_20:                              /* all complete            */
// to-do 29.12.11 KB error messages overflow
   if (bol_overflow_attr) {                 /* overflow of attribute storage */
     m_hlnew_printf( HLOG_WARN1, "HWSPRA019W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attributes received overflow",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1 );
   }
   adsl_rctrl1->imc_len_server_state = achl_server_state - adsl_rctrl1->chrc_server_state;
   if (adsl_rreq) {                         /* radius request          */
     adsl_rreq->achc_attr_in = NULL;        /* attributes input        */
     adsl_rreq->imc_attr_in = achl_attr - adsl_rctrl1->chrc_attr;  /* length attributes input */
     if (adsl_rreq->imc_attr_in > 0) {      /* length attributes input positive */
       adsl_rreq->achc_attr_in = adsl_rctrl1->chrc_attr;  /* set attributes input */
     }
#ifndef B171207
     /* save reply message                                             */
     if (achl_reply_message) {              /* save Radius reply message */
       iml1 = *((unsigned char *) achl_reply_message + 1) - 2;
       /* no need to check DEF_RADIUS_LEN_REPLY_MESSAGE */
       memcpy( adsl_rctrl1->chrc_reply_message,
               achl_reply_message + 2,
               iml1 );
       adsl_rreq->imc_len_reply_message = iml1;  /* length reply message */
       adsl_rreq->achc_reply_message = adsl_rctrl1->chrc_reply_message;  /* address reply message */
     }
#endif
     adsl_rreq->imc_ms_chap_v2_error = 0;   /* error from MS-CHAP-V2   */
     adsl_rreq->iec_radius_resp = ied_rar_access_reject;  /* reject access */
     switch (*((unsigned char *) (achl_packet_sta + 0))) {
       case 2:                              /* access-accept           */
         adsl_rreq->iec_radius_resp = ied_rar_access_accept;  /* accept sign on */
         break;
       case 3:                              /* access-reject           */
// to-do 29.12.11 KB need new password
         if (iml_a1 == 0) break;            /* numbers attributes not set */
         adsl_rreq->imc_ms_chap_v2_error = imrl_a[ 0 ];  /* error from MS-CHAP-V2 */
         if (imrl_a[ 0 ] != 648) break;     /* not ERROR_PASSWD_EXPIRED */
         adsl_rreq->iec_radius_resp = ied_rar_need_new_password;  /* needs new password */
         break;
       case 11:                             /* challenge               */
         adsl_rreq->iec_radius_resp = ied_rar_challenge;  /* request challenge */
         break;
     }
     if (img_wsp_trace_core_flags1 & HL_WT_CORE_RADIUS) {  /* generate WSP trace record */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data     */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "CRADIUS2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id             */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "l%05d call amc_radius_query_compl( rctrl1=%p , 0 ) rreq=%p iec_radius_resp=%d type=%d.",
                       __LINE__, adsl_rctrl1, adsl_rreq, adsl_rreq->iec_radius_resp,
                       *((unsigned char *) (achl_packet_sta + 0)) );
       ADSL_WTR_G1->achc_content            /* content of text / data  */
         = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
       ADSL_WTR_G1->imc_length = iml1;      /* length of text / data   */
#undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
     }
     adsl_rctrl1->amc_radius_query_compl( adsl_rctrl1, 0 );  /* callback when radius request complete */
   }

   p_free_received:                         /* free received memory    */
   m_proc_free( adsp_sdhc1_rb );            /* free the packet again   */
   return;                                  /* all done                */

#undef ADSL_RECB_1_G

} /* end m_cb_radius_recv()                                            */

/** routine called by timer thread when a radius query timed out       */
static void m_timeout_radius( struct dsd_timer_ele *adsp_timer_ele ) {
   BOOL       bol1;                         /* working-variable        */
   int        iml1;                         /* working variable        */
   struct dsd_radius_group *adsl_radius_group;  /* radius group        */
   struct dsd_radius_entry *adsl_raent_act;  /* active radius entry / single radius server */
   struct dsd_radius_control_1 *adsl_rctrl1_w1;  /* working-variable   */
   struct dsd_hl_aux_radius_1 *adsl_rreq;   /* radius request          */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace area          */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_timeout_radius( %p )",
                   __LINE__, adsp_timer_ele );
#endif
#ifdef XYZ1
#define ADSL_RAQUE_G ((class dsd_radius_query *) ((char *) adsp_timer_ele - offsetof( class dsd_radius_query, dsc_timer )))
   ADSL_RAQUE_G->mc_timeout();
#undef ADSL_RAQUE_G
#endif
#define ADSL_RCTRL1_G ((struct dsd_radius_control_1 *) ((char *) adsp_timer_ele - offsetof( struct dsd_radius_control_1, dsc_timer )))
#ifdef DEBUG_141102_01                      /* crash Radius            */
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_timeout_radius() p_radse_00: HL_THRID=%d ADSL_RCTRL1_G=%p ->dsc_timer.vpc_chain_2=%p.",
                   __LINE__, HL_THRID, ADSL_RCTRL1_G, ADSL_RCTRL1_G->dsc_timer.vpc_chain_2 );
#endif
   adsl_radius_group = ADSL_RCTRL1_G->adsc_radius_group;  /* radius group */
   adsl_raent_act = ADSL_RCTRL1_G->adsc_radius_entry_act;  /* active radius entry / single radius server */
   if (adsl_raent_act) {                    /* active radius entry / single radius server */
     bol1 = FALSE;                          /* no logic error          */
     if (adsl_raent_act->adsc_rc1_active != ADSL_RCTRL1_G) {  /* currently active radius control */
       bol1 = TRUE;                         /* logic error             */
     }
     iml1 = adsl_radius_group->imc_retry_after_error;  /* configured time retry after error seconds */
     if (iml1 == 0) iml1 = DEF_RADIUS_TIME_LOCK;  /* standard radius time to lock */
     adsl_raent_act->imc_epoch_locked = (int) time( NULL ) + iml1;  /* epoch radius server locked until */
     if (adsl_raent_act->imc_epoch_locked == 0) adsl_raent_act->imc_epoch_locked = 1;
     adsl_raent_act->adsc_rc1_active = NULL;  /* currently active radius control */
     m_hlnew_printf( HLOG_WARN1, "HWSPRA001W l%05d radius-group %.*(u8)s radius-server %.*(u8)s timed out - no response received",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_raent_act->imc_len_name, adsl_raent_act + 1 );
     if (bol1) {                            /* logic error             */
       m_hlnew_printf( HLOG_WARN1, "HWSPRA002W l%05d radius-group %.*(u8)s radius-server %.*(u8)s logic error - other request found",
                       __LINE__,
                       adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                       adsl_raent_act->imc_len_name, adsl_raent_act + 1 );
     }
   }
   adsl_rreq = ADSL_RCTRL1_G->adsc_rreq;    /* get active radius request */
   adsl_rctrl1_w1 = adsl_radius_group->adsc_rctrl1_queued;  /* no radius control queued */
   while (adsl_rctrl1_w1) {                 /* loop over all queued entries */
     if (adsl_rctrl1_w1->adsc_radius_entry_act == adsl_raent_act) {  /* currently active radius control */
       adsl_rctrl1_w1->adsc_radius_entry_act = NULL;  /* we try all radius servers */
       adsl_rctrl1_w1->ilc_marked = 0;      /* marked radius-servers   */
     }
     adsl_rctrl1_w1 = adsl_rctrl1_w1->adsc_rctrl1_queued;  /* get next queued entry */
   }
   if (adsl_rreq) {                         /* active radius request found */
     ADSL_RCTRL1_G->adsc_radius_entry_act = NULL;  /* active radius entry / single radius server */
     bol1 = m_radius_request( ADSL_RCTRL1_G, adsl_rreq );
     if (bol1 == FALSE) {                   /* could not find other radius server */
       ADSL_RCTRL1_G->ilc_marked = 0;       /* marked radius-servers   */
       adsl_rreq->iec_radius_resp = ied_rar_error;  /* error, no valid response */
       if (img_wsp_trace_core_flags1 & HL_WT_CORE_RADIUS) {  /* generate WSP trace record */
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data   */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, "CRADIUS4", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id           */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                         "l%05d call amc_radius_query_compl( rctrl1=%p , -1 ) rreq=%p timeout",
                         __LINE__, ADSL_RCTRL1_G, adsl_rreq );
         ADSL_WTR_G1->achc_content          /* content of text / data  */
           = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
         ADSL_WTR_G1->imc_length = iml1;    /* length of text / data   */
#undef ADSL_WTR_G1
         m_wsp_trace_out( adsl_wt1_w1 );    /* output of WSP trace record */
       }
       ADSL_RCTRL1_G->amc_radius_query_compl( ADSL_RCTRL1_G, -1 );  /* callback when radius request complete */
     }
   }
   m_radius_queued( adsl_radius_group );
#undef ADSL_RCTRL1_G
} /* end m_timeout_radius()                                            */

/** activate queued entries                                            */
static void m_radius_queued( struct dsd_radius_group *adsp_radius_group ) {
   BOOL       bol1;                         /* working-variable        */
   int        iml_count;                    /* count entries           */
   int        iml_time;                     /* current time            */
   struct dsd_radius_entry *adsl_raent_act;  /* active radius entry / single radius server */
   struct dsd_radius_control_1 *adsl_rctrl1_w1;  /* working-variable   */
   struct dsd_radius_control_1 *adsl_rctrl1_w2;  /* working-variable   */
   struct dsd_hl_aux_radius_1 *adsl_rreq;   /* radius request          */

   if (adsp_radius_group->adsc_rctrl1_queued == NULL) return;  /* no radius control queued */
   iml_time = (int) time( NULL );           /* current time            */

   p_check_00:                              /* check radius servers    */
   adsl_raent_act = adsp_radius_group->adsc_radius_entry;  /* chain radius entry / single radius server */
   iml_count = 0;                           /* count entries           */
   bol1 = FALSE;                            /* no active query found   */
   do {                                     /* loop over all radius servers */
     if (   (adsl_raent_act->imc_epoch_locked != 0)  /* epoch radius server locked until */
//       && (adsl_raent_act->imc_epoch_locked <= iml_time)) {  /* no more locked */
         && ((adsl_raent_act->imc_epoch_locked - iml_time) <= 0)) {  /* no more locked */
       adsl_raent_act->imc_epoch_locked = 0;  /* unlock radius server  */
     }
     if (adsl_raent_act->imc_epoch_locked == 0) {  /* epoch radius server locked until */
       if (adsl_raent_act->adsc_rc1_active == NULL) {  /* currently active radius control */
         iml_count++;                       /* count entries           */
         break;
       }
       bol1 = TRUE;                         /* active query found      */
     }
     adsl_raent_act = adsl_raent_act->adsc_next;  /* get next in chain */
   } while (adsl_raent_act);
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_radius_queued( %p ) iml_count=%d bol1=%d (some active)",
                   __LINE__, adsp_radius_group, iml_count, bol1 );
#endif
   if (iml_count == 0) {                    /* no entry free           */
     if (bol1) return;                      /* active query found      */
     goto p_act_00;                         /* all queries cannot proceed */
   }
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
   adsl_rctrl1_w1 = adsp_radius_group->adsc_rctrl1_queued;  /* no radius control queued */
   adsl_rctrl1_w2 = NULL;                   /* clear last in chain     */
   while (adsl_rctrl1_w1) {                 /* loop over all queued entries */
#ifdef DEBUG_141102_01                      /* crash Radius            */
     m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_radius_queued() in crit-sect queued HL_THRID=%d adsl_rctrl1_w1=%p.",
                     __LINE__, HL_THRID, adsl_rctrl1_w1 );
#endif
     if (   (adsl_rctrl1_w1->adsc_radius_entry_act == NULL)  /* active radius entry / single radius server */
         || (adsl_rctrl1_w1->adsc_radius_entry_act->adsc_rc1_active == NULL)) {  /* currently active radius control */
       if (adsl_rctrl1_w2 == NULL) {        /* was first in chain      */
         adsp_radius_group->adsc_rctrl1_queued = adsl_rctrl1_w1->adsc_rctrl1_queued;  /* set radius control queued */
         break;
       }
       adsl_rctrl1_w2->adsc_rctrl1_queued = adsl_rctrl1_w1->adsc_rctrl1_queued;  /* set radius control queued */
       break;
     }
     adsl_rctrl1_w2 = adsl_rctrl1_w1;       /* save last one           */
     adsl_rctrl1_w1 = adsl_rctrl1_w1->adsc_rctrl1_queued;  /* get next queued entry */
   }
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_radius_queued( %p ) found queued adsl_rctrl1_w1=%p.",
                   __LINE__, adsp_radius_group, adsl_rctrl1_w1 );
#endif
   if (adsl_rctrl1_w1 == NULL) return;      /* nothing to activate     */
   adsl_rreq = adsl_rctrl1_w1->adsc_rreq;   /* get active radius request */
#ifdef DEBUG_141102_01                      /* crash Radius            */
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_radius_queued() after search HL_THRID=%d adsl_rctrl1_w1=%p adsl_rreq=%p.",
                   __LINE__, HL_THRID, adsl_rctrl1_w1, adsl_rreq );
#endif
   if (adsl_rreq) {                         /* active radius request found */
     bol1 = m_radius_request( adsl_rctrl1_w1, adsl_rreq );
     if (bol1) return;                      /* request activated       */
     adsl_rreq->iec_radius_resp = ied_rar_error;  /* error, no valid response */
     adsl_rctrl1_w1->amc_radius_query_compl( adsl_rctrl1_w1, 2 );  /* callback when radius request complete */
   }
   if (adsp_radius_group->adsc_rctrl1_queued == NULL) return;  /* no radius control queued */
   goto p_check_00;                         /* check radius servers    */

   p_act_00:                                /* all queries cannot proceed */
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
   adsl_rctrl1_w1 = adsp_radius_group->adsc_rctrl1_queued;  /* get radius control queued */
   if (adsl_rctrl1_w1) {                    /* queued entry found      */
     adsp_radius_group->adsc_rctrl1_queued = adsl_rctrl1_w1->adsc_rctrl1_queued;  /* set radius control queued */
   }
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
   if (adsl_rctrl1_w1 == NULL) return;      /* nothing to activate     */
   adsl_rreq = adsl_rctrl1_w1->adsc_rreq;   /* get active radius request */
   if (adsl_rreq) {                         /* active radius request found */
#ifndef B140329
     adsl_rctrl1_w1->adsc_rreq = NULL;      /* no more active radius request */
#endif
     adsl_rreq->iec_radius_resp = ied_rar_error;  /* error, no valid response */
     adsl_rctrl1_w1->amc_radius_query_compl( adsl_rctrl1_w1, 3 );  /* callback when radius request complete */
   }
   if (adsp_radius_group->adsc_rctrl1_queued) {  /* check radius control queued */
     goto p_act_00;                         /* all queries cannot proceed */
   }
   return;
} /* end m_radius_queued()                                             */

/** cleanup Radius request                                             */
extern "C" void m_radius_cleanup( struct dsd_radius_control_1 *adsp_rctrl1 ) {
   BOOL       bol_found;                    /* entry found             */
   struct dsd_radius_group *adsl_radius_group;  /* radius group        */
   struct dsd_radius_entry *adsl_raent_act;  /* active radius entry / single radius server */
   struct dsd_radius_control_1 *adsl_rctrl1_w1;  /* working-variable   */
   struct dsd_radius_control_1 *adsl_rctrl1_w2;  /* working-variable   */

#ifndef B141103
#ifndef HL_UNIX
   Sleep( 200 );
#endif
#endif
#ifdef DEBUG_141102_01                      /* crash Radius            */
   {
     int imt1 = -1;
     if (adsp_rctrl1->adsc_rreq) {
       imt1 = adsp_rctrl1->adsc_rreq->iec_radius_resp;
     }
     m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_radius_cleanup() HL_THRID=%d adsp_rctrl1=%p ->dsc_timer.vpc_chain_2=%p ->adsc_rreq=%p - ->iec_radius_resp=%d.",
                     __LINE__, HL_THRID, adsp_rctrl1, adsp_rctrl1->dsc_timer.vpc_chain_2, adsp_rctrl1->adsc_rreq, imt1 );
   }
#endif
#ifndef B140329
   if (adsp_rctrl1->dsc_timer.vpc_chain_2) {  /* timer still set       */
     m_time_rel( &adsp_rctrl1->dsc_timer );  /* release timer          */
   }
   if (adsp_rctrl1->adsc_rreq == NULL) {    /* no more active radius request */
     return;                                /* nothing to do           */
   }
#endif
   adsl_radius_group = adsp_rctrl1->adsc_radius_group;  /* radius group */
   bol_found = FALSE;                       /* reset entry found       */
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
   adsl_raent_act = adsl_radius_group->adsc_radius_entry;  /* chain radius entry / single radius server */
   do {                                     /* loop over all radius servers */
     if (adsl_raent_act->adsc_rc1_active == adsp_rctrl1) {  /* currently active radius control */
       adsl_raent_act->adsc_rc1_active = NULL;  /* no more currently active radius control */
       bol_found = TRUE;                    /* set entry found         */
       break;
     }
     adsl_raent_act = adsl_raent_act->adsc_next;  /* get next in chain */
   } while (adsl_raent_act);
   while (bol_found == FALSE) {             /* check entry found       */
     adsl_rctrl1_w1 = adsl_radius_group->adsc_rctrl1_queued;  /* get radius control queued */
     if (adsl_rctrl1_w1 == NULL) break;     /* no radius control queued */
     adsl_rctrl1_w2 = NULL;                 /* clear last in chain     */
     while (adsl_rctrl1_w1) {               /* loop over all queued entries */
       if (adsl_rctrl1_w1 == adsp_rctrl1) {  /* active radius entry / single radius server */
         if (adsl_rctrl1_w2 == NULL) {      /* was first in chain      */
           adsl_radius_group->adsc_rctrl1_queued = adsp_rctrl1->adsc_rctrl1_queued;  /* set radius control queued */
           break;
         }
         adsl_rctrl1_w2->adsc_rctrl1_queued = adsp_rctrl1->adsc_rctrl1_queued;  /* set radius control queued */
         break;
       }
       adsl_rctrl1_w2 = adsl_rctrl1_w1;     /* save last one           */
       adsl_rctrl1_w1 = adsl_rctrl1_w1->adsc_rctrl1_queued;  /* get next queued entry */
     }
     break;
   }
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
#ifdef DEBUG_141102_01                      /* crash Radius            */
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-radius-01-l%05d-T m_radius_cleanup() after m_leave() HL_THRID=%d adsp_rctrl1=%p bol_found=%d adsl_radius_group=%p ->adsc_rctrl1_queued=%p.",
                   __LINE__, HL_THRID, adsp_rctrl1, bol_found, adsl_radius_group, adsl_radius_group->adsc_rctrl1_queued );
#endif
   if (bol_found == FALSE) return;          /* check entry found       */
   if (adsl_radius_group->adsc_rctrl1_queued == NULL) return;  /* check radius control queued */
   m_radius_queued( adsl_radius_group );    /* activate queued entries */
} /* end m_radius_cleanup()                                            */

#ifndef HL_UNIX
#ifdef D_CONSOLE_OUT
static void m_console_out( char *achp_buff, int implength ) {
   int        iml1, iml2, iml3, iml4, iml5, iml6;  /* working variables */
   char       byl1;                         /* working-variable        */
   char       chrlwork1[ 76 ];              /* buffer to print         */

   iml1 = 0;
   while (iml1 < implength) {
     iml2 = iml1 + 16;
     if (iml2 > implength) iml2 = implength;
     for ( iml3 = 4; iml3 < 75; iml3++ ) {
       chrlwork1[iml3] = ' ';
     }
     chrlwork1[58] = '*';
     chrlwork1[75] = '*';
     iml3 = 4;
     do {
       iml3--;
       chrlwork1[ iml3 ] = chrstrans[ (iml1 >> ((4 - 1 - iml3) << 2)) & 0X0F ];
     } while (iml3 > 0);
     iml4 = 6;                              /* start hexa digits here  */
     iml5 = 59;                             /* start ASCII here        */
     iml6 = 4;                              /* times normal            */
     do {
       byl1 = achp_buff[ iml1++ ];
       chrlwork1[ iml4++ ] = chrstrans[ (byl1 >> 4) & 0X0F ];
       chrlwork1[ iml4++ ] = chrstrans[ byl1 & 0X0F ];
       iml4++;
       if (byl1 > 0X20) {
         chrlwork1[ iml5 ] = byl1;
       }
       iml5++;
       iml6--;
       if (iml6 == 0) {
         iml4++;
         iml6 = 4;
       }
     } while (iml1 < iml2);
     m_hlnew_printf( HLOG_TRACE1, "%.*s", sizeof(chrlwork1), chrlwork1 );
   }
} /* end m_console_out()                                            */
#endif
#endif
