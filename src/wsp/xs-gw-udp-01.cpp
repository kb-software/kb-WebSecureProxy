//#ifndef HL_UNIX
//#define TRACEHL1
//#define HELP_DEBUG
//#endif
//#define TRACEHL1
#ifdef DEBUG_140118_01                      /* load-balancing problem  */
#define TRACEHL1
#endif
#define CHECK_QUALITY_DOUBLE
#define TRY_140123_01                       /* problem array UDP connections */
//#define SLEEP_RECV_UDP
//#define PROBLEM_HOBPHONE_1003
#ifdef PROBLEM_HOBPHONE_1003
#define D_CONSOLE_OUT
#endif
//#define TRACEHL_100427
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xs-gw-udp-01                                        |*/
/*| -------------                                                     |*/
/*|  Subroutine which manages UDP, Radius and SIP for gateways        |*/
/*|  KB 12.12.07                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|                                                                   |*/
/*| EXPECTED INPUT:                                                   |*/
/*| ---------------                                                   |*/
/*|                                                                   |*/
/*| EXPECTED OUTPUT:                                                  |*/
/*| ----------------                                                  |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

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

#ifdef TRACEHL1
#define TRACEHL_CO_OUT
#endif

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#ifdef XYZ2
#include <conio.h>
#endif
#include <time.h>
#ifdef HL_UNIX
#include <fcntl.h>
#include <poll.h>
#ifdef HL_LINUX
#ifdef B120306
#include <pth.h>
#endif
#include <sys/syscall.h>
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
#include <ws2tcpip.h>
//#include <wspiapi.h>
#include <hob-wtspo1.h>
#endif
#define EXT_BASE64
#include <hob-tab-mime-base64.h>
#include <hob-xslunic1.h>
#ifndef HL_UNIX
#include <hob-thread.hpp>
#include <iswcord1.h>
#endif
//#include "hob-hlwspat2.h"
#include <hob-wspsu1.h>
#include <hob-avl03.h>

#define DOMNode void

#define DEF_HL_INCL_DOM
#include "hob-xsclib01.h"

#include <hob-netw-01.h>
#include "hob-wsppriv.h"                    /* privileges              */
#define HOB_CONTR_TIMER
#include <hob-xslcontr.h>                   /* HOB Control             */
//#define INCL_GW_ALL
#define D_INCL_AUX_UDP
#include "hob-xbipgw08-1.h"
#include "hob-xbipgw08-2.h"

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

/*+-------------------------------------------------------------------+*/
/*| Internal used structures.                                         |*/
/*+-------------------------------------------------------------------+*/

struct dsd_udp_socket_1 {                   /* structure UDP socket    */
   struct dsd_udp_socket_1 *adsc_next;      /* for chaining            */
   struct dsd_udp_multiw_1 dsc_udp_multiw_1;  /* active receive        */
   struct sockaddr_storage dsc_soa_bind;    /* address information bind */
};

struct dsd_udp_gw_1 {                       /* structure UDP for gateway */
#ifdef B160705
   struct dsd_conn1 *adsc_conn1;                  /* connection              */
#endif
   DSD_CONN_G *adsc_conn1;                  /* connection              */
   int        imc_signal;                   /* signal to set           */
   void *     vpc_userfld;                  /* userfield               */
   struct dsd_sdh_control_1 *adsc_sdhc1_rb;  /* chain of receive buffers */
};

struct dsd_udp_recv_thr {                   /* thread to do UDP receive */
   struct dsd_udp_recv_thr *adsc_next;      /* chain                   */
#ifndef TRY_140123_01                       /* problem array UDP connections */
   int        imc_active;                   /* active receives         */
   int        imc_receive;                  /* number of receives      */
#else
   volatile int imc_active;                 /* active receives         */
   volatile int imc_receive;                /* number of receives      */
#endif
#ifndef HL_UNIX
   HANDLE     dsrc_hand_thr[ 1 + DEF_MAX_MULT_TH ];  /* handles for wait */
#else
   int        imc_fd_pipe_write;            /* file-descriptor write to file */
   struct pollfd dsrc_poll[ 1 + DEF_MAX_MULT_TH ];  /* for poll()      */
#endif
   struct dsd_udp_multiw_1 *adsrc_udp_multiw_1[ DEF_MAX_MULT_TH ];  /* active receives */
   class dsd_hcthread dsc_hcthread;         /* thread UDP Receive mult */
};

struct dsd_sip_gw_1 {                       /* structure for a SIP gateway */
   struct dsd_sip_gw_1 *adsc_next;          /* next in chain           */
   int        imc_len_ineta_sip_gw;         /* length INETA SIP gateway */
   struct dsd_htree1_avl_cntl dsc_htree1_avl_cntl;  /* control area tree */
};

struct dsd_sip_entry_1 {                    /* structure for a SIP entry */
   int        imc_len_sip_ident;            /* length SIP ident in bytes UTF-8 */
   int        imc_signal;                   /* signal to set           */
#ifdef B160705
   struct dsd_conn1 *adsc_conn1;                  /* connection              */
#endif
   DSD_CONN_G *adsc_conn1;                  /* connection              */
   struct dsd_sdh_control_1 *adsc_sdhc1_rb;  /* chain of receive buffers */
   struct dsd_sip_gw_1 *adsc_sip_gw_1;      /* structure for a SIP gateway */
   struct dsd_htree1_avl_entry dsc_sort_1;  /* entry for sorting       */
};

struct dsd_udp_gate_sort_1 {                /* structure for a UDP-gate sort */
   struct dsd_htree1_avl_entry dsc_sort_1;  /* entry for sorting       */
   char       chrc_nonce[ DEF_LEN_UDP_GATE_NONCE ];  /* the nonce      */
};

struct dsd_udp_gate_subch_sort_1 {          /* structure for a UDP-gate subchannel sort */
   struct dsd_htree1_avl_entry dsc_sort_1;  /* entry for sorting       */
   struct dsd_uga_subch_s_field {           /* field for compare       */
     char       chrc_nonce[ DEF_LEN_UDP_GATE_NONCE ];  /* the nonce    */
     unsigned char ucc_subchannel_id;       /* subchannel Id           */
   } dsc_uga_subch_s_field;
};

/**
   struct dsd_udp_gate_entry_1 is append to the connection thru struct dsd_auxf_1.
   When the SDH (Server-Data-Hook) deletes this entry, boc_deleted is set.
   struct dsd_udp_gate_entry_1 is needed at the end of the connection
   for statistics.
*/
struct dsd_udp_gate_entry_1 {               /* structure for a UDP-gate entry */
   struct dsd_udp_gate_sort_1 dsc_ug_sort;  /* structure for a UDP-gate sort */
   BOOL       boc_deleted;                  /* the entry is deleted    */
   int        imc_len_soa_client;           /* length address information client */
   struct sockaddr_storage dsc_soa_client;  /* address information client */
   int        imc_c_udp_rece;               /* count receive UDP       */
   int        imc_c_udp_send;               /* count send UDP          */
   HL_LONGLONG ilc_d_udp_rece;              /* data receive UDP        */
   HL_LONGLONG ilc_d_udp_send;              /* data send UDP           */
};

struct dsd_uga_subch_1 {                    /* UDP-gate subchannel     */
   struct dsd_udp_gate_subch_sort_1 dsc_uga_subch_s1;  /* structure for a UDP-gate subchannel sort */
   struct dsd_udp_gate_entry_1 *adsc_udp_gate_entry_1;  /* structure for a UDP-gate entry */
   void *     vpc_udpr_handle;              /* handle of UDP associated request */
   BOOL       boc_subch_srtp;               /* SRTP is used            */
   struct sockaddr_storage dsc_subch_sockaddr;  /* sockaddr structure subchannel */
};

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

static struct dsd_udp_socket_1 * m_create_udp_socket_1( struct sockaddr_storage *, amd_udp_recv_compl );
static void m_gw_sip_start( void );
static void m_aux_close_udp_entry( void *, struct dsd_udp_multiw_1 * );
static void m_udp_gate_srtp_encry( struct dsd_hco_wothr *, void *, void *, void * );
static void m_udp_gate_srtp_decry( struct dsd_hco_wothr *, void *, void *, void * );
static void m_close_udp_recv( struct dsd_udp_multiw_1 * );
static void m_cb_gate_recv( struct dsd_udp_multiw_1 *, struct dsd_sdh_control_1 * );
static void m_cb_rtp_sip_gw_recv( struct dsd_udp_multiw_1 *, struct dsd_sdh_control_1 * );
static void m_cb_srtp_recv( struct dsd_udp_multiw_1 *, struct dsd_sdh_control_1 * );
static void m_cb_none_recv( struct dsd_udp_multiw_1 *, struct dsd_sdh_control_1 * );
static void m_cb_udp_recv( struct dsd_udp_multiw_1 *, struct dsd_sdh_control_1 * );
static void m_cb_sip_ipv4_recv( struct dsd_udp_multiw_1 *, struct dsd_sdh_control_1 * );
static void m_close_sip_entry( void *, struct dsd_sip_entry_1 * );
static int m_cmp_sip_ident( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static int m_cmp_udp_gate_main( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static int m_cmp_udp_gate_subch( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static htfunc1_t m_udp_recv_thread( void * );
#ifdef D_CONSOLE_OUT
static void m_console_out( char *achp_buff, int implength );
static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
#endif
#ifdef TRACEHL1
static void m_display_udp( int imp_line, char *achp_text );
#endif

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

static class dsd_hcla_critsect_1 dss_critsect_udp;  /* critical section for UDP */

static struct dsd_udp_socket_1 *adss_udp_socket_1_ch = NULL;  /* chain of UDP sockets */

static struct dsd_udp_recv_thr *adss_udp_recv_thr_a = NULL;  /* anchor threads to do UDP receive */
static struct dsd_udp_socket_1 *adss_udp_socket_1_udp_gate_ipv4 = NULL;  /* UDP-gate IPV4 */
static struct dsd_udp_socket_1 *adss_udp_socket_1_udp_gate_ipv6 = NULL;  /* UDP-gate IPV6 */
static struct dsd_sip_gw_1 *adss_sip_gw_1_a = NULL;  /* anchor SIP gateways */

static struct dsd_udp_multiw_1 dss_udp_multiw_1_sip_ipv4;  /* SIP IPV4 */

static int    ims_sip_last_try;             /* time last try start SIP */

static struct sockaddr_storage dss_sip_v4_soa;  /* INETA SIP IPV4      */
static socklen_t ims_sip_v4_len_soa;        /* length address information */

static struct dsd_htree1_avl_cntl dss_htree1_avl_cntl_udp_gate_m;  /* control area tree */
static struct dsd_htree1_avl_cntl dss_htree1_avl_cntl_udp_gate_subch;  /* control area tree */

#ifdef HL_UNIX
static int    ims_write_pipe_recv = 0;      /* write to pipe for receive */
#endif

static const unsigned char ucrs_sip_resp[] = {
   'S', 'I', 'P', '/'
};

static const unsigned char ucrs_sip_to[] = {
   'T', 'o', ':'
};

static const unsigned char ucrs_sip_from[] = {
   'F', 'r', 'o', 'm', ':'
};

static const unsigned char ucrs_sip_ident[] = {
   '<', 's', 'i', 'p', ':'
};

static const unsigned char ucrs_udp_gate_header[] = {
   'H', 'O', 'B', '-', 'W', 'S', 'P', ' '
};

static const unsigned char ucrs_tab_inp_rfc_3986[256] = {

/*         0     1     2     3     4     5     6     7                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0 DOS    */

/*         8     9     A     B     C     D     E     F                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0X08 - 0X0F */

/*         0     1     2     3     4     5     6     7                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0X10 - 0X17 */

/*         8     9     A     B     C     D     E     F                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0X18 - 0X1F */

/*         0     1     2     3     4     5     6     7                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X01, 0X00, 0X00,   /* 0X20 - 0X27 */
/*                                       %                             */

/*         8     9     A     B     C     D     E     F                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0X28 - 0X2F */

/*         0     1     2     3     4     5     6     7                 */
         0X01, 0X01, 0X01, 0X01, 0X01, 0X01, 0X01, 0X01,   /* 0X30 - 0X37 */
/*         0     1     2     3     4     5     6     7                 */

/*         8     9     A     B     C     D     E     F                 */
         0X01, 0X01, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0X38 - 0X3F */
/*         8     9                                                     */

/*         0     1     2     3     4     5     6     7                 */
         0X00, 0X01, 0X01, 0X01, 0X01, 0X01, 0X01, 0X01,   /* 0X40 - 0X47 */
/*               A     B     C     D     E     F     G                 */

/*         8     9     A     B     C     D     E     F                 */
         0X01, 0X01, 0X01, 0X01, 0X01, 0X01, 0X01, 0X01,   /* 0X48 - 0X4F */
/*         H     I     J     K     L     M     N     O                 */

/*         0     1     2     3     4     5     6     7                 */
         0X01, 0X01, 0X01, 0X01, 0X01, 0X01, 0X01, 0X01,   /* 0X50 - 0X57 */
/*         P     Q     R     S     T     U     V     W                 */

/*         8     9     A     B     C     D     E     F                 */
         0X01, 0X01, 0X01, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0X58 - 0X5F */
/*         X     Y     Z                                               */

/*         0     1     2     3     4     5     6     7                 */
         0X00, 0X01, 0X01, 0X01, 0X01, 0X01, 0X01, 0X01,   /* 0X60 - 0X67 */
/*               a     b     c     d     e     f     g                 */

/*         8     9     A     B     C     D     E     F                 */
         0X01, 0X01, 0X01, 0X01, 0X01, 0X01, 0X01, 0X01,   /* 0X68 - 0X6F */
/*         h     i     j     k     l     m     n     o                 */

/*         0     1     2     3     4     5     6     7                 */
         0X01, 0X01, 0X01, 0X01, 0X01, 0X01, 0X01, 0X01,   /* 0X70 - 0X77 */
/*         p     q     r     s     t     u     v     w                 */

/*         8     9     A     B     C     D     E     F                 */
         0X01, 0X01, 0X01, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0X78 - 0X7F */
/*         x     y     z                                               */

/*         0     1     2     3     4     5     6     7                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0X80 - 0X87 */

/*         8     9     A     B     C     D     E     F                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0X88 - 0X8F */

/*         0     1     2     3     4     5     6     7                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0X90 - 0X97 */

/*         8     9     A     B     C     D     E     F                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0X98 - 0X9F */

/*         0     1     2     3     4     5     6     7                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0XA0 - 0XA7 */

/*         8     9     A     B     C     D     E     F                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0XA8 - 0XAF */

/*         0     1     2     3     4     5     6     7                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0XB0 - 0XB7 */

/*         8     9     A     B     C     D     E     F                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0XB8 - 0XBF */

/*         0     1     2     3     4     5     6     7                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0XC0 - 0XC7 */

/*         8     9     A     B     C     D     E     F                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0XC8 - 0XCF */

/*         0     1     2     3     4     5     6     7                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0XD0 - 0XD7 */

/*         8     9     A     B     C     D     E     F                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0XD8 - 0XDF */

/*         0     1     2     3     4     5     6     7                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0XE0 - 0XE7 */

/*         8     9     A     B     C     D     E     F                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0XE8 - 0XEF */

/*         0     1     2     3     4     5     6     7                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,   /* 0XF0 - 0XF7 */

/*         8     9     A     B     C     D     E     F                 */
         0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00    /* 0XF8 - 0XFF */

};

#ifdef PROBLEM_HOBPHONE_1003
static int ims_count_recv_sip = 0;
#endif

/*+-------------------------------------------------------------------+*/
/*| Procedure division.                                               |*/
/*+-------------------------------------------------------------------+*/

/** called at starting the gateway to initialize SIP and UDP           */
extern "C" void m_gw_udp_start( void ) {
   int        iml_rc;                       /* return code             */
   BOOL       bol1;                         /* working variable        */

#ifndef HL_UNIX
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-udp-01 m_gw_udp_start() called sizeof(adss_udp_recv_thr_a->dsrc_hand_thr)=%d sizeof(adss_udp_recv_thr_a->adsrc_udp_multiw_1)=%d.",
                   __LINE__, sizeof(adss_udp_recv_thr_a->dsrc_hand_thr), sizeof(adss_udp_recv_thr_a->adsrc_udp_multiw_1) );
#endif
#endif
   iml_rc = dss_critsect_udp.m_create();
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_gw_udp_start() dss_critsect_udp m_create return code %d.",
                     __LINE__, iml_rc );
   }
   if (adsg_loconf_1_inuse->dsc_sip_l_ineta.boc_bind_needed) {  /* flag bind() is needed */
     m_gw_sip_start();                      /* prepare SIP             */
   } else {                                 /* start SIP later         */
     ims_sip_last_try = ((int) time( NULL )) - DEF_RETRY_START_SIP;  /* time last try start SIP */
   }
   bol1 = m_htree1_avl_init( NULL,
                             &dss_htree1_avl_cntl_udp_gate_m,
                             &m_cmp_udp_gate_main );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_gw_udp_start() m_htree1_avl_init() init tree UDP-gate main failed",
                     __LINE__ );
   }
   bol1 = m_htree1_avl_init( NULL,
                             &dss_htree1_avl_cntl_udp_gate_subch,
                             &m_cmp_udp_gate_subch );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_gw_udp_start() m_htree1_avl_init() init tree UDP-gate sub-channel failed",
                     __LINE__ );
   }
} /* end m_gw_udp_start()                                              */

/** end of UDP and SIP processing                                      */
extern "C" void m_gw_udp_end( void ) {
} /* end m_gw_udp_end()                                                */
#ifdef XYZ1
   iml_rc = dss_critsect_cluster.m_create();
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPM0xxW l%05d m_cluster_start() dss_critsect_cluster m_create Return Code %d",
                     __LINE__, iml_rc );
   }
#endif

/** called at starting the gateway to initialize SIP and UDP           */
extern "C" void m_gw_udp_update( struct dsd_loconf_1 *adsg_loconf_1_new ) {
   struct dsd_udp_socket_1 *adsl_udp_socket_1_w1;  /* working variable */
   struct dsd_snmp_trap_target *adsl_stt_w1;  /* <trap-target>         */
#ifdef XYZ1
   struct sockaddr_storage *adsl_soa_w1;    /* working variable        */
#endif
   struct sockaddr_storage dsl_soa_bind;    /* address information bind */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "l%05d xs-gw-udp-01 m_gw_udp_update( %p ) called",
                   __LINE__, adsg_loconf_1_new );
#endif
   if (adsg_loconf_1_new->imc_udp_gate_ipv4_port > 0) {  /* UDP port IPV4 */
     if (adsg_loconf_1_new->dsc_udp_gate_ineta.boc_ipv4) {  /* IPV4 is supported */
       memcpy( &dsl_soa_bind,
               &adsg_loconf_1_new->dsc_udp_gate_ineta.dsc_soai4,  /* address information IPV4 */
               sizeof(struct sockaddr_in) );
     } else {
       memset( &dsl_soa_bind, 0, sizeof(struct sockaddr_storage) );
       ((sockaddr_in *) &dsl_soa_bind)->sin_family = AF_INET;
     }
     ((sockaddr_in *) &dsl_soa_bind)->sin_port
       = m_ip_htons( adsg_loconf_1_new->imc_udp_gate_ipv4_port );
     adss_udp_socket_1_udp_gate_ipv4 = m_create_udp_socket_1( &dsl_soa_bind, &m_cb_gate_recv );
   }
   if (adsg_loconf_1_new->imc_udp_gate_ipv6_port > 0) {  /* UDP port IPV4 */
     if (adsg_loconf_1_new->dsc_udp_gate_ineta.boc_ipv6) {  /* IPV6 is supported */
       memcpy( &dsl_soa_bind,
               &adsg_loconf_1_new->dsc_udp_gate_ineta.dsc_soai6,  /* address information IPV6 */
               sizeof(struct sockaddr_in6) );
     } else {
       memset( &dsl_soa_bind, 0, sizeof(struct sockaddr_storage) );
       ((sockaddr_in6 *) &dsl_soa_bind)->sin6_family = AF_INET6;
     }
     ((sockaddr_in6 *) &dsl_soa_bind)->sin6_port
       = m_ip_htons( adsg_loconf_1_new->imc_udp_gate_ipv6_port );
     adss_udp_socket_1_udp_gate_ipv6 = m_create_udp_socket_1( &dsl_soa_bind, &m_cb_gate_recv );
   }
   if (adsg_loconf_1_new->adsc_snmp_conf == NULL) return;  /* no SNMP configuration */
   adsl_stt_w1 = adsg_loconf_1_new->adsc_snmp_conf->adsc_snmp_trap_target;  /* chain of <trap-target> */
   while (adsl_stt_w1) {                    /* loop over all trap-targets */
     adsl_udp_socket_1_w1
       = m_create_udp_socket_1( &adsl_stt_w1->dsc_udp_param_1.dsc_soa_bind,
                                &m_cb_none_recv );
// to-do 02.08.10 KB set socket
     if (adsl_udp_socket_1_w1) {            /* socket exists           */
       adsl_stt_w1->imc_socket = adsl_udp_socket_1_w1->dsc_udp_multiw_1.imc_socket;  /* UDP socket for sendto() */
     }
     adsl_stt_w1 = adsl_stt_w1->adsc_next;  /* get next in chain       */
   }
} /* end m_gw_udp_update()                                             */

/** we need a struct dsd_udp_socket_1                                  */
static struct dsd_udp_socket_1 * m_create_udp_socket_1( struct sockaddr_storage *adsp_soa_bind,
                                                        amd_udp_recv_compl amp_udp_recv_compl ) {
#ifdef HL_UNIX
   int        iml1;                         /* working variable        */
#endif
   int        iml_rc;                       /* return code             */
   int        iml_soa_len;                  /* length of struct sockaddr */
   int        iml_cmp_pos;                  /* position to compare     */
   int        iml_cmp_len;                  /* length to compare       */
   int        iml_cmp_port;                 /* position of port        */
   struct dsd_udp_socket_1 *adsl_udp_socket_1_w1;  /* working variable */

   switch (adsp_soa_bind->ss_family) {
     case AF_INET:                          /* IPV4                    */
       iml_soa_len = sizeof(struct sockaddr_in);  /* length of struct sockaddr */
       iml_cmp_pos = offsetof( struct sockaddr_in, sin_addr );  /* position to compare */
       iml_cmp_len = 4;                     /* length to compare       */
       iml_cmp_port = offsetof( struct sockaddr_in, sin_port );  /* position of port */
       break;
     case AF_INET6:                         /* IPV6                    */
       iml_soa_len = sizeof(struct sockaddr_in6);  /* length of struct sockaddr */
       iml_cmp_pos = offsetof( struct sockaddr_in6, sin6_addr );  /* position to compare */
       iml_cmp_len = 16;                    /* length to compare       */
       iml_cmp_port = offsetof( struct sockaddr_in6, sin6_port );  /* position of port */
       break;
     default:
       return NULL;
   }
   adsl_udp_socket_1_w1 = adss_udp_socket_1_ch;  /* get chain of UDP sockets */
   while (adsl_udp_socket_1_w1) {           /* loop over all UDP sockets */
#ifdef XYZ1
     if (   (adsl_udp_socket_1_w1->dsc_soa_bind.ss_family == adsp_soa_bind->ss_family)
         && (!memcmp( &adsl_udp_socket_1_w1->dsc_soa_bind, adsp_soa_bind, iml_soa_len ))) {
       if (adsl_udp_socket_1_w1->dsc_udp_multiw_1.amc_udp_recv_compl == amp_udp_recv_compl) {
         return adsl_udp_socket_1_w1;       /* this value found        */
       }
       if (amp_udp_recv_compl == &m_cb_none_recv) {
         return adsl_udp_socket_1_w1;       /* this value found        */
       }
       adsl_udp_socket_1_w1->dsc_udp_multiw_1.amc_udp_recv_compl = amp_udp_recv_compl;
       return adsl_udp_socket_1_w1;         /* this value found        */
     }
#endif
     while (   (adsl_udp_socket_1_w1->dsc_soa_bind.ss_family == adsp_soa_bind->ss_family)
            && (!memcmp( (char *) &adsl_udp_socket_1_w1->dsc_soa_bind + iml_cmp_pos,
                         (char *) adsp_soa_bind + iml_cmp_pos,
                         iml_cmp_len ))) {
       if (*((unsigned short int *) ((char *) &adsl_udp_socket_1_w1->dsc_soa_bind + iml_cmp_port))
             != (*((unsigned short int *) ((char *) adsp_soa_bind + iml_cmp_port)))) {
         if (*((unsigned short int *) ((char *) adsp_soa_bind + iml_cmp_port))) break;
       }
       if (adsl_udp_socket_1_w1->dsc_udp_multiw_1.amc_udp_recv_compl == amp_udp_recv_compl) {
         return adsl_udp_socket_1_w1;       /* this value found        */
       }
       if (amp_udp_recv_compl == &m_cb_none_recv) {
         return adsl_udp_socket_1_w1;       /* this value found        */
       }
       adsl_udp_socket_1_w1->dsc_udp_multiw_1.amc_udp_recv_compl = amp_udp_recv_compl;
       return adsl_udp_socket_1_w1;         /* this value found        */
     }
     adsl_udp_socket_1_w1 = adsl_udp_socket_1_w1->adsc_next;  /* get next in chain */
   }
   adsl_udp_socket_1_w1 = (struct dsd_udp_socket_1 *) malloc( sizeof(struct dsd_udp_socket_1) );
   memcpy( &adsl_udp_socket_1_w1->dsc_soa_bind, adsp_soa_bind, sizeof(struct sockaddr_storage) );
   memset( &adsl_udp_socket_1_w1->dsc_udp_multiw_1, 0, sizeof(struct dsd_udp_multiw_1) );  /* active receive */
   adsl_udp_socket_1_w1->dsc_udp_multiw_1.imc_socket = m_ip_socket( adsp_soa_bind->ss_family, SOCK_DGRAM, 0 );
   if (adsl_udp_socket_1_w1->dsc_udp_multiw_1.imc_socket < 0) {  /* error occured */
#ifndef HL_UNIX
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_create_udp_socket_1() socket() Return Code %d/%d.",
                     __LINE__, adsl_udp_socket_1_w1->dsc_udp_multiw_1.imc_socket, m_ip_wsaglerr() );
#else
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_create_udp_socket_1() socket() Return Code %d/%d.",
                     __LINE__, adsl_udp_socket_1_w1->dsc_udp_multiw_1.imc_socket, errno );
#endif
     return NULL;                           /* could not create socket */
   }
   iml_rc = m_ip_bind( adsl_udp_socket_1_w1->dsc_udp_multiw_1.imc_socket,
                       (struct sockaddr *) adsp_soa_bind, iml_soa_len );
   if (iml_rc) {                            /* error occured           */
#ifndef HL_UNIX
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_create_udp_socket_1() bind() return code %d/%d.",
                     __LINE__, iml_rc, m_ip_wsaglerr() );
#else
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_create_udp_socket_1() bind() return code %d/%d.",
                     __LINE__, iml_rc, errno );
#endif
     D_TCP_CLOSE( adsl_udp_socket_1_w1->dsc_udp_multiw_1.imc_socket );
     return NULL;                           /* could not bind socket   */
   }
#ifndef HL_UNIX
   adsl_udp_socket_1_w1->dsc_udp_multiw_1.dsc_event = m_ip_wsaevent();  /* create event for recv */
   if (adsl_udp_socket_1_w1->dsc_udp_multiw_1.dsc_event == WSA_INVALID_EVENT) {
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_create_udp_socket_1() WSAEvent Return Code %d.",
                     __LINE__, m_ip_wsaglerr() );
     D_TCP_CLOSE( adsl_udp_socket_1_w1->dsc_udp_multiw_1.imc_socket );
     return NULL;                           /* could not create event  */
   }
   iml_rc = WSAEventSelect( adsl_udp_socket_1_w1->dsc_udp_multiw_1.imc_socket,
                            adsl_udp_socket_1_w1->dsc_udp_multiw_1.dsc_event,
                            FD_WRITE | FD_READ | FD_CLOSE );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_create_udp_socket_1() WSAEventSelect Return Code %d/%d.",
                     __LINE__, iml_rc, m_ip_wsaglerr() );
     WSACloseEvent( adsl_udp_socket_1_w1->dsc_udp_multiw_1.dsc_event );
     D_TCP_CLOSE( adsl_udp_socket_1_w1->dsc_udp_multiw_1.imc_socket );
     return NULL;                           /* could not select event  */
   }
#endif
#ifdef HL_UNIX
   /* set the UDP socket to non-blocking                               */
   iml1 = fcntl( adsl_udp_socket_1_w1->dsc_udp_multiw_1.imc_socket, F_GETFL, 0 );
   iml_rc = fcntl( adsl_udp_socket_1_w1->dsc_udp_multiw_1.imc_socket, F_SETFL, iml1 | O_NONBLOCK );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_create_udp_socket_1() fcntl() return code %d/%d.",
                     __LINE__, iml_rc, errno );
   }
#endif
   adsl_udp_socket_1_w1->dsc_udp_multiw_1.amc_udp_recv_compl = amp_udp_recv_compl;
   m_start_udp_recv( &adsl_udp_socket_1_w1->dsc_udp_multiw_1 );

   adsl_udp_socket_1_w1->adsc_next = adss_udp_socket_1_ch;  /* get chain of UDP sockets */
   adss_udp_socket_1_ch = adsl_udp_socket_1_w1;  /* set new chain of UDP sockets */
   return adsl_udp_socket_1_w1;
} /* end m_create_udp_socket_1()                                       */

/** start SIP UDP gateway connection                                   */
static void m_gw_sip_start( void ) {
   int        iml_rc;                       /* return code             */
   struct hostent *adsl_hostentry;
   struct sockaddr_storage dsl_soa_bind;    /* bind address information */
   char       chrl_work1[ 256 ];            /* work area               */

   /* prepare SIP                                                      */
   memset( &dss_udp_multiw_1_sip_ipv4, 0, sizeof(struct dsd_udp_multiw_1) );
   dss_udp_multiw_1_sip_ipv4.amc_udp_recv_compl = m_cb_sip_ipv4_recv;  /* callback when receive complete */
   dss_udp_multiw_1_sip_ipv4.imc_socket = m_ip_socket( AF_INET, SOCK_DGRAM, 0 );
   if (dss_udp_multiw_1_sip_ipv4.imc_socket < 0) {  /* error occured   */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_gw_sip_start() SIP IPV4 socket() Return Code %d/%d.",
                     __LINE__, dss_udp_multiw_1_sip_ipv4.imc_socket, D_TCP_ERROR );
     goto psipst_err_00;                    /* error occured           */
   }
   if (   (adsg_loconf_1_inuse->dsc_sip_l_ineta.boc_bind_needed)  /* flag bind() is needed */
       && (adsg_loconf_1_inuse->dsc_sip_l_ineta.boc_ipv4)) {  /* IPV4 is supported */
     memcpy( &dsl_soa_bind, &adsg_loconf_1_inuse->dsc_sip_l_ineta.dsc_soai4, sizeof(sockaddr_in) );
   } else {                                 /* do bind to any interface */
     memset( &dsl_soa_bind, 0, sizeof(sockaddr_in) );
     ((sockaddr_in *) &dsl_soa_bind)->sin_family = AF_INET;
   }
   if (adsg_loconf_1_inuse->boc_sip_p5060) {  /* <SIP-use-UDP-port-5060> */
     ((sockaddr_in *) &dsl_soa_bind)->sin_port = m_ip_htons( D_PORT_SIP );
   }
   iml_rc = m_ip_bind( dss_udp_multiw_1_sip_ipv4.imc_socket,
                       (struct sockaddr *) &dsl_soa_bind, sizeof(sockaddr_in) );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_gw_sip_start() SIP IPV4 bind() Return Code %d/%d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
     D_TCP_CLOSE( dss_udp_multiw_1_sip_ipv4.imc_socket );
     goto psipst_err_00;                    /* error occured           */
   }
#ifndef HL_UNIX
   dss_udp_multiw_1_sip_ipv4.dsc_event = m_ip_wsaevent();  /* create event for recv */
   if (dss_udp_multiw_1_sip_ipv4.dsc_event == WSA_INVALID_EVENT) {
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_gw_sip_start() SIP IPV4 WSAEvent Return Code %d.",
                     __LINE__, m_ip_wsaglerr() );
     D_TCP_CLOSE( dss_udp_multiw_1_sip_ipv4.imc_socket );
     goto psipst_err_00;                    /* error occured           */
   }
   iml_rc = WSAEventSelect( dss_udp_multiw_1_sip_ipv4.imc_socket,
                            dss_udp_multiw_1_sip_ipv4.dsc_event,
                            FD_WRITE | FD_READ | FD_CLOSE );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_gw_sip_start() SIP IPV4 WSAEventSelect Return Code %d/%d.",
                     __LINE__, iml_rc, m_ip_wsaglerr() );
     WSACloseEvent( dss_udp_multiw_1_sip_ipv4.dsc_event );
     D_TCP_CLOSE( dss_udp_multiw_1_sip_ipv4.imc_socket );
     goto psipst_err_00;                    /* error occured           */
   }
#endif
   m_start_udp_recv( &dss_udp_multiw_1_sip_ipv4 );
   ims_sip_last_try = 0;                    /* time last try start SIP */
   ims_sip_v4_len_soa = sizeof(dss_sip_v4_soa);  /* set length of area */
   iml_rc = m_ip_getsockname( dss_udp_multiw_1_sip_ipv4.imc_socket,
                              (sockaddr *) &dss_sip_v4_soa,
                              &ims_sip_v4_len_soa );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_gw_sip_start() getsockname() Return Code %d/%d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
     ims_sip_v4_len_soa = 0;                /* no information returned */
     return;                                /* nothing more to do      */
   }
   if (*((UNSIG_MED *) &((struct sockaddr_in *) &dss_sip_v4_soa)->sin_addr)) return;
   /* socket is bound to all INETAs, get one single INETA of this server */
   chrl_work1[0] = 0;
   iml_rc = gethostname( chrl_work1, sizeof(chrl_work1) );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_gw_sip_start() gethostname() Return Code %d/%d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
     return;                                /* nothing more to do      */
   }
   adsl_hostentry = gethostbyname( (char *) chrl_work1 );
   if (adsl_hostentry == NULL) {
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_gw_sip_start() get my own IP address - gethostname( %s ) not valid - error %d.",
                     __LINE__, chrl_work1, D_TCP_ERROR );
     return;                                /* nothing more to do      */
   }
   *((UNSIG_MED *) &((struct sockaddr_in *) &dss_sip_v4_soa)->sin_addr)
     = *((UNSIG_MED *) adsl_hostentry->h_addr_list[ 0 ]);
   return;                                  /* all done                */

   psipst_err_00:                           /* error occured           */
   ims_sip_last_try = (int) time( NULL );   /* time last try start SIP */
   return;                                  /* all done                */
} /* end m_gw_sip_start()                                              */

/** UDP request                                                        */
extern "C" BOOL m_aux_udp_requ_1( void *vpp_userfld, struct dsd_sdh_udp_requ_1 *adsp_udp_r1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working-variables       */
   int        iml_w1, iml_w2;               /* working variables       */
   int        iml_rc;                       /* return code             */
   int        iml_sec_rc;                   /* second return code      */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_sdh_udp_recbuf_1 *adsl_rec_b_cur;  /* current in chain   */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working-variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working-variable       */
   struct dsd_udp_gw_ineta *adsl_udp_gw_ineta_w1;  /* UDP-gw-INETA     */
   struct dsd_sdh_control_1 **aadsl_sdhc1_extra;  /* chain of buffers extra */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   struct sockaddr_storage dsl_soa_bind;    /* bind address information */
   int        iml_no_iov;                   /* number of WSABUF / vector */
   int        iml_len_packet;               /* length of packet        */
#ifndef HL_UNIX
   unsigned int uml_sent;                   /* bytes sent              */
#endif
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
#ifdef XYZ1
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* working variable        */
   WSANETWORKEVENTS dsl_net_events;
   DWORD      dwl_timeout;                  /* timeout for wait multiple */
   WSAEVENT   dsrl_wsaeve[3];               /* for wait multiple       */
#endif
#ifndef HL_UNIX
   WSABUF     dsrl_wsabuf[ DEF_SEND_IOV ];  /* buffer for WSASend()    */
#else
   struct msghdr dsl_msghdr;                /* for sendmsg()           */
   struct iovec dsrl_iov[ DEF_SEND_IOV ];   /* buffer for sendmsg()    */
#endif
   struct dsd_wsp_trace_info_conn1 dsl_wtic;  /* WSP trace information for connection */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-udp-01 m_aux_udp_requ_1( %p ) called iec_sdh_udpr1=%d.",
                   __LINE__, adsp_udp_r1, adsp_udp_r1->iec_sdh_udpr1 );
#endif
   switch (adsp_udp_r1->iec_sdh_udpr1) {    /* depending on command    */
     case ied_sdh_udpr1_register:           /* UDP register entry      */
       goto p_aux_udp_register;             /* UDP register entry      */
     case ied_sdh_udpr1_send:               /* UDP send packet         */
       goto p_aux_udp_send;                 /* send UDP packet         */
     case ied_sdh_udpr1_send_gather:        /* UDP send gather         */
       goto p_aux_udp_se_gai1;              /* send UDP gather         */
     case ied_sdh_udpr1_update_recv:        /* UDP update received packets */
#define ADSL_UDP_MULTIW_1_G ((struct dsd_udp_multiw_1 *) adsp_udp_r1->vpc_udpr_handle)
#define ADSL_UDP_GW_1_G ((struct dsd_udp_gw_1 *) (ADSL_UDP_MULTIW_1_G + 1))
       dss_critsect_udp.m_enter();          /* critical section        */
       adsp_udp_r1->adsc_recb_1 = NULL;
       adsl_sdhc1_w1 = ADSL_UDP_GW_1_G->adsc_sdhc1_rb;
       if (adsl_sdhc1_w1) {                 /* buffers to transfer     */
         aadsl_sdhc1_extra = m_get_sdhc1_extra_from_conn1( ADSL_UDP_GW_1_G->adsc_conn1 );
         ADSL_UDP_GW_1_G->adsc_sdhc1_rb = NULL;  /* all buffers copied */
#ifndef TRY100302
         adsp_udp_r1->adsc_recb_1 = (struct dsd_sdh_udp_recbuf_1 *) (adsl_sdhc1_w1 + 1);
#else
         adsp_udp_r1->adsc_recb_1 = (struct dsd_sdh_udp_recbuf_1 *) ((BOOL *) (adsl_sdhc1_w1 + 1) + 1);
#endif
         adsl_rec_b_cur = NULL;
#ifdef B100426
         while (TRUE) {                     /* loop over all buffers   */
           adsl_sdhc1_w2 = adsl_sdhc1_w1;   /* save this buffer        */
           adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
           adsl_sdhc1_w2->imc_usage_count = 1;
#ifdef TRY100302
           *((BOOL *) (adsl_sdhc1_w2 + 1)) = TRUE;  /* buffer has been given */
#endif
           /* put buffer in chain extra to be freed when no more used  */
           adsl_sdhc1_w2->adsc_next = *aadsl_sdhc1_extra;
           *aadsl_sdhc1_extra = adsl_sdhc1_w2;
           if (adsl_sdhc1_w1 == NULL) break;
           if (adsl_rec_b_cur == NULL) {
             adsl_rec_b_cur = adsp_udp_r1->adsc_recb_1;
           } else {
#ifndef TRY100302
             adsl_rec_b_cur->adsc_next = (struct dsd_sdh_udp_recbuf_1 *) (adsl_sdhc1_w2 + 1);
#else
             adsl_rec_b_cur->adsc_next = (struct dsd_sdh_udp_recbuf_1 *) ((BOOL *) (adsl_sdhc1_w2 + 1) + 1);
#endif
             adsl_rec_b_cur = adsl_rec_b_cur->adsc_next;
           }
         }
#else
         do {                               /* loop over all buffers   */
           adsl_sdhc1_w2 = adsl_sdhc1_w1;   /* save this buffer        */
           adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
           adsl_sdhc1_w2->imc_usage_count = 1;
#ifdef TRY100302
           *((BOOL *) (adsl_sdhc1_w2 + 1)) = TRUE;  /* buffer has been given */
#endif
           /* put buffer in chain extra to be freed when no more used  */
           adsl_sdhc1_w2->adsc_next = *aadsl_sdhc1_extra;
           *aadsl_sdhc1_extra = adsl_sdhc1_w2;
           if (adsl_rec_b_cur == NULL) {
             adsl_rec_b_cur = adsp_udp_r1->adsc_recb_1;
           } else {
#ifndef TRY100302
             adsl_rec_b_cur->adsc_next = (struct dsd_sdh_udp_recbuf_1 *) (adsl_sdhc1_w2 + 1);
#else
             adsl_rec_b_cur->adsc_next = (struct dsd_sdh_udp_recbuf_1 *) ((BOOL *) (adsl_sdhc1_w2 + 1) + 1);
#endif
             adsl_rec_b_cur = adsl_rec_b_cur->adsc_next;
           }
         } while (adsl_sdhc1_w1);
#endif
       }
       dss_critsect_udp.m_leave();          /* critical section        */
       return TRUE;                         /* all done                */
#undef ADSL_UDP_MULTIW_1_G
#undef ADSL_UDP_GW_1_G
     case ied_sdh_udpr1_free_buffer:        /* UDP free buffer(s)      */
       while (adsp_udp_r1->adsc_recb_1) {
#ifndef TRY100302
         ((struct dsd_sdh_control_1 *) adsp_udp_r1->adsc_recb_1 - 1)->imc_usage_count--;
#else
#ifdef B100426
         ((struct dsd_sdh_control_1 *) ((char *) adsp_udp_r1->adsc_recb_1) - sizeof(struct dsd_sdh_control_1) - sizeof(BOOL))->imc_usage_count--;
#else
#ifdef TRACEHL_100427
         {
           char *achh1, *achh2;
           achh1 = (char *) adsp_udp_r1->adsc_recb_1 - sizeof(struct dsd_sdh_control_1) - sizeof(BOOL);
           achh2 = (char *) &((struct dsd_sdh_control_1 *) ((char *) adsp_udp_r1->adsc_recb_1 - sizeof(struct dsd_sdh_control_1) - sizeof(BOOL)))->imc_usage_count;
           m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_aux_udp_requ_1() adsc_recb_1=%p imc_usage_count=%d achh1=%p achh2=%p.",
                           __LINE__,
                           adsp_udp_r1->adsc_recb_1,
                           ((struct dsd_sdh_control_1 *) ((char *) adsp_udp_r1->adsc_recb_1 - sizeof(struct dsd_sdh_control_1) - sizeof(BOOL)))->imc_usage_count,
                           achh1,
                           achh2 );
         }
#endif
         ((struct dsd_sdh_control_1 *) ((char *) adsp_udp_r1->adsc_recb_1 - sizeof(struct dsd_sdh_control_1) - sizeof(BOOL)))->imc_usage_count--;
#endif
#endif
         adsp_udp_r1->adsc_recb_1 = adsp_udp_r1->adsc_recb_1->adsc_next;
       }
       return TRUE;                         /* all done                */
     case ied_sdh_udpr1_close:              /* UDP close               */
#define ADSL_UDP_MULTIW_1_G ((struct dsd_udp_multiw_1 *) adsp_udp_r1->vpc_udpr_handle)
#define ADSL_UDP_GW_1_G ((struct dsd_udp_gw_1 *) (ADSL_UDP_MULTIW_1_G + 1))
       m_aux_close_udp_entry( vpp_userfld, ADSL_UDP_MULTIW_1_G );
#undef ADSL_UDP_MULTIW_1_G
#undef ADSL_UDP_GW_1_G
       return TRUE;                         /* all done                */
   }
   return FALSE;

   p_aux_udp_register:                      /* UDP register entry      */
   if (   (adsp_udp_r1->ac_bind == NULL)    /* name configured bind    */
       || (adsp_udp_r1->imc_len_bind == 0)  /* length bind name in elements */
       || (adsp_udp_r1->iec_chs_bind == ied_chs_invalid)) {  /* character set bind name */
     return FALSE;                          /* error occured           */
   }
   adsl_udp_gw_ineta_w1 = adsg_loconf_1_inuse->adsc_udp_gw_ineta;  /* chain UDP-gw-INETA */
   while (adsl_udp_gw_ineta_w1) {           /* loop over all configured UDP-gw-INETA */
     bol1 = m_cmp_vx_vx( &iml_rc,
                         adsp_udp_r1->ac_bind, adsp_udp_r1->imc_len_bind, adsp_udp_r1->iec_chs_bind,
                         adsl_udp_gw_ineta_w1 + 1, adsl_udp_gw_ineta_w1->imc_len_name, ied_chs_utf_8 );
     if ((iml_rc == 0) && bol1) break;      /* entry found             */
     adsl_udp_gw_ineta_w1 = adsl_udp_gw_ineta_w1->adsc_next;  /* get next in chain */
   }
   if (adsl_udp_gw_ineta_w1 == NULL) return FALSE;  /* entry not configured */
   adsp_udp_r1->vpc_udpr_handle = m_wsp_s_ent_add( vpp_userfld,
                                                   DEF_WSP_TYPE_UDP,
                                                   sizeof(struct dsd_udp_multiw_1)
                                                     + sizeof(struct dsd_udp_gw_1) );
   memset( adsp_udp_r1->vpc_udpr_handle,
           0,
           sizeof(struct dsd_udp_multiw_1) + sizeof(struct dsd_udp_gw_1) );
#define ADSL_UDP_MULTIW_1_G ((struct dsd_udp_multiw_1 *) adsp_udp_r1->vpc_udpr_handle)
#define ADSL_UDP_GW_1_G ((struct dsd_udp_gw_1 *) (ADSL_UDP_MULTIW_1_G + 1))
   ADSL_UDP_GW_1_G->adsc_conn1 = m_get_conn1_from_userfld( vpp_userfld );
   ADSL_UDP_GW_1_G->imc_signal = adsp_udp_r1->imc_signal;
   ADSL_UDP_MULTIW_1_G->amc_udp_recv_compl = m_cb_udp_recv;  /* callback when receive complete */
   ADSL_UDP_MULTIW_1_G->imc_socket = m_ip_socket( AF_INET, SOCK_DGRAM, 0 );
   if (ADSL_UDP_MULTIW_1_G->imc_socket < 0) {  /* error occured        */
// to-do 30.09.08 KB
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_aux_udp_requ_1() %p socket() return code %d.",
                     __LINE__, ADSL_UDP_MULTIW_1_G, D_TCP_ERROR );
   }
   memset( &dsl_soa_bind, 0, sizeof(sockaddr_in) );
   ((sockaddr_in *) &dsl_soa_bind)->sin_family = AF_INET;
   if (   (adsl_udp_gw_ineta_w1->dsc_ineta.boc_bind_needed)
       && (adsl_udp_gw_ineta_w1->dsc_ineta.boc_ipv4)) {  /* IPV4 is supported */
     memcpy( &dsl_soa_bind, &adsl_udp_gw_ineta_w1->dsc_ineta.dsc_soai4, sizeof(sockaddr_in) );
   }
   ((sockaddr_in *) &dsl_soa_bind)->sin_port = m_ip_htons( adsp_udp_r1->imc_port_bind );
// iml_soadlen = sizeof(sockaddr_in);
   iml_rc = m_ip_bind( ADSL_UDP_MULTIW_1_G->imc_socket,
                       (struct sockaddr *) &dsl_soa_bind, sizeof(sockaddr_in) );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_aux_udp_requ_1() %p bind() return code %d/%d.",
                     __LINE__, ADSL_UDP_MULTIW_1_G, iml_rc, D_TCP_ERROR );
   }
   if ((adsp_udp_r1->achc_soa_bind) && (adsp_udp_r1->imc_len_soa_bind > 0)) {
     iml_rc = m_ip_getsockname( ADSL_UDP_MULTIW_1_G->imc_socket,
                                (sockaddr *) adsp_udp_r1->achc_soa_bind,
                                (socklen_t *) &adsp_udp_r1->imc_len_soa_bind );
     if (iml_rc) {                          /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_aux_udp_requ_1() %p getsockname() return code %d/%d.",
                       __LINE__, ADSL_UDP_MULTIW_1_G, iml_rc, D_TCP_ERROR );
       adsp_udp_r1->imc_len_soa_bind = 0;   /* no information returned */
     }
   }
#ifndef HL_UNIX
   ADSL_UDP_MULTIW_1_G->dsc_event = m_ip_wsaevent();  /* create event for recv */
   if (ADSL_UDP_MULTIW_1_G->dsc_event == WSA_INVALID_EVENT) {
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_aux_udp_requ_1() %p WSAEvent Return Code %d.",
                     __LINE__, ADSL_UDP_MULTIW_1_G, m_ip_wsaglerr() );
   }
   iml_rc = WSAEventSelect( ADSL_UDP_MULTIW_1_G->imc_socket,
                            ADSL_UDP_MULTIW_1_G->dsc_event,
                            FD_WRITE | FD_READ | FD_CLOSE );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_aux_udp_requ_1() %p WSAEventSelect Return Code %d/%d.",
                     __LINE__, ADSL_UDP_MULTIW_1_G, iml_rc, m_ip_wsaglerr() );
   }
#endif
   m_start_udp_recv( ADSL_UDP_MULTIW_1_G );
#undef ADSL_UDP_MULTIW_1_G
#undef ADSL_UDP_GW_1_G
   return TRUE;                             /* all done                */

   p_aux_udp_send:                          /* send UDP packet         */
#define ADSL_UDP_MULTIW_1_G ((struct dsd_udp_multiw_1 *) adsp_udp_r1->vpc_udpr_handle)
#define ADSL_UDP_GW_1_G ((struct dsd_udp_gw_1 *) (ADSL_UDP_MULTIW_1_G + 1))
   iml_rc = m_ip_sendto( ADSL_UDP_MULTIW_1_G->imc_socket,
                         adsp_udp_r1->achc_data_send, adsp_udp_r1->imc_len_data_send,
                         0,
                         (sockaddr *) adsp_udp_r1->achc_sockaddr, adsp_udp_r1->imc_len_sockaddr );
#ifndef HL_UNIX
   iml_sec_rc = m_ip_wsaglerr();            /* second return code      */
#else
   iml_sec_rc = errno;                      /* second return code      */
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-udp-01-%05d-T m_aux_udp_requ_1() %p p_aux_udp_send sendto() returned %d/%d.",
                   __LINE__, ADSL_UDP_MULTIW_1_G, iml_rc, D_TCP_ERROR );

#endif
   m_get_wsp_trace_info_conn1( &dsl_wtic, ADSL_UDP_GW_1_G->adsc_conn1 );
   if (dsl_wtic.imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SUDPSEN1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = dsl_wtic.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "UDP data sent length %d/0X%X / sendto returned %d/%d.",
                     adsp_udp_r1->imc_len_data_send, adsp_udp_r1->imc_len_data_send,
                     iml_rc, iml_sec_rc );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (dsl_wtic.imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2)) {  /* generate WSP trace record */
//     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
       achl_w1 = (char *) (((size_t) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml1 = adsp_udp_r1->imc_len_data_send;  /* length of data sent  */
       achl_w3 = adsp_udp_r1->achc_data_send;  /* start of data        */
       adsl_wt1_w2 = adsl_wt1_w1;           /* in this piece of memory */
       adsl_wtr_w1 = ADSL_WTR_G1;           /* set last in chain       */
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
         if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
           adsl_wtr_w1->boc_more = TRUE;    /* more data to follow     */
         }
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
       } while (iml1 > 0);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (iml_rc > 0) {                        /* send successful         */
     m_count_sent_server( ADSL_UDP_GW_1_G->adsc_conn1, adsp_udp_r1->imc_len_data_send );
     return TRUE;                           /* all done                */
   }
   /* error occured                                                    */
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-%05d-T m_aux_udp_requ_1() %p p_aux_udp_send sendto() returned %d/%d.",
                   __LINE__, ADSL_UDP_MULTIW_1_G, iml_rc, iml_sec_rc );
   return TRUE;                             /* all done                */
#undef ADSL_UDP_MULTIW_1_G
#undef ADSL_UDP_GW_1_G

   p_aux_udp_se_gai1:                       /* send UDP gather         */
#define ADSL_UDP_MULTIW_1_G ((struct dsd_udp_multiw_1 *) adsp_udp_r1->vpc_udpr_handle)
#define ADSL_UDP_GW_1_G ((struct dsd_udp_gw_1 *) (ADSL_UDP_MULTIW_1_G + 1))
   iml_no_iov = 0;                          /* clear number of WSABUF / vector */
   iml_len_packet = 0;                      /* clear length of packet  */
   adsl_gai1_w1 = adsp_udp_r1->adsc_gai1_send;  /* gather to send      */
   do {                                     /* loop over all gather structures */
     if (iml_no_iov < DEF_SEND_IOV) {       /* can fill structure      */
#ifndef HL_UNIX
       dsrl_wsabuf[ iml_no_iov ].buf = adsl_gai1_w1->achc_ginp_cur;
       dsrl_wsabuf[ iml_no_iov ].len = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       iml_len_packet += dsrl_wsabuf[ iml_no_iov ].len;  /* increment length of packet */
#else
       dsrl_iov[ iml_no_iov ].iov_base = adsl_gai1_w1->achc_ginp_cur;
       dsrl_iov[ iml_no_iov ].iov_len = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       iml_len_packet += dsrl_iov[ iml_no_iov ].iov_len;  /* increment length of packet */
#endif
     }
     iml_no_iov++;                          /* increment number of WSABUF / vector */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   } while (adsl_gai1_w1);
   if (iml_no_iov > DEF_SEND_IOV) {         /* too many entries structure */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_aux_udp_requ_1() %p ied_sdh_udpr1_send_gather too many gather in chain - %d.",
                     __LINE__, ADSL_UDP_MULTIW_1_G, iml_no_iov );
     return TRUE;                           /* all done                */
   }
#ifndef HL_UNIX
   iml_rc = WSASendTo( ADSL_UDP_MULTIW_1_G->imc_socket,
                       dsrl_wsabuf, iml_no_iov,
                       (DWORD *) &uml_sent, 0,
                       (struct sockaddr *) adsp_udp_r1->achc_sockaddr,
                       adsp_udp_r1->imc_len_sockaddr,
                       NULL, NULL );
   iml_sec_rc = m_ip_wsaglerr();            /* second return code      */
#else
   memset( &dsl_msghdr, 0, sizeof(struct msghdr) );
#ifndef HL_HPUX
   dsl_msghdr.msg_name = (struct sockaddr *) adsp_udp_r1->achc_sockaddr;
#else
   dsl_msghdr.msg_name = (char *) adsp_udp_r1->achc_sockaddr;
#endif
   dsl_msghdr.msg_namelen = adsp_udp_r1->imc_len_sockaddr;
   dsl_msghdr.msg_iov = dsrl_iov;
   dsl_msghdr.msg_iovlen = iml_no_iov;
// dsl_msghdr.msg_flags = 0;
   iml_rc = sendmsg( ADSL_UDP_MULTIW_1_G->imc_socket, &dsl_msghdr, 0 );
   iml_sec_rc = errno;                      /* second return code      */
#endif
   m_get_wsp_trace_info_conn1( &dsl_wtic, ADSL_UDP_GW_1_G->adsc_conn1 );
   if (dsl_wtic.imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SUDPSEN2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = dsl_wtic.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "UDP data sent gather / sendto returned %d/%d.",
                     iml_rc, iml_sec_rc );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     adsl_wt1_w2 = adsl_wt1_w1;             /* last WSP Trace area     */
     adsl_wtr_w1 = ADSL_WTR_G1;             /* set last in chain       */
//   achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
     achl_w1 = (char *) (((size_t) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
     achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
     if (dsl_wtic.imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2)) {  /* generate WSP trace record */
       iml_w1 = iml_w2 = 0;                 /* clear counters          */
       adsl_gai1_w1 = adsp_udp_r1->adsc_gai1_send;  /* get chain data to send */
       do {                                 /* loop over all input gather */
         iml_w1++;                          /* count gather            */
         iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
         if (iml1 > 0) {                    /* data in this gather     */
           if ((achl_w1 + sizeof(struct dsd_wsp_trace_record) + 80) >= achl_w2) {
             adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
             memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
             adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
             adsl_wt1_w2 = adsl_wt1_w3;     /* this is current area    */
             achl_w1 = (char *) (adsl_wt1_w2 + 1);
             achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
           }
           memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
           iml2 = sprintf( (char *) (ADSL_WTR_G2 + 1),
                           "+ SIP send gather-no=%d disp=0X%X addr=0X%X length=%d/0X%X.",
                           iml_w1, iml_w2, adsl_gai1_w1->achc_ginp_cur, iml1, iml1 );
           ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed      */
           ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
           ADSL_WTR_G2->imc_length = iml2;  /* length of text / data   */
           adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain   */
           adsl_wtr_w1 = ADSL_WTR_G2;       /* this is last in chain now */
//         achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
           achl_w1 = (char *) (((size_t) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
           achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* here start binary data */
           do {                             /* loop for output of data */
             iml2 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             if (iml2 <= 0) {               /* we need another area    */
               adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
               memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
               adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
               adsl_wt1_w2 = adsl_wt1_w3;   /* this is current area    */
               achl_w1 = (char *) (adsl_wt1_w2 + 1);
               achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
               iml2 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             }
             if (iml2 > iml1) iml2 = iml1;
             memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
             ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
             achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
             ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
             if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
               adsl_wtr_w1->boc_more = TRUE;  /* more data to follow   */
             }
             adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
             adsl_wtr_w1 = ADSL_WTR_G2;     /* this is last in chain now */
             memcpy( achl_w4, achl_w3, iml2 );
             achl_w3 += iml2;
             ADSL_WTR_G2->imc_length = iml2;  /* length of text / data */
//           achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
             achl_w1 = (char *) (((size_t) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
             iml1 -= iml2;
           } while (iml1 > 0);
           iml_w2 += iml1;                  /* increment displacement  */
         }
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       } while (adsl_gai1_w1);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#ifdef HL_UNIX
#ifndef B150710
   if (iml_rc > 0) iml_rc = 0;
#endif
#endif
   if (iml_rc != 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_aux_udp_requ_1() %p WSASendTo Return Code %d/%d.",
                     __LINE__, ADSL_UDP_MULTIW_1_G, iml_rc, iml_sec_rc );
     return TRUE;                           /* all done                */
   }
   m_count_sent_server( ADSL_UDP_GW_1_G->adsc_conn1, iml_len_packet );
   return TRUE;                             /* all done                */
#undef ADSL_UDP_MULTIW_1_G
#undef ADSL_UDP_GW_1_G
} /* end m_aux_udp_requ_1()                                            */

/** aux UDP cleanup                                                    */
//extern "C" void m_aux_udp_cleanup( struct dsd_conn1 *adsp_conn1, char *achp_ext ) {
extern "C" void m_aux_udp_cleanup( DSD_CONN_G *adsp_conn1, char *achp_ext ) {
#define ADSL_UDP_MULTIW_1_G ((struct dsd_udp_multiw_1 *) achp_ext)
//#define ADSL_UDP_GW_1_G ((struct dsd_udp_gw_1 *) (ADSL_UDP_MULTIW_1_G + 1))
   m_aux_close_udp_entry( NULL, ADSL_UDP_MULTIW_1_G );
#undef ADSL_UDP_MULTIW_1_G
//#undef ADSL_UDP_GW_1_G
} /* end m_aux_udp_cleanup()                                           */

#ifdef B111022
/* UDP sendto                                                          */
extern "C" void m_udp_sendto( struct dsd_udp_multiw_1 *adsp_udp_multiw_1,
                              char *adsp_data, int imp_len_data,
                              sockaddr *adsp_soa, int imp_len_soa ) {
   int        iml_rc;                       /* return code             */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-%05d-T m_udp_sendto( %p , %p , %d , %p , %d )",
                   __LINE__, adsp_udp_multiw_1, adsp_data, imp_len_data, adsp_soa, imp_len_soa );
   fflush( stdout );
#endif
   iml_rc = m_ip_sendto( adsp_udp_multiw_1->imc_socket,
                         adsp_data, imp_len_data,
                         0,
                         adsp_soa, imp_len_soa );
#ifndef HL_UNIX
   if (iml_rc <= 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_udp_sendto() %p sendto return code %d/%d.",
                     __LINE__, adsp_udp_multiw_1, iml_rc, m_ip_wsaglerr() );
   }
#else
   if (iml_rc <= 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_udp_sendto() %p sendto return code %d/%d.",
                     __LINE__, adsp_udp_multiw_1, iml_rc, errno );
   }
#endif
} /* end m_udp_sendto()                                                */
#endif
/** UDP sendto                                                         */
extern "C" int m_udp_sendto( struct dsd_udp_multiw_1 *adsp_udp_multiw_1,
                             char *achp_data, int imp_len_data,
                             struct sockaddr *adsp_soa, int imp_len_soa,
                             int *aimp_error ) {
   BOOL       bol1;                         /* working-variable        */
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* returned error          */
   int        iml1, iml2;                   /* working variables       */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   char       chrl_ineta[ LEN_DISP_INETA ];  /* internet-address char  */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-%05d-T m_udp_sendto( %p , %p , %d , %p , %d , ... )",
                   __LINE__, adsp_udp_multiw_1, achp_data, imp_len_data, adsp_soa, imp_len_soa );
   fflush( stdout );
#endif
   iml_rc = m_ip_sendto( adsp_udp_multiw_1->imc_socket,
                         achp_data, imp_len_data,
                         0,
                         adsp_soa, imp_len_soa );
   if (aimp_error) {                        /* pass error code         */
     *aimp_error = 0;                       /* clear error code        */
     if (iml_rc < 0) {                      /* OS reports error        */
#ifndef HL_UNIX
       *aimp_error = m_ip_wsaglerr();       /* set error code          */
#else
       *aimp_error = errno;                 /* set error code          */
#endif
     }
   }
   iml_error = 0;                           /* clear returned error    */
#ifndef HL_UNIX
   if (iml_rc != imp_len_data) {            /* error occured           */
     iml_error = m_ip_wsaglerr();           /* returned error          */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_udp_sendto() %p sendto return code %d/%d.",
                     __LINE__, adsp_udp_multiw_1, iml_rc, m_ip_wsaglerr() );
   }
#else
   if (iml_rc != imp_len_data) {            /* error occured           */
     iml_error = errno;                     /* returned error          */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_udp_sendto() %p sendto return code %d/%d.",
                     __LINE__, adsp_udp_multiw_1, iml_rc, errno );
   }
#endif
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_UDP) {  /* core UDP receive and send */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     strcpy( chrl_ineta, "???" );           /* if getnameinfo() fails  */
     getnameinfo( adsp_soa, imp_len_soa,
                  chrl_ineta, sizeof(chrl_ineta), 0, 0, NI_NUMERICHOST );
     iml2 = 0;                              /* clear port              */
     switch (adsp_soa->sa_family) {
       case AF_INET:                        /* IPV4                    */
         iml2 = ntohs( ((struct sockaddr_in *) adsp_soa)->sin_port );
         break;
       case AF_INET6:                       /* IPV6                    */
         iml2 = ntohs( ((struct sockaddr_in6 *) adsp_soa)->sin6_port );
         break;
     }
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CUDPSEN1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "UDP data send length %d/0X%X returned %d error %d / destination %s port %d.",
                     imp_len_data, imp_len_data, iml_rc, iml_error,
                     chrl_ineta, iml2 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2)) {  /* generate WSP trace record */
//     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
       achl_w1 = (char *) (((size_t) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml1 = imp_len_data;                 /* length of data to be sent */
       achl_w3 = achp_data;                 /* start of data           */
       adsl_wt1_w2 = adsl_wt1_w1;           /* in this piece of memory */
       adsl_wtr_w1 = ADSL_WTR_G1;           /* set last in chain       */
       bol1 = FALSE;                        /* reset more flag         */
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
         bol1 = TRUE;                       /* set more flag           */
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
       } while (iml1 > 0);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   return iml_rc;
} /* end m_udp_sendto()                                                */

/** UDP send vector                                                    */
extern "C" int m_udp_send_vector( struct dsd_udp_multiw_1 *adsp_udp_multiw_1,
                                  void *adsp_vector, int imp_vector_elements,
                                  struct sockaddr *adsp_soa, int imp_len_soa,
                                  int *aimp_error ) {
   BOOL       bol1;                         /* working-variable        */
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* returned error          */
   int        iml_len;                      /* length of data          */
   int        iml1, iml2, iml3, iml4;       /* working variables       */
#ifndef HL_UNIX
   unsigned int uml_sent;                   /* bytes sent              */
#endif
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4, *achl_w5;  /* working variables */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
#ifdef HL_UNIX
   struct msghdr dsl_msghdr;                /* for sendmsg()           */
#endif
   char       chrl_ineta[ LEN_DISP_INETA ];  /* internet-address char  */
   char       chrl_work1[ 256 ];            /* work area               */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-udp-01-%05d-T m_udp_send_vector( %p , %p , %d , %p , %d , ... )",
                   __LINE__, adsp_udp_multiw_1, adsp_vector, imp_vector_elements, adsp_soa, imp_len_soa );
#endif
#ifndef HL_UNIX
//#define DSRL_WSABUF ((WSABUF *) adsp_vector)
   uml_sent = 0;                            /* no data sent yet        */
   iml_rc = WSASendTo( adsp_udp_multiw_1->imc_socket,
                       (WSABUF *) adsp_vector, imp_vector_elements,
                       (DWORD *) &uml_sent, 0,
                       adsp_soa, imp_len_soa,
                       NULL, NULL );
   iml_error = m_ip_wsaglerr();             /* second return code      */
#else
   memset( &dsl_msghdr, 0, sizeof(struct msghdr) );
#ifndef HL_HPUX
   dsl_msghdr.msg_name = adsp_soa;
#else
   dsl_msghdr.msg_name = (char *) adsp_soa;
#endif
   dsl_msghdr.msg_namelen = imp_len_soa;
   dsl_msghdr.msg_iov = (struct iovec *) adsp_vector,
   dsl_msghdr.msg_iovlen = imp_vector_elements;
// dsl_msghdr.msg_flags = 0;
   iml_rc = sendmsg( adsp_udp_multiw_1->imc_socket, &dsl_msghdr, 0 );
   iml_error = errno;                       /* second return code      */
#endif
   if (aimp_error) {                        /* pass error code         */
     *aimp_error = 0;                       /* clear error code        */
     if (iml_rc < 0) {                      /* OS reports error        */
       *aimp_error = iml_error;             /* set error code          */
     }
   }
#ifndef HL_UNIX
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_udp_send_vector() %p WSASendTo return code %d/%d.",
                     __LINE__, adsp_udp_multiw_1, iml_rc, iml_error );
   }
#else
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_udp_send_vector() %p sendmsg return code %d/%d.",
                     __LINE__, adsp_udp_multiw_1, iml_rc, iml_error );
   }
#endif
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_UDP) {  /* core UDP receive and send */
     achl_w1 = "";
     iml2 = iml_len = 0;
     while (iml2 < imp_vector_elements) {   /* loop over all elements  */
#ifndef HL_UNIX
       iml_len += ((WSABUF *) adsp_vector + iml2)->len;
#else
       iml_len += ((struct iovec *) adsp_vector + iml2)->iov_len;
#endif
       iml2++;                              /* increment index         */
     }
#ifndef HL_UNIX
     if (iml_len != uml_sent) {             /* not all data sent       */
       sprintf( chrl_work1, " / data sent %d/0X%X", uml_sent, uml_sent );
       achl_w1 = chrl_work1;
     }
#endif
     strcpy( chrl_ineta, "???" );           /* if getnameinfo() fails  */
     getnameinfo( adsp_soa, imp_len_soa,
                  chrl_ineta, sizeof(chrl_ineta), 0, 0, NI_NUMERICHOST );
     iml2 = 0;                              /* clear port              */
     switch (adsp_soa->sa_family) {
       case AF_INET:                        /* IPV4                    */
         iml2 = ntohs( ((struct sockaddr_in *) adsp_soa)->sin_port );
         break;
       case AF_INET6:                       /* IPV6                    */
         iml2 = ntohs( ((struct sockaddr_in6 *) adsp_soa)->sin6_port );
         break;
     }
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CUDPSEV1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "UDP data send vector elements %d length total %d/0X%X returned %d error %d / target %s port %d%s.",
                     imp_vector_elements, iml_len, iml_len, iml_rc, iml_error,
                     chrl_ineta, iml2, achl_w1 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2)) {  /* generate WSP trace record */
//     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
       achl_w1 = (char *) (((size_t) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml1 = iml_len;                      /* length of data to be sent */
       iml2 = 0;                            /* in this buffer          */
#ifndef HL_UNIX
       achl_w3 = ((WSABUF *) adsp_vector + 0)->buf;  /* start of data  */
#else
       achl_w3 = (char *) ((struct iovec *) adsp_vector + 0)->iov_base;  /* start of data */
#endif
       adsl_wt1_w2 = adsl_wt1_w1;           /* in this piece of memory */
       adsl_wtr_w1 = ADSL_WTR_G1;           /* set last in chain       */
       bol1 = FALSE;                        /* reset more flag         */
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
         bol1 = TRUE;                       /* set more flag           */
         adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain     */
         adsl_wtr_w1 = ADSL_WTR_G2;         /* this is last in chain now */
         while (TRUE) {                     /* loop over data sent     */
#ifndef HL_UNIX
           achl_w5 = ((WSABUF *) adsp_vector + iml2)->buf + ((WSABUF *) adsp_vector + iml2)->len;
#else
           achl_w5 = (char *) ((struct iovec *) adsp_vector + iml2)->iov_base + ((struct iovec *) adsp_vector + iml2)->iov_len;
#endif
           iml3 = achl_w5 - achl_w3;
           if (iml3 > iml1) iml3 = iml1;
           iml4 = achl_w2 - achl_w4;
           if (iml4 > iml3) iml4 = iml3;
           memcpy( achl_w4, achl_w3, iml4 );
           achl_w4 += iml4;
           achl_w3 += iml4;
           ADSL_WTR_G2->imc_length += iml4;  /* length of text / data  */
           iml1 -= iml4;                    /* length to be copied     */
           if (iml1 <= 0) break;
           if (achl_w3 < achl_w5) break;
           iml2++;                          /* next part to be copied  */
#ifndef HL_UNIX
           achl_w3 = ((WSABUF *) adsp_vector + iml2)->buf;  /* start of data */
#else
           achl_w3 = (char *) ((struct iovec *) adsp_vector + iml2)->iov_base;  /* start of data */
#endif
           if (achl_w4 >= achl_w2) break;
         }
         achl_w1 = achl_w2;                 /* set end of this area    */
       } while (iml1 > 0);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#ifdef HL_UNIX
#ifndef B150710
   if (iml_rc > 0) iml_rc = 0;
#endif
#endif
   return iml_rc;
} /* end m_udp_send_vector()                                           */

/** close UDP entry                                                    */
extern "C" void m_close_udp_multiw_1( struct dsd_udp_multiw_1 *adsp_udp_multiw_1 ) {
#ifndef HL_UNIX
   BOOL       bol1;                         /* working-variable        */
#endif
   int        iml_rc;                       /* return code             */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-udp-01-%05d-T m_close_udp_multiw_1() adsp_udp_multiw_1=%p.",
                   __LINE__, adsp_udp_multiw_1 );
#endif
   m_close_udp_recv( adsp_udp_multiw_1 );
   iml_rc = D_TCP_CLOSE( adsp_udp_multiw_1->imc_socket );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_close_udp_multiw_1() %p closesocket Return Code %d/%d.",
                     __LINE__, adsp_udp_multiw_1, iml_rc, D_TCP_ERROR );
   }
#ifndef HL_UNIX
   bol1 = WSACloseEvent( adsp_udp_multiw_1->dsc_event );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_close_udp_multiw_1() %p WSACloseEvent Return Code %d.",
                     __LINE__, adsp_udp_multiw_1, m_ip_wsaglerr() );
   }
#endif
} /* end m_close_udp_multiw_1()                                        */

/** cleanup of aux UDP entry                                           */
static void m_aux_close_udp_entry( void *vpp_userfld, struct dsd_udp_multiw_1 *adsp_udp_multiw_1 ) {
   struct dsd_sdh_control_1 *adsl_sdhc1_cur;  /* current in chain      */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-%05d-T m_aux_close_udp_entry() vpp_userfld=%p adsp_udp_multiw_1=%p.",
                   __LINE__, vpp_userfld, adsp_udp_multiw_1 );
// fflush( stdout );
#endif
   m_close_udp_multiw_1( adsp_udp_multiw_1 );
#define ADSL_UDP_GW_1_G ((struct dsd_udp_gw_1 *) (adsp_udp_multiw_1 + 1))
   while (ADSL_UDP_GW_1_G->adsc_sdhc1_rb) {  /* loop over all buffers  */
     adsl_sdhc1_cur = ADSL_UDP_GW_1_G->adsc_sdhc1_rb;
     ADSL_UDP_GW_1_G->adsc_sdhc1_rb = ADSL_UDP_GW_1_G->adsc_sdhc1_rb->adsc_next;
     m_proc_free( adsl_sdhc1_cur );         /* free this buffer        */
   }
   if (vpp_userfld == NULL) return;         /* no need to remove entry */
   m_wsp_s_ent_del( vpp_userfld, DEF_WSP_TYPE_UDP, (char *) adsp_udp_multiw_1 );
#undef ADSL_UDP_GW_1_G
} /* end m_aux_close_udp_entry()                                       */

/** SIP request                                                        */
extern "C" BOOL m_aux_sip_requ_1( void *vpp_userfld, struct dsd_sdh_sip_requ_1 *adsp_sip_r1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working-variables       */
   int        iml_w1, iml_w2;               /* working variables       */
   int        iml_rc;                       /* return code             */
   int        iml_sec_rc;                   /* second return code      */
   int        iml_no_iov;                   /* number of WSABUF / vector */
   int        iml_len_packet;               /* length of packet        */
   unsigned int uml_sent;                   /* bytes sent              */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_sdh_udp_recbuf_1 *adsl_rec_b_cur;  /* current in chain   */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working-variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working-variable       */
   struct dsd_sdh_control_1 **aadsl_sdhc1_extra;  /* chain of buffers extra */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
// struct dsd_gather_i_1 *adsl_gai1_w2;     /* working variable        */
   struct dsd_sip_gw_1 *adsl_sip_gw_1_w1;   /* structure for a SIP gateway */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   struct sockaddr_storage dsl_soa_send;    /* send address information */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   struct dsd_sip_compare {
     struct dsd_sip_entry_1 dsc_sip_entry_1;  /* structure for a SIP entry */
     char     chrc_sip_ident[ MAX_LEN_SIP_IDENT ];
   } dsl_sip_compare;
#ifndef HL_UNIX
   WSABUF     dsrl_wsabuf[ DEF_SEND_IOV ];  /* buffer for WSASend()    */
#else
   struct msghdr dsl_msghdr;                /* for sendmsg()           */
   struct iovec dsrl_iov[ DEF_SEND_IOV ];   /* buffer for sendmsg()    */
#endif
   struct dsd_wsp_trace_info_conn1 dsl_wtic;  /* WSP trace information for connection */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "l%05d xs-gw-udp-01 m_aux_sip_requ_1( %p ) called",
                   __LINE__, adsp_sip_r1 );
#endif
   switch (adsp_sip_r1->iec_sdh_sipr1) {    /* depending on command    */
     case ied_sdh_sipr1_register:           /* SIP register entry      */
       goto p_aux_sip_register;             /* SIP register entry      */
     case ied_sdh_sipr1_send:               /* SIP send packet         */
       goto p_aux_sip_send;                 /* send SIP packet         */
     case ied_sdh_sipr1_send_gather:        /* SIP send gather         */
       goto p_aux_sip_se_gai1;              /* send SIP gather         */
     case ied_sdh_sipr1_update_recv:        /* SIP update received packets */
#define ADSL_SIP_ENTRY_1_G ((struct dsd_sip_entry_1 *) adsp_sip_r1->vpc_sipr_handle)
       dss_critsect_udp.m_enter();          /* critical section        */
       adsp_sip_r1->adsc_recb_1 = NULL;
       adsl_sdhc1_w1 = ADSL_SIP_ENTRY_1_G->adsc_sdhc1_rb;
       if (adsl_sdhc1_w1) {                 /* buffers to transfer     */
         aadsl_sdhc1_extra = m_get_sdhc1_extra_from_conn1( ADSL_SIP_ENTRY_1_G->adsc_conn1 );
         ADSL_SIP_ENTRY_1_G->adsc_sdhc1_rb = NULL;  /* all buffers copied */
#ifndef TRY100302
         adsp_sip_r1->adsc_recb_1 = (struct dsd_sdh_udp_recbuf_1 *) (adsl_sdhc1_w1 + 1);
#else
         adsp_sip_r1->adsc_recb_1 = (struct dsd_sdh_udp_recbuf_1 *) ((BOOL *) (adsl_sdhc1_w1 + 1) + 1);
#endif
         adsl_rec_b_cur = NULL;
#ifdef B100426
         while (TRUE) {                     /* loop over all buffers   */
           adsl_sdhc1_w2 = adsl_sdhc1_w1;   /* save this buffer        */
           adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
           adsl_sdhc1_w2->imc_usage_count = 1;
#ifdef TRY100302
           *((BOOL *) (adsl_sdhc1_w2 + 1)) = TRUE;  /* buffer has been given */
#endif
           /* put buffer in chain extra to be freed when no more used  */
           adsl_sdhc1_w2->adsc_next = *aadsl_sdhc1_extra;
           *aadsl_sdhc1_extra = adsl_sdhc1_w2;
           if (adsl_sdhc1_w1 == NULL) break;
           if (adsl_rec_b_cur == NULL) {
             adsl_rec_b_cur = adsp_sip_r1->adsc_recb_1;
           } else {
#ifndef TRY100302
             adsl_rec_b_cur->adsc_next = (struct dsd_sdh_udp_recbuf_1 *) (adsl_sdhc1_w2 + 1);
#else
             adsl_rec_b_cur->adsc_next = (struct dsd_sdh_udp_recbuf_1 *) ((BOOL *) (adsl_sdhc1_w2 + 1) + 1);
#endif
             adsl_rec_b_cur = adsl_rec_b_cur->adsc_next;
           }
         }
#else
         do {                               /* loop over all buffers   */
           adsl_sdhc1_w2 = adsl_sdhc1_w1;   /* save this buffer        */
           adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
           adsl_sdhc1_w2->imc_usage_count = 1;
#ifdef TRY100302
           *((BOOL *) (adsl_sdhc1_w2 + 1)) = TRUE;  /* buffer has been given */
#endif
           /* put buffer in chain extra to be freed when no more used  */
           adsl_sdhc1_w2->adsc_next = *aadsl_sdhc1_extra;
           *aadsl_sdhc1_extra = adsl_sdhc1_w2;
           if (adsl_rec_b_cur == NULL) {
             adsl_rec_b_cur = adsp_sip_r1->adsc_recb_1;
           } else {
#ifndef TRY100302
             adsl_rec_b_cur->adsc_next = (struct dsd_sdh_udp_recbuf_1 *) (adsl_sdhc1_w2 + 1);
#else
             adsl_rec_b_cur->adsc_next = (struct dsd_sdh_udp_recbuf_1 *) ((BOOL *) (adsl_sdhc1_w2 + 1) + 1);
#endif
             adsl_rec_b_cur = adsl_rec_b_cur->adsc_next;
           }
         } while (adsl_sdhc1_w1);
#endif
       }
       dss_critsect_udp.m_leave();          /* critical section        */
#ifdef PROBLEM_HOBPHONE_1003
       {
         int      imh1 = 0;
         adsl_rec_b_cur = adsp_sip_r1->adsc_recb_1;
         while (adsl_rec_b_cur) {
           imh1++;
           m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-%05d-T m_aux_sip_requ_1() ADSL_SIP_ENTRY_1_G=%p pass-rec-b=%p no=%d",
                           __LINE__,
                           ADSL_SIP_ENTRY_1_G,
                           adsl_rec_b_cur, imh1 );
           adsl_rec_b_cur = adsl_rec_b_cur->adsc_next;
         }
         m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-%05d-T m_aux_sip_requ_1() ADSL_SIP_ENTRY_1_G=%p adsp_sip_r1=%p passed %d SIP-records",
                         __LINE__,
                         ADSL_SIP_ENTRY_1_G, adsp_sip_r1, imh1 );
       }
#endif
       adsp_sip_r1->iec_ret_sipr1 = ied_ret_sipr1_ok;  /* SIP request command o.k. */
       return TRUE;                         /* all done                */
#undef ADSL_SIP_ENTRY_1_G
     case ied_sdh_sipr1_free_buffer:        /* SIP free buffer(s)      */
#ifdef PROBLEM_HOBPHONE_1003
       {
#define ADSL_SIP_ENTRY_1_G ((struct dsd_sip_entry_1 *) adsp_sip_r1->vpc_sipr_handle)
         int      imh1 = 0;
         adsl_rec_b_cur = adsp_sip_r1->adsc_recb_1;
         while (adsl_rec_b_cur) {
           imh1++;
           m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-%05d-T m_aux_sip_requ_1() ADSL_SIP_ENTRY_1_G=%p free-rec-b=%p no=%d",
                           __LINE__,
                           ADSL_SIP_ENTRY_1_G,
                           adsl_rec_b_cur, imh1 );
           adsl_rec_b_cur = adsl_rec_b_cur->adsc_next;
         }
         m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-%05d-T m_aux_sip_requ_1() ADSL_SIP_ENTRY_1_G=%p adsp_sip_r1=%p free %d SIP-records",
                         __LINE__,
                         ADSL_SIP_ENTRY_1_G, adsp_sip_r1, imh1 );
#undef ADSL_SIP_ENTRY_1_G
       }
#endif
       while (adsp_sip_r1->adsc_recb_1) {
         ((struct dsd_sdh_control_1 *) adsp_sip_r1->adsc_recb_1 - 1)->imc_usage_count--;
         adsp_sip_r1->adsc_recb_1 = adsp_sip_r1->adsc_recb_1->adsc_next;
       }
       adsp_sip_r1->iec_ret_sipr1 = ied_ret_sipr1_ok;  /* SIP request command o.k. */
       return TRUE;                         /* all done                */
     case ied_sdh_sipr1_close:              /* SIP close               */
       m_close_sip_entry( vpp_userfld, (struct dsd_sip_entry_1 *) adsp_sip_r1->vpc_sipr_handle );
       adsp_sip_r1->iec_ret_sipr1 = ied_ret_sipr1_ok;  /* SIP request command o.k. */
       return TRUE;                         /* all done                */
   }
   return FALSE;                            /* command not defined     */

   p_aux_sip_register:                      /* SIP register entry      */
   if (   (adsp_sip_r1->ac_sip_ident == NULL)  /* SIP ident            */
       || (adsp_sip_r1->imc_len_sip_ident == 0)  /* length SIP ident in elements */
       || (adsp_sip_r1->iec_chs_sip_ident == ied_chs_invalid)) {  /* character set SIP ident */
     adsp_sip_r1->iec_ret_sipr1 = ied_ret_sipr1_ident_invalid;  /* SIP ident invalid parameter */
     return TRUE;                           /* all done                */
   }
// to-do 16.12.14 - is crirical section really needed here ???
// gave deadlock on Unix
#ifdef B141216
   dss_critsect_udp.m_enter();              /* critical section        */
#endif
   while (ims_sip_last_try) {               /* time last try start SIP */
     if ((((int) time( NULL )) - DEF_RETRY_START_SIP) < ims_sip_last_try) break;  /* check time last try start SIP */
     m_gw_sip_start();                      /* prepare SIP             */
     break;
   }
   if (ims_sip_last_try) {                  /* SIP not started         */
#ifdef B141216
     dss_critsect_udp.m_leave();            /* critical section        */
#endif
     adsp_sip_r1->iec_ret_sipr1 = ied_ret_sipr1_net_err;  /* SIP request network error */
     return TRUE;                           /* all done                */
   }
#ifndef B141216
   dss_critsect_udp.m_enter();              /* critical section        */
#endif
   /* search SIP gateway entry                                         */
   adsl_sip_gw_1_w1 = adss_sip_gw_1_a;      /* get anchor SIP gateways */
   while (adsl_sip_gw_1_w1) {               /* loop over all active SIP gateways */
     if (   (adsl_sip_gw_1_w1->imc_len_ineta_sip_gw == adsp_sip_r1->imc_len_ineta_sip_gw)  /* length INETA */
         && (!memcmp( adsp_sip_r1->achc_ineta_sip_gw,
                      adsl_sip_gw_1_w1 + 1,
                      adsl_sip_gw_1_w1->imc_len_ineta_sip_gw ))) {
       break;
     }
     adsl_sip_gw_1_w1 = adsl_sip_gw_1_w1->adsc_next;  /* get next in chain */
   }
   if (adsl_sip_gw_1_w1 == NULL) {          /* SIP gateway not found   */
     adsl_sip_gw_1_w1
       = (struct dsd_sip_gw_1 *) malloc( sizeof(struct dsd_sip_gw_1)
                                           + adsp_sip_r1->imc_len_ineta_sip_gw );
     memset( adsl_sip_gw_1_w1, 0, sizeof(struct dsd_sip_gw_1) );
     adsl_sip_gw_1_w1->imc_len_ineta_sip_gw = adsp_sip_r1->imc_len_ineta_sip_gw;
     memcpy( adsl_sip_gw_1_w1 + 1,
             adsp_sip_r1->achc_ineta_sip_gw,
             adsp_sip_r1->imc_len_ineta_sip_gw );
     bol1 = m_htree1_avl_init( adsl_sip_gw_1_w1,
                               &adsl_sip_gw_1_w1->dsc_htree1_avl_cntl,
                               &m_cmp_sip_ident );
     if (bol1 == FALSE) {                   /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_aux_sip_requ_1() m_htree1_avl_init() init tree failed",
                       __LINE__ );
     }
     adsl_sip_gw_1_w1->adsc_next = adss_sip_gw_1_a;  /* get anchor SIP gateways */
     adss_sip_gw_1_a = adsl_sip_gw_1_w1;    /* insert into chain       */
   }
   /* get SIP Ident, needed in UTF-8                                   */
   iml1 = m_cpy_vx_vx( dsl_sip_compare.chrc_sip_ident,
                       sizeof(dsl_sip_compare.chrc_sip_ident),
                       ied_chs_utf_8,
                       adsp_sip_r1->ac_sip_ident,  /* SIP ident        */
                       adsp_sip_r1->imc_len_sip_ident,  /* length SIP ident in elements */
                       adsp_sip_r1->iec_chs_sip_ident );  /* character set SIP ident */
   dsl_sip_compare.dsc_sip_entry_1.imc_len_sip_ident = iml1;
   bol1 = m_htree1_avl_search( adsl_sip_gw_1_w1,
                               &adsl_sip_gw_1_w1->dsc_htree1_avl_cntl,
                               &dsl_htree1_work,
                               &dsl_sip_compare.dsc_sip_entry_1.dsc_sort_1 );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_aux_sip_requ_1() search in tree failed",
                     __LINE__ );
   }
   if (dsl_htree1_work.adsc_found) {        /* already in tree         */
     dss_critsect_udp.m_leave();            /* critical section        */
     adsp_sip_r1->iec_ret_sipr1 = ied_ret_sipr1_entry_double;  /* SIP entry defined double */
     return TRUE;                           /* all done                */
   }
   adsp_sip_r1->vpc_sipr_handle = m_wsp_s_ent_add( vpp_userfld,
                                                   DEF_WSP_TYPE_SIP,
                                                   sizeof(struct dsd_sip_entry_1) + iml1 );
#define ADSL_SIP_ENTRY_1_G ((struct dsd_sip_entry_1 *) adsp_sip_r1->vpc_sipr_handle)
   memset( ADSL_SIP_ENTRY_1_G, 0, sizeof(struct dsd_sip_entry_1) );
   memcpy( ADSL_SIP_ENTRY_1_G + 1, dsl_sip_compare.chrc_sip_ident, iml1 );
   ADSL_SIP_ENTRY_1_G->imc_len_sip_ident = iml1;
   ADSL_SIP_ENTRY_1_G->adsc_sip_gw_1 = adsl_sip_gw_1_w1;
   ADSL_SIP_ENTRY_1_G->adsc_conn1 = m_get_conn1_from_userfld( vpp_userfld );
   ADSL_SIP_ENTRY_1_G->imc_signal = adsp_sip_r1->imc_signal;
   bol1 = m_htree1_avl_insert( adsl_sip_gw_1_w1,
                               &adsl_sip_gw_1_w1->dsc_htree1_avl_cntl,
                               &dsl_htree1_work,
                               &ADSL_SIP_ENTRY_1_G->dsc_sort_1 );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_aux_sip_requ_1() %p insert in tree failed",
                     __LINE__, ADSL_SIP_ENTRY_1_G );
   }
   dss_critsect_udp.m_leave();              /* critical section        */
   adsp_sip_r1->achc_local_sip_sockaddr = (char *) &dss_sip_v4_soa;  /* pointer to sockaddr structure */
   adsp_sip_r1->imc_len_local_sip_sockaddr = ims_sip_v4_len_soa;  /* length of sockaddr structure */
   adsp_sip_r1->iec_ret_sipr1 = ied_ret_sipr1_ok;  /* SIP request command o.k. */
#ifdef PROBLEM_HOBPHONE_1003
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-%05d-T m_aux_sip_requ_1() ADSL_SIP_ENTRY_1_G=%p adsp_sip_r1=%p p_aux_sip_register SIP-Ident=%.*s.",
                   __LINE__,
                   ADSL_SIP_ENTRY_1_G, adsp_sip_r1,
                   ADSL_SIP_ENTRY_1_G->imc_len_sip_ident,
                   ADSL_SIP_ENTRY_1_G + 1 );
#endif
   return TRUE;                             /* all done                */
#undef ADSL_SIP_ENTRY_1_G

   p_aux_sip_send:                          /* send SIP packet         */
#define ADSL_SIP_ENTRY_1_G ((struct dsd_sip_entry_1 *) adsp_sip_r1->vpc_sipr_handle)
   /* prepare sockaddr                                                 */
   memset( &dsl_soa_send, 0, sizeof(sockaddr_in) );
   ((sockaddr_in *) &dsl_soa_send)->sin_family = AF_INET;
   ((sockaddr_in *) &dsl_soa_send)->sin_port = m_ip_htons( D_PORT_SIP );
   memcpy( &((sockaddr_in *) &dsl_soa_send)->sin_addr.s_addr,
           ADSL_SIP_ENTRY_1_G->adsc_sip_gw_1 + 1,
           4 );
   iml_rc = m_ip_sendto( dss_udp_multiw_1_sip_ipv4.imc_socket,
                         adsp_sip_r1->achc_data_send, adsp_sip_r1->imc_len_data_send,
                         0,
                         (sockaddr *) &dsl_soa_send, sizeof(sockaddr_in) );
#ifndef HL_UNIX
   iml_sec_rc = m_ip_wsaglerr();            /* second return code      */
#else
   iml_sec_rc = errno;                      /* second return code      */
#endif
   m_get_wsp_trace_info_conn1( &dsl_wtic, ADSL_SIP_ENTRY_1_G->adsc_conn1 );
   if (dsl_wtic.imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SSIPUSE1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = dsl_wtic.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "SIP data sent length %d/0X%X / sendto returned %d/%d.",
                     adsp_sip_r1->imc_len_data_send, adsp_sip_r1->imc_len_data_send,
                     iml_rc, iml_sec_rc );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (dsl_wtic.imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2)) {  /* generate WSP trace record */
//     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
       achl_w1 = (char *) (((size_t) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml1 = adsp_sip_r1->imc_len_data_send;  /* length of data sent  */
       achl_w3 = adsp_sip_r1->achc_data_send;  /* start of data        */
       adsl_wt1_w2 = adsl_wt1_w1;           /* in this piece of memory */
       adsl_wtr_w1 = ADSL_WTR_G1;           /* set last in chain       */
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
         if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
           adsl_wtr_w1->boc_more = TRUE;    /* more data to follow     */
         }
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
       } while (iml1 > 0);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (iml_rc <= 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_aux_sip_requ_1() %p send Return Code %d/%d.",
                     __LINE__, ADSL_SIP_ENTRY_1_G, iml_rc, iml_sec_rc );
     adsp_sip_r1->iec_ret_sipr1 = ied_ret_sipr1_send_error;  /* SIP send failed */
     return TRUE;                           /* all done                */
   }
   m_count_sent_server( ADSL_SIP_ENTRY_1_G->adsc_conn1, adsp_sip_r1->imc_len_data_send );
   adsp_sip_r1->iec_ret_sipr1 = ied_ret_sipr1_ok;  /* SIP request command o.k. */
   return TRUE;                             /* all done                */
#undef ADSL_SIP_ENTRY_1_G

   p_aux_sip_se_gai1:                       /* send SIP gather         */
#define ADSL_SIP_ENTRY_1_G ((struct dsd_sip_entry_1 *) adsp_sip_r1->vpc_sipr_handle)
   iml_no_iov = 0;                          /* clear number of WSABUF / vector */
   iml_len_packet = 0;                      /* clear length of packet  */
   adsl_gai1_w1 = adsp_sip_r1->adsc_gai1_send;  /* gather to send      */
   do {                                     /* loop over all gather structures */
     if (iml_no_iov < DEF_SEND_IOV) {       /* can fill structure      */
#ifndef HL_UNIX
       dsrl_wsabuf[ iml_no_iov ].buf = adsl_gai1_w1->achc_ginp_cur;
       dsrl_wsabuf[ iml_no_iov ].len = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       iml_len_packet += dsrl_wsabuf[ iml_no_iov ].len;  /* increment length of packet */
#else
       dsrl_iov[ iml_no_iov ].iov_base = adsl_gai1_w1->achc_ginp_cur;
       dsrl_iov[ iml_no_iov ].iov_len = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       iml_len_packet += dsrl_iov[ iml_no_iov ].iov_len;  /* increment length of packet */
#endif
     }
     iml_no_iov++;                          /* increment number of WSABUF / vector */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   } while (adsl_gai1_w1);
   if (iml_no_iov > DEF_SEND_IOV) {         /* too many entries structure */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_aux_sip_requ_1() %p ied_sdh_sipr1_send_gather too many gather in chain - %d.",
                     __LINE__, ADSL_SIP_ENTRY_1_G, iml_no_iov );
     adsp_sip_r1->iec_ret_sipr1 = ied_ret_sipr1_send_error;  /* SIP send failed */
     return TRUE;                           /* all done                */
   }
   /* prepare sockaddr                                                 */
   memset( &dsl_soa_send, 0, sizeof(sockaddr_in) );
   ((sockaddr_in *) &dsl_soa_send)->sin_family = AF_INET;
   ((sockaddr_in *) &dsl_soa_send)->sin_port = m_ip_htons( D_PORT_SIP );
   memcpy( &((sockaddr_in *) &dsl_soa_send)->sin_addr.s_addr,
           ADSL_SIP_ENTRY_1_G->adsc_sip_gw_1 + 1,
           4 );
#ifndef HL_UNIX
   iml_rc = WSASendTo( dss_udp_multiw_1_sip_ipv4.imc_socket,
                       dsrl_wsabuf, iml_no_iov,
                       (DWORD *) &uml_sent, 0,
                       (struct sockaddr *) &dsl_soa_send,
                       sizeof(sockaddr_in),
                       NULL, NULL );
   iml_sec_rc = m_ip_wsaglerr();            /* second return code      */
#else
   memset( &dsl_msghdr, 0, sizeof(struct msghdr) );
#ifndef HL_HPUX
   dsl_msghdr.msg_name = (struct sockaddr *) &dsl_soa_send;
#else
   dsl_msghdr.msg_name = (char *) &dsl_soa_send;
#endif
   dsl_msghdr.msg_namelen = sizeof(struct sockaddr_in);
   dsl_msghdr.msg_iov = dsrl_iov;
   dsl_msghdr.msg_iovlen = iml_no_iov;
// dsl_msghdr.msg_flags = 0;
   iml_rc = sendmsg( dss_udp_multiw_1_sip_ipv4.imc_socket, &dsl_msghdr, 0 );
   iml_sec_rc = errno;                      /* second return code      */
#endif
   m_get_wsp_trace_info_conn1( &dsl_wtic, ADSL_SIP_ENTRY_1_G->adsc_conn1 );
   if (dsl_wtic.imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SSIPUSE2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = dsl_wtic.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "SIP data sent gather / sendto returned %d/%d.",
                     iml_rc, iml_sec_rc );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     adsl_wt1_w2 = adsl_wt1_w1;             /* last WSP Trace area     */
     adsl_wtr_w1 = ADSL_WTR_G1;             /* set last in chain       */
//   achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
     achl_w1 = (char *) (((size_t) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
     achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
     if (dsl_wtic.imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2)) {  /* generate WSP trace record */
       iml_w1 = iml_w2 = 0;                 /* clear counters          */
       adsl_gai1_w1 = adsp_sip_r1->adsc_gai1_send;  /* get chain data to send */
       do {                                 /* loop over all input gather */
         iml_w1++;                          /* count gather            */
         iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
         if (iml1 > 0) {                    /* data in this gather     */
           if ((achl_w1 + sizeof(struct dsd_wsp_trace_record) + 80) >= achl_w2) {
             adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
             memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
             adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
             adsl_wt1_w2 = adsl_wt1_w3;     /* this is current area    */
             achl_w1 = (char *) (adsl_wt1_w2 + 1);
             achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
           }
           memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
           iml2 = sprintf( (char *) (ADSL_WTR_G2 + 1),
                           "+ SIP send gather-no=%d disp=0X%X addr=0X%X length=%d/0X%X.",
                           iml_w1, iml_w2, adsl_gai1_w1->achc_ginp_cur, iml1, iml1 );
           ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed      */
           ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
           ADSL_WTR_G2->imc_length = iml2;  /* length of text / data   */
           adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain   */
           adsl_wtr_w1 = ADSL_WTR_G2;       /* this is last in chain now */
//         achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
           achl_w1 = (char *) (((size_t) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
           achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* here start binary data */
           do {                             /* loop for output of data */
             iml2 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             if (iml2 <= 0) {               /* we need another area    */
               adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
               memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
               adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
               adsl_wt1_w2 = adsl_wt1_w3;   /* this is current area    */
               achl_w1 = (char *) (adsl_wt1_w2 + 1);
               achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
               iml2 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             }
             if (iml2 > iml1) iml2 = iml1;
             memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
             ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
             achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
             ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
             if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
               adsl_wtr_w1->boc_more = TRUE;  /* more data to follow   */
             }
             adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
             adsl_wtr_w1 = ADSL_WTR_G2;     /* this is last in chain now */
             memcpy( achl_w4, achl_w3, iml2 );
             achl_w3 += iml2;
             ADSL_WTR_G2->imc_length = iml2;  /* length of text / data */
//           achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
             achl_w1 = (char *) (((size_t) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
             iml1 -= iml2;
           } while (iml1 > 0);
           iml_w2 += iml1;                  /* increment displacement  */
         }
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       } while (adsl_gai1_w1);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#ifdef HL_UNIX
#ifndef B150710
   if (iml_rc > 0) iml_rc = 0;
#endif
#endif
   if (iml_rc != 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_aux_sip_requ_1() %p WSASendTo Return Code %d/%d.",
                     __LINE__, ADSL_SIP_ENTRY_1_G, iml_rc, iml_sec_rc );
     adsp_sip_r1->iec_ret_sipr1 = ied_ret_sipr1_send_error;  /* SIP send failed */
     return TRUE;                           /* all done                */
   }
   m_count_sent_server( ADSL_SIP_ENTRY_1_G->adsc_conn1, iml_len_packet );
   adsp_sip_r1->iec_ret_sipr1 = ied_ret_sipr1_ok;  /* SIP request command o.k. */
   return TRUE;                             /* all done                */
#undef ADSL_SIP_ENTRY_1_G
} /* end m_aux_sip_requ_1()                                            */

/** SIP cleanup                                                        */
//extern "C" void m_aux_sip_cleanup( struct dsd_conn1 *adsp_conn1, char *achp_ext ) {
extern "C" void m_aux_sip_cleanup( DSD_CONN_G *adsp_conn1, char *achp_ext ) {
   m_close_sip_entry( NULL, (struct dsd_sip_entry_1 *) achp_ext );
} /* end m_aux_sip_cleanup()                                           */

/** set connection for SIP entry                                       */
extern "C" void m_sip_set_conn1( void * ap_sipr_handle, void * ap_conn1 ) {
#define ADSL_SIP_ENTRY_1_G ((struct dsd_sip_entry_1 *) ap_sipr_handle)
// ADSL_SIP_ENTRY_1_G->adsc_conn1 = (struct dsd_conn1 *) ap_conn1;
   ADSL_SIP_ENTRY_1_G->adsc_conn1 = (DSD_CONN_G *) ap_conn1;
#undef ADSL_SIP_ENTRY_1_G
} /* end m_sip_set_conn1()                                             */

/** command for UDP-gate                                               */
extern "C" BOOL m_aux_udp_gate_1( void *vpp_userfld, struct dsd_aux_cmd_udp_gate *adsp_cmd_ug ) {
   int        iml1;                         /* working variable        */
   BOOL       bol1;                         /* working variable        */
   char       *achl_avl_error;              /* error code AVL tree     */
#ifdef XYZ1
   struct dsd_auxf_1 *adsl_auxf_1_new;      /* new auxiliary extension field */
#endif
   struct dsd_udp_gate_entry_1 *adsl_uge1_w1;  /* structure for a UDP-gate entry */
   struct dsd_uga_subch_1 *adsl_uga_subch_1_w1;  /* UDP-gate subchannel */
   struct dsd_udp_gate_subch_sort_1 dsl_uga_subch_s1_l;  /* structure for a UDP-gate subchannel sort */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */

   switch (adsp_cmd_ug->iec_cmd_ug) {       /* command for UDP-gate    */
     case ied_cmd_udp_gate_create:          /* create an entry         */
       break;
     case ied_cmd_udp_gate_delete:          /* delete the entry        */
       goto p_delete_00;                    /* delete the entry        */
     case ied_cmd_uga_subch_register:       /* register sub-channel    */
       goto p_subch_register;               /* register sub-channel    */
     case ied_cmd_uga_subch_close:          /* close sub-channel       */
       goto p_subch_close;                  /* close sub-channel       */
     default:
       adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_cmd_not_def;  /* command not defined */
       return TRUE;
   }
   if (   (adsg_loconf_1_inuse->imc_udp_gate_ipv4_port <= 0)  /* UDP port IPV4 */
       && (adsg_loconf_1_inuse->imc_udp_gate_ipv6_port <= 0)){  /* UDP port IPV6 */
     adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_not_conf;  /* UDP-gate not configured */
     return TRUE;
   }
#ifdef XYZ1
   adsl_uge1_w1 = (struct dsd_udp_gate_entry_1 *) malloc( sizeof(struct dsd_udp_gate_entry_1) );  /* structure for a UDP-gate entry */
   memset( adsl_uge1_w1, 0, sizeof(struct dsd_udp_gate_entry_1) );  /* structure for a UDP-gate entry */
   memcpy( adsl_uge1_w1->chrc_nonce, adsp_cmd_ug->chrc_nonce, DEF_LEN_UDP_GATE_NONCE );  /* copy the nonce */
   adsl_auxf_1_new = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1) + sizeof(struct dsd_udp_gate_entry_1) );  /* structure for a UDP-gate entry */
   memset( adsl_auxf_1_new, 0, sizeof(struct dsd_auxf_1) + sizeof(struct dsd_udp_gate_entry_1) );  /* structure for a UDP-gate entry */
#endif
   adsl_uge1_w1
     = (struct dsd_udp_gate_entry_1 *) m_wsp_s_ent_add( vpp_userfld,
                                                        DEF_WSP_TYPE_GATE_UDP,
                                                        sizeof(struct dsd_udp_gate_entry_1) );
   memset( adsl_uge1_w1, 0, sizeof(struct dsd_udp_gate_entry_1) );
   memcpy( adsl_uge1_w1->dsc_ug_sort.chrc_nonce, adsp_cmd_ug->chrc_nonce, DEF_LEN_UDP_GATE_NONCE );  /* copy the nonce */
   achl_avl_error = NULL;                   /* error code AVL tree     */
   dss_critsect_udp.m_enter();              /* critical section        */
   do {                                     /* pseudo-loop             */
     bol1 = m_htree1_avl_search( NULL,
                                 &dss_htree1_avl_cntl_udp_gate_m,
                                 &dsl_htree1_work,
                                 &adsl_uge1_w1->dsc_ug_sort.dsc_sort_1 );
     if (bol1 == FALSE) {                     /* error occured           */
       achl_avl_error = "search in tree failed";
       adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_misc;  /* miscellaneous error */
       break;
     }
     if (dsl_htree1_work.adsc_found) {      /* already in tree         */
       adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_nonce_double;  /* nonce is double */
       bol1 = FALSE;                        /* error occured           */
       break;
     }
     bol1 = m_htree1_avl_insert( NULL,
                                 &dss_htree1_avl_cntl_udp_gate_m,
                                 &dsl_htree1_work,
                                 &adsl_uge1_w1->dsc_ug_sort.dsc_sort_1 );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "insert in tree UDP-gate main failed";
       adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_misc;  /* miscellaneous error */
       break;
     }
   } while (FALSE);
   dss_critsect_udp.m_leave();              /* critical section        */
   if (achl_avl_error) {                    /* AVL-error occured       */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_aux_udp_gate_1() %s",
                     __LINE__, achl_avl_error );
   }
   if (bol1 == FALSE) {                     /* error already set       */
     m_wsp_s_ent_del( vpp_userfld, DEF_WSP_TYPE_GATE_UDP, (char *) adsl_uge1_w1 );
     adsp_cmd_ug->vpc_ug_handle = NULL;     /* handle of entry for UDP-gate */
     adsp_cmd_ug->imc_udp_gate_ipv4_port = -1;  /* UDP port IPV4       */
     adsp_cmd_ug->imc_udp_gate_ipv6_port = -1;  /* UDP port IPV6       */
     adsp_cmd_ug->adsc_udp_gate_ineta = NULL;  /* <UDP-gate>           */
     return TRUE;
   }
   adsp_cmd_ug->vpc_ug_handle = adsl_uge1_w1;  /* handle of entry for UDP-gate */
   adsp_cmd_ug->imc_udp_gate_ipv4_port = adsg_loconf_1_inuse->imc_udp_gate_ipv4_port;  /* UDP port IPV4 */
   adsp_cmd_ug->imc_udp_gate_ipv6_port = adsg_loconf_1_inuse->imc_udp_gate_ipv4_port;  /* UDP port IPV6 */
   adsp_cmd_ug->adsc_udp_gate_ineta = &adsg_loconf_1_inuse->dsc_udp_gate_ineta;  /* <UDP-gate> */
   adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_ok;  /* return success   */
   return TRUE;

   p_delete_00:                             /* delete the entry        */
   adsl_uge1_w1 = (struct dsd_udp_gate_entry_1 *) adsp_cmd_ug->vpc_ug_handle;  /* structure for a UDP-gate entry */
   if (adsl_uge1_w1 == NULL) {              /* handle invalid          */
     adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_handle_invalid;  /* the handle is invalid */
     return TRUE;
   }
   if (adsl_uge1_w1->boc_deleted) {         /* the entry is deleted    */
     adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_handle_invalid;  /* the handle is invalid */
     return TRUE;
   }
   adsl_uge1_w1->boc_deleted = TRUE;        /* the entry is deleted    */
   memset( &dsl_uga_subch_s1_l, 0, sizeof(struct dsd_udp_gate_subch_sort_1) );  /* structure for a UDP-gate subchannel sort */
   memcpy( dsl_uga_subch_s1_l.dsc_uga_subch_s_field.chrc_nonce,
           adsl_uge1_w1->dsc_ug_sort.chrc_nonce,
           DEF_LEN_UDP_GATE_NONCE );      /* length of UDP-gate nonce */
   achl_avl_error = NULL;                   /* error code AVL tree     */
   dss_critsect_udp.m_enter();              /* critical section        */
   do {                                     /* pseudo-loop             */
     bol1 = m_htree1_avl_search( NULL,
                                 &dss_htree1_avl_cntl_udp_gate_m,
                                 &dsl_htree1_work,
                                 &adsl_uge1_w1->dsc_ug_sort.dsc_sort_1 );
     if (bol1 == FALSE) {                     /* error occured           */
       achl_avl_error = "search in tree UDP-gate main failed";
       adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_misc;  /* miscellaneous error */
       break;
     }
     if (dsl_htree1_work.adsc_found == NULL) {  /* not found in tree   */
       adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_not_in_tree;  /* the entry is not in the AVL-tree */
       bol1 = FALSE;                        /* error occured           */
       break;
     }
     bol1 = m_htree1_avl_delete( NULL,
                                 &dss_htree1_avl_cntl_udp_gate_m,
                                 &dsl_htree1_work );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "delete from tree UDP-gate main failed";
       adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_misc;  /* miscellaneous error */
       break;
     }
     /* delete subchannel entries                                      */
     bol1 = m_htree1_avl_search( NULL,
                                 &dss_htree1_avl_cntl_udp_gate_subch,
                                 &dsl_htree1_work,
                                 &dsl_uga_subch_s1_l.dsc_sort_1 );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "search in tree UDP-gate subchannel failed";
       adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_misc;  /* miscellaneous error */
       break;
     }
#define ADSL_UGA_SUBCH_1_G ((struct dsd_uga_subch_1 *) ((char *) dsl_htree1_work.adsc_found \
            - offsetof( struct dsd_uga_subch_1, dsc_uga_subch_s1 ) \
            - offsetof( struct dsd_udp_gate_subch_sort_1, dsc_sort_1 )))
     while (TRUE) {                         /* delete all subchannel entries */
       if (dsl_htree1_work.adsc_found) {    /* found in tree           */
         iml1 = memcmp( ADSL_UGA_SUBCH_1_G->dsc_uga_subch_s1.dsc_uga_subch_s_field.chrc_nonce,
                        dsl_uga_subch_s1_l.dsc_uga_subch_s_field.chrc_nonce,
                        DEF_LEN_UDP_GATE_NONCE );  /* length of UDP-gate nonce */
         if (iml1) break;                   /* not this main entry     */
         bol1 = m_htree1_avl_delete( NULL,
                                     &dss_htree1_avl_cntl_udp_gate_subch,
                                     &dsl_htree1_work );
         if (bol1 == FALSE) {               /* error occured           */
           achl_avl_error = "delete from tree UDP-gate subchannel failed";
           adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_misc;  /* miscellaneous error */
           break;
         }
       }
       bol1 = m_htree1_avl_getnext( NULL,
                                    &dss_htree1_avl_cntl_udp_gate_subch,
                                    &dsl_htree1_work, FALSE );
       if (bol1 == FALSE) {                 /* error occured           */
         achl_avl_error = "getnext from tree UDP-gate subchannel failed";  /* error code AVL tree */
         break;                             /* do not continue         */
       }
       if (dsl_htree1_work.adsc_found == NULL) break;  /* reached end of tree */
#undef ADSL_UGA_SUBCH_1_G
     }
   } while (FALSE);
   dss_critsect_udp.m_leave();              /* critical section        */
   if (achl_avl_error) {                    /* AVL-error occured       */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_aux_udp_gate_1() %s",
                     __LINE__, achl_avl_error );
   }
   if (bol1 == FALSE) return TRUE;          /* error already set       */
   adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_ok;  /* return success   */
   return TRUE;

   p_subch_register:                        /* register sub-channel    */
   adsl_uge1_w1 = (struct dsd_udp_gate_entry_1 *) adsp_cmd_ug->vpc_ug_handle;  /* structure for a UDP-gate entry */
   if (adsl_uge1_w1 == NULL) {              /* handle invalid          */
     adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_handle_invalid;  /* the handle is invalid */
     return TRUE;
   }
   if (adsl_uge1_w1->boc_deleted) {         /* the entry is deleted    */
     adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_handle_invalid;  /* the handle is invalid */
     return TRUE;
   }
   if (scrs_from_base64[ adsp_cmd_ug->ucc_subchannel_id ] < 0) {
// to-do 19.08.10 KB other error number - parameter error
     adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_misc;  /* miscellaneous error */
     return TRUE;
   }
   if (   (adsp_cmd_ug->imc_len_subch_sockaddr <= 0)  /* length of sockaddr structure subchannel */
       || (adsp_cmd_ug->imc_len_subch_sockaddr > sizeof(struct sockaddr_storage))) {  /* length of sockaddr structure subchannel */
// to-do 19.08.10 KB other error number - parameter error
     adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_misc;  /* miscellaneous error */
     return TRUE;
   }
   if (adsp_cmd_ug->achc_subch_sockaddr == NULL) {  /* pointer to sockaddr structure subchannel */
// to-do 19.08.10 KB other error number - parameter error
     adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_misc;  /* miscellaneous error */
     return TRUE;
   }
   if (   (adsp_cmd_ug->boc_subch_srtp == FALSE)  /* SRTP is not used    */
       && (adsp_cmd_ug->achc_subch_keys == NULL)) {  /* address of subchannel keys */
// to-do 19.08.10 KB other error number - parameter error
     adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_misc;  /* miscellaneous error */
     return TRUE;
   }
   iml1 = sizeof(struct dsd_uga_subch_1);   /* set length memory needed */
   if (adsp_cmd_ug->boc_subch_srtp == FALSE) {  /* SRTP is not used    */
#ifdef XYZ1
     iml1 += DEF_LEN_UDP_GATE_KEYS          /* length of UDP-gate keys for HOBPhone */
             + 2 * DEF_LEN_UDP_GATE_ENCRY;  /* length of UDP-gate encrytion for HOBPhone */
#endif
     iml1 += 2 * DEF_LEN_UDP_GATE_ENCRY;    /* length of UDP-gate encrytion for HOBPhone */
   }
   adsl_uga_subch_1_w1 = (struct dsd_uga_subch_1 *) malloc( iml1 );  /* UDP-gate subchannel */
   memset( adsl_uga_subch_1_w1, 0, sizeof(struct dsd_uga_subch_1) );
   adsl_uga_subch_1_w1->dsc_uga_subch_s1.dsc_uga_subch_s_field.ucc_subchannel_id
     = adsp_cmd_ug->ucc_subchannel_id;      /* subchannel Id           */
   adsl_uga_subch_1_w1->vpc_udpr_handle = adsp_cmd_ug->vpc_udpr_handle;  /* handle of UDP associated request */
   adsl_uga_subch_1_w1->adsc_udp_gate_entry_1 = adsl_uge1_w1;  /* structure for a UDP-gate entry */
   memcpy( &adsl_uga_subch_1_w1->dsc_subch_sockaddr,  /* sockaddr structure subchannel */
           adsp_cmd_ug->achc_subch_sockaddr,  /* pointer to sockaddr structure subchannel */
           adsp_cmd_ug->imc_len_subch_sockaddr );  /* length of sockaddr structure subchannel */
   adsl_uga_subch_1_w1->boc_subch_srtp = adsp_cmd_ug->boc_subch_srtp;  /* SRTP is used */
#define ADSL_UDP_MULTIW_1_G ((struct dsd_udp_multiw_1 *) adsp_cmd_ug->vpc_udpr_handle)
#define ADSL_UDP_GW_1_G ((struct dsd_udp_gw_1 *) (ADSL_UDP_MULTIW_1_G + 1))
   if (adsp_cmd_ug->boc_subch_srtp == FALSE) {  /* SRTP is not used    */
// to-do 20.09.10 KB - does not need keys later
#ifdef XYZ1
     memcpy( adsl_uga_subch_1_w1 + 1,
             adsp_cmd_ug->achc_subch_keys,  /* address of subchannel keys */
             DEF_LEN_UDP_GATE_KEYS );       /* length of UDP-gate keys for HOBPhone */
#endif
     bol1 = m_udp_gate_encry_init( adsp_cmd_ug->achc_subch_keys,
                                   (char *) (adsl_uga_subch_1_w1 + 1),
                                   (char *) (adsl_uga_subch_1_w1 + 1) + DEF_LEN_UDP_GATE_ENCRY );
     if (bol1 == FALSE) {                   /* error occured           */
       free( adsl_uga_subch_1_w1 );         /* free memory again       */
// to-do 19.08.10 KB other error number - parameter error
       adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_misc;  /* miscellaneous error */
       return TRUE;
     }
     ADSL_UDP_MULTIW_1_G->amc_udp_recv_compl = &m_cb_rtp_sip_gw_recv;
     ADSL_UDP_GW_1_G->vpc_userfld = adsl_uga_subch_1_w1;
   }
   if (adsp_cmd_ug->boc_subch_srtp) {       /* SRTP is used            */
     ADSL_UDP_MULTIW_1_G->amc_udp_recv_compl = &m_cb_srtp_recv;
     ADSL_UDP_GW_1_G->vpc_userfld = adsl_uga_subch_1_w1;
   }
#undef ADSL_UDP_MULTIW_1_G
#undef ADSL_UDP_GW_1_G
   achl_avl_error = NULL;                   /* error code AVL tree     */
   dss_critsect_udp.m_enter();              /* critical section        */
   do {                                     /* pseudo-loop             */
     bol1 = m_htree1_avl_search( NULL,
                                 &dss_htree1_avl_cntl_udp_gate_m,
                                 &dsl_htree1_work,
                                 &adsl_uge1_w1->dsc_ug_sort.dsc_sort_1 );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "search in tree UDP-gate main failed";
       adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_misc;  /* miscellaneous error */
       break;
     }
#define ADSL_UGE1_G ((struct dsd_udp_gate_entry_1 *) ((char *) dsl_htree1_work.adsc_found \
                       - offsetof( struct dsd_udp_gate_entry_1, dsc_ug_sort ) \
                       - offsetof( struct dsd_udp_gate_sort_1, dsc_sort_1 )))
     if (dsl_htree1_work.adsc_found == NULL) {  /* not found in tree   */
       adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_not_in_tree;  /* the entry is not in the AVL-tree */
       bol1 = FALSE;                        /* error occured           */
       break;
     }
     memcpy( adsl_uga_subch_1_w1->dsc_uga_subch_s1.dsc_uga_subch_s_field.chrc_nonce,
             ADSL_UGE1_G->dsc_ug_sort.chrc_nonce,
             DEF_LEN_UDP_GATE_NONCE );      /* length of UDP-gate nonce */
#undef ADSL_UGE1_G
     bol1 = m_htree1_avl_search( NULL,
                                 &dss_htree1_avl_cntl_udp_gate_subch,
                                 &dsl_htree1_work,
                                 &adsl_uga_subch_1_w1->dsc_uga_subch_s1.dsc_sort_1 );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "search in tree UDP-gate subchannel failed";
       adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_misc;  /* miscellaneous error */
       break;
     }
     if (dsl_htree1_work.adsc_found) {      /* already found in tree   */
// to-do 19.08.10 KB other error number
       adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_not_in_tree;  /* the entry is not in the AVL-tree */
       bol1 = FALSE;                        /* error occured           */
       break;
     }
     bol1 = m_htree1_avl_insert( NULL,
                                 &dss_htree1_avl_cntl_udp_gate_subch,
                                 &dsl_htree1_work,
                                 &adsl_uga_subch_1_w1->dsc_uga_subch_s1.dsc_sort_1 );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "insert in tree UDP-gate subchannel failed";
       adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_misc;  /* miscellaneous error */
       break;
     }
   } while (FALSE);
   dss_critsect_udp.m_leave();              /* critical section        */
   if (achl_avl_error) {                    /* AVL-error occured       */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_aux_udp_gate_1() %s",
                     __LINE__, achl_avl_error );
   }
   if (bol1 == FALSE) {
     free( adsl_uga_subch_1_w1 );           /* free memory again       */
     return TRUE;                           /* error already set       */
   }
   adsp_cmd_ug->vpc_ug_subch_handle = adsl_uga_subch_1_w1;  /* handle of UDP-gate subchannel */
   adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_ok;  /* return success   */
   return TRUE;

   p_subch_close:                           /* close sub-channel       */
   adsl_uga_subch_1_w1 = (struct dsd_uga_subch_1 *) adsp_cmd_ug->vpc_ug_subch_handle;
   if (adsl_uga_subch_1_w1 == NULL) {       /* handle invalid          */
// to-do 19.08.10 KB other error number
     adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_handle_invalid;  /* the handle is invalid */
     return TRUE;
   }
   achl_avl_error = NULL;                   /* error code AVL tree     */
   dss_critsect_udp.m_enter();              /* critical section        */
   do {                                     /* pseudo-loop             */
     bol1 = m_htree1_avl_search( NULL,
                                 &dss_htree1_avl_cntl_udp_gate_subch,
                                 &dsl_htree1_work,
                                 &adsl_uga_subch_1_w1->dsc_uga_subch_s1.dsc_sort_1 );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "search in tree UDP-gate subchannel failed";
       adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_misc;  /* miscellaneous error */
       break;
     }
     if (dsl_htree1_work.adsc_found == NULL) {  /* not found in tree   */
       adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_not_in_tree;  /* the entry is not in the AVL-tree */
       bol1 = FALSE;                        /* error occured           */
       break;
     }
     bol1 = m_htree1_avl_delete( NULL,
                                 &dss_htree1_avl_cntl_udp_gate_subch,
                                 &dsl_htree1_work );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "delete from tree UDP-gate subchannel failed";
       adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_misc;  /* miscellaneous error */
       break;
     }
   } while (FALSE);
   dss_critsect_udp.m_leave();              /* critical section        */
   if (achl_avl_error) {                    /* AVL-error occured       */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_aux_udp_gate_1() %s",
                     __LINE__, achl_avl_error );
   }
   if (bol1 == FALSE) return TRUE;          /* error already set       */
   adsp_cmd_ug->iec_ret_ug = ied_ret_udp_gate_ok;  /* return success   */
   return TRUE;
} /* end m_aux_udp_gate_1()                                            */

/** retrieve counters of UDP gate                                      */
extern "C" void m_aux_gate_udp_counter( char *achp_ext,
                                        int *aimp_c_udp_rece, int *aimp_c_udp_send,
                                        HL_LONGLONG *ailp_d_udp_rece, HL_LONGLONG *ailp_d_udp_send ) {
#define ADSL_UGE1_G ((struct dsd_udp_gate_entry_1 *) achp_ext)
   *aimp_c_udp_rece = ADSL_UGE1_G->imc_c_udp_rece;  /* count receive UDP */
   *aimp_c_udp_send = ADSL_UGE1_G->imc_c_udp_send;  /* count send UDP  */
   *ailp_d_udp_rece = ADSL_UGE1_G->ilc_d_udp_rece;  /* data receive UDP */
   *ailp_d_udp_send = ADSL_UGE1_G->ilc_d_udp_send;  /* data send UDP   */
#undef ADSL_UGE1_G
} /* end m_aux_gate_udp_counter()                                      */

/** UDP gate cleanup for session over aux callback routine             */
//extern "C" void m_aux_gate_udp_cleanup( struct dsd_conn1 *adsp_conn1, char *achp_ext ) {
extern "C" void m_aux_gate_udp_cleanup( DSD_CONN_G *adsp_conn1, char *achp_ext ) {
   BOOL       bol1;                         /* working variable        */
   char       *achl_avl_error;              /* error code AVL tree     */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */

#define ADSL_UGE1_G ((struct dsd_udp_gate_entry_1 *) achp_ext)
   if (ADSL_UGE1_G->boc_deleted) return;    /* the entry is deleted    */
   achl_avl_error = NULL;                   /* error code AVL tree     */
   dss_critsect_udp.m_enter();              /* critical section        */
   do {                                     /* pseudo-loop             */
     bol1 = m_htree1_avl_search( NULL,
                                 &dss_htree1_avl_cntl_udp_gate_m,
                                 &dsl_htree1_work,
                                 &ADSL_UGE1_G->dsc_ug_sort.dsc_sort_1 );
     if (bol1 == FALSE) {                     /* error occured           */
       achl_avl_error = "search in tree failed";
       break;
     }
     if (dsl_htree1_work.adsc_found == NULL) {  /* not found in tree   */
       achl_avl_error = "entry not found in tree";
       bol1 = FALSE;                        /* error occured           */
       break;
     }
     bol1 = m_htree1_avl_delete( NULL,
                                 &dss_htree1_avl_cntl_udp_gate_m,
                                 &dsl_htree1_work );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "delete from tree failed";
       break;
     }
   } while (FALSE);
   dss_critsect_udp.m_leave();              /* critical section        */
   if (achl_avl_error) {                    /* AVL-error occured       */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_aux_gate_udp_cleanup() %s",
                     __LINE__, achl_avl_error );
   }
#undef ADSL_UGE1_G
} /* end m_aux_gate_udp_cleanup()                                      */

/** encrypt and send UDP-gate SRTP packet                              */
static void m_udp_gate_srtp_encry( struct dsd_hco_wothr *adsp_hco_wothr,
                                   void *ap_param_1, void *ap_param_2, void *ap_param_3 ) {
   int        iml_len;                      /* length returned         */
   int        iml_rc;                       /* return code             */
   unsigned int uml_sent;                   /* bytes sent              */
   struct dsd_udp_socket_1 *adsl_udp_socket_1_w1;  /* working variable */
#ifndef HL_UNIX
   WSABUF     dsrl_wsabuf[ 4 ];             /* buffer for WSASend()    */
#else
   struct msghdr dsl_msghdr;                /* for sendmsg()           */
   struct iovec dsrl_iov[ 4 ];              /* buffer for sendmsg()    */
#endif
   char       chrl_send[ 1024 ];

#define ADSL_UGA_SUBCH_1_G ((struct dsd_uga_subch_1 *) ap_param_1)
#define ADSL_UGE1_G (ADSL_UGA_SUBCH_1_G->adsc_udp_gate_entry_1)
#define ADSL_SDHC1_G ((struct dsd_sdh_control_1 *) ap_param_2)
#define ADSL_RECB_1_G ((struct dsd_sdh_udp_recbuf_1 *) (ADSL_SDHC1_G + 1))
   if (ADSL_RECB_1_G->imc_len_data <= 0) {
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_udp_gate_srtp_encry() subchannel %p data received length error",
                     __LINE__, ADSL_UGA_SUBCH_1_G );
     m_proc_free( ADSL_SDHC1_G );           /* free data received      */
// to-do 20.09.10 KB - counters
     return;
   }
   iml_len = m_udp_gate_encry_encode( chrl_send, 1024,
                                      ADSL_RECB_1_G->achc_data, ADSL_RECB_1_G->imc_len_data,
                                      (char *) (ADSL_UGA_SUBCH_1_G + 1) );
   if (iml_len <= 0) {                      /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_udp_gate_srtp_encry() subchannel %p m_udp_gate_encry_encode() returned %d.",
                     __LINE__, ADSL_UGA_SUBCH_1_G, iml_len );
     m_proc_free( ADSL_SDHC1_G );           /* free data received      */
// to-do 20.09.10 KB - counters
     return;
   }
#ifndef HL_UNIX
   dsrl_wsabuf[ 0 ].buf = (char *) ucrs_udp_gate_header;
   dsrl_wsabuf[ 0 ].len = sizeof(ucrs_udp_gate_header);
   dsrl_wsabuf[ 1 ].buf = ADSL_UGA_SUBCH_1_G->dsc_uga_subch_s1.dsc_uga_subch_s_field.chrc_nonce;
   dsrl_wsabuf[ 1 ].len = DEF_LEN_UDP_GATE_NONCE;  /* length of UDP-gate nonce */
   dsrl_wsabuf[ 2 ].buf = (char *) &ADSL_UGA_SUBCH_1_G->dsc_uga_subch_s1.dsc_uga_subch_s_field.ucc_subchannel_id;
   dsrl_wsabuf[ 2 ].len = 1;
   dsrl_wsabuf[ 3 ].buf = chrl_send;
   dsrl_wsabuf[ 3 ].len = iml_len;
#else
   dsrl_iov[ 0 ].iov_base = (char *) ucrs_udp_gate_header;
   dsrl_iov[ 0 ].iov_len = sizeof(ucrs_udp_gate_header);
   dsrl_iov[ 1 ].iov_base = ADSL_UGA_SUBCH_1_G->dsc_uga_subch_s1.dsc_uga_subch_s_field.chrc_nonce;
   dsrl_iov[ 1 ].iov_len = DEF_LEN_UDP_GATE_NONCE;  /* length of UDP-gate nonce */
   dsrl_iov[ 2 ].iov_base = (char *) &ADSL_UGA_SUBCH_1_G->dsc_uga_subch_s1.dsc_uga_subch_s_field.ucc_subchannel_id;
   dsrl_iov[ 2 ].iov_len = 1;
   dsrl_iov[ 3 ].iov_base = chrl_send;
   dsrl_iov[ 3 ].iov_len = iml_len;
#endif
   switch(ADSL_UGE1_G->dsc_soa_client.ss_family) {  /* check client    */
     case AF_INET:                          /* IPV4                    */
       adsl_udp_socket_1_w1 = adss_udp_socket_1_udp_gate_ipv4;
       break;
     case AF_INET6:                         /* IPV6                    */
       adsl_udp_socket_1_w1 = adss_udp_socket_1_udp_gate_ipv4;
       break;
     default:
// to-do 20.08.10 KB statistics and free
       return;
   }
#ifndef HL_UNIX
   iml_rc = WSASendTo( adsl_udp_socket_1_w1->dsc_udp_multiw_1.imc_socket,  /* UDP socket for sendto() */
                       dsrl_wsabuf, 4,
                       (DWORD *) &uml_sent, 0,
                       (struct sockaddr *) &ADSL_UGE1_G->dsc_soa_client,
                       sizeof(struct sockaddr_storage),
                       NULL, NULL );
   if (iml_rc != 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_udp_gate_srtp_encry() %p WSASendTo Return Code %d/%d.",
                     __LINE__, ADSL_UGA_SUBCH_1_G, iml_rc, m_ip_wsaglerr() );
   }
#else
   memset( &dsl_msghdr, 0, sizeof(struct msghdr) );
#ifndef HL_HPUX
   dsl_msghdr.msg_name = (struct sockaddr *) &ADSL_UGE1_G->dsc_soa_client;
#else
   dsl_msghdr.msg_name = (char *) &ADSL_UGE1_G->dsc_soa_client;
#endif
   dsl_msghdr.msg_namelen = sizeof(struct sockaddr_storage);
   dsl_msghdr.msg_iov = dsrl_iov;
   dsl_msghdr.msg_iovlen = 4;
// dsl_msghdr.msg_flags = 0;
   iml_rc = sendmsg( adsl_udp_socket_1_w1->dsc_udp_multiw_1.imc_socket, &dsl_msghdr, 0 );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_udp_gate_srtp_encry() %p sendmsg() return code %d/%d.",
                     __LINE__, ADSL_UGA_SUBCH_1_G, iml_rc, errno );
   }
#endif
// to-do 07.08.10 KB - count for statistic
   m_proc_free( ADSL_SDHC1_G );             /* free memory again       */
//
#undef ADSL_UGA_SUBCH_1_G
#undef ADSL_UGE1_G
#undef ADSL_SDHC1_G
#undef ADSL_RECB_1_G
} /* end m_udp_gate_srtp_encry()                                       */

/** decrypt and send UDP-gate SRTP packet                              */
static void m_udp_gate_srtp_decry( struct dsd_hco_wothr *adsp_hco_wothr,
                                   void *ap_param_1, void *ap_param_2, void *ap_param_3 ) {
   int        iml_len;                      /* length returned         */
   int        iml_rc;                       /* return code             */
   char       chrl_send[ 1024 ];

#define ADSL_UGA_SUBCH_1_G ((struct dsd_uga_subch_1 *) ap_param_1)
#define ADSL_UGE1_G (ADSL_UGA_SUBCH_1_G->adsc_udp_gate_entry_1)
#define ADSL_SDHC1_G ((struct dsd_sdh_control_1 *) ap_param_2)
#define ADSL_RECB_1_G ((struct dsd_sdh_udp_recbuf_1 *) (ADSL_SDHC1_G + 1))
#define IML_LEN_HEADER (sizeof(ucrs_udp_gate_header) + DEF_LEN_UDP_GATE_NONCE + 1)
   if (ADSL_RECB_1_G->imc_len_data <= 0) {
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_udp_gate_srtp_decry() subchannel %p data received length error",
                     __LINE__, ADSL_UGA_SUBCH_1_G );
     m_proc_free( ADSL_SDHC1_G );           /* free data received      */
// to-do 20.09.10 KB - counters
     return;
   }
   iml_len = m_udp_gate_encry_decode( chrl_send, 1024,
                                      ADSL_RECB_1_G->achc_data + IML_LEN_HEADER,
                                      ADSL_RECB_1_G->imc_len_data - IML_LEN_HEADER,
                                      (char *) (ADSL_UGA_SUBCH_1_G + 1) + DEF_LEN_UDP_GATE_ENCRY );
   if (iml_len <= 0) {                      /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_udp_gate_srtp_decry() subchannel %p m_udp_gate_encry_decode() returned %d.",
                     __LINE__, ADSL_UGA_SUBCH_1_G, iml_len );
     m_proc_free( ADSL_SDHC1_G );           /* free data received      */
// to-do 20.09.10 KB - counters
     return;
   }
#ifdef B101004
   iml_rc = m_ip_sendto( ((struct dsd_udp_socket_1 *) ADSL_UGA_SUBCH_1_G->vpc_udpr_handle)->dsc_udp_multiw_1.imc_socket,
                         chrl_send, iml_len,
                         0,
                         (struct sockaddr *) &ADSL_UGA_SUBCH_1_G->dsc_subch_sockaddr,
                         sizeof(struct sockaddr_storage) );
#endif
#define ADSL_UDP_MULTIW_1_G ((struct dsd_udp_multiw_1 *) ADSL_UGA_SUBCH_1_G->vpc_udpr_handle)
   iml_rc = m_ip_sendto( ADSL_UDP_MULTIW_1_G->imc_socket,
                         chrl_send, iml_len,
                         0,
                         (struct sockaddr *) &ADSL_UGA_SUBCH_1_G->dsc_subch_sockaddr,
                         sizeof(struct sockaddr_storage) );
#undef ADSL_UDP_MULTIW_1_G
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-udp-01-l%05d-T m_udp_gate_srtp_decry() sendto returned %d.",
                   __LINE__, iml_rc );
#endif
#ifndef HL_UNIX
   if (iml_rc != iml_len) {                 /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_udp_gate_srtp_decry() %p sendto length %d return code %d/%d.",
                     __LINE__, ADSL_UGA_SUBCH_1_G, iml_len, iml_rc, m_ip_wsaglerr() );
   }
// to-do 07.08.10 KB - count for statistic
#else
   if (iml_rc != iml_len) {                 /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_udp_gate_srtp_decry() %p sendto length %d return code %d/%d.",
                     __LINE__, ADSL_UGA_SUBCH_1_G, iml_len, iml_rc, errno );
   }
// to-do 07.08.10 KB - count for statistic
#endif
   m_proc_free( ADSL_SDHC1_G );             /* free memory again       */
//
#undef ADSL_UGA_SUBCH_1_G
#undef ADSL_UGE1_G
#undef ADSL_SDHC1_G
#undef ADSL_RECB_1_G
} /* end m_udp_gate_srtp_decry()                                       */

/** send all SNMP UDP packets to the corresponding targets             */
extern "C" int m_send_snmp_packet( char *achp_record, int imp_length ) {
   return 0;
} /* end m_send_snmp_packet()                                          */

/** start receiving on a UDP socket                                    */
extern "C" void m_start_udp_recv( struct dsd_udp_multiw_1 *adsp_udp_multiw_1 ) {
   BOOL       bol1;                         /* working-variable        */
   int        iml_rc;                       /* return code             */
#ifdef HL_UNIX
   int        imrl_fd_pipe[2];              /* file descriptores pipe  */
#endif
   struct dsd_udp_recv_thr *adsl_udprthr_w1;  /* threads to do UDP receive */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-udp-01 m_start_udp_recv( %p ) called",
                   __LINE__, adsp_udp_multiw_1 );
   adsl_udprthr_w1 = adss_udp_recv_thr_a;   /* get anchor threads to do UDP receive */
   while (adsl_udprthr_w1) {
     int      imh1 = 0;
     char     *achh_error = "";

     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-udp-01 adsl_udprthr_w1=%p imc_active=%d.",
                     __LINE__, adsl_udprthr_w1, adsl_udprthr_w1->imc_active );
     while (imh1 < adsl_udprthr_w1->imc_active) {
       char     *achh_error = "";
       struct dsd_udp_multiw_1 *adsh_udp_multiw_1 = adsl_udprthr_w1->adsrc_udp_multiw_1[ imh1 ];
       char     chrh_msg_1[ 128 ];
       char     chrh_msg_2[ 128 ];

       strcpy( chrh_msg_1, "- NULL - unknown -" );
       chrh_msg_2[ 0 ] = 0;
       if (adsh_udp_multiw_1) {
         sprintf( chrh_msg_1, "%p", adsh_udp_multiw_1->adsc_udprthr_w1 );
         if (adsh_udp_multiw_1->adsc_udprthr_w1 != adsl_udprthr_w1) {
           strcpy( chrh_msg_2, " - thread adsc_udprthr_w1 not set correct - error" );
         }
       }
       if (adsp_udp_multiw_1 == adsh_udp_multiw_1) {
         achh_error = " - entry double - error";
       }
       m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-udp-01 adsrc_udp_multiw_1[ %03d ] = %p adsc_udprthr_w1 = %s%s%s.",
                       __LINE__, imh1 + 1, adsh_udp_multiw_1, chrh_msg_1, achh_error, chrh_msg_2 );
       imh1++;                              /* increment index         */
     }
     adsl_udprthr_w1 = adsl_udprthr_w1->adsc_next;  /* get next thread from chain */
   }
#endif
   adsl_udprthr_w1 = adss_udp_recv_thr_a;   /* get anchor threads to do UDP receive */
   while (adsl_udprthr_w1) {
     if (adsl_udprthr_w1->imc_active < DEF_MAX_MULT_TH) {
       dss_critsect_udp.m_enter();
       if (adsl_udprthr_w1->imc_active < DEF_MAX_MULT_TH) {
         adsp_udp_multiw_1->adsc_udprthr_w1 = adsl_udprthr_w1;  /* thread to do UDP receive */
#ifndef HL_UNIX
         adsl_udprthr_w1->dsrc_hand_thr[ 1 + adsl_udprthr_w1->imc_active ]
           = adsp_udp_multiw_1->dsc_event;  /* WSA event for recv      */
#else
         adsl_udprthr_w1->dsrc_poll[ 1 + adsl_udprthr_w1->imc_active ].fd
           = adsp_udp_multiw_1->imc_socket;  /* socket for recv        */
#ifndef B140717
         adsl_udprthr_w1->dsrc_poll[ 1 + adsl_udprthr_w1->imc_active ].events
           = POLLIN;
#endif
#endif
         adsl_udprthr_w1->adsrc_udp_multiw_1[ adsl_udprthr_w1->imc_active ]
           = adsp_udp_multiw_1;
         adsl_udprthr_w1->imc_active++;     /* one more active now     */
         dss_critsect_udp.m_leave();
#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-udp-01 m_start_udp_recv( %p ) returns - adsp_udp_multiw_1->adsc_udprthr_w1=%p.",
                         __LINE__, adsp_udp_multiw_1, adsp_udp_multiw_1->adsc_udprthr_w1 );
#endif
#ifndef HL_UNIX
         bol1 = SetEvent( adsl_udprthr_w1->dsrc_hand_thr[ 0 ] );
         if (bol1) return;                  /* succeeded               */
         m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_start_udp_recv() %p SetEvent Return Code %d.",
                         __LINE__, adsl_udprthr_w1, GetLastError() );
         return;                            /* all done                */
#else
         iml_rc = write( adsl_udprthr_w1->imc_fd_pipe_write, &ims_write_pipe_recv, sizeof(int) );
         if (iml_rc == sizeof(int)) return;  /* succeeded              */
         m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_close_udp_recv() %p pipe write() return code %d/%d.",
                         __LINE__, adsl_udprthr_w1, iml_rc, errno );
         return;                            /* all done                */
#endif
       }
       dss_critsect_udp.m_leave();
     }
     adsl_udprthr_w1 = adsl_udprthr_w1->adsc_next;  /* get next thread from chain */
   }
   /* create an additional thread                                      */
   adsl_udprthr_w1 = (struct dsd_udp_recv_thr *) malloc( sizeof(struct dsd_udp_recv_thr) );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-udp-01 m_start_udp_recv( %p ) new thread adsl_udprthr_w1=%p.",
                   __LINE__, adsp_udp_multiw_1, adsl_udprthr_w1 );
#endif
   memset( adsl_udprthr_w1, 0, sizeof(struct dsd_udp_recv_thr) );
#ifndef HL_UNIX
   adsl_udprthr_w1->dsrc_hand_thr[ 0 ] = CreateEvent( NULL , TRUE , FALSE , NULL );
   if (adsl_udprthr_w1->dsrc_hand_thr[ 0 ] == NULL) {
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_start_udp_recv() %p CreateEvent Return Code %d.",
                     __LINE__, adsl_udprthr_w1, GetLastError() );
   }
   adsl_udprthr_w1->dsrc_hand_thr[ 1 ]
     = adsp_udp_multiw_1->dsc_event;        /* WSA event for recv      */
   adsl_udprthr_w1->adsrc_udp_multiw_1[ 0 ]
     = adsp_udp_multiw_1;
#else
   iml_rc = pipe( imrl_fd_pipe );           /* create pipe             */
   if (iml_rc != 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_start_udp_recv() %p pipe() return code %d/%d.",
                     __LINE__, adsl_udprthr_w1, iml_rc, errno );
   }
   adsl_udprthr_w1->imc_fd_pipe_write = imrl_fd_pipe[ 1 ];  /* file-descriptor write to file */
   adsl_udprthr_w1->dsrc_poll[ 0 ].fd = imrl_fd_pipe[ 0 ];
   adsl_udprthr_w1->dsrc_poll[ 0 ].events = POLLIN;
   adsl_udprthr_w1->dsrc_poll[ 1 ].fd
     = adsp_udp_multiw_1->imc_socket;       /* socket for recv         */
   adsl_udprthr_w1->dsrc_poll[ 1 ].events = POLLIN;
   adsl_udprthr_w1->adsrc_udp_multiw_1[ 0 ]
     = adsp_udp_multiw_1;
#endif
   adsl_udprthr_w1->imc_active = 1;
   adsl_udprthr_w1->imc_receive = 1;
   adsp_udp_multiw_1->adsc_udprthr_w1 = adsl_udprthr_w1;  /* thread to do UDP receive */
   dss_critsect_udp.m_enter();              /* critical section        */
   adsl_udprthr_w1->adsc_next = adss_udp_recv_thr_a;  /* get anchor threads to do UDP receive */
   adss_udp_recv_thr_a = adsl_udprthr_w1;   /* set new anchor threads to do UDP receive */
   dss_critsect_udp.m_leave();              /* critical section        */
   iml_rc = adsl_udprthr_w1->dsc_hcthread.mc_create( &m_udp_recv_thread, adsl_udprthr_w1 );
   if (iml_rc < 0) {                        /* create thread failed    */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_start_udp_recv() %p Create Thread Return Code %d.",
                     __LINE__, adsl_udprthr_w1, iml_rc );
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-udp-01 m_start_udp_recv( %p ) returns - adsp_udp_multiw_1->adsc_udprthr_w1=%p.",
                   __LINE__, adsp_udp_multiw_1, adsp_udp_multiw_1->adsc_udprthr_w1 );
#endif
   return;                                  /* all done                */
} /* end m_start_udp_recv()                                            */

/** end receiving on a UDP socket                                      */
static void m_close_udp_recv( struct dsd_udp_multiw_1 *adsp_udp_multiw_1 ) {
   BOOL       bol1;                         /* working-variable        */
   int        iml1;                         /* working-variable        */
#ifdef HL_UNIX
   int        iml_rc;                       /* return code             */
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-udp-01 m_close_udp_recv( %p ) called adsp_udp_multiw_1->adsc_udprthr_w1=%p.",
                   __LINE__, adsp_udp_multiw_1, adsp_udp_multiw_1->adsc_udprthr_w1 );
#endif
   adsp_udp_multiw_1->amc_udp_recv_compl = NULL;  /* first clear callback when receive complete */
#ifndef HELP_DEBUG
#define ADSL_UDPRTHR_G (adsp_udp_multiw_1->adsc_udprthr_w1)
#endif
#ifdef HELP_DEBUG
   struct dsd_udp_recv_thr *ADSL_UDPRTHR_G = adsp_udp_multiw_1->adsc_udprthr_w1;
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-udp-01 m_close_udp_recv( %p ) called ADSL_UDPRTHR_G->imc_receive=%d ADSL_UDP_RECV_THR->imc_active=%d.",
                   __LINE__, adsp_udp_multiw_1, ADSL_UDPRTHR_G->imc_receive, ADSL_UDPRTHR_G->imc_active );
#endif
#ifdef TRACEHL1
   m_display_udp( __LINE__, "m_close_udp_recv() before loop" );
#endif
   iml1 = 0;                                /* start at first entry    */
#ifndef B131231
   dss_critsect_udp.m_enter();
#endif
#ifdef B140123
   while (iml1 < ADSL_UDPRTHR_G->imc_receive) {  /* loop over all receiving entries */
     if (ADSL_UDPRTHR_G->adsrc_udp_multiw_1[ iml1 ] == adsp_udp_multiw_1) {
       ADSL_UDPRTHR_G->adsrc_udp_multiw_1[ iml1 ] = NULL;  /* remove entry */
       break;
     }
     iml1++;                                /* search next entry       */
   }
   if (iml1 >= ADSL_UDPRTHR_G->imc_receive) {  /* entry not found      */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_close_udp_recv() %p Entry %p not found",
                     __LINE__, ADSL_UDPRTHR_G, adsp_udp_multiw_1 );
   }
#endif
   while (iml1 < ADSL_UDPRTHR_G->imc_active) {  /* loop over active receives */
     if (ADSL_UDPRTHR_G->adsrc_udp_multiw_1[ iml1 ] == adsp_udp_multiw_1) {
       ADSL_UDPRTHR_G->adsrc_udp_multiw_1[ iml1 ] = NULL;  /* remove entry */
       break;
     }
     iml1++;                                /* search next entry       */
   }
   if (iml1 >= ADSL_UDPRTHR_G->imc_active) {  /* entry not found       */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_close_udp_recv() %p Entry %p not found",
                     __LINE__, ADSL_UDPRTHR_G, adsp_udp_multiw_1 );
   }
#ifndef B131231
   dss_critsect_udp.m_leave();
#endif
#ifdef TRACEHL1
   m_display_udp( __LINE__, "m_close_udp_recv() after  loop" );
#endif
#ifndef HL_UNIX
   bol1 = SetEvent( ADSL_UDPRTHR_G->dsrc_hand_thr[ 0 ] );
   if (bol1) return;                        /* succeeded               */
   m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_close_udp_recv() %p SetEvent Return Code %d.",
                   __LINE__, ADSL_UDPRTHR_G, GetLastError() );
   return;                                  /* all done                */
#else
   iml_rc = write( ADSL_UDPRTHR_G->imc_fd_pipe_write, &ims_write_pipe_recv, sizeof(int) );
   if (iml_rc == sizeof(int)) return;       /* succeeded               */
   m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_close_udp_recv() %p pipe write() return code %d/%d.",
                   __LINE__, ADSL_UDPRTHR_G, iml_rc, errno );
   return;                                  /* all done                */
#endif
#ifndef HELP_DEBUG
#undef ADSL_UDPRTHR_G
#endif
} /* end m_close_udp_recv()                                            */

/** set connection for UDP entry                                       */
extern "C" void m_udp_set_conn1( void * ap_udpr_handle, void * ap_conn1 ) {
#define ADSL_UDP_MULTIW_1_G ((struct dsd_udp_multiw_1 *) ap_udpr_handle)
#define ADSL_UDP_GW_1_G ((struct dsd_udp_gw_1 *) (ADSL_UDP_MULTIW_1_G + 1))
// ADSL_UDP_GW_1_G->adsc_conn1 = (struct dsd_conn1 *) ap_conn1;
   ADSL_UDP_GW_1_G->adsc_conn1 = (DSD_CONN_G *) ap_conn1;
#undef ADSL_UDP_MULTIW_1_G
#undef ADSL_UDP_GW_1_G
} /* end m_udp_set_conn1()                                             */

/** callback for receiving on a UDP-gate socket                        */
static void m_cb_gate_recv( struct dsd_udp_multiw_1 *adsp_udp_multiw_1,
                            struct dsd_sdh_control_1 *adsp_sdhc1_rb ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
   char       *achl_avl_error;              /* error code AVL tree     */
   struct dsd_udp_gate_sort_1 dsl_ug_sort;  /* structure for a UDP-gate sort */
   struct dsd_udp_gate_subch_sort_1 dsl_uga_subch_s1_l;  /* structure for a UDP-gate subchannel sort */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   struct dsd_call_para_1 dsl_call_para_1_w1;  /* call parameters      */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-udp-01-%05d-T m_cb_gate_recv( %p , %p ) called",
                   __LINE__, adsp_udp_multiw_1, adsp_sdhc1_rb );
#endif
#define ADSL_RECB_1_G ((struct dsd_sdh_udp_recbuf_1 *) (adsp_sdhc1_rb + 1))
   if (ADSL_RECB_1_G->imc_len_data < (sizeof(ucrs_udp_gate_header) + DEF_LEN_UDP_GATE_NONCE + 1)) {
// to-do 07.08.10 KB - count for statistic
     goto p_free_00;                        /* free the buffer         */
   }
   if (memcmp( ADSL_RECB_1_G->achc_data, ucrs_udp_gate_header, sizeof(ucrs_udp_gate_header) )) {
// to-do 07.08.10 KB - count for statistic
     goto p_free_00;                        /* free the buffer         */
   }
#define UCL_MIME_G (*((unsigned char *) ADSL_RECB_1_G->achc_data + sizeof(ucrs_udp_gate_header) + DEF_LEN_UDP_GATE_NONCE))
   if (scrs_from_base64[ UCL_MIME_G ] >= 0) {  /* with subchannel Id   */
     goto p_load_00;                        /* packet with load        */
   }
#undef UCL_MIME_G
   memcpy( dsl_ug_sort.chrc_nonce, ADSL_RECB_1_G->achc_data + sizeof(ucrs_udp_gate_header), DEF_LEN_UDP_GATE_NONCE );  /* copy the nonce */
   achl_avl_error = NULL;                   /* error code AVL tree     */
   dss_critsect_udp.m_enter();              /* critical section        */
   bol1 = m_htree1_avl_search( NULL,
                               &dss_htree1_avl_cntl_udp_gate_m,
                               &dsl_htree1_work,
                               &dsl_ug_sort.dsc_sort_1 );
   if (bol1 == FALSE) {                     /* error occured           */
     achl_avl_error = "search in tree UDP-gate main failed";
   }
   dss_critsect_udp.m_leave();              /* critical section        */
   if (achl_avl_error) {                    /* AVL-error occured       */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_aux_udp_gate_1() %s",
                     __LINE__, achl_avl_error );
   }
   if (bol1 == FALSE) {                     /* error occured           */
// to-do 07.08.10 KB - count for statistic
     goto p_free_00;                        /* free the buffer         */
   }
#define ADSL_UGE1_G ((struct dsd_udp_gate_entry_1 *) ((char *) dsl_htree1_work.adsc_found \
                       - offsetof( struct dsd_udp_gate_entry_1, dsc_ug_sort ) \
                       - offsetof( struct dsd_udp_gate_sort_1, dsc_sort_1 )))
   if (dsl_htree1_work.adsc_found == NULL) {  /* not found in tree     */
// to-do 07.08.10 KB - count for statistic
     goto p_free_00;                        /* free the buffer         */
   }
   ADSL_UGE1_G->imc_len_soa_client = ADSL_RECB_1_G->imc_len_sockaddr;  /* length address information client */
   memcpy( &ADSL_UGE1_G->dsc_soa_client, ADSL_RECB_1_G->achc_sockaddr, ADSL_RECB_1_G->imc_len_sockaddr );
   ADSL_UGE1_G->imc_c_udp_rece++;           /* count receive UDP       */
   ADSL_UGE1_G->ilc_d_udp_rece += ADSL_RECB_1_G->imc_len_data;  /* data receive UDP */
   if (*(ADSL_RECB_1_G->achc_data + sizeof(ucrs_udp_gate_header) + DEF_LEN_UDP_GATE_NONCE)
          != WSP_HPUPD_MSG_0_CH) {          /* not from the client / function / subchannel ? 0X3F */
// to-do 07.08.10 KB - count for statistic
     goto p_free_00;                        /* free the buffer         */
   }
   *(ADSL_RECB_1_G->achc_data + sizeof(ucrs_udp_gate_header) + DEF_LEN_UDP_GATE_NONCE)
     = WSP_HPUPD_MSG_1_CH;                  /* function / subchannel ! 0X21 */
   iml_rc = m_ip_sendto( adsp_udp_multiw_1->imc_socket,
                         ADSL_RECB_1_G->achc_data, sizeof(ucrs_udp_gate_header) + DEF_LEN_UDP_GATE_NONCE + 1,
                         0,
                         (struct sockaddr *) &ADSL_UGE1_G->dsc_soa_client, ADSL_UGE1_G->imc_len_soa_client );
#ifndef HL_UNIX
   if (iml_rc <= 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_cb_gate_recv() send return code %d/%d.",
                     __LINE__, iml_rc, m_ip_wsaglerr() );
// to-do 07.08.10 KB - count for statistic
   }
#else
   if (iml_rc <= 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_cb_gate_recv() send return code %d/%d.",
                     __LINE__, iml_rc, errno );
// to-do 07.08.10 KB - count for statistic
   }
#endif
   if (iml_rc > 0) {                        /* data sent               */
     ADSL_UGE1_G->imc_c_udp_send++;         /* count send UDP          */
     ADSL_UGE1_G->ilc_d_udp_send += iml_rc;  /* data send UDP          */
   }
   goto p_free_00;                          /* free the buffer         */
#undef ADSL_UGE1_G

   p_load_00:                               /* packet with load        */
   memcpy( dsl_uga_subch_s1_l.dsc_uga_subch_s_field.chrc_nonce,
           ADSL_RECB_1_G->achc_data + sizeof(ucrs_udp_gate_header),
           DEF_LEN_UDP_GATE_NONCE );        /* copy the nonce          */
#define UCL_MIME_G (*((unsigned char *) ADSL_RECB_1_G->achc_data + sizeof(ucrs_udp_gate_header) + DEF_LEN_UDP_GATE_NONCE))
   dsl_uga_subch_s1_l.dsc_uga_subch_s_field.ucc_subchannel_id = UCL_MIME_G;
#undef UCL_MIME_G
   achl_avl_error = NULL;                   /* error code AVL tree     */
   dss_critsect_udp.m_enter();              /* critical section        */
   bol1 = m_htree1_avl_search( NULL,
                               &dss_htree1_avl_cntl_udp_gate_subch,
                               &dsl_htree1_work,
                               &dsl_uga_subch_s1_l.dsc_sort_1 );
   if (bol1 == FALSE) {                     /* error occured           */
     achl_avl_error = "search in tree UDP-gate subchannel failed";
   }
   dss_critsect_udp.m_leave();              /* critical section        */
   if (achl_avl_error) {                    /* AVL-error occured       */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_aux_udp_gate_1() %s",
                     __LINE__, achl_avl_error );
   }
   if (bol1 == FALSE) {                     /* error occured           */
// to-do 07.08.10 KB - count for statistic
     goto p_free_00;                        /* free the buffer         */
   }
   if (dsl_htree1_work.adsc_found == NULL) {  /* not found in tree     */
// to-do 07.08.10 KB - count for statistic
     goto p_free_00;                        /* free the buffer         */
   }
   iml1 = ADSL_RECB_1_G->imc_len_data - ((sizeof(ucrs_udp_gate_header) + DEF_LEN_UDP_GATE_NONCE + 1));
   if (iml1 <= 0) {                         /* nothing to send         */
// to-do 07.08.10 KB - count for statistic
     goto p_free_00;                        /* free the buffer         */
   }
// to-do 20.08.10 KB name ADSL_UGA_SUBCH_1_G misleading, not _s1_
#define ADSL_UGA_SUBCH_1_G ((struct dsd_uga_subch_1 *) ((char *) dsl_htree1_work.adsc_found \
            - offsetof( struct dsd_uga_subch_1, dsc_uga_subch_s1 ) \
            - offsetof( struct dsd_udp_gate_subch_sort_1, dsc_sort_1 )))
#define ADSL_UDP_MULTIW_1_G ((struct dsd_udp_multiw_1 *) ADSL_UGA_SUBCH_1_G->vpc_udpr_handle)
   if (ADSL_UGA_SUBCH_1_G->boc_subch_srtp) {  /* SRTP is used          */
     goto p_load_40;                        /* packet with SRTP        */
   }
// to-do 20.08.10 KB - SRTP / RTP
// to-do 20.09.10 KB counts and check backlog work-threads
   memset( &dsl_call_para_1_w1, 0, sizeof(struct dsd_call_para_1) );
   dsl_call_para_1_w1.amc_function = &m_udp_gate_srtp_decry;
   dsl_call_para_1_w1.ac_param_1 = ADSL_UGA_SUBCH_1_G;
   dsl_call_para_1_w1.ac_param_2 = adsp_sdhc1_rb;
   m_hco_run_thread( &dsl_call_para_1_w1 );
   return;                                  /* all done                */

   p_load_40:                               /* packet with SRTP        */
   iml_rc = m_ip_sendto( ADSL_UDP_MULTIW_1_G->imc_socket,
                         ADSL_RECB_1_G->achc_data
                           + sizeof(ucrs_udp_gate_header)
                           + DEF_LEN_UDP_GATE_NONCE
                           + 1,
                         iml1,
                         0,
                         (struct sockaddr *) &ADSL_UGA_SUBCH_1_G->dsc_subch_sockaddr,
                         sizeof(struct sockaddr_storage) );
#ifndef HL_UNIX
   if (iml_rc <= 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_cb_gate_recv() send return code %d/%d.",
                     __LINE__, iml_rc, m_ip_wsaglerr() );
// to-do 07.08.10 KB - count for statistic
   }
#else
   if (iml_rc <= 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_cb_gate_recv() send return code %d/%d.",
                     __LINE__, iml_rc, errno );
// to-do 07.08.10 KB - count for statistic
   }
#endif
   if (iml_rc > 0) {                        /* data sent               */
//   ADSL_UGE1_G->imc_c_udp_send++;         /* count send UDP          */
//   ADSL_UGE1_G->ilc_d_udp_send += iml_rc;  /* data send UDP          */
   }
#undef ADSL_UDP_MULTIW_1_G
#undef ADSL_UGA_SUBCH_1_G

   p_free_00:                               /* free the buffer         */
   m_proc_free( adsp_sdhc1_rb );            /* free memory again       */
#undef ADSL_RECB_1_G
} /* end m_cb_gate_recv()                                              */

/** callback for receiving on a socket where we do RTP with the SIP-gateway for HOBPhone */
static void m_cb_rtp_sip_gw_recv( struct dsd_udp_multiw_1 *adsp_udp_multiw_1,
                                  struct dsd_sdh_control_1 *adsp_sdhc1_rb ) {
   struct dsd_call_para_1 dsl_call_para_1_w1;  /* call parameters      */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-udp-01-%05d-T m_cb_srtp_recv( %p , %p ) called",
                   __LINE__, adsp_udp_multiw_1, adsp_sdhc1_rb );
#endif
// to-do 20.09.10 KB counts and check backlog work-threads
#define ADSL_UDP_GW_1_G ((struct dsd_udp_gw_1 *) (adsp_udp_multiw_1 + 1))
#define ADSL_UGA_SUBCH_1_G ((struct dsd_uga_subch_1 *) ADSL_UDP_GW_1_G->vpc_userfld)
   memset( &dsl_call_para_1_w1, 0, sizeof(struct dsd_call_para_1) );
   dsl_call_para_1_w1.amc_function = &m_udp_gate_srtp_encry;
   dsl_call_para_1_w1.ac_param_1 = ADSL_UGA_SUBCH_1_G;
   dsl_call_para_1_w1.ac_param_2 = adsp_sdhc1_rb;
   m_hco_run_thread( &dsl_call_para_1_w1 );
   return;
#undef ADSL_UDP_GW_1_G
#undef ADSL_UGA_SUBCH_1_G
} /* end m_cb_rtp_sip_gw_recv()                                        */

/** callback for receiving on a socket where we do SRTP with HOBPhone  */
static void m_cb_srtp_recv( struct dsd_udp_multiw_1 *adsp_udp_multiw_1,
                            struct dsd_sdh_control_1 *adsp_sdhc1_rb ) {
   int        iml_rc;                       /* return code             */
   unsigned int uml_sent;                   /* bytes sent              */
   struct dsd_udp_socket_1 *adsl_udp_socket_1_w1;  /* working variable */
#ifndef HL_UNIX
   WSABUF     dsrl_wsabuf[ 4 ];             /* buffer for WSASend()    */
#else
   struct msghdr dsl_msghdr;                /* for sendmsg()           */
   struct iovec dsrl_iov[ 4 ];              /* buffer for sendmsg()    */
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-udp-01-%05d-T m_cb_srtp_recv( %p , %p ) called",
                   __LINE__, adsp_udp_multiw_1, adsp_sdhc1_rb );
#endif
#define ADSL_RECB_1_G ((struct dsd_sdh_udp_recbuf_1 *) (adsp_sdhc1_rb + 1))
#define ADSL_UDP_GW_1_G ((struct dsd_udp_gw_1 *) (adsp_udp_multiw_1 + 1))
#define ADSL_UGA_SUBCH_1_G ((struct dsd_uga_subch_1 *) ADSL_UDP_GW_1_G->vpc_userfld)
#define ADSL_UGE1_G (ADSL_UGA_SUBCH_1_G->adsc_udp_gate_entry_1)
#ifndef HL_UNIX
   dsrl_wsabuf[ 0 ].buf = (char *) ucrs_udp_gate_header;
   dsrl_wsabuf[ 0 ].len = sizeof(ucrs_udp_gate_header);
   dsrl_wsabuf[ 1 ].buf = ADSL_UGA_SUBCH_1_G->dsc_uga_subch_s1.dsc_uga_subch_s_field.chrc_nonce;
   dsrl_wsabuf[ 1 ].len = DEF_LEN_UDP_GATE_NONCE;  /* length of UDP-gate nonce */
   dsrl_wsabuf[ 2 ].buf = (char *) &ADSL_UGA_SUBCH_1_G->dsc_uga_subch_s1.dsc_uga_subch_s_field.ucc_subchannel_id;
   dsrl_wsabuf[ 2 ].len = 1;
   dsrl_wsabuf[ 3 ].buf = ADSL_RECB_1_G->achc_data;
   dsrl_wsabuf[ 3 ].len = ADSL_RECB_1_G->imc_len_data;
#else
   dsrl_iov[ 0 ].iov_base = (char *) ucrs_udp_gate_header;
   dsrl_iov[ 0 ].iov_len = sizeof(ucrs_udp_gate_header);
   dsrl_iov[ 1 ].iov_base = ADSL_UGA_SUBCH_1_G->dsc_uga_subch_s1.dsc_uga_subch_s_field.chrc_nonce;
   dsrl_iov[ 1 ].iov_len = DEF_LEN_UDP_GATE_NONCE;  /* length of UDP-gate nonce */
   dsrl_iov[ 2 ].iov_base = (char *) &ADSL_UGA_SUBCH_1_G->dsc_uga_subch_s1.dsc_uga_subch_s_field.ucc_subchannel_id;
   dsrl_iov[ 2 ].iov_len = 1;
   dsrl_iov[ 3 ].iov_base = ADSL_RECB_1_G->achc_data;
   dsrl_iov[ 3 ].iov_len = ADSL_RECB_1_G->imc_len_data;
#endif
   switch(ADSL_UGE1_G->dsc_soa_client.ss_family) {  /* check client    */
     case AF_INET:                          /* IPV4                    */
       adsl_udp_socket_1_w1 = adss_udp_socket_1_udp_gate_ipv4;
       break;
     case AF_INET6:                         /* IPV6                    */
       adsl_udp_socket_1_w1 = adss_udp_socket_1_udp_gate_ipv4;
       break;
     default:
// to-do 20.08.10 KB statistics and free
       return;
   }
#ifndef HL_UNIX
   iml_rc = WSASendTo( adsl_udp_socket_1_w1->dsc_udp_multiw_1.imc_socket,  /* UDP socket for sendto() */
                       dsrl_wsabuf, 4,
                       (DWORD *) &uml_sent, 0,
#ifdef XYZ1
                       (struct sockaddr *) &ADSL_UGA_SUBCH_1_G->dsc_subch_sockaddr,
                       sizeof(struct sockaddr_storage),
#endif
                       (struct sockaddr *) &ADSL_UGE1_G->dsc_soa_client,
                       sizeof(struct sockaddr_storage),
                       NULL, NULL );
   if (iml_rc != 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_cb_srtp_recv() %p WSASendTo Return Code %d/%d.",
                     __LINE__, adsp_udp_multiw_1, iml_rc, m_ip_wsaglerr() );
   }
#else
   memset( &dsl_msghdr, 0, sizeof(struct msghdr) );
#ifndef HL_HPUX
   dsl_msghdr.msg_name = (struct sockaddr *) &ADSL_UGE1_G->dsc_soa_client;
#else
   dsl_msghdr.msg_name = (char *) &ADSL_UGE1_G->dsc_soa_client;
#endif
   dsl_msghdr.msg_namelen = sizeof(struct sockaddr_storage);
   dsl_msghdr.msg_iov = dsrl_iov;
   dsl_msghdr.msg_iovlen = 4;
// dsl_msghdr.msg_flags = 0;
   iml_rc = sendmsg( adsl_udp_socket_1_w1->dsc_udp_multiw_1.imc_socket, &dsl_msghdr, 0 );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_cb_srtp_recv() %p sendmsg() return code %d/%d.",
                     __LINE__, adsp_udp_multiw_1, iml_rc, errno );
   }
#endif
// to-do 07.08.10 KB - count for statistic
   m_proc_free( adsp_sdhc1_rb );            /* free memory again       */
#undef ADSL_UGE1_G
#undef ADSL_UGA_SUBCH_1_G
#undef ADSL_UDP_GW_1_G
#undef ADSL_RECB_1_G
} /* end m_cb_srtp_recv()                                              */

/** callback for receiving on a socket where we do not expect to receive something */
static void m_cb_none_recv( struct dsd_udp_multiw_1 *adsp_udp_multiw_1,
                           struct dsd_sdh_control_1 *adsp_sdhc1_rb ) {
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-udp-01-%05d-T m_cb_none_recv( %p , %p ) called",
                   __LINE__, adsp_udp_multiw_1, adsp_sdhc1_rb );
#endif
// to-do 07.08.10 KB - count for statistic
   m_proc_free( adsp_sdhc1_rb );            /* free memory again       */
} /* end m_cb_none_recv()                                              */

/** callback for receiving on a UDP socket                             */
static void m_cb_udp_recv( struct dsd_udp_multiw_1 *adsp_udp_multiw_1,
                           struct dsd_sdh_control_1 *adsp_sdhc1_rb ) {
   BOOL       bol1;                         /* working-variable        */
   BOOL       bol_signal;                   /* set signal              */
   int        iml1, iml2;                   /* working-variables       */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_sdh_control_1 *adsl_sdhc1_cur;  /* current in chain      */
   struct dsd_sdh_control_1 *adsl_sdhc1_end;  /* end of chain          */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   struct dsd_wsp_trace_info_conn1 dsl_wtic;  /* WSP trace information for connection */

#ifdef SLEEP_RECV_UDP
   Sleep( 1000 );
#endif
#define ADSL_UDP_MULTIW_1_G adsp_udp_multiw_1
#define ADSL_UDP_GW_1_G ((struct dsd_udp_gw_1 *) (ADSL_UDP_MULTIW_1_G + 1))
#ifndef TRY100302
#define ADSL_RECB_1_G ((struct dsd_sdh_udp_recbuf_1 *) (adsp_sdhc1_rb + 1))
#else
#define ADSL_RECB_1_G ((struct dsd_sdh_udp_recbuf_1 *) ((BOOL *) (adsp_sdhc1_rb + 1) + 1))
#endif
   bol1 = m_check_conn_active( ADSL_UDP_GW_1_G->adsc_conn1 );  /* check if session still active */
   if (bol1 == FALSE) {                     /* session no more active  */
     m_proc_free( adsp_sdhc1_rb );          /* free memory again       */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_cb_udp_recv() Session %p no more active",
                     __LINE__, ADSL_UDP_GW_1_G->adsc_conn1 );
     return;
   }
   m_get_wsp_trace_info_conn1( &dsl_wtic, ADSL_UDP_GW_1_G->adsc_conn1 );
   if (dsl_wtic.imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SSIPURE1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = dsl_wtic.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "UDP data received length %d/0X%X.",
                     ADSL_RECB_1_G->imc_len_data, ADSL_RECB_1_G->imc_len_data );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (   (ADSL_RECB_1_G->imc_len_data > 0)
         && (dsl_wtic.imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
//     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
       achl_w1 = (char *) (((size_t) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml1 = ADSL_RECB_1_G->imc_len_data;  /* length of data received */
       achl_w3 = ADSL_RECB_1_G->achc_data;  /* start of data           */
       adsl_wt1_w2 = adsl_wt1_w1;           /* in this piece of memory */
       adsl_wtr_w1 = ADSL_WTR_G1;           /* set last in chain       */
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
         if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
           adsl_wtr_w1->boc_more = TRUE;    /* more data to follow     */
         }
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
       } while (iml1 > 0);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (ADSL_RECB_1_G->imc_len_data > 0) {
     m_count_recv_server( ADSL_UDP_GW_1_G->adsc_conn1, ADSL_RECB_1_G->imc_len_data );
   }
#undef ADSL_RECB_1_G
   bol_signal = FALSE;                      /* reset set signal        */
   dss_critsect_udp.m_enter();              /* critical section        */
   if (ADSL_UDP_GW_1_G->adsc_sdhc1_rb == NULL) {  /* first in chain    */
     ADSL_UDP_GW_1_G->adsc_sdhc1_rb = adsp_sdhc1_rb;
     bol_signal = TRUE;                     /* set signal              */
   } else {                                 /* append to chain         */
     adsl_sdhc1_cur = ADSL_UDP_GW_1_G->adsc_sdhc1_rb;  /* get chain       */
     do {                                   /* loop over chain of buffers */
#ifdef TRY100302
       if (*((BOOL *) (adsl_sdhc1_cur + 1))) {  /* buffer already given */
         bol_signal = TRUE;                 /* set signal              */
       }
#endif
       adsl_sdhc1_end = adsl_sdhc1_cur;     /* save current entry      */
       adsl_sdhc1_cur = adsl_sdhc1_cur->adsc_next;  /* get next in chain */
     } while (adsl_sdhc1_cur);
     adsl_sdhc1_end->adsc_next = adsp_sdhc1_rb;  /* append to chain    */
   }
   dss_critsect_udp.m_leave();              /* critical section        */
   if (bol_signal == FALSE) return;
   /* activate work-thread for this connection                         */
   m_act_conn1_signal( ADSL_UDP_GW_1_G->adsc_conn1, (char *) ADSL_UDP_MULTIW_1_G, ADSL_UDP_GW_1_G->imc_signal );
#undef ADSL_UDP_MULTIW_1_G
#undef ADSL_UDP_GW_1_G
} /* end m_cb_udp_recv()                                               */

/** callback for receiving SIP packets on a UDP socket IPV4            */
static void m_cb_sip_ipv4_recv( struct dsd_udp_multiw_1 *adsp_udp_multiw_1,
                                struct dsd_sdh_control_1 *adsp_sdhc1_rb ) {
   BOOL       bol1;                         /* working-variable        */
   BOOL       bol_signal;                   /* set signal              */
   int        iml1, iml2;                   /* working-variables       */
   int        iml_cmp;                      /* length to compare       */
   int        iml_status;                   /* status of input         */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   char       *achl_cur, *achl_end;         /* pointer input data      */
   char       *achl_cmp;                    /* data to compare         */
   char       *achl_out;                    /* output data             */
   struct dsd_sip_gw_1 *adsl_sip_gw_1_w1;   /* structure for a SIP gateway */
   struct dsd_sdh_control_1 *adsl_sdhc1_cur;  /* current in chain      */
   struct dsd_sdh_control_1 *adsl_sdhc1_end;  /* end of chain          */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   struct dsd_sip_compare {
     struct dsd_sip_entry_1 dsc_sip_entry_1;  /* structure for a SIP entry */
     char     chrc_sip_ident[ MAX_LEN_SIP_IDENT ];
   } dsl_sip_compare;
   struct dsd_wsp_trace_info_conn1 dsl_wtic;  /* WSP trace information for connection */

   adsl_sip_gw_1_w1 = adss_sip_gw_1_a;      /* get anchor SIP gateways */
   while (adsl_sip_gw_1_w1) {               /* loop over all active SIP gateways */
#ifndef TRY100302
     if (   (adsl_sip_gw_1_w1->imc_len_ineta_sip_gw == 4)  /* length IPV4 */
         && (!memcmp( &((sockaddr_in *) ((struct dsd_sdh_udp_recbuf_1 *) (adsp_sdhc1_rb + 1))->achc_sockaddr)
                        ->sin_addr.s_addr,
                      adsl_sip_gw_1_w1 + 1,
                      4 ))) {
       break;
     }
#else
#define ADSL_RECB_1_G ((struct dsd_sdh_udp_recbuf_1 *) ((BOOL *) (adsp_sdhc1_rb + 1) + 1))
     if (   (adsl_sip_gw_1_w1->imc_len_ineta_sip_gw == 4)  /* length IPV4 */
         && (!memcmp( &((sockaddr_in *) ADSL_RECB_1_G->achc_sockaddr)
                        ->sin_addr.s_addr,
                      adsl_sip_gw_1_w1 + 1,
                      4 ))) {
       break;
     }
#undef ADSL_RECB_1_G
#endif
     adsl_sip_gw_1_w1 = adsl_sip_gw_1_w1->adsc_next;  /* get next in chain */
   }
   if (adsl_sip_gw_1_w1 == NULL) {          /* SIP gateway not found   */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_cb_sip_ipv4_recv() data received but no corresponding SIP gateway",
                     __LINE__ );
     m_proc_free( adsp_sdhc1_rb );          /* free data received      */
     return;
   }
#ifdef XYZ1
struct dsd_sdh_udp_recbuf_1 {               /* UDP receive buffer      */
   struct dsd_sdh_udp_recbuf_1 *adsc_next;  /* next in chain           */
   char       *achc_data;                   /* pointer to data         */
   char       *achc_sockaddr;               /* pointer to sockaddr structure */
   int        imc_len_data;                 /* length of data          */
   int        imc_len_sockaddr;             /* length of sockaddr structure */
};
#endif
#ifndef TRY100302
#define ADSL_RECB_1_G ((struct dsd_sdh_udp_recbuf_1 *) (adsp_sdhc1_rb + 1))
#else
#define ADSL_RECB_1_G ((struct dsd_sdh_udp_recbuf_1 *) ((BOOL *) (adsp_sdhc1_rb + 1) + 1))
#endif
   if (ADSL_RECB_1_G->imc_len_data <= 0) {
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_cb_sip_ipv4_recv() SIP gateway %p data received length error",
                     __LINE__, adsl_sip_gw_1_w1 );
     m_proc_free( adsp_sdhc1_rb );          /* free data received      */
     return;
   }
   achl_cur = ADSL_RECB_1_G->achc_data;     /* pointer to data         */
   achl_end = achl_cur + ADSL_RECB_1_G->imc_len_data;
   achl_cmp = (char *) ucrs_sip_to;
   iml_cmp = sizeof(ucrs_sip_to);
   if (!memcmp( achl_cur, ucrs_sip_resp, sizeof(ucrs_sip_resp) )) {
     achl_cmp = (char *) ucrs_sip_from;
     iml_cmp = sizeof(ucrs_sip_from);
   }
   iml_status = 0;

   p_srecv_00:                              /* search carriage-return line-feed */
   if (achl_cur >= achl_end) {
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_cb_sip_ipv4_recv() SIP gateway %p data received To / From not found",
                     __LINE__, adsl_sip_gw_1_w1 );
     m_proc_free( adsp_sdhc1_rb );          /* free data received      */
     return;
   }
   switch (*achl_cur) {                     /* current character       */
     case CHAR_CR:                          /* carriage-return         */
       iml_status = 1;
       break;
     case CHAR_LF:                          /* line-feed               */
       if (iml_status > 0) {
         iml_status = -1;                   /* sequence found          */
         break;
       }
       break;
     default:
       iml_status = 0;
       break;
   }
   achl_cur++;
   if (iml_status >= 0) goto p_srecv_00;    /* search carriage-return line-feed */
   if (memcmp( achl_cur, achl_cmp, iml_cmp )) {
     iml_status = 0;
     goto p_srecv_00;                       /* search carriage-return line-feed */
   }
   achl_cur += iml_cmp;
   iml_status = 0;

   p_srecv_20:                              /* search Ident            */
   if (achl_cur >= achl_end) {
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_cb_sip_ipv4_recv() SIP gateway %p data received Ident not found",
                     __LINE__, adsl_sip_gw_1_w1 );
     m_proc_free( adsp_sdhc1_rb );          /* free data received      */
     return;
   }
   switch (*achl_cur) {                     /* current character       */
     case ' ':                              /* space to be ignored     */
       break;
     case '\"':                             /* something in quotes     */
       iml_status ^= 1;                     /* set / reset bit         */
       break;
     default:
       if (iml_status) break;               /* still in quotes         */
       iml_status = -1;
       break;
   }
   if (iml_status >= 0) {                   /* still not end of ident  */
     achl_cur++;                            /* overread this character */
     goto p_srecv_20;                       /* search Ident            */
   }
   if (memcmp( achl_cur, ucrs_sip_ident, sizeof(ucrs_sip_ident) )) {
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_cb_sip_ipv4_recv() SIP gateway %p data received after To/From Ident not found",
                     __LINE__, adsl_sip_gw_1_w1 );
     m_proc_free( adsp_sdhc1_rb );          /* free data received      */
     return;
   }
   achl_cur += sizeof(ucrs_sip_ident);
#ifdef B100525
   /* copy Ident                                                       */
   achl_out = dsl_sip_compare.chrc_sip_ident;
   while (   (achl_cur < achl_end)
          && (*achl_cur >= '0')
          && (*achl_cur <= '9')
          && (achl_out < (dsl_sip_compare.chrc_sip_ident + MAX_LEN_SIP_IDENT))) {
     *achl_out++ = *achl_cur++;             /* copy the character      */
   }
   dsl_sip_compare.dsc_sip_entry_1.imc_len_sip_ident
     = achl_out - dsl_sip_compare.chrc_sip_ident;
#else
   /* copy Ident                                                       */
   achl_out = achl_cur;                     /* save current position   */
   while (   (achl_cur < achl_end)
          && (ucrs_tab_inp_rfc_3986[ *((unsigned char *) achl_cur) ] != 0)) {
     achl_cur++;                            /* use this character      */
   }
   if (   (achl_cur >= achl_end)
       || (*achl_cur != '@')) {
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_cb_sip_ipv4_recv() SIP gateway %p data received Ident end wrong character",
                     __LINE__, adsl_sip_gw_1_w1 );
     m_proc_free( adsp_sdhc1_rb );          /* free data received      */
     return;
   }
   dsl_sip_compare.dsc_sip_entry_1.imc_len_sip_ident
     = m_cpy_vx_vx( dsl_sip_compare.chrc_sip_ident,
                    MAX_LEN_SIP_IDENT,
                    ied_chs_utf_8,          /* Unicode UTF-8           */
                    achl_out,
                    achl_cur - achl_out,
                    ied_chs_uri_1 );        /* URI RFC 3986            */
#endif
   if (dsl_sip_compare.dsc_sip_entry_1.imc_len_sip_ident <= 0) {
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_cb_sip_ipv4_recv() SIP gateway %p data received Ident is empty",
                     __LINE__, adsl_sip_gw_1_w1 );
     m_proc_free( adsp_sdhc1_rb );          /* free data received      */
     return;
   }
   dss_critsect_udp.m_enter();              /* critical section        */
   bol1 = m_htree1_avl_search( adsl_sip_gw_1_w1,
                               &adsl_sip_gw_1_w1->dsc_htree1_avl_cntl,
                               &dsl_htree1_work,
                               &dsl_sip_compare.dsc_sip_entry_1.dsc_sort_1 );
   dss_critsect_udp.m_leave();              /* critical section        */
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_cb_sip_ipv4_recv() %p search in tree failed",
                     __LINE__, adsl_sip_gw_1_w1 );
     m_proc_free( adsp_sdhc1_rb );          /* free data received      */
     return;
   }
   if (dsl_htree1_work.adsc_found == NULL) {  /* not found in tree     */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_cb_sip_ipv4_recv() %p Ident \"%.*s\" not found in tree",
                     __LINE__, adsl_sip_gw_1_w1,
                     dsl_sip_compare.dsc_sip_entry_1.imc_len_sip_ident,
                     dsl_sip_compare.chrc_sip_ident );
     m_proc_free( adsp_sdhc1_rb );          /* free data received      */
     return;
   }
#define ADSL_SIP_ENTRY_1_G ((struct dsd_sip_entry_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_sip_entry_1, dsc_sort_1 )))
   m_get_wsp_trace_info_conn1( &dsl_wtic, ADSL_SIP_ENTRY_1_G->adsc_conn1 );
   if (dsl_wtic.imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SSIPURE1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = dsl_wtic.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "SIP data received length %d/0X%X.",
                     ADSL_RECB_1_G->imc_len_data, ADSL_RECB_1_G->imc_len_data );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (dsl_wtic.imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2)) {  /* generate WSP trace record */
//     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
       achl_w1 = (char *) (((size_t) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml1 = ADSL_RECB_1_G->imc_len_data;  /* length of data received */
       achl_w3 = ADSL_RECB_1_G->achc_data;  /* start of data           */
       adsl_wt1_w2 = adsl_wt1_w1;           /* in this piece of memory */
       adsl_wtr_w1 = ADSL_WTR_G1;           /* set last in chain       */
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
         if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
           adsl_wtr_w1->boc_more = TRUE;    /* more data to follow     */
         }
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
       } while (iml1 > 0);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   m_count_recv_server( ADSL_SIP_ENTRY_1_G->adsc_conn1, ADSL_RECB_1_G->imc_len_data );
   bol_signal = FALSE;                      /* reset set signal        */
   dss_critsect_udp.m_enter();              /* critical section        */
   if (ADSL_SIP_ENTRY_1_G->adsc_sdhc1_rb == NULL) {  /* first in chain */
     ADSL_SIP_ENTRY_1_G->adsc_sdhc1_rb = adsp_sdhc1_rb;
     bol_signal = TRUE;                     /* set signal              */
   } else {                                 /* append to chain         */
     adsl_sdhc1_cur = ADSL_SIP_ENTRY_1_G->adsc_sdhc1_rb;  /* get chain */
     do {                                   /* loop over chain of buffers */
#ifdef TRY100302
       if (*((BOOL *) (adsl_sdhc1_cur + 1))) {  /* buffer already given */
         bol_signal = TRUE;                 /* set signal              */
       }
#endif
       adsl_sdhc1_end = adsl_sdhc1_cur;     /* save current entry      */
       adsl_sdhc1_cur = adsl_sdhc1_cur->adsc_next;  /* get next in chain */
     } while (adsl_sdhc1_cur);
     adsl_sdhc1_end->adsc_next = adsp_sdhc1_rb;  /* append to chain    */
   }
   dss_critsect_udp.m_leave();              /* critical section        */
#ifdef PROBLEM_HOBPHONE_1003
   {
     int      imh1 = 0;
     adsl_sdhc1_cur = ADSL_SIP_ENTRY_1_G->adsc_sdhc1_rb;  /* get chain */
     while (adsl_sdhc1_cur) {
       imh1++;
       adsl_sdhc1_cur = adsl_sdhc1_cur->adsc_next;
     }
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-%05d-T m_cb_sip_ipv4_recv() sdhc1=%p attach-to-ADSL_SIP_ENTRY_1_G=%p bol_signal=%d.",
                     __LINE__,
                     adsp_sdhc1_rb, ADSL_SIP_ENTRY_1_G, bol_signal );
   }
#endif
   if (bol_signal == FALSE) return;
   /* activate work-thread for this connection                         */
   m_act_conn1_signal( ADSL_SIP_ENTRY_1_G->adsc_conn1, (char *) ADSL_SIP_ENTRY_1_G, ADSL_SIP_ENTRY_1_G->imc_signal );
#undef ADSL_SIP_ENTRY_1_G
#undef ADSL_RECB_1_G
} /* end m_cb_sip_ipv4_recv()                                          */

/** close SIP entry                                                    */
static void m_close_sip_entry( void *vpp_userfld, struct dsd_sip_entry_1 *adsp_sip_entry_1 ) {
   BOOL       bol1;                         /* working-variable        */
   BOOL       bol_found;                    /* entry found in tree     */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */

   bol_found = FALSE;                       /* entry found in tree     */
#ifdef B160413
   dss_critsect_udp.m_enter();              /* critical section        */
   bol1 = m_htree1_avl_search( adsp_sip_entry_1->adsc_sip_gw_1,
                               &adsp_sip_entry_1->adsc_sip_gw_1->dsc_htree1_avl_cntl,
                               &dsl_htree1_work,
                               &adsp_sip_entry_1->dsc_sort_1 );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_close_sip_entry() SIP entry %p search in tree failed",
                     __LINE__, adsp_sip_entry_1 );
   }
   if (dsl_htree1_work.adsc_found) {        /* found in tree           */
     bol_found = TRUE;                      /* entry found in tree     */
     bol1 = m_htree1_avl_delete( adsp_sip_entry_1->adsc_sip_gw_1,
                                 &adsp_sip_entry_1->adsc_sip_gw_1->dsc_htree1_avl_cntl,
                                 &dsl_htree1_work );
     if (bol1 == FALSE) {                   /* error occured           */
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_close_sip_entry() SIP entry %p delete from tree failed",
                       __LINE__, adsp_sip_entry_1 );
     }
   }
   dss_critsect_udp.m_leave();              /* critical section        */
   if (bol_found == FALSE) {                /* not found in tree       */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_close_sip_entry() SIP entry %p not found in tree",
                     __LINE__, adsp_sip_entry_1 );
   }
   if (vpp_userfld == NULL) return;         /* no need to remove entry */
   m_wsp_s_ent_del( vpp_userfld, DEF_WSP_TYPE_SIP, (char *) adsp_sip_entry_1 );
#endif
#ifndef B160413
   /* Marvic Sammut reported crash                                     */
   dss_critsect_udp.m_enter();              /* critical section        */
   bol1 = m_htree1_avl_search( adsp_sip_entry_1->adsc_sip_gw_1,
                               &adsp_sip_entry_1->adsc_sip_gw_1->dsc_htree1_avl_cntl,
                               &dsl_htree1_work,
                               &adsp_sip_entry_1->dsc_sort_1 );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_close_sip_entry() SIP entry %p search in tree failed",
                     __LINE__, adsp_sip_entry_1 );
   }
   while (dsl_htree1_work.adsc_found) {     /* found in tree           */
     bol_found = TRUE;                      /* entry found in tree     */
     bol1 = m_htree1_avl_delete( adsp_sip_entry_1->adsc_sip_gw_1,
                                 &adsp_sip_entry_1->adsc_sip_gw_1->dsc_htree1_avl_cntl,
                                 &dsl_htree1_work );
     if (bol1 == FALSE) {                   /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_close_sip_entry() SIP entry %p delete from tree failed",
                       __LINE__, adsp_sip_entry_1 );
       break;
     }
     if (vpp_userfld == NULL) break;        /* no need to remove entry */
     m_wsp_s_ent_del( vpp_userfld, DEF_WSP_TYPE_SIP, (char *) adsp_sip_entry_1 );
     break;
   }
   dss_critsect_udp.m_leave();              /* critical section        */
   if (bol_found == FALSE) {                /* not found in tree       */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_close_sip_entry() SIP entry %p not found in tree",
                     __LINE__, adsp_sip_entry_1 );
   }
#endif
} /* end m_close_sip_entry()                                           */

/** compare SIP ident as callback for AVL tree                         */
static int m_cmp_sip_ident( void *vpp_userfld,
                            struct dsd_htree1_avl_entry *adsp_entry_1,
                            struct dsd_htree1_avl_entry *adsp_entry_2 ) {
   int        iml1, iml2;                   /* working variables       */
#define ADSL_SIP_ENTRY_1_P1 ((struct dsd_sip_entry_1 *) ((char *) adsp_entry_1 - offsetof( struct dsd_sip_entry_1, dsc_sort_1 )))
#define ADSL_SIP_ENTRY_1_P2 ((struct dsd_sip_entry_1 *) ((char *) adsp_entry_2 - offsetof( struct dsd_sip_entry_1, dsc_sort_1 )))
   iml1 = ADSL_SIP_ENTRY_1_P1->imc_len_sip_ident;
   if (iml1 > ADSL_SIP_ENTRY_1_P2->imc_len_sip_ident) {
     iml1 = ADSL_SIP_ENTRY_1_P2->imc_len_sip_ident;
   }
   iml2 = memcmp( ADSL_SIP_ENTRY_1_P1 + 1, ADSL_SIP_ENTRY_1_P2 + 1, iml1 );
   if (iml2) return iml2;
   return ADSL_SIP_ENTRY_1_P1->imc_len_sip_ident - ADSL_SIP_ENTRY_1_P2->imc_len_sip_ident;
#undef ADSL_SIP_ENTRY_1_P1
#undef ADSL_SIP_ENTRY_1_P2
} /* end m_cmp_sip_ident()                                             */

/** compare UDP gate entry as callback for AVL tree                    */
static int m_cmp_udp_gate_main( void *vpp_userfld,
                                struct dsd_htree1_avl_entry *adsp_entry_1,
                                struct dsd_htree1_avl_entry *adsp_entry_2 ) {
#define ADSL_UGM_ENTRY_1_P1 ((struct dsd_udp_gate_sort_1 *) ((char *) adsp_entry_1 - offsetof( struct dsd_udp_gate_sort_1, dsc_sort_1 )))
#define ADSL_UGM_ENTRY_1_P2 ((struct dsd_udp_gate_sort_1 *) ((char *) adsp_entry_2 - offsetof( struct dsd_udp_gate_sort_1, dsc_sort_1 )))
   return memcmp( ADSL_UGM_ENTRY_1_P1->chrc_nonce, ADSL_UGM_ENTRY_1_P2->chrc_nonce, DEF_LEN_UDP_GATE_NONCE );
#undef ADSL_UGM_ENTRY_1_P1
#undef ADSL_UGM_ENTRY_1_P2
} /* end m_cmp_udp_gate_main()                                         */

/** compare UDP gate subchannel as callback for AVL tree               */
static int m_cmp_udp_gate_subch( void *vpp_userfld,
                                 struct dsd_htree1_avl_entry *adsp_entry_1,
                                 struct dsd_htree1_avl_entry *adsp_entry_2 ) {
#define ADSL_UGS_ENTRY_1_P1 ((struct dsd_udp_gate_subch_sort_1 *) ((char *) adsp_entry_1 - offsetof( struct dsd_udp_gate_subch_sort_1, dsc_sort_1 )))
#define ADSL_UGS_ENTRY_1_P2 ((struct dsd_udp_gate_subch_sort_1 *) ((char *) adsp_entry_2 - offsetof( struct dsd_udp_gate_subch_sort_1, dsc_sort_1 )))
   return memcmp( &ADSL_UGS_ENTRY_1_P1->dsc_uga_subch_s_field,
                  &ADSL_UGS_ENTRY_1_P2->dsc_uga_subch_s_field,
                  sizeof(struct dsd_udp_gate_subch_sort_1::dsd_uga_subch_s_field) );
#undef ADSL_UGS_ENTRY_1_P1
#undef ADSL_UGS_ENTRY_1_P2
} /* end m_cmp_udp_gate_subch()                                        */

/** send SNMP trap                                                     */
extern "C" void m_send_snmp_trap_1( char *adsp_packet, int imp_len_packet ) {
   int        iml_rc;                       /* return code             */
   struct dsd_snmp_conf *adsl_snmp_conf_w1;  /* SNMP configuration     */
   struct dsd_snmp_trap_target *adsl_snmp_tt_w1;  /* chain of <trap-target> */

   adsl_snmp_conf_w1 = adsg_loconf_1_inuse->adsc_snmp_conf;  /* get SNMP configuration */
   if (adsl_snmp_conf_w1 == NULL) return;   /* no SNMP configuration   */
   adsl_snmp_tt_w1 = adsl_snmp_conf_w1->adsc_snmp_trap_target;  /* get chain of <trap-target> */
   while (adsl_snmp_tt_w1) {              /* loop over all SNMP configurations */
     if (adsl_snmp_tt_w1->imc_socket >= 0) {  /* UDP socket for sendto() valid */
       iml_rc = m_ip_sendto( adsl_snmp_tt_w1->imc_socket,
                             adsp_packet, imp_len_packet,
                             0,
                             (struct sockaddr *) &adsl_snmp_tt_w1->dsc_udp_param_1.dsc_soa_target,
                             adsl_snmp_tt_w1->dsc_udp_param_1.imc_len_soa_target );
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_send_snmp_trap_1() sendto returned %d.",
                       __LINE__, iml_rc );
     }
     adsl_snmp_tt_w1 = adsl_snmp_tt_w1->adsc_next;  /* get next in chain */
   }
} /* end m_send_snmp_trap_1()                                          */

/** Thread to receive from multiple UDP ports (one of many)            */
static htfunc1_t m_udp_recv_thread( void * vpp_thread_arg ) {
#ifndef HELP_DEBUG
#define ADSL_UDP_RECV_THR ((struct dsd_udp_recv_thr *) vpp_thread_arg)
#endif
   BOOL       bol1;                         /* working-variable        */
   int        iml1, iml2;                   /* working variables       */
   int        iml_error;                    /* error number            */
#ifndef HL_UNIX
   DWORD      dwl_rc_m;                     /* Number of event signal  */
   DWORD      dwl_rc_2;                     /* return code             */
#else
   int        iml_rc_g;                     /* global return code      */
   int        iml_rc_m;                     /* number of event signal  */
// int        iml_rc_2;                     /* return code             */
#endif
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_udp_multiw_1 *adsl_udp_multiw_1_w1;  /* working-variable */
   struct dsd_sdh_control_1 *adsl_sdhc1_rb;  /* receive buffer          */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
#ifndef HL_UNIX
   WSANETWORKEVENTS dsl_net_events;         /* event occured           */
#endif
   amd_udp_recv_compl aml_udp_recv_compl;   /* callback when receive complete */
   char       chrl_ineta[ LEN_DISP_INETA ];  /* internet-address char  */

#ifdef HELP_DEBUG
   struct dsd_udp_recv_thr *ADSL_UDP_RECV_THR = (struct dsd_udp_recv_thr *) vpp_thread_arg;
#endif

   pthrm10:                                 /* wait for event          */
#ifndef HL_UNIX
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-udp-01-%05d-T m_udp_recv_thread() %p pthrm10 wsawaitm imc_receive=%d",
                   __LINE__, ADSL_UDP_RECV_THR, ADSL_UDP_RECV_THR->imc_receive );
   fflush( stdout );
#endif
   dwl_rc_m = m_ip_wsawaitm( ADSL_UDP_RECV_THR->imc_receive + 1, ADSL_UDP_RECV_THR->dsrc_hand_thr,
                             FALSE, WSA_INFINITE, FALSE );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-udp-01-%05d-T m_udp_recv_thread() %p wsawaitm completed %d WSA_WAIT_EVENT_0 = %d.",
                   __LINE__, ADSL_UDP_RECV_THR, dwl_rc_m, WSA_WAIT_EVENT_0 );
   fflush( stdout );
#endif
   if (dwl_rc_m == WSA_WAIT_FAILED) {         /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_udp_recv_thread() %p Error on wait: %d.",
                     __LINE__, ADSL_UDP_RECV_THR, m_ip_wsaglerr() );
#ifndef OLD01
     Sleep( 1000 );
#ifdef B140701
     goto pthrm10;                          /* wait for event          */
#endif
#ifndef B140701
     goto pthrm20;                          /* check if HANDLE deleted */
#endif
#else
     ExitThread( 1 );
#endif
   }
   if (dwl_rc_m > WSA_WAIT_EVENT_0) goto pthrm40;  /* receive          */
   if (dwl_rc_m != WSA_WAIT_EVENT_0) {      /* wait invalid return     */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_udp_recv_thread() %p wait returned invalid rc: %d.",
                     __LINE__, ADSL_UDP_RECV_THR, dwl_rc_m );
     goto pthrm10;                          /* wait for event          */
   }
   bol1 = ResetEvent( ADSL_UDP_RECV_THR->dsrc_hand_thr[ 0 ] );
   if (bol1 == FALSE) {
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_udp_recv_thread() %p ResetEvent Error %d.",
                     __LINE__, ADSL_UDP_RECV_THR, GetLastError() );
   }
#endif
#ifdef HL_UNIX
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_udp_recv_thread() l%05d before poll() ADSL_UDP_RECV_THR->imc_receive=%d.",
                   __LINE__, ADSL_UDP_RECV_THR->imc_receive );
#endif
   iml_rc_g = poll( ADSL_UDP_RECV_THR->dsrc_poll, ADSL_UDP_RECV_THR->imc_receive + 1, INFTIM );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_udp_recv_thread() l%05d after  poll() iml_rc_g=%d errno=%d.",
                   __LINE__, iml_rc_g, errno );
#endif
   if (iml_rc_g <= 0) {                     /* did not signal event    */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_udp_recv_thread() %p poll() returned invalid rc: %d/%d.",
                     __LINE__, ADSL_UDP_RECV_THR, iml_rc_g, errno );
     goto pthrm10;                          /* wait for event          */
   }
   iml_rc_m = 0;                            /* did not check entry     */
   if ((ADSL_UDP_RECV_THR->dsrc_poll[ 0 ].revents & POLLIN) == 0) {
     goto pthrm40;                          /* receive                 */
   }
   iml_rc_g = read( ADSL_UDP_RECV_THR->dsrc_poll[ 0 ].fd, &iml1, sizeof(int) );
   if (iml_rc_g != sizeof(int)) {           /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_udp_recv_thread() %p pipe read() returned invalid rc: %d/%d.",
                     __LINE__, ADSL_UDP_RECV_THR, iml_rc_g, errno );
   }
#endif
#ifndef HL_UNIX

   pthrm20:                                 /* check if HANDLE deleted */
#endif
#ifdef TRACEHL1
   m_display_udp( __LINE__, "m_udp_recv_thread() before loop cleanup" );
#endif
   iml1 = iml2 = 0;                         /* reset indexes           */
   dss_critsect_udp.m_enter();              /* critical section        */
   while (iml1 < ADSL_UDP_RECV_THR->imc_active) {  /* loop over all entries */
     if (ADSL_UDP_RECV_THR->adsrc_udp_multiw_1[ iml1 ]) {  /* entry still active */
       if (iml1 != iml2) {                  /* has to copy entries     */
#ifndef HL_UNIX
         ADSL_UDP_RECV_THR->dsrc_hand_thr[ 1 + iml2 ]
           = ADSL_UDP_RECV_THR->dsrc_hand_thr[ 1 + iml1 ];
#else
         memcpy( &ADSL_UDP_RECV_THR->dsrc_poll[ 1 + iml2 ],
                 &ADSL_UDP_RECV_THR->dsrc_poll[ 1 + iml1 ],
                 sizeof(struct pollfd) );
#endif
         ADSL_UDP_RECV_THR->adsrc_udp_multiw_1[ iml2 ]
           = ADSL_UDP_RECV_THR->adsrc_udp_multiw_1[ iml1 ];
       }
       iml2++;                              /* count this entry        */
     }
     iml1++;
   }
   ADSL_UDP_RECV_THR->imc_active = ADSL_UDP_RECV_THR->imc_receive = iml2;
   dss_critsect_udp.m_leave();              /* critical section        */
#ifdef TRACEHL1
   m_display_udp( __LINE__, "m_udp_recv_thread() after  loop cleanup" );
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-udp-01 m_udp_recv_thread( %p ) cleanup iml2 = imc_active = imc_receive = %d.",
                   __LINE__, m_udp_recv_thread, iml2 );
#endif
#ifndef HL_UNIX
   goto pthrm10;                            /* wait for next event     */
#endif

#ifndef HL_UNIX
   pthrm40:                                 /* receive completed       */
#ifndef B140121
   if ((dwl_rc_m - WSA_WAIT_EVENT_0 - 1) >= ADSL_UDP_RECV_THR->imc_receive) {
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-udp-01 m_udp_recv_thread() wait-event=%d higher than %d - ignored",
                     __LINE__, dwl_rc_m, ADSL_UDP_RECV_THR->imc_receive );
#endif
     goto pthrm10;                          /* wait for next event     */
   }
#endif
   adsl_udp_multiw_1_w1 = ADSL_UDP_RECV_THR->adsrc_udp_multiw_1[ dwl_rc_m - WSA_WAIT_EVENT_0 - 1 ];
   if (adsl_udp_multiw_1_w1 == NULL) goto pthrm10;  /* entry has been removed */
#ifndef B140121
   aml_udp_recv_compl = adsl_udp_multiw_1_w1->amc_udp_recv_compl;  /* callback when receive complete */
#endif
   dwl_rc_2 = m_ip_wsa_enum_net_events( adsl_udp_multiw_1_w1->imc_socket, adsl_udp_multiw_1_w1->dsc_event, &dsl_net_events );
   if (dwl_rc_2) {                          /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_udp_recv_thread() %p WSAEnumNetworkEvents Error %d/%d.",
                     __LINE__, ADSL_UDP_RECV_THR, dwl_rc_2, m_ip_wsaglerr() );
   }
#ifdef B140121
   aml_udp_recv_compl = adsl_udp_multiw_1_w1->amc_udp_recv_compl;  /* callback when receive complete */
#endif
   if (aml_udp_recv_compl == NULL) {        /* structure no more valid */
     goto pthrm10;                          /* wait for next event     */
   }
   if ((dsl_net_events.lNetworkEvents & FD_READ) == 0) {
     goto pthrm10;                          /* wait for next event     */
   }
#endif
#ifdef HL_UNIX
   pthrm40:                                 /* check event             */
   if (iml_rc_m >= ADSL_UDP_RECV_THR->imc_receive) {  /* all events processed */
     goto pthrm10;                          /* wait for next event     */
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_udp_recv_thread() l%05d pthrm40: after  poll() iml_rc_m=%d revents=0X%X adsrc_udp_multiw_1=%p.",
                   __LINE__, iml_rc_m, ADSL_UDP_RECV_THR->dsrc_poll[ 1 + iml_rc_m ].revents, ADSL_UDP_RECV_THR->adsrc_udp_multiw_1[ iml_rc_m ] );
#endif
   if ((ADSL_UDP_RECV_THR->dsrc_poll[ 1 + iml_rc_m ].revents & POLLIN) == 0) {
     goto pthrm60;                          /* event has been checked  */
   }
#ifdef B120720
   ADSL_UDP_RECV_THR->dsrc_poll[ 1 + iml_rc_m ].events = 0;
#else
   ADSL_UDP_RECV_THR->dsrc_poll[ 1 + iml_rc_m ].revents = 0;
#endif
   adsl_udp_multiw_1_w1 = ADSL_UDP_RECV_THR->adsrc_udp_multiw_1[ iml_rc_m ];
   if (adsl_udp_multiw_1_w1 == NULL) {      /* entry has been removed  */
     goto pthrm60;                          /* event has been checked  */
   }
   aml_udp_recv_compl = adsl_udp_multiw_1_w1->amc_udp_recv_compl;  /* callback when receive complete */
   if (aml_udp_recv_compl == NULL) {        /* structure no more valid */
     goto pthrm60;                          /* event has been checked  */
   }
#endif
   adsl_sdhc1_rb = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* receive buffer */
#ifndef TRY100302
   memset( adsl_sdhc1_rb, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_sdh_udp_recbuf_1) );
#define ADSL_REC_B ((struct dsd_sdh_udp_recbuf_1 *) (adsl_sdhc1_rb + 1))
#else
   memset( adsl_sdhc1_rb, 0, sizeof(struct dsd_sdh_control_1) + sizeof(BOOL) + sizeof(struct dsd_sdh_udp_recbuf_1) );
#define ADSL_REC_B ((struct dsd_sdh_udp_recbuf_1 *) ((BOOL *) (adsl_sdhc1_rb + 1) + 1))
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_udp_recv_thread() l%05d adsl_sdhc1_rb=%p ADSL_REC_B=%p data=%p.",
                   __LINE__, adsl_sdhc1_rb, ADSL_REC_B, ADSL_REC_B + 1 );
#endif
#ifndef B080323
   ADSL_REC_B->achc_sockaddr = (char *) adsl_sdhc1_rb + LEN_TCP_RECV - sizeof(sockaddr_in6);
   ADSL_REC_B->imc_len_sockaddr = sizeof(sockaddr_in6);
   ADSL_REC_B->achc_data = (char *) (ADSL_REC_B + 1);
   ADSL_REC_B->imc_len_data
     = m_ip_recvfrom( adsl_udp_multiw_1_w1->imc_socket,
                      (char *) (ADSL_REC_B + 1),
                      LEN_TCP_RECV - sizeof(struct dsd_sdh_control_1)
#ifndef TRY100302
                        - sizeof(struct dsd_sdh_udp_recbuf_1) - sizeof(sockaddr_in6),
#else
                        - sizeof(BOOL) - sizeof(struct dsd_sdh_udp_recbuf_1) - sizeof(sockaddr_in6),
#endif
                      0,
                      (struct sockaddr *) ADSL_REC_B->achc_sockaddr, (socklen_t *) &ADSL_REC_B->imc_len_sockaddr );
#else
   ADSL_REC_B->achc_sockaddr = (char *) adsl_sdhc1_rb + LEN_TCP_RECV - sizeof(sockaddr_in);
   ADSL_REC_B->imc_len_sockaddr = sizeof(sockaddr_in);
   ADSL_REC_B->achc_data = (char *) (ADSL_REC_B + 1);
   ADSL_REC_B->imc_len_data
     = m_ip_recvfrom( adsl_udp_multiw_1_w1->imc_socket,
                      (char *) (ADSL_REC_B + 1),
                      LEN_TCP_RECV - sizeof(struct dsd_sdh_control_1)
                        - sizeof(struct dsd_sdh_udp_recbuf_1) - sizeof(sockaddr_in),
                      0,
                      (struct sockaddr *) ADSL_REC_B->achc_sockaddr, (socklen_t *) &ADSL_REC_B->imc_len_sockaddr );
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_udp_recv_thread() l%05d ADSL_REC_B->achc_sockaddr=%p ADSL_REC_B->achc_data=%p ADSL_REC_B->imc_len_data=%p.",
                   __LINE__, ADSL_REC_B->achc_sockaddr, ADSL_REC_B->achc_data, ADSL_REC_B->imc_len_data );
#endif
   iml_error = D_TCP_ERROR;                 /* error number            */
#ifdef TRACEHL1
#ifndef HL_UNIX
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-%05d-T m_udp_recv_thread() %p recvfrom returned %d adsl..w1=%p adsrc_udp_m...[]=%p adsl_sdhc1_rb=%p.",
                   __LINE__, ADSL_UDP_RECV_THR, ADSL_REC_B->imc_len_data,
                   adsl_udp_multiw_1_w1, ADSL_UDP_RECV_THR->adsrc_udp_multiw_1[ dwl_rc_m - 1 ], adsl_sdhc1_rb );
   m_console_out( ADSL_REC_B->achc_sockaddr, ADSL_REC_B->imc_len_sockaddr );
   fflush( stdout );
#endif
#endif
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_UDP) {  /* core UDP receive and send */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     strcpy( chrl_ineta, "???" );           /* if getnameinfo() fails  */
     getnameinfo( (struct sockaddr *) ADSL_REC_B->achc_sockaddr, ADSL_REC_B->imc_len_sockaddr,
                  chrl_ineta, sizeof(chrl_ineta), 0, 0, NI_NUMERICHOST );
     iml2 = 0;                              /* clear port              */
     switch (((struct sockaddr *) ADSL_REC_B->achc_sockaddr)->sa_family) {
       case AF_INET:                        /* IPV4                    */
         iml2 = ntohs( ((struct sockaddr_in *) ADSL_REC_B->achc_sockaddr)->sin_port );
         break;
       case AF_INET6:                       /* IPV6                    */
         iml2 = ntohs( ((struct sockaddr_in6 *) ADSL_REC_B->achc_sockaddr)->sin6_port );
         break;
     }
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CUDPRECV", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     if (ADSL_REC_B->imc_len_data > 0) {    /* data received           */
       iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "UDP data received length %d/0X%X / source %s port %d.",
                       ADSL_REC_B->imc_len_data, ADSL_REC_B->imc_len_data,
                       chrl_ineta, iml2 );
     } else {                               /* error received          */
       iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "UDP received error %d %d / source %s port %d.",
                       ADSL_REC_B->imc_len_data, iml_error,
                       chrl_ineta, iml2 );
     }
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (   (ADSL_REC_B->imc_len_data > 0)  /* data received           */
         && (img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2))) {  /* generate WSP trace record */
//     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
       achl_w1 = (char *) (((size_t) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml1 = ADSL_REC_B->imc_len_data;     /* length of data received */
       achl_w3 = (char *) (ADSL_REC_B + 1);  /* start of data          */
       adsl_wt1_w2 = adsl_wt1_w1;           /* in this piece of memory */
       adsl_wtr_w1 = ADSL_WTR_G1;           /* set last in chain       */
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
         if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
           adsl_wtr_w1->boc_more = TRUE;    /* more data to follow     */
         }
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
       } while (iml1 > 0);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#ifdef PROBLEM_HOBPHONE_1003
   if (aml_udp_recv_compl == &m_cb_sip_ipv4_recv) {
     ims_count_recv_sip++;                  /* count block             */
     m_hlnew_printf( HLOG_TRACE1, "xs-gw-udp-01-%05d-T m_udp_recv_thread() recvfrom bl-no=%05d sdhc1=%p ADSL_REC_B=%p len=%d/0X%X.",
                     __LINE__, ims_count_recv_sip,
                     adsl_sdhc1_rb, ADSL_REC_B,
                     ADSL_REC_B->imc_len_data,
                     ADSL_REC_B->imc_len_data );
     if (ADSL_REC_B->imc_len_data > 0) {
       m_console_out( (char *) (ADSL_REC_B + 1), ADSL_REC_B->imc_len_data );
     }
   }
#endif
   if (ADSL_REC_B->imc_len_data <= 0) {     /* set error numbers       */
     ADSL_REC_B->imc_error_os = iml_error;  /* error from the operating system */
// to-do 27.03.14 KB - define HOB specific error numbers
     ADSL_REC_B->imc_error_hob = 1;         /* HOB specific error number */
   }
#undef ADSL_REC_B
   aml_udp_recv_compl( adsl_udp_multiw_1_w1, adsl_sdhc1_rb );
#ifndef HL_UNIX
   goto pthrm10;                            /* wait for next event     */
#else

   pthrm60:                                 /* event has been checked  */
   iml_rc_m++;                              /* increment number of event signal */
   goto pthrm40;                            /* check event             */
#endif
#ifndef HELP_DEBUG
#undef ADSL_UDP_RECV_THR
#endif
} /* end m_udp_recv_thread()                                           */

/** create UDP socket                                                  */
extern "C" BOOL m_udp_create_socket( struct dsd_udp_multiw_1 *adsp_udp_multiw_1,
                                     struct dsd_udp_param_1 *adsp_udp_param_1 ) {
   int        iml_rc;                       /* return code             */
#ifdef HL_UNIX
   int        iml1;                         /* working variable        */
#endif

   adsp_udp_multiw_1->imc_socket = m_ip_socket( adsp_udp_param_1->dsc_soa_bind.ss_family, SOCK_DGRAM, 0 );
   if (adsp_udp_multiw_1->imc_socket < 0) {  /* error occured          */
// to-do 30.09.08 KB
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_udp_create_socket() %p socket() return code %d.",
                     __LINE__, adsp_udp_multiw_1, D_TCP_ERROR );
     return FALSE;                          /* did not open socket     */
   }
   iml_rc = m_ip_bind( adsp_udp_multiw_1->imc_socket,
                       (struct sockaddr *) &adsp_udp_param_1->dsc_soa_bind, (socklen_t) adsp_udp_param_1->imc_len_soa_bind );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_udp_create_socket() %p bind() Return Code %d/%d.",
                     __LINE__, adsp_udp_multiw_1, iml_rc, D_TCP_ERROR );
   }
#ifdef NOT_YET
   if ((adsp_udp_r1->achc_soa_bind) && (adsp_udp_r1->imc_len_soa_bind > 0)) {
     iml_rc = m_ip_getsockname( adsp_udp_multiw_1->imc_socket,
                                (sockaddr *) adsp_udp_r1->achc_soa_bind,
                                (socklen_t *) &adsp_udp_r1->imc_len_soa_bind );
     if (iml_rc) {                          /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_udp_create_socket() %p getsockname() Return Code %d/%d.",
                       __LINE__, adsp_udp_multiw_1, iml_rc, m_ip_wsaglerr() );
       adsp_udp_r1->imc_len_soa_bind = 0;   /* no information returned */
     }
   }
#endif
#ifndef HL_UNIX
   adsp_udp_multiw_1->dsc_event = m_ip_wsaevent();  /* create event for recv */
   if (adsp_udp_multiw_1->dsc_event == WSA_INVALID_EVENT) {
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-udp-01-l%05d-W m_udp_create_socket() %p WSAEvent Return Code %d.",
                     __LINE__, adsp_udp_multiw_1, m_ip_wsaglerr() );
   }
   iml_rc = WSAEventSelect( adsp_udp_multiw_1->imc_socket,
                            adsp_udp_multiw_1->dsc_event,
                            FD_WRITE | FD_READ | FD_CLOSE );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_udp_create_socket() %p WSAEventSelect Return Code %d/%d.",
                     __LINE__, adsp_udp_multiw_1, iml_rc, m_ip_wsaglerr() );
   }
#else
   /* set the UDP socket to non-blocking                               */
   iml1 = fcntl( adsp_udp_multiw_1->imc_socket, F_GETFL, 0 );
   iml_rc = fcntl( adsp_udp_multiw_1->imc_socket, F_SETFL, iml1 | O_NONBLOCK );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-udp-01-l%05d-W m_udp_create_socket() %p fcntl() return code %d/%d.",
                     __LINE__, adsp_udp_multiw_1, iml_rc, errno );
   }
#endif
   return TRUE;
} /* end m_udp_create_socket()                                         */

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
     m_hlnew_printf( HLOG_XYZ1, "%.*s", sizeof(chrlwork1), chrlwork1 );
   }
} /* end m_console_out()                                               */
#endif
#ifdef TRACEHL1
static void m_display_udp( int imp_line, char *achp_text ) {
   struct dsd_udp_recv_thr *adsl_udprthr_w1;  /* threads to do UDP receive */

   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-udp-01 m_display_udp() l%05d %s.",
                   __LINE__, imp_line, achp_text );
   adsl_udprthr_w1 = adss_udp_recv_thr_a;   /* get anchor threads to do UDP receive */
   while (adsl_udprthr_w1) {
     int      imh1 = 0;
     char     *achh_error = "";

     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-udp-01 adsl_udprthr_w1=%p imc_active=%d.",
                     __LINE__, adsl_udprthr_w1, adsl_udprthr_w1->imc_active );
     while (imh1 < adsl_udprthr_w1->imc_active) {
       struct dsd_udp_multiw_1 *adsh_udp_multiw_1 = adsl_udprthr_w1->adsrc_udp_multiw_1[ imh1 ];
       char     chrh_msg_1[ 128 ];
       char     chrh_msg_2[ 128 ];

       strcpy( chrh_msg_1, "- NULL - unknown -" );
       chrh_msg_2[ 0 ] = 0;
       if (adsh_udp_multiw_1) {
         sprintf( chrh_msg_1, "%p", adsh_udp_multiw_1->adsc_udprthr_w1 );
         if (adsh_udp_multiw_1->adsc_udprthr_w1 != adsl_udprthr_w1) {
           strcpy( chrh_msg_2, " - thread adsc_udprthr_w1 not set correct - error" );
         }
       }
       m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-udp-01 adsrc_udp_multiw_1[ %03d ] = %p adsc_udprthr_w1 = %s%s.",
                       __LINE__, imh1 + 1, adsh_udp_multiw_1, chrh_msg_1, chrh_msg_2 );
       imh1++;                              /* increment index         */
     }
     adsl_udprthr_w1 = adsl_udprthr_w1->adsc_next;  /* get next thread from chain */
   }
} /* end m_display_udp()                                               */
#endif
