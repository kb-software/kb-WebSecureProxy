#ifdef TO_DO
--- 31.08.12 KB ---
send to client:
enum ied_charset iec_chs_ppp;            /* character set PPP       */
#endif
//#define HPPPT1_V14_RECV                     /* 31.08.12 KB HOB-PPP-T1 V1.4 receive */
//#define HPPPT1_V21                          /* 03.12.12 KB HOB-PPP-T1 V2.1 */
//#define TRY_090424
//#define TRACEHL1
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xs-gw-l2tp                                          |*/
/*| -------------                                                     |*/
/*|  Subroutine which handles L2TP in the gateways                    |*/
/*|  KB 24.09.08                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
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

/**
   RFC 2661 Layer Two Tunneling Protocol "L2TP"

   SSTP:
     [MS-SSTP].pdf
     2.2.7 Crypto Binding Attribute
*/

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
#include <time.h>
#ifdef HL_UNIX
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
//#include <sys/stropts.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
//#include <xti.h>
#ifndef HL_LINUX
#include <unistd.h>
#endif
#ifdef HL_LINUX
#include <sys/syscall.h>
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
#ifdef HL_IPV6
#include <ws2tcpip.h>
//#include <wspiapi.h>
#endif
#include <hob-wtspo1.h>
#endif
#include <hob-xslunic1.h>
#include <hob-xsltime1.h>
#ifndef HL_UNIX
#include <hob-thread.hpp>
#include <iswcord1.h>
#endif
//#include "hob-hlwspat2.h"
#include <hob-wspsu1.h>
#include <hob-tabau.h>
#ifdef OLD01
#include <hob-nblock_acc.hpp>
#include <hob-tcpco1.hpp>
#endif
#ifndef HL_UNIX
#include <hob-avl03.h>
#else
#include "hob-avl03.h"
#endif
#include "hob-tun01.h"
#include "hob-gw-ppp-1.h"

#define DOMNode void

#define DEF_HL_INCL_DOM
#include "hob-xsclib01.h"

#include <hob-netw-01.h>
#include "hob-wsppriv.h"                    /* privileges              */
#define HOB_CONTR_TIMER
#include <hob-xslcontr.h>                   /* HOB Control             */
#ifndef B160501
#ifndef HL_UNIX
#include <stdint.h>
#endif
#endif
#include <hob-encry-1.h>
//#define INCL_GW_ALL
#define D_INCL_AUX_UDP
#define INCL_GW_L2TP
#define D_INCL_HOB_TUN
#include "hob-xbipgw08-1.h"
#include "hob-xbipgw08-2.h"

#ifndef HL_UNIX
#define D_TCP_ERROR WSAGetLastError()
#define D_TCP_CLOSE closesocket
#else
#define D_TCP_ERROR errno
#define D_TCP_CLOSE close
#endif

#define MAX_LEN_HTTP_HEADER    1024         /* maximum length HTTP header */

#define MAX_LEN_NHASN          4

#define CHAR_CR                0X0D         /* carriage-return         */
#define CHAR_LF                0X0A         /* line-feed               */

#define SSTP_CONTROL_MSG       0X1001
#define SSTP_DATA_MSG          0X1000
#define SSTP_LEN_HEADER        4

/* SSTP control message types                                          */
#define SSTP_MSG_CALL_CONNECT_REQ           1
#define SSTP_MSG_CALL_CONNECT_ACK           2
#define SSTP_MSG_CALL_CONNECTED             4
#define SSTP_MSG_CALL_ABORT                 5
#define SSTP_MSG_CALL_DISCONNECT            6
#define SSTP_MSG_CALL_DISCONNECT_ACK        7
#define SSTP_MSG_ECHO_REQ                   8
#define SSTP_MSG_ECHO_ACK                   9

/* SSTP control message attribute types                                */
#define SSTP_ATTR_ENCAPSULATED_PROTO        1
#define SSTP_ATTR_CRYPTO                    3
#define SSTP_ATTR_CRYPTO_REQ                4

/* Encapsulated Protocol attribute values                              */
#define SSTP_ATTR_ENCAPSULATED_PROTO_PPP    1

/* Certificate Hash Protocol values                                    */
#define HASH_PROTO_SHA1                     1
#define HASH_PROTO_SHA256                   2

#define SSTP_NONCE_LEN                      32
#define SSTP_HASH_LEN                       32

#define TIMER_TCP_RECONNECT    (4 * 60)     /* wait seconds for TCP reconnect */
#define TIMER_L2TP_INIT        2000         /* wait milliseconds for L2TP init */
#define TIMER_L2TP_SHUTDOWN    30           /* seconds shutdown L2TP   */
#define TIMER_L2TP_CLOSED      30           /* seconds L2TP keeps closed */
#define TIMER_L2TP_HELLO       60           /* seconds keep-alive L2TP */
#define NO_L2TP_HELLO          8            /* number of unresponded keep-alive L2TP */
#define MAX_LEN_HOSTNAME       15           /* maximum length HOSTNAME L2TP */
#define LEN_HOSTNAME_P1        8            /* length HOSTNAME L2TP part one */
#define LEN_IP_SEND            512          /* length IP send control packet */
#define D_LEN_L2TP_HEADER      8            /* length of L2TP header   */
#define D_MAX_PPP_CONTROL      128          /* maximum length of PPP control sequences */
#define DEF_SEND_IOV           32           /* for WSASendTo() or sendmsg() */
#define D_POS_IPV4_H_PROT      9            /* position protocol in IPV4 header */
#define D_POS_IPV6_H_NEXT      6            /* position type next header in IPV6 header */
#define D_LEN_HEADER_IPV6      40           /* length of IPV6 header   */

/*+-------------------------------------------------------------------+*/
/*| Internal used structures.                                         |*/
/*+-------------------------------------------------------------------+*/

enum ied_state_l2tp {                       /* state of L2TP with server */
   ied_stl_wait_init = 0,                   /* wait for init from client */
   ied_stl_wait_sccrp,                      /* wait for SCCRP          */
   ied_stl_start_conn,                      /* start connect           */
   ied_stl_connected,                       /* connected               */
   ied_stl_cdn_sent,                        /* CDN has been sent       */
   ied_stl_shutdown,                        /* do shutdown             */
   ied_stl_closed                           /* session closed          */
};

enum ied_state_tcp_cl {                     /* state of TCP connection with the client */
   ied_stt_start = 0,                       /* session was started     */
   ied_stt_connected,                       /* session is connected    */
   ied_stt_stop_sent,                       /* STOP has been sent      */
   ied_stt_start_cl,                        /* close has been started  */
   ied_stt_closed                           /* TCP session is closed   */
};

enum ied_state_recv_client {                /* state of received from client */
   ied_str_wait_cr = 0,                     /* wait for carriage-return */
   ied_str_wait_lf,                         /* wait for line-feed      */
   ied_str_len_nhasn,                       /* process length in NHASN */
   ied_str_control,                         /* process control character */
   ied_str_word_01,                         /* process first word      */
   ied_str_start_02,                        /* search start second word */
   ied_str_word_02,                         /* process second word     */
   ied_str_copy,                            /* copy field              */
   ied_str_hexno,                           /* decode hexa number      */
   ied_str_decno,                           /* decode decimal number   */
   ied_str_data                             /* process data            */
};

enum ied_command_recv_client {              /* command received from client */
   ied_corc_invalid = 0,                    /* nothing set yet         */
   ied_corc_start,                          /* START received          */
   ied_corc_reconnect,                      /* RECONNECT received      */
   ied_corc_end                             /* END received            */
};

enum ied_keyword_recv_client {              /* keyword received from client */
   ied_kwrc_invalid = 0,                    /* nothing set yet         */
   ied_kwrc_hostname,                       /* HOSTNAME received       */
   ied_kwrc_local_ineta,                    /* LOCAL-INETA received    */
   ied_kwrc_tunnel_id,                      /* TUNNEL-ID received      */
   ied_kwrc_epoch,                          /* EPOCH received          */
#ifdef HPPPT1_V14_RECV                      /* 31.08.12 KB HOB-PPP-T1 V1.4 receive */
   ied_kwrc_tcp_mss_server,                 /* TCP-MSS-SERVER received */
#endif
   ied_kwrc_drpa                            /* DROPPED-PACKETS received */
};

enum ied_header_client {                    /* header received from client */
   ied_hecl_start = 0,                      /* nothing set yet         */
   ied_hecl_esc_1,                          /* escape 1                */
   ied_hecl_esc_2,                          /* escape 2                */
   ied_hecl_esc_3,                          /* escape 3                */
   ied_hecl_ineta_ch,                       /* INETA character         */
   ied_hecl_ineta_esc,                      /* INETA escape            */
   ied_hecl_user_ch,                        /* username character      */
   ied_hecl_user_esc                        /* username escape         */
};

enum ied_sstp_state {                       /* state of SSTP connection */
   ied_sstpst_start = 0,                    /* start of SSTP connection */
   ied_sstpst_firec,                        /* first record has been received */
   ied_sstpst_start_l2tp                    /* start L2TP              */
};

struct dsd_l2tp_contr {                     /* L2TP control structure  */
   struct dsd_l2tp_contr *adsc_next;        /* next L2TP control structure in chain */
   struct dsd_udp_param_1 *adsc_udp_param_1;  /* UDP parameters        */
   unsigned short int usc_free_tunnel_id;   /* return unique tunnel ids */
   dsd_htree1_avl_cntl dsc_htree1_avl_cntl;  /* AVL tree control area  */
   struct dsd_udp_multiw_1 dsc_udp_multiw_1;  /* structure for UDP multiple wait */
};

struct dsd_session_ident {                  /* identification of session */
   struct dsd_htree1_avl_entry dsc_sort_1;  /* entry for sorting       */
   unsigned short int usc_tunnel_id;        /* L2TP tunnel Id          */
};

struct dsd_l2tp_conn_1 {                    /* for L2TP UDP connection */
   struct dsd_session_ident dsc_session_ident;  /* identification of session */
   struct dsd_timer_ele dsc_timer;          /* timer for wait          */
   struct dsd_l2tp_session *adsc_l2tp_session;  /* L2TP connection session */
   struct dsd_l2tp_contr *adsc_l2tp_contr;  /* L2TP control structure  */
   struct dsd_ppp_targfi_act_1 *adsc_ptfa1;  /* active target filter   */
   ied_scp_def iec_scp;                     /* server-conf protocol    */
   int        imc_len_ident;                /* length ident this L2TP session */
   int        imc_time_tcp_disco;           /* time TCP connected was disconnected */
   int        imc_len_hostname;             /* length of hostname      */
   ied_state_l2tp iec_stl;                  /* state of L2TP with server */
   int        imc_send_hello_l2tp;          /* times sendet L2TP HELLO */
   int        imc_dropped_packet_server;    /* number of packets dropped by the server */
   int        imc_dropped_packet_client;    /* number of packets dropped by the client */
   int        imc_dropped_packet_targfi;    /* number of packets dropped because of target-filter */
   unsigned short int usc_ns;               /* count number send       */
   unsigned short int usc_nr;               /* count number receive    */
   unsigned short int usc_assgn_t_id;       /* assigned tunnel id      */
   unsigned short int usc_assgn_s_id;       /* assigned session id     */
   unsigned short int usc_random_tid;       /* random tunnel id        */
   char       chrc_hostname[ MAX_LEN_HOSTNAME ];  /* maximum length HOSTNAME L2TP */
   struct dsd_ppp_server_1 dsc_ppp_se_1;    /* PPP server              */
   struct dsd_ppp_client_1 dsc_ppp_cl_1;    /* PPP client              */
};

/*+-------------------------------------------------------------------+*/
/*| Definitions for target-filter                                     |*/
/*+-------------------------------------------------------------------+*/

#define D_CACHE_TF_IPV4_NO_ENTRY    64      /* entries cache entry IPV4 */

#define D_CACHE_TF_IPV4_LEN         8       /* length array cache entry IPV4 */
#define D_CACHE_TF_IPV4_INETA       4       /* length array cache entry INETA */
#define D_CACHE_TF_IPV4_PROTO       1       /* length array cache entry protocol */
#define D_CACHE_TF_IPV4_PORT        2       /* length array cache entry protocol */

#define D_CACHE_TF_IPV6_NO_ENTRY    64      /* entries cache entry IPV6 */

#define D_CACHE_TF_IPV6_LEN         20      /* length array cache entry IPV6 */
#define D_CACHE_TF_IPV6_INETA       16      /* length array cache entry INETA */
#define D_CACHE_TF_IPV6_PROTO       1       /* length array cache entry protocol */
#define D_CACHE_TF_IPV6_PORT        2       /* length array cache entry protocol */

#ifdef XYZ1
enum ied_ret_cf {                           /* return value from processing target filter */
   ied_rcf_incompl = 0,                     /* packet is incomplete    */
   ied_rcf_invalid,                         /* packet is invalid       */
   ied_rcf_drop,                            /* drop packet             */
   ied_rcf_ok                               /* packet is o.k.          */
};
#endif

typedef enum ied_ret_cf ( * amd_proc_ppp_targfi )( struct dsd_hco_wothr *, struct dsd_ppp_targfi_act_1 *, struct dsd_gather_i_1 *, int );

struct dsd_ppp_targfi_cache_ipv4 {          /* cache entry PPP target filter IPV4 */
   struct dsd_ppp_targfi_cache_ipv4 *adsc_next;  /* next in chain      */
   char       chrc_cache_e[ D_CACHE_TF_IPV4_LEN ];  /* cache entry     */
};

struct dsd_ppp_targfi_cache_ipv6 {          /* cache entry PPP target filter IPV4 */
   struct dsd_ppp_targfi_cache_ipv6 *adsc_next;  /* next in chain      */
   char       chrc_cache_e[ D_CACHE_TF_IPV6_LEN ];  /* cache entry     */
};

struct dsd_ppp_targfi_act_1 {               /* active target filter    */
   struct dsd_targfi_1 *adsc_targfi_1;      /* used target filter      */
   struct dsd_ppp_targfi_cache_ipv4 *adsc_ce_ipv4_act;  /* chain active cache entries PPP target filter */
   struct dsd_ppp_targfi_cache_ipv4 *adsc_ce_ipv4_empty;  /* chain empty cache entries PPP target filter */
   struct dsd_ppp_targfi_cache_ipv6 *adsc_ce_ipv6_act;  /* chain active cache entries PPP target filter */
   struct dsd_ppp_targfi_cache_ipv6 *adsc_ce_ipv6_empty;  /* chain empty cache entries PPP target filter */
   struct dsd_ppp_targfi_cache_ipv4 dsrc_ce_ipv4[ D_CACHE_TF_IPV4_NO_ENTRY ];  /* cache entries PPP target filter */
   struct dsd_ppp_targfi_cache_ipv6 dsrc_ce_ipv6[ D_CACHE_TF_IPV6_NO_ENTRY ];  /* cache entries PPP target filter */
#ifndef B160503
   BOOL       boc_blacklist;                /* use-as-blacklist        */
   int        imc_trace_level;              /* trace_level             */
   int        imc_sno;                      /* WSP session number      */
#endif
};

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

static void m_hpppt1_wait_init( struct dsd_hco_wothr *, struct dsd_l2tp_session *, struct dsd_gather_i_1 * );
static void m_hpppt1_proc_tcp_header( struct dsd_l2tp_session *, char *, int );
static void m_display_epoch( struct dsd_l2tp_session *, int );
static void m_hpppt1_rec_client( struct dsd_hco_wothr *, struct dsd_l2tp_session *, struct dsd_gather_i_1 * );
static void m_hpppt1_send_stop( struct dsd_l2tp_session *, BOOL );
static BOOL m_sstp_recv( struct dsd_hco_wothr *, struct dsd_l2tp_session *, struct dsd_gather_i_1 * );
static void m_sstp_ctrl_recv( struct dsd_hco_wothr *, struct dsd_l2tp_session *, char *, int );
static void m_server_control_recv( struct dsd_l2tp_conn_1 *, char *, int );
static struct dsd_gather_i_1 * m_l2tp_send_gather( struct dsd_hco_wothr *, struct dsd_l2tp_conn_1 *, struct dsd_gather_i_1 *, int );
static void m_start_l2tp_conn( struct dsd_l2tp_session *, char *, int, char *, int );
static void m_start_l2tp_ppp( struct dsd_l2tp_conn_1 * );
static void m_send_gw_sccrq( struct dsd_l2tp_conn_1 * );
static void m_send_gw_scccn( struct dsd_l2tp_conn_1 * );
static void m_send_gw_icrq( struct dsd_l2tp_conn_1 * );
static void m_send_gw_iccn( struct dsd_l2tp_conn_1 * );
static void m_send_gw_cdn( struct dsd_l2tp_conn_1 * );
static void m_send_gw_stopccn( struct dsd_l2tp_conn_1 * );
static void m_send_gw_hello( struct dsd_l2tp_conn_1 * );
static void m_send_gw_zlb( struct dsd_l2tp_conn_1 * );
static void m_send_udp( struct dsd_l2tp_conn_1 *, char *, int, char *, int );
static void m_cleanup_l2tp( struct dsd_l2tp_conn_1 * );
static void m_check_timeout_reco( struct dsd_l2tp_conn_1 * );
static void m_timeout_l2tp( struct dsd_timer_ele * );
static int m_cmp_tunnel_id( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static unsigned short int m_get_tunnel_id( struct dsd_l2tp_contr * );
static void m_cb_udp_recv( struct dsd_udp_multiw_1 *, struct dsd_sdh_control_1 * );
#ifdef OLD01
static ied_ppp_frse_rc m_ppp_from_server( struct dsd_l2tp_conn_1 *, char *, int * );
static void m_ppp_auth_callback( struct dsd_ppp_str_1 *, ied_ppp_auth_rc, struct dsd_buf_vector_ele * );
#endif
static void m_ppp_se_send( struct dsd_ppp_server_1 *, struct dsd_buf_vector_ele * );
static void m_ppp_se_auth_1( struct dsd_ppp_server_1 * );
static char * m_ppp_se_get_ineta_client( struct dsd_ppp_server_1 * );
static void m_ppp_se_hs_compl( struct dsd_ppp_server_1 * );
static void m_ppp_se_abend( struct dsd_ppp_server_1 *, char * );
static void m_ppp_cl_send( struct dsd_ppp_client_1 *, char *, int );
static void m_ppp_cl_abend( struct dsd_ppp_client_1 *, char * );
#ifdef TRACEHL1
static int m_get_date_time( char *achp_buff );
#ifndef HL_UNIX
static void m_console_out( char *achp_buff, int implength );
#endif
#endif
#ifdef XYZ1
extern "C" struct dsd_ppp_targfi_act_1 * m_create_ppp_targfi( struct dsd_targfi_1 * );
extern "C" ied_ret_cf m_proc_ppp_targfi_ipv4( struct dsd_hco_wothr *, struct dsd_ppp_targfi_act_1 *, struct dsd_gather_i_1 *, int );
#endif

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

extern class dsd_hcla_critsect_1 dsg_global_lock;  /* global lock      */

static struct dsd_l2tp_contr *adsc_l2tp_contr_a = NULL;  /* chain of L2TP control structures */

/* SSTP first record to be sent as response                            */
static const unsigned char ucrs_send_sstp_firec_p1[] = {
   'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', CHAR_CR, CHAR_LF,
   'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ',
   '1', '8', '4', '4', '6', '7', '4', '4',
   '0', '7', '3', '7', '0', '9', '5', '5',
   '1', '6', '1', '5', CHAR_CR, CHAR_LF,
   'S', 'e', 'r', 'v', 'e', 'r', ':', ' ',
   'H', 'O', 'B', ' ', 'W', 'e', 'b', 'S',
   'e', 'c', 'u', 'r', 'e', 'P', 'r', 'o',
   'x', 'y', ' ', 'V', 'e', 'r', 's', 'i',
   'o', 'n', ' ', '2', '.', '3', CHAR_CR, CHAR_LF,
   'D', 'a', 't', 'e', ':', ' '
};

static const unsigned char ucrs_send_sstp_firec_p2[] = {
   CHAR_CR, CHAR_LF, CHAR_CR, CHAR_LF
};

/* SSTP control message                                                */
static const unsigned char ucrs_send_sstp_ctrl_a_p1[] = {
   (unsigned char) (SSTP_CONTROL_MSG >> 8), (unsigned char) SSTP_CONTROL_MSG,
   0X00, 0X30,                              /* length packet           */
   (unsigned char) (SSTP_MSG_CALL_CONNECT_ACK >> 8), (unsigned char) SSTP_MSG_CALL_CONNECT_ACK,  /* Message Type */
   0X00, 0X01,                              /* NumAttributes           */
   0X00,                                    /* reserved 1              */
   (unsigned char) SSTP_ATTR_CRYPTO_REQ,    /* AttributeID             */
   0X00, 0X28,                              /* LengthAttribute         */
   0X00, 0X00, 0X00,                        /* reserved 2              */
   (unsigned char) (HASH_PROTO_SHA1 | HASH_PROTO_SHA256)  /* HashProtocol */
};

/* SSTP control message                                                */
static const unsigned char ucrs_send_sstp_ctrl_echo_ack[] = {
   (unsigned char) (SSTP_CONTROL_MSG >> 8), (unsigned char) SSTP_CONTROL_MSG,
   0X00, 0X08,                              /* length packet           */
   (unsigned char) (SSTP_MSG_ECHO_ACK >> 8), (unsigned char) SSTP_MSG_ECHO_ACK,  /* Message Type */
   0X00, 0X00                               /* NumAttributes           */
};

static const unsigned char ucrs_avp_controlmsg[] = {
   0X80, 0X08, 0X00, 0X00, 0X00, 0X00, 0X00, 0X01
};

static const unsigned char ucrs_avp_protvers[] = {
   0X80, 0X08, 0X00, 0X00, 0X00, 0X02, 0X01, 0X00
};

static const unsigned char ucrs_avp_frame_cap[] = {
   0X80, 0X0A, 0X00, 0X00, 0X00, 0X03, 0X00, 0X00,
   0X00, 0X01
};

static const unsigned char ucrs_avp_bearer_cap[] = {
   0X80, 0X0A, 0X00, 0X00, 0X00, 0X04, 0X00, 0X00,
   0X00, 0X00
};

static const unsigned char ucrs_avp_firmware_rev[] = {
   0X00, 0X08, 0X00, 0X00, 0X00, 0X06, 0X00, 0X00
};

static const unsigned char ucrs_avp_vendor_name[] = {
   0X00, 0X11, 0X00, 0X00, 0X00, 0X08,
   /* HOB Germany                                                      */
   0X48, 0X4F, 0X42, 0X20,
   0X47, 0X65, 0X72, 0X6D, 0X61, 0X6E, 0X79
};

static const unsigned char ucrs_avp_recv_window_s[] = {
   0X80, 0X08, 0X00, 0X00, 0X00, 0X0A, 0X00, 0X08
};

static const unsigned char ucrs_send_scccn[] = {
   0XC8, 0X02, 0X00, 0X14, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X01, 0X00, 0X01,
   0X80, 0X08, 0X00, 0X00, 0X00, 0X00, 0X00, 0X03
};

/* Incoming-Call-Request                                               */
static const unsigned char ucrs_send_icrq[] = {
   0XC8, 0X02, 0X00, 0X30, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X02, 0X00, 0X01,
   0X80, 0X08, 0X00, 0X00, 0X00, 0X00, 0X00, 0X0A,  /* Message Type AVP, Attribute Type 0 */
   0X80, 0X08, 0X00, 0X00, 0X00, 0X0E, 0X12, 0X34,  /* Assigned Session ID AVP, Attribute Type 14 */
   0X80, 0X0A, 0X00, 0X00, 0X00, 0X0F, 0X00, 0X00, 0X00, 0X01,  /* Call Serial Number AVP, Attribute Type 15 */
   0X80, 0X0A, 0X00, 0X00, 0X00, 0X12, 0X00, 0X00, 0X00, 0X00  /* Bearer Type AVP, Attribute Type 18 */
};

/* ICCN - Incoming-Call-Connected                                      */
static const unsigned char ucrs_send_iccn[] = {
   0XC8, 0X02, 0X00, 0X32, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X03, 0X00, 0X02,
   0X80, 0X08, 0X00, 0X00, 0X00, 0X00, 0X00, 0X0C,  /* Message Type AVP, Attribute Type 0 */
   0X80, 0X0A, 0X00, 0X00, 0X00, 0X18, 0X00, 0X98, 0X96, 0X80,  /* Connect Speed BPS AVP, Attribute Type 24 */
   0X80, 0X0A, 0X00, 0X00, 0X00, 0X13, 0X00, 0X00, 0X00, 0X01,  /* Framing Type AVP, Attribute Type 19 */
   0X80, 0X0A, 0X00, 0X00, 0X00, 0X26, 0X00, 0X98, 0X96, 0X80  /* Rx Connect Speed AVP, Attribute Type 38 */
};

/* CDN                                                                 */
static const unsigned char ucrs_send_cdn[] = {
   0XC8, 0X02, 0X00, 0X26, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X01, 0X00, 0X03,
   0X80, 0X08, 0X00, 0X00, 0X00, 0X00, 0X00, 0X0E,  /* Message Type AVP, Attribute Type 0 */
   0X80, 0X0A, 0X00, 0X00, 0X00, 0X01, 0X00, 0X06, 0X00, 0X00,  /* Result Error Code Type AVP, Attribute Type 1 */
   0X80, 0X08, 0X00, 0X00, 0X00, 0X0E, 0X12, 0X34  /* Assigned Session Id AVP, Attribute Type 9 */
};

/* StopCCN                                                             */
static const unsigned char ucrs_send_stopccn[] = {
   0XC8, 0X02, 0X00, 0X26, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X01, 0X00, 0X03,
   0X80, 0X08, 0X00, 0X00, 0X00, 0X00, 0X00, 0X04,  /* Message Type AVP, Attribute Type 0 */
   0X80, 0X08, 0X00, 0X00, 0X00, 0X09, 0XFF, 0XFF,  /* Assigned Tunnel Id AVP, Attribute Type 9 */
   0X80, 0X0A, 0X00, 0X00, 0X00, 0X01, 0X00, 0X06, 0X00, 0X00  /* Result Error Code Type AVP, Attribute Type 1 */
};

/* HELLO                                                               */
static const unsigned char ucrs_send_hello[] = {
   0XC8, 0X02, 0X00, 0X14, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X01, 0X00, 0X03,
   0X80, 0X08, 0X00, 0X00, 0X00, 0X00, 0X00, 0X06  /* Message Type AVP, Attribute Type 0 */
};

#ifdef B100316
static const unsigned char ucrs_send_tunnel_id[] = {
   1 + 10 + 8,
   '0',                                     /* control channel         */
   'T', 'U', 'N', 'N', 'E', 'L', '-', 'I', 'D',
   '='                                      /* variable follows        */
};
#endif
#ifndef B100316
static const unsigned char ucrs_send_response_start_1[] = {
#ifndef HPPPT1_V21                          /* 03.12.12 KB HOB-PPP-T1 V2.1 */
   '0',                                     /* control channel         */
#endif
   'R', 'E', 'S', 'P', 'O', 'N', 'S', 'E', '-', 'S', 'T', 'A', 'R', 'T', ' ',
   'T', 'U', 'N', 'N', 'E', 'L', '-', 'I', 'D',
   '='                                      /* variable follows        */
};

static const unsigned char ucrs_send_response_start_2[] = {
   ' ', 'S', 'E', 'R', 'V', 'E', 'R', '-',
   'N', 'E', 'T', 'W', 'O', 'R', 'K', '-',
   'I', 'N', 'E', 'T', 'A', '='
};

static const unsigned char ucrs_send_response_start_3[] = {
   ' ', 'S', 'E', 'R', 'V', 'E', 'R', '-',
   'N', 'E', 'T', 'W', 'O', 'R', 'K', '-',
   'M', 'A', 'S', 'K', '='
};
#endif

#ifndef HPPPT1_V21                          /* 03.12.12 KB HOB-PPP-T1 V2.1 */
static const unsigned char ucrs_send_stop[] = {
   1 + 4,
   '0',                                     /* control channel         */
   'S', 'T', 'O', 'P'
};

static const unsigned char ucrs_send_nop[] = {
   1 + 3,
   '0',                                     /* control channel         */
   'N', 'O', 'P'
};
#endif
#ifdef HPPPT1_V21                           /* 03.12.12 KB HOB-PPP-T1 V2.1 */
static const unsigned char ucrs_send_stop[] = {
   '0',                                     /* control channel         */
   4,                                       /* length                  */
   'S', 'T', 'O', 'P'
};

static const unsigned char ucrs_send_nop[] = {
   '0',                                     /* control channel         */
   3,                                       /* length                  */
   'N', 'O', 'P'
};
#endif

/* this PPP control header part is forbidden                           */
static const unsigned char ucrs_send_ppp_header[] = {
   0XFF, 0X03, 0X00
};

static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

/*+-------------------------------------------------------------------+*/
/*| Procedure division.                                               |*/
/*+-------------------------------------------------------------------+*/

/** start L2TP UDP connection                                          */
extern "C" void m_l2tp_start( struct dsd_l2tp_conf *adsp_l2tp_conf ) {
   BOOL       bol1;                         /* working variable        */
#ifdef OLD01
   int        iml1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
   int        iml_listen_socket;            /* socket to be used       */
   socklen_t  iml_soadlen;                  /* length of sockaddr      */
   struct dsd_ineta_single_1 *adsl_ineta_s_w1;  /* single INETA target */
   struct dsd_cluster_remote *adsl_clrem_w1;  /* cluster remote structure */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster structure */
   struct sockaddr_storage dsl_soa_listen;  /* server address information */
#endif
   struct dsd_l2tp_contr *adsl_l2tp_contr_w1;  /* L2TP control structure */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "l%05d xs-gw-l2tp m_l2tp_start( 0X%p ) called",
                   __LINE__, adsp_l2tp_conf );
#endif
   adsl_l2tp_contr_w1 = adsc_l2tp_contr_a;  /* chain of L2TP control structures */
   while (adsl_l2tp_contr_w1) {             /* loop over all existing L2TP control structures */
     if (!memcmp( &adsp_l2tp_conf->dsc_udp_param_1,
                  adsl_l2tp_contr_w1->adsc_udp_param_1,
                  sizeof(struct dsd_udp_param_1) )) {
        adsp_l2tp_conf->ac_l2tp_contr = adsl_l2tp_contr_w1;  /* L2TP control structure */
        return;                             /* all done                */
     }
     adsl_l2tp_contr_w1 = adsl_l2tp_contr_w1->adsc_next;  /* get next in chain */
   }
   adsl_l2tp_contr_w1 = (struct dsd_l2tp_contr *) malloc( sizeof(struct dsd_l2tp_contr) );
   memset( adsl_l2tp_contr_w1, 0, sizeof(struct dsd_l2tp_contr) );
   adsl_l2tp_contr_w1->adsc_udp_param_1 = &adsp_l2tp_conf->dsc_udp_param_1;
   adsl_l2tp_contr_w1->adsc_next = adsc_l2tp_contr_a;  /* get chain of L2TP control structures */
   adsc_l2tp_contr_a = adsl_l2tp_contr_w1;  /* new chain of L2TP control structures */
   adsp_l2tp_conf->ac_l2tp_contr = adsl_l2tp_contr_w1;  /* L2TP control structure */
   /* init AVL Tree functions                                          */
   bol1 = m_htree1_avl_init( NULL, &adsl_l2tp_contr_w1->dsc_htree1_avl_cntl,
                             &m_cmp_tunnel_id );
   if (bol1 == FALSE) {                     /* error occured           */
//   m_hlnew_printf( HLOG_XYZ1, "l%05d xs-gw-l2tp E m_htree1_avl_init() failed",
//                 __LINE__ );
//   goto p_end_80;                         /* end of program          */
// to-do 30.09.08 KB
   }
   bol1 = m_udp_create_socket( &adsl_l2tp_contr_w1->dsc_udp_multiw_1,
                               adsl_l2tp_contr_w1->adsc_udp_param_1 );
   if (bol1 == FALSE) {                     /* error occured           */
//   m_hlnew_printf( HLOG_XYZ1, "l%05d xs-gw-l2tp E m_htree1_avl_init() failed",
//                 __LINE__ );
//   goto p_end_80;                         /* end of program          */
// to-do 30.09.08 KB
   }
   adsl_l2tp_contr_w1->dsc_udp_multiw_1.amc_udp_recv_compl = m_cb_udp_recv;  /* callback when receive complete */
   m_start_udp_recv( &adsl_l2tp_contr_w1->dsc_udp_multiw_1 );  /* start UDP */
} /* end m_l2tp_start()                                                */

/** set values for L2TP connection                                     */
extern "C" void m_l2tp_conn( struct dsd_l2tp_conf *adsp_l2tp_conf,
                             struct dsd_l2tp_session *adsp_l2tp_session,
                             ied_scp_def iep_scp,
                             UNSIG_MED ump_s_nw_ineta,
                             UNSIG_MED ump_s_nw_mask ) {
   int        iml_trace_level;              /* trace_level             */
   int        iml_sno;                      /* WSP session number      */
   struct dsd_targfi_1 *adsl_targfi_w1;     /* working variable        */

   adsp_l2tp_session->adsc_l2tp_conf = adsp_l2tp_conf;  /* L2TP connection configuration */
   adsp_l2tp_session->adsc_ptfa1 = NULL;    /* active target filter    */
#ifdef B160503
   adsl_targfi_w1 = m_get_l2tp_targfi( adsp_l2tp_session );
#endif
#ifndef B160503
   adsl_targfi_w1 = m_get_l2tp_targfi( adsp_l2tp_session, &iml_trace_level, &iml_sno );
#endif
   if (adsl_targfi_w1) {                    /* target-filter set       */
#ifdef B160503
     adsp_l2tp_session->adsc_ptfa1 = m_create_ppp_targfi( adsl_targfi_w1 );  /* active target filter */
#endif
#ifndef B160503
     adsp_l2tp_session->adsc_ptfa1 = m_create_ppp_targfi( adsl_targfi_w1, iml_trace_level, iml_sno );  /* active target filter */
#endif
   }
   adsp_l2tp_session->iec_scp = iep_scp;    /* server-conf protocol    */
   adsp_l2tp_session->umc_s_nw_ineta = ump_s_nw_ineta;  /* server-network-ineta */
   adsp_l2tp_session->umc_s_nw_mask = ump_s_nw_mask;  /* server-network-mask */
   adsp_l2tp_session->ac_l2tp_conn_1 = NULL;  /* no L2TP UDP connection */
   adsp_l2tp_session->imc_state_1 = 0;      /* state of input          */
#ifdef B110904
   adsp_l2tp_session->boc_cont_send_client = TRUE;  /* continue send to client */
   adsp_l2tp_session->ac_buf_chain = NULL;  /* chain of buffers to send to client empty */
#endif
   if (adsp_l2tp_session->iec_scp == ied_scp_hpppt1) {  /* protocol HOB-PPP-T1 */
     adsp_l2tp_session->boc_rec_header = FALSE;  /* header first record received */
     adsp_l2tp_session->boc_rec_eye_catcher = FALSE;  /* first record received   */
   }
} /* end m_l2tp_conn()                                                 */

/** send L2TP packet                                                   */
extern "C" BOOL m_l2tp_send( struct dsd_hco_wothr *adsp_hco_wothr,
                             struct dsd_l2tp_session *adsp_l2tp_session,
                             struct dsd_gather_i_1 *adsp_gai1 ) {
/**
   when m_l2tp_send() is called,
   the critical section or mutex of the connection
   is locked by the calling program.
*/
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-l2tp m_l2tp_send( 0X%p , 0X%p ) called",
                   __LINE__, adsp_l2tp_session, adsp_gai1 );
#endif
   switch (adsp_l2tp_session->iec_scp) {    /* server-conf protocol    */
     case ied_scp_sstp:                     /* protocol SSTP           */
       return m_sstp_recv( adsp_hco_wothr, adsp_l2tp_session, adsp_gai1 );
     case ied_scp_hpppt1:                   /* protocol HOB-PPP-T1     */
       if (adsp_l2tp_session->ac_l2tp_conn_1 == NULL) {  /* no L2TP UDP connection */
         m_hpppt1_wait_init( adsp_hco_wothr, adsp_l2tp_session, adsp_gai1 );
         return TRUE;
       }
       m_hpppt1_rec_client( adsp_hco_wothr, adsp_l2tp_session, adsp_gai1 );
       return TRUE;
   }
   return FALSE;
} /* end m_l2tp_send()                                                 */

/** close L2TP connection                                              */
extern "C" void m_l2tp_close( struct dsd_l2tp_session *adsp_l2tp_session ) {
   struct dsd_l2tp_conn_1 *adsl_l2tpc1;     /* for L2TP UDP connection */
#ifdef B110904
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-l2tp m_l2tp_close( 0X%p ) called",
                   __LINE__, adsp_l2tp_session );
#endif
   adsl_l2tpc1 = (struct dsd_l2tp_conn_1 *) adsp_l2tp_session->ac_l2tp_conn_1;  /* L2TP UDP connection */
   if (adsl_l2tpc1 == NULL) return;         /* nothing more to do      */
   adsl_l2tpc1->adsc_l2tp_session = NULL;   /* no more corresponding TCP connection */
   adsl_l2tpc1->adsc_ptfa1 = adsp_l2tp_session->adsc_ptfa1;  /* active target filter */
   adsp_l2tp_session->adsc_ptfa1 = NULL;    /* do not free memory      */
#ifdef OLD01
   adsl_l2tpc1->dsc_ppp_str_1.vpc_handle = NULL;  /* no more handle L2TP or HTUN */
#endif
#ifdef B110904
   while (adsp_l2tp_session->ac_buf_chain) {  /* chain of buffers to send to client */
     adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) adsp_l2tp_session->ac_buf_chain;
     adsp_l2tp_session->ac_buf_chain = adsl_sdhc1_w1->adsc_next;  /* remove from chain */
     m_proc_free( adsl_sdhc1_w1 );          /* free buffer             */
   }
#endif
   if (adsp_l2tp_session->adsc_ptfa1) {     /* active target filter    */
     free( adsp_l2tp_session->adsc_ptfa1 );  /* free memory            */
     adsp_l2tp_session->adsc_ptfa1 = NULL;
   }
   adsl_l2tpc1->dsc_ppp_se_1.vpc_handle = NULL;  /* no more handle L2TP or HOB-TUN */
   if (adsl_l2tpc1->iec_scp == ied_scp_hpppt1) return;  /* protocol HOB-PPP-T1 */
// to-do 16.10.08 KB - end of L2TP session
   return;                                  /* all done                */
} /* end m_l2tp_close()                                                */

/** end of L2TP client                                                 */
extern "C" void m_l2tp_client_end( struct dsd_l2tp_session *adsp_l2tp_session ) {
   struct dsd_l2tp_conn_1 *adsl_l2tpc1;     /* for L2TP UDP connection */

   adsl_l2tpc1 = (struct dsd_l2tp_conn_1 *) adsp_l2tp_session->ac_l2tp_conn_1;  /* L2TP UDP connection */
   if (adsl_l2tpc1 == NULL) return;         /* nothing more to do      */
   adsl_l2tpc1->adsc_l2tp_session = NULL;   /* no more corresponding TCP connection */
   adsl_l2tpc1->imc_time_tcp_disco = (int) time( NULL );  /* time TCP connected was disconnected */
   adsp_l2tp_session->ac_l2tp_conn_1 = NULL;  /* no more L2TP UDP connection */
} /* m_l2tp_client_end()                                               */

/** process first packet from client - wait for init                   */
static void m_hpppt1_wait_init( struct dsd_hco_wothr *adsp_hco_wothr,
                                struct dsd_l2tp_session *adsp_l2tp_session,
                                struct dsd_gather_i_1 *adsp_gai1 ) {
   HL_LONGLONG ill1;                        /* working variable        */
   char       *achl1, *achl2;               /* working variables       */
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working variables       */
   int        iml_len;                      /* length of structure     */
   int        iml_var_out;                  /* output variable         */
   int        iml_l_var;                    /* length of variable      */
   int        iml_tunnel_id;                /* decoded tunnel-id       */
   int        iml_dropped_packet_client;    /* number of packets dropped by the client */
   char       chl_more;                     /* more bit                */
#ifdef OLD01
   int        iml_rc;                       /* return code             */
#endif
   char       *achl_out;                    /* copy to output area     */
   int        iml_local_ineta;              /* local INETA of the client */
   int        iml_len_hostname;             /* length of hostname      */
   int        iml_recv_epoch;               /* received EPOCH          */
   char       *achl_hostname;               /* attached memory hostname */
   ied_state_recv_client iel_state_recvc;   /* state of received from client */
   ied_command_recv_client iel_corc;        /* command received from client */
   ied_keyword_recv_client iel_kwrc;        /* keyword received from client */
   struct dsd_l2tp_conn_1 *adsl_l2tpc1;     /* for L2TP UDP connection */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* gather input            */
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* gather input            */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_l2tp_contr *adsl_l2tp_contr_w1;  /* L2TP control structure */
   char       *achl_buf_w1;                 /* buffer for send         */
   char       *achl_avl_error;              /* error code AVL tree     */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   struct dsd_session_ident dsl_session_ident;  /* identification of session */
   char       chrl_work_1[ 1024 ];          /* work area               */

   adsl_l2tpc1 = NULL;                      /* no L2TP UDP connection yet */
   iel_state_recvc = ied_str_wait_cr;       /* state of received from client */
   achl_out = chrl_work_1;                  /* start output word       */
   if (adsp_l2tp_session->boc_rec_eye_catcher) {  /* first record received  */
#ifndef HPPPT1_V21                          /* 03.12.12 KB HOB-PPP-T1 V2.1 */
     iel_state_recvc = ied_str_len_nhasn;   /* process length in NHASN */
     iml_len = 0;                           /* clear length            */
     iml1 = 4;                              /* maximum number of digits */
#endif
#ifdef HPPPT1_V21                           /* 03.12.12 KB HOB-PPP-T1 V2.1 */
     iel_state_recvc = ied_str_control;     /* process control character */
#endif
   }
   iel_corc = ied_corc_invalid;             /* nothing set yet         */
   iml_tunnel_id = 0;                       /* clear decoded tunnel-id */
   iml_dropped_packet_client = -1;          /* invalid number of packets dropped by the client */
   iml_local_ineta = 0;                     /* clear local INETA of the client */
   iml_len_hostname = 0;                    /* clear length of hostname */
   iml_recv_epoch = 0;                      /* received EPOCH          */
   achl_hostname = chrl_work_1;             /* for empty display only  */
   adsl_gai1_w1 = adsp_gai1;                /* chain of receive buffers */

   p_wi_scan_00:                            /* start scanning          */
   if (adsl_gai1_w1 == NULL) {              /* needs more data         */
     if (iml_len_hostname) free( achl_hostname );  /* free HOSTNAME    */
     return;                                /* receive more data       */
   }
   achl1 = adsl_gai1_w1->achc_ginp_cur;     /* get start data          */

   p_wi_scan_20:                            /* search character        */
   if (achl1 >= adsl_gai1_w1->achc_ginp_end) {  /* at end of data      */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather input */
     goto p_wi_scan_00;                     /* start scanning          */
   }
   switch (iel_state_recvc) {               /* state of received from client */
     case ied_str_wait_cr:                  /* wait for carriage-return */
       if (*achl1 == CHAR_CR) {             /* carriage-return found   */
         iel_state_recvc = ied_str_wait_lf;  /* wait for line-feed now */
         achl1++;                           /* this character has been processed */
         goto p_wi_scan_20;                 /* search character        */
       }
       if (achl_out >= (chrl_work_1 + sizeof(chrl_work_1))) {
         goto p_wi_scan_err;                /* error in datastream     */
       }
       *achl_out++ = *achl1++;              /* copy this character     */
       goto p_wi_scan_20;                   /* search character        */
     case ied_str_wait_lf:                  /* wait for line-feed      */
       if (*achl1 == CHAR_LF) {             /* line-feed found         */
         if (adsp_l2tp_session->boc_rec_header == FALSE) {  /* not yet header first record received */
           m_hpppt1_proc_tcp_header( adsp_l2tp_session, chrl_work_1, achl_out - chrl_work_1 );
           adsp_l2tp_session->boc_rec_header = TRUE;  /* now header first record received */
         }
#ifndef HPPPT1_V21                          /* 03.12.12 KB HOB-PPP-T1 V2.1 */
         iel_state_recvc = ied_str_len_nhasn;  /* process length in NHASN */
         iml_len = 0;                       /* clear length            */
         iml1 = 4;                          /* maximum number of digits */
#endif
#ifdef HPPPT1_V21                           /* 03.12.12 KB HOB-PPP-T1 V2.1 */
         iel_state_recvc = ied_str_control;  /* process control character */
#endif
         achl1++;                           /* this character has been processed */
         goto p_wi_scan_20;                 /* search character        */
       }
       if (achl_out >= (chrl_work_1 + sizeof(chrl_work_1 - 1))) {
         goto p_wi_scan_err;                /* error in datastream     */
       }
       *achl_out++ = CHAR_CR;               /* put missing carriage-return in ouput buffer */
       if (*achl1 == CHAR_CR) {             /* again carriage-return found */
         goto p_wi_scan_20;                 /* search character        */
       }
       iel_state_recvc = ied_str_wait_cr;   /* wait for carriage-return again */
       *achl_out++ = *achl1++;              /* copy this character     */
       goto p_wi_scan_20;                   /* search character        */
#ifndef HPPPT1_V21                          /* 03.12.12 KB HOB-PPP-T1 V2.1 */
     case ied_str_len_nhasn:                /* process length in NHASN */
       iml_len <<= 8;                       /* shift old value length  */
       iml_len |= *achl1 & 0X7F;            /* apply new bits          */
       iml1--;                              /* decrement number of digits */
       if ((signed char) *achl1 < 0) {      /* more bit set            */
         if (iml1 <= 0) goto p_wi_scan_err;  /* error in datastream    */
         achl1++;                           /* next character          */
         goto p_wi_scan_20;                 /* search character        */
       }
       if (iml_len <= 0) goto p_wi_scan_err;  /* error in datastream   */
       iel_state_recvc = ied_str_control;   /* process control character */
       achl1++;                             /* next character          */
       goto p_wi_scan_20;                   /* search character        */
     case ied_str_control:                  /* process control character */
       if (*achl1 != '0') goto p_wi_scan_err;  /* error in datastream  */
       iml_len--;                           /* decrement length        */
       if (iml_len <= 0) goto p_wi_scan_err;  /* error in datastream   */
       iel_state_recvc = ied_str_word_01;   /* process first word      */
       achl_out = chrl_work_1;              /* start output word       */
       achl1++;                             /* next character          */
       goto p_wi_scan_20;                   /* search character        */
#endif
#ifdef HPPPT1_V21                           /* 03.12.12 KB HOB-PPP-T1 V2.1 */
     case ied_str_control:                  /* process control character */
       if (*achl1 != '0') goto p_wi_scan_err;  /* error in datastream  */
       achl1++;                             /* next character          */
       iel_state_recvc = ied_str_len_nhasn;   /* process length in NHASN */
       iml_len = 0;                         /* clear length            */
       iml1 = 4;                            /* maximum number of digits */
       goto p_wi_scan_20;                   /* search character        */
     case ied_str_len_nhasn:                /* process length in NHASN */
       iml_len <<= 8;                       /* shift old value length  */
       iml_len |= *achl1 & 0X7F;            /* apply new bits          */
       iml1--;                              /* decrement number of digits */
       if ((signed char) *achl1 < 0) {      /* more bit set            */
         if (iml1 <= 0) goto p_wi_scan_err;  /* error in datastream    */
         achl1++;                           /* next character          */
         goto p_wi_scan_20;                 /* search character        */
       }
       if (iml_len <= 0) goto p_wi_scan_err;  /* error in datastream   */
       iel_state_recvc = ied_str_word_01;   /* process first word      */
       achl_out = chrl_work_1;              /* start output word       */
       achl1++;                             /* next character          */
       goto p_wi_scan_20;                   /* search character        */
#endif
     case ied_str_word_01:                  /* process first word      */
       if (*achl1 != ' ') {                 /* real character found    */
         if (achl_out >= (chrl_work_1 + sizeof(chrl_work_1))) {  /* output word too long */
           goto p_wi_scan_err;              /* error in datastream     */
         }
         *achl_out++ = *achl1++;            /* copy character          */
         iml_len--;                         /* decrement length        */
         if (iml_len <= 0) goto p_wi_scan_err;  /* error in datastream */
         goto p_wi_scan_20;                 /* search character        */
       }
       if (   (achl_out == (chrl_work_1 + 5))  /* check output word length */
           && (!memcmp( chrl_work_1, "START", 5 ))) {  /* output word like expected */
         iel_corc = ied_corc_start;         /* START received          */
       } else if (   (achl_out == (chrl_work_1 + 9))  /* check output word length */
                  && (!memcmp( chrl_work_1, "RECONNECT", 9 ))) {  /* output word like expected */
         iel_corc = ied_corc_reconnect;     /* RECONNECT received      */
       } else if (   (achl_out == (chrl_work_1 + 3))  /* check output word length */
                  && (!memcmp( chrl_work_1, "END", 3 ))) {  /* output word like expected */
         iel_corc = ied_corc_end;           /* END received            */
       } else {                             /* other command received  */
         goto p_wi_scan_err;                /* error in datastream     */
       }
       iel_state_recvc = ied_str_start_02;  /* search start second word */
       achl1++;                             /* next character          */
       iml_len--;                           /* decrement length        */
       if (iml_len <= 0) goto p_wi_scan_err;  /* error in datastream   */
       goto p_wi_scan_20;                   /* search character        */
     case ied_str_start_02:                 /* search start second word */
       if (*achl1 == ' ') {                 /* space character found   */
         iml_len--;                         /* decrement length        */
         if (iml_len <= 0) goto p_wi_scan_err;  /* error in datastream */
         goto p_wi_scan_20;                 /* search character        */
       }
       achl_out = chrl_work_1;              /* start output word       */
       *achl_out++ = *achl1++;              /* copy character          */
       iml_len--;                           /* decrement length        */
       if (iml_len <= 0) goto p_wi_scan_err;  /* error in datastream   */
       iel_state_recvc = ied_str_word_02;   /* process second word     */
       goto p_wi_scan_20;                   /* search character        */
     case ied_str_word_02:                  /* process second word     */
       if ((*achl1 != ' ') && (*achl1 != '=')) {  /* real character found */
         if (achl_out >= (chrl_work_1 + sizeof(chrl_work_1))) {  /* output word too long */
           goto p_wi_scan_err;              /* error in datastream     */
         }
         *achl_out++ = *achl1++;            /* copy character          */
         iml_len--;                         /* decrement length        */
         if (iml_len <= 0) goto p_wi_scan_err;  /* error in datastream */
         goto p_wi_scan_20;                 /* search character        */
       }
       if (*achl1 != '=') {                 /* separater not like searched for */
         goto p_wi_scan_err;                /* error in datastream     */
       }
       if (   (achl_out == (chrl_work_1 + 8))  /* check output word length */
           && (!memcmp( chrl_work_1, "HOSTNAME", 8 ))) {  /* output word like expected */
         if (iel_corc != ied_corc_start) {  /* not START received      */
           goto p_wi_scan_err;              /* error in datastream     */
         }
         iel_kwrc = ied_kwrc_hostname;      /* HOSTNAME received       */
       } else if (   (achl_out == (chrl_work_1 + 11))  /* check output word length */
                  && (!memcmp( chrl_work_1, "LOCAL-INETA", 11 ))) {  /* output word like expected */
//       if (iel_corc != ied_corc_start) {  /* not START received      */
//         goto p_wi_scan_err;              /* error in datastream     */
//       }
         iel_kwrc = ied_kwrc_local_ineta;   /* LOCAL-INETA received    */
       } else if (   (achl_out == (chrl_work_1 + 9))  /* check output word length */
                  && (!memcmp( chrl_work_1, "TUNNEL-ID", 9 ))) {  /* output word like expected */
         if (iel_corc != ied_corc_reconnect) {  /* not RECONNECT received */
           goto p_wi_scan_err;              /* error in datastream     */
         }
         iel_kwrc = ied_kwrc_tunnel_id;     /* TUNNEL-ID received      */
       } else if (   (achl_out == (chrl_work_1 + 5))  /* check output word length */
                  && (!memcmp( chrl_work_1, "EPOCH", 5 ))) {  /* output word like expected */
         iel_kwrc = ied_kwrc_epoch;         /* EPOCH received          */
       } else if (   (achl_out == (chrl_work_1 + 15))  /* check output word length */
                  && (!memcmp( chrl_work_1, "DROPPED-PACKETS", 15 ))) {  /* output word like expected */
         if (iel_corc == ied_corc_start) {  /* START received          */
           goto p_wi_scan_err;              /* error in datastream     */
         }
         iel_kwrc = ied_kwrc_drpa;          /* DROPPED-PACKETS received */
#ifdef HPPPT1_V14_RECV                      /* 31.08.12 KB HOB-PPP-T1 V1.4 receive */
       } else if (   (achl_out == (chrl_work_1 + 14))  /* check output word length */
                  && (!memcmp( chrl_work_1, "TCP-MSS-SERVER", 14 ))) {  /* output word like expected */
         iel_kwrc = ied_kwrc_tcp_mss_server;  /* TCP-MSS-SERVER received */
#endif
       } else {                             /* other keyword received  */
         goto p_wi_scan_err;                /* error in datastream     */
       }
       achl1++;                             /* next character          */
       iml_len--;                           /* decrement length        */
       if (iml_len <= 0) goto p_wi_scan_err;  /* error in datastream   */
       switch (iel_kwrc) {                  /* keyword received from client */
         case ied_kwrc_hostname:            /* HOSTNAME received       */
         case ied_kwrc_local_ineta:         /* LOCAL-INETA received    */
           achl_out = chrl_work_1;          /* start output word       */
           iel_state_recvc = ied_str_copy;  /* copy field              */
           goto p_wi_scan_20;               /* search character        */
         case ied_kwrc_tunnel_id:           /* TUNNEL-ID received      */
           iel_state_recvc = ied_str_hexno;  /* decode hexa number     */
           iml_var_out = 0;                 /* clear output variable   */
           iml_l_var = 8;                   /* length of variable      */
           goto p_wi_scan_20;               /* search character        */
         case ied_kwrc_epoch:               /* EPOCH received          */
#ifdef HPPPT1_V14_RECV                      /* 31.08.12 KB HOB-PPP-T1 V1.4 receive */
         case ied_kwrc_tcp_mss_server:      /* TCP-MSS-SERVER received */
#endif
         case ied_kwrc_drpa:                /* DROPPED-PACKETS received */
           iml_var_out = 0;                 /* clear output variable   */
           iml_l_var = 12;                  /* length of variable      */
           iel_state_recvc = ied_str_decno;  /* decode decimal number  */
           goto p_wi_scan_20;               /* search character        */
       }
       goto p_wi_scan_err;                  /* error in datastream     */
     case ied_str_copy:                     /* copy field              */
       if (*achl1 != ' ') {                 /* real character found    */
         if (achl_out >= (chrl_work_1 + sizeof(chrl_work_1))) {  /* output word too long */
           goto p_wi_scan_err;              /* error in datastream     */
         }
         *achl_out++ = *achl1++;            /* copy character          */
         iml_len--;                         /* decrement length        */
         if (iml_len) {                     /* more characters follow  */
           goto p_wi_scan_20;               /* search character        */
         }
       }
       if (achl_out == chrl_work_1) {       /* length of string zero   */
         goto p_wi_scan_err;                /* error in datastream     */
       }
       switch (iel_kwrc) {                  /* keyword received from client */
         case ied_kwrc_hostname:            /* HOSTNAME received       */
           if (iml_len_hostname) goto p_wi_scan_err;  /* HOSTNAME double */
           iml_len_hostname = achl_out - chrl_work_1;  /* length of hostname */
           achl_hostname = (char *) malloc( iml_len_hostname );
           memcpy( achl_hostname, chrl_work_1, iml_len_hostname );
           break;
         case ied_kwrc_local_ineta:         /* LOCAL-INETA received    */
           if (iml_local_ineta) goto p_wi_scan_err;  /* local INETA of the client double */
           if (achl_out >= (chrl_work_1 + sizeof(chrl_work_1))) {  /* output word too long */
             goto p_wi_scan_err;            /* error in datastream     */
           }
           *achl_out = 0;                   /* make zero-terminated    */
           iml_local_ineta = (int) inet_addr( chrl_work_1 );
           break;
       }
       if (iml_len == 0) break;             /* end of control frame reached */
       iel_state_recvc = ied_str_start_02;  /* search start second word */
       achl1++;                             /* ignore space            */
       iml_len--;                           /* decrement length        */
       if (iml_len) goto p_wi_scan_20;      /* search character        */
       goto p_wi_scan_err;                  /* error in datastream     */
     case ied_str_hexno:                    /* decode hexa number      */
       if (*achl1 == ' ') {                 /* end of characters found */
         achl1++;                           /* after this character    */
         iml_len--;                         /* decrement length        */
         if (iml_len == 0) goto p_wi_scan_err;  /* error in datastream */
         if (iml_l_var != 0) goto p_wi_scan_err;  /* error in datastream */
         iml_tunnel_id = iml_var_out;       /* set decoded tunnel-id   */
         iel_state_recvc = ied_str_start_02;  /* search start second word */
         goto p_wi_scan_20;                 /* search character        */
       }
       if (iml_l_var <= 0) {                /* check length of variable */
         goto p_wi_scan_err;                /* error in datastream     */
       }
       if ((*achl1 >= '0') && (*achl1 <= '9')) {  /* digit found       */
         iml1 = *achl1 - '0';
       } else if ((*achl1 >= 'A') && (*achl1 <= 'F')) {  /* uppercase character found */
         iml1 = *achl1 - 'A' + 10;
       } else if ((*achl1 >= 'a') && (*achl1 <= 'f')) {  /* lowercase character found */
         iml1 = *achl1 - 'a' + 10;
       } else goto p_wi_scan_err;           /* error in datastream     */
       iml_var_out <<= 4;                   /* shift old value         */
       iml_var_out |= iml1;                 /* apply new bits          */
       iml_l_var--;                         /* decrement length of variable */
       achl1++;                             /* character has been processed */
       iml_len--;                           /* decrement length        */
       if (iml_len > 0) {                   /* more characters follow */
         goto p_wi_scan_20;                 /* search character        */
       }
       if (iml_l_var != 0) goto p_wi_scan_err;  /* error in datastream */
       iml_tunnel_id = iml_var_out;         /* set decoded tunnel-id   */
       break;                               /* control frame has been processed */
     case ied_str_decno:                    /* decode decimal number   */
       if (*achl1 == ' ') {                 /* end of characters found */
         achl1++;                           /* after this character    */
         iml_len--;                         /* decrement length        */
         if (iml_len == 0) goto p_wi_scan_err;  /* error in datastream */
         switch (iel_kwrc) {                /* keyword received from client */
           case ied_kwrc_epoch:             /* EPOCH received          */
             iml_recv_epoch = iml_var_out;  /* set received EPOCH      */
             break;
           case ied_kwrc_drpa:              /* DROPPED-PACKETS received */
             iml_dropped_packet_client = iml_var_out;  /* set number of packets dropped by the client */
             break;
         }
         iel_state_recvc = ied_str_start_02;  /* search start second word */
         goto p_wi_scan_20;                 /* search character        */
       }
       if (iml_l_var <= 0) {                /* check length of variable */
         goto p_wi_scan_err;                /* error in datastream     */
       }
       if ((*achl1 >= '0') && (*achl1 <= '9')) {  /* digit found       */
         iml_var_out *= 10;                 /* multiply old value by base */
         iml_var_out += *achl1 - '0';       /* apply new digit         */
       } else goto p_wi_scan_err;           /* error in datastream     */
       iml_l_var--;                         /* decrement length of variable */
       achl1++;                             /* character has been processed */
       iml_len--;                           /* decrement length        */
       if (iml_len > 0) {                   /* more characters follow */
         goto p_wi_scan_20;                 /* search character        */
       }
       switch (iel_kwrc) {                  /* keyword received from client */
         case ied_kwrc_epoch:               /* EPOCH received          */
           iml_recv_epoch = iml_var_out;    /* set received EPOCH      */
           break;
         case ied_kwrc_drpa:                /* DROPPED-PACKETS received */
           iml_dropped_packet_client = iml_var_out;  /* set number of packets dropped by the client */
           break;
       }
       break;                               /* control frame has been processed */
     default:
       goto p_wi_scan_err;                  /* error in datastream     */
   }
   adsl_gai1_w1->achc_ginp_cur = achl1;     /* set end of data         */
   adsl_gai1_w2 = adsp_gai1;                /* get start input         */
   while (adsl_gai1_w2 != adsl_gai1_w1) {   /* loop over all gather before */
     adsl_gai1_w2->achc_ginp_cur = adsl_gai1_w2->achc_ginp_end;  /* set end of data */
     adsl_gai1_w2 = adsl_gai1_w2->adsc_next;  /* get next in chain     */
   }
   if (adsl_gai1_w1->achc_ginp_cur >= adsl_gai1_w1->achc_ginp_end) {  /* no more data in buffer */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   adsp_l2tp_session->boc_rec_eye_catcher = TRUE;  /* first record received */
   switch (iel_corc) {                      /* command received from client */
     case ied_corc_reconnect:               /* RECONNECT received      */
       if (iml_recv_epoch) {                /* EPOCH received          */
         m_display_epoch( adsp_l2tp_session, iml_recv_epoch );
       }
       goto p_wi_reco_00;                   /* command RECONNECT received */
     case ied_corc_end:                     /* END received            */
       if (iml_recv_epoch) {                /* EPOCH received          */
         m_display_epoch( adsp_l2tp_session, iml_recv_epoch );
       }
       goto p_wi_end;                       /* command END received    */
   }
   /* get here when end of START reached                               */
#ifdef NOT_YET
   adsp_l2tp_session->iec_stt = ied_stt_connected;  /* session is connected */
   if (adsp_l2tp_session->dsc_timer.vpc_chain_2) {  /* timer already set    */
     m_time_rel( &adsp_l2tp_session->dsc_timer );  /* release timer         */
   }
#endif
#define IEC_HPPPT1 *((ied_state_tcp_cl *) &adsp_l2tp_session->imc_state_1)
   IEC_HPPPT1 = ied_stt_connected;          /* session is connected    */
#undef IEC_HPPPT1
   achl1 = achl2 = "";
   if (iml_len_hostname) achl1 = " HOSTNAME=";
   if (iml_local_ineta) {                   /* local INETA found       */
     sprintf( chrl_work_1, " client-local-INETA=%d.%d.%d.%d.",
              *((unsigned char *) &iml_local_ineta + 0),
              *((unsigned char *) &iml_local_ineta + 1),
              *((unsigned char *) &iml_local_ineta + 2),
              *((unsigned char *) &iml_local_ineta + 3) );
     achl2 = chrl_work_1;                   /* display this area       */
   }
   m_l2tp_information( adsp_l2tp_session, "l%05d HOB-PPP-T1 start from client%s%.*s%s",
                       __LINE__,
                       achl1, iml_len_hostname, achl_hostname, achl2 );
   if (iml_recv_epoch) {                    /* EPOCH received          */
     m_display_epoch( adsp_l2tp_session, iml_recv_epoch );
   }
   iml1 = m_l2tp_pass_session_owner( adsp_l2tp_session, chrl_work_1, sizeof(chrl_work_1) );
   m_start_l2tp_conn( adsp_l2tp_session, achl_hostname, iml_len_hostname, chrl_work_1, iml1 );
   if (iml_len_hostname) free( achl_hostname );  /* free HOSTNAME      */
   adsl_l2tpc1 = (struct dsd_l2tp_conn_1 *) adsp_l2tp_session->ac_l2tp_conn_1;  /* L2TP UDP connection */
   ill1 = (HL_LONGLONG) rand() * (64 * 1024);
#ifdef B140527
   ill1 /= RAND_MAX + 1;
#else
   ill1 /= (HL_LONGLONG) RAND_MAX + 1;
#endif
   adsl_l2tpc1->usc_random_tid = (unsigned short int) ill1;
   /* send response-start to client                                    */
   adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
   memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
   achl_buf_w1 = (char *) adsl_sdhc1_w1
                   + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1)
                   + MAX_LEN_NHASN;
   memcpy( achl_buf_w1, ucrs_send_response_start_1, sizeof(ucrs_send_response_start_1) );
   achl1 = achl_buf_w1 + sizeof(ucrs_send_response_start_1) + 8;
   iml_tunnel_id = iml1 = adsl_l2tpc1->dsc_session_ident.usc_tunnel_id
                            | (adsl_l2tpc1->usc_random_tid << 16);
   m_l2tp_information( adsp_l2tp_session, "l%05d HOB-PPP-T1 start tunnel-id %08X",
                       __LINE__,
                       iml_tunnel_id );
   iml2 = 8;                                /* number of hex digits    */
   do {
     *(--achl1) = chrstrans[ iml1 & 0X0F ];
     iml1 >>= 4;                            /* shift bits              */
     iml2--;                                /* decrement index         */
   } while (iml2 > 0);
   memcpy( achl_buf_w1 + sizeof(ucrs_send_response_start_1) + 8,
           ucrs_send_response_start_2,
           sizeof(ucrs_send_response_start_2) );
   iml1 = sprintf( achl_buf_w1
                     + sizeof(ucrs_send_response_start_1) + 8
                     + sizeof(ucrs_send_response_start_2),
                   "%d.%d.%d.%d",
                   *((unsigned char *) &adsp_l2tp_session->umc_s_nw_ineta + 0),
                   *((unsigned char *) &adsp_l2tp_session->umc_s_nw_ineta + 1),
                   *((unsigned char *) &adsp_l2tp_session->umc_s_nw_ineta + 2),
                   *((unsigned char *) &adsp_l2tp_session->umc_s_nw_ineta + 3) );
   achl1 = achl_buf_w1
             + sizeof(ucrs_send_response_start_1) + 8
             + sizeof(ucrs_send_response_start_2)
             + iml1;
   memcpy( achl1,
           ucrs_send_response_start_3,
           sizeof(ucrs_send_response_start_3) );
   iml1 = sprintf( achl1
                     + sizeof(ucrs_send_response_start_3),
                   "%d.%d.%d.%d",
                   *((unsigned char *) &adsp_l2tp_session->umc_s_nw_mask + 0),
                   *((unsigned char *) &adsp_l2tp_session->umc_s_nw_mask + 1),
                   *((unsigned char *) &adsp_l2tp_session->umc_s_nw_mask + 2),
                   *((unsigned char *) &adsp_l2tp_session->umc_s_nw_mask + 3) );
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))
   ADSL_GAI1_G->achc_ginp_end = achl1 + sizeof(ucrs_send_response_start_3) + iml1;
   iml1 = ADSL_GAI1_G->achc_ginp_end - achl_buf_w1;  /* length of frame */
   chl_more = 0;                            /* not yet more bit        */
   while (TRUE) {                           /* loop output length NHASN */
     *(--achl_buf_w1) = (unsigned char) (iml1 & 0X7F) | chl_more;
     iml1 >>= 7;                            /* shift bits              */
     if (iml1 == 0) break;                  /* end of output           */
     chl_more = (unsigned char) 0X80;       /* set more bit            */
   }
#ifdef HPPPT1_V21                           /* 03.12.12 KB HOB-PPP-T1 V2.1 */
   *(--achl_buf_w1) = (unsigned char) '0';  /* control character       */
#endif
   ADSL_GAI1_G->achc_ginp_cur = achl_buf_w1;
   ADSL_GAI1_G->adsc_next = NULL;           /* clear chain             */
   adsl_sdhc1_w1->adsc_gather_i_1_i = ADSL_GAI1_G;  /* gather input data */
#undef ADSL_GAI1_G
   m_l2tp_to_client( adsp_l2tp_session, adsl_sdhc1_w1, TRUE );
   return;                                  /* continue receive TCP from client */

   p_wi_reco_00:                            /* command RECONNECT received */
   if (iml_tunnel_id == 0) {                /* check decoded tunnel-id */
     m_l2tp_warning( adsp_l2tp_session, "l%05d HOB-PPP-T1 command RECONNECT received without tunnel-id",
                     __LINE__ );
     m_hpppt1_send_stop( adsp_l2tp_session, TRUE );  /* send STOP to client */
     return;                                /* receive TCP from client */
   }
   memset( &dsl_session_ident, 0, sizeof(struct dsd_session_ident) );
   dsl_session_ident.usc_tunnel_id = (unsigned short int) iml_tunnel_id;
   adsl_l2tp_contr_w1 = (struct dsd_l2tp_contr *) adsp_l2tp_session->adsc_l2tp_conf->ac_l2tp_contr;
   achl_avl_error = NULL;                   /* clear error code AVL tree */
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
   bol1 = m_htree1_avl_search( NULL, &adsl_l2tp_contr_w1->dsc_htree1_avl_cntl,
                               &dsl_htree1_work, &dsl_session_ident.dsc_sort_1 );
   if (bol1 == FALSE) {                     /* error occured           */
     achl_avl_error = "m_htree1_avl_search() failed";  /* error code AVL tree */
     dsl_htree1_work.adsc_found = NULL;     /* element not found in tree */
   }
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
   if (achl_avl_error) {                    /* error occured           */
     m_l2tp_warning( adsp_l2tp_session, "l%05d HOB-PPP-T1 m_hpppt1_wait_init() error %s",
                     __LINE__,
                     achl_avl_error );
   }
   if (dsl_htree1_work.adsc_found == NULL) {  /* not found in tree     */
     m_l2tp_warning( adsp_l2tp_session, "l%05d HOB-PPP-T1 command RECONNECT tunnel-id %08X not found",
                     __LINE__,
                     iml_tunnel_id );
     m_hpppt1_send_stop( adsp_l2tp_session, TRUE );  /* send STOP to client */
     return;                                /* receive TCP from client */
   }
   adsl_l2tpc1 = ((struct dsd_l2tp_conn_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_l2tp_conn_1, dsc_session_ident.dsc_sort_1 )));
   if (adsl_l2tpc1->usc_random_tid != (unsigned short int) (iml_tunnel_id >> 16)) {
     m_l2tp_warning( adsp_l2tp_session, "l%05d HOB-PPP-T1 command RECONNECT tunnel-id %08X invalid checksum",
                     __LINE__,
                     iml_tunnel_id );
     m_hpppt1_send_stop( adsp_l2tp_session, TRUE );  /* send STOP to client */
     return;                                /* receive TCP from client */
   }
   if (adsl_l2tpc1->iec_scp != ied_scp_hpppt1) {  /* protocol not HOB-PPP-T1 */
     m_l2tp_warning( adsp_l2tp_session, "l%05d HOB-PPP-T1 command RECONNECT tunnel-id %08X used by other protocol",
                     __LINE__,
                     iml_tunnel_id );
     m_hpppt1_send_stop( adsp_l2tp_session, TRUE );  /* send STOP to client */
     return;                                /* receive TCP from client */
   }
   iml1 = m_l2tp_pass_session_owner( adsp_l2tp_session, chrl_work_1, sizeof(chrl_work_1) );
   if (   (iml1 != adsl_l2tpc1->imc_len_ident)  /* length ident this L2TP session */
       || (iml1 > sizeof(chrl_work_1))
       || (memcmp( adsl_l2tpc1 + 1, chrl_work_1, iml1 ))) {
     m_l2tp_warning( adsp_l2tp_session, "l%05d HOB-PPP-T1 command RECONNECT tunnel-id %08X from other user",
                     __LINE__,
                     iml_tunnel_id );
     m_hpppt1_send_stop( adsp_l2tp_session, TRUE );  /* send STOP to client */
     return;                                /* receive TCP from client */
   }
   if (adsl_l2tpc1->adsc_l2tp_session) {    /* with corresponding TCP connection */
#define IEC_HPPPT1 *((ied_state_tcp_cl *) &adsl_l2tpc1->adsc_l2tp_session->imc_state_1)
     adsl_l2tpc1->adsc_l2tp_session->ac_l2tp_conn_1 = NULL;  /* no more path to L2TP session */
     adsl_l2tpc1->adsc_ptfa1 = adsp_l2tp_session->adsc_ptfa1;  /* active target filter */
     adsp_l2tp_session->adsc_ptfa1 = NULL;  /* do not free memory      */
     if (   (IEC_HPPPT1 != ied_stt_closed)  /* TCP session not closed  */
         && (IEC_HPPPT1 != ied_stt_start_cl)) {  /* not close has been started */
       m_l2tp_warning( adsl_l2tpc1->adsc_l2tp_session,
                       "l%05d HOB-PPP-T1 command RECONNECT tunnel-id %08X TCP-session still active - closed",
                       __LINE__, iml_tunnel_id );
       IEC_HPPPT1 = ied_stt_start_cl;       /* close has been started  */
       m_l2tp_server_end( adsl_l2tpc1->adsc_l2tp_session, FALSE, "L2TP reconnected from other session" );
       adsl_l2tpc1->adsc_l2tp_session = NULL;   /* no more corresponding TCP connection */
#ifdef OLD01
       adsl_l2tpc1->dsc_ppp_str_1.vpc_handle = NULL;  /* no more handle L2TP or HTUN */
#endif
       adsl_l2tpc1->dsc_ppp_se_1.vpc_handle = NULL;  /* no more handle L2TP or HOB-TUN */
     }
#undef IEC_HPPPT1
   }
   adsl_l2tpc1->adsc_l2tp_session = adsp_l2tp_session;  /* corresponding TCP connection */
#ifdef OLD01
   adsl_l2tpc1->dsc_ppp_str_1.vpc_handle = adsp_l2tp_session;  /* handle L2TP or HTUN */
#endif
   adsl_l2tpc1->dsc_ppp_se_1.vpc_handle = adsp_l2tp_session;  /* handle L2TP or HOB-TUN */
   adsp_l2tp_session->ac_l2tp_conn_1 = adsl_l2tpc1;
   adsp_l2tp_session->adsc_ptfa1 = adsl_l2tpc1->adsc_ptfa1;  /* active target filter */
   adsl_l2tpc1->adsc_ptfa1 = NULL;          /* clear temporary value in L2TP session */
#ifdef XYZ1
   if (adsp_l2tp_session->adsc_ptfa1 == NULL) {  /* no target-filter set */
     adsp_l2tp_session->adsc_ptfa1 = m_get_l2tp_targfi( adsp_l2tp_session );  /* active target filter */
   }
#endif
   if (iml_dropped_packet_client >= 0) {    /* number of packets dropped by the client set */
     adsl_l2tpc1->imc_dropped_packet_client = iml_dropped_packet_client;  /* number of packets dropped by the client */
   }
#ifdef NOT_YET
   adsp_l2tp_session->iec_stt = ied_stt_connected;  /* session is connected */
   if (adsp_l2tp_session->dsc_timer.vpc_chain_2) {  /* timer already set    */
     m_time_rel( &adsp_l2tp_session->dsc_timer );  /* release timer         */
   }
#endif
#define IEC_HPPPT1 *((ied_state_tcp_cl *) &adsp_l2tp_session->imc_state_1)
   IEC_HPPPT1 = ied_stt_connected;          /* session is connected    */
#undef IEC_HPPPT1
   m_l2tp_information( adsp_l2tp_session, "l%05d HOB-PPP-T1 RECONNECT tunnel-id %08X",
                       __LINE__, iml_tunnel_id );
   adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
   memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))
   ADSL_GAI1_G->adsc_next = NULL;           /* clear chain             */
   ADSL_GAI1_G->achc_ginp_cur = (char *) ucrs_send_nop;
   ADSL_GAI1_G->achc_ginp_end = (char *) ucrs_send_nop + sizeof(ucrs_send_nop);
   adsl_sdhc1_w1->adsc_gather_i_1_i = ADSL_GAI1_G;  /* gather input data */
#undef ADSL_GAI1_G
   m_l2tp_to_client( adsp_l2tp_session, adsl_sdhc1_w1, TRUE );
   if (adsl_gai1_w1) {                      /* already more received   */
     m_hpppt1_rec_client( adsp_hco_wothr, adsp_l2tp_session, adsl_gai1_w1 );  /* process data received */
   }
   return;                                  /* receive TCP from client */

   p_wi_end:                                /* command end received    */
// to-do 11.10.08 KB - end L2TP UDP connection
   if (adsl_l2tpc1) {                       /* with L2TP UDP connection */
     adsl_l2tpc1->adsc_l2tp_session = NULL;   /* no more corresponding TCP connection */
     adsl_l2tpc1->dsc_ppp_se_1.vpc_handle = NULL;  /* no more handle L2TP or HOB-TUN */
   }
   m_l2tp_server_end( adsp_l2tp_session, FALSE, NULL );
   return;                                  /* receive TCP from client */

   p_wi_scan_err:                           /* error in datastream     */
   m_l2tp_warning( adsp_l2tp_session, "l%05d HOB-PPP-T1 m_hpppt1_wait_init() p_wi_scan_err error in received TCP packet",
                   __LINE__ );
   if (iml_len_hostname) free( achl_hostname );  /* free HOSTNAME      */
   m_hpppt1_send_stop( adsp_l2tp_session, TRUE );  /* send STOP to client */
   return;                                  /* receive TCP from client */
} /* end m_hpppt1_wait_init()                                          */

/** process the received header                                        */
static void m_hpppt1_proc_tcp_header( struct dsd_l2tp_session *adsp_l2tp_session,
                                      char *achp_data, int imp_len_data ) {
   int        iml_len_username;             /* length username         */
   char       *achl1, *achl2;               /* working variables       */
   char       *achl_ineta;                  /* received INETA          */
   char       *achl_username;               /* received username       */
   ied_header_client iel_hecl;              /* header received from client */
   char       chrl_ineta[ 16 ];             /* display INETA           */
   char       chrl_username[ 256 ];         /* display username        */
   char       chrl_disp_ineta[ 16 ];        /* display INETA ASCII     */

   achl1 = achp_data;                       /* here start data         */
   achl2 = achp_data + imp_len_data;        /* here end of data        */
   iel_hecl = ied_hecl_start;               /* nothing set yet         */
   achl_ineta = NULL;                       /* received INETA          */
   achl_username = NULL;                    /* received username       */

   p_header_00:                             /* decode header           */
   if (achl1 >= achl2) return;              /* all done                */
   switch (iel_hecl) {                      /* header received from client */
     case ied_hecl_start:                   /* nothing set yet         */
       if (((unsigned char) *achl1) != 0XFF) {
         goto p_header_40;                  /* header decoded          */
       }
       achl1++;                             /* after FF                */
       iel_hecl = ied_hecl_esc_1;           /* escape 1                */
       goto p_header_00;                    /* decode header           */
     case ied_hecl_esc_1:                   /* escape 1                */
       if (((unsigned char) *achl1) != 0XFA) goto p_header_err;
       achl1++;                             /* after FF                */
       iel_hecl = ied_hecl_esc_2;           /* escape 2                */
       goto p_header_00;                    /* decode header           */
     case ied_hecl_esc_2:                   /* escape 2                */
       if (((unsigned char) *achl1) != 0X28) goto p_header_err;
       achl1++;                             /* after FF                */
       iel_hecl = ied_hecl_esc_3;           /* escape 3                */
       goto p_header_00;                    /* decode header           */
     case ied_hecl_esc_3:                   /* escape 3                */
       switch ((unsigned char) *achl1) {
         case 0X60:                         /* INETA received          */
           if (achl_ineta) goto p_header_err;  /* received INETA double */
           achl_ineta = chrl_ineta;         /* display INETA           */
           achl1++;                         /* after character         */
           iel_hecl = ied_hecl_ineta_ch;    /* INETA character         */
           goto p_header_00;                /* decode header           */
         case 0X61:                         /* username received       */
           if (achl_username) goto p_header_err;  /* received username double */
           achl_username = chrl_username;   /* display username        */
           achl1++;                         /* after character         */
           iel_hecl = ied_hecl_user_ch;     /* username character      */
           goto p_header_00;                /* decode header           */
       }
       goto p_header_err;                   /* invalid character       */
     case ied_hecl_ineta_ch:                /* INETA character         */
       if (((unsigned char) *achl1) == 0XFF) {  /* escape found        */
         achl1++;                           /* after character         */
         iel_hecl = ied_hecl_ineta_esc;     /* INETA escape            */
         goto p_header_00;                  /* decode header           */
       }
       if (achl_ineta >= (chrl_ineta + sizeof(chrl_ineta))) {  /* INETA too long */
         goto p_header_err;                 /* invalid character       */
       }
       *achl_ineta++ = *achl1++;            /* copy the character      */
       goto p_header_00;                    /* decode header           */
     case ied_hecl_ineta_esc:               /* INETA escape            */
       if (((unsigned char) *achl1) == 0XF0) {  /* end of sequence     */
         achl1++;                           /* after character         */
         iel_hecl = ied_hecl_start;         /* nothing set yet         */
         goto p_header_00;                  /* decode header           */
       }
       if (((unsigned char) *achl1) != 0XFF) {  /* not double escape   */
         goto p_header_err;                 /* invalid character       */
       }
       if (achl_ineta >= (chrl_ineta + sizeof(chrl_ineta))) {  /* INETA too long */
         goto p_header_err;                 /* invalid character       */
       }
       *achl_ineta++ = *achl1++;            /* copy the character      */
       iel_hecl = ied_hecl_ineta_ch;        /* INETA character         */
       goto p_header_00;                    /* decode header           */
     case ied_hecl_user_ch:                 /* username character      */
       if (((unsigned char) *achl1) == 0XFF) {  /* escape found        */
         achl1++;                           /* after character         */
         iel_hecl = ied_hecl_user_esc;      /* username escape         */
         goto p_header_00;                  /* decode header           */
       }
       if (achl_username < (chrl_username + sizeof(chrl_username))) {
         *achl_username++ = *achl1;         /* copy the character      */
       }
       achl1++;                             /* character has been processed */
       goto p_header_00;                    /* decode header           */
     case ied_hecl_user_esc:                /* username escape         */
       if (((unsigned char) *achl1) == 0XF0) {  /* end of sequence     */
         achl1++;                           /* after character         */
         iel_hecl = ied_hecl_start;         /* nothing set yet         */
         goto p_header_00;                  /* decode header           */
       }
       if (((unsigned char) *achl1) != 0XFF) {  /* not double escape   */
         goto p_header_err;                 /* invalid character       */
       }
       if (achl_username < (chrl_username + sizeof(chrl_username))) {
         *achl_username++ = *achl1;         /* copy the character      */
       }
       achl1++;                             /* character has been processed */
       goto p_header_00;                    /* decode header           */
   }

   p_header_40:                             /* header decoded          */
   if (iel_hecl != ied_hecl_start) {        /* nothing set yet         */
     goto p_header_err;                     /* invalid character received */
   }
   if ((achl_ineta == NULL) && (achl_username == NULL)) return;  /* no hcproxauth */
   chrl_disp_ineta[0] = 0;                  /* no INETA yet            */
   achl1 = "";                              /* nothing before          */
   if (achl_ineta == (chrl_ineta + 4)) {    /* INETA IPV4              */
     sprintf( chrl_disp_ineta, "%d.%d.%d.%d",
              (unsigned char) chrl_ineta[0],
              (unsigned char) chrl_ineta[1],
              (unsigned char) chrl_ineta[2],
              (unsigned char) chrl_ineta[3] );
     achl1 = " origin INETA ";
   }
   achl2 = "";                              /* nothing before          */
   iml_len_username = 0;                    /* clear length username   */
   if (achl_username) {                     /* username set            */
     iml_len_username = achl_username - chrl_username;  /* set length username */
     achl2 = " username ";
   }
   m_l2tp_information( adsp_l2tp_session, "l%05d HOB-PPP-T1%s%s%s%.*(u8)s",
                       __LINE__,
                       achl1, chrl_disp_ineta, achl2, iml_len_username, chrl_username );
   return;                                  /* all done                */

   p_header_err:                            /* invalid character received */
   m_l2tp_warning( adsp_l2tp_session, "l%05d HOB-PPP-T1 m_hpppt1_proc_tcp_header() p_header_err iel_hecl=%d pos=%d.",
                   __LINE__,
                   iel_hecl, achl1 - achp_data );
#ifdef TRACEHL1
   m_console_out( achp_data, imp_len_data );
#endif
} /* end m_hpppt1_proc_tcp_header()                                           */

/** display the EPOCH received                                         */
static void m_display_epoch( struct dsd_l2tp_session *adsp_l2tp_session, int imp_recv_epoch ) {
   int        iml_time;                     /* current time            */
   int        iml_diff;                     /* difference time         */

   iml_time = time( NULL );
   iml_diff = imp_recv_epoch - iml_time;
   m_l2tp_information( adsp_l2tp_session, "l%05d HOB-PPP-T1 EPOCH received %d - EPOCH this host %d - difference %d.",
                       __LINE__,
                       imp_recv_epoch, iml_time, iml_diff );
} /* end m_display_epoch()                                             */

/** process packet from client - contains PPP data or something else   */
static void m_hpppt1_rec_client( struct dsd_hco_wothr *adsp_hco_wothr,
                                 struct dsd_l2tp_session *adsp_l2tp_session,
                                 struct dsd_gather_i_1 *adsp_gai1 ) {
   int        iml1, iml2;                   /* working variables       */
   BOOL       bol_end;                      /* end of connection       */
   int        iml_rc;                       /* return code             */
#ifndef B111022
   int        iml_error;                    /* returned error          */
#endif
   int        iml_no_iov;                   /* number of WSABUF / vector */
   int        iml_remainder;                /* remaining length packet */
   int        iml_len_packet;               /* length of packet        */
   ied_ret_cf iel_rcf;                      /* return value from processing target filter */
   char       chl_type;                     /* type received           */
#ifndef HL_UNIX
#ifdef B111022
   unsigned int uml_sent;                   /* bytes sent              */
#endif
#endif
   int        iml_dropped_packet_client;    /* number of packets dropped by the client */
   int        iml_var_out;                  /* output variable         */
   int        iml_l_var;                    /* length of variable      */
   enum ied_state_recv_client iel_state_recvc;   /* state of received from client */
   enum ied_command_recv_client iel_corc;   /* command received from client */
   enum ied_keyword_recv_client iel_kwrc;   /* keyword received from client */
   char       *achl1, *achl2, *achl3;       /* working variables       */
   char       *achl_out;                    /* copy to output area     */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* working variable        */
   struct dsd_l2tp_conn_1 *adsl_l2tpc1;     /* for L2TP UDP connection */
#ifndef HPPPT1_V21                          /* 03.12.12 KB HOB-PPP-T1 V2.1 */
   struct dsd_gather_i_1 dsl_gai1_sub;      /* data to pass to subroutine */
#ifdef HPPPT1_V14_RECV                      /* 31.08.12 KB HOB-PPP-T1 V1.4 receive */
   struct dsd_gather_i_1 dsl_gai1_sub_1;    /* data to pass to subroutine */
   struct dsd_gather_i_1 dsl_gai1_sub_2;    /* data to pass to subroutine */
#endif
#endif
#ifdef HPPPT1_V21                           /* 03.12.12 KB HOB-PPP-T1 V2.1 */
   struct dsd_gather_i_1 dsl_gai1_sub_1;    /* data to pass to subroutine */
   struct dsd_gather_i_1 dsl_gai1_sub_2;    /* data to pass to subroutine */
#endif
#ifdef OLD01
   struct dsd_ppp_subr_1 dsl_ppps1;         /* request PPP subroutine */
#endif
#ifndef HL_UNIX
   WSABUF     dsrl_wsabuf[ DEF_SEND_IOV ];  /* buffer for WSASend()    */
#else
#ifdef B111022
   struct msghdr dsl_msghdr;                /* for sendmsg()           */
#endif
   struct iovec dsrl_iov[ DEF_SEND_IOV ];   /* buffer for sendmsg()    */
#endif
#ifndef HPPPT1_V21                          /* 03.12.12 KB HOB-PPP-T1 V2.1 */
#ifndef HPPPT1_V14_RECV                     /* 31.08.12 KB HOB-PPP-T1 V1.4 receive */
   char       chrl_l2tp_header[ D_LEN_L2TP_HEADER + 1 ];  /* L2TP header */
#else
   char       chrl_l2tp_header[ D_LEN_L2TP_HEADER + 2 ];  /* L2TP header */
#endif
#else
   char       chrl_l2tp_header[ D_LEN_L2TP_HEADER + 1 + 6 ];  /* L2TP header */
#endif
   char       chrl_work_1[ 1024 ];          /* work area               */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-l2tp m_hpppt1_rec_client( ... ,  0X%p , ... ) called",
                   __LINE__, adsp_l2tp_session );
#endif
   bol_end = FALSE;                         /* end of connection       */
   adsl_l2tpc1 = (struct dsd_l2tp_conn_1 *) adsp_l2tp_session->ac_l2tp_conn_1;  /* L2TP UDP connection */
#ifdef TRACEHL1
   memset( chrl_work_1, 0, sizeof(chrl_work_1) );
   achl1 = achl2 = achl3 = NULL;
   iml_no_iov = 0;
   chl_type = 0;
   iel_state_recvc = ied_str_wait_cr;
   iel_corc = ied_corc_invalid;
   iel_kwrc = ied_kwrc_invalid;
   achl_out = NULL;
#endif
   adsl_gai1_w1 = adsp_gai1;                /* chain of receive buffers */
   achl1 = adsl_gai1_w1->achc_ginp_cur;     /* get start of buffer     */
#ifndef HPPPT1_V21                          /* 03.12.12 KB HOB-PPP-T1 V2.1 */
   iml_remainder = 0;                       /* remaining length packet */
   iml1 = 4;                                /* characters NHASN maximum */
#endif
#ifdef HPPPT1_V21                           /* 03.12.12 KB HOB-PPP-T1 V2.1 */
#endif

   p_rec_00:                                /* scan length             */
   if (achl1 >= adsl_gai1_w1->achc_ginp_end) {  /* at end of buffer    */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_w1 == NULL) goto p_ret_00;  /* needs more data      */
     achl1 = adsl_gai1_w1->achc_ginp_cur;   /* get start of buffer     */
   }
#ifndef HPPPT1_V21                          /* 03.12.12 KB HOB-PPP-T1 V2.1 */
   iml_remainder <<= 7;                     /* shift old bits          */
   iml_remainder |= *achl1 & 0X7F;          /* apply new bits          */
   if ((signed char) *achl1 < 0) {          /* more bit set            */
     achl1++;                               /* next character input    */
     iml1--;                                /* count character NHASN   */
     if (iml1 < 0) goto p_rec_err;          /* data received invalid   */
     goto p_rec_00;                         /* scan length             */
   }
   achl1++;                                 /* next character input    */
   /* get TAG                                                          */
   if (achl1 >= adsl_gai1_w1->achc_ginp_end) {  /* at end of buffer    */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_w1 == NULL) goto p_ret_00;  /* needs more data      */
     achl1 = adsl_gai1_w1->achc_ginp_cur;   /* get start of buffer     */
   }
   chl_type = *achl1++;                     /* type received           */
   iml_remainder--;                         /* count character processed */
   if (iml_remainder <= 0) goto p_rec_err;  /* data received invalid   */
   iml_no_iov = 1;                          /* number of WSABUF / vector */
   iml_len_packet = D_LEN_L2TP_HEADER + iml_remainder;  /* length of packet */
#endif
#ifdef HPPPT1_V21                           /* 03.12.12 KB HOB-PPP-T1 V2.1 */
   chl_type = *achl1++;                     /* type received           */
   if ((chl_type & 0XFE) == 0X30) {         /* 0X30 '0' and 0X31 '1'   */
     iml_remainder = 0;                     /* remaining length packet */
     iml1 = 4;                              /* characters NHASN maximum */
     while (TRUE) {                         /* loop                    */
       if (achl1 >= adsl_gai1_w1->achc_ginp_end) {  /* at end of buffer */
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather in chain */
         if (adsl_gai1_w1 == NULL) goto p_ret_00;  /* needs more data  */
         achl1 = adsl_gai1_w1->achc_ginp_cur;  /* get start of buffer  */
       }
       iml_remainder <<= 7;                 /* shift old bits          */
       iml_remainder |= *achl1 & 0X7F;      /* apply new bits          */
       if ((signed char) *achl1 >= 0) break;  /* more bit not set      */
       achl1++;                             /* next character input    */
       iml1--;                              /* count character NHASN   */
       if (iml1 < 0) goto p_rec_err;        /* data received invalid   */
     }
     achl1++;                               /* next character input    */
     iml_no_iov = 1;                        /* number of WSABUF / vector */
     iml_len_packet = D_LEN_L2TP_HEADER + iml_remainder;  /* length of packet */
   } else if ((chl_type & 0XD0) == 0X40) {  /* received IPV4 or IPV6   */
     chrl_l2tp_header[ D_LEN_L2TP_HEADER + 1 ] = chl_type;  /* save first byte */
     chl_type &= 0XF0;                      /* only bits IPV4 - IPV6   */
     iml_len_packet = 4;                    /* after length            */
     if (chl_type == 0X60) {                /* received IPV6           */
       iml_len_packet = 6;                  /* after length            */
     }
     iml1 = 1;                              /* first byte already copied */
     do {                                   /* copy part of header     */
       if (achl1 >= adsl_gai1_w1->achc_ginp_end) {  /* at end of buffer */
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather in chain */
         if (adsl_gai1_w1 == NULL) goto p_ret_00;  /* needs more data  */
         achl1 = adsl_gai1_w1->achc_ginp_cur;  /* get start of buffer  */
       }
       chrl_l2tp_header[ D_LEN_L2TP_HEADER + 1 + iml1++ ] = *achl1++;  /* copy IP header */
     } while (iml1 < iml_len_packet);
     iml_len_packet
       = ((*((unsigned char *) chrl_l2tp_header + D_LEN_L2TP_HEADER + 1 + 2 + 0) << 8)
             | *((unsigned char *) chrl_l2tp_header + D_LEN_L2TP_HEADER + 1 + 2 + 1));
     iml_remainder = iml_len_packet - 4;
     iml1 = (chrl_l2tp_header[ D_LEN_L2TP_HEADER + 1 ] & 0X0F) << 2;  /* length IPV4 header */
     if (chl_type == 0X60) {                /* is IPV6                 */
       iml_len_packet
         = ((*((unsigned char *) chrl_l2tp_header + D_LEN_L2TP_HEADER + 1 + 4 + 0) << 8)
               | *((unsigned char *) chrl_l2tp_header + D_LEN_L2TP_HEADER + 1 + 4 + 1))
             + D_LEN_HEADER_IPV6;
       iml_remainder = iml_len_packet - 6;
       iml1 = D_LEN_HEADER_IPV6;            /* length IPV6 header      */
     }
     if (iml_len_packet <= iml1) {          /* length too short        */
       goto p_rec_err;                      /* data received invalid   */
     }
     iml_len_packet += D_LEN_L2TP_HEADER + 1;  /* length of packet     */
     iml_no_iov = 1;                        /* number of WSABUF / vector */
   } else {                                 /* invalid type received   */
     goto p_rec_err;                        /* data received invalid   */
   }
#endif
   if (chl_type != '0') {                   /* not control data received / PPP, IPV4, IPV6 */
     if (   (adsl_l2tpc1)                   /* with connection to L2TP UDP */
         && (adsl_l2tpc1->iec_stl != ied_stl_connected)) {  /* not connected */
       goto p_ret_00;                       /* wait till connected     */
     }
   } else {                                 /* control data received   */
     iel_state_recvc = ied_str_word_01;     /* process first word      */
     achl_out = chrl_work_1;                /* start output word       */
     iel_corc = ied_corc_invalid;           /* nothing set yet         */
     iml_dropped_packet_client = -1;        /* number of packets dropped by the client */
   }
   if (achl1 >= adsl_gai1_w1->achc_ginp_end) {  /* at end of buffer    */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_w1 == NULL) goto p_ret_00;  /* needs more data      */
     achl1 = adsl_gai1_w1->achc_ginp_cur;   /* get start of buffer     */
   }
   if (chl_type == '1') {                   /* PPP data received       */
     if (adsl_l2tpc1 == NULL) {             /* no connection to L2TP UDP */
       goto p_rec_20;                       /* scan data               */
     }
     achl2 = achl1;                         /* send this data          */
     /* check if more than one chunk                                   */
     if ((achl1 + iml_remainder) > adsl_gai1_w1->achc_ginp_end) {
       if (iml_remainder > sizeof(chrl_work_1)) {
         if (adsl_l2tpc1->adsc_l2tp_session) {  /* session exists      */
           m_l2tp_warning( adsl_l2tpc1->adsc_l2tp_session, "l%05d HOB-PPP-T1 m_hpppt1_rec_client() received PPP control packet too long %d - ignored",
                           __LINE__, iml_remainder );
         }
         goto p_consume_00;                 /* consume the record      */
       }
       achl3 = chrl_work_1;                 /* set target              */
       iml1 = iml_remainder;                /* number of bytes to copy */
       while (TRUE) {                       /* loop to copy the record */
         iml2 = adsl_gai1_w1->achc_ginp_end - achl2;
         if (iml2 > iml1) iml2 = iml1;
         memcpy( achl3, achl2, iml2 );      /* copy the data           */
         achl3 += iml2;                     /* increment pointer target */
         iml1 -= iml2;                      /* decrement length to copy */
         if (iml1 == 0) break;              /* all has been copied     */
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
         if (adsl_gai1_w1 == NULL) goto p_ret_00;  /* needs more data  */
         achl2 = adsl_gai1_w1->achc_ginp_cur;  /* input current chunk  */
       }
       achl2 = chrl_work_1;                 /* here is PPP control sequence */
     }
#ifdef B110218
     if (adsl_l2tpc1->dsc_ppp_se_1.chrc_ppp_auth[0] == (unsigned char) ied_pppa_pass_thru) {  /* pass-thru */
       goto p_rec_20;                       /* scan data               */
     }
     m_recv_ppp_server_cs( &adsl_l2tpc1->dsc_ppp_se_1, achl2, iml_remainder );
#else
     if (!memcmp( achl2, ucrs_send_ppp_header, sizeof(ucrs_send_ppp_header) )) {
       m_l2tp_warning( adsl_l2tpc1->adsc_l2tp_session, "l%05d HOB-PPP-T1 m_hpppt1_rec_client() received IP packet with uncompressed header - forbidden and ignored",
                       __LINE__ );
     } else {
       if (adsl_l2tpc1->dsc_ppp_se_1.chrc_ppp_auth[0] == (unsigned char) ied_pppa_pass_thru) {  /* pass-thru */
         goto p_rec_20;                     /* scan data               */
       }
       m_recv_ppp_server_cs( &adsl_l2tpc1->dsc_ppp_se_1, achl2, iml_remainder );
     }
#endif
     while (TRUE) {                         /* eat input data          */
       iml1 = adsl_gai1_w1->achc_ginp_end - achl1;  /* remaining data  */
       if (iml1 > iml_remainder) iml1 = iml_remainder;
       iml_remainder -= iml1;               /* compute remaining part  */
       achl1 += iml1;
       adsl_gai1_w1->achc_ginp_cur = achl1;
       if (iml_remainder == 0) break;       /* all data processed      */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather in chain */
       if (adsl_gai1_w1 == NULL) goto p_rec_illogic;  /* program illogic */
       achl1 = adsl_gai1_w1->achc_ginp_cur;   /* get start of buffer   */
     }
     goto p_rec_60;                         /* packet has been processed */
#ifdef OLD01
       dsl_gai1_sub.achc_ginp_cur = achl1;  /* start with current data */
       dsl_gai1_sub.achc_ginp_end = adsl_gai1_w1->achc_ginp_end;  /* end of this gather */
       dsl_gai1_sub.adsc_next = adsl_gai1_w1->adsc_next;  /* next gather in chain */
       dsl_ppps1.adsc_ppp_str_1 = &adsl_l2tpc1->dsc_ppp_str_1;  /* PPP structure */
       dsl_ppps1.iec_pppsq = ied_pppsq_fr_client;  /* check PPP packet from client */
       dsl_ppps1.adsc_gai1_inp = &dsl_gai1_sub;  /* input data         */
       dsl_ppps1.imc_len_inp = iml_remainder;  /* length input data    */
       m_ppp_subr_1( &dsl_ppps1 );
       switch (dsl_ppps1.iec_pppsr) {       /* request PPP subroutine return code */
         case ied_pppsr_ok:                 /* request was checked O.K. */
           break;                           /* process normal          */
         case ied_pppsr_not_compl:          /* packet not complete     */
           return;                          /* wait for more data      */
         case ied_pppsr_ign_p:              /* ignore the packet       */
           while (TRUE) {                   /* eat input data          */
             iml1 = adsl_gai1_w1->achc_ginp_end - achl1;  /* remaining data */
             if (iml1 > iml_remainder) iml1 = iml_remainder;
             iml_remainder -= iml1;         /* compute remaining part  */
             achl1 += iml1;
             adsl_gai1_w1->achc_ginp_cur = achl1;
             if (iml_remainder == 0) break;  /* all data processed     */
             adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather in chain */
             if (adsl_gai1_w1 == NULL) goto p_rec_illogic;  /* program illogic */
             achl1 = adsl_gai1_w1->achc_ginp_cur;   /* get start of buffer     */
           }
           goto p_rec_60;                   /* packet has been processed */
       }
#endif
// to-do 10.11.08 KB check PPP
//   }
#ifndef HPPPT1_V21                          /* 03.12.12 KB HOB-PPP-T1 V2.1 */
   } else if (chl_type == '4') {            /* IPV4 packet received    */
     if ((adsl_l2tpc1->dsc_ppp_se_1.imc_options & D_PPP_OPT_HS_COMPL) == 0) {  /* handshake not complete */
       if (adsl_l2tpc1->adsc_l2tp_session) {  /* session exists        */
         m_l2tp_warning( adsl_l2tpc1->adsc_l2tp_session, "l%05d HOB-PPP-T1 m_hpppt1_rec_client() received IPV4 packet but handshake not complete - ignored",
                         __LINE__ );
       }
       goto p_consume_00;                   /* consume the record      */
     }
     if (adsp_l2tp_session->adsc_ptfa1) {   /* active target filter    */
       dsl_gai1_sub.achc_ginp_cur = achl1;  /* start with current data */
       dsl_gai1_sub.achc_ginp_end = adsl_gai1_w1->achc_ginp_end;  /* end of this gather */
       dsl_gai1_sub.adsc_next = adsl_gai1_w1->adsc_next;  /* next gather in chain */
       iel_rcf = m_proc_ppp_targfi_ipv4( adsp_hco_wothr, adsp_l2tp_session->adsc_ptfa1,
                                         &dsl_gai1_sub, iml_remainder );
       if (iel_rcf != ied_rcf_ok) {         /* packet is not o.k.      */
         if (iel_rcf == ied_rcf_incompl) goto p_ret_00;  /* needs more data */
         adsl_l2tpc1->imc_dropped_packet_targfi++;  /* increment number of packets dropped because of target-filter */
         goto p_consume_00;                 /* consume the record      */
       }
     }
   } else if (chl_type == '6') {            /* IPV6 packet received    */
     if ((adsl_l2tpc1->dsc_ppp_se_1.imc_options & D_PPP_OPT_HS_COMPL) == 0) {  /* handshake not complete */
       if (adsl_l2tpc1->adsc_l2tp_session) {  /* session exists        */
         m_l2tp_warning( adsl_l2tpc1->adsc_l2tp_session, "l%05d HOB-PPP-T1 m_hpppt1_rec_client() received IPV6 packet but handshake not complete - ignored",
                         __LINE__ );
       }
       goto p_consume_00;                   /* consume the record      */
     }
     if (adsp_l2tp_session->adsc_ptfa1) {   /* active target filter    */
       dsl_gai1_sub.achc_ginp_cur = achl1;  /* start with current data */
       dsl_gai1_sub.achc_ginp_end = adsl_gai1_w1->achc_ginp_end;  /* end of this gather */
       dsl_gai1_sub.adsc_next = adsl_gai1_w1->adsc_next;  /* next gather in chain */
       iel_rcf = m_proc_ppp_targfi_ipv6( adsp_hco_wothr, adsp_l2tp_session->adsc_ptfa1,
                                         &dsl_gai1_sub, iml_remainder );
       if (iel_rcf != ied_rcf_ok) {         /* packet is not o.k.      */
         if (iel_rcf == ied_rcf_incompl) goto p_ret_00;  /* needs more data */
         adsl_l2tpc1->imc_dropped_packet_targfi++;  /* increment number of packets dropped because of target-filter */
         goto p_consume_00;                 /* consume the record      */
       }
     }
#ifdef HPPPT1_V14_RECV                      /* 31.08.12 KB HOB-PPP-T1 V1.4 receive */
   } else if ((chl_type & 0XF0) == 0X40) {  /* IPV4 packet received    */
     if ((adsl_l2tpc1->dsc_ppp_se_1.imc_options & D_PPP_OPT_HS_COMPL) == 0) {  /* handshake not complete */
       if (adsl_l2tpc1->adsc_l2tp_session) {  /* session exists        */
         m_l2tp_warning( adsl_l2tpc1->adsc_l2tp_session, "l%05d HOB-PPP-T1 m_hpppt1_rec_client() received IPV4 packet but handshake not complete - ignored",
                         __LINE__ );
       }
       goto p_consume_00;                   /* consume the record      */
     }
     if (adsp_l2tp_session->adsc_ptfa1) {   /* active target filter    */
       dsl_gai1_sub_1.achc_ginp_cur = &chl_type;  /* start with first byte IP packet */
       dsl_gai1_sub_1.achc_ginp_end = &chl_type + 1;  /* end of this gather */
       dsl_gai1_sub_1.adsc_next = &dsl_gai1_sub_2;  /* next gather in chain */
       dsl_gai1_sub_2.achc_ginp_cur = achl1;  /* start with current data */
       dsl_gai1_sub_2.achc_ginp_end = adsl_gai1_w1->achc_ginp_end;  /* end of this gather */
       dsl_gai1_sub_2.adsc_next = adsl_gai1_w1->adsc_next;  /* next gather in chain */
       iel_rcf = m_proc_ppp_targfi_ipv4( adsp_hco_wothr, adsp_l2tp_session->adsc_ptfa1,
                                         &dsl_gai1_sub_1, 1 + iml_remainder );
       if (iel_rcf != ied_rcf_ok) {         /* packet is not o.k.      */
         if (iel_rcf == ied_rcf_incompl) goto p_ret_00;  /* needs more data */
         adsl_l2tpc1->imc_dropped_packet_targfi++;  /* increment number of packets dropped because of target-filter */
         goto p_consume_00;                 /* consume the record      */
       }
     }
   } else if ((chl_type & 0XF0) == 0X60) {  /* IPV6 packet received    */
     if ((adsl_l2tpc1->dsc_ppp_se_1.imc_options & D_PPP_OPT_HS_COMPL) == 0) {  /* handshake not complete */
       if (adsl_l2tpc1->adsc_l2tp_session) {  /* session exists        */
         m_l2tp_warning( adsl_l2tpc1->adsc_l2tp_session, "l%05d HOB-PPP-T1 m_hpppt1_rec_client() received IPV6 packet but handshake not complete - ignored",
                         __LINE__ );
       }
       goto p_consume_00;                   /* consume the record      */
     }
     if (adsp_l2tp_session->adsc_ptfa1) {   /* active target filter    */
       dsl_gai1_sub_1.achc_ginp_cur = &chl_type;  /* start with first byte IP packet */
       dsl_gai1_sub_1.achc_ginp_end = &chl_type + 1;  /* end of this gather */
       dsl_gai1_sub_1.adsc_next = &dsl_gai1_sub_2;  /* next gather in chain */
       dsl_gai1_sub_2.achc_ginp_cur = achl1;  /* start with current data */
       dsl_gai1_sub_2.achc_ginp_end = adsl_gai1_w1->achc_ginp_end;  /* end of this gather */
       dsl_gai1_sub_2.adsc_next = adsl_gai1_w1->adsc_next;  /* next gather in chain */
       iel_rcf = m_proc_ppp_targfi_ipv6( adsp_hco_wothr, adsp_l2tp_session->adsc_ptfa1,
                                         &dsl_gai1_sub_1, 1 + iml_remainder );
       if (iel_rcf != ied_rcf_ok) {         /* packet is not o.k.      */
         if (iel_rcf == ied_rcf_incompl) goto p_ret_00;  /* needs more data */
         adsl_l2tpc1->imc_dropped_packet_targfi++;  /* increment number of packets dropped because of target-filter */
         goto p_consume_00;                 /* consume the record      */
       }
     }
#endif
#endif
#ifdef HPPPT1_V21                           /* 03.12.12 KB HOB-PPP-T1 V2.1 */
   } else if (chl_type == 0X40) {           /* IPV4 packet received    */
#ifndef B150509
#endif
     if ((adsl_l2tpc1->dsc_ppp_se_1.imc_options & D_PPP_OPT_HS_COMPL) == 0) {  /* handshake not complete */
       if (adsl_l2tpc1->adsc_l2tp_session) {  /* session exists        */
         m_l2tp_warning( adsl_l2tpc1->adsc_l2tp_session, "l%05d HOB-PPP-T1 m_hpppt1_rec_client() received IPV4 packet but handshake not complete - ignored",
                         __LINE__ );
       }
       goto p_consume_00;                   /* consume the record      */
     }
     if (adsp_l2tp_session->adsc_ptfa1) {   /* active target filter    */
       dsl_gai1_sub_1.achc_ginp_cur = &chrl_l2tp_header[ D_LEN_L2TP_HEADER + 1 ];  /* start with first byte IP packet */
       dsl_gai1_sub_1.achc_ginp_end = &chrl_l2tp_header[ D_LEN_L2TP_HEADER + 1 + 4 ];  /* end of this gather */
       dsl_gai1_sub_1.adsc_next = &dsl_gai1_sub_2;  /* next gather in chain */
       dsl_gai1_sub_2.achc_ginp_cur = achl1;  /* start with current data */
       dsl_gai1_sub_2.achc_ginp_end = adsl_gai1_w1->achc_ginp_end;  /* end of this gather */
       dsl_gai1_sub_2.adsc_next = adsl_gai1_w1->adsc_next;  /* next gather in chain */
       iel_rcf = m_proc_ppp_targfi_ipv4( adsp_hco_wothr, adsp_l2tp_session->adsc_ptfa1,
                                         &dsl_gai1_sub_1, 4 + iml_remainder );
       if (iel_rcf != ied_rcf_ok) {         /* packet is not o.k.      */
         if (iel_rcf == ied_rcf_incompl) goto p_ret_00;  /* needs more data */
         adsl_l2tpc1->imc_dropped_packet_targfi++;  /* increment number of packets dropped because of target-filter */
         goto p_consume_00;                 /* consume the record      */
       }
     }
   } else if (chl_type == 0X60) {           /* IPV6 packet received    */
#ifndef B150509
#endif
     if ((adsl_l2tpc1->dsc_ppp_se_1.imc_options & D_PPP_OPT_HS_COMPL) == 0) {  /* handshake not complete */
       if (adsl_l2tpc1->adsc_l2tp_session) {  /* session exists        */
         m_l2tp_warning( adsl_l2tpc1->adsc_l2tp_session, "l%05d HOB-PPP-T1 m_hpppt1_rec_client() received IPV6 packet but handshake not complete - ignored",
                         __LINE__ );
       }
       goto p_consume_00;                   /* consume the record      */
     }
     if (adsp_l2tp_session->adsc_ptfa1) {   /* active target filter    */
       dsl_gai1_sub_1.achc_ginp_cur = &chrl_l2tp_header[ D_LEN_L2TP_HEADER + 1 ];  /* start with first byte IP packet */
       dsl_gai1_sub_1.achc_ginp_end = &chrl_l2tp_header[ D_LEN_L2TP_HEADER + 1 + 6 ];  /* end of this gather */
       dsl_gai1_sub_1.adsc_next = &dsl_gai1_sub_2;  /* next gather in chain */
       dsl_gai1_sub_2.achc_ginp_cur = achl1;  /* start with current data */
       dsl_gai1_sub_2.achc_ginp_end = adsl_gai1_w1->achc_ginp_end;  /* end of this gather */
       dsl_gai1_sub_2.adsc_next = adsl_gai1_w1->adsc_next;  /* next gather in chain */
       iel_rcf = m_proc_ppp_targfi_ipv6( adsp_hco_wothr, adsp_l2tp_session->adsc_ptfa1,
                                         &dsl_gai1_sub_1, 6 + iml_remainder );
       if (iel_rcf != ied_rcf_ok) {         /* packet is not o.k.      */
         if (iel_rcf == ied_rcf_incompl) goto p_ret_00;  /* needs more data */
         adsl_l2tpc1->imc_dropped_packet_targfi++;  /* increment number of packets dropped because of target-filter */
         goto p_consume_00;                 /* consume the record      */
       }
     }
#endif
   }

   p_rec_20:                                /* scan data               */
   iml1 = adsl_gai1_w1->achc_ginp_end - achl1;  /* remaining data      */
   if (iml1 > iml_remainder) iml1 = iml_remainder;
   iml_remainder -= iml1;                   /* compute remaining part  */
   while (chl_type != '0') {                /* PPP or IPV4 or IPV4 packet received */
     if (iml_no_iov >= DEF_SEND_IOV) {
       m_l2tp_warning( adsp_l2tp_session, "l%05d HOB-PPP-T1 received PPP packet in too many TCP chunks - ignored",
                     __LINE__ );
       chl_type = (unsigned char) 0XFF;
       break;
     }
#ifndef HL_UNIX
     dsrl_wsabuf[ iml_no_iov ].buf = achl1;
     dsrl_wsabuf[ iml_no_iov ].len = iml1;
#else
     dsrl_iov[ iml_no_iov ].iov_base = achl1;
     dsrl_iov[ iml_no_iov ].iov_len = iml1;
#endif
     iml_no_iov++;                          /* number of WSABUF / vector */
     break;
   }
   while (chl_type == '0') {                /* control data received   */
#ifdef TRACEHL1
     m_l2tp_warning( adsp_l2tp_session, "l%05d-T HOB-PPP-T1 m_hpppt1_rec_client() chl_type == '0' achl1=%p iml1=%d iel_state_recvc=%d.",
                     __LINE__, achl1, iml1, iel_state_recvc );
     m_console_out( achl1, iml1 );
#endif
     achl2 = achl1;                         /* start input data        */
     achl3 = achl1 + iml1;                  /* end of input data       */
     do {                                   /* loop over input data    */
       switch (iel_state_recvc) {           /* state of received from client */
         case ied_str_word_01:              /* process first word      */
           if (*achl2 != ' ') {             /* real character found    */
             if (achl_out >= (chrl_work_1 + sizeof(chrl_work_1))) {  /* output word too long */
               goto p_rc_scan_err;          /* error in datastream     */
             }
             *achl_out++ = *achl2++;        /* copy character          */
             if (achl2 < achl3) break;      /* check end of input      */
             if (iml_remainder) break;      /* more characters follow  */
           }
           if (   (achl_out == (chrl_work_1 + 5))  /* check output word length */
               && (!memcmp( chrl_work_1, "START", 5 ))) {  /* output word like expected */
             iel_corc = ied_corc_start;     /* START received          */
           } else if (   (achl_out == (chrl_work_1 + 9))  /* check output word length */
                      && (!memcmp( chrl_work_1, "RECONNECT", 9 ))) {  /* output word like expected */
             iel_corc = ied_corc_reconnect;  /* RECONNECT received     */
           } else if (   (achl_out == (chrl_work_1 + 3))  /* check output word length */
                      && (!memcmp( chrl_work_1, "NOP", 3 ))) {  /* output word like expected */
             if (   (achl2 >= achl3)        /* check end of input      */
                 && (iml_remainder == 0)) {  /* was last chunk         */
               break;                       /* all done                */
             }
             goto p_rc_scan_err;            /* error in datastream     */
           } else if (   (achl_out == (chrl_work_1 + 3))  /* check output word length */
                      && (!memcmp( chrl_work_1, "END", 3 ))) {  /* output word like expected */
             iel_corc = ied_corc_end;       /* END received            */
           } else {                         /* other command received  */
             goto p_rc_scan_err;            /* error in datastream     */
           }
           if (   (achl2 >= achl3)          /* check end of input      */
               && (iml_remainder == 0)) {   /* was last chunk          */
             break;                         /* all done                */
           }
           if (iel_corc != ied_corc_end) {  /* not END received        */
             m_l2tp_warning( adsp_l2tp_session, "l%05d HOB-PPP-T1 received control but not END",
                           __LINE__ );
             goto p_ret_00;                 /* error in datastream     */
           }
           iel_state_recvc = ied_str_start_02;  /* search start second word */
           achl2++;                         /* next character          */
           break;                           /* get next character      */
         case ied_str_start_02:             /* search start second word */
           if (*achl2 == ' ') {             /* space character found   */
             achl2++;                       /* ignore this character   */
             if (   (achl2 >= achl3)        /* check end of input      */
                 && (iml_remainder == 0)) {  /* was space at end       */
               goto p_rc_scan_err;          /* error in datastream     */
             }
           }
           achl_out = chrl_work_1;          /* start output word       */
           *achl_out++ = *achl2++;          /* copy character          */
           break;                           /* get next character      */
         case ied_str_word_02:              /* process second word     */
           if ((*achl2 != ' ') && (*achl2 != '=')) {  /* real character found */
             if (achl_out >= (chrl_work_1 + sizeof(chrl_work_1))) {  /* output word too long */
               goto p_rc_scan_err;          /* error in datastream     */
             }
             *achl_out++ = *achl2++;        /* copy character          */
             if (achl2 < achl3) break;      /* check end of input      */
             if (iml_remainder) break;      /* more characters follow  */
           }
           if (achl_out == chrl_work_1) {   /* length of string zero   */
             goto p_rc_scan_err;            /* error in datastream     */
           }
           if (*achl2 != '=') {             /* separater not like searched for */
             goto p_rc_scan_err;            /* error in datastream     */
           }
           if (   (achl_out == (chrl_work_1 + 15))  /* check output word length */
               && (!memcmp( chrl_work_1, "DROPPED-PACKETS", 15 ))) {  /* output word like expected */
             iel_kwrc = ied_kwrc_drpa;      /* DROPPED-PACKETS received */
           } else {                         /* other keyword received  */
             goto p_rc_scan_err;            /* error in datastream     */
           }
           achl2++;                         /* next character          */
           if (   (achl2 >= achl3)          /* check end of input      */
               && (iml_remainder == 0)) {   /* was space at end        */
             goto p_rc_scan_err;            /* error in datastream     */
           }
           iml_var_out = 0;                 /* clear output variable   */
           iml_l_var = 12;                  /* length of variable      */
           iel_state_recvc = ied_str_decno;  /* decode decimal number  */
           break;                           /* get next character      */
         case ied_str_decno:                /* decode decimal number   */
           if (*achl2 == ' ') {             /* end of characters found */
             achl2++;                       /* after this character    */
             if (   (achl2 >= achl3)        /* check end of input      */
                 && (iml_remainder == 0)) {  /* was space at end       */
               goto p_rc_scan_err;          /* error in datastream */
             }
             iml_dropped_packet_client = iml_var_out;  /* set number of packets dropped by the client */
             iel_state_recvc = ied_str_start_02;  /* search start second word */
             break;                         /* get next character      */
           }
           if (iml_l_var <= 0) {            /* check length of variable */
             goto p_rc_scan_err;            /* error in datastream     */
           }
           if ((*achl2 >= '0') && (*achl2 <= '9')) {  /* digit found   */
             iml_var_out *= 10;             /* multiply old value by base */
             iml_var_out += *achl2 - '0';   /* apply new digit         */
           } else goto p_rc_scan_err;       /* error in datastream     */
           iml_l_var--;                     /* decrement length of variable */
           achl2++;                         /* character has been processed */
           if (achl2 < achl3) break;        /* check end of input      */
           if (iml_remainder) break;        /* more characters follow  */
           iml_dropped_packet_client = iml_var_out;  /* set number of packets dropped by the client */
           break;                           /* control frame has been processed */
         default:
           goto p_rc_scan_err;              /* error in datastream     */
       }
     } while (achl2 < achl3);
     if (iml_dropped_packet_client >= 0) {  /* received dropped packets */
       if (adsl_l2tpc1) {                   /* with connection to L2TP UDP */
         adsl_l2tpc1->imc_dropped_packet_client = iml_dropped_packet_client;
       }
     }
     if (iml_remainder > 0) break;          /* needs more data         */
     if (iel_corc != ied_corc_end) break;   /* not END received        */
     bol_end = TRUE;                        /* end of connection       */
     if (adsl_l2tpc1 == NULL) break;        /* no more connection to L2TP UDP */
     if (adsl_l2tpc1->iec_stl != ied_stl_connected) break;  /* not connected */
// to-do 20.07.12 KB - no PPP when ied_pppa_pass_thru
     m_close_ppp_server_cs( &adsl_l2tpc1->dsc_ppp_se_1 );  /* end of PPP */
     m_send_gw_cdn( adsl_l2tpc1 );          /* send CDN                */
     adsl_l2tpc1->iec_stl = ied_stl_cdn_sent;  /* CDN has been sent    */
     adsl_l2tpc1->adsc_l2tp_session = NULL;  /* no more L2TP connection session */
#ifdef OLD01
     adsl_l2tpc1->dsc_ppp_str_1.vpc_handle = NULL;  /* no more handle L2TP or HTUN */
#endif
     adsl_l2tpc1->dsc_ppp_se_1.vpc_handle = NULL;  /* no more handle L2TP or HOB-TUN */
     adsp_l2tp_session->ac_l2tp_conn_1 = NULL;  /* no more connection to L2TP UDP */
     adsl_l2tpc1 = NULL;                    /* no more connection to L2TP UDP */
     break;
   }
   if (iml_remainder > 0) {                 /* needs more data         */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_w1 == NULL) goto p_ret_00;  /* needs more data      */
     achl1 = adsl_gai1_w1->achc_ginp_cur;   /* get start of buffer     */
     goto p_rec_20;                         /* scan data               */
   }
   /* the total packet has been scanned                                */
   achl1 += iml1;                           /* after data sent         */
   adsl_gai1_w1->achc_ginp_cur = achl1;     /* this is the end of the data */
   if (chl_type == '0') goto p_rec_60;      /* no PPP / IPV4 / IPV6 packet received */
   if (adsl_l2tpc1 == NULL) goto p_rec_60;  /* no more connection to L2TP UDP */
   iml1 = D_LEN_L2TP_HEADER;
#ifndef HPPPT1_V21                          /* 03.12.12 KB HOB-PPP-T1 V2.1 */
   if (chl_type == '4') {                   /* IPV4 received           */
     *((unsigned char *) chrl_l2tp_header + D_LEN_L2TP_HEADER) = (unsigned char) 0X21;  /* IPV4 */
     iml1++;                                /* increment length        */
     iml_len_packet++;                      /* increment length of packet */
   } else if (chl_type == '6') {            /* IPV6 received           */
     *((unsigned char *) chrl_l2tp_header + D_LEN_L2TP_HEADER) = (unsigned char) 0X57;  /* IPV6 */
     iml1++;                                /* increment length        */
     iml_len_packet++;                      /* increment length of packet */
#ifdef HPPPT1_V14_RECV                      /* 31.08.12 KB HOB-PPP-T1 V1.4 receive */
   } else if ((chl_type & 0XF0) == 0X40) {  /* IPV4 packet received    */
     *((unsigned char *) chrl_l2tp_header + D_LEN_L2TP_HEADER) = (unsigned char) 0X21;  /* IPV4 */
     *((unsigned char *) chrl_l2tp_header + D_LEN_L2TP_HEADER + 1) = chl_type;  /* first byte */
     iml1 += 2;                             /* increment length        */
     iml_len_packet += 2;                   /* increment length of packet */
   } else if ((chl_type & 0XF0) == 0X60) {  /* IPV6 packet received    */
     *((unsigned char *) chrl_l2tp_header + D_LEN_L2TP_HEADER) = (unsigned char) 0X57;  /* IPV6 */
     *((unsigned char *) chrl_l2tp_header + D_LEN_L2TP_HEADER + 1) = chl_type;  /* first byte */
     iml1 += 2;                             /* increment length        */
     iml_len_packet += 2;                   /* increment length of packet */
#endif
   }
#endif
#ifdef HPPPT1_V21                           /* 03.12.12 KB HOB-PPP-T1 V2.1 */
   if (chl_type == 0X40) {                  /* IPV4 packet received    */
     *((unsigned char *) chrl_l2tp_header + D_LEN_L2TP_HEADER) = (unsigned char) 0X21;  /* IPV4 */
     iml1 += 1 + 4;                         /* increment length        */
#ifdef B121218
     iml_len_packet += D_LEN_L2TP_HEADER + 1;  /* increment length of packet */
#endif
   } else if (chl_type == 0X60) {           /* IPV6 packet received    */
     *((unsigned char *) chrl_l2tp_header + D_LEN_L2TP_HEADER) = (unsigned char) 0X57;  /* IPV6 */
     iml1 += 1 + 6;                         /* increment length        */
#ifdef B121218
     iml_len_packet += D_LEN_L2TP_HEADER + 1;  /* increment length of packet */
#endif
   }
#endif
   *(chrl_l2tp_header) = (unsigned char) 0X40;  /* data packet         */
   *(chrl_l2tp_header + 1) = (unsigned char) 0X02;  /* version         */
   *(chrl_l2tp_header + 2 + 0) = (unsigned char) (iml_len_packet >> 8);  /* length of packet */
   *(chrl_l2tp_header + 2 + 1) = (unsigned char) iml_len_packet;  /* length of packet */
   *((unsigned char *) chrl_l2tp_header + 4 + 0) = (unsigned char) (((struct dsd_l2tp_conn_1 *) adsp_l2tp_session->ac_l2tp_conn_1)->usc_assgn_t_id >> 8);
   *((unsigned char *) chrl_l2tp_header + 4 + 1) = (unsigned char) ((struct dsd_l2tp_conn_1 *) adsp_l2tp_session->ac_l2tp_conn_1)->usc_assgn_t_id;
   *((unsigned char *) chrl_l2tp_header + 6 + 0) = (unsigned char) (((struct dsd_l2tp_conn_1 *) adsp_l2tp_session->ac_l2tp_conn_1)->usc_assgn_s_id >> 8);
   *((unsigned char *) chrl_l2tp_header + 6 + 1) = (unsigned char) ((struct dsd_l2tp_conn_1 *) adsp_l2tp_session->ac_l2tp_conn_1)->usc_assgn_s_id;
#ifndef HL_UNIX
   dsrl_wsabuf[ 0 ].buf = chrl_l2tp_header;
   dsrl_wsabuf[ 0 ].len = iml1;
#else
   dsrl_iov[ 0 ].iov_base = chrl_l2tp_header;
   dsrl_iov[ 0 ].iov_len = iml1;
#endif

#ifdef TRACEHL1
   m_l2tp_warning( adsp_l2tp_session, "l%05d-T HOB-PPP-T1 m_hpppt1_rec_client() send iml_no_iov=%d iml_len_packet=%d.",
                   __LINE__, iml_no_iov, iml_len_packet );
#endif
#ifdef B111022
#ifndef HL_UNIX
   iml_rc = WSASendTo( adsl_l2tpc1->adsc_l2tp_contr->dsc_udp_multiw_1.imc_socket,
                       dsrl_wsabuf, iml_no_iov, (DWORD *) &uml_sent, 0,
                       (struct sockaddr *) &adsl_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->dsc_soa_target,
                       adsl_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->imc_len_soa_target,
                       NULL, NULL );
   if (iml_rc != 0) {                       /* error occured           */
     m_l2tp_warning( adsp_l2tp_session, "l%05d HOB-PPP-T1 m_hpppt1_rec_client() WSASendTo UDP failed with code %d/%d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
   }
#else
   memset( &dsl_msghdr, 0, sizeof(struct msghdr) );
   dsl_msghdr.msg_name = (struct sockaddr *) &adsl_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->dsc_soa_target;
   dsl_msghdr.msg_namelen = adsl_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->imc_len_soa_target;
   dsl_msghdr.msg_iov = dsrl_iov;
   dsl_msghdr.msg_iovlen = iml_no_iov;
// dsl_msghdr.msg_flags = 0;
   iml_rc = sendmsg( adsl_l2tpc1->adsc_l2tp_contr->dsc_udp_multiw_1.imc_socket,
                     &dsl_msghdr, 0 );
   if (iml_rc < 0) {                        /* error occured           */
     m_l2tp_warning( adsp_l2tp_session, "l%05d HOB-PPP-T1 m_hpppt1_rec_client() sendmsg UDP failed with code %d/%d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
   }
#endif
#else
   iml_rc = m_udp_send_vector( &adsl_l2tpc1->adsc_l2tp_contr->dsc_udp_multiw_1,
#ifndef HL_UNIX
                               dsrl_wsabuf, iml_no_iov,
#else
                               dsrl_iov, iml_no_iov,
#endif
                               (struct sockaddr *) &adsl_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->dsc_soa_target,
                               adsl_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->imc_len_soa_target,
                               &iml_error );
   if (iml_rc < 0) {                        /* error occured           */
     m_l2tp_warning( adsp_l2tp_session, "l%05d HOB-PPP-T1 m_hpppt1_rec_client() m_udp_send_vector() UDP failed with code %d/%d.",
                     __LINE__, iml_rc, iml_error );
   }
#endif

   p_rec_60:                                /* packet has been processed */
   adsl_gai1_w2 = adsp_gai1;                /* get start input         */
   while (adsl_gai1_w2 != adsl_gai1_w1) {   /* loop over all gather before */
     adsl_gai1_w2->achc_ginp_cur = adsl_gai1_w2->achc_ginp_end;  /* set end of data */
     adsl_gai1_w2 = adsl_gai1_w2->adsc_next;  /* get next in chain     */
   }
   if (adsl_gai1_w1->achc_ginp_cur >= adsl_gai1_w1->achc_ginp_end) {  /* no more data in buffer */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1 == NULL) goto p_ret_00;  /* all data have been processed */
   }
   achl1 = adsl_gai1_w1->achc_ginp_cur;     /* get start of buffer     */
   iml_remainder = 0;                       /* remaining length packet */
   iml1 = 4;                                /* characters NHASN maximum */
   goto p_rec_00;                           /* scan length             */

   p_consume_00:                            /* consume the record      */
   while (TRUE) {                           /* eat input data          */
     iml1 = adsl_gai1_w1->achc_ginp_end - achl1;  /* remaining data    */
     if (iml1 > iml_remainder) iml1 = iml_remainder;
     iml_remainder -= iml1;                 /* compute remaining part  */
     achl1 += iml1;
     adsl_gai1_w1->achc_ginp_cur = achl1;
     if (iml_remainder == 0) break;         /* all data processed      */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_w1 == NULL) goto p_ret_00;  /* needs more data      */
     achl1 = adsl_gai1_w1->achc_ginp_cur;   /* get start of buffer     */
   }
   goto p_rec_60;                           /* packet has been processed */

   p_rec_err:                               /* data received invalid   */
   m_l2tp_warning( adsp_l2tp_session, "l%05d HOB-PPP-T1 m_hpppt1_rec_client() p_rec_err",
                   __LINE__ );
   goto p_ret_00;                           /* return from subroutine  */

   p_rec_illogic:                           /* program illogic         */
   m_l2tp_warning( adsp_l2tp_session, "l%05d HOB-PPP-T1 m_hpppt1_rec_client() p_rec_illogic",
                   __LINE__ );
   if (adsl_l2tpc1) {                       /* with L2TP UDP connection */
     adsl_l2tpc1->adsc_l2tp_session = NULL;   /* no more corresponding TCP connection */
#ifdef OLD01
     adsl_l2tpc1->dsc_ppp_str_1.vpc_handle = NULL;  /* no more handle L2TP or HTUN */
#endif
     adsl_l2tpc1->dsc_ppp_se_1.vpc_handle = NULL;  /* no more handle L2TP or HOB-TUN */
   }
   m_l2tp_server_end( adsp_l2tp_session, FALSE, NULL );
   return;

   p_rc_scan_err:                           /* error in datastream     */
   m_l2tp_warning( adsp_l2tp_session, "l%05d HOB-PPP-T1 received control but syntax invalid",
                   __LINE__ );
#ifdef TRACEHL1
   m_l2tp_warning( adsp_l2tp_session, "l%05d-T HOB-PPP-T1 m_hpppt1_rec_client() p_rc_scan_err: achl1=%p achl2=%p achl3=%p iml1=%d iml_remainder=%d achl_out=%p chrl_work_1=%p.",
                   __LINE__, achl1, achl2, achl3, iml1, iml_remainder, achl_out, chrl_work_1 );
   m_console_out( chrl_work_1, 128 );
   m_l2tp_warning( adsp_l2tp_session, "l%05d-T HOB-PPP-T1 m_hpppt1_rec_client() p_rc_scan_err: iel_state_recvc=%d chl_type=%02X iel_corc=%d iel_kwrc=%d iml_var_out=%d iml_l_var=%d",
                   __LINE__, iel_state_recvc, (unsigned char) chl_type, iel_corc, iel_kwrc, iml_var_out, iml_l_var );

#endif

   p_ret_00:                                /* return from subroutine  */
   if (bol_end == FALSE) return;            /* end of connection       */
   if (adsl_l2tpc1) {                       /* with L2TP UDP connection */
     adsl_l2tpc1->adsc_l2tp_session = NULL;   /* no more corresponding TCP connection */
#ifdef OLD01
     adsl_l2tpc1->dsc_ppp_str_1.vpc_handle = NULL;  /* no more handle L2TP or HTUN */
#endif
     adsl_l2tpc1->dsc_ppp_se_1.vpc_handle = NULL;  /* no more handle L2TP or HOB-TUN */
   }
   m_l2tp_server_end( adsp_l2tp_session, TRUE, NULL );
   return;
} /* end m_hpppt1_rec_client()                                         */

/** send STOP to the TCP client                                        */
static void m_hpppt1_send_stop( struct dsd_l2tp_session *adsp_l2tp_session, BOOL bop_locked ) {
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
#ifdef TRACEHL1
   char       chrl_date_time[ 32 ];         /* for date and time       */
#endif

#ifdef TRACEHL1
   m_get_date_time( chrl_date_time );
   m_l2tp_warning( adsp_l2tp_session, "l%05d-T HOB-PPP-T1 %s m_hpppt1_send_stop( adsp_l2tp_session=%p )",
                   __LINE__, chrl_date_time, adsp_l2tp_session );
#endif
   if (adsp_l2tp_session == NULL) return;   /* no connection           */
#define IEC_HPPPT1 *((ied_state_tcp_cl *) &adsp_l2tp_session->imc_state_1)
   if (IEC_HPPPT1 == ied_stt_stop_sent) return;  /* STOP has been sent */
   if (IEC_HPPPT1 == ied_stt_closed) return;  /* TCP session is closed */
   if (IEC_HPPPT1 == ied_stt_start_cl) return;  /* close has been started */
#undef IEC_HPPPT1
#ifdef B110904
   if (adsp_l2tp_session->boc_cont_send_client == FALSE) {  /* cannot send to client */
     m_l2tp_warning( adsp_l2tp_session, "l%05d HOB-PPP-T1 cannot send STOP - send buffers full",
                     __LINE__ );
     return;                                /* maybe possible later    */
   }
#endif
   adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
   memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))
   ADSL_GAI1_G->adsc_next = NULL;           /* clear chain             */
   ADSL_GAI1_G->achc_ginp_cur = (char *) ucrs_send_stop;
   ADSL_GAI1_G->achc_ginp_end = (char *) ucrs_send_stop + sizeof(ucrs_send_stop);
   adsl_sdhc1_w1->adsc_gather_i_1_i = ADSL_GAI1_G;  /* gather input data */
#undef ADSL_GAI1_G
   m_l2tp_to_client( adsp_l2tp_session, adsl_sdhc1_w1, bop_locked );
#define IEC_HPPPT1 *((ied_state_tcp_cl *) &adsp_l2tp_session->imc_state_1)
   IEC_HPPPT1 = ied_stt_stop_sent;          /* STOP has been sent      */
#undef IEC_HPPPT1
} /* end m_hpppt1_send_stop()                                          */

/** received data from SSTP client                                     */
static BOOL m_sstp_recv( struct dsd_hco_wothr *adsp_hco_wothr,
                         struct dsd_l2tp_session *adsp_l2tp_session,
                         struct dsd_gather_i_1 *adsp_gai1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3;             /* working-variables       */
   int        iml_count;                    /* count bytes retrieved   */
   char       *achl_rp;                     /* read input pointer      */
   char       *achl_check;                  /* check read input pointer */
   char       *achl_out;                    /* output pointer          */
   char       *achl_work;                   /* work area               */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working-variable        */
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* working-variable        */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_l2tp_conn_1 *adsl_l2tpc1_w1;  /* for L2TP UDP connection */
   struct dsd_hl_aux_epoch_1 dsl_epoch;     /* parameters for subroutine */
   char       chrl_work1[ 256 ];            /* work area               */

#define IEC_SSTPST *((ied_sstp_state *) &adsp_l2tp_session->imc_state_1)
   adsl_gai1_w1 = adsp_gai1;                /* get input               */
   achl_rp = adsl_gai1_w1->achc_ginp_cur;   /* start input here        */
   if (IEC_SSTPST == ied_sstpst_start) {    /* start of SSTP connection */
     iml1 = 0;                              /* no CR / LF found        */
     iml2 = MAX_LEN_HTTP_HEADER;            /* maximum length HTTP header */
     achl_out = chrl_work1;                 /* output pointer          */
     while (TRUE) {                         /* loop                    */
       while (achl_rp >= adsl_gai1_w1->achc_ginp_end) {  /* end of gather input */
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
         if (adsl_gai1_w1 == NULL) return TRUE;  /* end of data received */
         achl_rp = adsl_gai1_w1->achc_ginp_cur;  /* next input from here */
       }
       if (achl_out) {                      /* save first bytes        */
         *achl_out++ = *achl_rp;            /* copy one byte           */
         if (achl_out >= (chrl_work1 + sizeof(chrl_work1))) achl_out = NULL;
       }
       switch (*achl_rp) {
         case CHAR_CR:                      /* carriage-return         */
           if ((iml1 & 1) == 0) {           /* what was before         */
             iml1++;
             break;
           }
           iml1 = 1;                        /* first CR found          */
           break;
         case CHAR_LF:                      /* line-feed               */
           if (iml1 & 1) {                  /* CR was before           */
             iml1++;
             break;
           }
           iml1 = 0;                        /* like normal character   */
           break;
         default:
           iml1 = 0;                        /* normal character found  */
           break;
       }
       achl_rp++;                           /* this byte consumed      */
       if (iml1 == 4) break;
       iml2--;                              /* adjust length HTTP header */
       if (iml2 <= 0) {                     /* HTTP header too long    */
// to-do 03.10.08 KB
       }
     }
     if (achl_out) {                        /* HTTP header too short   */
// to-do 04.10.08 KB
     }
// to-do 04.10.08 KB compare SSTP_
     /* consume this record                                            */
     while (adsp_gai1 != adsl_gai1_w1) {
       adsp_gai1->achc_ginp_cur = adsp_gai1->achc_ginp_end;  /* these data have been consumed */
       adsp_gai1 = adsp_gai1->adsc_next;    /* get next in chain       */
     }
     adsp_gai1->achc_ginp_cur = achl_rp;    /* these data have been consumed */
     while (achl_rp >= adsl_gai1_w1->achc_ginp_end) {  /* end of gather input */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
       if (adsl_gai1_w1 == NULL) break;     /* end of data received    */
       achl_rp = adsl_gai1_w1->achc_ginp_cur;  /* next input from here */
     }
     if (adsl_gai1_w1) {                    /* to many data received   */
// to-do 03.10.08 KB
     }
     IEC_SSTPST = ied_sstpst_firec;         /* first record has been received */
     adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
     memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - sizeof(struct dsd_gather_i_1)))
     ADSL_GAI1_G->adsc_next = ADSL_GAI1_G - 1;  /* set chain element before */
     ADSL_GAI1_G->achc_ginp_cur = (char *) ucrs_send_sstp_firec_p1;
     ADSL_GAI1_G->achc_ginp_end = (char *) ucrs_send_sstp_firec_p1 + sizeof(ucrs_send_sstp_firec_p1);
     adsl_sdhc1_w1->adsc_gather_i_1_i = ADSL_GAI1_G;
#undef ADSL_GAI1_G
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - 2 * sizeof(struct dsd_gather_i_1)))
     ADSL_GAI1_G->adsc_next = NULL;       /* end of chain            */
     memset( &dsl_epoch, 0, sizeof(struct dsd_hl_aux_epoch_1) );  /* parameters for subroutine */
     dsl_epoch.ac_epoch_str = (char *) (adsl_sdhc1_w1 + 1);
     dsl_epoch.inc_len_epoch = 64;
     dsl_epoch.iec_chs_epoch = ied_chs_ansi_819;
     dsl_epoch.imc_epoch_val = (int) time( NULL );  /* get current time */
     m_string_from_epoch( &dsl_epoch );
     memcpy( (char *) (adsl_sdhc1_w1 + 1) + dsl_epoch.inc_len_epoch,
             ucrs_send_sstp_firec_p2,
             sizeof(ucrs_send_sstp_firec_p2) );
     ADSL_GAI1_G->achc_ginp_cur = (char *) (adsl_sdhc1_w1 + 1);
     ADSL_GAI1_G->achc_ginp_end = (char *) (adsl_sdhc1_w1 + 1)
                                    + dsl_epoch.inc_len_epoch
                                    + sizeof(ucrs_send_sstp_firec_p2);
#undef ADSL_GAI1_G
#ifdef B150611
     m_l2tp_to_client( adsp_l2tp_session, adsl_sdhc1_w1, FALSE );
#endif
#ifndef B150611
     m_l2tp_to_client( adsp_l2tp_session, adsl_sdhc1_w1, TRUE );
#endif
     return TRUE;
   }

   p_recv_20:                               /* process next record received */
   /* get type of record                                               */
   iml1 = 0;
   iml_count = 2;
   do {                                     /* loop to retrieve record type */
     while (achl_rp >= adsl_gai1_w1->achc_ginp_end) {  /* end of gather input */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
       if (adsl_gai1_w1 == NULL) return TRUE;  /* end of data received */
       achl_rp = adsl_gai1_w1->achc_ginp_cur;  /* next input from here */
     }
     iml1 <<= 8;
     iml1 |= (unsigned char) *achl_rp++;
     iml_count--;
   } while (iml_count > 0);
   /* get length of record                                             */
   iml2 = 0;
   iml_count = 2;
   do {                                     /* loop to retrieve record length */
     while (achl_rp >= adsl_gai1_w1->achc_ginp_end) {  /* end of gather input */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
       if (adsl_gai1_w1 == NULL) return TRUE;  /* end of data received */
       achl_rp = adsl_gai1_w1->achc_ginp_cur;  /* next input from here */
     }
     iml2 <<= 8;
     iml2 |= (unsigned char) *achl_rp++;
     iml_count--;
   } while (iml_count > 0);
   /* check if the record is complete                                  */
   iml3 = iml2 - 4;                         /* length remaining part   */
   if (iml3 <= 0) {                         /* length too short        */
// to-do 03.10.08 KB
     return FALSE;
   }
   achl_check = achl_rp;                    /* get read pointer        */
   adsl_gai1_w2 = adsl_gai1_w1;             /* current gather structure */
   do {                                     /* loop to check if record is complete */
     while (achl_check >= adsl_gai1_w2->achc_ginp_end) {  /* end of gather input */
       adsl_gai1_w2 = adsl_gai1_w2->adsc_next;  /* get next in chain   */
       if (adsl_gai1_w2 == NULL) return TRUE;  /* end of data received */
       achl_check = adsl_gai1_w2->achc_ginp_cur;  /* next input from here */
     }
     iml3 -= adsl_gai1_w2->achc_ginp_end - achl_check;
     achl_check = adsl_gai1_w2->achc_ginp_end;  /* end of this gather input */
   } while (iml3 > 0);
   switch (iml1) {                          /* record type received    */
     case SSTP_CONTROL_MSG:
#ifdef TRACEHL1
      m_hlnew_printf( HLOG_TRACE1, "xs-gw-l2tp.cpp l%05d m_sstp_recv() SSTP_CONTROL_MSG length=%d.",
                      __LINE__, iml2 );
#endif
       achl_work = adsp_gai1->achc_ginp_cur;  /* save start of header  */
       /* consume header of this record                                */
       iml1 = SSTP_LEN_HEADER;              /* number of bytes to consume */
       while (TRUE) {
         while (adsp_gai1->achc_ginp_cur >= adsp_gai1->achc_ginp_end) {  /* end of gather input */
           adsp_gai1 = adsp_gai1->adsc_next;  /* get next in chain     */
           if (adsp_gai1 == NULL) break;    /* end of data received    */
           achl_work = NULL;                /* no more start of header */
         }
         if (adsp_gai1 == NULL) break;      /* end of data received    */
         if (iml1 == 0) break;
         iml3 = adsp_gai1->achc_ginp_end - adsp_gai1->achc_ginp_cur;
         if (iml3 > iml1) iml3 = iml1;
         memcpy( chrl_work1 + SSTP_LEN_HEADER - iml1, adsp_gai1->achc_ginp_cur, iml3 );
         adsp_gai1->achc_ginp_cur += iml3;
         iml1 -= iml3;
       }
// to-do 25.04.09 KB illogic
       if (adsp_gai1 == NULL) {             /* illogic                 */
// to-do 03.07.14 KB - error message
         m_l2tp_warning( adsp_l2tp_session, "l%05d SSTP SSTP_CONTROL_MSG header illogic",
                         __LINE__ );
         return FALSE;
       }
#ifdef B150415
#ifdef B140703
// to-do 15.04.15 KB
       if ((adsp_gai1->achc_ginp_cur + (iml2 - 4)) <= adsp_gai1->achc_ginp_end) {
         m_sstp_ctrl_recv( adsp_hco_wothr, adsp_l2tp_session,
                           adsp_gai1->achc_ginp_cur, iml2 - 4 );
         adsp_gai1->achc_ginp_cur += iml2 - 4;
         break;                             /* all done                */
       }
#endif
       if (iml2 > sizeof(chrl_work1)) {
// to-do 25.04.09 KB invalid data
// to-do 03.07.14 KB - error message
         return FALSE;
       }
       iml1 = iml2 - SSTP_LEN_HEADER;       /* length of control data  */
#define ACHL_PACKET (chrl_work1 + SSTP_LEN_HEADER)
       achl_out = ACHL_PACKET;              /* set target              */
       while (TRUE) {
         while (adsp_gai1->achc_ginp_cur >= adsp_gai1->achc_ginp_end) {  /* end of gather input */
           adsp_gai1 = adsp_gai1->adsc_next;  /* get next in chain     */
           if (adsp_gai1 == NULL) break;    /* end of data received    */
         }
         if (adsp_gai1 == NULL) break;      /* end of data received    */
         if (iml1 == 0) break;
         iml3 = adsp_gai1->achc_ginp_end - adsp_gai1->achc_ginp_cur;
         if (iml3 > iml1) iml3 = iml1;
         memcpy( achl_out, adsp_gai1->achc_ginp_cur, iml3 );
         achl_out += iml3;
         adsp_gai1->achc_ginp_cur += iml3;
         iml1 -= iml3;
       }
#ifndef B140703
       while ((ACHL_PACKET[0] == 0) && (ACHL_PACKET[1] == 0X04)) {
         iml3 = ((unsigned char) ACHL_PACKET[4] << 8) | ((unsigned char) ACHL_PACKET[5]);
         if (iml3 != 3) break;
         /* 2.2.7 Crypto Binding Attribute                             */
         bol1 = m_get_l2tp_sstp_flag_channel_binding( adsp_l2tp_session );
         if (bol1) break;                   /* do not check channel binding for SSTP */
         iml3 = ((unsigned char) ACHL_PACKET[2] << 8) | ((unsigned char) ACHL_PACKET[3]);
         if (iml3 != 1) {
// to-do 03.07.14 KB - error message
           return FALSE;
         }
         /* get length                                                 */
         iml3 = ((unsigned char) ACHL_PACKET[6] << 8) | ((unsigned char) ACHL_PACKET[7]);
         if (iml3 != (iml2 - 4 - 4)) {
// to-do 03.07.14 KB - error message
           return FALSE;
         }
         if (iml2 < (4 + 12 + SSTP_HASH_LEN)) {
// to-do 03.07.14 KB - error message
           return FALSE;
         }
         if (memcmp( ACHL_PACKET + 4 + 12,
                     adsp_l2tp_session->imrc_nonce,
                     SSTP_HASH_LEN )) {
// to-do 03.07.14 KB - error message
           return FALSE;
         }
         bol1 = m_check_l2tp_sstp_channel_binding( adsp_l2tp_session,
                                                   chrl_work1,
                                                   iml2 );
         if (bol1) break;                   /* all valid               */
// to-do 03.07.14 KB - error message
         return FALSE;
       }
#endif
#endif
       if (  (achl_work == NULL)            /* not in gather           */
          || ((achl_work + iml2) > adsp_gai1->achc_ginp_end)) {
         achl_work = chrl_work1;            /* copy packet here        */
         if (iml2 > sizeof(chrl_work1)) {
           m_l2tp_warning( adsp_l2tp_session, "l%05d SSTP SSTP_CONTROL_MSG header too long",
                           __LINE__ );
           return FALSE;
         }
         iml1 = iml2 - SSTP_LEN_HEADER;     /* length of control data  */
#define ACHL_PACKET (achl_work + SSTP_LEN_HEADER)
         achl_out = ACHL_PACKET;            /* set target              */
         while (TRUE) {
           while (adsp_gai1->achc_ginp_cur >= adsp_gai1->achc_ginp_end) {  /* end of gather input */
             adsp_gai1 = adsp_gai1->adsc_next;  /* get next in chain   */
             if (adsp_gai1 == NULL) break;  /* end of data received    */
           }
           if (adsp_gai1 == NULL) break;    /* end of data received    */
           if (iml1 == 0) break;
           iml3 = adsp_gai1->achc_ginp_end - adsp_gai1->achc_ginp_cur;
           if (iml3 > iml1) iml3 = iml1;
           memcpy( achl_out, adsp_gai1->achc_ginp_cur, iml3 );
           achl_out += iml3;
           adsp_gai1->achc_ginp_cur += iml3;
           iml1 -= iml3;
         }
         if (iml1 > 0) {                    /* record not copied       */
           m_l2tp_warning( adsp_l2tp_session, "l%05d SSTP SSTP_CONTROL_MSG record illogic",
                           __LINE__ );
           return FALSE;
         }
       } else {
          adsp_gai1->achc_ginp_cur = achl_work + iml2;  /* consume input */
       }
       while ((ACHL_PACKET[0] == 0) && (ACHL_PACKET[1] == 0X04)) {
         iml3 = ((unsigned char) ACHL_PACKET[4] << 8) | ((unsigned char) ACHL_PACKET[5]);
         if (iml3 != 3) break;
         /* 2.2.7 Crypto Binding Attribute                             */
#ifndef B150509
#endif
         bol1 = m_get_l2tp_sstp_flag_channel_binding( adsp_l2tp_session );
         if (bol1) break;                   /* do not check channel binding for SSTP */
         iml3 = ((unsigned char) ACHL_PACKET[2] << 8) | ((unsigned char) ACHL_PACKET[3]);
         if (iml3 != 1) {
// to-do 03.07.14 KB - error message
           m_l2tp_warning( adsp_l2tp_session, "l%05d SSTP SSTP_CONTROL_MSG record illogic",
                           __LINE__ );
           return FALSE;
         }
         /* get length                                                 */
         iml3 = ((unsigned char) ACHL_PACKET[6] << 8) | ((unsigned char) ACHL_PACKET[7]);
         if (iml3 != (iml2 - SSTP_LEN_HEADER - 4)) {
// to-do 03.07.14 KB - error message
           m_l2tp_warning( adsp_l2tp_session, "l%05d SSTP SSTP_CONTROL_MSG record length invalid",
                           __LINE__ );
           return FALSE;
         }
         if (iml2 < (SSTP_LEN_HEADER + 12 + SSTP_HASH_LEN)) {
// to-do 03.07.14 KB - error message
           m_l2tp_warning( adsp_l2tp_session, "l%05d SSTP SSTP_CONTROL_MSG record length invalid",
                           __LINE__ );
           return FALSE;
         }
//#define DEBUG_150416_01
#ifdef DEBUG_150416_01
         void *ah_w1 = ACHL_PACKET + 12;
         void *ah_w2 = adsp_l2tp_session->imrc_nonce;
         int imh_w1 = SSTP_HASH_LEN;
#endif
         if (memcmp( ACHL_PACKET + 12,
                     adsp_l2tp_session->imrc_nonce,
                     SSTP_HASH_LEN )) {
// to-do 03.07.14 KB - error message
           m_l2tp_warning( adsp_l2tp_session, "l%05d SSTP SSTP_CONTROL_MSG record channel binding nonce does not match",
                           __LINE__ );
           return FALSE;
         }
         bol1 = m_check_l2tp_sstp_channel_binding( adsp_l2tp_session,
                                                   achl_work,
                                                   iml2 );
//#define DEBUG_150416_02
#ifdef DEBUG_150416_02
         bol1 = TRUE;
#endif
         if (bol1) break;                   /* all valid               */
// to-do 03.07.14 KB - error message
         m_l2tp_warning( adsp_l2tp_session, "l%05d SSTP SSTP_CONTROL_MSG record channel binding certificate does not match",
                         __LINE__ );
         return FALSE;
       }
#undef ACHL_PACKET
       m_sstp_ctrl_recv( adsp_hco_wothr, adsp_l2tp_session,
                         achl_work + SSTP_LEN_HEADER, iml2 - SSTP_LEN_HEADER );
       break;                               /* all done                */
     case SSTP_DATA_MSG:                    /* data received           */
       adsl_l2tpc1_w1 = (struct dsd_l2tp_conn_1 *) adsp_l2tp_session->ac_l2tp_conn_1;  /* L2TP UDP connection */
       if (   (adsl_l2tpc1_w1 == NULL)
           || (adsl_l2tpc1_w1->iec_stl != ied_stl_connected)) {  /* connected */
         return TRUE;
       }
       /* consume header of this record                                */
       iml1 = 4;                            /* number of bytes to consume */
       while (TRUE) {
         while (adsp_gai1->achc_ginp_cur >= adsp_gai1->achc_ginp_end) {  /* end of gather input */
           adsp_gai1 = adsp_gai1->adsc_next;  /* get next in chain     */
           if (adsp_gai1 == NULL) break;    /* end of data received    */
         }
         if (adsp_gai1 == NULL) break;      /* end of data received    */
         if (iml1 == 0) break;
         iml3 = adsp_gai1->achc_ginp_end - adsp_gai1->achc_ginp_cur;
         if (iml3 > iml1) iml3 = iml1;
         adsp_gai1->achc_ginp_cur += iml3;
         iml1 -= iml3;
       }
// to-do 05.10.08 KB illogic
       if (adsp_gai1 == NULL) return FALSE;  /* illogic                */
       adsp_gai1 = m_l2tp_send_gather( adsp_hco_wothr, adsl_l2tpc1_w1, adsp_gai1, iml2 - 4 );
       break;
   }
   if (adsp_gai1 == NULL) return TRUE;      /* no more data to process */
   adsl_gai1_w1 = adsp_gai1;                /* get input               */
   achl_rp = adsl_gai1_w1->achc_ginp_cur;   /* start input here        */
   goto p_recv_20;                          /* process next record received */
#undef IEC_SSTPST
} /* end m_sstp_recv()                                                 */

/** SSTP_CONTROL_MSG received from client                              */
static void m_sstp_ctrl_recv( struct dsd_hco_wothr *adsp_hco_wothr,
                              struct dsd_l2tp_session *adsp_l2tp_session,
                              char *achp_data, int imp_data_len ) {
   int        iml1, iml2, iml3;             /* working-variables       */
   int        iml_count;                    /* count bytes retrieved   */
   char       *achl_rp;                     /* read input pointer      */
   char       *achl_out;                    /* output pointer          */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working-variable        */
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* working-variable        */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_l2tp_conn_1 *adsl_l2tpc1_w1;  /* for L2TP UDP connection */
   struct dsd_hl_aux_epoch_1 dsl_epoch;     /* parameters for subroutine */

#define IEC_SSTPST *((ied_sstp_state *) &adsp_l2tp_session->imc_state_1)
   if (imp_data_len < 2) {
// to-do 25.04.09 KB invalid data
     return;
   }
   iml1 = (*((unsigned char *) achp_data + 0) << 8)
            | *((unsigned char *) achp_data + 1);
   if (iml1 != SSTP_MSG_CALL_CONNECT_REQ) goto p_ctrl_20;
   if (IEC_SSTPST != ied_sstpst_firec) {    /* first record has been received */
// to-do 25.04.09 KB invalid data
     return;                            /* ignore data of this record */
   }
#ifdef B110904
   if (adsp_l2tp_session->boc_cont_send_client == FALSE) {
// to-do 04.10.08 KB
   }
#endif
// to-do 03.07.14 KB - use secure random
   IEC_SSTPST = ied_sstpst_start_l2tp;      /* start L2TP now          */
   adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
   memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - sizeof(struct dsd_gather_i_1)))
   ADSL_GAI1_G->adsc_next = ADSL_GAI1_G - 1;  /* set chain element before */
   ADSL_GAI1_G->achc_ginp_cur = (char *) ucrs_send_sstp_ctrl_a_p1;
   ADSL_GAI1_G->achc_ginp_end = (char *) ucrs_send_sstp_ctrl_a_p1 + sizeof(ucrs_send_sstp_ctrl_a_p1);
   adsl_sdhc1_w1->adsc_gather_i_1_i = ADSL_GAI1_G;
#undef ADSL_GAI1_G
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - 2 * sizeof(struct dsd_gather_i_1)))
   ADSL_GAI1_G->adsc_next = NULL;           /* end of chain            */
#ifdef B150310
// to-do 10.03.15 KB - use secure random
   achl_out = (char *) adsp_l2tp_session->imrc_nonce;
   iml3 = SSTP_HASH_LEN;
   do {
     *((unsigned short int *) achl_out) = (unsigned short int) m_get_random_number( 64 * 1024 );
     achl_out += sizeof(unsigned short int);
     iml3 -= sizeof(unsigned short int);
   } while (iml3 > 0);
#endif
   iml1 = m_secdrbg_randbytes( (char *) adsp_l2tp_session->imrc_nonce, SSTP_NONCE_LEN );
// to-do 10.03.15 KB - error message and abend of session
// if (iml1 != 0) {                         /* returned error          */
// }
   ADSL_GAI1_G->achc_ginp_cur = (char *) adsp_l2tp_session->imrc_nonce;
// ADSL_GAI1_G->achc_ginp_end = (char *) adsp_l2tp_session->imrc_nonce + SSTP_HASH_LEN;
   ADSL_GAI1_G->achc_ginp_end = (char *) adsp_l2tp_session->imrc_nonce + SSTP_NONCE_LEN;
#undef ADSL_GAI1_G
#ifdef B150611
   m_l2tp_to_client( adsp_l2tp_session, adsl_sdhc1_w1, FALSE );
#endif
#ifndef B150611
   m_l2tp_to_client( adsp_l2tp_session, adsl_sdhc1_w1, TRUE );
#endif
   m_start_l2tp_conn( adsp_l2tp_session, "SSTP-client", 11, NULL, 0 );
   adsl_l2tpc1_w1 = (struct dsd_l2tp_conn_1 *) adsp_l2tp_session->ac_l2tp_conn_1;  /* L2TP UDP connection */
// to-do 05.10.08 KB message tunnel-id
   return;                                  /* all done                */

   p_ctrl_20:                               /* not SSTP_MSG_CALL_CONNECT_REQ received */
   if (IEC_SSTPST == ied_sstpst_firec) {    /* first record has not been received */
// to-do 25.04.09 KB invalid data
     return;                                /* ignore data of this record */
   }
   if (iml1 != SSTP_MSG_ECHO_REQ) return;
#ifdef B110904
   if (adsp_l2tp_session->boc_cont_send_client == FALSE) {
// to-do 04.10.08 KB
   }
#endif
   adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
   memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - sizeof(struct dsd_gather_i_1)))
   ADSL_GAI1_G->adsc_next = NULL;           /* set end of chain        */
   ADSL_GAI1_G->achc_ginp_cur = (char *) ucrs_send_sstp_ctrl_echo_ack;
   ADSL_GAI1_G->achc_ginp_end = (char *) ucrs_send_sstp_ctrl_echo_ack + sizeof(ucrs_send_sstp_ctrl_echo_ack);
   adsl_sdhc1_w1->adsc_gather_i_1_i = ADSL_GAI1_G;
#undef ADSL_GAI1_G
#ifdef B150611
   m_l2tp_to_client( adsp_l2tp_session, adsl_sdhc1_w1, FALSE );
#endif
#ifndef B150611
   m_l2tp_to_client( adsp_l2tp_session, adsl_sdhc1_w1, TRUE );
#endif
   return;                                  /* all done                */
#undef IEC_SSTPST
} /* end m_sstp_ctrl_recv()                                            */

/** control packet received from server                                */
static void m_server_control_recv( struct dsd_l2tp_conn_1 *adsp_l2tpc1, char * achp_buf, int imp_length ) {
   int        iml1;                         /* working variable        */
   char       *achl1;                       /* working variable        */
   char       *achl_start_avp;              /* start AVPs here         */
   char       *achl_end_pa;                 /* end of packet           */
   char       *achl_cur_avp;                /* start of AVP            */
#ifdef OLD01
   struct dsd_connect *adsl_conn_w1;        /* connection              */
#endif
   struct dsd_l2tp_session *adsl_l2tp_session;  /* L2TP connection session */
   unsigned short int usl_tunnel_id;        /* received tunnel id      */
   unsigned short int usl_session_id;       /* received session id     */
   int        iml_ns;                       /* sequence number sent    */
   int        iml_nr;                       /* sequence number received */
   int        iml_len_avp;                  /* length AVP              */
   int        iml_msg_type;                 /* message type            */
   int        iml_assgn_t_id;               /* assigned tunnel id      */
   int        iml_assgn_s_id;               /* assigned session id     */
//#ifdef TRACEHL1
// char       chrl_date_time[ 32 ];         /* for date and time       */
//#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-l2tp m_server_control_recv( %p ,  %p , %d ) called",
                   __LINE__, adsp_l2tpc1, achp_buf, imp_length );
#endif
   achl_end_pa = achp_buf + imp_length;     /* end of packet           */
   achl_start_avp = achp_buf + 6;           /* minimum length          */
   if (achl_start_avp > achl_end_pa) {      /* is too long             */
     m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() packet content reaches after end of packet",
                     __LINE__ );
     return;
   }
   if (*achp_buf & 0X40) {                  /* length bit present      */
     iml1 = (*((unsigned char *) achp_buf + 2 + 0) << 8)
              | *((unsigned char *) achp_buf + 2 + 1);
     if (iml1 != imp_length) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() length-packet=%d length-in-packet=%d",
                       __LINE__, imp_length, iml1 );
       return;
     }
     achl_start_avp += 2;                   /* add length of field     */
     if (achl_start_avp > achl_end_pa) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() packet content reaches after end of packet",
                       __LINE__ );
       return;
     }
   }
   usl_tunnel_id                            /* received tunnel id      */
     = (*((unsigned char *) achl_start_avp - 4 + 0) << 8)
         | *((unsigned char *) achl_start_avp - 4 + 1);
   usl_session_id                           /* received session id     */
     = (*((unsigned char *) achl_start_avp - 2 + 0) << 8)
         | *((unsigned char *) achl_start_avp - 2 + 1);
   iml_ns = iml_nr = -1;
   if (*achp_buf & 0X08) {                  /* sequence bit present    */
     achl1 = achl_start_avp;                /* save end of packet      */
     achl_start_avp += 4;                   /* add length of fields    */
     if (achl_start_avp > achl_end_pa) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() packet content reaches after end of packet",
                       __LINE__ );
       return;
     }
#ifdef MAKES_NO_SENSE
     iml_ns = (*((unsigned char *) achl1 + 0 + 0) << 8)
                | *((unsigned char *) achl1 + 0 + 1);
     iml_nr = (*((unsigned char *) achl1 + 2 + 0) << 8)
                | *((unsigned char *) achl1 + 2 + 1);
     if (iml_ns != adsp_l2tpc1->usc_nr) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() packet ns %d - should be %d",
                       __LINE__, iml_ns, adsp_l2tpc1->usc_nr );
     }
     if (iml_nr != adsp_l2tpc1->usc_ns) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() packet nr %d - should be %d",
                       __LINE__, iml_nr, adsp_l2tpc1->usc_ns );
     }
#endif
   }
   if (*achp_buf & 0X02) {                  /* offset size bit present */
     m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() offset size bit present",
                     __LINE__ );
     return;
   }
   if (*achp_buf & 0X01) {                  /* priority bit present    */
     m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() priority bit present",
                     __LINE__ );
     return;
   }
   if ((*(achp_buf + 1) & 0X0F) != 2) {     /* check version           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() version invalid - %d.",
                     __LINE__, *(achp_buf + 1) & 0X0F );
     return;
   }

   achl_cur_avp = achl_start_avp;           /* here are AVPs           */
   iml_msg_type = -1;                       /* message type not set    */
   iml_assgn_t_id = -1;                     /* assigned tunnel id not set */
   iml_assgn_s_id = -1;                     /* assigned session id not set */

   p_avp_00:                                /* check AVP               */
   if (achl_cur_avp == achl_end_pa) {
     goto p_avp_end;                        /* end of packet reached   */
   }
   achl1 = achl_cur_avp;                    /* save start of AVP       */
   if ((achl_cur_avp + 6) > achl_end_pa) {  /* is too long             */
     m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() packet content reaches after end of packet",
                     __LINE__ );
     return;
   }
   achl_cur_avp += (*((unsigned char *) achl1) & 0X03) << 8;  /* compute end of AVP */
   achl_cur_avp += *((unsigned char *) achl1 + 1);  /* compute end of AVP */
   if (achl_cur_avp > achl_end_pa) {        /* is too long             */
     m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() packet content reaches after end of packet",
                     __LINE__ );
     return;
   }
   iml_len_avp = achl_cur_avp - achl1;      /* compute length AVP      */
   /* get AVP Vendor ID and Attribute Type                             */
   iml1 = (*((unsigned char *) achl1 + 2 + 0) << 24)
            | (*((unsigned char *) achl1 + 2 + 1) << 16)
            | (*((unsigned char *) achl1 + 2 + 2) << 8)
            | *((unsigned char *) achl1 + 2 + 3);
   /* check if first AVP is Message Type                               */
   if (   (iml_msg_type < 0)                /* message type not set    */
       && (iml1 != 0)) {                    /* is not Message Type     */
     m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() first AVP not Message Type - %d.",
                     __LINE__, iml1 );
     return;
   }
   switch (iml1) {                          /* Attribute Type          */
     case 0:                                /* Message Type AVP        */
       if (iml_msg_type >= 0) {             /* message type already set */
         m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() Message Type AVP double - value first %d.",
                         __LINE__, iml_msg_type );
         return;
       }
       if (iml_len_avp != (6 + sizeof(short int))) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() Message Type AVP length invalid - %d.",
                         __LINE__, iml_len_avp );
         return;
       }
       iml_msg_type = (*((unsigned char *) achl1 + 6 + 0) << 8)
                        | *((unsigned char *) achl1 + 6 + 1);
       break;                               /* all done                */
     case 9:                                /* Assigned Tunnel Id      */
       if (iml_assgn_t_id >= 0) {           /* assigned tunnel id already set */
         m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() Assigned Tunnel Id AVP double - value first %d.",
                         __LINE__, iml_assgn_t_id );
         return;
       }
       if (iml_len_avp != (6 + sizeof(short int))) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() Assigned Tunnel Id AVP length invalid - %d.",
                         __LINE__, iml_len_avp );
         return;
       }
       iml_assgn_t_id = (*((unsigned char *) achl1 + 6 + 0) << 8)
                          | *((unsigned char *) achl1 + 6 + 1);
       break;                               /* all done                */
     case 14:                               /* Assigned Session Id     */
       if (iml_assgn_s_id >= 0) {           /* assigned session id already set */
         m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() Assigned Session Id AVP double - value first %d.",
                         __LINE__, iml_assgn_s_id );
         return;
       }
       if (iml_len_avp != (6 + sizeof(short int))) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() Assigned Session Id AVP length invalid - %d.",
                         __LINE__, iml_len_avp );
         return;
       }
       iml_assgn_s_id = (*((unsigned char *) achl1 + 6 + 0) << 8)
                          | *((unsigned char *) achl1 + 6 + 1);
       break;                               /* all done                */
   }
   goto p_avp_00;                           /* check next AVP          */

   p_avp_end:                               /* end of packet reached   */
   switch (iml_msg_type) {                  /* Message Type received   */
     case 2:                                /* start control reply, SCCRP */
       if (adsp_l2tpc1->iec_stl != ied_stl_wait_sccrp) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() received SCCRP - state invalid - %d.",
                         __LINE__, adsp_l2tpc1->iec_stl );
         return;
       }
       if (iml_assgn_t_id < 0) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() received SCCRP without Assigned Tunnel Id",
                         __LINE__ );
         return;
       }
       adsp_l2tpc1->usc_assgn_t_id = iml_assgn_t_id;
       adsp_l2tpc1->usc_nr++;               /* increment sequence number received */
       m_send_gw_scccn( adsp_l2tpc1 );
       m_send_gw_icrq( adsp_l2tpc1 );
       m_send_gw_zlb( adsp_l2tpc1 );
       adsp_l2tpc1->iec_stl = ied_stl_start_conn;  /* start connect    */
       break;
     case 6:                                /* 6 (HELLO) Hello         */
       adsp_l2tpc1->usc_nr++;               /* increment sequence number received */
       m_send_gw_zlb( adsp_l2tpc1 );
       break;
     case 11:                               /* 11 (ICRP) Incoming-Call-Reply */
       if (adsp_l2tpc1->iec_stl != ied_stl_start_conn) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() received ICRP - state invalid - %d.",
                         __LINE__, adsp_l2tpc1->iec_stl );
         return;
       }
       if (iml_assgn_s_id < 0) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() received ICRP without Assigned Session Id.",
                         __LINE__ );
         return;
       }
       adsp_l2tpc1->usc_assgn_s_id = iml_assgn_s_id;
       adsp_l2tpc1->usc_nr++;               /* increment sequence number received */
       m_send_gw_iccn( adsp_l2tpc1 );
       m_send_gw_zlb( adsp_l2tpc1 );
       adsp_l2tpc1->iec_stl = ied_stl_connected;  /* connected         */
// to-do 20.07.12 KB - no PPP when ied_pppa_pass_thru
       m_start_l2tp_ppp( adsp_l2tpc1 );     /* start PPP               */
       adsl_l2tp_session = adsp_l2tpc1->adsc_l2tp_session;  /* L2TP connection session */
       if (adsl_l2tp_session == NULL) break;  /* no L2TP connection session */
       m_l2tp_repeat_send( NULL, adsl_l2tp_session );  /* get records in storage */
       break;
     case 14:                               /* 14 (CDN) Call-Disconnect-Notify */
       if (adsp_l2tpc1->iec_stl != ied_stl_connected) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() received CDN - state invalid - %d.",
                         __LINE__, adsp_l2tpc1->iec_stl );
         return;
       }
       adsp_l2tpc1->usc_nr++;               /* increment sequence number received */
       m_send_gw_zlb( adsp_l2tpc1 );
       m_send_gw_stopccn( adsp_l2tpc1 );
// to-do 05.10.08 KB
       m_close_ppp_server_cs( &adsp_l2tpc1->dsc_ppp_se_1 );  /* end of PPP */
       if (adsp_l2tpc1->dsc_timer.vpc_chain_2) {  /* timer already set */
         m_time_rel( &adsp_l2tpc1->dsc_timer );  /* release timer      */
       }
       adsp_l2tpc1->iec_stl = ied_stl_shutdown;  /* do shutdown now    */
       adsp_l2tpc1->dsc_timer.ilcwaitmsec = TIMER_L2TP_SHUTDOWN * 1000;  /* wait in milliseconds */
       m_time_set( &adsp_l2tpc1->dsc_timer, FALSE );  /* set timeout now */
       break;
     case -1:                               /* zero body message received */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() received ZLB",
                     __LINE__ );
#endif
#ifndef D_RELEASE_1205
       if (iml_ns < 0) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() received ZLB but no ns + nr",
                         __LINE__ );
       }
#endif
//     adsp_l2tpc1->usc_nr++;               /* increment sequence number received */
       if (adsp_l2tpc1->iec_stl != ied_stl_cdn_sent) break;  /* not CDN has been sent */
       m_send_gw_stopccn( adsp_l2tpc1 );
       if (adsp_l2tpc1->dsc_timer.vpc_chain_2) {  /* timer already set */
         m_time_rel( &adsp_l2tpc1->dsc_timer );  /* release timer      */
       }
       adsp_l2tpc1->iec_stl = ied_stl_shutdown;  /* do shutdown now    */
       adsp_l2tpc1->dsc_timer.ilcwaitmsec = TIMER_L2TP_SHUTDOWN * 1000;  /* wait in milliseconds */
       m_time_set( &adsp_l2tpc1->dsc_timer, FALSE );  /* set timeout now */
       break;
     default:
       m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_server_control_recv() received Message Type %d - state %d.",
                       __LINE__, iml_msg_type, adsp_l2tpc1->iec_stl );
       adsp_l2tpc1->usc_nr++;               /* increment sequence number received */
       return;
   }
   return;
} /* end m_server_control_recv()                                       */

/** send UDP records to the L2TP gateway                               */
static struct dsd_gather_i_1 * m_l2tp_send_gather( struct dsd_hco_wothr *adsp_hco_wothr,
                                                   struct dsd_l2tp_conn_1 *adsp_l2tpc1,
                                                   struct dsd_gather_i_1 *adsp_gai1, int imp_len ) {
#ifdef OLD01
   char       *achl1, *achl2, *achl3;       /* working variables       */
#endif
   char       *achl1, *achl2;               /* working variables       */
   int        iml1, iml2;                   /* working variables       */
   BOOL       bol_error;                    /* error message given     */
   int        iml_rc;                       /* return code             */
#ifndef B120720
   int        iml_error;                    /* returned error          */
#endif
   int        iml_no_iov;                   /* number of WSABUF / vector */
   int        iml_remainder;                /* remaining length packet */
   int        iml_len_packet;               /* length of packet        */
#ifndef HL_UNIX
#ifdef B120720
   unsigned int uml_sent;                   /* bytes sent              */
#endif
#endif
   ied_ret_cf iel_rcf;                      /* return value from processing target filter */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   amd_proc_ppp_targfi aml_proc_ppp_targfi;  /* address routine target-filter */
#ifndef B160707
   struct dsd_gather_i_1 dsl_gai1_sub;      /* data to pass to subroutine */
#endif
#ifndef HL_UNIX
   WSABUF     dsrl_wsabuf[ DEF_SEND_IOV ];  /* buffer for WSASend()    */
#else
#ifdef B120720
   struct msghdr dsl_msghdr;                /* for sendmsg()           */
#endif
   struct iovec dsrl_iov[ DEF_SEND_IOV ];   /* buffer for sendmsg()    */
#endif
   char       chrl_l2tp_header[ D_LEN_L2TP_HEADER ];  /* L2TP header   */
   char       chrl_ppp_control[ D_MAX_PPP_CONTROL ];  /* PPP control sequence */

#ifdef TRY_090424
   adsp_l2tpc1->dsc_ppp_se_1.imc_options |= D_PPP_OPT_HS_COMPL;  /* handshake complete */
#endif
   aml_proc_ppp_targfi = NULL;              /* address routine target-filter */
   if (*adsp_gai1->achc_ginp_cur == 0X21) {  /* IPV4 packet received     */
     aml_proc_ppp_targfi = m_proc_ppp_targfi_ipv4;  /* address routine target-filter */
   } else if (*adsp_gai1->achc_ginp_cur == 0X57) {  /* IPV6 packet received */
     aml_proc_ppp_targfi = m_proc_ppp_targfi_ipv6;  /* address routine target-filter */
   } else {
     iml1 = sizeof(ucrs_send_ppp_header);
     adsl_gai1_w1 = adsp_gai1;              /* get gather input        */
     achl1 = chrl_l2tp_header;              /* use for temporary output */
     while (TRUE) {                         /* loop to fill output     */
       iml2 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       if (iml2 > iml1) iml2 = iml1;
       memcpy( achl1, adsl_gai1_w1->achc_ginp_cur, iml2 );  /* copy the data */
       iml1 -= iml2;
       if (iml1 <= 0) break;
       achl1 += iml2;                       /* increment pointer output */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
       if (adsl_gai1_w1 == NULL) break;     /* end of input data - illogic */
     }
     if (!memcmp( chrl_l2tp_header, ucrs_send_ppp_header, sizeof(ucrs_send_ppp_header) )) {
       m_l2tp_warning( adsp_l2tpc1->adsc_l2tp_session, "l%05d SSTP m_l2tp_send_gather() input data contains IP packet with uncompressed header - forbidden and ignored",
                       __LINE__ );
       adsl_gai1_w1 = adsp_gai1;            /* get gather input        */
       iml1 = imp_len;                      /* number of bytes to copy */
       while (TRUE) {                       /* loop to consume record  */
         iml2 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         if (iml2 > iml1) iml2 = iml1;
         adsl_gai1_w1->achc_ginp_cur += iml2;  /* consume length received */
         iml1 -= iml2;                      /* decrement length to copy */
         if (iml1 == 0) break;              /* all has been copied     */
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
         if (adsl_gai1_w1 == NULL) {        /* end of input data - illogic */
           m_l2tp_warning( adsp_l2tpc1->adsc_l2tp_session, "l%05d SSTP m_l2tp_send_gather() input data not complete",
                           __LINE__ );
           return NULL;
         }
       }
       if (adsl_gai1_w1->achc_ginp_cur >= adsl_gai1_w1->achc_ginp_end) {
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       }
       return adsl_gai1_w1;
     }
   }
   if (aml_proc_ppp_targfi) {               /* protocol recognized     */
     if (   (adsp_l2tpc1->dsc_ppp_se_1.chrc_ppp_auth[0] != (unsigned char) ied_pppa_pass_thru)  /* not pass-thru */
         && ((adsp_l2tpc1->dsc_ppp_se_1.imc_options & D_PPP_OPT_HS_COMPL) == 0)) {  /* handshake not complete */
       if (adsp_l2tpc1->adsc_l2tp_session) {  /* session exists        */
         m_l2tp_warning( adsp_l2tpc1->adsc_l2tp_session, "l%05d SSTP m_l2tp_send_gather() received PPP packet but handshake not complete - ignored",
                         __LINE__ );
       }
       goto p_consume_00;                   /* consume the record      */
     }
     if (   (adsp_l2tpc1->adsc_l2tp_session)  /* session exists        */
         && (adsp_l2tpc1->adsc_l2tp_session->adsc_ptfa1)) {  /* active target filter */
#ifdef B160707
       iel_rcf = aml_proc_ppp_targfi( adsp_hco_wothr, adsp_l2tpc1->adsc_l2tp_session->adsc_ptfa1,
                                      adsp_gai1, imp_len );
#endif
#ifndef B160707
       adsl_gai1_w1 = adsp_gai1;            /* get gather input        */
       while (adsl_gai1_w1->achc_ginp_cur >= adsl_gai1_w1->achc_ginp_end) {
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
         if (adsl_gai1_w1 == NULL) {        /* no more input           */
           m_l2tp_warning( adsp_l2tpc1->adsc_l2tp_session, "l%05d SSTP m_l2tp_send_gather() input data not complete",
                           __LINE__ );
           return NULL;
         }
       }
       achl1 = adsl_gai1_w1->achc_ginp_cur + 1;  /* after PPP header   */
       while (achl1 >= adsl_gai1_w1->achc_ginp_end) {
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
         if (adsl_gai1_w1 == NULL) {        /* no more input           */
           m_l2tp_warning( adsp_l2tpc1->adsc_l2tp_session, "l%05d SSTP m_l2tp_send_gather() input data not complete",
                           __LINE__ );
           return NULL;
         }
         achl1 = adsl_gai1_w1->achc_ginp_cur;  /* first byte packet    */
       }
       dsl_gai1_sub.achc_ginp_cur = achl1;  /* start with current data */
       dsl_gai1_sub.achc_ginp_end = adsl_gai1_w1->achc_ginp_end;  /* end of this gather */
       dsl_gai1_sub.adsc_next = adsl_gai1_w1->adsc_next;  /* next gather in chain */
       iel_rcf = aml_proc_ppp_targfi( adsp_hco_wothr, adsp_l2tpc1->adsc_l2tp_session->adsc_ptfa1,
                                      &dsl_gai1_sub, imp_len - 1 );
#endif
       if (iel_rcf != ied_rcf_ok) {         /* packet is not o.k.      */
         if (iel_rcf == ied_rcf_incompl) {  /* packet is incomplete    */
           m_l2tp_warning( adsp_l2tpc1->adsc_l2tp_session, "l%05d SSTP m_l2tp_send_gather() input data not complete",
                           __LINE__ );
           return NULL;
         }
         adsp_l2tpc1->imc_dropped_packet_targfi++;  /* increment number of packets dropped because of target-filter */
         goto p_consume_00;                 /* consume the record      */
       }
     }
   } else {                                 /* other packet received   */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_XYZ1, "l%05d xs-gw-l2tp m_l2tp_send_gather() ...chrc_ppp_auth[0] = %02X ied_pppa_pass_thru=%d.",
                     __LINE__,
                     (unsigned char) adsp_l2tpc1->dsc_ppp_se_1.chrc_ppp_auth[0],
                     ied_pppa_pass_thru );
#endif
     if (adsp_l2tpc1->dsc_ppp_se_1.chrc_ppp_auth[0] == (unsigned char) ied_pppa_pass_thru) goto p_send_12;  /* pass-thru */
#ifdef TRY_090424
     goto p_send_12;                        /* send data over L2TP     */
#endif
     adsl_gai1_w1 = adsp_gai1;              /* get gather input        */
     achl1 = adsl_gai1_w1->achc_ginp_cur;   /* input current chunk     */
     /* check if only one chunk                                        */
     if ((adsl_gai1_w1->achc_ginp_cur + imp_len) <= adsl_gai1_w1->achc_ginp_end) {
       adsl_gai1_w1->achc_ginp_cur += imp_len;  /* consume characters  */
     } else {                               /* copy to work area       */
       if (imp_len > sizeof(chrl_ppp_control)) {
         if (adsp_l2tpc1->adsc_l2tp_session) {  /* session exists        */
           m_l2tp_warning( adsp_l2tpc1->adsc_l2tp_session, "l%05d SSTP m_l2tp_send_gather() received PPP control packet too long %d - ignored",
                           __LINE__, imp_len );
         }
         goto p_consume_00;                 /* consume the record      */
       }
       achl2 = chrl_ppp_control;            /* set target              */
       iml1 = imp_len;                      /* number of bytes to copy */
       while (TRUE) {                         /* loop to consume record  */
         iml2 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         if (iml2 > iml1) iml2 = iml1;
         memcpy( achl2, achl1, iml2 );      /* copy the data           */
         adsl_gai1_w1->achc_ginp_cur += iml2;  /* consume length received */
         achl2 += iml2;                     /* increment pointer target */
         iml1 -= iml2;                      /* decrement length to copy */
         if (iml1 == 0) break;              /* all has been copied     */
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
         if (adsl_gai1_w1 == NULL) {        /* end of input data - illogic */
           m_l2tp_warning( adsp_l2tpc1->adsc_l2tp_session, "l%05d SSTP m_l2tp_send_gather() input data not complete",
                           __LINE__ );
           return NULL;
         }
         achl1 = adsl_gai1_w1->achc_ginp_cur;  /* input current chunk  */
       }
       achl1 = chrl_ppp_control;            /* here is PPP control sequence */
     }
     m_recv_ppp_server_cs( &adsp_l2tpc1->dsc_ppp_se_1, achl1, imp_len );
     if (adsl_gai1_w1 == NULL) return NULL;  /* end of input data      */
     while (adsl_gai1_w1->achc_ginp_cur >= adsl_gai1_w1->achc_ginp_end) {  /* not all consumed */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
       if (adsl_gai1_w1 == NULL) return NULL;  /* end of input data    */
     }
     return adsl_gai1_w1;                   /* return data not consumed */
   }

   p_send_12:                               /* send data over L2TP     */
   iml_no_iov = 1;                          /* number of WSABUF / vector */
   iml_len_packet = D_LEN_L2TP_HEADER + imp_len;  /* length of packet  */
   adsl_gai1_w1 = adsp_gai1;                /* get gather input        */
   iml_remainder = imp_len;                 /* remaining length packet */
   bol_error = FALSE;                       /* error message not yet given */

   p_send_20:                               /* prepare vector          */
   while (adsl_gai1_w1->achc_ginp_cur >= adsl_gai1_w1->achc_ginp_end) {
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1 == NULL) {            /* end of input data - illogic */
       if (iml_remainder == 0) goto p_send_40;  /* send data now       */
       m_l2tp_warning( adsp_l2tpc1->adsc_l2tp_session, "l%05d SSTP m_l2tp_send_gather() input data not complete",
                       __LINE__ );
       return NULL;
     }
   }
   if (iml_remainder == 0) goto p_send_40;  /* send data now           */
   iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* remaining data */
   if (iml1 > iml_remainder) iml1 = iml_remainder;
   iml_remainder -= iml1;                   /* compute remaining part  */
   if (iml_no_iov >= DEF_SEND_IOV) {
     if (bol_error == FALSE) {              /* error message not yet given */
       m_l2tp_warning( adsp_l2tpc1->adsc_l2tp_session, "l%05d SSTP m_l2tp_send_gather() received PPP packet in too many TCP chunks - ignored",
                       __LINE__ );
       bol_error = TRUE;                    /* error message given     */
     }
   } else {
#ifndef HL_UNIX
     dsrl_wsabuf[ iml_no_iov ].buf = adsl_gai1_w1->achc_ginp_cur;
     dsrl_wsabuf[ iml_no_iov ].len = iml1;
#else
     dsrl_iov[ iml_no_iov ].iov_base = adsl_gai1_w1->achc_ginp_cur;
     dsrl_iov[ iml_no_iov ].iov_len = iml1;
#endif
     iml_no_iov++;                          /* number of WSABUF / vector */
   }
   adsl_gai1_w1->achc_ginp_cur += iml1;     /* data have been processed */
   goto p_send_20;                          /* continue prepare vector */

   p_send_40:                               /* send data now           */
   *(chrl_l2tp_header) = (unsigned char) 0X40;  /* data packet         */
   *(chrl_l2tp_header + 1) = (unsigned char) 0X02;  /* version         */
   *(chrl_l2tp_header + 2 + 0) = (unsigned char) (iml_len_packet >> 8);  /* length of packet */
   *(chrl_l2tp_header + 2 + 1) = (unsigned char) iml_len_packet;  /* length of packet */
   *((unsigned char *) chrl_l2tp_header + 4 + 0) = (unsigned char) (adsp_l2tpc1->usc_assgn_t_id >> 8);
   *((unsigned char *) chrl_l2tp_header + 4 + 1) = (unsigned char) adsp_l2tpc1->usc_assgn_t_id;
   *((unsigned char *) chrl_l2tp_header + 6 + 0) = (unsigned char) (adsp_l2tpc1->usc_assgn_s_id >> 8);
   *((unsigned char *) chrl_l2tp_header + 6 + 1) = (unsigned char) adsp_l2tpc1->usc_assgn_s_id;
#ifndef HL_UNIX
   dsrl_wsabuf[ 0 ].buf = chrl_l2tp_header;
   dsrl_wsabuf[ 0 ].len = D_LEN_L2TP_HEADER;
#else
   dsrl_iov[ 0 ].iov_base = chrl_l2tp_header;
   dsrl_iov[ 0 ].iov_len = D_LEN_L2TP_HEADER;
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "HWSPL2TPnnT l%05d m_l2tp_send_gather() send iml_no_iov=%d iml_len_packet=%d.",
                   __LINE__, iml_no_iov, iml_len_packet );
#endif
#ifdef B120720
#ifndef HL_UNIX
   iml_rc = WSASendTo( adsp_l2tpc1->adsc_l2tp_contr->dsc_udp_multiw_1.imc_socket,
                       dsrl_wsabuf, iml_no_iov, (DWORD *) &uml_sent, 0,
                       (struct sockaddr *) &adsp_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->dsc_soa_target,
                       adsp_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->imc_len_soa_target,
                       NULL, NULL );
   if (iml_rc != 0) {                       /* error occured           */
     m_l2tp_warning( adsp_l2tpc1->adsc_l2tp_session, "l%05d SSTP m_l2tp_send_gather() WSASendTo UDP failed with code %d/%d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
   }
#else
   memset( &dsl_msghdr, 0, sizeof(struct msghdr) );
   dsl_msghdr.msg_name = (struct sockaddr *) &adsp_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->dsc_soa_target;
   dsl_msghdr.msg_namelen = adsp_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->imc_len_soa_target;
   dsl_msghdr.msg_iov = dsrl_iov;
   dsl_msghdr.msg_iovlen = iml_no_iov;
// dsl_msghdr.msg_flags = 0;
   iml_rc = sendmsg( adsp_l2tpc1->adsc_l2tp_contr->dsc_udp_multiw_1.imc_socket,
                     &dsl_msghdr, 0 );
   if (iml_rc < 0) {                        /* error occured           */
     m_l2tp_warning( adsp_l2tpc1->adsc_l2tp_session, "l%05d SSTP m_l2tp_send_gather() sendmsg UDP failed with code %d/%d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
   }
#endif
#else
   iml_rc = m_udp_send_vector( &adsp_l2tpc1->adsc_l2tp_contr->dsc_udp_multiw_1,
#ifndef HL_UNIX
                               dsrl_wsabuf, iml_no_iov,
#else
                               dsrl_iov, iml_no_iov,
#endif
                               (struct sockaddr *) &adsp_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->dsc_soa_target,
                               adsp_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->imc_len_soa_target,
                               &iml_error );
   if (iml_rc < 0) {                        /* error occured           */
     m_l2tp_warning( adsp_l2tpc1->adsc_l2tp_session, "l%05d HOB-PPP-T1 m_l2tp_send_gather() m_udp_send_vector() UDP failed with code %d/%d.",
                     __LINE__, iml_rc, iml_error );
   }
#endif
   return adsl_gai1_w1;                     /* return processed so far */

   p_consume_00:                            /* consume the record      */
   adsl_gai1_w1 = adsp_gai1;                /* get gather input        */
   iml1 = imp_len;                          /* number of bytes to consume */
   while (TRUE) {                           /* loop to consume record  */
     iml2 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     if (iml2 > iml1) iml2 = iml1;
     adsl_gai1_w1->achc_ginp_cur += iml2;   /* consume length received */
     iml1 -= iml2;                          /* decrement length to consume */
     if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) {  /* not all consumed */
       return adsl_gai1_w1;                 /* return remaining data   */
     }
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1 == NULL) {            /* end of input data       */
       if (iml1 == 0) break;                /* all has been consumed   */
       m_l2tp_warning( adsp_l2tpc1->adsc_l2tp_session, "l%05d SSTP m_l2tp_send_gather() input data not complete",
                       __LINE__ );
       break;                               /* end of input data - illogic */
     }
     if (iml1 == 0) break;                  /* all has been copied     */
   }
   return adsl_gai1_w1;                     /* return processed so far */
} /* end m_l2tp_send_gather()                                          */

/** start L2TP connection                                              */
static void m_start_l2tp_conn( struct dsd_l2tp_session *adsp_l2tp_session,
                               char *achp_hostname, int imp_len_hostname,
                               char *achp_ident, int imp_len_ident ) {
   BOOL       bol1;                         /* working variable        */
   struct dsd_l2tp_contr *adsl_l2tp_contr_w1;  /* L2TP control structure */
   struct dsd_l2tp_conn_1 *adsl_l2tpc1;     /* for L2TP UDP connection */
   char       *achl_avl_error;              /* error code AVL tree     */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */

   adsl_l2tp_contr_w1 = (struct dsd_l2tp_contr *) adsp_l2tp_session->adsc_l2tp_conf->ac_l2tp_contr;
   adsl_l2tpc1 = (struct dsd_l2tp_conn_1 *) malloc( sizeof(struct dsd_l2tp_conn_1) + imp_len_ident );
   memset( adsl_l2tpc1, 0, sizeof(struct dsd_l2tp_conn_1) );
   adsl_l2tpc1->imc_len_ident = imp_len_ident;  /* length ident this L2TP session */
   if (imp_len_ident) {                     /* ident set               */
     memcpy( adsl_l2tpc1 + 1, achp_ident, imp_len_ident );
   }
   if (imp_len_hostname > MAX_LEN_HOSTNAME) {  /* maximum length HOSTNAME L2TP */
     memcpy ( adsl_l2tpc1->chrc_hostname, achp_hostname, LEN_HOSTNAME_P1 );
     memcpy ( adsl_l2tpc1->chrc_hostname + LEN_HOSTNAME_P1,
              achp_hostname + imp_len_hostname
                - (MAX_LEN_HOSTNAME - LEN_HOSTNAME_P1),
              MAX_LEN_HOSTNAME - LEN_HOSTNAME_P1 );
     adsl_l2tpc1->imc_len_hostname = MAX_LEN_HOSTNAME;  /* set length HOSTNAME L2TP */
   } else {                                 /* hostname not too long   */
     memcpy ( adsl_l2tpc1->chrc_hostname, achp_hostname, imp_len_hostname );
     adsl_l2tpc1->imc_len_hostname = imp_len_hostname;  /* set length HOSTNAME L2TP */
   }
   adsl_l2tpc1->adsc_l2tp_session = adsp_l2tp_session;  /* L2TP connection session */
   adsl_l2tpc1->adsc_l2tp_contr = adsl_l2tp_contr_w1;  /* L2TP control structure */
   adsl_l2tpc1->dsc_timer.amc_compl = &m_timeout_l2tp;  /* set routine for timeout */
   adsl_l2tpc1->iec_scp = adsp_l2tp_session->iec_scp;  /* server-conf protocol */
   m_l2tp_set_ppp_auth( adsp_l2tp_session, adsl_l2tpc1->dsc_ppp_se_1.chrc_ppp_auth );
   if (adsl_l2tpc1->dsc_ppp_se_1.chrc_ppp_auth[0] == (unsigned char) ied_pppa_pass_thru) {  /* pass-thru */
     adsl_l2tpc1->dsc_ppp_se_1.imc_options |= D_PPP_OPT_HS_COMPL;  /* handshake complete */
   }
#ifdef OLD01
// to-do 10.11.08 KB remove
   adsl_l2tpc1->dsc_ppp_str_1.vpc_handle = adsp_l2tp_session;  /* handle L2TP or HTUN */
   adsl_l2tpc1->dsc_ppp_str_1.amc_ppp_auth_callback = m_ppp_auth_callback;  /* callback after authentication was done */
#endif
   adsp_l2tp_session->ac_l2tp_conn_1 = adsl_l2tpc1;  /* set L2TP UDP connection */
   /* get a new unique tunnel id                                       */
   achl_avl_error = NULL;                   /* clear error code AVL tree */
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
   do {
     adsl_l2tpc1->dsc_session_ident.usc_tunnel_id = m_get_tunnel_id( adsl_l2tp_contr_w1 );
     bol1 = m_htree1_avl_search( NULL, &adsl_l2tp_contr_w1->dsc_htree1_avl_cntl,
                                 &dsl_htree1_work, &adsl_l2tpc1->dsc_session_ident.dsc_sort_1 );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "m_htree1_avl_search() failed";  /* error code AVL tree */
       break;                               /* do not continue         */
     }
   } while (dsl_htree1_work.adsc_found);    /* continue if found in tree */
   if (achl_avl_error == NULL) {            /* no error before         */
     bol1 = m_htree1_avl_insert( NULL, &adsl_l2tp_contr_w1->dsc_htree1_avl_cntl,
                                 &dsl_htree1_work, &adsl_l2tpc1->dsc_session_ident.dsc_sort_1 );
     if (bol1 == FALSE) {                     /* error occured           */
       achl_avl_error = "m_htree1_avl_insert() failed";  /* error code AVL tree */
     }
   }
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
   if (achl_avl_error) {                    /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d m_start_l2tp_conn() error %s",
                     __LINE__,
                     achl_avl_error );
   }
   /* send 1 (SCCRQ) Start-Control-Connection-Request                  */
   adsl_l2tpc1->usc_ns = 1;                 /* sequence number sent    */
   adsl_l2tpc1->iec_stl = ied_stl_wait_sccrp;  /* wait for SCCRP       */
   adsl_l2tpc1->dsc_timer.ilcwaitmsec = TIMER_L2TP_INIT;  /* wait in milliseconds */
   m_time_set( &adsl_l2tpc1->dsc_timer, FALSE );  /* set timeout now   */
   m_send_gw_sccrq( adsl_l2tpc1 );          /* send SCCRQ              */
} /* end m_start_l2tp_conn()                                           */

/** start L2TP PPP                                                     */
static void m_start_l2tp_ppp( struct dsd_l2tp_conn_1 *adsp_l2tpc1 ) {
   int        iml1, iml2;                   /* working-variables       */

   /* dsc_ppp_se_1 (incl. chrc_ppp_auth set) and dsc_ppp_cl_1 are already cleared to zeroes */
   do {                                     /* compute magic number    */
     iml1 = iml2 = sizeof(adsp_l2tpc1->dsc_ppp_se_1.chrc_magic_number_se);
     do {
       iml1--;                              /* decrement index         */
       adsp_l2tpc1->dsc_ppp_se_1.chrc_magic_number_se[ iml1 ]
         = (unsigned char) m_get_random_number( 0X0100 );
       if (adsp_l2tpc1->dsc_ppp_se_1.chrc_magic_number_se[ iml1 ] == 0) {
         iml2--;                            /* count character zero    */
       }
     } while (iml1 > 0);
   } while (iml2 == 0);                     /* magic number zero not allowed */
   adsp_l2tpc1->dsc_ppp_se_1.amc_ppp_se_send = &m_ppp_se_send;  /* PPP server sends packet to the client */
   adsp_l2tpc1->dsc_ppp_se_1.amc_ppp_se_auth = &m_ppp_se_auth_1;  /* PPP server do authentication */
   adsp_l2tpc1->dsc_ppp_se_1.amc_ppp_se_get_ineta_client = &m_ppp_se_get_ineta_client;  /* PPP server get INETA client */
   adsp_l2tpc1->dsc_ppp_se_1.amc_ppp_se_hs_compl = &m_ppp_se_hs_compl;  /* PPP server handshake is complete */
   adsp_l2tpc1->dsc_ppp_se_1.amc_ppp_se_abend = &m_ppp_se_abend;  /* PPP server abend with message */
   adsp_l2tpc1->dsc_ppp_se_1.vpc_handle = adsp_l2tpc1->adsc_l2tp_session;  /* handle L2TP or HOB-TUN */
   adsp_l2tpc1->dsc_ppp_se_1.adsc_ppp_cl_1 = &adsp_l2tpc1->dsc_ppp_cl_1;  /* PPP client */
   do {                                     /* compute magic number    */
     iml1 = iml2 = sizeof(adsp_l2tpc1->dsc_ppp_cl_1.chrc_magic_number_cl);
     do {
       iml1--;                              /* decrement index         */
       adsp_l2tpc1->dsc_ppp_cl_1.chrc_magic_number_cl[ iml1 ]
         = (unsigned char) m_get_random_number( 0X0100 );
       if (adsp_l2tpc1->dsc_ppp_cl_1.chrc_magic_number_cl[ iml1 ] == 0) {
         iml2--;                            /* count character zero    */
       }
     } while (iml1 > 0);
   } while (iml2 == 0);                     /* magic number zero not allowed */
   adsp_l2tpc1->dsc_ppp_cl_1.amc_ppp_cl_send = &m_ppp_cl_send;  /* PPP client sends packet to the server */
   adsp_l2tpc1->dsc_ppp_cl_1.amc_ppp_cl_auth = &m_ppp_auth_2;  /* PPP client do authentication */
   adsp_l2tpc1->dsc_ppp_cl_1.amc_ppp_cl_abend = &m_ppp_cl_abend;  /* PPP client abend with message */
   adsp_l2tpc1->dsc_ppp_cl_1.adsc_ppp_se_1 = &adsp_l2tpc1->dsc_ppp_se_1;  /* PPP server */
   adsp_l2tpc1->dsc_ppp_cl_1.imc_auth_no = -2;  /* index for authentication */
   m_start_ppp_server_cs( &adsp_l2tpc1->dsc_ppp_se_1 );  /* start PPP  */
} /* end m_start_l2tp_ppp()                                            */

/** send 1 (SCCRQ) Start-Control-Connection-Request                    */
static void m_send_gw_sccrq( struct dsd_l2tp_conn_1 *adsp_l2tpc1 ) {
   int        iml1;                         /* working variable        */
   char       *achl1;                       /* working variable        */
   char       chrl_send_udp[ LEN_IP_SEND ];

   achl1 = chrl_send_udp + 12;              /* start output AVP here   */
   /* control message AVP                                              */
   memcpy( achl1, ucrs_avp_controlmsg, sizeof(ucrs_avp_controlmsg) );
   achl1 += sizeof(ucrs_avp_controlmsg);
   /* protocol version AVP                                             */
   memcpy( achl1, ucrs_avp_protvers, sizeof(ucrs_avp_protvers) );
   achl1 += sizeof(ucrs_avp_protvers);
   /* framing capabilities AVP                                         */
   memcpy( achl1, ucrs_avp_frame_cap, sizeof(ucrs_avp_frame_cap) );
   achl1 += sizeof(ucrs_avp_frame_cap);
   /* bearer capabilities AVP                                          */
   memcpy( achl1, ucrs_avp_bearer_cap, sizeof(ucrs_avp_bearer_cap) );
   achl1 += sizeof(ucrs_avp_bearer_cap);
   /* firmware revision AVP                                            */
   memcpy( achl1, ucrs_avp_firmware_rev, sizeof(ucrs_avp_firmware_rev) );
   achl1 += sizeof(ucrs_avp_firmware_rev);
   /* hostname AVP                                                     */
   *(achl1 + 0) = (unsigned char) 0X80;
   *(achl1 + 1) = (unsigned char) (6 + adsp_l2tpc1->imc_len_hostname);
   *(achl1 + 2) = 0;
   *(achl1 + 3) = 0;
   *(achl1 + 4) = 0;
   *(achl1 + 5) = (unsigned char) 0X07;
   memcpy ( achl1 + 6, adsp_l2tpc1->chrc_hostname, adsp_l2tpc1->imc_len_hostname );
   achl1 += 6 + adsp_l2tpc1->imc_len_hostname;  /* end of hostname     */
   /* vendor name AVP                                                  */
   memcpy( achl1, ucrs_avp_vendor_name, sizeof(ucrs_avp_vendor_name) );
   achl1 += sizeof(ucrs_avp_vendor_name);
   /* assigned tunnel id AVP                                           */
   *(achl1 + 0) = (unsigned char) 0X80;
   *(achl1 + 1) = (unsigned char) 0X08;
   *(achl1 + 2) = 0;
   *(achl1 + 3) = 0;
   *(achl1 + 4) = 0;
   *(achl1 + 5) = (unsigned char) 0X09;
   *(achl1 + 6) = (unsigned char) (adsp_l2tpc1->dsc_session_ident.usc_tunnel_id >> 8);
   *(achl1 + 7) = (unsigned char) adsp_l2tpc1->dsc_session_ident.usc_tunnel_id;
   achl1 += 8;
   /* receive window size AVP                                          */
   memcpy( achl1, ucrs_avp_recv_window_s, sizeof(ucrs_avp_recv_window_s) );
   achl1 += sizeof(ucrs_avp_recv_window_s);
   iml1 = achl1 - chrl_send_udp;            /* size of packet          */
   memset( chrl_send_udp, 0, 12 );          /* clear first part        */
   *(chrl_send_udp + 0) = (unsigned char) 0XC8;
   *(chrl_send_udp + 1) = (unsigned char) 0X02;
   *(chrl_send_udp + 2) = (unsigned char) (iml1 >> 8);
   *(chrl_send_udp + 3) = (unsigned char) iml1;
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "l%05d xs-gw-l2tp T m_send_gw_sccrq() send SCCRQ length=%d/0X%X.",
                 __LINE__, iml1, iml1 );
   m_console_out( chrl_send_udp, iml1 );
#endif
   m_send_udp( adsp_l2tpc1, chrl_send_udp, iml1, "SCCRQ", __LINE__ );
} /* end m_send_gw_sccrq()                                             */

/** send SCCCN Start-Control-Connection-Connected                      */
static void m_send_gw_scccn( struct dsd_l2tp_conn_1 *adsp_l2tpc1 ) {
   char       chrl_send_udp[ LEN_IP_SEND ];

#define ACHL_RECV_BUF chrl_send_udp
   memcpy( ACHL_RECV_BUF, ucrs_send_scccn, sizeof(ucrs_send_scccn) );
   *((unsigned char *) ACHL_RECV_BUF + 4 + 0) = (unsigned char) (adsp_l2tpc1->usc_assgn_t_id >> 8);
   *((unsigned char *) ACHL_RECV_BUF + 4 + 1) = (unsigned char) adsp_l2tpc1->usc_assgn_t_id;
   m_send_udp( adsp_l2tpc1, ACHL_RECV_BUF, sizeof(ucrs_send_scccn), "SCCCN", __LINE__ );
   adsp_l2tpc1->usc_ns++;                   /* increment sequence number sent */
#undef ACHL_RECV_BUF
} /* end m_send_gw_scccn()                                             */

/** send ICRQ Incoming-Call-Request                                    */
static void m_send_gw_icrq( struct dsd_l2tp_conn_1 *adsp_l2tpc1 ) {
   char       chrl_send_udp[ LEN_IP_SEND ];

#define ACHL_RECV_BUF chrl_send_udp
   memcpy( ACHL_RECV_BUF, ucrs_send_icrq, sizeof(ucrs_send_icrq) );
   *((unsigned char *) ACHL_RECV_BUF + 4 + 0) = (unsigned char) (adsp_l2tpc1->usc_assgn_t_id >> 8);
   *((unsigned char *) ACHL_RECV_BUF + 4 + 1) = (unsigned char) adsp_l2tpc1->usc_assgn_t_id;
   m_send_udp( adsp_l2tpc1, ACHL_RECV_BUF, sizeof(ucrs_send_icrq), "ICRQ", __LINE__ );
   adsp_l2tpc1->usc_ns++;                   /* increment sequence number sent */
#undef ACHL_RECV_BUF
} /* end m_send_gw_icrq()                                              */

/** send ICCN Incoming-Call-Connected                                  */
static void m_send_gw_iccn( struct dsd_l2tp_conn_1 *adsp_l2tpc1 ) {
   char       chrl_send_udp[ LEN_IP_SEND ];

#define ACHL_RECV_BUF chrl_send_udp
   memcpy( ACHL_RECV_BUF, ucrs_send_iccn, sizeof(ucrs_send_iccn) );
   *((unsigned char *) ACHL_RECV_BUF + 4 + 0) = (unsigned char) (adsp_l2tpc1->usc_assgn_t_id >> 8);
   *((unsigned char *) ACHL_RECV_BUF + 4 + 1) = (unsigned char) adsp_l2tpc1->usc_assgn_t_id;
   *((unsigned char *) ACHL_RECV_BUF + 6 + 0) = (unsigned char) (adsp_l2tpc1->usc_assgn_s_id >> 8);
   *((unsigned char *) ACHL_RECV_BUF + 6 + 1) = (unsigned char) adsp_l2tpc1->usc_assgn_s_id;
   m_send_udp( adsp_l2tpc1, ACHL_RECV_BUF, sizeof(ucrs_send_iccn), "ICCN", __LINE__ );
   adsp_l2tpc1->usc_ns++;                   /* increment sequence number sent */
#undef ACHL_RECV_BUF
} /* end m_send_gw_icrq()                                              */

/** send 14 (CDN) Call-Disconnect-Notify                               */
static void m_send_gw_cdn( struct dsd_l2tp_conn_1 *adsp_l2tpc1 ) {
   char       chrl_send_udp[ LEN_IP_SEND ];

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "l%05d  m_send_gw_cdn() tunnel-id %04X.",
                 __LINE__, adsp_l2tpc1->dsc_session_ident.usc_tunnel_id );
#endif
#define ACHL_RECV_BUF chrl_send_udp
   memcpy( ACHL_RECV_BUF, ucrs_send_cdn, sizeof(ucrs_send_cdn) );
   *((unsigned char *) ACHL_RECV_BUF + 4 + 0) = (unsigned char) (adsp_l2tpc1->usc_assgn_t_id >> 8);
   *((unsigned char *) ACHL_RECV_BUF + 4 + 1) = (unsigned char) adsp_l2tpc1->usc_assgn_t_id;
   *((unsigned char *) ACHL_RECV_BUF + 6 + 0) = (unsigned char) (adsp_l2tpc1->usc_assgn_s_id >> 8);
   *((unsigned char *) ACHL_RECV_BUF + 6 + 1) = (unsigned char) adsp_l2tpc1->usc_assgn_s_id;
   *((unsigned char *) ACHL_RECV_BUF + 8 + 0) = (unsigned char) (adsp_l2tpc1->usc_ns >> 8);
   *((unsigned char *) ACHL_RECV_BUF + 8 + 1) = (unsigned char) adsp_l2tpc1->usc_ns;
   *((unsigned char *) ACHL_RECV_BUF + 10 + 0) = (unsigned char) (adsp_l2tpc1->usc_nr >> 8);
   *((unsigned char *) ACHL_RECV_BUF + 10 + 1) = (unsigned char) adsp_l2tpc1->usc_nr;
#ifdef XYZ1
   *((unsigned char *) ACHL_RECV_BUF + sizeof(ucrs_send_cdn) - 2 + 0) = (unsigned char) (adsp_l2tpc1->dsc_session_ident.usc_tunnel_id >> 8);
   *((unsigned char *) ACHL_RECV_BUF + sizeof(ucrs_send_cdn) - 2 + 1) = (unsigned char) adsp_l2tpc1->dsc_session_ident.usc_tunnel_id;
#endif
   m_send_udp( adsp_l2tpc1, ACHL_RECV_BUF, sizeof(ucrs_send_cdn), "CDN", __LINE__ );
   adsp_l2tpc1->usc_ns++;                   /* increment sequence number sent */
#undef ACHL_RECV_BUF
} /* end m_send_gw_cdn()                                               */

/** send 4 (StopCCN) Stop-Control-Connection-Notification              */
static void m_send_gw_stopccn( struct dsd_l2tp_conn_1 *adsp_l2tpc1 ) {
   char       chrl_send_udp[ LEN_IP_SEND ];

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "l%05d  m_send_gw_stopccn() tunnel-id %04X.",
                 __LINE__, adsp_l2tpc1->dsc_session_ident.usc_tunnel_id );
#endif
#define ACHL_RECV_BUF chrl_send_udp
   memcpy( ACHL_RECV_BUF, ucrs_send_stopccn, sizeof(ucrs_send_stopccn) );
   *((unsigned char *) ACHL_RECV_BUF + 4 + 0) = (unsigned char) (adsp_l2tpc1->usc_assgn_t_id >> 8);
   *((unsigned char *) ACHL_RECV_BUF + 4 + 1) = (unsigned char) adsp_l2tpc1->usc_assgn_t_id;
   *((unsigned char *) ACHL_RECV_BUF + 8 + 0) = (unsigned char) (adsp_l2tpc1->usc_ns >> 8);
   *((unsigned char *) ACHL_RECV_BUF + 8 + 1) = (unsigned char) adsp_l2tpc1->usc_ns;
   *((unsigned char *) ACHL_RECV_BUF + 10 + 0) = (unsigned char) (adsp_l2tpc1->usc_nr >> 8);
   *((unsigned char *) ACHL_RECV_BUF + 10 + 1) = (unsigned char) adsp_l2tpc1->usc_nr;
   *((unsigned char *) ACHL_RECV_BUF + 26 + 0) = (unsigned char) (adsp_l2tpc1->dsc_session_ident.usc_tunnel_id >> 8);
   *((unsigned char *) ACHL_RECV_BUF + 26 + 1) = (unsigned char) adsp_l2tpc1->dsc_session_ident.usc_tunnel_id;
   m_send_udp( adsp_l2tpc1, ACHL_RECV_BUF, sizeof(ucrs_send_stopccn), "StopCCN", __LINE__ );
   adsp_l2tpc1->usc_ns++;                   /* increment sequence number sent */
#undef ACHL_RECV_BUF
} /* end m_send_gw_stopccn()                                           */

/** send 6 (HELLO) Hello                                               */
static void m_send_gw_hello( struct dsd_l2tp_conn_1 *adsp_l2tpc1 ) {
   char       chrl_send_udp[ LEN_IP_SEND ];

#define ACHL_RECV_BUF chrl_send_udp
   memcpy( ACHL_RECV_BUF, ucrs_send_hello, sizeof(ucrs_send_hello) );
   *((unsigned char *) ACHL_RECV_BUF + 4 + 0) = (unsigned char) (adsp_l2tpc1->usc_assgn_t_id >> 8);
   *((unsigned char *) ACHL_RECV_BUF + 4 + 1) = (unsigned char) adsp_l2tpc1->usc_assgn_t_id;
   *((unsigned char *) ACHL_RECV_BUF + 8 + 0) = (unsigned char) (adsp_l2tpc1->usc_ns >> 8);
   *((unsigned char *) ACHL_RECV_BUF + 8 + 1) = (unsigned char) adsp_l2tpc1->usc_ns;
   *((unsigned char *) ACHL_RECV_BUF + 10 + 0) = (unsigned char) (adsp_l2tpc1->usc_nr >> 8);
   *((unsigned char *) ACHL_RECV_BUF + 10 + 1) = (unsigned char) adsp_l2tpc1->usc_nr;
   m_send_udp( adsp_l2tpc1, ACHL_RECV_BUF, sizeof(ucrs_send_hello), "HELLO", __LINE__ );
   adsp_l2tpc1->usc_ns++;                   /* increment sequence number sent */
#undef ACHL_RECV_BUF
} /* end m_send_gw_hello()                                             */

/** send ZLB Zero-Length Body Message                                  */
static void m_send_gw_zlb( struct dsd_l2tp_conn_1 *adsp_l2tpc1 ) {
   char       chrl_send_udp[ LEN_IP_SEND ];

#define ACHL_RECV_BUF chrl_send_udp
   memset( ACHL_RECV_BUF, 0, 12 );
   *((unsigned char *) ACHL_RECV_BUF + 0) = (unsigned char) 0XC8;
   *((unsigned char *) ACHL_RECV_BUF + 1) = (unsigned char) 0X02;
   *((unsigned char *) ACHL_RECV_BUF + 3) = (unsigned char) 12;
   *((unsigned char *) ACHL_RECV_BUF + 4 + 0) = (unsigned char) (adsp_l2tpc1->usc_assgn_t_id >> 8);
   *((unsigned char *) ACHL_RECV_BUF + 4 + 1) = (unsigned char) adsp_l2tpc1->usc_assgn_t_id;
// *((unsigned char *) ACHL_RECV_BUF + 6 + 0) = (unsigned char) (adsp_l2tpc1->usc_assgn_s_id >> 8);
// *((unsigned char *) ACHL_RECV_BUF + 6 + 1) = (unsigned char) adsp_l2tpc1->usc_assgn_s_id;
   *((unsigned char *) ACHL_RECV_BUF + 8 + 0) = (unsigned char) (adsp_l2tpc1->usc_ns >> 8);
   *((unsigned char *) ACHL_RECV_BUF + 8 + 1) = (unsigned char) adsp_l2tpc1->usc_ns;
   *((unsigned char *) ACHL_RECV_BUF + 10 + 0) = (unsigned char) (adsp_l2tpc1->usc_nr >> 8);
   *((unsigned char *) ACHL_RECV_BUF + 10 + 1) = (unsigned char) adsp_l2tpc1->usc_nr;
   m_send_udp( adsp_l2tpc1, ACHL_RECV_BUF, 12, "ZLB", __LINE__ );
// adsp_l2tpc1->usc_ns++;                   /* increment sequence number sent */
#undef ACHL_RECV_BUF
} /* end m_send_gw_zlb()                                               */

/** send L2TP packet over UDP to the gateway                           */
static void m_send_udp( struct dsd_l2tp_conn_1 *adsp_l2tpc1,
                        char *achp_buf, int imp_length,
                        char *achp_text, int imp_lineno ) {
   int        iml_rc;                       /* return code             */
#ifndef B111022
   int        iml_error;                    /* returned error          */
#endif
   struct dsd_l2tp_session *adsl_l2tp_session;  /* L2TP connection session */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "l%05d xs-gw-l2tp T m_send_udp() tunnel-id %04X len=%d/0X%X.",
                 __LINE__, adsp_l2tpc1->dsc_session_ident.usc_tunnel_id, imp_length, imp_length );
   m_console_out( achp_buf, imp_length );
#endif
#ifdef B111022
   iml_rc = sendto( adsp_l2tpc1->adsc_l2tp_contr->dsc_udp_multiw_1.imc_socket,
                    achp_buf, imp_length, 0,
                    (struct sockaddr *) &adsp_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->dsc_soa_target,
                    adsp_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->imc_len_soa_target );
#else
   iml_rc = m_udp_sendto( &adsp_l2tpc1->adsc_l2tp_contr->dsc_udp_multiw_1,
                          achp_buf, imp_length,
                          (struct sockaddr *) &adsp_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->dsc_soa_target,
                          adsp_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->imc_len_soa_target,
                          &iml_error );
#endif
   if (iml_rc == imp_length) return;        /* sendto succeeded        */
   /* error occured                                                    */
   adsl_l2tp_session = adsp_l2tpc1->adsc_l2tp_session;  /* L2TP connection session */
   if (adsl_l2tp_session) {                 /* connected with session  */
#ifdef B111022
     m_l2tp_warning( adsl_l2tp_session, "l%05d m_send_udp() sendto L2TP UDP failed with code %d/%d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
#else
     m_l2tp_warning( adsl_l2tp_session, "l%05d m_send_udp() sendto L2TP UDP failed with code %d/%d.",
                     __LINE__, iml_rc, iml_error );
#endif
     return;
   }
#ifdef B111022
   m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d xs-gw-l2tp W m_send_udp() sendto L2TP UDP failed with code %d/%d.",
                   __LINE__, iml_rc, D_TCP_ERROR );
#else
   m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d xs-gw-l2tp W m_send_udp() sendto L2TP UDP failed with code %d/%d.",
                   __LINE__, iml_rc, iml_error );
#endif
} /* end m_send_udp()                                                  */

/** cleanup of L2TP connection over UDP                                */
static void m_cleanup_l2tp( struct dsd_l2tp_conn_1 *adsp_l2tpc1 ) {
   BOOL       bol1;                         /* working variable        */
   char       *achl_avl_error;              /* error code AVL tree     */
   struct dsd_l2tp_session *adsl_l2tp_session;  /* L2TP connection session */
   struct dsd_l2tp_contr *adsl_l2tp_contr_w1;  /* L2TP control structure */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
#ifdef TRACEHL1
   char       chrl_date_time[ 32 ];         /* for date and time       */
#endif

#ifdef TRACEHL1
   m_get_date_time( chrl_date_time );
   m_hlnew_printf( HLOG_XYZ1, "l%05d xs-gw-l2tp T m_cleanup_l2tp( %p )",
                   __LINE__, chrl_date_time, adsp_l2tpc1 );
#endif
   adsl_l2tp_contr_w1 = adsp_l2tpc1->adsc_l2tp_contr;
   adsl_l2tp_session = adsp_l2tpc1->adsc_l2tp_session;  /* connection  */
   if (adsp_l2tpc1->iec_stl == ied_stl_connected) {  /* L2TP connected */
     m_close_ppp_server_cs( &adsp_l2tpc1->dsc_ppp_se_1 );  /* end of PPP */
   }
   m_ppp_auth_free( &adsp_l2tpc1->dsc_ppp_se_1 );  /* free authentication entry */
   achl_avl_error = NULL;                   /* clear error code AVL tree */
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
   do {                                     /* pseudo-loop             */
     bol1 = m_htree1_avl_search( NULL, &adsl_l2tp_contr_w1->dsc_htree1_avl_cntl,
                                 &dsl_htree1_work, &adsp_l2tpc1->dsc_session_ident.dsc_sort_1 );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "m_htree1_avl_search() failed";  /* error code AVL tree */
       break;                               /* do not continue         */
     }
     if (dsl_htree1_work.adsc_found == NULL) {  /* not found in tree   */
       achl_avl_error = "m_htree1_avl_search() tunnel-id not found in tree";  /* error code AVL tree */
       break;                               /* do not continue         */
     }
     bol1 = m_htree1_avl_delete( NULL, &adsl_l2tp_contr_w1->dsc_htree1_avl_cntl,
                                 &dsl_htree1_work );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "m_htree1_avl_delete() failed";  /* error code AVL tree */
       break;                               /* do not continue         */
     }
   } while (FALSE);
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
   if (achl_avl_error) {                    /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPL2TP01W l%05d m_cleanup_l2tp() tunnel-id %04X error %s",
                     __LINE__, adsp_l2tpc1->dsc_session_ident.usc_tunnel_id, achl_avl_error );
   }
   m_hlnew_printf( HLOG_INFO1, "HWSPL2TP02I l%05d tunnel-id %04X%04X ended packets-dropped: server %d - client %d - target-filter %d.",
                   __LINE__,
                   adsp_l2tpc1->usc_random_tid,
                   adsp_l2tpc1->dsc_session_ident.usc_tunnel_id,
                   adsp_l2tpc1->imc_dropped_packet_server,  /* number of packets dropped by the server */
                   adsp_l2tpc1->imc_dropped_packet_client,  /* number of packets dropped by the client */
                   adsp_l2tpc1->imc_dropped_packet_targfi );  /* number of packets dropped because of target-filter */
   if (adsl_l2tp_session) {                 /* with L2TP connection    */
     m_l2tp_information( adsl_l2tp_session, "l%05d tunnel-id %04X%04X ended packets-dropped: server %d - client %d - target-filter %d.",
                         __LINE__,
                         adsp_l2tpc1->usc_random_tid,
                         adsp_l2tpc1->dsc_session_ident.usc_tunnel_id,
                         adsp_l2tpc1->imc_dropped_packet_server,  /* number of packets dropped by the server */
                         adsp_l2tpc1->imc_dropped_packet_client,  /* number of packets dropped by the client */
                         adsp_l2tpc1->imc_dropped_packet_targfi );  /* number of packets dropped because of target-filter */
   }
   if (adsp_l2tpc1->adsc_ptfa1) {           /* active target filter    */
     free( adsp_l2tpc1->adsc_ptfa1 );       /* free memory             */
   }
   free( adsp_l2tpc1 );                     /* free memory of L2TP connection */
} /* end m_cleanup_l2tp()                                              */

/** check if reconnect timed out                                       */
static void m_check_timeout_reco( struct dsd_l2tp_conn_1 *adsp_l2tpc1 ) {
   int        iml_time;                     /* current time            */

   if (adsp_l2tpc1->adsc_l2tp_session) return;  /* with L2TP connection session */
   if (adsp_l2tpc1->iec_stl == ied_stl_cdn_sent) return;  /* CDN has been sent */
   if (adsp_l2tpc1->iec_stl == ied_stl_shutdown) return;  /* do shutdown */
   if (adsp_l2tpc1->iec_stl == ied_stl_closed) return;  /* session closed */
   iml_time = (int) time( NULL );           /* get current time        */
   if ((iml_time - adsp_l2tpc1->imc_time_tcp_disco) < TIMER_TCP_RECONNECT) return;
   m_hlnew_printf( HLOG_WARN1, "HWSPL2TP01W l%05d tunnel-id %04X%04X timeout - TCP session did not reconnect",
                   __LINE__,
                   adsp_l2tpc1->usc_random_tid,
                   adsp_l2tpc1->dsc_session_ident.usc_tunnel_id );
   m_send_gw_cdn( adsp_l2tpc1 );            /* send CDN                */
   if (adsp_l2tpc1->iec_stl == ied_stl_connected) {  /* L2TP connected */
     m_close_ppp_server_cs( &adsp_l2tpc1->dsc_ppp_se_1 );  /* end of PPP */
   }
   adsp_l2tpc1->iec_stl = ied_stl_cdn_sent;  /* CDN has been sent      */
   return;                                  /* all done                */
} /* end m_check_timeout_reco()                                        */

/** routine called by timer thread when a L2TP connection timed out    */
static void m_timeout_l2tp( struct dsd_timer_ele *adsp_timer_ele ) {
#ifdef TRACEHL1
   char       chrl_date_time[ 32 ];         /* for date and time       */
#endif

#ifdef TRACEHL1
   m_get_date_time( chrl_date_time );
   m_hlnew_printf( HLOG_XYZ1, "l%05d xs-gw-l2tp T %s m_timeout_l2tp( %p )",
                   __LINE__, chrl_date_time, adsp_timer_ele );
#endif
#define ADSL_L2TPC1_G ((struct dsd_l2tp_conn_1 *) ((char *) adsp_timer_ele - offsetof( struct dsd_l2tp_conn_1, dsc_timer )))
   if (ADSL_L2TPC1_G->iec_stl == ied_stl_connected) {  /* connected    */
     if (ADSL_L2TPC1_G->imc_send_hello_l2tp >= NO_L2TP_HELLO) {  /* times sendet L2TP HELLO */
       m_hlnew_printf( HLOG_WARN1, "HWSPL2TP01W l%05d tunnel-id %04X timed out",
                     __LINE__, ADSL_L2TPC1_G->dsc_session_ident.usc_tunnel_id );
       if (ADSL_L2TPC1_G->iec_scp == ied_scp_hpppt1) {  /* protocol HOB-PPP-T1 */
         if (ADSL_L2TPC1_G->adsc_l2tp_session) {  /* L2TP connection session */
           m_hpppt1_send_stop( ADSL_L2TPC1_G->adsc_l2tp_session, FALSE );  /* send STOP to the TCP client */
         }
       } else {                             /* SSTP                    */
// to-do 11.10.08 KB - end L2TP UDP connection
         if (ADSL_L2TPC1_G->adsc_l2tp_session) {  /* L2TP connection session */
           m_l2tp_server_end( ADSL_L2TPC1_G->adsc_l2tp_session, FALSE, "L2TP UDP timed out" );
           ADSL_L2TPC1_G->adsc_l2tp_session = NULL;  /* no more L2TP connection session */
#ifdef OLD01
           ADSL_L2TPC1_G->dsc_ppp_str_1.vpc_handle = NULL;  /* no more handle L2TP or HTUN */
#endif
           ADSL_L2TPC1_G->dsc_ppp_se_1.vpc_handle = NULL;  /* no more handle L2TP or HOB-TUN */
         }
       }
       if (ADSL_L2TPC1_G->adsc_l2tp_session == NULL) {  /* no corresponding TCP client */
         m_cleanup_l2tp( ADSL_L2TPC1_G );   /* do cleanup of L2TP session */
         return;
       }
       ADSL_L2TPC1_G->iec_stl = ied_stl_closed;  /* session closed     */
       ADSL_L2TPC1_G->dsc_timer.ilcwaitmsec = TIMER_L2TP_CLOSED * 1000;  /* seconds L2TP keeps closed */
       m_time_set( &ADSL_L2TPC1_G->dsc_timer, FALSE );  /* set timeout now   */
       return;
     }
     ADSL_L2TPC1_G->imc_send_hello_l2tp++;  /* increment times sendet L2TP HELLO */
     m_send_gw_hello( ADSL_L2TPC1_G );      /* send HELLO / keep-alive */
     ADSL_L2TPC1_G->dsc_timer.ilcwaitmsec = TIMER_L2TP_HELLO * 1000;  /* wait in milliseconds */
     m_time_set( &ADSL_L2TPC1_G->dsc_timer, FALSE );  /* set timeout now   */
     return;                                /* all done                */
   }
   if (ADSL_L2TPC1_G->iec_stl == ied_stl_shutdown) {  /* do shutdown   */
     m_cleanup_l2tp( ADSL_L2TPC1_G );       /* cleanup                 */
     return;                                /* all done                */
   }
   if (ADSL_L2TPC1_G->iec_stl == ied_stl_closed) {  /* session closed  */
     m_cleanup_l2tp( ADSL_L2TPC1_G );       /* cleanup                 */
     return;                                /* all done                */
   }
   if (   (ADSL_L2TPC1_G->iec_stl == ied_stl_wait_sccrp)  /* wait for SCCRP */
       && (ADSL_L2TPC1_G->imc_send_hello_l2tp < NO_L2TP_HELLO)) {  /* times sendet L2TP HELLO */
     ADSL_L2TPC1_G->imc_send_hello_l2tp++;  /* times sendet L2TP HELLO */
     m_time_set( &ADSL_L2TPC1_G->dsc_timer, FALSE );  /* set timeout again */
     m_send_gw_sccrq( ADSL_L2TPC1_G );      /* repeat send SCCRQ       */
     return;                                /* all done                */
   }
   m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d tunnel-id %04X timed out state %d",
                   __LINE__,
                   ADSL_L2TPC1_G->dsc_session_ident.usc_tunnel_id,
                   ADSL_L2TPC1_G->iec_stl );
   if (ADSL_L2TPC1_G->iec_scp == ied_scp_hpppt1) {  /* protocol HOB-PPP-T1 */
     if (ADSL_L2TPC1_G->adsc_l2tp_session) {  /* L2TP connection session */
       m_hpppt1_send_stop( ADSL_L2TPC1_G->adsc_l2tp_session, FALSE );  /* send STOP to the TCP client */
     }
   } else {                                 /* SSTP                    */
// to-do 11.10.08 KB - end L2TP UDP connection
     if (ADSL_L2TPC1_G->adsc_l2tp_session) {  /* L2TP connection session */
       m_l2tp_server_end( ADSL_L2TPC1_G->adsc_l2tp_session, FALSE, "L2TP UDP timed out" );
       ADSL_L2TPC1_G->adsc_l2tp_session = NULL;  /* no more L2TP connection session */
#ifdef OLD01
       ADSL_L2TPC1_G->dsc_ppp_str_1.vpc_handle = NULL;  /* no more handle L2TP or HTUN */
#endif
       ADSL_L2TPC1_G->dsc_ppp_se_1.vpc_handle = NULL;  /* no more handle L2TP or HOB-TUN */
     }
   }
   ADSL_L2TPC1_G->iec_stl = ied_stl_closed;  /* session closed         */
   ADSL_L2TPC1_G->dsc_timer.ilcwaitmsec = TIMER_L2TP_CLOSED * 1000;  /* seconds L2TP keeps closed */
   m_time_set( &ADSL_L2TPC1_G->dsc_timer, FALSE );  /* set timeout now */
#undef ADSL_L2TPC1_G
} /* end m_timeout_l2tp()                                              */

/** compare entries in AVL tree                                        */
static int m_cmp_tunnel_id( void *,
                            struct dsd_htree1_avl_entry *adsp_entry_1,
                            struct dsd_htree1_avl_entry *adsp_entry_2 ) {
#define ADSL_SESSION_IDENT_P1 ((struct dsd_session_ident *) ((char *) adsp_entry_1 - offsetof( struct dsd_session_ident, dsc_sort_1 )))
#define ADSL_SESSION_IDENT_P2 ((struct dsd_session_ident *) ((char *) adsp_entry_2 - offsetof( struct dsd_session_ident, dsc_sort_1 )))
#ifdef XYZ1
   if (ADSL_SESSION_IDENT_P1->usc_tunnel_id < ADSL_SESSION_IDENT_P2->usc_tunnel_id) return -1;
   if (ADSL_SESSION_IDENT_P1->usc_tunnel_id == ADSL_SESSION_IDENT_P2->usc_tunnel_id) return 0;
   return 1;
#endif
   return ADSL_SESSION_IDENT_P1->usc_tunnel_id - ADSL_SESSION_IDENT_P2->usc_tunnel_id;
#undef ADSL_SESSION_IDENT_P1
#undef ADSL_SESSION_IDENT_P2
} /* end m_cmp_tunnel_id()                                             */

/** return a free tunnel id                                            */
static unsigned short int m_get_tunnel_id( struct dsd_l2tp_contr *adsp_l2tp_contr ) {
   while (TRUE) {
     adsp_l2tp_contr->usc_free_tunnel_id++;
     if (adsp_l2tp_contr->usc_free_tunnel_id != 0) return adsp_l2tp_contr->usc_free_tunnel_id;
   }
} /* end m_get_tunnel_id()                                             */

/** callback for receiving on a UDP socket                             */
static void m_cb_udp_recv( struct dsd_udp_multiw_1 *adsp_udp_multiw_1,
                           struct dsd_sdh_control_1 *adsp_sdhc1_rb ) {
   BOOL       bol1;                         /* working variable        */
   BOOL       bol_not_count_packet;         /* do not count packet     */
   int        iml1;                         /* working variable        */
   int        iml_len_rec;                  /* length of record        */
   char       *achl1;                       /* working variable        */
   char       *achl_buf_w1;                 /* buffer for receive      */
   char       *achl_buf_end;                /* end of buffer           */
   char       chl_more;                     /* more bit                */
#ifndef HPPPT1_V21                          /* 03.12.12 KB HOB-PPP-T1 V2.1 */
   char       chl_type;                     /* type of send            */
#endif
#ifdef OLD01
   ied_ppp_frse_rc iel_pppfsr;              /* return code PPP from server */
#endif
   struct dsd_l2tp_contr *adsl_l2tp_contr_w1;  /* L2TP control structure */
   struct dsd_l2tp_conn_1 *adsl_l2tpc1_w1;  /* for L2TP UDP connection */
   struct dsd_l2tp_session *adsl_l2tp_session;  /* L2TP connection session */
   struct dsd_session_ident dsl_session_ident;  /* identification of session */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
#ifdef TRACEHL1
   char       chrl_date_time[ 32 ];         /* for date and time       */
#endif

#ifdef TRACEHL1
   m_get_date_time( chrl_date_time );
   m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01T l%05d xs-gw-l2tp T %s m_cb_udp_recv( %p , %p )",
                   __LINE__, chrl_date_time, adsp_udp_multiw_1, adsp_sdhc1_rb );
#endif
   adsl_l2tp_contr_w1
     = ((struct dsd_l2tp_contr *) ((char *) adsp_udp_multiw_1 - offsetof( struct dsd_l2tp_contr, dsc_udp_multiw_1 )));
#ifndef TRY100302
#define ADSL_REC_B ((struct dsd_sdh_udp_recbuf_1 *) (adsp_sdhc1_rb + 1))
#else
#define ADSL_REC_B ((struct dsd_sdh_udp_recbuf_1 *) ((BOOL *) (adsp_sdhc1_rb + 1) + 1))
#endif
   achl_buf_w1 = (char *) (ADSL_REC_B + 1);  /* start of receive buffer */
   iml_len_rec = ADSL_REC_B->imc_len_data;  /* length of received data */
#undef ADSL_REC_B
   achl_buf_end = achl_buf_w1 + iml_len_rec;  /* end of buffer         */
   achl1 = achl_buf_w1 + 2;                 /* here is tunnel id       */
   if (*achl_buf_w1 & 0X40) {               /* length bit present      */
     iml1 = (*((unsigned char *) achl_buf_w1 + 2 + 0) << 8)
              | *((unsigned char *) achl_buf_w1 + 2 + 1);
     if (iml1 != iml_len_rec) {             /* length value invalid    */
       m_hlnew_printf( HLOG_WARN1, "HWSPL2TP01W l%05d received L2TP data - length in packet %d not equal received %d.",
                       __LINE__, iml1, iml_len_rec );
       m_proc_free( adsp_sdhc1_rb );        /* free buffer again       */
       return;                              /* nothing more to do      */
     }
     achl1 = achl_buf_w1 + 4;               /* here is tunnel id       */
   }
   if ((achl1 + sizeof(unsigned short int)) > achl_buf_end) {  /* packet too short */
     m_hlnew_printf( HLOG_WARN1, "HWSPL2TP01W l%05d received L2TP data - packet too short",
                     __LINE__ );
     m_proc_free( adsp_sdhc1_rb );          /* free buffer again       */
     return;                                /* nothing more to do      */
   }
   /* get L2TP tunnel Id                                               */
   dsl_session_ident.usc_tunnel_id = (*((unsigned char *) achl1 + 0) << 8)
                                       | *((unsigned char *) achl1 + 1);
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
   bol1 = m_htree1_avl_search( NULL, &adsl_l2tp_contr_w1->dsc_htree1_avl_cntl,
                               &dsl_htree1_work, &dsl_session_ident.dsc_sort_1 );
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d received data - m_htree1_avl_search() failed",
                   __LINE__ );
     m_proc_free( adsp_sdhc1_rb );          /* free buffer again       */
     return;                                /* nothing more to do      */
   }
   if (dsl_htree1_work.adsc_found == NULL) {  /* entry not found in tree */
     m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d received data - tunnel id %d not active",
                     __LINE__, dsl_session_ident.usc_tunnel_id );
     m_proc_free( adsp_sdhc1_rb );          /* free buffer again       */
     return;                                /* nothing more to do      */
   }
   adsl_l2tpc1_w1 = ((struct dsd_l2tp_conn_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_l2tp_conn_1, dsc_session_ident.dsc_sort_1 )));
   adsl_l2tp_session = adsl_l2tpc1_w1->adsc_l2tp_session;  /* L2TP connection session */
#ifdef TRACEHL1
// if (adsl_l2tp_session) {                 /* L2TP connection session active */
   {
     char chrh_work1[128];
     chrh_work1[0] = 0;

#ifdef B110904
#define IEC_HPPPT1 *((ied_state_tcp_cl *) &adsl_l2tp_session->imc_state_1)
     if (adsl_l2tp_session) {
       sprintf( chrh_work1, " IEC_HPPPT1=%d boc_cont_send_client=%d",
                IEC_HPPPT1, adsl_l2tp_session->boc_cont_send_client );
     }
#undef IEC_HPPPT1
#endif
     m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01T l%05d recvfrom adsl_l2tp_session=%p length=%d/0X%X%s.",
                     __LINE__, adsl_l2tp_session, iml_len_rec, iml_len_rec, chrh_work1 );
     m_console_out( achl_buf_w1, iml_len_rec );
   }
#endif
   if (adsl_l2tpc1_w1->dsc_timer.vpc_chain_2) {  /* timer already set  */
     m_time_rel( &adsl_l2tpc1_w1->dsc_timer );  /* release timer       */
   }
   adsl_l2tpc1_w1->imc_send_hello_l2tp = 0;  /* times sendet L2TP HELLO */
   adsl_l2tpc1_w1->dsc_timer.ilcwaitmsec = TIMER_L2TP_HELLO * 1000;  /* wait in milliseconds */
   m_time_set( &adsl_l2tpc1_w1->dsc_timer, FALSE );  /* set timeout now */
   if (*((signed char *) achl_buf_w1) < 0) {  /* MSB set               */
     m_server_control_recv( adsl_l2tpc1_w1, achl_buf_w1, iml_len_rec );
     m_check_timeout_reco( adsl_l2tpc1_w1 );  /* check timeout         */
     m_proc_free( adsp_sdhc1_rb );          /* free buffer again       */
     return;                                /* nothing more to do      */
   }
   if (adsl_l2tpc1_w1->iec_stl != ied_stl_connected) {  /* not connected */
     m_hlnew_printf( HLOG_WARN1, "HWSPL2TP01W l%05d received data - tunnel id %d - state invalid - %d.",
                     __LINE__, dsl_session_ident.usc_tunnel_id, adsl_l2tpc1_w1->iec_stl );
     m_proc_free( adsp_sdhc1_rb );          /* free buffer again       */
     return;                                /* nothing more to do      */
   }
   bol1 = FALSE;                            /* session not connected   */
   if (adsl_l2tp_session) {                 /* L2TP connection session active */
     if (adsl_l2tpc1_w1->iec_scp == ied_scp_hpppt1) {  /* protocol HOB-PPP-T1 */
#define IEC_HPPPT1 *((ied_state_tcp_cl *) &adsl_l2tp_session->imc_state_1)
       if (IEC_HPPPT1 == ied_stt_connected) bol1 = TRUE;  /* session is connected */
#undef IEC_HPPPT1
     } else {                                 /* is SSTP                 */
#define IEC_SSTPST *((ied_sstp_state *) &adsl_l2tp_session->imc_state_1)
       if (IEC_SSTPST == ied_sstpst_start_l2tp) bol1 = TRUE;  /* start L2TP */
#undef IEC_SSTPST
     }
   }
#ifdef B110904
   if (   (bol1 == FALSE)                   /* L2TP connection session not active or not connected */
       || (adsl_l2tp_session->boc_cont_send_client == FALSE)) {  /* continue send to client */
     adsl_l2tpc1_w1->imc_dropped_packet_server++;  /* number of packets dropped by the server */
     m_check_timeout_reco( adsl_l2tpc1_w1 );  /* check timeout         */
     m_proc_free( adsp_sdhc1_rb );          /* free buffer again       */
     return;                                /* nothing more to do      */
   }
#endif
   achl1 += 4;                              /* after tunnel id and session id */
   if (*achl_buf_w1 & 0X02) {               /* offset size bit present */
     iml1 = (*((unsigned char *) achl1 + 0 + 0) << 8)
              | *((unsigned char *) achl1 + 0 + 1);
     achl1 += 2 + iml1;                     /* after offset            */
     if (achl1 >= achl_buf_end) {           /* offset too high         */
       m_hlnew_printf( HLOG_WARN1, "HWSPL2TP01W l%05d received L2TP packet tunnel id %d with offset %d - length invalid %d.",
                       __LINE__, dsl_session_ident.usc_tunnel_id, iml1, achl_buf_end - achl1 );
       m_proc_free( adsp_sdhc1_rb );        /* free buffer again       */
       return;                              /* nothing more to do      */
     }
   }
   iml_len_rec = achl_buf_end - achl1;      /* length of record        */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-l2tp m_cb_udp_recv() ...chrc_ppp_auth[0] = %02X ied_pppa_pass_thru=%d.",
                   __LINE__,
                   (unsigned char) adsl_l2tpc1_w1->dsc_ppp_se_1.chrc_ppp_auth[0],
                   ied_pppa_pass_thru );
#endif
   if (adsl_l2tpc1_w1->dsc_ppp_se_1.chrc_ppp_auth[0] == (unsigned char) ied_pppa_pass_thru) goto p_recv_20;  /* pass-thru */
#ifndef TRY_090424
#ifndef B150509
// 0X21 = IPv4
// 0X57 = IPv6
#endif
   if (*achl1 != 0X21) {                    /* is not IP packet        */
#ifdef OLD01
     iel_pppfsr = m_ppp_from_server( adsl_l2tpc1_w1, achl1, &iml_len_rec );
     if (iel_pppfsr != ied_pppfsr_send) {   /* do not send packet to client */
       m_proc_free( adsp_sdhc1_rb );        /* free buffer again       */
       return;                              /* nothing more to do      */
     }
     achl_buf_end = achl1 + iml_len_rec;
#endif
     m_recv_ppp_client_cs( &adsl_l2tpc1_w1->dsc_ppp_cl_1, achl1, iml_len_rec );
     m_proc_free( adsp_sdhc1_rb );          /* free buffer again       */
     return;                                /* nothing more to do      */
   }
#ifndef B150509
#endif
   if ((adsl_l2tpc1_w1->dsc_ppp_se_1.imc_options & D_PPP_OPT_HS_COMPL) == 0) {  /* handshake not complete */
     m_l2tp_warning( adsl_l2tp_session, "l%05d m_cb_udp_recv() received PPP packet but handshake not complete - ignored",
                     __LINE__ );
     adsl_l2tpc1_w1->imc_dropped_packet_server++;  /* number of packets dropped by the server */
     m_proc_free( adsp_sdhc1_rb );          /* free buffer again       */
     return;                                /* nothing more to do      */
   }
#endif

   p_recv_20:                               /* process data received   */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-l2tp m_cb_udp_recv() p_recv_20",
                   __LINE__ );
#endif
   bol_not_count_packet = FALSE;            /* do not count packet     */
   if (adsl_l2tpc1_w1->iec_scp == ied_scp_hpppt1) {  /* protocol HOB-PPP-T1 */
#ifndef HPPPT1_V21                          /* 03.12.12 KB HOB-PPP-T1 V2.1 */
     chl_type = '1';                        /* type of send            */
     if (*((unsigned char *) achl1) == 0X21) {  /* IPV4 received       */
       chl_type = '4';                      /* type of send IPV4       */
       achl1++;                             /* remove control character PPP */
       iml_len_rec--;                       /* decrement length        */
       if (   (adsl_l2tp_session)           /* L2TP session connected  */
           && (adsl_l2tp_session->boc_not_drop_tcp_packet)  /* do not drop TCP packets */
           && (*(achl1 + D_POS_IPV4_H_PROT) == IPPROTO_TCP)) {  /* protocol TCP from IP header */
         bol_not_count_packet = TRUE;       /* do not count packet     */
       }
     } else if (*((unsigned char *) achl1) == 0X57) {  /* IPV6 received */
       chl_type = '6';                      /* type of send IPV6       */
       achl1++;                             /* remove control character PPP */
       iml_len_rec--;                       /* decrement length        */
       if (   (adsl_l2tp_session)           /* L2TP session connected  */
           && (adsl_l2tp_session->boc_not_drop_tcp_packet)  /* do not drop TCP packets */
           && (*(achl1 + D_POS_IPV6_H_NEXT) == IPPROTO_TCP)) {  /* protocol TCP from IP header */
         bol_not_count_packet = TRUE;       /* do not count packet     */
       }
     } else {                               /* other packet            */
       bol_not_count_packet = TRUE;         /* do not count packet     */
     }
     *(--achl1) = chl_type;                 /* source UDP              */
     iml1 = iml_len_rec + 1;                /* get length              */
     chl_more = 0;                          /* not yet more bit        */
     while (TRUE) {                         /* loop output length NHASN */
       *(--achl1) = (unsigned char) (iml1 & 0X7F) | chl_more;
       iml1 >>= 7;                          /* shift bits              */
       if (iml1 == 0) break;                /* end of output           */
       chl_more = (unsigned char) 0X80;     /* set more bit            */
     }
#endif
#ifdef HPPPT1_V21                           /* 03.12.12 KB HOB-PPP-T1 V2.1 */
     if (*((unsigned char *) achl1) == 0X21) {  /* IPV4 received       */
       achl1++;                             /* do not send first byte PPP */
       iml_len_rec--;                       /* decrement length        */
       if ((*achl1 & 0XF0) != 0X40) {       /* not IPV4 packet         */
         m_l2tp_warning( adsl_l2tp_session, "l%05d m_cb_udp_recv() invalid packet IPV4 received - 0X%02X.",
                         __LINE__, *((unsigned char *) achl1) );
         adsl_l2tpc1_w1->imc_dropped_packet_server++;  /* number of packets dropped by the server */
         m_proc_free( adsp_sdhc1_rb );      /* free buffer again       */
         return;                            /* nothing more to do      */
       }
       if ((*achl1 & 0X0F) < 5) {           /* IPV4 header too short   */
         m_l2tp_warning( adsl_l2tp_session, "l%05d m_cb_udp_recv() received packet IPV4 header too short - 0X%02X.",
                         __LINE__, *((unsigned char *) achl1) );
         adsl_l2tpc1_w1->imc_dropped_packet_server++;  /* number of packets dropped by the server */
         m_proc_free( adsp_sdhc1_rb );      /* free buffer again       */
         return;                            /* nothing more to do      */
       }
       if (iml_len_rec <= (5 * 4)) {        /* length too short      */
         m_l2tp_warning( adsl_l2tp_session, "l%05d m_cb_udp_recv() received packet IPV4 length %d too short",
                         __LINE__, iml_len_rec );
         adsl_l2tpc1_w1->imc_dropped_packet_server++;  /* number of packets dropped by the server */
         m_proc_free( adsp_sdhc1_rb );      /* free buffer again       */
         return;                            /* nothing more to do      */
       }
       iml1 = (*((unsigned char *) achl1 + 2 + 0) << 8)
                | *((unsigned char *) achl1 + 2 + 1);
       if (iml1 != iml_len_rec) {           /* length invalid          */
         m_l2tp_warning( adsl_l2tp_session, "l%05d m_cb_udp_recv() received packet IPV4 length %d - %d does not match",
                         __LINE__, iml1, iml_len_rec );
         adsl_l2tpc1_w1->imc_dropped_packet_server++;  /* number of packets dropped by the server */
         m_proc_free( adsp_sdhc1_rb );      /* free buffer again       */
         return;                            /* nothing more to do      */
       }
       if (   (adsl_l2tp_session)           /* L2TP session connected  */
           && (adsl_l2tp_session->boc_not_drop_tcp_packet)  /* do not drop TCP packets */
           && (*(achl1 + D_POS_IPV4_H_PROT) == IPPROTO_TCP)) {  /* protocol TCP from IP header */
         bol_not_count_packet = TRUE;       /* do not count packet     */
       }
     } else if (*((unsigned char *) achl1) == 0X57) {  /* IPV6 received */
       achl1++;                               /* do not send first byte PPP */
       iml_len_rec--;                       /* decrement length        */
       if ((*achl1 & 0XF0) != 0X60) {         /* not IPV6 packet         */
         m_l2tp_warning( adsl_l2tp_session, "l%05d m_cb_udp_recv() invalid packet IPV6 received - 0X%02X.",
                         __LINE__, *((unsigned char *) achl1) );
         adsl_l2tpc1_w1->imc_dropped_packet_server++;  /* number of packets dropped by the server */
         m_proc_free( adsp_sdhc1_rb );      /* free buffer again       */
         return;                            /* nothing more to do      */
       }
       if (iml_len_rec <= D_LEN_HEADER_IPV6) {  /* length too short    */
         m_l2tp_warning( adsl_l2tp_session, "l%05d m_cb_udp_recv() received packet IPV6 length %d too short",
                         __LINE__, iml_len_rec );
         adsl_l2tpc1_w1->imc_dropped_packet_server++;  /* number of packets dropped by the server */
         m_proc_free( adsp_sdhc1_rb );      /* free buffer again       */
         return;                            /* nothing more to do      */
       }
       iml1 = (*((unsigned char *) achl1 + 4 + 0) << 8)
                | *((unsigned char *) achl1 + 4 + 1);
       if ((iml1 + D_LEN_HEADER_IPV6) != iml_len_rec) {  /* length invalid */
         m_l2tp_warning( adsl_l2tp_session, "l%05d m_cb_udp_recv() received packet IPV6 length 40 + %d - %d does not match",
                         __LINE__, iml1, iml_len_rec );
         adsl_l2tpc1_w1->imc_dropped_packet_server++;  /* number of packets dropped by the server */
         m_proc_free( adsp_sdhc1_rb );      /* free buffer again       */
         return;                            /* nothing more to do      */
       }
       if (   (adsl_l2tp_session)           /* L2TP session connected  */
           && (adsl_l2tp_session->boc_not_drop_tcp_packet)  /* do not drop TCP packets */
           && (*(achl1 + D_POS_IPV6_H_NEXT) == IPPROTO_TCP)) {  /* protocol TCP from IP header */
         bol_not_count_packet = TRUE;       /* do not count packet     */
       }
     } else {                               /* other PPP data          */
       bol_not_count_packet = TRUE;         /* do not count packet     */
       iml1 = iml_len_rec;                  /* get length              */
       chl_more = 0;                        /* not yet more bit        */
       while (TRUE) {                       /* loop output length NHASN */
         *(--achl1) = (unsigned char) (iml1 & 0X7F) | chl_more;
         iml1 >>= 7;                        /* shift bits              */
         if (iml1 == 0) break;              /* end of output           */
         chl_more = (unsigned char) 0X80;   /* set more bit            */
       }
       *(--achl1) = '1';                    /* source UDP              */
     }
#endif
   } else {                                 /* protocol SSTP           */
     iml1 = 4 + iml_len_rec;                /* get length              */
     *(--achl1) = (unsigned char) iml1;
     *(--achl1) = (unsigned char) (iml1 >> 8);
     *(--achl1) = (unsigned char) SSTP_DATA_MSG;
     *(--achl1) = (unsigned char) (SSTP_DATA_MSG >> 8);
     if (*((unsigned char *) achl1) == 0X21) {  /* IPV4 received       */
       if (   (adsl_l2tp_session)           /* L2TP session connected  */
           && (adsl_l2tp_session->boc_not_drop_tcp_packet)  /* do not drop TCP packets */
           && (*(achl1 + 1 + D_POS_IPV4_H_PROT) == IPPROTO_TCP)) {  /* protocol TCP from IP header */
         bol_not_count_packet = TRUE;       /* do not count packet     */
       }
     } else if (*((unsigned char *) achl1) == 0X57) {  /* IPV6 received */
       if (   (adsl_l2tp_session)           /* L2TP session connected  */
           && (adsl_l2tp_session->boc_not_drop_tcp_packet)  /* do not drop TCP packets */
           && (*(achl1 + 1 + D_POS_IPV6_H_NEXT) == IPPROTO_TCP)) {  /* protocol TCP from IP header */
         bol_not_count_packet = TRUE;       /* do not count packet     */
       }
     } else {                               /* other packet            */
       bol_not_count_packet = TRUE;         /* do not count packet     */
     }
   }
   if (   (bol_not_count_packet == FALSE)   /* do count packet         */
       && (bol1)) {                         /* packet should be sent   */
     if (adsl_l2tp_session->imc_on_the_fly_packets_client  /* number of packets on the fly to the client */
           >= MAX_PPP_ON_THE_FLY_PACKETS_CLIENT) {
       bol1 = FALSE;                        /* do not send packet      */
     } else {                               /* count this packet       */
       adsl_l2tp_session->imc_on_the_fly_packets_client++;  /* number of packets on the fly to the client */
     }
   }
   if (bol1 == FALSE) {                     /* L2TP connection session not active or not connected */
     adsl_l2tpc1_w1->imc_dropped_packet_server++;  /* number of packets dropped by the server */
     m_check_timeout_reco( adsl_l2tpc1_w1 );  /* check timeout         */
     m_proc_free( adsp_sdhc1_rb );          /* free buffer again       */
     return;                                /* nothing more to do      */
   }
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) ((char *) adsp_sdhc1_rb + LEN_TCP_RECV - sizeof(struct dsd_gather_i_1)))
   ADSL_GAI1_G->adsc_next = NULL;           /* clear chain             */
   ADSL_GAI1_G->achc_ginp_cur = achl1;
   ADSL_GAI1_G->achc_ginp_end = achl_buf_end;
   adsp_sdhc1_rb->adsc_gather_i_1_i = ADSL_GAI1_G;  /* gather input data */
#undef ADSL_GAI1_G
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-l2tp m_cb_udp_recv() call m_l2tp_to_client()",
                   __LINE__ );
#endif
   m_l2tp_to_client( adsl_l2tp_session, adsp_sdhc1_rb, FALSE );
} /* end m_cb_udp_recv()                                               */

#ifdef B120508
extern "C" void m_radqu_ret_callback( void * vpp_radqu_ppp, ied_radius_resp iep_radius_resp ) {
   struct dsd_l2tp_conn_1 *adsl_l2tpc1;     /* for L2TP UDP connection */
// struct dsd_l2tp_session *adsl_l2tp_session;  /* L2TP connection session */
   ied_ppp_auth_rc iel_ppp_auth_rc;         /* PPP authentication return code */
#ifdef OLD01
   struct dsd_ppp_str_1 *adsl_ppps1;
   char       *achl_out;                    /* copy to output area     */
   struct dsd_buf_vector_ele dsl_buf_ve;    /* vector with data to send */
#endif
#ifdef TRACEHL1
   char       chrl_date_time[ 32 ];         /* for date and time       */
#endif

#ifdef TRACEHL1
   m_get_date_time( chrl_date_time );
   m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01T l%05d xs-gw-l2tp T %s m_radqu_ret_callback( %p , %d )",
                   __LINE__, chrl_date_time, vpp_radqu_ppp, iep_radius_resp );
#endif
   adsl_l2tpc1
     = (struct dsd_l2tp_conn_1 *) ((char *) vpp_radqu_ppp - offsetof( struct dsd_l2tp_conn_1, dsc_ppp_se_1 ));
   switch (iep_radius_resp) {               /* response from radius server */
//   case ied_rar_invalid:                  /* parameter is invalid    */
     case ied_rar_access_accept:            /* accept sign on          */
       m_ppp_auth_free( &adsl_l2tpc1->dsc_ppp_se_1 );  /* free the entry */
       iel_ppp_auth_rc = ied_pppar_ok;      /* authentication was checked O.K. */
       break;
     case ied_rar_access_reject:            /* reject access           */
       iel_ppp_auth_rc = ied_pppar_auth_failed;  /* authentication failed */
       break;
//   case ied_rar_challenge:                /* request challenge       */
//   case ied_rar_error:                    /* error, no valid response */
     default:
       iel_ppp_auth_rc = ied_pppar_misc;    /* miscellaneous           */
       break;
   }
// adsl_l2tp_session = adsl_l2tpc1->adsc_l2tp_session;  /* L2TP connection session */
   m_auth_compl_ppp_server( &adsl_l2tpc1->dsc_ppp_se_1, iel_ppp_auth_rc );
} /* end m_radqu_ret_callback()                                        */
#endif

/** callback PPP server authentication                                 */
extern "C" void m_ppp_se_auth_ret( struct dsd_ppp_server_1 *adsp_ppp_se_1, ied_chid_ret iep_chid_ret ) {
// struct dsd_l2tp_conn_1 *adsl_l2tpc1;     /* for L2TP UDP connection */
// struct dsd_l2tp_session *adsl_l2tp_session;  /* L2TP connection session */
   ied_ppp_auth_rc iel_ppp_auth_rc;         /* PPP authentication return code */
#ifdef TRACEHL1
   char       chrl_date_time[ 32 ];         /* for date and time       */
#endif

#ifdef TRACEHL1
   m_get_date_time( chrl_date_time );
   m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01T l%05d xs-gw-l2tp T %s m_ppp_se_auth_ret( %p , %d )",
                   __LINE__, chrl_date_time, adsp_ppp_se_1, iep_chid_ret );
#endif
// adsl_l2tpc1
//   = (struct dsd_l2tp_conn_1 *) ((char *) adsp_ppp_se_1 - offsetof( struct dsd_l2tp_conn_1, dsc_ppp_se_1 ));
   switch (iep_chid_ret) {                  /* check ident return code */
     case ied_chid_ok:                      /* userid and password valid */
       iel_ppp_auth_rc = ied_pppar_ok;      /* authentication was checked O.K. */
       break;
#ifndef B140315
     case ied_chid_cont:                    /* not yet complete, continue processing */
       iel_ppp_auth_rc = ied_pppar_cont;    /* authentication continue processing */
       break;
#endif
     case ied_chid_inv_userid:              /* userid invalid - not known in system */
       iel_ppp_auth_rc = ied_pppar_userid_inv;  /* userid invalid      */
       break;
     case ied_chid_inv_password:            /* password invalid - does not match */
       iel_ppp_auth_rc = ied_pppar_password_inv;  /* password invalid  */
       break;
     default:
       iel_ppp_auth_rc = ied_pppar_misc;    /* miscellaneous           */
       break;
   }
// adsl_l2tp_session = adsl_l2tpc1->adsc_l2tp_session;  /* L2TP connection session */
// m_auth_compl_ppp_server( &adsl_l2tpc1->dsc_ppp_se_1, iel_ppp_auth_rc );
   m_auth_compl_ppp_server( adsp_ppp_se_1, iel_ppp_auth_rc );
} /* end m_ppp_se_auth_ret()                                           */

/** PPP server sends packet to the client                              */
static void m_ppp_se_send( struct dsd_ppp_server_1 *adsp_ppp_se_1,
                           struct dsd_buf_vector_ele *adsp_buf_ve ) {
   int        iml1;                         /* working variable        */
   char       chl_prot;                     /* protocol used           */
   char       chl_more;                     /* more bit                */
   char       *achl_out;                    /* copy to output area     */
   struct dsd_l2tp_session *adsl_l2tp_session;  /* L2TP connection session */
   struct dsd_l2tp_conn_1 *adsl_l2tpc1;     /* for L2TP UDP connection */
   struct dsd_ppp_auth_1 *adsl_auths_p1;    /* for authentication      */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working variable       */
   char       chrl_work_1[ 1024 ];          /* work area               */
#ifdef TRACEHL1
   char       chrl_date_time[ 32 ];         /* for date and time       */
#endif

#ifdef TRACEHL1
   m_get_date_time( chrl_date_time );
   m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01T l%05d xs-gw-l2tp T %s m_ppp_se_send( %p , %p )",
                   __LINE__, chrl_date_time, adsp_ppp_se_1, adsp_buf_ve );
#endif
   adsl_l2tpc1
     = (struct dsd_l2tp_conn_1 *) ((char *) adsp_ppp_se_1 - offsetof( struct dsd_l2tp_conn_1, dsc_ppp_se_1 ));
   adsl_l2tp_session = adsl_l2tpc1->adsc_l2tp_session;  /* L2TP connection session */
   if (adsl_l2tp_session == NULL) {         /* no more L2TP session    */
     if (adsp_buf_ve->ac_handle) m_proc_free( adsp_buf_ve->ac_handle );
     return;                                /* all done                */
   }
   achl_out = adsp_buf_ve->achc_data;       /* here is start output    */
   if (adsl_l2tp_session->iec_scp == ied_scp_hpppt1) {  /* protocol HOB-PPP-T1 */
#ifndef HPPPT1_V21                          /* 03.12.12 KB HOB-PPP-T1 V2.1 */
     chl_prot = '1';                        /* protocol used           */
     iml1 = adsp_buf_ve->imc_len_data + 1;  /* get length              */
     if (((unsigned char) *achl_out) == 0X21) {  /* is IPV4            */
       achl_out++;                          /* start after PPP control */
       iml1--;                              /* decrement length        */
       chl_prot = '4';                      /* protocol used           */
     } else if (((unsigned char) *achl_out) == 0X57) {  /* is IPV6     */
       achl_out++;                          /* start after PPP control */
       iml1--;                              /* decrement length        */
       chl_prot = '6';                      /* protocol used           */
     }
     *(--achl_out) = chl_prot;              /* source UDP              */
     chl_more = 0;                          /* not yet more bit        */
     while (TRUE) {                         /* loop output length NHASN */
       *(--achl_out) = (unsigned char) (iml1 & 0X7F) | chl_more;
       iml1 >>= 7;                          /* shift bits              */
       if (iml1 == 0) break;                /* end of output           */
       chl_more = (unsigned char) 0X80;     /* set more bit            */
     }
#endif
#ifdef HPPPT1_V21                           /* 03.12.12 KB HOB-PPP-T1 V2.1 */
     do {                                   /* pseudo-loop             */
       if (   (((unsigned char) *achl_out) == 0X21)  /* is IPv4        */
           || (((unsigned char) *achl_out) == 0X57)) {  /* is IPv6     */
         achl_out++;                        /* start after PPP control */
// to-do 27.05.15 KB - check if IP header correct
         break;                             /* nothing more to do      */
       }
       iml1 = adsp_buf_ve->imc_len_data;    /* get length              */
       chl_more = 0;                        /* not yet more bit        */
       while (TRUE) {                       /* loop output length NHASN */
         *(--achl_out) = (unsigned char) (iml1 & 0X7F) | chl_more;
         iml1 >>= 7;                        /* shift bits              */
         if (iml1 == 0) break;              /* end of output           */
         chl_more = (unsigned char) 0X80;   /* set more bit            */
       }
       *(--achl_out) = '1';                 /* type PPP                */
     } while (FALSE);
#endif
   } else {                                 /* protocol SSTP           */
     iml1 = 4 + adsp_buf_ve->imc_len_data;  /* get length              */
     *(--achl_out) = (unsigned char) iml1;
     *(--achl_out) = (unsigned char) (iml1 >> 8);
     *(--achl_out) = (unsigned char) SSTP_DATA_MSG;
     *(--achl_out) = (unsigned char) (SSTP_DATA_MSG >> 8);
   }
#define ADSL_SDHC1_G ((struct dsd_sdh_control_1 *) adsp_buf_ve->ac_handle)
   memset( ADSL_SDHC1_G, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) (ADSL_SDHC1_G + 1))
// ADSL_GAI1_G->adsc_next = NULL;           /* clear chain             */
   ADSL_GAI1_G->achc_ginp_cur = achl_out;   /* start of output area    */
   ADSL_GAI1_G->achc_ginp_end = adsp_buf_ve->achc_data + adsp_buf_ve->imc_len_data;
   ADSL_SDHC1_G->adsc_gather_i_1_i = ADSL_GAI1_G;  /* gather input data */
#undef ADSL_GAI1_G

   p_send_00:                               /* send data               */
   m_l2tp_to_client( adsl_l2tp_session, ADSL_SDHC1_G, FALSE );
#undef ADSL_SDHC1_G
} /* end m_ppp_se_send()                                               */

/** PPP server do authentication                                       */
static void m_ppp_se_auth_1( struct dsd_ppp_server_1 *adsp_ppp_se_1 ) {
#ifdef OLD01
   struct dsd_l2tp_conn_1 *adsl_l2tpc1;     /* for L2TP UDP connection */
   struct dsd_l2tp_session *adsl_l2tp_session;  /* L2TP connection session */
#endif
#ifdef TRACEHL1
   char       chrl_date_time[ 32 ];         /* for date and time       */
#endif

#ifdef TRACEHL1
   m_get_date_time( chrl_date_time );
   m_hlnew_printf( HLOG_TRACE1, "HWSPL2TP01T l%05d xs-gw-l2tp T %s m_ppp_se_auth_1( %p )",
                   __LINE__, chrl_date_time, adsp_ppp_se_1 );
#endif
#ifdef OLD01
   adsl_l2tpc1
     = (struct dsd_l2tp_conn_1 *) ((char *) adsp_ppp_se_1 - offsetof( struct dsd_l2tp_conn_1, dsc_ppp_se_1 ));
   adsl_l2tpc1->dsc_ppp_str_1.ac_auth_1 = adsp_ppp_se_1->adsc_ppp_auth_1;  /* authentication parameters */
   m_ppp_auth_1( &adsl_l2tpc1->dsc_ppp_str_1 );  /* call authentication routine */
#endif
#ifdef OLD01
   adsl_l2tp_session = adsl_l2tpc1->adsc_l2tp_session;  /* L2TP connection session */
   if (adsl_l2tp_session) {                 /* connected with session  */
     m_l2tp_warning( adsl_l2tp_session, "PPP server %s", achp_msg );
   } else {
     m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d xs-gw-l2tp W L2TP PPP server %s",
                     __LINE__, achp_msg );
   }
#endif
   m_ppp_auth_1( adsp_ppp_se_1 );           /* call authentication routine */
} /* end m_ppp_se_auth_1()                                             */

/** PPP server get INETA client                                        */
static char * m_ppp_se_get_ineta_client( struct dsd_ppp_server_1 *adsp_ppp_se_1 ) {
   char       *achl1;                       /* working variable        */
   struct dsd_l2tp_conn_1 *adsl_l2tpc1;     /* for L2TP UDP connection */
   struct dsd_l2tp_session *adsl_l2tp_session;  /* L2TP connection session */

#ifdef B120406
   adsl_l2tpc1
     = (struct dsd_l2tp_conn_1 *) ((char *) adsp_ppp_se_1 - offsetof( struct dsd_l2tp_conn_1, dsc_ppp_se_1 ));
   adsl_l2tp_session = adsl_l2tpc1->adsc_l2tp_session;  /* L2TP connection session */
   if (adsl_l2tp_session == NULL) return NULL;  /* currently no session */
   achl1 = m_l2tp_get_client_ineta( adsl_l2tp_session );
   if (*((UNSIG_MED *) achl1)) return achl1;  /* INETA configured      */
#endif
   return NULL;                             /* INETA not configured    */
} /* end m_ppp_se_get_ineta_client()                                   */

/** PPP server handshake is complete                                   */
static void m_ppp_se_hs_compl( struct dsd_ppp_server_1 *adsp_ppp_se_1 ) {
   int        iml_trace_level;              /* trace_level             */
   int        iml_sno;                      /* WSP session number      */
   struct dsd_l2tp_conn_1 *adsl_l2tpc1;     /* for L2TP UDP connection */
   struct dsd_l2tp_session *adsl_l2tp_session;  /* L2TP connection session */
   struct dsd_targfi_1 *adsl_targfi_w1;     /* working variable        */

   adsl_l2tpc1
     = (struct dsd_l2tp_conn_1 *) ((char *) adsp_ppp_se_1 - offsetof( struct dsd_l2tp_conn_1, dsc_ppp_se_1 ));
   adsl_l2tp_session = adsl_l2tpc1->adsc_l2tp_session;  /* L2TP connection session */
   if (adsl_l2tp_session == NULL) return;   /* currently no session    */
#ifndef B150509
#endif
   if (adsl_l2tp_session->adsc_ptfa1) free( adsl_l2tp_session->adsc_ptfa1 );
#ifdef B160503
   adsl_targfi_w1 = m_get_l2tp_targfi( adsl_l2tp_session );
#endif
#ifndef B160503
   adsl_targfi_w1 = m_get_l2tp_targfi( adsl_l2tp_session, &iml_trace_level, &iml_sno );
#endif
   if (adsl_targfi_w1 == NULL) {            /* no target-filter set    */
     adsl_l2tp_session->adsc_ptfa1 = NULL;  /* no active target filter */
     return;
   }
#ifdef B160503
   adsl_l2tp_session->adsc_ptfa1 = m_create_ppp_targfi( adsl_targfi_w1 );  /* active target filter */
#endif
#ifndef B160503
   adsl_l2tp_session->adsc_ptfa1 = m_create_ppp_targfi( adsl_targfi_w1, iml_trace_level, iml_sno );  /* active target filter */
#endif
} /* end m_ppp_se_hs_complete()                                        */

/** PPP server abend with message                                      */
static void m_ppp_se_abend( struct dsd_ppp_server_1 *adsp_ppp_se_1, char *achp_msg ) {
// to-do 06.05.12 KB - last parameter va_list
   struct dsd_l2tp_conn_1 *adsl_l2tpc1;     /* for L2TP UDP connection */
   struct dsd_l2tp_session *adsl_l2tp_session;  /* L2TP connection session */
#ifdef TRACEHL1
   char       chrl_date_time[ 32 ];         /* for date and time       */
#endif

#ifdef TRACEHL1
   m_get_date_time( chrl_date_time );
   m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01T l%05d xs-gw-l2tp T %s m_ppp_se_abend( %p , %p )",
                   __LINE__, chrl_date_time, adsp_ppp_se_1, achp_msg );
#endif
   adsl_l2tpc1
     = (struct dsd_l2tp_conn_1 *) ((char *) adsp_ppp_se_1 - offsetof( struct dsd_l2tp_conn_1, dsc_ppp_se_1 ));
   adsl_l2tp_session = adsl_l2tpc1->adsc_l2tp_session;  /* L2TP connection session */
   if (adsl_l2tp_session) {                 /* connected with session  */
     m_l2tp_warning( adsl_l2tp_session, "PPP server %s", achp_msg );
   } else {
     m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d xs-gw-l2tp W L2TP PPP server %s",
                     __LINE__, achp_msg );
   }
   if (adsl_l2tpc1->iec_stl == ied_stl_connected) {  /* L2TP connected */
     m_close_ppp_server_cs( &adsl_l2tpc1->dsc_ppp_se_1 );  /* end of PPP */
     m_send_gw_cdn( adsl_l2tpc1 );          /* send CDN                */
     adsl_l2tpc1->iec_stl = ied_stl_cdn_sent;  /* CDN has been sent    */
   }
   if (adsl_l2tpc1->adsc_l2tp_session) {    /* L2TP connection session */
     m_l2tp_server_end( adsl_l2tpc1->adsc_l2tp_session, FALSE, "L2TP PPP server abend" );
     adsl_l2tpc1->adsc_l2tp_session = NULL;  /* no more L2TP connection session */
#ifdef OLD01
     adsl_l2tpc1->dsc_ppp_str_1.vpc_handle = NULL;  /* no more handle L2TP or HTUN */
#endif
     adsl_l2tpc1->dsc_ppp_se_1.vpc_handle = NULL;  /* no more handle L2TP or HOB-TUN */
   }
} /* end m_ppp_se_abend()                                              */

/** PPP client sends packet to the server                              */
static void m_ppp_cl_send( struct dsd_ppp_client_1 *adsp_ppp_cl_1,
                           char *achp_send, int imp_len_send ) {
   int        iml_len_packet;               /* length of packet        */
   int        iml_rc;                       /* return code             */
#ifndef B111022
   int        iml_error;                    /* returned error          */
#endif
   char       *achl_send;                   /* output area to be sent  */
   struct dsd_l2tp_conn_1 *adsl_l2tpc1;     /* for L2TP UDP connection */
   struct dsd_l2tp_session *adsl_l2tp_session;  /* L2TP connection session */
#ifdef TRACEHL1
   char       chrl_date_time[ 32 ];         /* for date and time       */
#endif

#ifdef TRACEHL1
   m_get_date_time( chrl_date_time );
   m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01T l%05d xs-gw-l2tp T %s m_ppp_cl_send( %p , %p , %d )",
                   __LINE__, chrl_date_time, adsp_ppp_cl_1, achp_send, imp_len_send );
#endif
   adsl_l2tpc1
     = (struct dsd_l2tp_conn_1 *) ((char *) adsp_ppp_cl_1 - offsetof( struct dsd_l2tp_conn_1, dsc_ppp_cl_1 ));
   achl_send = achp_send - D_LEN_L2TP_HEADER;  /* subtract length of L2TP header */
   iml_len_packet = D_LEN_L2TP_HEADER + imp_len_send;  /* length of packet */
   *(achl_send) = (unsigned char) 0X40;  /* data packet         */
   *(achl_send + 1) = (unsigned char) 0X02;  /* version         */
   *(achl_send + 2 + 0) = (unsigned char) (iml_len_packet >> 8);  /* length of packet */
   *(achl_send + 2 + 1) = (unsigned char) iml_len_packet;  /* length of packet */
   *((unsigned char *) achl_send + 4 + 0) = (unsigned char) (adsl_l2tpc1->usc_assgn_t_id >> 8);
   *((unsigned char *) achl_send + 4 + 1) = (unsigned char) adsl_l2tpc1->usc_assgn_t_id;
   *((unsigned char *) achl_send + 6 + 0) = (unsigned char) (adsl_l2tpc1->usc_assgn_s_id >> 8);
   *((unsigned char *) achl_send + 6 + 1) = (unsigned char) adsl_l2tpc1->usc_assgn_s_id;
#ifdef TRACEHL1
   m_console_out( achl_send, iml_len_packet );
#endif
#ifdef B111022
   iml_rc = sendto( adsl_l2tpc1->adsc_l2tp_contr->dsc_udp_multiw_1.imc_socket,
                    achl_send, iml_len_packet, 0,
                    (struct sockaddr *) &adsl_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->dsc_soa_target,
                    adsl_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->imc_len_soa_target );
#else
   iml_rc = m_udp_sendto( &adsl_l2tpc1->adsc_l2tp_contr->dsc_udp_multiw_1,
                          achl_send, iml_len_packet,
                          (struct sockaddr *) &adsl_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->dsc_soa_target,
                          adsl_l2tpc1->adsc_l2tp_contr->adsc_udp_param_1->imc_len_soa_target,
                          &iml_error );
#endif
   if (iml_rc == iml_len_packet) return;    /* sendto succeeded        */
   /* error occured                                                    */
   adsl_l2tp_session = adsl_l2tpc1->adsc_l2tp_session;  /* L2TP connection session */
   if (adsl_l2tp_session) {                 /* connected with session  */
#ifdef B111022
     m_l2tp_warning( adsl_l2tp_session, "l%05d m_ppp_cl_send() sendto L2TP UDP PPP failed with code %d/%d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
#else
     m_l2tp_warning( adsl_l2tp_session, "l%05d m_ppp_cl_send() sendto L2TP UDP PPP failed with code %d/%d.",
                     __LINE__, iml_rc, iml_error );
#endif
     return;
   }
#ifdef B111022
   m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d xs-gw-l2tp W m_ppp_cl_send() sendto L2TP UDP PPP failed with code %d/%d.",
                   __LINE__, iml_rc, D_TCP_ERROR );
#else
   m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d xs-gw-l2tp W m_ppp_cl_send() sendto L2TP UDP PPP failed with code %d/%d.",
                   __LINE__, iml_rc, iml_error );
#endif
} /* end m_ppp_cl_send()                                               */

/** PPP client abend with message                                      */
static void m_ppp_cl_abend( struct dsd_ppp_client_1 *adsp_ppp_cl_1, char *achp_msg ) {
// to-do 06.05.12 KB - last parameter va_list
   struct dsd_l2tp_conn_1 *adsl_l2tpc1;     /* for L2TP UDP connection */
   struct dsd_l2tp_session *adsl_l2tp_session;  /* L2TP connection session */
#ifdef TRACEHL1
   char       chrl_date_time[ 32 ];         /* for date and time       */
#endif

#ifdef TRACEHL1
   m_get_date_time( chrl_date_time );
   m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01T l%05d xs-gw-l2tp T %s m_ppp_cl_abend( %p , %p )",
                   __LINE__, chrl_date_time, adsp_ppp_cl_1, achp_msg );
#endif
   adsl_l2tpc1
     = (struct dsd_l2tp_conn_1 *) ((char *) adsp_ppp_cl_1 - offsetof( struct dsd_l2tp_conn_1, dsc_ppp_cl_1 ));
   adsl_l2tp_session = adsl_l2tpc1->adsc_l2tp_session;  /* L2TP connection session */
   if (adsl_l2tp_session) {                 /* connected with session  */
     m_l2tp_warning( adsl_l2tp_session, "PPP client %s", achp_msg );
   } else {
     m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d xs-gw-l2tp W L2TP PPP client %s",
                     __LINE__, achp_msg );
   }
   if (adsl_l2tpc1->iec_stl == ied_stl_connected) {  /* L2TP connected */
     m_close_ppp_server_cs( &adsl_l2tpc1->dsc_ppp_se_1 );  /* end of PPP */
     m_send_gw_cdn( adsl_l2tpc1 );          /* send CDN                */
     adsl_l2tpc1->iec_stl = ied_stl_cdn_sent;  /* CDN has been sent    */
   }
   if (adsl_l2tpc1->adsc_l2tp_session) {    /* L2TP connection session */
     m_l2tp_server_end( adsl_l2tpc1->adsc_l2tp_session, FALSE, "L2TP PPP client abend" );
     adsl_l2tpc1->adsc_l2tp_session = NULL;  /* no more L2TP connection session */
#ifdef OLD01
     adsl_l2tpc1->dsc_ppp_str_1.vpc_handle = NULL;  /* no more handle L2TP or HTUN */
#endif
     adsl_l2tpc1->dsc_ppp_se_1.vpc_handle = NULL;  /* no more handle L2TP or HOB-TUN */
   }
} /* end m_ppp_cl_abend()                                              */

/** create target-filter for PPP                                       */
extern "C" struct dsd_ppp_targfi_act_1 * m_create_ppp_targfi( struct dsd_targfi_1 *adsp_targfi,
                                                              int imp_trace_level,  /* trace_level */
                                                              int imp_sno ) {  /* WSP session number */
   int        iml1;                         /* working variable        */
#ifdef XYZ1
   struct dsd_targfi_1 *adsl_targfi_w1;     /* working variable        */
#endif
   struct dsd_ppp_targfi_act_1 *adsl_ptfa1_w1;  /* working variable    */

#ifdef XYZ1
   adsl_targfi_w1 = m_get_l2tp_targfi( adsp_l2tp_session );
   if (adsl_targfi_w1 == NULL) return NULL;  /* no target-filter set   */
#endif
   adsl_ptfa1_w1 = (struct dsd_ppp_targfi_act_1 *) malloc( sizeof(struct dsd_ppp_targfi_act_1) );
   adsl_ptfa1_w1->adsc_targfi_1 = adsp_targfi;  /* used target filter  */
   adsl_ptfa1_w1->adsc_ce_ipv4_act = NULL;  /* chain active cache entries PPP target filter */
   adsl_ptfa1_w1->adsc_ce_ipv4_empty = adsl_ptfa1_w1->dsrc_ce_ipv4;  /* chain empty cache entries PPP target filter */
   iml1 = 0;                                /* clear index             */
   do {                                     /* loop over all cache entries */
     adsl_ptfa1_w1->dsrc_ce_ipv4[ iml1 ].adsc_next = &adsl_ptfa1_w1->dsrc_ce_ipv4[ iml1 + 1 ];
     iml1++;                                /* increment index         */
   } while (iml1 < (D_CACHE_TF_IPV4_NO_ENTRY - 1));  /* entries cache entry IPV4 */
   adsl_ptfa1_w1->dsrc_ce_ipv4[ D_CACHE_TF_IPV4_NO_ENTRY - 1 ].adsc_next = NULL;
   adsl_ptfa1_w1->adsc_ce_ipv6_act = NULL;  /* chain active cache entries PPP target filter */
   adsl_ptfa1_w1->adsc_ce_ipv6_empty = adsl_ptfa1_w1->dsrc_ce_ipv6;  /* chain empty cache entries PPP target filter */
   iml1 = 0;                                /* clear index             */
   do {                                     /* loop over all cache entries */
     adsl_ptfa1_w1->dsrc_ce_ipv6[ iml1 ].adsc_next = &adsl_ptfa1_w1->dsrc_ce_ipv6[ iml1 + 1 ];
     iml1++;                                /* increment index         */
   } while (iml1 < (D_CACHE_TF_IPV6_NO_ENTRY - 1));  /* entries cache entry IPV6 */
   adsl_ptfa1_w1->dsrc_ce_ipv6[ D_CACHE_TF_IPV6_NO_ENTRY - 1 ].adsc_next = NULL;
#ifndef B160503
   adsl_ptfa1_w1->boc_blacklist = adsp_targfi->boc_blacklist;  /* use-as-blacklist */
#endif
   adsl_ptfa1_w1->imc_trace_level = imp_trace_level;  /* trace_level   */
   adsl_ptfa1_w1->imc_sno = imp_sno;        /* WSP session number      */
   return adsl_ptfa1_w1;
} /* end m_create_ppp_targfi()                                         */

/** check IPV4 packet against target-filter                            */
extern "C" enum ied_ret_cf m_proc_ppp_targfi_ipv4( struct dsd_hco_wothr *adsp_hco_wothr, struct dsd_ppp_targfi_act_1 *adsp_ptfa1,
                                                   struct dsd_gather_i_1 *adsp_gai1, int imp_len ) {
#ifndef B121116
   BOOL       bol_rc;                       /* return code             */
   int        iml_rc;                       /* return code             */
#endif
   int        iml1, iml2;                   /* working variables       */
   int        iml_inp;                      /* position in input       */
   int        iml_pos_ce_s;                 /* position in cache entry */
   int        iml_pos_ce_e;                 /* position in cache entry */
   int        iml_pos_next;                 /* next input character    */
   ied_ret_cf iel_rcf;                      /* return value            */
   BOOL       bol_check_dns;                /* called check DNS        */
   int        iml_no_targfi_ele_1;          /* number of elements      */
   int        iml_no_protocol;              /* number of protocols     */
   int        iml_no_port;                  /* number of ports         */
#ifdef B121116
   int        iml_stack;                    /* position in stack       */
#endif
   int        iml_no_dns;                   /* position in DNS response */
   UNSIG_MED  uml_ineta_w1;                 /* temporary INETA         */
#ifdef B110104
   UNSIG_MED  uml_ineta_w2;                 /* temporary INETA         */
   UNSIG_MED  uml_work;                     /* for shift INETA         */
#endif
   char       *achl_inp;                    /* input bytes from here   */
#ifdef B121116
   char       *achl_mask;                   /* position in mask        */
#endif
   char       *achl_w1;                     /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   struct dsd_ppp_targfi_cache_ipv4 *adsl_ptfca_w1;  /* working variable  */
   struct dsd_ppp_targfi_cache_ipv4 *adsl_ptfca_prev;  /* previous entry  */
   struct dsd_ppp_targfi_cache_ipv4 *adsl_ptfca_keep;  /* last entry to keep */
   struct hostent *adsl_hostentry;          /* for gethostbyname()     */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   struct dsd_wsp_trace_1 **aadsl_wt1_r1;   /* WSP trace control record */
   struct dsd_wsp_trace_record **aadsl_wtr_r1;  /* WSP trace record    */
   char       chrl_ce[ D_CACHE_TF_IPV4_LEN ];  /* compare to cache entry */
   struct sockaddr_storage dsl_soa_l;       /* address information     */
   struct dsd_unicode_string dsl_ucs_l1;    /* Unicode string          */
   struct dsd_unicode_string dsl_ucs_l2;    /* Unicode string          */
   char       byrl_ineta[ LEN_DISP_INETA ];  /* internet-address char  */
#ifdef B121116
#define DEF_MASK_STACK 16
   char       *achrl_sm[ DEF_MASK_STACK ];
   char       *achrl_si[ DEF_MASK_STACK ];
#endif

   adsl_gai1_w1 = adsp_gai1;                /* get input               */
   iml_inp = imp_len;                       /* position in input       */
   /* first get length of IP header                                    */
   iml_pos_ce_s = D_CACHE_TF_IPV4_LEN - 1;  /* set position in cache entry */
   iml_pos_ce_e = D_CACHE_TF_IPV4_LEN;      /* set position in cache entry */
   iml_pos_next = 0;                        /* next input character - length IP header */

   p_proc_00:                               /* process input           */
   achl_inp = adsl_gai1_w1->achc_ginp_cur;

   p_proc_20:                               /* process one gather      */
   if (iml_inp == 0) {                      /* input packet completely scanned */
     goto p_proc_40;                        /* cache entry filled      */
   }
   iml1 = adsl_gai1_w1->achc_ginp_end - achl_inp;  /* number of input characters */
   if (iml1 <= 0) {                         /* at end of input         */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather       */
     if (adsl_gai1_w1) goto p_proc_00;      /* process input           */
     return ied_rcf_incompl;                /* packet is incomplete    */
   }
   if (iml1 > iml_inp) iml1 = iml_inp;      /* only as long as input   */
   if (iml_pos_next > 0) {                  /* bytes to be ignored     */
     if (iml1 > iml_pos_next) iml1 = iml_pos_next;
     iml_inp -= iml1;
     iml_pos_next -= iml1;
     achl_inp += iml1;
     goto p_proc_20;                        /* process one gather      */
   }
   if (iml_pos_next < 0) {                  /* scan till end of packet */
     iml_inp -= iml1;
     achl_inp += iml1;
     goto p_proc_20;                        /* process one gather      */
   }
   iml2 = iml_pos_ce_e - iml_pos_ce_s;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( &chrl_ce[ iml_pos_ce_s ], achl_inp, iml2 );
   iml_inp -= iml2;
   iml_pos_ce_s += iml2;
   achl_inp += iml2;
   if (iml_pos_ce_s < iml_pos_ce_e) {       /* not complete filled     */
     goto p_proc_20;                        /* process one gather      */
   }
   switch (iml_pos_ce_e) {                  /* which field was filled  */
     case D_CACHE_TF_IPV4_LEN:              /* after length IP header  */
       iml_pos_ce_s = D_CACHE_TF_IPV4_INETA;  /* set position in cache entry */
       iml_pos_ce_e = D_CACHE_TF_IPV4_INETA + D_CACHE_TF_IPV4_PROTO;  /* set position in cache entry */
       iml_pos_next = 8;                    /* next input character - protocol */
       break;
     case D_CACHE_TF_IPV4_INETA + D_CACHE_TF_IPV4_PROTO:  /* after protocol */
       iml_pos_ce_s = 0;                    /* set position INETA destination */
       iml_pos_ce_e = D_CACHE_TF_IPV4_INETA;  /* set position in cache entry */
       iml_pos_next = 6;                    /* next input character - INETA destination */
       break;
     case D_CACHE_TF_IPV4_INETA:            /* after INETA destination */
       if (((unsigned char) chrl_ce[ D_CACHE_TF_IPV4_INETA ]) == IPPROTO_TCP) {
         iml_pos_ce_s = D_CACHE_TF_IPV4_INETA + D_CACHE_TF_IPV4_PROTO;  /* set position in cache entry */
         iml_pos_ce_e = D_CACHE_TF_IPV4_INETA + D_CACHE_TF_IPV4_PROTO + D_CACHE_TF_IPV4_PORT;  /* set position in cache entry */
         iml_pos_next = (chrl_ce[ D_CACHE_TF_IPV4_LEN - 1 ] & 0X0F) * 4 - 20 + 2;  /* next input character - port TCP */
         break;
       }
       if (((unsigned char) chrl_ce[ D_CACHE_TF_IPV4_INETA ]) == IPPROTO_UDP) {
         iml_pos_ce_s = D_CACHE_TF_IPV4_INETA + D_CACHE_TF_IPV4_PROTO;  /* set position in cache entry */
         iml_pos_ce_e = D_CACHE_TF_IPV4_INETA + D_CACHE_TF_IPV4_PROTO + D_CACHE_TF_IPV4_PORT;  /* set position in cache entry */
         iml_pos_next = (chrl_ce[ D_CACHE_TF_IPV4_LEN - 1 ] & 0X0F) * 4 - 20 + 2;  /* next input character - port UDP */
         break;
       }
       memset( &chrl_ce[ D_CACHE_TF_IPV4_INETA + D_CACHE_TF_IPV4_PROTO ], 0, D_CACHE_TF_IPV4_PORT );
       iml_pos_next = -1;                   /* next input character - read entire packet */
       break;
     case D_CACHE_TF_IPV4_INETA + D_CACHE_TF_IPV4_PROTO + D_CACHE_TF_IPV4_PORT:  /* after port */
       iml_pos_next = -1;                   /* next input character - read entire packet */
       break;
   }
   goto p_proc_20;                          /* process one gather      */

   p_proc_40:                               /* cache entry filled      */
   if (iml_pos_next >= 0) return ied_rcf_invalid;  /* packet is invalid */
   adsl_ptfca_w1 = adsp_ptfa1->adsc_ce_ipv4_act;  /* get active cache entries */
   adsl_ptfca_prev = NULL;                  /* clear previous entry    */
   while (adsl_ptfca_w1) {                  /* loop over all active cache entries */
     if (!memcmp( chrl_ce, adsl_ptfca_w1->chrc_cache_e, D_CACHE_TF_IPV4_LEN - 1 )) {
       iel_rcf = ied_rcf_ok;                /* packet is o.k.          */
       if (adsl_ptfca_w1->chrc_cache_e [ D_CACHE_TF_IPV4_LEN - 1 ]) {  /* drop packet */
         iel_rcf = ied_rcf_drop;            /* drop packet             */
       }
       if (adsl_ptfca_prev == NULL) return iel_rcf;  /* do not change cache entry */
       adsl_ptfca_prev->adsc_next = adsl_ptfca_w1->adsc_next;  /* remove current entry from chain */
       adsl_ptfca_w1->adsc_next = adsp_ptfa1->adsc_ce_ipv4_act;  /* get chain */
       adsp_ptfa1->adsc_ce_ipv4_act = adsl_ptfca_w1;  /* current entry is first in chain now */
       return iel_rcf;                      /* all done                */
     }
     adsl_ptfca_keep = adsl_ptfca_prev;     /* save last entry to keep */
     adsl_ptfca_prev = adsl_ptfca_w1;       /* save previous entry     */
     adsl_ptfca_w1 = adsl_ptfca_w1->adsc_next;  /* get next in chain   */
   }
   /* entry not found in cache                                         */
   if (adsp_ptfa1->adsc_ce_ipv4_empty) {    /* chain empty cache entries PPP target filter */
     adsl_ptfca_w1 = adsp_ptfa1->adsc_ce_ipv4_empty;  /* save entry    */
     adsp_ptfa1->adsc_ce_ipv4_empty = adsp_ptfa1->adsc_ce_ipv4_empty->adsc_next;  /* remove entry from chain */
   } else {                                 /* overwrite oldest entry from chain */
     adsl_ptfca_w1 = adsl_ptfca_prev;       /* get oldest entry        */
     adsl_ptfca_keep->adsc_next = NULL;     /* this is last in chain now */
   }
   adsl_ptfca_w1->adsc_next = adsp_ptfa1->adsc_ce_ipv4_act;  /* get old chain */
   adsp_ptfa1->adsc_ce_ipv4_act = adsl_ptfca_w1;  /* set new chain     */
   chrl_ce[ D_CACHE_TF_IPV4_LEN - 1 ] = 0;  /* set entry valid         */
   memcpy( adsl_ptfca_w1->chrc_cache_e, chrl_ce, D_CACHE_TF_IPV4_LEN );  /* copy parameters */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "HWSPL2TP01W l%05d xs-gw-l2tp T target-filter",
                   __LINE__ );
   m_console_out( chrl_ce, sizeof(chrl_ce) );
#endif
   bol_check_dns = FALSE;                   /* not called check DNS    */
   iml_no_targfi_ele_1 = 0;                 /* clear index of elements */

   p_cht_in_00:                             /* check one element       */
   if (((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_no_protocol == 0) {
     goto p_cht_in_12;                      /* protocol is valid       */
   }
   iml_no_protocol = 0;                     /* clear index of protocols */
   do {
     if (*((unsigned char *) adsp_ptfa1->adsc_targfi_1
            + ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                  + iml_no_targfi_ele_1)->imc_off_protocol + iml_no_protocol)
           == ((unsigned char) chrl_ce[ D_CACHE_TF_IPV4_INETA ])) {
       goto p_cht_in_12;                    /* protocol is valid       */
     }
     iml_no_protocol++;                     /* increment index of protocols */
   } while (iml_no_protocol < ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                                 + iml_no_targfi_ele_1)->imc_no_protocol);
   goto p_cht_in_60;                        /* protocol not found in list */

   p_cht_in_12:                             /* protocol is valid       */
   if (((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_no_port == 0) {
     goto p_cht_in_20;                      /* port is valid           */
   }
   if (   (chrl_ce[ D_CACHE_TF_IPV4_INETA ] != IPPROTO_TCP)
       && (chrl_ce[ D_CACHE_TF_IPV4_INETA ] != IPPROTO_UDP)) {
#ifdef B110209
     goto p_cht_in_20;                      /* do not check port       */
#else
     if (((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
           + iml_no_targfi_ele_1)->imc_no_protocol) {  /* protocol has been checked */
       goto p_cht_in_20;                    /* do not check port       */
     }
     goto p_cht_in_60;                      /* port not found in list  */
#endif
   }
   iml1 = ((unsigned char) chrl_ce[ D_CACHE_TF_IPV4_INETA ] << 24)
            | ((unsigned char) chrl_ce[ D_CACHE_TF_IPV4_INETA + D_CACHE_TF_IPV4_PROTO + 0 ] << 8)
            | (unsigned char) chrl_ce[ D_CACHE_TF_IPV4_INETA + D_CACHE_TF_IPV4_PROTO + 1 ];
   iml_no_port = 0;                         /* clear index of ports    */
   do {
     if (iml1 == *((int *) ((char *) adsp_ptfa1->adsc_targfi_1
                              + ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                                   + iml_no_targfi_ele_1)->imc_off_port)
                            + iml_no_port)) {
       goto p_cht_in_20;                    /* port is valid           */
     }
     iml_no_port++;                         /* increment index of ports */
   } while (iml_no_port < ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                            + iml_no_targfi_ele_1)->imc_no_port);
   goto p_cht_in_60;                        /* port not found in list  */

   p_cht_in_20:                             /* port is valid           */
   if (((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_len_dns_name == 0) {
     goto p_cht_in_32;                      /* is not DNS name         */
   }
   if (bol_check_dns) goto p_cht_in_24;     /* called check DNS        */
   if (adsp_hco_wothr) {                    /* runs on work-thread     */
     m_hco_wothr_blocking( adsp_hco_wothr );  /* mark thread blocking  */
   }
   adsl_hostentry = gethostbyaddr( (const char *) chrl_ce,
                                   D_CACHE_TF_IPV4_INETA,
                                   AF_INET );
   if (adsp_hco_wothr) {                    /* runs on work-thread     */
     m_hco_wothr_active( adsp_hco_wothr, FALSE );  /* mark thread active */
   }
   bol_check_dns = TRUE;                    /* called check DNS        */
//------
   if ((adsp_ptfa1->imc_trace_level & HL_WT_SESS_NETW) == 0) {  /* generate WSP trace record */
     goto p_cht_in_24;                      /* DNS query has been done */
   }
   memset( &dsl_soa_l, 0, sizeof(struct sockaddr_in) );
   dsl_soa_l.ss_family = AF_INET;
   *((UNSIG_MED *) &((struct sockaddr_in *) &dsl_soa_l)->sin_addr) = *((UNSIG_MED *) chrl_ce);
   iml_rc = getnameinfo( (struct sockaddr *) &dsl_soa_l, sizeof(struct sockaddr_in),
                         byrl_ineta, sizeof(byrl_ineta), 0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPxxxxW l%05d getnameinfo() returned %d %d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
     strcpy( byrl_ineta, "???" );
   }
   iml1 = 0;                                /* no names found          */
   if (adsl_hostentry) {                    /* API returned entry      */
     if (adsl_hostentry->h_name) iml1 = 1;  /* entry found             */
     iml_no_dns = 0;                        /* position in DNS response */
     while (adsl_hostentry->h_aliases[ iml_no_dns ]) {
       iml_no_dns++;                        /* increment position in DNS response */
     }
     iml1 += iml_no_dns;                    /* number of entries       */
   }
   adsl_wt1_w1 = adsl_wt1_w2 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
   memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
   adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data         */
   adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
   memcpy( adsl_wt1_w1->chrc_wtrt_id, "SNETFDN1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
   adsl_wt1_w1->imc_wtrt_sno = adsp_ptfa1->imc_sno;  /* WSP session number */
   adsl_wt1_w1->imc_wtrt_tid = HL_THRID;    /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
   ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                      "l%05d gethostbyaddr( \"%s\" ) returned %d DNS-names",
                                      __LINE__, byrl_ineta, iml1 );
   ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;   /* text passed             */
   ADSL_WTR_G1->achc_content                /* content of text / data  */
     = (char *) (ADSL_WTR_G1 + 1);
   adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
   while (adsl_hostentry) {                 /* API returned entry      */
//   aadsl_wt1_r1 = &adsl_wt1_w1->adsc_next;
     aadsl_wt1_r1 = &adsl_wt1_w1->adsc_cont;
     adsl_wtr_w1
       = (struct dsd_wsp_trace_record *) ((char *) (ADSL_WTR_G1 + 1)
                                                     + ADSL_WTR_G1->imc_length
                                                     + sizeof(void *) - 1);
     *((size_t *) &adsl_wtr_w1) &= 0 - sizeof(void *);
     aadsl_wtr_r1 = &ADSL_WTR_G1->adsc_next;
     achl_inp = adsl_hostentry->h_name;
     iml_no_dns = -1;                       /* position in DNS response */
     iml1 = 0;                              /* set counter             */
     while (TRUE) {                         /* loop output DNS names   */
       if (achl_inp) {                      /* name found              */
         iml2 = strlen( achl_inp );         /* get length              */
         iml1++;                            /* increment counter       */
#define D_LEN_TEXT 48
         if (((char *) adsl_wtr_w1 + D_LEN_TEXT + iml2)
               > ((char *) adsl_wt1_w2 + LEN_TCP_RECV)) {
           adsl_wt1_w2 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
           memset( adsl_wt1_w2, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
           *aadsl_wt1_r1 = adsl_wt1_w2;
//         aadsl_wt1_r1 = &adsl_wt1_w2->adsc_next;
           aadsl_wt1_r1 = &adsl_wt1_w2->adsc_cont;
           adsl_wtr_w1 = (struct dsd_wsp_trace_record *) (adsl_wt1_w2 + 1);
         }
#undef D_LEN_TEXT
         memset( adsl_wtr_w1, 0, sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wtr_w1->imc_length
           = sprintf( (char *) (adsl_wtr_w1 + 1),
                      "l%05d found DNS-name %d. \"%.*s\"",
                      __LINE__, iml1, iml2, achl_inp );
         adsl_wtr_w1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         adsl_wtr_w1->achc_content          /* content of text / data  */
           = (char *) (adsl_wtr_w1 + 1);
         *aadsl_wtr_r1 = adsl_wtr_w1;
         aadsl_wtr_r1 = &adsl_wtr_w1->adsc_next;
         *((size_t *) &adsl_wtr_w1)
           += sizeof(struct dsd_wsp_trace_record)
                + adsl_wtr_w1->imc_length
                + sizeof(void *) - 1;
         *((size_t *) &adsl_wtr_w1) &= 0 - sizeof(void *);
       }
       iml_no_dns++;                        /* position in DNS response */
       achl_inp = adsl_hostentry->h_aliases[ iml_no_dns ];
       if (achl_inp == NULL) break;         /* end of DNS names        */
     }
     break;
   }
#undef ADSL_WTR_G1
   m_wsp_trace_out( adsl_wt1_w1 );          /* output of WSP trace record */
//------

   p_cht_in_24:                             /* DNS query has been done */
   if (adsl_hostentry == NULL) goto p_cht_in_60;  /* try next element  */
   achl_inp = adsl_hostentry->h_name;
   iml_no_dns = -1;                         /* position in DNS response */
   if (achl_inp == NULL) goto p_cht_in_30;  /* try next name from DNS  */

   p_cht_in_28:                             /* check next DNS name     */
#ifdef B121116
   iml_stack = 0;                           /* clear stack index       */
   achl_mask = (char *) adsp_ptfa1->adsc_targfi_1
                          + ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                               + iml_no_targfi_ele_1)->imc_off_dns_name;

   plook00:
   switch (*achl_mask) {
     case 0:
       goto plook60;
     case '*':
       goto plook40;
     case '?':
       goto plook20;
     default:
       if (tabaau[(unsigned char) *achl_mask] == tabaau[(unsigned char) *achl_inp]) {
         achl_mask++;
         achl_inp++;
         goto plook00;
       }
       goto plook62;
   }

   plook20:                                 /* single wildcard         */
   if (*achl_inp == 0) goto plook62;        /* character follows       */
   achl_inp++;                              /* next character input    */
   achl_mask++;
   if (*achl_mask == '?') goto plook20;
   if (*achl_mask == '*') goto plook40;     /* asterix found           */
   goto plook00;

   plook40:                                 /* asterix wildcard        */
   achl_mask++;
   if (*achl_mask == '*') goto plook40;
   if (*achl_mask == '?') {
     achl_inp++;                            /* next character input    */
     goto plook40;
   }
   if (iml_stack == DEF_MASK_STACK) {       /* stack overflow          */
#ifdef B110211
     goto p_cht_in_60;                      /* mask does not match     */
#else
     goto p_cht_in_30;                      /* try next name from DNS  */
#endif
   }
   achrl_sm[iml_stack] = achl_mask;
   achrl_si[iml_stack] = achl_inp;
   iml_stack++;
   goto plook00;

   plook60:                                 /* end of DNS-name         */
   if (*achl_inp == 0) goto p_cht_in_32;    /* no more characters      */

   plook62:                                 /* end of DNS-name         */
   if (iml_stack == 0) {                    /* no more in table        */
#ifdef B110211
     goto p_cht_in_60;                      /* mask does not match     */
#else
     goto p_cht_in_30;                      /* try next name from DNS  */
#endif
   }
   achrl_si[iml_stack - 1]++;
   achl_mask = achrl_sm[iml_stack - 1];
   achl_inp = achrl_si[iml_stack - 1];
   if (*achl_inp) goto plook00;
   if (*achl_mask == 0) goto p_cht_in_32;   /* end already found       */
   iml_stack--;
   goto plook62;
#endif
#ifndef B121116
   bol_rc = m_cmp_wc_i_vx_vx( &iml_rc,
                              achl_inp, -1, ied_chs_idna_1,
                              (char *) adsp_ptfa1->adsc_targfi_1
                                + ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                                     + iml_no_targfi_ele_1)->imc_off_dns_name,
                              ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                                 + iml_no_targfi_ele_1)->imc_len_dns_name,
                              ied_chs_utf_8 );
//------
   if (adsp_ptfa1->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     dsl_ucs_l1.ac_str = achl_inp;          /* address of string       */
     dsl_ucs_l1.imc_len_str = -1;           /* length string in elements */
     dsl_ucs_l1.iec_chs_str = ied_chs_idna_1;  /* character set string */
     dsl_ucs_l2.ac_str                      /* address of string       */
       = (char *) adsp_ptfa1->adsc_targfi_1
            + ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                 + iml_no_targfi_ele_1)->imc_off_dns_name;
     dsl_ucs_l2.imc_len_str                 /* length string in elements */
       = ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
            + iml_no_targfi_ele_1)->imc_len_dns_name,
     dsl_ucs_l2.iec_chs_str = ied_chs_utf_8;  /* character set string  */
     achl_w1 = "FALSE";
     if (   (bol_rc)
         && (iml_rc == 0)) {
       achl_w1 = "TRUE ";
     }

     adsl_wt1_w1 = adsl_wt1_w2 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SNETFDN2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = adsp_ptfa1->imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     ADSL_WTR_G1->imc_length
       = m_hlsnprintf( (char *) (ADSL_WTR_G1 + 1),
                       ((char *) adsl_wt1_w1 + LEN_TCP_RECV)
                         - ((char *) (ADSL_WTR_G1 + 1)),
                       ied_chs_utf_8,
                       "-- l%05d compare %s %(ucs)s %(ucs)s.",
                       __LINE__, achl_w1, &dsl_ucs_l1, &dsl_ucs_l2 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
//------
   if (   (bol_rc)
       && (iml_rc == 0)) {
     goto p_cht_in_32;                      /* mask does match         */
   }
#endif

   p_cht_in_30:                             /* try next name from DNS  */
   iml_no_dns++;                            /* position in DNS response */
   achl_inp = adsl_hostentry->h_aliases[iml_no_dns];
   if (achl_inp) goto p_cht_in_28;          /* check next DNS name     */
   goto p_cht_in_60;                        /* DNS name does not match */

   p_cht_in_32:                             /* is not DNS name         */
#ifdef B110104
   if (((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_netw_mask <= 0) {
     goto p_cht_in_40;                      /* this element matches    */
   }
#ifndef __LITTLE_ENDIAN
   uml_work = 0XFFFFFFFF << (32 - ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                                    + iml_no_targfi_ele_1)->imc_netw_mask);
#else
   uml_ineta_w1 = 0XFFFFFFFF << (32 - ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                                    + iml_no_targfi_ele_1)->imc_netw_mask);
   uml_work = GHFW( uml_ineta_w1 );
#endif
   uml_ineta_w1 = *((UNSIG_MED *) chrl_ce) & uml_work;
   uml_ineta_w2 = ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                    + iml_no_targfi_ele_1)->umc_ineta
                      & uml_work;
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_proc_ppp_targfi_ipv4() l%05d ump_ineta=%08X uml_work=%08X uml_ineta_w1=%08X uml_ineta_w2=%08X",
                   __LINE__, *((UNSIG_MED *) chrl_ce), uml_work, uml_ineta_w1, uml_ineta_w2 );
#endif
   if (uml_ineta_w1 != uml_ineta_w2) {      /* do not match            */
     goto p_cht_in_60;                      /* try next element        */
   }
#endif
   iml1 = ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
             + iml_no_targfi_ele_1)->imc_len_ineta;  /* get length INETA */
   if (iml1 == 0) {                         /* no INETA                */
     goto p_cht_in_40;                      /* this element matches    */
   }
   if (iml1 != 4) {                         /* is not IPV4             */
     goto p_cht_in_60;                      /* try next element        */
   }
#ifdef B110209
   achl_w1 = &chrl_ce[ D_CACHE_TF_IPV4_INETA ];  /* here is INETA      */
#else
   achl_w1 = chrl_ce;                       /* here is INETA           */
#endif
   iml1 = ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
              + iml_no_targfi_ele_1)->imc_prefix_ineta;  /* prefix of INETA */
   if (iml1 == 0) goto p_cht_in_36;         /* compare INETAs          */
#ifdef B110209
   uml_ineta_w1 = *((UNSIG_MED *) &chrl_ce[ D_CACHE_TF_IPV4_INETA ]);  /* copy INETA */
#else
   uml_ineta_w1 = *((UNSIG_MED *) chrl_ce);  /* copy INETA             */
#endif
   achl_w1 = (char *) &uml_ineta_w1 + sizeof(UNSIG_MED);  /* end of INETA */
   iml1 = 32 - iml1;                        /* number of bits to clear */
   while (iml1 >= 8) {                      /* clear one byte          */
     *(--achl_w1) = 0;                      /* clear this byte         */
     iml1 -= 8;                             /* decrement number of bits */
   }
   achl_w1--;                               /* byte before             */
   *achl_w1 &= 0XFF << iml1;                /* clear remaining bits    */
   achl_w1 = (char *) &uml_ineta_w1;        /* here is INETA           */

   p_cht_in_36:                             /* compare INETAs          */
   if (*((UNSIG_MED *) achl_w1)
         != *((UNSIG_MED *) ((char *) adsp_ptfa1->adsc_targfi_1
                               + ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                                    + iml_no_targfi_ele_1)->imc_off_ineta))) {   /* offset INETA */
     goto p_cht_in_60;                      /* try next element        */
   }

   p_cht_in_40:                             /* this element matches    */
   if (((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
         + iml_no_targfi_ele_1)->boc_allow) {
     return ied_rcf_ok;                     /* packet is o.k.          */
   }
   /* deny, target not allowed                                         */
   adsl_ptfca_w1->chrc_cache_e[ D_CACHE_TF_IPV4_LEN - 1 ] = (unsigned char) 0XFF;  /* set cache entry */
   return ied_rcf_drop;                     /* drop packet             */

   p_cht_in_60:                             /* next element            */
   iml_no_targfi_ele_1++;                   /* increment index of elements */
   if (iml_no_targfi_ele_1 < adsp_ptfa1->adsc_targfi_1->imc_no_targfi_ele_1) {
     goto p_cht_in_00;                      /* check next element      */
   }
#ifndef B160503
   if (adsp_ptfa1->boc_blacklist) {         /* use-as-blacklist        */
     return ied_rcf_ok;                     /* packet is o.k.          */
   }
#endif
   /* target not allowed                                               */
   adsl_ptfca_w1->chrc_cache_e[ D_CACHE_TF_IPV4_LEN - 1 ] = (unsigned char) 0XFF;  /* set cache entry */
   return ied_rcf_drop;                     /* drop packet             */
} /* end m_proc_ppp_targfi_ipv4()                                      */

/**
   to-do 13.02.11 KB
   missing other headers:
   Hop-By-Hop Options 0
   Routing 43
   Fragment 44
   Destination Options 60
*/
/** check IPV6 packet against target-filter                            */
extern "C" enum ied_ret_cf m_proc_ppp_targfi_ipv6( struct dsd_hco_wothr *adsp_hco_wothr, struct dsd_ppp_targfi_act_1 *adsp_ptfa1,
                                                   struct dsd_gather_i_1 *adsp_gai1, int imp_len ) {
#ifndef B121116
   BOOL       bol_rc;                       /* return code             */
   int        iml_rc;                       /* return code             */
#endif
   int        iml1, iml2;                   /* working variables       */
   int        iml_inp;                      /* position in input       */
   int        iml_pos_ce_s;                 /* position in cache entry */
   int        iml_pos_ce_e;                 /* position in cache entry */
   int        iml_pos_next;                 /* next input character    */
   ied_ret_cf iel_rcf;                      /* return value            */
   BOOL       bol_check_dns;                /* called check DNS        */
   int        iml_no_targfi_ele_1;          /* number of elements      */
   int        iml_no_protocol;              /* number of protocols     */
   int        iml_no_port;                  /* number of ports         */
#ifdef B121116
   int        iml_stack;                    /* position in stack       */
#endif
   int        iml_no_dns;                   /* position in DNS response */
   char       *achl_inp;                    /* input bytes from here   */
   char       *achl_mask;                   /* position in mask        */
   char       *achl_w1;                     /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   struct dsd_ppp_targfi_cache_ipv6 *adsl_ptfca_w1;  /* working variable */
   struct dsd_ppp_targfi_cache_ipv6 *adsl_ptfca_prev;  /* previous entry */
   struct dsd_ppp_targfi_cache_ipv6 *adsl_ptfca_keep;  /* last entry to keep */
   struct hostent *adsl_hostentry;          /* for gethostbyname()     */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   struct dsd_wsp_trace_1 **aadsl_wt1_r1;   /* WSP trace control record */
   struct dsd_wsp_trace_record **aadsl_wtr_r1;  /* WSP trace record    */
   struct sockaddr_storage dsl_soa_l;       /* address information     */
   char       chrl_ineta[ 16 ];             /* temporary INETA IPV6    */
   char       chrl_ce[ D_CACHE_TF_IPV6_LEN ];  /* compare to cache entry */
   struct dsd_unicode_string dsl_ucs_l1;    /* Unicode string          */
   struct dsd_unicode_string dsl_ucs_l2;    /* Unicode string          */
   char       byrl_ineta[ LEN_DISP_INETA ];  /* internet-address char  */
#ifdef B121116
#define DEF_MASK_STACK 16
   char       *achrl_sm[ DEF_MASK_STACK ];
   char       *achrl_si[ DEF_MASK_STACK ];
#endif

   adsl_gai1_w1 = adsp_gai1;                /* get input               */
   iml_inp = imp_len;                       /* position in input       */
   /* first get length of IP header                                    */
   iml_pos_ce_s = D_CACHE_TF_IPV6_INETA;    /* set position in cache entry */
   iml_pos_ce_e = D_CACHE_TF_IPV6_INETA + D_CACHE_TF_IPV6_PROTO;  /* set position in cache entry */
   iml_pos_next = 6;                        /* next input character - Next Header */

   p_proc_00:                               /* process input           */
   achl_inp = adsl_gai1_w1->achc_ginp_cur;

   p_proc_20:                               /* process one gather      */
   if (iml_inp == 0) {                      /* input packet completely scanned */
     goto p_proc_40;                        /* cache entry filled      */
   }
   iml1 = adsl_gai1_w1->achc_ginp_end - achl_inp;  /* number of input characters */
   if (iml1 <= 0) {                         /* at end of input         */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather       */
     if (adsl_gai1_w1) goto p_proc_00;      /* process input           */
     return ied_rcf_incompl;                /* packet is incomplete    */
   }
   if (iml1 > iml_inp) iml1 = iml_inp;      /* only as long as input   */
   if (iml_pos_next > 0) {                  /* bytes to be ignored     */
     if (iml1 > iml_pos_next) iml1 = iml_pos_next;
     iml_inp -= iml1;
     iml_pos_next -= iml1;
     achl_inp += iml1;
     goto p_proc_20;                        /* process one gather      */
   }
   if (iml_pos_next < 0) {                  /* scan till end of packet */
     iml_inp -= iml1;
     achl_inp += iml1;
     goto p_proc_20;                        /* process one gather      */
   }
   iml2 = iml_pos_ce_e - iml_pos_ce_s;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( &chrl_ce[ iml_pos_ce_s ], achl_inp, iml2 );
   iml_inp -= iml2;
   iml_pos_ce_s += iml2;
   achl_inp += iml2;
   if (iml_pos_ce_s < iml_pos_ce_e) {       /* not complete filled     */
     goto p_proc_20;                        /* process one gather      */
   }
   switch (iml_pos_ce_e) {                  /* which field was filled  */
     case D_CACHE_TF_IPV6_INETA + D_CACHE_TF_IPV6_PROTO:  /* after protocol */
       iml_pos_ce_s = 0;                    /* set position INETA destination */
       iml_pos_ce_e = D_CACHE_TF_IPV6_INETA;  /* set position in cache entry */
       iml_pos_next = 1 + 16;               /* next input character - INETA destination */
       break;
     case D_CACHE_TF_IPV6_INETA:            /* after INETA destination */
       if (((unsigned char) chrl_ce[ D_CACHE_TF_IPV6_INETA ]) == IPPROTO_TCP) {
         iml_pos_ce_s = D_CACHE_TF_IPV6_INETA + D_CACHE_TF_IPV6_PROTO;  /* set position in cache entry */
         iml_pos_ce_e = D_CACHE_TF_IPV6_INETA + D_CACHE_TF_IPV6_PROTO + D_CACHE_TF_IPV6_PORT;  /* set position in cache entry */
         iml_pos_next = 40 - 40 + 2;        /* next input character - port TCP */
         break;
       }
       if (((unsigned char) chrl_ce[ D_CACHE_TF_IPV6_INETA ]) == IPPROTO_UDP) {
         iml_pos_ce_s = D_CACHE_TF_IPV6_INETA + D_CACHE_TF_IPV6_PROTO;  /* set position in cache entry */
         iml_pos_ce_e = D_CACHE_TF_IPV6_INETA + D_CACHE_TF_IPV6_PROTO + D_CACHE_TF_IPV6_PORT;  /* set position in cache entry */
         iml_pos_next = 40 - 40 + 2;        /* next input character - port UDP */
         break;
       }
       memset( &chrl_ce[ D_CACHE_TF_IPV6_INETA + D_CACHE_TF_IPV6_PROTO ], 0, D_CACHE_TF_IPV6_PORT );
       iml_pos_next = -1;                   /* next input character - read entire packet */
       break;
     case D_CACHE_TF_IPV6_INETA + D_CACHE_TF_IPV6_PROTO + D_CACHE_TF_IPV6_PORT:  /* after port */
       iml_pos_next = -1;                   /* next input character - read entire packet */
       break;
   }
   goto p_proc_20;                          /* process one gather      */

   p_proc_40:                               /* cache entry filled      */
   if (iml_pos_next >= 0) return ied_rcf_invalid;  /* packet is invalid */
   adsl_ptfca_w1 = adsp_ptfa1->adsc_ce_ipv6_act;  /* get active cache entries */
   adsl_ptfca_prev = NULL;                  /* clear previous entry    */
   while (adsl_ptfca_w1) {                  /* loop over all active cache entries */
     if (!memcmp( chrl_ce, adsl_ptfca_w1->chrc_cache_e, D_CACHE_TF_IPV6_LEN - 1 )) {
       iel_rcf = ied_rcf_ok;                /* packet is o.k.          */
       if (adsl_ptfca_w1->chrc_cache_e [ D_CACHE_TF_IPV6_LEN - 1 ]) {  /* drop packet */
         iel_rcf = ied_rcf_drop;            /* drop packet             */
       }
       if (adsl_ptfca_prev == NULL) return iel_rcf;  /* do not change cache entry */
       adsl_ptfca_prev->adsc_next = adsl_ptfca_w1->adsc_next;  /* remove current entry from chain */
       adsl_ptfca_w1->adsc_next = adsp_ptfa1->adsc_ce_ipv6_act;  /* get chain */
       adsp_ptfa1->adsc_ce_ipv6_act = adsl_ptfca_w1;  /* current entry is first in chain now */
       return iel_rcf;                      /* all done                */
     }
     adsl_ptfca_keep = adsl_ptfca_prev;     /* save last entry to keep */
     adsl_ptfca_prev = adsl_ptfca_w1;       /* save previous entry     */
     adsl_ptfca_w1 = adsl_ptfca_w1->adsc_next;  /* get next in chain   */
   }
   /* entry not found in cache                                         */
   if (adsp_ptfa1->adsc_ce_ipv6_empty) {    /* chain empty cache entries PPP target filter */
     adsl_ptfca_w1 = adsp_ptfa1->adsc_ce_ipv6_empty;  /* save entry         */
     adsp_ptfa1->adsc_ce_ipv6_empty = adsp_ptfa1->adsc_ce_ipv6_empty->adsc_next;  /* remove entry from chain */
   } else {                                 /* overwrite oldest entry from chain */
     adsl_ptfca_w1 = adsl_ptfca_prev;       /* get oldest entry        */
     adsl_ptfca_keep->adsc_next = NULL;     /* this is last in chain now */
   }
   adsl_ptfca_w1->adsc_next = adsp_ptfa1->adsc_ce_ipv6_act;  /* get old chain */
   adsp_ptfa1->adsc_ce_ipv6_act = adsl_ptfca_w1;  /* set new chain          */
   chrl_ce[ D_CACHE_TF_IPV6_LEN - 1 ] = 0;  /* set entry valid         */
   memcpy( adsl_ptfca_w1->chrc_cache_e, chrl_ce, D_CACHE_TF_IPV6_LEN );  /* copy parameters */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "HWSPL2TP01W l%05d xs-gw-l2tp T target-filter",
                   __LINE__ );
   m_console_out( chrl_ce, sizeof(chrl_ce) );
#endif
   bol_check_dns = FALSE;                   /* not called check DNS    */
   iml_no_targfi_ele_1 = 0;                 /* clear index of elements */

   p_cht_in_00:                             /* check one element       */
   if (((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_no_protocol == 0) {
     goto p_cht_in_12;                      /* protocol is valid       */
   }
   iml_no_protocol = 0;                     /* clear index of protocols */
   do {
     if (*((unsigned char *) adsp_ptfa1->adsc_targfi_1
            + ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                  + iml_no_targfi_ele_1)->imc_off_protocol + iml_no_protocol)
           == ((unsigned char) chrl_ce[ D_CACHE_TF_IPV6_INETA ])) {
       goto p_cht_in_12;                    /* protocol is valid       */
     }
     iml_no_protocol++;                     /* increment index of protocols */
   } while (iml_no_protocol < ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                                 + iml_no_targfi_ele_1)->imc_no_protocol);
   goto p_cht_in_60;                        /* protocol not found in list */

   p_cht_in_12:                             /* protocol is valid       */
   if (((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_no_port == 0) {
     goto p_cht_in_20;                      /* port is valid           */
   }
   if (   (chrl_ce[ D_CACHE_TF_IPV6_INETA ] != IPPROTO_TCP)
       && (chrl_ce[ D_CACHE_TF_IPV6_INETA ] != IPPROTO_UDP)) {
     if (((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
           + iml_no_targfi_ele_1)->imc_no_protocol) {  /* protocol has been checked */
       goto p_cht_in_20;                    /* do not check port       */
     }
     goto p_cht_in_60;                      /* port not found in list  */
   }
   iml1 = ((unsigned char) chrl_ce[ D_CACHE_TF_IPV6_INETA ] << 24)
            | ((unsigned char) chrl_ce[ D_CACHE_TF_IPV6_INETA + D_CACHE_TF_IPV6_PROTO + 0 ] << 8)
            | (unsigned char) chrl_ce[ D_CACHE_TF_IPV6_INETA + D_CACHE_TF_IPV6_PROTO + 1 ];
   iml_no_port = 0;                         /* clear index of ports    */
   do {
     if (iml1 == *((int *) ((char *) adsp_ptfa1->adsc_targfi_1
                              + ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                                   + iml_no_targfi_ele_1)->imc_off_port)
                            + iml_no_port)) {
       goto p_cht_in_20;                    /* port is valid           */
     }
     iml_no_port++;                         /* increment index of ports */
   } while (iml_no_port < ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                            + iml_no_targfi_ele_1)->imc_no_port);
   goto p_cht_in_60;                        /* port not found in list  */

   p_cht_in_20:                             /* port is valid           */
   if (((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_len_dns_name == 0) {
     goto p_cht_in_32;                      /* is not DNS name         */
   }
   if (bol_check_dns) goto p_cht_in_24;     /* called check DNS        */
   if (adsp_hco_wothr) {                    /* runs on work-thread     */
     m_hco_wothr_blocking( adsp_hco_wothr );  /* mark thread blocking  */
   }
   adsl_hostentry = gethostbyaddr( (const char *) chrl_ce,
                                   D_CACHE_TF_IPV6_INETA,
                                   AF_INET6 );
   if (adsp_hco_wothr) {                    /* runs on work-thread     */
     m_hco_wothr_active( adsp_hco_wothr, FALSE );  /* mark thread active */
   }
   bol_check_dns = TRUE;                    /* called check DNS        */
//------
   if ((adsp_ptfa1->imc_trace_level & HL_WT_SESS_NETW) == 0) {  /* generate WSP trace record */
     goto p_cht_in_24;                      /* DNS query has been done */
   }
   memset( &dsl_soa_l, 0, sizeof(struct sockaddr_in6) );
   dsl_soa_l.ss_family = AF_INET6;
   memcpy( &((struct sockaddr_in6 *) &dsl_soa_l)->sin6_addr, chrl_ce, 16 );
   iml_rc = getnameinfo( (struct sockaddr *) &dsl_soa_l, sizeof(struct sockaddr_in6),
                         byrl_ineta, sizeof(byrl_ineta), 0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPxxxxW l%05d getnameinfo() returned %d %d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
     strcpy( byrl_ineta, "???" );
   }
   iml1 = 0;                                /* no names found          */
   if (adsl_hostentry) {                    /* API returned entry      */
     if (adsl_hostentry->h_name) iml1 = 1;  /* entry found             */
     iml_no_dns = 0;                        /* position in DNS response */
     while (adsl_hostentry->h_aliases[ iml_no_dns ]) {
       iml_no_dns++;                        /* increment position in DNS response */
     }
     iml1 += iml_no_dns;                    /* number of entries       */
   }
   adsl_wt1_w1 = adsl_wt1_w2 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
   memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
   adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data         */
   adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
   memcpy( adsl_wt1_w1->chrc_wtrt_id, "SNETFDN3", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
   adsl_wt1_w1->imc_wtrt_sno = adsp_ptfa1->imc_sno;  /* WSP session number */
   adsl_wt1_w1->imc_wtrt_tid = HL_THRID;    /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
   ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                      "l%05d gethostbyaddr( \"%s\" ) returned %d DNS-names",
                                      __LINE__, byrl_ineta, iml1 );
   ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;   /* text passed             */
   ADSL_WTR_G1->achc_content                /* content of text / data  */
     = (char *) (ADSL_WTR_G1 + 1);
   adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
   while (adsl_hostentry) {                 /* API returned entry      */
//   aadsl_wt1_r1 = &adsl_wt1_w1->adsc_next;
     aadsl_wt1_r1 = &adsl_wt1_w1->adsc_cont;
     adsl_wtr_w1
       = (struct dsd_wsp_trace_record *) ((char *) (ADSL_WTR_G1 + 1)
                                                     + ADSL_WTR_G1->imc_length
                                                     + sizeof(void *) - 1);
     *((size_t *) &adsl_wtr_w1) &= 0 - sizeof(void *);
     aadsl_wtr_r1 = &ADSL_WTR_G1->adsc_next;
     achl_inp = adsl_hostentry->h_name;
     iml_no_dns = -1;                       /* position in DNS response */
     iml1 = 0;                              /* set counter             */
     while (TRUE) {                         /* loop output DNS names   */
       if (achl_inp) {                      /* name found              */
         iml2 = strlen( achl_inp );         /* get length              */
         iml1++;                            /* increment counter       */
#define D_LEN_TEXT 48
         if (((char *) adsl_wtr_w1 + D_LEN_TEXT + iml2)
               > ((char *) adsl_wt1_w2 + LEN_TCP_RECV)) {
           adsl_wt1_w2 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
           memset( adsl_wt1_w2, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
           *aadsl_wt1_r1 = adsl_wt1_w2;
//         aadsl_wt1_r1 = &adsl_wt1_w2->adsc_next;
           aadsl_wt1_r1 = &adsl_wt1_w2->adsc_cont;
           adsl_wtr_w1 = (struct dsd_wsp_trace_record *) (adsl_wt1_w2 + 1);
         }
#undef D_LEN_TEXT
         memset( adsl_wtr_w1, 0, sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wtr_w1->imc_length
           = sprintf( (char *) (adsl_wtr_w1 + 1),
                      "l%05d found DNS-name %d. \"%.*s\"",
                      __LINE__, iml1, iml2, achl_inp );
         adsl_wtr_w1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         adsl_wtr_w1->achc_content          /* content of text / data  */
           = (char *) (adsl_wtr_w1 + 1);
         *aadsl_wtr_r1 = adsl_wtr_w1;
         aadsl_wtr_r1 = &adsl_wtr_w1->adsc_next;
         *((size_t *) &adsl_wtr_w1)
           += sizeof(struct dsd_wsp_trace_record)
                + adsl_wtr_w1->imc_length
                + sizeof(void *) - 1;
         *((size_t *) &adsl_wtr_w1) &= 0 - sizeof(void *);
       }
       iml_no_dns++;                        /* position in DNS response */
       achl_inp = adsl_hostentry->h_aliases[ iml_no_dns ];
       if (achl_inp == NULL) break;         /* end of DNS names        */
     }
     break;
   }
#undef ADSL_WTR_G1
   m_wsp_trace_out( adsl_wt1_w1 );          /* output of WSP trace record */
//------

   p_cht_in_24:                             /* DNS query has been done */
   if (adsl_hostentry == NULL) goto p_cht_in_60;  /* try next element  */
   achl_inp = adsl_hostentry->h_name;
   iml_no_dns = -1;                         /* position in DNS response */
   if (achl_inp == NULL) goto p_cht_in_30;  /* try next name from DNS  */

   p_cht_in_28:                             /* check next DNS name     */
#ifdef B121116
   iml_stack = 0;                           /* clear stack index       */
   achl_mask = (char *) adsp_ptfa1->adsc_targfi_1
                          + ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                               + iml_no_targfi_ele_1)->imc_off_dns_name;

   plook00:
   switch (*achl_mask) {
     case 0:
       goto plook60;
     case '*':
       goto plook40;
     case '?':
       goto plook20;
     default:
       if (tabaau[(unsigned char) *achl_mask] == tabaau[(unsigned char) *achl_inp]) {
         achl_mask++;
         achl_inp++;
         goto plook00;
       }
       goto plook62;
   }

   plook20:                                 /* single wildcard         */
   if (*achl_inp == 0) goto plook62;        /* character follows       */
   achl_inp++;                              /* next character input    */
   achl_mask++;
   if (*achl_mask == '?') goto plook20;
   if (*achl_mask == '*') goto plook40;     /* asterix found           */
   goto plook00;

   plook40:                                 /* asterix wildcard        */
   achl_mask++;
   if (*achl_mask == '*') goto plook40;
   if (*achl_mask == '?') {
     achl_inp++;                            /* next character input    */
     goto plook40;
   }
   if (iml_stack == DEF_MASK_STACK) {       /* stack overflow          */
     goto p_cht_in_30;                      /* try next name from DNS  */
   }
   achrl_sm[iml_stack] = achl_mask;
   achrl_si[iml_stack] = achl_inp;
   iml_stack++;
   goto plook00;

   plook60:                                 /* end of DNS-name         */
   if (*achl_inp == 0) goto p_cht_in_32;    /* no more characters      */

   plook62:                                 /* end of DNS-name         */
   if (iml_stack == 0) {                    /* no more in table        */
     goto p_cht_in_30;                      /* try next name from DNS  */
   }
   achrl_si[iml_stack - 1]++;
   achl_mask = achrl_sm[iml_stack - 1];
   achl_inp = achrl_si[iml_stack - 1];
   if (*achl_inp) goto plook00;
   if (*achl_mask == 0) goto p_cht_in_32;   /* end already found       */
   iml_stack--;
   goto plook62;
#endif
#ifndef B121116
   bol_rc = m_cmp_wc_i_vx_vx( &iml_rc,
                              achl_inp, -1, ied_chs_idna_1,
                              (char *) adsp_ptfa1->adsc_targfi_1
                                + ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                                     + iml_no_targfi_ele_1)->imc_off_dns_name,
                              ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                                 + iml_no_targfi_ele_1)->imc_len_dns_name,
                              ied_chs_utf_8 );
//------
   if (adsp_ptfa1->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     dsl_ucs_l1.ac_str = achl_inp;          /* address of string       */
     dsl_ucs_l1.imc_len_str = -1;           /* length string in elements */
     dsl_ucs_l1.iec_chs_str = ied_chs_idna_1;  /* character set string */
     dsl_ucs_l2.ac_str                      /* address of string       */
       = (char *) adsp_ptfa1->adsc_targfi_1
            + ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                 + iml_no_targfi_ele_1)->imc_off_dns_name;
     dsl_ucs_l2.imc_len_str                 /* length string in elements */
       = ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
            + iml_no_targfi_ele_1)->imc_len_dns_name,
     dsl_ucs_l2.iec_chs_str = ied_chs_utf_8;  /* character set string  */
     achl_w1 = "FALSE";
     if (   (bol_rc)
         && (iml_rc == 0)) {
       achl_w1 = "TRUE ";
     }

     adsl_wt1_w1 = adsl_wt1_w2 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SNETFDN4", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = adsp_ptfa1->imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     ADSL_WTR_G1->imc_length
       = m_hlsnprintf( (char *) (ADSL_WTR_G1 + 1),
                       ((char *) adsl_wt1_w1 + LEN_TCP_RECV)
                         - ((char *) (ADSL_WTR_G1 + 1)),
                       ied_chs_utf_8,
                       "-- l%05d compare %s %(ucs)s %(ucs)s.",
                       __LINE__, achl_w1, &dsl_ucs_l1, &dsl_ucs_l2 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
//------
   if (   (bol_rc)
       && (iml_rc == 0)) {
     goto p_cht_in_32;                      /* mask does match         */
   }
#endif

   p_cht_in_30:                             /* try next name from DNS  */
   iml_no_dns++;                            /* position in DNS response */
   achl_inp = adsl_hostentry->h_aliases[iml_no_dns];
   if (achl_inp) goto p_cht_in_28;          /* check next DNS name     */
   goto p_cht_in_60;                        /* DNS name does not match */

   p_cht_in_32:                             /* is not DNS name         */
   iml1 = ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
             + iml_no_targfi_ele_1)->imc_len_ineta;  /* get length INETA */
   if (iml1 == 0) {                         /* no INETA                */
     goto p_cht_in_40;                      /* this element matches    */
   }
   if (iml1 != 16) {                        /* is not IPV6             */
     goto p_cht_in_60;                      /* try next element        */
   }
   achl_w1 = chrl_ce;                       /* here is INETA           */
   iml1 = ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
              + iml_no_targfi_ele_1)->imc_prefix_ineta;  /* prefix of INETA */
   if (iml1 == 0) goto p_cht_in_36;         /* compare INETAs          */
   memcpy( chrl_ineta, chrl_ce, 16 );       /* temporary INETA IPV6    */
   achl_w1 = chrl_ineta + 16;               /* end of INETA            */
   iml1 = 16 * 8 - iml1;                    /* number of bits to clear */
   while (iml1 >= 8) {                      /* clear one byte          */
     *(--achl_w1) = 0;                      /* clear this byte         */
     iml1 -= 8;                             /* decrement number of bits */
   }
   achl_w1--;                               /* byte before             */
   *achl_w1 &= 0XFF << iml1;                /* clear remaining bits    */
   achl_w1 = chrl_ineta;                    /* here is INETA           */

   p_cht_in_36:                             /* compare INETAs          */
   if (memcmp( achl_w1,
               ((char *) adsp_ptfa1->adsc_targfi_1
                           + ((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
                                 + iml_no_targfi_ele_1)->imc_off_ineta),  /* offset INETA */
               16 )) {
     goto p_cht_in_60;                      /* try next element        */
   }

   p_cht_in_40:                             /* this element matches    */
   if (((struct dsd_targfi_ele_1 *) (adsp_ptfa1->adsc_targfi_1 + 1)
         + iml_no_targfi_ele_1)->boc_allow) {
     return ied_rcf_ok;                     /* packet is o.k.          */
   }
#ifndef B160503
   if (adsp_ptfa1->boc_blacklist) {         /* use-as-blacklist        */
     return ied_rcf_ok;                     /* packet is o.k.          */
   }
#endif
   /* deny, target not allowed                                         */
   adsl_ptfca_w1->chrc_cache_e[ D_CACHE_TF_IPV6_LEN - 1 ] = (unsigned char) 0XFF;  /* set cache entry */
   return ied_rcf_drop;                     /* drop packet             */

   p_cht_in_60:                             /* next element            */
   iml_no_targfi_ele_1++;                   /* increment index of elements */
   if (iml_no_targfi_ele_1 < adsp_ptfa1->adsc_targfi_1->imc_no_targfi_ele_1) {
     goto p_cht_in_00;                      /* check next element      */
   }
   /* target not allowed                                               */
   adsl_ptfca_w1->chrc_cache_e[ D_CACHE_TF_IPV6_LEN - 1 ] = (unsigned char) 0XFF;  /* set cache entry */
   return ied_rcf_drop;                     /* drop packet             */
} /* end m_proc_ppp_targfi_ipv6()                                      */

#ifdef TRACEHL1
/* subroutine to display date and time                                 */
static int m_get_date_time( char *achp_buff ) {
   time_t     dsl_time;

   time( &dsl_time );
   return strftime( achp_buff, 18, "%d.%m.%y %H:%M:%S", localtime( &dsl_time ) );
} /* end m_get_date_time()                                             */

#ifndef HL_UNIX
/* subroutine to dump storage-content to console                       */
static void m_console_out( char *achp_buff, int implength ) {
   int        iml1, iml2, iml3, iml4, iml5, iml6;  /* working variable */
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
} /* end m_console_out()                                            */
#endif
#endif
