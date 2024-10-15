//#define CHECK_OUTPUT_01                     /* temporary, 20.08.12 KB  */
//#define TRACEHL1                            /* temporary, 22.08.12 KB  */
//#define HPPPT1_V14_RECV                     /* 26.08.12 KB HOB-PPP-T1 V1.4 receive */
//#define HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
#define HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
#ifdef TO_DO
  23.02.12 KB
  dynamic NAT
    WINS
    <integrated-DNS-server>
  30.04.12 KB
  close all TCP sessions at server side when end
  SYN / SYN-ACK not immediately sent
  23.07.12
  display INETAs original and Natted, configurable
  09.03.14
  DNS-relay - if not dynamic NAT
  ICMP NAT - Radius to port not waiting
  SSTP
#endif
//#define TRACEHL_TIMER_01
#ifdef TRACEHL1
#define TRACEHL_TIMER_01
#endif
//#define TRACEHL_INETA_01
#define NEW_WSP_1102
#define EXT_111125_01
//#define DEBUG_101207_01
//#define DEBUG_101207_02
//#define DEBUG_101208_01
//#define DEBUG_110831_01
//#define DEBUG_110902_01
//#define DEBUG_111119_01
//#define DEBUG_120821_01
//#define DEBUG_120822_01
//#define DEBUG_140730_01                     /* problems FTP            */
//#define DEBUG_150116_01                     /* crash NAT / FTP         */
//#define CHECK_OUTPUT_01
//#define TRY_101205
#define TRY_110901_01
#define TRY_110901_02
#define TRY_141210_01
//#define TRACEHL1
//#define TRACEHL_DNS
//#define TRACEHL_090905
//#define TRACEHL_111004 8
//#define PACKET_LOSS_01 11                   /* lose packets            */
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xl-sdh-ppp-pf-07                                    |*/
/*| -------------                                                     |*/
/*|  DLL / Library for HOB WebSecureProxy                             |*/
/*|    Server-Data-Hook                                               |*/
/*|  PPP Packet-Filter 07, client and server may use any INETA range  |*/
/*|    dynamic NAT                                                    |*/
/*|    terminate all TCP sessions, IPV4 and IPV6                      |*/
/*|  TCP-Tuner                                                        |*/
/*|  KB 17.08.11                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  Unix / Linux GCC                                                 |*/
/*|                                                                   |*/
/*| FUNCTION:                                                         |*/
/*| ---------                                                         |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/* #define TRACEHL1 */

/**
   This SDH terminates all TCP sessions thru SDH-TCP.
   There are AVL-trees which contain entries for each TCP session;
   there is one AVL-tree for IPV4 and another AVL-tree for IPV6.
   This SDH also does dynamic NAT, translating all INETAs between
   the client and the server.
   The AVL-tree of the TCP session for IPV4 contains the INETAs
   of the network of the client.
   struct dsd_tcp_session_1 contains two TCP half-sessions,
   each represented thru struct dsd_sdh_tcp_1.
   The first struct dsd_sdh_tcp_1 (index 0) is the TCP half-session on client side,
   the second struct dsd_sdh_tcp_1 (index 1) is the TCP half-session on server side.
*/

#ifdef TRACEHL_DNS
#ifndef TRACEHL_TIME
#define TRACEHL_TIME
#endif
#endif

#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif

#ifndef HL_UNIX
#define HL_WCSLEN( p ) wcslen( (WCHAR *) p )
#define HL_WCSCMP( p1, p2 ) wcscmp( (WCHAR *) p1, (WCHAR *) p2 )
#define HL_FN_WCSCMP( p1, p2 ) _wcsicmp( (WCHAR *) p1, (WCHAR *) p2 )
#define HL_NAME_WCSCMP( p1, p2 ) _wcsicmp( (WCHAR *) p1, (WCHAR *) p2 )
#else
#define HL_WCSLEN( p ) m_len_u16z( (HL_WCHAR *) p )
#define HL_WCSCMP( p1, p2 ) m_cmp_u16z_u16z( (HL_WCHAR *) p1, (HL_WCHAR *) p2 )
#define HL_FN_WCSCMP( p1, p2 ) m_cmp_u16z_u16z( (HL_WCHAR *) p1, (HL_WCHAR *) p2 )
#define HL_NAME_WCSCMP( p1, p2 ) m_cmpi_u16z_u16z( (HL_WCHAR *) p1, (HL_WCHAR *) p2 )
#endif

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifndef HL_UNIX
#include <conio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#ifdef TRACEHL_TIME
#include <sys/timeb.h>
#endif
#else
#include <stdarg.h>
#include <netinet/in.h>
#ifdef TRACEHL_TIME
#include <sys/time.h>
#endif
#include "hob-unix01.h"
#endif
//#include "hob-xsclib01.h"
#include <hob-xslunic1.h>
#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>
#ifdef XYZ1
#include <hob-tabau.h>
#endif
#include <hob-netw-01.h>
#ifndef HL_UNIX
#include <hob-avl03.h>
#else
#include "hob-avl03.h"
#endif
#ifdef NOT_READY_110822
#include "hob-htcp-int-types.h"
#include "hob-htcp.h"
#include "hob-htcp-sdh-tcp.h"
#else
#include "hob-htcp-int-01.h"
#include "hob-htcp-01.h"
#include "hob-htcp-sdh-01.h"
#endif
#ifdef HL_FREEBSD
#include <sys/socket.h>
#endif

/*+-------------------------------------------------------------------+*/
/*| System and library header files for XERCES.                       |*/
/*+-------------------------------------------------------------------+*/

#include <xercesc/dom/DOMAttr.hpp>

#define DOMNode XERCES_CPP_NAMESPACE::DOMNode

/*+-------------------------------------------------------------------+*/
/*| header files for Server-Data-Hook.                                |*/
/*+-------------------------------------------------------------------+*/

#define DEF_HL_INCL_DOM
#include "hob-xsclib01.h"

#ifndef UNSIG_MED
#define UNSIG_MED unsigned int
#endif
#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif

#ifdef OLD01
#ifndef HL_UNIX
#define D_CHARSET_IP ied_chs_ansi_819       /* ANSI 819                */
#else
#define D_CHARSET_IP ied_chs_ascii_850      /* ASCII 850               */
#endif
#endif

#define HL_MAX_LEN_PACKET      (16 * 1024)

#define LEN_INETA_PR_IPV4      15           /* length Internet Address print IPV4 */

#define MAX_DNS_INETA          32           /* maximum number of INETA in DNS response */
#define MAX_DNS_QUEUED         8            /* maximum number of DNS responses queued */

#define DEF_INETA_TABLE_ORG    64           /* number of entries original table */
#define DEF_INETA_TABLE_EXT    32           /* number of entries extension */

#define DEF_NAT_FTP_TABLE_ORG  8            /* number of entries first chunk */
#define DEF_NAT_FTP_TABLE_EXT  8            /* number of entries extension chunk */

#define MAX_LEN_NHASN          4            /* maximum length NHASN length */
#define OUT_LEN_NHASN          3            /* output length NHASN length */
#define MAX_TCP_SNDBUF         (16 * 1024)  /* maximum TCP send buffer */
#ifdef B110818
#define D_POS_IPH_PROT         9            /* position protocol in IP header */
#endif
#define D_POS_IPV4_H_PROT      9            /* position protocol in IPV4 header */
#define D_POS_IPV6_H_NEXT      6            /* position type next header in IPV6 header */
#define D_POS_IPH_DCHS         10           /* position checksum in IP header */
#define D_LEN_HEADER_IPV4      20           /* length of IPV4 header minimum */
#define D_LEN_HEADER_IPV6      40           /* length of IPV6 header   */
#define D_LEN_UDP_HEADER       8            /* length of UDP header    */
#define D_LEN_TCP_H_MIN        20           /* length of TCP header minimum */
#define D_LEN_DNS_ID           sizeof(unsigned short int)  /* length of DNS Id */
#define D_EXT_SIP              64           /* SIP packet to be extended */
#define D_LEN_RESP_START       128          /* size maximum of RESPONSE-START */
#define D_PORT_SOCKS           1080         /* default TCP port of Socks */
#define D_PORT_FTP             21           /* default TCP port of FTP */

#define D_DEST_IPV4ADDR        1
#define D_DEST_IPV6ADDR        4

#define D_TCP_HEADER_FLAG_PSH  0X08         /* push flag of TCP header */

#define MAX_LEN_USERID         512          /* maximum length userid   */
#define MAX_LEN_DOMAIN         256          /* maximum length destination domain */

#define CHAR_CR                0X0D         /* carriage-return         */
#define CHAR_LF                0X0A         /* line-feed               */

struct dsd_sdh_call_1 {                     /* structure call in SDH   */
   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     vpc_userfld;                  /* User Field Subroutine   */
};

/**
   the memory of struct dsd_clib1_conf is built like that:
   1. struct dsd_clib1_conf
   2. entries struct dsd_conf_ext_1, followed by INETAs and DNS names
      and, if required, the DNS response packet
*/

struct dsd_clib1_conf {                     /* configuration data      */
   UNSIG_MED  umc_conf_ineta_1_lower;       /* configured INETAs 1 lower value */
   UNSIG_MED  umc_conf_ineta_1_upper;       /* configured INETAs 1 upper value */
   UNSIG_MED  umc_conf_ineta_1_mask;        /* configured INETAs 1 network mask */
   UNSIG_MED  umc_conf_ineta_2_lower;       /* configured INETAs 2 lower value */
   UNSIG_MED  umc_conf_ineta_2_upper;       /* configured INETAs 2 upper value */
   UNSIG_MED  umc_conf_ineta_2_mask;        /* configured INETAs 2 network mask */
   int        imc_len_conf_ext_1;           /* length of configuration extensions */
   int        imc_no_s5_ineta_nat;          /* number of reserved INETAs for Socks servers */
   BOOL       boc_disp_inetas;              /* display natted INETAs   */
   BOOL       boc_internal_dns_server;      /* use internal DNS server */
   BOOL       boc_alg_sip;                  /* use ALG for SIP VoIP protocol */
   BOOL       boc_use_ftp;                  /* use ALG for FTP, FTP server configured */
};

#ifdef B110818
/* to be removed 17.08.11 KB - start */
struct dsd_dns_resp_1 {                     /* structure DNS response  */
   int        imc_len_stor;                 /* storage reserved        */
   int        imc_len_entry;                /* length of entry         */
   int        imc_len_dns_n;                /* length DNS name         */
};
/* to be removed 17.08.11 KB - end */
#endif

enum ied_conf_ext_def {                     /* type of configuration extension */
   ied_coe_dns_resp,                        /* DNS resonse configured  */
   ied_coe_socks_se,                        /* Socks server            */
   ied_coe_ftp_se                           /* FTP server              */
};

struct dsd_conf_ext_1 {                     /* configuration extension */
   enum ied_conf_ext_def iec_coe;           /* type of configuration extension */
   int        imc_len_stor;                 /* storage reserved        */
   int        imc_len_entry;                /* length of entry         */
   int        imc_len_dns_n;                /* length DNS name         */
   int        imc_no_ineta;                 /* count INETA             */
   int        imc_port;                     /* TCP port                */
   int        imc_index_so_ineta_nat;       /* index of reserved INETAs for Socks servers */
};

#ifdef B110820
struct dsd_query_dns_resp_1 {               /* structure query DNS response */
   UNSIG_MED  umc_ineta_source;             /* INETA source            */
   char       chrs_port_dest[2];            /* destination port        */
   char       chrs_id[2];                   /* transaction ID          */
/* to be changed 17.08.11 KB */
   struct dsd_dns_resp_1 *adsc_dnsr1;       /* structure DNS response  */
};
#endif

struct dsd_ineta_ctl_1 {                    /* control INETA           */
   struct dsd_htree1_avl_entry dsc_sort_ineta;  /* entry for sorting INETAs */
   int        imc_ineta;                    /* INETA original          */
   BOOL       boc_nat_ftp;                  /* may be used for FTP     */
};

enum ied_ctrl_tcp_ipv4_def {                /* type of IPV4 TCP half-session */
   ied_cti4_normal = 0,                     /* normal TCP half-session */
   ied_cti4_s5_client,                      /* Socks client TCP half-session */
   ied_cti4_s5_server                       /* Socks server TCP half-session */
};

struct dsd_ctrl_tcp_ipv4 {                  /* structure control TCP IPV4 */
   char       chrrc_ineta[ 2 ][ 4 ];        /* INETA client / server   */
   char       chrrc_port[ 2 ][ 2 ];         /* port client / server    */
   enum ied_ctrl_tcp_ipv4_def iec_cti4;     /* type of IPV4 TCP half-session */
};

struct dsd_sort_tcp_ipv4 {                  /* sort TCP IPV4           */
   struct dsd_htree1_avl_entry dsc_sort_ineta;  /* entry for sorting INETAs and ports */
   struct dsd_ctrl_tcp_ipv4 dsc_ct_ipv4;    /* structure control TCP IPV4 */
};

struct dsd_ctrl_tcp_ipv6 {                  /* structure control TCP IPV6 */
   char       chrrc_ineta[ 2 ][ 16 ];       /* INETA client / server   */
   char       chrrc_port[ 2 ][ 2 ];         /* port client / server    */
};

struct dsd_sort_tcp_ipv6 {                  /* sort TCP IPV6           */
   struct dsd_htree1_avl_entry dsc_sort_ineta;  /* entry for sorting INETAs and ports */
   struct dsd_ctrl_tcp_ipv6 dsc_ct_ipv6;    /* structure control TCP IPV6 */
};

struct dsd_session_timer {                  /* session timer           */
   struct dsd_session_timer *adsc_next;     /* for chaining            */
   struct dsd_tcp_session_1 *adsc_ts1;      /* structure TCP session   */
#ifdef B110903
// to-do 02.09.11 KB - move boc_ipv6 to session, one one needed
   BOOL       boc_ipv6;                     /* is IPV6, not IPV4       */
#endif
   int        imc_index;                    /* index of TCP half-session */
   HL_LONGLONG ilc_epoch_end;               /* epoch timer set         */
};

enum ied_session_notify_def {               /* type of session notify  */
   ied_se_no_idle = 0,                      /* not set                 */
   ied_se_no_act_new,                       /* active, new             */
   ied_se_no_act_old                        /* active, old             */
};

struct dsd_session_notify {                 /* session notify send possible */
   struct dsd_session_notify *adsc_next;    /* for chaining            */
   enum ied_session_notify_def iec_se_no;   /* type of session notify  */
   BOOL       boc_active;                   /* session notify is active */
};

struct dsd_nat_ftp_entry {                  /* entry for NAT of FTP server */
   UNSIG_MED  umc_ineta;                    /* INETA used              */
   struct dsd_conf_ext_1 *adsc_coe1;        /* configuration extension */
   struct dsd_nat_ftp_entry *adsc_next;     /* next entry for NAT of FTP server with same INETA */
};

struct dsd_nat_ftp_ctl_org {                /* control area for NAT of FTP server, first */
   int        imc_no_nat_ftp_entries;       /* number of entries for NAT of FTP */
   struct dsd_nat_ftp_ctl_ext *adsc_nfce;   /* control area for NAT of FTP server, extension */
   struct dsd_nat_ftp_entry dsrc_nfe[ DEF_NAT_FTP_TABLE_ORG ];  /* entries for NAT of FTP server */
};

struct dsd_nat_ftp_ctl_ext {                /* control area for NAT of FTP server, extension */
   struct dsd_nat_ftp_ctl_ext *adsc_next;   /* control area for NAT of FTP server, extension */
   struct dsd_nat_ftp_entry dsrc_nfe[ DEF_NAT_FTP_TABLE_EXT ];  /* entries for NAT of FTP server */
};

struct dsd_nat_ret_val {                    /* NAT return values       */
   int        imc_index_so_ineta_nat;       /* index of reserved INETAs for Socks servers */
   struct dsd_nat_ftp_entry *adsc_nfe;      /* chain of entries for NAT of FTP server */
};

enum ied_tce1_status {                      /* TCP session extension status */
   ied_tce1s_socks5_start = 0,              /* start of Socks5 session */
   ied_tce1s_socks5_cont_inp,               /* continue input          */
   ied_tce1s_socks5_wait_connect,           /* wait for connect of other half-session */
   ied_tce1s_ftp_start,                     /* start of FTP packet     */
   ied_tce1s_ftp_cl2se,                     /* FTP client to server    */
   ied_tce1s_ftp_se2cl,                     /* FTP server to client    */
};

/* Session Status - Socks 5                                            */
enum ied_s_stat_type {
   ied_sall_stat_bp1,                       /* begin first packet      */
   ied_s4stat_cc,                           /* get SOCKS command code  */
   ied_s4stat_dstport,                      /* Socks 4 destination port */
   ied_s4stat_dstip,                        /* Socks 4 destination IP address */
   ied_s4stat_userid,                       /* Socks 4 userid          */
   ied_s4stat_domain,                       /* Socks 4 destination domain */
   ied_s5stat_nmeth,                        /* NMETHODS                */
   ied_s5stat_meth_f,                       /* METHODS field           */
   ied_s5stat_send_resp_1,                  /* send response authentication method */
   ied_s5stat_preq_b,                       /* packet request begin    */
   ied_s5stat_preq_cmd,                     /* packet request CMD      */
   ied_s5stat_preq_rsv,                     /* packet request reserved */
   ied_s5stat_preq_atyp,                    /* packet request address type */
   ied_s5stat_preq_nooct,                   /* packet request number of octets */
   ied_s5stat_preq_daddr,                   /* packet request destination address */
   ied_s5stat_preq_dport,                   /* packet request destination port */
   ied_sall_stat_do_connect                 /* do connect now          */
};

struct dsd_tcpse1_ext_1 {                   /* TCP session extension   */
   enum ied_tce1_status iec_tce1s;          /* TCP session extension status */
// int        imc_var_1;                    /* variable one            */
#ifdef B130407
   char       chrc_buffer[ 256 ];           /* buffer for content      */
#else
   char       chrc_buffer[ 128 + 256 ];     /* buffer for content      */
#endif
};

/**
   each struct dsd_tcp_session_1 is followed by
     struct dsd_ctrl_tcp_ipv4
       or
     struct dsd_ctrl_tcp_ipv6
   when this is an IPV4 Socks session,
   two struct dsd_ctrl_tcp_ipv4 are appended
*/
struct dsd_tcp_session_1 {                  /* structure TCP session   */
   struct dsd_sdh_tcp_1 dsrc_sdh_tcp_1[ 2 ];  /* two half-sessions     */
   struct dsd_session_timer dsrc_session_timer[ 2 ];  /* session timer */
   struct dsd_session_notify dsc_session_notify;  /* session notify send possible */
// to-do 02.09.11 KB - move boc_ipv6 to session, one one needed
   BOOL       boc_ipv6;                     /* is IPV6, not IPV4       */
   struct dsd_tcpse1_ext_1 *adsc_tcpse1_ext_1;  /* TCP session extension */
};

struct dsd_subaux_userfld {                 /* for aux calls           */
   struct dsd_hl_clib_1 *adsc_hl_clib_1;
   struct dsd_sdh_tcp_1 *adsc_sdh_tcp_1;    /* TCP half-session        */
   struct dsd_session_timer *adsc_session_timer;  /* session timer     */
   HL_LONGLONG ilc_epoch;                   /* epoch current time      */
};

struct dsd_output_area_1 {                  /* output of subroutine    */
   char       *achc_lower;                  /* lower addr output area  */
   char       *achc_upper;                  /* higher addr output area */
};

enum ied_prog_status {                      /* program status          */
   ied_ps_start = 0,                        /* start of TCP session    */
   ied_ps_cont,                             /* continue TCP session    */
   ied_ps_timer                             /* processing thru timer   */
};

struct dsd_clib1_contr_1 {                  /* structure session control */
   BOOL       boc_client_header;            /* client header has been received */
   UNSIG_MED  umc_ineta_lower;              /* natted INETAs lower entry */
   UNSIG_MED  umc_ineta_upper;              /* natted INETAs upper entry */
   UNSIG_MED  umc_ineta_dns_s_1;            /* original INETA DNS server 1 */
   UNSIG_MED  umc_ineta_dns_s_2;            /* original INETA DNS server 2 */
   UNSIG_MED  umc_ineta_mask;               /* natted INETAs network mask */
   UNSIG_MED  umc_ineta_client;             /* INETA client in tunnel  */
   UNSIG_MED  umc_ineta_cl_int;             /* INETA client intern in intranet */
   UNSIG_MED  umc_ineta_max_used;           /* natted INETAs maximum used INETA */
   int        imc_alloc;                    /* number of INETAs allocated */
#ifdef B111123
   int        imc_no_qdnsr1;                /* number of responses queued */
#endif
   int        imc_session_start;            /* count times session start */
   int        imc_session_cur;              /* current sessions        */
   int        imc_session_max;              /* maximum number of sessions reached */
   HL_LONGLONG ilc_epoch_set;               /* epoch timer set         */
   struct dsd_session_timer *adsc_session_timer;  /* session timer     */
   struct dsd_session_notify *adsc_session_notify;  /* session notify send possible */
   struct dsd_cc1_ext *adsc_cc1_ext;        /* structure session control extension */
   struct dsd_htree1_avl_cntl dsc_htree1_avl_cntl_ineta;
   struct dsd_htree1_avl_cntl dsc_htree1_avl_cntl_ineta_ipv4;
   struct dsd_htree1_avl_cntl dsc_htree1_avl_cntl_ineta_ipv6;
#ifdef B110820
/* 18.08.11 KB - remove the following field, send response direct */
   struct dsd_query_dns_resp_1 dsrc_qdnsr1[ MAX_DNS_QUEUED ];  /* structure query DNS response */
#endif
   struct dsd_ineta_ctl_1 dsrc_ic1[ DEF_INETA_TABLE_ORG ];  /* control INETA */
#ifdef DEBUG_101208_01
   char       chrc_display[ 64 * 1024 ];    /* display area            */
#endif
#ifdef PACKET_LOSS_01                       /* lose packets            */
   int        imc_packet_loss_01;           /* count to lose packets   */
#endif
#ifdef TRACEHL_111004
   int        imrl_trace_lno[ TRACEHL_111004 ];
#endif
};

struct dsd_cc1_ext {                        /* structure session control extension */
   struct dsd_cc1_ext *adsc_next;           /* for chaining            */
   struct dsd_ineta_ctl_1 dsrc_ic1[ DEF_INETA_TABLE_EXT ];  /* control INETA */
};

static const char * achrs_node_main[] = {
   "NAT-control",
   "display-natted-inetas",
   "integrated-DNS-server",
   "ALG-SIP",
   "Socks-server",
   "FTP-server",
   "exclude-DNS-name",
   "DNS-ineta"
};

static const char * achrs_node_nat_contr[] = {
   "ineta-use-1",
   "ineta-use-2"
};

static const char * achrs_node_dnsi1[] = {
   "DNS-name",
   "ineta"
};

static const char * achrs_node_dns_port[] = {
   "DNS-name",
   "TCP-port"
};

static const unsigned char ucrs_recv_contr_01[] = {
   'S', 'T', 'A', 'R', 'T'
};

static const unsigned char ucrs_recv_contr_02[] = {
   'R', 'E', 'C', 'O', 'N', 'N', 'E', 'C',
   'T'
};

static const unsigned char ucrs_recv_locineta[] = {
   'L', 'O', 'C', 'A', 'L', '-', 'I', 'N',
   'E', 'T', 'A', '='
};

static const unsigned char ucrs_send_stop[] = {
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   0X05, '0',
#else
   '0', 0X04,
#endif
   'S', 'T', 'O', 'P'
};

static const unsigned char ucrs_ctrl_ipcp[] = {
   0X80, 0X21
};

/* 1 = digit                                                           */
/* 2 = dot                                                             */
/* 3 = separator                                                       */
/* 4 = character                                                       */
/* 5 = invalid                                                         */
static const unsigned char ucrs_tab_char_sip[ 256 ] = {
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 3, 5, 5,  /* 0X00 till 0X0F  */
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,  /* 0X10 till 0X1F  */
   3, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 3, 5, 2, 5,  /* 0X20 till 0X2F  */
   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 3, 5, 3, 3, 5,  /* 0X30 till 0X3F  */
   3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,  /* 0X40 till 0X4F  */
   4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5,  /* 0X50 till 0X5F  */
   5, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,  /* 0X60 till 0X6F  */
   4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5,  /* 0X70 till 0X7F  */
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,  /* 0X80 till 0X8F  */
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,  /* 0X90 till 0X9F  */
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,  /* 0XA0 till 0XAF  */
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,  /* 0XB0 till 0XBF  */
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,  /* 0XC0 till 0XCF  */
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,  /* 0XD0 till 0XDF  */
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,  /* 0XE0 till 0XEF  */
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5   /* 0XF0 till 0XFF  */
};

/* invalid - not found - part 1                                        */
static const unsigned char chrs_dns_r_i_1[] = {
   (unsigned char) 0X85, (unsigned char) 0X83,  /* Response etc.       */
   (unsigned char) 0X00, (unsigned char) 0X01,  /* QDCOUNT             */
   (unsigned char) 0X00, (unsigned char) 0X00,  /* ANCOUNT             */
   (unsigned char) 0X00, (unsigned char) 0X00,  /* NSCOUNT             */
   (unsigned char) 0X00, (unsigned char) 0X00,  /* ARCOUNT             */
};

/* all types of response - part 2                                      */
static const unsigned char chrs_dns_r_a_2[] = {
   (unsigned char) 0X00, (unsigned char) 0X01,  /* Type A 0001         */
   (unsigned char) 0X00, (unsigned char) 0X01,  /* Class IN 0001       */
};

/* successful - found - part 1                                         */
static const unsigned char chrs_dns_r_s_1[] = {
   (unsigned char) 0X85, (unsigned char) 0X80,  /* Response etc.       */
   (unsigned char) 0X00, (unsigned char) 0X01,  /* QDCOUNT             */
   (unsigned char) 0X00, (unsigned char) 0X01,  /* ANCOUNT             */
   (unsigned char) 0X00, (unsigned char) 0X00,  /* NSCOUNT             */
   (unsigned char) 0X00, (unsigned char) 0X00,  /* ARCOUNT             */
};

/* successful - found - part 3 - with INETA                            */
static const unsigned char chrs_dns_r_s_3[] = {
   (unsigned char) 0XC0, (unsigned char) 0X0C,  /* DNS name compressed */
   (unsigned char) 0X00, (unsigned char) 0X01,  /* Type A 0001         */
   (unsigned char) 0X00, (unsigned char) 0X01,  /* Class IN 0001       */
   (unsigned char) 0X00, (unsigned char) 0X01,  /* Type to live        */
   (unsigned char) 0X51, (unsigned char) 0X80,  /* 1 Day               */
   (unsigned char) 0X00, (unsigned char) 0X04,  /* Data length         */
};

/* DNS query part one                                                  */
static const unsigned char chrs_dns_query_1[] = {
   (unsigned char) 0X01, (unsigned char) 0X00,  /* Flags standard query */
   (unsigned char) 0X00, (unsigned char) 0X01,  /* QDCOUNT             */
   (unsigned char) 0X00, (unsigned char) 0X00,  /* ANCOUNT             */
   (unsigned char) 0X00, (unsigned char) 0X00,  /* NSCOUNT             */
   (unsigned char) 0X00, (unsigned char) 0X00,  /* ARCOUNT             */
};

/* DNS query part two                                                  */
static const unsigned char chrs_dns_query_2[] = {
   (unsigned char) 0X00, (unsigned char) 0X01,  /* Type A 0001         */
   (unsigned char) 0X00, (unsigned char) 0X01,  /* Class IN 0001       */
};

static const unsigned char chrs_port_dns[] = {
   (unsigned char) 0,
   (unsigned char) 53
};

static const unsigned char chrs_port_sip[] = {  /* port 5060           */
   (unsigned char) 0X13,
   (unsigned char) 0XC4
};

static const unsigned char ucrs_sip_cont_len[] = {  /* SIP Content-Length */
   CHAR_CR, CHAR_LF,
   'C', 'o', 'n', 't', 'e', 'n', 't', '-',
   'L', 'e', 'n', 'g', 't', 'h', ':'
};

/* Socks 5 response no authentication                                  */
static const char chrs_socks5_resp_noauth[] = { 0X05, 0X00 };

static const unsigned char ucrs_ftp_cl2se_c1[] = {  /* FTP client to server command 1 */
   'P', 'O', 'R', 'T', ' '
};

static const unsigned char ucrs_ftp_se2cl_c1[] = {  /* FTP server to client command 1 */
   '2', '2', '7', ' '
};

static const unsigned char ucrs_socks_4_se2cl_dns[] = {  /* Socks 4 response DNS not configured */
   0,                                       /* VN reply code           */
   91,                                      /* CD request failed       */
   0, 0,                                    /* insert port             */
   0, 0, 0, 0                               /* INETA                   */
};

static const unsigned char ucrs_socks_5_se2cl_dns[] = {  /* Socks 5 response DNS not configured */
   0X05,                                    /* socks response          */
   0X01,                                    /* general SOCKS server failure */
   0,
   D_DEST_IPV4ADDR,                         /* ATYP                    */
   0, 0, 0, 0, 0, 0
};

static const unsigned char ucrs_crlf[] = {  /* carriage-return line-feed */
   CHAR_CR, CHAR_LF
};

/**
   see http://www.duxcw.com/faq/network/privip.htm
*/
static const unsigned char ucrrs_private_inetas[8][4] = {  /* private INETAs */
   {
     10, 0, 0, 0
   },
   {
     10, 255, 255, 255
   },
   {
     169, 254, 0, 0
   },
   {
     169, 254, 255, 255
   },
   {
     172, 16, 0, 0
   },
   {
     172, 31, 255, 255
   },
   {
     192, 168, 0, 0
   },
   {
     192, 168, 255, 255
   }
};

static int m_get_dns_name( char *, int, HL_WCHAR * );
static BOOL m_check_dns_n_double( char *achp_dns_n, int imp_len_dns_n,
                                  HL_WCHAR *awcp_dns_name,
                                  struct dsd_conf_ext_1 *adsp_coe1,
                                  struct dsd_clib1_conf *adsp_clco,
                                  struct dsd_sdh_call_1 *adsp_sdh_call_1 );
static BOOL m_sub_aux( void *, int, void *, int );
static void m_build_header_ipv4( char *, struct dsd_ctrl_tcp_ipv4 *, int, int );
static void m_build_header_ipv6( char *, struct dsd_ctrl_tcp_ipv6 *, int, int );
static int m_get_ineta_w( UNSIG_MED *, HL_WCHAR * );
static int m_get_ineta_a( UNSIG_MED *, char *, char * );
static BOOL m_get_decno_6( char *achp_out, char *achp_value, char *achp_end );
static BOOL m_check_private_ineta( char * );
static int m_natted_ineta( struct dsd_hl_clib_1 *, char *, struct dsd_conf_ext_1 *, BOOL );
static int m_original_ineta( struct dsd_hl_clib_1 *, char *, struct dsd_nat_ret_val * );
static int m_cmp_ineta_nat( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static int m_cmp_ineta_ipv4( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static int m_cmp_ineta_ipv6( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static int m_sdh_printf( struct dsd_sdh_call_1 *, const char *, ... );
static int m_get_date_time( char *achp_buff );
static void m_sdh_console_out( struct dsd_sdh_call_1 *, char *achp_buff, int implength );
static void m_dump_gather( struct dsd_sdh_call_1 *, struct dsd_gather_i_1 *, int );
#ifdef CHECK_OUTPUT_01
static void m_check_output_01( struct dsd_hl_clib_1 * );
#endif
#ifdef TRACEHL_INETA_01
static void m_trineta_print_01( char *achp_buffer, struct dsd_ctrl_tcp_ipv4 *adsp_ct_ipv4, int imp_cl_se );
#endif
#ifdef TRACEHL_TIME
static HL_LONGLONG m_get_epoch_ms( void );
#endif

static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

#ifdef DEBUG_101207_01
static BOOL   bos_debug_01 = FALSE;
#endif

/** subroutine to process the configuration data                       */
extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf( struct dsd_hl_clib_dom_conf *adsp_hlcldomf ) {
   BOOL       bol1;                         /* working variable        */
   BOOL       bol_disp_nat_i_conf;          /* display-natted-INETAs configured */
   BOOL       bol_int_dsn_s_conf;           /* integrated-DNS-server configured */
   BOOL       bol_alg_sip_conf;             /* use ALG for SIP VoIP protocol configured */
   int        iml1, iml2, iml3;             /* working variables       */
   int        iml_cmp;                      /* compare values          */
   int        iml_val;                      /* value in array          */
   int        iml_ineta_use;                /* entry ineta-use-n       */
   int        iml_flag_nat_control;         /* flag NAT-control defined */
   UNSIG_MED  uml_ineta_w1;                 /* working-variable INETA  */
   UNSIG_MED  uml_ineta_w2;                 /* working-variable INETA  */
   UNSIG_MED  uml_ineta_w3;                 /* working-variable INETA  */
   UNSIG_MED  *auml_w1;                     /* working-variable        */
   char       *achl_stor_new;               /* new storage             */
   char       *achl_stor_old;               /* old storage             */
   char       *achl_w1;                     /* working-variable        */
   DOMNode    *adsl_node_1;                 /* node for navigation     */
   DOMNode    *adsl_node_2;                 /* node for navigation     */
   DOMNode    *adsl_node_3;                 /* node for navigation     */
   HL_WCHAR   *awcl1;                       /* working variable        */
   HL_WCHAR   *awcl_name;                   /* name of Node            */
   HL_WCHAR   *awcl_value;                  /* value of Node           */
   HL_WCHAR   *awcl_dns_name;               /* save DNS name           */
   struct dsd_ineta_single_ret dsl_ineta_sret_work_1;
   struct dsd_conf_ext_1 *adsl_coe1_new;    /* new configuration extension */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
   struct dsd_clib1_conf dsl_clco;          /* configuration data      */
   struct dsd_conf_ext_1 dsl_coe1;          /* configuration extension */
   unsigned char chrl_ineta_w1[4];          /* INETA                   */
   char       chrl_dns_name[256];           /* for DNS name            */
   UNSIG_MED  umrl_ineta[ MAX_DNS_INETA ];  /* for INETAs              */

#ifdef TRACEHL1
   printf( "xl-sdh-ppp-pf-07-l%05d-T m_hlclib_conf() called adsp_hlcldomf=%p\n",
           __LINE__, adsp_hlcldomf );
#endif
   dsl_sdh_call_1.amc_aux = adsp_hlcldomf->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_hlcldomf->vpc_userfld;  /* User Field Subroutine */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-I V1.2 " __DATE__ " m_hlclib_conf() called",
                 __LINE__ );
#else
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-I V2.1 " __DATE__ " m_hlclib_conf() called",
                 __LINE__ );
#endif
#ifdef TRACEHL_090905
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T sizeof(struct dsd_hl_clib_1)=%d offsetof( ..., boc_callrevdir )=%d TRUE=%d.",
                 __LINE__, sizeof(struct dsd_hl_clib_1), offsetof( struct dsd_hl_clib_1, boc_callrevdir ), TRUE );
#endif

   if (adsp_hlcldomf->adsc_node_conf == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_hlclib_conf() no Node configured",
                   __LINE__ );
     return FALSE;
   }

   /* getFirstChild()                                                  */
   adsl_node_1 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsp_hlcldomf->adsc_node_conf,
                                                          ied_hlcldom_get_first_child );
   if (adsl_node_1 == NULL) {               /* no Node returned        */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_hlclib_conf() no getFirstChild()",
                   __LINE__ );
     return FALSE;
   }

   memset( &dsl_clco, 0, sizeof(struct dsd_clib1_conf) );  /* configuration data */
   iml_flag_nat_control = 0;                /* flag NAT-control defined */
   achl_stor_new = NULL;                    /* new storage             */
   bol_disp_nat_i_conf = FALSE;             /* display-natted-INETAs configured */
   bol_int_dsn_s_conf = FALSE;              /* integrated-DNS-server configured */
   bol_alg_sip_conf = FALSE;                /* use ALG for SIP VoIP protocol configured */

   pdomc20:                                 /* process DOM node        */
   if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_1, ied_hlcldom_get_node_type ))
         != DOMNode::ELEMENT_NODE) {
     goto pdomc80;                          /* get next sibling        */
   }
   awcl1 = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_1, ied_hlcldom_get_node_name );
#ifdef TRACEHL1
   printf( "xl-sdh-ppp-pf-07-l%05d-T m_hlclib_conf() found node %S\n", __LINE__, awcl1 );
#endif
   iml_val = sizeof(achrs_node_main) / sizeof(achrs_node_main[0]);
   do {
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl1, (char *) achrs_node_main[ iml_val - 1 ] );
     if ((bol1) && (iml_cmp == 0)) break;   /* strings are equal       */
     iml_val--;
   } while (iml_val > 0);
   if (iml_val == 0) {                      /* keyword not found       */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error first element name \"%(ux)s\" undefined - ignored",
                   __LINE__, awcl1 );
     goto pdomc80;                          /* DOM node processed - next */
   }
   adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_1,
                                                          ied_hlcldom_get_first_child );  /* getFirstChild() */
   if (adsl_node_2 == NULL) {               /* no child found          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error \"%(ux)s\" has no child - ignored",
                   __LINE__, awcl1 );
     goto pdomc80;                          /* DOM node processed - next */
   }
   switch (iml_val) {                       /* check keyword           */
     case 2:
       goto p_disp_nat_i_00;                /* display-natted-inetas   */
     case 3:
       goto p_int_dsn_s_00;                 /* integrated-DNS-server   */
     case 4:
       goto p_alg_sip_00;                   /* ALG-SIP                 */
     case 5:
       goto p_socks_se_00;                  /* Socks-server            */
     case 6:
       goto p_ftp_se_00;                    /* FTP-server              */
     case 7:
       goto p_excl_dns_00;                  /* exclude DNS name        */
     case 8:
       goto p_dns_ineta_00;                 /* retrieve DNS-ineta      */
   }
   /* is NAT-control                                                   */
   if (iml_flag_nat_control) {              /* flag NAT-control defined */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error \"%(ux)s\" defined double - new values ignored",
                   __LINE__, awcl1 );
     goto pdomc80;                          /* DOM node processed - next */
   }

   pdomc40:                                 /* process DOM node stage 2 */
   if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type ))
         != DOMNode::ELEMENT_NODE) {
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   awcl_name = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_name );
#ifdef TRACEHL1
   printf( "xl-sdh-ppp-pf-07-l%05d-T m_hlclib_conf() found node %S\n", __LINE__, awcl_name );
#endif
   iml_ineta_use = sizeof(achrs_node_nat_contr) / sizeof(achrs_node_nat_contr[0]) - 1;
   do {
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl_name, (char *) achrs_node_nat_contr[ iml_ineta_use ] );
     if ((bol1) && (iml_cmp == 0)) break;   /* strings are equal       */
     iml_ineta_use--;                       /* decrement index         */
   } while (iml_ineta_use >= 0);
   if (iml_ineta_use < 0) {                 /* parameter not found     */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"NAT-control\" child \"%(ux)s\" not defined - ignored",
                   __LINE__, awcl_name );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                          ied_hlcldom_get_first_child );  /* getFirstChild() */
   if (adsl_node_3 == NULL) {               /* no child found          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"NAT-control\" \"%(ux)s\" has no child - ignored",
                   __LINE__, awcl_name );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   do {                                     /* search value            */
     if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_3, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) break;
     adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_3,
                                                            ied_hlcldom_get_next_sibling );
   } while (adsl_node_3);
   if (adsl_node_3 == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"NAT-control\" \"%(ux)s\" no value found - ignored",
                   __LINE__, awcl_name );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_3, ied_hlcldom_get_node_value );  /* getNodeValue() */
   if (iml_flag_nat_control & (1 << iml_ineta_use)) {  /* flag NAT-control defined */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error \"NAT-control\" element \"%s\" value \"%(ux)s\" already defined before - ignored",
                   __LINE__, achrs_node_nat_contr[ iml_ineta_use ], awcl_value );
     goto pdomc56;                          /* get next sibling stage 2 */
   }

   /* INETA with prefix                                                */
   iml1 = HL_WCSLEN( awcl_value );          /* length of parameter     */
   while ((iml1 > 0) && (*(awcl_value + iml1 - 1) != '/')) iml1--;
   if (iml1 == 0) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error \"NAT-control\" element \"%s\" value \"%(ux)s\" could not find \"/\" for prefix - ignored",
                   __LINE__, achrs_node_nat_contr[ iml_ineta_use ], awcl_value );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   if ((iml1 - 1) > LEN_INETA_PR_IPV4) {    /* INETA too long          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error \"NAT-control\" element \"%s\" value \"%(ux)s\" INETA length %d too long - ignored",
                   __LINE__, achrs_node_nat_contr[ iml_ineta_use ], awcl_value, iml1 - 1 );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   awcl1 = awcl_value + iml1;               /* here starts prefix      */
   iml2 = 0;                                /* clear result            */
   while (TRUE) {                           /* loop over digits        */
     if (*awcl1 == 0) break;                /* end of digits           */
     if ((*awcl1 < '0') || (*awcl1 > '9')) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error \"NAT-control\" element \"%s\" value \"%(ux)s\" invalid digit \"%(ux)c\" in prefix found - ignored",
                     __LINE__, achrs_node_nat_contr[ iml_ineta_use ], awcl_value, *awcl1 );
       goto pdomc56;                        /* get next sibling stage 2 */
     }
     iml2 *= 10;                            /* shift old digits        */
     iml2 += *awcl1++ - '0';                /* add new digit           */
   }
   if ((iml2 <= 0) || (iml2 > 128)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error \"NAT-control\" element \"%s\" \"%(ux)s\" prefix %d out of range - ignored",
                   __LINE__, achrs_node_nat_contr[ iml_ineta_use ], awcl_value, iml2 );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   iml1--;                                  /* subtract separator      */
   if (iml1 <= 0) {                         /* too short for INETA     */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error \"NAT-control\" element \"%s\" value \"%(ux)s\" INETA length %d too short - ignored",
                   __LINE__, achrs_node_nat_contr[ iml_ineta_use ], awcl_value, iml1 );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   bol1 = m_get_single_ineta( &iml3, &dsl_ineta_sret_work_1,
                              awcl_value, iml1, ied_chs_utf_16 );
   if (bol1 == FALSE) {                     /* error occured           */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error \"NAT-control\" element \"%s\" value \"%(ux)s\" INETA invalid, error %d - ignored",
                   __LINE__, achrs_node_nat_contr[ iml_ineta_use ], awcl_value, iml3 );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   if (dsl_ineta_sret_work_1.usc_family != AF_INET) {  /* family IPV4 / IPV6 */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error \"NAT-control\" element \"%s\" value \"%(ux)s\" INETA not IPV4 - ignored",
                   __LINE__, achrs_node_nat_contr[ iml_ineta_use ], awcl_value );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   if (iml2 > (dsl_ineta_sret_work_1.usc_length * 8)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error \"NAT-control\" element \"%s\" value \"%(ux)s\" prefix %d out of range - ignored",
                   __LINE__, achrs_node_nat_contr[ iml_ineta_use ], awcl_value, iml2 );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   memcpy( &uml_ineta_w1, dsl_ineta_sret_work_1.chrc_ineta, sizeof(UNSIG_MED) );
   uml_ineta_w3 = (UNSIG_MED) 0XFFFFFFFF;   /* network mask            */
   iml1 = sizeof(UNSIG_MED);
   iml3 = sizeof(UNSIG_MED) * 8 - iml2;
   do {                                     /* loop over bytes on INETA */
     iml1--;                                /* decrement index         */
     if (iml3 >= 8) {
       *((unsigned char *) &uml_ineta_w1 + iml1) = 0;
       *((unsigned char *) &uml_ineta_w3 + iml1) = 0;
       iml3 -= 8;
       if (iml3 == 0) break;
     } else {
       *((unsigned char *) &uml_ineta_w1 + iml1) &= (unsigned char) (-1 << iml3);
       *((unsigned char *) &uml_ineta_w3 + iml1) &= (unsigned char) (-1 << iml3);
       break;
     }
   } while (iml1 > 0);
   if (memcmp( &uml_ineta_w1, dsl_ineta_sret_work_1.chrc_ineta, sizeof(UNSIG_MED) )) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error \"NAT-control\" element \"%s\" value \"%(ux)s\" INETA last bits not zero - ignored",
                   __LINE__, achrs_node_nat_contr[ iml_ineta_use ], awcl_value );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   uml_ineta_w2 = uml_ineta_w1;
   m_ineta_op_add( (char *) &uml_ineta_w2, sizeof(UNSIG_MED), (1 << (sizeof(UNSIG_MED) * 8 - iml2)) - 1 );
   if (iml_ineta_use == 0) {                /* entry ineta-use-n       */
     dsl_clco.umc_conf_ineta_1_lower = uml_ineta_w1;  /* configured INETAs 1 lower value */
     dsl_clco.umc_conf_ineta_1_upper = uml_ineta_w2;  /* configured INETAs 1 upper value */
     dsl_clco.umc_conf_ineta_1_mask = uml_ineta_w3;  /* configured INETAs 1 network mask */
   } else {
     dsl_clco.umc_conf_ineta_2_lower = uml_ineta_w1;  /* configured INETAs 2 lower value */
     dsl_clco.umc_conf_ineta_2_upper = uml_ineta_w2;  /* configured INETAs 2 upper value */
     dsl_clco.umc_conf_ineta_2_mask = uml_ineta_w3;  /* configured INETAs 2 network mask */
   }
   iml_flag_nat_control |= 1 << iml_ineta_use;  /* flag NAT-control defined */

   pdomc56:                                 /* get next sibling stage 2 */
   adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                          ied_hlcldom_get_next_sibling );
   if (adsl_node_2) goto pdomc40;           /* process DOM node stage 2 */
#ifdef TRACEHL1
   m_sdh_console_out( &dsl_sdh_call_1, (char *) &dsl_clco, sizeof(struct dsd_clib1_conf) );
#endif
   if (iml_flag_nat_control != 3) {         /* flag NAT-control defined */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error \"NAT-control\" not all values ineta-use-1 and ineta-use-2 defined - NAT-control ignored",
                   __LINE__ );
     iml_flag_nat_control = 0;              /* flag NAT-control defined */
   }
   goto pdomc80;                            /* DOM node processed - next */

   p_disp_nat_i_00:                         /* display-natted-inetas   */
   if (bol_disp_nat_i_conf) {               /* display-natted-INETAs configured */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"display-natted-inetas\" defined double - ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   do {                                     /* search value            */
     if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) break;
     adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                            ied_hlcldom_get_next_sibling );
   } while (adsl_node_2);
   if (adsl_node_2 == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"display-natted-inetas\" no value found - ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_value );  /* getNodeValue() */
   while (TRUE) {                           /* pseudo-loop             */
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "YES" );
     if ((bol1) && (iml_cmp == 0)) {        /* strings are equal       */
       dsl_clco.boc_disp_inetas = TRUE;     /* display natted INETAs   */
       break;
     }
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "NO" );
     if ((bol1) && (iml_cmp == 0)) break;   /* strings are equal       */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"display-natted-inetas\" value neither YES nor NO - \"%(ux)s\" - ignored",
                   __LINE__, awcl_value );
     goto pdomc80;                          /* DOM node processed - next */
   } while (FALSE);
   bol_disp_nat_i_conf = TRUE;              /* display-natted-INETAs configured */
   goto pdomc80;                            /* DOM node processed - next */

   p_int_dsn_s_00:                          /* integrated-DNS-server   */
   if (bol_int_dsn_s_conf) {                /* integrated-DNS-server configured */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"integrated-DNS-server\" defined double - ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   do {                                     /* search value            */
     if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) break;
     adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                            ied_hlcldom_get_next_sibling );
   } while (adsl_node_2);
   if (adsl_node_2 == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"integrated-DNS-server\" no value found - ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_value );  /* getNodeValue() */
   while (TRUE) {                           /* pseudo-loop             */
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "YES" );
     if ((bol1) && (iml_cmp == 0)) {        /* strings are equal       */
       dsl_clco.boc_internal_dns_server = TRUE;  /* use internal DNS server */
       break;
     }
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "NO" );
     if ((bol1) && (iml_cmp == 0)) break;   /* strings are equal       */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"integrated-DNS-server\" value neither YES nor NO - \"%(ux)s\" - ignored",
                   __LINE__, awcl_value );
     goto pdomc80;                          /* DOM node processed - next */
   } while (FALSE);
   bol_int_dsn_s_conf = TRUE;               /* integrated-DNS-server configured */
   goto pdomc80;                            /* DOM node processed - next */

   p_alg_sip_00:                            /* ALG-SIP                 */
   if (bol_alg_sip_conf) {                  /* use ALG for SIP VoIP protocol configured */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"ALG-SIP\" defined double - ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   do {                                     /* search value            */
     if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) break;
     adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                            ied_hlcldom_get_next_sibling );
   } while (adsl_node_2);
   if (adsl_node_2 == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"ALG-SIP\" no value found - ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_value );  /* getNodeValue() */
   while (TRUE) {                           /* pseudo-loop             */
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "YES" );
     if ((bol1) && (iml_cmp == 0)) {        /* strings are equal       */
       dsl_clco.boc_alg_sip = TRUE;         /* use ALG for SIP VoIP protocol */
       break;
     }
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "NO" );
     if ((bol1) && (iml_cmp == 0)) break;   /* strings are equal       */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"ALG-SIP\" value neither YES nor NO - \"%(ux)s\" - ignored",
                   __LINE__, awcl_value );
     goto pdomc80;                          /* DOM node processed - next */
   } while (FALSE);
   bol_alg_sip_conf = TRUE;                 /* use ALG for SIP VoIP protocol configured */
   goto pdomc80;                            /* DOM node processed - next */

   p_socks_se_00:                           /* Socks-server            */
   memset( &dsl_coe1, 0, sizeof(struct dsd_conf_ext_1) );  /* configuration extension */

   p_socks_se_20:                           /* process DOM node stage 2 */
   if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type ))
         != DOMNode::ELEMENT_NODE) {
     goto p_socks_se_60;                    /* get next sibling stage 2 */
   }
   awcl_name = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_name );
#ifdef TRACEHL1
   printf( "xl-sdh-ppp-pf-07-l%05d-T m_hlclib_conf() found node %S\n", __LINE__, awcl_name );
#endif
   iml_val = sizeof(achrs_node_dns_port) / sizeof(achrs_node_dns_port[0]);
   do {
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl_name, (char *) achrs_node_dns_port[ iml_val - 1 ] );
     if ((bol1) && (iml_cmp == 0)) break;   /* strings are equal       */
     iml_val--;                             /* decrement index         */
   } while (iml_val > 0);
   if (iml_val == 0) {                      /* parameter not found     */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"Socks-server\" child \"%(ux)s\" not defined - ignored",
                   __LINE__, awcl_name );
     goto p_socks_se_60;                    /* get next sibling stage 2 */
   }
   adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                          ied_hlcldom_get_first_child );  /* getFirstChild() */
   if (adsl_node_3 == NULL) {               /* no child found          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"Socks-server\" \"%(ux)s\" has no child - ignored",
                   __LINE__, awcl_name );
     goto p_socks_se_60;                    /* get next sibling stage 2 */
   }
   do {                                     /* search value            */
     if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_3, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) break;
     adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_3,
                                                            ied_hlcldom_get_next_sibling );
   } while (adsl_node_3);
   if (adsl_node_3 == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"Socks-server\" \"%(ux)s\" no value found - ignored",
                   __LINE__, awcl_name );
     goto p_socks_se_60;                    /* get next sibling stage 2 */
   }
   awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_3, ied_hlcldom_get_node_value );  /* getNodeValue() */
   if (iml_val != 1) goto p_socks_se_40;    /* retrieve TCP-port       */
   /* retrieve DNS-name                                                */
   if (dsl_coe1.imc_len_dns_n > 0) {        /* check length DNS name   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"Socks-server\" \"DNS-name\" defined double - \"%(ux)s\" ignored",
                   __LINE__, awcl_value );
     goto p_socks_se_60;                    /* get next sibling stage 2 */
   }
   dsl_coe1.imc_len_dns_n = m_get_dns_name( chrl_dns_name, sizeof(chrl_dns_name), (HL_WCHAR *) awcl_value );
   if (dsl_coe1.imc_len_dns_n < 0) {        /* DNS name is not valid   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"Socks-server\" \"DNS-name\" value \"%(ux)s\" invalid - ignored",
                   __LINE__, awcl_value );
   }
   awcl_dns_name = awcl_value;              /* save DNS name           */
   goto p_socks_se_60;                      /* get next sibling stage 2 */

   p_socks_se_40:                           /* retrieve TCP-port       */
   if (dsl_coe1.imc_port > 0) {             /* TCP port already defined */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"Socks-server\" \"TCP-port\" value \"%(ux)s\" ignored - already defined before",
                   __LINE__, awcl_value );
     goto p_socks_se_60;                    /* get next sibling stage 2 */
   }
   dsl_coe1.imc_port = m_get_wc_number( (HL_WCHAR *) awcl_value );
   if (dsl_coe1.imc_port < 0) {             /* no valid number found   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"Socks-server\" \"TCP-port\" value \"%(ux)s\" invalid - ignored",
                   __LINE__, awcl_value );
     goto p_socks_se_60;                    /* get next sibling stage 2 */
   }
   if (   (dsl_coe1.imc_port == 0)
       || (dsl_coe1.imc_port >= 0X010000)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"Socks-server\" \"TCP-port\" value \"%(ux)s\" / %d out of range - ignored",
                   __LINE__, awcl_value, dsl_coe1.imc_port );
     goto p_socks_se_60;                    /* get next sibling stage 2 */
   }

   p_socks_se_60:                           /* get next sibling stage 2 */
   adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                          ied_hlcldom_get_next_sibling );
   if (adsl_node_2) goto p_socks_se_20;     /* process DOM node stage 2 */

   if (dsl_coe1.imc_len_dns_n <= 0) {       /* DNS name is not defined */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"Socks-server\" no \"DNS-name\" defined - ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
#ifdef XYZ1
   bol1 = m_check_dns_n_double( chrl_dns_name, dsl_coe1.imc_len_dns_n, (struct dsd_clib1_conf *) achl_stor_new );
   if (bol1 == FALSE) {                     /* DNS name already defined */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"Socks-server\" \"DNS-name\" value \"%(ux)s\" DNS-name already configured before - ignored",
                   __LINE__, awcl_dns_name );
     goto pdomc80;                          /* DOM node processed - next */
   }
#endif
   if (dsl_coe1.imc_port <= 0) {            /* port not filled         */
     dsl_coe1.imc_port = D_PORT_SOCKS;      /* default TCP port of Socks */
   }
   dsl_coe1.iec_coe = ied_coe_socks_se;     /* Socks server            */
   bol1 = m_check_dns_n_double( chrl_dns_name, dsl_coe1.imc_len_dns_n,
                                awcl_dns_name,
                                &dsl_coe1,
                                (struct dsd_clib1_conf *) achl_stor_new,
                                &dsl_sdh_call_1 );
   if (bol1 == FALSE) {                     /* DNS name already defined */
     goto pdomc80;                          /* DOM node processed - next */
   }
   if (dsl_clco.imc_no_s5_ineta_nat <= dsl_coe1.imc_index_so_ineta_nat) {  /* index of reserved INETAs for Socks servers */
     dsl_clco.imc_no_s5_ineta_nat = dsl_coe1.imc_index_so_ineta_nat + 1;  /* index of reserved INETAs for Socks servers */
   }
   dsl_coe1.imc_len_entry = sizeof(chrs_dns_r_s_1) + dsl_coe1.imc_len_dns_n + sizeof(chrs_dns_r_a_2);
   dsl_coe1.imc_len_stor = (sizeof(struct dsd_conf_ext_1)
                               + dsl_coe1.imc_len_entry
                               + sizeof(void *) - 1)
                             & (0 - sizeof(void *));
   iml1 = dsl_clco.imc_len_conf_ext_1;      /* save old length         */
   dsl_clco.imc_len_conf_ext_1 += dsl_coe1.imc_len_stor;
   achl_stor_old = achl_stor_new;           /* save storage            */
   bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                  DEF_AUX_MEMGET,
                                  &achl_stor_new,
                                  sizeof(struct dsd_clib1_conf)
                                    + dsl_clco.imc_len_conf_ext_1 );
   if (bol1 == FALSE) {                     /* error occured           */
     return FALSE;
   }
   if (achl_stor_old) {                     /* copy old values         */
     memcpy( achl_stor_new + sizeof(struct dsd_clib1_conf),
             achl_stor_old + sizeof(struct dsd_clib1_conf),
             iml1 );
     bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                    DEF_AUX_MEMFREE,
                                    &achl_stor_old,
                                    sizeof(struct dsd_clib1_conf)
                                      + iml1 );
   }
   /* new configuration extension                                      */
   adsl_coe1_new
     = (struct dsd_conf_ext_1 *) (achl_stor_new + sizeof(struct dsd_clib1_conf)
                                    + iml1 );
   memcpy( adsl_coe1_new, &dsl_coe1, sizeof(struct dsd_conf_ext_1) );
   achl_w1 = (char *) (adsl_coe1_new + 1);
   memcpy( achl_w1, chrs_dns_r_s_1, sizeof(chrs_dns_r_s_1) );
   /* ANCOUNT already set to one (1)                                   */
   achl_w1 += sizeof(chrs_dns_r_s_1);
   memcpy( achl_w1, chrl_dns_name, dsl_coe1.imc_len_dns_n );
   achl_w1 += dsl_coe1.imc_len_dns_n;
   memcpy( achl_w1, chrs_dns_r_a_2, sizeof(chrs_dns_r_a_2) );
   memcpy( achl_stor_new, &dsl_clco, sizeof(struct dsd_clib1_conf) );
   goto pdomc80;                            /* DOM node processed - next */

   p_ftp_se_00:                             /* FTP-server              */
   memset( &dsl_coe1, 0, sizeof(struct dsd_conf_ext_1) );  /* configuration extension */

   p_ftp_se_20:                             /* process DOM node stage 2 */
   if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type ))
         != DOMNode::ELEMENT_NODE) {
     goto p_ftp_se_80;                      /* get next sibling stage 2 */
   }
   awcl_name = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_name );
#ifdef TRACEHL1
   printf( "xl-sdh-ppp-pf-07-l%05d-T m_hlclib_conf() found node %S\n", __LINE__, awcl_name );
#endif
   iml_val = sizeof(achrs_node_dns_port) / sizeof(achrs_node_dns_port[0]);
   do {
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl_name, (char *) achrs_node_dns_port[ iml_val - 1 ] );
     if ((bol1) && (iml_cmp == 0)) break;   /* strings are equal       */
     iml_val--;                             /* decrement index         */
   } while (iml_val > 0);
   if (iml_val == 0) {                      /* parameter not found     */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"FTP-server\" child \"%(ux)s\" not defined - ignored",
                   __LINE__, awcl_name );
     goto p_ftp_se_80;                      /* get next sibling stage 2 */
   }
   adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                          ied_hlcldom_get_first_child );  /* getFirstChild() */
   if (adsl_node_3 == NULL) {               /* no child found          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"FTP-server\" \"%(ux)s\" has no child - ignored",
                   __LINE__, awcl_name );
     goto p_ftp_se_80;                      /* get next sibling stage 2 */
   }
   do {                                     /* search value            */
     if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_3, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) break;
     adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_3,
                                                            ied_hlcldom_get_next_sibling );
   } while (adsl_node_3);
   if (adsl_node_3 == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"FTP-server\" \"%(ux)s\" no value found - ignored",
                   __LINE__, awcl_name );
     goto p_ftp_se_80;                      /* get next sibling stage 2 */
   }
   awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_3, ied_hlcldom_get_node_value );  /* getNodeValue() */
   if (iml_val != 1) goto p_ftp_se_60;      /* retrieve TCP-port       */
   /* retrieve DNS-name                                                */
   if (dsl_coe1.imc_len_dns_n > 0) {        /* check length DNS name   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"FTP-server\" \"DNS-name\" defined double - \"%(ux)s\" ignored",
                   __LINE__, awcl_value );
     goto p_ftp_se_80;                      /* get next sibling stage 2 */
   }
   dsl_coe1.imc_len_dns_n = m_get_dns_name( chrl_dns_name, sizeof(chrl_dns_name), (HL_WCHAR *) awcl_value );
   if (dsl_coe1.imc_len_dns_n < 0) {        /* DNS name is not valid   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"FTP-server\" \"DNS-name\" value \"%(ux)s\" invalid - ignored",
                   __LINE__, awcl_value );
   }
   awcl_dns_name = awcl_value;              /* save DNS name           */
   goto p_ftp_se_80;                        /* get next sibling stage 2 */

   p_ftp_se_60:                             /* retrieve TCP-port       */
   if (dsl_coe1.imc_port > 0) {             /* TCP port already defined */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"FTP-server\" \"TCP-port\" value \"%(ux)s\" ignored - already defined before",
                   __LINE__, awcl_value );
     goto p_ftp_se_80;                      /* get next sibling stage 2 */
   }
   dsl_coe1.imc_port = m_get_wc_number( (HL_WCHAR *) awcl_value );
   if (dsl_coe1.imc_port < 0) {             /* no valid number found   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"FTP-server\" \"TCP-port\" value \"%(ux)s\" invalid - ignored",
                   __LINE__, awcl_value );
     goto p_ftp_se_80;                      /* get next sibling stage 2 */
   }
   if (   (dsl_coe1.imc_port == 0)
       || (dsl_coe1.imc_port >= 0X010000)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"FTP-server\" \"TCP-port\" value \"%(ux)s\" / %d out of range - ignored",
                   __LINE__, awcl_value, dsl_coe1.imc_port );
     goto p_ftp_se_80;                      /* get next sibling stage 2 */
   }

   p_ftp_se_80:                             /* get next sibling stage 2 */
   adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                          ied_hlcldom_get_next_sibling );
   if (adsl_node_2) goto p_ftp_se_20;       /* process DOM node stage 2 */

   if (dsl_coe1.imc_len_dns_n <= 0) {       /* DNS name is not defined */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"FTP-server\" no \"DNS-name\" defined - ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
#ifdef XYZ1
   bol1 = m_check_dns_n_double( chrl_dns_name, dsl_coe1.imc_len_dns_n, (struct dsd_clib1_conf *) achl_stor_new );
   if (bol1 == FALSE) {                     /* DNS name already defined */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"FTP-server\" \"DNS-name\" value \"%(ux)s\" DNS-name already configured before - ignored",
                   __LINE__, awcl_dns_name );
     goto pdomc80;                          /* DOM node processed - next */
   }
#endif
   if (dsl_coe1.imc_port <= 0) {            /* port not filled         */
     dsl_coe1.imc_port = D_PORT_FTP;        /* default TCP port of FTP */
   }
   dsl_coe1.iec_coe = ied_coe_ftp_se;       /* FTP server              */
   bol1 = m_check_dns_n_double( chrl_dns_name, dsl_coe1.imc_len_dns_n,
                                awcl_dns_name,
                                &dsl_coe1,
                                (struct dsd_clib1_conf *) achl_stor_new,
                                &dsl_sdh_call_1 );
   if (bol1 == FALSE) {                     /* DNS name already defined */
     goto pdomc80;                          /* DOM node processed - next */
   }
   dsl_clco.boc_use_ftp = TRUE;             /* use ALG for FTP, FTP server configured */
   dsl_coe1.imc_len_stor = (sizeof(struct dsd_conf_ext_1)
                               + dsl_coe1.imc_len_dns_n
                               + sizeof(void *) - 1)
                             & (0 - sizeof(void *));
   iml1 = dsl_clco.imc_len_conf_ext_1;      /* save old length         */
   dsl_clco.imc_len_conf_ext_1 += dsl_coe1.imc_len_stor;
   achl_stor_old = achl_stor_new;           /* save storage            */
   bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                  DEF_AUX_MEMGET,
                                  &achl_stor_new,
                                  sizeof(struct dsd_clib1_conf)
                                    + dsl_clco.imc_len_conf_ext_1 );
   if (bol1 == FALSE) {                     /* error occured           */
     return FALSE;
   }
   if (achl_stor_old) {                     /* copy old values         */
     memcpy( achl_stor_new + sizeof(struct dsd_clib1_conf),
             achl_stor_old + sizeof(struct dsd_clib1_conf),
             iml1 );
     bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                    DEF_AUX_MEMFREE,
                                    &achl_stor_old,
                                    sizeof(struct dsd_clib1_conf)
                                      + iml1 );
   }
   /* new configuration extension                                      */
   adsl_coe1_new
     = (struct dsd_conf_ext_1 *) (achl_stor_new + sizeof(struct dsd_clib1_conf)
                                    + iml1 );
   memcpy( adsl_coe1_new, &dsl_coe1, sizeof(struct dsd_conf_ext_1) );
   if (dsl_coe1.imc_no_ineta) {
     memcpy( (char *) adsl_coe1_new + sizeof(struct dsd_conf_ext_1),
             umrl_ineta,
             dsl_coe1.imc_no_ineta * sizeof(UNSIG_MED) );
   }
   memcpy( (char *) adsl_coe1_new + sizeof(struct dsd_conf_ext_1)
             + dsl_coe1.imc_no_ineta * sizeof(UNSIG_MED),
           chrl_dns_name,
           dsl_coe1.imc_len_dns_n );
   memcpy( achl_stor_new, &dsl_clco, sizeof(struct dsd_clib1_conf) );
   goto pdomc80;                            /* DOM node processed - next */

   p_excl_dns_00:                           /* exclude DNS name        */
   memset( &dsl_coe1, 0, sizeof(struct dsd_conf_ext_1) );  /* configuration extension */
   do {                                     /* search value            */
     if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) break;
     adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                            ied_hlcldom_get_next_sibling );
   } while (adsl_node_2);
   if (adsl_node_2 == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"exclude-DNS-name\" no value found - ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_value );  /* getNodeValue() */
   dsl_coe1.imc_len_dns_n = m_get_dns_name( chrl_dns_name, sizeof(chrl_dns_name), (HL_WCHAR *) awcl_value );
   if (dsl_coe1.imc_len_dns_n < 0) {        /* DNS name is not valid   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"exclude-DNS-name\" value \"%(ux)s\" invalid - ignored",
                   __LINE__, awcl_value );
     goto pdomc80;                          /* DOM node processed - next */
   }
   awcl_dns_name = awcl_value;              /* save DNS name           */
#ifdef XYZ1
   bol1 = m_check_dns_n_double( chrl_dns_name, dsl_coe1.imc_len_dns_n, (struct dsd_clib1_conf *) achl_stor_new );
   if (bol1 == FALSE) {                     /* DNS name already defined */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"exclude-DNS-name\" value \"%(ux)s\" DNS-name already configured before - ignored",
                   __LINE__, awcl_dns_name );
     goto pdomc80;                          /* DOM node processed - next */
   }
#endif
   dsl_coe1.iec_coe = ied_coe_dns_resp;     /* DNS resonse configured  */
   bol1 = m_check_dns_n_double( chrl_dns_name, dsl_coe1.imc_len_dns_n,
                                awcl_dns_name,
                                &dsl_coe1,
                                (struct dsd_clib1_conf *) achl_stor_new,
                                &dsl_sdh_call_1 );
   if (bol1 == FALSE) {                     /* DNS name already defined */
     goto pdomc80;                          /* DOM node processed - next */
   }
   dsl_coe1.imc_len_entry = sizeof(chrs_dns_r_i_1) + dsl_coe1.imc_len_dns_n + sizeof(chrs_dns_r_a_2);
   dsl_coe1.imc_len_stor = (sizeof(struct dsd_conf_ext_1) + dsl_coe1.imc_len_entry + sizeof(void *) - 1)
                             & (0 - sizeof(void *));
   iml1 = dsl_clco.imc_len_conf_ext_1;      /* save old length         */
   dsl_clco.imc_len_conf_ext_1 += dsl_coe1.imc_len_stor;
   achl_stor_old = achl_stor_new;           /* save storage            */
   bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                  DEF_AUX_MEMGET,
                                  &achl_stor_new,
                                  sizeof(struct dsd_clib1_conf)
                                    + dsl_clco.imc_len_conf_ext_1 );
   if (bol1 == FALSE) {                     /* error occured           */
     return FALSE;
   }
   if (achl_stor_old) {                     /* copy old values         */
     memcpy( achl_stor_new + sizeof(struct dsd_clib1_conf),
             achl_stor_old + sizeof(struct dsd_clib1_conf),
             iml1 );
     bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                    DEF_AUX_MEMFREE,
                                    &achl_stor_old,
                                    sizeof(struct dsd_clib1_conf)
                                      + iml1 );
   }
   /* new configuration extension                                      */
   adsl_coe1_new
     = (struct dsd_conf_ext_1 *) (achl_stor_new + sizeof(struct dsd_clib1_conf)
                                    + iml1 );
   memcpy( adsl_coe1_new, &dsl_coe1, sizeof(struct dsd_conf_ext_1) );
   achl_w1 = (char *) (adsl_coe1_new + 1);
   memcpy( achl_w1, chrs_dns_r_i_1, sizeof(chrs_dns_r_i_1) );
   achl_w1 += sizeof(chrs_dns_r_i_1);
   memcpy( achl_w1, chrl_dns_name, dsl_coe1.imc_len_dns_n );
   achl_w1 += dsl_coe1.imc_len_dns_n;
   memcpy( achl_w1, chrs_dns_r_a_2, sizeof(chrs_dns_r_a_2) );
   memcpy( achl_stor_new, &dsl_clco, sizeof(struct dsd_clib1_conf) );
   goto pdomc80;                            /* DOM node processed - next */

   p_dns_ineta_00:                          /* retrieve DNS-ineta      */
   memset( &dsl_coe1, 0, sizeof(struct dsd_conf_ext_1) );  /* configuration extension */
#ifdef B110821
   iml_no_ineta = 0;                        /* no INETA till now       */
#endif

   p_dns_ineta_20:                          /* process DOM node stage 2 */
   if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type ))
         != DOMNode::ELEMENT_NODE) {
     goto p_dns_ineta_60;                   /* get next sibling stage 2 */
   }
   awcl_name = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_name );
#ifdef TRACEHL1
   printf( "xl-sdh-ppp-pf-07-l%05d-T m_hlclib_conf() found node %S\n", __LINE__, awcl_name );
#endif
   iml_val = sizeof(achrs_node_dnsi1) / sizeof(achrs_node_dnsi1[0]);
   do {
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl_name, (char *) achrs_node_dnsi1[ iml_val - 1 ] );
     if ((bol1) && (iml_cmp == 0)) break;   /* strings are equal       */
     iml_val--;                             /* decrement index         */
   } while (iml_val > 0);
   if (iml_val == 0) {                      /* parameter not found     */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"DNS-ineta\" child \"%(ux)s\" not defined - ignored",
                   __LINE__, awcl_name );
     goto p_dns_ineta_60;                   /* get next sibling stage 2 */
   }
   adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                          ied_hlcldom_get_first_child );  /* getFirstChild() */
   if (adsl_node_3 == NULL) {               /* no child found          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"DNS-ineta\" \"%(ux)s\" has no child - ignored",
                   __LINE__, awcl_name );
     goto p_dns_ineta_60;                   /* get next sibling stage 2 */
   }
   do {                                     /* search value            */
     if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_3, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) break;
     adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_3,
                                                            ied_hlcldom_get_next_sibling );
   } while (adsl_node_3);
   if (adsl_node_3 == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"DNS-ineta\" \"%(ux)s\" no value found - ignored",
                   __LINE__, awcl_name );
     goto p_dns_ineta_60;                   /* get next sibling stage 2 */
   }
   awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_3, ied_hlcldom_get_node_value );  /* getNodeValue() */
   if (iml_val != 1) goto p_dns_ineta_40;   /* retrieve INETA          */
   /* retrieve DNS-name                                                */
   if (dsl_coe1.imc_len_dns_n > 0) {        /* check length DNS name   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"DNS-ineta\" \"DNS-name\" defined double - \"%(ux)s\" ignored",
                   __LINE__, awcl_value );
     goto p_dns_ineta_60;                   /* get next sibling stage 2 */
   }
   dsl_coe1.imc_len_dns_n = m_get_dns_name( chrl_dns_name, sizeof(chrl_dns_name), (HL_WCHAR *) awcl_value );
   if (dsl_coe1.imc_len_dns_n < 0) {        /* DNS name is not valid   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"DNS-ineta\" \"DNS-name\" value \"%(ux)s\" invalid - ignored",
                   __LINE__, awcl_value );
   }
   awcl_dns_name = awcl_value;              /* save DNS name           */
   goto p_dns_ineta_60;                     /* get next sibling stage 2 */

   p_dns_ineta_40:                          /* retrieve INETA          */
#ifdef B110821
   if (iml_no_ineta >= MAX_DNS_INETA) {     /* INETA array filled      */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"DNS-ineta\" \"ineta\" value \"%(ux)s\" ignored - too many entries",
                   __LINE__, awcl_value );
     goto p_dns_ineta_60;                   /* get next sibling stage 2 */
   }
   iml1 = m_get_ineta_w( &umrl_ineta[ iml_no_ineta ], (HL_WCHAR *) awcl_value );
#else
   if (dsl_coe1.imc_no_ineta >= MAX_DNS_INETA) {  /* INETA array filled */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"DNS-ineta\" \"ineta\" value \"%(ux)s\" ignored - too many entries",
                   __LINE__, awcl_value );
     goto p_dns_ineta_60;                   /* get next sibling stage 2 */
   }
   iml1 = m_get_ineta_w( &umrl_ineta[ dsl_coe1.imc_no_ineta ], (HL_WCHAR *) awcl_value );
#endif
   if (iml1 < 0) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"DNS-ineta\" \"ineta\" value \"%(ux)s\" invalid - ignored",
                   __LINE__, awcl_value );
     goto p_dns_ineta_60;                   /* get next sibling stage 2 */
   }
   iml1 = 0;                                /* clear index             */
#ifdef B110821
   while (iml1 < iml_no_ineta) {            /* loop over all entries before */
     if (umrl_ineta[ iml1 ] == umrl_ineta[ iml_no_ineta ]) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"DNS-ineta\" \"ineta\" value \"%(ux)s\" defined double - ignored",
                     __LINE__, awcl_value );
       goto p_dns_ineta_60;                 /* get next sibling stage 2 */
     }
     iml1++;                                /* increment index         */
   }
   iml_no_ineta++;                          /* count INETA             */
#else
   while (iml1 < dsl_coe1.imc_no_ineta) {   /* loop over all entries before */
     if (umrl_ineta[ iml1 ] == umrl_ineta[ dsl_coe1.imc_no_ineta ]) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"DNS-ineta\" \"ineta\" value \"%(ux)s\" defined double - ignored",
                     __LINE__, awcl_value );
       goto p_dns_ineta_60;                 /* get next sibling stage 2 */
     }
     iml1++;                                /* increment index         */
   }
   dsl_coe1.imc_no_ineta++;                 /* count INETA             */
#endif

   p_dns_ineta_60:                          /* get next sibling stage 2 */
   adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                          ied_hlcldom_get_next_sibling );
   if (adsl_node_2) goto p_dns_ineta_20;    /* process DOM node stage 2 */
#ifdef B110821
   if (iml_no_ineta <= 0) {                 /* no INETA defined        */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"DNS-ineta\" no \"ineta\" defined - ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
#else
   if (dsl_coe1.imc_no_ineta <= 0) {        /* no INETA defined        */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"DNS-ineta\" no \"ineta\" defined - ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
#endif
   if (dsl_coe1.imc_len_dns_n <= 0) {       /* DNS name is not defined */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"DNS-ineta\" no \"DNS-name\" defined - ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
#ifdef XYZ1
   bol1 = m_check_dns_n_double( chrl_dns_name, dsl_coe1.imc_len_dns_n, (struct dsd_clib1_conf *) achl_stor_new );
   if (bol1 == FALSE) {                     /* DNS name already defined */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"DNS-ineta\" \"DNS-name\" value \"%(ux)s\" DNS-name already configured before - ignored",
                   __LINE__, awcl_dns_name );
     goto pdomc80;                          /* DOM node processed - next */
   }
#endif
   dsl_coe1.iec_coe = ied_coe_dns_resp;     /* DNS resonse configured  */
   bol1 = m_check_dns_n_double( chrl_dns_name, dsl_coe1.imc_len_dns_n,
                                awcl_dns_name,
                                &dsl_coe1,
                                (struct dsd_clib1_conf *) achl_stor_new,
                                &dsl_sdh_call_1 );
   if (bol1 == FALSE) {                     /* DNS name already defined */
     goto pdomc80;                          /* DOM node processed - next */
   }
#ifdef B110821
   dsl_coe1.imc_len_entry = sizeof(chrs_dns_r_s_1) + dsl_coe1.imc_len_dns_n + sizeof(chrs_dns_r_a_2)
                              + iml_no_ineta * (sizeof(chrs_dns_r_s_3) + sizeof(UNSIG_MED));
   dsl_coe1.imc_len_stor = (sizeof(struct dsd_conf_ext_1) + dsl_coe1.imc_len_entry + sizeof(void *) - 1)
                             & (0 - sizeof(void *));
#else
   dsl_coe1.imc_len_entry = sizeof(chrs_dns_r_s_1) + dsl_coe1.imc_len_dns_n + sizeof(chrs_dns_r_a_2);
   dsl_coe1.imc_len_stor = (sizeof(struct dsd_conf_ext_1)
                               + dsl_coe1.imc_len_entry
                               + dsl_coe1.imc_no_ineta * sizeof(UNSIG_MED)
                               + sizeof(void *) - 1)
                             & (0 - sizeof(void *));
#endif
   iml1 = dsl_clco.imc_len_conf_ext_1;      /* save old length         */
   dsl_clco.imc_len_conf_ext_1 += dsl_coe1.imc_len_stor;
   achl_stor_old = achl_stor_new;           /* save storage            */
   bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                  DEF_AUX_MEMGET,
                                  &achl_stor_new,
                                  sizeof(struct dsd_clib1_conf)
                                    + dsl_clco.imc_len_conf_ext_1 );
   if (bol1 == FALSE) {                     /* error occured           */
     return FALSE;
   }
   if (achl_stor_old) {                     /* copy old values         */
     memcpy( achl_stor_new + sizeof(struct dsd_clib1_conf),
             achl_stor_old + sizeof(struct dsd_clib1_conf),
             iml1 );
     bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                    DEF_AUX_MEMFREE,
                                    &achl_stor_old,
                                    sizeof(struct dsd_clib1_conf)
                                      + iml1 );
   }
   /* new configuration extension                                      */
   adsl_coe1_new
     = (struct dsd_conf_ext_1 *) (achl_stor_new + sizeof(struct dsd_clib1_conf)
                                    + iml1 );
   memcpy( adsl_coe1_new, &dsl_coe1, sizeof(struct dsd_conf_ext_1) );
   achl_w1 = (char *) (adsl_coe1_new + 1);
   memcpy( achl_w1, chrs_dns_r_s_1, sizeof(chrs_dns_r_s_1) );
   /* set ANCOUNT                                                      */
   *((unsigned char *) achl_w1 + 4 + 0) = (unsigned char) (dsl_coe1.imc_no_ineta >> 8);
   *((unsigned char *) achl_w1 + 4 + 1) = (unsigned char) dsl_coe1.imc_no_ineta;
   achl_w1 += sizeof(chrs_dns_r_s_1);
   memcpy( achl_w1, chrl_dns_name, dsl_coe1.imc_len_dns_n );
   achl_w1 += dsl_coe1.imc_len_dns_n;
   memcpy( achl_w1, chrs_dns_r_a_2, sizeof(chrs_dns_r_a_2) );
#ifdef B110821
   achl_w1 += sizeof(chrs_dns_r_a_2);
   iml1 = 0;                                /* clear index             */
   do {                                     /* loop to copy all INETA  */
     memcpy( achl_w1, chrs_dns_r_s_3, sizeof(chrs_dns_r_s_3) );
     achl_w1 += sizeof(chrs_dns_r_s_3);
     memcpy( achl_w1, &umrl_ineta[ iml1 ], sizeof(UNSIG_MED) );
     achl_w1 += sizeof(UNSIG_MED);
     iml1++;                                /* increment index         */
   } while (iml1 < iml_no_ineta);
#else
   memcpy( (char *) adsl_coe1_new + dsl_coe1.imc_len_stor
                      - dsl_coe1.imc_no_ineta * sizeof(UNSIG_MED),
           umrl_ineta,
           dsl_coe1.imc_no_ineta * sizeof(UNSIG_MED) );
#endif
   memcpy( achl_stor_new, &dsl_clco, sizeof(struct dsd_clib1_conf) );
// goto pdomc80;                            /* DOM node processed - next */

   pdomc80:                                 /* DOM node processed - next */
   adsl_node_1 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_1,
                                                          ied_hlcldom_get_next_sibling );
   if (adsl_node_1) goto pdomc20;           /* process DOM node        */
   if (iml_flag_nat_control == 0) {         /* flag NAT-control defined */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error no valid NAT-control found - Server-Data-Hook not usable",
                   __LINE__, awcl1 );
     if (achl_stor_new) {                   /* free storage            */
       bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                      DEF_AUX_MEMFREE,
                                      &achl_stor_new,
                                      sizeof(struct dsd_clib1_conf)
                                      + dsl_clco.imc_len_conf_ext_1 );
     }
     return FALSE;
   }
   if (achl_stor_new == NULL) {             /* no DNS-entries found    */
     bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                    DEF_AUX_MEMGET,
                                    &achl_stor_new,
                                    sizeof(struct dsd_clib1_conf) );
     if (bol1 == FALSE) {                   /* error occured           */
       return FALSE;
     }
   }
   if (dsl_clco.imc_no_s5_ineta_nat) {  /* number of reserved INETAs for Socks servers */
     m_ineta_op_add( (char *) &dsl_clco.umc_conf_ineta_1_upper,
                     sizeof(UNSIG_MED),
                     0 - dsl_clco.imc_no_s5_ineta_nat );  /* number of reserved INETAs for Socks servers */
     m_ineta_op_add( (char *) &dsl_clco.umc_conf_ineta_2_upper,
                     sizeof(UNSIG_MED),
                     0 - dsl_clco.imc_no_s5_ineta_nat );  /* number of reserved INETAs for Socks servers */
   }
   memcpy( achl_stor_new, &dsl_clco, sizeof(struct dsd_clib1_conf) );
   *adsp_hlcldomf->aac_conf = achl_stor_new;  /* save configuration data */
#ifdef TRACEHL1
   m_sdh_console_out( &dsl_sdh_call_1,
                      achl_stor_new,
                      sizeof(struct dsd_clib1_conf)
                        + dsl_clco.imc_len_conf_ext_1 );
#endif
   return TRUE;
} /* end m_hlclib_conf()                                               */

/* retrieve DNS name                                                   */
static int m_get_dns_name( char *achp_out, int imp_len_out, HL_WCHAR *awcp_value ) {
   char       *achl_wp, *achl_end;          /* write pointer, end      */
   char       *achl_first;                  /* first element with length */

   achl_wp = achp_out;                      /* get output              */
   achl_end = achp_out + imp_len_out;       /* end of output           */

   p_out_00:                                /* output next part        */
   achl_first = achl_wp;                    /* save start element      */
   achl_wp++;                               /* start here              */
   if (achl_wp >= achl_end) return -1;      /* output too long         */

   p_out_20:                                /* output characters       */
   if (*awcp_value >= 0X80) return -1;      /* invalid character       */
   if (   (*awcp_value != 0)                /* not end of string       */
       && (*awcp_value != '.')) {           /* is not separator        */
     if (achl_wp >= achl_end) return -1;    /* output too long         */
#ifdef B120821
     *achl_wp++ = (unsigned char) *awcp_value++;  /* copy value        */
#else
     *achl_wp++ = (unsigned char) (*awcp_value++ | 0X20);  /* copy value, lowercase */
#endif
     goto p_out_20;                         /* output characters       */
   }
   *achl_first = (unsigned char) (achl_wp - (achl_first + 1));
   if (*achl_first == 0) return -1;         /* only . / separator      */
   if (*awcp_value != 0) {                  /* not end of string       */
     awcp_value++;                          /* next input character    */
     goto p_out_00;                         /* output next part        */
   }
   if (achl_wp >= achl_end) return -1;      /* output too long         */
   *achl_wp++ = 0;                          /* set length zero as end  */
   return achl_wp - achp_out;               /* all done                */
} /* end m_get_dns_name()                                              */

static BOOL m_check_dns_n_double( char *achp_dns_n, int imp_len_dns_n,
                                  HL_WCHAR *awcp_dns_name,
                                  struct dsd_conf_ext_1 *adsp_coe1,
                                  struct dsd_clib1_conf *adsp_clco,
                                  struct dsd_sdh_call_1 *adsp_sdh_call_1 ) {
   BOOL       bol1;                         /* working variable        */
   struct dsd_conf_ext_1 *adsl_coe1_w1;     /* configuration extension */
   char       *achl_w1;                     /* working-variable        */
   char       *achl_end;                    /* end of configuration    */

   if (adsp_clco == NULL) return TRUE;      /* first configured value  */
   if (adsp_clco->imc_len_conf_ext_1 == 0) return TRUE;  /* no values before */

   p_check_00:                              /* check the configured entries */
   adsl_coe1_w1 = (struct dsd_conf_ext_1 *) (adsp_clco + 1);
   achl_end = (char *) adsl_coe1_w1 + adsp_clco->imc_len_conf_ext_1;  /* add length of DNS responses */
   bol1 = FALSE;                            /* do not repeat           */
   do {                                     /* loop over all DNS responses */
     while (imp_len_dns_n == adsl_coe1_w1->imc_len_dns_n) {
       achl_w1 = (char *) (adsl_coe1_w1 + 1);
       if (adsl_coe1_w1->iec_coe != ied_coe_ftp_se) {  /* not FTP server */
         achl_w1 += sizeof(chrs_dns_r_i_1);
       }
       if (memcmp( achp_dns_n, achl_w1, imp_len_dns_n )) break;
       if (   (adsl_coe1_w1->iec_coe == ied_coe_socks_se)  /* Socks server */
           && (adsp_coe1->iec_coe == ied_coe_socks_se)) {  /* Socks server */
         if (adsl_coe1_w1->imc_port == adsp_coe1->imc_port) {  /* TCP port equal */
           m_sdh_printf( adsp_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"Socks-server\" \"DNS-name\" value \"%(ux)s\" TCP-port value %d configured before - ignored",
                         __LINE__, awcp_dns_name, adsp_coe1->imc_port );
           return FALSE;                    /* Socks5 server double    */
         }
         break;
       }
       if (   (   (adsl_coe1_w1->iec_coe == ied_coe_ftp_se)  /* FTP server */
               || (adsp_coe1->iec_coe == ied_coe_ftp_se))  /* FTP server */
           && (adsl_coe1_w1->iec_coe != ied_coe_socks_se)  /* Socks server */
           && (adsp_coe1->iec_coe != ied_coe_socks_se)) {  /* Socks server */
         if (   (adsl_coe1_w1->iec_coe == adsp_coe1->iec_coe)  /* both FTP server */
             && (adsl_coe1_w1->imc_port == adsp_coe1->imc_port)) {  /* TCP port equal */
           m_sdh_printf( adsp_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error element \"FTP-server\" \"DNS-name\" value \"%(ux)s\" TCP-port value %d configured before - ignored",
                         __LINE__, awcp_dns_name, adsp_coe1->imc_port );
           return FALSE;                    /* FTP server double       */
         }
         break;
       }
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Error \"DNS-name\" value \"%(ux)s\" configured before - ignored",
                     __LINE__, awcp_dns_name );
       return FALSE;                        /* DNS name already defined */
     }
     if (   (adsl_coe1_w1->iec_coe == ied_coe_socks_se)  /* Socks server */
         && (adsp_coe1->iec_coe == ied_coe_socks_se)) {  /* Socks server */
       if (   (adsl_coe1_w1->imc_port == adsp_coe1->imc_port)  /* TCP port equal */
           && (adsl_coe1_w1->imc_index_so_ineta_nat == adsp_coe1->imc_index_so_ineta_nat)) {  /* index of reserved INETAs for Socks servers */
         adsp_coe1->imc_index_so_ineta_nat++;  /* increment index of reserved INETAs for Socks servers */
       }
     }
     *((char **) &adsl_coe1_w1) += adsl_coe1_w1->imc_len_stor;  /* add storage reserved */
   } while (((char *) adsl_coe1_w1) < achl_end);
   if (bol1) {                              /* do repeat               */
     goto p_check_00;                       /* check the configured entries */
   }
   return TRUE;                             /* all valid               */
} /* end m_check_dns_n_double()                                        */

/** subroutine to process the copy library function                    */
extern "C" HL_DLL_PUBLIC void m_hlclib01( struct dsd_hl_clib_1 *adsp_hl_clib_1 ) {
   int        iml1, iml2, iml3, iml4;       /* working variables       */
   BOOL       bol1;                         /* working variable        */
#ifndef B120309
   BOOL       bol_call_sec;                 /* call SDH-TCP secondary  */
#endif
   BOOL       bol_ipv6;                     /* is IPV6, not IPV4       */
   BOOL       bol_first;                    /* AVL tree first          */
   BOOL       bol_output;                   /* output has been done    */
   BOOL       bol_sdh_tcp_special;          /* special SDH-TCP         */
   int        iml_len_nhasn;                /* length bytes NHASN      */
   int        iml_len_packet;               /* length bytes packet     */
   int        iml_len_ip_header;            /* length of IP header     */
   int        iml_udp_pos_port;             /* port in UDP header      */
   int        iml_type;                     /* type of RR              */
   int        iml_class;                    /* class of RR             */
   int        iml_chs;                      /* calculate checksum      */
   int        iml_dir_inp;                  /* 0 = cl2se, 1 = se2cl    */
   int        iml_dir_oth;                  /* 0 = se2cl, 1 = cl2se    */
   int        iml_clse_pri;                 /* primary client to server */
   int        iml_clse_sec;                 /* secondary client to server */
   int        iml_len_dns_n;                /* length DNS name         */
#ifdef EXT_111125_01
   int        iml_invdat;                   /* line number invalid data */
#endif
   UNSIG_MED  uml_ineta_w1;                 /* working-variable        */
   UNSIG_MED  uml_ineta_dns;                /* INETA for DNS           */
   char       chl1;                         /* working variable        */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   char       chl_ipv4_ipv6;                /* protocol from IP header */
#endif
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   char       chl_type;                     /* type received           */
#endif
   enum ied_prog_status iel_ps;             /* program status          */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   int        iml_error_line;
#endif
   char       *achl1, *achl2, *achl3, *achl4, *achl5;  /* working variables */
   char       *achl_end;                    /* end of string to examine */
   char       *achl_rb;                     /* read in block           */
   char       *achl_out_ippa;               /* output area IP packet   */
   char       *achl_out_end;                /* output area end         */
   char       *achl_inp;                    /* input data              */
   char       *achl_packet;                 /* start of packet         */
   char       *achl_save_packet;            /* save start of packet    */
   char       *achl_sip_packet;             /* start of SIP packet     */
#ifdef B111021
   char       *achl_dns_name;               /* address of DNS name     */
#endif
#ifdef XYZ1
// 31.10.10 KB - remove next two fields
   UNSIG_MED  *auml_cnet_so;                /* cnet INETA source       */
   UNSIG_MED  *auml_cnet_de;                /* cnet INETA destination  */
#endif
   struct dsd_clib1_contr_1 *adsl_contr_1;  /* for addressing          */
   struct dsd_conf_ext_1 *adsl_coe1_w1;     /* configuration extension */
   struct dsd_nat_ftp_entry *adsl_nfe_w1;   /* entry for NAT of FTP server */
   struct dsd_gather_i_1 *adsl_gai1_inp_start;  /* start input data    */
   struct dsd_gather_i_1 *adsl_gai1_inp_packet;  /* input packet data  */
   struct dsd_gather_i_1 *adsl_gai1_inp_save_packet;  /* save input packet data */
   struct dsd_gather_i_1 *adsl_gai1_inp_w1;  /* input data             */
   struct dsd_gather_i_1 *adsl_gai1_inp_w2;  /* input data             */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
#ifdef B110818
   struct dsd_gather_i_1 *adsl_gai1_out_1;  /* output data             */
   struct dsd_gather_i_1 *adsl_gai1_out_2;  /* output data             */
#endif
   struct dsd_gather_i_1 *adsl_gai1_out_t1;  /* output data            */
   struct dsd_gather_i_1 *adsl_gai1_out_t2;  /* output data            */
   struct dsd_cc1_ext *adsl_cc1_ext_w1;     /* structure session control extension */
   struct dsd_cc1_ext *adsl_cc1_ext_w2;     /* structure session control extension */
// struct dsd_nat_entry_1 *adsl_nat_entry_1_w1;  /* structure NAT entry */
// struct dsd_nat_entry_1 *adsl_nat_entry_1_header;  /* structure NAT entry */
#ifdef B110818
   struct dsd_query_dns_resp_1 *adsl_qdnsr1_w1;  /* structure query DNS response */
   struct dsd_dns_resp_1 *adsl_dnsr1;       /* structure DNS response  */
#endif
#ifdef DEBUG_101208_01
   int        iml_d1, iml_d2;               /* working variables       */
   char       *achl_display;                /* pointer display         */
#define D_LEN_LINE_M1 128
#endif
   struct dsd_session_timer *adsl_session_timer_w1;  /* session timer  */
   struct dsd_session_notify *adsl_session_notify_w1;  /* session notify send possible */
   struct dsd_output_area_1 dsl_oa1;        /* output of subroutine    */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
/* new 29.06.11 KB */
   struct dsd_nat_ret_val dsl_nrv;          /* NAT return values       */
   struct dsd_gather_i_1 **aadsrl_gai1_out[ 2 ];  /* output data       */
   struct dsd_htree1_avl_cntl *adsl_htree1_avl_cntl_ineta;
   struct dsd_tcp_session_1 *adsl_ts1_w1;   /* structure TCP session   */
   struct dsd_subaux_userfld dsl_subaux_userfld;  /* for aux calls     */
   struct dsd_tcp_data_contr_1 *adsl_tdc1_w1;  /* TCP data control structure */
   struct dsd_tcp_data_contr_1 *adsl_tdc1_w2;  /* TCP data control structure */
   struct dsd_tcp_data_contr_1 *adsl_tdc1_w3;  /* TCP data control structure */
   struct dsd_tcp_data_contr_1 *adsl_tdc1_w4;  /* TCP data control structure */
   struct dsd_tcp_data_contr_1 *adsl_tdc1_w5;  /* TCP data control structure */
   struct dsd_sdh_tcp_1 *adsl_sdh_tcp_1_pri;  /* primary processed TCP half-session */
   struct dsd_sdh_tcp_1 *adsl_sdh_tcp_1_sec;  /* secondary processed TCP half-session */
   union {
     struct {
       struct dsd_htree1_avl_entry dsl_sort_ineta;  /* entry for sorting INETAs and ports */
       struct dsd_ctrl_tcp_ipv4 dsrl_ct_ipv4[2];  /* structures control TCP IPV4, client and server */
     };
     struct {
#ifndef HL_UNIX
       struct dsd_htree1_avl_entry dsl_sort_ineta;  /* entry for sorting INETAs and ports */
#else
       /* needed for GCC compiler, 11.04.13 KB                         */
       struct dsd_htree1_avl_entry dsl_sort_ineta_xx;  /* entry for sorting INETAs and ports */
#endif
       struct dsd_ctrl_tcp_ipv6 dsl_ct_ipv6;  /* structure control TCP IPV6 */
     };
   } unl_sort_ineta;
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   struct dsd_aux_get_workarea dsl_aux_get_workarea;  /* acquire additional work area */
   struct dsd_gather_i_1 dsl_gai1_sdh_tcp_in;  /* input to SDH-TCP     */
   struct dsd_tcp_data_contr_1 dsl_tdc1_sdh_tcp_in;  /* TCP data control structure */
/* old 29.06.11 KB */
   char       chrl_dns_name[ 256 ];         /* for DNS name            */
#ifdef B110701
   char       chrl_work1[ 1024 ];           /* work area               */
#else
   char       chrl_work1[ 2048 ];           /* work area               */
#endif
   char       chrl_work2[ 4 ];              /* work area               */
#ifndef B11116
   char       chrl_work3[ 2 ];              /* work area               */
#endif
#ifdef TRACEHL_INETA_01
   char       *achl_trhl_reason;
   char       chrl_trineta_buf[ 128 ];
#endif

   dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
   adsl_contr_1 = (struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext;
#ifdef DEBUG_101208_01
   achl_display = adsl_contr_1->chrc_display;  /* pointer display      */
#endif
#ifdef TRACEHL1
   {
     char *achh_text = "invalid function";
     switch (adsp_hl_clib_1->inc_func) {
       case DEF_IFUNC_START:
         achh_text = "DEF_IFUNC_START";
         break;
       case DEF_IFUNC_CLOSE:
         achh_text = "DEF_IFUNC_CLOSE";
         break;
       case DEF_IFUNC_FROMSERVER:
         achh_text = "DEF_IFUNC_FROMSERVER";
         break;
       case DEF_IFUNC_TOSERVER:
         achh_text = "DEF_IFUNC_TOSERVER";
         break;
       case DEF_IFUNC_REFLECT:
         achh_text = "DEF_IFUNC_REFLECT";
         break;
     }
     iml1 = iml2 = 0;                       /* length input data       */
     adsl_gai1_inp_w1 = adsp_hl_clib_1->adsc_gather_i_1_in;
     bol1 = FALSE;
     chl1 = 0;
     while (adsl_gai1_inp_w1) {
       iml2++;
       iml1 += adsl_gai1_inp_w1->achc_ginp_end - adsl_gai1_inp_w1->achc_ginp_cur;
       if (   (adsl_gai1_inp_w1->achc_ginp_end > adsl_gai1_inp_w1->achc_ginp_cur)
           && (bol1 == FALSE)) {
         chl1 = *adsl_gai1_inp_w1->achc_ginp_cur;
         bol1 = TRUE;
       }
       adsl_gai1_inp_w1 = adsl_gai1_inp_w1->adsc_next;  /* get next in chain */
     }
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_hlclib01() called inc_func=%d %s input=%p len=%d pieces=%d cont=0X%02X boc_eof_client=%d boc_eof_server=%d.",
                   __LINE__,
                   adsp_hl_clib_1->inc_func, achh_text,
                   adsp_hl_clib_1->adsc_gather_i_1_in, iml1, iml2, (unsigned char) chl1,
                   adsp_hl_clib_1->boc_eof_client,
                   adsp_hl_clib_1->boc_eof_server );
#ifdef OLD01
     if (adsl_contr_1) {                    /* memory allocated        */
       adsl_contr_1->imc_count_call++;      /* count all calls         */
       if (adsl_contr_1->imc_count_call > 40) {  /* already too many   */
#ifndef HL_UNIX
         Sleep( 500 );
#else
         sleep( 1 );
#endif
       }
     }
#endif
   }
   iml_len_nhasn = 0;                       /* length bytes NHASN      */
#endif
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = 0;
#endif
   switch (adsp_hl_clib_1->inc_func) {
     case DEF_IFUNC_START:
#define ADSL_CLCO ((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)
       iml1 = 0;                            /* size of extension       */
       if (ADSL_CLCO->boc_use_ftp) {        /* use ALG for FTP, FTP server configured */
         iml1 = sizeof(struct dsd_nat_ftp_ctl_org);  /* control area for NAT of FTP server, first */
       }
       bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                       DEF_AUX_MEMGET,
                                       &adsp_hl_clib_1->ac_ext,
                                       sizeof(struct dsd_clib1_contr_1) + iml1 );
       if (bol1 == FALSE) {
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
         return;
       }
       bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                       DEF_AUX_NOT_DROP_TCP_PACKET,  /* do not drop TCP packets */
                                       &bol1,
                                       sizeof(bol1) );
       if (bol1 == FALSE) {
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W could not set DEF_AUX_NOT_DROP_TCP_PACKET.",
                       __LINE__ );
       }
#define ADSL_CONTR_1_G ((struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext)
//     memset( adsp_hl_clib_1->ac_ext, 0, sizeof(struct dsd_clib1_contr_1) );
       ADSL_CONTR_1_G->boc_client_header = FALSE;  /* no client header has been received */
#ifndef B110317
       ADSL_CONTR_1_G->umc_ineta_cl_int = 0;  /* INETA client intern in intranet */
#endif
       ADSL_CONTR_1_G->umc_ineta_lower = 0;  /* natted INETAs lower entry */
       ADSL_CONTR_1_G->umc_ineta_upper = 0;  /* natted INETAs upper entry */
       ADSL_CONTR_1_G->umc_ineta_dns_s_1 = 0;  /* original INETA DNS server 1 */
       ADSL_CONTR_1_G->umc_ineta_dns_s_2 = 0;  /* original INETA DNS server 2 */
       ADSL_CONTR_1_G->umc_ineta_mask = 0;  /* natted INETAs network mask */
       ADSL_CONTR_1_G->umc_ineta_max_used = 0;  /* natted INETAs maximum used INETA */
       ADSL_CONTR_1_G->imc_alloc = 0;       /* number of INETAs allocated */
       ADSL_CONTR_1_G->imc_session_start = 0;  /* count times session start */
       ADSL_CONTR_1_G->imc_session_cur = 0;  /* current sessions       */
       ADSL_CONTR_1_G->imc_session_max = 0;  /* maximum number of sessions reached */
#ifndef B11116
       ADSL_CONTR_1_G->ilc_epoch_set = 0;   /* epoch timer set         */
#endif
       ADSL_CONTR_1_G->adsc_session_timer = NULL;  /* session timer    */
       ADSL_CONTR_1_G->adsc_session_notify = NULL;  /* session notify send possible */
       ADSL_CONTR_1_G->adsc_cc1_ext = NULL;  /* structure session control extension */
       bol1 = m_htree1_avl_init( NULL, &ADSL_CONTR_1_G->dsc_htree1_avl_cntl_ineta,
                                 &m_cmp_ineta_nat );
       if (bol1 == FALSE) {                 /* error occured           */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_init() NAT failed",
                       __LINE__ );
       }
       bol1 = m_htree1_avl_init( NULL, &ADSL_CONTR_1_G->dsc_htree1_avl_cntl_ineta_ipv4,
                                 &m_cmp_ineta_ipv4 );
       if (bol1 == FALSE) {                 /* error occured           */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_init() IPV4 failed",
                       __LINE__ );
       }
       bol1 = m_htree1_avl_init( NULL, &ADSL_CONTR_1_G->dsc_htree1_avl_cntl_ineta_ipv6,
                                 &m_cmp_ineta_ipv6 );
       if (bol1 == FALSE) {                 /* error occured           */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_init() IPV6 failed",
                       __LINE__ );
       }
#ifdef PACKET_LOSS_01                       /* lose packets            */
       ADSL_CONTR_1_G->imc_packet_loss_01 = PACKET_LOSS_01;  /* count to lose packets */
#endif
       if (iml1 == 0) return;
#define ADSL_NFCO ((struct dsd_nat_ftp_ctl_org *) (ADSL_CONTR_1_G + 1))  /* control area for NAT of FTP server, first */
       ADSL_NFCO->imc_no_nat_ftp_entries = 0;  /* clear number of entries for NAT of FTP */
       ADSL_NFCO->adsc_nfce = NULL;         /* control area for NAT of FTP server, extension */
       return;
#undef ADSL_NFCO
#undef ADSL_CONTR_1_G
#undef ADSL_CLCO
     case DEF_IFUNC_CLOSE:
#ifdef XYZ1
       adsl_cc1_ext_w1 = adsl_contr_1->adsc_cc1_ext;  /* structure session control extension */
       while (adsl_cc1_ext_w1) {            /* loop over all extensions */
         adsl_cc1_ext_w2 = adsl_cc1_ext_w1->adsc_next;  /* save next in chain */
         bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                         DEF_AUX_MEMFREE,
                                         &adsl_cc1_ext_w1,
                                         sizeof(struct dsd_clib1_contr_1) );
         if (bol1 == FALSE) {               /* error occured           */
           adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
           return;
         }
         adsl_cc1_ext_w1 = adsl_cc1_ext_w2;  /* get saved next in chain */
       }
       bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                       DEF_AUX_MEMFREE,
                                       &adsp_hl_clib_1->ac_ext,
                                       sizeof(struct dsd_clib1_contr_1) );
       if (bol1 == FALSE) {                 /* error occured           */
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       }
       return;
#endif
       goto p_cleanup_00;                   /* do cleanup              */
     case DEF_IFUNC_REFLECT:
#ifdef TRACEHL_DNS
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T time=%lld called DEF_IFUNC_REFLECT",
                   __LINE__, m_get_epoch_ms() );
#endif
       return;
   }
#ifdef DEBUG_101208_01
   adsl_gai1_inp_w1 = adsp_hl_clib_1->adsc_gather_i_1_in;  /* start input data */
   while (adsl_gai1_inp_w1) {               /* loop over all gather input */
     iml_d2 = adsl_gai1_inp_w1->achc_ginp_end - adsl_gai1_inp_w1->achc_ginp_cur;
     iml_d1 = sprintf( achl_display, "l%05d input-gather=%p cur=%p end=%p len=%d/0X%p.",
                       __LINE__, adsl_gai1_inp_w1,
                       adsl_gai1_inp_w1->achc_ginp_cur, adsl_gai1_inp_w1->achc_ginp_end,
                       iml_d2, iml_d2 );
     achl_display += iml_d1;
     iml_d2 = D_LEN_LINE_M1 - iml_d1;
     if (iml_d2 > 0) {
       memset( achl_display, ' ', iml_d2 );
       achl_display += iml_d2;
     }
     adsl_gai1_inp_w1 = adsl_gai1_inp_w1->adsc_next;  /* get next in chain */
   }
#endif
#ifdef TRACEHL_111004
   memmove( adsl_contr_1->imrl_trace_lno,
            adsl_contr_1->imrl_trace_lno + 1,
            (TRACEHL_111004 - 1) * sizeof(int) );
   adsl_contr_1->imrl_trace_lno[ TRACEHL_111004 - 1 ] = __LINE__;
#endif
#ifdef DEBUG_120821_01
   if (adsp_hl_clib_1->boc_eof_client) {    /* End-of-File Client      */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T SDH called boc_eof_client - inc_func=%d adsc_gather_i_1_in=%p.",
                   __LINE__, adsp_hl_clib_1->inc_func, adsp_hl_clib_1->adsc_gather_i_1_in );
   }
#endif
#define ADSL_CLCO ((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)
   bol_output = FALSE;                      /* clear output has been done */
   bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                   DEF_AUX_GET_T_MSEC,  /* get time / epoch in milliseconds */
                                   &dsl_subaux_userfld.ilc_epoch,
                                   sizeof(HL_LONGLONG) );
   if (bol1 == FALSE) {                     /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#ifdef TRACEHL_TIMER_01
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T SDH called ilc_epoch=%lld adsc_session_timer=%p.",
                 __LINE__, dsl_subaux_userfld.ilc_epoch, adsl_contr_1->adsc_session_timer );
#endif
/* new 29.06.11 KB */
   iml_dir_inp = 0;                         /* 0 = cl2se, 1 = se2cl    */
   if (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER) {
     iml_dir_inp = 1;                       /* 0 = cl2se, 1 = se2cl    */
   }
   iml_dir_oth = iml_dir_inp ^ 1;           /* 0 = se2cl, 1 = cl2se */
   aadsrl_gai1_out[ 0 ] = &adsp_hl_clib_1->adsc_gai1_out_to_client;  /* output data to client */
   aadsrl_gai1_out[ 1 ] = &adsp_hl_clib_1->adsc_gai1_out_to_server;  /* output data to server */
   dsl_subaux_userfld.adsc_hl_clib_1 = adsp_hl_clib_1;
   dsl_oa1.achc_lower = adsp_hl_clib_1->achc_work_area;  /* addr work-area */
   dsl_oa1.achc_upper = dsl_oa1.achc_lower + adsp_hl_clib_1->inc_len_work_area;  /* length work-area */
   adsl_gai1_inp_start = NULL;              /* start input data        */
   if (adsp_hl_clib_1->adsc_gather_i_1_in == NULL) {
     goto p_timer_00;                       /* check the timer         */
   }
/* old 29.06.11 KB */
   adsl_gai1_inp_start = adsl_gai1_inp_w1 = adsp_hl_clib_1->adsc_gather_i_1_in;  /* start input data */
   achl_inp = adsl_gai1_inp_w1->achc_ginp_cur;  /* start input data    */
   if (adsp_hl_clib_1->inc_func == DEF_IFUNC_FROMSERVER) {
#ifdef XYZ1
     iml_cmp_disp_ineta = offsetof( struct dsd_nat_entry_1, umc_ineta_real );  /* displacement INETA to compare */
     iml_repl_disp_ineta = offsetof( struct dsd_nat_entry_1, umc_ineta_translated );  /* displacement INETA to replace */
     iml_xchg_pos_packet = 12;              /* exchange in IP header   */
#endif
     iml_udp_pos_port = 0;                  /* port in UDP header      */
#ifdef XYZ1
     auml_cnet_so = &ADSL_CLCO->umc_cnat_ineta_real;  /* cnet INETA source */
     auml_cnet_de = &ADSL_CLCO->umc_cnat_ineta_translated;  /* cnet INETA destination */
#endif
     goto p_check_recv_00;                  /* check received packet   */
   }
   if (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER) {
#ifdef XYZ1
     iml_cmp_disp_ineta = offsetof( struct dsd_nat_entry_1, umc_ineta_translated );  /* displacement INETA to compare */
     iml_repl_disp_ineta = offsetof( struct dsd_nat_entry_1, umc_ineta_real );  /* displacement INETA to replace */
     iml_xchg_pos_packet = 16;              /* exchange in IP header   */
#endif
     iml_udp_pos_port = 2;                  /* port in UDP header      */
#ifdef XYZ1
     auml_cnet_so = &ADSL_CLCO->umc_cnat_ineta_translated;  /* cnet INETA source */
     auml_cnet_de = &ADSL_CLCO->umc_cnat_ineta_real;  /* cnet INETA destination */
#endif
     if (adsl_contr_1->boc_client_header) {  /* client header has been received */
       goto p_check_recv_00;                /* check received packet   */
     }
   } else {                                 /* is other function       */
#ifdef CHECK_OUTPUT_01
     m_check_output_01( adsp_hl_clib_1 );
#endif
     return;                                /* nothing to do           */
   }
   bol1 = FALSE;                            /* reset state             */

   p_header_00:                             /* search in header        */
   while (achl_inp >= adsl_gai1_inp_w1->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_w1 = adsl_gai1_inp_w1->adsc_next;  /* get next gather in chain */
#ifdef B120430
#ifndef CHECK_OUTPUT_01
     if (adsl_gai1_inp_w1 == NULL) return;  /* end of input data       */
#else
     if (adsl_gai1_inp_w1 == NULL) {        /* end of input data       */
       m_check_output_01( adsp_hl_clib_1 );
       return;
     }
#endif
#else
     if (adsl_gai1_inp_w1 == NULL) {        /* end of input data       */
       goto p_timer_00;                     /* check the timer         */
     }
#endif
     achl_inp = adsl_gai1_inp_w1->achc_ginp_cur;  /* start in gather   */
   }
   if (*achl_inp == CHAR_CR) {              /* carriage-return found   */
     bol1 = TRUE;                           /* set state               */
   } else if (*achl_inp == CHAR_LF) {       /* line-feed found         */
     if (bol1) {                            /* found carriage-return before */
       achl_inp++;                          /* after this character    */
       adsl_contr_1->boc_client_header = TRUE;  /* client header has been received */
       goto p_out_00;                       /* output of these data    */
     }
   } else {                                 /* normal character received */
     bol1 = FALSE;                          /* set state               */
   }
   achl_inp++;                              /* after this character    */
   goto p_header_00;                        /* search in header        */

   p_check_recv_00:                         /* check received packet   */
#ifndef B111125
   while (adsl_gai1_inp_start->achc_ginp_cur >= adsl_gai1_inp_start->achc_ginp_end) {
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_start == NULL) {     /* was last in chain       */
#ifdef B111205
#ifdef CHECK_OUTPUT_01
       m_check_output_01( adsp_hl_clib_1 );
#endif
       return;                              /* to be called again      */
#else
       goto p_timer_00;                     /* check the timer         */
#endif
     }
     achl_inp = adsl_gai1_inp_start->achc_ginp_cur;  /* start in gather */
   }
#endif
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   adsl_gai1_inp_w1 = adsl_gai1_inp_start;  /* start input data        */
   while (achl_inp >= adsl_gai1_inp_w1->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_w1 = adsl_gai1_inp_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_w1 == NULL) {        /* end of input data       */
#ifdef CHECK_OUTPUT_01
       m_check_output_01( adsp_hl_clib_1 );
#endif
       return;                              /* to be called again      */
     }
     achl_inp = adsl_gai1_inp_w1->achc_ginp_cur;  /* start in gather   */
   }
   achl_save_packet = achl_inp;             /* start of packet         */
   adsl_gai1_inp_save_packet = adsl_gai1_inp_w1;  /* input packet data */
   chl_type = *achl_inp++;                  /* type received           */
   switch (chl_type & 0XF0) {               /* first character         */
     case 0X30:                             /* control or PPP          */
       iml_len_nhasn = 0;                   /* clear length bytes NHASN */
       iml_len_packet = 0;                  /* clear length bytes packet */
       goto p_check_recv_20;                /* decode length NHASN     */
     case 0X40:                             /* IPV4                    */
       achl_out_ippa = (char *) (((long long int) (dsl_oa1.achc_lower + sizeof(UNSIG_MED) - 1)) & (0 - sizeof(UNSIG_MED)));
       if ((achl_out_ippa + (chl_type & 0X0F) * 4 + sizeof(struct dsd_gather_i_1)) > dsl_oa1.achc_upper) {  /* no space for output */
         adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
#ifdef CHECK_OUTPUT_01
         m_check_output_01( adsp_hl_clib_1 );
#endif
         return;                            /* to be called again      */
       }
       iml_len_ip_header = (chl_type & 0X0F) << 2;  /* length of IP header */
       if (iml_len_ip_header < (5 * 4)) {   /* IP header too short     */
         goto p_inv_data_00;                /* input data invalid      */
       }
       *achl_out_ippa = chl_type;           /* copy first byte         */
       achl1 = achl_out_ippa + 1;           /* copy here               */
       achl2 = achl_out_ippa + 4;           /* end of copy             */
       break;
     case 0X60:                             /* IPV6                    */
       achl_out_ippa = (char *) (((long long int) (dsl_oa1.achc_lower + sizeof(UNSIG_MED) - 1)) & (0 - sizeof(UNSIG_MED)));
       if ((achl_out_ippa + D_LEN_HEADER_IPV6 + sizeof(struct dsd_gather_i_1)) > dsl_oa1.achc_upper) {  /* no space for output */
         adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
#ifdef CHECK_OUTPUT_01
         m_check_output_01( adsp_hl_clib_1 );
#endif
         return;                            /* to be called again      */
       }
       *achl_out_ippa = chl_type;           /* copy first byte         */
       achl1 = achl_out_ippa + 1;           /* copy here               */
       achl2 = achl_out_ippa + 6;           /* end of copy             */
       break;
     default:                               /* other value             */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-E packet invalid control character 0X%02X.",
                     __LINE__, (unsigned char) chl_type );
       adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code      */
       return;
   }
   do {                                     /* loop copy characters    */
     iml1 = adsl_gai1_inp_w1->achc_ginp_end - achl_inp;  /* length of data */
     if (iml1 == 0) {                       /* no more data            */
       adsl_gai1_inp_w1 = adsl_gai1_inp_w1->adsc_next;  /* get next gather in chain */
       if (adsl_gai1_inp_w1 == NULL) {      /* end of input data       */
#ifdef CHECK_OUTPUT_01
         m_check_output_01( adsp_hl_clib_1 );
#endif
         return;                            /* to be called again      */
       }
       achl_inp = adsl_gai1_inp_w1->achc_ginp_cur;  /* start in gather */
     } else {                               /* found data              */
       iml2 = achl2 - achl1;                /* data to copy            */
       if (iml2 > iml1) iml2 = iml1;
       memcpy( achl1, achl_inp, iml2 );
       achl1 += iml2;
       achl_inp += iml2;
     }
   } while (achl1 < achl2);
   if ((chl_type & 0XF0) == 0X60) {         /* first character IPV6    */
     iml_len_packet = ((*((unsigned char *) achl_out_ippa + 4) << 8)
                         | *((unsigned char *) achl_out_ippa + 5))
                      + D_LEN_HEADER_IPV6;
     iml_len_ip_header = D_LEN_HEADER_IPV6;  /* length of IPV6 header  */
     bol_ipv6 = TRUE;                       /* is IPV6, not IPV4       */
   } else {                                 /* IPV4                    */
     iml_len_packet = (*((unsigned char *) achl_out_ippa + 2) << 8)
                        | *((unsigned char *) achl_out_ippa + 3);
     iml_len_ip_header = D_LEN_HEADER_IPV4;  /* length of IPV4 header  */
     bol_ipv6 = FALSE;                      /* is IPV4, not IPV6       */
   }
   if (iml_len_packet > HL_MAX_LEN_PACKET) {  /* packet too long       */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W packet length %d too high - ignored",
                   __LINE__, iml_len_packet );
     goto p_out_00;                         /* output unchanged        */
   }
   if (iml_len_packet < (1 + iml_len_ip_header)) {  /* packet too short */
#ifndef EXT_111125_01
     goto p_inv_data_00;                    /* input data invalid      */
#else
     iml_invdat = __LINE__;                 /* line number invalid data */
     goto p_inv_data_00;                    /* input data invalid      */
#endif
   }
   achl_packet = achl_inp;                  /* start of packet         */
   adsl_gai1_inp_packet = adsl_gai1_inp_w1;  /* input packet data      */

   /* first check if complete packet is in input data                  */
   iml1 = iml_len_packet - (achl2 - achl_out_ippa);  /* get length remaining packet */

   p_check_recv_04:                         /* read over packet        */
   while (achl_inp >= adsl_gai1_inp_w1->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_w1 = adsl_gai1_inp_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_w1 == NULL) {        /* end of input data       */
#ifdef B111125
#ifdef CHECK_OUTPUT_01
       m_check_output_01( adsp_hl_clib_1 );
#endif
       return;                              /* to be called again      */
#else
       goto p_timer_00;                     /* check the timer         */
#endif
     }
     achl_inp = adsl_gai1_inp_w1->achc_ginp_cur;  /* start in gather   */
   }
   iml2 = adsl_gai1_inp_w1->achc_ginp_end - achl_inp;  /* length this part */
   if (iml2 > iml1) iml2 = iml1;            /* only as long as requested */
   achl_inp += iml2;                        /* add length this part    */
   iml1 -= iml2;                            /* subtract length this part */
   if (iml1) goto p_check_recv_04;          /* read over packet        */

   if (bol_ipv6) {                          /* is IPV6, not IPV4       */
     goto p_check_ipv6_00;                  /* check IP header protocol */
   }
   achl_sip_packet = NULL;                  /* clear start of SIP packet */

   /* copy the first part of the packet to the output area             */
   achl_out_end = achl_out_ippa + iml_len_ip_header;
   adsl_gai1_out_t1 = (struct dsd_gather_i_1 *) dsl_oa1.achc_upper - 1;  /* output data */
   if (achl_out_end > ((char *) adsl_gai1_out_t1)) {  /* no space for output */
     adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
#ifdef CHECK_OUTPUT_01
     m_check_output_01( adsp_hl_clib_1 );
#endif
     return;                                /* to be called again      */
   }
   adsl_gai1_out_t1->achc_ginp_cur = achl_out_ippa;  /* start of gather */
   adsl_gai1_out_t1->achc_ginp_end = achl_out_end;  /* end of gather   */

   iml1 = achl_out_end - achl2;             /* end part one            */

   p_check_recv_08:                         /* copy IPV4 packet part one */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl_out_end - iml1, achl_packet, iml2 );
   achl_packet += iml2;
   iml1 -= iml2;
   if (iml1) goto p_check_recv_08;          /* copy IPV4 packet part one */
#ifdef DEBUG_101207_02
   if (bol_output) {                        /* output has been done    */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T second packet for output iml_len_packet=%d/0X%p.",
                   __LINE__, iml_len_packet, iml_len_packet );
   }
#endif
#define CHL_PROTOCOL *(achl_out_ippa + D_POS_IPV4_H_PROT)  /* protocol from IP header */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T packet protocol=0X%02X.",
                 __LINE__, (unsigned char) CHL_PROTOCOL );
#endif
   /* check TCP or UDP header                                          */
#ifndef TRY_101205
   if (CHL_PROTOCOL == IPPROTO_TCP) {       /* protocol TCP from IP header */
     iml1 = 20;                             /* length TCP header without options */
   } else if (CHL_PROTOCOL == IPPROTO_UDP) {  /* protocol UDP from IP header */
     iml1 = D_LEN_UDP_HEADER;               /* length UDP header       */
   } else goto p_check_recv_80;             /* all headers are in output area */
#else
   if (CHL_PROTOCOL == IPPROTO_TCP) {       /* protocol TCP from IP header */
     iml1 = 20;                             /* length TCP header without options */
   } else if ((CHL_PROTOCOL & 0X0F) == (IPPROTO_UDP & 0X0F)) {  /* protocol UDP from IP header */
     iml1 = D_LEN_UDP_HEADER;               /* length UDP header       */
   } else goto p_check_recv_80;             /* all headers are in output area */
#endif
   if (iml_len_packet < (iml_len_ip_header + iml1)) {  /* packet too short */
#ifndef EXT_111125_01
     goto p_inv_data_00;                    /* input data invalid      */
#else
     iml_invdat = __LINE__;                 /* line number invalid data */
     goto p_inv_data_00;                    /* input data invalid      */
#endif
   }
   achl_out_end += iml1;                    /* new end of headers      */
   if (achl_out_end > ((char *) adsl_gai1_out_t1)) {  /* no space for output */
     adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
#ifdef CHECK_OUTPUT_01
     m_check_output_01( adsp_hl_clib_1 );
#endif
     return;                                /* to be called again      */
   }
   adsl_gai1_out_t1->achc_ginp_end = achl_out_end;  /* end of gather   */

   p_check_recv_12:                         /* copy IPV4 packet part two */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl_out_end - iml1, achl_packet, iml2 );
   achl_packet += iml2;
   iml1 -= iml2;
   if (iml1) goto p_check_recv_12;          /* copy IPV4 packet part two */
   goto p_check_recv_80;                    /* check first part packet */
#endif
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml_len_nhasn = 0;                       /* clear length bytes NHASN */
   iml_len_packet = 0;                      /* clear length bytes packet */
   adsl_gai1_inp_w1 = adsl_gai1_inp_start;  /* start input data        */
#ifdef DEBUG_101208_01
   iml_d1 = sprintf( achl_display, "l%05d adsl_gai1_inp_w1=%p achl_inp=%p achl_work_1=%p achl_work_2=%p.",
                     __LINE__, adsl_gai1_inp_w1, achl_inp, achl_work_1, achl_work_2 );
   achl_display += iml_d1;
   iml_d2 = D_LEN_LINE_M1 - iml_d1;
   if (iml_d2 > 0) {
     memset( achl_display, ' ', iml_d2 );
     achl_display += iml_d2;
   }
#endif
#endif

   p_check_recv_20:                         /* decode length NHASN     */
   while (achl_inp >= adsl_gai1_inp_w1->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_w1 = adsl_gai1_inp_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_w1 == NULL) {        /* end of input data       */
#ifdef B111123
       if (   (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER)
           && (adsl_contr_1->imc_no_qdnsr1)) {  /* number of responses queued */
         adsp_hl_clib_1->boc_callrevdir = TRUE;  /* call on reverse direction */
       }
#endif
#ifdef B111125
#ifdef CHECK_OUTPUT_01
       m_check_output_01( adsp_hl_clib_1 );
#endif
       return;                              /* to be called again      */
#else
       goto p_timer_00;                     /* check the timer         */
#endif
     }
     achl_inp = adsl_gai1_inp_w1->achc_ginp_cur;  /* start in gather   */
   }
   iml_len_packet <<= 7;                    /* shift old value         */
   iml_len_packet |= *achl_inp++ & 0X7F;    /* apply new bits          */
   iml_len_nhasn++;                         /* increment length bytes NHASN */
   if ((unsigned char) *(achl_inp - 1) & 0X80) {  /* more bit set      */
#ifndef EXT_111125_01
     if (iml_len_nhasn > MAX_LEN_NHASN) goto p_inv_data_00;  /* input data invalid */
#else
     if (iml_len_nhasn > MAX_LEN_NHASN) {
       iml_invdat = __LINE__;               /* line number invalid data */
       goto p_inv_data_00;                  /* input data invalid      */
     }
#endif
     goto p_check_recv_20;                  /* decode length NHASN     */
   }
#ifndef EXT_111125_01
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   if (iml_len_packet <= 1) goto p_inv_data_00;  /* input data invalid */
#endif
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   if (iml_len_packet <= 0) goto p_inv_data_00;  /* input data invalid */
#endif
#else
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   if (iml_len_packet <= 1) {
     iml_invdat = __LINE__;                 /* line number invalid data */
     goto p_inv_data_00;                    /* input data invalid      */
   }
#endif
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   if (iml_len_packet <= 0) {
     iml_invdat = __LINE__;                 /* line number invalid data */
     goto p_inv_data_00;                    /* input data invalid      */
   }
#endif
#endif
   achl_packet = achl_save_packet = achl_inp;  /* start of packet      */
   adsl_gai1_inp_packet = adsl_gai1_inp_save_packet = adsl_gai1_inp_w1;  /* input packet data */
   iml1 = iml_len_packet;                   /* get length packet       */

   p_check_recv_40:                         /* read over packet        */
   while (achl_inp >= adsl_gai1_inp_w1->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_w1 = adsl_gai1_inp_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_w1 == NULL) {        /* end of input data       */
#ifdef B111125
#ifdef CHECK_OUTPUT_01
       m_check_output_01( adsp_hl_clib_1 );
#endif
       return;                              /* to be called again      */
#else
       goto p_timer_00;                     /* check the timer         */
#endif
     }
     achl_inp = adsl_gai1_inp_w1->achc_ginp_cur;  /* start in gather   */
   }
   iml2 = adsl_gai1_inp_w1->achc_ginp_end - achl_inp;  /* length this part */
   if (iml2 > iml1) iml2 = iml1;            /* only as long as requested */
   achl_inp += iml2;                        /* add length this part    */
   iml1 -= iml2;                            /* subtract length this part */
   if (iml1) goto p_check_recv_40;          /* read over packet        */

#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   /* check if control packet, IPV4 or IPV6                            */
   iml1 = 0;                                /* reset state             */
   bol_ipv6 = FALSE;                        /* is IPV4, not IPV6       */

   p_check_recv_60:                         /* check first part packet */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   if (achl_packet == achl_inp) goto p_out_00;  /* content too short   */
   switch (iml1) {                          /* depend on state         */
     case 0:
#ifdef HPPPT1_V14_RECV                      /* 26.08.12 KB HOB-PPP-T1 V1.4 receive */
       if ((*achl_packet & 0XF0) == 0X40) {  /* IPV4 data found         */
         chl_ipv4_ipv6 = '4';               /* type IPV4 / IPV6        */
         iml_len_ip_header = (*achl_packet & 0X0F) << 2;  /* length of IP header */
         if (iml_len_ip_header < (5 * 4)) {  /* IP header too short    */
#ifdef EXT_111125_01
           iml_invdat = __LINE__;           /* line number invalid data */
#endif
           goto p_inv_data_00;              /* input data invalid      */
         }
         iml1 = 3;                          /* next end of loop        */
         break;
       }
       if ((*achl_packet & 0XF0) == 0X60) {  /* IPV6 data found         */
         chl_ipv4_ipv6 = '6';               /* type IPV4 / IPV6        */
         iml_len_ip_header = D_LEN_HEADER_IPV6;  /* length of IPV6 header */
         bol_ipv6 = TRUE;                   /* is IPV6, not IPV4       */
         iml1 = 3;                          /* next end of loop        */
         break;
       }
#endif
       chl_ipv4_ipv6 = *achl_packet;        /* type IPV4 / IPV6        */
       if (*achl_packet == '4') {           /* IPV4 data found         */
         iml1 = 1;                          /* next is packet case 2   */
         break;
       }
       if (*achl_packet == '6') {           /* IPV6 data found         */
         iml1 = 2;                          /* next is packet case 3   */
         break;
       }
       if (*achl_packet == '1') break;      /* PPP data found          */
       if (*achl_packet == '0') {
         goto p_contr_00;                   /* control packet found    */
       }
       goto p_out_00;                       /* output unchanged        */
     case 1:
       iml1 = 3;                            /* next is end of compare  */
       if (((unsigned char) *achl_packet) == ucrs_ctrl_ipcp[0]) {
         goto p_ipcp_00;                    /* process IPCP            */
       }
       goto p_out_00;                       /* output unchanged        */
     case 2:                                /* check IPV4 header       */
       if ((*achl_packet & 0XF0) != 0X40) goto p_out_00;  /* not IPV4  */
       iml_len_ip_header = (*achl_packet & 0X0F) << 2;  /* length of IP header */
       if (iml_len_ip_header < (5 * 4)) {   /* IP header too short     */
#ifdef EXT_111125_01
         iml_invdat = __LINE__;             /* line number invalid data */
#endif
         goto p_inv_data_00;                /* input data invalid      */
       }
       iml1 = 3;                            /* next end of loop        */
       break;
     case 3:                                /* check IPV6 header       */
       if ((*achl_packet & 0XF0) != 0X60) goto p_out_00;  /* not IPV6  */
       iml_len_ip_header = D_LEN_HEADER_IPV6;  /* length of IPV6 header */
       bol_ipv6 = TRUE;                     /* is IPV6, not IPV4       */
       break;
   }
   achl_packet++;                           /* increment input         */
   iml1++;                                  /* increment state         */
   if (iml1 < 4) goto p_check_recv_60;      /* check first part packet */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T packet iml_len_nhasn=%d iml_len_packet=%d.",
                 __LINE__, iml_len_nhasn, iml_len_packet );
   m_dump_gather( &dsl_sdh_call_1, adsl_gai1_inp_start, iml_len_nhasn + iml_len_packet );
#endif
   if (iml_len_packet < (1 + iml_len_ip_header)) {  /* packet too short */
#ifdef EXT_111125_01
     iml_invdat = __LINE__;                 /* line number invalid data */
#endif
     goto p_inv_data_00;                    /* input data invalid      */
   }
   if (bol_ipv6) {                          /* is IPV6, not IPV4       */
     goto p_check_ipv6_00;                  /* check IP header protocol */
   }

   /* copy the first part of the packet to the output area             */
   achl_out_ippa = (char *) (((long long int) (dsl_oa1.achc_lower + MAX_LEN_NHASN + 1 + sizeof(UNSIG_MED) - 1)) & (0 - sizeof(UNSIG_MED)));
   achl_out_end = achl_out_ippa + iml_len_ip_header;
   adsl_gai1_out_t1 = (struct dsd_gather_i_1 *) dsl_oa1.achc_upper - 1;  /* output data */
   if (achl_out_end > ((char *) adsl_gai1_out_t1)) {  /* no space for output */
     adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
#ifdef CHECK_OUTPUT_01
     m_check_output_01( adsp_hl_clib_1 );
#endif
     return;                                /* to be called again      */
   }
   adsl_gai1_out_t1->achc_ginp_end = achl_out_end;  /* end of gather   */
   *achl_out_ippa = *(achl_packet - 1);     /* copy first byte IP header */
   iml1 = iml_len_ip_header - (2 - 1);      /* end part one            */

   p_check_recv_64:                         /* copy IPV4 packet part one */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl_out_end - iml1, achl_packet, iml2 );
   achl_packet += iml2;
   iml1 -= iml2;
   if (iml1) goto p_check_recv_64;          /* copy IPV4 packet part one */

#define CHL_PROTOCOL *(achl_out_ippa + D_POS_IPV4_H_PROT)  /* protocol from IP header */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T IPV4 packet protocol=0X%02X.",
                 __LINE__, (unsigned char) CHL_PROTOCOL );
#endif
   /* check TCP or UDP header                                          */
#ifndef TRY_101205
   if (CHL_PROTOCOL == IPPROTO_TCP) {       /* protocol TCP from IP header */
     iml1 = D_LEN_TCP_H_MIN;                /* length TCP header without options */
   } else if (CHL_PROTOCOL == IPPROTO_UDP) {  /* protocol UDP from IP header */
     iml1 = D_LEN_UDP_HEADER;               /* length UDP header       */
   } else goto p_check_recv_80;             /* all headers are in output area */
#else
   if (CHL_PROTOCOL == IPPROTO_TCP) {       /* protocol TCP from IP header */
     iml1 = D_LEN_TCP_H_MIN;                /* length TCP header without options */
   } else if ((CHL_PROTOCOL & 0X0F) == (IPPROTO_UDP & 0X0F)) {  /* protocol UDP from IP header */
     iml1 = D_LEN_UDP_HEADER;               /* length UDP header       */
   } else goto p_check_recv_80;             /* all headers are in output area */
#endif
   if (iml_len_packet < (1 + iml_len_ip_header + iml1)) {  /* packet too short */
#ifdef EXT_111125_01
     iml_invdat = __LINE__;                 /* line number invalid data */
#endif
     goto p_inv_data_00;                    /* input data invalid      */
   }
   achl_out_end += iml1;                    /* new end of headers      */
   if (achl_out_end > ((char *) adsl_gai1_out_t1)) {  /* no space for output */
     adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
#ifdef CHECK_OUTPUT_01
     m_check_output_01( adsp_hl_clib_1 );
#endif
     return;                                /* to be called again      */
   }
   adsl_gai1_out_t1->achc_ginp_end = achl_out_end;  /* end of gather   */

   p_check_recv_72:                         /* copy IPV4 packet part two */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl_out_end - iml1, achl_packet, iml2 );
   achl_packet += iml2;
   iml1 -= iml2;
   if (iml1) goto p_check_recv_72;          /* copy IPV4 packet part two */
#endif
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
// if (achl_packet == achl_inp) goto p_out_00;  /* content too short   */
   if (chl_type == '0') {
     goto p_contr_00;                       /* control packet found    */
   }
   if (chl_type != '1') {                   /* not PPP data            */
     goto p_out_00;                         /* output unchanged        */
   }
   if (((unsigned char) *achl_packet) == ucrs_ctrl_ipcp[0]) {
     goto p_ipcp_00;                        /* process IPCP            */
   }
   goto p_out_00;                           /* output unchanged        */

#define CHL_PROTOCOL *(achl_out_ippa + D_POS_IPV4_H_PROT)  /* protocol from IP header */
#endif

   p_check_recv_80:                         /* all headers are in output area */
   memcpy( &uml_ineta_dns, achl_out_ippa + 16, sizeof(UNSIG_MED) );  /* INETA for DNS */
   /* apply NAT                                                        */
   if (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER) {
     *((UNSIG_MED *) &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 0 ][ 0 ]) = *((UNSIG_MED *) (achl_out_ippa + 12));
     *((UNSIG_MED *) (achl_out_ippa + 12)) = adsl_contr_1->umc_ineta_cl_int;  /* INETA client intern in intranet */
     *((UNSIG_MED *) &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 0 ][ 0 ]) = *((UNSIG_MED *) (achl_out_ippa + 12));
     *((UNSIG_MED *) &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 1 ][ 0 ]) = *((UNSIG_MED *) (achl_out_ippa + 16));
     *((UNSIG_MED *) (achl_out_ippa + 16))
       = m_original_ineta( adsp_hl_clib_1, achl_out_ippa + 16, &dsl_nrv );
#ifdef DEBUG_110902_01
     unsigned char chrh_ineta_cmp[4] = { 172, 22, 0, 196 };
     if (!memcmp( achl_out_ippa + 16, chrh_ineta_cmp, sizeof(chrh_ineta_cmp) )) {
       iml1 = 0;
     }
#endif
     *((UNSIG_MED *) &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 1 ][ 0 ]) = *((UNSIG_MED *) (achl_out_ippa + 16));
   } else {
     *((UNSIG_MED *) &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 1 ][ 0 ]) = *((UNSIG_MED *) (achl_out_ippa + 12));
     *((UNSIG_MED *) (achl_out_ippa + 12))
       = m_natted_ineta( adsp_hl_clib_1, achl_out_ippa + 12, NULL, ADSL_CLCO->boc_disp_inetas );
     *((UNSIG_MED *) &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 1 ][ 0 ]) = *((UNSIG_MED *) (achl_out_ippa + 12));
     *((UNSIG_MED *) &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 0 ][ 0 ]) = *((UNSIG_MED *) (achl_out_ippa + 16));
     *((UNSIG_MED *) (achl_out_ippa + 16)) = adsl_contr_1->umc_ineta_client;  /* INETA client in tunnel */
     *((UNSIG_MED *) &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 0 ][ 0 ]) = *((UNSIG_MED *) (achl_out_ippa + 16));
   }
   if (CHL_PROTOCOL == IPPROTO_UDP) {       /* protocol UDP from IP header */
     goto p_udp_00;                         /* process UDP packet      */
   }
   if (CHL_PROTOCOL != IPPROTO_TCP) {       /* not protocol TCP from IP header */
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }
   unl_sort_ineta.dsrl_ct_ipv4[ 0 ].iec_cti4 = ied_cti4_normal;  /* normal TCP half-session */
   /* we need the TCP ports later                                      */
   *((unsigned short int *) &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_port[ iml_dir_oth ][ 0 ])
     = *((unsigned short int *) (achl_out_ippa + iml_len_ip_header + 0));
   *((unsigned short int *) &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_port[ iml_dir_inp ][ 0 ])
     = *((unsigned short int *) (achl_out_ippa + iml_len_ip_header + 2));
#ifdef NOT_NEEDED
   memcpy( unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_port,
           unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_port,
           sizeof(unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_port) );
#endif
#ifdef TRACEHL_111004
   memmove( adsl_contr_1->imrl_trace_lno,
            adsl_contr_1->imrl_trace_lno + 1,
            (TRACEHL_111004 - 1) * sizeof(int) );
   adsl_contr_1->imrl_trace_lno[ TRACEHL_111004 - 1 ] = __LINE__;
#endif
   goto p_sdh_tcp_start_00;                 /* process TCP packet      */

   /* check IPV6 if TCP or other protocol                              */
   p_check_ipv6_00:                         /* check IP header protocol */
   iml2 = D_POS_IPV6_H_NEXT - 1;            /* position type next header in IPV6 header */

   p_check_ipv6_20:                         /* loop to overread parts of the IP header */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml1 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml1 <= iml2) {
     achl_packet = adsl_gai1_inp_packet->achc_ginp_end;  /* at end of this gather */
     iml2 -= iml1;                          /* displacement in next gather */
     goto p_check_ipv6_20;                  /* check IP header protocol */
   }
   if (*((unsigned char *) achl_packet + iml2) != IPPROTO_TCP) {  /* protocol TCP from IP header */
     goto p_out_00;                         /* output unchanged        */
   }

   /* get IPV6 INETAs source and destination                           */
   iml1 = 1 + 8;                            /* displacement source IPV6 */
   achl_packet = achl_save_packet;          /* start of packet         */
   adsl_gai1_inp_packet = adsl_gai1_inp_save_packet;  /* input packet data */

   p_check_ipv6_24:                         /* loop to overread parts of IP header */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 <= iml1) {
     achl_packet = adsl_gai1_inp_packet->achc_ginp_end;  /* at end of this gather */
     iml1 -= iml2;                          /* displacement in next gather */
     goto p_check_ipv6_24;                  /* loop to overread parts of IP header */
   }
   achl_packet += iml1;                     /* start of INETAs         */
   achl1 = &unl_sort_ineta.dsl_ct_ipv6.chrrc_ineta[ iml_dir_inp ][ 0 ];  /* INETA IPV6 */
   iml1 = 16;                               /* length INETA IPV6       */
   bol1 = FALSE;                            /* is source INETA         */

   p_check_ipv6_28:                         /* copy source or destination INETA */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl1, achl_packet, iml2 );      /* copy part of INETA      */
   achl1 += iml2;
   achl_packet += iml2;
   iml1 -= iml2;
   if (iml1 > 0) {                          /* not yet filled          */
     goto p_check_ipv6_28;                  /* copy source or destination INETA */
   }
   if (bol1 == FALSE) {                     /* was source INETA        */
     achl1 = &unl_sort_ineta.dsl_ct_ipv6.chrrc_ineta[ iml_dir_oth ][ 0 ];  /* INETA IPV6 */
     iml1 = 16;                             /* length INETA IPV6       */
     bol1 = TRUE;                           /* is destination INETA    */
     goto p_check_ipv6_28;                  /* copy source or destination INETA */
   }

   /* get TCP ports source and destination                             */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml1 = (1 + D_LEN_HEADER_IPV6) - (1 + 8 + 2 * 16);  /* part overread header IPV6 */
#else
   iml1 = D_LEN_HEADER_IPV6 - (1 + 8 + 2 * 16);  /* part overread header IPV6 */
#endif

   p_check_ipv6_40:                         /* loop to overread parts of IP header */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 <= iml1) {
     achl_packet = adsl_gai1_inp_packet->achc_ginp_end;  /* at end of this gather */
     iml1 -= iml2;                          /* displacement in next gather */
     goto p_check_ipv6_40;                  /* loop to overread parts of IP header */
   }
   achl_packet += iml1;                     /* start of TCP ports      */
   achl1 = &unl_sort_ineta.dsl_ct_ipv6.chrrc_port[ iml_dir_inp ][ 0 ];  /* port IPV6 */
   iml1 = 2;                                /* length one port         */
   bol1 = FALSE;                            /* is source port          */

   p_check_ipv6_44:                         /* copy source or destination port */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl1, achl_packet, iml2 );      /* copy part of port       */
   achl1 += iml2;
   achl_packet += iml2;
   iml1 -= iml2;
   if (iml1 > 0) {                          /* not yet filled          */
     goto p_check_ipv6_44;                  /* copy source or destination port */
   }
   if (bol1 == FALSE) {                     /* was source port         */
     achl1 = &unl_sort_ineta.dsl_ct_ipv6.chrrc_port[ iml_dir_oth ][ 0 ];  /* port IPV6 */
     iml1 = 2;                              /* length one port         */
     bol1 = TRUE;                           /* is destination port     */
     goto p_check_ipv6_44;                  /* copy source or destination port */
   }

   p_sdh_tcp_start_00:                      /* process TCP packet      */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T TCP packet iml_len_nhasn=%d/0X%X iml_len_ip_header=%d/0X%X iml_len_packet=%d/0X%X.",
                 __LINE__, iml_len_nhasn, iml_len_nhasn, iml_len_ip_header, iml_len_ip_header, iml_len_packet, iml_len_packet );
   achl1 = (char *) unl_sort_ineta.dsrl_ct_ipv4;  /* control area IPV4 */
   iml1 = 2 * sizeof(struct dsd_ctrl_tcp_ipv4);  /* length control area IPV4 */
   if (bol_ipv6) {                          /* is IPV6, not IPV4       */
     achl1 = (char *) &unl_sort_ineta.dsl_ct_ipv6;  /* control area IPV6 */
     iml1 = sizeof(struct dsd_ctrl_tcp_ipv6);  /* length control area IPV6 */
   }
   m_sdh_console_out( &dsl_sdh_call_1, achl1, iml1 );
#endif
#ifdef TRACEHL_111004
   memmove( adsl_contr_1->imrl_trace_lno,
            adsl_contr_1->imrl_trace_lno + 1,
            (TRACEHL_111004 - 1) * sizeof(int) );
   adsl_contr_1->imrl_trace_lno[ TRACEHL_111004 - 1 ] = __LINE__;
#endif
#ifdef TRACEHL_INETA_01
   achl_trhl_reason = "normal-0";
   if (iml_dir_inp) {                       /* 0 = cl2se, 1 = se2cl    */
     achl_trhl_reason = "normal-1";
   }
#endif
   adsl_htree1_avl_cntl_ineta = &adsl_contr_1->dsc_htree1_avl_cntl_ineta_ipv4;
   if (bol_ipv6) {                          /* is IPV6, not IPV4       */
     adsl_htree1_avl_cntl_ineta = &adsl_contr_1->dsc_htree1_avl_cntl_ineta_ipv6;
   }
   bol1 = m_htree1_avl_search( NULL, adsl_htree1_avl_cntl_ineta,
                               &dsl_htree1_work, &unl_sort_ineta.dsl_sort_ineta );
   if (bol1 == FALSE) {                     /* error occured           */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_search() failed",
                   __LINE__ );
     goto p_out_00;                         /* output unchanged        */
   }
   if (dsl_htree1_work.adsc_found) {        /* entry found             */
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_htree1_avl_search() found entry",
                   __LINE__ );
#endif
     goto p_sdh_tcp_cont_00;                /* continue SDH-TCP        */
   }

   /* check if Socks or FTP                                          */
   bol_sdh_tcp_special = FALSE;             /* special SDH-TCP         */
   if (bol_ipv6) {                          /* is IPV6, not IPV4       */
     goto p_sdh_tcp_start_16;               /* type of session set     */
   }
   unl_sort_ineta.dsrl_ct_ipv4[ 1 ].iec_cti4 = ied_cti4_normal;  /* normal TCP half-session */
   if (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER) {
     goto p_sdh_tcp_start_16;               /* type of session set     */
   }
   iml1 = (((unsigned char) unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_port[ 0 ][ 0 ]) << 8)
            | ((unsigned char) unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_port[ 0 ][ 1 ]);
#ifdef DEBUG_110831_01
// to-do 31.08.11 KB
   iml2 = (((unsigned char) unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_port[ 1 ][ 0 ]) << 8)
            | ((unsigned char) unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_port[ 1 ][ 1 ]);
#endif
#ifdef DEBUG_140730_01                      /* problems FTP            */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_hlclib01() DEBUG_140730_01 dsl_nrv.adsc_nfe=%p.",
                 __LINE__, dsl_nrv.adsc_nfe );
#endif
   if (dsl_nrv.adsc_nfe) {                  /* chain of entries for NAT of FTP server */
     goto p_sdh_tcp_start_08;               /* check FTP               */
   }
   if (dsl_nrv.imc_index_so_ineta_nat < 0) {  /* index of reserved INETAs for Socks servers */
     goto p_sdh_tcp_start_16;               /* type of session set     */
   }
   adsl_coe1_w1 = (struct dsd_conf_ext_1 *) (ADSL_CLCO + 1);
   achl1 = (char *) adsl_coe1_w1 + ADSL_CLCO->imc_len_conf_ext_1;  /* add length of configuration extensions */
   do {                                     /* loop over all configuration extensions */
     if (   (adsl_coe1_w1->iec_coe == ied_coe_socks_se)  /* Socks server */
         && (iml1 == adsl_coe1_w1->imc_port)  /* TCP port              */
         && (dsl_nrv.imc_index_so_ineta_nat == adsl_coe1_w1->imc_index_so_ineta_nat)) {  /* index of reserved INETAs for Socks servers */
#ifdef TRY_110901_02
       unl_sort_ineta.dsrl_ct_ipv4[ 0 ].iec_cti4 = ied_cti4_s5_client;  /* set Socks client TCP half-session */
#endif
       unl_sort_ineta.dsrl_ct_ipv4[ 1 ].iec_cti4 = ied_cti4_s5_client;  /* Socks client TCP half-session */
       bol_sdh_tcp_special = TRUE;          /* special SDH-TCP         */
#ifdef DEBUG_110831_01
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T INETA DEBUG_110831_01 Socks server found",
                     __LINE__ );
#endif
       goto p_sdh_tcp_start_16;             /* type of session set     */
     }
     *((char **) &adsl_coe1_w1) += adsl_coe1_w1->imc_len_stor;  /* add storage reserved */
   } while (((char *) adsl_coe1_w1) < achl1);
   goto p_sdh_tcp_start_16;                 /* type of session set     */

   p_sdh_tcp_start_08:                      /* check FTP               */
   adsl_nfe_w1 = dsl_nrv.adsc_nfe;          /* chain of entries for NAT of FTP server */
   do {                                     /* loop over entries of this INETA */
#ifdef DEBUG_140730_01                      /* problems FTP            */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_hlclib01() DEBUG_140730_01 adsl_nfe_w1=%p adsl_nfe_w1->adsc_coe1->imc_port=%d. iml1=%d.",
                   __LINE__, adsl_nfe_w1, adsl_nfe_w1->adsc_coe1->imc_port, iml1 );
#endif
     if (adsl_nfe_w1->adsc_coe1->imc_port == iml1) {  /* TCP port      */
       bol_sdh_tcp_special = TRUE;          /* special SDH-TCP         */
       goto p_sdh_tcp_start_16;             /* type of session set     */
     }
     adsl_nfe_w1 = adsl_nfe_w1->adsc_next;  /* get next in chain       */
   } while (adsl_nfe_w1);

   p_sdh_tcp_start_16:                      /* type of session set     */
   iel_ps = ied_ps_start;                   /* start of TCP session    */
   adsl_contr_1->imc_session_start++;       /* count times session start */
   adsl_contr_1->imc_session_cur++;         /* current sessions        */
   if (adsl_contr_1->imc_session_cur > adsl_contr_1->imc_session_max ) {  /* maximum number of sessions reached */
     adsl_contr_1->imc_session_max = adsl_contr_1->imc_session_cur;  /* maximum number of sessions reached */
   }
   iml1 = iml2 = sizeof(struct dsd_sort_tcp_ipv6);  /* sort TCP IPV6   */
   if (bol_ipv6 == FALSE) {                 /* is IPV4, not IPV6       */
     iml1 = iml2 = sizeof(struct dsd_sort_tcp_ipv4);  /* sort TCP IPV4 */
     if (unl_sort_ineta.dsrl_ct_ipv4[ 1 ].iec_cti4 == ied_cti4_s5_client) {  /* Socks client TCP half-session */
       iml1 = 2 * sizeof(struct dsd_sort_tcp_ipv4);  /* twice sort TCP IPV4 */
     }
   }
   bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                   DEF_AUX_MEMGET,
                                   &adsl_ts1_w1,  /* structure TCP session */
                                   sizeof(struct dsd_tcp_session_1) + iml1 );
   if (bol1 == FALSE) {                     /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   memset( adsl_ts1_w1, 0, sizeof(struct dsd_tcp_session_1) );  /* structure TCP session */
   memcpy( adsl_ts1_w1 + 1, &unl_sort_ineta, iml2 );  /* copy sort with INETAs and ports */
   adsl_ts1_w1->boc_ipv6 = bol_ipv6;        /* is IPV4 or IPV6         */
   adsl_ts1_w1->dsrc_sdh_tcp_1[ 0 ].imc_sno = adsp_hl_clib_1->imc_sno;  /* session number */
   adsl_ts1_w1->dsrc_sdh_tcp_1[ 0 ].imc_trace_level = adsp_hl_clib_1->imc_trace_level;  /* WSP trace level */
   adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].imc_sno = adsp_hl_clib_1->imc_sno;  /* session number */
   adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].imc_trace_level = adsp_hl_clib_1->imc_trace_level;  /* WSP trace level */
   adsl_ts1_w1->dsrc_sdh_tcp_1[ 0 ].iec_stfc = ied_stfc_tcp_tunnel_1;  /* inside of TCP tunnel 1 */
   if (unl_sort_ineta.dsrl_ct_ipv4[ 1 ].iec_cti4 != ied_cti4_s5_client) {  /* not Socks client TCP half-session */
     adsl_ts1_w1->dsrc_sdh_tcp_1[ 0 ].boc_syn_extern = TRUE;  /* SYN is handled externally */
     adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].boc_syn_extern = TRUE;  /* SYN is handled externally */
   }
   adsl_ts1_w1->dsrc_session_timer[ iml_dir_oth ].adsc_ts1 = adsl_ts1_w1;  /* structure TCP session */
#ifdef B110903
   adsl_ts1_w1->dsrc_session_timer[ iml_dir_oth ].boc_ipv6 = bol_ipv6;  /* is IPV6, not IPV4 */
#endif
   adsl_ts1_w1->dsrc_session_timer[ iml_dir_oth ].imc_index = iml_dir_oth;  /* index of TCP half-session */
   adsl_ts1_w1->dsrc_session_timer[ iml_dir_inp ].adsc_ts1 = adsl_ts1_w1;  /* structure TCP session */
#ifdef B110903
   adsl_ts1_w1->dsrc_session_timer[ iml_dir_inp ].boc_ipv6 = bol_ipv6;  /* is IPV6, not IPV4 */
#endif
   adsl_ts1_w1->dsrc_session_timer[ iml_dir_inp ].imc_index = iml_dir_inp;  /* index of TCP half-session */
   adsl_sdh_tcp_1_pri = &adsl_ts1_w1->dsrc_sdh_tcp_1[ iml_dir_inp ];  /* the TCP server */
   adsl_sdh_tcp_1_sec = &adsl_ts1_w1->dsrc_sdh_tcp_1[ iml_dir_oth ];  /* the TCP client */
   adsl_sdh_tcp_1_pri->amc_aux = &m_sub_aux;  /* helper routine pointer */
   dsl_subaux_userfld.adsc_sdh_tcp_1 = adsl_sdh_tcp_1_pri;  /* TCP half-session */
#ifdef B120430
   dsl_subaux_userfld.adsc_session_timer = &adsl_ts1_w1->dsrc_session_timer[ iml_dir_oth ];  /* session timer */
#else
   dsl_subaux_userfld.adsc_session_timer = &adsl_ts1_w1->dsrc_session_timer[ iml_dir_inp ];  /* session timer */
#endif
   adsl_sdh_tcp_1_pri->vpc_userfld = &dsl_subaux_userfld;  /* User Field Subroutine */
   if (bol_ipv6 == FALSE) {                 /* is IPV4, not IPV6       */
     adsl_sdh_tcp_1_pri->usc_port_client    /* TCP port of client      */
       = *((unsigned short int *) &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_port[ iml_dir_inp ][ 0 ]);
     adsl_sdh_tcp_1_pri->usc_port_server    /* TCP port of server      */
       = *((unsigned short int *) &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_port[ iml_dir_oth ][ 0 ]);
     adsl_sdh_tcp_1_sec->usc_port_client    /* TCP port of client      */
       = *((unsigned short int *) &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_port[ iml_dir_oth ][ 0 ]);
     adsl_sdh_tcp_1_sec->usc_port_server    /* TCP port of server      */
       = *((unsigned short int *) &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_port[ iml_dir_inp ][ 0 ]);
     memcpy( adsl_sdh_tcp_1_pri->chrc_header_info, unl_sort_ineta.dsrl_ct_ipv4[ iml_dir_inp ].chrrc_ineta, sizeof(unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta) );  /* IP header information needed for checksum */
     adsl_sdh_tcp_1_pri->imc_len_header_info = sizeof(unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta);  /* length of header information, 8 for IPV4 and 32 for IPV6 */
     memcpy( adsl_sdh_tcp_1_sec->chrc_header_info, unl_sort_ineta.dsrl_ct_ipv4[ iml_dir_oth ].chrrc_ineta, sizeof(unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta) );  /* IP header information needed for checksum */
     adsl_sdh_tcp_1_sec->imc_len_header_info = sizeof(unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta);  /* length of header information, 8 for IPV4 and 32 for IPV6 */
   } else {                                 /* is IPV6, not IPV4       */
     adsl_sdh_tcp_1_pri->usc_port_client    /* TCP port of client      */
       = *((unsigned short int *) &unl_sort_ineta.dsl_ct_ipv6.chrrc_port[ iml_dir_inp ][ 0 ]);
     adsl_sdh_tcp_1_pri->usc_port_server    /* TCP port of server      */
       = *((unsigned short int *) &unl_sort_ineta.dsl_ct_ipv6.chrrc_port[ iml_dir_oth ][ 0 ]);
     adsl_sdh_tcp_1_sec->usc_port_client    /* TCP port of client      */
       = *((unsigned short int *) &unl_sort_ineta.dsl_ct_ipv6.chrrc_port[ iml_dir_oth ][ 0 ]);
     adsl_sdh_tcp_1_sec->usc_port_server    /* TCP port of server      */
       = *((unsigned short int *) &unl_sort_ineta.dsl_ct_ipv6.chrrc_port[ iml_dir_inp ][ 0 ]);
     memcpy( adsl_sdh_tcp_1_pri->chrc_header_info, unl_sort_ineta.dsl_ct_ipv6.chrrc_ineta, sizeof(unl_sort_ineta.dsl_ct_ipv6.chrrc_ineta) );  /* IP header information needed for checksum */
     adsl_sdh_tcp_1_pri->imc_len_header_info = sizeof(unl_sort_ineta.dsl_ct_ipv6.chrrc_ineta);  /* length of header information, 8 for IPV4 and 32 for IPV6 */
     memcpy( adsl_sdh_tcp_1_sec->chrc_header_info, unl_sort_ineta.dsl_ct_ipv6.chrrc_ineta, sizeof(unl_sort_ineta.dsl_ct_ipv6.chrrc_ineta) );  /* IP header information needed for checksum */
     adsl_sdh_tcp_1_sec->imc_len_header_info = sizeof(unl_sort_ineta.dsl_ct_ipv6.chrrc_ineta);  /* length of header information, 8 for IPV4 and 32 for IPV6 */
   }
#ifdef TRACEHL_TIMER_01
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T call SDH-TCP adsc_sdh_tcp_1=%p start",
                 __LINE__, adsl_sdh_tcp_1_pri );
#endif
   m_sdhtcp01( adsl_sdh_tcp_1_pri );        /* call SDH-TCP            */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_sdhtcp01() %d returned %d.",
                 __LINE__, iml_dir_oth, adsl_sdh_tcp_1_pri->imc_return );
#endif
   if (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL) {  /* not o.k. returned */
     goto p_sdh_tcp_end_80;                 /* only free memory        */
   }
   memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
   bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                      DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                      &dsl_aux_get_workarea,
                                      sizeof(struct dsd_aux_get_workarea) );
   if (bol1 == FALSE) {                     /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_sdh_tcp_1_pri->achc_work_area = dsl_aux_get_workarea.achc_work_area;  /* addr work-area returned */
   adsl_sdh_tcp_1_pri->imc_len_work_area = dsl_aux_get_workarea.imc_len_work_area;  /* length work-area returned */

   /* get input starting from the TCP header                           */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml1 = 1 + iml_len_ip_header;            /* after the IP header     */
#else
   iml1 = iml_len_ip_header;                /* after the IP header     */
#endif
   achl_packet = achl_save_packet;          /* start of packet         */
   adsl_gai1_inp_packet = adsl_gai1_inp_save_packet;  /* input packet data */

   p_sdh_tcp_start_20:                      /* loop to overread parts of IP header */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 <= iml1) {
     achl_packet = adsl_gai1_inp_packet->achc_ginp_end;  /* at end of this gather */
     iml1 -= iml2;                          /* displacement in next gather */
     goto p_sdh_tcp_start_20;               /* loop to overread parts of IP header */
   }
   achl_packet += iml1;                     /* start of INETAs         */
   dsl_gai1_sdh_tcp_in.achc_ginp_cur = achl_packet;  /* start in gather */
   dsl_gai1_sdh_tcp_in.achc_ginp_end = adsl_gai1_inp_packet->achc_ginp_end;  /* end in gather */
   dsl_gai1_sdh_tcp_in.adsc_next = adsl_gai1_inp_packet->adsc_next;  /* append chain of gather */
   memset( &dsl_tdc1_sdh_tcp_in, 0, sizeof(struct dsd_tcp_data_contr_1) );  /* TCP data control structure */
   dsl_tdc1_sdh_tcp_in.adsc_gai1 = &dsl_gai1_sdh_tcp_in;  /* data      */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   dsl_tdc1_sdh_tcp_in.imc_len_data = iml_len_packet - (1 + iml_len_ip_header);  /* length of the data */
#else
   dsl_tdc1_sdh_tcp_in.imc_len_data = iml_len_packet - iml_len_ip_header;  /* length of the data */
#endif
   adsl_sdh_tcp_1_pri->adsc_tdc1_in = &dsl_tdc1_sdh_tcp_in;  /* input data */
   adsl_sdh_tcp_1_pri->imc_func = DEF_IFUNC_FROMSERVER;  /* data from server */
#ifdef TRACEHL_TIMER_01
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T call SDH-TCP adsc_sdh_tcp_1=%p boc_timer_running=%d.",
                 __LINE__, adsl_sdh_tcp_1_pri, adsl_sdh_tcp_1_pri->boc_timer_running );
   if (adsl_sdh_tcp_1_pri->adsc_tdc1_in) {
     adsl_tdc1_w1 = adsl_sdh_tcp_1_pri->adsc_tdc1_in;
     iml1 = 0;
     do {                                   /* loop over input data    */
       iml1++;                              /* increment counter input */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T inp %d. addr=%p adsc_gai1=%p imc_len_data=%d/0X%X umc_flags=0X%08X.",
                     __LINE__,
                     adsl_tdc1_w1,
                     adsl_tdc1_w1->adsc_gai1,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->umc_flags );
       iml2 = adsl_tdc1_w1->imc_len_data;
       adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;
       while (adsl_gai1_w1) {
         if (iml2 <= 0) break;
         iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         if (iml3 > iml2) iml3 = iml2;
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T gather %p length %d/0X%X.",
                       __LINE__, adsl_gai1_w1, iml3, iml3 );
         m_sdh_console_out( &dsl_sdh_call_1, adsl_gai1_w1->achc_ginp_cur, iml3 );
         iml2 -= iml3;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
       adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next in chain   */
     } while (adsl_tdc1_w1);
   }
#endif
   m_sdhtcp01( adsl_sdh_tcp_1_pri );        /* call SDH-TCP            */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_sdhtcp01() %d returned %d adsc_tdc1_out_to_client=%p adsc_tdc1_out_to_server=%p.",
                 __LINE__,
                 iml_dir_oth,
                 adsl_sdh_tcp_1_pri->imc_return,
                 adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client,  /* output data to client */
                 adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server );  /* output data to server */
   if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client) {
     adsl_tdc1_w1 = adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client;
     iml1 = 0;
     do {                                   /* loop over input data    */
       iml1++;                              /* increment counter input */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T out-to-client %d. addr=%p adsc_gai1=%p imc_len_data=%d/0X%X umc_flags=0X%08X.",
                     __LINE__,
                     iml1,
                     adsl_tdc1_w1,
                     adsl_tdc1_w1->adsc_gai1,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->umc_flags );
       iml2 = adsl_tdc1_w1->imc_len_data;
       adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;
       while (adsl_gai1_w1) {
         if (iml2 <= 0) break;
         iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         if (iml3 > iml2) iml3 = iml2;
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T gather %p length %d/0X%X.",
                       __LINE__, adsl_gai1_w1, iml3, iml3 );
         m_sdh_console_out( &dsl_sdh_call_1, adsl_gai1_w1->achc_ginp_cur, iml3 );
         iml2 -= iml3;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
       adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next in chain   */
     } while (adsl_tdc1_w1);
   }
   if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server) {
     adsl_tdc1_w1 = adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server;
     iml1 = 0;
     do {                                   /* loop over input data    */
       iml1++;                              /* increment counter input */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T out-to-server %d. addr=%p adsc_gai1=%p imc_len_data=%d/0X%X umc_flags=0X%08X.",
                     __LINE__,
                     iml1,
                     adsl_tdc1_w1,
                     adsl_tdc1_w1->adsc_gai1,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->umc_flags );
       iml2 = adsl_tdc1_w1->imc_len_data;
       adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;
       while (adsl_gai1_w1) {
         if (iml2 <= 0) break;
         iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         if (iml3 > iml2) iml3 = iml2;
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T gather %p length %d/0X%X.",
                       __LINE__, adsl_gai1_w1, iml3, iml3 );
         m_sdh_console_out( &dsl_sdh_call_1, adsl_gai1_w1->achc_ginp_cur, iml3 );
         iml2 -= iml3;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
       adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next in chain   */
     } while (adsl_tdc1_w1);
   }
#endif
#ifndef B130409
   if (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL) {
     adsl_sdh_tcp_1_pri->imc_func = 0;      /* TCP connection not started, do not call again */
   }
#endif
   if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server == NULL) {  /* output data to server */
     goto p_sdh_tcp_start_40;               /* next part start SDH-TCP */
   }
   adsl_tdc1_w1 = adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server;  /* output data to server */
   adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server = NULL;  /* clear output data to server */
   iml_len_ip_header = D_LEN_HEADER_IPV4;   /* length of IP header IPV4 */
// chl_ipv4_ipv6 = '4';                     /* protocol from IP header */
   if (bol_ipv6) {                          /* is IPV6, not IPV4       */
     iml_len_ip_header = D_LEN_HEADER_IPV6;  /* length of IP header IPV6 */
//   chl_ipv4_ipv6 = '6';                   /* protocol from IP header */
   }

   p_sdh_tcp_start_24:                      /* process output of SDH-TCP */
   dsl_oa1.achc_upper -=sizeof(struct dsd_gather_i_1);
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   if (dsl_oa1.achc_upper < (dsl_oa1.achc_lower + OUT_LEN_NHASN + 1 + iml_len_ip_header)) goto p_out_80;  /* overflow */
#else
   if (dsl_oa1.achc_upper < (dsl_oa1.achc_lower + iml_len_ip_header)) goto p_out_80;  /* overflow */
#endif
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) dsl_oa1.achc_upper)
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   achl1 = achl2 = dsl_oa1.achc_lower + OUT_LEN_NHASN + 1;
#else
   achl1 = dsl_oa1.achc_lower;
#endif
   iml3 = adsl_tdc1_w1->imc_len_data;       /* length of the data      */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml3 <= 0) goto p_illogic_00;        /* program illogic         */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   *(--achl1) = chl_ipv4_ipv6;              /* type IPV4 / IPV6        */
   iml1 = 1 + iml_len_ip_header + iml3;     /* length of packet        */
   iml2 = 0;                                /* clear more bit          */
   do {
     *(--achl1) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* remove bits set         */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
#endif
   ADSL_GAI1_G->achc_ginp_cur = achl1;
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   ADSL_GAI1_G->achc_ginp_end = achl2 + iml_len_ip_header;
#else
   ADSL_GAI1_G->achc_ginp_end = achl1 + iml_len_ip_header;
#endif
   ADSL_GAI1_G->adsc_next = NULL;
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   if (bol_ipv6 == FALSE) {                 /* is IPV4, not IPV6       */
     m_build_header_ipv4( achl2,
//                        (struct dsd_ctrl_tcp_ipv4 *) (adsl_ts1_w1 + 1),
                          &unl_sort_ineta.dsrl_ct_ipv4[ iml_dir_inp ],
                          iml_dir_oth,
                          iml3 );
   } else {                                 /* is IPV6, not IPV4       */
     m_build_header_ipv6( achl2,
                          (struct dsd_ctrl_tcp_ipv6 *) (adsl_ts1_w1 + 1),
                          iml_dir_oth,
                          iml3 );
   }
#else
   if (bol_ipv6 == FALSE) {                 /* is IPV4, not IPV6       */
     m_build_header_ipv4( achl1,
//                        (struct dsd_ctrl_tcp_ipv4 *) (adsl_ts1_w1 + 1),
                          &unl_sort_ineta.dsrl_ct_ipv4[ iml_dir_inp ],
                          iml_dir_oth,
                          iml3 );
   } else {                                 /* is IPV6, not IPV4       */
     m_build_header_ipv6( achl1,
                          (struct dsd_ctrl_tcp_ipv6 *) (adsl_ts1_w1 + 1),
                          iml_dir_oth,
                          iml3 );
   }
#endif
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   dsl_oa1.achc_lower += OUT_LEN_NHASN + 1 + iml_len_ip_header;
#else
   dsl_oa1.achc_lower += iml_len_ip_header;
#endif
   *aadsrl_gai1_out[ iml_dir_inp ] = ADSL_GAI1_G;
   aadsrl_gai1_out[ iml_dir_inp ] = &ADSL_GAI1_G->adsc_next;
   adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;  /* data                    */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic    */

   p_sdh_tcp_start_28:                      /* process output of SDH-TCP */
   dsl_oa1.achc_upper -=sizeof(struct dsd_gather_i_1);
   if (dsl_oa1.achc_upper < dsl_oa1.achc_lower) goto p_out_80;  /* overflow */
   iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
   if (iml1 > iml3) iml1 = iml3;            /* only what is needed     */
   ADSL_GAI1_G->achc_ginp_cur = adsl_gai1_w1->achc_ginp_cur;
   ADSL_GAI1_G->achc_ginp_end = adsl_gai1_w1->achc_ginp_cur + iml1;
   ADSL_GAI1_G->adsc_next = NULL;
   *aadsrl_gai1_out[ iml_dir_inp ] = ADSL_GAI1_G;
   aadsrl_gai1_out[ iml_dir_inp ] = &ADSL_GAI1_G->adsc_next;
   iml3 -= iml1;                            /* count data processed    */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml3 > 0) {                          /* we need more data       */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next input in chain */
     if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic  */
     goto p_sdh_tcp_start_28;               /* process output of SDH-TCP */
   }
   adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next in chain       */
   if (adsl_tdc1_w1) {                      /* more packets to send    */
     goto p_sdh_tcp_start_24;               /* process output of SDH-TCP */
   }

   p_sdh_tcp_start_40:                      /* next part start SDH-TCP */
   if (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL) {  /* half-session already closed */
     adsl_sdh_tcp_1_sec->imc_return = DEF_IRET_END;  /* set other half-session to ended */
     goto p_sdh_tcp_end_00;                 /* packet has been processed by SDH-TCP */
   }
   bol1 = m_htree1_avl_insert( NULL, adsl_htree1_avl_cntl_ineta,
                               &dsl_htree1_work, (struct dsd_htree1_avl_entry *) (adsl_ts1_w1 + 1) );
   if (bol1 == FALSE) {                     /* error occured           */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_insert() failed",
                   __LINE__ );
#ifdef DEBUG_140730_01                      /* problems FTP            */
     iml_error_line = __LINE__;
#endif
     goto p_illogic_00;                     /* program illogic         */
   }
   adsl_sdh_tcp_1_sec->boc_is_client = TRUE;  /* this is client that does connect */
#ifndef B130217
   adsl_sdh_tcp_1_sec->adsc_tdc1_in = adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client;  /* input data */
#endif
#ifdef DEBUG_140730_01                      /* problems FTP            */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_hlclib01() DEBUG_140730_01 bol_sdh_tcp_special=%d.",
                 __LINE__, bol_sdh_tcp_special );
#endif
   if (bol_sdh_tcp_special == FALSE) {      /* no special SDH-TCP      */
     goto p_sdh_tcp_start_48;               /* start SDH-TCP of other side */
   }
   bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                   DEF_AUX_MEMGET,
                                   &adsl_ts1_w1->adsc_tcpse1_ext_1,  /* TCP session extension */
                                   sizeof(struct dsd_tcpse1_ext_1) );
   if (bol1 == FALSE) {                     /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
// to-do 22.08.11 KB fill structure
   if (unl_sort_ineta.dsrl_ct_ipv4[ 1 ].iec_cti4 == ied_cti4_s5_client) {  /* Socks client TCP half-session */
#ifndef TRY_110901_02
     unl_sort_ineta.dsrl_ct_ipv4[ 0 ].iec_cti4 = ied_cti4_s5_client;  /* set Socks client TCP half-session */
#endif
     adsl_ts1_w1->adsc_tcpse1_ext_1->iec_tce1s = ied_tce1s_socks5_start;  /* start of Socks5 session */
     adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].imc_return = DEF_IRET_INT_ERROR;  /* this half-session not active */
     goto p_check_recv_00;                  /* all done                */
   }
   adsl_ts1_w1->adsc_tcpse1_ext_1->iec_tce1s = ied_tce1s_ftp_start;  /* start of FTP packet  */

   p_sdh_tcp_start_48:                      /* start SDH-TCP of other side */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_sdh_tcp_start_48: process SDH-TCP at adsl_ts1_w1=%p iml_dir_oth=%d.",
                 __LINE__, adsl_ts1_w1, iml_dir_oth );
#endif
   memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
   bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                      DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                      &dsl_aux_get_workarea,
                                      sizeof(struct dsd_aux_get_workarea) );
   if (bol1 == FALSE) {                     /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_sdh_tcp_1_sec->achc_work_area = dsl_aux_get_workarea.achc_work_area;  /* addr work-area returned */
   adsl_sdh_tcp_1_sec->imc_len_work_area = dsl_aux_get_workarea.imc_len_work_area;  /* length work-area returned */
   adsl_sdh_tcp_1_sec->amc_aux = &m_sub_aux;  /* helper routine pointer */
   dsl_subaux_userfld.adsc_sdh_tcp_1 = adsl_sdh_tcp_1_sec;  /* TCP half-session */
#ifdef B110823
   dsl_subaux_userfld.adsc_session_timer = &adsl_ts1_w1->dsrc_session_timer[ iml_dir_inp ];  /* session timer */
#else
   dsl_subaux_userfld.adsc_session_timer = &adsl_ts1_w1->dsrc_session_timer[ iml_dir_oth ];  /* session timer */
#endif
   adsl_sdh_tcp_1_sec->vpc_userfld = &dsl_subaux_userfld;  /* User Field Subroutine */
#ifdef TRACEHL_TIMER_01
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T call SDH-TCP adsc_sdh_tcp_1=%p boc_timer_running=%d.",
                 __LINE__, adsl_sdh_tcp_1_sec, adsl_sdh_tcp_1_sec->boc_timer_running );
   if (adsl_sdh_tcp_1_sec->adsc_tdc1_in) {
     adsl_tdc1_w1 = adsl_sdh_tcp_1_sec->adsc_tdc1_in;
     iml1 = 0;
     do {                                   /* loop over input data    */
       iml1++;                              /* increment counter input */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T inp %d. addr=%p adsc_gai1=%p imc_len_data=%d/0X%X umc_flags=0X%08X.",
                     __LINE__,
                     iml1,
                     adsl_tdc1_w1,
                     adsl_tdc1_w1->adsc_gai1,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->umc_flags );
       iml2 = adsl_tdc1_w1->imc_len_data;
       adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;
       while (adsl_gai1_w1) {
         if (iml2 <= 0) break;
         iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         if (iml3 > iml2) iml3 = iml2;
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T gather %p length %d/0X%X.",
                       __LINE__, adsl_gai1_w1, iml3, iml3 );
         m_sdh_console_out( &dsl_sdh_call_1, adsl_gai1_w1->achc_ginp_cur, iml3 );
         iml2 -= iml3;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
       adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next in chain   */
     } while (adsl_tdc1_w1);
   }
#endif
   m_sdhtcp01( adsl_sdh_tcp_1_sec );     /* call SDH-TCP            */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_sdhtcp01() %d returned %d adsc_tdc1_out_to_client=%p adsc_tdc1_out_to_server=%p.",
                 __LINE__,
                 iml_dir_inp,
                 adsl_sdh_tcp_1_sec->imc_return,
                 adsl_sdh_tcp_1_sec->adsc_tdc1_out_to_client,  /* output data to client */
                 adsl_sdh_tcp_1_sec->adsc_tdc1_out_to_server );  /* output data to server */
   if (adsl_sdh_tcp_1_sec->adsc_tdc1_out_to_client) {
     adsl_tdc1_w1 = adsl_sdh_tcp_1_sec->adsc_tdc1_out_to_client;
     iml1 = 0;
     do {                                   /* loop over input data    */
       iml1++;                              /* increment counter input */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T out-to-client %d. addr=%p adsc_gai1=%p imc_len_data=%d/0X%X umc_flags=0X%08X.",
                     __LINE__,
                     iml1,
                     adsl_tdc1_w1,
                     adsl_tdc1_w1->adsc_gai1,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->umc_flags );
       iml2 = adsl_tdc1_w1->imc_len_data;
       adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;
       while (adsl_gai1_w1) {
         if (iml2 <= 0) break;
         iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         if (iml3 > iml2) iml3 = iml2;
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T gather %p length %d/0X%X.",
                       __LINE__, adsl_gai1_w1, iml3, iml3 );
         m_sdh_console_out( &dsl_sdh_call_1, adsl_gai1_w1->achc_ginp_cur, iml3 );
         iml2 -= iml3;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
       adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next in chain   */
     } while (adsl_tdc1_w1);
   }
   if (adsl_sdh_tcp_1_sec->adsc_tdc1_out_to_server) {
     adsl_tdc1_w1 = adsl_sdh_tcp_1_sec->adsc_tdc1_out_to_server;
     iml1 = 0;
     do {                                   /* loop over input data    */
       iml1++;                              /* increment counter input */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T out-to-server %d. addr=%p adsc_gai1=%p imc_len_data=%d/0X%X umc_flags=0X%08X.",
                     __LINE__,
                     iml1,
                     adsl_tdc1_w1,
                     adsl_tdc1_w1->adsc_gai1,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->umc_flags );
       iml2 = adsl_tdc1_w1->imc_len_data;
       adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;
       while (adsl_gai1_w1) {
         if (iml2 <= 0) break;
         iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         if (iml3 > iml2) iml3 = iml2;
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T gather %p length %d/0X%X.",
                       __LINE__, adsl_gai1_w1, iml3, iml3 );
         m_sdh_console_out( &dsl_sdh_call_1, adsl_gai1_w1->achc_ginp_cur, iml3 );
         iml2 -= iml3;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
       adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next in chain   */
     } while (adsl_tdc1_w1);
   }
#endif
#ifndef B130409
   if (adsl_sdh_tcp_1_sec->imc_return != DEF_IRET_NORMAL) {
     adsl_sdh_tcp_1_sec->imc_func = 0;      /* TCP connection not started, do not call again */
   }
#endif
   if (adsl_sdh_tcp_1_sec->adsc_tdc1_out_to_server == NULL) {  /* output data to server */
     goto p_check_recv_00;                  /* all done                */
   }
   adsl_tdc1_w1 = adsl_sdh_tcp_1_sec->adsc_tdc1_out_to_server;  /* output data to server */
   adsl_sdh_tcp_1_sec->adsc_tdc1_out_to_server = NULL;  /* clear output data to server */
   iml_len_ip_header = D_LEN_HEADER_IPV4;   /* length of IP header IPV4 */
// chl_ipv4_ipv6 = '4';                     /* protocol from IP header */
   if (bol_ipv6) {                          /* is IPV6, not IPV4       */
     iml_len_ip_header = D_LEN_HEADER_IPV6;  /* length of IP header IPV6 */
//   chl_ipv4_ipv6 = '6';                   /* protocol from IP header */
   }

   p_sdh_tcp_start_60:                      /* process output of SDH-TCP */
#ifdef DEBUG_120822_01
   if ((adsl_tdc1_w1->imc_len_data == 0) && adsl_tdc1_w1->umc_flags == 0) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_sdh_tcp_start_60: DEBUG_120822_01 p_sdh_tcp_cont_20: both imc_len_data and umc_flags zero",
                   __LINE__, iml_clse_pri );
   }
#endif
   dsl_oa1.achc_upper -=sizeof(struct dsd_gather_i_1);
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   if (dsl_oa1.achc_upper < (dsl_oa1.achc_lower + OUT_LEN_NHASN + 1 + iml_len_ip_header)) goto p_out_80;  /* overflow */
#else
   if (dsl_oa1.achc_upper < (dsl_oa1.achc_lower + iml_len_ip_header)) goto p_out_80;  /* overflow */
#endif
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) dsl_oa1.achc_upper)
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   achl1 = achl2 = dsl_oa1.achc_lower + OUT_LEN_NHASN + 1;
#else
   achl1 = dsl_oa1.achc_lower;
#endif
   iml3 = adsl_tdc1_w1->imc_len_data;       /* length of the data      */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml3 <= 0) goto p_illogic_00;        /* program illogic         */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   *(--achl1) = chl_ipv4_ipv6;              /* type IPV4 / IPV6        */
   iml1 = 1 + iml_len_ip_header + iml3;     /* length of packet        */
   iml2 = 0;                                /* clear more bit          */
   do {
     *(--achl1) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* remove bits set         */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
#endif
   ADSL_GAI1_G->achc_ginp_cur = achl1;
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   ADSL_GAI1_G->achc_ginp_end = achl2 + iml_len_ip_header;
#else
   ADSL_GAI1_G->achc_ginp_end = achl1 + iml_len_ip_header;
#endif
   ADSL_GAI1_G->adsc_next = NULL;
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   if (bol_ipv6 == FALSE) {                 /* is IPV4, not IPV6       */
     m_build_header_ipv4( achl2,
//                        (struct dsd_ctrl_tcp_ipv4 *) (adsl_ts1_w1 + 1),
                          &unl_sort_ineta.dsrl_ct_ipv4[ iml_dir_oth ],
                          iml_dir_inp,
                          iml3 );
   } else {                                 /* is IPV6, not IPV4       */
     m_build_header_ipv6( achl2,
                          (struct dsd_ctrl_tcp_ipv6 *) (adsl_ts1_w1 + 1),
                          iml_dir_inp,
                          iml3 );
   }
   dsl_oa1.achc_lower += OUT_LEN_NHASN + 1 + iml_len_ip_header;
#else
   if (bol_ipv6 == FALSE) {                 /* is IPV4, not IPV6       */
     m_build_header_ipv4( achl1,
//                        (struct dsd_ctrl_tcp_ipv4 *) (adsl_ts1_w1 + 1),
                          &unl_sort_ineta.dsrl_ct_ipv4[ iml_dir_oth ],
                          iml_dir_inp,
                          iml3 );
   } else {                                 /* is IPV6, not IPV4       */
     m_build_header_ipv6( achl1,
                          (struct dsd_ctrl_tcp_ipv6 *) (adsl_ts1_w1 + 1),
                          iml_dir_inp,
                          iml3 );
   }
   dsl_oa1.achc_lower += iml_len_ip_header;
#endif
   *aadsrl_gai1_out[ iml_dir_oth ] = ADSL_GAI1_G;
   aadsrl_gai1_out[ iml_dir_oth ] = &ADSL_GAI1_G->adsc_next;
   adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;  /* data                    */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic    */

   p_sdh_tcp_start_64:                      /* process output of SDH-TCP */
   dsl_oa1.achc_upper -=sizeof(struct dsd_gather_i_1);
   if (dsl_oa1.achc_upper < dsl_oa1.achc_lower) goto p_out_80;  /* overflow */
   iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
   if (iml1 > iml3) iml1 = iml3;            /* only what is needed     */
   ADSL_GAI1_G->achc_ginp_cur = adsl_gai1_w1->achc_ginp_cur;
   ADSL_GAI1_G->achc_ginp_end = adsl_gai1_w1->achc_ginp_cur + iml1;
   ADSL_GAI1_G->adsc_next = NULL;
   *aadsrl_gai1_out[ iml_dir_oth ] = ADSL_GAI1_G;
   aadsrl_gai1_out[ iml_dir_oth ] = &ADSL_GAI1_G->adsc_next;
   iml3 -= iml1;                            /* count data processed    */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml3 > 0) {                          /* we need more data       */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next input in chain */
     if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic  */
     goto p_sdh_tcp_start_64;               /* process output of SDH-TCP */
   }
   adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next in chain       */
   if (adsl_tdc1_w1) {                      /* more packets to send    */
     goto p_sdh_tcp_start_60;               /* process output of SDH-TCP */
   }
   goto p_sdh_tcp_end_00;                   /* packet has been processed by SDH-TCP */

#undef ADSL_GAI1_G

   p_sdh_tcp_cont_00:                       /* continue SDH-TCP        */
#ifdef TRACEHL_111004
   memmove( adsl_contr_1->imrl_trace_lno,
            adsl_contr_1->imrl_trace_lno + 1,
            (TRACEHL_111004 - 1) * sizeof(int) );
   adsl_contr_1->imrl_trace_lno[ TRACEHL_111004 - 1 ] = __LINE__;
#endif
   iel_ps = ied_ps_cont;                    /* continue TCP session    */
   adsl_ts1_w1 = ((struct dsd_tcp_session_1 *) dsl_htree1_work.adsc_found) - 1;  /* structure TCP session */
   if (bol_ipv6 == FALSE) {                 /* is IPV4, not IPV6       */
     if (((struct dsd_sort_tcp_ipv4 *) dsl_htree1_work.adsc_found)->dsc_ct_ipv4.iec_cti4 == ied_cti4_s5_server) {  /* Socks server TCP half-session */
       adsl_ts1_w1
         = ((struct dsd_tcp_session_1 *) ((char *) dsl_htree1_work.adsc_found - sizeof(struct dsd_sort_tcp_ipv4))) - 1;  /* structure TCP session */
     } else if (((struct dsd_sort_tcp_ipv4 *) dsl_htree1_work.adsc_found)->dsc_ct_ipv4.iec_cti4 == ied_cti4_s5_client) {  /* Socks client TCP half-session */
       *((UNSIG_MED *) &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 1 ][ 0 ])
         = *((UNSIG_MED *) &adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].chrc_header_info[ 4 ]);
     }
   }
   iml_clse_pri = iml_dir_inp;              /* primary client to server */
   iml_clse_sec = iml_dir_oth;              /* secondary client to server */
   adsl_sdh_tcp_1_pri = &adsl_ts1_w1->dsrc_sdh_tcp_1[ iml_clse_pri ];
   adsl_sdh_tcp_1_sec = &adsl_ts1_w1->dsrc_sdh_tcp_1[ iml_clse_sec ];
   if (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL) {  /* already closed */
     goto p_sdh_tcp_end_00;                 /* packet has been processed by SDH-TCP */
   }

   /* get input starting from the TCP header                           */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml1 = 1 + iml_len_ip_header;            /* after the IP header     */
#else
   iml1 = iml_len_ip_header;                /* after the IP header     */
#endif
   achl_packet = achl_save_packet;          /* start of packet         */
   adsl_gai1_inp_packet = adsl_gai1_inp_save_packet;  /* input packet data */

   p_sdh_tcp_cont_08:                      /* loop to overread parts of IP header */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 <= iml1) {
     achl_packet = adsl_gai1_inp_packet->achc_ginp_end;  /* at end of this gather */
     iml1 -= iml2;                          /* displacement in next gather */
     goto p_sdh_tcp_cont_08;                /* loop to overread parts of IP header */
   }
   achl_packet += iml1;                     /* start of INETAs         */
   dsl_gai1_sdh_tcp_in.achc_ginp_cur = achl_packet;  /* start in gather */
   dsl_gai1_sdh_tcp_in.achc_ginp_end = adsl_gai1_inp_packet->achc_ginp_end;  /* end in gather */
   dsl_gai1_sdh_tcp_in.adsc_next = adsl_gai1_inp_packet->adsc_next;  /* append chain of gather */
   memset( &dsl_tdc1_sdh_tcp_in, 0, sizeof(struct dsd_tcp_data_contr_1) );  /* TCP data control structure */
   dsl_tdc1_sdh_tcp_in.adsc_gai1 = &dsl_gai1_sdh_tcp_in;  /* data      */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   dsl_tdc1_sdh_tcp_in.imc_len_data = iml_len_packet - (1 + iml_len_ip_header);  /* length of the data */
#else
   dsl_tdc1_sdh_tcp_in.imc_len_data = iml_len_packet - iml_len_ip_header;  /* length of the data */
#endif
   adsl_sdh_tcp_1_pri->adsc_tdc1_in = &dsl_tdc1_sdh_tcp_in;  /* input data */

   p_sdh_tcp_cont_12:                       /* call SDH-TCP            */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_sdh_tcp_cont_12: process SDH-TCP at adsl_ts1_w1=%p iml_clse_pri=%d.",
                 __LINE__, adsl_ts1_w1, iml_clse_pri );
#endif
   memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
   bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                      DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                      &dsl_aux_get_workarea,
                                      sizeof(struct dsd_aux_get_workarea) );
   if (bol1 == FALSE) {                     /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_sdh_tcp_1_pri->achc_work_area = dsl_aux_get_workarea.achc_work_area;  /* addr work-area returned */
   adsl_sdh_tcp_1_pri->imc_len_work_area = dsl_aux_get_workarea.imc_len_work_area;  /* length work-area returned */
   dsl_subaux_userfld.adsc_sdh_tcp_1 = adsl_sdh_tcp_1_pri;  /* TCP half-session */
   dsl_subaux_userfld.adsc_session_timer = &adsl_ts1_w1->dsrc_session_timer[ iml_clse_pri ];  /* session timer */
#ifdef TRACEHL_TIMER_01
   bol1 = FALSE;                            /* no timer was running    */
#endif
   if (adsl_ts1_w1->dsrc_session_timer[ iml_clse_pri ].ilc_epoch_end) {  /* epoch timer set */
#ifdef TRACEHL_TIMER_01
     bol1 = TRUE;                           /* timer was running       */
#endif
     if (adsl_ts1_w1->dsrc_session_timer[ iml_clse_pri ].ilc_epoch_end
           <= dsl_subaux_userfld.ilc_epoch) {  /* timer has elapsed    */
       adsl_sdh_tcp_1_pri->boc_timer_running = FALSE;  /* timer is currently not running */
     }
   }
#ifdef XYZ1
   if (iml_clse_pri == 0) {                 /* primary client to server */
     adsl_sdh_tcp_1_pri->boc_notify_send_netw_possible
       = adsp_hl_clib_1->boc_notify_send_client_possible;  /* notify SDH when sending to the client is possible */
   }
#endif
   if (iml_clse_pri == 0) {                 /* primary client to server */
     adsl_sdh_tcp_1_pri->boc_send_netw_blocked  /* sending to the network is blocked */
       = adsp_hl_clib_1->boc_send_client_blocked;  /* sending to the client is blocked */
     if (adsl_ts1_w1->dsc_session_notify.iec_se_no != ied_se_no_idle) {  /* notify session set */
       if (&adsl_ts1_w1->dsc_session_notify == adsl_contr_1->adsc_session_notify) {
         adsl_contr_1->adsc_session_notify = adsl_contr_1->adsc_session_notify->adsc_next;  /* remove from chain */
       } else {                             /* middle in chain         */
         adsl_session_notify_w1 = adsl_contr_1->adsc_session_notify;  /* session notify send possible */
         while (TRUE) {                     /* loop over all session notify */
           if (&adsl_ts1_w1->dsc_session_notify == adsl_session_notify_w1->adsc_next) {
#ifdef B140708
             adsl_session_notify_w1->adsc_next->adsc_next = adsl_session_notify_w1->adsc_next;  /* remove from chain */
#endif
#ifndef B140708
             adsl_session_notify_w1->adsc_next = adsl_session_notify_w1->adsc_next->adsc_next;  /* remove from chain */
#endif
             break;                         /* all done                */
           }
           adsl_session_notify_w1 = adsl_session_notify_w1->adsc_next;
           if (adsl_session_notify_w1 == NULL) {  /* at end of chain   */
             m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W chain notify session corrupted", __LINE__ );
             break;
           }
         }
       }
       adsl_ts1_w1->dsc_session_notify.iec_se_no = ied_se_no_idle;  /* notify session no more set */
     }
   }
   adsl_sdh_tcp_1_pri->vpc_userfld = &dsl_subaux_userfld;  /* User Field Subroutine */
   adsl_sdh_tcp_1_pri->imc_func = DEF_IFUNC_FROMSERVER;  /* data from server */
#ifdef TRACEHL_TIMER_01
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T call SDH-TCP adsc_sdh_tcp_1=%p timer-before=%d boc_timer_running=%d.",
                 __LINE__, adsl_sdh_tcp_1_pri, bol1, adsl_sdh_tcp_1_pri->boc_timer_running );
   if (adsl_sdh_tcp_1_pri->adsc_tdc1_in) {
     adsl_tdc1_w1 = adsl_sdh_tcp_1_pri->adsc_tdc1_in;
     iml1 = 0;
     do {                                   /* loop over input data    */
       iml1++;                              /* increment counter input */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T inp %d. addr=%p adsc_gai1=%p imc_len_data=%d/0X%X umc_flags=0X%08X.",
                     __LINE__,
                     iml1,
                     adsl_tdc1_w1,
                     adsl_tdc1_w1->adsc_gai1,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->umc_flags );
       iml2 = adsl_tdc1_w1->imc_len_data;
       adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;
       while (adsl_gai1_w1) {
         if (iml2 <= 0) break;
         iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         if (iml3 > iml2) iml3 = iml2;
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T gather %p length %d/0X%X.",
                       __LINE__, adsl_gai1_w1, iml3, iml3 );
         m_sdh_console_out( &dsl_sdh_call_1, adsl_gai1_w1->achc_ginp_cur, iml3 );
         iml2 -= iml3;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
       adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next in chain   */
     } while (adsl_tdc1_w1);
   }
#endif
   m_sdhtcp01( adsl_sdh_tcp_1_pri );        /* call SDH-TCP            */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_sdhtcp01() %d returned %d adsc_tdc1_out_to_client=%p adsc_tdc1_out_to_server=%p.",
                 __LINE__,
                 iml_clse_pri,
                 adsl_sdh_tcp_1_pri->imc_return,
                 adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client,  /* output data to client */
                 adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server );  /* output data to server */
   if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client) {
     adsl_tdc1_w1 = adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client;
     iml1 = 0;
     do {                                   /* loop over input data    */
       iml1++;                              /* increment counter input */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T out-to-client %d. addr=%p adsc_gai1=%p imc_len_data=%d/0X%X umc_flags=0X%08X.",
                     __LINE__,
                     iml1,
                     adsl_tdc1_w1,
                     adsl_tdc1_w1->adsc_gai1,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->umc_flags );
       iml2 = adsl_tdc1_w1->imc_len_data;
       adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;
       while (adsl_gai1_w1) {
         if (iml2 <= 0) break;
         iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         if (iml3 > iml2) iml3 = iml2;
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T gather %p length %d/0X%X.",
                       __LINE__, adsl_gai1_w1, iml3, iml3 );
         m_sdh_console_out( &dsl_sdh_call_1, adsl_gai1_w1->achc_ginp_cur, iml3 );
         iml2 -= iml3;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
       adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next in chain   */
     } while (adsl_tdc1_w1);
   }
   if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server) {
     adsl_tdc1_w1 = adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server;
     iml1 = 0;
     do {                                   /* loop over input data    */
       iml1++;                              /* increment counter input */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T out-to-server %d. addr=%p adsc_gai1=%p imc_len_data=%d/0X%X umc_flags=0X%08X.",
                     __LINE__,
                     iml1,
                     adsl_tdc1_w1,
                     adsl_tdc1_w1->adsc_gai1,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->umc_flags );
       iml2 = adsl_tdc1_w1->imc_len_data;
       adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;
       while (adsl_gai1_w1) {
         if (iml2 <= 0) break;
         iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         if (iml3 > iml2) iml3 = iml2;
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T gather %p length %d/0X%X.",
                       __LINE__, adsl_gai1_w1, iml3, iml3 );
         m_sdh_console_out( &dsl_sdh_call_1, adsl_gai1_w1->achc_ginp_cur, iml3 );
         iml2 -= iml3;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
       adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next in chain   */
     } while (adsl_tdc1_w1);
   }
#endif
#ifdef B120309
   adsl_sdh_tcp_1_sec->boc_stop_receiving = FALSE;  /* stop receiving from the server */
   if (adsl_sdh_tcp_1_pri->imc_queue_buffer > MAX_TCP_SNDBUF) {  /* bytes TCP packets buffered for sending to the server */
     adsl_sdh_tcp_1_sec->boc_stop_receiving = TRUE;  /* stop receiving from the server */
   }
#endif
#ifndef B130409
   if (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL) {
     adsl_sdh_tcp_1_pri->imc_func = 0;      /* TCP connection not started, do not call again */
   }
#endif
   /* set notify send to network possible when requested               */
   if (   (iml_clse_pri == 0)               /* primary client to server */
       && (adsl_sdh_tcp_1_pri->boc_notify_send_netw_possible)  /* notify SDH-TCP when sending to the network is possible */
       && (adsl_sdh_tcp_1_pri->imc_return == DEF_IRET_NORMAL)) {
#ifdef DEBUG_111119_01
     if (   (adsp_hl_clib_1->boc_send_client_blocked == FALSE)  /* sending to the client is not blocked */
         && (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server == NULL)  /* no output data to server */
         && (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client == NULL)) {  /* no output data to client */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-X ! Attention ! m_sdhtcp01() generates loop - request boc_notify_send_netw_possible, send possible but no output",
                     __LINE__ );
     }
#endif
     adsl_ts1_w1->dsc_session_notify.iec_se_no = ied_se_no_act_new;  /* active, new */
     adsl_ts1_w1->dsc_session_notify.adsc_next = NULL;  /* clear chain field */
     if (adsl_contr_1->adsc_session_notify == NULL) {  /* now first in chain */
       adsl_contr_1->adsc_session_notify = &adsl_ts1_w1->dsc_session_notify;  /* set new chain */
     } else {                               /* middle in chain         */
       adsl_session_notify_w1 = adsl_contr_1->adsc_session_notify;  /* session notify send possible */
       while (adsl_session_notify_w1->adsc_next) adsl_session_notify_w1 = adsl_session_notify_w1->adsc_next;
       adsl_session_notify_w1->adsc_next = &adsl_ts1_w1->dsc_session_notify;  /* append to chain */
     }
   }
#ifdef TRACEHL_INETA_01
   if (bol_ipv6 == FALSE) {                 /* is IPV4, not IPV6       */
     m_trineta_print_01( chrl_trineta_buf,
                         &unl_sort_ineta.dsrl_ct_ipv4[ iml_clse_pri ],
                         iml_clse_sec );
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_sdh_tcp_cont_12: adsl_sdh_tcp_1_pri=%p iml_clse_pri=%d r=%s %s",
                   __LINE__, adsl_sdh_tcp_1_pri, iml_clse_pri, achl_trhl_reason, chrl_trineta_buf );
   }
#endif
   if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server == NULL) {  /* output data to server */
     goto p_sdh_tcp_cont_60;                /* check output client side */
   }
   adsl_tdc1_w1 = adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server;  /* output data to server */
   adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server = NULL;  /* clear output data to server */
   iml_len_ip_header = D_LEN_HEADER_IPV4;   /* length of IP header IPV4 */
// chl_ipv4_ipv6 = '4';                     /* protocol from IP header */
   if (bol_ipv6) {                          /* is IPV6, not IPV4       */
     iml_len_ip_header = D_LEN_HEADER_IPV6;  /* length of IP header IPV6 */
//   chl_ipv4_ipv6 = '6';                   /* protocol from IP header */
   }
#ifdef TRACEHL_111004
   memmove( adsl_contr_1->imrl_trace_lno,
            adsl_contr_1->imrl_trace_lno + 1,
            (TRACEHL_111004 - 1) * sizeof(int) );
   adsl_contr_1->imrl_trace_lno[ TRACEHL_111004 - 1 ] = __LINE__;
#endif

   p_sdh_tcp_cont_20:                       /* process output of SDH-TCP */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_sdh_tcp_cont_20: send output of SDH-TCP to iml_clse_pri=%d imc_len_data=%d umc_flags=0X%X.",
                 __LINE__, iml_clse_pri, adsl_tdc1_w1->imc_len_data, adsl_tdc1_w1->umc_flags );
#endif
#ifdef DEBUG_120822_01
   if ((adsl_tdc1_w1->imc_len_data == 0) && adsl_tdc1_w1->umc_flags == 0) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_sdh_tcp_cont_20: DEBUG_120822_01 p_sdh_tcp_cont_20: both imc_len_data and umc_flags zero",
                   __LINE__, iml_clse_pri );
   }
#endif
#ifdef TRACEHL_111004
   memmove( adsl_contr_1->imrl_trace_lno,
            adsl_contr_1->imrl_trace_lno + 1,
            (TRACEHL_111004 - 1) * sizeof(int) );
   adsl_contr_1->imrl_trace_lno[ TRACEHL_111004 - 1 ] = __LINE__;
#endif
   dsl_oa1.achc_upper -= sizeof(struct dsd_gather_i_1);
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   if (dsl_oa1.achc_upper < (dsl_oa1.achc_lower + OUT_LEN_NHASN + 1 + iml_len_ip_header)) goto p_out_80;  /* overflow */
#else
   if (dsl_oa1.achc_upper < (dsl_oa1.achc_lower + iml_len_ip_header)) goto p_out_80;  /* overflow */
#endif
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) dsl_oa1.achc_upper)
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   achl1 = achl2 = dsl_oa1.achc_lower + OUT_LEN_NHASN + 1;
#else
   achl1 = dsl_oa1.achc_lower;
#endif
   iml3 = adsl_tdc1_w1->imc_len_data;       /* length of the data      */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml3 <= 0) goto p_illogic_00;        /* program illogic         */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   *(--achl1) = chl_ipv4_ipv6;              /* type IPV4 / IPV6        */
   iml1 = 1 + iml_len_ip_header + iml3;     /* length of packet        */
   iml2 = 0;                                /* clear more bit          */
   do {
     *(--achl1) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* remove bits set         */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
#endif
   ADSL_GAI1_G->achc_ginp_cur = achl1;
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   ADSL_GAI1_G->achc_ginp_end = achl2 + iml_len_ip_header;
#else
   ADSL_GAI1_G->achc_ginp_end = achl1 + iml_len_ip_header;
#endif
   ADSL_GAI1_G->adsc_next = NULL;
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   if (bol_ipv6 == FALSE) {                 /* is IPV4, not IPV6       */
     m_build_header_ipv4( achl2,
//                        (struct dsd_ctrl_tcp_ipv4 *) (adsl_ts1_w1 + 1),
#ifdef B110823
                          &unl_sort_ineta.dsrl_ct_ipv4[ iml_clse_sec ],
                          iml_clse_pri,
#else
                          &unl_sort_ineta.dsrl_ct_ipv4[ iml_clse_pri ],
                          iml_clse_sec,
#endif
                          iml3 );
   } else {                                 /* is IPV6, not IPV4       */
     m_build_header_ipv6( achl2,
                          (struct dsd_ctrl_tcp_ipv6 *) (adsl_ts1_w1 + 1),
                          iml_clse_pri,
                          iml3 );
   }
   dsl_oa1.achc_lower += OUT_LEN_NHASN + 1 + iml_len_ip_header;
#else
   if (bol_ipv6 == FALSE) {                 /* is IPV4, not IPV6       */
     m_build_header_ipv4( achl1,
//                        (struct dsd_ctrl_tcp_ipv4 *) (adsl_ts1_w1 + 1),
#ifdef B110823
                          &unl_sort_ineta.dsrl_ct_ipv4[ iml_clse_sec ],
                          iml_clse_pri,
#else
                          &unl_sort_ineta.dsrl_ct_ipv4[ iml_clse_pri ],
                          iml_clse_sec,
#endif
                          iml3 );
   } else {                                 /* is IPV6, not IPV4       */
     m_build_header_ipv6( achl1,
                          (struct dsd_ctrl_tcp_ipv6 *) (adsl_ts1_w1 + 1),
                          iml_clse_pri,
                          iml3 );
   }
   dsl_oa1.achc_lower += iml_len_ip_header;
#endif
#ifdef B110823
   *aadsrl_gai1_out[ iml_clse_sec ] = ADSL_GAI1_G;
   aadsrl_gai1_out[ iml_clse_sec ] = &ADSL_GAI1_G->adsc_next;
#else
   *aadsrl_gai1_out[ iml_clse_pri ] = ADSL_GAI1_G;
   aadsrl_gai1_out[ iml_clse_pri ] = &ADSL_GAI1_G->adsc_next;
#endif
   adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;  /* data                    */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic    */

   p_sdh_tcp_cont_40:                       /* process output of SDH-TCP */
   dsl_oa1.achc_upper -=sizeof(struct dsd_gather_i_1);
   if (dsl_oa1.achc_upper < dsl_oa1.achc_lower) goto p_out_80;  /* overflow */
   iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
   if (iml1 > iml3) iml1 = iml3;            /* only what is needed     */
   ADSL_GAI1_G->achc_ginp_cur = adsl_gai1_w1->achc_ginp_cur;
   ADSL_GAI1_G->achc_ginp_end = adsl_gai1_w1->achc_ginp_cur + iml1;
   ADSL_GAI1_G->adsc_next = NULL;
#ifdef B110823
   *aadsrl_gai1_out[ iml_clse_sec ] = ADSL_GAI1_G;
   aadsrl_gai1_out[ iml_clse_sec ] = &ADSL_GAI1_G->adsc_next;
#else
   *aadsrl_gai1_out[ iml_clse_pri ] = ADSL_GAI1_G;
   aadsrl_gai1_out[ iml_clse_pri ] = &ADSL_GAI1_G->adsc_next;
#endif
   iml3 -= iml1;                            /* count data processed    */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml3 > 0) {                          /* we need more data       */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next input in chain */
     if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic  */
     goto p_sdh_tcp_cont_40;                /* process output of SDH-TCP */
   }
#ifdef TRACEHL_111004
   memmove( adsl_contr_1->imrl_trace_lno,
            adsl_contr_1->imrl_trace_lno + 1,
            (TRACEHL_111004 - 1) * sizeof(int) );
   adsl_contr_1->imrl_trace_lno[ TRACEHL_111004 - 1 ] = __LINE__;
#endif
   adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next in chain       */
   if (adsl_tdc1_w1) {                      /* more packets to send    */
     goto p_sdh_tcp_cont_20;                /* process output of SDH-TCP */
   }

   p_sdh_tcp_cont_60:                       /* check output client side */
#ifdef B120309
   bol1 = FALSE;                            /* do not process          */
   if (   (adsl_sdh_tcp_1_pri->iec_sts != ied_sts_normal)  /* not normal processing */
       || (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL)) {  /* half-session already closed */
     if (adsl_sdh_tcp_1_sec->boc_eof_client == FALSE) {  /* End-of-File Client */
       adsl_sdh_tcp_1_sec->boc_eof_client = TRUE;  /* End-of-File Client */
       bol1 = TRUE;                         /* do process              */
     }
   }
   if (adsl_ts1_w1->adsc_tcpse1_ext_1) {    /* not normal processing   */
     goto p_sdh_tcp_cont_64;                /* process special situation */
   }
   if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client) {  /* output data to client */
     bol1 = TRUE;                           /* do process              */
   }
   if (bol1) {                              /* do not process          */
     goto p_sdh_tcp_cont_80;                /* give output client to SDH-TCP other side */
   }
   goto p_sdh_tcp_end_00;                   /* packet has been processed by SDH-TCP */
#endif
#ifndef B120309
   bol_call_sec = FALSE;                    /* do not call SDH-TCP secondary */
   bol1 = FALSE;                            /* reset stop receiving from the server */
   if (adsl_sdh_tcp_1_pri->imc_queue_buffer > MAX_TCP_SNDBUF) {  /* bytes TCP packets buffered for sending to the server */
     bol1 = TRUE;                           /* stop receiving from the server */
   }
   if (adsl_sdh_tcp_1_sec->boc_stop_receiving != bol1) {  /* check stop receiving from the server */
     adsl_sdh_tcp_1_sec->boc_stop_receiving = bol1;  /* set stop receiving from the server */
     bol_call_sec = TRUE;                   /* do call SDH-TCP secondary */
   }
   if (   (adsl_sdh_tcp_1_pri->iec_sts != ied_sts_normal)  /* not normal processing */
       || (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL)) {  /* half-session already closed */
     if (adsl_sdh_tcp_1_sec->boc_eof_client == FALSE) {  /* End-of-File Client */
       adsl_sdh_tcp_1_sec->boc_eof_client = TRUE;  /* End-of-File Client */
       bol_call_sec = TRUE;                 /* do process              */
     }
   }
#ifdef B140730
   if (adsl_ts1_w1->adsc_tcpse1_ext_1) {    /* not normal processing   */
     goto p_sdh_tcp_cont_64;                /* process special situation */
   }
#endif
#ifndef B140730
   if (   (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client)  /* output data to client */
       && (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client->imc_len_data > 0)  /* length of the data */
       && (adsl_ts1_w1->adsc_tcpse1_ext_1)) {  /* not normal processing */
     goto p_sdh_tcp_cont_64;                /* process special situation */
   }
#endif
   if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client) {  /* output data to client */
     bol_call_sec = TRUE;                   /* do process              */
   }
   goto p_sdh_tcp_cont_80;                  /* give output client to SDH-TCP other side */
#endif

   p_sdh_tcp_cont_64:                       /* process special situation */
#ifdef DEBUG_110902_01
   if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client) {
     iml1 = 0;
   }
#endif
#define CHL_SOCKS_VERS *((char *) &adsl_ts1_w1->adsc_tcpse1_ext_1->chrc_buffer[ 4 ])
// if (iml_dir_oth == 0)                    /* from server to client   */
   if (iml_clse_sec == 0) {                 /* from server to client   */
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_sdh_tcp_cont_64: adsl_ts1_w1=%p adsl_sdh_tcp_1_pri=%p.",
                   __LINE__, adsl_ts1_w1, adsl_sdh_tcp_1_pri );
     m_sdh_console_out( &dsl_sdh_call_1, (char *) adsl_sdh_tcp_1_pri, sizeof(struct dsd_sdh_tcp_1) );
#endif
     switch (adsl_ts1_w1->adsc_tcpse1_ext_1->iec_tce1s) {  /* TCP session extension status */
       case ied_tce1s_ftp_start:            /* start of FTP packet     */
         if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client == NULL) {  /* no output data to client */
#ifdef B120309
           goto p_sdh_tcp_end_00;           /* packet has been processed by SDH-TCP */
#else
           goto p_sdh_tcp_cont_80;          /* give output client to SDH-TCP other side */
#endif
         }
         goto p_ftp_se2cl_00;               /* FTP server to client    */
       case ied_tce1s_ftp_cl2se:            /* FTP client to server    */
         if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client == NULL) {  /* no output data to client */
#ifdef B120309
           goto p_sdh_tcp_end_00;           /* packet has been processed by SDH-TCP */
#else
           goto p_sdh_tcp_cont_80;          /* give output client to SDH-TCP other side */
#endif
         }
         iml1 = __LINE__;                   /* set line of source      */
         goto p_ftp_error_00;               /* FTP error in command    */
       case ied_tce1s_ftp_se2cl:            /* FTP server to client    */
         if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client == NULL) {  /* no output data to client */
#ifdef B120309
           goto p_sdh_tcp_end_00;           /* packet has been processed by SDH-TCP */
#else
           goto p_sdh_tcp_cont_80;          /* give output client to SDH-TCP other side */
#endif
         }
         goto p_ftp_se2cl_20;               /* FTP server to client continue */
     }
     if (adsl_sdh_tcp_1_pri->boc_connection_established) {  /* TCP connection with server established */
       if ((dsl_oa1.achc_lower
             + 4 + 4 + 2
             + sizeof(struct dsd_gather_i_1)
             + sizeof(struct dsd_tcp_data_contr_1))
             > dsl_oa1.achc_upper) {
         goto p_out_80;                     /* overflow                */
       }
       dsl_oa1.achc_upper -= sizeof(struct dsd_tcp_data_contr_1) + sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) dsl_oa1.achc_upper)
#define ADSL_TDC1_G ((struct dsd_tcp_data_contr_1 *) (ADSL_GAI1_G + 1))
       ADSL_GAI1_G->achc_ginp_cur = dsl_oa1.achc_lower;
       if (CHL_SOCKS_VERS != 0X05) {        /* is not Socks5, so Socks4 */
         *(dsl_oa1.achc_lower + 0) = 0;     /* VN, version of the reply code */
         *(dsl_oa1.achc_lower + 1) = 90;    /* CD result code / request granted */
         memcpy( dsl_oa1.achc_lower + 2, &adsl_sdh_tcp_1_pri->usc_port_client, 2 );  /* set port */
         memcpy( dsl_oa1.achc_lower + 2 + 2, &adsl_sdh_tcp_1_pri->chrc_header_info[ 0 ], 4 );  /* set INETA */
         dsl_oa1.achc_lower += 2 + 2 + 4;
         dsl_oa1.achc_lower += 2 + 2 + 4;
         ADSL_TDC1_G->imc_len_data = 2 + 2 + 4;  /* length of the data */
       } else {                             /* is Socks5               */
         *(dsl_oa1.achc_lower + 0) = 0X05;  /* set Socks 5             */
         memset( dsl_oa1.achc_lower + 1, 0, 2 );  /* clear response area */
         *(dsl_oa1.achc_lower + 3) = D_DEST_IPV4ADDR;  /* ATYP         */
         memcpy( dsl_oa1.achc_lower + 4, &adsl_sdh_tcp_1_pri->chrc_header_info[ 0 ], 4 );  /* set INETA */
         memcpy( dsl_oa1.achc_lower + 4 + 4, &adsl_sdh_tcp_1_pri->usc_port_client, 2 );  /* set port */
         dsl_oa1.achc_lower += 4 + 4 + 2;
         ADSL_TDC1_G->imc_len_data = 4 + 4 + 2;  /* length of the data */
       }
       ADSL_GAI1_G->achc_ginp_end = dsl_oa1.achc_lower;
       ADSL_GAI1_G->adsc_next = NULL;       /* this is last in chain   */
       /* append data received from target                             */
       ADSL_TDC1_G->adsc_next = adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client;
       ADSL_TDC1_G->adsc_gai1 = ADSL_GAI1_G;  /* data                  */
#ifdef B120820
       ADSL_TDC1_G->boc_push_flag = TRUE;   /* PUSH flag of TCP header */
#else
       ADSL_TDC1_G->umc_flags = D_TCP_HEADER_FLAG_PSH;  /* PUSH flag of TCP header */
#endif
       adsl_sdh_tcp_1_sec->adsc_tdc1_in = ADSL_TDC1_G;  /* input data  */
#undef ADSL_GAI1_G
#undef ADSL_TDC1_G
     } else if (   (adsl_sdh_tcp_1_pri->iec_sts != ied_sts_normal)  /* not normal processing */
                || (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL)) {  /* half-session already closed */
       if ((dsl_oa1.achc_lower
             + 4 + 4 + 2
             + sizeof(struct dsd_gather_i_1)
             + sizeof(struct dsd_tcp_data_contr_1))
             > dsl_oa1.achc_upper) {
         goto p_out_80;                     /* overflow                */
       }
       dsl_oa1.achc_upper -= sizeof(struct dsd_tcp_data_contr_1) + sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) dsl_oa1.achc_upper)
#define ADSL_TDC1_G ((struct dsd_tcp_data_contr_1 *) (ADSL_GAI1_G + 1))
       ADSL_GAI1_G->achc_ginp_cur = dsl_oa1.achc_lower;
       *(dsl_oa1.achc_lower + 0) = 0X05;    /* set Socks 5             */
       *(dsl_oa1.achc_lower + 1) = 0X03;    /* REP network unreachable */
//     if (adsl_sdh_tcp_1_pri->imc_return == DEF_IRET_NORMAL) {  /* half-session not closed */
         if (adsl_sdh_tcp_1_pri->iec_sts == ied_sts_recv_rst) {  /* RST received from server */
           *(dsl_oa1.achc_lower + 1) = 0X05;  /* REP connection refused */
         } else if (adsl_sdh_tcp_1_pri->iec_sts == ied_sts_timeout) {  /* timeout of TCP session */
           *(dsl_oa1.achc_lower + 1) = 0X06;  /* REP TTL expired       */
         }
//     }
       *(dsl_oa1.achc_lower + 2) = 0;       /* RSV reserved            */
       *(dsl_oa1.achc_lower + 3) = D_DEST_IPV4ADDR;  /* ATYP           */
       memcpy( dsl_oa1.achc_lower + 4, &adsl_sdh_tcp_1_pri->chrc_header_info[ 0 ], 4 );  /* set INETA */
       memcpy( dsl_oa1.achc_lower + 4 + 4, &adsl_sdh_tcp_1_pri->usc_port_client, 2 );  /* set port */
       dsl_oa1.achc_lower += 4 + 4 + 2;
       ADSL_GAI1_G->achc_ginp_end = dsl_oa1.achc_lower;
       ADSL_GAI1_G->adsc_next = NULL;       /* this is last in chain   */
       /* append data received from target                             */
       ADSL_TDC1_G->adsc_next = adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client;
       ADSL_TDC1_G->adsc_gai1 = ADSL_GAI1_G;  /* data                  */
       ADSL_TDC1_G->imc_len_data = 4 + 4 + 2;  /* length of the data   */
#ifdef B120820
       ADSL_TDC1_G->boc_push_flag = TRUE;   /* PUSH flag of TCP header */
#else
       ADSL_TDC1_G->umc_flags = D_TCP_HEADER_FLAG_PSH;  /* PUSH flag of TCP header */
#endif
       adsl_sdh_tcp_1_sec->adsc_tdc1_in = ADSL_TDC1_G;  /* input data  */
#undef ADSL_GAI1_G
#undef ADSL_TDC1_G
     } else {                               /* still handshake         */
       if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client == NULL) {  /* no output data to client */
#ifdef B120309
         goto p_sdh_tcp_end_00;             /* packet has been processed by SDH-TCP */
#else
         goto p_sdh_tcp_cont_80;            /* give output client to SDH-TCP other side */
#endif
       }
#ifdef DEBUG_140730_01                      /* problems FTP            */
       iml_error_line = __LINE__;
#endif
       goto p_illogic_00;                   /* program illogic         */
     }
     bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                     DEF_AUX_MEMFREE,
                                     &adsl_ts1_w1->adsc_tcpse1_ext_1,
                                     0 );
     if (bol1 == FALSE) {                   /* error occured           */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
     adsl_ts1_w1->adsc_tcpse1_ext_1 = NULL;  /* no more special handling */
     iml_clse_pri = 0;                      /* primary client to server */
     iml_clse_sec = 1;                      /* secondary client to server */
     adsl_sdh_tcp_1_pri = &adsl_ts1_w1->dsrc_sdh_tcp_1[ 0 ];
     adsl_sdh_tcp_1_sec = &adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ];
     goto p_sdh_tcp_cont_84;                /* addresses for SDH-TCP have been set */
   }

#define IEL_S_STAT *((enum ied_s_stat_type *) &adsl_ts1_w1->adsc_tcpse1_ext_1->chrc_buffer[ 0 ])

#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T adsl_ts1_w1=%p iec_tce1s=%d adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client=%p.",
                 __LINE__, adsl_ts1_w1, adsl_ts1_w1->adsc_tcpse1_ext_1->iec_tce1s, adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client );
#endif

   switch (adsl_ts1_w1->adsc_tcpse1_ext_1->iec_tce1s) {  /* TCP session extension status */
     case ied_tce1s_socks5_start:           /* start of Socks5 session */
       if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client == NULL) {  /* no output data to client */
#ifdef B120309
         goto p_sdh_tcp_end_00;             /* packet has been processed by SDH-TCP */
#else
         goto p_sdh_tcp_cont_80;            /* give output client to SDH-TCP other side */
#endif
       }
       adsl_ts1_w1->adsc_tcpse1_ext_1->iec_tce1s = ied_tce1s_socks5_cont_inp;  /* continue input */
       IEL_S_STAT = ied_sall_stat_bp1;      /* begin first packet      */
       goto p_sdh_tcp_so_00;                /* process Socks packet    */
     case ied_tce1s_socks5_cont_inp:        /* continue input          */
       if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client == NULL) {  /* no output data to client */
#ifdef B120309
         goto p_sdh_tcp_end_00;             /* packet has been processed by SDH-TCP */
#else
         goto p_sdh_tcp_cont_80;            /* give output client to SDH-TCP other side */
#endif
       }
       goto p_sdh_tcp_so_00;                /* process Socks packet    */
     case ied_tce1s_socks5_wait_connect:    /* wait for connect of other half-session */
       if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client == NULL) {  /* no output data to client */
#ifdef B120309
         goto p_sdh_tcp_end_00;             /* packet has been processed by SDH-TCP */
#else
         goto p_sdh_tcp_cont_80;            /* give output client to SDH-TCP other side */
#endif
       }
       iml1 = __LINE__;                     /* set line number source  */
       goto p_sdh_tcp_so_60;                /* invalid data in packet  */
     case ied_tce1s_ftp_start:              /* start of FTP packet     */
       if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client == NULL) {  /* no output data to client */
#ifdef B120309
         goto p_sdh_tcp_end_00;             /* packet has been processed by SDH-TCP */
#else
         goto p_sdh_tcp_cont_80;            /* give output client to SDH-TCP other side */
#endif
       }
       goto p_ftp_cl2se_00;                 /* FTP client to server    */
     case ied_tce1s_ftp_cl2se:              /* FTP client to server    */
       if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client == NULL) {  /* no output data to client */
#ifdef B120309
         goto p_sdh_tcp_end_00;             /* packet has been processed by SDH-TCP */
#else
         goto p_sdh_tcp_cont_80;            /* give output client to SDH-TCP other side */
#endif
       }
       goto p_ftp_cl2se_20;                 /* FTP client to server continue */
     case ied_tce1s_ftp_se2cl:              /* FTP server to client    */
       if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client == NULL) {  /* no output data to client */
#ifdef B120309
         goto p_sdh_tcp_end_00;             /* packet has been processed by SDH-TCP */
#else
         goto p_sdh_tcp_cont_80;            /* give output client to SDH-TCP other side */
#endif
       }
       iml1 = __LINE__;                     /* set line of source      */
       goto p_ftp_error_00;                 /* FTP error in command    */
   }
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   goto p_illogic_00;                       /* program illogic         */

#define CHL_PREQ_ATYP *((char *) &adsl_ts1_w1->adsc_tcpse1_ext_1->chrc_buffer[ 5 ])
#define CHL_CHECK_DNS *((char *) &adsl_ts1_w1->adsc_tcpse1_ext_1->chrc_buffer[ 6 ])
#define BOL_S5_V1 *((BOOL *) &adsl_ts1_w1->adsc_tcpse1_ext_1->chrc_buffer[ 8 ])
#define IML_SALL_V1 (*((int *) &adsl_ts1_w1->adsc_tcpse1_ext_1->chrc_buffer[ 12 ]))
#define IML_SALL_V2 (*((int *) &adsl_ts1_w1->adsc_tcpse1_ext_1->chrc_buffer[ 16 ]))
#ifdef B130407
#define ACHL_SALL_INETA ((char *) &adsl_ts1_w1->adsc_tcpse1_ext_1->chrc_buffer[ 20 ])
#define ACHL_SALL_PORT ((char *) &adsl_ts1_w1->adsc_tcpse1_ext_1->chrc_buffer[ 36 ])
#ifndef B111108
#define ACHL_SALL_TARGET ((char *) &adsl_ts1_w1->adsc_tcpse1_ext_1->chrc_buffer[ 40 ])
#endif
#else
#define IML_SALL_V3 (*((int *) &adsl_ts1_w1->adsc_tcpse1_ext_1->chrc_buffer[ 20 ]))
#define ACHL_SALL_INETA ((char *) &adsl_ts1_w1->adsc_tcpse1_ext_1->chrc_buffer[ 128 ])
#define ACHL_SALL_PORT ((char *) &adsl_ts1_w1->adsc_tcpse1_ext_1->chrc_buffer[ 24 ])
#define ACHL_SALL_TARGET ((char *) &adsl_ts1_w1->adsc_tcpse1_ext_1->chrc_buffer[ 32 ])
#endif

   p_sdh_tcp_so_00:                         /* process Socks packet    */
   adsl_tdc1_w1 = adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client;  /* output data to client */
   adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client = NULL;  /* clear output data to client */

   p_sdh_tcp_so_04:                         /* process TCP record      */
   adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;  /* data                    */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic    */
   iml2 = adsl_tdc1_w1->imc_len_data;       /* length of the data      */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml2 <= 0) goto p_illogic_00;        /* program illogic         */
   do {                                     /* loop over input data    */
     if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) {
       achl_rb = adsl_gai1_w1->achc_ginp_cur;  /* start scann here     */
       achl1 = adsl_gai1_w1->achc_ginp_end;  /* end of data            */
       if ((achl_rb + iml2) < achl1) achl1 = achl_rb + iml2;
       iml2 -= achl1 - achl_rb;             /* subtruct from length record */
       while (achl_rb < achl1) {            /* loop over input data    */
         iml1 = achl1 - achl_rb;            /* length remaining        */
         switch (IEL_S_STAT) {              /* depending on Socks state */
           case ied_sall_stat_bp1:          /* begin first record      */
             CHL_SOCKS_VERS = *achl_rb++;   /* get first byte, Socks version */
             if (CHL_SOCKS_VERS == 0X04) {  /* is Socks4               */
               IEL_S_STAT = ied_s4stat_cc;  /* get SOCKS command code  */
               break;
             }
             if (CHL_SOCKS_VERS != 0X05) {  /* is not Socks5           */
               iml1 = __LINE__;             /* set line number source  */
               goto p_sdh_tcp_so_60;        /* invalid data in packet  */
             }
             IEL_S_STAT = ied_s5stat_nmeth;  /* get NMETHODS           */
             break;
           case ied_s4stat_cc:              /* get SOCKS command code  */
             if (*achl_rb != 1) {           /* is not CONNECT          */
               iml1 = __LINE__;             /* set line number source  */
               goto p_sdh_tcp_so_60;        /* invalid data in packet  */
             }
             achl_rb++;                     /* this byte procesed      */
             IEL_S_STAT = ied_s4stat_dstport;  /* Socks 4 destination port */
             IML_SALL_V1 = 2;               /* length of port          */
             IML_SALL_V2 = 0;               /* clear numeric value     */
             break;
           case ied_s4stat_dstport:         /* Socks 4 destination port */
             iml3 = IML_SALL_V1 - IML_SALL_V2;  /* bytes remaining to be filled */
             if (iml3 > iml1) iml3 = iml1;  /* only so many as input   */
             memcpy( ACHL_SALL_PORT + IML_SALL_V2, achl_rb, iml3 );  /* copy part of field */
             IML_SALL_V2 += iml3;           /* filled so far           */
             achl_rb += iml3;               /* so many input characters */
             if (IML_SALL_V2 < IML_SALL_V1) break;  /* field not yet filled */
             IEL_S_STAT = ied_s4stat_dstip;  /* Socks 4 destination IP address */
             IML_SALL_V1 = 4;               /* number of bytes to follow */
             IML_SALL_V2 = 0;               /* address filled so far   */
             break;
           case ied_s4stat_dstip:           /* Socks 4 destination IP address */
             iml3 = IML_SALL_V1 - IML_SALL_V2;  /* bytes remaining to be filled */
             if (iml3 > iml1) iml3 = iml1;  /* only so many as input   */
             memcpy( ACHL_SALL_INETA + IML_SALL_V2, achl_rb, iml3 );  /* copy part of field */
             IML_SALL_V2 += iml3;           /* filled so far           */
             achl_rb += iml3;               /* so many input characters */
             if (IML_SALL_V2 < IML_SALL_V1) break;  /* field not yet filled */
#ifdef B130407
             /* check Socks4A                                          */
             if (   (*(ACHL_SALL_INETA + 0) == 0)
                 && (*(ACHL_SALL_INETA + 1) == 0)
                 && (*(ACHL_SALL_INETA + 2) == 0)) {
               iml1 = __LINE__;             /* set line number source  */
               goto p_sdh_tcp_so_60;        /* invalid data in packet  */
             }
#endif
             IEL_S_STAT = ied_s4stat_userid;  /* Socks 4 userid        */
             IML_SALL_V1 = MAX_LEN_USERID;  /* maximum length userid   */
             break;
           case ied_s4stat_userid:          /* Socks 4 userid          */
             if (iml1 > IML_SALL_V1) {      /* check userid too long   */
               iml1 = __LINE__;             /* set line number source  */
               goto p_sdh_tcp_so_60;        /* invalid data in packet  */
             }
             IML_SALL_V1 -= iml1;           /* subtract length this chunk */
             do {                           /* loop over input userid, search NULL */
               if (*achl_rb++ == 0) break;  /* end of userid found     */
               iml1--;                      /* decrement length remaining input */
             } while (iml1 > 0);
             if (iml1 <= 0) break;          /* needs more input        */
             CHL_CHECK_DNS = 0;             /* do not check DNS name   */
             IEL_S_STAT = ied_sall_stat_do_connect;  /* do connect now */
             /* check Socks4A                                          */
             if (   (*(ACHL_SALL_INETA + 0) == 0)
                 && (*(ACHL_SALL_INETA + 1) == 0)
                 && (*(ACHL_SALL_INETA + 2) == 0)) {
               IEL_S_STAT = ied_s4stat_domain;  /* Socks 4 destination domain */
               IML_SALL_V1 = 0;             /* number of characters domain name */
             }
             break;
           case ied_s4stat_domain:          /* Socks 4 destination domain */
             do {                           /* loop to copy destination domain name */
               if (*achl_rb == 0) {         /* no auth found           */
                 achl_rb++;                 /* this byte processed     */
                 CHL_CHECK_DNS = 1;         /* do check DNS name       */
                 IEL_S_STAT = ied_sall_stat_do_connect;  /* do connect now */
                 break;
               }
               if (IML_SALL_V1 >= MAX_LEN_DOMAIN) {  /* maximum length destination domain */
                 iml1 = __LINE__;           /* set line number source  */
                 goto p_sdh_tcp_so_60;      /* invalid data in packet  */
               }
               ACHL_SALL_INETA[ IML_SALL_V1++ ] = *achl_rb++;  /* copy input */
               iml1--;                      /* decrement characters input */
             } while (iml1 > 0);
             break;                         /* needs more input data   */
           case ied_s5stat_nmeth:           /* NMETHODS field          */
             if (*achl_rb == 0) {           /* field is empty          */
               iml1 = __LINE__;             /* set line number source  */
               goto p_sdh_tcp_so_60;        /* invalid data in packet  */
             }
             IML_SALL_V1 = *achl_rb;        /* get NMETHODS            */
             achl_rb++;                     /* this byte procesed      */
             IEL_S_STAT = ied_s5stat_meth_f;  /* get field with METHODS */
             BOL_S5_V1 = FALSE;             /* not yet no auth         */
             break;
           case ied_s5stat_meth_f:          /* field with METHODS      */
             do {
               if (*achl_rb == 0) {         /* no auth found           */
                 if (BOL_S5_V1) {           /* no auth already set     */
                   iml1 = __LINE__;         /* set line number source  */
                   goto p_sdh_tcp_so_60;    /* invalid data in packet  */
                 }
                 BOL_S5_V1 = TRUE;          /* now no auth found       */
               }
               achl_rb++;                   /* input processed         */
               IML_SALL_V1--;                 /* one method decoded      */
               if (achl_rb >= achl1) break;  /* all input processed    */
             } while (IML_SALL_V1 > 0);
             if (IML_SALL_V1 > 0) break;      /* receive more data       */
             if (BOL_S5_V1 == FALSE) {      /* no auth already set     */
               iml1 = __LINE__;             /* set line number source  */
               goto p_sdh_tcp_so_60;        /* invalid data in packet  */
             }
             /* now send response                                      */
             IEL_S_STAT = ied_s5stat_send_resp_1;  /* send response authentication method */
             break;
           case ied_s5stat_send_resp_1:     /* send response authentication method */
             iml1 = __LINE__;               /* set line number source  */
             goto p_sdh_tcp_so_60;          /* invalid data in packet  */
           case ied_s5stat_preq_b:          /* packet request begin    */
             if (*achl_rb != 0X05) {        /* is not Socks5           */
               iml1 = __LINE__;             /* set line number source  */
               goto p_sdh_tcp_so_60;        /* invalid data in packet  */
             }
             achl_rb++;                     /* this byte procesed      */
             IEL_S_STAT = ied_s5stat_preq_cmd;  /* packet request CMD  */
             break;
           case ied_s5stat_preq_cmd:        /* packet request CMD      */
             if (*achl_rb != 1) {           /* is not connect          */
               iml1 = __LINE__;             /* set line number source  */
               goto p_sdh_tcp_so_60;        /* invalid data in packet  */
             }
             achl_rb++;                     /* this byte procesed      */
             IEL_S_STAT = ied_s5stat_preq_rsv;  /* packet request reseved */
             break;
           case ied_s5stat_preq_rsv:        /* packet request reserved */
             if (*achl_rb != 0) {           /* is not empty            */
               iml1 = __LINE__;             /* set line number source  */
               goto p_sdh_tcp_so_60;        /* invalid data in packet  */
             }
             achl_rb++;                     /* this byte procesed      */
             IEL_S_STAT = ied_s5stat_preq_atyp;  /* packet request address type */
             break;
           case ied_s5stat_preq_atyp:       /* packet request address type */
             CHL_PREQ_ATYP = *achl_rb++;    /* address type received   */
             CHL_CHECK_DNS = 0;             /* do not check DNS name   */
             switch (CHL_PREQ_ATYP) {       /* address type            */
               case 1:                      /* INETA IPV4              */
                 IML_SALL_V1 = 4;           /* number of bytes to follow */
                 break;
               case 3:                      /* domain name             */
                 CHL_CHECK_DNS = 1;         /* do check DNS name       */
                 break;
#ifdef NOT_YET_110831
               case 4:                      /* INETA IPV6              */
                 IML_SALL_V1 = 16;          /* number of bytes to follow */
                 break;
#endif
               default:
                 iml1 = __LINE__;           /* set line number source  */
                 goto p_sdh_tcp_so_60;      /* invalid data in packet  */
             }
             IEL_S_STAT = ied_s5stat_preq_daddr;  /* packet request destination address */
             if (CHL_CHECK_DNS) IEL_S_STAT = ied_s5stat_preq_nooct;  /* packet request number of octets */
#ifdef NOT_YET_110831
             adsl_gai1_w1 = 0;              /* position INETA          */
#endif
             IML_SALL_V2 = 0;               /* address filled so far   */
             break;
           case ied_s5stat_preq_nooct:      /* packet request number of octets */
             IML_SALL_V1 = *((unsigned char *) achl_rb);
             achl_rb++;                     /* this byte processed     */
             IEL_S_STAT = ied_s5stat_preq_daddr;  /* packet request destination address */
             if (IML_SALL_V1) break;        /* all valid               */
             iml1 = __LINE__;               /* set line number source  */
             goto p_sdh_tcp_so_60;          /* invalid data in packet  */
           case ied_s5stat_preq_daddr:      /* packet request destination address */
             iml3 = IML_SALL_V1 - IML_SALL_V2;  /* bytes remaining to be filled */
             if (iml3 > iml1) iml3 = iml1;  /* only so many as input   */
             memcpy( ACHL_SALL_INETA + IML_SALL_V2, achl_rb, iml3 );  /* copy part of field */
             IML_SALL_V2 += iml3;           /* filled so far           */
             achl_rb += iml3;               /* so many input characters */
             if (IML_SALL_V2 < IML_SALL_V1) break;  /* field not yet filled */
             IEL_S_STAT = ied_s5stat_preq_dport;  /* packet request destination port */
#ifdef B130409
             IML_SALL_V1 = 2;               /* length of port          */
#else
             IML_SALL_V3 = 2;               /* length of port          */
#endif
             IML_SALL_V2 = 0;               /* clear numeric value     */
             break;
           case ied_s5stat_preq_dport:      /* packet request destination port */
#ifdef NOT_YET_110831
             while (TRUE) {
               iml4 <<= 8;                  /* shift previous value    */
               iml4 |= (unsigned char) *achl_rb++;  /* get input       */
               iml3--;                      /* one byte processed      */
               if (iml3 == 0) break;        /* end of port             */
               if (achl_rb >= adsl_gai1_inp_1->achc_ginp_end) break;  /* end of input data */
             }
             if (iml3 > 0) break;           /* not yet end of port     */
             switch (CHL_PREQ_ATYP) {       /* address type            */
               case 1:                      /* INETA IPV4              */
                 sprintf( CHRL_WORK_2, "%d.%d.%d.%d",
                          (unsigned char) CHRL_WORK_1[0], (unsigned char) CHRL_WORK_1[1],
                          (unsigned char) CHRL_WORK_1[2], (unsigned char) CHRL_WORK_1[3] );
                 achl1 = CHRL_WORK_2;       /* here is INETA           */
                 break;
               case 3:                      /* domain name             */
                 *(CHRL_WORK_1 + iml2) = 0;  /* make zero-terminated   */
                 achl1 = CHRL_WORK_1;       /* here is INETA           */
                 break;
               case 4:                      /* INETA IPV6              */
                 memset( &dsl_soa_l, 0, sizeof(struct sockaddr_in6) );
                 dsl_soa_l.sin6_family = AF_INET6;
                 memcpy( &dsl_soa_l.sin6_addr, CHRL_WORK_1, 16 );
                 iml_rc = getnameinfo( (struct sockaddr *) &dsl_soa_l, sizeof(struct sockaddr_in6),
                                       CHRL_WORK_2, 128, 0, 0, NI_NUMERICHOST );
                 if (iml_rc) {              /* error occured           */
                   m_sdh_printf( &dsl_sdh_call_1, "xlt-sdh-socks5-1-l%05d-W IPV6 getnameinfo() returned %d %d.",
                                 __LINE__, iml_rc, D_TCP_ERROR );
                   iml1 = __LINE__;         /* set line number source  */
                   goto psock_20;           /* invalid data in packet  */
                 }
                 achl1 = CHRL_WORK_2;       /* here is INETA           */
                 break;
             }
#endif
#ifdef B130409
             iml3 = IML_SALL_V1 - IML_SALL_V2;  /* bytes remaining to be filled */
#else
             iml3 = IML_SALL_V3 - IML_SALL_V2;  /* bytes remaining to be filled */
#endif
             if (iml3 > iml1) iml3 = iml1;  /* only so many as input   */
             memcpy( ACHL_SALL_PORT + IML_SALL_V2, achl_rb, iml3 );  /* copy part of field */
             IML_SALL_V2 += iml3;             /* filled so far           */
             achl_rb += iml3;               /* so many input characters */
#ifdef B130409
             if (IML_SALL_V2 < IML_SALL_V1) break;  /* field not yet filled */
#else
             if (IML_SALL_V2 < IML_SALL_V3) break;  /* field not yet filled */
#endif
             IEL_S_STAT = ied_sall_stat_do_connect;  /* do connect now */
             break;
           case ied_sall_stat_do_connect:   /* do connect now          */
             iml1 = __LINE__;               /* set line number source  */
             goto p_sdh_tcp_so_60;          /* invalid data in packet  */
         }
       }
       break;                               /* valid data found        */
     }
     if (iml2 <= 0) break;                  /* end of this record      */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
   } while (adsl_gai1_w1);
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml2 > 0) {                          /* not all input data processed */
     goto p_illogic_00;                     /* program illogic         */
   }
   adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next record in chain */
   if (adsl_tdc1_w1) {                      /* more data follow        */
     goto p_sdh_tcp_so_04;                  /* process TCP record      */
   }
   switch (IEL_S_STAT) {                    /* depending on Socks state */
     case ied_s5stat_send_resp_1:           /* send response authentication method */
       if ((dsl_oa1.achc_lower
             + sizeof(chrs_socks5_resp_noauth)
             + sizeof(struct dsd_gather_i_1)
             + sizeof(struct dsd_tcp_data_contr_1))
             > dsl_oa1.achc_upper) {
         goto p_out_80;                     /* overflow                */
       }
       dsl_oa1.achc_upper -= sizeof(struct dsd_tcp_data_contr_1) + sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) dsl_oa1.achc_upper)
#define ADSL_TDC1_G ((struct dsd_tcp_data_contr_1 *) (ADSL_GAI1_G + 1))
       memcpy( dsl_oa1.achc_lower, chrs_socks5_resp_noauth, sizeof(chrs_socks5_resp_noauth) );
       ADSL_GAI1_G->achc_ginp_cur = dsl_oa1.achc_lower;
       dsl_oa1.achc_lower += sizeof(chrs_socks5_resp_noauth);
       ADSL_GAI1_G->achc_ginp_end = dsl_oa1.achc_lower;
       ADSL_GAI1_G->adsc_next = NULL;       /* this is last in chain   */
       ADSL_TDC1_G->adsc_next = NULL;       /* for chaining            */
       ADSL_TDC1_G->adsc_gai1 = ADSL_GAI1_G;  /* data                  */
       ADSL_TDC1_G->imc_len_data = sizeof(chrs_socks5_resp_noauth);  /* length of the data */
#ifdef B120820
       ADSL_TDC1_G->boc_push_flag = TRUE;   /* PUSH flag of TCP header */
#else
       ADSL_TDC1_G->umc_flags = D_TCP_HEADER_FLAG_PSH;  /* PUSH flag of TCP header */
#endif
       adsl_sdh_tcp_1_pri->adsc_tdc1_in = ADSL_TDC1_G;  /* input data  */
       IEL_S_STAT = ied_s5stat_preq_b;      /* packet request begin    */
       goto p_sdh_tcp_cont_84;              /* addresses for SDH-TCP have been set */
#undef ADSL_GAI1_G
#undef ADSL_TDC1_G
     case ied_sall_stat_do_connect:         /* do connect to target now */
       /* check if we have configured a DNS name                       */
       /* for DNS-request, sending an UDP DNS packet to the server     */
       /*   is not implemented                                         */
       if (CHL_CHECK_DNS) {                 /* do check DNS name       */
         /* in the DNS name, there are dots, '.', these need to be replaced by length fields */
         iml1 = 0;                          /* index in input          */
         achl1 = chrl_dns_name;             /* place for length        */
         achl2 = chrl_dns_name + 1;         /* place for content       */
         do {
           if (*(ACHL_SALL_INETA + iml1) == '.') {
             iml2 = achl2 - (achl1 + 1);    /* length of sub-field     */
             if (iml2 == 0) {               /* content length zero     */
               goto p_sdh_tcp_so_56;        /* Socks DNS could not be resoved */
             }
             *achl1 = (unsigned char) iml2;  /* set length sub-field   */
             achl1 = achl2;                 /* here is next length field */
             achl2++;                       /* after length field      */
           } else {                         /* normal content          */
             *achl2++ = *(ACHL_SALL_INETA + iml1);  /* copy character  */
           }
           iml1++;                          /* increment index         */
         } while (iml1 < IML_SALL_V1);
         iml1 = achl2 - (achl1 + 1);        /* length of sub-field     */
         if (iml1 == 0) {                   /* content length zero     */
           goto p_sdh_tcp_so_56;            /* Socks DNS could not be resoved */
         }
         *achl1 = (unsigned char) iml1;     /* set length sub-field    */
         iml1 = achl2 - chrl_dns_name;      /* length of DNS name      */
         adsl_coe1_w1 = (struct dsd_conf_ext_1 *) (ADSL_CLCO + 1);
         achl3 = (char *) adsl_coe1_w1 + ADSL_CLCO->imc_len_conf_ext_1;  /* add length of configuration extensions */
         while (((char *) adsl_coe1_w1) < achl3) {  /* loop over all configuration extensions */
#ifdef DEBUG_110902_01
           achl4 = (char *) (adsl_coe1_w1 + 1);
#endif
// to-do 09.04.13 - why length wrong value ???
//         if (   (iml1 == adsl_coe1_w1->imc_len_dns_n)
           if (   (iml1 == (adsl_coe1_w1->imc_len_dns_n - 1))
               && (adsl_coe1_w1->iec_coe == ied_coe_dns_resp)  /* DNS resonse configured */
               && (!memcmp( chrl_dns_name, (char *) (adsl_coe1_w1 + 1) + sizeof(chrs_dns_r_i_1), iml1 ))) {
             break;
           }
           *((char **) &adsl_coe1_w1) += adsl_coe1_w1->imc_len_stor;  /* add storage reserved */
         }
         if (  (((char *) adsl_coe1_w1) >= achl3)  /* DNS name not found */
             || (adsl_coe1_w1->imc_no_ineta <= 0)) {
           goto p_sdh_tcp_so_56;            /* Socks DNS could not be resoved */
         }
         /* use first configured INETA                                 */
         memcpy( ACHL_SALL_INETA,
                 (char *) adsl_coe1_w1 + adsl_coe1_w1->imc_len_stor
                            - adsl_coe1_w1->imc_no_ineta * sizeof(UNSIG_MED),
                 sizeof(UNSIG_MED) );
       }
#define ADSL_SORT_TCP_IPV4_SERVER ((struct dsd_sort_tcp_ipv4 *) ((char *) (adsl_ts1_w1 + 1) + sizeof(struct dsd_sort_tcp_ipv4)))
#define ADSL_CT_IPV4_SERVER (&ADSL_SORT_TCP_IPV4_SERVER->dsc_ct_ipv4)
       *((UNSIG_MED *) &ADSL_CT_IPV4_SERVER->chrrc_ineta[ 0 ][ 0 ])
         = adsl_contr_1->umc_ineta_client;  /* INETA client in tunnel  */
#ifdef B111108
       *((UNSIG_MED *) &ADSL_CT_IPV4_SERVER->chrrc_ineta[ 1 ][ 0 ])
         = m_natted_ineta( adsp_hl_clib_1, ACHL_SALL_INETA, NULL );
#else
       *((UNSIG_MED *) ACHL_SALL_TARGET)
         = m_original_ineta( adsp_hl_clib_1, ACHL_SALL_INETA, &dsl_nrv );
       *((UNSIG_MED *) &ADSL_CT_IPV4_SERVER->chrrc_ineta[ 1 ][ 0 ])
         = m_natted_ineta( adsp_hl_clib_1, ACHL_SALL_TARGET, NULL, ADSL_CLCO->boc_disp_inetas );
#endif
       *((unsigned short int *) (&ADSL_CT_IPV4_SERVER->chrrc_port[ 0 ][ 0 ]))
         = *((unsigned short int *) ACHL_SALL_PORT);
       *((unsigned short int *) (&ADSL_CT_IPV4_SERVER->chrrc_port[ 1 ][ 0 ]))
         = *((unsigned short int *) &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_port[ 1 ][ 0 ]);
       ADSL_CT_IPV4_SERVER->iec_cti4 = ied_cti4_s5_server;  /* Socks server TCP half-session */
#ifdef TRACEHL1
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T insert connection of Socks target",
                     __LINE__ );
       m_sdh_console_out( &dsl_sdh_call_1, (char *) ADSL_CT_IPV4_SERVER, sizeof(struct dsd_ctrl_tcp_ipv4) );
#endif
#ifdef TRY_110901_01
       bol1 = m_htree1_avl_search( NULL, adsl_htree1_avl_cntl_ineta,
                                   &dsl_htree1_work, &ADSL_SORT_TCP_IPV4_SERVER->dsc_sort_ineta );
       if (bol1 == FALSE) {                 /* error occured           */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_search() failed",
                       __LINE__ );
#ifdef DEBUG_140730_01                      /* problems FTP            */
         iml_error_line = __LINE__;
#endif
         goto p_illogic_00;                 /* program illogic         */
       }
       if (dsl_htree1_work.adsc_found) {    /* entry found             */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_search() found entry of Socks target",
                       __LINE__ );
#ifdef DEBUG_140730_01                      /* problems FTP            */
         iml_error_line = __LINE__;
#endif
         goto p_illogic_00;                 /* program illogic         */
       }
#endif
       bol1 = m_htree1_avl_insert( NULL, adsl_htree1_avl_cntl_ineta,
                                   &dsl_htree1_work, &ADSL_SORT_TCP_IPV4_SERVER->dsc_sort_ineta );
       if (bol1 == FALSE) {                 /* error occured           */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_insert() failed",
                       __LINE__ );
#ifdef DEBUG_140730_01                      /* problems FTP            */
         iml_error_line = __LINE__;
#endif
         goto p_illogic_00;                 /* program illogic         */
       }
       adsl_sdh_tcp_1_sec->usc_port_client  /* TCP port of client      */
         = *((unsigned short int *) &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_port[ 1 ][ 0 ]);
       adsl_sdh_tcp_1_sec->usc_port_server  /* TCP port of server      */
         = *((unsigned short int *) ACHL_SALL_PORT);
#ifdef B111108
       memcpy( &adsl_sdh_tcp_1_sec->chrc_header_info[ 4 ], ACHL_SALL_INETA, 4 );  /* IP header information needed for checksum */
       memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 1 ][ 0 ], ACHL_SALL_INETA, 4 );  /* IP header information needed for send to target */
#else
#ifdef XYZ1
       *((UNSIG_MED *) &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 1 ][ 0 ])
         = m_original_ineta( adsp_hl_clib_1, ACHL_SALL_INETA, &dsl_nrv );
       memcpy( &adsl_sdh_tcp_1_sec->chrc_header_info[ 4 ],  /* IP header information needed for checksum */
               &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 1 ][ 0 ],
               4 );
#endif
       memcpy( &adsl_sdh_tcp_1_sec->chrc_header_info[ 4 ], ACHL_SALL_TARGET, 4 );  /* IP header information needed for checksum */
       memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 1 ][ 0 ], ACHL_SALL_TARGET, 4 );  /* IP header information needed for send to target */
#endif
#ifdef TRACEHL1
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T adsl_sdh_tcp_1_sec=%p.",
                     __LINE__, adsl_sdh_tcp_1_sec );
       m_sdh_console_out( &dsl_sdh_call_1, (char *) adsl_sdh_tcp_1_sec, sizeof(struct dsd_sdh_tcp_1) );
       m_sdh_console_out( &dsl_sdh_call_1, (char *) &unl_sort_ineta, sizeof(unl_sort_ineta) );
#endif
       adsl_ts1_w1->adsc_tcpse1_ext_1->iec_tce1s = ied_tce1s_socks5_wait_connect;  /* wait for connect of other half-session */
       goto p_sdh_tcp_start_48;             /* start SDH-TCP of other side */
#undef ADSL_CT_IPV4_SERVER
#undef ADSL_SORT_TCP_IPV4_SERVER
   }
#ifdef B120309
   goto p_sdh_tcp_end_00;                   /* packet has been processed by SDH-TCP */
#else
   goto p_sdh_tcp_cont_80;                  /* give output client to SDH-TCP other side */
#endif

   p_sdh_tcp_so_56:                         /* Socks DNS could not be resoved */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Socks 4/5 reques with DNS name which cannot be resolved from configuration",
                 __LINE__ );
   adsl_sdh_tcp_1_pri->boc_eof_client = TRUE;  /* End-of-File Client   */
   adsl_sdh_tcp_1_pri->adsc_tdc1_in = NULL;  /* no input data          */
   if (CHL_SOCKS_VERS != 0X05) {            /* is Socks4               */
     achl1 = (char *) ucrs_socks_4_se2cl_dns;
     iml1 = sizeof(ucrs_socks_4_se2cl_dns);
   } else {                                 /* is Socks5               */
     achl1 = (char *) ucrs_socks_5_se2cl_dns;
     iml1 = sizeof(ucrs_socks_5_se2cl_dns);
   }
   dsl_oa1.achc_upper -= sizeof(struct dsd_tcp_data_contr_1) + sizeof(struct dsd_gather_i_1) + iml1;
   if (dsl_oa1.achc_upper < dsl_oa1.achc_lower) {  /* not enough space */
     goto p_sdh_tcp_cont_84;                /* addresses for SDH-TCP have been set */
   }
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) dsl_oa1.achc_upper)
#define ADSL_TDC1_G ((struct dsd_tcp_data_contr_1 *) (ADSL_GAI1_G + 1))
   memcpy( dsl_oa1.achc_lower, achl1, iml1 );
   ADSL_GAI1_G->achc_ginp_cur = dsl_oa1.achc_lower;
   dsl_oa1.achc_lower += iml1;
   ADSL_GAI1_G->achc_ginp_end = dsl_oa1.achc_lower;
   ADSL_GAI1_G->adsc_next = NULL;           /* this is last in chain   */
   ADSL_TDC1_G->adsc_next = NULL;           /* for chaining            */
   ADSL_TDC1_G->adsc_gai1 = ADSL_GAI1_G;    /* data                    */
   ADSL_TDC1_G->imc_len_data = iml1;        /* length of the data      */
   ADSL_TDC1_G->umc_flags = D_TCP_HEADER_FLAG_PSH;  /* PUSH flag of TCP header */
   adsl_sdh_tcp_1_pri->adsc_tdc1_in = ADSL_TDC1_G;  /* input data      */
   goto p_sdh_tcp_cont_84;                  /* addresses for SDH-TCP have been set */

   p_sdh_tcp_so_60:                         /* Socks data invalid      */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W Socks 4/5 invalid data received line %05d.",
                 __LINE__, iml1 );
   adsl_sdh_tcp_1_pri->boc_eof_client = TRUE;  /* End-of-File Client   */
   adsl_sdh_tcp_1_pri->adsc_tdc1_in = NULL;  /* no input data          */
   goto p_sdh_tcp_cont_84;                  /* addresses for SDH-TCP have been set */

#undef CHL_PREQ_ATYP
#undef BOL_S5_V1
#undef IML_SALL_V1
#undef IML_SALL_V2
#undef ACHL_SALL_INETA
#undef ACHL_SALL_PORT
#undef IEL_S_STAT
#undef CHL_SOCKS_VERS

#define IML_FTP_STATE (*((int *) &adsl_ts1_w1->adsc_tcpse1_ext_1->chrc_buffer[ 0 ]))
#define IML_FTP_CRLF (*((int *) &adsl_ts1_w1->adsc_tcpse1_ext_1->chrc_buffer[ 4 ]))
#define ACHL_FTP_WORK1 ((char *) &adsl_ts1_w1->adsc_tcpse1_ext_1->chrc_buffer[ 8 ])
#define IML_FTP_LEN_WORK1 (sizeof(adsl_ts1_w1->adsc_tcpse1_ext_1->chrc_buffer) - 8)

   p_ftp_cl2se_00:                          /* FTP client to server    */
   adsl_ts1_w1->adsc_tcpse1_ext_1->iec_tce1s = ied_tce1s_ftp_cl2se;  /* FTP client to server */
   adsl_tdc1_w1 = adsl_tdc1_w2 = adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client;  /* output data to client */
   adsl_tdc1_w3 = NULL;                     /* no output till now      */
   adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client = NULL;  /* clear output data to client */
//
// p_ftp_cl2se_04:                          /* FTP client to server, input record set */
   adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;  /* data                    */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic    */
   iml1 = adsl_tdc1_w1->imc_len_data;       /* length of the data      */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml1 <= 0) goto p_illogic_00;        /* program illogic         */
   achl_rb = adsl_gai1_w1->achc_ginp_cur;   /* start scann here        */

   p_ftp_cl2se_08:                          /* FTP client to server, input all set */
   IML_FTP_STATE = 0;                       /* no bytes scanned        */
   achl1 = (char *) ucrs_ftp_cl2se_c1;      /* command to compare      */
   iml2 = sizeof(ucrs_ftp_cl2se_c1);        /* length command to compare */
   goto p_ftp_cl2se_40;                     /* FTP client to server scan command */

   p_ftp_cl2se_20:                          /* FTP client to server continue */
   adsl_tdc1_w1 = adsl_tdc1_w2 = adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client;  /* output data to client */
   adsl_tdc1_w3 = NULL;                     /* no output till now      */
   adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client = NULL;  /* clear output data to client */
   adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;  /* data                    */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic    */
   iml1 = adsl_tdc1_w1->imc_len_data;       /* length of the data      */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml1 <= 0) goto p_illogic_00;        /* program illogic         */
   achl_rb = adsl_gai1_w1->achc_ginp_cur;   /* start scann here        */
   if (IML_FTP_STATE < 0) {                 /* did not recognize keyword */
     goto p_ftp_eol_00;                     /* FTP search end of line / command */
   }
   achl1 = (char *) ucrs_ftp_cl2se_c1 + IML_FTP_STATE;  /* command to compare */
   iml2 = sizeof(ucrs_ftp_cl2se_c1) - IML_FTP_STATE;  /* length command to compare */
   if (iml2 > 0) {                          /* still in keyword        */
     goto p_ftp_cl2se_40;                   /* FTP client to server scan command */
   }
   achl1 = ACHL_FTP_WORK1 - iml2;           /* put to work area        */
   goto p_ftp_cl2se_64;                     /* FTP client to server keyword found part two */

   p_ftp_cl2se_40:                          /* FTP client to server scan command */
   do {                                     /* loop over characters    */
     if (*achl_rb != *achl1) {              /* check character of keyword */
#ifdef B110902
       if (IML_FTP_STATE == 0) {            /* no data before          */
         IML_FTP_STATE = -1;                /* set state search end-of-line */
         goto p_ftp_eol_00;                 /* FTP search end of line / command */
       }
// to-do 01.09.11 KB
       goto p_illogic_00;  /* program illogic    */
#endif
       if (IML_FTP_STATE) {                 /* data before             */
         if ((dsl_oa1.achc_lower
                 + IML_FTP_STATE
                 + sizeof(struct dsd_gather_i_1)
                 + sizeof(struct dsd_tcp_data_contr_1))
               > dsl_oa1.achc_upper) {
           goto p_out_80;                   /* overflow                */
         }
         dsl_oa1.achc_upper -= sizeof(struct dsd_tcp_data_contr_1) + sizeof(struct dsd_gather_i_1);
#undef ADSL_TDC1_G
#undef ADSL_GAI1_G
#define ADSL_TDC1_G ((struct dsd_tcp_data_contr_1 *) dsl_oa1.achc_upper)
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) (ADSL_TDC1_G + 1))
         ADSL_GAI1_G->achc_ginp_cur = dsl_oa1.achc_lower;
         memcpy( dsl_oa1.achc_lower, ucrs_ftp_cl2se_c1, IML_FTP_STATE );
         dsl_oa1.achc_lower += IML_FTP_STATE;
         ADSL_GAI1_G->achc_ginp_end = dsl_oa1.achc_lower;
         ADSL_GAI1_G->adsc_next = NULL;
         ADSL_TDC1_G->adsc_next = NULL;
         ADSL_TDC1_G->adsc_gai1 = ADSL_GAI1_G;  /* data                */
         ADSL_TDC1_G->imc_len_data = IML_FTP_STATE;  /* length of the data */
#ifdef B120820
         ADSL_TDC1_G->boc_push_flag = FALSE;  /* PUSH flag of TCP header */
#else
         ADSL_TDC1_G->umc_flags = 0;        /* flags of TCP header     */
#endif
         if (adsl_tdc1_w3 == NULL) {        /* no output till now      */
           adsl_tdc1_w3 = ADSL_TDC1_G;      /* input data to other side */
         } else {                           /* need to append previous output */
           adsl_tdc1_w4 = adsl_tdc1_w3;     /* get start of output     */
           while (adsl_tdc1_w4->adsc_next) adsl_tdc1_w4 = adsl_tdc1_w4->adsc_next;
           adsl_tdc1_w4->adsc_next = ADSL_TDC1_G;  /* append new output */
         }
#undef ADSL_TDC1_G
#undef ADSL_GAI1_G
       }
       IML_FTP_STATE = -1;                  /* set state search end-of-line */
       goto p_ftp_eol_00;                   /* FTP search end of line / command */
     }
     achl1++;                               /* next character keyword  */
     iml2--;                                /* number of characters keyword */
     achl_rb++;                             /* the character has been processed */
     iml1--;                                /* decrement number of characters */
     if (iml2 <= 0) {                       /* end of keyword - command found */
       goto p_ftp_cl2se_60;                 /* FTP client to server keyword found */
     }
     if (iml1 <= 0) break;                  /* all characters processed */
   } while (achl_rb < adsl_gai1_w1->achc_ginp_end);
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml1 > 0) {                          /* not all input data processed */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1 == NULL) {            /* no more data            */
       goto p_illogic_00;                   /* program illogic         */
     }
     achl_rb = adsl_gai1_w1->achc_ginp_cur;  /* start scann here       */
     goto p_ftp_cl2se_40;                   /* FTP client to server scan command */
   }
   adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next record in chain */
   if (adsl_tdc1_w1 == NULL) {              /* no more data            */
     IML_FTP_STATE = sizeof(ucrs_ftp_cl2se_c1) - iml2;  /* length command to compare */
     if (adsl_tdc1_w3 == NULL) {            /* no data to other side   */
#ifdef B120309
       goto p_sdh_tcp_end_00;               /* packet has been processed by SDH-TCP */
#else
       goto p_sdh_tcp_cont_80;              /* give output client to SDH-TCP other side */
#endif
     }
     adsl_sdh_tcp_1_sec->adsc_tdc1_in = adsl_tdc1_w3;  /* input data to other side */
     iml_clse_pri = 1;                      /* primary client to server */
     iml_clse_sec = 0;                      /* secondary client to server */
     adsl_sdh_tcp_1_pri = &adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ];
     adsl_sdh_tcp_1_sec = &adsl_ts1_w1->dsrc_sdh_tcp_1[ 0 ];
     if (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL) {  /* already closed */
#ifdef B120309
       goto p_sdh_tcp_end_00;               /* packet has been processed by SDH-TCP */
#else
       goto p_sdh_tcp_cont_80;              /* give output client to SDH-TCP other side */
#endif
     }
     if (adsl_sdh_tcp_1_pri->iec_sts != ied_sts_normal) {  /* not normal processing */
#ifdef B120309
       goto p_sdh_tcp_end_00;               /* packet has been processed by SDH-TCP */
#else
       goto p_sdh_tcp_cont_80;              /* give output client to SDH-TCP other side */
#endif
     }
     goto p_sdh_tcp_cont_84;                /* addresses for SDH-TCP have been set */
   }
   adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;  /* data                    */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic    */
   iml1 = adsl_tdc1_w1->imc_len_data;       /* length of the data      */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml1 <= 0) goto p_illogic_00;        /* program illogic         */
   achl_rb = adsl_gai1_w1->achc_ginp_cur;   /* start scann here        */
   goto p_ftp_cl2se_40;                     /* FTP client to server scan command */

   p_ftp_cl2se_60:                          /* FTP client to server keyword found */
   IML_FTP_CRLF = 0;                        /* not yet carriage-return */
   achl1 = ACHL_FTP_WORK1;                  /* put to work area        */
   if (iml1 <= 0) {                         /* no more characters      */
     goto p_ftp_cl2se_68;                   /* part of command processed */
   }

   p_ftp_cl2se_64:                          /* FTP client to server keyword found part two */
   chl1 = *achl1++ = *achl_rb++;            /* get next character      */
   iml1--;                                  /* decrement number of characters in this record */
   switch (chl1) {                          /* check character         */
     case CHAR_CR:                          /* carriage-return found   */
       IML_FTP_CRLF = 1;                    /* state carriage-return   */
       break;
     case CHAR_LF:                          /* line-feed found         */
       if (IML_FTP_CRLF == 0) break;        /* not state carriage-return */
       goto p_ftp_cl2se_72;                 /* FTP client to server command in buffer */
     default:                               /* normal character found  */
       IML_FTP_CRLF = 0;                    /* not state carriage-return */
       break;
   }
   if (achl1 >= (ACHL_FTP_WORK1 + IML_FTP_LEN_WORK1)) {
     iml1 = __LINE__;                       /* set line of source      */
     goto p_ftp_error_00;                   /* FTP error in command    */
   }
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml1 > 0) {                          /* not all input data processed */
     if (achl_rb < adsl_gai1_w1->achc_ginp_end) {
       goto p_ftp_cl2se_64;                 /* FTP client to server keyword found part two */
     }
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1 == NULL) {            /* no more data            */
       goto p_illogic_00;                   /* program illogic         */
     }
     achl_rb = adsl_gai1_w1->achc_ginp_cur;  /* start scann here       */
     goto p_ftp_cl2se_64;                   /* FTP client to server keyword found part two */
   }

   p_ftp_cl2se_68:                          /* part of command processed */
   adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next record in chain */
   if (adsl_tdc1_w1 == NULL) {              /* no more data            */
     IML_FTP_STATE = achl1 - ACHL_FTP_WORK1 + sizeof(ucrs_ftp_cl2se_c1);  /* length command to compare */
     if (adsl_tdc1_w3 == NULL) {            /* no data to other side   */
#ifdef B120309
       goto p_sdh_tcp_end_00;               /* packet has been processed by SDH-TCP */
#else
       goto p_sdh_tcp_cont_80;              /* give output client to SDH-TCP other side */
#endif
     }
     adsl_sdh_tcp_1_sec->adsc_tdc1_in = adsl_tdc1_w3;  /* input data to other side */
     iml_clse_pri = 1;                      /* primary client to server */
     iml_clse_sec = 0;                      /* secondary client to server */
     adsl_sdh_tcp_1_pri = &adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ];
     adsl_sdh_tcp_1_sec = &adsl_ts1_w1->dsrc_sdh_tcp_1[ 0 ];
     if (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL) {  /* already closed */
#ifdef B120309
       goto p_sdh_tcp_end_00;               /* packet has been processed by SDH-TCP */
#else
       goto p_sdh_tcp_cont_80;              /* give output client to SDH-TCP other side */
#endif
     }
     if (adsl_sdh_tcp_1_pri->iec_sts != ied_sts_normal) {  /* not normal processing */
#ifdef B120309
       goto p_sdh_tcp_end_00;               /* packet has been processed by SDH-TCP */
#else
       goto p_sdh_tcp_cont_80;              /* give output client to SDH-TCP other side */
#endif
     }
     goto p_sdh_tcp_cont_84;                /* addresses for SDH-TCP have been set */
   }
   adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;  /* data                    */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic    */
   iml1 = adsl_tdc1_w1->imc_len_data;       /* length of the data      */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml1 <= 0) goto p_illogic_00;        /* program illogic         */
   achl_rb = adsl_gai1_w1->achc_ginp_cur;   /* start scann here        */
   goto p_ftp_cl2se_64;                     /* FTP client to server keyword found part two */

   p_ftp_cl2se_72:                          /* FTP client to server command in buffer */
   bol1 = m_get_decno_6( chrl_work1, ACHL_FTP_WORK1, achl1 - 2 );
   if (bol1 == FALSE) {                     /* did not decode numbers  */
     iml1 = __LINE__;                       /* set line of source      */
     goto p_ftp_error_00;                   /* FTP error in command    */
   }
   *((UNSIG_MED *) (chrl_work1 + 8)) = m_original_ineta( adsp_hl_clib_1, chrl_work1, &dsl_nrv );
#ifdef B110902
// SDH-TCP needs input in work area
   if ((dsl_oa1.achc_lower
           + 6 * 3 + 6 - 1 + 1
           + 3 * sizeof(struct dsd_gather_i_1)
           + sizeof(struct dsd_tcp_data_contr_1))
         > dsl_oa1.achc_upper) {
     goto p_out_80;                         /* overflow                */
   }
   dsl_oa1.achc_upper -= sizeof(struct dsd_tcp_data_contr_1) + 3 * sizeof(struct dsd_gather_i_1);
#define ADSL_TDC1_G ((struct dsd_tcp_data_contr_1 *) dsl_oa1.achc_upper)
#define ADSL_GAI1_G1 ((struct dsd_gather_i_1 *) (ADSL_TDC1_G + 1))
#define ADSL_GAI1_G2 (ADSL_GAI1_G1 + 1)
#define ADSL_GAI1_G3 (ADSL_GAI1_G2 + 1)
   ADSL_GAI1_G1->achc_ginp_cur = (char *) ucrs_ftp_cl2se_c1;
   ADSL_GAI1_G1->achc_ginp_end = (char *) ucrs_ftp_cl2se_c1 + sizeof(ucrs_ftp_cl2se_c1);
   ADSL_GAI1_G1->adsc_next = ADSL_GAI1_G2;
   ADSL_GAI1_G2->achc_ginp_cur = dsl_oa1.achc_lower;
   iml2 = sprintf( dsl_oa1.achc_lower,
                   "%d,%d,%d,%d,%d,%d",
                   *((unsigned char *) chrl_work1 + 8 + 0),
                   *((unsigned char *) chrl_work1 + 8 + 1),
                   *((unsigned char *) chrl_work1 + 8 + 2),
                   *((unsigned char *) chrl_work1 + 8 + 3),
                   *((unsigned char *) chrl_work1 + 4 + 0),
                   *((unsigned char *) chrl_work1 + 4 + 1) );
   dsl_oa1.achc_lower += iml2;
   ADSL_GAI1_G2->achc_ginp_end = dsl_oa1.achc_lower;
   ADSL_GAI1_G2->adsc_next = ADSL_GAI1_G3;
   ADSL_GAI1_G3->achc_ginp_cur = (char *) ucrs_crlf;
   ADSL_GAI1_G3->achc_ginp_end = (char *) ucrs_crlf + sizeof(ucrs_crlf);
   ADSL_GAI1_G3->adsc_next = NULL;          /* this is last in chain   */
   ADSL_TDC1_G->adsc_next = NULL;
   ADSL_TDC1_G->adsc_gai1 = ADSL_GAI1_G1;   /* data                    */
   ADSL_TDC1_G->imc_len_data = sizeof(ucrs_ftp_cl2se_c1) + iml2 + sizeof(ucrs_crlf);  /* length of the data */
#ifdef B120820
   ADSL_TDC1_G->boc_push_flag = TRUE;       /* PUSH flag of TCP header */
#else
   ADSL_TDC1_G->umc_flags = D_TCP_HEADER_FLAG_PSH;  /* PUSH flag of TCP header */
#endif
   if (adsl_tdc1_w3 == NULL) {              /* no output till now      */
     adsl_tdc1_w3 = ADSL_TDC1_G;            /* input data to other side */
   } else {                                 /* need to append previous output */
     adsl_tdc1_w4 = adsl_tdc1_w3;           /* get start of output     */
     while (adsl_tdc1_w4->adsc_next) adsl_tdc1_w4 = adsl_tdc1_w4->adsc_next;
     adsl_tdc1_w4->adsc_next = ADSL_TDC1_G;  /* append new output      */
   }
#undef ADSL_TDC1_G
#undef ADSL_GAI1_G1
#undef ADSL_GAI1_G2
#undef ADSL_GAI1_G3
#endif
   if ((dsl_oa1.achc_lower
           + sizeof(ucrs_ftp_cl2se_c1)
           + 6 * 3 + 6 - 1
           + sizeof(ucrs_crlf)
           + sizeof(struct dsd_gather_i_1)
           + sizeof(struct dsd_tcp_data_contr_1))
         > dsl_oa1.achc_upper) {
     goto p_out_80;                         /* overflow                */
   }
   dsl_oa1.achc_upper -= sizeof(struct dsd_tcp_data_contr_1) + sizeof(struct dsd_gather_i_1);
#define ADSL_TDC1_G ((struct dsd_tcp_data_contr_1 *) dsl_oa1.achc_upper)
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) (ADSL_TDC1_G + 1))
   ADSL_GAI1_G->achc_ginp_cur = dsl_oa1.achc_lower;
   memcpy( dsl_oa1.achc_lower, ucrs_ftp_cl2se_c1, sizeof(ucrs_ftp_cl2se_c1) );
   dsl_oa1.achc_lower += sizeof(ucrs_ftp_cl2se_c1);
   iml2 = sprintf( dsl_oa1.achc_lower,
                   "%d,%d,%d,%d,%d,%d",
                   *((unsigned char *) chrl_work1 + 8 + 0),
                   *((unsigned char *) chrl_work1 + 8 + 1),
                   *((unsigned char *) chrl_work1 + 8 + 2),
                   *((unsigned char *) chrl_work1 + 8 + 3),
                   *((unsigned char *) chrl_work1 + 4 + 0),
                   *((unsigned char *) chrl_work1 + 4 + 1) );
   dsl_oa1.achc_lower += iml2;
   memcpy( dsl_oa1.achc_lower, ucrs_crlf, sizeof(ucrs_crlf) );
   dsl_oa1.achc_lower += sizeof(ucrs_crlf);
   ADSL_GAI1_G->achc_ginp_end = dsl_oa1.achc_lower;
   ADSL_GAI1_G->adsc_next = NULL;
   ADSL_TDC1_G->adsc_next = NULL;
   ADSL_TDC1_G->adsc_gai1 = ADSL_GAI1_G;    /* data                    */
   ADSL_TDC1_G->imc_len_data = sizeof(ucrs_ftp_cl2se_c1) + iml2 + sizeof(ucrs_crlf);  /* length of the data */
#ifdef B120820
   ADSL_TDC1_G->boc_push_flag = TRUE;       /* PUSH flag of TCP header */
#else
   ADSL_TDC1_G->umc_flags = D_TCP_HEADER_FLAG_PSH;  /* PUSH flag of TCP header */
#endif
   if (adsl_tdc1_w3 == NULL) {              /* no output till now      */
     adsl_tdc1_w3 = ADSL_TDC1_G;            /* input data to other side */
   } else {                                 /* need to append previous output */
     adsl_tdc1_w4 = adsl_tdc1_w3;           /* get start of output     */
     while (adsl_tdc1_w4->adsc_next) adsl_tdc1_w4 = adsl_tdc1_w4->adsc_next;
     adsl_tdc1_w4->adsc_next = ADSL_TDC1_G;  /* append new output      */
   }
#undef ADSL_TDC1_G
#undef ADSL_GAI1_G
   if (iml1 <= 0) {                         /* all characters processed */
     adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next record in chain */
     if (adsl_tdc1_w1 == NULL) {            /* no more data            */
       adsl_ts1_w1->adsc_tcpse1_ext_1->iec_tce1s = ied_tce1s_ftp_start;  /* start of FTP packet */
       adsl_sdh_tcp_1_sec->adsc_tdc1_in = adsl_tdc1_w3;  /* input data to other side */
       iml_clse_pri = 1;                    /* primary client to server */
       iml_clse_sec = 0;                    /* secondary client to server */
       adsl_sdh_tcp_1_pri = &adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ];
       adsl_sdh_tcp_1_sec = &adsl_ts1_w1->dsrc_sdh_tcp_1[ 0 ];
       if (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL) {  /* already closed */
#ifdef B120309
         goto p_sdh_tcp_end_00;             /* packet has been processed by SDH-TCP */
#else
         goto p_sdh_tcp_cont_80;            /* give output client to SDH-TCP other side */
#endif
       }
       if (adsl_sdh_tcp_1_pri->iec_sts != ied_sts_normal) {  /* not normal processing */
#ifdef B120309
         goto p_sdh_tcp_end_00;             /* packet has been processed by SDH-TCP */
#else
         goto p_sdh_tcp_cont_80;            /* give output client to SDH-TCP other side */
#endif
       }
       goto p_sdh_tcp_cont_84;              /* addresses for SDH-TCP have been set */
     }
     adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;  /* data                  */
#ifdef DEBUG_140730_01                      /* problems FTP            */
     iml_error_line = __LINE__;
#endif
     if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic  */
     iml1 = adsl_tdc1_w1->imc_len_data;     /* length of the data      */
#ifdef DEBUG_140730_01                      /* problems FTP            */
     iml_error_line = __LINE__;
#endif
     if (iml1 <= 0) goto p_illogic_00;      /* program illogic         */
   }
   if (iml1 == adsl_tdc1_w1->imc_len_data) {  /* length of the data    */
     adsl_tdc1_w2 = adsl_tdc1_w1;           /* here is start input     */
     goto p_ftp_cl2se_08;                   /* FTP client to server, input all set */
   }
   if ((dsl_oa1.achc_lower
           + sizeof(struct dsd_tcp_data_contr_1)
           + sizeof(struct dsd_gather_i_1))
         > dsl_oa1.achc_upper) {
     goto p_out_80;                         /* overflow                */
   }
   dsl_oa1.achc_upper -= sizeof(struct dsd_tcp_data_contr_1) + sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_NEW ((struct dsd_gather_i_1 *) dsl_oa1.achc_upper)
#define ADSL_TDC1_NEW ((struct dsd_tcp_data_contr_1 *) (ADSL_GAI1_NEW + 1))
   ADSL_GAI1_NEW->achc_ginp_cur = achl_rb;
   ADSL_GAI1_NEW->achc_ginp_end = adsl_gai1_w1->achc_ginp_end;
   ADSL_GAI1_NEW->adsc_next = adsl_gai1_w1->adsc_next;  /* get chain of input gather */
   ADSL_TDC1_NEW->adsc_next = adsl_tdc1_w1->adsc_next;  /* set chaing  */
   ADSL_TDC1_NEW->adsc_gai1 = ADSL_GAI1_NEW;  /* data                  */
   ADSL_TDC1_NEW->imc_len_data = iml1;      /* length of the data      */
#ifdef B120820
   ADSL_TDC1_NEW->boc_push_flag = adsl_tdc1_w1->boc_push_flag;  /* PUSH flag of TCP header */
#else
   ADSL_TDC1_NEW->umc_flags = adsl_tdc1_w1->umc_flags;  /* flags of TCP header */
#endif
   adsl_tdc1_w1 = adsl_tdc1_w2 = ADSL_TDC1_NEW;  /* input data not yet processed */
#undef ADSL_GAI1_NEW
#undef ADSL_TDC1_NEW
   goto p_ftp_cl2se_08;                     /* FTP client to server, input all set */

   p_ftp_se2cl_00:                          /* FTP server to client    */
   adsl_ts1_w1->adsc_tcpse1_ext_1->iec_tce1s = ied_tce1s_ftp_se2cl;  /* FTP server to client */
   adsl_tdc1_w1 = adsl_tdc1_w2 = adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client;  /* output data to client */
   adsl_tdc1_w3 = NULL;                     /* no output till now      */
   adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client = NULL;  /* clear output data to client */
//
// p_ftp_se2cl_04:                          /* FTP server to client, input record set */
   adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;  /* data                    */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic    */
   iml1 = adsl_tdc1_w1->imc_len_data;       /* length of the data      */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml1 <= 0) goto p_illogic_00;        /* program illogic         */
   achl_rb = adsl_gai1_w1->achc_ginp_cur;   /* start scann here        */

   p_ftp_se2cl_08:                          /* FTP server to client, input all set */
   IML_FTP_STATE = 0;                       /* no bytes scanned        */
   achl1 = (char *) ucrs_ftp_se2cl_c1;      /* command to compare      */
   iml2 = sizeof(ucrs_ftp_se2cl_c1);        /* length command to compare */
   goto p_ftp_se2cl_40;                     /* FTP server to client scan command */

   p_ftp_se2cl_20:                          /* FTP server to client continue */
   adsl_tdc1_w1 = adsl_tdc1_w2 = adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client;  /* output data to client */
   adsl_tdc1_w3 = NULL;                     /* no output till now      */
   adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client = NULL;  /* clear output data to client */
   adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;  /* data                    */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic    */
   iml1 = adsl_tdc1_w1->imc_len_data;       /* length of the data      */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml1 <= 0) goto p_illogic_00;        /* program illogic         */
   achl_rb = adsl_gai1_w1->achc_ginp_cur;   /* start scann here        */
   if (IML_FTP_STATE < 0) {                 /* did not recognize keyword */
     goto p_ftp_eol_00;                     /* FTP search end of line / command */
   }
   achl1 = (char *) ucrs_ftp_se2cl_c1 + IML_FTP_STATE;  /* command to compare */
   iml2 = sizeof(ucrs_ftp_se2cl_c1) - IML_FTP_STATE;  /* length command to compare */
   if (iml2 > 0) {                          /* still in keyword        */
     goto p_ftp_se2cl_40;                   /* FTP server to client scan command */
   }
   achl1 = ACHL_FTP_WORK1 - iml2;           /* put to work area        */
   goto p_ftp_se2cl_64;                     /* FTP server to client keyword found part two */

   p_ftp_se2cl_40:                          /* FTP server to client scan command */
   do {                                     /* loop over characters    */
     if (*achl_rb != *achl1) {              /* check character of keyword */
#ifdef B110902
       if (IML_FTP_STATE == 0) {            /* no data before          */
         IML_FTP_STATE = -1;                /* set state search end-of-line */
         goto p_ftp_eol_00;                 /* FTP search end of line / command */
       }
// to-do 01.09.11 KB
       goto p_illogic_00;  /* program illogic    */
#endif
       if (IML_FTP_STATE) {                 /* data before             */
         if ((dsl_oa1.achc_lower
                 + IML_FTP_STATE
                 + sizeof(struct dsd_gather_i_1)
                 + sizeof(struct dsd_tcp_data_contr_1))
               > dsl_oa1.achc_upper) {
           goto p_out_80;                   /* overflow                */
         }
         dsl_oa1.achc_upper -= sizeof(struct dsd_tcp_data_contr_1) + sizeof(struct dsd_gather_i_1);
#define ADSL_TDC1_G ((struct dsd_tcp_data_contr_1 *) dsl_oa1.achc_upper)
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) (ADSL_TDC1_G + 1))
         ADSL_GAI1_G->achc_ginp_cur = dsl_oa1.achc_lower;
         memcpy( dsl_oa1.achc_lower, ucrs_ftp_se2cl_c1, IML_FTP_STATE );
         dsl_oa1.achc_lower += IML_FTP_STATE;
         ADSL_GAI1_G->achc_ginp_end = dsl_oa1.achc_lower;
         ADSL_GAI1_G->adsc_next = NULL;
         ADSL_TDC1_G->adsc_next = NULL;
         ADSL_TDC1_G->adsc_gai1 = ADSL_GAI1_G;  /* data                */
         ADSL_TDC1_G->imc_len_data = IML_FTP_STATE;  /* length of the data */
#ifdef B120820
         ADSL_TDC1_G->boc_push_flag = FALSE;  /* PUSH flag of TCP header */
#else
         ADSL_TDC1_G->umc_flags = 0;        /* flags of TCP header     */
#endif
         if (adsl_tdc1_w3 == NULL) {        /* no output till now      */
           adsl_tdc1_w3 = ADSL_TDC1_G;      /* input data to other side */
         } else {                           /* need to append previous output */
           adsl_tdc1_w4 = adsl_tdc1_w3;     /* get start of output     */
           while (adsl_tdc1_w4->adsc_next) adsl_tdc1_w4 = adsl_tdc1_w4->adsc_next;
           adsl_tdc1_w4->adsc_next = ADSL_TDC1_G;  /* append new output */
         }
#undef ADSL_TDC1_G
#undef ADSL_GAI1_G
       }
       IML_FTP_STATE = -1;                  /* set state search end-of-line */
       goto p_ftp_eol_00;                   /* FTP search end of line / command */
     }
     achl1++;                               /* next character keyword  */
     iml2--;                                /* number of characters keyword */
     achl_rb++;                             /* the character has been processed */
     iml1--;                                /* decrement number of characters */
     if (iml2 <= 0) {                       /* end of keyword - command found */
       goto p_ftp_se2cl_60;                 /* FTP server to client keyword found */
     }
     if (iml1 <= 0) break;                  /* all characters processed */
   } while (achl_rb < adsl_gai1_w1->achc_ginp_end);
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml1 > 0) {                          /* not all input data processed */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1 == NULL) {            /* no more data            */
       goto p_illogic_00;                   /* program illogic         */
     }
     achl_rb = adsl_gai1_w1->achc_ginp_cur;  /* start scann here       */
     goto p_ftp_se2cl_40;                   /* FTP server to client scan command */
   }
   adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next record in chain */
   if (adsl_tdc1_w1 == NULL) {              /* no more data            */
     IML_FTP_STATE = sizeof(ucrs_ftp_se2cl_c1) - iml2;  /* length command to compare */
     if (adsl_tdc1_w3 == NULL) {            /* no data to other side   */
#ifdef B120309
       goto p_sdh_tcp_end_00;               /* packet has been processed by SDH-TCP */
#else
       goto p_sdh_tcp_cont_80;              /* give output client to SDH-TCP other side */
#endif
     }
     adsl_sdh_tcp_1_sec->adsc_tdc1_in = adsl_tdc1_w3;  /* input data to other side */
     iml_clse_pri = 0;                      /* primary client to server */
     iml_clse_sec = 1;                      /* secondary client to server */
     adsl_sdh_tcp_1_pri = &adsl_ts1_w1->dsrc_sdh_tcp_1[ 0 ];
     adsl_sdh_tcp_1_sec = &adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ];
     if (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL) {  /* already closed */
#ifdef B120309
       goto p_sdh_tcp_end_00;               /* packet has been processed by SDH-TCP */
#else
       goto p_sdh_tcp_cont_80;              /* give output client to SDH-TCP other side */
#endif
     }
     if (adsl_sdh_tcp_1_pri->iec_sts != ied_sts_normal) {  /* not normal processing */
#ifdef B120309
       goto p_sdh_tcp_end_00;               /* packet has been processed by SDH-TCP */
#else
       goto p_sdh_tcp_cont_80;              /* give output client to SDH-TCP other side */
#endif
     }
     goto p_sdh_tcp_cont_84;                /* addresses for SDH-TCP have been set */
   }
   adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;  /* data                    */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic    */
   iml1 = adsl_tdc1_w1->imc_len_data;       /* length of the data      */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml1 <= 0) goto p_illogic_00;        /* program illogic         */
   achl_rb = adsl_gai1_w1->achc_ginp_cur;   /* start scann here        */
   goto p_ftp_se2cl_40;                     /* FTP server to client scan command */

   p_ftp_se2cl_60:                          /* FTP server to client keyword found */
   IML_FTP_CRLF = 0;                        /* not yet carriage-return */
   achl1 = ACHL_FTP_WORK1;                  /* put to work area        */
   if (iml1 <= 0) {                         /* no more characters      */
     goto p_ftp_se2cl_68;                   /* part of command processed */
   }

   p_ftp_se2cl_64:                          /* FTP server to client keyword found part two */
   chl1 = *achl1++ = *achl_rb++;            /* get next character      */
   iml1--;                                  /* decrement number of characters in this record */
   switch (chl1) {                          /* check character         */
     case CHAR_CR:                          /* carriage-return found   */
       IML_FTP_CRLF = 1;                    /* state carriage-return   */
       break;
     case CHAR_LF:                          /* line-feed found         */
       if (IML_FTP_CRLF == 0) break;        /* not state carriage-return */
       goto p_ftp_se2cl_72;                 /* FTP server to client command in buffer */
     default:                               /* normal character found  */
       IML_FTP_CRLF = 0;                    /* not state carriage-return */
       break;
   }
   if (achl1 >= (ACHL_FTP_WORK1 + IML_FTP_LEN_WORK1)) {
     iml1 = __LINE__;                       /* set line of source      */
     goto p_ftp_error_00;                   /* FTP error in command    */
   }
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml1 > 0) {                          /* not all input data processed */
     if (achl_rb < adsl_gai1_w1->achc_ginp_end) {
       goto p_ftp_se2cl_64;                 /* FTP server to client keyword found part two */
     }
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1 == NULL) {            /* no more data            */
       goto p_illogic_00;                   /* program illogic         */
     }
     achl_rb = adsl_gai1_w1->achc_ginp_cur;  /* start scann here       */
     goto p_ftp_se2cl_64;                   /* FTP server to client keyword found part two */
   }

   p_ftp_se2cl_68:                          /* part of command processed */
   adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next record in chain */
   if (adsl_tdc1_w1 == NULL) {              /* no more data            */
     IML_FTP_STATE = achl1 - ACHL_FTP_WORK1 + sizeof(ucrs_ftp_se2cl_c1);  /* length command to compare */
     if (adsl_tdc1_w3 == NULL) {            /* no data to other side   */
#ifdef B120309
       goto p_sdh_tcp_end_00;               /* packet has been processed by SDH-TCP */
#else
       goto p_sdh_tcp_cont_80;              /* give output client to SDH-TCP other side */
#endif
     }
     adsl_sdh_tcp_1_sec->adsc_tdc1_in = adsl_tdc1_w3;  /* input data to other side */
     iml_clse_pri = 0;                      /* primary client to server */
     iml_clse_sec = 1;                      /* secondary client to server */
     adsl_sdh_tcp_1_pri = &adsl_ts1_w1->dsrc_sdh_tcp_1[ 0 ];
     adsl_sdh_tcp_1_sec = &adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ];
     if (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL) {  /* already closed */
#ifdef B120309
       goto p_sdh_tcp_end_00;               /* packet has been processed by SDH-TCP */
#else
       goto p_sdh_tcp_cont_80;              /* give output client to SDH-TCP other side */
#endif
     }
     if (adsl_sdh_tcp_1_pri->iec_sts != ied_sts_normal) {  /* not normal processing */
#ifdef B120309
       goto p_sdh_tcp_end_00;               /* packet has been processed by SDH-TCP */
#else
       goto p_sdh_tcp_cont_80;              /* give output client to SDH-TCP other side */
#endif
     }
     goto p_sdh_tcp_cont_84;                /* addresses for SDH-TCP have been set */
   }
   adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;  /* data                    */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic    */
   iml1 = adsl_tdc1_w1->imc_len_data;       /* length of the data      */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml1 <= 0) goto p_illogic_00;        /* program illogic         */
   achl_rb = adsl_gai1_w1->achc_ginp_cur;   /* start scann here        */
   goto p_ftp_se2cl_64;                     /* FTP server to client keyword found part two */

   p_ftp_se2cl_72:                          /* FTP server to client command in buffer */
   achl2 = (char *) memchr( ACHL_FTP_WORK1, (int) '(', achl1 - 2 - ACHL_FTP_WORK1 );
   if (achl2 == NULL) {                     /* bracket not found       */
     iml1 = __LINE__;                       /* set line of source      */
     goto p_ftp_error_00;                   /* FTP error in command    */
   }
   achl2++;                                 /* after bracket           */
   achl3 = (char *) memchr( achl2, (int) ')', achl1 - 2 - achl2 );
   if (achl3 == NULL) {                     /* bracket not found       */
     iml1 = __LINE__;                       /* set line of source      */
     goto p_ftp_error_00;                   /* FTP error in command    */
   }
   bol1 = m_get_decno_6( chrl_work1, achl2, achl3 );
   if (bol1 == FALSE) {                     /* did not decode numbers  */
     iml1 = __LINE__;                       /* set line of source      */
     goto p_ftp_error_00;                   /* FTP error in command    */
   }
   *((UNSIG_MED *) (chrl_work1 + 8)) = m_natted_ineta( adsp_hl_clib_1, chrl_work1, NULL, ADSL_CLCO->boc_disp_inetas );
   iml3 = achl2 - ACHL_FTP_WORK1;           /* second part of message  */
   iml4 = achl1 - achl3;                    /* fourth part of message  */
   if ((dsl_oa1.achc_lower
           + sizeof(ucrs_ftp_se2cl_c1)
           + iml3
           + 6 * 3 + 6 - 1
           + iml4
           + sizeof(struct dsd_gather_i_1)
           + sizeof(struct dsd_tcp_data_contr_1))
         > dsl_oa1.achc_upper) {
     goto p_out_80;                         /* overflow                */
   }
   dsl_oa1.achc_upper -= sizeof(struct dsd_tcp_data_contr_1) + sizeof(struct dsd_gather_i_1);
#define ADSL_TDC1_G ((struct dsd_tcp_data_contr_1 *) dsl_oa1.achc_upper)
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) (ADSL_TDC1_G + 1))
   ADSL_GAI1_G->achc_ginp_cur = dsl_oa1.achc_lower;
   memcpy( dsl_oa1.achc_lower, ucrs_ftp_se2cl_c1, sizeof(ucrs_ftp_se2cl_c1) );
   dsl_oa1.achc_lower += sizeof(ucrs_ftp_se2cl_c1);
   if (iml3) {                              /* second part of message  */
     memcpy( dsl_oa1.achc_lower, ACHL_FTP_WORK1, iml3 );
     dsl_oa1.achc_lower += iml3;
   }
   iml2 = sprintf( dsl_oa1.achc_lower,
                   "%d,%d,%d,%d,%d,%d",
                   *((unsigned char *) chrl_work1 + 8 + 0),
                   *((unsigned char *) chrl_work1 + 8 + 1),
                   *((unsigned char *) chrl_work1 + 8 + 2),
                   *((unsigned char *) chrl_work1 + 8 + 3),
                   *((unsigned char *) chrl_work1 + 4 + 0),
                   *((unsigned char *) chrl_work1 + 4 + 1) );
   dsl_oa1.achc_lower += iml2;
   memcpy( dsl_oa1.achc_lower, achl3, iml4 );
   dsl_oa1.achc_lower += iml4;
   ADSL_GAI1_G->achc_ginp_end = dsl_oa1.achc_lower;
   ADSL_GAI1_G->adsc_next = NULL;
   ADSL_TDC1_G->adsc_next = NULL;
   ADSL_TDC1_G->adsc_gai1 = ADSL_GAI1_G;    /* data                    */
   ADSL_TDC1_G->imc_len_data = sizeof(ucrs_ftp_se2cl_c1) + iml3 + iml2 + iml4;  /* length of the data */
#ifdef B120820
   ADSL_TDC1_G->boc_push_flag = TRUE;       /* PUSH flag of TCP header */
#else
   ADSL_TDC1_G->umc_flags = D_TCP_HEADER_FLAG_PSH;  /* PUSH flag of TCP header */
#endif
   if (adsl_tdc1_w3 == NULL) {              /* no output till now      */
     adsl_tdc1_w3 = ADSL_TDC1_G;            /* input data to other side */
   } else {                                 /* need to append previous output */
     adsl_tdc1_w4 = adsl_tdc1_w3;           /* get start of output     */
     while (adsl_tdc1_w4->adsc_next) adsl_tdc1_w4 = adsl_tdc1_w4->adsc_next;
     adsl_tdc1_w4->adsc_next = ADSL_TDC1_G;  /* append new output      */
   }
#undef ADSL_TDC1_G
#undef ADSL_GAI1_G
   if (iml1 <= 0) {                         /* all characters processed */
     adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next record in chain */
     if (adsl_tdc1_w1 == NULL) {            /* no more data            */
       adsl_ts1_w1->adsc_tcpse1_ext_1->iec_tce1s = ied_tce1s_ftp_start;  /* start of FTP packet */
       adsl_sdh_tcp_1_sec->adsc_tdc1_in = adsl_tdc1_w3;  /* input data to other side */
       iml_clse_pri = 0;                    /* primary client to server */
       iml_clse_sec = 1;                    /* secondary client to server */
       adsl_sdh_tcp_1_pri = &adsl_ts1_w1->dsrc_sdh_tcp_1[ 0 ];
       adsl_sdh_tcp_1_sec = &adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ];
       if (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL) {  /* already closed */
#ifdef B120309
         goto p_sdh_tcp_end_00;             /* packet has been processed by SDH-TCP */
#else
         goto p_sdh_tcp_cont_80;            /* give output client to SDH-TCP other side */
#endif
       }
       if (adsl_sdh_tcp_1_pri->iec_sts != ied_sts_normal) {  /* not normal processing */
#ifdef B120309
         goto p_sdh_tcp_end_00;             /* packet has been processed by SDH-TCP */
#else
         goto p_sdh_tcp_cont_80;            /* give output client to SDH-TCP other side */
#endif
       }
       goto p_sdh_tcp_cont_84;              /* addresses for SDH-TCP have been set */
     }
     adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;  /* data                  */
#ifdef DEBUG_140730_01                      /* problems FTP            */
     iml_error_line = __LINE__;
#endif
     if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic  */
     iml1 = adsl_tdc1_w1->imc_len_data;     /* length of the data      */
#ifdef DEBUG_140730_01                      /* problems FTP            */
     iml_error_line = __LINE__;
#endif
     if (iml1 <= 0) goto p_illogic_00;      /* program illogic         */
   }
   if (iml1 == adsl_tdc1_w1->imc_len_data) {  /* length of the data    */
     adsl_tdc1_w2 = adsl_tdc1_w1;           /* here is start input     */
     goto p_ftp_se2cl_08;                   /* FTP server to client, input all set */
   }
   if ((dsl_oa1.achc_lower
           + sizeof(struct dsd_tcp_data_contr_1)
           + sizeof(struct dsd_gather_i_1))
         > dsl_oa1.achc_upper) {
     goto p_out_80;                         /* overflow                */
   }
   dsl_oa1.achc_upper -= sizeof(struct dsd_tcp_data_contr_1) + sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_NEW ((struct dsd_gather_i_1 *) dsl_oa1.achc_upper)
#define ADSL_TDC1_NEW ((struct dsd_tcp_data_contr_1 *) (ADSL_GAI1_NEW + 1))
   ADSL_GAI1_NEW->achc_ginp_cur = achl_rb;
   ADSL_GAI1_NEW->achc_ginp_end = adsl_gai1_w1->achc_ginp_end;
   ADSL_GAI1_NEW->adsc_next = adsl_gai1_w1->adsc_next;  /* get chain of input gather */
   ADSL_TDC1_NEW->adsc_next = adsl_tdc1_w1->adsc_next;  /* set chaing  */
   ADSL_TDC1_NEW->adsc_gai1 = ADSL_GAI1_NEW;  /* data                  */
   ADSL_TDC1_NEW->imc_len_data = iml1;      /* length of the data      */
#ifdef B120820
   ADSL_TDC1_NEW->boc_push_flag = adsl_tdc1_w1->boc_push_flag;  /* PUSH flag of TCP header */
#else
   ADSL_TDC1_NEW->umc_flags = adsl_tdc1_w1->umc_flags;  /* flags of TCP header */
#endif
   adsl_tdc1_w1 = adsl_tdc1_w2 = ADSL_TDC1_NEW;  /* input data not yet processed */
#undef ADSL_GAI1_NEW
#undef ADSL_TDC1_NEW
   goto p_ftp_se2cl_08;                     /* FTP server to client, input all set */

   p_ftp_eol_00:                            /* FTP search end of line / command */
   do {                                     /* loop over characters    */
     switch (*achl_rb) {                    /* check character         */
       case CHAR_CR:                        /* carriage-return found   */
         IML_FTP_STATE = -2;                /* state carriage-return   */
         break;
       case CHAR_LF:                        /* line-feed found         */
         if (IML_FTP_STATE != -2) {         /* not state carriage-return */
           break;                           /* continue searching      */
         }
         achl_rb++;                         /* the character has been processed */
         iml1--;                            /* decrement number of characters */
         adsl_tdc1_w4 = adsl_tdc1_w1;       /* save current record     */
         if (iml1 <= 0) {                   /* all characters processed */
           adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next record in chain */
           if (adsl_tdc1_w1 == NULL) {      /* no more data            */
             adsl_ts1_w1->adsc_tcpse1_ext_1->iec_tce1s = ied_tce1s_ftp_start;  /* start of FTP packet */
             if (adsl_tdc1_w3 == NULL) {    /* no output till now      */
               adsl_sdh_tcp_1_sec->adsc_tdc1_in = adsl_tdc1_w2;  /* input data to other side */
             } else {                       /* need to append previous output */
               adsl_tdc1_w4 = adsl_tdc1_w3;  /* get start of output    */
               while (adsl_tdc1_w4->adsc_next) adsl_tdc1_w4 = adsl_tdc1_w4->adsc_next;
               adsl_tdc1_w4->adsc_next = adsl_tdc1_w2;  /* append new output */
               adsl_sdh_tcp_1_sec->adsc_tdc1_in = adsl_tdc1_w3;  /* input data to other side */
             }
             iml_clse_pri = iml_clse_sec;   /* primary client to server */
             iml_clse_sec ^= 1;             /* secondary client to server */
             adsl_sdh_tcp_1_pri = &adsl_ts1_w1->dsrc_sdh_tcp_1[ iml_clse_pri ];
             adsl_sdh_tcp_1_sec = &adsl_ts1_w1->dsrc_sdh_tcp_1[ iml_clse_sec ];
             if (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL) {  /* already closed */
#ifdef B120309
               goto p_sdh_tcp_end_00;       /* packet has been processed by SDH-TCP */
#else
               goto p_sdh_tcp_cont_80;      /* give output client to SDH-TCP other side */
#endif
             }
             if (adsl_sdh_tcp_1_pri->iec_sts != ied_sts_normal) {  /* not normal processing */
#ifdef B120309
               goto p_sdh_tcp_end_00;       /* packet has been processed by SDH-TCP */
#else
               goto p_sdh_tcp_cont_80;      /* give output client to SDH-TCP other side */
#endif
             }
             goto p_sdh_tcp_cont_84;        /* addresses for SDH-TCP have been set */
           }
           adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;  /* data            */
#ifdef DEBUG_140730_01                      /* problems FTP            */
           iml_error_line = __LINE__;
#endif
           if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic */
           iml1 = adsl_tdc1_w1->imc_len_data;  /* length of the data   */
#ifdef DEBUG_140730_01                      /* problems FTP            */
           iml_error_line = __LINE__;
#endif
           if (iml1 <= 0) goto p_illogic_00;  /* program illogic       */
         }
         /* divide into old and new records                            */
         while (adsl_tdc1_w2 != adsl_tdc1_w4) {
           if ((dsl_oa1.achc_lower + sizeof(struct dsd_tcp_data_contr_1))
                 > dsl_oa1.achc_upper) {
             goto p_out_80;                 /* overflow                */
           }
           dsl_oa1.achc_upper -= sizeof(struct dsd_tcp_data_contr_1);
#define ADSL_TDC1_OLD ((struct dsd_tcp_data_contr_1 *) dsl_oa1.achc_upper)
           ADSL_TDC1_OLD->adsc_next = NULL;  /* end of chain           */
           ADSL_TDC1_OLD->adsc_gai1 = adsl_tdc1_w2->adsc_gai1;  /* data */
           ADSL_TDC1_OLD->imc_len_data = adsl_tdc1_w2->imc_len_data;  /* length of the data */
#ifdef B120820
           ADSL_TDC1_OLD->boc_push_flag = adsl_tdc1_w2->boc_push_flag;  /* PUSH flag of TCP header */
#else
           ADSL_TDC1_OLD->umc_flags = adsl_tdc1_w2->umc_flags;  /* flags of TCP header */
#endif
           if (adsl_tdc1_w3 == NULL) {      /* no output till now      */
             adsl_tdc1_w3 = ADSL_TDC1_OLD;  /* set old as first output */
           } else {                         /* need to append previous output */
             adsl_tdc1_w5 = adsl_tdc1_w3;   /* get start of output     */
             while (adsl_tdc1_w5->adsc_next) adsl_tdc1_w5 = adsl_tdc1_w5->adsc_next;
             adsl_tdc1_w5->adsc_next = ADSL_TDC1_OLD;  /* append new output */
           }
#undef ADSL_TDC1_OLD
           adsl_tdc1_w2 = adsl_tdc1_w2->adsc_next;  /* this record processed */
         }
         if (iml1 != adsl_tdc1_w1->imc_len_data) {  /* length of the data */
           if ((dsl_oa1.achc_lower + sizeof(struct dsd_tcp_data_contr_1))
                 > dsl_oa1.achc_upper) {
             goto p_out_80;                 /* overflow                */
           }
           dsl_oa1.achc_upper -= sizeof(struct dsd_tcp_data_contr_1);
#define ADSL_TDC1_OLD ((struct dsd_tcp_data_contr_1 *) dsl_oa1.achc_upper)
           ADSL_TDC1_OLD->adsc_next = NULL;  /* end of chain           */
           ADSL_TDC1_OLD->adsc_gai1 = adsl_tdc1_w1->adsc_gai1;  /* data */
           ADSL_TDC1_OLD->imc_len_data = adsl_tdc1_w1->imc_len_data - iml1;  /* length of the data */
#ifdef B120820
           ADSL_TDC1_OLD->boc_push_flag = FALSE;  /* PUSH flag of TCP header */
#else
           ADSL_TDC1_OLD->umc_flags = 0;    /* flags of TCP header     */
#endif
           if (adsl_tdc1_w3 == NULL) {      /* no output till now      */
             adsl_tdc1_w3 = ADSL_TDC1_OLD;  /* set old as first output */
           } else {                         /* need to append previous output */
             adsl_tdc1_w5 = adsl_tdc1_w3;   /* get start of output     */
             while (adsl_tdc1_w5->adsc_next) adsl_tdc1_w5 = adsl_tdc1_w5->adsc_next;
             adsl_tdc1_w5->adsc_next = ADSL_TDC1_OLD;  /* append new output */
           }
#undef ADSL_TDC1_OLD
         }
         if ((dsl_oa1.achc_lower
                 + sizeof(struct dsd_tcp_data_contr_1)
                 + sizeof(struct dsd_gather_i_1))
               > dsl_oa1.achc_upper) {
           goto p_out_80;                   /* overflow                */
         }
         dsl_oa1.achc_upper -= sizeof(struct dsd_tcp_data_contr_1) + sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_NEW ((struct dsd_gather_i_1 *) dsl_oa1.achc_upper)
#define ADSL_TDC1_NEW ((struct dsd_tcp_data_contr_1 *) (ADSL_GAI1_NEW + 1))
         ADSL_GAI1_NEW->achc_ginp_cur = achl_rb;
         ADSL_GAI1_NEW->achc_ginp_end = adsl_gai1_w1->achc_ginp_end;
         ADSL_GAI1_NEW->adsc_next = adsl_gai1_w1->adsc_next;  /* get chain of input gather */
         ADSL_TDC1_NEW->adsc_next = adsl_tdc1_w1->adsc_next;  /* set chaing */
         ADSL_TDC1_NEW->adsc_gai1 = ADSL_GAI1_NEW;  /* data            */
         ADSL_TDC1_NEW->imc_len_data = iml1;  /* length of the data    */
#ifdef B120820
         ADSL_TDC1_NEW->boc_push_flag = adsl_tdc1_w1->boc_push_flag;  /* PUSH flag of TCP header */
#else
         ADSL_TDC1_NEW->umc_flags = adsl_tdc1_w1->umc_flags;  /* flags of TCP header */
#endif
         adsl_tdc1_w1 = adsl_tdc1_w2 = ADSL_TDC1_NEW;  /* input data not yet processed */
#undef ADSL_GAI1_NEW
#undef ADSL_TDC1_NEW
         if (iml_clse_sec == 0) {           /* from server to client   */
           goto p_ftp_cl2se_08;             /* FTP client to server, input all set */
         }
         goto p_ftp_se2cl_08;               /* FTP server to client, input all set */
       default:                             /* normal character found  */
         IML_FTP_STATE = -1;                /* state wait for carriage-return */
         break;
     }
     achl_rb++;                             /* the character has been processed */
     iml1--;                                /* decrement number of characters */
     if (iml1 <= 0) break;                  /* all characters processed */
   } while (achl_rb < adsl_gai1_w1->achc_ginp_end);
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml1 > 0) {                          /* not all input data processed */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1 == NULL) {            /* no more data            */
       goto p_illogic_00;                   /* program illogic         */
     }
     achl_rb = adsl_gai1_w1->achc_ginp_cur;  /* start scann here       */
     goto p_ftp_eol_00;                     /* FTP search end of line / command */
   }
   adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next record in chain */
   if (adsl_tdc1_w1 == NULL) {              /* no more data            */
     adsl_sdh_tcp_1_sec->adsc_tdc1_in = adsl_tdc1_w2;  /* input data to other side */
     iml_clse_pri = iml_clse_sec;           /* primary client to server */
     iml_clse_sec ^= 1;                     /* secondary client to server */
     adsl_sdh_tcp_1_pri = &adsl_ts1_w1->dsrc_sdh_tcp_1[ iml_clse_pri ];
     adsl_sdh_tcp_1_sec = &adsl_ts1_w1->dsrc_sdh_tcp_1[ iml_clse_sec ];
     if (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL) {  /* already closed */
#ifdef B120309
       goto p_sdh_tcp_end_00;               /* packet has been processed by SDH-TCP */
#else
       goto p_sdh_tcp_cont_80;              /* give output client to SDH-TCP other side */
#endif
     }
     if (adsl_sdh_tcp_1_pri->iec_sts != ied_sts_normal) {  /* not normal processing */
#ifdef B120309
       goto p_sdh_tcp_end_00;               /* packet has been processed by SDH-TCP */
#else
       goto p_sdh_tcp_cont_80;              /* give output client to SDH-TCP other side */
#endif
     }
     goto p_sdh_tcp_cont_84;                /* addresses for SDH-TCP have been set */
   }
   adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;  /* data                    */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic    */
   iml1 = adsl_tdc1_w1->imc_len_data;       /* length of the data      */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iml1 <= 0) goto p_illogic_00;        /* program illogic         */
   achl_rb = adsl_gai1_w1->achc_ginp_cur;   /* start scann here        */
   goto p_ftp_eol_00;                       /* FTP search end of line / command */

   p_ftp_error_00:                          /* FTP error in command    */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W FTP invalid data received line %05d.",
                 __LINE__, iml1 );
   adsl_sdh_tcp_1_pri->boc_eof_client = TRUE;  /* End-of-File Client   */
   goto p_sdh_tcp_cont_84;                  /* addresses for SDH-TCP have been set */

#undef IML_FTP_STATE
#undef ACHL_FTP_WORK1
#undef IML_FTP_LEN_WORK1

   p_sdh_tcp_cont_80:                       /* give output client to SDH-TCP other side */
#ifndef B120309
   if (bol_call_sec == FALSE) {             /* do not call SDH-TCP secondary */
     goto p_sdh_tcp_end_00;                 /* packet has been processed by SDH-TCP */
   }
#endif
   iml_clse_pri = iml_clse_sec;             /* primary client to server */
   iml_clse_sec ^= 1;                       /* secondary client to server */
   adsl_sdh_tcp_1_pri = &adsl_ts1_w1->dsrc_sdh_tcp_1[ iml_clse_pri ];
   adsl_sdh_tcp_1_sec = &adsl_ts1_w1->dsrc_sdh_tcp_1[ iml_clse_sec ];
   if (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL) {  /* already closed */
     goto p_sdh_tcp_end_00;                 /* packet has been processed by SDH-TCP */
   }
   if (adsl_sdh_tcp_1_pri->iec_sts != ied_sts_normal) {  /* not normal processing */
     goto p_sdh_tcp_end_00;                 /* packet has been processed by SDH-TCP */
   }
   adsl_sdh_tcp_1_pri->adsc_tdc1_in = adsl_sdh_tcp_1_sec->adsc_tdc1_out_to_client;  /* input data */
   adsl_sdh_tcp_1_sec->adsc_tdc1_out_to_client = NULL;  /* clear output data to client */

   p_sdh_tcp_cont_84:                       /* addresses for SDH-TCP have been set */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_sdh_tcp_cont_84: process SDH-TCP at adsl_ts1_w1=%p iml_clse_pri=%d.",
                 __LINE__, adsl_ts1_w1, iml_clse_pri );
#endif
   memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
   bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                      DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                      &dsl_aux_get_workarea,
                                      sizeof(struct dsd_aux_get_workarea) );
   if (bol1 == FALSE) {                     /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_sdh_tcp_1_pri->achc_work_area = dsl_aux_get_workarea.achc_work_area;  /* addr work-area returned */
   adsl_sdh_tcp_1_pri->imc_len_work_area = dsl_aux_get_workarea.imc_len_work_area;  /* length work-area returned */
   dsl_subaux_userfld.adsc_sdh_tcp_1 = adsl_sdh_tcp_1_pri;  /* TCP half-session */
   dsl_subaux_userfld.adsc_session_timer = &adsl_ts1_w1->dsrc_session_timer[ iml_clse_pri ];  /* session timer */
#ifdef TRACEHL_TIMER_01
   bol1 = FALSE;                            /* no timer was running    */
#endif
   if (adsl_ts1_w1->dsrc_session_timer[ iml_clse_pri ].ilc_epoch_end) {  /* epoch timer set */
#ifdef TRACEHL_TIMER_01
     bol1 = TRUE;                           /* timer was running       */
#endif
     if (adsl_ts1_w1->dsrc_session_timer[ iml_clse_pri ].ilc_epoch_end
           <= dsl_subaux_userfld.ilc_epoch) {  /* timer has elapsed    */
       adsl_sdh_tcp_1_pri->boc_timer_running = FALSE;  /* timer is currently not running */
     }
   }
   if (iml_clse_pri == 0) {                 /* primary client to server */
     adsl_sdh_tcp_1_pri->boc_send_netw_blocked  /* sending to the network is blocked */
       = adsp_hl_clib_1->boc_send_client_blocked;  /* sending to the client is blocked */
     if (adsl_ts1_w1->dsc_session_notify.iec_se_no != ied_se_no_idle) {  /* notify session set */
       if (&adsl_ts1_w1->dsc_session_notify == adsl_contr_1->adsc_session_notify) {
         adsl_contr_1->adsc_session_notify = adsl_contr_1->adsc_session_notify->adsc_next;  /* remove from chain */
       } else {                             /* middle in chain         */
         adsl_session_notify_w1 = adsl_contr_1->adsc_session_notify;  /* session notify send possible */
         while (TRUE) {                     /* loop over all session notify */
           if (&adsl_ts1_w1->dsc_session_notify == adsl_session_notify_w1->adsc_next) {
#ifdef B140708
             adsl_session_notify_w1->adsc_next->adsc_next = adsl_session_notify_w1->adsc_next;  /* remove from chain */
#endif
#ifndef B140708
             adsl_session_notify_w1->adsc_next = adsl_session_notify_w1->adsc_next->adsc_next;  /* remove from chain */
#endif
             break;                         /* all done                */
           }
           adsl_session_notify_w1 = adsl_session_notify_w1->adsc_next;
           if (adsl_session_notify_w1 == NULL) {  /* at end of chain   */
             m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W chain notify session corrupted", __LINE__ );
             break;
           }
         }
       }
       adsl_ts1_w1->dsc_session_notify.iec_se_no = ied_se_no_idle;  /* notify session no more set */
     }
   }
   adsl_sdh_tcp_1_pri->vpc_userfld = &dsl_subaux_userfld;  /* User Field Subroutine */
   adsl_sdh_tcp_1_pri->imc_func = DEF_IFUNC_TOSERVER;  /* data to server */
#ifdef TRACEHL_TIMER_01
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T call SDH-TCP adsc_sdh_tcp_1=%p timer-before=%d boc_timer_running=%d.",
                 __LINE__, adsl_sdh_tcp_1_pri, bol1, adsl_sdh_tcp_1_pri->boc_timer_running );
   if (adsl_sdh_tcp_1_pri->adsc_tdc1_in) {
     adsl_tdc1_w1 = adsl_sdh_tcp_1_pri->adsc_tdc1_in;
     iml1 = 0;
     do {                                   /* loop over input data    */
       iml1++;                              /* increment counter input */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T inp %d. addr=%p adsc_gai1=%p imc_len_data=%d/0X%X umc_flags=0X%08X.",
                     __LINE__,
                     iml1,
                     adsl_tdc1_w1,
                     adsl_tdc1_w1->adsc_gai1,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->umc_flags );
       iml2 = adsl_tdc1_w1->imc_len_data;
       adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;
       while (adsl_gai1_w1) {
         if (iml2 <= 0) break;
         iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         if (iml3 > iml2) iml3 = iml2;
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T gather %p length %d/0X%X.",
                       __LINE__, adsl_gai1_w1, iml3, iml3 );
         m_sdh_console_out( &dsl_sdh_call_1, adsl_gai1_w1->achc_ginp_cur, iml3 );
         iml2 -= iml3;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
       adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next in chain   */
     } while (adsl_tdc1_w1);
   }
#endif
   m_sdhtcp01( adsl_sdh_tcp_1_pri );        /* call SDH-TCP            */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_sdhtcp01() %d returned %d adsc_tdc1_out_to_client=%p adsc_tdc1_out_to_server=%p.",
                 __LINE__,
                 iml_clse_pri,
                 adsl_sdh_tcp_1_pri->imc_return,
                 adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client,  /* output data to client */
                 adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server );  /* output data to server */
   if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client) {
     adsl_tdc1_w1 = adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_client;
     iml1 = 0;
     do {                                   /* loop over input data    */
       iml1++;                              /* increment counter input */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T out-to-client %d. addr=%p adsc_gai1=%p imc_len_data=%d/0X%X umc_flags=0X%08X.",
                     __LINE__,
                     iml1,
                     adsl_tdc1_w1,
                     adsl_tdc1_w1->adsc_gai1,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->umc_flags );
       iml2 = adsl_tdc1_w1->imc_len_data;
       adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;
       while (adsl_gai1_w1) {
         if (iml2 <= 0) break;
         iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         if (iml3 > iml2) iml3 = iml2;
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T gather %p length %d/0X%X.",
                       __LINE__, adsl_gai1_w1, iml3, iml3 );
         m_sdh_console_out( &dsl_sdh_call_1, adsl_gai1_w1->achc_ginp_cur, iml3 );
         iml2 -= iml3;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
       adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next in chain   */
     } while (adsl_tdc1_w1);
   }
   if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server) {
     adsl_tdc1_w1 = adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server;
     iml1 = 0;
     do {                                   /* loop over input data    */
       iml1++;                              /* increment counter input */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T out-to-server %d. addr=%p adsc_gai1=%p imc_len_data=%d/0X%X umc_flags=0X%08X.",
                     __LINE__,
                     iml1,
                     adsl_tdc1_w1,
                     adsl_tdc1_w1->adsc_gai1,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->imc_len_data,
                     adsl_tdc1_w1->umc_flags );
       iml2 = adsl_tdc1_w1->imc_len_data;
       adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;
       while (adsl_gai1_w1) {
         if (iml2 <= 0) break;
         iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         if (iml3 > iml2) iml3 = iml2;
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T gather %p length %d/0X%X.",
                       __LINE__, adsl_gai1_w1, iml3, iml3 );
         m_sdh_console_out( &dsl_sdh_call_1, adsl_gai1_w1->achc_ginp_cur, iml3 );
         iml2 -= iml3;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
       adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next in chain   */
     } while (adsl_tdc1_w1);
   }
#endif
   adsl_sdh_tcp_1_sec->boc_stop_receiving = FALSE;  /* stop receiving from the server */
   if (adsl_sdh_tcp_1_pri->imc_queue_buffer > MAX_TCP_SNDBUF) {  /* bytes TCP packets buffered for sending to the server */
     adsl_sdh_tcp_1_sec->boc_stop_receiving = TRUE;  /* stop receiving from the server */
   }
#ifndef B130409
   if (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL) {
     adsl_sdh_tcp_1_pri->imc_func = 0;      /* TCP connection not started, do not call again */
   }
#endif
   /* set notify send to network possible when requested               */
   if (   (iml_clse_pri == 0)               /* primary client to server */
       && (adsl_sdh_tcp_1_pri->boc_notify_send_netw_possible)  /* notify SDH-TCP when sending to the network is possible */
       && (adsl_sdh_tcp_1_pri->imc_return == DEF_IRET_NORMAL)) {
     adsl_ts1_w1->dsc_session_notify.iec_se_no = ied_se_no_act_new;  /* active, new */
     adsl_ts1_w1->dsc_session_notify.adsc_next = NULL;  /* clear chain field */
     if (adsl_contr_1->adsc_session_notify == NULL) {  /* now first in chain */
       adsl_contr_1->adsc_session_notify = &adsl_ts1_w1->dsc_session_notify;  /* set new chain */
     } else {                               /* middle in chain         */
       adsl_session_notify_w1 = adsl_contr_1->adsc_session_notify;  /* session notify send possible */
       while (adsl_session_notify_w1->adsc_next) adsl_session_notify_w1 = adsl_session_notify_w1->adsc_next;
       adsl_session_notify_w1->adsc_next = &adsl_ts1_w1->dsc_session_notify;  /* append to chain */
     }
   }
#ifdef TRACEHL_INETA_01
   if (bol_ipv6 == FALSE) {                 /* is IPV4, not IPV6       */
     m_trineta_print_01( chrl_trineta_buf,
                         &unl_sort_ineta.dsrl_ct_ipv4[ iml_clse_pri ],
                         iml_clse_sec );
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_sdh_tcp_cont_84: adsl_sdh_tcp_1_pri=%p iml_clse_pri=%d r=%s %s",
                   __LINE__, adsl_sdh_tcp_1_pri, iml_clse_pri, achl_trhl_reason, chrl_trineta_buf );
   }
#endif
   if (adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server == NULL) {  /* output data to server */
     goto p_sdh_tcp_cont_60;                /* check output client side */
   }
   adsl_tdc1_w1 = adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server;  /* output data to server */
   adsl_sdh_tcp_1_pri->adsc_tdc1_out_to_server = NULL;  /* clear output data to server */
#ifdef TRACEHL_111004
   memmove( adsl_contr_1->imrl_trace_lno,
            adsl_contr_1->imrl_trace_lno + 1,
            (TRACEHL_111004 - 1) * sizeof(int) );
   adsl_contr_1->imrl_trace_lno[ TRACEHL_111004 - 1 ] = __LINE__;
#endif
   goto p_sdh_tcp_cont_20;                  /* process output of SDH-TCP */

   p_sdh_tcp_end_00:                        /* packet has been processed by SDH-TCP */
#ifdef TRACEHL_111004
   memmove( adsl_contr_1->imrl_trace_lno,
            adsl_contr_1->imrl_trace_lno + 1,
            (TRACEHL_111004 - 1) * sizeof(int) );
   adsl_contr_1->imrl_trace_lno[ TRACEHL_111004 - 1 ] = __LINE__;
#endif
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   if (iel_ps != ied_ps_timer) {            /* not processing thru timer */
     if (adsl_gai1_inp_start != adsl_gai1_inp_w1) {
       adsl_gai1_inp_start->achc_ginp_cur = adsl_gai1_inp_start->achc_ginp_end;
       adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;
       if (adsl_gai1_inp_start == NULL) goto p_illogic_00;  /* program illogic */
     }
     adsl_gai1_inp_start->achc_ginp_cur = achl_inp;  /* processed so far */
   }
   if (   (adsl_ts1_w1->dsrc_sdh_tcp_1[ 0 ].imc_return == DEF_IRET_NORMAL)
       || (adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].imc_return == DEF_IRET_NORMAL)) {
     if (adsl_gai1_inp_start == NULL) {     /* no start input data     */
       goto p_timer_00;                     /* check the timer         */
     }
     goto p_check_recv_00;                  /* all done                */
   }

   /* the TCP session is no longer alive, remove it from the AVL tree  */
// p_sdh_tcp_end_20:                        /* remove the session      */
   adsl_contr_1->imc_session_cur--;         /* current sessions        */
   switch (iel_ps) {                        /* program status          */
     case ied_ps_start:                     /* start of TCP session    */
       goto p_sdh_tcp_end_60;               /* free memory             */
     case ied_ps_cont:                      /* continue TCP session    */
       goto p_sdh_tcp_end_40;               /* delete from AVL tree    */
   }
   adsl_htree1_avl_cntl_ineta = &adsl_contr_1->dsc_htree1_avl_cntl_ineta_ipv4;
   if (bol_ipv6) {                          /* is IPV6, not IPV4       */
     adsl_htree1_avl_cntl_ineta = &adsl_contr_1->dsc_htree1_avl_cntl_ineta_ipv6;
   }
   dsl_htree1_work.adsc_found = NULL;       /* no entry found          */

   p_sdh_tcp_end_40:                        /* delete from AVL tree    */
   while (   (bol_ipv6 == FALSE)            /* is IPV4, not IPV6       */
          && (   (adsl_ts1_w1->adsc_tcpse1_ext_1 == NULL)  /* no TCP session extension */
              || (adsl_ts1_w1->adsc_tcpse1_ext_1->iec_tce1s == ied_tce1s_socks5_wait_connect))  /* wait for connect of other half-session */
          && (((struct dsd_sort_tcp_ipv4 *) (adsl_ts1_w1 + 1))->dsc_ct_ipv4.iec_cti4
                == ied_cti4_s5_client)) {   /* Socks client TCP half-session */
#define ADSL_SORT_TCP_IPV4_SERVER ((struct dsd_sort_tcp_ipv4 *) ((char *) (adsl_ts1_w1 + 1) + sizeof(struct dsd_sort_tcp_ipv4)))
     if (((char *) dsl_htree1_work.adsc_found) != ((char *) &ADSL_SORT_TCP_IPV4_SERVER->dsc_sort_ineta)) {
       bol1 = m_htree1_avl_search( NULL, adsl_htree1_avl_cntl_ineta,
                                   &dsl_htree1_work, &ADSL_SORT_TCP_IPV4_SERVER->dsc_sort_ineta );
       if (bol1 == FALSE) {                 /* error occured           */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_search() failed",
                       __LINE__ );
         break;                             /* cannot delete entry     */
       }
       if (dsl_htree1_work.adsc_found == NULL) {  /* entry not found   */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_htree1_avl_search() did not find entry to be deleted",
                       __LINE__ );
         break;                             /* cannot delete entry     */
       }
     }
     bol1 = m_htree1_avl_delete( NULL, adsl_htree1_avl_cntl_ineta,
                                 &dsl_htree1_work );
     if (bol1 == FALSE) {                   /* error occured           */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_delete() failed",
                     __LINE__ );
     }
     break;                                 /* all done                */
#undef ADSL_SORT_TCP_IPV4_SERVER
   }
   if (((char *) dsl_htree1_work.adsc_found) != ((char *) (adsl_ts1_w1 + 1))) {
     bol1 = m_htree1_avl_search( NULL, adsl_htree1_avl_cntl_ineta,
                                 &dsl_htree1_work, (struct dsd_htree1_avl_entry *) (adsl_ts1_w1 + 1) );
     if (bol1 == FALSE) {                   /* error occured           */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_search() failed",
                     __LINE__ );
       goto p_sdh_tcp_end_60;               /* free memory             */
     }
     if (dsl_htree1_work.adsc_found == NULL) {  /* entry not found     */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_htree1_avl_search() did not find entry to be deleted",
                     __LINE__ );
       goto p_sdh_tcp_end_60;               /* free memory             */
     }
   }
   bol1 = m_htree1_avl_delete( NULL, adsl_htree1_avl_cntl_ineta,
                               &dsl_htree1_work );
   if (bol1 == FALSE) {                     /* error occured           */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_delete() failed",
                   __LINE__ );
   }

   p_sdh_tcp_end_60:                        /* release timers and free memory */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_sdh_tcp_end_60 end of TCP session",
                 __LINE__ );
#endif
   iml_clse_pri = 0;                        /* primary client to server */

   p_sdh_tcp_end_64:                        /* check the timer         */
   if (adsl_ts1_w1->dsrc_session_timer[ iml_clse_pri ].ilc_epoch_end == 0) {  /* epoch timer set */
     goto p_sdh_tcp_end_76;                 /* the timer is no more in chain */
   }
   if (&adsl_ts1_w1->dsrc_session_timer[ iml_clse_pri ] == adsl_contr_1->adsc_session_timer) {  /* is first in chain */
     adsl_contr_1->adsc_session_timer = adsl_contr_1->adsc_session_timer->adsc_next;  /* remove from chain */
     goto p_sdh_tcp_end_76;                 /* the timer is no more in chain */
   }
   adsl_session_timer_w1 = adsl_contr_1->adsc_session_timer;  /* get chain */
   if (adsl_session_timer_w1 == NULL) {     /* chain is empty          */
     goto p_sdh_tcp_end_72;                 /* timer chain corrupted   */
   }

   p_sdh_tcp_end_68:                        /* search timer in chain   */
   if (&adsl_ts1_w1->dsrc_session_timer[ iml_clse_pri ] == adsl_session_timer_w1->adsc_next) {  /* check if next from here */
     adsl_session_timer_w1->adsc_next = adsl_session_timer_w1->adsc_next->adsc_next;  /* remove entry from chain */
     goto p_sdh_tcp_end_76;                 /* the timer is no more in chain */
   }
   adsl_session_timer_w1 = adsl_session_timer_w1->adsc_next;  /* get next in chain */
   if (adsl_session_timer_w1) goto p_sdh_tcp_end_68;  /* search timer in chain */

   p_sdh_tcp_end_72:                        /* timer chain corrupted   */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W p_sdh_tcp_end_72 timer chain corrupted",
                 __LINE__ );

   p_sdh_tcp_end_76:                        /* the timer is no more in chain */
   if (iml_clse_pri == 0) {                 /* primary client to server */
     iml_clse_pri = 1;                      /* primary client to server */
     goto p_sdh_tcp_end_64;                 /* check the timer         */
   }

   if (adsl_ts1_w1->adsc_tcpse1_ext_1) {    /* TCP session extension   */
     bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                     DEF_AUX_MEMFREE,
                                     &adsl_ts1_w1->adsc_tcpse1_ext_1,
                                     0 );
     if (bol1 == FALSE) {                   /* error occured           */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
   }

   p_sdh_tcp_end_80:                        /* only free memory        */
   bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                   DEF_AUX_MEMFREE,
                                   &adsl_ts1_w1,
                                   0 );
   if (bol1 == FALSE) {                     /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (adsl_gai1_inp_start == NULL) {       /* no start input data     */
     goto p_timer_00;                       /* check the timer         */
   }
   goto p_check_recv_00;                    /* all done                */
#ifdef XYZ1
//-------------------------------------------
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T packet iml_len_nhasn=%d iml_len_packet=%d.",
                 __LINE__, iml_len_nhasn, iml_len_packet );
   m_dump_gather( &dsl_sdh_call_1, adsl_gai1_inp_start, iml_len_nhasn + iml_len_packet );
#endif
   iml_len_ip_header = (*(achl_packet - 1) & 0X0F) << 2;  /* length of IP header */
   if (iml_len_ip_header < (5 * 4)) {       /* IP header too short     */
     goto p_inv_data_00;                    /* input data invalid      */
   }
   if (iml_len_packet < (1 + iml_len_ip_header)) {  /* packet too short */
     goto p_inv_data_00;                    /* input data invalid      */
   }
#endif

   p_udp_00:                                /* UDP packet found        */
   achl_sip_packet = NULL;                  /* clear start of SIP packet */

#ifdef B110822
   /* copy the first part of the packet to the output area             */
   achl_out_ippa = (char *) (((long long int) (dsl_oa1.achc_lower + MAX_LEN_NHASN + 1 + sizeof(UNSIG_MED) - 1)) & (0 - sizeof(UNSIG_MED)));
   achl_out_end = achl_out_ippa + iml_len_ip_header;
   adsl_gai1_out_t1 = (struct dsd_gather_i_1 *) dsl_oa1.achc_upper - 1;  /* output data */
   if (achl_out_end > ((char *) adsl_gai1_out_t1)) {  /* no space for output */
     adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
#ifdef CHECK_OUTPUT_01
     m_check_output_01( adsp_hl_clib_1 );
#endif
     return;                                /* to be called again      */
   }
   adsl_gai1_out_t1->achc_ginp_end = achl_out_end;  /* end of gather   */
   *achl_out_ippa = *(achl_packet - 1);     /* copy first byte IP header */
   iml1 = iml_len_ip_header - (2 - 1);      /* end part one            */

   p_udp_20:                                /* copy IPV4 UDP packet part one */
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl_out_end - iml1, achl_packet, iml2 );
   achl_packet += iml2;
   iml1 -= iml2;
   if (iml1) goto p_udp_20;                 /* copy IPV4 UDP packet part one */
#ifdef DEBUG_101207_02
   if (bol_output) {                        /* output has been done    */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T second packet for output iml_len_packet=%d/0X%p.",
                   __LINE__, iml_len_packet, iml_len_packet );
   }
#endif
#define CHL_PROTOCOL *(achl_out_ippa + D_POS_IPV4_H_PROT)  /* protocol from IP header */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T packet protocol=0X%02X.",
                 __LINE__, (unsigned char) CHL_PROTOCOL );
#endif
   /* check if UDP header                                              */
#ifndef TRY_101205
   if (CHL_PROTOCOL != IPPROTO_UDP) {       /* not protocol UDP from IP header */
     goto p_udp_80;                         /* all headers are in output area */
   }
#else
   if ((CHL_PROTOCOL & 0X0F) != (IPPROTO_UDP & 0X0F)) {  /* not protocol UDP from IP header */
     goto p_udp_80;                         /* all headers are in output area */
   }
#endif
   if (iml_len_packet < (1 + iml_len_ip_header + D_LEN_UDP_HEADER)) {  /* packet too short */
#ifndef EXT_111125_01
     goto p_inv_data_00;                    /* input data invalid      */
#else
     iml_invdat = __LINE__;                 /* line number invalid data */
     goto p_inv_data_00;                    /* input data invalid      */
#endif
   }
   achl_out_end += D_LEN_UDP_HEADER;        /* new end of headers      */
   if (achl_out_end > ((char *) adsl_gai1_out_t1)) {  /* no space for output */
     adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
#ifdef CHECK_OUTPUT_01
     m_check_output_01( adsp_hl_clib_1 );
#endif
     return;                                /* to be called again      */
   }
   adsl_gai1_out_t1->achc_ginp_end = achl_out_end;  /* end of gather   */

   p_udp_60:                                /* copy IPV4 UDP packet part two */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl_out_end - iml1, achl_packet, iml2 );
   achl_packet += iml2;
   iml1 -= iml2;
   if (iml1) goto p_udp_60;                 /* copy IPV4 UDP packet part two */

   p_udp_80:                                /* all headers are in output area */
   memcpy( &uml_ineta_dns, achl_out_ippa + 16, sizeof(UNSIG_MED) );  /* INETA for DNS */
   /* apply NAT                                                        */
   if (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER) {
     *((UNSIG_MED *) (achl_out_ippa + 12)) = adsl_contr_1->umc_ineta_cl_int;  /* INETA client intern in intranet */
     *((UNSIG_MED *) (achl_out_ippa + 16))
       = m_original_ineta( adsp_hl_clib_1, achl_out_ippa + 16, &dsl_nrv );
   } else {
     *((UNSIG_MED *) (achl_out_ippa + 12))
       = m_natted_ineta( adsp_hl_clib_1, achl_out_ippa + 12, NULL, ADSL_CLCO->boc_disp_inetas );
     *((UNSIG_MED *) (achl_out_ippa + 16)) = adsl_contr_1->umc_ineta_client;  /* INETA client in tunnel */
   }
#ifdef B101204
// iml_pos_packet = 1 + D_LEN_IP_H_P1;      /* first part has been copied */
#endif

// p_check_sip_00:                          /* has to check SIP        */
#ifndef TRY_101205
   if (CHL_PROTOCOL != IPPROTO_UDP) {       /* protocol from IP header */
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }
#else
   if ((CHL_PROTOCOL & 0X0F) != (IPPROTO_UDP & 0X0F)) {       /* protocol from IP header */
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }
#endif
#endif
#ifdef TRACEHL1
// printf( "xl-sdh-ppp-pf-07-l%05d-T m_hlclib_conf() found node %S\n", __LINE__, awcl_name );
   iml1 = (*((unsigned char *) achl_out_ippa + iml_len_ip_header + iml_udp_pos_port + 0) << 8)
            | *((unsigned char *) achl_out_ippa + iml_len_ip_header + iml_udp_pos_port + 1);
#endif
   if (ADSL_CLCO->boc_alg_sip == FALSE) {   /* do not use ALG for SIP VoIP protocol */
     goto p_check_dns_00;                   /* has to check DNS        */
   }
// 28.08.12 KB - alignment
#ifdef B120828
   if (*((unsigned short int *) chrs_port_dns)
         == *((unsigned short int *) (achl_out_ippa + iml_len_ip_header + iml_udp_pos_port))) {
     if (ADSL_CLCO->imc_len_conf_ext_1) {   /* length of configuration extensions */
       goto p_check_dns_20;                 /* this is UDP DNS packet  */
     }
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }
#endif
   if (!memcmp( chrs_port_dns,
                achl_out_ippa + iml_len_ip_header + iml_udp_pos_port,
                sizeof(unsigned short int) )) {
#ifdef B130607
     if (ADSL_CLCO->imc_len_conf_ext_1) {   /* length of configuration extensions */
       goto p_check_dns_20;                 /* this is UDP DNS packet  */
     }
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
#else
     goto p_check_dns_20;                   /* this is UDP DNS packet  */
#endif
   }
#ifdef B120828
   if (*((unsigned short int *) chrs_port_sip)
         == *((unsigned short int *) (achl_out_ippa + iml_len_ip_header + 0))) {
     goto p_check_sip_20;                   /* this is UDP SIP packet  */
   }
   if (*((unsigned short int *) chrs_port_sip)
         != *((unsigned short int *) (achl_out_ippa + iml_len_ip_header + 2))) {
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }
#endif
   if (!memcmp( chrs_port_sip,
                achl_out_ippa + iml_len_ip_header + 0,
                sizeof(unsigned short int) )) {
     goto p_check_sip_20;                   /* this is UDP SIP packet  */
   }
   if (memcmp( chrs_port_sip,
               achl_out_ippa + iml_len_ip_header + 2,
               sizeof(unsigned short int) )) {
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }

   p_check_sip_20:                          /* this is UDP SIP packet  */
#ifdef DEBUG_101207_01
   bos_debug_01 = FALSE;
   if (adsp_hl_clib_1->inc_func == DEF_IFUNC_FROMSERVER) {
     iml3 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
     if (   (iml3 > 20)
         && (!memcmp( achl_packet, "INVITE ", 7))) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T FROMSERVER INVITE",
                     __LINE__ );
       bos_debug_01 = TRUE;
     }
   }
#endif
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml3 = iml_len_nhasn + 1 + (achl_out_end - achl_out_ippa);  /* overread this part */
#else
   iml3 = achl_out_end - achl_out_ippa;     /* overread this part      */
#endif

   p_check_sip_40:                          /* overread first part of packet */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
#ifdef B110709
   while (adsl_gai1_inp_start->achc_ginp_cur >= adsl_gai1_inp_w1->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_start == NULL) goto p_illogic_00;  /* program illogic */
   }
   iml2 = adsl_gai1_inp_w1->achc_ginp_end - adsl_gai1_inp_start->achc_ginp_cur;
#else
   while (adsl_gai1_inp_start->achc_ginp_cur >= adsl_gai1_inp_start->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_start == NULL) goto p_illogic_00;  /* program illogic */
   }
   iml2 = adsl_gai1_inp_start->achc_ginp_end - adsl_gai1_inp_start->achc_ginp_cur;
#endif
   if (iml2 > iml3) iml2 = iml3;
   adsl_gai1_inp_start->achc_ginp_cur += iml2;
   iml3 -= iml2;
   if (iml3) goto p_check_sip_40;           /* overread first part of packet */

#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (adsl_gai1_inp_start->achc_ginp_cur >= adsl_gai1_inp_start->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_start == NULL) goto p_illogic_00;  /* program illogic */
   }
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml1 = iml_len_packet - 1 - (achl_out_end - achl_out_ippa);  /* length to copy */
#else
   iml1 = iml_len_packet - (achl_out_end - achl_out_ippa);  /* length to copy */
#endif
#ifdef B110709
   iml2 = adsl_gai1_inp_w1->achc_ginp_end - adsl_gai1_inp_start->achc_ginp_cur;
#else
   iml2 = adsl_gai1_inp_start->achc_ginp_end - adsl_gai1_inp_start->achc_ginp_cur;
#endif
   if (iml1 <= iml2) {                      /* SIP packet in one single chunk */
     achl_sip_packet = adsl_gai1_inp_start->achc_ginp_cur;  /* here starts SIP packet */
     adsl_gai1_inp_start->achc_ginp_cur += iml1;  /* data are processed */
     goto p_copy_00;                        /* copy the packet         */
   }

   /* we copy the SIP packet to the work area                          */
   if (iml1 > sizeof(chrl_work1)) {
     goto p_data_to_long;                   /* input data too long     */
   }

   achl1 = chrl_work1;                      /* copy packet here        */

   p_check_sip_60:                          /* copy part of the packet */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (adsl_gai1_inp_start->achc_ginp_cur >= adsl_gai1_inp_start->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_start == NULL) goto p_illogic_00;  /* program illogic */
   }
   iml2 = adsl_gai1_inp_start->achc_ginp_end - adsl_gai1_inp_start->achc_ginp_cur;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl1, adsl_gai1_inp_start->achc_ginp_cur, iml2 );
   achl1 += iml2;
   adsl_gai1_inp_start->achc_ginp_cur += iml2;
   iml1 -= iml2;
   if (iml1) goto p_check_sip_60;           /* copy part of the packet */
   achl_sip_packet = chrl_work1;            /* here starts SIP packet  */
   goto p_copy_00;                          /* copy the packet         */

   p_check_dns_00:                          /* has to check DNS        */
   if (   (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER)
       && (ADSL_CLCO->imc_len_conf_ext_1 == 0)) {  /* length of configuration extensions */
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }
#ifdef B110822
   /* displacement zero in UDP header is source port                   */
   if (*((unsigned short int *) chrs_port_dns)
         != *((unsigned short int *) (achl_out_ippa + iml_len_ip_header + 0))) {
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }
#endif
// 28.08.12 KB - alignment
   if (memcmp( chrs_port_dns,
               achl_out_ippa + iml_len_ip_header + iml_udp_pos_port,
               sizeof(unsigned short int) )) {
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }

   p_check_dns_20:                          /* this is UDP DNS packet  */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T packet iml_len_nhasn=%d iml_len_packet=%d UDP DNS query found 1.",
                 __LINE__, iml_len_nhasn, iml_len_packet );
#endif
#ifdef TRACEHL_DNS
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T time=%lld packet iml_len_nhasn=%d iml_len_packet=%d UDP DNS query found 1.",
                 __LINE__, m_get_epoch_ms(), iml_len_nhasn, iml_len_packet );
   m_dump_gather( &dsl_sdh_call_1, adsl_gai1_inp_start, iml_len_nhasn + iml_len_packet );
#endif
   if (adsp_hl_clib_1->inc_func == DEF_IFUNC_FROMSERVER) {
     goto p_copy_00;                        /* copy the packet         */
   }
   /* check if DNS name as requested                                   */
#ifdef B101204
   if (iml_len_packet < (2 + iml_len_ip_header + D_LEN_UDP_HEADER
                           + 2 + sizeof(chrs_dns_query_1) + 2 + sizeof(chrs_dns_query_2))) {  /* packet too short */
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }
#endif
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   if (iml_len_packet < (1 + iml_len_ip_header + D_LEN_UDP_HEADER
                           + 2 + sizeof(chrs_dns_query_1) + 2 + sizeof(chrs_dns_query_2))) {  /* packet too short */
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }
#else
   if (iml_len_packet < (iml_len_ip_header + D_LEN_UDP_HEADER
                           + 2 + sizeof(chrs_dns_query_1) + 2 + sizeof(chrs_dns_query_2))) {  /* packet too short */
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }
#endif
   iml1 = D_LEN_DNS_ID;                     /* we need two bytes, id of DNS query */

   p_name_dns_20:                           /* overread part before start of UDP packet after ID */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( chrl_work2 + D_LEN_DNS_ID - iml1, achl_packet, iml2 );
   achl_packet += iml2;
   iml1 -= iml2;
   if (iml1) goto p_name_dns_20;            /* overread part before start of UDP packet after ID */
   /* copy part 1                                                      */
   iml1 = sizeof(chrs_dns_query_1);         /* copy part 1             */
   achl1 = chrl_work1;                      /* output area             */

   p_name_dns_40:                           /* copy DNS control fields */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl1, achl_packet, iml2 );
   achl_packet += iml2;
   achl1 += iml2;
   iml1 -= iml2;
   if (iml1) goto p_name_dns_40;            /* copy DNS control fields */
   if (memcmp( chrl_work1, chrs_dns_query_1, sizeof(chrs_dns_query_1) )) {
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }
   /* get the DNS name                                                 */
   achl1 = achl2 = chrl_dns_name;           /* output DNS name         */

   p_name_dns_60:                           /* copy DNS name           */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   if (achl1 >= (chrl_dns_name + sizeof(chrl_dns_name))) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W p_name_dns_60 DNS name too long", __LINE__ );
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }
   *achl1 = *achl_packet++;                 /* get next byte           */
   if (achl1 < achl2) {                     /* not yet at end this part */
     achl1++;                               /* next output             */
     goto p_name_dns_60;                    /* copy DNS name           */
   }
   achl2 += 1 + (unsigned char) *achl1++;
   if (achl1 < achl2) {                     /* not yet at end this part */
     goto p_name_dns_60;                    /* copy DNS name           */
   }
   /* end of DNS name                                                  */
   iml_len_dns_n = achl1 - chrl_dns_name;   /* length DNS name         */
#ifdef B101204
   iml1 = iml_len_ip_header + 2 + sizeof(chrs_dns_query_1);  /* position in packet */
   if ((iml_len_packet - 2 - iml1) != sizeof(chrs_dns_query_2)) {
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }
#endif
#ifdef XYZ1
   iml1 = iml_len_packet - 1 - iml_len_ip_header
            - D_LEN_UDP_HEADER
            - 2 - sizeof(chrs_dns_query_1)
            - iml_len_dns_n
            - sizeof(chrs_dns_query_2);
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_name_dns_60 iml1=%d.", __LINE__, iml1 );
#endif
#ifdef XYZ1
// 04.12.10 KB UUUU
   if (iml_len_packet > 0) {
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }
#endif
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   if (iml_len_packet - 1 - iml_len_ip_header
        - D_LEN_UDP_HEADER
        - D_LEN_DNS_ID - sizeof(chrs_dns_query_1)
        - iml_len_dns_n
        - sizeof(chrs_dns_query_2)) {
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }
#else
   if (iml_len_packet - iml_len_ip_header
        - D_LEN_UDP_HEADER
        - 2 - sizeof(chrs_dns_query_1)
        - iml_len_dns_n
        - sizeof(chrs_dns_query_2)) {
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }
#endif
   /* copy part 2 of DNS query                                         */
   iml1 = sizeof(chrs_dns_query_2);         /* copy part 2             */
   achl1 = chrl_work1;                      /* output area             */
#ifdef B101204
   iml_pos_packet += iml1;                  /* position in packet      */
#endif

   p_name_dns_80:                           /* copy DNS query last part */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl1, achl_packet, iml2 );
   achl_packet += iml2;
   achl1 += iml2;
   iml1 -= iml2;
   if (iml1) goto p_name_dns_80;            /* copy DNS query last part */
   if (memcmp( chrl_work1, chrs_dns_query_2, sizeof(chrs_dns_query_2) )) {
     goto p_rem_packet_00;                  /* remaining part of packet in gather */
   }
#ifndef B130607
   if (ADSL_CLCO->imc_len_conf_ext_1 == 0) {   /* length of configuration extensions */
     goto p_copy_00;                        /* check what to do with packet */
   }
#endif
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T packet DNS query found iml_len_nhasn=%d iml_len_packet=%d iml_len_dns_n=%d.",
                 __LINE__, iml_len_nhasn, iml_len_packet, iml_len_dns_n );
#endif
   adsl_coe1_w1 = (struct dsd_conf_ext_1 *) (ADSL_CLCO + 1);
   achl1 = (char *) adsl_coe1_w1 + ADSL_CLCO->imc_len_conf_ext_1;  /* add length of configuration extensions */
   do {                                     /* loop over all configuration extensions */
#ifdef B110822
     achl2 = (char *) (adsl_coe1_w1 + 1);   /* displacement DNS name   */
     switch (adsl_coe1_w1->iec_coe) {       /* type of configuration extension */
       case ied_coe_dns_resp:               /* DNS resonse configured  */
         achl2 += sizeof(chrs_dns_r_i_1);
         break;
       case ied_coe_ftp_se:                 /* FTP server              */
         achl2 += adsl_coe1_w1->imc_no_ineta * sizeof(UNSIG_MED);
         break;
     }
#endif
     if (   (iml_len_dns_n == adsl_coe1_w1->imc_len_dns_n)
         && (adsl_coe1_w1->iec_coe != ied_coe_ftp_se)  /* not FTP server */
         && (!memcmp( chrl_dns_name, (char *) (adsl_coe1_w1 + 1) + sizeof(chrs_dns_r_i_1), iml_len_dns_n ))) {
       goto p_found_dns_name;               /* DNS name found          */
     }
     *((char **) &adsl_coe1_w1) += adsl_coe1_w1->imc_len_stor;  /* add storage reserved */
   } while (((char *) adsl_coe1_w1) < achl1);
#ifdef B120820
   goto p_copy_00;                          /* check what to do with packet */
#else
   if (ADSL_CLCO->boc_internal_dns_server == FALSE) {  /* use internal DNS server */
     goto p_copy_00;                        /* check what to do with packet */
   }
   adsl_coe1_w1 = NULL;                     /* configuration extension - exclude-DNS-name */
#endif

   p_found_dns_name:                        /* DNS name found          */
#ifdef B111123
#ifdef TRACEHL_DNS
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T time=%lld p_found_dns_name: adsl_contr_1->imc_no_qdnsr1 = %d.",
                 __LINE__, m_get_epoch_ms(), adsl_contr_1->imc_no_qdnsr1 );
#endif
#endif

   /* ignore till end of the packet                                    */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml1 = iml_len_nhasn + iml_len_packet;   /* ignore full packet      */
#else
   iml1 = iml_len_packet;                   /* ignore full packet      */
#endif

   p_found_dn_40:                           /* ignore remaining part of packet */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (adsl_gai1_inp_start->achc_ginp_cur >= adsl_gai1_inp_start->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_start == NULL) goto p_illogic_00;  /* program illogic */
   }
   iml2 = adsl_gai1_inp_start->achc_ginp_end - adsl_gai1_inp_start->achc_ginp_cur;
   if (iml2 > iml1) iml2 = iml1;
#ifdef B130216
   achl1 += iml2;
#endif
   adsl_gai1_inp_start->achc_ginp_cur += iml2;
   iml1 -= iml2;
   if (iml1) goto p_found_dn_40;            /* ignore remaining part of packet */

#ifndef B11116
   memcpy( chrl_work3, achl_out_ippa + iml_len_ip_header + 0, sizeof(unsigned short int) );  /* save UDP source port */
#endif
   if (adsl_coe1_w1 == NULL) {              /* configuration extension - exclude-DNS-name */
     goto p_excl_dns_00;                    /* exclude this DNS name   */
   }
   /* (sizeof(chrs_dns_r_s_3) + sizeof(UNSIG_MED)) are a multiple of sizeof(void *)
      so no problem with alignment                                     */
#ifdef B130212
   iml1 = iml2 = 0;                         /* no additional length    */
#else
   iml2 = 0;                                /* no additional length    */
#endif
   if (adsl_coe1_w1->iec_coe != ied_coe_socks_se) {  /* not Socks server */
     iml1 = adsl_coe1_w1->imc_no_ineta;     /* get number of INETAs    */
   } else {                                 /* Socks5 server           */
     iml1 = 1;                              /* one INETA               */
   }
   if (iml1 > 0) {                          /* with additional INETAs  */
     iml2 = sizeof(struct dsd_gather_i_1) + iml1 * (sizeof(chrs_dns_r_s_3) + sizeof(UNSIG_MED));
   }
   dsl_oa1.achc_upper -= 2 * sizeof(struct dsd_gather_i_1) + iml2;
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   achl1 = dsl_oa1.achc_lower + MAX_LEN_NHASN;  /* start of packet     */
   dsl_oa1.achc_lower += MAX_LEN_NHASN + 1 + D_LEN_HEADER_IPV4 + D_LEN_UDP_HEADER + D_LEN_DNS_ID;
#endif
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   achl1 = dsl_oa1.achc_lower;              /* start of packet         */
   dsl_oa1.achc_lower += D_LEN_HEADER_IPV4 + D_LEN_UDP_HEADER + D_LEN_DNS_ID;
#endif
   if (dsl_oa1.achc_lower > dsl_oa1.achc_upper) {  /* no space for output */
     if (bol_output == FALSE) goto p_out_80;  /* overflow              */
     adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
#ifdef CHECK_OUTPUT_01
     m_check_output_01( adsp_hl_clib_1 );
#endif
     return;                                /* to be called again      */
   }
#define ADSL_GAI1_GS ((struct dsd_gather_i_1 *) dsl_oa1.achc_upper)
#define ADSL_GAI1_G1 (((struct dsd_gather_i_1 *) dsl_oa1.achc_upper) + 1)
#define AUML_INETA_G ((UNSIG_MED *) (ADSL_GAI1_G2 + 1))
   ADSL_GAI1_GS->adsc_next = ADSL_GAI1_G1;
   ADSL_GAI1_G1->achc_ginp_cur = (char *) (adsl_coe1_w1 + 1);
   ADSL_GAI1_G1->achc_ginp_end = (char *) (adsl_coe1_w1 + 1) + adsl_coe1_w1->imc_len_entry;
   adsl_gai1_out_t1 = ADSL_GAI1_G1;         /* this is last gather     */
   if (iml1 > 0) {                          /* with additional INETAs  */
     adsl_gai1_out_t1->adsc_next = adsl_gai1_out_t1 + 1;  /* append at end of last gather */
     adsl_gai1_out_t1++;                    /* additinal gather        */
     adsl_gai1_out_t1->achc_ginp_cur = achl2 = (char *) (adsl_gai1_out_t1 + 1);
     adsl_gai1_out_t1->achc_ginp_end
       = achl2 + iml1 * (sizeof(chrs_dns_r_s_3) + sizeof(UNSIG_MED));
     if (adsl_coe1_w1->iec_coe != ied_coe_socks_se) {  /* not Socks server */
       iml2 = iml1;                         /* get number of INETAs    */
       achl3 = (char *) adsl_coe1_w1 + adsl_coe1_w1->imc_len_stor - iml1 * sizeof(UNSIG_MED);
       do {                                 /* loop over all INETAs    */
         memcpy( achl2, chrs_dns_r_s_3, sizeof(chrs_dns_r_s_3) );
         *((UNSIG_MED *) (achl2 + sizeof(chrs_dns_r_s_3)))
           = m_natted_ineta( adsp_hl_clib_1, achl3, NULL, ADSL_CLCO->boc_disp_inetas );
         achl2 += sizeof(chrs_dns_r_s_3) + sizeof(UNSIG_MED);
         achl3 += sizeof(UNSIG_MED);
         iml2--;                            /* decrement index         */
       } while (iml2 > 0);
     } else {
// to-do 21.08.11 KB INETA of Socks5 server
       memcpy( achl2, chrs_dns_r_s_3, sizeof(chrs_dns_r_s_3) );
       *((UNSIG_MED *) (achl2 + sizeof(chrs_dns_r_s_3))) = adsl_contr_1->umc_ineta_upper;
       m_ineta_op_add( achl2 + sizeof(chrs_dns_r_s_3),
                       sizeof(UNSIG_MED),
                       1 + adsl_coe1_w1->imc_index_so_ineta_nat );  /* index of reserved INETAs for Socks servers */
     }
   }
   adsl_gai1_out_t1->adsc_next = NULL;      /* end of this sequence    */
   achl2 = achl1;
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   *achl2++ = '4';                          /* PPP IPV4 data           */
#endif
   *achl2++ = (unsigned char) 0X45;         /* IPV4 and length         */
   *achl2++ = 0;                            /* Type of Service         */
   iml2 = D_LEN_HEADER_IPV4 + D_LEN_UDP_HEADER + D_LEN_DNS_ID + adsl_coe1_w1->imc_len_entry
            + iml1 * (sizeof(chrs_dns_r_s_3) + sizeof(UNSIG_MED));
   *achl2++ = (unsigned char) (iml2 >> 8);  /* first part Total Length */
   *achl2++ = (unsigned char) iml2;         /* second part Total Length */
   *achl2++ = (unsigned char) 0X01;         /* first part Identification */
   *achl2++ = (unsigned char) 0X6A;         /* second part Identification */
   *achl2++ = 0;                            /* Flags + first part Fragment Offset */
   *achl2++ = 0;                            /* second part Fragment Offset */
   *achl2++ = (unsigned char) 0X80;         /* Time to live            */
   *achl2++ = (unsigned char) IPPROTO_UDP;  /* Protocol UDP            */
   *achl2++ = 0;                            /* first part Header checksum */
   *achl2++ = 0;                            /* second part Header checksum */
   memcpy( achl2, &uml_ineta_dns, sizeof(UNSIG_MED) );
   achl2 += sizeof(UNSIG_MED);
   memcpy( achl2, &adsl_contr_1->umc_ineta_client, sizeof(UNSIG_MED) );
   achl2 += sizeof(UNSIG_MED);
#ifdef TRACEHL_DNS
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T time=%lld send DNS response part one",
                 __LINE__, m_get_epoch_ms() );
   m_sdh_console_out( &dsl_sdh_call_1, achl1, achl2 - achl1 );
#endif
   /* calculate header checksum                                        */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   achl3 = achl1 + 1;                       /* here is start IP header */
#else
   achl3 = achl1;                           /* here is start IP header */
#endif
   iml_chs = 0;                             /* calculate checksum      */
   do {                                     /* loop over IP header     */
     /* calculate checksum                                             */
     iml_chs += (*((unsigned char *) achl3 + 0) << 8)
                  | *((unsigned char *) achl3 + 1);
     achl3 += 2;                            /* next position in header */
   } while (achl3 < achl2);
   while ((iml_chs >> 16) != 0) {           /* continue carry          */
     iml_chs = (iml_chs & 0X0000FFFF) + (iml_chs >> 16);
   }
   iml_chs = ~iml_chs;                      /* negate result           */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   *((unsigned char *) achl1 + 1 + D_POS_IPH_DCHS + 0) = (unsigned char) (iml_chs >> 8);
   *((unsigned char *) achl1 + 1 + D_POS_IPH_DCHS + 1) = (unsigned char) iml_chs;
#else
   *((unsigned char *) achl1 + D_POS_IPH_DCHS + 0) = (unsigned char) (iml_chs >> 8);
   *((unsigned char *) achl1 + D_POS_IPH_DCHS + 1) = (unsigned char) iml_chs;
#endif
   /* build UDP header                                                 */
   memcpy( achl2, chrs_port_dns, sizeof(chrs_port_dns) );
   achl2 += sizeof(chrs_port_dns);
#ifdef B11116
   memcpy( achl2, achl_out_ippa + iml_len_ip_header + 0, sizeof(unsigned short int) );
#else
   memcpy( achl2, chrl_work3, sizeof(unsigned short int) );  /* set UDP destination port */
#endif
   achl2 += sizeof(unsigned short int);
   iml2 = D_LEN_UDP_HEADER + D_LEN_DNS_ID + adsl_coe1_w1->imc_len_entry
            + iml1 * (sizeof(chrs_dns_r_s_3) + sizeof(UNSIG_MED));
   *achl2++ = (unsigned char) (iml2 >> 8);  /* first part Length UDP packet */
   *achl2++ = (unsigned char) iml2;         /* second part Length UDP packet */
   *achl2++ = 0;                            /* first part checksum     */
   *achl2++ = 0;                            /* second part checksum    */
   memcpy( achl2, chrl_work2, D_LEN_DNS_ID );
   achl2 += D_LEN_DNS_ID;
   /* calculate UDP checksum                                           */
   iml_chs = 0;                             /* calculate checksum      */
   do {                                     /* loop over data          */
     /* calculate checksum                                             */
     iml_chs += (*((unsigned char *) achl3 + 0) << 8)
                  | *((unsigned char *) achl3 + 1);
     achl3 += 2;                            /* next position in data   */
   } while (achl3 < achl2);
   /* checksum over constant part                                      */
   achl3 = (char *) (adsl_coe1_w1 + 1);
   achl2 = achl3 + adsl_coe1_w1->imc_len_entry - 1;
   do {                                     /* loop over data          */
     /* calculate checksum                                             */
     iml_chs += (*((unsigned char *) achl3 + 0) << 8)
                  | *((unsigned char *) achl3 + 1);
     achl3 += 2;                            /* next position in data   */
   } while (achl3 < achl2);
   if (adsl_coe1_w1->imc_len_entry & 1) {   /* one byte remaining      */
     iml_chs += *((unsigned char *) achl3 + 0) << 8;
     if (iml1 > 0) {                        /* additional area with INETAs */
       achl2 = adsl_gai1_out_t1->achc_ginp_cur;
       achl3 = adsl_gai1_out_t1->achc_ginp_end;
       do {
         iml_chs += *((unsigned char *) achl2 + 0);
         iml_chs += *((unsigned char *) achl2 + 1) << 8;
         achl2 += 2;
       } while (achl2 < achl3);
     }
   } else {
     if (iml1 > 0) {                        /* additional area with INETAs */
       achl2 = adsl_gai1_out_t1->achc_ginp_cur;
       achl3 = adsl_gai1_out_t1->achc_ginp_end;
       do {
         iml_chs += *((unsigned char *) achl2 + 0) << 8;
         iml_chs += *((unsigned char *) achl2 + 1);
         achl2 += 2;
       } while (achl2 < achl3);
     }
   }
   /* fields in the IP header                                          */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   achl2 = achl1 + 1 + 12;                  /* start source address    */
#else
   achl2 = achl1 + 12;                      /* start source address    */
#endif
   achl3 = achl2 + 4 + 4;                   /* after destination address */
   do {                                     /* loop over data          */
     /* calculate checksum                                             */
     iml_chs += (*((unsigned char *) achl2 + 0) << 8)
                  | *((unsigned char *) achl2 + 1);
     achl2 += 2;                            /* next position in data   */
   } while (achl2 < achl3);
   iml_chs += ((unsigned char) IPPROTO_UDP) + D_LEN_UDP_HEADER + D_LEN_DNS_ID + adsl_coe1_w1->imc_len_entry
                + iml1 * (sizeof(chrs_dns_r_s_3) + sizeof(UNSIG_MED));
   while ((iml_chs >> 16) != 0) {           /* continue carry          */
     iml_chs = (iml_chs & 0X0000FFFF) + (iml_chs >> 16);
   }
   iml_chs = ~iml_chs;                      /* negate result           */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   *((unsigned char *) achl1 + 1 + D_LEN_HEADER_IPV4 + 6 + 0) = (unsigned char) (iml_chs >> 8);
   *((unsigned char *) achl1 + 1 + D_LEN_HEADER_IPV4 + 6 + 1) = (unsigned char) iml_chs;
#else
   *((unsigned char *) achl1 + D_LEN_HEADER_IPV4 + 6 + 0) = (unsigned char) (iml_chs >> 8);
   *((unsigned char *) achl1 + D_LEN_HEADER_IPV4 + 6 + 1) = (unsigned char) iml_chs;
#endif
   /* packet has been prepared                                         */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml1 = (dsl_oa1.achc_lower - achl1) + adsl_coe1_w1->imc_len_entry  /* length of packet */
            + iml1 * (sizeof(chrs_dns_r_s_3) + sizeof(UNSIG_MED));
   iml2 = 0;                                /* clear more bit          */
   do {
     *(--achl1) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* remove bits             */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
#endif
   ADSL_GAI1_GS->achc_ginp_cur = achl1;
   ADSL_GAI1_GS->achc_ginp_end = dsl_oa1.achc_lower;
#ifdef TRACEHL1
   iml1 = (dsl_oa1.achc_lower - achl1) + adsl_coe1_w1->imc_len_entry;  /* length of packet */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T DNS response packet len=%d.",
                 __LINE__, iml1 );
   m_dump_gather( &dsl_sdh_call_1, ADSL_GAI1_GS, iml1 );
#endif
#ifdef TRACEHL_DNS
   iml1 = (dsl_oa1.achc_lower - achl1) + adsl_coe1_w1->imc_len_entry;  /* length of packet */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T time=%lld DNS response packet len=%d.",
                 __LINE__, m_get_epoch_ms(), iml1 );
   m_dump_gather( &dsl_sdh_call_1, ADSL_GAI1_GS, iml1 );
#endif
//-----------------------
// to-do 20.08.11 KB - append to output to client chain [0]
   bol_output = TRUE;                       /* output has been done    */
   *aadsrl_gai1_out[ 0 ] = ADSL_GAI1_GS;
   aadsrl_gai1_out[ 0 ] = &adsl_gai1_out_t1->adsc_next;
   goto p_check_recv_00;                    /* check received packet   */

#undef ADSL_GAI1_GS
#undef ADSL_GAI1_G1

   p_excl_dns_00:                           /* exclude this DNS name   */
   goto p_check_recv_00;                    /* check received packet   */

   p_rem_packet_00:                         /* remaining part of packet in gather */
   adsl_gai1_out_t2 = adsl_gai1_out_t1;     /* this is output gather   */
   adsl_gai1_inp_w1 = adsl_gai1_inp_start;  /* here is first gather    */
   achl_packet = adsl_gai1_inp_w1->achc_ginp_cur;  /* here is current input */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml1 = iml_len_nhasn + 1 + (achl_out_end - achl_out_ippa);  /* overread this part */
#endif
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml1 = achl_out_end - achl_out_ippa;     /* overread this part */
#endif

   p_rem_packet_20:                         /* overread first part of packet */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_w1->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_w1 = adsl_gai1_inp_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_w1 == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_w1->achc_ginp_cur;  /* here is current input */
   }
   iml2 = adsl_gai1_inp_w1->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   achl_packet += iml2;
   iml1 -= iml2;
   if (iml1) goto p_rem_packet_20;          /* overread first part of packet */

   /* the remaining parts of the record are put into gather structures for output */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml1 = iml_len_packet - (1 + achl_out_end - achl_out_ippa);  /* length remaining part */
#endif
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml1 = iml_len_packet - (achl_out_end - achl_out_ippa);  /* length remaining part */
#endif
   if (iml1 <= 0) goto p_rem_packet_60;     /* all output has been done */

   p_rem_packet_40:                         /* put following parts of packet in gather output */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   adsl_gai1_out_t2--;                      /* gather before           */
   if (achl_out_end > ((char *) adsl_gai1_out_t2)) {  /* no space for output */
     if (bol_output == FALSE) goto p_out_80;  /* overflow              */
     adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
#ifdef CHECK_OUTPUT_01
     m_check_output_01( adsp_hl_clib_1 );
#endif
     return;                                /* to be called again      */
   }
   (adsl_gai1_out_t2 + 1)->adsc_next = adsl_gai1_out_t2;  /* append gather output */
   while (achl_packet >= adsl_gai1_inp_w1->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_w1 = adsl_gai1_inp_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_w1 == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_w1->achc_ginp_cur;  /* here is current input */
   }
   iml2 = adsl_gai1_inp_w1->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   adsl_gai1_out_t2->achc_ginp_cur = achl_packet;  /* start of output this part */
   achl_packet += iml2;
   adsl_gai1_out_t2->achc_ginp_end = achl_packet;  /* end of output this part */
#ifdef DEBUG_101208_01
   iml_d2 = adsl_gai1_out_t2->achc_ginp_end - adsl_gai1_out_t2->achc_ginp_cur;
   iml_d1 = sprintf( achl_display, "l%05d gather=%p cur=%p end=%p len=%d/0X%p.",
                     __LINE__,
                     adsl_gai1_out_t2,
                     adsl_gai1_out_t2->achc_ginp_cur, adsl_gai1_out_t2->achc_ginp_end,
                     iml_d2, iml_d2 );
   achl_display += iml_d1;
   iml_d2 = D_LEN_LINE_M1 - iml_d1;
   if (iml_d2 > 0) {
     memset( achl_display, ' ', iml_d2 );
     achl_display += iml_d2;
   }
#endif
   iml1 -= iml2;
#ifdef B101208
   if (iml1) goto p_rem_packet_20;          /* overread first part of packet */
#else
   if (iml1) goto p_rem_packet_40;          /* put following parts of packet in gather output */
#endif

   p_rem_packet_60:                         /* all output has been done */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   /* prepare HOB-PPP-T1 header                                        */
   achl1 = achl_out_ippa;                   /* here is IP packet       */
   *(--achl1) = '4';                        /* type IPV4               */
   iml1 = iml_len_packet;                   /* length of packet        */
   iml2 = 0;                                /* clear more bit          */
   do {
     *(--achl1) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* remove bits set         */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
   /* use gather structure prepared before                             */
   adsl_gai1_out_t1->achc_ginp_cur = achl1;
#endif
#ifdef DEBUG_101208_01
   iml_d1 = sprintf( achl_display, "l%05d gather=%p cur=%p end=%p.",
                     __LINE__, adsl_gai1_out_t1, adsl_gai1_out_t1->achc_ginp_cur, adsl_gai1_out_t1->achc_ginp_end );
   achl_display += iml_d1;
   iml_d2 = D_LEN_LINE_M1 - iml_d1;
   if (iml_d2 > 0) {
     memset( achl_display, ' ', iml_d2 );
     achl_display += iml_d2;
   }
#endif
   adsl_gai1_out_t2->adsc_next = NULL;      /* end of this part        */
   dsl_oa1.achc_lower = achl_out_end;       /* workarea used till here */
   dsl_oa1.achc_upper = (char *) adsl_gai1_out_t2;  /* new upper limit */
   *aadsrl_gai1_out[ iml_dir_oth ] = adsl_gai1_out_t1;
   aadsrl_gai1_out[ iml_dir_oth ] = &adsl_gai1_out_t2->adsc_next;
   bol_output = TRUE;                       /* output has been done    */
   /* remove the input data                                            */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml1 = iml_len_nhasn + iml_len_packet;   /* length of data to be removed */
#endif
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml1 = iml_len_packet;                   /* length of data to be removed */
#endif
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   do {                                     /* loop to remove the data */
     while (adsl_gai1_inp_start->achc_ginp_cur >= adsl_gai1_inp_start->achc_ginp_end) {  /* end of gather */
       adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;  /* get next gather in chain */
       if (adsl_gai1_inp_start == NULL) goto p_illogic_00;  /* program illogic */
     }
     iml2 = adsl_gai1_inp_start->achc_ginp_end - adsl_gai1_inp_start->achc_ginp_cur;
     if (iml2 > iml1) iml2 = iml1;
     adsl_gai1_inp_start->achc_ginp_cur += iml2;
     iml1 -= iml2;
   } while (iml1 > 0);
   achl_inp = adsl_gai1_inp_start->achc_ginp_cur;  /* start input data */
   /* calculate checksum of IP-header                                  */
   /* clear old checksum                                               */
   *((unsigned char *) achl_out_ippa + D_POS_IPH_DCHS + 0) = 0;
   *((unsigned char *) achl_out_ippa + D_POS_IPH_DCHS + 1) = 0;
   achl1 = achl_out_ippa;                   /* start of IP header      */
   achl2 = achl1 + iml_len_ip_header;       /* end of IP header        */
   iml_chs = 0;                             /* calculate checksum      */
   do {                                     /* loop over IP header     */
     /* calculate checksum                                             */
     iml_chs += (*((unsigned char *) achl1 + 0) << 8)
                  | *((unsigned char *) achl1 + 1);
     achl1 += 2;                            /* next position in header */
   } while (achl1 < achl2);
   while ((iml_chs >> 16) != 0) {           /* continue carry          */
     iml_chs = (iml_chs & 0X0000FFFF) + (iml_chs >> 16);
   }
   iml_chs = ~iml_chs;                      /* negate result           */
   *((unsigned char *) achl_out_ippa + D_POS_IPH_DCHS + 0) = (unsigned char) (iml_chs >> 8);
   *((unsigned char *) achl_out_ippa + D_POS_IPH_DCHS + 1) = (unsigned char) iml_chs;
   /* check UDP header                                                 */
#ifndef TRY_101205
   if (CHL_PROTOCOL != IPPROTO_UDP) {       /* protocol not UDP from IP header */
     goto p_check_recv_00;                  /* no new checksum needed  */
   }
#else
   if ((CHL_PROTOCOL & 0X0F) != (IPPROTO_UDP & 0X0F)) {  /* protocol not UDP from IP header */
     goto p_check_recv_00;                  /* no new checksum needed  */
   }
#endif
   achl3 = achl_out_ippa + iml_len_ip_header + 6;
   /* clear old checksum                                               */
   *(achl3 + 0) = 0;
   *(achl3 + 1) = 0;
   iml_chs = 0;                             /* calculate checksum      */
   achl1 = achl_out_ippa + iml_len_ip_header;  /* start of TCP / UDP header */
   achl2 = achl_out_end;                    /* end of header           */
   do {                                     /* loop over header        */
     /* calculate checksum                                             */
     iml_chs += (*((unsigned char *) achl1 + 0) << 8)
                  | *((unsigned char *) achl1 + 1);
     achl1 += 2;                            /* next position in header */
   } while (achl1 < achl2);
   iml1 = 8;                                /* do shift bits           */
   adsl_gai1_inp_w1 = adsl_gai1_out_t1 - 1;  /* here is first part output */
   while (adsl_gai1_inp_w1 >= adsl_gai1_out_t2) {  /* loop over all gather output */
     achl1 = adsl_gai1_inp_w1->achc_ginp_cur;
     while (achl1 < adsl_gai1_inp_w1->achc_ginp_end) {
       iml_chs += *((unsigned char *) achl1) << iml1;
       iml1 ^= 8;
       achl1++;                             /* next character          */
     }
     adsl_gai1_inp_w1--;                    /* next gather before      */
   }
   /* fields in the IP header                                          */
   achl1 = achl_out_ippa + 12;              /* start source address    */
   achl2 = achl1 + 4 + 4;                   /* after destination address */
   do {                                     /* loop over data          */
     /* calculate checksum                                             */
     iml_chs += (*((unsigned char *) achl1 + 0) << 8)
                  | *((unsigned char *) achl1 + 1);
     achl1 += 2;                            /* next position in data   */
   } while (achl1 < achl2);
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml_chs += ((unsigned char) CHL_PROTOCOL) + iml_len_packet - (1 + iml_len_ip_header);
#endif
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml_chs += ((unsigned char) CHL_PROTOCOL) + iml_len_packet - iml_len_ip_header;
#endif
   while ((iml_chs >> 16) != 0) {           /* continue carry          */
     iml_chs = (iml_chs & 0X0000FFFF) + (iml_chs >> 16);
   }
   iml_chs = ~iml_chs;                      /* negate result           */
   *(achl3 + 0) = (unsigned char) (iml_chs >> 8);
   *(achl3 + 1) = (unsigned char) iml_chs;
   goto p_check_recv_00;                    /* all done                */

   p_copy_00:                               /* copy the packet         */
   /* the remaining parts of the record are put into the output area   */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml1 = iml_len_packet - 1 - (achl_out_end - achl_out_ippa);  /* length to copy */
#else
   iml1 = iml_len_packet - (achl_out_end - achl_out_ippa);  /* length to copy */
#endif
   dsl_oa1.achc_lower = achl_out_end + iml1;       /* here is space for the packet */
   dsl_oa1.achc_upper = (char *) adsl_gai1_out_t1;
   iml2 = 0;                                /* nothing extra           */
   if (achl_sip_packet) {                   /* is SIP packet           */
     iml2 = D_EXT_SIP;                      /* something extra         */
   }
   if (dsl_oa1.achc_upper < (dsl_oa1.achc_lower + iml2)) {  /* work-area too small */
     if (bol_output == FALSE) goto p_out_80;  /* overflow              */
     adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
#ifdef CHECK_OUTPUT_01
     m_check_output_01( adsp_hl_clib_1 );
#endif
     return;                                /* to be called again      */
   }
   bol_output = TRUE;                       /* output has been done    */
   adsl_gai1_out_t1->adsc_next = NULL;
   adsl_gai1_out_t1->achc_ginp_end = dsl_oa1.achc_lower;
#ifdef DEBUG_101208_01
   iml_d1 = sprintf( achl_display, "l%05d gather=%p cur=%p end=%p.",
                     __LINE__, adsl_gai1_out_t1, adsl_gai1_out_t1->achc_ginp_cur, adsl_gai1_out_t1->achc_ginp_end );
   achl_display += iml_d1;
   iml_d2 = D_LEN_LINE_M1 - iml_d1;
   if (iml_d2 > 0) {
     memset( achl_display, ' ', iml_d2 );
     achl_display += iml_d2;
   }
#endif
   *aadsrl_gai1_out[ iml_dir_oth ] = adsl_gai1_out_t1;
   aadsrl_gai1_out[ iml_dir_oth ] = &adsl_gai1_out_t1->adsc_next;

   if (achl_sip_packet) goto p_copy_84;     /* is SIP packet           */

#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml3 = iml_len_nhasn + 1 + (achl_out_end - achl_out_ippa);  /* overread this part */
#endif
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml3 = achl_out_end - achl_out_ippa;     /* overread this part      */
#endif

   p_copy_20:                               /* overread first part of packet */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
#ifdef B110709
   while (adsl_gai1_inp_start->achc_ginp_cur >= adsl_gai1_inp_w1->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_start == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_w1->achc_ginp_cur;  /* here is current input */
   }
   iml2 = adsl_gai1_inp_w1->achc_ginp_end - adsl_gai1_inp_start->achc_ginp_cur;
#else
   while (adsl_gai1_inp_start->achc_ginp_cur >= adsl_gai1_inp_start->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_start == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_w1->achc_ginp_cur;  /* here is current input */
   }
   iml2 = adsl_gai1_inp_start->achc_ginp_end - adsl_gai1_inp_start->achc_ginp_cur;
#endif
   if (iml2 > iml3) iml2 = iml3;
   adsl_gai1_inp_start->achc_ginp_cur += iml2;
   iml3 -= iml2;
   if (iml3) goto p_copy_20;                /* overread first part of packet */

   p_copy_40:                               /* copy part of the packet */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (adsl_gai1_inp_start->achc_ginp_cur >= adsl_gai1_inp_start->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_start == NULL) goto p_illogic_00;  /* program illogic */
   }
   iml2 = adsl_gai1_inp_start->achc_ginp_end - adsl_gai1_inp_start->achc_ginp_cur;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl_out_end, adsl_gai1_inp_start->achc_ginp_cur, iml2 );
   achl_out_end += iml2;
   adsl_gai1_inp_start->achc_ginp_cur += iml2;
   iml1 -= iml2;
   if (iml1) goto p_copy_40;                /* copy part of the packet */

   /* calculate checksum of IP-header                                  */
   /* clear old checksum                                               */
   *((unsigned char *) achl_out_ippa + D_POS_IPH_DCHS + 0) = 0;
   *((unsigned char *) achl_out_ippa + D_POS_IPH_DCHS + 1) = 0;
   achl1 = achl_out_ippa;                   /* start of IP header      */
   achl2 = achl1 + iml_len_ip_header;       /* end of IP header        */
   iml_chs = 0;                             /* calculate checksum      */
   do {                                     /* loop over IP header     */
     /* calculate checksum                                             */
     iml_chs += (*((unsigned char *) achl1 + 0) << 8)
                  | *((unsigned char *) achl1 + 1);
     achl1 += 2;                            /* next position in header */
   } while (achl1 < achl2);
   while ((iml_chs >> 16) != 0) {           /* continue carry          */
     iml_chs = (iml_chs & 0X0000FFFF) + (iml_chs >> 16);
   }
   iml_chs = ~iml_chs;                      /* negate result           */
   *((unsigned char *) achl_out_ippa + D_POS_IPH_DCHS + 0) = (unsigned char) (iml_chs >> 8);
   *((unsigned char *) achl_out_ippa + D_POS_IPH_DCHS + 1) = (unsigned char) iml_chs;
   if (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER) {
     goto p_copy_80;                        /* end of packet change    */
   }
#ifndef TRY_101205
   if (CHL_PROTOCOL != IPPROTO_UDP) {       /* protocol from IP header */
     goto p_copy_80;                        /* end of packet change    */
   }
#else
   if ((CHL_PROTOCOL & 0X0F) != (IPPROTO_UDP & 0X0F)) {  /* protocol from IP header */
     goto p_copy_80;                        /* end of packet change    */
   }
#endif
   if (memcmp( achl_out_ippa + iml_len_ip_header + 0, chrs_port_dns, 2 )) {
     goto p_copy_80;                        /* end of packet change    */
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T packet iml_len_nhasn=%d iml_len_packet=%d UDP DNS query found 2.",
                 __LINE__, iml_len_nhasn, iml_len_packet );
#endif
   /* check if response                                                */
   if ((*(achl_out_ippa + iml_len_ip_header + D_LEN_UDP_HEADER + D_LEN_DNS_ID) & 0X80) == 0) {
     goto p_copy_80;                        /* end of packet change    */
   }
   /* check RCODE                                                      */
   if ((*(achl_out_ippa + iml_len_ip_header + D_LEN_UDP_HEADER + D_LEN_DNS_ID + 1) & 0X0F) != 0) {
     goto p_copy_80;                        /* end of packet change    */
   }
   /* get QDCOUNT                                                      */
   iml1 = (*((unsigned char *) achl_out_ippa + iml_len_ip_header + D_LEN_UDP_HEADER + D_LEN_DNS_ID + 2 + 0) << 8)
            | *((unsigned char *) achl_out_ippa + iml_len_ip_header + D_LEN_UDP_HEADER + D_LEN_DNS_ID + 2 + 1);
#ifdef B111021
   /* get ANCOUNT                                                      */
   iml2 = (*((unsigned char *) achl_out_ippa + iml_len_ip_header + D_LEN_UDP_HEADER + D_LEN_DNS_ID + 4 + 0) << 8)
            | *((unsigned char *) achl_out_ippa + iml_len_ip_header + D_LEN_UDP_HEADER + D_LEN_DNS_ID + 4 + 1);
#else
   /* get ANCOUNT + NSCOUNT + ARCOUNT                                  */
   iml2 = ((*((unsigned char *) achl_out_ippa + iml_len_ip_header + D_LEN_UDP_HEADER + D_LEN_DNS_ID + 4 + 0) << 8)
             | *((unsigned char *) achl_out_ippa + iml_len_ip_header + D_LEN_UDP_HEADER + D_LEN_DNS_ID + 4 + 1))
            + ((*((unsigned char *) achl_out_ippa + iml_len_ip_header + D_LEN_UDP_HEADER + D_LEN_DNS_ID + 6 + 0) << 8)
                 | *((unsigned char *) achl_out_ippa + iml_len_ip_header + D_LEN_UDP_HEADER + D_LEN_DNS_ID + 6 + 1))
            + ((*((unsigned char *) achl_out_ippa + iml_len_ip_header + D_LEN_UDP_HEADER + D_LEN_DNS_ID + 8 + 0) << 8)
                 | *((unsigned char *) achl_out_ippa + iml_len_ip_header + D_LEN_UDP_HEADER + D_LEN_DNS_ID + 8 + 1));
#endif
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T packet UDP DNS query found 3 iml1=%d iml2=%d.",
                 __LINE__, iml1, iml2 );
#endif
   achl1 = achl_out_ippa + iml_len_ip_header + D_LEN_UDP_HEADER + 12;  /* here starts question section */
#ifdef B111021
   achl_dns_name = NULL;                    /* address of DNS name     */
#endif
   while (iml1 > 0) {                       /* loop over all questions */
#ifdef B111021
     if (achl_dns_name == NULL) {           /* address of DNS name not yet set */
       achl_dns_name = achl1;               /* set address of DNS name */
       iml_len_dns_n = -1;                  /* length DNS name         */
     }
#endif
     while (TRUE) {                         /* loop over elements of name */
       if (achl1 > dsl_oa1.achc_lower) goto p_copy_80;  /* after end of record */
       iml3 = *((unsigned char *) achl1);
       if (iml3 >= 64) {                    /* compression used        */
         achl1 += 2;                        /* after compression index */
         break;                             /* all done                */
       }
       achl1 += 1 + iml3;
       if (iml3 == 0) break;
     }
#ifdef B111021
     if (iml_len_dns_n < 0) {               /* length DNS name not yet set */
       iml_len_dns_n = achl1 - achl_dns_name;  /* set length DNS name  */
     }
#endif
     achl1 += 4;                            /* ignore QTYPE and QCLASS */
     iml1--;                                /* this question has been processed */
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T DNS query iml2=%d achl_packet=%p achl1=%p.",
                 __LINE__, iml2, achl_packet, achl1 );
#endif
#ifdef B111021
   if (ADSL_CLCO->boc_use_ftp == FALSE) {   /* no use ALG for FTP, FTP server configured */
     achl_dns_name = NULL;                  /* address of DNS name     */
   }
#endif
#ifndef B111021
   iml_len_dns_n = 0;                       /* length DNS name         */
#endif
   while (iml2 > 0) {                       /* loop over all resource records */
#ifdef B111021
     while (TRUE) {                         /* loop over elements of name */
       if (achl1 > dsl_oa1.achc_lower) goto p_copy_80;  /* after end of record */
       iml3 = *((unsigned char *) achl1);
       if (iml3 >= 64) {                    /* compression used        */
         achl1 += 2;                        /* after compression index */
         break;                             /* all done                */
       }
       achl1 += 1 + iml3;
       if (iml3 == 0) break;
     }
#endif
#ifndef B111021
     achl2 = chrl_dns_name;                 /* output DNS name         */
     achl3 = achl1;                         /* begin of source DNS name */
     iml4 = 16;                             /* maximum number of compression redirect */
     while (TRUE) {                         /* loop over elements of name */
       if (achl3 > dsl_oa1.achc_lower) goto p_copy_80;  /* after end of record */
       iml3 = *((unsigned char *) achl3);
       if ((iml3 & 0XC0) == 0XC0) {         /* compression used        */
         if ((achl3 + 2) > dsl_oa1.achc_lower) goto p_copy_80;  /* after end of record */
         iml4--;                            /* maximum number of compression redirect */
         if (iml4 <= 0) goto p_copy_80;     /* record invalid          */
         if (achl1 == achl3) {              /* still in original part  */
           achl1 += 2;                      /* after compression index */
         }
         achl3 = achl_out_ippa + iml_len_ip_header + D_LEN_UDP_HEADER
                   + *((unsigned char *) achl3 + 1)
                   + ((iml3 & 0X3F) << 8);
       } else {                             /* normal encoding         */
         if (iml3 & 0XC0) goto p_copy_80;   /* record invalid          */
         if ((achl2 + 1 + iml3) > (chrl_dns_name + sizeof(chrl_dns_name))) {  /* to long for target */
           goto p_copy_80;                  /* ignore this record      */
         }
         if (achl1 == achl3) {              /* still in original part  */
           achl1 += 1 + iml3;
         }
         memcpy( achl2, achl3, 1 + iml3 );  /* copy part of input      */
         achl2 += 1 + iml3;
         if (iml3 == 0) {                   /* end of DNS name         */
           if (ADSL_CLCO->boc_use_ftp == FALSE) break;  /* no use ALG for FTP, FTP server configured */
           iml_len_dns_n = achl2 - chrl_dns_name;  /* length DNS name  */
           break;                           /* all done                */
         }
         achl3 += 1 + iml3;
       }
     }
#endif
     iml_type = (*((unsigned char *) achl1 + 0 + 0) << 8)
                  | *((unsigned char *) achl1 + 0 + 1);
     iml_class = (*((unsigned char *) achl1 + 2 + 0) << 8)
                  | *((unsigned char *) achl1 + 2 + 1);
     iml3 = (*((unsigned char *) achl1 + 8 + 0) << 8)
              | *((unsigned char *) achl1 + 8 + 1);
     achl2 = achl1 + 10;
     achl1 += 10 + iml3;                    /* after this RR           */
     if (achl1 > dsl_oa1.achc_lower) goto p_copy_80;  /* after end of record  */
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T DNS query iml2=%d achl_packet=%p achl1=%p iml_type=%d iml_class=%d iml3=%d.",
                   __LINE__, iml2, achl_packet, achl1, iml_type, iml_class, iml3 );
#endif
     if (    (iml_type == 1)                /* A 1 a host address      */
          && (iml_class == 1)               /* IN 1 the Internet       */
          && (iml3 == 4)) {                 /* length INETA IPV4       */
       /* attention alignment                                          */
//     memcpy( &uml_ineta_w1, achl2, sizeof(UNSIG_MED) );
//     uml_ineta_w1 = m_natted_ineta( adsp_hl_clib_1, (char *) &uml_ineta_w1 );
       bol1 = FALSE;                        /* not yet INETA set       */
#ifdef B111021
       if (achl_dns_name) {                 /* address of DNS name set, check FTP */
         adsl_coe1_w1 = (struct dsd_conf_ext_1 *) (ADSL_CLCO + 1);
         achl3 = (char *) adsl_coe1_w1 + ADSL_CLCO->imc_len_conf_ext_1;  /* add length of configuration extensions */
         do {                               /* loop over all configuration extensions */
#ifdef DEBUG_110902_01
           achl4 = (char *) (adsl_coe1_w1 + 1);
#endif
           if (   (iml_len_dns_n == adsl_coe1_w1->imc_len_dns_n)
               && (adsl_coe1_w1->iec_coe == ied_coe_ftp_se)  /* FTP server */
               && (!memcmp( achl_dns_name, adsl_coe1_w1 + 1, iml_len_dns_n ))) {
             uml_ineta_w1 = m_natted_ineta( adsp_hl_clib_1, achl2, adsl_coe1_w1, ADSL_CLCO->boc_disp_inetas );
             bol1 = TRUE;                   /* INETA set               */
           }
           *((char **) &adsl_coe1_w1) += adsl_coe1_w1->imc_len_stor;  /* add storage reserved */
         } while (((char *) adsl_coe1_w1) < achl3);
       }
#endif
#ifndef B111021
#ifdef DEBUG_140730_01                      /* problems FTP            */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_hlclib01() DEBUG_140730_01 iml_len_dns_n=%d.",
                     __LINE__, iml_len_dns_n );
#endif
       if (iml_len_dns_n) {                 /* length of DNS name set, check FTP */
         adsl_coe1_w1 = (struct dsd_conf_ext_1 *) (ADSL_CLCO + 1);
         achl3 = (char *) adsl_coe1_w1 + ADSL_CLCO->imc_len_conf_ext_1;  /* add length of configuration extensions */
         do {                               /* loop over all configuration extensions */
#ifdef DEBUG_110902_01
           achl4 = (char *) (adsl_coe1_w1 + 1);
#endif
           if (   (iml_len_dns_n == adsl_coe1_w1->imc_len_dns_n)
               && (adsl_coe1_w1->iec_coe == ied_coe_ftp_se)  /* FTP server */
               && (!memcmp( chrl_dns_name, adsl_coe1_w1 + 1, iml_len_dns_n ))) {
             uml_ineta_w1 = m_natted_ineta( adsp_hl_clib_1, achl2, adsl_coe1_w1, ADSL_CLCO->boc_disp_inetas );
             bol1 = TRUE;                   /* INETA set               */
           }
           *((char **) &adsl_coe1_w1) += adsl_coe1_w1->imc_len_stor;  /* add storage reserved */
         } while (((char *) adsl_coe1_w1) < achl3);
       }
#endif
#ifdef DEBUG_140730_01                      /* problems FTP            */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_hlclib01() DEBUG_140730_01 bol1=%d.",
                     __LINE__, bol1 );
#endif
       if (bol1 == FALSE) {                 /* not yet INETA set       */
         uml_ineta_w1 = m_natted_ineta( adsp_hl_clib_1, achl2, NULL, ADSL_CLCO->boc_disp_inetas );
       }
       memcpy( achl2, &uml_ineta_w1, sizeof(UNSIG_MED) );
     }
     iml2--;                                /* this resource record has been processed */
   }

   p_copy_80:                               /* end of packet change    */
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   achl_inp = adsl_gai1_inp_start->achc_ginp_cur;  /* start input data */
#endif
   if (achl_sip_packet == NULL) {           /* not SIP packet          */
     goto p_copy_92;                        /* prepare HOB-PPP-T1 header */
   }

   p_copy_84:                               /* is SIP packet           */
   /* apply ALG SIP                                                    */
   achl1 = achl_sip_packet;                 /* start input to copy     */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   achl2 = achl_sip_packet + iml_len_packet - 1 - (achl_out_end - achl_out_ippa);  /* end input to copy */
#else
   achl2 = achl_sip_packet + iml_len_packet - (achl_out_end - achl_out_ippa);  /* end input to copy */
#endif
   achl3 = achl_out_end;                    /* start output of copy    */
   achl4 = achl_sip_packet;                 /* copied so far           */
   iml2 = 0;                                /* state CR LF             */
   achl5 = NULL;                            /* CR LF CR LF not found   */

   p_alg_sip_20:                            /* search invalid characters */
#ifdef B101022
   while ((achl1 < achl2) && (ucrs_tab_char_sip[ (unsigned char) *achl1 ] != 3)) achl1++;
#endif
   while (achl1 < achl2) {
     switch ((unsigned char) *achl1) {
       case CHAR_CR:
         if ((iml2 & 1) == 0) {
           iml2++;                          /* next state              */
           break;
         }
         iml2 = 1;                          /* CR found                */
         break;
       case CHAR_LF:
         if ((iml2 & 1) == 0) {             /* not CR before           */
           iml2 = 0;                        /* state CR LF             */
           break;
         }
         iml2++;                            /* next state              */
         if (iml2 < 4) break;               /* not CR LF CR LF         */
         achl5 = achl1 - 3;                 /* CR LF CR LF found       */
         achl5 += achl3 - achl4;            /* pointer to output area  */
#ifdef DEBUG_101207_01
         if (bos_debug_01) {
           m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T CR LF CR LF achl5=%p.",
                         __LINE__, achl5 );
         }
#endif
         break;
       default:
         iml2 = 0;                          /* state CR LF             */
         break;
     }
     if (ucrs_tab_char_sip[ (unsigned char) *achl1 ] == 3) break;
     achl1++;                               /* next character          */
   }
   if (achl1 >= achl2) goto p_alg_sip_60;   /* copy last part          */
   achl1++;                                 /* after separator         */
   if (ucrs_tab_char_sip[ (unsigned char) *achl1 ] != 1) goto p_alg_sip_20;  /* search invalid characters */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   iml1 = achl1 - achl4;                    /* get length input        */
   if ((achl3 + iml1) > dsl_oa1.achc_upper) goto p_illogic_00;  /* program illogic */
   memcpy( achl3, achl4, iml1 );            /* copy content            */
   achl3 += iml1;                           /* this is end packet      */
   achl4 = achl1;                           /* save start string       */
   while ((achl1 < achl2) && (ucrs_tab_char_sip[ (unsigned char) *achl1 ] <= 2)) achl1++;
   if ((achl1 < achl2) && (ucrs_tab_char_sip[ (unsigned char) *achl1 ] != 3)) {
     goto p_alg_sip_20;                     /* search invalid characters */
   }
   iml1 = m_get_ineta_a( &uml_ineta_w1, achl4, achl1 );
   if (iml1) goto p_alg_sip_20;             /* was not valid INETA     */
   if (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER) {
     uml_ineta_w1 = m_original_ineta( adsp_hl_clib_1, (char *) &uml_ineta_w1, &dsl_nrv );
   } else {
     uml_ineta_w1 = m_natted_ineta( adsp_hl_clib_1, (char *) &uml_ineta_w1, NULL, ADSL_CLCO->boc_disp_inetas );
   }
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
#ifdef B110701
   if ((achl3 + 15) > achl_work_2) goto p_illogic_00;  /* program illogic */
#else
   if ((achl3 + 15 + 1) > dsl_oa1.achc_upper) goto p_illogic_00;  /* program illogic */
#endif
   achl3 += sprintf( achl3, "%d.%d.%d.%d",
              *((unsigned char *) &uml_ineta_w1 + 0),
              *((unsigned char *) &uml_ineta_w1 + 1),
              *((unsigned char *) &uml_ineta_w1 + 2),
              *((unsigned char *) &uml_ineta_w1 + 3) );
   achl4 = achl1;                           /* input processed so far  */
   goto p_alg_sip_20;                       /* continue searching      */

   p_alg_sip_60:                            /* copy last part          */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   iml1 = achl1 - achl4;                    /* get length input        */
   if (iml1 > 0) {                          /* something to copy       */
     if ((achl3 + iml1) > dsl_oa1.achc_upper) goto p_illogic_00;  /* program illogic */
     memcpy( achl3, achl4, iml1 );          /* copy content            */
     achl3 += iml1;                         /* this is end packet      */
   }
   /* set length of packet                                             */
   while (   (achl5)
          && ((achl5 + 4) != achl3)) {
#ifdef DEBUG_101207_01
     if (bos_debug_01) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T set length of packet achl3=%p achl5=%p.",
                     __LINE__, achl3, achl5 );
     }
#endif
     achl1 = achl5;                         /* end of CR LF CR LF      */
     while ((achl1 > achl_out_end) && (*(achl1 - 1) != 0X20)) achl1--;
     if (achl1 <= achl_out_end) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W SIP NAT packet-length error 01",
                     __LINE__ );
       break;
     }
     if ((achl1 - 1 - sizeof(ucrs_sip_cont_len)) <= achl_out_end) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W SIP NAT packet-length error 02",
                     __LINE__ );
       break;
     }
     if (memcmp( (achl1 - 1 - sizeof(ucrs_sip_cont_len)),
                 ucrs_sip_cont_len,
                 sizeof(ucrs_sip_cont_len) )) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W SIP NAT packet-length error 03",
                     __LINE__ );
       break;
     }
     /* compute length of length in ASCII                              */
#ifdef B101207
     iml2 = iml3 = achl3 - achl5;           /* length of last part     */
#else
     iml2 = iml3 = achl3 - (achl5 + 4);     /* length of last part     */
#endif
#ifdef DEBUG_101207_01
     if (bos_debug_01) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T new length iml2=%d/%p packet-end=achl3=%p.",
                     __LINE__, iml2, iml2, achl3 );
     }
#endif
     iml4 = 0;
     do {
       iml4++;                              /* count the digit         */
       iml2 /= 10;                          /* divide number           */
     } while (iml2 > 0);
     iml2 = iml4 - (achl5 - achl1);         /* compute difference in number of digits */
     if (iml2) {                            /* different number of ASCII digits */
       memmove( (achl5 + 4) + iml2,
                achl5 + 4,
                achl3 - (achl5 - 4) );
       achl3 += iml2;                       /* new end of packet       */
       achl5 += iml2;                       /* new end of ASCII number */
     }
     do {
       *(--achl5) = (iml3 % 10) + '0';      /* output one digit        */
       iml3 /= 10;                          /* divide number           */
     } while (iml3 > 0);
     break;
   }
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml_len_packet = iml1 = achl3 - achl_out_ippa + 1;  /* length of packet */
   /* set length in the IP header                                      */
   iml2 = iml_len_packet - 1;
   achl1 = achl_out_ippa + 2;               /* here is length          */
   *(achl1 + 0) = (unsigned char) (iml2 >> 8);  /* first byte length big endian */
   *(achl1 + 1) = (unsigned char) iml2;     /* second byte length big endian */
#endif
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml_len_packet = iml1 = achl3 - achl_out_ippa;  /* length of packet */
   /* set length in the IP header                                      */
   achl1 = achl_out_ippa + 2;               /* here is length          */
   *(achl1 + 0) = (unsigned char) (iml_len_packet >> 8);  /* first byte length big endian */
   *(achl1 + 1) = (unsigned char) iml_len_packet;  /* second byte length big endian */
#endif
   /* calculate checksum of IP-header                                  */
   /* clear old checksum                                               */
   *((unsigned char *) achl_out_ippa + D_POS_IPH_DCHS + 0) = 0;
   *((unsigned char *) achl_out_ippa + D_POS_IPH_DCHS + 1) = 0;
   achl1 = achl_out_ippa;                   /* start of IP header      */
   achl2 = achl1 + iml_len_ip_header;       /* end of IP header        */
   iml_chs = 0;                             /* calculate checksum      */
   do {                                     /* loop over IP header     */
     /* calculate checksum                                           */
     iml_chs += (*((unsigned char *) achl1 + 0) << 8)
                  | *((unsigned char *) achl1 + 1);
     achl1 += 2;                            /* next position in header */
   } while (achl1 < achl2);
   while ((iml_chs >> 16) != 0) {           /* continue carry          */
     iml_chs = (iml_chs & 0X0000FFFF) + (iml_chs >> 16);
   }
   iml_chs = ~iml_chs;                      /* negate result           */
   *((unsigned char *) achl_out_ippa + D_POS_IPH_DCHS + 0) = (unsigned char) (iml_chs >> 8);
   *((unsigned char *) achl_out_ippa + D_POS_IPH_DCHS + 1) = (unsigned char) iml_chs;
   /* set length in the UDP header                                     */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml2 = iml_len_packet - (1 + iml_len_ip_header);
#else
   iml2 = iml_len_packet - iml_len_ip_header;
#endif
   achl1 = achl_out_ippa + iml_len_ip_header + 4;  /* here is length   */
   *(achl1 + 0) = (unsigned char) (iml2 >> 8);  /* first byte length big endian */
   *(achl1 + 1) = (unsigned char) iml2;     /* second byte length big endian */
   adsl_gai1_out_t1->achc_ginp_end = dsl_oa1.achc_lower = achl3;

   p_copy_92:                               /* prepare HOB-PPP-T1 header */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   achl1 = achl_out_ippa;                   /* start of IP packet      */
   *(--achl1) = '4';                        /* type IPV4               */
   iml1 = iml_len_packet;                   /* length of packet        */
   /* output length NHASN                                              */
   iml2 = 0;                                /* clear more bit          */
   do {
     *(--achl1) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* remove bits set         */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
   /* use gather structure prepared before                             */
   adsl_gai1_out_t1->achc_ginp_cur = achl1;
#endif
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   /* use gather structure prepared before                             */
   adsl_gai1_out_t1->achc_ginp_cur = achl_out_ippa;
#endif

#ifndef TRY_101205
   if (CHL_PROTOCOL == IPPROTO_TCP) {       /* protocol TCP from IP header */
     achl3 = achl_out_ippa + iml_len_ip_header + 16;
   } else if (CHL_PROTOCOL == IPPROTO_UDP) {  /* protocol UDP from IP header */
     achl3 = achl_out_ippa + iml_len_ip_header + 6;
   } else goto p_check_recv_00;             /* no new checksum needed  */
#else
   if (CHL_PROTOCOL == IPPROTO_TCP) {       /* protocol TCP from IP header */
     achl3 = achl_out_ippa + iml_len_ip_header + 16;
   } else if ((CHL_PROTOCOL & 0X0F) == (IPPROTO_UDP & 0X0F)) {  /* protocol UDP from IP header */
     achl3 = achl_out_ippa + iml_len_ip_header + 6;
   } else goto p_check_recv_00;             /* no new checksum needed  */
#endif
   achl1 = achl_out_ippa + iml_len_ip_header;  /* start of header and data */
// achl2 = achl_out_ippa + ((iml_len_packet - 1) & (-2));  /* end of data, even */
#ifdef B101204
   achl2 = achl_out_ippa + iml_len_packet - 1;  /* end of data, even or odd */
#endif
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   achl2 = achl_out_ippa + iml_len_packet - 2;  /* end of data, even or odd */
#else
   achl2 = achl_out_ippa + iml_len_packet - 1;  /* end of data, even or odd */
#endif
   if ((achl3 + 2) > achl2) goto p_check_recv_00;  /* packet is too short */
   /* clear old checksum                                               */
   *((unsigned char *) achl3 + 0) = 0;
   *((unsigned char *) achl3 + 1) = 0;
   iml_chs = 0;                             /* calculate checksum      */
   do {                                     /* loop over data          */
     /* calculate checksum                                             */
     iml_chs += (*((unsigned char *) achl1 + 0) << 8)
                  | *((unsigned char *) achl1 + 1);
     achl1 += 2;                            /* next position in data   */
   } while (achl1 < achl2);
   if (achl1 < dsl_oa1.achc_lower) {        /* one byte remaining      */
     iml_chs += *((unsigned char *) achl1 + 0) << 8;
   }
   /* fields in the IP header                                          */
   achl1 = achl_out_ippa + 12;              /* start source address    */
   achl2 = achl1 + 4 + 4;                   /* after destination address */
   do {                                     /* loop over data          */
     /* calculate checksum                                             */
     iml_chs += (*((unsigned char *) achl1 + 0) << 8)
                  | *((unsigned char *) achl1 + 1);
     achl1 += 2;                            /* next position in data   */
   } while (achl1 < achl2);
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml_chs += ((unsigned char) CHL_PROTOCOL) + iml_len_packet - (1 + iml_len_ip_header);
#else
   iml_chs += ((unsigned char) CHL_PROTOCOL) + iml_len_packet - iml_len_ip_header;
#endif
   while ((iml_chs >> 16) != 0) {           /* continue carry          */
     iml_chs = (iml_chs & 0X0000FFFF) + (iml_chs >> 16);
   }
   iml_chs = ~iml_chs;                      /* negate result           */
   *((unsigned char *) achl3 + 0) = (unsigned char) (iml_chs >> 8);
   *((unsigned char *) achl3 + 1) = (unsigned char) iml_chs;
   goto p_check_recv_00;                    /* check received packet   */

   p_ipcp_00:                               /* process IPCP            */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   achl_packet++;                           /* increment input         */
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   if (((unsigned char) *achl_packet) != ucrs_ctrl_ipcp[1]) {
     goto p_out_00;                         /* output unchanged        */
   }
   /* copy the complete packet to the work-area                        */
   achl1 = dsl_oa1.achc_lower;              /* output here             */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   achl_packet = dsl_oa1.achc_lower + iml_len_nhasn;  /* here comes packet */
   iml1 = iml_len_nhasn + iml_len_packet;   /* length to copy          */
#endif
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   achl_packet = dsl_oa1.achc_lower + 1 + iml_len_nhasn;  /* here comes packet */
   iml1 = 1 + iml_len_nhasn + iml_len_packet;  /* length to copy       */
#endif
   dsl_oa1.achc_lower += iml1;              /* here is space for the packet */
   dsl_oa1.achc_upper -= sizeof(struct dsd_gather_i_1);
   if (dsl_oa1.achc_upper < dsl_oa1.achc_lower) {  /* work-area too small */
     if (bol_output == FALSE) goto p_out_80;  /* overflow              */
     adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
#ifdef CHECK_OUTPUT_01
     m_check_output_01( adsp_hl_clib_1 );
#endif
     return;                                /* to be called again      */
   }
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) dsl_oa1.achc_upper)
   ADSL_GAI1_G->achc_ginp_cur = achl1;
   ADSL_GAI1_G->achc_ginp_end = dsl_oa1.achc_lower;
#ifdef DEBUG_101208_01
   iml_d1 = sprintf( achl_display, "l%05d gather=%p cur=%p end=%p.",
                     __LINE__, ADSL_GAI1_G, ADSL_GAI1_G->achc_ginp_cur, ADSL_GAI1_G->achc_ginp_end );
   achl_display += iml_d1;
   iml_d2 = D_LEN_LINE_M1 - iml_d1;
   if (iml_d2 > 0) {
     memset( achl_display, ' ', iml_d2 );
     achl_display += iml_d2;
   }
#endif
   ADSL_GAI1_G->adsc_next = NULL;           /* set last in chain       */
   bol_output = TRUE;                       /* output has been done    */
   *aadsrl_gai1_out[ iml_dir_oth ] = ADSL_GAI1_G;
   aadsrl_gai1_out[ iml_dir_oth ] = &ADSL_GAI1_G->adsc_next;
#undef ADSL_GAI1_G

   p_ipcp_20:                               /* copy part of the packet */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (adsl_gai1_inp_start->achc_ginp_cur >= adsl_gai1_inp_start->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_start == NULL) goto p_illogic_00;  /* program illogic */
   }
   iml2 = adsl_gai1_inp_start->achc_ginp_end - adsl_gai1_inp_start->achc_ginp_cur;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl1, adsl_gai1_inp_start->achc_ginp_cur, iml2 );
   achl1 += iml2;
   adsl_gai1_inp_start->achc_ginp_cur += iml2;
   iml1 -= iml2;
   if (iml1) goto p_ipcp_20;                /* copy part of the packet */
   if (iml_len_packet < (2 + 4)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W PPP IPCP packet too short",
                   __LINE__ );
     goto p_check_recv_00;                  /* check received packet   */
   }
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml1 = (*((unsigned char *) achl_packet + 1 + 2 + 2 + 0) << 8)
            | *((unsigned char *) achl_packet + 1 + 2 + 2 + 1);
   achl1 = achl_packet + 1 + 2 + iml1;
#endif
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml1 = (*((unsigned char *) achl_packet + 2 + 2 + 0) << 8)
            | *((unsigned char *) achl_packet + 2 + 2 + 1);
   achl1 = achl_packet + 2 + iml1;
#endif
   if (achl1 > (achl_packet + iml_len_packet)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W PPP IPCP packet length invalid",
                   __LINE__ );
     goto p_check_recv_00;                  /* check received packet   */
   }
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   if (   (*(achl_packet + 1 + 2 + 0) < 1)
       || (*(achl_packet + 1 + 2 + 0) > 4)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W PPP IPCP packet code 0X%02X invalid",
                   __LINE__, (unsigned char) *(achl_packet + 2 + 0) );
     goto p_check_recv_00;                  /* check received packet   */
   }
   iml2 = 0;
   if (*(achl_packet + 1 + 2 + 0) != 1) iml2 = 1;
   if (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER) {
     iml2 ^= 1;                             /* invert function         */
   }
   achl2 = achl_packet + 1 + 2 + 4;         /* start scanning          */
#endif
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   if (   (*(achl_packet + 2 + 0) < 1)
       || (*(achl_packet + 2 + 0) > 4)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W PPP IPCP packet code 0X%02X invalid",
                   __LINE__, (unsigned char) *(achl_packet + 2 + 0) );
     goto p_check_recv_00;                  /* check received packet   */
   }
   iml2 = 0;
   if (*(achl_packet + 2 + 0) != 1) iml2 = 1;
   if (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER) {
     iml2 ^= 1;                             /* invert function         */
   }
   achl2 = achl_packet + 2 + 4;             /* start scanning          */
#endif

   p_ipcp_40:                               /* scan option IPCP        */
   if (achl2 == achl1) goto p_check_recv_00;  /* check received packet */
   if ((achl2 + 2) > achl1) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W PPP IPCP packet no space for option",
                   __LINE__ );
     goto p_check_recv_00;                  /* check received packet   */
   }
   iml1 = (unsigned char) *(achl2 + 1);     /* get length option       */
   if (iml1 < 2) {                          /* length option too short */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W PPP IPCP packet length option %d too short",
                   __LINE__, iml1 );
     goto p_check_recv_00;                  /* check received packet   */
   }
   achl3 = achl2;                           /* save this position      */
   achl2 += iml1;                           /* after this option       */
   if (achl2 > achl1) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W PPP IPCP packet option too long",
                   __LINE__ );
     goto p_check_recv_00;                  /* check received packet   */
   }
   iml3 = iml2;                             /* is client INETA         */
   while (TRUE) {                           /* pseudo-loop             */
     if (*achl3 == 3) break;
     if (   (((unsigned char) *achl3) >= 0X81)
         && (((unsigned char) *achl3) <= 0X84)) {
       iml3 ^= 1;                           /* is not client INETA     */
       break;
     }
     goto p_ipcp_40;                        /* this option IPCP unchanged */
   }
   if (iml1 != (2 + sizeof(UNSIG_MED))) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W PPP IPCP packet length option %d for INETA invalid",
                   __LINE__, iml1 );
     goto p_check_recv_00;                  /* check received packet   */
   }
   memcpy( &uml_ineta_w1, achl3 + 2, sizeof(UNSIG_MED) );
   if (uml_ineta_w1 == 0) goto p_ipcp_40;   /* this option IPCP unchanged */
   if (iml3) {                              /* INETA client in tunnel  */
     if (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER) {
       memcpy( achl3 + 2, &adsl_contr_1->umc_ineta_cl_int, sizeof(UNSIG_MED) );
     } else {
       adsl_contr_1->umc_ineta_cl_int = uml_ineta_w1;  /* INETA client intern in intranet */
       memcpy( achl3 + 2, &adsl_contr_1->umc_ineta_client, sizeof(UNSIG_MED) );
     }
   } else {
#ifdef B120820
     if (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER) {
       uml_ineta_w1 = m_original_ineta( adsp_hl_clib_1, achl3 + 2, &dsl_nrv );
     } else {
       uml_ineta_w1 = m_natted_ineta( adsp_hl_clib_1, achl3 + 2, NULL, ADSL_CLCO->boc_disp_inetas );
     }
#endif
     if (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER) {
       if (   (ADSL_CLCO->boc_internal_dns_server == FALSE)  /* use internal DNS server */
           || (   (((unsigned char) *achl3) != 0X81)
               && (((unsigned char) *achl3) != 0X83))) {
         uml_ineta_w1 = m_original_ineta( adsp_hl_clib_1, achl3 + 2, &dsl_nrv );
       } else {
         if (((unsigned char) *achl3) == 0X81) {
           uml_ineta_w1 = adsl_contr_1->umc_ineta_dns_s_1;  /* original INETA DNS server 1 */
         } else {
           uml_ineta_w1 = adsl_contr_1->umc_ineta_dns_s_2;  /* original INETA DNS server 2 */
         }
       }
     } else {
       if (   (ADSL_CLCO->boc_internal_dns_server == FALSE)  /* use internal DNS server */
           || (   (((unsigned char) *achl3) != 0X81)
               && (((unsigned char) *achl3) != 0X83))) {
         uml_ineta_w1 = m_natted_ineta( adsp_hl_clib_1, achl3 + 2, NULL, ADSL_CLCO->boc_disp_inetas );
       } else {
         if (((unsigned char) *achl3) == 0X81) {
           memcpy( &adsl_contr_1->umc_ineta_dns_s_1, achl3 + 2, sizeof(UNSIG_MED) );  /* original INETA DNS server 1 */
           uml_ineta_w1 = adsl_contr_1->umc_ineta_upper;  /* natted INETAs upper entry */
         } else {
           memcpy( &adsl_contr_1->umc_ineta_dns_s_2, achl3 + 2, sizeof(UNSIG_MED) );  /* original INETA DNS server 2 */
           uml_ineta_w1 = 0;                /* no Secondary DNS Server Address */
         }
       }
     }
     memcpy( achl3 + 2, &uml_ineta_w1, sizeof(UNSIG_MED) );
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T PPP IPCP packet INETA replaced",
                 __LINE__ );
#endif
   goto p_ipcp_40;                          /* scan option IPCP        */

   p_contr_00:                              /* control packet found    */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   achl_packet++;                           /* after control character '0' */
#endif
   achl1 = achl_packet;                     /* here starts control packet */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   iml_len_packet--;                        /* remaining length        */
#endif
   achl2 = achl_packet + iml_len_packet;    /* end of control packet   */
   if (achl2 <= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     achl_packet = achl2;                   /* set end of packet       */
     goto p_contr_20;                       /* packet is in one chunk  */
   }
   achl1 = achl2 = chrl_work1;              /* copy to work area       */
   if (iml_len_packet > sizeof(chrl_work1)) iml_len_packet = sizeof(chrl_work1);
   iml1 = iml_len_packet;                   /* length to copy          */

   p_contr_04:                              /* copy one part of the packet */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;  /* length this chunk */
   if (iml2 > iml1) iml2 = iml1;            /* so much to copy         */
   memcpy( achl2, achl_packet, iml2 );
   achl2 += iml2;
   achl_packet += iml2;
   iml1 -= iml2;
   if (iml1) goto p_contr_04;               /* more to copy            */

   p_contr_20:                              /* packet is in one chunk  */
   if (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER) goto p_se_contr_00;  /* received control from server */
   achl3 = achl1 + sizeof(ucrs_recv_contr_01);
   if (!memcmp( achl1, ucrs_recv_contr_01, sizeof(ucrs_recv_contr_01) )) {
     adsl_contr_1->umc_ineta_lower          /* natted INETAs lower entry */
       = ADSL_CLCO->umc_conf_ineta_1_lower;  /* configured INETAs 1 lower value */
     adsl_contr_1->umc_ineta_upper          /* natted INETAs upper entry */
       = ADSL_CLCO->umc_conf_ineta_1_upper;  /* configured INETAs 1 upper value */
     adsl_contr_1->umc_ineta_mask           /* natted INETAs network mask */
       = ADSL_CLCO->umc_conf_ineta_1_mask;  /* configured INETAs 1 network mask */
     goto p_contr_24;                       /* command is valid        */
   }
   if (memcmp( achl1, ucrs_recv_contr_02, sizeof(ucrs_recv_contr_02) )) {
     goto p_out_00;                         /* other command found     */
   }
#ifdef NOT_YET_101031
   achl3 = achl1 + sizeof(ucrs_recv_contr_02);
#else
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) adsp_hl_clib_1->achc_work_area)
   ADSL_GAI1_G->achc_ginp_cur = (char *) ucrs_send_stop;
   ADSL_GAI1_G->achc_ginp_end = (char *) ucrs_send_stop + sizeof(ucrs_send_stop);
   ADSL_GAI1_G->adsc_next = NULL;           /* set last in chain       */
   adsp_hl_clib_1->adsc_gai1_out_to_client = ADSL_GAI1_G;  /* output data to client */
   adsp_hl_clib_1->adsc_gai1_out_to_server = NULL;  /* output data to server */
#undef ADSL_GAI1_G
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-E RECONNECT not supported by this Server-Data-Hook - end session",
                 __LINE__ );
   goto p_end_tunnel_00;                    /* end the tunnel          */
#endif

   p_contr_24:                              /* command is valid        */
   if (achl3 >= achl2) goto p_out_00;       /* end of command found    */
   if (*achl3 != ' ') goto p_out_00;        /* not separated by blank  */

   p_contr_28:                              /* search next keyword     */
   while ((achl3 < achl2) && (*achl3 == ' ')) achl3++;  /* overread spaces */
   if (achl3 >= achl2) goto p_out_00;       /* end of command found    */
#ifdef B110317
   achl4 = (char *) memchr( achl3, ' ', achl2 - achl4 );
#else
   achl4 = (char *) memchr( achl3, ' ', achl2 - achl3 );
#endif
   if (achl4 == NULL) achl4 = achl2;        /* end of control packet   */
   if (memcmp( achl3, ucrs_recv_locineta, sizeof(ucrs_recv_locineta) )) {
     achl3 = achl4;                         /* after this keyword      */
     goto p_contr_28;                       /* search next keyword     */
   }
   achl3 += sizeof(ucrs_recv_locineta);
   iml1 = m_get_ineta_a( &uml_ineta_w1, achl3, achl4 );
   if (iml1) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W LOCAL-INETA=\"%.*s\" invalid",
                   __LINE__, achl4 - achl3, achl3 );
     goto p_out_00;                         /* end of command          */
   }
   if (   (memcmp( &uml_ineta_w1, &ADSL_CLCO->umc_conf_ineta_1_lower, sizeof(UNSIG_MED) ) >= 0)  /* configured INETAs 1 lower value */
       && (memcmp( &uml_ineta_w1, &ADSL_CLCO->umc_conf_ineta_1_upper, sizeof(UNSIG_MED) ) <= 0)) {  /* configured INETAs 1 upper value */
     adsl_contr_1->umc_ineta_lower          /* natted INETAs lower entry */
       = ADSL_CLCO->umc_conf_ineta_2_lower;  /* configured INETAs 2 lower value */
     adsl_contr_1->umc_ineta_upper          /* natted INETAs upper entry */
       = ADSL_CLCO->umc_conf_ineta_2_upper;  /* configured INETAs 2 upper value */
     adsl_contr_1->umc_ineta_mask           /* natted INETAs network mask */
       = ADSL_CLCO->umc_conf_ineta_2_mask;  /* configured INETAs 2 network mask */
   }
   adsl_contr_1->umc_ineta_client = adsl_contr_1->umc_ineta_lower;  /* INETA client in tunnel */
   m_ineta_op_inc( (char *) &adsl_contr_1->umc_ineta_client, sizeof(UNSIG_MED) );  /* increment */
   goto p_out_00;                           /* output data unchanged   */

   p_se_contr_00:                           /* received control from server */
   if (   (iml_len_packet <= 15)
       || (memcmp( achl1, "RESPONSE-START ", 15 ))) {
     goto p_out_00;                         /* copy command unchanged  */
   }
   achl2 = achl1 + 15;                      /* scan from here          */
   achl_end = achl1 + iml_len_packet;       /* end of packet           */
   achl5 = NULL;                            /* tunnel-id not found     */
   while (TRUE) {                           /* loop over keywords      */
     while ((achl2 < achl_end) && (*achl2 == ' ')) achl2++;
     if (achl2 >= achl_end) break;
     achl3 = (char *) memchr( achl2, ' ', achl_end - achl2 );
     if (achl3 == NULL) achl3 = achl_end;   /* no space found          */
     achl4 = (char *) memchr( achl2, '=', achl3 - achl2 );
     if (achl4 == NULL) {                   /* no equals found         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W received keyword without \'=\' in RESPONSE-START packet \"%.*s\".",
                     __LINE__, iml_len_packet, achl1 );
       achl2 = achl3;                       /* set end of keyword      */
       continue;                            /* ignore this keyword     */
     }
     iml3 = achl4 - achl2;                  /* get length of string    */
     if (iml3 <= 0) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W received keyword length zero before \'=\' in RESPONSE-START packet \"%.*s\".",
                     __LINE__, iml_len_packet, achl1 );
       achl2 = achl3;                       /* set end of keyword      */
       continue;                            /* ignore this keyword     */
     }
     if (   (iml3 != 9)
         || (memcmp( achl2, "TUNNEL-ID", 9 ))) {
       achl2 = achl3;                       /* set end of keyword      */
       continue;                            /* ignore this keyword     */
     }
     achl4++;                               /* after equals            */
     iml4 = achl3 - achl4;                  /* length of value         */
     if (iml4 <= 0) {                       /* value too short         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W received value too short with keyword \"%.*s\" in RESPONSE-START packet \"%.*s\".",
                     __LINE__, iml3, achl2, iml_len_packet, achl1 );
       achl2 = achl3;                       /* set end of keyword      */
       continue;                            /* ignore this keyword     */
     }
     if (achl5) {                           /* tunnel-id already set   */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W received TUNNEL-ID= twice in RESPONSE-START packet \"%.*s\".",
                     __LINE__, iml_len_packet, achl1 );
       achl2 = achl3;                       /* set end of keyword      */
       continue;                            /* ignore this keyword     */
     }
     iml2 = iml4;                           /* set length tunnel-id    */
     achl5 = achl4;                         /* save address tunnel-id  */
     achl2 = achl3;                         /* set end of keyword      */
   }
   if (achl5 == NULL) {                     /* tunnel-id not found     */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W did not received TUNNEL-ID= in RESPONSE-START packet \"%.*s\".",
                   __LINE__, iml_len_packet, achl1 );
     goto p_out_00;                         /* copy command unchanged  */
   }
   dsl_oa1.achc_upper -= sizeof(struct dsd_gather_i_1);
   if ((dsl_oa1.achc_lower + D_LEN_RESP_START + iml2) > dsl_oa1.achc_upper) {  /* no space for output */
     if (bol_output == FALSE) goto p_out_80;  /* overflow              */
     adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
#ifdef CHECK_OUTPUT_01
     m_check_output_01( adsp_hl_clib_1 );
#endif
     return;                                /* to be called again      */
   }
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) dsl_oa1.achc_upper)
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   dsl_oa1.achc_lower += 2;                 /* leave space for length  */
   iml1 = sprintf( dsl_oa1.achc_lower, "0RESPONSE-START TUNNEL-ID=%.*s \
SERVER-NETWORK-INETA=%d.%d.%d.%d \
SERVER-NETWORK-MASK=%d.%d.%d.%d",
                   iml2, achl5,
                   *((unsigned char *) &adsl_contr_1->umc_ineta_lower + 0 ),
                   *((unsigned char *) &adsl_contr_1->umc_ineta_lower + 1 ),
                   *((unsigned char *) &adsl_contr_1->umc_ineta_lower + 2 ),
                   *((unsigned char *) &adsl_contr_1->umc_ineta_lower + 3 ),
                   *((unsigned char *) &adsl_contr_1->umc_ineta_mask + 0 ),
                   *((unsigned char *) &adsl_contr_1->umc_ineta_mask + 1 ),
                   *((unsigned char *) &adsl_contr_1->umc_ineta_mask + 2 ),
                   *((unsigned char *) &adsl_contr_1->umc_ineta_mask + 3 ) );
   achl1 = dsl_oa1.achc_lower;              /* get position output     */
   dsl_oa1.achc_lower += iml1;              /* after output            */
   if (iml1 < 0X80) {
     *(--achl1) = (unsigned char) iml1;
   } else {
     *(--achl1) = (unsigned char) (iml1 & 0X7F);
     *(--achl1) = (unsigned char) ((iml1 >> 7) | 0X80);
   }
#endif
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   dsl_oa1.achc_lower += 1 + 2;             /* leave space for tag and length */
   iml1 = sprintf( dsl_oa1.achc_lower, "RESPONSE-START TUNNEL-ID=%.*s \
SERVER-NETWORK-INETA=%d.%d.%d.%d \
SERVER-NETWORK-MASK=%d.%d.%d.%d",
                   iml2, achl5,
                   *((unsigned char *) &adsl_contr_1->umc_ineta_lower + 0 ),
                   *((unsigned char *) &adsl_contr_1->umc_ineta_lower + 1 ),
                   *((unsigned char *) &adsl_contr_1->umc_ineta_lower + 2 ),
                   *((unsigned char *) &adsl_contr_1->umc_ineta_lower + 3 ),
                   *((unsigned char *) &adsl_contr_1->umc_ineta_mask + 0 ),
                   *((unsigned char *) &adsl_contr_1->umc_ineta_mask + 1 ),
                   *((unsigned char *) &adsl_contr_1->umc_ineta_mask + 2 ),
                   *((unsigned char *) &adsl_contr_1->umc_ineta_mask + 3 ) );
   achl1 = dsl_oa1.achc_lower;              /* get position output     */
   dsl_oa1.achc_lower += iml1;              /* after output            */
   if (iml1 < 0X80) {
     *(--achl1) = (unsigned char) iml1;
   } else {
     *(--achl1) = (unsigned char) (iml1 & 0X7F);
     *(--achl1) = (unsigned char) ((iml1 >> 7) | 0X80);
   }
   *(--achl1) = (unsigned char) '0';        /* tag                     */
#endif
   ADSL_GAI1_G->achc_ginp_cur = achl1;
   ADSL_GAI1_G->achc_ginp_end = dsl_oa1.achc_lower;
   ADSL_GAI1_G->adsc_next = NULL;           /* set last in chain       */
   bol_output = TRUE;                       /* output has been done    */
   *aadsrl_gai1_out[ iml_dir_oth ] = ADSL_GAI1_G;
   aadsrl_gai1_out[ iml_dir_oth ] = &ADSL_GAI1_G->adsc_next;
#undef ADSL_GAI1_G
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   /* remove the received packet                                       */
   while (adsl_gai1_inp_start != adsl_gai1_inp_packet) {
     adsl_gai1_inp_start->achc_ginp_cur = adsl_gai1_inp_start->achc_ginp_end;
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;
     if (adsl_gai1_inp_start == NULL) goto p_illogic_00;  /* program illogic */
   }
   adsl_gai1_inp_start->achc_ginp_cur = achl_packet;  /* processed so far */
   goto p_check_recv_00;                    /* check received packet   */

   p_out_00:                                /* output data unchanged   */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   iml_error_line = __LINE__;
#endif
   /* check if enough space in output area                             */
   iml1 = sizeof(struct dsd_gather_i_1);
   adsl_gai1_inp_w2 = adsl_gai1_inp_start;  /* start from first gather */
   while (adsl_gai1_inp_w2 != adsl_gai1_inp_w1) {
     adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;
     if (adsl_gai1_inp_w2 == NULL) goto p_illogic_00;  /* program illogic */
     iml1 += sizeof(struct dsd_gather_i_1);
   }
   if ((dsl_oa1.achc_upper - iml1) < dsl_oa1.achc_lower) {  /* not enough space */
     if (bol_output == FALSE) goto p_out_80;  /* overflow              */
     adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
#ifdef CHECK_OUTPUT_01
     m_check_output_01( adsp_hl_clib_1 );
#endif
     return;                                /* to be called again      */
   }
   bol_output = TRUE;                       /* output has been done    */

   p_out_20:                                /* output data unchanged   */
#ifdef B110819
   achl_work_2 -= sizeof(struct dsd_gather_i_1);
   if (achl_work_2 < achl_work_1) goto p_out_80;  /* overflow          */
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;
   adsl_gai1_out_1->adsc_next = NULL;
   adsl_gai1_out_1->achc_ginp_cur = adsl_gai1_inp_start->achc_ginp_cur;
   adsl_gai1_out_1->achc_ginp_end = adsl_gai1_inp_start->achc_ginp_end;
#ifdef DEBUG_101208_01
   iml_d1 = sprintf( achl_display, "l%05d gather=%p cur=%p end=%p.",
                     __LINE__, adsl_gai1_out_1, adsl_gai1_out_1->achc_ginp_cur, adsl_gai1_out_1->achc_ginp_end );
   achl_display += iml_d1;
   iml_d2 = D_LEN_LINE_M1 - iml_d1;
   if (iml_d2 > 0) {
     memset( achl_display, ' ', iml_d2 );
     achl_display += iml_d2;
   }
#endif
   if (adsl_gai1_out_2 == NULL) {
#ifndef NEW_WSP_1102
     adsp_hl_clib_1->adsc_gather_i_1_out = adsl_gai1_out_1;
#else
     if (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER) {  /* send to client */
       adsp_hl_clib_1->adsc_gai1_out_to_client = adsl_gai1_out_1;  /* output data to client */
     } else {                               /* send to server          */
       adsp_hl_clib_1->adsc_gai1_out_to_server = adsl_gai1_out_1;  /* output data to server */
     }
#endif
   } else {
     adsl_gai1_out_2->adsc_next = adsl_gai1_out_1;
   }
   adsl_gai1_out_2 = adsl_gai1_out_1;
   if (adsl_gai1_inp_start != adsl_gai1_inp_w1) {
     adsl_gai1_inp_start->achc_ginp_cur = adsl_gai1_inp_start->achc_ginp_end;
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;
     if (adsl_gai1_inp_start) goto p_out_20;  /* output next part      */
#ifdef DEBUG_140730_01                      /* problems FTP            */
     iml_error_line = __LINE__;
#endif
     goto p_illogic_00;                     /* program illogic         */
   }
   adsl_gai1_inp_start->achc_ginp_cur = achl_inp;  /* processed so far */
   adsl_gai1_out_1->achc_ginp_end = achl_inp;  /* output only till here */
#endif
#ifndef B110819
   dsl_oa1.achc_upper -= sizeof(struct dsd_gather_i_1);
   if (dsl_oa1.achc_upper < dsl_oa1.achc_lower) goto p_out_80;  /* overflow */
   adsl_gai1_out_t1 = (struct dsd_gather_i_1 *) dsl_oa1.achc_upper;
   adsl_gai1_out_t1->adsc_next = NULL;
   adsl_gai1_out_t1->achc_ginp_cur = adsl_gai1_inp_start->achc_ginp_cur;
   adsl_gai1_out_t1->achc_ginp_end = adsl_gai1_inp_start->achc_ginp_end;
   *aadsrl_gai1_out[ iml_dir_oth ] = adsl_gai1_out_t1;
   aadsrl_gai1_out[ iml_dir_oth ] = &adsl_gai1_out_t1->adsc_next;
#ifdef DEBUG_101208_01
   iml_d1 = sprintf( achl_display, "l%05d gather=%p cur=%p end=%p.",
                     __LINE__, adsl_gai1_out_t1, adsl_gai1_out_t1->achc_ginp_cur, adsl_gai1_out_t1->achc_ginp_end );
   achl_display += iml_d1;
   iml_d2 = D_LEN_LINE_M1 - iml_d1;
   if (iml_d2 > 0) {
     memset( achl_display, ' ', iml_d2 );
     achl_display += iml_d2;
   }
#endif
   if (adsl_gai1_inp_start != adsl_gai1_inp_w1) {
     adsl_gai1_inp_start->achc_ginp_cur = adsl_gai1_inp_start->achc_ginp_end;
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;
     if (adsl_gai1_inp_start) goto p_out_20;  /* output next part      */
#ifdef DEBUG_140730_01                      /* problems FTP            */
     iml_error_line = __LINE__;
#endif
     goto p_illogic_00;                     /* program illogic         */
   }
   adsl_gai1_inp_start->achc_ginp_cur = achl_inp;  /* processed so far */
   adsl_gai1_out_t1->achc_ginp_end = achl_inp;  /* output only till here */
#endif
   goto p_check_recv_00;                    /* check received packet   */

   p_end_tunnel_00:                         /* end the tunnel          */
   adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code          */
   return;

   p_out_80:                                /* overflow in work-area   */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-E p_out_80 overflow work-area", __LINE__ );
   adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code          */
   return;

   p_inv_data_00:                           /* input data invalid      */
#ifndef EXT_111125_01
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-E p_inv_data_00 input data invalid", __LINE__ );
#else
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-E p_inv_data_00 input data invalid %d.",
                 __LINE__, iml_invdat );
#endif
   adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code          */
   return;

   p_data_to_long:                          /* input data too long     */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-E p_inv_data_00 input data too long", __LINE__ );
   adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code          */
   return;

   p_illogic_00:                            /* program illogic         */
#ifdef DEBUG_140730_01                      /* problems FTP            */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_hlclib01() DEBUG_140730_01 p_illogic_00 iml_error_line=%d.",
                 __LINE__, iml_error_line );
#endif
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-E p_illogic_00 program illogic", __LINE__ );
   adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code          */
   return;
#undef ADSL_CLCO
#undef CHL_PROTOCOL

   p_timer_00:                              /* check the timer         */
#ifdef TRACEHL_111004
   memmove( adsl_contr_1->imrl_trace_lno,
            adsl_contr_1->imrl_trace_lno + 1,
            (TRACEHL_111004 - 1) * sizeof(int) );
   adsl_contr_1->imrl_trace_lno[ TRACEHL_111004 - 1 ] = __LINE__;
#endif
   if (adsl_contr_1->adsc_session_timer == NULL) {  /* check session timer */
     goto p_timer_40;                       /* check notify send client */
   }

#define ADSL_SESSION_TIMER_G adsl_contr_1->adsc_session_timer

   if (ADSL_SESSION_TIMER_G->ilc_epoch_end > dsl_subaux_userfld.ilc_epoch) {  /* epoch timer set */
#ifdef B111205
     goto p_timer_60;                       /* set the new timer       */
#else
     goto p_timer_40;                       /* check notify send client */
#endif
   }
   adsl_ts1_w1 = ADSL_SESSION_TIMER_G->adsc_ts1;  /* structure TCP session */
   iml_clse_pri = ADSL_SESSION_TIMER_G->imc_index;  /* primary client to server */
   adsl_sdh_tcp_1_pri = &adsl_ts1_w1->dsrc_sdh_tcp_1[ iml_clse_pri ];
   if (adsl_sdh_tcp_1_pri->imc_return != DEF_IRET_NORMAL) {
     adsl_sdh_tcp_1_pri->boc_timer_running = FALSE;
   }
   if (adsl_sdh_tcp_1_pri->boc_timer_running == FALSE) {  /* timer is currently not running */
     ADSL_SESSION_TIMER_G->ilc_epoch_end = 0;  /* timer not in chain   */
     ADSL_SESSION_TIMER_G = ADSL_SESSION_TIMER_G->adsc_next;  /* remove timer from chain */
     goto p_timer_00;                       /* check the timer         */
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_timer_00: process SDH-TCP at adsl_ts1_w1=%p iml_clse_pri=%d.",
                 __LINE__, adsl_ts1_w1, iml_clse_pri );
#endif
#ifdef B110903
   bol_ipv6 = ADSL_SESSION_TIMER_G->boc_ipv6;  /* is IPV4 or IPV6      */
#endif
   bol_ipv6 = adsl_ts1_w1->boc_ipv6;        /* is IPV4 or IPV6         */
#ifdef B111004
   chl_ipv4_ipv6 = '4';                     /* protocol from IP header */
   if (bol_ipv6) {                          /* is IPV6, not IPV4       */
     chl_ipv4_ipv6 = '6';                   /* protocol from IP header */
   }
#else
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   chl_ipv4_ipv6 = '4';                     /* protocol from IP header */
#endif
   iml_len_ip_header = D_LEN_HEADER_IPV4;   /* length of IP header IPV4 */
   if (bol_ipv6) {                          /* is IPV6, not IPV4       */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
     chl_ipv4_ipv6 = '6';                   /* protocol from IP header */
#endif
     iml_len_ip_header = D_LEN_HEADER_IPV6;  /* length of IP header IPV6 */
   }
#endif
   iml_clse_sec = iml_clse_pri ^ 1;         /* secondary client to server */
   adsl_sdh_tcp_1_sec = &adsl_ts1_w1->dsrc_sdh_tcp_1[ iml_clse_sec ];
   adsl_sdh_tcp_1_pri->adsc_tdc1_in = NULL;  /* input data             */
   iel_ps = ied_ps_timer;                   /* processing thru timer   */
#ifdef TRACEHL_INETA_01
   achl_trhl_reason = "XXX";
   if (iml_clse_pri == 0) {                 /* 0 = cl2se, 1 = se2cl    */
     achl_trhl_reason = "timer--0";
   }
   if (iml_clse_pri) {                      /* 0 = cl2se, 1 = se2cl    */
     achl_trhl_reason = "timer--1";
   }
#endif
#ifdef B120102
#ifdef B111221
#ifdef B111219
   if (bol_ipv6) {                          /* is IPV6, not IPV4       */
     goto p_sdh_tcp_cont_12;                /* call SDH-TCP            */
   }
// to-do 01.09.11 KB - are these the correct INETAs or swap needed?
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 0 ][ 0 ],
           &adsl_sdh_tcp_1_pri->chrc_header_info[ 0 ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 1 ][ 0 ],
           &adsl_sdh_tcp_1_pri->chrc_header_info[ sizeof(UNSIG_MED) ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 0 ][ 0 ],
           &adsl_sdh_tcp_1_sec->chrc_header_info[ 0 ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 1 ][ 0 ],
           &adsl_sdh_tcp_1_sec->chrc_header_info[ sizeof(UNSIG_MED) ],
           sizeof(UNSIG_MED) );
   goto p_sdh_tcp_cont_12;                  /* call SDH-TCP            */
#else
   goto p_timer_44;                         /* set INETAs of session   */
#endif
#else
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 0 ][ 0 ],
           &adsl_sdh_tcp_1_sec->chrc_header_info[ 0 ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 1 ][ 0 ],
           &adsl_sdh_tcp_1_sec->chrc_header_info[ sizeof(UNSIG_MED) ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 0 ][ 0 ],
           &adsl_sdh_tcp_1_pri->chrc_header_info[ 0 ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 1 ][ 0 ],
           &adsl_sdh_tcp_1_pri->chrc_header_info[ sizeof(UNSIG_MED) ],
           sizeof(UNSIG_MED) );
   goto p_sdh_tcp_cont_12;                  /* call SDH-TCP            */
#endif
#else
#ifdef XXX_TRY_02 /* 02.01.12 KB does work with Socks5 */
   if (bol_ipv6) {                          /* is IPV6, not IPV4       */
     goto p_sdh_tcp_cont_12;                /* call SDH-TCP            */
   }
#endif
#ifdef XXX_TRY_01 /* pri exchanged, sec wrong pair */
// to-do 01.09.11 KB - are these the correct INETAs or swap needed?
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 0 ][ 0 ],
           &adsl_sdh_tcp_1_pri->chrc_header_info[ sizeof(UNSIG_MED) ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 1 ][ 0 ],
           &adsl_sdh_tcp_1_pri->chrc_header_info[ 0 ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 0 ][ 0 ],
           &adsl_sdh_tcp_1_sec->chrc_header_info[ sizeof(UNSIG_MED) ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 1 ][ 0 ],
           &adsl_sdh_tcp_1_sec->chrc_header_info[ 0 ],
           sizeof(UNSIG_MED) );
#endif
#ifdef XXX_TRY_02 /* 02.01.12 KB does work with Socks5 */
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 0 ][ 0 ],
           &adsl_ts1_w1->dsrc_sdh_tcp_1[ 0 ].chrc_header_info[ 0 ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 1 ][ 0 ],
           &adsl_ts1_w1->dsrc_sdh_tcp_1[ 0 ].chrc_header_info[ sizeof(UNSIG_MED) ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 0 ][ 0 ],
           &adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].chrc_header_info[ 0 ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 1 ][ 0 ],
           &adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].chrc_header_info[ sizeof(UNSIG_MED) ],
           sizeof(UNSIG_MED) );
   goto p_sdh_tcp_cont_12;                  /* call SDH-TCP            */
#endif
   goto p_timer_44;                         /* set INETAs of session   */
#endif

   p_timer_40:                              /* check notify send client */
   if (adsl_contr_1->adsc_session_notify == NULL) {  /* session notify send possible */
     goto p_timer_60;                       /* set the new timer       */
   }
#ifdef B111205
   if (adsp_hl_clib_1->boc_notify_send_client_possible == FALSE) {  /* notify SDH when sending to the client is not possible */
     goto p_timer_48;                       /* change session notify from new to old */
   }
#else
   if (adsp_hl_clib_1->boc_send_client_blocked) {  /* sending to the client is blocked */
     goto p_timer_48;                       /* change session notify from new to old */
   }
#endif
   if (adsl_contr_1->adsc_session_notify->iec_se_no == ied_se_no_act_new) {  /* active, new */
     goto p_timer_48;                       /* change session notify from new to old */
   }
   adsl_ts1_w1                              /* structure TCP session */
     = (struct dsd_tcp_session_1 *) ((char *) adsl_contr_1->adsc_session_notify
                                                - offsetof( struct dsd_tcp_session_1 , dsc_session_notify ));
   adsl_ts1_w1->dsc_session_notify.iec_se_no = ied_se_no_idle;  /* not set */
   adsl_contr_1->adsc_session_notify = adsl_contr_1->adsc_session_notify->adsc_next;  /* remove from chain */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_timer_40: process SDH-TCP at adsl_ts1_w1=%p.",
                 __LINE__, adsl_ts1_w1 );
#endif
   bol_ipv6 = adsl_ts1_w1->boc_ipv6;        /* is IPV4 or IPV6         */
#ifdef B111004
   chl_ipv4_ipv6 = '4';                     /* protocol from IP header */
   if (bol_ipv6) {                          /* is IPV6, not IPV4       */
     chl_ipv4_ipv6 = '6';                   /* protocol from IP header */
   }
#else
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
   chl_ipv4_ipv6 = '4';                     /* protocol from IP header */
#endif
   iml_len_ip_header = D_LEN_HEADER_IPV4;   /* length of IP header IPV4 */
   if (bol_ipv6) {                          /* is IPV6, not IPV4       */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
     chl_ipv4_ipv6 = '6';                   /* protocol from IP header */
#endif
     iml_len_ip_header = D_LEN_HEADER_IPV6;  /* length of IP header IPV6 */
   }
#endif
   iml_clse_pri = 0;                        /* primary client to server */
   iml_clse_sec = 1;                        /* secondary client to server */
   adsl_sdh_tcp_1_pri = &adsl_ts1_w1->dsrc_sdh_tcp_1[ 0 ];
   adsl_sdh_tcp_1_sec = &adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ];
   adsl_sdh_tcp_1_pri->adsc_tdc1_in = NULL;  /* input data             */
   iel_ps = ied_ps_timer;                   /* processing thru timer   */
#ifdef TRACEHL_INETA_01
   achl_trhl_reason = "notify--";
#endif
#ifdef B120102
#ifdef B111221
#ifndef B111219

   p_timer_44:                              /* set INETAs of session   */
#endif
#endif
#else

   p_timer_44:                              /* set INETAs of session   */
#endif
   if (bol_ipv6) {                          /* is IPV6, not IPV4       */
     goto p_sdh_tcp_cont_12;                /* call SDH-TCP            */
   }
#ifdef B120102
#ifdef B111221
#ifdef B111219
// to-do 01.09.11 KB - are these the correct INETAs or swap needed?
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 0 ][ 0 ],
           &adsl_sdh_tcp_1_pri->chrc_header_info[ 0 ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 1 ][ 0 ],
           &adsl_sdh_tcp_1_pri->chrc_header_info[ sizeof(UNSIG_MED) ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 0 ][ 0 ],
           &adsl_sdh_tcp_1_sec->chrc_header_info[ 0 ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 1 ][ 0 ],
           &adsl_sdh_tcp_1_sec->chrc_header_info[ sizeof(UNSIG_MED) ],
           sizeof(UNSIG_MED) );
#else
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 0 ][ 0 ],
           &adsl_sdh_tcp_1_sec->chrc_header_info[ 0 ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 1 ][ 0 ],
           &adsl_sdh_tcp_1_sec->chrc_header_info[ sizeof(UNSIG_MED) ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 0 ][ 0 ],
           &adsl_sdh_tcp_1_pri->chrc_header_info[ 0 ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 1 ][ 0 ],
           &adsl_sdh_tcp_1_pri->chrc_header_info[ sizeof(UNSIG_MED) ],
           sizeof(UNSIG_MED) );
#endif
#else
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 0 ][ 0 ],
           &adsl_sdh_tcp_1_pri->chrc_header_info[ 0 ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 1 ][ 0 ],
           &adsl_sdh_tcp_1_pri->chrc_header_info[ sizeof(UNSIG_MED) ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 0 ][ 0 ],
           &adsl_sdh_tcp_1_sec->chrc_header_info[ 0 ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 1 ][ 0 ],
           &adsl_sdh_tcp_1_sec->chrc_header_info[ sizeof(UNSIG_MED) ],
           sizeof(UNSIG_MED) );
#endif
#else
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 0 ][ 0 ],
           &adsl_ts1_w1->dsrc_sdh_tcp_1[ 0 ].chrc_header_info[ 0 ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 0 ].chrrc_ineta[ 1 ][ 0 ],
           &adsl_ts1_w1->dsrc_sdh_tcp_1[ 0 ].chrc_header_info[ sizeof(UNSIG_MED) ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 0 ][ 0 ],
           &adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].chrc_header_info[ 0 ],
           sizeof(UNSIG_MED) );
   memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 1 ][ 0 ],
           &adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].chrc_header_info[ sizeof(UNSIG_MED) ],
           sizeof(UNSIG_MED) );
#endif
   goto p_sdh_tcp_cont_12;                  /* call SDH-TCP            */

   p_timer_48:                              /* change session notify from new to old */
   adsl_session_notify_w1 = adsl_contr_1->adsc_session_notify;  /* session notify send possible */
   do {                                     /* loop over all session notify */
     adsl_session_notify_w1->iec_se_no = ied_se_no_act_old;  /* active, old */
     adsl_session_notify_w1 = adsl_session_notify_w1->adsc_next;  /* get next in chain */
   } while (adsl_session_notify_w1);

   p_timer_60:                              /* set the new timer       */
   if (adsl_contr_1->adsc_session_timer == NULL) {  /* check session timer */
     goto p_timer_80;                       /* the timer has been checked */
   }
   if (ADSL_SESSION_TIMER_G->ilc_epoch_end == adsl_contr_1->ilc_epoch_set) {  /* epoch timer set */
     goto p_timer_80;                       /* the timer has been checked */
   }
   adsl_contr_1->ilc_epoch_set = ADSL_SESSION_TIMER_G->ilc_epoch_end;  /* epoch timer set */
   bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                   DEF_AUX_TIMER1_SET,  /* set timer in milliseconds */
                                   NULL,
                                   (int) (adsl_contr_1->ilc_epoch_set - dsl_subaux_userfld.ilc_epoch) );
   if (bol1 == FALSE) {                     /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#ifdef TRACEHL_TIMER_01
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_timer_60 set timer adsl_contr_1->ilc_epoch_set=%lld.",
                 __LINE__, adsl_contr_1->ilc_epoch_set );
#endif

#undef ADSL_SESSION_TIMER_G

   p_timer_80:                              /* the timer has been checked */
   if (adsp_hl_clib_1->boc_eof_client == FALSE) {
     goto p_close_80;                       /* end of session closing  */
   }

   /* send RST over all TCP sessions on server side                    */
   adsl_htree1_avl_cntl_ineta = &adsl_contr_1->dsc_htree1_avl_cntl_ineta_ipv4;
   bol_ipv6 = FALSE;                        /* is IPV4, not IPV6       */
   while (TRUE) {                           /* loop for AVL tree       */
     bol_first = TRUE;                      /* AVL tree first          */
     while (TRUE) {                         /* loop for sequential retrieval */
       bol1 = m_htree1_avl_getnext( NULL, adsl_htree1_avl_cntl_ineta,
                                    &dsl_htree1_work, bol_first );
       if (bol1 == FALSE) {                 /* error occured           */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_getnext() failed",
                       __LINE__ );
         break;                             /* do not continue         */
       }
       if (dsl_htree1_work.adsc_found == NULL) break;  /* reached end of tree */
       bol_first = FALSE;                   /* AVL tree first          */
       adsl_ts1_w1 = (((struct dsd_tcp_session_1 *) dsl_htree1_work.adsc_found) - 1);  /* structure TCP session */
#ifdef TRACEHL1
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_timer_80: found entry adsl_ts1_w1=%p.",
                     __LINE__, adsl_ts1_w1 );
#endif
       while (adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].imc_func != 0) {  /* TCP connection started */
         memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 0 ][ 0 ],
                 &adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].chrc_header_info[ 0 ],
                 sizeof(UNSIG_MED) );
         memcpy( &unl_sort_ineta.dsrl_ct_ipv4[ 1 ].chrrc_ineta[ 1 ][ 0 ],
                 &adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].chrc_header_info[ sizeof(UNSIG_MED) ],
                 sizeof(UNSIG_MED) );
         adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].adsc_tdc1_in = NULL;  /* input data */
         dsl_subaux_userfld.adsc_sdh_tcp_1 = &adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ];  /* TCP half-session */
         dsl_subaux_userfld.adsc_session_timer = &adsl_ts1_w1->dsrc_session_timer[ 1 ];  /* session timer */
         adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].vpc_userfld = &dsl_subaux_userfld;  /* User Field Subroutine */
         adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].imc_func = DEF_IFUNC_PREP_CLOSE;  /* prepare close */
         memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
         bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                            DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                            &dsl_aux_get_workarea,
                                            sizeof(struct dsd_aux_get_workarea) );
         if (bol1 == FALSE) {               /* error occured           */
           adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
           return;
         }
         adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].achc_work_area = dsl_aux_get_workarea.achc_work_area;  /* addr work-area returned */
         adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].imc_len_work_area = dsl_aux_get_workarea.imc_len_work_area;  /* length work-area returned */
         m_sdhtcp01( &adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ] );  /* call SDH-TCP */
#ifdef TRACEHL1
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_sdhtcp01() prep-close returned %d.",
                       __LINE__, adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].imc_return );
#endif
         adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].imc_func = 0;  /* TCP connection ended */
         if (adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].imc_return != DEF_IRET_END) {  /* not end returned */
           m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W call SDH-TCP prep-close returned %d.",
                         __LINE__, adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].imc_return );
           break;                           /* nothing more to do      */
         }
#ifdef TRACEHL1
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_sdhtcp01() prep-close returned %d adsc_tdc1_out_to_client=%p adsc_tdc1_out_to_server=%p.",
                       __LINE__,
                       adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].imc_return,
                       adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].adsc_tdc1_out_to_client,  /* output data to client */
                       adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].adsc_tdc1_out_to_server );  /* output data to server */
         if (adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].adsc_tdc1_out_to_client) {
           adsl_tdc1_w1 = adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].adsc_tdc1_out_to_client;
           iml1 = 0;
           do {                             /* loop over input data    */
             iml1++;                        /* increment counter input */
             m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T out-to-client %d. addr=%p adsc_gai1=%p imc_len_data=%d/0X%X umc_flags=0X%08X.",
                           __LINE__,
                           iml1,
                           adsl_tdc1_w1,
                           adsl_tdc1_w1->adsc_gai1,
                           adsl_tdc1_w1->imc_len_data,
                           adsl_tdc1_w1->imc_len_data,
                           adsl_tdc1_w1->umc_flags );
             iml2 = adsl_tdc1_w1->imc_len_data;
             adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;
             while (adsl_gai1_w1) {
               if (iml2 <= 0) break;
               iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
               if (iml3 > iml2) iml3 = iml2;
               m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T gather %p length %d/0X%X.",
                             __LINE__, adsl_gai1_w1, iml3, iml3 );
               m_sdh_console_out( &dsl_sdh_call_1, adsl_gai1_w1->achc_ginp_cur, iml3 );
               iml2 -= iml3;
               adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
             }
             adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next in chain */
           } while (adsl_tdc1_w1);
         }
         if (adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].adsc_tdc1_out_to_server) {
           adsl_tdc1_w1 = adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].adsc_tdc1_out_to_server;
           iml1 = 0;
           do {                             /* loop over input data    */
             iml1++;                        /* increment counter input */
             m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T out-to-server %d. addr=%p adsc_gai1=%p imc_len_data=%d/0X%X umc_flags=0X%08X.",
                           __LINE__,
                           iml1,
                           adsl_tdc1_w1,
                           adsl_tdc1_w1->adsc_gai1,
                           adsl_tdc1_w1->imc_len_data,
                           adsl_tdc1_w1->imc_len_data,
                           adsl_tdc1_w1->umc_flags );
             iml2 = adsl_tdc1_w1->imc_len_data;
             adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;
             while (adsl_gai1_w1) {
               if (iml2 <= 0) break;
               iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
               if (iml3 > iml2) iml3 = iml2;
               m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T gather %p length %d/0X%X.",
                             __LINE__, adsl_gai1_w1, iml3, iml3 );
               m_sdh_console_out( &dsl_sdh_call_1, adsl_gai1_w1->achc_ginp_cur, iml3 );
               iml2 -= iml3;
               adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
             }
             adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next in chain   */
           } while (adsl_tdc1_w1);
         }
#endif
         if (adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].adsc_tdc1_out_to_server == NULL) break;
         adsl_tdc1_w1 = adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].adsc_tdc1_out_to_server;  /* output data to server */
         adsl_ts1_w1->dsrc_sdh_tcp_1[ 1 ].adsc_tdc1_out_to_server = NULL;  /* clear output data to server */
         iml_len_ip_header = D_LEN_HEADER_IPV4;  /* length of IP header IPV4 */
         if (bol_ipv6) {                    /* is IPV6, not IPV4       */
           iml_len_ip_header = D_LEN_HEADER_IPV6;  /* length of IP header IPV6 */
         }
#ifdef TRACEHL_111004
         memmove( adsl_contr_1->imrl_trace_lno,
                  adsl_contr_1->imrl_trace_lno + 1,
                  (TRACEHL_111004 - 1) * sizeof(int) );
         adsl_contr_1->imrl_trace_lno[ TRACEHL_111004 - 1 ] = __LINE__;
#endif
         do {                               /* process output of SDH-TCP */
#ifdef TRACEHL1
           m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_timer_80: send output of SDH-TCP prep-close imc_len_data=%d umc_flags=0X%X.",
                         __LINE__, adsl_tdc1_w1->imc_len_data, adsl_tdc1_w1->umc_flags );
#endif
#ifdef TRACEHL_111004
           memmove( adsl_contr_1->imrl_trace_lno,
                    adsl_contr_1->imrl_trace_lno + 1,
                    (TRACEHL_111004 - 1) * sizeof(int) );
           adsl_contr_1->imrl_trace_lno[ TRACEHL_111004 - 1 ] = __LINE__;
#endif
           dsl_oa1.achc_upper -= sizeof(struct dsd_gather_i_1);
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
           if (dsl_oa1.achc_upper < (dsl_oa1.achc_lower + OUT_LEN_NHASN + 1 + iml_len_ip_header)) goto p_out_80;  /* overflow */
#else
           if (dsl_oa1.achc_upper < (dsl_oa1.achc_lower + iml_len_ip_header)) goto p_out_80;  /* overflow */
#endif
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) dsl_oa1.achc_upper)
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
           achl1 = achl2 = dsl_oa1.achc_lower + OUT_LEN_NHASN + 1;
#else
           achl1 = dsl_oa1.achc_lower;
#endif
           iml3 = adsl_tdc1_w1->imc_len_data;  /* length of the data   */
           if (iml3 <= 0) goto p_illogic_00;  /* program illogic       */
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
           *(--achl1) = chl_ipv4_ipv6;      /* type IPV4 / IPV6        */
           iml1 = 1 + iml_len_ip_header + iml3;  /* length of packet   */
           iml2 = 0;                        /* clear more bit          */
           do {
             *(--achl1) = (unsigned char) ((iml1 & 0X7F) | iml2);
             iml1 >>= 7;                    /* remove bits set         */
             iml2 = 0X80;                   /* set more bit            */
           } while (iml1 > 0);
#endif
           ADSL_GAI1_G->achc_ginp_cur = achl1;
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
           ADSL_GAI1_G->achc_ginp_end = achl2 + iml_len_ip_header;
#else
           ADSL_GAI1_G->achc_ginp_end = achl1 + iml_len_ip_header;
#endif
           ADSL_GAI1_G->adsc_next = NULL;
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
           if (bol_ipv6 == FALSE) {         /* is IPV4, not IPV6       */
             m_build_header_ipv4( achl2,
                                  &unl_sort_ineta.dsrl_ct_ipv4[ 1 ],
                                  0,
                                  iml3 );
           } else {                         /* is IPV6, not IPV4       */
             m_build_header_ipv6( achl2,
                                  (struct dsd_ctrl_tcp_ipv6 *) (adsl_ts1_w1 + 1),
                                  0,
                                  iml3 );
           }
           dsl_oa1.achc_lower += OUT_LEN_NHASN + 1 + iml_len_ip_header;
#else
           if (bol_ipv6 == FALSE) {         /* is IPV4, not IPV6       */
             m_build_header_ipv4( achl1,
                                  &unl_sort_ineta.dsrl_ct_ipv4[ 1 ],
                                  0,
                                  iml3 );
           } else {                         /* is IPV6, not IPV4       */
             m_build_header_ipv6( achl1,
                                  (struct dsd_ctrl_tcp_ipv6 *) (adsl_ts1_w1 + 1),
                                  0,
                                  iml3 );
           }
           dsl_oa1.achc_lower += iml_len_ip_header;
#endif
           *aadsrl_gai1_out[ 1 ] = ADSL_GAI1_G;
           aadsrl_gai1_out[ 1 ] = &ADSL_GAI1_G->adsc_next;
           adsl_gai1_w1 = adsl_tdc1_w1->adsc_gai1;  /* data            */
           if (adsl_gai1_w1 == NULL) goto p_illogic_00;  /* program illogic */

           do {                             /* process output of SDH-TCP */
             dsl_oa1.achc_upper -=sizeof(struct dsd_gather_i_1);
             if (dsl_oa1.achc_upper < dsl_oa1.achc_lower) goto p_out_80;  /* overflow */
             iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
             if (iml1 > iml3) iml1 = iml3;  /* only what is needed     */
             ADSL_GAI1_G->achc_ginp_cur = adsl_gai1_w1->achc_ginp_cur;
             ADSL_GAI1_G->achc_ginp_end = adsl_gai1_w1->achc_ginp_cur + iml1;
             ADSL_GAI1_G->adsc_next = NULL;
             *aadsrl_gai1_out[ 1 ] = ADSL_GAI1_G;
             aadsrl_gai1_out[ 1 ] = &ADSL_GAI1_G->adsc_next;
             iml3 -= iml1;                  /* count data processed    */
             if (iml3 <= 0) break;          /* we do not need more data */
             adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next input in chain */
           } while (adsl_gai1_w1);
#ifdef TRACEHL_111004
           memmove( adsl_contr_1->imrl_trace_lno,
                    adsl_contr_1->imrl_trace_lno + 1,
                    (TRACEHL_111004 - 1) * sizeof(int) );
           adsl_contr_1->imrl_trace_lno[ TRACEHL_111004 - 1 ] = __LINE__;
#endif
           adsl_tdc1_w1 = adsl_tdc1_w1->adsc_next;  /* get next in chain */
         } while (adsl_tdc1_w1);
         break;
       }
     }
     if (adsl_htree1_avl_cntl_ineta != &adsl_contr_1->dsc_htree1_avl_cntl_ineta_ipv4) break;
     adsl_htree1_avl_cntl_ineta = &adsl_contr_1->dsc_htree1_avl_cntl_ineta_ipv6;
     bol_ipv6 = TRUE;                       /* is IPV6, not IPV4       */
   }

   p_close_80:                              /* end of session closing  */
   if (adsl_contr_1->adsc_session_notify) {  /* session notify send possible */
     adsp_hl_clib_1->boc_notify_send_client_possible = TRUE;  /* notify SDH when sending to the client is possible */
   }
#ifdef TRACEHL_TIMER_01
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T SDH returns p_timer_80 adsc_session_timer=%p ilc_epoch_set=%lld.",
                 __LINE__, adsl_contr_1->adsc_session_timer, adsl_contr_1->ilc_epoch_set );
#endif
#ifdef CHECK_OUTPUT_01
   m_check_output_01( adsp_hl_clib_1 );
#endif
#ifdef PACKET_LOSS_01                       /* lose packets            */
   adsl_contr_1->imc_packet_loss_01--;      /* count to lose packets   */
   if (adsl_contr_1->imc_packet_loss_01 <= 0) {  /* count to lose packets */
     adsp_hl_clib_1->adsc_gai1_out_to_client = NULL;  /* output data to client */
     adsp_hl_clib_1->adsc_gai1_out_to_server = NULL;  /* output data to server */
     adsl_contr_1->imc_packet_loss_01 = PACKET_LOSS_01;  /* count to lose packets */
   }
#endif
   return;                                  /* all done                */

   p_cleanup_00:                            /* do cleanup              */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-I TCP sessions started=%d current=%d maximum-concurrent=%d.",
                 __LINE__,
                 adsl_contr_1->imc_session_start,  /* count times session start */
                 adsl_contr_1->imc_session_cur,  /* current sessions   */
                 adsl_contr_1->imc_session_max );  /* maximum number of sessions reached */
   adsl_htree1_avl_cntl_ineta = &adsl_contr_1->dsc_htree1_avl_cntl_ineta_ipv4;
   bol_ipv6 = FALSE;                        /* is IPV4, not IPV6       */
   while (TRUE) {                           /* loop for AVL tree       */
     bol_first = TRUE;                      /* AVL tree first          */
     while (TRUE) {                         /* loop for sequential retrieval */
       bol1 = m_htree1_avl_getnext( NULL, adsl_htree1_avl_cntl_ineta,
                                    &dsl_htree1_work, bol_first );
       if (bol1 == FALSE) {                 /* error occured           */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_getnext() failed",
                       __LINE__ );
         break;                             /* do not continue         */
       }
       if (dsl_htree1_work.adsc_found == NULL) break;  /* reached end of tree */
       bol_first = FALSE;                   /* AVL tree first          */
       adsl_ts1_w1 = (((struct dsd_tcp_session_1 *) dsl_htree1_work.adsc_found) - 1);  /* structure TCP session */
#ifdef TRACEHL1
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_cleanup_00: found entry adsl_ts1_w1=%p.",
                     __LINE__, adsl_ts1_w1 );
#endif
       bol1 = TRUE;                         /* remove memory           */
       while (bol_ipv6 == FALSE) {          /* is IPV4, not IPV6       */
         if (((struct dsd_sort_tcp_ipv4 *) ((char *) dsl_htree1_work.adsc_found))->dsc_ct_ipv4.iec_cti4
                == ied_cti4_s5_server) {    /* Socks server TCP half-session */
           bol1 = FALSE;                    /* cannot free memory      */
           break;
         }
         if (   (   (adsl_ts1_w1->adsc_tcpse1_ext_1 == NULL)  /* no TCP session extension */
                 || (adsl_ts1_w1->adsc_tcpse1_ext_1->iec_tce1s == ied_tce1s_socks5_wait_connect))  /* wait for connect of other half-session */
             && (((struct dsd_ctrl_tcp_ipv4 *) ((struct dsd_htree1_avl_entry *) (adsl_ts1_w1 + 1)) + 1)->iec_cti4
                    == ied_cti4_s5_client)) {  /* Socks client TCP half-session */
           ((struct dsd_sort_tcp_ipv4 *) ((char *) dsl_htree1_work.adsc_found))->dsc_ct_ipv4.iec_cti4
             = ied_cti4_normal;             /* from now on normal TCP half-session */
           bol_first = TRUE;                /* AVL tree first - start from new */
#define ADSL_SORT_TCP_IPV4_SERVER ((struct dsd_sort_tcp_ipv4 *) ((char *) (adsl_ts1_w1 + 1) + sizeof(struct dsd_sort_tcp_ipv4)))
           bol1 = m_htree1_avl_search( NULL, adsl_htree1_avl_cntl_ineta,
                                       &dsl_htree1_work, &ADSL_SORT_TCP_IPV4_SERVER->dsc_sort_ineta );
           if (bol1 == FALSE) {             /* error occured           */
             m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_search() failed",
                           __LINE__ );
             break;                         /* cannot delete entry     */
           }
           if (dsl_htree1_work.adsc_found == NULL) {  /* entry not found */
             m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_htree1_avl_search() did not find entry to be deleted",
                           __LINE__ );
             bol1 = FALSE;                  /* cannot free memory      */
             break;                         /* cannot delete entry     */
           }
           bol1 = m_htree1_avl_delete( NULL, adsl_htree1_avl_cntl_ineta,
                                       &dsl_htree1_work );
           if (bol1 == FALSE) {             /* error occured           */
             m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_delete() failed",
                           __LINE__ );
           }
           bol1 = FALSE;                    /* cannot free memory      */
           break;                           /* do not delete entry in AVL-tree */
#undef ADSL_SORT_TCP_IPV4_SERVER
         }
#ifdef TRACEHL1
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_cleanup_00: call avl-delete at adsl_ts1_w1=%p.",
                       __LINE__, adsl_ts1_w1 );
#endif
         bol1 = m_htree1_avl_delete( NULL, adsl_htree1_avl_cntl_ineta,
                                     &dsl_htree1_work );
         if (bol1 == FALSE) {                     /* error occured           */
           m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_delete() failed",
                         __LINE__ );
         }
         break;
       }
       if (bol1) {                          /* remove memory           */
#ifdef TRACEHL1
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_cleanup_00: remove memory at adsl_ts1_w1=%p.",
                       __LINE__, adsl_ts1_w1 );
#endif
         if (adsl_ts1_w1->adsc_tcpse1_ext_1) {  /* TCP session extension */
           bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                           DEF_AUX_MEMFREE,
                                           &adsl_ts1_w1->adsc_tcpse1_ext_1,
                                           0 );
           if (bol1 == FALSE) {             /* error occured           */
             adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
             return;
           }
         }
         bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                         DEF_AUX_MEMFREE,
                                         &adsl_ts1_w1,
                                         0 );
         if (bol1 == FALSE) {                 /* error occured           */
           adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
           return;
         }
       }
     }
     if (adsl_htree1_avl_cntl_ineta != &adsl_contr_1->dsc_htree1_avl_cntl_ineta_ipv4) break;
     adsl_htree1_avl_cntl_ineta = &adsl_contr_1->dsc_htree1_avl_cntl_ineta_ipv6;
     bol_ipv6 = TRUE;                       /* is IPV6, not IPV4       */
   }
   adsl_cc1_ext_w1 = adsl_contr_1->adsc_cc1_ext;  /* structure session control extension */
   while (adsl_cc1_ext_w1) {                /* loop over all extensions */
     adsl_cc1_ext_w2 = adsl_cc1_ext_w1->adsc_next;  /* save next in chain */
     bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                     DEF_AUX_MEMFREE,
                                     &adsl_cc1_ext_w1,
                                     sizeof(struct dsd_clib1_contr_1) );
     if (bol1 == FALSE) {                   /* error occured           */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
     adsl_cc1_ext_w1 = adsl_cc1_ext_w2;     /* get saved next in chain */
   }
   adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code          */
   bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                   DEF_AUX_MEMFREE,
                                   &adsp_hl_clib_1->ac_ext,
                                   sizeof(struct dsd_clib1_contr_1) );
   if (bol1 == FALSE) {                     /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
   }
   return;
} /* end m_hlclib01()                                                  */

static BOOL m_sub_aux( void * vpp_userfld, int imp_func, void * ap_param, int imp_length ) {
#ifdef XYZ1
   char       *achl1;                       /* working-variable        */
   int        iml1;                         /* working-variable        */
   struct dsd_workarea_1 *adsl_workarea_1_w1;  /* work area            */
#endif
   struct dsd_clib1_contr_1 *adsl_contr_1;  /* for addressing          */
   struct dsd_session_timer *adsl_session_timer_w1;  /* session timer  */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */

#define X_ADSL_PARAM  *((void **) ap_param)
#define ADSL_SUBAUX_UF ((struct dsd_subaux_userfld *) vpp_userfld)  /* for aux calls */
#define ADSL_HL_CLIB_1 ADSL_SUBAUX_UF->adsc_hl_clib_1
#ifdef TRACEHL1
   dsl_sdh_call_1.amc_aux = ADSL_HL_CLIB_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = ADSL_HL_CLIB_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_sub_aux() imp_func=%d adsc_sdh_tcp_1=%p.",
                 __LINE__, imp_func, ADSL_SUBAUX_UF->adsc_sdh_tcp_1 );
#endif
   switch (imp_func) {                      /* depend on function      */
     case DEF_AUX_MEMGET:                   /* get some memory         */
     case DEF_AUX_MEMFREE:                  /* free memory             */
     case DEF_AUX_GET_WORKAREA:             /* get additional work area */
     case DEF_AUX_CONSOLE_OUT:
     case DEF_AUX_CO_UNICODE:
     case DEF_AUX_RANDOM_RAW:
     case DEF_AUX_RANDOM_BASE64:
     case DEF_AUX_MARK_WORKAREA_INC:        /* increment usage count in work area */
     case DEF_AUX_MARK_WORKAREA_DEC:        /* decrement usage count in work area */
     case DEF_AUX_WSP_TRACE:                /* write WSP trace         */
       return (*ADSL_HL_CLIB_1->amc_aux)( ADSL_HL_CLIB_1->vpc_userfld,
                                          imp_func, ap_param, imp_length );
     case DEF_AUX_GET_T_MSEC:               /* get time / epoch in milliseconds */
       if (imp_length != sizeof(HL_LONGLONG)) return FALSE;  /* invalid size */
       if ((((HL_LONGLONG) ap_param) & (sizeof(void *) - 1))) return FALSE;  /* misaligned */
       *((HL_LONGLONG *) ap_param) = ADSL_SUBAUX_UF->ilc_epoch;
       return TRUE;                         /* all done                */
     case DEF_AUX_TIMER1_SET:               /* set timer in milliseconds */
     case DEF_AUX_TIMER1_REL:               /* release timer set before */
       goto p_timer_00;                     /* release the timer, when set */
     case DEF_AUX_TIMER1_QUERY:             /* return struct dsd_timer1_ret */
       if (imp_length != sizeof(struct dsd_timer1_ret)) return FALSE;
#define ADSL_TIMER1_RET_G ((struct dsd_timer1_ret *) ap_param)
       ADSL_TIMER1_RET_G->ilc_epoch = ADSL_SUBAUX_UF->ilc_epoch;  /* epoch in milliseconds */
       if (ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end == 0) {  /* epoch timer not set */
         ADSL_TIMER1_RET_G->boc_timer_set = FALSE;  /* a timer is not set */
         ADSL_TIMER1_RET_G->ilc_timer = 0;  /* epoch when timer elapses */
         return TRUE;                       /* all done                */
       }
       ADSL_TIMER1_RET_G->boc_timer_set = TRUE;  /* a timer is set     */
       ADSL_TIMER1_RET_G->ilc_timer = ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end;  /* epoch when timer elapses */
       return TRUE;                         /* all done                */
#undef ADSL_TIMER1_RET_G
   }
   return FALSE;

   p_timer_00:                              /* release the timer, when set */
   adsl_contr_1 = (struct dsd_clib1_contr_1 *) ADSL_HL_CLIB_1->ac_ext;
   if (ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end == 0) {  /* epoch timer not set */
     goto p_timer_60;                       /* set the timer           */
   }
   ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end = 0;  /* reset epoch timer */
   if (ADSL_SUBAUX_UF->adsc_session_timer == adsl_contr_1->adsc_session_timer) {  /* is first in chain */
     adsl_contr_1->adsc_session_timer = adsl_contr_1->adsc_session_timer->adsc_next;  /* remove from chain */
     goto p_timer_60;                       /* set the timer           */
   }
   adsl_session_timer_w1 = adsl_contr_1->adsc_session_timer;  /* get chain */
   if (adsl_session_timer_w1 == NULL) {     /* chain is empty          */
     goto p_timer_40;                       /* timer chain corrupted   */
   }

   p_timer_20:                              /* search timer in chain   */
   if (ADSL_SUBAUX_UF->adsc_session_timer == adsl_session_timer_w1->adsc_next) {  /* check if next from here */
     adsl_session_timer_w1->adsc_next = adsl_session_timer_w1->adsc_next->adsc_next;  /* remove entry from chain */
     goto p_timer_60;                       /* set the timer           */
   }
   adsl_session_timer_w1 = adsl_session_timer_w1->adsc_next;  /* get next in chain */
   if (adsl_session_timer_w1) goto p_timer_20;  /* search timer in chain */

   p_timer_40:                              /* timer chain corrupted   */
   dsl_sdh_call_1.amc_aux = ADSL_HL_CLIB_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = ADSL_HL_CLIB_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_sub_aux() imp_func=%d adsc_sdh_tcp_1=%p timer chain corrupted",
                 __LINE__, imp_func, ADSL_SUBAUX_UF->adsc_sdh_tcp_1 );

   p_timer_60:                              /* set the timer           */
   ADSL_SUBAUX_UF->adsc_sdh_tcp_1->boc_timer_running = FALSE;  /* timer is currently not running */
   if (imp_func != DEF_AUX_TIMER1_SET) return TRUE;  /* do not set timer in milliseconds */
   ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end = ADSL_SUBAUX_UF->ilc_epoch + imp_length;  /* set epoch timer */
   ADSL_SUBAUX_UF->adsc_sdh_tcp_1->boc_timer_running = TRUE;  /* timer is currently running */
#ifdef TRACEHL_TIMER_01
   dsl_sdh_call_1.amc_aux = ADSL_HL_CLIB_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = ADSL_HL_CLIB_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T set timer    adsc_sdh_tcp_1=%p adsc_session_timer=%p ilc_epoch_end=%lld.",
                 __LINE__, ADSL_SUBAUX_UF->adsc_sdh_tcp_1, ADSL_SUBAUX_UF->adsc_session_timer, ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end );
#endif
// ADSL_SUBAUX_UF->adsc_session_timer->adsc_next = NULL;  /* clear chain */
   if (   (adsl_contr_1->adsc_session_timer == NULL)  /* chain is empty */
       || (ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end < adsl_contr_1->adsc_session_timer->ilc_epoch_end)) {
     ADSL_SUBAUX_UF->adsc_session_timer->adsc_next = adsl_contr_1->adsc_session_timer;  /* set chain */
     adsl_contr_1->adsc_session_timer = ADSL_SUBAUX_UF->adsc_session_timer;  /* set new anchor */
     return TRUE;                           /* all done                */
   }
   adsl_session_timer_w1 = adsl_contr_1->adsc_session_timer;  /* get chain */
   while (   (adsl_session_timer_w1->adsc_next)
          && (adsl_session_timer_w1->adsc_next->ilc_epoch_end <= ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end)) {
     adsl_session_timer_w1 = adsl_session_timer_w1->adsc_next;  /* get next in chain */
   }
   ADSL_SUBAUX_UF->adsc_session_timer->adsc_next = adsl_session_timer_w1->adsc_next;  /* set end of chain */
   adsl_session_timer_w1->adsc_next = ADSL_SUBAUX_UF->adsc_session_timer;  /* insert new entry in chain */
   return TRUE;                             /* all done                */

#undef X_ADSL_PARAM
#undef ADSL_SUBAUX_UF
#undef ADSL_HL_CLIB_1
} /* end m_sub_aux()                                                   */

static void m_build_header_ipv4( char *achp_buffer, struct dsd_ctrl_tcp_ipv4 *adsp_ct_ipv4, int imp_cl_se, int imp_len_data ) {
   int        iml1;                         /* working variable        */
   int        iml_chs;                      /* calculate checksum      */
   char       *achl1, *achl2;               /* working variables       */

   memset( achp_buffer, 0, D_LEN_HEADER_IPV4 );  /* length of IPV4 header minimum */
   iml1 = D_LEN_HEADER_IPV4 + imp_len_data;
   *(achp_buffer + 0) = (unsigned char) ((4 << 4) | (D_LEN_HEADER_IPV4 >> 2));
   *(achp_buffer + 2) = (unsigned char) (iml1 >> 8);
   *(achp_buffer + 3) = (unsigned char) iml1;
   *(achp_buffer + 8) = (unsigned char) 128;  /* TTL                   */
   *(achp_buffer + 9) = (unsigned char) IPPROTO_TCP;
   memcpy( achp_buffer + 12, &adsp_ct_ipv4->chrrc_ineta[ imp_cl_se ][ 0 ], 4 );
   memcpy( achp_buffer + 16, &adsp_ct_ipv4->chrrc_ineta[ imp_cl_se ^ 1 ][ 0 ], 4 );
   /* calculate checksum of IP-header                                  */
   achl1 = achp_buffer;                     /* start of IP header      */
   achl2 = achl1 + D_LEN_HEADER_IPV4;       /* end of IP header        */
   iml_chs = 0;                             /* calculate checksum      */
   do {                                     /* loop over IP header     */
     /* calculate checksum                                             */
     iml_chs += (*((unsigned char *) achl1 + 0) << 8)
                  | *((unsigned char *) achl1 + 1);
     achl1 += 2;                            /* next position in header */
   } while (achl1 < achl2);
   while ((iml_chs >> 16) != 0) {           /* continue carry          */
     iml_chs = (iml_chs & 0X0000FFFF) + (iml_chs >> 16);
   }
   iml_chs = ~iml_chs;                      /* negate result           */
   *((unsigned char *) achp_buffer + D_POS_IPH_DCHS + 0) = (unsigned char) (iml_chs >> 8);
   *((unsigned char *) achp_buffer + D_POS_IPH_DCHS + 1) = (unsigned char) iml_chs;
} /* end m_build_header_ipv4()                                         */

static void m_build_header_ipv6( char *achp_buffer, struct dsd_ctrl_tcp_ipv6 *adsp_ct_ipv6, int imp_cl_se, int imp_len_data ) {
// int        iml1;                         /* working variable        */
// int        iml_chs;                      /* calculate checksum      */
// char       *achl1, *achl2;               /* working variables       */

   memset( achp_buffer, 0, D_LEN_HEADER_IPV6 );  /* length of IPV6 header */
// iml1 = D_LEN_HEADER_IPV6 + imp_len_data;
   *(achp_buffer + 0) = (unsigned char) (6 << 4);
// *(achp_buffer + 4 + 0) = (unsigned char) (iml1 >> 8);
// *(achp_buffer + 4 + 1) = (unsigned char) iml1;
   *(achp_buffer + 4 + 0) = (unsigned char) (imp_len_data >> 8);
   *(achp_buffer + 4 + 1) = (unsigned char) imp_len_data;
   *(achp_buffer + 6) = (unsigned char) IPPROTO_TCP;
   *(achp_buffer + 6) = (unsigned char) 128;  /* TTL                   */
   memcpy( achp_buffer + 8, &adsp_ct_ipv6->chrrc_ineta[ imp_cl_se ][ 0 ], 16 );
   memcpy( achp_buffer + 24, &adsp_ct_ipv6->chrrc_ineta[ imp_cl_se ^ 1 ][ 0 ], 16 );
} /* end m_build_header_ipv6()                                         */

static int m_get_ineta_w( UNSIG_MED *amp_ineta, HL_WCHAR *awcp_value ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working variables       */
   HL_WCHAR   *awcl1;                       /* working variable        */
   unsigned char chrl_ineta_w1[4];          /* INETA                   */

   iml1 = 0;                                /* first digit             */
   awcl1 = awcp_value;                      /* get value               */

   p_ineta_20:                              /* retrieve number of INETA */
   iml2 = 0;                                /* clear number            */
   bol1 = FALSE;                            /* no digit yet            */
   while ((*awcl1 >= '0') && (*awcl1 <= '9')) {
// to-do 24.11.13 KB - check if 0n
// maybe bol1 && (iml2 == 0)
     iml2 *= 10;                            /* shift old value         */
     iml2 += *awcl1 - '0';
     if (iml2 >= 256) return -1;
     awcl1++;                               /* next digit              */
     bol1 = TRUE;                           /* digit found             */
   }
   if (bol1 == FALSE) return -1;            /* no digit found          */
   chrl_ineta_w1[ iml1++ ] = (unsigned char) iml2;
   if (iml1 == 4) {                         /* all parts set           */
     if (*awcl1 != 0) return -1;            /* too many parts          */
     /* INETA decoded                                                  */
     *amp_ineta = *((UNSIG_MED *) chrl_ineta_w1);
     return 0;                              /* all valid               */
   }
   if (*awcl1 == '.') {                     /* separator found         */
     awcl1++;                               /* next character          */
     goto p_ineta_20;                       /* retrieve number of INETA */
   }
   return -1;
} /* end m_get_ineta_w()                                               */

/** retrieve INETA of string                                           */
static int m_get_ineta_a( UNSIG_MED *amp_ineta, char *achp_value, char *achp_end ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working variables       */
   char       *achl1;                       /* working variable        */
   unsigned char chrl_ineta_w1[4];          /* INETA                   */

   iml1 = 0;                                /* first digit             */
   achl1 = achp_value;                      /* get value               */

   p_ineta_20:                              /* retrieve number of INETA */
   iml2 = 0;                                /* clear number            */
   bol1 = FALSE;                            /* no digit yet            */
   while ((achl1 < achp_end) && (*achl1 >= '0') && (*achl1 <= '9')) {
// to-do 24.11.13 KB - check if 0n
// maybe bol1 && (iml2 == 0)
     iml2 *= 10;                            /* shift old value         */
     iml2 += *achl1 - '0';
     if (iml2 >= 256) return -1;
     achl1++;                               /* next digit              */
     bol1 = TRUE;                           /* digit found             */
   }
   if (bol1 == FALSE) return -1;            /* no digit found          */
   chrl_ineta_w1[ iml1++ ] = (unsigned char) iml2;
   if (iml1 == 4) {                         /* all parts set           */
     if (achl1 != achp_end) return -1;      /* too many parts          */
     /* INETA decoded                                                  */
     *amp_ineta = *((UNSIG_MED *) chrl_ineta_w1);
     return 0;                              /* all valid               */
   }
   if (*achl1 == '.') {                     /* separator found         */
     achl1++;                               /* next character          */
     goto p_ineta_20;                       /* retrieve number of INETA */
   }
   return -1;
} /* end m_get_ineta_a()                                               */

/** retrieve INETA + port of string for FTP                            */
static BOOL m_get_decno_6( char *achp_out, char *achp_value, char *achp_end ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working variables       */
   char       *achl1;                       /* working variable        */

   iml1 = 0;                                /* first digit             */
   achl1 = achp_value;                      /* get value               */

   p_ineta_20:                              /* retrieve number of INETA */
   iml2 = 0;                                /* clear number            */
   bol1 = FALSE;                            /* no digit yet            */
   while ((achl1 < achp_end) && (*achl1 >= '0') && (*achl1 <= '9')) {
// to-do 24.11.13 KB - check if 0n
// maybe bol1 && (iml2 == 0)
     iml2 *= 10;                            /* shift old value         */
     iml2 += *achl1 - '0';
     if (iml2 >= 256) return FALSE;
     achl1++;                               /* next digit              */
     bol1 = TRUE;                           /* digit found             */
   }
   if (bol1 == FALSE) return FALSE;         /* no digit found          */
   *(achp_out + iml1) = (unsigned char) iml2;
   iml1++;                                  /* count output            */
   if (iml1 == 6) {                         /* all parts set           */
     if (achl1 != achp_end) return FALSE;   /* too many parts          */
     /* INETA + port / number decoded                                  */
     return TRUE;                           /* all valid               */
   }
   if (*achl1 == ',') {                     /* separator found         */
     achl1++;                               /* next character          */
     goto p_ineta_20;                       /* retrieve number of INETA */
   }
   return FALSE;
} /* end m_get_decno_6()                                               */

/** check if an INETA is in the range of private INETAs                */
static BOOL m_check_private_ineta( char *achp_ineta ) {
   int        iml1;                         /* working variable        */
   int        iml_cmp;                      /* for compare             */
   unsigned char *aucl_w1;                  /* working variable        */

   aucl_w1 = (unsigned char *) &ucrrs_private_inetas[0][0];

   p_check_upper:                           /* check upper INETA       */
   iml1 = 0;                                /* clear index             */
   do {
     iml_cmp = *(aucl_w1 + 4 + iml1) - *((unsigned char *) achp_ineta + iml1);
     if (iml_cmp > 0) break;                /* INETA to compare is higher */
     if (iml_cmp < 0) {                     /* INETA to compare is lower */
       goto p_end_range;                    /* not in this range       */
     }
     iml1++;                                /* next digit              */
   } while (iml1 < sizeof(int));
   iml1 = 0;                                /* clear index             */
   do {
     iml_cmp = *(aucl_w1 + iml1) - *((unsigned char *) achp_ineta + iml1);
     if (iml_cmp < 0) break;                /* INETA to compare is lower */
     if (iml_cmp > 0) {                     /* INETA to compare is higher */
       goto p_end_range;                    /* not in this range       */
     }
     if (*((unsigned char *) achp_ineta + iml1) < *(aucl_w1 + iml1)) {
       goto p_end_range;                    /* not in this range       */
     }
     iml1++;                                /* next digit              */
   } while (iml1 < sizeof(int));
   return TRUE;                             /* is private INETA        */

   p_end_range:                             /* not in this range       */
   aucl_w1 += 2 * sizeof(int);              /* next range              */
   if (aucl_w1 < ((unsigned char *) ucrrs_private_inetas + sizeof(ucrrs_private_inetas))) {
     goto p_check_upper;                    /* check upper INETA       */
   }
   return FALSE;                            /* is public INETA         */
} /* end m_check_private_ineta()                                       */

/** return the INETA used in the network of the client                 */
static int m_natted_ineta( struct dsd_hl_clib_1 *adsp_hl_clib_1,
                           char *achp_ineta,
                           struct dsd_conf_ext_1 *adsp_coe1,
                           BOOL bop_disp_inetas ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3;             /* working variables       */
   int        iml_ineta;                    /* INETA for computation   */
   struct dsd_clib1_contr_1 *adsl_contr_1;  /* for addressing          */
   struct dsd_cc1_ext *adsl_cc1_ext_w1;     /* structure session control extension */
   struct dsd_cc1_ext *adsl_cc1_ext_w2;     /* structure session control extension */
   struct dsd_ineta_ctl_1 *adsl_ic1_w1;     /* control INETA           */
   struct dsd_nat_ftp_entry *adsl_nfe_w1;   /* entry for NAT of FTP server */
   struct dsd_nat_ftp_entry *adsl_nfe_w2;   /* entry for NAT of FTP server */
   struct dsd_nat_ftp_ctl_ext *adsl_nfce_w1;  /* control area for NAT of FTP server, extension */
   struct dsd_nat_ftp_ctl_ext *adsl_nfce_w2;  /* control area for NAT of FTP server, extension */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
   struct dsd_ineta_ctl_1 dsl_ic1_l;        /* control INETA           */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */

// dsl_ic1_l.imc_ineta = *((int *) achp_ineta);
   memcpy( &dsl_ic1_l.imc_ineta, achp_ineta, sizeof(UNSIG_MED) );
   bol1 = m_check_private_ineta( achp_ineta );
   if (bol1 == FALSE) {                     /* is public INETA         */
     return dsl_ic1_l.imc_ineta;            /* return the original INETA */
   }
   adsl_contr_1 = (struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext;
   if (dsl_ic1_l.imc_ineta == adsl_contr_1->umc_ineta_cl_int) {  /* INETA client intern in intranet */
     return adsl_contr_1->umc_ineta_client;  /* INETA client in tunnel */
   }
   iml_ineta = adsl_contr_1->umc_ineta_lower;
   bol1 = m_htree1_avl_search( NULL, &adsl_contr_1->dsc_htree1_avl_cntl_ineta,
                               &dsl_htree1_work, &dsl_ic1_l.dsc_sort_ineta );
   if (bol1 == FALSE) {                     /* error occured           */
     dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_search() failed",
                   __LINE__ );
   }
   if (dsl_htree1_work.adsc_found) {        /* entry found             */
#define ADSL_IC1_G ((struct dsd_ineta_ctl_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_ineta_ctl_1, dsc_sort_ineta )))
     if (adsp_coe1) {                       /* mark FTP                */
       ADSL_IC1_G->boc_nat_ftp = TRUE;      /* may be used for FTP     */
#ifdef DEBUG_150116_01                      /* crash NAT / FTP         */
       dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
       dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_natted_ineta() set ADSL_IC1_G->boc_nat_ftp ADSL_IC1_G=%p.",
                     __LINE__, ADSL_IC1_G );
       {
         struct dsd_cc1_ext *adsl_cc1_ext_h1;     /* structure session control extension */
         adsl_cc1_ext_h1 = adsl_contr_1->adsc_cc1_ext;  /* structure session control extension */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_natted_ineta() ->adsc_cc1_ext=%p.",
                       __LINE__, adsl_cc1_ext_h1 );
         while (adsl_cc1_ext_h1) {
           adsl_cc1_ext_h1 = adsl_cc1_ext_h1->adsc_next;
           if (adsl_cc1_ext_h1 == NULL) break;
           m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_natted_ineta() chain ->adsc_cc1_ext=%p.",
                         __LINE__, adsl_cc1_ext_h1 );
         }
       }
#endif
     }
#undef ADSL_IC1_G
     if (   (((char *) dsl_htree1_work.adsc_found) >= ((char *) adsl_contr_1->dsrc_ic1))  /* lower address */
         && (((char *) dsl_htree1_work.adsc_found) < ((char *) adsl_contr_1->dsrc_ic1 + sizeof(adsl_contr_1->dsrc_ic1)))) {  /* upper address */
       iml1 = (((char *) dsl_htree1_work.adsc_found) - ((char *) adsl_contr_1->dsrc_ic1))
                / sizeof(struct dsd_ineta_ctl_1);
       goto p_ret_ineta;                    /* return INETA, iml1 contains index */
     }
     iml1 = DEF_INETA_TABLE_ORG;            /* number of entries original table */
     adsl_cc1_ext_w1 = adsl_contr_1->adsc_cc1_ext;  /* structure session control extension */
     while (adsl_cc1_ext_w1) {              /* loop over all extensions */
       if (   (((char *) dsl_htree1_work.adsc_found) >= ((char *) adsl_cc1_ext_w1->dsrc_ic1))  /* lower address */
           && (((char *) dsl_htree1_work.adsc_found) < ((char *) adsl_cc1_ext_w1->dsrc_ic1 + sizeof(adsl_cc1_ext_w1->dsrc_ic1)))) {  /* upper address */
         iml1 += (((char *) dsl_htree1_work.adsc_found) - ((char *) adsl_cc1_ext_w1->dsrc_ic1))
                  / sizeof(struct dsd_ineta_ctl_1);
         goto p_ret_ineta;                  /* return INETA, iml1 contains index */
       }
       iml1 += DEF_INETA_TABLE_EXT;         /* number of entries extension */
       adsl_cc1_ext_w1 = adsl_cc1_ext_w1->adsc_next;  /* get next in chain */
     }
   }
   /* create new entry                                                 */
   iml1 = adsl_contr_1->imc_alloc;          /* number of INETAs allocated */
   adsl_contr_1->imc_alloc++;               /* number of INETAs allocated */
   if (iml1 < DEF_INETA_TABLE_ORG) {        /* number of entries original table */
     adsl_ic1_w1 = &adsl_contr_1->dsrc_ic1[ iml1 ];  /* control INETA  */
   } else {                                 /* use extension           */
     iml2 = iml1 - DEF_INETA_TABLE_ORG;     /* number of entries original table */
     adsl_cc1_ext_w1 = adsl_contr_1->adsc_cc1_ext;  /* structure session control extension */
     adsl_cc1_ext_w2 = NULL;                /* clear last element      */
     while (iml2 >= DEF_INETA_TABLE_EXT) {  /* number of entries extension */
       iml2 -= DEF_INETA_TABLE_EXT;         /* number of entries extension */
       adsl_cc1_ext_w2 = adsl_cc1_ext_w1;   /* save last element       */
       adsl_cc1_ext_w1 = adsl_cc1_ext_w1->adsc_next;  /* get next in chain */
     }
     if (adsl_cc1_ext_w1 == NULL) {         /* need to allocate new extension */
       bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                       DEF_AUX_MEMGET,
                                       &adsl_cc1_ext_w1,
                                       sizeof(struct dsd_cc1_ext) );
       if (bol1 == FALSE) {
         dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
         dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W aux( DEF_AUX_MEMGET ) failed",
                       __LINE__ );
       }
       adsl_cc1_ext_w1->adsc_next = NULL;   /* clear chain field       */
       if (adsl_cc1_ext_w2 == NULL) {       /* first extension         */
         adsl_contr_1->adsc_cc1_ext = adsl_cc1_ext_w1;  /* structure session control extension */
       } else {                             /* next extension          */
         adsl_cc1_ext_w2->adsc_next = adsl_cc1_ext_w1;  /* append new extension */
       }
     }
     adsl_ic1_w1 = &adsl_cc1_ext_w1->dsrc_ic1[ iml2 ];  /* control INETA */
   }
   adsl_ic1_w1->imc_ineta = *((int *) achp_ineta);
   adsl_ic1_w1->boc_nat_ftp = FALSE;        /* reset may be used for FTP */
   if (adsp_coe1) {                         /* mark FTP                */
     adsl_ic1_w1->boc_nat_ftp = TRUE;       /* may be used for FTP     */
#ifdef DEBUG_150116_01                      /* crash NAT / FTP         */
     dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_natted_ineta() set adsl_ic1_w1->boc_nat_ftp adsl_ic1_w1=%p.",
                   __LINE__, adsl_ic1_w1 );
     {
       struct dsd_cc1_ext *adsl_cc1_ext_h1;     /* structure session control extension */
       adsl_cc1_ext_h1 = adsl_contr_1->adsc_cc1_ext;  /* structure session control extension */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_natted_ineta() ->adsc_cc1_ext=%p.",
                     __LINE__, adsl_cc1_ext_h1 );
       while (adsl_cc1_ext_h1) {
         adsl_cc1_ext_h1 = adsl_cc1_ext_h1->adsc_next;
         if (adsl_cc1_ext_h1 == NULL) break;
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_natted_ineta() chain ->adsc_cc1_ext=%p.",
                       __LINE__, adsl_cc1_ext_h1 );
       }
     }
#endif
   }
   bol1 = m_htree1_avl_insert( NULL, &adsl_contr_1->dsc_htree1_avl_cntl_ineta,
                               &dsl_htree1_work, &adsl_ic1_w1->dsc_sort_ineta );
   if (bol1 == FALSE) {                     /* error occured           */
     dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W m_htree1_avl_insert() failed",
                   __LINE__ );
   }
   m_ineta_op_add( (char *) &iml_ineta, sizeof(int), 2 + iml1 );
   adsl_contr_1->umc_ineta_max_used = iml_ineta;  /* set upper INETA   */
   if (bop_disp_inetas) {                   /* display natted INETAs   */
     dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-I apply NAT to original INETA %d.%d.%d.%d using INETA %d.%d.%d.%d.",
                   __LINE__,
                   *((unsigned char *) &dsl_ic1_l.imc_ineta + 0),
                   *((unsigned char *) &dsl_ic1_l.imc_ineta + 1),
                   *((unsigned char *) &dsl_ic1_l.imc_ineta + 2),
                   *((unsigned char *) &dsl_ic1_l.imc_ineta + 3),
                   *((unsigned char *) &iml_ineta + 0),
                   *((unsigned char *) &iml_ineta + 1),
                   *((unsigned char *) &iml_ineta + 2),
                   *((unsigned char *) &iml_ineta + 3) );
   }
   if (memcmp( &adsl_contr_1->umc_ineta_max_used,
               &adsl_contr_1->umc_ineta_upper,
               sizeof(UNSIG_MED) )
         <= 0) {
//   return iml_ineta;
     goto p_mark_ftp_00;                    /* mark for FTP            */
   }
   dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W use non-configured NAT INETA %d.%d.%d.%d.",
                 __LINE__,
                 *((unsigned char *) &iml_ineta + 0),
                 *((unsigned char *) &iml_ineta + 1),
                 *((unsigned char *) &iml_ineta + 2),
                 *((unsigned char *) &iml_ineta + 3) );
   return iml_ineta;

   p_ret_ineta:                             /* return INETA, iml1 contains index */
   m_ineta_op_add( (char *) &iml_ineta, sizeof(int), 2 + iml1 );

   p_mark_ftp_00:                           /* mark for FTP            */
   if (adsp_coe1 == NULL) {                 /* do not mark FTP         */
     return iml_ineta;                      /* all done                */
   }
#define ADSL_NFCO ((struct dsd_nat_ftp_ctl_org *) (((struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext) + 1))  /* control area for NAT of FTP server, first */
   iml1 = ADSL_NFCO->imc_no_nat_ftp_entries;  /* number of entries for NAT of FTP */
   iml2 = iml3 = DEF_NAT_FTP_TABLE_ORG;     /* number of entries first chunk */
   adsl_nfe_w1 = ADSL_NFCO->dsrc_nfe;       /* entry for NAT of FTP server */
   adsl_nfe_w2 = NULL;                      /* no entry before for NAT of FTP server */
   adsl_nfce_w1 = NULL;                     /* control area for NAT of FTP server, extension */
   if (iml2 > iml1) iml2 = iml1;            /* set remaining in this chunk */
   iml3 -= iml2;                            /* remaining entries in this chunk */
   if (iml1 <= 0) goto p_mark_ftp_40;       /* all entries have been checked, not found */
   iml1 -= iml2;                            /* number of remaining entries */

   p_mark_ftp_20:                           /* check entry             */
   if (adsl_nfe_w1->umc_ineta == ((UNSIG_MED) iml_ineta)) {  /* check INETA used */
     if (adsl_nfe_w1->adsc_coe1 == adsp_coe1) {  /* check configuration extension */
       return iml_ineta;                    /* all done                */
     }
     adsl_nfe_w2 = adsl_nfe_w1;             /* save this entry         */
   }
   adsl_nfe_w1++;                           /* next entry              */
   iml2--;                                  /* entry has been processed */
   if (iml2 > 0) {                          /* more entries in this chunk ? */
     goto p_mark_ftp_20;                    /* check entry             */
   }
   if (iml1 <= 0) goto p_mark_ftp_40;       /* all entries have been checked, not found */
   if (adsl_nfce_w1 == NULL) {              /* control area for NAT of FTP server, extension */
     adsl_nfce_w1 = ADSL_NFCO->adsc_nfce;   /* control area for NAT of FTP server, extension */
   } else {                                 /* we are already in extension chunk */
     adsl_nfce_w1 = adsl_nfce_w1->adsc_next;  /* control area for NAT of FTP server, extension */
   }
   if (adsl_nfce_w1 == NULL) {              /* extension not found     */
     dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W NAT of FTP server extension not found",
                   __LINE__ );
     return iml_ineta;                      /* all done                */
   }
   iml2 = iml3 = DEF_NAT_FTP_TABLE_EXT;     /* number of entries extension chunk */
   adsl_nfe_w1 = adsl_nfce_w1->dsrc_nfe;    /* entry for NAT of FTP server */
   if (iml2 > iml1) iml2 = iml1;            /* set remaining in this chunk */
   iml3 -= iml2;                            /* remaining entries in this chunk */
   iml1 -= iml2;                            /* number of remaining entries */
   goto p_mark_ftp_20;                      /* check entry             */

   p_mark_ftp_40:                           /* all entries have been checked, not found */
   if (iml3 > 0) {                          /* remaining entries in this chunk */
     goto p_mark_ftp_60;                    /* create new entry        */
   }
   /* we need a new extension                                          */
   bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                   DEF_AUX_MEMGET,
                                   &adsl_nfce_w2,
                                   sizeof(struct dsd_nat_ftp_ctl_ext) );
   if (bol1 == FALSE) {                     /* error occured           */
     dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W aux( DEF_AUX_MEMGET ) failed",
                   __LINE__ );
   }
#ifdef DEBUG_150116_01                      /* crash NAT / FTP         */
   dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-10-l%05d-T NAT of FTP server created %p.",
                 __LINE__, adsl_nfce_w2 );
#endif
   adsl_nfce_w2->adsc_next = NULL;          /* clear field for chaining */
   if (adsl_nfce_w1 == NULL) {              /* no extension yet        */
     ADSL_NFCO->adsc_nfce = adsl_nfce_w2;   /* control area for NAT of FTP server, extension */
   } else {                                 /* append new extension    */
     adsl_nfce_w1->adsc_next = adsl_nfce_w2;  /* control area for NAT of FTP server, extension */
   }
   adsl_nfe_w1 = adsl_nfce_w2->dsrc_nfe;    /* entry for NAT of FTP server */

   p_mark_ftp_60:                           /* create new entry        */
   adsl_nfe_w1->umc_ineta = ((UNSIG_MED) iml_ineta);  /* set INETA used */
   adsl_nfe_w1->adsc_coe1 = adsp_coe1;      /* set configuration extension */
   adsl_nfe_w1->adsc_next = NULL;           /* clear field for chaining */
   if (adsl_nfe_w2) {                       /* should we append to chain ? */
     adsl_nfe_w2->adsc_next = adsl_nfe_w1;  /* set field for chaining  */
   }
   ADSL_NFCO->imc_no_nat_ftp_entries++;     /* number of entries for NAT of FTP */
   return iml_ineta;                        /* all done                */
#undef ADSL_NFCO
} /* end m_natted_ineta()                                              */

/** return the original INETA                                          */
static int m_original_ineta( struct dsd_hl_clib_1 *adsp_hl_clib_1,
                             char *achp_ineta,
                             struct dsd_nat_ret_val *adsp_nrv ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working variables       */
   int        iml_cmp;                      /* for compare             */
// int        iml_ineta;                    /* INETA passed            */
   struct dsd_clib1_contr_1 *adsl_contr_1;  /* for addressing          */
   struct dsd_cc1_ext *adsl_cc1_ext_w1;     /* structure session control extension */
   struct dsd_ineta_ctl_1 *adsl_ic1_w1;     /* control INETA           */
   struct dsd_nat_ftp_entry *adsl_nfe_w1;   /* entry for NAT of FTP server */
   struct dsd_nat_ftp_ctl_ext *adsl_nfce_w1;  /* control area for NAT of FTP server, extension */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */

// to-do 02.09.11 KB alignment of achp_ineta
   adsl_contr_1 = (struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext;
#ifdef B110822
// iml_ineta = *((int *) achp_ineta);
   iml1 = 0;                                /* clear index             */
   do {                                     /* loop over digits of INETA */
     iml_cmp = *((unsigned char *) &adsl_contr_1->umc_ineta_lower + iml1)
                - *((unsigned char *) achp_ineta + iml1);
     if (iml_cmp < 0) break;                /* all done                */
     if (iml_cmp > 0) goto p_ret_original;  /* return original INETA   */
     iml1++;                                /* increment index         */
   } while (iml1 < sizeof(UNSIG_MED));
   iml1 = 0;                                /* clear index             */
   do {                                     /* loop over digits of INETA */
     iml_cmp = *((unsigned char *) &adsl_contr_1->umc_ineta_upper + iml1)
                - *((unsigned char *) achp_ineta + iml1);
     if (iml_cmp > 0) break;                /* all done                */
     if (iml_cmp < 0) goto p_ret_original;  /* return original INETA   */
     iml1++;                                /* increment index         */
   } while (iml1 < sizeof(UNSIG_MED));
   iml1 = m_ineta_op_diff( achp_ineta, (char *) &adsl_contr_1->umc_ineta_lower, sizeof(int) );
   if (iml1 < 0) {                          /* error occured           */
     dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W original INETA could not be translated 01",
                   __LINE__ );
     goto p_ret_original;                   /* return original INETA   */
   }
#endif
#ifdef DEBUG_110831_01
   if (   (*((unsigned char *) achp_ineta + 0) == 0XAC)
       && (*((unsigned char *) achp_ineta + 1) == 0X10)
       && (*((unsigned char *) achp_ineta + 2) == 0XFF)
       && (*((unsigned char *) achp_ineta + 3) == 0XFF)) {
     dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
#define ADSL_CLCO ((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)
     iml1 = ADSL_CLCO->imc_no_s5_ineta_nat;  /* number of reserved INETAs for Socks servers */
#undef ADSL_CLCO
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W INETA DEBUG_110831_01 found iml1=%d.",
                   __LINE__, iml1 );
   }
#endif
   adsp_nrv->imc_index_so_ineta_nat = -1;   /* index of reserved INETAs for Socks servers */
   adsp_nrv->adsc_nfe = NULL;               /* chain of entries for NAT of FTP server */
   iml1 = m_ineta_op_diff( achp_ineta, (char *) &adsl_contr_1->umc_ineta_lower, sizeof(int) );
   if (iml1 < 0) {                          /* INETA before this range */
     goto p_ret_original;                   /* return original INETA   */
   }
   iml1 -= 2;                               /* subtract offset first entry */
   if (iml1 < 0) {                          /* is control INETA        */
     return adsl_contr_1->umc_ineta_cl_int;  /* INETA client intern in intranet */
   }
   iml2 = m_ineta_op_diff( achp_ineta, (char *) &adsl_contr_1->umc_ineta_upper, sizeof(int) );
#define ADSL_CLCO ((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)
#ifndef B130223
   if (    (iml2 == 0)
       &&  (ADSL_CLCO->boc_internal_dns_server)) {  /* use internal DNS server */
     goto p_ret_original;                   /* return original INETA   */
   }
#endif
#ifdef B110831
   if (iml2 >= 0) {                         /* not in this range       */
     iml2++;                                /* next INETA              */
     if (iml2 <= ADSL_CLCO->imc_no_s5_ineta_nat) {  /* number of reserved INETAs for Socks servers */
       adsp_nrv->imc_index_so_ineta_nat = iml2;  /* index of reserved INETAs for Socks servers */
     }
     goto p_ret_original;                   /* return original INETA   */
   }
#endif
   if (iml2 > 0) {                          /* not in this range       */
     if (iml2 <= ADSL_CLCO->imc_no_s5_ineta_nat) {  /* number of reserved INETAs for Socks servers */
       adsp_nrv->imc_index_so_ineta_nat = iml2 - 1;  /* index of reserved INETAs for Socks servers */
     }
#ifdef DEBUG_110831_01
     dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W INETA DEBUG_110831_01 adsp_nrv->imc_index_so_ineta_nat=%d.",
                   __LINE__, adsp_nrv->imc_index_so_ineta_nat );
#endif
     goto p_ret_original;                   /* return original INETA   */
   }
#undef ADSL_CLCO
#ifndef B150117
   if (iml1 >= adsl_contr_1->imc_alloc) {   /* greater than allocated  */
#ifdef DEBUG_150116_01                      /* crash NAT / FTP         */
     dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T m_original_ineta() iml1=%d iml2=%d adsl_contr_1->imc_alloc=%d.",
                   __LINE__, iml1, iml2, adsl_contr_1->imc_alloc );
#endif
     goto p_ret_original;                   /* return original INETA   */
   }
#endif
   if (iml1 < DEF_INETA_TABLE_ORG) {        /* number of entries original table */
#ifdef B110902
     return adsl_contr_1->dsrc_ic1[ iml1 ].imc_ineta;  /* from control INETA */
#endif
     adsl_ic1_w1 = &adsl_contr_1->dsrc_ic1[ iml1 ];  /* control INETA  */
     goto p_check_ftp_00;                   /* check if FTP            */
   }
   iml1 -= DEF_INETA_TABLE_ORG;             /* number of entries original table */
   if (adsl_contr_1->adsc_cc1_ext == NULL) {  /* structure session control extension */
     dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W original INETA could not be translated 01",
                   __LINE__ );
     goto p_ret_original;                   /* return original INETA   */
   }
   adsl_cc1_ext_w1 = adsl_contr_1->adsc_cc1_ext;  /* structure session control extension */
   while (iml1 >= DEF_INETA_TABLE_EXT) {    /* number of entries extension */
     iml1 -= DEF_INETA_TABLE_EXT;           /* number of entries extension */
     adsl_cc1_ext_w1 = adsl_cc1_ext_w1->adsc_next;  /* get next in chain */
     if (adsl_cc1_ext_w1 == NULL) {
       dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
       dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W original INETA could not be translated 02",
                     __LINE__ );
       goto p_ret_original;                 /* return original INETA   */
     }
   }
   adsl_ic1_w1 = &adsl_cc1_ext_w1->dsrc_ic1[ iml1 ];  /* control INETA */

   p_check_ftp_00:                          /* check if FTP            */
#ifdef DEBUG_110902_01
   {
     unsigned char chrh_ineta_cmp[4] = { 172, 22, 0, 196 };
     if (!memcmp( &adsl_ic1_w1->imc_ineta, chrh_ineta_cmp, sizeof(chrh_ineta_cmp) )) {
       iml1 = 0;
     }
   }
#endif
   if (adsl_ic1_w1->boc_nat_ftp == FALSE) {  /* may not be used for FTP */
     return adsl_ic1_w1->imc_ineta;         /* from control INETA      */
   }
#ifdef DEBUG_150116_01                      /* crash NAT / FTP         */
   dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_check_ftp_00: adsl_ic1_w1=%p ->boc_nat_ftp=%d iml1=%d iml2=%d ->imc_alloc=%d.",
                 __LINE__, adsl_ic1_w1, adsl_ic1_w1->boc_nat_ftp, iml1, iml2, adsl_contr_1->imc_alloc );
   {
     struct dsd_cc1_ext *adsl_cc1_ext_h1;     /* structure session control extension */
     adsl_cc1_ext_h1 = adsl_contr_1->adsc_cc1_ext;  /* structure session control extension */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_check_ftp_00: ->adsc_cc1_ext=%p.",
                   __LINE__, adsl_cc1_ext_h1 );
     while (adsl_cc1_ext_h1) {
       adsl_cc1_ext_h1 = adsl_cc1_ext_h1->adsc_next;
       if (adsl_cc1_ext_h1 == NULL) break;
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_check_ftp_00: chain ->adsc_cc1_ext=%p.",
                     __LINE__, adsl_cc1_ext_h1 );
     }
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_check_ftp_00: *achp_ineta=%08X ->umc_ineta_lower=%08X ->umc_ineta_upper=%08X.",
                 __LINE__, *((UNSIG_MED *) achp_ineta), adsl_contr_1->umc_ineta_lower, adsl_contr_1->umc_ineta_upper );
   iml1 = m_ineta_op_diff( achp_ineta, (char *) &adsl_contr_1->umc_ineta_lower, sizeof(int) );
   iml2 = m_ineta_op_diff( achp_ineta, (char *) &adsl_contr_1->umc_ineta_upper, sizeof(int) );
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_check_ftp_00: m_ineta_op_diff() iml1=%d iml2=%d.",
                 __LINE__, adsl_ic1_w1, adsl_ic1_w1->boc_nat_ftp );
#endif
#define ADSL_NFCO ((struct dsd_nat_ftp_ctl_org *) (((struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext) + 1))  /* control area for NAT of FTP server, first */
   iml1 = ADSL_NFCO->imc_no_nat_ftp_entries;  /* number of entries for NAT of FTP */
   if (iml1 <= 0) {                         /* no entries              */
     return adsl_ic1_w1->imc_ineta;         /* from control INETA      */
   }
   iml2 = DEF_NAT_FTP_TABLE_ORG;            /* number of entries first chunk */
   adsl_nfe_w1 = ADSL_NFCO->dsrc_nfe;       /* entry for NAT of FTP server */
   adsl_nfce_w1 = NULL;                     /* control area for NAT of FTP server, extension */
   if (iml2 > iml1) iml2 = iml1;            /* set remaining in this chunk */
   iml1 -= iml2;                            /* number of remaining entries */

   p_check_ftp_20:                          /* check entry             */
#ifdef DEBUG_150116_01                      /* crash NAT / FTP         */
   dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-T p_check_ftp_20: adsl_nfce_w1=%p adsl_nfe_w1=%p iml1=%d iml2=%d.",
                 __LINE__, adsl_nfce_w1, adsl_nfe_w1, iml1, iml2 );
#endif
   if (adsl_nfe_w1->umc_ineta == *((UNSIG_MED *) achp_ineta)) {  /* check INETA used */
     adsp_nrv->adsc_nfe = adsl_nfe_w1;      /* set chain of entries for NAT of FTP server */
     return adsl_ic1_w1->imc_ineta;         /* from control INETA      */
   }
   adsl_nfe_w1++;                           /* next entry              */
   iml2--;                                  /* entry has been processed */
   if (iml2 > 0) {                          /* more entries in this chunk ? */
     goto p_check_ftp_20;                   /* check entry             */
   }
   if (iml1 <= 0) {                         /* all entries have been checked, not found */
     return adsl_ic1_w1->imc_ineta;         /* from control INETA      */
   }
   if (adsl_nfce_w1 == NULL) {              /* control area for NAT of FTP server, extension */
     adsl_nfce_w1 = ADSL_NFCO->adsc_nfce;   /* control area for NAT of FTP server, extension */
   } else {                                 /* we are already in extension chunk */
     adsl_nfce_w1 = adsl_nfce_w1->adsc_next;  /* control area for NAT of FTP server, extension */
   }
   if (adsl_nfce_w1 == NULL) {              /* extension not found     */
     dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-W NAT of FTP server extension not found",
                   __LINE__ );
     return adsl_ic1_w1->imc_ineta;         /* from control INETA      */
   }
   iml2 = DEF_NAT_FTP_TABLE_EXT;            /* number of entries extension chunk */
   adsl_nfe_w1 = adsl_nfce_w1->dsrc_nfe;    /* entry for NAT of FTP server */
   if (iml2 > iml1) iml2 = iml1;            /* set remaining in this chunk */
   iml1 -= iml2;                            /* number of remaining entries */
   goto p_check_ftp_20;                     /* check entry             */

#undef ADSL_NFCO

   p_ret_original:                          /* return original INETA   */
// return iml_ineta;
   return *((int *) achp_ineta);
} /* end m_original_ineta()                                            */

/** compare entries in AVL tree of INETAs IPV4                         */
static int m_cmp_ineta_nat( void *ap_option,
                            struct dsd_htree1_avl_entry *adsp_entry_1,
                            struct dsd_htree1_avl_entry *adsp_entry_2 ) {
   int        iml1;                         /* working variable        */
   int        iml_cmp;                      /* for compare             */

#define ADSL_INETA_P1 ((struct dsd_ineta_ctl_1 *) ((char *) adsp_entry_1 - offsetof( struct dsd_ineta_ctl_1, dsc_sort_ineta )))
#define ADSL_INETA_P2 ((struct dsd_ineta_ctl_1 *) ((char *) adsp_entry_2 - offsetof( struct dsd_ineta_ctl_1, dsc_sort_ineta )))
   iml1 = 0;                                /* clear index             */
   do {                                     /* loop over digits of INETA */
     iml_cmp = *((unsigned char *) &ADSL_INETA_P2->imc_ineta + iml1)
                 - *((unsigned char *) &ADSL_INETA_P1->imc_ineta + iml1);
     if (iml_cmp != 0) return iml_cmp;
     iml1++;                                /* increment index         */
   } while (iml1 < sizeof(int));
   return 0;                                /* entries are equal       */
#undef ADSL_INETA_P1
#undef ADSL_INETA_P2
} /* end m_cmp_ineta_nat()                                             */

/** compare entries in AVL tree of INETAs and ports IPV4               */
static int m_cmp_ineta_ipv4( void *ap_option,
                             struct dsd_htree1_avl_entry *adsp_entry_1,
                             struct dsd_htree1_avl_entry *adsp_entry_2 ) {

#define ADSL_SORT_TCP_IPV4_P1 ((struct dsd_sort_tcp_ipv4 *) ((char *) adsp_entry_1 - offsetof( struct dsd_sort_tcp_ipv4, dsc_sort_ineta )))
#define ADSL_SORT_TCP_IPV4_P2 ((struct dsd_sort_tcp_ipv4 *) ((char *) adsp_entry_2 - offsetof( struct dsd_sort_tcp_ipv4, dsc_sort_ineta )))
#define ADSL_CT_IPV4 (&ADSL_SORT_TCP_IPV4_P1->dsc_ct_ipv4)  /* structure control TCP IPV4 */
   return memcmp( &ADSL_SORT_TCP_IPV4_P1->dsc_ct_ipv4,
                  &ADSL_SORT_TCP_IPV4_P2->dsc_ct_ipv4,
                  sizeof(ADSL_CT_IPV4->chrrc_ineta)
                    + sizeof(ADSL_CT_IPV4->chrrc_port) );
#undef ADSL_CT_IPV4
#undef ADSL_SORT_TCP_IPV4_P1
#undef ADSL_SORT_TCP_IPV4_P2
} /* end m_cmp_ineta_ipv4()                                            */

/** compare entries in AVL tree of INETAs and ports IPV6               */
static int m_cmp_ineta_ipv6( void *ap_option,
                             struct dsd_htree1_avl_entry *adsp_entry_1,
                             struct dsd_htree1_avl_entry *adsp_entry_2 ) {

#define ADSL_SORT_TCP_IPV6_P1 ((struct dsd_sort_tcp_ipv6 *) ((char *) adsp_entry_1 - offsetof( struct dsd_sort_tcp_ipv6, dsc_sort_ineta )))
#define ADSL_SORT_TCP_IPV6_P2 ((struct dsd_sort_tcp_ipv6 *) ((char *) adsp_entry_2 - offsetof( struct dsd_sort_tcp_ipv6, dsc_sort_ineta )))
   return memcmp( &ADSL_SORT_TCP_IPV6_P1->dsc_ct_ipv6,
                  &ADSL_SORT_TCP_IPV6_P2->dsc_ct_ipv6,
                  sizeof(struct dsd_ctrl_tcp_ipv6) );
#undef ADSL_SORT_TCP_IPV6_P1
#undef ADSL_SORT_TCP_IPV6_P2
} /* end m_cmp_ineta_ipv6()                                            */

/** subroutine for output to console                                   */
static int m_sdh_printf( struct dsd_sdh_call_1 *adsp_sdh_call_1, const char *achptext, ... ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   va_list    dsl_argptr;
   char       chrl_out1[512];

   va_start( dsl_argptr, achptext );
   iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8, achptext, dsl_argptr );
   va_end( dsl_argptr );
   bol1 = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                       DEF_AUX_CONSOLE_OUT,  /* output to console */
                                       chrl_out1, iml1 );
   return iml1;
} /* end m_sdh_printf()                                                */

/** subroutine to display date and time                                */
static int m_get_date_time( char *achp_buff ) {
   time_t     dsl_time;

   time( &dsl_time );
   return strftime( achp_buff, 18, "%d.%m.%y %H:%M:%S", localtime( &dsl_time ) );
} /* end m_get_date_time()                                             */

/** subroutine to dump storage-content to console                      */
static void m_sdh_console_out( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                               char *achp_buff, int implength ) {
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
//   printf( "%.*s\n", sizeof(chrlwork1), chrlwork1 );
     m_sdh_printf( adsp_sdh_call_1, "%.*s", sizeof(chrlwork1), chrlwork1 );
   }
} /* end m_sdh_console_out()                                           */

/** dump output data from gather structures                            */
static void m_dump_gather( struct dsd_sdh_call_1 *adsp_sdh_call_1,
  struct dsd_gather_i_1 *adsp_gather_i_1_in,  /* input data            */
  int imp_len_trace_input ) {               /* length trace-input      */
   int        iml1, iml2, iml3, iml4, iml5, iml6;  /* working variable */
   char       byl1;                         /* working-variable        */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working-variable        */
   char       *achl_cur;                    /* position in gather      */
   char       chrlwork1[ 76 ];              /* buffer to print         */

   adsl_gai1_w1 = adsp_gather_i_1_in;
   if (adsl_gai1_w1 == NULL) return;
   achl_cur = adsl_gai1_w1->achc_ginp_cur;
   iml1 = 0;
   while (iml1 < imp_len_trace_input) {
     iml2 = iml1 + 16;
     if (iml2 > imp_len_trace_input) iml2 = imp_len_trace_input;
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
       while (achl_cur >= adsl_gai1_w1->achc_ginp_end) {
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
         if (adsl_gai1_w1 == NULL) return;
         achl_cur = adsl_gai1_w1->achc_ginp_cur;
       }
       byl1 = *achl_cur++;
       iml1++;
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
     m_sdh_printf( adsp_sdh_call_1, "%.*s", sizeof(chrlwork1), chrlwork1 );
   }
} /* end m_dump_gather()                                               */

/* pseudo-entry, cannot be used in Server-Data-Hook                    */
extern "C" int m_hl1_printf( char *aptext, ... ) {
   return 0;
} /* end m_hl1_printf()                                                */

#ifdef CHECK_OUTPUT_01
#ifndef HPPPT1_V21                          /* 18.01.13 KB HOB-PPP-T1 V2.1 */
static void m_check_output_01( struct dsd_hl_clib_1 *adsp_hl_clib_1 ) {
   BOOL       bol_pass;                     /* pass of check           */
   int        iml1, iml2;                   /* working variables       */
   int        iml_len_nhasn;                /* length bytes NHASN      */
   int        iml_len_packet;               /* length bytes packet     */
   char       *achl_w1;                     /* working variable        */
   char       *achl_w2;                     /* working variable        */
   struct dsd_clib1_contr_1 *adsl_contr_1;  /* for addressing          */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable gather */
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* working variable gather */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
   char       chrc_display[ 16 * 1024 ];    /* display area            */
#define D_LEN_LINE_M2 128

#ifdef B120826
#ifndef NEW_WSP_1102
   if (adsp_hl_clib_1->adsc_gather_i_1_out == NULL) return;
#else
   if (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER) {  /* send to client */
     adsl_gai1_w1 = adsp_hl_clib_1->adsc_gai1_out_to_client;  /* output data to client */
   } else {                                 /* send to server          */
     adsl_gai1_w1 = adsp_hl_clib_1->adsc_gai1_out_to_server;  /* output data to server */
   }
   if (adsl_gai1_w1 == NULL) return;
   adsl_gai1_w2 = adsl_gai1_w1;             /* save for later          */
#endif
#endif
   dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
   adsl_contr_1 = (struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext;
#ifndef NEW_WSP_1102
   adsl_gai1_w1 = adsp_hl_clib_1->adsc_gather_i_1_out;
#endif
   bol_pass = FALSE;                        /* pass of check           */
   adsl_gai1_w1 = adsp_hl_clib_1->adsc_gai1_out_to_client;  /* output data to client */

   p_check_00:                              /* start of check          */
   if (adsl_gai1_w1 == NULL) goto p_check_80;  /* end of check         */
   adsl_gai1_w2 = adsl_gai1_w1;             /* save for later          */
   achl_w1 = adsl_gai1_w1->achc_ginp_cur;
   iml1 = adsl_gai1_w1->achc_ginp_end - achl_w1;
   if (   (iml1 >= 18)
       && (!memcmp( achl_w1, "HOB PPP TUNNEL V01", 18 ))) {
     achl_w1 += 20;
     if (achl_w1 >= adsl_gai1_w1->achc_ginp_end) {
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
#ifdef B120826
       if (adsl_gai1_w1 == NULL) return;
#else
       if (adsl_gai1_w1 == NULL) goto p_check_80;  /* end of check     */
#endif
       achl_w1 = adsl_gai1_w1->achc_ginp_cur;
     }
   }

   p_check_recv_00:                         /* check next packet       */
   iml_len_nhasn = 0;                       /* clear length bytes NHASN */
   iml_len_packet = 0;                      /* clear length bytes packet */

   p_check_recv_20:                         /* decode length NHASN     */
   while (achl_w1 >= adsl_gai1_w1->achc_ginp_end) {  /* end of gather  */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_w1 == NULL) {            /* end of input data       */
#ifdef B120826
       if (iml_len_nhasn == 0) return;      /* to be called again      */
#else
       if (iml_len_nhasn == 0) goto p_check_80;  /* end of check       */
#endif
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-E end output data and iml_len_nhasn == 0.",
                     __LINE__ );
       goto p_display_00;                   /* display the chain       */
     }
     achl_w1 = adsl_gai1_w1->achc_ginp_cur;  /* start in gather        */
   }
   iml_len_packet <<= 7;                    /* shift old value         */
   iml_len_packet |= *achl_w1++ & 0X7F;     /* apply new bits          */
   iml_len_nhasn++;                         /* increment length bytes NHASN */
   if ((unsigned char) *(achl_w1 - 1) & 0X80) {  /* more bit set       */
     if (iml_len_nhasn > MAX_LEN_NHASN) {   /* input data invalid      */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-E end output data and iml_len_nhasn > MAX_LEN_NHASN.",
                     __LINE__ );
       goto p_display_00;                   /* display the chain       */
     }
     goto p_check_recv_20;                  /* decode length NHASN     */
   }
   if (iml_len_packet <= 1) {               /* input data invalid      */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-E length NHASN iml_len_packet=%d invalid",
                   __LINE__, iml_len_packet );
     goto p_display_00;                     /* display the chain       */
   }
   while (achl_w1 >= adsl_gai1_w1->achc_ginp_end) {  /* end of gather */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_w1 == NULL) {            /* end of input data       */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-E end output data after length NHASN",
                     __LINE__ );
       goto p_display_00;                   /* display the chain       */
     }
     achl_w1 = adsl_gai1_w1->achc_ginp_cur;  /* start in gather        */
   }
#ifdef HPPPT1_V14_RECV                      /* 26.08.12 KB HOB-PPP-T1 V1.4 receive */
   if ((*achl_w1 & 0XD0) == 0X40) {         /* 0X4x - IPV4 or 0X6x - IPV6 */
     iml1 = iml_len_packet;                 /* get length packet       */
     goto p_check_recv_40;                  /* read over packet        */
   }
#endif
   if (   (*achl_w1 != '0')
       && (*achl_w1 != '1')
       && (*achl_w1 != '4')
       && (*achl_w1 != '6')) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-E control character 0X%02X invalid",
                   __LINE__, (unsigned char) *achl_w1 );
     goto p_display_00;                     /* display the chain       */
   }
   iml1 = iml_len_packet;                   /* get length packet       */

   p_check_recv_40:                         /* read over packet        */
   while (achl_w1 >= adsl_gai1_w1->achc_ginp_end) {  /* end of gather */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_w1 == NULL) {            /* end of input data       */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-E end output data and %d/0X%X data in record missing",
                     __LINE__, iml1, iml1 );
       goto p_display_00;                   /* display the chain       */
     }
     achl_w1 = adsl_gai1_w1->achc_ginp_cur;  /* start in gather        */
   }
   iml2 = adsl_gai1_w1->achc_ginp_end - achl_w1;  /* length this part  */
   if (iml2 > iml1) iml2 = iml1;            /* only as long as requested */
   achl_w1 += iml2;                         /* add length this part    */
   iml1 -= iml2;                            /* subtract length this part */
   if (iml1) goto p_check_recv_40;          /* read over packet        */
   goto p_check_recv_00;                    /* check next packet       */

   p_display_00:                            /* display the chain       */
   achl_w2 = chrc_display;
#ifndef NEW_WSP_1102
   adsl_gai1_w2 = adsp_hl_clib_1->adsc_gather_i_1_out;
#endif
   while (adsl_gai1_w2) {
     iml2 = adsl_gai1_w2->achc_ginp_end - adsl_gai1_w2->achc_ginp_cur;
     iml1 = sprintf( achl_w2, "this=%p achc_ginp_cur=%p achc_ginp_end=%p len=%d/0X%p 0X%02X 0X%02X.",
                     adsl_gai1_w2, adsl_gai1_w2->achc_ginp_cur, adsl_gai1_w2->achc_ginp_end,
                     iml2, iml2,
                     *((unsigned char *) adsl_gai1_w2->achc_ginp_cur + 0),
                     *((unsigned char *) adsl_gai1_w2->achc_ginp_cur + 1) );
     achl_w2 += iml1;
     iml2 = D_LEN_LINE_M2 - iml1;
     if (iml2 > 0) {
       memset( achl_w2, ' ', iml2 );
       achl_w2 += iml2;
     }
     adsl_gai1_w2 = adsl_gai1_w2->adsc_next;
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-07-l%05d-E output of chain done start=%p end=%p.",
                 __LINE__, chrc_display, achl_w2 );
   return;

   p_check_80:                              /* end of check            */
   if (bol_pass) return;                    /* second pass of check    */
   bol_pass = TRUE;                         /* pass of check           */
   adsl_gai1_w1 = adsp_hl_clib_1->adsc_gai1_out_to_server;  /* output data to server */
   goto p_check_00;                         /* start of check          */
} /* end m_check_output_01()                                           */
#endif
#ifdef HPPPT1_V21                           /* 18.01.13 KB HOB-PPP-T1 V2.1 */
static void m_check_output_01( struct dsd_hl_clib_1 *adsp_hl_clib_1 ) {
   int        iml1, iml2;                   /* working variables       */
   int        iml_len_nhasn;                /* length bytes NHASN      */
   int        iml_len_packet;               /* length bytes packet     */
   char       chl_type;                     /* type received           */
   char       *achl_w1;                     /* working variable        */
   char       *achl_w2;                     /* working variable        */
   char       *achl_w3;                     /* working variable        */
   struct dsd_clib1_contr_1 *adsl_contr_1;  /* for addressing          */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable gather */
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* working variable gather */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
   char       chrl_work1[ 5 ];              /* work area               */
   char       chrc_display[ 16 * 1024 ];    /* display area            */
#define D_LEN_LINE_M2 128

#ifndef NEW_WSP_1102
   if (adsp_hl_clib_1->adsc_gather_i_1_out == NULL) return;
#else
   adsl_gai1_w1 = adsp_hl_clib_1->adsc_gai1_out_to_client;  /* output data to client */
   if (adsl_gai1_w1 == NULL) {
     adsl_gai1_w1 = adsp_hl_clib_1->adsc_gai1_out_to_server;  /* output data to server */
   }
   if (adsl_gai1_w1 == NULL) return;
   adsl_gai1_w2 = adsl_gai1_w1;             /* save for later          */
#endif
   dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
   adsl_contr_1 = (struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext;
#ifndef NEW_WSP_1102
   adsl_gai1_w1 = adsp_hl_clib_1->adsc_gather_i_1_out;
#endif
   achl_w1 = adsl_gai1_w1->achc_ginp_cur;
   iml1 = adsl_gai1_w1->achc_ginp_end - achl_w1;
   if (   (iml1 >= 18)
       && (!memcmp( achl_w1, "HOB PPP TUNNEL V01", 18 ))) {
     achl_w1 += 20;
     if (achl_w1 >= adsl_gai1_w1->achc_ginp_end) {
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
#ifndef NEW_WSP_1102
       if (adsl_gai1_w1 == NULL) return;
#else
       if (adsl_gai1_w1 == NULL) {          /* end of input data       */
         if (adsl_gai1_w2 == adsp_hl_clib_1->adsc_gai1_out_to_client) {  /* output data to client */
           adsl_gai1_w1 = adsp_hl_clib_1->adsc_gai1_out_to_server;  /* output data to server */
         }
         if (adsl_gai1_w1 == NULL) return;
         adsl_gai1_w2 = adsl_gai1_w1;       /* save for later          */
       }
#endif
       achl_w1 = adsl_gai1_w1->achc_ginp_cur;
     }
   }

   p_check_recv_00:                         /* check next packet       */
   while (achl_w1 >= adsl_gai1_w1->achc_ginp_end) {  /* end of gather  */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather in chain */
#ifndef NEW_WSP_1102
     if (adsl_gai1_w1 == NULL) return;      /* end of input data       */
#else
     if (adsl_gai1_w1 == NULL) {            /* end of input data       */
       if (adsl_gai1_w2 == adsp_hl_clib_1->adsc_gai1_out_to_client) {  /* output data to client */
         adsl_gai1_w1 = adsp_hl_clib_1->adsc_gai1_out_to_server;  /* output data to server */
       }
       if (adsl_gai1_w1 == NULL) return;
       adsl_gai1_w2 = adsl_gai1_w1;         /* save for later          */
     }
#endif
     achl_w1 = adsl_gai1_w1->achc_ginp_cur;  /* start in gather        */
   }
   chl_type = *achl_w1++;
   if ((chl_type & 0XF0) == 0X30) {
     iml_len_nhasn = 0;                     /* clear length bytes NHASN */
     iml_len_packet = 0;                    /* clear length bytes packet */
     goto p_check_recv_20;                  /* decode length NHASN     */
   }
   achl_w2 = chrl_work1;
   if ((chl_type & 0XF0) == 0X40) {         /* IPV4                    */
     if ((chl_type & 0X0F) < 5) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-05-l%05d-E control character 0X%02X IP header IPV4 too short",
                     __LINE__, (unsigned char) chl_type );
       goto p_display_00;                   /* display the chain       */
     }
     achl_w3 = chrl_work1 + 3;
   } else if ((chl_type & 0XF0) == 0X60) {  /* IPV6                    */
     achl_w3 = chrl_work1 + 5;
   } else {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-05-l%05d-E control character 0X%02X invalid",
                   __LINE__, (unsigned char) chl_type );
     goto p_display_00;                     /* display the chain       */
   }

   p_check_recv_08:                         /* get fields for length   */
   while (achl_w1 >= adsl_gai1_w1->achc_ginp_end) {  /* end of gather  */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_w1 == NULL) {            /* end of input data       */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-05-l%05d-E end output data NHASN length %d/0X%X and nothing follows",
                     __LINE__, iml_len_nhasn, iml_len_nhasn );
       goto p_display_00;                   /* display the chain       */
     }
     achl_w1 = adsl_gai1_w1->achc_ginp_cur;  /* start in gather        */
   }
   iml1 = achl_w3 - achl_w2;
   iml2 = adsl_gai1_w1->achc_ginp_end - achl_w1;
   if (iml1 > iml2) iml1 = iml2;
   memcpy( achl_w2, achl_w1, iml1 );
   achl_w2 += iml1;
   achl_w1 += iml1;
   if (achl_w2 < achl_w3) {
     goto p_check_recv_08;                  /* get fields for length   */
   }
   if ((chl_type & 0XF0) == 0X40) {         /* IPV4                    */
     iml_len_packet = (*((unsigned char *) &chrl_work1 + 1) << 8)
                        | *((unsigned char *) &chrl_work1 + 2);
     iml1 = iml_len_packet - 4;             /* get length remaining packet */
     iml2 = (chl_type & 0X0F) << 2;
   } else {                                 /* IPV6                    */
     iml_len_packet = ((*((unsigned char *) &chrl_work1 + 3) << 8)
                         | *((unsigned char *) &chrl_work1 + 4))
                      + D_LEN_HEADER_IPV6;
     iml1 = iml_len_packet - 6;             /* get length remaining packet */
     iml2 = D_LEN_HEADER_IPV6;
   }
   if (iml_len_packet <= iml2) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-05-l%05d-E packet IPV4 / IPV6 too short %d/0X%X.",
                   __LINE__, iml_len_packet, iml_len_packet );
     goto p_display_00;                     /* display the chain       */
   }
   goto p_check_recv_40;                    /* read over packet        */

   p_check_recv_20:                         /* decode length NHASN     */
   while (achl_w1 >= adsl_gai1_w1->achc_ginp_end) {  /* end of gather  */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_w1 == NULL) {            /* end of input data       */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-05-l%05d-E end output data NHASN length %d/0X%X and nothing follows",
                     __LINE__, iml_len_nhasn, iml_len_nhasn );
       goto p_display_00;                   /* display the chain       */
     }
     achl_w1 = adsl_gai1_w1->achc_ginp_cur;  /* start in gather        */
   }
   iml_len_packet <<= 7;                    /* shift old value         */
   iml_len_packet |= *achl_w1++ & 0X7F;     /* apply new bits          */
   iml_len_nhasn++;                         /* increment length bytes NHASN */
   if ((unsigned char) *(achl_w1 - 1) & 0X80) {  /* more bit set       */
     if (iml_len_nhasn > MAX_LEN_NHASN) {   /* input data invalid      */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-05-l%05d-E end output data and iml_len_nhasn > MAX_LEN_NHASN.",
                     __LINE__ );
       goto p_display_00;                   /* display the chain       */
     }
     goto p_check_recv_20;                  /* decode length NHASN     */
   }
   if (iml_len_packet <= 0) {               /* input data invalid      */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-05-l%05d-E length NHASN iml_len_packet=%d invalid",
                   __LINE__, iml_len_packet );
     goto p_display_00;                     /* display the chain       */
   }
   while (achl_w1 >= adsl_gai1_w1->achc_ginp_end) {  /* end of gather */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_w1 == NULL) {            /* end of input data       */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-05-l%05d-E end output data after length NHASN",
                     __LINE__ );
       goto p_display_00;                   /* display the chain       */
     }
     achl_w1 = adsl_gai1_w1->achc_ginp_cur;  /* start in gather        */
   }
   if (   (chl_type != '0')
       && (chl_type != '1')) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-05-l%05d-E control character 0X%02X invalid",
                   __LINE__, (unsigned char) chl_type );
     goto p_display_00;                     /* display the chain       */
   }
   iml1 = iml_len_packet;                   /* get length packet       */

   p_check_recv_40:                         /* read over packet        */
   while (achl_w1 >= adsl_gai1_w1->achc_ginp_end) {  /* end of gather */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_w1 == NULL) {            /* end of input data       */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-05-l%05d-E end output data and %d/0X%X data in record missing",
                     __LINE__, iml1, iml1 );
       goto p_display_00;                   /* display the chain       */
     }
     achl_w1 = adsl_gai1_w1->achc_ginp_cur;  /* start in gather        */
   }
   iml2 = adsl_gai1_w1->achc_ginp_end - achl_w1;  /* length this part  */
   if (iml2 > iml1) iml2 = iml1;            /* only as long as requested */
   achl_w1 += iml2;                         /* add length this part    */
   iml1 -= iml2;                            /* subtract length this part */
   if (iml1) goto p_check_recv_40;          /* read over packet        */
   goto p_check_recv_00;                    /* check next packet       */

   p_display_00:                            /* display the chain       */
   achl_w2 = chrc_display;
#ifndef NEW_WSP_1102
   adsl_gai1_w2 = adsp_hl_clib_1->adsc_gather_i_1_out;
#endif
   while (adsl_gai1_w2) {
     iml2 = adsl_gai1_w2->achc_ginp_end - adsl_gai1_w2->achc_ginp_cur;
     iml1 = sprintf( achl_w2, "this=%p achc_ginp_cur=%p achc_ginp_end=%p len=%d/0X%p 0X%02X 0X%02X.",
                     adsl_gai1_w2, adsl_gai1_w2->achc_ginp_cur, adsl_gai1_w2->achc_ginp_end,
                     iml2, iml2,
                     *((unsigned char *) adsl_gai1_w2->achc_ginp_cur + 0),
                     *((unsigned char *) adsl_gai1_w2->achc_ginp_cur + 1) );
     achl_w2 += iml1;
     iml2 = D_LEN_LINE_M2 - iml1;
     if (iml2 > 0) {
       memset( achl_w2, ' ', iml2 );
       achl_w2 += iml2;
     }
     adsl_gai1_w2 = adsl_gai1_w2->adsc_next;
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-05-l%05d-E output of chain done start=%p end=%p.",
                 __LINE__, chrc_display, achl_w2 );
   return;
} /* end m_check_output_01()                                           */
#endif
#endif
#ifdef TRACEHL_INETA_01
static void m_trineta_print_01( char *achp_buffer, struct dsd_ctrl_tcp_ipv4 *adsp_ct_ipv4, int imp_cl_se ) {
   int        iml1;                         /* working variable        */

   iml1 = sprintf( achp_buffer, "source-INETA=%d.%d.%d.%d:%d",
                   *((unsigned char *) &adsp_ct_ipv4->chrrc_ineta[ imp_cl_se ][ 0 ]),
                   *((unsigned char *) &adsp_ct_ipv4->chrrc_ineta[ imp_cl_se ][ 1 ]),
                   *((unsigned char *) &adsp_ct_ipv4->chrrc_ineta[ imp_cl_se ][ 2 ]),
                   *((unsigned char *) &adsp_ct_ipv4->chrrc_ineta[ imp_cl_se ][ 3 ]),
                   ((*((unsigned char *) &adsp_ct_ipv4->chrrc_port[ imp_cl_se ][ 0 ]) << 8)
                      | *((unsigned char *) &adsp_ct_ipv4->chrrc_port[ imp_cl_se ][ 1 ])) );
   while (iml1 < 35) achp_buffer[ iml1++ ] = ' ';
   iml1 = sprintf( achp_buffer + iml1, "destination-INETA=%d.%d.%d.%d:%d",
                   *((unsigned char *) &adsp_ct_ipv4->chrrc_ineta[ imp_cl_se ^ 1 ][ 0 ]),
                   *((unsigned char *) &adsp_ct_ipv4->chrrc_ineta[ imp_cl_se ^ 1 ][ 1 ]),
                   *((unsigned char *) &adsp_ct_ipv4->chrrc_ineta[ imp_cl_se ^ 1 ][ 2 ]),
                   *((unsigned char *) &adsp_ct_ipv4->chrrc_ineta[ imp_cl_se ^ 1 ][ 3 ]),
                   ((*((unsigned char *) &adsp_ct_ipv4->chrrc_port[ imp_cl_se ^ 1 ][ 0 ]) << 8)
                      | *((unsigned char *) &adsp_ct_ipv4->chrrc_port[ imp_cl_se ^ 1 ][ 1 ])) );
} /* end m_trineta_print_01()                                          */
#endif
#ifdef TRACEHL_TIME
/** return the Epoch value in milliseconds                             */
static HL_LONGLONG m_get_epoch_ms( void ) {
#ifndef HL_UNIX
   struct __timeb64 timebuffer;

   _ftime64( &timebuffer );

   return ( timebuffer.time * 1000 + timebuffer.millitm );
#else
   struct timeval dsl_timeval;

   gettimeofday( &dsl_timeval, NULL );
   return (dsl_timeval.tv_sec * 1000 + dsl_timeval.tv_usec / 1000);
#endif
} /* end m_get_epoch_ms()                                              */
#endif
