//#define TRACE_KB
//#define PROC_ALLOC_03
//#define PROC_ALLOC_02 (8 * 1024 * 1024)
#define WA_150216_01
//#define PROBLEM_141216                      /* HOB-PPP-T1, work-threads hang */
#ifdef PROBLEM_141216                       /* HOB-PPP-T1, work-threads hang */
#define DEBUG_141118_01
#define WSP_TRACE_CONSOLE
#endif
#ifndef HL_LINUX
#define DEBUG_121023_01                     /* debug listen-gateway create socket */
#endif
#define NEW_REPORT_1501
//#define TRACE_TCP_FLOW_01                   /* 27.05.14 KB - RDP connect same server */
//#define WSP_TRACE_FILE_BIN
#ifdef TO_DO
13.02.14
/* check if session is still active                                    */
extern "C" BOOL m_check_conn_active( struct dsd_conn1 *adsp_conn1 )
called by UDP
21.08.12 KB
remove
struct dsd_conn1                            /* connection to client    */
       struct dsd_netw_post_1 dsc_netw_post_1;  /* structure to post from network callback */
#endif
#define TRY_120306_01                       /* flow-control send       */
//#define TRY_120513_01                       /* SO_REUSEADDR            */
//#define TRY_120513_02                       /* SO_REUSEADDR            */
//#define TRY_120513_03                       /* SO_REUSEADDR            */
//#define TRY_120522_01                       /* SO_REUSEADDR            */
//#define TRY_120522_02                       /* SO_REUSEADDR            */
//#define TRY_121023_01                       /* SO_REUSEADDR            */
#define TRY_121128_01                       /* SO_REUSEADDR            */
#ifdef HL_LINUX
#define TRY_121211_01                       /* core dump               */
#endif
#define TRY_130624_01                       /* problems HTCP           */
//#define HL_THRID gettid()
//#define HL_THRID 0
#ifndef HL_LINUX
#define HL_THRID m_gettid()
#include <sys/thr.h>
extern "C" pid_t m_gettid( void );
#else
#define HL_THRID syscall( __NR_gettid )
#endif
#ifdef B160712
#define DEBUG_120705_01 32                  /* loop SSL                */
#endif
//#define DEBUG_120710_01                     /* flow-control send       */
//#define DEBUG_120808_01                     /* debug start SDHs        */
//#define DEBUG_121023_01                     /* debug listen-gateway create socket */
//#define DEBUG_121116_01                     /* debug listen-gateway    */
//#define DEBUG_130219_01                     /* debug configuration     */
#ifdef B160712
#define DEBUG_130509_01 16                  /* 09.05.13 KB check queue send buffers */
#endif
//#define DEBUG_130708                        /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
//#define DEBUG_130711_01                     /* 11.07.13 KB hangs after HTCP session end */
//#define DEBUG_130716_01                     /* 16.07.13 KB loop in Web Server Gate */
#ifdef B160712
#define DEBUG_130722_01                     /* HTCP connect fails      */
#define DEBUG_131129_01                     /* adsc_seco1_previous - configuration server previous */
#define DEBUG_140213_01                     /* crash HOB-TUN          */
#endif
//#define DEBUG_140701_01                     /* deadlock - critical section */
//#define DEBUG_140803_01                     /* problems boc_act_conn_send */
#ifdef B160712
#define TRY_130511_01                       /* HOB-TUN remove gai1     */
#define TRY_130709_01                       /* problem INETA of pool   */
#define TRY_130716_01                       /* problem loop Web Server Gate */
#define TRY_131018_01                       /* problem test Mr. Jira, not receiving from client */
#endif
//#define TRY_141125_01                       /* HOB-PPP-T1 serialize-thread memory barrier */
#ifdef B160712
#define TRY_141127_01                       /* Listen-Gateway received EINPROGRESS */
#define TRY_141212_01                       /* HOB-TUN memory barrier  */
#endif
// TRY_131018_01 18.10.13 - no success
#ifdef TRACE_KB
#define D_STOR_ONE_TIME
#define WSP_TRACE_FILE_01 "WSP-trace-01.dat"
#define WSP_TRACE_SLEEP 100
#endif
//#define TRACEHL_SDH_01
//#define TRACEHL_SDH_02
//#define D_REFUSE_CONNECT_1                  /* 25.06.07 KB             */
//#define TRACEHL1
#define PROB070717
#ifdef DEBUG_130716_01                      /* 16.07.13 KB loop in Web Server Gate */
#define DEBUG_LOOP_PROC_DATA_01 16
#define DEBUG_130711_01                     /* 11.07.13 KB hangs after HTCP session end */
#endif
#ifdef D_STOR_PATTERN
#define D_STOR_ONE_TIME
#endif
#ifndef HL_CPUTYPE
#define HL_CPUTYPE           "HL_CPUTYPE xyz 05.08.11 KB"
#endif
//#define NOT_YET_UNIX_110808
#define CSSSL_060620
//#define PROBLEM_OFFSETOF_110810
//#define NO_LDAP_071116
#ifndef HL_UNIX
#ifdef HL_LINUX
#define HL_UNIX
#endif
#ifdef HL_FREEBSD
#define HL_UNIX
#endif
#endif
#ifdef HL_FREEBSD
#define D_NO_STAT64
#endif
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: nbipgw20                                            |*/
/*| -------------                                                     |*/
/*|  WebSecureProxy for Unix / Linux / FreeBSD / HOB SCS              |*/
/*|  SSL gateway                                                      |*/
/*|  part of HOB RD VPN                                               |*/
/*|  KB 26.07.11                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|  Copyright (C) HOB Germany 2016                                   |*/
/*|                                                                   |*/
/*| EXPECTED INPUT:                                                   |*/
/*| ---------------                                                   |*/
/*|  started with name of XML configuration file                      |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#define D_CHARSET_IP ied_chs_ascii_850      /* ASCII 850               */

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#include <iostream>
#include <ostream>
#include <fstream>

using namespace std;

#define _LARGEFILE64_SOURCE

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef HL_LINUX
#include <stdarg.h>
#endif
#ifdef HL_SOLARIS
#include <stdarg.h>
#endif
#include <string.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#ifdef HL_LINUX
#ifdef B120306
#include <pth.h>
#endif
#include <limits.h>
// 01.07.14 KB ???
#include <linux/unistd.h>
#endif
#include <signal.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/mman.h>
// 01.07.14 KB ???
//#include <sys/types.h>
#ifdef HL_LINUX
#include <sys/syscall.h>
#endif
/* start header-files for TCPCOMP                                      */
#include <sys/uio.h>
#include <netinet/tcp.h>
/* end header-files for TCPCOMP                                        */
#ifdef TRY_121211_01                        /* core dump               */
#include <sys/prctl.h>
#endif /* TRY_121211_01                        core dump               */
#include <locale.h>
#include <langinfo.h>
#ifdef D_INCL_HOB_TUN
#include <sys/ioctl.h>
#ifdef B140213
//#include <sys/net/if.h>
#include <net/if.h>
#include <net/if_arp.h>
#endif
#ifndef B140213
#include <net/if.h>
#ifdef HL_LINUX
#include <netpacket/packet.h>
#endif
#include <net/ethernet.h> /* the L2 protocols */
#include <net/if_arp.h>
#endif
#include <net/route.h>
#ifdef HL_LINUX
#include <linux/if_tun.h>                   /* check for other unixes   */
#include <ifaddrs.h>
#endif
#ifdef HL_FREEBSD
#include <net/if_tun.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <netinet/if_ether.h>
//#include <sys/types.h>
#include <sys/sysctl.h>
#include <net/bpf.h>
#ifndef B160502
#include <net/if_var.h>
#include <netinet/in_var.h>
#endif
#endif
#endif
#include <hob-unix01.h>
#ifdef B160504
#include <hob-xsclib01.h>
#include <hob-ssl-01.h>
#endif
#ifdef B121009
#include "hob-xshlse03.h"
#ifdef CSSSL_060620
#include "hob-xshlcl01.h"
#endif
#endif
#include "hob-xslunic1.h"
#ifdef B121009
#include "HOBSSLTP.h"
#endif
#include "hob-xslhcla1.hpp"
#define HOB_CONTR_TIMER
#include "hob-xslcontr.h"
#include "hob-xsltime1.h"
#include "hob-http-header-1.h"
#include "hob-thread.hpp"
#include "hob-netw-01.h"
#include "hob-nblock_acc.hpp"
#include "hob-wspat3.h"
#ifdef B120219
#include "hob-perf-data-1.h"
#endif
#ifdef XYZ1
#include "hob-hlwspat2.h"
#endif
#ifdef B121009
#include <hob-xshlse03.h>
#include <hob-xshlcl01.h>
#endif
#include "hob-xsrerrm1.h"
#include "hob-xshlssle.h"
#include "hob-wspsu1.h"
#include <hob-avl03.h>
#ifndef TCPCOMP_V02
#include <hob-tcpco1.hpp>
#endif
#ifdef TCPCOMP_V02
#include <hob-tcpcomp-multi-v02.hpp>
#endif
#include <hob-xslcontr.h>
#ifdef B160504
#include <hob-encry-1.h>
#endif
#include <hob-xsltime1.h>
#include <hob-tab-ascii-ansi-1.h>
#ifdef XYZ1
/* attention 17.03.09 KB start */
#include <hltabaw2.h>
/* attention 17.03.09 KB end */
#endif
#include <hob-tab-mime-base64.h>
#include <hob-tabau.h>

/*+-------------------------------------------------------------------+*/
/*| System and library header files for XERCES.                       |*/
/*+-------------------------------------------------------------------+*/

#define READDISKXML

#ifdef XYZ1
#include <xercesc/parsers/XercesDOMParser.hpp>
#include <xercesc/parsers/DOMLSParserImpl.hpp>
#include <xercesc/dom/DOMImplementation.hpp>
#include <xercesc/util/BinInputStream.hpp>
#include <xercesc/util/BinMemInputStream.hpp>
#include <xercesc/sax/InputSource.hpp>
#include <xercesc/sax/SAXParseException.hpp>
#include <xercesc/sax/ErrorHandler.hpp>
#include <xercesc/dom/DOMLocator.hpp>
#include <xercesc/internal/XMLScanner.hpp>
#include <xercesc/dom/impl/DOMElementImpl.hpp>
#include <xercesc/dom/impl/DOMDocumentImpl.hpp>
#include <xercesc/dom/DOMMemoryManager.hpp>
//#include "nbipgw20-X1.hpp"
#endif

#ifdef XYZ1
#include <xercesc/dom/DOMDocument.hpp>
#include <xercesc/util/XMLString.hpp>
#include <xercesc/dom/DOMNode.hpp>
#include <xercesc/dom/impl/DOMElementImpl.hpp>
#endif
#include <xercesc/parsers/XercesDOMParser.hpp>
#include <xercesc/parsers/DOMLSParserImpl.hpp>
#include <xercesc/dom/DOMImplementation.hpp>
#include <xercesc/util/BinInputStream.hpp>
#include <xercesc/util/BinMemInputStream.hpp>
#include <xercesc/sax/InputSource.hpp>
#include <xercesc/sax/SAXParseException.hpp>
#include <xercesc/sax/ErrorHandler.hpp>
#include <xercesc/dom/DOMLocator.hpp>
#include <xercesc/internal/XMLScanner.hpp>
#include <xercesc/dom/impl/DOMElementImpl.hpp>
#include <xercesc/dom/impl/DOMDocumentImpl.hpp>
#include <xercesc/dom/DOMMemoryManager.hpp>
#include "xs-xml-frame-01.hpp"

/*+-------------------------------------------------------------------+*/
/*| header files for Server-Data-Hook.                                |*/
/*+-------------------------------------------------------------------+*/

#define DEF_HL_INCL_DOM
#define DEF_HL_INCL_INET
#define DEF_HL_INCL_SSL
#include "hob-xsclib01.h"
#ifndef B160504
/* header files for HOB Crypto                                         */
#include <hob-ssl-01.h>
#include <hob-encry-1.h>
#endif
#ifndef B170213
#include <hob-cert-ext.h>
#endif
/* header files for LDAP                                               */
#include "hob-ldap01.hpp"

#ifndef B120219
#include "hob-perf-data-1.h"
#endif

/*+-------------------------------------------------------------------+*/
/*| header files for this Gateway and corresponding sources           |*/
/*+-------------------------------------------------------------------+*/

#define D_INCL_CONF
#define INCL_GW_ALL
#define INCL_GW_ADMIN
#define INCL_GW_L2TP
#define INCL_GW_LISTEN
#define D_INCL_OCSP
#ifdef NOT_YET_AND_NOT_ALL_UNIX
#define D_INCL_HOB_TUN
#endif
#define D_INCL_AUX_UDP
#define D_HPPPT1_1
#ifdef D_HPPPT1_1
#include <string>
#include <map>
#include <list>
#ifdef B130123
#ifdef D_INCL_HOB_TUN
//#include <Iprtrmib.h>
//#include <Iphlpapi.h>
//#include <Iptypes.h>
#endif
#define D_INCL_TUN_CTRL
#include "hob-tun01.h"
#else
#ifdef D_INCL_HOB_TUN
//#include <Iprtrmib.h>
//#include <Iphlpapi.h>
//#include <Iptypes.h>
#define D_INCL_TUN_CTRL
#include "hob-tun01.h"
#endif
#endif
#ifdef NOT_YET_110808
#include "hob-htcp-int-types.h"
#include "hob-htcp-misc.h"
#include "hob-htcp.h"
#include "hob-htcp-bit-reference.h"
#include "hob-htcp-tcpip-hdr.h"
#include "hob-htcp-connection.h"
#include "hob-session01.h"
#include "hob-htcp-session.h"
#endif
#include "hob-gw-ppp-1.h"
#ifdef D_INCL_HOB_TUN
//#include "hob-hppp01.h"
//#include "hob-hsstp01.h"
//#include "hob-tun02.h"
#endif
#endif
#include "hob-tcp-sync-01.h"
#include "hob-wsppriv.h"                    /* privileges              */
#include "hob-xbipgw08-1.h"
#include "hob-xbipgw08-2.h"
#include "hob-xbipgw08-3.h"
#include "hob-wsp-admin-1.h"
#include "hob-wsp-snmp-1.h"
#include "hob-li-gw-01.h"

#ifndef HL_SOLARIS
#ifndef HL_HPUX
#define MSGHDR_CONTROL_AVAILABLE 1
#endif
#endif

#ifdef XYZ1
#define DEF_UDP_PORT           4097         /* default UDP port        */
#define MAX_PACKET_SIZE        (64 * 1024 - 1)  /* size UDP packet     */
#define LEN_IP_RECV            8192         /* length of IP recv       */
#define LEN_HEADER_RECV        128          /* length of IP recv       */

#define TIMEOUT_RECV           30           /* timeout receive in seconds */

#define D_PROTO_GRE            0X2F         /* protocol GRE            */
#endif

#ifndef HL_UNIX
typedef int socklen_t;
#define D_TCP_ERROR WSAGetLastError()
#define D_TCP_CLOSE closesocket
#else
#define D_TCP_ERROR errno
#define D_TCP_CLOSE close
#endif
#ifndef UNSIG_MED
#define UNSIG_MED unsigned int
#endif
#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif
#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif
#ifdef D_INCL_HOB_TUN
#define IP_getnameinfo getnameinfo
#endif

#ifdef XYZ1
/** Default name of the Unix domain socket used for communication with the clients */
#define DEFAULT_UDSNAME "/tmp/nbipgw19.uds"
/** Default for the shared secret                                      */
#define DEFAULT_SECRET "SADFACTORYWORKER"
#define D_LI_GW_TOKEN  0X10092011           /* token for start packet  */
#define D_LI_GW_VERSION        0            /* version of listen gateway */
#endif

#define EXT_RANDOM_G_UDS_NAME  "/tmp/hob-random.uds"
#define EXT_RANDOM_G_TIMEOUT_MS 500

#define MSG_CONS_P1    "HWSPM001I nbipgw20 started / Version 2.3 "
#define MSG_CONS_P2    " / HOB WebSecureProxy SSL-Gateway for Unix"
#define CHAR_CR        0X0D                 /* carriage-return         */
#define CHAR_LF        0X0A                 /* line-feed               */
#define WSP_TRACE_FILE_NOT_AUS "WSP-trace-not-aus.dat"
#define DEF_IPLEVEL            4            /* Level in Log            */
#define DEF_MSG_PIPE_LEN       2            /* length message in pipe  */
#ifdef XYZ1
#define D_LIGW_RANDOM_L        20           /* length random listen-gateway - length SHA-1 */
#endif
#define D_LIGW_TIMEOUT         5            /* timeout in seconds      */
#define D_WAIT_LIERR           15           /* wait after listen error in seconds */
#define D_WAIT_OPEN_TUN        60           /* wait for listen-gateway open TUN adapter */
#define DEF_SEND_IOVEC         32           /* for sendmsg()           */
#define HL_AES_LEN             16
#define D_MAX_LEN_NHASN        4            /* maximum length NHASN    */
#ifdef D_INCL_HOB_TUN
#define HL_ERROR_HTCP_CONN     (20000 + 1)  /* HOBLink Error Code      */
#ifdef HL_FREEBSD
#define MAX_TRY_BPF            128
#endif
#endif
#ifdef HL_LINUX
#define D_FN_IP_FORW   "/proc/sys/net/ipv4/ip_forward"
#else
#define D_FN_IP_FORW   "/etc/rc.conf"
#endif

/*+-------------------------------------------------------------------+*/
/*| static used enum used if function calls.                          |*/
/*+-------------------------------------------------------------------+*/

enum ied_func_main_poll {                   /* function of main poll   */
   ied_fmp_normal,                          /* normal processing       */
   ied_fmp_opli_sleep,                      /* open listen sleep       */
   ied_fmp_opli_ligw_wait,                  /* open listen listen gateway wait */
   ied_fmp_opli_ligw_ret,                   /* open listen listen gateway return */
#ifdef D_INCL_HOB_TUN
   ied_fmp_open_tun                         /* open TUN adapter        */
#endif
};

enum ied_ret_main_poll {                    /* return from main poll   */
   ied_rmp_timeout,                         /* timer elapsed           */
   ied_rmp_sig_end,                         /* message signal end      */
   ied_rmp_sig_reload,                      /* message signal reload configuration */
   ied_rmp_sig_check_shu,                   /* message signal check shutdown */
   ied_rmp_ligw_success,                    /* listen gateway socket passed or TUN adapter opened */
   ied_rmp_ligw_failed,                     /* socket and bind failed  */
   ied_rmp_ligw_closed                      /* listen gateway is closed */
};

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

static enum ied_ret_main_poll m_main_poll( enum ied_func_main_poll iep_fmp, int imp_endtime );
static BOOL m_startprog( struct dsd_wsp_startprog * );
static struct dsd_targfi_1 * m_get_session_targfi( char **, struct dsd_conn1 * );
static BOOL m_check_conn_sstp_channel_binding( struct dsd_conn1 *, char *, int );
#ifdef D_HPPPT1_1
static void m_ppp_auth_radius_compl( struct dsd_radius_control_1 *, int );
static void m_radius_mppe_calc_1( struct dsd_conn1 *, struct dsd_radius_control_1 *, char *, int );
#endif
static BOOL m_check_target_multiconn( struct dsd_conn1 *, struct dsd_targfi_1 *, struct dsd_unicode_string *, struct dsd_target_ineta_1 *, int );
static void m_lbal_udp_start( struct dsd_conn1 * );
static void m_lbal_udp_cb_recv( struct dsd_udp_multiw_1 *, struct dsd_sdh_control_1 * );
#ifdef XYZ1
static int m_get_random_number( int );
#endif
static htfunc1_t m_conn_pttd_thread( void * );
static htfunc1_t m_serial_thread( void * );
static htfunc1_t m_wsp_trace_thread( void * );
static void m_wsp_trace_bin_1( struct dsd_wsp_tr_intern_1 *, struct dsd_wsp_trace_record * );
static void m_dump_cma_01( void * vpp_userfld, struct dsd_cma_dump_01 *adsp_cm01 );
static void m_wsp_trace_ascii_1( struct dsd_wsp_tr_intern_1 *, char *, int );
inline dsd_user_entry ** m_get_addr_user_entry( void * );
inline dsd_user_group ** m_get_addr_user_group( void * );
static ied_chid_ret m_auth_user( struct dsd_user_entry **, struct dsd_user_group **,
                                 void *,
                                 struct dsd_unicode_string *, struct dsd_unicode_string *,
                                 BOOL, BOOL );
static void * m_get_certificate( void * );
//static BOOL m_aux_get_ident_set_1( void *, struct dsd_sdh_ident_set_1 * );
static int m_ocsp_start( void * vpp_userfld, struct dsd_hl_ocsp_d_1 * );  // OCSP start
static int m_ocsp_send( void * vpp_userfld, char *achp_buf, int inp_len );  // OCSP send
static struct dsd_hl_ocsp_rec * m_ocsp_recv( void * vpp_userfld );  // OCSP receive
static void m_ocsp_stop( void * vpp_userfld );  // OCSP stop
static void m_ocsp_cleanup( struct dsd_conn1 *, struct dsd_auxf_1 * );
#ifndef B150121
static inline void m_conn1_set_timer_1( struct dsd_conn1 * );
#endif
static BOOL m_secondary_aux( void *, int, void *, int );
static void m_aux_radius_req_compl( struct dsd_radius_control_1 *, int );
static void m_read_diskfile( struct dsd_hco_wothr *, int, int, int, struct dsd_hl_aux_diskfile_1 * );
#ifdef B130314
static void m_aux_timer_new( struct dsd_conn1 *, ied_src_func, void *, int );
static void m_aux_timer_del( struct dsd_conn1 *, ied_src_func, void * );
static BOOL m_aux_timer_check( struct dsd_conn1 *, ied_src_func, void * );
#endif
static void m_aux_timer_new( struct dsd_conn1 *, struct dsd_cid *, int, enum ied_auxt_usage );
static void m_aux_timer_del( struct dsd_conn1 *, struct dsd_cid * );
static BOOL m_aux_timer_check( struct dsd_conn1 *, struct dsd_cid * );
#ifndef B140620
static void m_sdh_cleanup( struct dsd_aux_cf1 *, struct dsd_cid * );  /* cleanup resources of Server-Data-Hook */
#endif
#ifdef CHECK_PROB_070113
static void m_check_chain_aux( void * );
#endif
static int m_ret_signal( struct dsd_aux_cf1 * );
#ifdef B130314
static void * m_check_sdh_signal( struct dsd_aux_cf1 * );
#endif
static struct dsd_cid * m_check_sdh_signal( struct dsd_aux_cf1 * );
static void m_set_wothr_blocking( void * );
static void m_set_wothr_active( void * );
static BOOL m_mark_work_area( void *, char *, int );
static BOOL m_proc_service_query( void *, struct dsd_aux_service_query_1 * );
static BOOL m_aux_sdh_obj_1( void *, struct dsd_get_sdh_object_1 * );
static BOOL m_aux_session_conf_1( void *, struct dsd_aux_session_conf_1 * );
static BOOL m_aux_admin_1( void *, struct dsd_aux_admin_1 * );
static BOOL m_aux_set_ident_1( void *, struct dsd_aux_set_ident_1 * );
static BOOL m_aux_get_ident_1( struct dsd_conn1 *, struct dsd_sdh_ident_set_1 * );
static void m_aux_get_duia_1( struct dsd_conn1 *, struct dsd_aux_get_duia_1 * );
static BOOL m_aux_secure_xor( struct dsd_aux_secure_xor_1 * );
static BOOL m_aux_webso_conn( void *, struct dsd_aux_webso_conn_1 * );
static void m_close_webso_conn( void * );
#ifndef B160423
static BOOL m_get_secure_seed( void *, void *, int );
#endif
static BOOL m_aux_pipe_manage( void *, struct dsd_aux_pipe_req_1 * );
static void m_aux_pipe_listen_cleanup( struct dsd_conn1 *, struct dsd_auxf_1 * );
static void m_aux_pipe_conn_cleanup( struct dsd_conn1 *, struct dsd_auxf_1 * );
static int m_cmp_aux_pipe_listen( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static BOOL m_aux_util_thread_cmd( void *, struct dsd_aux_util_thread_call_1 * );
static htfunc1_t m_aux_util_thread_execute( void * );
static void m_swap_stor_open( void );
static BOOL m_aux_swap_stor_req_1( void *, struct dsd_aux_swap_stor_req_1 * );
static BOOL m_swap_stor_file_write( struct dsd_hco_wothr *, int *, int, void * );
static BOOL m_swap_stor_file_read( struct dsd_hco_wothr *, int, int, void * );
static BOOL m_swap_stor_file_mark_free( int, BOOL );
static char * m_swap_stor_acq_mem( BOOL );
static struct dsd_swap_stor_chain * m_swap_stor_acq_ss_ch( void );
static void m_aux_swap_stor_cleanup( struct dsd_hco_wothr *, struct dsd_conn1 *, struct dsd_auxf_1 * );
static BOOL m_aux_dyn_lib_req_1( void *, struct dsd_aux_dyn_lib_req_1 * );
static BOOL m_aux_get_domain_info_1( void *, struct dsd_aux_get_domain_info_1 * );
static BOOL m_aux_file_io_req_1( void *, struct dsd_aux_file_io_req_1 *, int, int );
static BOOL m_aux_sdh_reload_call( void *, struct dsd_hl_aux_manage_sdh_reload * );
static void m_sdh_reload_old_resources( struct dsd_conn1 *, struct dsd_cid *, struct dsd_sdh_reload_saved * );
static void m_sdh_reload_new_resources( void *, struct dsd_sdh_reload_saved * );
static void m_sdh_reload_old_end( struct dsd_aux_cf1 *, struct dsd_auxf_1 * );
#ifdef WAS_BEFORE_1501
static void m_sdh_reload_do( void *, int );
static void m_sdh_reload_timeout( struct dsd_timer_ele * );
#endif
static void m_sdh_reload_client_ended( struct dsd_conn1 * );
static int m_cmp_aux_sdh_reload( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
//static void m_end_proc( void );
#ifdef NOT_YET
static void m_wait_conn( void *, int );     /* wait till activated     */
static void m_post_conn( void * );          /* post waiting thread     */
#endif
//static void m_act_conn( void * );           /* activate thread         */
static void m_display_conn( void *, char * );  /* display for connection */
#ifdef B120915
static void m_session_new_params( struct dsd_conn1 * );
#endif
#ifdef NOT_YET
static void m_start_ip( void );
static void LoadWinSockFunctions( void );
#ifdef HL_IPV6
static BOOL loadws_IPV6_functions( void );
#endif
#endif

static void m_acc_errorcallback( class dsd_nblock_acc *, void *, char *, int, int );  // Error callback function.
static void m_acc_acceptcallback( class dsd_nblock_acc *, void *, int, struct sockaddr *, int );
static void m_cb_tcpc_conn_err( class dsd_tcpcomp *, void *, struct sockaddr *, socklen_t, int, int, int );
#ifdef B121121
static void m_cb_tcpc_connect( class dsd_tcpcomp *, void *, struct sockaddr *, socklen_t, int );
#else
static void m_cb_tcpc_connect( dsd_tcpcomp *, void *, struct dsd_target_ineta_1 *, void *, struct sockaddr *, socklen_t, int );
#endif
static void m_cb_tcpc_send( class dsd_tcpcomp *, void * );  /* send callback function */
static int m_cb_tcpc_getbuf( class dsd_tcpcomp *, void *, void **, char **, int ** );  // get receive buffer callback function
static int m_cb_tcpc_recv( class dsd_tcpcomp *, void *, void * );  // receive callback function
static void m_cb_tcpc_error( class dsd_tcpcomp *, void *, char *, int, int );  // error callback function
static void m_cb_tcpc_cleanup( class dsd_tcpcomp *, void * );
#ifdef B121121
static void m_cb_tcpc_free_target_ineta( class dsd_tcpcomp *, void *, const struct dsd_target_ineta_1 * );
#endif
static void m_tc1_post_netw_post_1( struct dsd_tcp_ctrl_1 *adsp_tc1, int imp_mask );
static void m_tc1_close_1( struct dsd_tcp_ctrl_1 *adsp_tc1, struct dsd_hco_wothr * );
static void HLGW_set_timer( void *, int );
static void HLGW_sendto_LB( void *, char *, int );
static int HLGW_start_conn( void *, struct sockaddr * );
static int HLGW_check_name( void *, char *, int, char *, int );
static void HLGW_set_abend( void * );
#ifndef B140704
static void m_free_seco1( struct dsd_timer_ele * );
#endif
static int m_hlgw_printf( void *, char *, ... );
static BOOL m_client_recv_compl( struct dsd_conn1 *, struct dsd_sdh_control_1 *, int );
static BOOL m_server_recv_compl( struct dsd_conn1 *, struct dsd_sdh_control_1 *, int );
static void m_start_rec_server( struct dsd_pd_work * );
static void m_send_clse_tcp_1( struct dsd_conn1 *, struct dsd_tcp_ctrl_1 *, struct dsd_sdh_control_1 *, BOOL );
static void m_ligw_open( void );            /* open the listen gateway */
static void m_ligw_create_socket( void );
static BOOL m_ligw_send( char *, int, struct msghdr * );
static void m_ligw_recv( void );
static void m_ligw_close( void );
inline int m_tcp_sa_conn_server( struct dsd_aux_cf1 *, struct sockaddr * );
static inline void m_conn_close( struct dsd_pd_work * );  /* close session */

#ifdef NOT_YET
static void HLGW_set_timer( void *, int );
static void HLGW_sendto_LB( void *, char *, int );
static int HLGW_start_conn( void *, UNSIG_MED, int );
static int HLGW_check_name( void *, char *, int, char *, int );
static void HLGW_set_abend( void * );
static int m_hlgw_printf( void *, char *, ... );
#endif
static void m_act_thread_1( struct dsd_conn1 * );
static void m_act_thread_2( struct dsd_conn1 * );
static void m_timeout_conn( struct dsd_timer_ele * );
static void m_cancel_conn( struct dsd_conn1 * );
//static void m_free_session_b( struct dsd_timer_ele * );
static void m_timeout_free_memory( struct dsd_timer_ele * );
static struct dsd_tich2_ele * m_tich2_alloc( void );
static void m_tich2_free( struct dsd_tich2_ele * );
static struct dsd_targfi_1 * m_get_session_targfi( char **, struct dsd_conn1 * );
static BOOL m_check_target_multiconn( struct dsd_conn1 *, struct dsd_targfi_1 *, struct dsd_unicode_string *, struct dsd_target_ineta_1 *, int );
#ifdef D_INCL_HOB_TUN
static struct dsd_ineta_raws_1 * m_prepare_htun_ineta_htcp( struct dsd_conn1 *, struct dsd_hco_wothr *, enum ied_ineta_raws_def );
static BOOL m_update_htun_ineta( struct dsd_ineta_raws_1 *, struct dsd_conn1 *, struct dsd_hco_wothr *, enum ied_ineta_raws_def iep_irs_def, struct dsd_config_ineta_1 * );
static void m_cleanup_htun_ineta( struct dsd_ineta_raws_1 * );
static int m_cmp_ineta_n_ipv4( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static int m_cmp_ineta_n_ipv6( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static int m_cmp_ineta_user_ipv4( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static int m_cmp_ineta_user_ipv6( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
#endif
static void m_edit_sci_two( char *, HL_LONGLONG );
static void m_edit_sci_dec( char *, HL_LONGLONG );
#ifdef NEW_REPORT_1501
static void m_time_fingerprint( dsd_time_1 *, dsd_time_1 * );
#endif
#ifdef XYZ1
static inline void * m_clconn1_dcl_tcp_r_c( void * );
static inline WCHAR * m_clconn1_gatename( void * );
static inline int m_clconn1_sno( void * );
static inline char * m_clconn1_chrc_ineta( void * );
static inline void m_clconn1_critsect_enter( void * );
static inline void m_clconn1_critsect_leave( void * );
static inline BOOL m_clconn1_act_thread_x( void * );
static inline void m_clconn1_act_thread_1( void * );
static inline BOOL m_clconn1_rec_complete( void *, class cl_tcp_r *,
                                           struct dsd_sdh_control_1 *, int );
static inline BOOL m_clconn1_check_client( void *, class cl_tcp_r * );
static inline char ** m_clconn1_get_addr_reason_end( void * );
static inline void m_clconn1_mark_work_area( void *, struct dsd_sdh_control_1 * );
static inline void m_clconn1_check_end_l2tp( void * );
static inline void m_clconn1_check_end_server( void *, class cl_tcp_r * );
#endif
static inline HL_WCHAR * m_clconn1_gatename( void * );
static inline int m_clconn1_sno( void * );
static inline char * m_clconn1_chrc_ineta( void * );
static inline void m_clconn1_naeg1( void * adsp_conn1 );
static void m_free_session_b( struct dsd_timer_ele * );
#ifdef TRACEHL_STOR_USAGE
static inline struct dsd_conn1 * m_clconn1_get_conn( void * );
static inline struct dsd_sdh_control_1 * m_clconn1_get_sdhc1_chain( void * );
#endif
static inline int m_clconn1_get_trace_level( void * );
static inline BOOL m_sel_server_socks5_1( void *, struct dsd_user_entry *, struct dsd_user_group *,
                                          struct dsd_unicode_string *, ied_scp_def, char *, int );
static inline int m_conn_get_no_servent( void *, enum ied_scp_def, char *, int );
static HL_WCHAR * m_conn_get_servent_by_no( void *, int, enum ied_scp_def, char *, int );
static inline int m_conn_get_no_user_servent( void *, struct dsd_user_entry *, struct dsd_user_group *,
                                              enum ied_scp_def, char *, int );
static HL_WCHAR * m_conn_get_user_servent_by_no( void *, struct dsd_user_entry *, struct dsd_user_group *, int,
                                                 enum ied_scp_def, char *, int );
static inline ied_set_def m_conn_get_set( void *, BOOL );
static void m_ssl_conn_cl_compl_se( struct dsd_hl_ssl_ccb_1 * );  // Connect Callback
static void m_ssl_conn_cl_compl_cl( struct dsd_hl_ssl_ccb_1 * );  // Connect Callback
static inline void m_garb_coll_1( struct dsd_conn1 * );  /* do garbage collect */
static inline BOOL m_garb_coll_2( struct dsd_conn1 *, struct dsd_sdh_control_1 * );  /* do garbage collect */
static BOOL m_do_send_server( struct dsd_hco_wothr *, struct dsd_conn1 * );
static BOOL m_ext_send_server( struct dsd_hco_wothr *, struct dsd_conn1 *, struct dsd_sdh_control_1 * );
static void m_pd_plain_http( struct dsd_pd_work * );
static void m_pd_auth1( struct dsd_pd_work * );
static void m_auth_radius_req_compl( struct dsd_radius_control_1 *, int );
static inline void m_auth_get_input( struct dsd_gather_i_1 *, char *, char *, char * );
static void m_pd_auth_start_pttd( struct dsd_pd_work *, struct dsd_conn_pttd_thr * );  /* connect PTTD thread */
static void m_auth_delete( struct dsd_pd_work *, struct dsd_wsp_auth_1 * );
static void m_pd_loadbal1( struct dsd_pd_work * );
#ifdef TRACEHL_STOR_USAGE
static void m_proc_mark_1( void *ap1, char *achp_pos );
static void m_proc_trac_1( void *ap1, char *achp_trac );
extern "C" void * m_get_stack( void );
#endif
static void m_pd_do_sdh_frse( struct dsd_pd_work * );
static void m_pd_do_sdh_tose( struct dsd_pd_work * );
static void m_pd_do_cs_ssl( struct dsd_pd_work * );
static void m_pd_close_cs_ssl( struct dsd_pd_work * );
static inline void m_clconn1_mark_work_area( void * ap_conn1, struct dsd_sdh_control_1 *adsp_sdhc1 );
static void m_wothr_start_inj( struct dsd_hco_wothr *, int );
static int m_cmp_session_id( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
#ifdef D_INCL_HOB_TUN
static void m_gw_start_htun( struct dsd_raw_packet_if_conf * );
#ifdef HL_LINUX
static BOOL m_htun_search_interface_ipv4( UNSIG_MED ump_ineta, char *achp_if_name, struct sockaddr *adsp_rhwaddr, int *aimp_ifindex_nic );
#endif
#ifdef HL_FREEBSD
static BOOL m_htun_search_interface_ipv4( UNSIG_MED ump_ineta, char *achp_if_name, struct sockaddr_dl *adsp_soa_dl );
#endif
#endif
static HL_LONGLONG m_get_rand_epoch_ms( void );
//static HL_LONGLONG m_get_epoch_microsec( void );
static HL_LONGLONG m_get_epoch_nanoseconds( void );
static void m_lock_blade_control( void );   /* lock resource           */
static void m_unlock_blade_control( void );  /* unlock resource        */
static void m_hl_abend1( char * );
static void m_signal_end( int );
static void m_signal_rec( int );

extern "C" int m_hl1_printf( char *aptext, ... );
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
extern "C" void m_console_out( char *, int );
#endif

extern "C" void m_hl_lock_inc_1( int * );
extern "C" void m_hl_lock_dec_1( int * );
extern "C" void m_hl_lock_set_true_1( int * );
#ifdef PROC_ALLOC_03
extern "C" void * m_hl_get_chain( void **, int * );
extern "C" void m_hl_put_chain( void **, void * );
#endif

/*+-------------------------------------------------------------------+*/
/*| global used dsects = structures.                                  |*/
/*+-------------------------------------------------------------------+*/

enum ied_mess_pipe_main {                   /* message type main       */
   ied_mepm_invalid,                        /* message is invalid      */
   ied_mepm_work,                           /* message work to do      */
   ied_mepm_sig_end,                        /* message signal end      */
   ied_mepm_sig_reload,                     /* message signal reload configuration */
   ied_mepm_sig_check_shu                   /* message signal check shutdown */
};

struct dsd_tcp_ctrl_1 {                     /* TCP control structure   */
   class dsd_tcpcomp dsc_tcpco1_1;          /* connection object TCPCOMP */
   struct sockaddr_storage dsc_soa_conn;    /* address information of connection */
   volatile struct dsd_sdh_control_1 *adsc_sdhc1_send;  /* chain to send */
   struct dsd_netw_post_1 *adsc_netw_post_1;  /* structure to post from network callback */
   BOOL       boc_connected;                /* TCP session is connected */
   BOOL       boc_naeg1_disa;               /* disable naegle algorithm */
   BOOL       boc_act_conn_send;            /* activate connection after send */
};

enum ied_state_server {
   ied_ses_reset,
   ied_ses_auth,                            /* status authentication   */
   ied_ses_do_lbal,                         /* status do load-balancing */
   ied_ses_prep_server,
   ied_ses_wait_conn_s_static,              /* wait for static connect to server */
   ied_ses_wait_conn_s_dynamic,             /* wait for dynamic connect to server */
   ied_ses_do_cpttdt,                       /* connect pass thru to desktop */
   ied_ses_start_server_1,                  /* start connection to server part one */
   ied_ses_wait_csssl,                      /* wait for client-side SSL */
   ied_ses_start_server_2,                  /* start connection to server part two */
   ied_ses_start_sdh,                       /* start Server-Data-Hooks */
   ied_ses_conn,                            /* server is connected     */
   ied_ses_error_conn,                      /* error connect to server */
   ied_ses_error_co_dyn,                    /* error connect to server dynamic */
   ied_ses_rec_close,                       /* received close          */
   ied_ses_abend                            /* abnormal end of session */
};

enum ied_state_client {
   ied_cls_set_entropy = 0,                 /* set entropy             */
   ied_cls_normal,                          /* normal processing       */
   ied_cls_wait_start,                      /* wait for start message  */
   ied_cls_start_02,                        /* process start messages  */
   ied_cls_proc_ssl,                        /* process data as SSL input */
   ied_cls_normal_http,                     /* process normal HTTP     */
   ied_cls_rec_close,                       /* received close          */
   ied_cls_closed                           /* client connection closed */
};

enum ied_servcotype_def {                   /* type of server connection */
   ied_servcotype_none = 0,                 /* no server connection    */
   ied_servcotype_ended,                    /* server connection ended */
   ied_servcotype_normal_tcp,               /* normal TCP              */
   ied_servcotype_htun,                     /* HOB-TUN                 */
   ied_servcotype_l2tp                      /* L2TP                    */
};

struct dsd_vol_a_sdhc1 {                    /* structure with member volatile */
   volatile struct dsd_sdh_control_1 *adsc_sdhc1;  /* pointer to structure */
};

struct dsd_co_sort {                        /* for connection sort    */
   struct dsd_htree1_avl_entry dsc_sort_1;  /* entry for sorting       */
   int        imc_sno;                      /* session number          */
};

struct dsd_conn1 {                          /* connection to client    */
   struct dsd_co_sort dsc_co_sort;          /* for connection sort    */
   struct dsd_gate_1 *adsc_gate1;           /* which gateway           */
   struct dsd_gate_listen_1 *adsc_gate_listen_1;  /* listen part of gateway */
   struct dsd_server_conf_1 *adsc_server_conf_1;  /* configuration server */
// class dsd_tcpcomp dsc_tcpco1_client;     /* connection object client */
   struct dsd_tcp_ctrl_1 dsc_tc1_client;    /* TCP control structure client */
#ifndef HL_SOLARIS
   union {
     struct {                               /* for TCPCOMP             */
#endif
//     class dsd_tcpcomp dsc_tcpco1_server;  /* connection object server */
       struct dsd_tcp_ctrl_1 dsc_tc1_server;  /* TCP control structure server */
#ifdef B120911
       struct dsd_netw_post_1 dsc_netw_post_1;  /* structure to post from network callback */
#endif
#ifndef HL_SOLARIS
     };
#endif
#ifdef D_INCL_HOB_TUN
#ifndef HL_SOLARIS
     struct {                               /* for HOB-TUN             */
#endif
       volatile dsd_htun_h dsc_htun_h;      /* handle for HOB-TUN      */
       struct dsd_tun_contr_conn dsc_tun_contr_conn;  /* HOB-TUN control area connection */
       struct sockaddr_storage dsc_soa_htcp_server;  /* address information for connected */
       struct dsd_sdh_control_1 *adsc_sdhc1_htun_sch;  /* chain of buffers to send over HOB-TUN */
       int    imc_send_window;              /* number of bytes to be sent */
       int    imc_ppp_state;                /* PPP state               */
       struct dsd_netw_post_1 *adsc_ppp_netw_post_1;  /* structure to post from network callback */
#ifndef HL_SOLARIS
     };
#endif
#endif
#ifndef HL_SOLARIS
     struct {                               /* for L2TP                */
#endif
       struct dsd_l2tp_session dsc_l2tp_session;  /* L2TP connection session */
       struct dsd_sdh_control_1 *adsc_sdhc1_l2tp_sch;  /* chain of buffers to send over L2TP */
#ifndef HL_SOLARIS
     };
   };
#endif
   class dsd_hcla_critsect_1 dsc_critsect;  /* critical section        */
   struct dsd_hl_ssl_s_3 dsc_hlse03s;       /* structure for SSL       */
   struct dsd_timer_ele dsc_timer;          /* timer for wait          */
   int        imc_timeout_set;              /* timeout set in seconds  */
   HL_LONGLONG ilc_timeout;                 /* save end-time timeout   */
   struct dsd_auxf_1 *adsc_aux_timer_ch;    /* chain auxiliary timer   */
   struct dsd_auxf_1 *adsc_aux_ldap;        /* auxiliary LDAP field    */
#ifdef D_INCL_HOB_TUN
   struct dsd_ineta_raws_1 *adsc_ineta_raws_1;  /* INETA in use        */
#endif
   char       chrc_ineta[ LEN_DISP_INETA ];  /* internet-address char  */
#ifdef XYZ1
   int   ifd_c;                             /* file descr client       */
   int   ifd_s;                             /* file descr server       */
#endif
#ifdef B130216
   struct dsd_conn_server *adsc_conn_server;  /* temporary connect to server */
#endif
   struct dsd_conn_pttd_thr *adsc_cpttdt;   /* connect PTTD thread     */
#ifdef XYZ1
   union dsd_un_soaddr_1 dsc_un_sa_client;  /* from client             */
   union dsd_un_soaddr_1 dsc_un_sa_server;  /* from server             */
   int   inc_client_addr_len;               /* length client address   */
#endif
   class dsd_lbal_gw_1 *adsc_lbal_gw_1;     /* class load balancing GW */
   struct dsd_wts_udp_1 *adsc_wtsudp1;      /* WTS UDP                 */
   struct dsd_aux_cf1 *adsc_aux_cf1_cur;    /* current auxiliary control structure */
   BOOL       boc_st_sslc;                  /* SSL handshake complete  */
   BOOL       boc_sdh_started;              /* Server-Data-Hooks have been started */
#ifndef B130314
   BOOL       boc_signal_set;               /* signal for component set */
#endif
#ifdef OLD_1112
   class dsd_radius_query *adsc_radqu;      /* class Radius Query      */
#else
   struct dsd_wsp_auth_1 *adsc_wsp_auth_1;  /* structure for authentication */
#endif
   struct dsd_int_webso_conn_1 *adsc_int_webso_conn_1;  /* connect for WebSocket applications - internal */
   void **    avprc_sdh;                    /* address array serv-d-ho */
   struct dsd_auxf_1 *adsc_auxf_1;          /* chain auxiliary ext fi  */
   struct dsd_sdh_control_1 *adsc_sdhc1_frcl;  /* chain of buffers from client (SSL encrypted) */
   struct dsd_sdh_control_1 *adsc_sdhc1_chain;  /* chain of buffers input output */
   struct dsd_sdh_control_1 *adsc_sdhc1_inuse;  /* chain of buffers in use */
   struct dsd_sdh_control_1 *adsc_sdhc1_extra;  /* chain of buffers extra */
   struct dsd_csssl_oper_1 *adsc_csssl_oper_1;  /* operation of client-side SSL */
   struct dsd_user_group *adsc_user_group;  /* structure user group    */
   struct dsd_user_entry *adsc_user_entry;  /* structure user entry    */
   struct dsd_radius_group *adsc_radius_group;  /* active Radius group */
   struct dsd_krb5_kdc_1 *adsc_krb5_kdc_1;  /* active Kerberos 5 KDC   */
   struct dsd_ldap_group *adsc_ldap_group;  /* active LDAP group       */
   struct dsd_pd_http_ctrl *adsc_pd_http_ctrl;  /* process data HTTP control */
   struct dsd_util_thread_ctrl *adsc_util_thread_ctrl;  /* utility thread control */
#ifdef NOT_YET
   struct dsd_hl_ssl_s_2 dsc_hlse02s;       /* structure for SSL       */
#endif
   int        imc_connect_error;            /* save connect error      */
   enum ied_state_client iec_st_cls;        /* status client           */
   enum ied_state_server iec_st_ses;        /* status server           */
   char       *achc_reason_end;             /* reason end session      */
#ifdef OLD01
   volatile struct dsd_sdh_control_1 *adsc_sdhc1_ts_cl;  /* chain to send to client */
   volatile struct dsd_sdh_control_1 *adsc_sdhc1_ts_se;  /* chain to send to server */
#endif
#ifdef B120502
   struct dsd_vol_a_sdhc1 dsc_vol_a_sdhc1_ts_cl;  /* chain to send to client */
   struct dsd_vol_a_sdhc1 dsc_vol_a_sdhc1_ts_se;  /* chain to send to server */
#endif
   struct dsd_sdh_control_1 *adsc_sdhc1_c1;  /* receive buffer client 1 */
   struct dsd_sdh_control_1 *adsc_sdhc1_c2;  /* receive buffer client 2 */
   struct dsd_sdh_control_1 *adsc_sdhc1_s1;  /* receive buffer server 1 */
   struct dsd_sdh_control_1 *adsc_sdhc1_s2;  /* receive buffer server 2 */
   union {
     struct dsd_sdh_session_1 dsc_sdh_s_1;  /* work area server data hook per session */
     struct dsd_sdh_session_1 *adsrc_sdh_s_1;   /* array work area server data hook per session */
   };
   int        imc_timeout;                  /* timeout set in seconds  */
   enum ied_servcotype_def iec_servcotype;  /* type of server connection */
   BOOL       boc_survive;                  /* survive E-O-F client    */
   int        imc_trace_level;              /* trace level set         */
#ifdef D_INCL_HOB_TUN
   int        imc_references;               /* references to this session */
#endif
#ifdef XYZ1
   BOOL       boc_stop_ts_cl;               /* stop send to client     */
   BOOL       boc_stop_ts_se;               /* stop send to server     */
   int        inc_session_no;               /* session number          */
#endif
   int        imc_time_start;               /* time session started    */
   int        inc_c_ns_rece_c;              /* count receive client    */
   int        inc_c_ns_send_c;              /* count send client       */
   int        inc_c_ns_rece_s;              /* count receive server    */
   int        inc_c_ns_send_s;              /* count receive server    */
   int        inc_c_ns_rece_e;              /* count encrypted from cl */
   int        inc_c_ns_send_e;              /* count encrypted to clie */
   HL_LONGLONG ilc_d_ns_rece_c;             /* data receive client     */
   HL_LONGLONG ilc_d_ns_send_c;             /* data send client        */
   HL_LONGLONG ilc_d_ns_rece_s;             /* data receive server     */
   HL_LONGLONG ilc_d_ns_send_s;             /* data send server        */
   HL_LONGLONG ilc_d_ns_rece_e;             /* data receive encyrpted  */
   HL_LONGLONG ilc_d_ns_send_e;             /* data send encrypted     */
#ifdef XYZ1
#ifndef HL_IPV6
   char       chrc_ineta[16];               /* internet-address char   */
#else
   char       chrc_ineta[40];               /* internet-address char   */
#endif
#endif
   char       chrc_priv[ (DEF_PERS_PRIV_LEN + 8 - 1) / 8 ];  /* privileges */
   int        icl_len_cert_name;            /* length of certificate name */
   HL_WCHAR  *awch_cert_name;               /* name from certificate   */
   volatile BOOL boc_st_act;                /* util-thread active      */
   char       chrc_server_error[ LEN_SERVER_ERROR ];  /* display server error */
#ifdef XYZ1
   struct dsd_timer_ele dsc_timer;          /* timer for wait          */
   HL_LONGLONG ilc_timeout;                 /* save end-time timeout   */
   struct dsd_auxf_1 *adsc_aux_timer_ch;    /* chain auxiliary timer   */
   class dsd_hcla_critsect_1 dsc_critsect;  /* critical section        */
   struct dsd_cothr *adsc_cothr;            /* used connection thread  */
#endif
#ifdef NOTYET050818
   DHLSE01 dhlse01s;                        /* structure for SSL       */
#endif
#ifdef TRACEHLP
     int      inc_aux_mem_cur;              /* current memory size     */
     int      inc_aux_mem_max;              /* maximum memory size     */
#endif
};

struct dsd_ligw_receive {                   /* area for receive from listen-gateway */
   struct dsd_ligw_receive *adsc_next;      /* chain of receive areas  */
   struct dsd_gather_i_1 dsc_gai1_r;        /* gather input data       */
};

enum ied_decode_ligw_recv_1 {               /* decode received from listen-gateway */
   ied_dlr1_header = 0,                     /* header received         */
   ied_dlr1_len_nhasn,                      /* length NHASN            */
   ied_dlr1_content                         /* content                 */
};

struct dsd_map_charset {                    /* map character set       */
   char       *achc_name;                   /* name of character set   */
   enum ied_charset iec_charset;            /* define character set    */
};

#ifdef D_INCL_HOB_TUN
struct dsd_tun_send_garp {                  /* structure to send a GARP Gratuitous ARP */
   char       chrc_h_macaddr_destination[ 6 ];  /* mac address of destination */
   char       chrc_h_macaddr_source[ 6 ];   /* mac address of source   */
   char       chrc_const_01[ 10 ];          /* constants               */
   char       chrc_pl_macaddr_source[ 6 ];  /* Sender hardware address (SHA) */
   char       chrc_pl_ineta_source[ 4 ];    /* Sender protocol address (SPA) */
   char       chrc_pl_macaddr_target[ 6 ];  /* Target hardware address (THA) */
   char       chrc_pl_ineta_target[ 4 ];    /* Target protocol address (TPA) */
};
#endif

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

// to-do 08.08.11 KB ??? new radius
struct dsd_radius_control dsg_radius_control;  /* control radius       */

struct dsd_cdaux_control dsg_cdaux_control;  /* control m_cdaux        */

static struct dsd_extra_thread_stat dss_ets_pttd = {  /* statistics about extra threads - pass-thru-to-desktop */
   0,                                       /* int imc_no_started - number of instances started */
   0,                                       /* int imc_no_current - number of instances currently executing */
   0,                                       /* int imc_no_denied - number of start requests denied */
   0,                                       /* HL_LONGLONG ilc_sum_time_ms - summery time executed in milliseconds */
   NULL                                     /* struct dsd_extra_thread_entry *adsc_ete_ch - chain extra thread entries */
};

static struct dsd_extra_thread_stat dss_ets_ut = {  /* statistics about extra threads - utility threads */
   0,                                       /* int imc_no_started - number of instances started */
   0,                                       /* int imc_no_current - number of instances currently executing */
   0,                                       /* int imc_no_denied - number of start requests denied */
   0,                                       /* HL_LONGLONG ilc_sum_time_ms - summery time executed in milliseconds */
   NULL                                     /* struct dsd_extra_thread_entry *adsc_ete_ch - chain extra thread entries */
};

// to-do 08.08.11 KB ??? fill path
static char   *adss_path_param = NULL;      /* path of param - xml file */

       class dsd_hcla_critsect_1 dsg_global_lock;  /* global lock      */

static class dsd_hcla_critsect_1 dss_trace_lock;  /* lock for WSP-trace */

static int    imrs_m_fd_pipe[2] = { 0, 0 };  /* file decriptores pipe main */

/* anchor of previously loaded XML configurations                      */
static struct dsd_see_cd_plain_xml *adss_see_cd_plain_xml_anchor = NULL;  /* see in core dump plain XML configuration */
/* loaded configuration used in this program and in subroutines        */
static struct dsd_loconf_1 dss_loconf_1;
extern struct dsd_sdh_lib1 *adsg_sdhl_anchor = NULL;  /* anchor of cha */
#ifdef B120211
extern struct dsd_hlwspat2_lib1 *adsg_hlwspat2l_anchor = NULL;  /* anchor chain authentication library */
#endif

extern "C" BOOL bog_not_aus_start = FALSE;  /* stop immediately        */
extern "C" BOOL bog_log = FALSE;            /* no event log yet        */
extern "C" BOOL bog_event_log_out = FALSE;  /* something written to event log */
static BOOL   bos_end_proc = FALSE;         /* signal end of processing */
#ifdef XYZ1
static BOOL   bos_shutdown = FALSE;         /* is in graceful shutdown */
#endif
static BOOL   bos_mem_log = FALSE;          /* write to memory log     */
static BOOL   bos_disk_file = FALSE;        /* did not access disk file yet */
static BOOL   bos_pid_file = FALSE;         /* PID file not active     */

static struct dsd_wsp_tr_ineta_ctrl *adss_wtic_active = NULL;  /* WSP trace client with INETA control */
static struct dsd_diskfile_1 *adss_df1_anchor = NULL;  /* diskfile in memory */
static int    ins_session_no = 0;           /* session no              */
extern struct dsd_hco_main dsg_hco_main;    /* work threads            */
static int    ims_priority_process;         /* priority of process     */
static unsigned char ucs_random_01 = 0;
static int    ims_count_cma_sync = 0;       /* count currently active CMA synchronize */

static void   *asrecbuf = NULL;             /* chain of cached buffers */
#ifndef PROC_ALLOC_02
#ifndef PROC_ALLOC_03
static int    ims_count_free = 0;           /* count free of buffers   */
#endif
#endif
#ifdef PROC_ALLOC_02
static int    ims_proc_alloc_count = 0;     /* count free buffers in this memory area */
static char * achs_proc_alloc_next;         /* next address to use     */
static HL_LONGLONG ils_proc_alloc_occupied = 0;  /* storage occupied by proc-alloc */
#endif
#ifdef PROC_ALLOC_03
static int    ims_spin_alloc_1 = 0;         /* memory for spin lock    */
#endif
static struct dsd_perf_data dss_perf_data;  /* performance data        */
static class dsd_hcla_critsect_1 dss_alloc_critsect;  /* for alloc / free */
static class dsd_hcla_critsect_1 dss_critsect_aux;  /* for aux subroutine */
static class dsd_hcla_critsect_1 dss_main_critsect;  /* for AVL-tree   */
static class dsd_hcla_critsect_1 dss_util_critsect;  /* for utilities  */

static char   chrs_msg_pre[ 5 ] = { 0, 0, 0, 0, 0 };

#define LEN_MSG_PRE sizeof(chrs_msg_pre)

static void * vprs_message_shutdown[ DEF_MSG_PIPE_LEN ] = {  /* message in pipe shutdown */
   (void *) ied_mepm_sig_check_shu,         /* message signal check shutdown */
   NULL
};

static void * vprs_message_work[ DEF_MSG_PIPE_LEN ] = {  /* message in pipe work to do */
   (void *) ied_mepm_work,                  /* message work to do      */
   NULL
};

#ifndef TRY_120513_03                       /* SO_REUSEADDR            */
static int    ims_true = TRUE;
#else
static int    ims_true = -1;
#endif
#ifdef HL_UNIX
#ifndef HL_LINUX
static int    ims_zero = 0;
#endif
#endif

static unsigned char ucrs_cr_lf[ 2 ] = { CHAR_CR, CHAR_LF };

#ifndef B160423
static const char chrs_ext_random_g_eyecatcher[] = {
   'H', 'O', 'B', ' ',
   'r', 'a', 'n', 'd', 'o', 'm', ' ', 'g', 'e', 'n', 'e', 'r', 'a', 't', 'o', 'r', ' ', 'V', '0', '1',
   ' ', '-', ' ',
   'W', 'S', 'P', ' ',
   'n', 'b', 'i', 'p', 'g', 'w', '2', '0', ' ', 'V', '2', '.', '3',
   CHAR_CR, CHAR_LF
};
#endif
#ifdef D_HPPPT1_1
static unsigned char ucrs_wsp_ident[] = {
   'H', 'O', 'B', '-', 'W', 'S', 'P', '-', 'V', '2', '.', '3'
};

static unsigned char ucrs_mscv2_magic1[ 39 ] = {  /* length 39         */
   0X4D, 0X61, 0X67, 0X69, 0X63, 0X20, 0X73, 0X65, 0X72, 0X76,
   0X65, 0X72, 0X20, 0X74, 0X6F, 0X20, 0X63, 0X6C, 0X69, 0X65,
   0X6E, 0X74, 0X20, 0X73, 0X69, 0X67, 0X6E, 0X69, 0X6E, 0X67,
   0X20, 0X63, 0X6F, 0X6E, 0X73, 0X74, 0X61, 0X6E, 0X74
};

static unsigned char ucrs_mscv2_magic2[ 41 ] = {  /* length 41         */
   0X50, 0X61, 0X64, 0X20, 0X74, 0X6F, 0X20, 0X6D, 0X61, 0X6B,
   0X65, 0X20, 0X69, 0X74, 0X20, 0X64, 0X6F, 0X20, 0X6D, 0X6F,
   0X72, 0X65, 0X20, 0X74, 0X68, 0X61, 0X6E, 0X20, 0X6F, 0X6E,
   0X65, 0X20, 0X69, 0X74, 0X65, 0X72, 0X61, 0X74, 0X69, 0X6F,
   0X6E
};

static unsigned char ucrs_send_avp_ms_01[ 6 ] = {
   0X1A, 0X00,
   0X00, 0X00, 0X01, 0X37
};

static unsigned char ucrs_mscv2_failed_p1[] = {  /* MS-CHAP-V2 failure part one */
   0X04, 0X00, 0X00, 0X34,                  /* header                  */
   0X45, 0X3D, 0X36, 0X39, 0X31, 0X20,      /* E=691                   */
   0X52, 0X3D, 0X31, 0X20, 0X43, 0X3D       /* R=1 C=                  */
};

static unsigned char ucrs_mscv2_failed_p2[] = {  /* MS-CHAP-V2 failure part two */
   0X20, 0X56, 0X3D, 0X33                   /*  V=3                    */
};

static unsigned char ucrs_vendor_s_ms_numbers[ 3 ] = {
   'E', 'R', 'V'
};

/* Constants defined in RFC 3079 - MPPE                                */
static const unsigned char ucrs_mppe_magic1[27] =
        { 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
          0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20, 0x4d,
          0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79 };
      /* "On the client side, this is the send key; "
         "on the server side, it is the receive key." */
static const unsigned char ucrs_mppe_magic2[84] =
        { 0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
          0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
          0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
          0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
          0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
          0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
          0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
          0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
          0x6b, 0x65, 0x79, 0x2e };
      /* "On the client side, this is the receive key; "
         "on the server side, it is the send key." */
static const unsigned char ucrs_mppe_magic3[84] =
        { 0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
          0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
          0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
          0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
          0x6b, 0x65, 0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68,
          0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73,
          0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73,
          0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20,
          0x6b, 0x65, 0x79, 0x2e };

static const unsigned char ucrs_mppe_shspad1[40] =
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static const unsigned char ucrs_mppe_shspad2[40] =
        { 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
          0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
          0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
          0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2 };
#endif

#ifdef XYZ1
static int    imrs_sha1_security_token[ SHA_ARRAY_SIZE ];  /* for hash security-token */
#endif
static HL_LONGLONG ilrs_sha384_security_token[ SHA384_ARRAY_SIZE ];  /* for hash security-token */

extern struct dsd_this_server dsg_this_server = { 0 };  /* data about this server */

extern struct dsd_sys_state_1 dsg_sys_state_1 = {  /* system state     */
   FALSE,     /* boc_load_balancing_started load-balancing has been started */
   -1,        /* imc_load_balancing_value   last value returned by load-balancing */
   0,         /* imc_load_balancing_epoch   time last load-balancing query was done */
   FALSE,     /* boc_htun_started           HTUN has been started      */
   FALSE,     /* boc_htun_start_failed      start of HTUN has failed   */
   FALSE,     /* boc_listen_active          listen is currently active */
   FALSE,     /* boc_listen_ended           listen has already ended   */
   0          /* imc_epoch_listen_act       epoch until which listen keeps active */
};

static struct dsd_sysaddr dss_sysaddr = {   /* structure with System Addresses */
   sizeof(struct dsd_sysaddr),              /* length of structure     */
#ifdef B100815
   (void *) &m_aux_conn,                    /* address routine m_aux_conn() */
#endif
#ifdef NOT_YET
   (void *) &m_tcp_dynamic_conn,            /* address routine m_tcp_dynamic_conn() - connect TCP */
   &dsg_hco_main,                           /* work threads            */
   &dss_loconf_1,                           /* load configuration      */
   (void *) &m_set_wothr_blocking,
   (void *) &m_set_wothr_active
#endif
};

static struct dsd_map_charset dsrs_map_charset[] = {
   { "UTF-8",           ied_chs_utf_8 },      /* Unicode UTF-8         */
   { "US-ASCII",        ied_chs_ascii_850 },  /* ASCII 850             */
   { "ISO8859-1",       ied_chs_ascii_850 },  /* ASCII 850             */
   { "roman8",          ied_chs_ascii_850 },  /* ASCII 850             */
   { "646",             ied_chs_ascii_850 },  /* ASCII 850             */
   { "ANSI_X3.4-1968",  ied_chs_ascii_850 },  /* ASCII 850             */
   { "ISO-8859-15",     ied_chs_iso8859_15 }  /* ISO 8859-15           */
};

extern "C" enum ied_charset ieg_charset_system = ied_chs_utf_8;  /* Unicode UTF-8 */

/* loaded configurations that are in use now                           */
extern "C" struct dsd_loconf_1 *adsg_loconf_1_inuse = NULL;

static struct dsd_htree1_avl_cntl dss_htree1_avl_cntl_conn;

#ifdef D_INCL_HOB_TUN
static struct dsd_htree1_avl_cntl dss_htree1_avl_cntl_ineta_ipv4;
static struct dsd_htree1_avl_cntl dss_htree1_avl_cntl_ineta_ipv6;
static struct dsd_htree1_avl_cntl dss_htree1_avl_cntl_user_i_ipv4;
static struct dsd_htree1_avl_cntl dss_htree1_avl_cntl_user_i_ipv6;

static const unsigned char ucrs_tun_send_garp[ 10 ] = {
   0X08, 0X06,                              /* EtherType for ARP       */
   0X00, 0X01,                              /* Hardware type (HTYPE)   */
   0X08, 0X00,                              /* Protocol type (PTYPE)   */
   0X06,                                    /* Hardware address length (HLEN) */
   0X04,                                    /* Protocol address length (PLEN) */
   0X00, 0X01                               /* Operation (OPER)        */
};

static struct dsd_tun_send_garp dss_tun_send_garp;  /* structure to send a GARP Gratuitous ARP */

#ifdef HL_LINUX
static struct sockaddr_ll dss_soa_arp;
#endif
#endif

static struct dsd_htree1_avl_cntl dss_htree1_avl_cntl_aux_pipe_listen;

static struct dsd_htree1_avl_cntl dss_htree1_avl_cntl_aux_sdh_reload;

static struct dsd_swap_stor_ctrl dss_swap_stor_ctrl = { 0 };  /* swap storage control */

#ifdef B121031_X2
#ifndef B121031
static BOOL   bos_start_cluster;            /* need to start cluster   */
#endif
#endif
static struct dsd_cluster_ineta_this *adss_cluster_ineta_this = NULL;  /* chain save INETA this cluster member */
static int ims_cluster_ineta_sequ = 0;      /* sequence number cluster queries */

#ifdef WAS_BEFORE_1501
static struct dsd_sdh_reload_saved *adss_sdh_reload_saved_ch = NULL;  /* chain SDHs, saved for reload */
#endif

#ifndef TJ_B171019
static HL_LONGLONG ils_d_sent=0;            /* data sent to client network */
static HL_LONGLONG ils_d_recv=0;            /* data received from client network */
#endif

static struct dsd_acccallback dss_acccb;

static struct dsd_tcpcallback dss_tcpcomp_cb1 = {
   &m_cb_tcpc_conn_err,                     /* connect error callback function */
   &m_cb_tcpc_connect,                      /* connect callback function */
   &m_cb_tcpc_send,
   &m_cb_tcpc_getbuf,
   &m_cb_tcpc_recv,
   &m_cb_tcpc_error,
   &m_cb_tcpc_cleanup,
   &m_get_random_number
};

static struct dsd_main_poll_sub {           /* structure main poll subroutine */
   int        imc_poll_ele;                 /* elements for poll()     */
   struct pollfd dsrc_poll[ 2 ];            /* for poll()              */
} dss_main_poll_sub;

static struct dsd_ligw_g {                  /* structure Listen Gateway */
   BOOL       boc_connected;                /* connected to Listen Gateway */
   BOOL       boc_stop_listen_lbal;         /* stop listen load-balancing in progress */
   BOOL       boc_listen_start;             /* start listen at program start */
   BOOL       boc_listen_lbal;              /* start listen for load-balancing */
   BOOL       boc_rc_last_listen;           /* return code last listen */
#ifdef D_INCL_HOB_TUN
   BOOL       boc_ser_sent;                 /* serialize command sent  */
   int        imc_open_tun_sent;             /* command open TUN sent   */
#endif
   int        imc_sockfd;                   /* socket for connection   */
   int        imc_time_disconnect;          /* time of disconnect      */
// int        imc_fd_pipe[2];               /* file descriptores pipe  */
   struct dsd_gate_1 *adsc_gate_1_create_socket;  /* current gate to start */
   struct dsd_gate_listen_1 *adsc_gate_listen_1_cur;  /* listen part of gateway currently processed */
   struct dsd_gate_listen_1 *adsc_gate_listen_1_next;  /* listen part of gateway next to process */
   struct dsd_ligw_receive *adsc_rec1_ch;   /* chain of receive areas  */
   struct sockaddr_un dsc_soa_un;           /* address of domain socket */
   int        imrc_sha1_key[ SHA_ARRAY_SIZE ];  /* for hash of key     */
   int        *aimrc_ligw_cluster;          /* cluster structure       */
} dss_ligw_g;

static struct dsd_ser_thr_ctrl {            /* control serial thread   */
   struct dsd_ser_thr_task *adsc_sth_work;  /* work as task for serial thread */
   struct dsd_ser_thr_task *adsc_sth_free;  /* chain of free structures */
   class dsd_hcthread dsc_thread;           /* serial thread           */
   class dsd_hcla_event_1 dsc_event_thr;    /* event of thread         */
   UNSIG_MED  umc_index_if_arp;             /* holds index of compatible IF for ARP */
   UNSIG_MED  umc_index_if_route;           /* holds index of compatible IF for routes */
} dss_ser_thr_ctrl;

static struct dsd_wsp_trace_thr_ctrl {      /* control WSP trace thread */
   struct dsd_wsp_trace_1 *adsc_wt1_anchor;  /* WSP trace record anchor */
   struct dsd_wsp_trace_1 *adsc_wt1_last;   /* WSP trace record last in chain */
   BOOL       boc_tread_running;            /* WSP trace thread is running */
   enum ied_wsp_trace_target iec_wtt;       /* WSP Trace target        */
   BOOL       boc_cma_dump;                 /* make CMA dump           */
   class dsd_hcthread dsc_thread;           /* serial thread           */
   class dsd_hcla_event_1 dsc_event_thr;    /* event of thread         */
} dss_wsp_trace_thr_ctrl;

extern "C" int img_wsp_trace_core_flags1 = 0;  /* WSP trace core flags */

static const char chrs_query_main[] = MSG_QUERY MSG_CPU_TYPE __DATE__;

#ifdef NEW_REPORT_1501
static struct dsd_bandwidth_client_ctrl dss_bc_ctrl = { 0 };  /* measure bandwidth with clients - control */
#endif

#ifdef D_INCL_HOB_TUN
extern "C" struct dsd_tun_ctrl dsg_tun_ctrl = { 0 };  /* HOB-TUN control area  */
#endif
#ifdef XYZ1
static char chrs_requestheader_query[] = {  /* Request message header  */
   0X48, 0X4F, 0X42, 0X20, 0X4C, 0X49, 0X00, 0X51, 0X00  /* HOB LI - Q */
};

static char chrs_requestheader_response[] = {  /* Request message header */
   0X48, 0X4F, 0X42, 0X20, 0X4C, 0X49, 0X00, 0X52, 0X00  /* HOB LI - R */
};
#endif

#ifdef D_INCL_HOB_TUN
#ifdef HL_FREEBSD
#ifndef B160502
static char   chrs_tun_mask_ipv4[ 4 ] = { 0XFF, 0XFF, 0XFF, 0XFC };  /* TUN-adapter-network-mask IPv4 */
#endif
#endif
#endif

static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

static const char chrs_crlf[] = { 0X0D, 0X0A };

static char   chs_zero = 0;                 /* memory with zero        */
static void * vps_ones = (void *) ((long long int) -1);  /* memory with all bits set */

#ifdef TRACEHL1
static int    ims_cdaux = 0;                /* count call m_cdaux()    */
#endif

/*+-------------------------------------------------------------------+*/
/*| Internal used classes.                                            |*/
/*+-------------------------------------------------------------------+*/

#include "XSBSTR01.hpp"
#include "XSLBGW01.hpp"

   class dcl_blasetr_1 * dcl_blasetr_1::adss_blasetr_1_anchor = NULL;  /* anchor */
   class dcl_blasetr_1 * dcl_blasetr_1::adss_blasetr_1_free = NULL;  /* anchor free */

/*+-------------------------------------------------------------------+*/
/*| Main control procedure.                                           |*/
/*+-------------------------------------------------------------------+*/

int main( int impargc, char *achrpargv[] ) {
   BOOL       bol1;                         /* working variable        */
   BOOL       bol_rc;                       /* return code             */
#ifdef NEW_REPORT_1501
   BOOL       bol_fingerprint;              /* print fingerprint in report */
#endif
   int        iml_rc;                       /* return code             */
#ifndef NEW_REPORT_1501
   int        iml1, iml2;                   /* working variables       */
#endif
   int        iml_file1;                    /* file-descriptor for configuration file */
   int        iml_endtime;                  /* compute end-time for poll */
   enum ied_ret_main_poll iel_rmp;          /* return from main poll   */
   time_t     dsl_time_1;                   /* for time                */
   time_t     dsl_time_last_report;         /* time of last report     */
   time_t     dsl_time_cma_check;           /* time to check CMA entries */
#ifdef NEW_REPORT_1501
   time_t     dsl_time_fingerprint;         /* time to print fingerprint in report */
   int        iml_diff_report;              /* time difference report  */
   int        iml1, iml2, iml3, iml4, iml5;  /* working variables      */
   HL_LONGLONG ill_w1, ill_w2, ill_w3, ill_w4;  /* working variables   */
#endif
#ifndef NEW_REPORT_1501
   HL_LONGLONG ill1, ill2;                  /* working-variable        */
#endif
   char       *achl1, *achl2;               /* working variables       */
#ifdef B160827
   char       *achl_buffer;                 /* buffer for read         */
#endif
   struct dsd_see_cd_plain_xml *adsl_see_cd_plain_xml;  /* see in core dump plain XML configuration */
   char       *achl_avl_error;              /* error code AVL tree     */
#ifdef NEW_REPORT_1501
   struct dsd_bandwidth_client_1 *adsl_bc1_report;  /* measure bandwidth with clients */
#endif
   struct dsd_gate_1 *adsl_gate_1_w1;       /* for start listen        */
   struct dsd_diskfile_1 *adsl_df1_1;       /* diskfile in memory      */
   struct dsd_extra_thread_entry *adsl_ete_w1;  /* extra thread entries */
   struct dsd_bgt_contr_1 *adsl_bgt_contr_1;  /* definition background-task control */
   struct dsd_bgt_function_1 *adsl_bgt_function_1;  /* chain background-task functions */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace record        */
   struct sigaction dsl_aact;               /* Signal action structure */
   struct stat dsl_stat_1;                  /* for stat() of configuration file */
   struct dsd_aux_cf1 dsl_aux_cf1;          /* auxiliary control structure */
   struct dsd_bgt_call_1 dsl_bgt_call_1;    /* Background-Task Call    */
   struct dsd_cluster_report dsl_cluster_report;  /* cluster report structure */
   int        imrl_sha1[ SHA_ARRAY_SIZE ];  /* for hash                */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
#ifdef NEW_REPORT_1501
#ifdef XYZ1
   struct tm  *adsl_tm_w1;                  /* working variable        */
   struct tm  dsl_tm_l1;                    /* working variable        */
   struct tm  dsl_tm_l2;                    /* working variable        */
#endif
   char       chrl_disp_fp[ DEF_LEN_FINGERPRINT * 2 + DEF_LEN_FINGERPRINT / 2 - 1 ];
#endif
   char       chrl_ns_num[16];              /* for number              */
   char       chrl_work1[ 512 ];            /* work area               */
   char       chrl_work2[ 512 ];            /* work area               */
   char       chrl_work3[ 512 ];            /* work area               */
   /* field for Xerces                                                 */
   bool                       recognizeNEL = false;
   char                       localeStr[64];
#ifdef XYZ1
   dsd_xml_mis_1 *adsl_xml_mis;             /* for xml parsing         */
#endif
   AbstractDOMParser::ValSchemes valScheme = AbstractDOMParser::Val_Auto;
   bool                       doNamespaces       = false;
   bool                       doSchema           = false;
   bool                       schemaFullChecking = false;
   bool                       doList = false;
   bool                       errorOccurred = false;


#ifdef TRACEHL1
   setbuf( stdout, 0 );
   printf( "nbipgw20-l%05d-I start program\n", __LINE__ );
#endif
   printf( MSG_CONS_P1 HL_CPUTYPE " " __DATE__ MSG_CONS_P2 "\n" );

   if (impargc != (1 + 1)) {
     printf( "HWSPM004W Number of parameters invalid (*.xml)\n" );
     return -1;
   }

#ifdef TRY_121211_01                        /* core dump               */
   iml_rc = prctl( PR_SET_DUMPABLE, 1, 0, 0, 0 );
   m_hlnew_printf( HLOG_WARN1, "l%05d prctl() returned iml_rc=%d errno=%d.",
                   __LINE__, iml_rc, errno );
#endif /* TRY_121211_01                        core dump               */

   iml_rc = pipe( imrs_m_fd_pipe );         /* create pipe main        */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d pipe main completed / returned iml_rc=%d errno=%d.",
                   __LINE__, iml_rc, errno );
#endif
// to-do 06.08.11 KB error message
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_EMER1, "HWSPMnnnE l%05d error pipe() %d.",
                     __LINE__, errno );
     return -1;
   }
   dss_main_poll_sub.dsrc_poll[ 0 ].fd = imrs_m_fd_pipe[0];
   dss_main_poll_sub.dsrc_poll[ 0 ].events = POLLIN;
   dss_main_poll_sub.dsrc_poll[ 0 ].revents = 0;

   dss_main_poll_sub.imc_poll_ele = 1;      /* elements for poll()     */
   dss_main_poll_sub.dsrc_poll[ 1 ].revents = 0;  /* no event for listen-gateway */

   dsl_aact.sa_handler = &m_signal_end;     /* set handler method      */
   sigemptyset( &dsl_aact.sa_mask );        /* clear action set        */
   dsl_aact.sa_flags = 0;                   /* clear flags             */

   sigaction( SIGINT, &dsl_aact, 0 );       /* act handler on CTRL-C   */
   sigaction( SIGTSTP, &dsl_aact, 0 );      /* act handler on CTRL_Z   */
   sigaction( SIGTERM, &dsl_aact, 0 );      /* act handler on KILL     */
   signal( SIGPIPE, SIG_IGN );

   dsl_aact.sa_handler = &m_signal_rec;     /* set handler method      */
   sigemptyset( &dsl_aact.sa_mask );        /* clear action set        */
   dsl_aact.sa_flags = 0;                   /* clear flags             */

   sigaction( SIGUSR1, &dsl_aact, 0 );      /* act handler on USR1     */
   sigaction( SIGUSR2, &dsl_aact, 0 );      /* act handler on USR2     */

   /* character set                                                    */
   setlocale( LC_ALL, "" );
   achl1 = nl_langinfo( CODESET );
   if (achl1) {                             /* something returned      */
     iml1 = sizeof(dsrs_map_charset) / sizeof(dsrs_map_charset[0]);
     while (TRUE) {                         /* loop to find character set */
       iml1--;                              /* decrement index         */
       if (iml1 < 0) break;                 /* not in table            */
       if (!strcmp( dsrs_map_charset[ iml1 ].achc_name, achl1 )) {
         ieg_charset_system = dsrs_map_charset[ iml1 ].iec_charset;
         switch (ieg_charset_system) {
           case ied_chs_ascii_850:          /* ASCII 850               */
             achl2 = "ASCII 850";
             break;
           case ied_chs_utf_8:              /* Unicode UTF-8           */
             achl2 = "UTF-8";
             break;
           case ied_chs_iso8859_15:         /* ISO 8859-15             */
             achl2 = "ISO-8859-15";
             break;
           default:
             achl2 = "*invalid*";
             break;
         }
         m_hlnew_printf( HLOG_INFO1, "HWSPM110I found character set %s translated to %s.",
                         achl1, achl2 );
         break;
       }
     }
     if (iml1 < 0) {                        /* character set not found */
       m_hlnew_printf( HLOG_WARN1, "HWSPM111W found character set %s - not recognized, using UTF-8.",
                       achl1 );
     }
   } else {                                 /* nothing returned        */
     m_hlnew_printf( HLOG_WARN1, "HWSPM112W nl_langinfo() did not return character set - using UTF-8." );
   }
   /* fill data about this server                                      */
   dsg_this_server.ilc_epoch_started = m_get_rand_epoch_ms();
#ifndef B140819
   /* initialize random generator                                      */
   srand( (unsigned int) (m_get_rand_epoch_ms() >> 7) );
#endif
   dsg_this_server.chrc_server_name[0] = 0;
   iml1 = gethostname( dsg_this_server.chrc_server_name,
                       sizeof(dsg_this_server.chrc_server_name) );
   if (iml1 < 0) {                          /* did not return hostname */
// to-do 06.08.11 KB error message
     m_hlnew_printf( HLOG_XYZ1, "HWSPM115W l%05d error gethostname() %d.",
                     __LINE__, errno );
     dsg_this_server.imc_len_server_name = -1;
   } else {                                 /* no error                */
     dsg_this_server.imc_len_server_name = strlen( dsg_this_server.chrc_server_name );
   }
   if (dsg_this_server.imc_len_server_name <= 0) {  /* no valid server name */
     strcpy( dsg_this_server.chrc_server_name, "???" );
     dsg_this_server.imc_len_server_name = 3;
   }
   dsg_this_server.imc_pid = getpid();      /* get process id          */
// to-do 16.11.12 KB - move to other place, depending on configuration
   if (TRUE) {
     chrs_msg_pre[ 4 ] = ' ';               /* separator               */
     iml1 = dsg_this_server.imc_pid;        /* get pid                 */
     iml2 = 4;                              /* number of base64 characters */
     do {                                   /* loop generate base64    */
       iml2--;                              /* decrement index         */
       chrs_msg_pre[ iml2 ] = ucrs_base64[ iml1 & 0X3F ];
       iml1 >>= 6;                          /* remove 6 bits           */
     } while (iml2 > 0);
   }
#ifdef XYZ1
// to-do 06.08.11 KB
   dsg_this_server.boc_endian_big = FALSE;  /* Windows - CPU is not big endian */
#endif
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
   dsg_this_server.boc_endian_big = TRUE;   /* CPU is big endian       */
#else
   dsg_this_server.boc_endian_big = FALSE;  /* CPU is not big endian   */
#endif
   dsg_this_server.imc_aligment = sizeof(void *);  /* aligment         */
   /* compute fingerprint / hash                                       */
   SHA1_Init( imrl_sha1 );
   SHA1_Update( imrl_sha1, dsg_this_server.chrc_server_name, 0, dsg_this_server.imc_len_server_name );
   SHA1_Update( imrl_sha1, (char *) &dsg_this_server.imc_pid, 0, sizeof(dsg_this_server.imc_pid) );
   SHA1_Update( imrl_sha1, (char *) &dsg_this_server.ilc_epoch_started, 0, sizeof(dsg_this_server.ilc_epoch_started) );
   iml1 = m_get_random_number( 0X010000 );
   SHA1_Update( imrl_sha1, (char *) &iml1, 0, sizeof(iml1) );
   SHA1_Final( imrl_sha1, dsg_this_server.chrc_fingerprint, 0 );
   /* priority of process                                              */
   ims_priority_process = DEF_PRIO_DEFAULT;
   memset( &dss_ser_thr_ctrl, 0, sizeof(dss_ser_thr_ctrl) );  /* control serial thread */
   memset( &dss_wsp_trace_thr_ctrl, 0, sizeof(dss_wsp_trace_thr_ctrl) );  /* control WSP trace thread */
   dss_alloc_critsect.m_create();           /* critical section        */
   dss_main_critsect.m_create();            /* critical section        */
   dss_util_critsect.m_create();            /* critical section        */
#ifdef B080324
   ds_blade_control.boc_blade_active = FALSE;  /* blade funct not act  */
#endif
   memset( &dss_loconf_1, 0, sizeof(struct dsd_loconf_1) );
#ifdef XYZ1
   /* anchor of loaded configurations                                  */
   adss_loconf_1_anchor = &dss_loconf_1;
   /* loaded configurations that are filled now                        */
   adss_loconf_1_fill = &dss_loconf_1;
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T before initializing XML",
                   __LINE__ );
#endif
   /* loaded configurations that are in use now                        */
   adsg_loconf_1_inuse = &dss_loconf_1;
   // Initialize the XML4C system
   memset( localeStr, 0, sizeof localeStr );
    try
    {
        if (strlen(localeStr))
        {
            XMLPlatformUtils::Initialize(localeStr);
        }
        else
        {
            XMLPlatformUtils::Initialize();
        }

        if (recognizeNEL)
        {
            XMLPlatformUtils::recognizeNEL(recognizeNEL);
        }
    }

    catch (const XMLException& toCatch)
    {
      m_hlnew_printf( HLOG_EMER1, "HWSPM010W Error during XERCES-initialization: %s",
                      toCatch.getMessage() );
      m_hlnew_printf( HLOG_EMER1, "HWSPM011E Gateway could not start because exception in XERCES initialization" );
      return -1;
    }

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "l%05d open \"%s\"", __LINE__, achrpargv[1] );
#endif
   adss_path_param = realpath( achrpargv[1], NULL );
   if (adss_path_param == NULL) {           /* path not found          */
     m_hlnew_printf( HLOG_EMER1, "HWSPPCnnnE realpath input file %s returned error %d.",
                     achrpargv[1], errno );
     return -1;                             /* return with error       */
   }
   iml_file1 = open( adss_path_param, O_RDONLY );
   if (iml_file1 < 0) {                     /* error occured           */
     m_hlnew_printf( HLOG_EMER1, "HWSPPCnnnE open input file %s returned error %d.",
                     adss_path_param, errno );
     return -1;                             /* return with error       */
   }
   iml_rc = fstat( iml_file1, &dsl_stat_1 );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_EMER1, "HWSPPCnnnE fstat input file %s returned error %d %d.",
                     adss_path_param, iml_rc, errno );
     close( iml_file1 );                    /* close configuration file */
     return -1;                             /* return with error       */
   }
   if (dsl_stat_1.st_size > DEF_MAX_LEN_CONF_FILE) {
     m_hlnew_printf( HLOG_EMER1, "HWSPPCnnnE configuration file %s too big (size=%lld)",
                     adss_path_param, (HL_LONGLONG) dsl_stat_1.st_size );
     close( iml_file1 );                    /* close configuration file */
     return -1;                             /* return with error       */
   }
#ifdef B160827
   achl_buffer = (char *) malloc( (int) dsl_stat_1.st_size );
   if (achl_buffer == NULL) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPPCnnnE error malloc() content configuration-file %s",
                     adss_path_param );
     close( iml_file1 );                    /* close configuration file */
     return -1;                             /* return with error       */
   }
   iml_rc = read( iml_file1, achl_buffer, (int) dsl_stat_1.st_size );
   if (iml_rc != dsl_stat_1.st_size) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPPCnnnE read() file %s returned error %d %d.",
                     adss_path_param, iml_rc, errno );
     free( achl_buffer );                   /* free memory again       */
     close( iml_file1 );                    /* close configuration file */
     return -1;                             /* return with error       */
   }
#endif
   adsl_see_cd_plain_xml                    /* see in core dump plain XML configuration */
     = (struct dsd_see_cd_plain_xml *) malloc( sizeof(struct dsd_see_cd_plain_xml) + dsl_stat_1.st_size );
   if (adsl_see_cd_plain_xml == NULL) {     /* out of memory           */
     m_hlnew_printf( HLOG_EMER1, "HWSPPC004W error malloc() content configuration-file %s",
                     adss_path_param );
     close( iml_file1 );                    /* close configuration file */
     return -1;                             /* return with error       */
   }
   memset( adsl_see_cd_plain_xml, 0, sizeof(struct dsd_see_cd_plain_xml) );
   adsl_see_cd_plain_xml->dsc_time_loaded = m_get_time();  /* epoch when loaded */
   memcpy( adsl_see_cd_plain_xml->byrc_eye_catcher,
           DEF_LOAD_XML_CONF_EC,
           sizeof(DEF_LOAD_XML_CONF_EC) - 1 );
   strftime( adsl_see_cd_plain_xml->byrc_eye_catcher + sizeof(DEF_LOAD_XML_CONF_EC) - 1,
             sizeof(adsl_see_cd_plain_xml->byrc_eye_catcher) - sizeof(DEF_LOAD_XML_CONF_EC) + 1,
             "%d.%m.%y %H:%M:%S",
             localtime( &adsl_see_cd_plain_xml->dsc_time_loaded ) );
   adsl_see_cd_plain_xml->adsc_next = adss_see_cd_plain_xml_anchor;
   adss_see_cd_plain_xml_anchor = adsl_see_cd_plain_xml;
//----
   iml_rc = read( iml_file1, (char *) (adsl_see_cd_plain_xml + 1), (int) dsl_stat_1.st_size );
   if (iml_rc != dsl_stat_1.st_size) {
     m_hlnew_printf( HLOG_EMER1, "HWSPPCnnnE read() file %s returned error %d %d.",
                     adss_path_param, iml_rc, errno );
#ifdef B160827
     free( achl_buffer );                   /* free memory again       */
#endif
     close( iml_file1 );                    /* close configuration file */
     return -1;                             /* return with error       */
   }
   iml_rc = close( iml_file1 );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPPCnnnW close configuration file %s returned error %d.",
                     adss_path_param, errno );
   }
   /* compute fingerprint / hash                                       */
   SHA1_Init( imrl_sha1 );
#ifdef B160827
   SHA1_Update( imrl_sha1, achl_buffer, 0, (int) dsl_stat_1.st_size );
#endif
   SHA1_Update( imrl_sha1, (char *) (adsl_see_cd_plain_xml + 1), 0, (int) dsl_stat_1.st_size );
   SHA1_Final( imrl_sha1, dss_loconf_1.chrc_fingerprint, 0 );
#ifdef NOT_YET
   m_disp_conf_file( FALSE );
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T before processing XML",
                   __LINE__ );
#endif
#ifdef XYZ1
   adsl_xml_mis = new dsd_xml_mis_1( (XMLByte *) achl_buffer, (int) dsl_stat_1.st_size );
#endif

    // Instantiate the DOM parser.
    // create Xerces Parser:
    class dsd_xml_parser_1 *adsl_parser = new dsd_xml_parser_1();
#ifndef XYZ1
#ifdef B160827
    class dsd_xml_mis_1 dsl_xml_mis( (XMLByte *) achl_buffer, (int) dsl_stat_1.st_size );
#endif
    class dsd_xml_mis_1 dsl_xml_mis( (XMLByte *) (char *) (adsl_see_cd_plain_xml + 1), (int) dsl_stat_1.st_size );
#endif

    // set options:
    adsl_parser->setDoNamespaces                ( doNamespaces );
    adsl_parser->setDoSchema                    ( doSchema );
    adsl_parser->setValidationSchemaFullChecking( schemaFullChecking );
    adsl_parser->setValidationScheme            ( valScheme );

    // what is this ???
    // enable datatype normalization - default is off
    //parser->setFeature(XMLUni::fgDOMDatatypeNormalization, true);

    // create our error handler and install it
    dsd_xml_error_1 dsl_error_handler;
    adsl_parser->setErrorHandler( &dsl_error_handler );

    XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *doc = 0;

    try
    {
        // reset document pool
        adsl_parser->resetDocumentPool();
        adsl_parser->parse( dsl_xml_mis );
        doc = adsl_parser->getDocument();
    }
    catch (const XMLException& toCatch)
    {
        errorOccurred = true;
    }
    catch (const DOMException& toCatch)
    {
        const unsigned int maxChars = 2047;
        XMLCh errText[maxChars + 1];
        errorOccurred = true;
    }
    catch (...)
    {
        cerr << "\nUnexpected exception during parsing: '" << adss_path_param << "'\n";
        errorOccurred = true;
    }

    //
    //  Extract the DOM tree, get the list of all the elements and report the
    //  length as the count of elements.
    //
    if ( dsl_error_handler.m_error_happened() )
    {
#ifndef TRACE_PRINTF
         cout << "\nErrors occurred, no output available\n" << endl;
#else
         EnterCriticalSection( &dss_critsect_printf );
         printf( "\nErrors occurred, no output available\n" );
         LeaveCriticalSection( &dss_critsect_printf );
#endif
        errorOccurred = true;
    }
     else
    {
#ifdef NOTYET050817
      bol_rc = m_build_conf_01( doc );
#endif
      bol_rc = m_build_conf_01( doc, &dss_loconf_1, &m_startprog );
      if (bol_rc == FALSE) {
//      errorOccurred = true;
        bos_end_proc = TRUE;                /* signal end of processing */
      }
    }
    delete ( adsl_parser );
#ifdef B160827
   free( achl_buffer );                     /* free memory again       */
#endif
#ifdef XYZ1
   delete( adsl_xml_mis );                  /* delete xml class        */
#endif

   if (bos_end_proc) goto p_end_00;         /* end of program          */
   if (errorOccurred) {
     m_hlnew_printf( HLOG_EMER1, "HWSPXMLL001W Configuration could not be loaded because error in configuration file" );
     return -1;
   }
#ifdef DEBUG_130219_01                      /* debug configuration     */
   {
     int imt1 = 0;
     struct dsd_server_list_1 *adst_server_list_1;  /* chain of list of servers */
     struct dsd_server_conf_1 *adst_server_conf_1;  /* server configurat */

     adst_server_list_1 = dss_loconf_1.adsc_server_list_1;
     while (adst_server_list_1) {
       adst_server_conf_1 = adst_server_list_1->adsc_server_conf_1;
       while (adst_server_conf_1) {
         imt1++;
         if (adst_server_conf_1->boc_dynamic) {  /* dynamically allocated */
           m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T main() adst_server_conf_1->boc_dynamic set - entry %d.",
                           __LINE__, imt1 );
         }
         adst_server_conf_1 = adst_server_conf_1->adsc_next;
       }
       adst_server_list_1 = adst_server_list_1->adsc_next;
     }
   }
#endif
   if (dss_loconf_1.adsc_gate_anchor == NULL) {  /* anchor for chain gates */
     m_hlnew_printf( HLOG_EMER1, "HWSPM030W Gateway not started because no connections in configuration file" );
//   m_end_proc();
     goto p_end_00;                         /* end of program          */
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T configuration has been processed",
                   __LINE__ );
#endif

#ifdef NEW_REPORT_1501
   iml1 = dss_loconf_1.inc_report_intv;
   if (iml1 == 0) {
     goto pmt_bc_80;                        /* end of bandwidth client */
   }
   /* number of entries                                                */
   iml2 = (iml1 + DEF_BANDWIDTH_CLIENT_SECS - 1) / DEF_BANDWIDTH_CLIENT_SECS;
   iml_rc = dss_bc_ctrl.dsc_critsect.m_create();
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_bc_ctrl.dsc_critsect m_create Return Code %d",
                     __LINE__, iml_rc );
   }
   dss_bc_ctrl.adsrc_bc1[ 0 ]
     = (struct dsd_bandwidth_client_1 *) malloc( 2 * (sizeof(struct dsd_bandwidth_client_1)
                                                        + 2 * iml2 * sizeof(int)
                                                        + 2 * iml2 * sizeof(HL_LONGLONG)) );
   dss_bc_ctrl.adsrc_bc1[ 0 ]->dsc_time_start = m_get_time();  /* current time */
   dss_bc_ctrl.adsrc_bc1[ 0 ]->imc_no_entries = iml2;  /* number of entries */
   dss_bc_ctrl.adsrc_bc1[ 0 ]->aimc_p_sent  /* number of packets sent  */
     = (int *) (dss_bc_ctrl.adsrc_bc1[ 0 ] + 1);
   dss_bc_ctrl.adsrc_bc1[ 0 ]->aimc_p_recv  /* number of packets received */
     = (int *) (dss_bc_ctrl.adsrc_bc1[ 0 ] + 1) + iml2;
   dss_bc_ctrl.adsrc_bc1[ 0 ]->ailc_d_sent  /* count bytes data sent   */
     = (HL_LONGLONG *) ((char *) dss_bc_ctrl.adsrc_bc1[ 0 ]
                          + sizeof(struct dsd_bandwidth_client_1)
                          + 2 * iml2 * sizeof(int));
   dss_bc_ctrl.adsrc_bc1[ 0 ]->ailc_d_recv  /* count bytes data received */
     = (HL_LONGLONG *) ((char *) dss_bc_ctrl.adsrc_bc1[ 0 ]
                          + sizeof(struct dsd_bandwidth_client_1)
                          + 2 * iml2 * sizeof(int)
                          + iml2 * sizeof(HL_LONGLONG));
   memset( dss_bc_ctrl.adsrc_bc1[ 0 ] + 1,
           0,
           2 * iml2 * sizeof(int)
             + 2 * iml2 * sizeof(HL_LONGLONG) );
   dss_bc_ctrl.adsrc_bc1[ 1 ]
     = (struct dsd_bandwidth_client_1 *) ((char *) dss_bc_ctrl.adsrc_bc1[ 0 ]
                                            + sizeof(struct dsd_bandwidth_client_1)
                                            + 2 * iml2 * sizeof(int)
                                            + 2 * iml2 * sizeof(HL_LONGLONG));
   dss_bc_ctrl.adsrc_bc1[ 1 ]->imc_no_entries = iml2;  /* number of entries */
   dss_bc_ctrl.adsrc_bc1[ 1 ]->aimc_p_sent  /* number of packets sent  */
     = (int *) (dss_bc_ctrl.adsrc_bc1[ 1 ] + 1);
   dss_bc_ctrl.adsrc_bc1[ 1 ]->aimc_p_recv  /* number of packets received */
     = (int *) (dss_bc_ctrl.adsrc_bc1[ 1 ] + 1) + iml2;
   dss_bc_ctrl.adsrc_bc1[ 1 ]->ailc_d_sent  /* count bytes data sent   */
     = (HL_LONGLONG *) ((char *) dss_bc_ctrl.adsrc_bc1[ 1 ]
                          + sizeof(struct dsd_bandwidth_client_1)
                          + 2 * iml2 * sizeof(int));
   dss_bc_ctrl.adsrc_bc1[ 1 ]->ailc_d_recv  /* count bytes data received */
     = (HL_LONGLONG *) ((char *) dss_bc_ctrl.adsrc_bc1[ 1 ]
                          + sizeof(struct dsd_bandwidth_client_1)
                          + 2 * iml2 * sizeof(int)
                          + iml2 * sizeof(HL_LONGLONG));

   pmt_bc_80:                               /* end of bandwidth client */
#endif
#ifdef NOT_YET
   m_gw_udp_update( &dss_loconf_1 );
#endif
#ifdef D_INCL_HOB_TUN
   m_gw_start_htun( dss_loconf_1.adsc_raw_packet_if_conf );
#endif
//#ifdef NOT_YET
   bol1 = m_start_monitor_thread();
   if (bol1 == FALSE) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM181W l%05d start monitor performance parameter failed", __LINE__ );
   }
//#endif
   iml_rc = dsd_tcpcomp::m_startup( NULL );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPM0xxW l%05d m_startprog() dsd_tcpcomp::m_startup() Return Code %d",
                     __LINE__, iml_rc );
   }
   dsd_nblock_acc::mc_startup();
   dss_acccb.am_acceptcallback = &m_acc_acceptcallback;  // accept callback routine
   dss_acccb.am_errorcallback = &m_acc_errorcallback;   // error callback routine
#ifdef B121031
   m_cluster_start( dss_loconf_1.adsc_cluster );
#endif
#ifdef NOT_YET
   m_gw_udp_start();                        /* start UDP and SIP       */
   /* init AVL Tree functions session                                  */
   bol1 = m_htree1_avl_init( NULL, &dss_htree1_avl_cntl_conn,
                             &m_cmp_session_id );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPM0xxW l%05d m_htree1_avl_init() Session-Id failed",
                     __LINE__ );
     return FALSE;                          /* could not start resource */
   }
   m_admin_start();                         /* start ADMIN             */
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T before start listen",
                   __LINE__ );
#endif
#ifdef B121031_X2
#ifdef B121030
#ifdef B120602
   if (dss_loconf_1.boc_listen_gw) {        /* do use listen-gateway   */
     dss_ligw_g.boc_stop_listen_lbal = FALSE;  /* stop listen load-balancing in progress */
     dss_ligw_g.boc_listen_lbal = FALSE;    /* start listen for load-balancing */
     dss_ligw_g.adsc_gate_1_create_socket = dss_loconf_1.adsc_gate_anchor;  /* current gate to start */
     dss_ligw_g.adsc_gate_listen_1_next = NULL;  /* listen part of gateway next to process */
   } else {                                 /* no listen-gateway configured */
     adsl_gate_1_w1 = dss_loconf_1.adsc_gate_anchor;  /* get anchor gate */
     while (adsl_gate_1_w1) {               /* loop over all gates     */
       m_start_listen( adsl_gate_1_w1 );    /* start listen            */
       adsl_gate_1_w1 = adsl_gate_1_w1->adsc_next;
     }
     dsg_sys_state_1.boc_listen_active = TRUE;  /* listen is currently active */
   }
#else
   adsl_gate_1_w1 = dss_loconf_1.adsc_gate_anchor;  /* get anchor gate */
   while (adsl_gate_1_w1) {                 /* loop over all gates     */
     m_start_listen( adsl_gate_1_w1 );      /* start listen            */
     adsl_gate_1_w1 = adsl_gate_1_w1->adsc_next;
   }
   dsg_sys_state_1.boc_listen_active = TRUE;  /* listen is currently active */
#endif
#else
   if (dss_loconf_1.boc_listen_gw) {        /* do use listen-gateway   */
     dss_ligw_g.boc_stop_listen_lbal = FALSE;  /* stop listen load-balancing in progress */
     dss_ligw_g.boc_listen_lbal = FALSE;    /* start listen for load-balancing */
     dss_ligw_g.adsc_gate_1_create_socket = dss_loconf_1.adsc_gate_anchor;  /* current gate to start */
     dss_ligw_g.adsc_gate_listen_1_next = NULL;  /* listen part of gateway next to process */
#ifndef B121031
     bos_start_cluster = TRUE;              /* need to start cluster   */
#endif
   } else {                                 /* no listen-gateway configured */
     adsl_gate_1_w1 = dss_loconf_1.adsc_gate_anchor;  /* get anchor gate */
     while (adsl_gate_1_w1) {               /* loop over all gates     */
       m_start_listen( adsl_gate_1_w1 );    /* start listen            */
       adsl_gate_1_w1 = adsl_gate_1_w1->adsc_next;
     }
     dsg_sys_state_1.boc_listen_active = TRUE;  /* listen is currently active */
#ifndef B121031
     m_cluster_start( dss_loconf_1.adsc_cluster );
     bos_start_cluster = FALSE;             /* cluster has been started */
#endif
   }
#endif
#endif
#ifndef B121031_X2
   adsl_gate_1_w1 = dss_loconf_1.adsc_gate_anchor;  /* get anchor gate */
   while (adsl_gate_1_w1) {                 /* loop over all gates     */
     m_start_listen( adsl_gate_1_w1 );      /* start listen            */
     adsl_gate_1_w1 = adsl_gate_1_w1->adsc_next;
   }
   dsg_sys_state_1.boc_listen_active = TRUE;  /* listen is currently active */
   m_cluster_start( dss_loconf_1.adsc_cluster );
#endif
#ifdef XYZ1
   dsg_sys_state_1.boc_listen_active = TRUE;  /* listen is currently active */
#endif
   /* start SWAP-STOR                                                  */
   dss_swap_stor_ctrl.imc_fd_file = -1;     /* file-descriptor of open swap file */
   m_swap_stor_open();

   m_hlnew_printf( HLOG_INFO1, "HWSPM180I l%05d WebSecureProxy initialization done", __LINE__ );

   /* start timer thread                                               */
#ifdef B060628
   rcu = dss_thread_timer.mc_create( &m_timer_thr, NULL );
   if (rcu < 0) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPM034W l%05d CreateThread Timer Error", __LINE__ );
   }
#endif
   time( &dsl_time_1 );                     /* get current time        */
   dsl_time_last_report = dsl_time_1;       /* set time of last report */
   dsl_time_cma_check = dsl_time_1 + DEF_TIME_CMA_CHECK;  /* time to check CMA entries */
#ifdef NEW_REPORT_1501
   dsl_time_fingerprint = 0;                /* time to print fingerprint in report */
#endif

   p_m_poll_00:                             /* poll for events         */
#ifdef B121031_X2
#ifndef B121031
   if (   (bos_start_cluster)               /* need to start cluster   */
       && (dss_ligw_g.adsc_gate_listen_1_cur == NULL)  /* listen part of gateway currently processed */
       && (dss_ligw_g.adsc_gate_1_create_socket == NULL)) {  /* starting still active */
     m_cluster_start( dss_loconf_1.adsc_cluster );
     bos_start_cluster = FALSE;             /* cluster has been started */
   }
#endif
#endif
   time( &dsl_time_1 );                     /* get current time        */
#ifdef B150126
   if (dsl_time_1 >= dsl_time_cma_check) {  /* time now for CMA check  */
     m_cma1_free_old_e();                   /* remove old entries      */
     dsl_time_cma_check = dsl_time_1 + DEF_TIME_CMA_CHECK;  /* time to check CMA entries */
   }
   iml_endtime = dsl_time_cma_check;        /* set end time CMA check  */
#ifdef NEW_REPORT_1501
   if (dsl_time_fingerprint) {              /* time to print fingerprint in report */
     if (dsl_time_fingerprint <= dsl_time_1) {              /* display statistics now  */
       goto p_disp_stat_00;                 /* display statistics now  */
     }
     if (   (iml_endtime == 0)              /* end time not yet set    */
         || (dsl_time_fingerprint < iml_endtime)) {  /* report is less */
       iml_endtime = dsl_time_fingerprint;  /* set timer report        */
     }
   }
#endif
   if (adsg_loconf_1_inuse->inc_report_intv) {  /* with report         */
     iml1 = dsl_time_last_report + adsg_loconf_1_inuse->inc_report_intv;
     if (iml1 <= dsl_time_1) {              /* display statistics now  */
       goto p_disp_stat_00;                 /* display statistics now  */
     }
     if (   (iml_endtime == 0)              /* end time not yet set    */
         || (iml1 < iml_endtime)) {         /* report is less          */
       iml_endtime = iml1;                  /* set timer report        */
     }
   }
#endif
#ifndef B150126
   if ((dsl_time_1 - dsl_time_cma_check) >= 0) {  /* time now for CMA check */
     m_cma1_free_old_e();                   /* remove old entries      */
     dsl_time_cma_check = dsl_time_1 + DEF_TIME_CMA_CHECK;  /* time to check CMA entries */
   }
   iml_endtime = dsl_time_cma_check;        /* set end time CMA check  */
#ifdef NEW_REPORT_1501
#ifdef XYZ1
   if (dsl_time_fingerprint) {              /* time to print fingerprint in report */
     if ((dsl_time_1 - dsl_time_fingerprint) >= 0) {  /* display statistics now */
       goto p_disp_stat_00;                 /* display statistics now  */
     }
     if (   (iml_endtime == 0)              /* end time not yet set    */
         || ((iml_endtime - dsl_time_fingerprint) > 0)) {  /* report is less */
       iml_endtime = dsl_time_fingerprint;  /* set timer report        */
     }
   }
#endif
   if (   (dsl_time_fingerprint != 0)       /* display statistics now  */
       && ((dsl_time_1 - dsl_time_fingerprint) > 0)) {  /* display statistics now */
     goto p_disp_stat_00;                   /* display statistics now  */
   }
   dsl_time_fingerprint = 0;                /* time to print fingerprint in report */
   if (adsg_loconf_1_inuse->imc_tod_mark_log) {  /* <time-of-day-mark-log> seconds from midnight, +1 */
     m_time_fingerprint( &dsl_time_fingerprint, &dsl_time_1 );
     if (   (iml_endtime == 0)              /* end time not yet set    */
         || ((iml_endtime - dsl_time_fingerprint) > 0)) {  /* report is less */
       iml_endtime = dsl_time_fingerprint;  /* set timer report        */
     }
   }
#endif
   if (adsg_loconf_1_inuse->inc_report_intv) {  /* with report         */
     iml1 = dsl_time_last_report + adsg_loconf_1_inuse->inc_report_intv;
     if ((dsl_time_1 - iml1) >= 0) {        /* display statistics now  */
       goto p_disp_stat_00;                 /* display statistics now  */
     }
     if (   (iml_endtime == 0)              /* end time not yet set    */
         || ((iml_endtime - iml1) > 0)) {   /* report is less          */
       iml_endtime = iml1;                  /* set timer report        */
     }
   }
#endif
   iel_rmp = m_main_poll( ied_fmp_normal, iml_endtime );
   switch (iel_rmp) {                       /* check how returned      */
     case ied_rmp_timeout:                  /* timer elapsed           */
       goto p_m_poll_00;                    /* poll for events         */
     case ied_rmp_sig_end:                  /* message signal end      */
       goto p_disp_stat_00;                 /* display statistics now  */
     case ied_rmp_sig_reload:               /* message signal reload configuration */
       goto p_reload_00;                    /* received reload configuration */
     case ied_rmp_sig_check_shu:            /* message signal check shutdown */
       goto p_shutdown_00;                  /* check shutdown of this process */
     default:
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW nbipgw20 l%05d returned from m_main_poll() iel_rmp = %d invalid",
                       __LINE__, iel_rmp );
       break;
   }
   goto p_m_poll_00;                        /* poll for events         */

   p_disp_stat_00:                          /* display statistics now  */
#ifndef NEW_REPORT_1501
   dsl_time_last_report = dsl_time_1;       /* set time of last report */
   strftime( chrl_work1, sizeof(chrl_work1),
             "%a %B %d %Y %H:%M:%S %Z",
             localtime( &dsl_time_1 ) );
   chrl_work2[0] = 0;                       /* no text queue           */
   if (dsg_hco_main.imc_workque_max_no) {   /* work queue maximum      */
     memcpy( chrl_work2, " at time: ", 10 );
     strftime( chrl_work2 + 10, sizeof(chrl_work2) - 10,
               "%a %B %d %Y %H:%M:%S %Z",
               localtime( &dsg_hco_main.dsc_workque_max_time ) );
   }
   m_hlnew_printf( HLOG_XYZ1, "HWSPR001I Report %s / number of Work Threads %d - scheduled %d - busy %d - current queue %d - longest queue %d%s",
                   chrl_work1,
                   dsg_hco_main.imc_workthr_alloc, dsg_hco_main.imc_workthr_sched,
                   dsg_hco_main.imc_workthr_active,
                   dsg_hco_main.imc_workque_sched,
                   dsg_hco_main.imc_workque_max_no, chrl_work2 );
#ifdef TRACEHLD
   {
     int ih1 = 0;                           /* count threads           */
     audclworkth1 = adss_workth_1_anchor;   /* get anchor of chain     */
     while (audclworkth1) {                 /* loop over all threads   */
       m_hlnew_printf( HLOG_XYZ1, "+++ check thread thrid=%d no=%d / %08X clconn1=%p act=%p time=%08X",
                         audclworkth1->getthrid(),
                         ih1 + 1, audclworkth1,
                         audclworkth1->ad_clconn1,
                         audclworkth1->trace_act, audclworkth1->trace_time );
       ih1++;
       audclworkth1 = audclworkth1->getnext();  /* get next in chain   */
     }
   }
#endif
#ifdef TRACEHLX
   cl_tcp_r::report_thread_mrecv();         /* display receive thr     */
#endif
   m_get_perf_data( &dss_perf_data );
   m_edit_sci_two( chrl_work1, dss_perf_data.ulc_memory );
   m_edit_sci_dec( chrl_work2, dss_perf_data.ulc_io_total_ops );
   m_edit_sci_two( chrl_work3, dss_perf_data.ulc_io_total_bytes );
   m_hlnew_printf( HLOG_INFO1, "HWSPR002I Report Performance / elapsed CPU time %d sec / virt-stor %sB / I-O %s %sB.",
                   (int) ((dss_perf_data.ulc_cpu_total_time + 500) / 1000), chrl_work1, chrl_work2, chrl_work3 );
   if (bos_disk_file) {                     /* did access disk file    */
     iml1 = iml2 = ill1 = 0;                /* reset counters          */
     adsl_df1_1 = adss_df1_anchor;          /* get anchor of files     */
     while (adsl_df1_1) {                   /* loop over all files in cache */
       iml1++;                              /* count the files         */
       if (adsl_df1_1->dsc_int_df1.achc_filecont_start) {  /* file in memory */
         iml2++;                            /* count the files         */
         /* add size of this file  */
         ill1 += adsl_df1_1->dsc_int_df1.achc_filecont_end
                   - adsl_df1_1->dsc_int_df1.achc_filecont_start;
       }
       adsl_df1_1 = adsl_df1_1->adsc_next;  /* get next in chain       */
     }
     m_edit_sci_two( chrl_work1, ill1 );
     m_hlnew_printf( HLOG_INFO1, "HWSPR005I Report cached disk files number %d / %d with data - size in memory: %sB.",
                     iml1, iml2, chrl_work1 );
   }
   m_cma1_statistics( &iml1, &ill1 );       /* get statistics          */
   if (iml1) {                              /* entries in CMA          */
     m_edit_sci_two( chrl_work1, ill1 );
     m_hlnew_printf( HLOG_INFO1, "HWSPR006I Report CMA common memory area %d entries - size in memory: %sB.",
                     iml1, chrl_work1 );
   }
   m_cluster_report( &dsl_cluster_report );  /* cluster report structure */
   if (dsl_cluster_report.boc_cluster_active) {  /* cluster is active  */
     achl1 = "active";
     if (dsg_sys_state_1.boc_listen_active == FALSE) {
       achl1 = "closed";
     }
     m_hlnew_printf( HLOG_INFO1, "HWSPR008I Report Cluster active connections %d - this group %d - listen %s.",
                     dsl_cluster_report.imc_no_cluster_active,  /* number of active cluster connections */
                     dsl_cluster_report.imc_no_same_group,  /* number of active cluster connections same group */
                     achl1 );
   }
   if (dss_ets_pttd.imc_no_started > 0) {   /* pass-thru-to-desktop - number of instances started */
     ill1 = dss_ets_pttd.ilc_sum_time_ms;   /* summary time executed in milliseconds */
     if (dss_ets_pttd.adsc_ete_ch) {        /* chain extra thread entries */
       adsl_ete_w1 = dss_ets_pttd.adsc_ete_ch;  /* chain extra thread entries */
       ill2 = m_get_epoch_ms();             /* get current time        */
       while (adsl_ete_w1) {                /* loop over chain extra thread entries */
         ill1 += ill2 - adsl_ete_w1->ilc_time_started_ms;  /* time / epoch started in milliseconds */
         adsl_ete_w1 = adsl_ete_w1->adsc_next;  /* get next in chain   */
       }
     }
     achl1 = m_edit_dec_long( chrl_ns_num, ill1 );
     m_hlnew_printf( HLOG_INFO1, "HWSPR010I Report extra threads - desktop-on-demand - currently-running=%d started=%d start-denied=%d time-running-milliseconds=%s.",
                     dss_ets_pttd.imc_no_current,  /* number of instances currently executing */
                     dss_ets_pttd.imc_no_started,  /* number of instances started */
                     dss_ets_pttd.imc_no_denied,   /* number of start requests denied */
                     achl1 );
   }
   if (dss_ets_ut.imc_no_started > 0) {     /* utility threads - number of instances started */
     ill1 = dss_ets_ut.ilc_sum_time_ms;     /* summary time executed in milliseconds */
     if (dss_ets_ut.adsc_ete_ch) {          /* chain extra thread entries */
       adsl_ete_w1 = dss_ets_ut.adsc_ete_ch;  /* chain extra thread entries */
       ill2 = m_get_epoch_ms();             /* get current time        */
       while (adsl_ete_w1) {                /* loop over chain extra thread entries */
         ill1 += ill2 - adsl_ete_w1->ilc_time_started_ms;  /* time / epoch started in milliseconds */
         adsl_ete_w1 = adsl_ete_w1->adsc_next;  /* get next in chain   */
       }
     }
     achl1 = m_edit_dec_long( chrl_ns_num, ill1 );
     m_hlnew_printf( HLOG_INFO1, "HWSPR011I Report extra threads - utility threads   - currently-running=%d started=%d start-denied=%d time-running-milliseconds=%s.",
                     dss_ets_ut.imc_no_current,  /* number of instances currently executing */
                     dss_ets_ut.imc_no_started,  /* number of instances started */
                     dss_ets_ut.imc_no_denied,   /* number of start requests denied */
                     achl1 );
   }
   adsl_gate_1_w1 = adsg_loconf_1_inuse->adsc_gate_anchor;  /* get anchor gate */
   while (adsl_gate_1_w1) {
     chrl_work1[0] = 0;                     /* make zero string        */
     if (adsl_gate_1_w1->i_session_max) {
       sprintf( chrl_work1, " max-session-conf=%d max-session-exceeded=%d",
                adsl_gate_1_w1->i_session_max, adsl_gate_1_w1->i_session_exc );
     }
     m_hlnew_printf( HLOG_INFO1, "HWSPR004I GATE=%(ux)s report - current sessions=%d start session requests=%d number of session maximum reached=%d%s.",
                     adsl_gate_1_w1 + 1,
                     adsl_gate_1_w1->i_session_cur, adsl_gate_1_w1->i_session_cos, adsl_gate_1_w1->i_session_mre,
                     chrl_work1 );
     adsl_gate_1_w1 = adsl_gate_1_w1->adsc_next;  /* get next in chain */
   }
   /* background-task statistics                                       */
   adsl_bgt_contr_1 = adsg_loconf_1_inuse->adsc_bgt_contr_1;  /* chain background-task control */
   while (adsl_bgt_contr_1) {               /* loop over background-tasks */
     adsl_bgt_function_1 = adsl_bgt_contr_1->adsc_bgt_function_1;  /* chain background-task functions */
     do {                                   /* loop over background-task functions */
       if (adsl_bgt_function_1->iec_bgtf == ied_bgtf_stat) {  /* called for statistic */
         memset( &dsl_aux_cf1, 0, sizeof(struct dsd_aux_cf1) );  /* auxiliary control structure */
#ifdef B130314
         dsl_aux_cf1.iec_src_func = ied_src_fu_bgt_stat;  /* background-task for statistic */
#endif
         dsl_aux_cf1.dsc_cid.iec_src_func = ied_src_fu_bgt_stat;  /* background-task for statistic */
         memset( &dsl_bgt_call_1, 0, sizeof(struct dsd_bgt_call_1) );  /* Background-Task Call */
         dsl_bgt_call_1.imc_func = DEF_IFUNC_CONT;  /* process data as specified */
         dsl_bgt_call_1.ac_conf = adsl_bgt_contr_1->ac_conf;  /* data from configuration */
         dsl_bgt_call_1.vpc_userfld = &dsl_aux_cf1;  /* auxiliary control structure */
         dsl_bgt_call_1.amc_aux = &m_cdaux;  /* subroutine             */
         dsl_bgt_call_1.adsc_bgt_function_1 = adsl_bgt_function_1;  /* called for background-task function */
         adsl_bgt_contr_1->adsc_ext_lib1->amc_bgt_entry( &dsl_bgt_call_1 );
       }
       adsl_bgt_function_1 = adsl_bgt_function_1->adsc_next;  /* get next in chain */
     } while (adsl_bgt_function_1);
     adsl_bgt_contr_1 = adsl_bgt_contr_1->adsc_next;  /* get next in chain */
   }
#ifdef TRACEHL_P_COUNT
   {
     adsl_df1_1 = adss_df1_anchor;          /* get anchor of files     */
     while (adsl_df1_1) {                   /* loop over all files in cache */
       m_hlnew_printf( HLOG_XYZ1, "disk-file adsl_df1_1=%p inc_usage_count=%d boc_superseeded=%d"
                   " iec_difi_def=%d ipc_time_last_acc=%d/%08X ipc_time_last_checked=%d/%08X"
                   " achc_filecont_start=%p name=%S",
                   adsl_df1_1,
                   adsl_df1_1->inc_usage_count,
                   adsl_df1_1->boc_superseeded,
                   adsl_df1_1->iec_difi_def,
                   adsl_df1_1->ipc_time_last_acc,
                   adsl_df1_1->ipc_time_last_acc,
                   adsl_df1_1->ipc_time_last_checked,
                   adsl_df1_1->ipc_time_last_checked,
                   adsl_df1_1->dsc_int_df1.achc_filecont_start,
                   adsl_df1_1->dsc_int_df1.awcc_name );
       adsl_df1_1 = adsl_df1_1->adsc_next;    /* get next in chain       */
     }
   }
#endif
//ifdef TRACEHL_P_DISP
#ifdef TRACEHL_P_COUNT
   m_hlnew_printf( HLOG_XYZ1, "ins_count_buf_in_use=%d ins_count_buf_max=%d ins_count_memory=%d.",
                   ins_count_buf_in_use, ins_count_buf_max, ins_count_memory );
#endif
#ifdef TRACEHL_P_050118
   m_hlnew_printf( HLOG_XYZ1, "ims_p_050118 = %d\n", ims_p_050118 );
#endif
#ifdef TRACEHL_WA_COUNT                     /* 17.09.09 KB count work area inc / dec */
   m_hlnew_printf( HLOG_XYZ1, "l%05d work area inc=%d dec=%d diff=%d.",
                   __LINE__, ims_count_wa_inc, ims_count_wa_dec, ims_count_wa_inc - ims_count_wa_dec );
#endif
#ifdef TRACEHL_TCP_BLOCK                    /* 18.07.07 KB count TCP blocking */
   m_hlnew_printf( HLOG_XYZ1, "Report l%05d ims_trace_block_send=%d ims_trace_block_may=%d ims_trace_block_retry=%d.",
                   __LINE__,
                   ims_trace_block_send, ims_trace_block_may, ims_trace_block_retry );
#endif /* TRACEHL_TCP_BLOCK                    18.07.07 KB count TCP blocking */
#ifdef TRACEHL_STOR_USAGE
   {
     int imh1, imh2;
     struct dsd_tr_stor_usage_01 *adsl_tr_stor_usage_01_h1;
     EnterCriticalSection( &dsalloc_dcritsect );
     adsl_tr_stor_usage_01_h1 = adss_tr_stor_usage_01_anchor;
     while (adsl_tr_stor_usage_01_h1) {
#define ADSL_SDHC1_G ((struct dsd_sdh_control_1 *) (adsl_tr_stor_usage_01_h1 + 1))
       m_hlnew_printf( HLOG_XYZ1, "HWSP-TRACE-STOR-USAGE-l%05d stor=%p stack=%p chrc_pos=%s adsc_next=%p adsc_gather_i_1_i=%p inc_function=%p inc_position=%p boc_ready_t_p=%p imc_usage_count=%p.",
                       __LINE__, adsl_tr_stor_usage_01_h1, adsl_tr_stor_usage_01_h1->ac_stack, adsl_tr_stor_usage_01_h1->chrc_pos,
                       ADSL_SDHC1_G->adsc_next,  /* field for chaining */
                       ADSL_SDHC1_G->adsc_gather_i_1_i,  /* gather input data */
                       ADSL_SDHC1_G->inc_function,  /* function of SDH */
                       ADSL_SDHC1_G->inc_position,  /* position of SDH */
                       ADSL_SDHC1_G->boc_ready_t_p,  /* ready to process */
                       ADSL_SDHC1_G->imc_usage_count );  /* usage count */
#undef ADSL_SDHC1_G
       imh1 = adsl_tr_stor_usage_01_h1->imc_ind_trac;
       imh2 = 0;
       do {
         imh2++;
         m_hlnew_printf( HLOG_XYZ1, "HWSP-TRACE-STOR-USAGE-l%05d stor=%p no=%d trac=%s.",
                         __LINE__, adsl_tr_stor_usage_01_h1, imh2,
                         &adsl_tr_stor_usage_01_h1->chrc_trac[ imh1 * (sizeof(adsl_tr_stor_usage_01_h1->chrc_trac) / D_NO_TSU_NO) ] );
         imh1++;
         if (imh1 == D_NO_TSU_NO) imh1 = 0;
       } while (imh1 != adsl_tr_stor_usage_01_h1->imc_ind_trac);
       adsl_tr_stor_usage_01_h1 = adsl_tr_stor_usage_01_h1->adsc_next;
     }
     LeaveCriticalSection( &dsalloc_dcritsect );
   }
#endif
#ifdef TRACE_HL_SESS_01
   {
     BOOL     boh_first = TRUE;
     int      imh1, imh2, imh3, imh4, imh5;
     int      imh_gather;                   /* count gather            */
     int      imh_data;                     /* count data              */
     char     *achh2;
     char     *achh_avl_error = NULL;       /* clear error code AVL tree */
     struct dsd_sdh_control_1 *adsh_sdhc1_cur_1;  /* current location 1 */
     struct dsd_gather_i_1 *adsh_gai1_w1;   /* working variable        */
     struct dsd_htree1_avl_work dsh_htree1_work;  /* work-area for AVL-Tree */
     char     chrl_ns_1[320];               /* for network-statistic   */
     char     chrl_ns_num[16];              /* for number              */
     EnterCriticalSection( &d_clconn_critsect );
     while (TRUE) {                         /* loop for sequential retrieval */
       bol1 = m_htree1_avl_getnext( NULL, &dss_htree1_avl_cntl_conn,
                                    &dsh_htree1_work, boh_first );
       if (bol1 == FALSE) {                 /* error occured           */
         achh_avl_error = "m_htree1_avl_getnext() failed";  /* error code AVL tree */
         break;                             /* do not continue         */
       }
       if (dsh_htree1_work.adsc_found == NULL) break;  /* reached end of tree */
#define ADSL_CONN1_G ((class clconn1 *) (dsh_htree1_work.adsc_found))
       boh_first = FALSE;
       m_hlnew_printf( HLOG_XYZ1, "HWSP-TRACE-l%05d GATE=%(ux)s SNO=%08d INETA=%s adsc_server_conf_1=%p.",
                       __LINE__,
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       ADSL_CONN1_G->adsc_server_conf_1 );
       chrl_ns_1[0] = 0;                    /* for network-statistic   */
       imh2 = m_get_time() - ADSL_CONN1_G->imc_time_start;
       imh3 = imh2 / 3600;
       imh5 = imh2 - imh3 * 3600;
       imh4 = imh5 / 60;
       imh5 -= imh4 * 60;
       imh1 = sprintf( chrl_ns_1, "duration: %d h %d min %d sec", imh3, imh4, imh5 );
       achh2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_rece_c );
       imh1 += sprintf( chrl_ns_1 + imh1, " / client: rec %s", achh2 );
       achh2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_rece_c );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %s bytes", achh2 );
       achh2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_send_c );
       imh1 += sprintf( chrl_ns_1 + imh1, " + send %s", achh2 );
       achh2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_send_c );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %s bytes", achh2 );
       achh2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_rece_s );
       imh1 += sprintf( chrl_ns_1 + imh1, " / server: rec %s", achh2 );
       achh2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_rece_s );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %s bytes", achh2 );
       achh2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_send_s );
       imh1 += sprintf( chrl_ns_1 + imh1, " + send %s", achh2 );
       achh2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_send_s );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %s bytes", achh2 );
       achh2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_rece_e );
       imh1 += sprintf( chrl_ns_1 + imh1, " / encrypted: rec %s", achh2 );
       achh2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_rece_e );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %s bytes", achh2 );
       achh2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_send_e );
       imh1 += sprintf( chrl_ns_1 + imh1, " + send %s", achh2 );
       achh2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_send_e );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %s bytes", achh2 );
       m_hlnew_printf( HLOG_XYZ1, "HWSP-TRACE-l%05d %s.",
                       __LINE__, chrl_ns_1 );
       imh1 = 0;
       adsh_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain */
       while (adsh_sdhc1_cur_1) {           /* loop over all buffers   */
         adsh_gai1_w1 = adsh_sdhc1_cur_1->adsc_gather_i_1_i;  /* get chain to send */
         imh_gather = 0;                    /* clear count gather      */
         imh_data = 0;                      /* clear count data        */
         while (adsh_gai1_w1) {             /* loop over data to send  */
           imh_gather++;                    /* increment count gather  */
           imh2 = adsh_gai1_w1->achc_ginp_end - adsh_gai1_w1->achc_ginp_cur;
           imh_data += imh2;
           adsh_gai1_w1 = adsh_gai1_w1->adsc_next;  /* get next in chain */
         }
         m_hlnew_printf( HLOG_XYZ1, "HWSP-TRACE-l%05d adsh_sdhc1_cur_1=%p function=%d position=%d imc_usage_count=%d gather=%d data=%d",
                         __LINE__, adsh_sdhc1_cur_1,
                         adsh_sdhc1_cur_1->inc_function, adsh_sdhc1_cur_1->inc_position, adsh_sdhc1_cur_1->imc_usage_count,
                         imh_gather, imh_data );
         imh1++;
         adsh_sdhc1_cur_1 = adsh_sdhc1_cur_1->adsc_next;  /* get next in chain */
       }
       m_hlnew_printf( HLOG_XYZ1, "HWSP-TRACE-l%05d i_last_action=%05d i_prev_action=%05d adsc_sdhc1_chain=%p no-e=%d dcl_tcp_r_c.adsc_sdhc1_send=%p dcl_tcp_r_s.adsc_sdhc1_send=%p.",
                       __LINE__,
                       ADSL_CONN1_G->i_last_action, ADSL_CONN1_G->i_prev_action,
                       ADSL_CONN1_G->adsc_sdhc1_chain, imh1,
                       ADSL_CONN1_G->dcl_tcp_r_c.adsc_sdhc1_send,
                       ADSL_CONN1_G->dcl_tcp_r_s.adsc_sdhc1_send );
       imh1 = 0;
       do {
         m_hlnew_printf( HLOG_XYZ1, "HWSP-TRACE-l%05d ir_last_action[ %d ... ] = %05d %05d %05d %05d %05d %05d %05d %05d.",
                         __LINE__, imh1,
                         ADSL_CONN1_G->ir_last_action[ imh1 + 0 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 1 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 2 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 3 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 4 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 5 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 6 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 7 ] );
         imh1 += 8;
       } while (imh1 < DEF_LEN_LAST_ACTION);
#undef ADSL_CONN1_G
     }
     LeaveCriticalSection( &d_clconn_critsect );
     if (achh_avl_error) {                    /* error occured           */
       m_hlnew_printf( HLOG_XYZ1, "HWSP-TRACE-l%05d AVL error %s.",
                       __LINE__, achh_avl_error );
     }
   }
#endif  /* TRACE_HL_SESS_01 */
#endif
#ifdef NEW_REPORT_1501
#include "xiipgw08-report.cpp"
#endif
   if (bos_end_proc == FALSE) goto p_m_poll_00;  /* poll for events    */

   p_end_00:                                /* end of program          */
#ifdef DEBUG_121116_01                      /* debug listen-gateway    */
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T main() p_end_00",
                   __LINE__ );
#endif
   if (bos_pid_file) {                      /* PID file active         */
//   bos_pid_file = FALSE;                  /* PID file no more active */
     iml_rc = unlink( dss_loconf_1.achc_pid_file );  /* delete PID file */
     if (iml_rc < 0) {                      /* error occured           */
       m_hlnew_printf( HLOG_XYZ1, "HWSPMnnnW unlink pid-file returned %d / errno %d.",
                       iml_rc, errno );
     }
   }
   if (dss_ligw_g.boc_connected) {          /* connected to Listen Gateway */
     m_ligw_close();                        /* close connection to listen-gateway */
   }
   iml1 = m_stop_all_listen( FALSE );
   if (dss_swap_stor_ctrl.imc_fd_file >= 0) {  /* file-descriptor of open swap file */
     close( dss_swap_stor_ctrl.imc_fd_file );  /* file-descriptor of open swap file */
   }
   if (dss_wsp_trace_thr_ctrl.boc_tread_running) {  /* WSP trace thread is running */
#ifdef XYZ1
#define ADSL_WSPADM1_QWT1 ((struct dsd_wspadm1_q_wsp_trace_1 *) chrl_work1)
     memset( adsh_wspadm1_qwt1, 0, sizeof(struct dsd_wspadm1_q_wsp_trace_1) );
     ADSL_WSPADM1_QWT1->iec_wawt = ied_wawt_target;  /* define new target */
     ADSL_WSPADM1_QWT1->iec_wtt = ied_wtt_console;  /* print on console */
     m_ctrl_wspadm1_wsp_trace( ADSL_WSPADM1_QWT1, 0 );
#undef ADSL_WSPADM1_QWT1
#endif
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_control;  /* control record      */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     adsl_wt1_w1->imc_wsp_trace_target = (int) ied_wtt_console;  /* print on console */
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
     sleep( 2 );
   }
   m_hlnew_printf( HLOG_INFO1, "HWSPM069I normal end of program" );
   return 0;

   p_reload_00:                             /* received reload configuration */
   dsg_sys_state_1.boc_listen_ended = TRUE;  /* listen has already ended */
   m_hlnew_printf( HLOG_INFO1, "HWSPMnnnI nbipgw20 l%05d received signal reload configuration - start graceful shutdown",
                   __LINE__ );
#ifdef XYZ1
   bos_shutdown = TRUE;                     /* is in graceful shutdown */
#endif
   if (bos_pid_file) {                      /* PID file active         */
     bos_pid_file = FALSE;                  /* PID file no more active */
     iml_rc = unlink( dss_loconf_1.achc_pid_file );  /* delete PID file */
     if (iml_rc < 0) {                      /* error occured           */
       m_hlnew_printf( HLOG_XYZ1, "HWSPMnnnW unlink pid-file returned %d / errno %d.",
                       iml_rc, errno );
     }
   }
   iml1 = m_stop_all_listen( FALSE );
#ifndef B121119
   sleep( 5 );
#endif

   p_shutdown_00:                           /* check shutdown of this process */
   if (ims_count_cma_sync != 0) {           /* count currently active CMA synchronize */
     goto p_m_poll_00;                      /* poll for events         */
   }
   achl_avl_error = NULL;                   /* reset error text        */
   dss_main_critsect.m_enter();             /* enter CriticalSection   */
   do {
     bol1 = m_htree1_avl_getnext( NULL, &dss_htree1_avl_cntl_conn,
                                 &dsl_htree1_work, TRUE );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "m_htree1_avl_search() failed";  /* error code AVL tree */
       break;                               /* do not continue         */
     }
     if (dsl_htree1_work.adsc_found == NULL) {  /* no element in tree */
       bos_end_proc = TRUE;                 /* signal end of processing */
       m_hlnew_printf( HLOG_INFO1, "HWSPMnnnI all connections ended - end program" );
     }
   } while (FALSE);
   dss_main_critsect.m_leave();             /* leave CriticalSection   */
   if (achl_avl_error) {                    /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW nbipgw20 l%05d m_htree1_avl_getnext() returned error",
                     __LINE__ );
   }
#ifndef B140624
   if (bos_end_proc) {
     goto p_end_00;                         /* end of program          */
   }
#endif
   goto p_m_poll_00;                        /* poll for events         */
} /* end main()                                                        */

/** subroutine to do poll for main                                     */
static enum ied_ret_main_poll m_main_poll( enum ied_func_main_poll iep_fmp, int imp_endtime ) {
   int        iml_rc;                       /* return code             */
   int        iml_endtime_w1;               /* end time                */
   int        iml_endtime_w2;               /* end time                */
   int        iml_timeout;                  /* timeout for poll()      */
   time_t     dsl_time_1;                   /* for time                */
#ifdef D_INCL_HOB_TUN
   char       *achl1;                       /* working variable        */
   struct dsd_ser_thr_task *adsl_sth_w1;    /* working variable        */
   struct msghdr dsl_msghdr;                /* message structure       */
#ifdef MSGHDR_CONTROL_AVAILABLE
   union {
     struct cmsghdr dsc_msg;
     char chrc_control[ CMSG_SPACE(sizeof(int)) ];
   } dsl_control_un;
   struct cmsghdr *adsl_cmd;
#endif
   char       chrl_send_buf[ 512 ];         /* send buffer             */
#endif
   void *     vprl_message[ DEF_MSG_PIPE_LEN ];  /* message in pipe    */

   p_sub_poll_00:                           /* do poll now             */
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_main_poll() dss_loconf_1.boc_listen_gw=%d dss_ligw_g.adsc_gate_1_create_socket=%p dss_ligw_g.adsc_gate_listen_1_cur=%p dss_ligw_g.adsc_gate_listen_1_next=%p.",
                   __LINE__, dss_loconf_1.boc_listen_gw, dss_ligw_g.adsc_gate_1_create_socket, dss_ligw_g.adsc_gate_listen_1_cur, dss_ligw_g.adsc_gate_listen_1_next );
#endif
   if (   (   (iep_fmp == ied_fmp_opli_ligw_wait)  /* open listen listen gateway wait */
           || (iep_fmp == ied_fmp_opli_ligw_ret))  /* open listen listen gateway return */
       && (dss_ligw_g.boc_listen_start == FALSE)) {  /* start listen at program start */
     if (dss_ligw_g.boc_rc_last_listen) {   /* socket and bind succeeded */
       return ied_rmp_ligw_success;         /* listen gateway socket passed */
     }
     return ied_rmp_ligw_failed;            /* socket and bind failed  */
   }
#ifdef D_INCL_HOB_TUN
   if (dss_ligw_g.imc_open_tun_sent == 2) {  /* command open TUN sent   */
     dss_ligw_g.imc_open_tun_sent = 0;      /* command open TUN sent   */
     return ied_rmp_ligw_success;           /* listen gateway socket passed */
   }
#endif
   iml_endtime_w1 = imp_endtime;            /* get end time            */
   time( &dsl_time_1 );                     /* get current time        */
   if (   (dss_loconf_1.boc_listen_gw)      /* do use listen gateway   */
       && (dss_ligw_g.boc_connected == FALSE)) {  /* not connected to Listen Gateway */
     if (iep_fmp == ied_fmp_opli_ligw_ret) {  /* open listen listen gateway return */
       return ied_rmp_ligw_closed;          /* listen gateway is closed */
     }
     iml_endtime_w2                         /* end time reconnect listen-gateway */
       = dss_ligw_g.imc_time_disconnect + DEF_TIME_LIGW_RECO;  /* seconds between listen-gateway reconnect */
     if (iml_endtime_w2 <= dsl_time_1) {    /* try reconnect now       */
       m_ligw_open();                       /* open the listen gateway */
       if (dss_ligw_g.boc_connected == FALSE) {  /* not connected to Listen Gateway */
         m_hlnew_printf( HLOG_XYZ1, "HWSPMnnnW Listen-Gateway \"%(u8)s\" could not be connected to - waiting for Listen-Gateway to be started",
                         dss_ligw_g.dsc_soa_un.sun_path );
         goto p_sub_poll_00;                /* do poll now             */
       }
       dss_main_poll_sub.dsrc_poll[ 1 ].fd = dss_ligw_g.imc_sockfd;  /* socket for connection */
       dss_main_poll_sub.dsrc_poll[ 1 ].events = POLLIN;
       dss_main_poll_sub.imc_poll_ele = 2;  /* elements for poll()     */
     } else {
       if (   (iml_endtime_w1 == 0)
           || (iml_endtime_w1 > iml_endtime_w2)) {
         iml_endtime_w1 = iml_endtime_w2;   /* set new end time        */
       }
     }
   }
   if (   (dss_ligw_g.boc_connected)        /* connected to Listen Gateway */
       && (   (dss_ligw_g.adsc_gate_1_create_socket)  /* current gate to start */
           || (dss_ligw_g.boc_listen_start))  /* start listen at program start */
       && (dss_ligw_g.adsc_gate_listen_1_cur == NULL)) {  /* listen part of gateway currently processed */
// to-do 29.12.12 KB - multiple commands give problems? check dss_ligw_g.boc_ser_sent
     m_ligw_create_socket();                /* send command create socket */
     if (dss_ligw_g.boc_connected == FALSE) {  /* not connected to Listen Gateway */
       goto p_sub_poll_00;                  /* do poll now             */
     }
   }
#ifdef D_INCL_HOB_TUN
   if (   (dss_ligw_g.boc_connected)        /* connected to Listen Gateway */
       && (iep_fmp == ied_fmp_open_tun)     /* open TUN adapter        */
       && (dss_ligw_g.imc_open_tun_sent == 0)) {  /* command open TUN sent */
#define ADSL_LIGW_Q_OPEN_TUN_G ((struct dsd_ligw_q_open_tun *) (chrl_send_buf + 1))
#ifdef B130109
     ADSL_LIGW_Q_OPEN_TUN_G->ucc_use_ipv4 = 1;  /* use IPV4            */
     ADSL_LIGW_Q_OPEN_TUN_G->ucc_use_ipv6 = 0;  /* use IPV6            */
     ADSL_LIGW_Q_OPEN_TUN_G->ucc_no_ineta_ipv4 = 1;  /* number of INETAs IPV4 */
     ADSL_LIGW_Q_OPEN_TUN_G->ucc_no_ineta_ipv6 = 0;  /* number of INETAs IPV6 */
     memcpy( ADSL_LIGW_Q_OPEN_TUN_G + 1, &dss_loconf_1.adsc_raw_packet_if_conf->umc_ta_ineta_local, sizeof(UNSIG_MED) );   /* <TUN-adapter-ineta> */
#endif
     memset( ADSL_LIGW_Q_OPEN_TUN_G, 0, sizeof(struct dsd_ligw_q_open_tun) );
//   ADSL_LIGW_Q_OPEN_TUN_G->ucc_use_ipv4 = 0;  /* use IPV4            */
//   ADSL_LIGW_Q_OPEN_TUN_G->ucc_use_ipv6 = 0;  /* use IPV6            */
     ADSL_LIGW_Q_OPEN_TUN_G->ucc_no_ineta_ipv4 = (unsigned char) dss_loconf_1.adsc_raw_packet_if_conf->imc_no_ta_ineta_ipv4;  /* number of INETAs IPV4 */
     ADSL_LIGW_Q_OPEN_TUN_G->ucc_no_ineta_ipv6 = (unsigned char) dss_loconf_1.adsc_raw_packet_if_conf->imc_no_ta_ineta_ipv6;  /* number of INETAs IPV6 */
     achl1 = (char *) (ADSL_LIGW_Q_OPEN_TUN_G + 1);
     if (dss_loconf_1.adsc_raw_packet_if_conf->imc_no_ta_ineta_ipv4 > 0) {  /* number of INETAs IPV4 */
       memcpy( achl1,
               dss_loconf_1.adsc_raw_packet_if_conf->achc_ar_ta_ineta_ipv4,
               dss_loconf_1.adsc_raw_packet_if_conf->imc_no_ta_ineta_ipv4 * 4 );  /* number of INETAs IPV4 */
       achl1 += dss_loconf_1.adsc_raw_packet_if_conf->imc_no_ta_ineta_ipv4 * 4;  /* number of INETAs IPV4 */
       ADSL_LIGW_Q_OPEN_TUN_G->ucc_use_ipv4 = 1;  /* use IPV4          */
     }
     if (dss_loconf_1.adsc_raw_packet_if_conf->imc_no_ta_ineta_ipv6 > 0) {  /* number of INETAs IPV6 */
       memcpy( achl1,
               dss_loconf_1.adsc_raw_packet_if_conf->achc_ar_ta_ineta_ipv6,
               dss_loconf_1.adsc_raw_packet_if_conf->imc_no_ta_ineta_ipv6 * 16 );  /* number of INETAs IPV6 */
       achl1 += dss_loconf_1.adsc_raw_packet_if_conf->imc_no_ta_ineta_ipv6 * 16;  /* number of INETAs IPV6 */
       ADSL_LIGW_Q_OPEN_TUN_G->ucc_use_ipv6 = 1;  /* use IPV6          */
     }
     chrl_send_buf[ 0 ] = (unsigned char) ied_ligwq_open_tun;  /* open TUN adapter */
     memset( &dsl_msghdr, 0, sizeof(struct msghdr) );

#ifdef MSGHDR_CONTROL_AVAILABLE
     dsl_msghdr.msg_control = dsl_control_un.chrc_control;
     dsl_msghdr.msg_controllen = sizeof(dsl_control_un.chrc_control);

     adsl_cmd = CMSG_FIRSTHDR( &dsl_msghdr );
     adsl_cmd->cmsg_len = CMSG_LEN( sizeof(int) );
     adsl_cmd->cmsg_level = SOL_SOCKET;
     adsl_cmd->cmsg_type = SCM_RIGHTS;
     *((int *) CMSG_DATA( adsl_cmd )) = dsg_tun_ctrl.imc_fd_tun;
#else
     dsl_msghdr.msg_accrights = (caddr_t) &dsg_tun_ctrl.imc_fd_tun;
     dsl_msghdr.msg_accrightslen = sizeof(int);
#endif

#ifdef B130109
     m_ligw_send( chrl_send_buf, 1 + sizeof(struct dsd_ligw_q_open_tun) + sizeof(UNSIG_MED), &dsl_msghdr );
#endif
     m_ligw_send( chrl_send_buf, achl1 - chrl_send_buf, &dsl_msghdr );

#undef ADSL_LIGW_Q_OPEN_TUN_G

     if (dss_ligw_g.boc_connected == FALSE) {  /* not connected to Listen Gateway */
       goto p_sub_poll_00;                  /* do poll now             */
     }
     dss_ligw_g.imc_open_tun_sent = 1;      /* command open TUN sent   */
   }
   while (   (dss_ligw_g.boc_connected)     /* connected to Listen Gateway */
          && (dss_ser_thr_ctrl.adsc_sth_work)  /* work as task for serial thread */
          && (dss_ligw_g.boc_ser_sent == FALSE)) {  /* serialize command sent */
// to-do 29.12.12 KB - multiple commands give problems? check dss_ligw_g.adsc_gate_listen_1_cur
     if (dss_ser_thr_ctrl.adsc_sth_work->iec_sth  /* serial thread task type */
             == ied_sth_route_ipv4_add) {   /* add a route IPV4        */
#define ADSL_QUERY_AR_ADD_IPV4_G ((struct dsd_ligw_q_ar_add_ipv4 *) (chrl_send_buf + 1))  /* add ARP and route IPV4 */
#ifdef HL_LINUX
       ADSL_QUERY_AR_ADD_IPV4_G->imc_ifindex_nic  /* interface number of NIC */
         = dsg_tun_ctrl.imc_ifindex_nic_ipv4;  /* interface number of NIC IPV4 */
       memcpy( ADSL_QUERY_AR_ADD_IPV4_G->chrc_tiface, dsg_tun_ctrl.chrc_tiface, IFNAMSIZ );
       memcpy( ADSL_QUERY_AR_ADD_IPV4_G->chrc_riface, dsg_tun_ctrl.chrc_riface, IFNAMSIZ );
       memcpy( &ADSL_QUERY_AR_ADD_IPV4_G->dsc_rhwaddr, &dsg_tun_ctrl.dsc_rhwaddr, sizeof(struct sockaddr) );
#endif
#ifdef HL_FREEBSD
       memcpy( ADSL_QUERY_AR_ADD_IPV4_G->chrc_soa_dl_riface, &dsg_tun_ctrl.dsc_soa_dl_r, sizeof(sockaddr_dl) );
       memcpy( ADSL_QUERY_AR_ADD_IPV4_G->chrc_soa_dl_tiface, &dsg_tun_ctrl.dsc_soa_dl_t, sizeof(sockaddr_dl) );
       memcpy( ADSL_QUERY_AR_ADD_IPV4_G->chrc_riface, dsg_tun_ctrl.chrc_riface, IFNAMSIZ );
#endif
       memcpy( ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta, dss_ser_thr_ctrl.adsc_sth_work->chrc_ineta, sizeof(UNSIG_MED) );
#undef ADSL_QUERY_AR_ADD_IPV4_G
       chrl_send_buf[ 0 ] = (unsigned char) ied_ligwq_arproute_add_ipv4;  /* add ARP and route IPV4 */
       m_ligw_send( chrl_send_buf, 1 + sizeof(struct dsd_ligw_q_ar_add_ipv4), NULL );
       dss_ligw_g.boc_ser_sent = TRUE;      /* serialize command sent  */
     } else if (dss_ser_thr_ctrl.adsc_sth_work->iec_sth  /* serial thread task type */
             == ied_sth_route_ipv4_del) {   /* delete a route IPV4     */
       dss_ligw_g.boc_ser_sent = TRUE;      /* serialize command sent  */
#ifdef B140303
#define ADSL_QUERY_AR_DEL_IPV4_G ((struct dsd_ligw_q_ar_add_ipv4 *) (chrl_send_buf + 1))  /* del ARP and route IPV4 */
#endif
#define ADSL_QUERY_AR_DEL_IPV4_G ((struct dsd_ligw_q_ar_del_ipv4 *) (chrl_send_buf + 1))  /* del ARP and route IPV4 */
#ifdef HL_LINUX
       memcpy( ADSL_QUERY_AR_DEL_IPV4_G->chrc_tiface, dsg_tun_ctrl.chrc_tiface, IFNAMSIZ );
       memcpy( ADSL_QUERY_AR_DEL_IPV4_G->chrc_riface, dsg_tun_ctrl.chrc_riface, IFNAMSIZ );
       memcpy( &ADSL_QUERY_AR_DEL_IPV4_G->dsc_rhwaddr, &dsg_tun_ctrl.dsc_rhwaddr, sizeof(struct sockaddr) );
#endif
#ifdef HL_FREEBSD
       memcpy( ADSL_QUERY_AR_DEL_IPV4_G->chrc_soa_dl_riface, &dsg_tun_ctrl.dsc_soa_dl_r, sizeof(sockaddr_dl) );
       memcpy( ADSL_QUERY_AR_DEL_IPV4_G->chrc_soa_dl_tiface, &dsg_tun_ctrl.dsc_soa_dl_t, sizeof(sockaddr_dl) );
#endif
       memcpy( ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta, dss_ser_thr_ctrl.adsc_sth_work->chrc_ineta, sizeof(UNSIG_MED) );
#undef ADSL_QUERY_AR_DEL_IPV4_G
       chrl_send_buf[ 0 ] = (unsigned char) ied_ligwq_arproute_del_ipv4;  /* del ARP and route IPV4 */
       m_ligw_send( chrl_send_buf, 1 + sizeof(struct dsd_ligw_q_ar_del_ipv4), NULL );
       dss_ligw_g.boc_ser_sent = TRUE;      /* serialize command sent  */
     } else {                               /* invalid command         */
       m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W m_main_poll() invalid serialize command iec_sth %d.",
                       __LINE__, dss_ser_thr_ctrl.adsc_sth_work->iec_sth );
       dsg_global_lock.m_enter();           /* enter critical section  */
       adsl_sth_w1 = dss_ser_thr_ctrl.adsc_sth_work;  /* get work as task for serial thread */
       dss_ser_thr_ctrl.adsc_sth_work = adsl_sth_w1->adsc_next;  /* remove from chain */
       adsl_sth_w1->adsc_next = dss_ser_thr_ctrl.adsc_sth_free;  /* get old chain free */
       dss_ser_thr_ctrl.adsc_sth_free = adsl_sth_w1;  /* set new chain free */
       dsg_global_lock.m_leave();           /* leave critical section  */
//     goto p_sub_poll_00;                  /* do poll now             */
     }
   }
#endif
   iml_timeout = INFTIM;                    /* set infinite            */
   if (iml_endtime_w1 != 0) {               /* end time set            */
     iml_timeout = (iml_endtime_w1 - dsl_time_1) * 1000;
     if (iml_timeout <= 0) {                /* timer has elapsed       */
       return ied_rmp_timeout;              /* timer elapsed           */
     }
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T before poll( ... , imc_poll_ele=%d , %d )",
                   __LINE__, dss_main_poll_sub.imc_poll_ele, iml_timeout );
#endif
   iml_rc = poll( dss_main_poll_sub.dsrc_poll, dss_main_poll_sub.imc_poll_ele, iml_timeout );
   if (iml_rc < 0) {                        /* was error               */
     m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W poll() returned=%d errno=%d.",
                     __LINE__, iml_rc, errno );
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T poll() returned %d.",
                   __LINE__, iml_rc );
#endif
   if ((dss_main_poll_sub.dsrc_poll[ 0 ].revents & POLLIN) == 0) {  /* event not set */
     goto p_sub_poll_40;                    /* check listen-gateway    */
   }
   iml_rc = read( imrs_m_fd_pipe[0], vprl_message, sizeof(vprl_message) );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T read pipe completed cont=%p/%p / returned iml_rc=%d errno=%d.",
                   __LINE__, vprl_message[0], vprl_message[1], iml_rc, errno );
#endif
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T read pipe completed cont=%p/%p / returned iml_rc=%d errno=%d.",
                   __LINE__, vprl_message[0], vprl_message[1], iml_rc, errno );
#endif
   if (iml_rc != sizeof(vprl_message)) {    /* length not as expected  */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW nbipgw20 l%05d read pipe / invalid size %d errno %d.",
                     __LINE__, iml_rc, errno );
     goto p_sub_poll_40;                    /* check listen-gateway    */
   }
   switch (*((ied_mess_pipe_main *) &vprl_message[0])) {  /* type of message */
     case ied_mepm_work:                    /* message work to do      */
       break;                               /* nothing special         */
     case ied_mepm_sig_end:                 /* message signal end      */
       bos_end_proc = TRUE;                 /* signal end of processing */
       return ied_rmp_sig_end;              /* message signal end      */
     case ied_mepm_sig_reload:              /* message signal reload configuration */
       if (dss_loconf_1.boc_reload_conf) {  /* allow reload configuration */
         if (iep_fmp == ied_fmp_normal) {   /* normal processing       */
           return ied_rmp_sig_reload;       /* message signal reload configuration */
         }
         return ied_rmp_sig_end;            /* end of program while waiting for socket operation */
       }
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW nbipgw20 l%05d received signal reload configuration but not configured - ignored",
                       __LINE__ );
       break;
     case ied_mepm_sig_check_shu:           /* message signal check shutdown */
       return ied_rmp_sig_check_shu;        /* message signal check shutdown */
     default:
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW nbipgw20 l%05d read pipe / ied_mess_pipe_main = %d invalid",
                       __LINE__, *((ied_mess_pipe_main *) &vprl_message[0]) );
       break;
   }

   p_sub_poll_40:                           /* check listen-gateway    */
   if (dss_main_poll_sub.imc_poll_ele <= 1) {  /* not waiting for listen-gateway */
     goto p_sub_poll_00;                    /* do poll now             */
   }
   if (dss_main_poll_sub.dsrc_poll[ 1 ].revents & POLLIN) {
     m_ligw_recv();                         /* receive from listen-gateway */
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
     m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_main_poll() after m_ligw_recv() dss_ligw_g.adsc_gate_1_create_socket=%p dss_ligw_g.adsc_gate_listen_1_cur=%p dss_ligw_g.adsc_gate_listen_1_next=%p dsg_sys_state_1.boc_listen_active=%d.",
                     __LINE__, dss_ligw_g.adsc_gate_1_create_socket, dss_ligw_g.adsc_gate_listen_1_cur, dss_ligw_g.adsc_gate_listen_1_next, dsg_sys_state_1.boc_listen_active );
#endif
   }
   if (dss_main_poll_sub.dsrc_poll[ 1 ].revents & POLLHUP) {  /* Hung up. */
     if (dss_ligw_g.boc_connected) {        /* connected to Listen Gateway */
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW nbipgw20 l%05d socket listen-gateway returned POLLHUP - closing connection to listen-gateway",
                       __LINE__ );
       dss_ligw_g.imc_time_disconnect = (int) time( NULL );  /* time of disconnect */
       dss_ligw_g.boc_connected = FALSE;    /* not connected to Listen Gateway */
#ifdef D_INCL_HOB_TUN
       dss_ligw_g.boc_ser_sent = FALSE;     /* serialize command sent  */
       dss_ligw_g.imc_open_tun_sent = 0;    /* command open TUN sent   */
#endif
       iml_rc = close( dss_ligw_g.imc_sockfd );
       if (iml_rc != 0) {                   /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW nbipgw20 l%05d close socket listen-gateway returned %d %d.",
                         __LINE__, iml_rc, errno );
       }
     }
   }
   dss_main_poll_sub.dsrc_poll[ 1 ].revents = 0;  /* no event for listen-gateway */
   if (dss_ligw_g.boc_connected == FALSE) {  /* not connected to Listen Gateway */
     dss_main_poll_sub.imc_poll_ele = 1;    /* elements for poll()     */
   }
   goto p_sub_poll_00;                      /* do poll now             */
} /* end m_main_poll()                                                 */

/** start parts of the program                                         */
static BOOL m_startprog( struct dsd_wsp_startprog *adsp_wsp_startprog ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working variables       */
   int        iml_rc;                       /* return code             */
   int        iml_pid;                      /* process id this         */
   int        iml_fd_f1;                    /* file-descriptor for file */
   char       *achl1, *achl2;               /* working variables       */
#ifdef XYZ1
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */
#endif
#ifdef B100802
#ifdef D_HPPPT1_1
   DWORD      dwl_ret;                      /* return code             */
   unsigned long int uml_ai_buf_len;        /* length of buffer for adapter info */
   DWORD      dwl_index_if;                 /* holds index of compatible IF */
   PIP_ADAPTER_INFO adsl_adap_info_w1;      /* points to first adapter info */
   PIP_ADAPTER_INFO adsl_adap_info_w2;      /* points to first adapter info */
   IP_ADDR_STRING *adsl_ineta_cur;
#endif
#endif
#ifdef XYZ1
   int        imrl_sha1[ SHA_ARRAY_SIZE ];  /* for hash                */
#endif
   HL_LONGLONG ilrl_sha384_temp[ SHA384_ARRAY_SIZE ];  /* for hash security-token */
   char       chrl_work_1[512];             /* working area            */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_startprog() called" );
#endif

#ifdef XYZ1
#ifndef D_NO_DUMP
   m_hl_setdump();                          /* start dump              */
#endif
#endif
   bos_mem_log = m_create_log( adsg_loconf_1_inuse->ilc_mem_ls );
   /* initialize random generator                                      */
   srand( (unsigned int) (m_get_rand_epoch_ms() >> 7) );
   m_hco_set_thr_sta_func( &m_wothr_start_inj );

#ifdef XYZ1
   dsrs_heve_main[0] = CreateEvent( NULL, FALSE, FALSE, NULL );
   if (dsrs_heve_main[0] == NULL) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPM070W CreateEvent MAIN Error %d", GetLastError() );
     if (boisservice) {
       dclasrvstat.dwCurrentState = SERVICE_STOPPED;  /* service close */
       SetServiceStatus( dclhsrvstat, &dclasrvstat );  /* set state    */
     }
     return FALSE;
   }

   InitializeCriticalSection( &d_clconn_critsect );

   InitializeCriticalSection( &d_clutil_critsect );

   InitializeCriticalSection( &d_clwork_critsect );

   InitializeCriticalSection( &dsalloc_dcritsect );
#endif

   iml_rc = dss_critsect_aux.m_create();
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_critsect_aux m_create return code %d",
                     __LINE__, iml_rc );
     return FALSE;                          /* count not start resource */
   }

   iml_rc = dsg_global_lock.m_create();
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dsg_global_lock m_create return code %d.",
                     __LINE__, iml_rc );
     return FALSE;                          /* count not start resource */
   }

   iml_rc = dss_trace_lock.m_create();      /* lock for WSP-trace      */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPM0xxW l%05d m_startprog() dss_trace_lock m_create return code %d.",
                     __LINE__, iml_rc );
     return FALSE;                          /* count not start resource */
   }

#ifdef XYZ1
   InitializeCriticalSection( &dsg_radius_control.dsc_critsect );
#endif

   /* initialize common memory area                                    */
   m_cma1_init();

#ifdef XYZ1
   m_start_ip();                            /* start TCP/IP            */
   dsd_nblock_acc::mc_startup();
   dss_acccb.am_acc_acceptcallback = &m_acc_acceptcallback; // accept callback routine
   dss_acccb.am_acc_errorcallback = &m_acc_errorcallback;   // error callback routine
   iml_rc1 = dsd_tcpcomp::m_startup( NULL );
   if (iml_rc1) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dsd_tcpcomp::m_startup() Return Code %d",
                     __LINE__, iml_rc1 );
   }
   m_gw_udp_start();                        /* start UDP and SIP       */
#endif
#ifndef B120717
   m_gw_udp_start();                        /* start UDP and SIP       */
#endif
   iml_rc = dsg_radius_control.dsc_critsect.m_create();
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dsg_radius_control.dsc_critsect m_create return code %d.",
                     __LINE__, iml_rc );
     return FALSE;                          /* count not start resource */
   }

   /* init AVL Tree functions session                                  */
   bol1 = m_htree1_avl_init( NULL, &dss_htree1_avl_cntl_conn,
                             &m_cmp_session_id );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_htree1_avl_init() Session-Id failed",
                     __LINE__ );
     return FALSE;                          /* could not start resource */
   }
   m_admin_start();                         /* start ADMIN             */
   /* init AVL Tree aux-pipe-listen                                    */
   bol1 = m_htree1_avl_init( NULL, &dss_htree1_avl_cntl_aux_pipe_listen,
                             &m_cmp_aux_pipe_listen );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_htree1_avl_init() aux-pipe-listen failed",
                     __LINE__ );
     return FALSE;                          /* could not start resource */
   }
   /* init AVL Tree SDH-reload                                         */
   bol1 = m_htree1_avl_init( NULL, &dss_htree1_avl_cntl_aux_sdh_reload,
                             &m_cmp_aux_sdh_reload );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_htree1_avl_init() SDH-reload failed",
                     __LINE__ );
     return FALSE;                          /* could not start resource */
   }
   /* give message of SSL Library                                      */
   iml1 = m_hssl_getversioninfo( &iml2, NULL, NULL );
   if (iml1 != HSSL_OP_OK) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM040W Error m_hssl_getversioninfo failed rc=%d.", iml1 );
   } else {
     m_hlnew_printf( HLOG_INFO1, "HWSPM041I m_hssl_getversioninfo SSL-Version: %d, Revision=%d, Release=%d.%d",
                     (unsigned char) (iml2 >> 24), (unsigned char) (iml2 >> 16),
                     (unsigned char) (iml2 >> 8), (unsigned char) iml2 );
   }
   iml2 = sizeof(chrl_work_1);
   iml1 = m_hssl_getversioninfo( NULL, chrl_work_1, &iml2 );
   if (iml1 != HSSL_OP_OK) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM042W Error m_hssl_getversioninfo failed rc=%d.", iml1 );
   } else {
     m_hlnew_printf( HLOG_INFO1, "HWSPM043I m_hssl_getversioninfo %s", chrl_work_1 );
   }
   /* start work threads                                               */
   m_hco_init( dss_loconf_1.inc_max_poss_workthr, dss_loconf_1.inc_max_act_workthr );
#ifdef D_FILL_LOG                           /* 24.04.08 KB             */
   m_test_fill_log();
#endif
#ifdef WSP_TRACE_FILE_01
   {
     int      imh1;
     struct dsd_wspadm1_q_wsp_trace_1 *adsh_wspadm1_qwt1;
     char     chrh_work1[ 512 ];
#ifdef B120613
     adsg_loconf_1_inuse->boc_allow_wsp_trace = TRUE;  /* <allow-wsp-trace> */
#endif
     adsh_wspadm1_qwt1 = (struct dsd_wspadm1_q_wsp_trace_1 *) chrh_work1;
#ifndef WSP_TRACE_CONSOLE
     memset( adsh_wspadm1_qwt1, 0, sizeof(struct dsd_wspadm1_q_wsp_trace_1) );
     imh1 = sprintf( (char *) (adsh_wspadm1_qwt1 + 1), "%s", WSP_TRACE_FILE_01 );
     adsh_wspadm1_qwt1->iec_wawt = ied_wawt_target;  /* define new target */
#ifndef WSP_TRACE_FILE_BIN
     adsh_wspadm1_qwt1->iec_wtt = ied_wtt_file_ascii;  /* trace records to file ASCII */
#else
     adsh_wspadm1_qwt1->iec_wtt = ied_wtt_file_bin;  /* trace records to file binary */
#endif
     m_ctrl_wspadm1_wsp_trace( adsh_wspadm1_qwt1, imh1 );
#endif
#ifndef PROBLEM_141216                      /* HOB-PPP-T1, work-threads hang */
     memset( adsh_wspadm1_qwt1, 0, sizeof(struct dsd_wspadm1_q_wsp_trace_1) );
     adsh_wspadm1_qwt1->iec_wawt = ied_wawt_trace_new_ineta_all;  /* trace all INETAs */
     adsh_wspadm1_qwt1->imc_trace_level = -1;  /* trace level          */
     m_ctrl_wspadm1_wsp_trace( adsh_wspadm1_qwt1, 0 );
#endif
     memset( adsh_wspadm1_qwt1, 0, sizeof(struct dsd_wspadm1_q_wsp_trace_1) );
     adsh_wspadm1_qwt1->iec_wawt = ied_wawt_trace_new_core;  /* new parameters trace WSP core */
     adsh_wspadm1_qwt1->imc_trace_level = -1;  /* trace level          */
#ifdef PROBLEM_141216                       /* HOB-PPP-T1, work-threads hang */
     adsh_wspadm1_qwt1->imc_trace_level = HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2 | HL_WT_CORE_CLUSTER | HL_WT_CORE_LIGW;  /* trace level */
#endif
     m_ctrl_wspadm1_wsp_trace( adsh_wspadm1_qwt1, 0 );
   }
#endif
   if (dss_loconf_1.achc_pid_file == NULL) {  /* no name PID-file      */
     goto p_stpr_60;
   }
   iml_pid = getpid();                      /* get our process ID      */
   iml_fd_f1 = open( dss_loconf_1.achc_pid_file, O_RDONLY );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_startprog() l%05d open( %(u8)s ) returned=%d errno=%d",
                   __LINE__, dss_loconf_1.achc_pid_file, iml_fd_f1, errno );
#endif
   if (iml_fd_f1 < 0) {                     /* error occured           */
     goto p_stpr_20;                        /* PID file not opened     */
   }
   iml_rc = read( iml_fd_f1, chrl_work_1, sizeof(chrl_work_1) );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM050W m_startprog() PID-file %(u8)s read() returned Error %d.",
                     dss_loconf_1.achc_pid_file, errno );
     close( iml_fd_f1 );
     goto p_stpr_20;                        /* PID file not opened     */
   }
   achl1 = chrl_work_1;                     /* start of buffer         */
   achl2 = chrl_work_1 + iml_rc;            /* end of buffer           */
   iml1 = 0;                                /* clear result            */
   while ((achl1 < achl2) && (*achl1 >= 0X30) && (*achl1 <= 0X39)) {
     iml1 *= 10;                            /* multiple old result     */
     iml1 += *achl1 - 0X30;                 /* add new digit           */
     achl1++;                               /* next digit              */
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_startprog() l%05d read() returned=%d PID=%d",
                   __LINE__, iml_rc, iml1 );
#endif
   iml_rc = close( iml_fd_f1 );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM051W m_startprog() PID-file %(u8)s close() returned Error %d.",
                     dss_loconf_1.achc_pid_file, errno );
   }
   if (dss_loconf_1.boc_reload_conf) {      /* allow reload configuration */
     if (iml1 == iml_pid) {                 /* found PID of this process */
       m_hlnew_printf( HLOG_WARN1, "HWSPM052W m_startprog() PID-file %(u8)s contains PID %d of this process - do not send signal",
                       dss_loconf_1.achc_pid_file, iml_pid );
       goto p_stpr_20;                      /* PID file not opened     */
     }
     if (iml1) {                            /* PID is valid            */
       iml_rc = kill( iml1, SIGUSR1 );
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "m_startprog() l%05d kill() returned=%d.",
                       __LINE__, iml_rc );
#endif
       sleep( 2 );                          /* wait two seconds        */
     } else {                               /* PID zero not valid      */
       m_hlnew_printf( HLOG_WARN1, "HWSPM053W m_startprog() PID-file %(u8)s PID zero read - ignored",
                       dss_loconf_1.achc_pid_file );
     }
   }

   p_stpr_20:                               /* PID file not opened     */
   iml2 = sprintf( chrl_work_1, "%d\n", iml_pid );
#ifdef B160805
   iml_fd_f1 = open( dss_loconf_1.achc_pid_file, O_WRONLY | O_CREAT,
                     S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
#endif
#ifndef B160805
   iml_fd_f1 = open( dss_loconf_1.achc_pid_file, O_WRONLY | O_CREAT | O_TRUNC,
                     S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_startprog() l%05d open( %(u8)s ) returned=%d errno=%d",
                   __LINE__, dss_loconf_1.achc_pid_file, iml_fd_f1, errno );
#endif
   if (iml_fd_f1 < 0) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM054W m_startprog() PID-file %(u8)s open() returned Error %d.",
                     dss_loconf_1.achc_pid_file, errno );
     goto p_stpr_60;                        /* PID file not opened     */
   }
   iml_rc = write( iml_fd_f1, chrl_work_1, iml2 );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM055W m_startprog() PID-file %(u8)s write() returned Error %d.",
                     dss_loconf_1.achc_pid_file, errno );
     close( iml_fd_f1 );
     goto p_stpr_60;                        /* PID file not opened     */
   }
   iml_rc = close( iml_fd_f1 );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM056W m_startprog() PID-file %(u8)s close() returned Error %d.",
                     dss_loconf_1.achc_pid_file, errno );
   }
   bos_pid_file = TRUE;                     /* PID file active         */

   p_stpr_60:                               /* end of PID file         */
   dss_ligw_g.boc_connected = FALSE;        /* not connected to Listen Gateway */
#ifdef D_INCL_HOB_TUN
   dss_ligw_g.boc_ser_sent = FALSE;         /* serialize command sent  */
   dss_ligw_g.imc_open_tun_sent = 0;        /* command open TUN sent   */
#endif
   if (dss_loconf_1.boc_listen_gw == FALSE) {  /* do not use listen gateway */
     goto p_ligw_80;                        /* listen gateway has been initialized */
   }
   memset( &dss_ligw_g.dsc_soa_un, 0, sizeof(struct sockaddr_un) );
   dss_ligw_g.dsc_soa_un.sun_family = AF_LOCAL;
   achl1 = dss_loconf_1.achc_ligw_pipe_name;  /* pipe name of Listen Gateway */
   if (achl1 == NULL) {
     achl1 = DEFAULT_UDSNAME;
   }
   iml1 = iml2 = strlen( achl1 );
   if (iml1 > (sizeof(dss_ligw_g.dsc_soa_un.sun_path) - 1)) {
     iml1 = sizeof(dss_ligw_g.dsc_soa_un.sun_path) - 1;
   }
   memcpy( dss_ligw_g.dsc_soa_un.sun_path, achl1, iml1 );
   *((char *) dss_ligw_g.dsc_soa_un.sun_path + iml1) = 0;  /* make zero-terminated */
   if (iml1 != iml2) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPM131W Listen-Gateway pipe-name too long - shortened to \"%(u8)s\"",
                     dss_ligw_g.dsc_soa_un.sun_path );
   }
   dss_ligw_g.adsc_rec1_ch = NULL;          /* chain of receive areas  */
   dss_ligw_g.aimrc_ligw_cluster = NULL;    /* clear cluster structure */
   dss_ligw_g.adsc_gate_1_create_socket = NULL;  /* clear current gate to start */
   dss_ligw_g.boc_listen_start = FALSE;     /* start listen at program start */
   dss_ligw_g.boc_stop_listen_lbal = FALSE;  /* stop listen load-balancing in progress */
   m_ligw_open();                           /* open the listen gateway */
   if (dss_ligw_g.boc_connected == FALSE) {  /* not connected to Listen Gateway */
     m_hlnew_printf( HLOG_XYZ1, "HWSPMnnnW Listen-Gateway \"%(u8)s\" could not be connected to - waiting for Listen-Gateway to be started",
                     dss_ligw_g.dsc_soa_un.sun_path );
   } else {                                 /* connected to Listen Gateway */
     dss_main_poll_sub.dsrc_poll[ 1 ].fd = dss_ligw_g.imc_sockfd;  /* socket for connection */
     dss_main_poll_sub.dsrc_poll[ 1 ].events = POLLIN;
     dss_main_poll_sub.imc_poll_ele = 2;    /* elements for poll()     */
   }

   p_ligw_80:                               /* listen gateway has been initialized */
//#ifdef D_HPPPT1_1
#ifdef D_INCL_HOB_TUN
#ifdef B100802
   inl1 = (int) m_htun_start();
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T m_htun_start() returned %d.",
                   __LINE__, inl1 );
#endif
// to-do 13.05.10 KB - init before start cluster
   /* init AVL Tree functions INETA                                    */
   bol1 = m_htree1_avl_init( NULL, &dss_htree1_avl_cntl_ineta_ipv4,
                             &m_cmp_ineta_n_ipv4 );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPM0xxW l%05d m_htree1_avl_init() INETA normal IPV4 failed",
                     __LINE__ );
     return FALSE;                          /* count not start resource */
   }
   bol1 = m_htree1_avl_init( NULL, &dss_htree1_avl_cntl_ineta_ipv6,
                             &m_cmp_ineta_n_ipv6 );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPM0xxW l%05d m_htree1_avl_init() INETA normal IPV6 failed",
                     __LINE__ );
     return FALSE;                          /* count not start resource */
   }
   bol1 = m_htree1_avl_init( NULL, &dss_htree1_avl_cntl_user_i_ipv4,
                             &m_cmp_ineta_user_ipv4 );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPM0xxW l%05d m_htree1_avl_init() INETA user IPV4 failed",
                     __LINE__ );
     return FALSE;                          /* count not start resource */
   }
   bol1 = m_htree1_avl_init( NULL, &dss_htree1_avl_cntl_user_i_ipv6,
                             &m_cmp_ineta_user_ipv6 );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPM0xxW l%05d m_htree1_avl_init() INETA user IPV6 failed",
                     __LINE__ );
     return FALSE;                          /* count not start resource */
   }
#ifdef B100802
   if (adss_loconf_1_fill->adsc_raw_packet_if_conf == NULL) return TRUE;
   uml_ai_buf_len = 0;                      /* length of buffer for adapter info */
   adsl_adap_info_w1 = NULL;                /* points to first adapter info */
   dwl_ret = GetAdaptersInfo( adsl_adap_info_w1, &uml_ai_buf_len );
   if (dwl_ret != ERROR_BUFFER_OVERFLOW) {
     m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-W GetAdaptersInfo() returned %d/0X%08X.\n",
                     __LINE__, dwl_ret, dwl_ret );
   }
   adsl_adap_info_w1 = (PIP_ADAPTER_INFO) malloc( uml_ai_buf_len );
   dwl_ret = GetAdaptersInfo( adsl_adap_info_w1, &uml_ai_buf_len );
   if (dwl_ret != ERROR_SUCCESS) {
     m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-W GetAdaptersInfo() returned %d/0X%08X.\n",
                     __LINE__, dwl_ret, dwl_ret );
   }
   adsl_adap_info_w2 = adsl_adap_info_w1;
   while (adsl_adap_info_w2) {
     adsl_ineta_cur = &(adsl_adap_info_w2->IpAddressList);
     /* check all addresses                                            */
     while (adsl_ineta_cur) {
#ifndef TRACEHL1_XXX
       m_hl1_printf( "nbipgw20-l%05d-T m_getindex_if() found INETA \"%s\" Index=%d 0X%08X.",
                     __LINE__,
                     adsl_ineta_cur->IpAddress.String,
                     adsl_adap_info_w1->Index,
                     inet_addr( adsl_ineta_cur->IpAddress.String ) );
#endif
       if (inet_addr( adsl_ineta_cur->IpAddress.String)
             == *((DWORD *) &adss_loconf_1_fill->adsc_raw_packet_if_conf->umc_taif_ineta)) {  /* <TUN-adapter-use-interface-ineta> */
         dss_ser_thr_ctrl.umc_index_if = adsl_adap_info_w2->Index;  /* holds index of compatible IF */
         break;
       }
       adsl_ineta_cur = adsl_ineta_cur->Next;
     }
     if (adsl_ineta_cur) break;
     /* move to next interface                                         */
     adsl_adap_info_w2 = adsl_adap_info_w2->Next;
   }
   free( adsl_adap_info_w1 );
   if (adsl_adap_info_w2 == NULL) {         /* adapter not found       */
// 31.07.10 KB error message
   }
#endif
#endif
   /* use security-token                                               */
   achl1 = "HOB";
   iml1 = 3;
   if (dss_loconf_1.imc_len_security_token > 0) {  /* length of security-token */
     achl1 = dss_loconf_1.achc_security_token;  /* security-token UTF-8 */
     iml1 = dss_loconf_1.imc_len_security_token;  /* length of security-token */
   }
#ifdef XYZ1
   SHA1_Init( imrl_sha1 );
   SHA1_Update( imrl_sha1, achl1, 0, iml1 );
   memcpy( imrs_sha1_security_token, imrl_sha1, sizeof(imrs_sha1_security_token) );  /* for hash security-token */
#endif
   SHA384_Init( ilrl_sha384_temp );
   SHA384_512_Update( ilrl_sha384_temp, achl1, 0, iml1 );
   memcpy( ilrs_sha384_security_token, ilrl_sha384_temp, sizeof(ilrs_sha384_security_token) );  /* for hash security-token */
   return TRUE;                             /* all started             */
} /* end m_startprog()                                                 */

/** open the log                                                       */
extern "C" void m_open_log( void ) {        /* open log now            */
   m_hlnew_printf( HLOG_INFO1, MSG_CONS_P1 MSG_CPU_TYPE __DATE__ MSG_CONS_P2 );
} /* end m_open_log()                                                  */

/** Routine injected in Start of Work-Threads                          */
static void m_wothr_start_inj( struct dsd_hco_wothr *adsp_hco_wothr, int imp_threadid ) {
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_wothr_start_inj( %p, %d ) called",
                   adsp_hco_wothr, imp_threadid );
#endif
   srand( (unsigned int) (m_get_rand_epoch_ms() >> 7)
            ^ (unsigned int) imp_threadid ^ ((HL_LONGLONG) adsp_hco_wothr >> 3) );
} /* end m_wothr_start_inj()                                           */

#ifdef B110906
/* send something to the client                                        */
extern "C" BOOL m_l2tp_to_client( struct dsd_l2tp_session *adsp_l2tp_session,
                                  struct dsd_sdh_control_1 *adsp_sdhc1 ) {
#ifdef NOT_YET_110808
   BOOL       bol_act;                      /* activate thread         */
   BOOL       bol_cont_recv;                /* continue receive        */
   class clconn1 *adsl_conn1;               /* class connection        */

   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_l2tp_session
                      - offsetof( class clconn1, dsc_l2tp_session )));
   bol_cont_recv = FALSE;                   /* continue receive        */
   bol_act = FALSE;                         /* not yet set             */
   EnterCriticalSection( &adsl_conn1->d_act_critsect );  /* critical section act */
   if (adsl_conn1->adsc_sdhc1_s1 == NULL) {  /* receive buffer server 1 */
     adsl_conn1->adsc_sdhc1_s1 = adsp_sdhc1;  /* get data received first buffer */
     bol_cont_recv = TRUE;                  /* receive more data       */
     if (adsl_conn1->boc_st_act == FALSE) {  /* thread does not run    */
       adsl_conn1->boc_st_act = TRUE;       /* thread will run soon    */
       bol_act = TRUE;                      /* activate thread         */
     }
   } else {                                 /* already receive data    */
     adsl_conn1->adsc_sdhc1_s2 = adsp_sdhc1;  /* get data received second buffer */
   }
   LeaveCriticalSection( &adsl_conn1->d_act_critsect );  /* critical section act */
   if (bol_act) {                           /* activate thread         */
     m_act_thread_2( adsl_conn1 );
   }
   return bol_cont_recv;
#endif
} /* end m_l2tp_to_client()                                            */
#endif

/** send something to the client                                       */
extern "C" void m_l2tp_to_client( struct dsd_l2tp_session *adsp_l2tp_session,
                                  struct dsd_sdh_control_1 *adsp_sdhc1,
                                  BOOL bop_locked ) {
   int        iml_rc;                       /* return code             */
   BOOL       bol_act;                      /* activate thread         */
   struct dsd_conn1 *adsl_conn1;            /* connection              */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* chain of buffers       */

   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_l2tp_session
                      - offsetof( struct dsd_conn1, dsc_l2tp_session )));
   bol_act = FALSE;                         /* not yet set             */
   if (bop_locked == FALSE) {               /* connection not locked   */
     iml_rc = adsl_conn1->dsc_critsect.m_enter();  /* enter CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
// to-do 09.08.11 KB error number
       m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d m_enter() critical section failed %d.",
                       adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno, adsl_conn1->chrc_ineta, __LINE__, iml_rc );
     }
   }
   if (adsl_conn1->adsc_sdhc1_s1 == NULL) {  /* receive buffer server 1 */
     adsl_conn1->adsc_sdhc1_s1 = adsp_sdhc1;  /* get data received first buffer */
     if (adsl_conn1->boc_st_act == FALSE) {  /* thread does not run    */
       adsl_conn1->boc_st_act = TRUE;       /* thread will run soon    */
       bol_act = TRUE;                      /* activate thread         */
     }
   } else {                                 /* already receive data    */
     adsl_sdhc1_w1 = adsl_conn1->adsc_sdhc1_s1;  /* get first buffer   */
     while (adsl_sdhc1_w1->adsc_next) adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
     adsl_sdhc1_w1->adsc_next = adsp_sdhc1;  /* append data received to first buffer */
   }
   if (bop_locked == FALSE) {               /* connection not locked   */
     iml_rc = adsl_conn1->dsc_critsect.m_leave();  /* leave CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
// to-do 09.08.11 KB error number
       m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d m_leave() critical section failed %d.",
                       adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno, adsl_conn1->chrc_ineta, __LINE__, iml_rc );
     }
   }
   if (bol_act) {                           /* activate thread         */
     m_act_thread_2( adsl_conn1 );
   }
} /* end m_l2tp_to_client()                                            */

/** put a warning related to the session to the console                */
extern "C" void m_l2tp_warning( struct dsd_l2tp_session *adsp_l2tp_session,
                                const char *achp_format, ... ) {
   int        iml_len;                      /* length of message       */
   struct dsd_conn1 *adsl_conn1;            /* connection              */
   va_list    dsl_list;                     /* list of arguments       */
   char       chrl_msg[ 512 ];              /* area for message        */


   if (adsp_l2tp_session) {
     adsl_conn1 = ((struct dsd_conn1 *)
                     ((char *) adsp_l2tp_session
                        - offsetof( struct dsd_conn1, dsc_l2tp_session )));
   }
   va_start( dsl_list, achp_format );       /* build dsl_list of variable arguments */
   iml_len = m_hlvsnprintf( chrl_msg, sizeof(chrl_msg), ied_chs_utf_8,
                            achp_format, dsl_list );
   va_end( dsl_list );                      /* destroy list            */
   if (adsp_l2tp_session) {
     m_hlnew_printf( HLOG_WARN1, "HWSPS122W GATE=%(ux)s SNO=%08d INETA=%s L2TP %.*(u8)s",
                     adsl_conn1->adsc_gate1 + 1,
                     adsl_conn1->dsc_co_sort.imc_sno,
                     adsl_conn1->chrc_ineta,
                     iml_len, chrl_msg );
     return;
   }
   m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW no connection - L2TP %.*(u8)s",
                   iml_len, chrl_msg );
} /* end m_l2tp_warning()                                              */

/** put information related to the session to the console              */
extern "C" void m_l2tp_information( struct dsd_l2tp_session *adsp_l2tp_session,
                                    const char *achp_format, ... ) {
   int        iml_len;                      /* length of message       */
   struct dsd_conn1 *adsl_conn1;            /* connection              */
   va_list    dsl_list;                     /* list of arguments       */
   char       chrl_msg[ 512 ];              /* area for message        */

   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_l2tp_session
                      - offsetof( struct dsd_conn1, dsc_l2tp_session )));
   va_start( dsl_list, achp_format );       /* build dsl_list of variable arguments */
   iml_len = m_hlvsnprintf( chrl_msg, sizeof(chrl_msg), ied_chs_utf_8,
                            achp_format, dsl_list );
   va_end( dsl_list );                      /* destroy list            */
   m_hlnew_printf( HLOG_XYZ1, "HWSPS123I GATE=%(ux)s SNO=%08d INETA=%s L2TP %.*(u8)s",
                   adsl_conn1->adsc_gate1 + 1,
                   adsl_conn1->dsc_co_sort.imc_sno,
                   adsl_conn1->chrc_ineta,
                   iml_len, chrl_msg );
} /* end m_l2tp_information()                                          */

/** set PPP authentication type for L2TP session                       */
extern "C" void m_l2tp_set_ppp_auth( struct dsd_l2tp_session *adsp_l2tp_session, char *achp_ppp_auth ) {
   struct dsd_conn1 *adsl_conn1;            /* connection              */

   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_l2tp_session
                      - offsetof( struct dsd_conn1, dsc_l2tp_session )));
   if (adsl_conn1->adsc_server_conf_1 == NULL) return;  /* no configuration server */
   memcpy( achp_ppp_auth, adsl_conn1->adsc_server_conf_1->chrc_ppp_auth, DEF_NO_PPP_AUTH );
} /* end m_l2tp_set_ppp_auth()                                         */

/** repeat sending data of this session                                */
extern "C" void m_l2tp_repeat_send( struct dsd_hco_wothr *adsp_hco_wothr, struct dsd_l2tp_session *adsp_l2tp_session ) {
   struct dsd_conn1 *adsl_conn1;            /* connection              */

   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_l2tp_session
                      - offsetof( struct dsd_conn1, dsc_l2tp_session )));
   m_ext_send_server( adsp_hco_wothr, adsl_conn1, NULL );
} /* end m_l2tp_repeat_send()                                          */

/** get address of INETA configured                                    */
extern "C" char * m_l2tp_get_client_ineta( struct dsd_l2tp_session *adsp_l2tp_session ) {
#ifdef B100702
   struct dsd_conn1 *adsl_conn1;            /* connection              */

   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_l2tp_session
                      - offsetof( struct dsd_conn1, dsc_l2tp_session )));
   return (char *) &adsl_conn1->umc_ineta_ppp_ipv4;  /* INETA PPP IPV4 */
#endif
// to-do 03.07.10 KB - needs to use m_prepare_htun_ineta() without setting the route
   return NULL;
} /* end m_l2tp_get_client_ineta()                                     */

/** L2TP connection has ended                                          */
extern "C" void m_l2tp_server_end( struct dsd_l2tp_session *adsp_l2tp_session,
                                   BOOL bop_locked,
                                   char *achp_reason_end ) {
   int        iml_rc;                       /* return code             */
   BOOL       bol_act;                      /* activate thread         */
   struct dsd_conn1 *adsl_conn1;            /* connection              */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working variable       */

   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_l2tp_session
                      - offsetof( struct dsd_conn1, dsc_l2tp_session )));
   adsl_conn1->iec_servcotype = ied_servcotype_ended;  /* server connection ended */
   bol_act = FALSE;                         /* not yet set             */
   if (bop_locked == FALSE) {               /* critical section not yet set */
     iml_rc = adsl_conn1->dsc_critsect.m_enter();  /* enter CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
// to-do 09.08.11 KB error number
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d m_enter() critical section failed %d.",
                       adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno, adsl_conn1->chrc_ineta, __LINE__, iml_rc );
     }
   }
   adsl_sdhc1_w1 = adsl_conn1->adsc_sdhc1_l2tp_sch; /* get buffers in chain */
   adsl_conn1->adsc_sdhc1_l2tp_sch = NULL;  /* chain is empty now      */
   if (adsl_conn1->achc_reason_end == NULL) {  /* reason end session   */
     adsl_conn1->achc_reason_end = "L2TP ended";
     if (achp_reason_end) {
       adsl_conn1->achc_reason_end = achp_reason_end;
     }
   }
   if (adsl_conn1->boc_st_act == FALSE) {   /* thread does not run     */
     adsl_conn1->boc_st_act = TRUE;         /* thread will run soon    */
     bol_act = TRUE;                        /* activate thread         */
   }
   if (bop_locked == FALSE) {               /* critical section not yet set */
     iml_rc = adsl_conn1->dsc_critsect.m_leave();  /* leave CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
// to-do 09.08.11 KB error number
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d m_leave() critical section failed %d.",
                       adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno, adsl_conn1->chrc_ineta, __LINE__, iml_rc );
     }
   }
   if (bol_act) {                           /* activate thread         */
     m_act_thread_2( adsl_conn1 );
   }
   while (adsl_sdhc1_w1) {                  /* loop over buffers to free */
     adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* get buffer              */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
     m_proc_free( adsl_sdhc1_w2 );          /* free buffer             */
   }
} /* end m_l2tp_server_end()                                           */

/** put work area in chain inuse                                       */
static inline void m_clconn1_mark_work_area( void * ap_conn1, struct dsd_sdh_control_1 *adsp_sdhc1 ) {
#define ADSL_CONN1_G ((struct dsd_conn1 *) ap_conn1)
   ADSL_CONN1_G->dsc_critsect.m_enter();    /* critical section        */
   adsp_sdhc1->adsc_next = ADSL_CONN1_G->adsc_sdhc1_inuse;  /* chain of buffers in use */
   ADSL_CONN1_G->adsc_sdhc1_inuse = adsp_sdhc1;  /* append to chain    */
   ADSL_CONN1_G->dsc_critsect.m_leave();    /* critical section        */
#undef ADSL_CONN1_G
} /* end m_clconn1_mark_work_area()                                    */

/** compare entries in AVL tree of sessions                            */
static int m_cmp_session_id( void *,
                             struct dsd_htree1_avl_entry *adsp_entry_1,
                             struct dsd_htree1_avl_entry *adsp_entry_2 ) {
#define ADSL_CO_SORT_P1 ((struct dsd_co_sort *) ((char *) adsp_entry_1 - offsetof( struct dsd_co_sort, dsc_sort_1 )))
#define ADSL_CO_SORT_P2 ((struct dsd_co_sort *) ((char *) adsp_entry_2 - offsetof( struct dsd_co_sort, dsc_sort_1 )))
   return ADSL_CO_SORT_P1->imc_sno - ADSL_CO_SORT_P2->imc_sno;
#undef ADSL_CO_SORT_P1
#undef ADSL_CO_SORT_P2
} /* end m_cmp_session_id()                                            */

#include "xiipgw08-pd-main.cpp"
#include "xiipgw08-pd-http.cpp"
#include "xiipgw08-pd-auth.cpp"
#include "xiipgw08-pd-sdh.cpp"
#include "xiipgw08-seli.cpp"
#include "xiipgw08-aux.cpp"
#include "xiipgw08-tcp.cpp"
#include "xiipgw08-pttd.cpp"
#ifdef D_INCL_HOB_TUN
#include "xiipgw08-tun.cpp"
#endif
#include "xiipgw08-trace.cpp"
#include "xiipgw08-admin.cpp"

/** call DOM for subroutines                                           */
extern "C" void * m_call_dom( DOMNode *adsp_domnode, ied_hlcldom_def iep_hlcldom_def ) {
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_call_dom() called adsp_domnode=%p iep_hlcldom_def=%d",
                   adsp_domnode, iep_hlcldom_def );
#endif
   switch (iep_hlcldom_def) {               /* which function called   */
     case ied_hlcldom_get_first_child:      /* getFirstChild()         */
       return adsp_domnode->getFirstChild();
     case ied_hlcldom_get_next_sibling:     /* getNextSibling()        */
       if (adsp_domnode == dsg_cdaux_control.adsc_node_conf) {
         m_hlnew_printf( HLOG_WARN1, "HWSPD001W m_call_dom() call getNextSibling( conf ) forbidden" );
         return NULL;
       }
       return adsp_domnode->getNextSibling();
     case ied_hlcldom_get_node_type:        /* getNodeType()           */
       return (void *) adsp_domnode->getNodeType();
     case ied_hlcldom_get_node_value:       /* getNodeValue()          */
       return (void *) adsp_domnode->getNodeValue();
     case ied_hlcldom_get_node_name:        /* getNodeName()           */
       return (void *) adsp_domnode->getNodeName();
     case ied_hlcldom_get_file_line:        /* get line in file        */
       return (void *) ((int) GET_LINE( adsp_domnode ));
     case ied_hlcldom_get_file_column:      /* get column in file      */
       return (void *) ((int) GET_COLUMN( adsp_domnode ));
   }
   return NULL;
} /* end m_call_dom()                                                  */

/** non-blocking accept error callback routine                         */
static void m_acc_errorcallback( class dsd_nblock_acc *, void *, char *, int, int ) // Error callback function.
{
// do-to 27.01.08 KB
   m_hlnew_printf( HLOG_WARN1, "nbipgw20-%05d-W accept error",
                   __LINE__ );
   return;
} /* end m_acc_errorcallback()                                         */

/** non-blocking accept - accept callback routine                      */
static void m_acc_acceptcallback( class dsd_nblock_acc * dsp_, void * vpp_userfld,
                                  int imp_socket, struct sockaddr *adsp_soa, int imp_len_soa ) {
   BOOL       bol1;                         /* working-variable        */
   int        iml1;                         /* working-variable        */
   int        iml_rc;                       /* return code             */
   int        iml_session_no;               /* session no              */
   time_t     dsl_time_1;                   /* for time                */
   struct dsd_conn1 *adsl_conn1;            /* connection              */
   struct dsd_gate_1 *adsl_gate_1_w1;       /* gate of listen          */
   char       *achl_ineta;                  /* address of INETA        */
   char       *achl_cur;                    /* current INETA pointer   */
   char       *achl_end;                    /* end if INETAs           */
   struct dsd_wsp_tr_ineta_ctrl *adsl_wtic_w1;  /* WSP trace client with INETA control */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace record        */
   char       *achl_avl_error;              /* error code AVL tree     */
   union {
     struct dsd_wsp_snmp_trap_conn_maxconn dsl_snmpt_conn_maxconn;  /* connection maxconn reached */
     struct dsd_wsp_snmp_trap_conn_thresh dsl_snmpt_conn_thresh;  /* connection threshold reached */
   };
   struct dsd_co_sort dsl_co_sort;          /* for connection sort    */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_acc_acceptcallback() called",
                   __LINE__ );
#endif
#define ADSL_GATE_LISTEN_1_G ((struct dsd_gate_listen_1 *) vpp_userfld)
   adsl_gate_1_w1 = ADSL_GATE_LISTEN_1_G->adsc_gate_1;  /* gate of this listen */
#undef ADSL_GATE_LISTEN_1_G
#ifdef TRY_120522_01                        /* SO_REUSEADDR            */
   {
     int      imh_w1;
     socklen_t imh_w2 = sizeof(int);
     iml_rc = getsockopt( imp_socket, SOL_SOCKET, SO_REUSEADDR, (void *) &imh_w1, &imh_w2 );
     m_hlnew_printf( HLOG_TRACE1, "HWSPxxxxT l%05d getsockopt() gate \"%(ux)s\" returned %d %d imh_w1=0X%08X imh_w2=0X%08X.",
                     __LINE__, adsl_gate_1_w1 + 1, iml_rc, D_TCP_ERROR, imh_w1, imh_w2 );
   }
#endif
#ifdef TRY_120513_01                        /* SO_REUSEADDR            */
   if (dss_loconf_1.boc_reload_conf) {      /* allow reload configuration */
     iml_rc = setsockopt( imp_socket, SOL_SOCKET, SO_REUSEADDR, (const char *) &ims_true, sizeof(int) );
     if (iml_rc != 0) {                     /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPxxxxW l%05d Error setsockopt() gate \"%(ux)s\" returned %d %d.",
                       __LINE__, adsl_gate_1_w1 + 1, iml_rc, D_TCP_ERROR );
     }
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T setsockopt( ... SOL_SOCKET , SO_REUSEADDR , ... ) returned %d.",
                     __LINE__, iml_rc );
#endif
   }
#endif
#ifdef D_REFUSE_CONNECT_1                   /* 25.06.07 KB             */
   adsl_gate_1_w1->i_session_max = adsl_gate_1_w1->i_session_cur = 1;
#endif
   bol1 = TRUE;                             /* session is valid        */
   adsl_gate_1_w1->dsc_critsect.m_enter();  /* critical section        */
   adsl_gate_1_w1->i_session_cos++;         /* count start of session  */
   if (   (adsl_gate_1_w1->i_session_max)
       && (adsl_gate_1_w1->i_session_cur >= adsl_gate_1_w1->i_session_max)) {
     bol1 = FALSE;                          /* session not valid       */
     adsl_gate_1_w1->i_session_exc++;       /* count times exceeded    */
   } else {
     adsl_gate_1_w1->i_session_cur++;       /* count current session   */
     if (adsl_gate_1_w1->i_session_cur > adsl_gate_1_w1->i_session_mre)
       adsl_gate_1_w1->i_session_mre = adsl_gate_1_w1->i_session_cur;
     ins_session_no++;                      /* get new session no      */
     iml_session_no = ins_session_no;
   }
/* 19.12.04 KB - session-ID UUUUU */
   adsl_gate_1_w1->dsc_critsect.m_leave();  /* critical section        */
   if (bol1 == FALSE) {                     /* do not start session    */
     D_TCP_CLOSE( imp_socket );
     m_hlnew_printf( HLOG_XYZ1, "HWSPS001W GATE=%(ux)s maximum number of session exceeded",
                     adsl_gate_1_w1 + 1 );
     time( &dsl_time_1 );                   /* get current time        */
#ifdef NOT_YET_110808
     iml1 = adss_loconf_1_fill->imc_time_rda;  /* <time-repeat-delay-alert> */
     if (iml1 <= 0) iml1 = DEF_TIME_SNMP_TRAP_RDA;  /* set default value */
     if (   (adsl_gate_1_w1->imc_snmpt_epoch_conn_maxconn != 0)
         && ((adsl_gate_1_w1->imc_snmpt_epoch_conn_maxconn + iml1) > dsl_time_1)) {
       return;                              /* trap already sent       */
     }
     adsl_gate_1_w1->imc_snmpt_epoch_conn_maxconn = dsl_time_1;  /* set current time SNMP Trap */
     memset( &dsl_snmpt_conn_maxconn, 0, sizeof(struct dsd_wsp_snmp_trap_conn_maxconn) );  /* connection maxconn reached */
     dsl_snmpt_conn_maxconn.imc_no_conn = adsl_gate_1_w1->i_session_cur;  /* current number of connections */
     dsl_snmpt_conn_maxconn.dsc_conn_name.ac_str = adsl_gate_1_w1 + 1;  /* address of string */
     dsl_snmpt_conn_maxconn.dsc_conn_name.imc_len_str = -1;  /* length string in elements */
     dsl_snmpt_conn_maxconn.dsc_conn_name.iec_chs_str = ied_chs_utf_16;  /* character set string */
     m_snmp_trap_1( ied_wsp_snmp_trap_conn_maxconn, &dsl_snmpt_conn_maxconn );  /* send the Trap */
#endif
     return;                                /* all done                */
   }
   adsl_conn1 = (struct dsd_conn1 *) malloc( sizeof(struct dsd_conn1) );  /* connection */
   if (adsl_conn1 == NULL) {                /* no memory available     */
     D_TCP_CLOSE( imp_socket );
     adsl_gate_1_w1->dsc_critsect.m_enter();  /* critical section      */
     adsl_gate_1_w1->i_session_cur--;       /* count current session   */
     adsl_gate_1_w1->dsc_critsect.m_leave();  /* critical section      */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d malloc connection failed - short on memory",
                     adsl_gate_1_w1 + 1, iml_session_no );
     return;                                /* all done                */
   }
#ifdef NOT_YET_110808
   while (   (adsl_gate_1_w1->imc_thresh_session != 0)  /* threshold-session configured */
          && (adsl_gate_1_w1->i_session_cur >= adsl_gate_1_w1->imc_thresh_session)) {  /* threshold-session reached */
     time( &dsl_time_1 );                   /* get current time        */
     iml1 = adss_loconf_1_fill->imc_time_rda;  /* <time-repeat-delay-alert> */
     if (iml1 <= 0) iml1 = DEF_TIME_SNMP_TRAP_RDA;  /* set default value */
     if (   (adsl_gate_1_w1->imc_snmpt_epoch_conn_thresh != 0)
         && ((adsl_gate_1_w1->imc_snmpt_epoch_conn_thresh + iml1) > dsl_time_1)) {
       break;                               /* trap already sent       */
     }
     adsl_gate_1_w1->imc_snmpt_epoch_conn_thresh = dsl_time_1;  /* set current time SNMP Trap */
     memset( &dsl_snmpt_conn_thresh, 0, sizeof(struct dsd_wsp_snmp_trap_conn_thresh) );  /* connection threshold reached */
     dsl_snmpt_conn_thresh.imc_no_conn = adsl_gate_1_w1->i_session_cur;  /* current number of connections */
     dsl_snmpt_conn_thresh.dsc_conn_name.ac_str = adsl_gate_1_w1 + 1;  /* address of string */
     dsl_snmpt_conn_thresh.dsc_conn_name.imc_len_str = -1;  /* length string in elements */
     dsl_snmpt_conn_thresh.dsc_conn_name.iec_chs_str = ied_chs_utf_16;  /* character set string */
     m_snmp_trap_1( ied_wsp_snmp_trap_conn_thresh, &dsl_snmpt_conn_thresh );  /* send the Trap */
     break;
   }
#endif
   adsl_conn1->imc_time_start = m_get_time();  /* time session started */
   adsl_conn1->dsc_co_sort.imc_sno = iml_session_no;  /* set session no */
   iml_rc = getnameinfo( adsp_soa, imp_len_soa,
                         adsl_conn1->chrc_ineta, sizeof(adsl_conn1->chrc_ineta), 0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPM062W GATE=%(ux)s getnameinfo() returned %d %d.",
                     adsl_gate_1_w1 + 1, iml_rc, D_TCP_ERROR );
     strcpy( adsl_conn1->chrc_ineta, "???" );
   }
#ifdef TRY_SNMP_100812
   {
     struct dsd_wsp_snmp_trap_radius_query dsl_wsp_snmp_trap_radius_query;  /* Radius query reported error */
     memset( &dsl_wsp_snmp_trap_radius_query, 0, sizeof(struct dsd_wsp_snmp_trap_radius_query) );
     dsl_wsp_snmp_trap_radius_query.dsc_radius_conf.ac_str = "Test Radius Conf";
     dsl_wsp_snmp_trap_radius_query.dsc_radius_conf.imc_len_str = -1;  /* length string in elements */
     dsl_wsp_snmp_trap_radius_query.dsc_radius_conf.iec_chs_str = ied_chs_ansi_819;  /* character set string */
     dsl_wsp_snmp_trap_radius_query.dsc_error_msg.ac_str = "Error Message 12.08.10 äöüÜÖÄß";
     dsl_wsp_snmp_trap_radius_query.dsc_error_msg.imc_len_str = -1;  /* length string in elements */
     dsl_wsp_snmp_trap_radius_query.dsc_error_msg.iec_chs_str = ied_chs_ansi_819;  /* character set string */
     m_snmp_trap_1( ied_wsp_snmp_trap_radius_query, &dsl_wsp_snmp_trap_radius_query );  /* send the Trap */
   }
#endif
   m_hlnew_printf( HLOG_INFO1, "HWSPS003I GATE=%(ux)s SNO=%08d INETA=%s connect in",
                   adsl_gate_1_w1 + 1, iml_session_no, adsl_conn1->chrc_ineta );
   adsl_conn1->adsc_sdhc1_c1 = NULL;        /* receive buffer client 1 */
   adsl_conn1->adsc_sdhc1_c2 = NULL;        /* receive buffer client 2 */
   adsl_conn1->adsc_sdhc1_s1 = NULL;        /* receive buffer server 1 */
   adsl_conn1->adsc_sdhc1_s2 = NULL;        /* receive buffer server 2 */
   adsl_conn1->adsc_gate1 = adsl_gate_1_w1;  /* get gateway            */
   adsl_conn1->iec_servcotype = ied_servcotype_none;    /* no server connection    */
#define ADSL_GATE_LISTEN_1_G ((struct dsd_gate_listen_1 *) vpp_userfld)
   adsl_conn1->adsc_gate_listen_1 = ADSL_GATE_LISTEN_1_G;  /* listen part of gateway */
#undef ADSL_GATE_LISTEN_1_G
#ifdef B121018
   adsl_conn1->iec_st_cls = ied_cls_normal;  /* status client normal processing */
   if (   (adsl_conn1->adsc_gate1->imc_permmov_from_port > 0)  /* <permanently-moved-from_port> */
       && (((struct sockaddr_in *) &adsl_conn1->adsc_gate_listen_1->dsc_soa)->sin_port == htons( adsl_conn1->adsc_gate1->imc_permmov_from_port))) {  /* <permanently-moved-from_port> */
     adsl_conn1->iec_st_cls = ied_cls_wait_start;  /* status client wait for start message */
   }
#endif
   adsl_conn1->iec_st_cls = ied_cls_set_entropy;  /* set entropy       */
   adsl_conn1->boc_st_act = TRUE;           /* util-thread active      */
   adsl_conn1->boc_st_sslc = FALSE;         /* ssl handshake complete  */
#ifndef B130314
   adsl_conn1->boc_signal_set = FALSE;      /* signal for component set */
#endif
#ifdef XYZ1
   boc_hunt_end = FALSE;                    /* clear hunt end          */
#endif
   adsl_conn1->imc_timeout_set = 0;         /* timeout set in seconds  */
   adsl_conn1->boc_survive = FALSE;         /* survive E-O-F client    */
   adsl_conn1->imc_trace_level = 0;         /* trace level set         */
#ifdef D_INCL_HOB_TUN
   adsl_conn1->imc_references = 0;          /* references to this session */
#endif
   adsl_conn1->inc_c_ns_rece_c = 0;         /* count receive client    */
   adsl_conn1->inc_c_ns_send_c = 0;         /* count send client       */
   adsl_conn1->inc_c_ns_rece_s = 0;         /* count receive server    */
   adsl_conn1->inc_c_ns_send_s = 0;         /* count receive server    */
   adsl_conn1->inc_c_ns_rece_e = 0;         /* count encrypted from se */
   adsl_conn1->inc_c_ns_send_e = 0;         /* count encrypted from se */
   adsl_conn1->ilc_d_ns_rece_c = 0;         /* data receive client     */
   adsl_conn1->ilc_d_ns_send_c = 0;         /* data send client        */
   adsl_conn1->ilc_d_ns_rece_s = 0;         /* data receive server     */
   adsl_conn1->ilc_d_ns_send_s = 0;         /* data send server        */
   adsl_conn1->ilc_d_ns_rece_e = 0;         /* data receive encyrpted  */
   adsl_conn1->ilc_d_ns_send_e = 0;         /* data send encrypted     */
   adsl_conn1->adsc_lbal_gw_1 = NULL;       /* class load balancing GW */
   adsl_conn1->adsc_wtsudp1 = NULL;         /* no WTS UDP yet          */
   adsl_conn1->adsc_auxf_1 = NULL;          /* anchor of extensions    */
   adsl_conn1->adsc_aux_timer_ch = NULL;    /* no auxiliary timer      */
#ifndef NO_LDAP_071116
   adsl_conn1->adsc_aux_ldap = NULL;        /* clear auxiliary LDAP field */
#endif
#ifdef D_INCL_HOB_TUN
   adsl_conn1->adsc_ineta_raws_1 = NULL;    /* auxiliary field for HOB-TUN */
#endif
   adsl_conn1->adsc_sdhc1_frcl = NULL;      /* chain of buffers from client (SSL encrypted) */
   adsl_conn1->adsc_sdhc1_chain = NULL;     /* chain of buffers input output */
   adsl_conn1->adsc_sdhc1_inuse = NULL;     /* chain of buffers in use */
   adsl_conn1->adsc_sdhc1_extra = NULL;     /* chain of buffers extra  */
#ifdef TRACEHL_P_COUNT
   adsl_conn1->inc_aux_mem_cur = 0;         /* current memory size     */
   adsl_conn1->inc_aux_mem_max = 0;         /* maximum memory size     */
#endif
#ifdef WORK051119
   dcl_wsat1_1 = NULL;                      /* class authentication    */
#endif
   adsl_conn1->adsc_wsp_auth_1 = NULL;      /* structure for authentication */
   adsl_conn1->adsc_int_webso_conn_1 = NULL;  /* connect for WebSocket applications - internal */
#ifdef B130216
   adsl_conn1->adsc_conn_server = NULL;     /* temporary connect to server */
#endif
   adsl_conn1->adsc_cpttdt = NULL;          /* connect PTTD thread     */
   adsl_conn1->chrc_server_error[ 0 ] = 0;  /* display server error    */
// to-do 08.12.10 KB - check if imc_trace_level should be set
   adsl_wtic_w1 = adss_wtic_active;         /* WSP trace client with INETA control */
   while (adsl_wtic_w1) {                   /* WSP trace client with INETA control set */
     do {                                   /* pseudo-loop             */
       if (adsl_wtic_w1->boc_trace_ineta_all) {  /* trace all INETAS   */
         adsl_conn1->imc_trace_level = adsl_wtic_w1->imc_trace_level;  /* trace_level */
         break;
       }
       /* search if INETA set                                            */
       achl_ineta = (char *) &((struct sockaddr_in *) adsp_soa)->sin_addr;
       iml1 = 4;                              /* length of INETA         */
       if (adsp_soa->sa_family == AF_INET6) {  /* IPV6                   */
         achl_ineta = (char *) &((struct sockaddr_in6 *) adsp_soa)->sin6_addr;
         iml1 = 16;                           /* length of INETA         */
       }
       achl_cur = (char *) (adsl_wtic_w1 + 1);  /* here start INETAs     */
       achl_end = (char *) (adsl_wtic_w1 + 1) + adsl_wtic_w1->imc_len_inetas;
#define ADSL_WTIA1_G1 ((struct dsd_wsp_tr_ineta_1 *) achl_cur)
       while (achl_cur < achl_end) {          /* loop over all INETAs    */
         if (   (iml1 == ADSL_WTIA1_G1->usc_length)
             && (!memcmp( ADSL_WTIA1_G1 + 1, achl_ineta, iml1 ))) {
           adsl_conn1->imc_trace_level = ADSL_WTIA1_G1->imc_trace_level;  /* trace_level */
           break;                             /* all done                */
         }
         achl_cur += sizeof(struct dsd_wsp_tr_ineta_1) + ADSL_WTIA1_G1->usc_length;  /* next INETA */
       }
#undef ADSL_WTIA1_G1
     } while (FALSE);
     if (adsl_conn1->imc_trace_level == 0) break;
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SCONNIN1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = iml_session_no;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = m_hlsnprintf( (char *) (ADSL_WTR_G1 + 1), 256, ied_chs_ansi_819,
                          "GATE=%(ux)s INETA=%s connect in",
                          adsl_gate_1_w1 + 1, adsl_conn1->chrc_ineta );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
     break;
   }
#ifdef WSP_TRACE_110309
   imc_trace_level = WSP_TRACE_110309;      /* trace level set         */
#endif
   memset( &adsl_conn1->dsc_sdh_s_1, 0, sizeof(struct dsd_sdh_session_1) );  /* clear work area server data hook per session */
   adsl_conn1->adsc_csssl_oper_1 = NULL;    /* operation of client-side SSL */
   adsl_conn1->adsc_user_group = NULL;      /* clear structure user group */
   adsl_conn1->adsc_user_entry = NULL;      /* clear structure user entry */
   adsl_conn1->adsc_radius_group = NULL;    /* active Radius group     */
   adsl_conn1->adsc_krb5_kdc_1 = NULL;      /* active Kerberos 5 KDC   */
   adsl_conn1->adsc_ldap_group = NULL;      /* active LDAP group       */
   if (adsl_gate_1_w1->imc_no_radius == 1) {  /* check number of radius groups */
     adsl_conn1->adsc_radius_group = *(adsl_gate_1_w1->adsrc_radius_group + 0);  /* set active Radius group */
     adsl_conn1->adsc_ldap_group = adsl_conn1->adsc_radius_group->adsc_ldap_group;  /* set corresponding LDAP group */
   }
   if (adsl_gate_1_w1->imc_no_krb5_kdc == 1) {  /* check number of Kerberos 5 KDCs */
     adsl_conn1->adsc_krb5_kdc_1 = *(adsl_gate_1_w1->adsrc_krb5_kdc_1 + 0);  /* set active Kerberos 5 KDC */
     adsl_conn1->adsc_ldap_group = adsl_conn1->adsc_krb5_kdc_1->adsc_ldap_group;  /* set corresponding LDAP group */
   }
   if (adsl_gate_1_w1->imc_no_ldap_group == 1) {  /* check number of LDAP groups */
     adsl_conn1->adsc_ldap_group = *(adsl_gate_1_w1->adsrc_ldap_group + 0);  /* set active LDAP group */
   }
#ifdef XYZ1
   if (   (apdg1->imc_no_ldap_group == 1)   /* check number of LDAP groups */
       && (adsc_ldap_group == NULL)) {
     adsc_ldap_group = *(apdg1->adsrc_ldap_group + 0);  /* set active LDAP group */
   }
#endif
   adsl_conn1->adsc_pd_http_ctrl = NULL;    /* process data HTTP control */
   adsl_conn1->adsc_util_thread_ctrl = NULL;  /* utility thread control */
   adsl_conn1->adsc_server_conf_1 = adsl_conn1->adsc_gate1->adsc_server_conf_1;
   if (   (adsl_conn1->adsc_server_conf_1)
       && (adsl_conn1->adsc_server_conf_1->inc_no_sdh >= 2)) {
     adsl_conn1->adsrc_sdh_s_1 = (struct dsd_sdh_session_1 *) malloc( adsl_conn1->adsc_server_conf_1->inc_no_sdh * sizeof(struct dsd_sdh_session_1) );  /* array work area server data hook per session */
     memset( adsl_conn1->adsrc_sdh_s_1, 0, adsl_conn1->adsc_server_conf_1->inc_no_sdh * sizeof(struct dsd_sdh_session_1) );
   }
   adsl_conn1->achc_reason_end = NULL;      /* reason end session      */
   /* start receiving client                                           */
   memset( &adsl_conn1->dsc_tc1_client, 0, sizeof(struct dsd_tcp_ctrl_1) );  /* TCP control structure client */
   memcpy( &adsl_conn1->dsc_tc1_client.dsc_soa_conn, adsp_soa, imp_len_soa );  /* address information of connection */
   adsl_conn1->dsc_tc1_client.boc_connected = TRUE;  /* TCP session is connected */
   iml_rc = adsl_conn1->dsc_tc1_client.dsc_tcpco1_1.m_startco_fb(
                imp_socket,
                &dss_tcpcomp_cb1,
                adsl_conn1 );
   if (iml_rc) {                            /* error occured           */
     adsl_conn1->dsc_tc1_client.boc_connected = FALSE;  /* TCP session is not connected */
     D_TCP_CLOSE( imp_socket );
     adsl_gate_1_w1->dsc_critsect.m_enter();  /* critical section      */
     adsl_gate_1_w1->i_session_cur--;       /* count current session   */
     adsl_gate_1_w1->dsc_critsect.m_leave();  /* critical section      */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s client m_startco_fb() failed %d.",
                     adsl_gate_1_w1 + 1, iml_session_no, adsl_conn1->chrc_ineta, iml_rc );
     free( adsl_conn1 );                    /* free memory for connection */
     return;                                /* all done                */
   }

   if (adsg_loconf_1_inuse->imc_tcp_sndbuf) {  /* set TCP SNDBUF       */
     adsl_conn1->dsc_tc1_client.dsc_tcpco1_1.mc_set_sndbuf( adsg_loconf_1_inuse->imc_tcp_sndbuf );
   }
   if (adsg_loconf_1_inuse->imc_tcp_rcvbuf) {  /* set TCP RCVBUF       */
     adsl_conn1->dsc_tc1_client.dsc_tcpco1_1.mc_set_rcvbuf( adsg_loconf_1_inuse->imc_tcp_rcvbuf );
   }
   if (adsg_loconf_1_inuse->boc_tcp_keepalive) {  /* set TCP KEEPALIVE */
     adsl_conn1->dsc_tc1_client.dsc_tcpco1_1.mc_set_keepalive( TRUE );
   }
   adsl_conn1->iec_st_ses = ied_ses_prep_server;  /* status server prepare */
   if (adsl_gate_1_w1->ifunction < 0) {     /* do load-balancing first */
     adsl_conn1->iec_st_ses = ied_ses_reset;  /* status server         */
   }
   adsl_conn1->boc_sdh_started = FALSE;     /* Server-Data-Hooks have been started */
#ifndef NO_WSP_SOCKS_MODE_01
   if (   (adsl_conn1->adsc_server_conf_1 == NULL)  /* configuration server */
       || (adsl_gate_1_w1->imc_no_radius)   /* number of radius server */
       || (adsl_gate_1_w1->inc_no_usgro)    /* number of user groups   */
       || (adsl_gate_1_w1->inc_no_seli)     /* number of server lists  */
       || (adsl_gate_1_w1->adsc_hobwspat3_ext_lib1)) {  /* external library loaded for HOB-WSP-AT3 */
     if (adsl_gate_1_w1->ifunction != DEF_FUNC_L2TP) {  /* set function L2TP UDP connection */
       if (   (adsl_conn1->adsc_server_conf_1 == NULL)  /* no server configured yet */
           || (adsl_conn1->adsc_server_conf_1->boc_sdh_reflect == FALSE)  /* not only Server-Data-Hook */
           || (adsl_gate_1_w1->adsc_hobwspat3_ext_lib1)) {  /* external library loaded for HOB-WSP-AT3 */
         adsl_conn1->iec_st_ses = ied_ses_auth;  /* status authentication */
       }
     }
   }
#endif
#ifdef XYZ1
   bo_st_open = TRUE;                       /* connection open         */
#ifdef B060524
   boc_st_act = FALSE;                      /* util-thread not active  */
#endif
   InitializeCriticalSection( &d_act_critsect );  /* critical section  */
   achl_avl_error = NULL;                   /* clear error code AVL tree */
   EnterCriticalSection( &d_clconn_critsect );
#endif
   iml_rc = adsl_conn1->dsc_critsect.m_create();  /* CriticalSection   */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_create() critical section failed %d.",
                     adsl_gate_1_w1 + 1, iml_session_no, adsl_conn1->chrc_ineta, iml_rc );
   }
   achl_avl_error = NULL;                   /* reset error text        */
   dss_main_critsect.m_enter();             /* enter CriticalSection   */
   do {
     bol1 = m_htree1_avl_search( NULL, &dss_htree1_avl_cntl_conn,
                                 &dsl_htree1_work, &adsl_conn1->dsc_co_sort.dsc_sort_1 );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "m_htree1_avl_search() failed";  /* error code AVL tree */
       break;                               /* do not continue         */
     }
     if (dsl_htree1_work.adsc_found == NULL) break;  /* not found in tree */
     achl_avl_error = "m_htree1_avl_search() new element succeeded - double or illogic";  /* error code AVL tree */
   } while (FALSE);
   if (achl_avl_error == NULL) {            /* no error before         */
     bol1 = m_htree1_avl_insert( NULL, &dss_htree1_avl_cntl_conn,
                                 &dsl_htree1_work, &adsl_conn1->dsc_co_sort.dsc_sort_1 );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "m_htree1_avl_insert() failed";  /* error code AVL tree */
     }
   }
   dss_main_critsect.m_leave();             /* leave CriticalSection   */
   if (achl_avl_error) {                    /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPS110W GATE=%(ux)s SNO=%08d INETA=%s insert sno error %s",
                     adsl_gate_1_w1 + 1, adsl_conn1->dsc_co_sort.imc_sno, adsl_conn1->chrc_ineta, achl_avl_error );
   }
   /* structure for SSL                                                */
   memset( &adsl_conn1->dsc_hlse03s, 0, sizeof(adsl_conn1->dsc_hlse03s) );
   adsl_conn1->dsc_hlse03s.inc_func = DEF_IFUNC_START;  /* set start mode */
   adsl_conn1->dsc_hlse03s.amc_aux = &m_cdaux;  /* subroutine          */
   adsl_conn1->dsc_hlse03s.amc_conn_callback = &m_ssl_conn_cl_compl_se;
   adsl_conn1->dsc_hlse03s.amc_ocsp_start = &m_ocsp_start;
   adsl_conn1->dsc_hlse03s.amc_ocsp_send = &m_ocsp_send;
   adsl_conn1->dsc_hlse03s.amc_ocsp_recv = &m_ocsp_recv;
   adsl_conn1->dsc_hlse03s.amc_ocsp_stop = &m_ocsp_stop;
   adsl_conn1->dsc_hlse03s.ac_config_id = adsl_gate_1_w1->vpc_configid;
   adsl_conn1->dsc_hlse03s.imc_sno = adsl_conn1->dsc_co_sort.imc_sno;  /* session number */
   if (adsl_conn1->imc_trace_level & HL_WT_SESS_SSL_INT) {  /* WSP Trace SSL intern */
     adsl_conn1->dsc_hlse03s.imc_trace_level
       = HL_AUX_WT_ALL                      /* WSP Trace SDH all       */
           | (adsl_conn1->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2));
   }
   adsl_conn1->dsc_hlse03s.ilc_entropy = m_get_epoch_nanoseconds();
   memset( &adsl_conn1->dsc_timer, 0, sizeof(struct dsd_timer_ele) );
   adsl_conn1->dsc_timer.amc_compl = &m_timeout_conn;   /* set routine for timeout */
   adsl_conn1->ilc_timeout = adsl_conn1->dsc_timer.ilcendtime;  /* clear end-time */
#ifdef B090623
   iml1 = m_se_get_conf_timeout( apdg1->vpc_configid );
   if (iml1 <= 0) iml1 = DEF_SSL_TIMEOUT;
   if (   (apdg1->itimeout > 0)             /* set timeout             */
       && (apdg1->itimeout < iml1)) {
     iml1 = apdg1->itimeout;                /* get number of seconds   */
   }
   if (iml1) {                              /* time specified          */
     dsc_timer.ilcwaitmsec = iml1 * 1000;   /* wait in milliseconds    */
     m_time_set( &dsc_timer, FALSE );       /* set timeout now         */
     ilc_timeout = dsc_timer.ilcendtime;    /* save end-time           */
   }
#endif
#ifdef TRACEHLC
   m_check_aclconn1( this, 110 );
#endif

   /* start SSL subroutine                                             */
   m_act_thread_2( adsl_conn1 );            /* activate m_proc_data()  */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T m_acc_acceptcallback() return",
                   __LINE__ );
#endif
   return;                                  /* all done                */
} /* end m_acc_acceptcallback()                                            */

/** error message when TCPCOMP connect failed                          */
static void m_cb_tcpc_conn_err( dsd_tcpcomp *adsp_tcpco, void * vpp_userfld,
   struct sockaddr *adsp_soa, socklen_t imp_len_soa, int imp_current_index, int imp_total_index, int imp_errno ) {
   int        iml_rc;                       /* return code             */
   char       *achl_msg_no;                 /* message number          */
   char       *achl_conn_type;              /* message type of connecttion */
   char       *achl_msg_01;                 /* part one of message     */
   HL_WCHAR   *awcl_server;                 /* name of server          */
   char       *achl_doing;                  /* message what it is doing */
// struct dsd_conn1 *adsl_conn1;            /* connection created      */
   char       chrl_ineta[ LEN_DISP_INETA ];  /* internet-address char  */

//#define ADSL_CONN1_G ((struct dsd_conn1 *) ((char *) adsp_tcpco - offsetof( struct dsd_conn1 , dsc_tcpco1_server )))
#define ADSL_CONN1_G ((struct dsd_conn1 *) vpp_userfld)
// adsl_conn1 = (struct dsd_conn1 *) ADSL_TCP_R->aclconn1;  /* get connection */
   iml_rc = getnameinfo( adsp_soa, imp_len_soa,
                         chrl_ineta, sizeof(chrl_ineta),
                         0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s getnameinfo target server failed with code %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     iml_rc, D_TCP_ERROR );
     strcpy( chrl_ineta, "???" );
   }
   achl_msg_no = "???";                     /* message number          */
   achl_conn_type = "???";                  /* message type of connecttion */
   switch (ADSL_CONN1_G->iec_st_ses) {      /* status server           */
     case ied_ses_wait_conn_s_static:       /* wait for static connect to server */
       achl_msg_no = "HWSPS027W";           /* message number          */
       achl_conn_type = "(static)";         /* message type of connecttion */
       break;
     case ied_ses_wait_conn_s_dynamic:      /* wait for dynamic connect to server */
       achl_msg_no = "HWSPS055W";           /* message number          */
       achl_conn_type = "(dynamic)";        /* message type of connecttion */
       break;
   }
   achl_msg_01 = "";                        /* part one of message     */
   awcl_server = (HL_WCHAR *) L"";
   if (ADSL_CONN1_G->adsc_server_conf_1->inc_len_name > 0) {  /* length of name bytes */
     achl_msg_01 = " server ";              /* part one of message     */
     awcl_server = ADSL_CONN1_G->adsc_server_conf_1->awcc_name;  /* address of name */
   }
   achl_doing = ".";
   if ((imp_current_index + 1) < imp_total_index) {
     achl_doing = " - try next INETA from DNS";  /* set additional text */
   } else if (imp_total_index > 1) {
     achl_doing = " - was last INETA from DNS";  /* set additional text */
   }
   m_hlnew_printf( HLOG_WARN1, "%s GATE=%(ux)s SNO=%08d INETA=%s connect %s to%s%(ux)s INETA %s failed with code %d%s",
                   achl_msg_no,
                   ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                   achl_conn_type, achl_msg_01, awcl_server, chrl_ineta,
                   imp_errno, achl_doing );
#ifndef B140606
#endif
   return;
#ifdef XYZ1
   ADSL_TCP_R->m_post_netw_post_1( DEF_NETW_POST_1_TCPCOMP_CONN_ERR );  /* posted for TCPCOMP connect error */
#endif
#undef ADSL_CONN1_G
} /* end m_cb_tcpc_conn_err()                                               */

/** TCPCOMP connect callback function                                  */
static void m_cb_tcpc_connect( struct dsd_tcpcomp *adsp_tcpco, void *vpp_userfld,
#ifndef B121121
                               struct dsd_target_ineta_1 *, void * ap_free_ti1,  /* INETA to free */
#endif
                               struct sockaddr *adsp_soa, socklen_t imp_len_soa, int imp_error ) {
   int        iml_rc;                       /* return code             */
   char       *achl_msg_no;                 /* message number          */
   char       *achl_conn_type;              /* type of connect         */
   char       *achl_msg_01;                 /* part one of message     */
#ifdef X101214_XX
   enum ied_state_server iel_st_ses;        /* status server           */
#endif
   HL_WCHAR   *awcl_server;                 /* name of server          */
// class clconn1 *adsl_conn1;               /* class created           */
   char       chrl_ineta[ LEN_DISP_INETA ];  /* internet-address char  */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T m_cb_tcpc_connect( %p , %p , %p, %d , %d ) called",
                   __LINE__, adsp_tcpco, vpp_userfld, adsp_soa, imp_len_soa, imp_error );
#endif
//#define ADSL_TCP_R ((class cl_tcp_r *) vpp_userfld)
#define ADSL_CONN1_G ((struct dsd_conn1 *) vpp_userfld)
//   adsl_conn1 = (class clconn1 *) ADSL_TCP_R->aclconn1;  /* get connection */
#ifndef B140607
   if (ap_free_ti1) {                       /* INETA to free           */
     free( ap_free_ti1 );                   /* free passed memory      */
   }
#endif
   if (imp_error) {                         /* called with error       */
     ADSL_CONN1_G->imc_connect_error = imp_error;  /* save connect error */
     return;                                /* all done                */
   }
#ifndef PROG_IS_READY_110813
   if (adsp_soa == NULL) {
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s sockaddr not passed",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta );
     strcpy( chrl_ineta, "???" );
     goto p_help_00;
   }
#endif
#ifndef B150210
   memcpy( &ADSL_CONN1_G->dsc_tc1_server.dsc_soa_conn, adsp_soa, imp_len_soa );
#endif
   iml_rc = getnameinfo( adsp_soa, imp_len_soa,
                         chrl_ineta, sizeof(chrl_ineta),
                         0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s getnameinfo target server failed with code %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     iml_rc, D_TCP_ERROR );
     strcpy( chrl_ineta, "???" );
   }
#ifndef PROG_IS_READY_110813

   p_help_00:
#endif
   achl_msg_no = "???";                     /* message number          */
   achl_conn_type = "???";
   switch (ADSL_CONN1_G->iec_st_ses) {        /* status server           */
     case ied_ses_wait_conn_s_static:       /* wait for static connect to server */
       achl_msg_no = "HWSPS028I";           /* message number          */
       achl_conn_type = "static";           /* type of connect         */
#ifdef X101214_XX
       iel_st_ses = clconn1::ied_ses_start_server_1;  /* status server continue */
#endif
       break;
     case ied_ses_wait_conn_s_dynamic:      /* wait for dynamic connect to server */
       achl_msg_no = "HWSPS060I";           /* message number          */
       achl_conn_type = "dynamic";          /* type of connect         */
#ifdef X101214_XX
       iel_st_ses = clconn1::ied_ses_start_dyn_serv_1;  /* start connection to server part one dynamic */
#endif
       break;
   }
   achl_msg_01 = "";                        /* part one of message     */
   awcl_server = (HL_WCHAR *) L"";
   if (ADSL_CONN1_G->adsc_server_conf_1->inc_len_name > 0) {  /* length of name bytes */
     achl_msg_01 = " server ";              /* part one of message     */
     awcl_server = ADSL_CONN1_G->adsc_server_conf_1->awcc_name;  /* address of name */
   }
   m_hlnew_printf( HLOG_INFO1, "%s GATE=%(ux)s SNO=%08d INETA=%s connect (%s) to%s%(ux)s INETA %s successful",
                   achl_msg_no,
                   ADSL_CONN1_G->adsc_gate1 + 1,
                   ADSL_CONN1_G->dsc_co_sort.imc_sno,
                   ADSL_CONN1_G->chrc_ineta,
                   achl_conn_type, achl_msg_01, awcl_server, chrl_ineta );
   if (adsg_loconf_1_inuse->imc_tcp_sndbuf) {  /* set TCP SNDBUF       */
     adsp_tcpco->mc_set_sndbuf( adsg_loconf_1_inuse->imc_tcp_sndbuf );
   }
   if (adsg_loconf_1_inuse->imc_tcp_rcvbuf) {  /* set TCP RCVBUF       */
     adsp_tcpco->mc_set_rcvbuf( adsg_loconf_1_inuse->imc_tcp_rcvbuf );
   }
   if (adsg_loconf_1_inuse->boc_tcp_keepalive) {  /* set TCP KEEPALIVE */
     adsp_tcpco->mc_set_keepalive( TRUE );
   }
#ifdef NOT_YET_110811
   ADSL_TCP_R->m_did_conn_1();              /* connect successful      */
#endif
#ifndef X101214_XX
   ADSL_CONN1_G->iec_st_ses = ied_ses_start_server_1;  /* status server continue */
#else
   ADSL_CONN1_G->iec_st_ses = iel_st_ses;   /* status server           */
#endif
   if (ADSL_CONN1_G->adsc_wsp_auth_1) {     /* authentication active   */
     ADSL_CONN1_G->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
     ADSL_CONN1_G->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
   }
   if (ADSL_CONN1_G->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
     ADSL_CONN1_G->adsc_int_webso_conn_1->boc_did_connect = TRUE;  /* did connect */
     ADSL_CONN1_G->adsc_int_webso_conn_1->boc_notify = TRUE;  /* notify SDH  */
   }
#ifdef TRACE_TCP_FLOW_01
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20.cpp l%05d before m_tc1_post_netw_post_1() ADSL_CONN1_G->iec_st_ses=%d ADSL_CONN1_G->adsc_wsp_auth_1=%p.",
                   __LINE__, ADSL_CONN1_G->iec_st_ses, ADSL_CONN1_G->adsc_wsp_auth_1 );
#endif
   m_tc1_post_netw_post_1( &ADSL_CONN1_G->dsc_tc1_server, DEF_NETW_POST_1_TCPCOMP_CONN_OK );  /* posted for TCPCOMP connect ok */
#ifdef DEBUG_100830_02
#ifdef TRY_DEBUG_100830_02
   m_hlnew_printf( HLOG_XYZ1, "m_cb_tcpc_connect() l%05d before m_act_thread_1()",
                   __LINE__ );
#endif
#endif
   m_act_thread_1( ADSL_CONN1_G );          /* activate thread for session */
   return;                                  /* all done                */
//#undef ADSL_TCP_R
#undef ADSL_CONN1_G
} /* end m_cb_tcpc_connect()                                              */

/**
 * Send callback function. Resend buffers.
 * @param ads_con corresponding tcpcomp object for nonblocking IO.
 * @param ads_data corresponding condata object.
 */
static void m_cb_tcpc_send( struct dsd_tcpcomp* adsp_tcpco, void * vpp_userfld ) {
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T m_cb_tcpc_send() called",
                   __LINE__ );
#endif
#ifdef DEBUG_120710_01                      /* flow-control send       */
    m_hlnew_printf( HLOG_XYZ1, "DEBUG_120710_01 l%05d m_cb_tcpc_send( %p , %p )",
                    __LINE__, adsp_tcpco, vpp_userfld );
#endif
#ifdef NOT_YET_110811
// ((class cl_tcp_r *) vpp_userfld)->boc_tcpc_act = FALSE;  /* TCPCOMP no more active */
#define ADSL_TCP_R ((class cl_tcp_r *) vpp_userfld)
   if (ADSL_TCP_R->adsc_sdhc1_send == NULL) return;  /* nothing to send */
#ifdef B080407
   ADSL_TCP_R->bo_may_send = FALSE;
#endif
   ADSL_TCP_R->m_send_gather( (struct dsd_sdh_control_1 *) ADSL_TCP_R->adsc_sdhc1_send, TRUE );
#undef ADSL_TCP_R
#ifdef NOT_YET_080407
   int        iml_rc;                       /* return code             */
#ifdef XYZ1
   BOOL       bol1;
   struct dsd_tcp_session *adsl_tcp_se_w1;  /* TCP session             */
   struct dsd_tcp_session *adsl_tcp_se_w2;  /* TCP session             */
#endif

#ifdef TRACEHL1
   m_hl1_printf( "xbipgw16-%05d-T Resend data", __LINE__ );
#endif
#ifdef XYZ1
   adsl_tcp_se_w1 = (struct dsd_tcp_session *) vpp_userfld;
   adsl_tcp_se_w2 = adsl_tcp_se_w1->adsc_tcp_se_p;  /* get partner     */
   if (adsl_tcp_se_w2 == NULL) return;      /* no more partner         */
   bol1 = m_send_data( adsl_tcp_se_w2 );
   if (bol1 == FALSE) return;               /* do not restart receive  */
   adsl_tcp_se_w2->dsc_tcpco1.m_recv();
#endif
#define ADSL_CONNECT_G ((struct dsd_connect *) vpp_userfld)

   p_send_00:                               /* check if something to send */
   if (ADSL_CONNECT_G->imc_no_send_buf_1 == 0) return;  /* so many send buffers */

   p_send_20:                               /* send one buffer         */
   iml_rc = ADSL_CONNECT_G->dsc_tcpco1.m_send( ADSL_CONNECT_G->dsrc_send_buf_1[ 0 ].achc_data_cur,
              ADSL_CONNECT_G->dsrc_send_buf_1[ 0 ].achc_data_end - ADSL_CONNECT_G->dsrc_send_buf_1[ 0 ].achc_data_cur );
   if (iml_rc < 0) {                        /* error occured           */
     return;                                /* nothing more to do      */
   }
   ADSL_CONNECT_G->dsrc_send_buf_1[ 0 ].achc_data_cur += iml_rc;  /* add data sent */
   if (ADSL_CONNECT_G->dsrc_send_buf_1[ 0 ].achc_data_cur < ADSL_CONNECT_G->dsrc_send_buf_1[ 0 ].achc_data_end) {  /* not all data sent */
     ADSL_CONNECT_G->dsc_tcpco1.m_sendnotify();
     return;                                /* all done                */
   }
   m_proc_free( ADSL_CONNECT_G->dsrc_send_buf_1[ 0 ].achc_handle );  /* free buffer */
   dss_critsect_main.m_enter();             /* enter CriticalSection   */
   ADSL_CONNECT_G->imc_no_send_buf_1++;     /* decrement send buffers  */
   if (ADSL_CONNECT_G->imc_no_send_buf_1) {  /* so many send buffers   */
     memmove( &ADSL_CONNECT_G->dsrc_send_buf_1[ 0 ],
              &ADSL_CONNECT_G->dsrc_send_buf_1[ 1 ],
              ADSL_CONNECT_G->imc_no_send_buf_1 * sizeof(ADSL_CONNECT_G->dsrc_send_buf_1[ 0 ]) );
   }
   dss_critsect_main.m_leave();             /* leave CriticalSection   */
   goto p_send_00;                          /* check if something to send */
#undef ADSL_CONNECT_G
#endif
#endif
#ifdef DEBUG_120710_01                      /* flow-control send       */
   m_hlnew_printf( HLOG_XYZ1, "DEBUG_120710_01 l%05d tcpco=%p m_cb_tcpc_send() call m_send_clse_tcp_1()",
                   __LINE__, adsp_tcpco );
#endif
#define ADSL_CONN1_G ((struct dsd_conn1 *) vpp_userfld)
#define ADSL_TC1_G ((struct dsd_tcp_ctrl_1 *) (char *) adsp_tcpco - offsetof( struct dsd_tcp_ctrl_1, dsc_tcpco1_1 ))
   m_send_clse_tcp_1( ADSL_CONN1_G,
                      ADSL_TC1_G,
                      (struct dsd_sdh_control_1 *) ADSL_TC1_G->adsc_sdhc1_send,  /* chain to send */
                      TRUE );
#undef ADSL_TC1_G
#undef ADSL_CONN1_G
} // void m_cdsend(dsd_tcpcomp*, void*)

/**
 * Get receive buffer callback function.
 * @param ads_con corresponding tcpcomp object for nonblocking IO.
 * @param ads_data corresponding condata object.
 * @param aavo_handle pointer to the buffer handle field of the tcpcomp object.
 * @param aach_data pointer to the address field of the tcpcomp object.
 * @param aaim_datalen pointer to the data length field of the tcpcomp object.
 * @return number of bytes that may be received. Must be <= size of field, 0 = receive not allowed
 * pointed to by aach_data.
 */
static int m_cb_tcpc_getbuf(dsd_tcpcomp* ads_con,
               void * vpp_userfld,
               void** aavo_handle,
               char** aach_data,
               int** aaim_datalen)
{
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T m_cb_tcpc_getbuf() called",
                   __LINE__ );
#endif
   *aavo_handle = m_proc_alloc();
#ifdef TRACEHL_STOR_USAGE
   m_proc_mark_1( *aavo_handle, "m_cb_tcpc_getbuf" );
#endif
   *aach_data = (char *) *aavo_handle + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1);
   *aaim_datalen = (int *) *aavo_handle;
   return LEN_TCP_RECV - sizeof(struct dsd_sdh_control_1) - sizeof(struct dsd_gather_i_1);
} // int m_cb_tcpc_getbuf(dsd_tcpcomp*, void*, void**, char**,  int**)

/**
 * Receive callback function.
 * @param ads_con corresponding tcpcomp object for nonblocking IO.
 * @param ads_data corresponding condata object.
 * @param avo_handle handle of buffer.
 * @return TRUE, if more data should be received, otherwise FALSE.
 */
static int m_cb_tcpc_recv( class dsd_tcpcomp* adsp_tcpcomp,
             void * vpp_userfld,
             void * avo_handle )
{
   int        iml_len_recv;                 /* length received         */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T m_cb_tcpc_recv() called",
                   __LINE__ );
#endif
#define ADSL_CONN1_G ((struct dsd_conn1 *) vpp_userfld)  /* pointer on connection */
   iml_len_recv = 0;                        /* length received         */
   if (avo_handle) {                        /* buffer passed           */
     iml_len_recv = *((int *) avo_handle);  /* get length passed       */
   }
#ifdef TRACEHL_101209
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T m_cb_tcpc_recv() called iml_len_recv=%d/0X%p.",
                   __LINE__, iml_len_recv, iml_len_recv );
#endif
   if (adsp_tcpcomp == &ADSL_CONN1_G->dsc_tc1_client.dsc_tcpco1_1) {  /* connection object client */
     return m_client_recv_compl( ADSL_CONN1_G,
                                 (struct dsd_sdh_control_1 *) avo_handle,
                                 iml_len_recv );
   }
   return m_server_recv_compl( ADSL_CONN1_G,
                               (struct dsd_sdh_control_1 *) avo_handle,
                               iml_len_recv );
#undef ADSL_CONN1_G
} /* end m_cb_tcpc_recv()                                              */

/**
 * Error callback function.
 * @param ads_con corresponding tcpcomp object for nonblocking IO.
 * @param ads_data corresponding condata object.
 * @param im_errno error number.
 * @param im_where Error location. (See tcpcomp::ERRORAT_XXXX flags)
 */
static void m_cb_tcpc_error( dsd_tcpcomp* adsp_tcpco,
               void * vpp_userfld,
               char * achp_error,
               int imp_error,
               int imp_where )
{
// class clconn1 *adsl_conn_w1;             /* connection              */
   char       *achl_cl_se;                  /* client or server        */

#define ADSL_CONN1_G ((struct dsd_conn1 *) vpp_userfld)
   achl_cl_se = "client";                   /* client or server        */
   if (adsp_tcpco != &ADSL_CONN1_G->dsc_tc1_client.dsc_tcpco1_1) {  /* structure to receive client */
     achl_cl_se = "server";                 /* client or server        */
   }
   m_hlnew_printf( HLOG_XYZ1, "HWSPS160W GATE=%(ux)s SNO=%08d INETA=%s %s TCP error %s %d %d.",
                   ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                   achl_cl_se,
                   achp_error, imp_error, imp_where );
#undef ADSL_CONN1_G
} /* end m_cb_tcpc_error()                                             */

/** TCPCOMP cleanup callback function                                  */
static void m_cb_tcpc_cleanup( struct dsd_tcpcomp *adsp_tcpco, void *vpp_userfld ) {
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T m_cb_tcpc_cleanup() called",
                   __LINE__ );
#endif
#ifdef TRACE_090506
#define ADSL_CONNECT_G ((class clconn1 *) ((class cl_tcp_r *) vpp_userfld)->aclconn1)
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T m_cb_tcpc_cleanup() adsp_tcpco=%p vpp_userfld=%p ADSL_CONNECT_G=%p SNO=%08d.",
                   __LINE__, adsp_tcpco, vpp_userfld, ADSL_CONNECT_G, ADSL_CONNECT_G->dsc_co_sort.imc_sno );
#undef ADSL_CONNECT_G
#endif
#define ADSL_CONN1_G ((struct dsd_conn1 *) vpp_userfld)
// ((class cl_tcp_r *) vpp_userfld)->boc_tcpc_act = FALSE;  /* TCPCOMP no more active */
#ifdef XYZ1
#define ADSL_TCP_R ((class cl_tcp_r *) vpp_userfld)
   ADSL_TCP_R->m_cleanup_1();               /* TCPCOMP no more active */
   ADSL_TCP_R->m_post_netw_post_1( DEF_NETW_POST_1_TCPCOMP_CLEANUP );  /* posted for TCPCOMP cleanup */
#undef ADSL_TCP_R
#endif
#define ADSL_TC1_G ((struct dsd_tcp_ctrl_1 *) (char *) adsp_tcpco - offsetof( struct dsd_tcp_ctrl_1, dsc_tcpco1_1 ))
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SNECLEAN", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                        "l%05d cleanup received from TCP component %p.",
                                        __LINE__, ADSL_TC1_G );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   ADSL_TC1_G->boc_connected = FALSE;       /* TCP session no more connected */
// m_act_thread_1( ADSL_CONNECT_G );        /* activate session        */
#ifndef B140612
   if (ADSL_TC1_G == &ADSL_CONN1_G->dsc_tc1_server) {  /* TCP control structure server */
// to-do 13.06.14 KB
// move to subroutine m_conn_server_end()
// as this also needs to be called from HOB-TUN
     ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
     do {                                   /* pseudo-loop             */
       if (ADSL_CONN1_G->iec_st_ses == ied_ses_conn) {  /* server is connected */
         if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
           /* do not set when dynamic server                           */
           if (   (ADSL_CONN1_G->adsc_server_conf_1 == NULL)
               || (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic == FALSE)) {
             ADSL_CONN1_G->achc_reason_end = "server TCP end";
           }
         }
         if (ADSL_CONN1_G->chrc_server_error[0] == 0) {   /* no error message yet */
           sprintf( ADSL_CONN1_G->chrc_server_error,  /* display server error */
                    "TCP end" );
         }
         ADSL_CONN1_G->iec_st_ses = ied_ses_rec_close;  /* received close */
         break;
       }
       if (ADSL_CONN1_G->iec_st_ses != ied_ses_wait_conn_s_static) break;  /* wait for static connect to server */
       if (ADSL_CONN1_G->adsc_wsp_auth_1) {  /* authentication active  */
         ADSL_CONN1_G->adsc_wsp_auth_1->imc_connect_error = ADSL_CONN1_G->imc_connect_error;
         ADSL_CONN1_G->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
         ADSL_CONN1_G->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
         ADSL_CONN1_G->iec_st_ses = ied_ses_auth;  /* status authentication */
         break;;
       }
       if (ADSL_CONN1_G->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
         ADSL_CONN1_G->adsc_int_webso_conn_1->imc_connect_error = ADSL_CONN1_G->imc_connect_error;
         ADSL_CONN1_G->adsc_int_webso_conn_1->boc_did_connect = TRUE;  /* did connect */
         ADSL_CONN1_G->adsc_int_webso_conn_1->boc_notify = TRUE;  /* notify SDH */
         ADSL_CONN1_G->iec_st_ses = ied_ses_conn;  /* server is connected */
         break;
       }
       ADSL_CONN1_G->iec_st_ses = ied_ses_error_conn;  /* status server error */
       if (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic == FALSE) {  /* not dynamically allocated */
         break;
       }
       ADSL_CONN1_G->iec_st_ses = ied_ses_error_co_dyn;  /* status server error */
     } while (FALSE);
#ifndef TCPCOMP_V02
     m_act_thread_1( ADSL_CONN1_G );        /* activate session        */
#endif
#ifdef TCPCOMP_V02
// to-do 31.07.15 KB - TCPCOMP_V02 simple else
   } else {                                 /* is client connection    */
     if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
       ADSL_CONN1_G->achc_reason_end = "client TCP end";
     }
     ADSL_CONN1_G->iec_st_cls = ied_cls_rec_close;  /* received close  */
#endif
   }
#endif
#ifdef TCPCOMP_V02
   m_act_thread_1( ADSL_CONN1_G );          /* activate session        */
#endif
   m_tc1_post_netw_post_1( ADSL_TC1_G, DEF_NETW_POST_1_TCPCOMP_CLEANUP );  /* posted for TCPCOMP cleanup */
#undef ADSL_TC1_G
#undef ADSL_CONN1_G
} /* end m_cb_tcpc_cleanup()                                           */

#ifdef B121121
/** TCPCOMP free target INETA                                          */
static void m_cb_tcpc_free_target_ineta( dsd_tcpcomp *adsp_tcpcomp, void *vpp_userfld,
                                         const struct dsd_target_ineta_1 *adsp_target_ineta_1 ) {
#ifdef NOT_YET_110811
#ifdef XYZ1
15.11.10 KB is const struct dsd_target_ineta_1 *adsp_target_ineta_1 correct ???
#endif
   class clconn1 *adsl_conn_w1;             /* connection              */

   adsl_conn_w1 = (class clconn1 *) ((class cl_tcp_r *) vpp_userfld)->aclconn1;  /* address of calling */
   if (adsl_conn_w1->adsc_server_conf_1 == NULL) return;
   if (adsl_conn_w1->adsc_server_conf_1->inc_function != DEF_FUNC_DIR) return;
   if (adsl_conn_w1->adsc_server_conf_1->boc_dynamic) return;  /* dynamicly allocated */
   if (adsl_conn_w1->adsc_server_conf_1->boc_dns_lookup_before_connect == FALSE) return;  /* needs to solve INETA before connect */
   if (adsp_target_ineta_1 == adsl_conn_w1->adsc_server_conf_1->adsc_server_ineta) return;
#ifdef B101115
   free( adsp_target_ineta_1 );             /* free the memory         */
#else
   free( (void *) adsp_target_ineta_1 );    /* free the memory         */
#endif
#endif
   return;
} /* end m_cb_tcpc_free_target_ineta()                                 */
#endif

/** post network resource for TCP connection                           */
static void m_tc1_post_netw_post_1( struct dsd_tcp_ctrl_1 *adsp_tc1, int imp_select ) {
   int    iml_rc;                           /* return code             */
   int    iml_error;                        /* error code              */
   struct dsd_netw_post_1 *adsl_netw_post_1;  /* structure to post from network callback */

   adsl_netw_post_1 = adsp_tc1->adsc_netw_post_1;  /* get structure to post from network callback */
   if (adsl_netw_post_1 == NULL) return;    /* nothing to do         */
   if ((imp_select & adsl_netw_post_1->imc_select) == 0) return;  /* not selected */
   adsp_tc1->adsc_netw_post_1 = NULL;       /* remove structure to post from network callback */
   adsl_netw_post_1->boc_posted = TRUE;     /* event has been posted */
   iml_rc = adsl_netw_post_1->adsc_event->m_post( &iml_error );  /* event for posted */
   if (iml_rc < 0) {                     /* error occured           */
     m_hl1_printf( "xxxxxxxr-%05d-W m_tc1_post_netw_post_1() m_post Return Code %d Error %d.",
                   __LINE__, iml_rc, iml_error );
   }
} /* end m_tc1_post_netw_post_1()                                      */

/** close TCP connection                                               */
static void m_tc1_close_1( struct dsd_tcp_ctrl_1 *adsp_tc1, struct dsd_hco_wothr *adsp_hco_wothr ) {

#define ADSL_NETW_POST_1 ((struct dsd_netw_post_1 *) adsp_hco_wothr->vprc_aux_area)

   memset( ADSL_NETW_POST_1, 0, sizeof(struct dsd_netw_post_1) );  /* structure to post from network callback */
   ADSL_NETW_POST_1->adsc_event = &adsp_hco_wothr->dsc_event;  /* event to be posted */
   ADSL_NETW_POST_1->imc_select = DEF_NETW_POST_1_TCPCOMP_CLEANUP;  /* select the events */
   adsp_tc1->adsc_netw_post_1 = ADSL_NETW_POST_1;  /* structure to post from network callback */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_tc1_close_1() call m_end_session() TCPCOMP %p.",
                   __LINE__, &adsp_tc1->dsc_tcpco1_1 );
#endif
   adsp_tc1->dsc_tcpco1_1.m_end_session();  /* close TCP session       */
   if (adsp_tc1->boc_connected == FALSE) {  /* TCP session no more connected */
     ADSL_NETW_POST_1->boc_posted = TRUE;   /* no need to post event   */
   }
   while (ADSL_NETW_POST_1->boc_posted == FALSE) {  /* event has not been posted */
     m_hco_wothr_wait( adsp_hco_wothr );    /* wait for an event       */
   }
#undef ADSL_NETW_POST_1
} /* end m_tc1_close_1()                                               */

#ifdef B140810
// 07.02.14 KB - move to xiipgw08-tcp.cpp
/** Connect Callback Server-Side SSL                                   */
static void m_ssl_conn_cl_compl_se( struct dsd_hl_ssl_ccb_1 *adsp_ccb_1 ) {
#ifdef NOT_YET_110811
   int        inl1, inl2;                   /* working variables       */
   char       *achl1, *achl2;               /* working variables       */
   BOOL       bol1;                         /* working variable        */
   int        inl_len_cert;                 /* length of certificate n */
   int        iml_ns_prot, iml_ns_ci_sui, iml_ns_keyexch, iml_ns_ci_alg,
              iml_ns_ci_type, iml_ns_mac, iml_ns_auth, iml_ns_compr;
   en_at_claddrtype iel_claddrtype;         /* type of address         */
   void *     avol_client_netaddr;          /* address net-addr        */
   struct dsd_auxf_1 *adsl_auxf_1_1;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_2;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_3;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_dn;       /* aux ext fi dn distinguished name */
   struct dsd_auxf_1 *adsl_auxf_1_ce;       /* aux ext fi ce certificate */
   char       byrlwork1[ 112 + DEF_MAX_LEN_CERT_NAME + 1 ];
   char       byrlwork2[ 112 + DEF_MAX_LEN_CERT_NAME + 1 ];
   char       byrlwork_ssl[ 256 ];          /* for text cipher         */
   /* 04.08.04 KB + Joachim Frank */
   char       byrl_cout[1024];
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_ssl_conn_cl_compl_se called" );
#endif
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) adsp_ccb_1->vpc_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#ifdef NOT_YET_110813
#ifdef B121009
#define hssl_QueryInfo ((HSSL_QUERYINFO *) adsp_ccb_1->ac_conndata)
#endif
#define ADSL_SSL_QUERY_INFO ((struct dsd_ssl_query_info *) adsp_ccb_1->ac_conndata)
#define AUCL_CONNDATA ((unsigned char *) adsp_ccb_1->ac_conndata)
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_ssl_conn_cl_compl_se called adsp_ccb_1=%p", adsp_ccb_1 );
   m_hlnew_printf( HLOG_XYZ1, "-- vpc_userfld=%p ac_conndata=%p achc_fingerprint=%p achc_certificate=%p inc_len_certificate=%d",
                   adsp_ccb_1->vpc_userfld, adsp_ccb_1->ac_conndata, adsp_ccb_1->achc_fingerprint, adsp_ccb_1->achc_certificate, adsp_ccb_1->inc_len_certificate );
// partners name is Big-endian unicode. For simplicity we assume Latin
// and convert this unicode to a char string.
   char szString[512];
   int j, i;
         j=0;
         for (i = 0; i < (hssl_QueryInfo->hssl_byPartnerNameLength*2); i= i+2)
         {
       szString[j++] = hssl_QueryInfo->hssl_byPartnerName[i+1];
         }
         szString[j++] = 0x0;
   m_hlnew_printf( HLOG_XYZ1, "partner-id %s", szString );
#endif
   if (ADSL_CONN1_G->boc_st_sslc) {         /* ssl handshake complete  */
     m_hlnew_printf( HLOG_XYZ1, "HWSPS00nW SSL handshake complete double" );
   }
   adsl_auxf_1_1 = ADSL_CONN1_G->adsc_auxf_1;  /* anchor of extensions   */
   adsl_auxf_1_3 = NULL;                    /* no previous yet         */
   while (adsl_auxf_1_1) {                  /* loop over chain         */
     adsl_auxf_1_2 = adsl_auxf_1_1;         /* save this entry         */
     adsl_auxf_1_1 = adsl_auxf_1_1->adsc_next;  /* get next in chain   */
     bol1 = FALSE;                          /* is not double           */
     if (adsl_auxf_1_2->iec_auxf_def == ied_auxf_certname) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPS071W GATE=%(ux)s SNO=%08d INETA=%s Certificate Name (dn) came double",
                       (WCHAR *) (ADSL_CONN1_G->adsc_gate1 + 1),
                       ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       ADSL_CONN1_G->chrc_ineta );
       bol1 = TRUE;                         /* remove this entry       */
     } else if (adsl_auxf_1_2->iec_auxf_def == ied_auxf_certificate) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPS072W GATE=%(ux)s SNO=%08d INETA=%s Certificate came double",
                       (WCHAR *) (ADSL_CONN1_G->adsc_gate1 + 1),
                       ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       ADSL_CONN1_G->chrc_ineta );
       bol1 = TRUE;                         /* remove this entry       */
     }
     if (bol1) {                            /* remove this entry       */
       if (adsl_auxf_1_3 == NULL) {         /* is first in chain       */
         ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_1;
       } else {                             /* in middle of chain      */
         adsl_auxf_1_3->adsc_next = adsl_auxf_1_1;
       }
       free( adsl_auxf_1_2 );               /* free this entry         */
     } else {
       adsl_auxf_1_3 = adsl_auxf_1_2;       /* save previous           */
     }
   }
#ifdef B121009
   inl_len_cert = hssl_QueryInfo->hssl_byPartnerNameLength;
#endif
   inl_len_cert = ADSL_SSL_QUERY_INFO->ucc_partner_name_length;
   if (   (inl_len_cert < 0)
       || (inl_len_cert > DEF_MAX_LEN_CERT_NAME)) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPS073W GATE=%(ux)s SNO=%08d INETA=%s length of certificate name invalid %d",
                     (WCHAR *) (ADSL_CONN1_G->adsc_gate1 + 1),
                     ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta,
                     inl_len_cert );
     inl_len_cert = 0;
   }
   byrlwork_ssl[0] = 0;                     /* no data about handshake */
   if (adsg_loconf_1_inuse->inc_network_stat >= 2) {
     iml_ns_prot = *(AUCL_CONNDATA + 48);
     if (iml_ns_prot >= (sizeof(achrs_ssl_prot) / sizeof(achrs_ssl_prot[0]))) {
       iml_ns_prot = 0;                     /* make unknown            */
     }
     iml_ns_ci_sui = *(AUCL_CONNDATA + 51);
     if (iml_ns_ci_sui >= (sizeof(achrs_ssl_ci_prot) / sizeof(achrs_ssl_ci_prot[0]))) {
       iml_ns_ci_sui = sizeof(achrs_ssl_ci_prot) / sizeof(achrs_ssl_ci_prot[0]) - 1;
     }
     iml_ns_keyexch = *(AUCL_CONNDATA + 52);
     if (iml_ns_keyexch >= (sizeof(achrs_ssl_keyexch) / sizeof(achrs_ssl_keyexch[0]))) {
       iml_ns_keyexch = 0;                  /* make unknown            */
     }
     iml_ns_ci_alg = *(AUCL_CONNDATA + 53);
     if (iml_ns_ci_alg >= (sizeof(achrs_ssl_ci_alg) / sizeof(achrs_ssl_ci_alg[0]))) {
       iml_ns_ci_alg = 0;                   /* make unknown            */
     }
     iml_ns_ci_type = *(AUCL_CONNDATA + 54);
     if (iml_ns_ci_type >= (sizeof(achrs_ssl_ci_type) / sizeof(achrs_ssl_ci_type[0]))) {
       iml_ns_ci_type = (sizeof(achrs_ssl_ci_type) / sizeof(achrs_ssl_ci_type[0])) - 1;
     }
     iml_ns_mac = *(AUCL_CONNDATA + 55);
     if (iml_ns_mac >= (sizeof(achrs_ssl_ci_alg) / sizeof(achrs_ssl_ci_alg[0]))) {
       iml_ns_mac = 0;                      /* make unknown            */
     }
     iml_ns_auth = *(AUCL_CONNDATA + 57) & 3;
     iml_ns_auth |= 1;                      /* always server authentication */
     iml_ns_compr = *(AUCL_CONNDATA + 49);
     if (iml_ns_compr) {                    /* is not none             */
       if (iml_ns_compr == 0XF4) {          /* is defined              */
         iml_ns_compr = 1;
       } else {
         iml_ns_compr = 2;                  /* make unknown            */
       }
     }
     sprintf( byrlwork_ssl, " - protocol:%s cipher-suite:%s key-exchange-mode:%s"
              " cipher-algorithm:%s cipher-type:%s MAC-algorithm:%s authentication:%s compression:%s",
              achrs_ssl_prot[ iml_ns_prot ],
              achrs_ssl_ci_prot[ iml_ns_ci_sui ],
              achrs_ssl_keyexch[ iml_ns_keyexch ],
              achrs_ssl_ci_alg[ iml_ns_ci_alg ],
              achrs_ssl_ci_type[ iml_ns_ci_type ],
              achrs_ssl_mac[ iml_ns_mac ],
              achrs_ssl_auth[ iml_ns_auth ],
              achrs_ssl_compr[ iml_ns_compr ] );
   }
#ifdef B121009
   if (hssl_QueryInfo->hssl_byPartnerNameLength == 0) {
     achl1 = "SSL logon - no client certificate";
     achl2 = achl1;
     goto psussl80;
   }
#endif
   if (ADSL_SSL_QUERY_INFO->ucc_partner_name_length == 0) {
     achl1 = "SSL logon - no client certificate";
     achl2 = achl1;
     goto psussl80;
   }
   adsl_auxf_1_dn = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                                  + sizeof(int)
                                                  + (inl_len_cert + 1) * sizeof(WCHAR) );
   adsl_auxf_1_dn->iec_auxf_def = ied_auxf_certname;  /* name from certificate */
   *((int *) (adsl_auxf_1_dn + 1)) = inl_len_cert;  /* set length name  */
   inl1 = sprintf( byrlwork1, "SSL logon - " );
   if (adsp_ccb_1->achc_fingerprint) {
     inl1 += sprintf( &byrlwork1[inl1], "fingerprint: " );
     inl2 = 0;
     do {
       inl1 += sprintf( &byrlwork1[inl1], "%02X",
                        *((unsigned char *) adsp_ccb_1->achc_fingerprint + inl2) );

       if (inl2 % 2) byrlwork1[ inl1++ ] = ' ';
       inl2++;                              /* next character          */
     } while (inl2 < DEF_SSL_LEN_FINGERPRINT);
     inl1 += sprintf( &byrlwork1[inl1], "- " );  /* separate following text */
   }
   inl1 += sprintf( &byrlwork1[inl1], "DN (name from certificate): " );
   achl1 = &byrlwork1[inl1];                /* name comes here         */
   memcpy( byrlwork2, byrlwork1, inl1 );
   achl2 = &byrlwork2[inl1];                /* name comes here         */
   for (inl1 = 0; inl1 < inl_len_cert; inl1++ ) {
#ifdef B121009
     inl2 = GHHW( *((unsigned short int *) &hssl_QueryInfo->hssl_byPartnerName[ inl1 * 2 ]) );
#endif
     inl2 = GHHW( *((unsigned short int *) &ADSL_SSL_QUERY_INFO->ucrc_partner_name[ inl1 * 2 ]) );
     *((WCHAR *) (((int *) (adsl_auxf_1_dn + 1)) + 1) + inl1) = inl2;
     if (inl2 < 0X0100) {
       *achl1++ = ucrg_tab_819_to_850[ inl2 ];
       *achl2++ = (char) inl2;
     } else {
       *achl1++ = '?';
       *achl2++ = '?';
     }
   }
   *((WCHAR *) (((int *) (adsl_auxf_1_dn + 1)) + 1) + inl_len_cert) = 0;
   adsl_auxf_1_dn->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain */
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_dn;  /* set new chain       */
   *achl1 = 0;                              /* make zero-terminated    */
   achl1 = byrlwork1;
   *achl2 = 0;                              /* make zero-terminated    */
   achl2 = byrlwork2;
   if (adsp_ccb_1->inc_len_certificate == 0) goto psussl80;  /* write message */
   /* store certificate                                                */
   adsl_auxf_1_ce = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                                  + sizeof(int)
                                                  + adsp_ccb_1->inc_len_certificate );
   adsl_auxf_1_ce->iec_auxf_def = ied_auxf_certificate;  /* certificate */
   *((int *) (adsl_auxf_1_ce + 1)) = adsp_ccb_1->inc_len_certificate;  /* set length certificate */
   memcpy( (int *) (adsl_auxf_1_ce + 1) + 1,
           adsp_ccb_1->achc_certificate,
           adsp_ccb_1->inc_len_certificate );
   adsl_auxf_1_ce->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain */
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_ce;  /* set new chain       */

   psussl80:                                /* write message           */
#ifdef B060506
   /* 04.08.04 KB + Joachim Frank */
// printf( "%S INETA=%s %s\n",
//         (WCHAR *) (auclconn11->adsc_gate1 + 1), auclconn11->chrc_ineta, au1 );
   _snprintf( byrl_cout, sizeof(byrl_cout), "HWSPS080I GATE=%S SNO=%08d INETA=%s %s%s\n",
              (WCHAR *) (ADSL_CONN1_G->adsc_gate1 + 1),
              ADSL_CONN1_G->dsc_co_sort.imc_sno,
              ADSL_CONN1_G->chrc_ineta, achl1, byrlwork_ssl );
#ifndef TRACE_PRINTF
   cout << byrl_cout;
#else
   EnterCriticalSection( &dss_critsect_printf );
   printf( "%s", (char *) byrl_cout );
   LeaveCriticalSection( &dss_critsect_printf );
#endif
#endif
   m_hlnew_printf( HLOG_XYZ1, "HWSPS080I GATE=%(ux)s SNO=%08d INETA=%s %s%s",
                   (WCHAR *) (ADSL_CONN1_G->adsc_gate1 + 1),
                   ADSL_CONN1_G->dsc_co_sort.imc_sno,
                   ADSL_CONN1_G->chrc_ineta, achl2, byrlwork_ssl );
#ifdef WORK051119
   /* start authentication                                             */
   if (ADSL_CONN1_G->adsc_gate1->ad_auth_startup) {  /* must do authentication */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_XYZ1, "call ADSL_CONN1_G->dcl_wsat1_1 before" );
#endif
#ifdef NOTYET050819
     ADSL_CONN1_G->dcl_wsat1_1 = (*ADSL_CONN1_G->adsc_gate1->ad_authlib1->am_constr)
       ( ADSL_CONN1_G->adsc_gate1->ad_auth_startup,
         (HL_WCHAR *) (((int *) (adsl_auxf_1_1 + 1)) + 1),
         inl_len_cert,
         ADSL_CONN1_G->adsc_gate1->ienatfa,
#ifndef HL_IPV6
         en_atca_IPV4,
         (void *) &ADSL_CONN1_G->dcl_tcp_r_c.dclient1
#else
         en_atca_IPV6,
         (void *) &ADSL_CONN1_G->dcl_tcp_r_c.uncl1
#endif
       );
#endif
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_XYZ1, "call ADSL_CONN1_G->dcl_wsat1_1 after" );
#endif
   }
   if (   (ADSL_CONN1_G->adsc_server_conf_1)
       && (ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def != ied_scp_http)
       && (   (ADSL_CONN1_G->adsc_gate1->imc_no_radius)  /* authenticate Radius */
           || (ADSL_CONN1_G->adsc_gate1->inc_no_usgro))) {  /* authenticate usgr */
#ifndef HL_IPV6
     iel_claddrtype = en_atca_IPV4;
     avol_client_netaddr = (void *) &ADSL_CONN1_G->dcl_tcp_r_c.dclient1;
#else
     iel_claddrtype = en_atca_IPV6;
     avol_client_netaddr = (void *) &ADSL_CONN1_G->dcl_tcp_r_c.uncl1;
     if (bog_ipv6 == FALSE) {
       iel_claddrtype = en_atca_IPV4;
     }
#endif
     ADSL_CONN1_G->adsc_radqu = new dsd_radius_query( ADSL_CONN1_G,
                                                      ADSL_CONN1_G->adsc_gate1->imc_no_radius,
                                                      ADSL_CONN1_G->adsc_gate1->inc_no_usgro,
                                                      (HL_WCHAR *) (((int *) (adsl_auxf_1_1 + 1)) + 1),
                                                      inl_len_cert,
                                                      &(ADSL_CONN1_G->adsc_gate1->dsc_radius_conf),
                                                      iel_claddrtype,
                                                      avol_client_netaddr );
   }
#endif
#endif
   ADSL_CONN1_G->boc_st_sslc = TRUE;        /* ssl handshake complete  */
#ifdef NOT_YET_110813
#undef AUCL_CONNDATA
#undef hssl_QueryInfo
#endif
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_ssl_conn_cl_compl_se()                                      */

#ifdef CSSSL_060620
/** Connect Callback Client-Side SSL                                   */
static void m_ssl_conn_cl_compl_cl( struct dsd_hl_ssl_ccb_1 *adsp_ccb_1 ) {
#ifdef NOT_YET_110811
   int        iml1, iml2;                   /* working variables       */
   char       *achl1, *achl2;               /* working variables       */
#ifdef XYZ1
   BOOL       bol1;                         /* working variable        */
#endif
   BOOL       bol_not_valid_dn;             /* check DN                */
   int        iml_len_msg_ssl;              /* length of SSL message   */
   int        iml_len_cert;                 /* length of certificate n */
   int        iml_ns_prot, iml_ns_ci_sui, iml_ns_keyexch, iml_ns_ci_alg,
              iml_ns_ci_type, iml_ns_mac, iml_ns_auth, iml_ns_compr;
#ifdef XYZ1
   en_at_claddrtype iel_claddrtype;         /* type of address         */
   void *     avol_client_netaddr;          /* address net-addr        */
   struct dsd_auxf_1 *adsl_auxf_1_1;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_2;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_3;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_dn;       /* aux ext fi dn distinguished name */
   struct dsd_auxf_1 *adsl_auxf_1_ce;       /* aux ext fi ce certificate */
#endif
   char       byrlwork1[ 112 + DEF_MAX_LEN_CERT_NAME + 1 ];
   char       byrlwork_ssl[ 512 ];          /* for text cipher         */
#ifdef XYZ1
   /* 04.08.04 KB + Joachim Frank */
   char       byrl_cout[1024];
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_ssl_conn_cl_compl_cl called" );
#endif
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) adsp_ccb_1->vpc_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#ifdef B121009
#define hssl_QueryInfo ((HSSL_QUERYINFO *) adsp_ccb_1->ac_conndata)
#endif
#define ADSL_SSL_QUERY_INFO ((struct dsd_ssl_query_info *) adsp_ccb_1->ac_conndata)
#define AUCL_CONNDATA ((unsigned char *) adsp_ccb_1->ac_conndata)
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_ssl_conn_cl_compl_cl l%05d called adsp_ccb_1=%p", __LINE__, adsp_ccb_1 );
   m_hlnew_printf( HLOG_XYZ1, "-- vpc_userfld=%p ac_conndata=%p achc_fingerprint=%p achc_certificate=%p inc_len_certificate=%d",
                   adsp_ccb_1->vpc_userfld, adsp_ccb_1->ac_conndata, adsp_ccb_1->achc_fingerprint, adsp_ccb_1->achc_certificate, adsp_ccb_1->inc_len_certificate );
// partners name is Big-endian unicode. For simplicity we assume Latin
// and convert this unicode to a char string.
   char szString[512];
   int j, i;
         j=0;
         for (i = 0; i < (hssl_QueryInfo->hssl_byPartnerNameLength*2); i= i+2)
         {
       szString[j++] = hssl_QueryInfo->hssl_byPartnerName[i+1];
         }
         szString[j++] = 0x0;
   m_hlnew_printf( HLOG_XYZ1, "partner-id %s", szString );
#endif
#ifdef DEBUG_100809
   m_hlnew_printf( HLOG_XYZ1, "m_ssl_conn_cl_compl_cl l%05d called adsp_ccb_1=%p", __LINE__, adsp_ccb_1 );
   m_hlnew_printf( HLOG_XYZ1, "-- vpc_userfld=%p ac_conndata=%p achc_fingerprint=%p achc_certificate=%p inc_len_certificate=%d",
                   adsp_ccb_1->vpc_userfld, adsp_ccb_1->ac_conndata, adsp_ccb_1->achc_fingerprint, adsp_ccb_1->achc_certificate, adsp_ccb_1->inc_len_certificate );
// partners name is Big-endian unicode. For simplicity we assume Latin
// and convert this unicode to a char string.
   char szString[512];
   int j, i;
         j=0;
         for (i = 0; i < (hssl_QueryInfo->hssl_byPartnerNameLength*2); i= i+2)
         {
       szString[j++] = hssl_QueryInfo->hssl_byPartnerName[i+1];
         }
         szString[j++] = 0x0;
   m_hlnew_printf( HLOG_XYZ1, "partner-id %s", szString );
#endif
   if (ADSL_CONN1_G->adsc_csssl_oper_1 == NULL) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPS00nW Client-Side SSL handshake, but SSL not active" );
     return;
   }
   bol_not_valid_dn = adsg_loconf_1_inuse->boc_csssl_usage_dn;  /* check DN - TRUE if check necessary */
   if (ADSL_CONN1_G->adsc_csssl_oper_1->boc_sslc) {  /* ssl handshake complete */
     m_hlnew_printf( HLOG_XYZ1, "HWSPS00nW Client-Side SSL handshake complete double" );
   }
#ifdef B121009
   iml_len_cert = hssl_QueryInfo->hssl_byPartnerNameLength;
#endif
   iml_len_cert = ADSL_SSL_QUERY_INFO->ucc_partner_name_length;
   if (   (iml_len_cert < 0)
       || (iml_len_cert > DEF_MAX_LEN_CERT_NAME)) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPSxxxW GATE=%(ux)s SNO=%08d INETA=%s length of certificate name invalid %d",
                     ADSL_CONN1_G->adsc_gate1 + 1,
                     ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta,
                     iml_len_cert );
     iml_len_cert = 0;
   }
   byrlwork_ssl[0] = 0;                     /* no data about handshake */
   iml_len_msg_ssl = 0;                     /* length of SSL message   */
   if (adsg_loconf_1_inuse->inc_network_stat >= 2) {
     iml_ns_prot = *(AUCL_CONNDATA + 48);
     if (iml_ns_prot >= (sizeof(achrs_ssl_prot) / sizeof(achrs_ssl_prot[0]))) {
       iml_ns_prot = 0;                     /* make unknown            */
     }
     iml_ns_ci_sui = *(AUCL_CONNDATA + 51);
     if (iml_ns_ci_sui >= (sizeof(achrs_ssl_ci_prot) / sizeof(achrs_ssl_ci_prot[0]))) {
       iml_ns_ci_sui = sizeof(achrs_ssl_ci_prot) / sizeof(achrs_ssl_ci_prot[0]) - 1;
     }
     iml_ns_keyexch = *(AUCL_CONNDATA + 52);
     if (iml_ns_keyexch >= (sizeof(achrs_ssl_keyexch) / sizeof(achrs_ssl_keyexch[0]))) {
       iml_ns_keyexch = 0;                  /* make unknown            */
     }
     iml_ns_ci_alg = *(AUCL_CONNDATA + 53);
     if (iml_ns_ci_alg >= (sizeof(achrs_ssl_ci_alg) / sizeof(achrs_ssl_ci_alg[0]))) {
       iml_ns_ci_alg = 0;                   /* make unknown            */
     }
     iml_ns_ci_type = *(AUCL_CONNDATA + 54);
     if (iml_ns_ci_type >= (sizeof(achrs_ssl_ci_type) / sizeof(achrs_ssl_ci_type[0]))) {
       iml_ns_ci_type = (sizeof(achrs_ssl_ci_type) / sizeof(achrs_ssl_ci_type[0])) - 1;
     }
     iml_ns_mac = *(AUCL_CONNDATA + 55);
     if (iml_ns_mac >= (sizeof(achrs_ssl_ci_alg) / sizeof(achrs_ssl_ci_alg[0]))) {
       iml_ns_mac = 0;                      /* make unknown            */
     }
     iml_ns_auth = *(AUCL_CONNDATA + 57) & 3;
     iml_ns_auth |= 1;                      /* always server authentication */
     iml_ns_compr = *(AUCL_CONNDATA + 49);
     if (iml_ns_compr) {                    /* is not none             */
       if (iml_ns_compr == 0XF4) {          /* is defined              */
         iml_ns_compr = 1;
       } else {
         iml_ns_compr = 2;                  /* make unknown            */
       }
     }
     iml_len_msg_ssl = sprintf( byrlwork_ssl, " - protocol:%s cipher-suite:%s key-exchange-mode:%s"
                                " cipher-algorithm:%s cipher-type:%s MAC-algorithm:%s authentication:%s compression:%s",
                                achrs_ssl_prot[ iml_ns_prot ],
                                achrs_ssl_ci_prot[ iml_ns_ci_sui ],
                                achrs_ssl_keyexch[ iml_ns_keyexch ],
                                achrs_ssl_ci_alg[ iml_ns_ci_alg ],
                                achrs_ssl_ci_type[ iml_ns_ci_type ],
                                achrs_ssl_mac[ iml_ns_mac ],
                                achrs_ssl_auth[ iml_ns_auth ],
                                achrs_ssl_compr[ iml_ns_compr ] );
   }
#ifdef B121009
   if (hssl_QueryInfo->hssl_byPartnerNameLength == 0) {
     achl1 = "no server certificate";
     goto psussl80;
   }                                        /* no text yet             */
#endif
   if (ADSL_SSL_QUERY_INFO->ucc_partner_name_length == 0) {
     achl1 = "no server certificate";
     goto psussl80;
   }                                        /* no text yet             */
   iml1 = 0;
   if (adsp_ccb_1->achc_fingerprint) {
     iml1 += sprintf( &byrlwork1[iml1], "fingerprint: " );
     iml2 = 0;
     do {
       iml1 += sprintf( &byrlwork1[iml1], "%02X",
                        *((unsigned char *) adsp_ccb_1->achc_fingerprint + iml2) );

       if (iml2 % 2) byrlwork1[ iml1++ ] = ' ';
       iml2++;                              /* next character          */
     } while (iml2 < DEF_SSL_LEN_FINGERPRINT);
     iml1 += sprintf( &byrlwork1[iml1], "- " );  /* separate following text */
   }
   iml1 += sprintf( &byrlwork1[iml1], "DN (name from certificate): " );
   achl1 = achl2 = &byrlwork1[iml1];        /* name comes here         */
   for (iml1 = 0; iml1 < iml_len_cert; iml1++ ) {
#ifdef B121009
     iml2 = GHHW( *((unsigned short int *) &hssl_QueryInfo->hssl_byPartnerName[ iml1 * 2 ]) );
#endif
     iml2 = GHHW( *((unsigned short int *) &ADSL_SSL_QUERY_INFO->ucrc_partner_name[ iml1 * 2 ]) );
     if (iml2 < 0X0100) {
       *achl1++ = (char) iml2;
     } else {
       *achl1++ = '?';
     }
   }
   *achl1 = 0;                              /* make zero-terminated    */
   iml1 = _stricmp( achl2, (char *) (ADSL_CONN1_G->adsc_csssl_oper_1 + 1) );
   if (iml1) {                              /* strings not equal       */
     strcpy( &byrlwork_ssl[ iml_len_msg_ssl ], " Certificate does not contain valid DNS-name" );
   } else {                                 /* all valid               */
     bol_not_valid_dn = FALSE;              /* check DN successful     */
   }
   achl1 = byrlwork1;

   psussl80:                                /* write message           */
// to-do 30.04.09 KB IPV6 and HTCP
   m_hlnew_printf( HLOG_XYZ1, "HWSPSxxxI GATE=%(ux)s SNO=%08d INETA=%s Client-Side SSL logon - \
host=%s INETA-host=%d.%d.%d.%d - %s%s",
                   ADSL_CONN1_G->adsc_gate1 + 1,
                   ADSL_CONN1_G->dsc_co_sort.imc_sno,
                   ADSL_CONN1_G->chrc_ineta,
                   ADSL_CONN1_G->adsc_csssl_oper_1 + 1,
                   *((unsigned char *) &(((struct sockaddr_in *) ADSL_CONN1_G->dcl_tcp_r_s.m_get_ineta())->sin_addr)),
                   *((unsigned char *) &(((struct sockaddr_in *) ADSL_CONN1_G->dcl_tcp_r_s.m_get_ineta())->sin_addr) + 1),
                   *((unsigned char *) &(((struct sockaddr_in *) ADSL_CONN1_G->dcl_tcp_r_s.m_get_ineta())->sin_addr) + 2),
                   *((unsigned char *) &(((struct sockaddr_in *) ADSL_CONN1_G->dcl_tcp_r_s.m_get_ineta())->sin_addr) + 3),
                   achl1, byrlwork_ssl );
   ADSL_CONN1_G->adsc_csssl_oper_1->boc_sslc = TRUE;  /* ssl handshake complete */
   ADSL_CONN1_G->adsc_csssl_oper_1->boc_error = bol_not_valid_dn;  /* if DNS name wrong, error occured */
#ifndef B100731
   if (ADSL_CONN1_G->iec_st_ses == clconn1::ied_ses_wait_csssl) {  /* wait for client-side SSL */
     ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_start_server_2;  /* start connection to server part two */
   }
#endif
#undef AUCL_CONNDATA
#undef hssl_QueryInfo
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
#endif
} /* end m_ssl_conn_cl_compl_cl()                                      */
#endif
#endif

/** data received from client                                          */
static BOOL m_client_recv_compl( struct dsd_conn1 *adsp_conn1,
                                 struct dsd_sdh_control_1 *adsp_sdhc1_recv,
                                 int imp_len_recv ) {
   int        iml_rc;                       /* return code             */
   int        iml1, iml2;                   /* working-variables       */
   HL_LONGLONG ill1;                        /* working-variable        */
   BOOL       bol_rec;                      /* receive more data       */
   BOOL       bol_act;                      /* activate thread         */
   BOOL       bol_err_recv;                 /* error receive           */
#ifdef NEW_REPORT_1501
   dsd_time_1 dsl_time_cur;                 /* current time            */
#endif
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   void *     al_free;                      /* buffer to free          */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* working variable */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
#ifdef EXAMINE_SIGN_ON_01                   /* 10.08.11 KB examine sign on time */
   BOOL       bol1;                         /* working variable        */
   LARGE_INTEGER ill_exa_so_01;             /* time now                */
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_client_recv_compl l%05d imp_len_recv=%d time-sec=%d.",
                   __LINE__, imp_len_recv, m_get_time() );
#endif
#ifdef EXAMINE_SIGN_ON_01                   /* 10.08.11 KB examine sign on time */
   if (this->boc_exa_so_01 == TRUE) {       /* set if display to come  */
     this->boc_exa_so_01 = FALSE;           /* reset display to come   */
     bol1 = QueryPerformanceCounter( &ill_exa_so_01 );  /* time now    */
     if (bol1 == FALSE) {                   /* error occured           */
       m_hlnew_printf( HLOG_TRACE1, "HWSPM nbipgw20-l%05d-W GATE=%(ux)s QueryPerformanceCounter() error %d.",
                       __LINE__, adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta, GetLastError() );
     } else {
       char *achh1;                         /* working variable        */
       char chrh_edit[ 32 ];
       *((HL_LONGLONG *) &ill_exa_so_01) -= *((HL_LONGLONG *) &this->ilc_exa_so_01);
       achh1 = m_edit_dec_long( chrh_edit, (HL_LONGLONG) (*((HL_LONGLONG *) &ill_exa_so_01) * 1000000) / ils_freq );
       m_hlnew_printf( HLOG_TRACE1, "HWSPM nbipgw20-l%05d-T GATE=%(ux)s SNO=%08d INETA=%s interval=0X%016llX/%lld micro-sec=%s.",
                       __LINE__,
                       adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta,
                       ill_exa_so_01, ill_exa_so_01, achh1 );
     }
   }
#endif
#ifdef DEBUG_100830_02
#ifdef TRY_DEBUG_100830_02
   m_hlnew_printf( HLOG_TRACE1, "clconn1::rec_complete l%05d dpcltcpr=%p imp_len_recv=%d boc_st_act=%d time-sec=%d.",
                   __LINE__, dpcltcpr, imp_len_recv, boc_st_act, m_get_time() );
#endif
#endif
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = this->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "nbipgw20-l%05d rec_complete start", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifdef TRACE_P_060922                       /* problem received data   */
   if (imp_len_recv > 0) {
#define ADSL_GATHER_I_1_W ((struct dsd_gather_i_1 *) (adsp_sdhc1 + 1))
     m_hlnew_printf( HLOG_TRACE1, "clconn1::rec_complete l%05d imp_len_recv=%d time-sec=%lld\
 adsp_sdhc1=%p achc_ginp_cur=%p achc_ginp_end=%p data=0X%02X",
                     __LINE__, imp_len_recv, m_get_time(),
                     adsp_sdhc1, ADSL_GATHER_I_1_W->achc_ginp_cur, ADSL_GATHER_I_1_W->achc_ginp_end,
                     *((unsigned char *) ADSL_GATHER_I_1_W->achc_ginp_cur) );
#undef ADSL_GATHER_I_1_W
   }
#endif /* TRACE_P_060922                       problem received data   */
#ifdef NEW_REPORT_1501
   if (imp_len_recv > 0) {                  /* data received           */
     if (dss_bc_ctrl.adsrc_bc1[ 0 ] != NULL) {  /* with report         */
       dsl_time_cur = m_get_time();         /* current time            */
       dss_bc_ctrl.dsc_critsect.m_enter();  /* critical section        */
       iml1 = (int) dsl_time_cur - (int) dss_bc_ctrl.adsrc_bc1[ 0 ]->dsc_time_start;
       if (iml1 < 0) iml1 = 0;
       iml1 /= DEF_BANDWIDTH_CLIENT_SECS;   /* compute slot            */
       iml2 = dss_bc_ctrl.adsrc_bc1[ 0 ]->imc_no_entries;  /* number of entries */
       if (iml1 >= iml2) {                  /* check if at end         */
         iml1 = iml2 - 1;                   /* last entry              */
       }
       (*(dss_bc_ctrl.adsrc_bc1[ 0 ]->aimc_p_recv + iml1))++;  /* number of packets received */
       *(dss_bc_ctrl.adsrc_bc1[ 0 ]->ailc_d_recv + iml1) += imp_len_recv;  /* count bytes data received */
       dss_bc_ctrl.dsc_critsect.m_leave();  /* critical section        */
     }
   }
#endif
   if (   (adsp_conn1->dsc_tc1_client.boc_connected == FALSE)  /* TCP/IP connection status */
       && (adsp_conn1->achc_reason_end == NULL)) {
// to-do 09.03.11 KB WSP trace
     if (adsp_sdhc1_recv) m_proc_free( adsp_sdhc1_recv );  /* free the buffer */
     return FALSE;                          /* stop receiving          */
   }
   if (adsp_conn1->iec_st_cls == ied_cls_set_entropy) {  /* set entropy */
     adsp_conn1->dsc_hlse03s.ilc_entropy = m_get_epoch_nanoseconds() - adsp_conn1->dsc_hlse03s.ilc_entropy;
     adsp_conn1->iec_st_cls = ied_cls_normal;  /* status client normal processing */
     if (adsp_conn1->adsc_gate1->imc_permmov_from_port > 0) {  /* <permanently-moved-from_port> */
       if (adsp_conn1->adsc_gate_listen_1->dsc_soa.ss_family == AF_INET) {  /* IPV4 */
         iml1 = ntohs( ((struct sockaddr_in *) &adsp_conn1->adsc_gate_listen_1->dsc_soa)->sin_port );
       } else {                             /* IPV6                    */
         iml1 = ntohs( ((struct sockaddr_in6 *) &adsp_conn1->adsc_gate_listen_1->dsc_soa)->sin6_port );
       }
       if (iml1 == adsp_conn1->adsc_gate1->imc_permmov_from_port) {  /* <permanently-moved-from_port> */
         adsp_conn1->iec_st_cls = ied_cls_wait_start;  /* status client wait for start message */
       }
     }
   }
   bol_rec = FALSE;                         /* do not receive more     */
   bol_act = FALSE;                         /* do not activate thread  */
   bol_err_recv = FALSE;                    /* error receive           */
   if (imp_len_recv <= 0) {                 /* end connection          */
     if (adsp_conn1->achc_reason_end == NULL) {  /* reason end session */
       if (imp_len_recv == 0) {             /* normal end              */
         adsp_conn1->achc_reason_end = "client normal end";
       } else {                             /* abnormal end            */
         adsp_conn1->achc_reason_end = "client ended with error";
       }
     }
#ifdef NOT_YET_110811
     dpcltcpr->close1();
     boc_hunt_end = FALSE;                  /* do not more hunt end    */
#endif
     adsp_conn1->iec_st_cls = ied_cls_rec_close;  /* received close    */
   }
   if (adsp_conn1->boc_st_sslc) {           /* ssl handshake complete  */
     iml1 = adsp_conn1->adsc_gate1->itimeout;  /* from GATE            */
     adsl_server_conf_1_w1 = adsp_conn1->adsc_server_conf_1;  /* get server connected */
     if (adsl_server_conf_1_w1) {           /* server is connected     */
#ifndef B140704
       if (adsl_server_conf_1_w1->adsc_seco1_previous) {  /* configuration server previous */
         adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_seco1_previous;  /* configuration server previous */
       }
#endif
       if (adsl_server_conf_1_w1->inc_timeout) {
         if (   (iml1 == 0)
             || (adsl_server_conf_1_w1->inc_timeout < iml1)) {
           iml1 = adsl_server_conf_1_w1->inc_timeout;
         }
       }
     }
#ifndef B130323
     if (adsp_conn1->imc_timeout_set) {     /* timeout set in seconds  */
       iml1 = adsp_conn1->imc_timeout_set;  /* timeout set in seconds  */
     }
#endif
     if (iml1 > 0) {                        /* set timeout             */
       adsp_conn1->ilc_timeout = m_get_epoch_ms() + iml1 * 1000;  /* set new end-time */
     } else {                               /* no timeout              */
       adsp_conn1->ilc_timeout = 0;         /* no end-time             */
     }
   }
   adsl_auxf_1_w1 = adsp_conn1->adsc_aux_timer_ch;  /* get chain auxiliary timer */
   while (adsl_auxf_1_w1) {                 /* loop over all timer entries */
#define ADSL_AUX_T ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))
     if (ADSL_AUX_T->boc_expired == FALSE) break;  /* timer has not yet expired */
#undef ADSL_AUX_T
     adsl_auxf_1_w1 = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->adsc_auxf_next;
   }
   if (   (adsl_auxf_1_w1 == NULL)          /* no auxiliary timer entry not found */
       && (adsp_conn1->ilc_timeout == 0)) {  /* no timeout             */
     if (adsp_conn1->dsc_timer.vpc_chain_2) {  /* timer still set      */
       m_time_rel( &adsp_conn1->dsc_timer );  /* release timer         */
     }
   } else {                                 /* needs timer             */
     ill1 = adsp_conn1->ilc_timeout;        /* get timeout             */
     if (   (adsl_auxf_1_w1)                /* auxiliary timer set     */
         && (   (ill1 == 0)                /* timer not yet set       */
             || (ill1 > ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->ilc_endtime))) {
       ill1 = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->ilc_endtime;
     }
     if (   (ill1 != adsp_conn1->dsc_timer.ilcendtime)  /* different end-time */
         || (adsp_conn1->dsc_timer.vpc_chain_2 == NULL)) {  /* timer not set */
       if (adsp_conn1->dsc_timer.vpc_chain_2) {  /* timer still set    */
         m_time_rel( &adsp_conn1->dsc_timer );  /* release timer       */
       }
       adsp_conn1->dsc_timer.ilcendtime = ill1;  /* set new end-time   */
       m_time_set( &adsp_conn1->dsc_timer, TRUE );  /* set new timer   */
     }
   }
   al_free = NULL;                          /* no buffer to free       */
   iml_rc = adsp_conn1->dsc_critsect.m_enter();  /* enter CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d m_enter() critical section failed %d.",
                     adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, __LINE__, iml_rc );
   }
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                   __LINE__, HL_THRID, &adsp_conn1->dsc_critsect );
#endif
#ifdef NOT_YET_110811
// EnterCriticalSection( &d_act_critsect );  /* critical section act   */
   if (bo_st_open) {                        /* connection is open      */
#endif
     if (imp_len_recv > 0) {                       /* buffer given            */
       memset( adsp_sdhc1_recv, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsp_sdhc1_recv + 1))
       ADSL_GAI1_W1->achc_ginp_cur = (char *) (ADSL_GAI1_W1 + 1);
       ADSL_GAI1_W1->achc_ginp_end = ADSL_GAI1_W1->achc_ginp_cur + imp_len_recv;
#ifndef B080426
       adsp_sdhc1_recv->adsc_gather_i_1_i = ADSL_GAI1_W1;
#endif
#undef ADSL_GAI1_W1
         if (adsp_conn1->adsc_sdhc1_c1 == NULL) {  /* receive buffer client 1 */
           adsp_conn1->adsc_sdhc1_c1 = adsp_sdhc1_recv;  /* get data received first buffer */
           bol_rec = TRUE;                  /* receive more data       */
         } else {                           /* already receive data    */
           if (adsp_conn1->adsc_sdhc1_c2 == NULL) {     /* second buffer not yet set */
             adsp_conn1->adsc_sdhc1_c2 = adsp_sdhc1_recv;    /* get data received second buffer */
           } else {                         /* illogic                 */
             bol_err_recv = TRUE;           /* error receive           */
             al_free = adsp_sdhc1_recv;          /* set buffer to free      */
           }
         }
#ifndef B080407
     } else {
       al_free = adsp_sdhc1_recv;                /* set buffer to free      */
#endif
     }
     while (adsp_conn1->boc_st_act == FALSE) {  /* thread not active with session */
       bol_act = TRUE;                      /* activate thread         */
       if (   (adsp_conn1->iec_st_ses == ied_ses_conn)  /* status server */
           && (adsp_conn1->adsc_server_conf_1->boc_sdh_reflect == FALSE)) {  /* not only Server-Data-Hook */
         /* wait because of flow control                               */
         switch (adsp_conn1->iec_servcotype) {  /* type of server connection */
           case ied_servcotype_normal_tcp:  /* normal TCP              */
             if (adsp_conn1->dsc_tc1_server.adsc_sdhc1_send == NULL) break;  /* check flow server */
             adsp_conn1->dsc_tc1_server.boc_act_conn_send = TRUE;  /* activate connection after send */
             bol_act = FALSE;               /* do not activate thread  */
             break;                         /* all done                */
#ifdef D_INCL_HOB_TUN
           case ied_servcotype_htun:        /* HOB-TUN                 */
             if (adsp_conn1->imc_send_window <= DEF_HTCP_SEND_WINDOW) break;  /* number of bytes to be sent */
             bol_act = FALSE;               /* do not activate thread  */
             break;                         /* all done                */
#endif
         }
       }
       if (bol_act == FALSE) break;         /* do not activate thread  */
       adsp_conn1->boc_st_act = TRUE;       /* thread with session active now */
       break;
     }
#ifdef NOT_YET_110811
   } else {                                 /* connection not open     */
#ifndef B080407
     al_free = adsp_sdhc1;                  /* set buffer to free      */
#endif
#ifdef B080407
     if (imp_len_recv > 0) {                       /* buffer given            */
       al_free = adsp_sdhc1;                /* set buffer to free      */
     }
#endif
   }
// LeaveCriticalSection( &d_act_critsect );  /* critical section act   */
#endif
   iml_rc = adsp_conn1->dsc_critsect.m_leave();  /* leave CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d m_leave() critical section failed %d.",
                     adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, __LINE__, iml_rc );
   }
#ifdef B110501
   adsl_wt1_w1 = NULL;                      /* no WSP trace record     */
   if (imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_ms();  /* time trace record recorded */
     adsl_wt1_w1->achc_text = (char *) (adsl_wt1_w1 + 1);  /* address of text this record */
     adsl_wt1_w1->imc_len_text              /* length of text this record */
       = sprintf( (char *) (adsl_wt1_w1 + 1),
                  "SNO=%08d data received from %s length %d/0X%X bol_rec=%d bol_act=%d.",
                  dsc_co_sort.imc_sno, achl_cl_se, imp_len_recv, iplen, bol_rec, bol_act );
   }
   if (adsl_wt1_w1) {                       /* output trace generated  */
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
   if (adsp_conn1->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SNERECCL", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = adsp_conn1->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "data received from client length %d/0X%X bol_rec=%d bol_act=%d.",
                     imp_len_recv, imp_len_recv, bol_rec, bol_act );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (   (imp_len_recv > 0)              /* data received           */
         && (adsp_conn1->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml1 = imp_len_recv;                 /* length of data sent     */
       achl_w3 = (char *) ((struct dsd_gather_i_1 *) (adsp_sdhc1_recv + 1) + 1);  /* start of data */
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
   if (bol_act) {
     m_act_thread_2( adsp_conn1 );          /* activate m_proc_data()  */
   }
   if (al_free) {                           /* buffer to free          */
     m_proc_free( al_free );                /* free memory             */
   }
   if (bol_err_recv) {                      /* error receive           */
// to-do 08.09.10 KB error number
     m_hlnew_printf( HLOG_XYZ1, "HWSPSuuuW GATE=%(ux)s SNO=%08d INETA=%s client receive illogic",
                     adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta );
#ifdef DEBUG_100908_01

     m_hlnew_printf( HLOG_XYZ1, "nbipgw20 l%05d &(class dsd_tcpcomp)=%p.",
                     __LINE__,
                     (char *) dpcltcpr + offsetof( class cl_tcp_r, dsc_tcpco1 ) );
#endif
   }
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = this->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "nbipgw20-l%05d rec_complete end", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
   return bol_rec;
} /* end m_client_recv_compl()                                         */

/** data received from server                                          */
static BOOL m_server_recv_compl( struct dsd_conn1 *adsp_conn1,
                                 struct dsd_sdh_control_1 *adsp_sdhc1_recv,
                                 int imp_len_recv ) {
   int        iml_rc;                       /* return code             */
   int        iml1, iml2;                   /* working-variables       */
   HL_LONGLONG ill1;                        /* working-variable        */
   BOOL       bol_rec;                      /* receive more data       */
   BOOL       bol_act;                      /* activate thread         */
   BOOL       bol_err_recv;                 /* error receive           */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   void *     al_free;                      /* buffer to free          */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* working variable */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_server_recv_compl() l%05d imp_len_recv=%d time-sec=%d",
                   __LINE__, imp_len_recv, m_get_time() );
#endif
#ifdef DEBUG_100830_02
#ifdef TRY_DEBUG_100830_02
   m_hlnew_printf( HLOG_XYZ1, "clconn1::rec_complete l%05d dpcltcpr=%p iplen=%d boc_st_act=%d time-sec=%d.",
                   __LINE__, dpcltcpr, iplen, boc_st_act, m_get_time() );
#endif
#endif
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = this->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "nbipgw20-l%05d rec_complete start", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifdef TRACE_P_060922                       /* problem received data   */
   if (imp_len_recv > 0) {
#define ADSL_GATHER_I_1_W ((struct dsd_gather_i_1 *) (adsp_sdhc1_recv + 1))
     m_hlnew_printf( HLOG_XYZ1, "clconn1::rec_complete l%05d imp_len_recv=%d time-sec=%lld\
 adsp_sdhc1_recv=%p achc_ginp_cur=%p achc_ginp_end=%p data=0X%02X",
                     __LINE__, imp_len_recv, m_get_time(),
                     adsp_sdhc1_recv, ADSL_GATHER_I_1_W->achc_ginp_cur, ADSL_GATHER_I_1_W->achc_ginp_end,
                     *((unsigned char *) ADSL_GATHER_I_1_W->achc_ginp_cur) );
#undef ADSL_GATHER_I_1_W
   }
#endif /* TRACE_P_060922                       problem received data   */
#ifdef B061016
   if (dpcltcpr->boTCPIPconn == FALSE) return FALSE;  /* TCP/IP connection stat */
#endif
   if (   (adsp_conn1->dsc_tc1_server.boc_connected == FALSE)  /* TCP/IP connection status */
       && (adsp_conn1->achc_reason_end == NULL)) {
// to-do 09.03.11 KB WSP trace
     if (adsp_sdhc1_recv) m_proc_free( adsp_sdhc1_recv );  /* free the buffer */
     return FALSE;                          /* stop receiving          */
   }
   bol_rec = FALSE;                         /* do not receive more     */
   bol_act = FALSE;                         /* do not activate thread  */
   bol_err_recv = FALSE;                    /* error receive           */
   if (imp_len_recv <= 0) {                 /* end connection          */
#ifndef B080407
//   m_proc_free( adsp_sdhc1_recv );             /* free the buffer         */
#endif
     if (adsp_conn1->achc_reason_end == NULL) {  /* reason end session */
#ifdef B131011
       if (imp_len_recv == 0) {             /* normal end              */
         /* do not set when dynamic server                             */
         if (   (adsp_conn1->adsc_server_conf_1 == NULL)
             || (adsp_conn1->adsc_server_conf_1->boc_dynamic == FALSE)) {
//         if (this->boc_hunt_end == FALSE) {  /* do not hunt end    */
             adsp_conn1->achc_reason_end = "server normal end";
//         }
         }
       } else {                             /* abnormal end            */
         adsp_conn1->achc_reason_end = "server ended with error";
       }
#endif
       if (   (adsp_conn1->adsc_server_conf_1 == NULL)
           || (adsp_conn1->adsc_server_conf_1->boc_dynamic == FALSE)) {
         if (imp_len_recv == 0) {           /* normal end              */
           adsp_conn1->achc_reason_end = "server normal end";
         } else {
           adsp_conn1->achc_reason_end = "server ended with error";
         }
       }
     }
     adsp_conn1->iec_st_ses = ied_ses_rec_close;  /* received close    */
//   dpcltcpr->close1();
//   boc_hunt_end = FALSE;                  /* do not more hunt end    */
   }
#ifdef B060325
   bo_no_timeout = TRUE;                    /* do not timeout          */
#endif
   if (adsp_conn1->boc_st_sslc) {           /* ssl handshake complete  */
     iml1 = adsp_conn1->adsc_gate1->itimeout;  /* from GATE            */
     adsl_server_conf_1_w1 = adsp_conn1->adsc_server_conf_1;  /* get server connected */
     if (adsl_server_conf_1_w1) {           /* server is connected     */
#ifndef B140704
       if (adsl_server_conf_1_w1->adsc_seco1_previous) {  /* configuration server previous */
         adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_seco1_previous;  /* configuration server previous */
       }
#endif
       if (adsl_server_conf_1_w1->inc_timeout) {
         if (   (iml1 == 0)
             || (adsl_server_conf_1_w1->inc_timeout < iml1)) {
           iml1 = adsl_server_conf_1_w1->inc_timeout;
         }
       }
     }
     if (iml1 > 0) {                        /* set timeout             */
       adsp_conn1->ilc_timeout = m_get_epoch_ms() + iml1 * 1000;  /* set new end-time */
     } else {                               /* no timeout              */
       adsp_conn1->ilc_timeout = 0;         /* no end-time             */
     }
   }
#ifdef B150121
   adsl_auxf_1_w1 = adsp_conn1->adsc_aux_timer_ch;  /* get chain auxiliary timer */
   while (adsl_auxf_1_w1) {                 /* loop over all timer entries */
#define ADSL_AUX_T ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))
     if (ADSL_AUX_T->boc_expired == FALSE) break;  /* timer has not yet expired */
#undef ADSL_AUX_T
     adsl_auxf_1_w1 = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->adsc_auxf_next;
   }
   if (   (adsl_auxf_1_w1 == NULL)          /* no auxiliary timer entry not found */
       && (adsp_conn1->ilc_timeout == 0)) {  /* no timeout             */
     if (adsp_conn1->dsc_timer.vpc_chain_2) {  /* timer still set      */
       m_time_rel( &adsp_conn1->dsc_timer );  /* release timer         */
     }
   } else {                                 /* needs timer             */
     ill1 = adsp_conn1->ilc_timeout;              /* get timeout             */
     if (   (adsl_auxf_1_w1)                /* auxiliary timer set     */
         && (   (ill1 == 0)                 /* timer not yet set       */
             || (ill1 > ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->ilc_endtime))) {
       ill1 = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->ilc_endtime;
     }
     if (   (ill1 != adsp_conn1->dsc_timer.ilcendtime)  /* different end-time */
         || (adsp_conn1->dsc_timer.vpc_chain_2 == NULL)) {  /* timer not set */
       if (adsp_conn1->dsc_timer.vpc_chain_2) {  /* timer still set    */
         m_time_rel( &adsp_conn1->dsc_timer );  /* release timer       */
       }
       adsp_conn1->dsc_timer.ilcendtime = ill1;  /* set new end-time   */
       m_time_set( &adsp_conn1->dsc_timer, TRUE );  /* set new timer   */
     }
   }
#endif
#ifndef B150121
   m_conn1_set_timer_1( adsp_conn1 );
#endif
   al_free = NULL;                          /* no buffer to free       */
#ifdef NOT_YET_110813
   EnterCriticalSection( &d_act_critsect );  /* critical section act   */
#endif
   iml_rc = adsp_conn1->dsc_critsect.m_enter();  /* enter CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d m_enter() critical section failed %d.",
                     adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, __LINE__, iml_rc );
   }
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                   __LINE__, HL_THRID, &adsp_conn1->dsc_critsect );
#endif
// if (bo_st_open) {                        /* connection is open      */
     if (imp_len_recv > 0) {                /* buffer given            */
#ifndef B080407
       memset( adsp_sdhc1_recv, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsp_sdhc1_recv + 1))
       ADSL_GAI1_W1->achc_ginp_cur = (char *) (ADSL_GAI1_W1 + 1);
       ADSL_GAI1_W1->achc_ginp_end = ADSL_GAI1_W1->achc_ginp_cur + imp_len_recv;
#ifndef B080426
       adsp_sdhc1_recv->adsc_gather_i_1_i = ADSL_GAI1_W1;
#endif
#undef ADSL_GAI1_W1
#endif
         if (adsp_conn1->adsc_sdhc1_s1 == NULL) {  /* receive buffer server 1 */
           adsp_conn1->adsc_sdhc1_s1 = adsp_sdhc1_recv;  /* get data received first buffer */
           bol_rec = TRUE;                  /* receive more data       */
         } else {                           /* already receive data    */
           if (adsp_conn1->adsc_sdhc1_s2 == NULL) {     /* second buffer not yet set */
             adsp_conn1->adsc_sdhc1_s2 = adsp_sdhc1_recv;    /* get data received second buffer */
           } else {                         /* illogic                 */
             bol_err_recv = TRUE;           /* error receive           */
             al_free = adsp_sdhc1_recv;     /* set buffer to free      */
           }
         }
#ifdef TRACEHL1
#ifdef NOT_YET_110813
   m_hlnew_printf( HLOG_XYZ1, "clconn1::rec_complete entered Critical Section data from server adsc_sdhc1_s1=%p adsc_sdhc1_s2=%p dcl_tcp_r_s.getstc()=%d",
               adsc_sdhc1_s1, adsc_sdhc1_s2, dcl_tcp_r_s.getstc() );
#define ADSL_GATHER_I_1_W ((struct dsd_gather_i_1 *) (adsp_conn1->adsc_sdhc1_s1 + 1))
   if (adsp_conn1->adsc_sdhc1_s1) {
     m_hlnew_printf( HLOG_XYZ1, "clconn1::rec_complete adsc_sdhc1_s1=%p achc_ginp_cur=%p achc_ginp_end=%p",
                     adsp_conn1->adsc_sdhc1_s1, ADSL_GATHER_I_1_W->achc_ginp_cur, ADSL_GATHER_I_1_W->achc_ginp_end );
   }
#undef ADSL_GATHER_I_1_W
#define ADSL_GATHER_I_1_W ((struct dsd_gather_i_1 *) (adsc_sdhc1_s2 + 1))
   if (adsp_conn1->adsc_sdhc1_s2) {
     m_hlnew_printf( HLOG_XYZ1, "clconn1::rec_complete adsc_sdhc1_s2=%p achc_ginp_cur=%p achc_ginp_end=%p",
                 adsp_conn1->adsc_sdhc1_s2, ADSL_GATHER_I_1_W->achc_ginp_cur, ADSL_GATHER_I_1_W->achc_ginp_end );
   }
#undef ADSL_GATHER_I_1_W
#endif
#endif
#ifndef B080407
     } else {
       al_free = adsp_sdhc1_recv;                /* set buffer to free      */
#endif
     }
     while (adsp_conn1->boc_st_act == FALSE) {  /* thread not active with session */
       if (adsp_conn1->dsc_tc1_client.adsc_sdhc1_send) {  /* check flow client */
         adsp_conn1->dsc_tc1_client.boc_act_conn_send = TRUE;  /* activate connection after send */
         break;
       }
       adsp_conn1->boc_st_act = TRUE;       /* thread with session active now */
       bol_act = TRUE;                      /* activate thread         */
       break;
     }
// } else {                                 /* connection not open     */
#ifdef NOT_YET_110813
#ifndef B080407
     al_free = adsp_sdhc1_recv;                  /* set buffer to free      */
#endif
#ifdef B080407
     if (imp_len_recv > 0) {                       /* buffer given            */
       al_free = adsp_sdhc1_recv;                /* set buffer to free      */
     }
#endif
#endif
// }
#ifdef NOT_YET_110813
   LeaveCriticalSection( &d_act_critsect );  /* critical section act   */
#endif
   iml_rc = adsp_conn1->dsc_critsect.m_leave();  /* leave CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d m_leave() critical section failed %d.",
                     adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, __LINE__, iml_rc );
   }
#ifdef B110501
   adsl_wt1_w1 = NULL;                      /* no WSP trace record     */
   achl_cl_se = "server";                   /* client or server        */
   if (dpcltcpr == &this->dcl_tcp_r_c) {    /* is from client          */
     achl_cl_se = "client";                 /* client or server        */
   }
   if (imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
     adsl_wt1_w1->achc_text = (char *) (adsl_wt1_w1 + 1);  /* address of text this record */
     adsl_wt1_w1->imc_len_text              /* length of text this record */
       = sprintf( (char *) (adsl_wt1_w1 + 1),
                  "SNO=%08d data received from server length %d/0X%X bol_rec=%d bol_act=%d.",
                  dsc_co_sort.imc_sno, imp_len_recv, imp_len_recv, bol_rec, bol_act );
   }
   if (adsl_wt1_w1) {                       /* output trace generated  */
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
   if (adsp_conn1->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SNERECSE", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = adsp_conn1->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "data received from server length %d/0X%X bol_rec=%d bol_act=%d.",
                     imp_len_recv, imp_len_recv, bol_rec, bol_act );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (   (imp_len_recv > 0)              /* data received           */
         && (adsp_conn1->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml1 = imp_len_recv;                 /* length of data received */
       achl_w3 = (char *) ((struct dsd_gather_i_1 *) (adsp_sdhc1_recv + 1) + 1);  /* start of data */
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
   if (bol_act) {
     m_act_thread_2( adsp_conn1 );          /* activate m_proc_data()  */
   }
   if (al_free) {                           /* buffer to free          */
     m_proc_free( al_free );                /* free memory             */
   }
   if (bol_err_recv) {                      /* error receive           */
// to-do 08.09.10 KB error number
     m_hlnew_printf( HLOG_XYZ1, "HWSPSuuuW GATE=%(ux)s SNO=%08d INETA=%s server receive illogic",
                     adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta );
#ifdef DEBUG_100908_01

     m_hlnew_printf( HLOG_XYZ1, "nbipgw20 l%05d &(class dsd_tcpcomp)=%p.",
                     __LINE__,
                     (char *) dpcltcpr + offsetof( class cl_tcp_r, dsc_tcpco1 ) );
#endif
   }
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = this->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "nbipgw20-l%05d-T m_server_recv_compl() end", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
   return bol_rec;
} /* end m_server_recv_compl()                                         */

/** start receiving from server                                        */
static void m_start_rec_server( struct dsd_pd_work *adsp_pd_work ) {
   BOOL       bol1;                         /* working variable        */
   int        inl1;                         /* working variable        */
#ifdef B121121
   BOOL       bol_next_conn;                /* try next connection     */
#endif
   BOOL       bol_start_sdh;                /* start Server-Data-Hook  */
   char       *achl1, *achl2;               /* working variables       */
#ifdef NOT_YET_110808
   int        rc_sock;
#endif
   int        iml_rc;                       /* return code             */
   int        iml_server_socket;            /* socket for server connection */
   int        iml_ind_connect;              /* index of connect, no INETA */
   int        iml_tcpcomp_state;            /* value of TCPCOMP state  */
#ifdef D_INCL_HOB_TUN
   int        iml_hob_tun_state;            /* value of HOB-TUN state  */
#endif
   socklen_t  iml_namelen;                  /* length of name          */
   socklen_t  iml_bindlen;                  /* length for bind         */
#ifdef D_INCL_HOB_TUN
   socklen_t  iml_local_namelen;            /* length of name local    */
   enum ied_ineta_raws_def iel_irs_def;     /* type of INETA raw socket */
   struct sockaddr *adsl_soa_w1;            /* sockaddr temporary value */
   struct dsd_ineta_raws_1 *adsl_ineta_raws_1_w1;  /* extension field HOB-TUN */
   struct dsd_raw_packet_if_conf *adsl_raw_packet_if_conf;  /* configuration raw-packet-interface */
#endif
   struct sockaddr *adsl_soa_bind;          /* address information for bind */
   struct sockaddr_storage dsl_soa_conn;    /* address information for connect */
   struct sockaddr_in du_gateway_sockaddr;  /* gateway multihomed      */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
   struct dsd_target_ineta_1 *adsl_server_ineta_w1;  /* server INETA   */
   struct dsd_hl_clib_1 dsl_sdh_l1;         /* HOBLink Copy Library 1  */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_cur_1;  /* current location 1  */
   struct dsd_sdh_control_1 *adsl_sdhc1_last_1;  /* last location 1    */
// char       chrl_ineta_server[ 16 ];      /* for INETA server        */
   char       chrl_ineta_server[ LEN_DISP_INETA ];  /* for INETA server */
#ifdef D_INCL_HOB_TUN
   char       chrl_ineta_local[ LEN_DISP_INETA ];  /* for INETA local  */
   union {
     struct dsd_tun_start_htcp dsl_tun_start_htcp;  /* HOB-TUN start interface HTCP */
     struct dsd_tun_start_ppp dsl_tun_start_ppp;  /* HOB-TUN start interface PPP */
   };
#endif

#define ADSL_AUX_CF1 (&adsp_pd_work->dsc_aux_cf1)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
   if (ADSL_CONN1_G->adsc_server_conf_1 == NULL) return;  /* no server yet */
#ifndef TJ_B170809
   if (ADSL_CONN1_G->iec_st_ses == ied_ses_do_lbal) return;  /* status do load-balancing */
#endif

   bol_start_sdh = FALSE;                   /* start Server-Data-Hook  */
//#ifdef DEBUG_100824_01
//#ifdef TRACEHL1
#ifdef DEBUG_120808_01                      /* debug start SDHs        */
   m_hlnew_printf( HLOG_TRACE1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_start_rec_server() iec_st_ses=%d iec_servcotype=%d.",
                   ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                   ADSL_CONN1_G->iec_st_ses, ADSL_CONN1_G->iec_servcotype );
#endif
   /* check connect to receiving server                                */
   if (   (ADSL_CONN1_G->iec_st_ses == ied_ses_prep_server)  /* status server prepare */
       && (ADSL_CONN1_G->boc_st_sslc)       /* ssl handshake complete  */
       && (   (ADSL_CONN1_G->adsc_wsp_auth_1 == NULL)  /* authentication not active */
           || (ADSL_CONN1_G->adsc_wsp_auth_1->boc_connect_active))) {  /* connect active */
     if (   (ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def == ied_scp_websocket)  /* protocol WebSocket */
         && (ADSL_CONN1_G->adsc_int_webso_conn_1 == NULL)  /* connect for WebSocket applications - internal */
         && (   (ADSL_CONN1_G->adsc_server_conf_1->boc_sdh_reflect)  /* only Server-Data-Hook */
             || (   (ADSL_CONN1_G->adsc_server_conf_1->inc_function != DEF_FUNC_DIR)  /* set function direct */
                 && (ADSL_CONN1_G->adsc_server_conf_1->inc_function != DEF_FUNC_RDP)  /* set function RDP */
                 && (ADSL_CONN1_G->adsc_server_conf_1->inc_function != DEF_FUNC_ICA)))) {  /* set function ICA */
       ADSL_CONN1_G->iec_st_ses = ied_ses_start_sdh;  /* start Server-Data-Hooks */
       bol_start_sdh = TRUE;                /* start Server-Data-Hook  */
       goto p_strecs_40;                    /* continue start receive server */
     }
     switch (ADSL_CONN1_G->adsc_server_conf_1->inc_function) {
#ifdef D_INCL_HOB_TUN
       case DEF_FUNC_HPPPT1:
         memset( &ADSL_CONN1_G->dsc_tun_contr_conn, 0, sizeof(struct dsd_tun_contr_conn) );  /* HOB-TUN control area connection */
         ADSL_CONN1_G->dsc_tun_contr_conn.iec_tunc = ied_tunc_ppp;  /* PPP - HOB-PPP-T1 */
#ifndef B150706
         ADSL_CONN1_G->dsc_tun_contr_conn.imc_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* session number */
         ADSL_CONN1_G->dsc_tun_contr_conn.imc_trace_level = ADSL_CONN1_G->imc_trace_level;  /* WSP trace level */
#endif
         memset( &dsl_tun_start_ppp, 0, sizeof(struct dsd_tun_start_ppp) );  /* HOB-TUN start interface PPP */
         dsl_tun_start_ppp.umc_s_nw_ineta_ipv4 = ADSL_CONN1_G->adsc_server_conf_1->umc_s_nw_ineta;  /* server-network-ineta */
         dsl_tun_start_ppp.umc_s_nw_mask_ipv4 = ADSL_CONN1_G->adsc_server_conf_1->umc_s_nw_mask;  /* server-network-mask */
         goto p_strecs_24;                  /* start HOB-TUN           */
       case DEF_FUNC_SSTP:                  /* set function SSTP Tunnel */
         memset( &ADSL_CONN1_G->dsc_tun_contr_conn, 0, sizeof(struct dsd_tun_contr_conn) );  /* HOB-TUN control area connection */
         ADSL_CONN1_G->dsc_tun_contr_conn.iec_tunc = ied_tunc_sstp;  /* SSTP */
#ifndef B150706
         ADSL_CONN1_G->dsc_tun_contr_conn.imc_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* session number */
         ADSL_CONN1_G->dsc_tun_contr_conn.imc_trace_level = ADSL_CONN1_G->imc_trace_level;  /* WSP trace level */
#endif
         memset( &dsl_tun_start_ppp, 0, sizeof(struct dsd_tun_start_ppp) );  /* HOB-TUN start interface PPP */
         goto p_strecs_24;                  /* start HOB-TUN           */
#endif
       case DEF_FUNC_L2TP:                  /* set function L2TP UDP connection */
         ADSL_CONN1_G->iec_servcotype = ied_servcotype_l2tp;  /* L2TP  */
         ADSL_CONN1_G->adsc_sdhc1_l2tp_sch = NULL;  /* no buffers to sent */
         /* start L2TP                                                 */
         m_l2tp_conn( ADSL_CONN1_G->adsc_server_conf_1->adsc_l2tp_conf,
                      &ADSL_CONN1_G->dsc_l2tp_session,
                      ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def,
                      ADSL_CONN1_G->adsc_server_conf_1->umc_s_nw_ineta,
                      ADSL_CONN1_G->adsc_server_conf_1->umc_s_nw_mask );
         ADSL_CONN1_G->iec_st_ses = ied_ses_start_server_1;  /* status server continue */
         if (ADSL_CONN1_G->adsc_wsp_auth_1) {  /* authentication active */
           ADSL_CONN1_G->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
           ADSL_CONN1_G->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
         }
         goto p_strecs_40;                  /* continue start receive server */
     }
     do {                                   /* only for break          */
       if (ADSL_CONN1_G->adsc_server_conf_1->boc_sdh_reflect) {  /* only Server-Data-Hook */
         if (ADSL_CONN1_G->adsc_wsp_auth_1) break;  /* authentication active */
         ADSL_CONN1_G->iec_st_ses = ied_ses_start_sdh;  /* start Server-Data-Hooks */
         bol_start_sdh = TRUE;              /* start Server-Data-Hook  */
         break;
       }
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "nbipgw20.cpp l%05d clconn1::m_start_rec_server() do connect()", __LINE__ );
#endif
#ifdef B121121
       adsl_server_ineta_w1 = ADSL_CONN1_G->adsc_server_conf_1->adsc_server_ineta;  /* server INETA */
       iml_tcpcomp_state = 0;               /* value of TCPCOMP state  */
#ifdef D_INCL_HOB_TUN
       iml_hob_tun_state = 0;               /* value of HOB-TUN state  */
#endif
       if (ADSL_CONN1_G->adsc_server_conf_1->boc_dns_lookup_before_connect) {  /* needs to solve INETA before connect */
         adsl_server_ineta_w1 = m_get_target_ineta( ADSL_CONN1_G->adsc_server_conf_1->achc_dns_name,  /* address of DNS name */
                                                    ADSL_CONN1_G->adsc_server_conf_1->imc_len_dns_name,  /* length of DNS name */
                                                    ied_chs_ansi_819,
                                                    &ADSL_CONN1_G->adsc_server_conf_1->dsc_bind_out );
         if (adsl_server_ineta_w1 == NULL) {  /* could not resolve INETA */
           m_hlnew_printf( HLOG_WARN1, "HWSPS170W GATE=%(ux)s SNO=%08d INETA=%s configured INETA %.*s could not by resolved by DNS",
                           ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                           ADSL_CONN1_G->adsc_server_conf_1->imc_len_dns_name,  /* length of DNS name */
                           ADSL_CONN1_G->adsc_server_conf_1->achc_dns_name );  /* address of DNS name */
#define DEF_ERR_NO_DNS 124
           if (ADSL_CONN1_G->adsc_wsp_auth_1) {  /* authentication active */
             ADSL_CONN1_G->adsc_wsp_auth_1->imc_connect_error = DEF_ERR_NO_DNS;
             ADSL_CONN1_G->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
             ADSL_CONN1_G->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
             return;
           }
// to-do 03.07.10 KB we return now, we do not need to start the SDHs
           ADSL_CONN1_G->iec_st_ses = ied_ses_error_conn;  /* status server error     */
           if (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic == FALSE) return;  /* not dynamicly allocated */
           ADSL_CONN1_G->iec_st_ses = ied_ses_error_co_dyn;  /* status server error  */
           return;
         }
         iml_tcpcomp_state = 0;             /* value of TCPCOMP state  */
#ifdef D_INCL_HOB_TUN
         iml_hob_tun_state = DEF_STATE_HTUN_INETA_TARGET;  /* need to free target INETA */
#endif
       }
       ADSL_CONN1_G->imc_connect_error = 0;  /* save connect error     */
#ifdef D_INCL_HOB_TUN
       adsl_raw_packet_if_conf = adsg_loconf_1_inuse->adsc_raw_packet_if_conf;  /* configuration raw-packet-interface */
       if (   (ADSL_CONN1_G->adsc_server_conf_1->boc_use_ineta_appl)  /* use HTCP */
           && (adsl_raw_packet_if_conf)) {
         iel_irs_def = ied_ineta_raws_user_ipv4;  /* INETA user IPV4   */
         adsl_ineta_raws_1_w1 = m_prepare_htun_ineta_htcp( ADSL_CONN1_G,
                                                           ADSL_AUX_CF1->adsc_hco_wothr,
                                                           iel_irs_def );
         if (adsl_ineta_raws_1_w1) {        /* INETA found             */
           goto p_strecs_20;                /* start HOB-TUN           */
         }
         m_hlnew_printf( HLOG_WARN1, "HWSPS173W GATE=%(ux)s SNO=%08d INETA=%s configured use-ineta-appl but no ineta-appl available - use normal TCP",
                         ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta );
       }
#endif
       memset( &ADSL_CONN1_G->dsc_tc1_server, 0, sizeof(struct dsd_tcp_ctrl_1) );  /* TCP control structure server */
       ADSL_CONN1_G->iec_servcotype = ied_servcotype_normal_tcp;  /* normal TCP */
#ifdef TRY100514X01
#include "xiipgw08-test-ineta-1.cpp"
#endif
//     iec_st_ses = ied_ses_wait_conn_s_pttd;  /* wait for connect to server, pass-thru-to-desktop */
       ADSL_CONN1_G->iec_st_ses = ied_ses_wait_conn_s_static;  /* wait for static connect to server */
       ADSL_CONN1_G->dsc_tc1_server.boc_connected = TRUE;  /* TCP session is connected */
       iml_rc = ADSL_CONN1_G->dsc_tc1_server.dsc_tcpco1_1.m_startco_mh(
                  &dss_tcpcomp_cb1,
                  ADSL_CONN1_G,
                  &ADSL_CONN1_G->adsc_server_conf_1->dsc_bind_out,
                  adsl_server_ineta_w1,     /* server INETA            */
#ifndef B121121
                  NULL,
#endif
                  ADSL_CONN1_G->adsc_server_conf_1->inc_server_port,  /* TCP/IP port connect */
                  ADSL_CONN1_G->adsc_server_conf_1->boc_connect_round_robin );  /* do connect round-robin */
       if (iml_rc == 0) return;             /* no error occured        */
       ADSL_CONN1_G->dsc_tc1_server.boc_connected = FALSE;  /* TCP session is not connected */
//     boc_tcpc_act = FALSE;                /* TCPCOMP not active      */
       m_hlnew_printf( HLOG_XYZ1, "HWSPS175W GATE=%(ux)s SNO=%08d INETA=%s nbipgw20 l%05d m_startco_mh() failed %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, __LINE__, iml_rc );
// to-do 13.08.10 KB what to do ???
       return;
#endif
#ifndef B121121
       iml_rc = m_tcp_static_conn( ADSL_AUX_CF1, FALSE );
       if (iml_rc == 0) return;             /* no error occured        */
       ADSL_CONN1_G->dsc_tc1_server.boc_connected = FALSE;  /* TCP session is not connected */
//     boc_tcpc_act = FALSE;                /* TCPCOMP not active      */
       m_hlnew_printf( HLOG_WARN1, "HWSPS175W GATE=%(ux)s SNO=%08d INETA=%s nbipgw20 l%05d m_tcp_static_conn() failed %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, __LINE__, iml_rc );
// to-do 21.11.12 KB what to do ???
       return;
#endif
     } while (FALSE);
     if (ADSL_CONN1_G->adsc_wsp_auth_1) {   /* authentication active   */
       ADSL_CONN1_G->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
       ADSL_CONN1_G->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
     }
   }
   if (ADSL_CONN1_G->adsc_wsp_auth_1) return;  /* authentication active */
#ifdef TJ_B170809
   if (ADSL_CONN1_G->adsc_int_webso_conn_1) return;  /* connect for WebSocket applications - internal */
#endif
   /* check start receiving server                                     */
   if (ADSL_CONN1_G->iec_st_ses == ied_ses_start_server_1) {  /* status server */
     ADSL_CONN1_G->iec_st_ses = ied_ses_start_server_2;   /* start connection to server part two */
     switch (ADSL_CONN1_G->adsc_server_conf_1->inc_function) {
// to-do 08.08.13 KB - change #ifdef D_INCL_HOB_TUN
//#ifdef D_HPPPT1_1
#ifdef D_INCL_HOB_TUN
       case DEF_FUNC_HPPPT1:
//       dsc_tun_contr_conn.iec_tunc = ied_tunc_ppp;  /* PPP type session  */
//       goto p_strecs_24;                  /* start HTUN              */
         goto p_strecs_40;                  /* continue start receive server */
       case DEF_FUNC_SSTP:                  /* set function SSTP Tunnel */
//       dsc_tun_contr_conn.iec_tunc = ied_tunc_sstp;  /* SSTP session type */
//       goto p_strecs_24;                  /* start HTUN              */
         goto p_strecs_40;                  /* continue start receive server */
#endif
       case DEF_FUNC_L2TP:                  /* set function L2TP UDP connection */
         ADSL_CONN1_G->iec_servcotype = ied_servcotype_l2tp;  /* L2TP                */
         ADSL_CONN1_G->adsc_sdhc1_l2tp_sch = NULL;        /* no buffers to send      */
         /* start L2TP                                                 */
         m_l2tp_conn( ADSL_CONN1_G->adsc_server_conf_1->adsc_l2tp_conf,
                      &ADSL_CONN1_G->dsc_l2tp_session,
                      ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def,
                      ADSL_CONN1_G->adsc_server_conf_1->umc_s_nw_ineta,
                      ADSL_CONN1_G->adsc_server_conf_1->umc_s_nw_mask );
         goto p_strecs_40;                  /* continue start receive server */
     }
     if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "l%05d m_start_rec_server() before ADSL_CONN1_G->dsc_tc1_server.dsc_tcpco1_1.m_recv()",
                       __LINE__ );
#endif
       ADSL_CONN1_G->dsc_tc1_server.dsc_tcpco1_1.m_recv();  /* receive data now */
     }
#ifndef B100731
     do {
       if (ADSL_CONN1_G->adsc_server_conf_1->boc_use_csssl == FALSE) break;  /* do not use client-side-SSL */
       if (ADSL_CONN1_G->adsc_csssl_oper_1) {
         m_hlnew_printf( HLOG_XYZ1, "nbipgw20 l%05d clconn1::m_start_rec_server() this->adsc_csssl_oper_1 already set",
                         __LINE__ );
         break;
       }
       ADSL_CONN1_G->adsc_csssl_oper_1
         = (struct dsd_csssl_oper_1 *) malloc( sizeof(struct dsd_csssl_oper_1)
                                                 + ADSL_CONN1_G->adsc_server_conf_1->imc_len_dns_name + 1 );
       memset( ADSL_CONN1_G->adsc_csssl_oper_1, 0, sizeof(struct dsd_csssl_oper_1) );
       if (ADSL_CONN1_G->adsc_server_conf_1->imc_len_dns_name) {
         memcpy( ADSL_CONN1_G->adsc_csssl_oper_1 + 1,
                 ADSL_CONN1_G->adsc_server_conf_1->achc_dns_name,  /* address of DNS name */
                 ADSL_CONN1_G->adsc_server_conf_1->imc_len_dns_name );
       }
       *((char *) (ADSL_CONN1_G->adsc_csssl_oper_1 + 1) + ADSL_CONN1_G->adsc_server_conf_1->imc_len_dns_name) = 0;  /* make zero-terminated */
       ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.amc_aux = &m_cdaux;  /* subroutine */
       ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.amc_conn_callback = &m_ssl_conn_cl_compl_cl;
       ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.amc_ocsp_start = &m_ocsp_start;
       ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.amc_ocsp_send = &m_ocsp_send;
       ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.amc_ocsp_recv = &m_ocsp_recv;
       ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.amc_ocsp_stop = &m_ocsp_stop;
       ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.vpc_config_id = adsg_loconf_1_inuse->vpc_csssl_config_id;
       ADSL_CONN1_G->iec_st_ses = ied_ses_wait_csssl;  /* wait for client-side SSL */
     } while (FALSE);
#endif
#ifdef B100731
     if (adsc_server_conf_1->boc_hc_proxauth) {  /* HOBCOM proxy communic */
#ifdef FORKEDIT
//   }
#endif
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
       memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
       adsl_sdhc1_w1->adsc_gather_i_1_i = (struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1);
       adsl_sdhc1_w1->inc_function = DEF_IFUNC_TOSERVER;
       adsl_sdhc1_w1->inc_position = -1;    /* send direct to server   */
       adsl_sdhc1_w1->boc_ready_t_p = TRUE;  /* ready to process       */
       achl1 = (char *) adsl_sdhc1_w1 + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1);  /* start of buffer */
       ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))->achc_ginp_cur
         = (char *) adsl_sdhc1_w1 + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1);  /* start of buffer */
       *achl1++ = (char) 0XFF;
       *achl1++ = (char) 0XFA;
       *achl1++ = (char) 0X28;
#ifdef B080407
#ifndef HL_IPV6
       *achl1++ = (char) 0X60;
       achl2 = (char *) &dcl_tcp_r_c.dclient1.sin_addr;
       inl1 = 4;
#else
       *achl1++ = (char) 0X60;
       if (bog_ipv6 == FALSE) {
         achl2 = (char *) &dcl_tcp_r_c.uncl1.dsoad_client1.sin_addr;
         inl1 = 4;
       } else {
         if (dcl_tcp_r_c.uncl1.dsost_client1.ss_family == AF_INET) {
           achl2 = (char *) (&((struct sockaddr_in *) (&dcl_tcp_r_c.uncl1.dsost_client1))->sin_addr);
           inl1 = 4;
         } else if (dcl_tcp_r_c.uncl1.dsost_client1.ss_family == AF_INET6) {
           achl2 = (char *) (&((struct sockaddr_in6 *) (&dcl_tcp_r_c.uncl1.dsost_client1))->sin6_addr);
           inl1 = 16;
         } else {
           achl2 = "";
           inl1 = 1;
         }
       }
#endif
#endif
#ifndef B080407
       *achl1++ = (char) 0X60;
       if (dcl_tcp_r_c.dsc_soa.ss_family == AF_INET) {
         achl2 = (char *) (&((struct sockaddr_in *) (&dcl_tcp_r_c.dsc_soa))->sin_addr);
         inl1 = 4;
       } else if (dcl_tcp_r_c.dsc_soa.ss_family == AF_INET6) {
         achl2 = (char *) (&((struct sockaddr_in6 *) (&dcl_tcp_r_c.dsc_soa))->sin6_addr);
         inl1 = 16;
       } else {
         achl2 = "";
         inl1 = 1;
       }
#endif
       do {
         *achl1++ = *achl2;
         if (*achl2 == (char) 0XFF) *achl1++ = (char) 0XFF;
         achl2++;
         inl1--;
       } while (inl1 > 0);
       *achl1++ = (char) 0XFF;
       *achl1++ = (char) 0XF0;
       *achl1++ = (char) 0XFF;
       *achl1++ = (char) 0XFA;
       *achl1++ = (char) 0X28;
       *achl1++ = (char) 0X61;
       adsl_auxf_1_w1 = adsc_auxf_1;        /* anchor of extensions    */
       inl1 = 0;                            /* no name found           */
       while (adsl_auxf_1_w1) {             /* loop over chain         */
         if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_certname) {
#ifdef B080205
           /* does UTF-8 contain hexa FF?                              */
           inl1 = m_u8l_from_u16l( achl1,
                                   ((char *) adsl_sdhc1_w1 + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1)) - 2
                                     - achl1,
                                   (HL_WCHAR *) (((int *) (adsl_auxf_1_w1 + 1)) + 1),
                                   *((int *) (adsl_auxf_1_w1 + 1)) );
           if (inl1 >= 0) achl1 += inl1;    /* add length output       */
           else achl1 += ((char *) adsl_sdhc1_w1 + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1)) - 2
                           - achl1;
#else
           inl1 = m_u8l_from_u16l( achl1,
                                   ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - 2)
                                     - achl1,
                                   (HL_WCHAR *) (((int *) (adsl_auxf_1_w1 + 1)) + 1),
                                   *((int *) (adsl_auxf_1_w1 + 1)) );
           if (inl1 > 0) achl1 += inl1;     /* add length output       */
#endif
           break;
         }
         adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
       }
       /* output name from WSP-Socks-mode if no certificate            */
       if (inl1 <= 0) {                     /* no name from certificate */
#ifdef TRACEHL_USER_080202
         m_hlnew_printf( HLOG_XYZ1, "nbipgw20 l%05d clconn1::m_start_rec_server() adsc_user_entry=%p.",
                         __LINE__, adsc_user_entry );
#endif
         if (adsc_user_entry) {             /* structure user entry found */
           achl1 += m_cpy_vx_vx( achl1,
                                 ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - 2)
                                   - achl1,
                                 ied_chs_utf_8,
                                 (adsc_user_entry + 1), -1, ied_chs_utf_16 );
         } else achl1 -= 6;                 /* no user name            */
       }
       *achl1++ = (char) 0XFF;
       *achl1++ = (char) 0XF0;
       ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))->achc_ginp_end = achl1;
       /* send to server immediately                                   */
       adsl_sdhc1_cur_1 = adsc_sdhc1_chain;  /* get chain              */
       adsl_sdhc1_last_1 = NULL;            /* clear last in chain found */
       while (adsl_sdhc1_cur_1) {           /* loop over all buffers   */
         if (   (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER)
             && (adsl_sdhc1_cur_1->inc_position < 0)) {
           break;
         }
         adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* set last in chain found */
         adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
       }
       if (adsl_sdhc1_last_1 == NULL) {     /* insert at start of chain */
         adsc_sdhc1_chain = adsl_sdhc1_w1;
       } else {                             /* insert middle in chain  */
         adsl_sdhc1_last_1->adsc_next = adsl_sdhc1_w1;
       }
     }
#endif
   }
#ifdef D_INCL_HOB_TUN
   goto p_strecs_40;                        /* continue start receive server */

#ifdef B121121
   p_strecs_20:                             /* start HOB-TUN - entry HTCP */
   adsl_soa_w1 = (struct sockaddr *) &adsl_ineta_raws_1_w1->dsc_tun_contr_ineta.dsc_soa_local_ipv4;
   iml_local_namelen = sizeof(struct sockaddr_in);
   iml_rc = getnameinfo( adsl_soa_w1, iml_local_namelen,
                         chrl_ineta_local, sizeof(chrl_ineta_local),
                         0, 0, NI_NUMERICHOST );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPS171W GATE=%(ux)s SNO=%08d INETA=%s getnameinfo local failed with code %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, errno );
     strcpy( chrl_ineta_local, "???" );
   }
   m_hlnew_printf( HLOG_INFO1, "HWSPS172I GATE=%(ux)s SNO=%08d INETA=%s use ineta-appl %s TCP source port %d.",
                   ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, chrl_ineta_local, adsl_ineta_raws_1_w1->usc_appl_port );
   adsl_ineta_raws_1_w1->imc_state = iml_hob_tun_state;  /* value of HOB-TUN state  */
   ADSL_CONN1_G->adsc_ineta_raws_1 = adsl_ineta_raws_1_w1;  /* auxiliary field for HOB-TUN */
   memset( &ADSL_CONN1_G->dsc_tun_contr_conn, 0, sizeof(struct dsd_tun_contr_conn) );  /* HOB-TUN control area connection */
   ADSL_CONN1_G->dsc_tun_contr_conn.iec_tunc = ied_tunc_htcp;  /* HOB-TUN interface type */
   memset( &dsl_tun_start_htcp, 0, sizeof(struct dsd_tun_start_htcp) );  /* HOB-TUN start interface HTCP */
   dsl_tun_start_htcp.adsc_server_ineta = adsl_server_ineta_w1;  /* server INETA */
   dsl_tun_start_htcp.imc_server_port = ADSL_CONN1_G->adsc_server_conf_1->inc_server_port;  /* TCP/IP port connect */
   dsl_tun_start_htcp.boc_connect_round_robin = ADSL_CONN1_G->adsc_server_conf_1->boc_connect_round_robin;  /* do connect round-robin */
   dsl_tun_start_htcp.imc_tcpc_to_msec = adsl_raw_packet_if_conf->imc_tcpc_to_msec;  /* TCP connect timeout milliseconds */
   if (dsl_tun_start_htcp.imc_tcpc_to_msec == 0) {  /* no value configured */
     dsl_tun_start_htcp.imc_tcpc_to_msec = DEF_HTCP_TCPC_TO_MSEC;  /* TCP connect timeout milliseconds */
   }
   dsl_tun_start_htcp.imc_tcpc_try_no = adsl_raw_packet_if_conf->imc_tcpc_try_no;  /* TCP connect number of try */
   if (dsl_tun_start_htcp.imc_tcpc_try_no == 0) {  /* no value configured */
     dsl_tun_start_htcp.imc_tcpc_try_no = DEF_HTCP_TCPC_TRY_NO;  /* TCP connect number of try */
   }
   dsl_tun_start_htcp.boc_tcp_keepalive = adsg_loconf_1_inuse->boc_tcp_keepalive;  /* TCP KEEPALIVE */
   ADSL_CONN1_G->iec_st_ses = ied_ses_wait_conn_s_static;  /* wait for static connect to server */
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_htun;  /* HOB-TUN     */
   ADSL_CONN1_G->adsc_sdhc1_htun_sch = NULL;  /* no buffers to send    */
   ADSL_CONN1_G->imc_send_window = 0;       /* number of bytes to be sent */
   adsl_ineta_raws_1_w1->ac_conn1 = ADSL_CONN1_G;  /* set connection   */
   dsl_tun_start_htcp.adsc_htun_h = (dsd_htun_h *) &adsl_ineta_raws_1_w1->dsc_htun_h;  /* where to put the handle created */
   m_hl_lock_inc_1( &ADSL_CONN1_G->imc_references );  /* references to this session */
   m_htun_new_sess_htcp( &dsl_tun_start_htcp,
                         &ADSL_CONN1_G->dsc_tun_contr_conn,  /* HOB-TUN control area connection */
                         &adsl_ineta_raws_1_w1->dsc_tun_contr_ineta );  /* HOB-TUN control interface for INETA */
   ADSL_CONN1_G->dsc_htun_h = adsl_ineta_raws_1_w1->dsc_htun_h;  /* handle created */
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T clconn1::m_start_rec_server() m_htun_new_sess_htcp() handle %p &dsc_tun_contr_conn=%p.",
                   __LINE__, adsl_ineta_raws_1_w1->dsc_htun_h, &ADSL_CONN1_G->dsc_tun_contr_conn );
   return;                                  /* wait till connect complete */
#endif

   p_strecs_24:                             /* start HOB-TUN - PPP     */
#ifdef XYZ1
   iel_irs_def = ied_ineta_raws_n_ipv4;     /* INETA IPV4              */
   adsl_ineta_raws_1_w1 = m_prepare_htun_ineta( &dsl_tun_start1.dsc_soa_local,
                                                &iml_local_namelen,
                                                this,
                                                ADSL_AUX_CF1->adsc_hco_wothr,
                                                iel_irs_def );
   if (adsl_ineta_raws_1_w1 == NULL) {      /* no INETA found          */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s tries to start raw-interface PPP but no ineta-ppp available",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta );
#define DEF_HTUN_ERR_NO_INETA 123
     if (ADSL_CONN1_G->adsc_wsp_auth_1) {   /* authentication active   */
       ADSL_CONN1_G->adsc_wsp_auth_1->imc_connect_error = DEF_HTUN_ERR_NO_INETA;
       ADSL_CONN1_G->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
       ADSL_CONN1_G->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
       return;
     }
// to-do 03.07.10 KB we return now, we do not need to start the SDHs
     ADSL_CONN1_G->iec_st_ses = ied_ses_error_conn;  /* status server error */
     if (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic == FALSE) return;  /* not dynamicly allocated */
     ADSL_CONN1_G->iec_st_ses = ied_ses_error_co_dyn;  /* status server error */
     return;
   }
   adsl_soa_w1 = (struct sockaddr *) &adsl_ineta_raws_1_w1->dsc_tun_contr_ineta.dsc_soa_local_ipv4;
   iml_local_namelen = sizeof(struct sockaddr_in);
   iml_rc = getnameinfo( adsl_soa_w1, iml_local_namelen,
                         chrl_ineta_local, sizeof(chrl_ineta_local),
                         0, 0, NI_NUMERICHOST );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s getnameinfo local failed with code %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, errno );
   } else {
     m_hlnew_printf( HLOG_INFO1, "HWSPSnnnI GATE=%(ux)s SNO=%08d INETA=%s use ineta-ppp %s.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, ADSL_CONN1_G->chrl_ineta_local );
   }
   switch (ADSL_CONN1_G->adsc_server_conf_1->inc_function) {
     case DEF_FUNC_HPPPT1:
       adsl_ineta_raws_1_w1->dsc_tun_contr_conn.iec_tunc = ied_tunc_ppp;  /* PPP type session */
       break;
     case DEF_FUNC_SSTP:                  /* set function SSTP Tunnel */
       adsl_ineta_raws_1_w1->dsc_tun_contr_conn.iec_tunc = ied_tunc_sstp;  /* SSTP type session */
       break;
   }
#endif
#ifdef NEW_HOB_TUN_1103
   switch (adsc_server_conf_1->inc_function) {
     case DEF_FUNC_HPPPT1:
       dsc_tun_contr_conn.iec_tunc = ied_tunc_ppp;  /* PPP type session   */
       break;
     case DEF_FUNC_SSTP:                  /* set function SSTP Tunnel */
       dsc_tun_contr_conn.iec_tunc = ied_tunc_sstp;  /* SSTP type session */
       break;
   }
#endif
   adsl_raw_packet_if_conf = adsg_loconf_1_inuse->adsc_raw_packet_if_conf;  /* configuration raw-packet-interface */
#define DEF_HTUN_ERR_NO_CONF 124
   if (adsl_raw_packet_if_conf == NULL) {  /* cannot start HOB-TUN */
     if (ADSL_CONN1_G->adsc_wsp_auth_1) {  /* authentication active */
// to-do 16.09.12 KB - other error number
       ADSL_CONN1_G->adsc_wsp_auth_1->imc_connect_error = DEF_HTUN_ERR_NO_CONF;
       ADSL_CONN1_G->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
       ADSL_CONN1_G->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
       return;
     }
     ADSL_CONN1_G->iec_st_ses = ied_ses_error_conn;  /* status server error */
     if (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic == FALSE) return;  /* not dynamicly allocated */
     ADSL_CONN1_G->iec_st_ses = ied_ses_error_co_dyn;  /* status server error */
     return;
   }
#ifdef XYZ1
   if (adsg_loconf_1_inuse->adsc_raw_packet_if_conf) {  /* configuration raw-packet-interface */
     dsl_tun_start1.adsc_wsptun_conf_1
       = &adsg_loconf_1_inuse->adsc_raw_packet_if_conf->dsc_wsptun_conf_1;  /* TUN PPP INETAs */
   }
#endif
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_htun;  /* HOB-TUN     */
   ADSL_CONN1_G->adsc_sdhc1_htun_sch = NULL;  /* no buffers to send    */
   ADSL_CONN1_G->imc_send_window = 0;       /* number of bytes to be sent */
   ADSL_CONN1_G->imc_ppp_state = 0;         /* PPP state               */
   ADSL_CONN1_G->adsc_ppp_netw_post_1 = NULL;  /* structure to post from network callback */
   dsl_tun_start_ppp.adsc_htun_h = (void **) &ADSL_CONN1_G->dsc_htun_h;  /* where to put the handle created */
   m_htun_new_sess_ppp( &dsl_tun_start_ppp, &ADSL_CONN1_G->dsc_tun_contr_conn );
   ADSL_CONN1_G->iec_st_ses = ied_ses_start_server_1;  /* status server continue */
   if (ADSL_CONN1_G->adsc_wsp_auth_1) {     /* authentication active   */
     ADSL_CONN1_G->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
     ADSL_CONN1_G->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
     return;
   }
   if (ADSL_CONN1_G->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
     ADSL_CONN1_G->adsc_int_webso_conn_1->boc_did_connect = TRUE;  /* did connect */
     ADSL_CONN1_G->adsc_int_webso_conn_1->boc_notify = TRUE;  /* notify SDH */
     return;
   }

#endif

   p_strecs_40:                             /* continue start receive server */
#ifndef TJ_B170809
   if (ADSL_CONN1_G->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
     ADSL_CONN1_G->adsc_int_webso_conn_1->boc_did_connect = TRUE;  /* did connect */
     ADSL_CONN1_G->adsc_int_webso_conn_1->boc_notify = TRUE;  /* notify SDH */
     ADSL_CONN1_G->iec_st_ses = ied_ses_conn;  /* normal state of session */
     ADSL_CONN1_G->boc_signal_set = TRUE;  /* signal for component set */
   }
#endif

#ifndef B100731
   if (ADSL_CONN1_G->iec_st_ses == ied_ses_start_server_2) {  /* status server */
     ADSL_CONN1_G->iec_st_ses = ied_ses_start_sdh;  /* start Server-Data-Hooks */
     bol_start_sdh = TRUE;                  /* start Server-Data-Hook  */
     if (ADSL_CONN1_G->adsc_server_conf_1->boc_hc_proxauth) {  /* HOBCOM proxy communic */
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
       memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
       adsl_sdhc1_w1->adsc_gather_i_1_i = (struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1);
       adsl_sdhc1_w1->inc_function = DEF_IFUNC_TOSERVER;
       adsl_sdhc1_w1->inc_position = -1;    /* send direct to server   */
#ifdef B120808
       adsl_sdhc1_w1->boc_ready_t_p = TRUE;  /* ready to process       */
#else
       adsl_sdhc1_w1->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
#endif
       achl1 = (char *) adsl_sdhc1_w1 + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1);  /* start of buffer */
       ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))->achc_ginp_cur
         = (char *) adsl_sdhc1_w1 + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1);  /* start of buffer */
       *achl1++ = (char) 0XFF;
       *achl1++ = (char) 0XFA;
       *achl1++ = (char) 0X28;
       *achl1++ = (char) 0X60;
       if (ADSL_CONN1_G->dsc_tc1_client.dsc_soa_conn.ss_family == AF_INET) {
         achl2 = (char *) (&((struct sockaddr_in *) (&ADSL_CONN1_G->dsc_tc1_client.dsc_soa_conn))->sin_addr);
         inl1 = 4;
       } else if (ADSL_CONN1_G->dsc_tc1_client.dsc_soa_conn.ss_family == AF_INET6) {
         achl2 = (char *) (&((struct sockaddr_in6 *) (&ADSL_CONN1_G->dsc_tc1_client.dsc_soa_conn))->sin6_addr);
         inl1 = 16;
       } else {
         achl2 = "";
         inl1 = 1;
       }
       do {
         *achl1++ = *achl2;
         if (*achl2 == (char) 0XFF) *achl1++ = (char) 0XFF;
         achl2++;
         inl1--;
       } while (inl1 > 0);
       *achl1++ = (char) 0XFF;
       *achl1++ = (char) 0XF0;
       *achl1++ = (char) 0XFF;
       *achl1++ = (char) 0XFA;
       *achl1++ = (char) 0X28;
       *achl1++ = (char) 0X61;
       adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* anchor of extensions */
       inl1 = 0;                            /* no name found           */
       while (adsl_auxf_1_w1) {             /* loop over chain         */
         if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_certname) {
           inl1 = m_u8l_from_u16l( achl1,
                                   ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - 2)
                                     - achl1,
                                   (HL_WCHAR *) (((int *) (adsl_auxf_1_w1 + 1)) + 1),
                                   *((int *) (adsl_auxf_1_w1 + 1)) );
           if (inl1 > 0) achl1 += inl1;     /* add length output       */
           break;
         }
         adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
       }
       /* output name from WSP-Socks-mode if no certificate            */
       if (inl1 <= 0) {                     /* no name from certificate */
#ifdef TRACEHL_USER_080202
         m_hlnew_printf( HLOG_XYZ1, "nbipgw20 l%05d clconn1::m_start_rec_server() adsc_user_entry=%p.",
                         __LINE__, adsc_user_entry );
#endif
         if (ADSL_CONN1_G->adsc_user_entry) {  /* structure user entry found */
           achl1 += m_cpy_vx_vx( achl1,
                                 ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - 2)
                                   - achl1,
                                 ied_chs_utf_8,
                                 ADSL_CONN1_G->adsc_user_entry + 1, -1, ied_chs_utf_16 );
         } else achl1 -= 6;                 /* no user name            */
       }
       *achl1++ = (char) 0XFF;
       *achl1++ = (char) 0XF0;
       ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))->achc_ginp_end = achl1;
       /* send to server immediately                                   */
       adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain */
       adsl_sdhc1_last_1 = NULL;            /* clear last in chain found */
       while (adsl_sdhc1_cur_1) {           /* loop over all buffers   */
         if (   (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER)
             && (adsl_sdhc1_cur_1->inc_position < 0)) {
           break;
         }
         adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* set last in chain found */
         adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
       }
       if (adsl_sdhc1_last_1 == NULL) {     /* insert at start of chain */
         ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_w1;
       } else {                             /* insert middle in chain  */
         adsl_sdhc1_last_1->adsc_next = adsl_sdhc1_w1;
       }
     }
   }
#endif
   if (bol_start_sdh == FALSE) return;      /* start Server-Data-Hook  */
// if (adsc_server_conf_1 == NULL) return;  /* no server               */
//#ifdef B100830
   if (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh == 0) return;  /* no server-data-hook */
//#endif
#ifdef B100830_XXX
   if (adsc_server_conf_1->inc_no_sdh == 0) {  /* no server-data-hook  */
     iec_st_ses = ied_ses_conn;             /* do not start Server-Data-Hooks */
     return;
   }
#endif
#ifndef X101214_XX
#ifdef B101208
   if (adsc_server_conf_1->boc_dynamic) {   /* dynamicly allocated     */
     iec_st_ses = ied_ses_conn;             /* do not start Server-Data-Hooks */
     return;
   }
#else
#ifdef B101214
   if (adsc_server_conf_1->adsc_seco1_previous) {  /* configuration server previous */
     iec_st_ses = ied_ses_conn;             /* do not start Server-Data-Hooks */
     return;
   }
#ifdef XYZ1
   if (   (adsc_server_conf_1->boc_dynamic)  /* dynamicly allocated    */
       && (ADSL_CONN1_G->iec_servcotype != ied_servcotype_none)) {  /* with server connection */
     iec_st_ses = ied_ses_conn;             /* do not start Server-Data-Hooks */
     return;
   }
#endif
#endif
#endif
#endif
#ifndef B101214
#ifdef B110207_XXX
   iec_st_ses = ied_ses_conn;               /* Server-Data-Hooks have started */
#endif
   if (   (ADSL_CONN1_G->adsc_server_conf_1->adsc_seco1_previous)  /* configuration server previous */
       || (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh == 0)  /* no server-data-hook */
       || (ADSL_CONN1_G->boc_sdh_started)) {  /* Server-Data-Hooks have been started */
#ifndef B110207_XXX
     ADSL_CONN1_G->iec_st_ses = ied_ses_conn;  /* do not start Server-Data-Hooks */
#endif
     return;
   }
#ifdef B110211_XXX
   if (iec_servcotype != ied_servcotype_none) {  /* with server connection */
     iec_st_ses = ied_ses_conn;             /* session connected to server */
   }
#endif
   ADSL_CONN1_G->boc_sdh_started = TRUE;    /* Server-Data-Hooks have been started */
#endif
   inl1 = 0;                                /* count the hooks         */

#ifdef B080609
#define ADSL_SDH_LIB1 ((struct dsd_sdh_work_1 *) \
                        ((char *) (ADSL_CONN1_G->adsc_server_conf_1 + 1) \
                          + inl1 * sizeof(struct dsd_sdh_work_1)))->adsc_sdhl_1
#endif
#define ADSL_SDH_LIB1 ((struct dsd_sdh_work_1 *) \
                        ((char *) (ADSL_CONN1_G->adsc_server_conf_1 + 1) \
                          + inl1 * sizeof(struct dsd_sdh_work_1)))->adsc_ext_lib1
//#ifdef TRACEHL1
#ifdef DEBUG_120808_01                      /* debug start SDHs        */
   m_hlnew_printf( HLOG_XYZ1, "before pstsdh20 adsc_server_conf_1=%p ...(struct)=%p ADSL_SDH_LIB1=%p",
                   ADSL_CONN1_G->adsc_server_conf_1,
                   ((char *) (ADSL_CONN1_G->adsc_server_conf_1 + 1) + inl1 * sizeof(struct dsd_sdh_work_1)),
                   ADSL_SDH_LIB1 );
#endif

   pstsdh20:                                /* start Server-Data-Hook  */
   memset( &dsl_sdh_l1, 0, sizeof(dsl_sdh_l1) );
   if (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh < 2) {
     dsl_sdh_l1.ac_ext = ADSL_CONN1_G->dsc_sdh_s_1.ac_ext;  /* attached buffer pointer */
//   bol1 = ADSL_CONN1_G->dsc_sdh_s_1.boc_ended;  /* processing of this SDH has ended */
   } else {
     dsl_sdh_l1.ac_ext = ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].ac_ext;  /* attached buffer pointer */
//   bol1 = ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].boc_ended;  /* processing of this SDH has ended */
   }
   dsl_sdh_l1.inc_func = DEF_IFUNC_START;
   dsl_sdh_l1.vpc_userfld = ADSL_AUX_CF1;   /* pointer to parameter area */
#ifdef B130314
   ADSL_AUX_CF1->iec_src_func = ied_src_fu_sdh;  /* Server-Data-Hook   */
   /* current Server-Data-Hook                                         */
   ADSL_AUX_CF1->ac_sdh
     = (void *) ((char *) (ADSL_CONN1_G->adsc_server_conf_1 + 1) + inl1 * sizeof(struct dsd_sdh_work_1));
#endif
   ADSL_AUX_CF1->dsc_cid.iec_src_func = ied_src_fu_sdh;  /* Server-Data-Hook */
   /* current Server-Data-Hook                                         */
   ADSL_AUX_CF1->dsc_cid.ac_cid_addr
     = (void *) ((char *) (ADSL_CONN1_G->adsc_server_conf_1 + 1) + inl1 * sizeof(struct dsd_sdh_work_1));
   dsl_sdh_l1.amc_aux = &m_cdaux;           /* subroutine              */
   dsl_sdh_l1.ac_conf = ((struct dsd_sdh_work_1 *) \
                          ((char *) (ADSL_CONN1_G->adsc_server_conf_1 + 1) \
                            + inl1 * sizeof(struct dsd_sdh_work_1)))->ac_conf;
   dsl_sdh_l1.ac_hobwspat3_conf = ADSL_CONN1_G->adsc_gate1->vpc_hobwspat3_conf;  /* configuration authentication library */
   /* flags of configuration                                           */
   if (ADSL_CONN1_G->adsc_gate1->inc_no_usgro) {  /* user group defined */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_USERLI;
   }
   if (ADSL_CONN1_G->adsc_gate1->imc_no_radius) {  /* radius server defined */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_RADIUS;
     if (ADSL_CONN1_G->adsc_gate1->imc_no_radius > 1) {  /* multiple radius server defined */
       dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_RADIUS;
     }
   }
   if (ADSL_CONN1_G->adsc_gate1->imc_no_krb5_kdc) {  /* number of Kerberos 5 KDCs */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_KRB5;  /* Kerberos 5 KDC defined */
     if (ADSL_CONN1_G->adsc_gate1->imc_no_krb5_kdc > 1) {  /* number of Kerberos 5 KDCs */
       dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_KRB5;  /* dynamic Kerberos 5 KDC defined */
     }
   }
   if (ADSL_CONN1_G->adsc_gate1->imc_no_ldap_group) {  /* number of LDAP groups   */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_LDAP;  /* LDAP group defined */
     if (ADSL_CONN1_G->adsc_gate1->imc_no_ldap_group > 1) {  /* number of LDAP groups */
       dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_LDAP;  /* dynamic LDAP groups defined */
     }
   }
   dsl_sdh_l1.imc_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* session number */
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SDH_INT) {  /* WSP Trace SDH intern */
     dsl_sdh_l1.imc_trace_level
       = HL_AUX_WT_ALL                      /* WSP Trace SDH all       */
           | (ADSL_CONN1_G->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2));
   }
#ifdef TRACEHL1
   {
     void *vph1, *vph2;
     vph1 = ADSL_SDH_LIB1;
     vph2 = (void *) ADSL_SDH_LIB1->amc_hlclib01;
     m_hlnew_printf( HLOG_XYZ1, "pstsdh20 addr method1 amc_hlclib01=%p.", vph2 );
   }
#endif
#ifdef TRACEHL_P_050118
   {
     struct dsd_gather_i_1 *adsh_gather_i_1_1;  /* gather data         */
     adsh_gather_i_1_1 = dsl_sdh_l1.adsc_gather_i_1_in;
     while (adsh_gather_i_1_1) {
       if (   (adsh_gather_i_1_1->achc_ginp_cur < adsh_gather_i_1_1->achc_ginp_end)
           && (*adsh_gather_i_1_1->achc_ginp_cur >= 0X05)) {
         ims_p_050118++;
       }
       adsh_gather_i_1_1 = adsh_gather_i_1_1->adsc_next;
     }
     adsh_gather_i_1_1 = dsl_sdh_l1.adsc_gather_i_1_out;
     while (adsh_gather_i_1_1) {
       if (   (adsh_gather_i_1_1->achc_ginp_cur < adsh_gather_i_1_1->achc_ginp_end)
           && (*adsh_gather_i_1_1->achc_ginp_cur >= 0X05)) {
         ims_p_050118++;
       }
       adsh_gather_i_1_1 = adsh_gather_i_1_1->adsc_next;
     }
   }
#endif
   ADSL_SDH_LIB1->amc_hlclib01( &dsl_sdh_l1 );
#ifdef TRACEHL_P_050118
   {
     struct dsd_gather_i_1 *adsh_gather_i_1_1;  /* gather data         */
     adsh_gather_i_1_1 = dsl_sdh_l1.adsc_gather_i_1_in;
     while (adsh_gather_i_1_1) {
       if (   (adsh_gather_i_1_1->achc_ginp_cur < adsh_gather_i_1_1->achc_ginp_end)
           && (*adsh_gather_i_1_1->achc_ginp_cur >= 0X05)) {
         ims_p_050118++;
       }
       adsh_gather_i_1_1 = adsh_gather_i_1_1->adsc_next;
     }
     adsh_gather_i_1_1 = dsl_sdh_l1.adsc_gather_i_1_out;
     while (adsh_gather_i_1_1) {
       if (   (adsh_gather_i_1_1->achc_ginp_cur < adsh_gather_i_1_1->achc_ginp_end)
           && (*adsh_gather_i_1_1->achc_ginp_cur >= 0X05)) {
         ims_p_050118++;
       }
       adsh_gather_i_1_1 = adsh_gather_i_1_1->adsc_next;
     }
   }
#endif
   if (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh < 2) {
     ADSL_CONN1_G->dsc_sdh_s_1.ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   } else {
     ADSL_CONN1_G->adsrc_sdh_s_1[ inl1 ].ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   }
   if (dsl_sdh_l1.inc_return != DEF_IRET_NORMAL) {
     if (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh < 2) {
       ADSL_CONN1_G->dsc_sdh_s_1.boc_ended = TRUE;  /* processing of this SDH has ended */
     } else {
       ADSL_CONN1_G->adsrc_sdh_s_1[ inl1 ].boc_ended = TRUE;  /* processing of this SDH has ended */
     }
#ifdef NOT_YET
     dsl_sdh_l1.boc_callagain = FALSE;      /* do not process last server-data-hook again */
     dsl_sdh_l1.boc_callrevdir = FALSE;     /* not requested to call again in reverse direction */
#endif
   }
#undef ADSL_SDH_LIB1

   /* process next Server-Data-Hook                                    */
   inl1++;                                  /* increment no se-da-hook */
   if (inl1 < ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh) goto pstsdh20;
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
   return;
} /* m_start_rec_server()                                              */

/** send TCP/IP gather to client or server, also from TCPCOMP thread   */
static void m_send_clse_tcp_1( struct dsd_conn1 *adsp_conn1,
                               struct dsd_tcp_ctrl_1 *adsp_tcp_ctrl_1,
                               struct dsd_sdh_control_1 *adsp_sdhc1_send,
                               BOOL bop_tcpco_thread ) {
   BOOL       bol1;                         /* working variable        */
   BOOL       bol_cont;                     /* continue to send        */
   BOOL       bol_notify;                   /* send not complete       */
   int        iml_rc;                       /* return code             */
   int        iml1, iml2, iml3, iml4;       /* working variables       */
   int        iml_gai1;                     /* count send buffers      */
//     unsigned int uml_wsabuf;             /* number of WSABUF        */
   unsigned int uml_sent;                   /* bytes sent              */
#ifdef NEW_REPORT_1501
   dsd_time_1 dsl_time_cur;                 /* current time            */
#endif
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_sdh_control_1 *adsl_sdhc1_send;  /* chain to send        */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working variable       */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* working variable        */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   struct dsd_send_gai1_1 dsrl_send_gai1_1[ DEF_SEND_IOVEC ];  /* block passed to send function */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_send_clse_tcp_1( %p , %p , %p , %d )",
                   __LINE__, adsp_conn1, adsp_tcp_ctrl_1, adsp_sdhc1_send, bop_tcpco_thread );
#endif
#ifdef DEBUG_120710_01                      /* flow-control send       */
    m_hlnew_printf( HLOG_TRACE1, "DEBUG_120710_01 l%05d m_send_clse_tcp_1( %p , %p , %p , %d )",
                    __LINE__, adsp_conn1, adsp_tcp_ctrl_1, adsp_sdhc1_send, bop_tcpco_thread );
#endif
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = m_clconn1_get_sdhc1_chain( aclconn1 );  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "nbipgw20-l%05d m_send_gather start", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
   adsl_sdhc1_send = adsp_sdhc1_send;   /* chain to send           */

#ifdef TRACE_HL_SESS_01
   iml1 = 30;
   if (bop_tcpco_thread) iml1 = 31;
   m_clconn1_last_action( aclconn1, iml1 );  /* last action        */
#endif  /* TRACE_HL_SESS_01 */
#ifdef TRACEHL_SEND
   iml1 = 0;                            /* clear count             */
   adsl_sdhc1_w1 = adsl_sdhc1_send;     /* get chain to send       */
   do {                                 /* loop over chain sdhc1   */
     adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
     do {                               /* loop over chain gai1    */
       iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
     } while (adsl_gai1_w1);
     while (adsl_gai1_w1) {             /* loop over chain gai1    */
       iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
     }
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
   } while (adsl_sdhc1_w1);
   if (bop_tcpco_thread == FALSE) {
     inc_trace_end += iml1;
   }
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20 l%05d cl_tcp_r=%p m_send_gather() bop_tcpco_thread=%d adsp_tcp_ctrl_1->adsc_sdhc1_send=%p new=%d inc_trace_end=%d inc_trace_all=%d",
                   __LINE__, adsp_tcp_ctrl_1, bop_tcpco_thread, adsp_tcp_ctrl_1->adsc_sdhc1_send, iml1, inc_trace_end, inc_trace_all );
#endif
   bol_notify = FALSE;                  /* send not complete       */

   psend10:
#ifdef B080407
   bo_may_send = FALSE;
#endif
// 15.08.10 KB remove boTCPIPconn and use imc_conn_state
#ifdef B100827
   if (boTCPIPconn == FALSE) {          /* TCP/IP connection closed */
#ifdef FORKEDIT
   }
#endif
#endif
#ifdef NOT_YET_110814
   if (imc_conn_state != -1) {          /* state of the connection not connected */
     char *achl_w1 = "client";
     if (adsp_tcp_ctrl_1 != &adsp_conn1->dsc_tc1_client) achl_w1 = "server";
     m_hlnew_printf( HLOG_WARN1, "HWSPS017W GATE=%(ux)s SNO=%08d INETA=%s %s TCP/IP send data after socket closed",
                     adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, achl_w1 );
     /* free buffers                                                   */
     while (adsl_sdhc1_send) {              /* loop over all buffers   */
       adsl_sdhc1_w1 = adsl_sdhc1_send;     /* save this buffer        */
       adsl_sdhc1_send = adsl_sdhc1_send->adsc_next;  /* get next in chain */
       if (adsl_sdhc1_w1->imc_usage_count == 0) {  /* not in use       */
         m_proc_free( adsl_sdhc1_w1 );      /* free this buffer        */
       } else {                             /* work area still in use  */
         iml_rc = adsp_conn1->dsc_critsect.m_enter();  /* enter CriticalSection */
         if (iml_rc < 0) {                  /* error occured           */
// to-do 09.08.11 KB error number
           m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_enter() critical section failed %d.",
                           adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
         }
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
         m_hlnew_printf( HLOG_TRACE1, "nbipgw20.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                         __LINE__, HL_THRID, &adsp_conn1->dsc_critsect );
#endif
         adsl_sdhc1_w1->adsc_next = adsp_conn1->adsc_sdhc1_inuse;  /* chain of buffers in use */
         adsp_conn1->adsc_sdhc1_inuse = adsl_sdhc1_w1;  /* append to chain */
         iml_rc = adsp_conn1->dsc_critsect.m_leave();  /* leave CriticalSection */
         if (iml_rc < 0) {                  /* error occured           */
// to-do 09.08.11 KB error number
           m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_leave() critical section failed %d.",
                           adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
         }
       }
     }
#ifdef TRACE_HL_SESS_01
     iml1 = 32;
     if (bop_tcpco_thread) iml1 = 33;
     m_clconn1_last_action( aclconn1, iml1 );  /* last action        */
#endif  /* TRACE_HL_SESS_01 */
     return;
   }
#endif
   if (   (bop_tcpco_thread == FALSE)       /* not from TCP thread     */
       && (adsp_tcp_ctrl_1->adsc_sdhc1_send)) {  /* already send chain */
     m_hlnew_printf( HLOG_WARN1, "HWSPSxxxW GATE=%(ux)s SNO=%08d INETA=%s m_send_clse_tcp_1() logic error send already active",
                     adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta );
     /* free send buffers                                              */
     adsl_sdhc1_w1 = adsl_sdhc1_send;       /* get chain to send       */
#ifdef B141124
     do {                               /* loop over chain sdhc1   */
       if (adsl_sdhc1_w1->imc_usage_count == 0) {  /* not in use   */
         m_proc_free( adsl_sdhc1_w1 );  /* free this buffer        */
       } else {                         /* work area still in use  */
         iml_rc = adsp_conn1->dsc_critsect.m_enter();  /* enter CriticalSection */
         if (iml_rc < 0) {                  /* error occured           */
// to-do 09.08.11 KB error number
           m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_enter() critical section failed %d.",
                           adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
         }
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
         m_hlnew_printf( HLOG_TRACE1, "nbipgw20.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                         __LINE__, HL_THRID, &adsp_conn1->dsc_critsect );
#endif
         adsl_sdhc1_w1->adsc_next = adsp_conn1->adsc_sdhc1_inuse;  /* chain of buffers in use */
         adsp_conn1->adsc_sdhc1_inuse = adsl_sdhc1_w1;  /* append to chain */
         iml_rc = adsp_conn1->dsc_critsect.m_leave();  /* leave CriticalSection */
         if (iml_rc < 0) {                  /* error occured           */
// to-do 09.08.11 KB error number
           m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_leave() critical section failed %d.",
                           adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
         }
       }
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     } while (adsl_sdhc1_w1);
#endif
#ifndef B141124
     do {                                   /* loop over chain sdhc1   */
       adsl_sdhc1_w2 = adsl_sdhc1_w1;       /* save this entry         */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       if (adsl_sdhc1_w2->imc_usage_count == 0) {  /* not in use       */
         m_proc_free( adsl_sdhc1_w2 );      /* free this buffer        */
       } else {                             /* work area still in use  */
         iml_rc = adsp_conn1->dsc_critsect.m_enter();  /* enter CriticalSection */
         if (iml_rc < 0) {                  /* error occured           */
// to-do 09.08.11 KB error number
           m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_enter() critical section failed %d.",
                           adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
         }
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
         m_hlnew_printf( HLOG_TRACE1, "nbipgw20.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                         __LINE__, HL_THRID, &adsp_conn1->dsc_critsect );
#endif
         adsl_sdhc1_w2->adsc_next = adsp_conn1->adsc_sdhc1_inuse;  /* chain of buffers in use */
         adsp_conn1->adsc_sdhc1_inuse = adsl_sdhc1_w2;  /* append to chain */
         iml_rc = adsp_conn1->dsc_critsect.m_leave();  /* leave CriticalSection */
         if (iml_rc < 0) {                  /* error occured           */
// to-do 09.08.11 KB error number
           m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_leave() critical section failed %d.",
                           adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
         }
       }
     } while (adsl_sdhc1_w1);
#endif
#ifdef TRACE_HL_SESS_01
     iml1 = 34;
     if (bop_tcpco_thread) iml1 = 35;
     m_clconn1_last_action( aclconn1, iml1 );  /* last action        */
#endif  /* TRACE_HL_SESS_01 */
     return;
#ifdef B090615
// to-do 12.05.09 KB - data may be lost - prevent sending in xiipgw08-pd-main.cpp
     m_clconn1_critsect_enter( aclconn1 );
#ifdef B080407
     if (bo_may_send) {
       m_clconn1_critsect_leave( aclconn1 );
       goto psend10;                    /* try again               */
     }
#endif
#ifdef B090512
     if (this->adsc_sdhc1_send) {       /* already chain to send   */
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) this->adsc_sdhc1_send;  /* get start of chain */
     }
#endif
     adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) adsp_tcp_ctrl_1->adsc_sdhc1_send;  /* get start of chain */
     if (adsl_sdhc1_w1) {               /* already chain to send   */
       do {                             /* loop over all old buffers */
         adsl_sdhc1_w2 = adsl_sdhc1_w1;  /* save last entry        */
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       } while (adsl_sdhc1_w1);
       adsl_sdhc1_w2->adsc_next = adsl_sdhc1_send;  /* append new buffers to chain */
       m_clconn1_critsect_leave( aclconn1 );
#ifdef TRACEHL_SEND
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20 l%05d cl_tcp_r=%p m_send_gather() bop_tcpco_thread=%d adsp_tcp_ctrl_1->adsc_sdhc1_send=%p append to chain",
                       __LINE__, adsp_tcp_ctrl_1, bop_tcpco_thread, adsp_tcp_ctrl_1->adsc_sdhc1_send );
#endif
       return;
     }
     m_clconn1_critsect_leave( aclconn1 );
#endif
   }
#ifdef TRACE_091013_01
   if (adsp_tcp_ctrl_1 == &adsp_conn1->dsc_tc1_client) {
     int imh2 = 0;                      /* count gather            */
     iml1 = 0;                          /* clear length to send    */
     adsl_sdhc1_w1 = adsl_sdhc1_send;   /* get chain to send       */
     do {                               /* loop over all data to send */
       adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
       while (adsl_gai1_w1) {           /* loop over chain gai1    */
         iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         imh2++;                        /* count gather            */
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       }
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     } while (adsl_sdhc1_w1);
     m_hlnew_printf( HLOG_TRACE1, "HWSPSxxxW GATE=%(ux)s SNO=%08d INETA=%s count m_send_gather() to client gather=%d length=%d/0X%08X.",
                     m_clconn1_gatename( aclconn1 ),
                     m_clconn1_sno( aclconn1 ),
                     m_clconn1_chrc_ineta( aclconn1 ),
                     imh2, iml1, iml1 );
   }
#endif
#ifndef TJ_B171005 
       // In case of session end, data may be sent by work-thread although sending
       // data from TCPCOMP thread is active / scheduled
       if (bop_tcpco_thread) {                   /* from TCP thread         */
          adsp_conn1->dsc_critsect.m_enter();
       }
#endif //TJ_B171005
   do {                                 /* loop till all sent      */
     bol_cont = FALSE;                  /* reset continue to send  */
     iml_gai1 = 0;                      /* number of buffers       */
     adsl_sdhc1_w1 = adsl_sdhc1_send;   /* get chain to send       */
#ifdef TRY_110805_01
     iml1 = TRY_110805_01;
#endif
     do {                               /* loop over chain sdhc1   */
       adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
#ifndef PROB070717
       do {                             /* loop over chain gai1    */
#else
       while (adsl_gai1_w1) {           /* loop over chain gai1    */
#endif
         /* check if not already sent before                       */
         adsl_sdhc1_w2 = adsl_sdhc1_send;  /* get chain to send    */
         adsl_gai1_w2 = NULL;           /* not found till now      */
         while (TRUE) {                 /* loop till this element found */
           if (adsl_sdhc1_w2 == adsl_sdhc1_w1) break;  /* this element found */
           adsl_gai1_w2 = adsl_sdhc1_w2->adsc_gather_i_1_i;  /* get chain to send */
           while (adsl_gai1_w2) {       /* loop over all gather structures */
             if (adsl_gai1_w2 == adsl_gai1_w1) break;  /* same element sent before */
             adsl_gai1_w2 = adsl_gai1_w2->adsc_next;  /* get next in chain */
           }
           if (adsl_gai1_w2) break;     /* element sent before     */
           adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;  /* get next in chain */
           if (adsl_sdhc1_w2 == NULL) {
             m_hlnew_printf( HLOG_WARN1, "HWSPSxxxW GATE=%(ux)s SNO=%08d INETA=%s m_send_gather() logic error or chain corrupted",
                             adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta );
             break;
           }
         }
         if (adsl_gai1_w2 == NULL) {    /* this gather structure not sent before */
#ifndef TRY_110805_01
           if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) {
#ifdef TRACE_091121_01
             {
               unsigned char ucrh_cmp_01[] = { 0X03, 0X00, 0X00, 0X7A };
               if (!memcmp( adsl_gai1_w1->achc_ginp_cur, ucrh_cmp_01, sizeof(ucrh_cmp_01) )) {
                 m_hlnew_printf( HLOG_XYZ1, "l%05d m_send_gather() iml_gai1=%d achc_ginp_cur=%p achc_ginp_end=%p len=%d/0X%p.",
                                 __LINE__, iml_gai1,
                                 adsl_gai1_w1->achc_ginp_cur,
                                 adsl_gai1_w1->achc_ginp_end,
                                 adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur,
                                 adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur );
               }
             }
#endif
#ifdef TRY_090429_01
             if (iml_gai1 >= DEF_SEND_WSASEND) {
               bol_cont = TRUE;         /* continue processing     */
               break;
             }
#endif
#ifdef TRACEHL_090429_01
             m_hlnew_printf( HLOG_XYZ1, "l%05d m_send_gather() iml_gai1=%d achc_ginp_cur=%p achc_ginp_end=%p len=%d/0X%p.",
                             __LINE__, iml_gai1,
                             adsl_gai1_w1->achc_ginp_cur,
                             adsl_gai1_w1->achc_ginp_end,
                             adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur,
                             adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur );
#endif
             /* data to send found                                 */
             dsrl_send_gai1_1[ iml_gai1 ].dsc_gai1_send.achc_ginp_cur
               = adsl_gai1_w1->achc_ginp_cur;
             dsrl_send_gai1_1[ iml_gai1 ].dsc_gai1_send.achc_ginp_end
               = adsl_gai1_w1->achc_ginp_end;
             dsrl_send_gai1_1[ iml_gai1 ].dsc_gai1_send.adsc_next
               = &dsrl_send_gai1_1[ iml_gai1 + 1 ].dsc_gai1_send;
             dsrl_send_gai1_1[ iml_gai1 ].adsc_gai1_org = adsl_gai1_w1;  /* gather input data origin */
             iml_gai1++;                /* next WSABUF             */
#ifndef TRY_090429_01
             if (iml_gai1 >= DEF_SEND_IOVEC) break;
#endif
           }
#endif
#ifdef TRY_110805_01
           iml2 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
           if (iml2 > 0) {              /* we have data to send    */
             if (iml1 <= 0) {           /* no more length          */
               bol_cont = TRUE;         /* continue processing     */
               break;
             }
             if (iml2 > iml1) {
               iml2 = iml1;
               bol_cont = TRUE;         /* continue processing     */
             }
             iml1 -= iml2;
#ifdef TRACE_091121_01
             {
               unsigned char ucrh_cmp_01[] = { 0X03, 0X00, 0X00, 0X7A };
               if (!memcmp( adsl_gai1_w1->achc_ginp_cur, ucrh_cmp_01, sizeof(ucrh_cmp_01) )) {
                 m_hlnew_printf( HLOG_TRACE1, "l%05d m_send_gather() iml_gai1=%d achc_ginp_cur=%p achc_ginp_end=%p len=%d/0X%p.",
                                 __LINE__, iml_gai1,
                                 adsl_gai1_w1->achc_ginp_cur,
                                 adsl_gai1_w1->achc_ginp_end,
                                 adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur,
                                 adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur );
               }
             }
#endif
#ifdef TRY_090429_01
             if (iml_gai1 >= DEF_SEND_IOVEC) {
               bol_cont = TRUE;             /* continue processing     */
               break;
             }
#endif
#ifdef TRACEHL_090429_01
             m_hlnew_printf( HLOG_TRACE1, "l%05d m_send_gather() iml_gai1=%d achc_ginp_cur=%p achc_ginp_end=%p len=%d/0X%p.",
                             __LINE__, iml_gai1,
                             adsl_gai1_w1->achc_ginp_cur,
                             adsl_gai1_w1->achc_ginp_end,
                             adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur,
                             adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur );
#endif
             /* data to send found                                     */
             dsrl_send_gai1_1[ iml_gai1 ].dsc_gai1_send.achc_ginp_cur
               = adsl_gai1_w1->achc_ginp_cur;
             dsrl_send_gai1_1[ iml_gai1 ].dsc_gai1_send.achc_ginp_end
               = adsl_gai1_w1->achc_ginp_cur + iml2;
             dsrl_send_gai1_1[ iml_gai1 ].dsc_gai1_send.adsc_next
               = &dsrl_send_gai1_1[ iml_gai1 + 1 ].dsc_gai1_send;
             dsrl_send_gai1_1[ iml_gai1 ].adsc_gai1_org = adsl_gai1_w1;  /* gather input data origin */
             iml_gai1++;                    /* next WSABUF             */
#ifndef TRY_090429_01
             if (iml_gai1 >= DEF_SEND_IOVEC) break;
#endif
           }
#endif
         }
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
#ifndef PROB070717
       } while (adsl_gai1_w1);
#else
       }
#endif
       if (adsl_gai1_w1) break;             /* has to send immediately */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     } while (adsl_sdhc1_w1);
     /* when no data to send found, we still have to free the buffers  */
     uml_sent = 0;                          /* no data sent yet        */
     iml_rc = 0;                            /* did not send something  */
     if (iml_gai1) {                        /* data to send found      */
       dsrl_send_gai1_1[ iml_gai1 - 1 ].dsc_gai1_send.adsc_next = NULL;
#ifdef XYZ1
       iml_rc = amc_wsasend( iclsocket, dsrl_wsabuf, uml_wsabuf,
                             (LPDWORD) &uml_sent, 0, NULL, NULL );
#endif
       iml_rc = adsp_tcp_ctrl_1->dsc_tcpco1_1.m_send_gather( &dsrl_send_gai1_1[ 0 ].dsc_gai1_send, &adsl_gai1_w1 );
#ifdef TRACE_091013_01
       if (adsp_tcp_ctrl_1 == &adsp_conn1->dsc_tc1_client) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPSxxxW GATE=%(ux)s SNO=%08d INETA=%s m_send_gather() to client length=%d/0X%08X.",
                         m_clconn1_gatename( aclconn1 ),
                         m_clconn1_sno( aclconn1 ),
                         m_clconn1_chrc_ineta( aclconn1 ),
                         iml_rc, iml_rc );
       }
#endif
#ifdef DEBUG_120710_01                      /* flow-control send       */
       m_hlnew_printf( HLOG_TRACE1, "DEBUG_120710_01 l%05d tcpco=%p m_send_clse_tcp_1() iml_gai1=%d returned m_send_gather() adsl_gai1_w1=%p.",
                       __LINE__, &adsp_tcp_ctrl_1->dsc_tcpco1_1, iml_gai1, adsl_gai1_w1 );
#endif
#ifdef NEW_REPORT_1501
       if (   (iml_rc > 0)                  /* data sent               */
           && (adsp_tcp_ctrl_1 == &adsp_conn1->dsc_tc1_client)) {  /* on client side */
         if (dss_bc_ctrl.adsrc_bc1[ 0 ] != NULL) {  /* with report     */
           dsl_time_cur = m_get_time();     /* current time            */
           dss_bc_ctrl.dsc_critsect.m_enter();  /* critical section    */
           iml1 = (int) dsl_time_cur - (int) dss_bc_ctrl.adsrc_bc1[ 0 ]->dsc_time_start;
           if (iml1 < 0) iml1 = 0;
           iml1 /= DEF_BANDWIDTH_CLIENT_SECS;  /* compute slot         */
           iml2 = dss_bc_ctrl.adsrc_bc1[ 0 ]->imc_no_entries;  /* number of entries */
           if (iml1 >= iml2) {                 /* check if at end      */
             iml1 = iml2 - 1;                  /* last entry           */
           }
           (*(dss_bc_ctrl.adsrc_bc1[ 0 ]->aimc_p_sent + iml1))++;  /* number of packets sent */
           *(dss_bc_ctrl.adsrc_bc1[ 0 ]->ailc_d_sent + iml1) += iml_rc;  /* count bytes data sent */
           dss_bc_ctrl.dsc_critsect.m_leave();  /* critical section    */
         }
       }
#endif
       if (adsp_conn1->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
         achl_w1 = "SNESENCL";
         achl_w2 = "client";
         if (adsp_tcp_ctrl_1 != &adsp_conn1->dsc_tc1_client) {
           achl_w1 = "SNESENSE";
           achl_w2 = "server";
         }
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data   */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, achl_w1, sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_sno = adsp_conn1->dsc_co_sort.imc_sno;  /* WSP session number */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id           */
         achl_w3 = "";
         if (adsl_gai1_w1) achl_w3 = "not all data sent this chunk / ";
         iml1 = sprintf( (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record),
                         "data sent to %s returned %d/0X%X - %sboc_act_conn_send %d.",
                         achl_w2, iml_rc, iml_rc,
                         achl_w3, adsp_tcp_ctrl_1->boc_act_conn_send );
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         ADSL_WTR_G1->achc_content          /* content of text / data  */
           = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
         ADSL_WTR_G1->imc_length = iml1;    /* length of text / data   */
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
         if (   (iml_rc > 0)
             && (adsp_conn1->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
           achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
           iml1 = iml_rc;                   /* length of data sent     */
           iml2 = 0;                        /* in this buffer          */
           achl_w3 = dsrl_send_gai1_1[ 0 ].adsc_gai1_org->achc_ginp_cur;  /* start of data */
           adsl_wt1_w2 = adsl_wt1_w1;       /* in this piece of memory */
           adsl_wtr_w1 = ADSL_WTR_G1;       /* set last in chain       */
           bol1 = FALSE;                    /* reset more flag         */
           do {                             /* loop always with new struct dsd_wsp_trace_record */
             achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
             if ((achl_w1 + sizeof(struct dsd_wsp_trace_record)) >= achl_w2) {
               adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
               memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
               adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
               adsl_wt1_w2 = adsl_wt1_w3;  /* this is current network */
               achl_w1 = (char *) (adsl_wt1_w2 + 1);
               achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
             }
             memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
             ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
             achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
             ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
#ifdef B120709
             if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
               adsl_wtr_w1->boc_more = TRUE;  /* more data to follow   */
             }
#endif
             adsl_wtr_w1->boc_more = bol1;  /* more data to follow     */
             bol1 = TRUE;                   /* set more flag           */
             adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
             adsl_wtr_w1 = ADSL_WTR_G2;     /* this is last in chain now */
             while (TRUE) {                 /* loop over data sent     */
               iml3 = dsrl_send_gai1_1[ iml2 ].adsc_gai1_org->achc_ginp_end - achl_w3;
               if (iml3 > iml1) iml3 = iml1;
               iml4 = achl_w2 - achl_w4;
               if (iml4 > iml3) iml4 = iml3;
               memcpy( achl_w4, achl_w3, iml4 );
               achl_w4 += iml4;
               achl_w3 += iml4;
               ADSL_WTR_G2->imc_length += iml4;  /* length of text / data */
               iml1 -= iml4;                /* length to be copied     */
               if (iml1 <= 0) break;
               if (achl_w3 < dsrl_send_gai1_1[ iml2 ].adsc_gai1_org->achc_ginp_end) break;
               iml2++;                      /* next part to be copied  */
               achl_w3 = dsrl_send_gai1_1[ iml2 ].adsc_gai1_org->achc_ginp_cur;  /* start of data */
               if (achl_w4 >= achl_w2) break;
             }
             achl_w1 = achl_w2;             /* set end of this area    */
           } while (iml1 > 0);
         }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
         m_wsp_trace_out( adsl_wt1_w1 );    /* output of WSP trace record */
       }
       /* mark buffers sent                                        */
       iml1 = 0;
       do {                                 /* loop over all buffers sent */
         dsrl_send_gai1_1[ iml1 ].adsc_gai1_org->achc_ginp_cur
           = dsrl_send_gai1_1[ iml1 ].dsc_gai1_send.achc_ginp_cur;
         if (dsrl_send_gai1_1[ iml1 ].adsc_gai1_org->achc_ginp_cur
               < dsrl_send_gai1_1[ iml1 ].adsc_gai1_org->achc_ginp_end) {
           bol_notify = TRUE;               /* send not complete       */
#ifdef DEBUG_120710_01                      /* flow-control send       */
           m_hlnew_printf( HLOG_XYZ1, "DEBUG_120710_01 l%05d tcpco=%p m_send_clse_tcp_1() set bol_notify",
                           __LINE__, &adsp_tcp_ctrl_1->dsc_tcpco1_1 );
#endif
         }
         iml1++;                            /* take next buffer        */
       } while (iml1 < iml_gai1);
       uml_sent = 0;
       if (iml_rc > 0) uml_sent = iml_rc;
#ifdef TRACEHL1
#ifdef NOT_YET_110814
       m_hlnew_printf( HLOG_XYZ1, "nbipgw20 l%05d WSASend completed / sent iml_rc=%d uml_sent=%d iclsocket=%d time-sec=%d",
                       __LINE__, iml_rc, uml_sent, iclsocket, m_get_time() );
#endif
#endif
#ifdef TRACEHL_SEND
       inc_trace_all += uml_sent;
#endif
     }
     /* mark buffers that data have been sent                      */
#ifdef XYZ1
     iml_sent = uml_sent;               /* field with sign         */
#endif
     do {                                   /* loop over chain sdhc1   */
       adsl_gai1_w1 = adsl_sdhc1_send->adsc_gather_i_1_i;  /* get chain to send */
#ifndef PROB070717
       do {                                 /* loop over chain gai1    */
#else
       while (adsl_gai1_w1) {               /* loop over chain gai1    */
#endif
#ifdef XYZ1
         if (iml_sent > 0) {            /* more to mark            */
           iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
           if (iml1 > iml_sent) iml1 = iml_sent;  /* only as long as buffer */
#ifdef TRACEHL_SEND                         /* 27.06.07 KB             */
           m_console_out( adsl_gai1_w1->achc_ginp_cur, iml1 );
#endif
           adsl_gai1_w1->achc_ginp_cur += iml1;  /* mark buffer    */
           iml_sent -= iml1;                /* this length has been marked */
         }
#endif
#ifndef TRY_090429_01
         if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) break;
#else
         if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) {
           bol_cont = TRUE;                 /* continue processing     */
           break;
         }
#endif
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
#ifndef PROB070717
       } while (adsl_gai1_w1);
#else
       }
#endif
       if (adsl_gai1_w1) break;         /* has to send immediately */
       adsl_sdhc1_w1 = adsl_sdhc1_send;  /* save buffer for free   */
       adsl_sdhc1_send = adsl_sdhc1_send->adsc_next;  /* get next in chain */
#ifdef B110315
       if (adsl_sdhc1_w1->imc_usage_count == 0) {  /* not in use   */
         m_proc_free( adsl_sdhc1_w1 );  /* free this buffer        */
       } else {                         /* work area still in use  */
         iml_rc = adsp_conn1->dsc_critsect.m_enter();  /* enter CriticalSection */
         if (iml_rc < 0) {                  /* error occured           */
// to-do 09.08.11 KB error number
           m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_enter() critical section failed %d.",
                           adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
         }
         adsl_sdhc1_w1->adsc_next = adsp_conn1->adsc_sdhc1_inuse;  /* chain of buffers in use */
         adsp_conn1->adsc_sdhc1_inuse = adsl_sdhc1_w1;  /* append to chain */
         iml_rc = adsp_conn1->dsc_critsect.m_leave();  /* leave CriticalSection */
         if (iml_rc < 0) {                  /* error occured           */
// to-do 09.08.11 KB error number
           m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_leave() critical section failed %d.",
                           adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
         }
       }
#else
       if (   (adsl_sdhc1_w1->imc_usage_count == 0)  /* not in use */
           && (adsp_tcp_ctrl_1 == &adsp_conn1->dsc_tc1_client)) {  /* send to client */
         m_proc_free( adsl_sdhc1_w1 );  /* free this buffer        */
       } else {                         /* work area still in use  */
#ifndef TJ_B171005
         if (!bop_tcpco_thread) {
#endif //not TJ_B171005 
         iml_rc = adsp_conn1->dsc_critsect.m_enter();  /* enter CriticalSection */
         if (iml_rc < 0) {                  /* error occured           */
// to-do 09.08.11 KB error number
           m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_enter() critical section failed %d.",
                           adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
         }
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
         m_hlnew_printf( HLOG_TRACE1, "nbipgw20.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                         __LINE__, HL_THRID, &adsp_conn1->dsc_critsect );
#endif
#ifndef TJ_B171005
         }
#endif //not TJ_B171005 
         adsl_sdhc1_w1->adsc_next = adsp_conn1->adsc_sdhc1_inuse;  /* chain of buffers in use */
         adsp_conn1->adsc_sdhc1_inuse = adsl_sdhc1_w1;  /* append to chain */
#ifndef TJ_B171005
         if (!bop_tcpco_thread) {
#endif //not TJ_B171005
         iml_rc = adsp_conn1->dsc_critsect.m_leave();  /* leave CriticalSection */
         if (iml_rc < 0) {                  /* error occured           */
// to-do 09.08.11 KB error number
           m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_leave() critical section failed %d.",
                           adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
         }
#ifndef TJ_B171005
         }
#endif //not TJ_B171005 
       }
#endif
     } while (adsl_sdhc1_send);
#ifdef DEBUG_120710_01                      /* flow-control send       */
     m_hlnew_printf( HLOG_XYZ1, "DEBUG_120710_01 l%05d tcpco=%p m_send_clse_tcp_1() after loop send bol_notify=%d.",
                     __LINE__, &adsp_tcp_ctrl_1->dsc_tcpco1_1, bol_notify );
#endif
     if (bol_notify) {                      /* send not complete       */
       adsp_tcp_ctrl_1->adsc_sdhc1_send = adsl_sdhc1_send;  /* set chain to send later */
#ifndef TJ_B171005
       if (bop_tcpco_thread) {                   /* from TCP thread         */
         adsp_conn1->dsc_critsect.m_leave();
       }
#endif //TJ_B171005
#ifdef TRACEHL_090429_01
       m_hlnew_printf( HLOG_XYZ1, "l%05d m_send_gather() call dsc_tcpco1.m_sendnotify();",
                       __LINE__ );
#endif
#ifdef DEBUG_120710_01                      /* flow-control send       */
       m_hlnew_printf( HLOG_XYZ1, "DEBUG_120710_01 l%05d tcpco=%p m_send_clse_tcp_1() call m_sendnotify()",
                       __LINE__, &adsp_tcp_ctrl_1->dsc_tcpco1_1 );
#endif
//     dsc_tcpco1.m_sendnotify();
       adsp_tcp_ctrl_1->dsc_tcpco1_1.m_sendnotify();
#ifdef TRACEHL_SEND
       m_hlnew_printf( HLOG_XYZ1, "nbipgw20 l%05d cl_tcp_r=%p m_send_gather() bop_tcpco_thread=%d adsp_tcp_ctrl_1->adsc_sdhc1_send=%p bol_notify return",
                       __LINE__, adsp_tcp_ctrl_1, bop_tcpco_thread, adsp_tcp_ctrl_1->adsc_sdhc1_send );
#endif
       return;                          /* all done                */
     }
#ifdef TRACEHL_090429_01
     m_hlnew_printf( HLOG_XYZ1, "l%05d m_send_gather() bol_cont=%d iml_rc=%d adsl_sdhc1_send=%p.",
                     __LINE__, bol_cont, iml_rc, adsl_sdhc1_send );
#endif
   } while (bol_cont && (iml_rc > 0));  /* till all sent           */
#ifdef TRACEHL_090429_01
   m_hlnew_printf( HLOG_XYZ1, "l%05d m_send_gather() bol_cont=%d iml_rc=%d adsl_sdhc1_send=%p.",
                   __LINE__, bol_cont, iml_rc, adsl_sdhc1_send );
#endif
#ifdef XYZ1
   if (iml_rc == 0) {                   /* no error occured        */
   }
   if (iml_rc >= 0) {                   /* no error occured        */
     if (bop_tcpco_thread == FALSE) return;  /* not from TCP thread     */
     adsp_tcp_ctrl_1->adsc_sdhc1_send = NULL;      /* all has been sent       */
     m_act_thread_1( adsp_conn1 );            /* activate work-thread    */
     return;                            /* all done                */
   }
   iml_error = errno;                       /* get error code          */
   if (iml_error != WSAEWOULDBLOCK) {
     achl_w1 = "client";
     if (adsp_tcp_ctrl_1 != &adsp_conn1->dsc_tc1_client) achl_w1 = "server";
     m_hlnew_printf( HLOG_XYZ1, "HWSPS090W GATE=%(ux)s SNO=%08d INETA=%s %s TCP/IP send error %d / %d",
                     m_clconn1_gatename( aclconn1 ),
                     m_clconn1_sno( aclconn1 ),
                     m_clconn1_chrc_ineta( aclconn1 ),
                     achl_w1, iml_rc, iml_error );
     /* free buffers                                               */
     while (adsl_sdhc1_send) {          /* loop over all buffers   */
       adsl_sdhc1_w1 = adsl_sdhc1_send;  /* save adsp_tcp_ctrl_1 buffer       */
       adsl_sdhc1_send = adsl_sdhc1_send->adsc_next;  /* get next in chain */
       if (adsl_sdhc1_w1->imc_usage_count == 0) {  /* not in use   */
         m_proc_free( adsl_sdhc1_w1 );  /* free this buffer        */
       } else {                         /* work area still in use  */
         iml_rc = adsp_conn1->dsc_critsect.m_enter();  /* enter CriticalSection */
         if (iml_rc < 0) {                  /* error occured           */
// to-do 09.08.11 KB error number
           m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_enter() critical section failed %d.",
                           adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
         }
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
         m_hlnew_printf( HLOG_TRACE1, "nbipgw20.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                         __LINE__, HL_THRID, &adsp_conn1->dsc_critsect );
#endif
         adsl_sdhc1_w1->adsc_next = adsp_conn1->adsc_sdhc1_inuse;  /* chain of buffers in use */
         adsp_conn1->adsc_sdhc1_inuse = adsl_sdhc1_w1;  /* append to chain */
         iml_rc = adsp_conn1->dsc_critsect.m_leave();  /* leave CriticalSection */
         if (iml_rc < 0) {                  /* error occured           */
// to-do 09.08.11 KB error number
           m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_leave() critical section failed %d.",
                           adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
         }
       }
     }
     if (bop_tcpco_thread == FALSE) return;  /* not from TCP thread    */
     adsp_tcp_ctrl_1->adsc_sdhc1_send = NULL;  /* all has been sent    */
     m_act_thread_1( adsp_conn1 );          /* activate work-thread    */
     return;                            /* all done                */
   }
#ifdef TRACEHL_TCP_BLOCK                    /* 18.07.07 KB count TCP blocking */
   EnterCriticalSection( &dsalloc_dcritsect );
   ims_trace_block_send++;
   LeaveCriticalSection( &dsalloc_dcritsect );
#endif /* TRACEHL_TCP_BLOCK                    18.07.07 KB count TCP blocking */
   iml_rc = adsp_conn1->dsc_critsect.m_enter();  /* enter CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_enter() critical section failed %d.",
                     adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
   }
#ifdef B080407
   if (bo_may_send) {
     m_clconn1_critsect_leave( aclconn1 );
#ifdef TRACEHL_TCP_BLOCK                    /* 18.07.07 KB count TCP blocking */
     EnterCriticalSection( &dsalloc_dcritsect );
     ims_trace_block_may++;
     LeaveCriticalSection( &dsalloc_dcritsect );
#endif /* TRACEHL_TCP_BLOCK                    18.07.07 KB count TCP blocking */
     goto psend10;                      /* try again               */
   }
#endif
   adsp_tcp_ctrl_1->adsc_sdhc1_send = adsl_sdhc1_send;  /* set chain to send later */
   iml_rc = adsp_conn1->dsc_critsect.m_leave();  /* leave CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_leave() critical section failed %d.",
                     adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
   }
   return;
#endif
// to-do 12.05.09 KB - data may be lost - prevent sending in xiipgw08-pd-main.cpp
#ifdef TJ_B171005
#ifndef B090512
   if (bop_tcpco_thread) {                  /* from TCP thread         */
     iml_rc = adsp_conn1->dsc_critsect.m_enter();  /* enter CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
  // to-do 09.08.11 KB error number
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_enter() critical section failed %d.",
                       adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
     }
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
     m_hlnew_printf( HLOG_TRACE1, "nbipgw20.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                     __LINE__, HL_THRID, &adsp_conn1->dsc_critsect );
#endif
   }
#endif
#endif //TJ_B171005
   /* free buffers                                                 */
   while (adsl_sdhc1_send) {            /* loop over all buffers   */
     adsl_sdhc1_w1 = adsl_sdhc1_send;   /* save this buffer        */
     adsl_sdhc1_send = adsl_sdhc1_send->adsc_next;  /* get next in chain */
#ifdef B110315
     if (adsl_sdhc1_w1->imc_usage_count == 0) {  /* not in use     */
       m_proc_free( adsl_sdhc1_w1 );    /* free this buffer        */
     } else {                           /* work area still in use  */
       m_clconn1_mark_work_area( aclconn1, adsl_sdhc1_w1 );
     }
#else
     if (   (adsl_sdhc1_w1->imc_usage_count == 0)  /* not in use       */
         && (adsp_tcp_ctrl_1 == &adsp_conn1->dsc_tc1_client)) {  /* send to client */
       m_proc_free( adsl_sdhc1_w1 );        /* free this buffer        */
     } else {                               /* work area still in use  */
       if (bop_tcpco_thread == FALSE) {     /* not from TCP thread     */
         iml_rc = adsp_conn1->dsc_critsect.m_enter();  /* enter CriticalSection */
         if (iml_rc < 0) {                  /* error occured           */
// to-do 09.08.11 KB error number
           m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_enter() critical section failed %d.",
                           adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
         }
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
         m_hlnew_printf( HLOG_TRACE1, "nbipgw20.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                         __LINE__, HL_THRID, &adsp_conn1->dsc_critsect );
#endif
       }
       adsl_sdhc1_w1->adsc_next = adsp_conn1->adsc_sdhc1_inuse;  /* chain of buffers in use */
       adsp_conn1->adsc_sdhc1_inuse = adsl_sdhc1_w1;  /* append to chain */
       if (bop_tcpco_thread == FALSE) {     /* not from TCP thread     */
         iml_rc = adsp_conn1->dsc_critsect.m_leave();  /* leave CriticalSection */
         if (iml_rc < 0) {                  /* error occured           */
// to-do 09.08.11 KB error number
           m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_leave() critical section failed %d.",
                           adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
         }
       }
     }
#endif
   }
#ifdef TRACEHL_SEND
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20 l%05d cl_tcp_r=%p m_send_gather() bop_tcpco_thread=%d adsp_tcp_ctrl_1->adsc_sdhc1_send=%p return normal and act",
                   __LINE__, adsp_tcp_ctrl_1, bop_tcpco_thread, adsp_tcp_ctrl_1->adsc_sdhc1_send );
#endif
#ifdef TRACEHL_090429_01
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20 l%05d cl_tcp_r=%p m_send_gather() bop_tcpco_thread=%d adsp_tcp_ctrl_1->adsc_sdhc1_send=%p adsp_conn1=%p return normal and act",
                   __LINE__, adsp_tcp_ctrl_1, bop_tcpco_thread, adsp_tcp_ctrl_1->adsc_sdhc1_send, adsp_conn1 );
#endif
#ifdef TRACE_HL_SESS_01
   iml1 = 38;
   if (bop_tcpco_thread) iml1 = 39;
   m_clconn1_last_action( adsp_conn1, iml1 );  /* last action        */
#endif  /* TRACE_HL_SESS_01 */
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = m_clconn1_get_sdhc1_chain( adsp_conn1 );  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "nbipgw20-l%05d m_send_gather end", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
   /* for HOB-PPP-T1 and other tunnel, clear received packets          */
   if (adsp_tcp_ctrl_1 == &adsp_conn1->dsc_tc1_client) {  /* was send to client */
     switch (adsp_conn1->iec_servcotype) {  /* type of server connection */
#ifdef D_INCL_HOB_TUN
       case ied_servcotype_htun:            /* HOB-TUN                 */
         adsp_conn1->dsc_tun_contr_conn.imc_on_the_fly_packets_client = 0;  /* number of packets on the fly to the client */
         break;
#endif
       case ied_servcotype_l2tp:            /* L2TP                    */
         adsp_conn1->dsc_l2tp_session.imc_on_the_fly_packets_client = 0;  /* number of packets on the fly to the client */
         break;
     }
   }
   if (bop_tcpco_thread == FALSE) return;   /* not from TCP thread     */
   adsp_tcp_ctrl_1->adsc_sdhc1_send = NULL;  /* all has been sent      */
   bol_cont = FALSE;                        /* do not activate work thread */
   if (   (adsp_tcp_ctrl_1->boc_act_conn_send)  /* activate connection after send */
       && (adsp_conn1->boc_st_act == FALSE)) {  /* thread does not run */
     adsp_conn1->boc_st_act = TRUE;         /* thread will run soon    */
     bol_cont = TRUE;                       /* do activate work thread */
   }
   iml_rc = adsp_conn1->dsc_critsect.m_leave();  /* leave CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_leave() critical section failed %d.",
                     adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
   }
// m_post_netw_post_1( DEF_NETW_POST_1_TCPCOMP_SEND_COMPL );
   m_tc1_post_netw_post_1( adsp_tcp_ctrl_1, DEF_NETW_POST_1_TCPCOMP_SEND_COMPL );  /* posted for TCPCOMP send complete */
   if (bol_cont == FALSE) return;           /* do not activate work thread */
   m_act_thread_2( adsp_conn1 );            /* activate work-thread    */
   return;                                  /* all done                */
} /* end m_send_clse_tcp_1()                                           */

/** open Unix socket connection to listen-gateway                      */
static void m_ligw_open( void ) {           /* open the listen gateway */
   BOOL       bol1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   int        iml1;                         /* working variable        */
   char       *achl1;                       /* working variable        */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   int        imrl_send_li_gw[ 4 ];         /* send start to listen gateway */

   dss_ligw_g.imc_time_disconnect = (int) time( NULL );  /* time of disconnect */

   dss_ligw_g.imc_sockfd = socket( AF_LOCAL, SOCK_STREAM, 0 );
   if (dss_ligw_g.imc_sockfd < 0) {         /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPM130E Listen-Gateway socket() failed %d / %d.",
                     dss_ligw_g.imc_sockfd, errno );
     return;                                /* could not connect to listen gateway */
   }
   iml_rc = connect( dss_ligw_g.imc_sockfd,
                     (struct sockaddr *) &dss_ligw_g.dsc_soa_un,
                     sizeof(struct sockaddr_un) );
   iml_error = errno;                       /* save errno              */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_LIGW) {  /* Listen-Gateway Unix */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CLIGWOP1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "l%05d m_ligw_open() listen-gateway connect() \"%s\" returned %d errno %d.",
                     __LINE__,
                     dss_ligw_g.dsc_soa_un.sun_path,
                     iml_rc, iml_error );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPM132E Listen-Gateway pipe-name \"%(u8)s\" connect() failed %d / %d.",
                     dss_ligw_g.dsc_soa_un.sun_path, iml_rc, iml_error );
     close( dss_ligw_g.imc_sockfd );
     return;                                /* could not connect to listen gateway */
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T m_ligw_open() connected to Listen-Gateway pipe-name \"%(u8)s\".",
                   __LINE__, dss_ligw_g.dsc_soa_un.sun_path );
#endif
   /* set to non-blocking I/O                                          */
   iml1 = fcntl( dss_ligw_g.imc_sockfd, F_GETFL, 0 );
   fcntl( dss_ligw_g.imc_sockfd, F_SETFL, iml1 | O_NONBLOCK );
   /* prepare for encryption                                           */
   achl1 = dss_loconf_1.achc_ligw_shared_secret;  /* shared secret of Listen Gateway */
   if (achl1 == NULL) {
     achl1 = DEFAULT_SECRET;
   }
   iml1 = strlen( achl1 );
   SHA1_Init( dss_ligw_g.imrc_sha1_key );
   SHA1_Update( dss_ligw_g.imrc_sha1_key, achl1, 0, iml1 );
   /* send start to listen gateway                                     */
   imrl_send_li_gw[ 1 ] = D_LI_GW_TOKEN;    /* token for start packet  */
   imrl_send_li_gw[ 2 ] = D_LI_GW_VERSION;  /* version of listen gateway */
   imrl_send_li_gw[ 3 ] = getpid();         /* get our process ID      */
   *((unsigned char *) imrl_send_li_gw + sizeof(int) - 1) = ied_ligwq_start;  /* start of WSP */
   bol1 = m_ligw_send( (char *) imrl_send_li_gw + sizeof(int) - 1, sizeof(imrl_send_li_gw) - (sizeof(int) - 1), NULL );
   if (bol1 == FALSE) return;               /* connection listen-gateway not open */
   if (dss_ligw_g.aimrc_ligw_cluster) {     /* check cluster structure */
     bol1 = m_ligw_send( (char *) dss_ligw_g.aimrc_ligw_cluster + 2 * sizeof(int) - 1, dss_ligw_g.aimrc_ligw_cluster[ 0 ] + 1, NULL );
     if (bol1 == FALSE) return;             /* connection listen-gateway not open */
   }
   dss_ligw_g.adsc_gate_listen_1_cur = NULL;  /* listen part of gateway currently processed */
   dss_ligw_g.boc_connected = TRUE;         /* connected to Listen Gateway */
} /* end m_ligw_open()                                                 */

/** send command create socket to the listen-gateway                   */
static void m_ligw_create_socket( void ) {
   int        iml1;                         /* working variable        */
   char       *achl1;                       /* working variable        */
   struct dsd_gate_listen_1 *adsl_gate_listen_1_w1;  /* listen part of gateway */
   struct dsd_gate_1 *adsl_gate_1_create_socket_w1;  /* current gate to start */
   char       chrl_send_buf[ 64 ];          /* send buffer             */

#define ADSL_CREATE_SOCKET_LIGW ((struct dsd_create_socket_ligw *) (chrl_send_buf + 1))

#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_ligw_create_socket() called",
                   __LINE__ );
#endif

   p_create_00:                             /* check gate              */
   if (   (dss_ligw_g.boc_listen_start == FALSE)  /* start listen at program start */
       && (dss_ligw_g.adsc_gate_listen_1_next == NULL)) {  /* no listen part of gateway next to process */
     if (dss_ligw_g.boc_listen_lbal) {      /* start listen for load-balancing */
       while (TRUE) {
         adsl_gate_1_create_socket_w1 = dss_ligw_g.adsc_gate_1_create_socket;  /* get current gateway */
         if (adsl_gate_1_create_socket_w1 == NULL) return;  /* nothing more to do */
         if (adsl_gate_1_create_socket_w1->boc_not_close_lbal == FALSE) break;  /* do not use no close listen by load-balancing */
         /* overread this gate                                         */
         dss_ligw_g.adsc_gate_1_create_socket = adsl_gate_1_create_socket_w1->adsc_next;
       }
     }
     adsl_gate_1_create_socket_w1 = dss_ligw_g.adsc_gate_1_create_socket;  /* get current gateway */
     if (adsl_gate_1_create_socket_w1 == NULL) return;  /* nothing more to do */
     dss_ligw_g.adsc_gate_listen_1_next = adsl_gate_1_create_socket_w1->adsc_gate_listen_1_ch;  /* chain of listen part of gateway */
   }
   adsl_gate_listen_1_w1 = dss_ligw_g.adsc_gate_listen_1_next;  /* get next to process */
   if (adsl_gate_listen_1_w1 == NULL) return;  /* nothing more to process */

   dss_ligw_g.adsc_gate_listen_1_cur = adsl_gate_listen_1_w1;  /* listen part of gateway currently processed */
   /* prepare for next walk thru gates to be opened                    */
   dss_ligw_g.adsc_gate_listen_1_next = NULL;  /* nothing more to start */
   if (dss_ligw_g.boc_listen_start == FALSE) {  /* not start listen at program start */
     dss_ligw_g.adsc_gate_listen_1_next = adsl_gate_listen_1_w1->adsc_next;
     if (dss_ligw_g.adsc_gate_listen_1_next == NULL) {
#ifdef B121107
       dss_ligw_g.adsc_gate_1_create_socket = dss_ligw_g.adsc_gate_1_create_socket->adsc_next;
       while (   (dss_ligw_g.adsc_gate_1_create_socket)
              && (dss_ligw_g.adsc_gate_1_create_socket->boc_not_close_lbal)) {  /* no close listen by load-balancing */
         dss_ligw_g.adsc_gate_1_create_socket = dss_ligw_g.adsc_gate_1_create_socket->adsc_next;
       }
#endif
       adsl_gate_1_create_socket_w1 = dss_ligw_g.adsc_gate_1_create_socket;  /* get current gateway */
       if (adsl_gate_1_create_socket_w1) {  /* more to do              */
         adsl_gate_1_create_socket_w1 = adsl_gate_1_create_socket_w1->adsc_next;  /* get next in chain */
         while (   (adsl_gate_1_create_socket_w1)
                && (adsl_gate_1_create_socket_w1->boc_not_close_lbal)) {  /* no close listen by load-balancing */
           adsl_gate_1_create_socket_w1 = adsl_gate_1_create_socket_w1->adsc_next;  /* get next in chain */
         }
       }
       dss_ligw_g.adsc_gate_1_create_socket = adsl_gate_1_create_socket_w1;
     }
   }
   /* prepare packet to be sent to listen-gateway                      */
   ADSL_CREATE_SOCKET_LIGW->ucc_family = adsl_gate_listen_1_w1->dsc_soa.ss_family;  /* address family */
   ADSL_CREATE_SOCKET_LIGW->ucc_socket_type = SOCK_STREAM;  /* type of socket */
   ADSL_CREATE_SOCKET_LIGW->ucc_protocol = 0;  /* protocol used        */
   memcpy( ADSL_CREATE_SOCKET_LIGW->ucrc_port,
           &((struct sockaddr_in *) &adsl_gate_listen_1_w1->dsc_soa)->sin_port,
           sizeof(ADSL_CREATE_SOCKET_LIGW->ucrc_port) );
   achl1 = (char *) &((struct sockaddr_in *) &adsl_gate_listen_1_w1->dsc_soa)->sin_addr;
   iml1 = 4;                                /* length of INETA         */
   if (ADSL_CREATE_SOCKET_LIGW->ucc_family == AF_INET6) {
     achl1 = (char *) &((struct sockaddr_in6 *) &adsl_gate_listen_1_w1->dsc_soa)->sin6_addr;
     iml1 = 16;                             /* length of INETA         */
     memcpy( ADSL_CREATE_SOCKET_LIGW->ucrc_port,
             &((struct sockaddr_in6 *) &adsl_gate_listen_1_w1->dsc_soa)->sin6_port,
             sizeof(ADSL_CREATE_SOCKET_LIGW->ucrc_port) );
   }
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_ligw_create_socket() send INETA %02X %02X %02X %02X port 0X%04X.",
                   __LINE__,
                   *((unsigned char *) achl1 + 0),
                   *((unsigned char *) achl1 + 1),
                   *((unsigned char *) achl1 + 2),
                   *((unsigned char *) achl1 + 3),
                   *((unsigned short int *) ADSL_CREATE_SOCKET_LIGW->ucrc_port) );
#endif
   memcpy( ADSL_CREATE_SOCKET_LIGW + 1, achl1, iml1 );  /* copy INETA  */
   chrl_send_buf[ 0 ] = (unsigned char) ied_ligwq_socket;  /* create socket */
   m_ligw_send( chrl_send_buf, 1 + sizeof(struct dsd_create_socket_ligw) + iml1, NULL );

#undef ADSL_CREATE_SOCKET_LIGW

} /* end m_ligw_create_socket()                                        */

/** send a record encrypted to the listen-gateway                      */
static BOOL m_ligw_send( char *achp_content, int imp_len_content, struct msghdr *adsp_msghdr ) {
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   int        iml_len;                      /* length of data          */
   int        iml1, iml2, iml3;             /* working variables       */
   BOOL       bol1;                         /* working variable        */
   char       *achl1, *achl2, *achl3;       /* working variables       */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   struct iovec dsrl_iov[1];                /* vector containing send data */
   int        imrl_sha1[ SHA_ARRAY_SIZE ];  /* for hash                */
   char       chrl_sha1_out[ D_LIGW_RANDOM_L ];  /* output of SHA-1    */
   char       chrl_send_buf[ 512 ];         /* send buffer             */

   if (img_wsp_trace_core_flags1 & HL_WT_CORE_LIGW) {  /* Listen-Gateway Unix */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CLIGWSE1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "l%05d m_ligw_send( %p , %d , %p ) listen-gateway send",
                     __LINE__,
                     achp_content, imp_len_content, adsp_msghdr );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2)) {  /* generate WSP trace record */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml1 = imp_len_content;              /* length of data displayed */
       achl_w3 = achp_content;              /* start of data           */
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
         ADSL_WTR_G2->imc_length = iml1;    /* length of text / data   */
         iml1 -= iml2;                      /* length to be copied     */
         achl_w1 = achl_w2;                 /* set end of this area    */
       } while (iml1 > 0);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   memcpy( chrl_send_buf, chrs_requestheader_query, sizeof(chrs_requestheader_query) );
   /* send nonce for hash SHA-1                                        */
   achl1 = chrl_send_buf + sizeof(chrs_requestheader_query);
   iml1 = D_LIGW_RANDOM_L - 4;
   do {
     *achl1++ = ((unsigned char) m_get_random_number( 256 )) ^ ucs_random_01;
     iml1--;                                /* decrement count         */
   } while (iml1 > 0);
   /* send time                                                        */
   iml1 = m_get_time();
   *achl1++ = (unsigned char) (iml1 >> 24);
   *achl1++ = (unsigned char) (iml1 >> 16);
   *achl1++ = (unsigned char) (iml1 >> 8);
   *achl1++ = (unsigned char) iml1;
   /* output of length NHASN                                           */
   iml1 = imp_len_content;                  /* get length content      */
   do {                                     /* loop to get length NHASN */
     achl1++;                               /* space for digit         */
     iml1 >>= 7;                            /* shift digits            */
   } while (iml1 > 0);
   achl2 = achl1;                           /* get current output      */
   iml1 = imp_len_content;                  /* get length content      */
   iml2 = 0;                                /* clear more bit          */
   do {                                     /* loop to get length NHASN */
     *(--achl2) = (unsigned char) ((iml1 & 0X7F) | iml2);  /* output digit */
     iml1 >>= 7;                            /* shift digits            */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
   memcpy( achl1, achp_content, imp_len_content );
   achl2 = achl1 + imp_len_content;         /* end of content          */
   achl3 = chrl_send_buf + sizeof(chrs_requestheader_query);  /* first value for XOR */
   do {                                     /* loop for XOR with hash  */
     memcpy( imrl_sha1, dss_ligw_g.imrc_sha1_key, sizeof(imrl_sha1) );
     SHA1_Update( imrl_sha1, achl3, 0, D_LIGW_RANDOM_L );
     SHA1_Final( imrl_sha1, chrl_sha1_out, 0 );
     for ( iml1 = 0; iml1 < D_LIGW_RANDOM_L; iml1++ ) {
       achl1[ iml1 ] ^= chrl_sha1_out[ iml1 ];
     }
     achl3 = achl1;
     achl1 += D_LIGW_RANDOM_L;
   } while (achl1 < achl2);
   /* send data to the listen gateway                                  */
   iml_len = achl2 - chrl_send_buf;         /* length to send          */
   if (adsp_msghdr == NULL) {
     iml_rc = write( dss_ligw_g.imc_sockfd, chrl_send_buf, iml_len );
   } else {
     dsrl_iov[ 0 ].iov_base = chrl_send_buf;
     dsrl_iov[ 0 ].iov_len = iml_len;
     adsp_msghdr->msg_iov = dsrl_iov;
     adsp_msghdr->msg_iovlen = 1;
     iml_rc = sendmsg( dss_ligw_g.imc_sockfd, adsp_msghdr, 0 );
   }
   iml_error = errno;                       /* save errno              */
#ifdef TRACEHL1
   iml2 = errno;                            /* save errno              */
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T write() / sendmsg() to listen-gateway returned=%d %d.",
                   __LINE__, iml_rc, iml2 );
   errno = iml2;                            /* restore errno           */
#endif
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
   iml2 = errno;                            /* save errno              */
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_ligw_send() write() / sendmsg() returned %d errno %d.",
                   __LINE__, iml_rc, iml2 );
   errno = iml2;                            /* restore errno           */
#endif
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_LIGW) {  /* Listen-Gateway Unix */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CLIGWSE2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "l%05d m_ligw_send() listen-gateway write() / sendmsg() returned %d errno %d.",
                     __LINE__,
                     iml_rc, iml_error );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2)) {  /* generate WSP trace record */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml1 = iml_len;                      /* length of data displayed */
       achl_w3 = chrl_send_buf;             /* start of data           */
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
         ADSL_WTR_G2->imc_length = iml1;    /* length of text / data   */
         iml1 -= iml2;                      /* length to be copied     */
         achl_w1 = achl_w2;                 /* set end of this area    */
       } while (iml1 > 0);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (iml_rc == iml_len) return TRUE;      /* write succeeded         */
   if (   (iml_rc < 0)                      /* returned error          */
       && (iml_error == ENOTCONN)) {        /* 107 / Transport endpoint is not connected */
     m_hlnew_printf( HLOG_WARN1, "HWSPM134W l%05d listen-gateway write() / sendmsg() failed because not connected",
                     __LINE__ );
     dss_ligw_g.imc_time_disconnect = (int) time( NULL );  /* time of disconnect */
     dss_ligw_g.boc_connected = FALSE;      /* not connected to Listen Gateway */
#ifdef D_INCL_HOB_TUN
     dss_ligw_g.boc_ser_sent = FALSE;       /* serialize command sent  */
     dss_ligw_g.imc_open_tun_sent = 0;      /* command open TUN sent   */
#endif
     iml_rc = close( dss_ligw_g.imc_sockfd );
     if (iml_rc != 0) {                     /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPM135W nbipgw20 l%05d close socket listen-gateway returned %d %d.",
                       __LINE__, iml_rc, errno );
     }
     return FALSE;                          /* all done                */
   }
   /* write returned error                                             */
   m_hlnew_printf( HLOG_WARN1, "HWSPM136W l%05d listen-gateway write() / sendmsg() returned %d %d.",
                   __LINE__, iml_rc, iml_error );
   dss_ligw_g.imc_time_disconnect = (int) time( NULL );  /* time of disconnect */
   dss_ligw_g.boc_connected = FALSE;        /* not connected to Listen Gateway */
#ifdef D_INCL_HOB_TUN
   dss_ligw_g.boc_ser_sent = FALSE;         /* serialize command sent  */
   dss_ligw_g.imc_open_tun_sent = 0;        /* command open TUN sent   */
#endif
   iml_rc = close( dss_ligw_g.imc_sockfd );
   if (iml_rc != 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM137W nbipgw20 l%05d close socket listen-gateway returned %d %d.",
                     __LINE__, iml_rc, errno );
   }
   return FALSE;                            /* all done                */
} /* end m_ligw_send()                                                 */

/** receive from the listen-gateway                                    */
static void m_ligw_recv( void ) {
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   int        iml1, iml2, iml3;             /* working variables       */
   int        iml_socket;                   /* socket received         */
#ifdef TRY_141127_01                        /* Listen-Gateway received EINPROGRESS */
   int        iml_retry;                    /* count retry             */
#define MAX_UDS_RETRY 5
#endif
   BOOL       bol1;                         /* working variable        */
   enum ied_decode_ligw_recv_1 iel_dlr1;    /* decode received from listen-gateway */
   char       *achl1, *achl2, *achl3;       /* working variables       */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   struct dsd_ligw_receive *adsl_receive_in1;  /* receive buffer       */
   struct dsd_ligw_receive *adsl_rec1_w1;   /* area for receive        */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* gather input            */
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* gather input            */
#ifdef D_INCL_HOB_TUN
   struct dsd_ser_thr_task *adsl_sth_w1;    /* working variable        */
#endif
   struct msghdr dsl_msg;                   /* message structure       */
   struct iovec dsrl_iov[1];                /* vector containing send data */
#ifdef MSGHDR_CONTROL_AVAILABLE
   union {
     struct cmsghdr dsc_msg;
     char chrc_control[ CMSG_SPACE(sizeof(int)) ];
   } dsl_control_un;
   struct cmsghdr *adsl_cmd;
#endif
#ifdef D_INCL_HOB_TUN
   struct dsd_ser_thr_task dsl_sth_work;    /* work as task for serial thread */
#endif
   int        imrl_w1[ 3 ];                 /* array of int            */
   char       chrl_input[ 512 ];            /* input received          */

#ifdef DEBUG_121116_01                      /* debug listen-gateway    */
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_ligw_recv() called",
                   __LINE__ );
#endif
   adsl_receive_in1 = (struct dsd_ligw_receive *) m_proc_alloc();  /* receive buffer */
#ifdef B110913
   iml_rc = recv( dss_ligw_g.imc_sockfd,
                  (char *) (adsl_receive_in1 + 1),
                  LEN_TCP_RECV - sizeof(dsd_ligw_receive),
                  0 );
   if (iml_rc <= 0) {                       /* no data received        */
// to-do 12.09.11 KB error message
     m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T m_ligw_recv() called iml_rc=%d errno=%d - no data",
                     __LINE__, iml_rc, errno );
     m_proc_free( adsl_receive_in1 );       /* free storage            */
     m_ligw_close();                        /* close connection to listen-gateway */
     return;
   }
#ifdef TRACEHL1
   m_console_out( (char *) (adsl_receive_in1 + 1), iml_rc );
#endif
#endif
   iml_socket = -1;                         /* make socket invalid     */
#ifdef MSGHDR_CONTROL_AVAILABLE
   dsl_msg.msg_control = dsl_control_un.chrc_control;
   dsl_msg.msg_controllen = sizeof(dsl_control_un.chrc_control);
#else
   dsl_msg.msg_accrights = (caddr_t) &iml_socket;
   dsl_msg.msg_accrightslen = sizeof(int);
#endif
   dsl_msg.msg_name = NULL;
   dsl_msg.msg_namelen = 0;
   dsrl_iov[0].iov_base = (char *) (adsl_receive_in1 + 1);
   dsrl_iov[0].iov_len = LEN_TCP_RECV - sizeof(dsd_ligw_receive);
   dsl_msg.msg_iov = dsrl_iov;
   dsl_msg.msg_iovlen = 1;

#ifdef TRY_141127_01                        /* Listen-Gateway received EINPROGRESS */
   iml_retry = 0;                           /* count retry             */

   p_recv_start:                            /* start receiving         */
#endif
   iml_rc = recvmsg( dss_ligw_g.imc_sockfd, &dsl_msg, 0 );
   iml_error = errno;                       /* save errno              */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_LIGW) {  /* Listen-Gateway Unix */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CLIGWRE1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "l%05d recvmsg() listen-gateway returned %d/0X%X errno %d.",
                     __LINE__,
                     iml_rc, iml_rc, iml_error );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (   (iml_rc > 0)
         && (img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2))) {  /* generate WSP trace record */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml1 = iml_rc;                       /* length of data displayed */
       achl_w3 = (char *) (adsl_receive_in1 + 1);  /* start of data    */
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
         ADSL_WTR_G2->imc_length = iml1;    /* length of text / data   */
         iml1 -= iml2;                      /* length to be copied     */
         achl_w1 = achl_w2;                 /* set end of this area    */
       } while (iml1 > 0);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (iml_rc <= 0) {                       /* no data received        */
// to-do 12.09.11 KB error message
     m_hlnew_printf( HLOG_WARN1, "HWSPM160W nbipgw20 l%05d m_ligw_recv() called iml_rc=%d errno=%d - no data",
                     __LINE__, iml_rc, iml_error );
#ifdef TRY_141127_01                        /* Listen-Gateway received EINPROGRESS */
     if (   (iml_error == EINPROGRESS)
         && (iml_retry < MAX_UDS_RETRY)) {  /* count retry             */
       iml_retry++;                         /* count retry             */
       goto p_recv_start;                   /* start receiving         */
     }
#endif
     m_proc_free( adsl_receive_in1 );       /* free storage            */
     m_ligw_close();                        /* close connection to listen-gateway */
     return;
   }
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_ligw_recv() recvmsg() returned %d.",
                   __LINE__, iml_rc );
   m_console_out( (char *) (adsl_receive_in1 + 1), iml_rc );
#endif
#ifdef TRACEHL1
   m_console_out( (char *) (adsl_receive_in1 + 1), iml_rc );
#endif
#ifdef NOT_YET_110913
#ifdef MSGHDR_CONTROL_AVAILABLE
   adsl_cmd = CMSG_FIRSTHDR( &dsl_msg );
   if (   (adsl_cmd == NULL)
       || (adsl_cmd->cmsg_len != CMSG_LEN(sizeof(int)))
       || (adsl_cmd->cmsg_level != SOL_SOCKET)
       || (adsl_cmd->cmsg_type != SCM_RIGHTS)) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPSxxxW l%05d listen-gateway recvmsg() no descriptor in message",
                     __LINE__ );
     return;                                /* all done                */
   }
   iml_socket = *((int *) CMSG_DATA( adsl_cmd ));
#else
   if (dsl_msg.msg_accrightslen != sizeof(int)) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPSxxxW l%05d listen-gateway recvmsg() no descriptor in message",
                     __LINE__ );
     return;                                /* all done                */
   }
#endif
#endif

   adsl_receive_in1->adsc_next = NULL;      /* clear chain             */
   adsl_receive_in1->dsc_gai1_r.achc_ginp_cur = (char *) (adsl_receive_in1 + 1);
   adsl_receive_in1->dsc_gai1_r.achc_ginp_end = (char *) (adsl_receive_in1 + 1) + iml_rc;
   adsl_receive_in1->dsc_gai1_r.adsc_next = NULL;  /* clear chain      */
   if (dss_ligw_g.adsc_rec1_ch == NULL) {   /* chain received data     */
     dss_ligw_g.adsc_rec1_ch = adsl_receive_in1;  /* is first in chain now */
   } else {
     adsl_rec1_w1 = dss_ligw_g.adsc_rec1_ch;  /* get chain received data */
     while (adsl_rec1_w1->adsc_next) adsl_rec1_w1 = adsl_rec1_w1->adsc_next;
     adsl_rec1_w1->adsc_next = adsl_receive_in1;  /* append to chain   */
     adsl_rec1_w1->dsc_gai1_r.adsc_next = &adsl_receive_in1->dsc_gai1_r;  /* chain of gather */
   }

   p_recv_sc_00:                            /* we have input           */
   adsl_gai1_w1 = &dss_ligw_g.adsc_rec1_ch->dsc_gai1_r;  /* get chain of gather */
   achl1 = chrs_requestheader_response;     /* start to compare        */
   achl2 = chrs_requestheader_response + sizeof(chrs_requestheader_response);  /* end to compare */
   iel_dlr1 = ied_dlr1_header;              /* header received         */

   p_recv_sc_04:                            /* scan received input     */
   achl3 = adsl_gai1_w1->achc_ginp_cur;     /* get start of input      */

   p_recv_sc_20:                            /* continue scan received input */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T p_recv_sc_20: iel_dlr1=%d achl1=%p achl2=%p achl3=%p.",
                   __LINE__, iel_dlr1, achl1, achl2, achl3 );
#endif
   iml1 = adsl_gai1_w1->achc_ginp_end - achl3;  /* length of input     */
   if (iml1 <= 0) goto p_recv_sc_60;        /* end of this gather      */
#ifdef DEBUG_121116_01                      /* debug listen-gateway    */
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T p_recv_sc_20: iel_dlr1=%d achl1=%p achl2=%p achl3=%p.",
                   __LINE__, iel_dlr1, achl1, achl2, achl3 );
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T p_recv_sc_20: length iml1=%d state iel_dlr1=%d.",
                   __LINE__, iml1, iel_dlr1 );
   m_console_out( achl3, iml1 );
#endif
   switch (iel_dlr1) {                      /* decode received from listen-gateway */
     case ied_dlr1_header:                  /* header received         */
       iml2 = achl2 - achl1;                /* length remaining output */
       if (iml2 > iml1) iml2 = iml1;        /* maximum output          */
       if (memcmp( achl1, achl3, iml2 )) {  /* does not compare        */
#ifdef XYZ1
         m_wsp_send_msg( adsl_wsp_conn_w1,
                         "nbipgw19-l%05d-W input eye-catcher does not compare pos=%d.",
                         __LINE__,
                         achl1 - chrs_requestheader_query );
         adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
         return FALSE;                      /* do not receive more     */
#endif
         m_hlnew_printf( HLOG_WARN1, "HWSPM161W nbipgw20 l%05d m_ligw_recv() input eye-catcher does not compare pos=%d.",
                         __LINE__, achl1 - chrs_requestheader_query );
#ifdef DEBUG_121116_01                      /* debug listen-gateway    */
         m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T call m_ligw_close()",
                         __LINE__ );
#endif
         m_ligw_close();                    /* close connection to listen-gateway */
         return;
       }
       achl1 += iml2;                       /* increment to compare    */
       achl3 += iml2;                       /* increment input         */
       if (achl1 < achl2) break;            /* we need more input      */
       iml2 = D_MAX_LEN_NHASN;              /* maximum length NHASN    */
       iml3 = 0;                            /* clear akkumulator       */
       iel_dlr1 = ied_dlr1_len_nhasn;       /* length NHASN            */
       break;
     case ied_dlr1_len_nhasn:               /* length NHASN            */
       iml3 <<= 7;                          /* shift old akkumulator   */
       iml3 |= *achl3 & 0X7F;               /* apply new bits to akkumulator */
       iml2--;                              /* decrement length NHASN  */
       achl3++;                             /* this character consumed */
       if (*((unsigned char *) achl3 - 1) & 0X80) {  /* more bit still set */
         if (iml2 <= 0) {                   /* too many digits         */
#ifdef XYZ1
           m_wsp_send_msg( adsl_wsp_conn_w1,
                           "nbipgw19-l%05d-W input length NHASN contains too many digits",
                           __LINE__ );
           adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
           return FALSE;                    /* do not receive more     */
#endif
           m_hlnew_printf( HLOG_WARN1, "HWSPM162W nbipgw20 l%05d m_ligw_recv() input length NHASN contains too many digits",
                           __LINE__ );
#ifdef DEBUG_121116_01                      /* debug listen-gateway    */
           m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T call m_ligw_close()",
                           __LINE__ );
#endif
           m_ligw_close();                  /* close connection to listen-gateway */
           return;
         }
         break;                             /* we need more digits     */
       }
       if (iml3 <= 0) {
#ifdef XYZ1
         m_wsp_send_msg( adsl_wsp_conn_w1,
                         "nbipgw19-l%05d-W input content length zero invalid",
                         __LINE__ );
         adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
         return FALSE;                      /* do not receive more     */
#endif
         m_hlnew_printf( HLOG_WARN1, "HWSPM163W nbipgw20 l%05d m_ligw_recv() input content length zero invalid",
                         __LINE__ );
#ifdef DEBUG_121116_01                      /* debug listen-gateway    */
         m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T call m_ligw_close()",
                         __LINE__ );
#endif
         m_ligw_close();                    /* close connection to listen-gateway */
         return;
       }
#ifdef XYZ1
       if (iml3 > (ACHL_INPUT_END - ACHL_INPUT_STA)) {
         m_wsp_send_msg( adsl_wsp_conn_w1,
                         "nbipgw19-l%05d-W input content too long %d.",
                         __LINE__,
                         iml3 );
         adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
         return FALSE;                      /* do not receive more     */
       }
#endif
       iml1 = adsl_gai1_w1->achc_ginp_end - achl3;  /* length of this input */
       adsl_gai1_w2 = adsl_gai1_w1->adsc_next;  /* get chained gather  */
       while (adsl_gai1_w2) {               /* loop over all following gather */
         iml1 += adsl_gai1_w2->achc_ginp_end - adsl_gai1_w2->achc_ginp_cur;
         adsl_gai1_w2 = adsl_gai1_w2->adsc_next;  /* get next in chain */
       }
       if (iml1 < iml3) return;             /* not complete packet     */
       achl1 = achl3;                       /* start of content        */
       iml1 = iml3;                         /* length of content       */
       achl3 += iml1;                       /* input has been consumed */
       if (achl3 <= adsl_gai1_w1->achc_ginp_end) {  /* complete record in contigous area */
         goto p_record_00;                  /* record has been received */
       }
       achl3 -= iml1;                       /* input has not been consumed */
       if (iml3 > sizeof(chrl_input)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPM164W nbipgw20 l%05d m_ligw_recv() input content longer than prepared area",
                         __LINE__ );
// to-do 12.09.11 KB error message
#ifdef DEBUG_121116_01                      /* debug listen-gateway    */
         m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T call m_ligw_close()",
                         __LINE__ );
#endif
         m_ligw_close();                    /* close connection to listen-gateway */
         return;
       }
       achl1 = chrl_input;                  /* start of input          */
       achl2 = achl1 + iml3;                /* end of input            */
       iml2 = 0;                            /* start of block          */
       iel_dlr1 = ied_dlr1_content;         /* content                 */
       break;
     case ied_dlr1_content:                 /* content                 */
       iml2 = achl2 - achl1;                /* length remaining output */
       if (iml2 > iml1) iml2 = iml1;        /* maximum output          */
       memcpy( achl1, achl3, iml2 );        /* copy content            */
       achl1 += iml2;                       /* increment to compare    */
       achl3 += iml2;                       /* increment input         */
       if (achl1 < achl2) break;            /* not yet end of input    */
       achl1 = chrl_input;                  /* start of content        */
       iml1 = iml3;                         /* length of content       */
       goto p_record_00;                    /* record has been received */
   }

   goto p_recv_sc_20;                       /* continue scan received input */

   p_recv_sc_60:                            /* end of this gather      */
   adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain       */
   if (adsl_gai1_w1) goto p_recv_sc_04;     /* scan received input     */
   return;                                  /* continue receiving      */

   p_record_00:                             /* record has been received */
#ifdef TRACEHL1
   m_console_out( achl1, iml1 );
#endif
#ifdef DEBUG_121116_01                      /* debug listen-gateway    */
   m_console_out( achl1, iml1 );
#endif
   adsl_gai1_w1->achc_ginp_cur = achl3;     /* processed till here     */
   switch ((enum ied_li_gw_response) *achl1) {
     case ied_ligwr_msg:                    /* message                 */
       m_hlnew_printf( HLOG_INFO1, "HWSPM133I Listen-Gateway: %.*(u8)s.",
                       iml1 - 1, achl1 + 1 );
       break;
     case ied_ligwr_wsps:                   /* other WSPs              */
       achl1++;                             /* after tag               */
       iml1--;                              /* minus length tag        */
       do {                                 /* loop to open Unix domain socket connection */
         if (iml1 < sizeof(int)) {
           m_hlnew_printf( HLOG_WARN1, "HWSPM165W nbipgw20 l%05d m_ligw_recv() input ied_ligwr_wsps too short",
                           __LINE__ );
#ifdef DEBUG_121116_01                      /* debug listen-gateway    */
           m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T call m_ligw_close()",
                           __LINE__ );
#endif
           m_ligw_close();                  /* close connection to listen-gateway */
           return;
         }
         memcpy( &iml2, achl1, sizeof(int) );  /* for alignment        */
         m_cluster_ligw_conn( iml2 );       /* connect to WSP          */
         achl1 += sizeof(int);              /* after this              */
         iml1 -= sizeof(int);               /* this PID processed      */
       } while (iml1 > 0);
       break;
     case ied_ligwr_resp_socket_ok:         /* create socket succeeded */
       if (iml1 != 1) {                     /* check length sent      */
// to-do 14.09.11 KB error message
         m_hlnew_printf( HLOG_WARN1, "HWSPM166W nbipgw20 l%05d m_ligw_recv() input ied_ligwr_resp_socket_ok length %d invalid",
                         __LINE__, iml1 );
         break;
       }
#ifdef MSGHDR_CONTROL_AVAILABLE
       adsl_cmd = CMSG_FIRSTHDR( &dsl_msg );
       if (   (adsl_cmd == NULL)
           || (adsl_cmd->cmsg_len != CMSG_LEN(sizeof(int)))
           || (adsl_cmd->cmsg_level != SOL_SOCKET)
           || (adsl_cmd->cmsg_type != SCM_RIGHTS)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPM167W nbipgw20 l%05d listen-gateway recvmsg() no descriptor in message",
                         __LINE__ );
         dss_ligw_g.adsc_gate_listen_1_cur = NULL;  /* no listen currently processed */
         break;                             /* all done                */
       }
       iml_socket = *((int *) CMSG_DATA( adsl_cmd ));
#else
       if (dsl_msg.msg_accrightslen != sizeof(int)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPM167W nbipgw20 l%05d listen-gateway recvmsg() no descriptor in message",
                         __LINE__ );
         dss_ligw_g.adsc_gate_listen_1_cur = NULL;  /* no listen currently processed */
         break;                             /* all done                */
       }
#endif
       if (dss_ligw_g.adsc_gate_listen_1_cur == NULL) {  /* listen part of gateway currently processed */
// to-do 14.09.11 KB error message
         iml_rc = close( iml_socket );      /* close the socket        */
// to-do 14.09.11 KB error message
         break;
       }
       if (dss_ligw_g.boc_stop_listen_lbal) {  /* stop listen load-balancing in progress */
         iml_rc = close( iml_socket );      /* close the socket        */
// to-do 14.09.11 KB error message
         break;
       }
       dss_ligw_g.adsc_gate_listen_1_cur->imc_socket = iml_socket;
#ifdef TRY_121023_01                        /* SO_REUSEADDR            */
       {
         int      imh_w1;
         socklen_t imh_w2 = sizeof(int);
         iml_rc = getsockopt( iml_socket, SOL_SOCKET, SO_REUSEADDR, (void *) &imh_w1, &imh_w2 );
         m_hlnew_printf( HLOG_TRACE1, "HWSPxxxxT l%05d getsockopt() returned %d %d imh_w1=0X%08X imh_w2=0X%08X.",
                         __LINE__, iml_rc, D_TCP_ERROR, imh_w1, imh_w2 );
       }
       iml_rc = setsockopt( iml_socket, SOL_SOCKET, SO_REUSEADDR, (const char *) &ims_true, sizeof(int) );
       if (iml_rc != 0) {                     /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "HWSPxxxxW l%05d Error setsockopt() returned %d %d.",
                         __LINE__, iml_rc, D_TCP_ERROR );
       }
#endif
       if (dss_ligw_g.boc_listen_start) {   /* start listen at program start */
         dss_ligw_g.adsc_gate_listen_1_cur = NULL;  /* no listen currently processed */
         dss_ligw_g.boc_rc_last_listen = TRUE;  /* socket and bind succeeded */
         dss_ligw_g.boc_listen_start = FALSE;  /* start listen at program start */
         break;
       }
       iml_rc = listen( dss_ligw_g.adsc_gate_listen_1_cur->imc_socket,
                        dss_ligw_g.adsc_gate_listen_1_cur->adsc_gate_1->imc_backlog );
       if (iml_rc) {                        /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "HWSPM168W nbipgw20 l%05d Error listen() gate \"%(ux)s\" returned %d %d.",
                         __LINE__, dss_ligw_g.adsc_gate_listen_1_cur->adsc_gate_1 + 1, iml_rc, D_TCP_ERROR );
         break;
       }
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_ligw_recv() &dss_ligw_g.adsc_gate_listen_1_cur->dsc_acc_listen=%p dss_ligw_g.adsc_gate_listen_1_cur->imc_socket=%d.",
                       __LINE__, &dss_ligw_g.adsc_gate_listen_1_cur->dsc_acc_listen, dss_ligw_g.adsc_gate_listen_1_cur->imc_socket );
#endif
       iml_rc = dss_ligw_g.adsc_gate_listen_1_cur->dsc_acc_listen.mc_startlisten_fix( dss_ligw_g.adsc_gate_listen_1_cur->imc_socket,
                                                                                      &dss_acccb,
                                                                                      dss_ligw_g.adsc_gate_listen_1_cur );
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_ligw_recv() mc_startlisten_fix() returned %d.",
                       __LINE__, iml_rc );
#endif
// to-do 14.09.11 KB check return code
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_ligw_recv() dss_ligw_g.adsc_gate_1_create_socket=%p dss_ligw_g.adsc_gate_listen_1_cur=%p dss_ligw_g.adsc_gate_listen_1_next=%p dsg_sys_state_1.boc_listen_active=%d.",
                       __LINE__, dss_ligw_g.adsc_gate_1_create_socket, dss_ligw_g.adsc_gate_listen_1_cur, dss_ligw_g.adsc_gate_listen_1_next, dsg_sys_state_1.boc_listen_active );
#endif
       dss_ligw_g.adsc_gate_listen_1_cur->boc_active = TRUE;  /* listen is active now */
       dss_ligw_g.adsc_gate_listen_1_cur = NULL;  /* no listen currently processed */
       if (dss_ligw_g.adsc_gate_1_create_socket) break;  /* current gate to start */
#ifdef B121107
// to-do 30.10.12 KB - superflous
       if (dss_ligw_g.adsc_gate_listen_1_next) break;  /* listen part of gateway next to process */
#endif
       dsg_sys_state_1.boc_listen_active = TRUE;  /* listen is currently active */
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_ligw_recv() dss_ligw_g.adsc_gate_1_create_socket=%p dss_ligw_g.adsc_gate_listen_1_cur=%p dss_ligw_g.adsc_gate_listen_1_next=%p dsg_sys_state_1.boc_listen_active=%d.",
                       __LINE__, dss_ligw_g.adsc_gate_1_create_socket, dss_ligw_g.adsc_gate_listen_1_cur, dss_ligw_g.adsc_gate_listen_1_next, dsg_sys_state_1.boc_listen_active );
#endif
       m_status_cluster_lbal( TRUE );       /* notify other cluster members */
       break;                               /* all done                */
     case ied_ligwr_resp_socket_failed:     /* create socket failed    */
       if (iml1 != (1 + 3 * sizeof(int))) {  /* check length sent      */
// to-do 14.09.11 KB error message
         m_hlnew_printf( HLOG_WARN1, "HWSPM169W nbipgw20 l%05d m_ligw_recv() input ied_ligwr_resp_socket_failed length %d invalid",
                         __LINE__, iml1 );
         break;
       }
// to-do 14.09.11 KB error message
       memcpy( imrl_w1, achl1 + 1, 3 * sizeof(int) );  /* for alignment */
       m_hlnew_printf( HLOG_WARN1, "HWSPM170W Listen-Gateway responded error to create socket %d %d %d.",
                       imrl_w1[ 0 ], imrl_w1[ 1 ], imrl_w1[ 2 ] );
       if (dss_ligw_g.adsc_gate_listen_1_cur == NULL) {  /* listen part of gateway currently processed */
// to-do 14.09.11 KB error message
         break;
       }
       dss_ligw_g.adsc_gate_listen_1_cur = NULL;  /* no listen currently processed */
       if (dss_ligw_g.boc_listen_start) {   /* start listen at program start */
         dss_ligw_g.boc_rc_last_listen = FALSE;  /* socket and bind failed */
         dss_ligw_g.boc_listen_start = FALSE;  /* start listen at program start */
         break;
       }
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_ligw_recv() dss_ligw_g.adsc_gate_1_create_socket=%p dss_ligw_g.adsc_gate_listen_1_cur=%p dss_ligw_g.adsc_gate_listen_1_next=%p dsg_sys_state_1.boc_listen_active=%d.",
                       __LINE__, dss_ligw_g.adsc_gate_1_create_socket, dss_ligw_g.adsc_gate_listen_1_cur, dss_ligw_g.adsc_gate_listen_1_next, dsg_sys_state_1.boc_listen_active );
#endif
       if (dss_ligw_g.adsc_gate_1_create_socket) break;  /* current gate to start */
#ifdef B121107
// to-do 30.10.12 KB - superflous
       if (dss_ligw_g.adsc_gate_listen_1_next) break;  /* listen part of gateway next to process */
#endif
       dsg_sys_state_1.boc_listen_active = TRUE;  /* listen is currently active */
       m_status_cluster_lbal( TRUE );       /* notify other cluster members */
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_ligw_recv() dss_ligw_g.adsc_gate_1_create_socket=%p dss_ligw_g.adsc_gate_listen_1_cur=%p dss_ligw_g.adsc_gate_listen_1_next=%p dsg_sys_state_1.boc_listen_active=%d.",
                       __LINE__, dss_ligw_g.adsc_gate_1_create_socket, dss_ligw_g.adsc_gate_listen_1_cur, dss_ligw_g.adsc_gate_listen_1_next, dsg_sys_state_1.boc_listen_active );
#endif
       break;                               /* all done                */
#ifdef D_INCL_HOB_TUN
     case ied_ligwr_resp_open_tun:          /* open TUN adapter        */
       if (iml1 != (1 + sizeof(struct dsd_ligw_r_open_tun))) {  /* check length sent */
// to-do 14.09.11 KB error message
         m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW nbipgw20 l%05d m_ligw_recv() input ied_ligwr_resp_open_tun length %d invalid",
                         __LINE__, iml1 );
         break;
       }
       if (dss_ligw_g.imc_open_tun_sent != 1) {  /* command open TUN sent */
         m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW l%05d Listen-Gateway responded ied_ligwr_resp_open_tun but no command sent",
                         __LINE__ );
         break;
       }
#define ADSL_RESP_OPEN_TUN_G ((struct dsd_ligw_r_open_tun *) (achl1 + 1))  /* response open TUN adapter */
       if (ADSL_RESP_OPEN_TUN_G->ucc_index_ineta_ipv4 == 0) {  /* index of INETA IPV4 + 1 */
         m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW nbipgw20 l%05d m_ligw_recv() input ied_ligwr_resp_open_tun no free <TUN-adapter-ineta> IPV4 found",
                         __LINE__ );
       } else {                             /* assigned INETA to adapter */
         dsg_tun_ctrl.achc_ta_ineta_ipv4    /* entry <TUN-adapter-ineta> IPV4 */
           = &dss_loconf_1.adsc_raw_packet_if_conf->achc_ar_ta_ineta_ipv4[ (ADSL_RESP_OPEN_TUN_G->ucc_index_ineta_ipv4 - 1) * 4 ];  /* entry array <TUN-adapter-ineta> IPV4 */
       }
#ifdef HL_LINUX
       memcpy( dsg_tun_ctrl.chrc_tiface, ADSL_RESP_OPEN_TUN_G->chrc_tiface, IFNAMSIZ );
#endif
#ifdef HL_FREEBSD
#ifdef MSGHDR_CONTROL_AVAILABLE
       adsl_cmd = CMSG_FIRSTHDR( &dsl_msg );
       if (   (adsl_cmd == NULL)
           || (adsl_cmd->cmsg_len != CMSG_LEN(sizeof(int)))
           || (adsl_cmd->cmsg_level != SOL_SOCKET)
           || (adsl_cmd->cmsg_type != SCM_RIGHTS)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPM167W nbipgw20 l%05d listen-gateway recvmsg() no descriptor in message",
                         __LINE__ );
//       dss_ligw_g.adsc_gate_listen_1_cur = NULL;  /* no listen currently processed */
         break;                             /* all done                */
       }
       iml_socket = *((int *) CMSG_DATA( adsl_cmd ));
#else
       if (dsl_msg.msg_accrightslen != sizeof(int)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPM167W nbipgw20 l%05d listen-gateway recvmsg() no descriptor in message",
                         __LINE__ );
//       dss_ligw_g.adsc_gate_listen_1_cur = NULL;  /* no listen currently processed */
         break;                             /* all done                */
       }
#endif
       dsg_tun_ctrl.imc_fd_tun = iml_socket;  /* get TUN file-descriptor */
#endif
#undef ADSL_RESP_OPEN_TUN_G
       dss_ligw_g.imc_open_tun_sent = 2;    /* command open TUN sent   */
       break;                               /* all done                */
     case ied_ligwr_resp_arproute_add_ipv4:  /* add ARP and route IPV4 */
       if (iml1 != 1) {                     /* check length sent       */
// to-do 14.09.11 KB error message
         m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW nbipgw20 l%05d m_ligw_recv() input ied_ligwr_resp_arproute_add_ipv4 length %d invalid",
                         __LINE__, iml1 );
         break;
       }
       if (   (dss_ser_thr_ctrl.adsc_sth_work == NULL)  /* work as task for serial thread */
           || (dss_ligw_g.boc_ser_sent == FALSE)) {  /* serialize command sent */
         m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW l%05d Listen-Gateway responded ied_ligwr_resp_arproute_add_ipv4 but no command sent",
                         __LINE__ );
         break;
       }
       if (dss_ser_thr_ctrl.adsc_sth_work->iec_sth  /* serial thread task type */
             != ied_sth_route_ipv4_add) {   /* add a route IPV4        */
         m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW l%05d Listen-Gateway responded ied_ligwr_resp_arproute_add_ipv4 but not command ied_sth_route_ipv4_add sent",
                         __LINE__ );
         break;
       }
       dsg_global_lock.m_enter();           /* enter critical section  */
       adsl_sth_w1 = dss_ser_thr_ctrl.adsc_sth_work;  /* get work as task for serial thread */
       memcpy( &dsl_sth_work, adsl_sth_w1, sizeof(struct dsd_ser_thr_task) );
       dss_ser_thr_ctrl.adsc_sth_work = adsl_sth_w1->adsc_next;  /* remove from chain */
       adsl_sth_w1->adsc_next = dss_ser_thr_ctrl.adsc_sth_free;  /* get old chain free */
       dss_ser_thr_ctrl.adsc_sth_free = adsl_sth_w1;  /* set new chain free */
       dsg_global_lock.m_leave();           /* leave critical section  */
       if (dsl_sth_work.aboc_posted) {      /* with mark posted        */
         *dsl_sth_work.aboc_posted = TRUE;  /* mark posted             */
       }
       if (dsl_sth_work.adsc_event_posted) {  /* event for posted      */
         iml_rc = dsl_sth_work.adsc_event_posted->m_post( &iml_error );  /* event for posted */
// to-do 02.07.10 KB error message
         if (iml_rc < 0) {                     /* error occured           */
           m_hl1_printf( "xxxxxxxr-%05d-W m_ligw_recv() thread m_post Return Code %d Error %d",
                         __LINE__, iml_rc, iml_error );
         }
       }
       dss_ligw_g.boc_ser_sent = FALSE;     /* serialize command sent  */
       break;                               /* all done                */
     case ied_ligwr_resp_arproute_del_ipv4:  /* del ARP and route IPV4 */
       if (iml1 != 1) {                     /* check length sent       */
// to-do 14.09.11 KB error message
         m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW nbipgw20 l%05d m_ligw_recv() input ied_ligwr_resp_arproute_del_ipv4 length %d invalid",
                         __LINE__, iml1 );
         break;
       }
       if (   (dss_ser_thr_ctrl.adsc_sth_work == NULL)  /* work as task for serial thread */
           || (dss_ligw_g.boc_ser_sent == FALSE)) {  /* serialize command sent */
         m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW l%05d Listen-Gateway responded ied_ligwr_resp_arproute_del_ipv4 but no command sent",
                         __LINE__ );
         break;
       }
       if (dss_ser_thr_ctrl.adsc_sth_work->iec_sth  /* serial thread task type */
             != ied_sth_route_ipv4_del) {   /* del a route IPV4        */
         m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW l%05d Listen-Gateway responded ied_ligwr_resp_arproute_del_ipv4 but not command ied_sth_route_ipv4_del sent",
                         __LINE__ );
         break;
       }
       dsg_global_lock.m_enter();           /* enter critical section  */
       adsl_sth_w1 = dss_ser_thr_ctrl.adsc_sth_work;  /* get work as task for serial thread */
       memcpy( &dsl_sth_work, adsl_sth_w1, sizeof(struct dsd_ser_thr_task) );
       dss_ser_thr_ctrl.adsc_sth_work = adsl_sth_w1->adsc_next;  /* remove from chain */
       adsl_sth_w1->adsc_next = dss_ser_thr_ctrl.adsc_sth_free;  /* get old chain free */
       dss_ser_thr_ctrl.adsc_sth_free = adsl_sth_w1;  /* set new chain free */
       dsg_global_lock.m_leave();           /* leave critical section  */
       if (dsl_sth_work.aboc_posted) {      /* with mark posted        */
         *dsl_sth_work.aboc_posted = TRUE;  /* mark posted             */
       }
       if (dsl_sth_work.adsc_event_posted) {  /* event for posted      */
         iml_rc = dsl_sth_work.adsc_event_posted->m_post( &iml_error );  /* event for posted */
// to-do 02.07.10 KB error message
         if (iml_rc < 0) {                     /* error occured           */
           m_hl1_printf( "xxxxxxxr-%05d-W m_ligw_recv() thread m_post Return Code %d Error %d",
                         __LINE__, iml_rc, iml_error );
         }
       }
       dss_ligw_g.boc_ser_sent = FALSE;     /* serialize command sent  */
       break;                               /* all done                */
#endif
     default:
// to-do 12.09.11 KB error message
       m_hlnew_printf( HLOG_WARN1, "HWSPM171W nbipgw20 l%05d m_ligw_recv() input invalid response tag %d.",
                       __LINE__, (enum ied_li_gw_response) *achl1 );
#ifdef DEBUG_121116_01                      /* debug listen-gateway    */
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T call m_ligw_close()",
                       __LINE__ );
#endif
       m_ligw_close();                      /* close connection to listen-gateway */
       return;
   }

   p_record_80:                             /* the record has been processed */
   if (adsl_gai1_w1->achc_ginp_cur >= adsl_gai1_w1->achc_ginp_end) {  /* this gather processed */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   while (dss_ligw_g.adsc_rec1_ch) {        /* loop over chain received data */
     adsl_rec1_w1 = dss_ligw_g.adsc_rec1_ch;  /* get chain received data */
     if (adsl_gai1_w1 == &adsl_rec1_w1->dsc_gai1_r) break;  /* current one reached */
     dss_ligw_g.adsc_rec1_ch = adsl_rec1_w1->adsc_next;  /* remove from chain */
     m_proc_free( adsl_rec1_w1 );           /* free receive block      */
   }
   if (dss_ligw_g.adsc_rec1_ch) {           /* check chain received data */
     goto p_recv_sc_00;                     /* we have input           */
   }
   return;                                  /* all done                */
} /* end m_ligw_recv()                                                 */

/** send structure to listen-gateway                                   */
extern "C" void m_ligw_cluster_struct( int *aimrp_ligw_cluster ) {
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "l%05d m_ligw_cluster_struct( %p ) length %d.",
                   __LINE__, aimrp_ligw_cluster, aimrp_ligw_cluster[ 0 ] );
   m_console_out( (char *) aimrp_ligw_cluster + 2 * sizeof(int) - 1, aimrp_ligw_cluster[ 0 ] + 1 );
#endif
   dss_ligw_g.aimrc_ligw_cluster = aimrp_ligw_cluster;  /* set cluster structure */
   if (dss_ligw_g.boc_connected == FALSE) return;  /* not connected to Listen Gateway */
   m_ligw_send( (char *) dss_ligw_g.aimrc_ligw_cluster + 2 * sizeof(int) - 1, dss_ligw_g.aimrc_ligw_cluster[ 0 ] + 1, NULL );
} /* end m_ligw_cluster_struct()                                       */

/** close the connection to the listen-gateway                         */
static void m_ligw_close( void ) {
   int        iml_rc;                       /* return code             */
   struct dsd_ligw_receive *adsl_rec1_w1;   /* area for receive        */

#ifdef DEBUG_121116_01                      /* debug listen-gateway    */
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_ligw_close() called",
                   __LINE__ );
#endif
   iml_rc = close( dss_ligw_g.imc_sockfd );
   if (iml_rc != 0) {                       /* error occured           */
// to-do 12.09.11 KB error message
   }
   dss_ligw_g.imc_time_disconnect = (int) time( NULL );  /* time of disconnect */
   while (dss_ligw_g.adsc_rec1_ch) {        /* loop over chain received data */
     adsl_rec1_w1 = dss_ligw_g.adsc_rec1_ch;  /* get chain received data */
     dss_ligw_g.adsc_rec1_ch = adsl_rec1_w1->adsc_next;  /* remove from chain */
     m_proc_free( adsl_rec1_w1 );           /* free receive block      */
   }
   dss_ligw_g.boc_connected = FALSE;        /* not connected to Listen Gateway */
#ifdef D_INCL_HOB_TUN
   dss_ligw_g.boc_ser_sent = FALSE;         /* serialize command sent  */
   dss_ligw_g.imc_open_tun_sent = 0;        /* command open TUN sent   */
#endif
} /* end m_ligw_close()                                                */

/** subroutine to close a session on work-thread                       */
static inline void m_conn_close( struct dsd_pd_work *adsp_pd_work ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3, iml4, iml5;  /* working variables      */
   int        iml_c_udp_rece;               /* count receive UDP       */
   int        iml_c_udp_send;               /* count send UDP          */
   int        iml_rc;                       /* return code             */
#ifndef B140719
   int        iml_time_1;                   /* time - epoch            */
#endif
   HL_LONGLONG ill_d_udp_rece;              /* data receive UDP        */
   HL_LONGLONG ill_d_udp_send;              /* data send UDP           */
   char       *achl1, *achl2;               /* working variables       */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_w2;       /* auxiliary extension fi  */
#ifndef B140525
   struct dsd_server_conf_1 *adsl_server_conf_1_used;  /* configuration server */
#endif
   struct dsd_recudp1 *adsl_recudp1_w1;     /* chain of data received  */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* chain of buffers       */
#ifndef B140719
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* output data             */
#endif
   struct dsd_sdh_control_1 **aadsl_sdhc1_adr;  /* address chain of buffers */
   struct dsd_hco_wothr *adsl_workth_1;  /* working variable       */
   struct dsd_bgt_contr_1 *adsl_bgt_contr_1;  /* definition background-task control */
   struct dsd_bgt_function_1 *adsl_bgt_function_1;  /* chain background-task functions */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
#ifdef HL_UNIX
   struct dsd_ineta_raws_1 *adsl_ineta_raws_1_w1;  /* used INETA       */
   int        *aiml_state_a;                /* address state of HTUN / HTCP session */
   void       **avpl_netw_post_1;           /* address clear structure to post */
#endif
   char       *achl_avl_error;              /* error code AVL tree     */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
#ifdef B120214
   void       *vprl_message[ DEF_MSG_PIPE_LEN ];  /* message in pipe   */
#endif
   struct dsd_bgt_call_1 dsl_bgt_call_1;    /* Background-Task Call    */
   struct dsd_hl_clib_1 dsl_sdh_l1;         /* HOBLink Copy Library 1  */
   char       chrl_ns_1[320];               /* for network-statistic   */
   char       chrl_ns_num[16];              /* for number              */

#define ADSL_AUX_CF1 (&adsp_pd_work->dsc_aux_cf1)  /* auxiliary control structur */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_conn_close() l%05d started ADSL_CONN1_G=0X%p adsp_pd_work=0X%p.",
                   __LINE__, ADSL_CONN1_G, adsp_pd_work );
   m_hlnew_printf( HLOG_TRACE1, "m_conn_close() l%05d dsc_tc1_client.boc_connected=%d dsc_tc1_client.adsc_sdhc1_send=%p.",
                   __LINE__,
                   ADSL_CONN1_G->dsc_tc1_client.boc_connected,
                   ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send );
#endif
//inline void clconn1::cleanup( void ) {      /* cleanup                 */
   if (ADSL_CONN1_G->dsc_timer.vpc_chain_2) {  /* timer still set      */
     m_time_rel( &ADSL_CONN1_G->dsc_timer );  /* release timer         */
   }
#ifndef B140621
   /* check if SDH reload active                                   */
#ifdef WAS_BEFORE_1501
   do {                                     /* loop for multiple entries SDH reload */
#endif
     adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get chain auxiliary ext fields */
     while (adsl_auxf_1_w1) {               /* loop over all entries   */
       if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_sdh_reload) {  /* SDH reload */
         m_sdh_reload_old_end( ADSL_AUX_CF1, adsl_auxf_1_w1 );
         break;
       }
       adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
     }
#ifdef WAS_BEFORE_1501
   } while (adsl_auxf_1_w1);
#endif
#endif
#ifdef B140525
   if (   (ADSL_CONN1_G->iec_st_ses != ied_ses_conn)  /* not connected */
       && (ADSL_CONN1_G->iec_st_ses != ied_ses_rec_close)) {  /* received close */
     goto pcusdh80;                         /* do not call Server-Data-Hook */
   }
   if (   (ADSL_CONN1_G->adsc_server_conf_1 == NULL)  /* no server yet */
       || (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh == 0)) {  /* no server-data-hook */
     goto pcusdh80;                         /* do not call Server-Data-Hook */
   }
#endif
#ifndef B140525
   adsl_server_conf_1_used = ADSL_CONN1_G->adsc_server_conf_1;  /* configuration server */
   if (adsl_server_conf_1_used == NULL) {   /* no configuration server */
     goto pcusdh80;                         /* do not call Server-Data-Hook */
   }
   if (ADSL_CONN1_G->boc_sdh_started == FALSE) {  /* Server-Data-Hooks have been started */
     goto pcusdh80;                         /* do not call Server-Data-Hook */
   }
   if (adsl_server_conf_1_used->adsc_seco1_previous) {  /* configuration server previous */
     adsl_server_conf_1_used = adsl_server_conf_1_used->adsc_seco1_previous;  /* configuration server previous */
   }
   if (adsl_server_conf_1_used->inc_no_sdh == 0) {  /* no server-data-hook */
     goto pcusdh80;                         /* do not call Server-Data-Hook */
   }
#endif
   iml1 = 0;                                /* count the hooks         */

#ifdef B140525
#ifdef B120219
#define ADSL_SDH_LIB1 ((struct dsd_sdh_work_1 *) \
                        ((char *) (ADSL_CONN1_G->adsc_server_conf_1 + 1) \
                          + iml1 * sizeof(struct dsd_sdh_work_1)))->adsc_sdhl_1
#endif
#define ADSL_SDH_LIB1 ((struct dsd_sdh_work_1 *) \
                        ((char *) (ADSL_CONN1_G->adsc_server_conf_1 + 1) \
                          + iml1 * sizeof(struct dsd_sdh_work_1)))->adsc_ext_lib1
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "before pclsdh20 adsc_server_conf_1=%p ...(struct)=%p ADSL_SDH_LIB1=%p",
                   ADSL_CONN1_G->adsc_server_conf_1,
                   ((char *) (ADSL_CONN1_G->adsc_server_conf_1 + 1) + iml1 * sizeof(struct dsd_sdh_work_1)),
                   ADSL_SDH_LIB1 );
#endif
#endif
#ifndef B140525
#define ADSL_SDH_LIB1 ((struct dsd_sdh_work_1 *) \
                        ((char *) (adsl_server_conf_1_used + 1) \
                          + iml1 * sizeof(struct dsd_sdh_work_1)))->adsc_ext_lib1
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "before pclsdh20 adsc_server_conf_1=%p ...(struct)=%p ADSL_SDH_LIB1=%p",
                   ADSL_CONN1_G->adsc_server_conf_1,
                   ((char *) (adsl_server_conf_1_used + 1) + iml1 * sizeof(struct dsd_sdh_work_1)),
                   ADSL_SDH_LIB1 );
#endif
#endif

   pclsdh20:                                /* close Server-Data-Hook  */
   memset( &dsl_sdh_l1, 0, sizeof(dsl_sdh_l1) );
#ifdef B140525
   if (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh < 2) {
     dsl_sdh_l1.ac_ext = ADSL_CONN1_G->dsc_sdh_s_1.ac_ext;  /* attached buffer pointer */
     bol1 = ADSL_CONN1_G->dsc_sdh_s_1.boc_ended;  /* processing of this SDH has ended */
   } else {
     dsl_sdh_l1.ac_ext = ADSL_CONN1_G->adsrc_sdh_s_1[ iml1 ].ac_ext;  /* attached buffer pointer */
     bol1 = ADSL_CONN1_G->adsrc_sdh_s_1[ iml1 ].boc_ended;  /* processing of this SDH has ended */
   }
#endif
#ifndef B140525
   if (adsl_server_conf_1_used->inc_no_sdh < 2) {
     dsl_sdh_l1.ac_ext = ADSL_CONN1_G->dsc_sdh_s_1.ac_ext;  /* attached buffer pointer */
     bol1 = ADSL_CONN1_G->dsc_sdh_s_1.boc_ended;  /* processing of this SDH has ended */
   } else {
     dsl_sdh_l1.ac_ext = ADSL_CONN1_G->adsrc_sdh_s_1[ iml1 ].ac_ext;  /* attached buffer pointer */
     bol1 = ADSL_CONN1_G->adsrc_sdh_s_1[ iml1 ].boc_ended;  /* processing of this SDH has ended */
   }
#endif
   if (bol1) goto pclsdh40;                 /* SDH has already ended   */
   dsl_sdh_l1.inc_func = DEF_IFUNC_CLOSE;
   dsl_sdh_l1.vpc_userfld = ADSL_AUX_CF1;   /* pointer to parameter area */
#ifdef B130314
   ADSL_AUX_CF1->iec_src_func = ied_src_fu_sdh;  /* Server-Data-Hook   */
   /* current Server-Data-Hook                                         */
   ADSL_AUX_CF1->ac_sdh
     = (void *) ((char *) (ADSL_CONN1_G->adsc_server_conf_1 + 1) + iml1 * sizeof(struct dsd_sdh_work_1));
#endif
   ADSL_AUX_CF1->dsc_cid.iec_src_func = ied_src_fu_sdh;  /* Server-Data-Hook */
   /* current Server-Data-Hook                                         */
#ifdef B140525
   ADSL_AUX_CF1->dsc_cid.ac_cid_addr
     = (void *) ((char *) (ADSL_CONN1_G->adsc_server_conf_1 + 1) + iml1 * sizeof(struct dsd_sdh_work_1));
   dsl_sdh_l1.amc_aux = &m_cdaux;           /* subroutine              */
   dsl_sdh_l1.ac_conf = ((struct dsd_sdh_work_1 *) \
                          ((char *) (ADSL_CONN1_G->adsc_server_conf_1 + 1) \
                            + iml1 * sizeof(struct dsd_sdh_work_1)))->ac_conf;
#endif
#ifndef B140525
   ADSL_AUX_CF1->dsc_cid.ac_cid_addr
     = (void *) ((char *) (adsl_server_conf_1_used + 1) + iml1 * sizeof(struct dsd_sdh_work_1));
   dsl_sdh_l1.amc_aux = &m_cdaux;           /* subroutine              */
   dsl_sdh_l1.ac_conf = ((struct dsd_sdh_work_1 *) \
                          ((char *) (adsl_server_conf_1_used + 1) \
                            + iml1 * sizeof(struct dsd_sdh_work_1)))->ac_conf;
#endif
   /* flags of configuration                                           */
   if (ADSL_CONN1_G->adsc_gate1->inc_no_usgro) {  /* user group defined */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_USERLI;
   }
   if (ADSL_CONN1_G->adsc_gate1->imc_no_radius) {  /* radius server defined */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_RADIUS;
     if (ADSL_CONN1_G->adsc_gate1->imc_no_radius > 1) {  /* multiple radius server defined */
       dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_RADIUS;
     }
   }
#ifdef TRACEHL1
   {
     void *vph1, *vph2;
     vph1 = ADSL_SDH_LIB1;
     vph2 = (void *) ADSL_SDH_LIB1->amc_hlclib01;
     m_hlnew_printf( HLOG_XYZ1, "pclsdh20 addr method1 amc_hlclib01=%p", vph2 );
   }
#endif
   ADSL_SDH_LIB1->amc_hlclib01( &dsl_sdh_l1 );
#undef ADSL_SDH_LIB1
#ifdef B140525
   if (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh < 2) {
     ADSL_CONN1_G->dsc_sdh_s_1.ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   } else {
     ADSL_CONN1_G->adsrc_sdh_s_1[ iml1 ].ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   }
#endif
#ifndef B140525
   if (adsl_server_conf_1_used->inc_no_sdh < 2) {
     ADSL_CONN1_G->dsc_sdh_s_1.ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   } else {
     ADSL_CONN1_G->adsrc_sdh_s_1[ iml1 ].ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   }
#endif
#undef ADSL_SDH_LIB1

   pclsdh40:                                /* process next Server-Data-Hook */
   iml1++;                                  /* increment no se-da-hook */
#ifdef B140525
   if (iml1 < ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh) goto pclsdh20;
#endif
#ifndef B140525
   if (iml1 < adsl_server_conf_1_used->inc_no_sdh) goto pclsdh20;
#endif

#ifdef B140525
   if (   (ADSL_CONN1_G->adsrc_sdh_s_1)     /* array work area server data hook per session */
       && (ADSL_CONN1_G->adsc_server_conf_1)  /* server connected      */
       && (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh >= 2)) {  /* array needed */
     free( ADSL_CONN1_G->adsrc_sdh_s_1 );   /* free memory             */
   }
#endif
#ifndef B140525
   if (   (ADSL_CONN1_G->adsrc_sdh_s_1)     /* array work area server data hook per session */
       && (adsl_server_conf_1_used)         /* server connected        */
       && (adsl_server_conf_1_used->inc_no_sdh >= 2)) {  /* array needed */
     free( ADSL_CONN1_G->adsrc_sdh_s_1 );   /* free memory             */
   }
#endif

   pcusdh80:                                /* Server-Data-Hook ended  */
   if (ADSL_CONN1_G->adsc_lbal_gw_1) delete ADSL_CONN1_G->adsc_lbal_gw_1;
#ifdef WORK051119
   if (dcl_wsat1_1) {                       /* class authentication    */
     dcl_wsat1_1->HL_AUTH_ABEND();          /* process abend           */
   }
#endif
#define ADSL_NETW_POST_1 ((struct dsd_netw_post_1 *) ADSL_AUX_CF1->adsc_hco_wothr->vprc_aux_area)

   p_close_20:                              /* wait till data sent to client */
#ifndef B170620
// Stefan Martin SM170609_TCPCONNERR
#define ADSL_PD_WORK_G ((struct dsd_pd_work *) ((char *) vpp_userfld - offsetof( struct dsd_pd_work, dsc_aux_cf1 )))
// ADSL_PD_WORK_G->boc_eof_server = FALSE;              /* Reset EOF server flag in workthread. */
   adsp_pd_work->boc_eof_server = FALSE;              /* Reset EOF server flag in workthread. */
#undef ADSL_PD_WORK_G
#endif
   if (ADSL_CONN1_G->dsc_tc1_client.boc_connected == FALSE) {  /* TCP session is not connected */
     goto p_close_24;                       /* connection to client is closed */
   }
   memset( ADSL_NETW_POST_1, 0, sizeof(struct dsd_netw_post_1) );  /* structure to post from network callback */
   ADSL_NETW_POST_1->adsc_event = &ADSL_AUX_CF1->adsc_hco_wothr->dsc_event;  /* event to be posted */
#ifdef B140721
   ADSL_NETW_POST_1->imc_select = DEF_NETW_POST_1_TCPCOMP_SEND_COMPL;  /* posted for TCPCOMP send complete */
#endif
#ifndef B140721
   ADSL_NETW_POST_1->imc_select
     = DEF_NETW_POST_1_TCPCOMP_SEND_COMPL   /* posted for TCPCOMP send complete */
         | DEF_NETW_POST_1_TCPCOMP_CLEANUP;  /* posted for TCPCOMP cleanup */
#endif
   ADSL_CONN1_G->dsc_tc1_client.adsc_netw_post_1 = ADSL_NETW_POST_1;  /* structure to post from network callback */
#ifndef B140719
   iml_time_1 = m_get_time();               /* get current time        */
#endif
#ifdef B140719
   if (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send) {  /* chain to send */
     while (ADSL_NETW_POST_1->boc_posted == FALSE) {  /* event has not been posted */
       m_hco_wothr_wait( ADSL_AUX_CF1->adsc_hco_wothr );  /* wait for an event */
     }
     goto p_close_20;                       /* wait till data sent to client */
   }
#endif
#ifndef B140719
   if (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send) {  /* chain to send */
     while (TRUE) {                         /* loop to wait            */
       if (ADSL_NETW_POST_1->boc_posted) break;  /* event has been posted */
       iml1
         = iml_time_1                       /* time started            */
             + DEF_CLIENT_SEND_WAIT_SEC_MAX  /* time to wait for TCP send to client at session end */
             - m_get_time();                /* get current time        */
       if (iml1 <= 0) break;                /* time has elapsed        */
       if (iml1 > DEF_CLIENT_SEND_WAIT_SEC_INTV) iml1 = DEF_CLIENT_SEND_WAIT_SEC_INTV;
       m_hco_wothr_nonblock_wait_sec( ADSL_AUX_CF1->adsc_hco_wothr, iml1 );  /* wait for an event */
       if (ADSL_CONN1_G->dsc_tc1_client.boc_connected == FALSE) {  /* TCP session is not connected */
         goto p_close_24;                   /* connection to client is closed */
       }
       if (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send == NULL) break;  /* chain to send */
     }
     adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send;  /* chain to send */
     if (adsl_sdhc1_w1 == NULL) {           /* chain to send empty     */
       goto p_close_20;                     /* wait till data sent to client */
     }
     adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
     iml1 = 0;
     while (adsl_gai1_w1) {                 /* loop over data to send  */
       iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     m_hlnew_printf( HLOG_WARN1, "HWSPS116W GATE=%(ux)s SNO=%08d INETA=%s l%05d at session end could not send %d bytes data to client",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     __LINE__, iml1 );
     ADSL_NETW_POST_1->boc_posted = FALSE;  /* event has not been posted */
   }
#endif
   ADSL_NETW_POST_1->imc_select = DEF_NETW_POST_1_TCPCOMP_CLEANUP;  /* select the events */
   ADSL_CONN1_G->dsc_tc1_client.adsc_netw_post_1 = ADSL_NETW_POST_1;  /* structure to post from network callback */
#ifndef B140627
   if (ADSL_CONN1_G->dsc_tc1_client.boc_connected == FALSE) {  /* TCP session is not connected */
     goto p_close_24;                       /* connection to client is closed */
   }
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T call m_end_session() client %p.",
                   __LINE__, &ADSL_CONN1_G->dsc_tc1_client.dsc_tcpco1_1 );
#endif
   ADSL_CONN1_G->dsc_tc1_client.dsc_tcpco1_1.m_end_session();  /* close TCP session */
#ifndef B13117
   if (ADSL_CONN1_G->dsc_tc1_client.boc_connected == FALSE) {  /* TCP session no more connected */
     ADSL_NETW_POST_1->boc_posted = TRUE;   /* no need to post event   */
   }
#endif
   while (ADSL_NETW_POST_1->boc_posted == FALSE) {  /* event has not been posted */
     m_hco_wothr_wait( ADSL_AUX_CF1->adsc_hco_wothr );  /* wait for an event */
   }
#undef ADSL_NETW_POST_1

   p_close_24:                              /* connection to client is closed */
#ifdef B120214
   if (ADSL_CONN1_G->adsc_radqu) {          /* Radius Query active     */
/* UUUU 19.11.05 KB - end HLWSPAT2 */
     ADSL_CONN1_G->adsc_radqu->m_delete();  /* delete entry            */
   }
#endif
#ifndef B140719
   while (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send) {  /* loop to free chain to send */
     adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send;  /* chain to send */
     ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send = (volatile struct dsd_sdh_control_1 *) adsl_sdhc1_w1->adsc_next;
     m_proc_free( adsl_sdhc1_w1 );          /* free the buffer         */
   }
#endif
// to-do 23.06.14 KB - do earlier, like IBIPGW08.cpp, after timer release
   if (ADSL_CONN1_G->adsc_cpttdt) {         /* connect PTTD thread     */
     ADSL_CONN1_G->adsc_cpttdt->adsc_conn1 = NULL;  /* no more connected */
   }
   if (ADSL_CONN1_G->adsc_csssl_oper_1) {   /* with client-side SSL    */
     m_pd_close_cs_ssl( adsp_pd_work );
   }
   aadsl_sdhc1_adr = NULL;                  /* address chain of buffers */
#ifdef B120708
   if (   (ADSL_CONN1_G->iec_st_ses == ied_ses_conn)  /* status server */
       || (ADSL_CONN1_G->iec_st_ses == ied_ses_rec_close)) {  /* received close */
   }
#endif
   switch (ADSL_CONN1_G->iec_servcotype) {  /* type of server connection */
     case ied_servcotype_normal_tcp:        /* normal TCP              */
       iml1 = 0;                            /* clear count loop        */
       while (ADSL_CONN1_G->dsc_tc1_server.adsc_sdhc1_send) {  /* still data to send */
         iml1++;                            /* increment count loop    */
#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_conn_close() server still data to send",
                         __LINE__, iml1 );
         m_console_out( (char *) &ADSL_CONN1_G->dsc_tc1_server, sizeof(struct dsd_tcp_ctrl_1) );
#endif
         if (iml1 >= 10) break;             /* do not wait any longer  */
         usleep( 500 * 1000 );
       }
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T call m_end_session() server %p.",
                       __LINE__, &ADSL_CONN1_G->dsc_tc1_server.dsc_tcpco1_1 );
#endif
#ifdef B170801
       ADSL_CONN1_G->dsc_tc1_server.dsc_tcpco1_1.m_end_session();  /* close TCP session */
#endif
#ifndef B170801
#define ADSL_NETW_POST_1 ((struct dsd_netw_post_1 *) ADSL_AUX_CF1->adsc_hco_wothr->vprc_aux_area)
       memset( ADSL_NETW_POST_1, 0, sizeof(struct dsd_netw_post_1) );  /* structure to post from network callback */
       ADSL_NETW_POST_1->adsc_event = &ADSL_AUX_CF1->adsc_hco_wothr->dsc_event;  /* event to be posted */
       ADSL_NETW_POST_1->imc_select = DEF_NETW_POST_1_TCPCOMP_CLEANUP;  /* select the events */
       ADSL_CONN1_G->dsc_tc1_server.adsc_netw_post_1 = ADSL_NETW_POST_1;  /* structure to post from network callback */
       ADSL_CONN1_G->dsc_tc1_server.dsc_tcpco1_1.m_end_session();  /* close TCP session */
       if (ADSL_CONN1_G->dsc_tc1_server.boc_connected == FALSE) {  /* TCP session no more connected */
         ADSL_NETW_POST_1->boc_posted = TRUE;  /* no need to post event */
       }
       while (ADSL_NETW_POST_1->boc_posted == FALSE) {  /* event has not been posted */
         m_hco_wothr_wait( ADSL_AUX_CF1->adsc_hco_wothr );  /* wait for an event */
       }
#undef ADSL_NETW_POST_1
#endif
       aadsl_sdhc1_adr = (struct dsd_sdh_control_1 **) &ADSL_CONN1_G->dsc_tc1_server.adsc_sdhc1_send;  /* address chain of buffers */
       break;
#ifdef D_INCL_HOB_TUN
     case ied_servcotype_htun:              /* HOB-TUN                 */
#ifdef TRY_130624_01
       aadsl_sdhc1_adr = &ADSL_CONN1_G->adsc_sdhc1_htun_sch;  /* address chain of buffers */
       if (ADSL_CONN1_G->adsc_ineta_raws_1 == NULL) break;
#endif
#define ADSL_NETW_POST_1 ((struct dsd_netw_post_1 *) ADSL_AUX_CF1->adsc_hco_wothr->vprc_aux_area)
       memset( ADSL_NETW_POST_1, 0, sizeof(struct dsd_netw_post_1) );  /* structure to post from network callback */
       ADSL_NETW_POST_1->adsc_event = &ADSL_AUX_CF1->adsc_hco_wothr->dsc_event;  /* event to be posted */
       ADSL_NETW_POST_1->imc_select = DEF_NETW_POST_1_HTUN_SESS_END;  /* posted for HTUN HTCP session end */
//#ifdef NOT_YET_120916
#ifndef B141202
       adsl_ineta_raws_1_w1 = ADSL_CONN1_G->adsc_ineta_raws_1;
#endif
       adsl_ineta_raws_1_w1->adsc_netw_post_1 = ADSL_NETW_POST_1;  /* structure to post from network callback */
       if (ADSL_CONN1_G->adsc_ineta_raws_1->imc_state
             & (DEF_STATE_HTUN_SESS_END     /* done HOB-TUN HTCP session end */
                  | DEF_STATE_HTUN_ERR_SESS_END)) {  /* done HOB-TUN HTCP session end was with error */
         ADSL_NETW_POST_1->boc_posted = TRUE;  /* as if event has been posted */
       }
//#endif
#ifndef B130109
       aiml_state_a = NULL;                 /* address state of HTUN / HTCP session */
       avpl_netw_post_1 = NULL;             /* address clear structure to post */
#ifdef B141202
       adsl_ineta_raws_1_w1 = ADSL_CONN1_G->adsc_ineta_raws_1;
#endif
       if (   (ADSL_CONN1_G->adsc_server_conf_1)
           && (   (ADSL_CONN1_G->adsc_server_conf_1->inc_function == DEF_FUNC_HPPPT1)   /* PPP type session  */
               || (ADSL_CONN1_G->adsc_server_conf_1->inc_function == DEF_FUNC_SSTP))) {  /* SSTP session type */
         aiml_state_a                       /* address state of HTUN / HTCP session */
           = &ADSL_CONN1_G->imc_ppp_state;  /* PPP state               */
         avpl_netw_post_1                   /* address clear structure to post */
           = (void **) &ADSL_CONN1_G->adsc_ppp_netw_post_1;   /* address structure to post from network callback */
         adsl_ineta_raws_1_w1 = NULL;
       }
       if (adsl_ineta_raws_1_w1) {
         aiml_state_a                       /* address state of HTUN / HTCP session */
           = &adsl_ineta_raws_1_w1->imc_state;  /* HTCP state          */
         avpl_netw_post_1                   /* address clear structure to post */
           = (void **) &adsl_ineta_raws_1_w1->adsc_netw_post_1;  /* address structure to post from network callback */
       }
       if (avpl_netw_post_1) {              /* address clear structure to post */
         *avpl_netw_post_1                  /* address clear structure to post */
           = ADSL_NETW_POST_1;
       }
       if (aiml_state_a == NULL) {          /* no state found          */
         ADSL_NETW_POST_1->boc_posted = TRUE;  /* as if event has been posted */
       } else {
         if (*aiml_state_a
               & (DEF_STATE_HTUN_SESS_END   /* done HOB-TUN HTCP session end */
                    | DEF_STATE_HTUN_ERR_SESS_END))  /* done HOB-TUN HTCP session end was with error */
         ADSL_NETW_POST_1->boc_posted = TRUE;  /* as if event has been posted */
       }
#endif
       m_htun_sess_close( ADSL_CONN1_G->dsc_htun_h );
       while (ADSL_NETW_POST_1->boc_posted == FALSE) {  /* event has not been posted */
         m_hco_wothr_wait( ADSL_AUX_CF1->adsc_hco_wothr );  /* wait for an event */
       }
#ifdef DEBUG_140213_01                      /* crash HOB-TUN          */
       ADSL_CONN1_G->iec_servcotype         /* type of server connection */
         = ied_servcotype_none;             /* no server connection    */
#endif
#ifndef TRY_130624_01
       aadsl_sdhc1_adr = &ADSL_CONN1_G->adsc_sdhc1_htun_sch;  /* address chain of buffers */
#endif
       break;
#undef ADSL_NETW_POST_1
#endif
     case ied_servcotype_l2tp:              /* L2TP                    */
       m_l2tp_close( &ADSL_CONN1_G->dsc_l2tp_session );
       aadsl_sdhc1_adr = &ADSL_CONN1_G->adsc_sdhc1_l2tp_sch;  /* address chain of buffers */
       break;
   }
#ifdef TRACEHL6
       EnterCriticalSection( &ADSL_CONN1_G->adsc_gate1->dcritsect );
       ADSL_CONN1_G->adsc_gate1->i_session_cur++;            /* count later correct     */
       LeaveCriticalSection( &ADSL_CONN1_G->adsc_gate1->dcritsect );
       if (iec_st_ses != ied_ses_conn) {      /* status server           */
         m_hlnew_printf( HLOG_XYZ1, "Session-End iec_st_ses != ied_ses_conn / %d", iec_st_ses );
       }
#endif
#ifdef TRACEHLA
       m_hlnew_printf( HLOG_XYZ1, "--- connection ended auconn11 / this = %08X i_last_action = %d i_prev_action = %d",
                       this, i_last_action, i_prev_action );
#ifdef TRACEHL_ABEND
       bos_error = TRUE;                    /* do nothing more         */
       {
         int imh1, imh2, imh3;
         imh1 = 0;
         imh2 = imh1;
         imh3 = imh2;
         imh2 = 4;
         imh1 = imh2 / imh3;                /* divide by zero          */
//       printf( "abend %d\n", imh1 );
         *((void **) imh3) = 0;             /* access forbidden        */
       }
#endif
#endif
   ADSL_CONN1_G->adsc_gate1->dsc_critsect.m_enter();  /* critical section */
   ADSL_CONN1_G->adsc_gate1->i_session_cur--;  /* count current session */
   ADSL_CONN1_G->adsc_gate1->dsc_critsect.m_leave();  /* critical section */
   achl1 = "logic-error";
   if (ADSL_CONN1_G->achc_reason_end) {     /* reason end session      */
     achl1 = ADSL_CONN1_G->achc_reason_end;  /* set text               */
   }
   chrl_ns_1[0] = 0;                        /* for network-statistic   */
   if (   (ADSL_CONN1_G->adsc_gate1->adsc_loconf_1->inc_network_stat)  /* give network statistic */
       || (ADSL_CONN1_G->imc_trace_level)) {
     iml2 = m_get_time() - ADSL_CONN1_G->imc_time_start;
     iml3 = iml2 / 3600;
     iml5 = iml2 - iml3 * 3600;
     iml4 = iml5 / 60;
     iml5 -= iml4 * 60;
     iml1 = sprintf( chrl_ns_1, " / duration: %d h %d min %d sec", iml3, iml4, iml5 );
     achl2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_rece_c );
     iml1 += sprintf( chrl_ns_1 + iml1, " / client: rec %s", achl2 );
     achl2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_rece_c );
     iml1 += sprintf( chrl_ns_1 + iml1, " - %s bytes", achl2 );
     achl2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_send_c );
     iml1 += sprintf( chrl_ns_1 + iml1, " + send %s", achl2 );
     achl2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_send_c );
     iml1 += sprintf( chrl_ns_1 + iml1, " - %s bytes", achl2 );
     achl2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_rece_s );
     iml1 += sprintf( chrl_ns_1 + iml1, " / server: rec %s", achl2 );
     achl2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_rece_s );
     iml1 += sprintf( chrl_ns_1 + iml1, " - %s bytes", achl2 );
     achl2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_send_s );
     iml1 += sprintf( chrl_ns_1 + iml1, " + send %s", achl2 );
     achl2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_send_s );
     iml1 += sprintf( chrl_ns_1 + iml1, " - %s bytes", achl2 );
     achl2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_rece_e );
     iml1 += sprintf( chrl_ns_1 + iml1, " / encrypted: rec %s", achl2 );
     achl2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_rece_e );
     iml1 += sprintf( chrl_ns_1 + iml1, " - %s bytes", achl2 );
     achl2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_send_e );
     iml1 += sprintf( chrl_ns_1 + iml1, " + send %s", achl2 );
     achl2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_send_e );
     iml1 += sprintf( chrl_ns_1 + iml1, " - %s bytes", achl2 );
   }
   m_hlnew_printf( HLOG_XYZ1, "HWSPS004I GATE=%(ux)s SNO=%08d INETA=%s connection ended - %s%s",
                   ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, achl1, chrl_ns_1 );
   if (ADSL_CONN1_G->imc_trace_level) {
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data   */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SSESSEN1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = m_hlsnprintf( (char *) (ADSL_WTR_G1 + 1), 256, ied_chs_ansi_819,
                          "connection ended - %s%s",
                          achl1, chrl_ns_1 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (   (ADSL_CONN1_G->adsc_gate1->adsc_loconf_1->inc_network_stat >= 4)  /* give network statistic */
       || (ADSL_CONN1_G->imc_trace_level)) {
     adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get chain auxiliary ext field */
     while (adsl_auxf_1_w1) {               /* loop over all entries   */
       if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_gate_udp) {  /* UDP-gate entry */
         m_aux_gate_udp_counter( (char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1),
                                 &iml_c_udp_rece,  /* count receive UDP */
                                 &iml_c_udp_send,  /* count send UDP   */
                                 &ill_d_udp_rece,  /* data receive UDP */
                                 &ill_d_udp_send );  /* data send UDP  */
         achl2 = m_edit_dec_long( chrl_ns_num, ill_d_udp_rece );
         iml1 = sprintf( chrl_ns_1, "received packets %d - %s bytes", iml_c_udp_rece, achl2 );
         achl2 = m_edit_dec_long( chrl_ns_num, ill_d_udp_send );
         iml1 += sprintf( chrl_ns_1 + iml1, " + sent packets %d - %s bytes", iml_c_udp_send, achl2 );
         if (ADSL_CONN1_G->adsc_gate1->adsc_loconf_1->inc_network_stat >= 4) {  /* give network statistic */
           m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnI GATE=%(ux)s SNO=%08d INETA=%s connection ended - UDP-gate %s",
                           ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, chrl_ns_1 );
         }
         if (ADSL_CONN1_G->imc_trace_level) {
           adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
           memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
           adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
           adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
           memcpy( adsl_wt1_w1->chrc_wtrt_id, "SSESSEN2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
           adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
           adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id         */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
           iml1 = m_hlsnprintf( (char *) (ADSL_WTR_G1 + 1), 256, ied_chs_ansi_819,
                                "connection ended - UDP-gate %s",
                                chrl_ns_1 );
           ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed      */
           ADSL_WTR_G1->achc_content        /* content of text / data  */
             = (char *) (ADSL_WTR_G1 + 1);
           ADSL_WTR_G1->imc_length = iml1;  /* length of text / data   */
           adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
           m_wsp_trace_out( adsl_wt1_w1 );  /* output of WSP trace record */
         }
       }
       adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
     }
   }
   adsl_bgt_contr_1 = adsg_loconf_1_inuse->adsc_bgt_contr_1;  /* chain background-task control */
   while (adsl_bgt_contr_1) {               /* loop over background-tasks */
     adsl_bgt_function_1 = adsl_bgt_contr_1->adsc_bgt_function_1;  /* chain background-task functions */
     do {                                   /* loop over background-task functions */
       if (adsl_bgt_function_1->iec_bgtf == ied_bgtf_end_session) {  /* called at end of session */
#ifdef XYZ1
         memset( &dsl_aux_cf1, 0, sizeof(struct dsd_aux_cf1) );  /* auxiliary control structure */
         dsl_aux_cf1.adsc_conn = this;  /* set connection          */
         dsl_aux_cf1.adsc_hco_wothr = adsp_hco_wothr;  /* pointer on work-thread */
         dsl_aux_cf1.iec_src_func = ied_src_fu_bgt_end_session;  /* background-task at end of session */
         this->adsc_aux_cf1_cur = &dsl_aux_cf1;  /* current auxiliary control structure */
#endif
#ifdef B130314
         adsp_pd_work->dsc_aux_cf1.iec_src_func = ied_src_fu_bgt_end_session;  /* background-task at end of session */
#endif
         adsp_pd_work->dsc_aux_cf1.dsc_cid.iec_src_func = ied_src_fu_bgt_end_session;  /* background-task at end of session */
         memset( &dsl_bgt_call_1, 0, sizeof(struct dsd_bgt_call_1) );  /* Background-Task Call */
         dsl_bgt_call_1.imc_func = DEF_IFUNC_CONT;  /* process data as specified */
         dsl_bgt_call_1.ac_conf = adsl_bgt_contr_1->ac_conf;  /* data from configuration */
#ifdef XYZ1
         dsl_bgt_call_1.vpc_userfld = &dsl_aux_cf1;  /* auxiliary control structure */
#endif
         dsl_bgt_call_1.vpc_userfld = &adsp_pd_work->dsc_aux_cf1;  /* auxiliary control structure */
         dsl_bgt_call_1.amc_aux = &m_cdaux;  /* subroutine         */
         dsl_bgt_call_1.adsc_bgt_function_1 = adsl_bgt_function_1;  /* called for background-task function */
         dsl_bgt_call_1.imc_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* session number */
         adsl_bgt_contr_1->adsc_ext_lib1->amc_bgt_entry( &dsl_bgt_call_1 );
       }
       adsl_bgt_function_1 = adsl_bgt_function_1->adsc_next;  /* get next in chain */
     } while (adsl_bgt_function_1);
     adsl_bgt_contr_1 = adsl_bgt_contr_1->adsc_next;  /* get next in chain */
   }
#ifdef B130216
   if (ADSL_CONN1_G->adsc_conn_server) {    /* temporary connect to server */
     free( ADSL_CONN1_G->adsc_conn_server );  /* free memory again     */
   }
#endif
/*
   to-do 21.06.14 KB
   call m_sdh_cleanup( ADSL_AUX_CF1, NULL );
*/
#ifndef B140709
   if (ADSL_CONN1_G->adsc_wsp_auth_1) {     /* structure for authentication */
     m_auth_delete( adsp_pd_work, ADSL_CONN1_G->adsc_wsp_auth_1 );
   }
   if (ADSL_CONN1_G->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
     m_close_webso_conn( ADSL_AUX_CF1 );
   }
#endif
   while (ADSL_CONN1_G->adsc_auxf_1) {      /* chain auxiliary ext fields */
#ifdef TRACEHLP
     m_hlnew_printf( HLOG_TRACE1, "chain auxiliary ext field not empty / addr=%p iec_auxf_def=%d",
                     ADSL_CONN1_G->adsc_auxf_1, ADSL_CONN1_G->adsc_auxf_1->iec_auxf_def );
#endif
     adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* save old field    */
     ADSL_CONN1_G->adsc_auxf_1 = ADSL_CONN1_G->adsc_auxf_1->adsc_next;  /* get next in chain */
     switch (adsl_auxf_1_w1->iec_auxf_def) {
       case ied_auxf_defstor:               /* predefined storage      */
         m_proc_free( adsl_auxf_1_w1 );     /* put in chain of unused  */
         adsl_auxf_1_w1 = NULL;             /* no memory to free       */
         break;
       case ied_auxf_normstor:              /* normal storage          */
         break;                             /* free memory             */
       case ied_auxf_timer:                 /* timer                   */
         break;                             /* free memory             */
       case ied_auxf_certname:              /* name from certificate = DN */
         break;                             /* free memory             */
       case ied_auxf_certificate:           /* certificate             */
         break;                             /* free memory             */
       case ied_auxf_radqu:                 /* Radius query            */
#ifdef XYZ1
#define ADSL_RC1 ((struct dsd_radius_control_1 *) (adsl_auxf_1_w1 + 1))
         m_radius_cleanup( ADSL_RC1 );      /* Radius request no more needed */
#undef ADSL_RC1
#endif
#ifndef B141029
#define ADSL_RCTRL1_G ((struct dsd_radius_control_1 *) (adsl_auxf_1_w1 + 1))
         m_radius_cleanup( ADSL_RCTRL1_G );  /* do cleanup             */
#undef ADSL_RCTRL1_G
#endif
         break;                             /* free memory             */
       case ied_auxf_ocsp:                  /* OCSP entry              */
#ifdef TRACEHLP
         m_hlnew_printf( HLOG_XYZ1, "chain auxiliary ext field OCSP found" );
#endif
         m_ocsp_cleanup( ADSL_CONN1_G, adsl_auxf_1_w1 );
         break;
#ifdef B130911
       case ied_auxf_radqu:                 /* Radius query            */
// 08.02.12 KB m_radius_cleanup() not needed
#ifdef B120208
         m_radius_cleanup( (struct dsd_radius_control_1 *) (adsl_auxf_1_1 + 1) );
         adsl_auxf_1_1 = NULL;              /* no memory to free       */
#endif
         break;
#endif
       case ied_auxf_diskfile:              /* link to disk file       */
         time( (time_t *) &(*((struct dsd_diskfile_1 **) (adsl_auxf_1_w1 + 1)))->ipc_time_last_acc );  /* get current time */
         dss_critsect_aux.m_enter();
         (*((struct dsd_diskfile_1 **) (adsl_auxf_1_w1 + 1)))->inc_usage_count--;  /* usage-count */
         dss_critsect_aux.m_leave();
         break;
#ifdef XYZ1
       case ied_auxf_cma1:                  /* common memory area      */
#ifdef B060422
         /* activate all work threads that are waiting             */
         while (((struct dsd_wsp_cma_lock_1 *) (adsl_auxf_1_w1 + 1))->ADSL_CONN1_G->adsc_workth) {
           adsl_workth_1 = ((struct dsd_wsp_cma_lock_1 *) (adsl_auxf_1_w1 + 1))->ADSL_CONN1_G->adsc_workth;
           ((struct dsd_wsp_cma_lock_1 *) (adsl_auxf_1_w1 + 1))->ADSL_CONN1_G->adsc_workth
             = (class clworkth *) adsl_workth_1->vpc_lock_1;
           bol1 = SetEvent( adsl_workth_1->hevework );
           if (bol1 == FALSE) {
             m_hlnew_printf( HLOG_XYZ1, "HWSPM060W clconn1::close1() SetEvent WORK Error %d",
                             GetLastError() );
           }
         }
#endif
         break;
#endif
       case ied_auxf_cma1:                  /* common memory area      */
         /* activate all work threads that are waiting                 */
         m_hco_wothr_unlock( ADSL_AUX_CF1->adsc_hco_wothr,
                             (struct dsd_hco_lock_1 *) (adsl_auxf_1_w1 + 1) );
         break;
       case ied_auxf_q_gather:              /* query gather            */
         break;                             /* free memory             */
       case ied_auxf_sess_stor:             /* Session Storage         */
         break;                             /* free memory             */
       case ied_auxf_service_query_1:       /* service query 1         */
#ifdef B131224
         ((struct dsd_service_aux_1 *) ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1)) + 1)->amc_service_close
                                        ( ADSL_AUX_CF1, (char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1) );
#endif
         ((struct dsd_service_aux_1 *) ((char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1)))->amc_service_close
                                        ( ADSL_AUX_CF1, (char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1) );
         break;
       case ied_auxf_ldap:                  /* LDAP service            */
         m_ldap_free( (class dsd_ldap_cl *) (adsl_auxf_1_w1 + 1) );
         break;
       case ied_auxf_sip:                   /* SIP request             */
         m_aux_sip_cleanup( ADSL_CONN1_G, (char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1) );
         break;
       case ied_auxf_udp:                   /* UDP request             */
         m_aux_udp_cleanup( ADSL_CONN1_G, (char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1) );
         break;
       case ied_auxf_gate_udp:              /* UDP-gate entry          */
         m_aux_gate_udp_cleanup( ADSL_CONN1_G, (char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1) );
         break;
       case ied_auxf_sessco1:               /* session configuration   */
         break;                             /* free memory             */
//     case ied_auxf_sessco1:               /* session configuration   */
//       break;
       case ied_auxf_admin:                 /* admin command           */
         while (((struct dsd_auxf_admin1 *) ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1) + 1))->adsc_sdhc1_1) {  /* buffers from previous calls */
           adsl_sdhc1_w1 = ((struct dsd_auxf_admin1 *) ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1) + 1))->adsc_sdhc1_1;
           ((struct dsd_auxf_admin1 *) ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1) + 1))->adsc_sdhc1_1
             = adsl_sdhc1_w1->adsc_next;    /* remove from chain       */
           m_proc_free( adsl_sdhc1_w1 );    /* free the buffer         */
         }
         break;
       case ied_auxf_ident:                 /* ident - userid and user-group */
#ifdef B130602
         if (adsc_ineta_raws_1 == NULL) break;  /* auxiliary field for HOB-TUN */
// to-do 17.03.13 KB - other solution
         adsc_ineta_raws_1->adsc_auxf_1_ident = adsl_auxf_1_1;  /* store ident to free */
         adsl_auxf_1_1 = NULL;              /* do not free memory      */
#endif
         break;
       case ied_auxf_pipe_listen:           /* aux-pipe create with name */
         m_aux_pipe_listen_cleanup( ADSL_CONN1_G, adsl_auxf_1_w1 );
         break;
       case ied_auxf_pipe_conn:             /* aux-pipe established connection */
         m_aux_pipe_conn_cleanup( ADSL_CONN1_G, adsl_auxf_1_w1 );
         break;
       case ied_auxf_util_thread:           /* utility thread          */
#define ADSL_UTC_G ((struct dsd_util_thread_ctrl *) (adsl_auxf_1_w1 + 1))
         /* set signal to terminate the utility thread                 */
         ADSL_UTC_G->dsc_utp1.imc_signal |= HL_AUX_SIGNAL_CANCEL;
         dss_critsect_aux.m_enter();        /* critical section        */
         /* connection to session has ended                            */
         ADSL_UTC_G->dsc_ete.ac_conn1 = NULL;  /* clear connection     */
         /* check if utility thread is still running                   */
         if (ADSL_UTC_G->boc_thread_ended == FALSE) {  /* thread has not yet ended */
           /* utility thread will free all resources                   */
           adsl_auxf_1_w1 = NULL;           /* do not free memory now  */
         }
         dss_critsect_aux.m_leave();        /* critical section        */
         if (adsl_auxf_1_w1) {              /* memory to free          */
           while (ADSL_UTC_G->adsc_auxf_1) {  /* chain auxiliary extension fields */
             adsl_auxf_1_w2 = ADSL_UTC_G->adsc_auxf_1;  /* get first in chain auxiliary extension fields */
             ADSL_UTC_G->adsc_auxf_1 = adsl_auxf_1_w2->adsc_next;  /* remove from chain */
             if (adsl_auxf_1_w2->iec_auxf_def == ied_auxf_normstor) {  /* normal storage */
               free( adsl_auxf_1_w2 );      /* free memory             */
             } else {                       /* other type              */
               m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s ied_auxf_util_thread l%05d cannot free resource %p iec_auxf_def %d.",
                               ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                               __LINE__, adsl_auxf_1_w2, adsl_auxf_1_w2->iec_auxf_def );
             }
           }
         }
         break;
#undef ADSL_UTC_G
       case ied_auxf_swap_stor:             /* swap storage            */
         m_aux_swap_stor_cleanup( ADSL_AUX_CF1->adsc_hco_wothr, ADSL_CONN1_G, adsl_auxf_1_w1 );
         break;
//     case ied_auxf_dyn_lib:               /* dynamic library         */
//       break;
       case ied_auxf_sdh_reload:            /* SDH reload              */
         break;                             /* nothing to do, already processed before */
       case ied_auxf_mppe_keys:             /* SSTP - HLAK             */
         break;
       default:
         m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_conn_close() l%05d cannot free resource %p iec_auxf_def %d.",
                         ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                         __LINE__, adsl_auxf_1_w1, adsl_auxf_1_w1->iec_auxf_def );
     }
     if (adsl_auxf_1_w1) {                  /* memory to free          */
       free( adsl_auxf_1_w1 );              /* free memory extension   */
     }
   }
#ifdef TRACEHLP
   iml1 = 0;                                /* count buffers           */
#endif
   while (ADSL_CONN1_G->adsc_sdhc1_chain) {  /* free all buffers       */
#ifdef TRACEHLP
     iml1++;                                /* count buffers           */
#endif
     adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;   /* this is buffer          */
     ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     m_proc_free( adsl_sdhc1_w1 );         /* free buffer             */
   }
#ifdef TRACEHLP
   if (iml1) {
     m_hlnew_printf( HLOG_XYZ1, "leak struct dsd_sdh_control_1 count=%d", iml1 );
   }
   m_hlnew_printf( HLOG_XYZ1, "current memory size inc_aux_mem_cur = %d/0X%08X",
                   ADSL_CONN1_G->inc_aux_mem_cur, ADSL_CONN1_G->inc_aux_mem_cur );
   m_hlnew_printf( HLOG_XYZ1, "maximum memory size inc_aux_mem_max = %d/0X%08X",
                   ADSL_CONN1_G->inc_aux_mem_max, ADSL_CONN1_G->inc_aux_mem_max );
#endif
#ifdef TRACEHLP
   m_hlnew_printf( HLOG_XYZ1, "ins_count_buf_in_use=%d ins_count_buf_max=%d ins_count_memory=%d",
                   ins_count_buf_in_use, ins_count_buf_max, ins_count_memory );
   m_hlnew_printf( HLOG_XYZ1, "HWSPR001I Report session-end / number of Work Threads %d - scheduled %d - busy %d - longest queue %d",
                   dsg_hco_main.imc_workthr_alloc, dsg_hco_main.imc_workthr_sched,
                   dsg_hco_main.imc_workthr_active, dsg_hco_main.imc_workque_max_no );
#endif
#ifdef TRACEHLC
   m_check_aclconn1( this, 189 );
#endif
#ifdef B120219
   if (   (ADSL_CONN1_G->avprc_sdh)         /* address array serv-d-ho */
       && (ADSL_CONN1_G->adsc_server_conf_1)  /* server connected      */
       && (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh >= 2)) {  /* array needed */
     free( ADSL_CONN1_G->avprc_sdh );       /* free memory             */
   }
#endif
   if (ADSL_CONN1_G->adsc_server_conf_1) {  /* with server             */
#ifdef B130219
     if (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic) {  /* dynamically allocated */
       free( ADSL_CONN1_G->adsc_server_conf_1 );  /* free server entry */
     }
#else
     if (ADSL_CONN1_G->adsc_server_conf_1->adsc_seco1_previous) {  /* configuration server previous */
       free( ADSL_CONN1_G->adsc_server_conf_1 );  /* free server entry */
     }
#endif
   }
#ifdef TRACEHL6
       EnterCriticalSection( &ADSL_CONN1_G->adsc_gate1->dcritsect );
       ADSL_CONN1_G->adsc_gate1->i_session_cur--;            /* count current session   */
       LeaveCriticalSection( &ADSL_CONN1_G->adsc_gate1->dcritsect );
       memset( this, 0, sizeof(class clconn1) );
       {
         struct DTHRR *audthrr_1;
         audthrr_1 = cl_tcp_r::adthrr_a;    /* get anchor              */
         while (audthrr_1) {
           SetEvent( audthrr_1->dhandthr[0] );
           audthrr_1 = audthrr_1->next;     /* get next in chain       */
         }
       }
#endif
#ifdef B120214
   *((ied_message *) &vprl_message[0]) = ied_me_end_session;  /* type of message */
   vprl_message[1] = ADSL_CONN1_G;          /* pointer to class        */
   iml1 = write( ADSL_CONN1_G->adsc_cothr->ifdpipe[1], vprl_message, sizeof(vprl_message) );
#ifdef TRACEHL1
   printf( "l%05d write pipe completed / returned iml1=%d errno=%d\n", __LINE__, iml1, errno );
#endif
#endif
   achl_avl_error = NULL;                   /* clear error code AVL tree */
   dss_main_critsect.m_enter();             /* enter CriticalSection   */
   do {                                     /* pseudo-loop             */
     bol1 = m_htree1_avl_search( NULL, &dss_htree1_avl_cntl_conn,
                                 &dsl_htree1_work, &ADSL_CONN1_G->dsc_co_sort.dsc_sort_1 );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "m_htree1_avl_search() failed";  /* error code AVL tree */
       break;                               /* do not continue         */
     }
     if (dsl_htree1_work.adsc_found == NULL) {  /* not found in tree   */
       achl_avl_error = "m_htree1_avl_search() session-id not found in tree";  /* error code AVL tree */
       break;                               /* do not continue         */
     }
     bol1 = m_htree1_avl_delete( NULL, &dss_htree1_avl_cntl_conn,
                                 &dsl_htree1_work );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "m_htree1_avl_delete() failed";  /* error code AVL tree */
       break;                               /* do not continue         */
     }
   } while (FALSE);
   dss_main_critsect.m_leave();             /* leave CriticalSection   */
   if (achl_avl_error) {                    /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPS111W GATE=%(ux)s SNO=%08d INETA=%s remove sno error %s",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, achl_avl_error );
   }
   if (ADSL_CONN1_G->adsc_sdhc1_c1) m_proc_free( ADSL_CONN1_G->adsc_sdhc1_c1 );
   if (ADSL_CONN1_G->adsc_sdhc1_c2) m_proc_free( ADSL_CONN1_G->adsc_sdhc1_c2 );
   if (ADSL_CONN1_G->adsc_sdhc1_s1) m_proc_free( ADSL_CONN1_G->adsc_sdhc1_s1 );
   if (ADSL_CONN1_G->adsc_sdhc1_s2) m_proc_free( ADSL_CONN1_G->adsc_sdhc1_s2 );
#ifdef NOT_YET_120214
   while (dcl_tcp_r_c.adsc_sdhc1_send) {  /* loop over all buffers */
     adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) dcl_tcp_r_c.adsc_sdhc1_send;  /* save this buffer */
     dcl_tcp_r_c.adsc_sdhc1_send = dcl_tcp_r_c.adsc_sdhc1_send->adsc_next;  /* get next in chain */
     m_proc_free( adsl_sdhc1_w1 );      /* free this buffer        */
   }
#endif
   if (aadsl_sdhc1_adr) {                   /* address chain of buffers set */
     while (*aadsl_sdhc1_adr) {             /* loop over all buffers   */
       adsl_sdhc1_w1 = *aadsl_sdhc1_adr;    /* save this buffer        */
       *aadsl_sdhc1_adr = (*aadsl_sdhc1_adr)->adsc_next;  /* get next in chain */
       m_proc_free( adsl_sdhc1_w1 );        /* free this buffer        */
     }
   }
#ifdef B140709
   if (ADSL_CONN1_G->adsc_wsp_auth_1) {     /* structure for authentication */
     m_auth_delete( adsp_pd_work, ADSL_CONN1_G->adsc_wsp_auth_1 );
   }
   if (ADSL_CONN1_G->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
     m_close_webso_conn( ADSL_AUX_CF1 );
   }
#endif
   if (ADSL_CONN1_G->adsc_wtsudp1) {
     if (ADSL_CONN1_G->adsc_wtsudp1->dsc_wln_ipv4.adsc_wsp_udp_1) {  /* WTS UDP - also means in use */
       m_close_udp_multiw_1( &ADSL_CONN1_G->adsc_wtsudp1->dsc_wln_ipv4.dsc_udp_multiw_1 );  /* structure for multiple wait */
     }
     if (ADSL_CONN1_G->adsc_wtsudp1->dsc_wln_ipv6.adsc_wsp_udp_1) {  /* WTS UDP - also means in use */
       m_close_udp_multiw_1( &ADSL_CONN1_G->adsc_wtsudp1->dsc_wln_ipv6.dsc_udp_multiw_1 );  /* structure for multiple wait */
     }
     m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
     usleep( 200 );
     m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
     while (ADSL_CONN1_G->adsc_wtsudp1->adsc_sdhc1_rec) {  /* received UDP packets */
       adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_wtsudp1->adsc_sdhc1_rec;  /* get first in chain */
       ADSL_CONN1_G->adsc_wtsudp1->adsc_sdhc1_rec = adsl_sdhc1_w1->adsc_next;  /* set new chain */
       m_proc_free( adsl_sdhc1_w1 );    /* free memory             */
     }
     free( ADSL_CONN1_G->adsc_wtsudp1 );
   }
//---
#ifdef TRACEHLX
   m_hlnew_printf( HLOG_XYZ1, "m_conn_close l%05d end %p", __LINE__, ADSL_CONN1_G );
#endif
   ADSL_CONN1_G->dsc_timer.amc_compl = &m_free_session_b;  /* set routine for free after timer */
   ADSL_CONN1_G->dsc_timer.ilcwaitmsec = DEF_TIMER_FREE_SESSION_B;  /* delay in milliseconds before freeing the session block */
   m_time_set( &ADSL_CONN1_G->dsc_timer, FALSE );  /* set timer now    */
#ifdef TRACEHLC
       m_check_aclconn1( NULL, 200 );
#endif
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
#ifdef XYZ1
   if (bos_shutdown == FALSE) return;       /* is in graceful shutdown */
#endif
   if (dsg_sys_state_1.boc_listen_ended == FALSE) return;  /* listen has already ended */
   iml_rc = write( imrs_m_fd_pipe[1], vprs_message_shutdown, sizeof(vprs_message_shutdown) );
   if (iml_rc == sizeof(vprs_message_shutdown)) return;
   m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW nbipgw20 l%05d write pipe shutdown error %d %d.",
                   __LINE__, iml_rc, errno );
} /* end m_conn_close()                                                */

#ifndef D_INCL_HOB_TUN
//simulation function which returns a newly allocated buffer amd its length
extern "C" int m_htun_getrecvbuf( void **aap_handle, char **aachp_buffer ) {
#ifdef OLD01
   *aap_handle = new char[16384];
   *aachp_buffer = (char*)*aap_handle;
   return 16384;
#endif
   *aap_handle = m_proc_alloc();
   *aachp_buffer = (char *) *aap_handle + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1);
   return LEN_TCP_RECV - sizeof(struct dsd_sdh_control_1) - sizeof(struct dsd_gather_i_1);
} /* end m_htun_getrecvbuf()                                           */

//simulation function which releases a previously allocated buffer
extern "C" void m_htun_relrecvbuf( void *ap_handle ) {
#ifdef OLD01
   delete ap_handle;
#endif
   m_proc_free( ap_handle );
} /* end m_htun_relrecvbuf()                                           */
#endif

//#ifdef NOT_YET /* in xi...tun */
extern "C" struct dsd_wsptun_conf_1 * m_get_wsptun_conf_1() {
#ifdef D_INCL_HOB_TUN
   struct dsd_raw_packet_if_conf *adsl_raw_packet_if_conf;  /* configuration raw-packet-interface */

#ifdef B100702
   return &dss_wsptun_conf_1;
#endif
   adsl_raw_packet_if_conf = dss_loconf_1.adsc_raw_packet_if_conf;  /* get configuration raw-packet-interface */
   if (adsl_raw_packet_if_conf == NULL) return NULL;  /* did not find the configuration */
   return &adsl_raw_packet_if_conf->dsc_wsptun_conf_1;  /* TUN PPP INETAs */
#else
   return NULL;
#endif
} /* end m_get_wsptun_conf_1()                                         */

extern "C" char * m_get_wsptun_ineta_ipv4_adapter() {
#ifdef D_INCL_HOB_TUN
#ifdef B130109
   struct dsd_raw_packet_if_conf *adsl_raw_packet_if_conf;  /* configuration raw-packet-interface */

   adsl_raw_packet_if_conf = dss_loconf_1.adsc_raw_packet_if_conf;  /* get configuration raw-packet-interface */
   if (adsl_raw_packet_if_conf == NULL) return NULL;  /* did not find the configuration */
   return (char *) &adsl_raw_packet_if_conf->umc_ta_ineta_local;  /* <TUN-adapter-ineta> */
#endif
   return dsg_tun_ctrl.achc_ta_ineta_ipv4;  /* entry <TUN-adapter-ineta> IPV4 */
#else
   return NULL;
#endif
} /* end m_get_wsptun_ineta_ipv4_adapter()                             */
//#endif

/** return information about connection for WSP trace                  */
extern "C" void m_get_wsp_trace_info_conn1( struct dsd_wsp_trace_info_conn1 *adsp_wtic, void *ap_conn1 ) {
#ifdef NOT_YET_110808
#define ADSL_CONN1_G ((class clconn1 *) ap_conn1)
   memset( adsp_wtic, 0, sizeof(struct dsd_wsp_trace_info_conn1) );
   adsp_wtic->imc_trace_level = ADSL_CONN1_G->imc_trace_level;  /* trace_level */
   adsp_wtic->imc_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
#undef ADSL_CONN1_G
#endif
} /* end m_get_wsp_trace_info_conn1()                                  */

/** activate work-thread if not already active                         */
static inline void m_act_thread_1( struct dsd_conn1 *adsp_conn1 ) {
   BOOL       bol1;                         /* working-variable        */
   int        iml_rc;                       /* return code             */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_act_thread_1 l%05d adsp_conn1=%p boc_st_act=%d.",
                   __LINE__, adsp_conn1, adsp_conn1->boc_st_act );
#endif
   bol1 = FALSE;                            /* not yet set             */
   iml_rc = adsp_conn1->dsc_critsect.m_enter();  /* enter CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_enter() critical section failed %d.",
                     adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
   }
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                   __LINE__, HL_THRID, &adsp_conn1->dsc_critsect );
#endif
   if (adsp_conn1->boc_st_act == FALSE) {   /* thread does not run     */
     adsp_conn1->boc_st_act = TRUE;         /* thread will run soon    */
     bol1 = TRUE;                           /* activate thread         */
   }
   iml_rc = adsp_conn1->dsc_critsect.m_leave();  /* leave CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_leave() critical section failed %d.",
                     adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta, iml_rc );
   }
   if (bol1 == FALSE) return;
   m_act_thread_2( adsp_conn1 );
   return;
} /* end m_act_thread_1()                                              */

/** activate work-thread                                               */
static inline void m_act_thread_2( struct dsd_conn1 *adsp_conn1 ) {
   struct dsd_call_para_1 dsl_call_para_1_w1;  /* call parameters      */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_act_thread_2 l%05d adsp_conn1=%p",
                   __LINE__, adsp_conn1 );
#endif
   memset( &dsl_call_para_1_w1, 0, sizeof(struct dsd_call_para_1) );
   dsl_call_para_1_w1.amc_function = &m_proc_data;
   dsl_call_para_1_w1.ac_param_1 = adsp_conn1;
   m_hco_run_thread( &dsl_call_para_1_w1 );
   return;
} /* end m_act_thread_2()                                              */

/** routine called by timer thread when a connection timed out         */
static void m_timeout_conn( struct dsd_timer_ele *adsp_timer_ele ) {
#ifndef B150121
   int        iml_rc;                       /* return code             */
#endif
   HL_LONGLONG ill1;                        /* working-variable        */
   char       *achl1;                       /* working-variable        */
   BOOL       bol_act_conn;                 /* activate connection     */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
#ifdef TRACEHL1
   struct dsd_conn1 *adsl_clconn1_t1;
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-%05d-T m_timeout_conn( %p )",
                   __LINE__, adsp_timer_ele );
#endif
#ifndef PROBLEM_OFFSETOF_110810
#define ADSL_CONN1_G ((struct dsd_conn1 *) ((char *) adsp_timer_ele - offsetof( struct dsd_conn1 , dsc_timer )))
#ifdef TRACEHL1
   adsl_clconn1_t1 = ADSL_CONN1_G;
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-%05d-T m_timeout_conn( %p ) clconn1=%p vpc_chain_2=%p",
                   __LINE__, adsp_timer_ele, adsl_clconn1_t1, adsp_timer_ele->vpc_chain_2 );
#endif
   if (   (ADSL_CONN1_G->ilc_timeout == 0)  /* timeout not set         */
       && (ADSL_CONN1_G->adsc_aux_timer_ch == NULL)) {  /* no auxiliary timer */
     return;
   }
   ill1 = m_get_epoch_ms();                 /* get current time        */
   bol_act_conn = FALSE;                    /* reset activate connection */
#ifndef B150121
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_aux_timer_ch;  /* get anchor of chain */
   if (adsl_auxf_1_w1 == NULL) {            /* no timer chain          */
     goto p_timer_20;                       /* part of timer processed */
   }
   iml_rc = ADSL_CONN1_G->dsc_critsect.m_enter();  /* enter CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_enter() critical section failed %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, iml_rc );
   }
#endif
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_aux_timer_ch;  /* get anchor of chain */
   while (adsl_auxf_1_w1) {                 /* loop over timer entries */
     if (((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->ilc_endtime
           > ill1) {
       break;                               /* timer not yet expired   */
     }
#ifdef XYZ1
     if (((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->iec_auxtu == ied_auxtu_sdh_reload) {  /* wait for SDH-reload */
       if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
         ADSL_CONN1_G->achc_reason_end = "timeout reconnect";  /* set text */
       }
       achl1 = "HWSPS034W GATE=%S SNO=%08d INETA=%s waiting for reconnect - timed out";
       goto p_message;                      /* output message and cancel connection */
     }
#endif
     if (((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->boc_expired == FALSE) {
       ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->boc_expired = TRUE;
#ifndef B130314
       ADSL_CONN1_G->boc_signal_set = TRUE;  /* signal for component set */
#endif
       bol_act_conn = TRUE;                 /* activate connection     */
     }
     adsl_auxf_1_w1 = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->adsc_auxf_next;
   }
#ifdef PROB_T_060504                        /* problem with timer      */
#ifdef B060628
   if (adssticha_anchor) {
     if (adssticha_anchor->adsctiele_first == NULL) {
       m_hlnew_printf( HLOG_XYZ1, "nbipgw20 l%05d m_timeout_conn() error PROB_T_060504",
                       __LINE__ );
     }
   }
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20 l%05d m_timeout_conn() &dsc_timer=%p vpc_chain_2=%p adsl_auxf_1_w1=%p",
                   __LINE__, &ADSL_CONN1_G->dsc_timer, ADSL_CONN1_G->dsc_timer.vpc_chain_2, adsl_auxf_1_w1 );
#endif /* PROB_T_060504                     problem with timer         */
#endif
#ifndef B150121
   iml_rc = ADSL_CONN1_G->dsc_critsect.m_leave();  /* leave CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_leave() critical section failed %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, iml_rc );
   }

   p_timer_20:                              /* part of timer processed */
#endif
   if (ADSL_CONN1_G->ilc_timeout == 0) {    /* timeout not set         */
     if (adsl_auxf_1_w1) {                  /* with auxiliary timer    */
       ADSL_CONN1_G->dsc_timer.ilcendtime
         = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->ilc_endtime;
       m_time_set( &ADSL_CONN1_G->dsc_timer, TRUE );  /* set timer from new */
     }
   } else if (ill1 < ADSL_CONN1_G->ilc_timeout) {  /* did not timeout yet */
     ADSL_CONN1_G->dsc_timer.ilcendtime = ADSL_CONN1_G->ilc_timeout;
     if (   (adsl_auxf_1_w1)
         && (((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->ilc_endtime
               < ADSL_CONN1_G->dsc_timer.ilcendtime)) {
       ADSL_CONN1_G->dsc_timer.ilcendtime
         = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->ilc_endtime;
     }
     m_time_set( &ADSL_CONN1_G->dsc_timer, TRUE );  /* set timer from new */
   }
   if (bol_act_conn) {                      /* activate connection     */
     m_act_thread_1( ADSL_CONN1_G );        /* has to process timer    */
   }
   if (ADSL_CONN1_G->ilc_timeout == 0) return;  /* timeout not set     */
   if (ill1 < ADSL_CONN1_G->ilc_timeout) return;  /* did not timeout yet */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-%05d-T connection %p timed out time-sec=%d",
                   __LINE__, ADSL_CONN1_G, m_get_time() );
#endif
   if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
     ADSL_CONN1_G->achc_reason_end = "timeout";  /* set text           */
     if (ADSL_CONN1_G->boc_st_sslc == FALSE) {  /* check status SSL    */
       ADSL_CONN1_G->achc_reason_end = "timeout SSL";  /* set text     */
     }
   }
   achl1 = "HWSPS032W GATE=%(ux)s SNO=%08d INETA=%s connection timed out";
   if (ADSL_CONN1_G->boc_st_sslc == FALSE) {  /* check status SSL      */
     achl1 = "HWSPS031W GATE=%(ux)s SNO=%08d INETA=%s connection timed out (SSL)";
   }
#ifdef XYZ1

   p_message:                               /* output message and cancel connection */
#endif
   m_hlnew_printf( HLOG_WARN1, achl1,
                   (WCHAR *) (ADSL_CONN1_G->adsc_gate1 + 1), ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta );
// to-do 19.02.12 KB subroutine cancel session - admin and timeout
   m_cancel_conn( ADSL_CONN1_G );           /* cancel the connection   */
// to-do 19.02.12 KB WSP trace
#undef ADSL_CONN1_G
#endif
} /* end m_timeout_conn()                                              */

/** cancel connection, called by timeout and admin                     */
static void m_cancel_conn( struct dsd_conn1 *adsp_conn1 ) {
   if (adsp_conn1->dsc_tc1_client.boc_connected) {  /* TCP session client connected */
     adsp_conn1->dsc_tc1_client.dsc_tcpco1_1.m_end_session();  /* close TCP session */
     adsp_conn1->iec_st_cls = ied_cls_rec_close;  /* received close    */
   }
   if (   (adsp_conn1->iec_st_ses == ied_ses_conn)  /* status server   */
       && (adsp_conn1->iec_servcotype == ied_servcotype_normal_tcp)  /* normal TCP */
       && (adsp_conn1->dsc_tc1_server.boc_connected)) {  /* TCP session server connected */
     adsp_conn1->dsc_tc1_server.dsc_tcpco1_1.m_end_session();  /* close TCP session */
     adsp_conn1->iec_st_ses = ied_ses_rec_close;  /* received close    */
   }
#ifndef B160410
   adsp_conn1->ilc_timeout = 0;             /* timeout no more set     */
#endif
   m_act_thread_1( adsp_conn1 );            /* activate thread for session */
} /* end m_cancel_conn()                                               */

/** activate connection, start work-thread                             */
static void m_act_conn( void *vpp_userfld ) {  /* activate thread      */
   BOOL       bol1;                         /* working variable        */
   int        iml_rc;                       /* return code             */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_act_conn( vpp_userfld=%p )", vpp_userfld );
#endif
#define ADSL_CONN1_G ((struct dsd_conn1 *) vpp_userfld)  /* pointer on connection */
#define ADSL_AUX_CF1 (ADSL_CONN1_G->adsc_aux_cf1_cur)  /* auxiliary control structure */
   bol1 = FALSE;
   iml_rc = ADSL_CONN1_G->dsc_critsect.m_enter();  /* enter CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_enter() critical section failed %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, iml_rc );
   }
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                   __LINE__, HL_THRID, &ADSL_CONN1_G->dsc_critsect );
#endif
   if (ADSL_CONN1_G->boc_st_act == FALSE) {  /* util-thread not active */
     ADSL_CONN1_G->boc_st_act = TRUE;       /* util-thread active now  */
     bol1 = TRUE;                           /* activate thread         */
   }
   iml_rc = ADSL_CONN1_G->dsc_critsect.m_leave();  /* leave CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_leave() critical section failed %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, iml_rc );
   }
   if (bol1) {
     m_act_thread_2( ADSL_CONN1_G );        /* activate m_proc_data()  */
   }
#undef ADSL_AUX_CF1
#undef ADSL_CONN1_G
} /* end m_act_conn()                                                  */

/** display for connection                                             */
static void m_display_conn( void *vpp_userfld, char *achp_message ) {
#define ADSL_CONN1_G ((struct dsd_conn1 *) vpp_userfld)
   m_hlnew_printf( HLOG_XYZ1, "HWSPS081I GATE=%(ux)s SNO=%08d INETA=%s %s",
                   ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                   achp_message );
#undef ADSL_CONN1_G
} /* end m_display_conn()                                              */

/**
* open the connection for listen
* parameter 1 and 2 is address of work area to return error-messages
* parameter 3 and 4 is for the routine to display the error messages
* parameter 5 is what to do when listen fails
* parameter 6 is the target structure
* parameter 7 is the source structure
* parameter 8 is the port to be used
*/
extern "C" enum ied_opli_ret m_open_listen( char *achp_work, int inp_len_work,
                                            amd_msgprog amp_msgproc, void * vpp_userfld,
                                            enum ied_lierr iep_lierr,
                                            struct dsd_gate_listen_1 *adsp_gate_listen_1,
                                            struct dsd_ineta_single_1 *adsp_ineta_s,
                                            int imp_port ) {
   int        iml1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
   enum ied_func_main_poll iel_fmp;         /* function of main poll   */
   enum ied_ret_main_poll iel_rmp;          /* return from main poll   */
   time_t     dsl_time_1;                   /* for time                */
   char       *achl1;                       /* working-variable        */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T m_open_listen() called", __LINE__ );
#endif
#ifdef XYZ1
   amp_msgproc( vpp_userfld, "test", 0 );
   return ied_oplir_failure;
#else
   memset( adsp_gate_listen_1, 0, sizeof(struct dsd_gate_listen_1) );
   adsp_gate_listen_1->dsc_soa.ss_family = adsp_ineta_s->usc_family;
   if (adsp_ineta_s->usc_family == AF_INET) {  /* IPV4                 */
     ((struct sockaddr_in *) &adsp_gate_listen_1->dsc_soa)->sin_port = htons( imp_port );
     achl1 = (char *) &((struct sockaddr_in *) &adsp_gate_listen_1->dsc_soa)->sin_addr;
     iml1 = sizeof(struct sockaddr_in);
   } else if (adsp_ineta_s->usc_family == AF_INET6) {  /* IPV6         */
     achl1 = (char *) &((struct sockaddr_in6 *) &adsp_gate_listen_1->dsc_soa)->sin6_addr;
     iml1 = sizeof(struct sockaddr_in6);
     ((struct sockaddr_in6 *) &adsp_gate_listen_1->dsc_soa)->sin6_port = htons( imp_port );
   } else {
     snprintf( achp_work, inp_len_work, "m_open_listen() passed family invalid %d - ignored",
               adsp_ineta_s->usc_family );
// to-do 02.06.12 KB error number
     amp_msgproc( vpp_userfld, achp_work, 7 );
     goto p_opli_ret_err;                   /* error return from open listen */
   }
   memcpy( achl1, adsp_ineta_s + 1, adsp_ineta_s->usc_length );
   if (dss_loconf_1.boc_listen_gw) {        /* do use listen-gateway   */
     goto p_opli_ligw_00;                   /* open listen with listen-gateway */
   }
   /* Get a socket for accepting connections.                          */
   adsp_gate_listen_1->imc_socket = socket( adsp_ineta_s->usc_family, SOCK_STREAM, 0 );
   if (adsp_gate_listen_1->imc_socket < 0) {  /* error occured         */
     snprintf( achp_work, inp_len_work, "Socket() Error %d/%d - ignored",
               adsp_gate_listen_1->imc_socket, errno );
     amp_msgproc( vpp_userfld, achp_work, 7 );
     goto p_opli_ret_err;                   /* error return from open listen */
   }
#ifdef TRY_120522_02                       /* SO_REUSEADDR            */
#ifdef TRY_120522_01                        /* SO_REUSEADDR            */
   {
     int      imh_w1;
     socklen_t imh_w2 = sizeof(int);
     iml_rc = getsockopt( adsp_gate_listen_1->imc_socket, SOL_SOCKET, SO_REUSEADDR, (void *) &imh_w1, &imh_w2 );
     m_hlnew_printf( HLOG_TRACE1, "HWSPxxxxT l%05d getsockopt() returned %d %d imh_w1=0X%08X imh_w2=0X%08X.",
                     __LINE__, iml_rc, D_TCP_ERROR, imh_w1, imh_w2 );
   }
#endif
   if (dss_loconf_1.boc_reload_conf) {      /* allow reload configuration */
     iml_rc = setsockopt( adsp_gate_listen_1->imc_socket, SOL_SOCKET, SO_REUSEADDR, (const char *) &ims_true, sizeof(int) );
     if (iml_rc != 0) {                     /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPxxxxW l%05d Error setsockopt() returned %d %d.",
                       __LINE__, iml_rc, D_TCP_ERROR );
     }
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T setsockopt( ... SOL_SOCKET , SO_REUSEADDR , ... ) returned %d.",
                     __LINE__, iml_rc );
#endif
   }
#ifdef TRY_120522_01                        /* SO_REUSEADDR            */
   {
     int      imh_w1;
     socklen_t imh_w2 = sizeof(int);
     iml_rc = getsockopt( adsp_gate_listen_1->imc_socket, SOL_SOCKET, SO_REUSEADDR, (void *) &imh_w1, &imh_w2 );
     m_hlnew_printf( HLOG_TRACE1, "HWSPxxxxT l%05d getsockopt() returned %d %d imh_w1=0X%08X imh_w2=0X%08X.",
                     __LINE__, iml_rc, D_TCP_ERROR, imh_w1, imh_w2 );
   }
#endif
#endif
#ifdef TRY_121128_01                        /* SO_REUSEADDR            */
   iml_rc = setsockopt( adsp_gate_listen_1->imc_socket, SOL_SOCKET, SO_REUSEADDR, (const char *) &ims_true, sizeof(int) );
   if (iml_rc != 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPxxxxW l%05d Error setsockopt() returned %d %d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
   }
#endif
   p_opli_bind_40:                          /* open listen bind        */
   iml_rc = bind( adsp_gate_listen_1->imc_socket,
                  (struct sockaddr *) &adsp_gate_listen_1->dsc_soa,
                  iml1 );
   if (iml_rc == 0) {                       /* no error occured        */
     return ied_oplir_ok;                   /* return success          */
   }
   achl1 = "abend";                         /* set default value message text */
   switch (iep_lierr) {                     /* check what to do after listen error */
     case ied_le_ignore:                    /* ignore listen error     */
       achl1 = "ignore";                    /* set message text        */
       break;
     case ied_le_wait:                      /* wait after listen error */
       achl1 = "wait";                      /* set message text        */
   }
   snprintf( achp_work, inp_len_work, "bind() port=%d Error %d/%d - action : %s.",
             imp_port, iml_rc, errno, achl1 );
   amp_msgproc( vpp_userfld, achp_work, 8 );
   if (iep_lierr == ied_le_wait) {          /* wait after listen error */
     time( &dsl_time_1 );                   /* get current time        */
     iel_rmp = m_main_poll( ied_fmp_opli_sleep, dsl_time_1 + D_WAIT_LIERR );
     if (iel_rmp == ied_rmp_timeout) {      /* timer elapsed           */
       goto p_opli_bind_40;                 /* open listen bind        */
     }
     if (   (iel_rmp == ied_rmp_sig_end)    /* message signal end      */
         || (iel_rmp == ied_rmp_sig_reload)) {  /* message signal reload configuration */
       close( adsp_gate_listen_1->imc_socket );  /* close socket again */
       return ied_oplir_abend;              /* abend / exit of program */
     }
   }
   close( adsp_gate_listen_1->imc_socket );  /* close socket again     */
   goto p_opli_ret_err;                     /* error return from open listen */

   p_opli_ligw_00:                          /* open listen with listen-gateway */
   iel_fmp = ied_fmp_opli_ligw_wait;        /* open listen listen gateway wait */
   if (iep_lierr != ied_le_wait) {          /* not wait after listen error */
     if (dss_ligw_g.boc_connected == FALSE) {  /* not connected to Listen Gateway */
       snprintf( achp_work, inp_len_work, "m_open_listen() port=%d Listen-Gateway not accessed",
                 imp_port );
// to-do 02.06.12 KB error number
       amp_msgproc( vpp_userfld, achp_work, 9 );
       goto p_opli_ret_err;                 /* error return from open listen */
     }
     iel_fmp = ied_fmp_opli_ligw_ret;       /* open listen listen gateway return */
   }
   dss_ligw_g.adsc_gate_listen_1_next = adsp_gate_listen_1;  /* set structure to get port for */
   dss_ligw_g.boc_listen_start = TRUE;      /* start listen at program start */
   iel_rmp = m_main_poll( iel_fmp, 0 );
   switch (iel_rmp) {                       /* check how returned      */
     case ied_rmp_sig_end:                  /* message signal end      */
     case ied_rmp_sig_reload:               /* message signal reload configuration */
       return ied_oplir_abend;              /* abend / exit of program */
     case ied_rmp_sig_check_shu:            /* message signal check shutdown */
       goto p_opli_ligw_00;                 /* open listen with listen-gateway */
     case ied_rmp_ligw_success:             /* listen gateway socket passed */
       return ied_oplir_ok;                 /* return success          */
     case ied_rmp_ligw_failed:              /* socket and bind failed  */
     case ied_rmp_ligw_closed:              /* listen gateway is closed */
       if (iep_lierr != ied_le_wait) break;  /* not wait after listen error */
       time( &dsl_time_1 );                 /* get current time        */
       iel_rmp = m_main_poll( ied_fmp_opli_sleep, dsl_time_1 + D_WAIT_LIERR );
       if (iel_rmp != ied_rmp_timeout) break;  /* not timer elapsed    */
       goto p_opli_ligw_00;                 /* open listen with listen-gateway */

   }
#endif

   p_opli_ret_err:                          /* error return from open listen */
   if (iep_lierr != ied_le_abend) return ied_oplir_failure;  /* not abend after listen error */
   return ied_oplir_abend;                  /* abend / exit of program */
} /* end m_open_listen()                                               */

/**
* start listen of one connection
* returns the number of listen started
*/
extern "C" int m_start_listen( struct dsd_gate_1 *adsp_gate_1 ) {
   int        iml_count;                    /* count listen started    */
   int        iml_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
#ifdef XYZ1
   char       *achl1;                       /* working variable        */
#endif
   struct dsd_gate_listen_1 *adsl_gate_listen_1_w1;  /* listen part of gateway */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_start_listen() called",
                   __LINE__ );
#endif
   iml_count = 0;                           /* clear count listen started */
   adsl_gate_listen_1_w1 = adsp_gate_1->adsc_gate_listen_1_ch;  /* chain of listen part of gateway */
   while (adsl_gate_listen_1_w1) {
     while (adsl_gate_listen_1_w1->boc_active == FALSE) {  /* listen not active */
       if (adsl_gate_listen_1_w1->imc_socket < 0) {  /* prepare socket first */
         adsl_gate_listen_1_w1->imc_socket = socket( adsl_gate_listen_1_w1->dsc_soa.ss_family, SOCK_STREAM, 0 );
         if (adsl_gate_listen_1_w1->imc_socket < 0) {  /* error occured */
#ifdef XYZ1
           iml1 = adsl_gate_listen_1_w1->imc_socket;
           if (cl_tcp_r::hws2mod != NULL) {       /* functions loaded        */
             iml1 = cl_tcp_r::afunc_wsaglerr();   /* get error code          */
           }
           _snprintf( achp_work, inp_len_work, "Socket() Error %d/%d - ignored",
                      adsl_gate_listen_1_w1->imc_socket, iml1 );
           amp_msgproc( vpp_userfld, achp_work, 7 );
           return FALSE;                          /* return error            */
#endif
           m_hlnew_printf( HLOG_WARN1, "HWSPxxxxW l%05d Error socket() gate \"%(ux)s\" returned %d %d.",
                           __LINE__, adsp_gate_1 + 1, adsl_gate_listen_1_w1->imc_socket, D_TCP_ERROR );
           break;
         }
#ifdef TRY_120522_01                        /* SO_REUSEADDR            */
         {
           int      imh_w1;
           socklen_t imh_w2 = sizeof(int);
           iml_rc = getsockopt( adsl_gate_listen_1_w1->imc_socket, SOL_SOCKET, SO_REUSEADDR, (void *) &imh_w1, &imh_w2 );
           m_hlnew_printf( HLOG_TRACE1, "HWSPxxxxT l%05d getsockopt() gate \"%(ux)s\" returned %d %d imh_w1=0X%08X imh_w2=0X%08X.",
                           __LINE__, adsp_gate_1 + 1, iml_rc, D_TCP_ERROR, imh_w1, imh_w2 );
         }
#endif
#ifdef TRY_121128_01                        /* SO_REUSEADDR            */
         if (dss_loconf_1.boc_reload_conf) {  /* allow reload configuration */
           iml_rc = setsockopt( adsl_gate_listen_1_w1->imc_socket, SOL_SOCKET, SO_REUSEADDR, (const char *) &ims_true, sizeof(int) );
           if (iml_rc != 0) {               /* error occured           */
             m_hlnew_printf( HLOG_WARN1, "HWSPxxxxW l%05d Error setsockopt() gate \"%(ux)s\" returned %d %d.",
                             __LINE__, adsp_gate_1 + 1, iml_rc, D_TCP_ERROR );
           }
#ifdef TRACEHL1
           m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T setsockopt( ... SOL_SOCKET , SO_REUSEADDR , ... ) returned %d.",
                           __LINE__, iml_rc );
#endif
         }
#else /* TRY_121128_01                         SO_REUSEADDR            */
         iml_rc = setsockopt( adsl_gate_listen_1_w1->imc_socket, SOL_SOCKET, SO_REUSEADDR, (const char *) &ims_true, sizeof(int) );
         if (iml_rc != 0) {                 /* error occured           */
           m_hlnew_printf( HLOG_WARN1, "HWSPxxxxW l%05d Error setsockopt() gate \"%(ux)s\" returned %d %d.",
                           __LINE__, adsp_gate_1 + 1, iml_rc, D_TCP_ERROR );
         }
#endif
#ifdef TRY_120522_01                        /* SO_REUSEADDR            */
         {
           int      imh_w1;
           socklen_t imh_w2 = sizeof(int);
           iml_rc = getsockopt( adsl_gate_listen_1_w1->imc_socket, SOL_SOCKET, SO_REUSEADDR, (void *) &imh_w1, &imh_w2 );
           m_hlnew_printf( HLOG_TRACE1, "HWSPxxxxT l%05d getsockopt() gate \"%(ux)s\" returned %d %d imh_w1=0X%08X imh_w2=0X%08X.",
                           __LINE__, adsp_gate_1 + 1, iml_rc, D_TCP_ERROR, imh_w1, imh_w2 );
         }
#endif
         iml1 = sizeof(struct sockaddr_in);
         if (adsl_gate_listen_1_w1->dsc_soa.ss_family == AF_INET6) {
           iml1 = sizeof(struct sockaddr_in6);
         }
         iml_rc = bind( adsl_gate_listen_1_w1->imc_socket,
                        (struct sockaddr *) &adsl_gate_listen_1_w1->dsc_soa,
                        iml1 );
         if (iml_rc != 0) {                 /* error occured           */
#ifdef XYZ1
           iml1 = iml_rc;
           if (cl_tcp_r::hws2mod != NULL) {       /* functions loaded        */
             iml1 = cl_tcp_r::afunc_wsaglerr();   /* get error code          */
           }
           _snprintf( achp_work, inp_len_work, "Bind() port=%d Error %d/%d - ignored",
                      imp_port, iml_rc, iml1 );
           amp_msgproc( vpp_userfld, achp_work, 8 );
           IP_closesocket( adsl_gate_listen_1_w1->imc_socket );
           adsl_gate_listen_1_w1->imc_socket = -1;   /* mark as invalid         */
           return FALSE;                          /* return error            */
#endif
           m_hlnew_printf( HLOG_WARN1, "HWSPxxxxW l%05d Error bind() gate \"%(ux)s\" returned %d %d.",
                           __LINE__, adsp_gate_1 + 1, iml_rc, D_TCP_ERROR );
           adsl_gate_listen_1_w1->imc_socket = -1;  /* mark as invalid */
           break;
         }
       }

#ifdef TRY_120522_01                        /* SO_REUSEADDR            */
       {
         int      imh_w1;
         socklen_t imh_w2 = sizeof(int);
         iml_rc = getsockopt( adsl_gate_listen_1_w1->imc_socket, SOL_SOCKET, SO_REUSEADDR, (void *) &imh_w1, &imh_w2 );
         m_hlnew_printf( HLOG_TRACE1, "HWSPxxxxT l%05d getsockopt() gate \"%(ux)s\" returned %d %d imh_w1=0X%08X imh_w2=0X%08X.",
                         __LINE__, adsp_gate_1 + 1, iml_rc, D_TCP_ERROR, imh_w1, imh_w2 );
       }
#endif
       iml_rc = listen( adsl_gate_listen_1_w1->imc_socket, adsp_gate_1->imc_backlog );
       if (iml_rc) {                        /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "HWSPxxxxW l%05d Error listen() gate \"%(ux)s\" returned %d %d.",
                         __LINE__, adsp_gate_1 + 1, iml_rc, D_TCP_ERROR );
         break;
       }
#ifdef TRY_120513_02                        /* SO_REUSEADDR            */
       if (dss_loconf_1.boc_reload_conf) {  /* allow reload configuration */
         iml_rc = setsockopt( adsl_gate_listen_1_w1->imc_socket, SOL_SOCKET, SO_REUSEADDR, (const char *) &ims_true, sizeof(int) );
         if (iml_rc != 0) {                 /* error occured           */
           m_hlnew_printf( HLOG_WARN1, "HWSPxxxxW l%05d Error setsockopt() gate \"%(ux)s\" returned %d %d.",
                           __LINE__, adsp_gate_1 + 1, iml_rc, D_TCP_ERROR );
         }
#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T setsockopt( ... SOL_SOCKET , SO_REUSEADDR , ... ) returned %d.",
                         __LINE__, iml_rc );
#endif
       }
#endif
#ifdef TRY_120522_01                        /* SO_REUSEADDR            */
       {
         int      imh_w1;
         socklen_t imh_w2 = sizeof(int);
         iml_rc = getsockopt( adsl_gate_listen_1_w1->imc_socket, SOL_SOCKET, SO_REUSEADDR, (void *) &imh_w1, &imh_w2 );
         m_hlnew_printf( HLOG_TRACE1, "HWSPxxxxT l%05d getsockopt() gate \"%(ux)s\" returned %d %d imh_w1=0X%08X imh_w2=0X%08X.",
                         __LINE__, adsp_gate_1 + 1, iml_rc, D_TCP_ERROR, imh_w1, imh_w2 );
       }
#endif
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_start_listen() &adsl_gate_listen_1_w1->dsc_acc_listen=%p adsl_gate_listen_1_w1->imc_socket=%d.",
                       __LINE__, &adsl_gate_listen_1_w1->dsc_acc_listen, adsl_gate_listen_1_w1->imc_socket );
#endif
       iml_rc = adsl_gate_listen_1_w1->dsc_acc_listen.mc_startlisten_fix( adsl_gate_listen_1_w1->imc_socket,
                                                                          &dss_acccb,
                                                                          adsl_gate_listen_1_w1 );
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_start_listen() mc_startlisten_fix() returned %d.",
                       __LINE__, iml_rc );
#endif
// to-do 14.09.11 KB check return code
       adsl_gate_listen_1_w1->boc_active = TRUE;  /* listen is active now */
       iml_count++;                         /* increment count listen started */
       break;
     }
     adsl_gate_listen_1_w1 = adsl_gate_listen_1_w1->adsc_next;  /* get next in chain */
   }
   return iml_count;                        /* return count listen started */
} /* end m_start_listen()                                              */

/**
* stop listen of one connection
* returns the number of listen stopped
*/
extern "C" int m_stop_listen( struct dsd_gate_1 *adsg_gate_1 ) {
   int        iml_count;                    /* count listen stopped    */
   int        iml_rc;                       /* return code             */
   struct dsd_gate_listen_1 *adsl_gate_listen_1_w1;  /* listen part of gateway */

   iml_count = 0;                           /* clear count listen stopped */
   adsl_gate_listen_1_w1 = adsg_gate_1->adsc_gate_listen_1_ch;  /* chain of listen part of gateway */
   while (adsl_gate_listen_1_w1) {
     if (adsl_gate_listen_1_w1->boc_active) {  /* listen is active     */
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_stop_listen() &adsl_gate_listen_1_w1->dsc_acc_listen=%p adsl_gate_listen_1_w1->imc_socket=%d.",
                       __LINE__, &adsl_gate_listen_1_w1->dsc_acc_listen, adsl_gate_listen_1_w1->imc_socket );
#endif
       iml_rc = adsl_gate_listen_1_w1->dsc_acc_listen.mc_stoplistener_fix();
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T mc_stoplistener_fix() socket=%d called",
                           __LINE__, adsl_gate_listen_1_w1->imc_socket );
#endif
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_stop_listen() mc_stoplistener_fix() returned %d.",
                       __LINE__, iml_rc );
#endif
       adsl_gate_listen_1_w1->imc_socket = -1;  /* socket is now invalid */
       adsl_gate_listen_1_w1->boc_active = FALSE;  /* listen is not active */
       iml_count++;                         /* increment count listen stopped */
     }
     adsl_gate_listen_1_w1 = adsl_gate_listen_1_w1->adsc_next;  /* get next in chain */
   }
// dsg_sys_state_1.boc_listen_active = FALSE;  /* listen is currently not active */
   return iml_count;                        /* return count listen stopped */
} /* end m_stop_listen()                                               */

/**
* start listen of all connections
* returns the number of listen started
*/
extern "C" int m_start_all_listen( BOOL bop_lbal ) {
   int        iml_rc;                       /* return code             */
   int        iml_count;                    /* count listen started    */
   struct dsd_gate_1 *adsl_gate_1_w1;       /* for start listen        */
   struct dsd_gate_listen_1 *adsl_gate_listen_1_w1;  /* listen part of gateway */

#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_start_all_listen() dss_loconf_1.boc_listen_gw=%d dss_ligw_g.adsc_gate_1_create_socket=%p dss_ligw_g.adsc_gate_listen_1_cur=%p dss_ligw_g.adsc_gate_listen_1_next=%p.",
                   __LINE__, dss_loconf_1.boc_listen_gw, dss_ligw_g.adsc_gate_1_create_socket, dss_ligw_g.adsc_gate_listen_1_cur, dss_ligw_g.adsc_gate_listen_1_next );
#endif
   adsl_gate_1_w1 = adsg_loconf_1_inuse->adsc_gate_anchor;  /* get anchor gate */
   if (dss_loconf_1.boc_listen_gw) {        /* do use listen gateway   */
     dss_ligw_g.boc_stop_listen_lbal = FALSE;  /* stop listen load-balancing in progress */
     dss_ligw_g.boc_listen_lbal = bop_lbal;  /* start listen for load-balancing */
#ifdef B121107
     if (dss_ligw_g.adsc_gate_listen_1_cur != NULL) return 0;  /* listen part of gateway currently processed */
     if (dss_ligw_g.adsc_gate_1_create_socket != NULL) return 0;  /* starting still active */
#endif
     if (dss_ligw_g.adsc_gate_listen_1_cur != NULL) return -1;  /* listen part of gateway currently processed */
     if (dss_ligw_g.adsc_gate_1_create_socket != NULL) return -1;  /* starting still active */
     dss_ligw_g.adsc_gate_1_create_socket = adsl_gate_1_w1;  /* current gate to start */
     dss_ligw_g.adsc_gate_listen_1_next = NULL;  /* listen part of gateway next to process */
   }
   iml_count = 0;                           /* clear count listen started */
   while (adsl_gate_1_w1) {                 /* loop over all gates     */
     if (   (adsl_gate_1_w1->boc_not_close_lbal == FALSE)  /* do not close listen by load-balancing */
         || (bop_lbal == FALSE)) {
       if (dss_loconf_1.boc_listen_gw) {    /* do use listen gateway   */
         adsl_gate_listen_1_w1 = adsl_gate_1_w1->adsc_gate_listen_1_ch;  /* chain of listen part of gateway */
         while (adsl_gate_listen_1_w1) {
           if (adsl_gate_listen_1_w1->boc_active == FALSE) {  /* listen not active */
             iml_count++;                   /* increment count listen started */
           }
           adsl_gate_listen_1_w1 = adsl_gate_listen_1_w1->adsc_next;  /* get next in chain */
         }
       } else {                             /* normal listen           */
         iml_count += m_start_listen( adsl_gate_1_w1 );  /* start listen */
       }
     }
     adsl_gate_1_w1 = adsl_gate_1_w1->adsc_next;
   }
#ifdef B121029
   if (dss_loconf_1.boc_listen_gw == FALSE) {  /* do not use listen gateway */
     dsg_sys_state_1.boc_listen_active = TRUE;  /* listen is currently active */
   } else {                                 /* notify main thread      */
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
     m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_start_all_listen() iml_count=%d dss_ligw_g.adsc_gate_1_create_socket=%p.",
                     __LINE__, iml_count, dss_ligw_g.adsc_gate_1_create_socket );
#endif
     if (iml_count > 0) {                   /* port to be started      */
       iml_rc = write( imrs_m_fd_pipe[1], vprs_message_work, sizeof(vprs_message_work) );
       if (iml_rc != sizeof(vprs_message_work)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW nbipgw20 l%05d write pipe work error %d %d.",
                         __LINE__, iml_rc, errno );
       }
     }
   }
#else
   if (dss_loconf_1.boc_listen_gw) {        /* do use listen gateway   */
     /* notify main thread                                             */
#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
     m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_start_all_listen() iml_count=%d dss_ligw_g.adsc_gate_1_create_socket=%p.",
                     __LINE__, iml_count, dss_ligw_g.adsc_gate_1_create_socket );
#endif
     if (iml_count > 0) {                   /* port to be started      */
       iml_rc = write( imrs_m_fd_pipe[1], vprs_message_work, sizeof(vprs_message_work) );
       if (iml_rc != sizeof(vprs_message_work)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW nbipgw20 l%05d write pipe work error %d %d.",
                         __LINE__, iml_rc, errno );
       }
     }
   } else {
     dsg_sys_state_1.boc_listen_active = TRUE;  /* listen is currently active */
   }
#endif
   return iml_count;                        /* return count listen started */
} /* end m_start_all_listen()                                          */

/**
* stop listen of all connections
* returns the number of listen stopped
*/
extern "C" int m_stop_all_listen( BOOL bop_lbal ) {
   int        iml_count;                    /* count listen stopped    */
   struct dsd_gate_1 *adsl_gate_1_w1;       /* for stop listen         */

   dss_ligw_g.boc_stop_listen_lbal = TRUE;  /* stop listen load-balancing in progress */
   dss_ligw_g.adsc_gate_1_create_socket = NULL;  /* clear current gate to start */
   iml_count = 0;                           /* clear count listen stopped */
   adsl_gate_1_w1 = adsg_loconf_1_inuse->adsc_gate_anchor;  /* get anchor gate */
   while (adsl_gate_1_w1) {                 /* loop over all gates     */
     if (   (adsl_gate_1_w1->boc_not_close_lbal == FALSE)  /* do not close listen by load-balancing */
         || (bop_lbal == FALSE)) {
       iml_count += m_stop_listen( adsl_gate_1_w1 );  /* stop listen   */
     }
     adsl_gate_1_w1 = adsl_gate_1_w1->adsc_next;
   }
   dsg_sys_state_1.boc_listen_active = FALSE;  /* listen is currently not active */
   return iml_count;                        /* return count listen stopped */
} /* end m_stop_all_listen()                                           */

/** CMA module starts synchronization passive                          */
extern "C" void m_notify_cma_sync_passive_start( void ) {
   dss_main_critsect.m_enter();             /* enter CriticalSection   */
   ims_count_cma_sync++;                    /* count currently active CMA synchronize */
   dss_main_critsect.m_leave();             /* leave CriticalSection   */
} /* end m_notify_cma_sync_passive_start()                             */

/** CMA module stopps synchronization passive                          */
extern "C" void m_notify_cma_sync_passive_stop( void ) {
   int        iml_rc;                       /* return code             */

   dss_main_critsect.m_enter();             /* enter CriticalSection   */
   ims_count_cma_sync--;                    /* count currently active CMA synchronize */
   dss_main_critsect.m_leave();             /* leave CriticalSection   */
   if (dsg_sys_state_1.boc_listen_ended == FALSE) return;  /* listen has already ended */
   if (ims_count_cma_sync != 0) return;     /* count currently active CMA synchronize */
   iml_rc = write( imrs_m_fd_pipe[1], vprs_message_shutdown, sizeof(vprs_message_shutdown) );
   if (iml_rc == sizeof(vprs_message_shutdown)) return;
   m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW nbipgw20 l%05d write pipe shutdown error %d %d.",
                   __LINE__, iml_rc, errno );
} /* end m_notify_cma_sync_passive_stop()                              */

/** CMA module starts synchronization active                           */
extern "C" void m_notify_cma_sync_active_start( void ) {
   dss_main_critsect.m_enter();             /* enter CriticalSection   */
   ims_count_cma_sync++;                    /* count currently active CMA synchronize */
   dss_main_critsect.m_leave();             /* leave CriticalSection   */
} /* end m_notify_cma_sync_active_start()                              */

/** CMA module stopps synchronization active                           */
extern "C" void m_notify_cma_sync_active_stop( void ) {
   int        iml_rc;                       /* return code             */

   dss_main_critsect.m_enter();             /* enter CriticalSection   */
   ims_count_cma_sync--;                    /* count currently active CMA synchronize */
   dss_main_critsect.m_leave();             /* leave CriticalSection   */
   if (dsg_sys_state_1.boc_listen_ended == FALSE) return;  /* listen has already ended */
   if (ims_count_cma_sync != 0) return;     /* count currently active CMA synchronize */
   iml_rc = write( imrs_m_fd_pipe[1], vprs_message_shutdown, sizeof(vprs_message_shutdown) );
   if (iml_rc == sizeof(vprs_message_shutdown)) return;
   m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW nbipgw20 l%05d write pipe shutdown error %d %d.",
                   __LINE__, iml_rc, errno );
} /* end m_notify_cma_sync_active_stop()                               */

#ifndef PROC_ALLOC_02
#ifndef PROC_ALLOC_03
#ifndef TRACEHL_STOR_USAGE
/** allocate buffer, a chunk of memory                                 */
extern PTYPE void * m_proc_alloc( void ) {
   void     *alrecbuf;                      /* receive buffer          */

#ifdef TRACEHL_P_COUNT
   dss_alloc_critsect.m_enter();            /* critical section        */
   ins_count_buf_in_use++;
   if (ins_count_buf_in_use > ins_count_buf_max) ins_count_buf_max = ins_count_buf_in_use;
#ifdef D_STOR_ONE_TIME
   ins_count_memory++;
#endif
   dss_alloc_critsect.m_leave();            /* critical section        */
#ifdef D_STOR_ONE_TIME
   alrecbuf = malloc( LEN_TCP_RECV );
#ifdef TRACEHL_P_DISP
   m_hlnew_printf( HLOG_XYZ1, "+S+ proc_alloc new alrecbuf=%p", alrecbuf );
#endif
#ifdef DEBUG_110315_01
   if (bos_debug_110315_01) {
     m_hlnew_printf( HLOG_XYZ1, "+S+ proc_alloc new alrecbuf=%p / DEBUG_110315_01", alrecbuf );
   }
#endif
#ifdef D_STOR_PATTERN
   memset( alrecbuf, 0X33, LEN_TCP_RECV );
#endif
   return alrecbuf;
#endif
#endif
   pp_alloc_20:                             /* search buffer           */
#ifndef TRACEHL_P_COUNT
#ifndef D_STOR_PATTERN
#ifdef B170329
   if (asrecbuf == NULL) return malloc( LEN_TCP_RECV );
#endif
#ifndef B170329
   if (asrecbuf == NULL) {
     alrecbuf = malloc( LEN_TCP_RECV );
     if (alrecbuf) return alrecbuf;
     m_hlnew_printf( HLOG_EMER1, "HWSPM027E out of memory - l%05d m_proc_alloc()",
                     __LINE__ );
     return NULL;
   }
#endif
#else
   if (asrecbuf == NULL) {
     alrecbuf = malloc( LEN_TCP_RECV );
     memset( alrecbuf, 0X33, LEN_TCP_RECV );
     return alrecbuf;
   }
#endif
#else
   if (asrecbuf == NULL) {
     ins_count_memory++;
#ifndef TRACEHL3
     return malloc( LEN_TCP_RECV );
#else
     alrecbuf = malloc( LEN_TCP_RECV );
     m_hlnew_printf( HLOG_XYZ1, "+S+ proc_alloc new alrecbuf=%p", alrecbuf );
     return alrecbuf;
#endif
   }
#endif
   dss_alloc_critsect.m_enter();            /* critical section        */
   alrecbuf = asrecbuf;                     /* get first in chain      */
   if (alrecbuf) {
     asrecbuf = *((void **) alrecbuf);      /* set next in chain       */
   }
   dss_alloc_critsect.m_leave();            /* critical section        */
#ifndef TRACEHL3
   if (alrecbuf) return alrecbuf;
#else
   if (alrecbuf) {
     m_hlnew_printf( HLOG_XYZ1, "proc_alloc old alrecbuf=%p", alrecbuf );
     return alrecbuf;
   }
#endif
   goto pp_alloc_20;                        /* repeat                  */
}

/** release buffer or put it to chain of buffers to be reused          */
extern "C" void m_proc_free( void *ap1 ) {

#ifdef DEBUG_100809
   if (ap1 == as_debug_100809_01) {
     m_hlnew_printf( HLOG_XYZ1, "+S+ proc_free ap1=%p / as_debug_100809_01", ap1 );
   }
#endif
#ifdef DEBUG_110315_01
   if (bos_debug_110315_01) {
     m_hlnew_printf( HLOG_XYZ1, "+S+ proc_free ap1=%p / DEBUG_110315_01", ap1 );
     if (ap1 == as_debug_110315_01) {
       m_hlnew_printf( HLOG_XYZ1, "?S? proc_free debug-point reached" );
     }
   }
#endif
#ifdef D_STOR_ONE_TIME
#ifdef TRACEHL_P_DISP
   m_hlnew_printf( HLOG_XYZ1, "+S+ proc_free ap1=%p", ap1 );
#endif
#ifdef TRACEHL_P_COUNT
   dss_alloc_critsect.m_enter();            /* critical section        */
   ins_count_buf_in_use--;
   dss_alloc_critsect.m_leave();            /* critical section        */
#endif
   free( ap1 );
   return;
#endif
#ifdef TRACEHL3
   m_hlnew_printf( HLOG_XYZ1, "+S+ proc_free ap1=%p", ap1 );
#endif
   if (adsg_loconf_1_inuse->boc_clear_used_mem) {  /* clear used memory */
     memset( ap1, 0, LEN_TCP_RECV );        /* clear the memory, is more secure */
   }
#ifdef TRACEHL_P_050118
   free( ap1 );
#ifdef TRACEHL_P_COUNT
   dss_alloc_critsect.m_enter();            /* critical section        */
   ins_count_buf_in_use--;
   dss_alloc_critsect.m_leave();            /* critical section        */
#endif
   return;
#endif
   dss_alloc_critsect.m_enter();            /* critical section        */
#ifdef TRACEHL_P_COUNT
   ins_count_buf_in_use--;
#endif
   if (ims_count_free == 0) ims_count_free = 10;
   ims_count_free--;
   if (ims_count_free) {                     /* keep memory in stock    */
     *((void **) ap1) = asrecbuf;           /* get old chain           */
     asrecbuf = ap1;                        /* set new chain           */
     ap1 = NULL;
   }
   dss_alloc_critsect.m_leave();            /* critical section        */
   if (ap1 == NULL) return;                 /* do not free memory      */
   free( ap1 );                             /* free memory             */
} /* end m_proc_free()                                                 */
#endif
#ifdef TRACEHL_STOR_USAGE
extern PTYPE void * m_proc_alloc( void ) {
   void     *alrecbuf;                      /* receive buffer          */
   struct dsd_tr_stor_usage_01 *adsl_tr_stor_usage_01_w1;

   adsl_tr_stor_usage_01_w1 = (struct dsd_tr_stor_usage_01 *) malloc( sizeof(struct dsd_tr_stor_usage_01) + LEN_TCP_RECV );
   memset( adsl_tr_stor_usage_01_w1, 0, sizeof(struct dsd_tr_stor_usage_01) );
   adsl_tr_stor_usage_01_w1->ac_stack = m_get_stack();
   dss_alloc_critsect.m_enter();            /* critical section        */
#ifdef TRACEHL_P_COUNT
   ins_count_buf_in_use++;
   if (ins_count_buf_in_use > ins_count_buf_max) ins_count_buf_max = ins_count_buf_in_use;
#ifdef D_STOR_ONE_TIME
   ins_count_memory++;
#endif
#endif
   adsl_tr_stor_usage_01_w1->adsc_next = adss_tr_stor_usage_01_anchor;
   adss_tr_stor_usage_01_anchor = adsl_tr_stor_usage_01_w1;
   dss_alloc_critsect.m_leave();            /* critical section        */
   return adsl_tr_stor_usage_01_w1 + 1;
} /* end m_proc_alloc()                                                */

extern "C" void m_proc_free( void *ap1 ) {
   struct dsd_tr_stor_usage_01 *adsl_tr_stor_usage_01_w1;
   struct dsd_tr_stor_usage_01 *adsl_tr_stor_usage_01_w2;

   adsl_tr_stor_usage_01_w1 = (struct dsd_tr_stor_usage_01 *) ((char *) ap1 - sizeof(struct dsd_tr_stor_usage_01));

   dss_alloc_critsect.m_enter();            /* critical section        */
#ifdef D_STOR_ONE_TIME
#ifdef TRACEHL_P_COUNT
   ins_count_buf_in_use--;
#endif
#endif
   if (adsl_tr_stor_usage_01_w1 == adss_tr_stor_usage_01_anchor) {
     adss_tr_stor_usage_01_anchor = adsl_tr_stor_usage_01_w1->adsc_next;
     adsl_tr_stor_usage_01_w2 = adsl_tr_stor_usage_01_w1;  /* only for error message */
   } else {
     adsl_tr_stor_usage_01_w2 = adss_tr_stor_usage_01_anchor;
     while (   (adsl_tr_stor_usage_01_w2)
            && (adsl_tr_stor_usage_01_w2->adsc_next != adsl_tr_stor_usage_01_w1)) {
       adsl_tr_stor_usage_01_w2 = adsl_tr_stor_usage_01_w2->adsc_next;
     }
     if (adsl_tr_stor_usage_01_w2) {
       adsl_tr_stor_usage_01_w2->adsc_next = adsl_tr_stor_usage_01_w1->adsc_next;
     }
   }
   dss_alloc_critsect.m_leave();            /* critical section        */
   free( adsl_tr_stor_usage_01_w1 );
} /* end m_proc_free()                                                 */

static void m_proc_mark_1( void *ap1, char *achp_pos ) {
   int        iml1;                         /* working variable        */
   struct dsd_tr_stor_usage_01 *adsl_tr_stor_usage_01_w1;

   adsl_tr_stor_usage_01_w1 = (struct dsd_tr_stor_usage_01 *) ((char *) ap1 - sizeof(struct dsd_tr_stor_usage_01));
   iml1 = strlen( achp_pos );
   if (iml1 >= sizeof(adsl_tr_stor_usage_01_w1->chrc_pos)) {
     iml1 = sizeof(adsl_tr_stor_usage_01_w1->chrc_pos) - 1;
   }
   memcpy( adsl_tr_stor_usage_01_w1->chrc_pos, achp_pos, iml1 );
   *(adsl_tr_stor_usage_01_w1->chrc_pos + iml1) = 0;
} /* end m_proc_mark_1()                                               */

static void m_proc_trac_1( void *ap1, char *achp_trac ) {
   int        iml1, iml2;                   /* working variables       */
   struct dsd_tr_stor_usage_01 *adsl_tr_stor_usage_01_w1;
   struct dsd_tr_stor_usage_01 *adsl_tr_stor_usage_01_w2;

// return;
#define LEN_TRAC_ENTRY (sizeof(adsl_tr_stor_usage_01_w1->chrc_trac) / D_NO_TSU_NO)
   adsl_tr_stor_usage_01_w1 = (struct dsd_tr_stor_usage_01 *) ((char *) ap1 - sizeof(struct dsd_tr_stor_usage_01));
   iml1 = strlen( achp_trac );
   if (iml1 >= LEN_TRAC_ENTRY) {
     iml1 = LEN_TRAC_ENTRY - 1;
   }
   dss_alloc_critsect.m_enter();            /* critical section        */
   iml2 = adsl_tr_stor_usage_01_w1->imc_ind_trac;
   memcpy( &adsl_tr_stor_usage_01_w1->chrc_trac[ iml2 * LEN_TRAC_ENTRY ],
           achp_trac,
           iml1 );
   *(&adsl_tr_stor_usage_01_w1->chrc_trac[ iml2 * LEN_TRAC_ENTRY ] + iml1) = 0;
   iml2++;
   if (iml2 >= D_NO_TSU_NO) {
     iml2 = 0;
   }
   adsl_tr_stor_usage_01_w1->imc_ind_trac = iml2;
   /* check if still in chain of living blocks                         */
   adsl_tr_stor_usage_01_w2 = adss_tr_stor_usage_01_anchor;
   while (adsl_tr_stor_usage_01_w2) {
     if (adsl_tr_stor_usage_01_w2 == adsl_tr_stor_usage_01_w1) break;
     adsl_tr_stor_usage_01_w2 = adsl_tr_stor_usage_01_w2->adsc_next;
   }
   dss_alloc_critsect.m_leave();            /* critical section        */
   if (adsl_tr_stor_usage_01_w2) return;
   memcpy( &adsl_tr_stor_usage_01_w1->chrc_trac[ iml2 * LEN_TRAC_ENTRY ],
           "not-acquired",
           13 );
#undef LEN_TRAC_ENTRY
   iml2++;
   if (iml2 >= D_NO_TSU_NO) {
     iml2 = 0;
   }
   adsl_tr_stor_usage_01_w1->imc_ind_trac = iml2;
} /* end m_proc_trac_1()                                               */
#endif
#endif
#endif
#ifdef PROC_ALLOC_02
/** allocate buffer, a chunk of memory                                 */
extern "C" void * m_proc_alloc( void ) {
   void     *alrecbuf;                      /* receive buffer          */

   dss_alloc_critsect.m_enter();            /* critical section        */

   if (asrecbuf) {                          /* chain not empty         */
     alrecbuf = asrecbuf;                   /* get first in chain      */
     asrecbuf = *((void **) alrecbuf);      /* set next in chain       */
     dss_alloc_critsect.m_leave();          /* critical section        */
     return alrecbuf;
   }

   if (ims_proc_alloc_count > 0) {          /* count free buffers in this memory area */
     ims_proc_alloc_count--;                /* decrement free buffers in this memory area */
     alrecbuf = achs_proc_alloc_next;       /* next address to use     */
     achs_proc_alloc_next += LEN_TCP_RECV;  /* next address to use     */
     dss_alloc_critsect.m_leave();          /* critical section        */
     return alrecbuf;
   }

   alrecbuf = mmap( NULL, PROC_ALLOC_02, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
   if (alrecbuf == MAP_FAILED) {            /* memory not available    */
     m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-E m_proc_alloc() mmap() MAP_FAILED errno %d.",
                     __LINE__, errno );
     dss_alloc_critsect.m_leave();          /* critical section        */
     return NULL;
   }

   achs_proc_alloc_next = ((char *) alrecbuf) + LEN_TCP_RECV;  /* next address to use */
   ims_proc_alloc_count = PROC_ALLOC_02 / LEN_TCP_RECV - 1;  /* count free buffers in this memory area */
   ils_proc_alloc_occupied += PROC_ALLOC_02;  /* storage occupied by proc-alloc */
   dss_alloc_critsect.m_leave();            /* critical section        */
   return alrecbuf;
} /* end m_proc_alloc()                                                */

/** release buffer and put it to chain of buffers to be reused         */
extern "C" void m_proc_free( void *ap1 ) {
   dss_alloc_critsect.m_enter();            /* critical section        */
   *((void **) ap1) = asrecbuf;             /* get old chain           */
   asrecbuf = ap1;                          /* set new chain           */
   dss_alloc_critsect.m_leave();            /* critical section        */
} /* end m_proc_free()                                                 */
#endif
#ifdef PROC_ALLOC_03
/** allocate buffer, a chunk of memory                                 */
extern "C" void * m_proc_alloc( void ) {
   void     *alrecbuf;                      /* receive buffer          */

   alrecbuf = m_hl_get_chain( &asrecbuf, &ims_spin_alloc_1 );
   if (alrecbuf) return alrecbuf;
   return malloc( LEN_TCP_RECV );
} /* end m_proc_alloc()                                                */

/** release buffer and put it to chain of buffers to be reused         */
extern "C" void m_proc_free( void *ap1 ) {
   m_hl_put_chain( &asrecbuf, ap1 );
} /* end m_proc_free()                                                 */
#endif

/** print message on console and write it to the logs                  */
extern "C" int m_hlnew_printf( int imp_type, char *achptext, ... ) {
   va_list    dsl_argptr;
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3;             /* working-variables       */
#ifndef B120714
   int        iml_len_msg;                  /* length message          */
#endif
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   char       chrl_out1[ LEN_MSG_PRE + 512 ];  /* buffer               */
#ifndef B120714
   char       chrl_out_memlog[ 512 ];       /* buffer for memlog       */
#endif

#ifndef TEST01
   va_start( dsl_argptr, achptext );
#ifdef B120714
// to-do 12.07.12 KB use ieg_charset_system instead of ied_chs_ascii_850
   iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1) - 2, ied_chs_ascii_850, achptext, dsl_argptr );
#else
   iml_len_msg = m_hlvsnprintf( chrl_out1 + LEN_MSG_PRE, sizeof(chrl_out1) - LEN_MSG_PRE - 2, ieg_charset_system, achptext, dsl_argptr );
   iml1 = 0;
   if (iml_len_msg > 0) iml1 = iml_len_msg;
#endif
   va_end( dsl_argptr );
   if (iml1 > 0) {
     *((char *) chrl_out1 + LEN_MSG_PRE + iml1 + 0) = '\n';
     *((char *) chrl_out1 + LEN_MSG_PRE + iml1 + 1) = 0;
   }
   printf( "%.*s", iml1 + 1, chrl_out1 + LEN_MSG_PRE );
   if (   (img_wsp_trace_core_flags1 & HL_WT_CORE_CONSOLE)  /* messages written to the console */
       && (dss_wsp_trace_thr_ctrl.iec_wtt != ied_wtt_console)) {  /* not print on console */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CCONSOLE", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml2 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "write to console length %d/0X%X.",
                     iml1, iml1 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml2;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2)) {  /* generate WSP trace record */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml2 = iml1;                         /* length of data displayed */
       achl_w3 = (char *) chrl_out1 + LEN_MSG_PRE;  /* start of data   */
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
#ifdef B110706
         ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
#endif
         ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed        */
         achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
         ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
#ifdef B110706
         if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
           adsl_wtr_w1->boc_more = TRUE;    /* more data to follow     */
         }
#endif
         adsl_wtr_w1->boc_more = bol1;      /* more data to follow     */
         bol1 = TRUE;                       /* set more flag           */
         adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain     */
         adsl_wtr_w1 = ADSL_WTR_G2;         /* this is last in chain now */
         iml3 = achl_w2 - achl_w4;
         if (iml3 > iml2) iml3 = iml2;
         memcpy( achl_w4, achl_w3, iml3 );
         achl_w4 += iml3;
         achl_w3 += iml3;
         ADSL_WTR_G2->imc_length = iml2;    /* length of text / data   */
         iml2 -= iml3;                      /* length to be copied     */
         achl_w1 = achl_w2;                 /* set end of this area    */
       } while (iml2 > 0);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (bos_mem_log) {                       /* write to memory log     */
#ifdef B120714
     iml2 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8,
                           achptext, dsl_argptr );
     m_write_log( imp_type, (char *) chrl_out1, iml2 );
#else
     iml2 = iml_len_msg;                    /* get length message      */
     achl_w1 = chrl_out1 + LEN_MSG_PRE;     /* get address message     */
     if (ieg_charset_system != ied_chs_utf_8) {  /* need other character set */
       iml2 = m_hlvsnprintf( chrl_out_memlog, sizeof(chrl_out_memlog), ied_chs_utf_8,
                             achptext, dsl_argptr );
       achl_w1 = chrl_out_memlog;           /* get address message     */
     }
     m_write_log( imp_type, achl_w1, iml2 );
#endif
   }
   if (imp_type == HLOG_EMER1) {
     /* write line with program version first, if event log not yet opened */
     if (bog_event_log_out == FALSE) {      /* nothing written to event log yet */
       bog_event_log_out = TRUE;            /* something written to event log */
       syslog( DEF_IPLEVEL, "%s\n", MSG_CONS_P1 HL_CPUTYPE __DATE__ MSG_CONS_P2 );
     }
   } else if (bog_log == FALSE) return iml1;
#ifndef B120714
   if (iml_len_msg > 0) *(chrl_out1 + LEN_MSG_PRE + iml_len_msg) = 0;  /* make zero-terminated again */
#endif
   achl_w1 = chrl_out1 + LEN_MSG_PRE;       /* get address message     */
   if (chrs_msg_pre[ 0 ]) {                 /* with pid                */
     memcpy( chrl_out1, chrs_msg_pre, LEN_MSG_PRE );
     achl_w1 = chrl_out1;                   /* get address message     */
     iml_len_msg += LEN_MSG_PRE;
   }
   syslog( DEF_IPLEVEL, "%.*s\n", iml_len_msg, achl_w1 );
   return iml1;
#else
   iml1 = printf( "%s\n", achptext );
   if (bog_log == FALSE) return iml1;
   syslog( DEF_IPLEVEL, "%s\n", chrl_out1 );
   return iml1;
#endif
} /* end m_hlnew_printf()                                              */

/** print message on console and write it to the logs                  */
extern "C" int m_hl1_printf( char *aptext, ... ) {
   va_list    dsl_argptr;
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3;             /* working-variables       */
#ifndef B120714
   int        iml_len_msg;                  /* length message          */
#endif
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
// HL_WCHAR   chrl_out1[ 512 * sizeof(HL_WCHAR) ];  /* buffer          */
   char       chrl_out1[ LEN_MSG_PRE + 512 ];  /* buffer               */
#ifndef B120714
   char       chrl_out_memlog[ 512 ];       /* buffer for memlog       */
#endif

   va_start( dsl_argptr, aptext );
#ifdef B120714
// to-do 12.07.12 KB use ieg_charset_system instead of ied_chs_ascii_850
   iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1) - 2, ied_chs_ascii_850, aptext, dsl_argptr );
#else
   iml_len_msg = m_hlvsnprintf( chrl_out1 + LEN_MSG_PRE, sizeof(chrl_out1) - LEN_MSG_PRE - 2, ieg_charset_system, aptext, dsl_argptr );
   iml1 = 0;
   if (iml_len_msg > 0) iml1 = iml_len_msg;
#endif
   va_end( dsl_argptr );
   if (iml1 > 0) {
     *((char *) chrl_out1 + LEN_MSG_PRE + iml1 + 0) = '\n';
     *((char *) chrl_out1 + LEN_MSG_PRE + iml1 + 1) = 0;
   }
   printf( "%.*s", iml1 + 1, chrl_out1 + LEN_MSG_PRE );
   if (   (img_wsp_trace_core_flags1 & HL_WT_CORE_CONSOLE)  /* messages written to the console */
       && (dss_wsp_trace_thr_ctrl.iec_wtt != ied_wtt_console)) {  /* not print on console */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CCONSOLE", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml2 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "write to console length %d/0X%X.",
                     iml1, iml1 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml2;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2)) {  /* generate WSP trace record */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml2 = iml1;                         /* length of data displayed */
       achl_w3 = (char *) chrl_out1 + LEN_MSG_PRE;  /* start of data   */
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
#ifdef B110706
         ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
#endif
         ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed        */
         achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
         ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
#ifdef B110706
         if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
           adsl_wtr_w1->boc_more = TRUE;    /* more data to follow     */
         }
#endif
         adsl_wtr_w1->boc_more = bol1;      /* more data to follow     */
         bol1 = TRUE;                       /* set more flag           */
         adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain     */
         adsl_wtr_w1 = ADSL_WTR_G2;         /* this is last in chain now */
         iml3 = achl_w2 - achl_w4;
         if (iml3 > iml2) iml3 = iml2;
         memcpy( achl_w4, achl_w3, iml3 );
         achl_w4 += iml3;
         achl_w3 += iml3;
         ADSL_WTR_G2->imc_length = iml2;    /* length of text / data   */
         iml2 -= iml3;                      /* length to be copied     */
         achl_w1 = achl_w2;                 /* set end of this area    */
       } while (iml2 > 0);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (bos_mem_log) {                       /* write to memory log     */
#ifdef B120714
     iml2 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8,
                           aptext, dsl_argptr );
     m_write_log( HLOG_WARN1, (char *) chrl_out1, iml2 );
#else
     iml2 = iml_len_msg;                    /* get length message      */
     achl_w1 = chrl_out1 + LEN_MSG_PRE;     /* get address message     */
     if (ieg_charset_system != ied_chs_utf_8) {  /* need other character set */
       iml2 = m_hlvsnprintf( chrl_out_memlog, sizeof(chrl_out_memlog), ied_chs_utf_8,
                             aptext, dsl_argptr );
       achl_w1 = chrl_out_memlog;           /* get address message     */
     }
     m_write_log( HLOG_WARN1, achl_w1, iml2 );
#endif
   }
#ifdef TRACEHL1
   fflush( stdout );
#endif
   if (bog_log == FALSE) return iml1;
// to-do 12.05.12 KB - charset of system
#ifndef B120714
   if (iml_len_msg > 0) *(chrl_out1 + LEN_MSG_PRE + iml_len_msg) = 0;  /* make zero-terminated again */
#endif
   achl_w1 = chrl_out1 + LEN_MSG_PRE;       /* get address message     */
   if (chrs_msg_pre[ 0 ]) {                 /* with pid                */
     memcpy( chrl_out1, chrs_msg_pre, LEN_MSG_PRE );
     achl_w1 = chrl_out1;                   /* get address message     */
     iml_len_msg += LEN_MSG_PRE;
   }
   syslog( DEF_IPLEVEL, "%.*s\n", iml_len_msg, achl_w1 );
   return iml1;
} /* end m_hl1_printf()                                                */

/** print message on console and write it to the logs                  */
static int m_hlgw_printf( void *apparam, char *aptext, ... ) {
   va_list    dsl_argptr;
   int        iml1, iml2;                   /* working-variables       */
   char       chrl_out1[ 512 ];             /* buffer                  */

   va_start( dsl_argptr, aptext );
   iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8, aptext, dsl_argptr );
   va_end( dsl_argptr );
#define ADSL_CONN1_G ((struct dsd_conn1 *) apparam)
   iml2 = m_hlnew_printf( HLOG_XYZ1, "HWSPS019W GATE=%(ux)s SNO=%08d INETA=%s WTS/VDI load-balancing %.*(u8)s",
                          ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno,
                          ADSL_CONN1_G->chrc_ineta,
                          iml1, chrl_out1 );
   return iml2;
#undef ADSL_CONN1_G
} /* end m_hlgw_printf()                                               */

/** get current time in seconds                                        */
extern "C" dsd_time_1 m_get_time( void ) {
#ifdef B111010
   dsd_time_1 dsl_time;

#ifndef TRACEHLB
   return time( &dsl_time );
#else
   int imh1 = time( &dsl_time );
   m_hlnew_printf( HLOG_XYZ1, "m_get_time() returns %d.", imh1 );
   return imh1;
#endif
#else
   return time( NULL );
#endif
} /* end m_get_time()                                                  */

/** return the Epoch value in milliseconds, feed random                */
static HL_LONGLONG m_get_rand_epoch_ms( void ) {
   struct timeval dsl_timeval;

   gettimeofday( &dsl_timeval, NULL );
   ucs_random_01 = dsl_timeval.tv_usec >> 14;
   return (((HL_LONGLONG) dsl_timeval.tv_sec) * 1000 + dsl_timeval.tv_usec / 1000);
} /* end m_get_rand_epoch_ms()                                              */

/* return the Epoch value in microseconds                              */
extern "C" HL_LONGLONG m_get_epoch_microsec( void ) {
   struct timeval dsl_timeval;

   gettimeofday( &dsl_timeval, NULL );
   ucs_random_01 = dsl_timeval.tv_usec >> 14;
   return (((HL_LONGLONG) dsl_timeval.tv_sec) * 1000 * 1000 + dsl_timeval.tv_usec );
} /* end m_get_epoch_microsec()                                        */

/** return the Epoch value in nanoseconds                              */
static HL_LONGLONG m_get_epoch_nanoseconds( void ) {
   int        iml_rc;                       /* return code             */
   struct timespec dsl_timespec;
   struct timeval dsl_timeval;

   iml_rc = clock_gettime( CLOCK_REALTIME, &dsl_timespec );
   if (iml_rc >= 0) {                       /* succeeded               */
     return (((HL_LONGLONG) dsl_timespec.tv_sec) * 1000 * 1000 * 1000 + dsl_timespec.tv_nsec);
   }
   gettimeofday( &dsl_timeval, NULL );
   return (((HL_LONGLONG) dsl_timeval.tv_sec) * 1000 * 1000 * 1000 + dsl_timeval.tv_usec * 1000);
} /* end m_get_epoch_nanoseconds()                                     */

/** return the Epoch value in micro-seconds                            */
static HL_LONGLONG m_get_epoch_micro_sec( void ) {
   struct timeval dsl_timeval;

   gettimeofday( &dsl_timeval, NULL );
   return (((HL_LONGLONG) dsl_timeval.tv_sec) * 1000 * 1000 + dsl_timeval.tv_usec);
} /* end m_get_epoch_micro_sec()                                       */

/* check if session is still active                                    */
extern "C" BOOL m_check_conn_active( struct dsd_conn1 *adsp_conn1 ) {
#ifdef NOT_YET_110808
   return adsp_conn1->bo_st_open;
#endif
   return FALSE;
} /* end m_check_conn_active()                                         */

/** this routine returns a number between zero and impmax minus one
    0 <= ret-val < impmax                                              */
extern "C" int m_get_random_number( int impmax ) {
   HL_LONGLONG ill1;                        /* working-variable        */

   ill1 = (HL_LONGLONG) rand() * impmax;
   /* correction 30.09.08 KB - proposal Mr. Tischhöfer */
// ill1 /= RAND_MAX - 1;
// ill1 /= RAND_MAX + 1;
   ill1 /= (HL_LONGLONG) RAND_MAX + 1;
   return (int) ill1;
} /* end m_get_random_number()                                         */

/** lock blade - VDI                                                   */
static void m_lock_blade_control( void ) {  /* lock resource           */
   dss_util_critsect.m_enter();             /* enter CriticalSection   */
} /* end m_lock_blade_control()                                        */

/** unlock blade - VDI                                                 */
static void m_unlock_blade_control( void ) {  /* unlock resource       */
   dss_util_critsect.m_leave();             /* leave CriticalSection   */
} /* m_unlock_blade_control()                                          */

/** subroutine is called from OS when ended thru a signal              */
static void m_signal_end( int imp_param ) {
   struct sigaction dsl_aact;               /* Signal action structure */
   void *     vprl_message[ DEF_MSG_PIPE_LEN ];  /* message in pipe    */

   dsl_aact.sa_handler = SIG_DFL;           /* set handler method      */
   sigemptyset( &dsl_aact.sa_mask );        /* clear action set        */
   dsl_aact.sa_flags = 0;                   /* clear flags             */

   sigaction( SIGINT, &dsl_aact , 0 );      /* act handler on CTRL-C   */
   sigaction( SIGTSTP, &dsl_aact , 0 );     /* act handler on CTRL_Z   */
   sigaction( SIGTERM, &dsl_aact , 0 );     /* act handler on KILL     */

   if (imrs_m_fd_pipe[1] == 0) exit( 0 );   /* pipe not opened         */
   *((ied_mess_pipe_main *) &vprl_message[0]) = ied_mepm_sig_end;  /* type of message */
   *((int *) &vprl_message[1]) = imp_param; /* give signal type        */
   /* may fail, but what to do when failed                             */
   write( imrs_m_fd_pipe[1], vprl_message, sizeof(vprl_message) );
} /* end m_signal_end()                                                */

/** notify main thread that signal has been received                   */
static void m_signal_rec( int imp_param ) {
   void *     vprl_message[ DEF_MSG_PIPE_LEN ];  /* message in pipe    */

   if (imrs_m_fd_pipe[1] == 0) return;      /* pipe not opened         */
   *((ied_mess_pipe_main *) &vprl_message[0]) = ied_mepm_sig_reload;  /* type of message */
   *((int *) &vprl_message[1]) = imp_param;  /* give signal type       */
   /* may fail, but what to do when failed                             */
   write( imrs_m_fd_pipe[1], vprl_message, sizeof(vprl_message) );
} /* end m_signal_rec()                                                */

/** abend this process with message                                    */
static void m_hl_abend1( char *achp_message ) {
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20 l%05d m_hl_abend1() %s",
                   __LINE__, achp_message );
// UUUU 05.05.06 exit process
   exit( -1 );                              /* exit process            */
} /* end m_hl_abend1()                                                 */

/** subroutine to display date and time                                */
static int m_get_date_time( char *achp_buff ) {
   time_t     dsl_time;

   time( &dsl_time );
   return strftime( achp_buff, 18, "%d.%m.%y %H:%M:%S", localtime( &dsl_time ) );
} /* end m_get_date_time()                                             */

/** subroutine to dump storage-content to console                      */
extern "C" void m_console_out( char *achp_buff, int implength ) {
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
     m_hl1_printf( "%.*s", sizeof(chrlwork1), chrlwork1 );
   }
} /* end m_console_out()                                            */

#ifdef NOT_NEEDED_110808
/** edit a long integer number for decimal display                     */
static char * m_edit_dec_long( char *achp_target, HL_LONGLONG ilp1 ) {
   int        iml1;                         /* working variable        */
   char       *achl1;                       /* working variable        */

   achl1 = achp_target + 31;
   *achl1 = 0;                              /* make zero-terminated    */
   iml1 = 3;                                /* digits between separator */
   while (TRUE) {
     *(--achl1) = (char) (ilp1 % 10 + '0');
     ilp1 /= 10;
     if (ilp1 == 0) return achl1;
     iml1--;
     if (iml1 == 0) {
     *(--achl1) = ',';                      /* output separator        */
       iml1 = 3;                            /* digits between separator */
     }
   }
} /* end m_edit_dec_long()                                             */
#endif

/** put a warning related to the session to the console                */
extern "C" void m_radius_warning( void * ap_conn1,
                                  int imp_error_number,
                                  const char *achp_format, ... ) {
   int        iml_len;                      /* length of message       */
   va_list    dsl_list;                     /* list of arguments       */
   char       chrl_msg[ 512 ];              /* area for message        */

#define ADSL_CONN1_G ((struct dsd_conn1 *) ap_conn1)
   va_start( dsl_list, achp_format );       /* build dsl_list of variable arguments */
   iml_len = m_hlvsnprintf( chrl_msg, sizeof(chrl_msg), ied_chs_utf_8,
                            achp_format, dsl_list );
   va_end( dsl_list );                      /* destroy list            */
   m_hlnew_printf( HLOG_XYZ1, "HWSPRA%03dW GATE=%(ux)s SNO=%08d INETA=%s HTUN %.*(u8)s",
                   ADSL_CONN1_G->adsc_gate1 + 1,
                   ADSL_CONN1_G->dsc_co_sort.imc_sno,
                   ADSL_CONN1_G->chrc_ineta,
                   iml_len, chrl_msg );
   return;                                  /* all done                */
#undef ADSL_CONN1_G
} /* end m_radius_warning()                                            */

/** put a warning related to the session to the console for LDAP       */
extern "C" void m_ldap_warning( void * ap_conn1,
                                int imp_error_number,
                                const char *achp_format, ... ) {
} /* end m_ldap_warning()                                              */

/** put a informational message related to the session to the console for LDAP */
extern "C" void m_ldap_info( void * ap_conn1,
                             int imp_error_number,
                             const char *achp_format, ... ) {
} /* end m_ldap_info()                                                 */

/** query the OS, number of CPUs                                       */
extern "C" int m_get_no_cpu( void ) {
#ifndef HL_HPUX
   return sysconf( _SC_NPROCESSORS_ONLN );
#else
   struct pst_dynamic dsl_psd;

   pstat_getdynamic( &dsl_psd, sizeof(struct pst_dynamic), 1, 0 );
   return (int) dsl_psd.psd_proc_cnt;
#endif
} /* end m_get_no_cpu()                                                */

/** get single INETA IPV4                                              */
extern "C" UNSIG_MED m_get_ineta_single( char *achp1 ) {
   UNSIG_MED  uml_ineta;                    /* INETA to be returned    */
   struct hostent *adsl_hostentry;          /* for gethostbyname()     */

   uml_ineta = inet_addr( achp1 );
   if (uml_ineta == 0XFFFFFFFF) {           /* invalid IP-address      */
     adsl_hostentry = gethostbyname( achp1 );
     if (adsl_hostentry) {                  /* API call successful     */
       uml_ineta = *((UNSIG_MED *) *(adsl_hostentry->h_addr_list) );
     }
   }
   return uml_ineta;
} /* end m_get_ineta_single()                                          */

#ifdef B120827
// to-do 08.08.11 KB move to subroutine
/**
* open a Radius connection
*/
extern "C" void m_open_radius( char *achp_work, int inp_len_work,
                               amd_msgprog amp_msgproc, void * vpp_userfld,
                               struct dsd_radius_entry *adsp_raent ) {
}
#endif

#ifdef B110810
// to-do 08.08.11 KB move to subroutine
extern "C" BOOL m_cdaux( void * vpp_userfld, int imp_func, void * apparam, int imp_length ) {
   return FALSE;
}
#endif

#ifdef B120827
// to-do 08.08.11 KB move to subroutine
extern "C" struct dsd_service_conf_1 * m_service_vc_icap_http_conf( DOMNode *adsp_domnode,
                                             void * (* amp_call_dom) ( DOMNode *, ied_hlcldom_def ),   /* call DOM */
                                             HL_WCHAR * awcp_se_name ) {
   m_hlnew_printf( HLOG_XYZ1, "m_service_vc_icap_http_conf() l%05d adsp_domnode %p amp_call_dom %p name %(ux)s",
                   __LINE__, adsp_domnode, amp_call_dom, awcp_se_name );
   return NULL;
}
#endif

/** get string with name and version of the WSP                        */
extern "C" const char * m_get_query_main( void ) {
   return chrs_query_main;
} /* end m_get_chrs_query_main()                                       */

#ifdef XYZ1
/* Admin return Sessions                                               */
extern "C" struct dsd_sdh_control_1 * m_get_wspadm1_session( struct dsd_wspadm1_q_session * adsp_wspadm1_q_session ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working variables       */
   int        iml_count;                    /* count entries           */
   int        iml_cmp;                      /* to compare entries      */
   char       *achl_avl_error;              /* error code AVL tree     */
   struct dsd_conn1 *adsl_conn_w1;          /* connection              */
   char       *achl_w1;                     /* working variable        */
   char       *achl_out;                    /* output of values        */
   struct dsd_wspadm1_session *adsl_out_se;  /* WSP Administration Session */
   void *     arl_param[7];                 /* address of additional fields */
   int        imrl_len[7];                  /* length of additional fields */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working-variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_first;  /* first structure     */
   struct dsd_sdh_control_1 *adsl_sdhc1_last;  /* last structure       */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* output data             */
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* configuration server */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   struct dsd_co_sort dsl_co_sort_w1;       /* for connection sort     */
#ifdef XYZ1
   struct dsd_htree1_avl_entry dsc_sort_1;  /* entry for sorting       */
   int        imc_sno;                      /* session number          */
#endif
   int        imrl_ineta_port[ 24 / sizeof(int) ];  /* save INETA and Port */

   iml_count = adsp_wspadm1_q_session->imc_no_session;  /* count entries */
   if (iml_count <= 0) {                    /* invalid number          */
     /* output record type invalid parameters                          */
     adsl_sdhc1_first = (struct dsd_sdh_control_1 *) m_proc_alloc();
     memset( adsl_sdhc1_first, 0, sizeof(struct dsd_sdh_control_1) );
     achl_out = (char *) (adsl_sdhc1_first + 1);  /* output of values  */
     adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_first + LEN_TCP_RECV);
     adsl_gai1_w1--;                        /* here is gather output   */
     adsl_sdhc1_first->adsc_gather_i_1_i = adsl_gai1_w1;  /* first gather input data */
     adsl_gai1_w1->adsc_next = NULL;
     adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
     adsl_gai1_w1->achc_ginp_end = achl_out + 2;  /* end of this structure */
     *(achl_out + 0) = 1;                   /* length of record        */
     *(achl_out + 1) = (unsigned char) DEF_WSPADM_RT_INV_PARAM;  /* invalid parameters */
     return adsl_sdhc1_first;
   }
   memset( &dsl_co_sort_w1, 0, sizeof(struct dsd_co_sort) );
   dsl_co_sort_w1.imc_sno = adsp_wspadm1_q_session->imc_session_no;  /* session number before */
   achl_avl_error = NULL;                   /* clear error code AVL tree */
   adsl_sdhc1_first = NULL;                 /* first structure         */
   dss_main_critsect.m_enter();             /* enter CriticalSection   */
   do {                                     /* pseudo-loop             */
     bol1 = m_htree1_avl_search( NULL, &dss_htree1_avl_cntl_conn,
                                 &dsl_htree1_work, &dsl_co_sort_w1.dsc_sort_1 );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "m_htree1_avl_search() failed";  /* error code AVL tree */
       break;                               /* do not continue         */
     }
     do {                                   /* loop for sequential retrieval */
       bol1 = m_htree1_avl_getnext( NULL, &dss_htree1_avl_cntl_conn,
                                    &dsl_htree1_work, FALSE );
       if (bol1 == FALSE) {                 /* error occured           */
         achl_avl_error = "m_htree1_avl_getnext() failed";  /* error code AVL tree */
         break;                             /* do not continue         */
       }
       if (dsl_htree1_work.adsc_found == NULL) break;  /* reached end of tree */
#ifndef PROBLEM_OFFSETOF_110810
       adsl_conn_w1 = (struct dsd_conn1 *)
                        ((char *) dsl_htree1_work.adsc_found
                           - offsetof( struct dsd_co_sort, dsc_sort_1 )
                           - offsetof( struct dsd_conn1, dsc_co_sort ));
#else
       adsl_conn_w1 = NULL;
#endif
       memset( imrl_len, 0, sizeof(imrl_len) );
       /* search auxf records                                          */
       adsl_auxf_1_w1 = adsl_conn_w1->adsc_auxf_1;  /* get chain of auxiliary fields */
       while (adsl_auxf_1_w1) {             /* loop over all auxiliary fields */
         switch (adsl_auxf_1_w1->iec_auxf_def) {
           case ied_auxf_certname:          /* name from certificate = DN */
             arl_param[4] = ((int *) (adsl_auxf_1_w1 + 1)) + 1;
             imrl_len[4] = m_len_vx_vx( ied_chs_utf_8,
                                        (HL_WCHAR *) (((int *) (adsl_auxf_1_w1 + 1)) + 1),
                                        *((int *) (adsl_auxf_1_w1 + 1)) - 1,
                                        ied_chs_utf_16 );
             break;
           case ied_auxf_ident:             /* ident - userid and user-group */
             imrl_len[5] = ((struct dsd_auxf_ident_1 *) (adsl_auxf_1_w1 + 1))->imc_len_userid;  /* length userid UTF-8 */
             imrl_len[6] = ((struct dsd_auxf_ident_1 *) (adsl_auxf_1_w1 + 1))->imc_len_user_group;  /* length name user group UTF-8 */
             arl_param[5] = ((struct dsd_auxf_ident_1 *) (adsl_auxf_1_w1 + 1)) + 1;
             arl_param[6] = (char *) arl_param[5] + imrl_len[5];
             break;
         }
         adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
       }
       do {                                 /* pseudo-loop             */
         if (   (adsp_wspadm1_q_session->imc_len_userid == 0)  /* length userid UTF-8 */
             && (adsp_wspadm1_q_session->imc_len_user_group == 0)) {  /* length name user group UTF-8 */
           break;                           /* bol1 is already true    */
         }
         if (adsp_wspadm1_q_session->boc_use_wildcard == FALSE) {  /* do not use wildcard in search  */
           if (adsp_wspadm1_q_session->imc_len_userid != imrl_len[5]) {  /* compare length userid UTF-8 */
             bol1 = FALSE;                  /* do not include          */
             break;                         /* all done                */
           }
           if (adsp_wspadm1_q_session->imc_len_user_group != imrl_len[6]) {  /* compare length name user group UTF-8 */
             bol1 = FALSE;                  /* do not include          */
             break;                         /* all done                */
           }
           if (imrl_len[5]) {
             if (memcmp( adsp_wspadm1_q_session + 1, arl_param[5], imrl_len[5] )) {
               bol1 = FALSE;                /* do not include          */
               break;                       /* all done                */
             }
           }
           if (imrl_len[4]) {
             if (memcmp( (char *) (adsp_wspadm1_q_session + 1) + adsp_wspadm1_q_session->imc_len_userid,
                         arl_param[6], imrl_len[6] )) {
               bol1 = FALSE;                /* do not include          */
               break;                       /* all done                */
             }
           }
           break;                           /* bol1 is already true    */
         }
         /* search with wildcard                                       */
         if (adsp_wspadm1_q_session->imc_len_userid) {  /* check userid */
           bol1 = m_cmp_wc_i_vx_vx( &iml_cmp,
                                    arl_param[5], imrl_len[5], ied_chs_utf_8,
                                    adsp_wspadm1_q_session + 1, adsp_wspadm1_q_session->imc_len_userid, ied_chs_utf_8 );
           if ((bol1 == FALSE) || iml_cmp) {  /* strings do not match  */
             bol1 = FALSE;                  /* do not include          */
             break;                         /* all done                */
           }
         }
         if (adsp_wspadm1_q_session->imc_len_user_group) {  /* check user-group */
           bol1 = m_cmp_wc_i_vx_vx( &iml_cmp,
                                    arl_param[6], imrl_len[6], ied_chs_utf_8,
                                    (char *) (adsp_wspadm1_q_session + 1) + adsp_wspadm1_q_session->imc_len_userid,
                                    adsp_wspadm1_q_session->imc_len_user_group, ied_chs_utf_8 );
           if ((bol1 == FALSE) || iml_cmp) {  /* strings do not match  */
             bol1 = FALSE;                  /* do not include          */
             break;                         /* all done                */
           }
         }
       } while (FALSE);
       if (bol1) {                          /* return this session     */
#ifdef NOT_YET_110810
         while (adsl_conn_w1->dcl_tcp_r_s.getstc()) {  /* session to server is active */
           achl_w1 = NULL;                  /* no INETA yet            */
           switch (adsl_conn_w1->dcl_tcp_r_s.dsc_soa.ss_family) {
             case AF_INET:                  /* IPV4                    */
               achl_w1 = (char *) &((struct sockaddr_in *) &adsl_conn_w1->dcl_tcp_r_s.dsc_soa)->sin_addr;
               iml1 = 4;
               break;
             case AF_INET6:                 /* IPV6                    */
               achl_w1 = (char *) &((struct sockaddr_in6 *) &adsl_conn_w1->dcl_tcp_r_s.dsc_soa)->sin6_addr;
               iml1 = 16;
               break;
           }
           if (achl_w1 == NULL) break;      /* no INETA found          */
           memcpy( imrl_ineta_port, achl_w1, iml1 );
           arl_param[3] = imrl_ineta_port;  /* copy this field later   */
#ifdef NOT_YET_110810
           *((unsigned short int *) ((char *) imrl_ineta_port + iml1))
             = IP_ntohs( ((struct sockaddr_in *) &adsl_conn_w1->dcl_tcp_r_s.dsc_soa)->sin_port );
#endif
           imrl_len[3] = iml1 + sizeof(unsigned short int);
           break;
         }
#endif
         arl_param[0] = adsl_conn_w1->adsc_gate1 + 1;
         imrl_len[0] = m_len_vx_vx( ied_chs_utf_8,
                                    arl_param[0], -1, ied_chs_utf_16 );
         adsl_server_conf_1_w1 = NULL;      /* no configuration server yet */
         if (adsl_conn_w1->adsc_server_conf_1) {  /* configuration server */
           adsl_server_conf_1_w1 = adsl_conn_w1->adsc_server_conf_1;  /* get current server configuration */
#ifdef B101215
           if (adsl_server_conf_1_w1->boc_dynamic) {  /* dynamicly allocated */
             adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_seco1_previous;  /* configuration server previous */
           }
#else
           if (adsl_server_conf_1_w1->adsc_seco1_previous) {  /* has previous configuration */
             adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_seco1_previous;  /* configuration server previous */
           }
#endif
         }
         if (adsl_server_conf_1_w1) {       /* configuration server valid */
           if (adsl_server_conf_1_w1->inc_len_name) {  /* name has valid length */
             arl_param[1] = (char *) (adsl_server_conf_1_w1 + 1)
                                        + adsl_server_conf_1_w1->inc_no_sdh
                                          * sizeof(struct dsd_sdh_work_1);
             imrl_len[1] = m_len_vx_vx( ied_chs_utf_8,
                                        arl_param[1], -1, ied_chs_utf_16 );
           }
           switch (adsl_server_conf_1_w1->iec_scp_def) {
             case ied_scp_undef:            /* protocol undefined      */
               break;                       /* nothing to do           */
             case ied_scp_spec:             /* special protocol        */
               imrl_len[2] = adsl_server_conf_1_w1->inc_len_protocol;
               arl_param[2] = (char *) (adsl_server_conf_1_w1 + 1)
                                + adsl_server_conf_1_w1->inc_no_sdh
                                  * sizeof(struct dsd_sdh_work_1)
                                + adsl_server_conf_1_w1->inc_len_name;
               break;                       /* all done                */
             default:                       /* all other protocols     */
               iml1 = sizeof(dsrs_protdef_e) / sizeof(dsrs_protdef_e[0]);
               do {                         /* loop over all defined protocols */
                 iml1--;                    /* decrement index         */
                 if (dsrs_protdef_e[iml1].iec_scp_def == adsl_server_conf_1_w1->iec_scp_def) {
                   arl_param[2] = dsrs_protdef_e[iml1].achc_keyword;
                   imrl_len[2] = strlen( (char *) arl_param[2] );
                   break;                   /* all done                */
                 }
               } while (iml1 > 0);
               break;                       /* all done                */
           }
         }
         iml1 = sizeof(struct dsd_wspadm1_session);
         iml2 = sizeof(imrl_len) / sizeof(imrl_len[0]);  /* number of elements */
         do {                               /* add all length fields   */
           iml2--;                          /* decrement index         */
           iml1 += imrl_len[ iml2 ];        /* sum of length           */
         } while (iml2 > 0);
         do {                               /* pseudo-loop             */
           if (adsl_sdhc1_first) {          /* first structure present */
             achl_out += 4 + 1 + sizeof(void *) - 1;  /* output of values */
             achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
             if ((achl_out + iml1 + sizeof(struct dsd_gather_i_1))
                   <= ((char *) adsl_gai1_w1)) {
               adsl_gai1_w1--;              /* here is gather output   */
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
             adsl_sdhc1_last = adsl_sdhc1_w1;  /* set last structure   */
             break;
           }
           adsl_sdhc1_last->adsc_next = adsl_sdhc1_w1;  /* append to chain */
           adsl_sdhc1_last = adsl_sdhc1_w1;  /* set last structure     */
         } while (FALSE);
         adsl_gai1_w1->adsc_next = NULL;
         adsl_out_se = (struct dsd_wspadm1_session *) achl_out;
         iml1++;                            /* add length record type  */
         *(--achl_out) = 0;                 /* record type             */
         iml2 = 0;                          /* clear more bit          */
         while (TRUE) {                     /* output length NHASN     */
           *(--achl_out) = (unsigned char) ((iml1 & 0X7F) | iml2);  /* output of digit */
           iml1 >>= 7;                      /* remove digit            */
           if (iml1 == 0) break;            /* end of output           */
           iml2 = 0X80;                     /* set more bit            */
         }
         adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
         adsl_out_se->imc_len_gate_name = imrl_len[0];  /* length gate name UTF-8 */
         adsl_out_se->imc_len_serv_ent = imrl_len[1];  /* length name Server Entry UTF-8 */
         adsl_out_se->imc_len_protocol = imrl_len[2];  /* length of protocol UTF-8 */
         adsl_out_se->imc_len_ineta_port = imrl_len[3];  /* INETA and Port connection to server */
         adsl_out_se->imc_session_no = adsl_conn_w1->dsc_co_sort.imc_sno;  /* session number */
         memcpy( adsl_out_se->chrc_ineta, adsl_conn_w1->chrc_ineta, sizeof(adsl_out_se->chrc_ineta) );  /* internet-address client char */
         adsl_out_se->imc_time_start = adsl_conn_w1->imc_time_start;  /* time session started */
         adsl_out_se->imc_c_ns_rece_c = adsl_conn_w1->inc_c_ns_rece_c;  /* count receive client */
         adsl_out_se->imc_c_ns_send_c = adsl_conn_w1->inc_c_ns_send_c;  /* count send client */
         adsl_out_se->imc_c_ns_rece_s = adsl_conn_w1->inc_c_ns_rece_s;  /* count receive server */
         adsl_out_se->imc_c_ns_send_s = adsl_conn_w1->inc_c_ns_send_s;  /* count send server */
         adsl_out_se->imc_c_ns_rece_e = adsl_conn_w1->inc_c_ns_rece_e;  /* count encrypted from cl */
         adsl_out_se->imc_c_ns_send_e = adsl_conn_w1->inc_c_ns_send_e;  /* count encrypted to clie */
         adsl_out_se->ilc_d_ns_rece_c = adsl_conn_w1->ilc_d_ns_rece_c;  /* data received client */
         adsl_out_se->ilc_d_ns_send_c = adsl_conn_w1->ilc_d_ns_send_c;  /* data sent client */
         adsl_out_se->ilc_d_ns_rece_s = adsl_conn_w1->ilc_d_ns_rece_s;  /* data received server */
         adsl_out_se->ilc_d_ns_send_s = adsl_conn_w1->ilc_d_ns_send_s;  /* data sent server */
         adsl_out_se->ilc_d_ns_rece_e = adsl_conn_w1->ilc_d_ns_rece_e;  /* data received encyrpted */
         adsl_out_se->ilc_d_ns_send_e = adsl_conn_w1->ilc_d_ns_send_e;  /* data sent encrypted */
         adsl_out_se->imc_len_name_cert = imrl_len[4];  /* length name from certificate UTF-8 */
         adsl_out_se->imc_len_userid = imrl_len[5];  /* length userid UTF-8 */
         adsl_out_se->imc_len_user_group = imrl_len[6];  /* length name user group UTF-8 */
         achl_out = (char *) (adsl_out_se + 1);  /* output of strings here */
         iml1 = 0;                          /* clear count entry       */
         do {                               /* loop to generate additional UTF-8 fields */
           if (imrl_len[ iml1 ] > 0) {      /* set parameter           */
             if ((iml1 <= 1) || (iml1 == 4)) {  /* get from UTF-16     */
               m_cpy_vx_vx( achl_out, imrl_len[ iml1 ], ied_chs_utf_8,
                            arl_param[ iml1 ], -1, ied_chs_utf_16 );
             } else {                       /* is already UTF-8        */
               memcpy( achl_out, arl_param[ iml1 ], imrl_len[ iml1 ] );
             }
             achl_out += imrl_len[ iml1 ];  /* add length parameter    */
           }
           iml1++;                          /* take next entry         */
         } while (iml1 < (sizeof(imrl_len) / sizeof(imrl_len[0])));
         adsl_gai1_w1->achc_ginp_end = achl_out;  /* end of this structure */
         iml_count--;                       /* decrement count entries */
       }
     } while (iml_count > 0);
   } while (FALSE);
   dss_main_critsect.m_leave();             /* leave CriticalSection   */
   if (achl_avl_error) {                    /* error occured           */
/* to-do 13.04.08 KB - error message */
//   m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s remove sno error %s",
//                   adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta, achl_avl_error );
   }
   if (iml_count <= 0) {                    /* all processed           */
     return adsl_sdhc1_first;
   }
   /* output record type eof end-of-file                               */
   do {                                     /* pseudo-loop             */
     if (adsl_sdhc1_first) {                /* first structure present */
       if ((achl_out + 2 + sizeof(struct dsd_gather_i_1))
             <= ((char *) adsl_gai1_w1)) {
         adsl_gai1_w1--;                    /* here is gather output   */
         (adsl_gai1_w1 + 1)->adsc_next = adsl_gai1_w1;  /* set next in chain */
         break;
       }
     }
     adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
     memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
     achl_out = (char *) (adsl_sdhc1_w1 + 1);  /* output of values     */
     adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - sizeof(struct dsd_gather_i_1));
     adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_gai1_w1;  /* gather input data */
     if (adsl_sdhc1_first == NULL) {        /* first structure not present */
       adsl_sdhc1_first = adsl_sdhc1_w1;    /* first structure now present */
       adsl_sdhc1_last = adsl_sdhc1_w1;     /* set last structure      */
       break;
     }
     adsl_sdhc1_last->adsc_next = adsl_sdhc1_w1;  /* append to chain   */
     adsl_sdhc1_last = adsl_sdhc1_w1;       /* set last structure      */
   } while (FALSE);
   adsl_gai1_w1->adsc_next = NULL;
   adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
   adsl_gai1_w1->achc_ginp_end = achl_out + 2;  /* end of this structure */
   *(achl_out + 0) = 1;                     /* length of record        */
   *(achl_out + 1) = (unsigned char) DEF_WSPADM_RT_EOF;  /* end-of-file */
   return adsl_sdhc1_first;
} /* end m_get_wspadm1_session()                                       */

extern "C" struct dsd_sdh_control_1 * m_get_wspadm1_cancel_session( struct dsd_wspadm1_q_can_sess_1 *adsp_wspadm1_qcs1 ) {
#ifndef NOT_YET_UNIX_110808
   BOOL       bol1;                         /* working variable        */
   char       *achl_out;                    /* output of values        */
   char       *achl_avl_error;              /* error code AVL tree     */
   struct dsd_sdh_control_1 *adsl_sdhc1_first;  /* first structure     */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* output data             */
   struct dsd_conn1 *adsl_conn_w1;          /* connection              */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   struct dsd_co_sort dsl_co_sort_w1;       /* for connection sort     */

   adsl_sdhc1_first = (struct dsd_sdh_control_1 *) m_proc_alloc();
   memset( adsl_sdhc1_first, 0, sizeof(struct dsd_sdh_control_1) );
   achl_out = (char *) (adsl_sdhc1_first + 1) + 4 + 1 + sizeof(void *) - 1;  /* output of values */
   achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
   adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_first + LEN_TCP_RECV - sizeof(struct dsd_gather_i_1));
   adsl_gai1_w1->adsc_next = NULL;
   adsl_sdhc1_first->adsc_gather_i_1_i = adsl_gai1_w1;  /* gather input data */
   memset( &dsl_co_sort_w1, 0, sizeof(struct dsd_co_sort) );
   dsl_co_sort_w1.imc_sno = adsp_wspadm1_qcs1->imc_session_no;  /* session number to cancel */
   achl_avl_error = NULL;                   /* clear error code AVL tree */
   EnterCriticalSection( &d_clconn_critsect );
   bol1 = m_htree1_avl_search( NULL, &dss_htree1_avl_cntl_conn,
                               &dsl_htree1_work, &dsl_co_sort_w1.dsc_sort_1 );
   if (bol1 == FALSE) {                     /* error occured           */
     achl_avl_error = "m_htree1_avl_search() failed";  /* error code AVL tree */
   }
   LeaveCriticalSection( &d_clconn_critsect );
   if (achl_avl_error) {                    /* error occured           */
/* to-do 01.10.08 KB - error message */
     adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
     adsl_gai1_w1->achc_ginp_end = achl_out + 2;  /* end of this structure */
     *(achl_out + 0) = 1;                   /* length of record        */
     *(achl_out + 1) = (unsigned char) DEF_WSPADM_RT_PROC_E;  /* processing error */
     return adsl_sdhc1_first;
   }
#define ADSL_WSPADM1_RCS1_G ((struct dsd_wspadm1_r_can_sess_1 *) achl_out)
   adsl_gai1_w1->achc_ginp_end = (char *) (ADSL_WSPADM1_RCS1_G + 1);  /* end of this structure */
   memset( ADSL_WSPADM1_RCS1_G, 0, sizeof(struct dsd_wspadm1_r_can_sess_1) );
   if (dsl_htree1_work.adsc_found) {        /* entry found             */
     adsl_conn_w1 = (struct dsd_conn1 *)
                      ((char *) dsl_htree1_work.adsc_found
                         - offsetof( struct dsd_co_sort, dsc_sort_1 )
                         - offsetof( struct dsd_conn1, dsc_co_sort ));
     if (adsl_conn_w1->achc_reason_end == NULL) {  /* reason end session */
       adsl_conn_w1->achc_reason_end = "cancelled by Admin";  /* set text */
     }
     adsl_conn_w1->dcl_tcp_r_c.close1();
     if (   (adsl_conn_w1->iec_st_ses == clconn1::ied_ses_conn)  /* stat server */
         && (adsl_conn_w1->iec_servcotype == ied_servcotype_normal_tcp)) {  /* normal TCP */
       adsl_conn_w1->dcl_tcp_r_s.close1();
     }
     ADSL_WSPADM1_RCS1_G->boc_ok = TRUE;    /* cancel session successful */
   }
   *(--achl_out) = 0;                       /* type of record          */
   *(--achl_out) = (unsigned char) (1 + sizeof(struct dsd_wspadm1_r_can_sess_1));  /* length of record */
   adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
   return adsl_sdhc1_first;
#else
   return NULL;
#endif
} /* end m_get_wspadm1_cancel_session()                                */

/* Admin return Listen                                                 */
extern "C" struct dsd_sdh_control_1 * m_get_wspadm1_listen( void ) {
   int        iml1, iml2, iml3;             /* working variables       */
   int        iml_len_ineta;                /* length of INETAs        */
   char       *achl_ineta;                  /* address of INETA        */
   char       *achl_out;                    /* output of values        */
   struct dsd_wspadm1_listen_main *adsl_o_l_main;
   struct dsd_wspadm1_listen_ineta *adsl_o_l_ineta;
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working-variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_first;  /* first structure     */
   struct dsd_sdh_control_1 *adsl_sdhc1_last;  /* last structure       */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* output data             */
   struct dsd_gate_1 *adsl_gate_1_w1;       /* gateway                 */
   struct dsd_gate_listen_1 *adsl_gate_listen_1_w1;  /* listen part of gateway */

   adsl_sdhc1_first = NULL;                 /* first structure         */
#ifdef XYZ1
   m_hlnew_printf( HLOG_XYZ1, "HWSPR003I configuration loaded %s", adss_loconf_1_anchor->byrc_time );
#endif
   adsl_gate_1_w1 = dss_loconf_1.adsc_gate_anchor;  /* get anchor gate */
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
         *(--achl_out) = 1;               /* record type             */
         iml2 = 0;                        /* clear more bit          */
         while (TRUE) {                   /* output length NHASN     */
           *(--achl_out) = (unsigned char) ((iml1 & 0X7F) | iml2);  /* output of digit */
           iml1 >>= 7;                    /* remove digit            */
           if (iml1 == 0) break;          /* end of output           */
           iml2 = 0X80;                   /* set more bit            */
         }
         adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
         memset( adsl_o_l_ineta, 0, sizeof(struct dsd_wspadm1_listen_ineta) );
         adsl_o_l_ineta->imc_len_ineta = iml_len_ineta;  /* length of INETA in bytes */
         achl_out = (char *) (adsl_o_l_ineta + 1);  /* after this structure */
         memcpy( achl_out, achl_ineta, iml_len_ineta );
         achl_out += iml_len_ineta;
         adsl_gai1_w1->achc_ginp_end = achl_out;  /* end of this structure */
       }
       adsl_gate_listen_1_w1 = adsl_gate_listen_1_w1->adsc_next;  /* get next in chain */
     }
     adsl_gate_1_w1 = adsl_gate_1_w1->adsc_next;
   }
   return adsl_sdhc1_first;
} /* end m_get_wspadm1_listen()                                        */

/* Admin return Performance Data                                       */
extern "C" struct dsd_sdh_control_1 * m_get_wspadm1_perfdata( void ) {
   int        iml1, iml2;                   /* working variables       */
   char       *achl_w1;                     /* working variable        */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */

   adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
   memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
#define ADSL_GAI1_G1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))
   achl_w1 = (char *) adsl_sdhc1_w1 + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) + 8;
#ifndef NOT_YET_UNIX_110808
   iml1 = m_get_perf_array( achl_w1, ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV) - achl_w1 );
#else
   iml1 = 0;
#endif
   if (iml1 <= 0) {
// to-do 27.04.11 KB error message
     m_proc_free( adsl_sdhc1_w1 );          /* free data again         */
     return NULL;                           /* nothing prepared        */
   }
   ADSL_GAI1_G1->achc_ginp_end = achl_w1 + iml1;  /* end of data       */
   iml2 = 0;                                /* clear more bit          */
   do {                                     /* loop for output of length NHASN */
     *(--achl_w1) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* remove bits             */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
   ADSL_GAI1_G1->achc_ginp_cur = achl_w1;   /* start of data           */
   adsl_sdhc1_w1->adsc_gather_i_1_i = ADSL_GAI1_G1;  /* gather input data */
   return adsl_sdhc1_w1;                    /* return data prepared    */
#undef ADSL_GAI1_G1
} /* end m_get_wspadm1_perfdata()                                      */

/* Admin control WSP Trace                                             */
extern "C" void m_ctrl_wspadm1_wsp_trace( struct dsd_wspadm1_q_wsp_trace_1 *adsp_wspadm1_qwt1, int imp_len_content ) {
   char       *achl_cur;                    /* current INETA pointer   */
   char       *achl_end;                    /* end if INETAs           */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace record        */
   struct dsd_wsp_tr_ineta_ctrl *adsl_wtic_w1;  /* WSP trace client with INETA control */
   struct dsd_wsp_tr_ineta_ctrl *adsl_wtic_w2;  /* WSP trace client with INETA control */

//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "HWSPMXXX1-%05d-T m_ctrl_wspadm1_wsp_trace( %p , %d ) called",
                   __LINE__, adsp_wspadm1_qwt1, imp_len_content );
   m_console_out( (char *) adsp_wspadm1_qwt1, sizeof(struct dsd_wspadm1_q_wsp_trace_1) + imp_len_content );
//#endif
   if (adsg_loconf_1_inuse->boc_allow_wsp_trace == FALSE) {  /* <allow-wsp-trace> */
     m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW WSP Trace administration command but <allow-wsp-trace> not configured" );
     return;                                /* do nothing              */
   }
   m_hlnew_printf( HLOG_INFO1, "HWSPMnnnI WSP Trace administration command %d.",
                   adsp_wspadm1_qwt1->iec_wawt );
   switch (adsp_wspadm1_qwt1->iec_wawt) {   /* admin WSP Trace definition */
     case ied_wawt_target:                  /* define new target       */
       goto p_adm_target_00;                /* define new target       */
     case ied_wawt_trace_new_ineta_all:     /* trace all INETAs        */
       adsl_wtic_w1 = adss_wtic_active;     /* WSP trace client with INETA control */
       if (adsl_wtic_w1 == NULL) {          /* no WSP trace client with INETA control set */
         adsl_wtic_w2 = (struct dsd_wsp_tr_ineta_ctrl *) malloc( sizeof(struct dsd_wsp_tr_ineta_ctrl) );
         memset( adsl_wtic_w2, 0, sizeof(struct dsd_wsp_tr_ineta_ctrl) );
         adsl_wtic_w2->boc_trace_ineta_all = TRUE;  /* trace all INETAS */
         adsl_wtic_w2->imc_trace_level = adsp_wspadm1_qwt1->imc_trace_level;  /* trace_level */
         adss_wtic_active = adsl_wtic_w2;   /* WSP trace client with INETA control */
         return;                            /* all done                */
       }
       if (adsl_wtic_w1->boc_trace_ineta_all) {  /* trace all INETAS   */
         adsl_wtic_w1->imc_trace_level = adsp_wspadm1_qwt1->imc_trace_level;  /* trace_level */
         return;                            /* all done                */
       }
       adsl_wtic_w2 = (struct dsd_wsp_tr_ineta_ctrl *) malloc( sizeof(struct dsd_wsp_tr_ineta_ctrl) );
       memset( adsl_wtic_w2, 0, sizeof(struct dsd_wsp_tr_ineta_ctrl) );
       adsl_wtic_w2->boc_trace_ineta_all = TRUE;  /* trace all INETAS  */
       adsl_wtic_w2->imc_trace_level = adsp_wspadm1_qwt1->imc_trace_level;  /* trace_level */
       adss_wtic_active = adsl_wtic_w2;     /* WSP trace client with INETA control */
       free( adsl_wtic_w1 );                /* free old control area   */
       return;                              /* all done                */
     case ied_wawt_trace_new_ineta_spec:    /* trace specific INETA    */
       adsl_wtic_w1 = adss_wtic_active;     /* WSP trace client with INETA control */
       if (adsl_wtic_w1 == NULL) {          /* no WSP trace client with INETA control set */
         adsl_wtic_w2 = (struct dsd_wsp_tr_ineta_ctrl *) malloc( sizeof(struct dsd_wsp_tr_ineta_ctrl) + sizeof(struct dsd_wsp_tr_ineta_1) + imp_len_content );
         memset( adsl_wtic_w2, 0, sizeof(struct dsd_wsp_tr_ineta_ctrl) + sizeof(struct dsd_wsp_tr_ineta_1) );
         adsl_wtic_w2->imc_len_inetas = sizeof(struct dsd_wsp_tr_ineta_1) + imp_len_content;  /* length of following INETAs */
#define ADSL_WTIA1_G1 ((struct dsd_wsp_tr_ineta_1 *) (adsl_wtic_w2 + 1))
         ADSL_WTIA1_G1->imc_trace_level = adsp_wspadm1_qwt1->imc_trace_level;  /* trace_level */
         ADSL_WTIA1_G1->usc_family = AF_INET;  /* family IPV4 / IPV6   */
         ADSL_WTIA1_G1->usc_length = imp_len_content;  /* length of following address */
         if (imp_len_content == 16) {       /* IPV6                    */
           ADSL_WTIA1_G1->usc_family = AF_INET6;  /* family IPV4 / IPV6 */
         }
         memcpy( ADSL_WTIA1_G1 + 1, adsp_wspadm1_qwt1 + 1, imp_len_content );
         adss_wtic_active = adsl_wtic_w2;   /* WSP trace client with INETA control */
         return;                            /* all done                */
       }
#undef ADSL_WTIA1_G1
       if (adsl_wtic_w1->boc_trace_ineta_all) {  /* trace all INETAS   */
         return;                            /* all done                */
       }
       /* search if INETA already set                                  */
       achl_cur = (char *) (adsl_wtic_w1 + 1);  /* here start INETAs   */
       achl_end = (char *) (adsl_wtic_w1 + 1) + adsl_wtic_w1->imc_len_inetas;
#define ADSL_WTIA1_G1 ((struct dsd_wsp_tr_ineta_1 *) achl_cur)
       while (achl_cur < achl_end) {
         if (   (imp_len_content == ADSL_WTIA1_G1->usc_length)
             && (!memcmp( ADSL_WTIA1_G1 + 1, adsp_wspadm1_qwt1 + 1, imp_len_content ))) {
           ADSL_WTIA1_G1->imc_trace_level = adsp_wspadm1_qwt1->imc_trace_level;  /* trace_level */
           return;                          /* all done                */
         }
         achl_cur += sizeof(struct dsd_wsp_tr_ineta_1) + ADSL_WTIA1_G1->usc_length;  /* next INETA */
       }
#undef ADSL_WTIA1_G1
       adsl_wtic_w2 = (struct dsd_wsp_tr_ineta_ctrl *) malloc( sizeof(struct dsd_wsp_tr_ineta_ctrl) + adsl_wtic_w1->imc_len_inetas + sizeof(struct dsd_wsp_tr_ineta_1) + imp_len_content );
       memcpy( adsl_wtic_w2, adsl_wtic_w1, sizeof(struct dsd_wsp_tr_ineta_ctrl) + adsl_wtic_w1->imc_len_inetas );
       adsl_wtic_w2->imc_len_inetas = adsl_wtic_w1->imc_len_inetas + sizeof(struct dsd_wsp_tr_ineta_1) + imp_len_content;  /* length of following INETAs */
#define ADSL_WTIA1_G1 ((struct dsd_wsp_tr_ineta_1 *) ((char *) (adsl_wtic_w2 + 1) + adsl_wtic_w1->imc_len_inetas))
       ADSL_WTIA1_G1->imc_trace_level = adsp_wspadm1_qwt1->imc_trace_level;  /* trace_level */
       ADSL_WTIA1_G1->usc_family = AF_INET;  /* family IPV4 / IPV6   */
       ADSL_WTIA1_G1->usc_length = imp_len_content;  /* length of following address */
       if (imp_len_content == 16) {         /* IPV6                    */
         ADSL_WTIA1_G1->usc_family = AF_INET6;  /* family IPV4 / IPV6  */
       }
       memcpy( ADSL_WTIA1_G1 + 1, adsp_wspadm1_qwt1 + 1, imp_len_content );
       adss_wtic_active = adsl_wtic_w2;     /* WSP trace client with INETA control */
       free( adsl_wtic_w1 );                /* free old control area   */
       return;                              /* all done                */
#undef ADSL_WTIA1_G1
     case ied_wawt_trace_del_ineta_all:     /* delete trace all INETAs */
       adsl_wtic_w1 = adss_wtic_active;     /* WSP trace client with INETA control */
       if (adsl_wtic_w1 == NULL) {          /* no WSP trace client with INETA control set */
         return;                            /* all done                */
       }
       adss_wtic_active = NULL;             /* clear WSP trace client with INETA control */
       free( adsl_wtic_w1 );                /* free old control area   */
       return;                              /* all done                */
     case ied_wawt_trace_del_ineta_spec:    /* delete trace specific INETA */
       adsl_wtic_w1 = adss_wtic_active;     /* WSP trace client with INETA control */
       if (adsl_wtic_w1 == NULL) {          /* no WSP trace client with INETA control set */
         return;                            /* all done                */
       }
       if (adsl_wtic_w1->boc_trace_ineta_all) {  /* trace all INETAS   */
         return;                            /* all done                */
       }
       /* search if INETA already set                                  */
       achl_cur = (char *) (adsl_wtic_w1 + 1);  /* here start INETAs   */
       achl_end = (char *) (adsl_wtic_w1 + 1) + adsl_wtic_w1->imc_len_inetas;
#define ADSL_WTIA1_G1 ((struct dsd_wsp_tr_ineta_1 *) achl_cur)
       while (TRUE) {                       /* loop over all INETAs    */
         if (achl_cur >= achl_end) return;  /* INETA not found         */
         if (   (imp_len_content == ADSL_WTIA1_G1->usc_length)
             && (!memcmp( ADSL_WTIA1_G1 + 1, adsp_wspadm1_qwt1 + 1, imp_len_content ))) {
           break;                           /* INETA found             */
         }
         achl_cur += sizeof(struct dsd_wsp_tr_ineta_1) + ADSL_WTIA1_G1->usc_length;  /* next INETA */
       }
       if (   (achl_cur == (char *) (adsl_wtic_w1 + 1))  /* here start INETAs */
           && ((achl_cur + sizeof(struct dsd_wsp_tr_ineta_1) + ADSL_WTIA1_G1->usc_length) >= achl_end)) {
         adss_wtic_active = NULL;           /* clear WSP trace client with INETA control */
         free( adsl_wtic_w1 );              /* free old control area   */
         return;                            /* all done                */
       }
       adsl_wtic_w2 = (struct dsd_wsp_tr_ineta_ctrl *) malloc( sizeof(struct dsd_wsp_tr_ineta_ctrl) - adsl_wtic_w1->imc_len_inetas + sizeof(struct dsd_wsp_tr_ineta_1) - imp_len_content );
       memcpy( adsl_wtic_w2, adsl_wtic_w1, achl_cur - (char *) adsl_wtic_w1 );
#define ACHL_POS_G1 (achl_cur + sizeof(struct dsd_wsp_tr_ineta_1) + ADSL_WTIA1_G1->usc_length)
       if (ACHL_POS_G1 < achl_end) {
         memcpy( (char *) adsl_wtic_w2 + (achl_cur - (char *) adsl_wtic_w1 ),
                 ACHL_POS_G1,
                 sizeof(struct dsd_wsp_tr_ineta_1) + ADSL_WTIA1_G1->usc_length );
       }
       adsl_wtic_w2->imc_len_inetas -= sizeof(struct dsd_wsp_tr_ineta_1) + ADSL_WTIA1_G1->usc_length;
       adss_wtic_active = adsl_wtic_w2;     /* WSP trace client with INETA control */
       free( adsl_wtic_w1 );                /* free old control area   */
       return;                              /* all done                */
#undef ADSL_WTIA1_G1
     case ied_wawt_trace_new_core:          /* new parameters trace WSP core */
       img_wsp_trace_core_flags1 = adsp_wspadm1_qwt1->imc_trace_level;  /* WSP trace core flags */
       break;
   }
   return;

   p_adm_target_00:                         /* define new target       */
   switch (adsp_wspadm1_qwt1->iec_wtt) {    /* WSP Trace target        */
     case ied_wtt_console:                  /* print on console        */
       if (imp_len_content != 0) break;
       goto p_adm_target_20;                /* parameters for target valid */
     case ied_wtt_file_ascii:               /* trace records to file ASCII */
     case ied_wtt_file_bin:                 /* trace records to file binary */
       if (imp_len_content == 0) break;
       goto p_adm_target_20;                /* parameters for target valid */
     case ied_wtt_xyz:                             /* trace records to xyz    */
       break;
   }
   m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW WSP Trace administration command target invalid parameters" );
   return;

   p_adm_target_20:                         /* parameters for target valid */
   adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
   memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
   adsl_wt1_w1->iec_wtrt = ied_wtrt_control;  /* control record        */
   adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
   adsl_wt1_w1->imc_wsp_trace_target = (int) adsp_wspadm1_qwt1->iec_wtt;  /* enum ied_wsp_trace_target / Trace target */
   adsl_wt1_w1->imc_len_filename = imp_len_content;  /* length of following flie-name UTF-8 */
   if (imp_len_content) {                   /* copy content            */
     memcpy( adsl_wt1_w1 + 1, adsp_wspadm1_qwt1 + 1, imp_len_content );
   }
   m_wsp_trace_out( adsl_wt1_w1 );          /* output of WSP trace record */
   return;
} /* end m_ctrl_wspadm1_wsp_trace()                                    */

/* Admin get WSP Trace active settings                                 */
extern "C" struct dsd_sdh_control_1 * m_get_wspadm1_wsp_tr_act( void ) {
   return NULL;
} /* end m_get_wspadm1_wsp_tr_act()                                    */
#endif

/** process VDI-WSP received from other cluster member                 */
extern "C" void m_recv_cluster_vdi( char *achp_ineta, int imp_len_ineta ) {
   char       chrl_ineta_port[ 2 + 16 + 2 ];

   if (   (imp_len_ineta != (4 + 2))        /* not IPV4                */
       && (imp_len_ineta != (16 + 2))) {    /* not IPV6                */
     return;
   }
   chrl_ineta_port[ 0 ] = (unsigned char) (2 + imp_len_ineta);
   chrl_ineta_port[ 1 ] = 0X12;
   memcpy( &chrl_ineta_port[ 2 ], achp_ineta, imp_len_ineta );
   dcl_blasetr_1::m_set_twin_ineta( chrl_ineta_port );
} /* end m_recv_cluster_vdi()                                          */

static inline HL_WCHAR * m_clconn1_gatename( void * ap_conn1 ) {
   return (HL_WCHAR *) (((struct dsd_conn1 *) ap_conn1)->adsc_gate1 + 1);
} /* end m_clconn1_gatename()                                          */

static inline int m_clconn1_sno( void * ap_conn1 ) {
   return ((struct dsd_conn1 *) ap_conn1)->dsc_co_sort.imc_sno;
} /* end m_clconn1_sno()                                               */

static inline char * m_clconn1_chrc_ineta( void * ap_conn1 ) {
   return ((struct dsd_conn1 *) ap_conn1)->chrc_ineta;
} /* end m_clconn1_chrc_ineta()                                        */

#ifdef NOT_YET_120212
static inline void m_clconn1_critsect_enter( void * apdconn1 ) {
   EnterCriticalSection( &((class clconn1 *) apdconn1)->d_act_critsect );
} /* end m_clconn1_critsect_enter()                                    */

static inline void m_clconn1_critsect_leave( void * apdconn1 ) {
   LeaveCriticalSection( &((class clconn1 *) apdconn1)->d_act_critsect );
} /* end m_clconn1_critsect_leave()                                    */
#endif

/** set or clear nagle for TCP sessions                                */
static inline void m_clconn1_naeg1( void * adsp_conn1 ) {
   BOOL       bol_naeg1_disa;               /* disable naegle algorithm */
#define ADSL_CONN1_G ((struct dsd_conn1 *) adsp_conn1)  /* pointer on connection */

   /* first direction to client                                        */
   bol_naeg1_disa = TRUE;                   /* disable naegle algorithm */
   if (ADSL_CONN1_G->adsc_server_conf_1 == NULL) {  /* no configuration server */
     goto p_client_20;                      /* check gate for client   */
   }
   if (ADSL_CONN1_G->adsc_server_conf_1->iec_naeg1_cl == ied_naeg1_yes) {  /* do disable naegle algorithm */
     goto p_client_80;                      /* direction to client set */
   }
   if (ADSL_CONN1_G->adsc_server_conf_1->iec_naeg1_cl == ied_naeg1_no) {  /* do not disable naegle algorithm */
     bol_naeg1_disa = FALSE;                /* disable naegle algorithm */
     goto p_client_80;                      /* direction to client set */
   }

   p_client_20:                             /* check gate for client   */
   if (ADSL_CONN1_G->adsc_gate1->iec_naeg1_cl == ied_naeg1_yes) {  /* do disable naegle algorithm */
     goto p_client_80;                      /* direction to client set */
   }
   if (ADSL_CONN1_G->adsc_gate1->iec_naeg1_cl == ied_naeg1_no) {  /* do not disable naegle algorithm */
     bol_naeg1_disa = FALSE;                /* disable naegle algorithm */
     goto p_client_80;                      /* direction to client set */
   }
   /* both automatic, so take setting of protocol                      */
   if (ADSL_CONN1_G->adsc_server_conf_1 == NULL) {  /* no configuration server */
     goto p_client_80;                      /* direction to client set */
   }
   switch (ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def) {
     case ied_scp_http:                     /* protocol HTTP           */
     case ied_scp_ldap:                     /* protocol LDAP           */
     case ied_scp_hoby:                     /* protocol HOB-Y          */
     case ied_scp_3270:                     /* protocol IBM 3270       */
     case ied_scp_5250:                     /* protocol IBM 5250       */
     case ied_scp_smb:                      /* protocol SMB server message block */
     case ied_scp_soap:                     /* protocol SOAP           */
       bol_naeg1_disa = FALSE;              /* disable naegle algorithm */
       break;
   }

   p_client_80:                             /* direction to client set */
   if (bol_naeg1_disa != ADSL_CONN1_G->dsc_tc1_client.boc_naeg1_disa) {  /* disable naegle algorithm */
     ADSL_CONN1_G->dsc_tc1_client.dsc_tcpco1_1.mc_set_nodelay( (int) bol_naeg1_disa );  /* disable naegle algorithm */
     ADSL_CONN1_G->dsc_tc1_client.boc_naeg1_disa = bol_naeg1_disa;  /* disable naegle algorithm */
   }

   /* second direction to server                                       */
   if (ADSL_CONN1_G->iec_servcotype != ied_servcotype_normal_tcp) return;  /* not normal TCP */
   bol_naeg1_disa = TRUE;                   /* disable naegle algorithm */
   if (ADSL_CONN1_G->adsc_server_conf_1 == NULL) {  /* no configuration server */
     goto p_server_20;                      /* check gate for server   */
   }
   if (ADSL_CONN1_G->adsc_server_conf_1->iec_naeg1_cl == ied_naeg1_yes) {  /* do disable naegle algorithm */
     goto p_server_80;                      /* direction to server set */
   }
   if (ADSL_CONN1_G->adsc_server_conf_1->iec_naeg1_cl == ied_naeg1_no) {  /* do not disable naegle algorithm */
     bol_naeg1_disa = FALSE;                /* disable naegle algorithm */
     goto p_server_80;                      /* direction to server set */
   }

   p_server_20:                             /* check gate for server   */
   if (ADSL_CONN1_G->adsc_gate1->iec_naeg1_cl == ied_naeg1_yes) {  /* do disable naegle algorithm */
     goto p_server_80;                      /* direction to server set */
   }
   if (ADSL_CONN1_G->adsc_gate1->iec_naeg1_cl == ied_naeg1_no) {  /* do not disable naegle algorithm */
     bol_naeg1_disa = FALSE;                /* disable naegle algorithm */
     goto p_server_80;                      /* direction to server set */
   }
   /* both automatic, so take setting of protocol                      */
   if (ADSL_CONN1_G->adsc_server_conf_1 == NULL) {  /* no configuration server */
     goto p_server_80;                      /* direction to server set */
   }
   switch (ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def) {
     case ied_scp_http:                     /* protocol HTTP           */
     case ied_scp_ldap:                     /* protocol LDAP           */
     case ied_scp_hoby:                     /* protocol HOB-Y          */
     case ied_scp_3270:                     /* protocol IBM 3270       */
     case ied_scp_5250:                     /* protocol IBM 5250       */
     case ied_scp_smb:                      /* protocol SMB server message block */
     case ied_scp_soap:                     /* protocol SOAP           */
       bol_naeg1_disa = FALSE;              /* disable naegle algorithm */
       break;
   }

   p_server_80:                             /* direction to server set */
   if (bol_naeg1_disa != ADSL_CONN1_G->dsc_tc1_server.boc_naeg1_disa) {  /* disable naegle algorithm */
     ADSL_CONN1_G->dsc_tc1_server.dsc_tcpco1_1.mc_set_nodelay( (int) bol_naeg1_disa );  /* disable naegle algorithm */
     ADSL_CONN1_G->dsc_tc1_server.boc_naeg1_disa = bol_naeg1_disa;  /* disable naegle algorithm */
   }
   return;                                  /* all done                */

#undef ADSL_CONN1_G                         /* pointer on connection   */
} /* end m_clconn1_naeg1()                                             */

/** routine called by timer thread when the block of the connection has to be freed */
static void m_free_session_b( struct dsd_timer_ele *adsp_timer_ele ) {
   int        iml_rc;                       /* return code             */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_free_session_b( %p ) called",
                   __LINE__, adsp_timer_ele );
#endif
#define ADSL_CONN1_G ((struct dsd_conn1 *) ((char *) adsp_timer_ele - offsetof( struct dsd_conn1, dsc_timer )))
#ifdef D_INCL_HOB_TUN
   if (ADSL_CONN1_G->imc_references) {      /* references to this session */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_free_session_b() ADSL_CONN1_G=%p imc_references=%d - wait again",
                     __LINE__, ADSL_CONN1_G, ADSL_CONN1_G->imc_references );
#endif
     m_time_set( &ADSL_CONN1_G->dsc_timer, FALSE );  /* set timer now  */
     return;                                /* wait once more          */
   }
#endif
   iml_rc = ADSL_CONN1_G->dsc_critsect.m_close();  /* CriticalSection   */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_close() critical section failed %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, iml_rc );
   }
   free( ADSL_CONN1_G );                    /* free the block of the session */
#undef ADSL_CONN1_G
} /* end m_free_session_b()                                            */

#ifndef HL_LINUX
/** get the thread id                                                  */
extern "C" pid_t m_gettid( void ) {
   long int iml_pwtid;

   thr_self( &iml_pwtid );
// iml_pwtid = 999;
   return (pid_t) iml_pwtid;
} /* end m_gettid()                                                    */
#endif
