#define NOT_KB_DIRECT
//#define CRASH_120203_01                     /* crash when 204 - virus checked */
#define DEBUG_110722_01                     /* do not send before connected */
//#define DEBUG_120119_01                     /* check TCP connections   */
#define DEBUG_120119_02                     /* check ied_vat_active    */
#define DEBUG_120120_01                     /* m_check_first_packet()  */
#define DEBUG_120122_01                     /* sending to ICAP stops   */
#define DEBUG_120613_01                     /* remove from chain problem */
#define DEBUG_120619_01                     /* put in chain of active connections */
//#define DEBUG_151027_01                     /* data sent multiple times */
#define TRY_110722_01                       /* check if all connected  */
#define TRY_120120_01                       /* send first record only once */
#define TRY_120124_01                       /* sending to ICAP server stops */
#define TRY_120615_01                       /* send filename multiple times */
#define TRY_120618_01                       /* do not send file-name   */
#define TRY_120619_01                       /* put in chain of adsc_virch_act_ch */
#define TRY_150101_01                       /* more data to send       */
#define D_PROD_A2
#ifndef D_PROD_A2
//#define TRY_090121
#define TRACEHL1
//#define TRACEHL_090912_01
//#define TEST_090927_01                      /* longer timeout          */
//#define CHECK_VC_NOT_OPERATIONAL_01
#endif
//#define HL_DEBUG_02
#ifdef HL_DEBUG_02
#define TRACEHL_P_COUNT
#endif
#ifdef HL_TO_DO
/**
* 24.01.12 KB:
* when sending to ICAP server, the chunk should not be so big;
* maybe up to halve of the window size.
******************
* 25.01.12 KB:
* imc_timeout configured but nowhere used.
* possible solution: calculate maximum of all participation ICAP servers
* and use as timeout for each request.
* 01.12.13 KB
* TIMEOUT_VCH_1 use as timeout
*/
#endif
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xs-gw-serv-vch-icap                                 |*/
/*| -------------                                                     |*/
/*|  Subroutine as Service to Gateways                                |*/
/*|  Virus Checking using ICAP, Internet Content Adaption Protocol    |*/
/*|  KB 10.08.07                                                      |*/
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
   Strategy:
   When a new request is started, all groups are searched for a
   free server. Existing sessions are reused if possible.
   In a group, the servers are checked in a random order.
   It makes no sense to append requests to an existing session that
   is already in use since normally there are sufficent possible
   sessions for each virus checking server.
   When no servers are found immediately, an error is returned.
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
#include <sys/socket.h>
//#include <sys/stropts.h>
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
#ifdef OLD01
#include <HCTHREAD.HPP>
#endif
#include <hob-thread.hpp>
#include <iswcord1.h>
#endif
//#include "hob-hlwspat2.h"
#ifdef B121009
#include <hob-xshlse03.h>
#ifdef CSSSL_060620
#include <hob-xshlcl01.h>
#endif
#endif
#include <hob-xsrerrm1.h>
#define NO_SSL_ERROR_CONTENT
#include "hob-xshlssle.h"
#ifdef B121009
#include "HOBSSLTP.h"
#endif
#ifdef XYZ2
#include <hlwspsu1.h>
#endif

/*+-------------------------------------------------------------------+*/
/*| System and library header files for XERCES.                       |*/
/*+-------------------------------------------------------------------+*/

#ifdef B100518
#define READDISKXML
#include <xercesc/util/PlatformUtils.hpp>
#include <xercesc/parsers/AbstractDOMParser.hpp>
#include <xercesc/dom/DOMImplementation.hpp>
#include <xercesc/dom/DOMImplementationLS.hpp>
#include <xercesc/dom/DOMImplementationRegistry.hpp>
#include <xercesc/dom/DOMBuilder.hpp>
#include <xercesc/dom/DOMException.hpp>
#include <xercesc/dom/DOMDocument.hpp>
#include <xercesc/dom/DOMNodeList.hpp>
#include <xercesc/dom/DOMError.hpp>
#include <xercesc/dom/DOMLocator.hpp>
#include <xercesc/dom/DOMInputSource.hpp>
#include <xercesc/util/BinMemInputStream.hpp>
#else
#include <xercesc/util/XMLString.hpp>
#include <xercesc/dom/DOMNode.hpp>
#include <xercesc/dom/impl/DOMElementImpl.hpp>
#endif
#ifndef HL_UNIX
#include "IBIPGW08-X1.hpp"
#else
#ifdef OLD01
#include "NBIPGW08-X1.hpp"
#else
#include "xs-xml-frame-01.hpp"
#endif
#ifdef OLD01
#ifndef HL_AIX
#include <fstream.h>
#endif
#endif
#endif
#include <hob-netw-01.h>
#ifdef B150729
#ifndef TRY_090121
#include <hob-tcpco1.hpp>
#else
#include "E:\Garkuscha\Tests\tcpcomp_sample\hob-tcpco1.hpp"
#endif
#endif
#ifndef TCPCOMP_V02
#include <hob-tcpco1.hpp>
#endif
#ifdef TCPCOMP_V02
#include <hob-tcpcomp-multi-v02.hpp>
#endif
#include <hob-wspsu1.h>
#include <hob-xsltime1.h>

/*+-------------------------------------------------------------------+*/
/*| header files for Server-Data-Hook.                                |*/
/*+-------------------------------------------------------------------+*/

#define DEF_HL_INCL_DOM
#include "hob-xsclib01.h"

#include "hob-wsppriv.h"                    /* privileges              */
#define HOB_CONTR_TIMER
#include <hob-xslcontr.h>                   /* HOB Control             */
#define D_INCL_CONF
#define NOT_INCLUDED_CLIB
#include "hob-xbipgw08-1.h"
#include "hob-xbipgw08-2.h"
//#include "hob-xbipgw08-3.h"

#ifndef NOT_KB_DIRECT
#ifndef HL_UNIX
#ifndef RUN_ON_KBID
#include "D:\AKBI61\RDPACC\hob-xsrdpvch1.h"
#else
//#include "C:\AKBID1\RDPACC\hob-xsrdpvch1.h"
#include "Q:\AKBID3\RDPACC\hob-xsrdpvch1.h"
#endif
#else
#include "hob-xsrdpvch1.h"
#endif
#else
#include "hob-xsrdpvch1.h"
#endif
//#include "hob-xsrdpvch1.h"

/*+-------------------------------------------------------------------+*/
/*| Precompiler constants.                                            |*/
/*+-------------------------------------------------------------------+*/

#ifndef HL_UNIX
#define D_TCP_ERROR WSAGetLastError()
#define D_TCP_CLOSE closesocket
#else
#define D_TCP_ERROR errno
#define D_TCP_CLOSE close
#endif

#define IP_socket socket
#define IP_bind bind
#define IP_listen listen
#define IP_htons htons
#define IP_getnameinfo getnameinfo

#define CHAR_CR                0X0D         /* carriage-return         */
#define CHAR_LF                0X0A         /* line-feed               */

#ifndef HL_UNIX
#define HL_RET_NUM int
#else
#define HL_RET_NUM long long int
#endif
#define MAX_VCH_SERVERS        16           /* maximum virus checking servers per group */
#ifdef B120125
#ifndef TEST_090927_01
#define TIMEOUT_VCH_1          30           /* timeout virus checking in seconds */
#else
#define TIMEOUT_VCH_1          300          /* timeout virus checking in seconds */
#endif
#else
#define TIMEOUT_VCH_1          120          /* timeout virus checking in seconds */
#define D_ICAP_MAX_SESSION     100          /* default value maximum ICAP connections to this server */
#endif
#ifndef B131201
#define D_RETRY_AFTER_ERROR    300          /* time in seconds to retry after error occured */
#endif
#ifdef XYZ1
#define D_WINDOW_SEND          (64 * 1024)  /* window to send to Virus Checker */
#endif
#define MAX_LEN_H_ICAP         1024         /* maximum length ICAP header */
#define MAX_LEN_H_HTTP         1024         /* maximum length HTTP header */

#ifndef HL_UNIX
#define HL_GET_THREAD GetCurrentThreadId()
#else
//#define HL_GET_THREAD gettid()
// to-do 11.02.12 KB
#define HL_GET_THREAD 0
#endif

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

static void * m_service_open( void *, struct dsd_service_conf_1 *, struct dsd_aux_service_query_1 * );
static BOOL m_service_requ( void *, void *, void * );
static void m_service_close( void *, void * );
static BOOL m_create_active_virch( struct dsd_virch_request * );
static struct dsd_virch_active * m_new_active_virch( struct dsd_se_vcicaphttp_entry * );
#ifndef TRY_110722_01                       /* check if all connected */
static void m_check_first_packet( struct dsd_virch_request * );
#else
static BOOL m_check_first_packet( struct dsd_virch_request * );
#ifdef B150128
static void m_continue_send( struct dsd_virch_request * );
#endif
#ifndef B150128
static void m_continue_send( struct dsd_virch_request *, BOOL );
#endif
#endif
static BOOL m_send_first_packet( struct dsd_virch_active * );
static BOOL m_send_chunk( struct dsd_virch_active *,
                          struct dsd_se_vch_req_1 *,
                          struct dsd_se_vch_req_1 * );
static struct dsd_se_vcicaphttp_entry * m_get_se_random( struct dsd_random_server * );
#ifdef OLD01
static void m_virch_do_connect( struct dsd_virch_active * );
#endif
static void m_virch_cb_conn_err( dsd_tcpcomp *, void *, struct sockaddr *, socklen_t, int, int, int );
#ifdef B121120
static void m_virch_conncallback( dsd_tcpcomp *, void *, struct sockaddr *, socklen_t, int );  /* connect callback function */
#else
static void m_virch_conncallback( dsd_tcpcomp *, void *, struct dsd_target_ineta_1 *, void *, struct sockaddr *, socklen_t, int );  /* connect callback function */
#endif
static void m_virch_sendcallback( dsd_tcpcomp *, void * );  /* send callback function */
static int m_virch_getrecvbuf( dsd_tcpcomp *, void *, void **, char **, int ** );  /* get receive buffer callback function */
static int m_virch_recvcallback( dsd_tcpcomp *, void *, void * );  /* receive callback function */
static void m_virch_errorcallback( dsd_tcpcomp *, void *, char *, int, int );  /* error callback function */
static void m_virch_cleanup( dsd_tcpcomp *, void * );  /* cleanup callback function */
static void m_virch_timer( struct dsd_timer_ele * );
static void m_virch_free( struct dsd_timer_ele * );
static char * m_put_no( char *, int );      /* output number           /*

/*+-------------------------------------------------------------------+*/
/*| global used dsects = structures.                                  |*/
/*+-------------------------------------------------------------------+*/

enum ied_vchact_receive_st {                /* active connection receive status */
   ied_var_invalid = 0,                     /* does not wait for receive data */
   ied_var_start,                           /* start of receive data   */
   ied_var_rec_http,                        /* receive HTTP            */
   ied_var_pxyzt,                           /* start of receive data   */
   ied_var_no_virus,                        /* file does not contain virus */
#ifdef NONSENSE_120119
   ied_var_virus_found,                     /* file contains virus     */
#ifdef B120119
   ied_var_closed                           /* TCP session is closed - nonsense 24.07.08 KB */
#else
   ied_var_closed                           /* TCP session is closed - can remove connection */
#endif
#else
   ied_var_virus_found                      /* file contains virus     */
#endif
// ied_var_xyz                              /* ???                     */
};

enum ied_vchact_tcp_st {                    /* active connection TCP session status */
   ied_vat_invalid = 0,                     /* invalid status          */
   ied_vat_w_conn,                          /* wait for connect        */
   ied_vat_active,                          /* TCP session active      */
   ied_vat_wait_close,                      /* TCP session wait for close */
   ied_vat_closed                           /* TCP session is closed   */
};

enum ied_vch_vendor_def {                   /* virus checker vendor    */
   ied_vve_invalid = 0,                     /* vendor not defined      */
   ied_vve_kasp = 1,                        /* Kaspersky               */
   ied_vve_syman = 2,                       /* Symantec                */
   ied_vve_c_icap = 3                       /* c-icap                  */
};

enum ied_vch_reuse_def {                    /* virus checker reuse     */
   ied_vvr_reuse = 0,                       /* reuse TCP connection    */
   ied_vve_wait_close,                      /* wait for close          */
   ied_vve_do_close                         /* do close                */
};

struct dsd_se_vcicaphttp_conf {             /* definition service configuration */
   struct dsd_se_vcicaphttp_group *adsc_sg_ch;  /* chain server-group  */
   int        imc_need_ch_no_g;             /* number of groups that need to check */
};

struct dsd_se_vcicaphttp_group {            /* definition server-group */
   struct dsd_se_vcicaphttp_group *adsc_next;  /* next entry in chain  */
   struct dsd_se_vcicaphttp_conf *adsc_virch_conf;  /* this service configuration */
   char       *achc_name;                   /* address name UTF-8      */
   int        imc_len_name;                 /* length of name bytes    */
   int        imc_no_vch_se;                /* number of server entries */
   BOOL       boc_must_check;               /* this group must check   */
   struct dsd_se_vcicaphttp_entry *adsc_se_ch;  /* chain server-entry  */
};

struct dsd_se_vcicaphttp_entry {            /* definition server-entry */
   struct dsd_se_vcicaphttp_entry *adsc_next;  /* next entry in chain  */
   struct dsd_se_vcicaphttp_group *adsc_sg_this;  /* this server group */
   char       *achc_name;                   /* address name UTF-8      */
   int        imc_len_name;                 /* length of name bytes    */
   struct dsd_bind_ineta_1 dsc_bind_multih;  /* for bind multihomed    */
   struct dsd_target_ineta_1 *adsc_server_ineta;  /* LDAP-Server INETA */
   int        imc_port;                     /* Port TCP LDAP-Server    */
   int        imc_max_session;              /* maximum parallel sessions */
   int        imc_timeout;                  /* timeout in seconds      */
   int        imc_retry_ae;                 /* retry-after-error in seconds */
   int        imc_time_retry;               /* time next retry         */
   enum ied_vch_vendor_def iec_vve;         /* virus checker vendor    */
   enum ied_vch_reuse_def iec_vvr;          /* virus checker reuse     */
#ifdef OLD01
   BOOL       boc_close_after_scan;         /* this virus checker closes after each scan */
#endif
   int        imc_trace_level;              /* trace-level             */
   int        imc_stat_no_recv;             /* statistic number of receives */
   int        imc_stat_no_conn_failed;      /* statistic number of connects failed */
   int        imc_stat_no_conn_ok;          /* statistic number of connects succeeded */
   int        imc_stat_no_send;             /* statistic number of sends */
   HL_LONGLONG ilc_stat_len_recv;           /* statistic length of receives */
   HL_LONGLONG ilc_stat_len_send;           /* statistic length of sends */
   struct dsd_virch_active *adsc_virch_act;  /* active virus checking connection */
};

struct dsd_virch_session {                  /* virus checking bound to session */
   struct dsd_virch_request *adsc_virch_req_ch;  /* chain of virus checking requests */
   struct dsd_se_vcicaphttp_conf *adsc_virch_conf;  /* service configuration */
   int        imc_signal;                   /* signal to set           */
// 14.04.16 KB - changed
#ifdef ORIG_WSP_V24
   struct dsd_conn1 *adsc_conn1;                  /* connection              */
#else
   void *     adsc_conn1;                   /* connection              */
#endif
   HL_LONGLONG ilc_stat_len_send;           /* statistic length of sends */
};

struct dsd_virch_request {                  /* virus checking request  */
   struct dsd_virch_request *adsc_next;     /* next in chain           */
   struct dsd_virch_session *adsc_virch_session;  /* virus checking bound to session */
   void *     ac_control_area;              /* control area request    */
   struct dsd_virch_active *adsc_virch_act_ch;  /* chain active virus checking connections */
   BOOL       boc_send_active;              /* send is active          */
#ifdef TRY_120120_01                        /* send first record only once */
   BOOL       boc_first_record;             /* first record has been sent */
#endif
   struct dsd_timer_ele dsc_timer_ele;      /* timer element           */
};

struct dsd_virch_active {                   /* active virus checking connection */
   struct dsd_virch_active *adsc_se_next;   /* next in chain server entry */
   struct dsd_se_vcicaphttp_entry *adsc_sevirch_entry;  /* server entry */
   struct dsd_virch_request *adsc_virch_requ;  /* virus checking request */
   struct dsd_virch_active *adsc_requ_next;  /* next in chain for this request */
#ifdef OLD01
   int        imc_ind_conn;                 /* index of last connect   */
#endif
// 08.07.08 KB
#ifdef XYZ1
   BOOL       boc_wait_recv;                /* wait for receive data   */
#endif
   ied_vchact_tcp_st iec_vat;               /* active connection TCP session status */
   ied_vchact_receive_st iec_var;           /* active connection receive status */
   void *     ac_send_buf;                  /* current send buffer     */
#ifdef XYZ1
// ied_clr_stat iec_clr_stat;               /* state of connection     */
   HL_LONGLONG ilc_epoch_started;           /* time WSP started        */
   char       *achc_server_name;            /* server name in UTF-8    */
   char       *achc_config_name;            /* configuration name in UTF-8 */
   int        imc_len_server_name;          /* length server name      */
   int        imc_len_config_name;          /* length configuration name */
   int        imc_pid;                      /* process id              */
#endif
#ifdef XYZ1
   struct dsd_virch_remote *adsc_clrem;     /* cluster remote structure */
#endif
   struct dsd_virch_recv *adsc_recv_ch;     /* chain of received buffers */
#ifdef XYZ1
   struct dsd_virch_send *adsc_send_ch;     /* chain of send buffers   */
   int        imc_skip_recv_data;           /* length to skip received data */
   BOOL       boc_redirect;                 /* is redirected           */
// int        imc_ind_conn;                 /* index of last connect   */
   int        imc_count_recv_b;             /* count receive blocks outstanding */
#endif
   struct sockaddr_storage dsc_soa;         /* sockaddr for connect    */
   class dsd_tcpcomp dsc_tcpcomp;           /* data of connection      */
#ifdef XYZ1
   int        imc_stat_no_recv;             /* statistic number of receives */
   int        imc_stat_no_send;             /* statistic number of sends */
   HL_LONGLONG ilc_stat_len_recv;           /* statistic length of receives */
   HL_LONGLONG ilc_stat_len_send;           /* statistic length of sends */
   void *     vpc_cma_entry;                /* field for CMA entry     */
   void *     vpc_special_1;                /* special field one       */
#endif
   char       chrc_ineta[ LEN_DISP_INETA ];  /* internet-address char  */
};

struct dsd_virch_recv {                     /* block received from virus checker */
   struct dsd_virch_active *adsc_vchact;    /* active virus checker    */
   struct dsd_virch_recv *adsc_next;        /* for chaining            */
   char       *achc_processed;              /* processed so far        */
   int        imc_len_recv;                 /* length received         */
   int        imc_usage_count;              /* usage count             */
};

#ifdef XYZ1
struct dsd_virch_proc_recv {              /* process block received from cluster member */
   struct dsd_virch_active *adsc_vchact;    /* active virus checker    */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* gather input data       */
   int        imc_data_length;              /* length of received data */
   int        imc_no_recv_bl;               /* number of receive blocks */
};
#endif

struct dsd_virch_send {                     /* send to virus checker structure */
   struct dsd_virch_active *adsc_vchact;    /* active virus checker    */
   void (* amc_compl) ( struct dsd_virch_send * );  /* completition routine */
   void *     vpc_userfld;                  /* userfield calling program */
   ied_cl_type iec_cl_type;                 /* cluster data type       */
   struct dsd_gather_i_1 *adsc_gai1_send;   /* gather input data to send */
   /* the following fields are needed by the send routine              */
   struct dsd_virch_send *adsc_next;      /* next in chain, send routine */
   void *     vprc_work_area[8];            /* work area for send routine */
};

struct dsd_random_server {                  /* search server in random order */
   struct dsd_se_vcicaphttp_entry *adsrc_checked[ MAX_VCH_SERVERS ];  /* array with maximum virus checking servers per group */
   int        imc_no_checked;               /* number of already checked servers */
   struct dsd_se_vcicaphttp_group *adsc_sg;  /* server-group           */
};

/*+-------------------------------------------------------------------+*/
/*| Internal used classes.                                            |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

extern class dsd_hcla_critsect_1 dsg_global_lock;  /* global lock      */

#ifdef TRACEHL_090912_01
extern BOOL   bog_trace_v1;                 /* variable for debugging  */
#endif

extern "C" int img_wsp_trace_core_flags1;   /* WSP trace core flags    */

/* 24.12.07 KB */
static struct dsd_virch_active *adss_virch_active_anchor = NULL;  /* chain of active virus checking connections */

#ifdef DEBUG_151027_01                      /* data sent multiple times */
static struct dsd_se_vch_req_1 *adss_vchreq1_debug_1 = NULL;
#endif

static const char * achrs_node_01_entry[] = {  /* for section 01       */
   "name",
   "type",
   "server-group",
   "min-check-no-groups"
};

#define DEF_XML_01_NAME                1
#define DEF_XML_01_TYPE                2
#define DEF_XML_01_SERVER_GROUP        3
#define DEF_XML_01_MIN_CHNOG           4

static const char * achrs_node_sg_entry[] = {  /* for section server-group */
   "name",
   "server-entry",
   "must-check"
};

#define DEF_XML_SG_NAME                1
#define DEF_XML_SG_SERVER_ENTRY        2
#define DEF_XML_SG_MUST_CHECK          3

static const char * achrs_node_se_entry[] = {  /* for section server-entry */
   "name",
   "serverineta",
   "serverport",
   "gate-ineta",
   "max-session",
   "timeout",
   "retry-after-error",
   "trace-level",
   "vendor"
};

#define DEF_XML_SE_NAME                1
#define DEF_XML_SE_SERVER_INETA        2
#define DEF_XML_SE_SERVER_PORT         3
#define DEF_XML_SE_GATE_INETA          4
#define DEF_XML_SE_MAX_SESSION         5
#define DEF_XML_SE_TIMEOUT             6
#define DEF_XML_SE_RETRY_AE            7
#define DEF_XML_SE_TRACE_LEVEL         8
#define DEF_XML_SE_VENDOR              9

static const char * achrs_vendor_name[] = {  /* virus checker vendor name */
   "Kaspersky",
   "Symantec",
   "c-icap"
};

static struct dsd_tcpcallback dss_virch_tcpco1_cb1 = {
   &m_virch_cb_conn_err,                    /* connect error callback function */
   &m_virch_conncallback,                   /* connect callback function */
   &m_virch_sendcallback,                   /* send callback function  */
   &m_virch_getrecvbuf,                     /* get receive buffer callback function */
   &m_virch_recvcallback,                   /* receive callback function */
   &m_virch_errorcallback,                  /* error callback function */
   &m_virch_cleanup,                        /* cleanup callback function */
   &m_get_random_number
};

static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

static const unsigned char ucrs_icap_rm_kasp_00[] = {
   'R', 'E', 'S', 'P', 'M', 'O', 'D', ' ',
   'i', 'c', 'a', 'p', ':', '/', '/'
};

static const unsigned char ucrs_icap_rm_kasp_01[] = {
   '/', 'a', 'v', '/', 'r', 'e', 's', 'p', 'm', 'o', 'd',
   ' ', 'I', 'C', 'A', 'P', '/', '1', '.', '0', CHAR_CR, CHAR_LF,
   'H', 'o', 's', 't', ':', ' '
};

static const unsigned char ucrs_icap_rm_syman_00[] = {
   'R', 'E', 'S', 'P', 'M', 'O', 'D', ' ',
   'i', 'c', 'a', 'p', ':', '/', '/',
   'S', 'Y', 'M', 'A', 'N', 'T', 'E', 'X',
   '/',
   'S', 'Y', 'M', 'C', 'S', 'c', 'a', 'n',
   'R', 'e', 's', 'p', '-', 'A', 'V', ' ',
   'I', 'C', 'A', 'P', '/', '1', '.', '0', CHAR_CR, CHAR_LF,
   'H', 'o', 's', 't', ':', ' '
};

static const unsigned char ucrs_icap_rm_c_icap_00[] = {
   'R', 'E', 'S', 'P', 'M', 'O', 'D', ' ',
   'i', 'c', 'a', 'p', ':', '/', '/'
};

static const unsigned char ucrs_icap_rm_c_icap_01[] = {
   '/', 's', 'r', 'v', '_', 'c', 'l', 'a',
   'm', 'a', 'v', '?', 'a', 'l', 'l', 'o',
   'w', '2', '0', '4', '=', 'o', 'n', '&',
   'f', 'o', 'r', 'c', 'e', '=', 'o', 'n',
   '&', 's', 'i', 'z', 'e', 'l', 'i', 'm',
   'i', 't', '=', 'o', 'f', 'f', '&', 'm',
   'o', 'd', 'e', '=', 's', 'i', 'm', 'p',
   'l', 'e', ' ', 'I', 'C', 'A', 'P', '/',
   '1', '.', '0',
   CHAR_CR, CHAR_LF,
   'H', 'o', 's', 't', ':', ' '
};

static const unsigned char ucrs_icap_vn_c_icap_00[] = {  /* c-icap Virus Name */
   'f', 'i', 'l', 'e', ' ', 't', 'h', 'a',
   't', ' ', 'c', 'o', 'n', 't', 'a', 'i',
   'n', ' ', 't', 'h', 'e', ' ',
   'v', 'i', 'r', 'u', 's', '<', 'b', 'r', '>', CHAR_LF
};

static const unsigned char ucrs_icap_rm_02[] = {
   CHAR_CR, CHAR_LF,
   'C', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n', ':', ' ',
   'k', 'e', 'e', 'p', '-', 'a', 'l', 'i', 'v', 'e',
   CHAR_CR, CHAR_LF,
   'A', 'l', 'l', 'o', 'w', ':', ' ', '2', '0', '4',
   CHAR_CR, CHAR_LF,
   'E', 'n', 'c', 'a', 'p', 's', 'u', 'l', 'a', 't', 'e', 'd', ':', ' ',
   'r', 'e', 'q', '-', 'h', 'd', 'r', '=', '0', ',', ' ',
   'r', 'e', 's', '-', 'h', 'd', 'r', '='
};

static const unsigned char ucrs_icap_rm_03[] = {
   ',', ' ', 'r', 'e', 's', '-', 'b', 'o', 'd', 'y', '='
};

static const unsigned char ucrs_icap_rm_04[] = {
   CHAR_CR, CHAR_LF,
   CHAR_CR, CHAR_LF,
   'G', 'E', 'T', ' '
};

static const unsigned char ucrs_icap_rm_05[] = {
   ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1',
   CHAR_CR, CHAR_LF,
   'H', 'o', 's', 't', ':', ' ',
   'w', 'w', 'w', '.', 'h', 'o', 'b', 's', 'o', 'f', 't', '.', 'c', 'o', 'm',
   CHAR_CR, CHAR_LF,
   'A', 'c', 'c', 'e', 'p', 't', ':', ' ',
   't', 'e', 'x', 't', '/', 'h', 't', 'm', 'l', ',', ' ',
   't', 'e', 'x', 't', '/', 'p', 'l', 'a', 'i', 'n', ',', ' ',
   'i', 'm', 'a', 'g', 'e', '/', 'g', 'i', 'f',
   CHAR_CR, CHAR_LF,
   'A', 'c', 'c', 'e', 'p', 't', '-', 'E', 'n', 'c', 'o', 'd', 'i', 'n', 'g', ':', ' ',
   'g', 'z', 'i', 'p', ',', ' ',
   'c', 'o', 'm', 'p', 'r', 'e', 's', 's',
   CHAR_CR, CHAR_LF,
   CHAR_CR, CHAR_LF,
   'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ',
   '2', '0', '0', ' ', 'O', 'K',
   CHAR_CR, CHAR_LF,
   'D', 'a', 't', 'e', ':', ' '
};

static const unsigned char ucrs_icap_rm_06[] = {
   CHAR_CR, CHAR_LF,
   'S', 'e', 'r', 'v', 'e', 'r', ':', ' ',
   'H', 'O', 'B', ' ', 'W', 'S', 'P',
   CHAR_CR, CHAR_LF,
   'C', 'o', 'n', 't', 'e', 'n', 't', '-',
   'T', 'y', 'p', 'e', ':', ' ',
   'f', 'i', 'l', 'e',
   CHAR_CR, CHAR_LF,
   'T', 'r', 'a', 'n', 's', 'f', 'e', 'r', '-',
   'E', 'n', 'c', 'o', 'd', 'i', 'n', 'g', ':', ' ',
   'c', 'h', 'u', 'n', 'k', 'e', 'd',
   CHAR_CR, CHAR_LF,
   CHAR_CR, CHAR_LF
};

static const unsigned char ucrs_icap_last[] = {
   '0',
   CHAR_CR, CHAR_LF,
   CHAR_CR, CHAR_LF
};

/*+-------------------------------------------------------------------+*/
/*| Procedure section.                                                |*/
/*+-------------------------------------------------------------------+*/

/** process the XML configuration section                              */
extern "C" struct dsd_service_conf_1 * m_service_vc_icap_http_conf( DOMNode *adsp_domnode,
                                             void * (* amp_call_dom) ( DOMNode *, ied_hlcldom_def ),   /* call DOM */
                                             HL_WCHAR * awcp_se_name ) {
   int        iml1, iml2;                   /* working variables       */
   BOOL       bol1, bol2;                   /* working variables       */
   char       *achl_w1, *achl_w2;           /* working variables       */
   BOOL       bol_sg_must_check;            /* parameter has been set  */
   int        iml_entry;                    /* entry in table          */
   int        iml_count_sg;                 /* count server-groups     */
   DOMNode    *adsl_node_01;                /* node for navigation     */
   DOMNode    *adsl_node_02;                /* node for navigation     */
   DOMNode    *adsl_node_03;                /* node for navigation     */
   DOMNode    *adsl_node_04;                /* node for navigation     */
   DOMNode    *adsl_node_save_02;           /* save node for navigation */
   DOMNode    *adsl_node_save_03;           /* save node for navigation */
   DOMNode    *adsl_node_sg_name;           /* server-group name       */
   DOMNode    *adsl_node_se_name;           /* server-entry name       */
   HL_WCHAR   *awcl_01_name;                /* name stage 01           */
   HL_WCHAR   *awcl_02_name;                /* name stage 02           */
   HL_WCHAR   *awcl_03_name;                /* name stage 03           */
   HL_WCHAR   *awcl_01_value;               /* value stage 01          */
   HL_WCHAR   *awcl_02_value;               /* value stage 02          */
   HL_WCHAR   *awcl_03_value;               /* value stage 03          */
   HL_WCHAR   *awcl_sg_name;                /* name of server-group    */
   HL_WCHAR   *awcl_se_name;                /* name of server-entry    */
   HL_WCHAR   *awcl_se_server_ineta;        /* server-entry serverineta */
   HL_WCHAR   *awcl_se_gate_ineta;          /* server-entry gate-ineta */
   struct dsd_se_vcicaphttp_group *adsl_sg_w1;  /* definition server-group */
   struct dsd_se_vcicaphttp_entry *adsl_se_w1;  /* definition server-entry */
   struct dsd_se_vcicaphttp_entry *adsl_se_w2;  /* definition server-entry */
   struct dsd_se_vcicaphttp_entry *adsl_se_w3;  /* definition server-entry */
   struct dsd_service_conf_1 *adsl_service_c1;  /* definition service configuration */
   struct dsd_se_vcicaphttp_conf dsl_conf_fill;  /* definition service configuration */
   struct dsd_se_vcicaphttp_group dsl_sg_fill;  /* definition server-group */
   struct dsd_se_vcicaphttp_entry dsl_se_fill;  /* definition server-entry */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_service_vc_icap_http_conf() l%05d adsp_domnode %p amp_call_dom %p name %(ux)s",
                   __LINE__, adsp_domnode, amp_call_dom, awcp_se_name );
#endif
   /* getFirstChild()                                                  */
   adsl_node_01 = (DOMNode *) amp_call_dom( adsp_domnode,
                                            ied_hlcldom_get_first_child );
   if (adsl_node_01 == NULL) {
     m_hlnew_printf( HLOG_XYZ1, "m_service_vc_icap_http_conf() l%05d no getFirstChild()", __LINE__ );
     return NULL;
   }
   memset( &dsl_conf_fill, 0, sizeof(struct dsd_se_vcicaphttp_conf) );  /* definition service configuration */
   iml_count_sg = 0;                        /* reset count server-groups */

   p_serv_20:                               /* process DOM node service */
   if (((HL_RET_NUM) amp_call_dom( adsl_node_01, ied_hlcldom_get_node_type ))
         != DOMNode::ELEMENT_NODE) {
     goto p_serv_80;                        /* get next sibling        */
   }
   awcl_01_name = (HL_WCHAR *) amp_call_dom( adsl_node_01, ied_hlcldom_get_node_name );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d found node %(ux)s", __LINE__, awcl_01_name );
#endif
   iml_entry = sizeof(achrs_node_01_entry) / sizeof(achrs_node_01_entry[0]);
   while (TRUE) {                           /* loop over possible values */
     if (iml_entry == 0) {                   /* value not found in table */
       m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0000W Error service Virus-Checking-ICAP-HTTP entry %(ux)s invalid node found \"%(ux)s\" - ignored",
                       awcp_se_name, awcl_01_name );
       goto p_serv_80;                      /* get next node on stage 1 */
     }
     iml_entry--;                           /* decrement index         */
     bol1 = m_cmp_u16z_u8z( &iml1, awcl_01_name, (char *) achrs_node_01_entry[ iml_entry ] );
     if ((bol1) && (iml1 == 0)) {           /* strings are equal       */
       break;
     }
   }
   switch (iml_entry) {                     /* keyword found           */
     case (DEF_XML_01_SERVER_GROUP - 1):
       goto p_conf_sg_00;                   /* start process server-group */
     case (DEF_XML_01_MIN_CHNOG - 1):
       break;
     default:
       goto p_serv_80;                      /* get next node on stage 1 */
   }
   adsl_node_02 = (DOMNode *) amp_call_dom( adsl_node_01,
                                            ied_hlcldom_get_first_child );
   if (adsl_node_02 == NULL) {              /* no child found          */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0001W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s name \"%(ux)s\" has no child - ignored",
                     awcp_se_name, awcl_01_name );
     goto p_serv_80;                        /* get next node on stage 1 */
   }
   do {
     if (((HL_RET_NUM) amp_call_dom( adsl_node_02, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) {
       awcl_01_value = (HL_WCHAR *) amp_call_dom( adsl_node_02, ied_hlcldom_get_node_value );
       break;
     }
     adsl_node_02 = (DOMNode *) amp_call_dom( adsl_node_02,
                                              ied_hlcldom_get_next_sibling );
   } while (adsl_node_02);                  /* for all siblings        */
   if (adsl_node_02 == NULL) {              /* no text found           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0002W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s name \"%(ux)s\" no TEXT_NODE found - ignored",
                     awcp_se_name, awcl_01_name );
     goto p_serv_80;                        /* get next node on stage 1 */
   }
   if (dsl_conf_fill.imc_need_ch_no_g > 0) {  /* value already defined */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0003W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s name \"%(ux)s\" double - ignored",
                     awcp_se_name, awcl_01_name );
     goto p_serv_80;                        /* get next node on stage 1 */
   }
   dsl_conf_fill.imc_need_ch_no_g = m_get_wc_number( awcl_01_value );
   if (dsl_conf_fill.imc_need_ch_no_g > 0) {  /* value valid           */
     goto p_serv_80;                        /* get next node on stage 1 */
   }
   dsl_conf_fill.imc_need_ch_no_g = 0;      /* set not valid           */
   m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0004W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s min-check-no-groups value \"%(ux)s\" not valid - ignored",
                   awcp_se_name, awcl_01_value );
   goto p_serv_80;                          /* get next node on stage 1 */

   p_conf_sg_00:                            /* start process server-group */
   adsl_node_02 = (DOMNode *) amp_call_dom( adsl_node_01,
                                            ied_hlcldom_get_first_child );
   if (adsl_node_02 == NULL) {              /* no child found          */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0005W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s name \"%(ux)s\" has no child - ignored",
                     awcp_se_name, awcl_01_name );
     goto p_serv_80;                        /* get next node on stage 1 */
   }
   adsl_node_save_02 = adsl_node_02;        /* save node for navigation */
   /* search name first                                                */
   adsl_node_sg_name = NULL;                /* clear name of server-group */
   do {
     if (((HL_RET_NUM) amp_call_dom( adsl_node_02, ied_hlcldom_get_node_type ))
           == DOMNode::ELEMENT_NODE) {
       awcl_02_name = (HL_WCHAR *) amp_call_dom( adsl_node_02, ied_hlcldom_get_node_name );
       bol1 = m_cmp_u16z_u8z( &iml1, awcl_02_name, "name" );
       if ((bol1) && (iml1 == 0)) {         /* strings are equal       */
         if (adsl_node_sg_name) {           /* name already defined    */
           m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0006W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group name double - ignored",
                           awcp_se_name );
         } else {
           adsl_node_sg_name = adsl_node_02;  /* save name             */
         }
       }
     }
     adsl_node_02 = (DOMNode *) amp_call_dom( adsl_node_02,
                                              ied_hlcldom_get_next_sibling );
   } while (adsl_node_02);
   if (adsl_node_sg_name == NULL) {         /* no name found           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0007W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group has no name - ignored",
                     awcp_se_name );
     goto p_serv_80;                        /* get next node on stage 1 */
   }
   /* retrieve name                                                    */
   adsl_node_03 = (DOMNode *) amp_call_dom( adsl_node_sg_name,
                                            ied_hlcldom_get_first_child );
   if (adsl_node_03 == NULL) {              /* no child found          */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0008W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group name \"name\" has no child - ignored",
                     awcp_se_name );
     goto p_serv_80;                        /* get next node on stage 1 */
   }
   do {
     if (((HL_RET_NUM) amp_call_dom( adsl_node_03, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) {
       awcl_sg_name = (HL_WCHAR *) amp_call_dom( adsl_node_03, ied_hlcldom_get_node_value );
       break;
     }
     adsl_node_03 = (DOMNode *) amp_call_dom( adsl_node_03,
                                              ied_hlcldom_get_next_sibling );
   } while (adsl_node_03);                  /* for all siblings        */
   if (adsl_node_03 == NULL) {              /* no text found           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0009W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group name \"name\" no TEXT_NODE found - ignored",
                     awcp_se_name );
     goto p_serv_80;                        /* get next node on stage 1 */
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d found server-group name %(ux)s", __LINE__, awcl_sg_name );
#endif

   adsl_node_02 = adsl_node_save_02;        /* restore node for navigation */
   memset( &dsl_sg_fill, 0, sizeof(struct dsd_se_vcicaphttp_group) );  /* clear definition server-group */
   bol_sg_must_check = FALSE;               /* reset parameter has been set */

   p_conf_sg_20:                            /* process DOM node server-group */
   if (((HL_RET_NUM) amp_call_dom( adsl_node_02, ied_hlcldom_get_node_type ))
         != DOMNode::ELEMENT_NODE) {
     goto p_conf_sg_80;                     /* get next sibling        */
   }
   awcl_02_name = (HL_WCHAR *) amp_call_dom( adsl_node_02, ied_hlcldom_get_node_name );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d found node %(ux)s", __LINE__, awcl_02_name );
#endif
   iml_entry = sizeof(achrs_node_sg_entry) / sizeof(achrs_node_sg_entry[0]);
   while (TRUE) {                           /* loop over possible values */
     if (iml_entry == 0) {                   /* value not found in table */
       m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0010W Error service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s invalid node found \"%(ux)s\" - ignored",
                       awcp_se_name, awcl_sg_name, awcl_02_name );
       goto p_conf_sg_80;                   /* DOM node server-group processed - next */
     }
     iml_entry--;                            /* decrement index         */
     bol1 = m_cmp_u16z_u8z( &iml1, awcl_02_name, (char *) achrs_node_sg_entry[ iml_entry ] );
     if ((bol1) && (iml1 == 0)) {           /* strings are equal       */
       break;
     }
   }
   switch (iml_entry) {                     /* keyword found           */
     case (DEF_XML_SG_SERVER_ENTRY - 1):
       goto p_conf_sg_40;                   /* process server-entry    */
     case (DEF_XML_SG_MUST_CHECK - 1):
       break;
     default:
       goto p_conf_sg_80;                   /* DOM node server-group processed - next */
   }
   adsl_node_03 = (DOMNode *) amp_call_dom( adsl_node_02,
                                            ied_hlcldom_get_first_child );
   if (adsl_node_03 == NULL) {              /* no child found          */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0011W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s name \"%(ux)s\" has no child - ignored",
                     awcp_se_name, awcl_sg_name, awcl_02_name );
     goto p_conf_sg_80;                     /* DOM node server-group processed - next */
   }
   do {
     if (((HL_RET_NUM) amp_call_dom( adsl_node_03, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) {
       awcl_02_value = (HL_WCHAR *) amp_call_dom( adsl_node_03, ied_hlcldom_get_node_value );
       break;
     }
     adsl_node_03 = (DOMNode *) amp_call_dom( adsl_node_03,
                                              ied_hlcldom_get_next_sibling );
   } while (adsl_node_03);                  /* for all siblings        */
   if (adsl_node_03 == NULL) {              /* no text found           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0012W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s name \"%(ux)s\" no TEXT_NODE found - ignored",
                     awcp_se_name, awcl_sg_name, awcl_02_name );
     goto p_conf_sg_80;                     /* DOM node server-group processed - next */
   }
   if (bol_sg_must_check) {                 /* parameter has been already been set */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0013W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s name \"%(ux)s\" double - ignored",
                     awcp_se_name, awcl_sg_name, awcl_02_name );
     goto p_conf_sg_80;                     /* DOM node server-group processed - next */
   }
   bol1 = m_cmp_u16z_u8z( &iml1, awcl_02_value, "YES" );
   if ((bol1) && (iml1 == 0)) {             /* strings are equal       */
     dsl_sg_fill.boc_must_check = TRUE;     /* this group must check   */
     bol_sg_must_check = TRUE;              /* parameter has been set  */
     goto p_conf_sg_80;                     /* DOM node server-group processed - next */
   }
   bol1 = m_cmp_u16z_u8z( &iml1, awcl_02_value, "NO" );
   if ((bol1) && (iml1 == 0)) {             /* strings are equal       */
     bol_sg_must_check = TRUE;              /* parameter has been set  */
     goto p_conf_sg_80;                     /* DOM node server-group processed - next */
   }
   m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0014W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s name \"%(ux)s\" value \"%(ux)s\" neither NO nor YES - ignored",
                   awcp_se_name, awcl_sg_name, awcl_02_name, awcl_02_value );
   goto p_conf_sg_80;                       /* DOM node server-group processed - next */

   p_conf_sg_40:                            /* process server-entry    */
   adsl_node_03 = (DOMNode *) amp_call_dom( adsl_node_02,
                                            ied_hlcldom_get_first_child );
   if (adsl_node_03 == NULL) {              /* no child found          */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0015W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s name \"%(ux)s\" has no child - ignored",
                     awcp_se_name, awcl_sg_name, awcl_02_name );
     goto p_conf_sg_80;                     /* DOM node server-group processed - next */
   }
   adsl_node_save_03 = adsl_node_03;        /* save node for navigation */
   /* search name first                                                */
   adsl_node_se_name = NULL;                /* clear name of server-entry */
   do {
     if (((HL_RET_NUM) amp_call_dom( adsl_node_03, ied_hlcldom_get_node_type ))
           == DOMNode::ELEMENT_NODE) {
       awcl_03_name = (HL_WCHAR *) amp_call_dom( adsl_node_03, ied_hlcldom_get_node_name );
       bol1 = m_cmp_u16z_u8z( &iml1, awcl_03_name, "name" );
       if ((bol1) && (iml1 == 0)) {         /* strings are equal       */
         if (adsl_node_se_name) {           /* name already defined    */
           m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0016W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry name double - ignored",
                           awcp_se_name, awcl_sg_name );
         } else {
           adsl_node_se_name = adsl_node_03;  /* save name             */
         }
       }
     }
     adsl_node_03 = (DOMNode *) amp_call_dom( adsl_node_03,
                                              ied_hlcldom_get_next_sibling );
   } while (adsl_node_03);
   if (adsl_node_se_name == NULL) {         /* no name found           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0017W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry has no name - ignored",
                     awcp_se_name, awcl_sg_name );
     goto p_conf_sg_80;                     /* DOM node server-group processed - next */
   }
   /* retrieve name                                                    */
   adsl_node_04 = (DOMNode *) amp_call_dom( adsl_node_se_name,
                                            ied_hlcldom_get_first_child );
   if (adsl_node_04 == NULL) {              /* no child found          */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0018W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry name \"name\" has no child - ignored",
                     awcp_se_name, awcl_sg_name );
     goto p_conf_sg_80;                     /* DOM node server-group processed - next */
   }
   do {
     if (((HL_RET_NUM) amp_call_dom( adsl_node_04, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) {
       awcl_se_name = (HL_WCHAR *) amp_call_dom( adsl_node_04, ied_hlcldom_get_node_value );
       break;
     }
     adsl_node_04 = (DOMNode *) amp_call_dom( adsl_node_04,
                                              ied_hlcldom_get_next_sibling );
   } while (adsl_node_04);                  /* for all siblings        */
   if (adsl_node_04 == NULL) {              /* no text found           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0019W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry name \"name\" no TEXT_NODE found - ignored",
                     awcp_se_name, awcl_sg_name );
     goto p_conf_sg_80;                     /* DOM node server-group processed - next */
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d found server-entry name %(ux)s", __LINE__, awcl_se_name );
#endif

   adsl_node_03 = adsl_node_save_03;        /* restore node for navigation */
   memset( &dsl_se_fill, 0, sizeof(struct dsd_se_vcicaphttp_entry) );  /* clear definition server-entry */
   dsl_se_fill.imc_trace_level = -1;        /* trace-level             */
   awcl_se_server_ineta = NULL;             /* server-entry serverineta */
   awcl_se_gate_ineta = NULL;               /* server-entry gate-ineta */

   p_conf_se_20:                            /* process DOM node server-entry */
   if (((HL_RET_NUM) amp_call_dom( adsl_node_03, ied_hlcldom_get_node_type ))
         != DOMNode::ELEMENT_NODE) {
     goto p_conf_se_80;                     /* get next sibling        */
   }
   awcl_03_name = (HL_WCHAR *) amp_call_dom( adsl_node_03, ied_hlcldom_get_node_name );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d found node %(ux)s", __LINE__, awcl_03_name );
#endif
   iml_entry = sizeof(achrs_node_se_entry) / sizeof(achrs_node_se_entry[0]);
   while (TRUE) {                           /* loop over possible values */
     if (iml_entry == 0) {                   /* value not found in table */
       m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0020W Error service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry %(ux)s invalid node found \"%(ux)s\" - ignored",
                       awcp_se_name, awcl_sg_name, awcl_se_name, awcl_03_name );
       goto p_conf_se_80;                   /* DOM node server-entry processed - next */
     }
     iml_entry--;                            /* decrement index         */
     bol1 = m_cmp_u16z_u8z( &iml1, awcl_03_name, (char *) achrs_node_se_entry[ iml_entry ] );
     if ((bol1) && (iml1 == 0)) {           /* strings are equal       */
       break;
     }
   }
   adsl_node_04 = (DOMNode *) amp_call_dom( adsl_node_03,
                                            ied_hlcldom_get_first_child );
   if (adsl_node_04 == NULL) {              /* no child found          */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0021W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry %(ux)s name \"%(ux)s\" has no child - ignored",
                     awcp_se_name, awcl_sg_name, awcl_se_name, awcl_03_name );
     goto p_conf_se_80;                     /* DOM node server-entry processed - next */
   }
   do {
     if (((HL_RET_NUM) amp_call_dom( adsl_node_04, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) {
       awcl_03_value = (HL_WCHAR *) amp_call_dom( adsl_node_04, ied_hlcldom_get_node_value );
       break;
     }
     adsl_node_04 = (DOMNode *) amp_call_dom( adsl_node_04,
                                              ied_hlcldom_get_next_sibling );
   } while (adsl_node_04);                  /* for all siblings        */
   if (adsl_node_04 == NULL) {              /* no text found           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0022W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry name \"%(ux)s\" no TEXT_NODE found - ignored",
                     awcp_se_name, awcl_sg_name, awcl_se_name, awcl_03_name );
     goto p_conf_sg_80;                     /* DOM node server-group processed - next */
   }
   bol1 = FALSE;                            /* keyword not double      */
   switch (iml_entry) {                     /* keyword found           */
     case (DEF_XML_SE_NAME - 1):
//     goto p_conf_se_80;                   /* DOM node server-entry processed - next */
       break;
     case (DEF_XML_SE_SERVER_INETA - 1):
       if (awcl_se_server_ineta) {          /* already defined         */
         bol1 = TRUE;                       /* keyword double          */
         break;
       }
       awcl_se_server_ineta = awcl_03_value;
       break;
     case (DEF_XML_SE_SERVER_PORT - 1):
       if (dsl_se_fill.imc_port) {          /* already defined         */
         bol1 = TRUE;                       /* keyword double          */
         break;
       }
       dsl_se_fill.imc_port = m_get_port_no( awcl_03_value, -1, ied_chs_utf_16 );
       if (dsl_se_fill.imc_port > 0) break;  /* is valid               */
       dsl_se_fill.imc_port = 0;            /* set not valid           */
       m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0023W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry %(ux)s serverport value \"%(ux)s\" not valid - ignored",
                       awcp_se_name, awcl_sg_name, awcl_se_name, awcl_03_value );
       break;
     case (DEF_XML_SE_GATE_INETA - 1):
       if (awcl_se_gate_ineta) {            /* already defined         */
         bol1 = TRUE;                       /* keyword double          */
         break;
       }
       awcl_se_gate_ineta = awcl_03_value;
       break;
     case (DEF_XML_SE_MAX_SESSION - 1):
       if (dsl_se_fill.imc_max_session) {   /* already defined         */
         bol1 = TRUE;                       /* keyword double          */
         break;
       }
       dsl_se_fill.imc_max_session = m_get_wc_number( awcl_03_value );
       if (dsl_se_fill.imc_max_session > 0) break;  /* is valid            */
       dsl_se_fill.imc_max_session = 0;     /* set not valid           */
       m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0024W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry %(ux)s max-session value \"%(ux)s\" not valid - ignored",
                       awcp_se_name, awcl_sg_name, awcl_se_name, awcl_03_value );
       break;
     case (DEF_XML_SE_TIMEOUT - 1):
       if (dsl_se_fill.imc_timeout) {       /* already defined         */
         bol1 = TRUE;                       /* keyword double          */
         break;
       }
       dsl_se_fill.imc_timeout = m_get_wc_number( awcl_03_value );
       if (dsl_se_fill.imc_timeout > 0) break;  /* is valid            */
       dsl_se_fill.imc_timeout = 0;         /* set not valid           */
       m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0025W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry %(ux)s timeout value \"%(ux)s\" not valid - ignored",
                       awcp_se_name, awcl_sg_name, awcl_se_name, awcl_03_value );
       break;
     case (DEF_XML_SE_RETRY_AE - 1):
       if (dsl_se_fill.imc_retry_ae) {      /* already defined         */
         bol1 = TRUE;                       /* keyword double          */
         break;
       }
       dsl_se_fill.imc_retry_ae = m_get_wc_number( awcl_03_value );
       if (dsl_se_fill.imc_retry_ae > 0) break;  /* is valid           */
       dsl_se_fill.imc_retry_ae = 0;        /* set not valid           */
       m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0026W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry %(ux)s retry-after-error value \"%(ux)s\" not valid - ignored",
                       awcp_se_name, awcl_sg_name, awcl_se_name, awcl_03_value );
       break;
     case (DEF_XML_SE_TRACE_LEVEL - 1):
       if (dsl_se_fill.imc_trace_level >= 0) {  /* already defined     */
         bol1 = TRUE;                       /* keyword double          */
         break;
       }
       dsl_se_fill.imc_trace_level = m_get_wc_number( awcl_03_value );
       if (dsl_se_fill.imc_trace_level >= 0) break;  /* is valid       */
       dsl_se_fill.imc_trace_level = -1;    /* set not valid           */
       m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0026W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry %(ux)s trace-level value \"%(ux)s\" not valid - ignored",
                       awcp_se_name, awcl_sg_name, awcl_se_name, awcl_03_value );
       break;
     case (DEF_XML_SE_VENDOR - 1):
       if (dsl_se_fill.iec_vve) {           /* already defined         */
         bol1 = TRUE;                       /* keyword double          */
         break;
       }
       iml1 = sizeof(achrs_vendor_name) / sizeof(achrs_vendor_name[0]);
       do {
         bol2 = m_cmp_u16z_u8z( &iml2, awcl_03_value, (char *) achrs_vendor_name[ iml1 - 1 ] );
         if ((bol2) && (iml2 == 0)) {       /* strings are equal       */
           dsl_se_fill.iec_vve = (ied_vch_vendor_def) iml1;  /* set vendor */
           dsl_se_fill.iec_vvr = ied_vvr_reuse;  /* reuse TCP connection */
           switch (dsl_se_fill.iec_vve) {
//           case ied_vve_kasp:             /* Kaspersky               */
             case ied_vve_syman:            /* Symantec                */
               dsl_se_fill.iec_vvr = ied_vve_wait_close;  /* wait for close */
               break;
             case ied_vve_c_icap:           /* c-icap                  */
               dsl_se_fill.iec_vvr = ied_vve_do_close;  /* do close    */
               break;
           }
           break;
         }
         iml1--;                            /* decrement index         */
       } while (iml1 > 0);
       if (iml1 > 0) break;                 /* vendor found            */
       m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0035W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry %(ux)s vendor \"%(ux)s\" not valid - ignored",
                       awcp_se_name, awcl_sg_name, awcl_se_name, awcl_03_value );
       break;
   }
   if (bol1) {                              /* keyword double          */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0027W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry %(ux)s name \"%(ux)s\" value \"%(ux)s\" double - ignored",
                     awcp_se_name, awcl_sg_name, awcl_se_name, awcl_03_name, awcl_03_value );
   }

   p_conf_se_80:                            /* DOM node processed - next */
   adsl_node_03 = (DOMNode *) amp_call_dom( adsl_node_03,
                                            ied_hlcldom_get_next_sibling );
   if (adsl_node_03) goto p_conf_se_20;     /* process DOM node        */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d p_conf_se_80: end of server-entry %(ux)s", __LINE__, awcl_se_name );
#endif
   if (dsl_se_fill.iec_vve == ied_vve_invalid) {  /* vendor not defined */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0036W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry %(ux)s vendor missing - server-entry ignored",
                     awcp_se_name, awcl_sg_name, awcl_se_name );
     goto p_conf_sg_80;                     /* DOM node server-group processed - next */
   }
   if (awcl_se_server_ineta == NULL) {      /* serverineta missing     */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0028W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry %(ux)s serverineta missing - server-entry ignored",
                     awcp_se_name, awcl_sg_name, awcl_se_name );
     goto p_conf_sg_80;                     /* DOM node server-group processed - next */
   }
   if (dsl_se_fill.imc_port == 0) {         /* serverport missing      */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0029W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry %(ux)s serverport missing - server-entry ignored",
                     awcp_se_name, awcl_sg_name, awcl_se_name );
     goto p_conf_sg_80;                     /* DOM node server-group processed - next */
   }
   if (awcl_se_gate_ineta) {                /* multihomed              */
     iml1 = m_build_bind_ineta( &dsl_se_fill.dsc_bind_multih, awcl_se_gate_ineta, -1, ied_chs_utf_16 );
     if (iml1) {                            /* error occured           */
       m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0030W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry %(ux)s gate-ineta \"%(ux)s\" invalid - ignored",
                       awcp_se_name, awcl_sg_name, awcl_se_name, awcl_se_gate_ineta );
     }
   }
   dsl_se_fill.adsc_server_ineta = m_get_target_ineta( awcl_se_server_ineta, -1, ied_chs_utf_16,
                                                       &dsl_se_fill.dsc_bind_multih );
   if (dsl_se_fill.adsc_server_ineta == NULL) {  /* INETA not valid    */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0031W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry %(ux)s serverineta \"%(ux)s\" invalid - server-entry ignored",
                     awcp_se_name, awcl_sg_name, awcl_se_name, awcl_se_server_ineta );
     goto p_conf_sg_80;                     /* DOM node server-group processed - next */
   }
   if (dsl_sg_fill.imc_no_vch_se >= MAX_VCH_SERVERS) {  /* maximum virus checking servers per group */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0032W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s server-entry %(ux)s maximum allowed server-entries already reached - server-entry ignored",
                     awcp_se_name, awcl_sg_name, awcl_se_name );
     free( dsl_se_fill.adsc_server_ineta );
     goto p_conf_sg_80;                     /* DOM node server-group processed - next */
   }
#ifndef B131201
   if (dsl_se_fill.imc_max_session == 0) {     /* value not set or valid */
     dsl_se_fill.imc_max_session = D_ICAP_MAX_SESSION;  /* default value maximum ICAP connections to this server */
   }
   if (dsl_se_fill.imc_retry_ae == 0) {     /* value not set or valid  */
     dsl_se_fill.imc_retry_ae = D_RETRY_AFTER_ERROR;  /* time in seconds to retry after error occured */
   }
#endif
   /* put this new server-entry in chain of server-group               */
   dsl_se_fill.imc_len_name = m_len_vx_vx( ied_chs_utf_8, awcl_se_name, -1, ied_chs_utf_16 );
   if (dsl_se_fill.imc_trace_level < 0) dsl_se_fill.imc_trace_level = 0;
   adsl_se_w1 = (struct dsd_se_vcicaphttp_entry *) malloc( sizeof(struct dsd_se_vcicaphttp_entry)
                                                           + dsl_se_fill.imc_len_name );
   memcpy( adsl_se_w1, &dsl_se_fill, sizeof(struct dsd_se_vcicaphttp_entry) );
   m_cpy_vx_vx( adsl_se_w1 + 1, dsl_se_fill.imc_len_name, ied_chs_utf_8,
                awcl_se_name, -1, ied_chs_utf_16 );
   adsl_se_w1->adsc_next = dsl_sg_fill.adsc_se_ch;  /* get chain server-entry */
   dsl_sg_fill.adsc_se_ch = adsl_se_w1;     /* set chain server-entry  */
   dsl_sg_fill.imc_no_vch_se++;             /* increment number of server entries */
/* to-do 25.12.07 KB imc_max_session 0 */

   p_conf_sg_80:                            /* DOM node processed - next */
   adsl_node_02 = (DOMNode *) amp_call_dom( adsl_node_02,
                                            ied_hlcldom_get_next_sibling );
   if (adsl_node_02) goto p_conf_sg_20;     /* process DOM node        */
   if (dsl_sg_fill.adsc_se_ch == NULL) {    /* check chain server-entry */
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0033W Error element service Virus-Checking-ICAP-HTTP entry %(ux)s server-group %(ux)s no server-entry defined - server-group ignored",
                     awcp_se_name, awcl_sg_name );
     goto p_serv_80;                        /* get next node on stage 1 */
   }
   /* compute memory needed for all elements                           */
   dsl_sg_fill.imc_len_name = m_len_vx_vx( ied_chs_utf_8, awcl_sg_name, -1, ied_chs_utf_16 );
   iml1 = sizeof(struct dsd_se_vcicaphttp_group) + dsl_sg_fill.imc_len_name;
   iml2 = 0;                                /* count structures        */
   adsl_se_w1 = dsl_sg_fill.adsc_se_ch;     /* get chain server-entry  */
   do {                                     /* loop over all server-entries */
     iml1 += sizeof(struct dsd_se_vcicaphttp_entry)
             + ((adsl_se_w1->adsc_server_ineta->imc_len_mem + sizeof(void *) - 1) & (0 - sizeof(void *)))
             + adsl_se_w1->imc_len_name;
     iml2++;                                /* count this structure    */
     adsl_se_w1 = adsl_se_w1->adsc_next;    /* get next in chain       */
   } while (adsl_se_w1);
   adsl_sg_w1 = (struct dsd_se_vcicaphttp_group *) malloc( iml1 );
   memcpy( adsl_sg_w1, &dsl_sg_fill, sizeof(struct dsd_se_vcicaphttp_group) );
   achl_w1 = (char *) adsl_sg_w1 + iml1;    /* end of allocated storage */
   achl_w1 -= dsl_sg_fill.imc_len_name;
   m_cpy_vx_vx( achl_w1, dsl_sg_fill.imc_len_name, ied_chs_utf_8,
                awcl_sg_name, -1, ied_chs_utf_16 );
   adsl_sg_w1->achc_name = achl_w1;         /* here is name            */
   adsl_sg_w1->adsc_se_ch = NULL;           /* clear chain server-entry */
   adsl_se_w2 = (struct dsd_se_vcicaphttp_entry *) (adsl_sg_w1 + 1);
   achl_w2 = (char *) (adsl_sg_w1 + 1) + iml2 * sizeof(struct dsd_se_vcicaphttp_entry);
   adsl_se_w1 = dsl_sg_fill.adsc_se_ch;     /* get chain server-entry  */
   do {                                     /* loop over all server-entries */
     memcpy( adsl_se_w2, adsl_se_w1, sizeof(struct dsd_se_vcicaphttp_entry) );
     adsl_se_w2->adsc_sg_this = adsl_sg_w1;  /* this server group      */
     achl_w1 -= adsl_se_w2->imc_len_name;
     memcpy( achl_w1, adsl_se_w1 + 1, adsl_se_w2->imc_len_name );
     adsl_se_w2->achc_name = achl_w1;       /* here is name            */
     adsl_se_w2->adsc_next = adsl_sg_w1->adsc_se_ch;  /* get chain server-entry */
     adsl_sg_w1->adsc_se_ch = adsl_se_w2;   /* set chain server-entry  */
     memcpy( achl_w2, adsl_se_w1->adsc_server_ineta, adsl_se_w1->adsc_server_ineta->imc_len_mem );
     adsl_se_w2->adsc_server_ineta = (struct dsd_target_ineta_1 *) achl_w2;
     achl_w2 += (adsl_se_w1->adsc_server_ineta->imc_len_mem + sizeof(void *) - 1) & (0 - sizeof(void *));
     free( adsl_se_w1->adsc_server_ineta );  /* free target INETA      */
     adsl_se_w3 = adsl_se_w1;               /* save memory             */
     adsl_se_w1 = adsl_se_w1->adsc_next;    /* get next in chain       */
     free( adsl_se_w3 );                    /* free memory server-entry */
     adsl_se_w2++;                          /* output next server-entry */
   } while (adsl_se_w1);
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d p_conf_se_80: server-group fills achl_w1=%p achl_w2=%p",
                   __LINE__, achl_w1, achl_w2 );
#endif
   adsl_sg_w1->adsc_next = dsl_conf_fill.adsc_sg_ch;  /* get chain server-group */
   dsl_conf_fill.adsc_sg_ch = adsl_sg_w1;   /* set chain server-group */
   iml_count_sg++;                          /* increment count server-groups */

   p_serv_80:                               /* DOM node processed - next */
   adsl_node_01 = (DOMNode *) amp_call_dom( adsl_node_01,
                                            ied_hlcldom_get_next_sibling );
   if (adsl_node_01) goto p_serv_20;        /* process DOM node service */
   if (dsl_conf_fill.adsc_sg_ch == NULL) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0034W Error service Virus-Checking-ICAP-HTTP entry %(ux)s not valid server-group found - service ignored",
                     awcp_se_name );
     return NULL;
   }
   if (dsl_conf_fill.imc_need_ch_no_g > iml_count_sg) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPVCICAPHC0035W Error service Virus-Checking-ICAP-HTTP entry %(ux)s min-check-no-groups %d greater number of server-groups %d - adjusted",
                     awcp_se_name, dsl_conf_fill.imc_need_ch_no_g, iml_count_sg );
     dsl_conf_fill.imc_need_ch_no_g = iml_count_sg;
   }
   iml1 = m_len_vx_vx( ied_chs_utf_8, awcp_se_name, -1, ied_chs_utf_16 );
   adsl_service_c1
     = (struct dsd_service_conf_1 *) malloc( sizeof(struct dsd_service_conf_1)
                                             + sizeof(struct dsd_se_vcicaphttp_conf)
                                             + iml1 );
   memset( adsl_service_c1, 0, sizeof(struct dsd_service_conf_1) );
   adsl_service_c1->iec_service_type = ied_sety_vc_icap_http;  /* type is virus checking ICAP HTTP */
   memcpy( adsl_service_c1 + 1, &dsl_conf_fill, sizeof(struct dsd_se_vcicaphttp_conf) );
   adsl_sg_w1 = dsl_conf_fill.adsc_sg_ch;   /* get chain server-group  */
   do {                                     /* loop over all server groups */
     /* this service configuration                                     */
     adsl_sg_w1->adsc_virch_conf
       = (struct dsd_se_vcicaphttp_conf *) (adsl_service_c1 + 1);
     adsl_sg_w1 = adsl_sg_w1->adsc_next;    /* get next server group in chain */
   } while (adsl_sg_w1);
   adsl_service_c1->imc_len_name = iml1;
   adsl_service_c1->achc_name
     = (char *) adsl_service_c1 + sizeof(struct dsd_service_conf_1)
                                + sizeof(struct dsd_se_vcicaphttp_conf);
   m_cpy_vx_vx( adsl_service_c1->achc_name, iml1, ied_chs_utf_8,
                awcp_se_name, -1, ied_chs_utf_16 );
   adsl_service_c1->amc_service_open = &m_service_open;
   return adsl_service_c1;                  /* return service configured */
} /* end m_service_vc_icap_http_conf()                                 */

/** open service                                                       */
static void * m_service_open( void *vpp_userfld,
                              struct dsd_service_conf_1 *adsp_se_conf_1,
                              struct dsd_aux_service_query_1 * adsp_sequ1 ) {
   struct dsd_service_aux_1 *adsl_service_aux_1;  /* definition auxiliary service */

   adsl_service_aux_1
     = (struct dsd_service_aux_1 *) m_wsp_s_ent_add( vpp_userfld,
                                                     DEF_WSP_TYPE_SERVICE,
                                                     sizeof(struct dsd_service_aux_1)
                                                       + sizeof(struct dsd_virch_session) );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d m_service_open() vpp_userfld=%p adsp_se_conf_1=%p adsl_service_aux_1=%p",
                   __LINE__, vpp_userfld, adsp_se_conf_1, adsl_service_aux_1 );
#endif
   memset( adsl_service_aux_1,
           0,
           sizeof(struct dsd_service_aux_1)
             + sizeof(struct dsd_virch_session) );
   adsl_service_aux_1->amc_service_requ = &m_service_requ;  /* request service */
   adsl_service_aux_1->amc_service_close = &m_service_close;  /* close service */
#define ADSL_VIRCH_SE ((struct dsd_virch_session *) (adsl_service_aux_1 + 1))
   /* service configuration                                            */
   ADSL_VIRCH_SE->adsc_virch_conf = (struct dsd_se_vcicaphttp_conf *) (adsp_se_conf_1 + 1);
   ADSL_VIRCH_SE->imc_signal = adsp_sequ1->imc_signal;  /* signal to set */
   ADSL_VIRCH_SE->adsc_conn1 = m_get_conn1_from_userfld( vpp_userfld );  /* connection */
#undef ADSL_VIRCH_SE
   return adsl_service_aux_1;               /* return auxiliary entry  */
} /* end m_service_open()                                              */

/** request to service                                                 */
static BOOL m_service_requ( void *vpp_userfld, void *ap_service_aux_1, void *ap_sequ1 ) {
   BOOL       bol1;                         /* working-variable        */
#ifndef TRY_110722_01                       /* check if all connected */
   BOOL       bol_send_active;              /* sending is active       */
   BOOL       bol_all_sent;                 /* all data have been sent */
#endif
   int        iml1, iml2;                   /* working-variables       */
// int        iml_len_sent;                 /* length sent             */
   struct dsd_virch_request *adsl_virch_req_w1;  /* virus checking request */
   struct dsd_virch_request *adsl_virch_req_w2;  /* virus checking request */
   struct dsd_virch_request **aadsl_virch_req_l;  /* last virus checking request */
#ifdef XYZ1
   struct dsd_se_vch_req_1 *adsl_sevchreq1_w1;  /* request area virus checking */
#endif
#ifndef TRY_110722_01                       /* check if all connected  */
   struct dsd_se_vch_req_1 *adsl_vchreq1_first;  /* first to process   */
   struct dsd_se_vch_req_1 *adsl_vchreq1_last;  /* last to process     */
   struct dsd_virch_active *adsl_vchact_w1;  /* active virus checking connection */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working-variable        */
#endif
   struct dsd_se_vch_req_1 *adsl_vchreq1_w1;  /* working-variable      */
   struct dsd_virch_active *adsl_vchact_w1;  /* active virus checking connection */
   struct dsd_virch_active *adsl_vchact_w2;  /* active virus checking connection */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */

#define ADSL_VIRCH_SE ((struct dsd_virch_session *) ((char *) ap_service_aux_1 + sizeof(struct dsd_service_aux_1)))
#define ADSL_SEQU1 ((struct dsd_aux_service_query_1 *) ap_sequ1)
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d m_service_requ() vpp_userfld=%p ap_service_aux_1=%p ADSL_SEQU1=%p",
                   __LINE__, vpp_userfld, ap_service_aux_1, ADSL_SEQU1 );
#endif
   adsl_virch_req_w1 = ADSL_VIRCH_SE->adsc_virch_req_ch;  /* chain of virus checking requests */
   while (adsl_virch_req_w1) {              /* loop over all requests  */
     if (adsl_virch_req_w1->ac_control_area == ADSL_SEQU1->ac_control_area) break;
     adsl_virch_req_w1 = adsl_virch_req_w1->adsc_next;  /* get next in chain */
   }
   if (adsl_virch_req_w1 == NULL) {         /* new request             */
#ifdef DEBUG_120119_01                      /* check TCP connections   */
     {
       int    imh_count;                    /* count connections       */
       struct dsd_se_vcicaphttp_group *adsh_sg_w1;  /* working-variable server-group */
       struct dsd_se_vcicaphttp_entry *adsh_se_w1;  /* working-variable server-entry */
       struct dsd_virch_active *adsh_vchact_w1;  /* active virus checking connection */

#define ADSH_VIRCH_CONF (ADSL_VIRCH_SE->adsc_virch_conf)
       adsh_sg_w1 = ADSH_VIRCH_CONF->adsc_sg_ch;  /* get chain server groups */
       imh_count = 0;                       /* count connections       */
       while (adsh_sg_w1) {                 /* loop over all server groups */
         adsh_se_w1 = adsh_sg_w1->adsc_se_ch;  /* server-entry         */
         while (adsh_se_w1) {
           adsh_vchact_w1 = adsh_se_w1->adsc_virch_act;  /* get chain of active TCP sessions */
           while (adsh_vchact_w1) {
             m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d m_service_requ() adsh_sg_w1=%p adsh_se_w1=%p adsh_vchact_w1=%p adsc_virch_requ=%p iec_vat=%d.",
                             __LINE__, adsh_sg_w1, adsh_se_w1, adsh_vchact_w1,
                             adsh_vchact_w1->adsc_virch_requ,  /* virus checking request */
                             adsh_vchact_w1->iec_vat );  /* TCP session active  */
             imh_count++;                   /* count connections       */
             adsh_vchact_w1 = adsh_vchact_w1->adsc_se_next;  /* get next in chain of active TCP sessions */
           }
           adsh_se_w1 = adsh_se_w1->adsc_next;
         }
         adsh_sg_w1 = adsh_sg_w1->adsc_next;
       }
       m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d m_service_requ() DEBUG_120119_01 found %d connections",
                       __LINE__, imh_count );
#undef ADSH_VIRCH_CONF
     }
#endif
     if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data     */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCREQ1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id             */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "new Virus-checking request - ac_control_area=%p.",
                       ADSL_SEQU1->ac_control_area );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content            /* content of text / data  */
         = (char *) (ADSL_WTR_G1 + 1);
       ADSL_WTR_G1->imc_length = iml1;      /* length of text / data   */
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
     }
#define ADSL_SE_VCH_CONTR_1 ((struct dsd_se_vch_contr_1 *) ADSL_SEQU1->ac_control_area)  /* service virus checking control area */
     if (ADSL_SE_VCH_CONTR_1->boc_abend) {  /* stop all                */
       return TRUE;
     }
     adsl_virch_req_w1 = (struct dsd_virch_request *) malloc( sizeof(struct dsd_virch_request) );
     memset( adsl_virch_req_w1, 0, sizeof(struct dsd_virch_request) );
     adsl_virch_req_w1->adsc_virch_session = ADSL_VIRCH_SE;  /* set session */
     adsl_virch_req_w1->ac_control_area = ADSL_SEQU1->ac_control_area;
     adsl_virch_req_w1->dsc_timer_ele.amc_compl = &m_virch_timer;   /* set routine for timeout */
     adsl_virch_req_w1->dsc_timer_ele.ilcwaitmsec = TIMEOUT_VCH_1 * 1000;  /* wait in milliseconds */
     dsg_global_lock.m_enter();             /* enter CriticalSection   */
     adsl_virch_req_w1->adsc_next = ADSL_VIRCH_SE->adsc_virch_req_ch;  /* chain of virus checking requests */
     ADSL_VIRCH_SE->adsc_virch_req_ch = adsl_virch_req_w1;  /* set new chain */
     dsg_global_lock.m_leave();             /* leave CriticalSection   */
     bol1 = m_create_active_virch( adsl_virch_req_w1 );
     if (bol1 == FALSE) {                   /* virus checking not possible */
#ifdef XYZ1
       dsg_global_lock.m_enter();           /* enter CriticalSection   */
       if (adsl_virch_req_w1 == ADSL_VIRCH_SE->adsc_virch_req_ch) {  /* at anchor of chain of virus checking requests */
         ADSL_VIRCH_SE->adsc_virch_req_ch = adsl_virch_req_w1->adsc_next;  /* remove from chain */
       } else {                             /* middle of chain         */
         adsl_virch_req_w2 = ADSL_VIRCH_SE->adsc_virch_req_ch;  /* get chain of virus checking requests */
         do {                               /* loop to find entry */
           adsl_virch_req_w2->adsc_next = adsl_virch_req_w2;  /* get next in chain */
         } while (adsl_virch_req_w2->adsc_next != adsl_virch_req_w1);
         adsl_virch_req_w2->adsc_next = adsl_virch_req_w1->adsc_next;  /* remove from chain */
       }
       dsg_global_lock.m_leave();           /* leave CriticalSection   */
       free( adsl_virch_req_w1 );           /* free memory area        */
#endif
       ADSL_VIRCH_SE->adsc_virch_req_ch = adsl_virch_req_w1->adsc_next;  /* remove from chain */
       ADSL_SE_VCH_CONTR_1->iec_vchcompl = ied_vchcompl_no_server;  /* the necessary servers not found */
       adsl_virch_req_w1->adsc_virch_session = NULL;  /* is in progress to be deleted */
       if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data   */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCREQ3", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id           */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                         "Virus-checking request denied ied_vchcompl_no_server - ac_control_area=%p.",
                         ADSL_SE_VCH_CONTR_1 );
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         ADSL_WTR_G1->achc_content          /* content of text / data  */
           = (char *) (ADSL_WTR_G1 + 1);
         ADSL_WTR_G1->imc_length = iml1;    /* length of text / data   */
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
         m_wsp_trace_out( adsl_wt1_w1 );    /* output of WSP trace record */
       }
#undef ADSL_SE_VCH_CONTR_1
       if (adsl_virch_req_w1->dsc_timer_ele.amc_compl != &m_virch_timer) return TRUE;  /* check routine for timeout */
       adsl_virch_req_w1->dsc_timer_ele.amc_compl = &m_virch_free;  /* set routine for free */
       m_time_set( &adsl_virch_req_w1->dsc_timer_ele, FALSE );  /* set the timer */
       return TRUE;                         /* all done                */
     }
#ifndef TRY_110722_01                       /* check if all connected */
     m_check_first_packet( adsl_virch_req_w1 );  /* check send first packet */
#else
     adsl_virch_req_w1->boc_send_active = TRUE; /* send is active      */
#ifdef DEBUG_120120_01                      /* m_check_first_packet()  */
     m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d DEBUG_120120_01 adsl_virch_req_w1=%p.",
                     __LINE__, adsl_virch_req_w1 );
#endif
     bol1 = m_check_first_packet( adsl_virch_req_w1 );  /* check send first packet */
     if (bol1 == FALSE) {                   /* not yet all connected   */
       m_time_set( &adsl_virch_req_w1->dsc_timer_ele, FALSE );  /* set the timer */
       return TRUE;                         /* check how to continue   */
     }
     adsl_virch_req_w1->boc_send_active = FALSE;  /* send is not active */
#endif
   } else {                                 /* continue existing request */
#define ADSL_SE_VCH_CONTR_1 ((struct dsd_se_vch_contr_1 *) adsl_virch_req_w1->ac_control_area)  /* service virus checking control area */
     if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
       iml1 = 0;                            /* clear count             */
       adsl_vchreq1_w1 = ADSL_SE_VCH_CONTR_1->adsc_sevchreq1;  /* get requests */
       while (adsl_vchreq1_w1) {            /* loop over chain requests */
         iml1++;                            /* increment count         */
         adsl_vchreq1_w1 = adsl_vchreq1_w1->adsc_next;  /* get next in chain */
       }
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data     */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCREQ2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id             */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "continue Virus-checking request - ac_control_area=%p boc_abend=%d boc_wait_window=%d no-req=%d req=%p boc_send_active=%d.",
                       ADSL_SE_VCH_CONTR_1, ADSL_SE_VCH_CONTR_1->boc_abend, ADSL_SE_VCH_CONTR_1->boc_wait_window,
                       iml1, adsl_virch_req_w1, adsl_virch_req_w1->boc_send_active );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content            /* content of text / data  */
         = (char *) (ADSL_WTR_G1 + 1);
       ADSL_WTR_G1->imc_length = iml1;      /* length of text / data   */
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
     }
     if (ADSL_SE_VCH_CONTR_1->boc_abend) {  /* stop all                */
       goto p_abend_00;                     /* process abend - stop    */
     }
#undef ADSL_SE_VCH_CONTR_1
   }
#define ADSL_SE_VCH_CONTR_1 ((struct dsd_se_vch_contr_1 *) adsl_virch_req_w1->ac_control_area)  /* service virus checking control area */
#ifdef TRACEHL1
   {
     struct dsd_se_vch_req_1 *adsh_sevchreq1_w1;  /* request area virus checking */
     int      imh1 = 0;
     adsh_sevchreq1_w1 = ADSL_SE_VCH_CONTR_1->adsc_sevchreq1;  /* chain of requests */
     while (adsh_sevchreq1_w1) {
       imh1++;                              /* count this entry        */
       adsh_sevchreq1_w1 = adsh_sevchreq1_w1->adsc_next;  /* get next in chain */
     }
     m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d m_service_requ() adsc_sevchreq1 chain %d elements",
                     __LINE__, imh1 );
   }
#endif
   if (adsl_virch_req_w1->boc_send_active) {  /* send is active        */
     return TRUE;                           /* all done                */
   }
#ifdef TRY_150101_01                        /* more data to send       */

   p_send_00:                               /* try to send data        */
#endif
#ifndef TRY_110722_01                       /* check if all connected */
   adsl_vchreq1_first = ADSL_SE_VCH_CONTR_1->adsc_sevchreq1->adsc_next;  /* after file-name */
   if (adsl_vchreq1_first == NULL) {        /* nothing in chain        */
     return TRUE;                           /* all done                */
   }
   while (adsl_vchreq1_first->iec_stat != ied_vchstat_active) {  /* data already sent */
     adsl_vchreq1_first = adsl_vchreq1_first->adsc_next;  /* get next in chain */
#ifdef B090914
     if (adsl_vchreq1_first) {              /* end of chain reached    */
       return TRUE;                         /* all done                */
     }
#endif
     if (adsl_vchreq1_first == NULL) {      /* end of chain reached    */
       return TRUE;                         /* all done                */
     }
   }
   if (adsl_virch_req_w1->dsc_timer_ele.vpc_chain_2) {  /* timer set   */
     m_time_rel( &adsl_virch_req_w1->dsc_timer_ele );  /* release timer */
   }
   bol_all_sent = FALSE;                    /* not all data have been sent */
   adsl_vchreq1_last = adsl_vchreq1_first;  /* get remaining chain     */
   iml1 = 0;                                /* data sent               */
   iml2 = ADSL_SE_VCH_CONTR_1->imc_max_diff_window / 2;  /* maximum halve window */
   while (TRUE) {                           /* loop over remaining chain */
#ifdef XYZ1
     if ((ADSL_SE_VCH_CONTR_1->ilc_window_2 - ADSL_SE_VCH_CONTR_1->ilc_window_1)
           > D_WINDOW_SEND) {
       break;
     }
#endif
#ifdef TRY_120615_01                        /* send filename multiple times */
     if (adsl_vchreq1_last->iec_vchreq1 != ied_vchreq_filename) {  /* filename */
#endif
     adsl_vchreq1_last->iec_stat = ied_vchstat_sent;  /* data have been sent */
     adsl_gai1_w1 = adsl_vchreq1_last->adsc_gai1_data;  /* get data    */
     while (adsl_gai1_w1) {                 /* loop over all gather structures */
       iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     if (adsl_vchreq1_last->iec_vchreq1 == ied_vchreq_eof) {  /* End-of-File */
       bol_all_sent = TRUE;                 /* all data have been sent */
     }
#ifdef TRY_120615_01                        /* send filename multiple times */
     }
#endif
     if (adsl_vchreq1_last->adsc_next == NULL) break;  /* is last in chain */
     if (iml1 >= iml2) break;               /* maximum length to send reached */
     adsl_vchreq1_last = adsl_vchreq1_last->adsc_next;  /* get next in chain */
   }
   ADSL_SE_VCH_CONTR_1->ilc_window_2 += iml1;
   adsl_virch_req_w1->boc_send_active = TRUE;  /* send is active       */
   bol_send_active = FALSE;                 /* sending is not active   */
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
   adsl_vchact_w1 = adsl_virch_req_w1->adsc_virch_act_ch;  /* chain active virus checking connections */
   while (adsl_vchact_w1) {                 /* loop over all active TCP sessions */
#ifdef DEBUG_110722_01                      /* do not send before connected */
     if (adsl_vchact_w1->iec_vat != ied_vat_active) {  /* TCP session active */
       m_hlnew_printf( HLOG_WARN1, "xs-gw-serv-vch-icap l%05d TCP send to session not active",
                       __LINE__ );
     }
#endif
     bol1 = m_send_chunk( adsl_vchact_w1, adsl_vchreq1_first, adsl_vchreq1_last );
     if (bol1) {                            /* could not yet send data */
       bol_send_active = TRUE;              /* sending is active       */
     }
     adsl_vchact_w1 = adsl_vchact_w1->adsc_requ_next;  /* next in chain for this request */
   }
   if (bol_send_active) {                   /* send is active          */
     dsg_global_lock.m_leave();             /* leave CriticalSection   */
     m_time_set( &adsl_virch_req_w1->dsc_timer_ele, FALSE );  /* set the timer */
     return TRUE;                           /* all done                */
   }
   while (TRUE) {                           /* loop over requests sent */
     adsl_vchreq1_first->iec_stat = ied_vchstat_done;  /* area can be freed */
#ifdef XYZ1
     adsl_gai1_w1 = adsl_vchreq1_first->adsc_gai1_data;  /* get data   */
     while (adsl_gai1_w1) {                 /* loop over all gather structures */
       ADSL_SE_VCH_CONTR_1->ilc_window_1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     }
#endif
     if (adsl_vchreq1_first == adsl_vchreq1_last) break;  /* all requests marked */
     adsl_vchreq1_first = adsl_vchreq1_first->adsc_next;  /* get next in chain */
   }
   adsl_virch_req_w1->boc_send_active = FALSE;  /* send is not active  */
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
//#define ADSL_SE_VCH_CONTR_1 ((struct dsd_se_vch_contr_1 *) adsl_virch_req_w1->ac_control_area)  /* service virus checking control area */
   if (ADSL_SE_VCH_CONTR_1->boc_wait_window) {  /* wait till window smaller */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_service_requ() boc_wait_window set",
                     __LINE__ );
#endif
     ADSL_SE_VCH_CONTR_1->boc_wait_window = FALSE;
     m_wsp_s_ent_notify( adsl_virch_req_w1->adsc_virch_session->adsc_conn1,
                         (char *) adsl_virch_req_w1->adsc_virch_session - sizeof(struct dsd_service_aux_1),
                         adsl_virch_req_w1->adsc_virch_session->imc_signal );
   }
//#undef ADSL_SE_VCH_CONTR_1
   if (bol_all_sent) {                      /* all data have been sent */
     m_time_set( &adsl_virch_req_w1->dsc_timer_ele, FALSE );  /* set the timer */
   }
#endif
#ifdef TRY_110722_01                        /* check if all connected  */
#ifdef B150128
   m_continue_send( adsl_virch_req_w1 );    /* send more data          */
#endif
#ifndef B150128
   m_continue_send( adsl_virch_req_w1, FALSE );  /* send more data     */
#endif
#endif
#ifdef TRY_150101_01                        /* more data to send       */
   if (   (ADSL_SE_VCH_CONTR_1->ilc_window_2 < ADSL_SE_VCH_CONTR_1->ilc_window_1)
       && (adsl_virch_req_w1->boc_send_active == FALSE)) {  /* send is not active */
     goto p_send_00;                        /* try to send data        */
   }
#endif
   return TRUE;                             /* all done                */

   p_abend_00:                              /* process abend - stop    */
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
   aadsl_virch_req_l = &ADSL_VIRCH_SE->adsc_virch_req_ch;  /* last virus checking request */
   adsl_virch_req_w2 = ADSL_VIRCH_SE->adsc_virch_req_ch;  /* chain of virus checking requests */
   while (adsl_virch_req_w2) {              /* loop over all requests  */
     if (adsl_virch_req_w2 == adsl_virch_req_w1) {  /* request found   */
       *aadsl_virch_req_l = adsl_virch_req_w2->adsc_next;  /* remove from chain virus checking requests */
     }
     aadsl_virch_req_l = &adsl_virch_req_w2->adsc_next;  /* last virus checking request */
     adsl_virch_req_w2 = adsl_virch_req_w2->adsc_next;  /* get next in chain */
   }
   adsl_virch_req_w1->adsc_virch_session = NULL;  /* is in progress to be deleted */
   adsl_vchact_w1 = adsl_virch_req_w1->adsc_virch_act_ch;  /* chain active virus checking connections */
   while (adsl_vchact_w1) {                 /* loop over all active virus checking connections */
     adsl_vchact_w2 = adsl_vchact_w1;       /* save this connection    */
     adsl_vchact_w1 = adsl_vchact_w1->adsc_requ_next;  /* get next in chain for this request */
     if (   (adsl_vchact_w2->iec_vat == ied_vat_active)  /* TCP session active */
         && (adsl_vchact_w2->iec_var != ied_var_no_virus)  /* file does not contain virus */
         && (adsl_vchact_w2->iec_var != ied_var_virus_found)) {  /* file contains virus */
       if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data   */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCCLO9", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id         */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                         "close TCP connection to virus-checker %p.",
                         adsl_vchact_w2 );
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         ADSL_WTR_G1->achc_content          /* content of text / data  */
           = (char *) (ADSL_WTR_G1 + 1);
         ADSL_WTR_G1->imc_length = iml1;    /* length of text / data   */
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
         m_wsp_trace_out( adsl_wt1_w1 );    /* output of WSP trace record */
       }
       adsl_vchact_w2->iec_vat = ied_vat_wait_close;  /* TCP session wait for close */
       adsl_vchact_w2->adsc_virch_requ = NULL;  /* no more virus checking request */
       adsl_vchact_w2->dsc_tcpcomp.m_end_session();
     } else {
       adsl_vchact_w2->adsc_virch_requ = NULL;  /* no more virus checking request */
     }
   }
   adsl_virch_req_w1->dsc_timer_ele.amc_compl = &m_virch_free;  /* set routine for free */
   m_time_set( &adsl_virch_req_w1->dsc_timer_ele, FALSE );  /* set the timer */
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
   return TRUE;                             /* all done                */
#undef ADSL_SE_VCH_CONTR_1
#undef ADSL_VIRCH_SE
#undef ADSL_SEQU1
} /* end m_service_requ()                                              */

/** close the service                                                  */
static void m_service_close( void *vpp_userfld, void *ap_service_aux_1 ) {
#ifndef B120119
   int        iml1;                         /* working variable        */
#endif
   struct dsd_virch_request *adsl_virch_req_w1;  /* virus checking request */
   struct dsd_virch_request *adsl_virch_req_w2;  /* virus checking request */
   struct dsd_virch_active *adsl_vchact_w1;  /* active virus checking connection */
#ifndef B120119
   struct dsd_virch_active *adsl_vchact_w2;  /* active virus checking connection */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d m_service_close() vpp_userfld=%p ap_service_aux_1=%p.",
                   __LINE__, vpp_userfld, ap_service_aux_1 );
#endif
#define ADSL_VIRCH_SE ((struct dsd_virch_session *) ((char *) ap_service_aux_1 + sizeof(struct dsd_service_aux_1)))
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
#ifdef DEBUG_120122_01                      /* sending to ICAP stops   */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXX5", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "DEBUG_120122_01 l%05d thread=%d - after  lock-enter",
                     __LINE__, HL_GET_THREAD );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
   adsl_virch_req_w1 = ADSL_VIRCH_SE->adsc_virch_req_ch;  /* chain of virus checking requests */
   while (adsl_virch_req_w1) {              /* loop over all requests  */
     adsl_virch_req_w1->adsc_virch_session = NULL;  /* is in progress to be deleted */
     adsl_virch_req_w2 = adsl_virch_req_w1;  /* save request           */
     adsl_virch_req_w1 = adsl_virch_req_w1->adsc_next;  /* get next in chain */
     adsl_vchact_w1 = adsl_virch_req_w2->adsc_virch_act_ch;  /* chain active virus checking connections */
     while (adsl_vchact_w1) {               /* loop over all active virus checking connections */
#ifdef B120119
       adsl_vchact_w1->adsc_virch_requ = NULL;  /* no more virus checking request */
       if (   (adsl_vchact_w1->iec_vat == ied_vat_active)  /* TCP session active */
           && (adsl_vchact_w1->iec_var != ied_var_no_virus)  /* file does not contain virus */
           && (adsl_vchact_w1->iec_var != ied_var_virus_found)) {  /* file contains virus */
#ifdef NONSENSE_120119
#ifndef B120119
         adsl_vchact_w1->iec_var = ied_var_closed;  /* TCP session is closed - can remove connection */
#endif
#endif
         adsl_vchact_w1->iec_vat = ied_vat_wait_close;  /* TCP session wait for close */
         adsl_vchact_w1->dsc_tcpcomp.m_end_session();
       }
       adsl_vchact_w1 = adsl_vchact_w1->adsc_requ_next;  /* get next in chain for this request */
#endif
#ifndef B120119
       adsl_vchact_w2 = adsl_vchact_w1;     /* save this connection    */
       adsl_vchact_w1 = adsl_vchact_w1->adsc_requ_next;  /* get next in chain for this request */
       if (   (adsl_vchact_w2->iec_vat == ied_vat_active)  /* TCP session active */
           && (adsl_vchact_w2->iec_var != ied_var_no_virus)  /* file does not contain virus */
           && (adsl_vchact_w2->iec_var != ied_var_virus_found)) {  /* file contains virus */
#ifdef NONSENSE_120119
#ifndef B120119
         adsl_vchact_w1->iec_var = ied_var_closed;  /* TCP session is closed - can remove connection */
#endif
#endif
         if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
           adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
           memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
           adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data   */
           adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
           memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCCLO8", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
           adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id         */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
           iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                           "close TCP connection to virus-checker %p.",
                           adsl_vchact_w2 );
           ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed      */
           ADSL_WTR_G1->achc_content        /* content of text / data  */
             = (char *) (ADSL_WTR_G1 + 1);
           ADSL_WTR_G1->imc_length = iml1;  /* length of text / data   */
           adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
           m_wsp_trace_out( adsl_wt1_w1 );  /* output of WSP trace record */
         }
         adsl_vchact_w2->iec_vat = ied_vat_wait_close;  /* TCP session wait for close */
         adsl_vchact_w2->adsc_virch_requ = NULL;  /* no more virus checking request */
         adsl_vchact_w2->dsc_tcpcomp.m_end_session();
       } else {
         adsl_vchact_w2->adsc_virch_requ = NULL;  /* no more virus checking request */
       }
#endif
     }
     if (adsl_virch_req_w2->dsc_timer_ele.amc_compl == &m_virch_timer) {  /* check routine for timeout */
       adsl_virch_req_w2->dsc_timer_ele.amc_compl = &m_virch_free;  /* set routine for free */
       m_time_set( &adsl_virch_req_w2->dsc_timer_ele, FALSE );  /* set the timer */
     }
   }
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
#undef ADSL_VIRCH_SE
} /* end m_service_close()                                             */

/** create active virtual channel                                      */
static BOOL m_create_active_virch( struct dsd_virch_request *adsp_virch_req ) {
#ifndef B120119
   int        iml1;                         /* working variable        */
#endif
   int        iml_count_sg;                 /* count server groups     */
   int        iml_count_act;                /* count active TCP sessions */
   int        iml_epoch;                    /* current time            */
   struct dsd_se_vcicaphttp_entry *adsl_se_w1;  /* working-variable server-entry */
   struct dsd_virch_active *adsl_vchact_w1;  /* active virus checking connection */
   struct dsd_virch_active *adsl_vchact_w2;  /* active virus checking connection */
#ifndef B120119
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
#endif
   struct dsd_random_server dsl_rse;        /* search server in random order */

#define ADSL_VIRCH_SE (adsp_virch_req->adsc_virch_session)
#define ADSL_VIRCH_CONF (ADSL_VIRCH_SE->adsc_virch_conf)
   iml_epoch = 0;                           /* clear current time      */
   /* first check if enough servers are available                      */
   dsl_rse.adsc_sg = ADSL_VIRCH_CONF->adsc_sg_ch;  /* get chain server groups */
   iml_count_sg = 0;                        /* reset count server groups */
   do {
     dsl_rse.imc_no_checked = 0;            /* clear number of already checked servers */
     while (TRUE) {
       adsl_se_w1 = m_get_se_random( &dsl_rse );  /* get next server-entry */
       if (adsl_se_w1 == NULL) break;       /* was last server-entry   */
#ifdef CHECK_VC_NOT_OPERATIONAL_01
       iml_epoch = (int) time( NULL );      /* get current time        */
       adsl_se_w1->imc_time_retry = iml_epoch + 1;  /* mark as not operational */
#endif
       if (adsl_se_w1->imc_time_retry == 0) break;  /* time next retry */
       if (iml_epoch == 0) {                /* current time not set    */
         iml_epoch = (int) time( NULL );    /* get current time        */
       }
       if (adsl_se_w1->imc_time_retry <= iml_epoch) {  /* time next retry reached */
         adsl_se_w1->imc_time_retry = 0;    /* clear time next retry   */
         break;
       }
#ifdef B120119
       adsl_se_w1 = adsl_se_w1->adsc_next;  /* next server-entry in chain */
#endif
     }
     if (adsl_se_w1) {                      /* server entry valid found */
       iml_count_sg++;                      /* increment count server groups */
     } else {                               /* no valid server entry found */
       if (dsl_rse.adsc_sg->boc_must_check) return FALSE;  /* this group must check */
     }
     dsl_rse.adsc_sg = dsl_rse.adsc_sg->adsc_next;  /* get next in chain */
   } while (dsl_rse.adsc_sg);
   if (iml_count_sg < ADSL_VIRCH_CONF->imc_need_ch_no_g) {  /* number of groups that need to check */
     return FALSE;                          /* virus-checking not possible */
   }
   /* now get all active TCP sessions                                  */
   adsl_vchact_w2 = NULL;                   /* reset chain of requests */
   dsl_rse.adsc_sg = ADSL_VIRCH_CONF->adsc_sg_ch;  /* get chain server groups */
   iml_count_sg = ADSL_VIRCH_CONF->imc_need_ch_no_g;  /* number of groups that need to check */
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
#ifdef DEBUG_120122_01                      /* sending to ICAP stops   */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXX6", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "DEBUG_120122_01 l%05d thread=%d - after  lock-enter",
                     __LINE__, HL_GET_THREAD );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
   do {
     dsl_rse.imc_no_checked = 0;            /* clear number of already checked servers */
     while (TRUE) {
#ifdef B120620
       adsl_se_w1 = m_get_se_random( &dsl_rse );  /* get next server-entry */
       if (adsl_se_w1 == NULL) break;       /* was last server-entry   */
       if (adsl_se_w1->imc_time_retry) break;  /* retry later          */
#endif
#ifndef B120620
       do {                                 /* loop to find random server */
         adsl_se_w1 = m_get_se_random( &dsl_rse );  /* get next server-entry */
         if (adsl_se_w1 == NULL) break;     /* was last server-entry   */
       } while (adsl_se_w1->imc_time_retry);  /* retry later           */
       if (adsl_se_w1 == NULL) break;       /* was last server-entry   */
#endif
       iml_count_act = 0;                   /* reset count active TCP sessions */
       adsl_vchact_w1 = adsl_se_w1->adsc_virch_act;  /* get chain of active TCP sessions */
       while (adsl_vchact_w1) {             /* loop over all active TCP sessions */
//       if (   (adsl_vchact_w1->adsc_virch_requ == NULL)  /* no virus checking request */
//           && (adsl_vchact_w1->iec_vat == ied_vat_active)) {  /* TCP session active */
// 19.06.12 KB is this correct - twice in chain
         if (   (adsl_vchact_w1->adsc_virch_requ == NULL)  /* no virus checking request */
             && (   (adsl_vchact_w1->iec_vat == ied_vat_w_conn)  /* wait for connect */
                 || (adsl_vchact_w1->iec_vat == ied_vat_active))) {  /* TCP session active */
#ifdef DEBUG_120619_01                      /* not in chain of active connections */
           m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d DEBUG_120619_01 adsl_vchact_w1=%p adsp_virch_req=%p.",
                           __LINE__, adsl_vchact_w1, adsp_virch_req );
#endif
           adsl_vchact_w1->iec_var = ied_var_invalid;  /* does not wait for receive data */
           adsl_vchact_w1->adsc_virch_requ = adsp_virch_req;  /* set virus checking request */
           adsl_vchact_w1->adsc_requ_next = NULL;  /* clear chain request */
           if (adsl_vchact_w2 == NULL) {    /* at anchor of chain      */
             adsp_virch_req->adsc_virch_act_ch = adsl_vchact_w1;  /* chain active virus checking connections */
           } else {                         /* middle in chain         */
             adsl_vchact_w2->adsc_requ_next = adsl_vchact_w1;  /* next in chain for this request */
           }
           adsl_vchact_w2 = adsl_vchact_w1;  /* save last active TCP session */
           break;
         }
#ifdef B120119
         iml_count_act++;                   /* increment count active TCP sessions */
#else
         if (   (adsl_vchact_w1->iec_vat != ied_vat_wait_close)  /* TCP session wait for close */
             && (adsl_vchact_w1->iec_vat != ied_vat_closed)) {  /* TCP session is closed */
           iml_count_act++;                 /* increment count active TCP sessions */
         }
#endif
         adsl_vchact_w1 = adsl_vchact_w1->adsc_se_next;  /* next in chain server entry */
       }
       if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXXI", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id           */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                         "check for active connection l%05d adsp_virch_req=%p adsl_vchact_w1=%p iml_count_act=%d adsl_se_w1=%p ...->imc_max_session=%d.",
                         __LINE__, adsp_virch_req, adsl_vchact_w1, iml_count_act, adsl_se_w1, adsl_se_w1->imc_max_session );
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         ADSL_WTR_G1->achc_content          /* content of text / data  */
           = (char *) (ADSL_WTR_G1 + 1);
         ADSL_WTR_G1->imc_length = iml1;    /* length of text / data   */
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
         m_wsp_trace_out( adsl_wt1_w1 );    /* output of WSP trace record */
       }
#ifdef B120119
       if (adsl_vchact_w1) break;           /* active TCP session found */
#endif
#ifndef B120119
       if (adsl_vchact_w1) {                /* active TCP session found */
         if ((img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) == 0) break;  /* no trace Virus checking */
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data   */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCUEX1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id           */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                         "use existing TCP connection %p for virus-checking",
                         adsl_vchact_w1 );
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         ADSL_WTR_G1->achc_content          /* content of text / data  */
           = (char *) (ADSL_WTR_G1 + 1);
         ADSL_WTR_G1->imc_length = iml1;    /* length of text / data   */
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
         m_wsp_trace_out( adsl_wt1_w1 );    /* output of WSP trace record */
         break;
       }
#endif
       if (iml_count_act < adsl_se_w1->imc_max_session) {  /* compare count active TCP sessions */
         adsl_vchact_w1 = m_new_active_virch( adsl_se_w1 );  /* create new active TCP session */
         if (adsl_vchact_w1) {              /* active TCP session created */
           adsl_vchact_w1->adsc_virch_requ = adsp_virch_req;  /* set virus checking request */
//         adsl_vchact_w1->adsc_requ_next = NULL;  /* clear chain request */
           if (adsl_vchact_w2 == NULL) {    /* at anchor of chain      */
             adsp_virch_req->adsc_virch_act_ch = adsl_vchact_w1;  /* chain active virus checking connections */
           } else {                         /* middle in chain         */
             adsl_vchact_w2->adsc_requ_next = adsl_vchact_w1;  /* next in chain for this request */
           }
           adsl_vchact_w2 = adsl_vchact_w1;  /* save last active TCP session */
           break;                           /* all done this server entry */
         }
       }
#ifdef B120119
       adsl_se_w1 = adsl_se_w1->adsc_next;  /* next server-entry in chain */
#endif
     }
     if (adsl_se_w1 == NULL) {              /* no server entry valid found */
       if (dsl_rse.adsc_sg->boc_must_check) {  /* this group must check */
         goto p_crav_60;                    /* cannot do virus-checking */
       }
     }
     if (adsl_se_w1) {                      /* server entry valid found */
       iml_count_sg--;                      /* count number of groups that need to check */
     }
     dsl_rse.adsc_sg = dsl_rse.adsc_sg->adsc_next;  /* get next in chain */
   } while (dsl_rse.adsc_sg);
   if (iml_count_sg > 0) {                  /* check number of groups that need to check */
     goto p_crav_60;                        /* cannot do virus-checking */
   }
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
#ifdef DEBUG_120120_01                      /* m_check_first_packet()  */
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d DEBUG_120120_01 adsp_virch_req=%p.",
                   __LINE__, adsp_virch_req );
#endif
   m_check_first_packet( adsp_virch_req );  /* check send first packet */
   return TRUE;                             /* all done                */

   p_crav_60:                               /* cannot do virus-checking */
   adsl_vchact_w1 = adsp_virch_req->adsc_virch_act_ch;  /* chain active virus checking connections */
   while (adsl_vchact_w1) {                 /* loop over all entries created */
#ifdef DEBUG_120119_02                      /* check ied_vat_active    */
     if (adsl_vchact_w1->iec_vat == ied_vat_active) {  /* TCP session active */
       m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d DEBUG_120119_02 adsl_vchact_w1=%p.",
                       __LINE__, adsl_vchact_w1 );
     }
#endif
     adsl_vchact_w1->adsc_virch_requ = NULL;  /* clear virus checking request */
     adsl_vchact_w1 = adsl_vchact_w1->adsc_requ_next;  /* get next in chain */
   }
   adsp_virch_req->adsc_virch_act_ch = NULL;  /* clear chain active virus checking connections */
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXXJ", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "cannot do virus checking l%05d adsp_virch_req=%p.",
                     __LINE__, adsp_virch_req );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   return FALSE;                            /* virus-checking not possible */
#undef ADSL_VIRCH_CONF
#undef ADSL_VIRCH_SE
} /* end m_create_active_virch()                                       */

/** create new active TCP session                                      */
static struct dsd_virch_active * m_new_active_virch( struct dsd_se_vcicaphttp_entry *adsp_sevirch_entry ) {
   int        iml_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
   struct dsd_virch_active *adsl_vchact;    /* active virus checking connection */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */

   adsl_vchact = (struct dsd_virch_active *) malloc( sizeof(struct dsd_virch_active) );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d m_new_active_virch() adsl_vchact=%p.",
                   __LINE__, adsl_vchact );
#endif
   memset( adsl_vchact, 0, sizeof(struct dsd_virch_active) );
   adsl_vchact->adsc_sevirch_entry = adsp_sevirch_entry;
   adsl_vchact->adsc_se_next = adsp_sevirch_entry->adsc_virch_act;  /* get chain of active TCP sessions */
   adsp_sevirch_entry->adsc_virch_act = adsl_vchact;  /* set chain of active TCP sessions */
#ifdef OLD01
   m_virch_do_connect( adsl_vchact );
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap-l%05d-T m_new_active_virch() call m_startco_mh() &dsc_tcpcomp=%p vpp_userfld=%p.",
                   __LINE__, &adsl_vchact->dsc_tcpcomp, adsl_vchact );
#endif
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCOPE1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "open TCP connection to virus-checker %p.",
                     adsl_vchact );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   adsl_vchact->iec_vat = ied_vat_w_conn;   /* wait for connect        */
   iml_rc = adsl_vchact->dsc_tcpcomp.m_startco_mh(
              &dss_virch_tcpco1_cb1,
              adsl_vchact,
              &adsl_vchact->adsc_sevirch_entry->dsc_bind_multih,  /* for bind multihomed */
              adsl_vchact->adsc_sevirch_entry->adsc_server_ineta,  /* remote INETA */
#ifndef B121120
              NULL,                         /* INETA to free           */
#endif
              adsl_vchact->adsc_sevirch_entry->imc_port,  /* port of target */
              TRUE );                       /* do connect round-robin */
   if (iml_rc == 0) {                       /* no error occured        */
     return adsl_vchact;                    /* return entry created    */
   }
   m_hlnew_printf( HLOG_XYZ1, "HWSPnnnnnnW xs-gw-serv-vch-icap l%05d m_new_active_virch() m_startco_mh() failed %d.",
                   __LINE__, iml_rc );
   adsp_sevirch_entry->adsc_virch_act = adsl_vchact->adsc_se_next;  /* remove from chain of active TCP sessions */
   free( adsl_vchact );                     /* free memory again       */
   return NULL;                             /* no entry created        */
} /* end m_new_active_virch()                                          */

#ifndef TRY_110722_01                       /* check if all connected */
/** check if all TCP connections are connected now, to send first packet */
static void m_check_first_packet( struct dsd_virch_request *adsp_virch_req ) {
   struct dsd_virch_active *adsl_vchact_cur;  /* active virus checking connection */

   adsl_vchact_cur = adsp_virch_req->adsc_virch_act_ch;  /* chain active virus checking connections */
   if (adsl_vchact_cur == NULL) {
/* to-do 26.12.07 KB error message */
     return;
   }
#ifdef OLD01
   do {                                     /* loop over all TCP sessions */
     if (adsl_vchact_cur->imc_ind_conn >= 0) return;  /* check index of last connect */
     adsl_vchact_cur = adsl_vchact_cur->adsc_requ_next;  /* next in chain for this request */
   } while (adsl_vchact_cur);
#endif
   do {                                     /* loop over all TCP sessions */
     if (adsl_vchact_cur->iec_vat != ied_vat_active) return;  /* TCP session not active */
     adsl_vchact_cur = adsl_vchact_cur->adsc_requ_next;  /* next in chain for this request */
   } while (adsl_vchact_cur);
   /* all TCP sessions are connected                                   */
   adsl_vchact_cur = adsp_virch_req->adsc_virch_act_ch;  /* chain active virus checking connections */
   while (adsl_vchact_cur) {                /* loop over all TCP sessions */
     m_send_first_packet( adsl_vchact_cur );  /* send the first packet */
     adsl_vchact_cur = adsl_vchact_cur->adsc_requ_next;  /* next in chain for this request */
   }
   m_time_set( &adsp_virch_req->dsc_timer_ele, FALSE );  /* set the timer */
} /* end m_check_first_packet()                                        */
#endif
#ifdef TRY_110722_01                        /* check if all connected  */
#ifndef B150128
/*
   m_check_first_packet() is always called in critical section dsg_global_lock
*/
#endif
/** check if all TCP connections are connected now, to send first packet */
static BOOL m_check_first_packet( struct dsd_virch_request *adsp_virch_req ) {
   struct dsd_virch_active *adsl_vchact_cur;  /* active virus checking connection */

#ifdef TRY_120120_01                        /* send first record only once */
   if (adsp_virch_req->boc_first_record) {  /* first record has been sent */
     return TRUE;                           /* all TCP connections active */
   }
#endif
   adsl_vchact_cur = adsp_virch_req->adsc_virch_act_ch;  /* chain active virus checking connections */
   if (adsl_vchact_cur == NULL) {
/* to-do 26.12.07 KB error message */
     return FALSE;
   }
#ifdef OLD01
   do {                                     /* loop over all TCP sessions */
     if (adsl_vchact_cur->imc_ind_conn >= 0) return;  /* check index of last connect */
     adsl_vchact_cur = adsl_vchact_cur->adsc_requ_next;  /* next in chain for this request */
   } while (adsl_vchact_cur);
#endif
   do {                                     /* loop over all TCP sessions */
     if (adsl_vchact_cur->iec_vat != ied_vat_active) return FALSE;  /* TCP session not active */
     adsl_vchact_cur = adsl_vchact_cur->adsc_requ_next;  /* next in chain for this request */
   } while (adsl_vchact_cur);
   /* all TCP sessions are connected                                   */
#ifdef TRY_120120_01                        /* send first record only once */
   adsp_virch_req->boc_first_record = TRUE;  /* first record has been sent */
#endif
   adsp_virch_req->boc_send_active = FALSE;  /* send is not active     */
   adsl_vchact_cur = adsp_virch_req->adsc_virch_act_ch;  /* chain active virus checking connections */
   while (adsl_vchact_cur) {                /* loop over all TCP sessions */
     m_send_first_packet( adsl_vchact_cur );  /* send the first packet */
     adsl_vchact_cur = adsl_vchact_cur->adsc_requ_next;  /* next in chain for this request */
   }
#ifdef B150128
   m_continue_send( adsp_virch_req );       /* send more data          */
#endif
#ifndef B150128
   m_continue_send( adsp_virch_req, TRUE );  /* send more data         */
#endif
   if (adsp_virch_req->dsc_timer_ele.vpc_chain_2 == FALSE) {  /* timer not set */
     m_time_set( &adsp_virch_req->dsc_timer_ele, FALSE );  /* set the timer */
   }
   return TRUE;                             /* all TCP connections active */
} /* end m_check_first_packet()                                        */

/** continue to send for this request                                  */
#ifdef B150128
static void m_continue_send( struct dsd_virch_request *adsp_virch_req ) {
#ifdef FORKEDIT
}
#endif
#endif
#ifndef B150128
static void m_continue_send( struct dsd_virch_request *adsp_virch_req, BOOL bop_lock ) {
#endif
   int        iml1, iml2;                   /* working-variables       */
   BOOL       bol1;                         /* working-variable        */
   BOOL       bol_send_active;              /* sending is active       */
   BOOL       bol_all_sent;                 /* all data have been sent */
#ifndef B150620
   BOOL       bol_send_more;                /* more data to send       */
#endif
   struct dsd_se_vch_req_1 *adsl_vchreq1_first;  /* first to process   */
   struct dsd_se_vch_req_1 *adsl_vchreq1_last;  /* last to process     */
   struct dsd_virch_active *adsl_vchact_w1;  /* active virus checking connection */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working-variable        */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */

#define ADSL_SE_VCH_CONTR_1 ((struct dsd_se_vch_contr_1 *) adsp_virch_req->ac_control_area)  /* service virus checking control area */
#ifdef DEBUG_120122_01                      /* sending to ICAP stops   */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXXH", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "DEBUG_120122_01 l%05d thread=%d - m_continue_send() ADSL_SE_VCH_CONTR_1=%p adsc_sevchreq1=%p boc_wait_window=%d ilc_window_1=%lld ilc_window_2=%lld diff=%lld imc_max_diff_window=%d.",
                     __LINE__, HL_GET_THREAD, ADSL_SE_VCH_CONTR_1, ADSL_SE_VCH_CONTR_1->adsc_sevchreq1,
                     ADSL_SE_VCH_CONTR_1->boc_wait_window,  /* wait till window smaller */
                     ADSL_SE_VCH_CONTR_1->ilc_window_1,
                     ADSL_SE_VCH_CONTR_1->ilc_window_2,
                     (HL_LONGLONG) (ADSL_SE_VCH_CONTR_1->ilc_window_1 - ADSL_SE_VCH_CONTR_1->ilc_window_2),
                     ADSL_SE_VCH_CONTR_1->imc_max_diff_window );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
#ifndef B120124
   bol_all_sent = FALSE;                    /* not all data have been sent */
#endif
#ifndef TRY_120124_01
   adsl_vchreq1_first = ADSL_SE_VCH_CONTR_1->adsc_sevchreq1->adsc_next;  /* after file-name */
   if (adsl_vchreq1_first == NULL) {        /* nothing in chain        */
#ifdef DEBUG_120122_01                      /* sending to ICAP stops   */
     if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data     */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXXF", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id             */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "DEBUG_120122_01 l%05d thread=%d - m_continue_send() adsl_vchreq1_first == NULL ADSL_SE_VCH_CONTR_1->adsc_sevchreq1=%p.",
                       __LINE__, HL_GET_THREAD, ADSL_SE_VCH_CONTR_1->adsc_sevchreq1 );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content            /* content of text / data  */
         = (char *) (ADSL_WTR_G1 + 1);
       ADSL_WTR_G1->imc_length = iml1;      /* length of text / data   */
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
     }
#endif
#ifdef B120124
     return;                                /* all done                */
#else
     goto p_ret_00;                         /* return from this routine */
#endif
   }
#endif
#ifdef TRY_120124_01
   adsl_vchreq1_first = ADSL_SE_VCH_CONTR_1->adsc_sevchreq1;  /* get request */
#endif
   while (adsl_vchreq1_first->iec_stat != ied_vchstat_active) {  /* data already sent */
     adsl_vchreq1_first = adsl_vchreq1_first->adsc_next;  /* get next in chain */
#ifndef DEBUG_120122_01                     /* sending to ICAP stops   */
#ifdef B120124
     if (adsl_vchreq1_first == NULL) return;  /* end of chain reached  */
#else
     if (adsl_vchreq1_first == NULL) {      /* end of chain reached  */
       goto p_ret_00;                       /* return from this routine */
     }
#endif
#else
     if (adsl_vchreq1_first == NULL) {      /* end of chain reached  */
       if ((img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) == 0) goto p_ret_00;  /* no Virus checking */
       int    iml1;                         /* working-variable        */
       struct dsd_wsp_trace_1 *adsl_wt1_w1;  /* WSP trace control record */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data     */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXXG", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id             */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "DEBUG_120122_01 l%05d thread=%d - m_continue_send() iec_stat != ied_vchstat_active ADSL_SE_VCH_CONTR_1->adsc_sevchreq1=%p.",
                       __LINE__, HL_GET_THREAD, ADSL_SE_VCH_CONTR_1->adsc_sevchreq1 );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content            /* content of text / data  */
         = (char *) (ADSL_WTR_G1 + 1);
       ADSL_WTR_G1->imc_length = iml1;      /* length of text / data   */
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
       goto p_ret_00;                       /* end of chain reached    */
     }
#endif
   }
#ifndef B150620

   p_send_20:                               /* retry to send data      */
#endif
   if (adsp_virch_req->dsc_timer_ele.vpc_chain_2) {  /* timer set      */
     m_time_rel( &adsp_virch_req->dsc_timer_ele );  /* release timer   */
   }
#ifdef B120124
   bol_all_sent = FALSE;                    /* not all data have been sent */
#endif
   adsl_vchreq1_last = adsl_vchreq1_first;  /* get remaining chain     */
   iml1 = 0;                                /* data sent               */
   iml2 = ADSL_SE_VCH_CONTR_1->imc_max_diff_window / 2;  /* maximum halve window */
#ifdef B151027
   while (TRUE) {                           /* loop over remaining chain */
#ifdef XYZ1
     if ((ADSL_SE_VCH_CONTR_1->ilc_window_2 - ADSL_SE_VCH_CONTR_1->ilc_window_1)
           > D_WINDOW_SEND) {
       break;
     }
#endif
     adsl_vchreq1_last->iec_stat = ied_vchstat_sent;  /* data have been sent */
#ifdef B150101
     adsl_gai1_w1 = adsl_vchreq1_last->adsc_gai1_data;  /* get data    */
     while (adsl_gai1_w1) {                 /* loop over all gather structures */
       iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     }
     if (adsl_vchreq1_last->iec_vchreq1 == ied_vchreq_eof) {  /* End-of-File */
       bol_all_sent = TRUE;                 /* all data have been sent */
     }
#endif
#ifndef B150101
     if (adsl_vchreq1_last->iec_vchreq1 != ied_vchreq_filename) {  /* filename */
       adsl_gai1_w1 = adsl_vchreq1_last->adsc_gai1_data;  /* get data  */
       while (adsl_gai1_w1) {               /* loop over all gather structures */
         iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       }
       if (adsl_vchreq1_last->iec_vchreq1 == ied_vchreq_eof) {  /* End-of-File */
         bol_all_sent = TRUE;               /* all data have been sent */
       }
     }
#endif
     if (adsl_vchreq1_last->adsc_next == NULL) break;  /* is last in chain */
     if (iml1 >= iml2) break;               /* maximum length to send reached */
     adsl_vchreq1_last = adsl_vchreq1_last->adsc_next;  /* get next in chain */
   }
#endif
#ifndef B151027
   while (TRUE) {                           /* loop over remaining chain */
     if (adsl_vchreq1_last->iec_stat != ied_vchstat_done) {  /* data already sent */
       adsl_vchreq1_last->iec_stat = ied_vchstat_sent;  /* data have been sent */
       if (adsl_vchreq1_last->iec_vchreq1 != ied_vchreq_filename) {  /* filename */
         adsl_gai1_w1 = adsl_vchreq1_last->adsc_gai1_data;  /* get data  */
         while (adsl_gai1_w1) {             /* loop over all gather structures */
           iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
           adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
         }
         if (adsl_vchreq1_last->iec_vchreq1 == ied_vchreq_eof) {  /* End-of-File */
           bol_all_sent = TRUE;             /* all data have been sent */
         }
       }
     }
     if (adsl_vchreq1_last->adsc_next == NULL) break;  /* is last in chain */
     if (iml1 >= iml2) break;               /* maximum length to send reached */
     adsl_vchreq1_last = adsl_vchreq1_last->adsc_next;  /* get next in chain */
   }
#endif
   ADSL_SE_VCH_CONTR_1->ilc_window_2 += iml1;
#ifndef B150620
   bol_send_more = adsl_vchreq1_last->adsc_next != NULL;  /* more data to send */
   if (   (bol_send_more)                   /* more data in chain      */
       && (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH)) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSFC1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
#ifdef B150707
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "send data to virus-checker, but more data available - flow-control",
                     __LINE__, HL_GET_THREAD );
#endif
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "l%05d send data to virus-checker, but more data available - flow-control",
                     __LINE__ );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
   adsp_virch_req->boc_send_active = TRUE;  /* send is active          */
   bol_send_active = FALSE;                 /* sending is not active   */
#ifdef B150128
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
#endif
#ifndef B150128
   if (bop_lock == FALSE) {                 /* not called in critical section */
     dsg_global_lock.m_enter();             /* enter CriticalSection   */
   }
#endif
#ifdef DEBUG_120122_01                      /* sending to ICAP stops   */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     int      iml1;                         /* working-variable        */
     struct dsd_wsp_trace_1 *adsl_wt1_w1;   /* WSP trace control record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXX7", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "DEBUG_120122_01 l%05d thread=%d - after  lock-enter",
                     __LINE__, HL_GET_THREAD );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
   adsl_vchact_w1 = adsp_virch_req->adsc_virch_act_ch;  /* chain active virus checking connections */
   while (adsl_vchact_w1) {                 /* loop over all active TCP sessions */
#ifdef DEBUG_110722_01                      /* do not send before connected */
     if (adsl_vchact_w1->iec_vat != ied_vat_active) {  /* TCP session active */
       m_hlnew_printf( HLOG_WARN1, "xs-gw-serv-vch-icap l%05d TCP send to session not active",
                       __LINE__ );
     }
#endif
     bol1 = m_send_chunk( adsl_vchact_w1, adsl_vchreq1_first, adsl_vchreq1_last );
     if (bol1) {                            /* could not yet send data */
       bol_send_active = TRUE;              /* sending is active       */
     }
     adsl_vchact_w1 = adsl_vchact_w1->adsc_requ_next;  /* next in chain for this request */
   }
   if (bol_send_active) {                   /* send is active          */
#ifdef B150128
     dsg_global_lock.m_leave();             /* leave CriticalSection   */
#endif
#ifndef B150128
     if (bop_lock == FALSE) {               /* not called in critical section */
       dsg_global_lock.m_leave();           /* leave CriticalSection   */
     }
#endif
     m_time_set( &adsp_virch_req->dsc_timer_ele, FALSE );  /* set the timer */
     return;                                /* all done                */
   }
   while (TRUE) {                           /* loop over requests sent */
     adsl_vchreq1_first->iec_stat = ied_vchstat_done;  /* area can be freed */
#ifdef XYZ1
     adsl_gai1_w1 = adsl_vchreq1_first->adsc_gai1_data;  /* get data   */
     while (adsl_gai1_w1) {                 /* loop over all gather structures */
       ADSL_SE_VCH_CONTR_1->ilc_window_1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     }
#endif
     if (adsl_vchreq1_first == adsl_vchreq1_last) break;  /* all requests marked */
     adsl_vchreq1_first = adsl_vchreq1_first->adsc_next;  /* get next in chain */
   }
   adsp_virch_req->boc_send_active = FALSE;  /* send is not active     */
#ifdef B150128
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
#endif
#ifndef B150128
   if (bop_lock == FALSE) {                 /* not called in critical section */
     dsg_global_lock.m_leave();             /* leave CriticalSection   */
   }
#endif
#ifndef B150620
   if (bol_send_more) {                     /* more data to send       */
     goto p_send_20;                        /* retry to send data      */
   }
#endif
#ifndef B120124

   p_ret_00:                                /* return from this routine */
#endif
#ifdef B120124
   if (ADSL_SE_VCH_CONTR_1->boc_wait_window) {  /* wait till window smaller */
#ifdef FORKEDIT
   }
#endif
#else
   if (   (ADSL_SE_VCH_CONTR_1->boc_wait_window)  /* wait till window smaller */
       && ((ADSL_SE_VCH_CONTR_1->ilc_window_1 - ADSL_SE_VCH_CONTR_1->ilc_window_2)
              <= ADSL_SE_VCH_CONTR_1->imc_max_diff_window)) {
#endif
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_service_requ() boc_wait_window set",
                     __LINE__ );
#endif
     ADSL_SE_VCH_CONTR_1->boc_wait_window = FALSE;
     if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data     */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSCBH", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id             */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "activate SDH because of wait-window - ac_control_area=%p.",
                       ADSL_SE_VCH_CONTR_1 );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content            /* content of text / data  */
         = (char *) (ADSL_WTR_G1 + 1);
       ADSL_WTR_G1->imc_length = iml1;      /* length of text / data   */
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
     }
     m_wsp_s_ent_notify( adsp_virch_req->adsc_virch_session->adsc_conn1,
                         (char *) adsp_virch_req->adsc_virch_session - sizeof(struct dsd_service_aux_1),
                         adsp_virch_req->adsc_virch_session->imc_signal );
   }
#undef ADSL_SE_VCH_CONTR_1
   if (bol_all_sent) {                      /* all data have been sent */
     m_time_set( &adsp_virch_req->dsc_timer_ele, FALSE );  /* set the timer */
   }
   return;                                  /* all done                */
} /* end m_continue_send()                                             */
#endif

/** send the first TCP packet                                          */
static BOOL m_send_first_packet( struct dsd_virch_active *adsp_vchact ) {
   BOOL       bol1;                         /* working-variable        */
   int        iml1, iml2, iml3, iml4;       /* working-variables       */
   int        iml_len_fn;                   /* length file-name        */
   char       *achl_lower;                  /* lower boundary of buffer */
   char       *achl_upper;                  /* upper boundary of buffer */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_virch_send *adsl_virch_send;  /* send to virus checker structure */
   struct dsd_gather_i_1 *adsl_gai1_send;   /* block to be sent        */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working-variable        */
   struct dsd_gather_i_1 *adsl_gai1_wtr;    /* for WSP trace           */
   struct dsd_gather_i_1 *adsl_gai1_res_hdr;
   struct dsd_gather_i_1 *adsl_gai1_res_body;
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w4;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   struct dsd_hl_aux_epoch_1 dsl_hl_aux_epoch_1;  /* retrieve time and day */
#ifndef B110607
   char       chrl_file_name[ 2048 ];       /* contiguous area for file name */
#endif

#define ADSL_VIRCH_REQ_G (adsp_vchact->adsc_virch_requ)
#define ADSL_VIRCH_CONTR ((struct dsd_se_vch_contr_1 *) ADSL_VIRCH_REQ_G->ac_control_area)
#define ADSL_VIRCH_C_REQ_FN (ADSL_VIRCH_CONTR->adsc_sevchreq1)
   if (   (ADSL_VIRCH_C_REQ_FN == NULL)
       || (ADSL_VIRCH_C_REQ_FN->iec_vchreq1 != ied_vchreq_filename)) {  /* filename */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-serv-vch-icap l%05d m_send_first_packet() filename not found",
                     __LINE__ );
     return FALSE;                          /* report error            */
   }
   adsl_virch_send = (struct dsd_virch_send *) m_proc_alloc();
   achl_lower = (char *) (adsl_virch_send + 1);
   achl_upper = (char *) adsl_virch_send + LEN_TCP_RECV;
   achl_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_CUR ((struct dsd_gather_i_1 *) achl_upper)
   adsl_gai1_send = ADSL_GAI1_CUR;          /* this is data to be sent */
   switch (adsp_vchact->adsc_sevirch_entry->iec_vve) {  /* virus checker vendor */
     case ied_vve_kasp:                     /* Kaspersky               */
       ADSL_GAI1_CUR->achc_ginp_cur = (char *) ucrs_icap_rm_kasp_00;
       ADSL_GAI1_CUR->achc_ginp_end = (char *) ucrs_icap_rm_kasp_00 + sizeof(ucrs_icap_rm_kasp_00);
       ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain     */
       achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
       ADSL_GAI1_CUR->achc_ginp_cur = adsp_vchact->chrc_ineta;
       ADSL_GAI1_CUR->achc_ginp_end = adsp_vchact->chrc_ineta + strlen( adsp_vchact->chrc_ineta );
       ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain     */
       achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
       ADSL_GAI1_CUR->achc_ginp_cur = (char *) ucrs_icap_rm_kasp_01;
       ADSL_GAI1_CUR->achc_ginp_end = (char *) ucrs_icap_rm_kasp_01 + sizeof(ucrs_icap_rm_kasp_01);
       ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain     */
       achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
       break;
     case ied_vve_syman:                    /* Symantec                */
       ADSL_GAI1_CUR->achc_ginp_cur = (char *) ucrs_icap_rm_syman_00;
       ADSL_GAI1_CUR->achc_ginp_end = (char *) ucrs_icap_rm_syman_00 + sizeof(ucrs_icap_rm_syman_00);
       ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain     */
       achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
       break;
     case ied_vve_c_icap:                   /* c-icap                  */
       ADSL_GAI1_CUR->achc_ginp_cur = (char *) ucrs_icap_rm_c_icap_00;
       ADSL_GAI1_CUR->achc_ginp_end = (char *) ucrs_icap_rm_c_icap_00 + sizeof(ucrs_icap_rm_c_icap_00);
       ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain     */
       achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
       ADSL_GAI1_CUR->achc_ginp_cur = adsp_vchact->chrc_ineta;
       ADSL_GAI1_CUR->achc_ginp_end = adsp_vchact->chrc_ineta + strlen( adsp_vchact->chrc_ineta );
       ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain     */
       achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
       ADSL_GAI1_CUR->achc_ginp_cur = (char *) ucrs_icap_rm_c_icap_01;
       ADSL_GAI1_CUR->achc_ginp_end = (char *) ucrs_icap_rm_c_icap_01 + sizeof(ucrs_icap_rm_c_icap_01);
       ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain     */
       achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
       break;
   }
   ADSL_GAI1_CUR->achc_ginp_cur = adsp_vchact->chrc_ineta;
   ADSL_GAI1_CUR->achc_ginp_end = adsp_vchact->chrc_ineta + strlen( adsp_vchact->chrc_ineta );
   ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain         */
   achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
   ADSL_GAI1_CUR->achc_ginp_cur = (char *) ucrs_icap_rm_02;
   ADSL_GAI1_CUR->achc_ginp_end = (char *) ucrs_icap_rm_02 + sizeof(ucrs_icap_rm_02);
   ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain         */
   achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
   adsl_gai1_res_hdr = ADSL_GAI1_CUR;
   ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain         */
   achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
   ADSL_GAI1_CUR->achc_ginp_cur = (char *) ucrs_icap_rm_03;
   ADSL_GAI1_CUR->achc_ginp_end = (char *) ucrs_icap_rm_03 + sizeof(ucrs_icap_rm_03);
   ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain         */
   achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
   adsl_gai1_res_body = ADSL_GAI1_CUR;
   ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain         */
   achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
   ADSL_GAI1_CUR->achc_ginp_cur = (char *) ucrs_icap_rm_04;
   ADSL_GAI1_CUR->achc_ginp_end = (char *) ucrs_icap_rm_04 + sizeof(ucrs_icap_rm_04);
   ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain         */
   /* put file-name to be checked                                      */
   achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
   adsl_gai1_w1 = ADSL_VIRCH_C_REQ_FN->adsc_gai1_data;  /* get data    */
#ifdef B110607
   iml_len_fn = 0;                          /* clear length file-name  */
   while (adsl_gai1_w1) {                   /* loop over all gather structures */
     ADSL_GAI1_CUR->achc_ginp_cur = adsl_gai1_w1->achc_ginp_cur;
     ADSL_GAI1_CUR->achc_ginp_end = adsl_gai1_w1->achc_ginp_end;
     iml_len_fn += ADSL_GAI1_CUR->achc_ginp_end - ADSL_GAI1_CUR->achc_ginp_cur;
     ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain       */
     achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
#else
   if (adsl_gai1_w1 == NULL) {              /* no file name given      */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-serv-vch-icap.cpp l%05d m_send_first_packet() filename NULL",
                     __LINE__ );
     m_proc_free( adsl_virch_send );        /* free the buffer         */
     return FALSE;                          /* report error            */
   }
   /* send file name as URI RFC 3986                                   */
   if (adsl_gai1_w1->adsc_next == NULL) {   /* only one in chain       */
     achl_w1 = adsl_gai1_w1->achc_ginp_cur;
     iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
   } else {                                 /* need to copy to contiguous area */
     achl_w1 = chrl_file_name;              /* contiguous area for file name */
     do {                                   /* loop over parts         */
       iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       if ((achl_w1 + iml1) > (chrl_file_name + sizeof(chrl_file_name))) {
         m_hlnew_printf( HLOG_WARN1, "xs-gw-serv-vch-icap.cpp l%05d m_send_first_packet() filename too long",
                         __LINE__ );
         m_proc_free( adsl_virch_send );    /* free the buffer         */
         return FALSE;                      /* report error            */
       }
       memcpy( achl_w1, adsl_gai1_w1->achc_ginp_cur, iml1 );
       achl_w1 += iml1;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     } while (adsl_gai1_w1);
     iml1 = achl_w1 - chrl_file_name;       /* length of file name     */
     achl_w1 = chrl_file_name;              /* contiguous area for file name */
   }
   iml_len_fn = m_cpy_vx_vx( achl_lower, achl_upper - achl_lower, ied_chs_uri_1,
                             achl_w1, iml1, ied_chs_utf_8 );
   if (iml_len_fn <= 0) {                   /* could not copy file name */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-serv-vch-icap.cpp l%05d m_send_first_packet() copy file name failed",
                     __LINE__ );
     m_proc_free( adsl_virch_send );        /* free the buffer         */
     return FALSE;                          /* report error            */
   }
   ADSL_GAI1_CUR->achc_ginp_cur = achl_lower;
   achl_lower += iml_len_fn;
   ADSL_GAI1_CUR->achc_ginp_end = achl_lower;
   ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain         */
   achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
#endif
   ADSL_GAI1_CUR->achc_ginp_cur = (char *) ucrs_icap_rm_05;
   ADSL_GAI1_CUR->achc_ginp_end = (char *) ucrs_icap_rm_05 + sizeof(ucrs_icap_rm_05);
   ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain         */
   achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
   memset( &dsl_hl_aux_epoch_1, 0, sizeof(struct dsd_hl_aux_epoch_1) );
   dsl_hl_aux_epoch_1.ac_epoch_str = achl_lower;  /* epoch             */
   dsl_hl_aux_epoch_1.iec_chs_epoch = ied_chs_utf_8;  /* character set */
   dsl_hl_aux_epoch_1.inc_len_epoch = 64;   /* length epoch in elements */
   dsl_hl_aux_epoch_1.imc_epoch_val = time( NULL );  /* epoch value    */
   m_string_from_epoch( &dsl_hl_aux_epoch_1 );
   ADSL_GAI1_CUR->achc_ginp_cur = achl_lower;
   ADSL_GAI1_CUR->achc_ginp_end = achl_lower + dsl_hl_aux_epoch_1.inc_len_epoch;
   ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain         */
   achl_lower += dsl_hl_aux_epoch_1.inc_len_epoch;
   achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
   ADSL_GAI1_CUR->achc_ginp_cur = (char *) ucrs_icap_rm_06;
   ADSL_GAI1_CUR->achc_ginp_end = (char *) ucrs_icap_rm_06 + sizeof(ucrs_icap_rm_06);
   ADSL_GAI1_CUR->adsc_next = NULL;         /* is last in chain        */
   iml1 = iml_len_fn + (sizeof(ucrs_icap_rm_04) - 4) + (sizeof(ucrs_icap_rm_05) - 23);
   achl_lower += 8;                         /* space for number        */
   adsl_gai1_res_hdr->achc_ginp_cur = m_put_no( achl_lower, iml1 );
   adsl_gai1_res_hdr->achc_ginp_end = achl_lower;
   iml1 = iml_len_fn + (sizeof(ucrs_icap_rm_04) - 4) + sizeof(ucrs_icap_rm_05)
            + dsl_hl_aux_epoch_1.inc_len_epoch + sizeof(ucrs_icap_rm_06);
   achl_lower += 8;                         /* space for number        */
   adsl_gai1_res_body->achc_ginp_cur = m_put_no( achl_lower, iml1 );
   adsl_gai1_res_body->achc_ginp_end = achl_lower;
#ifndef B110607
   if (achl_lower > achl_upper) {           /* buffer was not long enough */
     m_hlnew_printf( HLOG_WARN1, "xs-gw-serv-vch-icap.cpp l%05d m_send_first_packet() buffer was not long enough",
                     __LINE__ );
     m_proc_free( adsl_virch_send );        /* free the buffer         */
     return FALSE;                          /* report error            */
   }
#endif
   adsp_vchact->ac_send_buf = adsl_virch_send;  /* current send buffer */
   adsl_wt1_w4 = NULL;                      /* no gathers to be traced */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     iml1 = 0;                              /* length                  */
     iml2 = 0;                              /* count gather            */
     adsl_gai1_w1 = adsl_gai1_send;         /* get gather to send      */
     do {                                   /* loop over parts         */
       iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       iml2++;                              /* count gather            */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     } while (adsl_gai1_w1);
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSFIB", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml2 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "send first packet to virus-checker %p length %d/0X%X in %d gather",
                     adsp_vchact, iml1, iml1, iml2 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml2;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
     if (img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2))  {  /* generate WSP trace record */
       adsl_wt1_w4 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       adsl_gai1_wtr = (struct dsd_gather_i_1 *) ((char *) adsl_wt1_w4 + LEN_TCP_RECV);  /* end of this piece of memory */
       adsl_gai1_w1 = adsl_gai1_send;       /* get gather to send      */
       do {                                 /* loop over parts         */
         adsl_gai1_wtr--;                   /* space for gather        */
         if (((char *) adsl_gai1_wtr) < ((char *) adsl_wt1_w4)) break;  /* too many gather */
         memcpy( adsl_gai1_wtr, adsl_gai1_w1, sizeof(struct dsd_gather_i_1) );
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       } while (adsl_gai1_w1);
     }
   }
   iml1 = adsp_vchact->dsc_tcpcomp.m_send_gather(
            adsl_gai1_send,
            &adsl_virch_send->adsc_gai1_send );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_send_first_packet() m_send_gather() returned %d gather=%p.",
                   __LINE__, iml1, adsl_virch_send->adsc_gai1_send );
#endif
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     iml2 = 0;                              /* length                  */
     iml3 = 0;                              /* count gather            */
     adsl_gai1_w1 = adsl_virch_send->adsc_gai1_send;  /* get gather to send */
     while (adsl_gai1_w1) {                 /* loop over parts         */
       iml2 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       iml3++;                              /* count gather            */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     if ((adsl_wt1_w4) && (iml1 <= 0)) {
       adsl_wt1_w1 = adsl_wt1_w4;           /* get old block           */
       adsl_wt1_w4 = NULL;                  /* do not free later       */
     } else {
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     }
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSFIA", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml2 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "after send first packet to virus-checker %p length-sent %d/0X%X length-remaining %d/0X%X in %d gather",
                     adsp_vchact, iml1, iml1, iml2, iml2, iml3 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml2;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (adsl_wt1_w4) {                     /* we append the data      */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml2 = iml1;                         /* length of data sent     */
       adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_wt1_w4 + LEN_TCP_RECV) - 1;  /* here is first gather */
       achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* start of data        */
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
           iml3 = adsl_gai1_w1->achc_ginp_end - achl_w3;
           if (iml3 > iml2) iml3 = iml2;
           iml4 = achl_w2 - achl_w4;
           if (iml4 > iml3) iml4 = iml3;
           memcpy( achl_w4, achl_w3, iml4 );
           achl_w4 += iml4;
           achl_w3 += iml4;
           ADSL_WTR_G2->imc_length += iml4;  /* length of text / data  */
           iml2 -= iml4;                    /* length to be copied     */
           if (iml2 <= 0) break;
           if (achl_w3 < adsl_gai1_w1->achc_ginp_end) break;
           if (adsl_gai1_w1 == adsl_gai1_wtr) break;
           adsl_gai1_w1--;
           if (((char *) adsl_gai1_w1) < ((char *) adsl_wt1_w4)) {  /* too many gather */
             m_hlnew_printf( HLOG_WARN1, "HWSPVCICAPHCnnnnW Error WSP Trace data sent could not be traced - remaining %d/0X%X.",
                             iml2, iml2 );
             break;
           }
           achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* start of data    */
           if (achl_w4 >= achl_w2) break;
         }
         achl_w1 = achl_w2;                 /* set end of this area    */
       } while (iml2 > 0);
       m_proc_free( adsl_wt1_w4 );          /* free block with gather  */
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (adsl_virch_send->adsc_gai1_send == NULL) {  /* all sent         */
     m_proc_free( adsl_virch_send );        /* free the buffer         */
     adsp_vchact->ac_send_buf = NULL;       /* no current send buffer  */
     return FALSE;                          /* sending not active      */
   }
   adsp_vchact->dsc_tcpcomp.m_sendnotify();
   return TRUE;
#undef ADSL_GAI1_CUR
#undef ADSL_VIRCH_REQ_G
#undef ADSL_VIRCH_CONTR
#undef ADSL_VIRCH_C_REQ_FN
} /* end m_send_first_packet()                                         */

/** send the TCP packets as chunks                                     */
static BOOL m_send_chunk( struct dsd_virch_active *adsp_vchact,
                          struct dsd_se_vch_req_1 *adsp_vchreq1_first,
                          struct dsd_se_vch_req_1 *adsp_vchreq1_last ) {
   BOOL       bol1;                         /* working-variable        */
#ifdef TRY_120618_01                        /* do not send file-name   */
   BOOL       bol_data;                     /* send data have been created */
#endif
   int        iml1, iml2, iml3, iml4;       /* working-variables       */
   int        iml_len_data;                 /* length data             */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   char       *achl_lower;                  /* lower boundary of buffer */
   char       *achl_upper;                  /* upper boundary of buffer */
   struct dsd_virch_send *adsl_virch_send;  /* send to virus checker structure */
   struct dsd_gather_i_1 *adsl_gai1_send;   /* block to be sent        */
   struct dsd_gather_i_1 *adsl_gai1_length;  /* store length here      */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working-variable        */
   struct dsd_gather_i_1 *adsl_gai1_wtr;    /* for WSP trace           */
   struct dsd_se_vch_req_1 *adsl_vchreq1_w1;  /* working-variable      */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w4;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */

#ifdef TRY_120618_01                        /* do not send file-name   */
   bol_data = FALSE;                        /* reset send data have been created */
#endif
   adsl_virch_send = (struct dsd_virch_send *) m_proc_alloc();
   achl_lower = (char *) (adsl_virch_send + 1);
   achl_upper = (char *) adsl_virch_send + LEN_TCP_RECV;
   achl_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_CUR ((struct dsd_gather_i_1 *) achl_upper)
   adsl_gai1_send = ADSL_GAI1_CUR;          /* this is data to be sent */
   adsl_vchreq1_w1 = adsp_vchreq1_first;    /* get first request       */

   p_se_chunk_20:                           /* send request            */
#ifndef B151027
   if (adsl_vchreq1_w1->iec_stat == ied_vchstat_done) {
     goto p_se_chunk_28;                    /* request counted         */
   }
#endif
   if (adsl_vchreq1_w1->iec_vchreq1 == ied_vchreq_eof) {  /* End-of-File */
#ifdef XYZ1
     adsp_vchact->boc_wait_recv = TRUE;  /* wait for receive data   */
#endif
#ifdef TRY_120618_01                        /* do not send file-name   */
     bol_data = TRUE;                       /* set send data have been created */
#endif
     adsp_vchact->iec_var = ied_var_start;  /* start of receive data */
     ADSL_GAI1_CUR->achc_ginp_cur = (char *) ucrs_icap_last;
     ADSL_GAI1_CUR->achc_ginp_end = (char *) ucrs_icap_last + sizeof(ucrs_icap_last);
     achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
     goto p_se_chunk_40;                    /* output data complete    */
   }
#ifdef TRY_120618_01                        /* do not send file-name   */
   if (adsl_vchreq1_w1->iec_vchreq1 == ied_vchreq_filename) {  /* filename */
     if (adsl_vchreq1_w1 != adsp_vchreq1_last) {  /* was not last request */
       adsl_vchreq1_w1 = adsl_vchreq1_w1->adsc_next;  /* get next request in chain */
       goto p_se_chunk_20;                  /* send request            */
     }
     goto p_se_chunk_40;                    /* output data complete    */
   }
   bol_data = TRUE;                         /* set send data have been created */
#endif
#ifdef XYZ1
#ifndef B151027
   if (adsl_vchreq1_w1->iec_stat == ied_vchstat_done) {
     m_hlnew_printf( HLOG_WARN1, "HWSPVCICAPHCnnnnW Error send chunk that has state ied_vchstat_done",
                     adsl_vchreq1_w1 );
   }
#endif
#endif
#ifdef DEBUG_151027_01                      /* data sent multiple times */
   if (adsl_vchreq1_w1 == adss_vchreq1_debug_1) {
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_send_chunk() adsl_vchreq1_w1 %p already sent",
                     __LINE__, adsl_vchreq1_w1 );
   }
   adss_vchreq1_debug_1 = adsl_vchreq1_w1;
#endif
   adsl_gai1_w1 = adsl_vchreq1_w1->adsc_gai1_data;  /* get gather data */
   iml_len_data = 0;                        /* length data             */
   adsl_gai1_length = ADSL_GAI1_CUR;        /* store length here       */
   achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
   do {                                     /* loop over all gather structures */
     ADSL_GAI1_CUR->achc_ginp_cur = adsl_gai1_w1->achc_ginp_cur;
     ADSL_GAI1_CUR->achc_ginp_end = adsl_gai1_w1->achc_ginp_end;
     iml_len_data += ADSL_GAI1_CUR->achc_ginp_end - ADSL_GAI1_CUR->achc_ginp_cur;
     ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain       */
     achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   } while (adsl_gai1_w1);
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSCOL", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "send request %p length %d/0X%X iec_stat %d.",
                     adsl_vchreq1_w1, iml_len_data, iml_len_data, adsl_vchreq1_w1->iec_stat );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#ifndef B141231
   if (iml_len_data <= 0) {                 /* length of data invalid  */
     m_proc_free( adsl_virch_send );        /* free the buffer         */
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_send_chunk() length to send %d invalid",
                     __LINE__, iml_len_data );
     return FALSE;                          /* sending not active      */
   }
#endif
   achl_lower += 8;                         /* space for length        */
   achl_w1 = achl_lower;                    /* end of space            */
   *(--achl_w1) = CHAR_LF;
   *(--achl_w1) = CHAR_CR;
   do {                                     /* loop output length hexadecimal */
     *(--achl_w1) = chrstrans[ iml_len_data & 0X0F ];
     iml_len_data >>= 4;                    /* shift value             */
   } while (iml_len_data);
   adsl_gai1_length->achc_ginp_cur = achl_w1;
   adsl_gai1_length->achc_ginp_end = achl_lower;
   adsl_gai1_length->adsc_next = adsl_gai1_length - 1;
   ADSL_GAI1_CUR->achc_ginp_cur = achl_lower - 2;  /* CR LF            */
   ADSL_GAI1_CUR->achc_ginp_end = achl_lower;
   ADSL_GAI1_CUR->adsc_next = ADSL_GAI1_CUR - 1;  /* set chain         */
   achl_upper -= sizeof(struct dsd_gather_i_1);  /* next gather structure */
#ifndef B151027

   p_se_chunk_28:                           /* request counted         */
#endif
   if (adsl_vchreq1_w1 != adsp_vchreq1_last) {  /* was not last request */
     adsl_vchreq1_w1 = adsl_vchreq1_w1->adsc_next;  /* get next request in chain */
     goto p_se_chunk_20;                    /* send request            */
   }

   p_se_chunk_40:                           /* output data complete    */
#ifdef TRY_120618_01                        /* do not send file-name   */
   if (bol_data == FALSE) {                 /* no send data have been created */
     m_proc_free( adsl_virch_send );        /* free the buffer         */
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_send_chunk() nothing found to be sent",
                     __LINE__ );
     return FALSE;                          /* sending not active      */
   }
#endif
   (ADSL_GAI1_CUR + 1)->adsc_next = NULL;   /* set last in chain       */
   adsp_vchact->ac_send_buf = adsl_virch_send;  /* current send buffer */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     iml1 = 0;                              /* length                  */
     iml2 = 0;                              /* count gather            */
     adsl_gai1_w1 = adsl_gai1_send;         /* get gather to send      */
     do {                                   /* loop over parts         */
       iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       iml2++;                              /* count gather            */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     } while (adsl_gai1_w1);
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSCHB", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml2 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "send chunk to virus-checker %p length %d/0X%X in %d gather",
                     adsp_vchact, iml1, iml1, iml2 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml2;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
     if (img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2))  {  /* generate WSP trace record */
       adsl_wt1_w4 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       adsl_gai1_wtr = (struct dsd_gather_i_1 *) ((char *) adsl_wt1_w4 + LEN_TCP_RECV);  /* end of this piece of memory */
       adsl_gai1_w1 = adsl_gai1_send;       /* get gather to send      */
       do {                                 /* loop over parts         */
         adsl_gai1_wtr--;                   /* space for gather        */
         if (((char *) adsl_gai1_wtr) < ((char *) adsl_wt1_w4)) break;  /* too many gather */
         memcpy( adsl_gai1_wtr, adsl_gai1_w1, sizeof(struct dsd_gather_i_1) );
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       } while (adsl_gai1_w1);
     }
   }
   iml1 = adsp_vchact->dsc_tcpcomp.m_send_gather(
            adsl_gai1_send,
            &adsl_virch_send->adsc_gai1_send );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_send_chunk() m_send_gather() returned %d gather=%p.",
                   __LINE__, iml1, adsl_virch_send->adsc_gai1_send );
#endif
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     iml2 = 0;                              /* length                  */
     iml3 = 0;                              /* count gather            */
     adsl_gai1_w1 = adsl_virch_send->adsc_gai1_send;  /* get gather to send */
     while (adsl_gai1_w1) {                 /* loop over parts         */
       iml2 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       iml3++;                              /* count gather            */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     if ((adsl_wt1_w4) && (iml1 <= 0)) {
       adsl_wt1_w1 = adsl_wt1_w4;           /* get old block           */
       adsl_wt1_w4 = NULL;                  /* do not free later       */
     } else {
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     }
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSCHA", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml2 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "after send chunk to virus-checker %p length-sent %d/0X%X length-remaining %d/0X%X in %d gather",
                     adsp_vchact, iml1, iml1, iml2, iml2, iml3 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml2;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (adsl_wt1_w4) {                     /* we append the data      */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml2 = iml1;                         /* length of data sent     */
       adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_wt1_w4 + LEN_TCP_RECV) - 1;  /* here is first gather */
       achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* start of data        */
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
           iml3 = adsl_gai1_w1->achc_ginp_end - achl_w3;
           if (iml3 > iml2) iml3 = iml2;
           iml4 = achl_w2 - achl_w4;
           if (iml4 > iml3) iml4 = iml3;
           memcpy( achl_w4, achl_w3, iml4 );
           achl_w4 += iml4;
           achl_w3 += iml4;
           ADSL_WTR_G2->imc_length += iml4;  /* length of text / data  */
           iml2 -= iml4;                    /* length to be copied     */
           if (iml2 <= 0) break;
           if (achl_w3 < adsl_gai1_w1->achc_ginp_end) break;
           if (adsl_gai1_w1 == adsl_gai1_wtr) break;
           adsl_gai1_w1--;
           if (((char *) adsl_gai1_w1) < ((char *) adsl_wt1_w4)) {  /* too many gather */
             m_hlnew_printf( HLOG_WARN1, "HWSPVCICAPHCnnnnW Error WSP Trace data sent could not be traced - remaining %d/0X%X.",
                             iml2, iml2 );
             break;
           }
           achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* start of data    */
           if (achl_w4 >= achl_w2) break;
         }
         achl_w1 = achl_w2;                 /* set end of this area    */
       } while (iml2 > 0);
       m_proc_free( adsl_wt1_w4 );          /* free block with gather  */
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (adsl_virch_send->adsc_gai1_send == NULL) {  /* all sent         */
     m_proc_free( adsl_virch_send );        /* free the buffer         */
     adsp_vchact->ac_send_buf = NULL;       /* no current send buffer  */
     return FALSE;                          /* sending not active      */
   }
   adsp_vchact->dsc_tcpcomp.m_sendnotify();
   return TRUE;
#undef ADSL_GAI1_CUR
} /* end m_send_chunk()                                                */

/** select ICAP server random                                          */
static struct dsd_se_vcicaphttp_entry * m_get_se_random( struct dsd_random_server *adsp_rse ) {
   int        iml_w1;                       /* working-variable        */
   int        iml_random;                   /* get random number       */
   struct dsd_se_vcicaphttp_entry *adsl_se_w1;  /* working-variable server-entry */

   if (adsp_rse->imc_no_checked >= adsp_rse->adsc_sg->imc_no_vch_se) {  /* compare number of already checked servers */
     return NULL;
   }
   if (adsp_rse->adsc_sg->imc_no_vch_se == 1) {  /* only one server-entry */
     adsp_rse->imc_no_checked = 1;          /* set number of already checked servers */
     return adsp_rse->adsc_sg->adsc_se_ch;  /* return the only server-entry */
   }
   iml_w1 = adsp_rse->adsc_sg->imc_no_vch_se - adsp_rse->imc_no_checked;
   iml_random = 0;
   if (iml_w1 > 1) {                        /* get random              */
     iml_random = m_get_random_number( iml_w1 );
   }
   adsl_se_w1 = adsp_rse->adsc_sg->adsc_se_ch;  /* get chain server-entry */

   p_rand_20:                               /* check this server-entry */
   iml_w1 = 0;                              /* clear check in array    */
   while (iml_w1 < adsp_rse->imc_no_checked) {
     if (adsl_se_w1 == adsp_rse->adsrc_checked[ iml_w1 ]) {
       goto p_rand_40;                      /* get next server-entry   */
     }
     iml_w1++;                              /* this entry processed    */
   }
   if (iml_random == 0) {                   /* this is entry searched for */
     adsp_rse->adsrc_checked[ iml_w1 ] = adsl_se_w1;  /* save this entry */
     adsp_rse->imc_no_checked++;            /* increment number of already checked servers */
     return adsl_se_w1;
   }
   iml_random--;                            /* overread this entry     */

   p_rand_40:                               /* get next server-entry   */
   adsl_se_w1 = adsl_se_w1->adsc_next;      /* get next in chain       */
   goto p_rand_20;                          /* check this server-entry */
} /* end m_get_se_random()                                             */

#ifdef OLD01
static void m_virch_do_connect( struct dsd_virch_active *adsp_vchact ) {
   int        iml_rc;                       /* return code             */
   int        iml_errno;                    /* error number            */
   int        iml_socket;                   /* socket for connect      */
   socklen_t  iml_len_soa;                  /* length struct sockaddr  */
   socklen_t  iml_bindlen;                  /* length struct sockaddr  */
   struct sockaddr *adsl_soa_bind;          /* address information for bind */

   p_conn_00:                               /* try to connect          */
   m_set_connect_p1( &adsp_vchact->dsc_soa, &iml_len_soa,
                     adsp_vchact->adsc_sevirch_entry->adsc_server_ineta,
                     adsp_vchact->imc_ind_conn );
   ((struct sockaddr_in *) &adsp_vchact->dsc_soa)->sin_port = IP_htons( adsp_vchact->adsc_sevirch_entry->imc_port );
   iml_rc = IP_getnameinfo( (SOCKADDR *) &adsp_vchact->dsc_soa, iml_len_soa,
                            adsp_vchact->chrc_ineta, sizeof(adsp_vchact->chrc_ineta), 0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPCL0nnnW l%05d Cluster m_do_connect getnameinfo() returned %d %d",
                     __LINE__, iml_rc, D_TCP_ERROR );
     strcpy( adsp_vchact->chrc_ineta, "XXX" );
   }
   iml_socket = IP_socket( ((struct sockaddr *) &adsp_vchact->dsc_soa)->sa_family, SOCK_STREAM, IPPROTO_TCP );
   if (iml_socket < 0) {
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-E socket failed with code %d %d",
                     __LINE__, iml_socket, D_TCP_ERROR );
     return;                                /* all done                */
   }
   while (adsp_vchact->adsc_sevirch_entry->dsc_bind_multih.boc_bind_needed) {  /* flag bind() is needed */
     iml_bindlen = 0;                       /* set flag not valid      */
     switch (((struct sockaddr *) &adsp_vchact->dsc_soa)->sa_family) {
       case AF_INET:                        /* IPV4                    */
         if (&adsp_vchact->adsc_sevirch_entry->dsc_bind_multih.boc_ipv4 == FALSE) break;  /* IPV4 not supported */
         adsl_soa_bind = (struct sockaddr *) &adsp_vchact->adsc_sevirch_entry->dsc_bind_multih.dsc_soai4;
         iml_bindlen = sizeof(struct sockaddr_in);
         break;
       case AF_INET6:                       /* IPV6                    */
         if (&adsp_vchact->adsc_sevirch_entry->dsc_bind_multih.boc_ipv6 == FALSE) break;  /* IPV6 not supported */
         adsl_soa_bind = (struct sockaddr *) &adsp_vchact->adsc_sevirch_entry->dsc_bind_multih.dsc_soai6;
         iml_bindlen = sizeof(struct sockaddr_in6);
         break;
     }
     if (iml_bindlen == 0) {                /* flag not valid set      */
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W bind GW-OUT not possible",
                       __LINE__ );
//     D_TCP_CLOSE( iml_socket );           /* close socket again */
//     goto p_conn_40;                      /* check if still connect possible */
// 29.09.07 KB - to-do
//     return;                                /* all done                */
       break;                               /* ignore multihomed       */
     }
     iml_rc = IP_bind( iml_socket, adsl_soa_bind, iml_bindlen );
     if (iml_rc < 0) {                      /* error occured           */
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W bind GW-OUT Error %d %d",
                       __LINE__, iml_rc, D_TCP_ERROR );
//     D_TCP_CLOSE( iml_socket );  /* close socket again */
//     goto p_conn_40;                      /* check if still connect possible */
// 29.09.07 KB - to-do
       break;                                 /* all done                */
     }
     break;                                 /* pseudo-loop             */
   }
   iml_rc = adsp_vchact->dsc_tcpcomp.m_startco_fb( iml_socket,
                                                   &dss_virch_tcpco1_cb1,
                                                   adsp_vchact );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-E m_startco_fb() failed",
                     __LINE__ );
     D_TCP_CLOSE( iml_socket );             /* close socket again      */
//   goto p_conn_80;                        /* close session to client */
// 29.09.07 KB - to-do
       return;                                /* all done                */
   }
   iml_rc = connect( iml_socket,
                     (struct sockaddr *) &adsp_vchact->dsc_soa, iml_len_soa );
   iml_errno = 0;                           /* clear error number      */
   if (iml_rc) iml_errno = D_TCP_ERROR;     /* set error number        */
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-T connect %d %d",
                   __LINE__, iml_rc, iml_errno );
// 29.09.07 KB - to-do - error number UNIX
   if ((iml_rc < 0) && (iml_errno == WSAEWOULDBLOCK)) return;
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-E connect error %d %d",
                   __LINE__, iml_rc, iml_errno );
// to-do 24.07.08 KB - ask Mr. Garkuscha what to do
   adsp_vchact->dsc_tcpcomp.m_stopconn( FALSE, TRUE );
// D_TCP_CLOSE( iml_socket );               /* close socket again      */
   adsp_vchact->imc_ind_conn++;             /* try next connection     */
   if (adsp_vchact->imc_ind_conn
         < adsp_vchact->adsc_sevirch_entry->adsc_server_ineta->imc_no_ineta) {
     goto p_conn_00;                        /* try to connect          */
   }
   adsp_vchact->adsc_sevirch_entry->imc_time_retry
     = ((int) time( NULL )) + adsp_vchact->adsc_sevirch_entry->imc_time_retry;  /* time next retry */
// adsp_connect->dsc_tcp_se[1].adsc_conn->m_stopconn( TRUE );
// 29.09.07 KB - to-do
} /* end m_virch_do_connect()                                          */
#endif

#ifdef OLD01
static void m_virch_do_connect( struct dsd_virch_active *adsp_vchact ) {
   int        iml_rc;                       /* return code             */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap-l%05d-T m_virch_do_connect() call m_startco_mh() &dsc_tcpcomp=%p vpp_userfld=%p.",
                   __LINE__, adsp_vchact->dsc_tcpcomp, adsp_vchact );
#endif
   iml_rc = adsp_vchact->dsc_tcpcomp.m_startco_mh(
              &dss_virch_tcpco1_cb1,
              adsp_vchact,
              adsp_vchact->adsc_sevirch_entry->adsc_server_ineta,  /* remote INETA */
              &adsp_vchact->adsc_sevirch_entry->dsc_bind_multih,  /* for bind multihomed */
              adsp_vchact->adsc_sevirch_entry->imc_port );  /* port of target */
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPnnnnnnW xs-gw-serv-vch-icap l%05d m_virch_do_connect() m_startco_mh() failed %d.",
                     __LINE__, iml_rc );
//   goto p_conn_80;                        /* close session to client */
// 29.09.07 KB - to-do
   }
} /* end m_virch_do_connect()                                          */
#endif

/** error message when TCPCOMP connect failed                          */
static void m_virch_cb_conn_err( dsd_tcpcomp *ads_con, void * vpp_userfld,
   struct sockaddr *adsp_soa, socklen_t imp_len_soa, int imp_current_index, int imp_total_index, int imp_errno ) {
   int        iml_rc;                       /* return code             */
   char       *achl1;                       /* working variable        */
   char       chrl_ineta[ LEN_DISP_INETA ];  /* internet-address char  */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_virch_cb_conn_err( 0X%p 0X%p 0X%p %d %d %d %d ) called",
                   __LINE__, ads_con, vpp_userfld, adsp_soa, imp_len_soa, imp_current_index, imp_total_index, imp_errno );
#endif
#define ADSL_VCHACT_G ((struct dsd_virch_active *) vpp_userfld)
   iml_rc = getnameinfo( adsp_soa, imp_len_soa,
                         chrl_ineta, sizeof(chrl_ineta),
                         0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPnnnnnnW xs-gw-serv-vch-icap l%05d m_virch_cb_conn_err() target ICAP server %.*(u8)s getnameinfo() returned %d %d.",
                     __LINE__,
                     ADSL_VCHACT_G->adsc_sevirch_entry->imc_len_name,
                     ADSL_VCHACT_G->adsc_sevirch_entry->achc_name,
                     iml_rc, D_TCP_ERROR );
     strcpy( chrl_ineta, "???" );
   }
   achl1 = ".";
   if ((imp_current_index + 1) < imp_total_index) {
     achl1 = " - try next INETA from DNS";  /* set additional text     */
   } else if (imp_total_index > 1) {
     achl1 = " - was last INETA from DNS";  /* set additional text     */
   }
   m_hlnew_printf( HLOG_XYZ1, "HWSPnnnnnnW xs-gw-serv-vch-icap l%05d connect to target ICAP server %.*(u8)s INETA %s failed %d%s",
                   __LINE__,
                   ADSL_VCHACT_G->adsc_sevirch_entry->imc_len_name,
                   ADSL_VCHACT_G->adsc_sevirch_entry->achc_name,
                   chrl_ineta, imp_errno, achl1 );
   return;
#undef ADSL_VCHACT_G
} /* end m_virch_cb_conn_err()                                         */

/** TCPCOMP connect callback function                                  */
static void m_virch_conncallback( dsd_tcpcomp *adsp_tcpco, void *vpp_userfld,
#ifndef B121120
                                  struct dsd_target_ineta_1 *, void *,  /* INETA to free */
#endif
                                  struct sockaddr *adsp_soa, socklen_t imp_len_soa, int imp_error ) {
   BOOL       bol1;                         /* working-variable        */
   int        iml1;                         /* working-variable        */
   struct dsd_virch_active *adsl_vchact;    /* active virus checking connection */
#ifdef TRY_110722_01                        /* check if all connected */
   struct dsd_virch_request *adsl_virch_req_w1;  /* virus checking request */
#endif
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_virch_conncallback( 0X%p 0X%p 0X%p %d %d ) called",
                   __LINE__, adsp_tcpco, vpp_userfld, adsp_soa, imp_len_soa, imp_error );
#endif
   if (imp_error) return;                   /* connect was not successful */
   adsl_vchact = (struct dsd_virch_active *) vpp_userfld;
#ifdef OLD01
   adsl_vchact->imc_ind_conn = -1;          /* connect successful      */
#endif
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCCON1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "TCP connection with virus-checker %p established",
                     adsl_vchact );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#ifndef TRY_110722_01                       /* check if all connected */
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
   adsl_vchact->iec_vat = ied_vat_active;   /* TCP session active      */
// 29.10.07 KB to-do critical section
   adsl_vchact->adsc_sevirch_entry->imc_stat_no_conn_ok++;  /* statistic number of connects succeeded */
// adsl_vchact->iec_clr_stat = ied_clrs_conn_recv_st;  /* after connect start receive */
   adsl_vchact->dsc_tcpcomp.m_recv();       /* start receiving         */
#ifdef B111024
   if (adsl_vchact->adsc_virch_requ == NULL) return;  /* no virus checking request */
#else
   if (adsl_virch_req_w1 == NULL) {         /* no virus checking request */
     dsg_global_lock.m_leave();             /* leave CriticalSection   */
     return;                                /* all done                */
   }
#endif
   m_check_first_packet( adsl_vchact->adsc_virch_requ );  /* check send first packet */
// m_send_control_init( adsl_vchact );
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
#else
   adsl_virch_req_w1 = adsl_vchact->adsc_virch_requ;  /* virus checking request */
   if (   (adsl_virch_req_w1)               /* with active request     */
       && (adsl_virch_req_w1->dsc_timer_ele.vpc_chain_2)) {  /* timer set   */
     m_time_rel( &adsl_virch_req_w1->dsc_timer_ele );  /* release timer */
   }
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
#ifdef DEBUG_120122_01                      /* sending to ICAP stops   */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXX8", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "DEBUG_120122_01 l%05d thread=%d - after  lock-enter",
                     __LINE__, HL_GET_THREAD );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
   adsl_vchact->iec_vat = ied_vat_active;   /* TCP session active      */
   adsl_vchact->adsc_sevirch_entry->imc_stat_no_conn_ok++;  /* statistic number of connects succeeded */
   adsl_vchact->dsc_tcpcomp.m_recv();       /* start receiving         */
#ifdef B111024
   if (adsl_virch_req_w1 == NULL) return;   /* no virus checking request */
#else
   if (adsl_virch_req_w1 == NULL) {         /* no virus checking request */
     dsg_global_lock.m_leave();             /* leave CriticalSection   */
     return;                                /* all done                */
   }
#endif
#ifdef DEBUG_120120_01                      /* m_check_first_packet()  */
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d DEBUG_120120_01 adsl_virch_req_w1=%p.",
                   __LINE__, adsl_virch_req_w1 );
#endif
   bol1 = m_check_first_packet( adsl_virch_req_w1 );  /* check send first packet */
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
   if (bol1) return;                        /* could send first packet */
   m_time_set( &adsl_virch_req_w1->dsc_timer_ele, FALSE );  /* set the timer */
   return;                                /* wait for other connections to be established */
#endif
} /* end m_virch_conncallback()                                        */

/** TCPCOMP send callback function                                     */
static void m_virch_sendcallback( dsd_tcpcomp *adsp_tcpco, void *vpp_userfld ) {
   BOOL       bol1;                         /* working-variable        */
   BOOL       bol_send_active;              /* sending is active       */
   BOOL       bol_all_sent;                 /* all data have been sent */
   int        iml1, iml2, iml3, iml4;       /* working-variables       */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_virch_active *adsl_vchact_cur;  /* active virus checking connection */
   struct dsd_virch_active *adsl_vchact_w1;  /* active virus checking connection */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working-variable        */
   struct dsd_gather_i_1 *adsl_gai1_wtr;    /* for WSP trace           */
   struct dsd_virch_request *adsl_virch_req_w1;  /* virus checking request */
   struct dsd_se_vch_req_1 *adsl_sevchreq1_w1;  /* request area virus checking */
   struct dsd_se_vch_req_1 *adsl_vchreq1_first;  /* first to process   */
#ifndef TRY_110722_01                       /* check if all connected */
   struct dsd_se_vch_req_1 *adsl_vchreq1_last;  /* last to process     */
#endif
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w4;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_virch_sendcallback( 0X%p , 0X%p ) called",
                   __LINE__, adsp_tcpco, vpp_userfld );
#endif
   adsl_vchact_cur = (struct dsd_virch_active *) vpp_userfld;  /* active virus checking connection */
   if (adsl_vchact_cur->ac_send_buf == NULL) return;  /* no current send buffer */
#define ADSL_VIRCH_SEND ((struct dsd_virch_send *) adsl_vchact_cur->ac_send_buf)  /* send to virus checker structure */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     iml1 = 0;                              /* length                  */
     iml2 = 0;                              /* count gather            */
     adsl_gai1_w1 = ADSL_VIRCH_SEND->adsc_gai1_send;  /* get gather to send */
     do {                                   /* loop over parts         */
       iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       iml2++;                              /* count gather            */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     } while (adsl_gai1_w1);
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSCBB", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml2 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "send in TCPCOMP callback to virus-checker %p length %d/0X%X in %d gather",
                     adsl_vchact_cur, iml1, iml1, iml2 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml2;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
     if (img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2))  {  /* generate WSP trace record */
       adsl_wt1_w4 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       adsl_gai1_wtr = (struct dsd_gather_i_1 *) ((char *) adsl_wt1_w4 + LEN_TCP_RECV);  /* end of this piece of memory */
       adsl_gai1_w1 = ADSL_VIRCH_SEND->adsc_gai1_send;  /* get gather to send */
       do {                                 /* loop over parts         */
         adsl_gai1_wtr--;                   /* space for gather        */
         if (((char *) adsl_gai1_wtr) < ((char *) adsl_wt1_w4)) break;  /* too many gather */
         memcpy( adsl_gai1_wtr, adsl_gai1_w1, sizeof(struct dsd_gather_i_1) );
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       } while (adsl_gai1_w1);
     }
   }
   adsl_gai1_w1 = ADSL_VIRCH_SEND->adsc_gai1_send;  /* get old gather  */
   iml1 = adsl_vchact_cur->dsc_tcpcomp.m_send_gather(
            adsl_gai1_w1,
            &ADSL_VIRCH_SEND->adsc_gai1_send );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_virch_sendcallback() m_send_gather() returned %d gather=%p.",
                   __LINE__, iml1, ADSL_VIRCH_SEND->adsc_gai1_send );
#endif
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     iml2 = 0;                              /* length                  */
     iml3 = 0;                              /* count gather            */
     adsl_gai1_w1 = ADSL_VIRCH_SEND->adsc_gai1_send;  /* get gather to send */
     while (adsl_gai1_w1) {                 /* loop over parts         */
       iml2 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       iml3++;                              /* count gather            */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     if ((adsl_wt1_w4) && (iml1 <= 0)) {
       adsl_wt1_w1 = adsl_wt1_w4;           /* get old block           */
       adsl_wt1_w4 = NULL;                  /* do not free later       */
     } else {
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     }
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSCBC", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml2 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "after send in TCPCOMP callback to virus-checker %p length-sent %d/0X%X length-remaining %d/0X%X in %d gather",
                     adsl_vchact_cur, iml1, iml1, iml2, iml2, iml3 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml2;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (adsl_wt1_w4) {                     /* we append the data      */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml2 = iml1;                         /* length of data sent     */
       adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_wt1_w4 + LEN_TCP_RECV) - 1;  /* here is first gather */
       achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* start of data        */
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
           iml3 = adsl_gai1_w1->achc_ginp_end - achl_w3;
           if (iml3 > iml2) iml3 = iml2;
           iml4 = achl_w2 - achl_w4;
           if (iml4 > iml3) iml4 = iml3;
           memcpy( achl_w4, achl_w3, iml4 );
           achl_w4 += iml4;
           achl_w3 += iml4;
           ADSL_WTR_G2->imc_length += iml4;  /* length of text / data  */
           iml2 -= iml4;                    /* length to be copied     */
           if (iml2 <= 0) break;
           if (achl_w3 < adsl_gai1_w1->achc_ginp_end) break;
           if (adsl_gai1_w1 == adsl_gai1_wtr) break;
           adsl_gai1_w1--;
           if (((char *) adsl_gai1_w1) < ((char *) adsl_wt1_w4)) {  /* too many gather */
             m_hlnew_printf( HLOG_WARN1, "HWSPVCICAPHCnnnnW Error WSP Trace data sent could not be traced - remaining %d/0X%X.",
                             iml2, iml2 );
             break;
           }
           achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* start of data    */
           if (achl_w4 >= achl_w2) break;
         }
         achl_w1 = achl_w2;                 /* set end of this area    */
       } while (iml2 > 0);
       m_proc_free( adsl_wt1_w4 );          /* free block with gather  */
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (ADSL_VIRCH_SEND->adsc_gai1_send) {   /* not all sent            */
     if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data     */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSCBG", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id             */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "notify TCPCOMP because not all sent to virus-checker %p.",
                       adsl_vchact_cur );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content            /* content of text / data  */
         = (char *) (ADSL_WTR_G1 + 1);
       ADSL_WTR_G1->imc_length = iml1;      /* length of text / data   */
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
     }
     adsl_vchact_cur->dsc_tcpcomp.m_sendnotify();
     return;                                /* wait for next send call back */
   }
#undef ADSL_VIRCH_SEND
   m_proc_free( adsl_vchact_cur->ac_send_buf );  /* free the buffer    */
#ifdef DEBUG_120122_01                      /* sending to ICAP stops   */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXX3", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "DEBUG_120122_01 l%05d thread=%d - before lock-enter for virus-checker %p.",
                     __LINE__, HL_GET_THREAD, adsl_vchact_cur );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
#ifdef DEBUG_120122_01                      /* sending to ICAP stops   */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXX4", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "DEBUG_120122_01 l%05d thread=%d -  after lock-enter for virus-checker %p.",
                     __LINE__, HL_GET_THREAD, adsl_vchact_cur );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
   adsl_vchact_cur->ac_send_buf = NULL;     /* no more send buffer     */
   adsl_virch_req_w1 = adsl_vchact_cur->adsc_virch_requ;  /* virus checking request */
   if (adsl_virch_req_w1 == NULL) {         /* no request found        */
     dsg_global_lock.m_leave();             /* leave CriticalSection   */
#ifdef DEBUG_120122_01                      /* sending to ICAP stops   */
     if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data     */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXX1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id             */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "DEBUG_120122_01 - leave TCPCOMP exit for virus-checker %p - adsc_virch_requ NULL",
                       adsl_vchact_cur );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content            /* content of text / data  */
         = (char *) (ADSL_WTR_G1 + 1);
       ADSL_WTR_G1->imc_length = iml1;      /* length of text / data   */
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
     }
#endif
     return;                                /* nothing to do           */
   }
   adsl_vchact_w1 = adsl_virch_req_w1->adsc_virch_act_ch;  /* chain active virus checking connections */
   while (adsl_vchact_w1) {                 /* loop over all active TCP sessions */
     if (adsl_vchact_w1->ac_send_buf) {     /* still buffer to send    */
       dsg_global_lock.m_leave();           /* leave CriticalSection   */
#ifdef DEBUG_120122_01                      /* sending to ICAP stops   */
       if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data   */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXX2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id           */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                         "DEBUG_120122_01 - leave TCPCOMP exit for virus-checker %p - %p still sending.",
                         adsl_vchact_cur, adsl_vchact_w1 );
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         ADSL_WTR_G1->achc_content          /* content of text / data  */
           = (char *) (ADSL_WTR_G1 + 1);
         ADSL_WTR_G1->imc_length = iml1;    /* length of text / data   */
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
         m_wsp_trace_out( adsl_wt1_w1 );    /* output of WSP trace record */
       }
#endif
       return;                              /* nothing to do           */
     }
     adsl_vchact_w1 = adsl_vchact_w1->adsc_requ_next;  /* next in chain for this request */
   }
   /* can send more data                                               */
   if (adsl_virch_req_w1->dsc_timer_ele.vpc_chain_2) {  /* timer set   */
     m_time_rel( &adsl_virch_req_w1->dsc_timer_ele );  /* release timer */
   }
// to-do 14.09.09 KB - activate session if needed
//---
#define ADSL_SE_VCH_CONTR_1 ((struct dsd_se_vch_contr_1 *) adsl_virch_req_w1->ac_control_area)  /* service virus checking control area */
#ifdef TRACEHL1
   {
     struct dsd_se_vch_req_1 *adsh_sevchreq1_w1;  /* request area virus checking */
     int      imh1 = 0;
     adsh_sevchreq1_w1 = ADSL_SE_VCH_CONTR_1->adsc_sevchreq1;  /* chain of requests */
     while (adsh_sevchreq1_w1) {
       imh1++;                              /* count this entry        */
       adsh_sevchreq1_w1 = adsh_sevchreq1_w1->adsc_next;  /* get next in chain */
     }
     m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d m_virch_sendcallback() adsc_sevchreq1 chain %d elements",
                     __LINE__, imh1 );
   }
#endif
   adsl_sevchreq1_w1 = ADSL_SE_VCH_CONTR_1->adsc_sevchreq1;  /* get first request */
   adsl_vchreq1_first = NULL;               /* nothing found to send   */
   while (adsl_sevchreq1_w1) {              /* loop over all requests  */
     switch (adsl_sevchreq1_w1->iec_stat) {
       case ied_vchstat_active:             /* data not sent yet       */
         if (adsl_vchreq1_first) break;     /* first already set       */
         adsl_vchreq1_first = adsl_sevchreq1_w1;  /* save as first one */
         break;
       case ied_vchstat_sent:               /* data have been sent     */
         adsl_sevchreq1_w1->iec_stat = ied_vchstat_done;  /* area can be freed */
#ifdef XYZ1
         adsl_gai1_w1 = adsl_sevchreq1_w1->adsc_gai1_data;  /* get data */
         while (adsl_gai1_w1) {                 /* loop over all gather structures */
           ADSL_SE_VCH_CONTR_1->ilc_window_1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
           adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
         }
#endif
         break;
     }
     adsl_sevchreq1_w1 = adsl_sevchreq1_w1->adsc_next;  /* get next in chain */
   }
   if (adsl_vchreq1_first == NULL) {        /* nothing found to send   */
     adsl_virch_req_w1->boc_send_active = FALSE;  /* send is not active */
     dsg_global_lock.m_leave();             /* leave CriticalSection   */
#ifdef DEBUG_120122_01                      /* sending to ICAP stops   */
     if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data     */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXX3", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id             */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "DEBUG_120122_01 - leave TCPCOMP exit for virus-checker %p - nothing to send - ac_control_area=%p boc_wait_window=%d.",
                       adsl_vchact_cur, ADSL_SE_VCH_CONTR_1, ADSL_SE_VCH_CONTR_1->boc_wait_window );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content            /* content of text / data  */
         = (char *) (ADSL_WTR_G1 + 1);
       ADSL_WTR_G1->imc_length = iml1;      /* length of text / data   */
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
     }
#endif
//#define ADSL_SE_VCH_CONTR_1 ((struct dsd_se_vch_contr_1 *) adsl_virch_req_w1->ac_control_area)  /* service virus checking control area */
#ifdef B120203
     if (ADSL_SE_VCH_CONTR_1->boc_wait_window) {  /* wait till window smaller */
#ifdef FORKEDIT
     }
#endif
#else
     if (   (ADSL_SE_VCH_CONTR_1->boc_wait_window)  /* wait till window smaller */
         && ((ADSL_SE_VCH_CONTR_1->ilc_window_1 - ADSL_SE_VCH_CONTR_1->ilc_window_2)
                <= ADSL_SE_VCH_CONTR_1->imc_max_diff_window)) {
#endif
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_virch_sendcallback() boc_wait_window set",
                       __LINE__ );
#endif
       ADSL_SE_VCH_CONTR_1->boc_wait_window = FALSE;
       m_wsp_s_ent_notify( adsl_virch_req_w1->adsc_virch_session->adsc_conn1,
                           (char *) adsl_virch_req_w1->adsc_virch_session - sizeof(struct dsd_service_aux_1),
                           adsl_virch_req_w1->adsc_virch_session->imc_signal );
     }
//#undef ADSL_SE_VCH_CONTR_1
     return;                                /* nothing to do           */
   }
#ifndef TRY_110722_01                       /* check if all connected */
   adsl_vchreq1_last = adsl_vchreq1_first;  /* get remaining chain     */
   bol_all_sent = FALSE;                    /* not all data have been sent */
   while (TRUE) {                           /* loop over remaining chain */
     adsl_vchreq1_last->iec_stat = ied_vchstat_sent;  /* data have been sent */
     adsl_gai1_w1 = adsl_vchreq1_last->adsc_gai1_data;  /* get data    */
     while (adsl_gai1_w1) {                 /* loop over all gather structures */
       ADSL_SE_VCH_CONTR_1->ilc_window_2 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     if (adsl_vchreq1_last->iec_vchreq1 == ied_vchreq_eof) {  /* End-of-File */
       bol_all_sent = TRUE;                 /* all data have been sent */
     }
     if (adsl_vchreq1_last->adsc_next == NULL) break;  /* is last in chain */
     adsl_vchreq1_last = adsl_vchreq1_last->adsc_next;  /* get next in chain */
   }
   bol_send_active = FALSE;                 /* sending is not active   */
   adsl_vchact_w1 = adsl_virch_req_w1->adsc_virch_act_ch;  /* chain active virus checking connections */
   while (adsl_vchact_w1) {                 /* loop over all active TCP sessions */
     bol1 = m_send_chunk( adsl_vchact_w1, adsl_vchreq1_first, adsl_vchreq1_last );
     if (bol1) {                            /* could not yet send data */
       bol_send_active = TRUE;              /* sending is active       */
     }
     adsl_vchact_w1 = adsl_vchact_w1->adsc_requ_next;  /* next in chain for this request */
   }
   if (bol_send_active) {                   /* send is active          */
     dsg_global_lock.m_leave();             /* leave CriticalSection   */
     if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data     */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSCBD", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id             */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "virus-checking wait because of send active - ac_control_area=%p all-sent=%d.",
                       ADSL_SE_VCH_CONTR_1, bol_all_sent );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content            /* content of text / data  */
         = (char *) (ADSL_WTR_G1 + 1);
       ADSL_WTR_G1->imc_length = iml1;      /* length of text / data   */
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
     }
     m_time_set( &adsl_virch_req_w1->dsc_timer_ele, FALSE );  /* set the timer */
     return;                                /* all done                */
   }
   while (TRUE) {                           /* loop over requests sent */
     adsl_vchreq1_first->iec_stat = ied_vchstat_done;  /* area can be freed */
     if (adsl_vchreq1_first == adsl_vchreq1_last) break;  /* all requests marked */
     adsl_vchreq1_first = adsl_vchreq1_first->adsc_next;  /* get next in chain */
   }
   adsl_virch_req_w1->boc_send_active = FALSE;  /* send is not active  */
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSCBE", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "activate SDH because of wait-window - ac_control_area=%p requ=%p boc_wait_window=%d.",
                     ADSL_SE_VCH_CONTR_1, adsl_virch_req_w1, ADSL_SE_VCH_CONTR_1->boc_wait_window );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
//#define ADSL_SE_VCH_CONTR_1 ((struct dsd_se_vch_contr_1 *) adsl_virch_req_w1->ac_control_area)  /* service virus checking control area */
   if (ADSL_SE_VCH_CONTR_1->boc_wait_window) {  /* wait till window smaller */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_virch_sendcallback() boc_wait_window set",
                     __LINE__ );
#endif
     ADSL_SE_VCH_CONTR_1->boc_wait_window = FALSE;
     if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data     */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSCBF", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id             */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "activate SDH because of wait-window - ac_control_area=%p.",
                       ADSL_SE_VCH_CONTR_1 );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content            /* content of text / data  */
         = (char *) (ADSL_WTR_G1 + 1);
       ADSL_WTR_G1->imc_length = iml1;      /* length of text / data   */
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
     }
     m_wsp_s_ent_notify( adsl_virch_req_w1->adsc_virch_session->adsc_conn1,
                         (char *) adsl_virch_req_w1->adsc_virch_session - sizeof(struct dsd_service_aux_1),
                         adsl_virch_req_w1->adsc_virch_session->imc_signal );
   }
//#undef ADSL_SE_VCH_CONTR_1
   if (bol_all_sent) {                      /* all data have been sent */
     m_time_set( &adsl_virch_req_w1->dsc_timer_ele, FALSE );  /* set the timer */
   }
#endif
#ifdef TRY_110722_01                        /* check if all connected  */
#ifndef B120124
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
#endif
#ifdef DEBUG_120122_01                      /* sending to ICAP stops   */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXXD", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "DEBUG_120122_01 l%05d thread=%d - m_sendcallback() before m_continue_send() adsl_virch_req=%p.",
                     __LINE__, HL_GET_THREAD, adsl_virch_req_w1 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
#ifdef B150128
   m_continue_send( adsl_virch_req_w1 );    /* send more data          */
#endif
#ifndef B150128
   m_continue_send( adsl_virch_req_w1, FALSE );  /* send more data     */
#endif
#ifdef DEBUG_120122_01                      /* sending to ICAP stops   */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXXE", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "DEBUG_120122_01 l%05d thread=%d - m_sendcallback() after  m_continue_send() adsl_virch_req=%p.",
                     __LINE__, HL_GET_THREAD, adsl_virch_req_w1 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
#ifdef B120124
#ifndef B111024
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
#endif
#endif
#endif
   return;                                  /* all done                */
#undef ADSL_SE_VCH_CONTR_1
} /* end m_sendcallback()                                              */

/** TCPCOMP get receive buffer callback function                       */
static int m_virch_getrecvbuf( dsd_tcpcomp *adsp_tcpco, void *vpp_userfld, void **aap_handle, char **aachp_buffer, int **aimp_len_recv ) {
//#ifdef XYZ1
   struct dsd_virch_recv *adsl_clrecv_w1;  /* block received from cluster member */

   adsl_clrecv_w1 = (struct dsd_virch_recv *) m_proc_alloc();  /* acquire memory */
   adsl_clrecv_w1->adsc_vchact = (struct dsd_virch_active *) vpp_userfld;
   adsl_clrecv_w1->imc_usage_count = 0;     /* clear usage count       */
   *aap_handle = adsl_clrecv_w1;            /* return handle           */
   *aachp_buffer = (char *) (adsl_clrecv_w1 + 1);
   *aimp_len_recv = &adsl_clrecv_w1->imc_len_recv;  /* length received */
   return LEN_TCP_RECV - sizeof(struct dsd_virch_recv);
//#endif
// return 0;
} /* end m_virch_getrecvbuf()                                          */

/** TCPCOMP receive callback function                                  */
static int m_virch_recvcallback( dsd_tcpcomp *adsp_tcpco, void *vpp_userfld, void *ap_handle ) {
   BOOL       bol1;                         /* working variable        */
   BOOL       bol_error;                    /* error found             */
   BOOL       bol_vir_name;                 /* virus name found        */
   struct dsd_virch_active *adsl_vchact_cur;  /* active virus checking connection */
   struct dsd_virch_active *adsl_vchact_rem;  /* active virus checking connection to be removed */
   struct dsd_virch_active *adsl_vchact_del;  /* active virus checking connection to be deleted */
   struct dsd_virch_active *adsl_vchact_w1;  /* virus checking connection */
   struct dsd_virch_active *adsl_vchact_w2;  /* virus checking connection */
   struct dsd_se_vcicaphttp_entry *adsl_se_w1;  /* definition server-entry */
   struct dsd_virch_request *adsl_virch_req_cur;  /* virus checking request */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   char       *achl_cmp1;                   /* compare text            */
   char       *achl_out;                    /* output to virus name    */
   char       *achl_rp;                     /* read pointer            */
   char       *achl_inend;                  /* input end               */
   struct dsd_virch_session *adsl_virch_session;  /* virus checking bound to session */
// ???? 08.07.08 KB
   int        iml1, iml2, iml3;             /* working variables       */
#ifdef XYZ1
   int        iml_pos;                      /* position scan received block */
   int        iml_len_data;                 /* save length of data     */
   char       *achl_w1;                     /* working variable        */
   void       **avpl_w1;                    /* working variable        */
   char       *achl_st_data;                /* start of data           */
   char       chl_main_tag;                 /* main tag of received packet */
#endif
   struct dsd_virch_recv *adsl_clrecv_w1;   /* block received from virus checker */
   struct dsd_virch_recv *adsl_clrecv_cur;  /* current in chain        */
   struct dsd_virch_recv *adsl_clrecv_last;  /* last in chain          */
#ifndef B111205
   struct dsd_virch_recv *adsl_clrecv_param;  /* receive block passed  */
#endif
#ifdef XYZ1
   struct dsd_virch_recv *adsl_clrecv_data;  /* start data in this block */
// struct dsd_virch_active *adsl_vchact;   /* active cluster entry    */
   struct dsd_virch_proc_recv *adsl_clprr_w1;  /* process block received from cluster member */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* gather input data       */
#endif
   struct dsd_virch_request *adsl_virch_req_w1;  /* virus checking request */
   struct dsd_virch_request *adsl_virch_req_w2;  /* virus checking request */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   char       chrl_virus_name[ 128 ];       /* output to virus name    */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_virch_recvcallback( 0X%p 0X%p 0X%p ) called",
                   __LINE__, adsp_tcpco, vpp_userfld, ap_handle );
#endif
   if (ap_handle == NULL) return 0;
#ifdef B111205
   adsl_clrecv_w1 = (struct dsd_virch_recv *) ap_handle;  /* block received from virus checker */
#else
   adsl_clrecv_w1 = adsl_clrecv_param = (struct dsd_virch_recv *) ap_handle;  /* block received from virus checker */
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_virch_recvcallback() imc_len_recv = %d.",
                   __LINE__, adsl_clrecv_w1->imc_len_recv );
#define TRACE_OUT
#ifdef TRACE_OUT
   if (adsl_clrecv_w1->imc_len_recv > 0) {
     m_console_out( (char *) (adsl_clrecv_w1 + 1), adsl_clrecv_w1->imc_len_recv );
   }
#endif
#endif
   adsl_vchact_cur = (struct dsd_virch_active *) vpp_userfld;  /* active virus checking connection */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCREC1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml2 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "received from virus-checker %p length %d/0X%X state(iec_var)=%d.",
                     adsl_vchact_cur, adsl_clrecv_w1->imc_len_recv, adsl_clrecv_w1->imc_len_recv, adsl_vchact_cur->iec_var );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml2;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (   (img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2))  /* generate WSP trace record */
         && (adsl_clrecv_w1->imc_len_recv > 0)) {  /* data received    */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml2 = adsl_clrecv_w1->imc_len_recv;  /* length of data received */
       achl_w3 = (char *) (adsl_clrecv_w1 + 1);  /* start of data      */
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
#ifndef B100311
   adsl_virch_req_cur = adsl_vchact_cur->adsc_virch_requ;  /* get virus checking request */
#endif
   if (adsl_clrecv_w1->imc_len_recv <= 0) {
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() length %d.",
                     __LINE__, adsl_clrecv_w1->imc_len_recv );
     goto p_recv_60;                        /* received illogic        */
   }
   adsl_clrecv_w1->achc_processed = (char *) (adsl_clrecv_w1 + 1);  /* processed so far */
#ifdef XYZ1
   if (adsl_vchact_cur->boc_wait_recv == FALSE) {  /* does not wait for receive data */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() not ready for receive",
                     __LINE__ );
// 08.07.08 KB to-do CMA close
     return 0;
   }
#endif
   if (adsl_vchact_cur->iec_var == ied_var_invalid) {  /* does not wait for receive data */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() not ready for receive",
                     __LINE__ );
     goto p_recv_60;                        /* received illogic        */
   }
#ifndef B100311
   if (adsl_virch_req_cur == NULL) {        /* no request associated */
     goto p_recv_80;                        /* free block received and close TCP session */
   }
#endif
#ifdef B100311
   adsl_virch_req_cur = adsl_vchact_cur->adsc_virch_requ;  /* get virus checking request */
   if (adsl_virch_req_cur == NULL) {        /* no request associated */
     goto p_recv_60;                        /* received illogic        */
   }
#endif
#ifdef XYZ1
   adsl_vchact_cur->imc_stat_no_recv++;          /* increment statistic number of receives */
   adsl_vchact_cur->ilc_stat_len_recv += adsl_clrecv_w1->imc_len_recv;  /* statistic length of receives */
#endif
   adsl_clrecv_w1->adsc_next = NULL;        /* clear chain             */
   if (adsl_vchact_cur->adsc_recv_ch == NULL) {  /* chain of received buffers */
     adsl_vchact_cur->adsc_recv_ch = adsl_clrecv_w1;  /* set only in chain */
   } else {                                 /* append to chain         */
     adsl_clrecv_cur = adsl_vchact_cur->adsc_recv_ch;  /* get first in chain */
     do {                                   /* loop over chain         */
       adsl_clrecv_last = adsl_clrecv_cur;  /* save current entry      */
       adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
     } while (adsl_clrecv_cur);
     adsl_clrecv_last->adsc_next = adsl_clrecv_w1;  /* append to chain */
   }
#ifndef B111205
   adsl_clrecv_param = NULL;                /* do not free receive block passed */
#endif
   switch (adsl_vchact_cur->iec_var) {      /* active connection receive status */
     case ied_var_start:                    /* start of receive data   */
       break;                               /* continue                */
     case ied_var_rec_http:                 /* receive HTTP            */
       goto p_recv_24;                      /* check HTTP header       */
     default:
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() iec_var=%d.",
                       __LINE__, adsl_vchact_cur->iec_var );
       goto p_recv_60;                      /* received illogic        */
   }

   achl_cmp1 = "ICAP/1.0 ";
#ifdef B100214
   achl_rp = (char *) (adsl_vchact_cur->adsc_recv_ch + 1);
   achl_inend = achl_rp + adsl_vchact_cur->adsc_recv_ch->imc_len_recv;
#endif
   adsl_clrecv_cur = adsl_vchact_cur->adsc_recv_ch;  /* get first in chain */
   achl_rp = (char *) (adsl_clrecv_cur + 1);
   achl_inend = achl_rp + adsl_clrecv_cur->imc_len_recv;
   do {
     if (achl_rp >= achl_inend) {
#ifdef B100214
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() end of ICAP",
                       __LINE__ );
       goto p_recv_60;                      /* received illogic        */
#endif
       adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
       if (adsl_clrecv_cur == NULL) {       /* was last in chain       */
         return 1;                          /* receive more            */
       }
       achl_rp = (char *) (adsl_clrecv_cur + 1);
       achl_inend = achl_rp + adsl_clrecv_cur->imc_len_recv;
     }
     if (*achl_rp++ != *achl_cmp1++) {
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() end of ICAP",
                       __LINE__ );
       goto p_recv_60;                      /* received illogic        */
     }
   } while (*achl_cmp1);
   iml1 = 3;
   iml2 = 0;
   do {
     if (achl_rp >= achl_inend) {
#ifdef B100214
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() end of status-no",
                       __LINE__ );
       goto p_recv_60;                      /* received illogic        */
#endif
       adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
       if (adsl_clrecv_cur == NULL) {       /* was last in chain       */
         return 1;                          /* receive more            */
       }
       achl_rp = (char *) (adsl_clrecv_cur + 1);
       achl_inend = achl_rp + adsl_clrecv_cur->imc_len_recv;
     }
     if ((*achl_rp < '0') || (*achl_rp > '9')) {
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() ICAP status-no not numeric",
                       __LINE__ );
       goto p_recv_60;                      /* received illogic        */
     }
     iml2 *= 10;
     iml2 += *achl_rp++ - '0';
     iml1--;
   } while (iml1);
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() ICAP status-no %d.",
                   __LINE__, iml2 );
#endif
   /* check data till CR LF CR LF                                      */
// iml1 = 0;                                /* check CR LF             */
#ifdef B100214
   while (achl_rp < achl_inend) {
     switch (*achl_rp) {
       case CHAR_CR:                        /* carriage-return         */
         if ((iml1 & 1) == 0) iml1++;
         else iml1 = 1;
         break;
       case CHAR_LF:                        /* line-feed               */
         if (iml1 & 1) iml1++;
         break;
       default:
         iml1 = 0;
         break;
     }
     achl_rp++;                             /* next input              */
     if (iml1 == 4) break;                  /* end of data found       */
   }
   if (   (iml1 != 4)
       || (achl_rp < achl_inend)) {
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() not CR LF CR LF found",
                     __LINE__ );
     goto p_recv_60;                        /* received illogic        */
   }
#endif
   while (TRUE) {
     if (achl_rp >= achl_inend) {
       adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
       if (adsl_clrecv_cur == NULL) {       /* was last in chain       */
         iml1 = MAX_LEN_H_ICAP;             /* maximum length ICAP header */
         adsl_clrecv_cur = adsl_vchact_cur->adsc_recv_ch;  /* get first in chain */
         do {                               /* loop over all blocks received */
           iml1 -= adsl_clrecv_cur->imc_len_recv;
           if (iml1 < 0) {                  /* ICAP header is too long */
             m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() ICAP header too long",
                             __LINE__ );
             goto p_recv_60;                /* received illogic        */
           }
           adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
         } while (adsl_clrecv_cur);
         return 1;                          /* receive more            */
       }
       achl_rp = (char *) (adsl_clrecv_cur + 1);
       achl_inend = achl_rp + adsl_clrecv_cur->imc_len_recv;
     }
     switch (*achl_rp) {
       case CHAR_CR:                        /* carriage-return         */
         if ((iml1 & 1) == 0) iml1++;
         else iml1 = 1;
         break;
       case CHAR_LF:                        /* line-feed               */
         if (iml1 & 1) iml1++;
         break;
       default:
         iml1 = 0;
         break;
     }
     achl_rp++;                             /* next input              */
     if (iml1 == 4) break;                  /* end of data found       */
   }
#ifdef B100214
   if (iml2 != 204) {
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() status-no not 204",
                     __LINE__ );
// 08.07.08 KB to-do CMA close
//   return 0;
     goto p_recv_60;                        /* received illogic        */
   }
#endif
#ifdef CRASH_120203_01                      /* crash when 204 - virus checked */
   ExitProcess( 815 );
#endif
   if (iml2 != 204) {                       /* did not receive unmodified */
     goto p_recv_20;                        /* did not receive unmodified */
   }
   if (   (achl_rp < ((char *) (adsl_clrecv_cur + 1) + adsl_clrecv_cur->imc_len_recv))
       || (adsl_vchact_cur->adsc_recv_ch->adsc_next)) {
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() received too much after ICAP Unmodified",
                     __LINE__ );
     goto p_recv_60;                        /* received illogic        */
   }
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCRCO1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "virus-checker %p has responded 204 - no virus",
                     adsl_vchact_cur );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   adsl_clrecv_cur = adsl_vchact_cur->adsc_recv_ch;  /* get first in chain */
   do {                                     /* loop over chain         */
     adsl_clrecv_w1 = adsl_clrecv_cur;      /* save current entry      */
     adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
     m_proc_free( adsl_clrecv_w1 );         /* free block used         */
   } while (adsl_clrecv_cur);
   adsl_vchact_cur->adsc_recv_ch = NULL;    /* no block received       */
   adsl_vchact_cur->iec_var = ied_var_no_virus;  /* file does not contain virus */
#ifdef OLD01
   if (adsl_vchact_cur->adsc_sevirch_entry->boc_close_after_scan) {  /* this virus checker closes after each scan */
     adsl_vchact_cur->iec_vat = ied_vat_wait_close;  /* TCP session wait for close */
   }
#endif
   switch (adsl_vchact_cur->adsc_sevirch_entry->iec_vvr) {  /* virus checker reuse */
     case ied_vve_wait_close:               /* wait for close          */
       adsl_vchact_cur->iec_vat = ied_vat_wait_close;  /* TCP session wait for close */
       break;
     case ied_vve_do_close:                 /* do close                */
#ifndef B120119
       adsl_vchact_cur->iec_vat = ied_vat_wait_close;  /* TCP session wait for close */
#endif
       if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCCLO1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id           */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         iml2 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                         "close TCP connection to virus-checker %p.",
                         adsl_vchact_cur );
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         ADSL_WTR_G1->achc_content          /* content of text / data  */
           = (char *) (ADSL_WTR_G1 + 1);
         ADSL_WTR_G1->imc_length = iml2;    /* length of text / data   */
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
         m_wsp_trace_out( adsl_wt1_w1 );    /* output of WSP trace record */
       }
#ifdef B120116
       adsp_tcpco->m_end_session();
       adsl_vchact_cur->iec_vat = ied_vat_wait_close;  /* TCP session wait for close */
#endif
#ifndef B120116
#ifdef B120119
       adsl_vchact_cur->iec_vat = ied_vat_wait_close;  /* TCP session wait for close */
#endif
       adsp_tcpco->m_end_session();
#endif
       break;
   }
   /* check if all virus checker have responded                        */
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
#ifdef DEBUG_120122_01                      /* sending to ICAP stops   */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXX9", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "DEBUG_120122_01 l%05d thread=%d - after  lock-enter",
                     __LINE__, HL_GET_THREAD );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
   adsl_virch_session = adsl_vchact_cur->adsc_virch_requ->adsc_virch_session;
   adsl_vchact_w1 = adsl_vchact_cur->adsc_virch_requ->adsc_virch_act_ch;  /* chain active virus checking connections */
   bol1 = TRUE;                             /* all sessions are complete */
   do {                                     /* loop over active connections */
     if (   (adsl_vchact_w1->iec_var != ied_var_no_virus)  /* file does not contain virus */
         && (adsl_vchact_w1->iec_var != ied_var_virus_found)) {  /* file contains virus */
       bol1 = FALSE;                        /* not all sessions are complete */
     }
     adsl_vchact_w1 = adsl_vchact_w1->adsc_requ_next;  /* next in chain for this request */
   } while (adsl_vchact_w1);
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
   if (bol1 == FALSE) return 1;             /* not yet complete        */
// to-do 22.09.09 KB better do atomic, Assembler Subroutine
   if (adsl_vchact_cur->adsc_virch_requ->adsc_virch_session == NULL) return 1;  /* no more session */
   adsl_vchact_cur->adsc_virch_requ->adsc_virch_session = NULL;  /* is in progress to be deleted */
   if (adsl_vchact_cur->adsc_virch_requ->dsc_timer_ele.vpc_chain_2) {  /* timer set */
     m_time_rel( &adsl_vchact_cur->adsc_virch_requ->dsc_timer_ele );  /* release timer */
   }
   /* to-do 09.07.08 KB - all sessions have to be complete */
   /* inform Server-Data-Hook that the file has been checked for Viruses */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCRCO3", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "activate SDH, file has no virus - ac_control_area=%p.",
                     adsl_virch_req_cur->ac_control_area );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#define ADSL_SE_VCH_CONTR_1 ((struct dsd_se_vch_contr_1 *) adsl_virch_req_cur->ac_control_area)  /* service virus checking control area */
   ADSL_SE_VCH_CONTR_1->iec_vchcompl = ied_vchcompl_ok;  /* file has no virus */
#undef ADSL_SE_VCH_CONTR_1
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_virch_recvcallback() adsl_virch_session=%p.",
                   __LINE__, adsl_virch_session );
#endif
   m_wsp_s_ent_notify( adsl_virch_session->adsc_conn1,
                       (char *) adsl_virch_session - sizeof(struct dsd_service_aux_1),
                       adsl_virch_session->imc_signal );
   /* all active sessions may be reused                                */
   adsl_vchact_rem = adsl_virch_req_cur->adsc_virch_act_ch;  /* chain active virus checking connections */
   adsl_virch_req_cur->adsc_virch_act_ch = NULL;  /* clear chain active virus checking connections */
// to-do 24.07.08 KB critical section
// 10.09.09 KB critical section not needed ???
   /* check where the request has to be removed                        */
   adsl_virch_req_w1 = adsl_virch_session->adsc_virch_req_ch;  /* chain of virus checking requests */
   adsl_virch_req_w2 = NULL;                /* no previous element yet */
   while (adsl_virch_req_w1) {              /* loop over all requests  */
     if (adsl_virch_req_w1 == adsl_vchact_cur->adsc_virch_requ) break;
     adsl_virch_req_w2 = adsl_virch_req_w1;  /* set previous element   */
     adsl_virch_req_w1 = adsl_virch_req_w1->adsc_next;  /* get next in chain */
   }
   do {                                     /* loop over active connections */
#ifdef DEBUG_120119_02                      /* check ied_vat_active    */
     if (adsl_vchact_rem->iec_vat == ied_vat_active) {  /* TCP session active */
       m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d DEBUG_120119_02 adsl_vchact_rem=%p.",
                       __LINE__, adsl_vchact_rem );
     }
#endif
     adsl_vchact_rem->adsc_virch_requ = NULL;  /* virus checking request no more active */
     adsl_vchact_del = adsl_vchact_rem;     /* active virus checking connection to be deleted */
     adsl_vchact_rem = adsl_vchact_rem->adsc_requ_next;  /* next in chain for this request */
     while (adsl_vchact_del->iec_vat == ied_vat_closed) {  /* TCP session is closed */
       adsl_se_w1 = adsl_vchact_del->adsc_sevirch_entry;  /* server entry */
       if (adsl_vchact_del == adsl_se_w1->adsc_virch_act) {  /* active virus checking connection */
         adsl_se_w1->adsc_virch_act = adsl_vchact_del->adsc_se_next;  /* next in chain server entry */
         free( adsl_vchact_del );           /* free memory again       */
         break;
       }
       adsl_vchact_w1 = adsl_se_w1->adsc_virch_act;  /* get chain active virus checking connection */
       do {                                 /* loop over all active elements */
         adsl_vchact_w2 = adsl_vchact_w1;   /* save previous entry     */
         adsl_vchact_w1 = adsl_vchact_w1->adsc_se_next;  /* next in chain server entry */
       } while (adsl_vchact_w1 != adsl_vchact_del);
       adsl_vchact_w2->adsc_se_next = adsl_vchact_del->adsc_se_next;  /* next in chain server entry */
       free( adsl_vchact_del );             /* free memory again       */
       break;
     }
   } while (adsl_vchact_rem);
   /* remove request from chain                                        */
   if (adsl_virch_req_w2 == NULL) {         /* remove at beginning of chain */
     adsl_virch_session->adsc_virch_req_ch = adsl_virch_req_w1->adsc_next;  /* remove from chain */
   } else {                                 /* remove middle in chain  */
     adsl_virch_req_w2->adsc_next = adsl_virch_req_w1->adsc_next;  /* remove from chain */
   }
   if (adsl_virch_req_w1->dsc_timer_ele.amc_compl != &m_virch_timer) return 1;  /* check routine for timeout */
   adsl_virch_req_w1->dsc_timer_ele.amc_compl = &m_virch_free;  /* set routine for free */
   m_time_set( &adsl_virch_req_w1->dsc_timer_ele, FALSE );  /* set the timer */
   return 1;                                /* continue receiving      */

   p_recv_20:                               /* did not receive unmodified */
   if (iml2 != 200) {                       /* did not receive OK      */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() received unknown ICAP status %03d.",
                     __LINE__, iml2 );
     goto p_recv_60;                        /* received illogic        */
   }
   while (adsl_clrecv_cur != adsl_vchact_cur->adsc_recv_ch) {  /* compare first in chain */
     adsl_clrecv_w1 = adsl_vchact_cur->adsc_recv_ch;  /* save current entry */
     adsl_vchact_cur->adsc_recv_ch = adsl_clrecv_w1->adsc_next;  /* get next in chain */
     m_proc_free( adsl_clrecv_w1 );         /* free block used         */
   }
   adsl_clrecv_cur->achc_processed = achl_rp;  /* processed so far */
   if (achl_rp >= ((char *) (adsl_clrecv_cur + 1) + adsl_clrecv_cur->imc_len_recv)) {
     adsl_clrecv_w1 = adsl_vchact_cur->adsc_recv_ch;  /* save current entry */
     adsl_vchact_cur->adsc_recv_ch = adsl_vchact_cur->adsc_recv_ch->adsc_next;  /* get next in chain */
     m_proc_free( adsl_clrecv_w1 );         /* free block used         */
   }
   adsl_vchact_cur->iec_var = ied_var_rec_http;  /* receive HTTP       */
   if (adsl_vchact_cur->adsc_recv_ch == NULL) return 1;  /* receive more data */

   p_recv_24:                               /* check HTTP header       */
   adsl_clrecv_cur = adsl_vchact_cur->adsc_recv_ch;  /* get first in chain */
   achl_rp = adsl_clrecv_cur->achc_processed;  /* processed so far     */
   achl_inend = (char *) (adsl_clrecv_cur + 1) + adsl_clrecv_cur->imc_len_recv;
   achl_cmp1 = "HTTP/1.0 ";
   do {
     if (achl_rp >= achl_inend) {           /* at end of buffer        */
       adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
       if (adsl_clrecv_cur == NULL) {       /* was last in chain       */
         return 1;                          /* receive more            */
       }
       achl_rp = (char *) (adsl_clrecv_cur + 1);
       achl_inend = achl_rp + adsl_clrecv_cur->imc_len_recv;
     }
     if (*achl_rp++ != *achl_cmp1++) {
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() end of HTTP",
                       __LINE__ );
       goto p_recv_60;                      /* received illogic        */
     }
   } while (*achl_cmp1);
   iml1 = 3;
   iml2 = 0;
   do {
     if (achl_rp >= achl_inend) {
       adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
       if (adsl_clrecv_cur == NULL) {       /* was last in chain       */
         return 1;                          /* receive more            */
       }
       achl_rp = adsl_clrecv_cur->achc_processed;  /* processed so far */
       achl_inend = (char *) (adsl_clrecv_cur + 1) + adsl_clrecv_cur->imc_len_recv;
     }
     if ((*achl_rp < '0') || (*achl_rp > '9')) {
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() HTTP status-no not numeric",
                       __LINE__ );
       goto p_recv_60;                      /* received illogic        */
     }
     iml2 *= 10;
     iml2 += *achl_rp++ - '0';
     iml1--;
   } while (iml1);
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() HTTP status-no %d.",
                   __LINE__, iml2 );
#endif
   if (iml2 != 403) {                       /* did not receive forbidden */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() received unknown HTTP status %03d.",
                     __LINE__, iml2 );
     goto p_recv_60;                        /* received illogic        */
   }
   /* check data till CR LF CR LF                                      */
   while (TRUE) {
     if (achl_rp >= achl_inend) {
       adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
       if (adsl_clrecv_cur == NULL) {       /* was last in chain       */
         iml1 = MAX_LEN_H_HTTP;             /* maximum length HTTP header */
         adsl_clrecv_cur = adsl_vchact_cur->adsc_recv_ch;  /* get first in chain */
         do {                               /* loop over all blocks received */
           iml1 -= adsl_clrecv_cur->imc_len_recv;
           if (iml1 < 0) {                  /* ICAP header is too long */
             m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() HTTP header too long",
                             __LINE__ );
             goto p_recv_60;                /* received illogic        */
           }
           adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
         } while (adsl_clrecv_cur);
         return 1;                          /* receive more            */
       }
       achl_rp = (char *) (adsl_clrecv_cur + 1);
       achl_inend = achl_rp + adsl_clrecv_cur->imc_len_recv;
     }
     switch (*achl_rp) {
       case CHAR_CR:                        /* carriage-return         */
         if ((iml1 & 1) == 0) iml1++;
         else iml1 = 1;
         break;
       case CHAR_LF:                        /* line-feed               */
         if (iml1 & 1) iml1++;
         break;
       default:
         iml1 = 0;
         break;
     }
     achl_rp++;                             /* next input              */
     if (iml1 == 4) break;                  /* end of data found       */
   }
   bol_vir_name = FALSE;                    /* clear virus name found  */
   achl_cmp1 = NULL;                        /* clear compare text      */
   achl_out = NULL;                         /* clear output to virus name */

   p_recv_28:                               /* get length chunk HTTP   */
   /* get length chunk                                                 */
   iml1 = 8;
   iml2 = 0;
   while (TRUE) {
     if (achl_rp >= achl_inend) {
       adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
       if (adsl_clrecv_cur == NULL) {       /* was last in chain       */
         return 1;                          /* receive more            */
       }
       achl_rp = adsl_clrecv_cur->achc_processed;  /* processed so far */
       achl_inend = (char *) (adsl_clrecv_cur + 1) + adsl_clrecv_cur->imc_len_recv;
     }
     if ((*achl_rp >= '0') && (*achl_rp <= '9')) {
       iml3 = *achl_rp - '0';
     } else if ((*achl_rp >= 'A') && (*achl_rp <= 'F')) {
       iml3 = *achl_rp - 'A' + 10;
     } else if ((*achl_rp >= 'a') && (*achl_rp <= 'f')) {
       iml3 = *achl_rp - 'a' + 10;
     } else if (*achl_rp == 0X0D) {
       break;
     } else {
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() HTTP chunk length contains %02X.",
                       __LINE__, (unsigned char) *achl_rp );
       goto p_recv_60;                      /* received illogic        */
     }
     if (iml1 <= 0) {                       /* too many digits         */
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() HTTP chunk length contains too many hex digits",
                       __LINE__ );
       goto p_recv_60;                      /* received illogic        */
     }
     achl_rp++;                             /* input next character    */
     iml2 <<= 4;                            /* shift old value         */
     iml2 |= iml3;
     iml1--;
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() HTTP chunk-length %d/0X%0X.",
                   __LINE__, iml2, iml2 );
#endif
   achl_rp++;                               /* input next character    */
   if (achl_rp >= achl_inend) {
     adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
     if (adsl_clrecv_cur == NULL) {         /* was last in chain       */
       return 1;                            /* receive more            */
     }
     achl_rp = adsl_clrecv_cur->achc_processed;  /* processed so far   */
     achl_inend = (char *) (adsl_clrecv_cur + 1) + adsl_clrecv_cur->imc_len_recv;
   }
   if (*achl_rp != 0X0A) {                  /* not line feed           */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() HTTP after chunk %02X.",
                     __LINE__, (unsigned char) *achl_rp );
     goto p_recv_60;                        /* received illogic        */
   }
   achl_rp++;                               /* input next character    */
   if (iml2) {                              /* chunk follows           */
     goto p_recv_40;                        /* process chunk HTTP      */
   }
   /* check if CR LF follow                                            */
   iml1 = 0;                                /* set default character   */
   bol_error = FALSE;                       /* no error found          */
   while (TRUE) {                           /* loop over remaining characters */
     if (achl_rp >= achl_inend) {
       adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
       if (adsl_clrecv_cur == NULL) {       /* was last in chain       */
         return 1;                          /* receive more            */
       }
       achl_rp = (char *) (adsl_clrecv_cur + 1);
       achl_inend = achl_rp + adsl_clrecv_cur->imc_len_recv;
     }
     switch (*achl_rp) {
       case CHAR_CR:                        /* carriage-return         */
         if ((iml1 & 1) == 0) {
           iml1 = 1;
           break;
         }
         bol_error = TRUE;                  /* error found             */
         break;
       case CHAR_LF:                        /* line-feed               */
         if (iml1 & 1) {
           iml1 = 2;
           break;
         }
         bol_error = TRUE;                  /* error found             */
         break;
       default:
         bol_error = TRUE;                  /* error found             */
         break;
     }
     if (bol_error) break;                  /* error found             */
     achl_rp++;                             /* next input              */
     if (iml1 == 2) break;                  /* end of data found       */
   }
   if (bol_error) {                         /* error found             */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() HTTP end of chunks invalid",
                     __LINE__ );
     goto p_recv_60;                        /* received illogic        */
   }
   adsl_clrecv_cur->achc_processed = achl_rp;  /* processed so far     */
   if (achl_rp >= ((char *) (adsl_clrecv_cur + 1) + adsl_clrecv_cur->imc_len_recv)) {
     do {                                   /* loop to free buffers    */
       adsl_clrecv_w1 = adsl_vchact_cur->adsc_recv_ch;  /* save current entry */
       adsl_vchact_cur->adsc_recv_ch = adsl_vchact_cur->adsc_recv_ch->adsc_next;  /* get next in chain */
       m_proc_free( adsl_clrecv_w1 );       /* free block used         */
     } while (adsl_clrecv_w1 != adsl_clrecv_cur);
   }
   if (adsl_vchact_cur->adsc_recv_ch) {
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() received too much after HTTP Forbidden",
                     __LINE__ );
     goto p_recv_60;                        /* received illogic        */
   }
   if (bol_vir_name == FALSE) {             /* virus name not found    */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() received HTTP but virus name not found",
                     __LINE__ );
     goto p_recv_60;                        /* received illogic        */
   }
// to-do 08.03.10 KB - give message with Virus found if Trace on
#define ADSL_VIRCH_REQ_G adsl_virch_req_cur
   if (ADSL_VIRCH_REQ_G == NULL) goto p_recv_36;  /* no request associated */
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
#ifdef DEBUG_120122_01                      /* sending to ICAP stops   */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXX9", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "DEBUG_120122_01 l%05d thread=%d - after  lock-enter",
                     __LINE__, HL_GET_THREAD );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
// to-do 22.09.09 KB better do atomic, Assembler Subroutine
   adsl_virch_session = ADSL_VIRCH_REQ_G->adsc_virch_session;
   if (adsl_virch_session == NULL) {        /* no more session         */
     dsg_global_lock.m_leave();             /* leave CriticalSection   */
     goto p_recv_36;                        /* end of virus received   */
   }
   ADSL_VIRCH_REQ_G->adsc_virch_session = NULL;  /* is in progress to be deleted */
   adsl_vchact_w1 = ADSL_VIRCH_REQ_G->adsc_virch_act_ch;  /* get chain active virus checking connections */
   while (adsl_vchact_w1) {                 /* loop over all remaining connections */
#ifdef DEBUG_120119_02                      /* check ied_vat_active    */
     if (adsl_vchact_w1->iec_vat == ied_vat_active) {  /* TCP session active */
       m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d DEBUG_120119_02 adsl_vchact_w1=%p.",
                       __LINE__, adsl_vchact_w1 );
     }
#endif
     adsl_vchact_w1->adsc_virch_requ = NULL;  /* no more virus checking request */
     if (   (adsl_vchact_w1->iec_vat == ied_vat_active)  /* TCP session active */
         && (adsl_vchact_w1->iec_var != ied_var_no_virus)  /* file does not contain virus */
         && (adsl_vchact_w1->iec_var != ied_var_virus_found)) {  /* file contains virus */
// to-do 15.02.10 does not set ied_var_virus_found
       if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data   */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCCLO2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id           */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                         "close TCP connection to virus-checker %p.",
                         adsl_vchact_w1 );
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         ADSL_WTR_G1->achc_content          /* content of text / data  */
           = (char *) (ADSL_WTR_G1 + 1);
         ADSL_WTR_G1->imc_length = iml1;    /* length of text / data   */
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
         m_wsp_trace_out( adsl_wt1_w1 );    /* output of WSP trace record */
       }
       adsl_vchact_w1->iec_vat = ied_vat_wait_close;  /* TCP session wait for close */
       adsl_vchact_w1->dsc_tcpcomp.m_end_session();
     }
     adsl_vchact_w1 = adsl_vchact_w1->adsc_requ_next;  /* get next in chain */
   }
   ADSL_VIRCH_REQ_G->adsc_virch_act_ch = NULL;  /* clear chain active virus checking connections */
   /* inform Server-Data-Hook that a Virus has beend detected          */
#define ADSL_SE_VCH_CONTR_1 ((struct dsd_se_vch_contr_1 *) ADSL_VIRCH_REQ_G->ac_control_area)  /* service virus checking control area */
   iml1 = achl_out - chrl_virus_name;       /* length returned virus name */
   ADSL_SE_VCH_CONTR_1->imc_len_virus_name = iml1;  /* length returned virus name */
   memcpy( ADSL_SE_VCH_CONTR_1->chrc_virus_name, chrl_virus_name, ADSL_SE_VCH_CONTR_1->imc_len_virus_name );
   ADSL_SE_VCH_CONTR_1->iec_vchcompl = ied_vchcompl_virus;  /* file contains virus */
#undef ADSL_SE_VCH_CONTR_1
   m_wsp_s_ent_notify( adsl_virch_session->adsc_conn1,
                       (char *) adsl_virch_session - sizeof(struct dsd_service_aux_1),
                       adsl_virch_session->imc_signal );
   adsl_virch_req_w1 = adsl_virch_session->adsc_virch_req_ch;  /* chain of virus checking requests */
   adsl_virch_req_w2 = NULL;                /* no previous element yet */
   while (adsl_virch_req_w1) {              /* loop over all requests  */
     if (adsl_virch_req_w1 == ADSL_VIRCH_REQ_G) break;
     adsl_virch_req_w2 = adsl_virch_req_w1;  /* set previous element   */
     adsl_virch_req_w1 = adsl_virch_req_w1->adsc_next;  /* get next in chain */
   }
   /* remove request from chain                                        */
   if (adsl_virch_req_w2 == NULL) {         /* remove at beginning of chain */
     adsl_virch_session->adsc_virch_req_ch = adsl_virch_req_w1->adsc_next;  /* remove from chain */
   } else {                                 /* remove middle in chain  */
     adsl_virch_req_w2->adsc_next = adsl_virch_req_w1->adsc_next;  /* remove from chain */
   }
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
   if (adsl_virch_req_w1->dsc_timer_ele.amc_compl == &m_virch_timer) {  /* check routine for timeout */
     adsl_virch_req_w1->dsc_timer_ele.amc_compl = &m_virch_free;  /* set routine for free */
     m_time_set( &adsl_virch_req_w1->dsc_timer_ele, FALSE );  /* set the timer */
   }
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCVIR1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "virus-checker %p found virus name \"%.*s\"",
                     adsl_vchact_w1, iml1, chrl_virus_name );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#undef ADSL_VIRCH_REQ_G

   p_recv_36:                               /* end of virus received   */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCCLO3", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "close TCP connection to virus-checker %p.",
                     adsl_vchact_w1 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   adsl_vchact_cur->iec_vat = ied_vat_wait_close;  /* TCP session wait for close */
   adsl_vchact_cur->dsc_tcpcomp.m_end_session();
#ifndef B111219
   if (adsl_clrecv_param) {                 /* receive block passed    */
     m_proc_free( adsl_clrecv_param );      /* free block passed       */
   }
#endif
   return 0;                                /* stop receiving          */

   p_recv_40:                               /* process chunk HTTP      */
   if (achl_rp >= achl_inend) {
     adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
     if (adsl_clrecv_cur == NULL) {         /* was last in chain       */
       return 1;                            /* receive more            */
     }
     achl_rp = (char *) (adsl_clrecv_cur + 1);
     achl_inend = achl_rp + adsl_clrecv_cur->imc_len_recv;
   }
   if (iml2 <= 0) {                         /* characters in chunk     */
     goto p_recv_48;                        /* search CR LF at end of chunk */
   }
   iml1 = achl_inend - achl_rp;             /* remaining characters    */
   if (iml1 > iml2) iml1 = iml2;
   if (bol_vir_name) {                      /* virus name found        */
     achl_rp += iml1;                       /* next input              */
     iml2 -= iml1;                          /* characters in chunk     */
     goto p_recv_40;                        /* process chunk HTTP      */
   }
   while (achl_cmp1) {                      /* compare text            */
     iml3 = ((char *) ucrs_icap_vn_c_icap_00 + sizeof(ucrs_icap_vn_c_icap_00)) - achl_cmp1;  /* remaining text */
     if (iml3 > iml1) iml3 = iml1;
     if (memcmp( achl_rp, achl_cmp1, iml3 )) {  /* does not compare    */
       achl_cmp1 = NULL;                    /* stop to compare text    */
       break;
     }
     achl_cmp1 += iml3;                     /* characters have been compared */
     achl_rp += iml3;                       /* skip input characters   */
     iml2 -= iml3;                          /* characters processed    */
     if (achl_cmp1 < ((char *) ucrs_icap_vn_c_icap_00 + sizeof(ucrs_icap_vn_c_icap_00))) {  /* remaining text */
       goto p_recv_40;                      /* process chunk HTTP      */
     }
     achl_cmp1 = NULL;                      /* no more compare         */
     achl_out = chrl_virus_name;            /* output to virus name    */
     goto p_recv_40;                        /* process chunk HTTP      */
   }
   if (achl_out) {                          /* output to virus name    */
     if (((unsigned char) *achl_rp) == 0X0A) {  /* end of virus name   */
       bol_vir_name = TRUE;                 /* virus name found        */
       achl_rp++;                           /* next input              */
       iml2--;                              /* characters in chunk     */
       goto p_recv_40;                      /* process chunk HTTP      */
     }
     if (achl_out < (chrl_virus_name + sizeof(chrl_virus_name))) {  /* space in output area */
       *achl_out++ = *achl_rp;              /* get input character     */
     }
     achl_rp++;                             /* next input              */
     iml2--;                                /* characters in chunk     */
     goto p_recv_40;                        /* process chunk HTTP      */
   }
   achl_w1 = (char *) memchr( achl_rp, *ucrs_icap_vn_c_icap_00, iml1 );
   if (achl_w1 == NULL) {                   /* first character not found */
     achl_rp += iml1;                       /* skip input characters   */
     iml2 -= iml1;                          /* characters processed    */
     goto p_recv_40;                        /* process chunk HTTP      */
   }
   iml2 -= (achl_w1 + 1) - achl_rp;         /* so many characters processed */
   achl_rp = achl_w1 + 1;                   /* input after first character */
   achl_cmp1 = (char *) ucrs_icap_vn_c_icap_00 + 1;  /* compare text from here */
   goto p_recv_40;                          /* process chunk HTTP      */

   p_recv_48:                               /* search CR LF at end of chunk */
   /* check if CR LF follow                                            */
   iml1 = 0;                                /* set default character   */
   bol_error = FALSE;                       /* no error found          */
   while (TRUE) {                           /* loop over remaining characters */
     if (achl_rp >= achl_inend) {
       adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
       if (adsl_clrecv_cur == NULL) {       /* was last in chain       */
         return 1;                          /* receive more            */
       }
       achl_rp = (char *) (adsl_clrecv_cur + 1);
       achl_inend = achl_rp + adsl_clrecv_cur->imc_len_recv;
     }
     switch (*achl_rp) {
       case CHAR_CR:                        /* carriage-return         */
         if ((iml1 & 1) == 0) {
           iml1 = 1;
           break;
         }
         bol_error = TRUE;                  /* error found             */
         break;
       case CHAR_LF:                        /* line-feed               */
         if (iml1 & 1) {
           iml1 = 2;
           break;
         }
         bol_error = TRUE;                  /* error found             */
         break;
       default:
         bol_error = TRUE;                  /* error found             */
         break;
     }
     if (bol_error) break;                  /* error found             */
     achl_rp++;                             /* next input              */
     if (iml1 == 2) break;                  /* end of data found       */
   }
   if (bol_error) {                         /* error found             */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() HTTP end of chunk invalid",
                     __LINE__ );
     goto p_recv_60;                        /* received illogic        */
   }
   goto p_recv_28;                          /* get length chunk HTTP   */

   p_recv_60:                               /* received illogic        */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap-%05d-W m_recvcallback() p_recv_60",
                   __LINE__ );
#endif
#ifdef B111221
#ifndef B111205
   if (adsl_clrecv_param) {                 /* receive block passed    */
     m_proc_free( adsl_clrecv_param );      /* free block passed       */
   }
#endif
#endif
#ifdef B100214
   m_proc_free( adsl_vchact_cur->adsc_recv_ch );  /* free block used   */
#endif
   /* error 21 = response from Virus-Checker invalid                   */
   adsl_clrecv_cur = adsl_vchact_cur->adsc_recv_ch;  /* get first in chain */
   adsl_vchact_cur->adsc_recv_ch = NULL;    /* all packets deleted     */
   while (adsl_clrecv_cur) {
     adsl_clrecv_w1 = adsl_clrecv_cur;      /* save current entry      */
     adsl_clrecv_cur = adsl_clrecv_cur->adsc_next;  /* get next in chain */
     m_proc_free( adsl_clrecv_w1 );         /* free block used         */
   }
#define ADSL_VIRCH_REQ_G adsl_virch_req_cur
   if (ADSL_VIRCH_REQ_G == NULL) goto p_recv_80;  /* no request associated */
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
#ifdef DEBUG_120122_01                      /* sending to ICAP stops   */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXXA", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "DEBUG_120122_01 l%05d thread=%d - after  lock-enter",
                     __LINE__, HL_GET_THREAD );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
// to-do 22.09.09 KB better do atomic, Assembler Subroutine
   adsl_virch_session = ADSL_VIRCH_REQ_G->adsc_virch_session;
   if (adsl_virch_session == NULL) {        /* no more session         */
     dsg_global_lock.m_leave();             /* leave CriticalSection   */
     goto p_recv_80;                        /* already in progress to be deleted */
   }
   ADSL_VIRCH_REQ_G->adsc_virch_session = NULL;  /* is in progress to be deleted */
   adsl_vchact_w1 = ADSL_VIRCH_REQ_G->adsc_virch_act_ch;  /* get chain active virus checking connections */
   while (adsl_vchact_w1) {                 /* loop over all remaining connections */
#ifdef DEBUG_120119_02                      /* check ied_vat_active    */
     if (adsl_vchact_w1->iec_vat == ied_vat_active) {  /* TCP session active */
       m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d DEBUG_120119_02 adsl_vchact_w1=%p.",
                       __LINE__, adsl_vchact_w1 );
     }
#endif
     adsl_vchact_w1->adsc_virch_requ = NULL;  /* no more virus checking request */
     if (   (adsl_vchact_w1->iec_vat == ied_vat_active)  /* TCP session active */
         && (adsl_vchact_w1->iec_var != ied_var_no_virus)  /* file does not contain virus */
         && (adsl_vchact_w1->iec_var != ied_var_virus_found)) {  /* file contains virus */
       if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data   */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCCLO4", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id           */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                         "close TCP connection to virus-checker %p.",
                         adsl_vchact_w1 );
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         ADSL_WTR_G1->achc_content          /* content of text / data  */
           = (char *) (ADSL_WTR_G1 + 1);
         ADSL_WTR_G1->imc_length = iml1;    /* length of text / data   */
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
         m_wsp_trace_out( adsl_wt1_w1 );    /* output of WSP trace record */
       }
       adsl_vchact_w1->iec_vat = ied_vat_wait_close;  /* TCP session wait for close */
       adsl_vchact_w1->dsc_tcpcomp.m_end_session();
     }
     adsl_vchact_w1 = adsl_vchact_w1->adsc_requ_next;  /* get next in chain */
   }
   ADSL_VIRCH_REQ_G->adsc_virch_act_ch = NULL;  /* clear chain active virus checking connections */
   /* inform Server-Data-Hook that Virus Checking has failed           */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCRCO2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "Virus Checking has failed - invalid response from virus checker" );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#define ADSL_SE_VCH_CONTR_1 ((struct dsd_se_vch_contr_1 *) ADSL_VIRCH_REQ_G->ac_control_area)  /* service virus checking control area */
   ADSL_SE_VCH_CONTR_1->iec_vchcompl = ied_vchcompl_vch_inv_resp;  /* invalid response from virus checker */
#undef ADSL_SE_VCH_CONTR_1
   m_wsp_s_ent_notify( adsl_virch_session->adsc_conn1,
                       (char *) adsl_virch_session - sizeof(struct dsd_service_aux_1),
                       adsl_virch_session->imc_signal );
   adsl_virch_req_w1 = adsl_virch_session->adsc_virch_req_ch;  /* chain of virus checking requests */
   adsl_virch_req_w2 = NULL;                /* no previous element yet */
   while (adsl_virch_req_w1) {              /* loop over all requests  */
     if (adsl_virch_req_w1 == ADSL_VIRCH_REQ_G) break;
     adsl_virch_req_w2 = adsl_virch_req_w1;  /* set previous element   */
     adsl_virch_req_w1 = adsl_virch_req_w1->adsc_next;  /* get next in chain */
   }
   /* remove request from chain                                        */
   if (adsl_virch_req_w2 == NULL) {         /* remove at beginning of chain */
     adsl_virch_session->adsc_virch_req_ch = adsl_virch_req_w1->adsc_next;  /* remove from chain */
   } else {                                 /* remove middle in chain  */
     adsl_virch_req_w2->adsc_next = adsl_virch_req_w1->adsc_next;  /* remove from chain */
   }
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
   if (adsl_virch_req_w1->dsc_timer_ele.amc_compl == &m_virch_timer) {  /* check routine for timeout */
     adsl_virch_req_w1->dsc_timer_ele.amc_compl = &m_virch_free;  /* set routine for free */
     m_time_set( &adsl_virch_req_w1->dsc_timer_ele, FALSE );  /* set the timer */
   }
#undef ADSL_VIRCH_REQ_G

   p_recv_80:                               /* free block received and close TCP session */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCCLO5", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "close TCP connection to virus-checker %p.",
                     adsl_vchact_cur );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   adsl_vchact_cur->iec_vat = ied_vat_wait_close;  /* TCP session wait for close */
   adsl_vchact_cur->dsc_tcpcomp.m_end_session();
#ifndef B111219
   if (adsl_clrecv_param) {                 /* receive block passed    */
     m_proc_free( adsl_clrecv_param );      /* free block passed       */
   }
#endif
   return 0;                                /* stop receiving          */
} /* end m_virch_recvcallback()                                        */

/** TCPCOMP error callback function                                    */
static void m_virch_errorcallback( dsd_tcpcomp *adsp_tcpco,
                                   void * vpp_userfld,
                                   char * achp_error,
                                   int imp_error,
                                   int imp_where )
{
   int        iml1;                         /* working-variable        */
   struct dsd_virch_active *adsl_vchact;    /* active virus checking connection */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
#ifdef OLD01
   int        iml_rc;                       /* return code             */
   char       *achl1;                       /* working variable        */
   socklen_t  iml_namelen;                  /* length of name          */
   struct sockaddr_storage dsl_soa_conn;    /* address information for connect */
   char       chrl_server_ineta[ LEN_DISP_INETA ];  /* for server INETA */
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap-%05d-T m_errorcallback() called",
                   __LINE__ );
#endif
   adsl_vchact = (struct dsd_virch_active *) vpp_userfld;
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCTERR", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "TCP connection to virus-checker %p TCP session status = %d error %s %d %d.",
                     adsl_vchact, adsl_vchact->iec_vat,
                     achp_error, imp_error, imp_where );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#ifdef OLD01
   if (adsl_vchact->imc_ind_conn >= 0) {    /* connect not yet successful */
     m_set_connect_p1( &dsl_soa_conn, &iml_namelen,
                       adsl_vchact->adsc_sevirch_entry->adsc_server_ineta,
                       adsl_vchact->imc_ind_conn );
     iml_rc = IP_getnameinfo( (SOCKADDR *) &dsl_soa_conn, iml_namelen,
                              chrl_server_ineta, sizeof(chrl_server_ineta),
                              0, 0, NI_NUMERICHOST );
     if (iml_rc) {                            /* error occured           */
       printf( "xs-gw-serv-vch-icap-%05d-W getnameinfo Error %d %d",
               __LINE__, iml_rc, D_TCP_ERROR );
       strcpy( chrl_server_ineta, "???" );
     }
     achl1 = "";
     if ((adsl_vchact->imc_ind_conn + 1) < adsl_vchact->adsc_sevirch_entry->adsc_server_ineta->imc_no_ineta) {
       achl1 = " - try next INETA";
     } else if (adsl_vchact->adsc_sevirch_entry->adsc_server_ineta->imc_no_ineta > 1) {
       achl1 = " - was last INETA";
     }
     printf( "xs-gw-serv-vch-icap-%05d-W connect to server INETA %s error %d%s\n",
             __LINE__, chrl_server_ineta, imp_error, achl1 );
     return;
   }
#endif
// to-do 21.07.11 KB name of Virus checker
   m_hlnew_printf( HLOG_WARN1, "xs-gw-serv-vch-icap l%05d TCP error %s %d %d.",
                   __LINE__, achp_error, imp_error, imp_where );
} /* m_virch_errorcallback()                                           */

/** TCPCOMP cleanup callback function                                  */
static void m_virch_cleanup( dsd_tcpcomp *adsp_tcpco, void *vpp_userfld ) {
   int        iml1;                         /* working-variable        */
   int        iml_count_sg;                 /* count server groups     */
   int        iml_count_act;                /* count active TCP sessions */
   int        iml_epoch;                    /* current time            */
   enum ied_vchact_tcp_st iel_vat;          /* active connection TCP session status */
   struct dsd_virch_active *adsl_vchact_cur;  /* active virus checking connection */
   struct dsd_virch_active *adsl_vchact_w1;  /* active virus checking connection */
   struct dsd_virch_active *adsl_vchact_w2;  /* active virus checking connection */
// struct dsd_virch_active *adsl_vchact_last;  /* active virus checking connection */
   struct dsd_se_vcicaphttp_entry *adsl_se_w1;  /* working-variable server-entry */
   struct dsd_virch_request *adsl_virch_req_cur;  /* virus checking request */
   struct dsd_virch_request *adsl_virch_req_w1;  /* virus checking request */
   struct dsd_virch_request *adsl_virch_req_w2;  /* virus checking request */
   struct dsd_virch_session *adsl_virch_session;  /* virus checking bound to session */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_random_server dsl_rse;        /* search server in random order */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap-%05d-T m_virch_cleanup() called",
                   __LINE__ );
#endif
#ifdef TRACEHL_090912_01
   bog_trace_v1 = TRUE;                     /* variable for debugging  */
#endif
   adsl_vchact_cur = (struct dsd_virch_active *) vpp_userfld;
   iel_vat = adsl_vchact_cur->iec_vat;      /* save active connection TCP session status */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCCLU1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "TCP connection to virus-checker %p cleanup TCP session status %d.",
                     adsl_vchact_cur, iel_vat );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   adsl_vchact_cur->iec_vat = ied_vat_closed;  /* TCP session is closed */
#ifdef B120119
#ifndef B120116
   if (iel_vat == ied_vat_wait_close) {     /* TCP session wait for close */
     return;                                /* nothing more to do      */
   }
#endif
#else
#ifdef NONSENSE_120119
   if (   (iel_vat == ied_vat_wait_close)   /* TCP session wait for close */
       && (adsl_vchact_cur->iec_var != ied_var_closed)) {  /* TCP session is closed - can remove connection */
     return;                                /* nothing more to do      */
   }
#else
   if (   (iel_vat == ied_vat_wait_close)   /* TCP session wait for close */
       && (adsl_vchact_cur->adsc_virch_requ)) {  /* virus checking request still active */
     return;                                /* nothing more to do      */
   }
#endif
#endif
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
#ifdef DEBUG_120122_01                      /* sending to ICAP stops   */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXXB", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "DEBUG_120122_01 l%05d thread=%d - after  lock-enter",
                     __LINE__, HL_GET_THREAD );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
   if (adsl_vchact_cur->adsc_virch_requ == NULL) {  /* virus checking request not active */
     goto p_cleanup_80;                     /* do only cleanup         */
   }
#ifdef TRACEHL1
   {
     char chrh_work1[128];
     adsl_virch_req_cur = adsl_vchact_cur->adsc_virch_requ;  /* get virus checking request */
     adsl_virch_session = adsl_virch_req_cur->adsc_virch_session;
     sprintf( chrh_work1, " = NULL" );
     if (adsl_virch_session) {
       sprintf( chrh_work1, "->adsc_conn1=%p.", adsl_virch_session->adsc_conn1 );
     }
     m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_virch_cleanup() adsl_virch_session%s",
                     __LINE__, chrh_work1 );
   }
#endif
#ifdef DEBUG_120613_01                      /* remove from chain problem */
   adsl_virch_req_cur = adsl_vchact_cur->adsc_virch_requ;  /* get virus checking request */
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_virch_cleanup() adsl_virch_req_cur->adsc_virch_act_ch=%p.",
                   __LINE__, adsl_virch_req_cur->adsc_virch_act_ch );
#endif
   iml_epoch = (int) time( NULL );          /* get current time        */
   adsl_vchact_cur->adsc_sevirch_entry->imc_time_retry
     = iml_epoch + adsl_vchact_cur->adsc_sevirch_entry->imc_retry_ae;
   /* remove from chain, anchor is in request                          */
   adsl_virch_req_cur = adsl_vchact_cur->adsc_virch_requ;  /* get virus checking request */
   adsl_vchact_w1 = adsl_virch_req_cur->adsc_virch_act_ch;  /* get chain active virus checking connections */
   if (adsl_vchact_w1 == adsl_vchact_cur) {  /* is first in chain      */
     adsl_virch_req_cur->adsc_virch_act_ch = adsl_vchact_w1->adsc_requ_next;  /* get next in chain for this request */
   } else {                                 /* middle in chain         */
     do {                                   /* loop to find entry      */
#ifdef DEBUG_120613_01                      /* remove from chain problem */
       if (adsl_vchact_w1 == NULL) {
         m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_virch_cleanup() adsl_vchact_w1 == NULL",
                         __LINE__ );
         break;
       }
#endif
       adsl_vchact_w2 = adsl_vchact_w1;     /* save this entry         */
       adsl_vchact_w1 = adsl_vchact_w1->adsc_requ_next;  /* get next in chain */
     } while (adsl_vchact_w1 != adsl_vchact_cur);
#ifdef DEBUG_120613_01                      /* remove from chain problem */
     if (adsl_vchact_w1) {
#endif
     adsl_vchact_w2->adsc_requ_next = adsl_vchact_w1->adsc_requ_next;  /* remove from chain */
#ifdef DEBUG_120613_01                      /* remove from chain problem */
     }
#endif
   }
   if (iel_vat != ied_vat_w_conn) {         /* not wait for connect    */
     goto p_cleanup_40;                     /* end of session while data transmitted */
   }
   adsl_vchact_cur->adsc_sevirch_entry->imc_stat_no_conn_failed++;  /* statistic number of connects failed */
/**
   check if another server of this group can be used,
   if not either this server is not necessary or the virus checking request fails
*/
#define ADSL_VIRCH_CONF (adsl_vchact_cur->adsc_sevirch_entry->adsc_sg_this->adsc_virch_conf)
   dsl_rse.adsc_sg = ADSL_VIRCH_CONF->adsc_sg_ch;  /* get chain server groups */
   iml_count_sg = ADSL_VIRCH_CONF->imc_need_ch_no_g;  /* number of groups that need to check */

   p_cleanup_20:                            /* check this server group */
   adsl_vchact_w1 = adsl_virch_req_cur->adsc_virch_act_ch;  /* get chain active virus checking connections */
   while (adsl_vchact_w1) {                 /* loop over all remaining connections */
     if (adsl_vchact_w1->adsc_sevirch_entry->adsc_sg_this == dsl_rse.adsc_sg) {
       goto p_cleanup_32;                   /* this server group in use */
     }
     adsl_vchact_w1 = adsl_vchact_w1->adsc_requ_next;  /* get next in chain */
   }
   dsl_rse.imc_no_checked = 0;              /* clear number of already checked servers */

   p_cleanup_24:                            /* check next server entry */
   adsl_se_w1 = m_get_se_random( &dsl_rse );  /* get next server-entry */
   if (adsl_se_w1 == NULL) goto p_cleanup_28;  /* was last server-entry */
   while (adsl_se_w1->imc_time_retry) {     /* time next retry set     */
     if (adsl_se_w1->imc_time_retry <= iml_epoch) {  /* time next retry reached */
       adsl_se_w1->imc_time_retry = 0;      /* clear time next retry   */
       break;
     }
     goto p_cleanup_24;                     /* this server entry not usable */
   }
   iml_count_act = 0;                       /* reset count active TCP sessions */
   adsl_vchact_w1 = adsl_se_w1->adsc_virch_act;  /* get chain of active TCP sessions */
   while (adsl_vchact_w1) {                 /* loop over all active TCP sessions */
     if (   (adsl_vchact_w1->adsc_virch_requ == NULL)  /* no virus checking request */
         && (adsl_vchact_w1->iec_vat == ied_vat_active)) {  /* TCP session active */
       adsl_vchact_w1->iec_var = ied_var_invalid;  /* does not wait for receive data */
       adsl_vchact_w1->adsc_virch_requ = adsl_virch_req_cur;  /* set virus checking request */
       adsl_vchact_w1->adsc_requ_next = NULL;  /* clear chain request  */
#ifdef NOT_YET
       if (adsl_vchact_w2 == NULL) {  /* at anchor of chain     */
         adsp_virch_req->adsc_virch_act_ch = adsl_vchact_w1;  /* chain active virus checking connections */
       } else {                         /* middle in chain         */
         adsl_vchact_w2->adsc_requ_next = adsl_vchact_w1;  /* next in chain for this request */
       }
       adsl_vchact_w2 = adsl_vchact_w1;  /* save last active TCP session */
#endif
       goto p_cleanup_32;                   /* active TCP session found */
     }
     iml_count_act++;                       /* increment count active TCP sessions */
     adsl_vchact_w1 = adsl_vchact_w1->adsc_se_next;  /* next in chain server entry */
   }
   if (iml_count_act < adsl_se_w1->imc_max_session) {  /* compare count active TCP sessions */
     adsl_vchact_w1 = m_new_active_virch( adsl_se_w1 );  /* create new active TCP session */
     if (adsl_vchact_w1) {                  /* active TCP session created */
       adsl_vchact_w1->adsc_virch_requ = adsl_virch_req_cur;  /* set virus checking request */
#ifndef TRY_120619_01                       /* put in chain of adsc_virch_act_ch */
       adsl_vchact_w1->adsc_requ_next = NULL;  /* clear chain request */
#endif
#ifdef TRY_120619_01                        /* put in chain of adsc_virch_act_ch */
       adsl_vchact_w1->adsc_requ_next = adsl_virch_req_cur->adsc_virch_act_ch;  /* next in chain for this request */
       adsl_virch_req_cur->adsc_virch_act_ch = adsl_vchact_w1;  /* this is first in chain now */
#endif
#ifdef NOT_YET
       if (adsl_vchact_w2 == NULL) {  /* at anchor of chain     */
         adsp_virch_req->adsc_virch_act_ch = adsl_vchact_w1;  /* chain active virus checking connections */
       } else {                         /* middle in chain         */
         adsl_vchact_w2->adsc_requ_next = adsl_vchact_w1;  /* next in chain for this request */
       }
       adsl_vchact_w2 = adsl_vchact_w1;  /* save last active TCP session */
       break;                           /* all done this server entry */
#endif
       if ((img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) == 0) goto p_cleanup_32;  /* no trace Virus checking */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data     */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCUEX2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id             */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "use existing TCP connection %p for virus-checking",
                       adsl_vchact_w1 );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content            /* content of text / data  */
         = (char *) (ADSL_WTR_G1 + 1);
       ADSL_WTR_G1->imc_length = iml1;      /* length of text / data   */
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
       goto p_cleanup_32;                   /* active TCP session created */
     }
   }

   p_cleanup_28:                            /* end of this server group */
   /* no server found in this server group                             */
   if (dsl_rse.adsc_sg->boc_must_check) {   /* this group must check   */
     goto p_cleanup_40;                     /* the necessary servers not found */
   }
   goto p_cleanup_36;                       /* get next server group   */

   p_cleanup_32:                            /* this server group in use */
   iml_count_sg--;                          /* decrement number of groups that need to check */

   p_cleanup_36:                            /* get next server group   */
   dsl_rse.adsc_sg = dsl_rse.adsc_sg->adsc_next;  /* get next server group in chain */
   if (dsl_rse.adsc_sg) goto p_cleanup_20;  /* check this server group */
   if (iml_count_sg <= 0) {                 /* compare number of groups that need to check */
#ifdef DEBUG_120120_01                      /* m_check_first_packet()  */
     m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d DEBUG_120120_01 adsl_virch_req_cur=%p.",
                     __LINE__, adsl_virch_req_cur );
#endif
     m_check_first_packet( adsl_virch_req_cur );  /* check send first packet */
     goto p_cleanup_80;                     /* all done                */
   }

#ifdef XYZ1
   p_cup_no_serv_00:                        /* the necessary servers not found */
   adsl_vchact_w1 = adsl_virch_req_cur->adsc_virch_act_ch;  /* chain active virus checking connections */
   while (adsl_vchact_w1) {              /* loop over all entries created */
     adsl_vchact_w1->adsc_virch_requ = NULL;  /* clear virus checking request */
     adsl_vchact_w1 = adsl_vchact_w1->adsc_requ_next;  /* get next in chain */
   }
   adsl_virch_req_cur->adsc_virch_act_ch = NULL;  /* clear chain active virus checking connections */
   /* inform Server-Data-Hook that Virus Checking has failed           */
#define ADSL_SE_VCH_CONTR_1 ((struct dsd_se_vch_contr_1 *) adsl_virch_req_cur->ac_control_area)  /* service virus checking control area */
   ADSL_SE_VCH_CONTR_1->iec_vchcompl = ied_vchcompl_no_server;  /* the necessary servers not found */
#undef ADSL_SE_VCH_CONTR_1
   adsl_virch_session = adsl_virch_req_cur->adsc_virch_session;
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_virch_cleanup() adsl_virch_session=%p.",
                   __LINE__, adsl_virch_session );
#endif
   m_wsp_s_ent_notify( adsl_virch_session->adsc_conn1,
                       (char *) adsl_virch_session - sizeof(struct dsd_service_aux_1),
                       adsl_virch_session->imc_signal );
   adsl_virch_req_w1 = adsl_virch_session->adsc_virch_req_ch;  /* chain of virus checking requests */
   adsl_virch_req_w2 = NULL;                /* no previous element yet */
   while (adsl_virch_req_w1) {              /* loop over all requests  */
     if (adsl_virch_req_w1 == adsl_virch_req_cur) break;
     adsl_virch_req_w2 = adsl_virch_req_w1;  /* set previous element   */
     adsl_virch_req_w1 = adsl_virch_req_w1->adsc_next;  /* get next in chain */
   }
#ifdef XYZ1
   do {                                     /* loop over active connections */
     adsl_vchact_rem->adsc_virch_requ = NULL;  /* virus checking request no more active */
     adsl_vchact_del = adsl_vchact_rem;     /* active virus checking connection to be deleted */
     adsl_vchact_rem = adsl_vchact_rem->adsc_requ_next;  /* next in chain for this request */
     while (adsl_vchact_del->iec_vat == ied_vat_closed) {  /* TCP session is closed */
       adsl_se_w1 = adsl_vchact_del->adsc_sevirch_entry;  /* server entry */
       if (adsl_vchact_del == adsl_se_w1->adsc_virch_act) {  /* active virus checking connection */
         adsl_se_w1->adsc_virch_act = adsl_vchact_del->adsc_se_next;  /* next in chain server entry */
         free( adsl_vchact_del );           /* free memory again       */
         break;
       }
       adsl_vchact_w1 = adsl_se_w1->adsc_virch_act;  /* get chain active virus checking connection */
       do {                                 /* loop over all active elements */
         adsl_vchact_w2 = adsl_vchact_w1;   /* save previous entry     */
         adsl_vchact_w1 = adsl_vchact_w1->adsc_se_next;  /* next in chain server entry */
       } while (adsl_vchact_w1 != adsl_vchact_del);
       adsl_vchact_w2->adsc_se_next = adsl_vchact_del->adsc_se_next;  /* next in chain server entry */
       free( adsl_vchact_del );             /* free memory again       */
       break;
     }
   } while (adsl_vchact_rem);
#endif
   /* remove request from chain                                        */
   if (adsl_virch_req_w2 == NULL) {         /* remove at beginning of chain */
     adsl_virch_session->adsc_virch_req_ch = adsl_virch_req_w1->adsc_next;  /* remove from chain */
   } else {                                 /* remove middle in chain  */
     adsl_virch_req_w2->adsc_next = adsl_virch_req_w1->adsc_next;  /* remove from chain */
   }
   free( adsl_virch_req_w1 );               /* free storage            */

#undef ADSL_VIRCH_CONF
#endif

   p_cleanup_40:                            /* end of session while data transmitted / end virus-checking */
// to-do 22.09.09 KB better do atomic, Assembler Subroutine
   adsl_virch_session = adsl_virch_req_cur->adsc_virch_session;
   if (adsl_virch_session == NULL) goto p_cleanup_80;  /* already in progress to be deleted */
   adsl_virch_req_cur->adsc_virch_session = NULL;  /* is in progress to be deleted */
   if (   (adsl_virch_req_cur->dsc_timer_ele.amc_compl == &m_virch_timer)  /* check routine for timeout */
       && (adsl_virch_req_cur->dsc_timer_ele.vpc_chain_2)) {  /* timer set */
     m_time_rel( &adsl_virch_req_cur->dsc_timer_ele );  /* release timer */
   }
   adsl_vchact_w1 = adsl_virch_req_cur->adsc_virch_act_ch;  /* chain active virus checking connections */
   while (adsl_vchact_w1) {                 /* loop over all entries created */
#ifdef DEBUG_120119_02                      /* check ied_vat_active    */
     if (adsl_vchact_w1->iec_vat == ied_vat_active) {  /* TCP session active */
       m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d DEBUG_120119_02 adsl_vchact_w1=%p.",
                       __LINE__, adsl_vchact_w1 );
     }
#endif
     adsl_vchact_w1->adsc_virch_requ = NULL;  /* clear virus checking request */
     if (iel_vat != ied_vat_w_conn) {       /* not wait for connect    */
       if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data   */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCCLO6", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id           */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                         "close TCP connection to virus-checker %p.",
                         adsl_vchact_w1 );
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         ADSL_WTR_G1->achc_content          /* content of text / data  */
           = (char *) (ADSL_WTR_G1 + 1);
         ADSL_WTR_G1->imc_length = iml1;    /* length of text / data   */
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
         m_wsp_trace_out( adsl_wt1_w1 );    /* output of WSP trace record */
       }
       adsl_vchact_w1->iec_vat = ied_vat_wait_close;  /* TCP session wait for close */
       adsl_vchact_w1->dsc_tcpcomp.m_end_session();
     }
     adsl_vchact_w1 = adsl_vchact_w1->adsc_requ_next;  /* get next in chain */
   }
   adsl_virch_req_cur->adsc_virch_act_ch = NULL;  /* clear chain active virus checking connections */
   /* inform Server-Data-Hook that Virus Checking has failed           */
#define ADSL_SE_VCH_CONTR_1 ((struct dsd_se_vch_contr_1 *) adsl_virch_req_cur->ac_control_area)  /* service virus checking control area */
   if (iel_vat == ied_vat_w_conn) {         /* wait for connect        */
     ADSL_SE_VCH_CONTR_1->iec_vchcompl = ied_vchcompl_no_server;  /* the necessary servers not found */
   } else {
     ADSL_SE_VCH_CONTR_1->iec_vchcompl = ied_vchcompl_comm_error;  /* communication error */
   }
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCCLC1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "activate SDH, error iec_vchcompl=%d ac_control_area=%p.",
                     ADSL_SE_VCH_CONTR_1->iec_vchcompl,
                     ADSL_SE_VCH_CONTR_1 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#undef ADSL_SE_VCH_CONTR_1
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_virch_cleanup() adsl_virch_session=%p.",
                   __LINE__, adsl_virch_session );
#endif
   m_wsp_s_ent_notify( adsl_virch_session->adsc_conn1,
                       (char *) adsl_virch_session - sizeof(struct dsd_service_aux_1),
                       adsl_virch_session->imc_signal );
   adsl_virch_req_w1 = adsl_virch_session->adsc_virch_req_ch;  /* chain of virus checking requests */
   adsl_virch_req_w2 = NULL;                /* no previous element yet */
   while (adsl_virch_req_w1) {              /* loop over all requests  */
     if (adsl_virch_req_w1 == adsl_virch_req_cur) break;
     adsl_virch_req_w2 = adsl_virch_req_w1;  /* set previous element   */
     adsl_virch_req_w1 = adsl_virch_req_w1->adsc_next;  /* get next in chain */
   }
   /* remove request from chain                                        */
   if (adsl_virch_req_w2 == NULL) {         /* remove at beginning of chain */
     adsl_virch_session->adsc_virch_req_ch = adsl_virch_req_w1->adsc_next;  /* remove from chain */
   } else {                                 /* remove middle in chain  */
     adsl_virch_req_w2->adsc_next = adsl_virch_req_w1->adsc_next;  /* remove from chain */
   }
   if (adsl_virch_req_w1->dsc_timer_ele.amc_compl == &m_virch_timer) {  /* check routine for timeout */
     adsl_virch_req_w1->dsc_timer_ele.amc_compl = &m_virch_free;  /* set routine for free */
     m_time_set( &adsl_virch_req_w1->dsc_timer_ele, FALSE );  /* set the timer */
   }

   p_cleanup_80:                            /* remove entry from active sessions */
   adsl_se_w1 = adsl_vchact_cur->adsc_sevirch_entry;  /* server entry */
   if (adsl_vchact_cur == adsl_se_w1->adsc_virch_act) {  /* active virus checking connection */
     adsl_se_w1->adsc_virch_act = adsl_vchact_cur->adsc_se_next;  /* next in chain server entry */
     free( adsl_vchact_cur );               /* free memory again       */
     dsg_global_lock.m_leave();             /* leave CriticalSection   */
     return;
   }
   adsl_vchact_w1 = adsl_se_w1->adsc_virch_act;  /* get chain active virus checking connection */
   do {                                     /* loop over all active elements */
     adsl_vchact_w2 = adsl_vchact_w1;       /* save previous entry     */
     adsl_vchact_w1 = adsl_vchact_w1->adsc_se_next;  /* next in chain server entry */
   } while (adsl_vchact_w1 != adsl_vchact_cur);
   adsl_vchact_w2->adsc_se_next = adsl_vchact_cur->adsc_se_next;  /* next in chain server entry */
   free( adsl_vchact_cur );                 /* free memory             */
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
} /* end m_virch_cleanup()                                             */

/** routine called by timer thread when Virus Checking times out       */
static void m_virch_timer( struct dsd_timer_ele *adsp_timer_ele ) {
   int        iml1;                         /* working-variable        */
   struct dsd_virch_active *adsl_vchact_w1;  /* active virus checking connection */
   struct dsd_virch_session *adsl_virch_session;  /* virus checking bound to session */
   struct dsd_virch_request *adsl_virch_req_w1;  /* virus checking request */
   struct dsd_virch_request *adsl_virch_req_w2;  /* virus checking request */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */

#define ADSL_VIRCH_REQ_G ((struct dsd_virch_request *) ((char *) adsp_timer_ele - offsetof( struct dsd_virch_request, dsc_timer_ele )))

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d m_virch_timer() adsp_timer_ele=%p ADSL_VIRCH_REQ=%p.",
                   __LINE__, adsp_timer_ele, ADSL_VIRCH_REQ_G );
#endif
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCTIMO", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "timeout of virus-checker %p.",
                     ADSL_VIRCH_REQ_G );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   dsg_global_lock.m_enter();               /* enter CriticalSection   */
#ifdef DEBUG_120122_01                      /* sending to ICAP stops   */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCSXXC", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "DEBUG_120122_01 l%05d thread=%d - after  lock-enter",
                     __LINE__, HL_GET_THREAD );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
// to-do 22.09.09 KB better do atomic, Assembler Subroutine
   adsl_virch_session = ADSL_VIRCH_REQ_G->adsc_virch_session;
   if (adsl_virch_session == NULL) {        /* no more session         */
     dsg_global_lock.m_leave();             /* leave CriticalSection   */
     return;
   }
   ADSL_VIRCH_REQ_G->adsc_virch_session = NULL;  /* is in progress to be deleted */
   adsl_vchact_w1 = ADSL_VIRCH_REQ_G->adsc_virch_act_ch;  /* get chain active virus checking connections */
   while (adsl_vchact_w1) {                 /* loop over all remaining connections */
#ifdef DEBUG_120119_02                      /* check ied_vat_active    */
     if (adsl_vchact_w1->iec_vat == ied_vat_active) {  /* TCP session active */
       m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d DEBUG_120119_02 adsl_vchact_w1=%p.",
                       __LINE__, adsl_vchact_w1 );
     }
#endif
     adsl_vchact_w1->adsc_virch_requ = NULL;  /* no more virus checking request */
     if (   (adsl_vchact_w1->iec_vat == ied_vat_active)  /* TCP session active */
         && (adsl_vchact_w1->iec_var != ied_var_no_virus)  /* file does not contain virus */
         && (adsl_vchact_w1->iec_var != ied_var_virus_found)) {  /* file contains virus */
       if (img_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH) {  /* Virus checking */
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data   */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, "CSVCCLO7", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id           */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                         "close TCP connection to virus-checker %p.",
                         adsl_vchact_w1 );
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         ADSL_WTR_G1->achc_content          /* content of text / data  */
           = (char *) (ADSL_WTR_G1 + 1);
         ADSL_WTR_G1->imc_length = iml1;    /* length of text / data   */
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
         m_wsp_trace_out( adsl_wt1_w1 );    /* output of WSP trace record */
       }
       adsl_vchact_w1->iec_vat = ied_vat_wait_close;  /* TCP session wait for close */
       adsl_vchact_w1->dsc_tcpcomp.m_end_session();
     }
     adsl_vchact_w1 = adsl_vchact_w1->adsc_requ_next;  /* get next in chain */
   }
   ADSL_VIRCH_REQ_G->adsc_virch_act_ch = NULL;  /* clear chain active virus checking connections */
   /* inform Server-Data-Hook that Virus Checking has failed           */
#define ADSL_SE_VCH_CONTR_1 ((struct dsd_se_vch_contr_1 *) ADSL_VIRCH_REQ_G->ac_control_area)  /* service virus checking control area */
   ADSL_SE_VCH_CONTR_1->iec_vchcompl = ied_vchcompl_vch_timeout;  /* timeout while virus checking */
#undef ADSL_SE_VCH_CONTR_1
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d xs-gw-serv-vch-icap m_virch_timer() adsl_virch_session=%p.",
                   __LINE__, adsl_virch_session );
#endif
   m_wsp_s_ent_notify( adsl_virch_session->adsc_conn1,
                       (char *) adsl_virch_session - sizeof(struct dsd_service_aux_1),
                       adsl_virch_session->imc_signal );
   adsl_virch_req_w1 = adsl_virch_session->adsc_virch_req_ch;  /* chain of virus checking requests */
   adsl_virch_req_w2 = NULL;                /* no previous element yet */
   while (adsl_virch_req_w1) {              /* loop over all requests  */
     if (adsl_virch_req_w1 == ADSL_VIRCH_REQ_G) break;
     adsl_virch_req_w2 = adsl_virch_req_w1;  /* set previous element   */
     adsl_virch_req_w1 = adsl_virch_req_w1->adsc_next;  /* get next in chain */
   }
   /* remove request from chain                                        */
   if (adsl_virch_req_w2 == NULL) {         /* remove at beginning of chain */
     adsl_virch_session->adsc_virch_req_ch = adsl_virch_req_w1->adsc_next;  /* remove from chain */
   } else {                                 /* remove middle in chain  */
     adsl_virch_req_w2->adsc_next = adsl_virch_req_w1->adsc_next;  /* remove from chain */
   }
   dsg_global_lock.m_leave();               /* leave CriticalSection   */
   if (adsl_virch_req_w1->dsc_timer_ele.amc_compl != &m_virch_timer) return;  /* check routine for timeout */
   adsl_virch_req_w1->dsc_timer_ele.amc_compl = &m_virch_free;  /* set routine for free */
   m_time_set( &adsl_virch_req_w1->dsc_timer_ele, FALSE );  /* set the timer */
#undef ADSL_VIRCH_REQ_G
} /* end m_virch_timer()                                               */

/** routine called by timer thread when request can be freed           */
static void m_virch_free( struct dsd_timer_ele *adsp_timer_ele ) {
#define ADSL_VIRCH_REQ_G ((struct dsd_virch_request *) ((char *) adsp_timer_ele - offsetof( struct dsd_virch_request, dsc_timer_ele )))
#ifdef TRACEHL1
#ifdef B100214
#define ADSL_SE_VCH_CONTR_1 ((struct dsd_se_vch_contr_1 *) ADSL_VIRCH_REQ_G->ac_control_area)  /* service virus checking control area */
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d m_virch_free() ADSL_VIRCH_REQ_G=%p ilc_window_1=%lld ilc_window_2=%lld.",
                   __LINE__, ADSL_VIRCH_REQ_G, ADSL_SE_VCH_CONTR_1->ilc_window_1, ADSL_SE_VCH_CONTR_1->ilc_window_2 );
#undef ADSL_SE_VCH_CONTR_1
#endif
   m_hlnew_printf( HLOG_TRACE1, "xs-gw-serv-vch-icap.cpp l%05d m_virch_free() ADSL_VIRCH_REQ_G=%p.",
                   __LINE__, ADSL_VIRCH_REQ_G );
#endif
   free( ADSL_VIRCH_REQ_G );                /* free storage            */
#undef ADSL_VIRCH_REQ_G
} /* end m_virch_free()                                                */

/** output number                                                      */
static char * m_put_no( char *achp_target, int imp_inp ) {
   do {                                     /* loop output digits      */
     *(--achp_target) = (imp_inp % 10) + '0';
     imp_inp /= 10;
   } while (imp_inp > 0);
   return achp_target;
} /* end m_put_no()                                                    */
