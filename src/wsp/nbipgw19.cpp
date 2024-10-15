//#define CONTROL_INETAS
//#define TRACEHL1
//#define TRACEHL_CLLI
#ifdef D_INCL_HOB_TUN
#define CONTROL_INETAS
#endif
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: nbipgw19                                            |*/
/*| -------------                                                     |*/
/*|  Program for communication with the Unix WebSecureProxies         |*/
/*|    (nbipgw20)                                                     |*/
/*|    for functions which need administration rights                 |*/
/*|    or communication between multiple WebSecureProxies             |*/
/*|  part of HOB RD VPN                                               |*/
/*|  KB 26.07.11                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2016                                   |*/
/*|                                                                   |*/
/*| EXPECTED INPUT:                                                   |*/
/*| ---------------                                                   |*/
/*| parameter domain-socket=       name of Unix domain socket         |*/
/*| parameter shared-secret=       shared secret for communication    |*/
/*|                                  with WSP (HOB WebSecureProxy)    |*/
/*| parameter log                  write messages to log              |*/
/*| parameter trace=               display trace messages             |*/
/*|                                  of certain level                 |*/
/*|                                                                   |*/
/*| EXPECTED OUTPUT:                                                  |*/
/*| ----------------                                                  |*/
/*|  displays messages on console                                     |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#ifndef HL_UNIX
#ifdef HL_LINUX
#define HL_UNIX
#endif
#ifdef HL_FREEBSD
#define HL_UNIX
#endif
#endif

#ifdef HL_LINUX
#define D_UMASK
#endif
#ifdef __FreeBSD__
#define D_UMASK
#endif
#ifndef HL_SOLARIS
#ifndef HL_HPUX
#define MSGHDR_CONTROL_AVAILABLE 1
#endif
#endif

#define DOMNode void *

#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#ifdef D_INCL_HOB_TUN
#ifdef CONTROL_INETAS
#include <stddef.h>
#endif
#endif
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#ifdef B120306
#ifdef HL_LINUX
#include <pth.h>
#endif
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#ifdef D_UMASK
#include <sys/stat.h>
#endif
#include <netinet/in.h>
#include <sys/time.h>
#include <syslog.h>
#ifdef D_INCL_HOB_TUN
#include <sys/ioctl.h>
//#include <sys/net/if.h>
#ifndef HL_LINUX
#include <net/if.h>
#include <net/if_arp.h>
#endif
#include <net/route.h>
#ifdef HL_LINUX
#include <linux/if_tun.h>                   /* check for other unixes   */
#endif
#include <ifaddrs.h>
#endif
#include <hob-unix01.h>
#include <hob-xslunic1.h>
#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>
#include <hob-netw-01.h>
#include <hob-tcpcomp-singthr.hpp>
#include <hob-encry-1.h>
#ifdef D_INCL_HOB_TUN
#ifdef CONTROL_INETAS
#include <hob-avl03.h>
#endif
#include <net/if.h>
#ifdef HL_LINUX
#include <netpacket/packet.h>
#endif
#include <net/ethernet.h>                   /* the L2 protocols        */
#include <net/if_arp.h>
#ifdef HL_FREEBSD
#include <net/if_dl.h>
#include <net/if_tun.h>
#include <net/bpf.h>
#ifndef B160502
#include <net/if_var.h>
#include <netinet/in_var.h>
#endif
#endif
#endif
#include "hob-li-gw-01.h"
#define INCL_GW_EXTERN
#define HL_KRB5
#define NOT_INCLUDED_CLIB
#include "hob-xbipgw08-1.h"
#include "hob-xbipgw08-2.h"

#define D_BUFFER_LEN           8192         /* length of receive buffer */
#define D_BACKLOG              8            /* backlog for listen      */
#define D_MAX_LEN_NHASN        4            /* maximum length NHASN    */

#define D_TCP_ERROR errno
#define D_TCP_CLOSE close
#ifndef UNSIG_MED
#define UNSIG_MED unsigned int
#endif
#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif
#ifndef HL_LONGLONG
#define HL_LONGLONG long long int
#endif
#define D_CHARSET_IP ied_chs_ascii_850      /* ASCII 850               */
#define DEF_IPLEVEL            4            /* Level in Log            */
#define D_POLL_MAX             64           /* maximum number of poll events */
#define LEN_DISP_INETA         56           /* length display Internet Address */
#ifdef D_INCL_HOB_TUN
#ifdef HL_FREEBSD
#define MAX_TRY_BPF            128
#endif
#ifdef CONTROL_INETAS
#define NO_STRUCT_INETA        64           /* number of struct INETA to be allocated */
#endif
#endif

#ifdef XYZ1
/** Default name of the Unix domain socket used for communication with the clients */
#define DEFAULT_UDSNAME "/tmp/nbipgw19.uds"
/** Default for the shared secret                                      */
#define DEFAULT_SECRET "SADFACTORYWORKER"
#endif

/*+-------------------------------------------------------------------+*/
/*| Function Calls definitions.                                       |*/
/*+-------------------------------------------------------------------+*/

extern "C" int m_hl1_printf( char *, ... );

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

static void m_cluster_listen_close( struct dsd_listen * );
static void m_cb_nbacc_acceptcallback( class dsd_nblock_acc *, void *, int, struct sockaddr *, int );
static void m_cb_nbacc_errorcallback( class dsd_nblock_acc *, void *, char *, int, int );  // Error callback function.
static int m_tccb_all_getrecvcallback( class dsd_tcpcomp *, void *, void **, char **, int ** );
static void m_tccb_wsp_sendcallback( class dsd_tcpcomp *, void * );
static BOOL m_tccb_wsp_recvcallback( class dsd_tcpcomp *, void *, void * );
static void m_tccb_wsp_errorcallback( class dsd_tcpcomp *, void *, char *, int, int );
static void m_tccb_wsp_cleanup( class dsd_tcpcomp *, void * );
static void m_tccb_cluster_sendcallback( class dsd_tcpcomp *, void * );
static BOOL m_tccb_cluster_recvcallback( class dsd_tcpcomp *, void *, void * );
static void m_tccb_cluster_errorcallback( class dsd_tcpcomp *, void *, char *, int, int );
static void m_tccb_cluster_cleanup( class dsd_tcpcomp *, void * );
static void m_wsp_send_msg( struct dsd_wsp_conn *, char *, ... );
#ifdef D_INCL_HOB_TUN
static BOOL m_htun_search_interface_ipv4( UNSIG_MED ump_ineta );
#ifdef HL_FREEBSD
static int m_htun_get_bpf_socket( char * );
#endif
#ifdef CONTROL_INETAS
static int m_cmp_ineta_ipv4( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
#endif
#endif
static void * m_proc_alloc( void );
static void m_proc_free( void * );
static void m_console_out( char *achp_buff, int implength );

/*+-------------------------------------------------------------------+*/
/*| global used dsects = structures.                                  |*/
/*+-------------------------------------------------------------------+*/

#ifndef DEF_HL_STR_G_I_1
#define DEF_HL_STR_G_I_1
struct dsd_gather_i_1 {                     /* gather input data       */
   struct dsd_gather_i_1 *adsc_next;        /* next in chain           */
   char *     achc_ginp_cur;                /* current position        */
   char *     achc_ginp_end;                /* end of input data       */
};
#endif

enum ied_decode_wsp_recv_1 {                /* decode received from WSP */
   ied_dwr1_header = 0,                     /* header received         */
   ied_dwr1_nonce,                          /* nonce received          */
   ied_dwr1_len_nhasn,                      /* length NHASN            */
   ied_dwr1_content                         /* content                 */
};

enum ied_decode_cluster_recv_1 {            /* decode received from cluster */
   ied_dcr1_header = 0,                     /* header received         */
   ied_dcr1_tag,                            /* tag                     */
   ied_dcr1_len_nhasn                       /* length NHASN            */
};

enum ied_listen_type {                      /* type of listen          */
   ied_lit_unix = 0,                        /* Unix socket             */
   ied_lit_cluster,                         /* cluster                 */
// to-do 19.09.11 KB not needed
   ied_lit_lpd,                             /* LDP - line printer daemon */
   ied_lit_ipp                              /* IPP - internet print protocol */
};

struct dsd_listen {                         /* for UDS and TCP listen  */
   struct dsd_listen *adsc_next;            /* for chaining            */
   enum ied_listen_type iec_lit;            /* type of listen          */
   class dsd_nblock_acc dsc_acc_lis;        /* accept structure        */
};

enum ied_conn_type {                        /* type of connection      */
#ifdef XYZ1
   ied_tco_unix = 0,                        /* Unix socket             */
   ied_tco_tcp                              /* TCP connection          */
#endif
   ied_cot_invalid = 0,                     /* invalid type            */
   ied_cot_wsp                              /* connection to a WSP     */
};

struct dsd_connect {                        /* for Unix or TCP connection */
#ifdef XYZ1
   struct dsd_connect *adsc_next;           /* next in chain           */
#endif
   enum ied_conn_type iec_cot;              /* type of connection      */
   struct dsd_receive_1 *adsc_rec1_ch;      /* chain of receive areas  */
   class dsd_tcpcomp dsc_tcpco1;            /* TCP connection object   */
};

struct dsd_receive_1 {                      /* area for receive        */
   struct dsd_receive_1 *adsc_next;         /* chain of receive areas  */
   int        imc_rc;                       /* returned from receive   */
   struct dsd_gather_i_1 dsc_gai1_r;        /* gather input data       */
};

struct dsd_send_block {                     /* send block              */
   struct dsd_gather_i_1 *adsc_gai1_s;      /* send data gather        */
};

struct dsd_ligw_clli_ext {                  /* extension listen for cluster */
   struct sockaddr_storage dsc_soa;         /* sockaddr for listen     */
   int        imc_usage;                    /* usage count             */
};

struct dsd_wsp_conn {                       /* connection to a WSP     */
   struct dsd_wsp_conn *adsc_next;          /* for chaining            */
   BOOL       boc_first_message;            /* first message has arrived */
   int        imc_pid;                      /* process id              */
   int        imc_no_clli;                  /* number of cluster listen */
   int        imc_len_cluster;              /* length cluster entry    */
   char       *achc_cluster;                /* cluster entry           */
   struct dsd_listen *adsrc_clli[ D_LIGW_MAX_CLUSTER_WSP ];  /* maximum number of cluster listen per WSP */
   struct dsd_connect dsc_connect;          /* connection              */
};

struct dsd_cluster_conn {                   /* connection to a cluster member */
   BOOL       boc_first_message;            /* first message has arrived */
   int        imc_pid;                      /* process id              */
   struct dsd_connect dsc_connect;          /* connection              */
   char       chrc_ineta[ LEN_DISP_INETA ];  /* internet-address char  */
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

#ifdef HL_FREEBSD
struct dsd_hobtun_bpf_ctrl {                /* structure for bpf - Berkeley Packet Filter */
   struct dsd_hobtun_bpf_ctrl *adsc_next;   /* for chaining            */
   int        imc_bpf_fd;                   /* file-descriptor for bpf - Berkeley Packet Filter */
   char       chrc_riface[ IFNAMSIZ ];      /* name of real interface  */
};
#endif
#ifdef CONTROL_INETAS
struct dsd_control_ineta_ipv4 {             /* structure to control INETAs IPV4 */
   union {
     struct dsd_control_ineta_ipv4 *adsc_next;  /* for chaining        */
     struct {
       struct dsd_htree1_avl_entry dsc_sort_1;  /* entry for sorting   */
       struct dsd_wsp_conn *adsc_wsp_conn;  /* connection to a WSP     */
       struct dsd_connect *adsc_connect;    /* for Unix connection     */
       struct dsd_ligw_q_ar_add_ipv4 dsc_ar_ipv4;  /* add ARP and route IPV4  */
     };
   };
};
#endif
#endif

/*+-------------------------------------------------------------------+*/
/*| Internal used classes.                                            |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

static struct pollfd dsrs_poll[ D_POLL_MAX ];  /* for poll()           */
static struct dsd_sithr_poll_1 * dsrs_sithr_poll_1[ D_POLL_MAX ];  /* single thread poll structure */
static int    ims_poll_ele = 0;             /* elements in poll array  */
static struct dsd_listen *adss_listen_chain = NULL;  /* chain for UDS and TCP listen */
static struct dsd_wsp_conn *adss_wsp_conn_chain = NULL;  /* connections to WSPs */

#ifdef D_INCL_HOB_TUN
static int    ims_tun_socket;               /* socket for HOB-TUN      */
#ifdef HL_FREEBSD
static int    ims_route_socket;             /* socket for HOB-TUN ARP and route */
static struct dsd_hobtun_bpf_ctrl *adss_hbc_ch = NULL;  /* chain of structure for bpf - Berkeley Packet Filter */
static int    ims_this_pid;                 /* process id this process */
#endif
#endif

static struct dsd_acccallback dss_acc_cb = {  /* callback routines     */
   &m_cb_nbacc_acceptcallback,
   &m_cb_nbacc_errorcallback
};

/* callback for WSP Unix Socket connections                            */
static struct dsd_tcpcallback dss_tcpcomp_wsp_cb1 = {
// &m_tccb_rdp_connerrcallback;
   NULL,
// &m_tccb_rdp_conncallback;
   NULL,
   &m_tccb_wsp_sendcallback,
   &m_tccb_all_getrecvcallback,
   &m_tccb_wsp_recvcallback,
   &m_tccb_wsp_errorcallback,
   &m_tccb_wsp_cleanup,
#ifdef B130807
   NULL,
#endif
   NULL
};

/* callback for WSP cluster connections                                */
static struct dsd_tcpcallback dss_tcpcomp_cluster_cb1 = {
// &m_tccb_rdp_connerrcallback;
   NULL,
// &m_tccb_rdp_conncallback;
   NULL,
   &m_tccb_cluster_sendcallback,
   &m_tccb_all_getrecvcallback,
   &m_tccb_cluster_recvcallback,
   &m_tccb_cluster_errorcallback,
   &m_tccb_cluster_cleanup,
#ifdef B130807
   NULL,
#endif
   NULL
};

static int    imrs_sha1_key[ SHA_ARRAY_SIZE ];  /* for hash of key     */

#ifdef D_INCL_HOB_TUN
#ifdef CONTROL_INETAS
static struct dsd_htree1_avl_cntl dss_htree1_avl_control_ineta_ipv4;
static struct dsd_control_ineta_ipv4 *adss_ci_ipv4_free_ch = NULL;  /* chain of free structure to control INETAs IPV4 */
#endif
#endif

static const char * achrs_param_01[] = {
   "domain-socket",
   "shared-secret",
   "trace",
   "log"
};

#define PA_01_DOMAIN_SOCKET   0             /* name of domain socket   */
#define PA_01_SHARED_SECRET   1             /* shared secret           */
#define PA_01_TRACE           2
#define PA_01_LOG             3

#define PARAM_01_ALPHA        1
#define PARAM_01_NUM          2

#define PARAM_01_MAX     (sizeof(achrs_param_01) / sizeof(achrs_param_01[0]))

static HL_LONGLONG ilrs_param_01[ PARAM_01_MAX ];  /* parameters passed */

static const unsigned char ucrs_resp_socket_ok[] = {
   (unsigned char) 1,                       /* length of message       */
   (unsigned char) ied_ligwr_resp_socket_ok  /* create socket succeeded */
};

#ifdef D_INCL_HOB_TUN
static const unsigned char ucrs_resp_ar_add_ipv4[] = {
   (unsigned char) 1,                       /* length of message       */
   (unsigned char) ied_ligwr_resp_arproute_add_ipv4  /* add ARP and route IPV4  */
};

static const unsigned char ucrs_resp_ar_del_ipv4[] = {
   (unsigned char) 1,                       /* length of message       */
   (unsigned char) ied_ligwr_resp_arproute_del_ipv4  /* del ARP and route IPV4  */
};

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

static const unsigned char ucrs_cluster_eye_catcher[] = {
   'H', 'O', 'B', ' ', 'W', 'S', 'P', ' ',
   'C', 'L', 'U', 'S', 'T', 'E', 'R', 0
};

static int    ims_true = TRUE;
#ifdef HL_FREEBSD
static int    ims_zero = 0;
#ifdef D_INCL_HOB_TUN
static char   chrs_tun_mask_ipv4[ 4 ] = { 0XFF, 0XFF, 0XFF, 0XFC };  /* TUN-adapter-network-mask IPv4 */
#endif
#endif

static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

/*+-------------------------------------------------------------------+*/
/*| Main control procedure.                                           |*/
/*+-------------------------------------------------------------------+*/

int main( int impargc, char *achrpargv[] ) {
   int        iml1, iml2;                   /* working variables       */
   int        iml_rc;                       /* return code             */
   int        iml_cmp;                      /* compare values          */
   int        iml_unix_socket;              /* Unix socket             */
   int        iml_poll_cur;                 /* current poll array      */
#ifdef D_INCL_HOB_TUN
#ifdef CONTROL_INETAS
   BOOL       bol_rc;                       /* return code             */
#endif
#endif
   BOOL       bol1;                         /* working variable        */
   HL_LONGLONG ill1;                        /* working variable        */
   char       *achl1, *achl2, *achl3;       /* working variables       */
   char       *achl_domain_socket;          /* name of domain socket   */
   struct dsd_unicode_string dsl_uc_in;     /* unicode string input    */
   struct dsd_unicode_string dsl_uc_out;    /* unicode string output   */
   struct sockaddr_un dsl_unix_socket_server;  /* address of domain socket */
   char       chrl_work1[ 4096 ];           /* work area               */

   printf( "nbipgw19-l%05d-I HOB Listen-Gateway for WebSecureProxy V2.1 " __DATE__ "\n", __LINE__ );

   if (   (impargc >= (1 + 1))
       && (!strcmp( achrpargv[1], "?" ))) {
     printf( "HOB nbipgw19 usage:\n" );
     printf( "parameter domain-socket=       name of Unix domain socket\n" );
//   printf( "parameter shared-secret=       shared secret for communication with WSP (HOB WebSecureProxy)\n" );
     printf( "parameter shared-secret=       shared secret for communication with WSP\n" );
     printf( "parameter log                  write messages to log\n" );
     printf( "parameter trace=               display trace messages of certain level\n" );
     return -1;
   }

#ifdef TRACEHL1
   setbuf( stdout, 0 );
#endif
   memset( ilrs_param_01, 0, sizeof(ilrs_param_01) );
// dsl_uc_out.ac_str = chrl_work1;          /* address of string       */
// dsl_uc_out.imc_len_str = sizeof(chrl_work1);  /* length string in elements */
   dsl_uc_out.imc_len_str = -1;             /* length string in elements */
   dsl_uc_out.iec_chs_str = ied_chs_utf_8;  /* Unicode UTF-8           */
   dsl_uc_in.iec_chs_str = D_CHARSET_IP;    /* input character set     */
   iml1 = 1;                                /* first parameter         */
   while (iml1 < impargc) {                 /* loop over input parameters */
     achl1 = achrpargv[ iml1++ ];
     achl2 = achl1 + strlen( achl1 );
     achl3 = achl1;                         /* point to first character */
     while (   (achl3 < achl2)
            && (*achl3 != '=')) {
       achl3++;
     }
     dsl_uc_in.ac_str = achl1;              /* address of string       */
     dsl_uc_in.imc_len_str = achl3 - achl1;  /* length string in elements */
     iml2 = PARAM_01_MAX - 1;
     do {                                   /* loop over all possible keywords */
       dsl_uc_out.ac_str = (void *) achrs_param_01[ iml2 ];  /* address of string */
       bol1 = m_cmpi_ucs_ucs( &iml_cmp, &dsl_uc_in, &dsl_uc_out );
       if ((bol1) && (iml_cmp == 0)) break;
       iml2--;                              /* decrement index         */
     } while (iml2 >= 0);
     bol1 = FALSE;                          /* no type of data set     */
     do {                                   /* pseudo-loop             */
       if (iml2 < 0) {
// to-do 06.05.11 KB error message
         printf( "nbipgw19-l%05d-W parameter \"%s\" not defined - ignored\n",
                 __LINE__, achl1 );
         break;
       }
       if (ilrs_param_01[ iml2 ]) {         /* parameter already set   */
// to-do 06.05.11 KB error message
         printf( "nbipgw19-l%05d-W parameter \"%s\" double - ignored\n",
                 __LINE__, achl1 );
         break;
       }
       if (achl3 >= achl2) {                /* no equals found         */
         if (iml2 <= PARAM_01_NUM) {        /* we need a parameter value */
// to-do 06.05.11 KB error message
           printf( "nbipgw19-l%05d-W parameter \"%s\" = and value missing - ignored\n",
                   __LINE__, achl1 );
           break;
         }
         ilrs_param_01[ iml2 ] = (HL_LONGLONG) TRUE;
         break;
       }
       achl3++;                             /* after equals            */
       if (achl3 >= achl2) {                /* no value follows        */
// to-do 06.05.11 KB error message
         printf( "nbipgw19-l%05d-W parameter \"%s\" after = value missing - ignored\n",
                 __LINE__, achl1 );
         break;
       }
       if (iml2 > PARAM_01_ALPHA) {         /* value must be numeric   */
         ill1 = 0;                          /* clear result            */
         bol1 = FALSE;                      /* no digit found          */
         while (achl3 < achl2) {            /* loop over remaining characters */
           if ((*achl3 >= '0') && (*achl3 <= '9')) {
             bol1 = TRUE;                   /* digit found             */
             ill1 *= 10;
             ill1 += *achl3 - '0';
           } else {                         /* invalid character       */
             printf( "nbipgw19-l%05d-W numeric value invalid character \"%c\" in parameter \"%s\"\n",
                     __LINE__, *achl3, achl1 );
             ill1 = -1;                     /* no valid value          */
             break;
           }
           achl3++;
         }
         if (ill1 < 0) break;               /* invalid value           */
         if (bol1 == FALSE) {               /* no digit found          */
           printf( "nbipgw19-l%05d-W numeric no digit found in parameter \"%s\"\n",
                   __LINE__, achl1 );
           break;
         }
         ilrs_param_01[ iml2 ] = ill1;
         break;
       }
       ilrs_param_01[ iml2 ] = (HL_LONGLONG) achl3;  /* set address of string */
     } while (FALSE);
   }
#ifdef D_UMASK
   umask(0);                                /* allow write access for all */
#endif

   achl1 = (char *) ilrs_param_01[ PA_01_SHARED_SECRET ];  /* shared secret */
   if (achl1 == NULL) {                     /* not configured          */
     achl1 = DEFAULT_SECRET;
   }
   iml1 = strlen( achl1 );
   SHA1_Init( imrs_sha1_key );
   SHA1_Update( imrs_sha1_key, achl1, 0, iml1 );

   achl_domain_socket = (char *) ilrs_param_01[ PA_01_DOMAIN_SOCKET ];  /* name of domain socket */
   if (achl_domain_socket == NULL) {        /* not configured          */
     achl_domain_socket = DEFAULT_UDSNAME;  /* default name of domain socket */
#ifdef TRACEHL1
     m_hl1_printf( "nbipgw19-l%05d-T set achl_domain_socket to \"%s\"",
                   __LINE__, achl_domain_socket );
#endif
   }
   iml_unix_socket = socket( AF_LOCAL, SOCK_STREAM, 0 );
   if (iml_unix_socket < 0) {               /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-E socket( AF_LOCAL ... ) returned %d %d.",
                   __LINE__, iml_unix_socket, D_TCP_ERROR );
     return -1;                             /* abend                   */
   }
   memset( &dsl_unix_socket_server, 0, sizeof(struct sockaddr_un) );
   dsl_unix_socket_server.sun_family = AF_LOCAL;
   iml1 = strlen( achl_domain_socket );     /* get length of name      */
   if (iml1 >= sizeof(dsl_unix_socket_server.sun_path)) {
     iml1 = sizeof(dsl_unix_socket_server.sun_path) - 1;
   }
   memcpy( dsl_unix_socket_server.sun_path, achl_domain_socket, iml1 );
   *(dsl_unix_socket_server.sun_path + iml1) = 0;  /* make zero-terminated */

   iml_rc = unlink( dsl_unix_socket_server.sun_path );
   if (iml_rc < 0) {                        /* error occured           */
     if (errno != ENOENT) {                 /* not No such file or directory */
       m_hl1_printf( "nbipgw19-l%05d-E unlink Unix socket domain name \"%s\" returned %d %d.",
                     __LINE__, dsl_unix_socket_server.sun_path, iml_rc, D_TCP_ERROR );
     }
   }

   iml_rc = bind( iml_unix_socket, (struct sockaddr *) &dsl_unix_socket_server, sizeof(struct sockaddr_un) );
   if (iml_rc < 0) {                        /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-E bind Unix socket domain name \"%s\" returned %d %d.",
                   __LINE__, dsl_unix_socket_server.sun_path, iml_rc, D_TCP_ERROR );
     D_TCP_CLOSE( iml_unix_socket );
     return -1;                             /* abend                   */
   }
   iml_rc = listen( iml_unix_socket, D_BACKLOG );
   if (iml_rc < 0) {                        /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-E listen Unix socket domain name \"%s\" returned %d %d.",
                   __LINE__, dsl_unix_socket_server.sun_path, iml_rc, D_TCP_ERROR );
     D_TCP_CLOSE( iml_unix_socket );
     return -1;                             /* abend                   */
   }

   adss_listen_chain = (struct dsd_listen *) malloc( sizeof(struct dsd_listen) );  /* for UDS listen */
   memset( adss_listen_chain, 0, sizeof(struct dsd_listen) );  /* for UDS listen */
   adss_listen_chain->iec_lit = ied_lit_unix;  /* Unix socket          */
   iml_rc = adss_listen_chain->dsc_acc_lis.mc_startlisten_fix( iml_unix_socket, &dss_acc_cb, adss_listen_chain );
// to-do 19.09.11 KB check return code
   if (iml_rc < 0) {                        /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-E mc_startlisten_fix() Unix socket domain name \"%s\" returned %d.",
                   __LINE__, dsl_unix_socket_server.sun_path, iml_rc );
     D_TCP_CLOSE( iml_unix_socket );
     return -1;                             /* abend                   */
   }
#ifdef D_INCL_HOB_TUN
#ifdef HL_LINUX
   ims_tun_socket                           /* socket for HOB-TUN      */
     = socket( AF_PACKET, SOCK_RAW, htons( ETH_P_ARP ) );
   if (ims_tun_socket < 0) {                /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W TUN socket() Return Code %d Error %d.",
                   __LINE__, ims_tun_socket, errno );
   }
#endif
#ifdef HL_FREEBSD
   ims_this_pid = getpid();                 /* process id this process */
   ims_tun_socket                           /* socket for HOB-TUN      */
     = socket( AF_INET, SOCK_STREAM, 0 );
   if (ims_tun_socket < 0) {                /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W TUN socket() Return Code %d Error %d.",
                   __LINE__, ims_tun_socket, errno );
   }
   ims_route_socket                         /* socket for HOB-TUN ARP and route */
     = socket( PF_ROUTE, SOCK_RAW, 0 );
   if (ims_tun_socket < 0) {                /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W ARP and route socket() Return Code %d Error %d.",
                   __LINE__, ims_tun_socket, errno );
   }
#endif
   /* prepare GARP packet                                              */
   memset( dss_tun_send_garp.chrc_h_macaddr_destination, 0XFF, sizeof(dss_tun_send_garp.chrc_h_macaddr_destination) );  /* mac address of destination */
   memcpy( dss_tun_send_garp.chrc_const_01,  /* constants              */
           ucrs_tun_send_garp,
           sizeof(dss_tun_send_garp.chrc_const_01) );
   memset( dss_tun_send_garp.chrc_pl_macaddr_target, 0XFF, sizeof(dss_tun_send_garp.chrc_pl_macaddr_target) );  /* Target hardware address (THA) */
   /* prepare sockaddr                                                 */
#ifdef HL_LINUX
   memset( &dss_soa_arp, 0, sizeof(struct sockaddr_ll) );
   dss_soa_arp.sll_family = AF_PACKET;
   dss_soa_arp.sll_protocol = htons( ETH_P_ARP );
#endif
#ifdef CONTROL_INETAS
   bol_rc = m_htree1_avl_init( NULL, &dss_htree1_avl_control_ineta_ipv4,
                               &m_cmp_ineta_ipv4 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W m_htree1_avl_init() control INETAs IPV4 returned error",
                   __LINE__ );
   }
#endif
#endif

   ppoll00:                                 /* do poll                 */
   iml1 = INFTIM;                           /* set wait infinite       */
#ifdef XYZ1
   if (adssticha_anchor) {                  /* timer set               */
     ill_time_cur = m_get_epoch_ms();       /* get current time        */
     iml1 = adssticha_anchor->ilcendtime - ill_time_cur;  /* intervall to first entry */
     if (iml1 <= 0) {                       /* timer has expired       */
       adsltiele_w1 = adssticha_anchor;     /* get timer element       */
       adssticha_anchor = adsltiele_w1->adsctiele_next;  /* remove from chain */
       if (adssticha_anchor) {              /* still element in chain  */
         adssticha_anchor->adsctiele_prev = NULL;  /* clear previous element */
       }
       adsltiele_w1->boc_timer_set = FALSE;  /* timer is no more set   */
       adsltiele_w1->amc_expired( adsltiele_w1, NULL, NULL, NULL );  /* call routine for timer elapsed */
       goto ppoll00;                        /* start from beginning    */
     }
   }
#endif
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T before poll( ... , ims_poll_ele=%d , %d )",
                 __LINE__, ims_poll_ele, iml1 );
#endif
   iml_rc = poll( dsrs_poll, ims_poll_ele, iml1 );
   if (iml_rc < 0) {                        /* was error               */
     m_hl1_printf( "nbipgw19-l%05d-W poll() returned=%d errno=%d.",
                   __LINE__, iml_rc, errno );
   }
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T poll() returned %d.",
                 __LINE__, iml_rc );
#endif
   iml_poll_cur = 0;                        /* clear current poll array */
   do {
     if (dsrs_poll[ iml_poll_cur ].revents) {  /* event to process     */
#ifdef TRACEHL1
       m_hl1_printf( "nbipgw19-l%05d-T after poll() %d event %08X dsrs_sithr_poll_1[ iml_poll_cur ]=%p.",
                     __LINE__, iml_poll_cur, dsrs_poll[ iml_poll_cur ].revents, dsrs_sithr_poll_1[ iml_poll_cur ] );
#endif
       dsrs_sithr_poll_1[ iml_poll_cur ]->amc_p_compl_poll( dsrs_sithr_poll_1[ iml_poll_cur ] );
       dsrs_poll[ iml_poll_cur ].revents = 0;  /* event has been processed */
     }
     iml_poll_cur++;                        /* increment current poll array */
   } while (iml_poll_cur < ims_poll_ele);
   goto ppoll00;                            /* do poll                 */
} /* end main()                                                        */

/** close cluster connection                                           */
static void m_cluster_listen_close( struct dsd_listen *adsp_listen ) {
   int        iml_rc;                       /* return code             */
   struct dsd_listen *adsl_listen_w1;       /* for TCP listen          */

#define ADSL_LIGW_CLI_EXT_G ((struct dsd_ligw_clli_ext *) (adsp_listen + 1))

#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_cluster_listen_close( %p ) called - ADSL_LIGW_CLI_EXT_G->imc_usage=%d.",
                 __LINE__, adsp_listen, ADSL_LIGW_CLI_EXT_G->imc_usage );
#endif
#ifdef TRACEHL_CLLI
   adsl_listen_w1 = adss_listen_chain;      /* chain for UDS and TCP listen */
   while (adsl_listen_w1) {
     int imh1 = 0;
     if (adsl_listen_w1->iec_lit == ied_lit_cluster) { /* cluster      */
       imh1 = ADSL_LIGW_CLI_EXT_G->imc_usage;
     }
     m_hl1_printf( "nbipgw19-l%05d-T m_cluster_listen_close() adsl_listen_w1=%p ->iec_lit=%d ADSL_LIGW_CLI_EXT_G->imc_usage=%d.",
                   __LINE__, adsl_listen_w1, adsl_listen_w1->iec_lit, imh1 );
     adsl_listen_w1 = adsl_listen_w1->adsc_next;
   }
#endif
   ADSL_LIGW_CLI_EXT_G->imc_usage--;        /* usage count             */
   if (ADSL_LIGW_CLI_EXT_G->imc_usage > 0) return;  /* still connections */
   iml_rc = adsp_listen->dsc_acc_lis.mc_stoplistener_fix();
   if (iml_rc != 0) {                       /* returned error          */
     m_hl1_printf( "nbipgw19-%05d-W m_cluster_listen_close() mc_stoplistener_fix() listen %p returned error %d.",
                   __LINE__, adsp_listen, iml_rc );
   }
   if (adsp_listen = adss_listen_chain) {   /* at beginning of chain for UDS and TCP listen */
     adss_listen_chain = adsp_listen->adsc_next;  /* remove from chain */
   } else {                                 /* middle in chain         */
     adsl_listen_w1 = adss_listen_chain;    /* chain for UDS and TCP listen */
     while (   (adsl_listen_w1->adsc_next)
            && (adsl_listen_w1->adsc_next != adsp_listen)) {
       adsl_listen_w1 = adsl_listen_w1->adsc_next;
     }
     if (adsl_listen_w1->adsc_next == NULL) {
       m_hl1_printf( "nbipgw19-%05d-W m_cluster_listen_close() listen %p not found in chain",
                     __LINE__, adsp_listen );
     } else {
       adsl_listen_w1->adsc_next = adsp_listen->adsc_next;  /* remove from chain */
     }
   }
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_cluster_listen_close() free %p.",
                 __LINE__, adsp_listen );
#endif
   free( adsp_listen );                     /* free storage of listen  */
   return;                                  /* all done                */

#undef ADSL_LIGW_CLI_EXT_G

} /* end m_cluster_listen_close()                                      */

extern "C" BOOL m_poll_arr_add( struct dsd_sithr_poll_1 *adsp_sithr_poll_1 ) {
   if (ims_poll_ele >= D_POLL_MAX) return FALSE;
   dsrs_sithr_poll_1[ ims_poll_ele ] = adsp_sithr_poll_1;  /* single thread poll structure */
   memset( &dsrs_poll[ ims_poll_ele ], 0, sizeof(dsrs_poll[0]) );
#ifdef B100803
   dsrs_poll[ ims_poll_ele ].fd = adsp_sithr_poll_1->imc_fd;
#endif
   adsp_sithr_poll_1->adsc_pollfd = &dsrs_poll[ ims_poll_ele ];  /* address of poll structure */
   ims_poll_ele++;                          /* elements in poll array  */
   return TRUE;                             /* all done                */
} /* end m_poll_arr_add()                                              */

extern "C" BOOL m_poll_arr_del( struct dsd_sithr_poll_1 *adsp_sithr_poll_1 ) {
   int        iml1;                         /* working variable        */

   iml1 = 0;                                /* start with first poll entry */
   while (iml1 < ims_poll_ele) {            /* loop over all existing poll entries */
     if (adsp_sithr_poll_1 == dsrs_sithr_poll_1[ iml1 ]) break;
     iml1++;                                /* increment index poll entry */
   }
   if (iml1 >= ims_poll_ele) return FALSE;  /* poll entry not found    */
   ims_poll_ele--;                          /* elements in poll array  */
   while (iml1 < ims_poll_ele) {            /* loop over all remaining poll entries */
     memcpy( &dsrs_poll[ iml1 ], &dsrs_poll[ iml1 + 1 ], sizeof(dsrs_poll[0]) );
     dsrs_sithr_poll_1[ iml1 ] = dsrs_sithr_poll_1[ iml1 + 1 ];
     dsrs_sithr_poll_1[ iml1 ]->adsc_pollfd = &dsrs_poll[ iml1 ];  /* address of poll structure */
     iml1++;                                /* increment index poll entry */
   }
   return TRUE;                             /* all done                */
} /* end m_poll_arr_del()                                              */

/** accept callback routine                                            */
static void m_cb_nbacc_acceptcallback( class dsd_nblock_acc * adsp_na, void * vpp_userfld, int imp_socket, struct sockaddr *adsp_soa, int imp_len_soa ) {
   int        iml_rc;                       /* return code             */
   char       *achl1;                       /* working-variable        */
   struct dsd_listen *adsl_listen_w1;       /* for TCP listen          */
   struct dsd_wsp_conn *adsl_wsp_conn_w1;   /* connection to a WSP     */
   struct dsd_cluster_conn *adsl_cluster_conn;  /* connection to a cluster member */
   char       chrl_client_ineta[ LEN_DISP_INETA ];

#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T called m_cb_nbacc_acceptcallback()",
                 __LINE__ );
#endif
   adsl_listen_w1 = (struct dsd_listen *) vpp_userfld;
   if (adsl_listen_w1->iec_lit == ied_lit_unix) {  /* Unix socket      */
     goto p_local_00;                       /* connect from Unix domain socket */
   }
   iml_rc = getnameinfo( adsp_soa, imp_len_soa,
                         chrl_client_ineta, sizeof(chrl_client_ineta),
                         0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
     m_hl1_printf( "nbipgw19-%05d-W getnameinfo Error %d %d.",
                   __LINE__, iml_rc, D_TCP_ERROR );
     strcpy( chrl_client_ineta, "???" );
   }
   m_hl1_printf( "nbipgw19-%05d-I connect-in WSP cluster-member INETA %s.",
                 __LINE__, chrl_client_ineta );
   adsl_cluster_conn = (struct dsd_cluster_conn *) malloc( sizeof(struct dsd_cluster_conn) );  /* connection to a cluster member */
   memset( adsl_cluster_conn, 0, sizeof(struct dsd_cluster_conn) );  /* clear connection to a cluster member */
   strcpy( adsl_cluster_conn->chrc_ineta, chrl_client_ineta );  /* internet-address char */
   iml_rc = adsl_cluster_conn->dsc_connect.dsc_tcpco1.m_startco_fb(
                imp_socket,
                &dss_tcpcomp_cluster_cb1,
                adsl_cluster_conn );
   if (iml_rc) {                            /* error occured           */
     m_hl1_printf( "nbipgw19-%05d-W cluster INETA %s m_startco_fb() failed",
                   __LINE__, chrl_client_ineta, iml_rc );
     D_TCP_CLOSE( imp_socket );
     free( adsl_cluster_conn );             /* free memory             */
     return;                                /* all done                */
   }
   iml_rc = adsl_cluster_conn->dsc_connect.dsc_tcpco1.m_recv();  /* receive data */
   if (iml_rc) {                            /* error occured           */
     m_hl1_printf( "nbipgw19-%05d-W cluster INETA %s m_recv() failed",
                   __LINE__, chrl_client_ineta, iml_rc );
     D_TCP_CLOSE( imp_socket );
     return;                                /* all done                */
   }
   return;                                  /* all done                */

   p_local_00:                              /* connect from Unix domain socket */
   adsl_wsp_conn_w1 = (struct dsd_wsp_conn *) malloc( sizeof(struct dsd_wsp_conn) );  /* connection to a WSP */
   memset( adsl_wsp_conn_w1, 0, sizeof(struct dsd_wsp_conn) );  /* connection to a WSP */
   adsl_wsp_conn_w1->dsc_connect.iec_cot = ied_cot_wsp;  /* connection to a WSP */
   iml_rc = adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_startco_unix_socket_fix(
                imp_socket,
                &dss_tcpcomp_wsp_cb1,
                adsl_wsp_conn_w1 );
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_cb_nbacc_acceptcallback() m_startco_unix_socket_fix( ... , %p ) at %p returned %d.",
                 __LINE__, adsl_wsp_conn_w1, &adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1, iml_rc );
#endif
   if (iml_rc) {                            /* error occured           */
     m_hl1_printf( "nbipgw19-%05d-W Unix socket m_startco_unix_socket_fix() failed %d.",
                   __LINE__, iml_rc );
     D_TCP_CLOSE( imp_socket );
     free( adsl_wsp_conn_w1 );              /* free memory again       */
     return;                                /* all done                */
   }
   iml_rc = adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_recv();  /* receive data */
   if (iml_rc) {                            /* error occured           */
     m_hl1_printf( "nbipgw19-%05d-W Unix socket m_recv() failed %d.",
                   __LINE__, iml_rc );
     D_TCP_CLOSE( imp_socket );
     free( adsl_wsp_conn_w1 );              /* free memory again       */
     return;                                /* all done                */
   }
   adsl_wsp_conn_w1->adsc_next = adss_wsp_conn_chain;  /* get connections to WSPs */
   adss_wsp_conn_chain = adsl_wsp_conn_w1;  /* new chain connections to WSPs */
} /* end m_cb_nbacc_acceptcallback()                                   */

/** error callback routine                                             */
static void m_cb_nbacc_errorcallback( class dsd_nblock_acc *, void *, char *, int, int ) // Error callback function.
{
// do-to 27.01.08 KB
   m_hl1_printf( "nbipgw19-l%05d-W accept error",
                 __LINE__ );
   return;
} /* end m_cb_nbacc_errorcallback()                                    */

/** get receive buffer callback function                               */
static int m_tccb_all_getrecvcallback( class dsd_tcpcomp *adsp_tcpcomp,
                                       void * vpp_userfld,
                                       void **avpp_handle,
                                       char **aachp_data,
                                       int **aaimp_datalen ) {
   struct dsd_receive_1 *adsl_receive_1;

   adsl_receive_1 = (struct dsd_receive_1 *) m_proc_alloc();
   memset( adsl_receive_1, 0, sizeof(struct dsd_receive_1) );
   *avpp_handle = adsl_receive_1;
   *aachp_data = (char *) (adsl_receive_1 + 1);
   *aaimp_datalen = &adsl_receive_1->imc_rc;
   return D_BUFFER_LEN - sizeof(struct dsd_receive_1);
} /* end m_tccb_all_getrecvcallback()                                  */

#ifdef XYZ1
   void (*am_connerrcallback)( class dsd_tcpcomp *, void *, struct sockaddr *adsp_soa, socklen_t imp_len_soa, int imp_current_index, int imp_total_index, int imp_errno );  /* connect failed function */
   void (*am_conncallback)( class dsd_tcpcomp *, void *, struct sockaddr *adsp_soa, socklen_t imp_len_soa );  /* connect callback function */
#endif

/** TCPCOMP WSP send callback function                                 */
static void m_tccb_wsp_sendcallback( class dsd_tcpcomp *adsp_tcpcomp, void * vpp_userfld ) {
   struct dsd_connect *adsl_conn_1;         /* connection              */

   m_hl1_printf( "nbipgw19-%05d-T m_tccb_wsp_sendcallback() called",
                 __LINE__ );
#ifdef XYZ1
   adsl_conn_1 = (struct dsd_connect *) vpp_userfld;  /* connection    */
   adsl_conn_1->dsc_tcpco1.m_send_gather( adsl_conn_1->adsc_gai1_send, &adsl_conn_1->adsc_gai1_send );  /* send to client */
   if (adsl_conn_1->adsc_gai1_send) {       /* more data to be sent    */
     adsl_conn_1->dsc_tcpco1.m_sendnotify();  /* notify main program when possible to send data */
     return;
   }
   adsl_conn_1->dsc_tcpco1.m_recv();        /* start receiving         */
#endif
} /* end m_tccb_wsp_sendcallback()                                     */

/** TCPCOMP WSP receive callback function                              */
static BOOL m_tccb_wsp_recvcallback( class dsd_tcpcomp *adsp_tcpcomp, void * vpp_userfld, void * vpp_handle ) {
#ifdef D_INCL_HOB_TUN
   BOOL       bol_rc;                       /* return code             */
#endif
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3;             /* working variables       */
   int        iml_rc;                       /* return code             */
   int        iml_socket;                   /* socket to be created    */
#ifdef D_INCL_HOB_TUN
   int        iml_error;                    /* error retrieved         */
   int        iml_index_ineta_ipv4;         /* index INETA IPV4        */
   int        iml_index_ineta_ipv6;         /* index INETA IPV6        */
#ifdef HL_FREEBSD
   int        iml_bpf_fd;                   /* file-descriptor for bpf - Berkeley Packet Filter */
#endif
   UNSIG_MED  uml_ineta_w1;                 /* working variable INETA IPV4 */
#endif
   enum ied_decode_wsp_recv_1 iel_dwr1;     /* decode received from WSP */
   char       *achl1, *achl2, *achl3, *achl4, *achl5;  /* working variables */
   struct dsd_wsp_conn *adsl_wsp_conn_w1;   /* connection to a WSP     */
   struct dsd_wsp_conn *adsl_wsp_conn_w2;   /* connection to a WSP     */
   struct dsd_receive_1 *adsl_receive_in1;  /* receive buffer          */
   struct dsd_receive_1 *adsl_rec1_w1;      /* area for receive        */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* gather input            */
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* gather input            */
   struct dsd_gather_i_1 dsrl_gai1_out1[ 2 ];  /* for send gather      */
   struct dsd_listen *adsl_listen_w1;       /* for TCP listen          */
   int        imrl_sha1[ SHA_ARRAY_SIZE ];  /* for hash                */
   char       chrl_nonce[ D_LIGW_RANDOM_L ];  /* nonce received        */
   char       chrl_next_xor[ D_LIGW_RANDOM_L ];  /* for next SHA-1     */
   char       chrl_sha1_out[ D_LIGW_RANDOM_L ];  /* output of SHA-1    */
   struct sockaddr_storage dsl_soa;         /* for bind()              */
#ifdef D_INCL_HOB_TUN
#ifdef HL_LINUX
   union {
     struct ifreq dsl_ifreq;                /* interface request       */
#ifdef HL_LINUX
     struct arpreq dsl_arpreq;              /* struct for arp requests */
     struct rtentry dsl_routereq;           /* struct for route request */
#endif
   };
#endif
#ifdef HL_FREEBSD
   struct ifreq dsl_ifreq;                  /* interface request       */
   struct {
     struct rt_msghdr dsc_m_rtm;
     char     byrc_m_space[512];
   } dsl_m_rtmsg;
   struct in_aliasreq dsl_alreq;            /* interface request       */
#endif
#ifdef CONTROL_INETAS
   struct dsd_control_ineta_ipv4 *adsl_ci_ipv4_w1;  /* structure to control INETAs IPV4 */
   struct dsd_control_ineta_ipv4 dsl_ci_ipv4_l;  /* structure to control INETAs IPV4 */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
#endif
#endif
   struct msghdr dsl_msg;                   /* message structure       */
   struct iovec dsrl_iov[ 2 ];              /* vector containing send data */
#ifdef MSGHDR_CONTROL_AVAILABLE
   union {
     struct cmsghdr dsc_msg;
     char chrc_control[ CMSG_SPACE(sizeof(int)) ];
   } dsl_control_un;
   struct cmsghdr *adsl_cmd;
#endif
   union {
     char     chrl_input[ 512 ];            /* input received decoded  */
     char     chrl_output[ 512 ];           /* output to send to WSP   */
   };
#ifdef TRACEHL1
   char       byrl_trace_ineta[ 128 ];
#endif

/* we need special alignment for int                                   */
#define ACHL_INPUT_STA (chrl_input + sizeof(int) - 1)
#define ACHL_INPUT_END (chrl_input + sizeof(chrl_input))

#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_recvcallback( adsp_tcpcomp=%p , vpp_userfld=%p , vpp_handle=%p ) called",
                 __LINE__, adsp_tcpcomp, vpp_userfld, vpp_handle );
#endif
   adsl_wsp_conn_w1 = (struct dsd_wsp_conn *) vpp_userfld;  /* connection to a WSP */
   adsl_receive_in1 = (struct dsd_receive_1 *) vpp_handle;
   if (ilrs_param_01[ PA_01_TRACE ] >= 4) {
     m_hl1_printf( "nbipgw19-l%05d-W m_tccb_wsp_recvcallback() called wsp-conn=%p imc_rc=%d.",
                   __LINE__, adsl_wsp_conn_w1, adsl_receive_in1->imc_rc );
   }
   if (adsl_receive_in1->imc_rc <= 0) {     /* no data received        */
     m_hl1_printf( "nbipgw19-l%05d-W m_tccb_wsp_recvcallback() called imc_rc=%d - no data",
                   __LINE__, adsl_receive_in1->imc_rc );
     m_proc_free( adsl_receive_in1 );       /* free storage            */
     return TRUE;
   }
   adsl_receive_in1->dsc_gai1_r.achc_ginp_cur = (char *) (adsl_receive_in1 + 1);
   adsl_receive_in1->dsc_gai1_r.achc_ginp_end = (char *) (adsl_receive_in1 + 1) + adsl_receive_in1->imc_rc;
   if (adsl_wsp_conn_w1->dsc_connect.adsc_rec1_ch == NULL) {  /* chain received data */
     adsl_wsp_conn_w1->dsc_connect.adsc_rec1_ch = adsl_receive_in1;  /* is first in chain now */
   } else {
     adsl_rec1_w1 = adsl_wsp_conn_w1->dsc_connect.adsc_rec1_ch;  /* get chain received data */
     while (adsl_rec1_w1->adsc_next) adsl_rec1_w1 = adsl_rec1_w1->adsc_next;
     adsl_rec1_w1->adsc_next = adsl_receive_in1;  /* append to chain   */
     adsl_rec1_w1->dsc_gai1_r.adsc_next = &adsl_receive_in1->dsc_gai1_r;  /* chain of gather */
   }

   p_recv_sc_00:                            /* we have input           */
   adsl_gai1_w1 = &adsl_wsp_conn_w1->dsc_connect.adsc_rec1_ch->dsc_gai1_r;  /* get chain of gather */
   achl1 = chrs_requestheader_query;        /* start to compare        */
   achl2 = chrs_requestheader_query + sizeof(chrs_requestheader_query);  /* end to compare */
   iel_dwr1 = ied_dwr1_header;              /* header received         */

   p_recv_sc_04:                            /* scan received input     */
   achl3 = adsl_gai1_w1->achc_ginp_cur;     /* get start of input      */

   p_recv_sc_20:                            /* continue scan received input */
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T p_recv_sc_20: iel_dwr1=%d achl1=%p achl2=%p achl3=%p.",
                 __LINE__, iel_dwr1, achl1, achl2, achl3 );
#endif
   iml1 = adsl_gai1_w1->achc_ginp_end - achl3;  /* length of input     */
   if (iml1 <= 0) goto p_recv_sc_60;        /* end of this gather      */
   switch (iel_dwr1) {                      /* decode received from WSP */
     case ied_dwr1_header:                  /* header received         */
       iml2 = achl2 - achl1;                /* length remaining output */
       if (iml2 > iml1) iml2 = iml1;        /* maximum output          */
       if (memcmp( achl1, achl3, iml2 )) {  /* does not compare        */
         m_wsp_send_msg( adsl_wsp_conn_w1,
                         "nbipgw19-l%05d-W input eye-catcher does not compare pos=%d.",
                         __LINE__,
                         achl1 - chrs_requestheader_query );
         adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
         return FALSE;                      /* do not receive more     */
       }
       achl1 += iml2;                       /* increment to compare    */
       achl3 += iml2;                       /* increment input         */
       if (achl1 < achl2) break;            /* we need more input      */
       achl1 = chrl_nonce;                  /* start nonce received    */
       achl2 = chrl_nonce + sizeof(chrl_nonce);  /* end nonce received */
       iel_dwr1 = ied_dwr1_nonce;           /* nonce received          */
       break;
     case ied_dwr1_nonce:                   /* nonce received          */
       iml2 = achl2 - achl1;                /* length remaining output */
       if (iml2 > iml1) iml2 = iml1;        /* maximum output          */
       memcpy( achl1, achl3, iml2 );        /* copy input              */
       achl1 += iml2;                       /* increment to compare    */
       achl3 += iml2;                       /* increment input         */
       if (achl1 < achl2) break;            /* we need more input      */
       iml2 = D_MAX_LEN_NHASN;              /* maximum length NHASN    */
       iml3 = 0;                            /* clear akkumulator       */
       iel_dwr1 = ied_dwr1_len_nhasn;       /* length NHASN            */
       break;
     case ied_dwr1_len_nhasn:               /* length NHASN            */
       iml3 <<= 7;                          /* shift old akkumulator   */
       iml3 |= *achl3 & 0X7F;               /* apply new bits to akkumulator */
       iml2--;                              /* decrement length NHASN  */
       achl3++;                             /* this character consumed */
       if (*((unsigned char *) achl3 - 1) & 0X80) {  /* more bit still set */
         if (iml2 <= 0) {                   /* too many digits         */
           m_wsp_send_msg( adsl_wsp_conn_w1,
                           "nbipgw19-l%05d-W input length NHASN contains too many digits",
                           __LINE__ );
           adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
           return FALSE;                    /* do not receive more     */
         }
         break;                             /* we need more digits     */
       }
       if (iml3 <= 0) {
         m_wsp_send_msg( adsl_wsp_conn_w1,
                         "nbipgw19-l%05d-W input content length zero invalid",
                         __LINE__ );
         adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
         return FALSE;                      /* do not receive more     */
       }
       if (iml3 > (ACHL_INPUT_END - ACHL_INPUT_STA)) {
         m_wsp_send_msg( adsl_wsp_conn_w1,
                         "nbipgw19-l%05d-W input content too long %d.",
                         __LINE__,
                         iml3 );
         adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
         return FALSE;                      /* do not receive more     */
       }
       iml1 = adsl_gai1_w1->achc_ginp_end - achl3;  /* length of this input */
       adsl_gai1_w2 = adsl_gai1_w1->adsc_next;  /* get chained gather  */
       while (adsl_gai1_w2) {               /* loop over all following gather */
         iml1 += adsl_gai1_w2->achc_ginp_end - adsl_gai1_w2->achc_ginp_cur;
         adsl_gai1_w2 = adsl_gai1_w2->adsc_next;  /* get next in chain */
       }
       if (iml1 < iml3) return TRUE;        /* not complete packet     */
       achl1 = ACHL_INPUT_STA;              /* start of input          */
       achl2 = achl1 + iml3;                /* end of input            */
       achl4 = chrl_nonce;                  /* decode with nonce       */
       iml2 = 0;                            /* start of block          */
       iel_dwr1 = ied_dwr1_content;         /* content                 */
       break;
     case ied_dwr1_content:                 /* content                 */
       if (iml2 <= 0) {                     /* need new encryption     */
         memcpy( imrl_sha1, imrs_sha1_key, sizeof(imrl_sha1) );
         SHA1_Update( imrl_sha1, achl4, 0, D_LIGW_RANDOM_L );
         SHA1_Final( imrl_sha1, chrl_sha1_out, 0 );
         iml2 = D_LIGW_RANDOM_L;
         achl4 = achl5 = chrl_next_xor;     /* address of next XOR value */
       }
       iml3 = achl2 - achl1;                /* remaining to be processed */
       if (iml3 > iml2) iml3 = iml2;        /* remaining in this block */
       if (iml3 > iml1) iml3 = iml1;        /* only as long as input   */
       do {                                 /* loop over input         */
         *achl5++ = *achl3;                 /* get character for encryption */
         *achl1++ = *achl3++ ^ chrl_sha1_out[ D_LIGW_RANDOM_L - iml2 ];
         iml2--;                            /* decrement position nonce */
         iml3--;                            /* decrement index         */
       } while (iml3 > 0);
       if (achl1 < achl2) break;            /* not yet end of input    */
       goto p_record_00;                    /* record has been received */
   }
   goto p_recv_sc_20;                       /* continue scan received input */

   p_recv_sc_60:                            /* end of this gather      */
   adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain       */
   if (adsl_gai1_w1) goto p_recv_sc_04;     /* scan received input     */
   return TRUE;                             /* continue receiving      */

   p_record_00:                             /* record has been received */
#ifdef TRACEHL1
   m_console_out( ACHL_INPUT_STA, achl1 - ACHL_INPUT_STA );
#endif
   adsl_gai1_w1->achc_ginp_cur = achl3;     /* processed till here     */
   if (adsl_gai1_w1->achc_ginp_cur >= adsl_gai1_w1->achc_ginp_end) {  /* this gather processed */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   while (adsl_wsp_conn_w1->dsc_connect.adsc_rec1_ch) {  /* loop over chain received data */
     adsl_rec1_w1 = adsl_wsp_conn_w1->dsc_connect.adsc_rec1_ch;  /* get chain received data */
     if (adsl_gai1_w1 == &adsl_rec1_w1->dsc_gai1_r) break;  /* current one reached */
     adsl_wsp_conn_w1->dsc_connect.adsc_rec1_ch = adsl_rec1_w1->adsc_next;  /* remove from chain */
     m_proc_free( adsl_rec1_w1 );           /* free receive block      */
   }
   /* time is passed big endian                                        */
   iml1 = (*((unsigned char *) chrl_nonce + 16 + 0) << 24)
            | (*((unsigned char *) chrl_nonce + 16 + 1) << 16)
            | (*((unsigned char *) chrl_nonce + 16 + 2) << 8)
            | *((unsigned char *) chrl_nonce + 16 + 3);
   iml1 -= (int) time( NULL );
// to-do 13.09.11 KB compare time, abend if wrong
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T time difference %d received 0X%08X current 0X%08X.",
                 __LINE__, iml1, *((int *) (chrl_nonce + 16)), time( NULL ) );
#endif
#ifdef B140213
   if (   (iml1 < 0)
       || (iml1 > D_LIGW_MAX_TIME_RANDOM)) {  /* maximum time in seconds that the listen-gateway decrypts the message after sent */
     m_hl1_printf( "nbipgw19-l%05d-W from connected WSP received encrypted time %d out of range",
                   __LINE__, iml1 );
     adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
     return FALSE;                          /* do not receive more     */
   }
#endif
   if (   (iml1 > 0)
       || (iml1 < (0 - D_LIGW_MAX_TIME_RANDOM))) {  /* maximum time in seconds that the listen-gateway decrypts the message after sent */
     m_hl1_printf( "nbipgw19-l%05d-W from connected WSP received encrypted time %d out of range",
                   __LINE__, iml1 );
     adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
     return FALSE;                          /* do not receive more     */
   }
   iml1 = achl1 - ACHL_INPUT_STA;           /* length of input         */
   if (adsl_wsp_conn_w1->boc_first_message) {  /* first message has arrived */
     goto p_record_20;                      /* process record          */
   }
   if (iml1 != (1 + 3 * sizeof(int))) {     /* not correct message size */
     m_hl1_printf( "nbipgw19-l%05d-W from connected WSP length first record %d invalid",
                   __LINE__, iml1 );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W length first record %d invalid",
                     __LINE__,
                     iml1 );
     adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
     return FALSE;                          /* do not receive more     */
   }
   if (*((int *) (ACHL_INPUT_STA + 1)) != D_LI_GW_TOKEN) {
     m_hl1_printf( "nbipgw19-l%05d-W from connected WSP first record token 0X%08X invalid - maybe shared-secret invalid",
                   __LINE__, *((int *) (ACHL_INPUT_STA + 1)) );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W first record token 0X%08X invalid - maybe shared-secret invalid",
                     __LINE__,
                     *((int *) (ACHL_INPUT_STA + 1)) );
     adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
     return FALSE;                          /* do not receive more     */
   }
   if (*((unsigned char *) ACHL_INPUT_STA) != ied_ligwq_start) {  /* start of WSP */
     m_hl1_printf( "nbipgw19-l%05d-W from connected WSP first record message type 0X%02X invalid - maybe shared-secret invalid",
                   __LINE__, *((unsigned char *) ACHL_INPUT_STA) );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W first record message type 0X%02X invalid - maybe shared-secret invalid",
                     __LINE__,
                     *((unsigned char *) ACHL_INPUT_STA) );
     adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
     return FALSE;                          /* do not receive more     */
   }
   if (*((int *) (ACHL_INPUT_STA + 1 + sizeof(int))) != 0) {  /* check version number */
     m_hl1_printf( "nbipgw19-l%05d-W from connected WSP version %d not supported",
                   __LINE__, *((int *) (ACHL_INPUT_STA + 1 + sizeof(int))) );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W version %d not supported",
                     __LINE__,
                     *((int *) (ACHL_INPUT_STA + 1 + sizeof(int))) );
     adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
     return FALSE;                          /* do not receive more     */
   }
   adsl_wsp_conn_w1->imc_pid                /* process id              */
     = *((int *) (ACHL_INPUT_STA + 1 + 2 * sizeof(int)));
   adsl_wsp_conn_w1->boc_first_message = TRUE;  /* first message has arrived */
   m_hl1_printf( "nbipgw19-l%05d-I connected WSP process id (PID) %d.",
                 __LINE__, *((int *) (ACHL_INPUT_STA + 1 + 2 * sizeof(int))) );
   m_wsp_send_msg( adsl_wsp_conn_w1,
                   "nbipgw19-l%05d-I connected to HOB Listen-Gateway for WebSecureProxy V2.1 " __DATE__ " Protocol Version 0.",
                   __LINE__ );
   /* we send a list of the PIDs of other connected WSPs               */
   iml1 = 0;                                /* clear number of WSPs    */
   achl1 = achl2 = chrl_output + sizeof(int);  /* start or output      */
   adsl_wsp_conn_w2 = adss_wsp_conn_chain;  /* get connections to WSPs */
   do {                                     /* loop over chain of WSPs */
     if (   (adsl_wsp_conn_w2 != adsl_wsp_conn_w1)  /* not this WSP    */
         && (adsl_wsp_conn_w2->boc_first_message)) {  /* first message has arrived */
       if (iml1 < D_LIGW_MAX_WSP) {         /* maximum number of WSPs connected */
         *((int *) achl1) = adsl_wsp_conn_w2->imc_pid;  /* process id  */
         achl1 += sizeof(int);              /* increment pointer output */
       }
       iml1++;                              /* count the WSP           */
     }
     adsl_wsp_conn_w2 = adsl_wsp_conn_w2->adsc_next;  /* get next in chain */
   } while (adsl_wsp_conn_w2);
   if (iml1 == 0) goto p_record_80;         /* no need to send other WSPs */
   if (iml1 > D_LIGW_MAX_WSP) {             /* maximum number of WSPs connected */
// to-do 11.09.11 KB error
     m_hl1_printf( "nbipgw19-l%05d-W maximum number of WSPs connected too high",
                   __LINE__, iml1 );
     goto p_record_80;                      /* the record has been processed */
   }
   *(--achl2) = (unsigned char) ied_ligwr_wsps;  /* other WSPs         */
   iml1 = achl1 - achl2;                    /* sizeof record           */
   iml2 = 0;                                /* clear more bit          */
   do {                                     /* loop output NHASN       */
     *(--achl2) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* shift bits              */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
   dsrl_gai1_out1[ 0 ].adsc_next = &dsrl_gai1_out1[ 1 ];
   dsrl_gai1_out1[ 0 ].achc_ginp_cur = chrs_requestheader_response;
   dsrl_gai1_out1[ 0 ].achc_ginp_end = chrs_requestheader_response + sizeof(chrs_requestheader_response);
   dsrl_gai1_out1[ 1 ].adsc_next = NULL;
   dsrl_gai1_out1[ 1 ].achc_ginp_cur = achl2;  /* start of content     */
   dsrl_gai1_out1[ 1 ].achc_ginp_end = achl1;  /* end of content       */
   iml_rc = adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_send_gather( dsrl_gai1_out1, NULL );
   if (ilrs_param_01[ PA_01_TRACE ] >= 4) {
     m_hl1_printf( "nbipgw19-l%05d-W sent data to wsp-conn=%p imc_rc=%d.",
                   __LINE__, adsl_wsp_conn_w1, iml_rc );
   }
   goto p_record_80;                        /* the record has been processed */

   p_record_20:                             /* process record          */
   switch ((enum ied_li_gw_query) *((unsigned char *) ACHL_INPUT_STA)) {
     case ied_ligwq_socket:                 /* create socket           */
       goto p_rec_crso_00;                  /* received create socket  */
     case ied_ligwq_cluster:                /* cluster message         */
       goto p_rec_cluster_00;               /* received cluster        */
#ifdef D_INCL_HOB_TUN
     case ied_ligwq_open_tun:               /* open TUN adapter        */
       goto p_rec_open_tun;                 /* received query open TUN */
     case ied_ligwq_arproute_add_ipv4:      /* add ARP and route IPV4  */
       goto p_rec_ar_add_ipv4;              /* received add AR IPV4    */
     case ied_ligwq_arproute_del_ipv4:      /* del ARP and route IPV4  */
       goto p_rec_ar_del_ipv4;              /* received del AR IPV4    */
#endif
   }
   m_hl1_printf( "nbipgw19-l%05d-W from connected WSP PID %d received ied_li_gw_query %d invalid",
                 __LINE__, adsl_wsp_conn_w1->imc_pid, *((unsigned char *) ACHL_INPUT_STA) );
   m_wsp_send_msg( adsl_wsp_conn_w1,
                   "nbipgw19-l%05d-W from connected WSP received ied_li_gw_query %d invalid",
                   __LINE__, *((unsigned char *) ACHL_INPUT_STA) );
   goto p_record_80;                        /* the record has been processed */

   p_rec_crso_00:                           /* received create socket  */

#define ADSL_CREATE_SOCKET_LIGW_G ((struct dsd_create_socket_ligw *) (ACHL_INPUT_STA + 1))
#define AIML_RESP_SOCKET_FAILED ((int *) chrl_output + 2)

   iml_socket = socket( ADSL_CREATE_SOCKET_LIGW_G->ucc_family,  /* address family */
                        ADSL_CREATE_SOCKET_LIGW_G->ucc_socket_type,  /* type of socket */
                        ADSL_CREATE_SOCKET_LIGW_G->ucc_protocol );  /* protocol used */
   if (iml_socket < 0) {                    /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W error socket() returned %d %d.",
                   __LINE__, iml_socket, D_TCP_ERROR );
     AIML_RESP_SOCKET_FAILED[ 0 ] = ied_ligwec_socket;  /* socket failed */
     AIML_RESP_SOCKET_FAILED[ 1 ] = iml_socket;  /* first error code   */
     AIML_RESP_SOCKET_FAILED[ 2 ] = errno;  /* second error code       */
     goto p_rec_crso_20;                    /* could not create socket */
   }
   iml_rc = setsockopt( iml_socket, SOL_SOCKET, SO_REUSEADDR, (const char *) &ims_true, sizeof(int) );
   if (iml_rc != 0) {                     /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W error setsockopt() returned %d %d.",
                   __LINE__, iml_rc, D_TCP_ERROR );
   }
   memset( &dsl_soa, 0, sizeof(struct sockaddr_storage) );  /* for bind() */
   dsl_soa.ss_family = ADSL_CREATE_SOCKET_LIGW_G->ucc_family;  /* address family */
   if (dsl_soa.ss_family == AF_INET) {      /* IPV4                    */
     achl2 = (char *) &((struct sockaddr_in *) &dsl_soa)->sin_addr;
     iml2 = 4;
     memcpy( &((struct sockaddr_in *) &dsl_soa)->sin_port,
             ADSL_CREATE_SOCKET_LIGW_G->ucrc_port,  /* port            */
             sizeof(((struct sockaddr_in *) &dsl_soa)->sin_port) );
     iml3 = sizeof(struct sockaddr_in);
   } else if (dsl_soa.ss_family == AF_INET6) {  /* IPV6                */
     achl2 = (char *) &((struct sockaddr_in6 *) &dsl_soa)->sin6_addr;
     iml2 = 16;
     memcpy( &((struct sockaddr_in6 *) &dsl_soa)->sin6_port,
             ADSL_CREATE_SOCKET_LIGW_G->ucrc_port,  /* port            */
             sizeof(((struct sockaddr_in6 *) &dsl_soa)->sin6_port) );
     iml3 = sizeof(struct sockaddr_in6);
   } else {
     m_hl1_printf( "nbipgw19-l%05d-W received create socket - family %d invalid",
                   __LINE__, dsl_soa.ss_family );
// to-do 13.09.11 KB error message
     iml2 = 0;
   }
   if (iml2 != (iml1 - 1 - sizeof(struct dsd_create_socket_ligw))) {
// to-do 13.09.11 KB error message
     m_hl1_printf( "nbipgw19-l%05d-W received create socket - length record received invalid",
                   __LINE__ );
   }
   memcpy( achl2, ADSL_CREATE_SOCKET_LIGW_G + 1, iml2 );
#ifdef TRACEHL1
   iml_rc = getnameinfo( (struct sockaddr *) &dsl_soa, iml3,
                         byrl_trace_ineta, sizeof(byrl_trace_ineta),
                         0, 0, NI_NUMERICHOST );
   if (iml_rc < 0) {                  /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W getnameinfo() returned %d %d.",
                   __LINE__, iml_rc, errno );
     strcpy( byrl_trace_ineta, "???" );
   }
   m_hl1_printf( "nbipgw19-l%05d-T before bind INETA=%s port=%d.",
                 __LINE__, byrl_trace_ineta, ntohs( *((unsigned short int *) ADSL_CREATE_SOCKET_LIGW_G->ucrc_port) ) );
#endif
   iml_rc = bind( iml_socket, (struct sockaddr *) &dsl_soa, iml3 );
   if (iml_rc != 0) {                       /* error occured           */
     AIML_RESP_SOCKET_FAILED[ 0 ] = ied_ligwec_bind;  /* bind failed   */
     AIML_RESP_SOCKET_FAILED[ 1 ] = iml_rc;  /* first error code       */
     AIML_RESP_SOCKET_FAILED[ 2 ] = errno;  /* second error code       */
     close( iml_socket );                   /* close socket again      */
     goto p_rec_crso_20;                    /* could not create socket */
   }
   memset( &dsl_msg, 0, sizeof(struct msghdr) );

#ifdef MSGHDR_CONTROL_AVAILABLE
   dsl_msg.msg_control = dsl_control_un.chrc_control;
   dsl_msg.msg_controllen = sizeof(dsl_control_un.chrc_control);

   adsl_cmd = CMSG_FIRSTHDR( &dsl_msg );
   adsl_cmd->cmsg_len = CMSG_LEN( sizeof(int) );
   adsl_cmd->cmsg_level = SOL_SOCKET;
   adsl_cmd->cmsg_type = SCM_RIGHTS;
   *((int *) CMSG_DATA( adsl_cmd )) = iml_socket;
#else
   dsl_msg.msg_accrights = (caddr_t) &iml_socket;
   dsl_msg.msg_accrightslen = sizeof(int);
#endif

// dsl_msg.msg_name = NULL;
// dsl_msg.msg_namelen = 0;
   dsrl_iov[ 0 ].iov_base = chrs_requestheader_response;
   dsrl_iov[ 0 ].iov_len = sizeof(chrs_requestheader_response);
   dsrl_iov[ 1 ].iov_base = (char *) ucrs_resp_socket_ok;
   dsrl_iov[ 1 ].iov_len = sizeof(ucrs_resp_socket_ok);
   dsl_msg.msg_iov = dsrl_iov;
   dsl_msg.msg_iovlen = 2;
   iml_rc = sendmsg( adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.mc_getsocket(), &dsl_msg, 0 );
   iml1 = iml_rc;                           /* save return code        */
   iml2 = errno;                            /* save error number       */
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T p_record_20: sendmsg() returned %d errno %d.",
                 __LINE__, iml_rc, errno );
#endif
   if (ilrs_param_01[ PA_01_TRACE ] >= 4) {
     m_hl1_printf( "nbipgw19-l%05d-W sent socket=%d to wsp-conn=%p imc_rc=%d errno=%d.",
                   __LINE__, iml_socket, adsl_wsp_conn_w1, iml1, iml2 );
   }
// to-do 14.09.11 KB what is the return code ??? 0 or sizeof + sizeof ???
// to-do 14.09.11 KB close socket
   iml_rc = close( iml_socket );            /* close socket again      */
   if (iml_rc != 0) {                       /* error occured           */
// to-do 14.09.11 KB error message
     m_hl1_printf( "nbipgw19-l%05d-W received create socket - error close() returned %d %d.",
                   __LINE__, iml_rc, D_TCP_ERROR );
   }
   if (iml1 == (sizeof(chrs_requestheader_response) + sizeof(ucrs_resp_socket_ok))) {  /* no error occured */
     goto p_record_80;                      /* the record has been processed */
   }
// to-do 14.09.11 KB error message
   m_hl1_printf( "nbipgw19-l%05d-W received create socket - sendmsg() returned %d %d.",
                 __LINE__, iml1, iml2 );
   goto p_record_80;                        /* the record has been processed */

#undef ADSL_CREATE_SOCKET_LIGW_G

   p_rec_crso_20:                           /* could not create socket */
   *((unsigned char *) AIML_RESP_SOCKET_FAILED - 1) = ied_ligwr_resp_socket_failed;  /* create socket failed */
   *((unsigned char *) AIML_RESP_SOCKET_FAILED - 2) = 1 + 3 * sizeof(int);  /* length of message */
   dsrl_gai1_out1[ 0 ].adsc_next = &dsrl_gai1_out1[ 1 ];
   dsrl_gai1_out1[ 0 ].achc_ginp_cur = chrs_requestheader_response;
   dsrl_gai1_out1[ 0 ].achc_ginp_end = chrs_requestheader_response + sizeof(chrs_requestheader_response);
   dsrl_gai1_out1[ 1 ].adsc_next = NULL;
   dsrl_gai1_out1[ 1 ].achc_ginp_cur = (char *) AIML_RESP_SOCKET_FAILED - 2;
   dsrl_gai1_out1[ 1 ].achc_ginp_end = (char *) (AIML_RESP_SOCKET_FAILED + 3);
   iml_rc = adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_send_gather( dsrl_gai1_out1, NULL );
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T p_rec_crso_20: m_send_gather() returned %d.",
                 __LINE__, iml_rc );
#endif
   if (ilrs_param_01[ PA_01_TRACE ] >= 4) {
     m_hl1_printf( "nbipgw19-l%05d-W sent could not create socket to wsp-conn=%p imc_rc=%d.",
                   __LINE__, adsl_wsp_conn_w1, iml_rc );
   }
   goto p_record_80;                        /* the record has been processed */

#undef AIML_RESP_SOCKET_FAILED

   p_rec_cluster_00:                        /* received cluster        */
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T p_rec_cluster_00: ACHL_INPUT_STA=%p length-iml1=%d.",
                 __LINE__, ACHL_INPUT_STA, iml1 );
#endif
   if (adsl_wsp_conn_w1->imc_len_cluster) {  /* length cluster entry   */
     free( adsl_wsp_conn_w1->achc_cluster );  /* free cluster entry    */
   }
// to-do 19.09.11 KB stop listen
   adsl_wsp_conn_w1->imc_no_clli = 0;       /* number of cluster listen */
   iml1--;                                  /* length minus tag        */
   if (iml1 <= 0) {                         /* length too short        */
// to-do 19.09.11 KB error message
     m_hl1_printf( "nbipgw19-l%05d-W received cluster record from connected WSP - record length %d invalid",
                   __LINE__, iml1 );
     adsl_wsp_conn_w1->imc_len_cluster = 0;  /* length cluster entry   */
     goto p_record_80;                      /* the record has been processed */
   }
   adsl_wsp_conn_w1->imc_len_cluster = iml1;  /* length cluster entry  */
   adsl_wsp_conn_w1->achc_cluster = (char *) malloc( iml1 );  /* allocate new cluster entry */
   memcpy( adsl_wsp_conn_w1->achc_cluster, ACHL_INPUT_STA + 1, iml1 );  /* copy new cluster entry */
   achl1 = ACHL_INPUT_STA + 1;              /* start of structures     */
   achl2 = achl1 + iml1;                    /* end of structures       */

#define ADSL_LIGW_CLI_EXT_G ((struct dsd_ligw_clli_ext *) (adsl_listen_w1 + 1))

   p_rec_cluster_20:                        /* check cluster structure */
   iml1 = *((unsigned char *) achl1);       /* get length              */
   achl3 = achl1 + iml1;                    /* end of this cluster structure */
   if (iml1 == (1 + 2 + 2 + 4)) {           /* is IPV4                 */
     iml2 = AF_INET;                        /* set IPV4                */
   } else if (iml1 == (1 + 2 + 2 + 16)) {   /* is IPV6                 */
     iml2 = AF_INET6;                       /* set IPV6                */
   } else {                                 /* other value not valid   */
// to-do 19.09.11 KB error message
     m_hl1_printf( "nbipgw19-l%05d-W received cluster record from connected WSP - record length %d invalid",
                   __LINE__, iml1 );
     goto p_record_80;                      /* the record has been processed */
   }
   if (achl3 > achl2) {                     /* compare with end        */
// to-do 19.09.11 KB error message
     m_hl1_printf( "nbipgw19-l%05d-W received cluster record from connected WSP - record incomplete",
                   __LINE__ );
     goto p_record_80;                      /* the record has been processed */
   }
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T p_rec_cluster_20: achl1=%p achl2=%p achl3=%p length-iml1=%d family-iml2=%d.",
                 __LINE__, achl1, achl2, achl3, iml1, iml2 );
#endif
   adsl_listen_w1 = adss_listen_chain;      /* chain for UDS and TCP listen */
   bol1 = FALSE;                            /* does not match          */
   while (adsl_listen_w1) {                 /* loop over all listen    */
#ifdef TRACEHL_CLLI
     int imh1 = 0;
     if (adsl_listen_w1->iec_lit == ied_lit_cluster) { /* cluster      */
       imh1 = ADSL_LIGW_CLI_EXT_G->imc_usage;
     }
     m_hl1_printf( "nbipgw19-l%05d-T p_rec_cluster_20 adsl_listen_w1=%p ->iec_lit=%d ADSL_LIGW_CLI_EXT_G->imc_usage=%d.",
                   __LINE__, adsl_listen_w1, adsl_listen_w1->iec_lit, imh1 );
#endif
     if (   (adsl_listen_w1->iec_lit == ied_lit_cluster)  /* cluster   */
         && (ADSL_LIGW_CLI_EXT_G->dsc_soa.ss_family == iml2)) {  /* same family */
       switch (iml2) {                      /* switch on family        */
         case AF_INET:                      /* IPV4                    */
           if (   (!memcmp( &((struct sockaddr_in *) &ADSL_LIGW_CLI_EXT_G->dsc_soa)->sin_port,
                            achl1 + 1,
                            2 ))
               && (!memcmp( &((struct sockaddr_in *) &ADSL_LIGW_CLI_EXT_G->dsc_soa)->sin_addr,
                            achl1 + 1 + 2 + 2,
                            4 ))) {
             bol1 = TRUE;                   /* does match              */
           }
           break;
         case AF_INET6:                     /* IPV6                    */
           if (   (!memcmp( &((struct sockaddr_in6 *) &ADSL_LIGW_CLI_EXT_G->dsc_soa)->sin6_port,
                            achl1 + 1,
                            2 ))
               && (!memcmp( &((struct sockaddr_in6 *) &ADSL_LIGW_CLI_EXT_G->dsc_soa)->sin6_addr,
                            achl1 + 1 + 2 + 2,
                            16 ))) {
             bol1 = TRUE;                   /* does match              */
           }
           break;
       }
       if (bol1) {                          /* does match              */
         if (adsl_wsp_conn_w1->imc_no_clli >= D_LIGW_MAX_CLUSTER_WSP) {  /* number of cluster listen */
// to-do 19.09.11 KB error message
           m_hl1_printf( "nbipgw19-l%05d-W received cluster record from connected WSP - too many entries",
                         __LINE__ );
           goto p_rec_cluster_80;           /* end of this cluster structure */
         }
         adsl_wsp_conn_w1->adsrc_clli[ adsl_wsp_conn_w1->imc_no_clli ] = adsl_listen_w1;
         adsl_wsp_conn_w1->imc_no_clli++;   /* increment count         */
         ADSL_LIGW_CLI_EXT_G->imc_usage++;  /* usage count             */
         goto p_rec_cluster_80;             /* end of this cluster structure */
       }
     }
     adsl_listen_w1 = adsl_listen_w1->adsc_next;  /* get next in chain */
   }

   /* we need new listen                                               */
   adsl_listen_w1 = (struct dsd_listen *) malloc( sizeof(struct dsd_listen) + sizeof(struct dsd_ligw_clli_ext) );  /* for cluster listen */
   memset( adsl_listen_w1, 0, sizeof(struct dsd_listen) + sizeof(struct dsd_ligw_clli_ext) );  /* for cluster listen */
   adsl_listen_w1->iec_lit = ied_lit_cluster;  /* cluster              */
   ADSL_LIGW_CLI_EXT_G->dsc_soa.ss_family = iml2;  /* set family       */
   switch (iml2) {                          /* switch on family        */
     case AF_INET:                          /* IPV4                    */
       memcpy( &((struct sockaddr_in *) &ADSL_LIGW_CLI_EXT_G->dsc_soa)->sin_port,
               achl1 + 1,
               2 );
       memcpy( &((struct sockaddr_in *) &ADSL_LIGW_CLI_EXT_G->dsc_soa)->sin_addr,
               achl1 + 1 + 2 + 2,
               4 );
       iml1 = sizeof(struct sockaddr_in);
       break;
     case AF_INET6:                         /* IPV6                    */
       memcpy( &((struct sockaddr_in6 *) &ADSL_LIGW_CLI_EXT_G->dsc_soa)->sin6_port,
               achl1 + 1,
               2 );
       memcpy( &((struct sockaddr_in6 *) &ADSL_LIGW_CLI_EXT_G->dsc_soa)->sin6_addr,
               achl1 + 1 + 2 + 2,
               16 );
       iml1 = sizeof(struct sockaddr_in6);
       break;
   }
   iml_socket = socket( iml2, SOCK_STREAM, 0 );
   if (iml_socket < 0) {                    /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W cluster socket Error %d %d.",
                     __LINE__, iml_socket, D_TCP_ERROR );
     free( adsl_listen_w1 );                /* free memory of listen   */
     goto p_rec_cluster_80;                 /* end of this cluster structure */
   }
   /* Bind the socket to the address passed                            */
   iml_rc = bind( iml_socket, (struct sockaddr *) &ADSL_LIGW_CLI_EXT_G->dsc_soa, iml1 );
   if (iml_rc != 0) {                       /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W cluster bind error %d %d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
     D_TCP_CLOSE( iml_socket );             /* close socket again      */
     free( adsl_listen_w1 );                /* free memory of listen   */
     goto p_rec_cluster_80;                 /* end of this cluster structure */
   }
   iml_rc = listen( iml_socket, D_LIGW_CLUSTER_BACKLOG );
   if (iml_rc != 0) {                       /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W cluster listen error %d %d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
     D_TCP_CLOSE( iml_socket );             /* close socket again      */
     free( adsl_listen_w1 );                /* free memory of listen   */
     goto p_rec_cluster_80;                 /* end of this cluster structure */
   }
   if (adsl_wsp_conn_w1->imc_no_clli >= D_LIGW_MAX_CLUSTER_WSP) {  /* number of cluster listen */
// to-do 19.09.11 KB error message
     m_hl1_printf( "nbipgw19-l%05d-W received cluster record from connected WSP - too many entries",
                   __LINE__ );
     D_TCP_CLOSE( iml_socket );             /* close socket again      */
     free( adsl_listen_w1 );                /* free memory of listen   */
     goto p_rec_cluster_80;                 /* end of this cluster structure */
   }
   adsl_wsp_conn_w1->adsrc_clli[ adsl_wsp_conn_w1->imc_no_clli ] = adsl_listen_w1;
   adsl_wsp_conn_w1->imc_no_clli++;         /* increment count         */
   ADSL_LIGW_CLI_EXT_G->imc_usage = 1;      /* usage count             */
   iml_rc = adsl_listen_w1->dsc_acc_lis.mc_startlisten_fix( iml_socket, &dss_acc_cb, adsl_listen_w1 );
// to-do 19.09.11 KB check return code
   if (iml_rc != 0) {                       /* returned error          */
     m_hl1_printf( "nbipgw19-%05d-W m_tccb_wsp_recvcallback() mc_startlisten_fix() listen %p returned error %d.",
                   __LINE__, adsl_listen_w1, iml_rc );
   }
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_recvcallback() adsl_listen_w1=%p iml_rc=%d.",
                 __LINE__, adsl_listen_w1, iml_rc );
#endif
   adsl_listen_w1->adsc_next = adss_listen_chain;  /* append old chain */
   adss_listen_chain = adsl_listen_w1;      /* set new chain           */

   p_rec_cluster_80:                        /* end of this cluster structure */
   achl1 = achl3;                           /* point to next cluster structure */
   if (achl1 < achl2) goto p_rec_cluster_20;  /* check cluster structure */
#ifdef D_INCL_HOB_TUN
   goto p_record_80;                        /* the record has been processed */
#endif

#undef ADSL_LIGW_CLI_EXT_G

#ifdef D_INCL_HOB_TUN
   p_rec_open_tun:                          /* received query open TUN */
#define ADSL_QUERY_OPEN_TUN_G ((struct dsd_ligw_q_open_tun *) (ACHL_INPUT_STA + 1))  /* query open TUN adapter */
#ifdef HL_LINUX
   iml_socket = adsp_tcpcomp->m_get_unix_socket_fd();
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_recvcallback() p_rec_open_tun: fd=%d.",
                 __LINE__, iml_socket );
#endif
   memset( &dsl_ifreq, 0, sizeof(struct ifreq) );  /* interface request */
   dsl_ifreq.ifr_flags = IFF_TUN | IFF_NO_PI;
   iml_rc = ioctl( iml_socket, TUNSETIFF, &dsl_ifreq );
#ifdef TRACEHL1
   iml_error = errno;                       /* error retrieved         */
   m_hl1_printf( "nbipgw19-l%05d-T p_rec_open_tun: ioctl( ... , TUNSETIFF , ... ) returned %d errno %d.",
                 __LINE__, iml_rc, errno );
   m_console_out( (char *) &dsl_ifreq, sizeof(dsl_ifreq) );
   errno = iml_error;                       /* error retrieved         */
#endif
   if (iml_rc < 0) {                        /* error occured           */
     iml_error = errno;                     /* error retrieved         */
     m_hl1_printf( "nbipgw19-l%05d-W p_rec_open_tun: ioctl( ... , TUNSETIFF , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, iml_error );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W p_rec_open_tun: ioctl( ... , TUNSETIFF , ... ) returned %d errno %d.",
                     __LINE__, iml_rc, iml_error );
   }
#endif
#ifdef HL_FREEBSD
   iml_socket = open( D_DEV_TUN, O_RDWR );
   if (iml_rc < 0) {                        /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W TUN open( %s , ... ) returned iml_socket %d errno %d.",
                   __LINE__, D_DEV_TUN, iml_socket, errno );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W p_rec_open_tun: TUN open( %s , ... ) returned iml_socket %d errno %d.",
                     __LINE__, D_DEV_TUN, iml_socket, iml_error );
   }
   iml_rc = ioctl( iml_socket, TUNSLMODE, &ims_zero );                //  Equivalent
//#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_gw_start_htun() ioctl( ... TUNSLMODE ... ) returned %d errno %d.",
                 __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W ioctl( ... , TUNSLMODE , ... ) retuned error %d errno %d.",
                   __LINE__, iml_rc, errno );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W p_rec_open_tun: ioctlioctl( ... , TUNSLMODE , ... ) returned %d errno %d.",
                     __LINE__, iml_rc, iml_error );
   }

   iml_rc = ioctl( iml_socket, TUNSIFHEAD, &ims_zero );               //  IFF_NO_PI
//#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_gw_start_htun() ioctl( ... TUNSIFHEAD ... ) returned %d errno %d.",
                 __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W ioctl( ... , TUNSIFHEAD , ... ) retuned error %d errno %d.",
                   __LINE__, iml_rc, errno );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W p_rec_open_tun: ioctlioctl( ... , TUNSIFHEAD , ... ) returned %d errno %d.",
                     __LINE__, iml_rc, iml_error );
   }

   iml_rc = ioctl( iml_socket, FIONBIO, &ims_zero );
//#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T p_rec_open_tun: ioctl( ... FIONBIO ... ) returned %d errno %d.",
                 __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W ioctl( ... , FIONBIO , ... ) retuned error %d errno %d.",
                   __LINE__, iml_rc, errno );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W p_rec_open_tun: ioctlioctl( ... , FIONBIO , ... ) returned %d errno %d.",
                     __LINE__, iml_rc, iml_error );
   }
//-----
   memset( &dsl_ifreq, 0, sizeof(struct ifreq) );  /* interface request */
   achl1 = fdevname_r( iml_socket, dsl_ifreq.ifr_name, sizeof(dsl_ifreq.ifr_name) );
   m_hl1_printf( "nbipgw19-l%05d-T p_rec_open_tun: fdevname_r( ... ) returned %p errno %d.",
                   __LINE__, achl1, errno );
#ifdef NOT_YET_150910
   if (achl1 == NULL) {
     m_hl1_printf( "nbipgw19-l%05d-W p_rec_open_tun: fdevname of TUN device returned error errno %d.",
                     errno );
     close( iml_socket );
//   return;
   }
#endif
#endif
   iml_index_ineta_ipv6 = 0;                /* index INETA IPV6        */
   iml_index_ineta_ipv4 = 0;                /* index INETA IPV4        */
   achl1 = (char *) (ADSL_QUERY_OPEN_TUN_G + 1);
   while (iml_index_ineta_ipv4 < ADSL_QUERY_OPEN_TUN_G->ucc_no_ineta_ipv4) {  /* number of INETAs IPV4 */
     /* aligned needed                                                 */
     memcpy( &uml_ineta_w1, achl1, sizeof(UNSIG_MED) );
     bol_rc = m_htun_search_interface_ipv4( uml_ineta_w1 );  /* <TUN-adapter-ineta> */
     m_hl1_printf( "nbipgw19-l%05d-T p_rec_open_tun: m_htun_search_interface_ipv4 TUN returned %d INETA %d.%d.%d.%d.",
                   __LINE__,
                   bol_rc,
                   *((unsigned char *) achl1 + 0),
                   *((unsigned char *) achl1 + 1),
                   *((unsigned char *) achl1 + 2),
                   *((unsigned char *) achl1 + 3) );
     if (bol_rc == FALSE) break;
     iml_index_ineta_ipv4++;                /* increment index INETA IPV4 */
     achl1 += 4;                            /* next INETA received     */
   }
   if (iml_index_ineta_ipv4 >= ADSL_QUERY_OPEN_TUN_G->ucc_no_ineta_ipv4) {  /* number of INETAs IPV4 */
     m_hl1_printf( "nbipgw19-l%05d-W p_rec_open_tun: no free <TUN-adapter-ineta> IPV4 found",
                   __LINE__ );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W p_rec_open_tun: no free <TUN-adapter-ineta> IPV4 found",
                     __LINE__ );
     iml_index_ineta_ipv4 = 0;              /* return error            */
     goto p_ro_tun_20;                      /* continue open TUN       */
   }
   iml_index_ineta_ipv4++;                  /* return + 1              */
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_recvcallback() p_rec_open_tun: SIOCSIFADDR with INETA %d.%d.%d.%d.",
                 __LINE__,
                   *((unsigned char *) achl1 + 0),
                   *((unsigned char *) achl1 + 1),
                   *((unsigned char *) achl1 + 2),
                   *((unsigned char *) achl1 + 3) );
#endif
#define ADSL_SOCKADDR_IFR_ADDR ((struct sockaddr_in *) &dsl_ifreq.ifr_addr)
#ifdef HL_LINUX
   ADSL_SOCKADDR_IFR_ADDR->sin_family = AF_INET;
#endif
#ifdef HL_FREEBSD
#ifdef B160706
   ((struct sockaddr *) ADSL_SOCKADDR_IFR_ADDR)->sa_len = sizeof(struct sockaddr_in);  /* total length */
   ((struct sockaddr *) ADSL_SOCKADDR_IFR_ADDR)->sa_family = AF_INET;
#endif
#define ADSL_SOCKADDR_ALR_ADDR ((struct sockaddr_in *) &dsl_alreq.ifra_addr)
#define ADSL_SOCKADDR_ALR_NETM ((struct sockaddr_in *) &dsl_alreq.ifra_mask)
#define ADSL_SOCKADDR_ALR_DST ((struct sockaddr_in *) &dsl_alreq.ifra_broadaddr)
   memset( &dsl_alreq, 0, sizeof(dsl_alreq) );
   memcpy( dsl_alreq.ifra_name, dsl_ifreq.ifr_name, sizeof(dsl_ifreq.ifr_name) );
   ((struct sockaddr *) ADSL_SOCKADDR_ALR_ADDR)->sa_len = sizeof(struct sockaddr);  /* total length */
   ((struct sockaddr *) ADSL_SOCKADDR_ALR_ADDR)->sa_family = AF_INET;
   ((struct sockaddr *) ADSL_SOCKADDR_ALR_NETM)->sa_len = sizeof(struct sockaddr);  /* total length */
   ((struct sockaddr *) ADSL_SOCKADDR_ALR_NETM)->sa_family = AF_INET;
   ((struct sockaddr *) ADSL_SOCKADDR_ALR_DST)->sa_len = sizeof(struct sockaddr);  /* total length */
   ((struct sockaddr *) ADSL_SOCKADDR_ALR_DST)->sa_family = AF_INET;
   memcpy( &ADSL_SOCKADDR_ALR_ADDR->sin_addr, achl1, sizeof(UNSIG_MED) );  /* <TUN-adapter-ineta> */
   memcpy( &ADSL_SOCKADDR_ALR_NETM->sin_addr, chrs_tun_mask_ipv4, sizeof(UNSIG_MED) );  /* <TUN-adapter-network-mask> */
// to-do 06.07.16 KB - why XOR
   //ADSL_SOCKADDR_ALR_DST->sin_addr.s_addr=ADSL_SOCKADDR_ALR_ADDR->sin_addr.s_addr|(~ADSL_SOCKADDR_ALR_NETM->sin_addr.s_addr);
   ADSL_SOCKADDR_ALR_DST->sin_addr.s_addr
     = ADSL_SOCKADDR_ALR_ADDR->sin_addr.s_addr ^ (~ADSL_SOCKADDR_ALR_NETM->sin_addr.s_addr);
#undef ADSL_SOCKADDR_ALR_ADDR
#undef ADSL_SOCKADDR_ALR_NETM
#undef ADSL_SOCKADDR_ALR_DST
#endif
   memcpy( &ADSL_SOCKADDR_IFR_ADDR->sin_addr, achl1, sizeof(UNSIG_MED) );  /* <TUN-adapter-ineta> */
#undef ADSL_SOCKADDR_IFR_ADDR
#ifdef HL_LINUX
#ifdef TRACEHL1
   m_console_out( (char *) &dsl_ifreq, sizeof(dsl_ifreq) );
#endif
   iml_rc = ioctl( ims_tun_socket, SIOCSIFADDR, &dsl_ifreq );
// iml_rc = ioctl( iml_socket, SIOCSIFADDR, &dsl_ifreq );
#ifdef TRACEHL1
   iml_error = errno;                       /* error retrieved         */
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_recvcallback() p_rec_open_tun: ioctl( ... , SIOCSIFADDR , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
   m_console_out( (char *) &dsl_ifreq, sizeof(dsl_ifreq) );
   errno = iml_error;                       /* error retrieved         */
#endif
   if (iml_rc < 0) {                        /* error occured           */
     iml_error = errno;                     /* error retrieved         */
     m_hl1_printf( "nbipgw19-l%05d-W p_rec_open_tun: ioctl( ... , SIOCSIFADDR , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, iml_error );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W p_rec_open_tun: ioctl( ... , SIOCSIFADDR , ... ) returned %d errno %d.",
                     __LINE__, iml_rc, iml_error );
   }
#ifdef TRACEHL1
   m_console_out( (char *) &dsl_ifreq, sizeof(dsl_ifreq) );
#endif
#endif
#ifdef HL_FREEBSD
#ifdef TRACEHL1
   m_console_out( (char *) &dsl_alreq, sizeof(dsl_alreq) );
#endif
   iml_rc = ioctl( ims_tun_socket, SIOCAIFADDR, &dsl_alreq );
#ifdef TRACEHL1
   iml_error = errno;                       /* error retrieved         */
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_recvcallback() p_rec_open_tun: ioctl( ... , SIOCAIFADDR , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
   m_console_out( (char *) &dsl_alreq, sizeof(dsl_alreq) );
   errno = iml_error;                       /* error retrieved         */
#endif
   if (iml_rc < 0) {                        /* error occured           */
     iml_error = errno;                     /* error retrieved         */
     m_hl1_printf( "nbipgw19-l%05d-W p_rec_open_tun: ioctl( ... , SIOCAIFADDR , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, iml_error );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W p_rec_open_tun: ioctl( ... , SIOCAIFADDR , ... ) returned %d errno %d.",
                     __LINE__, iml_rc, iml_error );
   }
#ifdef TRACEHL1
   m_console_out( (char *) &dsl_alreq, sizeof(dsl_alreq) );
#endif
#endif
   iml_rc = ioctl( ims_tun_socket, SIOCGIFFLAGS, &dsl_ifreq );
// iml_rc = ioctl( iml_socket, SIOCGIFFLAGS, &dsl_ifreq );
#ifdef TRACEHL1
   iml_error = errno;                       /* error retrieved         */
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_recvcallback() p_rec_open_tun: ioctl( ... , SIOCGIFFLAGS , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
   m_console_out( (char *) &dsl_ifreq, sizeof(dsl_ifreq) );
   errno = iml_error;                       /* error retrieved         */
#endif
   if (iml_rc < 0) {                        /* error occured           */
     iml_error = errno;                     /* error retrieved         */
     m_hl1_printf( "nbipgw19-l%05d-W p_rec_open_tun: ioctl( ... , SIOCGIFFLAGS , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, iml_error );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W p_rec_open_tun: ioctl( ... , SIOCGIFFLAGS , ... ) returned %d errno %d.",
                     __LINE__, iml_rc, iml_error );
   }
   dsl_ifreq.ifr_flags |= IFF_UP | IFF_RUNNING;
#ifdef TRACEHL1
   m_console_out( (char *) &dsl_ifreq, sizeof(dsl_ifreq) );
#endif
   iml_rc = ioctl( ims_tun_socket, SIOCSIFFLAGS, &dsl_ifreq );
// iml_rc = ioctl( iml_socket, SIOCSIFFLAGS, &dsl_ifreq );
#ifdef TRACEHL1
   iml_error = errno;                       /* error retrieved         */
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_recvcallback() p_rec_open_tun: ioctl( ... , SIOCSIFFLAGS , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
   m_console_out( (char *) &dsl_ifreq, sizeof(dsl_ifreq) );
   errno = iml_error;                       /* error retrieved         */
#endif
   if (iml_rc < 0) {                        /* error occured           */
     iml_error = errno;                     /* error retrieved         */
     m_hl1_printf( "nbipgw19-l%05d-W p_rec_open_tun: ioctl( ... , SIOCSIFFLAGS , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, iml_error );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W p_rec_open_tun: ioctl( ... , SIOCSIFFLAGS , ... ) returned %d errno %d.",
                     __LINE__, iml_rc, iml_error );
   }
#undef ims_tun_socket

   p_ro_tun_20:                             /* continue open TUN       */
#ifdef HL_LINUX
   iml_rc = close( iml_socket );
   if (iml_rc < 0) {                        /* error occured           */
     iml_error = errno;                     /* error retrieved         */
     m_hl1_printf( "nbipgw19-l%05d-W p_rec_open_tun: TUN adapter close( %d ) returned %d errno %d.",
                   __LINE__, iml_socket, iml_rc, iml_error );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W p_rec_open_tun: TUN adapter close( %d ) returned %d errno %d.",
                     __LINE__, iml_socket, iml_rc, iml_error );
   }
#endif
#define ADSL_RESP_OPEN_TUN_G ((struct dsd_ligw_r_open_tun *) (chrl_output + 8))  /* response open TUN adapter */
   ADSL_RESP_OPEN_TUN_G->ucc_index_ineta_ipv4  /* index of INETA IPV4 + 1 */
     = iml_index_ineta_ipv4;                /* index INETA IPV4        */
   ADSL_RESP_OPEN_TUN_G->ucc_index_ineta_ipv6  /* index of INETA IPV6 + 1 */
     = iml_index_ineta_ipv6;                /* index INETA IPV6        */
   memcpy( ADSL_RESP_OPEN_TUN_G->chrc_tiface, dsl_ifreq.ifr_name, IFNAMSIZ );
   achl1 = (char *) ADSL_RESP_OPEN_TUN_G;
   achl2 = (char *) (ADSL_RESP_OPEN_TUN_G + 1);
#undef ADSL_RESP_OPEN_TUN_G
#undef ADSL_QUERY_OPEN_TUN_G
   *(--achl1) = (unsigned char) ied_ligwr_resp_open_tun;  /* open TUN adapter */
   iml1 = achl2 - achl1;                    /* sizeof record           */
   iml2 = 0;                                /* clear more bit          */
   do {                                     /* loop output NHASN       */
     *(--achl1) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* shift bits              */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
#ifdef HL_LINUX
   dsrl_gai1_out1[ 0 ].adsc_next = &dsrl_gai1_out1[ 1 ];
   dsrl_gai1_out1[ 0 ].achc_ginp_cur = chrs_requestheader_response;
   dsrl_gai1_out1[ 0 ].achc_ginp_end = chrs_requestheader_response + sizeof(chrs_requestheader_response);
   dsrl_gai1_out1[ 1 ].adsc_next = NULL;
   dsrl_gai1_out1[ 1 ].achc_ginp_cur = achl1;  /* start of content     */
   dsrl_gai1_out1[ 1 ].achc_ginp_end = achl2;  /* end of content       */
   iml_rc = adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_send_gather( dsrl_gai1_out1, NULL );
   if (ilrs_param_01[ PA_01_TRACE ] >= 4) {
     m_hl1_printf( "nbipgw19-l%05d-W sent data to wsp-conn=%p imc_rc=%d.",
                   __LINE__, adsl_wsp_conn_w1, iml_rc );
   }
#endif
#ifdef HL_FREEBSD
   memset( &dsl_msg, 0, sizeof(struct msghdr) );

#ifdef MSGHDR_CONTROL_AVAILABLE
   dsl_msg.msg_control = dsl_control_un.chrc_control;
   dsl_msg.msg_controllen = sizeof(dsl_control_un.chrc_control);

   adsl_cmd = CMSG_FIRSTHDR( &dsl_msg );
   adsl_cmd->cmsg_len = CMSG_LEN( sizeof(int) );
   adsl_cmd->cmsg_level = SOL_SOCKET;
   adsl_cmd->cmsg_type = SCM_RIGHTS;
   *((int *) CMSG_DATA( adsl_cmd )) = iml_socket;
#else
   dsl_msg.msg_accrights = (caddr_t) &iml_socket;
   dsl_msg.msg_accrightslen = sizeof(int);
#endif

// dsl_msg.msg_name = NULL;
// dsl_msg.msg_namelen = 0;
   dsrl_iov[ 0 ].iov_base = chrs_requestheader_response;
   dsrl_iov[ 0 ].iov_len = sizeof(chrs_requestheader_response);
   dsrl_iov[ 1 ].iov_base = achl1;          /* start of content        */
   dsrl_iov[ 1 ].iov_len = achl2 - achl1;   /* length of content       */
   dsl_msg.msg_iov = dsrl_iov;
   dsl_msg.msg_iovlen = 2;
   iml_rc = sendmsg( adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.mc_getsocket(), &dsl_msg, 0 );
   iml1 = iml_rc;                           /* save return code        */
   iml2 = errno;                            /* save error number       */
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T TUN sendmsg() returned %d errno %d.",
                 __LINE__, iml_rc, errno );
#endif
   if (ilrs_param_01[ PA_01_TRACE ] >= 4) {
     m_hl1_printf( "nbipgw19-l%05d-W TUN sent socket=%d to wsp-conn=%p imc_rc=%d errno=%d.",
                   __LINE__, iml_socket, adsl_wsp_conn_w1, iml1, iml2 );
   }
   iml_rc = close( iml_socket );
   if (iml_rc < 0) {                        /* error occured           */
     iml_error = errno;                     /* error retrieved         */
     m_hl1_printf( "nbipgw19-l%05d-W p_rec_open_tun: TUN adapter close( %d ) returned %d errno %d.",
                   __LINE__, iml_socket, iml_rc, iml_error );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W p_rec_open_tun: TUN adapter close( %d ) returned %d errno %d.",
                     __LINE__, iml_socket, iml_rc, iml_error );
   }
#endif
   goto p_record_80;                        /* the record has been processed */

   p_rec_ar_add_ipv4:                       /* received add AR IPV4    */
#define ADSL_QUERY_AR_ADD_IPV4_G ((struct dsd_ligw_q_ar_add_ipv4 *) (ACHL_INPUT_STA + 1))  /* add ARP and route IPV4 */
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T p_rec_ar_add_ipv4: command",
                   __LINE__ );
   m_console_out( (char *) ADSL_QUERY_AR_ADD_IPV4_G, sizeof(struct dsd_ligw_q_ar_add_ipv4) );
#endif
#ifdef CONTROL_INETAS
   if (adss_ci_ipv4_free_ch == NULL) {      /* chain of free structure to control INETAs IPV4 */
     adss_ci_ipv4_free_ch = (struct dsd_control_ineta_ipv4 *) malloc( NO_STRUCT_INETA * sizeof(struct dsd_control_ineta_ipv4) );
     iml1 = NO_STRUCT_INETA - 1;
     adsl_ci_ipv4_w1 = adss_ci_ipv4_free_ch;  /* structure to control INETAs IPV4 */
     do {
       adsl_ci_ipv4_w1->adsc_next = adsl_ci_ipv4_w1 + 1;  /* set chain of free elements */
       adsl_ci_ipv4_w1++;                   /* increment storage structure */
       iml1--;                              /* decrement index         */
     } while (iml1 > 0);
     adsl_ci_ipv4_w1->adsc_next = NULL;     /* set end of chain        */
   }
   adsl_ci_ipv4_w1 = adss_ci_ipv4_free_ch;  /* structure to control INETAs IPV4 */
   adss_ci_ipv4_free_ch = adsl_ci_ipv4_w1->adsc_next;  /* remove from chain of free structure to control INETAs IPV4 */
   adsl_ci_ipv4_w1->adsc_wsp_conn = adsl_wsp_conn_w1;  /* connection to a WSP */
   memcpy( &adsl_ci_ipv4_w1->dsc_ar_ipv4, ADSL_QUERY_AR_ADD_IPV4_G, sizeof(struct dsd_ligw_q_ar_add_ipv4) );
   bol_rc = m_htree1_avl_search( NULL, &dss_htree1_avl_control_ineta_ipv4,
                                 &dsl_htree1_work, &adsl_ci_ipv4_w1->dsc_sort_1 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W m_tccb_wsp_recvcallback() m_htree1_avl_search() new element failed",
                   __LINE__ );
     dsl_htree1_work.adsc_found = NULL;     /* not found in tree       */
   }
   if (dsl_htree1_work.adsc_found) {        /* found in tree           */
     m_hl1_printf( "nbipgw19-l%05d-W m_tccb_wsp_recvcallback() add ARP and route new INETA %d.%d.%d.%d already exists in AVL-tree",
                   __LINE__,
                   *((unsigned char *) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta + 0),
                   *((unsigned char *) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta + 1),
                   *((unsigned char *) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta + 2),
                   *((unsigned char *) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta + 3) );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W p_rec_ar_add_ipv4: INETA=%d.%d.%d.%d already exists in AVL-tree",
                     __LINE__,
                     *((unsigned char *) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta + 0),
                     *((unsigned char *) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta + 1),
                     *((unsigned char *) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta + 2),
                     *((unsigned char *) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta + 3) );
     adsl_ci_ipv4_w1->adsc_next = adss_ci_ipv4_free_ch;  /* get old chain of free structure to control INETAs IPV4 */
     adss_ci_ipv4_free_ch = adsl_ci_ipv4_w1;  /* set new chain of free structure to control INETAs IPV4 */
   } else {                                 /* not found in tree       */
     bol_rc = m_htree1_avl_insert( NULL, &dss_htree1_avl_control_ineta_ipv4,
                                   &dsl_htree1_work, &adsl_ci_ipv4_w1->dsc_sort_1 );
     if (bol_rc == FALSE) {                   /* error occured           */
       m_hl1_printf( "nbipgw19-l%05d-W m_tccb_wsp_recvcallback() m_htree1_avl_insert() new element failed",
                     __LINE__ );
     }
   }
#endif
#ifdef HL_LINUX
   memset( &dsl_arpreq, 0, sizeof(struct arpreq) );  /* struct for arp requests */
#define ADSL_SOCKADDR_ARP ((struct sockaddr_in *) &dsl_arpreq.arp_pa)
   ADSL_SOCKADDR_ARP->sin_family = AF_INET;
   memcpy( &ADSL_SOCKADDR_ARP->sin_addr, ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta, sizeof(UNSIG_MED) );
#undef ADSL_SOCKADDR_ARP
   memcpy( &dsl_arpreq.arp_ha, &ADSL_QUERY_AR_ADD_IPV4_G->dsc_rhwaddr, sizeof(struct sockaddr) );
   dsl_arpreq.arp_flags = ATF_PUBL | ATF_NETMASK;
   memcpy( dsl_arpreq.arp_dev, ADSL_QUERY_AR_ADD_IPV4_G->chrc_riface, IFNAMSIZ );
#define ADSL_SOCKADDR_NETMASK ((struct sockaddr_in *) &dsl_arpreq.arp_netmask)
   ADSL_SOCKADDR_NETMASK->sin_family = AF_INET;
   *((UNSIG_MED *) &ADSL_SOCKADDR_NETMASK->sin_addr) = 0XFFFFFFFF;  /* 255.255.255.255 */
#undef ADSL_SOCKADDR_NETMASK
   iml_rc = ioctl( ims_tun_socket, SIOCSARP, &dsl_arpreq );
#ifdef TRACEHL1
   iml_error = errno;                       /* error retrieved         */
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_recvcallback() p_rec_ar_add_ipv4: ioctl( ... , SIOCSARP , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
   errno = iml_error;                       /* error retrieved         */
#endif
   if (iml_rc < 0) {                        /* error occured           */
     iml_error = errno;                     /* error retrieved         */
     m_hl1_printf( "nbipgw19-l%05d-W p_rec_ar_add_ipv4: INETA=%d.%d.%d.%d ioctl( ... , SIOCSARP , ... ) returned %d errno %d.",
                   __LINE__,
                   (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 0 ],
                   (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 1 ],
                   (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 2 ],
                   (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 3 ],
                   iml_rc, iml_error );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W p_rec_ar_add_ipv4: INETA=%d.%d.%d.%d ioctl( ... , SIOCSARP , ... ) returned %d errno %d.",
                     __LINE__,
                     (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 0 ],
                     (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 1 ],
                     (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 2 ],
                     (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 3 ],
                     iml_rc, iml_error );
   }
   /* set GARP packet                                                  */
   memcpy( dss_tun_send_garp.chrc_h_macaddr_source, /* mac address of source */
           ADSL_QUERY_AR_ADD_IPV4_G->dsc_rhwaddr.sa_data,
           sizeof(dss_tun_send_garp.chrc_h_macaddr_source) );
   memcpy( dss_tun_send_garp.chrc_pl_macaddr_source,  /* Sender hardware address (SHA) */
           ADSL_QUERY_AR_ADD_IPV4_G->dsc_rhwaddr.sa_data,
           sizeof(dss_tun_send_garp.chrc_pl_macaddr_source) );
   memcpy( dss_tun_send_garp.chrc_pl_ineta_source,  /* Sender protocol address (SPA) */
           ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta,
           sizeof(dss_tun_send_garp.chrc_pl_ineta_source) );
   memcpy( dss_tun_send_garp.chrc_pl_ineta_target,  /* Target protocol address (TPA) */
           ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta,
           sizeof(dss_tun_send_garp.chrc_pl_ineta_target) );
   dss_soa_arp.sll_ifindex = ADSL_QUERY_AR_ADD_IPV4_G->imc_ifindex_nic;  /* interface number of NIC */
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T p_rec_ar_add_ipv4: GARP dss_soa_arp.sll_ifindex=%d.",
                   __LINE__, dss_soa_arp.sll_ifindex );
   m_console_out( (char *) &dss_tun_send_garp, sizeof(dss_tun_send_garp) );
#endif
   iml_rc = sendto( ims_tun_socket,
                    &dss_tun_send_garp, sizeof(dss_tun_send_garp),
                    0,
                    (struct sockaddr *) &dss_soa_arp, sizeof(dss_soa_arp) );
#ifdef TRACEHL1
   iml_error = errno;                       /* error retrieved         */
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_recvcallback() p_rec_ar_add_ipv4: sento( GARP ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
   errno = iml_error;                       /* error retrieved         */
#endif
   if (iml_rc != sizeof(dss_tun_send_garp)) {  /* check if all sent    */
     iml_error = errno;                     /* error retrieved         */
     m_hl1_printf( "nbipgw19-l%05d-W p_rec_ar_add_ipv4: INETA=%d.%d.%d.%d sento( GARP ) returned %d errno %d.",
                   __LINE__,
                   (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 0 ],
                   (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 1 ],
                   (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 2 ],
                   (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 3 ],
                   iml_rc, iml_error );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W p_rec_ar_add_ipv4: INETA=%d.%d.%d.%d sento( GARP ) returned %d errno %d.",
                     __LINE__,
                     (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 0 ],
                     (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 1 ],
                     (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 2 ],
                     (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 3 ],
                     iml_rc, iml_error );
   }
   /* set route                                                        */
   memset( &dsl_routereq, 0, sizeof(struct rtentry) );  /* struct for route request */
#define ADSL_SOCKADDR_DST ((struct sockaddr_in *) &dsl_routereq.rt_dst)
   ADSL_SOCKADDR_DST->sin_family = AF_INET;
   memcpy( &ADSL_SOCKADDR_DST->sin_addr, ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta, sizeof(UNSIG_MED) );
#undef ADSL_SOCKADDR_DST
   dsl_routereq.rt_metric = 31;
   dsl_routereq.rt_dev = ADSL_QUERY_AR_ADD_IPV4_G->chrc_tiface;
#define ADSL_RT_MASK ((struct sockaddr_in *) &dsl_routereq.rt_genmask)
   /* set netmask to 255.255.255.255                                   */
   ADSL_RT_MASK->sin_family      = AF_INET;
   ADSL_RT_MASK->sin_addr.s_addr = 0XFFFFFFFF;
#undef ADSL_RT_MASK
   iml_rc = ioctl( ims_tun_socket, SIOCADDRT, &dsl_routereq );
#ifdef TRACEHL1
   iml_error = errno;                       /* error retrieved         */
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_recvcallback() p_rec_ar_add_ipv4: ioctl( ... , SIOCADDRT , ... ) returned %d errno %d.",
                 __LINE__, iml_rc, errno );
   errno = iml_error;                       /* error retrieved         */
#endif
   if (iml_rc < 0) {                        /* error occured           */
     iml_error = errno;                     /* error retrieved         */
     m_hl1_printf( "nbipgw19-l%05d-W p_rec_ar_add_ipv4: INETA=%d.%d.%d.%d ioctl( ... , SIOCADDRT , ... ) returned %d errno %d.",
                   __LINE__,
                   (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 0 ],
                   (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 1 ],
                   (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 2 ],
                   (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 3 ],
                   iml_rc, iml_error );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W p_rec_ar_add_ipv4: INETA=%d.%d.%d.%d ioctl( ... , SIOCADDRT , ... ) returned %d errno %d.",
                     __LINE__,
                     (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 0 ],
                     (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 1 ],
                     (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 2 ],
                     (unsigned char) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta[ 3 ],
                     iml_rc, iml_error );
   }
#endif
#ifdef HL_FREEBSD
   /*
     set ARP entry
     sample: arp -s 172.22.81.221 00:0c:29:d5:a6:27 pub
   */
#define ADSL_RTM_G (&dsl_m_rtmsg.dsc_m_rtm)
#define LEN_SOA_MASK 8
#define IML_MSG_LEN (sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in) + ((sizeof(struct sockaddr_dl) + sizeof(int) - 1) & (0 - sizeof(int))) + LEN_SOA_MASK)
#define IML_MSG_SEQU 1
   memset( &dsl_m_rtmsg, 0, IML_MSG_LEN );
   ADSL_RTM_G->rtm_msglen = IML_MSG_LEN;
   ADSL_RTM_G->rtm_version = RTM_VERSION;
   ADSL_RTM_G->rtm_inits = RTV_EXPIRE;
   ADSL_RTM_G->rtm_flags = RTF_LLDATA | RTF_STATIC | RTF_PROTO2;
   ADSL_RTM_G->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
   ADSL_RTM_G->rtm_pid = ims_this_pid;      /* set process id          */
   ADSL_RTM_G->rtm_seq = IML_MSG_SEQU;
   ADSL_RTM_G->rtm_type = RTM_ADD;
#define ADSL_SOA_DST ((struct sockaddr_in *) dsl_m_rtmsg.byrc_m_space)
   ((struct sockaddr *) ADSL_SOA_DST)->sa_len = sizeof(struct sockaddr_in);  /* total length */
   ((struct sockaddr *) ADSL_SOA_DST)->sa_family = AF_INET;
   *((UNSIG_MED *) &ADSL_SOA_DST->sin_addr)
     = *((UNSIG_MED *) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta);
#define ADSL_SDL_G ((struct sockaddr_dl *) (dsl_m_rtmsg.byrc_m_space + sizeof(struct sockaddr_in)))
   memcpy( ADSL_SDL_G, ADSL_QUERY_AR_ADD_IPV4_G->chrc_soa_dl_riface, sizeof(struct sockaddr_dl) );
#define ADSL_SOA_MASK ((struct sockaddr_in *) ((char *) &dsl_m_rtmsg + sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in) + ((sizeof(struct sockaddr_dl) + sizeof(int) - 1) & (0 - sizeof(int)))))
   memset( ADSL_SOA_MASK, 0, LEN_SOA_MASK );
   ((struct sockaddr *) ADSL_SOA_MASK)->sa_len = LEN_SOA_MASK;
   *((UNSIG_MED *) &ADSL_SOA_MASK->sin_addr) = 0XFFFFFFFF;

   m_console_out( (char *) &dsl_m_rtmsg,
                  IML_MSG_LEN );
   iml_rc = write( ims_route_socket,
                   (char *) &dsl_m_rtmsg,
                   IML_MSG_LEN );

//#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T write() ARP returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   while (TRUE) {
     iml_rc = read( ims_route_socket,
                    (char *) &dsl_m_rtmsg,
                    sizeof(dsl_m_rtmsg) );
//#ifdef TRACEHL1
     m_hl1_printf( "nbipgw19-l%05d-T read() ARP returned %d errno %d.",
                     __LINE__, iml_rc, errno );
//#endif
     if (iml_rc > 0) {
       m_console_out( (char *) &dsl_m_rtmsg, iml_rc );
     }
     if (iml_rc < 0) {
       break;
     }
     if (   (ADSL_RTM_G->rtm_pid == ims_this_pid)  /* compare process id */
         && (ADSL_RTM_G->rtm_seq == IML_MSG_SEQU)) {
       break;
     }
   }
#undef ADSL_SDL_G
#undef ADSL_SOA_DST
#undef ADSL_SOA_MASK
#undef IML_MSG_LEN
#undef IML_MSG_SEQU
#undef LEN_SOA_MASK
   /*
     send GARP packet
   */
   iml_bpf_fd = m_htun_get_bpf_socket( ADSL_QUERY_AR_ADD_IPV4_G->chrc_riface );
   if (iml_bpf_fd >= 0) {                   /* with file-descriptor for bpf - Berkeley Packet Filter */
     /* set GARP packet                                            */
     memcpy( dss_tun_send_garp.chrc_h_macaddr_source, /* mac address of source */
             LLADDR( (struct sockaddr_dl *) ADSL_QUERY_AR_ADD_IPV4_G->chrc_soa_dl_riface ),
             sizeof(dss_tun_send_garp.chrc_h_macaddr_source) );
     memcpy( dss_tun_send_garp.chrc_pl_macaddr_source,  /* Sender hardware address (SHA) */
             LLADDR( (struct sockaddr_dl *) ADSL_QUERY_AR_ADD_IPV4_G->chrc_soa_dl_riface ),
             sizeof(dss_tun_send_garp.chrc_pl_macaddr_source) );
     *((UNSIG_MED *) &dss_tun_send_garp.chrc_pl_ineta_source)  /* Sender protocol address (SPA) */
       = *((UNSIG_MED *) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta);
     *((UNSIG_MED *) &dss_tun_send_garp.chrc_pl_ineta_target)  /* Target protocol address (TPA) */
       = *((UNSIG_MED *) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta);
//#ifdef TRACEHL1
     m_console_out( (char *) &dss_tun_send_garp, sizeof(struct dsd_tun_send_garp) );
//#endif
     iml_rc = write( iml_bpf_fd, (char *) &dss_tun_send_garp, sizeof(struct dsd_tun_send_garp) );
//#ifdef TRACEHL1
     m_hl1_printf( "nbipgw19-l%05d-T write() GARP returned %d errno %d.",
                     __LINE__, iml_rc, errno );
//#endif
   }
   /*
     set route
     sample: route add -host 172.22.81.221/32 -iface tunX
   */
#define LEN_SOA_MASK 8
#define IML_MSG_LEN (sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in) + ((sizeof(struct sockaddr_dl) + sizeof(int) - 1) & (0 - sizeof(int))) + LEN_SOA_MASK)
#define IML_MSG_SEQU 1
   memset( &dsl_m_rtmsg, 0, IML_MSG_LEN );
   ADSL_RTM_G->rtm_msglen = IML_MSG_LEN;    /* to skip over non-understood messages */
   ADSL_RTM_G->rtm_version = RTM_VERSION;
   ADSL_RTM_G->rtm_type = RTM_ADD;          /* message type            */
   ADSL_RTM_G->rtm_flags = RTF_UP | RTF_HOST | RTF_STATIC;
   ADSL_RTM_G->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
   ADSL_RTM_G->rtm_seq = IML_MSG_SEQU;
#define ADSL_SOA_DST ((struct sockaddr_in *) dsl_m_rtmsg.byrc_m_space)
   ((struct sockaddr *) ADSL_SOA_DST)->sa_len = sizeof(struct sockaddr_in);  /* total length */
   ((struct sockaddr *) ADSL_SOA_DST)->sa_family = AF_INET;
   *((UNSIG_MED *) &ADSL_SOA_DST->sin_addr)
     = *((UNSIG_MED *) ADSL_QUERY_AR_ADD_IPV4_G->chrc_ineta);
#define ADSL_SDL_G ((struct sockaddr_dl *) (dsl_m_rtmsg.byrc_m_space + sizeof(struct sockaddr_in)))
   memcpy( ADSL_SDL_G, ADSL_QUERY_AR_ADD_IPV4_G->chrc_soa_dl_tiface, sizeof(struct sockaddr_dl) );
#define ADSL_SOA_MASK ((struct sockaddr_in *) ((char *) &dsl_m_rtmsg + sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in) + ((sizeof(struct sockaddr_dl) + sizeof(int) - 1) & (0 - sizeof(int)))))
   memset( ADSL_SOA_MASK, 0, LEN_SOA_MASK );
   ((struct sockaddr *) ADSL_SOA_MASK)->sa_len = LEN_SOA_MASK;
   *((UNSIG_MED *) &ADSL_SOA_MASK->sin_addr) = 0XFFFFFFFF;

   m_console_out( (char *) &dsl_m_rtmsg, IML_MSG_LEN );
   iml_rc = write( ims_route_socket,
                   (char *) &dsl_m_rtmsg, IML_MSG_LEN );

//#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T write() route returned %d errno %d.",
                 __LINE__, iml_rc, errno );
//#endif
//#undef ADSL_SOA_GATEWAY
#undef ADSL_SOA_DST
#undef ADSL_SDL_G
#undef IML_MSG_LEN
#undef IML_MSG_SEQU
#undef LEN_SOA_MASK
#undef ADSL_RTM_G
#endif
   dsrl_gai1_out1[ 0 ].adsc_next = &dsrl_gai1_out1[ 1 ];
   dsrl_gai1_out1[ 0 ].achc_ginp_cur = chrs_requestheader_response;
   dsrl_gai1_out1[ 0 ].achc_ginp_end = chrs_requestheader_response + sizeof(chrs_requestheader_response);
   dsrl_gai1_out1[ 1 ].adsc_next = NULL;
   dsrl_gai1_out1[ 1 ].achc_ginp_cur = (char *) ucrs_resp_ar_add_ipv4;
   dsrl_gai1_out1[ 1 ].achc_ginp_end = (char *) ucrs_resp_ar_add_ipv4 + sizeof(ucrs_resp_ar_add_ipv4);
   iml_rc = adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_send_gather( dsrl_gai1_out1, NULL );
   if (ilrs_param_01[ PA_01_TRACE ] >= 4) {
     m_hl1_printf( "nbipgw19-l%05d-W sent data to wsp-conn=%p imc_rc=%d.",
                   __LINE__, adsl_wsp_conn_w1, iml_rc );
   }
   goto p_record_80;                        /* the record has been processed */
#undef ADSL_QUERY_AR_ADD_IPV4_G

   p_rec_ar_del_ipv4:                       /* received del AR IPV4    */
#define ADSL_QUERY_AR_DEL_IPV4_G ((struct dsd_ligw_q_ar_del_ipv4 *) (ACHL_INPUT_STA + 1))  /* del ARP and route IPV4 */
#ifdef CONTROL_INETAS
   dsl_ci_ipv4_l.adsc_wsp_conn = adsl_wsp_conn_w1;  /* connection to a WSP */
   memcpy( dsl_ci_ipv4_l.dsc_ar_ipv4.chrc_ineta, ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta, sizeof(UNSIG_MED) );
   bol_rc = m_htree1_avl_search( NULL, &dss_htree1_avl_control_ineta_ipv4,
                                 &dsl_htree1_work, &dsl_ci_ipv4_l.dsc_sort_1 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W m_tccb_wsp_recvcallback() m_htree1_avl_search() old element failed",
                   __LINE__ );
     dsl_htree1_work.adsc_found = NULL;     /* not found in tree       */
   }
#define ADSL_CI_IPV4_G ((struct dsd_control_ineta_ipv4 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_control_ineta_ipv4, dsc_sort_1 )))
   if (dsl_htree1_work.adsc_found) {        /* found in tree           */
     adsl_ci_ipv4_w1 = ADSL_CI_IPV4_G;      /* save memory found       */
     bol_rc = m_htree1_avl_delete( NULL, &dss_htree1_avl_control_ineta_ipv4,
                                   &dsl_htree1_work );
     if (bol_rc == FALSE) {                   /* error occured           */
       m_hl1_printf( "nbipgw19-l%05d-W m_tccb_wsp_recvcallback() m_htree1_avl_delete() old element failed",
                     __LINE__ );
     }
     /* this is now a free element                                     */
     adsl_ci_ipv4_w1->adsc_next = adss_ci_ipv4_free_ch;  /* get old chain of free structure to control INETAs IPV4 */
     adss_ci_ipv4_free_ch = adsl_ci_ipv4_w1;  /* set new chain of free structure to control INETAs IPV4 */
   }
#undef ADSL_CI_IPV4_G
#endif
#ifdef HL_LINUX
   memset( &dsl_arpreq, 0, sizeof(struct arpreq) );  /* struct for arp requests */
#define ADSL_SOCKADDR_ARP ((struct sockaddr_in *) &dsl_arpreq.arp_pa)
   ADSL_SOCKADDR_ARP->sin_family = AF_INET;
   memcpy( &ADSL_SOCKADDR_ARP->sin_addr, ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta, sizeof(UNSIG_MED) );
#undef ADSL_SOCKADDR_ARP
   memcpy( &dsl_arpreq.arp_ha, &ADSL_QUERY_AR_DEL_IPV4_G->dsc_rhwaddr, sizeof(struct sockaddr) );
   dsl_arpreq.arp_flags = ATF_PUBL | ATF_NETMASK;
   memcpy( dsl_arpreq.arp_dev, ADSL_QUERY_AR_DEL_IPV4_G->chrc_riface, IFNAMSIZ );
#define ADSL_SOCKADDR_NETMASK ((struct sockaddr_in *) &dsl_arpreq.arp_netmask)
   ADSL_SOCKADDR_NETMASK->sin_family = AF_INET;
   *((UNSIG_MED *) &ADSL_SOCKADDR_NETMASK->sin_addr) = 0XFFFFFFFF;  /* 255.255.255.255 */
#undef ADSL_SOCKADDR_NETMASK
   iml_rc = ioctl( ims_tun_socket, SIOCDARP, &dsl_arpreq );
#ifdef TRACEHL1
   iml_error = errno;                       /* error retrieved         */
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_recvcallback() p_rec_ar_del_ipv4: ioctl( ... , SIOCDARP , ... ) returned %d errno %d.",
                 __LINE__, iml_rc, errno );
   errno = iml_error;                       /* error retrieved         */
#endif
   if (iml_rc < 0) {                        /* error occured           */
     iml_error = errno;                     /* error retrieved         */
     m_hl1_printf( "nbipgw19-l%05d-W p_rec_ar_del_ipv4: INETA=%d.%d.%d.%d ioctl( ... , SIOCDARP , ... ) returned %d errno %d.",
                   __LINE__,
                   (unsigned char) ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta[ 0 ],
                   (unsigned char) ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta[ 1 ],
                   (unsigned char) ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta[ 2 ],
                   (unsigned char) ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta[ 3 ],
                   iml_rc, iml_error );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W p_rec_ar_del_ipv4: INETA=%d.%d.%d.%d ioctl( ... , SIOCDARP , ... ) returned %d errno %d.",
                     __LINE__,
                     (unsigned char) ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta[ 0 ],
                     (unsigned char) ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta[ 1 ],
                     (unsigned char) ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta[ 2 ],
                     (unsigned char) ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta[ 3 ],
                     iml_rc, iml_error );
   }
   memset( &dsl_routereq, 0, sizeof(struct rtentry) );  /* struct for route request */
#define ADSL_SOCKADDR_DST ((struct sockaddr_in *) &dsl_routereq.rt_dst)
   ADSL_SOCKADDR_DST->sin_family = AF_INET;
   memcpy( &ADSL_SOCKADDR_DST->sin_addr, ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta, sizeof(UNSIG_MED) );
#undef ADSL_SOCKADDR_DST
   dsl_routereq.rt_metric = 31;
   dsl_routereq.rt_dev = ADSL_QUERY_AR_DEL_IPV4_G->chrc_tiface;
#define ADSL_RT_MASK ((struct sockaddr_in *) &dsl_routereq.rt_genmask)
   /* set netmask to 255.255.255.255                                   */
   ADSL_RT_MASK->sin_family      = AF_INET;
   ADSL_RT_MASK->sin_addr.s_addr = 0XFFFFFFFF;
#undef ADSL_RT_MASK
   iml_rc = ioctl( ims_tun_socket, SIOCDELRT, &dsl_routereq );
#ifdef TRACEHL1
   iml_error = errno;                       /* error retrieved         */
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_recvcallback() p_rec_ar_del_ipv4: ioctl( ... , SIOCDELRT , ... ) returned %d errno %d.",
                 __LINE__, iml_rc, errno );
   errno = iml_error;                       /* error retrieved         */
#endif
   if (iml_rc < 0) {                        /* error occured           */
     iml_error = errno;                     /* error retrieved         */
     m_hl1_printf( "nbipgw19-l%05d-W p_rec_ar_del_ipv4: INETA=%d.%d.%d.%d ioctl( ... , SIOCDELRT , ... ) returned %d errno %d.",
                   __LINE__,
                   (unsigned char) ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta[ 0 ],
                   (unsigned char) ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta[ 1 ],
                   (unsigned char) ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta[ 2 ],
                   (unsigned char) ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta[ 3 ],
                   iml_rc, iml_error );
     m_wsp_send_msg( adsl_wsp_conn_w1,
                     "nbipgw19-l%05d-W p_rec_ar_del_ipv4: INETA=%d.%d.%d.%d ioctl( ... , SIOCDELRT , ... ) returned %d errno %d.",
                     __LINE__,
                     (unsigned char) ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta[ 0 ],
                     (unsigned char) ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta[ 1 ],
                     (unsigned char) ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta[ 2 ],
                     (unsigned char) ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta[ 3 ],
                     iml_rc, iml_error );
   }
#endif
#ifdef HL_FREEBSD
   /*
     delete ARP entry
     sample: arp -d 172.22.81.221
   */
#define ADSL_RTM_G (&dsl_m_rtmsg.dsc_m_rtm)
#define LEN_SOA_MASK 8
#define IML_MSG_LEN (sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in) + ((sizeof(struct sockaddr_dl) + sizeof(int) - 1) & (0 - sizeof(int))) + LEN_SOA_MASK)
#define IML_MSG_SEQU 1
   memset( &dsl_m_rtmsg, 0, IML_MSG_LEN );
   ADSL_RTM_G->rtm_msglen = IML_MSG_LEN;
   ADSL_RTM_G->rtm_version = RTM_VERSION;
   ADSL_RTM_G->rtm_type = RTM_DELETE;
// ADSL_RTM_G->rtm_inits = RTV_EXPIRE;
   ADSL_RTM_G->rtm_flags = RTF_UP | RTF_DONE | RTF_LLDATA | RTF_PINNED;
   ADSL_RTM_G->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
   ADSL_RTM_G->rtm_pid = ims_this_pid;      /* set process id          */
   ADSL_RTM_G->rtm_seq = IML_MSG_SEQU;
#define ADSL_SOA_DST ((struct sockaddr_in *) dsl_m_rtmsg.byrc_m_space)
   ((struct sockaddr *) ADSL_SOA_DST)->sa_len = sizeof(struct sockaddr_in);  /* total length */
   ((struct sockaddr *) ADSL_SOA_DST)->sa_family = AF_INET;
   *((UNSIG_MED *) &ADSL_SOA_DST->sin_addr)
     = *((UNSIG_MED *) ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta);
#define ADSL_SDL_G ((struct sockaddr_dl *) (dsl_m_rtmsg.byrc_m_space + sizeof(struct sockaddr_in)))
   memcpy( ADSL_SDL_G, ADSL_QUERY_AR_DEL_IPV4_G->chrc_soa_dl_riface, sizeof(struct sockaddr_dl) );
#define ADSL_SOA_MASK ((struct sockaddr_in *) ((char *) &dsl_m_rtmsg + sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in) + ((sizeof(struct sockaddr_dl) + sizeof(int) - 1) & (0 - sizeof(int)))))
   memset( ADSL_SOA_MASK, 0, LEN_SOA_MASK );
   *((unsigned char *) ADSL_SOA_MASK) = 6;
   memset( (char *) ADSL_SOA_MASK + 1, 0XFF, 5 );

   m_console_out( (char *) &dsl_m_rtmsg,
                  IML_MSG_LEN );
   iml_rc = write( ims_route_socket,
                   (char *) &dsl_m_rtmsg,
                   IML_MSG_LEN );

//#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T write() ARP returned %d errno %d.",
                 __LINE__, iml_rc, errno );
//#endif
   while (TRUE) {
     iml_rc = read( ims_route_socket,
                    (char *) &dsl_m_rtmsg,
                    sizeof(dsl_m_rtmsg) );
//#ifdef TRACEHL1
     m_hl1_printf( "nbipgw19-l%05d-T read() ARP returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
     if (iml_rc > 0) {
       m_console_out( (char *) &dsl_m_rtmsg, iml_rc );
     }
     if (iml_rc < 0) {
       break;
     }
     if (   (ADSL_RTM_G->rtm_pid == ims_this_pid)  /* compare process id */
         && (ADSL_RTM_G->rtm_seq == IML_MSG_SEQU)) {
       break;
     }
   }
#undef ADSL_SDL_G
#undef ADSL_SOA_DST
#undef ADSL_SOA_MASK
#undef IML_MSG_LEN
#undef IML_MSG_SEQU
#undef LEN_SOA_MASK
   /*
     delete route
     sample: route del -host 172.22.81.221/32
   */
#define LEN_SOA_MASK 8
#define IML_MSG_LEN (sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in) + LEN_SOA_MASK)
#define IML_MSG_SEQU 1
   memset( &dsl_m_rtmsg, 0, IML_MSG_LEN );
   ADSL_RTM_G->rtm_msglen = IML_MSG_LEN;    /* to skip over non-understood messages */
   ADSL_RTM_G->rtm_version = RTM_VERSION;
   ADSL_RTM_G->rtm_type = RTM_DELETE;
   ADSL_RTM_G->rtm_flags = RTF_UP | RTF_GATEWAY | RTF_HOST | RTF_STATIC;
   ADSL_RTM_G->rtm_addrs = RTA_DST | RTA_NETMASK;
   ADSL_RTM_G->rtm_seq = IML_MSG_SEQU;
#define ADSL_SOA_DST ((struct sockaddr_in *) dsl_m_rtmsg.byrc_m_space)
   ((struct sockaddr *) ADSL_SOA_DST)->sa_len = sizeof(struct sockaddr_in);  /* total length */
   ((struct sockaddr *) ADSL_SOA_DST)->sa_family = AF_INET;
   *((UNSIG_MED *) &ADSL_SOA_DST->sin_addr)
     = *((UNSIG_MED *) ADSL_QUERY_AR_DEL_IPV4_G->chrc_ineta);
#define ADSL_SOA_MASK ((struct sockaddr_in *) ((char *) &dsl_m_rtmsg + sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in)))
   memset( ADSL_SOA_MASK, 0, LEN_SOA_MASK );
   ((struct sockaddr *) ADSL_SOA_MASK)->sa_len = LEN_SOA_MASK;
   *((UNSIG_MED *) &ADSL_SOA_MASK->sin_addr) = 0XFFFFFFFF;

   m_console_out( (char *) &dsl_m_rtmsg, IML_MSG_LEN );
   iml_rc = write( ims_route_socket,
                   (char *) &dsl_m_rtmsg, IML_MSG_LEN );

//#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T write() route returned %d errno %d.",
                 __LINE__, iml_rc, errno );
//#endif
//#undef ADSL_SOA_GATEWAY
#undef ADSL_SOA_DST
#undef ADSL_SOA_MASK
#undef IML_MSG_LEN
#undef IML_MSG_SEQU
#undef LEN_SOA_MASK
#undef ADSL_RTM_G
#endif
   dsrl_gai1_out1[ 0 ].adsc_next = &dsrl_gai1_out1[ 1 ];
   dsrl_gai1_out1[ 0 ].achc_ginp_cur = chrs_requestheader_response;
   dsrl_gai1_out1[ 0 ].achc_ginp_end = chrs_requestheader_response + sizeof(chrs_requestheader_response);
   dsrl_gai1_out1[ 1 ].adsc_next = NULL;
   dsrl_gai1_out1[ 1 ].achc_ginp_cur = (char *) ucrs_resp_ar_del_ipv4;
   dsrl_gai1_out1[ 1 ].achc_ginp_end = (char *) ucrs_resp_ar_del_ipv4 + sizeof(ucrs_resp_ar_del_ipv4);
   iml_rc = adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_send_gather( dsrl_gai1_out1, NULL );
   if (ilrs_param_01[ PA_01_TRACE ] >= 4) {
     m_hl1_printf( "nbipgw19-l%05d-W sent data to wsp-conn=%p imc_rc=%d.",
                   __LINE__, adsl_wsp_conn_w1, iml_rc );
   }
#undef ADSL_QUERY_AR_DEL_IPV4_G
#endif

   p_record_80:                             /* the record has been processed */
   if (adsl_wsp_conn_w1->dsc_connect.adsc_rec1_ch) {  /* check chain received data */
     goto p_recv_sc_00;                     /* we have input           */
   }
   return TRUE;                             /* continue receiving      */

#undef ACHL_INPUT_STA
#undef ACHL_INPUT_END

} /* end m_tccb_wsp_recvcallback()                                     */

/** TCPCOMP WSP error callback function                                */
static void m_tccb_wsp_errorcallback( class dsd_tcpcomp *adsp_tcpcomp, void * vpp_userfld, char *, int, int ) {
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_errorcallback() called",
                 __LINE__ );
} /* end m_tccb_wsp_errorcallback()                                    */

/* TCPCOMP WSP cleanup callback function                               */
static void m_tccb_wsp_cleanup( class dsd_tcpcomp *adsp_tcpcomp, void * vpp_userfld ) {
#ifdef D_INCL_HOB_TUN
#ifdef CONTROL_INETAS
   BOOL       bol_rc;                       /* return code             */
   int        iml_rc;                       /* return code             */
#ifdef TRACEHL1
   int        iml_error;                    /* error retrieved         */
#endif
#endif
#endif
   int        iml1;                         /* working variable        */
   char       *achl1;                       /* working variable        */
   struct dsd_wsp_conn *adsl_wsp_conn_w1;   /* connection to a WSP     */
   struct dsd_wsp_conn *adsl_wsp_conn_w2;   /* connection to a WSP     */
   struct dsd_receive_1 *adsl_rec1_w1;      /* area for receive        */
#ifdef D_INCL_HOB_TUN
#ifdef CONTROL_INETAS
   struct dsd_control_ineta_ipv4 *adsl_ci_ipv4_w1;  /* structure to control INETAs IPV4 */
#ifdef HL_LINUX
   union {
     struct arpreq dsl_arpreq;              /* struct for arp requests */
     struct rtentry dsl_routereq;           /* struct for route request */
   };
#endif
#ifdef HL_FREEBSD
   struct {
     struct rt_msghdr dsc_m_rtm;
     char     byrc_m_space[512];
   } dsl_m_rtmsg;
#endif
   struct dsd_control_ineta_ipv4 dsl_ci_ipv4_l;  /* structure to control INETAs IPV4 */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
#endif
#endif
   char       chrl_work1[ 32 ];             /* work area               */

#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_cleanup( adsp_tcpcomp=%p , vpp_userfld=%p ) called",
                 __LINE__, adsp_tcpcomp, vpp_userfld );
#endif
   adsl_wsp_conn_w1 = (struct dsd_wsp_conn *) vpp_userfld;  /* connection to a WSP */
   achl1 = "";                              /* empty string            */
   if (adsl_wsp_conn_w1->boc_first_message) {  /* first message has arrived */
     sprintf( chrl_work1, "process id (PID) %d ",
              adsl_wsp_conn_w1->imc_pid );  /* process id              */
     achl1 = chrl_work1;                    /* display as part of message */
   }
   m_hl1_printf( "nbipgw19-l%05d-I connection to WSP %sended",
                 __LINE__, achl1 );
   while (adsl_wsp_conn_w1->dsc_connect.adsc_rec1_ch) {  /* loop over chain received data */
     adsl_rec1_w1 = adsl_wsp_conn_w1->dsc_connect.adsc_rec1_ch;  /* get chain received data */
     adsl_wsp_conn_w1->dsc_connect.adsc_rec1_ch = adsl_rec1_w1->adsc_next;  /* remove from chain */
     m_proc_free( adsl_rec1_w1 );           /* free receive block      */
   }
   if (adsl_wsp_conn_w1->imc_len_cluster) {  /* length cluster entry   */
     free( adsl_wsp_conn_w1->achc_cluster );  /* free cluster entry    */
   }
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_cleanup() adsl_wsp_conn_w1=%p ->imc_no_clli=%d.",
                 __LINE__, adsl_wsp_conn_w1, adsl_wsp_conn_w1->imc_no_clli );
#endif
   iml1 = 0;                                /* clear index             */
   while (iml1 < adsl_wsp_conn_w1->imc_no_clli) {  /* loop over all listen */
     m_cluster_listen_close( adsl_wsp_conn_w1->adsrc_clli[ iml1 ] );
     iml1++;                                /* increment index         */
   }
#ifdef D_INCL_HOB_TUN
#ifdef CONTROL_INETAS
   memset( &dsl_ci_ipv4_l, 0, sizeof(struct dsd_control_ineta_ipv4) );  /* structure to control INETAs IPV4 */
   dsl_ci_ipv4_l.adsc_wsp_conn = adsl_wsp_conn_w1;  /* connection to a WSP */
   bol_rc = m_htree1_avl_search( NULL, &dss_htree1_avl_control_ineta_ipv4,
                                 &dsl_htree1_work, &dsl_ci_ipv4_l.dsc_sort_1 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W m_tccb_wsp_cleanup() m_htree1_avl_search() old elements failed",
                   __LINE__ );
     dsl_htree1_work.adsc_found = NULL;     /* not found in tree       */
   }
   iml1 = 0;                                /* clear count             */
#define ADSL_CI_IPV4_G ((struct dsd_control_ineta_ipv4 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_control_ineta_ipv4, dsc_sort_1 )))
   if (dsl_htree1_work.adsc_found == NULL) {  /* not found in tree     */
     goto p_contr_ineta_ipv4_40;            /* search next element in AVL-tree */
   }

   p_contr_ineta_ipv4_20:                   /* INETA found             */
   if (ADSL_CI_IPV4_G->adsc_wsp_conn != adsl_wsp_conn_w1) {  /* connection to a WSP */
     goto p_contr_ineta_ipv4_80;            /* end of removing set INETAs */
   }

#ifdef HL_LINUX
   memset( &dsl_arpreq, 0, sizeof(struct arpreq) );  /* struct for arp requests */
#define ADSL_SOCKADDR_ARP ((struct sockaddr_in *) &dsl_arpreq.arp_pa)
   ADSL_SOCKADDR_ARP->sin_family = AF_INET;
   memcpy( &ADSL_SOCKADDR_ARP->sin_addr, ADSL_CI_IPV4_G->dsc_ar_ipv4.chrc_ineta, sizeof(UNSIG_MED) );
#undef ADSL_SOCKADDR_ARP
   memcpy( &dsl_arpreq.arp_ha, &ADSL_CI_IPV4_G->dsc_ar_ipv4.dsc_rhwaddr, sizeof(struct sockaddr) );
   dsl_arpreq.arp_flags = ATF_PUBL | ATF_NETMASK;
   memcpy( dsl_arpreq.arp_dev, ADSL_CI_IPV4_G->dsc_ar_ipv4.chrc_riface, IFNAMSIZ );
#define ADSL_SOCKADDR_NETMASK ((struct sockaddr_in *) &dsl_arpreq.arp_netmask)
   ADSL_SOCKADDR_NETMASK->sin_family = AF_INET;
   *((UNSIG_MED *) &ADSL_SOCKADDR_NETMASK->sin_addr) = 0XFFFFFFFF;  /* 255.255.255.255 */
#undef ADSL_SOCKADDR_NETMASK
   iml_rc = ioctl( ims_tun_socket, SIOCDARP, &dsl_arpreq );
#ifdef TRACEHL1
   iml_error = errno;                       /* error retrieved         */
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_cleanup() remove old ARP and route: ioctl( ... , SIOCDARP , ... ) returned %d errno %d.",
                 __LINE__, iml_rc, errno );
   errno = iml_error;                       /* error retrieved         */
#endif
   if (iml_rc < 0) {                        /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W remove old ARP and route: INETA=%d.%d.%d.%d ioctl( ... , SIOCDARP , ... ) returned %d errno %d.",
                   __LINE__,
                   (unsigned char) ADSL_CI_IPV4_G->dsc_ar_ipv4.chrc_ineta[ 0 ],
                   (unsigned char) ADSL_CI_IPV4_G->dsc_ar_ipv4.chrc_ineta[ 1 ],
                   (unsigned char) ADSL_CI_IPV4_G->dsc_ar_ipv4.chrc_ineta[ 2 ],
                   (unsigned char) ADSL_CI_IPV4_G->dsc_ar_ipv4.chrc_ineta[ 3 ],
                   iml_rc, errno );
   }
   memset( &dsl_routereq, 0, sizeof(struct rtentry) );  /* struct for route request */
#define ADSL_SOCKADDR_DST ((struct sockaddr_in *) &dsl_routereq.rt_dst)
   ADSL_SOCKADDR_DST->sin_family = AF_INET;
   memcpy( &ADSL_SOCKADDR_DST->sin_addr, ADSL_CI_IPV4_G->dsc_ar_ipv4.chrc_ineta, sizeof(UNSIG_MED) );
#undef ADSL_SOCKADDR_DST
   dsl_routereq.rt_metric = 31;
   dsl_routereq.rt_dev = ADSL_CI_IPV4_G->dsc_ar_ipv4.chrc_tiface;
#define ADSL_RT_MASK ((struct sockaddr_in *) &dsl_routereq.rt_genmask)
   /* set netmask to 255.255.255.255                                   */
   ADSL_RT_MASK->sin_family      = AF_INET;
   ADSL_RT_MASK->sin_addr.s_addr = 0XFFFFFFFF;
#undef ADSL_RT_MASK
   iml_rc = ioctl( ims_tun_socket, SIOCDELRT, &dsl_routereq );
#ifdef TRACEHL1
   iml_error = errno;                       /* error retrieved         */
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_cleanup() remove old ARP and route: ioctl( ... , SIOCDELRT , ... ) returned %d errno %d.",
                 __LINE__, iml_rc, errno );
   errno = iml_error;                       /* error retrieved         */
#endif
   if (iml_rc < 0) {                        /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W remove old ARP and route: INETA=%d.%d.%d.%d ioctl( ... , SIOCDELRT , ... ) returned %d errno %d.",
                   __LINE__,
                   (unsigned char) ADSL_CI_IPV4_G->dsc_ar_ipv4.chrc_ineta[ 0 ],
                   (unsigned char) ADSL_CI_IPV4_G->dsc_ar_ipv4.chrc_ineta[ 1 ],
                   (unsigned char) ADSL_CI_IPV4_G->dsc_ar_ipv4.chrc_ineta[ 2 ],
                   (unsigned char) ADSL_CI_IPV4_G->dsc_ar_ipv4.chrc_ineta[ 3 ],
                   iml_rc, errno );
   }
#endif
#ifdef HL_FREEBSD
   /*
     delete ARP entry
     sample: arp -d 172.22.81.221
   */
#define ADSL_RTM_G (&dsl_m_rtmsg.dsc_m_rtm)
#define LEN_SOA_MASK 8
#define IML_MSG_LEN (sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in) + ((sizeof(struct sockaddr_dl) + sizeof(int) - 1) & (0 - sizeof(int))) + LEN_SOA_MASK)
#define IML_MSG_SEQU 1
   memset( &dsl_m_rtmsg, 0, IML_MSG_LEN );
   ADSL_RTM_G->rtm_msglen = IML_MSG_LEN;
   ADSL_RTM_G->rtm_version = RTM_VERSION;
   ADSL_RTM_G->rtm_type = RTM_DELETE;
// ADSL_RTM_G->rtm_inits = RTV_EXPIRE;
   ADSL_RTM_G->rtm_flags = RTF_UP | RTF_DONE | RTF_LLDATA | RTF_PINNED;
   ADSL_RTM_G->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
   ADSL_RTM_G->rtm_pid = ims_this_pid;      /* set process id          */
   ADSL_RTM_G->rtm_seq = IML_MSG_SEQU;
#define ADSL_SOA_DST ((struct sockaddr_in *) dsl_m_rtmsg.byrc_m_space)
   ((struct sockaddr *) ADSL_SOA_DST)->sa_len = sizeof(struct sockaddr_in);  /* total length */
   ((struct sockaddr *) ADSL_SOA_DST)->sa_family = AF_INET;
   *((UNSIG_MED *) &ADSL_SOA_DST->sin_addr)
     = *((UNSIG_MED *) ADSL_CI_IPV4_G->dsc_ar_ipv4.chrc_ineta);
#define ADSL_SDL_G ((struct sockaddr_dl *) (dsl_m_rtmsg.byrc_m_space + sizeof(struct sockaddr_in)))
   memcpy( ADSL_SDL_G, ADSL_CI_IPV4_G->dsc_ar_ipv4.chrc_soa_dl_riface, sizeof(struct sockaddr_dl) );
#define ADSL_SOA_MASK ((struct sockaddr_in *) ((char *) &dsl_m_rtmsg + sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in) + ((sizeof(struct sockaddr_dl) + sizeof(int) - 1) & (0 - sizeof(int)))))
   memset( ADSL_SOA_MASK, 0, LEN_SOA_MASK );
   *((unsigned char *) ADSL_SOA_MASK) = 6;
   memset( (char *) ADSL_SOA_MASK + 1, 0XFF, 5 );

   m_console_out( (char *) &dsl_m_rtmsg,
                  IML_MSG_LEN );
   iml_rc = write( ims_route_socket,
                   (char *) &dsl_m_rtmsg,
                   IML_MSG_LEN );

//#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T write() ARP returned %d errno %d.",
                 __LINE__, iml_rc, errno );
//#endif
   while (TRUE) {
     iml_rc = read( ims_route_socket,
                    (char *) &dsl_m_rtmsg,
                    sizeof(dsl_m_rtmsg) );
//#ifdef TRACEHL1
     m_hl1_printf( "nbipgw19-l%05d-T read() ARP returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
     if (iml_rc > 0) {
       m_console_out( (char *) &dsl_m_rtmsg, iml_rc );
     }
     if (iml_rc < 0) {
       break;
     }
     if (   (ADSL_RTM_G->rtm_pid == ims_this_pid)  /* compare process id */
         && (ADSL_RTM_G->rtm_seq == IML_MSG_SEQU)) {
       break;
     }
   }
#undef ADSL_SDL_G
#undef ADSL_SOA_DST
#undef ADSL_SOA_MASK
#undef IML_MSG_LEN
#undef IML_MSG_SEQU
#undef LEN_SOA_MASK
   /*
     delete route
     sample: route del -host 172.22.81.221/32
   */
#define LEN_SOA_MASK 8
#define IML_MSG_LEN (sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in) + LEN_SOA_MASK)
#define IML_MSG_SEQU 1
   memset( &dsl_m_rtmsg, 0, IML_MSG_LEN );
   ADSL_RTM_G->rtm_msglen = IML_MSG_LEN;    /* to skip over non-understood messages */
   ADSL_RTM_G->rtm_version = RTM_VERSION;
   ADSL_RTM_G->rtm_type = RTM_DELETE;
   ADSL_RTM_G->rtm_flags = RTF_UP | RTF_GATEWAY | RTF_HOST | RTF_STATIC;
   ADSL_RTM_G->rtm_addrs = RTA_DST | RTA_NETMASK;
   ADSL_RTM_G->rtm_seq = IML_MSG_SEQU;
#define ADSL_SOA_DST ((struct sockaddr_in *) dsl_m_rtmsg.byrc_m_space)
   ((struct sockaddr *) ADSL_SOA_DST)->sa_len = sizeof(struct sockaddr_in);  /* total length */
   ((struct sockaddr *) ADSL_SOA_DST)->sa_family = AF_INET;
   *((UNSIG_MED *) &ADSL_SOA_DST->sin_addr)
     = *((UNSIG_MED *) ADSL_CI_IPV4_G->dsc_ar_ipv4.chrc_ineta);
#define ADSL_SOA_MASK ((struct sockaddr_in *) ((char *) &dsl_m_rtmsg + sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in)))
   memset( ADSL_SOA_MASK, 0, LEN_SOA_MASK );
   ((struct sockaddr *) ADSL_SOA_MASK)->sa_len = LEN_SOA_MASK;
   *((UNSIG_MED *) &ADSL_SOA_MASK->sin_addr) = 0XFFFFFFFF;

   m_console_out( (char *) &dsl_m_rtmsg, IML_MSG_LEN );
   iml_rc = write( ims_route_socket,
                   (char *) &dsl_m_rtmsg, IML_MSG_LEN );

//#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T write() route returned %d errno %d.",
                 __LINE__, iml_rc, errno );
//#endif
//#undef ADSL_SOA_GATEWAY
#undef ADSL_SOA_DST
#undef ADSL_SOA_MASK
#undef IML_MSG_LEN
#undef IML_MSG_SEQU
#undef LEN_SOA_MASK
#undef ADSL_RTM_G
#endif

   adsl_ci_ipv4_w1 = ADSL_CI_IPV4_G;        /* save memory found       */
   bol_rc = m_htree1_avl_delete( NULL, &dss_htree1_avl_control_ineta_ipv4,
                                 &dsl_htree1_work );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W m_tccb_wsp_cleanup() m_htree1_avl_delete() old element failed",
                   __LINE__ );
   }

   /* this is now a free element                                       */
   adsl_ci_ipv4_w1->adsc_next = adss_ci_ipv4_free_ch;  /* get old chain of free structure to control INETAs IPV4 */
   adss_ci_ipv4_free_ch = adsl_ci_ipv4_w1;  /* set new chain of free structure to control INETAs IPV4 */

#undef ADSL_CI_IPV4_G

   iml1++;                                  /* increment count         */

   p_contr_ineta_ipv4_40:                   /* search next element in AVL-tree */
   bol_rc = m_htree1_avl_getnext( NULL, &dss_htree1_avl_control_ineta_ipv4,
                                  &dsl_htree1_work, FALSE );
   if (bol_rc == FALSE) {                 /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W m_tccb_wsp_cleanup() m_htree1_avl_getnext() old element failed",
                   __LINE__ );
     dsl_htree1_work.adsc_found = NULL;     /* not found in tree       */
   }
   if (dsl_htree1_work.adsc_found) {        /* found in tree           */
     goto p_contr_ineta_ipv4_20;            /* INETA found             */
   }

   p_contr_ineta_ipv4_80:                   /* end of removing set INETAs */
   if (iml1 > 0) {                          /* entries deleted         */
     m_hl1_printf( "nbipgw19-l%05d-I %d. entries for ARP and routes deleted",
                   __LINE__, iml1 );
   }
#endif
#endif
   if (adsl_wsp_conn_w1 == adss_wsp_conn_chain) {  /* first in chain connections to WSPs */
     adss_wsp_conn_chain = adsl_wsp_conn_w1->adsc_next;  /* remove from chain connections to WSPs */
   } else {                                 /* middle in chain         */
     adsl_wsp_conn_w2 = adss_wsp_conn_chain;  /* get chain connections to WSPs */
     while (TRUE) {                         /* loop over all connected WSPs */
       if (adsl_wsp_conn_w2->adsc_next == adsl_wsp_conn_w1) {  /* entry found */
         adsl_wsp_conn_w2->adsc_next = adsl_wsp_conn_w1->adsc_next;  /* remove from chain connections to WSPs */
         break;
       }
       adsl_wsp_conn_w2 = adsl_wsp_conn_w2->adsc_next;  /* get next in chain */
       if (adsl_wsp_conn_w2 == NULL) {      /* end of chain            */
         m_hl1_printf( "nbipgw19-l%05d-W m_tccb_wsp_cleanup() chain of connected WSPs corrupted",
                       __LINE__ );
         break;
       }
     }
   }
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_wsp_cleanup() free %p.",
                 __LINE__, adsl_wsp_conn_w1 );
#endif
   free( adsl_wsp_conn_w1 );                /* free memory of connected WSP */
} /* end m_tccb_wsp_cleanup()                                          */

/** TCPCOMP cluster send callback function                             */
static void m_tccb_cluster_sendcallback( class dsd_tcpcomp *adsp_tcpcomp, void * vpp_userfld ) {
   struct dsd_connect *adsl_conn_1;         /* connection              */

   m_hl1_printf( "nbipgw19-%05d-T m_tccb_cluster_sendcallback() called",
                 __LINE__ );
#ifdef XYZ1
   adsl_conn_1 = (struct dsd_connect *) vpp_userfld;  /* connection    */
   adsl_conn_1->dsc_tcpco1.m_send_gather( adsl_conn_1->adsc_gai1_send, &adsl_conn_1->adsc_gai1_send );  /* send to client */
   if (adsl_conn_1->adsc_gai1_send) {       /* more data to be sent    */
     adsl_conn_1->dsc_tcpco1.m_sendnotify();  /* notify main program when possible to send data */
     return;
   }
   adsl_conn_1->dsc_tcpco1.m_recv();        /* start receiving         */
#endif
} /* end m_tccb_cluster_sendcallback()                                 */

/** TCPCOMP cluster receive callback function                          */
static BOOL m_tccb_cluster_recvcallback( class dsd_tcpcomp *adsp_tcpco, void * vpp_userfld, void * vpp_handle ) {
   BOOL       bol1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
   int        iml1, iml2;                   /* working variables       */
#ifdef XYZ1
   int        iml_pos;                      /* position scan received block */
#endif
   int        iml_len_data;                 /* save length of data     */
   enum ied_decode_cluster_recv_1 iel_dcr1;  /* decode received from cluster */
   char       chl_main_tag;                 /* main tag of received packet */
   char       chl_tag;                      /* tag of field            */
   HL_LONGLONG ill_value;                   /* value decoding          */
   char       *achl1, *achl2;               /* working variables       */
   char       *achl_in;                     /* current input           */
   char       *achl_target;                 /* target of insert value  */
#ifdef XYZ1
   char       *achl_w1;                     /* working variable        */
   void       **avpl_w1;                    /* working variable        */
   char       *achl_st_data;                /* start of data           */
#endif
   struct dsd_cluster_conn *adsl_cluster_conn;  /* connection to a cluster member */
   struct dsd_receive_1 *adsl_receive_in1;  /* receive buffer          */
   struct dsd_receive_1 *adsl_rec1_cur;     /* current in chain        */
   struct dsd_receive_1 *adsl_rec1_last;    /* last in chain           */
   struct dsd_receive_1 *adsl_rec1_data;    /* start data in this block */
   struct dsd_send_block *adsl_send_block_out;  /* send block          */
#ifdef XYZ1
   struct dsd_cluster_active *adsl_clact;   /* active cluster entry    */
   struct dsd_cluster_proc_recv *adsl_clprr_w1;  /* process block received from cluster member */
#endif
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* gather input data       */
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* gather input            */
   struct dsd_gather_i_1 *adsl_gai1_s1;     /* gather send             */
   struct dsd_gather_i_1 *adsl_gai1_s2;     /* gather send             */
   struct dsd_gather_i_1 *adsl_gai1_s3;     /* gather send             */
   struct dsd_wsp_conn *adsl_wsp_conn_w1;   /* connection to a WSP     */
   char       chrl_disp_fp[ DEF_LEN_FINGERPRINT * 2 + DEF_LEN_FINGERPRINT / 2 - 1 ];
   char       chrl_work1[ 512 ];            /* work-area               */

#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_cluster_recvcallback( 0X%p 0X%p 0X%p ) called",
                 __LINE__, adsp_tcpco, vpp_userfld, vpp_handle );
#endif
   if (vpp_handle == NULL) return FALSE;
   adsl_receive_in1 = (struct dsd_receive_1 *) vpp_handle;  /* block received from cluster member */
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_cluster_recvcallback() adsl_receive_in1=%p imc_rc=%d.",
                 __LINE__, adsl_receive_in1, adsl_receive_in1->imc_rc );
#ifdef XYZ1
   if (adsl_receive_in1->imc_len_recv > 0) {
     m_console_out( (char *) (adsl_receive_in1 + 1), adsl_receive_in1->imc_len_recv );
   }
#endif
#endif
   adsl_cluster_conn = (struct dsd_cluster_conn *) vpp_userfld;
   if (adsl_receive_in1->imc_rc <= 0) {     /* no data received        */
     m_hl1_printf( "nbipgw19-l%05d-T m_tccb_cluster_recvcallback() called imc_rc=%d - no data",
                   __LINE__, adsl_receive_in1->imc_rc );
     m_proc_free( adsl_receive_in1 );       /* free storage            */
     return TRUE;
   }
   adsl_receive_in1->dsc_gai1_r.achc_ginp_cur = (char *) (adsl_receive_in1 + 1);
   adsl_receive_in1->dsc_gai1_r.achc_ginp_end = (char *) (adsl_receive_in1 + 1) + adsl_receive_in1->imc_rc;
   adsl_receive_in1->adsc_next = NULL;      /* clear chain             */
#ifdef XYZ1
   if (adsl_clact->adsc_recv_ch == NULL) {  /* chain of received buffers */
     adsl_clact->adsc_recv_ch = adsl_receive_in1;  /* set only in chain */
   } else {                                 /* append to chain         */
     adsl_rec1_cur = adsl_clact->adsc_recv_ch;  /* get first in chain  */
     do {                                   /* loop over chain         */
       adsl_rec1_last = adsl_rec1_cur;      /* save current entry      */
       adsl_rec1_cur = adsl_rec1_cur->adsc_next;  /* get next in chain */
     } while (adsl_rec1_cur);
     adsl_rec1_last->adsc_next = adsl_receive_in1;  /* append to chain */
   }
#endif
   if (adsl_cluster_conn->dsc_connect.adsc_rec1_ch == NULL) {  /* chain received data */
     adsl_cluster_conn->dsc_connect.adsc_rec1_ch = adsl_receive_in1;  /* is first in chain now */
   } else {
     adsl_rec1_cur = adsl_cluster_conn->dsc_connect.adsc_rec1_ch;  /* get chain received data */
     while (adsl_rec1_cur->adsc_next) adsl_rec1_cur = adsl_rec1_cur->adsc_next;
     adsl_rec1_cur->adsc_next = adsl_receive_in1;  /* append to chain  */
     adsl_rec1_cur->dsc_gai1_r.adsc_next = &adsl_receive_in1->dsc_gai1_r;  /* chain of gather */
   }

   p_recv_sc_00:                            /* we have input           */
   adsl_gai1_w1 = &adsl_cluster_conn->dsc_connect.adsc_rec1_ch->dsc_gai1_r;  /* get chain of gather */
   achl1 = (char *) ucrs_cluster_eye_catcher;  /* start to compare     */
   achl2 = (char *) ucrs_cluster_eye_catcher + sizeof(ucrs_cluster_eye_catcher);  /* end to compare */
   iel_dcr1 = ied_dcr1_header;              /* header received         */

   p_recv_sc_04:                            /* scan received input     */
   achl_in = adsl_gai1_w1->achc_ginp_cur;   /* get start of input      */

   p_recv_sc_20:                            /* continue scan received input */
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T p_recv_sc_20: iel_dcr1=%d achl1=%p achl2=%p achl_in=%p.",
                 __LINE__, iel_dcr1, achl1, achl2, achl_in );
#endif
   iml1 = adsl_gai1_w1->achc_ginp_end - achl_in;  /* length of input   */
   if (iml1 <= 0) goto p_recv_sc_60;        /* end of this gather      */
   switch (iel_dcr1) {                      /* decode received from cluster */
     case ied_dcr1_header:                  /* header received         */
       iml2 = achl2 - achl1;                /* length remaining output */
       if (iml2 > iml1) iml2 = iml1;        /* maximum output          */
       if (memcmp( achl1, achl_in, iml2 )) {  /* does not compare      */
         m_hl1_printf( "nbipgw19-l%05d-W received from cluster member %s input eye-catcher does not compare pos=%d.",
                       __LINE__,
                       adsl_cluster_conn->chrc_ineta,
                       achl1 - ((char *) ucrs_cluster_eye_catcher) );
         adsl_cluster_conn->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
         return FALSE;                      /* do not receive more     */
       }
       achl1 += iml2;                       /* increment to compare    */
       achl_in += iml2;                     /* increment input         */
       if (achl1 < achl2) break;            /* we need more input      */
       iel_dcr1 = ied_dcr1_tag;             /* tag                     */
       break;
     case ied_dcr1_tag:                     /* tag                     */
       chl_main_tag = *achl_in++;           /* main tag of received packet */
       iml2 = D_MAX_LEN_NHASN;              /* maximum length NHASN    */
       iml_len_data = 0;                    /* clear akkumulator       */
       iel_dcr1 = ied_dcr1_len_nhasn;       /* length NHASN            */
       break;
     case ied_dcr1_len_nhasn:               /* length NHASN            */
       iml_len_data <<= 7;                  /* shift old akkumulator   */
       iml_len_data |= *achl_in & 0X7F;     /* apply new bits to akkumulator */
       iml2--;                              /* decrement length NHASN  */
       achl_in++;                           /* this character consumed */
       if (*((unsigned char *) achl_in - 1) & 0X80) {  /* more bit still set */
         if (iml2 <= 0) {                   /* too many digits         */
           m_hl1_printf( "nbipgw19-l%05d-W received from cluster member %s input length NHASN contains too many digits",
                         __LINE__, adsl_cluster_conn->chrc_ineta );
           adsl_cluster_conn->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
           return FALSE;                    /* do not receive more     */
         }
         break;                             /* we need more digits     */
       }
#ifdef NO_YET
       if (iml3 <= 0) {
         m_wsp_send_msg( adsl_wsp_conn_w1,
                         "nbipgw19-l%05d-W input content length zero invalid",
                         __LINE__ );
         adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
         return FALSE;                      /* do not receive more     */
       }
       if (iml3 > (ACHL_INPUT_END - ACHL_INPUT_STA)) {
         m_wsp_send_msg( adsl_wsp_conn_w1,
                         "nbipgw19-l%05d-W input content too long %d.",
                         __LINE__,
                         iml3 );
         adsl_wsp_conn_w1->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
         return FALSE;                      /* do not receive more     */
       }
       iml1 = adsl_gai1_w1->achc_ginp_end - achl_in;  /* length of this input */
       adsl_gai1_w2 = adsl_gai1_w1->adsc_next;  /* get chained gather  */
       while (adsl_gai1_w2) {               /* loop over all following gather */
         iml1 += adsl_gai1_w2->achc_ginp_end - adsl_gai1_w2->achc_ginp_cur;
         adsl_gai1_w2 = adsl_gai1_w2->adsc_next;  /* get next in chain */
       }
       if (iml1 < iml3) return TRUE;        /* not complete packet     */
       achl1 = ACHL_INPUT_STA;              /* start of input          */
       achl2 = achl1 + iml3;                /* end of input            */
       achl4 = chrl_nonce;                  /* decode with nonce       */
       iml2 = 0;                            /* start of block          */
       iel_dwr1 = ied_dwr1_content;         /* content                 */
#endif
       goto p_record_00;                    /* record has been received */
   }

   goto p_recv_sc_20;                       /* continue scan received input */

   p_recv_sc_60:                            /* end of this gather      */
   adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain       */
   if (adsl_gai1_w1) goto p_recv_sc_04;     /* scan received input     */
   return TRUE;                             /* continue receiving      */

   p_record_00:                             /* record has been received */
   iml1 = adsl_gai1_w1->achc_ginp_end - achl_in;  /* length of this input */
   adsl_gai1_w2 = adsl_gai1_w1->adsc_next;  /* get chained gather  */
   while (adsl_gai1_w2) {               /* loop over all following gather */
     iml1 += adsl_gai1_w2->achc_ginp_end - adsl_gai1_w2->achc_ginp_cur;
     adsl_gai1_w2 = adsl_gai1_w2->adsc_next;  /* get next in chain */
   }
   if (iml1 < iml_len_data) return TRUE;    /* not complete packet     */
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_cluster_recvcallback() complete block main tag 0X%02X iml_len_data = %d.",
                 __LINE__, (unsigned char) chl_main_tag, iml_len_data );
#endif
   if (chl_main_tag != '0') {               /* is not control message  */
     m_hl1_printf( "nbipgw19-l%05d-W received from cluster member %s tag 0X%02X - not expected",
                   __LINE__, adsl_cluster_conn->chrc_ineta, (unsigned char) chl_main_tag );
     adsl_cluster_conn->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
     /* consume the received data                                      */
     while (TRUE) {                         /* loop over gather input  */
       iml1 = adsl_gai1_w1->achc_ginp_end - achl_in;  /* length of this input */
       if (iml1 <= iml_len_data) {          /* all in this gather      */
         adsl_gai1_w1->achc_ginp_cur = achl_in + iml_len_data;
         break;                             /* all consumed            */
       }
       iml_len_data -= iml1;                /* this part has been consumed */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
       achl_in = adsl_gai1_w1->achc_ginp_cur;  /* start of data        */
     }
     goto p_record_80;                      /* the record has been processed */
   }
#ifdef XYZ1
   bol1 = FALSE;                            /* do not free buffers     */
   switch (chl_main_tag) {                  /* depending on tag        */
     case '0':                              /* control                 */
//     m_recv_control( adsl_clact, adsl_rec1_data, achl_st_data, iml_len_data );
//     bol1 = TRUE;                         /* do free buffers         */
       break;
   }
   return TRUE;
-----------------------
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
   BOOL       bol_config_location;          /* configuration location received */
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
   iml_rem = imp_length;                    /* remaining input         */
   achl_w1 = achp_data;                     /* data start here         */
   adsl_clrecv_w1 = adsp_clrecv;            /* first received block    */

#endif
   p_len_00:                                /* decode length           */
   if (iml_len_data <= 0) {                 /* at end of data          */
     goto p_record_60;                      /* send response           */
   }
   iml1 = 0;                                /* clear akkumulator       */
   iml2 = iml_len_data - 4;                 /* maximum number of digits */
   if (iml2 < 0) iml2 = 0;                  /* minimum length          */
   while (TRUE) {                           /* loop to get length      */
     if (achl_in >= adsl_gai1_w1->achc_ginp_end) {  /* at end of received block */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
       if (adsl_gai1_w1 == NULL) {          /* end of gather           */
         goto p_error_00;                   /* error in datastream     */
       }
       achl_in = adsl_gai1_w1->achc_ginp_cur;  /* start of data        */
     }
     iml1 <<= 7;                            /* shift old value         */
     iml1 |= *achl_in & 0X7F;               /* apply new bits          */
     iml_len_data--;                        /* one byte processed      */
     if ((*achl_in & 0X80) == 0) break;     /* more bit not set        */
     if (iml_len_data <= iml2) {            /* too many digits length  */
       m_hl1_printf( "nbipgw19-l%05d-W received from cluster member %s tag '0' too many digits in length of field",
                     __LINE__, adsl_cluster_conn->chrc_ineta );
       goto p_error_00;                     /* error in datastream     */
     }
     achl_in++;                             /* after last digit        */
   }
   achl_in++;                               /* after last digit        */
   if (iml1 <= 0) {                         /* length value invalid    */
     m_hl1_printf( "nbipgw19-l%05d-W received from cluster member %s tag '0' length of field zero - invalid",
                   __LINE__, adsl_cluster_conn->chrc_ineta );
     goto p_error_00;                       /* error in datastream     */
   }
   if (iml1 > sizeof(chrl_work1)) {         /* maximum length received field */
     m_hl1_printf( "nbipgw19-l%05d-W received from cluster member %s tag '0' length of field %d - too high",
                   __LINE__, adsl_cluster_conn->chrc_ineta, iml1 );
     goto p_error_00;                       /* error in datastream     */
   }
   iml1 = iml_len_data - iml1;              /* position end of value   */
   if (iml1 < 0) {                          /* length too high         */
     m_hl1_printf( "nbipgw19-l%05d-W received from cluster member %s tag '0' length of field longer than remaining data",
                   __LINE__, adsl_cluster_conn->chrc_ineta );
     goto p_error_00;                       /* error in datastream     */
   }
   chl_tag = *achl_in++;                    /* tag of field            */
   iml_len_data--;                          /* one byte processed      */
   achl_target = NULL;                      /* clear target of insert value */
   iml2 = iml_len_data - iml1;              /* length remaining field  */
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_cluster_recvcallback() process tag 0X%02X iml_len_data = %d.",
                 __LINE__, (unsigned char) chl_tag, iml_len_data );
#endif
   switch (chl_tag) {                       /* depend on tag           */
     case 0:                                /* server name received    */
#ifdef XYZ1
       if (bol_server) {                    /* server name received double */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0210W l%05d Cluster INETA=%s tag 0 server name double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0211W l%05d Cluster INETA=%s tag 0 server name but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0212W l%05d Cluster INETA=%s tag 0 server name length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (adsp_clact->imc_len_server_name) {  /* length server name   */
         free( adsp_clact->achc_server_name );  /* free old memory     */
       }
       achl_target = (char *) malloc( iml2 );  /* get new storage      */
       if (achl_target == NULL) {           /* no memory available     */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0213W l%05d Cluster INETA=%s tag 0 server name malloc() failed - out of memory",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       adsp_clact->achc_server_name = achl_target;  /* server name in UTF-8 */
       adsp_clact->imc_len_server_name = iml2;  /* length server name  */
       bol_server = TRUE;                   /* server name received    */
#endif
       achl_target = chrl_work1;            /* fill this field         */
       break;
     case 1:                                /* PID received            */
#ifdef XYZ1
       if (bol_pid) {                       /* PID received double     */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0214W l%05d Cluster INETA=%s tag 1 PID double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0215W l%05d Cluster INETA=%s tag 1 PID but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0216W l%05d Cluster INETA=%s tag 1 PID length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 > sizeof(adsp_clact->imc_pid)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0217W l%05d Cluster INETA=%s tag 1 PID length %d too high",
                         __LINE__, adsp_clact->chrc_ineta, iml2 );
         goto p_error_00;                   /* error in datastream     */
       }
       bol_pid = TRUE;                      /* PID received            */
#endif
       ill_value = 0;                       /* clear value decoding    */
       break;
     case 2:                                /* epoch started received  */
#ifdef XYZ1
       if (bol_epoch_started) {             /* epoch started received double */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0218W l%05d Cluster INETA=%s tag 2 epoch started double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0219W l%05d Cluster INETA=%s tag 2 epoch started but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0220W l%05d Cluster INETA=%s tag 2 epoch started length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 > sizeof(adsp_clact->ilc_epoch_started)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0221W l%05d Cluster INETA=%s tag 2 epoch started length %d too high",
                         __LINE__, adsp_clact->chrc_ineta, iml2 );
         goto p_error_00;                   /* error in datastream     */
       }
       bol_epoch_started = TRUE;            /* epoch started received  */
#endif
       ill_value = 0;                       /* clear value decoding    */
       break;
     case 3:                                /* fingerprint received    */
#ifdef XYZ1
       if (bol_fingerprint) {               /* fingerprint received double */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0222W l%05d Cluster INETA=%s tag 3 fingerprint double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0223W l%05d Cluster INETA=%s tag 3 fingerprint but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0224W l%05d Cluster INETA=%s tag 3 fingerprint length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 != DEF_LEN_FINGERPRINT) {   /* length not like required */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0225W l%05d Cluster INETA=%s tag 3 fingerprint length %d invalid",
                         __LINE__, adsp_clact->chrc_ineta, iml2 );
         goto p_error_00;                   /* error in datastream     */
       }
       achl_target = adsp_clact->chrc_fingerprint;  /* address where to put fingerprint */
       bol_fingerprint = TRUE;              /* fingerprint received    */
#endif
       achl_target = chrl_work1;            /* fill this field         */
       break;
     case 4:                                /* endian-ness received    */
#ifdef XYZ1
       if (bol_endian) {                    /* endian received double  */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0226W l%05d Cluster INETA=%s tag 4 endian double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0227W l%05d Cluster INETA=%s tag 4 endian but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0228W l%05d Cluster INETA=%s tag 4 endian length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 > sizeof(adsp_clact->boc_endian_big)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0229W l%05d Cluster INETA=%s tag 4 endian length %d too high",
                         __LINE__, adsp_clact->chrc_ineta, iml2 );
         goto p_error_00;                   /* error in datastream     */
       }
       bol_endian = TRUE;                   /* endian received         */
#endif
       ill_value = 0;                       /* clear value decoding    */
       break;
     case 5:                                /* alignment received      */
#ifdef XYZ1
       if (bol_alignment) {                 /* epoch started received double */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0230W l%05d Cluster INETA=%s tag 5 alignment double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0231W l%05d Cluster INETA=%s tag 5 alignment but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0232W l%05d Cluster INETA=%s tag 5 aligment length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 > sizeof(adsp_clact->imc_aligment)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0233W l%05d Cluster INETA=%s tag 5 alignment length %d too high",
                         __LINE__, adsp_clact->chrc_ineta, iml2 );
         goto p_error_00;                   /* error in datastream     */
       }
       bol_alignment = TRUE;                /* alignment received      */
#endif
       ill_value = 0;                       /* clear value decoding    */
       break;
     case 6:                                /* query main received     */
#ifdef XYZ1
       if (bol_query_main) {                /* query main received double */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0234W l%05d Cluster INETA=%s tag 6 query main double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0235W l%05d Cluster INETA=%s tag 6 query main but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0236W l%05d Cluster INETA=%s tag 6 query main length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (adsp_clact->imc_len_query_main) {  /* length query main     */
         free( adsp_clact->achc_query_main );  /* free old memory      */
       }
       achl_target = (char *) malloc( iml2 );  /* get new storage      */
       if (achl_target == NULL) {           /* no memory available     */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0237W l%05d Cluster INETA=%s tag 6 query main malloc() failed - out of memory",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       adsp_clact->achc_query_main = achl_target;  /* query main in UTF-8 */
       adsp_clact->imc_len_query_main = iml2;  /* length query main    */
       bol_query_main = TRUE;               /* query main received     */
#endif
       achl_target = chrl_work1;            /* fill this field         */
       break;
     case 7:                                /* configuration name received */
#ifdef XYZ1
       if (bol_config_name) {               /* configuration name received double */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0238W l%05d Cluster INETA=%s tag 7 configuration name double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0239W l%05d Cluster INETA=%s tag 7 configuration name but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0240W l%05d Cluster INETA=%s tag 7 configuration name length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (adsp_clact->imc_len_config_name) {  /* length configuration name */
         free( adsp_clact->achc_config_name );  /* free old memory     */
       }
       achl_target = (char *) malloc( iml2 );  /* get new storage      */
       if (achl_target == NULL) {           /* no memory available     */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0241W l%05d Cluster INETA=%s tag 7 configuration name malloc() failed - out of memory",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       adsp_clact->achc_config_name = achl_target;  /* configuration name in UTF-8 */
       adsp_clact->imc_len_config_name = iml2;  /* length configuration name */
       bol_config_name = TRUE;                /* configuration name received */
#endif
       achl_target = chrl_work1;            /* fill this field         */
       break;
     case 8:                                /* configuration group received */
#ifdef XYZ1
       if (bol_config_group) {              /* configuration group received double */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0242W l%05d Cluster INETA=%s tag 8 configuration group double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0243W l%05d Cluster INETA=%s tag 8 configuration group but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0244W l%05d Cluster INETA=%s tag 8 configuration group length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (adsp_clact->imc_len_group) {     /* length configuration group */
         free( adsp_clact->achc_group );    /* free old memory         */
       }
       achl_target = (char *) malloc( iml2 );  /* get new storage      */
       if (achl_target == NULL) {           /* no memory available     */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0245W l%05d Cluster INETA=%s tag 8 configuration group malloc() failed - out of memory",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       adsp_clact->achc_group = achl_target;  /* configuration group in UTF-8 */
       adsp_clact->imc_len_group = iml2;    /* length configuration group */
       bol_config_group = TRUE;             /* configuration group received */
#endif
       achl_target = chrl_work1;            /* fill this field         */
       break;
     case 9:                                /* configuration location received */
#ifdef XYZ1
       if (bol_config_location) {           /* configuration location received double */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0246W l%05d Cluster INETA=%s tag 9 configuration location double",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (bol_no_start) {                  /* is not start connection */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0247W l%05d Cluster INETA=%s tag 9 configuration location but not start connection",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (iml2 <= 0) {                     /* length too short        */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0248W l%05d Cluster INETA=%s tag 9 configuration location length too short",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       if (adsp_clact->imc_len_location) {  /* length configuration location */
         free( adsp_clact->achc_location );  /* free old memory        */
       }
       achl_target = (char *) malloc( iml2 );  /* get new storage      */
       if (achl_target == NULL) {           /* no memory available     */
         m_hlnew_printf( HLOG_WARN1, "HWSPCL0249W l%05d Cluster INETA=%s tag 9 configuration location malloc() failed - out of memory",
                         __LINE__, adsp_clact->chrc_ineta );
         goto p_error_00;                   /* error in datastream     */
       }
       adsp_clact->achc_location = achl_target;  /* configuration location in UTF-8 */
       adsp_clact->imc_len_location = iml2;  /* length configuration location */
       bol_config_location = TRUE;          /* configuration location received */
#endif
       achl_target = chrl_work1;            /* fill this field         */
       break;
     case 10:                               /* configuration URL received */
       achl_target = chrl_work1;            /* fill this field         */
       break;
     default:
       m_hl1_printf( "nbipgw19-l%05d-W received from cluster member %s tag '0' tag 0X%02X received - not defined",
                     __LINE__, adsl_cluster_conn->chrc_ineta, (unsigned char) chl_tag );
       break;
   }
   if (iml_len_data <= iml1) {
     m_hl1_printf( "nbipgw19-l%05d-W received from cluster member %s tag '0' tag 0X%02X length %d less than remaining data %d.",
                   __LINE__, adsl_cluster_conn->chrc_ineta, (unsigned char) chl_tag, iml1, iml_len_data );
     goto p_error_00;                       /* error in datastream     */
   }
   do {                                     /* loop to process value   */
     if (achl_in >= adsl_gai1_w1->achc_ginp_end) {  /* at end of received block */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
       if (adsl_gai1_w1 == NULL) {          /* end of gather           */
         goto p_error_00;                   /* error in datastream     */
       }
       achl_in = adsl_gai1_w1->achc_ginp_cur;  /* start of data        */
     }
     if (achl_target) {                     /* alpha-numeric field     */
       *achl_target++ = *achl_in;           /* apply character         */
     } else {                               /* numeric field           */
       ill_value <<= 8;                     /* shift old value         */
       ill_value |= (unsigned char) *achl_in;  /* apply new bits       */
     }
     achl_in++;                             /* after last digit        */
     iml_len_data--;                        /* one byte processed      */
   } while (iml_len_data > iml1);
   switch (chl_tag) {                       /* depend on tag           */
     case 1:                                /* PID received            */
       adsl_cluster_conn->imc_pid = (int) ill_value;  /* PID           */
       break;
#ifdef NOT_YET
     case 2:                                /* epoch started received  */
       adsp_clact->ilc_epoch_started = ill_value;  /* set epoch started */
       break;
     case 4:                                /* endian-ness received    */
       adsp_clact->boc_endian_big = (BOOL) ill_value;  /* set endian   */
       break;
     case 5:                                /* alignment received      */
       adsp_clact->imc_aligment = (int) ill_value;  /* set alignment   */
       break;
#endif
   }
   goto p_len_00;                           /* decode length           */

   p_error_00:                              /* error in datastream     */
   m_hl1_printf( "nbipgw19-l%05d-W received from cluster member %s tag '0' p_error_00",
                 __LINE__, adsl_cluster_conn->chrc_ineta );
   adsl_cluster_conn->dsc_connect.dsc_tcpco1.m_end_session();  /* stop session */
   return FALSE;                            /* do not receive more data */

#ifdef XYZ1
   p_end_00:                                /* process end data        */
   if (bol_server == FALSE) {               /* server name missing     */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0260W l%05d Cluster INETA=%s tag received start - tag 0 server name missing",
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
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0261W l%05d Cluster INETA=%s tag received start - tag 1 PID missing",
                     __LINE__, adsp_clact->chrc_ineta );
   }
   if (bol_epoch_started == FALSE) {        /* epoch started missing   */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0262W l%05d Cluster INETA=%s tag received start - tag 2 epoch started missing",
                     __LINE__, adsp_clact->chrc_ineta );
   }
   if (bol_fingerprint == FALSE) {          /* fingerprint missing     */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0263W l%05d Cluster INETA=%s tag received start - tag 3 fingerprint missing",
                     __LINE__, adsp_clact->chrc_ineta );
   }
   if (bol_endian == FALSE) {               /* endian missing          */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0264W l%05d Cluster INETA=%s tag received start - tag 4 endian missing",
                     __LINE__, adsp_clact->chrc_ineta );
   }
   if (bol_alignment == FALSE) {            /* alignment missing       */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0265W l%05d Cluster INETA=%s tag received start - tag 5 alignment missing",
                     __LINE__, adsp_clact->chrc_ineta );
   }
   if (bol_config_name == FALSE) {          /* configuration name missing */
     m_hlnew_printf( HLOG_WARN1, "HWSPCL0266W l%05d Cluster INETA=%s tag received start - tag 6 configuration name missing",
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
   adsp_clact->imc_epoch_conn = (int) time( NULL );  /* time/epoch connected */
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
// URL
-----------------------
#endif
   p_record_60:                             /* send response           */
   adsl_cluster_conn->boc_first_message = TRUE;  /* first message has arrived */
   adsl_send_block_out = (struct dsd_send_block *) m_proc_alloc();  /* send block */
   adsl_gai1_s1 = adsl_gai1_s2
     = (struct dsd_gather_i_1 *) ((char *) adsl_send_block_out + D_BUFFER_LEN - sizeof(struct dsd_gather_i_1));
   adsl_gai1_s1->achc_ginp_cur = (char *) ucrs_cluster_eye_catcher;
   adsl_gai1_s1->achc_ginp_end = (char *) ucrs_cluster_eye_catcher + sizeof(ucrs_cluster_eye_catcher);
   achl1 = (char *) (adsl_send_block_out + 1);
   iml_len_data = 0;                        /* length of data          */
   adsl_gai1_s3 = NULL;                     /* no chain yet            */
   adsl_wsp_conn_w1 = adss_wsp_conn_chain;  /* get connections to WSPs */
   while (adsl_wsp_conn_w1) {               /* loop over chain of WSPs */
     if (adsl_wsp_conn_w1->imc_len_cluster > 0) {  /* length cluster entry */
       iml1 = adsl_wsp_conn_w1->imc_len_cluster;  /* length cluster entry */
       adsl_gai1_s2 -= 2;
       (adsl_gai1_s2 + 1)->achc_ginp_cur = adsl_wsp_conn_w1->achc_cluster;  /* cluster entry */
       (adsl_gai1_s2 + 1)->achc_ginp_end = adsl_wsp_conn_w1->achc_cluster + iml1;  /* end cluster entry */
       iml_len_data += iml1;                /* add to length           */
       achl1 += D_MAX_LEN_NHASN;            /* space for length NHASN  */
       achl2 = achl1;                       /* start here              */
       (adsl_gai1_s2 + 0)->achc_ginp_end = achl2;  /* here is end      */
       iml2 = 0;                            /* clear more bit          */
       do {                                 /* loop output NHASN       */
         *(--achl2) = (unsigned char) ((iml1 & 0X7F) | iml2);
         iml1 >>= 7;                        /* shift bits              */
         iml2 = 0X80;                       /* set more bit            */
       } while (iml1 > 0);
       (adsl_gai1_s2 + 0)->achc_ginp_cur = achl2;  /* here is start    */
       (adsl_gai1_s2 + 0)->adsc_next = adsl_gai1_s2 + 1;  /* set gather */
       iml_len_data += achl1 - achl2;       /* add to length           */
       if (adsl_gai1_s3) {                  /* chain already           */
         adsl_gai1_s3->adsc_next = adsl_gai1_s2;  /* append to chain   */
       }
       adsl_gai1_s3 = adsl_gai1_s2 + 1;     /* here is end of chain    */
     }
     adsl_wsp_conn_w1 = adsl_wsp_conn_w1->adsc_next;  /* get next in chain */
   }
   /* output tag and length                                            */
   adsl_gai1_s2--;                          /* space for gather        */
   achl1 += 1 + D_MAX_LEN_NHASN;            /* space for tag and length NHASN */
   achl2 = achl1;                           /* start here              */
   adsl_gai1_s2->achc_ginp_end = achl2;     /* here is end             */
   iml1 = iml_len_data;                     /* get length              */
   iml2 = 0;                                /* clear more bit          */
   do {                                     /* loop output NHASN       */
     *(--achl2) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* shift bits              */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
   *(--achl2) = '2';                        /* tag for redirect        */
   adsl_gai1_s2->achc_ginp_cur = achl2;     /* here is start           */
   adsl_gai1_s2->adsc_next = NULL;          /* is last gether          */
   adsl_gai1_s1->adsc_next = adsl_gai1_s2;  /* append to first gather  */
   if (adsl_gai1_s3) {                      /* chain already           */
     adsl_gai1_s3->adsc_next = NULL;        /* end of chain            */
     adsl_gai1_s2->adsc_next = adsl_gai1_s1 - 2;  /* after tag and length */
   }
   iml_rc = adsl_cluster_conn->dsc_connect.dsc_tcpco1.m_send_gather( adsl_gai1_s1, &adsl_send_block_out->adsc_gai1_s );
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_cluster_recvcallback() m_send_gather returned %d %p.",
                 __LINE__, iml_rc, adsl_send_block_out->adsc_gai1_s );
#endif
   if (ilrs_param_01[ PA_01_TRACE ] >= 4) {
     m_hl1_printf( "nbipgw19-l%05d-W sent data to cluster-conn=%p imc_rc=%d.",
                   __LINE__, adsl_cluster_conn, iml_rc );
   }
   if (iml_rc < 0) {                        /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W Cluster INETA=%s m_send_gather returned %d.",
                   __LINE__, adsl_cluster_conn->chrc_ineta, iml_rc );
     m_proc_free( adsl_send_block_out );    /* free buffer again       */
     goto p_record_80;                      /* the record has been processed */
   }
   if (adsl_send_block_out->adsc_gai1_s == NULL) {  /* sent completely */
     m_proc_free( adsl_send_block_out );    /* free buffer again       */
     goto p_record_80;                      /* the record has been processed */
   }
// to-do 24.09.11 KB

   p_record_80:                             /* the record has been processed */
   adsl_gai1_w1->achc_ginp_cur = achl_in;   /* processed till here     */
   if (adsl_gai1_w1->achc_ginp_cur >= adsl_gai1_w1->achc_ginp_end) {  /* this gather processed */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   while (adsl_cluster_conn->dsc_connect.adsc_rec1_ch) {  /* loop over chain received data */
     adsl_rec1_cur = adsl_cluster_conn->dsc_connect.adsc_rec1_ch;  /* get chain received data */
     if (adsl_gai1_w1 == &adsl_rec1_cur->dsc_gai1_r) break;  /* current one reached */
     adsl_cluster_conn->dsc_connect.adsc_rec1_ch = adsl_rec1_cur->adsc_next;  /* remove from chain */
     m_proc_free( adsl_rec1_cur );          /* free receive block      */
   }
   if (adsl_cluster_conn->dsc_connect.adsc_rec1_ch) {  /* check chain received data */
     goto p_recv_sc_00;                     /* we have input           */
   }
   return TRUE;                             /* continue receiving      */
} /* end m_tccb_cluster_recvcallback()                                 */

/* TCPCOMP cluster error callback function                             */
static void m_tccb_cluster_errorcallback( class dsd_tcpcomp *adsp_tcpcomp, void * vpp_userfld, char *, int, int ) {
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_cluster_errorcallback() called",
                 __LINE__ );
} /* end m_tccb_cluster_errorcallback()                                */

/* TCPCOMP cluster cleanup callback function                           */
static void m_tccb_cluster_cleanup( class dsd_tcpcomp *adsp_tcpcomp, void * vpp_userfld ) {
   int        iml1;                         /* working variable        */
   char       *achl1;                       /* working variable        */
   struct dsd_cluster_conn *adsl_cluster_conn;  /* connection to a cluster member */
   struct dsd_receive_1 *adsl_rec1_w1;      /* area for receive        */
   char       chrl_work1[ 32 ];             /* work area               */

#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_tccb_cluster_cleanup( adsp_tcpcomp=%p , vpp_userfld=%p ) called",
                 __LINE__, adsp_tcpcomp, vpp_userfld );
#endif
   adsl_cluster_conn = (struct dsd_cluster_conn *) vpp_userfld;  /* connection to a WSP */
   achl1 = "";                              /* empty string            */
   if (adsl_cluster_conn->boc_first_message) {  /* first message has arrived */
     sprintf( chrl_work1, "process id (PID) %d ",
              adsl_cluster_conn->imc_pid );  /* process id             */
     achl1 = chrl_work1;                    /* display as part of message */
   }
   m_hl1_printf( "nbipgw19-l%05d-I connection to WSP cluster-member INETA %s %sended",
                 __LINE__, adsl_cluster_conn->chrc_ineta, achl1 );
   while (adsl_cluster_conn->dsc_connect.adsc_rec1_ch) {  /* loop over chain received data */
     adsl_rec1_w1 = adsl_cluster_conn->dsc_connect.adsc_rec1_ch;  /* get chain received data */
     adsl_cluster_conn->dsc_connect.adsc_rec1_ch = adsl_rec1_w1->adsc_next;  /* remove from chain */
     m_proc_free( adsl_rec1_w1 );           /* free receive block      */
   }
   free( adsl_cluster_conn );               /* free this cluster member */
} /* end m_tccb_cluster_cleanup()                                          */

/** send a message to a connected WSP                                  */
static void m_wsp_send_msg( struct dsd_wsp_conn *adsp_wsp_conn, char *aptext, ... ) {
   int        iml_rc;                       /* return code             */
   int        iml1, iml2;                   /* working-variables       */
   char       *achl1, *achl2;               /* working-variables       */
   struct dsd_gather_i_1 dsrl_gai1_out1[ 2 ];  /* for send gather      */
   va_list    dsl_argptr;
   char       chrl_out1[ 512 ];

#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_wsp_send_msg( %p ... ) called",
                 __LINE__, adsp_wsp_conn );
#endif
   va_start( dsl_argptr, aptext );
   iml1 = m_hlvsnprintf( chrl_out1 + D_MAX_LEN_NHASN + 1, sizeof(chrl_out1) - D_MAX_LEN_NHASN - 1, ied_chs_ascii_850, aptext, dsl_argptr );
   va_end( dsl_argptr );
   if (iml1 <= 0) iml1 = sizeof(chrl_out1) - D_MAX_LEN_NHASN - 1;
   achl1 = chrl_out1 + D_MAX_LEN_NHASN + 1;  /* start of message       */
   achl2 = achl1 + iml1;                    /* end of message          */
   *(--achl1) = (unsigned char) ied_ligwr_msg;  /* message             */
   iml1++;                                  /* plus length of tag      */
   iml2 = 0;                                /* clear more bit          */
   do {                                     /* loop output NHASN       */
     *(--achl1) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* shift bits              */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
   dsrl_gai1_out1[ 0 ].adsc_next = &dsrl_gai1_out1[ 1 ];
   dsrl_gai1_out1[ 0 ].achc_ginp_cur = chrs_requestheader_response;
   dsrl_gai1_out1[ 0 ].achc_ginp_end = chrs_requestheader_response + sizeof(chrs_requestheader_response);
   dsrl_gai1_out1[ 1 ].adsc_next = NULL;
   dsrl_gai1_out1[ 1 ].achc_ginp_cur = achl1;
   dsrl_gai1_out1[ 1 ].achc_ginp_end = achl2;
   iml_rc = adsp_wsp_conn->dsc_connect.dsc_tcpco1.m_send_gather( dsrl_gai1_out1, NULL );
   if (ilrs_param_01[ PA_01_TRACE ] >= 4) {
     m_hl1_printf( "nbipgw19-l%05d-W sent data to wsp-conn=%p imc_rc=%d.",
                   __LINE__, adsp_wsp_conn, iml_rc );
   }
} /* end m_wsp_send_msg()                                              */

#ifdef D_INCL_HOB_TUN
#ifdef B150907
/** search the TUN interface for IPV4                                  */
static BOOL m_htun_search_interface_ipv4( UNSIG_MED ump_ineta ) {
   int        iml1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
#define HL_TUN_UNIX_MAX_IF 64
   struct ifconf dsl_ifconf;                /* interface configuration */
   struct ifreq dsrl_ifreq[ HL_TUN_UNIX_MAX_IF ];  /* return for each iface */

   memset( &dsl_ifconf, 0, sizeof(struct ifconf) );  /* interface configuration */
   memset( dsrl_ifreq, 0, sizeof(dsrl_ifreq) );  /* return for each iface */
   dsl_ifconf.ifc_len = sizeof(dsrl_ifreq);
   dsl_ifconf.ifc_buf = (char*) dsrl_ifreq;
   iml_rc = ioctl( ims_tun_socket, SIOCGIFCONF, &dsl_ifconf );
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_htun_search_interface_ipv4() ioctl( ... , SIOCGIFCONF , ... ) returned %d errno %d.",
                 __LINE__, iml_rc, errno );
#endif
   if (iml_rc < 0) {                        /* error occured           */
   }
   iml1 = 0;                                /* clear index             */

   p_check_if_20:                           /* check interface         */
   if (iml1 >= HL_TUN_UNIX_MAX_IF) {
     m_hl1_printf( "nbipgw19-l%05d-T m_htun_search_interface_ipv4() no interface for INETA %d.%d.%d.%d found",
                   __LINE__,
                   *((unsigned char *) &ump_ineta + 0),  /* <TUN-adapter-use-interface-ineta> */
                   *((unsigned char *) &ump_ineta + 1),  /* <TUN-adapter-use-interface-ineta> */
                   *((unsigned char *) &ump_ineta + 2),  /* <TUN-adapter-use-interface-ineta> */
                   *((unsigned char *) &ump_ineta + 3) );  /* <TUN-adapter-use-interface-ineta> */
     return FALSE;
   }
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_htun_search_interface_ipv4() array %d dsrl_ifreq[ iml1 ].ifr_ifindex=%d.",
                   __LINE__, iml1, dsrl_ifreq[ iml1 ].ifr_ifindex );
   m_console_out( (char *) &dsrl_ifreq[ iml1 ], sizeof(struct ifreq) );
#endif
   /* get flags for each network interfaces                            */
   iml_rc = ioctl( ims_tun_socket, SIOCGIFFLAGS, &dsrl_ifreq[ iml1 ] );
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_htun_search_interface_ipv4() ioctl( ... , SIOCGIFFLAGS , ... ) returned %d errno %d.",
                 __LINE__, iml_rc, errno );
#endif
   if (iml_rc < 0) {                        /* error occured           */
     iml1++;                                /* next interface          */
     goto p_check_if_20;                    /* check interface         */
   }
   if ((dsrl_ifreq[ iml1 ].ifr_flags & IFF_UP) == 0) {
     iml1++;                                /* next interface          */
     goto p_check_if_20;                    /* check interface         */
   }
   /* get interface INETA                                              */
   iml_rc = ioctl( ims_tun_socket, SIOCGIFADDR, &dsrl_ifreq[ iml1 ] );
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_htun_search_interface_ipv4() ioctl( ... , SIOCGIFADDR , ... ) returned %d errno %d.",
                 __LINE__, iml_rc, errno );
#endif
   if (iml_rc < 0) {                        /* error occured           */
     iml1++;                                /* next interface          */
     goto p_check_if_20;                    /* check interface         */
   }
   if (*((UNSIG_MED *) &(((struct sockaddr_in *) &dsrl_ifreq[ iml1 ].ifr_addr))->sin_addr) != ump_ineta) {
     iml1++;                                /* next interface          */
     goto p_check_if_20;                    /* check interface         */
   }
#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_htun_search_interface_ipv4() found interface \"%.*s\" for INETA %d.%d.%d.%d.",
                 __LINE__,
                 IFNAMSIZ, dsrl_ifreq[ iml1 ].ifr_name,
                 *((unsigned char *) &ump_ineta + 0),  /* <TUN-adapter-use-interface-ineta> */
                 *((unsigned char *) &ump_ineta + 1),  /* <TUN-adapter-use-interface-ineta> */
                 *((unsigned char *) &ump_ineta + 2),  /* <TUN-adapter-use-interface-ineta> */
                 *((unsigned char *) &ump_ineta + 3) );  /* <TUN-adapter-use-interface-ineta> */
#endif
   return TRUE;
} /* end m_htun_search_interface_ipv4()                                */
#endif
/** search the TUN interface for IPV4                                  */
static BOOL m_htun_search_interface_ipv4( UNSIG_MED ump_ineta ) {
   BOOL       bol_ret;                      /* return this function    */
   int        iml_rc;                       /* return code             */
   struct ifaddrs *adsl_ifaddrs_all;
   struct ifaddrs *adsl_ifaddrs_w1;

   iml_rc = getifaddrs( &adsl_ifaddrs_all );
   if (iml_rc < 0) {                        /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-E getifaddrs() returned %d errno %d.",
                   __LINE__, iml_rc, errno );
     return FALSE;
   }
   adsl_ifaddrs_w1 = adsl_ifaddrs_all;

   p_check_if_20:                           /* check interface         */
   if (   (adsl_ifaddrs_w1->ifa_addr)
       && (adsl_ifaddrs_w1->ifa_addr->sa_family == AF_INET)
       && (*((UNSIG_MED *) &((struct sockaddr_in *) adsl_ifaddrs_w1->ifa_addr)->sin_addr)
             == ump_ineta)) {
     bol_ret = TRUE;
     goto p_check_if_80;                    /* all interfaces checked  */
   }
   adsl_ifaddrs_w1 = adsl_ifaddrs_w1->ifa_next;
   if (adsl_ifaddrs_w1) {
     goto p_check_if_20;                    /* check interface         */
   }
   bol_ret = FALSE;

   p_check_if_80:                           /* all interfaces checked  */
   freeifaddrs( adsl_ifaddrs_all );
   return bol_ret;
} /* end m_htun_search_interface_ipv4()                                */

#ifdef HL_FREEBSD
/** get the corresponing bpf socket - Berkeley Packet Filter           */
static int m_htun_get_bpf_socket( char *achp_riface ) {
   int        iml1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
   struct dsd_hobtun_bpf_ctrl *adsl_hbc_w1;  /* structure for bpf - Berkeley Packet Filter */
   struct ifreq dsl_ifreq;                  /* interface request       */
   char       byrl_work1[ 32 ];             /* working area            */

   adsl_hbc_w1 = adss_hbc_ch;               /* chain of structure for bpf - Berkeley Packet Filter */
   while (adsl_hbc_w1) {                    /* loop over chain of structure for bpf - Berkeley Packet Filter */
     if (!strcmp( adsl_hbc_w1->chrc_riface, achp_riface )) {
       return adsl_hbc_w1->imc_bpf_fd;      /* file-descriptor for bpf - Berkeley Packet Filter */
     }
     adsl_hbc_w1 = adsl_hbc_w1->adsc_next;  /* get next in chain       */
   }

   /* create new entry                                                 */
   adsl_hbc_w1 = (struct dsd_hobtun_bpf_ctrl *) malloc( sizeof(struct dsd_hobtun_bpf_ctrl) );  /* structure for bpf - Berkeley Packet Filter */
   strcpy( adsl_hbc_w1->chrc_riface, achp_riface );
   adsl_hbc_w1->adsc_next = adss_hbc_ch;    /* get old chain of structure for bpf - Berkeley Packet Filter */
   adss_hbc_ch = adsl_hbc_w1;               /* set new chain of structure for bpf - Berkeley Packet Filter */
   iml1 = 0;                                /* clear index             */
   do {
     sprintf( byrl_work1, "/dev/bpf%d", iml1 );
     adsl_hbc_w1->imc_bpf_fd = open( byrl_work1, O_RDWR );
     if (adsl_hbc_w1->imc_bpf_fd >= 0) break;
//#ifdef TRACEHL1
     m_hl1_printf( "nbipgw19-l%05d-T m_htun_get_bpf_socket() open( %s ) returned errno %d.",
                     __LINE__, byrl_work1, errno );
//#endif
     iml1++;                                /* increment index         */
   } while (iml1 < MAX_TRY_BPF);
   if (adsl_hbc_w1->imc_bpf_fd < 0) {
     m_hl1_printf( "nbipgw19-l%05d-W m_htun_get_bpf_socket() could not open bpf device",
                     __LINE__ );
     return -1;
   }
   memset( &dsl_ifreq, 0, sizeof(struct ifreq) );  /* interface request */
   memcpy( dsl_ifreq.ifr_name, achp_riface, IFNAMSIZ );
   iml_rc = ioctl( adsl_hbc_w1->imc_bpf_fd, BIOCSETIF, &dsl_ifreq );
//#ifdef TRACEHL1
   m_hl1_printf( "nbipgw19-l%05d-T m_htun_get_bpf_socket() ioctl( ... , BIOCSETIF , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
     m_hl1_printf( "nbipgw19-l%05d-W m_htun_get_bpf_socket() ioctl( ... , BIOCSETIF , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
     adsl_hbc_w1->imc_bpf_fd = -1;
   }
   return adsl_hbc_w1->imc_bpf_fd;
} /* end m_htun_get_bpf_socket()                                       */
#endif

#ifdef CONTROL_INETAS
/** compare entries in AVL tree of control INETAs IPV4                 */
static int m_cmp_ineta_ipv4( void *ap_option,
                             struct dsd_htree1_avl_entry *adsp_entry_1,
                             struct dsd_htree1_avl_entry *adsp_entry_2 ) {

#define ADSL_CI_IPV4_P1 ((struct dsd_control_ineta_ipv4 *) ((char *) adsp_entry_1 - offsetof( struct dsd_control_ineta_ipv4, dsc_sort_1 )))
#define ADSL_CI_IPV4_P2 ((struct dsd_control_ineta_ipv4 *) ((char *) adsp_entry_2 - offsetof( struct dsd_control_ineta_ipv4, dsc_sort_1 )))

   if (ADSL_CI_IPV4_P1->adsc_wsp_conn > ADSL_CI_IPV4_P2->adsc_wsp_conn) return 1;  /* connection to a WSP */
   if (ADSL_CI_IPV4_P1->adsc_wsp_conn < ADSL_CI_IPV4_P2->adsc_wsp_conn) return -1;  /* connection to a WSP */

   return memcmp( ADSL_CI_IPV4_P1->dsc_ar_ipv4.chrc_ineta, ADSL_CI_IPV4_P2->dsc_ar_ipv4.chrc_ineta, sizeof(ADSL_CI_IPV4_P1->dsc_ar_ipv4.chrc_ineta) );

#undef ADSL_CI_IPV4_P1
#undef ADSL_CI_IPV4_P2
} /* end m_cmp_ineta_ipv4()                                            */
#endif
#endif

/** acquire memory as a buffer                                         */
static void * m_proc_alloc( void ) {
   return malloc( D_BUFFER_LEN );
} /* end m_proc_alloc()                                                */

/** free memory of buffer                                              */
static void m_proc_free( void *ap1 ) {
   free( ap1 );                             /* free memory             */
} /* end m_proc_free()                                                 */

/** print message on console                                           */
extern "C" int m_hl1_printf( char *aptext, ... ) {
   va_list    dsl_argptr;
   char       chrl_out1[ 512 ];
   int        iml1;                         /* working-variable        */

   va_start( dsl_argptr, aptext );
   iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_ascii_850, aptext, dsl_argptr );
   va_end( dsl_argptr );
   printf( "%s\n", chrl_out1 );
#ifdef TRACEHL1
   fflush( stdout );                        /* flush standard out      */
#endif
   if (ilrs_param_01[ PA_01_LOG ] <= 0) return iml1;
   syslog( DEF_IPLEVEL, "%s\n", chrl_out1 );
   return iml1;
} /* end m_hl1_printf()                                                */

#ifdef HL_UNIX
/** return the Epoch value in micro-seconds                            */
static HL_LONGLONG m_get_epoch_micro_sec( void ) {
   struct timeval dsl_timeval;

   gettimeofday( &dsl_timeval, NULL );
   return (((HL_LONGLONG) dsl_timeval.tv_sec) * 1000 * 1000 + dsl_timeval.tv_usec);
} /* end m_get_epoch_micro_sec()                                       */
#endif

/** subroutine to display date and time                                */
static int m_get_date_time( char *achp_buff ) {
   time_t     dsl_time;

   time( &dsl_time );
   return strftime( achp_buff, 18, "%d.%m.%y %H:%M:%S", localtime( &dsl_time ) );
} /* end m_get_date_time()                                             */

/** subroutine to dump storage-content to console                      */
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
     m_hl1_printf( "%.*s", sizeof(chrlwork1), chrlwork1 );
   }
} /* end m_console_out()                                               */

/** edit a long integer number for decimal display                     */
static char * m_edit_dec_long( char *achp_target, HL_LONGLONG ilp1 ) {
   int        iml1;                         /* working variable        */
   char       *achl1;

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
