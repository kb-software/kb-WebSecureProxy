//#define B080322
#ifndef NEW050421A
#define NEW050421A
#endif
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: hob-xbipgw08-2.h                                    |*/
/*| -------------                                                     |*/
/*|  IP-Gateway with SSL                                              |*/
/*|  WebSecureProxy                                                   |*/
/*|  Header File with configuration data                              |*/
/*|  KB 15.08.05                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2005                                   |*/
/*|  Copyright (C) HOB Germany 2006                                   |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|  Copyright (C) HOB Germany 2016                                   |*/
/*|  Copyright (C) HOB Germany 2017                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  GCC or other Unix C-Compilers                                    |*/
/*|  XERCES 2.6.0                                                     |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/


/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#ifdef B090125
#include "hob-wsppriv.h"                    /* privileges              */
#include <hob-xslcontr.h>                   /* HOB Control             */
#include <hob-netw-01.h>                    /* HOB Networking          */
#endif

/*+-------------------------------------------------------------------+*/
/*| Constant Values.                                                  |*/
/*+-------------------------------------------------------------------+*/

#define DEF_APPL_NAME          "HOB IBIPGW08"  /* application name     */
#define DEF_LOAD_XML_CONF_EC   "XML-CONF: "  /* eye-catcher            */
#define DEF_LEN_FINGERPRINT    20           /* length of hashes        */
#define DEF_CONFIGURATION_VERSION 1         /* configuration version   */
#define DEF_PRIO_DEFAULT       3            /* default priority        */
#define DEF_PRIO_MINIMUM       1            /* minimum priority        */
#define DEF_PRIO_MAXIMUM       5            /* maximum priority        */
#define DEF_BLACO_SIONTIME     120          /* sign on time            */
#define DEF_DELAY_RELOAD_CONF_FILE 20       /* delay in seconds before loading the file */
#define DEF_TIMER_FREE_SESSION_B (60 * 1000)  /* delay in milliseconds before freeing the session block */
#define DEF_TIMER_FREE_SERVER_CONF_1 (60 * 1000)  /* delay in milliseconds before freeing the temporary server configuration */
#define DEF_NO_WTHR_DEFAULT    64           /* default no work threads */
#define DEF_NO_WTHR_S_DEFAULT  64           /* default no work threads */
#define DEF_NO_WTHR_A_DEFAULT  8            /* default no work threads */
#define DEF_NO_WTHR_MINIMUM    4            /* minimum no work threads */
#define DEF_NO_WTHR_MAXIMUM    1024         /* maximum no work threads */
#define NO_WAIT_THR_S          32           /* no of waiting thread b  */
#ifndef HL_UNIX
#define DEF_MAX_MULT_TH (WSA_MAXIMUM_WAIT_EVENTS - 1)  /* maximum in t */
#else
#define DEF_MAX_MULT_TH        128          /* maximum for poll()      */
#endif
#define DEF_MAX_LEN_CO         256          /* maximum length console output */
#define DEF_MAX_LEN_PROT       64           /* maximum length protocol */
#define MAX_AUTH_IN            1024         /* maximum length input authentication */
#define MAX_AUTH_KRB5_TI       (8 * 1024)   /* maximum length authentication Kerberos ticket */
#define DEF_OCSP_TIMEOUT       60           /* standard OCSP receive timeout */
#define DEF_OCSP_RETRY         300          /* standard OCSP retry connect */
#define DEF_TCP_BACKLOG        16           /* default TCP/IP backlog  */
#define DEF_UDP_PORT           4095         /* port LB default         */
#define DEF_UDP_RECLEN         4096         /* length UDP receive      */
#ifdef HL_UNIX
#ifndef HL_LINUX
#define D_DEV_TUN              "/dev/tun"
#else
#define D_DEV_TUN              "/dev/net/tun"
#endif
#endif
#define DEF_APPL_USE_SOURCE_P_START 16368   /* for HOB-TUN / HTCP      */
#define DEF_APPL_USE_SOURCE_P_NO    4096    /* for HOB-TUN / HTCP      */
#define DEF_HTCP_SEND_WINDOW   (64 * 1024)  /* for HOB-TUN / HTCP      */
#define DEF_INETA_POOL_INUSE_WAIT 120       /* time to check again after all INETAs in use */
#define DEF_INETA_POOL_INUSE_MAX 7200       /* time to check again after all INETAs in use */
#define DEF_SERIAL_FREE_POOL   16           /* size chunk of serialise thread work entry */
#define DEF_WOL_PORT           65535        /* port wake-on-lan        */
#define DEF_SSL_TIMEOUT        120          /* default timeout SSL     */
#define DEF_CLIENT_SEND_WAIT_SEC_MAX  (2 * 60)  /* time to wait for TCP send to client at session end */
#define DEF_CLIENT_SEND_WAIT_SEC_INTV 20    /* interval to check if all data have been sent to the client */
#define DEF_LB_TIME1           2            /* timeout wait all        */
#define DEF_LB_TIME2           8            /* timeout wait any        */
#define DEF_MAX_LEN_CERT_NAME  512          /* maximum length cert nam */
#define DEF_WOTHR_LOOP         4            /* compare loop counter    */
#define MAX_SERVER_DATA_HOOK   32           /* maximum number server-data-hook configured */
#define STACK_TIME             8192UL       /* stack size for timeout  */
//#define LEN_TCP_RECV           (16 * 1024)  /* length of TCP/IP recv   */
/* maximum SSL block = 18k + 5 / + sizeof struct dsd_gather_i_1 + sizeof struct dsd_sdh_control_1 */
#define LEN_TCP_RECV           ((18 * 1024 + 5 + 24 + 48 + 8 - 1) & (0 - 8))  /* length of TCP/IP recv */
// to-do 16.11.13 KB - problems cannot read all data
//#define LEN_TCP_RECV           (256 * 1024)  /* length of TCP/IP recv */
#define MAX_TCP_RECV           16           /* maximum of send-buffers in memory */
#define LEN_TCP_SEND           2048         /* length of TCP/IP send   */
#define LEN_STA_DIR            2048         /* length directory sect   */
#define LEN_DISP_INETA         56           /* length display Internet Address */
#define LEN_SERVER_ERROR       64           /* length display server error */
#define MAX_LEN_RECV_FIELD     1024         /* maximum length received field */
#define HL_ERROR_GETHOSTBYNAME (20000 + 0)  /* HOBLink Error Code      */
#define HL_ERROR_AD_TARGET_FILTER (20000 + 1)  /* HOBLink Error Code   */
#ifdef XYZ1
#define HL_ERROR_XTI_TERRNO    (30000 + 0)  /* HOBLink Error Code      */
#define HL_ERROR_XTI_TLOOK     (40000 + 0)  /* HOBLink Error Code      */
#define HL_ERROR_XTI_RCVDIS    (50000 + 0)  /* HOBLink Error Code      */
#endif
#define HL_ERROR_LB_NO_SERVER  (30000 + 0)  /* HOBLink Error Code      */
#define DEF_REC_NO_B           3            /* number for buffer 1 / 2 */
#define LEN_HOST_IPA           255          /* length host IP address  */
#define DEF_DATA_PTR_TYPE unsigned char *
#define LEN_FILE_NAME          1024         /* maximum length of file name */
#ifdef B170620
#define DEF_MAX_LEN_CONF_FILE  0X00100000   /* maximum length configuration file */
#endif
#define DEF_MAX_LEN_CONF_FILE  0X01000000   /* maximum length configuration file */
#define DEF_TIME_CACHE_DISK_FILE (15 * 60)  /* time in seconds         */
#define DEF_TIME_CACHE_DF_MIN (1 * 60)      /* time in seconds         */
#define DEF_TIME_RELOAD_DISK_FILE (5 * 60)  /* time in seconds         */
#define DEF_TICH2_NO_FREE      32           /* number of elements in group */
#define DEF_TIME_CMA_CHECK     3600         /* seconds between CMA check */
#define DEF_TIME_LIGW_RECO     60           /* seconds between listen-gateway reconnect */
#define DEF_TIME_SNMP_TRAP_RDA 120          /* <time-repeat-delay-alert> */
#define DEF_HTCP_TCPC_TO_MSEC  3000         /* TCP connect timeout milliseconds */
#define DEF_HTCP_TCPC_TRY_NO   2            /* TCP connect number of try */
#define MAX_INETA_POOL_ENTR    128          /* maximum number of INETAs in one pool entry */
#define MAX_INETA_IN_CHUNK     0X100000     /* maximum number of INETAs in one chunk */
#define MAX_INETA_IN_CHUNK_SHIFT 20         /* maximum number of INETAs in one chunk */
#define MAX_LEN_AUTH_LEN_U_PW  512          /* maximum length authentication userid or password */
#define MAX_LEN_AUTH_LEN_SERVER 256         /* maximum length authentication length server */
#define MAX_PPP_ON_THE_FLY_PACKETS_CLIENT 3  /* number of packets on the fly to the client */
#define MAX_CERT_DNS_NAMES     64           /* maximum number of SSL certificate DNS names */
#define RANDOM_INETA_CLUSTER_WAIT 20        /* maximum random times cluster timeout value */
#define DEF_INETA_CLUSTER_WAIT 500          /* default cluster timeout value in milliseconds */
#define TIMER_FREE_MEMORY      (30 * 1000)  /* timer to wait some time before freeing memory */
#define LEN_HTTP_PATH_CHECK    128          /* length HTTP path to check */
#define DEF_PPP_EAP_MS_AUTH    26
#ifdef B131225
#define SHIFT_BLOCK_SWAP       16           /* shift bits length block of swap area */
#define LEN_BLOCK_SWAP         (1 << SHIFT_BLOCK_SWAP)  /* length block of swap area */
#endif
#define LEN_SWAP_OCCUPIED      (128 * 64)   /* length memory block bits for oppucied */
#define NO_SWAP_STOR_FREE      32           /* acquire number of free swap storage chunks */
#define NO_SWAP_STOR_OVERHEAD  32           /* overhead of swap storage chunks */
#define MAX_SWAP_STOR_SIZE     ((((HL_LONGLONG) 1) << 32 - 1) << SHIFT_BLOCK_SWAP)  /* maximum size swap storage */
#define MAX_LEN_SDH_RELOAD_NAME 256         /* maximum length name SDH reload */
#define LEN_HLAK               32           /* length HLAK - MPPE keys */
#ifdef HL_UNIX
#define EXT_RANDOM_G_UDS_NAME  "/tmp/hob-random.uds"
#define EXT_RANDOM_G_TIMEOUT_MS 500
#endif
#define CHAR_CR                0X0D         /* carriage-return         */
#define CHAR_LF                0X0A         /* line-feed               */
#define HLOG_XYZ1              0            /* to be replaced later    */
#define HLOG_EMER1             1            /* emergency output        */
#define HLOG_INFO1             0            /* information message     */
#define HLOG_WARN1             0            /* warning message         */
#define HLOG_TRACE1            0            /* trace message           */
#ifdef XYZ1
#ifndef HL_SPECIAL_OFFER_CEBIT_04
#define MSG_CONS_P1            "HWSPM001I IBIPGW08 started / Version 2.3 "
#else
#define MSG_CONS_P1            "IBIPGW08 started / Version 2.2-SO-CeBIT-04 "
#endif
#define MSG_CONS_P2            " / HOB WebSecureProxy / SSL gateway"
#endif
#define MSG_QUERY              "HOB WebSecureProxy V2.3 "
#ifndef MSG_CPU_TYPE
#ifndef WIN64
#define MSG_CPU_TYPE           "x86 "
#else
#ifndef _IA64_
#ifndef _AMD64_
#define MSG_CPU_TYPE           "unknown 64-Bit "
#else
#define MSG_CPU_TYPE           "EM64T "
#endif
#else
#define MSG_CPU_TYPE           "IPF "
#endif
#endif
#endif

#ifndef DEF_FUNC_INCLUDE
#define DEF_FUNC_INCLUDE
#define DEF_FUNC_DIR           0            /* set function direct     */
#define DEF_FUNC_RDP           1            /* set function RDP        */
#define DEF_FUNC_ICA           2            /* set function ICA        */
#define DEF_FUNC_PTTD          3            /* PASS-THRU-TO-DESKTOP    */
#define DEF_FUNC_SS5H          4            /* SELECT-SOCKS5-HTTP      */
#define DEF_FUNC_HRDPE1        5            /* set function HOB RDP Extension 1 */
#define DEF_FUNC_HPPPT1        6            /* set function HOB-PPP-T1 Tunnel */
#define DEF_FUNC_SSTP          7            /* set function SSTP Tunnel */
#define DEF_FUNC_CASC_WSP      8            /* set function CASCADED-WSP */
#define DEF_FUNC_L2TP          9            /* set function L2TP UDP connection */
#ifdef XYZ1
#define DEF_FUNC_RDG_OUT       10           /* set function remote desktop gateway out */
#define DEF_FUNC_RDG_IN        11           /* set function remote desktop gateway in */
#endif
#define DEF_FUNC_WTS           -1           /* set function WTSGATE    */
#define DEF_FUNC_VDI_WSP       -2           /* set function VDI-WSP-GATE */
#endif

#define HL_LANG_EN             (('e' << 8) | 'n')  /* en English       */
#define HL_LANG_ES             (('e' << 8) | 's')  /* es Spanish       */
#define HL_LANG_FR             (('f' << 8) | 'r')  /* fr French        */
#define HL_LANG_DE             (('d' << 8) | 'e')  /* de German        */
#define HL_LANG_IT             (('i' << 8) | 't')  /* it Italian       */
#define HL_LANG_NL             (('n' << 8) | 'l')  /* nl Dutch         */
#define HL_LANG_ZH             (('z' << 8) ¦ 'h')  /* zh chinese       */

#ifdef XYZ1
#define HTCP_ERR_BASE                 60000
#define HTCP_ERR_CANCELLED            (HTCP_ERR_BASE + 0)
#define HTCP_ERR_CONN_REFUSED         (HTCP_ERR_BASE + 1)
#define HTCP_ERR_CONN_TIMEOUT         (HTCP_ERR_BASE + 2)
#define HTCP_ERR_CONN_ALL_REFUSED     (HTCP_ERR_BASE + 3)
#define HTCP_ERR_CONN_ALL_TIMEOUT     (HTCP_ERR_BASE + 4)
#define HTCP_ERR_CONN_ALL_RF_TO       (HTCP_ERR_BASE + 5)
#define HTCP_ERR_SESS_END_FIN         (HTCP_ERR_BASE + 10)
#define HTCP_ERR_SESS_END_RST         (HTCP_ERR_BASE + 11)
#define HTCP_ERR_SESS_END_TIMEOUT     (HTCP_ERR_BASE + 12)
#define HTCP_ERR_INTERNAL_ERROR       (HTCP_ERR_BASE + 13)
#define TCPCOMP_ERR_BASE              70000
#define TCPCOMP_ERR_CANCELLED         (TCPCOMP_ERR_BASE + 0)
//#define TCPCOMP_ERR_CONN_REFUSED      (TCPCOMP_ERR_BASE + 1)
//#define TCPCOMP_ERR_CONN_TIMEOUT      (TCPCOMP_ERR_BASE + 2)
#define TCPCOMP_ERR_CONN_ALL_REFUSED  (TCPCOMP_ERR_BASE + 3)
#define TCPCOMP_ERR_CONN_ALL_TIMEOUT  (TCPCOMP_ERR_BASE + 4)
#define TCPCOMP_ERR_CONN_ALL_RF_TO    (TCPCOMP_ERR_BASE + 5)
#endif
#ifndef TCPSYNC_ERR_BASE
#define TCPSYNC_ERR_BASE              80000
#endif

#ifdef XYZ2
#define GHFW(str) ((ULONG) ((str & 0X000000FF) << 24) \
        | ((str & 0X0000FF00) << 8) | ((str & 0X00FF0000) >> 8) \
        | ((str & 0XFF000000) >> 24))

#define GHHW(str) ((USHORT) ((str & 0X00FF) << 8) \
        | ((str & 0XFF00) >> 8))
#endif

#define HEV    void *
#define HQUEUE void *
#define APIRET int
#ifndef UNSIG_MED
#define UNSIG_MED unsigned int
#endif
#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif
#ifndef HL_UNIX
#ifdef __cplusplus
#define DSD_CONN_G class clconn1
#else
#define DSD_CONN_G void
#endif
#else
#define DSD_CONN_G struct dsd_conn1
#endif

#ifdef XYZ2
#ifndef WIN64
typedef long int dsd_time_1;
#else
typedef __int64 dsd_time_1;
#define NEW_VISUAL_C
#endif
#endif
typedef time_t dsd_time_1;

#define HL_WT_SESS_DATA1      1             /* include data short      */
#define HL_WT_SESS_DATA2      2             /* include data extended   */
#define HL_WT_SESS_NETW       4
#define HL_WT_SESS_SSL_EXT    8
#define HL_WT_SESS_SSL_INT    16
#define HL_WT_SESS_SSL_OCSP   32            /* SSL OCSP                */
#define HL_WT_SESS_WSPAT3_EXT 64
#define HL_WT_SESS_WSPAT3_INT 128
#define HL_WT_SESS_SDH_EXT    256
#define HL_WT_SESS_SDH_INT    512
#define HL_WT_SESS_AUX        1024
#define HL_WT_SESS_MISC       (2 * 1024)

#define HL_WT_CORE_DATA1      1             /* include data short      */
#define HL_WT_CORE_DATA2      2             /* include data extended   */
#define HL_WT_CORE_CONSOLE    4             /* messages written to the console */
#define HL_WT_CORE_CLUSTER    8             /* core cluster            */
#define HL_WT_CORE_UDP        16            /* core UDP receive and send */
#define HL_WT_CORE_DOD        32            /* desktop-on-demand       */
#define HL_WT_CORE_RADIUS     64            /* radius packets          */
#define HL_WT_CORE_VIRUS_CH   128           /* Virus checking          */
#define HL_WT_CORE_HOB_TUN    256           /* HOB-TUN                 */
#define HL_WT_CORE_LDAP       512           /* LDAP                    */
#define HL_WT_CORE_KRB5       1024          /* Kerberos-5              */
#define HL_WT_CORE_MS_RPC     (2 * 1024)    /* MS-RPC                  */
#define HL_WT_CORE_ADMIN      (4 * 1024)    /* Admin                   */
#define HL_WT_CORE_LIGW       (8 * 1024)    /* Listen-Gateway Unix     */

#define HL_WT_DATA_SIZE_1     16            /* size of data when 01 is given */
#define HL_WT_DATA_SIZE_2     64            /* size of data when 10 is given */

typedef BOOL ( * amd_startprog )( struct dsd_wsp_startprog * );
typedef void ( * amd_msgprog )( void *, char *, int );
typedef BOOL ( * amd_service_requ )( void *, void *, void * );  /* request service */
typedef void ( * amd_service_close )( void *, void * );  /* close service */
#ifndef B080322
typedef void ( * amd_udp_recv_compl )( struct dsd_udp_multiw_1 *, struct dsd_sdh_control_1 * );
#endif
#ifdef OLD_1112
#ifndef INCL_GW_EXTERN
typedef void ( * amd_m_radqu_ret_cb )( void *, enum ied_radius_resp );
#endif
#endif
typedef void ( * amd_radius_query_compl )( struct dsd_radius_control_1 *, int );
#ifdef OLD01
#ifndef HL_UNIX
typedef void ( * amd_pd_proc )( class clconn1 *, struct dsd_pd_work * );
#else
typedef void ( * amd_pd_proc )( struct dsd_conn1 *, struct dsd_pd_work * );
#endif
#endif
#ifdef B110817
#ifdef HL_UNIX
typedef void ( * amd_proc_fdcompl )( void *, pollfd * );
#endif
#endif
typedef void ( * amd_dump_cma_01 )( void * vpp_userfld, struct dsd_cma_dump_01 *adsp_cm01 );

#ifdef B140328
#ifndef HL_AUX_AUTH_DEF
#define HL_AUX_AUTH_DEF
enum ied_auth_def { ied_ad_ok,              /* userid and password fit */
                    ied_ad_inv_user,        /* userid invalid - not fo */
                    ied_ad_inv_password };  /* password invalid        */
#endif
#endif

enum ied_auxf_def { ied_auxf_defstor,       /* predefined storage      */
                    ied_auxf_normstor,      /* normal storage          */
                    ied_auxf_timer,         /* timer                   */
                    ied_auxf_certname,      /* name from certificate = DN */
                    ied_auxf_certificate,   /* certificate             */
#ifdef B130911
                    ied_auxf_authname,      /* name from authentication (Radius) */
#endif
                    ied_auxf_radqu,         /* Radius query            */
                    ied_auxf_ocsp,          /* OCSP extension          */
                    ied_auxf_diskfile,      /* link to disk file       */
                    ied_auxf_cma1,          /* common memory area      */
   ied_auxf_q_gather,                       /* query gather            */
   ied_auxf_sess_stor,                      /* Session Storage         */
   ied_auxf_service_query_1,                /* service query 1         */
   ied_auxf_ldap,                           /* LDAP service query      */
   ied_auxf_sip,                            /* SIP request             */
   ied_auxf_udp,                            /* UDP request             */
   ied_auxf_gate_udp,                       /* UDP-gate entry          */
   ied_auxf_sessco1,                        /* session configuration   */
   ied_auxf_admin,                          /* admin command           */
   ied_auxf_ident,                          /* ident - userid and user-group */
   ied_auxf_pipe_listen,                    /* aux-pipe create with name */
   ied_auxf_pipe_conn,                      /* aux-pipe established connection */
   ied_auxf_util_thread,                    /* utility thread          */
   ied_auxf_swap_stor,                      /* swap storage            */
   ied_auxf_dyn_lib,                        /* dynamic library         */
   ied_auxf_sdh_reload,                     /* SDH reload              */
   ied_auxf_mppe_keys                       /* SSTP - HLAK             */
};

enum ied_src_func  {                        /* for auxiliary timer     */
   ied_src_fu_ssl,                          /* SSL subroutine active   */
   ied_src_fu_auth,                         /* Authentication active   */
   ied_src_fu_lbal,                         /* load-balancing          */
   ied_src_fu_radius,                       /* Radius Entry            */
   ied_src_fu_sdh,                          /* Server-Data-Hook        */
   ied_src_fu_cs_ssl,                       /* Client-Side SSL         */
   ied_src_fu_phl,                          /* plain-HTTP-library      */
   ied_src_fu_bgt_end_session,              /* background-task at end of session */
   ied_src_fu_bgt_stat,                     /* background-task for statistic */
   ied_src_fu_bgt_admin,                    /* background-task from administrator */
   ied_src_fu_util_thread,                  /* utility thread          */
   ied_src_fu_to_sdh_relo,                  /* timeout SDH reload      */
/* 05.01.15 KB - ied_src_fu_misc not used */
   ied_src_fu_misc                          /* miscellaneous           */
};

enum ied_difi_def { ied_difi_valid,         /* entry is valid          */
                    ied_difi_not_exists,    /* file does not exist     */
                    ied_difi_locked };      /* file is locked          */

#ifndef DEF_SET_DEF
#define DEF_SET_DEF
enum ied_set_def {                          /* server entry type       */
  ied_set_invalid = 0,                      /* entry is invalid        */
  ied_set_ss5h,                             /* SELECT-SOCKS5-HTTP      */
  ied_set_direct,                           /* connect direct to server */
  ied_set_loadbal,                          /* load balancing is used  */
  ied_set_pttd,                             /* pass-thru-to-desktop    */
  ied_set_casc_wsp,                         /* CASCADED-WSP            */
  ied_set_l2tp                              /* L2TP UDP connection     */
};
#endif

#ifndef DEF_SCP
#define DEF_SCP
/* hob-xsclib01.h, hob-wspat3.h and hob-xbipgw08-2.h */
enum ied_scp_def {                          /* server-conf protocol    */
   ied_scp_undef,                           /* protocol undefined      */
   ied_scp_http,                            /* protocol HTTP           */
   ied_scp_rdp,                             /* protocol MS RDP         */
   ied_scp_hrdpe1,                          /* protocol HOB MS RDP Extension 1 */
   ied_scp_ica,                             /* protocol ICA            */
   ied_scp_ldap,                            /* protocol LDAP           */
   ied_scp_hoby,                            /* protocol HOB-Y          */
   ied_scp_3270,                            /* protocol IBM 3270       */
   ied_scp_5250,                            /* protocol IBM 5250       */
   ied_scp_vt,                              /* protocol VT (100 - 525) */
   ied_scp_socks5,                          /* protocol Socks-5        */
   ied_scp_ssh,                             /* protocol SSH Secure Shell */
   ied_scp_smb,                             /* protocol SMB server message block */
   ied_scp_hpppt1,                          /* protocol HOB-PPP-T1     */
   ied_scp_hvoip1,                          /* protocol HOB-VOIP-1     */
   ied_scp_krb5ts1,                         /* protocol KRB5TS1 Kerberos Ticket Service */
   ied_scp_sstp,                            /* protocol SSTP           */
   ied_scp_soap,                            /* protocol SOAP           */
   ied_scp_ms_rpc,                          /* protocol MS-RPC         */
   ied_scp_websocket,                       /* protocol WebSocket      */
   ied_scp_hl_dash,                         /* protocol HOBLink data share */
   ied_scp_rdg_out_d,                       /* protocol MS RDG_OUT_DATA */
   ied_scp_rdg_in_d,                        /* protocol MS RDG_IN_DATA */
   ied_scp_spec                             /* special protocol        */
};
#endif

#ifdef B130704
/* <connection> <conn-type>                                            */
enum ied_conn_type_def {                    /* connection type         */
   ied_coty_undef = 0,                      /* parameter is undefined  */
   ied_coty_primary,                        /* primary listen          */
   ied_coty_secondary,                      /* secondary listen        */
   ied_coty_admin                           /* for administrator       */
};
#endif

/* hob-xbipgw08-2.h + hob-nbhpppt2.h */
enum ied_ppp_cs_def {                       /* define character set PPP */
   ied_pcs_invalid = 0,                     /* parameter is invalid    */
   ied_pcs_ascii_850,                       /* ASCII 850               */
   ied_pcs_ansi_819,                        /* ANSI 819                */
   ied_pcs_utf_8                            /* Unicode UTF-8           */
};

enum ied_naeg1_def {                        /* disable naegle algorithm */
   ied_naeg1_auto = 0,                      /* automatic               */
   ied_naeg1_yes,                           /* do disable naegle algorithm */
   ied_naeg1_no                             /* do not disable naegle algorithm */
};

#ifndef DEF_INCL_PPP_AUTH
#define DEF_INCL_PPP_AUTH
#define DEF_NO_PPP_AUTH        8            /* configured <PPP-authentication-method> */
enum ied_ppp_auth_def {                     /* authentication-methods  */
   ied_pppa_invalid = 0,                    /* is invalid              */
   ied_pppa_pass_thru,                      /* pass-thru               */
   ied_pppa_none,                           /* no authentication       */
   ied_pppa_pap,                            /* PAP                     */
   ied_pppa_chap,                           /* CHAP                    */
   ied_pppa_ms_chap_v2,                     /* MS-CHAP-V2              */
   ied_pppa_eap                             /* EAP                     */
};
#endif

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

static const int inrs_language[] = {
   HL_LANG_EN,                              /* en English              */
   HL_LANG_ES,                              /* es Spanish              */
   HL_LANG_FR,                              /* fr French               */
   HL_LANG_DE,                              /* de German               */
   HL_LANG_IT,                              /* it Italian              */
   HL_LANG_NL                               /* nl Dutch                */
};

#ifdef B080914
struct dsd_func_e {                         /* function element        */
   char       *achc_function;               /* function name           */
   int        inc_func_value;               /* function value          */
};

static const struct dsd_func_e dsrs_func_e[] = {
   { "DIRECT", DEF_FUNC_DIR },
#ifndef HL_UNIX
   { "RDP", DEF_FUNC_RDP },
   { "HOB-RDP-EXT1", ied_scp_hrdpe1 },      /* protocol HOB MS RDP Extension 1 */
   { "ICA", DEF_FUNC_ICA },
#endif
   { "PASS-THRU-TO-DESKTOP", DEF_FUNC_PTTD },
   { "SELECT-SOCKS5-HTTP", DEF_FUNC_SS5H },
   { "HOB-PPP-T1", DEF_FUNC_HPPPT1 },       /* set function HOB-PPP-T1 Tunnel */
   { "SSTP", DEF_FUNC_SSTP },               /* set function SSTP Tunnel */
   { "WTSGATE", DEF_FUNC_WTS },
   { "VDI-WSP-GATE", DEF_FUNC_VDI_WSP }
};
#endif

/*+-------------------------------------------------------------------+*/
/*| Internal used classes.                                            |*/
/*+-------------------------------------------------------------------+*/

#ifdef B120211
struct DAUTHLIB1 {                          /* loaded libraries auth   */
   struct DAUTHLIB1 *next;                  /* field for chaining      */
   HL_HMODULE dhlibmod;                     /* address of library      */
#ifdef NOTYET050819
#ifndef HL_UNIX
   def_call_wsat1_constr am_constr;         /* address of constructor  */
#endif
#endif
};
#endif

struct dsd_sys_state_1 {                    /* system state            */
   BOOL       boc_load_balancing_started;   /* load-balancing has been started */
   int        imc_load_balancing_value;     /* last value returned by load-balancing */
   int        imc_load_balancing_epoch;     /* time last load-balancing query was done */
   BOOL       boc_htun_started;             /* HTUN has been started   */
   BOOL       boc_htun_start_failed;        /* start of HTUN has failed */
   BOOL       boc_listen_active;            /* listen is currently active */
   BOOL       boc_listen_ended;             /* listen has already ended */
   int        imc_epoch_listen_act;         /* epoch until which listen keeps active */
};

#define DEF_SYS_STATE_LISTEN_INACTIVE 0X01  /* listen is currently not active */
#define DEF_SYS_STATE_LISTEN_ENDED 0X02     /* listen has already ended */

struct dsd_extra_thread_stat {              /* statistics about extra threads */
   int        imc_no_started;               /* number of instances started */
   int        imc_no_current;               /* number of instances currently executing */
   int        imc_no_denied;                /* number of start requests denied / failed */
   HL_LONGLONG ilc_sum_time_ms;             /* summary time executed in milliseconds */
   struct dsd_extra_thread_entry *adsc_ete_ch;  /* chain extra thread entries */
};

struct dsd_extra_thread_entry {             /* extra thread entry      */
   struct dsd_extra_thread_entry *adsc_next;  /* for chaining          */
   volatile void * ac_conn1;                /* for this connection     */
   HL_LONGLONG ilc_time_started_ms;         /* time / epoch started in milliseconds */
};

struct dsd_see_cd_plain_xml {               /* see in core dump plain XML configuration */
   struct dsd_see_cd_plain_xml *adsc_next;  /* for chaining            */
   char       byrc_eye_catcher[ 128 ];      /* eye catcher             */
   dsd_time_1 dsc_time_loaded;              /* epoch when loaded       */
};

struct dsd_loconf_1 {                       /* load configuration file */
/* 12.08.04 KB - add fields                                            */
   struct dsd_loconf_1 *adsc_next;          /* next in chain           */
// HMODULE    dsc_hlibmod;                  /* address of library      */
// amd_hlclib01 amc_hlclib01;               /* entry for call          */
   struct dsd_gate_1 *adsc_gate_anchor;     /* anchor for chain gates  */
   struct dsd_server_list_1 *adsc_server_list_1;  /* chain of list of servers */
   struct dsd_targfi_1 *adsc_targfi_1;      /* chain of target-filters */
   struct dsd_hl_ocsp_d_1 *adsc_hl_ocsp_d_1;  /* HOBLink OCSP Definition */
   struct dsd_pttd_ineta *adsc_pttd_ineta;  /* chain wake-on-lan relays */
   struct dsd_cluster_main *adsc_cluster;   /* pointer to main cluster structure */
   struct dsd_radius_group *adsc_radius_group;  /* chain Radius groups */
   struct dsd_krb5_kdc_1 *adsc_krb5_kdc_1;  /* chain of Kerberos 5 KDC */
// struct dsd_ldap_entry *adsd_ldap_entry;  /* definition LDAP entry   */
   struct dsd_ldap_group *adsc_ldap_group;  /* chain of LDAP groups    */
   struct dsd_rpc_group *adsc_rpc_group_ch;  /* chain of RPC groups    */
   struct dsd_service_conf_1 *adsc_service_conf_1;  /* chain of service configuration */
   struct dsd_udp_gw_ineta *adsc_udp_gw_ineta;  /* chain UDP-gw-INETA  */
   struct dsd_ext_lib1 *adsc_ext_lib1;      /* chain external loaded libraries */
   struct dsd_hrl_obj_1 *adsc_hrl_obj_1;    /* chain HTTP-redirect-library-object */
   struct dsd_phl_obj_1 *adsc_phl_obj_1;    /* chain plain-HTTP-library-object */
   struct dsd_wspat_obj_1 *adsc_wspat_obj_1;  /* chain authentication-library-object */
   struct dsd_sdh_obj_1 *adsc_sdh_obj_1;    /* chain server-data-hook-object */
   struct dsd_bgt_contr_1 *adsc_bgt_contr_1;  /* chain background-task control */
   struct dsd_l2tp_conf *adsc_l2tp_conf;    /* chain L2TP gateways     */
   struct dsd_sig_cred_1 *adsc_sig_cred_1;  /* signature credentials   */
   struct dsd_filename_1 *adsc_swap_fn_chain;  /* chain of filenames for swap file */
   char       *achc_installation_name;      /* installation-name       */
#ifndef HL_UNIX
   WCHAR      *awcc_rev_server;             /* for RegisterEventSourceW */
   WCHAR      *awcc_rev_source;             /* for RegisterEventSourceW */
   WCHAR      *awcc_windows_pipe_name;      /* <Windows-named-pipe>    */
#else
   char       *achc_pid_file;               /* name PID-file           */
   BOOL       boc_prot_include_pid;         /* <prot-include-pid>      */
#ifdef XYZ1
   ied_lierr  iec_lierr;                    /* state LISTEN-ERROR      */
#endif
   BOOL       boc_listen_gw;                /* use listen-gateway      */
#ifndef B160423
   int        imc_ext_random_g_timeout_ms;  /* timeout external Random Generator */
#endif
   int        iml_ligw_time_reco;           /* seconds to do reconnect after connection loss */
   char       *achc_ligw_pipe_name;         /* pipe name of Listen Gateway */
   char       *achc_ligw_shared_secret;     /* shared secret of Listen Gateway */
#ifndef B160423
   char       *achc_ext_random_g_domain_socket_name;  /* external Random Generator */
#endif
   char       *achc_unix_domain_socket;     /* <Unix-Domain-Socket>    */
#endif
   BOOL       boc_print_fingerprint_in_report;  /* <print-fingerprint-in-report> */
   int        imc_tod_mark_log;             /* <time-of-day-mark-log> seconds from midnight, +1 */
   int        imc_so_logout_threshold;      /* sign-on logout threshold */
   int        imc_so_logout_duration;       /* sign-on logout duration in seconds */
   int        imc_so_logout_reset_time;     /* sign-on logout reset time in seconds */
   int        inc_max_poss_workthr;         /* max possible work thr   */
   int        inc_max_act_workthr;          /* max active work thr     */
   int        inc_prio_work_thread;         /* priority work thread    */
   int        imc_max_util_thread;          /* <max-util-thread>       */
   int        inc_report_intv;              /* interval in seconds     */
   int        inc_network_stat;             /* give network statistic  */
   int        inc_time_reload_disk_file;    /* time in seconds         */
   int        inc_time_cache_disk_file;     /* time in seconds         */
   int        imc_swap_mem_size;            /* <size-swap-in-memory> in 64 KB units */
   int        imc_max_swap_size;            /* <max-swap-size> in 64 KB units */
   int        imc_tcp_sndbuf;               /* set TCP SNDBUF          */
   int        imc_tcp_rcvbuf;               /* set TCP RCVBUF          */
   BOOL       boc_tcp_keepalive;            /* set TCP KEEPALIVE       */
#ifndef B080322
   int        imc_vdi_sign_on_time;         /* VDI sign on time        */
#endif
   int        imc_len_security_token;       /* length of security-token */
   char       *achc_security_token;         /* security-token UTF-8    */
   BOOL       boc_auth_hide_msg;            /* hide authentication error message */
   BOOL       boc_clear_used_mem;           /* clear used memory       */
   BOOL       boc_pttd_cehu;                /* <ignore-PTTD-connect-error-host-unreachable> */
   BOOL       boc_sion_npw;                 /* <enable-sign-on-no-password> */
   BOOL       boc_allow_wsp_trace;          /* <allow-wsp-trace>       */
   HL_LONGLONG ilc_disk_file_size_max;      /* length one file         */
   HL_LONGLONG ilc_disk_file_storage;       /* maximum storage         */
   BOOL       boc_reload_conf;              /* allow reload configurat */
   BOOL       boc_csssl_conf;               /* Client Side SSL configured */
   BOOL       boc_csssl_usage_dn;           /* Client Side SSL check DN */
   void *     vpc_csssl_config_id;          /* Client Side SSL Configuration to use */
   int        imc_time_rda;                 /* <time-repeat-delay-alert> */
   int        imc_thres_cput;               /* <CPU-time-percent-threshold> */
   int        imc_syn_w_no;                 /* <watch-syn-no>          */
   int        imc_syn_w_time;               /* <watch-syn-time>        */
   int        imc_bl_wothr_thres;           /* <backlog-work-thread-threshold> */
   HL_LONGLONG ilc_thres_mem;               /* <memory-threshold>      */
   HL_LONGLONG ilc_mem_ls;                  /* <memory-log-size>       */
   BOOL       boc_sip_p5060;                /* <SIP-use-UDP-port-5060> */
   struct dsd_bind_ineta_1 dsc_sip_l_ineta;  /* <SIP-local-ineta>      */
   struct dsd_bind_ineta_1 dsc_udp_gate_ineta;  /* <UDP-gate>          */
   int        imc_udp_gate_ipv4_port;       /* UDP port IPV4           */
   int        imc_udp_gate_ipv6_port;       /* UDP port IPV6           */
   struct dsd_snmp_conf *adsc_snmp_conf;    /* SNMP configuration      */
#ifndef INCL_GW_L2TP
   void *     adsc_raw_packet_if_conf;      /* configuration raw-packet-interface */
#else
   struct dsd_raw_packet_if_conf *adsc_raw_packet_if_conf;  /* configuration raw-packet-interface */
#endif
   char       chrc_fingerprint[ DEF_LEN_FINGERPRINT ];  /* hash over configuration-file */
   int        imc_epoch_loaded;             /* date and time loaded    */
   char       byrc_time[80];                /* date and time loaded    */
};

struct dsd_snmp_conf {                      /* SNMP configuration      */
   int        imc_trap_send_level;          /* <trap-send-level>       */
   struct dsd_snmp_trap_target *adsc_snmp_trap_target;  /* chain of <trap-target> */
};

/**
   struct dsd_snmp_trap_target is followed by the comment
*/
struct dsd_snmp_trap_target {               /* <trap-target>           */
   struct dsd_snmp_trap_target *adsc_next;  /* for chaining            */
   int        imc_socket;                   /* UDP socket for sendto() */
   struct dsd_udp_param_1 dsc_udp_param_1;  /* definition UDP parameter */
   struct dsd_unicode_string dsc_comment;   /* comment                 */
};

struct dsd_udp_gw_ineta {                   /* UDP-gw-INETA            */
   struct dsd_udp_gw_ineta *adsc_next;      /* next in chain           */
   int        imc_len_name;                 /* length name UTF-8 in bytes */
   struct dsd_bind_ineta_1 dsc_ineta;       /* INETA IPV4 / IPV6       */
};

struct dsd_this_server {                    /* data about this server  */
   HL_LONGLONG ilc_epoch_started;           /* epoch started in milliseconds */
   int        imc_len_server_name;          /* length server name      */
   int        imc_pid;                      /* process id              */
   BOOL       boc_endian_big;               /* CPU is big endian       */
   int        imc_aligment;                 /* aligment                */
   char       chrc_fingerprint[ DEF_LEN_FINGERPRINT ];  /* hash over this WSP */
   char       chrc_server_name[512];        /* server name UTF-8       */
};

#define DEF_BANDWIDTH_CLIENT_SECS 20

struct dsd_bandwidth_client_1 {             /* measure bandwidth with clients */
   dsd_time_1 dsc_time_start;               /* start time              */
   int        imc_no_entries;               /* number of entries       */
   int        *aimc_p_sent;                 /* number of packets sent  */
   int        *aimc_p_recv;                 /* number of packets received */
   HL_LONGLONG *ailc_d_sent;                /* count bytes data sent   */
   HL_LONGLONG *ailc_d_recv;                /* count bytes data received */
};

#ifdef INCL_GW_ALL
/** wechsel-puffer                                                     */
struct dsd_bandwidth_client_ctrl {          /* measure bandwidth with clients - control */
   struct dsd_bandwidth_client_1 *adsrc_bc1[ 2 ];  /* measure bandwidth with clients */
#ifndef HL_UNIX
   struct dsd_bandwidth_client_1 *adsc_bc1_mem;  /* measure bandwidth with clients */
   int        imc_report_intv;              /* saved interval in seconds */
   BOOL       boc_critsect_init;            /* critical section has been initialized */
#endif
   class dsd_hcla_critsect_1 dsc_critsect;  /* critical section        */
};
#endif

#ifdef B110104
// to-do 23.04.10 KB remove pointers, length of complete structure = piece of memory
struct dsd_targfi_1 {                       /* target-filter           */
   struct dsd_targfi_1 *adsc_next;          /* next in chain           */
   HL_WCHAR   *awcc_name;                   /* address name UTF-16     */
#ifdef OLD01
   int        imc_len_name_by;              /* length name in bytes    */
#endif
   int        imc_no_targfi_ele_1;          /* number of elements      */
   BOOL       boc_with_dns;                 /* includes DNS filter     */
   BOOL       boc_in_use;                   /* target-filter is in use */
};

// to-do 23.04.10 KB remove pointers
struct dsd_targfi_ele_1 {                   /* target-filter element   */
   BOOL       boc_allow;                    /* this entry allow        */
   char       *achc_dns_name;               /* address DNS-name        */
   UNSIG_MED  umc_ineta;                    /* INETA                   */
   int        imc_netw_mask;                /* bits network-mask       */
   int        imc_no_port;                  /* number of ports         */
   int        imc_no_protocol;              /* number of protocols     */
   int        *aimrc_port;                  /* address array ports     */
   char       *achrc_protocol;              /* address array protocols */
};
#endif

struct dsd_targfi_1 {                       /* target-filter           */
   struct dsd_targfi_1 *adsc_next;          /* next in chain           */
   int        imc_len_total;                /* length total this target-filter */
   int        imc_off_name;                 /* offset name UTF-8       */
   int        imc_len_name;                 /* length name UTF-8       */
   int        imc_no_targfi_ele_1;          /* number of elements      */
   BOOL       boc_with_dns;                 /* includes DNS filter     */
#ifndef B160503
   BOOL       boc_blacklist;                /* use-as-blacklist        */
#endif
   BOOL       boc_in_use;                   /* target-filter is in use */
};

struct dsd_targfi_ele_1 {                   /* target-filter element   */
   BOOL       boc_allow;                    /* this entry allow        */
   int        imc_off_dns_name;             /* offset DNS-name         */
   int        imc_len_dns_name;             /* length DNS-name         */
   int        imc_off_ineta;                /* offset INETA            */
   int        imc_len_ineta;                /* length INETA            */
   int        imc_prefix_ineta;             /* prefix of INETA         */
   int        imc_off_port;                 /* offset of ports         */
   int        imc_no_port;                  /* number of ports         */
   int        imc_off_protocol;             /* offset of protocols     */
   int        imc_no_protocol;              /* number of protocols     */
};

enum ied_ret_cf {                           /* return value from processing target filter */
   ied_rcf_incompl = 0,                     /* packet is incomplete    */
   ied_rcf_invalid,                         /* packet is invalid       */
   ied_rcf_drop,                            /* drop packet             */
   ied_rcf_ok                               /* packet is o.k.          */
};

struct dsd_sig_cred_1 {                     /* signature credentials   */
   int        imc_len_modulus_bin;
   int        imc_len_modulus_base64;
   int        imc_len_private_key_bin;
   int        imc_len_public_key_base64;
   char       *achc_modulus_bin;
   char       *achc_modulus_base64;
   char       *achc_private_key_bin;
   char       *achc_public_key_base64;
};

struct dsd_filename_1 {                     /* for filenames           */
   struct dsd_filename_1 *adsc_next;        /* for chaining            */
   struct dsd_unicode_string dsc_ucs_file_name;  /* file name          */
};

#ifndef INCL_GW_EXTERN
#ifndef HL_KRB5
struct dsd_ext_lib1 {                       /* external loaded library */
   struct dsd_ext_lib1 *adsc_next;          /* field for chaining      */
   BOOL       boc_loaded;                   /* library has been loaded */
#ifndef HL_UNIX
   DWORD      umc_load_err;                 /* error from load library */
#else
   char       *achc_load_err;               /* error from load library */
#endif
   int        imc_usage_count;              /* usage count             */
   BOOL       boc_hrl_checked;              /* HTTP-redirect was checked */
   BOOL       boc_phl_checked;              /* plain-HTTP-library was checked */
   BOOL       boc_at3_checked;              /* HOB-WSP-AT3 was checked */
   BOOL       boc_sdh_checked;              /* server-data-hook was checked */
   BOOL       boc_bgt_checked;              /* background-task was checked */
   HL_HMODULE dsc_hlibmod;                  /* address of library      */
   amd_call_hrl_1 amc_hrl_entry;            /* entry for HTTP-redirect-library */
   amd_hrl_conf amc_hrl_conf;               /* entry for HTTP-redirect-library configuration */
   amd_call_phl_1 amc_phl_entry;            /* entry for plain-HTTP-library */
   amd_phl_conf amc_phl_conf;               /* entry for plain-HTTP-library configuration */
   amd_call_wspat3_1 amc_at3_entry;         /* entry for HOB-WSP-AT3 call */
// to-do 11.12.11 KB - is wrong type, but other header file
   amd_hlclib_conf amc_at3_conf;            /* entry for HOB-WSP-AT3 configuration */
   amd_hlclib01 amc_hlclib01;               /* entry for SDH call      */
   amd_hlclib_conf amc_hlclib_conf;         /* entry for SDH configuration */
   amd_call_bgt_1 amc_bgt_entry;            /* entry for background-task call */
   amd_bgt_conf amc_bgt_conf;               /* entry for background-task configuration */
};
#endif
#endif

#ifdef B080609
struct dsd_sdh_lib1 {                       /* server data hook lib    */
   struct dsd_sdh_lib1 *adsc_next;          /* field for chaining      */
   HL_HMODULE dsc_hlibmod;                  /* address of library      */
   amd_hlclib01 amc_hlclib01;               /* entry for call          */
   amd_hlclib_conf amc_hlclib_conf;         /* entry for configuration */
};
#endif

#ifdef OLD_1112
#ifndef HL_KRB5
struct dsd_sdh_def_1 {                      /* server data hook def    */
   struct dsd_sdh_def_1 *adsc_next;         /* field for chaining      */
   HL_WCHAR   *awcc_library_name;           /* name of library         */
   DOMNode    *adsc_node_conf;              /* entry configuration-section */
#ifdef B080609
   struct dsd_sdh_lib1 *adsc_sdhl_1;        /* server-data-hook libr   */
#endif
   struct dsd_ext_lib1 *adsc_ext_lib1;      /* external library loaded */
   void *     ac_conf;                      /* return data from conf   */
};
#endif
#endif

struct dsd_sdh_work_1 {                     /* work area server data hook */
#ifdef B080609
   struct dsd_sdh_lib1 *adsc_sdhl_1;        /* server-data-hook libr   */
#endif
   struct dsd_ext_lib1 *adsc_ext_lib1;      /* external library loaded */
   void *     ac_conf;                      /* return data from conf   */
};

struct dsd_sdh_session_1 {                  /* work area server data hook per session */
   void *     ac_ext;                       /* attached buffer pointer */
   BOOL       boc_ended;                    /* processing of this SDH has ended */
};

struct dsd_cid {                            /* component identifier    */
   enum ied_src_func iec_src_func;          /* type of component       */
   void *     ac_cid_addr;                  /* address of component / SDH / PHL */
};

struct dsd_auxf_1 {                         /* auxiliary extension field */
   struct dsd_auxf_1 *adsc_next;            /* next in chain           */
   enum ied_auxf_def iec_auxf_def;          /* type of entry           */
#ifdef B140621
// to-do 21.06.14 KB - remove imc_hookc
   int        imc_hookc;                    /* hook-count              */
#endif
#ifdef TRACEHL_P_COUNT
   int        inc_size_mem;                 /* size of memory          */
#endif
#ifdef NOT_YET_130417
// cid needed for sleeping components
   struct dsd_cid dsc_cid;                  /* component identifier    */
#endif
   struct dsd_cid dsc_cid;                  /* component identifier    */
};

enum ied_sdhc_state {                       /* state of control area server data hook */
   ied_sdhcs_idle = 0,                      /* idle, has been processed */
   ied_sdhcs_activate,                      /* activate SDH when possible */
   ied_sdhcs_wait_send_client               /* wait till send to client is possible */
};

struct dsd_sdh_control_1 {                  /* control area server data hook */
   struct dsd_sdh_control_1 *adsc_next;     /* field for chaining      */
   struct dsd_gather_i_1 *adsc_gather_i_1_i;  /* gather input data     */
   int        inc_function;                 /* function of SDH         */
   int        inc_position;                 /* position of SDH         */
#ifdef B110904
// to-do 30.08.11 KB remove this field
   BOOL       boc_ready_t_p;                /* ready to process        */
#endif
   enum ied_sdhc_state iec_sdhcs;           /* state of control area server data hook */
   int        imc_usage_count;              /* usage count             */
   struct dsd_cid dsc_cid;                  /* component identifier    */
#ifdef TRACEHL_SDH_01
   int        imc_line_no[ 4 ];             /* line numbers for debugging */
#endif
};

#define LEN_DSD_SDHC1 ((sizeof(struct dsd_sdh_control_1) + sizeof(void *) - 1) & (0 - sizeof(void *)))

#ifdef B080609
struct dsd_hlwspat2_lib1 {                  /* authentication library  */
   struct dsd_hlwspat2_lib1 *adsc_next;     /* field for chaining      */
   HL_HMODULE dsc_hlibmod;                  /* address of library      */
   amd_hlwspat2e amc_entry;                 /* entry for call          */
   amd_hlclib_conf amc_conf;                /* entry for configuration */
};
#endif

#ifndef HL_KRB5
#ifdef OLD_1112
struct dsd_hlwspat2_def_1 {                 /* authentication library definition */
// struct dsd_sdh_def_1 *adsc_next;         /* field for chaining      */
   HL_WCHAR   *awcc_library_name;           /* name of library         */
   DOMNode    *adsc_node_conf;              /* entry configuration-section */
#ifdef B080609
   struct dsd_hlwspat2_lib1 *adsc_hlwspat2_lib1;  /* authentication library */
#endif
   struct dsd_ext_lib1 *adsc_ext_lib1;      /* external library loaded */
   void *     ac_conf;                      /* return data from conf   */
};
#else
#ifdef B130228
struct dsd_hrl_def_1 {                      /* HTTP-redirect-library definition */
   HL_WCHAR   *awcc_library_name;           /* name of library         */
   DOMNode    *adsc_node_def;               /* node definition         */
   DOMNode    *adsc_node_conf;              /* entry configuration-section */
   struct dsd_ext_lib1 *adsc_ext_lib1;      /* external library loaded */
   void *     ac_conf;                      /* return data from conf   */
};
#endif

struct dsd_hrl_conf_1 {                     /* HTTP-redirect-library configuration */
   struct dsd_ext_lib1 *adsc_ext_lib1;      /* external library loaded */
   void *     ac_conf;                      /* return data from conf   */

};

#ifdef B130228
struct dsd_phl_def_1 {                      /* plain-HTTP-library definition */
   HL_WCHAR   *awcc_library_name;           /* name of library         */
   DOMNode    *adsc_node_def;               /* node definition         */
   DOMNode    *adsc_node_conf;              /* entry configuration-section */
   struct dsd_ext_lib1 *adsc_ext_lib1;      /* external library loaded */
   void *     ac_conf;                      /* return data from conf   */
};
#endif

struct dsd_phl_conf_1 {                     /* plain-HTTP-library configuration */
   struct dsd_ext_lib1 *adsc_ext_lib1;      /* external library loaded */
   void *     ac_conf;                      /* return data from conf   */
};

struct dsd_wspat_def_1 {                    /* authentication library definition */
   HL_WCHAR   *awcc_library_name;           /* name of library         */
   DOMNode    *adsc_node_def;               /* node definition         */
   DOMNode    *adsc_node_conf;              /* entry configuration-section */
   struct dsd_ext_lib1 *adsc_ext_lib1;      /* external library loaded */
   void *     ac_conf;                      /* return data from conf   */
};
#endif
#endif

enum ied_auxt_usage {                       /* usage of the auxiliary timer */
   ied_auxtu_normal = 0,                    /* normal aux-function     */
   ied_auxtu_sdh_reload                     /* wait for SDH-reload     */
};

/**
  the Structure struct dsd_aux_timer is appended to the Structure struct dsd_auxf_1
*/
struct dsd_aux_timer {                      /* auxiliary timer         */
   struct dsd_auxf_1 *adsc_auxf_next;       /* next in chain           */
   HL_LONGLONG ilc_endtime;                 /* end-time in milli-seconds */
#ifdef B130314
   enum ied_src_func iec_src_func;          /* type auxiliary timer    */
   void *     ac_sdh;                       /* address of SDH          */
#endif
// to-do 21.06.14 KB - remove dsc_cid
   struct dsd_cid dsc_cid;                  /* component identifier    */
#ifdef NOT_YET_130417
// cid needed in struct dsd_auxf_1 for sleeping components
#endif
   enum ied_auxt_usage iec_auxtu;           /* usage of the auxiliary timer */
   BOOL       boc_expired;                  /* timer has expired       */
};

/**
  the Structure struct dsd_aux_q_gather is appended to the Structure struct dsd_auxf_1
*/
struct dsd_aux_q_gather {                   /* query gather            */
   struct dsd_gather_i_1 *adsc_gai1_q;      /* address gather queried  */
#ifdef B130314
   enum ied_src_func iec_src_func;          /* type auxiliary timer    */
   void *     ac_sdh;                       /* address of SDH          */
#endif
// to-do 21.06.14 KB - remove dsc_cid
   struct dsd_cid dsc_cid;                  /* component identifier    */
   int        imc_signal;                   /* set signal when no more active */
};

#ifdef XYZ1
struct dsd_wsp_cma_lock_1 {                 /* aux field cma lock      */
   struct dsd_hco_wothr *adsc_hco_wothr;    /* work thread             */
};
#endif

struct dsd_sysaddr {                        /* structure with System Addresses */
   int        inc_length;                   /* length of structure     */
   void *     amc_aux_conn;                 /* address routine m_aux_conn() */
   struct dsd_hco_main *adsc_hco_main;      /* Work-Threads            */
   struct dsd_loconf_1 *adsc_loconf_1_first;  /* first load configuration */
   void *     amc_set_wothr_blocking;       /* address routine m_set_wothr_blocking() */
   void *     amc_set_wothr_active;         /* address routine m_set_wothr_active() */
};

#ifndef HL_UNIX
#ifdef B120816
struct dsd_ocspint_1 {                      /* internal OCSP structure */
   struct dsd_auxf_1 dsc_auxf_1;            /* auxiliary extension fi  */
   struct dsd_hl_ocsp_d_1 *adsc_ocsp_def_1;  /* address of definition  */
#ifndef HL_UNIX
   int        imc_socket_1;                 /* socket for connection   */
#ifdef HL_OCSP_IPV6
   struct addrinfo dsc_ai1;                 /* for IPV6                */
#endif
#else
   int        imc_fd;                       /* file descriptor for connection */
#endif
#ifndef HL_UNIX
   WSAEVENT   dsc_event_1;                  /* WSA event for recv      */
#endif
};
#endif

struct dsd_ocspext_1 {                      /* OCSP structure extensio */
#ifdef B070917
   BOOL       boc_multih;                   /* is multihomed           */
#endif
#ifdef B120813
   char       *achc_ineta;                  /* ineta                   */
   int        inc_len_ineta;                /* length ineta            */
#endif
   int        imc_port;                     /* port target             */
#ifdef B070917
   union {                                  /* for multihomed          */
     struct sockaddr_in dsc_soad1;          /* socket address informat */
#ifndef HL_UNIX
#ifdef HL_OCSP_IPV6
     SOCKADDR_STORAGE dsc_sost1;            /* socket address informat */
#endif
#endif
   } unc_multih;
#else
   struct dsd_bind_ineta_1 dsc_bind_multih;  /* for bind multihomed    */
#endif
#ifdef B060517
   union {                                  /* for target              */
     struct sockaddr_in dsc_soad1;          /* socket address informat */
#ifndef HL_UNIX
#ifdef HL_OCSP_IPV6
     SOCKADDR_STORAGE dsc_sost1;            /* socket address informat */
#endif
#endif
   } unc_target;
#endif
   struct dsd_target_ineta_1 *adsc_server_ineta;  /* server INETA      */
   int        inc_timeout;                  /* timeout receive         */
   int        inc_wait_retry;               /* after error wait sec    */
   int        inc_time_retry;               /* time when to retry      */
};
#endif
#ifdef D_INCL_OCSP
struct dsd_ocspint_1 {                      /* internal OCSP structure */
   struct dsd_auxf_1 dsc_auxf_1;            /* auxiliary extension fi  */
   struct dsd_hl_ocsp_d_1 *adsc_ocsp_def_1;  /* address of definition  */
   struct dsd_tcpsync_1 dsc_tcpsync_1;      /* TCP synchron            */
};

#ifdef HL_UNIX
#ifdef B120813
struct dsd_ocspext_1 {                      /* OCSP structure extensio */
#ifdef B070917
   BOOL       boc_multih;                   /* is multihomed           */
#endif
   char       *achc_ineta;                  /* ineta                   */
   int        inc_len_ineta;                /* length ineta            */
   int        imc_port;                     /* port target             */
#ifdef B070917
   union {                                  /* for multihomed          */
     struct sockaddr_in dsc_soad1;          /* socket address informat */
#ifndef HL_UNIX
#ifdef HL_OCSP_IPV6
     SOCKADDR_STORAGE dsc_sost1;            /* socket address informat */
#endif
#endif
   } unc_multih;
#else
   struct dsd_bind_ineta_1 dsc_bind_multih;  /* for bind multihomed    */
#endif
#ifdef B060517
   union {                                  /* for target              */
     struct sockaddr_in dsc_soad1;          /* socket address informat */
#ifndef HL_UNIX
#ifdef HL_OCSP_IPV6
     SOCKADDR_STORAGE dsc_sost1;            /* socket address informat */
#endif
#endif
   } unc_target;
#endif
   struct dsd_target_ineta_1 *adsc_server_ineta;  /* server INETA      */
   int        inc_timeout;                  /* timeout receive         */
   int        inc_wait_retry;               /* after error wait sec    */
   int        inc_time_retry;               /* time when to retry      */
};
#endif
struct dsd_ocspext_1 {                      /* OCSP structure extension */
   int        imc_port;                     /* port target             */
   struct dsd_bind_ineta_1 dsc_bind_multih;  /* for bind multihomed    */
   struct dsd_target_ineta_1 *adsc_server_ineta;  /* server INETA      */
   int        inc_timeout;                  /* timeout receive         */
   int        inc_wait_retry;               /* after error wait sec    */
   int        inc_time_retry;               /* time when to retry      */
};
#endif
#endif

#ifdef B070917
struct dsd_target_ineta_1 {                 /* definition INETA target */
   int        inc_no_ineta;                 /* number of INETA         */
};
#endif

struct dsd_wtsg_1 {                         /* gateway LB INETA        */
  struct dsd_wtsg_1 *adsc_next;             /* for chaining            */
// to-do 05.12.11 KB IPV6
#ifdef OLD_1112
#ifdef OLD01
   struct dsd_target_ineta_1 *adsc_ineta;   /* target INETA            */
#else
  UNSIG_MED umc_ineta;                      /* IP-addr where LB        */
#endif
  int         imc_port;                     /* UDP/IP port LB          */
#else
   struct sockaddr_storage dsc_soa;         /* target INETA and port LB */
#endif
};

#ifdef OLD01
#ifndef HL_UNIX
struct DWTSREG1 {                           /* WTS registry            */
  struct DWTSREG1 *next;                    /* for chaining            */
  int   ilen;                               /* length of name          */
  int   iport;                              /* port found              */
  int   ifunction;                          /* function found          */
  DWORD dwLanAdapter;                       /* LanAdapter found        */
  BOOL  bo_LA;                              /* status LanAdapter       */
};

struct DWTSREG2 {                           /* WTS registry            */
  struct DWTSREG2 *next;                    /* for chaining            */
  int   ilen;                               /* length of name          */
  BOOL  bo_valid;                           /* entry is valid          */
  DWORD dwLanAdapter;                       /* LanAdapter found        */
  BOOL  bo_LA;                              /* status LanAdapter       */
  unsigned long int ulineta;                /* IP-addr of adapter      */
};
#endif
#endif

#ifdef B0803XX
struct d_blade_twin {                       /* blade trimming twin     */
  struct d_blade_twin *next;                /* for chaining            */
  UNSIG_MED umc_ineta;                      /* IP-addr where twin      */
  int   imc_port;                           /* UDP/IP port twin        */
};
#endif

struct dsd_sdh_reload_saved {               /* SDH, saved for reload   */
   struct dsd_auxf_1 *adsc_auxf_1_ch;       /* chain auxiliary ext fields */
   struct dsd_sdh_control_1 *adsc_sdhc1_chain;  /* chain of buffers input output */
   struct dsd_sdh_session_1 dsc_sdh_s_1;    /* work area server data hook per session */
};

struct dsd_aux_cf1 {                        /* auxiliary control structure */
#ifndef HL_UNIX
#ifdef __cplusplus
   class clconn1 *adsc_conn;                /* pointer on connection   */
#else
   void *     adsc_conn;                    /* pointer on connection   */
#endif
#else
   struct dsd_conn1 *adsc_conn;             /* pointer on connection   */
#endif
   struct dsd_hco_wothr *adsc_hco_wothr;    /* pointer on work-thread  */
#ifdef B130314
   enum ied_src_func iec_src_func;          /* type function in progress */
   void *     ac_sdh;                       /* current Server-Data-Hook */
#endif
   struct dsd_cid dsc_cid;                  /* component identifier    */
   struct dsd_sdh_control_1 *adsc_sdhc1_chain;  /* chain of buffers - work areas */
#ifdef WAS_BEFORE_1501
   struct dsd_sdh_reload_saved *adsc_sdh_reload_saved;  /* SDH, saved for reload */
#endif
   /* new 04.01.15 KB - for SDH-reload                                 */
   void *     ac_sdhr_conn1;                /* reload SDH from this connection */
   struct dsd_cid dsc_sdhr_cid;             /* component identifier    */
};

enum ied_pdw_ret {                          /* return from process data */
   ied_pdwr_cont = 0,                       /* continue receiving      */
   ied_pdwr_ssl,                            /* found continue SSL      */
   ied_pdwr_end_session                     /* end session             */
};

struct dsd_pd_work {                        /* work to process data    */
   struct dsd_aux_cf1 dsc_aux_cf1;          /* auxiliary control structure */
#ifdef OLD01
// 15.04.06 KB UUUU ???
   amd_pd_proc amc_pd_proc;                 /* function to call        */
#endif
   int        imc_hookc;                    /* hook-count              */
   BOOL       boc_end_sdh;                  /* end process server-data-hook */
   BOOL       boc_eof_client;               /* End-of-File Client      */
   BOOL       boc_eof_server;               /* End-of-File Server      */
   BOOL       boc_abend;                    /* abend of session        */
   int        inc_count_proc_end;           /* process end of connection */
   int        imc_special_func;             /* call with special function */
// struct dsd_gather_i_1 *adsc_gai1_i;      /* gather input data       */
   enum ied_pdw_ret iec_pdwr;               /* return from process data */
   struct dsd_sdh_control_1 *adsc_sdhc1_serv_fi;  /* send to server first */
   struct dsd_sdh_control_1 *adsc_sdhc1_serv_do;  /* send to server really do */
#ifdef B090731
   struct dsd_sdh_control_1 *adsc_sdhc1_client;  /* send to client     */
#endif
#ifdef B060507
   char       *achc_out_start;              /* from encryption         */
   char       *achc_out_end;                /* from encryption         */
#endif
#ifdef OLD01
/* 29.09.05 KB nonsense */
  int   imc_port;                           /* UDP/IP port twin        */
#endif
   /* new 04.01.15 KB - for SDH-reload                                 */
   struct dsd_sdh_reload_saved dsc_sdh_reload_saved;  /* SDH, saved for reload */
};

/* enum for WSP authentication status of input data stream from client */
enum ied_wan_input_1 {                      /* state WSP authentication normal input */
   ied_wani_start = 0,                      /* start of input          */
   ied_wani_prot_cs,                        /* protocol const start    */
   ied_wani_prot_utf8,                      /* protocol in UTF-8       */
   ied_wani_keyword,                        /* search keyword          */
   ied_wani_kw_value,                       /* value for keyword       */
   ied_wani_lenmeth,                        /* length of methods       */
   ied_wani_methchoice,                     /* choice of methods       */
   ied_wani_recr1,                          /* start of input record   */
   ied_wani_meth_f,                         /* method field            */
   ied_wani_len_userid,                     /* length of userid        */
   ied_wani_data_userid,                    /* content of userid       */
   ied_wani_len_password,                   /* length of password      */
   ied_wani_data_password,                  /* content of password     */
   ied_wani_seen_st,                        /* start server entry      */
   ied_wani_seen_method,                    /* method server entry     */
   ied_wani_seen_stio,                      /* status input output     */
   ied_wani_seen_len,                       /* length field server entry */
   ied_wani_seen_data,                      /* data UTF-8 server-entry */
   ied_wani_proc_data,                      /* process the data        */
   ied_wani_lenient_recv                    /* received from client    */
};

#ifdef XYZ1
/* enum for WSP authentication header keyword                          */
enum ied_wanhkw_value {                     /* WSP authentication header keyword value */
   ied_wanhkw_invalid = 0,                  /* value is invalid        */
   ied_wanhkw_language,                     /* value is language       */
   ied_wanhkw_userid,                       /* value is userid         */
   ied_wanhkw_password,                     /* value is password       */
   ied_wanhkw_server,                       /* value is server         */
   ied_wanhkw_krb5_ticket                   /* value is krb5-ticket    */
};

struct dsd_wsp_auth_1 {                     /* structure for authentication */
   BOOL       boc_notify;                   /* notify authentication routine */
   BOOL       boc_timed_out;                /* received timed out      */
   BOOL       boc_connect_active;           /* connect active now      */
   BOOL       boc_did_connect;              /* did connect             */
   int        imc_connect_error;            /* connect error           */
   BOOL       boc_rec_from_server;          /* receive from server     */
   BOOL       boc_http;                     /* check HTTP              */
#ifdef XYZ1
   union {
     struct dsd_wsp_auth_normal dsc_wan;    /* normal authentication   */
   };
// to-do 03.12.11 KB
   char       chrc_filler[ 4 ];
#endif
#ifndef B140717
   BOOL       boc_auth_ended;               /* authentication has ended */
#endif
};

struct dsd_wsp_auth_normal {                /* normal authentication   */
   enum ied_wan_input_1 iec_wani;           /* state WSP authentication normal input */
   int        imc_inp_proc;                 /* save input processed    */
   char       *achc_protocol;               /* save protocol here      */
   int        imc_len_protocol;             /* set length received protocol */
// ied_hkw_value iec_hkw_value;             /* save value of header keyword */
   BOOL       boc_hkw_language;             /* language set in header  */
   int        imc_language;                 /* language selected       */
   BOOL       boc_hkw_userid;               /* userid set in header    */
   char       *achc_userid;                 /* save userid here        */
   int        imc_len_userid;               /* set length received userid */
   BOOL       boc_hkw_password;             /* password set in header  */
   char       *achc_password;               /* save password here      */
   int        imc_len_password;             /* set length received password */
   BOOL       boc_hkw_server;               /* server set in header    */
   char       *achc_stor_servent;           /* storage server entry    */
   int        imc_len_servent;              /* set length received server */
   BOOL       boc_hkw_krb5_ticket;          /* kerberos-5 ticket in header */
   char       *achc_stor_krb5_ticket;       /* storage kerberos-5 ticket */
   int        imc_len_krb5_ticket;          /* set length received kerberos-5 ticket */
// int      imc_no_radius;                  /* number of radius server */
// int      imc_no_usgro;                   /* number of user groups   */
// en_at_claddrtype iec_claddrtype;       /* type of client INETA    */
// void *   avoc_client_netaddr;          /* pointer to client INETA */
// struct dsd_radius_conf *adsc_radius_conf;
// ied_radq_input1 iec_rqi;               /* status input data strea */
   int        imc_inpds_v1;                 /* value 1 input data stream */
   int        imc_inpds_v2;                 /* value 2 input data stream */
   int        imc_inpds_v3;                 /* value 3 input data stream */
   int        imc_inpds_v4;                 /* value 4 input data stream */
   enum ied_scp_def iec_scp_def;            /* server-conf protocol    */
   enum ied_wanhkw_value iec_wanhkw;        /* WSP authentication header keyword value */
   BOOL       boc_varstor_name;             /* name for variable storage */
   BOOL       boc_varstor_password;         /* password for variable storage */
   char       chc_type_input;               /* input requested from client */
   struct dsd_user_entry **aadsc_usent;     /* user entry              */
   struct dsd_user_group **aadsc_usgro;     /* user group              */
};
#endif

/* enum for WSP authentication header keyword                          */
enum ied_wanhkw_value {                     /* WSP authentication header keyword value */
   ied_wanhkw_invalid = 0,                  /* value is invalid        */
   ied_wanhkw_language,                     /* value is language       */
   ied_wanhkw_userid,                       /* value is userid         */
   ied_wanhkw_password,                     /* value is password       */
   ied_wanhkw_host,                         /* value is host           */
   ied_wanhkw_device,                       /* value is device         */
   ied_wanhkw_appl,                         /* value is appl           */
   ied_wanhkw_flags,                        /* value is flags          */
   ied_wanhkw_server,                       /* value is server         */
   ied_wanhkw_krb5_ticket                   /* value is krb5-ticket    */
};

struct dsd_wsp_auth_1 {                     /* structure for authentication */
   BOOL       boc_notify;                   /* notify authentication routine */
   BOOL       boc_timed_out;                /* received timed out      */
   BOOL       boc_connect_active;           /* connect active now      */
   BOOL       boc_did_connect;              /* did connect             */
   int        imc_connect_error;            /* connect error           */
   BOOL       boc_rec_from_server;          /* receive from server     */
   BOOL       boc_http;                     /* check HTTP              */
#ifdef XYZ1
   union {
     struct dsd_wsp_auth_normal dsc_wan;    /* normal authentication   */
   };
// to-do 03.12.11 KB
   char       chrc_filler[ 4 ];
#endif
#ifndef B140717
   BOOL       boc_auth_ended;               /* authentication has ended */
#endif
};

struct dsd_wsp_auth_normal {                /* normal authentication   */
   enum ied_wan_input_1 iec_wani;           /* state WSP authentication normal input */
   int        imc_inp_proc;                 /* save input processed    */
   char       *achc_protocol;               /* save protocol here      */
   int        imc_len_protocol;             /* set length received protocol */
// ied_hkw_value iec_hkw_value;             /* save value of header keyword */
   BOOL       boc_hkw_language;             /* language set in header  */
   int        imc_language;                 /* language selected       */
   BOOL       boc_hkw_userid;               /* userid set in header    */
   char       *achc_userid;                 /* save userid here        */
   int        imc_len_userid;               /* set length received userid */
   BOOL       boc_hkw_password;             /* password set in header  */
   char       *achc_password;               /* save password here      */
   int        imc_len_password;             /* set length received password */
   BOOL       boc_hkw_host;                 /* host set in header      */
   char       *achc_host;                   /* save host here          */
   int        imc_len_host;                 /* set length received host */
   BOOL       boc_hkw_device;               /* device set in header    */
   char       *achc_device;                 /* save device here        */
   int        imc_len_device;               /* set length received device */
   BOOL       boc_hkw_appl;                 /* appl set in header      */
   char       *achc_appl;                   /* save appl here          */
   int        imc_len_appl;                 /* set length received appl */
   BOOL       boc_hkw_flags;                /* flags set in header     */
   int        imc_value_flags;              /* value of flags          */
   BOOL       boc_hkw_server;               /* server set in header    */
   char       *achc_stor_servent;           /* storage server entry    */
   int        imc_len_servent;              /* set length received server */
   BOOL       boc_hkw_krb5_ticket;          /* kerberos-5 ticket in header */
   char       *achc_stor_krb5_ticket;       /* storage kerberos-5 ticket */
   int        imc_len_krb5_ticket;          /* set length received kerberos-5 ticket */
// int      imc_no_radius;                  /* number of radius server */
// int      imc_no_usgro;                   /* number of user groups   */
// en_at_claddrtype iec_claddrtype;       /* type of client INETA    */
// void *   avoc_client_netaddr;          /* pointer to client INETA */
// struct dsd_radius_conf *adsc_radius_conf;
// ied_radq_input1 iec_rqi;               /* status input data strea */
   int        imc_inpds_v1;                 /* value 1 input data stream */
   int        imc_inpds_v2;                 /* value 2 input data stream */
   int        imc_inpds_v3;                 /* value 3 input data stream */
   int        imc_inpds_v4;                 /* value 4 input data stream */
   enum ied_scp_def iec_scp_def;            /* server-conf protocol    */
   enum ied_wanhkw_value iec_wanhkw;        /* WSP authentication header keyword value */
   BOOL       boc_varstor_name;             /* name for variable storage */
   BOOL       boc_varstor_password;         /* password for variable storage */
   char       chc_type_input;               /* input requested from client */
   struct dsd_user_entry **aadsc_usent;     /* user entry              */
   struct dsd_user_group **aadsc_usgro;     /* user group              */
};

struct dsd_csssl_oper_1 {                   /* operation of client-side SSL */
#ifdef CSSSL_060620
   struct dsd_hl_ssl_c_1 dsc_hlcl01s;       /* structure for SSL       */
   BOOL       boc_sslc;                     /* ssl handshake complete  */
   BOOL       boc_error;                    /* error occured           */
#else
// 20.06.06 KB nonsense
  int   imc_port;                           /* UDP/IP port twin        */
#endif
};

#ifdef OLD01
struct dsd_wspadm1_session {                /* WSP Administration Session */
   struct dsd_wspadm1_session *adsc_next;   /* chain to next entry     */
   HL_WCHAR   *awcc_gate_name;              /* address gate name       */
   HL_WCHAR   *awcc_serv_ent;               /* address name Server Entry */
   int        imc_session_no;               /* session number          */
   char       chrc_ineta[40];               /* internet-address char   */
   int        ipc_time_start;               /* time session started    */
   int        imc_c_ns_rece_c;              /* count receive client    */
   int        imc_c_ns_send_c;              /* count send client       */
   int        imc_c_ns_rece_s;              /* count receive server    */
   int        imc_c_ns_send_s;              /* count receive server    */
   int        imc_c_ns_rece_e;              /* count encrypted from cl */
   int        imc_c_ns_send_e;              /* count encrypted to clie */
   HL_LONGLONG ilc_d_ns_rece_c;             /* data receive client     */
   HL_LONGLONG ilc_d_ns_send_c;             /* data sent client        */
   HL_LONGLONG ilc_d_ns_rece_s;             /* data receive server     */
   HL_LONGLONG ilc_d_ns_send_s;             /* data sent server        */
   HL_LONGLONG ilc_d_ns_rece_e;             /* data receive encyrpted  */
   HL_LONGLONG ilc_d_ns_send_e;             /* data sent encrypted     */
   HL_WCHAR   *awcc_name_cert;              /* address name from certificate */
   HL_WCHAR   *awcc_userid;                 /* address userid          */
   HL_WCHAR   *awcc_user_group;             /* address name user group */
};
#endif

#ifdef D_FUNC01
enum en_auth_type { en_auty_none, en_auty_ace, en_auty_safeword };

#endif
/* enum for pass thru to desktop in radius                             */
enum ied_pttd_conf1 { ied_pttdc_nothing,    /* normal processing       */
                      ied_pttdc_do,         /* do pttd                 */
                      ied_pttdc_avendsp1,   /* do from attr vendor sp  */
                      ied_pttdc_attr116     /* do from attr 116        */
};

/* enum for send certificate to Radius Server                          */
enum ied_rasc_conf1 {
   ied_rasc_nothing,                        /* normal processing       */
   ied_rasc_avendsphob1                     /* do from attr vendor specific */
};

#ifdef B111218
struct dsd_radius_conf {                    /* radius configuration    */
   enum ied_pttd_conf1 iec_pttd_conf1;      /* pass thru to deskt conf */
   enum ied_rasc_conf1 iec_rasc_conf1;      /* send certificate        */
   int        inc_language;                 /* language of dialogue    */
};
#endif

/* new 12.10.04 KB - start UUUU */
enum ied_seli_e_def { ied_seli_invalid, ied_seli_defined, ied_seli_referenced };

#ifndef HL_KRB5
/* immediately after this structure there is the name, UTF-16, zero-terminated */
struct dsd_server_list_1 {                  /* list of servers         */
   struct dsd_server_list_1 *adsc_next;     /* chaining                */
   struct dsd_server_conf_1 *adsc_server_conf_1;  /* server configurat */
   int        inc_len_name;                 /* length of name bytes    */
   enum ied_seli_e_def iec_seli;            /* status of server-list   */
   DOMNode    *adsc_seli_node;              /* node from XML           */
};
#endif

/* immediately after this structure there are the Server-Data-Hook entries.
   then there are the Radius servers
   then there are the LDAP entries.
   then there is the name, UTF-16, zero-terminated;
   then there is the protocol, UTF-16, zero-terminated, if variable
   at last there is the DNS name of the server ASCII-850
   for new DNS-lookup and client-side-SSL
*/
// to-do 25.05.14 - memory for DNS name as needed for SSL certificated check

/**
   temporary struct dsd_server_conf_1 needs to get freed after some delay
   there is a timer structure, but adsc_seco1_previous still needs to stay accessable
*/

#define IMD_SERVER_CONF_1 (sizeof(struct dsd_server_conf_1) - sizeof(struct dsd_timer_ele))

struct dsd_server_conf_1 {                  /* configuration server    */
   struct dsd_server_conf_1 *adsc_next;     /* chaining                */
   int        imc_no_radius;                /* number of radius server */
   int        imc_no_ldap_group;            /* number of LDAP groups   */
   int        inc_len_name;                 /* length of name bytes    */
   int        inc_len_protocol;             /* length of protocol bytes */
   int        imc_len_dns_name;             /* length of DNS name      */
#ifdef DOES_NOT_WORK
   struct dsd_ldap_group *adsrc_ldap_group[];  /* LDAP groups          */
#endif
#ifdef B111219
   struct dsd_radius_entry **adsrc_radius_entry;  /* Radius entries    */
#endif
   struct dsd_ldap_group **adsrc_ldap_group;  /* LDAP groups           */
   HL_WCHAR   *awcc_name;                   /* address of name         */
   HL_WCHAR   *awcc_protocol;               /* address of protocol     */
   char       *achc_dns_name;               /* address of DNS name     */
   struct dsd_server_conf_1 *adsc_seco1_previous;  /* configuration server previous */
   BOOL       boc_dns_lookup_before_connect;  /* needs to solve INETA before connect */
   BOOL       boc_dynamic;                  /* dynamically allocated   */
   int        inc_function;                 /* function to process     */
#ifndef OLD01
   struct dsd_target_ineta_1 *adsc_server_ineta;  /* server INETA      */
#else
   UNSIG_MED  umc_server_ineta;             /* IP-addr where to conn   */
#endif
   int        inc_server_port;              /* TCP/IP port connect     */
#ifdef B070917
   UNSIG_MED  umc_out_ineta;                /* IP address multihomed   */
#else
   struct dsd_bind_ineta_1 dsc_bind_out;    /* IP address multihomed   */
#endif
   BOOL       boc_use_csssl;                /* use client-side-SSL     */
   BOOL       boc_use_ineta_appl;           /* use HTCP                */
   BOOL       boc_connect_round_robin;      /* do connect round-robin <connect-round-robin> */
   struct dsd_targfi_1 *adsc_targfi_1;      /* target-filter           */
   char       chrc_ppp_auth[ DEF_NO_PPP_AUTH ];  /* configured <PPP-authentication-method> */
#ifdef B150520
   BOOL       boc_check_cert;               /* do-not-check-certificate */
#endif
//#define B090411
#ifdef B090411
   struct dsd_ldap_group *adsc_ldap_group;  /* definition LDAP group   */
#endif
   struct dsd_l2tp_conf *adsc_l2tp_conf;    /* L2TP connection configuration */
   enum ied_scp_def iec_scp_def;            /* server-conf protocol    */
   UNSIG_MED  umc_s_nw_ineta;               /* server-network-ineta    */
   UNSIG_MED  umc_s_nw_mask;                /* server-network-mask     */
   int        inc_timeout;                  /* timeout in seconds      */
   int        inc_wts_br_port;              /* port for broadcast LB f */
   int        inc_wts_time1;                /* timer wait all          */
   int        inc_wts_time2;                /* timer wait any          */
   struct dsd_wtsg_1 *adsc_wtsg1;           /* for WTSGATE             */
   BOOL       boc_wts_check_name;           /* check name logon WTS    */
   BOOL       boc_is_blade_server;          /* function BLADEGATE      */
   BOOL       boc_hc_proxauth;              /* HOBCOM proxy communic   */
#ifdef B090516
   BOOL       boc_disa_ns_cl;               /* disable-naegle-send-client */
#endif
   enum ied_naeg1_def iec_naeg1_cl;         /* disable-naegle-send-client */
#ifdef B090516
   BOOL       boc_disa_ns_se;               /* disable-naegle-send-server */
#endif
   enum ied_naeg1_def iec_naeg1_se;         /* disable-naegle-send-server */
   BOOL       boc_conn_other_se;            /* option-connect-other-server */
   int        inc_no_sdh;                   /* no server-data-hook     */
   BOOL       boc_sdh_reflect;              /* only Server-Data-Hook   */
#ifdef B111219
   struct dsd_radius_conf dsc_radius_conf;  /* radius configuration    */
#endif
#ifndef B140703
   BOOL       boc_sstc_not_check_channel_bindings;  /* do not check channel binding for SSTP */
#endif
};

#ifdef B120708
#ifdef HL_UNIX
union dsd_un_soaddr_1 {
#ifdef HL_IPV6
   struct sockaddr_storage dsc_sost1;       /* for listen, use bigger size because of ipv6 */
#endif
   struct sockaddr_in dsc_soad1;            /* client address informat */
};

struct dsd_open_listen_param {              /* parameters for open listen */
   int        imc_listen_port;              /* port of listen          */
   int        imc_listen_fd;                /* file descriptor         */
   int        imc_ligw_userfld;             /* listen-gateway user-field */
   BOOL       boc_ipv6;                     /* is IPV6                 */
   int        inc_ai_addrlen;               /* from struct addrinfo    */
   union dsd_un_soaddr_1 dsc_un_soaddr_1;   /* for listen              */
};
#endif
#endif

enum ied_opli_ret {                         /* return from open listen */
   ied_oplir_abend,                         /* abend / exit of program */
   ied_oplir_ok,                            /* o.k. - succeeded        */
   ied_oplir_failure                        /* function failed         */
};

#ifndef B080407
#ifdef __cplusplus
struct dsd_send_gai1_1 {                    /* block passed to TCPCOMP m_send_gather() */
   struct dsd_gather_i_1 dsc_gai1_send;     /* gather input data to send */
   struct dsd_gather_i_1 *adsc_gai1_org;    /* gather input data origin */
};
#endif

#ifndef HL_UNIX
//#define DEF_INCL_LISTEN
#endif
#ifdef INCL_GW_LISTEN
#define DEF_INCL_LISTEN
#endif
#ifdef DEF_INCL_LISTEN
#undef DEF_INCL_LISTEN
struct dsd_gate_listen_1 {                  /* listen part of gateway  */
   struct dsd_gate_listen_1 *adsc_next;     /* chain of listen part of gateway */
   struct dsd_gate_1 *adsc_gate_1;          /* gate of this listen     */
   BOOL       boc_active;                   /* listen is active        */
   int        imc_socket;                   /* socket of listen        */
   struct sockaddr_storage dsc_soa;         /* address information listen */
#ifdef B110925
#ifndef HL_UNIX
#ifdef __cplusplus
   class dsd_nblock_acc *adsc_acc_lis;      /* accept structure        */
#else
   void *     adsc_acc_lis;                 /* accept structure        */
#endif
#else
   class dsd_nblock_acc dsc_acc_lis;        /* non-blocking accept structure */
#endif
#else
   class dsd_nblock_acc dsc_acc_listen;     /* non-blocking accept structure */
#endif
};
#endif
#endif

#ifndef INCL_GW_EXTERN
/* immediately after this structure there is the name, UTF-16, zero-terminated */
/* then there is the HTTP-redirect-library                             */
/* then there are the plain-HTTP-libraries                             */
/* then there are the Server-Lists                                     */
/* then there are the User-Groups                                      */
/* then there are the Radius groups                                    */
/* then there are the Kerberos 5 KDC entries                           */
/* then there are the LDAP entries                                     */
/* then there is is the <Kerberos-5-service-principal-name>, UTF-8 = ASCII, ANSI, not zero-terminated */
/* at last there is the <permanently-moved-URL>, UTF-8 = ASCII, ANSI, not zero-terminated */
struct dsd_gate_1 {                         /* gateway listening       */
   struct dsd_gate_1 *adsc_next;            /* chain                   */
   struct dsd_loconf_1 *adsc_loconf_1;      /* load configuration file */
#ifndef B080407
   struct dsd_gate_listen_1 *adsc_gate_listen_1_ch;  /* chain of listen part of gateway */
#endif
   BOOL       boc_gate_closed;              /* gate is closed          */
   int        inc_len_name;                 /* length name in bytes    */
   int        imc_len_permmov_url;          /* length URL in bytes     */
   int        imc_len_krb5_princ;           /* length krb5 service principal in bytes */
   int        imc_no_phl;                   /* number of plain-HTTP-libraries */
   int        inc_no_seli;                  /* number of server lists  */
   int        inc_no_usgro;                 /* number of user groups   */
   int        imc_no_radius;                /* number of radius groups */
   int        imc_no_rpc;                   /* number of RPC groups    */
   int        imc_no_krb5_kdc;              /* number of Kerberos 5 KDCs */
   int        imc_no_ldap_group;            /* number of LDAP groups   */
   int        imc_no_rpc_dc;                /* number of RPC-DC        */
   int        imc_no_domain_info;           /* number of domain informations */
#ifdef DOES_NOT_WORK
   struct dsd_server_list_1 *adsrc_server_list_1[];  /* list of servers */
   struct dsd_user_group *adsrc_user_group[];  /* user group entries   */
   struct dsd_radius_entry *adsrc_radius_entry[];  /* Radius entries   */
   struct dsd_krb5_kdc_1 *adsrc_krb5_kdc_1[];  /* Kerberos 5 KDCs      */
   struct dsd_ldap_group *adsrc_ldap_group[];  /* LDAP groups          */
#endif
   struct dsd_hrl_conf_1 *adsc_hrl_conf_1;  /* HTTP-redirect-library configuration */
   struct dsd_phl_conf_1 *adsc_phl_conf_1;  /* list of plain-HTTP-library configurations */
   struct dsd_server_list_1 **adsrc_server_list_1;  /* list of servers */
   struct dsd_user_group **adsrc_user_group;  /* user group entries    */
   struct dsd_radius_group **adsrc_radius_group;  /* Radius groups     */
   struct dsd_rpc_group **adsrc_rpc_group;    /* RPC groups            */
   struct dsd_krb5_kdc_1 **adsrc_krb5_kdc_1;  /* Kerberos 5 KDCs       */
   struct dsd_ldap_group **adsrc_ldap_group;  /* LDAP groups           */
   void *     adsrc_rpc_dc;
   struct dsd_domain_info_1 **adsrc_domain_info;  /* domain information */
   char       *achc_permmov_url;            /* address of URL          */
   char       *achc_krb5_princ;             /* address of krb5 service principal */
   struct dsd_krb5_keytab *adsc_krb5_keytab;  /* Kerberos 5 keytab file */
#ifdef B111219
   struct dsd_radius_conf dsc_radius_conf;  /* radius configuration    */
#endif
#ifdef B080609
   struct dsd_hlwspat2_lib1 *adsc_hlwspat2_lib1;  /* authentication library */
#endif
#ifdef OLD_1112
   struct dsd_ext_lib1 *adsc_hobwspat2_ext_lib1;  /* external library loaded for HOBWSPAT2 */
   void *     vpc_hlwspat2_conf;            /* configuration authentication library */
#else
   struct dsd_ext_lib1 *adsc_hobwspat3_ext_lib1;  /* external library loaded for HOB-WSP-AT3 */
   void *     vpc_hobwspat3_conf;           /* configuration authentication library */
#endif
#ifdef NOT_YET_130508
/* for kerberos sign on over WSM - WSP-socks-mode */
   char       *achc_keytab;                 /* address keytab          */
   int        imc_len_keytab;               /* length keytab           */
/* -or- */
   struct dsd_krb5_keytab *adsc_krb5_keytab;
#endif
//#define B090411
#ifdef B090411
   struct dsd_krb5_kdc_1 *adsc_krb5_kdc_1;  /* definition Kerberos 5 KDC */
   struct dsd_ldap_group *adsc_ldap_group;  /* definition LDAP group   */
#endif
#ifdef B080407
#ifndef HL_UNIX
   int        inc_listen_socket;            /* socket for accepting co */
#else
   int        imc_listen_fd;                /* file descriptor for accepting connections */
   int        imc_ligw_userfld;             /* listen-gateway user-field */
#endif
#endif
   enum ied_conn_type_def iec_coty;         /* connection type         */
   int   ifunction;                         /* function to process     */
#ifdef B080407
   int   igateport;                         /* TCP/IP port listen      */
   int   ibacklog;                          /* TCP/IP backlog listen   */
#endif
#ifndef B080407
   int        imc_gateport;                 /* TCP/IP port listen      */
   int        imc_permmov_from_port;        /* <permanently-moved-from-port> */
   int        imc_permmov_to_port;          /* <permanently-moved-to-port> */
   int        imc_backlog;                  /* TCP/IP backlog listen   */
#endif
   BOOL       boc_not_close_lbal;           /* do not close listen by load-balancing */
   int        imc_language;                 /* language of dialogue    */
#ifdef B080407
//#ifdef OLD01
   UNSIG_MED ul_in_ineta;                   /* IP address multihomed   */
//#endif
#endif
#ifdef D_FUNC01
   void  *ad_auth_startup;                  /* returned from auth sta  */
   en_auth_type ienauty;                    /* type of authentication  */
   en_at_funcauth ienatfa;                  /* parm1 value             */
#endif
#ifndef HL_UNIX
   CRITICAL_SECTION dcritsect;              /* critical section        */
#else
#ifdef B110801
   BOOL       boc_ipv6;                     /* this listen with IPV6   */
   struct t_bind dsc_bind_lis;              /* for listen              */
   struct t_call dsc_call_lis;              /* for listen              */
   union dsd_un_soaddr_1 dsc_un_soaddr_1;   /* for listen              */
   class dsd_hcla_critsect_1 dsc_critsect;  /* critical section        */
   amd_proc_fdcompl amc_proc_fdcompl;       /* routine to process poll complete */
#else
   class dsd_hcla_critsect_1 dsc_critsect;  /* critical section        */
#endif
#endif
   int   itimeout;                          /* timeout in seconds      */
   int        imc_thresh_session;           /* threshold-session       */
// BOOL       boc_cur_thresh_session;       /* currently over threshold-session */
// int        imc_epoch_thresh_se_notify;   /* last time of threshold-session notify */
   int   i_session_max;                     /* maximum number of sess  */
   int   i_session_cos;                     /* count start of session  */
   int   i_session_cur;                     /* current number of sess  */
   int   i_session_mre;                     /* maximum no sess reached */
   int   i_session_exc;                     /* number max session exce */
   void *     vpc_configid;                 /* from SSL register config */
   struct dsd_server_conf_1 *adsc_server_conf_1;  /* configuration server */
   struct dsd_targfi_1 *adsc_targfi_1;      /* target-filter           */
   void  *ad_auth_startup;                  /* returned from auth sta  */
#ifdef B080609
   struct DAUTHLIB1 *ad_authlib1;           /* library used for auth   */
#endif
#ifdef B081201
   BOOL       boc_disa_ns_cl;               /* disable-naegle-send-client */
#endif
   enum ied_naeg1_def iec_naeg1_cl;         /* disable-naegle-send-client */
#ifdef B081201
   BOOL       boc_disa_ns_se;               /* disable-naegle-send-server */
#endif
   enum ied_naeg1_def iec_naeg1_se;         /* disable-naegle-send-server */
   int        imc_snmpt_epoch_conn_maxconn;  /* SNMP Trap epoch connection maxconn reached */
   int        imc_snmpt_epoch_conn_thresh;  /* SNMP Trap epoch connection threshold reached */
#ifdef NOTYET050819
#ifndef HL_UNIX
   en_at_funcauth ienatfa;                  /* parm1 value             */
#endif
#endif
#ifdef B081201
#ifndef HL_UNIX
#ifdef OLD01
   class cThreads clthaccept;               /* thread                  */
#endif
   class dsd_hcthread clthaccept;           /* thread                  */
#endif
#endif
#ifdef OLD01
#ifdef HL_UNIX
#ifdef HL_IPV6
   BOOL       boc_IPV6;                     /* IP V 6 used             */
#endif
   HL_WCHAR   *agatename;                   /* name of gateway         */
#endif
#endif
};

struct dsd_domain_info_1 {                  /* domain information      */
   struct dsd_unicode_string dsc_ucs_dns_domain_name;  /* server-DNS-domain-name */
   struct dsd_unicode_string dsc_ucs_dns_computer_name;  /* server-DNS-computer-name */
   struct dsd_unicode_string dsc_ucs_dns_tree_name;  /* server-DNS-tree-name */
   struct dsd_unicode_string dsc_ucs_netbios_domain_name;  /* NetBIOS-domain-name */
   struct dsd_unicode_string dsc_ucs_permmov_url;  /* permanently-moved-URL */
#ifndef B160423
   struct dsd_unicode_string dsc_ucs_group_id;  /* group Id            */
   struct dsd_unicode_string dsc_ucs_auth_token;  /* authentication token */
#endif
   struct dsd_unicode_string dsc_ucs_comment;  /* comment              */
   int        imc_no_dotted_ineta;          /* number of server-dotted-ineta */
   int        imc_no_dns_ineta;             /* number of server-DNS-ineta */
   struct dsd_unicode_string *adsc_ucs_dotted_ineta;  /* array of server-dotted-ineta */
   struct dsd_unicode_string *adsc_ucs_dns_ineta;  /* array of server-DNS-ineta */
   enum ied_dom_inf_auth_type iec_diat;     /* domain information authentication-type */
   BOOL       boc_use_full_pm_url;          /* use-full-permanently-moved-URL */
   BOOL       boc_use_as_default;           /* use-as-default          */
};
#endif

#ifdef OLD01
#ifndef HL_UNIX
/* The following structure contains data for a thread becoming idle,
   this thread will get new work from this queue.                      */
struct DWAITT {                             /* wait for thread         */
   struct DWAITT *next;                     /* chain                   */
   class clconn1 *ad_clconn1;               /* what to process         */
   class clworkth *adsc_workthr;            /* thread that waits       */
};
#endif
#endif

#ifdef B080924
enum ied_type_send_server_def {             /* type of send to server  */
   ied_tss_hpppt1
};

struct dsd_send_server_1 {                  /* for send to server      */
   struct dsd_send_server_1 *adsc_next;     /* for chaining            */
   struct dsd_sdh_control_1 *adsc_sdhc1_send;  /* send buffers, needed for garbage collection */
   ied_type_send_server_def iec_tss;        /* type of send to server  */
};
#endif

enum ied_radius_e_def { ied_red_invalid, ied_red_defined, ied_red_referenced };

#ifndef HL_KRB5
#ifdef OLD_1112
struct dsd_radius_entry {                   /* radius entry            */
   struct dsd_radius_entry *adsc_next;      /* for chaining            */
   enum ied_radius_e_def iec_red;           /* status of radius entry  */
   int        inc_port;                     /* port of radius server   */
   int        inc_len_name;                 /* length of name bytes    */
   int        inc_len_shasec;               /* length of shared secret */
#ifndef B080322
   struct dsd_udp_param_1 dsc_udp_param_1;  /* definition UDP parameter radius */
   struct dsd_radius_recvfrom *adsc_rarf;   /* radius recvfrom         */
#else
   UNSIG_MED  umc_radius_ineta;             /* INETA of radius server  */
   UNSIG_MED  umc_multih_ineta;             /* INETA of this multihom  */
   struct dsd_radius_thread *adsc_rathr;    /* radius thread           */
#endif
   DOMNode    *adsc_radius_node;            /* node from XML           */
   HL_WCHAR   *awcc_radius_s_gate_ineta;    /* value INETA gate        */
   HL_WCHAR   *awcc_radius_s_radius_ineta;  /* value INETA radius-serv */
   HL_WCHAR   *awcc_radius_s_port;          /* value port radius-serv  */
   int        inc_radius_s_timeout;         /* value timeout radius-se */
   char       chc_identifier;               /* identifier of query     */
   class dsd_radius_query *adsc_raque_chain;  /* chain active rad entr */
};
#else

#define DEF_RADIUS_TIMEOUT                  10  /* standard radius receive timeout */
#define DEF_RADIUS_TIME_LOCK                (5 * 60)  /* standard radius time to lock */
#define DEF_RADIUS_GROUP_OPTION_MS_CHAP_V2  0X01
#define DEF_RADIUS_LEN_REQ_AUTH             16
#define DEF_RADIUS_LEN_ATTR                 2048
#define DEF_RADIUS_LEN_STATE                1024
#ifndef B171207
#define DEF_RADIUS_LEN_REPLY_MESSAGE        256
#endif

/** immediately after this structure there is the name, UTF-8, not zero-terminated */
struct dsd_radius_group {                   /* radius group            */
   struct dsd_radius_group *adsc_next;      /* for chaining            */
   char       *achc_comment;                /* address comment         */
   struct dsd_radius_entry *adsc_radius_entry;  /* chain radius entry / single radius server */
   struct dsd_ldap_group *adsc_ldap_group;  /* corresponding LDAP group */
   struct dsd_radius_control_1 *adsc_rctrl1_queued;  /* radius control queued */
   int        imc_len_name;                 /* length of name bytes    */
   int        imc_len_comment;              /* length of comment bytes */
   int        imc_options;                  /* options                 */
   int        imc_timeout;                  /* timeout in seconds / wait for radius response */
   int        imc_retry_after_error;        /* configured time retry after error seconds */
   enum ied_charset iec_chs;                /* define character set    */
   enum ied_rasc_conf1 iec_rasc_conf1;      /* send certificate        */
   enum ied_pttd_conf1 iec_pttd_conf1;      /* pass thru to desktop configuration */
   int        imc_references;               /* references to this radius-group */
};

/** immediately after this structure there is the name, UTF-8, not zero-terminated */
struct dsd_radius_entry {                   /* radius entry / single radius server */
   struct dsd_radius_entry *adsc_next;      /* for chaining            */
   struct dsd_udp_multiw_1 *adsc_udp_multiw_1;  /* structure for multiple wait */
   struct dsd_radius_entry *adsc_re_chain;  /* for chain of networking */
   struct dsd_radius_control_1 *adsc_rc1_active;  /* currently active radius control */
   int        imc_len_name;                 /* length of name bytes    */
   int        imc_len_comment;              /* length of comment bytes */
   int        imc_len_shasec;               /* length of shared secret */
   int        imc_epoch_locked;             /* epoch radius server locked until */
   char       *achc_comment;                /* address comment         */
   char       *achc_shasec;                 /* address shared secret   */
   struct dsd_udp_param_1 dsc_udp_param_1;  /* definition UDP parameters radius */
   char       byrc_hmac_1[ 64 ];            /* for HMAC                */
   char       byrc_hmac_2[ 64 ];            /* for HMAC                */
   char       chc_identifier;               /* next identifier to use  */
};

struct dsd_radius_control_1 {               /* radius control          */
   struct dsd_radius_group *adsc_radius_group;  /* radius group        */
   struct dsd_radius_entry *adsc_radius_entry_act;  /* active radius entry / single radius server */
   struct dsd_radius_control_1 *adsc_rctrl1_queued;  /* radius control queued */
   void *     ac_conn1;                     /* address connection      */
   struct sockaddr *adsc_soa_client;        /* sockaddr of client      */
   struct dsd_hl_aux_radius_1 *adsc_rreq;   /* active radius request   */
   amd_radius_query_compl amc_radius_query_compl;  /* callback when radius request complete */
   HL_LONGLONG ilc_marked;                  /* marked radius-servers   */
   int        imc_no_radius_server;         /* number of radius-server */
   char       chc_identifier;               /* identifier used         */
   char       chrc_req_auth[ DEF_RADIUS_LEN_REQ_AUTH ];  /* Request Authenticator */
   int        imc_len_server_state;         /* length server state     */
   struct dsd_timer_ele dsc_timer;          /* timer for wait for timeout */
   char       chrc_attr[ DEF_RADIUS_LEN_ATTR ];  /* pass attributes    */
   char       chrc_server_state[ DEF_RADIUS_LEN_STATE ];  /* save server state */
   char       chrc_radius_msg_auth[ LEN_RADIUS_MSG_AUTH ];  /* save message authenticator output */
#ifndef B171207
   char       chrc_reply_message[ DEF_RADIUS_LEN_REPLY_MESSAGE ];  /* save reply message */
#endif
};
#endif

struct dsd_rpc_group {                      /* RPC group               */
   struct dsd_rpc_group *adsc_next;         /* for chaining            */
   struct dsd_rpc_server *adsc_rpc_server_ch;  /* chain of RPC servers */
   struct dsd_unicode_string dsc_ucs_group_name;  /* name of RPC group */
   struct dsd_unicode_string dsc_ucs_comment;  /* comment              */
   struct dsd_unicode_string dsc_ucs_domain;  /* domain name           */
   struct dsd_unicode_string dsc_ucs_net_domain;  /* network domain name */
   struct dsd_unicode_string dsc_ucs_userid;  /* userid / user name    */
   struct dsd_unicode_string dsc_ucs_password;  /* password            */
/* new 15.09.14 KB */
   struct dsd_unicode_string dsc_ucs_account;  /* account used         */
   int        imc_retry_after_error;        /* configured time retry after error seconds */
   BOOL       boc_not_encrypted;            /* communication is not encrypted */
};

struct dsd_rpc_server {                     /* RPC server              */
   struct dsd_rpc_server *adsc_next;        /* for chaining            */
   struct dsd_rpc_group *adsc_rpc_group;    /* belongs to RPC group    */
   struct dsd_unicode_string dsc_ucs_server_name;  /* name of RPC server */
   struct dsd_unicode_string dsc_ucs_comment;  /* comment              */
   struct dsd_unicode_string dsc_ucs_target_ineta;  /* INETA of RPC server */
   struct dsd_bind_ineta_1 dsc_bind_multih;  /* for bind multihomed    */
   struct dsd_target_ineta_1 *adsc_target_ineta;  /* INETA of RPC server */
// SMB-port RPC-port
   int        imc_port;                     /* port of RPC server      */
   int        imc_timeout_msec;             /* timeout in milliseconds */
   int        imc_epoch_locked;             /* epoch RPC server locked until */
};
#endif

#ifndef B080322
struct dsd_udp_multiw_1 {                   /* structure for multiple wait */
   int        imc_socket;                   /* UDP socket              */
#ifndef HL_UNIX
   WSAEVENT   dsc_event;                    /* WSA event for recv      */
#endif
   amd_udp_recv_compl amc_udp_recv_compl;   /* callback when receive complete */
   struct dsd_udp_recv_thr *adsc_udprthr_w1;  /* thread to do UDP receive */
};

struct dsd_radius_recvfrom {                /* radius recvfrom         */
   struct dsd_radius_recvfrom *adsc_next;   /* for chaining            */
   BOOL       boc_invalid;                  /* entry is invalid        */
   int        imc_len_soa_bind;             /* length sockaddr bind    */
// int        imc_family;                   /* IPV4 / IPV6             */
   struct sockaddr_storage *adsc_soa_bind;  /* address information bind */
   struct dsd_udp_multiw_1 dsc_udp_multiw_1;  /* structure for multiple wait */
};
#else
struct dsd_radius_thread {                  /* radius thread           */
   struct dsd_radius_thread *adsc_next;     /* for chaining            */
   UNSIG_MED umc_multih_ineta;              /* INETA of this multihom  */
   BOOL       boc_invalid;                  /* entry is invalid        */
#ifndef HL_UNIX
   int        imc_socket;                   /* UDP socket              */
#ifdef OLD01
   class cThreads dscthr;                   /* thread process radius   */
#endif
   class dsd_hcthread dscthr;               /* thread process radius   */
#else
   int        imc_fd;                       /* UDP file descriptor     */
   amd_proc_fdcompl amc_proc_fdcompl;       /* routine to process poll complete */
#ifdef XYZ2
   class dsd_hcthread dscthr;               /* thread process radius   */
#endif
#endif
};
#endif

#ifdef OLD_1112
struct dsd_recudp1 {                        /* WTS UDP received        */
   struct dsd_recudp1 *adsc_next;           /* next in chain           */
   UNSIG_MED  umc_ineta;                    /* IP-addr where LB        */
   int        imc_reclen;                   /* length data received    */
};
#endif

#ifdef D_INCL_AUX_UDP
struct dsd_wts_lbal_netw {                  /* loadbalancing networking */
   struct dsd_wts_udp_1 *adsc_wsp_udp_1;    /* WTS UDP - also means in use */
   struct dsd_udp_multiw_1 dsc_udp_multiw_1;  /* structure for multiple wait */
};

struct dsd_wts_udp_1 {                      /* WTS UDP                 */
#ifdef OLD_1112
#ifdef B060616
   struct sockaddr_in dclientin;
   int        imc_client_socket;            /* socket of client        */
#endif
   BOOL       boc_timer_set;                /* timer has been set      */
#ifdef OLD01
   BOOL bo_timer_expired;                   /* timer has expired       */
#endif
   BOOL       boc_udp_close_active;         /* UDP socket close in progress */
#ifndef HL_UNIX
   int        imc_udp_socket;               /* socket for UDP          */
   BOOL       boc_started;                  /* thread has been started */
#else
   int        imc_save_fd_s;                /* save file-descriptor server */
   struct dsd_sendudp_1 *adsc_sendudp1;     /* send to UDP waiting     */
#endif
   BOOL       boc_udp_closed;               /* UDP socket closed       */
   struct dsd_recudp1 *adsc_recudp1;        /* chain of data received  */
#endif
   int        imc_no_target;                /* number of targets       */
   BOOL       boc_timer_set;                /* timer has been set      */
   void *     ac_conn1;                     /* address connection      */
   struct dsd_sdh_control_1 *adsc_sdhc1_rec;  /* received UDP packets  */
   struct dsd_wts_lbal_netw dsc_wln_ipv4;   /* loadbalancing networking IPV4 */
   struct dsd_wts_lbal_netw dsc_wln_ipv6;   /* loadbalancing networking IPV6 */
};
#endif

#ifndef INCL_GW_EXTERN
enum ied_usgro_e_def { ied_ugd_invalid, ied_ugd_defined, ied_ugd_referenced };

/*
   structure for users of configuration.
   storage following this structure:
   1. User-Name    WCHAR zero-terminated
      -- storage is aligned for sizeof(void *)
   2. Entries Server-List
*/
struct dsd_user_group {                     /* structure user group    */
   struct dsd_user_group *adsc_next;        /* chain                   */
   struct dsd_server_list_1 **adsrc_server_list_1;  /* list of servers */
   enum ied_usgro_e_def iec_ugd;            /* status of user group    */
   int        inc_len_name;                 /* length of name bytes    */
   int        inc_no_seli;                  /* number of server lists  */
   char       chrc_priv[ (DEF_PERS_PRIV_LEN + 8 - 1) / 8 ];  /* privileges */
   UNSIG_MED  umc_out_ineta;                /* IP address multihomed   */
   DOMNode    *adsc_usgro_node;             /* node from XML           */
   struct dsd_targfi_1 *adsc_targfi_1;      /* target-filter           */
   struct dsd_user_entry *adsc_usere;       /* chain user entries      */
};

#ifdef B100403
/*
   structure for users of configuration.
   storage following this structure:
   1. User-Name    WCHAR zero-terminated
   2. Password     UTF-8
   3. INETA-target ASCII zero-terminated
   4. INETA-PPP    IPV4 = 4 / IPV6 = 16
   5. INETA-HTCP   IPV4 = 4 / IPV6 = 16
   6. INETA-SIP-gw IPV4 = 4 / IPV6 = 16
   7. SIP Ident    UTF-8
   8. SIP shared secret UTF-8
*/
struct dsd_user_entry {                     /* structure user entry    */
   struct dsd_user_entry *adsc_next;        /* chain                   */
   int        inc_len_name_bytes;           /* length of name in bytes */
   int        inc_len_password_bytes;       /* len of password in bytes */
   int        inc_len_target_bytes;         /* len of target in bytes  */
   char       chrc_priv[ (DEF_PERS_PRIV_LEN + 8 - 1) / 8 ];  /* privileges */
   UNSIG_MED  umc_out_ineta;                /* IP address multihomed   */
   BOOL       boc_with_target;              /* target is included      */
   int        inc_port_target;              /* target port             */
   BOOL       boc_with_macaddr;             /* macaddr is included     */
   char       chrc_macaddr[6];              /* macaddr switch on       */
   int        inc_waitconn;                 /* wait for connect compl  */
   int        imc_len_ineta_ppp;            /* length INETA PPP        */
   int        imc_len_ineta_appl;           /* length INETA HTCP       */
   int        imc_len_ineta_sip_gw;         /* length INETA SIP Gateway */
   int        imc_len_sip_ident;            /* length SIP ident        */
   int        imc_len_sip_shase;            /* length SIP shared secret */
};
#endif
/*
   structure for users of configuration.
   storage following this structure:
   1.  User-Name           WCHAR zero-terminated
   2.  Password            UTF-8
   3.  INETA-target        IDNA zero-terminated
   4.  INETA-SIP-gw        IPV4 = 4 / IPV6 = 16
   7.  SIP Fullname        UTF-8
   8.  SIP Ident           UTF-8
   9.  SIP display-number  UTF-8
   10. SIP shared secret   UTF-8
*/
struct dsd_user_entry {                     /* structure user entry    */
   struct dsd_user_entry *adsc_next;        /* chain                   */
   int        inc_len_name_bytes;           /* length of name in bytes */
   int        inc_len_password_bytes;       /* len of password in bytes */
   int        inc_len_target_bytes;         /* len of target in bytes  */
   char       chrc_priv[ (DEF_PERS_PRIV_LEN + 8 - 1) / 8 ];  /* privileges */
   UNSIG_MED  umc_out_ineta;                /* IP address multihomed   */
   BOOL       boc_with_target;              /* target is included      */
   int        inc_port_target;              /* target port             */
   BOOL       boc_with_macaddr;             /* macaddr is included     */
   char       chrc_macaddr[6];              /* macaddr switch on       */
   int        inc_waitconn;                 /* wait for connect compl  */
   int        imc_len_ineta_sip_gw;         /* length INETA SIP Gateway */
   int        imc_len_sip_fullname;         /* length SIP fullname     */
   int        imc_len_sip_ident;            /* length SIP ident        */
   int        imc_len_sip_display_number;   /* length SIP display-number */
   int        imc_len_sip_shase;            /* length SIP shared secret */
   char       *achc_password;               /* address of password     */
   char       *achc_target;                 /* address of target - INETA Desktop-on-Demand */
   char       *achc_ineta_sip_gw;           /* address of INETA SIP Gateway */
   char       *achc_sip_fullname;           /* address of SIP fullname */
   char       *achc_sip_ident;              /* address of SIP ident    */
   char       *achc_sip_display_number;     /* address of SIP display-number */
   char       *achc_sip_shase;              /* address of SIP shared secret */
#ifdef NEW_1406
   struct dsd_unicode_string dsc_e_mail;    /* unicode string e-mail address */
   struct dsd_unicode_string dsc_aux_1;     /* unicode string auxiliary field 1 */
#endif
   struct dsd_config_ineta_1 *adsc_config_ineta_1_ppp;  /* configured INETA PPP */
   struct dsd_config_ineta_1 *adsc_config_ineta_1_appl;  /* configured INETA appl */
};
#endif

/**
  structure from configuration, one entry for each wake-on-lan relay
*/
struct dsd_pttd_ineta {                     /* INETA relay for wake-on-lan */
   struct dsd_pttd_ineta *adsc_next;        /* next in chain           */
   HL_WCHAR   *awcc_def_xml;                /* definition in XML file  */
   int        inc_family;                   /* address family - IPV4 / IPV6 */
   int        inc_port;                     /* port UDP or -1          */
   char       chrc_ineta[16];               /* INETA                   */
};

#ifndef INCL_GW_EXTERN
#ifdef __cplusplus

#define DEF_NETW_POST_1_HTUN_CONN_ERR    1  /* posted for HTUN connect error */
#define DEF_NETW_POST_1_HTUN_CONN_OK     2  /* posted for HTUN connect ok */
#define DEF_NETW_POST_1_HTUN_SEND_COMPL  4  /* posted for HTUN HTCP send complete */
#define DEF_NETW_POST_1_HTUN_SESS_END    8  /* posted for HTUN HTCP session end */
#define DEF_NETW_POST_1_HTUN_FREE_R      16  /* posted for HTUN free resources */
//#define DEF_NETW_POST_1_TCPCOMP_CLEANUP  32  /* posted for TCPCOMP end of session */
#define DEF_NETW_POST_1_TCPCOMP_CONN_ERR 32  /* posted for TCPCOMP connect error */
#define DEF_NETW_POST_1_TCPCOMP_CONN_OK  64  /* posted for TCPCOMP connect ok */
#define DEF_NETW_POST_1_TCPCOMP_SEND_COMPL 128  /* posted for TCPCOMP send complete */
#define DEF_NETW_POST_1_TCPCOMP_CLEANUP  256  /* posted for TCPCOMP cleanup */

struct dsd_netw_post_1 {                    /* structure to post from network callback */
   class dsd_hcla_event_1 *adsc_event;      /* event to be posted      */
   volatile BOOL boc_posted;                /* event has been posted   */
   int        imc_select;                   /* select the events       */
};

struct dsd_conn_pttd_thr {                  /* connect PTTD thread     */
#ifdef OLD01
   class cThreads dsc_thread;               /* thread                  */
#endif
#ifdef B120213
#ifndef TRY_D_INCL_HTUN
// 10.08.10 KB use same as work thread
//#ifndef D_INCL_HTUN
   class dsd_hcthread dsc_thread;           /* thread                  */
   class dsd_hcla_event_1 dsc_event_thr;    /* event of thread         */
//#endif
#endif
#endif
#ifndef HL_UNIX
   class clconn1 *adsc_conn1;               /* for this connection     */
#else
   struct dsd_conn1 *adsc_conn1;            /* for this connection     */
#endif
   UNSIG_MED  umc_out_ineta;                /* IP address multihomed   */
   char       *achc_target;                 /* INETA target ied_chs_idna_1 */
   int        imc_len_target_bytes;         /* length of target in bytes */
   int        imc_port_target;              /* target port             */
   BOOL       boc_with_macaddr;             /* macaddr is included     */
   char       chrc_macaddr[6];              /* macaddr switch on       */
   int        imc_waitconn;                 /* wait for connect compl  */
//#ifdef D_INCL_HOB_TUN
#ifdef XYZ1
   struct dsd_auxf_1 *adsc_aux_htun;        /* auxiliary field for HOB-TUN */
// 10.08.10 KB dsc_tun_start1 goes to thread
   struct dsd_tun_start1 dsc_tun_start1;    /* HTUN start interface    */
#endif
   struct dsd_hco_wothr dsc_hco_wothr;      /* same as structure for work-thread */
   struct dsd_extra_thread_entry dsc_ete;   /* extra thread entry      */
#ifdef B120913
#ifndef HL_UNIX
// to-do 13.02.12 KB remove when new HOB-TUN in Windows
#ifdef D_INCL_HOB_TUN
   struct dsd_netw_post_1 dsc_netw_post_1;  /* structure to post from network callback */
#endif
#endif
#endif
};
#endif
#endif

struct dsd_conn_pttd_socket {               /* socket for wake-on-lan  */
   struct dsd_conn_pttd_socket *adsc_next;  /* chain                   */
#ifndef HL_UNIX
   int        inc_udp_socket;               /* socket for UDP broadcas */
#else
   int        inc_udp_socket;               /* socket for UDP broadcas */
// int        inc_udp_fd;                   /* file descriptor for UDP broadcast */
#endif
   UNSIG_MED  umc_multih_ineta;             /* INETA of this multihomed */
};

enum ied_lierr { ied_le_ignore, ied_le_wait, ied_le_abend };

#ifndef INCL_GW_EXTERN
// to-do 13.02.12 KB rename to PTTD or other, no more used for Radius
struct dsd_radius_control {                 /* Radius Control Structure */
#ifdef B120213
   struct dsd_radius_entry *adsc_raent_anchor;  /* chain radius entr   */
#ifndef B080322
   struct dsd_radius_recvfrom *adsc_rarf_anchor;  /* chain radius recvfrom */
#else
   struct dsd_radius_thread *adsc_rathr_anchor;  /* chain radius threa */
#endif
#endif
#ifndef HL_UNIX
   CRITICAL_SECTION dsc_critsect;           /* critical section        */
#else
   class dsd_hcla_critsect_1 dsc_critsect;  /* critical section        */
#endif
   int        imc_port_wol;                 /* port for wake-on-lan    */
#ifdef B060518
   UNSIG_MED  umc_wol_r_ineta;              /* IP-addr wol relay       */
#endif
   struct dsd_conn_pttd_socket *adsc_cpttdso;  /* chain of sockets     */
};

struct dsd_cdaux_control {                  /* control m_cdaux         */
   DOMNode    *adsc_node_conf;              /* part of configuration   */
};
#endif

#ifdef HL_UNIX
#ifndef HOB_CONTR_TIMER
/* The following structure is used for timers which are queued.        */
struct dsd_timer_ele {                      /* for timers / element    */
   HL_LONGLONG ilcwaitmsec;                 /* wait in milliseconds    */
   HL_LONGLONG ilcendtime;                  /* epoch end of timer      */
   void (* amc_compl) ( struct dsd_timer_ele * );  /* Completition Routine */
                                            /* call when timer expired */
   struct dsd_timer_ele *adsctiele_prev;    /* previous element        */
   struct dsd_timer_ele *adsctiele_next;    /* next element in chain   */
   void *     vpc_chain_2;                  /* only used by islcontr.cpp */
   struct dsd_timer_base *adsc_timer_base;  /* address of structure timer base */
};

/* The following structure is user for the timer functions             */
struct dsd_tich2_ele {                      /* for timers / chain 2    */
   HL_LONGLONG ilcwaitmsec;                 /* wait in milliseconds    */
   HL_LONGLONG ilcendtime;                  /* epoch end of timer      */
   struct dsd_tich2_ele *adsc_next;         /* for chaining            */
   struct dsd_timer_ele *adsctiele_first;   /* first element in chain  */
   struct dsd_timer_ele *adsctiele_last;    /* last element in chain   */
};
#endif
#endif

#ifndef INCL_GW_EXTERN
#ifdef __cplusplus
struct dsd_diskfile_1 {                     /* diskfile in memory      */
   struct dsd_diskfile_1 *adsc_next;        /* chaining                */
   int        inc_usage_count;              /* usage-count             */
   BOOL       boc_superseeded;              /* already new file        */
   enum ied_difi_def iec_difi_def;          /* status of entry         */
#ifndef HL_UNIX
   dsd_time_1 ipc_time_last_acc;            /* time last accessed      */
   dsd_time_1 ipc_time_last_checked;        /* time last checked       */
   HL_LONGLONG ilc_file_size;               /* size of this file       */
   struct _FILETIME dsc_filetime_last_mod;  /* time file last modified */
#else
   dsd_time_1 ipc_time_last_acc;            /* time last accessed      */
   dsd_time_1 ipc_time_last_checked;        /* time last checked       */
// dsd_time_1 ipc_time_last_mod;            /* time last modified      */
   HL_LONGLONG ilc_file_size;               /* size of this file       */
#endif
#ifdef B060709
   void *     vpc_lock_1;                   /* for lock                */
#endif
   struct dsd_hco_lock_1 dsc_lock_1;        /* for lock                */
   struct dsd_hl_int_diskfile_1 dsc_int_df1;  /* diskfile intern       */
};
#endif
#endif

#ifndef INCL_GW_EXTERN
/* structure to start WSP                                              */
struct dsd_wsp_startprog {                  /* pass parameters start program */
   DOMNode    *adsc_node_ass_conf;          /* Alert Sub-System Configuration */
};
#endif

enum ied_clr_stat  {                        /* cluster remote state    */
   ied_clrs_invalid,                        /* state is invalid        */
   ied_clrs_conn_recv_st,                   /* after connect start receive */
   ied_clrs_acc_recv_st,                    /* after accept start receive */
   ied_clrs_acc_init_sent,                  /* after control init has been sent */
   ied_clrs_open,                           /* state is open           */
   ied_clrs_send_end,                       /* state is send end       */
   ied_clrs_timed_out,                      /* state is timed out      */
   ied_clrs_closed                          /* state is closed         */
};

enum ied_cl_type {                          /* cluster data type       */
   ied_clty_invalid,                        /* type is invalid         */
   ied_clty_control,                        /* type is control         */
   ied_clty_end,                            /* type is end             */
   ied_clty_lbal,                           /* type is load-balancing  */
   ied_clty_cma,                            /* type is common memory area */
   ied_clty_vdi,                            /* type is VDI-WSP         */
   ied_clty_admin,                          /* type is adminstration   */
   ied_clty_ineta_req_ipv4,                 /* type is request with INETAs IPV4 */
   ied_clty_ineta_resp_ipv4,                /* type is response with INETAs IPV4 */
   ied_clty_ineta_rej_ipv4,                 /* type is reject for INETAs IPV4 */
   ied_clty_ineta_req_ipv6,                 /* type is request with INETAs IPV6 */
   ied_clty_ineta_resp_ipv6,                /* type is response with INETAs IPV6 */
   ied_clty_ineta_rej_ipv6                  /* type is reject for INETAs IPV6 */
};

/* main structure for the cluster                                      */
struct dsd_cluster_main {                   /* main cluster structure  */
   char       *achc_this_name;              /* name of this WSP, UTF-8 */
   char       *achc_this_group;             /* group of this WSP, UTF-8 */
   char       *achc_this_location;          /* location of this WSP, UTF-8 */
   char       *achc_this_url;               /* URL of this WSP, UTF-8  */
#ifdef HL_UNIX
   int        *aimc_alternate_ports;        /* alternate ports         */
#endif
   int        imc_this_len_name;            /* length of name in bytes */
   int        imc_this_len_group;           /* length of group in bytes */
   int        imc_this_len_location;        /* length of location in bytes */
   int        imc_this_len_url;             /* length of URL in bytes  */
#ifdef HL_UNIX
   int        imc_no_alternate_ports;       /* number of alternate ports */
#endif
   BOOL       boc_deny_not_configured;      /* deny connect in from not configured WSP */
   BOOL       boc_display_load;             /* display load every time calculated */
   int        imc_lbal_diff;                /* load-balancing-diff     */
   char       *achc_lbal_formula;           /* load-balancing-formula UTF-8 */
   int        imc_lbal_len_formula;         /* length of formula in bytes */
   int        imc_lbal_intv;                /* <interval-load-balancing-probe> */
   int        imc_recv_timeout;             /* receive timeout         */
   int        imc_time_retry_conn;          /* time retry connect      */
#ifdef B070917
   UNSIG_MED  umc_multih_ineta;             /* IP address multihomed   */
#endif
// struct dsd_bind_ineta_1 dsc_bind_multih;  /* for bind multihomed    */
   struct dsd_listen_ineta_1 *adsc_listen_ineta;  /* listen INETA      */
   int        imc_port;                     /* port of listen          */
   int        imc_backlog;                  /* TCP/IP backlog listen   */
   int        imc_socket_listen;            /* socket for listen       */
   struct dsd_cluster_remote *adsc_clre;    /* chain of remote WSPs    */
   struct dsd_cluster_listen *adsc_clli;    /* cluster structure listen */
};

/* structure remote WSPs of the cluster                                */
struct dsd_cluster_remote {                 /* cluster remote structure */
   struct dsd_cluster_main *adsc_cl_main;   /* pointer to main cluster structure */
   struct dsd_cluster_remote *adsc_next;    /* chain of remote WSPs    */
   char       *achc_name;                   /* name of remote WSP, UTF-8 */
   int        imc_len_name;                 /* length of name in bytes */
   int        imc_timeout_msec;             /* timeout in milliseconds */
   int        imc_recv_timeout;             /* receive timeout         */
#ifdef B070929
   ied_clr_stat iec_clr_stat;               /* state of connection     */
#endif
#ifdef B070917
   UNSIG_MED  umc_multih_ineta;             /* IP address multihomed   */
#endif
   struct dsd_bind_ineta_1 dsc_bind_multih;  /* for bind multihomed    */
   struct dsd_target_ineta_1 *adsc_remote_ineta;  /* remote INETA      */
   int        imc_port;                     /* port of remote WSP      */
#ifdef B070929
   int        imc_socket_tcp;               /* socket for listen       */
   HL_LONGLONG ilc_epoch_started;           /* time WSP started        */
#endif
};

/* structure cluster report                                            */
struct dsd_cluster_report {                 /* cluster report structure */
   BOOL       boc_cluster_active;           /* cluster is active       */
   int        imc_no_cluster_active;        /* number of active cluster connections */
   int        imc_no_same_group;            /* number of active cluster connections same group */
};

#ifdef INCL_GW_ALL
#ifdef __cplusplus
struct dsd_cluster_listen {                 /* cluster structure listen */
#ifdef HL_UNIX
   BOOL       boc_unix_socket;              /* is Unix domain socket   */
#endif
   struct dsd_cluster_main *adsc_cl_main;   /* pointer to main cluster structure */
#ifdef B110916
   class dsd_nblock_acc *adsc_acc_lis;      /* accept structure        */
#else
   class dsd_nblock_acc dsc_acc_listen;     /* accept structure        */
#endif
};
#endif
#endif

#ifdef INCL_GW_ALL
struct dsd_cluster_active {                 /* active cluster structure */
   struct dsd_cluster_active *adsc_next;    /* next in chain           */
#ifndef B130901
   struct dsd_cluster_active *adsc_proc_ch;  /* next in chain to get processed */
#endif
   enum ied_clr_stat iec_clr_stat;          /* state of connection     */
   BOOL       boc_proc_active;              /* processing is active    */
   BOOL       boc_recv_active;              /* receive is active       */
   BOOL       boc_same_group;               /* is in same group as main */
#ifdef HL_UNIX
   BOOL       boc_unix_socket;              /* is Unix domain socket   */
   int        imc_uds_pid;                  /* process id Unix domain socket */
#endif
   HL_LONGLONG ilc_epoch_started;           /* time WSP started        */
   char       *achc_server_name;            /* server name in UTF-8    */
   char       *achc_config_name;            /* configuration name in UTF-8 */
   char       *achc_query_main;             /* WSP name, version etc. in UTF-8 */
   char       *achc_group;                  /* group of WSP, UTF-8     */
   char       *achc_location;               /* location of WSP, UTF-8  */
   char       *achc_url;                    /* URL of WSP, UTF-8       */
   int        imc_len_server_name;          /* length server name      */
   int        imc_len_config_name;          /* length configuration name */
   int        imc_len_query_main;           /* length WSP name, version etc. */
   int        imc_len_group;                /* length of group in bytes */
   int        imc_len_location;             /* length of location in bytes */
   int        imc_len_url;                  /* length of URL in bytes  */
   int        imc_pid;                      /* process id              */
   BOOL       boc_endian_big;               /* CPU is big endian       */
   int        imc_aligment;                 /* aligment                */
   int        imc_epoch_conn;               /* time/epoch connected    */
   struct dsd_cluster_remote *adsc_clrem;   /* cluster remote structure */
   struct dsd_cluster_recv *adsc_recv_ch;   /* chain of received buffers */
   struct dsd_cluster_send *adsc_send_ch;   /* chain of send buffers   */
#ifdef XYZ1
   void *     ac_temp_connect;              /* temporary connect structure */
#endif
   int        imc_skip_recv_data;           /* length to skip received data */
   BOOL       boc_redirect;                 /* is redirected           */
#ifdef OLD01
   int        imc_ind_conn;                 /* index of last connect   */
#endif
   int        imc_count_recv_b;             /* count receive blocks outstanding */
   char       chc_lbal_status;              /* status received in load-balancing */
   int        imc_lbal_load;                /* load reported in load-balancing */
   int        imc_lbal_epoch_recv;          /* epoch last report load-balancing received */
   int        imc_lbal_epoch_sent;          /* epoch last report load-balancing sent */
   BOOL       boc_listen_stopped;           /* listen has been stopped */
   struct sockaddr_storage dsc_soa;         /* sockaddr for connect or from accept */
   class dsd_tcpcomp dsc_tcpcomp;           /* data of connection      */
   int        imc_time_start;               /* time connection started */
   int        imc_time_recv;                /* time last received data */
   int        imc_stat_no_recv;             /* statistic number of receives */
   int        imc_stat_no_send;             /* statistic number of sends */
   HL_LONGLONG ilc_stat_len_recv;           /* statistic length of receives */
   HL_LONGLONG ilc_stat_len_send;           /* statistic length of sends */
   void *     vpc_cma_entry;                /* field for CMA entry     */
   void *     vpc_special_1;                /* special field one       */
   char       chrc_ineta[ LEN_DISP_INETA ];  /* internet-address char  */
   char       chrc_fingerprint[ DEF_LEN_FINGERPRINT ];  /* hash over remote WSP */
   struct dsd_timer_ele dsc_timer_ele;      /* timer element           */
};

struct dsd_cluster_recv {                   /* block received from cluster member */
   struct dsd_cluster_active *adsc_clact;   /* active cluster          */
   struct dsd_cluster_recv *adsc_next;      /* for chaining            */
   int        imc_len_recv;                 /* length received         */
   int        imc_usage_count;              /* usage count             */
};

struct dsd_cluster_proc_recv {              /* process block received from cluster member */
   struct dsd_cluster_active *adsc_clact;   /* active cluster          */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* gather input data       */
   int        imc_data_length;              /* length of received data */
   int        imc_no_recv_bl;               /* number of receive blocks */
};

struct dsd_cluster_send {                   /* send to cluster structure */
   struct dsd_cluster_active *adsc_clact;   /* active cluster          */
   void (* amc_compl) ( struct dsd_cluster_send * );  /* completion routine */
   void *     vpc_userfld;                  /* userfield calling program */
   enum ied_cl_type iec_cl_type;            /* cluster data type       */
   struct dsd_gather_i_1 *adsc_gai1_send;   /* gather input data to send */
   /* the following fields are needed by the send routine              */
   struct dsd_cluster_send *adsc_next;      /* next in chain, send routine */
   void *     vprc_work_area[8];            /* work area for send routine */
};
#endif

/* immediately after this structure there is the name, UTF-8, not zero-terminated */
struct dsd_ldap_template {                  /* definition LDAP template */
   int        imc_len_name;                 /* length of name bytes    */
   char       *achc_user_attr;              /* address user-attribute UTF-8 */
   int        imc_len_user_attr;            /* length user-attribute UTF-8 */
   char       *achc_group_attr;             /* address group-attribute UTF-8 */
   int        imc_len_group_attr;           /* length group-attribute UTF-8 */
   char       *achc_member_attr;            /* address member-attribute UTF-8 */
   int        imc_len_member_attr;          /* length member-attribute UTF-8 */
   char       *achc_mship_attr;             /* address membership-attribute UTF-8 */
   int        imc_len_mship_attr;           /* length membership-attribute UTF-8 */
   char       *achc_search_d_a;             /* search-default-attribute UTF-8 */
   int        imc_len_search_d_a;           /* length of search-default-attribute bytes */
   char       *achc_upref;                  /* address user-prefix UTF-8 */
   int        imc_len_upref;                /* length user-prefix UTF-8 */
};

/* immediately after this structure there is the name, UTF-8, not zero-terminated */
struct dsd_ldap_group {                     /* definition LDAP group   */
   struct dsd_ldap_group *adsc_next;        /* next group in chain     */
   struct dsd_ldap_entry *adsc_ldap_entry;  /* chain of LDAP entries   */
   int        imc_len_name;                 /* length of name bytes    */
   int        imc_len_comment;              /* length of Comment bytes */
/* 19.10.10 KB new ++++++++++++++++++++++++++ UUUUUUUUUUUUUUUU         */
   int        imc_trace_level;              /* trace_level             */
   int        imc_references;               /* references to this LDAP-group */
};

/* immediately after this structure there is the name, UTF-8, not zero-terminated */
struct dsd_ldap_entry {                     /* definition LDAP entry   */
   struct dsd_ldap_entry *adsc_next;        /* next entry in chain     */
   int        imc_len_name;                 /* length of name bytes    */
#ifdef B070917
   UNSIG_MED  umc_multih_ineta;             /* INETA of this multihomed */
#endif
   struct dsd_bind_ineta_1 dsc_bind_multih;  /* for bind multihomed    */
   struct dsd_target_ineta_1 *adsc_server_ineta;  /* LDAP-Server INETA */
   int        imc_port;                     /* Port TCP LDAP-Server    */
   char       *achc_userid;                 /* Userid Administrator UTF-8 */
   int        imc_len_userid;               /* length of Userid bytes  */
   char       *achc_password;               /* Password Administrator UTF-8 */
   int        imc_len_password;             /* length of Password bytes */
   char       *achc_base_dn;                /* base-dn UTF-8           */
   int        imc_len_base_dn;              /* length of base-dn bytes */
#ifdef B100907
// 07.09.10 KB moved to struct dsd_ldap_template - start
   char       *achc_search_d_a;             /* search-default-attribute UTF-8 */
   int        imc_len_search_d_a;           /* length of search-default-attribute bytes */
// 07.09.10 KB moved to struct dsd_ldap_template - end
#endif
   char       *achc_comment;                /* Comment                 */
   int        imc_len_comment;              /* length of Comment bytes */
   int        imc_search_nested_groups_level;  /* how deep to search in nested groups */
   BOOL       boc_global_directory;         /* is global directory     */
   int        imc_timeout_conn;             /* timeout connect seconds */
   int        imc_timeout_search;           /* timeout search seconds  */
   int        imc_search_buf_size;          /* default search buffer size */
   int        imc_retry_after_error;        /* time retry after error seconds */
   int        imc_conf_max_session;         /* maximum parallel session (TCP) */
   struct dsd_ldap_template *adsc_ldap_template;  /* LDAP template     */
   BOOL       boc_csssl_conf;               /* Client Side SSL configured */
   void *     vpc_csssl_config_id;          /* Client Side SSL Configuration to use */
   /* fields for statistics                                            */
   int        imc_cur_session;              /* current sessions        */
   int        imc_max_session;              /* maximum sessions reached */
   int        imc_max_backlog;              /* maximum backlog reached */
   int        imc_l_epoch_max_session;      /* last time / epoch maximum sessions / backlog reached */
   int        imc_no_conn_suc;              /* number of connect successful */
   int        imc_no_conn_fail;             /* number of connect failed */
   int        imc_error_sess;               /* number of sessions abended */
   int        imc_send_packet;              /* number of TCP packets sent */
   HL_LONGLONG ilc_send_data;               /* length of TCP data sent */
   int        imc_recv_packet;              /* number of TCP packets received */
   HL_LONGLONG ilc_recv_data;               /* length of TCP data received */
   HL_LONGLONG ilc_sum_search_t_msec;       /* sum search time millisec */
   int        imc_max_search_t_msec;        /* maximum search time millisec */
   int        imc_count_search;             /* count search            */
   int        imc_count_write;              /* count write             */
};

enum ied_service_type {                     /* type of service         */
   ied_sety_invalid,                        /* type is invalid         */
   ied_sety_vc_icap_http                    /* type is virus checking ICAP HTTP */
};

struct dsd_service_conf_1 {                 /* definition service configuration */
   struct dsd_service_conf_1 *adsc_next;    /* next entry in chain     */
   char       *achc_name;                   /* name of entry, UTF-8    */
   int        imc_len_name;                 /* length of name bytes    */
   enum ied_service_type iec_service_type;  /* type of service         */
   void * (* amc_service_open) ( void *, struct dsd_service_conf_1 *, struct dsd_aux_service_query_1 * );  /* open service */
};

struct dsd_service_aux_1 {                  /* definition auxiliary service */
   amd_service_requ amc_service_requ;       /* request service         */
   amd_service_close amc_service_close;     /* close service           */
};

struct dsd_auxf_ext_1 {                     /* definition auxiliary field extension */
   int        imc_signal;                   /* signal set when active  */
#ifdef B130314
   void *     ac_sdh;                       /* current Server-Data-Hook */
#endif
#ifdef NOT_YET_130417
// cid needed in struct dsd_auxf_1 for sleeping components
#endif
// to-do 21.06.14 KB - remove dsc_cid
   struct dsd_cid dsc_cid;                  /* component identifier    */
};

/**
   this structure is appended to struct dsd_auxf_1
   and followed by the addresses of struct dsd_server_list_1
*/
struct dsd_auxf_sessco1 {                   /* definition session configuration */
   int        imc_no_seli;                  /* number of server lists  */
   BOOL       boc_use_default_servli;       /* use default server list */
   struct dsd_targfi_1 *adsc_targfi_1;      /* target-filter           */
   struct dsd_config_ineta_1 *adsc_co_ineta_ppp;  /* configured INETAs PPP */
   struct dsd_config_ineta_1 *adsc_co_ineta_appl;  /* configured INETAs application / HTCP */
};

/**
   this structure is appended to struct dsd_auxf_1
   after struct dsd_auxf_ext_1
*/
struct dsd_auxf_admin1 {                    /* definition admin requests */
   struct dsd_sdh_control_1 *adsc_sdhc1_1;  /* buffers from previous calls */
};

/**
   this structure is appended to struct dsd_auxf_1
   and followed by the UTF-8 strings
*/
struct dsd_auxf_ident_1 {                   /* definition ident        */
   int        imc_len_userid;               /* length userid UTF-8     */
   int        imc_len_user_group;           /* length name user group UTF-8 */
   int        imc_len_userfld;              /* length user field any character set */
};

/* immediately after this structure there is the name, UTF-8, not zero-terminated */
/* then there is the comment, UTF-8, not zero-terminated               */
/* then there is the default-realm, UTF-8, not zero-terminated         */
struct dsd_krb5_kdc_1 {                     /* definition Kerberos 5 KDC */
   struct dsd_krb5_kdc_1 *adsc_next;        /* next group in chain     */
   struct dsd_krb5_kdc_server *adsc_kdc_server;  /* chain of Kerberos 5 KDC servers */
   struct dsd_ldap_group *adsc_ldap_group;  /* corresponding LDAP group */
   int        imc_len_name;                 /* length of name bytes    */
   int        imc_len_comment;              /* length of Comment bytes */
   int        imc_len_default_realm;        /* length of default-realm bytes */
   int        imc_clockskew;                /* clockskew in seconds    */
   int        imc_ticket_lifetime;          /* ticket-lifetime in seconds */
   int        imc_renewable_lifetime;       /* renewable-lifetime in seconds */
   BOOL       boc_allow_initital_ticket;    /* allow-initial-ticket    */
/* 19.10.10 KB new ++++++++++++++++++++++++++ UUUUUUUUUUUUUUUU         */
   int        imc_trace_level;              /* trace_level             */
   int        imc_references;               /* references to this Kerberos 5 KDC */
#ifdef NOT_YET_130508
   char       *achc_comment;                /* address of comment      */
   char       *achc_default_realm;          /* address of default-realm */
   struct dsd_unicode_string dsc_ucs_comment;  /* comment              */
   struct dsd_unicode_string dsc_ucs_default_realm;  /* default-realm  */
/* for constrained delegation */
   char       *achc_keytab;                 /* address keytab          */
   int        imc_len_keytab;               /* length keytab           */
/* -or- */
   struct dsd_krb5_keytab *adsc_krb5_keytab;
#endif
};

/* immediately after this structure there is the name, UTF-8, not zero-terminated */
/* then there is the comment, UTF-8, not zero-terminated               */
struct dsd_krb5_kdc_server {                /* definition Kerberos 5 KDC server */
   struct dsd_krb5_kdc_server *adsc_next;   /* next entry in chain     */
   int        imc_len_name;                 /* length of name bytes    */
   int        imc_len_comment;              /* length of Comment bytes */
   struct dsd_bind_ineta_1 dsc_bind_multih;  /* for bind multihomed    */
   struct dsd_target_ineta_1 *adsc_server_ineta;  /* KDC INETA         */
   int        imc_port;                     /* Port TCP KDC            */
#ifdef NOT_YET_130508
   char       *achc_comment;                /* address of comment      */
   struct dsd_unicode_string dsc_ucs_comment;  /* comment              */
/* for password change over Kerberos */
/* imc_port is removed */
   int        imc_tcp_auth_port;            /* Port TCP KDC authentication */
   int        imc_tcp_admin_port;           /* Port TCP KDC admin/changepw */
#endif
   int        imc_timeout;                  /* timeout seconds         */
   int        imc_retry_after_error;        /* time retry after error seconds */
   int        imc_conf_max_session;         /* maximum parallel session (TCP) */
   int        imc_max_ticket_size;          /* maximum length of ticket in bytes */
   /* fields for statistics                                            */
   int        imc_cur_session;              /* current sessions        */
   int        imc_max_session;              /* maximum sessions reached */
   int        imc_max_backlog;              /* maximum backlog reached */
   int        imc_l_epoch_max_session;      /* last time / epoch maximum sessions / backlog reached */
   int        imc_no_conn_suc;              /* number of connect successful */
   int        imc_no_conn_fail;             /* number of connect failed */
   int        imc_error_sess;               /* number of sessions abended */
   int        imc_send_packet;              /* number of TCP packets sent */
   HL_LONGLONG ilc_send_data;               /* length of TCP data sent */
   int        imc_recv_packet;              /* number of TCP packets received */
   HL_LONGLONG ilc_recv_data;               /* length of TCP data received */
   int        imc_count_signon_failed;      /* number of times sign-on failed */
   int        imc_count_tgt;                /* number of TGT iussued   */
   int        imc_count_ticket;             /* number of tickets iussued */
};

struct dsd_krb5_keytab {                    /* definition Kerberos 5 keytab file */
   struct dsd_unicode_string dsc_ucs_file_name;  /* file name          */
   char       *achc_data;                   /* address data            */
   int        imc_len_data;                 /* length of data          */
};

#ifndef INCL_GW_EXTERN
/* immediately after this structure there is the name, UTF-8, not zero-terminated */
struct dsd_hrl_obj_1 {                      /* definition HTTP-redirect-library-object */
   struct dsd_hrl_obj_1 *adsc_next;         /* next HTTP-redirect-library-object in chain */
   int        imc_len_name;                 /* length of name bytes    */
   struct dsd_ext_lib1 *adsc_ext_lib1;      /* external library loaded */
   void *     ac_conf;                      /* return data from conf   */
   int        imc_references;               /* references to this HTTP-redirect-library-object */
};

/* immediately after this structure there is the name, UTF-8, not zero-terminated */
struct dsd_phl_obj_1 {                      /* definition plain-HTTP-library-object */
   struct dsd_phl_obj_1 *adsc_next;         /* next plain-HTTP-library-object in chain */
   int        imc_len_name;                 /* length of name bytes    */
   struct dsd_ext_lib1 *adsc_ext_lib1;      /* external library loaded */
   void *     ac_conf;                      /* return data from conf   */
   int        imc_references;               /* references to this HTTP-redirect-library-object */
};

/* immediately after this structure there is the name, UTF-8, not zero-terminated */
struct dsd_wspat_obj_1 {                    /* definition authentication-library-object */
   struct dsd_wspat_obj_1 *adsc_next;       /* next authentication-library-object in chain */
   int        imc_len_name;                 /* length of name bytes    */
   struct dsd_ext_lib1 *adsc_ext_lib1;      /* external library loaded */
   void *     ac_conf;                      /* return data from conf   */
   int        imc_references;               /* references to this authentication-library-object */
};

/* immediately after this structure there is the name, UTF-8, not zero-terminated */
struct dsd_sdh_obj_1 {                      /* definition server-data-hook-object */
   struct dsd_sdh_obj_1 *adsc_next;         /* next server-data-hook-object in chain */
   int        imc_len_name;                 /* length of name bytes    */
#ifdef B080609
   struct dsd_sdh_lib1 *adsc_sdhl_1;        /* server-data-hook libr   */
#endif
   struct dsd_ext_lib1 *adsc_ext_lib1;      /* external library loaded */
   void *     ac_conf;                      /* return data from conf   */
};

#ifdef __cplusplus
/* immediately after this structure there is the name, UTF-8, not zero-terminated */
struct dsd_bgt_contr_1 {                    /* definition background-task control */
   struct dsd_bgt_contr_1 *adsc_next;       /* next background-task control in chain */
   int        imc_len_name;                 /* length of name bytes    */
// struct dsd_sdh_lib1 *adsc_sdhl_1;        /* server-data-hook libr   */
   struct dsd_ext_lib1 *adsc_ext_lib1;      /* external library loaded */
   void *     ac_conf;                      /* return data from conf   */
   struct dsd_bgt_function_1 *adsc_bgt_function_1;  /* chain background-task functions */
// to-do 11.12.11 KB - needed for individual entry
   void *     ac_ext;                       /* attached buffer pointer */
// to-do 11.12.11 KB - better usage with critical section, flag in config + boc_locked
   BOOL       boc_active;                   /* backgroud-task currently processed */
};
#endif
#endif

/* immediately after this structure there is the name, UTF-8, not zero-terminated */
/* then there is the <authenticate-use-userid>, UTF-8, not zero-terminated */
/* then there is the <authenticate-use-password>, UTF-8, not zero-terminated */
struct dsd_l2tp_conf {                      /* L2TP gateway configuration */
   struct dsd_l2tp_conf *adsc_next;         /* next L2TP gateway in chain */
   int        imc_len_name;                 /* length of name bytes    */
   int        imc_len_auth_userid;          /* length of authenticate-use-userid bytes */
   int        imc_len_auth_pwd;             /* length of authenticate-use-password bytes */
   char       *achc_auth_userid;            /* authenticate-use-userid UTF-8 */
   char       *achc_auth_pwd;               /* authenticate-use-password UTF-8 */
   struct dsd_udp_param_1 dsc_udp_param_1;  /* definition UDP parameter L2TP gateway */
   enum ied_charset iec_chs_ppp;            /* character set PPP       */
   BOOL       boc_referenced;               /* entry is referenced     */
   void       *ac_l2tp_contr;               /* L2TP control structure  */
};

#ifdef INCL_GW_L2TP
struct dsd_l2tp_session {                   /* L2TP connection session */
   struct dsd_l2tp_conf *adsc_l2tp_conf;    /* L2TP connection configuration */
   struct dsd_ppp_targfi_act_1 *adsc_ptfa1;  /* active target filter   */
// struct dsd_htree1_avl_entry dsc_sort_se1;  /* entry for sorting L2TP sessions */
   enum ied_scp_def iec_scp;                /* server-conf protocol    */
   UNSIG_MED  umc_s_nw_ineta;               /* server-network-ineta    */
   UNSIG_MED  umc_s_nw_mask;                /* server-network-mask     */
// int        imc_session_no;               /* session number          */
   void *     ac_l2tp_conn_1;               /* L2TP UDP connection     */
#ifdef B110904
   volatile void * ac_buf_chain;            /* chain of buffers to send to client */
#endif
   int        imc_state_1;                  /* state of input          */
#ifdef B110904
   BOOL       boc_cont_send_client;         /* continue send to client */
#endif
   BOOL       boc_not_drop_tcp_packet;      /* do not drop TCP packets */
   int        imc_on_the_fly_packets_client;  /* number of packets on the fly to the client */
   struct {                                 /* for HOB-PPP-T1          */
     BOOL     boc_rec_header;               /* header first record received */
     BOOL     boc_rec_eye_catcher;          /* first record received   */
#ifdef NOT_YET
     struct dsd_timer_ele dsc_timer;        /* timer for wait          */
#endif
   };
   int        imrc_nonce[ 32 / sizeof(int) ];  /* nonce exchanged      */
};

#ifdef B100405
/**
  the Structure struct dsd_auxf_ineta_appl is appended to the Structure struct dsd_auxf_1
  and is followed by the INETA
*/
struct dsd_auxf_ineta_appl {
   struct dsd_htree1_avl_entry dsc_sort_user;  /* entry for sorting INETAs depending on user */
   struct dsd_htree1_avl_entry dsc_sort_ineta;  /* entry for sorting INETAs depending on INETA */
   struct dsd_unicode_string dsc_user_name;  /* Username Sign On       */
   struct dsd_unicode_string dsc_user_group;  /* Usergroup Sign On     */
   void *     ac_conn1;                     /* for this connection     */
   unsigned short int usc_htcp_port;        /* port in use             */
   unsigned short int usc_ineta_family;     /* family IPV4 / IPV6      */
   unsigned short int usc_ineta_length;     /* length of following address */
};

/**
  the Structure struct dsd_auxf_ineta_ppp is appended to the Structure struct dsd_auxf_1
  and is followed by the INETA
*/
struct dsd_auxf_ineta_ppp {
   struct dsd_htree1_avl_entry dsc_sort_ineta;  /* entry for sorting INETAs depending on INETA */
   void *     ac_conn1;                     /* for this connection     */
   unsigned short int usc_ineta_family;     /* family IPV4 / IPV6      */
   unsigned short int usc_ineta_length;     /* length of following address */
};
#endif
#ifdef D_INCL_HOB_TUN
#define DEF_STATE_HTUN_CONN_OK       1      /* done HTUN connect ok    */
#define DEF_STATE_HTUN_SEND_COMPL    2      /* done HTUN send complete - m_htun_htcp_send_complete() */
#define DEF_STATE_HTUN_SESS_END      4      /* done HTUN HTCP session end */
#define DEF_STATE_HTUN_ERR_SESS_END  8      /* done HTUN HTCP session end was with error */
#define DEF_STATE_HTUN_FREE_R_1      16     /* done HTUN free resources */
#define DEF_STATE_HTUN_FREE_R_2      32     /* done HTUN free resources */
#ifdef B130116
#define DEF_STATE_HTUN_INETA_TARGET  64     /* need to free target INETA */
#endif
#define DEF_STATE_HTUN_NO_FREE_INETA 128    /* do not free local INETA */

enum ied_ineta_raws_def {                   /* type of INETA raw socket */
   ied_ineta_raws_invalid = 0,              /* value is invalid        */
   ied_ineta_raws_n_ipv4,                   /* INETA IPV4              */
   ied_ineta_raws_n_ipv6,                   /* INETA IPV6              */
   ied_ineta_raws_user_ipv4,                /* INETA user IPV4         */
   ied_ineta_raws_user_ipv6,                /* INETA user IPV6         */
   ied_ineta_raws_l2tp_ipv4,                /* INETA L2TP IPV4         */
   ied_ineta_raws_l2tp_ipv6                 /* INETA L2TP IPV6         */
};
/**
  the Structure struct dsd_ineta_raws_1 is followed by the INETA
  --- not longer true, 08.08.13 KB
  if boc_with_user set, followed by user_name and user_group
*/
struct dsd_ineta_raws_1 {                   /* INETA in use            */
   struct dsd_htree1_avl_entry dsc_sort_user;  /* entry for sorting INETAs depending on user */
   struct dsd_htree1_avl_entry dsc_sort_ineta_ipv4;  /* entry for sorting INETAs depending on INETA */
   struct dsd_htree1_avl_entry dsc_sort_ineta_ipv6;  /* entry for sorting INETAs depending on INETA */
   struct dsd_unicode_string dsc_user_name;  /* Username Sign On       */
   struct dsd_unicode_string dsc_user_group;  /* Usergroup Sign On     */
   BOOL       boc_with_user;                /* structure with user     */
   volatile void * ac_conn1;                /* for this connection     */
   volatile dsd_htun_h dsc_htun_h;          /* handle for HTUN         */
   struct dsd_netw_post_1 *adsc_netw_post_1;  /* structure to post from network callback */
   int        imc_state;                    /* state of HOB-TUN / HTCP session */
   UNSIG_MED  umc_index_if_arp_ipv4;        /* holds index of compatible IF for ARP */
   UNSIG_MED  umc_index_if_route_ipv4;      /* holds index of compatible IF for routes */
   UNSIG_MED  umc_taif_ineta_ipv4;          /* <TUN-adapter-use-interface-ineta> */
   unsigned short int usc_appl_port;        /* port in use             */
   struct dsd_tun_contr_ineta dsc_tun_contr_ineta;  /* HOB-TUN control interface for INETA */
};
#endif

enum ied_ser_thr_type {                     /* serial thread task type */
   ied_sth_invalid,                         /* type is invalid         */
   ied_sth_route_ipv4_add,                  /* add a route IPV4        */
   ied_sth_route_ipv4_del,                  /* delete a route IPV4     */
   ied_sth_route_ipv6_add,                  /* add a route IPV6        */
   ied_sth_route_ipv6_del                   /* delete a route IPV6     */
};

// 25.07.10 KB - fields for ARP and route
struct dsd_ser_thr_task {                   /* task for serial thread  */
   struct dsd_ser_thr_task *adsc_next;      /* for chaining            */
   enum ied_ser_thr_type iec_sth;           /* serial thread task type */
   char       chrc_ineta[16];               /* INETA IPV4 / IPV6       */
   UNSIG_MED  umc_index_if_arp;             /* holds index of compatible IF for ARP */
   UNSIG_MED  umc_index_if_route;           /* holds index of compatible IF for routes */
   UNSIG_MED  umc_taif_ineta;               /* <TUN-adapter-use-interface-ineta> */
   int        imc_wtrt_sno;                 /* WSP session number for trace */
   BOOL       boc_trace;                    /* generate record for WSP trace */
   BOOL       *aboc_posted;                 /* mark posted             */
   class dsd_hcla_event_1 *adsc_event_posted;  /* event for posted     */
};
#endif

/* new 28.09.14 KB - for IPV6                                          */
enum ied_rawpi_use_ip_type {                /* raw packet interface use IP type */
   ied_rpiui_invalid,                       /* type is invalid         */
   ied_rpiui_only_ipv4,                     /* use only IPV4           */
   ied_rpiui_only_ipv6,                     /* use only IPV6           */
   ied_rpiui_pref_ipv4,                     /* prefere IPV4            */
   ied_rpiui_pref_ipv6                      /* prefere IPV6            */
};

/**
  The Structure struct dsd_tun_ineta_1 is sorted in ascending order / INETA.
  After the structure there is the starting and the ending INETA.
*/
struct dsd_tun_ineta_1 {                    /* range of INETAs used by TUN */
   struct dsd_tun_ineta_1 *adsc_next;       /* next in chain           */
   int        imc_no_ineta;                 /* number of INETAs        */
   unsigned short int usc_ineta_family;     /* family IPV4 / IPV6      */
   unsigned short int usc_ineta_length;     /* length of following address */
};

/**
  The Structure struct dsd_pool_ineta_1 is followed by imc_no_ext extensions.
  Each extension contains an int with the number of INETAs configured and the starting INETA.
*/
struct dsd_pool_ineta_1 {                   /* pool of INETAs          */
   struct dsd_pool_ineta_1 *adsc_next;      /* next in chain           */
   unsigned int umc_last_all_in_use;        /* epoch when last found all INETAs in use */
   int        imc_no_ext;                   /* number of extensions    */
   unsigned short int usc_ineta_family;     /* family IPV4 / IPV6      */
   unsigned short int usc_ineta_length;     /* length of following address */
};

struct dsd_appl_port_conf {                 /* configured ports for appl */
   unsigned short int usc_port_start;       /* port to start with      */
   unsigned short int usc_no_ports;         /* number of ports         */
};

#ifdef INCL_GW_L2TP
#ifdef B100802
/**
  the ports adsc_appl_port_conf are sorted in ascending order
  if boc_random_appl_port is set, otherwise not.
*/
struct dsd_raw_packet_if_conf {             /* configuration raw-packet-interface */
   struct dsd_tun_ineta_1 *adsc_tun_ineta_1;  /* chain range of INETAs used by TUN */
   struct dsd_pool_ineta_1 *adsc_pool_ineta_1;  /* chain of pools of INETAs */
   struct dsd_appl_port_conf *adsc_appl_port_conf;  /* configured ports for appl */
#ifndef HL_UNIX
   WCHAR      *awcc_driver_fn;              /* filename of driver for installation */
#endif
   UNSIG_MED  umc_ta_ineta;                 /* <TUN-adapter-ineta>     */
   UNSIG_MED  umc_taif_ineta;               /* <TUN-adapter-use-interface-ineta> */
/* see B100802 - now in hob-tun01.h                                    */
/* new 06.01.13 KB - start                                             */
   int        imc_no_ta_ineta_ipv4;         /* <TUN-adapter-ineta ???>     */
   int        imc_no_ta_ineta_ipv6;         /* <TUN-adapter-ineta ???>     */
   char       *achc_ar_ta_ineta_ipv4;       /* <TUN-adapter-ineta ???>     */
   char       *achc_ar_ta_ineta_ipv6;         /* <TUN-adapter-ineta ???>     */
   UNSIG_MED  umc_taif_ineta_ipv4;          /* <TUN-adapter-use-interface-ineta> IPV4 */
   char       chrc_taif_ineta_ipv6[ 16 ];   /* <TUN-adapter-use-interface-ineta> IPV6 */
/* new 06.01.13 KB - end                                               */
   int        imc_tcpc_to_msec;             /* <TCP-connect-timeout-millisec> */
   int        imc_tcpc_try_no;              /* <TCP-connect-number-of-try> */
   int        imc_no_ele_appl_port_conf;    /* number of elements configured ports for appl */
   BOOL       boc_random_appl_port;         /* <appl-use-random-tcp-source-port> */
   BOOL       boc_c_tun_ipv4;               /* configured TUN IPV4     */
   BOOL       boc_c_tun_ipv6;               /* configured TUN IPV6     */
   struct dsd_wsptun_conf_1 dsc_wsptun_conf_1;  /* TUN PPP INETAs      */
};
#endif
#endif

#ifndef NOT_INCLUDED_CLIB
struct dsd_pd_http_ctrl {                   /* process data HTTP control */
   struct dsd_phl_conf_1 *adsc_phl_conf_1;  /* plain-HTTP-library configuration */
   struct dsd_phl_call_1 dsc_phl_call_1;    /* plain-HTTP-library Call */
};

struct dsd_aux_pipe_read_buffer {           /* aux-pipe read buffer    */
   struct dsd_aux_pipe_read_buffer *adsc_next;  /* for chaining        */
   BOOL       boc_passed;                   /* already passed to calling component */
   struct dsd_gather_i_1 dsc_gai1_data;     /* gather data             */
};

//*/** the aux-pipe-name is stored immediately after this structure       */
struct dsd_aux_pipe_listen {                /* aux-pipe listen control structure */
   struct dsd_htree1_avl_entry dsc_sort_pipe;  /* entry for sorting aux-pipe names */
   char       *achc_aux_pipe_name;          /* address name of aux-pipe */
   int        imc_len_aux_pipe_name;        /* length of name of aux-pipe */
   enum ied_aux_pipe_scope iec_aps;         /* scope of an aux-pipe    */
   void *     ac_conn1;                     /* for this connection     */
   struct dsd_auxf_1 *adsc_auxf_1_apc_ch_new_conn;  /* chain aux-pipe connection control structures new connections */
   int        imc_signal;                   /* signal to set           */
};

struct dsd_aux_pipe_conn {                  /* aux-pipe connection control structure */
   struct dsd_auxf_1 *adsc_auxf_1_apc_partner;  /* address aux-pipe connection control structure of partner */
   void *     ac_conn1;                     /* for this connection     */
   int        imc_signal;                   /* signal to set           */
   struct dsd_aux_pipe_read_buffer *adsc_aprb_ch;  /* chain of aux-pipe read buffers */
};
#endif

#ifndef NOT_INCLUDED_CLIB
/**
  the Structure struct dsd_util_thread_ctrl is appended to the Structure struct dsd_auxf_1
*/
struct dsd_util_thread_ctrl {               /* utility thread control  */
   struct dsd_extra_thread_entry dsc_ete;   /* extra thread entry      */
   amd_util_thread amc_util_thread;         /* entry of utility thread */
   struct dsd_auxf_1 *adsc_auxf_1;          /* chain auxiliary extension fields */
   int        imc_thread_priority;          /* priority of utility thread to be created */
   int        imc_signal_parent;            /* signal for parent       */
   BOOL       boc_thread_ended;             /* thread has ended        */
   class dsd_hcthread dsc_thread;           /* thread control area     */
#ifdef NOT_YET_130417
// cid needed in struct dsd_auxf_1 for sleeping components
#endif
   struct dsd_cid dsc_cid;                  /* component identifier    */
   struct dsd_pd_work dsc_pd_work;          /* work to process data    */
   struct dsd_aux_util_thread_param_1 dsc_utp1;  /* utility thread parameter */
};
#endif

/** structure dsd_dyn_lib_ctrl is followed by the file-name
    in the corresponding character set                                 */
struct dsd_dyn_lib_ctrl {                   /* dynamic library control */
   struct dsd_dyn_lib_ctrl *adsc_next;      /* for chaining            */
   int        imc_references;               /* count references        */
   int        imc_len_fn;                   /* length file-name in elements */
#ifndef HL_UNIX
   HMODULE    dsc_h_module;                 /* handle of module        */
#endif
};

struct dsd_aux_dyn_lib_conn {               /* dynamic library connection */
   struct dsd_dyn_lib_ctrl *adsc_dyn_lib_ctrl;  /* dynamic library control */
};

#ifdef B13127
enum ied_swap_stor_state {                  /* swap storage state      */
   ied_swsst_acq = 0,                       /* acquired by component   */
   ied_swsst_mem,                           /* in memory               */
   ied_swsst_file                           /* in file                 */
};

struct dsd_swap_stor_chunk {                /* swap storage chunk      */
   enum ied_swap_stor_state iec_swsst;      /* swap storage state      */
   int        imc_index;                    /* index of dataset / chunk */
   char       *achc_stor_addr;              /* storage address or RBA on file */
   union {
     void *   vpc_aux_swap_stor_handle;     /* handle of swap storage  */
     struct dsd_swap_stor_chunk *adsc_next;  /* for chain of free swap storage chunks */
   };
   struct dsd_htree1_avl_entry dsc_sort_comp;  /* entry for sorting for component */
   class dsd_hcla_critsect_1 dsc_critsect;  /* critical section        */
};
#endif
#ifdef B141229
enum ied_swap_stor_state {                  /* swap storage state      */
   ied_swsst_unused = 0,                    /* element unused          */
   ied_swsst_acq,                           /* acquired by component   */
   ied_swsst_mem,                           /* in memory               */
   ied_swsst_file                           /* in file                 */
};
#endif

#define D_SWAP_STOR_CHAIN_CHUNKS  32

struct dsd_swap_stor_chunk {                /* swap storage chunk      */
   int        imc_index_on_file;            /* index on file (RBA), -1 when not in file */
   char       *achc_stor_addr;              /* storage address when in memory */
};

struct dsd_swap_stor_chain {                /* chain of swap storage chunks */
   struct dsd_swap_stor_chain *adsc_next;   /* for chaining            */
   struct dsd_swap_stor_chunk dsrc_ss_c[ D_SWAP_STOR_CHAIN_CHUNKS ];  /* swap storage chunks */
};

struct dsd_swap_stor_aux {                  /* auxiliary field for swap storage */
   int        imc_index_filled;             /* index of dataset / chunks filled */
#ifdef HL_UNIX
   int        imc_fd_file;                  /* file-descriptor of open swap file */
#endif
   struct dsd_swap_stor_chain *adsc_ss_ch;  /* chain of swap storage chunks */
};

struct dsd_swap_occupied {                  /* swap file occupied bits */
   struct dsd_swap_occupied *adsc_next;     /* for chaining            */
   void **    avpc_occupied;                /* occupied till here      */
};

#ifdef INCL_GW_ALL
struct dsd_swap_stor_ctrl {                 /* swap storage control    */
#ifndef HL_UNIX
   BOOL       boc_init;                     /* swap storage has been initialized */
#endif
   int        imc_mem_max;                  /* number of chunks in memory maximum */
   int        imc_mem_free;                 /* number of chunks in memory free */
   int        imc_file_cur;                 /* number of chunks on file currently */
   int        imc_file_max;                 /* number of chunks on file maximum */
   HL_LONGLONG ilc_no_acq;                  /* number of chunks acquired */
#ifdef B141229
   HL_LONGLONG ilc_no_current;              /* number of chunks currently */
   HL_LONGLONG ilc_no_file;                 /* number of chunks on file */
   HL_LONGLONG ilc_no_max;                  /* number of chunks maximum */
   HL_LONGLONG ilc_no_mem_max;              /* number of chunks maximum in memory */
#endif
   HL_LONGLONG ilc_no_file_write;           /* number of writes to swap storage file */
   HL_LONGLONG ilc_no_file_read;            /* number of reads from swap storage file */
   HL_LONGLONG ilc_out_of_memory;           /* count times out of memory */
   void *      ac_free;                     /* chain of free storage pieces */
#ifdef B141228
   struct dsd_swap_stor_chunk *adsc_swstch_ch_free;  /* chain free swap storage chunks */
#endif
   struct dsd_swap_stor_chain *adsc_ss_ch_free;  /* chain of free swap storage chunks */
   struct dsd_swap_occupied *adsc_swap_occupied;  /* chain swap file occupied bits */
#ifndef HL_UNIX
   HANDLE     dsl_h_file;                   /* handle of open swap file */
   struct dsd_unicode_string dsc_ucs_file_name;  /* file name          */
#endif
#ifdef HL_UNIX
   int        imc_fd_file;                  /* file-descriptor of open swap file */
   char       *achc_file_name;              /* filename for multiple open */
#endif
#ifdef B141229
   struct dsd_htree1_avl_cntl dsc_htree1_avl_swap_stor_comp;
#endif
   class dsd_hcla_critsect_1 dsc_critsect;  /* critical section        */
};
#endif

#ifdef XYZ1
enum ied_clinth_def {                       /* cluster ineta this state */
   ied_clinth_waiting = 0,                  /* waiting for responses */
   ied_clinth_ret_ok,                       /* all responses returned  */
   ied_clinth_rejected                      /* cluster message was rejected */
};
#endif

struct dsd_cluster_ineta_wait {             /* wait to process INETAs this cluster member */
   struct dsd_cluster_ineta_wait *adsc_next;  /* for chaining          */
   struct dsd_hco_wothr *adsc_hco_wothr;    /* pointer on work-thread  */
   BOOL       boc_end_wait;                 /* end of waiting          */
};

/**
  the structure is followed by pairs of start and end INETA
*/
struct dsd_cluster_ineta_this {             /* save INETA this cluster member */
   struct dsd_cluster_ineta_this *adsc_next;  /* next in chain         */
   struct dsd_hco_wothr *adsc_hco_wothr;    /* pointer on work-thread  */
   struct dsd_cluster_ineta_wait *adsc_cluster_ineta_wait;  /* wait to process INETAs this cluster member */
   struct dsd_pool_ineta_1 *adsc_pool_ineta_1;  /* pool of INETAs      */
   struct dsd_cluster_ineta_temp *adsc_cluster_ineta_temp;  /* temporary INETAs received from other cluster member */
   void *     ac_ineta_buffer;              /* buffer with INETAs sent */
   volatile int imc_resp_outstanding;       /* number of responses outstanding */
   BOOL       boc_rejected;                 /* request has been rejected by other cluster member */
   int        imc_timeout_msec;             /* timeout in milliseconds */
   int        imc_sequ;                     /* sequence number         */
#ifdef XYZ1
   enum ied_clinth_def iec_clinth;          /* cluster ineta this state */
#endif
   unsigned short int usc_ineta_family;     /* family IPV4 / IPV6      */
   unsigned short int usc_ineta_length;     /* length of following address */
   char       *achc_end_used;               /* address used till here  */
};

/**
  the structure is followed by pairs of start and end INETA
*/
struct dsd_cluster_ineta_temp {             /* temporary INETAs received from other cluster member */
   char       *achc_end_used;               /* address used till here  */
};

#ifdef INCL_GW_ALL
struct dsd_int_webso_conn_1 {               /* connect for WebSocket applications - internal */
   enum ied_type_webso_conn iec_twc;        /* type of WebSocket connect */
#ifdef XYZ1
   struct dsd_aux_webso_conn_1 adsc_awc1;   /* connect for WebSocket applications - aux */
#endif
   int        imc_signal;                   /* signal to set           */
   BOOL       boc_notify;                   /* notify SDH              */
   BOOL       boc_connect_active;           /* connect active now      */
   BOOL       boc_did_connect;              /* did connect             */
   int        imc_connect_error;            /* connect error           */
#ifdef B130314
   void *     ac_sdh;                       /* address of SDH          */
#endif
   struct dsd_cid dsc_cid;                  /* component identifier    */
   struct dsd_sdh_control_1 *adsc_sdhc1_recv;  /* buffers received     */
   struct dsd_gather_i_1 *adsc_gai1_pass;   /* data passed to calling program */
};
#endif

#ifndef NOT_INCLUDED_CLIB
struct dsd_sdh_reload_auxf {                /* auxiliary field for SDH reload */
#ifdef WAS_BEFORE_1501
//   struct dsd_sdh_work_1 *adsc_sdh_work_1;  /* work area server data hook */
   char       *achc_addr_pass_data;         /* address of data to pass */
   int        imc_len_pass_data;            /* length of data to pass  */
#endif
   int        imc_len_sdh_name;             /* length of SDH name      */
   int        imc_wait_seconds;             /* wait seconds for destroy */
#ifdef WAS_BEFORE_1501
   int        imc_hookc;                    /* hook-count              */
#endif
   void *     ac_conn1;                     /* for this connection     */
   struct dsd_htree1_avl_entry dsc_sort_sdh_reload;  /* entry for sorting SDH-reload identifiers */
};

#ifdef WAS_BEFORE_1501
struct dsd_sdh_reload_saved {               /* SDH, saved for reload   */
   struct dsd_sdh_reload_saved *adsc_next;  /* for chaining            */
//   struct dsd_sdh_work_1 *adsc_sdh_work_1;  /* work area server data hook */
   void *     ac_cid_addr;                  /* address of component / SDH / PHL */
   struct dsd_auxf_1 *adsc_auxf_1_sdh_reload;  /* auxiliary extension field for reload */
   struct dsd_auxf_1 *adsc_auxf_1_ch;       /* chain auxiliary ext fields */
   struct dsd_sdh_control_1 *adsc_sdhc1_chain;  /* chain of buffers input output */
   BOOL       boc_reload_active;            /* reload is active        */
   struct dsd_sdh_session_1 dsc_sdh_s_1;    /* work area server data hook per session */
   struct dsd_timer_ele dsc_timer_ele;      /* timer element           */
};
#endif
#endif

struct dsd_wsp_trace_info_conn1 {           /* WSP trace information for connection */
   int        imc_trace_level;              /* trace_level             */
   int        imc_sno;                      /* WSP session number      */
};

enum ied_wsp_trace_rt_def {                 /* type of record WSP trace */
   ied_wtrt_invalid = 0,                    /* value is invalid        */
   ied_wtrt_control,                        /* control record          */
   ied_wtrt_trace_data                      /* trace data              */
};

struct dsd_wsp_trace_1 {                    /* WSP trace record        */
   struct dsd_wsp_trace_1 *adsc_next;       /* for chaining            */
   struct dsd_wsp_trace_1 *adsc_cont;       /* continue this record    */
   enum ied_wsp_trace_rt_def iec_wtrt;      /* type of record WSP trace */
   HL_LONGLONG ilc_epoch;                   /* time trace record recorded */
#ifndef HL_SOLARIS
   union {
     struct {
#endif
       char   chrc_wtrt_id[ 8 ];            /* Id of trace record      */
       int    imc_wtrt_sno;                 /* WSP session number      */
       int    imc_wtrt_tid;                 /* thread-id               */
       struct dsd_wsp_trace_record *adsc_wsp_trace_record;  /* WSP trace records */
#ifndef HL_SOLARIS
     };
     struct {
#endif
       int    imc_wsp_trace_target;         /* enum ied_wsp_trace_target / Trace target */
       int    imc_len_filename;             /* length of following flie-name UTF-8 */
#ifndef HL_SOLARIS
     };
   };
#endif
#ifdef XYZ1
   char       *achc_text;                   /* address of text this record */
// 26.04.11 KB - to be removed
   int        imc_len_text;                 /* length of text this record */
   char       *achc_dump;                   /* address of data to dump this record */
   int        imc_len_dump;                 /* length of data to dump this record */
   BOOL       boc_dump_last;                /* last record with data to dump */
#endif
};

struct dsd_wsp_tr_ineta_ctrl {              /* WSP trace client with INETA control */
   BOOL       boc_trace_ineta_all;          /* trace all INETAS        */
   union {
     int      imc_trace_level;              /* trace_level             */
     int      imc_len_inetas;               /* length of following INETAs */
   };
};

struct dsd_wsp_tr_ineta_1 {                 /* WSP trace client with INETA */
   unsigned short int usc_family;           /* family IPV4 / IPV6      */
   unsigned short int usc_length;           /* length of following address */
   int        imc_trace_level;              /* trace_level             */
};

struct dsd_wsp_tr_bin_header_1 {            /* WSP trace record in binary file */
   char       chrc_wtrt_id[ 8 ];            /* Id of trace record      */
   char       chrc_wtrt_epoch[ 8 ];         /* time trace record recorded */
   char       chrc_wtrt_sno[ 4 ];           /* WSP session number      */
   char       chrc_wtrt_tid[ 4 ];           /* thread-id               */
   char       chrc_wtrt_record_no[ 4 ];     /* WSP trace record number */
};

struct dsd_cma_dump_01 {                    /* structure CMA dump      */
   int        imc_size_area;                /* size of area            */
   HL_LONGLONG ilc_epoch_last_used;         /* save EPOCH entry last used */
   int        imc_retention_time;           /* retention time in seconds */
   char       *achc_area;                   /* area cma                */
   int        imc_no_locks;                 /* number of locks         */
   struct dsd_unicode_string dsc_ucs_name;  /* name of entry           */
};

#ifndef INCL_GW_EXTERN
/* programs at main */
extern PTYPE int m_hlnew_printf( int, char *, ... );
extern PTYPE BOOL m_cdaux( void *, int, void *, int );
extern PTYPE const char * m_get_query_main( void );
extern PTYPE int m_get_no_cpu( void );
extern PTYPE void m_open_log( void );       /* open log now            */
#ifndef HL_KRB5
extern PTYPE void * m_call_dom( DOMNode *, enum ied_hlcldom_def );
#endif
extern PTYPE UNSIG_MED m_get_ineta_single( char * );
extern PTYPE UNSIG_MED m_get_ineta_dotted( char * );
#ifdef B070917
extern PTYPE struct dsd_target_ineta_1 * m_get_ineta_multi( char * );
#endif
extern PTYPE enum ied_scp_def m_decode_prot( enum ied_charset, void *, int );
static void m_get_servent_1( int inp_param, DSD_CONN_G *,struct dsd_get_servent_1 *adsp_gse1 );
extern PTYPE void m_count_recv_server( DSD_CONN_G *, int );
extern PTYPE void m_count_sent_server( DSD_CONN_G *, int );
// to-do 06.04.10 KB - no static entries
static void m_prep_conn_1( DSD_CONN_G *, struct dsd_hlwspat2_conn * );
static void m_prep_pttd_1( struct dsd_wspat3_conn *, struct dsd_server_conf_1 * );
// to-do 06.04.10 KB - m_check_target_dns
// to-do 06.04.10 KB - m_check_target_ineta
extern PTYPE void m_disp_conf_file( BOOL );
extern PTYPE void m_edit_fingerprint( char *, char * );
extern PTYPE void * m_find_htun_ineta( struct sockaddr_storage * );
extern PTYPE void m_recv_cluster_vdi( char *, int );
#ifdef HL_UNIX
extern PTYPE void m_ligw_cluster_struct( int * );
#endif
extern PTYPE enum ied_opli_ret m_open_listen( char *, int, amd_msgprog, void *, enum ied_lierr,
                                              struct dsd_gate_listen_1 *,
                                              struct dsd_ineta_single_1 *,
                                              int );
extern PTYPE int m_start_listen( struct dsd_gate_1 * );
extern PTYPE int m_stop_listen( struct dsd_gate_1 * );
extern PTYPE int m_start_all_listen( BOOL );
extern PTYPE int m_stop_all_listen( BOOL );
#ifdef B080407
extern PTYPE int m_open_listen( char *, int, amd_msgprog, void *, enum ied_lierr,
                                UNSIG_MED, char *, int, char *, int );
#endif
#ifdef OLD_1112
extern PTYPE void m_open_radius( char *, int, amd_msgprog, void *,
                                 struct dsd_radius_entry * );
#endif
#ifdef B080424
extern PTYPE void m_open_blade_control( HL_WCHAR **, int, HL_WCHAR *, int, int );
#endif
#ifndef INCL_GW_EXTERN
extern PTYPE void * m_proc_alloc( void );
extern PTYPE void m_proc_free( void * );
extern PTYPE int m_get_random_number( int );
#endif
extern PTYPE dsd_time_1 m_get_time( void );
extern PTYPE HL_LONGLONG m_get_epoch_microsec( void );
extern PTYPE char * m_edit_dec_int( char *, int );
extern PTYPE char * m_edit_dec_long( char *, HL_LONGLONG );
extern PTYPE BOOL m_check_conn_active( DSD_CONN_G * );
extern PTYPE DSD_CONN_G * m_get_conn1_from_userfld( void * );
extern PTYPE struct dsd_sdh_control_1 ** m_get_sdhc1_extra_from_conn1( DSD_CONN_G * );
extern PTYPE void m_act_conn1_signal( DSD_CONN_G *, char *, int );
extern PTYPE void m_wsp_trace_out( struct dsd_wsp_trace_1 * );
#ifndef INCL_GW_EXTERN
#ifdef TRACEHL1
extern PTYPE void m_console_out( char *, int );
#endif
#endif
extern struct dsd_this_server dsg_this_server;  /* data about this server */
#ifdef D_INCL_CONF
extern PTYPE BOOL m_build_conf_01( XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *,
                                   struct dsd_loconf_1 *, amd_startprog );
#endif
#ifdef INCL_TEST_RPC
extern PTYPE void m_rpc_start( void );
extern PTYPE BOOL m_rpc_ntlmv2_proc( struct dsd_hco_wothr *, void *, struct dsd_rpc_group *, struct dsd_aux_auth_rpc_ntlmv2_1 * );
#endif
extern PTYPE void m_cluster_start( struct dsd_cluster_main * );
extern PTYPE BOOL m_status_cluster_lbal( BOOL );
extern PTYPE BOOL m_create_log( HL_LONGLONG );
extern PTYPE BOOL m_write_log( int, char *, int );
#ifdef INCL_GW_ALL
extern PTYPE int m_send_cluster_ineta( struct dsd_cluster_ineta_this * );
extern PTYPE int m_cluster_count_active( void );
extern PTYPE void m_cluster_report( struct dsd_cluster_report * );
extern PTYPE void m_cluster_proc_recv_done( struct dsd_cluster_proc_recv * );
extern PTYPE int m_cluster_send( struct dsd_cluster_send * );
extern PTYPE void m_cluster_vdi_send( char *, int );
extern PTYPE void m_admin_cluster_recv( struct dsd_cluster_proc_recv * );
#ifdef HL_UNIX
extern PTYPE void m_cluster_ligw_conn( int );
#endif
extern PTYPE void m_cluster_end( void );
#endif
extern PTYPE void m_notify_cma_sync_passive_start( void );
extern PTYPE void m_notify_cma_sync_passive_stop( void );
extern PTYPE void m_notify_cma_sync_active_start( void );
extern PTYPE void m_notify_cma_sync_active_stop( void );
extern PTYPE BOOL m_cma1_gen_dump_01( void *, amd_dump_cma_01 );
#ifdef INCL_GW_ADMIN
extern PTYPE void m_admin_start( void );
extern PTYPE void m_admin_reload_conf( void );
extern PTYPE struct dsd_sdh_control_1 * m_get_wspadm1_cluster( void );
extern PTYPE struct dsd_sdh_control_1 * m_get_wspadm1_session( struct dsd_wspadm1_q_session * );
extern PTYPE struct dsd_sdh_control_1 * m_get_wspadm1_cancel_session( struct dsd_wspadm1_q_can_sess_1 * );
extern PTYPE struct dsd_sdh_control_1 * m_get_wspadm1_listen( void );
extern PTYPE struct dsd_sdh_control_1 * m_get_wspadm1_perfdata( void );
extern PTYPE void m_ctrl_wspadm1_wsp_trace( struct dsd_wspadm1_q_wsp_trace_1 *, int );
extern PTYPE struct dsd_sdh_control_1 * m_get_wspadm1_wsp_tr_act( void );
extern PTYPE BOOL m_proc_admin_aux( struct dsd_aux_admin_1 *, struct dsd_auxf_1 *, struct dsd_hco_wothr * );
#endif
#ifdef D_INCL_CONF
extern PTYPE struct dsd_service_conf_1 * m_service_vc_icap_http_conf( DOMNode *,
                    void * (* amp_call_dom) ( DOMNode *, enum ied_hlcldom_def ),   /* call DOM */
                    HL_WCHAR * );
#endif
extern PTYPE BOOL m_aux_get_ident_set_1( void *, struct dsd_sdh_ident_set_1 * );
extern PTYPE struct dsd_gate_1 * m_conn2gate( void * vpp_conn );
extern PTYPE void m_get_wsp_trace_info_conn1( struct dsd_wsp_trace_info_conn1 *, void * );
#ifdef D_INCL_AUX_UDP
extern PTYPE void m_gw_udp_start( void );
extern PTYPE void m_gw_udp_end( void );
extern PTYPE void m_gw_udp_update( struct dsd_loconf_1 * );
extern PTYPE BOOL m_aux_udp_requ_1( void *, struct dsd_sdh_udp_requ_1 * );
extern PTYPE void m_aux_udp_cleanup( DSD_CONN_G *, char * );
extern PTYPE BOOL m_aux_sip_requ_1( void *, struct dsd_sdh_sip_requ_1 * );
extern PTYPE void m_aux_sip_cleanup( DSD_CONN_G *, char * );
extern PTYPE void m_sip_set_conn1( void * ap_sipr_handle, void * ap_conn1 );
extern PTYPE BOOL m_aux_udp_gate_1( void *, struct dsd_aux_cmd_udp_gate * );
extern PTYPE void m_aux_gate_udp_counter( char *, int *, int *, HL_LONGLONG *, HL_LONGLONG * );
extern PTYPE void m_aux_gate_udp_cleanup( DSD_CONN_G *, char * );
#ifdef INCL_GW_L2TP
extern PTYPE int m_l2tp_pass_session_owner( struct dsd_l2tp_session *adsp_l2tp_session, char *achp_area, int imp_len_area );
#endif
extern PTYPE BOOL m_radius_server_open( char *achp_work, int imp_len_work,
                                        amd_msgprog amp_msgproc, void * vpp_userfld,
                                        struct dsd_radius_entry *adsp_re );
extern PTYPE void m_radius_init( struct dsd_radius_control_1 *adsp_rctrl1,
                                 struct dsd_radius_group *adsp_radius_group,
                                 void * ap_conn1,  /* address connection */
                                 struct sockaddr *adsp_soa_client,  /* sockaddr of client */
                                 amd_radius_query_compl amp_radius_query_compl );  /* callback when radius request complete */
extern PTYPE BOOL m_radius_request( struct dsd_radius_control_1 *, struct dsd_hl_aux_radius_1 * );
extern PTYPE void m_radius_cleanup( struct dsd_radius_control_1 * );
extern PTYPE int m_send_snmp_packet( char *, int );
extern PTYPE BOOL m_udp_create_socket( struct dsd_udp_multiw_1 *, struct dsd_udp_param_1 * );
extern PTYPE void m_start_udp_recv( struct dsd_udp_multiw_1 * );
extern PTYPE void m_udp_set_conn1( void * ap_udpr_handle, void * ap_conn1 );
extern PTYPE int m_udp_sendto( struct dsd_udp_multiw_1 *, char *, int, struct sockaddr *, int, int * );
extern PTYPE int m_udp_send_vector( struct dsd_udp_multiw_1 *, void *, int, struct sockaddr *, int, int * );
extern PTYPE void m_close_udp_multiw_1( struct dsd_udp_multiw_1 * );
#endif
extern PTYPE void m_l2tp_start( struct dsd_l2tp_conf * );
#ifdef INCL_GW_L2TP
extern PTYPE void m_l2tp_conn( struct dsd_l2tp_conf *, struct dsd_l2tp_session *, enum ied_scp_def, UNSIG_MED, UNSIG_MED );
extern PTYPE BOOL m_l2tp_send( struct dsd_hco_wothr *, struct dsd_l2tp_session *, struct dsd_gather_i_1 * );
#ifdef B110904
extern PTYPE void m_l2tp_canrecv( struct dsd_l2tp_session * );
#endif
extern PTYPE void m_l2tp_close( struct dsd_l2tp_session * );
extern PTYPE void m_l2tp_client_end( struct dsd_l2tp_session * );
//#ifdef D_HPPPT1_1
#ifdef D_INCL_HOB_TUN
#ifdef B160503
extern PTYPE struct dsd_targfi_1 * m_get_l2tp_targfi( struct dsd_l2tp_session * );
#endif
#ifndef B160503
extern PTYPE struct dsd_targfi_1 * m_get_l2tp_targfi( struct dsd_l2tp_session *, int *, int * );
#endif
extern PTYPE BOOL m_get_l2tp_sstp_flag_channel_binding( struct dsd_l2tp_session * );
extern PTYPE BOOL m_get_tun_sstp_flag_channel_binding( struct dsd_tun_contr_conn * );
extern PTYPE BOOL m_check_l2tp_sstp_channel_binding( struct dsd_l2tp_session *, char *, int );
extern PTYPE BOOL m_check_tun_sstp_channel_binding( struct dsd_tun_contr_conn *, char *, int );
extern PTYPE void m_ppp_auth_1( struct dsd_ppp_server_1 * );
extern PTYPE void m_ppp_auth_2( struct dsd_ppp_client_1 *, enum ied_ppp_auth_def );
#endif
extern PTYPE void m_ppp_auth_free( struct dsd_ppp_server_1 * );
#ifdef B120508
extern PTYPE void m_radqu_ret_callback( void *, enum ied_radius_resp );
#endif
extern PTYPE void m_ppp_se_auth_ret( struct dsd_ppp_server_1 *, enum ied_chid_ret );
#ifdef D_INCL_HOB_TUN
#ifdef B160503
extern PTYPE struct dsd_ppp_targfi_act_1 * m_create_ppp_targfi( struct dsd_targfi_1 * );
#endif
#ifndef B160503
extern PTYPE struct dsd_ppp_targfi_act_1 * m_create_ppp_targfi( struct dsd_targfi_1 *, int, int );
#endif
extern PTYPE enum ied_ret_cf m_proc_ppp_targfi_ipv4( struct dsd_hco_wothr *, struct dsd_ppp_targfi_act_1 *, struct dsd_gather_i_1 *, int );
extern PTYPE enum ied_ret_cf m_proc_ppp_targfi_ipv6( struct dsd_hco_wothr *, struct dsd_ppp_targfi_act_1 *, struct dsd_gather_i_1 *, int );
/* new 30.04.10 KB */
extern PTYPE void m_ineta_req_cluster_recv( struct dsd_cluster_proc_recv *, int );
extern PTYPE void m_ineta_resp_cluster_recv( struct dsd_cluster_proc_recv *, int );
extern PTYPE void m_ineta_rej_cluster_recv( struct dsd_cluster_proc_recv *, int );
extern PTYPE int m_tun_pass_session_owner( struct dsd_tun_contr_conn *, char *, int );
#endif
#endif
#ifdef TRY_D_INCL_HTUN
extern PTYPE BOOL m_tcp_dynamic_conn( void *, struct dsd_aux_tcp_conn_1 *, struct dsd_target_ineta_1 *, void *, BOOL );
extern PTYPE int m_tcp_static_conn( void *, BOOL );
extern PTYPE BOOL m_tcp_close( void * );
#endif
#ifdef HL_UNIX
extern PTYPE BOOL m_tcp_dynamic_conn( void *, struct dsd_aux_tcp_conn_1 *, struct dsd_target_ineta_1 *, void *, BOOL );
extern PTYPE int m_tcp_static_conn( void *, BOOL );
extern PTYPE BOOL m_tcp_close( void * );
#endif
#ifdef B110904
extern PTYPE BOOL m_l2tp_to_client( struct dsd_l2tp_session *, struct dsd_sdh_control_1 * );
#endif
extern PTYPE void m_l2tp_to_client( struct dsd_l2tp_session *, struct dsd_sdh_control_1 *, BOOL );
extern PTYPE void m_l2tp_warning( struct dsd_l2tp_session *, const char *achp_format, ... );
extern PTYPE void m_l2tp_information( struct dsd_l2tp_session *, const char *achp_format, ... );
extern PTYPE void m_l2tp_set_ppp_auth( struct dsd_l2tp_session *, char * );
extern PTYPE void m_l2tp_repeat_send( struct dsd_hco_wothr *, struct dsd_l2tp_session * );
extern PTYPE char * m_l2tp_get_client_ineta( struct dsd_l2tp_session * );
extern PTYPE void m_l2tp_server_end( struct dsd_l2tp_session *, BOOL, char * );
extern PTYPE void m_radius_warning( void * ap_conn1, int imp_error_number, const char *achp_format, ... );
extern PTYPE void m_ldap_warning( void * ap_conn1, int imp_error_number, const char *achp_format, ... );
extern PTYPE void m_ldap_info( void * ap_conn1, int imp_error_number, const char *achp_format, ... );
extern PTYPE BOOL m_krb5_sign_on( struct dsd_aux_cf1 *, struct dsd_krb5_kdc_1 *, struct dsd_aux_krb5_sign_on_1 * );
extern PTYPE BOOL m_krb5_se_ti_get( struct dsd_aux_cf1 *, struct dsd_krb5_kdc_1 *, struct dsd_aux_krb5_se_ti_get_1 * );
extern PTYPE BOOL m_krb5_se_ti_c_r( struct dsd_aux_cf1 *, struct dsd_aux_krb5_se_ti_c_r_1 * );
extern PTYPE BOOL m_krb5_se_ti_check_request( struct dsd_aux_cf1 *, struct dsd_aux_krb5_se_ti_check_1 * );
extern PTYPE BOOL m_krb5_get_session_key( struct dsd_aux_krb5_get_session_key * );
extern PTYPE BOOL m_krb5_encrypt( struct dsd_aux_cf1 *, struct dsd_aux_krb5_encrypt * );
extern PTYPE BOOL m_krb5_decrypt( struct dsd_aux_cf1 *, struct dsd_aux_krb5_decrypt * );
extern PTYPE BOOL m_krb5_se_ti_rel( struct dsd_aux_cf1 *, struct dsd_aux_krb5_se_ti_rel_1 * );
extern PTYPE BOOL m_krb5_logoff( struct dsd_aux_cf1 *, struct dsd_aux_krb5_logoff * );
extern PTYPE struct dsd_krb5_kdc_1 * m_krb5_session_assign_conf( struct dsd_aux_cf1 *, struct dsd_aux_krb5_session_assign_conf * );
extern PTYPE BOOL m_udp_gate_encry_init( char *achp_keys, char *achp_encode, char *achp_decode );
extern PTYPE int m_udp_gate_encry_encode( char *achp_out, int imp_len_out, char *achp_inp, int imp_len_inp, char *achp_encode );
extern PTYPE int m_udp_gate_encry_decode( char *achp_out, int imp_len_out, char *achp_inp, int imp_len_inp, char *achp_decode );
#endif
#undef DSD_CONN_G
