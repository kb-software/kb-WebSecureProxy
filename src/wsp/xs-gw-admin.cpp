#define DEBUG_100909_01
#define D_PROD_A2
#ifndef D_PROD_A2
//#define TRY_090121
//#define DEBUG_080505
#define TRACEHL1
//#define HL_DEBUG_02
#ifdef HL_DEBUG_02
#define TRACEHL_P_COUNT
#endif
#endif
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xs-gw-admin                                         |*/
/*| -------------                                                     |*/
/*|  Subroutine which builds the administration interface of gateways |*/
/*|  KB 03.04.08                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
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

#include <iostream>
#include <ostream>
#include <fstream>

using namespace std;

#ifdef TRACEHL1
#define TRACEHL_CO_OUT
#endif

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
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
#endif
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
#ifdef HL_IPV6
#include <ws2tcpip.h>
//#include <wspiapi.h>
#endif
#include <hob-wtspo1.h>
#endif
#include <hob-xslunic1.h>
#ifndef HL_UNIX
#include <hob-thread.hpp>
#include <iswcord1.h>
#endif
#include <hob-netw-01.h>
#include <hob-nblock_acc.hpp>
#ifndef TCPCOMP_V02
#ifndef TRY_090121
#include <hob-tcpco1.hpp>
#else
#include "E:\Garkuscha\Tests\tcpcomp_sample\hob-tcpco1.hpp"
#endif
#endif
#ifdef TCPCOMP_V02
#include <hob-tcpcomp-multi-v02.hpp>
#endif

#define DOMNode void

#define DEF_HL_INCL_DOM
#include "hob-xsclib01.h"

#include "hob-wsppriv.h"                    /* privileges              */
#include <hob-xslcontr.h>                   /* HOB Control             */
//#define INCL_GW_ALL
#define INCL_GW_ADMIN
#define INCL_GW_ALL
#define HL_KRB5
#define NOT_INCLUDED_CLIB
#include "hob-xbipgw08-1.h"
#include "hob-xbipgw08-2.h"
#include "hob-wsp-admin-1.h"
#include <hob-llog01.h>

#define HOBETS_1_PIPE_LB_INST 4             /* only four instances for testing */
#define HOBETS_1_PIPE_LB_NAME "\\\\.\\pipe\\test-pipe-01"
#define D_PIPE_MAX_LEN_NAME   32            /* maximum length of eyecatcher */
#define HOBADM_PIPE_NAME      "HOB-WSP-ADMIN-V01"
#define HOBADM_PIPE_MAX_OUT   4

#define CHAR_CR                0X0D         /* carriage-return         */
#define CHAR_LF                0X0A         /* line-feed               */

/* loaded configurations that are in use now                           */
extern "C" struct dsd_loconf_1 *adsg_loconf_1_inuse;

/*+-------------------------------------------------------------------+*/
/*| Internal used structures.                                         |*/
/*+-------------------------------------------------------------------+*/

#ifdef XYZ1
struct dsd_cluster_timer_1 {                /* cluster timer one       */
   struct dsd_cluster_active *adsc_clact;   /* active cluster          */
   struct dsd_timer_ele dsc_timer_ele;      /* timer element           */
};
#endif

typedef BOOL ( * amd_x_new_log_check )( void * );
typedef BOOL ( * amd_x_new_log_register )( void *, char *, int );
typedef void ( * amd_x_new_log_unreg )( void * );

#ifndef HL_UNIX
/* new 06.04.08 KB */
enum ied_pipe_state {                       /* state of pipe           */
   ied_pist_closed,                         /* pipe is closed          */
   ied_pist_error,                          /* pipe is in error condition */
   ied_pist_idle,                           /* pipe is open but idle   */
   ied_pist_didcon,                         /* pipe did connect        */
   ied_pist_wcon,                           /* pipe wait connect       */
   ied_pist_wread_first,                    /* pipe wait read first record */
   ied_pist_wread_admin,                    /* pipe wait read admin control records */
#ifdef XYZ1
   ied_pist_wwrite,                         /* pipe wait write         */
#endif
// to do 26.04.11 - the following two states are never set
   ied_pist_reaksuc,                        /* pipe read successful    */
   ied_pist_reakdir                         /* pipe read direct        */
};

enum ied_pipe_conn_command {                /* connect command for pipe */
   ied_picc_first,                          /* first call, open first  */
   ied_picc_next,                           /* open next instance      */
   ied_picc_check                           /* open next instance, check if necessary */
};
#endif

enum ied_adm_command {                      /* command for admin       */
   ied_admc_invalid = 0,                    /* command not valid       */
   ied_admc_cluster = 1,                    /* cluster                 */
   ied_admc_session = 2,                    /* session                 */
   ied_admc_cancel_session = 3,             /* cancel-session          */
   ied_admc_listen = 4,                     /* listen                  */
   ied_admc_perfdata = 5,                   /* perfdata - Performance Data */
   ied_admc_log = 6,                        /* log                     */
   ied_admc_wsp_trace = 7,                  /* WSP Trace               */
   ied_admc_wsp_tr_act = 8                  /* WSP Trace active settings */
};

#ifndef HL_UNIX
struct dsd_adm_pipe {                       /* pipe for administration */
   ied_pipe_state iec_pipe_state;           /* state of pipe           */
   BOOL       boc_write_active;             /* write is active         */
   HANDLE     dsc_hpipe1;                   /* pipe-handle load-balancing */
   struct dsd_sdh_control_1 *adsc_sdhc1_inp;  /* chain input from pipe */
   struct dsd_sdh_control_1 *adsc_sdhc1_out;  /* chain output to pipe  */
   struct dsd_gather_i_1 *adsc_gai1_out;    /* gather out data pipe    */
   struct dsd_adm_pipe_new_log *adsc_ap_new_log;  /* structure for new log to pipe */
   OVERLAPPED dsc_olstruct_read;            /* structure for overlapped IO */
   OVERLAPPED dsc_olstruct_write;           /* structure for overlapped IO */
// char       chrc_inp_pipe[ LEN_BUFFER_PIPE_LB ];  /* area input from pipe */
// int        inc_inp_pos;                  /* position in input area  */
};

struct dsd_adm_pipe_new_log {               /* structure for new log to pipe */
   struct dsd_log_new_call dsc_lnc;         /* parameters call new log message */
   struct dsd_adm_pipe *adsc_adm_pipe;      /* pipe for administration */
   int        imc_len_query;                /* length of following query string, UTF-8 */
   struct dsd_ml_search_1 dsc_mls1;         /* search in memory log    */
};
#endif

struct dsd_cb_new_log {                     /* structure for new log callbacks */
   amd_x_new_log_check amc_x_new_log_check;
   amd_x_new_log_register amc_x_new_log_register;
   amd_x_new_log_unreg amc_x_new_log_unreg;
};

struct dsd_cluster_admin_1 {                /* admin request in cluster */
   struct dsd_cluster_admin_1 *adsc_next;   /* for chaining            */
   struct dsd_hco_wothr *adsc_hco_wothr;    /* pointer on work-thread  */
   struct dsd_cluster_active *adsc_clact;   /* active cluster structure */
#ifdef XYZ1
   struct dsd_cluster_send dsc_clsend;      /* data to send            */
#endif
   struct dsd_sdh_control_1 *adsc_sdhc1_ret;  /* data returned         */
#ifdef XYZ1
// do-to 07.09.08 use timer in wait
   struct dsd_timer_ele dsc_timer;          /* timer for wait          */
#endif
};

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

#ifndef HL_UNIX
/* new 06.04.08 KB */
static void m_admin_pipe_start( void );
static htfunc1_t m_adm_pipe_thread( void * );
static void m_adm_pipe_proc( struct dsd_adm_pipe * );
static void m_adm_pipe_write( struct dsd_adm_pipe *, BOOL );
static void m_pipe_new_inst( ied_pipe_conn_command );
#endif
static struct dsd_sdh_control_1 * m_cluster_admin( HL_LONGLONG, struct dsd_gather_i_1 *, struct dsd_cluster_admin_1 * );
static void m_cluster_free_send( struct dsd_cluster_send * );
static void m_timeout_cluster( struct dsd_timer_ele * );
static struct dsd_sdh_control_1 * m_get_wspadm1_log( struct dsd_wspadm1_q_log *, int, struct dsd_cb_new_log *, void * );
#ifdef XYZ1
static int m_pipe_lb_1_req( char *, int );
#endif
#ifndef HL_UNIX
static BOOL m_pipe_new_log_check( void * );
static BOOL m_pipe_new_log_register( void *, char *, int );
static void m_pipe_new_log_unreg( void * );
static void m_pipe_log_new_call( struct dsd_log_new_call *, struct dsd_log_new_pass * );
#endif

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

#ifndef HL_UNIX
static class dsd_hcla_critsect_1 dss_critsect_admin;  /* critical section for admin */
static class dsd_hcthread dss_thread_adm_pipe;  /* thread of console    */
static struct dsd_adm_pipe dsrs_pipe_lb_1[ HOBETS_1_PIPE_LB_INST ];  /* pipe to Load-Balancing  */
static HANDLE dss_heve_main = NULL;         /* event handle main       */
static WCHAR  *awcs_windows_pipe_name = NULL;  /* <Windows-named-pipe> */
#endif
static BOOL   bos_end = FALSE;              /* end of processing       */
static struct dsd_cluster_admin_1 *adss_cluster_admin_1_ch = NULL;  /* chain of admin request in cluster */
extern struct dsd_cluster_active *adsg_clact_ch;  /* chain of active cluster members */

static const char * achrs_adm_command[] = {
   "cluster",
   "session",
   "cancel-session",
   "listen",
   "perfdata",
   "log",
   "wsp-trace",
   "wsp-tr-act"
};

#ifndef HL_UNIX
static struct dsd_cb_new_log dss_cb_new_log_pipe = {
   &m_pipe_new_log_check,
   &m_pipe_new_log_register,
   &m_pipe_new_log_unreg
};
#endif

static const char chrs_adm_eyecatcher[] = HOBADM_PIPE_NAME;

/*+-------------------------------------------------------------------+*/
/*| Procedure division.                                               |*/
/*+-------------------------------------------------------------------+*/

//extern PTYPE void m_admin_start( struct dsd_cluster_main *adsp_cluster_main ) {
//}
/** start admin interface                                              */
extern "C" void m_admin_start( void ) {
// int        iml1;                         /* working variable        */
// BOOL       bol1;                         /* working variable        */
// int        iml_rc;                       /* return code             */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_admin_start() called",
                   __LINE__ );
#endif
#ifndef HL_UNIX
   if (adsg_loconf_1_inuse->awcc_windows_pipe_name == NULL) return;  /* <Windows-named-pipe> */
   awcs_windows_pipe_name = adsg_loconf_1_inuse->awcc_windows_pipe_name;  /* <Windows-named-pipe> */
   m_admin_pipe_start();
#endif
} /* end m_admin_start()                                               */

/** process reload configuration for admin interface                   */
extern "C" void m_admin_reload_conf( void ) {
   BOOL       bol1;                         /* working variable        */
   int        iml_rc;                       /* return code             */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_admin_reload_conf() called",
                   __LINE__ );
#endif
#ifndef HL_UNIX
   if (awcs_windows_pipe_name == adsg_loconf_1_inuse->awcc_windows_pipe_name) {  /* <Windows-named-pipe> */
     return;
   }
   awcs_windows_pipe_name = adsg_loconf_1_inuse->awcc_windows_pipe_name;  /* <Windows-named-pipe> */
   if (dss_heve_main == NULL) {             /* thread not yet started  */
     m_admin_pipe_start();
     return;
   }
   bol1 = SetEvent( dss_heve_main );
   if (bol1) return;                        /* no error occured        */
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W SetEvent() main Error %d.",
                   __LINE__, GetLastError() );
#endif
} /* end m_admin_reload_conf()                                         */

#ifndef HL_UNIX
/** start pipe for admin interface                                     */
static void m_admin_pipe_start( void ) {
   int        iml_rc;                       /* return code             */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_admin_pipe_start() called",
                   __LINE__ );
#endif
   iml_rc = dss_critsect_admin.m_create();  /* critical section        */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W m_cluster_start() dss_critsect_admin m_create Return Code %d.",
                     __LINE__, iml_rc );
   }
   dss_heve_main = CreateEvent( NULL, FALSE, FALSE, NULL );
   if (dss_heve_main == NULL) {             /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W m_admin_start() create main event Return Code %d.",
                     __LINE__, GetLastError() );
   }
   iml_rc = dss_thread_adm_pipe.mc_create( &m_adm_pipe_thread, NULL );
   if (iml_rc < 0) {
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W m_admin_start() create pipe thread Return Code %d.",
                     __LINE__, iml_rc );
   }
} /* end m_admin_pipe_start()                                          */

/** thread which handles input from the pipes                          */
static htfunc1_t m_adm_pipe_thread( void * vpp_thread_arg ) {
   BOOL       bol1;                         /* working variable        */
   DWORD      dwl1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   int        iml_lwaitch;                  /* length wait-chain       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working-variable       */
   WCHAR      *awcl_windows_pipe_name;      /* <Windows-named-pipe>    */
   HANDLE     dsrl_hwait[ 1 + HOBETS_1_PIPE_LB_INST * 2 ];  /* wait multiple */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "l%05d xs-gw-admin m_adm_pipe_thread( 0X%p ) called",
                   __LINE__, vpp_thread_arg );
#endif
   awcl_windows_pipe_name = NULL;           /* <Windows-named-pipe>    */
   dsrl_hwait[0] = dss_heve_main;           /* wait main               */
   iml_lwaitch = 1 + HOBETS_1_PIPE_LB_INST * 2;  /* length wait-chain  */
   iml1 = HOBETS_1_PIPE_LB_INST;
   do {                                     /* loop over all instances of the pipe */
     iml1--;                                /* decrement entry         */
     memset( &dsrs_pipe_lb_1[iml1], 0, sizeof(struct dsd_adm_pipe) );
     dsrs_pipe_lb_1[iml1].dsc_olstruct_read.hEvent = CreateEvent( NULL, TRUE, FALSE, NULL );
     if (dsrs_pipe_lb_1[iml1].dsc_olstruct_read.hEvent == NULL) {
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W CreateEvent Pipe Error %d",
                       __LINE__, GetLastError() );
       iml_lwaitch = 1;                     /* length wait-chain       */
       break;                               /* do not try more         */
     }
     dsrl_hwait[ 1 + iml1 * 2 ] = dsrs_pipe_lb_1[iml1].dsc_olstruct_read.hEvent;  /* wait multiple */
     dsrs_pipe_lb_1[iml1].dsc_olstruct_write.hEvent = CreateEvent( NULL, TRUE, FALSE, NULL );
     if (dsrs_pipe_lb_1[iml1].dsc_olstruct_write.hEvent == NULL) {
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W CreateEvent Pipe Error %d",
                       __LINE__, GetLastError() );
       iml_lwaitch = 1;                     /* length wait-chain       */
       break;                               /* do not try more         */
     }
     dsrl_hwait[ 1 + iml1 * 2 + 1 ] = dsrs_pipe_lb_1[iml1].dsc_olstruct_write.hEvent;  /* wait multiple */
   } while (iml1 > 0);
   /* open first instance now                                          */
   while (TRUE) {                           /* endless loop            */
     if (awcl_windows_pipe_name != awcs_windows_pipe_name) {  /* pipe name has changed */
       awcl_windows_pipe_name = awcs_windows_pipe_name;  /* save new pipe name */
       if (awcl_windows_pipe_name) {        /* we want to have a pipe  */
         m_pipe_new_inst( ied_picc_first );   /* first call, open first */
       }
     }
     dwl1 = WaitForMultipleObjects( iml_lwaitch, dsrl_hwait, FALSE, INFINITE );
     if (bos_end) break;                    /* end of processing       */
     iml1 = dwl1 - (WAIT_OBJECT_0 + 1);
     if (iml1 >= 0) {                       /* event of pipe           */
#define DSL_PIPE_LB_1 dsrs_pipe_lb_1[ iml1 >> 1 ]
#ifndef OLD01
       bol1 = ResetEvent( dsrl_hwait[ iml1 + 1 ] );
       if (bol1 == FALSE) {
         m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W ResetEvent Pipe LB Error %d",
                         __LINE__, GetLastError() );
       }
#endif
       if ((iml1 & 1) == 0) {
         m_adm_pipe_proc( &DSL_PIPE_LB_1 );
       } else {
         m_adm_pipe_write( &DSL_PIPE_LB_1, TRUE );
       }
#undef DSL_PIPE_LB_1
     } else if (iml1 == -1) {
       iml1 = HOBETS_1_PIPE_LB_INST;
       do {                                     /* loop over all instances of the pipe */
         iml1--;                                /* decrement entry         */
#define DSL_PIPE_LB_1 dsrs_pipe_lb_1[ iml1 ]
         if ((DSL_PIPE_LB_1.adsc_sdhc1_out) && (DSL_PIPE_LB_1.boc_write_active == FALSE)) {
           m_adm_pipe_write( &DSL_PIPE_LB_1, FALSE );
         }
#undef DSL_PIPE_LB_1
       } while (iml1 > 0);
     } else {
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W main WaitForMultipleObjects() Error %d/%d.",
                       __LINE__, dwl1, GetLastError() );
     }
   }
   /* close pipe instances                                             */
   iml1 = HOBETS_1_PIPE_LB_INST;
   do {                                     /* loop over all instances of the pipe */
     iml1--;                                /* decrement entry         */
     if (dsrs_pipe_lb_1[iml1].iec_pipe_state != ied_pist_closed) {  /* pipe is not closed */
       bol1 = CloseHandle( dsrs_pipe_lb_1[iml1].dsc_hpipe1 );
       if (bol1 == FALSE) {
         m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W CloseHandle Pipe Error %d.",
                         __LINE__, GetLastError() );
       }
     }
     if (dsrs_pipe_lb_1[iml1].adsc_ap_new_log) {
       bol1 = m_log_new_p_unreg( &dsrs_pipe_lb_1[iml1].adsc_ap_new_log->dsc_lnc );
       if (bol1 == FALSE) {
         m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W m_log_new_p_unreg() returned FALSE",
                         __LINE__ );
       }
       Sleep( 500 );                        /* wait some time          */
       free( dsrs_pipe_lb_1[iml1].adsc_ap_new_log );  /* free memory again */
     }
     while (dsrs_pipe_lb_1[iml1].adsc_sdhc1_inp) {  /* loop over input data */
       adsl_sdhc1_w1 = dsrs_pipe_lb_1[iml1].adsc_sdhc1_inp;  /* get input data */
       dsrs_pipe_lb_1[iml1].adsc_sdhc1_inp = dsrs_pipe_lb_1[iml1].adsc_sdhc1_inp->adsc_next;
       m_proc_free( adsl_sdhc1_w1 );        /* free buffer             */
     }
     while (dsrs_pipe_lb_1[iml1].adsc_sdhc1_out) {  /* loop over output data */
       adsl_sdhc1_w1 = dsrs_pipe_lb_1[iml1].adsc_sdhc1_out;  /* get output data */
       dsrs_pipe_lb_1[iml1].adsc_sdhc1_out = dsrs_pipe_lb_1[iml1].adsc_sdhc1_out->adsc_next;
       m_proc_free( adsl_sdhc1_w1 );        /* free buffer             */
     }
   } while (iml1 > 0);
   /* close all event-semaphores                                       */
   iml1 = iml_lwaitch;
   do {
     iml1--;                                /* decrement entry         */
     bol1 = CloseHandle( dsrl_hwait[ iml1 ] );
     if (bol1 == FALSE) {
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W CloseHandle Event Error %d.",
                       __LINE__, GetLastError() );
     }
   } while (iml1 > 0);
   dss_critsect_admin.m_close();            /* critical section        */
   return 0;
} /* end m_adm_pipe_thread()                                           */

/** process new state of pipe                                          */
static void m_adm_pipe_proc( struct dsd_adm_pipe *adsp_adm_pipe ) {
   BOOL       bol1;                         /* working variable        */
   DWORD      dwl1;                         /* working variable        */
   int        iml1, iml2;                   /* working variables       */
   char       *achl1, *achl2;               /* working variables       */
   int        iml_len;                      /* length of data received */
   int        iml_sub;                      /* length of sub structure */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working-variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working-variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w3;  /* working-variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_cur;  /* current in chain      */
   struct dsd_sdh_control_1 *adsl_sdhc1_last;  /* was last in chain    */
   ULONG      uml_trans_pipe;               /* return bytes transfered */
   enum ied_adm_command iel_adm_command;    /* command for admin       */
   char       chl_record_type;              /* record type             */
   void *     vprl_work[ 1024 / sizeof(void *) ];  /* work-area aligned */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_adm_pipe_proc( %p ) iec_pipe_state=%d",
                   __LINE__, adsp_adm_pipe, adsp_adm_pipe->iec_pipe_state );
#endif
   switch (adsp_adm_pipe->iec_pipe_state) {
     case ied_pist_didcon:                  /* pipe did connect        */
       adsp_adm_pipe->iec_pipe_state = ied_pist_wread_first;  /* pipe wait read first record */
       goto p_adm_pipe_20;                  /* read from pipe          */
     case ied_pist_wcon:                    /* pipe wait connect       */
       bol1 = GetOverlappedResult( adsp_adm_pipe->dsc_hpipe1,
                                   &adsp_adm_pipe->dsc_olstruct_read, &uml_trans_pipe, TRUE );
       if (bol1 == FALSE) {                 /* error occured           */
         dwl1 = GetLastError();
#ifdef TRACEHL1
         m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_adm_pipe_proc( %p ) ied_pist_wcon GetOverlappedResult() GetLastError()=%d",
                         __LINE__, adsp_adm_pipe, dwl1 );
#endif
         adsp_adm_pipe->iec_pipe_state = ied_pist_error;  /* pipe is in error condition */
         return;
       }
       adsp_adm_pipe->iec_pipe_state = ied_pist_wread_first;  /* pipe wait read first record */
       m_pipe_new_inst( ied_picc_next );    /* open next instance      */
       goto p_adm_pipe_20;                  /* read from pipe          */
     case ied_pist_wread_first:             /* pipe wait read first record */
     case ied_pist_wread_admin:             /* pipe wait read admin control records */
       bol1 = GetOverlappedResult( adsp_adm_pipe->dsc_hpipe1,
                                   &adsp_adm_pipe->dsc_olstruct_read, &uml_trans_pipe, TRUE );
       if (bol1 == TRUE) goto p_adm_pipe_40;  /* read from pipe complete */
       dwl1 = GetLastError();
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_adm_pipe_proc( %p ) ied_pist_wread_... GetOverlappedResult() GetLastError()=%d",
                       __LINE__, adsp_adm_pipe, dwl1 );
#endif
       if (dwl1 != ERROR_BROKEN_PIPE) {     /* not pipe ended          */
         m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W ied_pist_wread_... GetOverlappedResult() Error %d.",
                         __LINE__, GetLastError() );
         adsp_adm_pipe->iec_pipe_state = ied_pist_error;  /* pipe is in error condition */
         return;
       }
       /* pipe ended                                                   */
#ifdef XYZ1
       if (adsp_adm_pipe->inc_inp_pos) {   /* already bytes read      */
         m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W ied_pist_wread_... ReadFile returned ERROR_BROKEN_PIPE but partitial read %d",
                         __LINE__, adsp_adm_pipe->inc_inp_pos );
       }
#endif
       if (adsp_adm_pipe->adsc_ap_new_log) {
         bol1 = m_log_new_p_unreg( &adsp_adm_pipe->adsc_ap_new_log->dsc_lnc );
         if (bol1 == FALSE) {
           m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W m_log_new_p_unreg() returned FALSE",
                           __LINE__ );
         }
         Sleep( 500 );                      /* wait some time          */
         free( adsp_adm_pipe->adsc_ap_new_log );  /* free memory again */
         adsp_adm_pipe->adsc_ap_new_log = NULL;  /* new log not active */
       }
       while (adsp_adm_pipe->adsc_sdhc1_inp) {  /* loop over input data */
         adsl_sdhc1_w1 = adsp_adm_pipe->adsc_sdhc1_inp;  /* get input data */
         adsp_adm_pipe->adsc_sdhc1_inp = adsp_adm_pipe->adsc_sdhc1_inp->adsc_next;
         m_proc_free( adsl_sdhc1_w1 );      /* free buffer             */
       }
       while (adsp_adm_pipe->adsc_sdhc1_out) {  /* loop over output data */
         adsl_sdhc1_w1 = adsp_adm_pipe->adsc_sdhc1_out;  /* get output data */
         adsp_adm_pipe->adsc_sdhc1_out = adsp_adm_pipe->adsc_sdhc1_out->adsc_next;
         m_proc_free( adsl_sdhc1_w1 );      /* free buffer             */
       }
       adsp_adm_pipe->adsc_gai1_out = NULL;  /* no data to be written  */
       adsp_adm_pipe->iec_pipe_state = ied_pist_idle;  /* pipe is idle now */
       bol1 = DisconnectNamedPipe( adsp_adm_pipe->dsc_hpipe1 );
       if (bol1 == FALSE) {
         m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W ied_pist_wread_... DisconnectNamedPipe() Error %d.",
                         __LINE__, GetLastError() );
       }
       m_pipe_new_inst( ied_picc_check );   /* start new instance, if required */
       return;
#ifdef XYZ1
     case ied_pist_wwrite:                  /* pipe wait write         */
       bol1 = GetOverlappedResult( adsp_adm_pipe->dsc_hpipe1, &adsp_adm_pipe->dsc_olstruct_read, &uml_trans_pipe, TRUE );
       if (bol1 == TRUE) {                  /* write from pipe complete */
         goto p_adm_pipe_64;                /* write succeeded         */
       }
       dwl1 = GetLastError();
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W ied_pist_wwrite GetOverlappedResult() Error %d.",
                       __LINE__, dwl1 );
       adsp_adm_pipe->iec_pipe_state = ied_pist_error;  /* pipe is in error condition */
       return;
#endif
     case ied_pist_reaksuc:                 /* pipe read successful    */
       goto p_adm_pipe_40;                  /* process data read       */
     case ied_pist_reakdir:                 /* pipe read direct        */
       break;
// 06.03.06 KB default = illogic
   }
   adsp_adm_pipe->iec_pipe_state = ied_pist_wread_first;  /* pipe wait read */
//   ied_pist_wread_first,                    /* pipe wait read first record */
//   ied_pist_wread_admin,                    /* pipe wait read admin control records */

   p_adm_pipe_20:                           /* read from pipe          */
#ifdef XYZ1
   adsp_adm_pipe->inc_inp_pos = 0;         /* not bytes read till now */
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_adm_pipe_proc( %p ) p_adm_pipe_20: start",
                   __LINE__, adsp_adm_pipe );
#endif
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))
   adsl_sdhc1_w1 = adsp_adm_pipe->adsc_sdhc1_inp;  /* get input data  */
   adsl_sdhc1_last = NULL;                  /* clear last entry        */
   while (adsl_sdhc1_w1) {                  /* loop over input data    */
     adsl_sdhc1_last = adsl_sdhc1_w1;       /* save last element       */
     if (ADSL_GAI1_W1->achc_ginp_end < ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV)) break;
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   }
   if (adsl_sdhc1_w1 == NULL) {             /* no buffer usable        */
     adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
#ifdef DEBUG_080505
     printf( "xs-gw-admin-l%05d-T m_adm_pipe_proc( %p ) m_proc_alloc returned %p.\n",
             __LINE__, adsp_adm_pipe, adsl_sdhc1_w1 );
     fflush( stdout );
#endif
     memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
     adsl_sdhc1_w1->adsc_gather_i_1_i = ADSL_GAI1_W1;
     ADSL_GAI1_W1->achc_ginp_cur = (char *) adsl_sdhc1_w1 + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1);
     ADSL_GAI1_W1->achc_ginp_end = ADSL_GAI1_W1->achc_ginp_cur;
     if (adsl_sdhc1_last == NULL) {         /* is first element        */
       adsp_adm_pipe->adsc_sdhc1_inp = adsl_sdhc1_w1;  /* set first element */
     } else {                               /* append to chain         */
       adsl_sdhc1_last->adsc_next = adsl_sdhc1_w1;  /* append to chain */
       ((struct dsd_gather_i_1 *) (adsl_sdhc1_last + 1))->adsc_next = ADSL_GAI1_W1;
     }
   }
   bol1 = ReadFile( adsp_adm_pipe->dsc_hpipe1,
                    ADSL_GAI1_W1->achc_ginp_end,
                    ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV) - ADSL_GAI1_W1->achc_ginp_end,
                    &uml_trans_pipe, &adsp_adm_pipe->dsc_olstruct_read );
#ifdef TRACEHL1
   dwl1 = GetLastError();
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_adm_pipe_proc( %p ) p_adm_pipe_20: after ReadFile 1 bol1=%d",
                   __LINE__, adsp_adm_pipe, bol1 );
#endif
   if (bol1 == FALSE) {                     /* read returned error     */
#ifndef TRACEHL1
     dwl1 = GetLastError();
#endif
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_adm_pipe_proc( %p ) p_adm_pipe_20: after ReadFile 2 GetLastError()=%d",
                   __LINE__, adsp_adm_pipe, dwl1 );
#endif
     switch (dwl1) {
       case ERROR_BROKEN_PIPE:
         adsp_adm_pipe->iec_pipe_state = ied_pist_idle;  /* pipe is idle now */
         bol1 = DisconnectNamedPipe( adsp_adm_pipe->dsc_hpipe1 );
         if (bol1 == FALSE) {               /* error occured           */
           m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W DisconnectNamedPipe() Pipe Error %d.",
                         __LINE__, GetLastError() );
         }
         m_pipe_new_inst( ied_picc_check );  /* start new instance, if required */
         return;
       case ERROR_IO_PENDING:
         return;
       default:
         m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W ReadFile() Pipe Error %d.",
                       __LINE__, GetLastError() );
         return;
     }
     return;
   }
#undef ADSL_GAI1_W1

   p_adm_pipe_40:                           /* process data read       */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_adm_pipe_proc( %p ) after ReadFile p_adm_pipe_40 uml_trans_pipe=%d.",
                 __LINE__, adsp_adm_pipe, uml_trans_pipe );
#endif
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))
   adsl_sdhc1_w1 = adsp_adm_pipe->adsc_sdhc1_inp;  /* get input data   */
   while (adsl_sdhc1_w1) {                  /* loop over input data    */
     if (ADSL_GAI1_W1->achc_ginp_end < ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV)) break;
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   }
   if (adsl_sdhc1_w1 == NULL) {             /* no buffer usable        */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W after ReadFile() p_adm_pipe_40 no data read found - illogic",
                     __LINE__ );
     return;
   }
   ADSL_GAI1_W1->achc_ginp_end += uml_trans_pipe;  /* add length read  */
   if (adsp_adm_pipe->iec_pipe_state == ied_pist_wread_admin) {  /* pipe wait read admin control records */
     goto p_adm_pipe_60;                    /* process admin control record */
   }
   adsl_sdhc1_w1 = adsl_sdhc1_w2 = adsp_adm_pipe->adsc_sdhc1_inp;  /* get input data */
   achl1 = ADSL_GAI1_W1->achc_ginp_cur;     /* get start of data       */
   achl2 = (char *) vprl_work;              /* put first string into work area */
   bol1 = FALSE;                            /* state <CR><LF>          */
   while (TRUE) {                           /* loop to retrieve eyecatcher */
     while (achl1 >= ADSL_GAI1_W1->achc_ginp_end) {
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       if (adsl_sdhc1_w1 == NULL) {         /* end of data read        */
         goto p_adm_pipe_20;                /* read next record        */
       }
       achl1 = ADSL_GAI1_W1->achc_ginp_cur;  /* get start of data      */
     }
     if (*achl1 == CHAR_CR) {               /* carriage-return found   */
       bol1 = TRUE;                         /* set state               */
     } else if (*achl1 == CHAR_LF) {        /* line-feed found         */
       if (bol1) {                          /* found carriage-return before */
         achl1++;                           /* after this character    */
         achl2--;                           /* decrement end output    */
         break;
       }
     } else {                               /* normal character received */
       bol1 = FALSE;                        /* set state               */
     }
     if (achl2 >= ((char *) vprl_work + D_PIPE_MAX_LEN_NAME)) {  /* maximum length of eyecatcher */
       m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_adm_pipe_proc( %p ) eyecatcher too long - first part \"%.*s\"",
                       __LINE__, adsp_adm_pipe, achl2 - ((char *) vprl_work), vprl_work );
       goto p_adm_pipe_close;               /* close pipe              */
     }
     *achl2++ = *achl1++;                   /* get character input     */
   }
   if (   ((achl2 - ((char *) vprl_work)) != (sizeof(chrs_adm_eyecatcher) - 1))
       || (memcmp( vprl_work, chrs_adm_eyecatcher, sizeof(chrs_adm_eyecatcher) - 1 ))) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_adm_pipe_proc( %p ) eyecatcher \"%.*s\" unknow - pipe closed",
                     __LINE__, adsp_adm_pipe, achl2 - ((char *) vprl_work), vprl_work );
     goto p_adm_pipe_close;                 /* close pipe              */
   }
   adsp_adm_pipe->iec_pipe_state = ied_pist_wread_admin;  /* now pipe wait read admin control records */
   m_hlnew_printf( HLOG_XYZ1, "HWSPA01I xs-gw-admin-l%05d m_adm_pipe_proc( %p ) admin-pipe connected",
                   __LINE__, adsp_adm_pipe );
   ADSL_GAI1_W1->achc_ginp_cur = achl1;     /* this gather data processed */
   /* release all memory received before                               */
   if (adsl_sdhc1_w1 != adsl_sdhc1_w2) {
     adsp_adm_pipe->adsc_sdhc1_inp = adsl_sdhc1_w1;  /* set input data */
     do {                                   /* loop to release memory  */
       adsl_sdhc1_w3 = adsl_sdhc1_w2;       /* get this block          */
       adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;  /* get next in chain */
       m_proc_free( adsl_sdhc1_w3 );        /* free buffer             */
     } while (adsl_sdhc1_w2 != adsl_sdhc1_w1);
   }
   if (achl1 >= ADSL_GAI1_W1->achc_ginp_end) {  /* all data in this block processed */
     adsp_adm_pipe->adsc_sdhc1_inp = adsl_sdhc1_w1->adsc_next;  /* set input data */
     m_proc_free( adsl_sdhc1_w1 );          /* free buffer             */
     if (adsp_adm_pipe->adsc_sdhc1_inp == NULL) {  /* no more data to process */
       goto p_adm_pipe_20;                  /* read next record        */
     }
   }

   p_adm_pipe_60:                           /* process admin control record */
   /* check if complete record                                         */
   adsl_sdhc1_w1 = adsp_adm_pipe->adsc_sdhc1_inp;  /* get input data   */
   achl1 = ADSL_GAI1_W1->achc_ginp_cur;     /* get start of data       */
   iml_len = 0;                             /* clear length retrieved  */
   iml1 = 4;                                /* maximum number of digits */
   do {                                     /* loop to retrieve length NHASN */
     if (iml1 <= 0) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_adm_pipe_proc( %p ) NHASN too many digits - record total",
                       __LINE__, adsp_adm_pipe );
       goto p_adm_pipe_close;               /* close pipe              */
     }
     while (achl1 >= ADSL_GAI1_W1->achc_ginp_end) {
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       if (adsl_sdhc1_w1 == NULL) {         /* end of data read        */
         goto p_adm_pipe_20;                /* read next record        */
       }
       achl1 = ADSL_GAI1_W1->achc_ginp_cur;  /* get start of data      */
     }
     iml2 = (unsigned char) *achl1 & 0X80;  /* get more bit            */
     iml_len <<= 7;                         /* shift old value         */
     iml_len |= *achl1 & 0X7F;              /* apply new bits          */
     achl1++;                               /* increment input         */
     iml1--;                                /* decrement digits allowed */
   } while (iml2);
   if (iml_len <= 0) {                      /* record length invalid   */
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_adm_pipe_proc( %p ) length record total zero",
                     __LINE__, adsp_adm_pipe );
     goto p_adm_pipe_close;                 /* close pipe              */
   }
   /* check if complete record received                                */
#define ADSL_GAI1_W2 ((struct dsd_gather_i_1 *) (adsl_sdhc1_w2 + 1))
   adsl_sdhc1_w2 = adsl_sdhc1_w1;           /* get current structure   */
   achl2 = achl1;                           /* get current input       */
   iml1 = iml_len;                          /* get length of data      */
   while (TRUE) {
     if (adsl_sdhc1_w2 != adsl_sdhc1_w1) {
       achl2 = ADSL_GAI1_W2->achc_ginp_cur;
     }
     iml2 = ADSL_GAI1_W2->achc_ginp_end - achl2;
     iml1 -= iml2;
     if (iml1 <= 0) break;
     adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;  /* get next in chain   */
     if (adsl_sdhc1_w2 == NULL) {           /* end of data read        */
       goto p_adm_pipe_20;                  /* read next record        */
     }
   }
#undef ADSL_GAI1_W2
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_adm_pipe_proc( %p ) ReadFile complete record length=%d.",
                 __LINE__, adsp_adm_pipe, iml_len );
#endif
   /* retrieve length of query type                                    */
   iml_sub = 0;                             /* clear length retrieved  */
   iml1 = 4;                                /* maximum number of digits */
   do {                                     /* loop to retrieve length NHASN */
     if (iml_len <= 0) {                    /* record exhausted        */
       m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_adm_pipe_proc( %p ) NHASN length query type longer than total query",
                       __LINE__, adsp_adm_pipe );
       goto p_adm_pipe_close;               /* close pipe              */
     }
     if (iml1 <= 0) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_adm_pipe_proc( %p ) NHASN too many digits - query type",
                       __LINE__, adsp_adm_pipe );
       goto p_adm_pipe_close;               /* close pipe              */
     }
     while (achl1 >= ADSL_GAI1_W1->achc_ginp_end) {
       ADSL_GAI1_W1->achc_ginp_cur = achl1;
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       if (adsl_sdhc1_w1 == NULL) {         /* end of data read        */
         goto p_adm_pipe_20;                /* read next record        */
       }
       achl1 = ADSL_GAI1_W1->achc_ginp_cur;  /* get start of data      */
     }
     iml2 = (unsigned char) *achl1 & 0X80;  /* get more bit            */
     iml_sub <<= 7;                         /* shift old value         */
     iml_sub |= *achl1 & 0X7F;              /* apply new bits          */
     achl1++;                               /* increment input         */
     iml_len--;                             /* decrement length record */
     iml1--;                                /* decrement digits allowed */
   } while (iml2);
   if (iml_sub <= 0) {                      /* length query type invalid */
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_adm_pipe_proc( %p ) length query type zero",
                     __LINE__, adsp_adm_pipe );
     goto p_adm_pipe_close;                 /* close pipe              */
   }
   if (iml_sub > iml_len) {                 /* length query type too high */
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_adm_pipe_proc( %p ) length query too high %d %d.",
                     __LINE__, adsp_adm_pipe, iml_sub, iml_len );
     goto p_adm_pipe_close;                 /* close pipe              */
   }
   if (iml_sub > sizeof(vprl_work)) {       /* length query type too high */
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_adm_pipe_proc( %p ) length query %d more than size work area",
                     __LINE__, adsp_adm_pipe, iml_sub );
     goto p_adm_pipe_close;                 /* close pipe              */
   }
   iml_len -= iml_sub;                      /* compute remaining length */
   iml1 = iml_sub;                          /* length to copy name     */
   achl2 = (char *) vprl_work;              /* fill in query type      */
   while (TRUE) {                           /* loop to fill name query type */
     while (TRUE) {
       iml2 = ADSL_GAI1_W1->achc_ginp_end - achl1;
       if (iml2 > 0) break;
       ADSL_GAI1_W1->achc_ginp_cur = achl1;
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       if (adsl_sdhc1_w1 == NULL) {         /* end of data read        */
/* to-do 13.04.08 KB data invalid */
         return;
       }
       achl1 = ADSL_GAI1_W1->achc_ginp_cur;  /* get start of data      */
     }
     if (iml2 > iml1) iml2 = iml1;
     memcpy( achl2, achl1, iml2 );
     achl1 += iml2;
     iml1 -= iml2;
     if (iml1 == 0) break;
     achl2 += iml2;
   }
   /* search type of query                                             */
   iel_adm_command = (enum ied_adm_command) (sizeof(achrs_adm_command) / sizeof(achrs_adm_command[0]));
   do {
     if (   (iml_sub == strlen( achrs_adm_command[ iel_adm_command - 1 ] ))
         && (!memcmp( vprl_work, achrs_adm_command[ iel_adm_command - 1 ], iml_sub ))) {
       break;                               /* command found           */
     }
     iel_adm_command = (ied_adm_command) (iel_adm_command - 1);
   } while (iel_adm_command > 0);
   if (iel_adm_command == ied_admc_invalid) {  /* command not valid    */
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_adm_pipe_proc( %p ) admin-command \"%.*s\" unknow - pipe closed",
                     __LINE__, adsp_adm_pipe, iml_sub, vprl_work );
     goto p_adm_pipe_close;                 /* close pipe              */
   }
   if (iel_adm_command == ied_admc_perfdata) {  /* perfdata - Performance Data */
     if (iml_len != 0) {                    /* more data passed        */
       m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_adm_pipe_proc( %p ) received ied_admc_perfdata with superflous data length=%d.",
                       __LINE__, adsp_adm_pipe, iml_len );
       goto p_adm_pipe_close;               /* close pipe              */
     }
     goto p_adm_pipe_68;                    /* process admin control record */
   }
   /* retrieve length of query data                                    */
   iml_sub = 0;                             /* clear length retrieved  */
   iml1 = 4;                                /* maximum number of digits */
   do {                                     /* loop to retrieve length NHASN */
     if (iml_len <= 0) {                    /* record exhausted        */
/* to-do 13.04.08 KB data invalid */
       break;
     }
     if (iml1 <= 0) {
/* to-do 13.04.08 KB data invalid */
       break;
     }
     while (achl1 >= ADSL_GAI1_W1->achc_ginp_end) {
       ADSL_GAI1_W1->achc_ginp_cur = achl1;
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       if (adsl_sdhc1_w1 == NULL) {         /* end of data read        */
         goto p_adm_pipe_20;                /* read next record        */
       }
       achl1 = ADSL_GAI1_W1->achc_ginp_cur;  /* get start of data      */
     }
     iml2 = (unsigned char) *achl1 & 0X80;  /* get more bit            */
     iml_sub <<= 7;                         /* shift old value         */
     iml_sub |= *achl1 & 0X7F;              /* apply new bits          */
     achl1++;                               /* increment input         */
     iml_len--;                             /* decrement length record */
     iml1--;                                /* decrement digits allowed */
   } while (iml2);
   if (iml_sub <= 0) {                      /* length query data invalid */
/* to-do 13.04.08 KB data invalid */
     return;
   }
   if (iml_sub != iml_len) {                /* length query data invalid */
/* to-do 13.04.08 KB data invalid */
     return;
   }
   /* get record type                                                  */
   chl_record_type = *achl1++;              /* get record type         */
   iml_sub--;                               /* decrement length structure */
   if (iml_sub > 0) {                       /* structure with data follow */
     if (iml_sub > sizeof(vprl_work)) {     /* length query too high   */
/* to-do 02.09.08 KB data invalid */
       return;
     }
     iml1 = iml_sub;                        /* length to copy structure */
     achl2 = (char *) vprl_work;            /* fill in query record    */
     while (TRUE) {                         /* loop to fill query record */
       while (TRUE) {
         iml2 = ADSL_GAI1_W1->achc_ginp_end - achl1;
         if (iml2 > 0) break;
         ADSL_GAI1_W1->achc_ginp_cur = achl1;
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
         if (adsl_sdhc1_w1 == NULL) {       /* end of data read        */
  /* to-do 13.04.08 KB data invalid */
           return;
         }
         achl1 = ADSL_GAI1_W1->achc_ginp_cur;  /* get start of data    */
       }
       if (iml2 > iml1) iml2 = iml1;
       memcpy( achl2, achl1, iml2 );
       achl1 += iml2;
       iml1 -= iml2;
       if (iml1 == 0) break;
       achl2 += iml2;
     }
   }
   /* remove data retrieved                                            */
   ADSL_GAI1_W1->achc_ginp_cur = achl1;
   while (   (adsp_adm_pipe->adsc_sdhc1_inp)  /* loop over input data  */
          && (adsp_adm_pipe->adsc_sdhc1_inp->adsc_gather_i_1_i->achc_ginp_cur
                >= adsp_adm_pipe->adsc_sdhc1_inp->adsc_gather_i_1_i->achc_ginp_end)) {
     adsl_sdhc1_w1 = adsp_adm_pipe->adsc_sdhc1_inp;  /* get input data */
     adsp_adm_pipe->adsc_sdhc1_inp = adsp_adm_pipe->adsc_sdhc1_inp->adsc_next;
     m_proc_free( adsl_sdhc1_w1 );          /* free buffer             */
   }
#undef ADSL_GAI1_W1
   if (chl_record_type) {
/* to-do 30.04.08 KB data invalid */
   }

   p_adm_pipe_68:                           /* process admin control record */
   adsl_sdhc1_w1 = NULL;                    /* clear return value      */
   switch (iel_adm_command) {               /* command for admin       */
     case ied_admc_cluster:                 /* cluster                 */
       if (adsp_adm_pipe->adsc_ap_new_log) break;  /* structure for new log to pipe */
       adsl_sdhc1_w1 = m_get_wspadm1_cluster();
       break;
     case ied_admc_session:                 /* session                 */
//#ifdef XYZ1
       if (iml_sub != sizeof(struct dsd_wspadm1_q_session)) {
/* to-do 30.04.08 KB data invalid */
         break;
       }
//#endif
       if (adsp_adm_pipe->adsc_ap_new_log) break;  /* structure for new log to pipe */
       adsl_sdhc1_w1 = m_get_wspadm1_session( (struct dsd_wspadm1_q_session *) vprl_work );
       break;
     case ied_admc_cancel_session:          /* cancel-session          */
//#ifdef XYZ1
       if (iml_sub != sizeof(struct dsd_wspadm1_q_can_sess_1)) {
/* to-do 01.10.08 KB data invalid */
         break;
       }
//#endif
       if (adsp_adm_pipe->adsc_ap_new_log) break;  /* structure for new log to pipe */
       adsl_sdhc1_w1 = m_get_wspadm1_cancel_session( (struct dsd_wspadm1_q_can_sess_1 *) vprl_work );
       break;
     case ied_admc_listen:                  /* listen                  */
       if (adsp_adm_pipe->adsc_ap_new_log) break;  /* structure for new log to pipe */
       adsl_sdhc1_w1 = m_get_wspadm1_listen();
       break;
     case ied_admc_perfdata:                /* perfdata - Performance Data */
       if (adsp_adm_pipe->adsc_ap_new_log) break;  /* structure for new log to pipe */
       adsl_sdhc1_w1 = m_get_wspadm1_perfdata();
       break;
     case ied_admc_log:                     /* log                     */
       adsl_sdhc1_w1 = m_get_wspadm1_log( (struct dsd_wspadm1_q_log *) vprl_work, iml_sub,
                                          &dss_cb_new_log_pipe, adsp_adm_pipe );
       break;
     case ied_admc_wsp_trace:               /* WSP Trace               */
       if (adsp_adm_pipe->adsc_ap_new_log) break;  /* structure for new log to pipe */
       if (iml_sub < sizeof(struct dsd_wspadm1_q_wsp_trace_1)) {
/* to-do 26.04.11 KB data invalid */
         break;
       }
       m_ctrl_wspadm1_wsp_trace( (struct dsd_wspadm1_q_wsp_trace_1 *) vprl_work,
                                 iml_sub - sizeof(struct dsd_wspadm1_q_wsp_trace_1) );
       break;
     case ied_admc_wsp_tr_act:              /* WSP Trace active settings */
       adsl_sdhc1_w1 = m_get_wspadm1_wsp_tr_act();
       break;
   }
   if (adsl_sdhc1_w1 == NULL) {             /* nothing returned        */
     goto p_adm_pipe_72;                    /* check if we can process more */
   }
   adsl_sdhc1_last = NULL;                  /* clear last in chain     */
   dss_critsect_admin.m_enter();            /* critical section        */
   adsl_sdhc1_cur = adsp_adm_pipe->adsc_sdhc1_out;  /* chain output to pipe */
   while (adsl_sdhc1_cur) {                 /* loop over all existing buffers */
     adsl_sdhc1_last = adsl_sdhc1_cur;      /* save last in chain      */
     adsl_sdhc1_cur = adsl_sdhc1_cur->adsc_next;  /* get next in chain */
   }
   if (adsl_sdhc1_last == NULL) {           /* at beginning of chain   */
     adsp_adm_pipe->adsc_sdhc1_out = adsl_sdhc1_w1;
   } else {
     adsl_sdhc1_last->adsc_next = adsl_sdhc1_w1;
   }
   dss_critsect_admin.m_leave();            /* critical section        */
   if (adsl_sdhc1_last) {                   /* not first one to write  */
     goto p_adm_pipe_72;                    /* check if we can process more */
   }
   m_adm_pipe_write( adsp_adm_pipe, FALSE );

   p_adm_pipe_72:                           /* check if we can process more */
   if (adsp_adm_pipe->adsc_sdhc1_inp) {     /* we have more input data */
     goto p_adm_pipe_60;                    /* process admin control record */
   }
#ifdef XYZ1
----
   if (adsp_adm_pipe->adsc_sdhc1_out == NULL) {
     goto p_adm_pipe_20;                    /* continue reading from pipe */
   }
   adsp_adm_pipe->adsc_gai1_out = adsp_adm_pipe->adsc_sdhc1_out->adsc_gather_i_1_i;
   if (adsp_adm_pipe->adsc_gai1_out == NULL) {
/* invalid to-do 14.04.08 KB */
     goto p_adm_pipe_20;                        /* continue reading from pipe */
   }

// p_adm_pipe_60:                           /* write data back         */
   bol1 = WriteFile( adsp_adm_pipe->dsc_hpipe1,
                     adsp_adm_pipe->adsc_gai1_out->achc_ginp_cur,
                     adsp_adm_pipe->adsc_gai1_out->achc_ginp_end
                       - adsp_adm_pipe->adsc_gai1_out->achc_ginp_cur,
                     &uml_trans_pipe, &adsp_adm_pipe->dsc_olstruct_read );
#ifdef TRACEHL1
   dwl1 = GetLastError();
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_adm_pipe_proc( %p ) p_adm_pipe_20: after WriteFile 1 bol1=%d",
                 __LINE__, adsp_adm_pipe, bol1 );
#endif
   if (bol1 == FALSE) {
#ifndef TRACEHL1
     dwl1 = GetLastError();
#endif
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_adm_pipe_proc( %p ) p_adm_pipe_20: after WriteFile 2 GetLastError()=%d",
                   __LINE__, adsp_adm_pipe, dwl1 );
#endif
     adsp_adm_pipe->iec_pipe_state = ied_pist_wwrite;  /* pipe wait write */
     return;
   }

   p_adm_pipe_64:                           /* write succeeded         */
   adsp_adm_pipe->adsc_gai1_out->achc_ginp_cur += uml_trans_pipe;
   if (adsp_adm_pipe->adsc_gai1_out->achc_ginp_cur
         >= adsp_adm_pipe->adsc_gai1_out->achc_ginp_end) {
     adsp_adm_pipe->adsc_gai1_out = adsp_adm_pipe->adsc_gai1_out->adsc_next;
   }
   if (adsp_adm_pipe->adsc_gai1_out) {      /* more to send            */
     goto p_adm_pipe_60;                    /* write data back         */
   }
   /* remove data written                                              */
   while (adsp_adm_pipe->adsc_sdhc1_out) {  /* loop over output data   */
     adsl_sdhc1_w1 = adsp_adm_pipe->adsc_sdhc1_out;  /* get output data */
     adsp_adm_pipe->adsc_sdhc1_out = adsp_adm_pipe->adsc_sdhc1_out->adsc_next;
     m_proc_free( adsl_sdhc1_w1 );          /* free buffer             */
   }
#endif
#ifdef XYZ1
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_adm_pipe_proc( %p ) ReadFile ret-length=%d.",
                 __LINE__, adsp_adm_pipe, uml_trans_pipe );
   m_console_out( adsp_adm_pipe->chrc_inp_pipe + adsp_adm_pipe->inc_inp_pos, uml_trans_pipe );
#endif
   adsp_adm_pipe->inc_inp_pos += uml_trans_pipe;
   if (   (adsp_adm_pipe->inc_inp_pos > sizeof(chrs_lbh_q_1))
       && !memcmp( adsp_adm_pipe->chrc_inp_pipe, chrs_lbh_q_1, sizeof(chrs_lbh_q_1) )) {
     iml1 = m_pipe_lb_1_req( adsp_adm_pipe->chrc_inp_pipe,
                             adsp_adm_pipe->inc_inp_pos );
   } else if (   (adsp_adm_pipe->inc_inp_pos >= sizeof(chrs_lbh_wmi_thread_q))
              && !memcmp( adsp_adm_pipe->chrc_inp_pipe, chrs_lbh_wmi_thread_q, sizeof(chrs_lbh_wmi_thread_q) )) {
     iml1 = m_pipe_wmi_thread( adsp_adm_pipe->chrc_inp_pipe,
                               adsp_adm_pipe->inc_inp_pos );
   } else {                                 /* invalid record received */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W Pipe invalid record received", __LINE__ );
     iml1 = 0;                              /* ignore this record      */
   }
   if (iml1 < 0) goto p_adm_pipe_20;        /* read more               */
   if (iml1 == 0) {                         /* ignore record           */
     adsp_adm_pipe->inc_inp_pos = 0;        /* start from beginning    */
     goto p_adm_pipe_20;                    /* read next record        */
   }
   adsp_adm_pipe->inc_inp_pos = 0;          /* nothing written yet     */
   bol1 = WriteFile( adsp_adm_pipe->dsc_hpipe1,
                     adsp_adm_pipe->chrc_inp_pipe, iml1,
                     &uml_trans_pipe, &adsp_adm_pipe->dsc_olstruct_read );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_adm_pipe_proc( %p ) p_adm_pipe_20: after WriteFile 1 bol1=%d",
                 __LINE__, adsp_adm_pipe, bol1 );
#endif
   if (bol1 == FALSE) {
     dwl1 = GetLastError();
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_adm_pipe_proc( %p ) p_adm_pipe_20: after WriteFile 2 GetLastError()=%d",
                   __LINE__, adsp_adm_pipe, dwl1 );
#endif
     adsp_adm_pipe->iec_pipe_state = ied_pist_wwrite;  /* pipe wait write */
     return;
   }
#endif
   goto p_adm_pipe_20;                      /* continue reading from pipe */

   p_adm_pipe_close:                        /* close pipe because of error */
// do-to 08.09.08 KB - free buffers, set state
   bol1 = DisconnectNamedPipe( adsp_adm_pipe->dsc_hpipe1 );
   if (bol1 == FALSE) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d pipe close DisconnectNamedPipe() Error %d.",
                     __LINE__, GetLastError() );
   }
   bol1 = CloseHandle( adsp_adm_pipe->dsc_hpipe1 );
   if (bol1 == FALSE) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d pipe close CloseHandle() Error %d.",
                     __LINE__, GetLastError() );
   }
   m_pipe_new_inst( ied_picc_check );       /* start new instance, if required */
   return;
} /* end m_adm_pipe_proc()                                            */

/** process write to pipe                                              */
static void m_adm_pipe_write( struct dsd_adm_pipe *adsp_adm_pipe, BOOL bop_post ) {
   BOOL       bol1;                         /* working variable        */
   DWORD      dwl1;                         /* working variable        */
   ULONG      uml_trans_pipe;               /* return bytes transfered */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working-variable       */

   if (bop_post == FALSE) goto p_p_wri_40;  /* write to pipe           */
   if (adsp_adm_pipe->adsc_sdhc1_out == NULL) {
     return;
   }
   if (adsp_adm_pipe->adsc_gai1_out == NULL) {  /* no write active     */
     return;
   }
   if (adsp_adm_pipe->boc_write_active == FALSE) {
     return;
   }
   bol1 = GetOverlappedResult( adsp_adm_pipe->dsc_hpipe1, &adsp_adm_pipe->dsc_olstruct_write, &uml_trans_pipe, TRUE );
   if (bol1) goto p_p_wri_20;               /* write complete          */
   dwl1 = GetLastError();
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W GetOverlappedResult() Write Pipe Error %d",
                   __LINE__, dwl1 );

   goto p_p_wri_80;                         /* remove all buffers      */

   p_p_wri_20:                              /* write complete          */
   adsp_adm_pipe->boc_write_active = FALSE;
   adsp_adm_pipe->adsc_gai1_out->achc_ginp_cur += uml_trans_pipe;
   if (adsp_adm_pipe->adsc_gai1_out->achc_ginp_cur < adsp_adm_pipe->adsc_gai1_out->achc_ginp_end) {
     goto p_p_wri_60;                       /* prepared for write      */
   }
   adsp_adm_pipe->adsc_gai1_out = adsp_adm_pipe->adsc_gai1_out->adsc_next;  /* get next in chain */
   if (adsp_adm_pipe->adsc_gai1_out) {      /* more to write           */
     goto p_p_wri_60;                       /* prepared for write      */
   }

   p_p_wri_28:                              /* remove this buffer      */
   dss_critsect_admin.m_enter();            /* critical section        */
   adsl_sdhc1_w1 = adsp_adm_pipe->adsc_sdhc1_out;  /* get this buffer  */
   adsp_adm_pipe->adsc_sdhc1_out = adsp_adm_pipe->adsc_sdhc1_out->adsc_next;  /* get next in chain */
   dss_critsect_admin.m_leave();            /* critical section        */
   m_proc_free( adsl_sdhc1_w1 );            /* free old buffer         */

   p_p_wri_40:                              /* write to pipe           */
   if (adsp_adm_pipe->adsc_sdhc1_out == NULL) return;
   adsp_adm_pipe->adsc_gai1_out = adsp_adm_pipe->adsc_sdhc1_out->adsc_gather_i_1_i;
   if (adsp_adm_pipe->adsc_gai1_out == NULL) {
     goto p_p_wri_28;                       /* remove this buffer      */
   }

   p_p_wri_60:                              /* prepared for write      */
   bol1 = WriteFile( adsp_adm_pipe->dsc_hpipe1,
                     adsp_adm_pipe->adsc_gai1_out->achc_ginp_cur,
                     adsp_adm_pipe->adsc_gai1_out->achc_ginp_end
                       - adsp_adm_pipe->adsc_gai1_out->achc_ginp_cur,
                     &uml_trans_pipe, &adsp_adm_pipe->dsc_olstruct_write );
   if (bol1) goto p_p_wri_20;               /* write complete          */
   dwl1 = GetLastError();
   switch (dwl1) {
     case ERROR_IO_PENDING:
       adsp_adm_pipe->boc_write_active = TRUE;
       return;
     case ERROR_BROKEN_PIPE:
       goto p_p_wri_80;                     /* remove all buffers      */
   }
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W WriteFile() Pipe Error %d",
                   __LINE__, dwl1 );

   p_p_wri_80:                              /* remove all buffers      */
   dss_critsect_admin.m_enter();            /* critical section        */
   while (adsp_adm_pipe->adsc_sdhc1_out) {  /* loop over all existing buffers */
     adsl_sdhc1_w1 = adsp_adm_pipe->adsc_sdhc1_out;  /* get this buffer  */
     adsp_adm_pipe->adsc_sdhc1_out = adsp_adm_pipe->adsc_sdhc1_out->adsc_next;  /* get next in chain */
     m_proc_free( adsl_sdhc1_w1 );          /* free old buffer         */
   }
   dss_critsect_admin.m_leave();            /* critical section        */
   adsp_adm_pipe->adsc_gai1_out = NULL;     /* no write active         */
   return;
} /* end m_adm_pipe_write()                                            */

/** make new instance of the pipe active                               */
static void m_pipe_new_inst( ied_pipe_conn_command iep_picc ) {
   BOOL       bol1;                         /* working variable        */
   DWORD      dwl1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   int        inl_found_idle;               /* position found instance idle */
   WCHAR      *awcl_windows_pipe_name;      /* <Windows-named-pipe>    */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_pipe_new_inst( %d ) called",
                   __LINE__, iep_picc );
#endif
   awcl_windows_pipe_name = awcs_windows_pipe_name;  /* <Windows-named-pipe> */
   if (awcl_windows_pipe_name == NULL) return;

   pnew00:                                  /* try next pipe instance  */
   iml1 = HOBETS_1_PIPE_LB_INST;
   inl_found_idle = -1;                     /* position found instance idle */
   do {                                     /* loop over all instances of the pipe */
     iml1--;                                /* decrement entry         */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_pipe_new_inst() pos=%d / %p iec_pipe_state=%d",
                     __LINE__, iml1, &dsrs_pipe_lb_1[iml1], dsrs_pipe_lb_1[iml1].iec_pipe_state );
#endif
     if (   (dsrs_pipe_lb_1[iml1].iec_pipe_state == ied_pist_closed)  /* pipe is closed */
         || (dsrs_pipe_lb_1[iml1].iec_pipe_state == ied_pist_idle)) {  /* pipe is idle */
       if (inl_found_idle < 0) {            /* position found instance idle already set? */
         inl_found_idle = iml1;             /* set position found instance idle */
         if (iep_picc != ied_picc_check) break;  /* nothing more to do */
       }
     } else if (dsrs_pipe_lb_1[iml1].iec_pipe_state == ied_pist_wcon) {  /* pipe wait connect */
       return;                              /* already instance waiting for connect */
     }
   } while (iml1 > 0);
   if (inl_found_idle < 0) return;          /* no position found instance idle */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_pipe_new_inst( %d ) open new index=%d / %p",
                   __LINE__, iep_picc, inl_found_idle, &dsrs_pipe_lb_1[ inl_found_idle ] );
#endif
   /* open this instance now                                           */
   if (dsrs_pipe_lb_1[ inl_found_idle ].iec_pipe_state == ied_pist_closed) {  /* pipe is closed */
     dsrs_pipe_lb_1[ inl_found_idle ].dsc_hpipe1
       = CreateNamedPipeW( awcl_windows_pipe_name,  // pointer to pipe name
                           PIPE_ACCESS_DUPLEX | FILE_FLAG_WRITE_THROUGH  // pipe open mode
                             | FILE_FLAG_OVERLAPPED,
                           PIPE_WAIT | PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,  //DWORD  dwPipeMode,	// pipe-specific modes
                           HOBETS_1_PIPE_LB_INST,  // maximum number of instances
                           512,  // output buffer size, in bytes
                           512,  // input buffer size, in bytes
                           INFINITE,  // time-out time, in milliseconds
                           NULL );  // pointer to security attributes structure
     if (dsrs_pipe_lb_1[ inl_found_idle ].dsc_hpipe1 == INVALID_HANDLE_VALUE) {
       m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W CreateNamedPipe Error %d.",
                       __LINE__, GetLastError() );
       dsrs_pipe_lb_1[ inl_found_idle ].iec_pipe_state = ied_pist_error;  /* pipe is in error condition */
       return;
     }
   }
   dsrs_pipe_lb_1[ inl_found_idle ].iec_pipe_state = ied_pist_wcon;  /* pipe wait connect */
   bol1 = ConnectNamedPipe( dsrs_pipe_lb_1[ inl_found_idle ].dsc_hpipe1,
                            &dsrs_pipe_lb_1[ inl_found_idle ].dsc_olstruct_read );
   if (bol1 == FALSE) {
     dwl1 = GetLastError();
     if (dwl1 == ERROR_IO_PENDING) return;  /* wait till request done  */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W ConnectNamedPipe Error %d",
                   __LINE__, GetLastError() );
     CloseHandle( dsrs_pipe_lb_1[ inl_found_idle ].dsc_hpipe1 );
     dsrs_pipe_lb_1[ inl_found_idle ].dsc_hpipe1 = INVALID_HANDLE_VALUE;  /* mark as invalid */
     dsrs_pipe_lb_1[ inl_found_idle ].iec_pipe_state
       = ied_pist_error;                    /* pipe is in error condition */
     goto pnew00;                           /* try next pipe instance  */
   }
   /* function returned immediately                                    */
   dsrs_pipe_lb_1[ inl_found_idle ].iec_pipe_state = ied_pist_didcon;  /* pipe did connect */
   m_adm_pipe_proc( &dsrs_pipe_lb_1[ inl_found_idle ] );
} /* end m_pipe_new_inst()                                              */
#endif

/** process admin request, over aux callback routine                   */
extern "C" BOOL m_proc_admin_aux( struct dsd_aux_admin_1 *adsp_admin1,
                                  struct dsd_auxf_1 *adsp_auxf_1,
                                  struct dsd_hco_wothr *adsp_hco_wothr ) {
#ifdef XYZ1
   BOOL       bol1;                         /* working variable        */
   DWORD      dwl1;                         /* working variable        */
#endif
   int        iml1, iml2;                   /* working variables       */
   char       *achl1;                       /* working variable        */
   int        iml_len;                      /* length of data received */
   int        iml_sub;                      /* length of sub structure */
   struct dsd_cluster_admin_1 *adsl_cluster_admin_1_w1;  /* admin request in cluster */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working-variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working-variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_cur;  /* current in chain      */
   struct dsd_sdh_control_1 *adsl_sdhc1_last;  /* was last in chain    */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* data to pass            */
#ifdef XYZ1
   ULONG      uml_trans_pipe;               /* return bytes transfered */
#endif
   enum ied_adm_command iel_adm_command;    /* command for admin       */
   char       chl_record_type;              /* record type             */
#ifdef XYZ1
   struct dsd_gather_i_1 dsl_gai1_w1;       /* data to pass            */
#endif
   void *     vprl_work[ 1024 / sizeof(void *) ];  /* work-area aligned */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-T m_proc_admin_aux( %p , %p )",
                   __LINE__, adsp_admin1, adsp_auxf_1 );
#endif
   if (adsp_admin1->ilc_handle_cluster) {   /* command for cluster     */
#ifdef NO_COPY_STACK
     adsl_cluster_admin_1_w1 = (struct dsd_cluster_admin_1 *)
                                 malloc( sizeof(struct dsd_cluster_admin_1)
                                           + sizeof(struct dsd_gather_i_1) );
     memset( adsl_cluster_admin_1_w1, 0, sizeof(struct dsd_cluster_admin_1) + sizeof(struct dsd_gather_i_1) );  /* data to pass */
#define ADSL_GAI1_w1 ((struct dsd_gather_i_1 *) (adsl_cluster_admin_1_w1 + 1))
     ADSL_GAI1_w1->achc_ginp_cur = adsp_admin1->achc_command;
     ADSL_GAI1_w1->achc_ginp_end = ADSL_GAI1_w1->achc_ginp_cur + adsp_admin1->imc_len_command;
     adsl_cluster_admin_1_w1->adsc_hco_wothr = adsp_hco_wothr;
     adsl_sdhc1_w1 = m_cluster_admin( adsp_admin1->ilc_handle_cluster, ADSL_GAI1_w1, adsl_cluster_admin_1_w1 );
#undef ADSL_GAI1_w1
#else
     /* copy data since they may be in the stack of the thread of the SDH */
     adsl_cluster_admin_1_w1 = (struct dsd_cluster_admin_1 *)
                                 malloc( sizeof(struct dsd_cluster_admin_1)
                                           + sizeof(struct dsd_gather_i_1)
                                           + adsp_admin1->imc_len_command );
     memset( adsl_cluster_admin_1_w1, 0, sizeof(struct dsd_cluster_admin_1) + sizeof(struct dsd_gather_i_1) );  /* data to pass */
#define ADSL_GAI1_w1 ((struct dsd_gather_i_1 *) (adsl_cluster_admin_1_w1 + 1))
     ADSL_GAI1_w1->achc_ginp_cur = (char *) (ADSL_GAI1_w1 + 1);
     ADSL_GAI1_w1->achc_ginp_end = ADSL_GAI1_w1->achc_ginp_cur + adsp_admin1->imc_len_command;
     memcpy( ADSL_GAI1_w1 + 1, adsp_admin1->achc_command, adsp_admin1->imc_len_command );
     adsl_cluster_admin_1_w1->adsc_hco_wothr = adsp_hco_wothr;
     adsl_sdhc1_w1 = m_cluster_admin( adsp_admin1->ilc_handle_cluster, ADSL_GAI1_w1, adsl_cluster_admin_1_w1 );
#undef ADSL_GAI1_w1
#endif
     free( adsl_cluster_admin_1_w1 );       /* free memory again       */
     if (adsl_sdhc1_w1 == NULL) {           /* no data returned        */
// to-do 06.11.09 KB
// to-do 09.09.10 KB
       adsp_admin1->adsc_gai1_ret = NULL;   /* no data returned from call */
       return TRUE;                         /* all done                */
     }
#define ADSL_AUXF_ADMIN1_W1 ((struct dsd_auxf_admin1 *) ((struct dsd_auxf_ext_1 *) (adsp_auxf_1 + 1) + 1))
     adsp_admin1->adsc_gai1_ret = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* set data returned from call */
     if (ADSL_AUXF_ADMIN1_W1->adsc_sdhc1_1) {
       adsl_sdhc1_cur = adsl_sdhc1_w1;      /* get new chain           */
       do {                                 /* loop to find last element */
         adsl_sdhc1_last = adsl_sdhc1_cur;  /* save this element       */
         adsl_sdhc1_cur = adsl_sdhc1_cur->adsc_next;  /* get next in chain */
       } while (adsl_sdhc1_cur);
       adsl_sdhc1_last->adsc_next = ADSL_AUXF_ADMIN1_W1->adsc_sdhc1_1;  /* append old buffers */
     }
     ADSL_AUXF_ADMIN1_W1->adsc_sdhc1_1 = adsl_sdhc1_w1;  /* save buffers to free later */
     return TRUE;                           /* all done                */
#undef ADSL_AUXF_ADMIN1_W1
   }
   achl1 = adsp_admin1->achc_command;       /* address of command      */
   iml_len = adsp_admin1->imc_len_command;  /* length of command       */
   /* retrieve length of query type                                    */
   iml_sub = 0;                             /* clear length retrieved  */
   iml1 = 4;                                /* maximum number of digits */
   do {                                     /* loop to retrieve length NHASN */
     if (iml_len <= 0) {                    /* record exhausted        */
       m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_proc_admin_aux( %p , %p ) length total - query type - invalid",
                       __LINE__, adsp_admin1, adsp_auxf_1 );
       return FALSE;                        /* return error            */
     }
     if (iml1 <= 0) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_proc_admin_aux( %p , %p ) NHASN too many digits - query type",
                       __LINE__, adsp_admin1, adsp_auxf_1 );
       return FALSE;                        /* return error            */
     }
     iml2 = (unsigned char) *achl1 & 0X80;  /* get more bit            */
     iml_sub <<= 7;                         /* shift old value         */
     iml_sub |= *achl1 & 0X7F;              /* apply new bits          */
     achl1++;                               /* increment input         */
     iml_len--;                             /* decrement length record */
     iml1--;                                /* decrement digits allowed */
   } while (iml2);
   if (iml_sub <= 0) {                      /* length query type invalid */
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_proc_admin_aux( %p , %p ) length query type zero",
                     __LINE__, adsp_admin1, adsp_auxf_1 );
     return FALSE;                          /* return error            */
   }
   if (iml_sub > iml_len) {                 /* length query type too high */
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_proc_admin_aux( %p , %p ) length query too high %d %d.",
                     __LINE__, adsp_admin1, adsp_auxf_1, iml_sub, iml_len );
     return FALSE;                          /* return error            */
   }
   if (iml_sub > sizeof(vprl_work)) {       /* length query type too high */
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_proc_admin_aux( %p , %p ) length query greater length work area %d.",
                     __LINE__, adsp_admin1, adsp_auxf_1, iml_sub );
     return FALSE;                          /* return error            */
   }
   iml_len -= iml_sub;                      /* compute remaining length */
   /* search type of query                                             */
   iel_adm_command = (ied_adm_command) (sizeof(achrs_adm_command) / sizeof(achrs_adm_command[0]));
   do {
     if (   (iml_sub == strlen( achrs_adm_command[ iel_adm_command - 1 ] ))
         && (!memcmp( achl1, achrs_adm_command[ iel_adm_command - 1 ], iml_sub ))) {
       break;                               /* command found           */
     }
     iel_adm_command = (ied_adm_command) (iel_adm_command - 1);
   } while (iel_adm_command > 0);
   if (iel_adm_command == ied_admc_invalid) {  /* command not valid    */
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_proc_admin_aux( %p , %p ) command \"%.*(u8)s\" not defined",
                     __LINE__, adsp_admin1, adsp_auxf_1, iml_sub, achl1 );
     return FALSE;                          /* return error            */
   }
   achl1 += iml_sub;                        /* after command type      */
   /* retrieve length of query data                                    */
   iml_sub = 0;                             /* clear length retrieved  */
   iml1 = 4;                                /* maximum number of digits */
   do {                                     /* loop to retrieve length NHASN */
     if (iml_len <= 0) {                    /* record exhausted        */
       m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_proc_admin_aux( %p , %p ) length query data invalid",
                       __LINE__, adsp_admin1, adsp_auxf_1 );
       return FALSE;                        /* return error            */
     }
     if (iml1 <= 0) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_proc_admin_aux( %p , %p ) length query data too many digits",
                       __LINE__, adsp_admin1, adsp_auxf_1 );
       return FALSE;                        /* return error            */
     }
     iml2 = (unsigned char) *achl1 & 0X80;  /* get more bit            */
     iml_sub <<= 7;                         /* shift old value         */
     iml_sub |= *achl1 & 0X7F;              /* apply new bits          */
     achl1++;                               /* increment input         */
     iml_len--;                             /* decrement length record */
     iml1--;                                /* decrement digits allowed */
   } while (iml2);
   if (iml_sub <= 0) {                      /* length query data invalid */
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_proc_admin_aux( %p , %p ) length query data too small",
                     __LINE__, adsp_admin1, adsp_auxf_1 );
     return FALSE;                          /* return error            */
   }
   if (iml_sub != iml_len) {                /* length query data invalid */
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_proc_admin_aux( %p , %p ) length query data too high %d %d.",
                     __LINE__, adsp_admin1, adsp_auxf_1, iml_sub, iml_len );
     return FALSE;                          /* return error            */
   }
   /* get record type                                                  */
   chl_record_type = *achl1++;              /* get record type         */
   iml_sub--;                               /* decrement length structure */
   if (iml_sub > 0) {                       /* structure with data follow */
     if (iml_sub > sizeof(vprl_work)) {     /* length query too high   */
       m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_proc_admin_aux( %p , %p ) length query too high %d.",
                       __LINE__, adsp_admin1, adsp_auxf_1, iml_sub );
       return FALSE;                        /* return error            */
     }
     memcpy( vprl_work, achl1, iml_sub );   /* copy query              */
   }
   if (chl_record_type) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_proc_admin_aux( %p , %p ) record type 0X%02X invalid",
                       __LINE__, adsp_admin1, adsp_auxf_1, (unsigned char) chl_record_type );
     return FALSE;                          /* return error            */
   }
   adsl_sdhc1_w1 = NULL;                    /* clear return value      */
   switch (iel_adm_command) {               /* command for admin       */
     case ied_admc_cluster:                 /* cluster                 */
       adsl_sdhc1_w1 = m_get_wspadm1_cluster();
       break;
     case ied_admc_session:                 /* session                 */
#ifdef NOT_YET
       if (adsp_adm_pipe->adsc_ap_new_log) break;  /* structure for new log to pipe */
#endif
       if (iml_sub < sizeof(struct dsd_wspadm1_q_session)) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_proc_admin_aux( %p , %p ) length query too small %d.",
                         __LINE__, adsp_admin1, adsp_auxf_1, iml_sub );
         return FALSE;                      /* return error            */
       }
#define ADSL_WSPADM1_Q_SESSION_G ((struct dsd_wspadm1_q_session *) vprl_work)
       iml1 = ADSL_WSPADM1_Q_SESSION_G->imc_len_user_group;
       if (iml1 < 0) iml1 = 0;
#ifndef EXT_WSP_ADM_SESSION_USERFLD
       if (iml_sub != (sizeof(struct dsd_wspadm1_q_session)
                         + ADSL_WSPADM1_Q_SESSION_G->imc_len_userid  /* length userid UTF-8 */
                         + iml1 )) {        /* length name user group UTF-8 */
         m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_proc_admin_aux( %p , %p ) length query invalid %d.",
                         __LINE__, adsp_admin1, adsp_auxf_1, iml_sub );
         return FALSE;                      /* return error            */
       }
#endif
#ifdef EXT_WSP_ADM_SESSION_USERFLD
       if (iml_sub != (sizeof(struct dsd_wspadm1_q_session)
                         + ADSL_WSPADM1_Q_SESSION_G->imc_len_userid  /* length userid UTF-8 */
                         + iml1             /* length name user group UTF-8 */
                         + ADSL_WSPADM1_Q_SESSION_G->imc_len_userfld)) {  /* length user field in bytes */
         m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_proc_admin_aux( %p , %p ) length query invalid %d.",
                         __LINE__, adsp_admin1, adsp_auxf_1, iml_sub );
         return FALSE;                      /* return error            */
       }
#endif
#undef ADSL_WSPADM1_Q_SESSION_G
       adsl_sdhc1_w1 = m_get_wspadm1_session( (struct dsd_wspadm1_q_session *) vprl_work );
       break;
     case ied_admc_cancel_session:          /* cancel-session          */
//#ifdef XYZ1
       if (iml_sub != sizeof(struct dsd_wspadm1_q_can_sess_1)) {
/* to-do 01.10.08 KB data invalid */
         break;
       }
//#endif
#ifdef NOT_YET
       if (adsp_adm_pipe->adsc_ap_new_log) break;  /* structure for new log to pipe */
#endif
       adsl_sdhc1_w1 = m_get_wspadm1_cancel_session( (struct dsd_wspadm1_q_can_sess_1 *) vprl_work );
       break;
     case ied_admc_listen:                  /* listen                  */
       adsl_sdhc1_w1 = m_get_wspadm1_listen();
       break;
     case ied_admc_log:                     /* log                     */
       adsl_sdhc1_w1 = m_get_wspadm1_log( (struct dsd_wspadm1_q_log *) vprl_work, iml_sub,
                                          NULL, NULL );
       break;
     case ied_admc_wsp_trace:               /* WSP Trace               */
       m_ctrl_wspadm1_wsp_trace( (struct dsd_wspadm1_q_wsp_trace_1 *) vprl_work,
                                 iml_sub - sizeof(struct dsd_wspadm1_q_wsp_trace_1) );
       break;
     case ied_admc_wsp_tr_act:              /* WSP Trace active settings */
       adsl_sdhc1_w1 = m_get_wspadm1_wsp_tr_act();
       break;
   }
   adsp_admin1->adsc_gai1_ret = NULL;       /* clear data returned from call */
#define ADSL_AUXF_ADMIN1_W1 ((struct dsd_auxf_admin1 *) ((struct dsd_auxf_ext_1 *) (adsp_auxf_1 + 1) + 1))
   if (adsl_sdhc1_w1) {                     /* data returned           */
     adsp_admin1->adsc_gai1_ret = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* set data returned from call */
     /* gather structers need to be chained together                   */
     adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* get first block         */
     while (adsl_sdhc1_w2->adsc_next) {     /* still block that follows */
       adsl_gai1_w1 = adsl_sdhc1_w2->adsc_gather_i_1_i;  /* get data in this block */
       while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* search last in chain */
       adsl_gai1_w1->adsc_next = adsl_sdhc1_w2->adsc_next->adsc_gather_i_1_i;
       adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;  /* get next in chain */
     }
     if (ADSL_AUXF_ADMIN1_W1->adsc_sdhc1_1) {
       adsl_sdhc1_cur = adsl_sdhc1_w1;      /* get new chain           */
       do {                                 /* loop to find last element */
         adsl_sdhc1_last = adsl_sdhc1_cur;  /* save this element       */
         adsl_sdhc1_cur = adsl_sdhc1_cur->adsc_next;  /* get next in chain */
       } while (adsl_sdhc1_cur);
       adsl_sdhc1_last->adsc_next = ADSL_AUXF_ADMIN1_W1->adsc_sdhc1_1;  /* append old buffers */
     }
     ADSL_AUXF_ADMIN1_W1->adsc_sdhc1_1 = adsl_sdhc1_w1;  /* save buffers to free later */
   }
   return TRUE;
#undef ADSL_AUXF_ADMIN1_W1
} /* end m_proc_admin_aux()                                            */

/** send admin command to other active cluster member, receive response */
static struct dsd_sdh_control_1 * m_cluster_admin( HL_LONGLONG ilp_handle_cluster,
                                                   struct dsd_gather_i_1 *adsp_gai1,
                                                   struct dsd_cluster_admin_1 *adsp_cluster_admin_1 ) {
   int        iml1;                         /* working variable        */
// BOOL       bol1;                         /* working variable        */
   char       *achl_w1;                     /* working variable        */
   struct dsd_cluster_active *adsl_clact_w1;  /* active cluster structure */
   struct dsd_cluster_send *adsl_clsend_w1;  /* send buffer            */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working-variable       */

   adsl_clact_w1 = adsg_clact_ch;           /* get chain of active cluster members */
   while (adsl_clact_w1) {                  /* loop over all active cluster members */
     if (ilp_handle_cluster == (HL_LONGLONG) adsl_clact_w1) break;
     adsl_clact_w1 = adsl_clact_w1->adsc_next;  /* get next in chain   */
   }
   if (adsl_clact_w1 == NULL) {             /* active cluster member not found */
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05 m_cluster_admin() cluster not found",
                     __LINE__ );
     adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))
#define ACHL_OUT ((char *) adsl_sdhc1_w1 + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1))
     memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
     adsl_sdhc1_w1->adsc_gather_i_1_i = ADSL_GAI1_W1;  /* gather input data */
     *(ACHL_OUT + 0) = 1;                   /* length of data          */
     *(ACHL_OUT + 1) = (unsigned char) DEF_WSPADM_RT_CLUSTER;  /* error invalid cluster */
     ADSL_GAI1_W1->achc_ginp_cur = ACHL_OUT;  /* start of output       */
     ADSL_GAI1_W1->achc_ginp_end = ACHL_OUT + 2;  /* end of output     */
     return adsl_sdhc1_w1;                  /* return error message    */
#undef ADSL_GAI1_W1
#undef ACHL_OUT
   }
   if (   (adsl_clact_w1->boc_endian_big != dsg_this_server.boc_endian_big)
       || (adsl_clact_w1->imc_aligment != dsg_this_server.imc_aligment)) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05 m_cluster_admin() cluster has different architecture",
                     __LINE__ );
     adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))
#define ACHL_OUT ((char *) adsl_sdhc1_w1 + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1))
     memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
     adsl_sdhc1_w1->adsc_gather_i_1_i = ADSL_GAI1_W1;  /* gather input data */
     *(ACHL_OUT + 0) = 1;                   /* length of data          */
     *(ACHL_OUT + 1) = (unsigned char) DEF_WSPADM_RT_MISC;  /* miscellaneous */
     ADSL_GAI1_W1->achc_ginp_cur = ACHL_OUT;  /* start of output       */
     ADSL_GAI1_W1->achc_ginp_end = ACHL_OUT + 2;  /* end of output     */
     return adsl_sdhc1_w1;                  /* return error message    */
#undef ADSL_GAI1_W1
#undef ACHL_OUT
   }
   adsp_cluster_admin_1->adsc_clact = adsl_clact_w1;  /* active cluster structure */
   adsl_clsend_w1 = (struct dsd_cluster_send *) m_proc_alloc();
   *((struct dsd_sdh_control_1 **) (adsl_clsend_w1 + 1)) = NULL;  /* data to be freed */
   /* first 9 bytes are address of entry struct dsd_cluster_admin_1 plus type Q / R */
   achl_w1 = (char *) adsl_clsend_w1 + LEN_TCP_RECV - 8 - 1;
   achl_w1 = (char *) (((long long int) achl_w1) & (0 - sizeof(void *)));
   *((HL_LONGLONG *) achl_w1) = (HL_LONGLONG) adsp_cluster_admin_1;
   *(achl_w1 + sizeof(HL_LONGLONG)) = 'Q';  /* type is query           */
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) ((char *) (adsl_clsend_w1 + 1) + sizeof(void *)))
   ADSL_GAI1_W1->achc_ginp_cur = achl_w1;
   ADSL_GAI1_W1->achc_ginp_end = achl_w1 + sizeof(HL_LONGLONG) + 1;
   ADSL_GAI1_W1->adsc_next = adsp_gai1;     /* append query data       */
   adsl_clsend_w1->adsc_clact = adsl_clact_w1;  /* active cluster      */
   adsl_clsend_w1->amc_compl = &m_cluster_free_send;  /* completition routine */
   adsl_clsend_w1->iec_cl_type = ied_clty_admin;  /* type is adminstration */
   adsl_clsend_w1->adsc_gai1_send = ADSL_GAI1_W1;  /* set data to be sent */
#undef ADSL_GAI1_W1
// to-do 07.09.08 critical section
   adsp_cluster_admin_1->adsc_next = adss_cluster_admin_1_ch;  /* get old chain */
   adss_cluster_admin_1_ch = adsp_cluster_admin_1;  /* set new chain   */
#ifdef NOT_YET
// to-do 07.09.08 timeout
   /* set timer                                                        */
   memset( &adsp_cluster_admin_1->dsc_timer, 0, sizeof(struct dsd_timer_ele) );
   adsp_cluster_admin_1->dsc_timer.amc_compl = &m_timeout_cluster;   /* set routine for timeout */
   adsp_cluster_admin_1->dsc_timer.ilcwaitmsec = adsl_clact_w1->imc_timeout_msec;  /* wait in milliseconds */
   m_time_set( &adsp_cluster_admin_1->dsc_timer, FALSE );  /* set timeout now */
#endif
   iml1 = m_cluster_send( adsl_clsend_w1 );
   if (iml1) {                              /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05 m_cluster_admin() m_cluster_send() returned %d",
                     __LINE__, iml1 );
//   m_proc_free( adsl_clsend_w1 );
   } else {
     m_hco_wothr_blocking( adsp_cluster_admin_1->adsc_hco_wothr );  /* mark thread blocking */
     m_hco_wothr_wait( adsp_cluster_admin_1->adsc_hco_wothr );  /* wait till response received */
     m_hco_wothr_active( adsp_cluster_admin_1->adsc_hco_wothr, FALSE );  /* mark thread active */
   }
   adsl_sdhc1_w1 = adsp_cluster_admin_1->adsc_sdhc1_ret;  /* data returned */
#ifdef OLD01
// 05.11.09 KB - already freed at m_cluster_free_send() - insure++ Mr. Jakobs
   m_proc_free( adsl_clsend_w1 );           /* free data again         */
#endif
   return adsl_sdhc1_w1;                    /* return data received    */
} /* end m_cluster_admin()                                             */

/** free buffer sent                                                   */
static void m_cluster_free_send( struct dsd_cluster_send *adsp_clsend ) {
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working-variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working-variable       */

   adsl_sdhc1_w1 = *((struct dsd_sdh_control_1 **) (adsp_clsend + 1));  /* data to be freed */
   m_proc_free( adsp_clsend );              /* free memory             */
   while (adsl_sdhc1_w1) {                  /* loop over all buffers to free */
     adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* get this buffer         */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
     m_proc_free( adsl_sdhc1_w2 );          /* free this buffer        */
   }
} /* end m_cluster_free_send()                                         */

/** routine called by timer thread when a query to another cluster member timed out */
static void m_timeout_cluster( struct dsd_timer_ele *adsp_timer_ele ) {
// to-do 07.09.08 timeout
// do-to 07.09.08 use timer in wait
} /* end m_timeout_cluster()                                           */

/** a logical block was reveived from other cluster member             */
extern "C" void m_admin_cluster_recv( struct dsd_cluster_proc_recv *adsp_clprr ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3;             /* working variables       */
// int        iml_len;                      /* length of data received */
   int        iml_sub;                      /* length of sub structure */
   HL_LONGLONG ill_handle_cluster;          /* address of request      */
   char       *achl1, *achl2;               /* working variables       */
   char       *achl_out;                    /* output of values        */
   char       *achl_error;                  /* error message           */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* gather input data       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working-variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working-variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_first;  /* first structure     */
   struct dsd_sdh_control_1 *adsl_sdhc1_last;  /* last structure       */
   struct dsd_cluster_send *adsl_clsend_w1;  /* send buffer            */
   struct dsd_cluster_admin_1 *adsl_cluster_admin_1_w1;  /* admin request in cluster */
   struct dsd_cluster_admin_1 *adsl_cluster_admin_1_w2;  /* admin request in cluster */
   int        iml_data_length;              /* length of received data */
   ied_adm_command iel_adm_command;         /* command for admin       */
   char       chl_record_type;              /* record type             */
   void *     vprl_work[ 1024 / sizeof(void *) ];  /* work-area aligned */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d m_admin_cluster_recv( %p ) called",
                   __LINE__, adsp_clprr );
#endif
   adsl_gai1_w1 = adsp_clprr->adsc_gai1_data;  /* gather input data    */
   iml_data_length = adsp_clprr->imc_data_length;  /* length of received data */
   iml1 = 1;                                /* first get address request */
   achl_out = (char *) &ill_handle_cluster;  /* get address area to fill */
   iml2 = sizeof(ill_handle_cluster);       /* get length area to fill */

   p_scan_00:                               /* scann input data        */
   if (iml2 > iml_data_length) {            /* more than data received */
     achl_error = "length data received too short";
     goto p_scan_error;                     /* invalid data received   */
   }
   iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* length of data */
   if (iml3 <= 0) {                         /* no more data            */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1) goto p_scan_00;      /* continue scann input data */
     achl_error = "end of gather input";
     goto p_scan_error;                     /* invalid data received   */
   }
   if (iml3 > iml2) iml3 = iml2;            /* copy only what needed   */
   if (iml1) {                              /* data to be copied       */
     memcpy( achl_out, adsl_gai1_w1->achc_ginp_cur, iml3 );  /* copy input data */
     adsl_gai1_w1->achc_ginp_cur += iml3;   /* increment address input */
     achl_out += iml3;                      /* increment address output */
     iml2 -= iml3;                          /* decrement length to fill */
     iml_data_length -= iml3;               /* decrement length received */
     if (iml2) goto p_scan_00;              /* continue scann input data */
     iml1--;                                /* get next field          */
     goto p_scan_00;                        /* continue scann input data */
   }
   if (*adsl_gai1_w1->achc_ginp_cur == 'R') {  /* response received    */
     adsl_gai1_w1->achc_ginp_cur++;         /* this character processed */
     iml_data_length--;                     /* decrement length received */
     goto p_resp_00;                        /* response received       */
   }
   if (*adsl_gai1_w1->achc_ginp_cur == 'Q') {  /* query received       */
     adsl_gai1_w1->achc_ginp_cur++;         /* this character processed */
     iml_data_length--;                     /* decrement length received */
     goto p_query_00;                       /* query received          */
   }
   achl_error = "function received neither Q nor R";

   p_scan_error:                            /* invalid data received   */
   m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05 m_admin_cluster_recv() %s",
                   __LINE__, achl_error );
   m_cluster_proc_recv_done( adsp_clprr );  /* free data that we received */
   return;

   p_query_00:                              /* query received          */
   achl1 = adsl_gai1_w1->achc_ginp_cur;     /* get start of data       */
   /* retrieve length of query type                                    */
   iml_sub = 0;                             /* clear length retrieved  */
   iml1 = 4;                                /* maximum number of digits */
   do {                                     /* loop to retrieve length NHASN */
     if (iml_data_length <= 0) {            /* record exhausted        */
       m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_admin_cluster_recv() NHASN length query type longer than total query",
                       __LINE__ );
//     goto p_adm_pipe_close;               /* close pipe              */
     }
     if (iml1 <= 0) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_admin_cluster_recv() NHASN too many digits - query type",
                       __LINE__ );
//     goto p_adm_pipe_close;               /* close pipe              */
     }
     while (achl1 >= adsl_gai1_w1->achc_ginp_end) {
       adsl_gai1_w1->achc_ginp_cur = achl1;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
       if (adsl_gai1_w1 == NULL) {          /* end of data read        */
//       goto p_adm_pipe_20;                /* read next record        */
       }
       achl1 = adsl_gai1_w1->achc_ginp_cur;  /* get start of data      */
     }
     iml2 = (unsigned char) *achl1 & 0X80;  /* get more bit            */
     iml_sub <<= 7;                         /* shift old value         */
     iml_sub |= *achl1 & 0X7F;              /* apply new bits          */
     achl1++;                               /* increment input         */
     iml_data_length--;                     /* decrement length record */
     iml1--;                                /* decrement digits allowed */
   } while (iml2);
   if (iml_sub <= 0) {                      /* length query type invalid */
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_admin_cluster_recv() length query type zero",
                     __LINE__ );
//   goto p_adm_pipe_close;                 /* close pipe              */
   }
   if (iml_sub > iml_data_length) {         /* length query type too high */
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_admin_cluster_recv() length query too high %d %d.",
                     __LINE__, iml_sub, iml_data_length );
//   goto p_adm_pipe_close;                 /* close pipe              */
   }
   if (iml_sub > sizeof(vprl_work)) {       /* length query type too high */
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05d m_admin_cluster_recv() length query %d more than size work area",
                     __LINE__, iml_sub );
//   goto p_adm_pipe_close;                 /* close pipe              */
   }
   iml_data_length -= iml_sub;              /* compute remaining length */
   iml1 = iml_sub;                          /* length to copy name     */
   achl2 = (char *) vprl_work;              /* fill in query type      */
   while (TRUE) {                           /* loop to fill name query type */
     while (TRUE) {
       iml2 = adsl_gai1_w1->achc_ginp_end - achl1;
       if (iml2 > 0) break;
       adsl_gai1_w1->achc_ginp_cur = achl1;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
       if (adsl_gai1_w1 == NULL) {          /* end of data read        */
//       goto p_adm_pipe_20;                /* read next record        */
       }
       achl1 = adsl_gai1_w1->achc_ginp_cur;  /* get start of data      */
     }
     if (iml2 > iml1) iml2 = iml1;
     memcpy( achl2, achl1, iml2 );
     achl1 += iml2;
     iml1 -= iml2;
     if (iml1 == 0) break;
     achl2 += iml2;
   }
   /* search type of query                                             */
   iel_adm_command = (ied_adm_command) (sizeof(achrs_adm_command) / sizeof(achrs_adm_command[0]));
   do {
     if (   (iml_sub == strlen( achrs_adm_command[ iel_adm_command - 1 ] ))
         && (!memcmp( vprl_work, achrs_adm_command[ iel_adm_command - 1 ], iml_sub ))) {
       break;                               /* command found           */
     }
     iel_adm_command = (ied_adm_command) (iel_adm_command - 1);
   } while (iel_adm_command > 0);
   if (iel_adm_command == ied_admc_invalid) {  /* command not valid    */
/* to-do 30.04.08 KB data invalid */
   }
   /* retrieve length of query data                                    */
   iml_sub = 0;                             /* clear length retrieved  */
   iml1 = 4;                                /* maximum number of digits */
   do {                                     /* loop to retrieve length NHASN */
     if (iml_data_length <= 0) {            /* record exhausted        */
/* to-do 13.04.08 KB data invalid */
       break;
     }
     if (iml1 <= 0) {
/* to-do 13.04.08 KB data invalid */
       break;
     }
     while (achl1 >= adsl_gai1_w1->achc_ginp_end) {
       adsl_gai1_w1->achc_ginp_cur = achl1;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
       if (adsl_gai1_w1 == NULL) {          /* end of data read        */
//       goto p_adm_pipe_20;                /* read next record        */
       }
       achl1 = adsl_gai1_w1->achc_ginp_cur;  /* get start of data      */
     }
     iml2 = (unsigned char) *achl1 & 0X80;  /* get more bit            */
     iml_sub <<= 7;                         /* shift old value         */
     iml_sub |= *achl1 & 0X7F;              /* apply new bits          */
     achl1++;                               /* increment input         */
     iml_data_length--;                     /* decrement length record */
     iml1--;                                /* decrement digits allowed */
   } while (iml2);
   if (iml_sub <= 0) {                      /* length query data invalid */
/* to-do 13.04.08 KB data invalid */
     return;
   }
   if (iml_sub != iml_data_length) {        /* length query data invalid */
/* to-do 13.04.08 KB data invalid */
     return;
   }
   /* get record type                                                  */
   chl_record_type = *achl1++;              /* get record type         */
   iml_sub--;                               /* decrement length structure */
   if (iml_sub > 0) {                       /* structure with data follow */
     if (iml_sub > sizeof(vprl_work)) {     /* length query too high   */
/* to-do 02.09.08 KB data invalid */
       return;
     }
     iml1 = iml_sub;                        /* length to copy structure */
     achl2 = (char *) vprl_work;            /* fill in query record    */
     while (TRUE) {                         /* loop to fill query record */
       while (TRUE) {
         iml2 = adsl_gai1_w1->achc_ginp_end - achl1;
         if (iml2 > 0) break;
         adsl_gai1_w1->achc_ginp_cur = achl1;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
         if (adsl_gai1_w1 == NULL) {        /* end of data read        */
//       goto p_adm_pipe_20;                /* read next record        */
         }
         achl1 = adsl_gai1_w1->achc_ginp_cur;  /* get start of data    */
       }
       if (iml2 > iml1) iml2 = iml1;
       memcpy( achl2, achl1, iml2 );
       achl1 += iml2;
       iml1 -= iml2;
       if (iml1 == 0) break;
       achl2 += iml2;
     }
   }
#ifdef NOT_YET
   /* remove data retrieved                                            */
   ADSL_GAI1_W1->achc_ginp_cur = achl1;
   while (   (adsp_adm_pipe->adsc_sdhc1_inp)  /* loop over input data  */
          && (adsp_adm_pipe->adsc_sdhc1_inp->adsc_gather_i_1_i->achc_ginp_cur
                >= adsp_adm_pipe->adsc_sdhc1_inp->adsc_gather_i_1_i->achc_ginp_end)) {
     adsl_sdhc1_w1 = adsp_adm_pipe->adsc_sdhc1_inp;  /* get input data */
     adsp_adm_pipe->adsc_sdhc1_inp = adsp_adm_pipe->adsc_sdhc1_inp->adsc_next;
     m_proc_free( adsl_sdhc1_w1 );          /* free buffer             */
   }
#endif
//#undef ADSL_GAI1_W1
   if (chl_record_type) {
/* to-do 30.04.08 KB data invalid */
     m_hlnew_printf( HLOG_WARN1, "HWSPA02W xs-gw-admin-l%05 m_admin_cluster_recv() received record type 0X%02X invalid",
                     __LINE__, (unsigned char) chl_record_type );
   }
   adsl_sdhc1_w1 = NULL;                    /* clear return value      */
   switch (iel_adm_command) {               /* command for admin       */
     case ied_admc_cluster:                 /* cluster                 */
//     if (adsp_adm_pipe->adsc_ap_new_log) break;  /* structure for new log to pipe */
       adsl_sdhc1_w1 = m_get_wspadm1_cluster();
       break;
     case ied_admc_session:                 /* session                 */
#ifdef B131129
//#ifdef XYZ1
       if (iml_sub != sizeof(struct dsd_wspadm1_q_session)) {
/* to-do 30.04.08 KB data invalid */
         break;
       }
//#endif
#endif
#define ADSL_WQS_G ((struct dsd_wspadm1_q_session *) vprl_work)
#ifdef B131225
       if (iml_sub != (sizeof(struct dsd_wspadm1_q_session) + ADSL_WQS_G->imc_len_userid + ADSL_WQS_G->imc_len_user_group)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPA02W xs-gw-admin-l%05 m_admin_cluster_recv() length %d invalid for ied_admc_session",
                         __LINE__, iml_sub );
         break;
       }
#endif
#ifndef EXT_WSP_ADM_SESSION_USERFLD
       bol1 = FALSE;                        /* reset error condition   */
       if (iml_sub < sizeof(struct dsd_wspadm1_q_session)) {
         bol1 = TRUE;                       /* set error condition     */
       } else {
         iml1 = ADSL_WQS_G->imc_len_user_group;
         if (iml1 < 0) iml1 = 0;
         if (iml_sub != (sizeof(struct dsd_wspadm1_q_session) + ADSL_WQS_G->imc_len_userid + iml1)) {
           bol1 = TRUE;                     /* set error condition     */
         }
       }
       if (bol1) {                          /* error condition set     */
         m_hlnew_printf( HLOG_WARN1, "HWSPA02W xs-gw-admin-l%05 m_admin_cluster_recv() length %d invalid for ied_admc_session",
                         __LINE__, iml_sub );
         break;
       }
#endif
#ifdef EXT_WSP_ADM_SESSION_USERFLD
       bol1 = FALSE;                        /* reset error condition   */
       if (iml_sub < sizeof(struct dsd_wspadm1_q_session)) {
         bol1 = TRUE;                       /* set error condition     */
       } else {
         iml1 = ADSL_WQS_G->imc_len_user_group;
         if (iml1 < 0) iml1 = 0;
         if (iml_sub != (sizeof(struct dsd_wspadm1_q_session)
                           + ADSL_WQS_G->imc_len_userid
                           + iml1
                           + ADSL_WQS_G->imc_len_userfld)) {
           bol1 = TRUE;                     /* set error condition     */
         }
       }
       if (bol1) {                          /* error condition set     */
         m_hlnew_printf( HLOG_WARN1, "HWSPA02W xs-gw-admin-l%05 m_admin_cluster_recv() length %d invalid for ied_admc_session",
                         __LINE__, iml_sub );
         break;
       }
#endif
//     if (adsp_adm_pipe->adsc_ap_new_log) break;  /* structure for new log to pipe */
       adsl_sdhc1_w1 = m_get_wspadm1_session( ADSL_WQS_G );
#undef ADSL_WQS_G
       break;
     case ied_admc_cancel_session:          /* cancel-session          */
//#ifdef XYZ1
       if (iml_sub != sizeof(struct dsd_wspadm1_q_can_sess_1)) {
/* to-do 01.10.08 KB data invalid */
         break;
       }
//#endif
#ifdef NOT_YET
       if (adsp_adm_pipe->adsc_ap_new_log) break;  /* structure for new log to pipe */
#endif
       adsl_sdhc1_w1 = m_get_wspadm1_cancel_session( (struct dsd_wspadm1_q_can_sess_1 *) vprl_work );
       break;
     case ied_admc_listen:                  /* listen                  */
//     if (adsp_adm_pipe->adsc_ap_new_log) break;  /* structure for new log to pipe */
       adsl_sdhc1_w1 = m_get_wspadm1_listen();
       break;
     case ied_admc_log:                     /* log                     */
       adsl_sdhc1_w1 = m_get_wspadm1_log( (struct dsd_wspadm1_q_log *) vprl_work, iml_sub,
                                          NULL, NULL );
       break;
     case ied_admc_wsp_trace:               /* WSP Trace               */
       m_ctrl_wspadm1_wsp_trace( (struct dsd_wspadm1_q_wsp_trace_1 *) vprl_work,
                                 iml_sub - sizeof(struct dsd_wspadm1_q_wsp_trace_1) );
       break;
     case ied_admc_wsp_tr_act:              /* WSP Trace active settings */
       adsl_sdhc1_w1 = m_get_wspadm1_wsp_tr_act();
       break;
   }
   adsl_gai1_w1 = NULL;                     /* no data to send         */
   if (adsl_sdhc1_w1) {                     /* data had been returned  */
     /* gather structers need to be chained together                   */
     adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* get first block         */
     while (adsl_sdhc1_w2->adsc_next) {     /* still block that follows */
       adsl_gai1_w1 = adsl_sdhc1_w2->adsc_gather_i_1_i;  /* get data in this block */
       while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* search last in chain */
       adsl_gai1_w1->adsc_next = adsl_sdhc1_w2->adsc_next->adsc_gather_i_1_i;
       adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;  /* get next in chain */
     }
     adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* set data returned from call */
   }
   adsl_clsend_w1 = (struct dsd_cluster_send *) m_proc_alloc();
   *((struct dsd_sdh_control_1 **) (adsl_clsend_w1 + 1)) = adsl_sdhc1_w1;  /* data to be freed */
   /* first 9 bytes are address of entry struct dsd_cluster_admin_1 plus type Q / R */
   achl1 = (char *) adsl_clsend_w1 + LEN_TCP_RECV - 8 - 1;
   achl1 = (char *) (((long long int) achl1) & (0 - sizeof(void *)));
   *((HL_LONGLONG *) achl1) = ill_handle_cluster;  /* send back address received */
   *(achl1 + sizeof(HL_LONGLONG)) = 'R';    /* type is response        */
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) ((char *) (adsl_clsend_w1 + 1) + sizeof(void *)))
   ADSL_GAI1_W1->achc_ginp_cur = achl1;
   ADSL_GAI1_W1->achc_ginp_end = achl1 + sizeof(HL_LONGLONG) + 1;
   ADSL_GAI1_W1->adsc_next = adsl_gai1_w1;  /* append result of query  */
   adsl_clsend_w1->adsc_clact = adsp_clprr->adsc_clact;  /* active cluster where we received from */
   adsl_clsend_w1->amc_compl = &m_cluster_free_send;  /* completition routine */
   adsl_clsend_w1->iec_cl_type = ied_clty_admin;  /* type is adminstration */
   adsl_clsend_w1->adsc_gai1_send = ADSL_GAI1_W1;  /* set data to be sent */
#undef ADSL_GAI1_W1
   m_cluster_proc_recv_done( adsp_clprr );  /* free data that we received */
   iml1 = m_cluster_send( adsl_clsend_w1 );
   if (iml1) {                              /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPA01W xs-gw-admin-l%05 m_cluster_admin() m_cluster_send() returned %d",
                     __LINE__, iml1 );
     m_proc_free( adsl_clsend_w1 );
     while (adsl_sdhc1_w1) {                /* loop over all buffers to free */
       adsl_sdhc1_w2 = adsl_sdhc1_w1;       /* get this buffer         */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       m_proc_free( adsl_sdhc1_w1 );        /* free this buffer        */
     }
   }
   return;                                  /* all done                */

   p_resp_00:                               /* response received       */
   adsl_cluster_admin_1_w2 = NULL;          /* clear previous entry    */
// to-do 08.09.08 critical section
   adsl_cluster_admin_1_w1 = adss_cluster_admin_1_ch;  /* get chain of entries */
   while (adsl_cluster_admin_1_w1) {        /* loop over all entries   */
     if (   ((HL_LONGLONG) adsl_cluster_admin_1_w1 == ill_handle_cluster)  /* entry found */
         && (adsl_cluster_admin_1_w1->adsc_clact == adsp_clprr->adsc_clact)) {
       if (adsl_cluster_admin_1_w2 == NULL) {  /* is anchor of chain   */
         adss_cluster_admin_1_ch = adsl_cluster_admin_1_w1->adsc_next;  /* remove from chain */
       } else {                             /* middle in chain         */
         adsl_cluster_admin_1_w2->adsc_next = adsl_cluster_admin_1_w1->adsc_next;  /* remove from chain */
       }
       break;
     }
     adsl_cluster_admin_1_w2 = adsl_cluster_admin_1_w1;  /* set previous entry */
     adsl_cluster_admin_1_w1 = adsl_cluster_admin_1_w1->adsc_next;  /* get next in chain */
   }
// to-do 08.09.08 critical section
   if (adsl_cluster_admin_1_w1 == NULL) {   /* query not found         */
     m_hlnew_printf( HLOG_XYZ1, "HWSPA01W xs-gw-admin-l%05 m_cluster_admin() response received but no active query",
                     __LINE__ );
     m_cluster_proc_recv_done( adsp_clprr );  /* free data that we received */
     return;
   }
   /* copy the received data, since free is too compilcated            */
   achl1 = adsl_gai1_w1->achc_ginp_cur;     /* get start of data       */
   adsl_sdhc1_first = NULL;                 /* no first structure      */
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))
   while (iml_data_length) {                /* loop over data received */
     while (achl1 >= adsl_gai1_w1->achc_ginp_end) {
       adsl_gai1_w1->achc_ginp_cur = achl1;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
       if (adsl_gai1_w1 == NULL) {          /* end of data read        */
//       goto p_adm_pipe_20;                /* read next record        */
       }
       achl1 = adsl_gai1_w1->achc_ginp_cur;  /* get start of data      */
     }
     iml1 = adsl_gai1_w1->achc_ginp_end - achl1;  /* length of data    */
     if (iml1 > iml_data_length) iml1 = iml_data_length;
     do {                                   /* pseudo-loop             */
       if (adsl_sdhc1_first) {              /* first structure present */
         if (achl_out
              < ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - (sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1))))
           break;
         ADSL_GAI1_W1->achc_ginp_end = achl_out;  /* end of output     */
       }
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
#ifdef DEBUG_080505
       printf( "xs-gw-admin-l%05d-T m_proc_alloc returned %p.\n",
               __LINE__, adsl_sdhc1_w1 );
       fflush( stdout );
#endif
       memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
       achl_out = (char *) (adsl_sdhc1_w1 + 1) + sizeof(struct dsd_gather_i_1);
       ADSL_GAI1_W1->achc_ginp_cur = achl_out;  /* start of output     */
       adsl_sdhc1_w1->adsc_gather_i_1_i = ADSL_GAI1_W1;  /* gather input data */
       if (adsl_sdhc1_first == NULL) {      /* first structure not present */
         adsl_sdhc1_first = adsl_sdhc1_w1;  /* first structure now present */
         adsl_sdhc1_last = adsl_sdhc1_w1;   /* set last structure      */
         break;
       }
       adsl_sdhc1_last->adsc_next = adsl_sdhc1_w1;  /* append to chain */
       adsl_sdhc1_last = adsl_sdhc1_w1;     /* set last structure      */
     } while (FALSE);
     iml2 = ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - (sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1)))
              - achl_out;
     if (iml2 > iml1) iml2 = iml1;
     memcpy( achl_out, achl1, iml2 );
     achl1 += iml2;                         /* increment input pointer */
     achl_out += iml2;                      /* increment output pointer */
     iml_data_length -= iml2;               /* subtract from length to copy */
   }
   if (adsl_sdhc1_first) {                  /* first structure present */
     ADSL_GAI1_W1->achc_ginp_end = achl_out;  /* end of output         */
   }
   adsl_cluster_admin_1_w1->adsc_sdhc1_ret = adsl_sdhc1_first;  /* give data returned */
   m_hco_wothr_post( NULL, adsl_cluster_admin_1_w1->adsc_hco_wothr );  /* notify thread waiting */
   m_cluster_proc_recv_done( adsp_clprr );  /* free data that we received */
   return;
#undef ADSL_GAI1_W1
} /* end m_admin_cluster_recv()                                        */

/** retrieve messages from log for admin interface                     */
static struct dsd_sdh_control_1 * m_get_wspadm1_log( struct dsd_wspadm1_q_log *adsp_waqlog, int imp_len,
                                                     struct dsd_cb_new_log *adsp_cb_new_log, void * vpp_param ) {
   int        iml1, iml2, iml3;             /* working variables       */
   BOOL       bol1;                         /* working variable        */
   ied_logreq1_def iel_logreq1_def;         /* request type            */
   char       *achl_out;                    /* output of values        */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working-variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_first;  /* first structure     */
   struct dsd_sdh_control_1 *adsl_sdhc1_last;  /* last structure       */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* output data             */
   struct dsd_log_requ_1 dsl_lr1;           /* memory log request      */

   adsl_sdhc1_first = NULL;                 /* first structure         */
   if (   (imp_len < sizeof(struct dsd_wspadm1_q_log))
       || (imp_len != (sizeof(struct dsd_wspadm1_q_log) + adsp_waqlog->imc_len_query))) {
     iml1 = DEF_WSPADM_RT_INV_PARAM;        /* invalid parameters      */
     goto p_logr_err;                       /* return error in iml1    */
   }
   if (adsp_cb_new_log == NULL) {           /* not from pipe           */
     if (   (adsp_waqlog->iec_wa1l == ied_wa1l_upd_start)  /* start dynamic update */
         || (adsp_waqlog->iec_wa1l == ied_wa1l_upd_stop)) {  /* stop dynamic update */
       iml1 = DEF_WSPADM_RT_INV_PARAM;      /* invalid parameters      */
       goto p_logr_err;                     /* return error in iml1    */
     }
   }
   if (adsp_waqlog->iec_wa1l == ied_wa1l_upd_stop) {  /* stop dynamic update */
     if (adsp_cb_new_log->amc_x_new_log_check( vpp_param )) {
       adsp_cb_new_log->amc_x_new_log_unreg( vpp_param );
       return NULL;
     }
     iml1 = DEF_WSPADM_RT_INV_PARAM;        /* invalid parameters      */
     goto p_logr_err;                       /* return error in iml1    */
   }
   if (adsp_cb_new_log) {                   /* is from pipe            */
     if (adsp_cb_new_log->amc_x_new_log_check( vpp_param )) {
       return NULL;
     }
   }
   if (adsp_waqlog->iec_wa1l == ied_wa1l_upd_start) {  /* start dynamic update */
     bol1 = adsp_cb_new_log->amc_x_new_log_register( vpp_param, (char *) (adsp_waqlog + 1), adsp_waqlog->imc_len_query );
     if (bol1) return NULL;
     iml1 = DEF_WSPADM_RT_RESOURCE_UA;      /* resource unavailable    */
     goto p_logr_err;                       /* return error in iml1    */
   }
   if (adsp_waqlog->imc_retr_no_rec <= 0) {  /* retrieve number of records */
     iml1 = DEF_WSPADM_RT_INV_PARAM;        /* invalid parameters      */
     goto p_logr_err;                       /* return error in iml1    */
   }
   memset( &dsl_lr1, 0, sizeof(struct dsd_log_requ_1) );  /* memory log request */
   dsl_lr1.imc_len_area = D_MEM_LOG_MAX_LEN_REC;  /* length of area to be filled */
   dsl_lr1.iec_chs_area = ied_chs_utf_8;    /* character set area      */
   if (adsp_waqlog->imc_len_query) {        /* with sub-string         */
     if (adsp_waqlog->iec_wa1l == ied_wa1l_epoch) {  /* read records with this epoch */
       iml1 = DEF_WSPADM_RT_INV_PARAM;      /* invalid parameters      */
       goto p_logr_err;                     /* return error in iml1    */
     }
     dsl_lr1.achc_search_a = (char *) (adsp_waqlog + 1);  /* search key area */
     dsl_lr1.imc_len_search_a = adsp_waqlog->imc_len_query;  /* length of search area, elements */
     dsl_lr1.iec_chs_search = ied_chs_utf_8;  /* character set search  */
     dsl_lr1.boc_query_regex = adsp_waqlog->boc_query_regex;  /* query is regular expression */
   }
   switch (adsp_waqlog->iec_wa1l) {
     case ied_wa1l_cur:                     /* return current / last records */
       break;
     case ied_wa1l_pos:                     /* read from position      */
       iel_logreq1_def = ied_lreq1d_read_f;  /* read forward           */
       if (adsp_waqlog->imc_len_query) {    /* with sub-string         */
         iel_logreq1_def = ied_lreq1d_search_f;  /* search forward     */
         if (adsp_waqlog->boc_query_regex) {  /* query is regular expression */
           iel_logreq1_def = ied_lreq1d_s_regex_f;  /* search regular expression forward */
         }
       }
       if (adsp_waqlog->boc_backward) {     /* read backward           */
         iel_logreq1_def = ied_lreq1d_read_b;  /* read backward        */
         if (adsp_waqlog->imc_len_query) {  /* with sub-string         */
           iel_logreq1_def = ied_lreq1d_search_b;  /* search backward  */
           if (adsp_waqlog->boc_query_regex) {  /* query is regular expression */
             iel_logreq1_def = ied_lreq1d_s_regex_b;  /* search regular expression backward */
           }
         }
       }
       dsl_lr1.iec_logreq1_def = iel_logreq1_def;  /* set value for first call */
       dsl_lr1.ilc_position = adsp_waqlog->ilc_position;  /* position where to read */
       dsl_lr1.imc_count_filled = adsp_waqlog->imc_count_filled;  /* count how often filled */
       goto p_logr_40;                      /* output of requested log records */
     case ied_wa1l_epoch:                   /* read records with this epoch */
       dsl_lr1.iec_logreq1_def = ied_lreq1d_epoch_first;  /* retrieve first position log with this epoch */
#ifdef B100908
       dsl_lr1.imc_epoch = adsp_waqlog->imc_epoch;  /* epoch / time of log record */
#endif
       dsl_lr1.ilc_epoch = adsp_waqlog->ilc_epoch;  /* epoch / time of log record */
       iel_logreq1_def = ied_lreq1d_read_f;  /* read forward           */
       if (adsp_waqlog->boc_backward) {     /* read backward           */
         iel_logreq1_def = ied_lreq1d_read_b;  /* read backward        */
       }
       goto p_logr_40;                        /* output of requested log records */
     default:
       iml1 = DEF_WSPADM_RT_INV_PARAM;      /* invalid parameters      */
       goto p_logr_err;                     /* return error in iml1    */
   }
   dsl_lr1.iec_logreq1_def = ied_lreq1d_cur_pos;  /* return current position */
   m_mem_log_1_req( &dsl_lr1 );
   if (dsl_lr1.iec_logreq1_ret != ied_lreq1r_ok) {  /* request processed o.k. */
     if (dsl_lr1.iec_logreq1_ret == ied_lreq1r_not_open) {  /* log not opened */
       iml1 = DEF_WSPADM_RT_RESOURCE_UA;    /* resource unavailable    */
       goto p_logr_err;                     /* return error in iml1    */
     }
     iml1 = DEF_WSPADM_RT_MISC;             /* miscellaneous           */
     goto p_logr_err;                       /* return error in iml1    */
   }
   dsl_lr1.iec_logreq1_def = ied_lreq1d_read_b;  /* read backward      */
   if (adsp_waqlog->imc_len_query) {  /* with sub-string         */
     dsl_lr1.iec_logreq1_def = ied_lreq1d_search_b;  /* search backward */
     if (adsp_waqlog->boc_query_regex) {    /* query is regular expression */
       dsl_lr1.iec_logreq1_def = ied_lreq1d_s_regex_b;  /* search regular expression backward */
     }
   }
   if (adsp_waqlog->boc_backward) {         /* read backward           */
     iel_logreq1_def = dsl_lr1.iec_logreq1_def;  /* as set before      */
     goto p_logr_40;                        /* output of requested log records */
   }
   /* read backward over the requested records                         */
   iml1 = adsp_waqlog->imc_retr_no_rec - 1;  /* retrieve number of records */
   while (iml1 > 0) {                       /* loop to read backward   */
     m_mem_log_1_req( &dsl_lr1 );
     if (dsl_lr1.iec_logreq1_ret != ied_lreq1r_ok) {  /* request processed o.k. */
       if (dsl_lr1.iec_logreq1_ret == ied_lreq1r_eof) {  /* end of file found */
         if (iml1 == (adsp_waqlog->imc_retr_no_rec - 1)) {
           iml1 = DEF_WSPADM_RT_EOF;        /* end-of-file             */
           goto p_logr_err;                 /* return error in iml1    */
         }
         dsl_lr1.iec_logreq1_def = ied_lreq1d_read_f;  /* read forward */
         if (adsp_waqlog->imc_len_query) {  /* with sub-string         */
           dsl_lr1.iec_logreq1_def = ied_lreq1d_search_f;  /* search forward */
           if (adsp_waqlog->boc_query_regex) {  /* query is regular expression */
             dsl_lr1.iec_logreq1_def = ied_lreq1d_s_regex_f;  /* search regular expression forward */
           }
         }
         break;
       }
       iml1 = DEF_WSPADM_RT_MISC;           /* miscellaneous           */
       goto p_logr_err;                     /* return error in iml1    */
     }
     iml1--;                                /* decrement index         */
   }
   iel_logreq1_def = ied_lreq1d_read_f;     /* read forward            */
   if (adsp_waqlog->imc_len_query) {        /* with sub-string         */
     iel_logreq1_def = ied_lreq1d_search_f;  /* search forward         */
     if (adsp_waqlog->boc_query_regex) {    /* query is regular expression */
       iel_logreq1_def = ied_lreq1d_s_regex_f;  /* search regular expression forward */
     }
   }

   p_logr_40:                               /* output of requested log records */
   iml1 = adsp_waqlog->imc_retr_no_rec;     /* retrieve number of records */
   while (TRUE) {
     do {                                   /* pseudo-loop             */
       iml2 = sizeof(struct dsd_wspadm1_log) + D_MEM_LOG_MAX_LEN_REC;
       if (adsl_sdhc1_first) {              /* first structure present */
         achl_out += 4 + 1 + sizeof(void *) - 1;  /* output of values  */
         achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
         if ((achl_out + iml2 + sizeof(struct dsd_gather_i_1))
               <= ((char *) adsl_gai1_w1)) {
           adsl_gai1_w1--;                  /* here is gather output   */
           (adsl_gai1_w1 + 1)->adsc_next = adsl_gai1_w1;  /* set next in chain */
           break;
         }
       }
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
#ifdef DEBUG_080505
       printf( "xs-gw-admin-l%05d-T m_proc_alloc returned %p.\n",
               __LINE__, adsl_sdhc1_w1 );
       fflush( stdout );
#endif
       memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
       achl_out = (char *) (adsl_sdhc1_w1 + 1) + 4 + 1 + sizeof(void *) - 1;  /* output of values */
       achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
       adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - sizeof(struct dsd_gather_i_1));
#ifdef DEBUG_100909_01
       adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + 2048 - sizeof(struct dsd_gather_i_1));
#endif
       adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_gai1_w1;  /* gather input data */
       if (adsl_sdhc1_first == NULL) {      /* first structure not present */
         adsl_sdhc1_first = adsl_sdhc1_w1;  /* first structure now present */
         adsl_sdhc1_last = adsl_sdhc1_w1;   /* set last structure      */
         break;
       }
       adsl_sdhc1_last->adsc_next = adsl_sdhc1_w1;  /* append to chain */
       adsl_sdhc1_last = adsl_sdhc1_w1;     /* set last structure      */
     } while (FALSE);
#ifdef B101115
     adsl_gai1_w1->adsc_next = NULL;
#else
     memset( adsl_gai1_w1, 0, sizeof(struct dsd_gather_i_1) );
#endif
#define ADSL_WAL ((struct dsd_wspadm1_log *) achl_out)
     dsl_lr1.achc_area = (char *) (ADSL_WAL + 1);  /* area with log record */
     m_mem_log_1_req( &dsl_lr1 );
     if (dsl_lr1.iec_logreq1_ret != ied_lreq1r_ok) {  /* request processed o.k. */
       if (dsl_lr1.iec_logreq1_ret == ied_lreq1r_not_open) {  /* log not opened */
         iml1 = DEF_WSPADM_RT_RESOURCE_UA;  /* resource unavailable    */
         goto p_logr_err;                   /* return error in iml1    */
       }
       if (dsl_lr1.iec_logreq1_ret == ied_lreq1r_eof) {  /* end of file found */
         iml1 = DEF_WSPADM_RT_EOF;          /* end-of-file             */
         goto p_logr_err;                   /* return error in iml1    */
       }
       iml1 = DEF_WSPADM_RT_MISC;           /* miscellaneous           */
       goto p_logr_err;                     /* return error in iml1    */
     }
     ADSL_WAL->ilc_position = dsl_lr1.ilc_position;  /* position where to read */
     ADSL_WAL->imc_count_filled = dsl_lr1.imc_count_filled;  /* count how often filled  */
#ifdef B100908
     ADSL_WAL->imc_epoch = dsl_lr1.imc_epoch;  /* epoch / time of log record */
#endif
     ADSL_WAL->ilc_epoch = dsl_lr1.ilc_epoch;  /* epoch / time of log record */
     ADSL_WAL->imc_len_msg = dsl_lr1.imc_len_record;  /* length of following message, UTF-8 */
#undef ADSL_WAL
     adsl_gai1_w1->achc_ginp_end = achl_out + sizeof(struct dsd_wspadm1_log) + dsl_lr1.imc_len_record;  /* end of this structure */
     iml2 = 1 + sizeof(struct dsd_wspadm1_log) + dsl_lr1.imc_len_record;  /* length of record total */
     *(--achl_out) = 0;                     /* record type             */
     iml3 = 0;                              /* clear more bit          */
     while (TRUE) {                         /* output length NHASN     */
       *(--achl_out) = (unsigned char) ((iml2 & 0X7F) | iml3);  /* output of digit */
       iml2 >>= 7;                          /* remove digit            */
       if (iml2 == 0) break;                /* end of output           */
       iml3 = 0X80;                         /* set more bit            */
     }
     adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
     iml1--;                                /* decrement index         */
     if (iml1 <= 0) break;
     dsl_lr1.iec_logreq1_def = iel_logreq1_def;  /* continue read      */
     achl_out = adsl_gai1_w1->achc_ginp_end;  /* restore end of output */
   }
   return adsl_sdhc1_first;

   p_logr_err:                              /* return error in iml1    */
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
#ifdef DEBUG_080505
     printf( "xs-gw-admin-l%05d-T m_proc_alloc returned %p.\n",
             __LINE__, adsl_sdhc1_w1 );
     fflush( stdout );
#endif
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
   adsl_gai1_w1->achc_ginp_cur = achl_out;
   *achl_out++ = 1;                         /* length                  */
   *achl_out++ = (unsigned char) iml1;      /* error code              */
   adsl_gai1_w1->achc_ginp_end = achl_out;
   return adsl_sdhc1_first;
} /* end m_get_wspadm1_log()                                           */

#ifndef HL_UNIX
/** check if pipe retrieves log                                        */
static BOOL m_pipe_new_log_check( void * vpp_param ) {
   struct dsd_adm_pipe *adsl_adm_pipe;

   adsl_adm_pipe = (struct dsd_adm_pipe *) vpp_param;
   if (adsl_adm_pipe->adsc_ap_new_log) return TRUE;  /* structure for new log to pipe */
   return FALSE;
} /* end m_pipe_new_log_check()                                        */

/** register admin pipe to retrieve log messages                       */
static BOOL m_pipe_new_log_register( void * vpp_param, char *achp_search_a, int imp_len_search ) {
   BOOL       bol1;                         /* working variable        */
   struct dsd_adm_pipe *adsl_adm_pipe;

   adsl_adm_pipe = (struct dsd_adm_pipe *) vpp_param;
   adsl_adm_pipe->adsc_ap_new_log
     = (struct dsd_adm_pipe_new_log *) malloc( sizeof(struct dsd_adm_pipe_new_log) + imp_len_search );
   memset( adsl_adm_pipe->adsc_ap_new_log, 0, sizeof(struct dsd_adm_pipe_new_log) );
   adsl_adm_pipe->adsc_ap_new_log->adsc_adm_pipe = adsl_adm_pipe;  /* pipe for administration */
   adsl_adm_pipe->adsc_ap_new_log->dsc_lnc.amc_log_new_call = &m_pipe_log_new_call;  /* address callback routine */
   if (imp_len_search) {                    /* with search string      */
     adsl_adm_pipe->adsc_ap_new_log->imc_len_query = imp_len_search;  /* length of following query string, UTF-8 */
     memcpy( adsl_adm_pipe->adsc_ap_new_log + 1, achp_search_a, imp_len_search );
     adsl_adm_pipe->adsc_ap_new_log->dsc_mls1.achc_cmp_str = (char *) (adsl_adm_pipe->adsc_ap_new_log + 1);  /* string to compare */
     adsl_adm_pipe->adsc_ap_new_log->dsc_mls1.imc_len_cmp_str = imp_len_search;
     adsl_adm_pipe->adsc_ap_new_log->dsc_mls1.chc_fchar_1 = *adsl_adm_pipe->adsc_ap_new_log->dsc_mls1.achc_cmp_str;
     if ((adsl_adm_pipe->adsc_ap_new_log->dsc_mls1.chc_fchar_1 >= 'A') && (adsl_adm_pipe->adsc_ap_new_log->dsc_mls1.chc_fchar_1 <= 'Z')) {
       adsl_adm_pipe->adsc_ap_new_log->dsc_mls1.chc_fchar_2 = adsl_adm_pipe->adsc_ap_new_log->dsc_mls1.chc_fchar_1 + 0X20;
     } else if ((adsl_adm_pipe->adsc_ap_new_log->dsc_mls1.chc_fchar_1 >= 'a') && (adsl_adm_pipe->adsc_ap_new_log->dsc_mls1.chc_fchar_1 <= 'z')) {
       adsl_adm_pipe->adsc_ap_new_log->dsc_mls1.chc_fchar_2 = adsl_adm_pipe->adsc_ap_new_log->dsc_mls1.chc_fchar_1 - 0X20;
     }
   }
   bol1 = m_log_new_p_register( &adsl_adm_pipe->adsc_ap_new_log->dsc_lnc );
   if (bol1) return TRUE;
   free( adsl_adm_pipe->adsc_ap_new_log );  /* free memory again       */
   adsl_adm_pipe->adsc_ap_new_log = NULL;   /* new log not active      */
   return FALSE;
} /* end m_pipe_new_log_register()                                     */

/** end retrieve log for admin pipe                                    */
static void m_pipe_new_log_unreg( void * vpp_param ) {
   BOOL       bol1;                         /* working variable        */
   struct dsd_adm_pipe *adsl_adm_pipe;

   adsl_adm_pipe = (struct dsd_adm_pipe *) vpp_param;
   bol1 = m_log_new_p_unreg( &adsl_adm_pipe->adsc_ap_new_log->dsc_lnc );
   if (bol1 == FALSE) {
     m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W m_log_new_p_unreg() returned FALSE",
                     __LINE__ );
   }
   Sleep( 500 );                            /* wait some time          */
   free( adsl_adm_pipe->adsc_ap_new_log );  /* free memory again       */
   adsl_adm_pipe->adsc_ap_new_log = NULL;   /* new log not active      */
} /* end m_pipe_new_log_unreg()                                        */

/** callback routine when new log entry was created                    */
static void m_pipe_log_new_call( struct dsd_log_new_call *adsp_lnc,
                                 struct dsd_log_new_pass *adsp_lnp ) {
   int        iml1, iml2;                   /* working variables       */
   BOOL       bol1;                         /* working variable        */
   struct dsd_adm_pipe_new_log *adsl_apnl;  /* structure for new log to pipe */
   char       *achl_out;                    /* output of values        */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working-variable       */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* output data             */
   struct dsd_sdh_control_1 *adsl_sdhc1_cur;  /* current in chain      */
   struct dsd_sdh_control_1 *adsl_sdhc1_last;  /* was last in chain    */

   adsl_apnl = (struct dsd_adm_pipe_new_log *)
                 ((char *) adsp_lnc - offsetof( struct dsd_adm_pipe_new_log, dsc_lnc ));
   if (adsl_apnl->imc_len_query) {          /* length of following query string, UTF-8 */
     if (m_search_utf8_1( adsp_lnp->achc_area, adsp_lnp->imc_len_record, &adsl_apnl->dsc_mls1 ) == FALSE) return;
   }
   adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
#ifdef DEBUG_080505
   printf( "xs-gw-admin-l%05d-T m_proc_alloc returned %p.\n",
           __LINE__, adsl_sdhc1_w1 );
   fflush( stdout );
#endif
   memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
   achl_out = (char *) (adsl_sdhc1_w1 + 1) + 4 + 1 + sizeof(void *) - 1;  /* output of values */
   achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
   adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV) - 1;
   memset( adsl_gai1_w1, 0, sizeof(struct dsd_gather_i_1) );
#define ADSL_WAL ((struct dsd_wspadm1_log *) achl_out)
   ADSL_WAL->ilc_position = adsp_lnp->ilc_position;  /* position where to read */
   ADSL_WAL->imc_count_filled = adsp_lnp->imc_count_filled;  /* count how often filled */
#ifdef B100908
   ADSL_WAL->imc_epoch = adsp_lnp->imc_epoch;  /* epoch / time of log record */
#endif
   ADSL_WAL->ilc_epoch = adsp_lnp->ilc_epoch;  /* epoch / time of log record */
   ADSL_WAL->imc_len_msg = adsp_lnp->imc_len_record;  /* length of following message, UTF-8 */
   memcpy( ADSL_WAL + 1, adsp_lnp->achc_area, adsp_lnp->imc_len_record );
#undef ADSL_WAL
   adsl_gai1_w1->achc_ginp_end = achl_out + sizeof(struct dsd_wspadm1_log) + adsp_lnp->imc_len_record;  /* end of this structure */
   iml1 = 1 + sizeof(struct dsd_wspadm1_log) + adsp_lnp->imc_len_record;  /* length of record total */
   *(--achl_out) = 0;                       /* record type             */
   iml2 = 0;                                /* clear more bit          */
   while (TRUE) {                           /* output length NHASN     */
     *(--achl_out) = (unsigned char) ((iml1 & 0X7F) | iml2);  /* output of digit */
     iml1 >>= 7;                            /* remove digit            */
     if (iml1 == 0) break;                  /* end of output           */
     iml2 = 0X80;                           /* set more bit            */
   }
   adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
   adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_gai1_w1;  /* gather input data */
   adsl_sdhc1_last = NULL;                  /* clear last in chain     */
   dss_critsect_admin.m_enter();            /* critical section        */
   adsl_sdhc1_cur = adsl_apnl->adsc_adm_pipe->adsc_sdhc1_out;  /* chain output to pipe */
   iml1 = HOBADM_PIPE_MAX_OUT;
   while (adsl_sdhc1_cur) {                 /* loop over all existing buffers */
     iml1--;
     if (iml1 <= 0) break;                  /* already too many buffers */
     adsl_sdhc1_last = adsl_sdhc1_cur;      /* save last in chain      */
     adsl_sdhc1_cur = adsl_sdhc1_cur->adsc_next;  /* get next in chain */
   }
   if (adsl_sdhc1_cur == NULL) {            /* add this buffer         */
     if (adsl_sdhc1_last == NULL) {         /* at beginning of chain   */
       adsl_apnl->adsc_adm_pipe->adsc_sdhc1_out = adsl_sdhc1_w1;
     } else {
       adsl_sdhc1_last->adsc_next = adsl_sdhc1_w1;
     }
   }
   dss_critsect_admin.m_leave();            /* critical section        */
   if (adsl_sdhc1_cur) {                    /* too many buffers        */
     m_proc_free( adsl_sdhc1_w1 );          /* free buffer again       */
     return;
   }
   if (adsl_sdhc1_last) return;             /* not first one to write  */
   bol1 = SetEvent( dss_heve_main );
   if (bol1) return;                        /* no error occured        */
   m_hlnew_printf( HLOG_XYZ1, "xs-gw-admin-l%05d-W SetEvent() main Error %d.",
                   __LINE__, GetLastError() );
} /* end m_pipe_log_new_call()                                         */
#endif
