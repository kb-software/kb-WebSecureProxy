#define CL_RET_TIME     // use of retention time not yet tested
//#define TRACEHL1
//#define TRACE_170913
#define CLUSTER
//#ifndef HL_UNIX
//  #define TRACE_LOCKTIME
//#endif
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xswspcma                                            |*/
/*| -------------                                                     |*/
/*|  Process Common Memory Area                                       |*/
/*|  Subroutine of WebSecureproxy                                     |*/
/*|  KB 23.12.04                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB 2004                                           |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

//define HL_SPECIAL_OFFER_CEBIT_04 5
//#define HL_IPV6
/* define TRACEHL1 */
/* define TRACEWSAT */
#ifdef TRACEHL1
#define TRACEHLB
#ifndef TRACEHLP
#define TRACEHLP
#endif
#endif

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#include <stddef.h>
#include <stdlib.h>
//#include <stdio.h>
#include <string.h>
#ifndef HL_UNIX
#include <conio.h>
#endif
#include <time.h>
#ifdef HL_UNIX
#include <stdarg.h>
#include <sys/types.h>
#include <netinet/in.h>
/* start header-files for TCPCOMP                                      */
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/uio.h>
#include <netinet/tcp.h>
/* end header-files for TCPCOMP                                        */
#endif
#ifdef HL_LINUX
#ifdef B120306
#include <pth.h>                            /* for INFTIM              */
#endif
#ifdef B120221
#include <hxnet.h>
#endif
#endif
#ifndef HL_UNIX
#include <wchar.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <process.h>
#ifdef PROBLEM_090226                       /* KDRS - deadlock - Web-Server hangs */
#include <sys/timeb.h>
#endif
//#include "hob-avl03.h"
#else
#include <sys/ipc.h>
#include <sys/sem.h>
#include <errno.h>
#include "hob-unix01.h"
#endif
#include "hob-xslhcla1.hpp"
#include <hob-xslunic1.h>
#define HL_EXT_TAB_850_TO_819
#include <hob-tab-ascii-ansi-1.h>
#include <hob-avl03.h>
#include "hob-wspsu1.h"
#include <hob-netw-01.h>
#include <hob-tcpco1.hpp>
#ifndef B111013
#include <hob-nblock_acc.hpp>
#endif
#ifdef B110817
#ifdef NOT_YET_090225
#ifndef D_SDHREF
#include <hob-netw-01.h>
#include <hob-nblock_acc.hpp>
#ifndef TRY_090121
#include <hob-tcpco1.hpp>
#else
#include "E:\Garkuscha\Tests\tcpcomp_sample\hob-tcpco1.hpp"
#endif
#endif
#endif
#ifndef FIX_090317
#include <hob-netw-01.h>
#ifndef TRY_090121
#include <hob-tcpco1.hpp>
#else
#include "E:\Garkuscha\Tests\tcpcomp_sample\hob-tcpco1.hpp"
#endif
#endif
#endif
#ifndef HL_UNIX
#include <hob-thread.hpp>
#endif

#ifdef B110817
#ifdef B090225
#define DOMNode void
#else
#ifdef B100518
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
#include "NBIPGW08-X1.hpp"
#endif
#endif
#else
#define DOMNode void
#endif

//#define DEF_HL_INCL_DOM
#include "hob-xsclib01.h"

#ifndef D_SDHREF
#define INCL_GW_ALL
#define HL_KRB5
#include "hob-wsppriv.h"        /* privileges   */
//#define HOB_CONTR_TIMER
#include <hob-xslcontr.h>       /* HOB Control  */
#include "hob-xbipgw08-1.h"
#include "hob-xbipgw08-2.h"
#endif

#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif

#ifdef CLUSTER
#define WT_CLUSTER 30  /* wait time (sec) for response from other WSP */
#endif

/*+-------------------------------------------------------------------+*/
/*| Constant Values.                                                  |*/
/*+-------------------------------------------------------------------+*/

#ifdef CLUSTER
/* for messages between cma of different WSP's in a cluster            */
enum ied_cma_msg {          /* type of message received from other WSP */
   ied_cma_msg_resp,            /* response to a message               */
   ied_cma_msg_upd_lock,        /* lock area for update data           */
   ied_cma_msg_upd_data,        /* recieve update data                 */
   ied_cma_msg_upd_req_l,       /* request for update (lock)           */
   ied_cma_msg_upd_req_d,       /* request for update (data)           */
   ied_cma_msg_lock_global,     /* request for global lock             */
   ied_cma_msg_lock_region,     /* request for lock on region          */
   ied_cma_msg_lock_release,    /* request for release lock            */
   ied_cma_msg_lock_rel_upd,    /* request for release lock and update */
   ied_cma_msg_data_if_empty    /* recieve data, if still empty        */
};
#endif

/*+-------------------------------------------------------------------+*/
/*| Function Calls definitions.                                       |*/
/*+-------------------------------------------------------------------+*/

//extern void GetPerfData( IBHWTSS1_PERFDATA * );
#ifdef D_SDHREF
extern "C" int m_hl2_printf( char *, ... );
#endif

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Internal used structures and classes.                             |*/
/*+-------------------------------------------------------------------+*/

#ifdef CLUSTER
struct dsd_elem_chain {                     /* general chain of elements  */
   struct dsd_elem_chain *adsc_next;        /* next in chain              */
   void   *ac_elem;                         /* element                    */
};

struct dsd_double_chain {                   /* general chain of elements  */
   struct dsd_double_chain *adsc_pred;      /* predecessor                */
   struct dsd_double_chain *adsc_succ;      /* successor                  */
   void   *ac_d_elem;                       /* element                    */
};

struct dsd_cma_ext_lock {                   /* chain of external locks    */
   struct dsd_cma_ext_lock  *adsc_next;     /* next in chain              */
   struct dsd_cma1_ent   *adsc_entry;      /* back reference to cma entry */
   struct dsd_elem_chain *adsc_wait_entry;  /* waiting threads            */
   struct dsd_double_chain *adsc_remote_chain;  /* reference of this lock */
                                            /* in clact structure         */
   void   *ac_clact;                        /* active cluster             */
   HL_LONGLONG      ilc_epoch_ms;           /* epoch in milliseconds      */
   int        inc_lock_type;                /* flags of lock              */
   int        inc_lock_disp;                /* displacement locked area   */
   int        inc_lock_len;                 /* length of locked area      */
};

struct dsd_cluster_info {          /* one for every wsp, that connects   */
   struct dsd_cluster_info   *adsc_next;
   struct dsd_cluster_active *adsc_clact;     /* identifies remote WSP   */
   /* chain adsc_active_locks is used to free all external locks related */
   /* to this remote WSP, if it is no longer reachable                   */
   struct dsd_double_chain *adsc_active_locks;  /* current active locks  */
   BOOL   boc_update;                /* request for cma update is active */
};
#endif

struct dsd_cma1_ent {                       /* common memory area 1 entry */
   //struct dsd_cma1_ent *adsc_next;        /* next in chain              */
   struct dsd_htree1_avl_entry dsc_htree1;  /* position of entry in tree  */
#ifdef CLUSTER
   struct dsd_cma_ext_lock *adsc_ext_chain; /* chain of external locks    */
#endif
   int        inc_size_area;                /* size of area               */
   HL_LONGLONG ilc_epoch_last_used;         /* save EPOCH entry last used */
   int        imc_retention_time;           /* retention time in seconds  */
   char       *achc_area;                   /* area cma                   */
   void *     vpc_lock_chain;               /* chain of locks             */
};

struct dsd_cma1_co {                        /* common memory area 1 control area */
   //struct dsd_cma1_ent *adsc_cma1_ent_anchor;  /* anchor of chain      */
   struct dsd_htree1_avl_cntl dsc_avl_cntl;    /* avl control structure  */
#ifdef D_SDHREF
   struct dsd_cma1_lock *adsc_cma1_lock_anchor;  /* anchor of chain of locks */
#endif
#ifdef CLUSTER
   //for testing
//#ifdef TRACEHL1
//   int    inc_test;
//#endif
   struct dsd_cluster_info *adsc_cluster_info; /* for working with wsp clusters */
   struct dsd_hco_wothr    *adsc_thr_upd;      /* thread for doing cma update   */
   struct dsd_cluster_active *adsc_clact_upd;  /* cluster for update            */
   struct dsd_cma1_ent     *adsc_ent_upd;      /* entry to be updated           */
   struct dsd_cma1_ent     *adsc_ent_loc;   /* local entry not yet on other WSP */
   int    inc_upd_length;                      /* length of updated data        */
#endif
   class dsd_hcla_critsect_1 dsc_critsect_1;  /* critical section      */
#ifdef PROBLEM_090226                       /* KDRS - deadlock - Web-Server hangs */
   int        imc_count_locks;              /* count the locks         */
#endif
#ifdef TRACEHL_CMA_LOCK
   int        imc_lock_no;
#endif
#ifdef TRACE_LOCKTIME
   HL_LONGLONG ilc_freq;                    /* for QueryPerformanceFrequency() */
#endif
};

#ifdef CLUSTER
struct dsd_cl_lock_state {          /* state of lock in cluster         */
   struct dsd_cl_lock_state  *adsc_next;
   struct dsd_cluster_active *adsc_cluster;
   int  inc_state;                 /* -1: lock, 0: invalid, 1: release */
   int  inc_sub_state;             /*  0: waiting, 1: pos., -1: neg.   */
};
#endif

struct dsd_cma1_lock {                      /* common memory area 1 lock */
   struct dsd_cma1_lock *adsc_next;         /* next in chain           */
#ifdef D_SDHREF
   struct dsd_cma1_lock *adsc_global_next;  /* next in global chain    */
#endif
#ifdef CLUSTER
   struct dsd_cl_lock_state *adsc_cl_lock;  /* state of lock for clust.*/
   HL_LONGLONG      ilc_epoch_ms;           /* epoch of lock [ms]      */
   BOOL       boc_ready;                    /* ready for next state    */
#endif
   void *     vpc_userfld;                  /* entry session           */
   int        inc_lock_disp;                /* displacement locked area */
   int        inc_lock_len;                 /* length of locked area   */
   int        inc_lock_type;                /* flags of lock           */
#ifdef TRACEHL_CMA_LOCK
   int        imc_lock_no;
#endif
#ifdef TRACE_LOCKTIME
   HL_LONGLONG ilc_start_lock;
   HL_LONGLONG ilc_start_post;
#endif
};


struct dsd_avl_dummy {
   struct dsd_cma1_ent dsc_cma_dummy;
   HL_WCHAR  wcrc_cma_name[ DEF_MAX_LEN_CMA_NAME + 2 ]; /* +2bytes len */
};

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

#ifdef PROBLEM_090226                       /* KDRS - deadlock - Web-Server hangs */
static HL_LONGLONG m_get_epoch_ms( void );
#endif

/* compare avl entries */
static int m_cma1_comp_names( void *, struct dsd_htree1_avl_entry *,
                                      struct dsd_htree1_avl_entry * );

static inline int m_get_browse_name( struct dsd_hl_aux_c_cma_1 *,
                                     int, struct dsd_cma1_ent * );

#ifdef CLUSTER
static int m_send_cma_entry( void *ap_cma_entry, ied_cma_msg iep_cma_msg,
                             struct dsd_cluster_active *adsp_clact );

static void m_send_compl1( struct dsd_cluster_send *adsp_cluster_s );

static void m_send_compl2( struct dsd_cluster_send *adsp_cluster_s );

static void m_proc_cma_update( struct dsd_hco_wothr *adsp_hco_wothr,
                  void *ap_param_1, void *ap_param_2, void *ap_param_3 );

static dsd_cma_ext_lock* m_check_ext_locks( dsd_hl_aux_c_cma_1 *adsp_cma,
                                      dsd_cma_ext_lock *adsp_ext_chain );

static inline char* m_conv_to_nhasn( char *achp1, HL_LONGLONG ilp_number );

static inline HL_LONGLONG m_conv_from_nhasn(struct dsd_gather_i_1
                                                           *adsp_gather);

static inline void m_remove_ext_lock( struct dsd_cma1_ent *adsp_entry,
                                 struct dsd_cma_ext_lock *adsp_ext_lock );

/* KT-130114- following line changed:
   static void m_cleanup_lock_chain(struct dsd_double_chain *adsp_lock_chain);
   see also m_cma1_cluster_close() */
static void m_cleanup_lock_chain(struct dsd_cluster_info *adsp_clinfo);
#endif

/*+-------------------------------------------------------------------+*/
/*| Internal used classes.                                            |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

static struct dsd_cma1_co dss_cma1_co;      /* common memory area 1 control area */

/*+-------------------------------------------------------------------+*/
/*| Procedure Section.                                                |*/
/*+-------------------------------------------------------------------+*/

/**
 * m_cma1_init() initializes the global structure dsd_cma1_co
 * and the AVL tree for the cma entries.
 */
extern "C" void m_cma1_init( void ) {
#ifdef TRACE_LOCKTIME
   BOOL       bol1;                         /* working variable        */
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xswspcma.cpp m_cma1_init() called" );
#endif
   dss_cma1_co.dsc_critsect_1.m_create();   /* critical section        */
#ifdef CLUSTER
   //dss_cma1_co.boc_no_sync       = TRUE;
   dss_cma1_co.adsc_cluster_info = NULL;   /* chain of WSP's connected */
   dss_cma1_co.adsc_clact_upd    = NULL;   /* clact used for update    */
   dss_cma1_co.adsc_thr_upd      = NULL;   /* for waking up upd.thread */
   dss_cma1_co.adsc_ent_upd      = NULL;   /* updated untill this entry */
   dss_cma1_co.adsc_ent_loc      = NULL;
   //for testing
//#ifdef TRACEHL1
//   dss_cma1_co.inc_test = 0;
//#endif
#endif
   /* KT -07.04.11- initialize random generator with time */
   srand( (unsigned)time(NULL) );  /* used to avoid lock collisions    */

   /* init AVL Tree functions                                          */
   m_htree1_avl_init( NULL, &dss_cma1_co.dsc_avl_cntl, &m_cma1_comp_names);
#ifdef PROBLEM_090226                       /* KDRS - deadlock - Web-Server hangs */
   dss_cma1_co.imc_count_locks = 0;         /* count the locks         */
#endif
#ifdef TRACEHL_CMA_LOCK
   dss_cma1_co.imc_lock_no = 0;
#endif
#ifdef TRACE_LOCKTIME
   dss_cma1_co.ilc_freq = 0;
   bol1 = QueryPerformanceFrequency( (LARGE_INTEGER *) &dss_cma1_co.ilc_freq );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_XYZ1,
                     "xs-gw_cma1-02-l%05d-W QueryPerformanceFrequency() Error %d.\n",
                     __LINE__, GetLastError() );
   }
#endif

   return;
} /* end m_cma1_init()                                                 */

/**
 * m_cma1_proc processes a common memory area command.
 *
 * @param  vpp_userfld   void pointer, that can be passed through to a callback function
 * @param  adsp_cma_1    structure containing a name or id to identify the
 *                       cma entry and other informations, what to do with the cma
 * @return BOOL          TRUE, if cma command was processed correctly, else FALSE
 */
extern "C" BOOL m_cma1_proc( void *vpp_userfld, struct dsd_hl_aux_c_cma_1 *adsp_cma_1 ) {
#ifdef D_SDHREF
   BOOL       bol1;                         /* working variable        */
#endif
   BOOL       bol_test;                     /* working variable        */
   int        iml1;                         /* working variable        */
   int        iml_rc;                       /* working variable        */
// DWORD      dwl1;                         /* working variable        */
   char       *achl1, *achl2;               /* working variables       */
   int        iml_len_name;                 /* length of file-name     */
//   BOOL       bolerror;                     /* save error              */
   time_t     dsl_time_1;                   /* for time                */
#ifdef B090226
   void *     vpl_userfld_p;                /* entry has to post event */
#endif
   struct dsd_cma1_ent *adsl_cma_1_1;       /* working variable        */
   //struct dsd_cma1_ent *adsl_cma_1_2;       /* working variable        */
   struct dsd_cma1_lock *adsl_cma1_lock_1;  /* working variable        */
   struct dsd_cma1_lock *adsl_cma1_lock_2;  /* working variable        */
   struct dsd_htree1_avl_work dsl_avl_work; /* working struct. for avl */
   struct dsd_avl_dummy dsl_dummy_entry;    /* dummy for avl search    */
#ifdef CLUSTER
   struct dsd_cluster_send *adsl_cluster_s;  /* send to cluster        */
   struct dsd_cluster_send *adsl_cluster_s2; /* send to cluster        */
   char   *achl_cl_send_data;                /* data to send           */
   //int    iml_size_cluster_send;    /* size of dsd_cluster_send + data */
   //struct dsd_cluster_active *adsl_cluster_a; /* for cluster connect.  */
   struct dsd_cluster_info  *adsl_cluster_i; /* remote WSP info chain  */
   struct dsd_cluster_info **adsrl_cluster_i; /* array of chain entries*/
   struct dsd_cl_lock_state *adsl_cluster_ls; /* lock state in cluster */
   struct dsd_cl_lock_state *adsl_cluster_ls2; /* copy for free()      */
   HL_LONGLONG ill_nhasn;                   /* for conversion to nhasn */
   ied_ccma_def iel_ccma_def;       /* for retry locking after release */
   //HL_WCHAR *wcrl_msg;                      /* for error messages      */
#endif
#ifdef PROBLEM_090226                       /* KDRS - deadlock - Web-Server hangs */
   void *     vpl_userfld_lock;
#endif
#ifdef TRACEHL_CMA_LOCK
   struct dsd_cma1_lock dsl_cma1_lock_save;
#endif
   HL_WCHAR   *wcrl_cma_name;                  /* for cma name         */
   //HL_WCHAR   wcrl_cma_name[ DEF_MAX_LEN_CMA_NAME + 1 ];  /* for cma name */
#ifdef TRACE_LOCKTIME
   HL_LONGLONG ill_start;
   HL_LONGLONG ill_end;
#endif

   /* -KT 260613- get current epoch time first */
   time( &dsl_time_1 );                     /* get current epoch time       */

//#ifdef TRACEHL1
//   m_hlnew_printf( HLOG_XYZ1, "xswspcma.cpp m_cma1_proc() called vpp_userfld=%p adsp_cma_1=%p.",
//                   vpp_userfld, adsp_cma_1 );
//#endif
#ifndef D_SDHREF
   if (adsp_cma_1->iec_ccma_def == ied_ccma_check_lock) {  /* check if lock exists */
     adsp_cma_1->imc_ret_no_locks = m_wsp_s_count( vpp_userfld, DEF_WSP_TYPE_CMA );  /* return number of lock that exist */
     return TRUE;                           /* all done                */
   }
#endif
#ifdef D_SDHREF
   if (adsp_cma_1->iec_ccma_def == ied_ccma_check_lock) {  /* check if lock exists */
     adsp_cma_1->imc_ret_no_locks = 0;      /* clear number of lock that exist */
     dss_cma1_co.dsc_critsect_1.m_enter();  /* critical section        */
     adsl_cma1_lock_w3 = dss_cma1_co.adsc_cma1_lock_anchor;  /* get chain of locks */
     while (adsl_cma1_lock_w3) {            /* loop over all locks     */
       if (adsl_cma1_lock_w3->vpc_userfld == vpp_userfld) {  /* from this calling context */
         adsp_cma_1->imc_ret_no_locks++;    /* increment number of lock that exist */
       }
       adsl_cma1_lock_w3 = adsl_cma1_lock_w3->adsc_global_next;  /* get next in chain */
     }
     dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section        */
     return TRUE;                           /* all done                */
   }
#endif

   if (adsp_cma_1->ac_cma_handle) goto p_proc_08;  /* handle found     */

   if (   (   (adsp_cma_1->ac_cma_name == NULL)
           || (adsp_cma_1->inc_len_cma_name == 0))
       && (   (adsp_cma_1->iec_ccma_def == ied_ccma_browse_entry_gr_eq)  /* browse entry greater equal */
           || (adsp_cma_1->iec_ccma_def == ied_ccma_browse_entry_greater))) {  /* browse entry greater    */
     //wcrl_cma_name[0] = 0;                  /* clear name              */
     //goto p_browse_00;                      /* browse thru entries     */
     dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section      */
     /* look for first entry in avl tree */
     bol_test = m_htree1_avl_getnext( NULL, &dss_cma1_co.dsc_avl_cntl,
                                      &dsl_avl_work, 1 );
     //dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section      */
     if (bol_test == false) {
       dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section      */
       return FALSE;
     }

     if (dsl_avl_work.adsc_found) {
       /* -KT 260613- update ilc_epoch_last_used inside critical section
         to prevent problems with expired retention time                 */
       ((dsd_cma1_ent *) dsl_avl_work.adsc_found)->ilc_epoch_last_used
                                                            = dsl_time_1;
       dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section      */
       iml1 = adsp_cma_1->imc_mem_cma_browse_name;
       if (iml1 <= 0)   /* invalid size */
         return FALSE;

       adsp_cma_1->imc_len_cma_browse_name
           = m_get_browse_name( adsp_cma_1, iml1,
                     (dsd_cma1_ent *)((char *)dsl_avl_work.adsc_found
                                 - offsetof(dsd_cma1_ent, dsc_htree1)) );
     }
     else { /* no entry found */
       adsp_cma_1->imc_len_cma_browse_name = 0;  /* clear length cma browse name in elements */
     }
     return TRUE;
   }

   /* pointer to copy cma name into dummy entry for tree search        */
   wcrl_cma_name = dsl_dummy_entry.wcrc_cma_name + 1;

   //iml_len_name = m_cpy_vx_vx( wcrl_cma_name, sizeof(wcrl_cma_name) / sizeof(HL_WCHAR), ied_chs_utf_16,
   //                            adsp_cma_1->ac_cma_name, adsp_cma_1->inc_len_cma_name, adsp_cma_1->iec_chs_name );
   iml_len_name
      = m_cpy_vx_vx( wcrl_cma_name,
          (sizeof(dsl_dummy_entry.wcrc_cma_name) / sizeof(HL_WCHAR)) - 1,
          ied_chs_utf_16, adsp_cma_1->ac_cma_name,
          adsp_cma_1->inc_len_cma_name, adsp_cma_1->iec_chs_name );
   if (iml_len_name <= 0) return FALSE;

   /* fill first byte with length                                      */
   *((char *)dsl_dummy_entry.wcrc_cma_name) = (unsigned char) iml_len_name;

   if (   (adsp_cma_1->iec_ccma_def == ied_ccma_browse_entry_gr_eq)  /* browse entry greater equal */
       || (adsp_cma_1->iec_ccma_def == ied_ccma_browse_entry_greater)) {  /* browse entry greater    */
     //goto p_browse_00;                      /* browse thru entries     */
     /* search for entry */
     dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section      */
     bol_test = m_htree1_avl_search( NULL, &dss_cma1_co.dsc_avl_cntl,
              &dsl_avl_work, &dsl_dummy_entry.dsc_cma_dummy.dsc_htree1 );
     if (!bol_test) {
       dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section    */
       return FALSE;
     }

     if (dsl_avl_work.adsc_found == NULL
         || (adsp_cma_1->iec_ccma_def == ied_ccma_browse_entry_greater))
     { /* search for next greater entry  */
       bol_test = m_htree1_avl_getnext( NULL, &dss_cma1_co.dsc_avl_cntl,
                                      &dsl_avl_work, 0 );

       if (!bol_test) {
         dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section      */
         return FALSE;
       }
     }
     //dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section      */

     if (dsl_avl_work.adsc_found) {
       /* -KT 260613- update ilc_epoch_last_used inside critical section
         to prevent problems with expired retention time                 */
       ((dsd_cma1_ent *) dsl_avl_work.adsc_found)->ilc_epoch_last_used
                                                            = dsl_time_1;
       dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section      */
       iml1 = adsp_cma_1->imc_mem_cma_browse_name;
       if (iml1 <= 0)   /* invalid size */
         return FALSE;

       adsp_cma_1->imc_len_cma_browse_name
           = m_get_browse_name( adsp_cma_1, iml1,
                     (dsd_cma1_ent *)((char *)dsl_avl_work.adsc_found
                                 - offsetof(dsd_cma1_ent, dsc_htree1)) );
     }
     else { /* no entry found */
       dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section      */
       adsp_cma_1->imc_len_cma_browse_name = 0;  /* clear length cma browse name in elements */
     }
     return TRUE;
   } /* end: if ied_ccma_browse... */

   /* search if this cma already defined                               */
   dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section        */
   bol_test = m_htree1_avl_search( NULL, &dss_cma1_co.dsc_avl_cntl,
              &dsl_avl_work, &dsl_dummy_entry.dsc_cma_dummy.dsc_htree1 );
   //dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section        */
   if (bol_test == FALSE) {
     dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section        */
     return FALSE;
   }

   if (dsl_avl_work.adsc_found != NULL) {  /* entry found              */
     /* -KT 260613- update ilc_epoch_last_used inside critical section
       to prevent problems with expired retention time                 */
     ((dsd_cma1_ent *) dsl_avl_work.adsc_found)->ilc_epoch_last_used
                                                            = dsl_time_1;
     dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section        */
     adsp_cma_1->ac_cma_handle = dsl_avl_work.adsc_found;

     goto p_proc_20;                       /* cma entry defined        */
   }
   dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section        */

   /* At this point a message could be sent to the other WSP's to create
      a new, empty cma. This is unnecessary step, because it's sufficient
      to create the cma, when the size of that cma is known.           */

   /* create new entry                                                 */
   adsl_cma_1_1
         = (struct dsd_cma1_ent *) malloc( sizeof(struct dsd_cma1_ent)
                                   + (iml_len_name+1)*sizeof(HL_WCHAR) );
   memset( adsl_cma_1_1, 0, sizeof(struct dsd_cma1_ent) );
   memcpy( adsl_cma_1_1 + 1, dsl_dummy_entry.wcrc_cma_name,
                                     (iml_len_name+1)*sizeof(HL_WCHAR) );

   /* check if defined inbetween                                       */
   dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section        */
   bol_test = m_htree1_avl_search( NULL, &dss_cma1_co.dsc_avl_cntl,
                              &dsl_avl_work, &adsl_cma_1_1->dsc_htree1 );
   if (bol_test == FALSE) {  /* error in search  */
     dss_cma1_co.dsc_critsect_1.m_leave();
     free(adsl_cma_1_1);
     return FALSE;
   }
   if (dsl_avl_work.adsc_found == NULL) {   /* no other entry found    */
     bol_test = m_htree1_avl_insert( NULL, &dss_cma1_co.dsc_avl_cntl,
                              &dsl_avl_work, &adsl_cma_1_1->dsc_htree1 );
     /* -KT 260613- update ilc_epoch_last_used inside critical section
       to prevent problems with expired retention time                 */
     adsl_cma_1_1->ilc_epoch_last_used = dsl_time_1;
     dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section        */
     if (bol_test == FALSE) {               /* error in insert         */
       free( adsl_cma_1_1 );                /* free new entry          */
       return FALSE;
     }
     adsp_cma_1->ac_cma_handle = adsl_cma_1_1;
   }
   else {  /* entry found now */
     /* -KT 260613- update ilc_epoch_last_used inside critical section
       to prevent problems with expired retention time                 */
     ((dsd_cma1_ent *) dsl_avl_work.adsc_found)->ilc_epoch_last_used
                                                            = dsl_time_1;
     dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section        */
     adsp_cma_1->ac_cma_handle = dsl_avl_work.adsc_found;
     free( adsl_cma_1_1 );                  /* free new entry          */
   }
   goto p_proc_20;

//   adsl_cma_1_1 = dss_cma1_co.adsc_cma1_ent_anchor;  /* anchor of chain */
//   while (adsl_cma_1_1) {                   /* loop over chain         */
//#ifndef HL_UNIX
//     if (!_wcsicoll( (WCHAR *) (adsl_cma_1_1 + 1), (WCHAR *) wcrl_cma_name )) break;
//#else
//     if (!m_cmpi_u16z_u16z( (HL_WCHAR *) (adsl_cma_1_1 + 1), wcrl_cma_name )) break;
//#endif
//     adsl_cma_1_1 = adsl_cma_1_1->adsc_next;  /* get next in chain     */
//   }
//   if (adsl_cma_1_1 == NULL) {              /* no other entry found    */
//     /* new element replaces old anchor                                */
//     adsl_cma_1_2->adsc_next = dss_cma1_co.adsc_cma1_ent_anchor;
//     dss_cma1_co.adsc_cma1_ent_anchor = adsl_cma_1_2;
//   }

   //if (adsl_cma_1_1) {                      /* other entry found       */
   //  free( adsl_cma_1_1 );                  /* free new entry          */
   //  adsp_cma_1->ac_cma_handle = dsl_avl_work.adsc_found;
   //} else {                                 /* is new entry            */
   //  adsl_cma_1_1 = adsl_cma_1_2;           /* use this entry now      */
   //}
   //adsp_cma_1->ac_cma_handle = adsl_cma_1_1;  /* set handle of created entry */

   p_proc_08:                               /* handle found            */
#define ADSL_CMA_1_G ((struct dsd_cma1_ent *) adsp_cma_1->ac_cma_handle)
   //if (   (adsp_cma_1->iec_ccma_def == ied_ccma_browse_entry_gr_eq)  /* browse entry greater equal */
   //    || (adsp_cma_1->iec_ccma_def == ied_ccma_browse_entry_greater)) {  /* browse entry greater    */
   //  iml1 = m_cpy_vx_vx( wcrl_cma_name, sizeof(wcrl_cma_name) / sizeof(HL_WCHAR), ied_chs_utf_16,
   //                      adsl_cma_1_1 + 1, -1, ied_chs_utf_16 );
   //  if (iml1 <= 0) return FALSE;

   //  goto p_browse_00;                      /* browse thru entries     */
   //}
   if ( adsp_cma_1->iec_ccma_def == ied_ccma_browse_entry_gr_eq )
   { /* browse entry greater equal */
     iml1 = adsp_cma_1->imc_mem_cma_browse_name;
     if (iml1 <= 0)   /* invalid size */
       return FALSE;

     adsp_cma_1->imc_len_cma_browse_name
         = m_get_browse_name( adsp_cma_1, iml1, ADSL_CMA_1_G );

     return TRUE;
   }
   if (adsp_cma_1->iec_ccma_def == ied_ccma_browse_entry_greater)
   { /* browse entry greater    */
     dsl_avl_work.adsc_found = &(ADSL_CMA_1_G->dsc_htree1);
     dss_cma1_co.dsc_critsect_1.m_enter();  /* critical section        */
     bol_test = m_htree1_avl_getnext( NULL, &dss_cma1_co.dsc_avl_cntl,
                                      &dsl_avl_work, 0 );
     //dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section        */
     if (!bol_test) {
       dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section        */
       return FALSE;
     }
     if (dsl_avl_work.adsc_found) {
       /* -KT 260613- update ilc_epoch_last_used inside critical section
         to prevent problems with expired retention time                 */
       ((dsd_cma1_ent *) dsl_avl_work.adsc_found)->ilc_epoch_last_used
                                                            = dsl_time_1;
       dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section      */
       iml1 = adsp_cma_1->imc_mem_cma_browse_name;
       if (iml1 <= 0) {  /* invalid size */
         return FALSE;
       }

       adsp_cma_1->imc_len_cma_browse_name
           = m_get_browse_name( adsp_cma_1, iml1,
                     (dsd_cma1_ent *)((char *)dsl_avl_work.adsc_found
                                 - offsetof(dsd_cma1_ent, dsc_htree1)) );
     }
     else { /* end of tree reached */
       dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section      */
       adsp_cma_1->imc_len_cma_browse_name = 0;  /* clear length cma browse name in elements */
     }

     adsp_cma_1->ac_cma_handle = NULL;      /* do not return handle of entry */
     return TRUE;                           /* all done                */
   }

//#ifdef TRACEHL1
//   adsl_cma_1_1 = dss_cma1_co.adsc_cma1_ent_anchor;  /* anchor of chain */
//   while (adsl_cma_1_1) {                   /* loop over chain         */
//     if (adsl_cma_1_1 == ADSL_CMA_1_G) break;
//     adsl_cma_1_1 = adsl_cma_1_1->adsc_next;  /* get next in chain     */
//   }
//   if (adsl_cma_1_1 == NULL) {
//     printf( "entry not found\n" );
//#ifndef HL_UNIX
//     ExitProcess( 1 );
//#else
//     exit( 1 );
//#endif
//   }
//#endif

   p_proc_20:                               /* cma entry defined       */
   /* -KT 260613- update ilc_epoch_last_used earlier already after
     finding the entry in the tree to prevent problems with expired
     retention time                 */
   //time( &dsl_time_1 );                     /* get current time        */
   //ADSL_CMA_1_G->ilc_epoch_last_used = dsl_time_1;  /* save EPOCH entry last used */
   switch (adsp_cma_1->iec_ccma_def) {
     case ied_ccma_query:                   /* query size of cma area  */
       adsp_cma_1->inc_len_cma_area = ADSL_CMA_1_G->inc_size_area;
       /* KTI-230609: to prevent usage of handle in a wrong way */
       adsp_cma_1->ac_cma_handle = NULL;
       return TRUE;                         /* all done                */

     case ied_ccma_set_size:                /* set new size of cma area */
       /* KTI-230609: set size is only valid, if global lock was set   */
       dss_cma1_co.dsc_critsect_1.m_enter();  /* critical section      */
       adsl_cma1_lock_1 = (dsd_cma1_lock *) (ADSL_CMA_1_G->vpc_lock_chain);

       while (adsl_cma1_lock_1) { /* test for global lock and no share */
         if (adsl_cma1_lock_1->inc_lock_len == 0
              && !(adsl_cma1_lock_1->inc_lock_type & D_CMA_SHARE_READ)
              && !(adsl_cma1_lock_1->inc_lock_type & D_CMA_SHARE_WRITE))
           break;
         adsl_cma1_lock_1 = adsl_cma1_lock_1->adsc_next;
       }
       if (adsl_cma1_lock_1 == NULL) {       /* not properly locked    */
         adsp_cma_1->ac_cma_handle = NULL;
         dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section    */
         m_hlnew_printf( HLOG_XYZ1, "HWSPCMA1015W set size was called without proper locking -%05d-",
               __LINE__ );
         return FALSE;
       }

       if (ADSL_CMA_1_G->inc_size_area == adsp_cma_1->inc_len_cma_area) {
         dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section    */
         return TRUE;
       }
       achl1 = achl2 = NULL;                  /* no storage yet          */
       if (adsp_cma_1->inc_len_cma_area) {
#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &ill_start );
#endif
         achl1 = (char *) malloc( adsp_cma_1->inc_len_cma_area );
#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &ill_end );
       if (dss_cma1_co.ilc_freq) {
         printf( "xs-gw-cma1-02-l%05d-T malloc of cma entry needs \t%lld[ns]\n",
                 __LINE__,
                 (HL_LONGLONG) ((ill_end - ill_start) * 1000000)
                                                                    / dss_cma1_co.ilc_freq );
       }
#endif
         if (achl1 == NULL) {
           //printf( "out of storage\n" );
           m_hlnew_printf( HLOG_XYZ1, "HWSPCMA1001E allocation of %d bytes failed --> out of storage -%05d-",
               adsp_cma_1->inc_len_cma_area, __LINE__ );

           adsp_cma_1->ac_cma_handle = NULL;
           dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section  */
           return FALSE;
         }
       }
       //dss_cma1_co.dsc_critsect_1.m_enter();  /* critical section      */
       if (ADSL_CMA_1_G->inc_size_area != adsp_cma_1->inc_len_cma_area) {
         iml1 = ADSL_CMA_1_G->inc_size_area;
         if (iml1 > adsp_cma_1->inc_len_cma_area) iml1 = adsp_cma_1->inc_len_cma_area;
         achl2 = ADSL_CMA_1_G->achc_area;
         ADSL_CMA_1_G->achc_area = achl1;
         achl1 = NULL;                      /* do not free afterwards  */
         ADSL_CMA_1_G->inc_size_area = adsp_cma_1->inc_len_cma_area;
         if (adsp_cma_1->inc_len_cma_area) {
           if ((achl2) && (iml1)) {
             memcpy( ADSL_CMA_1_G->achc_area, achl2, iml1 );
           }
           if (iml1 < ADSL_CMA_1_G->inc_size_area) {
             memset( ADSL_CMA_1_G->achc_area + iml1, 0,
                     ADSL_CMA_1_G->inc_size_area - iml1 );
           }
         }
         // for testing
//#ifdef TRACEHL1
//         if (ADSL_CMA_1_G->achc_area && (*(ADSL_CMA_1_G->achc_area) == (char)0xcd)) {
//           if (!dss_cma1_co.inc_test)
//             dss_cma1_co.inc_test = 1;
//         }
//#endif
       }
       dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section      */
       if (achl1) free( achl1 );
       if (achl2) free( achl2 );
       adsp_cma_1->achc_cma_area = ADSL_CMA_1_G->achc_area;
       return TRUE;                         /* all done                */
     case ied_ccma_lock_region:             /* set lock on region      */
       if (adsp_cma_1->inc_lock_len == 0) return FALSE;
     case ied_ccma_lock_global:             /* set global lock         */
#ifndef D_SDHREF
       adsp_cma_1->vpc_cma_lock = m_wsp_s_ent_add( vpp_userfld,
         DEF_WSP_TYPE_CMA, sizeof(struct dsd_cma1_lock) );
#endif
#ifdef D_SDHREF
       adsp_cma_1->vpc_cma_lock = malloc( sizeof(struct dsd_cma1_lock) );
       memset( adsp_cma_1->vpc_cma_lock, 0, sizeof(struct dsd_cma1_lock) );
       bol1 = TRUE;                         /* needs to put in chain   */
#endif
#define ADSL_CMA1_LOCK_G ((struct dsd_cma1_lock *) adsp_cma_1->vpc_cma_lock)
#ifdef TRACE_LOCKTIME
   bol_test = QueryPerformanceCounter( (LARGE_INTEGER *) &(ADSL_CMA1_LOCK_G->ilc_start_lock) );
   if (bol_test == FALSE) {                 /* error occured           */
     m_hlnew_printf( HLOG_XYZ1,
                     "xs-gw_cma1-02-l%05d-W QueryPerformanceCounter() Error %d.\n",
                     __LINE__, GetLastError() );
   }
#endif
#ifdef CLUSTER
       ADSL_CMA1_LOCK_G->adsc_cl_lock = 0;  /* has to be initzialized  */
       ADSL_CMA1_LOCK_G->ilc_epoch_ms = 0;  /* has to be initzialized  */
       ADSL_CMA1_LOCK_G->boc_ready = 0;     /* has to be initzialized  */
#endif
       ADSL_CMA1_LOCK_G->vpc_userfld = vpp_userfld;
       //ADSL_CMA1_LOCK_G->adsc_next = 0;     /* terminate chain          */
       ADSL_CMA1_LOCK_G->inc_lock_disp = 0; /* displacement locked area */
       ADSL_CMA1_LOCK_G->inc_lock_len = 0;  /* length of locked area    */
       ADSL_CMA1_LOCK_G->inc_lock_type = adsp_cma_1->imc_lock_type;  /* flags of lock */
       if (adsp_cma_1->iec_ccma_def == ied_ccma_lock_region) {  /* set lock on region */
         ADSL_CMA1_LOCK_G->inc_lock_disp = adsp_cma_1->inc_lock_disp;  /* displacement locked area */
         ADSL_CMA1_LOCK_G->inc_lock_len = adsp_cma_1->inc_lock_len;  /* length of locked area */
       }
#ifdef TRACEHL_CMA_LOCK
       dss_cma1_co.imc_lock_no++;
       ADSL_CMA1_LOCK_G->imc_lock_no = dss_cma1_co.imc_lock_no;
       m_hlnew_printf( HLOG_XYZ1, "xswspcma-l%05d-T new lock %08d vpc_userfld=%p ADSL_CMA_1_G=%p inc_lock_type=%d inc_lock_disp=%08X till %08X",
                       __LINE__,
                       ADSL_CMA1_LOCK_G->imc_lock_no,
                       ADSL_CMA1_LOCK_G->vpc_userfld,
                       ADSL_CMA_1_G,
                       ADSL_CMA1_LOCK_G->inc_lock_type,
                       ADSL_CMA1_LOCK_G->inc_lock_disp,
                       ADSL_CMA1_LOCK_G->inc_lock_disp + ADSL_CMA1_LOCK_G->inc_lock_len );
#endif
       while (TRUE) {                       /* loop to acquire access  */
         dss_cma1_co.dsc_critsect_1.m_enter();  /* critical section    */
#ifdef D_SDHREF
         if (bol1) {                        /* put in chain of locks   */
           ((struct dsd_cma1_lock *) adsp_cma_1->vpc_cma_lock)->adsc_global_next
             = dss_cma1_co.adsc_cma1_lock_anchor;  /* get chain of locks */
           dss_cma1_co.adsc_cma1_lock_anchor = (struct dsd_cma1_lock *) adsp_cma_1->vpc_cma_lock;
           bol1 = FALSE;                    /* is in chain of locks now */
         }
#endif
         adsl_cma1_lock_1 = (struct dsd_cma1_lock *) ADSL_CMA_1_G->vpc_lock_chain;
         //adsl_cma1_lock_2 = NULL;
         while (TRUE) {                     /* loop over all locks     */
           adsl_cma1_lock_2 = adsl_cma1_lock_1;  /* this entry to process */
           if (adsl_cma1_lock_2 == NULL) break;
           adsl_cma1_lock_1 = adsl_cma1_lock_1->adsc_next;  /* get next in chain */
           do {
             /* check if global lock                                   */
             if (ADSL_CMA1_LOCK_G->inc_lock_len == 0) break;
             if (adsl_cma1_lock_2->inc_lock_len == 0) break;
             /* check if area overlaps                                 */
             if (adsl_cma1_lock_2->inc_lock_disp
                   >= (ADSL_CMA1_LOCK_G->inc_lock_disp + ADSL_CMA1_LOCK_G->inc_lock_len)) {
               adsl_cma1_lock_2 = NULL;     /* area does not overlap   */
               break;
             }
             if ((adsl_cma1_lock_2->inc_lock_disp + adsl_cma1_lock_2->inc_lock_len)
                   <= ADSL_CMA1_LOCK_G->inc_lock_disp) {
               adsl_cma1_lock_2 = NULL;     /* area does not overlap   */
               break;
             }
           } while (FALSE);
           if (adsl_cma1_lock_2 == NULL) continue;  /* area does not overlap */
           if (adsl_cma1_lock_2->vpc_userfld != vpp_userfld) {
#ifdef B090226
             vpl_userfld_p = adsl_cma1_lock_2->vpc_userfld;  /* save session */
#endif
             if ((adsl_cma1_lock_2->inc_lock_type & (D_CMA_SHARE_READ | D_CMA_SHARE_WRITE))
                   == 0) break;
             if ((ADSL_CMA1_LOCK_G->inc_lock_type & (D_CMA_SHARE_READ | D_CMA_SHARE_WRITE))
                   == 0) break;
             if (   ((adsl_cma1_lock_2->inc_lock_type & D_CMA_SHARE_WRITE) == 0)
                 && (ADSL_CMA1_LOCK_G->inc_lock_type & (D_CMA_ALL_ACCESS | D_CMA_WRITE_DATA)))
               break;
             if (   ((ADSL_CMA1_LOCK_G->inc_lock_type & D_CMA_SHARE_WRITE) == 0)
                 && (adsl_cma1_lock_2->inc_lock_type & (D_CMA_ALL_ACCESS | D_CMA_WRITE_DATA)))
               break;
             if (   ((adsl_cma1_lock_2->inc_lock_type & D_CMA_SHARE_READ) == 0)
                 && (ADSL_CMA1_LOCK_G->inc_lock_type & (D_CMA_ALL_ACCESS | D_CMA_READ_DATA)))
               break;
             if (   ((ADSL_CMA1_LOCK_G->inc_lock_type & D_CMA_SHARE_READ) == 0)
                 && (adsl_cma1_lock_2->inc_lock_type & (D_CMA_ALL_ACCESS | D_CMA_READ_DATA)))
               break;
           }
         }
         if (adsl_cma1_lock_2 == NULL) {    /* no other lock           */
           ADSL_CMA1_LOCK_G->adsc_next = (struct dsd_cma1_lock *) ADSL_CMA_1_G->vpc_lock_chain;
           ADSL_CMA_1_G->vpc_lock_chain = ADSL_CMA1_LOCK_G;
#ifdef CLUSTER
           /* changed: KT -24.02.10- */
           /* epoch time should be unique for a lock in the chain        */
           /* there may be a problem with a huge number of connections   */
           ADSL_CMA1_LOCK_G->ilc_epoch_ms =  m_get_epoch_ms();  /* get epoch in ms */
           if (ADSL_CMA1_LOCK_G->adsc_next) {
             if (ADSL_CMA1_LOCK_G->ilc_epoch_ms
                     <= ADSL_CMA1_LOCK_G->adsc_next->ilc_epoch_ms)  /* <= because of clock changes (summertime etc.) */
             { /* don't let two locks have the same epoch time */
               ADSL_CMA1_LOCK_G->ilc_epoch_ms
                   = ADSL_CMA1_LOCK_G->adsc_next->ilc_epoch_ms + 1;
             }
           }
#endif
#ifndef D_SDHREF
         } else if (adsp_cma_1->boc_ret_lock_fails == FALSE) {  /* append to chain */
           m_wsp_s_ent_wacha_add( vpp_userfld, DEF_WSP_TYPE_CMA, (char *) ADSL_CMA1_LOCK_G, (char *) adsl_cma1_lock_2 );
#ifdef TRACEHL_CMA_LOCK
           memcpy( &dsl_cma1_lock_save, adsl_cma1_lock_2, sizeof(dsl_cma1_lock_save) );
#endif
#else
         } else {                           /* cannot access - is locked */
           if (adsp_cma_1->boc_ret_lock_fails) {
             /* remove lock from global chain                          */
             adsl_cma1_lock_w3 = dss_cma1_co.adsc_cma1_lock_anchor;  /* get chain of locks */
             adsl_cma1_lock_w4 = NULL;      /* clear last in chain     */
             while (adsl_cma1_lock_w3) {    /* loop over all locks     */
               if (adsl_cma1_lock_w3 == ADSL_CMA1_LOCK_G) break;  /* lock found */
               adsl_cma1_lock_w4 = adsl_cma1_lock_w3;  /* save last in chain */
               adsl_cma1_lock_w3 = adsl_cma1_lock_w3->adsc_global_next;  /* get next in chain */
             }
             if (adsl_cma1_lock_w3) {       /* lock found              */
               if (adsl_cma1_lock_w4 == NULL) {  /* at anchor of chain */
                 dss_cma1_co.adsc_cma1_lock_anchor = adsl_cma1_lock_w3->adsc_global_next;
               } else {                     /* middle in chain         */
                 adsl_cma1_lock_w4->adsc_global_next = adsl_cma1_lock_w3->adsc_global_next;
               }
               free( adsl_cma1_lock_w3 );   /* free memory of lock     */
             } else {                       /* lock not found in chain */
               m_hl2_printf( "xswspcma-l%05d-W cma-lock %p not found in chain - vpp_userfld %p.",
                             __LINE__, ADSL_CMA1_LOCK_G, vpp_userfld );
             }
           }
#endif
         }
#ifdef PROBLEM_090226                       /* KDRS - deadlock - Web-Server hangs */
         if (adsl_cma1_lock_2) {
           vpl_userfld_lock = adsl_cma1_lock_2->vpc_userfld;
         }
#endif
         dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section  */
         if (adsl_cma1_lock_2 == NULL) {    /* no other lock           */
           break;
         }
         if (adsp_cma_1->boc_ret_lock_fails) {
#ifndef D_SDHREF
           m_wsp_s_ent_del( vpp_userfld, DEF_WSP_TYPE_CMA, (char *) ADSL_CMA1_LOCK_G );
#endif
           adsp_cma_1->vpc_cma_lock = NULL;  /* report nothing locked  */
           adsp_cma_1->achc_cma_area = NULL;
#ifndef D_SDHREF
           if (m_wsp_s_ent_get( vpp_userfld, DEF_WSP_TYPE_CMA, NULL )) {
             adsp_cma_1->achc_cma_area = ADSL_CMA_1_G->achc_area;
           }
#endif
           adsp_cma_1->inc_len_cma_area = ADSL_CMA_1_G->inc_size_area;
           return TRUE;
         }
#ifdef TRACEHL_CMA_LOCK
         m_hlnew_printf( HLOG_XYZ1, "xswspcma-l%05d-T wai lock %08d because of lock %08d",
                        __LINE__,
                        ADSL_CMA1_LOCK_G->imc_lock_no,
                        dsl_cma1_lock_save.imc_lock_no );
#endif
#ifdef PROBLEM_090226                       /* KDRS - deadlock - Web-Server hangs */
         dss_cma1_co.imc_count_locks++;     /* count the locks         */
         m_hlnew_printf( HLOG_XYZ1, "xswspcma-l%05d-T before m_wsp_s_wait( %p - %p ) time=%lld adsl_cma1_lock_2->vpc_userfld=%p.",
                         __LINE__, vpp_userfld, adsl_cma1_lock_2, m_get_epoch_ms(), vpl_userfld_lock );
#endif
#ifndef D_SDHREF
#ifdef B090226
         m_wsp_s_wait( vpp_userfld, DEF_WSP_TYPE_CMA,
                       vpl_userfld_p, (char *) adsl_cma1_lock_2 );
#else
         m_wsp_s_wait( vpp_userfld, DEF_WSP_TYPE_CMA, (char *) ADSL_CMA1_LOCK_G );
#endif
#else
#ifdef TRACEHL1
         m_hlnew_printf( HLOG_XYZ1, "xswspcma.cpp m_cma1_proc() sleep vpp_userfld=%p adsp_cma_1=%p.",
                         vpp_userfld, adsp_cma_1 );
#endif
         Sleep( 200 );                      /* wait some time          */
#endif
#ifdef PROBLEM_090226                       /* KDRS - deadlock - Web-Server hangs */
         dss_cma1_co.imc_count_locks--;     /* count the locks         */
         m_hlnew_printf( HLOG_XYZ1, "xswspcma-l%05d-T after  m_wsp_s_wait( %p - %p ) time=%lld adsl_cma1_lock_2->vpc_userfld=%p.",
                         __LINE__, vpp_userfld, adsl_cma1_lock_2, m_get_epoch_ms(), vpl_userfld_lock );
#endif
       }
       /* get pointer to cma area */
       adsp_cma_1->achc_cma_area    = ADSL_CMA_1_G->achc_area;
       adsp_cma_1->inc_len_cma_area = ADSL_CMA_1_G->inc_size_area;
#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &ill_end );
       if (dss_cma1_co.ilc_freq) {
         printf( "xs-gw-cma1-02-l%05d-T lock without cluster needs \t%lld[ns]\n",
                 __LINE__,
                 (HL_LONGLONG) ((ill_end - ADSL_CMA1_LOCK_G->ilc_start_lock) * 1000000)
                                                                    / dss_cma1_co.ilc_freq );
       }
#endif

#ifdef CLUSTER
       if (dss_cma1_co.adsc_cluster_info == NULL)
       {  /* no open cluster connection      */
#endif
         return TRUE;                         /* all done              */
#ifdef CLUSTER
       }

       dss_cma1_co.dsc_critsect_1.m_enter();   /* critical section     */
       if (dss_cma1_co.adsc_clact_upd) {      /* update is in progress */
         if ( dss_cma1_co.adsc_ent_upd){
           if (m_cma1_comp_names(vpp_userfld,
                  (dsd_htree1_avl_entry *) (ADSL_CMA_1_G),
                  (dsd_htree1_avl_entry *) dss_cma1_co.adsc_ent_upd) > 0)
           { /* entry is not yet updated --> don't request external lock */
             dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section  */
             return TRUE;
           }
         }
       }
       dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section    */


       /* prepare message to be sent to the other WSP's */
       /*****************************************************************
          send: - 1 byte length + cma name (as wchar)
                - type global/region
                following numbers NHASN-coded:
                    - epoch in msec
                    - lock-type
                    - displacement of locked area
                    - length of locked area
       *****************************************************************/

       adsl_cluster_s = (struct dsd_cluster_send *)
           malloc( sizeof(dsd_cluster_send) + 2*sizeof(dsd_gather_i_1) );
       achl_cl_send_data
            = (char *) malloc( 20*sizeof(char) );

       /* fill structure */
       adsl_cluster_i = dss_cma1_co.adsc_cluster_info;
       if ( adsl_cluster_i == NULL)
       {  /* no remote wsp found -> error handling ??? */
         free(adsl_cluster_s);
         free(achl_cl_send_data);
         return TRUE;
       }

       adsl_cluster_s->amc_compl   = &m_send_compl1;
       adsl_cluster_s->vpc_userfld = vpp_userfld;
       adsl_cluster_s->iec_cl_type = ied_clty_cma;
       adsl_cluster_s->adsc_gai1_send    /* contains cma name + length */
           = (dsd_gather_i_1 *) (adsl_cluster_s + 1);
       adsl_cluster_s->adsc_gai1_send->achc_ginp_cur
           = (char *) ((ADSL_CMA_1_G) + 1);
       adsl_cluster_s->adsc_gai1_send->achc_ginp_end
           = adsl_cluster_s->adsc_gai1_send->achc_ginp_cur
              + (*adsl_cluster_s->adsc_gai1_send->achc_ginp_cur + 1)
                                                      * sizeof(HL_WCHAR);
       adsl_cluster_s->adsc_gai1_send->adsc_next /* contains lock info */
           = adsl_cluster_s->adsc_gai1_send + 1;
       adsl_cluster_s->adsc_gai1_send->adsc_next->adsc_next = NULL;
       //achl1 = (char *) (adsl_cluster_s->adsc_gai1_send + 2);
       achl1 = achl_cl_send_data;
       achl1 += 20;
       adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_end = achl1;
       /* convert numbers to NHASN from last to first */
       ill_nhasn = ADSL_CMA1_LOCK_G->inc_lock_len;
       achl1 = m_conv_to_nhasn( achl1, ill_nhasn );
       ill_nhasn = ADSL_CMA1_LOCK_G->inc_lock_disp;
       achl1 = m_conv_to_nhasn( achl1, ill_nhasn );
       ill_nhasn = adsp_cma_1->imc_lock_type;
       achl1 = m_conv_to_nhasn( achl1, ill_nhasn );
       /* calculation of epoch time changed: KT -24.02.10- */
       //ill_nhasn = m_get_epoch_ms();  /* get epoch in ms */
       //ADSL_CMA1_LOCK_G->ilc_epoch_ms = ill_nhasn;
       ill_nhasn = ADSL_CMA1_LOCK_G->ilc_epoch_ms;
       ADSL_CMA1_LOCK_G->adsc_cl_lock = NULL;

       /* insert epoch time into message */
       achl1 = m_conv_to_nhasn( achl1, ill_nhasn );
       achl1--;
       //*achl1 = adsp_cma_1->iec_ccma_def;   /* begin of lock info data */
       *achl1 = ied_cma_msg_lock_global;
       if (adsp_cma_1->iec_ccma_def == ied_ccma_lock_region)
         *achl1 = ied_cma_msg_lock_region;

       adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_cur = achl1;
       /* achl1 is later used to restore the achc_ginp_cur pointer     */

       /* check for external locks */
       while ( ADSL_CMA_1_G->adsc_ext_chain != NULL ) {
         struct dsd_cma_ext_lock  *adsl_ext_lock;    /* blocking lock  */
         struct dsd_elem_chain    *adsl_wait_entry;  /* new wait entry */
         struct dsd_elem_chain    *adsl_wait_entry2; /* entry in chain */

         adsl_wait_entry = (dsd_elem_chain *)
                              malloc( sizeof(dsd_elem_chain) );
         dss_cma1_co.dsc_critsect_1.m_enter();  /* critical section    */
         adsl_ext_lock =
           m_check_ext_locks(adsp_cma_1, ADSL_CMA_1_G->adsc_ext_chain);

         if (adsl_ext_lock == NULL) {             /* no lock blocks    */
           dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section  */
           free(adsl_wait_entry);
           break;
         }
         if (adsp_cma_1->boc_ret_lock_fails) {    /* do not wait       */
           dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section  */

           free(adsl_wait_entry);             /* waiting thread entry  */

           /* release new lock */
           adsp_cma_1->iec_ccma_def = ied_ccma_lock_release;
           m_cma1_proc(vpp_userfld, adsp_cma_1);
           adsp_cma_1->vpc_cma_lock = NULL;  /* report nothing locked  */
           adsp_cma_1->achc_cma_area = NULL;
           if (m_wsp_s_ent_get( vpp_userfld, DEF_WSP_TYPE_CMA, NULL )) {
             adsp_cma_1->achc_cma_area = ADSL_CMA_1_G->achc_area;
           }
           adsp_cma_1->inc_len_cma_area = ADSL_CMA_1_G->inc_size_area;
           free(adsl_cluster_s);              /* send to cluster struc.*/
           free(achl_cl_send_data);

           return TRUE;
         }

         /* put wait entry into external lock chain                    */
         adsl_wait_entry->ac_elem = ((struct dsd_aux_cf1 *)
                   vpp_userfld)->adsc_hco_wothr;   /* waiting thread   */
         if ( adsl_ext_lock->adsc_wait_entry == NULL ) {
           adsl_wait_entry->adsc_next = NULL;
           adsl_ext_lock->adsc_wait_entry = adsl_wait_entry;
         }
         else {
           adsl_wait_entry->adsc_next = adsl_ext_lock->adsc_wait_entry;
           adsl_ext_lock->adsc_wait_entry = adsl_wait_entry;
         }
         dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section  */

#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &ill_start );
#endif
         /* wait for release of this external lock (max. WT_CLUSTER sec)       */
         iml_rc = m_hco_wothr_nonblock_wait_sec(((struct dsd_aux_cf1 *)
                                vpp_userfld)->adsc_hco_wothr, WT_CLUSTER);
#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &ill_end );
       if (dss_cma1_co.ilc_freq) {
         printf( "xs-gw-cma1-02-l%05d-T wait for ext. lock needs \t%lld[ns]\n",
                 __LINE__,
                 (HL_LONGLONG) ((ill_end - ill_start) * 1000000)
                                                                    / dss_cma1_co.ilc_freq );
       }
#endif

         if (iml_rc == D_RET_WAIT_TIMEOUT) {   /* timeout   */
           m_hlnew_printf( HLOG_XYZ1,
               "HWSPCMA1002W timeout: waiting for release of external lock -%05d-", __LINE__ );

           /* remove wait entry from chain and free memory, when found */
           dss_cma1_co.dsc_critsect_1.m_enter();  /* critical section  */
           /* fix: KT -24.03.11- calculate adsl_ext_lock again,
             maybe other cluster was closed and memory was freed, while waiting */
           adsl_ext_lock =
             m_check_ext_locks(adsp_cma_1, ADSL_CMA_1_G->adsc_ext_chain);
           if (adsl_ext_lock == NULL) {             /* no lock blocks    */
             dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section  */
             break;
           }
           /* end fix: KT -24.03.11- */

           /* fix: KT -11.12.14- check, if adsl_ext_lock->adsc_wait_entry == 0
              TODO: check logic in update phase, if adsl_ext_lock->adsc_wait_entry == 0
              may be a possible case here */
           if ( adsl_ext_lock->adsc_wait_entry != NULL) {
             if ( adsl_ext_lock->adsc_wait_entry == adsl_wait_entry )
             { /* is first entry */
               adsl_ext_lock->adsc_wait_entry = adsl_wait_entry->adsc_next;
               free( adsl_wait_entry );
             }
             else {
               adsl_wait_entry2 = adsl_ext_lock->adsc_wait_entry;
               while (adsl_wait_entry2->adsc_next) {
                 if (adsl_wait_entry2->adsc_next == adsl_wait_entry) {
                   adsl_wait_entry2->adsc_next->adsc_next
                     = adsl_wait_entry->adsc_next;  /* remove from chain */
                   free( adsl_wait_entry );
                   break;
                 }
                 adsl_wait_entry2 = adsl_wait_entry2->adsc_next;
               }
             }
           }
           dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section  */
           /* end fix: KT -11.12.14- */
         } /* check chain of external locks once again */

       } /* end: while ( ADSL_CMA_1_G->adsc_ext_chain != NULL ) */
       /* count entries in dsd_cluster_info and make a backup   */
       dss_cma1_co.dsc_critsect_1.m_enter();      /* critical section  */
       adsl_cluster_i = dss_cma1_co.adsc_cluster_info;
       iml1 = 0;
       while (adsl_cluster_i) { /* count chain entries */
         iml1++;
         adsl_cluster_i = adsl_cluster_i->adsc_next;
       }

       if ( iml1 == 0 ) {  /* no more entries in cluster info chain */
         dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section  */
         free(adsl_cluster_s);
         free(achl_cl_send_data);
         return TRUE;
       }

       adsl_cluster_i = dss_cma1_co.adsc_cluster_info;
       /* allocate array to backup chain entries */
       adsrl_cluster_i
            = (dsd_cluster_info **) malloc( iml1*sizeof(void *) );
       for (int i=0; i<iml1; i++) {
         adsrl_cluster_i[i] = adsl_cluster_i;
         adsl_cluster_i = adsl_cluster_i->adsc_next;
       }
       dss_cma1_co.dsc_critsect_1.m_leave();      /* critical section  */

       *achl_cl_send_data = 1;  /* first byte is usage counter         */
       /* inizialize to 1 to ensure, that storage isn't freed before
          all send operations are done */
       do {  /* send to all clusters   */
         adsl_cluster_ls
             = (dsd_cl_lock_state *) malloc(sizeof(dsd_cl_lock_state));
         //adsl_cluster_ls->adsc_cluster = adsl_cluster_i->adsc_clact;
         adsl_cluster_ls->inc_state = -1;          /* state: locking    */
         adsl_cluster_ls->inc_sub_state = 0;       /* waiting for resp. */
         //dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section  */
         //adsl_cluster_ls->adsc_next = ADSL_CMA1_LOCK_G->adsc_cl_lock;
         //ADSL_CMA1_LOCK_G->adsc_cl_lock = adsl_cluster_ls;
         //dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section  */

         adsl_cluster_s2 = (struct dsd_cluster_send *)
           malloc( sizeof(dsd_cluster_send) + 2*sizeof(dsd_gather_i_1) );
         memcpy( adsl_cluster_s2, adsl_cluster_s,
                 (sizeof(dsd_cluster_send) + 2*sizeof(dsd_gather_i_1)) );
         /* write correct gather pointers */
         adsl_cluster_s2->adsc_gai1_send
             = (dsd_gather_i_1 *) (adsl_cluster_s2 + 1);
         adsl_cluster_s2->adsc_gai1_send->adsc_next
             = adsl_cluster_s2->adsc_gai1_send + 1;

         dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section  */
         iml1--;  /* index for adsrl_cluster_i, from last to first */
         adsl_cluster_i = dss_cma1_co.adsc_cluster_info;
         while (adsl_cluster_i) {
           if (adsl_cluster_i == adsrl_cluster_i[iml1])
             break;
           adsl_cluster_i = adsl_cluster_i->adsc_next;
         }
         if (adsl_cluster_i == NULL) { /* entry not found */
           /* cleanup memory and continue */
           dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section  */
           free( adsl_cluster_ls );
           free( adsl_cluster_s2 );
           continue;
         }

         adsl_cluster_s2->adsc_clact = adsl_cluster_i->adsc_clact;
         adsl_cluster_ls->adsc_cluster = adsl_cluster_i->adsc_clact;
         /* insert as first entry in adsc_cl_lock-chain */
         adsl_cluster_ls->adsc_next = ADSL_CMA1_LOCK_G->adsc_cl_lock;
         ADSL_CMA1_LOCK_G->adsc_cl_lock = adsl_cluster_ls;
         (*achl_cl_send_data)++; /* increase counter */
         dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section  */

#ifdef TRACE_LOCKTIME
   QueryPerformanceCounter( (LARGE_INTEGER *) &ill_start );
#endif
         if (m_cluster_send(adsl_cluster_s2)) {   /* error - sending   */
           /* remove 'dsd_cl_lock_state' entry */
           dss_cma1_co.dsc_critsect_1.m_enter();  /* critical section  */
           ADSL_CMA1_LOCK_G->adsc_cl_lock
               = ADSL_CMA1_LOCK_G->adsc_cl_lock->adsc_next;
           dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section  */
           free(adsl_cluster_ls);
           //TODO: error message
           m_hlnew_printf( HLOG_XYZ1,
               "HWSPCMA1003I m_cluster_send() failed -%05d-", __LINE__ );
         }
#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &ill_end );
       if (dss_cma1_co.ilc_freq) {
         printf( "xs-gw-cma1-02-l%05d-T m_cluster_send(lock) needs \t%lld[ns]\n",
                 __LINE__,
                 (HL_LONGLONG) ((ill_end - ill_start) * 1000000)
                                                                    / dss_cma1_co.ilc_freq );
       }
#endif

         //adsl_cluster_i = adsl_cluster_i->adsc_next;
       //} while (adsl_cluster_i);
       } while (iml1);

#ifdef TRACE_LOCKTIME
       bol_test = QueryPerformanceCounter( (LARGE_INTEGER *) &ill_start );
       if (bol_test == FALSE) {                 /* error occured           */
          m_hlnew_printf( HLOG_XYZ1,
                     "xs-gw_cma1-02-l%05d-W QueryPerformanceCounter() Error %d.\n",
                     __LINE__, GetLastError() );
       }
#endif
       /* start wait as soon as possible (before freeing memory)       */
       iml_rc = m_hco_wothr_nonblock_wait_sec(((struct dsd_aux_cf1 *)
                              vpp_userfld)->adsc_hco_wothr, WT_CLUSTER);
       //iml1 = ((struct dsd_aux_cf1 *) vpp_userfld)->adsc_hco_wothr->
       //  dsc_event.m_wait_msec( WT_CLUSTER * 1000, &iml2 );  /* event of thread */
#ifdef TRACE_LOCKTIME
       bol_test = QueryPerformanceCounter( (LARGE_INTEGER *) &ill_end );
       if (bol_test == FALSE) {                 /* error occured           */
          m_hlnew_printf( HLOG_XYZ1,
                     "xs-gw_cma1-02-l%05d-W QueryPerformanceCounter() Error %d.\n",
                     __LINE__, GetLastError() );
       }
       if (dss_cma1_co.ilc_freq) {
         printf( "xs-gw-cma1-02-l%05d-T wake up from post needs \t%lld[ns]\n",
                 __LINE__, (HL_LONGLONG) ((ill_end - ADSL_CMA1_LOCK_G->ilc_start_post) * 1000000)
                                                                    / dss_cma1_co.ilc_freq );

         printf( "xs-gw-cma1-02-l%05d-T wait for cluster answer needs \t%lld[ns]\n",
                 __LINE__, (HL_LONGLONG) ((ill_end - ill_start) * 1000000)
                                                                    / dss_cma1_co.ilc_freq );
       }
#endif

       if (iml_rc == D_RET_WAIT_POST) /* no timeout */
       {
         dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section  */
         adsl_cluster_ls = ADSL_CMA1_LOCK_G->adsc_cl_lock;
         while (adsl_cluster_ls) {
           if (adsl_cluster_ls->inc_sub_state != 0) {
             adsl_cluster_ls = adsl_cluster_ls->adsc_next;
             continue;
           }
           break;
         }
         dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section  */
         if (adsl_cluster_ls != NULL) {
           /* at least one cluster has not responded --> wait again */
           iml_rc = m_hco_wothr_nonblock_wait_sec(((struct dsd_aux_cf1 *)
                              vpp_userfld)->adsc_hco_wothr, WT_CLUSTER);
           //iml1 = ((struct dsd_aux_cf1 *) vpp_userfld)->adsc_hco_wothr->
           //  dsc_event.m_wait_msec( WT_CLUSTER * 1000, &iml2 );  /* event of thread */
         }
       }

       dss_cma1_co.dsc_critsect_1.m_enter();      /* critical section  */
       (*achl_cl_send_data)--; /* decrease counter --> can be freed if 0 */
       if (*achl_cl_send_data == 0) /* no longer used   */
         free(achl_cl_send_data);
       dss_cma1_co.dsc_critsect_1.m_leave();      /* critical section  */

       free(adsl_cluster_s);        /* free copy of send structure     */
       free(adsrl_cluster_i);

       if ( ADSL_CMA1_LOCK_G->boc_ready )
       { /* external locks were successful */
         return TRUE;
       }

       /* KT -14.06.16- messages HWSPCMA1004I and HWSPCMA1021I extented by cma name */
       iml_len_name = *((char *) ((ADSL_CMA_1_G) + 1));
       wcrl_cma_name = (HL_WCHAR *) ((ADSL_CMA_1_G) + 1) + 1;

       if (iml_rc == D_RET_WAIT_TIMEOUT) {
         m_hlnew_printf( HLOG_XYZ1,
           "HWSPCMA1004I timeout: waiting for response from other WSP (%.*(u16)s) -%05d-",
           iml_len_name, wcrl_cma_name, __LINE__ );
         //m_hlnew_printf( HLOG_XYZ1,
         //  "HWSPCMA1004I timeout: waiting for response from other WSP -%05d-", __LINE__ );
       }
       else { /* negative response received */
         m_hlnew_printf( HLOG_XYZ1,
           "HWSPCMA1021I lock collision with external lock --> release and try again (%.*(u16)s) -%05d-",
           iml_len_name, wcrl_cma_name, __LINE__ );
         //m_hlnew_printf( HLOG_XYZ1,
         //  "HWSPCMA1021I lock collision with external lock --> release and try again -%05d-", __LINE__ );
       }
       /* KT -14.06.16- end */

       /* if response was negative or timeout, release lock and try once again */
       //ADSL_CMA1_LOCK_G->adsc_cl_lock->inc_state = 1;   /* set waiting is complete */ <--wrong
       iel_ccma_def = adsp_cma_1->iec_ccma_def;
       adsp_cma_1->iec_ccma_def = ied_ccma_lock_release;
       m_cma1_proc(vpp_userfld, adsp_cma_1);
       adsp_cma_1->achc_cma_area = NULL;
       adsp_cma_1->vpc_cma_lock = NULL;
       /* KT -13.04.11- sleep for a random time to avoid periodic collisions             */
#ifndef HL_UNIX
       Sleep((DWORD)(rand()%500));    /* wait up to 0.5 sec */
#else
       usleep( m_get_random_number( 500 * 1000 ) );  /* wait up to 0.5 sec */
#endif

       if (adsp_cma_1->boc_ret_lock_fails) { /* return to caller with unsuccessfull lock */
         return TRUE;
       }

       /* retry locking */
       adsp_cma_1->iec_ccma_def = iel_ccma_def;   /* restore saved value */
       goto p_proc_20;
#endif /* CLUSTER */
#undef ADSL_CMA1_LOCK_G

     case ied_ccma_lock_release:            /* release lock            */
     case ied_ccma_lock_rel_upd:            /* release lock and update */
#define ADSL_CMA1_LOCK_G ((struct dsd_cma1_lock *) adsp_cma_1->vpc_cma_lock)
       if (ADSL_CMA1_LOCK_G == NULL) return FALSE;
#ifdef PROBLEM_090226                       /* KDRS - deadlock - Web-Server hangs */
       if (dss_cma1_co.imc_count_locks) {   /* count the locks         */
         m_hlnew_printf( HLOG_XYZ1, "xswspcma-l%05d-T lock to release vpp_userfld=%p imc_count_locks=%d.",
                         __LINE__, vpp_userfld, dss_cma1_co.imc_count_locks );
       }
#endif
#ifdef TRACEHL_CMA_LOCK
       m_hlnew_printf( HLOG_XYZ1, "xswspcma-l%05d-T rem lock %08d vpp_userfld=%p.",
                       __LINE__,
                       ADSL_CMA1_LOCK_G->imc_lock_no,
                       vpp_userfld );
#endif
       /* check if lock in chain                                       */
#ifndef D_SDHREF
       adsl_cma1_lock_1 = NULL;
       while (TRUE) {
         adsl_cma1_lock_1 = (struct dsd_cma1_lock *) m_wsp_s_ent_get( vpp_userfld,
                                                       DEF_WSP_TYPE_CMA,
                                                       (char *) adsl_cma1_lock_1 );
#ifndef TRACEHL_CMA_LOCK
         if (adsl_cma1_lock_1 == NULL) return FALSE;  /* lock not in chain */
#else
         if (adsl_cma1_lock_1 == NULL) {    /* lock not in chain       */
           m_hlnew_printf( HLOG_XYZ1, "xswspcma-l%05d-T err lock %08d vpp_userfld=%p not in chain",
                           __LINE__,
                           ADSL_CMA1_LOCK_G->imc_lock_no,
                           vpp_userfld );
           return FALSE;
         }
#endif
         if (adsl_cma1_lock_1 == ADSL_CMA1_LOCK_G) break;
       }
#endif
#ifdef D_SDHREF
       adsl_cma1_lock_1 = dss_cma1_co.adsc_cma1_lock_anchor;  /* get chain of locks */
       while (adsl_cma1_lock_1) {           /* loop over all locks     */
         if (adsl_cma1_lock_1 == ADSL_CMA1_LOCK_G) break;  /* lock found */
         adsl_cma1_lock_1 = adsl_cma1_lock_1->adsc_global_next;  /* get next in chain */
       }
       if (adsl_cma1_lock_1 == NULL) return FALSE;  /* lock not in chain */
#endif
       /* lock found */
#ifdef CLUSTER
       /* --> if external locks, send message to other WSP's */
       while (ADSL_CMA1_LOCK_G->adsc_cl_lock) {
         /* test for update removed, because it makes only sense
            when setting locks, not when releasing them                   */
         //dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section  */
         //if (dss_cma1_co.adsc_clact_upd) {  /* update is in progress   */
         //  /* don't send message, if not yet updated */
         //  if ( dss_cma1_co.adsc_ent_upd == NULL ||
         //       m_cma1_comp_names( NULL,
         //              (dsd_htree1_avl_entry *)dss_cma1_co.adsc_ent_upd,
         //              (dsd_htree1_avl_entry *)(ADSL_CMA_1_G) ) <= 0) {
         //    dss_cma1_co.dsc_critsect_1.m_leave(); /* critical section */
         //    break;
         //  }
         //}
         //dss_cma1_co.dsc_critsect_1.m_leave(); /* critical section */

         adsl_cluster_ls = ADSL_CMA1_LOCK_G->adsc_cl_lock;
         /* check, if states are all negative --> other clusters are not locked */
         do {
           if (adsl_cluster_ls->inc_sub_state >= 0)
             break;
           adsl_cluster_ls = adsl_cluster_ls->adsc_next;
         } while (adsl_cluster_ls);
         if (adsl_cluster_ls == NULL)
         { /* all sub states are negative */
           adsl_cluster_ls = ADSL_CMA1_LOCK_G->adsc_cl_lock;
           ADSL_CMA1_LOCK_G->adsc_cl_lock = NULL;
           while (adsl_cluster_ls) { /* free cl_lock_state-chain */
             adsl_cluster_ls2 = adsl_cluster_ls;
             adsl_cluster_ls  = adsl_cluster_ls->adsc_next;
             free (adsl_cluster_ls2);
           }
           break; /* --> no external lock has to be released */
         }

         ADSL_CMA1_LOCK_G->boc_ready = FALSE; /* reinitialize */
         /***************************************************************
            send: - 1 byte length + cma name (as wchar)
                  - type release/rel_upd
                  following numbers NHASN-coded:
                      - epoch in msec
                      //- lock-type (not necessary, removed)
                      only for ied_ccma_lock_rel_upd:
                      - not yet implemented: retention time in sec
                      - displacement of locked area
                      - length of locked area
                      - size of cma
                  - data[length] (if length > 0)
         ***************************************************************/

         /* epoch and active cluster are sufficient to identify a lock
            displacement and length are only necessary for updating    */
         if (adsp_cma_1->iec_ccma_def == ied_ccma_lock_release
             || (ADSL_CMA_1_G->inc_size_area == 0)) {
           adsl_cluster_s = (struct dsd_cluster_send *)
                  malloc( sizeof(dsd_cluster_send)
                          + 2*sizeof(dsd_gather_i_1) );
           achl_cl_send_data = (char *) malloc( 20*sizeof(char) );
           bol_test = FALSE;  /* send no data from cma */
         }
         else {
           adsl_cluster_s = (struct dsd_cluster_send *)
                  malloc( sizeof(dsd_cluster_send)
                          + 3*sizeof(dsd_gather_i_1) );
           achl_cl_send_data = (char *) malloc( 20*sizeof(char)
                                                                );
//                                      + adsl_cma1_lock_1->inc_lock_len );
           bol_test = TRUE;  /* send data from cma */
         }
         //if (adsl_cluster_s == NULL) {
//         if (achl_cl_send_data == NULL) {
//           m_hlnew_printf( HLOG_XYZ1, "HWSPCMA1001E allocation of %d bytes failed --> out of storage -%05d-",
//               (adsl_cma1_lock_1->inc_lock_len + 20), __LINE__ );
//         //for testing
//#ifdef TRACEHL1
//           iml1 /= 0;
//#endif
////#ifndef HL_UNIX
////           ExitProcess( 1 );
////#else
////           exit( 1 );
////#endif
//           adsp_cma_1->ac_cma_handle = NULL;
//           return FALSE;
//         }
         /* fill structure */
         adsl_cluster_s->amc_compl   = &m_send_compl1;
         adsl_cluster_s->vpc_userfld = vpp_userfld;
         adsl_cluster_s->iec_cl_type = ied_clty_cma;
         adsl_cluster_s->adsc_gai1_send  /* contains cma name + length */
             = (dsd_gather_i_1 *) (adsl_cluster_s + 1);
         adsl_cluster_s->adsc_gai1_send->achc_ginp_cur
             = (char *) ((ADSL_CMA_1_G) + 1);       /* name of cma     */
         adsl_cluster_s->adsc_gai1_send->achc_ginp_end
             = adsl_cluster_s->adsc_gai1_send->achc_ginp_cur
               + (*adsl_cluster_s->adsc_gai1_send->achc_ginp_cur + 1)
                                                      * sizeof(HL_WCHAR);
         adsl_cluster_s->adsc_gai1_send->adsc_next /* contains lock info */
             = adsl_cluster_s->adsc_gai1_send + 1;
         if (bol_test) {  /* send data, too */
           adsl_cluster_s->adsc_gai1_send->adsc_next->adsc_next
               = adsl_cluster_s->adsc_gai1_send + 2;
           adsl_cluster_s->adsc_gai1_send->adsc_next->adsc_next->adsc_next
               = NULL;
           //achl1 = (char *) (adsl_cluster_s->adsc_gai1_send + 3);
           achl1 = achl_cl_send_data;
         }
         else {  /* send no data */
           adsl_cluster_s->adsc_gai1_send->adsc_next->adsc_next = NULL;
           //achl1 = (char *) (adsl_cluster_s->adsc_gai1_send + 2);
           achl1 = achl_cl_send_data;
         }
         achl1 += 20;
         adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_end = achl1;
         /* convert numbers to NHASN from last to first */
         if (adsp_cma_1->iec_ccma_def == ied_ccma_lock_rel_upd)
         { /* if ied_ccma_lock_rel_upd     */
           ill_nhasn = ADSL_CMA_1_G->inc_size_area;
           achl1 = m_conv_to_nhasn( achl1, ill_nhasn );
           ill_nhasn = ADSL_CMA1_LOCK_G->inc_lock_len;
           achl1 = m_conv_to_nhasn( achl1, ill_nhasn );
           ill_nhasn = ADSL_CMA1_LOCK_G->inc_lock_disp;
           achl1 = m_conv_to_nhasn( achl1, ill_nhasn );
#ifdef CL_RET_TIME
           ill_nhasn = ADSL_CMA_1_G->imc_retention_time;
           achl1 = m_conv_to_nhasn( achl1, ill_nhasn );
#endif
         }
         /* lock type not necessary for release */
         //ill_nhasn = ADSL_CMA1_LOCK_G->inc_lock_type;
         //achl1 = m_conv_to_nhasn( achl1, ill_nhasn );
         ill_nhasn = ADSL_CMA1_LOCK_G->ilc_epoch_ms;
         achl1 = m_conv_to_nhasn( achl1, ill_nhasn );
         achl1--;
         //*achl1 = adsp_cma_1->iec_ccma_def;   /* begin of lock info data */
         *achl1 = ied_cma_msg_lock_release;
         if (adsp_cma_1->iec_ccma_def == ied_ccma_lock_rel_upd)
           *achl1 = ied_cma_msg_lock_rel_upd;

         adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_cur = achl1;
         if (bol_test) {   /* send locked data to update cma area */
           achl1 = ADSL_CMA_1_G->achc_area + ADSL_CMA1_LOCK_G->inc_lock_disp;
           adsl_cluster_s->adsc_gai1_send->adsc_next->adsc_next->achc_ginp_cur
               = achl1;
           achl1 += ADSL_CMA1_LOCK_G->inc_lock_len;
           if (ADSL_CMA1_LOCK_G->inc_lock_len == 0) {  /* global lock  */
             achl1 += ADSL_CMA_1_G->inc_size_area;
           }
           adsl_cluster_s->adsc_gai1_send->adsc_next->adsc_next->achc_ginp_end
               = achl1;
           achl2 =
               adsl_cluster_s->adsc_gai1_send->adsc_next->adsc_next
                                                         ->achc_ginp_cur;
         }
         adsl_cluster_ls = ADSL_CMA1_LOCK_G->adsc_cl_lock;
         achl1 = adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_cur;

         *achl_cl_send_data = 1;  /* first byte is usage counter       */
         /* inizialize to 1 to ensure, that storage isn't freed before
            all send operations are done */
         do { /* send to all clusters */
           if (adsl_cluster_ls->inc_sub_state == -1)
           { /* negative response means: no external lock was set
                --> no release is necessary                            */
             adsl_cluster_ls->inc_state = 1; /* switch state to release */
             adsl_cluster_ls->inc_sub_state = 1;   /* positive response */
             adsl_cluster_ls = adsl_cluster_ls->adsc_next;
             continue; /* go on with next cluster */
           }
           if (adsl_cluster_ls->inc_sub_state == 0)
           { /* error: lock is still waiting for response */
             //m_hlnew_printf( HLOG_XYZ1,
             //  "HWSPCMA1005I release external lock: response from Cluster INETA=%s was negative -%05d-",
             //                adsl_cluster_ls->adsc_cluster->chrc_ineta, __LINE__ );
             m_hlnew_printf( HLOG_XYZ1,
               "HWSPCMA1005W release external lock: lock is still in waiting state -%05d-",
                             __LINE__ );
           }
           adsl_cluster_ls->inc_state = 1;   /* switch state to release */
           adsl_cluster_ls->inc_sub_state = 0;     /* waiting for resp. */
           if (bol_test) {
             adsl_cluster_s2 = (struct dsd_cluster_send *)
                                malloc( sizeof(dsd_cluster_send)
                                            + 3*sizeof(dsd_gather_i_1) );
             memcpy( adsl_cluster_s2, adsl_cluster_s,
                 (sizeof(dsd_cluster_send) + 3*sizeof(dsd_gather_i_1)) );
             /* write correct gather pointers */
             adsl_cluster_s2->adsc_gai1_send
                 = (dsd_gather_i_1 *) (adsl_cluster_s2 + 1);
             adsl_cluster_s2->adsc_gai1_send->adsc_next
                 = adsl_cluster_s2->adsc_gai1_send + 1;
             adsl_cluster_s2->adsc_gai1_send->adsc_next->adsc_next
                 = adsl_cluster_s2->adsc_gai1_send + 2;
           }
           else {
             adsl_cluster_s2 = (struct dsd_cluster_send *)
                                malloc( sizeof(dsd_cluster_send)
                                            + 2*sizeof(dsd_gather_i_1) );
             memcpy( adsl_cluster_s2, adsl_cluster_s,
                 (sizeof(dsd_cluster_send) + 2*sizeof(dsd_gather_i_1)) );
             /* write correct gather pointers */
             adsl_cluster_s2->adsc_gai1_send
                 = (dsd_gather_i_1 *) (adsl_cluster_s2 + 1);
             adsl_cluster_s2->adsc_gai1_send->adsc_next
                 = adsl_cluster_s2->adsc_gai1_send + 1;
           }

           /* check, if adsl_cluster_ls->adsc_cluster is still valid */
           dss_cma1_co.dsc_critsect_1.m_enter();  /* critical section  */
           adsl_cluster_i = dss_cma1_co.adsc_cluster_info;
           while (adsl_cluster_i) {
             if (adsl_cluster_i->adsc_clact == adsl_cluster_ls->adsc_cluster)
               break;
             adsl_cluster_i = adsl_cluster_i->adsc_next;
           }
           if (adsl_cluster_i == NULL) { /* entry not found */
             /* cleanup memory and continue */
             dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section  */
             m_hlnew_printf( HLOG_XYZ1,
               "HWSPCMA1019I release lock: inactive cluster connection ignored -%05d-",
                             __LINE__ );
             //adsl_cluster_ls2 = adsl_cluster_ls;
             adsl_cluster_ls = adsl_cluster_ls->adsc_next;
             //free(adsl_cluster_ls2);  //free later, after release
             free( adsl_cluster_s2 );
             continue;
           }

           adsl_cluster_s2->adsc_clact = adsl_cluster_ls->adsc_cluster;
           (*achl_cl_send_data)++; /* increase counter */
           dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section  */

#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &ill_start );
#endif
           if (m_cluster_send(adsl_cluster_s2)) {  /* error - sending  */
             //m_hlnew_printf( HLOG_XYZ1,
             // "HWSPCMA1003I m_cluster_send() to Cluster INETA=%s failed -%05d-",
             //              adsl_cluster_s2->adsc_clact->chrc_ineta, __LINE__ );
             m_hlnew_printf( HLOG_XYZ1,
               "HWSPCMA1003I m_cluster_send() failed -%05d-", __LINE__ );
           }
#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &ill_end );
       if (dss_cma1_co.ilc_freq) {
         printf( "xs-gw-cma1-02-l%05d-T m_cluster_send(release) needs \t%lld[ns]\n",
                 __LINE__,
                 (HL_LONGLONG) ((ill_end - ill_start) * 1000000)
                                                                    / dss_cma1_co.ilc_freq );
       }
#endif
           //dss_cma1_co.dsc_critsect_1.m_enter();  /* critical section  */
           adsl_cluster_ls = adsl_cluster_ls->adsc_next;
           //dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section  */
         } while (adsl_cluster_ls);

         /* start wait as soon as possible (before freeing memory)       */
         iml_rc = m_hco_wothr_nonblock_wait_sec(((struct dsd_aux_cf1 *)
                                vpp_userfld)->adsc_hco_wothr, WT_CLUSTER);


#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &ill_end );
       if (dss_cma1_co.ilc_freq) {
         printf( "xs-gw-cma1-02-l%05d-T wake up from post needs \t%lld[ns]\n",
                 __LINE__, (HL_LONGLONG) ((ill_end - ADSL_CMA1_LOCK_G->ilc_start_post) * 1000000)
                                                                    / dss_cma1_co.ilc_freq );
       }
#endif
         /* Sometimes m_hco_wothr_nonblock_wait_sec() returns immediatly
            in this case wait again. changed: KT -14.07.10-            */
         if (iml_rc == D_RET_WAIT_POST)  /* no timeout */
         {
           dss_cma1_co.dsc_critsect_1.m_enter();  /* critical section  */
           adsl_cluster_ls = ADSL_CMA1_LOCK_G->adsc_cl_lock;
           while (adsl_cluster_ls) {
             if (adsl_cluster_ls->inc_sub_state != 0) {
               adsl_cluster_ls = adsl_cluster_ls->adsc_next;
               continue;
             }
             break;
           }
           dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section  */
           if (adsl_cluster_ls != NULL) {
             /* at least one cluster has not responded --> wait again */
             iml_rc = m_hco_wothr_nonblock_wait_sec(((struct dsd_aux_cf1 *)
                              vpp_userfld)->adsc_hco_wothr, WT_CLUSTER);
           }
         }

         dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section  */
         (*achl_cl_send_data)--; /* decrease counter --> can be freed if 0 */
         if (*achl_cl_send_data == 0) /* no longer used   */
           free(achl_cl_send_data);
         dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section  */

         free(adsl_cluster_s);

         adsl_cluster_ls = ADSL_CMA1_LOCK_G->adsc_cl_lock;
         if (ADSL_CMA1_LOCK_G->boc_ready == FALSE) { /* timeout or neg. resp. */
           //if (adsl_cluster_ls && adsl_cluster_ls->inc_sub_state == 0) { /* if timeout */
           //  m_hlnew_printf( HLOG_XYZ1,
           //    "HWSPCMA1002W timeout: waiting for release of external lock -%05d-", __LINE__ );
           //}
            m_hlnew_printf( HLOG_XYZ1,
              "HWSPCMA1020W release lock: timeout or negative response from other cluster -%05d-",
                             __LINE__ );
         }

         ADSL_CMA1_LOCK_G->adsc_cl_lock = NULL;
         while (adsl_cluster_ls) { /* free cl_lock_state-chain */
           adsl_cluster_ls2 = adsl_cluster_ls;
           adsl_cluster_ls  = adsl_cluster_ls->adsc_next;
           free (adsl_cluster_ls2);
         }

         break; /* leave loop */
       }
#endif /* CLUSTER */

       adsl_cma1_lock_2 = NULL;
       dss_cma1_co.dsc_critsect_1.m_enter();  /* critical section      */
       adsl_cma1_lock_1 = (struct dsd_cma1_lock *) ADSL_CMA_1_G->vpc_lock_chain;
       while (adsl_cma1_lock_1) {
         if (adsl_cma1_lock_1 == ADSL_CMA1_LOCK_G) {
           if (adsl_cma1_lock_2 == NULL) {  /* was first in chain      */
             ADSL_CMA_1_G->vpc_lock_chain = adsl_cma1_lock_1->adsc_next;
           } else {                         /* was middle in chain     */
             adsl_cma1_lock_2->adsc_next = adsl_cma1_lock_1->adsc_next;
           }
           break;
         }
         adsl_cma1_lock_2 = adsl_cma1_lock_1;
         adsl_cma1_lock_1 = adsl_cma1_lock_1->adsc_next;
       }
#ifdef D_SDHREF
       /* remove lock from global chain                                */
       adsl_cma1_lock_w3 = dss_cma1_co.adsc_cma1_lock_anchor;  /* get chain of locks */
       adsl_cma1_lock_w4 = NULL;            /* clear last in chain     */
       while (adsl_cma1_lock_w3) {          /* loop over all locks     */
         if (adsl_cma1_lock_w3 == ADSL_CMA1_LOCK_G) break;  /* lock found */
         adsl_cma1_lock_w4 = adsl_cma1_lock_w3;  /* save last in chain */
         adsl_cma1_lock_w3 = adsl_cma1_lock_w3->adsc_global_next;  /* get next in chain */
       }
       if (adsl_cma1_lock_w3) {             /* lock found              */
         if (adsl_cma1_lock_w4 == NULL) {   /* at anchor of chain      */
           dss_cma1_co.adsc_cma1_lock_anchor = adsl_cma1_lock_w3->adsc_global_next;
         } else {                           /* middle in chain         */
           adsl_cma1_lock_w4->adsc_global_next = adsl_cma1_lock_w3->adsc_global_next;
         }
         free( adsl_cma1_lock_w3 );         /* free memory of lock     */
       } else {                             /* lock not found in chain */
         m_hl2_printf( "xswspcma-l%05d-W cma-lock %p not found in chain - vpp_userfld %p.",
                       __LINE__, ADSL_CMA1_LOCK_G, vpp_userfld );
       }
#endif
       dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section      */
#ifdef PROBLEM_090226                       /* KDRS - deadlock - Web-Server hangs */
       if (adsl_cma1_lock_1 == NULL) {
         m_hlnew_printf( HLOG_XYZ1, "xswspcma-l%05d-T lock to release not found vpp_userfld=%p.",
                         __LINE__, vpp_userfld );
       }
#endif
#ifdef TRACEHL_CMA_LOCK
       m_hlnew_printf( HLOG_XYZ1, "xswspcma-l%05d-T re2 lock %08d vpp_userfld=%p adsl_cma1_lock_1=%p.",
                       __LINE__,
                       ADSL_CMA1_LOCK_G->imc_lock_no,
                       vpp_userfld,
                       adsl_cma1_lock_1 );
#endif
       if (adsl_cma1_lock_1 == NULL) return FALSE;
#ifdef CLUSTER
       dss_cma1_co.dsc_critsect_1.m_enter();  /* critical section      */
       if (ADSL_CMA_1_G->adsc_ext_chain)
       { /* check, if external locks are still there */
         if (dss_cma1_co.adsc_clact_upd
             && dss_cma1_co.adsc_ent_upd == ADSL_CMA_1_G) {
           if (ADSL_CMA_1_G->adsc_ext_chain->adsc_wait_entry->ac_elem
             != dss_cma1_co.adsc_thr_upd) { /* new update thread */
             m_hco_wothr_post( NULL, (dsd_hco_wothr *)
                ADSL_CMA_1_G->adsc_ext_chain->adsc_wait_entry->ac_elem );
           }
           else {
             /* set mark for update thread, to show release was correct  */
         /* KT-130114-
            ac_elem == NULL may cause errors, so don't use it anymore */
             //ADSL_CMA_1_G->adsc_ext_chain->adsc_wait_entry->ac_elem = NULL;
             /* wake up update thread */
             m_hco_wothr_post( NULL, dss_cma1_co.adsc_thr_upd );
           }
         }
       }
       dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section    */

#endif /* CLUSTER */

#ifdef TRACE_LOCKTIME
       bol_test = QueryPerformanceCounter( (LARGE_INTEGER *) &ill_end );
       if (bol_test == FALSE) {                 /* error occured           */
          m_hlnew_printf( HLOG_XYZ1,
                     "xs-gw_cma1-02-l%05d-W QueryPerformanceCounter() Error %d.\n",
                     __LINE__, GetLastError() );
       }
       if (dss_cma1_co.ilc_freq) {
         printf( "xs-gw-cma1-02-l%05d-T lock exists for \t%lld[ns]\n",
                 __LINE__,
                 (HL_LONGLONG) ((ill_end - ADSL_CMA1_LOCK_G->ilc_start_lock) * 1000000)
                                                                    / dss_cma1_co.ilc_freq );
       }
#endif

#ifndef D_SDHREF
       m_wsp_s_ent_del( vpp_userfld, DEF_WSP_TYPE_CMA, (char *) ADSL_CMA1_LOCK_G );
#endif
       /* check if still lock; return address of area when locked      */
       adsp_cma_1->achc_cma_area = NULL;
#ifndef D_SDHREF
       if (m_wsp_s_ent_get( vpp_userfld, DEF_WSP_TYPE_CMA, NULL )) {
         adsp_cma_1->achc_cma_area = ADSL_CMA_1_G->achc_area;
       }
#endif
       adsp_cma_1->inc_len_cma_area = ADSL_CMA_1_G->inc_size_area;
       return TRUE;                         /* all done                */
#undef ADSL_CMA1_LOCK_G
     case ied_ccma_retention_set:           /* set retention time      */
	   /* -KT 180717- check, if entry was locked before setting retention time START */
       dss_cma1_co.dsc_critsect_1.m_enter();  /* critical section      */
       adsl_cma1_lock_1 = (dsd_cma1_lock *) (ADSL_CMA_1_G->vpc_lock_chain);
	   if ( adsl_cma1_lock_1 == NULL ||
		    adsl_cma1_lock_1->vpc_userfld != vpp_userfld ) {  /* not properly locked */
#ifdef DELETE_EMPTY_ENTRY
		 if (bol_ref_count_set)
		   ADSL_CMA_1_G->inc_ref_count--;
#endif
         adsp_cma_1->ac_cma_handle = NULL;
         dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section    */
         m_hlnew_printf( HLOG_XYZ1, "HWSPCMA1024W set retention time was called without locking -%05d-",
               __LINE__ );
         return FALSE;
       }
	   /* -KT 180717- END */
       ADSL_CMA_1_G->imc_retention_time = adsp_cma_1->imc_retention_time;
       /* -KT 180717- START */
#ifdef DELETE_EMPTY_ENTRY
	   if (bol_ref_count_set)
		 ADSL_CMA_1_G->inc_ref_count--;
#endif
       dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section    */
	   /* -KT 180717- END */
       return TRUE;                         /* all done                */
     case ied_ccma_retention_get:           /* get retention time      */
       adsp_cma_1->imc_retention_time = ADSL_CMA_1_G->imc_retention_time;
       return TRUE;                         /* all done                */
   }
   return FALSE;
#undef ADSL_CMA_1_G

// p_browse_00:                             /* browse thru entries     */
//   adsl_cma_1_1 = dss_cma1_co.adsc_cma1_ent_anchor;  /* anchor of chain */
//   adsl_cma_1_2 = NULL;                     /* no entry found          */
//   while (adsl_cma_1_1) {                   /* loop over chain         */
//#ifndef HL_UNIX
//     iml1 = _wcsicoll( (WCHAR *) (adsl_cma_1_1 + 1), (WCHAR *) wcrl_cma_name );
//#else
//     iml1 = m_cmpi_u16z_u16z( (HL_WCHAR *) (adsl_cma_1_1 + 1), wcrl_cma_name );
//#endif
//     if (iml1 == 0) {                       /* entries are equal       */
//       if (adsp_cma_1->iec_ccma_def == ied_ccma_browse_entry_gr_eq) {  /* browse entry greater equal */
//         adsl_cma_1_2 = adsl_cma_1_1;       /* set this entry          */
//         break;                             /* end of search           */
//       }
//     } else if (iml1 > 0) {                 /* entries found greater   */
//       if (adsl_cma_1_2) {                  /* entry found before      */
//#ifndef HL_UNIX
//         iml1 = _wcsicoll( (WCHAR *) (adsl_cma_1_1 + 1), (WCHAR *) (adsl_cma_1_2 + 1) );
//#else
//         iml1 = m_cmpi_u16z_u16z( (HL_WCHAR *) (adsl_cma_1_1 + 1), (HL_WCHAR *) (adsl_cma_1_2 + 1) );
//#endif
//         if (iml1 < 0) {                    /* new entries found less  */
//           adsl_cma_1_2 = adsl_cma_1_1;     /* save this entry         */
//         }
//       } else {
//         adsl_cma_1_2 = adsl_cma_1_1;       /* save this entry         */
//       }
//     }
//     adsl_cma_1_1 = adsl_cma_1_1->adsc_next;  /* get next in chain     */
//   }
   //if (adsl_cma_1_2) {                      /* entry found             */
   //  iml1 = adsp_cma_1->imc_mem_cma_browse_name;  /* length cma browse name area in bytes */
   //  if (iml1 <= 0) return FALSE;
   //  switch (adsp_cma_1->iec_chs_browse_name) {  /* character set      */
   //    case ied_chs_utf_16:                 /* Unicode UTF-16 = WCHAR  */
   //    case ied_chs_be_utf_16:              /* Unicode UTF-16 big endian */
   //    case ied_chs_le_utf_16:              /* Unicode UTF-16 little endian */
   //      iml1 /= sizeof(HL_WCHAR);
   //      break;
   //    case ied_chs_utf_32:                 /* Unicode UTF-32          */
   //    case ied_chs_be_utf_32:              /* Unicode UTF-32 big endian */
   //    case ied_chs_le_utf_32:              /* Unicode UTF-32 little endian */
   //      iml1 /= sizeof(unsigned int);
   //      break;
   //  }
   //  adsp_cma_1->imc_len_cma_browse_name
   //    = m_cpy_vx_vx( adsp_cma_1->ac_cma_browse_name,  /* result cma browse name */
   //                   iml1, adsp_cma_1->iec_chs_browse_name,  /* character set */
   //                   adsl_cma_1_2 + 1, -1, ied_chs_utf_16 );
   //} else {                                 /* no entry found          */
   //  adsp_cma_1->imc_len_cma_browse_name = 0;  /* clear length cma brwose name in elements */
   //}
   adsp_cma_1->ac_cma_handle = NULL;        /* do not return handle of entry */
   return TRUE;                             /* all done                */
} /* end m_cma1_proc()                                                 */

/**
 * m_cma1_statistics() returns statistics about the common memory area
 *
 * @param *ainp_count   was filled with the number of cma entries
 * @param *ailp_length  was filled with the summed up length from all entries
 */
extern "C" void m_cma1_statistics( int *ainp_count, HL_LONGLONG *ailp_length ) {
   struct dsd_cma1_ent *adsl_cma_1_w1;      /* working variable        */
   struct dsd_htree1_avl_work dsl_avl_work; /* working var. for avl    */

   *ainp_count = 0;                         /* clear number entries    */
   *ailp_length = 0;                        /* clear sum length entries */
   //adsl_cma_1_w1 = dss_cma1_co.adsc_cma1_ent_anchor;  /* anchor of chain */
   //while (adsl_cma_1_w1) {                   /* loop over chain         */
   //  (*ainp_count)++;                       /* increment number entries */
   //  *ailp_length += adsl_cma_1_w1->inc_size_area;  /* add to sum length entries */
   //  adsl_cma_1_w1 = adsl_cma_1_w1->adsc_next;  /* get next in chain     */
   //}
   dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section        */
   if (!m_htree1_avl_getnext( NULL, &dss_cma1_co.dsc_avl_cntl,
                              &dsl_avl_work, TRUE )) {
     dss_cma1_co.dsc_critsect_1.m_leave();
     return;
   }

   while (dsl_avl_work.adsc_found) {
// 23.01.15 KB - possible bug, use offsetof()
     adsl_cma_1_w1 = (dsd_cma1_ent *)dsl_avl_work.adsc_found;
     (*ainp_count)++;                       /* increment number entries */
     *ailp_length += adsl_cma_1_w1->inc_size_area;  /* add to sum length entries */
     if (!m_htree1_avl_getnext( NULL, &dss_cma1_co.dsc_avl_cntl,
                                &dsl_avl_work, FALSE )) {
       *ainp_count = 0;
       *ailp_length = 0;
       dss_cma1_co.dsc_critsect_1.m_leave();
       return;
     }
   }
   dss_cma1_co.dsc_critsect_1.m_leave();
} /* end m_cma1_statistics()                                           */

/**
 * m_cma1_free_old_e() frees entries where the retention time has elapsed.
 */
extern "C" void m_cma1_free_old_e( void ) {
   time_t     dsl_time_1;                   /* for time                */
   struct dsd_cma1_ent *adsl_cma_1_w1;      /* working variable        */
   struct dsd_htree1_avl_work dsl_avl_work; /* working var. for avl    */
   //struct dsd_cma1_ent *adsl_cma_1_cur;     /* current entry           */
   //struct dsd_cma1_ent *adsl_cma_1_prev;    /* previous entry          */

   time( &dsl_time_1 );                     /* get current time        */
   //adsl_cma_1_prev = NULL;                  /* no previous entry       */
   dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section        */
   if (!m_htree1_avl_getnext( NULL, &dss_cma1_co.dsc_avl_cntl,
                              &dsl_avl_work, TRUE )) {
     dss_cma1_co.dsc_critsect_1.m_leave();
     return;
   }
   //adsl_cma_1_cur = dss_cma1_co.adsc_cma1_ent_anchor;  /* anchor of chain */
   while (TRUE) {                           /* loop over chain         */
     //if (adsl_cma_1_cur == NULL) break;     /* end of chain reached    */
     //adsl_cma_1_w1 = adsl_cma_1_cur;        /* save current entry      */
     //adsl_cma_1_cur = adsl_cma_1_cur->adsc_next;  /* get next in chain */
     //if (   (adsl_cma_1_w1->imc_retention_time == 0)
     //    || ((adsl_cma_1_w1->ilc_epoch_last_used + adsl_cma_1_w1->imc_retention_time)
     //          > dsl_time_1)) {
     //  adsl_cma_1_prev = adsl_cma_1_w1;     /* set previous entry      */
     //  continue;                            /* end of this entry       */
     //}
     ///* entry will be removed                                          */
     //if (adsl_cma_1_prev == NULL) {         /* beginning of chain      */
     //  dss_cma1_co.adsc_cma1_ent_anchor = adsl_cma_1_cur;
     //} else {                               /* middle of chain         */
     //  adsl_cma_1_prev->adsc_next = adsl_cma_1_cur;
     //}
     //free( adsl_cma_1_w1 );                 /* free memory             */
     if (dsl_avl_work.adsc_found == NULL)
       break;
     adsl_cma_1_w1 = (dsd_cma1_ent *)dsl_avl_work.adsc_found;
     if ( (adsl_cma_1_w1->imc_retention_time)
         && ((adsl_cma_1_w1->ilc_epoch_last_used + adsl_cma_1_w1->imc_retention_time)
               <= dsl_time_1)) {
       if (adsl_cma_1_w1->vpc_lock_chain || adsl_cma_1_w1->adsc_ext_chain)
       {
         //TODO: display cma name in message
         //WCHAR *awcl_name;
         //int iml_len;

         //awcl_name  = (HL_WCHAR *)(adsl_cma_1_w1 + 1);
         //iml_len = (int) *((unsigned char *)awcl_name); /* 1st byte */

         m_hlnew_printf( HLOG_XYZ1,
            "HWSPCMA1017W lock still exists after retention time expired -%05d-",
            __LINE__ );
       }
       if (!m_htree1_avl_delete( NULL, &dss_cma1_co.dsc_avl_cntl,
                                 &dsl_avl_work )) {
         dss_cma1_co.dsc_critsect_1.m_leave();
         return;
       }
       if ( adsl_cma_1_w1->achc_area )
         free (adsl_cma_1_w1->achc_area);
       free( adsl_cma_1_w1 );
     }
     if (!m_htree1_avl_getnext( NULL, &dss_cma1_co.dsc_avl_cntl,
                                &dsl_avl_work, FALSE)) {
       dss_cma1_co.dsc_critsect_1.m_leave();
       return;
     }
   }
   dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section        */
} /* end m_cma1_free_old_e()                                           */

/* compare avl entries */
static int m_cma1_comp_names( void *vpp_user_fld,
                              struct dsd_htree1_avl_entry *adsp_avl_e1,
                              struct dsd_htree1_avl_entry *adsp_avl_e2 )
{  /* 1.sort: length, 2.sort: alphabetical                             */
   int      iml_len;                        /* length to compare       */
   int      iml_cmp;                        /* result of compare       */
   HL_WCHAR *awcl_name1;                    /* name of cma entry1      */
   HL_WCHAR *awcl_name2;                    /* name of cma entry2      */
   struct dsd_cma1_ent *adsl_cma_e1;        /* structure cma entry1    */
   struct dsd_cma1_ent *adsl_cma_e2;        /* structure cma entry2    */

   adsl_cma_e1 = (struct dsd_cma1_ent *) adsp_avl_e1;
   adsl_cma_e2 = (struct dsd_cma1_ent *) adsp_avl_e2;
   awcl_name1  = (HL_WCHAR *)(adsl_cma_e1 + 1);
   awcl_name2  = (HL_WCHAR *)(adsl_cma_e2 + 1);

   iml_len = (int) *((unsigned char *)awcl_name1); /* 1st byte */
   iml_cmp = iml_len - *((unsigned char *)awcl_name2);
   if (iml_cmp != 0)
     return iml_cmp;

   awcl_name1++;
   awcl_name2++;
   while (iml_len) {
     iml_cmp = (int) (*awcl_name1 - *awcl_name2);
     if (iml_cmp)
       return iml_cmp;
     /* next sign */
     iml_len--;
     awcl_name1++;
     awcl_name2++;
   }

   return 0;
} /* end m_cma1_comp_names()                                           */

static inline int m_get_browse_name( struct dsd_hl_aux_c_cma_1 *adsp_cma,
                                    int imp_mem_size,
                                    struct dsd_cma1_ent *adsp_cma_entry )
{
   char *achl_name;
   int  iml1;

   achl_name = (char *)(adsp_cma_entry + 1);
   iml1 = (int)(*achl_name);        /* get length */
   achl_name += sizeof(HL_WCHAR);   /* start of name */

   switch (adsp_cma->iec_chs_browse_name) {      /* character set      */
     case ied_chs_utf_16:                   /* Unicode UTF-16 = WCHAR  */
     case ied_chs_be_utf_16:              /* Unicode UTF-16 big endian */
     case ied_chs_le_utf_16:              /* Unicode UTF-16 little endian */
       imp_mem_size /= sizeof(HL_WCHAR);
       break;
     case ied_chs_utf_32:                 /* Unicode UTF-32          */
     case ied_chs_be_utf_32:              /* Unicode UTF-32 big endian */
     case ied_chs_le_utf_32:              /* Unicode UTF-32 little endian */
       imp_mem_size /= sizeof(unsigned int);
       break;
   }
   return m_cpy_vx_vx( adsp_cma->ac_cma_browse_name,  /* result cma browse name */
                       imp_mem_size,
                       adsp_cma->iec_chs_browse_name,  /* character set */
                       achl_name, iml1, ied_chs_utf_16 );
}

#ifdef CLUSTER
static dsd_cma_ext_lock* m_check_ext_locks( dsd_hl_aux_c_cma_1 *adsp_cma,
                                       dsd_cma_ext_lock *adsp_ext_chain )
{
   struct dsd_cma_ext_lock    *adsl_ext_entry;

   while (TRUE) {                            /* loop over all locks    */
     adsl_ext_entry = adsp_ext_chain;        /* this entry to process  */
     if (adsl_ext_entry == NULL) break;
     adsp_ext_chain = adsp_ext_chain->adsc_next;  /* get next in chain */
     do {
       /* check if global lock                                         */
       if (adsp_cma->inc_lock_len == 0) break;
       if (adsl_ext_entry->inc_lock_len == 0) break;

       /* check if area overlaps                                       */
       if (adsl_ext_entry->inc_lock_disp
            >= (adsp_cma->inc_lock_disp + adsp_cma->inc_lock_len)) {
         adsl_ext_entry = NULL;             /* area does not overlap   */
         break;
       }
       if ((adsl_ext_entry->inc_lock_disp + adsl_ext_entry->inc_lock_len)
             <= adsp_cma->inc_lock_disp) {
         adsl_ext_entry = NULL;             /* area does not overlap   */
         break;
       }
     } while (FALSE);
     if (adsl_ext_entry == NULL) continue;  /* area does not overlap   */

     /* check type of lock */
     if ((adsl_ext_entry->inc_lock_type & (D_CMA_SHARE_READ | D_CMA_SHARE_WRITE))
           == 0) break;
     if ((adsp_cma->imc_lock_type & (D_CMA_SHARE_READ | D_CMA_SHARE_WRITE))
           == 0) break;
     if ( ((adsl_ext_entry->inc_lock_type & D_CMA_SHARE_WRITE) == 0)
          && (adsp_cma->imc_lock_type & (D_CMA_ALL_ACCESS | D_CMA_WRITE_DATA)))
       break;
     if ( ((adsp_cma->imc_lock_type & D_CMA_SHARE_WRITE) == 0)
          && (adsl_ext_entry->inc_lock_type & (D_CMA_ALL_ACCESS | D_CMA_WRITE_DATA)))
       break;
     if ( ((adsl_ext_entry->inc_lock_type & D_CMA_SHARE_READ) == 0)
          && (adsp_cma->imc_lock_type & (D_CMA_ALL_ACCESS | D_CMA_READ_DATA)))
       break;
     if ( ((adsp_cma->imc_lock_type & D_CMA_SHARE_READ) == 0)
          && (adsl_ext_entry->inc_lock_type & (D_CMA_ALL_ACCESS | D_CMA_READ_DATA)))
       break;
   }

   return adsl_ext_entry;   /* return external lock, that blocks the local one */
}

static void m_send_compl1( struct dsd_cluster_send *adsp_cluster_s )
{
   char *achl_cl_send_data;
   /* decrease usage counter */
   achl_cl_send_data      /* first byte in send data := usage counter  */
       = adsp_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_end - 20;
   dss_cma1_co.dsc_critsect_1.m_enter();      /* critical section      */
   (*achl_cl_send_data)--;
   if (*achl_cl_send_data == 0) {
     dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section      */
     free(achl_cl_send_data);
   }
   else {
     dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section      */
   }

   free(adsp_cluster_s);

   return;
}

static void m_send_compl2( struct dsd_cluster_send *adsp_cluster_s )
{
   free(adsp_cluster_s);

   return;
}

/**
 * m_cma1_cluster_open() was called, when an other WSP from the cluster
 * connects to this WSP. It checks, if the cma of this WSP should be updated
 * from the other WSP.
 *
 * @param adsp_clact  structure, containing information about the other WSP
 */
extern "C" void m_cma1_cluster_open( struct dsd_cluster_active *adsp_clact ) {
   struct dsd_cluster_info *adsl_cl_info;    /* new cluster_info entry */
   //struct dsd_cluster_info *adsl_cl_info2;   /* old cluster_info entry */
   //struct dsd_cluster_send *adsl_cluster_s;
   struct dsd_call_para_1 dsl_call_para_1;     /* parameters for work thread */
   //int  iml_result;

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xswspcma-%05d-T m_cma1_cluster_open() entered", __LINE__ );
#endif
#ifdef TRACE_170913
   m_hlnew_printf( HLOG_XYZ1, "xswspcma-%05d-T m_cma1_cluster_open():adsp_clact=%p", __LINE__, adsp_clact );
#endif
   //adsp_clact->vpc_cma_entry = &dss_cma1_co;
   adsl_cl_info = (dsd_cluster_info *) malloc(sizeof(dsd_cluster_info));
   memset(adsl_cl_info, 0, sizeof(dsd_cluster_info));
   adsl_cl_info->adsc_clact = adsp_clact;
   adsp_clact->vpc_cma_entry = &dss_cma1_co;

   dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section        */
   if ( dss_cma1_co.adsc_cluster_info == 0) {  /* is first remote WSP  */
     adsl_cl_info->adsc_next = 0;              /* insert into chain    */
     dss_cma1_co.adsc_cluster_info = adsl_cl_info;
   }
   else {
     /* insert as first element */
     adsl_cl_info->adsc_next = dss_cma1_co.adsc_cluster_info;
     dss_cma1_co.adsc_cluster_info = adsl_cl_info;
   }
   dss_cma1_co.dsc_critsect_1.m_leave();

   /* check, if remote WSP is older */
   if (dsg_this_server.ilc_epoch_started > adsp_clact->ilc_epoch_started)
   { /* check if there is already an update thread */
     dss_cma1_co.dsc_critsect_1.m_enter();
     if (dss_cma1_co.adsc_clact_upd)
     { /* check, if that WSP is younger */
       if (dss_cma1_co.adsc_clact_upd->ilc_epoch_started
                                         > adsp_clact->ilc_epoch_started)
       { /* stop current update thread */
         dss_cma1_co.adsc_clact_upd = NULL;
         if (dss_cma1_co.adsc_thr_upd) {
           m_hco_wothr_post( NULL, dss_cma1_co.adsc_thr_upd );
           dss_cma1_co.adsc_thr_upd = NULL;
         }
       }
       else {
         dss_cma1_co.dsc_critsect_1.m_leave();
         return;  /* current update works with the older WSP */
       }
     }
     dss_cma1_co.adsc_clact_upd = adsp_clact;
     dss_cma1_co.dsc_critsect_1.m_leave();

     /* start new work thread to do update of cma */
     memset( &dsl_call_para_1, 0, sizeof(struct dsd_call_para_1) );
     dsl_call_para_1.amc_function = &m_proc_cma_update;
     dsl_call_para_1.ac_param_1 = adsp_clact;  /* WSP for update */
     m_hco_run_thread( &dsl_call_para_1 );
     return;
   }
   return;
} /* end m_cma1_cluster_open()                                         */

/* connection to other cluster member is closed                        */
/**
 * m_cma1_cluster_close() was called, when the connection of an other WSP
 * from the cluster ends. Saved information about that WSP was freed.
 *
 * @param adsp_clact  information to identify the other WSP
 */
extern "C" void m_cma1_cluster_close( struct dsd_cluster_active *adsp_clact )
{
  struct dsd_cluster_info *adsl_clinfo;
  struct dsd_cluster_info *adsl_clinfo2;

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xswspcma-%05d-T m_cma1_cluster_close() entered", __LINE__ );
#endif
#ifdef TRACE_170913
   m_hlnew_printf( HLOG_XYZ1, "xswspcma-%05d-T m_cma1_cluster_close():adsp_clact=%p", __LINE__, adsp_clact );
#endif
   dss_cma1_co.dsc_critsect_1.m_enter();          /* critical section  */
   adsl_clinfo = dss_cma1_co.adsc_cluster_info;
   if (adsl_clinfo == NULL) {
     /* no entries there: error handling */
     m_hlnew_printf( HLOG_XYZ1,
       "HWSPCMA1014W m_cma1_cluster_close was called for missing entry -%05d-", __LINE__ );
     dss_cma1_co.dsc_critsect_1.m_leave();        /* critical section  */
     adsp_clact->vpc_cma_entry = NULL;
     return;
   }
   if (adsl_clinfo->adsc_clact == adsp_clact) {  /* is first entry */
   if (adsl_clinfo->boc_update) { /* if update request was started */
     m_notify_cma_sync_passive_stop();  /* notify, that request is no longer valid */
     adsl_clinfo->boc_update = FALSE;
   }
     dss_cma1_co.adsc_cluster_info = adsl_clinfo->adsc_next;
     dss_cma1_co.dsc_critsect_1.m_leave();        /* critical section  */

     /* remove external locks */
   /* KT-130114- following line may cause a synchronization problem with m_cma1_cluster_recv():
      m_cleanup_lock_chain(adsl_clinfo->adsc_active_locks);
    access to adsl_clinfo->adsc_active_locks should be inside a critical section,
    therefore the argument of m_cleanup_lock_chain() should be only adsl_clinfo */
     m_cleanup_lock_chain(adsl_clinfo);
     free(adsl_clinfo);
     adsp_clact->vpc_cma_entry = NULL;
     return;
   }

   while (adsl_clinfo->adsc_next) { /* is not first entry */
     if (adsl_clinfo->adsc_next->adsc_clact == adsp_clact)
       break;
     adsl_clinfo = adsl_clinfo->adsc_next;
   }
   adsl_clinfo2 = adsl_clinfo->adsc_next;
   if (adsl_clinfo2 == NULL) {
     /* entry not found: error handling */
     m_hlnew_printf( HLOG_XYZ1,
       "HWSPCMA1014W m_cma1_cluster_close was called for missing entry -%05d-", __LINE__ );

     dss_cma1_co.dsc_critsect_1.m_leave();        /* critical section  */
     adsp_clact->vpc_cma_entry = NULL;
     return;
   }

   if (adsl_clinfo2->boc_update) { /* if update request was started */
   m_notify_cma_sync_passive_stop();  /* notify, that request is no longer valid */
   adsl_clinfo2->boc_update = FALSE;
   }
   adsl_clinfo->adsc_next = adsl_clinfo2->adsc_next;
   dss_cma1_co.dsc_critsect_1.m_leave();          /* critical section  */
   /* remove external locks and wake up waiting threads */
   /* m_cleanup_lock_chain(adsl_clinfo2->adsc_active_locks); */
   m_cleanup_lock_chain(adsl_clinfo2);
   free(adsl_clinfo2);
   adsp_clact->vpc_cma_entry = NULL;
   return;
} /* end m_cma1_cluster_close()                                        */

/* a logical block was reveived from other cluster member              */
/**
 * m_cma1_cluster_recv() was called, when a message from an other WSP of
 * the cluster has been recieved, that effects the cma.
 * m_cluster_proc_recv_done() has to be called, after the message
 * was processed.
 *
 * @param adsp_clprr  structure, containing information about the other WSP,
 *                    and a pointer to the recieved message.
 */
extern "C" void m_cma1_cluster_recv( struct dsd_cluster_proc_recv *adsp_clprr ) {
   struct dsd_avl_dummy  *adsl_dummy_entry;  /* dummy for avl search     */
   struct dsd_avl_dummy  dsl_dummy_split;    /* if message is split      */
   struct dsd_htree1_avl_work dsl_avl_work;  /* working struct. for avl  */
   struct dsd_cma1_ent     *adsl_cma_ent;    /* cma entry                */
   struct dsd_cma_ext_lock *adsl_lock_ext;   /* external lock entry      */
   struct dsd_cma_ext_lock *adsl_lock_ext2;  /* external lock entry      */
   struct dsd_cluster_info *adsl_clinfo;     /* info about active cluster*/
   struct dsd_cluster_send *adsl_cluster_s;  /* send to cluster struct.  */
   struct dsd_gather_i_1 *adsl_gather;       /* temp. gather structure   */
   HL_LONGLONG  ill_epoch_ms;                /* epoch of cluster message */
#ifdef TRACE_LOCKTIME
   HL_LONGLONG  ill_start;
   HL_LONGLONG  ill_end;
#endif
   time_t dsl_time1;                         /* for retention time       */
   BOOL   bol1;
   ied_cma_msg iel_cma_msg;                  /* type of message received */
   char   *achl_curr;                        /* save gather start        */
   char   *achl_end;                         /* save gather end          */
   char   *achl1;                            /* for temporary use        */
   char   *achl2;
   int    iml_length;
   int    iml1;

//#ifdef TRACEHL1
//   m_hlnew_printf( HLOG_XYZ1, "xswspcma-%05d-T m_cma1_cluster_recv() entered", __LINE__ );
//#endif
   adsl_gather = adsp_clprr->adsc_gai1_data;
   achl_curr   = adsl_gather->achc_ginp_cur;
   //iml_length  = (unsigned char) *achl_curr;
   iml_length  = *achl_curr;

   if (iml_length < 0) {   /* message for starting or ending update    */
     switch (iml_length) {
       case -1: /* send back first tree element */
#ifdef TRACE_170913
         m_hlnew_printf( HLOG_XYZ1, "xswspcma-%05d-T m_cma1_cluster_recv():adsp_clprr->adsc_clact=%p",
                                                                    __LINE__, adsp_clprr->adsc_clact );
#endif
         dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section  */
         /* get information about active cluster */
         adsl_clinfo = dss_cma1_co.adsc_cluster_info;
         while (adsl_clinfo
                 && adsl_clinfo->adsc_clact != adsp_clprr->adsc_clact) {
           adsl_clinfo = adsl_clinfo->adsc_next;
         }
         if (adsl_clinfo == NULL)
         { /* active cluster not in chain -> fatal error */
           //TODO: error handling
           dss_cma1_co.dsc_critsect_1.m_leave();   /* critical section */
           m_hlnew_printf( HLOG_XYZ1,
            "HWSPCMA1011W cluster message belongs to an invalid cluster connection -%05d-", __LINE__ );

           m_cluster_proc_recv_done(adsp_clprr);
           return;
     }
     adsl_clinfo->boc_update = TRUE;
     m_notify_cma_sync_passive_start();

     /* get first element from avl tree */
         m_htree1_avl_getnext( NULL, &dss_cma1_co.dsc_avl_cntl, &dsl_avl_work, TRUE );
         dss_cma1_co.dsc_critsect_1.m_leave();
         /* send response to requesting wsp */
         if (m_send_cma_entry( dsl_avl_work.adsc_found,
                                ied_cma_msg_upd_lock,
                                adsp_clprr->adsc_clact )) {
           //m_hlnew_printf( HLOG_XYZ1,
           //   "HWSPCMA1003I m_cluster_send() to Cluster INETA=%s failed -%05d-",
           //                adsp_clprr->adsc_clact->chrc_ineta, __LINE__ );
           m_hlnew_printf( HLOG_XYZ1,
               "HWSPCMA1003I m_cluster_send() failed -%05d-", __LINE__ );
         }

         m_cluster_proc_recv_done(adsp_clprr);
         return;
       case -2:  /* no more elements for update -> wake up update thread */
         dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section    */
         if (dss_cma1_co.adsc_clact_upd == adsp_clprr->adsc_clact) {
           dss_cma1_co.adsc_ent_upd = NULL;
           dss_cma1_co.inc_upd_length = 0;
           if (dss_cma1_co.adsc_thr_upd)        /* check, if still running */
             m_hco_wothr_post( NULL, dss_cma1_co.adsc_thr_upd );
         }
         dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section    */
         /* else, ignore update message */

         m_cluster_proc_recv_done(adsp_clprr);
         return;
   case -3: /* update request from other cma has completed */
         dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section  */
     /* get information about active cluster */
         adsl_clinfo = dss_cma1_co.adsc_cluster_info;
         while (adsl_clinfo
                 && adsl_clinfo->adsc_clact != adsp_clprr->adsc_clact) {
           adsl_clinfo = adsl_clinfo->adsc_next;
         }
         if (adsl_clinfo == NULL)
         { /* active cluster not in chain -> fatal error */
           //TODO: error handling
           dss_cma1_co.dsc_critsect_1.m_leave();   /* critical section */
           m_hlnew_printf( HLOG_XYZ1,
            "HWSPCMA1011W cluster message belongs to an invalid cluster connection -%05d-", __LINE__ );

           m_cluster_proc_recv_done(adsp_clprr);
           return;
     }
     adsl_clinfo->boc_update = FALSE;  /* reset update flag */
     m_notify_cma_sync_passive_stop();

         dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section    */
         m_cluster_proc_recv_done(adsp_clprr);
         return;
     }
   }

   /* in all other cases the message has the following format:
      - 1st byte: length of cma name
      - cma name in utf16
      - 1 byte message type
      - nhasn coded epoch time
      - more data depending on message type
   */
#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &ill_start );
#endif
   /* get cma name out of the cluster message and look for it locally  */
   adsl_dummy_entry = (dsd_avl_dummy *)
                    (achl_curr - offsetof(dsd_avl_dummy, wcrc_cma_name));
   achl_curr += (iml_length+1)*sizeof(HL_WCHAR);   /* after cma name   */
   if (adsl_gather->achc_ginp_end < achl_curr )
   { /* message is not in one part --> copy together  */
     adsl_dummy_entry = &dsl_dummy_split;   /* need copy of cma name   */
     achl_curr = (char *) adsl_dummy_entry->wcrc_cma_name;
     achl_end  = achl_curr + (iml_length+1)*sizeof(HL_WCHAR);
     while (TRUE) {
       iml1 = adsl_gather->achc_ginp_end - adsl_gather->achc_ginp_cur;
       if ( (achl_curr + iml1) > achl_end )
         break;
       memcpy(achl_curr, adsl_gather->achc_ginp_cur, iml1);
       achl_curr += iml1;
       adsl_gather = adsl_gather->adsc_next;
     }
     iml1 = achl_end - achl_curr;
     memcpy(achl_curr, adsl_gather->achc_ginp_cur, iml1);

     /* set achl_curr to current pointer in gather stucture            */
     achl_curr = adsl_gather->achc_ginp_cur + iml1;
   }
   adsl_gather->achc_ginp_cur = achl_curr;

   /* look for cma name     */
   time( &dsl_time1 );    /* get current epoch time */
   dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section        */
   bol1 = m_htree1_avl_search( NULL, &dss_cma1_co.dsc_avl_cntl,
            &dsl_avl_work, &adsl_dummy_entry->dsc_cma_dummy.dsc_htree1 );
   if (bol1 == FALSE) {
     dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section        */
     m_cluster_proc_recv_done(adsp_clprr);
     return;
   }

   adsl_cma_ent = (struct dsd_cma1_ent *) dsl_avl_work.adsc_found;
   if (adsl_cma_ent != NULL) {
     /* -KT 260613- update ilc_epoch_last_used inside critical section
        to prevent problems with expiring retention time                 */
     adsl_cma_ent->ilc_epoch_last_used = dsl_time1;
     dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section        */
   }
   //if (dsl_avl_work.adsc_found == NULL) {  /* not found --> create new */
   else {   /* not found --> create new */
     dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section        */

     adsl_cma_ent
         = (struct dsd_cma1_ent *) malloc( sizeof(struct dsd_cma1_ent)
                                   + (iml_length + 1)*sizeof(HL_WCHAR) );
     memset( adsl_cma_ent, 0, sizeof(struct dsd_cma1_ent) );
     memcpy( adsl_cma_ent + 1, adsl_dummy_entry->wcrc_cma_name,
                                     (iml_length + 1)*sizeof(HL_WCHAR) );
     dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section      */
     bol1 = m_htree1_avl_search( NULL, &dss_cma1_co.dsc_avl_cntl,
                              &dsl_avl_work, &adsl_cma_ent->dsc_htree1 );
     if (bol1 == FALSE) {  /* error in search */
       dss_cma1_co.dsc_critsect_1.m_leave();
       /* this case only is possible, if TREECHECK was set in xsavl03  */
       free( adsl_cma_ent );                  /* free new entry        */
       m_cluster_proc_recv_done(adsp_clprr);
       return;
     }
     if (dsl_avl_work.adsc_found == NULL) {   /* no other entry found  */
       bol1 = m_htree1_avl_insert( NULL, &dss_cma1_co.dsc_avl_cntl,
                              &dsl_avl_work, &adsl_cma_ent->dsc_htree1 );
       /* -KT 260613- update ilc_epoch_last_used inside critical section
          to prevent problems with expired retention time              */
       adsl_cma_ent->ilc_epoch_last_used = dsl_time1;
       dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section      */
       if (bol1 == FALSE) {                   /* error in insert       */
         //TODO: error message
         m_cluster_proc_recv_done(adsp_clprr);
         return;
       }
     }
     else {  /* entry found now */
       /* -KT 260613- update ilc_epoch_last_used inside critical section
          to prevent problems with expired retention time							 */
       ((struct dsd_cma1_ent *) dsl_avl_work.adsc_found)
                                       ->ilc_epoch_last_used	= dsl_time1;
       dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section      */
       free( adsl_cma_ent );                  /* free new entry        */
       adsl_cma_ent = (struct dsd_cma1_ent *) dsl_avl_work.adsc_found;
     }
   }
   iel_cma_msg = (ied_cma_msg) *adsl_gather->achc_ginp_cur++;

   /* get epoch in ms */
   ill_epoch_ms = m_conv_from_nhasn(adsl_gather);
#ifdef TRACEHL1
   if (ill_epoch_ms < 0) {
     m_hlnew_printf( HLOG_XYZ1, "xswspcma-%05d-T negative epoch time send", __LINE__ );
   }
#endif
   /* go to next unprocessed gather structure                          */
   while (adsl_gather &&
          (adsl_gather->achc_ginp_cur == adsl_gather->achc_ginp_end))
     adsl_gather = adsl_gather->adsc_next;

   /* -KT 260613- changed: ilc_epoch_last_used should be updated already
      after searching an entry in the tree just inside critical section
      to prevent problems with expired retention time                     */
   ///* update epoch last used */
   //time( &dsl_time1 );
   //adsl_cma_ent->ilc_epoch_last_used = dsl_time1;
#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &ill_end );

       if (dss_cma1_co.ilc_freq) {
         printf( "xs-gw-cma1-02-l%05d-T looking for cma entry needs \t%lld[ns]\n",
                 __LINE__,
                 (HL_LONGLONG) ((ill_end - ill_start) * 1000000)
                                                                    / dss_cma1_co.ilc_freq );
       }
#endif

   switch (iel_cma_msg) {         /* type of message                   */
     struct dsd_elem_chain *adsl_wait_ent1;     /* waiting threads     */
     struct dsd_elem_chain *adsl_wait_ent2;     /* waiting threads     */
     struct dsd_cma1_lock  *adsl_lock;
     struct dsd_cl_lock_state *adsl_cl_lock;
     struct dsd_double_chain *adsl_lock_el; /* lock chain from dsd_cluster_info */
     struct dsd_hco_wothr  *adsl_cur_thr;   /* thread to be posted     */
     int  inl_lock_type;                /* flags of lock               */
     int  inl_lock_disp;                /* displacement locked area    */
     int  inl_lock_len;                 /* length of locked area       */
     int  inl_cma_size;                 /* size of cma                 */
#ifdef CL_RET_TIME
     int  inl_ret_time;                 /* retention time              */
#endif

     case ied_cma_msg_resp:         /* used for response to a message    */
       /* update 'pending lock' chain */
       dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section  */
       adsl_lock = ((dsd_cma1_lock *) adsl_cma_ent->vpc_lock_chain);
#ifdef TRACEHL2
       //awcl_name = (HL_WCHAR *) (adsl_cma_ent+1);
       //inl_size_name = *((char) awcl_name);
       //awcl_name++; /* first byte is length */
       printf( "xs-gw-cma1-02i response msg received %lld\n",
           ill_epoch_ms );
#endif

       while (adsl_lock && (adsl_lock->ilc_epoch_ms != ill_epoch_ms)) {
         adsl_lock = adsl_lock->adsc_next;
       }
       if (adsl_lock == NULL) { /* error: entry not found */
         dss_cma1_co.dsc_critsect_1.m_leave(); /* critical section */
         m_hlnew_printf( HLOG_XYZ1,
           //"HWSPCMA1006W response msg received for not existing lock -%05d-", __LINE__ );
           "HWSPCMA1006W response msg received for not existing lock, type:%d/%d -%05d-",
            *(adsl_gather->achc_ginp_cur), *(adsl_gather->achc_ginp_cur+1), __LINE__ );
         m_cluster_proc_recv_done(adsp_clprr);

         return;
       }
#ifdef TRACEHL1
       if (adsl_lock->adsc_next &&
           (adsl_lock->ilc_epoch_ms == adsl_lock->adsc_next->ilc_epoch_ms))
       {
         printf("xs-gw-cma1-02 -%d- error: two locks with equal time\n", __LINE__);
       }
#endif

       adsl_cl_lock = adsl_lock->adsc_cl_lock;
       adsl_lock->boc_ready = TRUE;
       while (adsl_cl_lock) {
         if ( adsp_clprr->adsc_clact == adsl_cl_lock->adsc_cluster ) {
           /* check response byte */
           if (*(adsl_gather->achc_ginp_cur) > 0)
             adsl_cl_lock->inc_sub_state = 1;    /* positive response  */
           else {
             adsl_cl_lock->inc_sub_state = -1;   /* negative response  */
             adsl_lock->boc_ready = FALSE;
             break;             /* wake up thread with neg. response   */
           }
         }
         else if (adsl_cl_lock->inc_sub_state <= 0) {
           adsl_lock->boc_ready = FALSE;
         }
         adsl_cl_lock = adsl_cl_lock->adsc_next;
       }

       /* wake up waiting thread */
       if (adsl_lock->boc_ready || adsl_cl_lock) {
         dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section  */
#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &adsl_lock->ilc_start_post );
#endif
         m_hco_wothr_post( NULL,
              ((dsd_aux_cf1 *) adsl_lock->vpc_userfld)->adsc_hco_wothr );
       }
       else
         dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section  */

       m_cluster_proc_recv_done(adsp_clprr);

       return;

     case ied_cma_msg_upd_lock:            /* lock entry for update    */
       dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section    */
       if ( dss_cma1_co.adsc_thr_upd == NULL
            || dss_cma1_co.adsc_clact_upd != adsp_clprr->adsc_clact ) {
         //TODO: error-handling
         m_hlnew_printf( HLOG_XYZ1,
           "HWSPCMA1007I update thread for received update message is no longer active -%05d-", __LINE__ );
         dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section  */
         m_cluster_proc_recv_done(adsp_clprr);
         return;
       }
       dss_cma1_co.adsc_ent_upd = adsl_cma_ent;
       dss_cma1_co.inc_upd_length = (int) m_conv_from_nhasn(adsl_gather);

       /* post update thread */
       m_hco_wothr_post( NULL, dss_cma1_co.adsc_thr_upd );
       dss_cma1_co.dsc_critsect_1.m_leave();      /* critical section  */

       m_cluster_proc_recv_done(adsp_clprr);
       return;

     case ied_cma_msg_upd_data:             /* receive data for update  */
       /* prevent from changes in external lock chain by critical section */
       dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section  */
       if (adsl_cma_ent->adsc_ext_chain
           && adsl_cma_ent->adsc_ext_chain->adsc_wait_entry)
       {
         /* save wait entries */
         adsl_wait_ent1 = adsl_cma_ent->adsc_ext_chain->adsc_wait_entry;
         adsl_wait_ent2 = adsl_wait_ent1;
         /* oldest (last) entry in wait chain is update thread */
         while (adsl_wait_ent2->adsc_next) {
           adsl_wait_ent2 = adsl_wait_ent2->adsc_next;
         }
         adsl_cur_thr = (dsd_hco_wothr *) adsl_wait_ent2->ac_elem;

         if ( adsl_cur_thr != dss_cma1_co.adsc_thr_upd
              || adsp_clprr->adsc_clact != dss_cma1_co.adsc_clact_upd )
         { /* update thread is no longer valid */
           /* free external lock chain (only 1 entry in update phase)  */
           free(adsl_cma_ent->adsc_ext_chain);
           adsl_cma_ent->adsc_ext_chain = NULL;
           dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section  */
           m_hlnew_printf( HLOG_XYZ1,
             "HWSPCMA1007I update thread for received update message is no longer active -%05d-", __LINE__ );

           /* post to local thread waiting for external lock */
           while (adsl_wait_ent1->adsc_next) {
             //m_hco_wothr_post(NULL, ((struct dsd_aux_cf1 *)
             //                adsl_wait_ent1->ac_elem)->adsc_hco_wothr);
             m_hco_wothr_post(NULL, (struct dsd_hco_wothr *)
                                                adsl_wait_ent1->ac_elem);

             adsl_wait_ent2 = adsl_wait_ent1;
             adsl_wait_ent1 = adsl_wait_ent1->adsc_next;
             free(adsl_wait_ent2);
           }
           free(adsl_wait_ent1);
           m_cluster_proc_recv_done(adsp_clprr);
           return;
         }
       }
       else { /* no thread is waiting for this cma entry, ignore data */
         //TODO: error handling
         if (adsl_cma_ent->adsc_ext_chain) {
           free(adsl_cma_ent->adsc_ext_chain);
           adsl_cma_ent->adsc_ext_chain = NULL;
         }
         dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section  */
         m_hlnew_printf( HLOG_XYZ1,
           "HWSPCMA1008W unexpected update data recieved -%05d-", __LINE__ );
         m_cluster_proc_recv_done(adsp_clprr);
         return;
       }

#ifdef CL_RET_TIME
       /* get retention time and insert it                             */
       adsl_cma_ent->imc_retention_time
           = (int) m_conv_from_nhasn(adsl_gather);
#endif

       /* get cma size - still inside critical section */
       inl_cma_size = (int) m_conv_from_nhasn(adsl_gather);
       achl_curr = adsl_cma_ent->achc_area;
       if (inl_cma_size == 0) {
         if (adsl_cma_ent->achc_area != NULL)
           free (adsl_cma_ent->achc_area);
         adsl_cma_ent->inc_size_area = 0;
         adsl_cma_ent->achc_area = NULL;
       }

       /* insert data into cma, then call m_cluster_proc_recv_done()   */
       else {
         if (adsl_cma_ent->inc_size_area != inl_cma_size)
         { /* different size --> allocate new memory */
           achl_curr = (char *) malloc(inl_cma_size*sizeof(char));

           if (adsl_cma_ent->achc_area != NULL) {
             free (adsl_cma_ent->achc_area);
           }

           //dss_cma1_co.dsc_critsect_1.m_enter(); /* critical section */
           adsl_cma_ent->achc_area = achl_curr;
           adsl_cma_ent->inc_size_area = inl_cma_size;
           //dss_cma1_co.dsc_critsect_1.m_leave(); /* critical section */
         }
         /* copy data from message to cma */
         while (inl_cma_size) {
           /* test for gather structures without data */
           while (adsl_gather->achc_ginp_cur == adsl_gather->achc_ginp_end)
             adsl_gather = adsl_gather->adsc_next;

           *achl_curr = *(adsl_gather->achc_ginp_cur);
           achl_curr++;
           adsl_gather->achc_ginp_cur++;
           //if (adsl_gather->achc_ginp_cur == adsl_gather->achc_ginp_end)
           //  adsl_gather = adsl_gather->adsc_next;
           inl_cma_size--;
         }

         // for testing
//#ifdef TRACEHL1
//         if (adsl_cma_ent && (*(adsl_cma_ent->achc_area) == (char)0xcd)) {
//           if (!dss_cma1_co.inc_test)
//             dss_cma1_co.inc_test = 2;
//         }
//#endif
       }

       /* free external lock chain (only 1 entry in update phase)      */
       free(adsl_cma_ent->adsc_ext_chain);
       adsl_cma_ent->adsc_ext_chain = NULL;
       dss_cma1_co.inc_upd_length = 0;      /* for timeout detection   */
       dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section    */

       /* post to local thread waiting for external lock */
       while (adsl_wait_ent1->adsc_next) {
         //m_hco_wothr_post(NULL, ((struct dsd_aux_cf1 *)
         //                    adsl_wait_ent1->ac_elem)->adsc_hco_wothr);
         m_hco_wothr_post(NULL, (struct dsd_hco_wothr *)
                                                adsl_wait_ent1->ac_elem);

         adsl_wait_ent2 = adsl_wait_ent1;
         adsl_wait_ent1 = adsl_wait_ent1->adsc_next;
         free(adsl_wait_ent2);
       }
       free(adsl_wait_ent1);

       /* post to update thread */
       dss_cma1_co.dsc_critsect_1.m_enter();      /* critical section  */
       if (adsl_cur_thr == dss_cma1_co.adsc_thr_upd)
         m_hco_wothr_post(NULL, adsl_cur_thr);
       dss_cma1_co.dsc_critsect_1.m_leave();      /* critical section  */

       break;
     case ied_cma_msg_upd_req_l:        /* request for update (lock)   */
       dsl_avl_work.adsc_found = (dsd_htree1_avl_entry *) adsl_cma_ent;
       dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section    */
       m_htree1_avl_getnext( NULL, &dss_cma1_co.dsc_avl_cntl,
                             &dsl_avl_work, FALSE );
       dss_cma1_co.dsc_critsect_1.m_leave();
       if (m_send_cma_entry( dsl_avl_work.adsc_found,
                              ied_cma_msg_upd_lock,
                              adsp_clprr->adsc_clact )) {
         //TODO:error handling
         //m_hlnew_printf( HLOG_XYZ1,
         //   "HWSPCMA1003I m_cluster_send() to Cluster INETA=%s failed -%05d-",
         //                  adsp_clprr->adsc_clact->chrc_ineta, __LINE__ );
         m_hlnew_printf( HLOG_XYZ1,
               "HWSPCMA1003I m_cluster_send() failed -%05d-", __LINE__ );
       }
       break;
     case ied_cma_msg_upd_req_d:        /* request for update (data)   */
       dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section    */
       if (m_send_cma_entry( adsl_cma_ent, ied_cma_msg_upd_data,
                              adsp_clprr->adsc_clact )) {
         //TODO:error handling
         //m_hlnew_printf( HLOG_XYZ1,
         //   "HWSPCMA1003I m_cluster_send() to Cluster INETA=%s failed -%05d-",
         //                  adsp_clprr->adsc_clact->chrc_ineta, __LINE__ );
         m_hlnew_printf( HLOG_XYZ1,
               "HWSPCMA1003I m_cluster_send() failed -%05d-", __LINE__ );
       }
       dss_cma1_co.dsc_critsect_1.m_leave();
       break;
     case ied_cma_msg_lock_global: /* get a lock on the whole cma       */
     case ied_cma_msg_lock_region: /* get a lock of a region of the cma */
#ifdef TRACEHL2
       //awcl_name = (HL_WCHAR *) (adsl_cma_ent+1);
       //awcl_name++; /* first byte is length */

       printf( "xs-gw-cma1-02i lock request received: start %lld\n",
           ill_epoch_ms );
#endif
#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &ill_start );
#endif

       /* get lock type */
       inl_lock_type = (int) m_conv_from_nhasn(adsl_gather);
       if (inl_lock_type < 0) {
         //TODO: error handling
         m_hlnew_printf( HLOG_XYZ1,
            "HWSPCMA1009W invalid lock type -%05d-", __LINE__ );
       }
       while (adsl_gather->achc_ginp_cur == adsl_gather->achc_ginp_end)
         adsl_gather = adsl_gather->adsc_next;
       /* get lock displacement */
       inl_lock_disp = (int) m_conv_from_nhasn(adsl_gather);
       while (adsl_gather->achc_ginp_cur == adsl_gather->achc_ginp_end)
         adsl_gather = adsl_gather->adsc_next;
       /* get lock length */
       inl_lock_len = (int) m_conv_from_nhasn(adsl_gather);

       /* prepare entry for 'external lock' chain' */
       adsl_lock_ext
           = (dsd_cma_ext_lock *) malloc(sizeof(dsd_cma_ext_lock));
       //if (adsl_lock_ext == NULL) {
       //  //TODO: error out of memory
       //}
       /* fill 'external lock' structure */
       adsl_lock_ext->adsc_wait_entry = 0;
       adsl_lock_ext->ac_clact = adsp_clprr->adsc_clact;
       adsl_lock_ext->ilc_epoch_ms  = ill_epoch_ms;
       adsl_lock_ext->inc_lock_type = inl_lock_type;
       adsl_lock_ext->inc_lock_disp = inl_lock_disp;
       adsl_lock_ext->inc_lock_len  = inl_lock_len;

       /* prepare response message: lock successful                    */
       /* made before locking, to keep time in critical section short  */
       adsl_cluster_s = (struct dsd_cluster_send *)
                  malloc( sizeof(dsd_cluster_send)
                          + 2*sizeof(dsd_gather_i_1) + 20*sizeof(char) );
       adsl_cluster_s->adsc_clact  = adsp_clprr->adsc_clact;
       adsl_cluster_s->amc_compl   = &m_send_compl2;
       //adsl_cluster_s->vpc_userfld = NULL;
       adsl_cluster_s->iec_cl_type = ied_clty_cma;
       adsl_cluster_s->adsc_gai1_send    /* contains cma name + length */
           = (dsd_gather_i_1 *) (adsl_cluster_s + 1);
       adsl_cluster_s->adsc_gai1_send->achc_ginp_cur
           = (char *) ((adsl_cma_ent) + 1);
       adsl_cluster_s->adsc_gai1_send->achc_ginp_end
           = adsl_cluster_s->adsc_gai1_send->achc_ginp_cur
             + (*adsl_cluster_s->adsc_gai1_send->achc_ginp_cur + 1)
                                                      * sizeof(HL_WCHAR);
       adsl_cluster_s->adsc_gai1_send->adsc_next /* contains lock info */
           = adsl_cluster_s->adsc_gai1_send + 1;
       adsl_cluster_s->adsc_gai1_send->adsc_next->adsc_next = NULL;
       achl_curr = (char *) (adsl_cluster_s->adsc_gai1_send + 2);
       achl_curr += 20;
       adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_end = achl_curr;

       /*****************************************************************
          send: - '00' = ied_cma_msg_response
                - epoch in ms
                - '01':positive, 'FF':negative
                - '01':lock ( added for debugging 23.04.10 )
       *****************************************************************/

       /* convert numbers to NHASN from last to first */
       achl_curr--;
       *achl_curr = 1;      /* response to lock (23.04.10) */
       achl_curr--;
       *achl_curr = 1;      /* positive response  */
       achl_curr = m_conv_to_nhasn( achl_curr, ill_epoch_ms );
       achl_curr--;
       *achl_curr = 0;      /* ied_cma_msg == ied_cma_msg_resp   */
       adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_cur = achl_curr;

       /* get position of flag for positive/negative response */
       achl_curr =
            //adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_end - 1;
            adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_end - 2;  //(23.04.10)

       dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section    */
       /* check, if conflict with update */
       if (dss_cma1_co.adsc_ent_upd == adsl_cma_ent) {
         adsl_lock_ext2 = adsl_cma_ent->adsc_ext_chain;
         if (adsl_lock_ext2 && adsl_lock_ext2->adsc_wait_entry)
         {
           adsl_wait_ent1 = adsl_lock_ext2->adsc_wait_entry;
           /* if the last entry of the wait chain is the update thread,
              send back a negative response to the caller              */
           while (adsl_wait_ent1->adsc_next)
             adsl_wait_ent1 = adsl_wait_ent1->adsc_next;
           if (dss_cma1_co.adsc_thr_upd == adsl_wait_ent1->ac_elem)
           {
             *achl_curr = -1;     /* set to negative response          */
             dss_cma1_co.dsc_critsect_1.m_leave(); /* critical section */
             free(adsl_lock_ext); /* not needed */
             if (m_cluster_send(adsl_cluster_s))
             {    /* error - sending   */
               // TODO: error handling, remote WSP not open
               m_hlnew_printf( HLOG_XYZ1,
                 "HWSPCMA1003I m_cluster_send() failed -%05d-", __LINE__ );
             }
             m_cluster_proc_recv_done(adsp_clprr);
             return;
           }
         }
       }

       adsl_lock = (dsd_cma1_lock *) adsl_cma_ent->vpc_lock_chain;
       if (adsl_lock != NULL) { /* other locks in chain */
         do {
           //if (adsl_lock->boc_ready) {  /* this lock was already verified */
           //  adsl_lock = adsl_lock->adsc_next;
           //  continue;
           //}
           /* lock conflict now was solved by fingerprint KT -18.04.11- */
           //if (adsl_lock->ilc_epoch_ms <= ill_epoch_ms || adsl_lock->boc_ready) {
           if (memcmp(adsp_clprr->adsc_clact->chrc_fingerprint,
               dsg_this_server.chrc_fingerprint, DEF_LEN_FINGERPRINT) >= 0
                || adsl_lock->boc_ready) {
             /* check for lock conflict   */
             if (!(adsl_lock->inc_lock_len == 0 || inl_lock_len == 0)) {
               /* check if areas do not overlap                        */
               if (adsl_lock->inc_lock_disp >= (inl_lock_disp + inl_lock_len)
                   || (adsl_lock->inc_lock_disp + adsl_lock->inc_lock_len)
                     <= inl_lock_disp) {
                 adsl_lock = adsl_lock->adsc_next;
                 continue;   /* areas don't overlap  */
               }
             }
             /* check if lock types conflict   */
             *achl_curr = -1;    /* preset to negative resp.    */
             /* response is negative, if one of these is true   */
             if ((adsl_lock->inc_lock_type
                & (D_CMA_SHARE_READ | D_CMA_SHARE_WRITE)) == 0)
               break;
             if ((inl_lock_type & (D_CMA_SHARE_READ | D_CMA_SHARE_WRITE)) == 0)
               break;
             if (((adsl_lock->inc_lock_type & D_CMA_SHARE_WRITE) == 0)
                && (inl_lock_type & (D_CMA_ALL_ACCESS | D_CMA_WRITE_DATA)))
               break;
             if (((inl_lock_type & D_CMA_SHARE_WRITE) == 0)
                && (adsl_lock->inc_lock_type & (D_CMA_ALL_ACCESS | D_CMA_WRITE_DATA)))
               break;
             if (((adsl_lock->inc_lock_type & D_CMA_SHARE_READ) == 0)
                && (inl_lock_type & (D_CMA_ALL_ACCESS | D_CMA_READ_DATA)))
               break;
             if (((inl_lock_type & D_CMA_SHARE_READ) == 0)
                && (adsl_lock->inc_lock_type & (D_CMA_ALL_ACCESS | D_CMA_READ_DATA)))
               break;

             *achl_curr = 1; /* reset to positive */
           }
           adsl_lock = adsl_lock->adsc_next;
         } while (adsl_lock);
       }
       /* insert lock, if positive result */
       if (*achl_curr > 0) {
         adsl_clinfo = dss_cma1_co.adsc_cluster_info;
         while (adsl_clinfo
                 && adsl_clinfo->adsc_clact != adsp_clprr->adsc_clact) {
           adsl_clinfo = adsl_clinfo->adsc_next;
         }
         if (adsl_clinfo == NULL)
         { /* active cluster not in chain -> fatal error */
           //TODO: error handling
           dss_cma1_co.dsc_critsect_1.m_leave();   /* critical section */
           m_hlnew_printf( HLOG_XYZ1,
            "HWSPCMA1011W cluster message belongs to an invalid cluster connection -%05d-", __LINE__ );
           free(adsl_lock_ext);
           free(adsl_cluster_s);

           m_cluster_proc_recv_done(adsp_clprr);
           return;
         }
         adsl_lock_ext->adsc_next = adsl_cma_ent->adsc_ext_chain;
         adsl_lock_ext->adsc_entry = adsl_cma_ent; /* set back reference */
         adsl_cma_ent->adsc_ext_chain = adsl_lock_ext;
         /* insert external lock into active locks chain of adsl_clinfo  */
         /* used for releasing locks, if remote WSP is no more reachable */
         adsl_lock_el
             = (dsd_double_chain *) malloc(sizeof(dsd_double_chain));
         adsl_lock_el->ac_d_elem = adsl_lock_ext;
         adsl_lock_el->adsc_pred = NULL;     /* first in chain */
         adsl_lock_el->adsc_succ = adsl_clinfo->adsc_active_locks;
         if (adsl_clinfo->adsc_active_locks)
           adsl_clinfo->adsc_active_locks->adsc_pred = adsl_lock_el;
         adsl_clinfo->adsc_active_locks = adsl_lock_el;
         /* make entry in external lock structure, to speed up
            removing this entry after a normal release                 */
         adsl_lock_ext->adsc_remote_chain = adsl_lock_el;
         dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section  */
       }
       else { /* negative response */
         dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section  */
         free(adsl_lock_ext); /* not needed */
       }
#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &ill_end );

       if (dss_cma1_co.ilc_freq) {
         printf( "xs-gw-cma1-02-l%05d-T setting ext. lock and prepare response needs \t%lld[ns]\n",
                 __LINE__,
                 (HL_LONGLONG) ((ill_end - ill_start) * 1000000)
                                                                    / dss_cma1_co.ilc_freq );
       }
#endif
#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &ill_end );

       if (dss_cma1_co.ilc_freq) {
         printf( "xs-gw-cma1-02-l%05d-T same+printf needs \t%lld[ns]\n",
                 __LINE__,
                 (HL_LONGLONG) ((ill_end - ill_start) * 1000000)
                                                                    / dss_cma1_co.ilc_freq );
       }
#endif

#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &ill_start );
#endif
       if (m_cluster_send(adsl_cluster_s))
       {    /* error - sending   */
         // TODO: error handling, remote WSP not open
         m_hlnew_printf( HLOG_XYZ1,
               "HWSPCMA1003I m_cluster_send() failed -%05d-", __LINE__ );
       }
#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &ill_end );
       if (dss_cma1_co.ilc_freq) {
         printf( "xs-gw-cma1-02-l%05d-T m_cluster_send(resp.-lock) needs \t%lld[ns]\n",
                 __LINE__,
                 (HL_LONGLONG) ((ill_end - ill_start) * 1000000)
                                                                    / dss_cma1_co.ilc_freq );
       }
#endif
       m_cluster_proc_recv_done(adsp_clprr);
#ifdef TRACEHL2
         printf( "xs-gw-cma1-02i lock request received: end %lld\n",
           ill_epoch_ms );
#endif

       return;
     case ied_cma_msg_lock_release:         /* release lock            */
     case ied_cma_msg_lock_rel_upd:         /* release lock and update */
       ///* get lock type --> not necessary for release, lock was found by epoch time */
       //inl_lock_type = (int) m_conv_from_nhasn(adsl_gather);
       //if (inl_lock_type < 0) {
       //  //TODO: error handling
       //  m_hlnew_printf( HLOG_XYZ1,
       //     "HWSPCMA1009W invalid format of cluster message -%05d-", __LINE__ );
       //}
#ifdef TRACEHL2
       //awcl_name = (HL_WCHAR *) (adsl_cma_ent+1);
       //awcl_name++; /* first byte is length */

       printf( "xs-gw-cma1-02i release request received: start %lld\n",
           ill_epoch_ms );
#endif
       achl1 = NULL;
       achl2 = NULL;
       if (iel_cma_msg == ied_cma_msg_lock_rel_upd) {
#ifdef CL_RET_TIME
         /* get retention time */
         inl_ret_time = (int) m_conv_from_nhasn(adsl_gather);
#endif
         /* get lock displacement */
         inl_lock_disp = (int) m_conv_from_nhasn(adsl_gather);
         /* get lock length */
         inl_lock_len = (int) m_conv_from_nhasn(adsl_gather);
         /* get cma size */
         inl_cma_size = (int) m_conv_from_nhasn(adsl_gather);

         /* Update size of cma in other clusters is done with the
            ied_cma_msg_lock_rel_upd command, after changing it locally.
            While changing the size, the global lock is still active.  */
         if (adsl_cma_ent->inc_size_area != inl_cma_size) {
           achl1 = adsl_cma_ent->achc_area;

           if (inl_cma_size) {   /* allocate new memory for cma data   */
             achl2 = (char *) malloc(inl_cma_size*sizeof(char));
             if (!achl2) {
               m_hlnew_printf( HLOG_XYZ1, "HWSPCMA1010W allocation of %d bytes failed --> no update performed -%05d-",
               inl_cma_size, __LINE__ );
               m_cluster_proc_recv_done(adsp_clprr);
               return;  /* out of memory */
             }
             if (achl1 != NULL) {
               if ((inl_lock_disp > 0) || (inl_lock_len < inl_cma_size))
               {  /* if lock was not global, backup old data */
                 if (inl_cma_size > adsl_cma_ent->inc_size_area) {
                   memcpy( achl2, achl1, adsl_cma_ent->inc_size_area );
                 }
                 else {
                   memcpy( achl2, achl1, inl_cma_size );
                 }
               }
               //free (adsl_cma_ent->achc_area);
             }

             //dss_cma1_co.dsc_critsect_1.m_enter(); /* critical section */
             //adsl_cma_ent->achc_area = achl_curr;
             //adsl_cma_ent->inc_size_area = inl_cma_size;
             //dss_cma1_co.dsc_critsect_1.m_leave(); /* critical section */
           }
           //else {  /* inl_cma_size == 0 */
           //  //free( adsl_cma_ent->achc_area );
           //  dss_cma1_co.dsc_critsect_1.m_enter(); /* critical section */
           //  adsl_cma_ent->achc_area = NULL;
           //  adsl_cma_ent->inc_size_area = 0;
           //  dss_cma1_co.dsc_critsect_1.m_leave(); /* critical section */
           //}
           //if (achl1)
           //  free( achl1 );  /* free old data */
         }
         /* if data was split up */
         while (adsl_gather &&
                adsl_gather->achc_ginp_cur == adsl_gather->achc_ginp_end)
           adsl_gather = adsl_gather->adsc_next;
       }

       /* prepare response message: */
       adsl_cluster_s = (struct dsd_cluster_send *)
                  malloc( sizeof(dsd_cluster_send)
                          + 2*sizeof(dsd_gather_i_1) + 20*sizeof(char) );
       //if (!adsl_cluster_s) { /* return without update */
       //  if (achl_curr)
       //    free(achl_curr);   /* free new data area */
       //  m_cluster_proc_recv_done(adsp_clprr);
       //  return;  /* out of memory */
       //}

       adsl_cluster_s->adsc_clact  = adsp_clprr->adsc_clact;
       adsl_cluster_s->amc_compl   = &m_send_compl2;
       //adsl_cluster_s->vpc_userfld = NULL;
       adsl_cluster_s->iec_cl_type = ied_clty_cma;
       adsl_cluster_s->adsc_gai1_send    /* contains cma name + length */
           = (dsd_gather_i_1 *) (adsl_cluster_s + 1);
       adsl_cluster_s->adsc_gai1_send->achc_ginp_cur
           = (char *) ((adsl_cma_ent) + 1);
       adsl_cluster_s->adsc_gai1_send->achc_ginp_end
           = adsl_cluster_s->adsc_gai1_send->achc_ginp_cur
             + (*adsl_cluster_s->adsc_gai1_send->achc_ginp_cur + 1)
                                                      * sizeof(HL_WCHAR);
       adsl_cluster_s->adsc_gai1_send->adsc_next /* contains lock info */
           = adsl_cluster_s->adsc_gai1_send + 1;
       adsl_cluster_s->adsc_gai1_send->adsc_next->adsc_next = NULL;
       achl_curr = (char *) (adsl_cluster_s->adsc_gai1_send + 2);
       achl_curr += 20;
       adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_end = achl_curr;

       /*****************************************************************
          send: - '00' = response
                - epoch in ms
                - '01':positive, 'FF':negative
                - '00':release (added for debugging 23.04.10)
       *****************************************************************/

       /* convert numbers to NHASN from last to first */
       achl_curr--;
       *achl_curr = 0;    /* response to release (23.04.10) */
       achl_curr--;
       *achl_curr = 1;    /* positive response  */
       achl_curr = m_conv_to_nhasn( achl_curr, ill_epoch_ms );
       achl_curr--;
       *achl_curr = 0;    /* ied_cma_msg == ied_cma_msg_resp  */
       adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_cur = achl_curr;


       dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section    */
       /* search for external lock entry   */
       adsl_lock_ext = adsl_cma_ent->adsc_ext_chain;
       adsl_lock_ext2 = NULL;
       while (adsl_lock_ext) {
         if ( adsl_lock_ext->ilc_epoch_ms == ill_epoch_ms
              && adsl_lock_ext->ac_clact == adsp_clprr->adsc_clact )
           break;
         adsl_lock_ext2 = adsl_lock_ext;
         adsl_lock_ext  = adsl_lock_ext->adsc_next;
       }
       /* remove from chain */
       if (adsl_lock_ext) {     /* entry was found      */
         if (adsl_lock_ext2) {  /* was not first entry  */
           adsl_lock_ext2->adsc_next = adsl_lock_ext->adsc_next;
         }
         else {                 /* was first entry     */
           adsl_cma_ent->adsc_ext_chain = adsl_lock_ext->adsc_next;
         }

         /* remove from active locks chain, too */
         adsl_clinfo = dss_cma1_co.adsc_cluster_info;
         /* search for WSP, sending the message */
         while (adsl_clinfo
                 && adsl_clinfo->adsc_clact != adsp_clprr->adsc_clact) {
           adsl_clinfo = adsl_clinfo->adsc_next;
         }
         if (adsl_clinfo == NULL)
         { /* active cluster not in chain -> fatal error */
           //TODO: error handling
           dss_cma1_co.dsc_critsect_1.m_leave();   /* critical section */
           m_hlnew_printf( HLOG_XYZ1,
            "HWSPCMA1011W cluster message belongs to an invalid cluster connection -%05d-", __LINE__ );
           if (achl2)
             free(achl2);

           m_cluster_proc_recv_done(adsp_clprr);
           return;
         }

         /* remove also from active locks chain */
         adsl_lock_el = adsl_lock_ext->adsc_remote_chain;
         if (adsl_lock_el->adsc_pred == NULL) {
           adsl_clinfo->adsc_active_locks = adsl_lock_el->adsc_succ;
           if (adsl_clinfo->adsc_active_locks)
             adsl_clinfo->adsc_active_locks->adsc_pred = NULL;
         }
         else {
           adsl_lock_el->adsc_pred->adsc_succ = adsl_lock_el->adsc_succ;
           if (adsl_lock_el->adsc_succ)
             adsl_lock_el->adsc_succ->adsc_pred = adsl_lock_el->adsc_pred;
         }

         /* update cma, if ied_cma_msg_lock_rel_upd                    */
         if (iel_cma_msg == ied_cma_msg_lock_rel_upd) {
#ifdef CL_RET_TIME
           adsl_cma_ent->imc_retention_time = inl_ret_time;
#endif
           if (inl_cma_size == 0) {  /* cma entry contains no data */
             adsl_cma_ent->achc_area = NULL;
             adsl_cma_ent->inc_size_area = 0;
           }
           else { /* copy data from message to cma */
             if (achl2) {   /* new data area for cma entry */
               adsl_cma_ent->achc_area = achl2;
               adsl_cma_ent->inc_size_area = inl_cma_size;
             }
             achl_curr = adsl_cma_ent->achc_area + inl_lock_disp;
             iml1 = inl_lock_len;
             if (iml1 == 0)    /* global lock   */
               iml1 = inl_cma_size;
             while (iml1) {
               *achl_curr = *(adsl_gather->achc_ginp_cur);
               achl_curr++;
               adsl_gather->achc_ginp_cur++;
               if (adsl_gather->achc_ginp_cur == adsl_gather->achc_ginp_end)
                 adsl_gather = adsl_gather->adsc_next;
               iml1--;
             }
           }
         }
         dss_cma1_co.dsc_critsect_1.m_leave();   /* critical section   */
         if (achl1)
           free(achl1);  /* free old data area of this cma entry */

#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &ill_start );
#endif
         /* send positive response */
         if (m_cluster_send(adsl_cluster_s)) {    /* error - sending   */
           // TODO: error handling
           //m_hlnew_printf( HLOG_XYZ1,
           // "HWSPCMA1003I m_cluster_send() to Cluster INETA=%s failed -%05d-",
           //                adsp_clprr->adsc_clact->chrc_ineta, __LINE__ );
           m_hlnew_printf( HLOG_XYZ1,
               "HWSPCMA1003I m_cluster_send() failed -%05d-", __LINE__ );
         }
#ifdef TRACE_LOCKTIME
       QueryPerformanceCounter( (LARGE_INTEGER *) &ill_end );
       if (dss_cma1_co.ilc_freq) {
         printf( "xs-gw-cma1-02-l%05d-T m_cluster_send(resp.-rel.) needs \t%lld[ns]\n",
                 __LINE__,
                 (HL_LONGLONG) ((ill_end - ill_start) * 1000000)
                                                                    / dss_cma1_co.ilc_freq );
       }
#endif
         /* syncronization problem, when in same moment timeout waiting for that external
            lock occures (dump from 11.07.12 on A7), because adsl_wait_ent1 used here,
            maybe already freed in the other thread.
            Setting a critical section arround the following lines of code should solve
            this problem. */
         dss_cma1_co.dsc_critsect_1.m_enter();   /* critical section (KT -130712-) */
         adsl_wait_ent1 = adsl_lock_ext->adsc_wait_entry;
         adsl_lock_ext->adsc_wait_entry = NULL; /* for timeout detection */
         /* wake up threads, waiting for release of lock */
         while (adsl_wait_ent1) {
           //m_hco_wothr_post( NULL,
           //  ((dsd_aux_cf1 *) adsl_wait_ent1->ac_elem)->adsc_hco_wothr );
           m_hco_wothr_post( NULL,
                             (dsd_hco_wothr *) adsl_wait_ent1->ac_elem );
           adsl_wait_ent2 = adsl_wait_ent1;
           adsl_wait_ent1 = adsl_wait_ent1->adsc_next;
           free(adsl_wait_ent2);
         }
         dss_cma1_co.dsc_critsect_1.m_leave();   /* critical section (KT -130712-) */

         free(adsl_lock_el);
         free(adsl_lock_ext);
       }
       else {   /* no entry found, send negative response */
         dss_cma1_co.dsc_critsect_1.m_leave();   /* critical section   */
         m_hlnew_printf( HLOG_XYZ1,
            "HWSPCMA1016W release could not be assigned to a lock --> no action performed -%05d-",
            __LINE__ );
         if (achl2)
           free(achl2);   /* free new allocated memory */

         /* get position of flag for positive/negative response        */
         achl_curr =
            //adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_end - 1;
            adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_end - 2;  //(23.04.10)
         *achl_curr = -1;        /* set to negative response           */
         if (m_cluster_send(adsl_cluster_s)) {    /* error - sending   */
           // TODO: error handling
           //m_hlnew_printf( HLOG_XYZ1,
           // "HWSPCMA1003I m_cluster_send() to Cluster INETA=%s failed -%05d-",
           //                adsp_clprr->adsc_clact->chrc_ineta, __LINE__ );
           m_hlnew_printf( HLOG_XYZ1,
               "HWSPCMA1003I m_cluster_send() failed -%05d-", __LINE__ );
         }
       }
       m_cluster_proc_recv_done(adsp_clprr);
#ifdef TRACEHL2
       printf( "xs-gw-cma1-02i release request received: end %lld\n",
         ill_epoch_ms );
#endif
       return;

     case ied_cma_msg_data_if_empty:
       /* data from other WSP, that has local server as update server  */
#ifdef CL_RET_TIME
       /* get retention time */
       inl_ret_time = (int) m_conv_from_nhasn(adsl_gather);
#endif
       /* get size of data send */
       inl_cma_size = (int) m_conv_from_nhasn(adsl_gather);
       /* if data was split up */
       while (adsl_gather &&
              adsl_gather->achc_ginp_cur == adsl_gather->achc_ginp_end)
         adsl_gather = adsl_gather->adsc_next;

       /* only use it, if this entry is still empty and not locked     */
       dss_cma1_co.dsc_critsect_1.m_enter();  /* critical section      */
       if ((adsl_cma_ent->achc_area != NULL)
           || (adsl_cma_ent->vpc_lock_chain != NULL))
       { /* don't use received data */
         dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section    */
         m_cluster_proc_recv_done(adsp_clprr);
         return;
       }
       achl_curr = (char *) malloc(inl_cma_size*sizeof(char));
       if (!achl_curr) {
         dss_cma1_co.dsc_critsect_1.m_leave();   /* critical section   */
         m_cluster_proc_recv_done(adsp_clprr);
         return;  /* out of memory */
       }

       adsl_cma_ent->achc_area = achl_curr;
       adsl_cma_ent->inc_size_area = inl_cma_size;
#ifdef CL_RET_TIME
       adsl_cma_ent->imc_retention_time = inl_ret_time;
#endif
       /* copy data from message to cma */
       while (inl_cma_size) {
         *achl_curr = *(adsl_gather->achc_ginp_cur);
         achl_curr++;
         adsl_gather->achc_ginp_cur++;
         if (adsl_gather->achc_ginp_cur == adsl_gather->achc_ginp_end)
           adsl_gather = adsl_gather->adsc_next;

         inl_cma_size--;
       }

       /* send to other WSP's, without waiting for response */
       adsl_clinfo = dss_cma1_co.adsc_cluster_info;
       while (adsl_clinfo) {
         if (adsl_clinfo->adsc_clact != adsp_clprr->adsc_clact) {
           m_send_cma_entry( adsl_cma_ent, ied_cma_msg_data_if_empty,
                           (dsd_cluster_active *) adsl_clinfo->adsc_clact );
         }
         adsl_clinfo = adsl_clinfo->adsc_next;
       }
       dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section      */
     } /* end switch (iel_cma_msg) */
     m_cluster_proc_recv_done(adsp_clprr);
     return;
} /* end m_cma1_cluster_recv()                                         */

static void m_proc_cma_update( struct dsd_hco_wothr *adsp_hco_wothr,
                void *ap_param_1, void *ap_param_2, void *ap_param_3 )
{
   struct dsd_htree1_avl_work dsl_avl_work; /* working struct. for avl */
   struct dsd_cma1_ent     *adsl_upd_entry;
   struct dsd_cma1_ent     *adsl_local_entry;
   struct dsd_cma_ext_lock *adsl_lock_ext;  /* for external lock       */
   //struct dsd_cma_ext_lock *adsl_lock_ext2; /* to free external lock   */
   struct dsd_elem_chain *adsl_wait_ent1;   /* waiting threads         */
   struct dsd_elem_chain *adsl_wait_ent2;   /* waiting threads         */
   struct dsd_cluster_send *adsl_cluster_s; /* send to other wsp       */
   char   *achl_curr;                       /* temporary data pointer  */

   m_notify_cma_sync_active_start();
   dss_cma1_co.dsc_critsect_1.m_enter();      /* critical section      */
   if (dss_cma1_co.adsc_thr_upd) {      /* awake old thread to end it  */
     m_hco_wothr_post( NULL, dss_cma1_co.adsc_thr_upd );
     //dss_cma1_co.adsc_thr_upd = adsp_hco_wothr; /* important to set inside crit. section */
     //dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section      */
     //m_hco_wothr_nonblock_wait_sec(adsp_hco_wothr, WT_CLUSTER);
     //dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section      */
   }

   /* make entry for running update thread */
   dss_cma1_co.adsc_thr_upd = adsp_hco_wothr;
   dss_cma1_co.adsc_ent_upd = NULL;
   dss_cma1_co.adsc_ent_loc = NULL;
   dss_cma1_co.inc_upd_length = -1;           /* to detect timeouts    */
   dss_cma1_co.dsc_critsect_1.m_leave();      /* critical section      */

   m_hlnew_printf( HLOG_XYZ1,
       "HWSPCMA1012I update of cma from INETA=%s started -%05d-",
       ((dsd_cluster_active *) ap_param_1)->chrc_ineta, __LINE__ );

   adsl_cluster_s = (struct dsd_cluster_send *)
                malloc( sizeof(dsd_cluster_send) + sizeof(dsd_gather_i_1)
                                                 + sizeof(char) );
   adsl_cluster_s->adsc_clact  = (dsd_cluster_active *) ap_param_1;
#ifdef TRACE_170913
   m_hlnew_printf( HLOG_XYZ1, "xswspcma-%05d-T update from:adsl_cluster_s->adsc_clact=%p",
                                                      __LINE__, adsl_cluster_s->adsc_clact );
#endif
   adsl_cluster_s->amc_compl   = &m_send_compl2;
   adsl_cluster_s->vpc_userfld = NULL;
   adsl_cluster_s->iec_cl_type = ied_clty_cma;
   adsl_cluster_s->adsc_gai1_send       /* contains request for update */
           = (dsd_gather_i_1 *) (adsl_cluster_s + 1);
   adsl_cluster_s->adsc_gai1_send->achc_ginp_cur
           = (char *) (adsl_cluster_s->adsc_gai1_send + 1);
   adsl_cluster_s->adsc_gai1_send->achc_ginp_end
           = adsl_cluster_s->adsc_gai1_send->achc_ginp_cur + 1;
   adsl_cluster_s->adsc_gai1_send->adsc_next = NULL;
   /* first byte < 0 means: message effects total cma   */
   *(adsl_cluster_s->adsc_gai1_send->achc_ginp_cur) = -1;
   /* request first update element   */
   if (m_cluster_send(adsl_cluster_s))
   {    /* error - sending   */
     // TODO: error handling
     m_hlnew_printf( HLOG_XYZ1,
               "HWSPCMA1003I m_cluster_send() failed -%05d-", __LINE__ );
   }
   m_hco_wothr_nonblock_wait_sec(adsp_hco_wothr, WT_CLUSTER);
   dss_cma1_co.dsc_critsect_1.m_enter();         /* critical section   */
   if (dss_cma1_co.adsc_clact_upd != (dsd_cluster_active *)ap_param_1) {
     /* newer update thread has been started, end this one             */
     //if (dss_cma1_co.adsc_thr_upd)
  //     m_hco_wothr_post( NULL, dss_cma1_co.adsc_thr_upd );
     dss_cma1_co.dsc_critsect_1.m_leave();       /* critical section   */
     m_notify_cma_sync_active_stop();
     return;
   }
   if (dss_cma1_co.inc_upd_length < 0)
   { //TODO: timeout handling
     dss_cma1_co.adsc_clact_upd = NULL;
     dss_cma1_co.adsc_thr_upd = NULL;

     dss_cma1_co.dsc_critsect_1.m_leave();       /* critical section   */
     m_hlnew_printf( HLOG_XYZ1,
       "HWSPCMA1004I timeout: waiting for response from other WSP -%05d-", __LINE__ );
     m_notify_cma_sync_active_stop();
     return;  /* leave update */
   }

   /* check, if local tree has elenments, not yet on the update server */
   m_htree1_avl_getnext( NULL, &dss_cma1_co.dsc_avl_cntl,
                               &dsl_avl_work, TRUE );
   dss_cma1_co.adsc_ent_loc
       = (struct dsd_cma1_ent *) dsl_avl_work.adsc_found;
   adsl_upd_entry = dss_cma1_co.adsc_ent_upd;
   dss_cma1_co.dsc_critsect_1.m_leave();

   if (adsl_upd_entry == NULL) {     /* no entries on update server    */
     /* Send all local entries to the remote WSP without waiting
        for a response. The receiving WSP only inserts the data, if it
        has neither own data nor a lock for this entry, otherwise it
        will reject the data.                                          */

     dss_cma1_co.dsc_critsect_1.m_enter();       /* critical section   */
     while (dsl_avl_work.adsc_found) {
       adsl_local_entry = (dsd_cma1_ent *) dsl_avl_work.adsc_found;
       if (adsl_local_entry->inc_size_area) {  /* area is not empty */
         m_send_cma_entry( adsl_local_entry, ied_cma_msg_data_if_empty,
                           (dsd_cluster_active *)ap_param_1 );
       }

       m_htree1_avl_getnext( NULL, &dss_cma1_co.dsc_avl_cntl,
                             &dsl_avl_work, FALSE );
     }
     if (dss_cma1_co.adsc_clact_upd == (dsd_cluster_active *)ap_param_1)
     { /* if meanwhile no other update thread was started */
       dss_cma1_co.adsc_clact_upd = NULL;
       dss_cma1_co.adsc_thr_upd = NULL;
       dss_cma1_co.adsc_ent_loc = NULL;
     }
     else if (dss_cma1_co.adsc_thr_upd == adsp_hco_wothr) {
       dss_cma1_co.adsc_thr_upd = NULL;
       dss_cma1_co.adsc_ent_loc = NULL;
     }
     //???
     dss_cma1_co.dsc_critsect_1.m_leave();       /* critical section   */
     m_hlnew_printf( HLOG_XYZ1,
       "HWSPCMA1013I update of cma completed -%05d-", __LINE__ );
     m_notify_cma_sync_active_stop();
     /* send back message that update is complete */
     adsl_cluster_s = (struct dsd_cluster_send *)
                malloc( sizeof(dsd_cluster_send) + sizeof(dsd_gather_i_1)
                                                 + sizeof(char) );
     adsl_cluster_s->adsc_clact  = (dsd_cluster_active *) ap_param_1;
     adsl_cluster_s->amc_compl   = &m_send_compl2;
     adsl_cluster_s->vpc_userfld = NULL;
     adsl_cluster_s->iec_cl_type = ied_clty_cma;
     adsl_cluster_s->adsc_gai1_send       /* contains request for update */
           = (dsd_gather_i_1 *) (adsl_cluster_s + 1);
     adsl_cluster_s->adsc_gai1_send->achc_ginp_cur
           = (char *) (adsl_cluster_s->adsc_gai1_send + 1);
     adsl_cluster_s->adsc_gai1_send->achc_ginp_end
           = adsl_cluster_s->adsc_gai1_send->achc_ginp_cur + 1;
     adsl_cluster_s->adsc_gai1_send->adsc_next = NULL;
     /* first byte < 0 means: message effects total cma   */
     *(adsl_cluster_s->adsc_gai1_send->achc_ginp_cur) = -3; /* update is complete */
     if (m_cluster_send(adsl_cluster_s))
     {    /* error - sending   */
       // TODO: error handling
       m_hlnew_printf( HLOG_XYZ1,
               "HWSPCMA1003I m_cluster_send() failed -%05d-", __LINE__ );
     }

     return;   /* ready with update */
   }

   while (adsl_upd_entry) {   /* update next entry */
     dss_cma1_co.dsc_critsect_1.m_enter();       /* critical section   */
     /* check if local entries exist, that are not on the update server */
     while ( dsl_avl_work.adsc_found &&
         (m_cma1_comp_names(NULL, (dsd_htree1_avl_entry *)adsl_upd_entry,
                                          dsl_avl_work.adsc_found) > 0 ))
     { /* send local entry to update server */
       adsl_local_entry = (dsd_cma1_ent *) dsl_avl_work.adsc_found;
       if (adsl_local_entry->inc_size_area) {  /* area is not empty */
         m_send_cma_entry( adsl_local_entry, ied_cma_msg_data_if_empty,
                           (dsd_cluster_active *)ap_param_1 );
       }
       m_htree1_avl_getnext( NULL, &dss_cma1_co.dsc_avl_cntl,
                             &dsl_avl_work, FALSE );
     } /* end: send local entry */
     dss_cma1_co.dsc_critsect_1.m_leave();       /* critical section   */

     /* prepare entry for 'external lock' chain' */
     adsl_lock_ext
         = (dsd_cma_ext_lock *) malloc(sizeof(dsd_cma_ext_lock));
     /* fill 'external lock' structure */
     adsl_lock_ext->adsc_wait_entry
         = (dsd_elem_chain *) malloc(sizeof(dsd_elem_chain));
     adsl_lock_ext->ac_clact = (dsd_cluster_active *) ap_param_1;
     adsl_lock_ext->ilc_epoch_ms  = m_get_epoch_ms();
     adsl_lock_ext->inc_lock_type = D_CMA_ALL_ACCESS;
     adsl_lock_ext->inc_lock_disp = 0;
     adsl_lock_ext->adsc_wait_entry->adsc_next = NULL;
     adsl_lock_ext->adsc_next = NULL;        /* should be the only one */

     dss_cma1_co.dsc_critsect_1.m_enter();        /* critical section  */
     if (dss_cma1_co.adsc_clact_upd != (dsd_cluster_active *)ap_param_1) {
       /* new update thread has been started, end the old one          */
       //if (dss_cma1_co.adsc_thr_upd == adsp_hco_wothr) {
       //  dss_cma1_co.adsc_thr_upd = NULL;
       dss_cma1_co.dsc_critsect_1.m_leave();     /* critical section   */
       free(adsl_lock_ext->adsc_wait_entry);
       free(adsl_lock_ext);
       m_notify_cma_sync_active_stop();

       return;
     }

     adsl_lock_ext->inc_lock_len = dss_cma1_co.inc_upd_length;
     //adsl_lock_ext->adsc_wait_entry->ac_elem = dss_cma1_co.adsc_thr_upd;
     adsl_lock_ext->adsc_wait_entry->ac_elem = adsp_hco_wothr;

     /* if there is already an external lock, wait for release         */
     while (adsl_upd_entry->adsc_ext_chain) {
       adsl_wait_ent1 = adsl_upd_entry->adsc_ext_chain->adsc_wait_entry;
       adsl_upd_entry->adsc_ext_chain->adsc_wait_entry
           = (dsd_elem_chain *) malloc(sizeof(dsd_elem_chain));
       adsl_upd_entry->adsc_ext_chain->adsc_wait_entry->ac_elem
           = adsp_hco_wothr;
       adsl_upd_entry->adsc_ext_chain->adsc_wait_entry->adsc_next
           = adsl_wait_ent1;
       dss_cma1_co.dsc_critsect_1.m_leave();      /* critical section  */
       m_hco_wothr_nonblock_wait_sec(adsp_hco_wothr, WT_CLUSTER);
       dss_cma1_co.dsc_critsect_1.m_enter();      /* critical section  */
       if (dss_cma1_co.adsc_clact_upd != (dsd_cluster_active *)ap_param_1)
       { /* new update thread has been started, end the old one        */
         //if (dss_cma1_co.adsc_thr_upd == adsp_hco_wothr) {
         //  dss_cma1_co.adsc_thr_upd = NULL;
         dss_cma1_co.dsc_critsect_1.m_leave();     /* critical section */
         free(adsl_lock_ext->adsc_wait_entry);
         free(adsl_lock_ext);
         m_notify_cma_sync_active_stop();

         return;
       }
     }

     /* prevent from new local locks by setting an external lock entry */
     adsl_upd_entry->adsc_ext_chain = adsl_lock_ext;
     dss_cma1_co.dsc_critsect_1.m_leave();        /* critical section  */

     while (adsl_upd_entry->vpc_lock_chain)
     { /* while a local lock exists, wait for release of this lock     */
       m_hco_wothr_nonblock_wait_sec(adsp_hco_wothr, WT_CLUSTER);

       dss_cma1_co.dsc_critsect_1.m_enter();  /* critical section    */
       if (dss_cma1_co.adsc_clact_upd != (dsd_cluster_active *)ap_param_1)
       { /* new update thread has been started, stop the old one       */
         if (adsl_upd_entry->adsc_ext_chain) { /* remove external lock */
           adsl_wait_ent1 = adsl_lock_ext->adsc_wait_entry;
           adsl_wait_ent2 = adsl_wait_ent1;
           m_remove_ext_lock(adsl_upd_entry, adsl_lock_ext);
           /* post to local thread waiting for external lock */
           while (adsl_wait_ent1->adsc_next) {
             m_hco_wothr_post(NULL, (struct dsd_hco_wothr *)
                                                adsl_wait_ent1->ac_elem);
             adsl_wait_ent2 = adsl_wait_ent1;
             adsl_wait_ent1 = adsl_wait_ent1->adsc_next;
             free(adsl_wait_ent2);
           }
           free(adsl_wait_ent1);
           free(adsl_lock_ext);
         } /* end: if external lock */

         if (dss_cma1_co.adsc_thr_upd == adsp_hco_wothr)
           dss_cma1_co.adsc_thr_upd = NULL;
         //else if (dss_cma1_co.adsc_thr_upd)
         //  m_hco_wothr_post( NULL, dss_cma1_co.adsc_thr_upd );

         dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section    */
         m_notify_cma_sync_active_stop();

         return;
       }

       //if (adsl_lock_ext->adsc_wait_entry->ac_elem != NULL) {
       //  //TODO: error handling
       //}
       dss_cma1_co.dsc_critsect_1.m_leave();  /* critical section    */
     }

     /* prepare dsd_cluster_send structure (type: request update data) */
     adsl_cluster_s = (struct dsd_cluster_send *)
                   malloc( sizeof(dsd_cluster_send)
                           + 2*sizeof(dsd_gather_i_1) + 2*sizeof(char) );
     adsl_cluster_s->adsc_clact  = (dsd_cluster_active *) ap_param_1;
     adsl_cluster_s->amc_compl   = &m_send_compl2;
     adsl_cluster_s->vpc_userfld = NULL;
     adsl_cluster_s->iec_cl_type = ied_clty_cma;
     adsl_cluster_s->adsc_gai1_send    /* contains request for update  */
           = (dsd_gather_i_1 *) (adsl_cluster_s + 1);
     dss_cma1_co.dsc_critsect_1.m_enter();        /* critical section  */
     /* pointer to length and name of cma entry */
     adsl_cluster_s->adsc_gai1_send->achc_ginp_cur
         = (char *) (dss_cma1_co.adsc_ent_upd + 1);
     dss_cma1_co.inc_upd_length = -1;     /* detect timeout after wait */
     dss_cma1_co.dsc_critsect_1.m_leave();        /* critical section  */
     adsl_cluster_s->adsc_gai1_send->achc_ginp_end
         = adsl_cluster_s->adsc_gai1_send->achc_ginp_cur
             + (*adsl_cluster_s->adsc_gai1_send->achc_ginp_cur + 1)
                                                      * sizeof(HL_WCHAR);
     adsl_cluster_s->adsc_gai1_send->adsc_next   /* type of message    */
         = adsl_cluster_s->adsc_gai1_send + 1;
     achl_curr = (char *) (adsl_cluster_s->adsc_gai1_send + 2);
     adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_cur = achl_curr;
     *achl_curr++ = ied_cma_msg_upd_req_d; /* request for update data  */
     *achl_curr++ = 0;    /* dummy for epoch */
     adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_end = achl_curr;
     adsl_cluster_s->adsc_gai1_send->adsc_next->adsc_next = NULL;
     if (m_cluster_send(adsl_cluster_s)) {      /* error - sending     */
       // TODO: error handling
       //m_hlnew_printf( HLOG_XYZ1,
       // "HWSPCMA1003I m_cluster_send() to Cluster INETA=%s failed -%05d-",
       //                adsl_cluster_s->adsc_clact->chrc_ineta, __LINE__ );
       m_hlnew_printf( HLOG_XYZ1,
               "HWSPCMA1003I m_cluster_send() failed -%05d-", __LINE__ );
     }
     m_hco_wothr_nonblock_wait_sec(adsp_hco_wothr, WT_CLUSTER); /* wait for data  */
     dss_cma1_co.dsc_critsect_1.m_enter();       /* critical section   */
     if (dss_cma1_co.adsc_clact_upd != (dsd_cluster_active *)ap_param_1)
     { /* new update thread has been started, end the old one          */
       if (dss_cma1_co.adsc_thr_upd)
         m_hco_wothr_post( NULL, dss_cma1_co.adsc_thr_upd );

       dss_cma1_co.dsc_critsect_1.m_leave();       /* critical section */
       m_notify_cma_sync_active_stop();

       return;
     }
     if (dss_cma1_co.inc_upd_length < 0)
     { //TODO: timeout handling
       m_hlnew_printf( HLOG_XYZ1,
         "HWSPCMA1004I timeout: waiting for response from other WSP -%05d-", __LINE__ );
       dss_cma1_co.adsc_clact_upd = NULL;
       dss_cma1_co.adsc_thr_upd = NULL;
       if (dss_cma1_co.adsc_ent_upd) { /* remove external lock */
       }

       dss_cma1_co.dsc_critsect_1.m_leave();       /* critical section */
       m_notify_cma_sync_active_stop();

       return;
     }
     dss_cma1_co.dsc_critsect_1.m_leave();         /* critical section */

     //free(dss_cma1_co.adsc_ent_upd->adsc_ext_chain);
     //dss_cma1_co.adsc_ent_upd->adsc_ext_chain = NULL;
     //dss_cma1_co.dsc_critsect_1.m_leave();       /* critical section   */

     if ( dsl_avl_work.adsc_found &&
         (m_cma1_comp_names(NULL, (dsd_htree1_avl_entry *)adsl_upd_entry,
                                          dsl_avl_work.adsc_found) == 0 ))
     { /* get next local entry */
       dss_cma1_co.dsc_critsect_1.m_enter();       /* critical section */
       m_htree1_avl_getnext( NULL, &dss_cma1_co.dsc_avl_cntl,
                             &dsl_avl_work, FALSE );
       dss_cma1_co.dsc_critsect_1.m_leave();       /* critical section */
     }

     /* request for lock of next update entry                          */
     adsl_cluster_s = (struct dsd_cluster_send *)
                   malloc( sizeof(dsd_cluster_send)
                           + 2*sizeof(dsd_gather_i_1) + 2*sizeof(char) );
     adsl_cluster_s->adsc_clact  = (dsd_cluster_active *) ap_param_1;
     adsl_cluster_s->amc_compl   = &m_send_compl2;
     adsl_cluster_s->vpc_userfld = NULL;
     adsl_cluster_s->iec_cl_type = ied_clty_cma;
     adsl_cluster_s->adsc_gai1_send    /* contains request for lock    */
           = (dsd_gather_i_1 *) (adsl_cluster_s + 1);
     dss_cma1_co.dsc_critsect_1.m_enter();        /* critical section  */
     /* pointer to length and name of cma entry */
     adsl_cluster_s->adsc_gai1_send->achc_ginp_cur
         = (char *) (adsl_upd_entry + 1);
     dss_cma1_co.dsc_critsect_1.m_leave();        /* critical section  */
     adsl_cluster_s->adsc_gai1_send->achc_ginp_end
         = adsl_cluster_s->adsc_gai1_send->achc_ginp_cur
             + (*adsl_cluster_s->adsc_gai1_send->achc_ginp_cur + 1)
                                                      * sizeof(HL_WCHAR);
     adsl_cluster_s->adsc_gai1_send->adsc_next    /* type of message   */
         = adsl_cluster_s->adsc_gai1_send + 1;
     achl_curr = (char *) (adsl_cluster_s->adsc_gai1_send + 2);
     adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_cur = achl_curr;
     *achl_curr++ = ied_cma_msg_upd_req_l; /* request for update lock  */
     *achl_curr++ = 0;    /* dummy for epoch */
     adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_end = achl_curr;
     adsl_cluster_s->adsc_gai1_send->adsc_next->adsc_next = NULL;
     if (m_cluster_send(adsl_cluster_s)) {    /* error - sending   */
       // TODO: error handling
       //m_hlnew_printf( HLOG_XYZ1,
       // "HWSPCMA1003I m_cluster_send() to Cluster INETA=%s failed -%05d-",
       //                adsl_cluster_s->adsc_clact->chrc_ineta, __LINE__ );
       m_hlnew_printf( HLOG_XYZ1,
               "HWSPCMA1003I m_cluster_send() failed -%05d-", __LINE__ );
     }
     /* wait for remote lock */
     m_hco_wothr_nonblock_wait_sec(adsp_hco_wothr, WT_CLUSTER);
     dss_cma1_co.dsc_critsect_1.m_enter();       /* critical section   */
     if (dss_cma1_co.adsc_clact_upd != (dsd_cluster_active *)ap_param_1)
     { /* new update thread has been started, stop the old one         */
       if (dss_cma1_co.adsc_thr_upd)
         m_hco_wothr_post( NULL, dss_cma1_co.adsc_thr_upd );

       dss_cma1_co.dsc_critsect_1.m_leave();       /* critical section */
       m_notify_cma_sync_active_stop();

       return;
     }
     if (dss_cma1_co.inc_upd_length < 0)
     { //TODO: timeout handling

       dss_cma1_co.dsc_critsect_1.m_leave();       /* critical section */
       m_notify_cma_sync_active_stop();

       return;
     }
     adsl_upd_entry = dss_cma1_co.adsc_ent_upd;  /* entry to lock      */
     dss_cma1_co.dsc_critsect_1.m_leave();       /* critical section   */
   } /* while (adsl_upd_entry) */

   /* update is complete --> leave update thread */
   dss_cma1_co.dsc_critsect_1.m_enter();        /* critical section    */
   /* if there are more local entries, send them now */
   while ( dsl_avl_work.adsc_found )
   { /* send local entry to update server */
     adsl_local_entry = (dsd_cma1_ent *) dsl_avl_work.adsc_found;
     if (adsl_local_entry->inc_size_area) {  /* area is not empty */
       m_send_cma_entry( adsl_local_entry, ied_cma_msg_data_if_empty,
                         (dsd_cluster_active *)ap_param_1 );
     }
     m_htree1_avl_getnext( NULL, &dss_cma1_co.dsc_avl_cntl,
                             &dsl_avl_work, FALSE );
   } /* end: send local entry */

   if (dss_cma1_co.adsc_clact_upd == (dsd_cluster_active *)ap_param_1)
   { /* if meanwhile no other update thread was started */
     dss_cma1_co.adsc_clact_upd = NULL;
     dss_cma1_co.adsc_thr_upd = NULL;
     dss_cma1_co.adsc_ent_loc = NULL;
   }
   else if (dss_cma1_co.adsc_thr_upd == adsp_hco_wothr) {
     dss_cma1_co.adsc_thr_upd = NULL;
     dss_cma1_co.adsc_ent_loc = NULL;
   }
   //???
   m_hlnew_printf( HLOG_XYZ1,
       "HWSPCMA1013I update of cma completed -%05d-", __LINE__ );

   dss_cma1_co.dsc_critsect_1.m_leave();        /* critical section    */
   m_notify_cma_sync_active_stop();
   /* send back message that update is complete */
   adsl_cluster_s = (struct dsd_cluster_send *)
                malloc( sizeof(dsd_cluster_send) + sizeof(dsd_gather_i_1)
                                                 + sizeof(char) );
   adsl_cluster_s->adsc_clact  = (dsd_cluster_active *) ap_param_1;
   adsl_cluster_s->amc_compl   = &m_send_compl2;
   adsl_cluster_s->vpc_userfld = NULL;
   adsl_cluster_s->iec_cl_type = ied_clty_cma;
   adsl_cluster_s->adsc_gai1_send       /* contains request for update */
           = (dsd_gather_i_1 *) (adsl_cluster_s + 1);
   adsl_cluster_s->adsc_gai1_send->achc_ginp_cur
           = (char *) (adsl_cluster_s->adsc_gai1_send + 1);
   adsl_cluster_s->adsc_gai1_send->achc_ginp_end
           = adsl_cluster_s->adsc_gai1_send->achc_ginp_cur + 1;
   adsl_cluster_s->adsc_gai1_send->adsc_next = NULL;
   /* first byte < 0 means: message effects total cma   */
   *(adsl_cluster_s->adsc_gai1_send->achc_ginp_cur) = -3; /* update is complete */
   if (m_cluster_send(adsl_cluster_s))
   {    /* error - sending   */
     // TODO: error handling
     m_hlnew_printf( HLOG_XYZ1,
               "HWSPCMA1003I m_cluster_send() failed -%05d-", __LINE__ );
   }

   return;
} /* end m_proc_cma_update()                                           */

static int m_send_cma_entry( void *ap_cma_entry, ied_cma_msg iep_cma_msg,
                             struct dsd_cluster_active *adsp_clact )
{
   struct dsd_cma1_ent     *adsl_cma_ent;
   struct dsd_cluster_send *adsl_cluster_s;        /* send to cluster  */
   char   *achl1;
   HL_LONGLONG ill_nhasn;                   /* for conversion to nhasn */
   int    iml_rc;

   if (ap_cma_entry == NULL)
   { /* no entry found, tell requesting WSP, that update is complete   */
     adsl_cluster_s = (struct dsd_cluster_send *)
          malloc( sizeof(dsd_cluster_send) + sizeof(dsd_gather_i_1)
                  + sizeof(char) );
     adsl_cluster_s->adsc_clact  = adsp_clact;
     adsl_cluster_s->amc_compl   = &m_send_compl2;
     adsl_cluster_s->vpc_userfld = NULL;
     adsl_cluster_s->iec_cl_type = ied_clty_cma;
     adsl_cluster_s->adsc_gai1_send    /* contains request for update  */
           = (dsd_gather_i_1 *) (adsl_cluster_s + 1);
     adsl_cluster_s->adsc_gai1_send->achc_ginp_cur
           = (char *) (adsl_cluster_s->adsc_gai1_send + 1);
     adsl_cluster_s->adsc_gai1_send->achc_ginp_end
           = adsl_cluster_s->adsc_gai1_send->achc_ginp_cur + 1;
     adsl_cluster_s->adsc_gai1_send->adsc_next = NULL;
     /* no more cma elements to update: flag = -2                      */
     *adsl_cluster_s->adsc_gai1_send->achc_ginp_cur = -2;
     iml_rc = m_cluster_send(adsl_cluster_s);
     if (iml_rc) {       /* error - sending    */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1,
         "xs-gw-cma1-02 m_cluster_send() has return code: %d  -%05d-",
         iml_rc, __LINE__ );
#endif

       /* error message is printed outside this function */
       return -1;
     }
     return 0;
   }

   if (iep_cma_msg == ied_cma_msg_upd_lock) {
     adsl_cluster_s = (struct dsd_cluster_send *)
                       malloc( sizeof(dsd_cluster_send)
                       + 2*sizeof(dsd_gather_i_1) + 10*sizeof(char) );
   }
   else { /* ied_cma_msg_upd_data or ied_cma_msg_data_if_empty */
     adsl_cluster_s = (struct dsd_cluster_send *)
                       malloc( sizeof(dsd_cluster_send)
                       + 3*sizeof(dsd_gather_i_1) + 10*sizeof(char)
                       + ((dsd_cma1_ent *)ap_cma_entry)->inc_size_area );
   }

   adsl_cma_ent = (dsd_cma1_ent *) ap_cma_entry;
   /* fill structure */
   adsl_cluster_s->adsc_clact  = adsp_clact;
   adsl_cluster_s->amc_compl   = &m_send_compl2;
   adsl_cluster_s->vpc_userfld = NULL;
   adsl_cluster_s->iec_cl_type = ied_clty_cma;
   adsl_cluster_s->adsc_gai1_send      /* contains cma name + length   */
       = (dsd_gather_i_1 *) (adsl_cluster_s + 1);
   adsl_cluster_s->adsc_gai1_send->achc_ginp_cur
             = (char *) (adsl_cma_ent + 1);         /* name of cma     */
   adsl_cluster_s->adsc_gai1_send->achc_ginp_end
             = adsl_cluster_s->adsc_gai1_send->achc_ginp_cur
               + (*adsl_cluster_s->adsc_gai1_send->achc_ginp_cur + 1)
                                                      * sizeof(HL_WCHAR);
   adsl_cluster_s->adsc_gai1_send->adsc_next     /* contains lock info */
             = adsl_cluster_s->adsc_gai1_send + 1;
   if (iep_cma_msg == ied_cma_msg_upd_lock) {
     adsl_cluster_s->adsc_gai1_send->adsc_next->adsc_next
                 = NULL;
     achl1 = (char *) (adsl_cluster_s->adsc_gai1_send + 2);
     achl1 += 10;   /* to end of NHASN coding */
   }
   else { /* ied_cma_msg_upd_data */
     achl1 = (char *) (adsl_cluster_s->adsc_gai1_send + 3);
     achl1 += 10;   /* to end of NHASN coding */
     if (adsl_cma_ent->inc_size_area) {
       adsl_cluster_s->adsc_gai1_send->adsc_next->adsc_next
                 = adsl_cluster_s->adsc_gai1_send + 2;
       adsl_cluster_s->adsc_gai1_send->adsc_next->adsc_next->adsc_next
                 = NULL;

       /* append data to cluster message */
       memcpy(achl1, adsl_cma_ent->achc_area, adsl_cma_ent->inc_size_area);
       adsl_cluster_s->adsc_gai1_send->adsc_next->adsc_next->achc_ginp_cur
         = achl1;
       adsl_cluster_s->adsc_gai1_send->adsc_next->adsc_next->achc_ginp_end
         = achl1 + adsl_cma_ent->inc_size_area;
     }
     else { /* size of cma is 0 */
       adsl_cluster_s->adsc_gai1_send->adsc_next->adsc_next = NULL;
     }
   }
   adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_end = achl1;
   /* convert numbers to NHASN from last to first digit */
   ill_nhasn = adsl_cma_ent->inc_size_area;
   achl1 = m_conv_to_nhasn( achl1, ill_nhasn );
#ifdef CL_RET_TIME
   ill_nhasn = adsl_cma_ent->imc_retention_time;
   achl1 = m_conv_to_nhasn( achl1, ill_nhasn );
#endif
   achl1--;
   *achl1 = 0;                 /* dummy for epoch time */
   achl1--;

   *achl1 = iep_cma_msg;       /* type of message      */
   adsl_cluster_s->adsc_gai1_send->adsc_next->achc_ginp_cur = achl1;
   iml_rc = m_cluster_send(adsl_cluster_s);
   if (iml_rc) {       /* error - sending    */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_XYZ1,
       "xs-gw-cma1-02 m_cluster_send() has return code: %d  -%05d-",
       iml_rc, __LINE__ );
#endif
     /* error message is printed outside this function */
     return -1;
   }

   return 0;
}

/* KT-130114- changed ( see m_cma1_cluster_close() )
static void m_cleanup_lock_chain(struct dsd_double_chain *adsp_lock_chain) */
#ifdef OLD
static void m_cleanup_lock_chain(struct dsd_cluster_info *adsp_clinfo)
{
   struct dsd_cma_ext_lock *adsl_ext_lock;
   struct dsd_cma_ext_lock *adsl_ext_lock2;
   struct dsd_cma1_ent     *adsl_entry;
   struct dsd_elem_chain   *adsl_wait_entry;
   struct dsd_elem_chain   *adsl_wait_entry2;
   struct dsd_double_chain *adsl_lock_chain_start;
   struct dsd_double_chain *adsl_lock_chain;

   dss_cma1_co.dsc_critsect_1.m_enter();       /* critical section   */
   adsl_lock_chain_start = adsp_clinfo->adsc_active_locks;
   /* while (adsp_lock_chain) { (replace adsp_lock_chain with adsl_lock_chain_start) */
   while (adsl_lock_chain_start) {
     adsl_ext_lock = (dsd_cma_ext_lock *) adsl_lock_chain_start->ac_d_elem;
     adsl_wait_entry = adsl_ext_lock->adsc_wait_entry;
     adsl_entry = adsl_ext_lock->adsc_entry;
     adsl_ext_lock2 = adsl_entry->adsc_ext_chain;
     if (adsl_ext_lock == adsl_ext_lock2) {       /* remove ext lock   */
       while (adsl_wait_entry) {          /* post to waiting threads   */
         m_hco_wothr_post(NULL, (struct dsd_hco_wothr *)
                                               adsl_wait_entry->ac_elem);
         adsl_wait_entry2 = adsl_wait_entry;
         adsl_wait_entry = adsl_wait_entry->adsc_next;
         free(adsl_wait_entry2);
       }
       adsl_entry->adsc_ext_chain = adsl_ext_lock2->adsc_next;
       free(adsl_ext_lock);
       adsl_lock_chain = adsl_lock_chain_start;
       adsl_lock_chain_start = adsl_lock_chain_start->adsc_succ;
       //adsl_lock_chain_start->adsc_pred = NULL;
       free(adsl_lock_chain);
       continue;  // --> go to next entry
     }

     while (adsl_ext_lock2->adsc_next) {
       if (adsl_ext_lock == adsl_ext_lock2->adsc_next) { /* remove ext lock */
         while (adsl_wait_entry) {        /* post to waiting threads   */
           m_hco_wothr_post(NULL, (struct dsd_hco_wothr *)
                                               adsl_wait_entry->ac_elem);
           adsl_wait_entry2 = adsl_wait_entry;
           adsl_wait_entry = adsl_wait_entry->adsc_next;
           free(adsl_wait_entry2);
         }
         adsl_ext_lock2->adsc_next = adsl_ext_lock->adsc_next;
         free(adsl_ext_lock);
         adsl_lock_chain = adsl_lock_chain_start;
         adsl_lock_chain_start = adsl_lock_chain_start->adsc_succ;
         //adsl_lock_chain_start->adsc_pred = NULL;
         free(adsl_lock_chain);
         break;  // --> go to next entry
       }
       adsl_ext_lock2 = adsl_ext_lock2->adsc_next;
     }
     // if (adsl_ext_lock2 == NULL) --> error: entry not found
   }
   dss_cma1_co.dsc_critsect_1.m_leave();       /* critical section   */
}
#else
/* new version on 14.01.2014:
   Don't free any memory inside critical section.
   First only remove found external lock from the adsc_ext_chain of an cma entry.
   Post to all threads waiting for this lock.
   Remember pointer to adsp_clinfo->adsc_active_locks and than set it to null.
   Now leave critical section and free no longer used memory */
static void m_cleanup_lock_chain(struct dsd_cluster_info *adsp_clinfo)
{
   struct dsd_cma1_ent     *adsl_entry;
   struct dsd_double_chain *adsl_lock_chain_start; /* remember start pointer */
   struct dsd_double_chain *adsl_lock_chain;
   struct dsd_cma_ext_lock *adsl_ext_lock;      /* from active locks chain */
   struct dsd_cma_ext_lock *adsl_ext_lock2;     /* from chain of cma entry */
   struct dsd_elem_chain   *adsl_wait_entry;

   dss_cma1_co.dsc_critsect_1.m_enter();       /* critical section   */
   adsl_lock_chain_start = adsp_clinfo->adsc_active_locks;
   adsl_lock_chain = adsl_lock_chain_start;
   while (adsl_lock_chain) {
     //adsl_ext_lock = (dsd_cma_ext_lock *) adsl_lock_chain_start->ac_d_elem; (bug -170816-)
     adsl_ext_lock = (dsd_cma_ext_lock *) adsl_lock_chain->ac_d_elem;
     adsl_entry = adsl_ext_lock->adsc_entry;
     adsl_ext_lock2 = adsl_entry->adsc_ext_chain;

     /* remove adsl_ext_lock from adsc_ext_chain */
     if (adsl_ext_lock == adsl_ext_lock2) {  /* first in chain */
       adsl_entry->adsc_ext_chain = adsl_ext_lock2->adsc_next;
     }
     else {
       if (adsl_ext_lock2 == NULL) { /* KT -170816- check for null pointer */
         m_hlnew_printf( HLOG_XYZ1,
           "HWSPCMA1023W cleanup lock chain: lock 0X%X not found -%05d-", adsl_ext_lock, __LINE__ );
       } else {
         while (adsl_ext_lock2->adsc_next) {
           if (adsl_ext_lock == adsl_ext_lock2->adsc_next) {
             adsl_ext_lock2->adsc_next = adsl_ext_lock->adsc_next;
             //continue; (senseless to continue, because every adsl_ext_lock can be found only once KT -170816-)
             break;
           }
           adsl_ext_lock2 = adsl_ext_lock2->adsc_next;
         }
       }
     }

     /* post to all threads waiting for this lock */
     adsl_wait_entry = adsl_ext_lock->adsc_wait_entry;
     while (adsl_wait_entry) {          /* post to waiting threads   */
       m_hco_wothr_post(NULL, (struct dsd_hco_wothr *)adsl_wait_entry->ac_elem);
       adsl_wait_entry = adsl_wait_entry->adsc_next;
     }
     adsl_lock_chain = adsl_lock_chain->adsc_succ;
   }
   adsp_clinfo->adsc_active_locks = NULL;
   dss_cma1_co.dsc_critsect_1.m_leave();       /* critical section   */

   /* free memory */
   while (adsl_lock_chain_start) {
     struct dsd_elem_chain   *adsl_wait_entry2;

     adsl_ext_lock = (dsd_cma_ext_lock *) adsl_lock_chain_start->ac_d_elem;
     adsl_wait_entry = adsl_ext_lock->adsc_wait_entry;
     while (adsl_wait_entry) {
       adsl_wait_entry2 = adsl_wait_entry->adsc_next;
       free(adsl_wait_entry);
       adsl_wait_entry = adsl_wait_entry2;
     }
     free(adsl_ext_lock);
     adsl_lock_chain = adsl_lock_chain_start;
     adsl_lock_chain_start = adsl_lock_chain_start->adsc_succ;
     free(adsl_lock_chain);
   }
}
#endif

static inline char *m_conv_to_nhasn( char *achp1, HL_LONGLONG ilp_number )
{
   unsigned char ucl_more = 0;

   if (ilp_number < 0) {
     m_hlnew_printf( HLOG_XYZ1,
       "HWSPCMA1018W nhasn coding of negative number not defined -> replace with 0 -%05d-",
       __LINE__ );
     --achp1;
     *achp1 = 0;
     return achp1;
   }

   do {                                     /* loop output length NHASN */
     --achp1;
     *achp1 = (unsigned char) ((ilp_number & 0X7F) | ucl_more);
     ilp_number >>= 7;                      /* remove these bits       */
     ucl_more = 0X80;                       /* set more bit            */
   } while (ilp_number);

   return achp1;
}

static inline HL_LONGLONG m_conv_from_nhasn(struct dsd_gather_i_1 *adsp_gather)
{
   HL_LONGLONG ill_number = 0;


   adsp_gather->achc_ginp_cur--;
   do {
     adsp_gather->achc_ginp_cur++;
     while (adsp_gather->achc_ginp_cur >= adsp_gather->achc_ginp_end) {
       adsp_gather = adsp_gather->adsc_next;
       if (adsp_gather == NULL)
         return -1;   /* gather structure not complete */
     }

     ill_number <<= 7;                      /* shift old value         */
     ill_number
        |= *adsp_gather->achc_ginp_cur & 0X7F;  /* apply new bits      */
   } while ((*adsp_gather->achc_ginp_cur & 0X80) != 0);  /* while more bit set */
   adsp_gather->achc_ginp_cur++;  /* set pointer behind processed number */

   return ill_number;
}

static inline void m_remove_ext_lock( struct dsd_cma1_ent *adsp_entry,
                                 struct dsd_cma_ext_lock *adsp_ext_lock )
{
   struct dsd_cma_ext_lock *adsl_cur_lock;

   //dss_cma1_co.dsc_critsect_1.m_enter();       /* critical section     */
   adsl_cur_lock = adsp_entry->adsc_ext_chain;
   if (adsl_cur_lock == adsp_ext_lock) {
     adsp_entry->adsc_ext_chain = adsp_ext_lock->adsc_next;
     //free(adsp_ext_lock);
   }
   else {
     while (adsl_cur_lock->adsc_next) {
       if (adsl_cur_lock->adsc_next == adsp_ext_lock) {
         adsl_cur_lock->adsc_next = adsp_ext_lock->adsc_next;
         //free(adsp_ext_lock);
         break;
       }
       adsl_cur_lock = adsl_cur_lock->adsc_next;
     }
   }
   //dss_cma1_co.dsc_critsect_1.m_leave();       /* critical section     */
}
#else   /* not defined CLUSTER */
#ifndef D_SDHREF
/* connection to other cluster member is open                          */
extern "C" void m_cma1_cluster_open( struct dsd_cluster_active *adsp_clact ) {
#ifdef TRACEHL1
#ifndef D_SDHREF
   m_hlnew_printf( HLOG_XYZ1, "xswspcma-%05d-T m_cma1_cluster_open() entered", __LINE__ );
#else
   m_hl2_printf( "xswspcma-%05d-T m_cma1_cluster_open() entered", __LINE__ );
#endif
#endif
} /* end m_cma1_cluster_open()                                         */

/* connection to other cluster member is closed                        */
extern "C" void m_cma1_cluster_close( struct dsd_cluster_active *adsp_clact ) {
#ifdef TRACEHL1
#ifndef D_SDHREF
   m_hlnew_printf( HLOG_XYZ1, "xswspcma-%05d-T m_cma1_cluster_close() entered", __LINE__ );
#else
   m_hl2_printf( "xswspcma-%05d-T m_cma1_cluster_close() entered", __LINE__ );
#endif
#endif
} /* end m_cma1_cluster_close()                                        */

/* a logical block was reveived from other cluster member              */
extern "C" void m_cma1_cluster_recv( struct dsd_cluster_proc_recv *adsp_clprr ) {
#ifdef TRACEHL1
#ifndef D_SDHREF
   m_hlnew_printf( HLOG_XYZ1, "xswspcma-%05d-T m_cma1_cluster_recv() entered", __LINE__ );
#else
   m_hl2_printf( "xswspcma-%05d-T m_cma1_cluster_recv() entered", __LINE__ );
#endif
#endif
} /* end m_cma1_cluster_recv()                                         */
#endif

#endif  /* cluster */

#ifndef B150123
//#define TRACEHL1
extern "C" BOOL m_cma1_gen_dump_01( void * vpp_userfld, amd_dump_cma_01 amp_dump_cma_01 ) {
   BOOL       bol_rc;                       /* return code             */
   BOOL       bol_avl_first;                /* get first AVL tree entry */
   struct dsd_cma1_lock *adsl_cma1_lock_1;  /* working variable        */
   struct dsd_htree1_avl_work dsl_avl_work; /* working struct. for avl */
   struct dsd_cma_dump_01 dsl_cd01;         /* structure CMA dump      */

#ifdef TRACEHL1
#ifndef D_SDHREF
   m_hlnew_printf( HLOG_TRACE1, "xswspcma-%05d-T m_cma1_gen_dump_01() called", __LINE__ );
#else
   m_hl2_printf( "xswspcma-%05d-T m_cma1_gen_dump_01() called", __LINE__ );
#endif
#endif
   bol_avl_first = TRUE;                    /* get first AVL tree entry */
   dss_cma1_co.dsc_critsect_1.m_enter();    /* critical section        */

   p_get_20:                                /* get next entry          */
   bol_rc = m_htree1_avl_getnext( NULL, &dss_cma1_co.dsc_avl_cntl,
                                  &dsl_avl_work, bol_avl_first );
   if (dsl_avl_work.adsc_found == NULL) {
     goto p_get_80;                         /* E-O-F end of file / CMA */
   }
   bol_avl_first = FALSE;                   /* get first AVL tree entry */
#define ADSL_CMA1_ENT_G ((struct dsd_cma1_ent *) ((char *) dsl_avl_work.adsc_found - offsetof( struct dsd_cma1_ent, dsc_htree1 )))
   memset( &dsl_cd01, 0, sizeof(struct dsd_cma_dump_01) );  /* structure CMA dump */
   /* name of entry                                                    */
   dsl_cd01.dsc_ucs_name.ac_str = (HL_WCHAR *) (ADSL_CMA1_ENT_G + 1) + 1;
   dsl_cd01.dsc_ucs_name.imc_len_str = *((unsigned char *) (ADSL_CMA1_ENT_G + 1));
   dsl_cd01.dsc_ucs_name.iec_chs_str = ied_chs_utf_16;
   /* other fields                                                     */
   dsl_cd01.imc_size_area = ADSL_CMA1_ENT_G->inc_size_area;  /* size of area */
   dsl_cd01.ilc_epoch_last_used = ADSL_CMA1_ENT_G->ilc_epoch_last_used;  /* save EPOCH entry last used */
// to-do 25.01.15 - milliseconds
   dsl_cd01.ilc_epoch_last_used *= 1000;
   dsl_cd01.imc_retention_time = ADSL_CMA1_ENT_G->imc_retention_time;  /* retention time in seconds */
   dsl_cd01.achc_area = ADSL_CMA1_ENT_G->achc_area;  /* area cma       */
   adsl_cma1_lock_1 = (struct dsd_cma1_lock *) (ADSL_CMA1_ENT_G->vpc_lock_chain);
   while (adsl_cma1_lock_1) {               /* test for global lock and no share */
     dsl_cd01.imc_no_locks++;               /* number of locks         */
     adsl_cma1_lock_1 = adsl_cma1_lock_1->adsc_next;  /* get next in chain */
   }
#undef ADSL_CMA1_ENT_G
   amp_dump_cma_01( vpp_userfld, &dsl_cd01 );
   goto p_get_20;                           /* get next entry          */

   p_get_80:                                /* E-O-F end of file / CMA */
   dss_cma1_co.dsc_critsect_1.m_leave();    /* critical section        */
   return TRUE;                             /* all done                */
} /* end m_cma1_trace()                                                */
#endif

#ifdef PROBLEM_090226                       /* KDRS - deadlock - Web-Server hangs */
/* return the Epoch value in milliseconds                              */
static HL_LONGLONG m_get_epoch_ms( void ) {
#ifndef HL_UNIX
   struct __timeb64 timebuffer;

   _ftime64( &timebuffer );

#ifdef B090211
   return ( timebuffer.time * 1000 - timebuffer.timezone * 60 * 1000 + timebuffer.millitm );
#else
   return ( timebuffer.time * 1000 + timebuffer.millitm );
#endif
#else
   struct timeval dsl_timeval;

   gettimeofday( &dsl_timeval, NULL );
   return (dsl_timeval.tv_sec * 1000 + dsl_timeval.tv_usec / 1000);
#endif
} /* end m_get_epoch_ms()                                              */
#endif
