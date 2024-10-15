//#define WOTHR_LOCK_FREE
#ifdef TO_DO
--- 02.03.12 ---
statistic struct dsd_tich2_ele
struct dsd_tich2_ele managed in one or two AVL-trees
one of them: time-frame when timer elapses
--- 14.10.15 ---
extern struct dsd_hco_main dsg_hco_main
--->
extern "C" struct dsd_hco_main dsg_hco_main
---
extern "C" void m_hco_wothr_active( struct dsd_hco_wothr *adsp_hco_wothr )
--->
extern "C" void m_hco_wothr_active( struct dsd_hco_wothr *adsp_hco_wothr, BOOL bop_force = FALSE )
--- 13.02.16 ---
extern struct dsd_hco_main dsg_hco_main -> extern "C" struct dsd_hco_main dsg_hco_main
#endif
//#define TRACEHL_WACHA_1
//#define PROBLEM_090226                      /* KDRS - deadlock - Web-Server hangs */
#define PROBLEM_090305                      /* KDRS - deadlock - Web-Server hangs */
//#define TRACE_TIMER_1
//#define TRACE_TIMER_2
//#define D_STRESS_TEST_THR_1
//#define CHECKTHRACT
//#define TRACEHL1
//#define HELP_DEBUG                          /* 05.07.06 KB - help in tracing */
//#define B071120                             /* is there really a problem ? 03.12.07 KB */
//#define DEB_071204_01                       /* help debugging          */
#ifdef TRACE_TIMER_2
#define TRACE_TIMER_1
#endif
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xslcontr                                            |*/
/*| -------------                                                     |*/
/*|  HOB common library - control                                     |*/
/*|  Work Threads and Timers                                          |*/
/*|  Project WSP, WSPnG, HCU2 and HL-VPN V2                           |*/
/*|  KB 04.08.05                                                      |*/
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
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|  Copyright (C) HOB Germany 2016                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio .NET 2003                                       |*/
/*|  MS Visual Studio 2005                                            |*/
/*|  MS Visual Studio 2012                                            |*/
/*|  GCC all versions                                                 |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifdef WOTHR_LOCK_FREE
/**
 * there are two structures for the backlog of work
 * when no work-thread is free:
 *   struct dsd_hco_waitwth                 -- wait for thread         --
 *   struct dsd_hco_fifo_ele                -- FIFO element            --
 * and so there are two queues for unused elements:
 *   aas_free_waiting_ctrl                  -- control of free blocks waiting --
 *   aas_hco_fifo_ele_ctrl                  -- control of fifo elements waiting --
 * when aas_free_waiting_ctrl is not empty,
 * aas_hco_fifo_ele_ctrl also needs to contain elements,
 * otherwise there will be problems.
*/
#endif
/* #define TRACEHL1 */
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
#ifdef HL_FREEBSD
#define HL_THRID m_gettid()
#include <sys/thr.h>
static pid_t m_gettid( void );
#endif
#ifdef HL_LINUX
#define HL_THRID syscall( __NR_gettid )
#endif
#endif

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef HL_UNIX
#include <conio.h>
#endif
#include <time.h>
#include <sys/timeb.h>
//#include <wchar.h>
#ifndef HL_UNIX
#include <windows.h>
//#include <iswcord1.h>
#include <hob-xslhcla1.hpp>
#include <hob-xslcontr.h>
#else
#include <errno.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <pthread.h>
#ifdef HL_LINUX
#include <sys/syscall.h>
#endif
#include "hob-unix01.h"
#include "hob-xslhcla1.hpp"
#include "hob-xslcontr.h"
#endif
#ifdef XYZ1
#include <hob-thread.hpp>
#endif

/*+-------------------------------------------------------------------+*/
/*| Definitions for the Compiler.                                     |*/
/*+-------------------------------------------------------------------+*/

#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif

#ifndef WIN64
typedef long int dsd_time_1;
#else
typedef __int64 dsd_time_1;
#endif

#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif

#ifdef HL_UNIX
//#ifdef HL_AIX
#define INFTIM         -1                   /* value for IP            */
//#endif
#define INFINITE       INFTIM
#endif

#ifndef HL_UNIX
#define HL_THRID GetCurrentThreadId()
#else
#ifndef HL_LINUX
#define HL_THRID m_gettid()
#else
#define HL_THRID syscall( __NR_gettid )
#endif
#endif

#ifdef HL_HPUX
#define STACK_SIZE (512 * 1024)
#endif

#define D_WACHA_INTV_INIT  5
#define D_WACHA_INTV_INCR  10

/*+-------------------------------------------------------------------+*/
/*| Function Calls definitions.                                       |*/
/*+-------------------------------------------------------------------+*/

#ifdef WOTHR_LOCK_FREE
extern "C" void * m_hl_get_chain( void ** );
extern "C" void m_hl_put_chain( void **, void * );
extern "C" void * m_hl_check_chain( void ** );
extern "C" void * m_hl_get_fifo( void ** );
extern "C" void m_hl_put_fifo( void **, void * );
extern "C" void * m_hl_check_fifo( void ** );
extern "C" void m_hl_lock_inc_1( int * );
extern "C" void m_hl_lock_dec_1( int * );
extern "C" void m_hl_lock_inc_2( void ** );
#endif

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

static htfunc1_t m_work_thread( void * );
#ifdef CHECKTHRACT
static void m_count_active( int, char * );  /* check active threads    */
#endif
#ifdef HOB_CONTR_TIMER
static struct dsd_tich2_ele * m_tich2_alloc( void );
static void m_tich2_free( struct dsd_tich2_ele * );
static htfunc1_t m_timer_thr( void * );
#ifdef TRACE_TIMER_1
static int m_check_timer_chain( int, char * );
#endif
#endif
static void m_hco_put_chain_wothr( struct dsd_call_para_1 *, struct dsd_hco_wothr * );

/*+-------------------------------------------------------------------+*/
/*| Constant data.                                                    |*/
/*+-------------------------------------------------------------------+*/

#ifdef HOB_CONTR_TIMER
#define DEF_TICH2_NO_FREE 32                /* number of elements in group */
#endif

#define NO_WAIT_THR_S    32                 /* no of waiting thread b  */

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

/*+-------------------------------------------------------------------+*/
/*| global used dsects = structures.                                  |*/
/*+-------------------------------------------------------------------+*/

/* The following structure contains data for a thread becoming idle,
   this thread will get new work from this queue.                      */
struct dsd_hco_waitwth {                    /* wait for thread         */
#ifndef WOTHR_LOCK_FREE
   struct dsd_hco_waitwth *adsc_next;       /* chain                   */
#endif
   struct dsd_hco_wothr *adsc_hco_wothr;    /* thread active / block   */
   struct dsd_call_para_1 dsc_call_para_1;  /* call parameters         */
// struct dsd_hco_waitwth *adsc_ch_spec;    /* chain special entry     */
};

#ifdef WOTHR_LOCK_FREE
struct dsd_hco_fifo_ele {                   /* FIFO element            */
   void *     vpc_filler_01;                /* for next field          */
   void *     vpc_filler_02;                /* for counter             */
   struct dsd_hco_waitwth *adsc_waitwth;    /* real element            */
   void *     vpc_filler_03;                /* unsed - alignment       */
};
#endif

/* The following structure is user for the timer functions             */
struct dsd_tich2_ele {                      /* for timers / chain 2    */
   HL_LONGLONG ilcwaitmsec;                 /* wait in milliseconds    */
#define B071204_B
#ifdef B071204_B
   HL_LONGLONG ilcendtime;                  /* epoch end of timer      */
#endif
   struct dsd_tich2_ele *adsc_next;         /* for chaining            */
   volatile struct dsd_timer_ele *adsctiele_first;  /* first element in chain */
   struct dsd_timer_ele *adsctiele_last;    /* last element in chain   */
};

/*+-------------------------------------------------------------------+*/
/*| Internal used classes.                                            |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

#ifndef WOTHR_LOCK_FREE
static struct dsd_hco_waitwth *adss_waitwth_free = NULL;  /* chain of free elements */
static struct dsd_hco_waitwth *adss_waitwth_proc_first = NULL; /* chain to process */
static struct dsd_hco_waitwth *adss_waitwth_proc_last;  /* last to process */
#endif
static class dsd_hcla_critsect_1 dss_critsect_wothr;  /* critical section WORK_T */
#ifdef XYZ1
#ifdef CHECKWAITTH
static int ins_count_waitwth = 0;
#endif
#ifdef TRACEHL1
static int is_count_memory = 0;
#endif
#endif
#ifdef DEB_071204_01
static int iss_timer_c1_1 = 0;
#endif

extern "C" int m_hl1_printf( char *aptext, ... );

// to-do 17.05.16 KB - should be extern "C"
extern struct dsd_hco_main dsg_hco_main = {  /* HOB control main structure */
   0,      /* imc_max_poss_workthr             max possible work thr   */
   0,      /* imc_max_act_workthr              max active work thr     */
   0,      /* imc_workthr_alloc                allocated work threads  */
   0,      /* imc_workthr_sched                scheduled work threads  */
   0,      /* imc_workthr_active               active work threads     */
   0,      /* imc_workque_sched                work queue scheduled    */
   0,      /* imc_workque_max_no               work queue maximum      */
   (time_t) 0,  /* time_t dsc_workque_max_time for time of maximum     */
   (struct dsd_hco_wothr *) NULL,  /* struct dsd_hco_wothr *adsc_hco_wothr_anchor; anchor of chain */
   (struct dsd_hco_wothr *) NULL,  /* struct dsd_hco_wothr *adsc_hco_wothr_free; free work thread */
   DEF_PRIO_DEFAULT,  /* imc_prio_thr          priority work thread    */
   NULL    /* amc_func_thr_sta                 function to call at thread start */
};

static BOOL   bos_end_proc = FALSE;         /* signal end of processing */

#ifdef WOTHR_LOCK_FREE
static void * vprs_thread_idle_var[ 8 ] = { 0, 0, 0, 0, 0, 0, 0, 0 };  /* variables for idle threads */
static void ** aas_thread_idle_ctrl;        /* control of idle threads */
static void * vprs_thread_backlog_var[ 8 ] = { 0, 0, 0, 0, 0, 0, 0, 0 };  /* variables for thread-backlog */
#ifdef B151215
static void * vprs_thread_backlog_ele[ 7 ] = { 0, 0, 0, 0, 0, 0, 0 };  /* variables for null element */
#else
static void * vprs_thread_backlog_ele[ 8 ] = { 0, 0, 0, 0, 0, 0, 0,0 };  /* variables for null element */
#endif
static void ** aas_thread_backlog_ctrl;     /* control of thread-backlog */
static void * vprs_free_waiting_var[ 8 ] = { 0, 0, 0, 0, 0, 0, 0, 0 };  /* variables for free blocks waiting */
static void ** aas_free_waiting_ctrl;       /* control of free blocks waiting */
static void * vprs_hco_fifo_ele_var[ 9 ] = { 0 };  /* variables for fifo elements waiting */
static void ** aas_hco_fifo_ele_ctrl;       /* control of fifo elements waiting */
#endif

#ifdef HOB_CONTR_TIMER
static class dsd_hcla_critsect_1 dss_critsect_timer;  /* critical section for timer */
//hs_eve_timer
static class dsd_hcla_event_1 dss_event_timer;  /* event for timer     */
static class dsd_hcthread dss_hcthread_timer;  /* Thread Functions Timer */
static volatile struct dsd_tich2_ele *adssticha_anchor = NULL;  /* anchor of chain timer 2 */
static struct dsd_tich2_ele *adssticha_free = NULL;  /* anchor of free elements chain timer 2 */
#endif
/*+-------------------------------------------------------------------+*/
/*| Procedure Sections.                                               |*/
/*+-------------------------------------------------------------------+*/

/**
* m_hco_init()
* initialize HOB Control
* parameter 1 = max possible work threads
* parameter 2 = max active work threads
*/
extern "C" void m_hco_init( int imp_max_poss_workthr, int imp_max_act_workthr) {
#ifdef HOB_CONTR_TIMER
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */
#endif

#ifdef TRACEHL1
   m_hl1_printf( "xslcontr l%05d m_hco_init() called", __LINE__ );
#endif
   dsg_hco_main.imc_max_poss_workthr = imp_max_poss_workthr;
   dsg_hco_main.imc_max_act_workthr = imp_max_act_workthr;
#ifdef WOTHR_LOCK_FREE
   /* align to 16 bytes                                                */
   aas_thread_idle_ctrl = (void **) (((size_t) &vprs_thread_idle_var[ 1 ]) & (0 - 2 * sizeof(void *)));
   /* align to 16 bytes                                                */
   aas_thread_backlog_ctrl = (void **) (((size_t) &vprs_thread_backlog_var[ 1 ]) & (0 - 2 * sizeof(void *)));
   /* set head and tail to null element                                */
#ifdef B151215
   *(aas_thread_backlog_ctrl + 0) = vprs_thread_backlog_ele;
   *(aas_thread_backlog_ctrl + 2) = vprs_thread_backlog_ele;
#else
   *(aas_thread_backlog_ctrl + 0)
     = *(aas_thread_backlog_ctrl + 2)
         = (void *) (((size_t) &vprs_thread_backlog_ele[ 1 ]) & (0 - 2 * sizeof(void *)));
#endif
   /* align to 16 bytes                                                */
   aas_free_waiting_ctrl = (void **) (((size_t) &vprs_free_waiting_var[ 1 ]) & (0 - 2 * sizeof(void *)));
   /* align to 16 bytes                                                */
#ifdef B160517
   aas_hco_fifo_ele_ctrl = (void **) (((size_t) &vprs_free_waiting_var[ 1 ]) & (0 - 2 * sizeof(void *)));
#endif
   aas_hco_fifo_ele_ctrl = (void **) (((size_t) &vprs_hco_fifo_ele_var[ 1 ]) & (0 - 2 * sizeof(void *)));
#endif
   dss_critsect_wothr.m_create();           /* critical section for Work-Threads */
#ifdef HOB_CONTR_TIMER
   dss_critsect_timer.m_create();           /* critical section for timer */
   iml_rc1 = dss_event_timer.m_create( &iml_rc2 );  /* event for timer */
   if (iml_rc1 < 0) {                       /* error occured           */
     m_hl1_printf( "xslcontr-%05d-W m_hco_init timer m_create Return Code %d Error %d",
                   __LINE__, iml_rc1, iml_rc2 );
   }
   iml_rc1 = dss_hcthread_timer.mc_create( &m_timer_thr, NULL );
   if (iml_rc1 < 0) {
     m_hl1_printf( "xslcontr-%05d-W m_hco_init timer CreateThread Error", __LINE__ );
   }
#endif
} /* end m_hco_init()                                                  */

/** shut down HOB Control                                              */
extern "C" void m_hco_shutdown( void ) {    /* shutdown HOB Control    */
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */
   struct dsd_hco_wothr *adsl_hco_wothr_w1;  /* address work thread    */

#ifdef TRACEHL1
   m_hl1_printf( "xslcontr l%05d m_hco_shutdown() called", __LINE__ );
#endif
   bos_end_proc = TRUE;                     /* end of processing       */
   adsl_hco_wothr_w1 = dsg_hco_main.adsc_hco_wothr_free;  /* get free work thread */
   while (adsl_hco_wothr_w1) {              /* for all free threads    */
     if (adsl_hco_wothr_w1->boc_thr_close == FALSE) {  /* thread not closed */
       iml_rc1 = adsl_hco_wothr_w1->dsc_event.m_post( &iml_rc2 );  /* event of thread */
       if (iml_rc1 < 0) {                     /* error occured           */
         m_hl1_printf( "xslcontr-%05d-W m_hco_shutdown thread m_post Return Code %d Error %d",
                       __LINE__, iml_rc1, iml_rc2 );
       }
     }
     adsl_hco_wothr_w1 = adsl_hco_wothr_w1->adsc_ch_free;
   }
#ifdef HOB_CONTR_TIMER
   iml_rc1 = dss_event_timer.m_post( &iml_rc2 );  /* event for timer   */
   if (iml_rc1 < 0) {                       /* error occured           */
     m_hl1_printf( "xslcontr-%05d-W m_hco_shutdown timer m_post Return Code %d Error %d",
                   __LINE__, iml_rc1, iml_rc2 );
   }
#endif
#ifndef HL_UNIX
   Sleep( 500 );                            /* wait till threads have ended */
#else
   sleep( 1 );                              /* wait till threads have ended */
#endif
   while (dsg_hco_main.adsc_hco_wothr_free) {  /* for all free threads */
     adsl_hco_wothr_w1 = dsg_hco_main.adsc_hco_wothr_free;  /* get free work thread */
     dsg_hco_main.adsc_hco_wothr_free = adsl_hco_wothr_w1->adsc_ch_free;
     free( adsl_hco_wothr_w1 );             /* free memory of thread   */
   }
   iml_rc1 = dss_critsect_wothr.m_close();
#ifdef HOB_CONTR_TIMER
   iml_rc1 = dss_critsect_timer.m_close();  /* critical section for timer */
#endif
} /* end m_hco_shutdown()                                              */

/** set priority of work threads                                       */
extern "C" void m_hco_set_prio_thr( int imp_prio ) {
   dsg_hco_main.imc_prio_thr = imp_prio;
} /* end m_hco_set_prio_thr()                                          */

/** set function to call at thread start                               */
extern "C" void m_hco_set_thr_sta_func( md_func_thr_sta amc_func_thr_sta ) {
   dsg_hco_main.amc_func_thr_sta = amc_func_thr_sta;
} /* end m_hco_set_thr_sta_func()                                      */

#ifndef WOTHR_LOCK_FREE
/** schedule some piece of work to be run on a work-thread             */
extern "C" void m_hco_run_thread( struct dsd_call_para_1 *adsp_call_para_1 ) {
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */
   struct dsd_hco_wothr *adsl_hco_wothr_w1;  /* address work thread    */
   struct dsd_hco_wothr *adsl_hco_wothr_new;  /* address work thread new */
// struct dsd_hco_waitwth *dsl_waitwth_1_1;   /* address wait for thread */

#ifdef TRACEHL1
   m_hl1_printf( "m_hco_run_thread start amc_function=%p apparam1=%p apparam2=%p apparam3=%p",
                 adsp_call_para_1->amc_function,
                 adsp_call_para_1->ac_param_1,
                 adsp_call_para_1->ac_param_2,
                 adsp_call_para_1->ac_param_3 );
#endif
#ifdef WOTHR_LOCK_FREE
   /* check if we can get free thread in linked list                   */
#endif
   adsl_hco_wothr_w1 = NULL;                /* no thread idle found    */
   adsl_hco_wothr_new = NULL;               /* address work thread new */
   dss_critsect_wothr.m_enter();            /* critical section        */
   if (dsg_hco_main.imc_workthr_active < dsg_hco_main.imc_max_act_workthr) {
     if (dsg_hco_main.adsc_hco_wothr_free) {  /* free thread found     */
       adsl_hco_wothr_w1 = dsg_hco_main.adsc_hco_wothr_free;  /* get free work thread */
       dsg_hco_main.adsc_hco_wothr_free = dsg_hco_main.adsc_hco_wothr_free->adsc_ch_free;
     }
   }
   if (adsl_hco_wothr_w1) {                 /* thread idle found       */
     adsl_hco_wothr_w1->dsc_call_para_1 = *adsp_call_para_1;  /* set parameters */
     adsl_hco_wothr_w1->boc_active = TRUE;  /* thread is active        */
     dsg_hco_main.imc_workthr_active++;     /* active work threads     */
     dsg_hco_main.imc_workthr_sched++;      /* scheduled work threads  */
   } else {                                 /* no thread free          */
#ifdef TRACEHLX
         int ih1 = 0;                       /* count threads           */
         adsl_hco_wothr_w1 = dsg_hco_main.adsc_hco_wothr_anchor;         /* get anchor of chain     */
         while (adsl_hco_wothr_w1) {             /* loop over all threads   */
           /* Attentent printf() 03.08.06 KB / SR */
           m_hl1_printf( "+++ check thread no=%d / %08X clconn1=%08X act=%08X time=%08X",
                             ih1 + 1, adsl_hco_wothr_w1,
                             adsl_hco_wothr_w1->ad_clconn1,
                             adsl_hco_wothr_w1->trace_act, adsl_hco_wothr_w1->trace_time );
           ih1++;
           adsl_hco_wothr_w1 = adsl_hco_wothr_w1->next;  /* get next in chain    */
         }
         m_hl1_printf( "create new thread / no=%d", ih1 + 1 );
#endif
     if (   (dsg_hco_main.imc_workthr_alloc < dsg_hco_main.imc_max_poss_workthr)
         && (dsg_hco_main.imc_workthr_active < dsg_hco_main.imc_max_act_workthr)) {
       adsl_hco_wothr_new = (struct dsd_hco_wothr *) malloc( sizeof(struct dsd_hco_wothr) );
       adsl_hco_wothr_new->dsc_call_para_1 = *adsp_call_para_1;  /* set parameters */
       adsl_hco_wothr_new->boc_active = TRUE;  /* thread is active     */
       adsl_hco_wothr_new->boc_thr_close = FALSE;  /* thread not closed */
#ifdef XYZ1
       adsl_hco_wothr_new->adsc_waitwth_1 = NULL;  /* address wait for thread */
#endif
       dsg_hco_main.imc_workthr_alloc++;    /* count allocated work th */
       dsg_hco_main.imc_workthr_active++;   /* active work threads     */
       dsg_hco_main.imc_workthr_sched++;    /* scheduled work threads  */
       adsl_hco_wothr_new->adsc_next = dsg_hco_main.adsc_hco_wothr_anchor;  /* set anchor of chain */
       dsg_hco_main.adsc_hco_wothr_anchor = adsl_hco_wothr_new;  /* set new start chain */
     } else {
       m_hco_put_chain_wothr( adsp_call_para_1, NULL );
     }
   }
   dss_critsect_wothr.m_leave();            /* critical section        */
   if (adsl_hco_wothr_w1) {                 /* thread idle found       */
     iml_rc1 = adsl_hco_wothr_w1->dsc_event.m_post( &iml_rc2 );  /* set event of thread */
     if (iml_rc1 < 0) {                     /* error occured           */
       m_hl1_printf( "xslcontr-%05d-W m_hco_run_thread event m_post Return Code %d Error %d",
                     __LINE__, iml_rc1, iml_rc2 );
     }
   }
   if (adsl_hco_wothr_new) {                 /* address work thread new */
     iml_rc1 = adsl_hco_wothr_new->dsc_event.m_create( &iml_rc2 );  /* event of thread */
     if (iml_rc1 < 0) {                     /* error occured           */
       m_hl1_printf( "xslcontr-%05d-W m_hco_run_thread event m_create Return Code %d Error %d",
                     __LINE__, iml_rc1, iml_rc2 );
     }
#ifdef TRACEHL1
     m_hl1_printf( "run_thread before Thread.Create" );
#endif
#ifndef HL_HPUX
     iml_rc1 = adsl_hco_wothr_new->dsc_hcthread.mc_create( &m_work_thread, (void *) adsl_hco_wothr_new );
#else
     iml_rc1 = adsl_hco_wothr_new->dsc_hcthread.mc_create( &m_work_thread,
                                                           (void *) adsl_hco_wothr_new,
                                                           STACK_SIZE );
#endif
     if (iml_rc1 < 0) {
       m_hl1_printf( "xslcontr-%05d-W m_hco_run_thread CreateThread Error", __LINE__ );
     }
   }
} /* end m_hco_run_thread()                                            */

/** put request in chain of backlog for work-threads                   */
static void m_hco_put_chain_wothr( struct dsd_call_para_1 *adsp_call_para_1,
                                   struct dsd_hco_wothr *adsp_hco_woth ) {
   int        inl1;                         /* working variable        */
   struct dsd_hco_waitwth *adsl_waitwth_1_w1;  /* address wait for thread */

   dsg_hco_main.imc_workque_sched++;        /* work queue scheduled    */
   if (dsg_hco_main.imc_workque_max_no < dsg_hco_main.imc_workque_sched) {  /* work queue maximum */
     time( &dsg_hco_main.dsc_workque_max_time );  /* get current time  */
     dsg_hco_main.imc_workque_max_no = dsg_hco_main.imc_workque_sched;  /* set new queue maximum */
   }
   if (adss_waitwth_free == NULL) {         /* chain of free elements  */
#ifdef TRACEHLA
     m_hl1_printf( "acquire new area for adss_waitwth_free chain" );
#endif
     adss_waitwth_free = (struct dsd_hco_waitwth *) malloc( NO_WAIT_THR_S * sizeof(struct dsd_hco_waitwth) );
     adsl_waitwth_1_w1 = adss_waitwth_free;  /* get first              */
     inl1 = NO_WAIT_THR_S - 1;              /* no of waiting thread b  */
     while (inl1) {
       adsl_waitwth_1_w1->adsc_next = adsl_waitwth_1_w1 + 1;  /* here is next element */
       adsl_waitwth_1_w1++;                 /* point to next element   */
       inl1--;
     }
     adsl_waitwth_1_w1->adsc_next = NULL;   /* set end of chain        */
   }
#ifdef CHECKWAITTH
   ins_count_waitwth++;
#endif
   adsl_waitwth_1_w1 = adss_waitwth_free;   /* get first               */
   adss_waitwth_free = adsl_waitwth_1_w1->adsc_next;  /* get next in chain */
   /* set work to do                                                   */
   adsl_waitwth_1_w1->dsc_call_para_1 = *adsp_call_para_1;
   adsl_waitwth_1_w1->adsc_hco_wothr = adsp_hco_woth;  /* thread active / block */
   adsl_waitwth_1_w1->adsc_next = NULL;     /* is last in chain now    */
#ifdef XYZ1
   adsl_waitwth_1_w1->adsc_ch_spec = NULL;  /* chain special entry     */
#endif
   if (adss_waitwth_proc_first == NULL) {   /* chain to process        */
     adss_waitwth_proc_first = adsl_waitwth_1_w1;  /* set first in chain */
   } else {
     adss_waitwth_proc_last->adsc_next = adsl_waitwth_1_w1;  /* set in chain */
   }
   adss_waitwth_proc_last = adsl_waitwth_1_w1;  /* set last to process */
} /* end m_hco_put_chain_wothr()                                       */

/** mark work-thread as blocking                                       */
extern "C" void m_hco_wothr_blocking( struct dsd_hco_wothr *adsp_hco_wothr ) {
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */
   struct dsd_hco_wothr *adsl_hco_wothr_w1;  /* working variable       */
   struct dsd_hco_wothr *adsl_hco_wothr_new;  /* address work thread new */
   struct dsd_hco_waitwth *adsl_waitwth_1_w1;  /* address wait for thread */

#ifdef TRACEHL1
   m_hl1_printf( "m_hco_wothr_blocking() called %p", adsp_hco_wothr );
#endif
#ifdef CHECKTHRACT
   if (adsp_hco_wothr->boc_active == FALSE) {  /* this thread not active  */
     m_hl1_printf( "m_hco_wothr_blocking() called %p - invalid, already blocking", adsp_hco_wothr );
     return;
   }
#endif
   adsp_hco_wothr->boc_active = FALSE;      /* this thread not active  */
   adsl_hco_wothr_w1 = NULL;                /* no thread to activate   */
   adsl_hco_wothr_new = NULL;               /* address work thread new */
   iml_rc1 = dss_critsect_wothr.m_enter();
   if (   (adss_waitwth_proc_first)         /* something to process    */
       && (dsg_hco_main.imc_workthr_active <= dsg_hco_main.imc_max_act_workthr)) {
#ifdef TRACEHL1
     m_hl1_printf( "m_hco_wothr_blocking() activates work from chain" );
#endif
     adsl_waitwth_1_w1 = adss_waitwth_proc_first;  /* get first in chain */
     if (adsl_waitwth_1_w1->adsc_hco_wothr == NULL) {  /* not special thread */
//     adsl_hco_wothr_w1 = dsg_hco_main.adsc_hco_wothr_anchor;  /* get anchor of chain */
       while (dsg_hco_main.adsc_hco_wothr_free) {  /* free thread found */
         adsl_hco_wothr_w1 = dsg_hco_main.adsc_hco_wothr_free;  /* get free work thread */
         dsg_hco_main.adsc_hco_wothr_free = dsg_hco_main.adsc_hco_wothr_free->adsc_ch_free;
         adsl_hco_wothr_w1->dsc_call_para_1 = adsl_waitwth_1_w1->dsc_call_para_1;
         adsl_hco_wothr_w1->boc_active = TRUE;  /* thread is active    */
         dsg_hco_main.imc_workthr_sched++;  /* scheduled work threads  */
/* UUUU 15.10.06 KB */
//       dsg_hco_main.imc_workthr_active++;  /* active work threads    */
/* UUUU 15.10.06 KB */
         adss_waitwth_proc_first = adsl_waitwth_1_w1->adsc_next;  /* remove from chain */
         dsg_hco_main.imc_workque_sched--;  /* work queue scheduled    */
         adsl_waitwth_1_w1->adsc_next = adss_waitwth_free;  /* get old chain free */
         adss_waitwth_free = adsl_waitwth_1_w1;  /* set new chain free */
#ifdef CHECKWAITTH
         ins_count_waitwth--;
#ifndef TRACEHL1
         m_hl1_printf( "ins_count_waitwth-- --> %d / workque_sched=%d / workthr_active=%d / workthr_sched=%d m_workth_set_block() 1",
                       ins_count_waitwth,
                       dsg_hco_main.imc_workque_sched,
                       dsg_hco_main.imc_workthr_active,  /* active work threads     */
                       dsg_hco_main.imc_workthr_sched );  /* scheduled work threads */
#endif
#endif
         break;
       }
       while (   (adsl_hco_wothr_w1 == NULL)  /* no thread idle found  */
              && (dsg_hco_main.imc_workthr_alloc < dsg_hco_main.imc_max_poss_workthr)) {
         /* create new thread                                          */
         adsl_hco_wothr_new = (struct dsd_hco_wothr *) malloc( sizeof(struct dsd_hco_wothr) );
         adsl_hco_wothr_new->dsc_call_para_1 = adsl_waitwth_1_w1->dsc_call_para_1;
         adsl_hco_wothr_new->boc_active = TRUE;  /* thread is active    */
         adsl_hco_wothr_new->boc_thr_close = FALSE;  /* thread not closed */
#ifdef XYZ1
         adsl_hco_wothr_new->adsc_waitwth_1 = NULL;  /* address wait for thread */
#endif
         dsg_hco_main.imc_workthr_alloc++;  /* count allocated work th */
         dsg_hco_main.imc_workthr_sched++;  /* scheduled work threads  */
/* UUUU 15.10.06 KB */
//       dsg_hco_main.imc_workthr_active++;  /* active work threads    */
/* UUUU 15.10.06 KB */
         adsl_hco_wothr_new->adsc_next = dsg_hco_main.adsc_hco_wothr_anchor;  /* set anchor of chain */
         dsg_hco_main.adsc_hco_wothr_anchor = adsl_hco_wothr_new;  /* set new start chain */
         dsg_hco_main.imc_workque_sched--;  /* work queue scheduled    */
         /* remove this entry from wait list                           */
         adsl_hco_wothr_w1 = adsl_waitwth_1_w1->adsc_hco_wothr;  /* thread to activate */
         adss_waitwth_proc_first = adsl_waitwth_1_w1->adsc_next;  /* remove from chain */
         adsl_waitwth_1_w1->adsc_next = adss_waitwth_free;  /* get old chain free */
         adss_waitwth_free = adsl_waitwth_1_w1;  /* set new chain free  */
#ifdef CHECKWAITTH
         ins_count_waitwth--;
#ifndef TRACEHL1
         m_hl1_printf( "ins_count_waitwth-- --> %d / workque_sched=%d / workthr_active=%d / workthr_sched=%d m_workth_set_block() 2",
                       ins_count_waitwth,
                       dsg_hco_main.imc_workque_sched,
                       dsg_hco_main.imc_workthr_active,  /* active work threads     */
                       dsg_hco_main.imc_workthr_sched );  /* scheduled work threads */
#endif
#endif
         break;
       }
     } else {
       adsl_hco_wothr_w1 = adsl_waitwth_1_w1->adsc_hco_wothr;  /* thread to activate */
#ifdef CHECKTHRACT
       adsl_hco_wothr_w1->boc_active = TRUE;  /* this thread active again */
#endif
       adss_waitwth_proc_first = adsl_waitwth_1_w1->adsc_next;  /* remove from chain */
       adsl_waitwth_1_w1->adsc_next = adss_waitwth_free;  /* get old chain free */
       adss_waitwth_free = adsl_waitwth_1_w1;  /* set new chain free   */
#ifdef CHECKWAITTH
         ins_count_waitwth--;
#endif
       dsg_hco_main.imc_workque_sched--;    /* work queue scheduled    */
     }
   }
   if (   (adsl_hco_wothr_w1 == NULL)       /* no thread to activate   */
       && (adsl_hco_wothr_new == NULL)) {   /* no new thread           */
     dsg_hco_main.imc_workthr_active--;     /* active work threads     */
   }
   iml_rc1 = dss_critsect_wothr.m_leave();
   if (adsl_hco_wothr_w1) {                 /* thread to activate      */
     iml_rc1 = adsl_hco_wothr_w1->dsc_event.m_post( &iml_rc2 );  /* set event of thread */
     if (iml_rc1 < 0) {                     /* error occured           */
       m_hl1_printf( "xslcontr-%05d-W m_workth_set_block event m_post Return Code %d Error %d",
                     __LINE__, iml_rc1, iml_rc2 );
     }
   }
   if (adsl_hco_wothr_new) {                /* address work thread new */
     iml_rc1 = adsl_hco_wothr_new->dsc_event.m_create( &iml_rc2 );  /* event of thread */
     if (iml_rc1 < 0) {                     /* error occured           */
       m_hl1_printf( "xslcontr-%05d-W m_workth_set_block event m_create Return Code %d Error %d",
                     __LINE__, iml_rc1, iml_rc2 );
     }
#ifdef TRACEHL1
     m_hl1_printf( "m_workth_set_block before Thread.mc_create" );
#endif
#ifndef HL_HPUX
     iml_rc1 = adsl_hco_wothr_new->dsc_hcthread.mc_create( &m_work_thread, (void *) adsl_hco_wothr_new );
#else
     iml_rc1 = adsl_hco_wothr_new->dsc_hcthread.mc_create( &m_work_thread,
                                                           (void *) adsl_hco_wothr_new,
                                                           STACK_SIZE );
#endif
     if (iml_rc1 < 0) {                     /* error occured           */
       m_hl1_printf( "xslcontr-%05d-W m_workth_set_block Thread mc_create Error", __LINE__ );
     }
   }
#ifdef CHECKTHRACT
   m_count_active( __LINE__, "m_hco_wothr_blocking()" );
#endif
} /* end m_hco_wothr_blocking()                                        */

/** mark work-thread as active                                         */
extern "C" void m_hco_wothr_active( struct dsd_hco_wothr *adsp_hco_wothr, BOOL bop_force ) {
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */
   BOOL       bol1;                         /* working variable        */

#ifdef TRACEHL1
   m_hl1_printf( "m_hco_wothr_active() called %p", adsp_hco_wothr );
#endif
#ifdef CHECKTHRACT
   if (adsp_hco_wothr->boc_active) {  /* this thread not active  */
     m_hl1_printf( "m_hco_wothr_active() called %p - invalid, already active", adsp_hco_wothr );
     return;
   }
#endif
#ifndef CHECKTHRACT
   adsp_hco_wothr->boc_active = TRUE;       /* this thread active again */
#endif
   bol1 = FALSE;                            /* do not wait             */
   iml_rc1 = dss_critsect_wothr.m_enter();
   if (   (dsg_hco_main.imc_workthr_active >= dsg_hco_main.imc_max_act_workthr)
       && (bop_force == FALSE)) {
#ifdef XYZ1
     if (adsp_hco_wothr->adsc_waitwth_1) {  /* special / audio         */
       dsg_hco_main.imc_workque_sched++;    /* work queue scheduled    */
       if (dsg_hco_main.imc_workque_max_no < dsg_hco_main.imc_workque_sched) {  /* work queue maximum */
         time( &dsg_hco_main.dsc_workque_max_time );  /* get current time */
         dsg_hco_main.imc_workque_max_no = dsg_hco_main.imc_workque_sched;  /* set new queue maximum */
       }
       if (adss_waitwth_proc_first == NULL) {  /* chain to process     */
         adss_waitwth_proc_first = adsp_hco_wothr->adsc_waitwth_1;  /* set first in chain */
       } else {
         adss_waitwth_proc_last->adsc_next = adsp_hco_wothr->adsc_waitwth_1;  /* set in chain */
       }
       adss_waitwth_proc_last = adsp_hco_wothr->adsc_waitwth_1;  /* set last to process */
     } else {
#endif
       m_hco_put_chain_wothr( &adsp_hco_wothr->dsc_call_para_1, adsp_hco_wothr );
#ifdef XYZ1
     }
#endif
     bol1 = TRUE;                           /* wait for idle thread    */
   } else {
     dsg_hco_main.imc_workthr_active++;     /* active work threads     */
#ifdef CHECKTHRACT
     adsp_hco_wothr->boc_active = TRUE;     /* this thread active again */
#endif
   }
   iml_rc1 = dss_critsect_wothr.m_leave();
   if (bol1) {                              /* wait till activated     */
     iml_rc1 = adsp_hco_wothr->dsc_event.m_wait( &iml_rc2 );  /* event of thread */
     if (iml_rc1) {                         /* error occured           */
       m_hl1_printf( "xslcontr-%05d-W m_hco_wothr_active thread m_wait Return Code %d Error %d",
                     __LINE__, iml_rc1, iml_rc2 );
     }
   }
#ifdef CHECKTHRACT
   m_count_active( __LINE__, "m_hco_wothr_active()" );
#endif
} /* end m_hco_wothr_active()                                          */
#endif
#ifdef WOTHR_LOCK_FREE
/** schedule some piece of work to be run on a work-thread             */
extern "C" void m_hco_run_thread( struct dsd_call_para_1 *adsp_call_para_1 ) {
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */
   struct dsd_hco_wothr *adsl_hco_wothr_w1;  /* address work thread    */
   struct dsd_hco_wothr *adsl_hco_wothr_new;  /* address work thread new */
// struct dsd_hco_waitwth *dsl_waitwth_1_1;   /* address wait for thread */

#ifdef TRACEHL1
   m_hl1_printf( "m_hco_run_thread start amc_function=%p apparam1=%p apparam2=%p apparam3=%p",
                 adsp_call_para_1->amc_function,
                 adsp_call_para_1->ac_param_1,
                 adsp_call_para_1->ac_param_2,
                 adsp_call_para_1->ac_param_3 );
#endif
   if (dsg_hco_main.imc_workthr_active >= dsg_hco_main.imc_max_act_workthr) {
     goto p_put_backlog_00;                 /* put to backlock         */
   }

   /* check if we can get free thread in linked list                   */
   adsl_hco_wothr_w1 = (struct dsd_hco_wothr *) m_hl_get_chain( aas_thread_idle_ctrl );
   if (adsl_hco_wothr_w1) {                 /* got thread              */
     adsl_hco_wothr_w1->dsc_call_para_1 = *adsp_call_para_1;  /* set parameters */
     adsl_hco_wothr_w1->boc_active = TRUE;  /* thread is active        */
     m_hl_lock_inc_1( &dsg_hco_main.imc_workthr_active );  /* active work threads */
     m_hl_lock_inc_1( &dsg_hco_main.imc_workthr_sched );  /* scheduled work threads */
     iml_rc1 = adsl_hco_wothr_w1->dsc_event.m_post( &iml_rc2 );  /* set event of thread */
     if (iml_rc1 < 0) {                     /* error occured           */
       m_hl1_printf( "xslcontr-%05d-W m_hco_run_thread event m_post Return Code %d Error %d",
                     __LINE__, iml_rc1, iml_rc2 );
     }
     return;
   }

#ifdef TRACEHLX
         int ih1 = 0;                       /* count threads           */
         adsl_hco_wothr_w1 = dsg_hco_main.adsc_hco_wothr_anchor;         /* get anchor of chain     */
         while (adsl_hco_wothr_w1) {             /* loop over all threads   */
           /* Attentent printf() 03.08.06 KB / SR */
           m_hl1_printf( "+++ check thread no=%d / %08X clconn1=%08X act=%08X time=%08X",
                             ih1 + 1, adsl_hco_wothr_w1,
                             adsl_hco_wothr_w1->ad_clconn1,
                             adsl_hco_wothr_w1->trace_act, adsl_hco_wothr_w1->trace_time );
           ih1++;
           adsl_hco_wothr_w1 = adsl_hco_wothr_w1->next;  /* get next in chain    */
         }
         m_hl1_printf( "create new thread / no=%d", ih1 + 1 );
#endif
   dss_critsect_wothr.m_enter();            /* critical section        */
   if (   (dsg_hco_main.imc_workthr_alloc >= dsg_hco_main.imc_max_poss_workthr)
       || (dsg_hco_main.imc_workthr_active >= dsg_hco_main.imc_max_act_workthr)) {
     dss_critsect_wothr.m_leave();          /* critical section        */
     goto p_put_backlog_00;                 /* put to backlock         */
   }
   adsl_hco_wothr_new = (struct dsd_hco_wothr *) malloc( sizeof(struct dsd_hco_wothr) );
   if (adsl_hco_wothr_new == NULL) {        /* out of memory           */
     dss_critsect_wothr.m_leave();          /* critical section        */
     m_hl1_printf( "xslcontr-%05d-W m_work_thread m_hco_run_thread() - new thread - out of memory",
                   __LINE__ );
     return;
   }
   adsl_hco_wothr_new->dsc_call_para_1 = *adsp_call_para_1;  /* set parameters */
   adsl_hco_wothr_new->boc_active = TRUE;   /* thread is active        */
   adsl_hco_wothr_new->boc_thr_close = FALSE;  /* thread not closed    */
   dsg_hco_main.imc_workthr_alloc++;        /* count allocated work threads */
   m_hl_lock_inc_1( &dsg_hco_main.imc_workthr_active );  /* active work threads */
   m_hl_lock_inc_1( &dsg_hco_main.imc_workthr_sched );  /* scheduled work threads */
   adsl_hco_wothr_new->adsc_next = dsg_hco_main.adsc_hco_wothr_anchor;  /* set anchor of chain */
   dsg_hco_main.adsc_hco_wothr_anchor = adsl_hco_wothr_new;  /* set new start chain */
   dss_critsect_wothr.m_leave();            /* critical section        */

   iml_rc1 = adsl_hco_wothr_new->dsc_event.m_create( &iml_rc2 );  /* event of thread */
   if (iml_rc1 < 0) {                       /* error occured           */
     m_hl1_printf( "xslcontr-%05d-W m_hco_run_thread event m_create Return Code %d Error %d",
                   __LINE__, iml_rc1, iml_rc2 );
   }
#ifdef TRACEHL1
   m_hl1_printf( "run_thread before Thread.Create" );
#endif
#ifndef HL_HPUX
   iml_rc1 = adsl_hco_wothr_new->dsc_hcthread.mc_create( &m_work_thread, (void *) adsl_hco_wothr_new );
#else
   iml_rc1 = adsl_hco_wothr_new->dsc_hcthread.mc_create( &m_work_thread,
                                                         (void *) adsl_hco_wothr_new,
                                                         STACK_SIZE );
#endif
   if (iml_rc1 < 0) {
     m_hl1_printf( "xslcontr-%05d-W m_hco_run_thread CreateThread Error", __LINE__ );
   }
   return;                                  /* all done                */

   p_put_backlog_00:                        /* put to backlock         */
   m_hco_put_chain_wothr( adsp_call_para_1, NULL );
   return;                                  /* all done                */
} /* end m_hco_run_thread()                                            */

/** put request in chain of backlog for work-threads                   */
static void m_hco_put_chain_wothr( struct dsd_call_para_1 *adsp_call_para_1,
                                   struct dsd_hco_wothr *adsp_hco_woth ) {
   int        iml1;                         /* working variable        */
   struct dsd_hco_waitwth *adsl_waitwth_1_w1;  /* address wait for thread */
#ifndef B160131
   struct dsd_hco_fifo_ele *adsl_hfe_w1;    /* FIFO element            */
   char       *achl_w1;                     /* address                 */
#endif

   m_hl_lock_inc_1( &dsg_hco_main.imc_workque_sched );  /* work queue scheduled */
   if (dsg_hco_main.imc_workque_max_no < dsg_hco_main.imc_workque_sched) {  /* work queue maximum */
     time( &dsg_hco_main.dsc_workque_max_time );  /* get current time  */
     dsg_hco_main.imc_workque_max_no = dsg_hco_main.imc_workque_sched;  /* set new queue maximum */
   }
   adsl_hfe_w1 = NULL;                      /* FIFO element            */
   adsl_waitwth_1_w1 = (struct dsd_hco_waitwth *) m_hl_get_chain( aas_free_waiting_ctrl );
   if (adsl_waitwth_1_w1 == NULL) {         /* no free element found   */
#ifdef TRACEHLA
     m_hl1_printf( "acquire new area for adss_waitwth_free chain" );
#endif
#ifdef B151215
     adsl_waitwth_1_w1 = (struct dsd_hco_waitwth *) malloc( NO_WAIT_THR_S * sizeof(struct dsd_hco_waitwth) );
     if (adsl_waitwth_1_w1 == NULL) {       /* out of memory           */
       m_hl1_printf( "xslcontr-%05d-W m_work_thread m_hco_put_chain_wothr() out of memory",
                     __LINE__ );
       return;
     }
     iml1 = 1;                              /* set index element to save */
     do {
       m_hl_put_chain( aas_free_waiting_ctrl, adsl_waitwth_1_w1 + iml1 );
       iml1++;                              /* increment index         */
     } while (iml1 < NO_WAIT_THR_S);
#endif
#ifndef B151215
#ifdef B160131
#define IML_DS_LEN ((sizeof(struct dsd_hco_waitwth) + 2 * sizeof(void *) - 1) & (0 - 2 * sizeof(void *)))
     adsl_waitwth_1_w1 = (struct dsd_hco_waitwth *) malloc( NO_WAIT_THR_S * IML_DS_LEN + sizeof(void *) );
     if (adsl_waitwth_1_w1 == NULL) {       /* out of memory           */
       m_hl1_printf( "xslcontr-%05d-W m_work_thread m_hco_put_chain_wothr() out of memory",
                     __LINE__ );
       return;
     }
     /* align to 16 bytes                                              */
     *((char **) &adsl_waitwth_1_w1) += (2 * sizeof(void *) - (((size_t) adsl_waitwth_1_w1) & (2 * sizeof(void *) - 1))) & (2 * sizeof(void *) - 1);
     iml1 = 1;                              /* set index element to save */
     do {
       m_hl_put_chain( aas_free_waiting_ctrl, (char *) adsl_waitwth_1_w1 + iml1 * IML_DS_LEN );
       iml1++;                              /* increment index         */
     } while (iml1 < NO_WAIT_THR_S);
#undef IML_DS_LEN
#endif
#endif
#ifndef B160131
#define IML_DS_LEN ((sizeof(struct dsd_hco_fifo_ele) + 2 * sizeof(void *) - 1) & (0 - 2 * sizeof(void *)))
     achl_w1 = (char *) malloc( NO_WAIT_THR_S * (IML_DS_LEN + sizeof(struct dsd_hco_waitwth)) + sizeof(void *) );
     if (achl_w1 == NULL) {                 /* out of memory           */
       m_hl1_printf( "xslcontr-%05d-W m_work_thread m_hco_put_chain_wothr() out of memory",
                     __LINE__ );
       return;
     }
     /* align to 16 bytes                                              */
     *((char **) &achl_w1) += (2 * sizeof(void *) - (((size_t) achl_w1) & (2 * sizeof(void *) - 1))) & (2 * sizeof(void *) - 1);
     adsl_hfe_w1 = (struct dsd_hco_fifo_ele *) achl_w1;  /* FIFO element */
     achl_w1 += IML_DS_LEN;
     iml1 = 1;                              /* set index element to save */
     do {
#ifndef __INSURE__
       m_hl_put_chain( aas_hco_fifo_ele_ctrl, achl_w1 );
#endif
       achl_w1 += IML_DS_LEN;
       iml1++;                              /* increment index         */
     } while (iml1 < NO_WAIT_THR_S);
     adsl_waitwth_1_w1 = (struct dsd_hco_waitwth *) achl_w1;
     achl_w1 += sizeof(struct dsd_hco_waitwth);
     iml1 = 1;                              /* set index element to save */
     do {
#ifndef __INSURE__
       m_hl_put_chain( aas_free_waiting_ctrl, achl_w1 );
#endif
       achl_w1 += sizeof(struct dsd_hco_waitwth);
       iml1++;                              /* increment index         */
     } while (iml1 < NO_WAIT_THR_S);
#endif
#ifdef __INSURE__
     iml1 = NO_WAIT_THR_S;
     while (TRUE) {
       iml1--;                              /* decrement index         */
       achl_w1 = (char *) malloc( IML_DS_LEN + sizeof(void *) );
       if (achl_w1 == NULL) {               /* out of memory           */
         m_hl1_printf( "xslcontr-%05d-W m_work_thread m_hco_put_chain_wothr() out of memory",
                       __LINE__ );
         return;
       }
       /* align to 16 bytes                                              */
       *((char **) &achl_w1) += (2 * sizeof(void *) - (((size_t) achl_w1) & (2 * sizeof(void *) - 1))) & (2 * sizeof(void *) - 1);
       if (iml1 == 0) {                     /* last element            */
         adsl_hfe_w1 = (struct dsd_hco_fifo_ele *) achl_w1;  /* FIFO element */
         break;
       }
       m_hl_put_chain( aas_hco_fifo_ele_ctrl, achl_w1 );
     }
     iml1 = NO_WAIT_THR_S;
     while (TRUE) {
       iml1--;                              /* decrement index         */
       achl_w1 = (char *) malloc( sizeof(struct dsd_hco_waitwth) );
       if (achl_w1 == NULL) {               /* out of memory           */
         m_hl1_printf( "xslcontr-%05d-W m_work_thread m_hco_put_chain_wothr() out of memory",
                       __LINE__ );
         return;
       }
       if (iml1 == 0) {                     /* last element            */
         adsl_waitwth_1_w1 = (struct dsd_hco_waitwth *) achl_w1;
         break;
       }
       m_hl_put_chain( aas_free_waiting_ctrl, achl_w1 );
     }
#endif
#undef IML_DS_LEN
   }
   if (adsl_hfe_w1 == NULL) {               /* FIFO element            */
     adsl_hfe_w1 = (struct dsd_hco_fifo_ele *) m_hl_get_chain( aas_hco_fifo_ele_ctrl );
     if (adsl_hfe_w1 == NULL) {             /* no free element found   */
       m_hl1_printf( "xslcontr-%05d-W m_work_thread m_hco_put_chain_wothr() no FIFO-element - illogic",
                     __LINE__ );
       return;
     }
   }
#ifdef CHECKWAITTH
   ins_count_waitwth++;
#endif

   /* set work to do                                                   */
   adsl_waitwth_1_w1->dsc_call_para_1 = *adsp_call_para_1;
   adsl_waitwth_1_w1->adsc_hco_wothr = adsp_hco_woth;  /* thread active / block */
#ifdef XYZ1
   adsl_waitwth_1_w1->adsc_ch_spec = NULL;  /* chain special entry     */
#endif
#ifdef B160131
   m_hl_put_fifo( aas_thread_backlog_ctrl, adsl_waitwth_1_w1 );
#endif
   adsl_hfe_w1->adsc_waitwth = adsl_waitwth_1_w1;  /* real element     */
   m_hl_put_fifo( aas_thread_backlog_ctrl, adsl_hfe_w1 );
} /* end m_hco_put_chain_wothr()                                       */

/** mark work-thread as blocking                                       */
extern "C" void m_hco_wothr_blocking( struct dsd_hco_wothr *adsp_hco_wothr ) {
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */
   struct dsd_hco_wothr *adsl_hco_wothr_w1;  /* working variable       */
   struct dsd_hco_wothr *adsl_hco_wothr_new;  /* address work thread new */
   struct dsd_hco_fifo_ele *adsl_hfe_w1;    /* FIFO element            */
   struct dsd_hco_waitwth *adsl_waitwth_1_w1;  /* address wait for thread */

#ifdef TRACEHL1
   m_hl1_printf( "m_hco_wothr_blocking() called %p", adsp_hco_wothr );
#endif
#ifdef CHECKTHRACT
   if (adsp_hco_wothr->boc_active == FALSE) {  /* this thread not active  */
     m_hl1_printf( "m_hco_wothr_blocking() called %p - invalid, already blocking", adsp_hco_wothr );
     return;
   }
#endif
   adsp_hco_wothr->boc_active = FALSE;      /* this thread not active  */
   m_hl_lock_dec_1( &dsg_hco_main.imc_workthr_active );  /* active work threads */

   p_blo_20:                                /* check if work for other thread */
   if (dsg_hco_main.imc_workthr_active >= dsg_hco_main.imc_max_act_workthr) {
     return;                                /* nothing to do           */
   }
   adsl_waitwth_1_w1 = (struct dsd_hco_waitwth *) m_hl_check_fifo( aas_thread_backlog_ctrl );
   if (adsl_waitwth_1_w1 == NULL) return;   /* no work found           */
   if (   (dsg_hco_main.imc_workthr_alloc >= dsg_hco_main.imc_max_poss_workthr)
       && (adsl_waitwth_1_w1->adsc_hco_wothr == NULL)  /* not special thread */
       && (m_hl_check_chain( aas_thread_idle_ctrl ) == NULL)) {
     /* already maximum threads, cannot create new thread              */
     return;                                /* nothing to do           */
   }

   /* now we do real work                                              */
#ifdef B160131
   adsl_waitwth_1_w1 = (struct dsd_hco_waitwth *) m_hl_get_fifo( aas_thread_backlog_ctrl );
   if (adsl_waitwth_1_w1 == NULL) return;   /* no work found           */
#endif
#ifndef B160131
   adsl_hfe_w1 = (struct dsd_hco_fifo_ele *) m_hl_get_fifo( aas_thread_backlog_ctrl );
   if (adsl_hfe_w1 == NULL) return;         /* no work found           */
   adsl_waitwth_1_w1 = adsl_hfe_w1->adsc_waitwth;  /* real element     */
#endif

   m_hl_lock_dec_1( &dsg_hco_main.imc_workque_sched );  /* work queue scheduled */

   adsl_hco_wothr_w1 = adsl_waitwth_1_w1->adsc_hco_wothr;  /* get special thread */
   if (adsl_hco_wothr_w1) {                 /* special thread found    */
     adsl_hco_wothr_w1->boc_active = TRUE;  /* this thread active again */
     m_hl_lock_inc_1( &dsg_hco_main.imc_workthr_active );  /* active work threads */
     iml_rc1 = adsl_hco_wothr_w1->dsc_event.m_post( &iml_rc2 );  /* event of thread */
     if (iml_rc1 < 0) {                     /* error occured           */
       m_hl1_printf( "xslcontr-%05d-W m_work_thread thread m_post Return Code %d Error %d",
                     __LINE__, iml_rc1, iml_rc2 );
     }
     m_hl_put_chain( aas_hco_fifo_ele_ctrl, adsl_hfe_w1 );
     m_hl_put_chain( aas_free_waiting_ctrl, adsl_waitwth_1_w1 );
     return;                                /* all done                */
   }

   /* check if we can get free thread in linked list                   */
   adsl_hco_wothr_w1 = (struct dsd_hco_wothr *) m_hl_get_chain( aas_thread_idle_ctrl );
   if (adsl_hco_wothr_w1) {                 /* got thread              */
     adsl_hco_wothr_w1->dsc_call_para_1 = adsl_waitwth_1_w1->dsc_call_para_1;  /* set parameters */
     m_hl_put_chain( aas_hco_fifo_ele_ctrl, adsl_hfe_w1 );
     m_hl_put_chain( aas_free_waiting_ctrl, adsl_waitwth_1_w1 );
     adsl_hco_wothr_w1->boc_active = TRUE;  /* thread is active        */
     m_hl_lock_inc_1( &dsg_hco_main.imc_workthr_active );  /* active work threads */
     m_hl_lock_inc_1( &dsg_hco_main.imc_workthr_sched );  /* scheduled work threads */
     iml_rc1 = adsl_hco_wothr_w1->dsc_event.m_post( &iml_rc2 );  /* set event of thread */
     if (iml_rc1 < 0) {                     /* error occured           */
       m_hl1_printf( "xslcontr-%05d-W m_hco_run_thread event m_post Return Code %d Error %d",
                     __LINE__, iml_rc1, iml_rc2 );
     }
     return;                                /* all done                */
   }

   dss_critsect_wothr.m_enter();            /* critical section        */
   adsl_hco_wothr_new = (struct dsd_hco_wothr *) malloc( sizeof(struct dsd_hco_wothr) );
   if (adsl_hco_wothr_new == NULL) {        /* out of memory           */
     dss_critsect_wothr.m_leave();          /* critical section        */
     m_hl1_printf( "xslcontr-%05d-W m_work_thread m_hco_wothr_blocking() - new thread - out of memory",
                   __LINE__ );
     return;
   }
   adsl_hco_wothr_new->dsc_call_para_1 = adsl_waitwth_1_w1->dsc_call_para_1;  /* set parameters */
   m_hl_put_chain( aas_hco_fifo_ele_ctrl, adsl_hfe_w1 );
   m_hl_put_chain( aas_free_waiting_ctrl, adsl_waitwth_1_w1 );
   adsl_hco_wothr_new->boc_active = TRUE;   /* thread is active        */
   adsl_hco_wothr_new->boc_thr_close = FALSE;  /* thread not closed    */
   dsg_hco_main.imc_workthr_alloc++;        /* count allocated work threads */
   m_hl_lock_inc_1( &dsg_hco_main.imc_workthr_active );  /* active work threads */
   m_hl_lock_inc_1( &dsg_hco_main.imc_workthr_sched );  /* scheduled work threads */
   adsl_hco_wothr_new->adsc_next = dsg_hco_main.adsc_hco_wothr_anchor;  /* set anchor of chain */
   dsg_hco_main.adsc_hco_wothr_anchor = adsl_hco_wothr_new;  /* set new start chain */
   dss_critsect_wothr.m_leave();            /* critical section        */

   iml_rc1 = adsl_hco_wothr_new->dsc_event.m_create( &iml_rc2 );  /* event of thread */
   if (iml_rc1 < 0) {                       /* error occured           */
     m_hl1_printf( "xslcontr-%05d-W m_hco_wothr_blocking() event m_create Return Code %d Error %d",
                   __LINE__, iml_rc1, iml_rc2 );
   }
#ifdef TRACEHL1
   m_hl1_printf( "run_thread before Thread.Create" );
#endif
#ifndef HL_HPUX
   iml_rc1 = adsl_hco_wothr_new->dsc_hcthread.mc_create( &m_work_thread, (void *) adsl_hco_wothr_new );
#else
   iml_rc1 = adsl_hco_wothr_new->dsc_hcthread.mc_create( &m_work_thread,
                                                         (void *) adsl_hco_wothr_new,
                                                         STACK_SIZE );
#endif
   if (iml_rc1 < 0) {
     m_hl1_printf( "xslcontr-%05d-W m_hco_wothr_blocking() CreateThread Error", __LINE__ );
   }
#ifdef CHECKTHRACT
   m_count_active( __LINE__, "m_hco_wothr_blocking()" );
#endif
   return;                                  /* all done                */
} /* end m_hco_wothr_blocking()                                        */

/** mark work-thread as active                                         */
extern "C" void m_hco_wothr_active( struct dsd_hco_wothr *adsp_hco_wothr, BOOL bop_force ) {
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */

#ifdef TRACEHL1
   m_hl1_printf( "m_hco_wothr_active() called %p", adsp_hco_wothr );
#endif
#ifdef CHECKTHRACT
   if (adsp_hco_wothr->boc_active) {  /* this thread not active  */
     m_hl1_printf( "m_hco_wothr_active() called %p - invalid, already active", adsp_hco_wothr );
     return;
   }
#endif
#ifndef CHECKTHRACT
// adsp_hco_wothr->boc_active = TRUE;       /* this thread active again */
#endif
// to-do 18.10.15 KB - bop_force == TRUE
   if (   (dsg_hco_main.imc_workthr_active < dsg_hco_main.imc_max_act_workthr)
       || (bop_force)) {
     adsp_hco_wothr->boc_active = TRUE;     /* this thread active again */
     m_hl_lock_inc_1( &dsg_hco_main.imc_workthr_active );  /* active work threads */
     return;
   }
   m_hco_put_chain_wothr( &adsp_hco_wothr->dsc_call_para_1, adsp_hco_wothr );
   while (adsp_hco_wothr->boc_active == FALSE) {  /* wait till activated */
     iml_rc1 = adsp_hco_wothr->dsc_event.m_wait( &iml_rc2 );  /* event of thread */
     if (iml_rc1) {                         /* error occured           */
       m_hl1_printf( "xslcontr-%05d-W m_hco_wothr_active thread m_wait Return Code %d Error %d",
                     __LINE__, iml_rc1, iml_rc2 );
     }
   }
   /* dsg_hco_main.imc_workthr_active == active work threads set by post() */
// to-do 18.10.15 KB - volatile BOOL boc_run
#ifdef CHECKTHRACT
   m_count_active( __LINE__, "m_hco_wothr_active()" );
#endif
} /* end m_hco_wothr_active()                                          */
#endif

/** lock a resource for this work thread                               */
extern "C" void m_hco_wothr_lock( struct dsd_hco_wothr *adsp_hco_wothr,
                                  struct dsd_hco_lock_1 *adsp_hco_lock_1 ) {
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */
   struct dsd_hco_wothr *adsl_hco_wothr_w1;  /* thread to wait for     */
   BOOL       bol_active;                   /* set this thread active  */
   BOOL       bol_locked;                   /* resource is locked      */

   bol_locked = FALSE;                      /* clear resource is locked */
   dss_critsect_wothr.m_enter();
   if (adsp_hco_lock_1->adsc_wothr_in_use == NULL) {
     adsp_hco_lock_1->adsc_wothr_in_use = adsp_hco_wothr;  /* locked by this thread */
     adsp_hco_lock_1->adsc_ch_lock = NULL;  /* no one waiting for this lock */
   } else {                                 /* thread is locked        */
     bol_locked = TRUE;                     /* resource is locked      */
     adsp_hco_wothr->adsc_ch_lock = NULL;   /* is last in chain        */
     if (adsp_hco_lock_1->adsc_ch_lock == NULL) {  /* first thread to lock */
       adsp_hco_lock_1->adsc_ch_lock = adsp_hco_wothr;
     } else {                               /* set at end of chain     */
       adsl_hco_wothr_w1 = adsp_hco_lock_1->adsc_ch_lock;
       while (adsl_hco_wothr_w1->adsc_ch_lock) {
         adsl_hco_wothr_w1 = adsl_hco_wothr_w1->adsc_ch_lock;
       }
       adsl_hco_wothr_w1->adsc_ch_lock = adsp_hco_wothr;
     }
   }
   dss_critsect_wothr.m_leave();
   if (bol_locked == FALSE) return;         /* this thread has lock    */
   bol_active = adsp_hco_wothr->boc_active;  /* save if active         */
   if (bol_active) m_hco_wothr_blocking( adsp_hco_wothr );
   iml_rc1 = adsp_hco_wothr->dsc_event.m_wait( &iml_rc2 );  /* event of thread */
   if (iml_rc1) {                           /* error occured           */
     m_hl1_printf( "xslcontr-%05d-W end m_hco_wothr_lock thread m_wait Return Code %d Error %d",
                   __LINE__, iml_rc1, iml_rc2 );
   }
#ifdef TRACEHL1
   if (adsp_hco_lock_1->adsc_wothr_in_use != adsp_hco_wothr) {  /* check locked by this thread */
     m_hl1_printf( "m_hco_wothr_lock() l%05d after WaitForSingleObject other object locked",
                   __LINE__ );
   }
#endif
   if (bol_active) m_hco_wothr_active( adsp_hco_wothr, FALSE );
} /* end m_hco_wothr_lock()                                            */

/** unlock a resource that has been locked for this work thread        */
extern "C" void m_hco_wothr_unlock( struct dsd_hco_wothr *adsp_hco_wothr,
                                    struct dsd_hco_lock_1 *adsp_hco_lock_1 ) {
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */
   struct dsd_hco_wothr *adsl_hco_wothr_w1;  /* thread to wait for     */

#ifdef TRACEHL1
   if (adsp_hco_lock_1->adsc_wothr_in_use != adsp_hco_wothr) {  /* check locked by this thread */
     m_hl1_printf( "m_hco_wothr_unlock() l%05d entry other object locked",
                   __LINE__ );
   }
#endif
   iml_rc1 = dss_critsect_wothr.m_enter();
   adsl_hco_wothr_w1 = adsp_hco_lock_1->adsc_ch_lock;
   adsp_hco_lock_1->adsc_wothr_in_use = adsl_hco_wothr_w1;
   if (adsl_hco_wothr_w1) {
     adsp_hco_lock_1->adsc_ch_lock = adsl_hco_wothr_w1->adsc_ch_lock;
   }
   iml_rc1 = dss_critsect_wothr.m_leave();
   if (adsl_hco_wothr_w1 == NULL) return;
   iml_rc1 = adsl_hco_wothr_w1->dsc_event.m_post( &iml_rc2 );  /* event of thread */
   if (iml_rc1 < 0) {                       /* error occured           */
     m_hl1_printf( "xslcontr-%05d-W m_hco_wothr_unlock thread m_post Return Code %d Error %d",
                   __LINE__, iml_rc1, iml_rc2 );
   }
#ifdef PROBLEM_090226                       /* KDRS - deadlock - Web-Server hangs */
   m_hl1_printf( "xslcontr-%05d-T m_hco_wothr_unlock thread after m_post adsl_hco_wothr_w1=%p.",
                 __LINE__, adsl_hco_wothr_w1 );
#endif
} /* end m_hco_wothr_unlock()                                          */

/** prepare wait-chain                                                 */
extern "C" void m_hco_wothr_wacha_prep( struct dsd_hco_wothr *adsp_hco_wothr,
                                        struct dsd_hco_wacha_1 *adsp_hco_wacha ) {
   adsp_hco_wacha->adsc_wothr_in_use = adsp_hco_wothr;  /* resource in use by this thread */
   adsp_hco_wacha->adsc_wacha_waiting = NULL;  /* entry wait-chain waiting */
   adsp_hco_wacha->boc_is_waiting = FALSE;  /* is currently not waiting */
} /* end m_hco_wothr_wacha_prep()                                      */

/** append to wait-chain                                               */
extern "C" void m_hco_wothr_wacha_append( struct dsd_hco_wothr *adsp_hco_wothr,
                                          struct dsd_hco_wacha_1 *adsp_hco_wacha_this,
                                          struct dsd_hco_wacha_1 *adsp_hco_wacha_lock ) {
   struct dsd_hco_wacha_1 *adsp_hco_wacha_w1;

#ifdef TRACEHL_WACHA_1
   m_hl1_printf( "xslcontr-%05d-T m_hco_wothr_wacha_append adsp_hco_wothr=%p adsp_hco_wacha_this=%p adsp_hco_wacha_lock=%p.",
                 __LINE__, adsp_hco_wothr, adsp_hco_wacha_this, adsp_hco_wacha_lock );
#endif
   adsp_hco_wacha_this->boc_is_waiting = TRUE;  /* is currently waiting */
   if (adsp_hco_wacha_lock->adsc_wacha_waiting == NULL) {
     adsp_hco_wacha_lock->adsc_wacha_waiting = adsp_hco_wacha_this;
     return;
   }
   adsp_hco_wacha_w1 = adsp_hco_wacha_lock->adsc_wacha_waiting;
   while (adsp_hco_wacha_w1->adsc_wacha_waiting) {
     adsp_hco_wacha_w1 = adsp_hco_wacha_w1->adsc_wacha_waiting;
   }
   adsp_hco_wacha_w1->adsc_wacha_waiting = adsp_hco_wacha_this;
} /* end m_hco_wothr_wacha_append()                                    */

/** release wait-chain                                                 */
extern "C" void m_hco_wothr_wacha_rel( struct dsd_hco_wothr *adsp_hco_wothr,
                                       struct dsd_hco_wacha_1 *adsp_hco_wacha ) {
   if (adsp_hco_wacha->adsc_wacha_waiting == NULL) return;  /* no wait-chain waiting */
#ifdef TRACEHL_WACHA_1
   m_hl1_printf( "xslcontr-%05d-T m_hco_wothr_wacha_rel adsp_hco_wothr=%p target=%p.",
                 __LINE__, adsp_hco_wothr, adsp_hco_wacha->adsc_wacha_waiting->adsc_wothr_in_use );
#endif
   adsp_hco_wacha->adsc_wacha_waiting->boc_is_waiting = FALSE;  /* is no more waiting */
   m_hco_wothr_post( adsp_hco_wothr, adsp_hco_wacha->adsc_wacha_waiting->adsc_wothr_in_use );
} /* end m_hco_wothr_wacha_rel()                                       */

/** wait for entry in wait-chain                                       */
extern "C" void m_hco_wothr_wacha_wait( struct dsd_hco_wacha_1 *adsp_hco_wacha ) {
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */
   int        iml_time_cur;                 /* current time            */
   int        iml_time_start;               /* time wait started       */
   int        iml_time_wmax;                /* wait maximum this time  */
   int        iml_intv_wait;                /* interval to wait        */
   BOOL       bol_msg;                      /* output of message       */

   iml_time_start = 0;                      /* time wait started       */
   bol_msg = FALSE;                         /* output of message       */
   do {
     iml_time_cur = (int) time( NULL );     /* current time            */
     if (iml_time_start == 0) {             /* time wait started not set */
       iml_time_start = iml_time_cur;       /* time wait started set   */
       iml_time_wmax = iml_time_cur + D_WACHA_INTV_INIT;  /* wait maximum this time  */
       iml_intv_wait = D_WACHA_INTV_INIT;   /* interval to wait        */
     } else if (iml_time_cur >= iml_time_wmax) {  /* interval for message */
       bol_msg = TRUE;                      /* output of message       */
       m_hl1_printf( "xslcontr-%05d-W m_hco_wothr_wacha_wait waiting for %d seconds",
                     __LINE__, iml_time_cur - iml_time_start );
       iml_intv_wait += D_WACHA_INTV_INCR;  /* interval to wait        */
       iml_time_wmax += iml_intv_wait;      /* wait maximum this time  */
     }
     iml_rc1 = adsp_hco_wacha->adsc_wothr_in_use->dsc_event.m_wait_msec( (iml_time_wmax - iml_time_cur) * 1000, &iml_rc2 );  /* event of thread */
     if (iml_rc1) {                         /* error occured           */
       m_hl1_printf( "xslcontr-%05d-W m_hco_wothr_wacha_wait m_wait_msec Return Code %d Error %d",
                     __LINE__, iml_rc1, iml_rc2 );
     }
   } while (adsp_hco_wacha->boc_is_waiting);
   if (bol_msg == FALSE) return;            /* output of message       */
   iml_time_cur = (int) time( NULL );       /* current time            */
   m_hl1_printf( "xslcontr-%05d-W m_hco_wothr_wacha_wait was waiting for %d seconds",
                 __LINE__, iml_time_cur - iml_time_start );
} /* end m_hco_wothr_wacha_wait()                                      */

/** wait till posted in this work thread                               */
extern "C" void m_hco_wothr_wait( struct dsd_hco_wothr *adsp_hco_wothr ) {
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */
   BOOL       bol_active;                   /* set this thread active  */

   bol_active = adsp_hco_wothr->boc_active;  /* save if active         */
   if (bol_active) m_hco_wothr_blocking( adsp_hco_wothr );
   iml_rc1 = adsp_hco_wothr->dsc_event.m_wait( &iml_rc2 );  /* event of thread */
   if (iml_rc1) {                           /* error occured           */
     m_hl1_printf( "xslcontr-%05d-W end m_hco_wothr_wait thread m_wait Return Code %d Error %d.",
                   __LINE__, iml_rc1, iml_rc2 );
   }
   if (bol_active) m_hco_wothr_active( adsp_hco_wothr, FALSE );
} /* end m_hco_wothr_wait()                                            */

/** wait till posted in this work thread or timeout                    */
extern "C" int m_hco_wothr_wait_sec( struct dsd_hco_wothr *adsp_hco_wothr, int imp_sec ) {
   int        iml_rc_sub;                   /* Return Code of Subroutine */
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */
   BOOL       bol_active;                   /* set this thread active  */

   bol_active = adsp_hco_wothr->boc_active;  /* save if active         */
   if (bol_active) m_hco_wothr_blocking( adsp_hco_wothr );
   iml_rc_sub = D_RET_WAIT_POST;            /* event was set thru post */
   iml_rc1 = adsp_hco_wothr->dsc_event.m_wait_msec( imp_sec * 1000, &iml_rc2 );  /* event of thread */
   while (iml_rc1) {                        /* error occured           */
     if (iml_rc1 == -2) {                   /* timed out               */
       iml_rc_sub = D_RET_WAIT_TIMEOUT;     /* timeout occured         */
       break;
     }
     m_hl1_printf( "xslcontr-%05d-W end m_hco_wothr_wait_sec thread m_wait_msec Return Code %d Error %d.",
                   __LINE__, iml_rc1, iml_rc2 );
     iml_rc_sub = D_RET_WAIT_ERROR;         /* error occured           */
     break;
   }
   if (bol_active) m_hco_wothr_active( adsp_hco_wothr, FALSE );
   return iml_rc_sub;                       /* Return Code of Subroutine */
} /* end m_hco_wothr_wait()                                            */

/** wait till posted in this work thread or timeout - do not set work-thread blocking */
extern "C" int m_hco_wothr_nonblock_wait_sec( struct dsd_hco_wothr *adsp_hco_wothr, int imp_sec ) {
   int        iml_rc_sub;                   /* Return Code of Subroutine */
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */

   iml_rc_sub = D_RET_WAIT_POST;            /* event was set thru post */
   iml_rc1 = adsp_hco_wothr->dsc_event.m_wait_msec( imp_sec * 1000, &iml_rc2 );  /* event of thread */
   while (iml_rc1) {                        /* error occured           */
     if (iml_rc1 == -2) {                   /* timed out               */
       iml_rc_sub = D_RET_WAIT_TIMEOUT;     /* timeout occured         */
       break;
     }
     m_hl1_printf( "xslcontr-%05d-W end m_hco_wothr_nonblock_wait_sec thread m_wait_msec Return Code %d Error %d",
                   __LINE__, iml_rc1, iml_rc2 );
     iml_rc_sub = D_RET_WAIT_ERROR;         /* error occured           */
     break;
   }
   return iml_rc_sub;                       /* Return Code of Subroutine */
} /* end m_hco_wothr_nonblock_wait_sec()                               */

/** post another work thread waiting for this post                     */
extern "C" void m_hco_wothr_post( struct dsd_hco_wothr *adsp_hco_wt_this,
                                  struct dsd_hco_wothr *adsp_hco_wt_awake ) {
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */

   iml_rc1 = adsp_hco_wt_awake->dsc_event.m_post( &iml_rc2 );  /* event of thread */
   if (iml_rc1 < 0) {                       /* error occured           */
     m_hl1_printf( "xslcontr-%05d-W m_hco_wothr_post thread m_post Return Code %d Error %d",
                   __LINE__, iml_rc1, iml_rc2 );
   }
} /* end m_hco_wothr_post()                                            */

/** thread, one of many work-threads                                   */
static htfunc1_t m_work_thread( void * ulThreadArg ) {
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */
#ifndef WOTHR_LOCK_FREE
   int        inl1;                         /* working variable        */
#endif
#ifdef WOTHR_LOCK_FREE
   int        iml1;                         /* working variable        */
#endif
   BOOL       bol1;                         /* working variable        */
   struct dsd_hco_wothr *adsl_hco_wothr_w1;  /* thread to activate     */
   struct dsd_hco_waitwth *adsl_waitwth_1_w1;  /* address wait for thread */
#ifdef WOTHR_LOCK_FREE
   struct dsd_hco_fifo_ele *adsl_hfe_w1;    /* FIFO element            */
#endif
#ifdef TRACEHL1
   md_func_1 ahfunc;
#endif
#define ADSL_HCO_WOTHR_G ((struct dsd_hco_wothr *) ulThreadArg)

#ifdef TRACEHL1
   m_hl1_printf( "m_work_thread start %p.", ulThreadArg );
#endif
   ADSL_HCO_WOTHR_G->imc_tid = HL_THRID;    /* thread-id               */
   ADSL_HCO_WOTHR_G->imc_prio_thr = DEF_PRIO_DEFAULT;
#ifdef OLD01
   bol1 = SetThreadPriority( GetCurrentThread(), is_prio_proc );
   if (bol1 == FALSE) {
     m_hl1_printf( "SetThreadPriority WORK Error:%d", GetLastError() );
   }
#endif
   if (dsg_hco_main.amc_func_thr_sta) {     /* process start function  */
#ifndef HL_UNIX
     dsg_hco_main.amc_func_thr_sta( ADSL_HCO_WOTHR_G, GetCurrentThreadId() );
#else
     dsg_hco_main.amc_func_thr_sta( ADSL_HCO_WOTHR_G, 0 );
#endif
   }
   while (TRUE) {
     if (ADSL_HCO_WOTHR_G->imc_prio_thr != dsg_hco_main.imc_prio_thr) {  /* priority of one thread */
       ADSL_HCO_WOTHR_G->imc_prio_thr = dsg_hco_main.imc_prio_thr;  /* save priority */
#ifndef HL_UNIX
       bol1 = SetThreadPriority( GetCurrentThread(), ADSL_HCO_WOTHR_G->imc_prio_thr );
       if (bol1 == FALSE) {
         m_hl1_printf( "xslcontr-%05d-W m_work_thread SetThreadPriority Error:%d",
                       __LINE__, GetLastError() );
       }
#else
       ADSL_HCO_WOTHR_G->dsc_hcthread.mc_setpriority( ADSL_HCO_WOTHR_G->imc_prio_thr );
#endif
     }
     if (ADSL_HCO_WOTHR_G->dsc_call_para_1.amc_function) {  /* something to do */
#ifdef TRACEHL1
       ahfunc = (md_func_1) ADSL_HCO_WOTHR_G->dsc_call_para_1.amc_function;
       m_hl1_printf( "thread process function %p", ahfunc );
#endif
       /* process data                                                 */
       ((md_func_1) ADSL_HCO_WOTHR_G->dsc_call_para_1.amc_function)
         ( ADSL_HCO_WOTHR_G,
           ADSL_HCO_WOTHR_G->dsc_call_para_1.ac_param_1,
           ADSL_HCO_WOTHR_G->dsc_call_para_1.ac_param_2,
           ADSL_HCO_WOTHR_G->dsc_call_para_1.ac_param_3 );
#ifdef TRACEHL4
       m_hl1_printf( "thread data processed %p", ADSL_HCO_WOTHR_G );
#endif
#ifdef D_STRESS_TEST_THR_1
#ifndef HL_UNIX
       Sleep( 200 );
#else
       sleep( 1 );
#endif
#endif
     }
#ifdef PROBLEM_090305                       /* KDRS - deadlock - Web-Server hangs */
     ADSL_HCO_WOTHR_G->dsc_call_para_1.amc_function = NULL;  /* no work to do */
#endif
#ifndef WOTHR_LOCK_FREE
     bol1 = FALSE;                          /* nothing to process      */
     adsl_hco_wothr_w1 = NULL;              /* no thread to activate   */
#ifdef CHECKTHRACT
     m_count_active( __LINE__, "m_work_thread() 1" );
#endif
     iml_rc1 = dss_critsect_wothr.m_enter();   /* critical section     */
#ifdef CHECKTHRACT
     ADSL_HCO_WOTHR_G->dsc_call_para_1.amc_function = NULL;
#endif
     inl1 = 0;                              /* is already active       */
     if (ADSL_HCO_WOTHR_G->boc_active == FALSE) {  /* was not active   */
       inl1 = dsg_hco_main.imc_workthr_active;  /* no more active      */
     }
     if (   (adss_waitwth_proc_first)       /* something to process    */
         && (inl1 < dsg_hco_main.imc_max_act_workthr)) {
#ifdef TRACEHL1
       m_hl1_printf( "l%05d thread %p gets work from chain ADSL_HCO_WOTHR_G->boc_active=%d adss_waitwth_proc_first=%p",
                     __LINE__, ADSL_HCO_WOTHR_G, ADSL_HCO_WOTHR_G->boc_active, adss_waitwth_proc_first );
#endif
       adsl_waitwth_1_w1 = adss_waitwth_proc_first;  /* get first in chain */
       adss_waitwth_proc_first = adsl_waitwth_1_w1->adsc_next;  /* remove from chain */
       dsg_hco_main.imc_workque_sched--;    /* work queue scheduled    */
       if (adsl_waitwth_1_w1->adsc_hco_wothr == NULL) {  /* not special thread */
         ADSL_HCO_WOTHR_G->dsc_call_para_1 = adsl_waitwth_1_w1->dsc_call_para_1;  /* get work */
         if (ADSL_HCO_WOTHR_G->boc_active == FALSE) {  /* was not active */
           ADSL_HCO_WOTHR_G->boc_active = TRUE;  /* active working     */
           dsg_hco_main.imc_workthr_active++;  /* active work threads  */
         }
         bol1 = TRUE;                       /* something found to process */
       } else {
         adsl_hco_wothr_w1 = adsl_waitwth_1_w1->adsc_hco_wothr;  /* thread to activate */
#ifdef CHECKTHRACT
         adsl_hco_wothr_w1->boc_active = TRUE;  /* this thread active again */
#endif
#ifndef B061015
         if (ADSL_HCO_WOTHR_G->boc_active == FALSE) {  /* was not active before */
           dsg_hco_main.imc_workthr_active++;  /* active work threads  */
         }
#endif
       }
       adsl_waitwth_1_w1->adsc_next = adss_waitwth_free;  /* get old chain free */
       adss_waitwth_free = adsl_waitwth_1_w1;  /* set new chain free   */
#ifdef CHECKWAITTH
       ins_count_waitwth--;
#ifndef TRACEHL1
       m_hl1_printf( "ins_count_waitwth-- --> %d / workque_sched=%d / workthr_active=%d / workthr_sched=%d m_work_thread() 2",
                     ins_count_waitwth,
                     dsg_hco_main.imc_workque_sched,
                     dsg_hco_main.imc_workthr_active,    /* active work threads     */
                     dsg_hco_main.imc_workthr_sched );   /* scheduled work threads  */
#endif
#endif
     }
     if (bol1 == FALSE) {                   /* this thread idle now    */
       dsg_hco_main.imc_workthr_sched--;    /* scheduled work threads  */
#ifdef B061015
       if (ADSL_HCO_WOTHR_G->boc_active) {  /* was active before       */
         dsg_hco_main.imc_workthr_active--;  /* active work threads    */
       }
#else
       if (   (adsl_hco_wothr_w1 == NULL)   /* no thread to activate   */
           && (ADSL_HCO_WOTHR_G->boc_active)) {  /* was active before  */
         dsg_hco_main.imc_workthr_active--;  /* active work threads    */
       }
#endif
       ADSL_HCO_WOTHR_G->adsc_ch_free = dsg_hco_main.adsc_hco_wothr_free;  /* get old chain */
       dsg_hco_main.adsc_hco_wothr_free = ADSL_HCO_WOTHR_G;  /* set new chain */
     }
     iml_rc1 = dss_critsect_wothr.m_leave();  /* critical section      */
#ifdef CHECKTHRACT
     m_count_active( __LINE__, "m_work_thread() 2" );
#endif
     if (bol1) continue;                    /* continue                */
     if (adsl_hco_wothr_w1) {               /* thread to activate      */
       iml_rc1 = adsl_hco_wothr_w1->dsc_event.m_post( &iml_rc2 );  /* event of thread */
       if (iml_rc1 < 0) {                   /* error occured           */
         m_hl1_printf( "xslcontr-%05d-W m_work_thread thread m_post Return Code %d Error %d",
                       __LINE__, iml_rc1, iml_rc2 );
       }
     }
#endif
#ifdef WOTHR_LOCK_FREE
     iml1 = 0;
     if (ADSL_HCO_WOTHR_G->boc_active) {    /* was active before       */
       iml1 = 1;
//     dsg_hco_main.imc_workthr_active++;  /* active work threads  */
     }
     while ((dsg_hco_main.imc_workthr_active - iml1) < dsg_hco_main.imc_max_act_workthr) {
       adsl_hfe_w1 = (struct dsd_hco_fifo_ele *) m_hl_get_fifo( aas_thread_backlog_ctrl );
       if (adsl_hfe_w1 == NULL) break;      /* no work found           */
       adsl_waitwth_1_w1 = adsl_hfe_w1->adsc_waitwth;  /* real element */
       m_hl_lock_dec_1( &dsg_hco_main.imc_workque_sched );  /* work queue scheduled */
       adsl_hco_wothr_w1 = adsl_waitwth_1_w1->adsc_hco_wothr;  /* get special thread */
       if (adsl_waitwth_1_w1->adsc_hco_wothr == NULL) {  /* not special thread */
         ADSL_HCO_WOTHR_G->dsc_call_para_1 = adsl_waitwth_1_w1->dsc_call_para_1;  /* get work */
         if (ADSL_HCO_WOTHR_G->boc_active == FALSE) {  /* was not active */
           ADSL_HCO_WOTHR_G->boc_active = TRUE;  /* active working     */
           m_hl_lock_inc_1( &dsg_hco_main.imc_workthr_active );  /* active work threads */
         }
         m_hl_put_chain( aas_hco_fifo_ele_ctrl, adsl_hfe_w1 );
         m_hl_put_chain( aas_free_waiting_ctrl, adsl_waitwth_1_w1 );
         break;
       }
       adsl_hco_wothr_w1->boc_active = TRUE;  /* this thread active again */
       m_hl_lock_inc_1( &dsg_hco_main.imc_workthr_active );  /* active work threads */
       iml_rc1 = adsl_hco_wothr_w1->dsc_event.m_post( &iml_rc2 );  /* event of thread */
       if (iml_rc1 < 0) {                   /* error occured           */
         m_hl1_printf( "xslcontr-%05d-W m_work_thread thread m_post Return Code %d Error %d",
                       __LINE__, iml_rc1, iml_rc2 );
       }
       m_hl_put_chain( aas_hco_fifo_ele_ctrl, adsl_hfe_w1 );
       m_hl_put_chain( aas_free_waiting_ctrl, adsl_waitwth_1_w1 );
     }
     if (ADSL_HCO_WOTHR_G->dsc_call_para_1.amc_function) {  /* found work to do */
       if (ADSL_HCO_WOTHR_G->boc_active == FALSE) {  /* was not active before */
         ADSL_HCO_WOTHR_G->boc_active = TRUE;  /* is active now        */
         m_hl_lock_inc_1( &dsg_hco_main.imc_workthr_active );  /* active work threads */
       }
       continue;                            /* do the work             */
     }
     if (ADSL_HCO_WOTHR_G->boc_active) {    /* was active before       */
       m_hl_lock_dec_1( &dsg_hco_main.imc_workthr_active );  /* active work threads */
     }
     m_hl_lock_dec_1( &dsg_hco_main.imc_workthr_sched );  /* scheduled work threads */
     m_hl_put_chain( aas_thread_idle_ctrl, ADSL_HCO_WOTHR_G );
#endif
#ifndef PROBLEM_090305                      /* KDRS - deadlock - Web-Server hangs */
     /* wait for something to do                                       */
     iml_rc1 = ADSL_HCO_WOTHR_G->dsc_event.m_wait( &iml_rc2 );  /* event of thread */
     if (iml_rc1) {                         /* error occured           */
       m_hl1_printf( "xslcontr-%05d-W m_work_thread thread m_wait Return Code %d Error %d",
                     __LINE__, iml_rc1, iml_rc2 );
     }
#else
     /* wait for something to do                                       */
     do {
       iml_rc1 = ADSL_HCO_WOTHR_G->dsc_event.m_wait( &iml_rc2 );  /* event of thread */
       if (iml_rc1) {                       /* error occured           */
         m_hl1_printf( "xslcontr-%05d-W m_work_thread thread m_wait Return Code %d Error %d",
                       __LINE__, iml_rc1, iml_rc2 );
       }
       if (bos_end_proc) break;             /* end of threads          */
     } while (ADSL_HCO_WOTHR_G->dsc_call_para_1.amc_function == NULL);
#endif
     if (bos_end_proc) break;               /* end of threads          */
   }
   ADSL_HCO_WOTHR_G->boc_thr_close = TRUE;  /* thread closed           */
   iml_rc1 = ADSL_HCO_WOTHR_G->dsc_event.m_close( &iml_rc2 );
   if (iml_rc1) {                           /* error occured           */
     m_hl1_printf( "xslcontr-%05d-W m_work_thread event m_close Return Code %d Error %d",
                   __LINE__, iml_rc1, iml_rc2 );
   }
// free( ADSL_HCO_WOTHR_G );                /* free memory             */
   return 0;
#undef ADSL_HCO_WOTHR_G
} /* end m_work_thread()                                               */

#ifdef CHECKTHRACT
static void m_count_active( int imp_line, char *achp_msg ) {
   int        iml_disp_act;
   int        iml_count_act;
   int        iml_rc1;                      /* Return Code 1           */
   struct dsd_hco_wothr *adsl_hco_wothr_w1;  /* working variable       */

   iml_count_act = 0;
   iml_rc1 = dss_critsect_wothr.m_enter();  /* critical section        */
   iml_disp_act = dsg_hco_main.imc_workthr_active;  /* active work threads */
   adsl_hco_wothr_w1 = dsg_hco_main.adsc_hco_wothr_anchor;  /* set anchor of chain */
   while (adsl_hco_wothr_w1) {
     if (   (adsl_hco_wothr_w1->dsc_call_para_1.amc_function)
         && (adsl_hco_wothr_w1->boc_active)) {
       iml_count_act++;
     }
     adsl_hco_wothr_w1 = adsl_hco_wothr_w1->adsc_next;
   }
   iml_rc1 = dss_critsect_wothr.m_leave();  /* critical section        */
   if (iml_disp_act == iml_count_act) return;
   m_hl1_printf( "xslcontr-%05d-W m_count_active iml_disp_act=%d iml_count_act=%d source-l%05d %s",
                 __LINE__, iml_disp_act, iml_count_act,
                 imp_line, achp_msg );
} /* end m_count_active()                                              */
#endif
#ifdef HOB_CONTR_TIMER
/** set timer                                                          */
extern "C" void m_time_set( struct dsd_timer_ele *adsptiele, BOOL bop_endtime ) {
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */
   BOOL       bol_first_e;                  /* indicator changed first element */
   BOOL       bol_found_e;                  /* indicator element chain 2 found */
   BOOL       bol_next_time;                /* indicator element chain 2 next end-time */
   BOOL       bol_remove_ch2;               /* remove element chain 2  */
   struct dsd_tich2_ele *adsl_ticha_w1;     /* working-variable        */
   struct dsd_tich2_ele *adsl_ticha_prev;   /* save previous element   */
   struct dsd_tich2_ele *adsl_ticha_npos;   /* save new position element */
   HL_LONGLONG ill_time;                    /* current time / Epoch    */
#ifdef TRACE_TIMER_1
   int        iml_ts, iml_te;               /* count timer             */
#endif

#ifdef TRACEHL1
   m_hl1_printf( "m_time_set element %p", adsptiele );
#endif
#ifdef TRACE_TIMER_3
   m_hl1_printf( "xslcontr-%05d-T m_time_set() THR=%08d tiele=%p.",
                 __LINE__, HL_THRID, adsptiele );
#endif
   if (adsptiele == NULL) {
     m_hl1_printf( "xslcontr-%05d-W m_time_set() called with dsd_timer_ele zero",
                   __LINE__ );
     return;
   }
   ill_time = m_get_epoch_ms();             /* current time / Epoch    */
   if (bop_endtime == FALSE) {              /* wait time set           */
     adsptiele->ilcendtime = adsptiele->ilcwaitmsec + ill_time;
   } else {                                 /* end time set            */
     adsptiele->ilcwaitmsec = adsptiele->ilcendtime - ill_time;
   }
   dss_critsect_timer.m_enter();
#ifdef TRACE_TIMER_1
   iml_ts = m_check_timer_chain( __LINE__, "m_time_set() start" );
#endif
#define VPL_CHAIN_2 ((struct dsd_tich2_ele *) adsptiele->vpc_chain_2)
   /* put out of chain 2 first                                         */
   do {                                     /* pseudo-loop             */
     if (VPL_CHAIN_2 == NULL) break;        /* timer not in chain      */
     bol_first_e = FALSE;                   /* indicator changed first element */
     bol_remove_ch2 = FALSE;                /* do not remove element chain 2 */
     /* put out of chain                                               */
     if (adsptiele->adsctiele_prev) {
       (adsptiele->adsctiele_prev)->adsctiele_next
         = adsptiele->adsctiele_next;
     } else {
       bol_remove_ch2 = TRUE;               /* remove element chain 2  */
       if (adsptiele->adsctiele_next) {     /* is not only element     */
         VPL_CHAIN_2->adsctiele_first = adsptiele->adsctiele_next;
         bol_remove_ch2 = FALSE;            /* do not remove element chain 2 */
       }
       bol_first_e = TRUE;                  /* indicator changed first element */
     }
     if (adsptiele->adsctiele_next) {
       (adsptiele->adsctiele_next)->adsctiele_prev
         = adsptiele->adsctiele_prev;
     } else {
       VPL_CHAIN_2->adsctiele_last = adsptiele->adsctiele_prev;
     }
     if (bol_first_e == FALSE) {            /* indicator changed first element */
       adsptiele->vpc_chain_2 = NULL;       /* element no more in chain 2 */
       break;                               /* all done                */
     }
     if (bol_remove_ch2) {                  /* remove element chain 2  */
       /* no more element of chain 1 in this element of chain 2        */
       adsl_ticha_w1 = (struct dsd_tich2_ele *) adssticha_anchor;  /* get anchor chain 2 */
       adsl_ticha_prev = NULL;              /* no previous element yet */
       while (adsl_ticha_w1) {              /* search position in chain 2 */
         if (adsl_ticha_w1 == VPL_CHAIN_2) break;  /* position found   */
         adsl_ticha_prev = adsl_ticha_w1;   /* save previous element   */
         adsl_ticha_w1 = adsl_ticha_w1->adsc_next;  /* get next in chain */
       }
       if (adsl_ticha_w1 == NULL) {         /* position not found      */
         m_hl1_printf( "xslcontr-%05d-W logic-error timer-chain not found", __LINE__ );
         m_hl1_printf( "xslcontr-%05d-W +++ adsptiele=%p adsptiele->ilcwaitmsec=%lld",
                       __LINE__, adsptiele, adsptiele->ilcwaitmsec );
         break;
       }
       if (adsl_ticha_prev == NULL) {       /* was first in chain      */
         adssticha_anchor = VPL_CHAIN_2->adsc_next;
       } else {                             /* was middle in chain     */
         adsl_ticha_prev->adsc_next = VPL_CHAIN_2->adsc_next;
       }
       m_tich2_free( VPL_CHAIN_2 );         /* free this element of chain 2 */
       adsptiele->vpc_chain_2 = NULL;       /* element no more in chain 2 */
       break;                               /* all done                */
     }
     /* position of element chain 2 changes                            */
#ifdef B071204_B
     VPL_CHAIN_2->ilcendtime = VPL_CHAIN_2->adsctiele_first->ilcendtime;  /* epoch end of timer */
#endif
     adsl_ticha_w1 = (struct dsd_tich2_ele *) adssticha_anchor;  /* get anchor chain 2 */
     adsl_ticha_prev = NULL;                /* no previous element yet */
     adsl_ticha_npos = NULL;                /* no new position yet     */
     bol_found_e = FALSE;                   /* indicator element chain 2 found */
     bol_next_time = FALSE;                 /* indicator element chain 2 next end-time */
     while (adsl_ticha_w1) {                /* search position in chain 2 */
       if (adsl_ticha_w1 == VPL_CHAIN_2) {  /* position found          */
         if (bol_next_time) break;          /* indicator element chain 2 next end-time */
         bol_found_e = TRUE;                /* indicator element chain 2 found */
#ifdef OLD01
#ifdef FOR_KEDIT
       {
#endif
       }
       if (adsptiele->ilcendtime >= adsl_ticha_w1->ilcendtime) {
         if (bol_found_e) break;            /* indicator element chain 2 found */
         bol_next_time = TRUE;              /* indicator element chain 2 next end-time */
       } else {
         adsl_ticha_npos = adsl_ticha_w1;   /* save new position element */
       }
       if (bol_found_e == FALSE) {          /* indicator element chain 2 found */
         adsl_ticha_prev = adsl_ticha_w1;   /* save previous element   */
       }
#endif
       } else {                             /* is not old element      */
#ifdef B071120
         if (VPL_CHAIN_2->ilcendtime >= adsl_ticha_w1->ilcendtime) {
#ifdef FORKEDIT
         }
#endif
#else
#ifdef B071204_B
         if (adsl_ticha_w1->ilcendtime >= VPL_CHAIN_2->ilcendtime) {
#ifdef FORKEDIT
         }
#endif
#else
         if (adsl_ticha_w1->adsctiele_first->ilcendtime >= VPL_CHAIN_2->adsctiele_first->ilcendtime) {
#endif
#endif
           if (bol_found_e) break;          /* indicator element chain 2 found */
           bol_next_time = TRUE;            /* indicator element chain 2 next end-time */
         } else {
           adsl_ticha_npos = adsl_ticha_w1;  /* save new position element */
         }
         if (bol_found_e == FALSE) {        /* indicator element chain 2 found */
           adsl_ticha_prev = adsl_ticha_w1;  /* save previous element  */
         }
       }
       adsl_ticha_w1 = adsl_ticha_w1->adsc_next;  /* get next in chain */
     }
     if (adsl_ticha_npos != adsl_ticha_prev) {  /* position has changed */
       /* first element chain 2 out of chain                           */
       if (adsl_ticha_prev == NULL) {       /* was first in chain      */
         adssticha_anchor = VPL_CHAIN_2->adsc_next;  /* set anchor chain 2 */
       } else {                             /* middle in chain         */
         adsl_ticha_prev->adsc_next = VPL_CHAIN_2->adsc_next;  /* out of chain 2 */
       }
       /* second insert in chain at new position                       */
       if (adsl_ticha_npos == NULL) {       /* is now first in chain   */
         VPL_CHAIN_2->adsc_next = (struct dsd_tich2_ele *) adssticha_anchor;  /* get old chain */
         adssticha_anchor = VPL_CHAIN_2;    /* set anchor chain 2      */
       } else {                             /* middle in chain         */
         VPL_CHAIN_2->adsc_next = adsl_ticha_npos->adsc_next;  /* get old chain  */
         adsl_ticha_npos->adsc_next = VPL_CHAIN_2;  /* set in chain 2  */
       }
     }
     adsptiele->vpc_chain_2 = NULL;         /* element no more in chain 2 */
   } while (FALSE);
   /* now search position where the interval is equal                  */
   adsl_ticha_w1 = (struct dsd_tich2_ele *) adssticha_anchor;  /* get anchor chain 2 */
   adsl_ticha_npos = NULL;                  /* no new position yet     */
   /* store in adsl_ticha_npos the last element, where the end-time is smaller */
   /* then insert the new element after this element                   */
   while (adsl_ticha_w1) {                  /* search position in chain 2 */
     if (adsl_ticha_w1->ilcwaitmsec == adsptiele->ilcwaitmsec) {  /* position found */
       adsptiele->vpc_chain_2 = adsl_ticha_w1;  /* save this element   */
       adsl_ticha_npos = adsl_ticha_w1;     /* do not notify timer thread */
       break;                               /* all done                */
     }
#ifdef B071204_B
     if (adsl_ticha_w1->ilcendtime < adsptiele->ilcendtime) {  /* end-timer smaller */
#ifdef FORKEDIT
     }
#endif
#else
     if (adsl_ticha_w1->adsctiele_first->ilcendtime < adsptiele->ilcendtime) {  /* end-timer smaller */
#endif
       adsl_ticha_npos = adsl_ticha_w1;     /* save new position element */
     }
     /* extended 12.12.07 KB */
     if (adsl_ticha_w1->ilcendtime > adsptiele->ilcendtime) break;  /* already too far */
     adsl_ticha_w1 = adsl_ticha_w1->adsc_next;  /* get next in chain   */
   }
   if (VPL_CHAIN_2 == NULL) {               /* element chain 2 not found */
     adsptiele->vpc_chain_2 = m_tich2_alloc();  /* acquire new element */
     VPL_CHAIN_2->adsctiele_last = NULL;    /* no element yet          */
     VPL_CHAIN_2->ilcwaitmsec = adsptiele->ilcwaitmsec;  /* set interval */
#ifdef B071204_B
     VPL_CHAIN_2->ilcendtime = adsptiele->ilcendtime;  /* set end-time */
#endif
     if (adsl_ticha_npos == NULL) {         /* is now first element    */
       VPL_CHAIN_2->adsc_next = (struct dsd_tich2_ele *) adssticha_anchor;  /* get old anchor */
       adssticha_anchor = VPL_CHAIN_2;      /* set new anchor          */
     } else {                               /* is now middle in chain  */
       VPL_CHAIN_2->adsc_next = adsl_ticha_npos->adsc_next;  /* get old chain */
       adsl_ticha_npos->adsc_next = VPL_CHAIN_2;  /* set now in chain  */
     }
   }
   /* set new chain 1                                                  */
   adsptiele->adsctiele_next = NULL;        /* no element after this   */
   adsptiele->adsctiele_prev = VPL_CHAIN_2->adsctiele_last;
   VPL_CHAIN_2->adsctiele_last = adsptiele;  /* is now last in chain   */
   if (adsptiele->adsctiele_prev)
     (adsptiele->adsctiele_prev)->adsctiele_next = adsptiele;
   else VPL_CHAIN_2->adsctiele_first = adsptiele;  /* is only in chain */
#undef VPL_CHAIN_2
#ifdef TRACE_TIMER_1
   iml_te = m_check_timer_chain( __LINE__, "m_time_set() end" );
   if (iml_te != (iml_ts + 1)) {
     m_hl1_printf( "l%05d m_time_set() illogic counter",
                   __LINE__, adsptiele );
#ifndef HL_UNIX
     ExitProcess( 3 );
#else
     exit( 3 );
#endif
   }
#endif
   dss_critsect_timer.m_leave();
   if (adsl_ticha_npos == NULL) {           /* timer thread has to expirer more early */
     iml_rc1 = dss_event_timer.m_post( &iml_rc2 );  /* event for timer */
     if (iml_rc1 < 0) {                     /* error occured           */
       m_hl1_printf( "xslcontr-%05d-W m_time_set timer m_post Return Code %d Error %d",
                     __LINE__, iml_rc1, iml_rc2 );
     }
   }
} /* end m_time_set()                                                  */

/** release timer                                                      */
extern "C" BOOL m_time_rel( struct dsd_timer_ele *adsptiele ) {
   BOOL       bol_removed;                  /* indicator timer really removed */
   BOOL       bol_first_e;                  /* indicator changed first element */
   BOOL       bol_found_e;                  /* indicator element chain 2 found */
   BOOL       bol_next_time;                /* indicator element chain 2 next end-time */
   BOOL       bol_remove_ch2;               /* remove element chain 2  */
   struct dsd_tich2_ele *adsl_ticha_w1;     /* working variable        */
   struct dsd_tich2_ele *adsl_ticha_prev;   /* save previous element   */
   struct dsd_tich2_ele *adsl_ticha_npos;   /* save new position element */
#ifdef TRACE_TIMER_1
   int        iml_ts, iml_te;               /* count timer             */
#endif

#ifdef TRACE_TIMER_3
   m_hl1_printf( "xslcontr-%05d-T m_time_rel() THR=%08d tiele=%p.",
                 __LINE__, HL_THRID, adsptiele );
#endif
   if (adsptiele == NULL) {
     m_hl1_printf( "xslcontr-%05d-W m_time_rel() called with dsd_timer_ele zero",
                     __LINE__ );
     return FALSE;
   }
   bol_removed = FALSE;                     /* indicator timer really removed */
   dss_critsect_timer.m_enter();
#ifdef TRACE_TIMER_1
   iml_ts = m_check_timer_chain( __LINE__, "m_time_rel() start" );
#endif
#ifndef HELP_DEBUG                          /* 05.07.06 KB - help in tracing */
#define VPL_CHAIN_2 ((struct dsd_tich2_ele *) adsptiele->vpc_chain_2)
#else                                       /* ifndef HELP_DEBUG * 05.07.06 KB - help in tracing */
   struct dsd_tich2_ele *VPL_CHAIN_2 = (struct dsd_tich2_ele *) adsptiele->vpc_chain_2;
#endif                                      /* ifndef HELP_DEBUG * 05.07.06 KB - help in tracing */
   do {                                     /* pseudo-loop             */
     if (VPL_CHAIN_2 == NULL) break;        /* timer not in chain      */
#ifndef B120125
#ifdef TRACE_TIMER_1
     iml_ts--;
#endif
#endif
     bol_removed = TRUE;                    /* indicator timer really removed */
     bol_first_e = FALSE;                   /* indicator changed first element */
     bol_remove_ch2 = FALSE;                /* do not remove element chain 2 */
     /* put out of chain                                               */
     if (adsptiele->adsctiele_prev) {
       (adsptiele->adsctiele_prev)->adsctiele_next
         = adsptiele->adsctiele_next;
     } else {
       bol_remove_ch2 = TRUE;               /* remove element chain 2  */
       if (adsptiele->adsctiele_next) {     /* is not only element     */
         VPL_CHAIN_2->adsctiele_first = adsptiele->adsctiele_next;
         bol_remove_ch2 = FALSE;            /* do not remove element chain 2 */
       }
       bol_first_e = TRUE;                  /* indicator changed first element */
     }
     if (adsptiele->adsctiele_next) {
       (adsptiele->adsctiele_next)->adsctiele_prev
         = adsptiele->adsctiele_prev;
     } else {
       VPL_CHAIN_2->adsctiele_last = adsptiele->adsctiele_prev;
     }
     if (bol_first_e == FALSE) {            /* indicator changed first element */
       adsptiele->vpc_chain_2 = NULL;       /* element no more in chain 2 */
       break;                               /* all done                */
     }
     if (bol_remove_ch2) {                  /* remove element chain 2  */
       /* no more element of chain 1 in this element of chain 2        */
       adsl_ticha_w1 = (struct dsd_tich2_ele *) adssticha_anchor;  /* get anchor chain 2 */
       adsl_ticha_prev = NULL;              /* no previous element yet */
       while (adsl_ticha_w1) {              /* search position in chain 2 */
         if (adsl_ticha_w1 == VPL_CHAIN_2) break;  /* position found   */
         adsl_ticha_prev = adsl_ticha_w1;   /* save previous element   */
         adsl_ticha_w1 = adsl_ticha_w1->adsc_next;  /* get next in chain */
       }
       if (adsl_ticha_w1 == NULL) {         /* position not found      */
         m_hl1_printf( "xslcontr-%05d-W logic-error timer-chain not found", __LINE__ );
         m_hl1_printf( "xslcontr-%05d-W +++ adsptiele=%p adsptiele->ilcwaitmsec=%lld",
                       __LINE__, adsptiele, adsptiele->ilcwaitmsec );
         break;
       }
       if (adsl_ticha_prev == NULL) {       /* was first in chain      */
         adssticha_anchor = VPL_CHAIN_2->adsc_next;
       } else {                             /* was middle in chain     */
         adsl_ticha_prev->adsc_next = VPL_CHAIN_2->adsc_next;
       }
       m_tich2_free( VPL_CHAIN_2 );         /* free this element of chain 2 */
       adsptiele->vpc_chain_2 = NULL;       /* element no more in chain 2 */
       break;                               /* all done                */
     }
     /* position of element chain 2 changes                            */
#ifdef B071204_B
     VPL_CHAIN_2->ilcendtime = VPL_CHAIN_2->adsctiele_first->ilcendtime;  /* epoch end of timer */
#endif
     adsl_ticha_w1 = (struct dsd_tich2_ele *) adssticha_anchor;  /* get anchor chain 2 */
     adsl_ticha_prev = NULL;                /* no previous element yet */
     adsl_ticha_npos = NULL;                /* no new position yet     */
     bol_found_e = FALSE;                   /* indicator element chain 2 found */
     bol_next_time = FALSE;                 /* indicator element chain 2 next end-time */
#ifdef B060705
     while (adsl_ticha_w1) {                /* search position in chain 2 */
       if (adsl_ticha_w1 == VPL_CHAIN_2) {  /* position found          */
         if (bol_next_time) break;          /* indicator element chain 2 next end-time */
         bol_found_e = TRUE;                /* indicator element chain 2 found */
       }
#ifdef B071204_B
       if (adsptiele->ilcendtime >= adsl_ticha_w1->ilcendtime) {
#ifdef FORKEDIT
       }
#endif
#else
       if (adsptiele->adsctiele_first->ilcendtime >= adsl_ticha_w1->adsctiele_first->ilcendtime) {
#endif
         if (bol_found_e) break;            /* indicator element chain 2 found */
         bol_next_time = TRUE;              /* indicator element chain 2 next end-time */
       } else {
         adsl_ticha_npos = adsl_ticha_w1;   /* save new position element */
       }
       if (bol_found_e == FALSE) {          /* indicator element chain 2 found */
         adsl_ticha_prev = adsl_ticha_w1;   /* save previous element   */
       }
       adsl_ticha_w1 = adsl_ticha_w1->adsc_next;  /* get next in chain */
     }
#endif
     while (adsl_ticha_w1) {                /* search position in chain 2 */
       if (adsl_ticha_w1 == VPL_CHAIN_2) {  /* position found          */
         if (bol_next_time) break;          /* indicator element chain 2 next end-time */
         bol_found_e = TRUE;                /* indicator element chain 2 found */
       } else {
#ifdef B071120
         if (VPL_CHAIN_2->ilcendtime >= adsl_ticha_w1->ilcendtime) {
#ifdef FORKEDIT
         }
#endif
#else
#ifdef B071204_B
         if (adsl_ticha_w1->ilcendtime >= VPL_CHAIN_2->ilcendtime) {
#ifdef FORKEDIT
         }
#endif
#else
         if (adsl_ticha_w1->adsctiele_first->ilcendtime >= VPL_CHAIN_2->adsctiele_first->ilcendtime) {
#endif
#endif
           if (bol_found_e) break;          /* indicator element chain 2 found */
           bol_next_time = TRUE;            /* indicator element chain 2 next end-time */
         } else {
           adsl_ticha_npos = adsl_ticha_w1;  /* save new position element */
         }
         if (bol_found_e == FALSE) {        /* indicator element chain 2 found */
           adsl_ticha_prev = adsl_ticha_w1;  /* save previous element  */
         }
       }
       adsl_ticha_w1 = adsl_ticha_w1->adsc_next;  /* get next in chain */
     }
     if (adsl_ticha_npos != adsl_ticha_prev) {  /* position has changed */
       /* first element chain 2 out of chain                           */
       if (adsl_ticha_prev == NULL) {       /* was first in chain      */
         adssticha_anchor = VPL_CHAIN_2->adsc_next;  /* set anchor chain 2 */
       } else {                             /* middle in chain         */
         adsl_ticha_prev->adsc_next = VPL_CHAIN_2->adsc_next;  /* out of chain 2 */
       }
       /* second insert in chain at new position                       */
       if (adsl_ticha_npos == NULL) {       /* is now first in chain   */
         VPL_CHAIN_2->adsc_next = (struct dsd_tich2_ele *) adssticha_anchor;  /* get old chain */
         adssticha_anchor = VPL_CHAIN_2;    /* set anchor chain 2      */
       } else {                             /* middle in chain         */
         VPL_CHAIN_2->adsc_next = adsl_ticha_npos->adsc_next;  /* get old chain  */
         adsl_ticha_npos->adsc_next = VPL_CHAIN_2;  /* set in chain 2  */
       }
     }
     adsptiele->vpc_chain_2 = NULL;         /* element no more in chain 2 */
   } while (FALSE);
#ifndef HELP_DEBUG                          /* 05.07.06 KB - help in tracing */
#undef VPL_CHAIN_2
#endif                                      /* ifndef HELP_DEBUG * 05.07.06 KB - help in tracing */
#ifdef TRACE_TIMER_1
   iml_te = m_check_timer_chain( __LINE__, "m_time_rel() end" );
#ifdef B120125
   if (iml_te != (iml_ts - 1)) {
     m_hl1_printf( "l%05d m_time_rel() illogic counter",
                   __LINE__, adsptiele );
#ifndef HL_UNIX
     ExitProcess( 3 );
#else
     exit( 3 );
#endif
   }
#endif
#ifndef B120125
   if (iml_te != iml_ts) {
     m_hl1_printf( "l%05d m_time_rel() illogic counter",
                   __LINE__, adsptiele );
#ifndef HL_UNIX
     ExitProcess( 3 );
#else
     exit( 3 );
#endif
   }
#endif
   if (adsptiele->vpc_chain_2) {
     m_hl1_printf( "l%05d m_time_rel() found vpc_chain_2 still set",
                   __LINE__, adsptiele );
#ifndef HL_UNIX
     ExitProcess( 3 );
#else
     exit( 3 );
#endif
   }
#endif
   dss_critsect_timer.m_leave();
   return bol_removed;                      /* indicated if really removed */
} /* end m_time_rel()                                                  */

/** thread which takes track of the timers                             */
static htfunc1_t m_timer_thr( void * ) {
   int        iml_rc1;                      /* Return Code 1           */
   int        iml_rc2;                      /* Return Code 2           */
   HL_LONGLONG ill_timer_act;               /* current time milliseconds */
   struct dsd_timer_ele *adsl_tiele_w1;
   struct dsd_tich2_ele *adsl_ticha_w1;     /* working variable        */
   struct dsd_tich2_ele *adsl_ticha_w2;     /* working variable        */
   struct dsd_tich2_ele *adsl_ticha_prev;   /* save previous element   */
   signed int iml_wait;                     /* difference of time      */
#ifndef B071203
   void (* aml_compl) ( struct dsd_timer_ele * );  /* Completition Routine */
#endif
// BOOL     bol1;
#ifdef TRACEHLA
   HL_LONGLONG ilh_timer_set;
   HL_LONGLONG ilh_timer_act;
#endif

   putime00:                                /* what to do              */
#ifdef TRACEHLA
   ilh_timer_set = ims_timer_set;
   ilh_timer_act = 0;
#endif
   iml_wait = INFINITE;
   adsl_ticha_w1 = (struct dsd_tich2_ele *) adssticha_anchor;  /* get first in chain */
   if (adsl_ticha_w1 == NULL) goto putime20;  /* no timer set          */
   /* not yet elapsed                                                  */
   ill_timer_act = m_get_epoch_ms();        /* get current Epoch Milliseconds */
#ifdef TRACEHLA
   ilh_timer_act = ill_timer_act;
#endif
   adsl_tiele_w1 = (struct dsd_timer_ele *) adsl_ticha_w1->adsctiele_first;  /* save entry      */
#ifndef B071203
   aml_compl = adsl_tiele_w1->amc_compl;    /* save address completition-routine */
#endif
   iml_wait = (int) (adsl_tiele_w1->ilcendtime - ill_timer_act);  /* compute millisec */
   if (iml_wait > 0) {                      /* timer not yet elapsed   */
     goto putime20;
   }
   /* timer timed out                                                  */
   dss_critsect_timer.m_enter();
#ifdef TRACE_TIMER_1
   m_check_timer_chain( __LINE__, "m_timer_thr() 1" );
#endif
#ifdef DEB_071204_01
   m_hl1_printf( "xslcontr-%05d-T m_timer_thr timeout iss_timer_c1_1=%d",
                 __LINE__, iss_timer_c1_1 );
   if (iss_timer_c1_1 == 4) {
     m_hl1_printf( "xslcontr-%05d-T m_timer_thr timeout iss_timer_c1_1=%d - debug here",
                   __LINE__, iss_timer_c1_1 );
   }
#endif
   do {                                     /* pseudo-loop             */
     /* first check if something changed, we were not in Critical Section */
     if (adsl_ticha_w1 != adssticha_anchor) {
#ifdef B071203
       adsl_tiele_w1 = NULL;                /* do not activate         */
#else
       aml_compl = NULL;                    /* do not activate         */
#endif
       break;                               /* do again                */
     }
     if (adsl_tiele_w1 != adsl_ticha_w1->adsctiele_first) {
#ifdef B071203
       adsl_tiele_w1 = NULL;                /* do not activate         */
#else
       aml_compl = NULL;                    /* do not activate         */
#endif
       break;                               /* do again                */
     }
     adsl_tiele_w1->vpc_chain_2 = NULL;     /* element no more in chain 2 */
     adssticha_anchor = adsl_ticha_w1->adsc_next;  /* element type 2 out of chain */
     if (adsl_tiele_w1->adsctiele_next == NULL) {  /* was only element */
       m_tich2_free( adsl_ticha_w1 );       /* element type 2 no more needed */
       break;
     }
     adsl_ticha_w1->adsctiele_first = adsl_tiele_w1->adsctiele_next;  /* element type 1 out of chain */
#ifndef B071205
#ifdef B071204_B
     adsl_ticha_w1->ilcendtime = adsl_ticha_w1->adsctiele_first->ilcendtime;
#endif
#endif
     adsl_ticha_w1->adsctiele_first->adsctiele_prev = NULL;  /* points on anchor now */
     adsl_ticha_w2 = (struct dsd_tich2_ele *) adssticha_anchor;  /* get anchor of chain type 2 */
     adsl_ticha_prev = NULL;                /* no previous element yet */
#ifdef DEB_071204_01
     iss_timer_c1_1++;
     m_hl1_printf( "xslcontr-%05d-T m_timer_thr change chain iss_timer_c1_1=%d",
                   __LINE__, iss_timer_c1_1 );
#endif
     while (adsl_ticha_w2) {                /* loop over chain type 2  */
#ifdef B060920
       if (adsl_ticha_w2->adsctiele_first->ilcendtime
             < adsl_ticha_w1->adsctiele_first->ilcendtime)
         break;                             /* correct position found  */
#endif
#ifdef D_XXX_U1
#undef D_XXX_U1
#endif
#ifdef B071205
#define D_XXX_U1
#endif
#ifndef B071204_B
#ifndef D_XXX_U1
#define D_XXX_U1
#endif
#endif
#ifdef D_XXX_U1
#define B071204_A
#ifdef B071204_A
       if (adsl_ticha_w2->adsctiele_first->ilcendtime
             > adsl_ticha_w1->adsctiele_first->ilcendtime)
         break;                             /* correct position found  */
#else
       if (adsl_ticha_w2->adsctiele_first->ilcendtime
             < adsl_ticha_w1->adsctiele_first->ilcendtime)
         break;                             /* correct position found  */
#endif
#else
       if (adsl_ticha_w2->ilcendtime > adsl_ticha_w1->ilcendtime)
         break;                             /* correct position found  */
#endif
       adsl_ticha_prev = adsl_ticha_w2;     /* save previous element chain type 2 */
       adsl_ticha_w2 = adsl_ticha_w2->adsc_next;  /* get next in chain */
     }
     if (adsl_ticha_prev == NULL) {         /* was first in chain      */
       adsl_ticha_w1->adsc_next = (struct dsd_tich2_ele *) adssticha_anchor;
       adssticha_anchor = adsl_ticha_w1;
     } else {                               /* now middle in chain     */
       adsl_ticha_w1->adsc_next = adsl_ticha_prev->adsc_next;
       adsl_ticha_prev->adsc_next = adsl_ticha_w1;
     }
   } while (FALSE);
#ifdef TRACE_TIMER_1
   m_check_timer_chain( __LINE__, "m_timer_thr() 2" );
#endif
   dss_critsect_timer.m_leave();
#ifdef TRACE_TIMER_3
   m_hl1_printf( "xslcontr-%05d-T m_timer_thr() THR=%08d tiele=%p compl=%p.",
                 __LINE__, HL_THRID, adsl_tiele_w1, aml_compl );
#endif
#ifdef B071203
   if (adsl_tiele_w1) {                     /* do activate             */
     adsl_tiele_w1->amc_compl( adsl_tiele_w1 );
   }
#else
   if (aml_compl) {                         /* do activate             */
     aml_compl( adsl_tiele_w1 );
   }
#endif
   goto putime00;                           /* what to do              */

   putime20:                                /* wait for event          */
   /* wait for timeout                                                 */
   iml_rc1 = dss_event_timer.m_wait_msec( iml_wait, &iml_rc2 );  /* wait for timer */
   if ((iml_rc1 < 0) && (iml_rc1 != -2)) {  /* error occured           */
     m_hl1_printf( "xslcontr-%05d-W m_timer_thr m_waitmsec Return Code %d Error %d.",
                   __LINE__, iml_rc1, iml_rc2 );
   }
   if (bos_end_proc == FALSE) {             /* check end of threads    */
     goto putime00;                         /* continue                */
   }
   return 0;
} /* end m_timer_thr()                                                 */

/**
   Method to acquire an element for timer chain 2.
   No synchronisation or Critical Section is needed,
   since the calling method already is in a Critical Section
   and protected everything
*/
static struct dsd_tich2_ele * m_tich2_alloc( void ) {
   int        inl1;                         /* working variable        */
   struct dsd_tich2_ele *adsl_ticha_w1;     /* working variable        */
   struct dsd_tich2_ele *adsl_ticha_w2;     /* working variable        */

   if (adssticha_free) {                    /* already free buffer found */
     adsl_ticha_w1 = adssticha_free;        /* get first element       */
     adssticha_free = adsl_ticha_w1->adsc_next;  /* get next in chain  */
     return adsl_ticha_w1;
   }
   adsl_ticha_w1 = (struct dsd_tich2_ele *) malloc( DEF_TICH2_NO_FREE * sizeof(struct dsd_tich2_ele) );
   adsl_ticha_w2 = adsl_ticha_w1 + 1;       /* first free element      */
   adssticha_free = adsl_ticha_w2;          /* set new chain of free elements */
   inl1 = DEF_TICH2_NO_FREE - 2;            /* set index for loop      */
   do {
     adsl_ticha_w2->adsc_next = adsl_ticha_w2 + 1;  /* set chain to next free */
     adsl_ticha_w2++;                       /* pointer to next element */
     inl1--;                                /* decrement index         */
   } while (inl1 > 0);
   adsl_ticha_w2->adsc_next = NULL;         /* this is last element in chain */
   return adsl_ticha_w1;
} /* end m_tich2_alloc()                                               */

/** subroutine to free an element for timer chain 2.                   */
static void m_tich2_free( struct dsd_tich2_ele *adsp_ticha ) {
   adsp_ticha->adsc_next = adssticha_free;  /* get old chain           */
   adssticha_free = adsp_ticha;             /* set new chain of free elements */
} /* end m_tich2_free()                                                */

#ifdef TRACE_TIMER_1
static int m_check_timer_chain( int imp_line, char * achp_comment ) {
   int        iml_count;                    /* count entries           */
#ifdef TRACE_TIMER_2
   int        iml_index;                    /* index to display        */
#endif
   struct dsd_timer_ele *adsl_tiele_w1;     /* working-variable        */
   struct dsd_timer_ele *adsl_tiele_w2;     /* working-variable        */
   struct dsd_tich2_ele *adsl_ticha_w1;     /* working variable        */
   struct dsd_tich2_ele *adsl_ticha_w2;     /* working variable        */

   if (adssticha_anchor == NULL) return 0;
   iml_count = 0;                           /* count entries           */
#ifdef TRACE_TIMER_2
   iml_index = 0;                           /* index to display        */
#endif
   adsl_ticha_w1 = (struct dsd_tich2_ele *) adssticha_anchor;  /* get first in chain */
   adsl_ticha_w2 = NULL;                    /* no previous element     */
   do {
#ifdef B071204_B
     if (adsl_ticha_w1->ilcendtime != adsl_ticha_w1->adsctiele_first->ilcendtime) {
       m_hl1_printf( "l%05d m_check_timer_chain() found ilcendtime different from adsctiele_first dsd_tich2_ele=%p source-l%05d %s",
                     __LINE__, adsl_ticha_w1,
                     imp_line, achp_comment );
#ifndef HL_UNIX
       fflush( stdout );
       ExitProcess( 3 );
#else
       exit( 3 );
#endif
     }
     if (   (adsl_ticha_w2)
         && (adsl_ticha_w1->ilcendtime < adsl_ticha_w2->ilcendtime)) {
#ifdef FORKEDIT
     }
#endif
#else
     if (   (adsl_ticha_w2)
         && (adsl_ticha_w1->adsctiele_first->ilcendtime < adsl_ticha_w2->adsctiele_first->ilcendtime)) {
#endif
       m_hl1_printf( "l%05d m_check_timer_chain() found invalid sequence dsd_tich2_ele=%p source-l%05d %s",
                     __LINE__, adsl_ticha_w1,
                     imp_line, achp_comment );
#ifndef HL_UNIX
       {
         int imh1 = 1000;
         do {
           m_hl1_printf( "fill output ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" );
           imh1--;
         } while (imh1 > 0);
       }
       fflush( stdout );
       ExitProcess( 3 );
#else
       exit( 3 );
#endif
     }
     adsl_tiele_w1 = (struct dsd_timer_ele *) adsl_ticha_w1->adsctiele_first;  /* get start of chain */
     adsl_tiele_w2 = NULL;                  /* no previous element     */
     do {
#ifdef TRACE_TIMER_2
       iml_index++;                         /* index to display        */
       m_hl1_printf( "l%05d m_check_timer_chain() e%04d dsd_tich2_ele=%p dsd_timer_ele=%p compl=%p source-l%05d %s",
                     __LINE__, iml_index, adsl_ticha_w1, adsl_tiele_w1, adsl_tiele_w1->amc_compl,
                     imp_line, achp_comment );
#endif
       if (adsl_tiele_w1->vpc_chain_2 != (void *) adsl_ticha_w1) {
         m_hl1_printf( "l%05d m_check_timer_chain() found != vpc_chain_2 dsd_tich2_ele=%p dsd_timer_ele=%p source-l%05d %s",
                       __LINE__, adsl_ticha_w1, adsl_tiele_w1,
                       imp_line, achp_comment );
#ifndef HL_UNIX
         ExitProcess( 3 );
#else
         exit( 3 );
#endif
       }
       if (adsl_tiele_w1->ilcwaitmsec != adsl_ticha_w1->ilcwaitmsec) {
         m_hl1_printf( "l%05d m_check_timer_chain() found != ilcwaitmsec dsd_tich2_ele=%p dsd_timer_ele=%p source-l%05d %s",
                       __LINE__, adsl_ticha_w1, adsl_tiele_w1,
                       imp_line, achp_comment );
#ifndef HL_UNIX
         ExitProcess( 3 );
#else
         exit( 3 );
#endif
       }
       if (adsl_tiele_w1->adsctiele_prev != adsl_tiele_w2) {
         m_hl1_printf( "l%05d m_check_timer_chain() found != adsctiele_prev dsd_tich2_ele=%p dsd_timer_ele=%p source-l%05d %s",
                       __LINE__, adsl_ticha_w1, adsl_tiele_w1,
                       imp_line, achp_comment );
#ifndef HL_UNIX
         ExitProcess( 3 );
#else
         exit( 3 );
#endif
       }
       if (   (adsl_tiele_w2)
           && (adsl_tiele_w1->ilcendtime < adsl_tiele_w2->ilcendtime)) {
         m_hl1_printf( "l%05d m_check_timer_chain() found invalid sequ ilcendtime dsd_tich2_ele=%p dsd_timer_ele=%p source-l%05d %s",
                       __LINE__, adsl_ticha_w1, adsl_tiele_w1,
                       imp_line, achp_comment );
#ifndef HL_UNIX
         ExitProcess( 3 );
#else
         exit( 3 );
#endif
       }
       iml_count++;                         /* count entries           */
       adsl_tiele_w2 = adsl_tiele_w1;       /* set previous element    */
       adsl_tiele_w1 = adsl_tiele_w1->adsctiele_next;
     } while (adsl_tiele_w1);
     if (adsl_tiele_w2 != adsl_ticha_w1->adsctiele_last) {
       m_hl1_printf( "l%05d m_check_timer_chain() found invalid adsctiele_last dsd_tich2_ele=%p source-l%05d %s",
                     __LINE__, adsl_ticha_w1,
                     imp_line, achp_comment );
#ifndef HL_UNIX
       ExitProcess( 3 );
#else
       exit( 3 );
#endif
     }
     adsl_ticha_w2 = adsl_ticha_w1;         /* set previous element    */
     adsl_ticha_w1 = adsl_ticha_w1->adsc_next;  /* get next in chain   */
   } while (adsl_ticha_w1);
   return iml_count;                        /* return count entries    */
} /* end m_check_timer_chain()                                         */
#endif
#endif

/** return the Epoch value in milliseconds                             */
extern "C" HL_LONGLONG m_get_epoch_ms( void ) {
#ifndef HL_UNIX
   struct __timeb64 timebuffer;

   _ftime64( &timebuffer );

#ifdef B090317
   return ( timebuffer.time * 1000 - timebuffer.timezone * 60 * 1000 + timebuffer.millitm );
#else
   return ( timebuffer.time * 1000 + timebuffer.millitm );
#endif
#else
   struct timeval dsl_timeval;

   gettimeofday( &dsl_timeval, NULL );
#ifdef B120220
   return (dsl_timeval.tv_sec * 1000 + dsl_timeval.tv_usec / 1000);
#else
   return (((HL_LONGLONG) dsl_timeval.tv_sec) * 1000 + dsl_timeval.tv_usec / 1000);
#endif
#endif
} /* end m_get_epoch_ms()                                              */

#ifdef HL_FREEBSD
/** get the thread id                                                  */
static pid_t m_gettid( void ) {
   long int iml_pwtid;

   thr_self( &iml_pwtid );
// iml_pwtid = 999;
   return (pid_t) iml_pwtid;
} /* end m_gettid()                                                    */
#endif
