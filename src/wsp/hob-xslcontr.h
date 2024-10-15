/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: hob-xslcontr.h                                      |*/
/*| -------------                                                     |*/
/*|  HOB common library - control                                     |*/
/*|  Work Threads and Timers                                          |*/
/*|  KB 04.08.05                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2005                                   |*/
/*|  Copyright (C) HOB Germany 2006                                   |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|  Copyright (C) HOB Germany 2016                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio .NET 2003                                       |*/
/*|                                                                   |*/
/*| EXPECTED INPUT:                                                   |*/
/*| ---------------                                                   |*/
/*|                                                                   |*/
/*| EXPECTED OUTPUT:                                                  |*/
/*| ----------------                                                  |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifndef HOB_XSLCONTR
#define HOB_XSLCONTR

#include <hob-thread.hpp>
#include <hob-xslhcla1.hpp>

#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif

#ifndef DEF_PRIO_DEFAULT
#define DEF_PRIO_DEFAULT       3            /* default priority        */
#define DEF_PRIO_MINIMUM       1            /* minimum priority        */
#define DEF_PRIO_MAXIMUM       5            /* maximum priority        */
#endif

#define D_RET_WAIT_POST        0            /* event was set thru post */
#define D_RET_WAIT_TIMEOUT     1            /* timeout occured         */
#define D_RET_WAIT_ERROR       2            /* error occured           */

typedef void ( * md_func_1 )( struct dsd_hco_wothr *, void *, void *, void * );
typedef void ( * md_func_thr_sta )( struct dsd_hco_wothr *, int );

#ifdef HOB_CONTR_TIMER
/* The following structure is used for timers which are queued.        */
struct dsd_timer_ele {                      /* for timers / element    */
   HL_LONGLONG ilcwaitmsec;                 /* wait in milliseconds    */
   HL_LONGLONG ilcendtime;                  /* epoch end of timer      */
// BOOL       boc_timer_set;                /* timer has been set      */
   void (* amc_compl) ( struct dsd_timer_ele * );  /* Completition Routine */
                                            /* call when timer expired */
   struct dsd_timer_ele *adsctiele_prev;    /* previous element        */
   struct dsd_timer_ele *adsctiele_next;    /* next element in chain   */
   void *     vpc_chain_2;                  /* only used by islcontr.cpp */
};
#endif

/* The following structure is used for all the parameters used when
   calling a function.                                                 */
struct dsd_call_para_1 {                    /* call parameters         */
   md_func_1  amc_function;                 /* function to call        */
   void       *ac_param_1;                  /* parameter for call      */
   void       *ac_param_2;                  /* parameter for call      */
   void       *ac_param_3;                  /* parameter for call      */
};

struct dsd_hco_main {                       /* HOB control main structure */
   int        imc_max_poss_workthr;         /* max possible work thr   */
   int        imc_max_act_workthr;          /* max active work thr     */
   int        imc_workthr_alloc;            /* allocated work threads  */
   int        imc_workthr_sched;            /* scheduled work threads  */
   int        imc_workthr_active;           /* active work threads     */
   int        imc_workque_sched;            /* work queue scheduled    */
   int        imc_workque_max_no;           /* work queue maximum      */
   time_t     dsc_workque_max_time;         /* for time of maximum     */
   struct dsd_hco_wothr *adsc_hco_wothr_anchor;  /* anchor of chain    */
   struct dsd_hco_wothr *adsc_hco_wothr_free;  /* free work thread     */
   int        imc_prio_thr;                 /* priority of one thread  */
   md_func_thr_sta amc_func_thr_sta;        /* function to call at thread start */
};

/* The following structure contains all the data for the work threads
   active or maybe waiting for work                                    */
struct dsd_hco_wothr {
   struct dsd_hco_wothr *adsc_next;         /* next in chain           */
   struct dsd_hco_wothr *adsc_ch_free;      /* chain of free work thr  */
   struct dsd_hco_wothr *adsc_ch_lock;      /* chain of locked threads */
   class dsd_hcthread dsc_hcthread;         /* Thread Functions        */
#ifndef OLD01
   class dsd_hcla_event_1 dsc_event;        /* event for thread        */
#else
#ifndef HL_UNIX
   HANDLE     dsc_heve;                     /* event                   */
#else
   class dsd_hcla_event_1 dsc_heve;         /* event                   */
#endif
#endif
   BOOL       boc_active;                   /* active working          */
   BOOL       boc_thr_close;                /* thread closed           */
   int        imc_prio_thr;                 /* priority of one thread  */
   int        imc_tid;                      /* thread-id               */
   struct dsd_call_para_1 dsc_call_para_1;  /* call parameters         */
   void *     vpc_aux_field;                /* auxiliary field         */
   void *     vprc_aux_area[ 16 ];          /* auxiliary thread area   */
};

/* The following structure is used if a resource is locked by a thread */
struct dsd_hco_lock_1 {                     /* structure for locking   */
   struct dsd_hco_wothr *adsc_wothr_in_use;  /* resource in use by this thread */
   struct dsd_hco_wothr *adsc_ch_lock;      /* chain of locked threads */
};

/* The following structure is used for the wait-chain                  */
struct dsd_hco_wacha_1 {                    /* structure for wait chain */
   struct dsd_hco_wothr *adsc_wothr_in_use;  /* resource in use by this thread */
   struct dsd_hco_wacha_1 *adsc_wacha_waiting;  /* entry wait-chain waiting */
   volatile BOOL boc_is_waiting;            /* is currently waiting    */
};

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

extern PTYPE void m_hco_init( int, int );   /* initialize HOB Control  */
/**
* function m_hco_init()
* parameter 1 = max possible work threads
* parameter 2 = max active work threads
*/

extern PTYPE void m_hco_shutdown( void );   /* shutdown HOB Control    */

extern PTYPE void m_hco_set_prio_thr( int );  /* set priority of work threads */

extern PTYPE void m_hco_set_thr_sta_func( md_func_thr_sta );  /* set function to call at thread start */

extern PTYPE void m_hco_run_thread( struct dsd_call_para_1 * );

extern PTYPE void m_hco_wothr_blocking( struct dsd_hco_wothr * );   /* set work thread blocking */
extern PTYPE void m_hco_wothr_active( struct dsd_hco_wothr *, BOOL bop_force );   /* set work thread active */

/* lock a resource for this work thread                                */
extern PTYPE void m_hco_wothr_lock( struct dsd_hco_wothr *,
                                    struct dsd_hco_lock_1 * );

/* unlock a resource that has been locked for this work thread         */
extern PTYPE void m_hco_wothr_unlock( struct dsd_hco_wothr *,
                                      struct dsd_hco_lock_1 * );

/* prepare wait-chain                                                  */
extern PTYPE void m_hco_wothr_wacha_prep( struct dsd_hco_wothr *,
                                          struct dsd_hco_wacha_1 * );

/* append to wait-chain                                                */
extern PTYPE void m_hco_wothr_wacha_append( struct dsd_hco_wothr *,
                                            struct dsd_hco_wacha_1 *,
                                            struct dsd_hco_wacha_1 * );

/* release wait-chain                                                  */
extern PTYPE void m_hco_wothr_wacha_rel( struct dsd_hco_wothr *,
                                         struct dsd_hco_wacha_1 * );

/* wait for entry in wait-chain             */
extern PTYPE void m_hco_wothr_wacha_wait( struct dsd_hco_wacha_1 * );

/* wait till posted in this work thread                                */
extern PTYPE void m_hco_wothr_wait( struct dsd_hco_wothr * );

/* wait till posted in this work thread or timeout                     */
extern PTYPE int m_hco_wothr_wait_sec( struct dsd_hco_wothr *, int );

/* wait till posted in this work thread or timeout - do not set work-thread blocking */
extern PTYPE int m_hco_wothr_nonblock_wait_sec( struct dsd_hco_wothr *, int );

/* post another work thread waiting for this post                      */
extern PTYPE void m_hco_wothr_post( struct dsd_hco_wothr *, struct dsd_hco_wothr * );

#ifdef HOB_CONTR_TIMER
/* set timer                                                           */
extern PTYPE void m_time_set( struct dsd_timer_ele *adsptiele, BOOL bop_endtime );

/* release timer                                                       */
extern PTYPE BOOL m_time_rel( struct dsd_timer_ele *adsptiele );

/* return the Epoch value in milliseconds                              */
extern PTYPE HL_LONGLONG m_get_epoch_ms( void );
#endif
#endif
