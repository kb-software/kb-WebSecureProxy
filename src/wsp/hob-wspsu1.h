/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: hob-wspsu1.h                                        |*/
/*| -------------                                                     |*/
/*|  Header File for WebSecureproxy Subroutines 1                     |*/
/*|  KB 23.12.04                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB 2004                                           |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif

#define DEF_MAX_LEN_CMA_NAME   128
#define DEF_WSP_TYPE_CMA       1
#define DEF_WSP_TYPE_SIP       2
#define DEF_WSP_TYPE_UDP       3
#define DEF_WSP_TYPE_GATE_UDP  4
#define DEF_WSP_TYPE_SERVICE   5

#ifdef B090423
struct dsd_cma1_ent {                       /* common memory area 1 entry */
#ifndef B090423
   struct dsd_htree1_avl_entry dsc_htree1;  /* position of entry in tree */
   struct dsd_cma_ext_lock *adsc_ext_chain;  /* chain of external locks */
#endif
   struct dsd_cma1_ent *adsc_next;          /* next in chain           */
   int        inc_size_area;                /* size of area            */
   int        imc_epoch_last_used;          /* save EPOCH entry last used */
   int        imc_retention_time;           /* retention time in seconds */
   char       *achc_area;                   /* area cma                */
   void *     vpc_lock_chain;               /* chain of locks          */
};
#endif

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

/* initialize common memory area                                       */
extern PTYPE void m_cma1_init( void );

/* process a common memory area command                                */
extern PTYPE BOOL m_cma1_proc( void *, struct dsd_hl_aux_c_cma_1 * );

/* add an entry to the session entry chain                             */
extern PTYPE char * m_wsp_s_ent_add( void *, int, int );

/* delete an entry from the session entry chain                        */
extern PTYPE void m_wsp_s_ent_del( void *, int, char * );

/* retrieve an entry from the session entry chain                      */
extern PTYPE char * m_wsp_s_ent_get( void *, int, char * );

/* add an entry to the wait-chain                                      */
extern PTYPE void m_wsp_s_ent_wacha_add( void *, int, char *, char * );

/* notify an entry with a signal                                       */
extern PTYPE void m_wsp_s_ent_notify( void *, char *, int );

/* wait for event, depending on session entry chain                    */
extern PTYPE void m_wsp_s_wait( void *, int, char * );

/* count entries from the session entry chain                          */
extern PTYPE int m_wsp_s_count( void *, int );

/* statistics about common memory area                                 */
extern PTYPE void m_cma1_statistics( int *, HL_LONGLONG * );

/* free entries where the retention time has elapsed                   */
extern PTYPE void m_cma1_free_old_e( void );

/* connection to other cluster member is open                          */
extern PTYPE void m_cma1_cluster_open( struct dsd_cluster_active * );

/* connection to other cluster member is closed                        */
extern PTYPE void m_cma1_cluster_close( struct dsd_cluster_active * );

/* a logical block was reveived from other cluster member              */
extern PTYPE void m_cma1_cluster_recv( struct dsd_cluster_proc_recv * );
