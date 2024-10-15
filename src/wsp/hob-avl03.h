#ifndef _HOB_AVL03
#define _HOB_AVL03
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: hob-avl03.h                                         |*/
/*| -------------                                                     |*/
/*|  Header File for avl-tree routines                                |*/
/*|  Tischhöfer 06.12.05                                              |*/
/*|  KB 11.05.07                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB 2005                                           |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifndef BOOL
typedef int BOOL;
#endif

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

typedef int ( * amd_htree1_avl_cmp )( void *, struct dsd_htree1_avl_entry *,
                                      struct dsd_htree1_avl_entry * );

struct dsd_htree1_avl_cntl {       /* control structure for HOB Tree AVL */
   amd_htree1_avl_cmp    amc_htree1_avl_cmp;
   struct dsd_htree1_avl_entry  *adsc_root;        /* root element              */
   //int                   imc_count;       /* number of entries in tree */
};

struct dsd_htree1_avl_entry {               /* header of AVL Tree entry  */
   struct dsd_htree1_avl_entry *adsc_left;  /* pointer to left son       */
   struct dsd_htree1_avl_entry *adsc_right; /* pointer to right son      */
   struct dsd_htree1_avl_entry *adsc_parent; /* pointer to parent        */
   char       byc_balance;                  /* tree balance at this node */
   char       byrc_flags[3];                /* reserved                  */
};

struct dsd_htree1_avl_work {                /* HOB Tree Work Area        */
   struct dsd_htree1_avl_entry *adsc_found; /* element found in Tree     */
   struct dsd_htree1_avl_entry *adsc_curr_node; /* reserved              */
   int imc_flag;                            /* flag for processing       */
};

extern PTYPE BOOL m_htree1_avl_init( void *,
                                     struct dsd_htree1_avl_cntl *,
                                     amd_htree1_avl_cmp);

//extern PTYPE BOOL m_htree1_avl_end( void *, struct dsd_htree1_avl_cntl * );

extern PTYPE BOOL m_htree1_avl_search( void *,
                                       struct dsd_htree1_avl_cntl *,
                                       struct dsd_htree1_avl_work *,
                                       struct dsd_htree1_avl_entry * );

extern PTYPE BOOL m_htree1_avl_insert( void *,
                                       struct dsd_htree1_avl_cntl *,
                                       struct dsd_htree1_avl_work *,
                                       struct dsd_htree1_avl_entry * );

extern PTYPE BOOL m_htree1_avl_getnext( void *,
                                        struct dsd_htree1_avl_cntl *,
                                        struct dsd_htree1_avl_work *,
                                        BOOL );

extern PTYPE BOOL m_htree1_avl_delete( void *,
                                       struct dsd_htree1_avl_cntl *,
                                       struct dsd_htree1_avl_work * );

//extern PTYPE int avl_get_count( struct dsd_htree1_avl_cntl *adsp_cntl );

#endif //_HOB_AVL03