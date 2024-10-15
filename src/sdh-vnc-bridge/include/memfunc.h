#if 0
/*****************************************************************************/
/* Project:       hob ssl and others                                         */
/* Source:        memfunc.h                                                  */
/* Description:   header file, structure definitions, externals              */
/*                                                                           */
/* Copyright 2004 HOB GmbH & Co. KG                                          */
/*                                                                           */
/* Created by:    g.oed                                                      */
/* Creation Date: 2004/08/15                                                 */
/*                                                                           */
/* Operating system(architecture): -                                         */
/*                                                                           */
/* Compile with:  XH_INTERFACE                                               */
/*                                                                           */
/* Additional requirements:                                                  */
/*                                                                           */
/* Changed by:                                                               */
/*                                                                           */
/*****************************************************************************/
#endif

#if !defined __HMEM_FUNCT_HEADER__
#define __HMEM_FUNCT_HEADER__

#if !defined JAVA && !defined XH_INTERFACE
#ifndef HL_FREEBSD
#include <malloc.h>
#else
#include <stdlib.h>
#endif
#endif


#if defined XH_INTERFACE 

#if !defined BOOL
#define BOOL int
#endif

#if !defined FALSE
#define FALSE 0
#endif

#if !defined    DEF_AUX_MEMGET
#define DEF_AUX_MEMGET  0
#endif

#if !defined    DEF_AUX_MEMFREE
#define DEF_AUX_MEMFREE 1
#endif


#if 0
//#define	HMEM_PASS_TRANSPARENT_FLAG	0x01
#endif // 0

#define	HMEM_LOCKED_STRUC_FLAG_BIT		0x01	// is locked
#define	HMEM_NO_POOLS_FLAG_BIT			0x02	// do not use pools
#define	HMEM_STRUC_LOCAL_FLAG_BIT		0x04	// is local struc


struct HMEMINFO_t;	// forward declaration to avoid warnings!

typedef struct ds__hmem_t {
        int     in__struc_size;         // for version control
	int	in__flags;		// control flags
	int	in__aux_up_version;	// 0 - V1, 1 - V2
	int	(* pMemSizeInfoCallback)(struct HMEMINFO_t *); // info callback/NULL
	struct HMEMDESC_t * pHmemDesc;	// internal memory manager desc.
        void * vp__context;             // context for allocation function
        BOOL (* am__aux1)(int in__funct,
                          void * vp__p_mem,
                          int  in__size);  // allocation / free function (old)
        BOOL (* am__aux2)(void * vp__p_ctx,
                          int in__funct,
                          void * vp__p_mem,
                          int  in__size);  // allocation / free function (new)
} ds__hmem;

#include "hmemmgr.h"


#if defined __cplusplus
extern "C" {
#endif


extern void * m__hextmalloc(ds__hmem * ads__p_hmem_struc,
                            int in__memory_size);

extern void * m__hextmalloc_glbl(ds__hmem * ads__p_hmem_struc,
                                 int in__memory_size);

extern void * m__hextcalloc(ds__hmem * ads__p_hmem_struc,
			    int in__element_cnt, int in__element_size);

extern void * m__hextcalloc_glbl(ds__hmem * ads__p_hmem_struc,
			         int in__element_cnt, int in__element_size);

extern void m__hextfree(ds__hmem * ads__p_hmem_struc,
			void * vp__p_mem);

extern void m__hextfree_glbl(ds__hmem * ads__p_hmem_struc,
			     void * vp__p_mem);

extern void * m__hmalloc(ds__hmem * ads__p_hmem_struc,
                         int in__memory_size);

extern void * m__hcalloc(ds__hmem * ads__p_hmem_struc,
		         int in__element_cnt, int in__element_size);


extern void m__hfree(ds__hmem * ads__p_hmem_struc,void * vp__p_mem);




#if defined __cplusplus
}
#endif





#endif // XH_INTERFACE

#endif // !defined __HMEM_FUNCT_HEADER__
