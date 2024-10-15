#ifndef __MPPC_CMPR_HEADER__
#define __MPPC_CMPR_HEADER__
//
// For a Description of Compression / Decompression Process
// see RFC2118
//
#include <basetype.h>
#include <basemacs.h>
//#include "../hmem/memfunc.h"
#include "memfunc.h"

#if !defined JAVA
#include <memory.h>
#endif // JAVA

#if !defined JAVA
#define MPPCDECOMPinst
#define	MPPCCOMPinst
#else // JAVA
#define MPPCDECOMPinst mppcdcmp
#define	MPPCCOMPinst mppccmpr
#endif

#if !defined UNUSED_PARAM
#define	UNUSED_PARAM(a)	a = a
#endif

#if 0
// Function codes for the Memory Manager Subroutine
#endif
#if ! defined DEF_AUX_MEMGET
#define DEF_AUX_MEMGET  0
#define DEF_AUX_MEMFREE 1
#endif

#if !defined BOOL
#define BOOL int
#endif

//--------------------------------------------------------
// Basic Defines
//--------------------------------------------------------
#define	MPPC_SMALL_DICT_SIZE		8192		// + 1 (?)
#if !defined JAVA
#define	MPPC_LARGE_DICT_SIZE		65536L
#else
#define	MPPC_LARGE_DICT_SIZE		65536
#endif

#define	MPPC_SMALL_HASH_TAB_SIZE	8192		// BIT16 Elements
#define	MPPC_LARGE_HASH_TAB_SIZE	32768		// BIT16 Elements

#define	MPPC_DICT_CLEARED_BIT	0x80
#define	MPPC_RESET_PTR_BIT	0x40
#define	MPPC_COMPRESSED_BIT	0x20
#define	MPPC_DICTSIZE_MASK	0x0F		// Bit 3-0: 0 small, 1 large
#define	MPPC_LARGE_DICT_FLAG	0x01		// dto.

#define	MPPC_MAX_TOKEN_BYTES	7	// maximum encoding needed
#define	MPPC_MAX_LITERAL_BYTES	2	// dto.

//--------------------------------------------------------
// The Dictionary / Hashtable Structure
//--------------------------------------------------------
#if !defined JAVA
typedef struct DICTSTRU_t {
#if defined C600
  BIT8  _huge * pDictBuf;		// Allocated Dictionary
  BIT16 _huge * pHashTab;		// Allocated HashTable
#else
  BIT8PTR	pDictBuf;		// Allocated Dictionary
  BIT16PTR	pHashTab;		// Allocated HashTable
#endif
  int		MaxDictIndex;		// Max. used Dictionary size
  BIT32		CurrDictIndex;		// Current Index into Dictionary
  BIT32		DictSize;		// Size of Dictionary
  BIT32		HashTabSize;		// Size of HashTable
  int		FlagsSave;		// Flag saver for DictReset etc.
} DICTSTRU;  

#else // JAVA

#if defined __MPPC_COMPRESSOR__
class DICTSTRU {
  BIT8PTR	pDictBuf;		// Allocated Dictionary
  BIT16PTR	pHashTab;		// Allocated HashTable
  int		MaxDictIndex;		// Max. used Dictionary size
  int		CurrDictIndex;		// Current Index into Dictionary
  int		DictSize;		// Size of Dictionary
  int		HashTabSize;		// Size of HashTable
  int		FlagsSave;		// Flag saver for DictReset etc.
}
#endif // __MPPC_COMPRESSOR__
#endif
//----------------------------------------------------------
// Access Macros for the Structure
//----------------------------------------------------------
#if !defined JAVA
#define	DICTSTRU_PTR			DICTSTRU *
#define	DICTSTRU_pDictBuf(a)		a->pDictBuf
#define	DICTSTRU_pHashTab(a)		a->pHashTab
#define	DICTSTRU_MaxDictIndex(a)	a->MaxDictIndex
#define	DICTSTRU_CurrDictIndex(a)	a->CurrDictIndex
#define	DICTSTRU_DictSize(a)		a->DictSize
#define	DICTSTRU_HashTabSize(a)		a->HashTabSize
#define	DICTSTRU_FlagsSave(a)		a->FlagsSave

#else // JAVA

#define	DICTSTRU_PTR			DICTSTRU
#define	DICTSTRU_pDictBuf(a)		a.pDictBuf
#define	DICTSTRU_pHashTab(a)		a.pHashTab
#define	DICTSTRU_MaxDictIndex(a)	a.MaxDictIndex
#define	DICTSTRU_CurrDictIndex(a)	a.CurrDictIndex
#define	DICTSTRU_DictSize(a)		a.DictSize
#define	DICTSTRU_HashTabSize(a)		a.HashTabSize
#define	DICTSTRU_FlagsSave(a)		a.FlagsSave
#endif



//--------------------------------------------------
// Function Access Macros
//--------------------------------------------------
#ifndef JAVA

#define	MPPC_DICT_STRUC_INIT(a,b,c,d)	MPPC_DictStrucInit(b,c,d)
#define	MPPC_COMPRESS(a,b,c,d,e,f,g,h)	MPPC_Compress(b,c,d,e,f,g,h)
#define	MPPC_DECOMPR(a,b,c,d,e,f,g,h,i,j) MPPCDecompress(b,c,d,e,f,g,h,i,j)

#if !defined XH_INTERFACE
#define	MPPC_FREE_DICT(a,b,c)		MPPC_FreeDict(c)
#define MPPC_ALLOC_DICT(a,b,c,d)	MPPC_AllocDict(c,d)

#else // XH_INTERFACE

#define	MPPC_FREE_DICT(a,b,c)		MPPC_FreeDict(b,c)
#define MPPC_ALLOC_DICT(a,b,c,d)	MPPC_AllocDict(b,c,d)
#endif


#else // JAVA

#define	MPPC_FREE_DICT(a,b,c)		a.MPPC_FreeDict(c)
#define MPPC_ALLOC_DICT(a,b,c,d)	a.MPPC_AllocDict(c,d)
#define	MPPC_DICT_STRUC_INIT(a,b,c,d)	a.MPPC_DictStrucInit(b,c,d)
#define	MPPC_COMPRESS(a,b,c,d,e,f,g,h)	a.MPPC_Compress(b,c,d,e,f,g,h)

#define	MPPC_DECOMPR(a,b,c,d,e,f,g,h,i,j) a.MPPCDecompress(b,c,d,e,f,g,h,i,j)
#endif
//--------------------------------------------------
// External Declarations
//--------------------------------------------------
#if !defined JAVA

#if !defined EXTPTYPE
#if defined __cplusplus
#define EXTPTYPE "C"
#else
#define EXTPTYPE
#endif
#endif // !defined EXTPTYPE

#if !defined __MPPC_DECOMPRESS__

extern EXTPTYPE STATIC int MPPCDecompress(
			BIT8 SrcBuf[], BIT32 SrcOff, BIT32 SrcLen,
			BIT8 CmprFlags,	BIT8 DictBuf[], BIT32 pActDictIndex[],
			BIT8PTR pDstBuf[], BIT32 pDstOff[], BIT32 pDstLen[]);
#endif // !defined __MPPC_DECOMPRESS__



#if !defined __MPPC_COMPRESSOR__

extern EXTPTYPE STATIC void FAST MPPC_FreeDict(HMEM_CTX_DEF
				               DICTSTRU_PTR pDictStruc);

extern EXTPTYPE STATIC DICTSTRU_PTR FAST MPPC_AllocDict(HMEM_CTX_DEF
					BIT32 DictSize, BIT32 HashTabSize);

extern EXTPTYPE STATIC void FAST MPPC_DictStrucInit(DICTSTRU_PTR pDictStruc,
					   int MaxDictIndClearFlag,
					   int CurrDictIndSetMode);

extern EXTPTYPE STATIC int FAST MPPC_Compress(
			BIT8PTR SrcBuf, int SrcOff, int SrcLen,
			BIT8PTR DstBuf, int DstOff, int pDstLen[],
			DICTSTRU_PTR pDictStruc);

#endif // !defined __MPPC_COMPRESSOR__


#endif // !defined JAVA


#endif // __MPPC_CMPR_HEADER__
