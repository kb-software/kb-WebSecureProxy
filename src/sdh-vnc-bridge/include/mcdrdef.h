#if 0
/* UCDRDEF1.H HOBLink Compression Record 06.10.97 KB / 04.04.99 KB     */
// adapted for MPPC Compression 9.7.2001 G.O.
// Version2 for hob-cdr 13.12.2006 G.O.
#endif

#ifndef __MPPC_CDRDEF_HEADER__
#define __MPPC_CDRDEF_HEADER__


#if !defined XH_MPPC_INTF_VERSION
#error XH_MPPC_INTF_VERSION not defined, STOP!
#endif


#include <basetype.h>
#include <basemacs.h>
//#include "../hmem/memfunc.h"
#include "memfunc.h"

#ifdef FALSE
#undef FALSE
#endif
#ifdef TRUE
#undef TRUE
#endif

#define FALSE 0
#define TRUE  1

#if 0
// Function codes for the En-/Decoder
#endif

#define DEF_IFUNC_START 0		// Initialize, allocate memory
#define DEF_IFUNC_CONT  1
#define DEF_IFUNC_RESET 2
#define DEF_IFUNC_END   3

#if 0
// returncodes from En-/Decoder
#endif

#define DEF_IRET_NORMAL 0
#define DEF_IRET_END    1
#define DEF_IRET_ERRAU  2                   /* error in auxiliary prog */

#if XH_MPPC_INTF_VERSION < 200
#define DEF_IRET_INVDA  3                   /* invalid data found      */
#define DEF_IRET_OVERFLOW 4
#define DEF_IRET_UNDERRUN 4
#else
#define DEF_IRET_INVDA  5                   /* invalid data found      */
#define DEF_IRET_OVERFLOW 5		// Map to same
#define DEF_IRET_UNDERRUN 5		// map to same
#endif // XH_MPPC_INTF_VERSION


#if 0
// Function codes for the helper Subroutine
#endif
#define DEF_AUX_MEMGET  0
#define DEF_AUX_MEMFREE 1


#if 0
//---------------------------------------------------
// Continue Mode State Machine state definitions
//---------------------------------------------------
#endif

#define	WAIT_FIRST_SOURCE_BLOCK		0	// implicit default
#define	WAIT_MORE_SOURCE_BLOCKS		1	// more data for input
#define	WAIT_FIRST_DSTBUF_BLOCK		2	// no output buffer yet
#define	WAIT_MORE_DSTBUF_BLOCKS		3	// more data for output


#if 0
//---------------------------------------------------
// Temporary Buffer allocation Sizes
//---------------------------------------------------
#endif

#define	MIN_GATHER_BUF_SIZE		8192	// 8 kB
#define	GATHER_BUF_INCREMENT		4096	// 4 kB


#if 0
/*-------------------------------------------------------------------*/
/* Application header files.                                         */
/*-------------------------------------------------------------------*/
#endif

#if 0
/* MPPC Parameters                                                  */
// NOTE: Dictionary Size and Hash-Table Size may be chosen independant
// ----- Dictionary Size MUST be either 8kB or 64kB, Hash-Table Size
//	 May be chosen to be any size >= SMALL_HASH_TAB_SIZE, but must
//	 be a power of 2 !!
#endif

#define	VAL_SMALL_MPPC_DICT	0		// Dictionary Size  8kB
#define	VAL_LARGE_MPPC_DICT	1		// Dictionary Size 64kB

#define	VAL_SMALL_MPPC_HASHTAB	8192	// 16kB
#define	VAL_LARGE_MPPC_HASHTAB	32768	// 64kB (may be larger though)

#define	VAL_DATALEN_LOW_LIMIT	32	// Record will not be compressed if <=

#if 0
// structures for Encoder / Decoder
#endif

#ifndef JAVA

typedef struct {
  DICTSTRU * pDictStruc;		// Dictionary / HashTable etc.
  BIT8PTR  pSrcGatherBuf;		// Source Gathering Buffer
  BIT32	   SrcGatherBufSize;		// allocated size of Buffer
  BIT32	   SrcGatherDataLen;		// length of Data in buffer
  BIT8PTR  pTmpDstBuf;			// Temporary Output Buffer

  BIT8PTR  pOutDataBuf;			// Output Buffer from Compression
  BIT32	   OutDataIndex;		// current index into buffer
  BIT32	   OutDataLen;			// length of data on buffer

  int	   SubState;			// Current Compress State
  BIT8	   CompressFlags;		// Flag Byte for Control
  BIT8	   DictInUseFlag;		// Dictionary is used (not empty)
#if defined XH_INTERFACE
  ds__hmem MemCtxStruc;			// context
  ds__hmem *pMemCtxStruc;		// pointer to context 
#endif // XH_INTERFACE
} MPENC;

#else // JAVA

#endif // JAVA


#if 0
//---------------------------------------------------
// Access Macros for Encoder/Decoder Structures
//---------------------------------------------------
#endif

#ifndef JAVA

#define ENC_PTR				MPENC *
#define	ENC_PTR_REF			MPENC *

#define	ENC_PDICT_STRU(a)		a->pDictStruc
#define	ENC_PSRC_GATHER_BUF(a)		a->pSrcGatherBuf
#define	ENC_SRC_GATHER_BUFSIZE(a)	a->SrcGatherBufSize
#define	ENC_SRC_GATHER_DATALEN(a)	a->SrcGatherDataLen
#define	ENC_PTMP_DSTBUF(a)		a->pTmpDstBuf

#define	ENC_PCMPR_OUTBUF(a)		a->pOutDataBuf
#define	ENC_CMPR_OUT_DATA_INDEX(a)	a->OutDataIndex
#define	ENC_CMPR_OUT_DATALEN(a)		a->OutDataLen

#define	ENC_SUBSTATE(a)			a->SubState
#define	ENC_COMPRESS_FLAGS(a)		a->CompressFlags
#define	ENC_DICT_IN_USE_FLAG(a)		a->DictInUseFlag

#define	ENC_MemCtxStruc(a)		a->MemCtxStruc
#define	ENC_pMemCtxStruc(a)		a->pMemCtxStruc

#else // JAVA

#define ENC_PTR				MPENC
#define	ENC_PTR_REF			MPENC

#define	ENC_PDICT_STRU(a)		a.pDictStruc
#define	ENC_PSRC_GATHER_BUF(a)		a.pSrcGatherBuf
#define	ENC_SRC_GATHER_BUFSIZE(a)	a.SrcGatherBufSize
#define	ENC_SRC_GATHER_DATALEN(a)	a.SrcGatherDataLen
#define	ENC_PTMP_DSTBUF(a)		a.pTmpDstBuf

#define	ENC_PCMPR_OUTBUF(a)		a.pOutDataBuf
#define	ENC_CMPR_OUT_DATA_INDEX(a)	a.OutDataIndex
#define	ENC_CMPR_OUT_DATALEN(a)		a.OutDataLen

#define	ENC_SUBSTATE(a)			a.SubState
#define	ENC_COMPRESS_FLAGS(a)		a.CompressFlags
#define	ENC_DICT_IN_USE_FLAG(a)		a.DictInUseFlag

#endif // JAVA

#if 0
//--------------------------------------------------------------
// The HOLY compression control structure, adapted from UCDRDEF1
// and for Version 2 from hob-cdrdef1.h
// NOTE: At present only defined for C, NOT for JAVA !!
//--------------------------------------------------------------
#endif

#if !defined JAVA

#if !defined BOOL
#define BOOL int
#endif

typedef struct {
  int   ifunc;                              /* function of subroutine  */
  int   ireturn;                            /* return from function    */
  BOOL  bo_mp_flush;                        /* end-of-record input     */
                                            /* set by main-program     */
  BOOL  bo_sr_flush;                        /* end-of-record output    */
                                            /* set by subroutine       */
  BOOL  bo_maybe_uncompressed;              /* subroutine may req unco */
                                            /* set by subroutine       */
  BOOL  bo_compressed;                      /* use compressed output   */
                                            /* set by subroutine       */
  BYTE  *ainpa;                             /* address act input-data  */
  BYTE  *ainpe;                             /* address end input-data  */
  BYTE  *aouta;                             /* address act output-data */
  BYTE  *aoute;                             /* address end output-data */
#if XH_MPPC_INTF_VERSION < 200
  BOOL  (*uaux)( int, void *, int );         /* address of aux-subrout  */
#else // XH_MPPC_INTF_VERSION >= 200
  BOOL  (*uaux)(void *, int, void *, int ); /* address of aux-subrout  */
#endif
  void  *aext;                               /* extension-field         */
#if XH_MPPC_INTF_VERSION >= 200
  void	*vpc_userfld;			    /* User Field Subroutine   */
#endif

  BIT32 ul_save_mp_needed;                  /* length save-area needed */
                                            /* set by subroutine       */
  BYTE  *a_save_mp;                         /* save-area from main pr  */
                                            /* set by main-program     */
  BIT32 ul_save_mp_given;                   /* length save-area given  */
                                            /* set by main-program     */
  BIT32 ul_param_1;                         /* parameter value 1       */
  BIT32 ul_param_2;                         /* parameter value 2       */
  BIT32 ul_param_3;                         /* parameter value 3       */
  BIT32 ul_param_4;                         /* parameter value 4       */
} DCDRFIELD;


#else // JAVA

#endif // JAVA


#if 0
//-----------------------------------------
// externals
//-----------------------------------------
#endif

#if !defined JAVA

#if !defined EXTPTYPE
#if defined __cplusplus
#define EXTPTYPE "C"
#else
#define EXTPTYPE
#endif
#endif // !defined EXTPTYPE


#if XH_MPPC_INTF_VERSION < 200
extern EXTPTYPE void CDRENC(DCDRFIELD *dcdf);
extern EXTPTYPE void CDRDEC(DCDRFIELD *dcdf);
#else
extern EXTPTYPE void m_cdr_enc(DCDRFIELD * dcdf);
extern EXTPTYPE void m_cdr_dec(DCDRFIELD * dcdf);
#endif


#endif // !defined JAVA


#if 0
//-----------------------------------------
// function macros
//-----------------------------------------
#endif

#ifndef JAVA
#define CDR_ENC(a,b)	CDRENC(b)
#define CDR_DEC(a,b)	CDRDEC(b)

#else // JAVA
#define CDR_ENC(a,b)	a.CDRENC(b)
#define CDR_DEC(a,b)	a.CDRDEC(b)

#endif // JAVA

#endif // Header
