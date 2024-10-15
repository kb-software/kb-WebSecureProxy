#if !defined __HMEM_MGR__
#define __HMEM_MGR__

#include <basetype.h>
#include <basemacs.h>

#include "memfunc.h"

#define	HMEM_OP_OK	0
#define	HMEM_NULL_PTR	-1
#define	HMEM_PARAM_ERR	-2
#define	HMEM_ALLOC_ERR	-3





//#define __HMEM_DEBUG__	// TEST TEST TEST

#define	HMEM_MAX_MANAGED_BUF_SIZE	512

#if !defined __HMEM_DEBUG__

#define	HMEM_DEFAULT_16BYTE_BLOCKS	256
#define	HMEM_DEFAULT_32BYTE_BLOCKS	 64
#define	HMEM_DEFAULT_64BYTE_BLOCKS	 32
#define	HMEM_DEFAULT_256BYTE_BLOCKS	 32
#define	HMEM_DEFAULT_512BYTE_BLOCKS	 32

#else // defined __HMEM_DEGUG__

#define	HMEM_DEFAULT_16BYTE_BLOCKS	 64
#define	HMEM_DEFAULT_32BYTE_BLOCKS	 32
#define	HMEM_DEFAULT_64BYTE_BLOCKS	 32
#define	HMEM_DEFAULT_256BYTE_BLOCKS	 32
#define	HMEM_DEFAULT_512BYTE_BLOCKS	 32

#endif


#define	DEFAULT_HMEM_POOL_SIZE		1024
#define	DEFAULT_HMEM_POOL_COUNT		4



#if defined __cplusplus
extern "C" {
#endif

//---------------------------------------------------------
// Memory preallocation info structure
// Used with the Callback function (if supplied)
//---------------------------------------------------------
typedef struct HMEMINFO_t {
  int	InfoStrucSize;			// for versioning
  int	InitialByte16BlockCount;	// number of 16  Byte blocks to use
  int	InitialByte32BlockCount;	// number of 32  Byte blocks to use
  int	InitialByte64BlockCount;	// number of 64  Byte blocks to use
  int	InitialByte256BlockCount;	// number of 256 Byte blocks to use
  int	InitialByte512BlockCount;	// number of 512 Byte blocks to use
  int	InitialPoolSize;		// initial pool buffer size
  int   InitialPoolCount;		// initial pool count
} HMEMINFO;

//---------------------------------------------------------
// Memory block management structure
// Note: Allocation bit array and buffer will be allocated
// ----- together with the header structure (C-Version)
//---------------------------------------------------------
typedef struct HMEMHDR_t {
  struct HMEMHDR_t * pNextMemHdr;	// pointer to next structure
  int	BlockSize;			// size of blocks managed
  int	BlockCount;			// number of blocks managed
  int	MaxUsedCount;			// number of buffers used
  int   ActUsedCount;			// actual in use count
  BIT8PTR  pBufStart;			// Starting Address of buffer
  BIT8PTR  pBufEnd;			// Last address of buffer (byte)
  BIT32PTR pUsedBlockBitArray;		// start of array of block used bits
} HMEMHDR;

#define	HMEM_HDR_PTR	HMEMHDR *



//---------------------------------------------------------
// Memory management link structure
//---------------------------------------------------------
typedef struct HMEMDESC_t {
  HMEMHDR *	pMemCtlAnchor16Byte;	// 16 byte blocks list  (256, 4kB)
  HMEMHDR *	pMemCtlAnchor32Byte;	// 32 byte blocks list  (64,  2kB)
  HMEMHDR *	pMemCtlAnchor64Byte;	// 64 byte blocks list  (32,  2kB)
  HMEMHDR *	pMemCtlAnchor256Byte;	// 256 byte blocks list (32,  8kB)
  HMEMHDR *	pMemCtlAnchor512Byte;	// 512 byte blocks list (32, 16kB)
  struct HMEMPOOL_STRUC_t * pUsedPoolListAnchor; // Pool used list / NULL
  struct HMEMPOOL_STRUC_t * pFreePoolListAnchor; // Pool free list / NULL
} HMEMDESC;

#define HMEM_DESC_PTR	HMEMDESC *

#if 0
//-------------------------------------------------------------
// Memory pool buffer management structure
//-------------------------------------------------------------
#endif

typedef struct HMEMPOOL_STRUC_t {
  struct HMEMPOOL_STRUC_t * pNext;	// pointer to next structure/NULL
  BIT32	AllocSize;			// actual allocated size
  BIT8PTR pMemBase;			// Buffer base address
} HMEMPOOL_STRUC;

#define	HMEMPOOL_PTR	HMEMPOOL_STRUC *



#if 0
//--------------------------------------------------------------
// External definitions
//--------------------------------------------------------------
#endif // 0

extern STATIC void FAST FreeHmemCtlStruc(HMEM_CTX_DEF
					 HMEM_HDR_PTR pMemCtlStruc);
extern STATIC HMEM_HDR_PTR FAST AllocHmemCtlStruc(HMEM_CTX_DEF
			int BlockSize, int BlockCount);
extern STATIC void FAST FreeHmemCtlStrucList(HMEM_CTX_DEF
				HMEM_HDR_PTR pMemCtlStruc);
extern STATIC int FAST FreeManagedBuffer(HMEM_HDR_PTR pMemCtlStruc,
					 BIT8PTR pMemSlot);
extern STATIC BIT8PTR FAST AllocManagedBuffer(HMEM_CTX_DEF
				HMEM_HDR_PTR pMemCtlStruc);

extern STATIC void FAST FreeSmallMemDescStruc(HMEM_CTX_DEF
			HMEM_DESC_PTR pMemDescStruc);

#if defined XH_INTERFACE
extern STATIC HMEM_DESC_PTR FAST AllocSmallMemDescStruc(HMEM_CTX_DEF1);
extern STATIC void FAST HMemMgrFree(HMEM_CTX_DEF1);
#endif

extern STATIC int FAST HFreeManagedBuffer(HMEM_CTX_DEF
			 BIT8PTR pMem, HMEM_DESC_PTR pMemDesc);

extern STATIC BIT8PTR FAST HAllocManagedBuffer(HMEM_CTX_DEF
				int BufSize, HMEM_DESC_PTR pMemDesc);


extern STATIC void FAST m__hpoolfree(HMEM_CTX_DEF void * ach_ppool_mem);
extern STATIC BIT8PTR FAST m__hpoolmalloc(HMEM_CTX_DEF int in__memory_size);

extern STATIC void FAST MemStatistics(HMEM_CTX_DEF1);


#if defined __cplusplus
}
#endif




#endif // !defined __HMEM_MGR__ 
