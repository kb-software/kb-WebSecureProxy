#ifndef __BASE_MACROS__
#define __BASE_MACROS__

#if !defined JAVA
#include <stdlib.h>
#include <memory.h>
#endif

#if 0
//------------------------------------------------------
// Macro for unused Parameters
//------------------------------------------------------
#endif

#if !defined JAVA
#define UNUSED_PARAM(a)	a = a
#else
#define	UNUSED_PARAM(a)
#endif


#if 0
//------------------------------------------------------
// Macro for casts
//------------------------------------------------------
#endif

#if !defined JAVA
#define BYTEF(a)	(BYTE) a
#define BIT8F(a)	(BIT8) a
#define BIT32F(a)	(BIT32) a
#else // JAVA, CSHARP
#if !defined CSHARP
#define BYTEF(a)	(BIT8) a
#define BIT8F(a)	(BIT8) a
#define BIT32F(a)	(BIT32) a
#else
#define BYTEF(a)	unchecked((BIT8) a)
#define BIT8F(a)	unchecked((BIT8) a)
#define BIT32F(a)	unchecked((BIT32) a)
#endif
#endif

#if 0
//------------------------------------------------------
// Array-Allocate Macros
//------------------------------------------------------
#endif

#if defined HOB_DRIVER
#include <hobrtl.h>
#endif

#if 0
// Macros now also usable for external memalloc
#endif

#if !defined JAVA
#if !defined XH_INTERFACE
#define	HMEM_CTX_DEF
#define	HMEM_CTX_DEF1
#define	HMEM_CTX_REF
#define	HMEM_CTX_REF1
#define	LOAD_HMEM_CTX_PTR(a)

#define BIT8_ARRAY_ALLOC(Ctx,Size)		(BIT8 *) malloc(Size)
#define BIT8_ARRAY_ALLOCEX(Ctx,Size)   		(BIT8 *) malloc(Size)
#define	BIT8_ARRAY_ALLOC_POOL(Ctx,Size)		(BIT8 *) malloc(Size)
#define BIT8_ARRAY_CALLOC(Ctx,Cnt,Size)		(BIT8 *) calloc(Cnt,Size)
#define BIT8_ARRAY_CALLOCEX(Ctx,Cnt,Size)	(BIT8 *) calloc(Cnt,Size)
#define BIT16_ARRAY_ALLOC(Ctx,Size)		(BIT16 *) malloc((Size)*2)
#define BIT16_ARRAY_ALLOCEX(Ctx,Size)		(BIT16 *) malloc((Size)*2)
#define	BIT16_ARRAY_ALLOC_POOL(Ctx,Size)	(BIT16 *) malloc((Size)*2)
#define BIT32_ARRAY_ALLOC(Ctx,Size)		(BIT32 *) malloc((Size)*4)
#define INT_ARRAY_ALLOC(Ctx,Size)       (int *) malloc((Size)*sizeof(int))
#define INT_ARRAY_ALLOCEX(Ctx,Size)     (int *) malloc((Size)*sizeof(int))
#define	STRING_ARRAY_ALLOC(Ctx,Size) \
          (STRING_PPTR) malloc((Size)*sizeof(STRING_PTR))
#else // XH_INTERFACE
#define	HMEM_CTX_DEF void * vp__ctx,
#define	HMEM_CTX_DEF1 void * vp__ctx
#define	HMEM_CTX_REF vp__ctx
#define	HMEM_CTX_REF1 vp__ctx,
#define	LOAD_HMEM_CTX_PTR(a)	vp__ctx = a

#define BIT8_ARRAY_ALLOC(Ctx,Size)	  (BIT8 *) m__hmalloc(Ctx,Size)
#define BIT8_ARRAY_ALLOCEX(Ctx,Size)      (BIT8 *) m__hextmalloc(Ctx,Size)
#define	BIT8_ARRAY_ALLOC_POOL(Ctx,Size)	  (BIT8 *) m__hpoolmalloc(Ctx,Size)
#define BIT8_ARRAY_CALLOC(Ctx,Cnt,Size)	  (BIT8 *) m__hcalloc(Ctx,Cnt,Size)
#define BIT8_ARRAY_CALLOCEX(Ctx,Cnt,Size) (BIT8 *) m__hextcalloc(Ctx,Cnt,Size)
#define BIT16_ARRAY_ALLOC(Ctx,Size)	  (BIT16 *) m__hmalloc(Ctx,(Size)*2)
#define BIT16_ARRAY_ALLOCEX(Ctx,Size)	  (BIT16 *) m__hextmalloc(Ctx,(Size)*2)
#define BIT16_ARRAY_ALLOC_POOL(Ctx,Size)  (BIT16 *) m__hpoolmalloc(Ctx,(Size)*2)
#define BIT32_ARRAY_ALLOC(Ctx,Size)	  (BIT32 *) m__hmalloc(Ctx,(Size)*4)
#define INT_ARRAY_ALLOC(Ctx,Size) \
          (int *) m__hmalloc(Ctx,(Size)*sizeof(int))
#define INT_ARRAY_ALLOCEX(Ctx,Size) \
          (int *) m__hextmalloc(Ctx,(Size)*sizeof(int))
#define	STRING_ARRAY_ALLOC(Ctx,Size) \
          (STRING_PPTR) m__hmalloc((Size)*sizeof(STRING_PTR))
#endif // XH_INTERFACE

#else // JAVA, CSHARP
#define	HMEM_CTX_DEF
#define	HMEM_CTX_DEF1
#define	HMEM_CTX_REF
#define	HMEM_CTX_REF1
#define	LOAD_HMEM_CTX_PTR(a)
#define BIT8_ARRAY_ALLOC(Ctx,Size)        new BYTE[Size]
#define BIT8_ARRAY_ALLOCEX(Ctx,Size)      new BYTE[Size]
#define	BIT8_ARRAY_ALLOC_POOL(Ctx,Size)	  new BYTE[Size]
#define BIT8_ARRAY_CALLOC(Ctx,Cnt,Size)   new BYTE[Cnt*Size]
#define BIT8_ARRAY_CALLOCEX(Ctx,Cnt,Size) new BYTE[Cnt*Size]
#define BIT16_ARRAY_ALLOC(Ctx,Size)	  new BIT16[Size]
#define BIT16_ARRAY_ALLOCEX(Ctx,Size)	  new BIT16[Size]
#define BIT32_ARRAY_ALLOC(Ctx,Size)	  new BIT32[Size]
#define INT_ARRAY_ALLOC(Ctx,Size)         new int[Size]
#define INT_ARRAY_ALLOCEX(Ctx,Size)       new int[Size]
#define	STRING_ARRAY_ALLOC(Ctx,Size)      new String[Size]
#endif // JAVA

#if 0
//------------------------------------------------------
// Array-Copy Macros
//------------------------------------------------------
#endif

#ifndef JAVA
#define	BIT8_ARRAY_COPY(Src,SrcOff,Dst,DstOff,Size) \
	memcpy(Dst+DstOff,Src+SrcOff,Size)

#define	BIT16_ARRAY_COPY(Src,SrcOff,Dst,DstOff,Size) \
	memcpy(Dst+DstOff,Src+SrcOff,(Size)*2)

#define	BIT32_ARRAY_COPY(Src,SrcOff,Dst,DstOff,Size) \
	memcpy(Dst+DstOff,Src+SrcOff,(Size)*4)

#define	INT_ARRAY_COPY(Src,SrcOff,Dst,DstOff,Size) \
	memcpy(Dst+DstOff,Src+SrcOff,(Size)*sizeof(int))

#else // JAVA, CSHARP
#if !defined CSHARP
#define	BIT8_ARRAY_COPY(Src,SrcOff,Dst,DstOff,Size) \
	System.arraycopy(Src,SrcOff,Dst,DstOff,Size)

#define	BIT16_ARRAY_COPY(Src,SrcOff,Dst,DstOff,Size) \
	System.arraycopy(Src,SrcOff,Dst,DstOff,Size)

#define BIT32_ARRAY_COPY(Src,SrcOff,Dst,DstOff,Size) \
	System.arraycopy(Src,SrcOff,Dst,DstOff,Size)

#define INT_ARRAY_COPY(Src,SrcOff,Dst,DstOff,Size) \
	System.arraycopy(Src,SrcOff,Dst,DstOff,Size)

#else // defined CSHARP

#define	BIT8_ARRAY_COPY(Src,SrcOff,Dst,DstOff,Size) \
	Array.Copy(Src,SrcOff,Dst,DstOff,Size)

#define	BIT16_ARRAY_COPY(Src,SrcOff,Dst,DstOff,Size) \
	Array.Copy(Src,SrcOff,Dst,DstOff,Size)

#define BIT32_ARRAY_COPY(Src,SrcOff,Dst,DstOff,Size) \
	Array.Copy(Src,SrcOff,Dst,DstOff,Size)

#define INT_ARRAY_COPY(Src,SrcOff,Dst,DstOff,Size) \
	Array.Copy(Src,SrcOff,Dst,DstOff,Size)
#endif // CSHARP
#endif // JAVA

#if 0
//------------------------------------------------------
// Array-Clear Macros, cannot be used for JAVA !!
//------------------------------------------------------
#endif

#ifndef JAVA
#define	BIT8_ARRAY_FCLEAR(Src,Size) \
	memset(Src,0,Size)

#define	BIT16_ARRAY_FCLEAR(Src,Size) \
	memset(Src,0,(Size)*2)

#define	BIT32_ARRAY_FCLEAR(Src,Size) \
	memset(Src,0,(Size)*4)

#define	INT_ARRAY_FCLEAR(Src,Size) \
	memset(Src,0,(Size)*sizeof(int))
#define	STRING_ARRAY_FCLEAR(Src,Size) \
	memset(Src,0,(Size)*sizeof(STRING_PTR))

#else
#define	BIT8_ARRAY_FCLEAR(Src,Size)
#define	BIT16_ARRAY_FCLEAR(Src,Size)
#define BIT32_ARRAY_FCLEAR(Src,Size)
#define INT_ARRAY_FCLEAR(Src,Size)
#define	STRING_ARRAY_FCLEAR(Src,Size)
#endif // JAVA

#if 0
//------------------------------------------------------
// Array-Size Macros
//------------------------------------------------------
#endif


#if !defined JAVA
#if 0 // DO NOT USE FOR C !!
#define	BIT8_ARRAY_SIZE(a)	_msize(a)
#define	BIT16_ARRAY_SIZE(a)	(_msize(a) * 2)
#define	BIT32_ARRAY_SIZE(a)	(_msize(a) * 4)
#define	INT_ARRAY_SIZE(a)	(_msize(a) * sizeof(int))
#endif // DO NOT USE FOR C !!
#else
#define	BIT8_ARRAY_SIZE(a)	a.length
#define	BIT16_ARRAY_SIZE(a)	a.length
#define	BIT32_ARRAY_SIZE(a)	a.length
#define	INT_ARRAY_SIZE(a)	a.length
#endif

#if 0
//--------------------------------------------------------
// Macro for freeing allocated arrays
//--------------------------------------------------------
#endif

#if !defined JAVA
#if !defined XH_INTERFACE
#define	FREE_ARRAY(ctx,a)      if((a) != 0) {free(a);a = 0;}
#define	FREE_ARRAYEX(ctx,a)    if((a) != 0) {free(a);a = 0;}
#define	FREE_ARRAY_POOL(ctx,a) if((a) != 0) {free(a);a = 0;}
#define	FREE_CARRAY(ctx,a)     if((a) != 0) {free(a);a = 0;}
#define	FREE_CARRAYEX(ctx,a)   if((a) != 0) {free(a);a = 0;}
#define	MEMMGR_FREE(ctx)
#else
#define	FREE_ARRAY(ctx,a)      if((a) != 0) {m__hfree(ctx,a);a = 0;}
#define	FREE_ARRAYEX(ctx,a)    if((a) != 0) {m__hextfree(ctx,a);a = 0;}
#define	FREE_ARRAY_POOL(ctx,a) if((a) != 0) {m__hpoolfree(ctx,a);a = 0;}
#define	FREE_CARRAY(ctx,a)     if((a) != 0) {m__hfree(ctx,a);a = 0;}
#define	FREE_CARRAYEX(ctx,a)   if((a) != 0) {m__hextfree(ctx,a);a = 0;}
#define	MEMMGR_FREE(ctx)     HMemMgrFree(ctx);
#endif // XH_INTERFACE
#else // JAVA
#define	FREE_ARRAY(ctx,a)      a = NULL
#define	FREE_ARRAYEX(ctx,a)    a = NULL
#define	FREE_ARRAY_POOL(ctx,a) a = NULL
#define	FREE_CARRAY(ctx,a)
#define	FREE_CARRAYEX(ctx,a)
#define	MEMMGR_FREE(ctx)
#endif
#if 0
//--------------------------------------------------------
// Macro for String to Byte conversions
//--------------------------------------------------------
#endif
#if !defined JAVA
#define	STRING_TO_BYTES(pString)	pString
#else
#define	STRING_TO_BYTES(pString)	pString.getBytes()	
#endif

#if !defined JAVA
#define	STRING_TO_SZBYTES(pString)	pString
#else
#define	STRING_TO_SZBYTES(pString)	(pString+"\u0000").getBytes()
#endif


#if 0
/*--------------------------------------------------------------*/
/* Byte/Long Converters Little Endian Format			*/
/*--------------------------------------------------------------*/
//
// from bytes to long
//
#endif


#if defined WIN32
#define char2long(c,l,i) l = (BIT32) *((BIT32 *) &c[i]); \
                         i += 4;

#define char2longn(c,l,i) l = (BIT32) *((BIT32 *) &c[i]); \

#else // JAVA, WIN64, SOLARIS

#if defined WIN64

#define char2long(c,l,i)\
       l  = (((BIT32) c[i+3] & 0xFF) << 24) |\
            (((BIT32) c[i+2] & 0xFF) << 16) |\
            (((BIT32) c[i+1] & 0xFF) << 8)  |\
            ((BIT32) c[i  ] & 0xFF);\
       i +=4;

#define char2longn(c,l,i)\
       l  = (((BIT32) c[i+3] & 0xFF) << 24) |\
            (((BIT32) c[i+2] & 0xFF) << 16) |\
            (((BIT32) c[i+1] & 0xFF) << 8)  |\
            ((BIT32)  c[i  ] & 0xFF);

#else // JAVA, Solaris etc

#define char2long(c,l,i)\
       l  = (((BIT32) c[i+3] & 0xFF) << 24) |\
            (((BIT32) c[i+2] & 0xFF) << 16) |\
            (((BIT32) c[i+1] & 0xFF) << 8)  |\
            ((BIT32) c[i  ] & 0xFF);\
       i +=4;

#define char2longn(c,l,i)\
       l  = (((BIT32) c[i+3] & 0xFF) << 24) |\
            (((BIT32) c[i+2] & 0xFF) << 16) |\
            (((BIT32) c[i+1] & 0xFF) << 8)  |\
            ((BIT32)  c[i  ] & 0xFF);
#endif
#endif


#if 0
// needed by MD5 / RIPEMD, special case
#endif


#if !defined CSHARP
#define char2longcx(c,l,n,i) \
 { \
   l = 0;\
   switch (n) \
   { \
     case 0: l = (BIT32)(((BIT16) c[i+3] & (BIT16) 0xFF)<< 8) << 16;\
     case 3: l|= ((BIT32) ((BIT16) c[i+2] & (BIT16) 0xFF)<< 16);\
     case 2: l|= ((BIT32)(((BIT16) c[i+1] & (BIT16) 0xFF)<< 8) & (BIT32) 0xFFFF);\
     case 1: l|= ((BIT32) ((BIT16) c[i  ] & (BIT16) 0xFF)      & (BIT32) 0xFFFF);\
   } \
   if(n == 0) i += 4;\
   else i += n;\
}	
#else // CSHARP special ....
#define char2longcx(c,l,n,i) \
 { \
   l = 0;\
   switch (n) \
   { \
     case 0: l = (BIT32)(((BIT16) c[i+3] & (BIT16) 0xFF)<< 8) << 16;\
	     goto case 3;\
     case 3: l|= ((BIT32) ((BIT16) c[i+2] & (BIT16) 0xFF)<< 16);\
	     goto case 2;\
     case 2: l|= ((BIT32)(((BIT16) c[i+1] & (BIT16) 0xFF)<< 8) & (BIT32) 0xFFFF);\
	     goto case 1;\
     case 1: l|= ((BIT32) ((BIT16) c[i  ] & (BIT16) 0xFF)      & (BIT32) 0xFFFF);\
	     break;\
   } \
   if(n == 0) i += 4;\
   else i += n;\
}	
#endif



#if 0
// Padding Insertion macro for RIPEMD
#endif

#define char2longcn(c,l,n)\
{ \
  switch (n)\
  { \
    case 0: \
      l = (((BIT32)  c[3]                 << 24)|\
           (((BIT32) c[2] & (BIT32) 0xFF) << 16)|\
           (((BIT32) c[1] & (BIT32) 0xFF) <<  8)|\
           (((BIT32) c[0] & (BIT32) 0xFF)      ));\
      break;\
    case 1: \
      l |=(((BIT32)  c[2]                 << 24)|\
           (((BIT32) c[1] & (BIT32) 0xFF) << 16)|\
           (((BIT32) c[0] & (BIT32) 0xFF) <<  8));\
      break;\
    case 2: \
      l |=(((BIT32)  c[1]                 << 24)|\
           (((BIT32) c[0] & (BIT32) 0xFF) << 16));\
      break;\
    case 3: \
      l |=((BIT32)  c[0]                  << 24);\
      break;\
  } \
}


#if 0
// special without case 0, for RIPEMD
#endif


#if !defined CSHARP
#define char2long3n(c,l,n,i) \
 { \
   l = 0;\
   switch (n) \
   { \
     case 3: l= ((BIT32) ((BIT16) c[i+2] & (BIT16) 0xFF)<< 16);\
     case 2: l|= ((BIT32)(((BIT16) c[i+1] & (BIT16) 0xFF)<< 8) & (BIT32) 0xFFFF);\
     case 1: l|= ((BIT32) ((BIT16) c[i] & (BIT16) 0xFF)      & (BIT32) 0xFFFF);\
   } \
}	
#else // defined CSHARP
#define char2long3n(c,l,n,i) \
 { \
   l = 0;\
   switch (n) \
   { \
     case 3: l= ((BIT32) ((BIT16) c[i+2] & (BIT16) 0xFF)<< 16);\
             goto case 2;\
     case 2: l|= ((BIT32)(((BIT16) c[i+1] & (BIT16) 0xFF)<< 8) & (BIT32) 0xFFFF);\
             goto case 1;\
     case 1: l|= ((BIT32) ((BIT16) c[i] & (BIT16) 0xFF)      & (BIT32) 0xFFFF);\
             break;\
   } \
}	
#endif // CSHARP



#if 0
// from long to bytes
#endif

#if defined WIN32
#define	long2char(l,c,i) (*((BIT32 *) &c[i]) = l); i += 4;
#define	long2charn(l,c,i) (*((BIT32 *) &c[i]) = l);

#else // JAVA, SOLARIS, WIN64 (!)

#if defined WIN64

#define long2char(l,c,i) c[i]   = (BIT8) (l);\
                         c[i+1] = (BIT8) (l>> 8);\
                         c[i+2] = (BIT8) (l>>16);\
                         c[i+3] = (BIT8) (l>>24);\
                         i += 4;
#define long2charn(l,c,i) c[i]   = (BIT8) (l);\
                          c[i+1] = (BIT8) (l>> 8);\
                          c[i+2] = (BIT8) (l>>16);\
                          c[i+3] = (BIT8) (l>>24);

#else // JAVA, SOLARIS etc

#if 0 // old version, not for CSHARP
#define long2char(l,c,i) c[i]   = (BIT8) (l & (BIT8) 0xFF);\
                         c[i+1] = (BIT8) (((l>> 8) & (BIT8) 0xFF));\
                         c[i+2] = (BIT8) (((l>>16) & (BIT8) 0xFF));\
                         c[i+3] = (BIT8) (((l>>24) & (BIT8) 0xFF));\
                         i += 4;
#define long2charn(l,c,i) c[i]   = (BIT8) (l & (BIT8) 0xFF);\
                          c[i+1] = (BIT8) (((l>> 8) & (BIT8) 0xFF));\
                          c[i+2] = (BIT8) (((l>>16) & (BIT8) 0xFF));\
                          c[i+3] = (BIT8) (((l>>24) & (BIT8) 0xFF));
#endif // 0 old version

#define long2char(l,c,i) c[i]   = (BIT8) (l       & 0x0FF);\
                         c[i+1] = (BIT8) ((l>> 8) & 0x0FF);\
                         c[i+2] = (BIT8) ((l>>16) & 0x0FF);\
                         c[i+3] = (BIT8) ((l>>24) & 0x0FF);\
                         i += 4;
#define long2charn(l,c,i) c[i]   = (BIT8) (l       & 0x0FF);\
                          c[i+1] = (BIT8) ((l>> 8) & 0x0FF);\
                          c[i+2] = (BIT8) ((l>>16) & 0x0FF);\
                          c[i+3] = (BIT8) ((l>>24) & 0x0FF);
#endif
#endif


#if 0
/*--------------------------------------------------------------*/
/* Byte/Long Converters Big Endian Format			*/
/*--------------------------------------------------------------*/
//
// from bytes to long
//
#endif


#define BIGchar2long(c,l,i) \
  {\
    l = ((BIT32)  ((BIT16) c[i+3] & (BIT16) 0xFF)         & (BIT32) 0xFFFF) | \
        ((BIT32) (((BIT16) c[i+2] & (BIT16) 0xFF)  <<  8) & (BIT32) 0xFFFF) | \
        ((BIT32)  ((BIT16) c[i+1] & (BIT16) 0xFF)  << 16) | \
        ((BIT32) (((BIT16) c[i]   & (BIT16) 0xFF)  <<  8) << 16);\
        i +=4; \
  }

#if 0
// the same as above, but no pointer increment
#endif

#define BIGchar2longn(c,l,i) \
  {\
    l = ((BIT32)  ((BIT16) c[i+3] & (BIT16) 0xFF)         & (BIT32) 0xFFFF) | \
        ((BIT32) (((BIT16) c[i+2] & (BIT16) 0xFF)  <<  8) & (BIT32) 0xFFFF) | \
        ((BIT32)  ((BIT16) c[i+1] & (BIT16) 0xFF)  << 16) | \
        ((BIT32) (((BIT16) c[i]   & (BIT16) 0xFF)  <<  8) << 16); \
  }



#if !defined CSHARP
#define BIGchar2longc(c,l,n,i)\
{ \
  switch (n)\
  { \
    case 0: \
      l =  (BIT32) (((BIT16) c[i++] & (BIT16) 0xFF)  <<  8) << 16; \
    case 1: \
      l |= ((BIT32)  ((BIT16) c[i++] & (BIT16) 0xFF)  << 16); \
    case 2: \
      l |= ((BIT32) (((BIT16) c[i++] & (BIT16) 0xFF)  <<  8) & (BIT32) 0xFFFF);\
    case 3: \
      l |= ((BIT32)  ((BIT16) c[i++] & (BIT16) 0xFF)         & (BIT32) 0xFFFF);\
  } \
}
#else // defined CSHARP
#define BIGchar2longc(c,l,n,i)\
{ \
  switch (n)\
  { \
    case 0: \
      l =  (BIT32) (((BIT16) c[i++] & (BIT16) 0xFF)  <<  8) << 16; \
      goto case 1;\
    case 1: \
      l |= ((BIT32)  ((BIT16) c[i++] & (BIT16) 0xFF)  << 16); \
      goto case 2;\
    case 2: \
      l |= ((BIT32) (((BIT16) c[i++] & (BIT16) 0xFF)  <<  8) & (BIT32) 0xFFFF);\
      goto case 3;\
    case 3: \
      l |= ((BIT32)  ((BIT16) c[i++] & (BIT16) 0xFF)         & (BIT32) 0xFFFF);\
      break;\
  } \
}
#endif // CSHARP


#if 0
// the same as above, but no pointer is used !!
#endif

#define BIGchar2longcn(c,l,n)\
{ \
  switch (n)\
  { \
    case 0: \
      l = ((BIT32)  ((BIT16) c[3] & (BIT16) 0xFF)         & (BIT32) 0xFFFF) | \
          ((BIT32) (((BIT16) c[2] & (BIT16) 0xFF)  <<  8) & (BIT32) 0xFFFF) | \
          ((BIT32)  ((BIT16) c[1] & (BIT16) 0xFF)  << 16) | \
          ((BIT32) (((BIT16) c[0]   & (BIT16) 0xFF)  <<  8) << 16); \
      break;\
    case 1: \
      l |=((BIT32)  ((BIT16) c[2] & (BIT16) 0xFF)         & (BIT32) 0xFFFF) |\
          ((BIT32) (((BIT16) c[1] & (BIT16) 0xFF)  <<  8) & (BIT32) 0xFFFF) |\
          ((BIT32)  ((BIT16) c[0] & (BIT16) 0xFF)  << 16); \
      break;\
    case 2: \
      l |=((BIT32)  ((BIT16) c[1] & (BIT16) 0xFF)         & (BIT32) 0xFFFF) |\
          ((BIT32) (((BIT16) c[0] & (BIT16) 0xFF)  <<  8) & (BIT32) 0xFFFF);\
      break;\
    case 3: \
      l |=((BIT32)  ((BIT16) c[0] & (BIT16) 0xFF)         & (BIT32) 0xFFFF);\
      break;\
  } \
}

#if !defined CSHARP
#define BIGchar2long3n(c,l,n,i)\
{ \
  l = 0; \
  switch (n)\
  { \
    case 3: \
      l  = (BIT32) (((BIT16) c[i+2] & (BIT16) 0xFF)  <<  8) & (BIT32) 0xFFFF; \
    case 2: \
      l |= ((BIT32)  ((BIT16) c[i+1] & (BIT16) 0xFF)  << 16); \
    case 1: \
      l |= ((BIT32) (((BIT16) c[i]   & (BIT16) 0xFF)  <<  8) << 16); \
      break;\
  } \
}
#else // defined CSHARP
#define BIGchar2long3n(c,l,n,i)\
{ \
  l = 0; \
  switch (n)\
  { \
    case 3: \
      l  = (BIT32) (((BIT16) c[i+2] & (BIT16) 0xFF)  <<  8) & (BIT32) 0xFFFF; \
      goto case 2;\
    case 2: \
      l |= ((BIT32)  ((BIT16) c[i+1] & (BIT16) 0xFF)  << 16); \
      goto case 1;\
    case 1: \
      l |= ((BIT32) (((BIT16) c[i]   & (BIT16) 0xFF)  <<  8) << 16); \
      break;\
  } \
}
#endif // CSHARP



#if 0
// from long to bytes
#endif

#if 0 // old version, not for CSHARP
#define BIGlong2char(l,c,i)  c[i+3] = (BIT8) (l       & (BYTE) 0xFF);\
                             c[i+2] = (BIT8) ((l>> 8) & (BYTE) 0xFF);\
                             c[i+1] = (BIT8) ((l>>16) & (BYTE) 0xFF);\
                             c[i]   = (BIT8) ((l>>24) & (BYTE) 0xFF);\
                             i += 4;
#endif // 0

#define BIGlong2char(l,c,i)  c[i+3] = (BIT8) (l       & 0x0FF);\
                             c[i+2] = (BIT8) ((l>> 8) & 0x0FF);\
                             c[i+1] = (BIT8) ((l>>16) & 0x0FF);\
                             c[i]   = (BIT8) ((l>>24) & 0x0FF);\
                             i += 4;

#if 0
// the same as above, but no pointer increment
#endif

#if 0 // old version, not for CSHARP
#define BIGlong2charn(l,c,i) c[i+3] = (BIT8) (l       & (BYTE) 0xFF);\
                             c[i+2] = (BIT8) ((l>> 8) & (BYTE) 0xFF);\
                             c[i+1] = (BIT8) ((l>>16) & (BYTE) 0xFF);\
                             c[i]   = (BIT8) ((l>>24) & (BYTE) 0xFF);
#endif // old version

#define BIGlong2charn(l,c,i) c[i+3] = (BIT8) (l       & 0x0FF);\
                             c[i+2] = (BIT8) ((l>> 8) & 0x0FF);\
                             c[i+1] = (BIT8) ((l>>16) & 0x0FF);\
                             c[i]   = (BIT8) ((l>>24) & 0x0FF);
#if 0
/*--------------------------------------------------------------*/
/* Byte/Word Converters						*/
/* NOTE: Output is always an integer filled with 16 bit		*/
/*--------------------------------------------------------------*/
//
// from bytes to word
//
#endif

#define char2word(c,w,i) \
  {\
    w = (int) (((int) c[i+1] & 0xFF)  << 8) | \
        (int) c[i] & 0xFF;\
        i +=2; \
  }

#if 0
// the same as above, but no pointer increment
#endif

#define char2wordn(c,w,i) \
  {\
    w = (int) (((int) c[i+1] & 0xFF)  << 8) | \
        (int) c[i] & 0xFF;\
  }



#define BIGchar2word(c,w,i) \
  {\
    w = ((int) (((int) c[i] & 0xFF)  << 8)) | \
        ((int) c[i+1] & 0xFF);\
        i +=2; \
  }

#if 0
// the same as above, but no pointer increment
#endif

#define BIGchar2wordn(c,w,i) \
  {\
    w = ((int) (((int) c[i] & 0xFF)  << 8)) | \
        ((int) c[i+1] & 0xFF);\
  }


#if 0
// from word to bytes
#endif

#define BIGword2char(w,c,i)  c[i+1] = (BYTE) (w        & (BYTE) 0xFF);\
                             c[i]   = (BYTE) ((w >> 8) & (BYTE) 0xFF);\
                             i += 2;
#if 0
// the same as above, but no pointer increment
#endif

#define BIGword2charn(w,c,i) c[i+1] = (BIT8)((BYTE) (w        & (BYTE) 0xFF));\
                             c[i]   = (BIT8)((BYTE) ((w >> 8) & (BYTE) 0xFF));
#if 0
/*--------------------------------------------------------------*/
/* Rotation functions (32 Bit)					*/
/*--------------------------------------------------------------*/
//
// unspecific rotates.
// NOTE: n must not be 32 !!!
// ----
//
#endif

#if defined WIN32
unsigned long __cdecl _lrotl(unsigned long, int);
unsigned long __cdecl _lrotr(unsigned long, int);

#define LROTATE(a,n)     _lrotl(a,n)
#define RROTATE(a,n)     _lrotr(a,n)

#else // WIN64, SOLARIS, etc

#define LROTATE(a,n)      (((a) << (n)) | \
                         ((((a) >> (32-(n)))) & (0x7FFFFFFF >>(31-n))))

#define RROTATE(a,n)     ((((a) >> (n)) & (0x7FFFFFFF >> (n-1))) | \
                          (((a) << (32-(n))))
#endif


#if 0
// specific rotates.
#endif


#if !defined CSHARP
#define	UBIT32F(a)	a
#define	UBIT64F(a)	a
#else
#define	UBIT32F(a)	unchecked ((BIT32) a)
#define	UBIT64F(a)	unchecked ((long) a)
#endif

#define LROT1(l) ((( l << 1) | ((l >> 31) &   1)) & UBIT32F(0xFFFFFFFF))

#define LROT2(l) ((( l << 2) | ((l >> 30) &    3)) & UBIT32F(0xFFFFFFFF))
#define LROT3(l) ((( l << 3) | ((l >> 29) &    7)) & UBIT32F(0xFFFFFFFF))
#define LROT4(l) ((( l << 4) | ((l >> 28) & 0x0F)) & UBIT32F(0xFFFFFFFF))
#define LROT5(l) ((( l << 5) | ((l >> 27) & 0x1F)) & UBIT32F(0xFFFFFFFF))
#define LROT6(l) ((( l << 6) | ((l >> 26) & 0x3F)) & UBIT32F(0xFFFFFFFF))


#define RROT1(l) ((((l >> 1) & 0x7FFFFFFF) | ((l & 1) << 31)) & UBIT32F(0xFFFFFFFF))
#define RROT2(l) ((((l >> 2) & 0x3FFFFFFF) | ((l & 3) << 30)) & UBIT32F(0xFFFFFFFF))
#define RROT3(l) ((((l >> 3) & 0x1FFFFFFF) | ((l & 7) << 29)) & UBIT32F(0xFFFFFFFF))
#define	RROT4(l) ((((l >> 4) & 0x0FFFFFFF) | ((l & 0x0F)<< 28)) & UBIT32F(0xFFFFFFFF))
#define	RROT5(l) ((((l >> 5) & 0x07FFFFFF) | ((l & 0x1F)<< 27)) & UBIT32F(0xFFFFFFFF))

#define RROT1MOD28BIT(l)\
        ((((l >> 1) & 0x07FFFFFF) | ((l & 1) << 27)) & UBIT32F(0x0FFFFFFF))
#define RROT2MOD28BIT(l)\
        ((((l >> 2) & 0x03FFFFFF) | ((l & 3) << 26)) & UBIT32F(0x0FFFFFFF))
#if 0
/*--------------------------------------------------------------*/
/* BIT64 Addition (32/32 Bit + 32 Bit)				*/
/*--------------------------------------------------------------*/
#endif
#ifndef JAVA
#define ADD_64(SumMsw, SumLsw, Summand) \
  if((unsigned BIT32) SumLsw > \
     ((unsigned BIT32) SumLsw + (unsigned BIT32) Summand)) SumMsw++; \
  SumLsw += Summand;
#else // JAVA
#define ADD_64(SumMsw, SumLsw, Summand) \
  if(((long) SumLsw & 0xFFFFFFFFL) > (((long) SumLsw + (long) Summand) & \
       0xFFFFFFFFL))  SumMsw++; \
  SumLsw += Summand;
#endif


#endif // __BASE_MACROS__
