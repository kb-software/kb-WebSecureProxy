#ifndef __HOB_ENCRY_1_INTERNALS__
#define __HOB_ENCRY_1_INTERNALS__
// Required additional headers: stdlib.h, string.h, hob-encry-1.h, hob-unix01.h
#ifdef _WIN32
#pragma once
#endif

/** @file
This header contains defines used within xs_encry_1.cpp. It will be needed for
compilation, but not for usage of the external functions.

*/
#ifndef __DEF_CLEAR_BIT_8__
#define __DEF_CLEAR_BIT_8__

/**
* Clears a BIT8 array (ClearBit8Array).
*
*  @param pArr Buffer base
*  @param Offset Start of data
*  @param Size Number of elements
*/
inline void ClearBit8Array(char* pArr, int Offset, int Size)
{
   if(Size > 0)
   {
      memset(pArr + Offset, 0, Size * sizeof(char));
   }  
}

#endif // !__DEF_CLEAR_BIT_8__

/**
* Clears a BIT32 array (ClearBit32Array).
*
*  @param pArr Buffer base
*  @param Offset Start of data
*  @param Size Number of elements
*/
inline void ClearBit32Array(int* pArr, int Offset, int Size)
{
  if(Size > 0)
  {
    memset(pArr + Offset, 0, Size * sizeof(int));
  }  
}

/**
* DoAddcWLnum sums two WLarge Numbers u and v and saves the
* Carry out in the Result (DoAddcWLnum).
* NOTE: a) Size of 1st Summand >= size of 2nd Summand
* ----- b) Size of 1st and 2nd Summand must be > 0  !!
*
*  @param pSum pointer to result
*  @param pU pointer to number u
*  @param pV pointer to number v
*  @param uSize size of 1st number u
*  @param vSize size of 2nd number v
*/
extern void DoAddcWLnum(WLARGENUM* pSum, WLARGENUM* pU,
		WLARGENUM* pV,int uSize, int vSize);
/**
* DoSubbWLnum does subtract two Wnumbers u and v
*
* NOTE: a) | Minuend (1st) | > | Subtrahend(2nd) |
*       b) Size of Minuend and Subtrahend must be != 0
*       c) As |u| > |v| no carry can be generated
*
*  @param pDif pointer to result
*  @param pU pointer to Minuend (u)
*  @param pV pointer to Subtrahend(v)
*  @param uSize size of Minuend (u)
*  @param vSize size of Subtrahend (v)
*/
extern void DoSubbWLnum(WLARGENUM* pDif, WLARGENUM* pU,
		WLARGENUM* pV, int uSize, int vSize);
//-----------------------------------------------------------------------------
// basemacs.h
//-----------------------------------------------------------------------------

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

/*--------------------------------------------------------------*/
/* Byte/Long Converters Little Endian Format			*/
/*--------------------------------------------------------------*/
//
// from bytes to long
//

#if defined _WIN32
#define char2long(c,l,i) l = (int) *((int *) &c[i]); \
                         i += 4;

#define char2longn(c,l,i) l = (int) *((int *) &c[i]); \

#else // JAVA, WIN64, SOLARIS

#define char2long(c,l,i)\
       l  = (((int) c[i+3] & 0xFF) << 24) |\
            (((int) c[i+2] & 0xFF) << 16) |\
            (((int) c[i+1] & 0xFF) << 8)  |\
            ((int) c[i  ] & 0xFF);\
       i +=4;

#define char2longn(c,l,i)\
       l  = (((int) c[i+3] & 0xFF) << 24) |\
            (((int) c[i+2] & 0xFF) << 16) |\
            (((int) c[i+1] & 0xFF) << 8)  |\
            ((int)  c[i  ] & 0xFF);
#endif

// needed by MD5 / RIPEMD, special case

#define char2longcx(c,l,n,i) \
 { \
   l = 0;\
   switch (n) \
   { \
     case 0: l = (int)(((short) c[i+3] & (short) 0xFF)<< 8) << 16;\
     case 3: l|= ((int) ((short) c[i+2] & (short) 0xFF)<< 16);\
     case 2: l|= ((int)(((short) c[i+1] & (short) 0xFF)<< 8) & (int) 0xFFFF);\
     case 1: l|= ((int) ((short) c[i  ] & (short) 0xFF)      & (int) 0xFFFF);\
   } \
   if(n == 0) i += 4;\
   else i += n;\
}	


// Padding Insertion macro for RIPEMD

#define char2longcn(c,l,n)\
{ \
  switch (n)\
  { \
    case 0: \
      l = (((int)  c[3]                 << 24)|\
           (((int) c[2] & (int) 0xFF) << 16)|\
           (((int) c[1] & (int) 0xFF) <<  8)|\
           (((int) c[0] & (int) 0xFF)      ));\
      break;\
    case 1: \
      l |=(((int)  c[2]                 << 24)|\
           (((int) c[1] & (int) 0xFF) << 16)|\
           (((int) c[0] & (int) 0xFF) <<  8));\
      break;\
    case 2: \
      l |=(((int)  c[1]                 << 24)|\
           (((int) c[0] & (int) 0xFF) << 16));\
      break;\
    case 3: \
      l |=((int)  c[0]                  << 24);\
      break;\
  } \
}

// special without case 0, for RIPEMD

#define char2long3n(c,l,n,i) \
 { \
   l = 0;\
   switch (n) \
   { \
     case 3: l= ((int) ((short) c[i+2] & (short) 0xFF)<< 16);\
     case 2: l|= ((int)(((short) c[i+1] & (short) 0xFF)<< 8) & (int) 0xFFFF);\
     case 1: l|= ((int) ((short) c[i] & (short) 0xFF)      & (int) 0xFFFF);\
   } \
}	

#define char2longlong7n(c,l,n,i) \
 { \
   l = 0;\
   switch (n) \
   { \
     case 7: l=  ((long long) c[i+6] & (long long) 0x0FF) << 48;\
     case 6: l|= ((long long) c[i+5] & (long long) 0x0FF) << 40;\
     case 5: l|= ((long long) c[i+4] & (long long) 0x0FF) << 32;\
     case 4: l|= ((long long) c[i+3] & (long long) 0x0FF) << 24;\
     case 3: l|= ((long long) c[i+2] & (long long) 0x0FF) << 16;\
     case 2: l|= ((long long) c[i+1] & (long long) 0x0FF) << 8;\
     case 1: l|= ((long long) c[i]   & (long long) 0x0FF);\
   } \
}	

// from long to bytes

#if defined _WIN32 && !defined _M_IA64 && !defined WINCE // AG added && !defined WINCE
#define	long2char(l,c,i) (*((int *) &c[i]) = l); i += 4;
#define	long2charn(l,c,i) (*((int *) &c[i]) = l);

#else // JAVA, SOLARIS, WIN64 (!)

#if defined WIN64

#define long2char(l,c,i) c[i]   = (char) (l);\
                         c[i+1] = (char) (l>> 8);\
                         c[i+2] = (char) (l>>16);\
                         c[i+3] = (char) (l>>24);\
                         i += 4;
#define long2charn(l,c,i) c[i]   = (char) (l);\
                          c[i+1] = (char) (l>> 8);\
                          c[i+2] = (char) (l>>16);\
                          c[i+3] = (char) (l>>24);

#else // JAVA, SOLARIS etc

#define long2char(l,c,i) c[i]   = (char) (l       & 0x0FF);\
                         c[i+1] = (char) ((l>> 8) & 0x0FF);\
                         c[i+2] = (char) ((l>>16) & 0x0FF);\
                         c[i+3] = (char) ((l>>24) & 0x0FF);\
                         i += 4;
#define long2charn(l,c,i) c[i]   = (char) (l       & 0x0FF);\
                          c[i+1] = (char) ((l>> 8) & 0x0FF);\
                          c[i+2] = (char) ((l>>16) & 0x0FF);\
                          c[i+3] = (char) ((l>>24) & 0x0FF);
#endif
#endif

/*--------------------------------------------------------------*/
/* Byte/Long Converters Big Endian Format			*/
/*--------------------------------------------------------------*/
//
// from bytes to long
//

#define BIGchar2long(c,l,i) \
  {\
    l = ((int)  ((short) c[i+3] & (short) 0xFF)         & (int) 0xFFFF) | \
        ((int) (((short) c[i+2] & (short) 0xFF)  <<  8) & (int) 0xFFFF) | \
        ((int)  ((short) c[i+1] & (short) 0xFF)  << 16) | \
        ((int) (((short) c[i]   & (short) 0xFF)  <<  8) << 16);\
        i +=4; \
  }

// the same as above, but no pointer increment

#define BIGchar2longn(c,l,i) \
  {\
    l = ((int)  ((short) c[i+3] & (short) 0xFF)         & (int) 0xFFFF) | \
        ((int) (((short) c[i+2] & (short) 0xFF)  <<  8) & (int) 0xFFFF) | \
        ((int)  ((short) c[i+1] & (short) 0xFF)  << 16) | \
        ((int) (((short) c[i]   & (short) 0xFF)  <<  8) << 16); \
  }

#define BIGchar2longlong(c,l,i) \
  {\
    l = ((long long)  c[i+7] & (long long) 0x0FF) | \
        (((long long) c[i+6] & (long long) 0x0FF)  <<  8) | \
        (((long long) c[i+5] & (long long) 0x0FF)  << 16) | \
        (((long long) c[i+4] & (long long) 0x0FF)  << 24) | \
        (((long long) c[i+3] & (long long) 0x0FF)  << 32) | \
        (((long long) c[i+2] & (long long) 0x0FF)  << 40) | \
        (((long long) c[i+1] & (long long) 0x0FF)  << 48) | \
        (((long long) c[i]   & (long long) 0x0FF)  << 56);\
        i +=8; \
  }

// the same as above, but no pointer increment

#define BIGchar2longlongn(c,l,i) \
  {\
    l = ((long long)  c[i+7] & (long long) 0x0FF) | \
        (((long long) c[i+6] & (long long) 0x0FF)  <<  8) | \
        (((long long) c[i+5] & (long long) 0x0FF)  << 16) | \
        (((long long) c[i+4] & (long long) 0x0FF)  << 24) | \
        (((long long) c[i+3] & (long long) 0x0FF)  << 32) | \
        (((long long) c[i+2] & (long long) 0x0FF)  << 40) | \
        (((long long) c[i+1] & (long long) 0x0FF)  << 48) | \
        (((long long) c[i]   & (long long) 0x0FF)  << 56);\
  }

#define BIGchar2longc(c,l,n,i)\
{ \
  switch (n)\
  { \
    case 0: \
      l =  (int) (((short) c[i++] & (short) 0xFF)  <<  8) << 16; \
    case 1: \
      l |= ((int)  ((short) c[i++] & (short) 0xFF)  << 16); \
    case 2: \
      l |= ((int) (((short) c[i++] & (short) 0xFF)  <<  8) & (int) 0xFFFF);\
    case 3: \
      l |= ((int)  ((short) c[i++] & (short) 0xFF)         & (int) 0xFFFF);\
  } \
}

#define BIGchar2longlongc(c,l,n,i)\
{ \
  switch (n)\
  { \
    case 0: \
      l  = ((long long) c[i++] & (long long) 0x0FF)  << 56; \
    case 1: \
      l |= ((long long) c[i++] & (long long) 0x0FF)  << 48; \
    case 2: \
      l |= ((long long) c[i++] & (long long) 0x0FF)  << 40; \
    case 3: \
      l |= ((long long) c[i++] & (long long) 0x0FF)  << 32;\
    case 4: \
      l |= ((long long) c[i++] & (long long) 0x0FF)  << 24;\
    case 5: \
      l |= ((long long) c[i++] & (long long) 0x0FF)  << 16; \
    case 6: \
      l |= ((long long) c[i++] & (long long) 0x0FF)  <<  8;\
    case 7: \
      l |= ((long long) c[i++] & (long long) 0x0FF);\
  } \
}

// the same as above, but no pointer is used !!

#define BIGchar2longcn(c,l,n)\
{ \
  switch (n)\
  { \
    case 0: \
      l = ((int)  ((short) c[3] & (short) 0xFF)         & (int) 0xFFFF) | \
          ((int) (((short) c[2] & (short) 0xFF)  <<  8) & (int) 0xFFFF) | \
          ((int)  ((short) c[1] & (short) 0xFF)  << 16) | \
          ((int) (((short) c[0]   & (short) 0xFF)  <<  8) << 16); \
      break;\
    case 1: \
      l |=((int)  ((short) c[2] & (short) 0xFF)         & (int) 0xFFFF) |\
          ((int) (((short) c[1] & (short) 0xFF)  <<  8) & (int) 0xFFFF) |\
          ((int)  ((short) c[0] & (short) 0xFF)  << 16); \
      break;\
    case 2: \
      l |=((int)  ((short) c[1] & (short) 0xFF)         & (int) 0xFFFF) |\
          ((int) (((short) c[0] & (short) 0xFF)  <<  8) & (int) 0xFFFF);\
      break;\
    case 3: \
      l |=((int)  ((short) c[0] & (short) 0xFF)         & (int) 0xFFFF);\
      break;\
  } \
}

#define BIGchar2longlongcn(c,l,n)\
{ \
  switch (n)\
  { \
    case 0: \
      l = ((long long) c[7] & (long long) 0x0FF) | \
          (((long long) c[6] & (long long) 0x0FF) <<  8) | \
          (((long long) c[5] & (long long) 0x0FF) << 16) | \
          (((long long) c[4] & (long long) 0x0FF) << 24) | \
          (((long long) c[3] & (long long) 0x0FF) << 32) | \
          (((long long) c[2] & (long long) 0x0FF) << 40) | \
          (((long long) c[1] & (long long) 0x0FF) << 48) | \
          (((long long) c[0] & (long long) 0x0FF) << 56); \
      break;\
    case 1: \
      l |=((long long) c[6] & (long long) 0x0FF) | \
          (((long long) c[5] & (long long) 0x0FF) <<  8) | \
          (((long long) c[4] & (long long) 0x0FF) << 16) | \
          (((long long) c[3] & (long long) 0x0FF) << 24) | \
          (((long long) c[2] & (long long) 0x0FF) << 32) | \
          (((long long) c[1] & (long long) 0x0FF) << 40) | \
          (((long long) c[0] & (long long) 0x0FF) << 48); \
      break;\
    case 2: \
      l |=((long long) c[5] & (long long) 0x0FF) | \
          (((long long) c[4] & (long long) 0x0FF) <<  8) | \
          (((long long) c[3] & (long long) 0x0FF) << 16) | \
          (((long long) c[2] & (long long) 0x0FF) << 24) | \
          (((long long) c[1] & (long long) 0x0FF) << 32) | \
          (((long long) c[0] & (long long) 0x0FF) << 40); \
      break;\
    case 3: \
      l |=((long long) c[4] & (long long) 0x0FF) | \
          (((long long) c[3] & (long long) 0x0FF) <<  8) | \
          (((long long) c[2] & (long long) 0x0FF) << 16) | \
          (((long long) c[1] & (long long) 0x0FF) << 24) | \
          (((long long) c[0] & (long long) 0x0FF) << 32); \
      break;\
    case 4: \
      l |=((long long) c[3] & (long long) 0x0FF) | \
          (((long long) c[2] & (long long) 0x0FF) <<  8) | \
          (((long long) c[1] & (long long) 0x0FF) << 16) | \
          (((long long) c[0] & (long long) 0x0FF) << 24); \
      break;\
    case 5: \
      l |=((long long) c[2] & (long long) 0x0FF) | \
          (((long long) c[1] & (long long) 0x0FF) <<  8) | \
          (((long long) c[0] & (long long) 0x0FF) << 16); \
      break;\
    case 6: \
      l |=((long long) c[1] & (long long) 0x0FF) | \
          (((long long) c[0] & (long long) 0x0FF) <<  8); \
      break;\
    case 7: \
      l |=((long long) c[0] & (long long) 0x0FF); \
      break;\
  } \
}

#define BIGchar2long3n(c,l,n,i)\
{ \
  l = 0; \
  switch (n)\
  { \
    case 3: \
      l  = (int) (((short) c[i+2] & (short) 0xFF)  <<  8) & (int) 0xFFFF; \
    case 2: \
      l |= ((int)  ((short) c[i+1] & (short) 0xFF)  << 16); \
    case 1: \
      l |= ((int) (((short) c[i]   & (short) 0xFF)  <<  8) << 16); \
      break;\
  } \
}

#define BIGchar2longlong7n(c,l,n,i)\
{ \
  l = 0; \
  switch (n)\
  { \
    case 7: \
      l  = ((long long) c[i+6] & (long long) 0x0FF)  <<  8; \
    case 6: \
      l |= ((long long) c[i+5] & (long long) 0x0FF)  << 16; \
    case 5: \
      l |= ((long long) c[i+4] & (long long) 0x0FF)  << 24; \
    case 4: \
      l |= ((long long) c[i+3] & (long long) 0x0FF)  << 32; \
    case 3: \
      l |= ((long long) c[i+2] & (long long) 0x0FF)  << 40; \
    case 2: \
      l |= ((long long) c[i+1] & (long long) 0x0FF)  << 48; \
    case 1: \
      l |= ((long long) c[i]   & (long long) 0x0FF)  << 56; \
      break;\
  } \
}

// from long to bytes

#define BIGlong2char(l,c,i)  c[i+3] = (char) (l       & 0x0FF);\
                             c[i+2] = (char) ((l>> 8) & 0x0FF);\
                             c[i+1] = (char) ((l>>16) & 0x0FF);\
                             c[i]   = (char) ((l>>24) & 0x0FF);\
                             i += 4;

// the same as above, but no pointer increment

#define BIGlong2charn(l,c,i) c[i+3] = (char) (l       & 0x0FF);\
                             c[i+2] = (char) ((l>> 8) & 0x0FF);\
                             c[i+1] = (char) ((l>>16) & 0x0FF);\
                             c[i]   = (char) ((l>>24) & 0x0FF);

// from longlong to bytes

#define BIGlonglong2char(l,c,i)  c[i+7] = (char) l;\
                             c[i+6] = (char) (l>> 8);\
                             c[i+5] = (char) (l>>16);\
                             c[i+4] = (char) (l>>24);\
                             c[i+3] = (char) (l>>32);\
                             c[i+2] = (char) (l>>40);\
                             c[i+1] = (char) (l>>48);\
                             c[i]   = (char) (l>>56);\
                             i += 8;

// the same as above, but no pointer increment

#define BIGlonglong2charn(l,c,i)  c[i+7] = (char) l;\
                             c[i+6] = (char) (l>> 8);\
                             c[i+5] = (char) (l>>16);\
                             c[i+4] = (char) (l>>24);\
                             c[i+3] = (char) (l>>32);\
                             c[i+2] = (char) (l>>40);\
                             c[i+1] = (char) (l>>48);\
                             c[i]   = (char) (l>>56);

/*--------------------------------------------------------------*/
/* Byte/Word Converters						*/
/* NOTE: Output is always an integer filled with 16 bit		*/
/*--------------------------------------------------------------*/
//
// from bytes to word
//

#define char2word(c,w,i) \
  {\
    w = (int) (((int) c[i+1] & 0xFF)  << 8) | \
        (int) c[i] & 0xFF;\
        i +=2; \
  }

// the same as above, but no pointer increment

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

// the same as above, but no pointer increment

#define BIGchar2wordn(c,w,i) \
  {\
    w = ((int) (((int) c[i] & 0xFF)  << 8)) | \
        ((int) c[i+1] & 0xFF);\
  }

// from word to bytes

#define BIGword2char(w,c,i)  c[i+1] = (unsigned char) (w        & (unsigned char) 0xFF);\
                             c[i]   = (unsigned char) ((w >> 8) & (unsigned char) 0xFF);\
                             i += 2;
// the same as above, but no pointer increment

#define BIGword2charn(w,c,i) c[i+1] = (char)((unsigned char) (w        & (unsigned char) 0xFF));\
                             c[i]   = (char)((unsigned char) ((w >> 8) & (unsigned char) 0xFF));

#define CHAR_AS_UNSIGNED(c) (((int)c)&0xff)

/*--------------------------------------------------------------*/
/* Rotation functions (32 Bit)					*/
/*--------------------------------------------------------------*/
//
// unspecific rotates.
// NOTE: n must not be 32 !!!
// ----
//

#if defined _WIN32

#define LROTATE(a,n)     _lrotl(a,n)
#define RROTATE(a,n)     _lrotr(a,n)

#else // WIN64, SOLARIS, etc

#define LROTATE(a,n)      (((a) << (n)) | \
                         ((((a) >> (32-(n)))) & (0x7FFFFFFF >>(31-n))))

#define RROTATE(a,n)     ((((a) >> (n)) & (0x7FFFFFFF >> (n-1))) | \
                          (((a) << (32-(n))))
#endif

// specific rotates.

#define LROT1(l) ((( l << 1) | ((l >> 31) &   1)) & (uint32_t)(0xFFFFFFFF))

#define LROT2(l) ((( l << 2) | ((l >> 30) &    3)) & (uint32_t)(0xFFFFFFFF))
#define LROT3(l) ((( l << 3) | ((l >> 29) &    7)) & (uint32_t)(0xFFFFFFFF))
#define LROT4(l) ((( l << 4) | ((l >> 28) & 0x0F)) & (uint32_t)(0xFFFFFFFF))
#define LROT5(l) ((( l << 5) | ((l >> 27) & 0x1F)) & (uint32_t)(0xFFFFFFFF))
#define LROT6(l) ((( l << 6) | ((l >> 26) & 0x3F)) & (uint32_t)(0xFFFFFFFF))

#define RROT1(l) ((((l >> 1) & 0x7FFFFFFF) | ((l & 1) << 31)) & (uint32_t)(0xFFFFFFFF))
#define RROT2(l) ((((l >> 2) & 0x3FFFFFFF) | ((l & 3) << 30)) & (uint32_t)(0xFFFFFFFF))
#define RROT3(l) ((((l >> 3) & 0x1FFFFFFF) | ((l & 7) << 29)) & (uint32_t)(0xFFFFFFFF))
#define	RROT4(l) ((((l >> 4) & 0x0FFFFFFF) | ((l & 0x0F)<< 28)) & (uint32_t)(0xFFFFFFFF))
#define	RROT5(l) ((((l >> 5) & 0x07FFFFFF) | ((l & 0x1F)<< 27)) & (uint32_t)(0xFFFFFFFF))

#define RROT1MOD28BIT(l)\
        ((((l >> 1) & 0x07FFFFFF) | ((l & 1) << 27)) & (uint32_t)(0x0FFFFFFF))
#define RROT2MOD28BIT(l)\
        ((((l >> 2) & 0x03FFFFFF) | ((l & 3) << 26)) & (uint32_t)(0x0FFFFFFF))
/*--------------------------------------------------------------*/
/* long long Addition (32/32 Bit + 32 Bit)				*/
/*--------------------------------------------------------------*/
#define ADD_64(SumMsw, SumLsw, Summand) \
  if((uint32_t) SumLsw > \
     ((uint32_t) SumLsw + (uint32_t) Summand)) SumMsw++; \
  SumLsw += Summand;

/*--------------------------------------------------------------*/
/* hdsadh.h						*/
/*--------------------------------------------------------------*/

#define SMALL_PRIME_CNT		1000	// small numbers < 2000, suggested
#define PRIME_CHECK_CNT		20

//-----------------------------------------------------------------------------
// hmd2.h
//-----------------------------------------------------------------------------
  
#define MD2_CBLOCK	16		// Blocklength in bytes 
#define	MD2_X_ARRAY_LEN	48		// length of Helper array
#define	MD2_ROUNDS	18		// number of rounds

#define	MD2_data	0				// Array offset
#define	MD2_ChkSum	(MD2_data   + MD2_CBLOCK)	// Array offset n
#define	MD2_X		(MD2_data   + (2*MD2_CBLOCK))	// Array offset 2*n
#define	MD2_DatCnt	(MD2_X      + MD2_X_ARRAY_LEN)	// Array offset 2*n+m

//-----------------------------------------------------------------------------
// hmd4.h
//-----------------------------------------------------------------------------

  
#define MD4_CBLOCK	(512 / 8)	// Blocklength in bytes (64)
#define MD4_LBLOCK	16      	// Blocklength in longs (16)
#define MD4_LAST_BLOCK  (448 / 8)	// Last Block length in bytes (56)

#define	MD4_data	0			// Array offset
#define	MD4_A		(MD4_data+MD4_LBLOCK)	// Array offset n
#define	MD4_B		(MD4_data+MD4_LBLOCK+1)	// Array offset n+1
#define	MD4_C		(MD4_data+MD4_LBLOCK+2)	// Array offset n+2
#define	MD4_D		(MD4_data+MD4_LBLOCK+3)	// Array offset n+3
#define	MD4_LenL	(MD4_data+MD4_LBLOCK+4)	// Array offset n+4
#define	MD4_LenH	(MD4_data+MD4_LBLOCK+5)	// Array offset n+5
#define	MD4_DatInd	(MD4_data+MD4_LBLOCK+6)	// Array offset n+6
#define	MD4_DatCnt	(MD4_data+MD4_LBLOCK+7)	// Array offset n+7

#define LSWAP(a) ( \
	((int) (a >> 16) & 0xFFFF ) >> 8 | \
        ((int) (a >> 16) & 0xFFFF) << 8  | \
        (long) (((int) a & 0xFFFF) >> 8) << 16 | \
        (long) ((int) (((int) a & 0xFFFF) << 8) & 0xFFFF) << 16 )

#define WSWAP(a) ( (a >> 8) | ( (int) (a << 8) ) )

#define	F_MD4(X,Y,Z)	((((Y) ^ (Z)) & (X)) ^ (Z))
#define G_MD4(X,Y,Z)	(((X) & (Y | Z)) | ((Y) & (Z)))
#define	H_MD4(X,Y,Z)	((X) ^ (Y) ^ (Z))



#define R1_MD4(a,b,c,d,k,s,t) { \
	a += ((k)+(t)+F_MD4((b),(c),(d))); \
	a =LROTATE(a,s); };

#define R2_MD4(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+G_MD4((b),(c),(d))); \
	a =LROTATE(a,s); };

#define R3_MD4(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+H_MD4((b),(c),(d))); \
	a =LROTATE(a,s); };

#define INIT_A_MD4 (int) 0x67452301
#define INIT_B_MD4 (int) 0xefcdab89
#define INIT_C_MD4 (int) 0x98badcfe
#define INIT_D_MD4 (int) 0x10325476

//-----------------------------------------------------------------------------
// hmd5.h
//-----------------------------------------------------------------------------
  
#define MD5_CBLOCK	(512 / 8)	// Blocklength in bytes (64)
#define MD5_LBLOCK	16      	// Blocklength in longs (16)
#define MD5_LAST_BLOCK  (448 / 8)	// Last Block length in bytes (56)

#define	MD5_data	0			// Array offset
#define	MD5_A		(MD5_data+MD5_LBLOCK)	// Array offset n
#define	MD5_B		(MD5_data+MD5_LBLOCK+1)	// Array offset n+1
#define	MD5_C		(MD5_data+MD5_LBLOCK+2)	// Array offset n+2
#define	MD5_D		(MD5_data+MD5_LBLOCK+3)	// Array offset n+3
#define	MD5_LenL	(MD5_data+MD5_LBLOCK+4)	// Array offset n+4
#define	MD5_LenH	(MD5_data+MD5_LBLOCK+5)	// Array offset n+5
#define	MD5_DatInd	(MD5_data+MD5_LBLOCK+6)	// Array offset n+6
#define	MD5_DatCnt	(MD5_data+MD5_LBLOCK+7)	// Array offset n+7

#define	F_MD5(X,Y,Z)	((((Y) ^ (Z)) & (X)) ^ (Z))
#define	G_MD5(X,Y,Z)	((((X) ^ (Y)) & (Z)) ^ (Y))
#define	H_MD5(X,Y,Z)	((X) ^ (Y) ^ (Z))
#define	I_MD5(X,Y,Z)	(((X) | (~(Z))) ^ (Y))


#define R1_MD5(a,b,c,d,k,s,t) { \
	a += ((k)+(t)+F_MD5((b),(c),(d))); \
	a =LROTATE(a,s); \
	a += (b); };\

#define R2_MD5(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+G_MD5((b),(c),(d))); \
	a =LROTATE(a,s); \
	a+=b; };

#define R3_MD5(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+H_MD5((b),(c),(d))); \
	a =LROTATE(a,s); \
	a+=b; };

#define R4_MD5(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+I_MD5((b),(c),(d))); \
	a =LROTATE(a,s); \
	a+=b; };

#define INIT_A_MD5 (int)(0x67452301)
#define INIT_B_MD5 (int)(0xefcdab89)
#define INIT_C_MD5 (int)(0x98badcfe)
#define INIT_D_MD5 (int)(0x10325476)

//-----------------------------------------------------------------------------
// hsha.h
//-----------------------------------------------------------------------------

#define SHA_CBLOCK	64
#define SHA_LBLOCK	16
#define SHA_BLOCK	16
#define SHA_LAST_BLOCK  56
#define SHA_LENGTH_BLOCK 8

#define	SHA_data	0			// Array offset 0
#define	SHA_h0		(SHA_data+SHA_BLOCK)	// Array offset + n
#define	SHA_h1		(SHA_data+SHA_BLOCK+1)	// Array offset + n+1
#define	SHA_h2		(SHA_data+SHA_BLOCK+2)	// Array offset + n+2
#define	SHA_h3		(SHA_data+SHA_BLOCK+3)	// Array offset + n+3
#define	SHA_h4		(SHA_data+SHA_BLOCK+4)	// Array offset + n+4
#define	SHA_Nl		(SHA_data+SHA_BLOCK+5)	// Array offset + n+5
#define	SHA_Nh		(SHA_data+SHA_BLOCK+6)	// Array offset + n+6
#define	SHA_num		(SHA_data+SHA_BLOCK+7)	// Array offset + n+7

#define K_00_19	(uint32_t) 0x5a827999
#define K_20_39 (uint32_t) 0x6ed9eba1
#define K_40_59 (uint32_t) 0x8f1bbcdc
#define K_60_79 (uint32_t) 0xca62c1d6

#if defined _WIN32	// only faster on older Pentiums ???
#define	ULROT1(l)	_lrotl(l,1)
#define	ULROT5(l)	_lrotl(l,5)
#define	URROT2(l)	_lrotl(l,30)
#else
#define	ULROT1(l) (l << 1) | ((l >> 31) & 0x01)
#define	ULROT5(l) (l << 5) + ((l >> 27) & 0x1F)
#define	URROT2(l) ((l >> 2) & 0x3FFFFFFF) | (l << 30)
#endif

// NOTE: we assume that base offset for SHA_Array is 0 !!

#define Xupdate(a,i) \
  a = (SHA_Array[i      & 0x0F]^SHA_Array[(i+2)  & 0x0F]^\
       SHA_Array[(i+8)  & 0x0F]^SHA_Array[(i+13) & 0x0F]);\
  SHA_Array[i & 0x0F] = a = ULROT1(a);

#define BODY_00_15(i,a,b,c,d,e,f) \
  f = SHA_Array[i] + e + K_00_19 + ULROT5(a) + (((c ^ d) & b) ^ d); \
  b = URROT2(b);

#define BODY_16_19(i,a,b,c,d,e,f) \
  Xupdate(f,i); \
  f += e + K_00_19 + ULROT5(a) + (((c ^ d) & b) ^ d); \
  b = URROT2(b);

#define BODY_20_39(i,a,b,c,d,e,f) \
  Xupdate(f,i); \
  f += e + K_20_39 + ULROT5(a) + (b^c^d); \
  b = URROT2(b);

#define BODY_40_59(i,a,b,c,d,e,f) \
  Xupdate(f,i); \
  f += e + K_40_59 + ULROT5(a) + ((b & c) | ((b | c) & d)); \
  b = URROT2(b);

#define BODY_60_79(i,a,b,c,d,e,f) \
  Xupdate(f,i); \
  f = SHA_Array[i & 0x0F]+e+ K_60_79 + ULROT5(a) + (b^c^d); \
  b = URROT2((b));

#define INIT_DATA_h0 (uint32_t) 0x67452301
#define INIT_DATA_h1 (uint32_t) 0xefcdab89
#define INIT_DATA_h2 (uint32_t) 0x98badcfe
#define INIT_DATA_h3 (uint32_t) 0x10325476
#define INIT_DATA_h4 (uint32_t) 0xc3d2e1f0

//-----------------------------------------------------------------------------
// shaconst.h
//-----------------------------------------------------------------------------

//-------------------------------------------
// Initializer Values for SHA-224/256/384/512
//-------------------------------------------
/** @addtogroup sha2
* @{
* @file
* This header contains the constants needed for SHA-2 hash family.
* @}
*/

#define H0_SHA224	(int)(0xc1059ed8)
#define H1_SHA224	(int)(0x367cd507)
#define H2_SHA224	(int)(0x3070dd17)
#define H3_SHA224	(int)(0xf70e5939)
#define H4_SHA224	(int)(0xffc00b31)
#define H5_SHA224	(int)(0x68581511)
#define H6_SHA224	(int)(0x64f98fa7)
#define H7_SHA224	(int)(0xbefa4fa4)

#define H0_SHA256	(int)(0x6a09e667)
#define H1_SHA256	(int)(0xbb67ae85)
#define H2_SHA256	(int)(0x3c6ef372)
#define H3_SHA256	(int)(0xa54ff53a)
#define H4_SHA256	(int)(0x510e527f)
#define H5_SHA256	(int)(0x9b05688c)
#define H6_SHA256	(int)(0x1f83d9ab)
#define H7_SHA256	(int)(0x5be0cd19)

#define H0_SHA384	(long long)(0xcbbb9d5dc1059ed8LL)
#define H1_SHA384	(long long)(0x629a292a367cd507LL)
#define H2_SHA384	(long long)(0x9159015a3070dd17LL)
#define H3_SHA384	(long long)(0x152fecd8f70e5939LL)
#define H4_SHA384	(long long)(0x67332667ffc00b31LL)
#define H5_SHA384	(long long)(0x8eb44a8768581511LL)
#define H6_SHA384	(long long)(0xdb0c2e0d64f98fa7LL)
#define H7_SHA384	(long long)(0x47b5481dbefa4fa4LL)

#define H0_SHA512	(long long)(0x6a09e667f3bcc908LL)
#define H1_SHA512	(long long)(0xbb67ae8584caa73bLL)
#define H2_SHA512	(long long)(0x3c6ef372fe94f82bLL)
#define H3_SHA512	(long long)(0xa54ff53a5f1d36f1LL)
#define H4_SHA512	(long long)(0x510e527fade682d1LL)
#define H5_SHA512	(long long)(0x9b05688c2b3e6c1fLL)
#define H6_SHA512	(long long)(0x1f83d9abfb41bd6bLL)
#define H7_SHA512	(long long)(0x5be0cd19137e2179LL)

//---------------------------------------
// Constants for SHA-256, 64 32-Bit words
//---------------------------------------

#define K0_SHA256	(int)(0x428a2f98)
#define K1_SHA256	(int)(0x71374491)
#define K2_SHA256	(int)(0xb5c0fbcf)
#define K3_SHA256	(int)(0xe9b5dba5)
#define K4_SHA256	(int)(0x3956c25b)
#define K5_SHA256	(int)(0x59f111f1)
#define K6_SHA256	(int)(0x923f82a4)
#define K7_SHA256	(int)(0xab1c5ed5)
#define K8_SHA256	(int)(0xd807aa98)
#define K9_SHA256	(int)(0x12835b01)
#define K10_SHA256	(int)(0x243185be)
#define K11_SHA256	(int)(0x550c7dc3)
#define K12_SHA256	(int)(0x72be5d74)
#define K13_SHA256	(int)(0x80deb1fe)
#define K14_SHA256	(int)(0x9bdc06a7)
#define K15_SHA256	(int)(0xc19bf174)
#define K16_SHA256	(int)(0xe49b69c1)
#define K17_SHA256	(int)(0xefbe4786)
#define K18_SHA256	(int)(0x0fc19dc6)
#define K19_SHA256	(int)(0x240ca1cc)
#define K20_SHA256	(int)(0x2de92c6f)
#define K21_SHA256	(int)(0x4a7484aa)
#define K22_SHA256	(int)(0x5cb0a9dc)
#define K23_SHA256	(int)(0x76f988da)
#define K24_SHA256	(int)(0x983e5152)
#define K25_SHA256	(int)(0xa831c66d)
#define K26_SHA256	(int)(0xb00327c8)
#define K27_SHA256	(int)(0xbf597fc7)
#define K28_SHA256	(int)(0xc6e00bf3)
#define K29_SHA256	(int)(0xd5a79147)
#define K30_SHA256	(int)(0x06ca6351)
#define K31_SHA256	(int)(0x14292967)
#define K32_SHA256	(int)(0x27b70a85)
#define K33_SHA256	(int)(0x2e1b2138)
#define K34_SHA256	(int)(0x4d2c6dfc)
#define K35_SHA256	(int)(0x53380d13)
#define K36_SHA256	(int)(0x650a7354)
#define K37_SHA256	(int)(0x766a0abb)
#define K38_SHA256	(int)(0x81c2c92e)
#define K39_SHA256	(int)(0x92722c85)
#define K40_SHA256	(int)(0xa2bfe8a1)
#define K41_SHA256	(int)(0xa81a664b)
#define K42_SHA256	(int)(0xc24b8b70)
#define K43_SHA256	(int)(0xc76c51a3)
#define K44_SHA256	(int)(0xd192e819)
#define K45_SHA256	(int)(0xd6990624)
#define K46_SHA256	(int)(0xf40e3585)
#define K47_SHA256	(int)(0x106aa070)
#define K48_SHA256	(int)(0x19a4c116)
#define K49_SHA256	(int)(0x1e376c08)
#define K50_SHA256	(int)(0x2748774c)
#define K51_SHA256	(int)(0x34b0bcb5)
#define K52_SHA256	(int)(0x391c0cb3)
#define K53_SHA256	(int)(0x4ed8aa4a)
#define K54_SHA256	(int)(0x5b9cca4f)
#define K55_SHA256	(int)(0x682e6ff3)
#define K56_SHA256	(int)(0x748f82ee)
#define K57_SHA256	(int)(0x78a5636f)
#define K58_SHA256	(int)(0x84c87814)
#define K59_SHA256	(int)(0x8cc70208)
#define K60_SHA256	(int)(0x90befffa)
#define K61_SHA256	(int)(0xa4506ceb)
#define K62_SHA256	(int)(0xbef9a3f7)
#define K63_SHA256	(int)(0xc67178f2)

//-------------------------------------------
// Constants for SHA-384/512, 80 64-Bit words
//-------------------------------------------

#define K0_SHA512	(long long)(0x428a2f98d728ae22LL)
#define K1_SHA512	(long long)(0x7137449123ef65cdLL)
#define K2_SHA512	(long long)(0xb5c0fbcfec4d3b2fLL)
#define K3_SHA512	(long long)(0xe9b5dba58189dbbcLL)
#define K4_SHA512	(long long)(0x3956c25bf348b538LL)
#define K5_SHA512	(long long)(0x59f111f1b605d019LL)
#define K6_SHA512	(long long)(0x923f82a4af194f9bLL)
#define K7_SHA512	(long long)(0xab1c5ed5da6d8118LL)
#define K8_SHA512	(long long)(0xd807aa98a3030242LL)
#define K9_SHA512	(long long)(0x12835b0145706fbeLL)
#define K10_SHA512	(long long)(0x243185be4ee4b28cLL)
#define K11_SHA512	(long long)(0x550c7dc3d5ffb4e2LL)
#define K12_SHA512	(long long)(0x72be5d74f27b896fLL)
#define K13_SHA512	(long long)(0x80deb1fe3b1696b1LL)
#define K14_SHA512	(long long)(0x9bdc06a725c71235LL)
#define K15_SHA512	(long long)(0xc19bf174cf692694LL)
#define K16_SHA512	(long long)(0xe49b69c19ef14ad2LL)
#define K17_SHA512	(long long)(0xefbe4786384f25e3LL)
#define K18_SHA512	(long long)(0x0fc19dc68b8cd5b5LL)
#define K19_SHA512	(long long)(0x240ca1cc77ac9c65LL)
#define K20_SHA512	(long long)(0x2de92c6f592b0275LL)
#define K21_SHA512	(long long)(0x4a7484aa6ea6e483LL)
#define K22_SHA512	(long long)(0x5cb0a9dcbd41fbd4LL)
#define K23_SHA512	(long long)(0x76f988da831153b5LL)
#define K24_SHA512	(long long)(0x983e5152ee66dfabLL)
#define K25_SHA512	(long long)(0xa831c66d2db43210LL)
#define K26_SHA512	(long long)(0xb00327c898fb213fLL)
#define K27_SHA512	(long long)(0xbf597fc7beef0ee4LL)
#define K28_SHA512	(long long)(0xc6e00bf33da88fc2LL)
#define K29_SHA512	(long long)(0xd5a79147930aa725LL)
#define K30_SHA512	(long long)(0x06ca6351e003826fLL)
#define K31_SHA512	(long long)(0x142929670a0e6e70LL)
#define K32_SHA512	(long long)(0x27b70a8546d22ffcLL)
#define K33_SHA512	(long long)(0x2e1b21385c26c926LL)
#define K34_SHA512	(long long)(0x4d2c6dfc5ac42aedLL)
#define K35_SHA512	(long long)(0x53380d139d95b3dfLL)
#define K36_SHA512	(long long)(0x650a73548baf63deLL)
#define K37_SHA512	(long long)(0x766a0abb3c77b2a8LL)
#define K38_SHA512	(long long)(0x81c2c92e47edaee6LL)
#define K39_SHA512	(long long)(0x92722c851482353bLL)
#define K40_SHA512	(long long)(0xa2bfe8a14cf10364LL)
#define K41_SHA512	(long long)(0xa81a664bbc423001LL)
#define K42_SHA512	(long long)(0xc24b8b70d0f89791LL)
#define K43_SHA512	(long long)(0xc76c51a30654be30LL)
#define K44_SHA512	(long long)(0xd192e819d6ef5218LL)
#define K45_SHA512	(long long)(0xd69906245565a910LL)
#define K46_SHA512	(long long)(0xf40e35855771202aLL)
#define K47_SHA512	(long long)(0x106aa07032bbd1b8LL)
#define K48_SHA512	(long long)(0x19a4c116b8d2d0c8LL)
#define K49_SHA512	(long long)(0x1e376c085141ab53LL)
#define K50_SHA512	(long long)(0x2748774cdf8eeb99LL)
#define K51_SHA512	(long long)(0x34b0bcb5e19b48a8LL)
#define K52_SHA512	(long long)(0x391c0cb3c5c95a63LL)
#define K53_SHA512	(long long)(0x4ed8aa4ae3418acbLL)
#define K54_SHA512	(long long)(0x5b9cca4f7763e373LL)
#define K55_SHA512	(long long)(0x682e6ff3d6b2b8a3LL)
#define K56_SHA512	(long long)(0x748f82ee5defb2fcLL)
#define K57_SHA512	(long long)(0x78a5636f43172f60LL)
#define K58_SHA512	(long long)(0x84c87814a1f0ab72LL)
#define K59_SHA512	(long long)(0x8cc702081a6439ecLL)
#define K60_SHA512	(long long)(0x90befffa23631e28LL)
#define K61_SHA512	(long long)(0xa4506cebde82bde9LL)
#define K62_SHA512	(long long)(0xbef9a3f7b2c67915LL)
#define K63_SHA512	(long long)(0xc67178f2e372532bLL)
#define K64_SHA512	(long long)(0xca273eceea26619cLL)
#define K65_SHA512	(long long)(0xd186b8c721c0c207LL)
#define K66_SHA512	(long long)(0xeada7dd6cde0eb1eLL)
#define K67_SHA512	(long long)(0xf57d4f7fee6ed178LL)
#define K68_SHA512	(long long)(0x06f067aa72176fbaLL)
#define K69_SHA512	(long long)(0x0a637dc5a2c898a6LL)
#define K70_SHA512	(long long)(0x113f9804bef90daeLL)
#define K71_SHA512	(long long)(0x1b710b35131c471bLL)
#define K72_SHA512	(long long)(0x28db77f523047d84LL)
#define K73_SHA512	(long long)(0x32caab7b40c72493LL)
#define K74_SHA512	(long long)(0x3c9ebe0a15c9bebcLL)
#define K75_SHA512	(long long)(0x431d67c49c100d4cLL)
#define K76_SHA512	(long long)(0x4cc5d4becb3e42b6LL)
#define K77_SHA512	(long long)(0x597f299cfc657e2aLL)
#define K78_SHA512	(long long)(0x5fcb6fab3ad6faecLL)
#define K79_SHA512	(long long)(0x6c44198c4a475817LL)

//--------------------------------------------------
// Macros for SHA-256/384/512
//--------------------------------------------------

#define	Ch_SHA(x,y,z)	((x & y)^((~x) & z))
#define	Maj_SHA(x,y,z)	((x & y)^(x & z)^(y & z))

#define S0_256(x)	((((x>> 2) & 0x3FFFFFFF)|(x<<30))^\
			 (((x>>13) & 0x0007FFFF)|(x<<19))^\
			 (((x>>22) & 0x000003FF)|(x<<10)))
#define S1_256(x)	((((x>> 6) & 0x03FFFFFF)|(x<<26))^\
			 (((x>>11) & 0x001FFFFF)|(x<<21))^\
			 (((x>>25) & 0x0000007F)|(x<<7)))
#define s0_256(x)	((((x>> 7) & 0x01FFFFFF)|(x<<25))^\
			 (((x>>18) & 0x00003FFF)|(x<<14))^\
			 (((x>> 3) & 0x1FFFFFFF)))
#define s1_256(x)	((((x>>17) & 0x00007FFF)|(x<<15))^\
			 (((x>>19) & 0x00001FFF)|(x<<13))^\
			 (((x>>10) & 0x003FFFFF)))

#define S0_512(x)	((((x>>28) & (long long)(0x0000000FFFFFFFFFLL))|(x<<36))^\
			 (((x>>34) & (long long)(0x000000003FFFFFFFLL))|(x<<30))^\
			 (((x>>39) & (long long)(0x0000000001FFFFFFLL))|(x<<25)))
#define S1_512(x)	((((x>>14) & (long long)(0x0003FFFFFFFFFFFFLL))|(x<<50))^\
			 (((x>>18) & (long long)(0x00003FFFFFFFFFFFLL))|(x<<46))^\
			 (((x>>41) & (long long)(0x00000000007FFFFFLL))|(x<<23)))
#define s0_512(x)	((((x>> 1) & (long long)(0x7FFFFFFFFFFFFFFFLL))|(x<<63))^\
			 (((x>> 8) & (long long)(0x00FFFFFFFFFFFFFFLL))|(x<<56))^\
			 (((x>> 7) & (long long)(0x01FFFFFFFFFFFFFFLL))))
#define s1_512(x)	((((x>>19) & (long long)(0x00001FFFFFFFFFFFLL))|(x<<45))^\
			 (((x>>61) & (long long)(0x0000000000000007LL))|(x<<3))^\
			 (((x>> 6) & (long long)(0x03FFFFFFFFFFFFFFLL))))

//-----------------------------------------------------------------------------
// RIPEMD 160
//-----------------------------------------------------------------------------

#define RPMD_CBLOCK	64
#define RPMD_LBLOCK	16
#define RPMD_BLOCK	16
#define RPMD_LAST_BLOCK  56

#define	RPMD_data	0				// Array offset 0
#define	RPMD_A		(RPMD_data+RPMD_BLOCK)		// Array offset + n
#define	RPMD_B		(RPMD_data+RPMD_BLOCK+1)	// Array offset + n+1
#define	RPMD_C		(RPMD_data+RPMD_BLOCK+2)	// Array offset + n+2
#define	RPMD_D		(RPMD_data+RPMD_BLOCK+3)	// Array offset + n+3
#define	RPMD_E		(RPMD_data+RPMD_BLOCK+4)	// Array offset + n+4
#define	RPMD_Nl		(RPMD_data+RPMD_BLOCK+5)	// Array offset + n+5
#define	RPMD_Nh		(RPMD_data+RPMD_BLOCK+6)	// Array offset + n+6
#define	RPMD_num	(RPMD_data+RPMD_BLOCK+7)	// Array offset + n+7

// Initialization Constants

#define RPMD160_A       (int)(0x67452301)
#define RPMD160_B       (int)(0xEFCDAB89)
#define RPMD160_C       (int)(0x98BADCFE)
#define RPMD160_D       (int)(0x10325476)
#define RPMD160_E       (int)(0xC3D2E1F0)

// Additive constants, left and right side

#define	YL_0    (int)(0x00000000)
#define YL_1	(int)(0x5A827999)
#define YL_2    (int)(0x6ED9EBA1)
#define YL_3    (int)(0x8F1BBCDC)
#define YL_4    (int)(0xA953FD4E)

#define YR_0    (int)(0x50A28BE6)
#define YR_1    (int)(0x5C4DD124)
#define YR_2    (int)(0x6D703EF3)
#define YR_3    (int)(0x7A6D76E9)
#define YR_4    (int)(0x00000000)

// Data Access Indices left and right

#define ZL_00   (int) 0
#define ZL_01   (int) 1
#define ZL_02   (int) 2
#define ZL_03   (int) 3
#define ZL_04   (int) 4
#define ZL_05   (int) 5
#define ZL_06   (int) 6
#define ZL_07   (int) 7
#define ZL_08   (int) 8
#define ZL_09   (int) 9
#define ZL_10   (int) 10
#define ZL_11   (int) 11
#define ZL_12   (int) 12
#define ZL_13   (int) 13
#define ZL_14   (int) 14
#define ZL_15   (int) 15

#define ZL_16   (int) 7
#define ZL_17   (int) 4
#define ZL_18   (int) 13
#define ZL_19   (int) 1
#define ZL_20   (int) 10
#define ZL_21   (int) 6
#define ZL_22   (int) 15
#define ZL_23   (int) 3
#define ZL_24   (int) 12
#define ZL_25   (int) 0
#define ZL_26   (int) 9
#define ZL_27   (int) 5
#define ZL_28   (int) 2
#define ZL_29   (int) 14
#define ZL_30   (int) 11
#define ZL_31   (int) 8

#define ZL_32   (int) 3
#define ZL_33   (int) 10
#define ZL_34   (int) 14
#define ZL_35   (int) 4
#define ZL_36   (int) 9
#define ZL_37   (int) 15
#define ZL_38   (int) 8
#define ZL_39   (int) 1
#define ZL_40   (int) 2
#define ZL_41   (int) 7
#define ZL_42   (int) 0
#define ZL_43   (int) 6
#define ZL_44   (int) 13
#define ZL_45   (int) 11
#define ZL_46   (int) 5
#define ZL_47   (int) 12

#define ZL_48   (int) 1
#define ZL_49   (int) 9
#define ZL_50   (int)11
#define ZL_51   (int)10
#define ZL_52   (int) 0
#define ZL_53   (int) 8
#define ZL_54   (int)12
#define ZL_55   (int) 4
#define ZL_56   (int)13
#define ZL_57   (int) 3
#define ZL_58   (int) 7
#define ZL_59   (int)15
#define ZL_60   (int)14
#define ZL_61   (int) 5
#define ZL_62   (int) 6
#define ZL_63   (int) 2

#define ZL_64   (int) 4
#define ZL_65   (int) 0
#define ZL_66   (int) 5
#define ZL_67   (int) 9
#define ZL_68   (int) 7
#define ZL_69   (int) 12
#define ZL_70   (int) 2
#define ZL_71   (int) 10
#define ZL_72   (int) 14
#define ZL_73   (int) 1
#define ZL_74   (int) 3
#define ZL_75   (int) 8
#define ZL_76   (int) 11
#define ZL_77   (int) 6
#define ZL_78   (int) 15
#define ZL_79   (int) 13

#define ZR_00   (int) 5
#define ZR_01   (int) 14
#define ZR_02   (int) 7
#define ZR_03   (int) 0
#define ZR_04   (int) 9
#define ZR_05   (int) 2
#define ZR_06   (int) 11
#define ZR_07   (int) 4
#define ZR_08   (int) 13
#define ZR_09   (int) 6
#define ZR_10   (int) 15
#define ZR_11   (int) 8
#define ZR_12   (int) 1
#define ZR_13   (int) 10
#define ZR_14   (int) 3
#define ZR_15   (int) 12

#define ZR_16   (int) 6
#define ZR_17   (int) 11
#define ZR_18   (int) 3
#define ZR_19   (int) 7
#define ZR_20   (int) 0
#define ZR_21   (int) 13
#define ZR_22   (int) 5
#define ZR_23   (int) 10
#define ZR_24   (int) 14
#define ZR_25   (int) 15
#define ZR_26   (int) 8
#define ZR_27   (int) 12
#define ZR_28   (int) 4
#define ZR_29   (int) 9
#define ZR_30   (int) 1
#define ZR_31   (int) 2

#define ZR_32   (int) 15
#define ZR_33   (int) 5
#define ZR_34   (int) 1
#define ZR_35   (int) 3
#define ZR_36   (int) 7
#define ZR_37   (int) 14
#define ZR_38   (int) 6
#define ZR_39   (int) 9
#define ZR_40   (int) 11
#define ZR_41   (int) 8
#define ZR_42   (int) 12
#define ZR_43   (int) 2
#define ZR_44   (int) 10
#define ZR_45   (int) 0
#define ZR_46   (int) 4
#define ZR_47   (int) 13

#define ZR_48   (int) 8
#define ZR_49   (int) 6
#define ZR_50   (int) 4
#define ZR_51   (int) 1
#define ZR_52   (int) 3
#define ZR_53   (int) 11
#define ZR_54   (int) 15
#define ZR_55   (int) 0
#define ZR_56   (int) 5
#define ZR_57   (int) 12
#define ZR_58   (int) 2
#define ZR_59   (int) 13
#define ZR_60   (int) 9
#define ZR_61   (int) 7
#define ZR_62   (int) 10
#define ZR_63   (int) 14

#define ZR_64   (int) 12
#define ZR_65   (int) 15
#define ZR_66   (int) 10
#define ZR_67   (int) 4
#define ZR_68   (int) 1
#define ZR_69   (int) 5
#define ZR_70   (int) 8
#define ZR_71   (int) 7
#define ZR_72   (int) 6
#define ZR_73   (int) 2
#define ZR_74   (int) 13
#define ZR_75   (int) 14
#define ZR_76   (int) 0
#define ZR_77   (int) 3
#define ZR_78   (int) 9
#define ZR_79   (int) 11

// Bitshift counts left and right

#define SL_00   (int) 11
#define SL_01   (int) 14
#define SL_02   (int) 15
#define SL_03   (int) 12
#define SL_04   (int) 5
#define SL_05   (int) 8
#define SL_06   (int) 7
#define SL_07   (int) 9
#define SL_08   (int) 11
#define SL_09   (int) 13
#define SL_10   (int) 14
#define SL_11   (int) 15
#define SL_12   (int) 6
#define SL_13   (int) 7
#define SL_14   (int) 9
#define SL_15   (int) 8

#define SL_16   (int) 7
#define SL_17   (int) 6
#define SL_18   (int) 8
#define SL_19   (int) 13
#define SL_20   (int) 11
#define SL_21   (int) 9
#define SL_22   (int) 7
#define SL_23   (int) 15
#define SL_24   (int) 7
#define SL_25   (int) 12
#define SL_26   (int) 15
#define SL_27   (int) 9
#define SL_28   (int) 11
#define SL_29   (int) 7
#define SL_30   (int) 13
#define SL_31   (int) 12

#define SL_32   (int) 11
#define SL_33   (int) 13
#define SL_34   (int) 6
#define SL_35   (int) 7
#define SL_36   (int) 14
#define SL_37   (int) 9
#define SL_38   (int) 13
#define SL_39   (int) 15
#define SL_40   (int) 14
#define SL_41   (int) 8
#define SL_42   (int) 13
#define SL_43   (int) 6
#define SL_44   (int) 5
#define SL_45   (int) 12
#define SL_46   (int) 7
#define SL_47   (int) 5

#define SL_48   (int) 11
#define SL_49   (int) 12
#define SL_50   (int) 14
#define SL_51   (int) 15
#define SL_52   (int) 14
#define SL_53   (int) 15
#define SL_54   (int) 9
#define SL_55   (int) 8
#define SL_56   (int) 9
#define SL_57   (int) 14
#define SL_58   (int) 5
#define SL_59   (int) 6
#define SL_60   (int) 8
#define SL_61   (int) 6
#define SL_62   (int) 5
#define SL_63   (int) 12

#define SL_64   (int) 9
#define SL_65   (int) 15
#define SL_66   (int) 5
#define SL_67   (int) 11
#define SL_68   (int) 6
#define SL_69   (int) 8
#define SL_70   (int) 13
#define SL_71   (int) 12
#define SL_72   (int) 5
#define SL_73   (int) 12
#define SL_74   (int) 13
#define SL_75   (int) 14
#define SL_76   (int) 11
#define SL_77   (int) 8
#define SL_78   (int) 5
#define SL_79   (int) 6

#define SR_00   (int) 8
#define SR_01   (int) 9
#define SR_02   (int) 9
#define SR_03   (int) 11
#define SR_04   (int) 13
#define SR_05   (int) 15
#define SR_06   (int) 15
#define SR_07   (int) 5
#define SR_08   (int) 7
#define SR_09   (int) 7
#define SR_10   (int) 8
#define SR_11   (int) 11
#define SR_12   (int) 14
#define SR_13   (int) 14
#define SR_14   (int) 12
#define SR_15   (int) 6

#define SR_16   (int) 9
#define SR_17   (int) 13
#define SR_18   (int) 15
#define SR_19   (int) 7
#define SR_20   (int) 12
#define SR_21   (int) 8
#define SR_22   (int) 9
#define SR_23   (int) 11
#define SR_24   (int) 7
#define SR_25   (int) 7
#define SR_26   (int) 12
#define SR_27   (int) 7
#define SR_28   (int) 6
#define SR_29   (int) 15
#define SR_30   (int) 13
#define SR_31   (int) 11

#define SR_32   (int) 9
#define SR_33   (int) 7
#define SR_34   (int) 15
#define SR_35   (int) 11
#define SR_36   (int) 8
#define SR_37   (int) 6
#define SR_38   (int) 6
#define SR_39   (int) 14
#define SR_40   (int) 12
#define SR_41   (int) 13
#define SR_42   (int) 5
#define SR_43   (int) 14
#define SR_44   (int) 13
#define SR_45   (int) 13
#define SR_46   (int) 7
#define SR_47   (int) 5

#define SR_48   (int) 15
#define SR_49   (int) 5
#define SR_50   (int) 8
#define SR_51   (int) 11
#define SR_52   (int) 14
#define SR_53   (int) 14
#define SR_54   (int) 6
#define SR_55   (int) 14
#define SR_56   (int) 6
#define SR_57   (int) 9
#define SR_58   (int) 12
#define SR_59   (int) 9
#define SR_60   (int) 12
#define SR_61   (int) 5
#define SR_62   (int) 15
#define SR_63   (int) 8

#define SR_64   (int) 8
#define SR_65   (int) 5
#define SR_66   (int) 12
#define SR_67   (int) 9
#define SR_68   (int) 12
#define SR_69   (int) 5
#define SR_70   (int) 14
#define SR_71   (int) 6
#define SR_72   (int) 8
#define SR_73   (int) 13
#define SR_74   (int) 6
#define SR_75   (int) 5
#define SR_76   (int) 15
#define SR_77   (int) 13
#define SR_78   (int) 11
#define SR_79   (int) 11

#define F1(x,y,z)	((x) ^ (y) ^ (z))
#define F2(x,y,z)	((((y) ^ (z)) & (x)) ^ (z))
#define F3(x,y,z)	(((~(y)) | (x)) ^ (z))
#define F4(x,y,z)	((((x) ^ (y)) & (z)) ^ (y))
#define F5(x,y,z)	(((~(z)) | (y)) ^ (x))

#define RIP1(a,b,c,d,e,w,s) { \
	a+=F1(b,c,d)+RPMD_Array[w]; \
        a=LROTATE(a,s)+e; \
        c=LROTATE(c,10); }

#define RIP2(a,b,c,d,e,w,s,K) { \
	a+=F2(b,c,d)+RPMD_Array[w]+K; \
        a=LROTATE(a,s)+e; \
        c=LROTATE(c,10); }

#define RIP3(a,b,c,d,e,w,s,K) { \
	a+=F3(b,c,d)+RPMD_Array[w]+K; \
        a=LROTATE(a,s)+e; \
        c=LROTATE(c,10); }

#define RIP4(a,b,c,d,e,w,s,K) { \
	a+=F4(b,c,d)+RPMD_Array[w]+K; \
        a=LROTATE(a,s)+e; \
        c=LROTATE(c,10); }

#define RIP5(a,b,c,d,e,w,s,K) { \
	a+=F5(b,c,d)+RPMD_Array[w]+K; \
        a=LROTATE(a,s)+e; \
        c=LROTATE(c,10); }

//-----------------------------------------------------------------------------
// HMAC
//-----------------------------------------------------------------------------

#define	HMAC_MAX_HASH_ARRAY_SIZE    SHA512_ARRAY_SIZE	// SHA-512 is largest

#define	HMAC_BLOCK_LEN	64

#define	HMAC_IPAD	0x36
#define	HMAC_OPAD	0x5C

//-----------------------------------------------------------------------------
// RC4
//-----------------------------------------------------------------------------

#define	RC4_x		0			// index 0 into structure
#define	RC4_y		1			// index 1 into structure
#define	RC4_data	2			// index 2 into structure

#define SK_LOOP(n) { \
		tmp= state[(n)+RC4_data]; \
		id2 = ((((int) data[id1]) & 0xFF) + \
                       (((int) tmp) & 0xFF) + id2) & 0xFF; \
                id1++; \
		if (id1 == index) id1=Offset; \
		state[(n)+RC4_data]=state[id2+RC4_data]; \
		state[id2+RC4_data]=tmp; }

#define RC4_ENC_LOOP(in,out) \
		x  = (x+1) & 0xFF; \
		tx = ((int) key[x+RC4_data]) & 0xFF; \
		y  = (tx + y) & 0xFF; \
		key[x+RC4_data] = key[y+RC4_data]; \
		key[y+RC4_data] = (char) (tx & 0xFF); \
		out = (char)(key[((tx + ((int) key[x+RC4_data])) & 0xff) +\
                            RC4_data] ^ (in));

//-----------------------------------------------------------------------------
// DES
//-----------------------------------------------------------------------------

#define SP_BOX_LEN	64			// 64 longs a 32 Bit
/*--------------------------------------------------------------*/
/* Permutation functions (taken from EAY)			*/
/*--------------------------------------------------------------*/
// Bit-Permutation between 2 long words, see documentation
// DESSWAP.TXT for specification of operation

#define PERMUTE2(x,y,tmp,bitcnt,bitmask) {\
	 tmp = ((x >> bitcnt) ^ y) & bitmask;\
         x ^= (tmp << bitcnt);\
         y ^= tmp;}

// Bit-Permutation within 1 long words, works similar
// as Bit-Permutation between 2 long words, but does not work
// for bitcnt <= 0 !!!
// (due to sign extension problem when using right shift !!!)

#define PERMUTE1(x,tmp,bitcnt,bitmask) { \
         tmp = (x ^ (x >> (16+bitcnt))) & bitmask;\
         x = x ^ tmp ^ (tmp << (16+bitcnt));}

/*--------------------------------------------------------------*/
/* DES functions (adapted from EAY)				*/
/*--------------------------------------------------------------*/
//
// DES Encryption/Decryption Round Function
//
//
// NOTE: the primary l,r rotate that is needed to generate correct
//       Bit order for the S-Box inputs (Expansion Permutation) has
//	 been changed so that the bit order for l and r is now:
//       31,20,29,......,1,32 in FIPS order (was before:
//       29,28,27,......,1,32,31,30).
//	 This eases and unifies access via a single Index into SP-Tables.
//       Therefore the SP-Boxes had to be modified (changed Output
//       Permutation) see SBOXGEN1.C. Further the Subkey-Generation
//	 routine is modified for reduced left rotate by 2 Bits.
//
// Operations:
// XOR with S1,S3,S5,S7 Subkey i   (C'')
// XOR with S2,S4,S6,S8 Subkey i+1 (D'')
// align for S-Box Access (E-Box Function helper function RROT4)
// XOR with S1 Output,
// XOR with S3 Output,
// XOR with S5 Output,
// XOR with S7 Output,
// XOR with S2 Output,
// XOR with S4 Output,
// XOR with S6 Output,
// XOR with S8 Output

#define DES_ROUND(L,R,K,SK_TAB) { \
	u=R^SK_TAB[K  ]; \
	v=R^SK_TAB[K+1]; \
	v=RROT4(v); \
	L^= \
        DesSPBox[u & 0x3F]^\
        DesSPBox[2*SP_BOX_LEN + ((u>> 8) & 0x3F)]^\
        DesSPBox[4*SP_BOX_LEN + ((u>>16) & 0x3F)]^\
        DesSPBox[6*SP_BOX_LEN + ((u>>24) & 0x3F)]^\
        DesSPBox[1*SP_BOX_LEN + (v & 0x3F)]^\
        DesSPBox[3*SP_BOX_LEN + ((v>> 8) & 0x3F)]^\
        DesSPBox[5*SP_BOX_LEN + ((v>>16) & 0x3F)]^\
        DesSPBox[7*SP_BOX_LEN + ((v>>24) & 0x3F)];}

//----------------------------------------------------------------------
// DES Initial permutation (IP)
//
// Note: the Output is in reversed bit-Order with l and r values
// ----- exchanged !!
//
// Description of Operation:
//	 exch. low/high nibbles
//	 exch. low/high 16 Bit Words
//	 exch. low/high 2 bits/nib.
//	 exch. low/high bytes
//	 exch. even/odd bits
//

#define IP(l,r) { \
	unsigned int IP_TMP; \
	PERMUTE2(r,l,IP_TMP, 4,0x0F0F0F0F) \
	PERMUTE2(l,r,IP_TMP,16,0x0000FFFF) \
	PERMUTE2(r,l,IP_TMP, 2,0x33333333) \
	PERMUTE2(l,r,IP_TMP, 8,0x00FF00FF) \
	PERMUTE2(r,l,IP_TMP, 1,0x55555555)}

//----------------------------------------------------------------------
// DES Final permutation (FP)
//
// Note: the Input is in reversed bit-Order with l and r values
// ----- exchanged !!
//
// Description of Operation:
//	 exch. odd/even bits
//	 exch. low/high bytes
//	 exch. low/high 2 bits/nib.
//	 exch. low/high 16 Bit Words
//	 exch. low/high nibbles
//

#define FP(l,r) { \
	unsigned int IP_TMP; \
	PERMUTE2(l,r,IP_TMP, 1,0x55555555) \
	PERMUTE2(r,l,IP_TMP, 8,0x00FF00FF) \
	PERMUTE2(l,r,IP_TMP, 2,0x33333333) \
	PERMUTE2(r,l,IP_TMP,16,0x0000FFFF) \
	PERMUTE2(l,r,IP_TMP, 4,0x0F0F0F0F)}

//----------------------------------------------------------------------
// DES Initial Key permutation (PC-1)
//
// Note: the Output is in reversed bit-Order !
// ----
//
// Description of Operation:
//	 exch. low/high Nibbles
//	 exch. low/high upmost bits C
//	 dto.			    D
//	 exch. odd/even bits
//	 exch. low/high bytes
//	 exch. odd/even bits
//	 assemble D-Bits, note c is used for upmost bits !!
//	 remove D-Bits from C

#define PC1(d,c) { \
        unsigned int PC1_TMP; \
	PERMUTE2(d,c,PC1_TMP, 4,0x0F0F0F0F)\
	PERMUTE1(c,PC1_TMP,2,0x00003333)\
	PERMUTE1(d,PC1_TMP,2,0x00003333)\
	PERMUTE2(d,c,PC1_TMP, 1,0x55555555)\
	PERMUTE2(c,d,PC1_TMP, 8,0x00FF00FF)\
	PERMUTE2(d,c,PC1_TMP, 1,0x55555555)\
	d= (((d & 0x000000FF) << 16) |\
             (d & 0x0000FF00) | \
            ((d & 0x00FF0000) >> 16) |\
            ((c & 0xF0000000) >>  4));\
	c &= 0x0FFFFFFF;}

//-----------------------------------------------------------------------------
// AES
//-----------------------------------------------------------------------------

#define	AES_MX_VAL	0x11B		// reduction polynom
#define	AES_MX_VAL_LSB	0x1B		// dto. LSB only

//===================================================================
// Macros for the AES Round Functions
//===================================================================
#define	AES_ENC_ROUND(U,V,W,X,A,B,C,D,KeyTab,N) \
  U = TabEncT0[(unsigned char) A] ^ \
      TabEncT1[(unsigned char) (B >> 8)] ^ \
      TabEncT2[(unsigned char) (C >> 16)] ^ \
      TabEncT3[(unsigned char) (D >> 24)] ^ \
      KeyTab[4+(N*4)];\
  V = TabEncT0[(unsigned char) B] ^ \
      TabEncT1[(unsigned char) (C >> 8)] ^ \
      TabEncT2[(unsigned char) (D >> 16)] ^ \
      TabEncT3[(unsigned char) (A >> 24)] ^ \
      KeyTab[4+(N*4)+1];\
  W = TabEncT0[(unsigned char) C] ^ \
      TabEncT1[(unsigned char) (D >> 8)] ^ \
      TabEncT2[(unsigned char) (A >> 16)] ^ \
      TabEncT3[(unsigned char) (B >> 24)] ^ \
      KeyTab[4+(N*4)+2];\
  X = TabEncT0[(unsigned char) D] ^ \
      TabEncT1[(unsigned char) (A >> 8)] ^ \
      TabEncT2[(unsigned char) (B >> 16)] ^ \
      TabEncT3[(unsigned char) (C >> 24)] ^ \
      KeyTab[4+(N*4)+3];

#define	AES_ENC_LAST_ROUND(U,V,W,X,A,B,C,D,KeyTab,N) \
  U = ((unsigned int) SBox[(unsigned char) A] | \
      ((unsigned int) SBox[(unsigned char) (B >> 8)]  <<  8) | \
      ((unsigned int) SBox[(unsigned char) (C >> 16)] << 16) | \
      ((unsigned int) SBox[(unsigned char) (D >> 24)] << 24)) ^ \
      KeyTab[4+(N*4)]; \
  V = ((unsigned int) SBox[(unsigned char) B] | \
      ((unsigned int) SBox[(unsigned char) (C >> 8)]  <<  8) | \
      ((unsigned int) SBox[(unsigned char) (D >> 16)] << 16) | \
      ((unsigned int) SBox[(unsigned char) (A >> 24)] << 24)) ^ \
      KeyTab[4+(N*4)+1]; \
  W = ((unsigned int) SBox[(unsigned char) C] | \
      ((unsigned int) SBox[(unsigned char) (D >> 8)]  <<  8) | \
      ((unsigned int) SBox[(unsigned char) (A >> 16)] << 16) | \
      ((unsigned int) SBox[(unsigned char) (B >> 24)] << 24)) ^ \
      KeyTab[4+(N*4)+2]; \
  X = ((unsigned int) SBox[(unsigned char) D] | \
      ((unsigned int) SBox[(unsigned char) (A >> 8)]  <<  8) | \
      ((unsigned int) SBox[(unsigned char) (B >> 16)] << 16) | \
      ((unsigned int) SBox[(unsigned char) (C >> 24)] << 24)) ^ \
      KeyTab[4+(N*4)+3];

#define AES_DEC_ROUND(U,V,W,X,A,B,C,D,KeyTab,N) \
  U = TabDecT0[(unsigned char) A] ^ \
      TabDecT1[(unsigned char) (D >> 8)] ^ \
      TabDecT2[(unsigned char) (C >> 16)] ^ \
      TabDecT3[(unsigned char) (B >> 24)] ^ \
      KeyTab[4+(N*4)]; \
  V = TabDecT0[(unsigned char) B] ^ \
      TabDecT1[(unsigned char) (A >> 8)] ^ \
      TabDecT2[(unsigned char) (D >> 16)] ^ \
      TabDecT3[(unsigned char) (C >> 24)] ^ \
      KeyTab[4+(N*4)+1]; \
  W = TabDecT0[(unsigned char) C] ^ \
      TabDecT1[(unsigned char) (B >> 8)] ^ \
      TabDecT2[(unsigned char) (A >> 16)] ^ \
      TabDecT3[(unsigned char) (D >> 24)] ^ \
      KeyTab[4+(N*4)+2];\
  X = TabDecT0[(unsigned char) D] ^ \
      TabDecT1[(unsigned char) (C >> 8)] ^ \
      TabDecT2[(unsigned char) (B >> 16)] ^ \
      TabDecT3[(unsigned char) (A >> 24)] ^ \
      KeyTab[4+(N*4)+3];

#define	AES_DEC_LAST_ROUND(U,V,W,X,A,B,C,D,KeyTab,N) \
  U = ((unsigned int) InvSBox[(unsigned char) A] | \
      ((unsigned int) InvSBox[(unsigned char) (D >>  8)] <<  8) | \
      ((unsigned int) InvSBox[(unsigned char) (C >> 16)] << 16) | \
      ((unsigned int) InvSBox[(unsigned char) (B >> 24)] << 24)) ^ \
      KeyTab[4+(N*4)]; \
  V = ((unsigned int) InvSBox[(unsigned char) B] | \
      ((unsigned int) InvSBox[(unsigned char) (A >>  8)] <<  8) | \
      ((unsigned int) InvSBox[(unsigned char) (D >> 16)] << 16) | \
      ((unsigned int) InvSBox[(unsigned char) (C >> 24)] << 24)) ^ \
      KeyTab[4+(N*4)+1]; \
  W = ((unsigned int) InvSBox[(unsigned char) C] | \
      ((unsigned int) InvSBox[(unsigned char) (B >>  8)] <<  8) | \
      ((unsigned int) InvSBox[(unsigned char) (A >> 16)] << 16) | \
      ((unsigned int) InvSBox[(unsigned char) (D >> 24)] << 24)) ^ \
      KeyTab[4+(N*4)+2]; \
  X = ((unsigned int) InvSBox[(unsigned char) D] | \
      ((unsigned int) InvSBox[(unsigned char) (C >>  8)] <<  8) | \
      ((unsigned int) InvSBox[(unsigned char) (B >> 16)] << 16) | \
      ((unsigned int) InvSBox[(unsigned char) (A >> 24)] << 24)) ^ \
      KeyTab[4+(N*4)+3];

//-----------------------------------------------------------------------------
// hmemmgr
//-----------------------------------------------------------------------------

#define	HMEM_DEFAULT_16BYTE_BLOCKS	256
#define	HMEM_DEFAULT_32BYTE_BLOCKS	 64
#define	HMEM_DEFAULT_64BYTE_BLOCKS	 32
#define	HMEM_DEFAULT_256BYTE_BLOCKS	 32
#define	HMEM_DEFAULT_512BYTE_BLOCKS	 32

#define	DEFAULT_HMEM_POOL_SIZE		1024
#define	DEFAULT_HMEM_POOL_COUNT		4
  
#define	HMEM_LOCKED_STRUC_FLAG_BIT		0x01	// is locked
#define	HMEM_NO_POOLS_FLAG_BIT			0x02	// do not use pools
#define	HMEM_STRUC_LOCAL_FLAG_BIT		0x04	// is local struc
      
#define	HMEM_MAX_MANAGED_BUF_SIZE	512
/**
* This structure is used for management of a collection of memory blocks of a
* specific size. It works as a linked list.
* Note: Allocation bit array and buffer will be allocated
*   together with the header structure (C-Version).
*/
typedef struct HMEMHDR_t {
  struct HMEMHDR_t * pNextMemHdr;	//!< pointer to next structure
  int	BlockSize;			//!< size of blocks managed
  int	BlockCount;			//!< number of blocks managed
  int	MaxUsedCount;			//!< number of buffers used
  int   ActUsedCount;			//!< actual in use count
  char*  pBufStart;			//!< Starting Address of buffer
  char*  pBufEnd;			//!< Last address of buffer (byte)
  int* pUsedBlockBitArray;		//!< start of array of block used bits
} HMEMHDR;

/**
* This structure contains the anchors of the managed memory block lists and the
* used/free pool lists.
*/
typedef struct HMEMDESC_t {
  HMEMHDR *	pMemCtlAnchor16Byte;	//!< 16 byte blocks list  (256, 4kB)
  HMEMHDR *	pMemCtlAnchor32Byte;	//!< 32 byte blocks list  (64,  2kB)
  HMEMHDR *	pMemCtlAnchor64Byte;	//!< 64 byte blocks list  (32,  2kB)
  HMEMHDR *	pMemCtlAnchor256Byte;	//!< 256 byte blocks list (32,  8kB)
  HMEMHDR *	pMemCtlAnchor512Byte;	//!< 512 byte blocks list (32, 16kB)
  struct HMEMPOOL_STRUC_t * pUsedPoolListAnchor; //!< Pool used list / NULL
  struct HMEMPOOL_STRUC_t * pFreePoolListAnchor; //!< Pool free list / NULL
} HMEMDESC;

/** 
* This structure is the control structure for the so called pooled buffers.
* It creats a linked list.
*/
typedef struct HMEMPOOL_STRUC_t {
  struct HMEMPOOL_STRUC_t * pNext;	//!< pointer to next structure/NULL
  int	AllocSize;			//!< actual allocated size
  char* pMemBase;			//!< Buffer base address
} HMEMPOOL_STRUC;

#ifdef XH_INTERFACE
extern ds__hmem m_make_mem_struct(BOOL (* am__aux2)(void * vp__p_ctx,
                                             int in__funct,
                                             void * vp__p_mem,
                                             int  in__size),
                                  void* avop_user_field,
                                  int inp_flags);

#endif

#ifndef DEF_AUX_MEMGET
#define DEF_AUX_MEMGET             0        // get a block of memory
#endif
#ifndef DEF_AUX_MEMFREE
#define DEF_AUX_MEMFREE            1        // release a block of memory
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined XH_INTERFACE
extern  HMEMDESC* AllocSmallMemDescStruc(HMEM_CTX_DEF1);
#endif

extern  int HFreeManagedBuffer(HMEM_CTX_DEF
			 char* pMem, HMEMDESC* pMemDesc);
extern  char* HAllocManagedBuffer(HMEM_CTX_DEF
				int BufSize, HMEMDESC* pMemDesc);
#ifdef __cplusplus
}
#endif

//-----------------------------------------------------------------------------
// LNUM32
//-----------------------------------------------------------------------------

#define	WELEMENT_SIZE		4
#define	WELEMENT_BITS		32

//-----------------------------------------------------------------------------
// RSA
//-----------------------------------------------------------------------------

#define	MD2_DIGEST_LEN			16	// byte length
#define	MD5_DIGEST_LEN			16	// byte length
#define	SHA1_DIGEST_LEN			20	// byte length
#define	RIPEMD160_DIGEST_LEN		20	// byte length
#define	SHA256_DIGEST_LEN		32	// byte length
#define	SHA384_DIGEST_LEN		48	// byte length
#define	SHA512_DIGEST_LEN		64	// byte length
#define	SHA224_DIGEST_LEN		28	// byte length

#define	RSA_MAX_DIGEST_LEN		64	// from SHA512 (old value = 20 from SHA1/RIPEMD)
#define	MAX_DIGEST_STATE_LEN		100	// pruefen, obs langt

#define	RSA_DEF_MD_HDR_ALG_ID_IND	13	// index of Algor-ID Byte

#define MD2_WITH_RSA_ALGOR_ID_BYTE	0x02	// PKCS1 MD2
#define MD5_WITH_RSA_ALGOR_ID_BYTE	0x05	// PKCS1 MD5

#define RSA_DEF_SHA2_HDR_TOTLEN_IND	1	// index of Total length
#define RSA_DEF_SHA2_HDR_ALG_ID_IND	14	// index of Algor-ID Byte
#define RSA_DEF_SHA2_HDR_HASHLEN_IND	18	// index of hash length
#define SHA256_WITH_RSA_ALGOR_ID_BYTE	0x01	// NIST SHA-256
#define SHA384_WITH_RSA_ALGOR_ID_BYTE	0x02	// NIST SHA-384
#define SHA512_WITH_RSA_ALGOR_ID_BYTE	0x03	// NIST SHA-512
#define SHA224_WITH_RSA_ALGOR_ID_BYTE	0x04	// NIST SHA-224

//-----------------------------------------------------------------------------
// RNG
//-----------------------------------------------------------------------------

#define CRNG_REQ_MAX_BYTES	8192		// max. number of byte per request
#define	CRNG_RESEED_INTERVAL	0xFFFFFFFF	// reseed limit
#define	CRNG_CHECK_INTERVAL	128		// recheck limit

/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| FILE NAME: hob-random-cas-02.h                                    |*/
/*| -------------                                                     |*/
/*|  header file for random CAS routine / HOB-SSL                     |*/
/*|  all platforms, Windows and all Unix                              |*/
/*|  KB 20.08.16                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2016                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif

struct dsd_random_cas_02 {                  /* parameters call random CAS */
   int        imc_proc_max_msec;            /* process for number of milli-seconds maximum */
   int        imc_max_cores;                /* use maximum number of cores / zero == all */
   int        imc_thread_prio;              /* priority of threads / zero == default */
   int        imc_alloc_no;                 /* number of allocs        */
   BOOL       boc_cas_time_rel;             /* store CAS time relative */
   int        imc_max_len_random;           /* length of memory achc_random in bytes / octets */
   int        imc_comp_len_random;          /* compute length achc_random in bytes / octets */
   char       *achc_random;                 /* returned random         */
};

struct dsd_ari_entropy_01 {                 /* compute entropy of data */
   int        imc_func;                     /* called function         */
   
#ifndef DEF_IFUNC_START
#define DEF_IFUNC_START        0            /* start of processing, initialize */
#endif
#ifndef DEF_IFUNC_CONT
#define DEF_IFUNC_CONT         1            /* process data as specified */
                                            /* by buffer pointers      */
#endif
#ifndef DEF_IFUNC_RESET
#define DEF_IFUNC_RESET        2
#endif
#ifndef DEF_IFUNC_END
#define DEF_IFUNC_END          3
#endif
   int        imc_return;                   /* return code             */
#ifndef DEF_IRET_NORMAL
#define DEF_IRET_NORMAL        0            /* continue processing     */
#endif
#ifndef DEF_IRET_END
#define DEF_IRET_END           1            /* subroutine has ended processing */
#endif
#ifndef DEF_IRET_ERRAU
#define DEF_IRET_ERRAU         2            /* error in auxiliary prog */
#endif
#ifndef DEF_IRET_ERREY
#define DEF_IRET_ERREY         3            /* eyecather invalid       */
#endif
#ifndef DEF_IRET_ERRNE
#define DEF_IRET_ERRNE         4            /* no end-of-file found    */
#endif
#ifndef DEF_IRET_INVDA
#define DEF_IRET_INVDA         5            /* invalid data found      */
#endif

   BOOL       boc_eof;                      /* end of file input       */

   char *     achc_in_cur;                  /* current position input data */
   char *     achc_in_end;                  /* end of buffer with input data */

   char *     achc_out_cur;                 /* current end of output data */
   char *     achc_out_end;                 /* end of buffer for output data */

   BOOL (* amc_aux) ( void *, int, void *, int );  /* auxiliary helper routine pointer */
                                            /* callback                */
#ifndef DEF_AUX_MEMGET
#define DEF_AUX_MEMGET             0        /* get / acquire a block of memory */
#endif
#ifndef DEF_AUX_MEMFREE
#define DEF_AUX_MEMFREE            1        /* free / release a block of memory */
#endif
   void *     ac_ext;                       /* attached buffer pointer */
   void *     vpc_userfld;                  /* User Field Subroutine   */
};
#ifdef HL_UNIX
/** get values to find out clock cycle of CPU in Unix                  */
struct dsd_clock_cycle_01 {                 /* store values clock cycle */
   HL_LONGLONG ilc_value[ 4 ];
};
#endif

extern PTYPE int m_call_random_cas_02( struct dsd_random_cas_02 * );
extern PTYPE void m_call_ari_entropy_01( struct dsd_ari_entropy_01 * );
extern PTYPE BOOL m_aux( void * vpp_userfld, int imp_func, void * ap_addr, int imp_length );

#endif // !__HOB_ENCRY_1_INTERNALS__
