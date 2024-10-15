#ifndef HEADER_SHA_H
#define HEADER_SHA_H

#include "basetype.h"
#include "basemacs.h"

#ifndef JAVA
#define SHA1inst
#else
#define SHA1inst sha1dgst
#endif

#if 0
#define JDEBUG
#endif

#define SHA_CBLOCK	64
#define SHA_LBLOCK	16
#define SHA_BLOCK	16
#define SHA_LAST_BLOCK  56
#define SHA_LENGTH_BLOCK 8
#define SHA_DIGEST_LEN	20

#if 0
// NOTE NOTE NOTE: Do NOT Change the following offsets, or the
// --------------- SHA-1 macros below will not work any longer !!!
#endif // 0

#define	SHA_data	0			// Array offset 0
#define	SHA_h0		(SHA_data+SHA_BLOCK)	// Array offset + n
#define	SHA_h1		(SHA_data+SHA_BLOCK+1)	// Array offset + n+1
#define	SHA_h2		(SHA_data+SHA_BLOCK+2)	// Array offset + n+2
#define	SHA_h3		(SHA_data+SHA_BLOCK+3)	// Array offset + n+3
#define	SHA_h4		(SHA_data+SHA_BLOCK+4)	// Array offset + n+4
#define	SHA_Nl		(SHA_data+SHA_BLOCK+5)	// Array offset + n+5
#define	SHA_Nh		(SHA_data+SHA_BLOCK+6)	// Array offset + n+6
#define	SHA_num		(SHA_data+SHA_BLOCK+7)	// Array offset + n+7

#define	SHA_ARRAY_SIZE	(SHA_num+1)		// size of array

#if !defined CSHARP
#define K_00_19	(UBIT32) 0x5a827999
#define K_20_39 (UBIT32) 0x6ed9eba1
#define K_40_59 (UBIT32) 0x8f1bbcdc
#define K_60_79 (UBIT32) 0xca62c1d6
#else
#define K_00_19	UBIT32F(0x5a827999)
#define K_20_39 UBIT32F(0x6ed9eba1)
#define K_40_59 UBIT32F(0x8f1bbcdc)
#define K_60_79 UBIT32F(0xca62c1d6)
#endif


#if 0
//#define	F_00_19(b,c,d)	(((c ^ d) & b) ^ d)
//#define	F_20_39(b,c,d)	(b ^ c ^ d)
//#define	F_40_59(b,c,d)	((b & c) | ((b|c) & d))
//#define	F_60_79(b,c,d)	F_20_39(b,c,d)
#endif

#if defined WIN32 || defined WIN64	// only faster on older Pentiums ???
#define	ULROT1(l)	_lrotl(l,1)
#define	ULROT5(l)	_lrotl(l,5)
#define	URROT2(l)	_lrotl(l,30)
#elif !defined JAVA || defined CSHARP
#define	ULROT1(l) (l << 1) | ((l >> 31) & 0x01)
#define	ULROT5(l) (l << 5) + ((l >> 27) & 0x1F)
#define	URROT2(l) ((l >> 2) & 0x3FFFFFFF) | (l << 30)
#else // JAVA only
#define	ULROT1(l) (l << 1) | (l >>> 31)
#define	ULROT5(l) (l << 5) + (l >>> 27)
#define	URROT2(l) (l >>> 2) | (l << 30)
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

#ifndef JAVA
//--------------------------------------------------------------------
#endif


#ifndef JAVA


#define SHA1_INIT(a,b) SHA1_Init(b)
#define SHA1_UPDATE(a,b,c,d,e) SHA1_Update(b,c,d,e)
#define SHA1_FINAL(a,b,c,d) SHA1_Final(b,c,d)


#if !defined __SHA1_DIGEST__ || !defined WIN32
#ifdef __cplusplus
extern"C"{
#endif

extern void FAST SHA1_Init(BIT32PTR SHA_Array);
extern void FAST SHA1_Update(REGISTER UBIT32PTR SHA_Array,
                            BIT8PTR data, int Offset, UBIT32 len);
extern void FAST SHA1_Final(UBIT32PTR SHA_Array, BIT8PTR Digest, int Offset);

#ifdef __cplusplus
}
#endif
#endif // __SHA1_DIGEST


#define SHA1_SINGLE(a,b,c,d) SHA1_Single(b,c,d)

#ifndef __SHA1_ONE__
#ifdef __cplusplus
extern "C" {
#endif

extern BIT8PTR FAST SHA1_Single(BIT8 data[], BIT32 len, BIT8 digest[]);

#ifdef __cplusplus
}
#endif
#endif // __SHA1_ONE__

#else

#define SHA1_INIT(a,b) a.SHA1_Init(b)
#define SHA1_UPDATE(a,b,c,d,e) a.SHA1_Update(b,c,d,e)
#define SHA1_FINAL(a,b,c,d) a.SHA1_Final(b,c,d)
#ifndef __SHA1_DIGEST__

#endif

#ifndef __SHA1_ONE__
#define SHA1  Sha1_one.SHA1
#endif

#endif // JAVA

#undef JDEBUG

#endif // HEADER
