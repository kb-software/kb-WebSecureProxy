#ifndef __MD5_HEADER__
#define __MD5_HEADER__

#include <basetype.h>
#include <basemacs.h>

#ifndef JAVA
#define MD5inst
#else
#define MD5inst md5dgst
#endif

#if 0
#define JDEBUG
#endif

#include "hmd5subs.h"


#if 0 // no longer used ....
#if 0
/*--------------------------------------------------------------*/
/* Swapper Macros, optimized for Intel				*/
/*--------------------------------------------------------------*/
//
// 32 Bit macros, compiler optimized
//
#endif


#ifdef _WIN32_

#define WSWAP(a) (((a & 0xFF) <<8) | ((a & 0xFF00) >> 8))
#define LSWAP(a) (((a & 0xFF) << 24) | ((a & 0xFF00) << 8) |\
                  ((a & 0xFF0000) >> 8) | ((a & 0xFF000000) >> 24))

#else

#if 0
//
// 16 Bit integer macros, compiler optimized
//
#endif

#define LSWAP(a) ( \
	((int) (a >> 16) & 0xFFFF ) >> 8 | \
        ((int) (a >> 16) & 0xFFFF) << 8  | \
        (long) (((int) a & 0xFFFF) >> 8) << 16 | \
        (long) ((int) (((int) a & 0xFFFF) << 8) & 0xFFFF) << 16 )


#define WSWAP(a) ( (a >> 8) | ( (int) (a << 8) ) )

#endif
#endif // 0, no longer used ....




#if 0
/*--------------------------------------------------------------*/
/* Functions used in MD5 from RFC 1321				*/
/*--------------------------------------------------------------*/
//
// original functions F,G
//
//#define F(X,Y,Z)	(((X) & (Y))  |  ((~(X)) & (Z)))
//#define G(X,Y,Z)	(((X) & (Z))  |  ((Y) & (~(Z))))

/* Following simplification taken from SSLEAY for functions F and G */
#endif

#ifdef __MD5__

#define	F(X,Y,Z)	((((Y) ^ (Z)) & (X)) ^ (Z))
#define	G(X,Y,Z)	((((X) ^ (Y)) & (Z)) ^ (Y))
#define	H(X,Y,Z)	((X) ^ (Y) ^ (Z))
#define	I(X,Y,Z)	(((X) | (~(Z))) ^ (Y))


#define R1(a,b,c,d,k,s,t) { \
	a += ((k)+(t)+F((b),(c),(d))); \
	a =LROTATE(a,s); \
	a += (b); };\

#define R2(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+G((b),(c),(d))); \
	a =LROTATE(a,s); \
	a+=b; };

#define R3(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+H((b),(c),(d))); \
	a =LROTATE(a,s); \
	a+=b; };

#define R4(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+I((b),(c),(d))); \
	a =LROTATE(a,s); \
	a+=b; };

#endif // __MD5__

#if 0
/*--------------------------------------------------------------*/
/* MD5 State Structure						*/
/*--------------------------------------------------------------*/
#endif

#define MD5_CBLOCK	(512 / 8)	// Blocklength in bytes (64)
#define MD5_LBLOCK	16      	// Blocklength in longs (16)
#define MD5_LAST_BLOCK  (448 / 8)	// Last Block length in bytes (56)
#define MD5_DIGEST_LEN	16		// Number of digest bytes

#if 0
//typedef struct MD5_State_t
//{
//  BIT32	A,B,C,D;		// 32 Bit variables
//  BIT32 LengthL,LengthH;		// total BYTE length, excl. padding
//  BIT32	BufDatIndex;		// Actual block buffer index
//  BIT32 BufDatCnt;			// Buffer Data byte count
//  BIT32	Buffer[MD5_LBLOCK];	// Block Buffer
//} MD5_State;
#endif

#define	MD5_data	0			// Array offset
#define	MD5_A		(MD5_data+MD5_LBLOCK)	// Array offset n
#define	MD5_B		(MD5_data+MD5_LBLOCK+1)	// Array offset n+1
#define	MD5_C		(MD5_data+MD5_LBLOCK+2)	// Array offset n+2
#define	MD5_D		(MD5_data+MD5_LBLOCK+3)	// Array offset n+3
#define	MD5_LenL	(MD5_data+MD5_LBLOCK+4)	// Array offset n+4
#define	MD5_LenH	(MD5_data+MD5_LBLOCK+5)	// Array offset n+5
#define	MD5_DatInd	(MD5_data+MD5_LBLOCK+6)	// Array offset n+6
#define	MD5_DatCnt	(MD5_data+MD5_LBLOCK+7)	// Array offset n+7

#define	MD5_ARRAY_SIZE	(MD5_DatCnt + 1)	// Array Size

#if 0
/*--------------------------------------------------------------*/
/* Externals							*/
/*--------------------------------------------------------------*/
#endif

#ifndef JAVA

#define MD5_INIT(a,b) MD5_Init(b)
#define MD5_UPDATE(a,b,c,d,e) MD5_Update(b,c,d,e)
#define MD5_FINAL(a,b,c,d) MD5_Final(b,c,d)


//#if !defined __MD5__ || !defined WIN32
#ifndef __MD5__

#ifdef __cplusplus
extern"C"{
#endif

extern void FAST MD5_Init(BIT32 MD5_Array[]);
extern void FAST MD5_Update(BIT32 MD5_Array[], REGISTER BIT8 data[],
                            int offset, BIT32 len);
extern void FAST MD5_Final(BIT32 MD5_Array[], BIT8 Digest[],int Offset);
extern BIT8PTR FAST MD5(BIT8 data[], BIT32 len, BIT8 Digest[]);
#ifdef __cplusplus
}
#endif

#endif	// __MD5__


#else
#define MD5_INIT(a,b) a.MD5_Init(b)
#define MD5_UPDATE(a,b,c,d,e) a.MD5_Update(b,c,d,e)
#define MD5_FINAL(a,b,c,d) a.MD5_Final(b,c,d)
#endif  // JAVA

#undef JDEBUG

#endif	//__MD5_HEADER__
