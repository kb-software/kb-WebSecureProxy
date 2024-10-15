#ifdef JAVA
#ifndef JDEBUG

#undef MD5inst
#define MD5inst m5

#if 0
//-----------------------------------
// local variables
//-----------------------------------
#endif

#ifdef __MD5__
#define R1F	A1
#define R2F	A2
#define R3F	A3
#define R4F	A4
#define MD5BlockService	A5
#endif

#if 0
//-----------------------------------
// global exports
//-----------------------------------
#endif

#define MD5_Init	M5I
#define MD5_Update	M5U
#define MD5_Final	M5F

#endif // JDEBUG
#endif // JAVA
