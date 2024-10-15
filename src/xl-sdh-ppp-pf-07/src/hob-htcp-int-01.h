/******************************************************************************
 * File name: hob-htcp-int-01.h
 *
 * Provides typedefs for 8, 16, 32 and 64 bit signed and unsigned integers.
 * Also provides bool in C.
 *
 * Author: Kevin Spiteri
 * Copyright: Copyright (c) HOB Software 2011
 ******************************************************************************/

#ifndef HOB_HTCP_INT_01_H
#define HOB_HTCP_INT_01_H

#if __STDC_VERSION__ >= 199901L /* C99 */

#include <stdint.h>

#elif defined _MSC_VER

#if _MSC_VER >= 1600 /* Visual Studio 2010 */

#include <stdint.h>

#else /* _MSC_VER < 1600 */

typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;

typedef __int8 int8_t;
typedef __int16 int16_t;
typedef __int32 int32_t;
typedef __int64 int64_t;

#endif /* _MSC_VER < 1600 */

#else /* __STDC_VERSION__ < 199901L && !defined _MSC_VER */


#include <limits.h>


typedef unsigned char uint8_t;
typedef signed char int8_t;


#if SHRT_MAX == 32767

typedef unsigned short uint16_t;
typedef short int16_t;

#else /* SHRT_MAX != 32767 */

#if INT_MAX == 32767
typedef unsigned uint16_t;
typedef int int16_t;
#else /* INT_MAX != 32767 */
#error "cannot find 16-bit integer type"
#endif /* INT_MAX != 32767 */

#endif /* SHRT_MAX != 32767 */


#if INT_MAX == 2147483647

typedef unsigned uint32_t;
typedef int int32_t;

#else /* INT_MAX != 2147483647 */

#if LONG_MAX == 2147483647L
typedef unsigned long uint32_t;
typedef long int32_t;
#else /* LONG_MAX != 2147483647L */
#error "cannot find 32-bit integer type"
#endif /* LONG_MAX != 2147483647L */

#endif /* INT_MAX != 2147483647 */


#if LONG_MAX == 9223372036854775807L

typedef unsigned long uint64_t;
typedef long int64_t;

#else /* LONG_MAX != 9223372036854775807L */

#if defined LLONG_MAX && LLONG_MAX == 9223372036854775807LL
typedef unsigned long long uint64_t;
typedef long long int64_t;
#else /* !defined LLONG_MAX || LLONG_MAX != 9223372036854775807LL */
#error "cannot find 64-bit integer type"
#endif /* !defined LLONG_MAX || LLONG_MAX != 9223372036854775807LL */

#endif /* LONG_MAX != 9223372036854775807L */


#endif /* __STDC_VERSION__ < 199901L && !defined _MSC_VER */


#ifndef __cplusplus

#define bool unsigned char
#define false 0
#define true (!false)

#endif /* !__cplusplus */

#endif /* HOB_HTCP_INT_01_H */
