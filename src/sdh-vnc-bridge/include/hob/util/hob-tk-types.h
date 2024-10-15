#ifndef TYPES_H_
#define TYPES_H_


#include <hob/util/hob-tk-arch.h>

#if defined(WIN32) || defined(_WINDOWS)
#define HOB_WINDOWS	1
#endif

#if (defined(HOB_LINUX) || defined(HOB_MACOSX) || defined(HOB_FREEBSD)) && !defined(HOB_UNIX)
#define HOB_UNIX        1
#endif

#if !defined(HOB_WINDOWS) && !defined(HOB_UNIX)
#error "Unspecified OS"
#endif

#ifdef _MSC_VER
typedef __int8  int8_t;
typedef unsigned __int8  uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
typedef __int64 int64_t;
//typedef unsigned int uint;
#elif defined(HOB_HPUX)
#include <sys/types.h>
#else
#include <stdint.h>
//typedef unsigned int uint;
#endif
typedef unsigned char byte_t;

#define NAMESPACE1(a) namespace a {
#define NAMESPACE2(a, b) namespace a { namespace b {
#define ENDNAMESPACE1() }
#define ENDNAMESPACE2() } }

#define NOTHROW() throw()
#define THROWSX(a) throw a
#define THROWS(a) throw(a)
#define THROWS2(a, b) throw(a, b)
#define THROWS_NOTHING() NOTHROW()

#define HOB_PAD_INTEGER(val, align) (((val) + (align-1))&(~(align-1)))

#ifdef _MSC_VER
#define __NOINLINE __declspec(noinline)
#define __FLATTEN
#define __ALWAYSINLINE __forceinline
#define __ALIGN(x) __declspec(align(x))
#define __ALIGNOF(x) __alignof(x)
#else
#define __NOINLINE __attribute__((noinline))
#define __FLATTEN __attribute__((flatten))
#define __ALWAYSINLINE  __attribute__((always_inline))
#define __ALIGN(x) __attribute__((aligned (x)))
#define __ALIGNOF(x) __alignof(x)
#define _FARQ
#endif

#ifdef _MSC_VER
#pragma warning ( disable : 4127 )
#pragma warning ( disable : 4201 )
#pragma warning ( disable : 4290 )
#endif

#ifdef HOB_WINDOWS
#include <windows.h>
#include <tchar.h>
#undef min
#undef max
#else
typedef char TCHAR;
#define _tcslen(x) strlen(x)
#endif

#ifndef FALSE
#define FALSE     0
#endif
#ifndef TRUE
#define TRUE      1
#endif

#define LITERAL_INT64(x)	x##LL
#define LITERAL_UINT64(x)	x##ULL

//#define OFFSETOF(st, m) ((size_t)(&((st *)0)->m))
#define OFFSETOF(st, m) offsetof(st, m)

#define SIZE_OF_MEMBER(cls, member) sizeof( ((cls*)1)->member )

#endif /*TYPES_H_*/
