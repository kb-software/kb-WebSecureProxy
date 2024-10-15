/************************************************************************************************************************************/
/*																						*/
/*	hob/util/arch.h																			*/
/*																						*/
/* Defines macros to check target architecture at compile time.												*/
/*																						*/
/*																						*/
/*																						*/
/*																						*/
/*	HOB_X86																				*/
/*	HOB_X86_64																				*/
/*	HOB_ITANIUM																				*/
/*																						*/
/*																						*/
/* @autor Dmitri Yufa																			*/
/* @date 10.06.2011																			*/
/*																						*/
/************************************************************************************************************************************/

#if !defined(__HOB_UTIL_ARCH_H__)
#define __HOB_UTIL_ARCH_H__


#if defined(_MSC_VER)
#define HOB_MICROSOFT_COMPILER _MSC_VER
#elif defined(__GNUC__)
#define HOB_GCC_COMPILER (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#endif


#define HOB_X86				0
#define HOB_X86_64			0
#define HOB_IA64				0


/* Microsoft Compiler */
#if defined(HOB_MICROSOFT_COMPILER)

#if defined(_M_IX86)		/* x86 */
#undef HOB_X86
#define HOB_X86				1
#elif defined(_M_X64)		/* x86_64 */
#undef HOB_X86_64
#define HOB_X86_64			1
#elif defined(_M_IA64)		/* Itanium */
#undef HOB_IA64
#define HOB_IA64				1
#endif

/* GCC Compiler */
#elif defined(HOB_GCC_COMPILER)

#if defined(__i386__)		/* x86 */
#undef HOB_X86
#define HOB_X86				1
#elif defined(__x86_64__)	/* x86_64 */
#undef HOB_X86_64
#define HOB_X86_64			1
#elif defined(__ia64__)		/* Itanium */
#undef HOB_IA64
#define HOB_IA64				1
#elif defined(__ppc__)		/* PPC */
#undef HOB_PPC
#define HOB_PPC				1
#endif

#else

#pragma error Unkonwn compiler.

#endif


#if !HOB_X86 && !HOB_X86_64 && !HOB_IA64 && !HOB_PPC
#pragma error Unkonwn CPU arch.
#endif


#if !defined(HOB_TOOLKIT_SUPPORT_SSE2_DEFAULT)
#define HOB_TOOLKIT_SUPPORT_SSE2_DEFAULT					1
#endif


#if HOB_X86 || HOB_X86_64
#define HOB_TOOLKIT_SUPPORT_SSE2				HOB_TOOLKIT_SUPPORT_SSE2_DEFAULT
#else
#define HOB_TOOLKIT_SUPPORT_SSE2				0
#endif






#endif /* __HOB_UTIL_ARCH_H__ */
