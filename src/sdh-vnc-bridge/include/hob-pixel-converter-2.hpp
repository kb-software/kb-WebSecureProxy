/************************************************************************************************************************************/
/* This file is generated automatically. Do not edit. Ask Mr.Yufa for support.  		                                            */
/************************************************************************************************************************************/
/************************************************************************************************************************************/
/*																						                                            */
/*	hob/util/arch.h																			                                        */
/*																						                                            */
/* Defines macros to check target architecture at compile time.												                        */
/*																			                                                        */
/*																						                                            */
/*																						                                            */
/*																						                                            */
/*	HOB_X86																				                                            */
/*	HOB_X86_64																				                                        */
/*	HOB_ITANIUM																				                                        */
/*																						                                            */
/*																						                                            */
/* @autor Dmitri Yufa																			                                    */
/* @date 10.06.2011																			                                        */
/*																						                                            */
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
#ifndef TYPES_H_
#define TYPES_H_



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
// typedef __int8  int8_t;
// typedef unsigned __int8  uint8_t;
// typedef __int16 int16_t;
// typedef unsigned __int16 uint16_t;
// typedef __int32 int32_t;
// typedef unsigned __int32 uint32_t;
// typedef __int64 int64_t;
// typedef unsigned __int64 uint64_t;
// typedef __int64 int64_t;
// typedef unsigned int uint;
#elif defined(HOB_HPUX)
#include <sys/types.h>
#else
#include <stdint.h>
typedef unsigned int uint;
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
#else
#define __NOINLINE __attribute__((noinline))
#define __FLATTEN __attribute__((flatten))
#define __ALWAYSINLINE  __attribute__((always_inline))
#define __ALIGN(x) __attribute__((aligned (x)))
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


#endif /*TYPES_H_*/
/************************************************************************************************************************************/
/*																																	*/
/*	uncopyable.h 																													*/
/*																																	*/
/*																																	*/
/*																																	*/
/*																																	*/
/*																																	*/
/*																																	*/
/*	@autor Dmitri Yufa																												*/
/*	@date 01.07.2011																												*/
/*																																	*/
/************************************************************************************************************************************/

#if !defined(__HOB_UTIL_UNCOPYABLE_H__)
#define __HOB_UTIL_UNCOPYABLE_H__

namespace hob {
namespace util {

class c_uncopyable
{
private:
	c_uncopyable(const c_uncopyable&) {}
	c_uncopyable& operator=(const c_uncopyable&) {return *this;}
public:
	c_uncopyable() {}
};

} /*namespace util*/
} /*namespace hob*/

#endif /*__HOB_UTIL_UNCOPYABLE_H__*/
/****************************************************************************************************************************************/
/*																																		*/
/*	memory_provider_stack.hpp																											*/
/*																																		*/
/*																																		*/
/*																																		*/
/*																																		*/
/*  11.01.12 - Added std::nothrow version of m_allocate(). Default version of m_allocate() throws std::bad_alloc if fails.              */
/*																																		*/
/*																																		*/
/* @autor yufadi																														*/
/* @date  10.08.2011																													*/
/****************************************************************************************************************************************/


#if !defined(__HOB_MEMORY_MEMORY_PROViDER_STACK_HPP__)
#define __HOB_MEMORY_MEMORY_PROViDER_STACK_HPP__


#include <new>
namespace hob {
namespace memory {


template <unsigned UM_LENGTH>
class c_memory_provider_stack : hob::util::c_uncopyable
{
	unsigned char		byrc_buffer[UM_LENGTH];
	unsigned char * 	abyc_buffer;
	unsigned int		umc_available;

public:


	/**
	 *	We have only default constructor. Control how much to preallocate through template argument.
	 */
	c_memory_provider_stack() : abyc_buffer(byrc_buffer), umc_available(UM_LENGTH)
	{
	}



	/**
	 *	Memory Allocation
	 *
	 *	@param	unp_count			How much in bytes.
	 *	@param  std::nothrow        If you don't wanna get an exception.
	 *	@returns					A pointer to the newly allocated storage space. NULL if not successfull.
	 */
	void * m_allocate(std::size_t unp_count, const std::nothrow_t&) throw()
	{ 
		if (unp_count > umc_available)			// not enough memory
			return NULL;
		void * avol_return = abyc_buffer;
		umc_available -= unp_count;
		abyc_buffer += unp_count;
		return avol_return;
	}
	

	/**
     *  Memory Allocation
     *
     *  @param  unp_count           How much in bytes.
     *  @returns                    A pointer to the newly allocated storage space.
     *  @throws                     std::bad_alloc, if not successfull.
     */
    void * m_allocate(std::size_t unp_count)
    {
        if (unp_count > umc_available)          // not enough memory
            throw std::bad_alloc();
        void * avol_return = abyc_buffer;
        umc_available -= unp_count;
        abyc_buffer += unp_count;
        return avol_return;
    }

	void m_deallocate(void *avop_buffer) throw()
	{
		return;							// do nothing
	}
};

} /* namespace memory */
} /* namespace hob */

#endif /* __HOB_MEMORY_MEMORY_PROViDER_STACK_HPP__ */
/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  for_each.hpp                                                                                                                    */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*  @autor  Dmitri Yufa                                                                                                             */
/*  @date   27.01.2012                                                                                                              */
/*                                                                                                                                  */
/************************************************************************************************************************************/


#if !defined(__HOB_META_TYPE_LiST_HPP__)
#define __HOB_META_TYPE_LiST_HPP__


/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Type List Components.                                                                                                           */
/*                                                                                                                                  */
/************************************************************************************************************************************/

class NULL_CLASS {};

template <class V, class N>
struct c_node
{
    typedef V value_t;
    typedef N next_t;

    typedef V VALUE;
    typedef N NEXT;
};


#define TYPE_LIST0()\
NULL_CLASS

#define TYPE_LIST1(t1)\
c_node<t1, NULL_CLASS>

#define TYPE_LIST2(t1, t2)\
c_node<t1, c_node<t2, NULL_CLASS> >

#define TYPE_LIST3(t1, t2, t3)\
c_node<t1, c_node<t2, c_node<t3, NULL_CLASS> > >

#define TYPE_LIST4(t1, t2, t3, t4)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, NULL_CLASS> > > >

#define TYPE_LIST5(t1, t2, t3, t4, t5)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, NULL_CLASS> > > > >

#define TYPE_LIST6(t1, t2, t3, t4, t5, t6)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, c_node<t6, NULL_CLASS> > > > > >

#define TYPE_LIST7(t1, t2, t3, t4, t5, t6, t7)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, c_node<t6, c_node<t7, NULL_CLASS> > > > > > >

#define TYPE_LIST8(t1, t2, t3, t4, t5, t6, t7, t8)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, c_node<t6, c_node<t7, c_node<t8, NULL_CLASS> > > > > > > >

#define TYPE_LIST9(t1, t2, t3, t4, t5, t6, t7, t8, t9)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, c_node<t6, c_node<t7, c_node<t8, c_node<t9, NULL_CLASS> > > > > > > > >

#define TYPE_LIST10(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, c_node<t6, c_node<t7, c_node<t8, c_node<t9, c_node<t10, NULL_CLASS> > > > > > > > > >

#define TYPE_LIST11(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, c_node<t6, c_node<t7, c_node<t8, c_node<t9, c_node<t10, c_node<t11, NULL_CLASS> > > > > > > > > > >

#define TYPE_LIST12(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, c_node<t6, c_node<t7, c_node<t8, c_node<t9, c_node<t10, c_node<t11, c_node<t12,\
NULL_CLASS> > > > > > > > > > > >

#define TYPE_LIST13(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, c_node<t6, c_node<t7, c_node<t8, c_node<t9, c_node<t10, c_node<t11, c_node<t12,\
c_node<t13, NULL_CLASS> > > > > > > > > > > > >

#define TYPE_LIST14(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, c_node<t6, c_node<t7, c_node<t8, c_node<t9, c_node<t10, c_node<t11, c_node<t12,\
c_node<t13, c_node<t14, NULL_CLASS> > > > > > > > > > > > > >

#define TYPE_LIST15(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, c_node<t6, c_node<t7, c_node<t8, c_node<t9, c_node<t10, c_node<t11, c_node<t12,\
c_node<t13, c_node<t14, c_node<t15, NULL_CLASS> > > > > > > > > > > > > > >

#define TYPE_LIST16(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, c_node<t6, c_node<t7, c_node<t8, c_node<t9, c_node<t10, c_node<t11, c_node<t12,\
c_node<t13, c_node<t14, c_node<t15, c_node<t16, NULL_CLASS> > > > > > > > > > > > > > > >

#define TYPE_LIST17(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, t17)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, c_node<t6, c_node<t7, c_node<t8, c_node<t9, c_node<t10, c_node<t11, c_node<t12,\
c_node<t13, c_node<t14, c_node<t15, c_node<t16, c_node<t17, NULL_CLASS> > > > > > > > > > > > > > > > >

#define TYPE_LIST18(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, t17, t18)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, c_node<t6, c_node<t7, c_node<t8, c_node<t9, c_node<t10, c_node<t11, c_node<t12,\
c_node<t13, c_node<t14, c_node<t15, c_node<t16, c_node<t17, c_node<t18, NULL_CLASS> > > > > > > > > > > > > > > > > >

#define TYPE_LIST19(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, t17, t18, t19)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, c_node<t6, c_node<t7, c_node<t8, c_node<t9, c_node<t10, c_node<t11, c_node<t12,\
c_node<t13, c_node<t14, c_node<t15, c_node<t16, c_node<t17, c_node<t18, c_node<t19, NULL_CLASS> > > > > > > > > > > > > > > > > > >

#define TYPE_LIST20(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, t17, t18, t19, t20)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, c_node<t6, c_node<t7, c_node<t8, c_node<t9, c_node<t10, c_node<t11, c_node<t12,\
c_node<t13, c_node<t14, c_node<t15, c_node<t16, c_node<t17, c_node<t18, c_node<t19, c_node<t20, NULL_CLASS> > > > > > > > > > > > > > > > > > > >

#define TYPE_LIST21(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, t17, t18, t19, t20, t21)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, c_node<t6, c_node<t7, c_node<t8, c_node<t9, c_node<t10, c_node<t11, c_node<t12,\
c_node<t13, c_node<t14, c_node<t15, c_node<t16, c_node<t17, c_node<t18, c_node<t19, c_node<t20, c_node<t21, NULL_CLASS> > > > > > > > > > > > > > > > > > > > >

#define TYPE_LIST22(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, t17, t18, t19, t20, t21, t22)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, c_node<t6, c_node<t7, c_node<t8, c_node<t9, c_node<t10, c_node<t11, c_node<t12,\
c_node<t13, c_node<t14, c_node<t15, c_node<t16, c_node<t17, c_node<t18, c_node<t19, c_node<t20, c_node<t21, c_node<t22, NULL_CLASS> > > > > > > > > > > > > > > > > > > > > >

#define TYPE_LIST23(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, t17, t18, t19, t20, t21, t22, t23)\
c_node<t1, c_node<t2, c_node<t3, c_node<t4, c_node<t5, c_node<t6, c_node<t7, c_node<t8, c_node<t9, c_node<t10, c_node<t11, c_node<t12,\
c_node<t13, c_node<t14, c_node<t15, c_node<t16, c_node<t17, c_node<t18, c_node<t19, c_node<t20, c_node<t21, c_node<t22, c_node<t23, NULL_CLASS> > > > > > > > > > > > > > > > > > > > > > >




#define TYPE_PREPEND(t, l) c_node<t, l>





// just for fun
template <class T>
struct c_count {
    static const int IN_VALUE = c_count<typename T::NEXT>::IN_VALUE + 1;
};

template <>
struct c_count<NULL_CLASS> {
    static const int IN_VALUE = 0;
};


#endif  // __HOB_META_TYPE_LiST_HPP__
/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  for_each.hpp                                                                                                                    */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*  @autor  Dmitri Yufa                                                                                                             */
/*  @autor  Stefan Martin                                                                                                           */
/*  @date   27.01.2012                                                                                                              */
/*                                                                                                                                  */
/************************************************************************************************************************************/

#if !defined (__HOB_META_FOR_EACH_HPP__)
#define __HOB_META_FOR_EACH_HPP__


namespace hob {
namespace meta {

enum {

    IN_TRUE     = 1,
    IN_FALSE    = 2,
    IN_ASK      = 3,

};


template <template <int, class, class> class CLASS_CONTROL, class LISTS, class CLASS_USER = void>
struct c_for_each
{
    template <int LEVEL, class LIST_RESULT, class LIST_CURRENT, class LISTS_NEXT>
    struct c_next {
        static void next(CLASS_USER* adsp_userdata)
        {
            // current result
			typedef TYPE_PREPEND(typename LIST_CURRENT::VALUE, LIST_RESULT) current_result_t;

			// match class
			typedef typename CLASS_CONTROL<LEVEL, current_result_t, CLASS_USER>::c_match match_t;
            
			
            // ask for current result match
            if ((match_t::IN_VALUE == IN_TRUE) || ((match_t::IN_VALUE != IN_FALSE) && match_t::match(adsp_userdata)))
            {
                
				// action class
				typedef typename CLASS_CONTROL<LEVEL, current_result_t, CLASS_USER>::c_action action_t;

				// ask for action
                if ((action_t::IN_VALUE == IN_TRUE) || ((action_t::IN_VALUE != IN_FALSE) && action_t::action(adsp_userdata)))
                    return;
                
                
                // try next level
                c_next<LEVEL+1, current_result_t, typename LISTS_NEXT::VALUE, typename LISTS_NEXT::NEXT>::next(adsp_userdata);


				// abort class
				typedef typename CLASS_CONTROL<LEVEL, current_result_t, CLASS_USER>::c_abort abort_t;
				
				// ask for abort
                if ((abort_t::IN_VALUE == IN_TRUE) || ((abort_t::IN_VALUE != IN_FALSE) && abort_t::abort(adsp_userdata)))
                    return;
            }

            c_next<LEVEL, LIST_RESULT, typename LIST_CURRENT::NEXT, LISTS_NEXT>::next(adsp_userdata);
        }
    };


	
	// max depth
    template <int LEVEL, class LIST_RESULT, class LIST_CURRENT>
    struct c_next<LEVEL, LIST_RESULT, LIST_CURRENT, NULL_CLASS> {
        static void next(CLASS_USER* adsp_userdata)
        {
            // current result
			typedef TYPE_PREPEND(typename LIST_CURRENT::VALUE, LIST_RESULT) current_result_t;

			// match class
			typedef typename CLASS_CONTROL<LEVEL, current_result_t, CLASS_USER>::c_match match_t;
            
			
            // ask for current result match
            if ((match_t::IN_VALUE == IN_TRUE) || ((match_t::IN_VALUE != IN_FALSE) && match_t::match(adsp_userdata)))
            {
                
				// action class
				typedef typename CLASS_CONTROL<LEVEL, current_result_t, CLASS_USER>::c_action action_t;

				// ask for action
                if ((action_t::IN_VALUE == IN_TRUE) || ((action_t::IN_VALUE != IN_FALSE) && action_t::action(adsp_userdata)))
                    return;
                
                
                // no more levels


				// abort class
				typedef typename CLASS_CONTROL<LEVEL, current_result_t, CLASS_USER>::c_abort abort_t;
				
				// ask for abort
                if ((abort_t::IN_VALUE == IN_TRUE) || ((abort_t::IN_VALUE != IN_FALSE) && abort_t::abort(adsp_userdata)))
                    return;
            }

            c_next<LEVEL, LIST_RESULT, typename LIST_CURRENT::NEXT, NULL_CLASS>::next(adsp_userdata);
        }
    };




	// max level width
    template <int LEVEL, class LIST_RESULT, class LISTS_NEXT>
    struct c_next<LEVEL, LIST_RESULT, NULL_CLASS, LISTS_NEXT> {
        static void next(CLASS_USER*) {
        }
    };

    // max level width on max depth
    template <int LEVEL, class LIST_RESULT>
    struct c_next<LEVEL, LIST_RESULT, NULL_CLASS, NULL_CLASS> {
        static void next(CLASS_USER*) {
        }
    };


    // entry point
    static void run(CLASS_USER* adsp_userdata = NULL) {
        return c_next<0, NULL_CLASS, typename LISTS::VALUE, typename LISTS::NEXT>::next(adsp_userdata);
    }
};

#endif // __HOB_META_FOR_EACH_HPP__

}   // namespace meta
}   // namespace hob


#if defined (HOB_MICROSOFT_COMPILER)
#define __HOB_INLINE    __forceinline
#pragma warning (disable : 4710)
#elif defined (HOB_GCC_COMPILER)
#define __HOB_INLINE    
#endif

/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  ass_converter_aux.hpp                                                                                                           */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*  Assembleable Color Converter - Type Tools                                                                                       */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*  Features:                                                                                                                       */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*  @autor  Dmitri Yufa                                                                                                             */
/*  @date   11.01.12                                                                                                                */
/*                                                                                                                                  */
/************************************************************************************************************************************/




#if !defined(__HOB_GRAPHiCS_ASS_COLOR_CONVERTER_TYPES_H__)
#define __HOB_GRAPHiCS_ASS_COLOR_CONVERTER_TYPES_H__


//#include <hob/util/types.h>
//#include <hob/util/uncopyable.h>
//#include <hob/memory/memory_provider_stack.hpp>
#include <memory>
#include <stdexcept>
#include <emmintrin.h>


//#include <hob/meta/type_list.hpp>
//#include <hob/meta/for_each.hpp>

namespace hob {
namespace graphics {
namespace cc {


    
/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Endianess Enum   																												*/
/*                                                                                                                                  */
/*  Specifies endianess of the color model.                                                                                         */
/*                                                                                                                                  */
/************************************************************************************************************************************/
enum en_endianess {
    ie_endian_undefined = 0,
	ie_endian_little    = 1,
	ie_endian_big       = 2,
#if HOB_LITTLE_ENDIAN
	ie_endian_default	= ie_endian_little
#elif HOB_BIG_ENDIAN
	ie_endian_default	= ie_endian_big
#endif
};



/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Use this type for the mask.                                                                                                     */
/*                                                                                                                                  */
/************************************************************************************************************************************/
    
typedef unsigned int mask_t;






/************************************************************************************************************************************/
/*  Finds first set bit in the mask starting at index (at compile time).                                                            */
/************************************************************************************************************************************/
template <unsigned MASK, int INDEX, int ISSET = MASK & (1 << INDEX)>
struct c_find_set_bit {
    static const unsigned int UN_VALUE = INDEX;
};
template <unsigned MASK, int INDEX>
struct c_find_set_bit<MASK, INDEX, 0> {
    static const unsigned int UN_VALUE = c_find_set_bit<MASK, (INDEX + 1)>::UN_VALUE;
};

/************************************************************************************************************************************/
/*  Finds first unset bit in the mask starting at index (at compile time).                                                          */
/************************************************************************************************************************************/
template <unsigned MASK, int INDEX, int ISSET = MASK & (1 << INDEX)>
struct c_find_unset_bit {
    static const unsigned int UN_VALUE = c_find_unset_bit<MASK, (INDEX + 1)>::UN_VALUE;
};
template <unsigned MASK, int INDEX>
struct c_find_unset_bit<MASK, INDEX, 0> {
    static const unsigned int UN_VALUE = INDEX;
};






/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  length(mask)    = set bits count                    (e.g. length(1) = 1, length(2) = 1, length(7) = 3)                          */
/*  offset(mask)    = index of the first set bit        (e.g. offset(1) = 0, offset(2) = 1, offset(7) = 0)                          */
/*  start(mask)     = offset+length                                                                                                 */
/*                                                                                                                                  */
/************************************************************************************************************************************/






/************************************************************************************************************************************/
/*  STATIC MASK STUFF                                                                                                               */
/************************************************************************************************************************************/

/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Create mask statically.                                                                                                         */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*  One more time for slowpokes like me:                                                                                            */
/*                                                                                                                                  */
/*      Start = Length + Offset                                                                                                     */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <unsigned int LENGTH, unsigned int OFFSET>
struct c_static_create_mask
{
    static const mask_t UN_VALUE = ((1 << LENGTH) - 1) << OFFSET;
};


/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Calculates mask information at compile time.                                                                                    */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <mask_t MASK>
struct c_static_mask_info
{
    static const unsigned int UN_OFFSET     = c_find_set_bit<MASK, 0>::UN_VALUE;
    static const unsigned int UN_START      = c_find_unset_bit<MASK, UN_OFFSET>::UN_VALUE;
    static const unsigned int UN_LENGTH     = (UN_START - UN_OFFSET);
};



/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Calculates auxiliary values for an reduce converter (at compile time).                                                          */
/*                                                                                                                                  */
/*  (for one color component)                                                                                                       */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template<bool BO_ASSERT> struct s_static_assert;
template<> struct s_static_assert<true> {
};

template <unsigned UN_LENGTH, unsigned UN_OFFSET, unsigned UN_START_1, unsigned UN_START_2>
struct c_dummy
{
    static const signed IN_OFFSET = ((int)UN_OFFSET) + ((int)UN_START_1 - (int)UN_START_2);
    typedef s_static_assert<IN_OFFSET >= 0> klaus_t;
    static const mask_t UN_MASK     = c_static_create_mask<UN_LENGTH, (unsigned)IN_OFFSET>::UN_VALUE;
};

template <mask_t MASK_SOURCE, mask_t MASK_TARGET>
class c_static_reduce_mask_aux
{
    typedef c_static_mask_info<MASK_SOURCE>    source_t;
    typedef c_static_mask_info<MASK_TARGET>    target_t;

public:
    //static const mask_t UN_MASK     = c_static_create_mask<target_t::UN_LENGTH, target_t::UN_OFFSET + (source_t::UN_START - target_t::UN_START)>::UN_VALUE;
    static const mask_t UN_MASK     = c_dummy<target_t::UN_LENGTH, target_t::UN_OFFSET, source_t::UN_START, target_t::UN_START>::UN_MASK;
    static const int    IN_SHIFT    = source_t::UN_START - target_t::UN_START;
    //c_dummy<UN_MASK> dsc_dummy;
};



/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Calculates auxiliary values for an extend converter (at compile time).                                                          */
/*                                                                                                                                  */
/*  (for one color component)                                                                                                       */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <mask_t MASK_SOURCE, mask_t MASK_TARGET>
class c_static_extend_mask_aux
{
    /********************************************************************************************************************************/
    /*                                                                                                                              */
    /*      x1 = pixel << in_shift_1                                                                                                */
    /*      x2 = ((x1 & un_mask_1) | ((x1 >> in_shift_2) & un_mask_2))                                                              */
    /*                                                                                                                              */
    /********************************************************************************************************************************/


    typedef c_static_mask_info<MASK_SOURCE>    source_t;
    typedef c_static_mask_info<MASK_TARGET>    target_t;

public:
    static const mask_t UN_MASK_1   = c_static_create_mask<source_t::UN_LENGTH, target_t::UN_START - source_t::UN_LENGTH>::UN_VALUE;
    static const mask_t UN_MASK_2   = c_static_create_mask<target_t::UN_LENGTH - source_t::UN_LENGTH, target_t::UN_OFFSET>::UN_VALUE;

    static const int IN_SHIFT_1     = target_t::UN_START - source_t::UN_START;
    static const int IN_SHIFT_2     = UN_MASK_2 ? source_t::UN_LENGTH : 0;
};






/************************************************************************************************************************************/
/*  DYNAMIC MASK STUFF                                                                                                              */
/************************************************************************************************************************************/

/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Create mask dynamically                                                                                                         */
/*                                                                                                                                  */
/************************************************************************************************************************************/
__HOB_INLINE static mask_t create_mask(unsigned int unp_length, unsigned int unp_offset) throw() {
    return ((1 << unp_length) - 1) << unp_offset;
}





/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Calculates mask information (at runtime).                                                                                       */
/*                                                                                                                                  */
/************************************************************************************************************************************/
struct c_dynamic_mask_info
{
    unsigned int unc_offset;
    unsigned int unc_start;
    unsigned int unc_length;

    c_dynamic_mask_info(mask_t unp_mask) throw() {
        unsigned int unl_index = 0;
        while ( (unp_mask & (1 << unl_index++)) == 0 );
        unc_offset = unl_index - 1;
        while ( (unp_mask & (1 << unl_index++)) != 0 );
        unc_start = unl_index - 1;
        unc_length = unc_start - unc_offset;
    }
};




/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Calculates auxiliary values for an reduce converter (at runtime).                                                               */
/*                                                                                                                                  */
/*  (for one color component)                                                                                                       */
/*                                                                                                                                  */
/************************************************************************************************************************************/
struct c_dynamic_reduce_mask_aux
{
    mask_t  unc_mask;
    int     inc_shift;

    c_dynamic_reduce_mask_aux(mask_t unp_mask_src, mask_t unp_mask_dst) throw()
    {
        c_dynamic_mask_info ds_src(unp_mask_src);
        c_dynamic_mask_info ds_dst(unp_mask_dst);
    
        unc_mask = create_mask(ds_dst.unc_length, ds_dst.unc_offset + (ds_src.unc_start - ds_dst.unc_start));
        inc_shift = ds_src.unc_start - ds_dst.unc_start;
    }
};


/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Reduce Mask Set for all components.                                                                                             */
/*                                                                                                                                  */
/************************************************************************************************************************************/
class c_dynamic_reduce_mask_set {

    c_dynamic_reduce_mask_aux   dsc_rmask_aux;
    c_dynamic_reduce_mask_aux   dsc_gmask_aux;
    c_dynamic_reduce_mask_aux   dsc_bmask_aux;

public:
    c_dynamic_reduce_mask_set(
        mask_t unp_src_r, mask_t unp_dst_r,
        mask_t unp_src_g, mask_t unp_dst_g,
        mask_t unp_src_b, mask_t unp_dst_b) throw()
        : dsc_rmask_aux(unp_src_r, unp_dst_r)
        , dsc_gmask_aux(unp_src_g, unp_dst_g)
        , dsc_bmask_aux(unp_src_b, unp_dst_b)
    {
    }

    mask_t rmask() const throw() { return dsc_rmask_aux.unc_mask; }
    int rshift() const throw() { return dsc_rmask_aux.inc_shift; }

    mask_t gmask() const throw() { return dsc_gmask_aux.unc_mask; }
    int gshift() const throw() { return dsc_gmask_aux.inc_shift; }

    mask_t bmask() const throw() { return dsc_bmask_aux.unc_mask; }
    int bshift() const throw() { return dsc_bmask_aux.inc_shift; }

#if defined (HOB_DEBUG)
    void show() const throw() {
        printf("rmask   = 0x%08x\n", dsc_rmask_aux.unc_mask);
        printf("rshift  = %d\n", dsc_rmask_aux.inc_shift);
        printf("gmask   = 0x%08x\n", dsc_gmask_aux.unc_mask);
        printf("gshift  = %d\n", dsc_gmask_aux.inc_shift);
        printf("bmask   = 0x%08x\n", dsc_bmask_aux.unc_mask);
        printf("bshift  = %d\n", dsc_bmask_aux.inc_shift);
    }
#endif
};




/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Calculates auxiliary values for an extend converter (at runtime).                                                               */
/*                                                                                                                                  */
/*  (for one color component)                                                                                                       */
/*                                                                                                                                  */
/************************************************************************************************************************************/
struct c_dynamic_extend_mask_aux
{

    /********************************************************************************************************************************/
    /*                                                                                                                              */
    /*      x1 = pixel << in_shift_1                                                                                                */
    /*      x2 = ((x1 & un_mask_1) | ((x1 >> in_shift_2) & un_mask_2))                                                              */
    /*                                                                                                                              */
    /********************************************************************************************************************************/

    mask_t unc_mask_1;
    mask_t unc_mask_2;
    int inc_shift_1;
    int inc_shift_2;

    c_dynamic_extend_mask_aux(mask_t unp_mask_src, mask_t unp_mask_dst) throw() {
        c_dynamic_mask_info ds_src(unp_mask_src);
        c_dynamic_mask_info ds_dst(unp_mask_dst);

        unc_mask_1 = create_mask(ds_src.unc_length, ds_dst.unc_start - ds_src.unc_length);
        inc_shift_1 = ds_dst.unc_start - ds_src.unc_start;
      
        unc_mask_2 = create_mask(ds_dst.unc_length - ds_src.unc_length, ds_dst.unc_offset);
        inc_shift_2 = unc_mask_2 ? ds_src.unc_length : 0;  // we would be shifting zero if the second mask equals zero
    }
};


/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Extend Mask Set for all components.                                                                                             */
/*                                                                                                                                  */
/************************************************************************************************************************************/

struct c_dynamic_extend_mask_set
{
    c_dynamic_extend_mask_aux   dsc_rmask_aux;
    c_dynamic_extend_mask_aux   dsc_gmask_aux;
    c_dynamic_extend_mask_aux   dsc_bmask_aux;

public:
    c_dynamic_extend_mask_set(
        mask_t unp_src_r, mask_t unp_dst_r,
        mask_t unp_src_g, mask_t unp_dst_g,
        mask_t unp_src_b, mask_t unp_dst_b) throw()
        : dsc_rmask_aux(unp_src_r, unp_dst_r)
        , dsc_gmask_aux(unp_src_g, unp_dst_g)
        , dsc_bmask_aux(unp_src_b, unp_dst_b)
    {
    }

    mask_t rmask1() const throw() { return dsc_rmask_aux.unc_mask_1; }
    mask_t rmask2() const throw() { return dsc_rmask_aux.unc_mask_2; }
    int rshift1() const throw() { return dsc_rmask_aux.inc_shift_1; }
    int rshift2() const throw() { return dsc_rmask_aux.inc_shift_2; }

    mask_t gmask1() const throw() { return dsc_gmask_aux.unc_mask_1; }
    mask_t gmask2() const throw() { return dsc_gmask_aux.unc_mask_2; }
    int gshift1() const throw() { return dsc_gmask_aux.inc_shift_1; }
    int gshift2() const throw() { return dsc_gmask_aux.inc_shift_2; }

    mask_t bmask1() const throw() { return dsc_bmask_aux.unc_mask_1; }
    mask_t bmask2() const throw() { return dsc_bmask_aux.unc_mask_2; }
    int bshift1() const throw() { return dsc_bmask_aux.inc_shift_1; }
    int bshift2() const throw() { return dsc_bmask_aux.inc_shift_2; }


#if defined (HOB_DEBUG)
    void show() const throw() {
        printf("rmask1  = 0x%08x\n", dsc_rmask_aux.unc_mask_1);
        printf("rshift1 = %d\n", dsc_rmask_aux.inc_shift_1);
        printf("rmask2  = 0x%08x\n", dsc_rmask_aux.unc_mask_2);
        printf("rshift2 = %d\n", dsc_rmask_aux.inc_shift_2);
        printf("gmask1  = 0x%08x\n", dsc_gmask_aux.unc_mask_1);
        printf("gshift1 = %d\n", dsc_gmask_aux.inc_shift_1);
        printf("gmask2  = 0x%08x\n", dsc_gmask_aux.unc_mask_2);
        printf("gshift2 = %d\n", dsc_gmask_aux.inc_shift_2);
        printf("bmask1  = 0x%08x\n", dsc_bmask_aux.unc_mask_1);
        printf("bshift1 = %d\n", dsc_bmask_aux.inc_shift_1);
        printf("bmask2  = 0x%08x\n", dsc_bmask_aux.unc_mask_2);
        printf("bshift2 = %d\n", dsc_bmask_aux.inc_shift_2);
    }
#endif

};















/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Big/Little endian swap functions.																							    */
/*                                                                                                                                  */
/************************************************************************************************************************************/

__HOB_INLINE static uint16_t m_swap_endian(uint16_t usp_value) throw() {
    return (usp_value >> 8) | (usp_value << 8);
}
__HOB_INLINE static uint32_t m_swap_endian(uint32_t ump_value) throw() {
    return (ump_value >> 24) | ((ump_value << 8) & 0x00ff0000) | ((ump_value >> 8) & 0x0000ff00) | (ump_value << 24);
}






/************************************************************************************************************************************/
/*  READ CLASSES.                                                                                                                   */
/************************************************************************************************************************************/

/*
 *  read 8
 */
struct c_read_8 {
	static const int IN_INCREMENT = 1;
	static bool is_aligned(const void *avop1) throw() {
		return true;
	}
	static uint32_t read_unaligned(const uint8_t *byrp_buffer) throw() {
		return *byrp_buffer;
	}
	static uint32_t read_aligned(const uint8_t *byrp_buffer) throw() {
		return *byrp_buffer;
	}
};


/*
 *  read 16 little endian
 *
 */
struct c_read_16_l {
	static const int IN_INCREMENT           = 2;
	static const int IN_INCREMENT_SSE2      = 16;
	static const int IN_ENDIANESS           = ie_endian_little;

	static bool is_aligned(const void *avop1) throw() {
		return ((size_t) avop1 & 0x1) == 0;
	}
    static bool is_aligned_sse2(const void *avop1) throw() {
		return ((size_t) avop1 & 0xf) == 0;
	}
	static uint32_t read_unaligned(const uint8_t *byrp_buffer) throw() {
		return (((uint32_t) byrp_buffer[0])) | (((uint32_t) byrp_buffer[1]) << 8);
	}
	static uint32_t read_aligned(const uint8_t *byrp_buffer) throw() {
#if defined(HOB_LITTLE_ENDIAN)
		return *((uint16_t *) byrp_buffer);
#elif defined(HOB_BIG_ENDIAN)
		return m_swap_endian(*((uint16_t *) byrp_buffer));
#endif
	}
    static void read_aligned(const uint8_t *byrp_buffer, __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
        mmp_target = _mm_load_si128 ((__m128i *) byrp_buffer);
#endif
    }
    static void read_unaligned(const uint8_t *byrp_buffer, __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
        mmp_target = _mm_loadu_si128 ((__m128i *) byrp_buffer);
#endif
    }
};


/*
 *  read 16 big endian
 */
struct c_read_16_b {
	static const int IN_INCREMENT           = 2;
	static const int IN_INCREMENT_SSE2      = 16;
	static const int IN_ENDIANESS           = ie_endian_big;

	static bool is_aligned(const void *avop1) throw() {
		return ((size_t) avop1 & 0x1) == 0;
	}
	static bool is_aligned_sse2(const void *avop1) throw() {
		return is_aligned(avop1);
	}
    static uint32_t read_unaligned(const uint8_t *byrp_buffer) throw() {
		return (((uint32_t) byrp_buffer[0]) << 8) | (((uint32_t) byrp_buffer[1]));
	}
	static uint32_t read_aligned(const uint8_t *byrp_buffer) throw() {
#if defined(HOB_LITTLE_ENDIAN)
		return m_swap_endian(*((uint16_t *) byrp_buffer));
#elif defined(HOB_BIG_ENDIAN)
		return *((uint16_t *) byrp_buffer);
#endif
	}
    static void read_aligned(const uint8_t *byrp_buffer, __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
        mmp_target = _mm_set_epi16 (
            (short) read_aligned(byrp_buffer + 14),
            (short) read_aligned(byrp_buffer + 12),
            (short) read_aligned(byrp_buffer + 10),
            (short) read_aligned(byrp_buffer + 8),
            (short) read_aligned(byrp_buffer + 6),
            (short) read_aligned(byrp_buffer + 4),
            (short) read_aligned(byrp_buffer + 2),
            (short) read_aligned(byrp_buffer) 
        );
#endif
    }
    static void read_unaligned(const uint8_t *byrp_buffer, __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
        mmp_target = _mm_set_epi16 (
            (short) read_unaligned(byrp_buffer + 14),
            (short) read_unaligned(byrp_buffer + 12),
            (short) read_unaligned(byrp_buffer + 10),
            (short) read_unaligned(byrp_buffer + 8),
            (short) read_unaligned(byrp_buffer + 6),
            (short) read_unaligned(byrp_buffer + 4),
            (short) read_unaligned(byrp_buffer + 2),
            (short) read_unaligned(byrp_buffer) 
        );
#endif
    }
};



/*
 *  read 24 little endian
 */
struct c_read_24_l {
	static const int IN_INCREMENT           = 3;
	static const int IN_INCREMENT_SSE2      = 12;
	static const int IN_ENDIANESS           = ie_endian_little;

	static bool is_aligned(const void *avop1) throw() {
		return false;
	}
    static bool is_aligned_sse2(const void *avop1) throw() {
		return is_aligned(avop1);
	}
	static uint32_t read_unaligned(const uint8_t *byrp_buffer) throw() {
		return (((uint32_t) byrp_buffer[0])) | (((uint32_t) byrp_buffer[1]) << 8) | (((uint32_t) byrp_buffer[2]) << 16);
	}
	static uint32_t read_aligned(const uint8_t *byrp_buffer) throw() {
		return (((uint32_t) byrp_buffer[0])) | (((uint32_t) byrp_buffer[1]) << 8) | (((uint32_t) byrp_buffer[2]) << 16);
	}
    static void read_aligned(const uint8_t *byrp_buffer, __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
        mmp_target = _mm_set_epi32 (
            (int) read_aligned(byrp_buffer + 9),
            (int) read_aligned(byrp_buffer + 6),
            (int) read_aligned(byrp_buffer + 3),
            (int) read_aligned(byrp_buffer) 
        );
#endif
    }
    static void read_unaligned(const uint8_t *byrp_buffer, __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
        mmp_target = _mm_set_epi32 (
            (int) read_unaligned(byrp_buffer + 9),
            (int) read_unaligned(byrp_buffer + 6),
            (int) read_unaligned(byrp_buffer + 3),
            (int) read_unaligned(byrp_buffer) 
        );
#endif
    }
};


/*
 *  read 24 big endian
 */
struct c_read_24_b {
	static const int IN_INCREMENT           = 3;
	static const int IN_INCREMENT_SSE2      = 12;
	static const int IN_ENDIANESS           = ie_endian_big;

	static bool is_aligned(const void *avop1) throw() {
		return false;
	}
    static bool is_aligned_sse2(const void *avop1) throw() {
		return is_aligned(avop1);
	}
	static uint32_t read_unaligned(const uint8_t *byrp_buffer) throw() {
		return (((uint32_t) byrp_buffer[0]) << 16) | (((uint32_t) byrp_buffer[1]) << 8) | (((uint32_t) byrp_buffer[2]));
	}
	static uint32_t read_aligned(const uint8_t *byrp_buffer) throw() {
		return (((uint32_t) byrp_buffer[0]) << 16) | (((uint32_t) byrp_buffer[1]) << 8) | (((uint32_t) byrp_buffer[2]));
	}
    static void read_aligned(const uint8_t *byrp_buffer, __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
        mmp_target = _mm_set_epi32 (
            (int) read_aligned(byrp_buffer + 9),
            (int) read_aligned(byrp_buffer + 6),
            (int) read_aligned(byrp_buffer + 3),
            (int) read_aligned(byrp_buffer) 
        );
#endif
    }
    static void read_unaligned(const uint8_t *byrp_buffer, __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
        mmp_target = _mm_set_epi32 (
            (int) read_unaligned(byrp_buffer + 9),
            (int) read_unaligned(byrp_buffer + 6),
            (int) read_unaligned(byrp_buffer + 3),
            (int) read_unaligned(byrp_buffer) 
        );
#endif
    }
};


/*
 *  read 32 little endian
 */
struct c_read_32_l {
	static const int IN_INCREMENT           = 4;
	static const int IN_INCREMENT_SSE2      = 16;
	static const int IN_ENDIANESS           = ie_endian_little;

	static bool is_aligned(const void *avop1) throw() {
		return ((size_t) avop1 & 0x3) == 0;
	}
    static bool is_aligned_sse2(const void *avop1) throw() {
		return ((size_t) avop1 & 0xf) == 0;
	}
	static uint32_t read_unaligned(const uint8_t *byrp_buffer) throw() {
		return (((uint32_t) byrp_buffer[0])) | (((uint32_t) byrp_buffer[1]) << 8) | (((uint32_t) byrp_buffer[2]) << 16) | (((uint32_t) byrp_buffer[3]) << 24);
	}
	static uint32_t read_aligned(const uint8_t *byrp_buffer) throw() {
#if defined(HOB_LITTLE_ENDIAN)
		return *((uint32_t *) byrp_buffer);
#elif defined(HOB_BIG_ENDIAN)
		return m_swap_endian(*((uint32_t *) byrp_buffer));
#endif
	}
    static void read_aligned(const uint8_t *byrp_buffer, __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
        mmp_target = _mm_load_si128 ((__m128i *) byrp_buffer);
#endif
    }
    static void read_unaligned(const uint8_t *byrp_buffer, __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
        mmp_target = _mm_loadu_si128 ((__m128i *) byrp_buffer);
#endif
    }
};

/*
 *  read 32 big endian
 */
struct c_read_32_b {
	static const int IN_INCREMENT           = 4;
	static const int IN_INCREMENT_SSE2      = 16;
	static const int IN_ENDIANESS           = ie_endian_big;

	static bool is_aligned(const void *avop1) throw() {
		return ((size_t) avop1 & 0x3) == 0;
	}
    static bool is_aligned_sse2(const void *avop1) throw() {
		return is_aligned(avop1);
	}
	static uint32_t read_unaligned(const uint8_t *byrp_buffer) throw() {
		return (((uint32_t) byrp_buffer[0]) << 24) | (((uint32_t) byrp_buffer[1]) << 16) | (((uint32_t) byrp_buffer[2]) << 8) | (((uint32_t) byrp_buffer[3]));
	}
	static uint32_t read_aligned(const uint8_t *byrp_buffer) throw() {
#if defined(HOB_LITTLE_ENDIAN)
		return m_swap_endian(*((uint32_t *) byrp_buffer));
#elif defined(HOB_BIG_ENDIAN)
		return *((uint32_t *) byrp_buffer);
#endif
	}
    static void read_aligned(const uint8_t *byrp_buffer, __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
        mmp_target = _mm_set_epi32 (
            (int) read_aligned(byrp_buffer + 12),
            (int) read_aligned(byrp_buffer + 8),
            (int) read_aligned(byrp_buffer + 4),
            (int) read_aligned(byrp_buffer) 
        );
#endif
    }
    static void read_unaligned(const uint8_t *byrp_buffer, __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
        mmp_target = _mm_set_epi32 (
            (int) read_unaligned(byrp_buffer + 12),
            (int) read_unaligned(byrp_buffer + 8),
            (int) read_unaligned(byrp_buffer + 4),
            (int) read_unaligned(byrp_buffer) 
        );
#endif
    }
};




/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Read Functions.                                                                                                                 */
/*                                                                                                                                  */
/************************************************************************************************************************************/
#if OLD_AND_WRONG
template <class reader_t, int IN_SIGN>
uint32_t read_unaligned(const uint8_t *&byrp_buffer) throw() {
	uint32_t uml_value = reader_t::read_unaligned(byrp_buffer);
	byrp_buffer += (reader_t::IN_INCREMENT * IN_SIGN);
	return uml_value;
}

template <class reader_t, int IN_SIGN>
uint32_t read_aligned(const uint8_t *&byrp_buffer) throw() {
	uint32_t uml_value = reader_t::read_aligned(byrp_buffer);
	byrp_buffer += (reader_t::IN_INCREMENT * IN_SIGN);
	return uml_value;
}
#else
template <class reader_t, int IN_SIGN>
struct c_reader_unaligned {
    static uint32_t read(const uint8_t *&byrp_buffer) throw() {
	    uint32_t uml_value = reader_t::read_unaligned(byrp_buffer);
	    byrp_buffer += (reader_t::IN_INCREMENT * IN_SIGN);
	    return uml_value;
    }
};
template <class reader_t, int IN_SIGN>
struct c_reader_aligned {
    static uint32_t read(const uint8_t *&byrp_buffer) throw() {
	    uint32_t uml_value = reader_t::read_aligned(byrp_buffer);
	    byrp_buffer += (reader_t::IN_INCREMENT * IN_SIGN);
	    return uml_value;
    }
};
#endif
template <class reader_t, int IN_SIGN>
void read_unaligned_sse2(const uint8_t *&byrp_buffer, __m128i& mmp_target) throw() {
    reader_t::read_unaligned(byrp_buffer, mmp_target);
    byrp_buffer += (reader_t::IN_INCREMENT_SSE2 * IN_SIGN);
}

template <class reader_t, int IN_SIGN>
void read_aligned_sse2(const uint8_t *&byrp_buffer, __m128i& mmp_target) throw() {
    reader_t::read_aligned(byrp_buffer, mmp_target);
    byrp_buffer += (reader_t::IN_INCREMENT_SSE2 * IN_SIGN);
}


/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Write Classes.                                                                                                                  */
/*                                                                                                                                  */
/************************************************************************************************************************************/

/*
 *  write 8
 */
struct c_write_8 {
	static const int IN_INCREMENT = 1;
	static bool is_aligned(const void *avop1) throw() {
		return true;
	}
	static void write_unaligned(uint8_t *byrp_buffer, uint32_t ump_value) throw() {
		*byrp_buffer = (uint8_t) ump_value;
	}
	static void write_aligned(uint8_t *byrp_buffer, uint32_t ump_value) throw() {
		*byrp_buffer = (uint8_t) ump_value;
	}
};

/*
 *  write 16 little endian
 */
struct c_write_16_l {
	static const int IN_INCREMENT           = 2;
	static const int IN_INCREMENT_SSE2      = 16;
	static const int IN_ENDIANESS           = ie_endian_little;

	static bool is_aligned(const void *avop1) throw() {
		return ((size_t) avop1 & 0x1) == 0;
	}
    static bool is_aligned_sse2(const void *avop1) throw() {
		return ((size_t) avop1 & 0xf) == 0;
	}
	static void write_unaligned(uint8_t *byrp_buffer, uint32_t ump_value) throw() {
		byrp_buffer[0] = (uint8_t) (ump_value);
		byrp_buffer[1] = (uint8_t) (ump_value >> 8);
	}
	static void write_aligned(uint8_t *byrp_buffer, uint32_t ump_value) throw() {
#if defined(HOB_LITTLE_ENDIAN)
		*((uint16_t *) byrp_buffer) = (uint16_t) ump_value;
#elif defined(HOB_BIG_ENDIAN)
		*((uint16_t *) byrp_buffer) = m_swap_endian((uint16_t) ump_value);
#endif
	}
    static void write_aligned(uint8_t *byrp_buffer, const __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
        _mm_store_si128 ((__m128i *) byrp_buffer, mmp_target);
#endif
    }
    static void write_unaligned(uint8_t *byrp_buffer, const __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
        _mm_storeu_si128 ((__m128i *) byrp_buffer, mmp_target);
#endif
    }
};

/*
 *  write 16 big endian
 */
struct c_write_16_b {
	static const int IN_INCREMENT           = 2;
	static const int IN_INCREMENT_SSE2      = 16;
	static const int IN_ENDIANESS           = ie_endian_big;

	static bool is_aligned(const void *avop1) throw() {
		return ((size_t) avop1 & 0x1) == 0;
	}
    static bool is_aligned_sse2(const void *avop1) throw() {
		return is_aligned(avop1);
	}
	static void write_unaligned(uint8_t *byrp_buffer, uint32_t ump_value) throw() {
		byrp_buffer[0] = (uint8_t) (ump_value >> 8);
		byrp_buffer[1] = (uint8_t) (ump_value);
	}
	static void write_aligned(uint8_t *byrp_buffer, uint32_t ump_value) throw() {
#if defined(HOB_LITTLE_ENDIAN)
		*((uint16_t *) byrp_buffer) = m_swap_endian((uint16_t) ump_value);
#elif defined(HOB_BIG_ENDIAN)
		*((uint16_t *) byrp_buffer) = (uint16_t) ump_value;
#endif
	}
    static void write_aligned(uint8_t *byrp_buffer, const __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
#if defined(_MSC_VER)
        __declspec(align(16)) uint16_t usrl_buffer[8];
#elif defined(__GNUC__)
        uint16_t usrl_buffer[8] __attribute__ ((aligned (16)));
#endif
        _mm_store_si128 ((__m128i *) usrl_buffer, mmp_target);

        write_aligned(byrp_buffer,      usrl_buffer[0]);
        write_aligned(byrp_buffer + 2,  usrl_buffer[1]);
        write_aligned(byrp_buffer + 4,  usrl_buffer[2]);
        write_aligned(byrp_buffer + 6,  usrl_buffer[3]);
        write_aligned(byrp_buffer + 8,  usrl_buffer[4]);
        write_aligned(byrp_buffer + 10, usrl_buffer[5]);
        write_aligned(byrp_buffer + 12, usrl_buffer[6]);
        write_aligned(byrp_buffer + 14, usrl_buffer[7]);
#endif
    }
    static void write_unaligned(uint8_t *byrp_buffer, const __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
        #if defined(_MSC_VER)
        __declspec(align(16)) uint16_t usrl_buffer[8];
#elif defined(__GNUC__)
        uint16_t usrl_buffer[8] __attribute__ ((aligned (16)));
#endif
        _mm_store_si128 ((__m128i *) usrl_buffer, mmp_target);

        write_unaligned(byrp_buffer,      usrl_buffer[0]);
        write_unaligned(byrp_buffer + 2,  usrl_buffer[1]);
        write_unaligned(byrp_buffer + 4,  usrl_buffer[2]);
        write_unaligned(byrp_buffer + 6,  usrl_buffer[3]);
        write_unaligned(byrp_buffer + 8,  usrl_buffer[4]);
        write_unaligned(byrp_buffer + 10, usrl_buffer[5]);
        write_unaligned(byrp_buffer + 12, usrl_buffer[6]);
        write_unaligned(byrp_buffer + 14, usrl_buffer[7]);
#endif
    }
};

/*
 *  write 24 little endian
 */
struct c_write_24_l {
	static const int IN_INCREMENT           = 3;
	static const int IN_INCREMENT_SSE2      = 12;
	static const int IN_ENDIANESS           = ie_endian_little;

	static bool is_aligned(const void *avop1) throw() {
		return false;
	}
    static bool is_aligned_sse2(const void *avop1) throw() {
		return is_aligned(avop1);
	}
	static void write_unaligned(uint8_t *byrp_buffer, uint32_t ump_value) throw() {
		byrp_buffer[0] = (uint8_t) (ump_value);
		byrp_buffer[1] = (uint8_t) (ump_value >> 8);
		byrp_buffer[2] = (uint8_t) (ump_value >> 16);
	}
	static void write_aligned(uint8_t *byrp_buffer, uint32_t ump_value) throw() {
		byrp_buffer[0] = (uint8_t) (ump_value);
		byrp_buffer[1] = (uint8_t) (ump_value >> 8);
		byrp_buffer[2] = (uint8_t) (ump_value >> 16);
	}
    static void write_aligned(uint8_t *byrp_buffer, const __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
#if defined(_MSC_VER)
        __declspec(align(16)) uint32_t umrl_buffer[4];
#elif defined(__GNUC__)
        uint32_t umrl_buffer[4] __attribute__ ((aligned (16)));
#endif
        _mm_store_si128 ((__m128i *) umrl_buffer, mmp_target);

        write_aligned(byrp_buffer,      umrl_buffer[0]);
        write_aligned(byrp_buffer + 3,  umrl_buffer[1]);
        write_aligned(byrp_buffer + 6,  umrl_buffer[2]);
        write_aligned(byrp_buffer + 9,  umrl_buffer[3]);
#endif
    }
    static void write_unaligned(uint8_t *byrp_buffer, const __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
#if defined(_MSC_VER)
        __declspec(align(16)) uint32_t umrl_buffer[4];
#elif defined(__GNUC__)
        uint32_t umrl_buffer[4] __attribute__ ((aligned (16)));
#endif
        _mm_store_si128 ((__m128i *) umrl_buffer, mmp_target);

        write_unaligned(byrp_buffer,      umrl_buffer[0]);
        write_unaligned(byrp_buffer + 3,  umrl_buffer[1]);
        write_unaligned(byrp_buffer + 6,  umrl_buffer[2]);
        write_unaligned(byrp_buffer + 9,  umrl_buffer[3]);
#endif
    }
};


/*
 *  write 24 big endian
 */
struct c_write_24_b {
	static const int IN_INCREMENT           = 3;
	static const int IN_INCREMENT_SSE2      = 12;
	static const int IN_ENDIANESS           = ie_endian_big;

	static bool is_aligned(const void *avop1) throw() {
		return false;
	}
    static bool is_aligned_sse2(const void *avop1) throw() {
		return is_aligned(avop1);
	}
	static void write_unaligned(uint8_t *byrp_buffer, uint32_t ump_value) throw() {
		byrp_buffer[0] = (uint8_t) (ump_value >> 16);
		byrp_buffer[1] = (uint8_t) (ump_value >> 8);
		byrp_buffer[2] = (uint8_t) (ump_value);
	}
	static void write_aligned(uint8_t *byrp_buffer, uint32_t ump_value) throw() {
		byrp_buffer[0] = (uint8_t) (ump_value >> 16);
		byrp_buffer[1] = (uint8_t) (ump_value >> 8);
		byrp_buffer[2] = (uint8_t) (ump_value);
	}
    static void write_aligned(uint8_t *byrp_buffer, const __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
#if defined(_MSC_VER)
        __declspec(align(16)) uint32_t umrl_buffer[4];
#elif defined(__GNUC__)
        uint32_t umrl_buffer[4] __attribute__ ((aligned (16)));
#endif
        _mm_store_si128 ((__m128i *) umrl_buffer, mmp_target);

        write_aligned(byrp_buffer,      umrl_buffer[0]);
        write_aligned(byrp_buffer + 3,  umrl_buffer[1]);
        write_aligned(byrp_buffer + 6,  umrl_buffer[2]);
        write_aligned(byrp_buffer + 9,  umrl_buffer[3]);
#endif
    }
    static void write_unaligned(uint8_t *byrp_buffer, const __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
#if defined(_MSC_VER)
        __declspec(align(16)) uint32_t umrl_buffer[4];
#elif defined(__GNUC__)
        uint32_t umrl_buffer[4] __attribute__ ((aligned (16)));
#endif
        _mm_store_si128 ((__m128i *) umrl_buffer, mmp_target);

        write_unaligned(byrp_buffer,      umrl_buffer[0]);
        write_unaligned(byrp_buffer + 3,  umrl_buffer[1]);
        write_unaligned(byrp_buffer + 6,  umrl_buffer[2]);
        write_unaligned(byrp_buffer + 9,  umrl_buffer[3]);
#endif
    }
};

/*
 *  write 32 little endian
 */
struct c_write_32_l {
	static const int IN_INCREMENT           = 4;
	static const int IN_INCREMENT_SSE2      = 16;
	static const int IN_ENDIANESS           = ie_endian_little;

	static bool is_aligned(const void *avop1) throw() {
		return ((size_t) avop1 & 0x3) == 0;
	}
    static bool is_aligned_sse2(const void *avop1) throw() {
		return ((size_t) avop1 & 0xf) == 0;
	}
	static void write_unaligned(uint8_t *byrp_buffer, uint32_t ump_value) throw() {
		byrp_buffer[0] = (uint8_t) (ump_value);
		byrp_buffer[1] = (uint8_t) (ump_value >> 8);
		byrp_buffer[2] = (uint8_t) (ump_value >> 16);
		byrp_buffer[3] = (uint8_t) (ump_value >> 24);
	}
	static void write_aligned(uint8_t *byrp_buffer, uint32_t ump_value) throw() {
#if defined(HOB_LITTLE_ENDIAN)
		*((uint32_t *) byrp_buffer) = (uint32_t) ump_value;
#elif defined(HOB_BIG_ENDIAN)
		*((uint32_t *) byrp_buffer) = m_swap_endian((uint32_t) ump_value);
#endif
	}
    static void write_aligned(uint8_t *byrp_buffer, const __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
        _mm_store_si128 ((__m128i *) byrp_buffer, mmp_target);
#endif
    }
    static void write_unaligned(uint8_t *byrp_buffer, const __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
        _mm_storeu_si128 ((__m128i *) byrp_buffer, mmp_target);
#endif
    }
};

/*
 *  write 32 big endian
 */
struct c_write_32_b {
	static const int IN_INCREMENT           = 4;
	static const int IN_INCREMENT_SSE2      = 16;
	static const int IN_ENDIANESS           = ie_endian_big;

	static bool is_aligned(const void *avop1) throw() {
		return ((size_t) avop1 & 0x3) == 0;
	}
    static bool is_aligned_sse2(const void *avop1) throw() {
		return is_aligned(avop1);
	}
	static void write_unaligned(uint8_t *byrp_buffer, uint32_t ump_value) throw() {
		byrp_buffer[0] = (uint8_t) (ump_value >> 24);
		byrp_buffer[1] = (uint8_t) (ump_value >> 16);
		byrp_buffer[2] = (uint8_t) (ump_value >> 8);
		byrp_buffer[3] = (uint8_t) (ump_value);
	}
	static void write_aligned(uint8_t *byrp_buffer, uint32_t ump_value) throw() {
#if defined(HOB_LITTLE_ENDIAN)
		*((uint32_t *) byrp_buffer) = m_swap_endian((uint32_t) ump_value);
#elif defined(HOB_BIG_ENDIAN)
		*((uint32_t *) byrp_buffer) = (uint32_t) ump_value;
#endif
	}
	static void write_aligned(uint8_t *byrp_buffer, const __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
#if defined(_MSC_VER)
        __declspec(align(16)) uint32_t umrl_buffer[4];
#elif defined(__GNUC__)
        uint32_t umrl_buffer[4] __attribute__ ((aligned (16)));
#endif
        _mm_store_si128 ((__m128i *) umrl_buffer, mmp_target);

        write_aligned(byrp_buffer,      umrl_buffer[0]);
        write_aligned(byrp_buffer + 4,  umrl_buffer[1]);
        write_aligned(byrp_buffer + 8,  umrl_buffer[2]);
        write_aligned(byrp_buffer + 12, umrl_buffer[3]);
#endif
    }
    static void write_unaligned(uint8_t *byrp_buffer, const __m128i& mmp_target) throw() {
#if defined(HOB_LITTLE_ENDIAN)
#if defined(_MSC_VER)
        __declspec(align(16)) uint32_t umrl_buffer[4];
#elif defined(__GNUC__)
        uint32_t umrl_buffer[4] __attribute__ ((aligned (16)));
#endif
        _mm_store_si128 ((__m128i *) umrl_buffer, mmp_target);

        write_aligned(byrp_buffer,      umrl_buffer[0]);
        write_aligned(byrp_buffer + 4,  umrl_buffer[1]);
        write_aligned(byrp_buffer + 8,  umrl_buffer[2]);
        write_aligned(byrp_buffer + 12, umrl_buffer[3]);
#endif
    }
};




/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Write Functions.                                                                                                                */
/*                                                                                                                                  */
/************************************************************************************************************************************/
#if OLD_AND_WRONG
template <class writer_t, int IN_SIGN>
void write_unaligned(uint8_t *&byrp_buffer, uint32_t ump_value) throw() {
	writer_t::write_unaligned(byrp_buffer, ump_value);
	byrp_buffer += (writer_t::IN_INCREMENT * IN_SIGN);
}

template <class writer_t, int IN_SIGN>
void write_aligned(uint8_t *&byrp_buffer, uint32_t ump_value) throw() {
	writer_t::write_aligned(byrp_buffer, ump_value);
	byrp_buffer += (writer_t::IN_INCREMENT * IN_SIGN);
}
#else
template <class writer_t, int IN_SIGN>
struct c_writer_unaligned {
    static void write(uint8_t *&byrp_buffer, uint32_t ump_value) throw() {
	    writer_t::write_unaligned(byrp_buffer, ump_value);
	    byrp_buffer += (writer_t::IN_INCREMENT * IN_SIGN);
    }
};
template <class writer_t, int IN_SIGN>
struct c_writer_aligned {
    static void write(uint8_t *&byrp_buffer, uint32_t ump_value) throw() {
	    writer_t::write_aligned(byrp_buffer, ump_value);
	    byrp_buffer += (writer_t::IN_INCREMENT * IN_SIGN);
    }
};
#endif

template <class writer_t, int IN_SIGN>
void write_unaligned_sse2(uint8_t *&byrp_buffer, const __m128i& ump_value) throw() {
    writer_t::write_unaligned(byrp_buffer, ump_value);
    byrp_buffer += (writer_t::IN_INCREMENT_SSE2 * IN_SIGN);
}

template <class writer_t, int IN_SIGN>
void write_aligned_sse2(uint8_t *&byrp_buffer, const __m128i& ump_value) throw() {
    writer_t::write_aligned(byrp_buffer, ump_value);
    byrp_buffer += (writer_t::IN_INCREMENT_SSE2 * IN_SIGN);
}



/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Reader and Writer selector classes.                                                                                             */
/*                                                                                                                                  */
/************************************************************************************************************************************/


template <unsigned PIXEL_SIZE, int ENDIANESS>
struct c_select_reader;


template <int ENDIANESS>
struct c_select_reader <8, ENDIANESS> {
    typedef c_read_8 reader_t;
};
template <>
struct c_select_reader <16, 2> {            // ie_endian_big
    typedef c_read_16_b reader_t;
};
template <>
struct c_select_reader <16, 1> {            // ie_endian_little
    typedef c_read_16_l reader_t;
};
template <>
struct c_select_reader <24, 2> {            // ie_endian_big
    typedef c_read_24_b reader_t;
};
template <>
struct c_select_reader <24, 1> {            // ie_endian_little
    typedef c_read_24_l reader_t;
};
template <>
struct c_select_reader <32, 2> {            // ie_endian_big
    typedef c_read_32_b reader_t;
};
template <>
struct c_select_reader <32, 1> {            // ie_endian_little
    typedef c_read_32_l reader_t;
};




template <unsigned PIXEL_SIZE, int ENDIANESS>
struct c_select_writer;

template <int ENDIANESS>
struct c_select_writer <8, ENDIANESS> {
    typedef c_write_8 writer_t;
};
template <>
struct c_select_writer <16, 2> {            // ie_endian_big
    typedef c_write_16_b writer_t;
};
template <>
struct c_select_writer <16, 1> {            // ie_endian_little
    typedef c_write_16_l writer_t;
};
template <>
struct c_select_writer <24, 2> {            // ie_endian_big
    typedef c_write_24_b writer_t;
};
template <>
struct c_select_writer <24, 1> {            // ie_endian_little
    typedef c_write_24_l writer_t;
};
template <>
struct c_select_writer <32, 2> {            // ie_endian_big
    typedef c_write_32_b writer_t;
};
template <>
struct c_select_writer <32, 1> {            // ie_endian_little
    typedef c_write_32_l writer_t;
};



/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Shifter for integral data types.                                                                                                */
/*                                                                                                                                  */
/************************************************************************************************************************************/

template <int QUANTITY, int DIRECTION = ((QUANTITY > 0) ? (+1) : ((QUANTITY < 0) ? (-1) : (0)))>
struct c_shift;

template <int QUANTITY>
struct c_shift <QUANTITY, +1> {
    template <class T> static T left(const T& ttp_value) throw() {
        return (ttp_value << QUANTITY);
    }
    template <class T> static T right(const T& ttp_value) throw() {
        return (ttp_value >> QUANTITY);
    }
};
template <int QUANTITY>
struct c_shift <QUANTITY, -1> {
    template <class T> static T left(const T& ttp_value) throw() {
        return (ttp_value >> -QUANTITY);
    }
    template <class T> static T right(const T& ttp_value) throw() {
        return (ttp_value << -QUANTITY);
    }
};
template <int QUANTITY>
struct c_shift <QUANTITY, 0> {
    template <class T> static T left(const T& ttp_value) throw() {
        return ttp_value;
    }
    template <class T> static T right(const T& ttp_value) throw() {
        return ttp_value;
    }
};


/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Shifter for Monster Dynamic Converters.                                                                                         */
/*                                                                                                                                  */
/************************************************************************************************************************************/

enum {
    ie_shift_left,
    ie_shift_right
};


struct c_shifter_left {
    static bool supports(int inp_direction, int inp_value) throw() {
        switch (inp_direction) {
        case ie_shift_left:
            return (inp_value > 0);
        case ie_shift_right:
            return (inp_value < 0);
        }
        return false;
    }
    template <class T> static T shift(const T& ttp_value, int inp_shift) throw() {
        return (ttp_value << inp_shift);
    }
};

struct c_shifter_right {
    static bool supports(int inp_direction, int inp_value) throw() {
        switch (inp_direction) {
        case ie_shift_left:
            return (inp_value < 0);
        case ie_shift_right:
            return (inp_value > 0);
        }
        return false;
    }
    template <class T> static T shift(const T& ttp_value, int inp_shift) throw() {
        return (ttp_value >> inp_shift);
    }
};

struct c_shifter_zero {
    static bool supports(int inp_direction, int inp_value) throw() {
        return (inp_value == 0);
    }
    template <class T> static T shift(const T& ttp_value, int inp_shift) throw() {
        return ttp_value;
    }
};



/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Dynamic (runtime) shift functions for integer values.                                                                           */
/*                                                                                                                                  */
/************************************************************************************************************************************/

__HOB_INLINE static uint32_t shift_left(uint32_t ump_value, int inp_count) throw() {
	return ((inp_count >= 0) ? (ump_value << inp_count) : (ump_value >> (-inp_count)));
}
__HOB_INLINE static uint32_t shift_right(uint32_t ump_value, int inp_count) throw() {
	return ((inp_count >= 0) ? (ump_value >> inp_count) : (ump_value << (-inp_count)));
}








/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Shifter for vector data types.                                                                                                  */
/*                                                                                                                                  */
/************************************************************************************************************************************/
// TODO: implement...






} // cc
} // graphics
} // hob


#endif //__HOB_GRAPHiCS_ASS_COLOR_CONVERTER_TYPES_H__
/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  ass_converter.hpp                                                                                                               */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*  Assembleable Color Converter - Declaration                                                                                      */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*  Features:                                                                                                                       */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*  @autor  Dmitri Yufa                                                                                                             */
/*  @date   10.01.12                                                                                                                */
/*                                                                                                                                  */
/************************************************************************************************************************************/





#if !defined(__HOB_GRAPHiCS_ASS_COLOR_CONVERTER_H__)
#define __HOB_GRAPHiCS_ASS_COLOR_CONVERTER_H__

#define HOB_CC_PREFER_SPEED




#define NAME(x) typeid(x).name()


//#include "ass_converter_aux.hpp"


#if defined(HOB_MICROSOFT_COMPILER)
#define __DYFUNCTION__  __FUNCTION__
#elif defined(HOB_GCC_COMPILER)
#define __DYFUNCTION__  __PRETTY_FUNCTION__
#endif


/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Check Endianess																										            */
/*                                                                                                                                  */
/*  Specifies native endianess. User have to define one of following preprocessor constans: HOB_BIG_ENDIAN or HOB_LITTLE_ENDIAN.    */
/*                                                                                                                                  */
/************************************************************************************************************************************/
#if !defined(HOB_BIG_ENDIAN) && !defined(HOB_LITTLE_ENDIAN)
#error Please define endianess with HOB_BIG_ENDIAN or HOB_LITTLE_ENDIAN
#endif




namespace hob {
namespace graphics {
namespace cc {






/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Colormap Class																											        */
/*                                                                                                                                  */
/*  Defines a colormap. A colormap always contains 256 items, i.e. maximum colormap item count to avoid dynamic memory allocation.  */
/*                                                                                                                                  */
/************************************************************************************************************************************/
class c_colormap
{
private:
	unsigned	    unc_count;
	uint32_t        umrc_table[256];

public:
	c_colormap(const uint32_t umrp_table[], unsigned unp_count) throw() : unc_count(unp_count) {
		std::copy(umrp_table, umrp_table + unp_count, umrc_table);
	}
    // copy constructor
	c_colormap(const c_colormap& dsp_colormap) throw() : unc_count(dsp_colormap.unc_count) {
		std::copy(dsp_colormap.umrc_table, dsp_colormap.umrc_table + dsp_colormap.unc_count, umrc_table);
	}
	const uint32_t& get_pixel(unsigned unp_index) const throw() {
		return umrc_table[unp_index];
	}
	const uint32_t& operator[](unsigned unp_index) const throw() {
		return umrc_table[unp_index];
	}
	uint32_t& operator[](unsigned unp_index) throw() {
		return umrc_table[unp_index];
	}
	const uint32_t* table() const throw() {
		return umrc_table;
	}
	uint32_t count() const throw() {
		return unc_count;
	}

    template <class MEMORY_PROVIDER>
    static void destroy(c_colormap* adsp_colormap, MEMORY_PROVIDER& rdsp_memory_provider) {
        adsp_colormap->~c_colormap();
        rdsp_memory_provider.m_deallocate(adsp_colormap);
    }
};

inline bool operator ==(const c_colormap& rdsp_left, const c_colormap& rdsp_right) throw()
{
	if (rdsp_left.count() != rdsp_right.count())
		return false;
	unsigned unl_length = rdsp_left.count();
	for (unsigned unl_index = 0; unl_index < unl_length; unl_index++)
		if (rdsp_left[unl_index] != rdsp_right[unl_index])
			return false;
	return true;
}






/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Color Model Class																												*/
/*                                                                                                                                  */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*                                                                                                                                  */
/************************************************************************************************************************************/
class c_colormodel : hob::util::c_uncopyable    // any copy only with custom memory provider
{
	unsigned			unc_bpp;
	unsigned			unc_pixel_size;
	mask_t			    umc_rmask;
	mask_t			    umc_gmask;
	mask_t			    umc_bmask;
	mask_t			    umc_amask;
	mask_t			    umc_pixel_mask;
	en_endianess		iec_endianess;

	c_colormap *        adsc_colormap;
	c_colormodel *      adsc_colormodel_map;



public:
	// creates a colormodel without a colormap
	c_colormodel(
		unsigned		unp_bpp,
		unsigned		unp_pixel_size,
		mask_t		    ump_rmask,
		mask_t		    ump_gmask,
		mask_t		    ump_bmask,
		mask_t		    ump_amask,
		en_endianess	iep_endianess)  throw()
		: unc_bpp(unp_bpp)
		, unc_pixel_size(unp_pixel_size)
		, umc_rmask(ump_rmask)
		, umc_gmask(ump_gmask)
		, umc_bmask(ump_bmask)
		, umc_amask(ump_amask)
		, umc_pixel_mask(umc_rmask | umc_gmask | umc_bmask | umc_amask)
		, iec_endianess(iep_endianess)
		, adsc_colormap(NULL)
		, adsc_colormodel_map(NULL)
	{
	}


	// creates a colormodel with a colormap and its colormodel
	template <class MEMORY_PROVIDER>                                            // this is a memory_provider class
	c_colormodel(
		unsigned				unp_bpp,
		unsigned				unp_pixel_size,
        en_endianess	        iep_endianess,
		const c_colormap&		rdsp_colormap,
		const c_colormodel&		rdsp_colormodel_map,
		MEMORY_PROVIDER&	    rdsp_memprov)
		: unc_bpp(unp_bpp)
		, unc_pixel_size(unp_pixel_size)
		, umc_rmask(0x0)
		, umc_gmask(0x0)
		, umc_bmask(0x0)
		, umc_amask(0x0)
		, umc_pixel_mask(0x0)
		, iec_endianess(iep_endianess)
		, adsc_colormap(new (rdsp_memprov.m_allocate(sizeof(c_colormap))) c_colormap(rdsp_colormap))
		, adsc_colormodel_map(new (rdsp_memprov.m_allocate(sizeof(c_colormodel))) c_colormodel(rdsp_colormodel_map, rdsp_memprov))
	{
        // check if custom allocator returns NULL instead of throwing exception
        if (adsc_colormap == NULL)
            throw std::bad_alloc();
        if (adsc_colormodel_map == NULL)
            throw std::bad_alloc();
	}

	// "copy"-constructor with allocator
	template <class MEMORY_PROVIDER>                                            // this is a memory_provider class
	c_colormodel(const c_colormodel& dsp_other, MEMORY_PROVIDER& ds_memprov)
		: unc_bpp(dsp_other.unc_bpp)
		, unc_pixel_size(dsp_other.unc_pixel_size)
		, umc_rmask(dsp_other.umc_rmask)
		, umc_gmask(dsp_other.umc_gmask)
		, umc_bmask(dsp_other.umc_bmask)
		, umc_amask(dsp_other.umc_amask)
		, umc_pixel_mask(dsp_other.umc_pixel_mask)
		, iec_endianess(dsp_other.iec_endianess)
		, adsc_colormap( (dsp_other.adsc_colormap == NULL) ? NULL : new (ds_memprov.m_allocate(sizeof(c_colormap))) c_colormap(*dsp_other.adsc_colormap) )
		, adsc_colormodel_map( (dsp_other.adsc_colormodel_map == NULL) ? NULL : new (ds_memprov.m_allocate(sizeof(c_colormodel))) c_colormodel(*dsp_other.adsc_colormodel_map, ds_memprov) )
	{
        // check if custom allocator returns NULL instead of throwing exception
        if (dsp_other.adsc_colormap != NULL && adsc_colormap == NULL)
            throw std::bad_alloc();
        if (dsp_other.adsc_colormodel_map != NULL && adsc_colormodel_map == NULL)
            throw std::bad_alloc();
	}

    template <class MEMORY_PROVIDER>
    void destruct(MEMORY_PROVIDER& rdsp_memory_provider) {
        if (this->adsc_colormap != NULL) {
            c_colormap::destroy(this->adsc_colormap, rdsp_memory_provider);
        }
        if (this->adsc_colormodel_map != NULL) {
            c_colormodel::destroy(this->adsc_colormodel_map, rdsp_memory_provider);
        }
        this->~c_colormodel();
    }

    template <class MEMORY_PROVIDER>
    static void destroy(c_colormodel *adsp_colormodel, MEMORY_PROVIDER& rdsp_memory_provider)
    {
        if (adsp_colormodel == NULL)
            return;
        adsp_colormodel->destruct(rdsp_memory_provider);
        rdsp_memory_provider.m_deallocate(adsp_colormodel);
    }

public:
	

	bool is_index_based() const throw() {
		return (adsc_colormap != NULL);
	}

	bool is_little_endian() const throw() {
		return (iec_endianess == ie_endian_little);
	}
	bool is_big_endian() const throw() {
		return (iec_endianess == ie_endian_big);
	}


	bool is_15_bit() const throw() {
		return ((umc_rmask == 0x7c00)	&& (umc_gmask == 0x03e0) && (umc_bmask == 0x001f));
	}
	bool is_16_bit() const throw() {
		return ((umc_rmask == 0xf800) && (umc_gmask == 0x07e0) && (umc_bmask == 0x001f));
	}
	bool is_24_bit() const throw() {
		return ((unc_bpp == 24) && (umc_rmask == 0xff0000) && (umc_gmask == 0x00ff00) && (umc_bmask == 0x0000ff));
	}
	bool is_32_bit() const throw() {
		return ((unc_bpp == 32) && (umc_rmask == 0xff0000) && (umc_gmask == 0x00ff00) && (umc_bmask == 0x0000ff) /*&& (umc_amask == 0xff000000)*/);
	}

	bool is_16_15_bit() const throw() {
		return ((unc_bpp == 15) && (unc_pixel_size == 16) && (umc_rmask == 0x7c00) && (umc_gmask == 0x03e0) && (umc_bmask == 0x001f));
	}
	bool is_16_16_bit() const throw() {
		return ((unc_bpp == 16) && (unc_pixel_size == 16) && (umc_rmask == 0xf800) && (umc_gmask == 0x07e0) && (umc_bmask == 0x001f));
	}
	bool is_24_24_bit() const throw() {
		return ((unc_bpp == 24) && (unc_pixel_size == 24) && (umc_rmask == 0xff0000) && (umc_gmask == 0x00ff00) && (umc_bmask == 0x0000ff));
	}
	bool is_32_24_bit() const throw() {
		return ((unc_bpp == 24) && (unc_pixel_size == 32) && (umc_rmask == 0xff0000) && (umc_gmask == 0x00ff00) && (umc_bmask == 0x0000ff) && (umc_amask == 0));
	}
	bool is_32_32_bit() const throw() {
		return ((unc_bpp == 32) && (unc_pixel_size == 32) && (umc_rmask == 0xff0000) && (umc_gmask == 0x00ff00) && (umc_bmask == 0x0000ff) && (umc_amask == 0xff000000));
	}



	unsigned bpp()				const throw() { return unc_bpp; }
	unsigned color_depth()		const throw() { return unc_bpp; }
	unsigned pixel_size()		const throw() { return unc_pixel_size; }
	mask_t pixel_mask()		    const throw() { return umc_pixel_mask; }
	en_endianess endianess()	const throw() { return iec_endianess; }
	
	mask_t rmask() const throw() { return umc_rmask; }
	mask_t gmask() const throw() { return umc_gmask; }
	mask_t bmask() const throw() { return umc_bmask; }
	mask_t amask() const throw() { return umc_amask; }

	mask_t mask_red()		const throw() { return umc_rmask; }
	mask_t mask_green()	    const throw() { return umc_gmask; }
	mask_t mask_blue()	    const throw() { return umc_bmask; }
	mask_t mask_alpha() 	const throw() { return umc_amask; }

	const c_colormap * colormap() const throw() { return adsc_colormap; }
	const c_colormodel * colormodel_map() const throw() { return adsc_colormodel_map; }



	bool total_equals(const c_colormodel& ds_colormodel) const throw() {
		return (
			(endianess() == ds_colormodel.endianess())	&&
			(pixel_size() == ds_colormodel.pixel_size())	&&
			(bpp()   == ds_colormodel.bpp())   &&
			(rmask() == ds_colormodel.rmask()) &&
			(gmask() == ds_colormodel.gmask()) &&
			(bmask() == ds_colormodel.bmask())
		);
	}

	bool total_equals_but_endianess(const c_colormodel& ds_colormodel) const throw() {
		return (
			(endianess() != ds_colormodel.endianess())	&&
			(pixel_size() == ds_colormodel.pixel_size())	&&
			(bpp()   == ds_colormodel.bpp())		&&
			(rmask() == ds_colormodel.rmask())		&&
			(gmask() == ds_colormodel.gmask())		&&
			(bmask() == ds_colormodel.bmask())
		);
	}


#if defined(HOB_DEBUG)
    void show() const throw() {
        printf("bpp         = %d\n", bpp());
        printf("pixel_size  = %d\n", pixel_size());
        printf("rmask       = 0x%08x\n", rmask());
        printf("gmask       = 0x%08x\n", gmask());
        printf("bmask       = 0x%08x\n", bmask());
        printf("amask       = 0x%08x\n", amask());
        printf("endianess   = %s\n", (endianess() == ie_endian_big) ? "ie_endian_big" : "ie_endian_little");
    }
#endif

};




/************************************************************************************************************************************/
/*  CLASSES FOR OPTIMIZED SUPPORT                                                                                                   */
/************************************************************************************************************************************/

/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Direct Static Color Model Template Class                                                                                        */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <unsigned BPP, unsigned PIXEL_SIZE, mask_t RMASK, mask_t GMASK, mask_t BMASK, mask_t AMASK, int ENDIANESS>
struct c_statcon_colormodel_direct
{
    static const unsigned   UN_BPP              = BPP;
    static const unsigned   UN_PIXEL_SIZE       = PIXEL_SIZE;
    static const mask_t     UN_RMASK            = RMASK;
    static const mask_t     UN_GMASK            = GMASK;
    static const mask_t     UN_BMASK            = BMASK;
    static const mask_t     UN_AMASK            = AMASK;
    static const int        IN_ENDIANESS        = ENDIANESS;

    static bool equals_but_endianess(const c_colormodel& rdsp_other) throw() {
        return (
            UN_BPP == rdsp_other.color_depth()         &&
            UN_PIXEL_SIZE == rdsp_other.pixel_size()   &&
            UN_RMASK == rdsp_other.rmask()     &&
            UN_GMASK == rdsp_other.gmask()     &&
            UN_BMASK == rdsp_other.bmask()     &&
            UN_AMASK == rdsp_other.amask()
        );
    }

    static bool equals(const c_colormodel& rdsp_other) throw() {
        return (
            UN_BPP == rdsp_other.color_depth()          &&
            UN_PIXEL_SIZE == rdsp_other.pixel_size()    &&
            UN_RMASK == rdsp_other.rmask()      &&
            UN_GMASK == rdsp_other.gmask()      &&
            UN_BMASK == rdsp_other.bmask()      &&
            UN_AMASK == rdsp_other.amask()      &&
            IN_ENDIANESS == rdsp_other.endianess()
        );
    }

#if defined(HOB_DEBUG)
    static void show() throw() {
        printf("bpp         = %d\n", UN_BPP);
        printf("pixel_size  = %d\n", UN_PIXEL_SIZE);
        printf("rmask       = 0x%08x\n", UN_RMASK);
        printf("gmask       = 0x%08x\n", UN_GMASK);
        printf("bmask       = 0x%08x\n", UN_BMASK);
        printf("amask       = 0x%08x\n", UN_AMASK);
        printf("endianess   = %s\n", (IN_ENDIANESS == ie_endian_big) ? "ie_endian_big" : "ie_endian_little");
    }
#endif
};






/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Static Configuration Flags                                                                                                      */
/*                                                                                                                                  */
/*                                                                                                                                  */
/************************************************************************************************************************************/
enum {
    IN_STATIC_ALU           = 0x1,
    IN_STATIC_SSE2          = 0x2,
    IN_DYNAMIC_REDUCE       = 0x10,
    IN_DYNAMIC_EXTEND       = 0x20,
    IN_TABLE_1              = 0x40,
    IN_TABLE_2              = 0x80,
    IN_TABLE_4              = 0x100,
    IN_TABLE_8              = 0x200,

    IN_DYNAMIC_SOURCE_ENDIAN_LITTLE    = 0x1000,
    IN_DYNAMIC_SOURCE_ENDIAN_BIG       = 0x2000,
    IN_DYNAMIC_TARGET_ENDIAN_LITTLE    = 0x4000,
    IN_DYNAMIC_TARGET_ENDIAN_BIG       = 0x8000,

    IN_NO_EQUAL    = 0x10000,             // converter will be NOT choosen
    IN_NO_SAME     = 0x20000,             // converter will be NOT choosen
};
enum {
    IN_READ_ALIGNED            = 0x1,
    IN_READ_UNALIGNED          = 0x2,
    IN_READ_AUTO               = 0x3,
    IN_WRITE_ALIGNED           = 0x1,
    IN_WRITE_UNALIGNED         = 0x2,
    IN_WRITE_AUTO              = 0x3,
};


/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Static Configuration Class                                                                                                      */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <class LIST_SOURCE, class LIST_TARGET, class ALGORITHM, int TYPE_FLAGS, int READER_FLAGS, int WRITER_FLAGS>
struct c_static_config
{
    typedef LIST_SOURCE         list_source_t;
    typedef LIST_TARGET         list_target_t;
    typedef ALGORITHM           algorithm_t;

    static const int  IN_TYPE_FLAGS         = TYPE_FLAGS;
    static const int  IN_READER_FLAGS       = READER_FLAGS;
    static const int  IN_WRITER_FLAGS       = WRITER_FLAGS;
};

// error case: WRITER_FLAGS not set
template <class LIST_SOURCE, class LIST_TARGET, class ALGORITHM, int TYPE_FLAGS, int READER_FLAGS>
struct c_static_config<LIST_SOURCE, LIST_TARGET, ALGORITHM, TYPE_FLAGS, READER_FLAGS, 0>;
// error case: READER_FLAGS not set
template <class LIST_SOURCE, class LIST_TARGET, class ALGORITHM, int TYPE_FLAGS, int WRITER_FLAGS>
struct c_static_config<LIST_SOURCE, LIST_TARGET, ALGORITHM, TYPE_FLAGS, 0, WRITER_FLAGS>;


/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Converter Interface                                                                                                             */
/*                                                                                                                                  */
/*                                                                                                                                  */
/************************************************************************************************************************************/

struct c_converter : hob::util::c_uncopyable
{
    virtual bool changes() const {
        return true;
    }

    virtual uint32_t convert(
        uint32_t        ump_pixel           /* input pixel value */
    ) const                                                                         throw() = 0;

    virtual void convert(
        const void *    byrp_input,         /* input buffer */
        void *          byrp_output,        /* output buffer */
        int             unp_count           /* number of pixels to convert */
    ) const                                                                         throw() = 0;

    virtual void convert(
        void *          byrp_inoutput,      /* input-output buffer */
        int             unp_count           /* number of pixels to convert */
    ) const                                                                         throw() = 0;

    virtual void convert_area(
        const void *    byrp_input,             /* input buffer */
        int             inp_source_scanline,    /* size of source scanline in bytes */
        void *          byrp_output,            /* output buffer */
        int             inp_target_scanline,    /* size of target scanline in bytes */
        int             unp_width,              /* width of area */
        int             unp_height              /* height of area */
    ) const                                                                         throw() = 0;


    virtual ~c_converter() throw() {}                   /* don't forget! */


#if defined(HOB_DEBUG)
    virtual const char * name() const throw() {
        return typeid(*this).name();
    }
    virtual void show() const throw() {
    }
#endif
};






/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Converter Manager                                                                                                               */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <class CONVERTER>
class c_converter_manager
{
    typedef typename CONVERTER::reader_t        reader_t;
    typedef typename CONVERTER::writer_t        writer_t;

    typedef typename CONVERTER::algorithm_t     algorithm_t;

    static const int IN_READER_FLAGS = CONVERTER::IN_READER_FLAGS;
    static const int IN_WRITER_FLAGS = CONVERTER::IN_WRITER_FLAGS;



    /************************************************************************************************************************************/
    /*                                                                                                                                  */
    /*      Iterators direction sign.                                                                                                   */
    /*                                                                                                                                  */
    /*  1 if the source pixel is greater then or equal to the destination pixel     - buffer move forward                               */
    /* -1 if the source pixel is less then the destination pixel                    - buffer move backward                              */
    /*                                                                                                                                  */
    /************************************************************************************************************************************/
    template <class READER, class WRITER> struct c_sign {
        static const signed int IN_SIGN = ((READER::IN_INCREMENT >= WRITER::IN_INCREMENT) ? (+1) : (-1));
    };


    static const int IN_SIGN = c_sign<reader_t, writer_t>::IN_SIGN;


    
    static const int IN_ALIGNED             = 1;
    static const int IN_UNALIGNED           = 2;
    static const int IN_AUTO                = 3;
    

    

public:
    template <int READER_TYPE, int WRITER_TYPE>
    static void convert(const CONVERTER& rdsp_converter, const void *avop_input, void *avop_output, int inp_count, bool bop_read_aligned, bool bop_write_aligned)
    {
        const uint8_t * byrl_input_start;
        const uint8_t * byrl_input_end;
        uint8_t *       byrl_output_start;

        /* foreward */
        if (IN_SIGN > 0) {
            byrl_input_start    = (const uint8_t *) avop_input;
            byrl_input_end      = (const uint8_t *) avop_input + (inp_count * reader_t::IN_INCREMENT);
            byrl_output_start   = (uint8_t *) avop_output;
        }
        /* backward */
        else {
            byrl_input_start    = (const uint8_t *) avop_input + (inp_count - 1) * reader_t::IN_INCREMENT;
            byrl_input_end      = (const uint8_t *) avop_input - reader_t::IN_INCREMENT;
            byrl_output_start   = (uint8_t *) avop_output + (inp_count - 1) * writer_t::IN_INCREMENT;
        }

        if ((READER_TYPE == IN_ALIGNED) || ((READER_TYPE != IN_UNALIGNED) && bop_read_aligned)) {
            if ((WRITER_TYPE == IN_ALIGNED) || ((WRITER_TYPE != IN_UNALIGNED) && bop_write_aligned))
                while (byrl_input_start != byrl_input_end)
                    /* read aligned + write aligned */                    
                    c_writer_aligned<writer_t, IN_SIGN>::write(byrl_output_start, rdsp_converter.convert_pixel(c_reader_aligned<reader_t, IN_SIGN>::read(byrl_input_start)));
            else
                while (byrl_input_start != byrl_input_end)
                    /* read aligned + write unaligned */
                    c_writer_unaligned<writer_t, IN_SIGN>::write(byrl_output_start, rdsp_converter.convert_pixel(c_reader_aligned<reader_t, IN_SIGN>::read(byrl_input_start)));
        } else {
            if ((WRITER_TYPE == IN_ALIGNED) || ((WRITER_TYPE != IN_UNALIGNED) && bop_write_aligned))
                while (byrl_input_start != byrl_input_end)
                    /* read unaligned + write aligned */
                    c_writer_aligned<writer_t, IN_SIGN>::write(byrl_output_start, rdsp_converter.convert_pixel(c_reader_unaligned<reader_t, IN_SIGN>::read(byrl_input_start)));
            else
                while (byrl_input_start != byrl_input_end)
                    /* read unaligned + write unaligned */
                    c_writer_unaligned<writer_t, IN_SIGN>::write(byrl_output_start, rdsp_converter.convert_pixel(c_reader_unaligned<reader_t, IN_SIGN>::read(byrl_input_start)));
        }
    }


    static void convert(const CONVERTER& rdsp_converter, const void *avop_input, void *avop_output, int inp_count)
    {
        bool bol_reader_aligned = (IN_READER_FLAGS == IN_ALIGNED) || ((IN_READER_FLAGS != IN_UNALIGNED) && reader_t::is_aligned(avop_input));
        bool bol_writer_aligned = (IN_WRITER_FLAGS == IN_ALIGNED) || ((IN_WRITER_FLAGS != IN_UNALIGNED) && writer_t::is_aligned(avop_output));

        convert<IN_READER_FLAGS, IN_WRITER_FLAGS>(rdsp_converter, avop_input, avop_output, inp_count, bol_reader_aligned, bol_writer_aligned);
    }




    static void convert(const CONVERTER& rdsp_converter, const void *avop_input, int inp_source_scanline, void *avop_output, int inp_target_scanline, int inp_width, int inp_height)
    {

    }

};



enum {      // These flags have nothing to do with en_endianess flags. You have nothing to do with them too. They are private.
    IN_ENDIAN_UNDEFINED     = 0x0,
    IN_ENDIAN_LITTLE        = 0x1,
    IN_ENDIAN_BIG           = 0x2,
};




/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Converter Manager for Tables                                                                                                    */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*                                                                                                                                  */
/************************************************************************************************************************************/


template <class CONVERTER>
class c_from_table_manager
{
    typedef typename CONVERTER::reader_t        reader_t;
    typedef typename CONVERTER::writer_t        writer_t;
    typedef typename CONVERTER::algorithm_t     algorithm_t;

    enum {
        IN_COLOR_DEPTH          = CONVERTER::IN_COLOR_DEPTH,
        IN_READER_ENDIANESS     = CONVERTER::IN_READER_ENDIANESS,
        IN_WRITER_FLAGS         = CONVERTER::IN_WRITER_FLAGS,

        IN_ALIGNED             = 1,
        IN_UNALIGNED           = 2,
        IN_AUTO                = 3,
    };



    template <int COLOR_DEPTH>
    struct c_colors_per_byte {
        enum {
            IN_VALUE = 8 / COLOR_DEPTH
        };
    };


    template <class READER, class WRITER, int COLOR_DEPTH, int ENDIANGESS_READER>
    struct c_convert;

    // 1-bit, little endian
    template <class READER, class WRITER>
    struct c_convert<READER, WRITER, 1, IN_ENDIAN_LITTLE> {
        static void convert(const CONVERTER& rdsp_converter, const uint8_t *&byrp_input, uint8_t *&byrp_output) {
            uint8_t utl_input = (uint8_t) READER::read(byrp_input);
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 0) & 0x01));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 1) & 0x01));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 2) & 0x01));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 3) & 0x01));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 4) & 0x01));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 5) & 0x01));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 6) & 0x01));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 7) & 0x01));
        }
        static void convert(const CONVERTER& rdsp_converter, const uint8_t *&byrp_input, uint8_t *&byrp_output, int inp_count) {
            uint8_t utl_input = (uint8_t) READER::read(byrp_input);
            for (int inl_index = 0; inl_index < inp_count; inl_index++) {
                WRITER::write(byrp_output, rdsp_converter.convert_pixel(utl_input & 0x01));
                utl_input >>= 1;
            }
        }
    };


    // 1-bit, big endian
    template <class READER, class WRITER>
    struct c_convert<READER, WRITER, 1, IN_ENDIAN_BIG> {
        struct c_msb {
            uint8_t utc_bits : 7;
            uint8_t utc_msb  : 1;
        };
        static void convert(const CONVERTER& rdsp_converter, const uint8_t *&byrp_input, uint8_t *&byrp_output) {
            uint8_t utl_input = (uint8_t) READER::read(byrp_input);
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((uint32_t) ((utl_input >> 7) & 0x01)));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((uint32_t) ((utl_input >> 6) & 0x01)));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((uint32_t) ((utl_input >> 5) & 0x01)));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((uint32_t) ((utl_input >> 4) & 0x01)));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((uint32_t) ((utl_input >> 3) & 0x01)));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((uint32_t) ((utl_input >> 2) & 0x01)));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((uint32_t) ((utl_input >> 1) & 0x01)));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((uint32_t) ((utl_input >> 0) & 0x01)));
        }
        static void convert(const CONVERTER& rdsp_converter, const uint8_t *&byrp_input, uint8_t *&byrp_output, int inp_count) {
            uint8_t utl_input = (uint8_t) READER::read(byrp_input);
            for (int inl_index = 0; inl_index < inp_count; inl_index++) {
                WRITER::write(byrp_output, rdsp_converter.convert_pixel(((c_msb *) &utl_input)->utc_msb));
                utl_input <<= 1;
            }
        }
    };

    // 2-bit, little endian
    template <class READER, class WRITER>
    struct c_convert<READER, WRITER, 2, IN_ENDIAN_LITTLE> {
        static void convert(const CONVERTER& rdsp_converter, const uint8_t *&byrp_input, uint8_t *&byrp_output) {
            uint8_t utl_input = (uint8_t) READER::read(byrp_input);
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 0) & 0x03));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 2) & 0x03));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 4) & 0x03));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 6) & 0x03));
        }
        static void convert(const CONVERTER& rdsp_converter, const uint8_t *&byrp_input, uint8_t *&byrp_output, int inp_count) {
            uint8_t utl_input = (uint8_t) READER::read(byrp_input);
            for (int inl_index = 0; inl_index < inp_count; inl_index++) {
                WRITER::write(byrp_output, rdsp_converter.convert_pixel(utl_input & 0x03));
                utl_input >>= 2;
            }
        }
    };
    // 2-bit, big endian
    template <class READER, class WRITER>
    struct c_convert<READER, WRITER, 2, IN_ENDIAN_BIG> {
        struct c_msb {
            uint8_t utc_bits : 6;
            uint8_t utc_msb  : 2;
        };
        static void convert(const CONVERTER& rdsp_converter, const uint8_t *&byrp_input, uint8_t *&byrp_output) {
            uint8_t utl_input = (uint8_t) READER::read(byrp_input);
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 6) & 0x03));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 4) & 0x03));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 2) & 0x03));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 0) & 0x03));
        }
        static void convert(const CONVERTER& rdsp_converter, const uint8_t *&byrp_input, uint8_t *&byrp_output, int inp_count) {
            uint8_t utl_input = (uint8_t) READER::read(byrp_input);
            for (int inl_index = 0; inl_index < inp_count; inl_index++) {
                WRITER::write(byrp_output, rdsp_converter.convert_pixel(((c_msb *) &utl_input)->utc_msb));
                utl_input <<= 2;
            }
        }
    };

    // 4-bit, little endian
    template <class READER, class WRITER>
    struct c_convert<READER, WRITER, 4, IN_ENDIAN_LITTLE> {
        static void convert(const CONVERTER& rdsp_converter, const uint8_t *&byrp_input, uint8_t *&byrp_output) {
            uint8_t utl_input = (uint8_t) READER::read(byrp_input);
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 0) & 0x0f));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 4) & 0x0f));
        }
        static void convert(const CONVERTER& rdsp_converter, const uint8_t *&byrp_input, uint8_t *&byrp_output, int inp_count) {
            uint8_t utl_input = (uint8_t) READER::read(byrp_input);
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 0) & 0x0f));
        }
    };

    // 4-bit, big endian
    template <class READER, class WRITER>
    struct c_convert<READER, WRITER, 4, IN_ENDIAN_BIG> {
        static void convert(const CONVERTER& rdsp_converter, const uint8_t *&byrp_input, uint8_t *&byrp_output) {
            uint8_t utl_input = (uint8_t) READER::read(byrp_input);
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((uint32_t) ((utl_input >> 4) & 0x0f)));
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((uint32_t) ((utl_input >> 0) & 0x0f)));
        }
        static void convert(const CONVERTER& rdsp_converter, const uint8_t *&byrp_input, uint8_t *&byrp_output, int) {
            uint8_t utl_input = (uint8_t) READER::read(byrp_input);
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((utl_input >> 4) & 0x0f));
        }
    };

    // 8-bit, no endian
    template <class READER, class WRITER, int ENDIANGESS_READER>
    struct c_convert<READER, WRITER, 8, ENDIANGESS_READER> {
        static void convert(const CONVERTER& rdsp_converter, const uint8_t *&byrp_input, uint8_t *&byrp_output) {
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((uint8_t) READER::read(byrp_input)));
        }
        static void convert(const CONVERTER& rdsp_converter, const uint8_t *&byrp_input, uint8_t *&byrp_output, int) {
            WRITER::write(byrp_output, rdsp_converter.convert_pixel((uint8_t) READER::read(byrp_input)));
        }
    };
    


public:
    template <int WRITER_TYPE>
    static void convert(const CONVERTER& rdsp_converter, const void *avop_input, void *avop_output, int inp_count, bool bop_read_aligned, bool bop_write_aligned)
    {
        const uint8_t * byrl_input_start;
        const uint8_t * byrl_input_end;
        uint8_t *       byrl_output_start;


        int inl_full = inp_count / c_colors_per_byte<IN_COLOR_DEPTH>::IN_VALUE;
        int inl_rest = inp_count & (c_colors_per_byte<IN_COLOR_DEPTH>::IN_VALUE - 1);


        byrl_input_start    = (const uint8_t *) avop_input;
        byrl_input_end      = (const uint8_t *) avop_input + (inl_full * reader_t::IN_INCREMENT);  // TODO: hier stimmt noch...
        byrl_output_start   = (uint8_t *) avop_output;


        typedef c_reader_aligned<reader_t, +1> local_reader_t;
        
        // write aligned
        if ((WRITER_TYPE == IN_ALIGNED) || ((WRITER_TYPE != IN_UNALIGNED) && bop_write_aligned))
        {
            typedef c_writer_aligned<writer_t, +1> local_writer_t;

            while (byrl_input_start != byrl_input_end)
                c_convert<local_reader_t, local_writer_t, IN_COLOR_DEPTH, IN_READER_ENDIANESS>::convert(rdsp_converter, byrl_input_start, byrl_output_start);
            if (inl_rest != 0)
                c_convert<local_reader_t, local_writer_t, IN_COLOR_DEPTH, IN_READER_ENDIANESS>::convert(rdsp_converter, byrl_input_start, byrl_output_start, inl_rest);
        }
        // write unaligned
        else
        {
            typedef c_writer_unaligned<writer_t, +1> local_writer_t;

            while (byrl_input_start != byrl_input_end)
                c_convert<local_reader_t, local_writer_t, IN_COLOR_DEPTH, IN_READER_ENDIANESS>::convert(rdsp_converter, byrl_input_start, byrl_output_start);
            if (inl_rest != 0)
                c_convert<local_reader_t, local_writer_t, IN_COLOR_DEPTH, IN_READER_ENDIANESS>::convert(rdsp_converter, byrl_input_start, byrl_output_start, inl_rest);
        }
    }

    static void convert(const CONVERTER& rdsp_converter, const void *avop_input, void *avop_output, int inp_count)
    {
        bool bol_reader_aligned = true;
        bool bol_writer_aligned = (IN_WRITER_FLAGS == IN_ALIGNED) || ((IN_WRITER_FLAGS != IN_UNALIGNED) && writer_t::is_aligned(avop_output));

        convert<IN_WRITER_FLAGS>(rdsp_converter, avop_input, avop_output, inp_count, bol_reader_aligned, bol_writer_aligned);
    }

    static void convert(const CONVERTER& rdsp_converter, const void *avop_input, int inp_source_scanline, void *avop_output, int inp_target_scanline, int inp_width, int inp_height)
    {

    }



};






/************************************************************************************************************************************/
/*  STATIC CONVERTER                                                                                                                */
/************************************************************************************************************************************/

/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Static Reduce Converter Class                                                                                                   */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <
	class READER, class WRITER, class ALGORITHM,

	
    mask_t RSRC, mask_t RDST,
    mask_t GSRC, mask_t GDST,
    mask_t BSRC, mask_t BDST,

	int READER_FLAGS, int WRITER_FLAGS
>
struct c_converter_static_alu_reduce : c_converter
{

    typedef c_static_reduce_mask_aux<RSRC, RDST> rmask_t;
    typedef c_static_reduce_mask_aux<GSRC, GDST> gmask_t;
    typedef c_static_reduce_mask_aux<BSRC, BDST> bmask_t;


    static const mask_t UN_RMASK = rmask_t::UN_MASK;
    static const int IN_RSHIFT = rmask_t::IN_SHIFT;
	static const mask_t UN_GMASK = gmask_t::UN_MASK;
    static const int IN_GSHIFT = gmask_t::IN_SHIFT;
	static const mask_t UN_BMASK = bmask_t::UN_MASK;
    static const int IN_BSHIFT = bmask_t::IN_SHIFT;


    typedef c_converter_static_alu_reduce<
        READER, WRITER, ALGORITHM,
        RSRC, RDST, GSRC, GDST, BSRC, BDST,
        READER_FLAGS, WRITER_FLAGS
    > self_t;

    typedef c_converter_manager<self_t> manager_t;

    // needed by manager
    typedef READER      reader_t;
    typedef WRITER      writer_t;
    static const int IN_READER_FLAGS = READER_FLAGS;
    static const int IN_WRITER_FLAGS = WRITER_FLAGS;
    typedef ALGORITHM   algorithm_t;

#if 0
    c_converter_static_alu_reduce() throw() {
#if defined (HOB_DEBUG)
        show();
#endif
    }
#endif

    static uint32_t convert_pixel(uint32_t ump_pixel) throw()
	{
		return (
			c_shift<IN_RSHIFT>::right(ump_pixel & UN_RMASK) |
			c_shift<IN_GSHIFT>::right(ump_pixel & UN_GMASK) |
			c_shift<IN_BSHIFT>::right(ump_pixel & UN_BMASK)
		);
	}

	virtual uint32_t convert(uint32_t ump_pixel) const throw() {
		return convert_pixel(ump_pixel);
	}
	virtual void convert(const void *avop_input, void *avop_output, int inp_count) const throw() {
		manager_t::convert(*this, avop_input, avop_output, inp_count);
	}
	virtual void convert(void *avop_inoutput, int inp_count) const throw() {
	    manager_t::convert(*this, avop_inoutput, avop_inoutput, inp_count);
	}
	virtual void convert_area(const void *avop_input, int inp_source_scanline, void *avop_output, int inp_target_scanline, int inp_width, int inp_height) const throw() {
	    manager_t::convert(*this, avop_input, inp_source_scanline, avop_output, inp_target_scanline, inp_width, inp_height);
	}


#if defined (HOB_DEBUG)
    virtual void show() const throw() {
        printf("rmask   = 0x%08x\n", UN_RMASK);
        printf("rshift  = %d\n", IN_RSHIFT);
        printf("gmask   = 0x%08x\n", UN_GMASK);
        printf("gshift  = %d\n", IN_GSHIFT);
        printf("bmask   = 0x%08x\n", UN_BMASK);
        printf("bshift  = %d\n", IN_BSHIFT);
    }
#endif
};



/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Static ALU Extend Converter Class                                                                                               */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <
    class READER, class WRITER, class ALGORITHM,
    
    mask_t RSRC, mask_t RDST,
    mask_t GSRC, mask_t GDST,
    mask_t BSRC, mask_t BDST,

    int READER_FLAGS, int WRITER_FLAGS,
    
    mask_t AMASK // = 0x00000000
>
struct c_converter_static_alu_extend : c_converter
{

    typedef c_static_extend_mask_aux<RSRC, RDST> rmask_t;
    typedef c_static_extend_mask_aux<GSRC, GDST> gmask_t;
    typedef c_static_extend_mask_aux<BSRC, BDST> bmask_t;

    static const mask_t UN_RMASK1 = rmask_t::UN_MASK_1;
    static const int IN_RSHIFT1 = rmask_t::IN_SHIFT_1;
    static const mask_t UN_RMASK2 = rmask_t::UN_MASK_2;
    static const int IN_RSHIFT2 = rmask_t::IN_SHIFT_2;
    static const mask_t UN_GMASK1 = gmask_t::UN_MASK_1;
    static const int IN_GSHIFT1 = gmask_t::IN_SHIFT_1;
    static const mask_t UN_GMASK2 = gmask_t::UN_MASK_2;
    static const int IN_GSHIFT2 = gmask_t::IN_SHIFT_2;
    static const mask_t UN_BMASK1 = bmask_t::UN_MASK_1;
    static const int IN_BSHIFT1 = bmask_t::IN_SHIFT_1;
    static const mask_t UN_BMASK2 = bmask_t::UN_MASK_2;
    static const int IN_BSHIFT2 = bmask_t::IN_SHIFT_2;



    typedef c_converter_static_alu_extend<
        READER, WRITER, ALGORITHM,
        RSRC, RDST, GSRC, GDST, BSRC, BDST,
        READER_FLAGS, WRITER_FLAGS, AMASK
    > self_t;

    typedef c_converter_manager<self_t> manager_t;

    // needed by manager
    typedef READER reader_t;
    typedef WRITER writer_t;
    static const int IN_READER_FLAGS = READER_FLAGS;
    static const int IN_WRITER_FLAGS = WRITER_FLAGS;
    typedef ALGORITHM algorithm_t;

#if 0
    c_converter_static_alu_extend() throw() {
#if defined (HOB_DEBUG)
        show();
#endif
    }
#endif


    static uint32_t convert_pixel(uint32_t ump_pixel) throw()
	{
        uint32_t uml_r = c_shift<IN_RSHIFT1>::left(ump_pixel);
        uml_r = ( (uml_r & UN_RMASK1) | (c_shift<IN_RSHIFT2>::right(uml_r) & UN_RMASK2) );
        uint32_t uml_g = c_shift<IN_GSHIFT1>::left(ump_pixel);
        uml_g = ( (uml_g & UN_GMASK1) | (c_shift<IN_GSHIFT2>::right(uml_g) & UN_GMASK2) );
        uint32_t uml_b = c_shift<IN_BSHIFT1>::left(ump_pixel);
        uml_b = ( (uml_b & UN_BMASK1) | (c_shift<IN_BSHIFT2>::right(uml_b) & UN_BMASK2) );

        return (uml_r | uml_g | uml_b | AMASK);
	}

    virtual uint32_t convert(uint32_t ump_pixel) const throw() {
        return convert_pixel(ump_pixel);
    }
    virtual void convert(const void *avop_input, void *avop_output, int inp_count) const throw() {
        manager_t::convert(*this, avop_input, avop_output, inp_count);
    }
    virtual void convert(void *avop_inoutput, int inp_count) const throw() {
        manager_t::convert(*this, avop_inoutput, avop_inoutput, inp_count);
    }
    virtual void convert_area(const void *avop_input, int inp_source_scanline, void *avop_output, int inp_target_scanline, int inp_width, int inp_height) const throw() {
        manager_t::convert(*this, avop_input, inp_source_scanline, avop_output, inp_target_scanline, inp_width, inp_height);
    }

#if defined (HOB_DEBUG)
    virtual void show() const throw() {
        printf("rmask1  = 0x%08x\n", UN_RMASK1);
        printf("rshift1 = %d\n", IN_RSHIFT1);
        printf("rmask2  = 0x%08x\n", UN_RMASK2);
        printf("rshift2 = %d\n", IN_RSHIFT2);
        printf("gmask1  = 0x%08x\n", UN_GMASK1);
        printf("gshift1 = %d\n", IN_GSHIFT1);
        printf("gmask2  = 0x%08x\n", UN_GMASK2);
        printf("gshift2 = %d\n", IN_GSHIFT2);
        printf("bmask1  = 0x%08x\n", UN_BMASK1);
        printf("bshift1 = %d\n", IN_BSHIFT1);
        printf("bmask2  = 0x%08x\n", UN_BMASK2);
        printf("bshift2 = %d\n", IN_BSHIFT2);
    }
#endif
};



/************************************************************************************************************************************/
/*  SSE2 CONVERTER                                                                                                                  */
/************************************************************************************************************************************/

/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  SSE2 Reduce Converter Class                                                                                                     */
/*                                                                                                                                  */
/************************************************************************************************************************************/
struct c_converter_sse2_reduce : c_converter {

};

/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  SSE2 Extend Converter Class                                                                                                     */
/*                                                                                                                                  */
/************************************************************************************************************************************/
struct c_converter_sse2_extend : c_converter {

};







/************************************************************************************************************************************/
/*  DYNAMIC CONVERTER                                                                                                               */
/************************************************************************************************************************************/

/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Dynamic Reduce Converter Class                                                                                                  */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <
    class READER, class WRITER, class ALGORITHM,

    int READER_FLAGS,
    int WRITER_FLAGS
>
struct c_converter_dynamic_reduce : c_converter {

    typedef c_converter_dynamic_reduce<
        READER, WRITER, ALGORITHM, READER_FLAGS, WRITER_FLAGS
    > self_t;

    typedef c_converter_manager<self_t> manager_t;

    // needed by manager
    typedef READER      reader_t;
    typedef WRITER      writer_t;
    typedef ALGORITHM   algorithm_t;

    static const int IN_READER_FLAGS = READER_FLAGS;
    static const int IN_WRITER_FLAGS = WRITER_FLAGS;


    c_dynamic_reduce_mask_set   dsc_maskset;

    c_converter_dynamic_reduce(const c_colormodel& rdsp_source, const c_colormodel& rdsp_target) throw()
        : dsc_maskset(rdsp_source.rmask(), rdsp_target.rmask(), rdsp_source.gmask(), rdsp_target.gmask(), rdsp_source.bmask(), rdsp_target.bmask())
    {
#if 0
#if defined (HOB_DEBUG)
        show();
#endif
#endif
    }

    uint32_t convert_pixel(uint32_t ump_pixel) const throw()
    {
        return (
            shift_right   (ump_pixel & dsc_maskset.rmask(), dsc_maskset.rshift()) |
            shift_right   (ump_pixel & dsc_maskset.gmask(), dsc_maskset.gshift()) |
            shift_right   (ump_pixel & dsc_maskset.bmask(), dsc_maskset.bshift())
       );
    }

    virtual uint32_t convert(uint32_t ump_pixel) const throw() {
        return convert_pixel(ump_pixel);
    }
    virtual void convert(const void *avop_input, void *avop_output, int inp_count) const throw() {
        manager_t::convert(*this, avop_input, avop_output, inp_count);
    }
    virtual void convert(void *avop_inoutput, int inp_count) const throw() {
        manager_t::convert(*this, avop_inoutput, avop_inoutput, inp_count);
    }
    virtual void convert_area(const void *avop_input, int inp_source_scanline, void *avop_output, int inp_target_scanline, int inp_width, int inp_height) const throw() {
        manager_t::convert(*this, avop_input, inp_source_scanline, avop_output, inp_target_scanline, inp_width, inp_height);
    }

#if defined (HOB_DEBUG)
    virtual void show() const throw() {
        dsc_maskset.show();
    }
#endif
};





/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Dynamic Extend Converter Class                                                                                                  */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <
    class READER, class WRITER, class ALGORITHM,

    int READER_FLAGS,
    int WRITER_FLAGS
>
struct c_converter_dynamic_extend : c_converter {

    typedef c_converter_dynamic_extend<
        READER, WRITER, ALGORITHM, READER_FLAGS, WRITER_FLAGS
    > self_t;

    typedef c_converter_manager<self_t> manager_t;

    // needed by manager
    typedef READER      reader_t;
    typedef WRITER      writer_t;
    typedef ALGORITHM   algorithm_t;

    static const int IN_READER_FLAGS = READER_FLAGS;
    static const int IN_WRITER_FLAGS = WRITER_FLAGS;



    c_dynamic_extend_mask_set   dsc_maskset;
    mask_t umc_amask;


    c_converter_dynamic_extend(const c_colormodel& rdsp_source, const c_colormodel& rdsp_target) throw()
       : dsc_maskset(rdsp_source.rmask(), rdsp_target.rmask(), rdsp_source.gmask(), rdsp_target.gmask(), rdsp_source.bmask(), rdsp_target.bmask()), umc_amask(rdsp_target.amask())
    {
#if 0
#if defined (HOB_DEBUG)
        show();
#endif
#endif
    }


    uint32_t convert_pixel(uint32_t ump_pixel) const throw()
    {
        uint32_t uml_r = shift_left (ump_pixel, dsc_maskset.rshift1());
        uml_r = ( (uml_r & dsc_maskset.rmask1()) | ((shift_right(uml_r, dsc_maskset.rshift2())) & dsc_maskset.rmask2()) );
        uint32_t uml_g = shift_left (ump_pixel, dsc_maskset.gshift1());
        uml_g = ( (uml_g & dsc_maskset.gmask1()) | ((shift_right(uml_g, dsc_maskset.gshift2())) & dsc_maskset.gmask2()) );
        uint32_t uml_b = shift_left (ump_pixel, dsc_maskset.bshift1());
        uml_b = ( (uml_b & dsc_maskset.bmask1()) | ((shift_right(uml_b, dsc_maskset.bshift2())) & dsc_maskset.bmask2()) );

        return (uml_r | uml_g | uml_b | umc_amask);
    }

    virtual uint32_t convert(uint32_t ump_pixel) const throw() {
        return convert_pixel(ump_pixel);
    }
    virtual void convert(const void *avop_input, void *avop_output, int inp_count) const throw() {
        manager_t::convert(*this, avop_input, avop_output, inp_count);
    }
    virtual void convert(void *avop_inoutput, int inp_count) const throw() {
        manager_t::convert(*this, avop_inoutput, avop_inoutput, inp_count);
    }
    virtual void convert_area(const void *avop_input, int inp_source_scanline, void *avop_output, int inp_target_scanline, int inp_width, int inp_height) const throw() {
        manager_t::convert(*this, avop_input, inp_source_scanline, avop_output, inp_target_scanline, inp_width, inp_height);
    }

#if defined (HOB_DEBUG)
    virtual void show() const throw() {
        dsc_maskset.show();
    }
#endif
};











/************************************************************************************************************************************/
/*  TABLE CONVERTER                                                                                                                 */
/************************************************************************************************************************************/

/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Converter from Table Class                                                                                                      */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <
    class READER, class WRITER, class ALGORITHM,

    int READER_ENDIANESS,
    int WRITER_FLAGS,
    int COLOR_DEPTH
>
struct c_converter_from_table : c_converter {

    typedef c_converter_from_table<
        READER, WRITER, ALGORITHM, READER_ENDIANESS, WRITER_FLAGS, COLOR_DEPTH
    > self_t;

    typedef c_from_table_manager<self_t> manager_t;

    // needed by manager
    typedef READER      reader_t;
    typedef WRITER      writer_t;
    typedef ALGORITHM   algorithm_t;

    // needed by manager
    enum {
        IN_COLOR_DEPTH          = COLOR_DEPTH,
        IN_READER_ENDIANESS     = READER_ENDIANESS,
        IN_WRITER_FLAGS         = WRITER_FLAGS,
    };


    // colortable
    uint32_t    umrc_table[1 << COLOR_DEPTH];




    c_converter_from_table(const c_colormap& rdsp_colormap) throw() {
        std::copy(rdsp_colormap.table(), rdsp_colormap.table() + (1 << COLOR_DEPTH), umrc_table);

#if defined (HOB_DEBUG)
        puts(__DYFUNCTION__);
#endif
    }





    uint32_t convert_pixel(uint32_t ump_pixel) const throw() {
        return umrc_table[ump_pixel];
    }
    virtual uint32_t convert(uint32_t ump_pixel) const throw() {
		return convert_pixel(ump_pixel);
	}
	virtual void convert(const void *avop_input, void *avop_output, int inp_count) const throw() {
		manager_t::convert(*this, avop_input, avop_output, inp_count);
	}
	virtual void convert(void *avop_inoutput, int inp_count) const throw() {
	    manager_t::convert(*this, avop_inoutput, avop_inoutput, inp_count);
	}
	virtual void convert_area(const void *avop_input, int inp_source_scanline, void *avop_output, int inp_target_scanline, int inp_width, int inp_height) const throw() {
	    manager_t::convert(*this, avop_input, inp_source_scanline, avop_output, inp_target_scanline, inp_width, inp_height);
	}
};





/************************************************************************************************************************************/
/*  SIMPLE CONVERTER                                                                                                                */
/************************************************************************************************************************************/

/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Converter OR Class                                                                                                              */
/*                                                                                                                                  */
/*  Purpose:                                                                                                                        */
/*      Puts alpha value into pixel.                                                                                                */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <uint32_t OR_VALUE>
struct c_converter_or : c_converter {
    static const uint32_t ums_or_value = OR_VALUE;
    static uint32_t convert_pixel(uint32_t ump_pixel) {
        return ump_pixel | ums_or_value;
    }
};

/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Converter NULL Class                                                                                                            */
/*                                                                                                                                  */
/*  Purpose:                                                                                                                        */
/*      Does nothing. Must be discarded by compiler.                                                                                */
/*                                                                                                                                  */
/************************************************************************************************************************************/
struct c_converter_null : c_converter {
    static uint32_t convert_pixel(uint32_t ump_pixel) {
        return ump_pixel;
    }
};

/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Converter Equal Class                                                                                                           */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <
    class READER, class WRITER, class ALGORITHM,

    int READER_FLAGS,
    int WRITER_FLAGS
>
struct c_converter_equal : c_converter {
    typedef c_converter_equal<
        READER, WRITER, ALGORITHM, READER_FLAGS, WRITER_FLAGS
    > self_t;

    typedef c_converter_manager<self_t> manager_t;

    // needed by manager
    typedef READER      reader_t;
    typedef WRITER      writer_t;
    typedef ALGORITHM   algorithm_t;

    static const int IN_READER_FLAGS = READER_FLAGS;
    static const int IN_WRITER_FLAGS = WRITER_FLAGS;


    
    c_converter_equal() {
    }

    uint32_t convert_pixel(uint32_t ump_pixel) const throw()
    {
        return ump_pixel;   // no changes
    }

    virtual uint32_t convert(uint32_t ump_pixel) const throw() {
		return convert_pixel(ump_pixel);
	}
	virtual void convert(const void *avop_input, void *avop_output, int inp_count) const throw() {
		manager_t::convert(*this, avop_input, avop_output, inp_count);
	}
	virtual void convert(void *avop_inoutput, int inp_count) const throw() {
	    manager_t::convert(*this, avop_inoutput, avop_inoutput, inp_count);
	}
	virtual void convert_area(const void *avop_input, int inp_source_scanline, void *avop_output, int inp_target_scanline, int inp_width, int inp_height) const throw() {
	    manager_t::convert(*this, avop_input, inp_source_scanline, avop_output, inp_target_scanline, inp_width, inp_height);
	}
};

/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Converter Same Class                                                                                                            */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <
    class READER, class WRITER, class ALGORITHM,

    int READER_FLAGS,
    int WRITER_FLAGS
>
struct c_converter_same : c_converter {
    typedef c_converter_same<
        READER, WRITER, ALGORITHM, READER_FLAGS, WRITER_FLAGS
    > self_t;

    typedef c_converter_manager<self_t> manager_t;

    // needed by manager
    typedef READER      reader_t;
    typedef WRITER      writer_t;
    typedef ALGORITHM   algorithm_t;

    static const int IN_READER_FLAGS = READER_FLAGS;
    static const int IN_WRITER_FLAGS = WRITER_FLAGS;


    bool changes() const throw() {
        return false;
    }

    c_converter_same() {
    }

    uint32_t convert_pixel(uint32_t ump_pixel) const throw()
    {
        return ump_pixel;   // no changes
    }

    virtual uint32_t convert(uint32_t ump_pixel) const throw() {
		return convert_pixel(ump_pixel);
	}
	virtual void convert(const void *avop_input, void *avop_output, int inp_count) const throw() {
		manager_t::convert(*this, avop_input, avop_output, inp_count);
	}
	virtual void convert(void *avop_inoutput, int inp_count) const throw() {
	    manager_t::convert(*this, avop_inoutput, avop_inoutput, inp_count);
	}
	virtual void convert_area(const void *avop_input, int inp_source_scanline, void *avop_output, int inp_target_scanline, int inp_width, int inp_height) const throw() {
	    manager_t::convert(*this, avop_input, inp_source_scanline, avop_output, inp_target_scanline, inp_width, inp_height);
	}
};

/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Converter Same Class without ALGORITHM                                                                                          */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <
    class READER, class WRITER,

    int READER_FLAGS,
    int WRITER_FLAGS
>
struct c_converter_same<READER, WRITER, NULL_CLASS, READER_FLAGS, WRITER_FLAGS> : c_converter {     // without algorithm


    bool changes() const throw() {
        return false;
    }

    c_converter_same() {
    }

    uint32_t convert_pixel(uint32_t ump_pixel) const throw() {
        return ump_pixel;   // no changes
    }

    virtual uint32_t convert(uint32_t ump_pixel) const throw() {
        return convert_pixel(ump_pixel);
    }
    virtual void convert(const void *avop_input, void *avop_output, int inp_count) const throw() {
       memcpy(avop_output, avop_input, READER::IN_INCREMENT * inp_count);
    }
    virtual void convert(void *avop_inoutput, int inp_count) const throw() {
        // do nothing
    }
    virtual void convert_area(const void *avop_input, int inp_source_scanline, void *avop_output, int inp_target_scanline, int inp_width, int inp_height) const throw() {
        // TODO: copy
    }
};




/************************************************************************************************************************************/
/*  MAX SIZE                                                                                                                        */
/************************************************************************************************************************************/

template <class CONFIG>
struct c_converter_size
{

    typedef c_read_8	        default_reader_t;
	typedef c_write_8	        default_writer_t;


    template <int VALUE1, int VALUE2>
    struct c_static_max {
        static const int IN_MAX = ((VALUE1 >= VALUE2) ? (VALUE1) : (VALUE2));
    };


    enum {
        IN_SET_TABLE_1  = CONFIG::IN_TYPE_FLAGS & IN_TABLE_1,
        IN_SET_TABLE_2  = CONFIG::IN_TYPE_FLAGS & IN_TABLE_2,
        IN_SET_TABLE_4  = CONFIG::IN_TYPE_FLAGS & IN_TABLE_4,
        IN_SET_TABLE_8  = CONFIG::IN_TYPE_FLAGS & IN_TABLE_8,

        IN_SET_TABLE    = (IN_SET_TABLE_1 | IN_SET_TABLE_2 | IN_SET_TABLE_4 | IN_SET_TABLE_8),

        IN_TABLE_MAX_COLOR_DEPTH    = (IN_SET_TABLE_8 ? 8 : (IN_SET_TABLE_4 ? 4 : (IN_SET_TABLE_2 ? 2 : (IN_SET_TABLE_1 ? 1 : 0)))),

        IN_SET_STATIC_ALU       = CONFIG::IN_TYPE_FLAGS & IN_STATIC_ALU,
        //IN_SET_STATIC_SSE2      = CONFIG::IN_TYPE_FLAGS & IN_STATIC_SSE2,
        IN_SET_DYNAMIC_REDUCE   = CONFIG::IN_TYPE_FLAGS & IN_DYNAMIC_REDUCE,
        IN_SET_DYNAMIC_EXTEND   = CONFIG::IN_TYPE_FLAGS & IN_DYNAMIC_EXTEND,
        IN_SET_EQUAL            = (CONFIG::IN_TYPE_FLAGS & IN_NO_EQUAL) == 0,
        IN_SET_SAME             = (CONFIG::IN_TYPE_FLAGS & IN_NO_SAME) == 0,

        
    };




    typedef c_converter_static_alu_reduce<default_reader_t, default_writer_t, NULL_CLASS, 0xff0000, 0x7c00, 0xff00, 0x3e0, 0xff, 0x1f, 0, 0> alu_reduce_t;
    typedef c_converter_static_alu_extend<default_reader_t, default_writer_t, NULL_CLASS, 0x7c00, 0xff0000, 0x3e0, 0xff00, 0x1f, 0xff, 0, 0, 0> alu_extend_t;
    typedef c_converter_dynamic_reduce<default_reader_t, default_writer_t, NULL_CLASS, 0, 0> dynamic_reduce_t;
    typedef c_converter_dynamic_extend<default_reader_t, default_writer_t, NULL_CLASS, 0, 0> dynamic_extend_t;
    typedef c_converter_from_table<default_reader_t, default_writer_t, NULL_CLASS, 1, 0, IN_TABLE_MAX_COLOR_DEPTH> from_table_t;
    typedef c_converter_equal<default_reader_t, default_writer_t, NULL_CLASS, 0, 0> equal_t;
    typedef c_converter_same<default_reader_t, default_writer_t, NULL_CLASS, 0, 0> same_t;


    
	template <class T, int I>
    struct c_size_of {        
        static const int IN_VALUE = sizeof(T);
    };
    template <class T>
    struct c_size_of<T, 0> {
        static const int IN_VALUE = 0;
    };




    enum {

        IN_SIZE_COLORMAP                = sizeof(c_colormap),
        IN_SIZE_COLORMODEL              = sizeof(c_colormodel),

        IN_SIZE_ALU_REDUCE              = c_size_of<alu_reduce_t, IN_SET_STATIC_ALU>::IN_VALUE,
        IN_SIZE_ALU_EXTEND              = c_size_of<alu_extend_t, IN_SET_STATIC_ALU>::IN_VALUE,
        
        IN_SIZE_DYNAMIC_REDUCE          = c_size_of<dynamic_reduce_t, IN_SET_DYNAMIC_REDUCE>::IN_VALUE,
        IN_SIZE_DYNAMIC_EXTEND          = c_size_of<dynamic_extend_t, IN_SET_DYNAMIC_EXTEND>::IN_VALUE,

        IN_SIZE_TABLE                   = c_size_of<from_table_t, IN_SET_TABLE>::IN_VALUE,

        IN_SIZE_EQUAL                   = c_size_of<equal_t, IN_SET_EQUAL>::IN_VALUE,
        IN_SIZE_SAME                    = c_size_of<same_t, IN_SET_SAME>::IN_VALUE,


        IN_SIZE_MAX                     = c_static_max<IN_SIZE_ALU_REDUCE,
                                          c_static_max<IN_SIZE_ALU_EXTEND,
                                          c_static_max<IN_SIZE_DYNAMIC_REDUCE,
                                          c_static_max<IN_SIZE_DYNAMIC_EXTEND,
                                          c_static_max<IN_SIZE_TABLE,
                                          c_static_max<IN_SIZE_EQUAL, IN_SIZE_SAME>::IN_MAX>::IN_MAX>::IN_MAX>::IN_MAX>::IN_MAX>::IN_MAX
    };
};



/************************************************************************************************************************************/
/*  BUILDERS                                                                                                                        */
/************************************************************************************************************************************/
/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  User Data Class to Pass-Through                                                                                                 */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <class MEMORY_PROVIDER>
struct c_userdata {

    const c_colormodel&                 rdsc_source;
    const c_colormodel&                 rdsc_target;
    MEMORY_PROVIDER&                    rdsc_memory_provider;
    c_converter *                       adsc_converter;

    c_userdata(const c_colormodel& rdsp_source, const c_colormodel& rdsp_target, MEMORY_PROVIDER& rdsp_memory_provider) throw()
        : rdsc_source(rdsp_source), rdsc_target(rdsp_target), rdsc_memory_provider(rdsp_memory_provider), adsc_converter(NULL)
    {
    }
};




/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Reader Writer Selector Dynamic                                                                                                  */
/*                                                                                                                                  */
/************************************************************************************************************************************/

template <template <template <class, class, class, int, int> class, class, class> class BUILDER,
    template <class, class, class, int, int> class CONVERTER, class LIST_READER, class LIST_WRITER>
struct c_reader_writer_selector {

    template <int LEVEL, class LIST_RESULT, class CLASS_USER>
    struct c_control;
    

    template <class LIST_RESULT, class CLASS_USER>
    struct c_control<0, LIST_RESULT, CLASS_USER>
    {
        struct c_match {
            static const int IN_VALUE = hob::meta::IN_ASK;
            static bool match(CLASS_USER* adsp_userdata) {
                typedef typename LIST_RESULT::VALUE reader_t;
                return ((adsp_userdata->rdsc_source.endianess() == reader_t::IN_ENDIANESS) &&
                    (adsp_userdata->rdsc_source.pixel_size() == reader_t::IN_INCREMENT * 8));
            }
        };
    
        struct c_action {
            static const int IN_VALUE = hob::meta::IN_FALSE;
            static bool action(CLASS_USER* adsp_userdata) {
                return false;
            }
        };

        struct c_abort {
            static const int IN_VALUE = hob::meta::IN_TRUE;
            static bool abort(CLASS_USER* adsp_userdata) {
                return true;
            }
        };
    };




    template <class LIST_RESULT, class CLASS_USER>
    struct c_control<1, LIST_RESULT, CLASS_USER>
    {
        struct c_match {
            static const int IN_VALUE = hob::meta::IN_ASK;
            static bool match(CLASS_USER* adsp_userdata) {
                typedef typename LIST_RESULT::VALUE writer_t;
                return ((adsp_userdata->rdsc_target.endianess() == writer_t::IN_ENDIANESS) &&
                    (adsp_userdata->rdsc_target.pixel_size() == writer_t::IN_INCREMENT * 8));
            }
        };
    
        struct c_action {
            static const int IN_VALUE = hob::meta::IN_ASK;
            static bool action(CLASS_USER* adsp_userdata) {
                typedef typename LIST_RESULT::NEXT::VALUE    reader_t;
                typedef typename LIST_RESULT::VALUE          writer_t;
                typedef BUILDER<CONVERTER, reader_t, writer_t> builder_t;
                adsp_userdata->adsc_converter = builder_t::create(*adsp_userdata);
                return true;
            }
        };

        struct c_abort {
            static const int IN_VALUE = hob::meta::IN_TRUE;
            static bool abort(CLASS_USER* adsp_userdata) {
                return true;
            }
        };
    };



public:        
    template <class MEMORY_PROVIDER>
    static c_converter* create_converter(c_userdata<MEMORY_PROVIDER>& rdsp_userdata) {
        typedef TYPE_LIST2(LIST_READER, LIST_WRITER) input_t;
        hob::meta::c_for_each<c_control, input_t, c_userdata<MEMORY_PROVIDER> >::run(&rdsp_userdata);
        return rdsp_userdata.adsc_converter;
    }


};



/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Endianess Selector for Dynamic, Same and Equal.                                                                                 */
/*                                                                                                                                  */
/************************************************************************************************************************************/



/*
 *  Source Calculation out
 */
template <int TYPE_FLAGS>
struct c_transform_endianess {
    static const int IN_VALUE_SOURCE = (((TYPE_FLAGS & (IN_DYNAMIC_SOURCE_ENDIAN_LITTLE | IN_DYNAMIC_SOURCE_ENDIAN_BIG)) == (IN_DYNAMIC_SOURCE_ENDIAN_LITTLE | IN_DYNAMIC_SOURCE_ENDIAN_BIG)) ? (IN_ENDIAN_LITTLE | IN_ENDIAN_BIG) :
        (((TYPE_FLAGS & (IN_DYNAMIC_SOURCE_ENDIAN_LITTLE | IN_DYNAMIC_SOURCE_ENDIAN_BIG)) == IN_DYNAMIC_SOURCE_ENDIAN_LITTLE) ? (IN_ENDIAN_LITTLE) :
            (((TYPE_FLAGS & (IN_DYNAMIC_SOURCE_ENDIAN_LITTLE | IN_DYNAMIC_SOURCE_ENDIAN_BIG)) == IN_DYNAMIC_SOURCE_ENDIAN_BIG) ? (IN_ENDIAN_BIG) :
                (IN_ENDIAN_UNDEFINED))));

    static const int IN_VALUE_TARGET = (((TYPE_FLAGS & (IN_DYNAMIC_TARGET_ENDIAN_LITTLE | IN_DYNAMIC_TARGET_ENDIAN_BIG)) == (IN_DYNAMIC_TARGET_ENDIAN_LITTLE | IN_DYNAMIC_TARGET_ENDIAN_BIG)) ? (IN_ENDIAN_LITTLE | IN_ENDIAN_BIG) :
        (((TYPE_FLAGS & (IN_DYNAMIC_TARGET_ENDIAN_LITTLE | IN_DYNAMIC_TARGET_ENDIAN_BIG)) == IN_DYNAMIC_TARGET_ENDIAN_LITTLE) ? (IN_ENDIAN_LITTLE) :
            (((TYPE_FLAGS & (IN_DYNAMIC_TARGET_ENDIAN_LITTLE | IN_DYNAMIC_TARGET_ENDIAN_BIG)) == IN_DYNAMIC_TARGET_ENDIAN_BIG) ? (IN_ENDIAN_BIG) :
                (IN_ENDIAN_UNDEFINED))));
};




template <template <template <class, class, class, int, int> class, class, class> class BUILDER,
    template <class, class, class, int, int> class CONVERTER, int ENDIANESS_SOURCE, int ENDIANESS_TARGET>
struct c_endianess_selector;

/*
 *  Little Endian Reader -> Little Endian Writer
 */
template <template <template <class, class, class, int, int> class, class, class> class BUILDER,
    template <class, class, class, int, int> class CONVERTER>
struct c_endianess_selector<BUILDER, CONVERTER, 1, 1> {           // IN_ENDIAN_LITTLE -> IN_ENDIAN_LITTLE

    template <class MEMORY_PROVIDER>
    static c_converter* create_converter(c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
    {
        typedef TYPE_LIST3(c_read_16_l, c_read_24_l, c_read_32_l)                   reader_list_t;
        typedef TYPE_LIST3(c_write_16_l, c_write_24_l, c_write_32_l)                writer_list_t;

        return c_reader_writer_selector<BUILDER, CONVERTER, reader_list_t, writer_list_t>::create_converter(rdsp_userdata);
    }
};

/*
 *  Little Endian Reader -> Big Endian Writer
 */
template <template <template <class, class, class, int, int> class, class, class> class BUILDER,
    template <class, class, class, int, int> class CONVERTER>
struct c_endianess_selector<BUILDER, CONVERTER, 1, 2> {           // IN_ENDIAN_LITTLE -> IN_ENDIAN_BIG
    template <class MEMORY_PROVIDER>
    static c_converter* create_converter(c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
    {
        typedef TYPE_LIST3(c_read_16_l, c_read_24_l, c_read_32_l)                                   reader_list_t;
        typedef TYPE_LIST3(c_write_16_b, c_write_24_b, c_write_32_b)                                writer_list_t;

        return c_reader_writer_selector<BUILDER, CONVERTER, reader_list_t, writer_list_t>::create_converter(rdsp_userdata);
    }
};

/*
 *  Little Endian Reader -> Little and Big Endian Writer
 */
template <template <template <class, class, class, int, int> class, class, class> class BUILDER,
    template <class, class, class, int, int> class CONVERTER>
struct c_endianess_selector<BUILDER, CONVERTER, 1, 3> {           // IN_ENDIAN_LITTLE -> IN_ENDIAN_LITTLE | IN_ENDIAN_BIG
    template <class MEMORY_PROVIDER>
    static c_converter* create_converter(c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
    {
        typedef TYPE_LIST3(c_read_16_l, c_read_24_l, c_read_32_l)                                               reader_list_t;
        typedef TYPE_LIST6(c_write_16_l, c_write_16_b, c_write_24_l, c_write_24_b, c_write_32_l, c_write_32_b)  writer_list_t;

        return c_reader_writer_selector<BUILDER, CONVERTER, reader_list_t, writer_list_t>::create_converter(rdsp_userdata);
    }
};

/*
 *  Big Endian Reader -> Little Endian Writer
 */
template <template <template <class, class, class, int, int> class, class, class> class BUILDER,
    template <class, class, class, int, int> class CONVERTER>
struct c_endianess_selector<BUILDER, CONVERTER, 2, 1> {           // IN_ENDIAN_BIG -> IN_ENDIAN_LITTLE
    template <class MEMORY_PROVIDER>
    static c_converter* create_converter(c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
    {
        typedef TYPE_LIST3(c_read_16_b, c_read_24_b, c_read_32_b)                           reader_list_t;
        typedef TYPE_LIST3(c_write_16_l, c_write_24_l, c_write_32_l)                        writer_list_t;

        return c_reader_writer_selector<BUILDER, CONVERTER, reader_list_t, writer_list_t>::create_converter(rdsp_userdata);
    }
};
    
/*
 *  Big Endian Reader -> Big Endian Writer
 */
template <template <template <class, class, class, int, int> class, class, class> class BUILDER,
    template <class, class, class, int, int> class CONVERTER>
struct c_endianess_selector<BUILDER, CONVERTER, 2, 2> {           // IN_ENDIAN_BIG -> IN_ENDIAN_BIG
    template <class MEMORY_PROVIDER>
    static c_converter* create_converter(c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
    {
        typedef TYPE_LIST3(c_read_16_b, c_read_24_b, c_read_32_b)                           reader_list_t;
        typedef TYPE_LIST3(c_write_16_b, c_write_24_b, c_write_32_b)                        writer_list_t;

        return c_reader_writer_selector<BUILDER, CONVERTER, reader_list_t, writer_list_t>::create_converter(rdsp_userdata);
    }
};
    
/*
 *  Big Endian Reader -> Little and Big Endian Writer
 */
template <template <template <class, class, class, int, int> class, class, class> class BUILDER,
    template <class, class, class, int, int> class CONVERTER>
struct c_endianess_selector<BUILDER, CONVERTER, 2, 3> {           // IN_ENDIAN_BIG -> IN_ENDIAN_LITTLE | IN_ENDIAN_BIG
    template <class MEMORY_PROVIDER>
    static c_converter* create_converter(c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
    {
        typedef TYPE_LIST3(c_read_16_b, c_read_24_b, c_read_32_b)                                                   reader_list_t;
        typedef TYPE_LIST6(c_write_16_l, c_write_16_b, c_write_24_l, c_write_24_b, c_write_32_l, c_write_32_b)      writer_list_t;

        return c_reader_writer_selector<BUILDER, CONVERTER, reader_list_t, writer_list_t>::create_converter(rdsp_userdata);
    }
};

/*
 *  Little and Big Endean Reader -> Little Endian Writer
 */
template <template <template <class, class, class, int, int> class, class, class> class BUILDER,
    template <class, class, class, int, int> class CONVERTER>
struct c_endianess_selector<BUILDER, CONVERTER, 3, 1> {           // IN_ENDIAN_LITTLE | IN_ENDIAN_BIG -> IN_ENDIAN_LITTLE
    template <class MEMORY_PROVIDER>
    static c_converter* create_converter(c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
    {
        // todo: here
        typedef TYPE_LIST6(c_read_16_l, c_read_16_b, c_read_24_l, c_read_24_b, c_read_32_l, c_read_32_b)    reader_list_t;
        typedef TYPE_LIST3(c_write_16_l, c_write_24_l, c_write_32_l)                                        writer_list_t;

        return c_reader_writer_selector<BUILDER, CONVERTER, reader_list_t, writer_list_t>::create_converter(rdsp_userdata);
    }
};

/*
 *  Little and Big Endian Reader -> Big Endian Writer
 */
template <template <template <class, class, class, int, int> class, class, class> class BUILDER,
    template <class, class, class, int, int> class CONVERTER>
struct c_endianess_selector<BUILDER, CONVERTER, 3, 2> {           // IN_ENDIAN_LITTLE | IN_ENDIAN_BIG -> IN_ENDIAN_BIG
    template <class MEMORY_PROVIDER>
    static c_converter* create_converter(c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
    {
        typedef TYPE_LIST6(c_read_16_l, c_read_16_b, c_read_24_l, c_read_24_b, c_read_32_l, c_read_32_b)    reader_list_t;
        typedef TYPE_LIST3(c_write_16_b, c_write_24_b, c_write_32_b)                                        writer_list_t;

        return c_reader_writer_selector<BUILDER, CONVERTER, reader_list_t, writer_list_t>::create_converter(rdsp_userdata);
    }
};

/*
 *  Little and Big Endian Reader -> Little and Big Endian Writer
 */
template <template <template <class, class, class, int, int> class, class, class> class BUILDER,
    template <class, class, class, int, int> class CONVERTER>
struct c_endianess_selector<BUILDER, CONVERTER, 3, 3> {           // IN_ENDIAN_LITTLE | IN_ENDIAN_BIG -> IN_ENDIAN_LITTLE | IN_ENDIAN_BIG
    template <class MEMORY_PROVIDER>
    static c_converter* create_converter(c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
    {
        typedef TYPE_LIST6(c_read_16_l, c_read_16_b, c_read_24_l, c_read_24_b, c_read_32_l, c_read_32_b)        reader_list_t;
        typedef TYPE_LIST6(c_write_16_l, c_write_16_b, c_write_24_l, c_write_24_b, c_write_32_l, c_write_32_b)  writer_list_t;

        return c_reader_writer_selector<BUILDER, CONVERTER, reader_list_t, writer_list_t>::create_converter(rdsp_userdata);
    }
};







/************************************************************************************************************************************/
/*  BUILDERS                                                                                                                        */
/************************************************************************************************************************************/

/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Static Converter Builder Class                                                                                                  */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <class CONFIG>
struct c_static_alu_builder
{

    /*
     *  Builder Declaration
     */
    template <class COLORMODEL_SOURCE, class COLORMODEL_TARGET, bool REDUCE>
    struct c_static_alu_builder_inner;


    /*
     *  Reduce Builder Definition
     */
    template <class COLORMODEL_SOURCE, class COLORMODEL_TARGET>
    struct c_static_alu_builder_inner <COLORMODEL_SOURCE, COLORMODEL_TARGET, true> {
        template <class MEMORY_PROVIDER>
        static c_converter* create(const c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
        {
            
            typedef typename c_select_reader<COLORMODEL_SOURCE::UN_PIXEL_SIZE, COLORMODEL_SOURCE::IN_ENDIANESS>::reader_t reader_t;
            typedef typename c_select_writer<COLORMODEL_TARGET::UN_PIXEL_SIZE, COLORMODEL_TARGET::IN_ENDIANESS>::writer_t writer_t;
            typedef typename CONFIG::algorithm_t algorithm_t;


            static const int IN_READER_FLAGS = CONFIG::IN_READER_FLAGS;
            static const int IN_WRITER_FLAGS = CONFIG::IN_WRITER_FLAGS;

            typedef c_converter_static_alu_reduce<reader_t, writer_t, algorithm_t,
                COLORMODEL_SOURCE::UN_RMASK, COLORMODEL_TARGET::UN_RMASK,
                COLORMODEL_SOURCE::UN_GMASK, COLORMODEL_TARGET::UN_GMASK,
                COLORMODEL_SOURCE::UN_BMASK, COLORMODEL_TARGET::UN_BMASK,
                IN_READER_FLAGS, IN_WRITER_FLAGS>
            converter_t;

            return new (rdsp_userdata.rdsc_memory_provider.m_allocate(sizeof(converter_t))) converter_t();
        }
    };



    /*
     *  Extend Builder Definition
     */
    template <class COLORMODEL_SOURCE, class COLORMODEL_TARGET>
    struct c_static_alu_builder_inner <COLORMODEL_SOURCE, COLORMODEL_TARGET, false> {
        template <class MEMORY_PROVIDER>
        static c_converter* create(const c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
        {
            typedef typename c_select_reader<COLORMODEL_SOURCE::UN_PIXEL_SIZE, COLORMODEL_SOURCE::IN_ENDIANESS>::reader_t reader_t;
            typedef typename c_select_writer<COLORMODEL_TARGET::UN_PIXEL_SIZE, COLORMODEL_TARGET::IN_ENDIANESS>::writer_t writer_t;
            typedef typename CONFIG::algorithm_t algorithm_t;

                
            static const int IN_READER_FLAGS = CONFIG::IN_READER_FLAGS;
            static const int IN_WRITER_FLAGS = CONFIG::IN_WRITER_FLAGS;

            typedef c_converter_static_alu_extend<reader_t, writer_t, algorithm_t,
                COLORMODEL_SOURCE::UN_RMASK, COLORMODEL_TARGET::UN_RMASK,
                COLORMODEL_SOURCE::UN_GMASK, COLORMODEL_TARGET::UN_GMASK,
                COLORMODEL_SOURCE::UN_BMASK, COLORMODEL_TARGET::UN_BMASK,
                IN_READER_FLAGS, IN_WRITER_FLAGS, COLORMODEL_TARGET::UN_AMASK>
            converter_t;

            return new (rdsp_userdata.rdsc_memory_provider.m_allocate(sizeof(converter_t))) converter_t();
        }
    };


    template <int LEVEL, class LIST_RESULT, class CLASS_USER>
    struct c_control;
    

    template <class LIST_RESULT, class CLASS_USER>
    struct c_control<0, LIST_RESULT, CLASS_USER>
    {
        struct c_match {
            static const int IN_VALUE = hob::meta::IN_ASK;
            static bool match(CLASS_USER* adsp_userdata) {
                typedef typename LIST_RESULT::VALUE source_t;
                return source_t::equals(adsp_userdata->rdsc_source);
            }
        };
    
        struct c_action {
            static const int IN_VALUE = hob::meta::IN_FALSE;
            static bool action(CLASS_USER* adsp_userdata) {
                return false;
            }
        };

        struct c_abort {
            static const int IN_VALUE = hob::meta::IN_ASK;
            static bool abort(CLASS_USER* adsp_userdata) {
                return (adsp_userdata->adsc_converter != NULL);
            }
        };
    };




    template <class LIST_RESULT, class CLASS_USER>
    struct c_control<1, LIST_RESULT, CLASS_USER>
    {
        struct c_match {
            static const int IN_VALUE = hob::meta::IN_ASK;
            static bool match(CLASS_USER* adsp_userdata) {
                typedef typename LIST_RESULT::VALUE target_t;
                return target_t::equals(adsp_userdata->rdsc_target);
            }
        };
    
        struct c_action {
            static const int IN_VALUE = hob::meta::IN_ASK;
            static bool action(CLASS_USER* adsp_userdata) {
                typedef typename LIST_RESULT::NEXT::VALUE    source_t;
                typedef typename LIST_RESULT::VALUE          target_t;

                adsp_userdata->adsc_converter = c_static_alu_builder_inner
                    <source_t, target_t, source_t::UN_BPP >= target_t::UN_BPP>::create(*adsp_userdata);


                return true;
            }
        };

        struct c_abort {
            static const int IN_VALUE = hob::meta::IN_ASK;
            static bool abort(CLASS_USER* adsp_userdata) {
                return (adsp_userdata->adsc_converter != NULL);
            }
        };
    };





    template <class MEMORY_PROVIDER>
    static c_converter* create_converter(c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
    {
        typedef typename CONFIG::list_source_t list_source_t;
        typedef typename CONFIG::list_target_t list_target_t;

        
        typedef TYPE_LIST2(list_source_t, list_target_t) input_t;

        hob::meta::c_for_each<c_control, input_t, c_userdata<MEMORY_PROVIDER> >::run(&rdsp_userdata);

        return rdsp_userdata.adsc_converter;
    }

};









/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  SSE2 Converter Builder Class                                                                                                    */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <class CONFIG>
struct c_static_sse2_builder {
    
    typedef CONFIG config_t;
    typedef typename config_t::list_source_t list_source_t;
    typedef typename config_t::list_target_t list_target_t;


    template <class COLORMODEL_SOURCE, class COLORMODEL_TARGET, bool REDUCE>
    struct c_static_sse2_builder_inner {
        template <class MEMORY_PROVIDER>
#if !defined(HOB_CC_PREFER_SPEED)
        static c_converter* create(const c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
#else
        static c_converter* create(const c_userdata<MEMORY_PROVIDER>& rdsp_userdata, bool& bop_wrong_source)
#endif
        {
            //puts(__DYFUNCTION__);
            return NULL;
        }
    };


    template <class MEMORY_PROVIDER>
    static c_converter* create_converter(const c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
    {
        //puts(__DYFUNCTION__);

//        return c_static_selector<c_static_sse2_builder_inner, list_source_t, list_target_t>::create_converter(rdsp_userdata);
        return NULL;
    }
};


/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Dynamic Extend Converter Builder Class                                                                                          */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <class CONFIG>
struct c_dynamic_builder {

    typedef typename CONFIG::algorithm_t algorithm_t;


    static const int IN_TYPE_FLAGS      = CONFIG::IN_TYPE_FLAGS;
    static const int IN_READER_FLAGS    = CONFIG::IN_READER_FLAGS;
    static const int IN_WRITER_FLAGS    = CONFIG::IN_WRITER_FLAGS;


    /*
     *  Builder Declaration.
     */
    template <template <class, class, class, int, int> class CONVERTER, class READER, class WRITER>
    struct c_dynamic_builder_inner
    {
        template <class MEMORY_PROVIDER>
        static c_converter* create(const c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
        {
            typedef CONVERTER<READER, WRITER, algorithm_t, IN_READER_FLAGS, IN_WRITER_FLAGS> converter_t;

            return new (rdsp_userdata.rdsc_memory_provider.m_allocate(sizeof(converter_t)))
                converter_t(rdsp_userdata.rdsc_source, rdsp_userdata.rdsc_target);
        }
    };



    /*
     *  Called from outside.
     */
    template <class MEMORY_PROVIDER>
    static c_converter* create_converter(c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
    {
        typedef c_transform_endianess<IN_TYPE_FLAGS> endianess_t;

        // TODO: remove runtime check!
        if (rdsp_userdata.rdsc_source.color_depth() >= rdsp_userdata.rdsc_target.color_depth())                             // reduce
            return c_endianess_selector<c_dynamic_builder_inner, c_converter_dynamic_reduce,
                endianess_t::IN_VALUE_SOURCE, endianess_t::IN_VALUE_TARGET>::create_converter(rdsp_userdata);
        else
            return c_endianess_selector<c_dynamic_builder_inner, c_converter_dynamic_extend,
                endianess_t::IN_VALUE_SOURCE, endianess_t::IN_VALUE_TARGET>::create_converter(rdsp_userdata);

    }
};





/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Table Converter Builder Class                                                                                                   */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <class CONFIG, int COLOR_DEPTH>
struct c_table_builder {
  

    typedef typename CONFIG::algorithm_t algorithm_t;


    
    enum {
        IN_TYPE_FLAGS       = CONFIG::IN_TYPE_FLAGS,
        IN_READER_FLAGS     = CONFIG::IN_READER_FLAGS,
        IN_WRITER_FLAGS     = CONFIG::IN_WRITER_FLAGS,
    };



    /*
     *  Builder Declaration.
     */
    template <class WRITER>
    struct c_table_builder_inner
    {
        template <class MEMORY_PROVIDER>
        static c_converter* create(const c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
        {
            if (rdsp_userdata.rdsc_source.endianess() == ie_endian_little) {
                typedef c_converter_from_table<c_read_8, WRITER, algorithm_t, 1, IN_WRITER_FLAGS, COLOR_DEPTH> converter_t;
                return new (rdsp_userdata.rdsc_memory_provider.m_allocate(sizeof(converter_t)))
                    converter_t(*rdsp_userdata.rdsc_source.colormap());
            }
            typedef c_converter_from_table<c_read_8, WRITER, algorithm_t, 2, IN_WRITER_FLAGS, COLOR_DEPTH> converter_t;
            return new (rdsp_userdata.rdsc_memory_provider.m_allocate(sizeof(converter_t)))
                converter_t(*rdsp_userdata.rdsc_source.colormap());
            
        }
    };



    template <template <class> class BUILDER, class LIST_WRITER>
    struct c_table_writer_selector {

        template <int LEVEL, class LIST_RESULT, class CLASS_USER>
        struct c_control;

        template <class LIST_RESULT, class CLASS_USER>
        struct c_control<0, LIST_RESULT, CLASS_USER>
        {
            struct c_match {
                static const int IN_VALUE = hob::meta::IN_ASK;
                static bool match(CLASS_USER* adsp_userdata) {
                    typedef typename LIST_RESULT::VALUE writer_t;
                    return ((adsp_userdata->rdsc_target.pixel_size() == (writer_t::IN_INCREMENT * 8)) &&
                        (adsp_userdata->rdsc_target.endianess() == writer_t::IN_ENDIANESS));
                }
            };
    
            struct c_action {
                static const int IN_VALUE = hob::meta::IN_ASK;
                static bool action(CLASS_USER* adsp_userdata) {
                    typedef typename LIST_RESULT::VALUE         writer_t;
                    typedef BUILDER<writer_t>                   builder_t;
                    adsp_userdata->adsc_converter = builder_t::create(*adsp_userdata);
                    return true;
                }
            };

            struct c_abort {
                static const int IN_VALUE = hob::meta::IN_TRUE;
                static bool abort(CLASS_USER* adsp_userdata) {
                    return true;
                }
            };
        };



        template <class MEMORY_PROVIDER>
        static c_converter* create_converter(c_userdata<MEMORY_PROVIDER>& rdsp_userdata) {
            typedef TYPE_LIST1(LIST_WRITER) input_t;
            hob::meta::c_for_each<c_control, input_t, c_userdata<MEMORY_PROVIDER> >::run(&rdsp_userdata);
            return rdsp_userdata.adsc_converter;
        }

    };





    
    template <template <class> class BUILDER, int ENDIANESS_TARGET>
    struct c_table_endianess_selector;

    template <template <class> class BUILDER>
    struct c_table_endianess_selector<BUILDER, 1> {
        template <class MEMORY_PROVIDER>
        static c_converter* create_converter(c_userdata<MEMORY_PROVIDER>& rdsp_userdata) {
            typedef TYPE_LIST3(c_write_16_l, c_write_24_l, c_write_32_l) writer_list_t;
            return c_table_writer_selector<c_table_builder_inner, writer_list_t>::create_converter(rdsp_userdata);
        }
    };
    template <template <class> class BUILDER>
    struct c_table_endianess_selector<BUILDER, 2> {
        template <class MEMORY_PROVIDER>
        static c_converter* create_converter(c_userdata<MEMORY_PROVIDER>& rdsp_userdata) {
            typedef TYPE_LIST3(c_write_16_b, c_write_24_b, c_write_32_b)            writer_list_t;
            return c_table_writer_selector<c_table_builder_inner, writer_list_t>::create_converter(rdsp_userdata);
        }
    };
    template <template <class> class BUILDER>
    struct c_table_endianess_selector<BUILDER, 3> {
        template <class MEMORY_PROVIDER>
        static c_converter* create_converter(c_userdata<MEMORY_PROVIDER>& rdsp_userdata) {
            typedef TYPE_LIST6(c_write_16_l, c_write_16_b, c_write_24_l, c_write_24_b, c_write_32_l, c_write_32_b)  writer_list_t;
            return c_table_writer_selector<c_table_builder_inner, writer_list_t>::create_converter(rdsp_userdata);
        }
    };








    template <class MEMORY_PROVIDER>
    static c_converter* create_converter(c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
    {
        typedef c_transform_endianess<IN_TYPE_FLAGS> endianess_t;


        return c_table_endianess_selector<c_table_builder_inner, endianess_t::IN_VALUE_TARGET>::create_converter(rdsp_userdata);
    }

    
    
};



/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Same and Equal Converter Builder Class                                                                                          */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*                                                                                                                                  */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <class CONFIG, int CREATE_SAME>
class c_equal_builder
{

    typedef typename CONFIG::algorithm_t algorithm_t;



    enum {
        IN_TYPE_FLAGS      = CONFIG::IN_TYPE_FLAGS,
        IN_READER_FLAGS    = CONFIG::IN_READER_FLAGS,
        IN_WRITER_FLAGS    = CONFIG::IN_WRITER_FLAGS,
    };


    /*
     *  Builder Declaration.
     */
    template <template <class, class, class, int, int> class CONVERTER, class READER, class WRITER>
    struct c_equal_builder_inner {
        template <class MEMORY_PROVIDER>
        static c_converter* create(const c_userdata<MEMORY_PROVIDER>& rdsp_userdata) {
            typedef CONVERTER<READER, WRITER, algorithm_t, IN_READER_FLAGS, IN_WRITER_FLAGS> converter_t;
            return new (rdsp_userdata.rdsc_memory_provider.m_allocate(sizeof(converter_t))) converter_t();
        }
    };


public:
    template <class MEMORY_PROVIDER>
    static c_converter* create_converter(c_userdata<MEMORY_PROVIDER>& rdsp_userdata) {
        if (CREATE_SAME == 1) {
            return c_endianess_selector<c_equal_builder_inner, c_converter_same, c_transform_endianess<IN_TYPE_FLAGS>::IN_VALUE_SOURCE,
                c_transform_endianess<IN_TYPE_FLAGS>::IN_VALUE_TARGET>::create_converter(rdsp_userdata);
        }
        return c_endianess_selector<c_equal_builder_inner, c_converter_equal, c_transform_endianess<IN_TYPE_FLAGS>::IN_VALUE_SOURCE,
            c_transform_endianess<IN_TYPE_FLAGS>::IN_VALUE_TARGET>::create_converter(rdsp_userdata);
    }
};







#define M_DUMMY_SUPPORTS_SSE2(x) x


/************************************************************************************************************************************/
/*                                                                                                                                  */
/*  Static Generator Class                                                                                                          */
/*                                                                                                                                  */
/*                                                                                                                                  */
/************************************************************************************************************************************/
template <class CONFIG>
struct c_converter_factory {
    

    template <class MEMORY_PROVIDER, int COLOR_DEPTH>
    static c_converter* create_table_converter_recursive(c_userdata<MEMORY_PROVIDER>& rdsp_userdata)
    {
        //puts(__DYFUNCTION__);

        const c_colormodel& rdsl_source = rdsp_userdata.rdsc_source;
        const c_colormodel& rdsl_target = rdsp_userdata.rdsc_target;

        // check if colormap colormodel matches target 
        if (rdsl_source.colormodel_map()->total_equals(rdsl_target))
        {
            return c_table_builder<CONFIG, COLOR_DEPTH>::create_converter(rdsp_userdata);
        }


        hob::memory::c_memory_provider_stack<
            c_converter_size<CONFIG>::IN_SIZE_MAX +                  // converter for the colormap
            c_converter_size<CONFIG>::IN_SIZE_COLORMAP +             // new colormap
            c_converter_size<CONFIG>::IN_SIZE_COLORMODEL             // new colormodel
        > dsl_stack_provider;



        // create temporary converter for the colortable
        c_converter *adsl_converter = c_converter_factory<CONFIG>::create_converter(*rdsl_source.colormodel_map(), rdsl_target, dsl_stack_provider);


        // convert table
        uint32_t umrl_table[256];
        unsigned int unl_count = rdsl_source.colormap()->count();
        for (unsigned int unl1 = 0; unl1 < unl_count; ++unl1)
            umrl_table[unl1] = adsl_converter->convert(rdsl_source.colormap()->get_pixel(unl1));
        
        
        // TODO: there is no need to free 'adsl_converter'...


        // create new input
        c_colormodel dsl_new_input(rdsl_source.color_depth(), rdsl_source.pixel_size(), rdsl_source.endianess(), c_colormap(umrl_table, unl_count), rdsl_target, dsl_stack_provider);
        // userdata with new input and old provider
        c_userdata<MEMORY_PROVIDER> dsl_new_userdata(dsl_new_input, rdsl_target, rdsp_userdata.rdsc_memory_provider);


        // TODO: there is no need to free 'dsl_new_input'...

        return create_table_converter_recursive<MEMORY_PROVIDER, COLOR_DEPTH>(dsl_new_userdata);
    }



    /*
     *  No Exception Version
     */
    template <class MEMORY_PROVIDER>
    static c_converter* create_converter(const c_colormodel& rdsp_source, const c_colormodel& rdsp_target, MEMORY_PROVIDER& rdsp_memory_provider, const std::nothrow_t&) throw()
    {
        try {
            return create_converter(rdsp_source, rdsp_target, rdsp_memory_provider);
        } catch (...) {
            return NULL;
        }
    }





    template <class MEMORY_PROVIDER>
    static c_converter* create_converter(const c_colormodel& rdsp_source, const c_colormodel& rdsp_target, MEMORY_PROVIDER& rdsp_memory_provider)
    {
        //puts(__DYFUNCTION__);

        c_userdata<MEMORY_PROVIDER> dsl_userdata(rdsp_source, rdsp_target, rdsp_memory_provider);

        // check same
        if (((CONFIG::IN_TYPE_FLAGS & IN_NO_SAME) == 0) && rdsp_source.total_equals(rdsp_target)) {
            return c_equal_builder<CONFIG, true>::create_converter(dsl_userdata);
        }
        // check equal
        if (((CONFIG::IN_TYPE_FLAGS & IN_NO_EQUAL) == 0) && rdsp_source.total_equals_but_endianess(rdsp_target)) {
            return c_equal_builder<CONFIG, false>::create_converter(dsl_userdata);
        }



        // need table converter
        if (rdsp_source.is_index_based())
        {
            // check table 1
            if ((CONFIG::IN_TYPE_FLAGS & IN_TABLE_1) && rdsp_source.color_depth() == 1) {
                c_converter* adsl_converter = create_table_converter_recursive<MEMORY_PROVIDER, 1>(dsl_userdata);
                if (adsl_converter != NULL)     // TODO: check if direct return
                    return adsl_converter;
            }
            // check table 2
            if ((CONFIG::IN_TYPE_FLAGS & IN_TABLE_2) && rdsp_source.color_depth() == 2) {
                c_converter* adsl_converter = create_table_converter_recursive<MEMORY_PROVIDER, 2>(dsl_userdata);
                if (adsl_converter != NULL)     // TODO: check if direct return
                    return adsl_converter;
            }
            // check table 4
            if ((CONFIG::IN_TYPE_FLAGS & IN_TABLE_4) && rdsp_source.color_depth() == 4) {
                c_converter* adsl_converter = create_table_converter_recursive<MEMORY_PROVIDER, 4>(dsl_userdata);
                if (adsl_converter != NULL)     // TODO: check if direct return
                    return adsl_converter;
            }
            // check table 8
            if ((CONFIG::IN_TYPE_FLAGS & IN_TABLE_8) && rdsp_source.color_depth() == 8) {
                c_converter* adsl_converter = create_table_converter_recursive<MEMORY_PROVIDER, 8>(dsl_userdata);
                if (adsl_converter != NULL)     // TODO: check if direct return
                    return adsl_converter;
            }
        }




        // 'sse2' has highest priority
        if ((CONFIG::IN_TYPE_FLAGS & IN_STATIC_SSE2) && M_DUMMY_SUPPORTS_SSE2(false)) {
            c_converter* adsl_converter = c_static_sse2_builder<CONFIG>::create_converter(dsl_userdata);
            if (adsl_converter != NULL)
                return adsl_converter;
        }
        // 'static' has high priority
        else if (CONFIG::IN_TYPE_FLAGS & IN_STATIC_ALU) {
            c_converter* adsl_converter = c_static_alu_builder<CONFIG>::create_converter(dsl_userdata);
            if (adsl_converter != NULL)
                return adsl_converter;
        }

        

        // 'dynamic reduce' has lowest priority (and is a plan C)
        if (rdsp_source.color_depth() >= rdsp_target.color_depth())
        {
            if (CONFIG::IN_TYPE_FLAGS & IN_DYNAMIC_REDUCE) {
                c_converter* adsl_converter = c_dynamic_builder<CONFIG>::create_converter(dsl_userdata);
                if (adsl_converter != NULL)
                    return adsl_converter;
            }
        }
        else
        {
            // 'dynamic extend' has lowest priority (and is a plan C)
            if (CONFIG::IN_TYPE_FLAGS & IN_DYNAMIC_EXTEND) {
                c_converter* adsl_converter = c_dynamic_builder<CONFIG>::create_converter(dsl_userdata);
                if (adsl_converter != NULL)
                    return adsl_converter;
            }
        }


        throw std::runtime_error("converter not found");
    }
};








} // cc
} // graphics
} // hob

#endif //__HOB_GRAPHiCS_ASS_COLOR_CONVERTER_H__
