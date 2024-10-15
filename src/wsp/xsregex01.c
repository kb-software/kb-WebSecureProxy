/*************************************************
*      Perl-Compatible Regular Expressions       *
*************************************************/

/* PCRE is a library of functions to support regular expressions whose syntax
and semantics are as close as possible to those of the Perl 5 language.

                       Written by Philip Hazel
           Copyright (c) 1997-2008 University of Cambridge

-----------------------------------------------------------------------------
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

    * Neither the name of the University of Cambridge nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
-----------------------------------------------------------------------------
*/

/*+-------------------------------------------------------------------------+*/
/*| includes:                                                               |*/
/*+-------------------------------------------------------------------------+*/
//#include "hob-pcre.h"
#ifndef _HOB_PCRE_H
#define _HOB_PCRE_H
/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT:                                                                |*/
/*| ========                                                                |*/
/*|   Regular Expression search function with utf8 support                  |*/
/*|   based on the pcre library, version 7.8, 2008-09-05                    |*/
/*|   source taken from Philip Hazel, University of Cambridge, BSD          |*/
/*|   watch http://www.pcre.org                                             |*/
/*|                                                                         |*/
/*|   modifications:                                                        |*/
/*|    - removed unused source-code                                         |*/
/*|    - copied all stuff in one file 'pcre.c'                              |*/
/*|    - a lot compiler warnings removed                                    |*/
/*|    - easy to use interface added                                        |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|   Michael Jakobs                                                        |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| =====                                                                   |*/
/*|   in November 2008                                                      |*/
/*|                                                                         |*/
/*| COPYRIGHT:                                                              |*/
/*| ==========                                                              |*/
/*|  HOB GmbH & Co. KG, Germany                                             |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/
#ifndef PTYPE
#   ifdef __cplusplus
#       define PTYPE "C"
#   else
#       define PTYPE
#   endif
#endif

#ifndef BOOL
    typedef int BOOL;
#   define FALSE   0
#   define TRUE    1
#endif

/*+-------------------------------------------------------------------------+*/
/*| type definitions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/* This structure is used as return for m_search_regexp1
   and will keep only first match                                            */
typedef struct dsd_regexp_match1 {
    char* achc_match;                       /* matching string               */
    int   inc_match_len;                    /* length of found match         */
} dsd_regexp_match1;

/* This structure is used as return for m_search_regexp2
   and will keep only all matches                                            */
typedef struct dsd_regexp_match2 {
    char*                     achc_match;   /* matching string               */
    int                       inc_match_len;/* length of found match         */
    struct dsd_regexp_match2* adsc_next;    /* next match (recursive calls)  */
} dsd_regexp_match2;


/*+-------------------------------------------------------------------------+*/
/*| public interface function:                                              |*/
/*+-------------------------------------------------------------------------+*/
/**
 * search with a regular expression in an utf8 string
 * only first match will be returned
 *
 * @param[in]   const char*         ach_regexp          regular expression
 *                                                      example "/\s[abc]/g"
 * @param[in]   int                 in_len_regexp       length of regexp
 * @param[in]   const char*         ach_search_in       string to search in
 *                                                      must be utf8!
 * @param[in]   int                 in_search_len       length of ach_search_in
 * @param[out]  dsd_regexp_match1*  ads_match           first match
 *
 * @return      BOOL
*/
extern PTYPE BOOL m_search_regexp1( const char* ach_regexp, int in_len_regexp,
                                    const char* ach_search_in, int in_search_len,
                                    struct dsd_regexp_match1* ads_match );
/**
 * search with a regular expression in an utf8 string
 * NOTE:
 *   if there is more than one match, dsd_regexp_match will be filled
 *   automaticly, but memory must be freed outside!
 *
 * @param[in]   const char*         ach_regexp          regular expression
 *                                                      example "/\s[abc]/g"
 * @param[in]   int                 in_len_regexp       length of regexp
 * @param[in]   const char*         ach_search_in       string to search in
 *                                                      must be utf8!
 * @param[in]   int                 in_search_len       length of ach_search_in
 * @param[out]  dsd_regexp_match2*  ads_match           matching strings
 *
 * @return      BOOL
*/
extern PTYPE BOOL m_search_regexp2( const char* ach_regexp, int in_len_regexp,
                                    const char* ach_search_in, int in_search_len,
                                    struct dsd_regexp_match2* ads_match );

#endif // _HOB_PCRE_H
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/**
 * check if a matching string an utf8 string exist for given regexp
 *
 * @param[in]   const char*         ach_search_in       string to search in
 *                                                      must be utf8!
 * @param[in]   int                 in_search_len       length of ach_search_in
 * @param[in]   const char*         achp_regexp         regular expression
 *                                                      example "/\s[abc]/g"
 * @param[in]   int                 imp_len_regexp      length of regexp
 *
 * @return      BOOL                                    TRUE = regexp matches
 *                                                      FALSE otherwise
*/
extern BOOL m_search_regex_exists( const char *achp_search_in, int imp_search_len,
                                   const char *achp_regexp, int imp_len_regexp ) {
    BOOL       bol1;
    struct dsd_regexp_match1 dsl_match;

    bol1 = m_search_regexp1( achp_regexp, imp_len_regexp,
                             achp_search_in, imp_search_len,
                             &dsl_match );
    if (    bol1 == TRUE
         && dsl_match.achc_match != NULL
         && dsl_match.inc_match_len > 0 ) {
        return TRUE;
    }
    return FALSE;
} /* end m_search_regex_exists()                                       */

/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/
/* The current PCRE version information. */
#define PCRE_MAJOR          7
#define PCRE_MINOR          8
#define PCRE_DATE           2008-09-05

/* When PCRE is compiled as a C++ library, the subject pointer type can be
replaced with a custom type. For conventional use, the public interface is a
const char *. */
#ifndef PCRE_SPTR
#define PCRE_SPTR const char *
#define USPTR const unsigned char *
#endif

/* When an application links to a PCRE DLL in Windows, the symbols that are
imported have to be identified as such. When building PCRE, the appropriate
export setting is defined in pcre_internal.h, which includes this file. So we
don't change existing definitions of PCRE_EXP_DECL and PCRECPP_EXP_DECL. */
#ifndef PCRE_EXP_DECL
#  ifdef _WIN32
#      define PCRE_EXP_DECL
#      define PCRE_EXP_DEFN
#      define PCRE_EXP_DATA_DEFN
#  else
#    ifdef __cplusplus
#      define PCRE_EXP_DECL       extern "C"
#    else
#      define PCRE_EXP_DECL       extern
#    endif
#    define PCRE_EXP_DEFN       PCRE_EXP_DECL
#    define PCRE_EXP_DATA_DEFN
#  endif
#endif

/* By default, the \R escape sequence matches any Unicode line ending
   character or sequence of characters. If BSR_ANYCRLF is defined, this is
   changed so that backslash-R matches only CR, LF, or CRLF. */
/* #undef BSR_ANYCRLF */

/* The value of LINK_SIZE determines the number of bytes used to store links
   as offsets within the compiled regex. The default is 2, which allows for
   compiled patterns up to 64K long. This covers the vast majority of cases.
   However, PCRE can also be compiled to use 3 or 4 bytes instead. This allows
   for longer patterns in extreme cases. */
#define LINK_SIZE 2

/* The value of MATCH_LIMIT determines the default number of times the
   internal match() function can be called during a single execution of
   pcre_exec(). There is a runtime interface for setting a different limit.
   The limit exists in order to catch runaway regular expressions that take
   for ever to determine that they do not match. The default is set very large
   so that it does not accidentally catch legitimate cases. */
#define MATCH_LIMIT 10000000

/* The above limit applies to all calls of match(), whether or not they
   increase the recursion depth. In some environments it is desirable to limit
   the depth of recursive calls of match() more strictly, in order to restrict
   the maximum amount of stack (or heap, if NO_RECURSE is defined) that is
   used. The value of MATCH_LIMIT_RECURSION applies only to recursive calls of
   match(). To have any useful effect, it must be less than the value of
   MATCH_LIMIT. The default is to use the same value as MATCH_LIMIT. There is
   a runtime method for setting a different limit. */
#define MATCH_LIMIT_RECURSION MATCH_LIMIT

/* This limit is parameterized just in case anybody ever wants to change it.
   Care must be taken if it is increased, because it guards against integer
   overflow caused by enormously large patterns. */
#define MAX_NAME_COUNT 10000

/* This limit is parameterized just in case anybody ever wants to change it.
   Care must be taken if it is increased, because it guards against integer
   overflow caused by enormously large patterns. */
#define MAX_NAME_SIZE 32

/* The value of NEWLINE determines the newline character sequence. On systems
   that support it, "configure" can be used to override the default, which is
   10. The possible values are 10 (LF), 13 (CR), 3338 (CRLF), -1 (ANY), or -2
   (ANYCRLF). */
#define NEWLINE 10

/* PCRE uses recursive function calls to handle backtracking while matching.
   This can sometimes be a problem on systems that have stacks of limited
   size. Define NO_RECURSE to get a version that doesn't use recursion in the
   match() function; instead it creates its own stack by steam using
   pcre_recurse_malloc() to obtain memory from the heap. For more detail, see
   the comments and other stuff just above the match() function. */
/* #undef NO_RECURSE */

/* Define to enable support for Unicode properties */
/* #undef SUPPORT_UCP */

/* Define to enable support for the UTF-8 Unicode encoding. */
#define SUPPORT_UTF8

/* Options */
#define PCRE_CASELESS           0x00000001
#define PCRE_MULTILINE          0x00000002
#define PCRE_DOTALL             0x00000004
#define PCRE_EXTENDED           0x00000008
#define PCRE_ANCHORED           0x00000010
#define PCRE_DOLLAR_ENDONLY     0x00000020
#define PCRE_EXTRA              0x00000040
#define PCRE_NOTBOL             0x00000080
#define PCRE_NOTEOL             0x00000100
#define PCRE_UNGREEDY           0x00000200
#define PCRE_NOTEMPTY           0x00000400
#define PCRE_UTF8               0x00000800
#define PCRE_NO_AUTO_CAPTURE    0x00001000
#define PCRE_NO_UTF8_CHECK      0x00002000
#define PCRE_AUTO_CALLOUT       0x00004000
#define PCRE_PARTIAL            0x00008000
#define PCRE_FIRSTLINE          0x00040000
#define PCRE_DUPNAMES           0x00080000
#define PCRE_NEWLINE_CR         0x00100000
#define PCRE_NEWLINE_LF         0x00200000
#define PCRE_NEWLINE_CRLF       0x00300000
#define PCRE_NEWLINE_ANY        0x00400000
#define PCRE_NEWLINE_ANYCRLF    0x00500000
#define PCRE_BSR_ANYCRLF        0x00800000
#define PCRE_BSR_UNICODE        0x01000000
#define PCRE_JAVASCRIPT_COMPAT  0x02000000

/* Exec-time and get/set-time error codes */
#define PCRE_ERROR_NOMATCH         (-1)
#define PCRE_ERROR_NULL            (-2)
#define PCRE_ERROR_BADOPTION       (-3)
#define PCRE_ERROR_BADMAGIC        (-4)
#define PCRE_ERROR_UNKNOWN_OPCODE  (-5)
#define PCRE_ERROR_UNKNOWN_NODE    (-5)  /* For backward compatibility */
#define PCRE_ERROR_NOMEMORY        (-6)
#define PCRE_ERROR_NOSUBSTRING     (-7)
#define PCRE_ERROR_MATCHLIMIT      (-8)
#define PCRE_ERROR_CALLOUT         (-9)  /* Never used by PCRE itself */
#define PCRE_ERROR_BADUTF8        (-10)
#define PCRE_ERROR_BADUTF8_OFFSET (-11)
#define PCRE_ERROR_PARTIAL        (-12)
#define PCRE_ERROR_BADPARTIAL     (-13)
#define PCRE_ERROR_INTERNAL       (-14)
#define PCRE_ERROR_BADCOUNT       (-15)
#define PCRE_ERROR_RECURSIONLIMIT (-21)
#define PCRE_ERROR_NULLWSLIMIT    (-22)  /* No longer actually used */
#define PCRE_ERROR_BADNEWLINE     (-23)

/* Request types for pcre_fullinfo() */
#define PCRE_INFO_OPTIONS            0
#define PCRE_INFO_SIZE               1
#define PCRE_INFO_CAPTURECOUNT       2
#define PCRE_INFO_BACKREFMAX         3
#define PCRE_INFO_FIRSTBYTE          4
#define PCRE_INFO_FIRSTCHAR          4  /* For backwards compatibility */
#define PCRE_INFO_FIRSTTABLE         5
#define PCRE_INFO_LASTLITERAL        6
#define PCRE_INFO_NAMEENTRYSIZE      7
#define PCRE_INFO_NAMECOUNT          8
#define PCRE_INFO_NAMETABLE          9
#define PCRE_INFO_STUDYSIZE         10
#define PCRE_INFO_DEFAULT_TABLES    11
#define PCRE_INFO_OKPARTIAL         12
#define PCRE_INFO_JCHANGED          13
#define PCRE_INFO_HASCRORLF         14

/* Bit flags for the pcre_extra structure. Do not re-arrange or redefine
these bits, just add new ones on the end, in order to remain compatible. */
#define PCRE_EXTRA_STUDY_DATA             0x0001
#define PCRE_EXTRA_MATCH_LIMIT            0x0002
#define PCRE_EXTRA_CALLOUT_DATA           0x0004
#define PCRE_EXTRA_TABLES                 0x0008
#define PCRE_EXTRA_MATCH_LIMIT_RECURSION  0x0010

/* We need to have types that specify unsigned 16-bit and 32-bit integers. We
cannot determine these outside the compilation (e.g. by running a program as
part of "configure") because PCRE is often cross-compiled for use on other
systems. Instead we make use of the maximum sizes that are available at
preprocessor time in standard C environments. */
#if USHRT_MAX == 65535
  typedef unsigned short pcre_uint16;
  typedef short pcre_int16;
#elif UINT_MAX == 65535
  typedef unsigned int pcre_uint16;
  typedef int pcre_int16;
#else
  #error Cannot determine a type for 16-bit unsigned integers
#endif

#if UINT_MAX == 4294967295
  typedef unsigned int pcre_uint32;
  typedef int pcre_int32;
#elif ULONG_MAX == 4294967295
  typedef unsigned long int pcre_uint32;
  typedef long int pcre_int32;
#else
  #error Cannot determine a type for 32-bit unsigned integers
#endif

/* This is an unsigned int value that no character can ever have. UTF-8
characters only go up to 0x7fffffff (though Unicode doesn't go beyond
0x0010ffff). */
#define NOTACHAR 0xffffffff

/* PCRE is able to support several different kinds of newline (CR, LF, CRLF,
"any" and "anycrlf" at present). The following macros are used to package up
testing for newlines. NLBLOCK, PSSTART, and PSEND are defined in the various
modules to indicate in which datablock the parameters exist, and what the
start/end of string field names are. */
#define NLTYPE_FIXED    0     /* Newline is a fixed length string */
#define NLTYPE_ANY      1     /* Newline is any Unicode line ending */
#define NLTYPE_ANYCRLF  2     /* Newline is CR, LF, or CRLF */

/* These are the public options that can change during matching. */
#define PCRE_IMS (PCRE_CASELESS|PCRE_MULTILINE|PCRE_DOTALL)

/* Private flags containing information about the compiled regex. They used to
live at the top end of the options word, but that got almost full, so now they
are in a 16-bit flags word. */

#define PCRE_NOPARTIAL     0x0001  /* can't use partial with this regex */
#define PCRE_FIRSTSET      0x0002  /* first_byte is set */
#define PCRE_REQCHSET      0x0004  /* req_byte is set */
#define PCRE_STARTLINE     0x0008  /* start after \n for multiline */
#define PCRE_JCHANGED      0x0010  /* j option used in regex */
#define PCRE_HASCRORLF     0x0020  /* explicit \r or \n in pattern */

/* Options for the "extra" block produced by pcre_study(). */
#define PCRE_STUDY_MAPPED   0x01     /* a map of starting chars exists */

/* Masks for identifying the public options that are permitted at compile
time, run time, or study time, respectively. */
#define PCRE_NEWLINE_BITS (PCRE_NEWLINE_CR|PCRE_NEWLINE_LF|PCRE_NEWLINE_ANY| \
                           PCRE_NEWLINE_ANYCRLF)

#define PUBLIC_OPTIONS \
  (PCRE_CASELESS|PCRE_EXTENDED|PCRE_ANCHORED|PCRE_MULTILINE| \
   PCRE_DOTALL|PCRE_DOLLAR_ENDONLY|PCRE_EXTRA|PCRE_UNGREEDY|PCRE_UTF8| \
   PCRE_NO_AUTO_CAPTURE|PCRE_NO_UTF8_CHECK|PCRE_AUTO_CALLOUT|PCRE_FIRSTLINE| \
   PCRE_DUPNAMES|PCRE_NEWLINE_BITS|PCRE_BSR_ANYCRLF|PCRE_BSR_UNICODE| \
   PCRE_JAVASCRIPT_COMPAT)

#define PUBLIC_EXEC_OPTIONS \
  (PCRE_ANCHORED|PCRE_NOTBOL|PCRE_NOTEOL|PCRE_NOTEMPTY|PCRE_NO_UTF8_CHECK| \
   PCRE_PARTIAL|PCRE_NEWLINE_BITS|PCRE_BSR_ANYCRLF|PCRE_BSR_UNICODE)

/* Magic number to provide a small check against being handed junk. Also used
to detect whether a pattern was compiled on a host of different endianness. */

#define MAGIC_NUMBER  0x50435245UL   /* 'PCRE' */

/* Negative values for the firstchar and reqchar variables */
#define REQ_UNSET (-2)
#define REQ_NONE  (-1)

/* The maximum remaining length of subject we are prepared to search for a
req_byte match. */
#define REQ_BYTE_MAX 1000

/* Flags added to firstbyte or reqbyte; a "non-literal" item is either a
variable-length repeat, or a anything other than literal characters. */
#define REQ_CASELESS 0x0100    /* indicates caselessness */
#define REQ_VARY     0x0200    /* reqbyte followed non-literal item */

/* Miscellaneous definitions. The #ifndef is to pacify compiler warnings in
environments where these macros are defined elsewhere. */
#ifndef FALSE
typedef int BOOL;

#define FALSE   0
#define TRUE    1
#endif

/* Escape items that are just an encoding of a particular data value. */
#ifndef ESC_e
#define ESC_e 27
#endif

#ifndef ESC_f
#define ESC_f '\f'
#endif

#ifndef ESC_n
#define ESC_n '\n'
#endif

#ifndef ESC_r
#define ESC_r '\r'
#endif

/* We can't officially use ESC_t because it is a POSIX reserved identifier
(presumably because of all the others like size_t). */
#ifndef ESC_tee
#define ESC_tee '\t'
#endif

/* Codes for different types of Unicode property */
#define PT_ANY        0    /* Any property - matches all chars */
#define PT_LAMP       1    /* L& - the union of Lu, Ll, Lt */
#define PT_GC         2    /* General characteristic (e.g. L) */
#define PT_PC         3    /* Particular characteristic (e.g. Lu) */
#define PT_SC         4    /* Script (e.g. Han) */

/* Flag bits and data types for the extended class (OP_XCLASS) for classes that
contain UTF-8 characters with values greater than 255. */
#define XCL_NOT    0x01    /* Flag: this is a negative class */
#define XCL_MAP    0x02    /* Flag: a 32-byte map is present */
#define XCL_END       0    /* Marks end of individual items */
#define XCL_SINGLE    1    /* Single item (one multibyte char) follows */
#define XCL_RANGE     2    /* A range (two multibyte chars) follows */
#define XCL_PROP      3    /* Unicode property (2-byte property code follows) */
#define XCL_NOTPROP   4    /* Unicode inverted property (ditto) */

/* Bit definitions for entries in the pcre_ctypes table. */
#define ctype_space   0x01
#define ctype_letter  0x02
#define ctype_digit   0x04
#define ctype_xdigit  0x08
#define ctype_word    0x10   /* alphanumeric or '_' */
#define ctype_meta    0x80   /* regexp meta char or zero (end pattern) */

/* Offsets for the bitmap tables in pcre_cbits. Each table contains a set
of bits for a class map. Some classes are built by combining these tables. */
#define cbit_space     0      /* [:space:] or \s */
#define cbit_xdigit   32      /* [:xdigit:] */
#define cbit_digit    64      /* [:digit:] or \d */
#define cbit_upper    96      /* [:upper:] */
#define cbit_lower   128      /* [:lower:] */
#define cbit_word    160      /* [:word:] or \w */
#define cbit_graph   192      /* [:graph:] */
#define cbit_print   224      /* [:print:] */
#define cbit_punct   256      /* [:punct:] */
#define cbit_cntrl   288      /* [:cntrl:] */
#define cbit_length  320      /* Length of the cbits table */

/* Offsets of the various tables from the base tables pointer, and
total length. */
#define lcc_offset      0
#define fcc_offset    256
#define cbits_offset  512
#define ctypes_offset (cbits_offset + cbit_length)
#define tables_length (ctypes_offset + 256)

/***************************************************************************
****************************************************************************
                   RECURSION IN THE match() FUNCTION

The match() function is highly recursive, though not every recursive call
increases the recursive depth. Nevertheless, some regular expressions can cause
it to recurse to a great depth. I was writing for Unix, so I just let it call
itself recursively. This uses the stack for saving everything that has to be
saved for a recursive call. On Unix, the stack can be large, and this works
fine.

It turns out that on some non-Unix-like systems there are problems with
programs that use a lot of stack. (This despite the fact that every last chip
has oodles of memory these days, and techniques for extending the stack have
been known for decades.) So....

There is a fudge, triggered by defining NO_RECURSE, which avoids recursive
calls by keeping local variables that need to be preserved in blocks of memory
obtained from malloc() instead instead of on the stack. Macros are used to
achieve this so that the actual code doesn't look very different to what it
always used to.

The original heap-recursive code used longjmp(). However, it seems that this
can be very slow on some operating systems. Following a suggestion from Stan
Switzer, the use of longjmp() has been abolished, at the cost of having to
provide a unique number for each call to RMATCH. There is no way of generating
a sequence of numbers at compile time in C. I have given them names, to make
them stand out more clearly.

Crude tests on x86 Linux show a small speedup of around 5-8%. However, on
FreeBSD, avoiding longjmp() more than halves the time taken to run the standard
tests. Furthermore, not using longjmp() means that local dynamic variables
don't have indeterminate values; this has meant that the frame size can be
reduced because the result can be "passed back" by straight setting of the
variable instead of being passed in the frame.
****************************************************************************
***************************************************************************/

/* Numbers for RMATCH calls. When this list is changed, the code at HEAP_RETURN
below must be updated in sync.  */

enum { RM1=1, RM2,  RM3,  RM4,  RM5,  RM6,  RM7,  RM8,  RM9,  RM10,
       RM11,  RM12, RM13, RM14, RM15, RM16, RM17, RM18, RM19, RM20,
       RM21,  RM22, RM23, RM24, RM25, RM26, RM27, RM28, RM29, RM30,
       RM31,  RM32, RM33, RM34, RM35, RM36, RM37, RM38, RM39, RM40,
       RM41,  RM42, RM43, RM44, RM45, RM46, RM47, RM48, RM49, RM50,
       RM51,  RM52, RM53, RM54 };

/* These versions of the macros use the stack, as normal. There are debugging
versions and production versions. Note that the "rw" argument of RMATCH isn't
actuall used in this definition. */

#ifndef NO_RECURSE
#define REGISTER register

#ifdef DEBUG
#define RMATCH(ra,rb,rc,rd,re,rf,rg,rw) \
  { \
  printf("match() called in line %d\n", __LINE__); \
  rrc = match(ra,rb,mstart,rc,rd,re,rf,rg,rdepth+1); \
  printf("to line %d\n", __LINE__); \
  }
#define RRETURN(ra) \
  { \
  printf("match() returned %d from line %d ", ra, __LINE__); \
  return ra; \
  }
#else
#define RMATCH(ra,rb,rc,rd,re,rf,rg,rw) \
  rrc = match(ra,rb,mstart,rc,rd,re,rf,rg,rdepth+1)
#define RRETURN(ra) return ra
#endif

#else


/* These versions of the macros manage a private stack on the heap. Note that
the "rd" argument of RMATCH isn't actually used in this definition. It's the md
argument of match(), which never changes. */

#define REGISTER

#define RMATCH(ra,rb,rc,rd,re,rf,rg,rw)\
  {\
  heapframe *newframe = (pcre_stack_malloc)(sizeof(heapframe));\
  frame->Xwhere = rw; \
  newframe->Xeptr = ra;\
  newframe->Xecode = rb;\
  newframe->Xmstart = mstart;\
  newframe->Xoffset_top = rc;\
  newframe->Xims = re;\
  newframe->Xeptrb = rf;\
  newframe->Xflags = rg;\
  newframe->Xrdepth = frame->Xrdepth + 1;\
  newframe->Xprevframe = frame;\
  frame = newframe;\
  DPRINTF(("restarting from line %d\n", __LINE__));\
  goto HEAP_RECURSE;\
  L_##rw:\
  DPRINTF(("jumped back to line %d\n", __LINE__));\
  }

#define RRETURN(ra)\
  {\
  heapframe *newframe = frame;\
  frame = newframe->Xprevframe;\
  (pcre_stack_free)(newframe);\
  if (frame != NULL)\
    {\
    rrc = ra;\
    goto HEAP_RETURN;\
    }\
  return ra;\
  }


/* Structure for remembering the local variables in a private frame */

typedef struct heapframe {
  struct heapframe *Xprevframe;

  /* Function arguments that may change */

  const uschar *Xeptr;
  const uschar *Xecode;
  const uschar *Xmstart;
  int Xoffset_top;
  long int Xims;
  eptrblock *Xeptrb;
  int Xflags;
  unsigned int Xrdepth;

  /* Function local variables */

  const uschar *Xcallpat;
  const uschar *Xcharptr;
  const uschar *Xdata;
  const uschar *Xnext;
  const uschar *Xpp;
  const uschar *Xprev;
  const uschar *Xsaved_eptr;

  recursion_info Xnew_recursive;

  BOOL Xcur_is_word;
  BOOL Xcondition;
  BOOL Xprev_is_word;

  unsigned long int Xoriginal_ims;

#ifdef SUPPORT_UCP
  int Xprop_type;
  int Xprop_value;
  int Xprop_fail_result;
  int Xprop_category;
  int Xprop_chartype;
  int Xprop_script;
  int Xoclength;
  uschar Xocchars[8];
#endif

  int Xctype;
  unsigned int Xfc;
  int Xfi;
  int Xlength;
  int Xmax;
  int Xmin;
  int Xnumber;
  int Xoffset;
  int Xop;
  int Xsave_capture_last;
  int Xsave_offset1, Xsave_offset2, Xsave_offset3;
  int Xstacksave[REC_STACK_SAVE_MAX];

  eptrblock Xnewptrb;

  /* Where to jump back to */

  int Xwhere;

} heapframe;

#endif

/* This value specifies the size of stack workspace that is used during the
first pre-compile phase that determines how much memory is required. The regex
is partly compiled into this space, but the compiled parts are discarded as
soon as they can be, so that hopefully there will never be an overrun. The code
does, however, check for an overrun. The largest amount I've seen used is 218,
so this number is very generous.

The same workspace is used during the second, actual compile phase for
remembering forward references to groups so that they can be filled in at the
end. Each entry in this list occupies LINK_SIZE bytes, so even when LINK_SIZE
is 4 there is plenty of room. */
#define COMPILE_WORK_SIZE (4096)

/*+-------------------------------------------------------------------------+*/
/*| type definitions:                                                       |*/
/*+-------------------------------------------------------------------------+*/

/* The structure for passing additional data to pcre_exec(). This is defined in
such as way as to be extensible. Always add new fields at the end, in order to
remain compatible. */
typedef struct pcre_extra {
  unsigned long int flags;        /* Bits for which fields are set */
  void *study_data;               /* Opaque data from pcre_study() */
  unsigned long int match_limit;  /* Maximum number of calls to match() */
  void *callout_data;             /* Data passed back in callouts */
  const unsigned char *tables;    /* Pointer to character tables */
  unsigned long int match_limit_recursion; /* Max recursive calls to match() */
} pcre_extra;

/* The structure for passing out data via the pcre_callout_function. We use a
structure so that new fields can be added on the end in future versions,
without changing the API of the function, thereby allowing old clients to work
without modification. */
typedef struct pcre_callout_block {
  int          version;           /* Identifies version of block */
  /* ------------------------ Version 0 ------------------------------- */
  int          callout_number;    /* Number compiled into pattern */
  int         *offset_vector;     /* The offset vector */
  PCRE_SPTR    subject;           /* The subject being matched */
  int          subject_length;    /* The length of the subject */
  int          start_match;       /* Offset to start of this match attempt */
  int          current_position;  /* Where we currently are in the subject */
  int          capture_top;       /* Max current capture */
  int          capture_last;      /* Most recently closed capture */
  void        *callout_data;      /* Data passed in with the call */
  /* ------------------- Added for Version 1 -------------------------- */
  int          pattern_position;  /* Offset to next item in the pattern */
  int          next_item_length;  /* Length of next item in the pattern */
  /* ------------------------------------------------------------------ */
} pcre_callout_block;

/* The real format of the start of the pcre block; the index of names and the
code vector run on as long as necessary after the end. We store an explicit
offset to the name table so that if a regex is compiled on one host, saved, and
then run on another where the size of pointers is different, all might still
be well. For the case of compiled-on-4 and run-on-8, we include an extra
pointer that is always NULL. For future-proofing, a few dummy fields were
originally included - even though you can never get this planning right - but
there is only one left now.
*/
typedef struct real_pcre {
  pcre_uint32 magic_number;
  pcre_uint32 size;               /* Total that was malloced */
  pcre_uint32 options;            /* Public options */
  pcre_uint16 flags;              /* Private flags */
  pcre_uint16 dummy1;             /* For future use */
  pcre_uint16 top_bracket;
  pcre_uint16 top_backref;
  pcre_uint16 first_byte;
  pcre_uint16 req_byte;
  pcre_uint16 name_table_offset;  /* Offset to name table that follows */
  pcre_uint16 name_entry_size;    /* Size of any name items */
  pcre_uint16 name_count;         /* Number of name items */
  pcre_uint16 ref_count;          /* Reference count */

  const unsigned char *tables;    /* Pointer to tables or NULL for std */
  const unsigned char *nullpad;   /* NULL padding */
} real_pcre;
typedef struct real_pcre pcre;

/* All character handling must be done as unsigned characters. Otherwise there
are problems with top-bit-set characters and functions such as isspace().
However, we leave the interface to the outside world as char *, because that
should make things easier for callers. We define a short type for unsigned char
to save lots of typing. I tried "uchar", but it causes problems on Digital
Unix, where it is defined in sys/types, so use "uschar" instead. */
typedef unsigned char uschar;

/* The format of the block used to store data from pcre_study(). The same
remark (see NOTE above) about extending this structure applies. */
typedef struct pcre_study_data {
  pcre_uint32 size;               /* Total that was malloced */
  pcre_uint32 options;
  uschar start_bits[32];
} pcre_study_data;

/* Structure for passing "static" information around between the functions
doing the compiling, so that they are thread-safe. */
typedef struct compile_data {
  const uschar *lcc;            /* Points to lower casing table */
  const uschar *fcc;            /* Points to case-flipping table */
  const uschar *cbits;          /* Points to character type table */
  const uschar *ctypes;         /* Points to table of type maps */
  const uschar *start_workspace;/* The start of working space */
  const uschar *start_code;     /* The start of the compiled code */
  const uschar *start_pattern;  /* The start of the pattern */
  const uschar *end_pattern;    /* The end of the pattern */
  uschar *hwm;                  /* High watermark of workspace */
  uschar *name_table;           /* The name/number table */
  int  names_found;             /* Number of entries so far */
  int  name_entry_size;         /* Size of each entry */
  int  bracount;                /* Count of capturing parens as we compile */
  int  final_bracount;          /* Saved value after first pass */
  int  top_backref;             /* Maximum back reference */
  unsigned int backref_map;     /* Bitmap of low back refs */
  int  external_options;        /* External (initial) options */
  int  external_flags;          /* External flag bits to be set */
  int  req_varyopt;             /* "After variable item" flag for reqbyte */
  BOOL had_accept;              /* (*ACCEPT) encountered */
  int  nltype;                  /* Newline type */
  int  nllen;                   /* Newline string length */
  uschar nl[4];                 /* Newline string when fixed length */
} compile_data;

/* Structure for maintaining a chain of pointers to the currently incomplete
branches, for testing for left recursion. */
typedef struct branch_chain {
  struct branch_chain *outer;
  uschar *current;
} branch_chain;

/* Structure for items in a linked list that represents an explicit recursive
call within the pattern. */
typedef struct recursion_info {
  struct recursion_info *prevrec; /* Previous recursion record (or NULL) */
  int group_num;                /* Number of group that was called */
  const uschar *after_call;     /* "Return value": points after the call in the expr */
  USPTR save_start;             /* Old value of mstart */
  int *offset_save;             /* Pointer to start of saved offsets */
  int saved_max;                /* Number of saved offsets */
} recursion_info;

/* Structure for building a chain of data for holding the values of the subject
pointer at the start of each subpattern, so as to detect when an empty string
has been matched by a subpattern - to break infinite loops. */
typedef struct eptrblock {
  struct eptrblock *epb_prev;
  USPTR epb_saved_eptr;
} eptrblock;


/* Structure for passing "static" information around between the functions
doing traditional NFA matching, so that they are thread-safe. */
typedef struct match_data {
  unsigned long int match_call_count;      /* As it says */
  unsigned long int match_limit;           /* As it says */
  unsigned long int match_limit_recursion; /* As it says */
  int   *offset_vector;         /* Offset vector */
  int    offset_end;            /* One past the end */
  int    offset_max;            /* The maximum usable for return data */
  int    nltype;                /* Newline type */
  int    nllen;                 /* Newline string length */
  uschar nl[4];                 /* Newline string when fixed */
  const uschar *lcc;            /* Points to lower casing table */
  const uschar *ctypes;         /* Points to table of type maps */
  BOOL   offset_overflow;       /* Set if too many extractions */
  BOOL   notbol;                /* NOTBOL flag */
  BOOL   noteol;                /* NOTEOL flag */
  BOOL   utf8;                  /* UTF8 flag */
  BOOL   jscript_compat;        /* JAVASCRIPT_COMPAT flag */
  BOOL   endonly;               /* Dollar not before final \n */
  BOOL   notempty;              /* Empty string match not wanted */
  BOOL   partial;               /* PARTIAL flag */
  BOOL   hitend;                /* Hit the end of the subject at some point */
  BOOL   bsr_anycrlf;           /* \R is just any CRLF, not full Unicode */
  const uschar *start_code;     /* For use when recursing */
  USPTR  start_subject;         /* Start of the subject string */
  USPTR  end_subject;           /* End of the subject string */
  USPTR  start_match_ptr;       /* Start of matched string */
  USPTR  end_match_ptr;         /* Subject position at end match */
  int    end_offset_top;        /* Highwater mark at end of match */
  int    capture_last;          /* Most recent capture number */
  int    start_offset;          /* The start offset value */
  eptrblock *eptrchain;         /* Chain of eptrblocks for tail recursions */
  int    eptrn;                 /* Next free eptrblock */
  recursion_info *recursive;    /* Linked list of recursion data */
  void  *callout_data;          /* To pass back to callouts */
} match_data;

/* Layout of the UCP type table that translates property names into types and
codes. Each entry used to point directly to a name, but to reduce the number of
relocations in shared libraries, it now has an offset into a single string
instead. */
typedef struct {
  pcre_uint16 name_offset;
  pcre_uint16 type;
  pcre_uint16 value;
} ucp_type_table;

/* Unicode character database (UCD) */
typedef struct {
  uschar script;
  uschar chartype;
  pcre_int32 other_case;
} ucd_record;



/*+-------------------------------------------------------------------------+*/
/*| macro definitions:                                                      |*/
/*+-------------------------------------------------------------------------+*/

/* Use a macro for debugging printing, 'cause that eliminates the use of #ifdef
inline, and there are *still* stupid compilers about that don't like indented
pre-processor statements, or at least there were when I first wrote this. After
all, it had only been about 10 years then...

It turns out that the Mac Debugging.h header also defines the macro DPRINTF, so
be absolutely sure we get our version. */
#undef DPRINTF
#ifdef DEBUG
#define DPRINTF(p) printf p
#else
#define DPRINTF(p) /* Nothing */
#endif

/* This macro checks for a newline at the given position */
#define IS_NEWLINE(p) \
  ((NLBLOCK->nltype != NLTYPE_FIXED)? \
    ((p) < NLBLOCK->PSEND && \
     _pcre_is_newline((p), NLBLOCK->nltype, NLBLOCK->PSEND, &(NLBLOCK->nllen),\
       utf8)) \
    : \
    ((p) <= NLBLOCK->PSEND - NLBLOCK->nllen && \
     (p)[0] == NLBLOCK->nl[0] && \
     (NLBLOCK->nllen == 1 || (p)[1] == NLBLOCK->nl[1]) \
    ) \
  )

/* This macro checks for a newline immediately preceding the given position */
#define WAS_NEWLINE(p) \
  ((NLBLOCK->nltype != NLTYPE_FIXED)? \
    ((p) > NLBLOCK->PSSTART && \
     _pcre_was_newline((p), NLBLOCK->nltype, NLBLOCK->PSSTART, \
       &(NLBLOCK->nllen), utf8)) \
    : \
    ((p) >= NLBLOCK->PSSTART + NLBLOCK->nllen && \
     (p)[-NLBLOCK->nllen] == NLBLOCK->nl[0] && \
     (NLBLOCK->nllen == 1 || (p)[-NLBLOCK->nllen+1] == NLBLOCK->nl[1]) \
    ) \
  )

/* PCRE keeps offsets in its compiled code as 2-byte quantities (always stored
in big-endian order) by default. These are used, for example, to link from the
start of a subpattern to its alternatives and its end. The use of 2 bytes per
offset limits the size of the compiled regex to around 64K, which is big enough
for almost everybody. However, I received a request for an even bigger limit.
For this reason, and also to make the code easier to maintain, the storing and
loading of offsets from the byte string is now handled by the macros that are
defined here. */
#if LINK_SIZE == 2

#define PUT(a,n,d)   \
  (a[n] = (uschar)((d) >> 8)), \
  (a[(n)+1] = (uschar)((d) & 255))

#define GET(a,n) \
  (((a)[n] << 8) | (a)[(n)+1])

#define MAX_PATTERN_SIZE (1 << 16)


#elif LINK_SIZE == 3

#define PUT(a,n,d)       \
  (a[n] = (d) >> 16),    \
  (a[(n)+1] = (d) >> 8), \
  (a[(n)+2] = (d) & 255)

#define GET(a,n) \
  (((a)[n] << 16) | ((a)[(n)+1] << 8) | (a)[(n)+2])

#define MAX_PATTERN_SIZE (1 << 24)


#elif LINK_SIZE == 4

#define PUT(a,n,d)        \
  (a[n] = (d) >> 24),     \
  (a[(n)+1] = (d) >> 16), \
  (a[(n)+2] = (d) >> 8),  \
  (a[(n)+3] = (d) & 255)

#define GET(a,n) \
  (((a)[n] << 24) | ((a)[(n)+1] << 16) | ((a)[(n)+2] << 8) | (a)[(n)+3])

#define MAX_PATTERN_SIZE (1 << 30)   /* Keep it positive */


#else
#error LINK_SIZE must be either 2, 3, or 4
#endif

/* Convenience macro defined in terms of the others */
#define PUTINC(a,n,d)   PUT(a,n,d), a += LINK_SIZE

/* PCRE uses some other 2-byte quantities that do not change when the size of
offsets changes. There are used for repeat counts and for other things such as
capturing parenthesis numbers in back references. */
#define PUT2(a,n,d)   \
  a[n] = (uschar)((d) >> 8); \
  a[(n)+1] = (uschar)((d) & 255)

#define GET2(a,n) \
  (((a)[n] << 8) | (a)[(n)+1])

#define PUT2INC(a,n,d)  PUT2(a,n,d), a += 2

/* When UTF-8 encoding is being used, a character is no longer just a single
byte. The macros for character handling generate simple sequences when used in
byte-mode, and more complicated ones for UTF-8 characters. BACKCHAR should
never be called in byte mode. To make sure it can never even appear when UTF-8
support is omitted, we don't even define it. */
#ifndef SUPPORT_UTF8
#define GETCHAR(c, eptr) c = *eptr;
#define GETCHARTEST(c, eptr) c = *eptr;
#define GETCHARINC(c, eptr) c = *eptr++;
#define GETCHARINCTEST(c, eptr) c = *eptr++;
#define GETCHARLEN(c, eptr, len) c = *eptr;
/* #define BACKCHAR(eptr) */
#else   /* SUPPORT_UTF8 */
/* Get the next UTF-8 character, not advancing the pointer. This is called when
we know we are in UTF-8 mode. */
#define GETCHAR(c, eptr) \
  c = *eptr; \
  if (c >= 0xc0) \
    { \
    int gcii; \
    int gcaa = _pcre_utf8_table4[c & 0x3f];  /* Number of additional bytes */ \
    int gcss = 6*gcaa; \
    c = (c & _pcre_utf8_table3[gcaa]) << gcss; \
    for (gcii = 1; gcii <= gcaa; gcii++) \
      { \
      gcss -= 6; \
      c |= (eptr[gcii] & 0x3f) << gcss; \
      } \
    }

/* Get the next UTF-8 character, testing for UTF-8 mode, and not advancing the
pointer. */
#define GETCHARTEST(c, eptr) \
  c = *eptr; \
  if (utf8 && c >= 0xc0) \
    { \
    int gcii; \
    int gcaa = _pcre_utf8_table4[c & 0x3f];  /* Number of additional bytes */ \
    int gcss = 6*gcaa; \
    c = (c & _pcre_utf8_table3[gcaa]) << gcss; \
    for (gcii = 1; gcii <= gcaa; gcii++) \
      { \
      gcss -= 6; \
      c |= (eptr[gcii] & 0x3f) << gcss; \
      } \
    }

/* Get the next UTF-8 character, advancing the pointer. This is called when we
know we are in UTF-8 mode. */
#define GETCHARINC(c, eptr) \
  c = *eptr++; \
  if (c >= 0xc0) \
    { \
    int gcaa = _pcre_utf8_table4[c & 0x3f];  /* Number of additional bytes */ \
    int gcss = 6*gcaa; \
    c = (c & _pcre_utf8_table3[gcaa]) << gcss; \
    while (gcaa-- > 0) \
      { \
      gcss -= 6; \
      c |= (*eptr++ & 0x3f) << gcss; \
      } \
    }

/* Get the next character, testing for UTF-8 mode, and advancing the pointer */
#define GETCHARINCTEST(c, eptr) \
  c = *eptr++; \
  if (utf8 && c >= 0xc0) \
    { \
    int gcaa = _pcre_utf8_table4[c & 0x3f];  /* Number of additional bytes */ \
    int gcss = 6*gcaa; \
    c = (c & _pcre_utf8_table3[gcaa]) << gcss; \
    while (gcaa-- > 0) \
      { \
      gcss -= 6; \
      c |= (*eptr++ & 0x3f) << gcss; \
      } \
    }

/* Get the next UTF-8 character, not advancing the pointer, incrementing length
if there are extra bytes. This is called when we know we are in UTF-8 mode. */
#define GETCHARLEN(c, eptr, len) \
  c = *eptr; \
  if (c >= 0xc0) \
    { \
    int gcii; \
    int gcaa = _pcre_utf8_table4[c & 0x3f];  /* Number of additional bytes */ \
    int gcss = 6*gcaa; \
    c = (c & _pcre_utf8_table3[gcaa]) << gcss; \
    for (gcii = 1; gcii <= gcaa; gcii++) \
      { \
      gcss -= 6; \
      c |= (eptr[gcii] & 0x3f) << gcss; \
      } \
    len += gcaa; \
    }

/* If the pointer is not at the start of a character, move it back until
it is. This is called only in UTF-8 mode - we don't put a test within the macro
because almost all calls are already within a block of UTF-8 only code. */
#define BACKCHAR(eptr) while((*eptr & 0xc0) == 0x80) eptr--

#endif

/* UCD access macros */
#define UCD_BLOCK_SIZE 128
#define GET_UCD(ch) (_pcre_ucd_records + \
        _pcre_ucd_stage2[_pcre_ucd_stage1[(ch) / UCD_BLOCK_SIZE] * \
        UCD_BLOCK_SIZE + ch % UCD_BLOCK_SIZE])

#define UCD_CHARTYPE(ch)  GET_UCD(ch)->chartype
#define UCD_SCRIPT(ch)    GET_UCD(ch)->script
#define UCD_CATEGORY(ch)  _pcre_ucp_gentype[UCD_CHARTYPE(ch)]
#define UCD_OTHERCASE(ch) (ch + GET_UCD(ch)->other_case)


PCRE_EXP_DATA_DEFN void *(*pcre_malloc)(size_t) = malloc;
PCRE_EXP_DATA_DEFN void  (*pcre_free)(void *) = free;
PCRE_EXP_DATA_DEFN void *(*pcre_stack_malloc)(size_t) = malloc;
PCRE_EXP_DATA_DEFN void  (*pcre_stack_free)(void *) = free;
PCRE_EXP_DATA_DEFN int   (*pcre_callout)(pcre_callout_block *) = NULL;

/* Macro for setting individual bits in class bitmaps. */
#define SETBIT(a,b) a[b/8] |= (1 << (b%8))

/* Maximum length value to check against when making sure that the integer that
holds the compiled pattern length does not overflow. We make it a bit less than
INT_MAX to allow for adding in group terminating bytes, so that we don't have
to check them every time. */
#define OFLOW_MAX (INT_MAX - 20)

#define STRING(a)  # a
#define XSTRING(s) STRING(s)

/* Undefine some potentially clashing cpp symbols */
#undef min
#undef max

/* Flag bits for the match() function */
#define match_condassert     0x01  /* Called to check a condition assertion */
#define match_cbegroup       0x02  /* Could-be-empty unlimited repeat group */

/* Non-error returns from the match() function. Error returns are externally
defined PCRE_ERROR_xxx codes, which are all negative. */
#define MATCH_MATCH        1
#define MATCH_NOMATCH      0

/* Special internal returns from the match() function. Make them sufficiently
negative to avoid the external error codes. */
#define MATCH_COMMIT       (-999)
#define MATCH_PRUNE        (-998)
#define MATCH_SKIP         (-997)
#define MATCH_THEN         (-996)

/* Maximum number of ints of offset to save on the stack for recursive calls.
If the offset vector is bigger, malloc is used. This should be a multiple of 3,
because the offset vector is always a multiple of 3 long. */
#define REC_STACK_SAVE_MAX 30

/***************************************************************************
****************************************************************************
                   RECURSION IN THE match() FUNCTION

Undefine all the macros that were defined above to handle this. */

#ifdef NO_RECURSE
#undef eptr
#undef ecode
#undef mstart
#undef offset_top
#undef ims
#undef eptrb
#undef flags

#undef callpat
#undef charptr
#undef data
#undef next
#undef pp
#undef prev
#undef saved_eptr

#undef new_recursive

#undef cur_is_word
#undef condition
#undef prev_is_word

#undef original_ims

#undef ctype
#undef length
#undef max
#undef min
#undef number
#undef offset
#undef op
#undef save_capture_last
#undef save_offset1
#undef save_offset2
#undef save_offset3
#undef stacksave

#undef newptrb

#endif

/* These two are defined as macros in both cases */

#undef fc
#undef fi

/***************************************************************************
***************************************************************************/


/*+-------------------------------------------------------------------------+*/
/*| global constants:                                                       |*/
/*+-------------------------------------------------------------------------+*/

/* These are the general character categories. */
enum {
  ucp_C,     /* Other */
  ucp_L,     /* Letter */
  ucp_M,     /* Mark */
  ucp_N,     /* Number */
  ucp_P,     /* Punctuation */
  ucp_S,     /* Symbol */
  ucp_Z      /* Separator */
};

/* These are the particular character types. */
enum {
  ucp_Cc,    /* Control */
  ucp_Cf,    /* Format */
  ucp_Cn,    /* Unassigned */
  ucp_Co,    /* Private use */
  ucp_Cs,    /* Surrogate */
  ucp_Ll,    /* Lower case letter */
  ucp_Lm,    /* Modifier letter */
  ucp_Lo,    /* Other letter */
  ucp_Lt,    /* Title case letter */
  ucp_Lu,    /* Upper case letter */
  ucp_Mc,    /* Spacing mark */
  ucp_Me,    /* Enclosing mark */
  ucp_Mn,    /* Non-spacing mark */
  ucp_Nd,    /* Decimal number */
  ucp_Nl,    /* Letter number */
  ucp_No,    /* Other number */
  ucp_Pc,    /* Connector punctuation */
  ucp_Pd,    /* Dash punctuation */
  ucp_Pe,    /* Close punctuation */
  ucp_Pf,    /* Final punctuation */
  ucp_Pi,    /* Initial punctuation */
  ucp_Po,    /* Other punctuation */
  ucp_Ps,    /* Open punctuation */
  ucp_Sc,    /* Currency symbol */
  ucp_Sk,    /* Modifier symbol */
  ucp_Sm,    /* Mathematical symbol */
  ucp_So,    /* Other symbol */
  ucp_Zl,    /* Line separator */
  ucp_Zp,    /* Paragraph separator */
  ucp_Zs     /* Space separator */
};

/* These are the script identifications. */
enum {
  ucp_Arabic,
  ucp_Armenian,
  ucp_Bengali,
  ucp_Bopomofo,
  ucp_Braille,
  ucp_Buginese,
  ucp_Buhid,
  ucp_Canadian_Aboriginal,
  ucp_Cherokee,
  ucp_Common,
  ucp_Coptic,
  ucp_Cypriot,
  ucp_Cyrillic,
  ucp_Deseret,
  ucp_Devanagari,
  ucp_Ethiopic,
  ucp_Georgian,
  ucp_Glagolitic,
  ucp_Gothic,
  ucp_Greek,
  ucp_Gujarati,
  ucp_Gurmukhi,
  ucp_Han,
  ucp_Hangul,
  ucp_Hanunoo,
  ucp_Hebrew,
  ucp_Hiragana,
  ucp_Inherited,
  ucp_Kannada,
  ucp_Katakana,
  ucp_Kharoshthi,
  ucp_Khmer,
  ucp_Lao,
  ucp_Latin,
  ucp_Limbu,
  ucp_Linear_B,
  ucp_Malayalam,
  ucp_Mongolian,
  ucp_Myanmar,
  ucp_New_Tai_Lue,
  ucp_Ogham,
  ucp_Old_Italic,
  ucp_Old_Persian,
  ucp_Oriya,
  ucp_Osmanya,
  ucp_Runic,
  ucp_Shavian,
  ucp_Sinhala,
  ucp_Syloti_Nagri,
  ucp_Syriac,
  ucp_Tagalog,
  ucp_Tagbanwa,
  ucp_Tai_Le,
  ucp_Tamil,
  ucp_Telugu,
  ucp_Thaana,
  ucp_Thai,
  ucp_Tibetan,
  ucp_Tifinagh,
  ucp_Ugaritic,
  ucp_Yi,
  /* New for Unicode 5.0: */
  ucp_Balinese,
  ucp_Cuneiform,
  ucp_Nko,
  ucp_Phags_Pa,
  ucp_Phoenician,
  /* New for Unicode 5.1: */
  ucp_Carian,
  ucp_Cham,
  ucp_Kayah_Li,
  ucp_Lepcha,
  ucp_Lycian,
  ucp_Lydian,
  ucp_Ol_Chiki,
  ucp_Rejang,
  ucp_Saurashtra,
  ucp_Sundanese,
  ucp_Vai
};

/* These are escaped items that aren't just an encoding of a particular data
value such as \n. They must have non-zero values, as check_escape() returns
their negation. Also, they must appear in the same order as in the opcode
definitions below, up to ESC_z. There's a dummy for OP_ANY because it
corresponds to "." rather than an escape sequence, and another for OP_ALLANY
(which is used for [^] in JavaScript compatibility mode).

The final escape must be ESC_REF as subsequent values are used for
backreferences (\1, \2, \3, etc). There are two tests in the code for an escape
greater than ESC_b and less than ESC_Z to detect the types that may be
repeated. These are the types that consume characters. If any new escapes are
put in between that don't consume a character, that code will have to change.
*/
enum { ESC_A = 1, ESC_G, ESC_K, ESC_B, ESC_b, ESC_D, ESC_d, ESC_S, ESC_s,
       ESC_W, ESC_w, ESC_dum1, ESC_dum2, ESC_C, ESC_P, ESC_p, ESC_R, ESC_H,
       ESC_h, ESC_V, ESC_v, ESC_X, ESC_Z, ESC_z, ESC_E, ESC_Q, ESC_g, ESC_k,
       ESC_REF };


/* Opcode table: Starting from 1 (i.e. after OP_END), the values up to
OP_EOD must correspond in order to the list of escapes immediately above.

*** NOTE NOTE NOTE *** Whenever this list is updated, the two macro definitions
that follow must also be updated to match. There is also a table called
"coptable" in pcre_dfa_exec.c that must be updated. */
enum {
  OP_END,            /* 0 End of pattern */
  /* Values corresponding to backslashed metacharacters */
  OP_SOD,            /* 1 Start of data: \A */
  OP_SOM,            /* 2 Start of match (subject + offset): \G */
  OP_SET_SOM,        /* 3 Set start of match (\K) */
  OP_NOT_WORD_BOUNDARY,  /*  4 \B */
  OP_WORD_BOUNDARY,      /*  5 \b */
  OP_NOT_DIGIT,          /*  6 \D */
  OP_DIGIT,              /*  7 \d */
  OP_NOT_WHITESPACE,     /*  8 \S */
  OP_WHITESPACE,         /*  9 \s */
  OP_NOT_WORDCHAR,       /* 10 \W */
  OP_WORDCHAR,           /* 11 \w */
  OP_ANY,            /* 12 Match any character (subject to DOTALL) */
  OP_ALLANY,         /* 13 Match any character (not subject to DOTALL) */
  OP_ANYBYTE,        /* 14 Match any byte (\C); different to OP_ANY for UTF-8 */
  OP_NOTPROP,        /* 15 \P (not Unicode property) */
  OP_PROP,           /* 16 \p (Unicode property) */
  OP_ANYNL,          /* 17 \R (any newline sequence) */
  OP_NOT_HSPACE,     /* 18 \H (not horizontal whitespace) */
  OP_HSPACE,         /* 19 \h (horizontal whitespace) */
  OP_NOT_VSPACE,     /* 20 \V (not vertical whitespace) */
  OP_VSPACE,         /* 21 \v (vertical whitespace) */
  OP_EXTUNI,         /* 22 \X (extended Unicode sequence */
  OP_EODN,           /* 23 End of data or \n at end of data: \Z. */
  OP_EOD,            /* 24 End of data: \z */
  OP_OPT,            /* 25 Set runtime options */
  OP_CIRC,           /* 26 Start of line - varies with multiline switch */
  OP_DOLL,           /* 27 End of line - varies with multiline switch */
  OP_CHAR,           /* 28 Match one character, casefully */
  OP_CHARNC,         /* 29 Match one character, caselessly */
  OP_NOT,            /* 30 Match one character, not the following one */
  OP_STAR,           /* 31 The maximizing and minimizing versions of */
  OP_MINSTAR,        /* 32 these six opcodes must come in pairs, with */
  OP_PLUS,           /* 33 the minimizing one second. */
  OP_MINPLUS,        /* 34 This first set applies to single characters.*/
  OP_QUERY,          /* 35 */
  OP_MINQUERY,       /* 36 */
  OP_UPTO,           /* 37 From 0 to n matches */
  OP_MINUPTO,        /* 38 */
  OP_EXACT,          /* 39 Exactly n matches */
  OP_POSSTAR,        /* 40 Possessified star */
  OP_POSPLUS,        /* 41 Possessified plus */
  OP_POSQUERY,       /* 42 Posesssified query */
  OP_POSUPTO,        /* 43 Possessified upto */
  OP_NOTSTAR,        /* 44 The maximizing and minimizing versions of */
  OP_NOTMINSTAR,     /* 45 these six opcodes must come in pairs, with */
  OP_NOTPLUS,        /* 46 the minimizing one second. They must be in */
  OP_NOTMINPLUS,     /* 47 exactly the same order as those above. */
  OP_NOTQUERY,       /* 48 This set applies to "not" single characters. */
  OP_NOTMINQUERY,    /* 49 */
  OP_NOTUPTO,        /* 50 From 0 to n matches */
  OP_NOTMINUPTO,     /* 51 */
  OP_NOTEXACT,       /* 52 Exactly n matches */
  OP_NOTPOSSTAR,     /* 53 Possessified versions */
  OP_NOTPOSPLUS,     /* 54 */
  OP_NOTPOSQUERY,    /* 55 */
  OP_NOTPOSUPTO,     /* 56 */
  OP_TYPESTAR,       /* 57 The maximizing and minimizing versions of */
  OP_TYPEMINSTAR,    /* 58 these six opcodes must come in pairs, with */
  OP_TYPEPLUS,       /* 59 the minimizing one second. These codes must */
  OP_TYPEMINPLUS,    /* 60 be in exactly the same order as those above. */
  OP_TYPEQUERY,      /* 61 This set applies to character types such as \d */
  OP_TYPEMINQUERY,   /* 62 */
  OP_TYPEUPTO,       /* 63 From 0 to n matches */
  OP_TYPEMINUPTO,    /* 64 */
  OP_TYPEEXACT,      /* 65 Exactly n matches */
  OP_TYPEPOSSTAR,    /* 66 Possessified versions */
  OP_TYPEPOSPLUS,    /* 67 */
  OP_TYPEPOSQUERY,   /* 68 */
  OP_TYPEPOSUPTO,    /* 69 */
  OP_CRSTAR,         /* 70 The maximizing and minimizing versions of */
  OP_CRMINSTAR,      /* 71 all these opcodes must come in pairs, with */
  OP_CRPLUS,         /* 72 the minimizing one second. These codes must */
  OP_CRMINPLUS,      /* 73 be in exactly the same order as those above. */
  OP_CRQUERY,        /* 74 These are for character classes and back refs */
  OP_CRMINQUERY,     /* 75 */
  OP_CRRANGE,        /* 76 These are different to the three sets above. */
  OP_CRMINRANGE,     /* 77 */
  OP_CLASS,          /* 78 Match a character class, chars < 256 only */
  OP_NCLASS,         /* 79 Same, but the bitmap was created from a negative
                           class - the difference is relevant only when a UTF-8
                           character > 255 is encountered. */
  OP_XCLASS,         /* 80 Extended class for handling UTF-8 chars within the
                           class. This does both positive and negative. */
  OP_REF,            /* 81 Match a back reference */
  OP_RECURSE,        /* 82 Match a numbered subpattern (possibly recursive) */
  OP_CALLOUT,        /* 83 Call out to external function if provided */
  OP_ALT,            /* 84 Start of alternation */
  OP_KET,            /* 85 End of group that doesn't have an unbounded repeat */
  OP_KETRMAX,        /* 86 These two must remain together and in this */
  OP_KETRMIN,        /* 87 order. They are for groups the repeat for ever. */
  /* The assertions must come before BRA, CBRA, ONCE, and COND.*/
  OP_ASSERT,         /* 88 Positive lookahead */
  OP_ASSERT_NOT,     /* 89 Negative lookahead */
  OP_ASSERTBACK,     /* 90 Positive lookbehind */
  OP_ASSERTBACK_NOT, /* 91 Negative lookbehind */
  OP_REVERSE,        /* 92 Move pointer back - used in lookbehind assertions */
  /* ONCE, BRA, CBRA, and COND must come after the assertions, with ONCE first,
  as there's a test for >= ONCE for a subpattern that isn't an assertion. */
  OP_ONCE,           /* 93 Atomic group */
  OP_BRA,            /* 94 Start of non-capturing bracket */
  OP_CBRA,           /* 95 Start of capturing bracket */
  OP_COND,           /* 96 Conditional group */
  /* These three must follow the previous three, in the same order. There's a
  check for >= SBRA to distinguish the two sets. */
  OP_SBRA,           /* 97 Start of non-capturing bracket, check empty  */
  OP_SCBRA,          /* 98 Start of capturing bracket, check empty */
  OP_SCOND,          /* 99 Conditional group, check empty */
  OP_CREF,           /* 100 Used to hold a capture number as condition */
  OP_RREF,           /* 101 Used to hold a recursion number as condition */
  OP_DEF,            /* 102 The DEFINE condition */
  OP_BRAZERO,        /* 103 These two must remain together and in this */
  OP_BRAMINZERO,     /* 104 order. */
  /* These are backtracking control verbs */
  OP_PRUNE,          /* 105 */
  OP_SKIP,           /* 106 */
  OP_THEN,           /* 107 */
  OP_COMMIT,         /* 108 */
  /* These are forced failure and success verbs */
  OP_FAIL,           /* 109 */
  OP_ACCEPT,         /* 110 */
  /* This is used to skip a subpattern with a {0} quantifier */
  OP_SKIPZERO        /* 111 */
};


/* This macro defines the length of fixed length operations in the compiled
regex. The lengths are used when searching for specific things, and also in the
debugging printing of a compiled regex. We use a macro so that it can be
defined close to the definitions of the opcodes themselves.

As things have been extended, some of these are no longer fixed lenths, but are
minima instead. For example, the length of a single-character repeat may vary
in UTF-8 mode. The code that uses this table must know about such things. */
#define OP_LENGTHS \
  1,                             /* End                                    */ \
  1, 1, 1, 1, 1,                 /* \A, \G, \K, \B, \b                     */ \
  1, 1, 1, 1, 1, 1,              /* \D, \d, \S, \s, \W, \w                 */ \
  1, 1, 1,                       /* Any, AllAny, Anybyte                   */ \
  3, 3, 1,                       /* NOTPROP, PROP, EXTUNI                  */ \
  1, 1, 1, 1, 1,                 /* \R, \H, \h, \V, \v                     */ \
  1, 1, 2, 1, 1,                 /* \Z, \z, Opt, ^, $                      */ \
  2,                             /* Char  - the minimum length             */ \
  2,                             /* Charnc  - the minimum length           */ \
  2,                             /* not                                    */ \
  /* Positive single-char repeats                            ** These are  */ \
  2, 2, 2, 2, 2, 2,              /* *, *?, +, +?, ?, ??      ** minima in  */ \
  4, 4, 4,                       /* upto, minupto, exact     ** UTF-8 mode */ \
  2, 2, 2, 4,                    /* *+, ++, ?+, upto+                      */ \
  /* Negative single-char repeats - only for chars < 256                   */ \
  2, 2, 2, 2, 2, 2,              /* NOT *, *?, +, +?, ?, ??                */ \
  4, 4, 4,                       /* NOT upto, minupto, exact               */ \
  2, 2, 2, 4,                    /* Possessive *, +, ?, upto               */ \
  /* Positive type repeats                                                 */ \
  2, 2, 2, 2, 2, 2,              /* Type *, *?, +, +?, ?, ??               */ \
  4, 4, 4,                       /* Type upto, minupto, exact              */ \
  2, 2, 2, 4,                    /* Possessive *+, ++, ?+, upto+           */ \
  /* Character class & ref repeats                                         */ \
  1, 1, 1, 1, 1, 1,              /* *, *?, +, +?, ?, ??                    */ \
  5, 5,                          /* CRRANGE, CRMINRANGE                    */ \
 33,                             /* CLASS                                  */ \
 33,                             /* NCLASS                                 */ \
  0,                             /* XCLASS - variable length               */ \
  3,                             /* REF                                    */ \
  1+LINK_SIZE,                   /* RECURSE                                */ \
  2+2*LINK_SIZE,                 /* CALLOUT                                */ \
  1+LINK_SIZE,                   /* Alt                                    */ \
  1+LINK_SIZE,                   /* Ket                                    */ \
  1+LINK_SIZE,                   /* KetRmax                                */ \
  1+LINK_SIZE,                   /* KetRmin                                */ \
  1+LINK_SIZE,                   /* Assert                                 */ \
  1+LINK_SIZE,                   /* Assert not                             */ \
  1+LINK_SIZE,                   /* Assert behind                          */ \
  1+LINK_SIZE,                   /* Assert behind not                      */ \
  1+LINK_SIZE,                   /* Reverse                                */ \
  1+LINK_SIZE,                   /* ONCE                                   */ \
  1+LINK_SIZE,                   /* BRA                                    */ \
  3+LINK_SIZE,                   /* CBRA                                   */ \
  1+LINK_SIZE,                   /* COND                                   */ \
  1+LINK_SIZE,                   /* SBRA                                   */ \
  3+LINK_SIZE,                   /* SCBRA                                  */ \
  1+LINK_SIZE,                   /* SCOND                                  */ \
  3,                             /* CREF                                   */ \
  3,                             /* RREF                                   */ \
  1,                             /* DEF                                    */ \
  1, 1,                          /* BRAZERO, BRAMINZERO                    */ \
  1, 1, 1, 1,                    /* PRUNE, SKIP, THEN, COMMIT,             */ \
  1, 1, 1                        /* FAIL, ACCEPT, SKIPZERO                 */


/* A magic value for OP_RREF to indicate the "any recursion" condition. */
#define RREF_ANY  0xffff

/* Error code numbers. They are given names so that they can more easily be
tracked. */
enum { ERR0,  ERR1,  ERR2,  ERR3,  ERR4,  ERR5,  ERR6,  ERR7,  ERR8,  ERR9,
       ERR10, ERR11, ERR12, ERR13, ERR14, ERR15, ERR16, ERR17, ERR18, ERR19,
       ERR20, ERR21, ERR22, ERR23, ERR24, ERR25, ERR26, ERR27, ERR28, ERR29,
       ERR30, ERR31, ERR32, ERR33, ERR34, ERR35, ERR36, ERR37, ERR38, ERR39,
       ERR40, ERR41, ERR42, ERR43, ERR44, ERR45, ERR46, ERR47, ERR48, ERR49,
       ERR50, ERR51, ERR52, ERR53, ERR54, ERR55, ERR56, ERR57, ERR58, ERR59,
       ERR60, ERR61, ERR62, ERR63, ERR64 };


/* Table of sizes for the fixed-length opcodes. It's defined in a macro so that
the definition is next to the definition of the opcodes in pcre_internal.h. */
const uschar _pcre_OP_lengths[] = { OP_LENGTHS };

/*************************************************
*           Tables for UTF-8 support             *
*************************************************/
/* These are the breakpoints for different numbers of bytes in a UTF-8
character. */
#ifdef SUPPORT_UTF8
const int _pcre_utf8_table1[] =
  { 0x7f, 0x7ff, 0xffff, 0x1fffff, 0x3ffffff, 0x7fffffff};

const int _pcre_utf8_table1_size = sizeof(_pcre_utf8_table1)/sizeof(int);

/* These are the indicator bits and the mask for the data bits to set in the
first byte of a character, indexed by the number of additional bytes. */
const int _pcre_utf8_table2[] = { 0,    0xc0, 0xe0, 0xf0, 0xf8, 0xfc};
const int _pcre_utf8_table3[] = { 0xff, 0x1f, 0x0f, 0x07, 0x03, 0x01};

/* Table of the number of extra bytes, indexed by the first byte masked with
0x3f. The highest number for a valid UTF-8 first byte is in fact 0x3d. */
const uschar _pcre_utf8_table4[] = {
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  3,3,3,3,3,3,3,3,4,4,4,4,5,5,5,5 };

/* Table to translate from particular type value to the general value. */
const int _pcre_ucp_gentype[] = {
  ucp_C, ucp_C, ucp_C, ucp_C, ucp_C,  /* Cc, Cf, Cn, Co, Cs */
  ucp_L, ucp_L, ucp_L, ucp_L, ucp_L,  /* Ll, Lu, Lm, Lo, Lt */
  ucp_M, ucp_M, ucp_M,                /* Mc, Me, Mn */
  ucp_N, ucp_N, ucp_N,                /* Nd, Nl, No */
  ucp_P, ucp_P, ucp_P, ucp_P, ucp_P,  /* Pc, Pd, Pe, Pf, Pi */
  ucp_P, ucp_P,                       /* Ps, Po */
  ucp_S, ucp_S, ucp_S, ucp_S,         /* Sc, Sk, Sm, So */
  ucp_Z, ucp_Z, ucp_Z                 /* Zl, Zp, Zs */
};

/* The pcre_utt[] table below translates Unicode property names into type and
code values. It is searched by binary chop, so must be in collating sequence of
name. Originally, the table contained pointers to the name strings in the first
field of each entry. However, that leads to a large number of relocations when
a shared library is dynamically loaded. A significant reduction is made by
putting all the names into a single, large string and then using offsets in the
table itself. Maintenance is more error-prone, but frequent changes to this
data are unlikely.

July 2008: There is now a script called maint/GenerateUtt.py which can be used
to generate this data instead of maintaining it entirely by hand. */
const char _pcre_utt_names[] =
  "Any\0"
  "Arabic\0"
  "Armenian\0"
  "Balinese\0"
  "Bengali\0"
  "Bopomofo\0"
  "Braille\0"
  "Buginese\0"
  "Buhid\0"
  "C\0"
  "Canadian_Aboriginal\0"
  "Carian\0"
  "Cc\0"
  "Cf\0"
  "Cham\0"
  "Cherokee\0"
  "Cn\0"
  "Co\0"
  "Common\0"
  "Coptic\0"
  "Cs\0"
  "Cuneiform\0"
  "Cypriot\0"
  "Cyrillic\0"
  "Deseret\0"
  "Devanagari\0"
  "Ethiopic\0"
  "Georgian\0"
  "Glagolitic\0"
  "Gothic\0"
  "Greek\0"
  "Gujarati\0"
  "Gurmukhi\0"
  "Han\0"
  "Hangul\0"
  "Hanunoo\0"
  "Hebrew\0"
  "Hiragana\0"
  "Inherited\0"
  "Kannada\0"
  "Katakana\0"
  "Kayah_Li\0"
  "Kharoshthi\0"
  "Khmer\0"
  "L\0"
  "L&\0"
  "Lao\0"
  "Latin\0"
  "Lepcha\0"
  "Limbu\0"
  "Linear_B\0"
  "Ll\0"
  "Lm\0"
  "Lo\0"
  "Lt\0"
  "Lu\0"
  "Lycian\0"
  "Lydian\0"
  "M\0"
  "Malayalam\0"
  "Mc\0"
  "Me\0"
  "Mn\0"
  "Mongolian\0"
  "Myanmar\0"
  "N\0"
  "Nd\0"
  "New_Tai_Lue\0"
  "Nko\0"
  "Nl\0"
  "No\0"
  "Ogham\0"
  "Ol_Chiki\0"
  "Old_Italic\0"
  "Old_Persian\0"
  "Oriya\0"
  "Osmanya\0"
  "P\0"
  "Pc\0"
  "Pd\0"
  "Pe\0"
  "Pf\0"
  "Phags_Pa\0"
  "Phoenician\0"
  "Pi\0"
  "Po\0"
  "Ps\0"
  "Rejang\0"
  "Runic\0"
  "S\0"
  "Saurashtra\0"
  "Sc\0"
  "Shavian\0"
  "Sinhala\0"
  "Sk\0"
  "Sm\0"
  "So\0"
  "Sundanese\0"
  "Syloti_Nagri\0"
  "Syriac\0"
  "Tagalog\0"
  "Tagbanwa\0"
  "Tai_Le\0"
  "Tamil\0"
  "Telugu\0"
  "Thaana\0"
  "Thai\0"
  "Tibetan\0"
  "Tifinagh\0"
  "Ugaritic\0"
  "Vai\0"
  "Yi\0"
  "Z\0"
  "Zl\0"
  "Zp\0"
  "Zs\0";

const ucp_type_table _pcre_utt[] = {
  {   0, PT_ANY, 0 },
  {   4, PT_SC, ucp_Arabic },
  {  11, PT_SC, ucp_Armenian },
  {  20, PT_SC, ucp_Balinese },
  {  29, PT_SC, ucp_Bengali },
  {  37, PT_SC, ucp_Bopomofo },
  {  46, PT_SC, ucp_Braille },
  {  54, PT_SC, ucp_Buginese },
  {  63, PT_SC, ucp_Buhid },
  {  69, PT_GC, ucp_C },
  {  71, PT_SC, ucp_Canadian_Aboriginal },
  {  91, PT_SC, ucp_Carian },
  {  98, PT_PC, ucp_Cc },
  { 101, PT_PC, ucp_Cf },
  { 104, PT_SC, ucp_Cham },
  { 109, PT_SC, ucp_Cherokee },
  { 118, PT_PC, ucp_Cn },
  { 121, PT_PC, ucp_Co },
  { 124, PT_SC, ucp_Common },
  { 131, PT_SC, ucp_Coptic },
  { 138, PT_PC, ucp_Cs },
  { 141, PT_SC, ucp_Cuneiform },
  { 151, PT_SC, ucp_Cypriot },
  { 159, PT_SC, ucp_Cyrillic },
  { 168, PT_SC, ucp_Deseret },
  { 176, PT_SC, ucp_Devanagari },
  { 187, PT_SC, ucp_Ethiopic },
  { 196, PT_SC, ucp_Georgian },
  { 205, PT_SC, ucp_Glagolitic },
  { 216, PT_SC, ucp_Gothic },
  { 223, PT_SC, ucp_Greek },
  { 229, PT_SC, ucp_Gujarati },
  { 238, PT_SC, ucp_Gurmukhi },
  { 247, PT_SC, ucp_Han },
  { 251, PT_SC, ucp_Hangul },
  { 258, PT_SC, ucp_Hanunoo },
  { 266, PT_SC, ucp_Hebrew },
  { 273, PT_SC, ucp_Hiragana },
  { 282, PT_SC, ucp_Inherited },
  { 292, PT_SC, ucp_Kannada },
  { 300, PT_SC, ucp_Katakana },
  { 309, PT_SC, ucp_Kayah_Li },
  { 318, PT_SC, ucp_Kharoshthi },
  { 329, PT_SC, ucp_Khmer },
  { 335, PT_GC, ucp_L },
  { 337, PT_LAMP, 0 },
  { 340, PT_SC, ucp_Lao },
  { 344, PT_SC, ucp_Latin },
  { 350, PT_SC, ucp_Lepcha },
  { 357, PT_SC, ucp_Limbu },
  { 363, PT_SC, ucp_Linear_B },
  { 372, PT_PC, ucp_Ll },
  { 375, PT_PC, ucp_Lm },
  { 378, PT_PC, ucp_Lo },
  { 381, PT_PC, ucp_Lt },
  { 384, PT_PC, ucp_Lu },
  { 387, PT_SC, ucp_Lycian },
  { 394, PT_SC, ucp_Lydian },
  { 401, PT_GC, ucp_M },
  { 403, PT_SC, ucp_Malayalam },
  { 413, PT_PC, ucp_Mc },
  { 416, PT_PC, ucp_Me },
  { 419, PT_PC, ucp_Mn },
  { 422, PT_SC, ucp_Mongolian },
  { 432, PT_SC, ucp_Myanmar },
  { 440, PT_GC, ucp_N },
  { 442, PT_PC, ucp_Nd },
  { 445, PT_SC, ucp_New_Tai_Lue },
  { 457, PT_SC, ucp_Nko },
  { 461, PT_PC, ucp_Nl },
  { 464, PT_PC, ucp_No },
  { 467, PT_SC, ucp_Ogham },
  { 473, PT_SC, ucp_Ol_Chiki },
  { 482, PT_SC, ucp_Old_Italic },
  { 493, PT_SC, ucp_Old_Persian },
  { 505, PT_SC, ucp_Oriya },
  { 511, PT_SC, ucp_Osmanya },
  { 519, PT_GC, ucp_P },
  { 521, PT_PC, ucp_Pc },
  { 524, PT_PC, ucp_Pd },
  { 527, PT_PC, ucp_Pe },
  { 530, PT_PC, ucp_Pf },
  { 533, PT_SC, ucp_Phags_Pa },
  { 542, PT_SC, ucp_Phoenician },
  { 553, PT_PC, ucp_Pi },
  { 556, PT_PC, ucp_Po },
  { 559, PT_PC, ucp_Ps },
  { 562, PT_SC, ucp_Rejang },
  { 569, PT_SC, ucp_Runic },
  { 575, PT_GC, ucp_S },
  { 577, PT_SC, ucp_Saurashtra },
  { 588, PT_PC, ucp_Sc },
  { 591, PT_SC, ucp_Shavian },
  { 599, PT_SC, ucp_Sinhala },
  { 607, PT_PC, ucp_Sk },
  { 610, PT_PC, ucp_Sm },
  { 613, PT_PC, ucp_So },
  { 616, PT_SC, ucp_Sundanese },
  { 626, PT_SC, ucp_Syloti_Nagri },
  { 639, PT_SC, ucp_Syriac },
  { 646, PT_SC, ucp_Tagalog },
  { 654, PT_SC, ucp_Tagbanwa },
  { 663, PT_SC, ucp_Tai_Le },
  { 670, PT_SC, ucp_Tamil },
  { 676, PT_SC, ucp_Telugu },
  { 683, PT_SC, ucp_Thaana },
  { 690, PT_SC, ucp_Thai },
  { 695, PT_SC, ucp_Tibetan },
  { 703, PT_SC, ucp_Tifinagh },
  { 712, PT_SC, ucp_Ugaritic },
  { 721, PT_SC, ucp_Vai },
  { 725, PT_SC, ucp_Yi },
  { 728, PT_GC, ucp_Z },
  { 730, PT_PC, ucp_Zl },
  { 733, PT_PC, ucp_Zp },
  { 736, PT_PC, ucp_Zs }
};

const int _pcre_utt_size = sizeof(_pcre_utt)/sizeof(ucp_type_table);

#endif  /* SUPPORT_UTF8 */

/* Character tables that are used when no external tables are passed to PCRE
by the application that calls it. The tables are used only for characters
whose code values are less than 256. */
const unsigned char _pcre_default_tables[] = {
/* This table is a lower casing table. */
    0,  1,  2,  3,  4,  5,  6,  7,
    8,  9, 10, 11, 12, 13, 14, 15,
   16, 17, 18, 19, 20, 21, 22, 23,
   24, 25, 26, 27, 28, 29, 30, 31,
   32, 33, 34, 35, 36, 37, 38, 39,
   40, 41, 42, 43, 44, 45, 46, 47,
   48, 49, 50, 51, 52, 53, 54, 55,
   56, 57, 58, 59, 60, 61, 62, 63,
   64, 97, 98, 99,100,101,102,103,
  104,105,106,107,108,109,110,111,
  112,113,114,115,116,117,118,119,
  120,121,122, 91, 92, 93, 94, 95,
   96, 97, 98, 99,100,101,102,103,
  104,105,106,107,108,109,110,111,
  112,113,114,115,116,117,118,119,
  120,121,122,123,124,125,126,127,
  128,129,130,131,132,133,134,135,
  136,137,138,139,140,141,142,143,
  144,145,146,147,148,149,150,151,
  152,153,154,155,156,157,158,159,
  160,161,162,163,164,165,166,167,
  168,169,170,171,172,173,174,175,
  176,177,178,179,180,181,182,183,
  184,185,186,187,188,189,190,191,
  192,193,194,195,196,197,198,199,
  200,201,202,203,204,205,206,207,
  208,209,210,211,212,213,214,215,
  216,217,218,219,220,221,222,223,
  224,225,226,227,228,229,230,231,
  232,233,234,235,236,237,238,239,
  240,241,242,243,244,245,246,247,
  248,249,250,251,252,253,254,255,
/* This table is a case flipping table. */
    0,  1,  2,  3,  4,  5,  6,  7,
    8,  9, 10, 11, 12, 13, 14, 15,
   16, 17, 18, 19, 20, 21, 22, 23,
   24, 25, 26, 27, 28, 29, 30, 31,
   32, 33, 34, 35, 36, 37, 38, 39,
   40, 41, 42, 43, 44, 45, 46, 47,
   48, 49, 50, 51, 52, 53, 54, 55,
   56, 57, 58, 59, 60, 61, 62, 63,
   64, 97, 98, 99,100,101,102,103,
  104,105,106,107,108,109,110,111,
  112,113,114,115,116,117,118,119,
  120,121,122, 91, 92, 93, 94, 95,
   96, 65, 66, 67, 68, 69, 70, 71,
   72, 73, 74, 75, 76, 77, 78, 79,
   80, 81, 82, 83, 84, 85, 86, 87,
   88, 89, 90,123,124,125,126,127,
  128,129,130,131,132,133,134,135,
  136,137,138,139,140,141,142,143,
  144,145,146,147,148,149,150,151,
  152,153,154,155,156,157,158,159,
  160,161,162,163,164,165,166,167,
  168,169,170,171,172,173,174,175,
  176,177,178,179,180,181,182,183,
  184,185,186,187,188,189,190,191,
  192,193,194,195,196,197,198,199,
  200,201,202,203,204,205,206,207,
  208,209,210,211,212,213,214,215,
  216,217,218,219,220,221,222,223,
  224,225,226,227,228,229,230,231,
  232,233,234,235,236,237,238,239,
  240,241,242,243,244,245,246,247,
  248,249,250,251,252,253,254,255,
/* This table contains bit maps for various character classes. Each map is 32
bytes long and the bits run from the least significant end of each byte. The
classes that have their own maps are: space, xdigit, digit, upper, lower, word,
graph, print, punct, and cntrl. Other classes are built from combinations. */
  0x00,0x3e,0x00,0x00,0x01,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

  0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x03,
  0x7e,0x00,0x00,0x00,0x7e,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

  0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x03,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0xfe,0xff,0xff,0x07,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0xfe,0xff,0xff,0x07,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

  0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x03,
  0xfe,0xff,0xff,0x87,0xfe,0xff,0xff,0x07,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

  0x00,0x00,0x00,0x00,0xfe,0xff,0xff,0xff,
  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

  0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

  0x00,0x00,0x00,0x00,0xfe,0xff,0x00,0xfc,
  0x01,0x00,0x00,0xf8,0x01,0x00,0x00,0x78,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

  0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

/* This table identifies various classes of character by individual bits:
  0x01   white space character
  0x02   letter
  0x04   decimal digit
  0x08   hexadecimal digit
  0x10   alphanumeric or '_'
  0x80   regular expression metacharacter or binary zero
*/
  0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /*   0-  7 */
  0x00,0x01,0x01,0x00,0x01,0x01,0x00,0x00, /*   8- 15 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /*  16- 23 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /*  24- 31 */
  0x01,0x00,0x00,0x00,0x80,0x00,0x00,0x00, /*    - '  */
  0x80,0x80,0x80,0x80,0x00,0x00,0x80,0x00, /*  ( - /  */
  0x1c,0x1c,0x1c,0x1c,0x1c,0x1c,0x1c,0x1c, /*  0 - 7  */
  0x1c,0x1c,0x00,0x00,0x00,0x00,0x00,0x80, /*  8 - ?  */
  0x00,0x1a,0x1a,0x1a,0x1a,0x1a,0x1a,0x12, /*  @ - G  */
  0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12, /*  H - O  */
  0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12, /*  P - W  */
  0x12,0x12,0x12,0x80,0x80,0x00,0x80,0x10, /*  X - _  */
  0x00,0x1a,0x1a,0x1a,0x1a,0x1a,0x1a,0x12, /*  ` - g  */
  0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12, /*  h - o  */
  0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12, /*  p - w  */
  0x12,0x12,0x12,0x80,0x80,0x00,0x00,0x00, /*  x -127 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 128-135 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 136-143 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 144-151 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 152-159 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 160-167 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 168-175 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 176-183 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 184-191 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 192-199 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 200-207 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 208-215 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 216-223 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 224-231 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 232-239 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 240-247 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};/* 248-255 */


/* Unicode character database. */
const ucd_record _pcre_ucd_records[] = { /* 3656 bytes, record size 8 */
  {     9,      0,      0, }, /*   0 */
  {     9,     29,      0, }, /*   1 */
  {     9,     21,      0, }, /*   2 */
  {     9,     23,      0, }, /*   3 */
  {     9,     22,      0, }, /*   4 */
  {     9,     18,      0, }, /*   5 */
  {     9,     25,      0, }, /*   6 */
  {     9,     17,      0, }, /*   7 */
  {     9,     13,      0, }, /*   8 */
  {    33,      9,     32, }, /*   9 */
  {     9,     24,      0, }, /*  10 */
  {     9,     16,      0, }, /*  11 */
  {    33,      5,    -32, }, /*  12 */
  {     9,     26,      0, }, /*  13 */
  {    33,      5,      0, }, /*  14 */
  {     9,     20,      0, }, /*  15 */
  {     9,      1,      0, }, /*  16 */
  {     9,     15,      0, }, /*  17 */
  {     9,      5,    743, }, /*  18 */
  {     9,     19,      0, }, /*  19 */
  {    33,      5,    121, }, /*  20 */
  {    33,      9,      1, }, /*  21 */
  {    33,      5,     -1, }, /*  22 */
  {    33,      9,   -199, }, /*  23 */
  {    33,      5,   -232, }, /*  24 */
  {    33,      9,   -121, }, /*  25 */
  {    33,      5,   -300, }, /*  26 */
  {    33,      5,    195, }, /*  27 */
  {    33,      9,    210, }, /*  28 */
  {    33,      9,    206, }, /*  29 */
  {    33,      9,    205, }, /*  30 */
  {    33,      9,     79, }, /*  31 */
  {    33,      9,    202, }, /*  32 */
  {    33,      9,    203, }, /*  33 */
  {    33,      9,    207, }, /*  34 */
  {    33,      5,     97, }, /*  35 */
  {    33,      9,    211, }, /*  36 */
  {    33,      9,    209, }, /*  37 */
  {    33,      5,    163, }, /*  38 */
  {    33,      9,    213, }, /*  39 */
  {    33,      5,    130, }, /*  40 */
  {    33,      9,    214, }, /*  41 */
  {    33,      9,    218, }, /*  42 */
  {    33,      9,    217, }, /*  43 */
  {    33,      9,    219, }, /*  44 */
  {    33,      7,      0, }, /*  45 */
  {    33,      5,     56, }, /*  46 */
  {    33,      9,      2, }, /*  47 */
  {    33,      8,     -1, }, /*  48 */
  {    33,      5,     -2, }, /*  49 */
  {    33,      5,    -79, }, /*  50 */
  {    33,      9,    -97, }, /*  51 */
  {    33,      9,    -56, }, /*  52 */
  {    33,      9,   -130, }, /*  53 */
  {    33,      9,  10795, }, /*  54 */
  {    33,      9,   -163, }, /*  55 */
  {    33,      9,  10792, }, /*  56 */
  {    33,      9,   -195, }, /*  57 */
  {    33,      9,     69, }, /*  58 */
  {    33,      9,     71, }, /*  59 */
  {    33,      5,  10783, }, /*  60 */
  {    33,      5,  10780, }, /*  61 */
  {    33,      5,   -210, }, /*  62 */
  {    33,      5,   -206, }, /*  63 */
  {    33,      5,   -205, }, /*  64 */
  {    33,      5,   -202, }, /*  65 */
  {    33,      5,   -203, }, /*  66 */
  {    33,      5,   -207, }, /*  67 */
  {    33,      5,   -209, }, /*  68 */
  {    33,      5,   -211, }, /*  69 */
  {    33,      5,  10743, }, /*  70 */
  {    33,      5,  10749, }, /*  71 */
  {    33,      5,   -213, }, /*  72 */
  {    33,      5,   -214, }, /*  73 */
  {    33,      5,  10727, }, /*  74 */
  {    33,      5,   -218, }, /*  75 */
  {    33,      5,    -69, }, /*  76 */
  {    33,      5,   -217, }, /*  77 */
  {    33,      5,    -71, }, /*  78 */
  {    33,      5,   -219, }, /*  79 */
  {    33,      6,      0, }, /*  80 */
  {     9,      6,      0, }, /*  81 */
  {    27,     12,      0, }, /*  82 */
  {    27,     12,     84, }, /*  83 */
  {    19,      9,      1, }, /*  84 */
  {    19,      5,     -1, }, /*  85 */
  {    19,     24,      0, }, /*  86 */
  {     9,      2,      0, }, /*  87 */
  {    19,      6,      0, }, /*  88 */
  {    19,      5,    130, }, /*  89 */
  {    19,      9,     38, }, /*  90 */
  {    19,      9,     37, }, /*  91 */
  {    19,      9,     64, }, /*  92 */
  {    19,      9,     63, }, /*  93 */
  {    19,      5,      0, }, /*  94 */
  {    19,      9,     32, }, /*  95 */
  {    19,      5,    -38, }, /*  96 */
  {    19,      5,    -37, }, /*  97 */
  {    19,      5,    -32, }, /*  98 */
  {    19,      5,    -31, }, /*  99 */
  {    19,      5,    -64, }, /* 100 */
  {    19,      5,    -63, }, /* 101 */
  {    19,      9,      8, }, /* 102 */
  {    19,      5,    -62, }, /* 103 */
  {    19,      5,    -57, }, /* 104 */
  {    19,      9,      0, }, /* 105 */
  {    19,      5,    -47, }, /* 106 */
  {    19,      5,    -54, }, /* 107 */
  {    19,      5,     -8, }, /* 108 */
  {    10,      9,      1, }, /* 109 */
  {    10,      5,     -1, }, /* 110 */
  {    19,      5,    -86, }, /* 111 */
  {    19,      5,    -80, }, /* 112 */
  {    19,      5,      7, }, /* 113 */
  {    19,      9,    -60, }, /* 114 */
  {    19,      5,    -96, }, /* 115 */
  {    19,     25,      0, }, /* 116 */
  {    19,      9,     -7, }, /* 117 */
  {    19,      9,   -130, }, /* 118 */
  {    12,      9,     80, }, /* 119 */
  {    12,      9,     32, }, /* 120 */
  {    12,      5,    -32, }, /* 121 */
  {    12,      5,    -80, }, /* 122 */
  {    12,      9,      1, }, /* 123 */
  {    12,      5,     -1, }, /* 124 */
  {    12,     26,      0, }, /* 125 */
  {    12,     12,      0, }, /* 126 */
  {    12,     11,      0, }, /* 127 */
  {    12,      9,     15, }, /* 128 */
  {    12,      5,    -15, }, /* 129 */
  {     1,      9,     48, }, /* 130 */
  {     1,      6,      0, }, /* 131 */
  {     1,     21,      0, }, /* 132 */
  {     1,      5,    -48, }, /* 133 */
  {     1,      5,      0, }, /* 134 */
  {     1,     17,      0, }, /* 135 */
  {    25,     12,      0, }, /* 136 */
  {    25,     17,      0, }, /* 137 */
  {    25,     21,      0, }, /* 138 */
  {    25,      7,      0, }, /* 139 */
  {     0,     25,      0, }, /* 140 */
  {     0,     21,      0, }, /* 141 */
  {     0,     23,      0, }, /* 142 */
  {     0,     26,      0, }, /* 143 */
  {     0,     12,      0, }, /* 144 */
  {     0,      7,      0, }, /* 145 */
  {     0,     11,      0, }, /* 146 */
  {     0,      6,      0, }, /* 147 */
  {     0,     13,      0, }, /* 148 */
  {    49,     21,      0, }, /* 149 */
  {    49,      1,      0, }, /* 150 */
  {    49,      7,      0, }, /* 151 */
  {    49,     12,      0, }, /* 152 */
  {    55,      7,      0, }, /* 153 */
  {    55,     12,      0, }, /* 154 */
  {    63,     13,      0, }, /* 155 */
  {    63,      7,      0, }, /* 156 */
  {    63,     12,      0, }, /* 157 */
  {    63,      6,      0, }, /* 158 */
  {    63,     26,      0, }, /* 159 */
  {    63,     21,      0, }, /* 160 */
  {    14,     12,      0, }, /* 161 */
  {    14,     10,      0, }, /* 162 */
  {    14,      7,      0, }, /* 163 */
  {    14,     13,      0, }, /* 164 */
  {    14,      6,      0, }, /* 165 */
  {     2,     12,      0, }, /* 166 */
  {     2,     10,      0, }, /* 167 */
  {     2,      7,      0, }, /* 168 */
  {     2,     13,      0, }, /* 169 */
  {     2,     23,      0, }, /* 170 */
  {     2,     15,      0, }, /* 171 */
  {     2,     26,      0, }, /* 172 */
  {    21,     12,      0, }, /* 173 */
  {    21,     10,      0, }, /* 174 */
  {    21,      7,      0, }, /* 175 */
  {    21,     13,      0, }, /* 176 */
  {    20,     12,      0, }, /* 177 */
  {    20,     10,      0, }, /* 178 */
  {    20,      7,      0, }, /* 179 */
  {    20,     13,      0, }, /* 180 */
  {    20,     23,      0, }, /* 181 */
  {    43,     12,      0, }, /* 182 */
  {    43,     10,      0, }, /* 183 */
  {    43,      7,      0, }, /* 184 */
  {    43,     13,      0, }, /* 185 */
  {    43,     26,      0, }, /* 186 */
  {    53,     12,      0, }, /* 187 */
  {    53,      7,      0, }, /* 188 */
  {    53,     10,      0, }, /* 189 */
  {    53,     13,      0, }, /* 190 */
  {    53,     15,      0, }, /* 191 */
  {    53,     26,      0, }, /* 192 */
  {    53,     23,      0, }, /* 193 */
  {    54,     10,      0, }, /* 194 */
  {    54,      7,      0, }, /* 195 */
  {    54,     12,      0, }, /* 196 */
  {    54,     13,      0, }, /* 197 */
  {    54,     15,      0, }, /* 198 */
  {    54,     26,      0, }, /* 199 */
  {    28,     10,      0, }, /* 200 */
  {    28,      7,      0, }, /* 201 */
  {    28,     12,      0, }, /* 202 */
  {    28,     13,      0, }, /* 203 */
  {    36,     10,      0, }, /* 204 */
  {    36,      7,      0, }, /* 205 */
  {    36,     12,      0, }, /* 206 */
  {    36,     13,      0, }, /* 207 */
  {    36,     15,      0, }, /* 208 */
  {    36,     26,      0, }, /* 209 */
  {    47,     10,      0, }, /* 210 */
  {    47,      7,      0, }, /* 211 */
  {    47,     12,      0, }, /* 212 */
  {    47,     21,      0, }, /* 213 */
  {    56,      7,      0, }, /* 214 */
  {    56,     12,      0, }, /* 215 */
  {    56,      6,      0, }, /* 216 */
  {    56,     21,      0, }, /* 217 */
  {    56,     13,      0, }, /* 218 */
  {    32,      7,      0, }, /* 219 */
  {    32,     12,      0, }, /* 220 */
  {    32,      6,      0, }, /* 221 */
  {    32,     13,      0, }, /* 222 */
  {    57,      7,      0, }, /* 223 */
  {    57,     26,      0, }, /* 224 */
  {    57,     21,      0, }, /* 225 */
  {    57,     12,      0, }, /* 226 */
  {    57,     13,      0, }, /* 227 */
  {    57,     15,      0, }, /* 228 */
  {    57,     22,      0, }, /* 229 */
  {    57,     18,      0, }, /* 230 */
  {    57,     10,      0, }, /* 231 */
  {    38,      7,      0, }, /* 232 */
  {    38,     10,      0, }, /* 233 */
  {    38,     12,      0, }, /* 234 */
  {    38,     13,      0, }, /* 235 */
  {    38,     21,      0, }, /* 236 */
  {    38,     26,      0, }, /* 237 */
  {    16,      9,   7264, }, /* 238 */
  {    16,      7,      0, }, /* 239 */
  {    16,      6,      0, }, /* 240 */
  {    23,      7,      0, }, /* 241 */
  {    15,      7,      0, }, /* 242 */
  {    15,     12,      0, }, /* 243 */
  {    15,     26,      0, }, /* 244 */
  {    15,     21,      0, }, /* 245 */
  {    15,     15,      0, }, /* 246 */
  {     8,      7,      0, }, /* 247 */
  {     7,      7,      0, }, /* 248 */
  {     7,     21,      0, }, /* 249 */
  {    40,     29,      0, }, /* 250 */
  {    40,      7,      0, }, /* 251 */
  {    40,     22,      0, }, /* 252 */
  {    40,     18,      0, }, /* 253 */
  {    45,      7,      0, }, /* 254 */
  {    45,     14,      0, }, /* 255 */
  {    50,      7,      0, }, /* 256 */
  {    50,     12,      0, }, /* 257 */
  {    24,      7,      0, }, /* 258 */
  {    24,     12,      0, }, /* 259 */
  {     6,      7,      0, }, /* 260 */
  {     6,     12,      0, }, /* 261 */
  {    51,      7,      0, }, /* 262 */
  {    51,     12,      0, }, /* 263 */
  {    31,      7,      0, }, /* 264 */
  {    31,      1,      0, }, /* 265 */
  {    31,     10,      0, }, /* 266 */
  {    31,     12,      0, }, /* 267 */
  {    31,     21,      0, }, /* 268 */
  {    31,      6,      0, }, /* 269 */
  {    31,     23,      0, }, /* 270 */
  {    31,     13,      0, }, /* 271 */
  {    31,     15,      0, }, /* 272 */
  {    37,     21,      0, }, /* 273 */
  {    37,     17,      0, }, /* 274 */
  {    37,     12,      0, }, /* 275 */
  {    37,     29,      0, }, /* 276 */
  {    37,     13,      0, }, /* 277 */
  {    37,      7,      0, }, /* 278 */
  {    37,      6,      0, }, /* 279 */
  {    34,      7,      0, }, /* 280 */
  {    34,     12,      0, }, /* 281 */
  {    34,     10,      0, }, /* 282 */
  {    34,     26,      0, }, /* 283 */
  {    34,     21,      0, }, /* 284 */
  {    34,     13,      0, }, /* 285 */
  {    52,      7,      0, }, /* 286 */
  {    39,      7,      0, }, /* 287 */
  {    39,     10,      0, }, /* 288 */
  {    39,     13,      0, }, /* 289 */
  {    39,     21,      0, }, /* 290 */
  {    31,     26,      0, }, /* 291 */
  {     5,      7,      0, }, /* 292 */
  {     5,     12,      0, }, /* 293 */
  {     5,     10,      0, }, /* 294 */
  {     5,     21,      0, }, /* 295 */
  {    61,     12,      0, }, /* 296 */
  {    61,     10,      0, }, /* 297 */
  {    61,      7,      0, }, /* 298 */
  {    61,     13,      0, }, /* 299 */
  {    61,     21,      0, }, /* 300 */
  {    61,     26,      0, }, /* 301 */
  {    75,     12,      0, }, /* 302 */
  {    75,     10,      0, }, /* 303 */
  {    75,      7,      0, }, /* 304 */
  {    75,     13,      0, }, /* 305 */
  {    69,      7,      0, }, /* 306 */
  {    69,     10,      0, }, /* 307 */
  {    69,     12,      0, }, /* 308 */
  {    69,     21,      0, }, /* 309 */
  {    69,     13,      0, }, /* 310 */
  {    72,     13,      0, }, /* 311 */
  {    72,      7,      0, }, /* 312 */
  {    72,      6,      0, }, /* 313 */
  {    72,     21,      0, }, /* 314 */
  {    12,      5,      0, }, /* 315 */
  {    12,      6,      0, }, /* 316 */
  {    33,      5,  35332, }, /* 317 */
  {    33,      5,   3814, }, /* 318 */
  {    33,      5,    -59, }, /* 319 */
  {    33,      9,  -7615, }, /* 320 */
  {    19,      5,      8, }, /* 321 */
  {    19,      9,     -8, }, /* 322 */
  {    19,      5,     74, }, /* 323 */
  {    19,      5,     86, }, /* 324 */
  {    19,      5,    100, }, /* 325 */
  {    19,      5,    128, }, /* 326 */
  {    19,      5,    112, }, /* 327 */
  {    19,      5,    126, }, /* 328 */
  {    19,      8,     -8, }, /* 329 */
  {    19,      5,      9, }, /* 330 */
  {    19,      9,    -74, }, /* 331 */
  {    19,      8,     -9, }, /* 332 */
  {    19,      5,  -7205, }, /* 333 */
  {    19,      9,    -86, }, /* 334 */
  {    19,      9,   -100, }, /* 335 */
  {    19,      9,   -112, }, /* 336 */
  {    19,      9,   -128, }, /* 337 */
  {    19,      9,   -126, }, /* 338 */
  {    27,      1,      0, }, /* 339 */
  {     9,     27,      0, }, /* 340 */
  {     9,     28,      0, }, /* 341 */
  {    27,     11,      0, }, /* 342 */
  {     9,      9,      0, }, /* 343 */
  {     9,      5,      0, }, /* 344 */
  {    19,      9,  -7517, }, /* 345 */
  {    33,      9,  -8383, }, /* 346 */
  {    33,      9,  -8262, }, /* 347 */
  {    33,      9,     28, }, /* 348 */
  {     9,      7,      0, }, /* 349 */
  {    33,      5,    -28, }, /* 350 */
  {    33,     14,     16, }, /* 351 */
  {    33,     14,    -16, }, /* 352 */
  {    33,     14,      0, }, /* 353 */
  {     9,     26,     26, }, /* 354 */
  {     9,     26,    -26, }, /* 355 */
  {     4,     26,      0, }, /* 356 */
  {    17,      9,     48, }, /* 357 */
  {    17,      5,    -48, }, /* 358 */
  {    33,      9, -10743, }, /* 359 */
  {    33,      9,  -3814, }, /* 360 */
  {    33,      9, -10727, }, /* 361 */
  {    33,      5, -10795, }, /* 362 */
  {    33,      5, -10792, }, /* 363 */
  {    33,      9, -10780, }, /* 364 */
  {    33,      9, -10749, }, /* 365 */
  {    33,      9, -10783, }, /* 366 */
  {    10,      5,      0, }, /* 367 */
  {    10,     26,      0, }, /* 368 */
  {    10,     21,      0, }, /* 369 */
  {    10,     15,      0, }, /* 370 */
  {    16,      5,  -7264, }, /* 371 */
  {    58,      7,      0, }, /* 372 */
  {    58,      6,      0, }, /* 373 */
  {    22,     26,      0, }, /* 374 */
  {    22,      6,      0, }, /* 375 */
  {    22,     14,      0, }, /* 376 */
  {    26,      7,      0, }, /* 377 */
  {    26,      6,      0, }, /* 378 */
  {    29,      7,      0, }, /* 379 */
  {    29,      6,      0, }, /* 380 */
  {     3,      7,      0, }, /* 381 */
  {    23,     26,      0, }, /* 382 */
  {    29,     26,      0, }, /* 383 */
  {    22,      7,      0, }, /* 384 */
  {    60,      7,      0, }, /* 385 */
  {    60,      6,      0, }, /* 386 */
  {    60,     26,      0, }, /* 387 */
  {    76,      7,      0, }, /* 388 */
  {    76,      6,      0, }, /* 389 */
  {    76,     21,      0, }, /* 390 */
  {    76,     13,      0, }, /* 391 */
  {    12,      7,      0, }, /* 392 */
  {    12,     21,      0, }, /* 393 */
  {    33,      9, -35332, }, /* 394 */
  {    48,      7,      0, }, /* 395 */
  {    48,     12,      0, }, /* 396 */
  {    48,     10,      0, }, /* 397 */
  {    48,     26,      0, }, /* 398 */
  {    64,      7,      0, }, /* 399 */
  {    64,     21,      0, }, /* 400 */
  {    74,     10,      0, }, /* 401 */
  {    74,      7,      0, }, /* 402 */
  {    74,     12,      0, }, /* 403 */
  {    74,     21,      0, }, /* 404 */
  {    74,     13,      0, }, /* 405 */
  {    68,     13,      0, }, /* 406 */
  {    68,      7,      0, }, /* 407 */
  {    68,     12,      0, }, /* 408 */
  {    68,     21,      0, }, /* 409 */
  {    73,      7,      0, }, /* 410 */
  {    73,     12,      0, }, /* 411 */
  {    73,     10,      0, }, /* 412 */
  {    73,     21,      0, }, /* 413 */
  {    67,      7,      0, }, /* 414 */
  {    67,     12,      0, }, /* 415 */
  {    67,     10,      0, }, /* 416 */
  {    67,     13,      0, }, /* 417 */
  {    67,     21,      0, }, /* 418 */
  {     9,      4,      0, }, /* 419 */
  {     9,      3,      0, }, /* 420 */
  {    25,     25,      0, }, /* 421 */
  {    35,      7,      0, }, /* 422 */
  {    19,     14,      0, }, /* 423 */
  {    19,     15,      0, }, /* 424 */
  {    19,     26,      0, }, /* 425 */
  {    70,      7,      0, }, /* 426 */
  {    66,      7,      0, }, /* 427 */
  {    41,      7,      0, }, /* 428 */
  {    41,     15,      0, }, /* 429 */
  {    18,      7,      0, }, /* 430 */
  {    18,     14,      0, }, /* 431 */
  {    59,      7,      0, }, /* 432 */
  {    59,     21,      0, }, /* 433 */
  {    42,      7,      0, }, /* 434 */
  {    42,     21,      0, }, /* 435 */
  {    42,     14,      0, }, /* 436 */
  {    13,      9,     40, }, /* 437 */
  {    13,      5,    -40, }, /* 438 */
  {    46,      7,      0, }, /* 439 */
  {    44,      7,      0, }, /* 440 */
  {    44,     13,      0, }, /* 441 */
  {    11,      7,      0, }, /* 442 */
  {    65,      7,      0, }, /* 443 */
  {    65,     15,      0, }, /* 444 */
  {    65,     21,      0, }, /* 445 */
  {    71,      7,      0, }, /* 446 */
  {    71,     21,      0, }, /* 447 */
  {    30,      7,      0, }, /* 448 */
  {    30,     12,      0, }, /* 449 */
  {    30,     15,      0, }, /* 450 */
  {    30,     21,      0, }, /* 451 */
  {    62,      7,      0, }, /* 452 */
  {    62,     14,      0, }, /* 453 */
  {    62,     21,      0, }, /* 454 */
  {     9,     10,      0, }, /* 455 */
  {    19,     12,      0, }, /* 456 */
};

const uschar _pcre_ucd_stage1[] = { /* 8704 bytes */
  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, /* U+0000 */
 16, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, /* U+0800 */
 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 40, 40, 41, 42, 43, 44, /* U+1000 */
 45, 46, 47, 48, 49, 16, 50, 51, 52, 16, 53, 54, 55, 56, 57, 58, /* U+1800 */
 59, 60, 61, 62, 63, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, /* U+2000 */
 74, 74, 63, 75, 63, 63, 76, 16, 77, 78, 79, 80, 81, 82, 83, 84, /* U+2800 */
 85, 86, 87, 88, 89, 90, 91, 68, 92, 92, 92, 92, 92, 92, 92, 92, /* U+3000 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+3800 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+4000 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 93, 92, 92, 92, 92, /* U+4800 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+5000 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+5800 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+6000 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+6800 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+7000 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+7800 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+8000 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+8800 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+9000 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 94, /* U+9800 */
 95, 96, 96, 96, 96, 96, 96, 96, 96, 97, 98, 98, 99,100,101,102, /* U+A000 */
103,104,105, 16,106, 16, 16, 16,107,107,107,107,107,107,107,107, /* U+A800 */
107,107,107,107,107,107,107,107,107,107,107,107,107,107,107,107, /* U+B000 */
107,107,107,107,107,107,107,107,107,107,107,107,107,107,107,107, /* U+B800 */
107,107,107,107,107,107,107,107,107,107,107,107,107,107,107,107, /* U+C000 */
107,107,107,107,107,107,107,107,107,107,107,107,107,107,107,107, /* U+C800 */
107,107,107,107,107,107,107,107,107,107,107,107,107,107,107,108, /* U+D000 */
109,109,109,109,109,109,109,109,109,109,109,109,109,109,109,109, /* U+D800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+E000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+E800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F000 */
110,110, 92, 92,111,112,113,114,115,115,116,117,118,119,120,121, /* U+F800 */
122,123,124,125, 16,126,127,128,129,130, 16, 16, 16, 16, 16, 16, /* U+10000 */
131, 16,132, 16,133, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+10800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+11000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+11800 */
134,134,134,134,134,134,135, 16,136, 16, 16, 16, 16, 16, 16, 16, /* U+12000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+12800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+13000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+13800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+14000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+14800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+15000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+15800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+16000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+16800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+17000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+17800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+18000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+18800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+19000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+19800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+1A000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+1A800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+1B000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+1B800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+1C000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+1C800 */
 68,137,138,139,140, 16,141, 16,142,143,144,145,146,147,148,149, /* U+1D000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+1D800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+1E000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+1E800 */
150,151, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+1F000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+1F800 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+20000 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+20800 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+21000 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+21800 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+22000 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+22800 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+23000 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+23800 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+24000 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+24800 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+25000 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+25800 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+26000 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+26800 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+27000 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+27800 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+28000 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+28800 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+29000 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, /* U+29800 */
 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92,152, 16, 16, /* U+2A000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+2A800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+2B000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+2B800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+2C000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+2C800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+2D000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+2D800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+2E000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+2E800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+2F000 */
 92, 92, 92, 92,153, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+2F800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+30000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+30800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+31000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+31800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+32000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+32800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+33000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+33800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+34000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+34800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+35000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+35800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+36000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+36800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+37000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+37800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+38000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+38800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+39000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+39800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+3A000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+3A800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+3B000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+3B800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+3C000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+3C800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+3D000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+3D800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+3E000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+3E800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+3F000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+3F800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+40000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+40800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+41000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+41800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+42000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+42800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+43000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+43800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+44000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+44800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+45000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+45800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+46000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+46800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+47000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+47800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+48000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+48800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+49000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+49800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+4A000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+4A800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+4B000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+4B800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+4C000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+4C800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+4D000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+4D800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+4E000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+4E800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+4F000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+4F800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+50000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+50800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+51000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+51800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+52000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+52800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+53000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+53800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+54000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+54800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+55000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+55800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+56000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+56800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+57000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+57800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+58000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+58800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+59000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+59800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+5A000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+5A800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+5B000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+5B800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+5C000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+5C800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+5D000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+5D800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+5E000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+5E800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+5F000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+5F800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+60000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+60800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+61000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+61800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+62000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+62800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+63000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+63800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+64000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+64800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+65000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+65800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+66000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+66800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+67000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+67800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+68000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+68800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+69000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+69800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+6A000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+6A800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+6B000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+6B800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+6C000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+6C800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+6D000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+6D800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+6E000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+6E800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+6F000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+6F800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+70000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+70800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+71000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+71800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+72000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+72800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+73000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+73800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+74000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+74800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+75000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+75800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+76000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+76800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+77000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+77800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+78000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+78800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+79000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+79800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+7A000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+7A800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+7B000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+7B800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+7C000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+7C800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+7D000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+7D800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+7E000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+7E800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+7F000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+7F800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+80000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+80800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+81000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+81800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+82000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+82800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+83000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+83800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+84000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+84800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+85000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+85800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+86000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+86800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+87000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+87800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+88000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+88800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+89000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+89800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+8A000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+8A800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+8B000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+8B800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+8C000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+8C800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+8D000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+8D800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+8E000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+8E800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+8F000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+8F800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+90000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+90800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+91000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+91800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+92000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+92800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+93000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+93800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+94000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+94800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+95000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+95800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+96000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+96800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+97000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+97800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+98000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+98800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+99000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+99800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+9A000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+9A800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+9B000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+9B800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+9C000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+9C800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+9D000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+9D800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+9E000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+9E800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+9F000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+9F800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A0000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A0800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A1000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A1800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A2000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A2800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A3000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A3800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A4000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A4800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A5000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A5800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A6000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A6800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A7000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A7800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A8000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A8800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A9000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+A9800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+AA000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+AA800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+AB000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+AB800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+AC000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+AC800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+AD000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+AD800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+AE000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+AE800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+AF000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+AF800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B0000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B0800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B1000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B1800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B2000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B2800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B3000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B3800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B4000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B4800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B5000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B5800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B6000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B6800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B7000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B7800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B8000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B8800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B9000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+B9800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+BA000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+BA800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+BB000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+BB800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+BC000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+BC800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+BD000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+BD800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+BE000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+BE800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+BF000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+BF800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C0000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C0800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C1000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C1800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C2000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C2800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C3000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C3800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C4000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C4800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C5000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C5800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C6000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C6800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C7000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C7800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C8000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C8800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C9000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+C9800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+CA000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+CA800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+CB000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+CB800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+CC000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+CC800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+CD000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+CD800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+CE000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+CE800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+CF000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+CF800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D0000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D0800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D1000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D1800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D2000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D2800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D3000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D3800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D4000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D4800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D5000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D5800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D6000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D6800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D7000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D7800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D8000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D8800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D9000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+D9800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+DA000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+DA800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+DB000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+DB800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+DC000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+DC800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+DD000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+DD800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+DE000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+DE800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+DF000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+DF800 */
154, 16,155,156, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E0000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E0800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E1000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E1800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E2000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E2800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E3000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E3800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E4000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E4800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E5000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E5800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E6000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E6800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E7000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E7800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E8000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E8800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E9000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+E9800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+EA000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+EA800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+EB000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+EB800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+EC000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+EC800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+ED000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+ED800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+EE000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+EE800 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+EF000 */
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* U+EF800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F0000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F0800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F1000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F1800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F2000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F2800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F3000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F3800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F4000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F4800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F5000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F5800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F6000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F6800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F7000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F7800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F8000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F8800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F9000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+F9800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+FA000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+FA800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+FB000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+FB800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+FC000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+FC800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+FD000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+FD800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+FE000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+FE800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+FF000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,157, /* U+FF800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+100000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+100800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+101000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+101800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+102000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+102800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+103000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+103800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+104000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+104800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+105000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+105800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+106000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+106800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+107000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+107800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+108000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+108800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+109000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+109800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+10A000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+10A800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+10B000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+10B800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+10C000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+10C800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+10D000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+10D800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+10E000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+10E800 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,110, /* U+10F000 */
110,110,110,110,110,110,110,110,110,110,110,110,110,110,110,157, /* U+10F800 */
};

const pcre_uint16 _pcre_ucd_stage2[] = { /* 40448 bytes, block = 128 */
/* block 0 */
  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  1,  2,  2,  2,  3,  2,  2,  2,  4,  5,  2,  6,  2,  7,  2,  2,
  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  2,  2,  6,  6,  6,  2,
  2,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,
  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  4,  2,  5, 10, 11,
 10, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,  4,  6,  5,  6,  0,

/* block 1 */
  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  1,  2,  3,  3,  3,  3, 13, 13, 10, 13, 14, 15,  6, 16, 13, 10,
 13,  6, 17, 17, 10, 18, 13,  2, 10, 17, 14, 19, 17, 17, 17,  2,
  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,
  9,  9,  9,  9,  9,  9,  9,  6,  9,  9,  9,  9,  9,  9,  9, 14,
 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
 12, 12, 12, 12, 12, 12, 12,  6, 12, 12, 12, 12, 12, 12, 12, 20,

/* block 2 */
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 23, 24, 21, 22, 21, 22, 21, 22, 14, 21, 22, 21, 22, 21, 22, 21,
 22, 21, 22, 21, 22, 21, 22, 21, 22, 14, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 25, 21, 22, 21, 22, 21, 22, 26,

/* block 3 */
 27, 28, 21, 22, 21, 22, 29, 21, 22, 30, 30, 21, 22, 14, 31, 32,
 33, 21, 22, 30, 34, 35, 36, 37, 21, 22, 38, 14, 36, 39, 40, 41,
 21, 22, 21, 22, 21, 22, 42, 21, 22, 42, 14, 14, 21, 22, 42, 21,
 22, 43, 43, 21, 22, 21, 22, 44, 21, 22, 14, 45, 21, 22, 14, 46,
 45, 45, 45, 45, 47, 48, 49, 47, 48, 49, 47, 48, 49, 21, 22, 21,
 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 50, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 14, 47, 48, 49, 21, 22, 51, 52, 21, 22, 21, 22, 21, 22, 21, 22,

/* block 4 */
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 53, 14, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 14, 14, 14, 14, 14, 14, 54, 21, 22, 55, 56, 14,
 14, 21, 22, 57, 58, 59, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 60, 61, 14, 62, 63, 14, 64, 64, 14, 65, 14, 66, 14, 14, 14, 14,
 64, 14, 14, 67, 14, 14, 14, 14, 68, 69, 14, 70, 14, 14, 14, 69,
 14, 71, 72, 14, 14, 73, 14, 14, 14, 14, 14, 14, 14, 74, 14, 14,

/* block 5 */
 75, 14, 14, 75, 14, 14, 14, 14, 75, 76, 77, 77, 78, 14, 14, 14,
 14, 14, 79, 14, 45, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
 80, 80, 80, 80, 80, 80, 80, 80, 80, 81, 81, 81, 81, 81, 81, 81,
 81, 81, 10, 10, 10, 10, 81, 81, 81, 81, 81, 81, 81, 81, 81, 81,
 81, 81, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
 80, 80, 80, 80, 80, 10, 10, 10, 10, 10, 10, 10, 81, 10, 81, 10,
 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,

/* block 6 */
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 83, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 84, 85, 84, 85, 81, 86, 84, 85, 87, 87, 88, 89, 89, 89,  2, 87,

/* block 7 */
 87, 87, 87, 87, 86, 10, 90,  2, 91, 91, 91, 87, 92, 87, 93, 93,
 94, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95,
 95, 95, 87, 95, 95, 95, 95, 95, 95, 95, 95, 95, 96, 97, 97, 97,
 94, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98,
 98, 98, 99, 98, 98, 98, 98, 98, 98, 98, 98, 98,100,101,101,102,
103,104,105,105,105,106,107,108, 84, 85, 84, 85, 84, 85, 84, 85,
 84, 85,109,110,109,110,109,110,109,110,109,110,109,110,109,110,
111,112,113, 94,114,115,116, 84, 85,117, 84, 85, 94,118,118,118,

/* block 8 */
119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,
120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,
120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,
121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,
121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,
122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,
123,124,123,124,123,124,123,124,123,124,123,124,123,124,123,124,
123,124,123,124,123,124,123,124,123,124,123,124,123,124,123,124,

/* block 9 */
123,124,125,126,126,126,126,126,127,127,123,124,123,124,123,124,
123,124,123,124,123,124,123,124,123,124,123,124,123,124,123,124,
123,124,123,124,123,124,123,124,123,124,123,124,123,124,123,124,
123,124,123,124,123,124,123,124,123,124,123,124,123,124,123,124,
128,123,124,123,124,123,124,123,124,123,124,123,124,123,124,129,
123,124,123,124,123,124,123,124,123,124,123,124,123,124,123,124,
123,124,123,124,123,124,123,124,123,124,123,124,123,124,123,124,
123,124,123,124,123,124,123,124,123,124,123,124,123,124,123,124,

/* block 10 */
123,124,123,124,123,124,123,124,123,124,123,124,123,124,123,124,
123,124,123,124,123,124,123,124,123,124,123,124,123,124,123,124,
123,124,123,124, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87,130,130,130,130,130,130,130,130,130,130,130,130,130,130,130,
130,130,130,130,130,130,130,130,130,130,130,130,130,130,130,130,
130,130,130,130,130,130,130, 87, 87,131,132,132,132,132,132,132,
 87,133,133,133,133,133,133,133,133,133,133,133,133,133,133,133,
133,133,133,133,133,133,133,133,133,133,133,133,133,133,133,133,

/* block 11 */
133,133,133,133,133,133,133,134, 87,  2,135, 87, 87, 87, 87, 87,
 87,136,136,136,136,136,136,136,136,136,136,136,136,136,136,136,
136,136,136,136,136,136,136,136,136,136,136,136,136,136,136,136,
136,136,136,136,136,136,136,136,136,136,136,136,136,136,137,136,
138,136,136,138,136,136,138,136, 87, 87, 87, 87, 87, 87, 87, 87,
139,139,139,139,139,139,139,139,139,139,139,139,139,139,139,139,
139,139,139,139,139,139,139,139,139,139,139, 87, 87, 87, 87, 87,
139,139,139,138,138, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 12 */
 16, 16, 16, 16, 87, 87,140,140,140,141,141,142,  2,141,143,143,
144,144,144,144,144,144,144,144,144,144,144,  2, 87, 87,141,  2,
 87,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
 81,145,145,145,145,145,145,145,145,145,145, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82,144,144,144,144,144,144,144,144,144, 87,
  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,141,141,141,141,145,145,
 82,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,

/* block 13 */
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,141,145,144,144,144,144,144,144,144, 16,146,144,
144,144,144,144,144,147,147,144,144,143,144,144,144,144,145,145,
148,148,148,148,148,148,148,148,148,148,145,145,145,143,143,145,

/* block 14 */
149,149,149,149,149,149,149,149,149,149,149,149,149,149, 87,150,
151,152,151,151,151,151,151,151,151,151,151,151,151,151,151,151,
151,151,151,151,151,151,151,151,151,151,151,151,151,151,151,151,
152,152,152,152,152,152,152,152,152,152,152,152,152,152,152,152,
152,152,152,152,152,152,152,152,152,152,152, 87, 87,151,151,151,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,

/* block 15 */
153,153,153,153,153,153,153,153,153,153,153,153,153,153,153,153,
153,153,153,153,153,153,153,153,153,153,153,153,153,153,153,153,
153,153,153,153,153,153,154,154,154,154,154,154,154,154,154,154,
154,153, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
155,155,155,155,155,155,155,155,155,155,156,156,156,156,156,156,
156,156,156,156,156,156,156,156,156,156,156,156,156,156,156,156,
156,156,156,156,156,156,156,156,156,156,156,157,157,157,157,157,
157,157,157,157,158,158,159,160,160,160,158, 87, 87, 87, 87, 87,

/* block 16 */
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 17 */
 87,161,161,162,163,163,163,163,163,163,163,163,163,163,163,163,
163,163,163,163,163,163,163,163,163,163,163,163,163,163,163,163,
163,163,163,163,163,163,163,163,163,163,163,163,163,163,163,163,
163,163,163,163,163,163,163,163,163,163, 87, 87,161,163,162,162,
162,161,161,161,161,161,161,161,161,162,162,162,162,161, 87, 87,
163, 82, 82,161,161, 87, 87, 87,163,163,163,163,163,163,163,163,
163,163,161,161,  2,  2,164,164,164,164,164,164,164,164,164,164,
  2,165,163, 87, 87, 87, 87, 87, 87, 87, 87,163,163,163,163,163,

/* block 18 */
 87,166,167,167, 87,168,168,168,168,168,168,168,168, 87, 87,168,
168, 87, 87,168,168,168,168,168,168,168,168,168,168,168,168,168,
168,168,168,168,168,168,168,168,168, 87,168,168,168,168,168,168,
168, 87,168, 87, 87, 87,168,168,168,168, 87, 87,166,168,167,167,
167,166,166,166,166, 87, 87,167,167, 87, 87,167,167,166,168, 87,
 87, 87, 87, 87, 87, 87, 87,167, 87, 87, 87, 87,168,168, 87,168,
168,168,166,166, 87, 87,169,169,169,169,169,169,169,169,169,169,
168,168,170,170,171,171,171,171,171,171,172, 87, 87, 87, 87, 87,

/* block 19 */
 87,173,173,174, 87,175,175,175,175,175,175, 87, 87, 87, 87,175,
175, 87, 87,175,175,175,175,175,175,175,175,175,175,175,175,175,
175,175,175,175,175,175,175,175,175, 87,175,175,175,175,175,175,
175, 87,175,175, 87,175,175, 87,175,175, 87, 87,173, 87,174,174,
174,173,173, 87, 87, 87, 87,173,173, 87, 87,173,173,173, 87, 87,
 87,173, 87, 87, 87, 87, 87, 87, 87,175,175,175,175, 87,175, 87,
 87, 87, 87, 87, 87, 87,176,176,176,176,176,176,176,176,176,176,
173,173,175,175,175,173, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 20 */
 87,177,177,178, 87,179,179,179,179,179,179,179,179,179, 87,179,
179,179, 87,179,179,179,179,179,179,179,179,179,179,179,179,179,
179,179,179,179,179,179,179,179,179, 87,179,179,179,179,179,179,
179, 87,179,179, 87,179,179,179,179,179, 87, 87,177,179,178,178,
178,177,177,177,177,177, 87,177,177,178, 87,178,178,177, 87, 87,
179, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
179,179,177,177, 87, 87,180,180,180,180,180,180,180,180,180,180,
 87,181, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 21 */
 87,182,183,183, 87,184,184,184,184,184,184,184,184, 87, 87,184,
184, 87, 87,184,184,184,184,184,184,184,184,184,184,184,184,184,
184,184,184,184,184,184,184,184,184, 87,184,184,184,184,184,184,
184, 87,184,184, 87,184,184,184,184,184, 87, 87,182,184,183,182,
183,182,182,182,182, 87, 87,183,183, 87, 87,183,183,182, 87, 87,
 87, 87, 87, 87, 87, 87,182,183, 87, 87, 87, 87,184,184, 87,184,
184,184,182,182, 87, 87,185,185,185,185,185,185,185,185,185,185,
186,184, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 22 */
 87, 87,187,188, 87,188,188,188,188,188,188, 87, 87, 87,188,188,
188, 87,188,188,188,188, 87, 87, 87,188,188, 87,188, 87,188,188,
 87, 87, 87,188,188, 87, 87, 87,188,188,188, 87, 87, 87,188,188,
188,188,188,188,188,188,188,188,188,188, 87, 87, 87, 87,189,189,
187,189,189, 87, 87, 87,189,189,189, 87,189,189,189,187, 87, 87,
188, 87, 87, 87, 87, 87, 87,189, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87,190,190,190,190,190,190,190,190,190,190,
191,191,191,192,192,192,192,192,192,193,192, 87, 87, 87, 87, 87,

/* block 23 */
 87,194,194,194, 87,195,195,195,195,195,195,195,195, 87,195,195,
195, 87,195,195,195,195,195,195,195,195,195,195,195,195,195,195,
195,195,195,195,195,195,195,195,195, 87,195,195,195,195,195,195,
195,195,195,195, 87,195,195,195,195,195, 87, 87, 87,195,196,196,
196,194,194,194,194, 87,196,196,196, 87,196,196,196,196, 87, 87,
 87, 87, 87, 87, 87,196,196, 87,195,195, 87, 87, 87, 87, 87, 87,
195,195,196,196, 87, 87,197,197,197,197,197,197,197,197,197,197,
 87, 87, 87, 87, 87, 87, 87, 87,198,198,198,198,198,198,198,199,

/* block 24 */
 87, 87,200,200, 87,201,201,201,201,201,201,201,201, 87,201,201,
201, 87,201,201,201,201,201,201,201,201,201,201,201,201,201,201,
201,201,201,201,201,201,201,201,201, 87,201,201,201,201,201,201,
201,201,201,201, 87,201,201,201,201,201, 87, 87,202,201,200,202,
200,200,200,200,200, 87,202,200,200, 87,200,200,202,202, 87, 87,
 87, 87, 87, 87, 87,200,200, 87, 87, 87, 87, 87, 87, 87,201, 87,
201,201,202,202, 87, 87,203,203,203,203,203,203,203,203,203,203,
 87, 13, 13, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 25 */
 87, 87,204,204, 87,205,205,205,205,205,205,205,205, 87,205,205,
205, 87,205,205,205,205,205,205,205,205,205,205,205,205,205,205,
205,205,205,205,205,205,205,205,205, 87,205,205,205,205,205,205,
205,205,205,205,205,205,205,205,205,205, 87, 87, 87,205,204,204,
204,206,206,206,206, 87,204,204,204, 87,204,204,204,206, 87, 87,
 87, 87, 87, 87, 87, 87, 87,204, 87, 87, 87, 87, 87, 87, 87, 87,
205,205,206,206, 87, 87,207,207,207,207,207,207,207,207,207,207,
208,208,208,208,208,208, 87, 87, 87,209,205,205,205,205,205,205,

/* block 26 */
 87, 87,210,210, 87,211,211,211,211,211,211,211,211,211,211,211,
211,211,211,211,211,211,211, 87, 87, 87,211,211,211,211,211,211,
211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,
211,211, 87,211,211,211,211,211,211,211,211,211, 87,211, 87, 87,
211,211,211,211,211,211,211, 87, 87, 87,212, 87, 87, 87, 87,210,
210,210,212,212,212, 87,212, 87,210,210,210,210,210,210,210,210,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87,210,210,213, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 27 */
 87,214,214,214,214,214,214,214,214,214,214,214,214,214,214,214,
214,214,214,214,214,214,214,214,214,214,214,214,214,214,214,214,
214,214,214,214,214,214,214,214,214,214,214,214,214,214,214,214,
214,215,214,214,215,215,215,215,215,215,215, 87, 87, 87, 87,  3,
214,214,214,214,214,214,216,215,215,215,215,215,215,215,215,217,
218,218,218,218,218,218,218,218,218,218,217,217, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 28 */
 87,219,219, 87,219, 87, 87,219,219, 87,219, 87, 87,219, 87, 87,
 87, 87, 87, 87,219,219,219,219, 87,219,219,219,219,219,219,219,
 87,219,219,219, 87,219, 87,219, 87, 87,219,219, 87,219,219,219,
219,220,219,219,220,220,220,220,220,220, 87,220,220,219, 87, 87,
219,219,219,219,219, 87,221, 87,220,220,220,220,220,220, 87, 87,
222,222,222,222,222,222,222,222,222,222, 87, 87,219,219, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 29 */
223,224,224,224,225,225,225,225,225,225,225,225,225,225,225,225,
225,225,225,224,224,224,224,224,226,226,224,224,224,224,224,224,
227,227,227,227,227,227,227,227,227,227,228,228,228,228,228,228,
228,228,228,228,224,226,224,226,224,226,229,230,229,230,231,231,
223,223,223,223,223,223,223,223, 87,223,223,223,223,223,223,223,
223,223,223,223,223,223,223,223,223,223,223,223,223,223,223,223,
223,223,223,223,223,223,223,223,223,223,223,223,223, 87, 87, 87,
 87,226,226,226,226,226,226,226,226,226,226,226,226,226,226,231,

/* block 30 */
226,226,226,226,226,225,226,226,223,223,223,223, 87, 87, 87, 87,
226,226,226,226,226,226,226,226, 87,226,226,226,226,226,226,226,
226,226,226,226,226,226,226,226,226,226,226,226,226,226,226,226,
226,226,226,226,226,226,226,226,226,226,226,226,226, 87,224,224,
224,224,224,224,224,224,226,224,224,224,224,224,224, 87,224,224,
225,225,225,225,225, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 31 */
232,232,232,232,232,232,232,232,232,232,232,232,232,232,232,232,
232,232,232,232,232,232,232,232,232,232,232,232,232,232,232,232,
232,232,232,232,232,232,232,232,232,232,232,233,233,234,234,234,
234,233,234,234,234,234,234,234,233,234,234,233,233,234,234,232,
235,235,235,235,235,235,235,235,235,235,236,236,236,236,236,236,
232,232,232,232,232,232,233,233,234,234,232,232,232,232,234,234,
234,232,233,233,233,232,232,233,233,233,233,233,233,233,232,232,
232,234,234,234,234,232,232,232,232,232,232,232,232,232,232,232,

/* block 32 */
232,232,234,233,233,234,234,233,233,233,233,233,233,234,232,233,
235,235,235,235,235,235,235,235,235,235, 87, 87, 87, 87,237,237,
238,238,238,238,238,238,238,238,238,238,238,238,238,238,238,238,
238,238,238,238,238,238,238,238,238,238,238,238,238,238,238,238,
238,238,238,238,238,238, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,
239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,239,
239,239,239,239,239,239,239,239,239,239,239,  2,240, 87, 87, 87,

/* block 33 */
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241, 87, 87, 87, 87, 87,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,

/* block 34 */
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241, 87, 87, 87, 87, 87,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241, 87, 87, 87, 87, 87, 87,

/* block 35 */
242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,
242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,
242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,
242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,
242,242,242,242,242,242,242,242,242, 87,242,242,242,242, 87, 87,
242,242,242,242,242,242,242, 87,242, 87,242,242,242,242, 87, 87,
242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,
242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,

/* block 36 */
242,242,242,242,242,242,242,242,242, 87,242,242,242,242, 87, 87,
242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,
242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,
242, 87,242,242,242,242, 87, 87,242,242,242,242,242,242,242, 87,
242, 87,242,242,242,242, 87, 87,242,242,242,242,242,242,242,242,
242,242,242,242,242,242,242, 87,242,242,242,242,242,242,242,242,
242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,
242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,

/* block 37 */
242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,
242, 87,242,242,242,242, 87, 87,242,242,242,242,242,242,242,242,
242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,
242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,
242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,
242,242,242,242,242,242,242,242,242,242,242, 87, 87, 87, 87,243,
244,245,245,245,245,245,245,245,245,246,246,246,246,246,246,246,
246,246,246,246,246,246,246,246,246,246,246,246,246, 87, 87, 87,

/* block 38 */
242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,
244,244,244,244,244,244,244,244,244,244, 87, 87, 87, 87, 87, 87,
247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,
247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,
247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,
247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,
247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,
247,247,247,247,247, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 39 */
 87,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,

/* block 40 */
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,

/* block 41 */
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,
248,248,248,248,248,248,248,248,248,248,248,248,248,249,249,248,
248,248,248,248,248,248,248, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 42 */
250,251,251,251,251,251,251,251,251,251,251,251,251,251,251,251,
251,251,251,251,251,251,251,251,251,251,251,252,253, 87, 87, 87,
254,254,254,254,254,254,254,254,254,254,254,254,254,254,254,254,
254,254,254,254,254,254,254,254,254,254,254,254,254,254,254,254,
254,254,254,254,254,254,254,254,254,254,254,254,254,254,254,254,
254,254,254,254,254,254,254,254,254,254,254,254,254,254,254,254,
254,254,254,254,254,254,254,254,254,254,254,  2,  2,  2,255,255,
255, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 43 */
256,256,256,256,256,256,256,256,256,256,256,256,256, 87,256,256,
256,256,257,257,257, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
258,258,258,258,258,258,258,258,258,258,258,258,258,258,258,258,
258,258,259,259,259,  2,  2, 87, 87, 87, 87, 87, 87, 87, 87, 87,
260,260,260,260,260,260,260,260,260,260,260,260,260,260,260,260,
260,260,261,261, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
262,262,262,262,262,262,262,262,262,262,262,262,262, 87,262,262,
262, 87,263,263, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 44 */
264,264,264,264,264,264,264,264,264,264,264,264,264,264,264,264,
264,264,264,264,264,264,264,264,264,264,264,264,264,264,264,264,
264,264,264,264,264,264,264,264,264,264,264,264,264,264,264,264,
264,264,264,264,265,265,266,267,267,267,267,267,267,267,266,266,
266,266,266,266,266,266,267,266,266,267,267,267,267,267,267,267,
267,267,267,267,268,268,268,269,268,268,268,270,264,267, 87, 87,
271,271,271,271,271,271,271,271,271,271, 87, 87, 87, 87, 87, 87,
272,272,272,272,272,272,272,272,272,272, 87, 87, 87, 87, 87, 87,

/* block 45 */
273,273,  2,  2,273,  2,274,273,273,273,273,275,275,275,276, 87,
277,277,277,277,277,277,277,277,277,277, 87, 87, 87, 87, 87, 87,
278,278,278,278,278,278,278,278,278,278,278,278,278,278,278,278,
278,278,278,278,278,278,278,278,278,278,278,278,278,278,278,278,
278,278,278,279,278,278,278,278,278,278,278,278,278,278,278,278,
278,278,278,278,278,278,278,278,278,278,278,278,278,278,278,278,
278,278,278,278,278,278,278,278,278,278,278,278,278,278,278,278,
278,278,278,278,278,278,278,278, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 46 */
278,278,278,278,278,278,278,278,278,278,278,278,278,278,278,278,
278,278,278,278,278,278,278,278,278,278,278,278,278,278,278,278,
278,278,278,278,278,278,278,278,278,275,278, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 47 */
280,280,280,280,280,280,280,280,280,280,280,280,280,280,280,280,
280,280,280,280,280,280,280,280,280,280,280,280,280, 87, 87, 87,
281,281,281,282,282,282,282,281,281,282,282,282, 87, 87, 87, 87,
282,282,281,282,282,282,282,282,282,281,281,281, 87, 87, 87, 87,
283, 87, 87, 87,284,284,285,285,285,285,285,285,285,285,285,285,
286,286,286,286,286,286,286,286,286,286,286,286,286,286,286,286,
286,286,286,286,286,286,286,286,286,286,286,286,286,286, 87, 87,
286,286,286,286,286, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 48 */
287,287,287,287,287,287,287,287,287,287,287,287,287,287,287,287,
287,287,287,287,287,287,287,287,287,287,287,287,287,287,287,287,
287,287,287,287,287,287,287,287,287,287, 87, 87, 87, 87, 87, 87,
288,288,288,288,288,288,288,288,288,288,288,288,288,288,288,288,
288,287,287,287,287,287,287,287,288,288, 87, 87, 87, 87, 87, 87,
289,289,289,289,289,289,289,289,289,289, 87, 87, 87, 87,290,290,
291,291,291,291,291,291,291,291,291,291,291,291,291,291,291,291,
291,291,291,291,291,291,291,291,291,291,291,291,291,291,291,291,

/* block 49 */
292,292,292,292,292,292,292,292,292,292,292,292,292,292,292,292,
292,292,292,292,292,292,292,293,293,294,294,294, 87, 87,295,295,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 50 */
296,296,296,296,297,298,298,298,298,298,298,298,298,298,298,298,
298,298,298,298,298,298,298,298,298,298,298,298,298,298,298,298,
298,298,298,298,298,298,298,298,298,298,298,298,298,298,298,298,
298,298,298,298,296,297,296,296,296,296,296,297,296,297,297,297,
297,297,296,297,297,298,298,298,298,298,298,298, 87, 87, 87, 87,
299,299,299,299,299,299,299,299,299,299,300,300,300,300,300,300,
300,301,301,301,301,301,301,301,301,301,301,296,296,296,296,296,
296,296,296,296,301,301,301,301,301,301,301,301,301, 87, 87, 87,

/* block 51 */
302,302,303,304,304,304,304,304,304,304,304,304,304,304,304,304,
304,304,304,304,304,304,304,304,304,304,304,304,304,304,304,304,
304,303,302,302,302,302,303,303,302,302,303, 87, 87, 87,304,304,
305,305,305,305,305,305,305,305,305,305, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 52 */
306,306,306,306,306,306,306,306,306,306,306,306,306,306,306,306,
306,306,306,306,306,306,306,306,306,306,306,306,306,306,306,306,
306,306,306,306,307,307,307,307,307,307,307,307,308,308,308,308,
308,308,308,308,307,307,308,308, 87, 87, 87,309,309,309,309,309,
310,310,310,310,310,310,310,310,310,310, 87, 87, 87,306,306,306,
311,311,311,311,311,311,311,311,311,311,312,312,312,312,312,312,
312,312,312,312,312,312,312,312,312,312,312,312,312,312,312,312,
312,312,312,312,312,312,312,312,313,313,313,313,313,313,314,314,

/* block 53 */
 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
 14, 14, 14, 14, 14, 14, 94, 94, 94, 94, 94,315, 80, 80, 80, 80,
 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 88, 88, 88,
 88, 88, 14, 14, 14, 14, 94, 94, 94, 94, 94, 14, 14, 14, 14, 14,
 14, 14, 14, 14, 14, 14, 14, 14,316,317, 14, 14, 14,318, 14, 14,

/* block 54 */
 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 80, 80, 80, 80, 80,
 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 88,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 82, 82,

/* block 55 */
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,

/* block 56 */
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 14, 14, 14, 14, 14,319, 14, 14,320, 14,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,

/* block 57 */
321,321,321,321,321,321,321,321,322,322,322,322,322,322,322,322,
321,321,321,321,321,321, 87, 87,322,322,322,322,322,322, 87, 87,
321,321,321,321,321,321,321,321,322,322,322,322,322,322,322,322,
321,321,321,321,321,321,321,321,322,322,322,322,322,322,322,322,
321,321,321,321,321,321, 87, 87,322,322,322,322,322,322, 87, 87,
 94,321, 94,321, 94,321, 94,321, 87,322, 87,322, 87,322, 87,322,
321,321,321,321,321,321,321,321,322,322,322,322,322,322,322,322,
323,323,324,324,324,324,325,325,326,326,327,327,328,328, 87, 87,

/* block 58 */
321,321,321,321,321,321,321,321,329,329,329,329,329,329,329,329,
321,321,321,321,321,321,321,321,329,329,329,329,329,329,329,329,
321,321,321,321,321,321,321,321,329,329,329,329,329,329,329,329,
321,321, 94,330, 94, 87, 94, 94,322,322,331,331,332, 86,333, 86,
 86, 86, 94,330, 94, 87, 94, 94,334,334,334,334,332, 86, 86, 86,
321,321, 94, 94, 87, 87, 94, 94,322,322,335,335, 87, 86, 86, 86,
321,321, 94, 94, 94,113, 94, 94,322,322,336,336,117, 86, 86, 86,
 87, 87, 94,330, 94, 87, 94, 94,337,337,338,338,332, 86, 86, 87,

/* block 59 */
  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1, 16,339,339, 16, 16,
  7,  7,  7,  7,  7,  7,  2,  2, 15, 19,  4, 15, 15, 19,  4, 15,
  2,  2,  2,  2,  2,  2,  2,  2,340,341, 16, 16, 16, 16, 16,  1,
  2,  2,  2,  2,  2,  2,  2,  2,  2, 15, 19,  2,  2,  2,  2, 11,
 11,  2,  2,  2,  6,  4,  5,  2,  2,  2,  2,  2,  2,  2,  2,  2,
  2,  2,  6,  2, 11,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  1,
 16, 16, 16, 16, 16, 87, 87, 87, 87, 87, 16, 16, 16, 16, 16, 16,
 17, 14, 87, 87, 17, 17, 17, 17, 17, 17,  6,  6,  6,  4,  5, 14,

/* block 60 */
 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,  6,  6,  6,  4,  5, 87,
 80, 80, 80, 80, 80, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,
  3,  3,  3,  3,  3,  3, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,342,342,342,
342, 82,342,342,342, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 61 */
 13, 13,343, 13, 13, 13, 13,343, 13, 13,344,343,343,343,344,344,
343,343,343,344, 13,343, 13, 13, 13,343,343,343,343,343, 13, 13,
 13, 13, 13, 13,343, 13,345, 13,343, 13,346,347,343,343, 13,344,
343,343,348,343,344,349,349,349,349,344, 13, 13,344,344,343,343,
  6,  6,  6,  6,  6,343,344,344,344,344, 13,  6, 13, 13,350, 13,
 87, 87, 87, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,
352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,

/* block 62 */
353,353,353, 21, 22,353,353,353,353, 87, 87, 87, 87, 87, 87, 87,
  6,  6,  6,  6,  6, 13, 13, 13, 13, 13,  6,  6, 13, 13, 13, 13,
  6, 13, 13,  6, 13, 13,  6, 13, 13, 13, 13, 13, 13, 13,  6, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,  6,  6,
 13, 13,  6, 13,  6, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,

/* block 63 */
  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,

/* block 64 */
 13, 13, 13, 13, 13, 13, 13, 13,  6,  6,  6,  6, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
  6,  6, 13, 13, 13, 13, 13, 13, 13,  4,  5, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,  6, 13, 13, 13,

/* block 65 */
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,  6,  6,  6,  6,  6,
  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
  6,  6,  6,  6, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,  6,  6,  6,  6,
  6,  6, 13, 13, 13, 13, 13, 13, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 66 */
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,

/* block 67 */
 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13,354,354,354,354,354,354,354,354,354,354,
354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,
355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,
355,355,355,355,355,355,355,355,355,355, 17, 17, 17, 17, 17, 17,
 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,

/* block 68 */
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,

/* block 69 */
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13,  6, 13, 13, 13, 13, 13, 13, 13, 13,
 13,  6, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13,  6,  6,  6,  6,  6,  6,  6,  6,

/* block 70 */
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,  6,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,

/* block 71 */
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 87, 87,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 87, 87, 87,
 13, 13, 13, 13, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 72 */
 87, 13, 13, 13, 13, 87, 13, 13, 13, 13, 87, 87, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 87, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 87, 13, 87, 13,
 13, 13, 13, 87, 87, 87, 13, 87, 13, 13, 13, 13, 13, 13, 13, 87,
 87, 13, 13, 13, 13, 13, 13, 13,  4,  5,  4,  5,  4,  5,  4,  5,
  4,  5,  4,  5,  4,  5, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,

/* block 73 */
 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
 17, 17, 17, 17, 13, 87, 87, 87, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 87, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 87,
  6,  6,  6,  6,  6,  4,  5,  6,  6,  6,  6, 87,  6, 87, 87, 87,
  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
  6,  6,  6,  6,  6,  6,  4,  5,  4,  5,  4,  5,  4,  5,  4,  5,
  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,

/* block 74 */
356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,
356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,
356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,
356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,
356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,
356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,
356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,
356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,

/* block 75 */
  6,  6,  6,  4,  5,  4,  5,  4,  5,  4,  5,  4,  5,  4,  5,  4,
  5,  4,  5,  4,  5,  4,  5,  4,  5,  6,  6,  6,  6,  6,  6,  6,
  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
  6,  6,  6,  6,  6,  6,  6,  6,  4,  5,  4,  5,  6,  6,  6,  6,
  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  4,  5,  6,  6,

/* block 76 */
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
  6,  6,  6,  6,  6, 13, 13,  6,  6,  6,  6,  6,  6, 87, 87, 87,
 13, 13, 13, 13, 13, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 77 */
357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,
357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,
357,357,357,357,357,357,357,357,357,357,357,357,357,357,357, 87,
358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,
358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,
358,358,358,358,358,358,358,358,358,358,358,358,358,358,358, 87,
 21, 22,359,360,361,362,363, 21, 22, 21, 22, 21, 22,364,365,366,
 87, 14, 21, 22, 14, 21, 22, 14, 14, 14, 14, 14, 14, 80, 87, 87,

/* block 78 */
109,110,109,110,109,110,109,110,109,110,109,110,109,110,109,110,
109,110,109,110,109,110,109,110,109,110,109,110,109,110,109,110,
109,110,109,110,109,110,109,110,109,110,109,110,109,110,109,110,
109,110,109,110,109,110,109,110,109,110,109,110,109,110,109,110,
109,110,109,110,109,110,109,110,109,110,109,110,109,110,109,110,
109,110,109,110,109,110,109,110,109,110,109,110,109,110,109,110,
109,110,109,110,367,368,368,368,368,368,368, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87,369,369,369,369,370,369,369,

/* block 79 */
371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,
371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,
371,371,371,371,371,371, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,
372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,
372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,
372,372,372,372,372,372, 87, 87, 87, 87, 87, 87, 87, 87, 87,373,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 80 */
242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,242,
242,242,242,242,242,242,242, 87, 87, 87, 87, 87, 87, 87, 87, 87,
242,242,242,242,242,242,242, 87,242,242,242,242,242,242,242, 87,
242,242,242,242,242,242,242, 87,242,242,242,242,242,242,242, 87,
242,242,242,242,242,242,242, 87,242,242,242,242,242,242,242, 87,
242,242,242,242,242,242,242, 87,242,242,242,242,242,242,242, 87,
126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,
126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,

/* block 81 */
  2,  2, 15, 19, 15, 19,  2,  2,  2, 15, 19,  2, 15, 19,  2,  2,
  2,  2,  2,  2,  2,  2,  2,  7,  2,  2,  7,  2, 15, 19,  2,  2,
 15, 19,  4,  5,  4,  5,  4,  5,  4,  5,  2,  2,  2,  2,  2, 81,
  2, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 82 */
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,
374,374,374,374,374,374,374,374,374,374, 87,374,374,374,374,374,
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,
374,374,374,374, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 83 */
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,

/* block 84 */
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,
374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,
374,374,374,374,374,374, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 87, 87, 87, 87,

/* block 85 */
  1,  2,  2,  2, 13,375,349,376,  4,  5,  4,  5,  4,  5,  4,  5,
  4,  5, 13, 13,  4,  5,  4,  5,  4,  5,  4,  5,  7,  4,  5,  5,
 13,376,376,376,376,376,376,376,376,376, 82, 82, 82, 82, 82, 82,
  7, 81, 81, 81, 81, 81, 13, 13,376,376,376,375,349,  2, 13, 13,
 87,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,
377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,
377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,
377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,

/* block 86 */
377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,
377,377,377,377,377,377,377, 87, 87, 82, 82, 10, 10,378,378,377,
  7,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,
379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,
379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,
379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,
379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,
379,379,379,379,379,379,379,379,379,379,379,  2, 81,380,380,379,

/* block 87 */
 87, 87, 87, 87, 87,381,381,381,381,381,381,381,381,381,381,381,
381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,
381,381,381,381,381,381,381,381,381,381,381,381,381,381, 87, 87,
 87,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,

/* block 88 */
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241, 87,
 13, 13, 17, 17, 17, 17, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,
381,381,381,381,381,381,381,381, 87, 87, 87, 87, 87, 87, 87, 87,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,

/* block 89 */
382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,
382,382,382,382,382,382,382,382,382,382,382,382,382,382,382, 87,
 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 13, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,
382,382,382,382,382,382,382,382,382,382,382,382,382,382,382, 13,

/* block 90 */
 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,
383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,
383,383,383,383,383,383,383,383,383,383,383,383,383,383,383, 87,

/* block 91 */
383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,
383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,
383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,
383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,
383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,
383,383,383,383,383,383,383,383, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,

/* block 92 */
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,

/* block 93 */
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,

/* block 94 */
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 95 */
385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,
385,385,385,385,385,386,385,385,385,385,385,385,385,385,385,385,
385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,
385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,
385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,
385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,
385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,
385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,

/* block 96 */
385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,
385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,
385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,
385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,
385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,
385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,
385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,
385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,

/* block 97 */
385,385,385,385,385,385,385,385,385,385,385,385,385, 87, 87, 87,
387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,
387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,
387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,
387,387,387,387,387,387,387, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 98 */
388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,
388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,
388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,
388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,
388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,
388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,
388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,
388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,

/* block 99 */
388,388,388,388,388,388,388,388,388,388,388,388,389,390,390,390,
388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,
391,391,391,391,391,391,391,391,391,391,388,388, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
123,124,123,124,123,124,123,124,123,124,123,124,123,124,123,124,
123,124,123,124,123,124,123,124,123,124,123,124,123,124,123,124,
 87, 87,123,124,123,124,123,124,123,124,123,124,123,124,392,126,
127,127,127,393, 87, 87, 87, 87, 87, 87, 87, 87,126,126,393,316,

/* block 100 */
123,124,123,124,123,124,123,124,123,124,123,124,123,124,123,124,
123,124,123,124,123,124,123,124, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 101 */
 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
 10, 10, 10, 10, 10, 10, 10, 81, 81, 81, 81, 81, 81, 81, 81, 81,
 10, 10, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 14, 14, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22, 21, 22,
 80, 14, 14, 14, 14, 14, 14, 14, 14, 21, 22, 21, 22,394, 21, 22,

/* block 102 */
 21, 22, 21, 22, 21, 22, 21, 22, 81, 10, 10, 21, 22, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 45, 45, 45, 45, 45,

/* block 103 */
395,395,396,395,395,395,396,395,395,395,395,396,395,395,395,395,
395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,
395,395,395,397,397,396,396,397,398,398,398,398, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,
399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,
399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,
399,399,399,399,400,400,400,400, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 104 */
401,401,402,402,402,402,402,402,402,402,402,402,402,402,402,402,
402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,
402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,
402,402,402,402,401,401,401,401,401,401,401,401,401,401,401,401,
401,401,401,401,403, 87, 87, 87, 87, 87, 87, 87, 87, 87,404,404,
405,405,405,405,405,405,405,405,405,405, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 105 */
406,406,406,406,406,406,406,406,406,406,407,407,407,407,407,407,
407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,
407,407,407,407,407,407,408,408,408,408,408,408,408,408,409,409,
410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,
410,410,410,410,410,410,410,411,411,411,411,411,411,411,411,411,
411,411,412,412, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,413,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 106 */
414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,
414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,
414,414,414,414,414,414,414,414,414,415,415,415,415,415,415,416,
416,415,415,416,416,415,415, 87, 87, 87, 87, 87, 87, 87, 87, 87,
414,414,414,415,414,414,414,414,414,414,414,414,415,416, 87, 87,
417,417,417,417,417,417,417,417,417,417, 87, 87,418,418,418,418,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 107 */
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,

/* block 108 */
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 109 */
419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,
419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,
419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,
419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,
419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,
419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,
419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,
419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,

/* block 110 */
420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,
420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,
420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,
420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,
420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,
420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,
420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,
420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,

/* block 111 */
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384, 87, 87,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384, 87, 87, 87, 87, 87,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,

/* block 112 */
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 113 */
 14, 14, 14, 14, 14, 14, 14, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87,134,134,134,134,134, 87, 87, 87, 87, 87,139,136,139,
139,139,139,139,139,139,139,139,139,421,139,139,139,139,139,139,
139,139,139,139,139,139,139, 87,139,139,139,139,139, 87,139, 87,
139,139, 87,139,139, 87,139,139,139,139,139,139,139,139,139,139,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,

/* block 114 */
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,

/* block 115 */
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,

/* block 116 */
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,  4,  5,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,

/* block 117 */
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
 87, 87,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
145,145,145,145,145,145,145,145,145,145,145,145,142, 13, 87, 87,

/* block 118 */
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
  2,  2,  2,  2,  2,  2,  2,  4,  5,  2, 87, 87, 87, 87, 87, 87,
 82, 82, 82, 82, 82, 82, 82, 87, 87, 87, 87, 87, 87, 87, 87, 87,
  2,  7,  7, 11, 11,  4,  5,  4,  5,  4,  5,  4,  5,  4,  5,  4,
  5,  4,  5,  4,  5,  2,  2,  4,  5,  2,  2,  2,  2, 11, 11, 11,
  2,  2,  2, 87,  2,  2,  2,  2,  7,  4,  5,  4,  5,  4,  5,  2,
  2,  2,  6,  7,  6,  6,  6, 87,  2,  3,  2,  2, 87, 87, 87, 87,
145,145,145,145,145, 87,145,145,145,145,145,145,145,145,145,145,

/* block 119 */
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,145,
145,145,145,145,145,145,145,145,145,145,145,145,145, 87, 87, 16,

/* block 120 */
 87,  2,  2,  2,  3,  2,  2,  2,  4,  5,  2,  6,  2,  7,  2,  2,
  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  2,  2,  6,  6,  6,  2,
  2,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,
  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  4,  2,  5, 10, 11,
 10, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,  4,  6,  5,  6,  4,
  5,  2,  4,  5,  2,  2,379,379,379,379,379,379,379,379,379,379,
 81,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,

/* block 121 */
379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,
379,379,379,379,379,379,379,379,379,379,379,379,379,379, 81, 81,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,241,
241,241,241,241,241,241,241,241,241,241,241,241,241,241,241, 87,
 87, 87,241,241,241,241,241,241, 87, 87,241,241,241,241,241,241,
 87, 87,241,241,241,241,241,241, 87, 87,241,241,241, 87, 87, 87,
  3,  3,  6, 10, 13,  3,  3, 87, 13,  6,  6,  6,  6, 13, 13, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 16, 16, 16, 13, 13, 87, 87,

/* block 122 */
422,422,422,422,422,422,422,422,422,422,422,422, 87,422,422,422,
422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,
422,422,422,422,422,422,422, 87,422,422,422,422,422,422,422,422,
422,422,422,422,422,422,422,422,422,422,422, 87,422,422, 87,422,
422,422,422,422,422,422,422,422,422,422,422,422,422,422, 87, 87,
422,422,422,422,422,422,422,422,422,422,422,422,422,422, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 123 */
422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,
422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,
422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,
422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,
422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,
422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,
422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,
422,422,422,422,422,422,422,422,422,422,422, 87, 87, 87, 87, 87,

/* block 124 */
  2,  2, 13, 87, 87, 87, 87, 17, 17, 17, 17, 17, 17, 17, 17, 17,
 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
 17, 17, 17, 17, 87, 87, 87, 13, 13, 13, 13, 13, 13, 13, 13, 13,
423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,
423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,
423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,
423,423,423,423,423,424,424,424,424,425,425,425,425,425,425,425,

/* block 125 */
425,425,425,425,425,425,425,425,425,425,424, 87, 87, 87, 87, 87,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 82, 87, 87,

/* block 126 */
426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,
426,426,426,426,426,426,426,426,426,426,426,426,426, 87, 87, 87,
427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,
427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,
427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,
427, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 127 */
428,428,428,428,428,428,428,428,428,428,428,428,428,428,428,428,
428,428,428,428,428,428,428,428,428,428,428,428,428,428,428, 87,
429,429,429,429, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,
430,431,430,430,430,430,430,430,430,430,431, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 128 */
432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,
432,432,432,432,432,432,432,432,432,432,432,432,432,432, 87,433,
434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,
434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,
434,434,434,434, 87, 87, 87, 87,434,434,434,434,434,434,434,434,
435,436,436,436,436,436, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 129 */
437,437,437,437,437,437,437,437,437,437,437,437,437,437,437,437,
437,437,437,437,437,437,437,437,437,437,437,437,437,437,437,437,
437,437,437,437,437,437,437,437,438,438,438,438,438,438,438,438,
438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,
438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,
439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,
439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,
439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,

/* block 130 */
440,440,440,440,440,440,440,440,440,440,440,440,440,440,440,440,
440,440,440,440,440,440,440,440,440,440,440,440,440,440, 87, 87,
441,441,441,441,441,441,441,441,441,441, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 131 */
442,442,442,442,442,442, 87, 87,442, 87,442,442,442,442,442,442,
442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,
442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,
442,442,442,442,442,442, 87,442,442, 87, 87, 87,442, 87, 87,442,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 132 */
443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,
443,443,443,443,443,443,444,444,444,444, 87, 87, 87, 87, 87,445,
446,446,446,446,446,446,446,446,446,446,446,446,446,446,446,446,
446,446,446,446,446,446,446,446,446,446, 87, 87, 87, 87, 87,447,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 133 */
448,449,449,449, 87,449,449, 87, 87, 87, 87, 87,449,449,449,449,
448,448,448,448, 87,448,448,448, 87,448,448,448,448,448,448,448,
448,448,448,448,448,448,448,448,448,448,448,448,448,448,448,448,
448,448,448,448, 87, 87, 87, 87,449,449,449, 87, 87, 87, 87,449,
450,450,450,450,450,450,450,450, 87, 87, 87, 87, 87, 87, 87, 87,
451,451,451,451,451,451,451,451,451, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 134 */
452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,
452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,
452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,
452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,
452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,
452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,
452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,
452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,

/* block 135 */
452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,
452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,
452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,
452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,
452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,
452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,
452,452,452,452,452,452,452,452,452,452,452,452,452,452,452, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 136 */
453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,
453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,
453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,
453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,
453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,
453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,
453,453,453, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
454,454,454,454, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 137 */
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 138 */
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 87, 87, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13,455,455, 82, 82, 82, 13, 13, 13,455,455,455,
455,455,455, 16, 16, 16, 16, 16, 16, 16, 16, 82, 82, 82, 82, 82,

/* block 139 */
 82, 82, 82, 13, 13, 82, 82, 82, 82, 82, 82, 82, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 82, 82, 82, 82, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 140 */
425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,
425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,
425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,
425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,
425,425,456,456,456,425, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 141 */
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
 17, 17, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 142 */
343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,
343,343,343,343,343,343,343,343,343,343,344,344,344,344,344,344,
344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,
344,344,344,344,343,343,343,343,343,343,343,343,343,343,343,343,
343,343,343,343,343,343,343,343,343,343,343,343,343,343,344,344,
344,344,344,344,344, 87,344,344,344,344,344,344,344,344,344,344,
344,344,344,344,344,344,344,344,343,343,343,343,343,343,343,343,
343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,

/* block 143 */
343,343,344,344,344,344,344,344,344,344,344,344,344,344,344,344,
344,344,344,344,344,344,344,344,344,344,344,344,343, 87,343,343,
 87, 87,343, 87, 87,343,343, 87, 87,343,343,343,343, 87,343,343,
343,343,343,343,343,343,344,344,344,344, 87,344, 87,344,344,344,
344,344,344,344, 87,344,344,344,344,344,344,344,344,344,344,344,
343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,
343,343,343,343,343,343,343,343,343,343,344,344,344,344,344,344,
344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,

/* block 144 */
344,344,344,344,343,343, 87,343,343,343,343, 87, 87,343,343,343,
343,343,343,343,343, 87,343,343,343,343,343,343,343, 87,344,344,
344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,
344,344,344,344,344,344,344,344,343,343, 87,343,343,343,343, 87,
343,343,343,343,343, 87,343, 87, 87, 87,343,343,343,343,343,343,
343, 87,344,344,344,344,344,344,344,344,344,344,344,344,344,344,
344,344,344,344,344,344,344,344,344,344,344,344,343,343,343,343,
343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,

/* block 145 */
343,343,343,343,343,343,344,344,344,344,344,344,344,344,344,344,
344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,
343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,
343,343,343,343,343,343,343,343,343,343,344,344,344,344,344,344,
344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,
344,344,344,344,343,343,343,343,343,343,343,343,343,343,343,343,
343,343,343,343,343,343,343,343,343,343,343,343,343,343,344,344,
344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,

/* block 146 */
344,344,344,344,344,344,344,344,343,343,343,343,343,343,343,343,
343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,
343,343,344,344,344,344,344,344,344,344,344,344,344,344,344,344,
344,344,344,344,344,344,344,344,344,344,344,344,343,343,343,343,
343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,
343,343,343,343,343,343,344,344,344,344,344,344,344,344,344,344,
344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,
343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,

/* block 147 */
343,343,343,343,343,343,343,343,343,343,344,344,344,344,344,344,
344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,
344,344,344,344,344,344, 87, 87,343,343,343,343,343,343,343,343,
343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,
343,  6,344,344,344,344,344,344,344,344,344,344,344,344,344,344,
344,344,344,344,344,344,344,344,344,344,344,  6,344,344,344,344,
344,344,343,343,343,343,343,343,343,343,343,343,343,343,343,343,
343,343,343,343,343,343,343,343,343,343,343,  6,344,344,344,344,

/* block 148 */
344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,
344,344,344,344,344,  6,344,344,344,344,344,344,343,343,343,343,
343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,
343,343,343,343,343,  6,344,344,344,344,344,344,344,344,344,344,
344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,  6,
344,344,344,344,344,344,343,343,343,343,343,343,343,343,343,343,
343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,  6,
344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,

/* block 149 */
344,344,344,344,344,344,344,344,344,  6,344,344,344,344,344,344,
343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,
343,343,343,343,343,343,343,343,343,  6,344,344,344,344,344,344,
344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,
344,344,344,  6,344,344,344,344,344,344,343,344, 87, 87,  8,  8,
  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,
  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,
  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,

/* block 150 */
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 87, 87, 87, 87,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,

/* block 151 */
 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
 13, 13, 13, 13, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 152 */
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 153 */
384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,
384,384,384,384,384,384,384,384,384,384,384,384,384,384, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 154 */
 87, 16, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,

/* block 155 */
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,

/* block 156 */
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87, 87,

/* block 157 */
420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,
420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,
420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,
420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,
420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,
420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,
420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,
420,420,420,420,420,420,420,420,420,420,420,420,420,420, 87, 87,

};

#if UCD_BLOCK_SIZE != 128
#error Please correct UCD_BLOCK_SIZE
#endif

/* Table for handling escaped characters in the range '0'-'z'. Positive returns
are simple data values; negative values are for special things like \d and so
on. Zero means further processing is needed (for things like \x), or the escape
is invalid. */

/* This is the "normal" table for ASCII systems */
static const short int escapes[] = {
     0,      0,      0,      0,      0,      0,      0,      0,   /* 0 - 7 */
     0,      0,    ':',    ';',    '<',    '=',    '>',    '?',   /* 8 - ? */
   '@', -ESC_A, -ESC_B, -ESC_C, -ESC_D, -ESC_E,      0, -ESC_G,   /* @ - G */
-ESC_H,      0,      0, -ESC_K,      0,      0,      0,      0,   /* H - O */
-ESC_P, -ESC_Q, -ESC_R, -ESC_S,      0,      0, -ESC_V, -ESC_W,   /* P - W */
-ESC_X,      0, -ESC_Z,    '[',   '\\',    ']',    '^',    '_',   /* X - _ */
   '`',      7, -ESC_b,      0, -ESC_d,  ESC_e,  ESC_f,      0,   /* ` - g */
-ESC_h,      0,      0, -ESC_k,      0,      0,  ESC_n,      0,   /* h - o */
-ESC_p,      0,  ESC_r, -ESC_s,  ESC_tee,    0, -ESC_v, -ESC_w,   /* p - w */
     0,      0, -ESC_z                                            /* x - z */
};

/* Table of special "verbs" like (*PRUNE). This is a short table, so it is
searched linearly. Put all the names into a single string, in order to reduce
the number of relocations when a shared library is dynamically linked. */

typedef struct verbitem {
  int   len;
  int   op;
} verbitem;

static const char verbnames[] =
  "ACCEPT\0"
  "COMMIT\0"
  "F\0"
  "FAIL\0"
  "PRUNE\0"
  "SKIP\0"
  "THEN";

static const verbitem verbs[] = {
  { 6, OP_ACCEPT },
  { 6, OP_COMMIT },
  { 1, OP_FAIL },
  { 4, OP_FAIL },
  { 5, OP_PRUNE },
  { 4, OP_SKIP  },
  { 4, OP_THEN  }
};

static const int verbcount = sizeof(verbs)/sizeof(verbitem);


/* Tables of names of POSIX character classes and their lengths. The names are
now all in a single string, to reduce the number of relocations when a shared
library is dynamically loaded. The list of lengths is terminated by a zero
length entry. The first three must be alpha, lower, upper, as this is assumed
for handling case independence. */

static const char posix_names[] =
  "alpha\0"  "lower\0"  "upper\0"  "alnum\0"  "ascii\0"  "blank\0"
  "cntrl\0"  "digit\0"  "graph\0"  "print\0"  "punct\0"  "space\0"
  "word\0"   "xdigit";

static const uschar posix_name_lengths[] = {
  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 4, 6, 0 };

/* Table of class bit maps for each POSIX class. Each class is formed from a
base map, with an optional addition or removal of another map. Then, for some
classes, there is some additional tweaking: for [:blank:] the vertical space
characters are removed, and for [:alpha:] and [:alnum:] the underscore
character is removed. The triples in the table consist of the base map offset,
second map offset or -1 if no second map, and a non-negative value for map
addition or a negative value for map subtraction (if there are two maps). The
absolute value of the third field has these meanings: 0 => no tweaking, 1 =>
remove vertical space characters, 2 => remove underscore. */

static const int posix_class_maps[] = {
  cbit_word,  cbit_digit, -2,             /* alpha */
  cbit_lower, -1,          0,             /* lower */
  cbit_upper, -1,          0,             /* upper */
  cbit_word,  -1,          2,             /* alnum - word without underscore */
  cbit_print, cbit_cntrl,  0,             /* ascii */
  cbit_space, -1,          1,             /* blank - a GNU extension */
  cbit_cntrl, -1,          0,             /* cntrl */
  cbit_digit, -1,          0,             /* digit */
  cbit_graph, -1,          0,             /* graph */
  cbit_print, -1,          0,             /* print */
  cbit_punct, -1,          0,             /* punct */
  cbit_space, -1,          0,             /* space */
  cbit_word,  -1,          0,             /* word - a Perl extension */
  cbit_xdigit,-1,          0              /* xdigit */
};



/* The texts of compile-time error messages. These are "char *" because they
are passed to the outside world. Do not ever re-use any error number, because
they are documented. Always add a new error instead. Messages marked DEAD below
are no longer used. This used to be a table of strings, but in order to reduce
the number of relocations needed when a shared library is loaded dynamically,
it is now one long string. We cannot use a table of offsets, because the
lengths of inserts such as XSTRING(MAX_NAME_SIZE) are not known. Instead, we
simply count through to the one we want - this isn't a performance issue
because these strings are used only when there is a compilation error. */

static const char error_texts[] =
  "no error\0"
  "\\ at end of pattern\0"
  "\\c at end of pattern\0"
  "unrecognized character follows \\\0"
  "numbers out of order in {} quantifier\0"
  /* 5 */
  "number too big in {} quantifier\0"
  "missing terminating ] for character class\0"
  "invalid escape sequence in character class\0"
  "range out of order in character class\0"
  "nothing to repeat\0"
  /* 10 */
  "operand of unlimited repeat could match the empty string\0"  /** DEAD **/
  "internal error: unexpected repeat\0"
  "unrecognized character after (? or (?-\0"
  "POSIX named classes are supported only within a class\0"
  "missing )\0"
  /* 15 */
  "reference to non-existent subpattern\0"
  "erroffset passed as NULL\0"
  "unknown option bit(s) set\0"
  "missing ) after comment\0"
  "parentheses nested too deeply\0"  /** DEAD **/
  /* 20 */
  "regular expression is too large\0"
  "failed to get memory\0"
  "unmatched parentheses\0"
  "internal error: code overflow\0"
  "unrecognized character after (?<\0"
  /* 25 */
  "lookbehind assertion is not fixed length\0"
  "malformed number or name after (?(\0"
  "conditional group contains more than two branches\0"
  "assertion expected after (?(\0"
  "(?R or (?[+-]digits must be followed by )\0"
  /* 30 */
  "unknown POSIX class name\0"
  "POSIX collating elements are not supported\0"
  "this version of PCRE is not compiled with PCRE_UTF8 support\0"
  "spare error\0"  /** DEAD **/
  "character value in \\x{...} sequence is too large\0"
  /* 35 */
  "invalid condition (?(0)\0"
  "\\C not allowed in lookbehind assertion\0"
  "PCRE does not support \\L, \\l, \\N, \\U, or \\u\0"
  "number after (?C is > 255\0"
  "closing ) for (?C expected\0"
  /* 40 */
  "recursive call could loop indefinitely\0"
  "unrecognized character after (?P\0"
  "syntax error in subpattern name (missing terminator)\0"
  "two named subpatterns have the same name\0"
  "invalid UTF-8 string\0"
  /* 45 */
  "support for \\P, \\p, and \\X has not been compiled\0"
  "malformed \\P or \\p sequence\0"
  "unknown property name after \\P or \\p\0"
  "subpattern name is too long (maximum " XSTRING(MAX_NAME_SIZE) " characters)\0"
  "too many named subpatterns (maximum " XSTRING(MAX_NAME_COUNT) ")\0"
  /* 50 */
  "repeated subpattern is too long\0"    /** DEAD **/
  "octal value is greater than \\377 (not in UTF-8 mode)\0"
  "internal error: overran compiling workspace\0"
  "internal error: previously-checked referenced subpattern not found\0"
  "DEFINE group contains more than one branch\0"
  /* 55 */
  "repeating a DEFINE group is not allowed\0"
  "inconsistent NEWLINE options\0"
  "\\g is not followed by a braced, angle-bracketed, or quoted name/number or by a plain number\0"
  "a numbered reference must not be zero\0"
  "(*VERB) with an argument is not supported\0"
  /* 60 */
  "(*VERB) not recognized\0"
  "number is too big\0"
  "subpattern name expected\0"
  "digit expected after (?+\0"
  "] is an invalid data character in JavaScript compatibility mode";


/* Table to identify digits and hex digits. This is used when compiling
patterns. Note that the tables in chartables are dependent on the locale, and
may mark arbitrary characters as digits - but the PCRE compiling code expects
to handle only 0-9, a-z, and A-Z as digits when compiling. That is why we have
a private table here. It costs 256 bytes, but it is a lot faster than doing
character value tests (at least in some simple cases I timed), and in some
applications one wants PCRE to compile efficiently as well as match
efficiently.

For convenience, we use the same bit definitions as in chartables:

  0x04   decimal digit
  0x08   hexadecimal digit

Then we can use ctype_digit and ctype_xdigit in the code. */

/* This is the "normal" case, for ASCII systems */
static const unsigned char digitab[] =
  {
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /*   0-  7 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /*   8- 15 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /*  16- 23 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /*  24- 31 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /*    - '  */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /*  ( - /  */
  0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c, /*  0 - 7  */
  0x0c,0x0c,0x00,0x00,0x00,0x00,0x00,0x00, /*  8 - ?  */
  0x00,0x08,0x08,0x08,0x08,0x08,0x08,0x00, /*  @ - G  */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /*  H - O  */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /*  P - W  */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /*  X - _  */
  0x00,0x08,0x08,0x08,0x08,0x08,0x08,0x00, /*  ` - g  */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /*  h - o  */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /*  p - w  */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /*  x -127 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 128-135 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 136-143 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 144-151 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 152-159 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 160-167 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 168-175 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 176-183 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 184-191 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 192-199 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 200-207 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 208-215 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 216-223 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 224-231 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 232-239 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* 240-247 */
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};/* 248-255 */

/* Min and max values for the common repeats; for the maxima, 0 => infinity */
static const char rep_min[] = { 0, 0, 1, 1, 0, 0 };
static const char rep_max[] = { 0, 0, 0, 0, 1, 1 };

/*+-------------------------------------------------------------------------+*/
/*| functions:                                                              |*/
/*+-------------------------------------------------------------------------+*/

/*************************************************
*      Check for newline at given position       *
*************************************************/

/* It is guaranteed that the initial value of ptr is less than the end of the
string that is being processed.

Arguments:
  ptr          pointer to possible newline
  type         the newline type
  endptr       pointer to the end of the string
  lenptr       where to return the length
  utf8         TRUE if in utf8 mode

Returns:       TRUE or FALSE
*/

BOOL
_pcre_is_newline(const uschar *ptr, int type, const uschar *endptr,
  int *lenptr, BOOL utf8)
{
int c;
if (utf8) { GETCHAR(c, ptr); } else c = *ptr;

if (type == NLTYPE_ANYCRLF) switch(c)
  {
  case 0x000a: *lenptr = 1; return TRUE;             /* LF */
  case 0x000d: *lenptr = (ptr < endptr - 1 && ptr[1] == 0x0a)? 2 : 1;
               return TRUE;                          /* CR */
  default: return FALSE;
  }

/* NLTYPE_ANY */

else switch(c)
  {
  case 0x000a:                                       /* LF */
  case 0x000b:                                       /* VT */
  case 0x000c: *lenptr = 1; return TRUE;             /* FF */
  case 0x000d: *lenptr = (ptr < endptr - 1 && ptr[1] == 0x0a)? 2 : 1;
               return TRUE;                          /* CR */
  case 0x0085: *lenptr = utf8? 2 : 1; return TRUE;   /* NEL */
  case 0x2028:                                       /* LS */
  case 0x2029: *lenptr = 3; return TRUE;             /* PS */
  default: return FALSE;
  }
}



/*************************************************
*     Check for newline at previous position     *
*************************************************/

/* It is guaranteed that the initial value of ptr is greater than the start of
the string that is being processed.

Arguments:
  ptr          pointer to possible newline
  type         the newline type
  startptr     pointer to the start of the string
  lenptr       where to return the length
  utf8         TRUE if in utf8 mode

Returns:       TRUE or FALSE
*/

BOOL
_pcre_was_newline(const uschar *ptr, int type, const uschar *startptr,
  int *lenptr, BOOL utf8)
{
int c;
ptr--;
#ifdef SUPPORT_UTF8
if (utf8)
  {
  BACKCHAR(ptr);
  GETCHAR(c, ptr);
  }
else c = *ptr;
#else   /* no UTF-8 support */
c = *ptr;
#endif  /* SUPPORT_UTF8 */

if (type == NLTYPE_ANYCRLF) switch(c)
  {
  case 0x000a: *lenptr = (ptr > startptr && ptr[-1] == 0x0d)? 2 : 1;
               return TRUE;                         /* LF */
  case 0x000d: *lenptr = 1; return TRUE;            /* CR */
  default: return FALSE;
  }

else switch(c)
  {
  case 0x000a: *lenptr = (ptr > startptr && ptr[-1] == 0x0d)? 2 : 1;
               return TRUE;                         /* LF */
  case 0x000b:                                      /* VT */
  case 0x000c:                                      /* FF */
  case 0x000d: *lenptr = 1; return TRUE;            /* CR */
  case 0x0085: *lenptr = utf8? 2 : 1; return TRUE;  /* NEL */
  case 0x2028:                                      /* LS */
  case 0x2029: *lenptr = 3; return TRUE;            /* PS */
  default: return FALSE;
  }
}

/* This module contains an internal function that tests a compiled pattern to
see if it was compiled with the opposite endianness. If so, it uses an
auxiliary local function to flip the appropriate bytes. */



/*************************************************
*         Flip bytes in an integer               *
*************************************************/

/* This function is called when the magic number in a regex doesn't match, in
order to flip its bytes to see if we are dealing with a pattern that was
compiled on a host of different endianness. If so, this function is used to
flip other byte values.

Arguments:
  value        the number to flip
  n            the number of bytes to flip (assumed to be 2 or 4)

Returns:       the flipped value
*/

static unsigned long int
byteflip(unsigned long int value, int n)
{
if (n == 2) return ((value & 0x00ff) << 8) | ((value & 0xff00) >> 8);
return ((value & 0x000000ff) << 24) |
       ((value & 0x0000ff00) <<  8) |
       ((value & 0x00ff0000) >>  8) |
       ((value & 0xff000000) >> 24);
}



/*************************************************
*       Test for a byte-flipped compiled regex   *
*************************************************/

/* This function is called from pcre_exec(), pcre_dfa_exec(), and also from
pcre_fullinfo(). Its job is to test whether the regex is byte-flipped - that
is, it was compiled on a system of opposite endianness. The function is called
only when the native MAGIC_NUMBER test fails. If the regex is indeed flipped,
we flip all the relevant values into a different data block, and return it.

Arguments:
  re               points to the regex
  study            points to study data, or NULL
  internal_re      points to a new regex block
  internal_study   points to a new study block

Returns:           the new block if is is indeed a byte-flipped regex
                   NULL if it is not
*/

real_pcre *
_pcre_try_flipped(const real_pcre *re, real_pcre *internal_re,
  const pcre_study_data *study, pcre_study_data *internal_study)
{
if (byteflip(re->magic_number, sizeof(re->magic_number)) != MAGIC_NUMBER)
  return NULL;

*internal_re = *re;           /* To copy other fields */
internal_re->size = byteflip(re->size, sizeof(re->size));
internal_re->options = byteflip(re->options, sizeof(re->options));
internal_re->flags = (pcre_uint16)byteflip(re->flags, sizeof(re->flags));
internal_re->top_bracket =
  (pcre_uint16)byteflip(re->top_bracket, sizeof(re->top_bracket));
internal_re->top_backref =
  (pcre_uint16)byteflip(re->top_backref, sizeof(re->top_backref));
internal_re->first_byte =
  (pcre_uint16)byteflip(re->first_byte, sizeof(re->first_byte));
internal_re->req_byte =
  (pcre_uint16)byteflip(re->req_byte, sizeof(re->req_byte));
internal_re->name_table_offset =
  (pcre_uint16)byteflip(re->name_table_offset, sizeof(re->name_table_offset));
internal_re->name_entry_size =
  (pcre_uint16)byteflip(re->name_entry_size, sizeof(re->name_entry_size));
internal_re->name_count =
  (pcre_uint16)byteflip(re->name_count, sizeof(re->name_count));

if (study != NULL)
  {
  *internal_study = *study;   /* To copy other fields */
  internal_study->size = byteflip(study->size, sizeof(study->size));
  internal_study->options = byteflip(study->options, sizeof(study->options));
  }

return internal_re;
}

/*************************************************
*         Validate a UTF-8 string                *
*************************************************/

/* This function is called (optionally) at the start of compile or match, to
validate that a supposed UTF-8 string is actually valid. The early check means
that subsequent code can assume it is dealing with a valid string. The check
can be turned off for maximum performance, but the consequences of supplying
an invalid string are then undefined.

Originally, this function checked according to RFC 2279, allowing for values in
the range 0 to 0x7fffffff, up to 6 bytes long, but ensuring that they were in
the canonical format. Once somebody had pointed out RFC 3629 to me (it
obsoletes 2279), additional restrictions were applied. The values are now
limited to be between 0 and 0x0010ffff, no more than 4 bytes long, and the
subrange 0xd000 to 0xdfff is excluded.

Arguments:
  string       points to the string
  length       length of string, or -1 if the string is zero-terminated

Returns:       < 0    if the string is a valid UTF-8 string
               >= 0   otherwise; the value is the offset of the bad byte
*/

int
_pcre_valid_utf8(const uschar *string, int length)
{
#ifdef SUPPORT_UTF8
register const uschar *p;

if (length < 0)
  {
  for (p = string; *p != 0; p++);
  length = (int)(p - string);
  }

for (p = string; length-- > 0; p++)
  {
  register int ab;
  register int c = *p;
  if (c < 128) continue;
  if (c < 0xc0) return (int)(p - string);
  ab = _pcre_utf8_table4[c & 0x3f];     /* Number of additional bytes */
  if (length < ab || ab > 3) return (int)(p - string);
  length -= ab;

  /* Check top bits in the second byte */
  if ((*(++p) & 0xc0) != 0x80) return (int)(p - string);

  /* Check for overlong sequences for each different length, and for the
  excluded range 0xd000 to 0xdfff.  */

  switch (ab)
    {
    /* Check for xx00 000x (overlong sequence) */

    case 1:
    if ((c & 0x3e) == 0) return (int)(p - string);
    continue;   /* We know there aren't any more bytes to check */

    /* Check for 1110 0000, xx0x xxxx (overlong sequence) or
                 1110 1101, 1010 xxxx (0xd000 - 0xdfff) */

    case 2:
    if ((c == 0xe0 && (*p & 0x20) == 0) ||
        (c == 0xed && *p >= 0xa0))
      return (int)(p - string);
    break;

    /* Check for 1111 0000, xx00 xxxx (overlong sequence) or
       greater than 0x0010ffff (f4 8f bf bf) */

    case 3:
    if ((c == 0xf0 && (*p & 0x30) == 0) ||
        (c > 0xf4 ) ||
        (c == 0xf4 && *p > 0x8f))
      return (int)(p - string);
    break;

#if 0
    /* These cases can no longer occur, as we restrict to a maximum of four
    bytes nowadays. Leave the code here in case we ever want to add an option
    for longer sequences. */

    /* Check for 1111 1000, xx00 0xxx */
    case 4:
    if (c == 0xf8 && (*p & 0x38) == 0) return (int)(p - string);
    break;

    /* Check for leading 0xfe or 0xff, and then for 1111 1100, xx00 00xx */
    case 5:
    if (c == 0xfe || c == 0xff ||
       (c == 0xfc && (*p & 0x3c) == 0)) return (int)(p - string);
    break;
#endif

    }

  /* Check for valid bytes after the 2nd, if any; all must start 10 */
  while (--ab > 0)
    {
    if ((*(++p) & 0xc0) != 0x80) return (int)(p - string);
    }
  }
#else
(void)(string);  /* Keep picky compilers happy */
(void)(length);
#endif

return -1;
}


/*************************************************
*       Match character against an XCLASS        *
*************************************************/

/* This function is called to match a character against an extended class that
might contain values > 255.

Arguments:
  c           the character
  data        points to the flag byte of the XCLASS data

Returns:      TRUE if character matches, else FALSE
*/

BOOL
_pcre_xclass(int c, const uschar *data)
{
int t;
BOOL negated = (*data & XCL_NOT) != 0;

/* Character values < 256 are matched against a bitmap, if one is present. If
not, we still carry on, because there may be ranges that start below 256 in the
additional data. */

if (c < 256)
  {
  if ((*data & XCL_MAP) != 0 && (data[1 + c/8] & (1 << (c&7))) != 0)
    return !negated;   /* char found */
  }

/* First skip the bit map if present. Then match against the list of Unicode
properties or large chars or ranges that end with a large char. We won't ever
encounter XCL_PROP or XCL_NOTPROP when UCP support is not compiled. */

if ((*data++ & XCL_MAP) != 0) data += 32;

while ((t = *data++) != XCL_END)
  {
  int x, y;
  if (t == XCL_SINGLE)
    {
    GETCHARINC(x, data);
    if (c == x) return !negated;
    }
  else if (t == XCL_RANGE)
    {
    GETCHARINC(x, data);
    GETCHARINC(y, data);
    if (c >= x && c <= y) return !negated;
    }

#ifdef SUPPORT_UCP
  else  /* XCL_PROP & XCL_NOTPROP */
    {
    const ucd_record * prop = GET_UCD(c);

    switch(*data)
      {
      case PT_ANY:
      if (t == XCL_PROP) return !negated;
      break;

      case PT_LAMP:
      if ((prop->chartype == ucp_Lu || prop->chartype == ucp_Ll || prop->chartype == ucp_Lt) ==
          (t == XCL_PROP)) return !negated;
      break;

      case PT_GC:
      if ((data[1] == _pcre_ucp_gentype[prop->chartype]) == (t == XCL_PROP)) return !negated;
      break;

      case PT_PC:
      if ((data[1] == prop->chartype) == (t == XCL_PROP)) return !negated;
      break;

      case PT_SC:
      if ((data[1] == prop->script) == (t == XCL_PROP)) return !negated;
      break;

      /* This should never occur, but compilers may mutter if there is no
      default. */

      default:
      return FALSE;
      }

    data += 2;
    }
#endif  /* SUPPORT_UCP */
  }

return negated;   /* char did not match */
}



/*************************************************
*       Convert character value to UTF-8         *
*************************************************/

/* This function takes an integer value in the range 0 - 0x7fffffff
and encodes it as a UTF-8 character in 0 to 6 bytes.

Arguments:
  cvalue     the character value
  buffer     pointer to buffer for result - at least 6 bytes long

Returns:     number of characters placed in the buffer
*/

int
_pcre_ord2utf8(int cvalue, uschar *buffer)
{
#ifdef SUPPORT_UTF8
register int i, j;
for (i = 0; i < _pcre_utf8_table1_size; i++)
  if (cvalue <= _pcre_utf8_table1[i]) break;
buffer += i;
for (j = i; j > 0; j--)
 {
 *buffer-- = (uschar)(0x80 | (cvalue & 0x3f));
 cvalue >>= 6;
 }
*buffer = (uschar)(_pcre_utf8_table2[i] | cvalue);
return i + 1;
#else
(void)(cvalue);  /* Keep compiler happy; this function won't ever be */
(void)(buffer);  /* called when SUPPORT_UTF8 is not defined. */
return 0;
#endif
}


/* Definition to allow mutual recursion */
static BOOL
  compile_regex(int, int, uschar **, const uschar **, int *, BOOL, BOOL, int,
    int *, int *, branch_chain *, compile_data *, int *);



/*************************************************
*            Find an error text                  *
*************************************************/

/* The error texts are now all in one long string, to save on relocations. As
some of the text is of unknown length, we can't use a table of offsets.
Instead, just count through the strings. This is not a performance issue
because it happens only when there has been a compilation error.

Argument:   the error number
Returns:    pointer to the error string
*/

static const char *
find_error_text(int n)
{
const char *s = error_texts;
for (; n > 0; n--) while (*s++ != 0) {};
return s;
}


/*************************************************
*            Handle escapes                      *
*************************************************/

/* This function is called when a \ has been encountered. It either returns a
positive value for a simple escape such as \n, or a negative value which
encodes one of the more complicated things such as \d. A backreference to group
n is returned as -(ESC_REF + n); ESC_REF is the highest ESC_xxx macro. When
UTF-8 is enabled, a positive value greater than 255 may be returned. On entry,
ptr is pointing at the \. On exit, it is on the final character of the escape
sequence.

Arguments:
  ptrptr         points to the pattern position pointer
  errorcodeptr   points to the errorcode variable
  bracount       number of previous extracting brackets
  options        the options bits
  isclass        TRUE if inside a character class

Returns:         zero or positive => a data character
                 negative => a special escape sequence
                 on error, errorcodeptr is set
*/

static int
check_escape(const uschar **ptrptr, int *errorcodeptr, int bracount,
  int options, BOOL isclass)
{
BOOL utf8 = (options & PCRE_UTF8) != 0;
const uschar *ptr = *ptrptr + 1;
int c, i;

GETCHARINCTEST(c, ptr);           /* Get character value, increment pointer */
ptr--;                            /* Set pointer back to the last byte */

/* If backslash is at the end of the pattern, it's an error. */

if (c == 0) *errorcodeptr = ERR1;

/* Non-alphanumerics are literals. For digits or letters, do an initial lookup
in a table. A non-zero result is something that can be returned immediately.
Otherwise further processing may be required. */

else if (c < '0' || c > 'z') {}                           /* Not alphanumeric */
else if ((i = escapes[c - '0']) != 0) c = i;


/* Escapes that need further processing, or are illegal. */

else
  {
  const uschar *oldptr;
  BOOL braced, negated;

  switch (c)
    {
    /* A number of Perl escapes are not handled by PCRE. We give an explicit
    error. */

    case 'l':
    case 'L':
    case 'N':
    case 'u':
    case 'U':
    *errorcodeptr = ERR37;
    break;

    /* \g must be followed by one of a number of specific things:

    (1) A number, either plain or braced. If positive, it is an absolute
    backreference. If negative, it is a relative backreference. This is a Perl
    5.10 feature.

    (2) Perl 5.10 also supports \g{name} as a reference to a named group. This
    is part of Perl's movement towards a unified syntax for back references. As
    this is synonymous with \k{name}, we fudge it up by pretending it really
    was \k.

    (3) For Oniguruma compatibility we also support \g followed by a name or a
    number either in angle brackets or in single quotes. However, these are
    (possibly recursive) subroutine calls, _not_ backreferences. Just return
    the -ESC_g code (cf \k). */

    case 'g':
    if (ptr[1] == '<' || ptr[1] == '\'')
      {
      c = -ESC_g;
      break;
      }

    /* Handle the Perl-compatible cases */

    if (ptr[1] == '{')
      {
      const uschar *p;
      for (p = ptr+2; *p != 0 && *p != '}'; p++)
        if (*p != '-' && (digitab[*p] & ctype_digit) == 0) break;
      if (*p != 0 && *p != '}')
        {
        c = -ESC_k;
        break;
        }
      braced = TRUE;
      ptr++;
      }
    else braced = FALSE;

    if (ptr[1] == '-')
      {
      negated = TRUE;
      ptr++;
      }
    else negated = FALSE;

    c = 0;
    while ((digitab[ptr[1]] & ctype_digit) != 0)
      c = c * 10 + *(++ptr) - '0';

    if (c < 0)   /* Integer overflow */
      {
      *errorcodeptr = ERR61;
      break;
      }

    if (braced && *(++ptr) != '}')
      {
      *errorcodeptr = ERR57;
      break;
      }

    if (c == 0)
      {
      *errorcodeptr = ERR58;
      break;
      }

    if (negated)
      {
      if (c > bracount)
        {
        *errorcodeptr = ERR15;
        break;
        }
      c = bracount - (c - 1);
      }

    c = -(ESC_REF + c);
    break;

    /* The handling of escape sequences consisting of a string of digits
    starting with one that is not zero is not straightforward. By experiment,
    the way Perl works seems to be as follows:

    Outside a character class, the digits are read as a decimal number. If the
    number is less than 10, or if there are that many previous extracting
    left brackets, then it is a back reference. Otherwise, up to three octal
    digits are read to form an escaped byte. Thus \123 is likely to be octal
    123 (cf \0123, which is octal 012 followed by the literal 3). If the octal
    value is greater than 377, the least significant 8 bits are taken. Inside a
    character class, \ followed by a digit is always an octal number. */

    case '1': case '2': case '3': case '4': case '5':
    case '6': case '7': case '8': case '9':

    if (!isclass)
      {
      oldptr = ptr;
      c -= '0';
      while ((digitab[ptr[1]] & ctype_digit) != 0)
        c = c * 10 + *(++ptr) - '0';
      if (c < 0)    /* Integer overflow */
        {
        *errorcodeptr = ERR61;
        break;
        }
      if (c < 10 || c <= bracount)
        {
        c = -(ESC_REF + c);
        break;
        }
      ptr = oldptr;      /* Put the pointer back and fall through */
      }

    /* Handle an octal number following \. If the first digit is 8 or 9, Perl
    generates a binary zero byte and treats the digit as a following literal.
    Thus we have to pull back the pointer by one. */

    if ((c = *ptr) >= '8')
      {
      ptr--;
      c = 0;
      break;
      }

    /* \0 always starts an octal number, but we may drop through to here with a
    larger first octal digit. The original code used just to take the least
    significant 8 bits of octal numbers (I think this is what early Perls used
    to do). Nowadays we allow for larger numbers in UTF-8 mode, but no more
    than 3 octal digits. */

    case '0':
    c -= '0';
    while(i++ < 2 && ptr[1] >= '0' && ptr[1] <= '7')
        c = c * 8 + *(++ptr) - '0';
    if (!utf8 && c > 255) *errorcodeptr = ERR51;
    break;

    /* \x is complicated. \x{ddd} is a character number which can be greater
    than 0xff in utf8 mode, but only if the ddd are hex digits. If not, { is
    treated as a data character. */

    case 'x':
    if (ptr[1] == '{')
      {
      const uschar *pt = ptr + 2;
      int count = 0;

      c = 0;
      while ((digitab[*pt] & ctype_xdigit) != 0)
        {
        register int cc = *pt++;
        if (c == 0 && cc == '0') continue;     /* Leading zeroes */
        count++;

        if (cc >= 'a') cc -= 32;               /* Convert to upper case */
        c = (c << 4) + cc - ((cc < 'A')? '0' : ('A' - 10));
        }

      if (*pt == '}')
        {
        if (c < 0 || count > (utf8? 8 : 2)) *errorcodeptr = ERR34;
        ptr = pt;
        break;
        }

      /* If the sequence of hex digits does not end with '}', then we don't
      recognize this construct; fall through to the normal \x handling. */
      }

    /* Read just a single-byte hex-defined char */

    c = 0;
    while (i++ < 2 && (digitab[ptr[1]] & ctype_xdigit) != 0)
      {
      int cc;                               /* Some compilers don't like ++ */
      cc = *(++ptr);                        /* in initializers */
      if (cc >= 'a') cc -= 32;              /* Convert to upper case */
      c = c * 16 + cc - ((cc < 'A')? '0' : ('A' - 10));
      }
    break;

    /* For \c, a following letter is upper-cased; then the 0x40 bit is flipped.
    This coding is ASCII-specific, but then the whole concept of \cx is
    ASCII-specific. */

    case 'c':
    c = *(++ptr);
    if (c == 0)
      {
      *errorcodeptr = ERR2;
      break;
      }

    if (c >= 'a' && c <= 'z') c -= 32;
    c ^= 0x40;
    break;

    /* PCRE_EXTRA enables extensions to Perl in the matter of escapes. Any
    other alphanumeric following \ is an error if PCRE_EXTRA was set;
    otherwise, for Perl compatibility, it is a literal. This code looks a bit
    odd, but there used to be some cases other than the default, and there may
    be again in future, so I haven't "optimized" it. */

    default:
    if ((options & PCRE_EXTRA) != 0) switch(c)
      {
      default:
      *errorcodeptr = ERR3;
      break;
      }
    break;
    }
  }

*ptrptr = ptr;
return c;
}



#ifdef SUPPORT_UCP
/*************************************************
*               Handle \P and \p                 *
*************************************************/

/* This function is called after \P or \p has been encountered, provided that
PCRE is compiled with support for Unicode properties. On entry, ptrptr is
pointing at the P or p. On exit, it is pointing at the final character of the
escape sequence.

Argument:
  ptrptr         points to the pattern position pointer
  negptr         points to a boolean that is set TRUE for negation else FALSE
  dptr           points to an int that is set to the detailed property value
  errorcodeptr   points to the error code variable

Returns:         type value from ucp_type_table, or -1 for an invalid type
*/

static int
get_ucp(const uschar **ptrptr, BOOL *negptr, int *dptr, int *errorcodeptr)
{
int c, i, bot, top;
const uschar *ptr = *ptrptr;
char name[32];

c = *(++ptr);
if (c == 0) goto ERROR_RETURN;

*negptr = FALSE;

/* \P or \p can be followed by a name in {}, optionally preceded by ^ for
negation. */

if (c == '{')
  {
  if (ptr[1] == '^')
    {
    *negptr = TRUE;
    ptr++;
    }
  for (i = 0; i < (int)sizeof(name) - 1; i++)
    {
    c = *(++ptr);
    if (c == 0) goto ERROR_RETURN;
    if (c == '}') break;
    name[i] = c;
    }
  if (c !='}') goto ERROR_RETURN;
  name[i] = 0;
  }

/* Otherwise there is just one following character */

else
  {
  name[0] = c;
  name[1] = 0;
  }

*ptrptr = ptr;

/* Search for a recognized property name using binary chop */

bot = 0;
top = _pcre_utt_size;

while (bot < top)
  {
  i = (bot + top) >> 1;
  c = strcmp(name, _pcre_utt_names + _pcre_utt[i].name_offset);
  if (c == 0)
    {
    *dptr = _pcre_utt[i].value;
    return _pcre_utt[i].type;
    }
  if (c > 0) bot = i + 1; else top = i;
  }

*errorcodeptr = ERR47;
*ptrptr = ptr;
return -1;

ERROR_RETURN:
*errorcodeptr = ERR46;
*ptrptr = ptr;
return -1;
}
#endif


/*************************************************
*            Check for counted repeat            *
*************************************************/

/* This function is called when a '{' is encountered in a place where it might
start a quantifier. It looks ahead to see if it really is a quantifier or not.
It is only a quantifier if it is one of the forms {ddd} {ddd,} or {ddd,ddd}
where the ddds are digits.

Arguments:
  p         pointer to the first char after '{'

Returns:    TRUE or FALSE
*/

static BOOL
is_counted_repeat(const uschar *p)
{
if ((digitab[*p++] & ctype_digit) == 0) return FALSE;
while ((digitab[*p] & ctype_digit) != 0) p++;
if (*p == '}') return TRUE;

if (*p++ != ',') return FALSE;
if (*p == '}') return TRUE;

if ((digitab[*p++] & ctype_digit) == 0) return FALSE;
while ((digitab[*p] & ctype_digit) != 0) p++;

return (*p == '}');
}


/*************************************************
*         Read repeat counts                     *
*************************************************/

/* Read an item of the form {n,m} and return the values. This is called only
after is_counted_repeat() has confirmed that a repeat-count quantifier exists,
so the syntax is guaranteed to be correct, but we need to check the values.

Arguments:
  p              pointer to first char after '{'
  minp           pointer to int for min
  maxp           pointer to int for max
                 returned as -1 if no max
  errorcodeptr   points to error code variable

Returns:         pointer to '}' on success;
                 current ptr on error, with errorcodeptr set non-zero
*/

static const uschar *
read_repeat_counts(const uschar *p, int *minp, int *maxp, int *errorcodeptr)
{
int min = 0;
int max = -1;

/* Read the minimum value and do a paranoid check: a negative value indicates
an integer overflow. */

while ((digitab[*p] & ctype_digit) != 0) min = min * 10 + *p++ - '0';
if (min < 0 || min > 65535)
  {
  *errorcodeptr = ERR5;
  return p;
  }

/* Read the maximum value if there is one, and again do a paranoid on its size.
Also, max must not be less than min. */

if (*p == '}') max = min; else
  {
  if (*(++p) != '}')
    {
    max = 0;
    while((digitab[*p] & ctype_digit) != 0) max = max * 10 + *p++ - '0';
    if (max < 0 || max > 65535)
      {
      *errorcodeptr = ERR5;
      return p;
      }
    if (max < min)
      {
      *errorcodeptr = ERR4;
      return p;
      }
    }
  }

/* Fill in the required variables, and pass back the pointer to the terminating
'}'. */

*minp = min;
*maxp = max;
return p;
}


/*************************************************
*       Find forward referenced subpattern       *
*************************************************/

/* This function scans along a pattern's text looking for capturing
subpatterns, and counting them. If it finds a named pattern that matches the
name it is given, it returns its number. Alternatively, if the name is NULL, it
returns when it reaches a given numbered subpattern. This is used for forward
references to subpatterns. We know that if (?P< is encountered, the name will
be terminated by '>' because that is checked in the first pass.

Arguments:
  ptr          current position in the pattern
  cd           compile background data
  name         name to seek, or NULL if seeking a numbered subpattern
  lorn         name length, or subpattern number if name is NULL
  xmode        TRUE if we are in /x mode

Returns:       the number of the named subpattern, or -1 if not found
*/

static int
find_parens(const uschar *ptr, compile_data *cd, const uschar *name, int lorn,
  BOOL xmode)
{
const uschar *thisname;
int count = cd->bracount;

for (; *ptr != 0; ptr++)
  {
  int term;

  /* Skip over backslashed characters and also entire \Q...\E */

  if (*ptr == '\\')
    {
    if (*(++ptr) == 0) return -1;
    if (*ptr == 'Q') for (;;)
      {
      while (*(++ptr) != 0 && *ptr != '\\') {};
      if (*ptr == 0) return -1;
      if (*(++ptr) == 'E') break;
      }
    continue;
    }

  /* Skip over character classes; this logic must be similar to the way they
  are handled for real. If the first character is '^', skip it. Also, if the
  first few characters (either before or after ^) are \Q\E or \E we skip them
  too. This makes for compatibility with Perl. */

  if (*ptr == '[')
    {
    BOOL negate_class = FALSE;
    for (;;)
      {
      int c = *(++ptr);
      if (c == '\\')
        {
        if (ptr[1] == 'E') ptr++;
          else if (strncmp((const char *)ptr+1, "Q\\E", 3) == 0) ptr += 3;
            else break;
        }
      else if (!negate_class && c == '^')
        negate_class = TRUE;
      else break;
      }

    /* If the next character is ']', it is a data character that must be
    skipped, except in JavaScript compatibility mode. */

    if (ptr[1] == ']' && (cd->external_options & PCRE_JAVASCRIPT_COMPAT) == 0)
      ptr++;

    while (*(++ptr) != ']')
      {
      if (*ptr == 0) return -1;
      if (*ptr == '\\')
        {
        if (*(++ptr) == 0) return -1;
        if (*ptr == 'Q') for (;;)
          {
          while (*(++ptr) != 0 && *ptr != '\\') {};
          if (*ptr == 0) return -1;
          if (*(++ptr) == 'E') break;
          }
        continue;
        }
      }
    continue;
    }

  /* Skip comments in /x mode */

  if (xmode && *ptr == '#')
    {
    while (*(++ptr) != 0 && *ptr != '\n') {};
    if (*ptr == 0) return -1;
    continue;
    }

  /* An opening parens must now be a real metacharacter */

  if (*ptr != '(') continue;
  if (ptr[1] != '?' && ptr[1] != '*')
    {
    count++;
    if (name == NULL && count == lorn) return count;
    continue;
    }

  ptr += 2;
  if (*ptr == 'P') ptr++;                      /* Allow optional P */

  /* We have to disambiguate (?<! and (?<= from (?<name> */

  if ((*ptr != '<' || ptr[1] == '!' || ptr[1] == '=') &&
       *ptr != '\'')
    continue;

  count++;

  if (name == NULL && count == lorn) return count;
  term = *ptr++;
  if (term == '<') term = '>';
  thisname = ptr;
  while (*ptr != term) ptr++;
  if (name != NULL && lorn == ptr - thisname &&
      strncmp((const char *)name, (const char *)thisname, lorn) == 0)
    return count;
  }

return -1;
}



/*************************************************
*      Find first significant op code            *
*************************************************/

/* This is called by several functions that scan a compiled expression looking
for a fixed first character, or an anchoring op code etc. It skips over things
that do not influence this. For some calls, a change of option is important.
For some calls, it makes sense to skip negative forward and all backward
assertions, and also the \b assertion; for others it does not.

Arguments:
  code         pointer to the start of the group
  options      pointer to external options
  optbit       the option bit whose changing is significant, or
                 zero if none are
  skipassert   TRUE if certain assertions are to be skipped

Returns:       pointer to the first significant opcode
*/

static const uschar*
first_significant_code(const uschar *code, int *options, int optbit,
  BOOL skipassert)
{
for (;;)
  {
  switch ((int)*code)
    {
    case OP_OPT:
    if (optbit > 0 && ((int)code[1] & optbit) != (*options & optbit))
      *options = (int)code[1];
    code += 2;
    break;

    case OP_ASSERT_NOT:
    case OP_ASSERTBACK:
    case OP_ASSERTBACK_NOT:
    if (!skipassert) return code;
    do code += GET(code, 1); while (*code == OP_ALT);
    code += _pcre_OP_lengths[*code];
    break;

    case OP_WORD_BOUNDARY:
    case OP_NOT_WORD_BOUNDARY:
    if (!skipassert) return code;
    /* Fall through */

    case OP_CALLOUT:
    case OP_CREF:
    case OP_RREF:
    case OP_DEF:
    code += _pcre_OP_lengths[*code];
    break;

    default:
    return code;
    }
  }
/* Control never reaches here */
}


/*************************************************
*        Find the fixed length of a pattern      *
*************************************************/

/* Scan a pattern and compute the fixed length of subject that will match it,
if the length is fixed. This is needed for dealing with backward assertions.
In UTF8 mode, the result is in characters rather than bytes.

Arguments:
  code     points to the start of the pattern (the bracket)
  options  the compiling options

Returns:   the fixed length, or -1 if there is no fixed length,
             or -2 if \C was encountered
*/

static int
find_fixedlength(uschar *code, int options)
{
int length = -1;

register int branchlength = 0;
register uschar *cc = code + 1 + LINK_SIZE;

/* Scan along the opcodes for this branch. If we get to the end of the
branch, check the length against that of the other branches. */

for (;;)
  {
  int d;
  register int op = *cc;
  switch (op)
    {
    case OP_CBRA:
    case OP_BRA:
    case OP_ONCE:
    case OP_COND:
    d = find_fixedlength(cc + ((op == OP_CBRA)? 2:0), options);
    if (d < 0) return d;
    branchlength += d;
    do cc += GET(cc, 1); while (*cc == OP_ALT);
    cc += 1 + LINK_SIZE;
    break;

    /* Reached end of a branch; if it's a ket it is the end of a nested
    call. If it's ALT it is an alternation in a nested call. If it is
    END it's the end of the outer call. All can be handled by the same code. */

    case OP_ALT:
    case OP_KET:
    case OP_KETRMAX:
    case OP_KETRMIN:
    case OP_END:
    if (length < 0) length = branchlength;
      else if (length != branchlength) return -1;
    if (*cc != OP_ALT) return length;
    cc += 1 + LINK_SIZE;
    branchlength = 0;
    break;

    /* Skip over assertive subpatterns */

    case OP_ASSERT:
    case OP_ASSERT_NOT:
    case OP_ASSERTBACK:
    case OP_ASSERTBACK_NOT:
    do cc += GET(cc, 1); while (*cc == OP_ALT);
    /* Fall through */

    /* Skip over things that don't match chars */

    case OP_REVERSE:
    case OP_CREF:
    case OP_RREF:
    case OP_DEF:
    case OP_OPT:
    case OP_CALLOUT:
    case OP_SOD:
    case OP_SOM:
    case OP_EOD:
    case OP_EODN:
    case OP_CIRC:
    case OP_DOLL:
    case OP_NOT_WORD_BOUNDARY:
    case OP_WORD_BOUNDARY:
    cc += _pcre_OP_lengths[*cc];
    break;

    /* Handle literal characters */

    case OP_CHAR:
    case OP_CHARNC:
    case OP_NOT:
    branchlength++;
    cc += 2;
#ifdef SUPPORT_UTF8
    if ((options & PCRE_UTF8) != 0)
      {
      while ((*cc & 0xc0) == 0x80) cc++;
      }
#endif
    break;

    /* Handle exact repetitions. The count is already in characters, but we
    need to skip over a multibyte character in UTF8 mode.  */

    case OP_EXACT:
    branchlength += GET2(cc,1);
    cc += 4;
#ifdef SUPPORT_UTF8
    if ((options & PCRE_UTF8) != 0)
      {
      while((*cc & 0x80) == 0x80) cc++;
      }
#endif
    break;

    case OP_TYPEEXACT:
    branchlength += GET2(cc,1);
    if (cc[3] == OP_PROP || cc[3] == OP_NOTPROP) cc += 2;
    cc += 4;
    break;

    /* Handle single-char matchers */

    case OP_PROP:
    case OP_NOTPROP:
    cc += 2;
    /* Fall through */

    case OP_NOT_DIGIT:
    case OP_DIGIT:
    case OP_NOT_WHITESPACE:
    case OP_WHITESPACE:
    case OP_NOT_WORDCHAR:
    case OP_WORDCHAR:
    case OP_ANY:
    case OP_ALLANY:
    branchlength++;
    cc++;
    break;

    /* The single-byte matcher isn't allowed */

    case OP_ANYBYTE:
    return -2;

    /* Check a class for variable quantification */

#ifdef SUPPORT_UTF8
    case OP_XCLASS:
    cc += GET(cc, 1) - 33;
    /* Fall through */
#endif

    case OP_CLASS:
    case OP_NCLASS:
    cc += 33;

    switch (*cc)
      {
      case OP_CRSTAR:
      case OP_CRMINSTAR:
      case OP_CRQUERY:
      case OP_CRMINQUERY:
      return -1;

      case OP_CRRANGE:
      case OP_CRMINRANGE:
      if (GET2(cc,1) != GET2(cc,3)) return -1;
      branchlength += GET2(cc,1);
      cc += 5;
      break;

      default:
      branchlength++;
      }
    break;

    /* Anything else is variable length */

    default:
    return -1;
    }
  }
/* Control never gets here */
}


/*************************************************
*    Scan compiled regex for numbered bracket    *
*************************************************/

/* This little function scans through a compiled pattern until it finds a
capturing bracket with the given number.

Arguments:
  code        points to start of expression
  utf8        TRUE in UTF-8 mode
  number      the required bracket number

Returns:      pointer to the opcode for the bracket, or NULL if not found
*/

static const uschar *
find_bracket(const uschar *code, BOOL utf8, int number)
{
for (;;)
  {
  register int c = *code;
  if (c == OP_END) return NULL;

  /* XCLASS is used for classes that cannot be represented just by a bit
  map. This includes negated single high-valued characters. The length in
  the table is zero; the actual length is stored in the compiled code. */

  if (c == OP_XCLASS) code += GET(code, 1);

  /* Handle capturing bracket */

  else if (c == OP_CBRA)
    {
    int n = GET2(code, 1+LINK_SIZE);
    if (n == number) return (uschar *)code;
    code += _pcre_OP_lengths[c];
    }

  /* Otherwise, we can get the item's length from the table, except that for
  repeated character types, we have to test for \p and \P, which have an extra
  two bytes of parameters. */

  else
    {
    switch(c)
      {
      case OP_TYPESTAR:
      case OP_TYPEMINSTAR:
      case OP_TYPEPLUS:
      case OP_TYPEMINPLUS:
      case OP_TYPEQUERY:
      case OP_TYPEMINQUERY:
      case OP_TYPEPOSSTAR:
      case OP_TYPEPOSPLUS:
      case OP_TYPEPOSQUERY:
      if (code[1] == OP_PROP || code[1] == OP_NOTPROP) code += 2;
      break;

      case OP_TYPEUPTO:
      case OP_TYPEMINUPTO:
      case OP_TYPEEXACT:
      case OP_TYPEPOSUPTO:
      if (code[3] == OP_PROP || code[3] == OP_NOTPROP) code += 2;
      break;
      }

    /* Add in the fixed length from the table */

    code += _pcre_OP_lengths[c];

  /* In UTF-8 mode, opcodes that are followed by a character may be followed by
  a multi-byte character. The length in the table is a minimum, so we have to
  arrange to skip the extra bytes. */

#ifdef SUPPORT_UTF8
    if (utf8) switch(c)
      {
      case OP_CHAR:
      case OP_CHARNC:
      case OP_EXACT:
      case OP_UPTO:
      case OP_MINUPTO:
      case OP_POSUPTO:
      case OP_STAR:
      case OP_MINSTAR:
      case OP_POSSTAR:
      case OP_PLUS:
      case OP_MINPLUS:
      case OP_POSPLUS:
      case OP_QUERY:
      case OP_MINQUERY:
      case OP_POSQUERY:
      if (code[-1] >= 0xc0) code += _pcre_utf8_table4[code[-1] & 0x3f];
      break;
      }
#else
    (void)(utf8);  /* Keep compiler happy by referencing function argument */
#endif
    }
  }
}


/*************************************************
*   Scan compiled regex for recursion reference  *
*************************************************/

/* This little function scans through a compiled pattern until it finds an
instance of OP_RECURSE.

Arguments:
  code        points to start of expression
  utf8        TRUE in UTF-8 mode

Returns:      pointer to the opcode for OP_RECURSE, or NULL if not found
*/

static const uschar *
find_recurse(const uschar *code, BOOL utf8)
{
for (;;)
  {
  register int c = *code;
  if (c == OP_END) return NULL;
  if (c == OP_RECURSE) return code;

  /* XCLASS is used for classes that cannot be represented just by a bit
  map. This includes negated single high-valued characters. The length in
  the table is zero; the actual length is stored in the compiled code. */

  if (c == OP_XCLASS) code += GET(code, 1);

  /* Otherwise, we can get the item's length from the table, except that for
  repeated character types, we have to test for \p and \P, which have an extra
  two bytes of parameters. */

  else
    {
    switch(c)
      {
      case OP_TYPESTAR:
      case OP_TYPEMINSTAR:
      case OP_TYPEPLUS:
      case OP_TYPEMINPLUS:
      case OP_TYPEQUERY:
      case OP_TYPEMINQUERY:
      case OP_TYPEPOSSTAR:
      case OP_TYPEPOSPLUS:
      case OP_TYPEPOSQUERY:
      if (code[1] == OP_PROP || code[1] == OP_NOTPROP) code += 2;
      break;

      case OP_TYPEPOSUPTO:
      case OP_TYPEUPTO:
      case OP_TYPEMINUPTO:
      case OP_TYPEEXACT:
      if (code[3] == OP_PROP || code[3] == OP_NOTPROP) code += 2;
      break;
      }

    /* Add in the fixed length from the table */

    code += _pcre_OP_lengths[c];

    /* In UTF-8 mode, opcodes that are followed by a character may be followed
    by a multi-byte character. The length in the table is a minimum, so we have
    to arrange to skip the extra bytes. */

#ifdef SUPPORT_UTF8
    if (utf8) switch(c)
      {
      case OP_CHAR:
      case OP_CHARNC:
      case OP_EXACT:
      case OP_UPTO:
      case OP_MINUPTO:
      case OP_POSUPTO:
      case OP_STAR:
      case OP_MINSTAR:
      case OP_POSSTAR:
      case OP_PLUS:
      case OP_MINPLUS:
      case OP_POSPLUS:
      case OP_QUERY:
      case OP_MINQUERY:
      case OP_POSQUERY:
      if (code[-1] >= 0xc0) code += _pcre_utf8_table4[code[-1] & 0x3f];
      break;
      }
#else
    (void)(utf8);  /* Keep compiler happy by referencing function argument */
#endif
    }
  }
}


/*************************************************
*    Scan compiled branch for non-emptiness      *
*************************************************/

/* This function scans through a branch of a compiled pattern to see whether it
can match the empty string or not. It is called from could_be_empty()
below and from compile_branch() when checking for an unlimited repeat of a
group that can match nothing. Note that first_significant_code() skips over
backward and negative forward assertions when its final argument is TRUE. If we
hit an unclosed bracket, we return "empty" - this means we've struck an inner
bracket whose current branch will already have been scanned.

Arguments:
  code        points to start of search
  endcode     points to where to stop
  utf8        TRUE if in UTF8 mode

Returns:      TRUE if what is matched could be empty
*/

static BOOL
could_be_empty_branch(const uschar *code, const uschar *endcode, BOOL utf8)
{
register int c;
for (code = first_significant_code(code + _pcre_OP_lengths[*code], NULL, 0, TRUE);
     code < endcode;
     code = first_significant_code(code + _pcre_OP_lengths[c], NULL, 0, TRUE))
  {
  const uschar *ccode;

  c = *code;

  /* Skip over forward assertions; the other assertions are skipped by
  first_significant_code() with a TRUE final argument. */

  if (c == OP_ASSERT)
    {
    do code += GET(code, 1); while (*code == OP_ALT);
    c = *code;
    continue;
    }

  /* Groups with zero repeats can of course be empty; skip them. */

  if (c == OP_BRAZERO || c == OP_BRAMINZERO || c == OP_SKIPZERO)
    {
    code += _pcre_OP_lengths[c];
    do code += GET(code, 1); while (*code == OP_ALT);
    c = *code;
    continue;
    }

  /* For other groups, scan the branches. */

  if (c == OP_BRA || c == OP_CBRA || c == OP_ONCE || c == OP_COND)
    {
    BOOL empty_branch;
    if (GET(code, 1) == 0) return TRUE;    /* Hit unclosed bracket */

    /* Scan a closed bracket */

    empty_branch = FALSE;
    do
      {
      if (!empty_branch && could_be_empty_branch(code, endcode, utf8))
        empty_branch = TRUE;
      code += GET(code, 1);
      }
    while (*code == OP_ALT);
    if (!empty_branch) return FALSE;   /* All branches are non-empty */
    c = *code;
    continue;
    }

  /* Handle the other opcodes */

  switch (c)
    {
    /* Check for quantifiers after a class. XCLASS is used for classes that
    cannot be represented just by a bit map. This includes negated single
    high-valued characters. The length in _pcre_OP_lengths[] is zero; the
    actual length is stored in the compiled code, so we must update "code"
    here. */

#ifdef SUPPORT_UTF8
    case OP_XCLASS:
    ccode = code += GET(code, 1);
    goto CHECK_CLASS_REPEAT;
#endif

    case OP_CLASS:
    case OP_NCLASS:
    ccode = code + 33;

#ifdef SUPPORT_UTF8
    CHECK_CLASS_REPEAT:
#endif

    switch (*ccode)
      {
      case OP_CRSTAR:            /* These could be empty; continue */
      case OP_CRMINSTAR:
      case OP_CRQUERY:
      case OP_CRMINQUERY:
      break;

      default:                   /* Non-repeat => class must match */
      case OP_CRPLUS:            /* These repeats aren't empty */
      case OP_CRMINPLUS:
      return FALSE;

      case OP_CRRANGE:
      case OP_CRMINRANGE:
      if (GET2(ccode, 1) > 0) return FALSE;  /* Minimum > 0 */
      break;
      }
    break;

    /* Opcodes that must match a character */

    case OP_PROP:
    case OP_NOTPROP:
    case OP_EXTUNI:
    case OP_NOT_DIGIT:
    case OP_DIGIT:
    case OP_NOT_WHITESPACE:
    case OP_WHITESPACE:
    case OP_NOT_WORDCHAR:
    case OP_WORDCHAR:
    case OP_ANY:
    case OP_ALLANY:
    case OP_ANYBYTE:
    case OP_CHAR:
    case OP_CHARNC:
    case OP_NOT:
    case OP_PLUS:
    case OP_MINPLUS:
    case OP_POSPLUS:
    case OP_EXACT:
    case OP_NOTPLUS:
    case OP_NOTMINPLUS:
    case OP_NOTPOSPLUS:
    case OP_NOTEXACT:
    case OP_TYPEPLUS:
    case OP_TYPEMINPLUS:
    case OP_TYPEPOSPLUS:
    case OP_TYPEEXACT:
    return FALSE;

    /* These are going to continue, as they may be empty, but we have to
    fudge the length for the \p and \P cases. */

    case OP_TYPESTAR:
    case OP_TYPEMINSTAR:
    case OP_TYPEPOSSTAR:
    case OP_TYPEQUERY:
    case OP_TYPEMINQUERY:
    case OP_TYPEPOSQUERY:
    if (code[1] == OP_PROP || code[1] == OP_NOTPROP) code += 2;
    break;

    /* Same for these */

    case OP_TYPEUPTO:
    case OP_TYPEMINUPTO:
    case OP_TYPEPOSUPTO:
    if (code[3] == OP_PROP || code[3] == OP_NOTPROP) code += 2;
    break;

    /* End of branch */

    case OP_KET:
    case OP_KETRMAX:
    case OP_KETRMIN:
    case OP_ALT:
    return TRUE;

    /* In UTF-8 mode, STAR, MINSTAR, POSSTAR, QUERY, MINQUERY, POSQUERY, UPTO,
    MINUPTO, and POSUPTO may be followed by a multibyte character */

#ifdef SUPPORT_UTF8
    case OP_STAR:
    case OP_MINSTAR:
    case OP_POSSTAR:
    case OP_QUERY:
    case OP_MINQUERY:
    case OP_POSQUERY:
    case OP_UPTO:
    case OP_MINUPTO:
    case OP_POSUPTO:
    if (utf8) while ((code[2] & 0xc0) == 0x80) code++;
    break;
#endif
    }
  }

return TRUE;
}


/*************************************************
*    Scan compiled regex for non-emptiness       *
*************************************************/

/* This function is called to check for left recursive calls. We want to check
the current branch of the current pattern to see if it could match the empty
string. If it could, we must look outwards for branches at other levels,
stopping when we pass beyond the bracket which is the subject of the recursion.

Arguments:
  code        points to start of the recursion
  endcode     points to where to stop (current RECURSE item)
  bcptr       points to the chain of current (unclosed) branch starts
  utf8        TRUE if in UTF-8 mode

Returns:      TRUE if what is matched could be empty
*/

static BOOL
could_be_empty(const uschar *code, const uschar *endcode, branch_chain *bcptr,
  BOOL utf8)
{
while (bcptr != NULL && bcptr->current >= code)
  {
  if (!could_be_empty_branch(bcptr->current, endcode, utf8)) return FALSE;
  bcptr = bcptr->outer;
  }
return TRUE;
}

/*************************************************
*           Check for POSIX class syntax         *
*************************************************/

/* This function is called when the sequence "[:" or "[." or "[=" is
encountered in a character class. It checks whether this is followed by a
sequence of characters terminated by a matching ":]" or ".]" or "=]". If we
reach an unescaped ']' without the special preceding character, return FALSE.

Originally, this function only recognized a sequence of letters between the
terminators, but it seems that Perl recognizes any sequence of characters,
though of course unknown POSIX names are subsequently rejected. Perl gives an
"Unknown POSIX class" error for [:f\oo:] for example, where previously PCRE
didn't consider this to be a POSIX class. Likewise for [:1234:].

The problem in trying to be exactly like Perl is in the handling of escapes. We
have to be sure that [abc[:x\]pqr] is *not* treated as containing a POSIX
class, but [abc[:x\]pqr:]] is (so that an error can be generated). The code
below handles the special case of \], but does not try to do any other escape
processing. This makes it different from Perl for cases such as [:l\ower:]
where Perl recognizes it as the POSIX class "lower" but PCRE does not recognize
"l\ower". This is a lesser evil that not diagnosing bad classes when Perl does,
I think.

Arguments:
  ptr      pointer to the initial [
  endptr   where to return the end pointer

Returns:   TRUE or FALSE
*/

static BOOL
check_posix_syntax(const uschar *ptr, const uschar **endptr)
{
int terminator;          /* Don't combine these lines; the Solaris cc */
terminator = *(++ptr);   /* compiler warns about "non-constant" initializer. */
for (++ptr; *ptr != 0; ptr++)
  {
  if (*ptr == '\\' && ptr[1] == ']') ptr++; else
    {
    if (*ptr == ']') return FALSE;
    if (*ptr == terminator && ptr[1] == ']')
      {
      *endptr = ptr;
      return TRUE;
      }
    }
  }
return FALSE;
}


/*************************************************
*          Check POSIX class name                *
*************************************************/

/* This function is called to check the name given in a POSIX-style class entry
such as [:alnum:].

Arguments:
  ptr        points to the first letter
  len        the length of the name

Returns:     a value representing the name, or -1 if unknown
*/

static int
check_posix_name(const uschar *ptr, int len)
{
const char *pn = posix_names;
register int yield = 0;
while (posix_name_lengths[yield] != 0)
  {
  if (len == posix_name_lengths[yield] &&
    strncmp((const char *)ptr, pn, len) == 0) return yield;
  pn += posix_name_lengths[yield] + 1;
  yield++;
  }
return -1;
}


/*************************************************
*    Adjust OP_RECURSE items in repeated group   *
*************************************************/

/* OP_RECURSE items contain an offset from the start of the regex to the group
that is referenced. This means that groups can be replicated for fixed
repetition simply by copying (because the recursion is allowed to refer to
earlier groups that are outside the current group). However, when a group is
optional (i.e. the minimum quantifier is zero), OP_BRAZERO or OP_SKIPZERO is
inserted before it, after it has been compiled. This means that any OP_RECURSE
items within it that refer to the group itself or any contained groups have to
have their offsets adjusted. That one of the jobs of this function. Before it
is called, the partially compiled regex must be temporarily terminated with
OP_END.

This function has been extended with the possibility of forward references for
recursions and subroutine calls. It must also check the list of such references
for the group we are dealing with. If it finds that one of the recursions in
the current group is on this list, it adjusts the offset in the list, not the
value in the reference (which is a group number).

Arguments:
  group      points to the start of the group
  adjust     the amount by which the group is to be moved
  utf8       TRUE in UTF-8 mode
  cd         contains pointers to tables etc.
  save_hwm   the hwm forward reference pointer at the start of the group

Returns:     nothing
*/

static void
adjust_recurse(uschar *group, int adjust, BOOL utf8, compile_data *cd,
  uschar *save_hwm)
{
uschar *ptr = group;

while ((ptr = (uschar *)find_recurse(ptr, utf8)) != NULL)
  {
  int offset;
  uschar *hc;

  /* See if this recursion is on the forward reference list. If so, adjust the
  reference. */

  for (hc = save_hwm; hc < cd->hwm; hc += LINK_SIZE)
    {
    offset = GET(hc, 0);
    if (cd->start_code + offset == ptr + 1)
      {
      PUT(hc, 0, offset + adjust);
      break;
      }
    }

  /* Otherwise, adjust the recursion offset if it's after the start of this
  group. */

  if (hc >= cd->hwm)
    {
    offset = GET(ptr, 1);
    if (cd->start_code + offset >= group) PUT(ptr, 1, offset + adjust);
    }

  ptr += 1 + LINK_SIZE;
  }
}



/*************************************************
*        Insert an automatic callout point       *
*************************************************/

/* This function is called when the PCRE_AUTO_CALLOUT option is set, to insert
callout points before each pattern item.

Arguments:
  code           current code pointer
  ptr            current pattern pointer
  cd             pointers to tables etc

Returns:         new code pointer
*/

static uschar *
auto_callout(uschar *code, const uschar *ptr, compile_data *cd)
{
*code++ = OP_CALLOUT;
*code++ = 255;
PUT(code, 0, ptr - cd->start_pattern);  /* Pattern offset */
PUT(code, LINK_SIZE, 0);                /* Default length */
return code + 2*LINK_SIZE;
}


/*************************************************
*         Complete a callout item                *
*************************************************/

/* A callout item contains the length of the next item in the pattern, which
we can't fill in till after we have reached the relevant point. This is used
for both automatic and manual callouts.

Arguments:
  previous_callout   points to previous callout item
  ptr                current pattern pointer
  cd                 pointers to tables etc

Returns:             nothing
*/

static void
complete_callout(uschar *previous_callout, const uschar *ptr, compile_data *cd)
{
int length = (int)(ptr - cd->start_pattern - GET(previous_callout, 2));
PUT(previous_callout, 2 + LINK_SIZE, length);
}



#ifdef SUPPORT_UCP
/*************************************************
*           Get othercase range                  *
*************************************************/

/* This function is passed the start and end of a class range, in UTF-8 mode
with UCP support. It searches up the characters, looking for internal ranges of
characters in the "other" case. Each call returns the next one, updating the
start address.

Arguments:
  cptr        points to starting character value; updated
  d           end value
  ocptr       where to put start of othercase range
  odptr       where to put end of othercase range

Yield:        TRUE when range returned; FALSE when no more
*/

static BOOL
get_othercase_range(unsigned int *cptr, unsigned int d, unsigned int *ocptr,
  unsigned int *odptr)
{
unsigned int c, othercase, next;

for (c = *cptr; c <= d; c++)
  { if ((othercase = UCD_OTHERCASE(c)) != c) break; }

if (c > d) return FALSE;

*ocptr = othercase;
next = othercase + 1;

for (++c; c <= d; c++)
  {
  if (UCD_OTHERCASE(c) != next) break;
  next++;
  }

*odptr = next - 1;
*cptr = c;

return TRUE;
}
#endif  /* SUPPORT_UCP */



/*************************************************
*     Check if auto-possessifying is possible    *
*************************************************/

/* This function is called for unlimited repeats of certain items, to see
whether the next thing could possibly match the repeated item. If not, it makes
sense to automatically possessify the repeated item.

Arguments:
  op_code       the repeated op code
  this          data for this item, depends on the opcode
  utf8          TRUE in UTF-8 mode
  utf8_char     used for utf8 character bytes, NULL if not relevant
  ptr           next character in pattern
  options       options bits
  cd            contains pointers to tables etc.

Returns:        TRUE if possessifying is wanted
*/

static BOOL
check_auto_possessive(int op_code, int item, BOOL utf8, uschar *utf8_char,
  const uschar *ptr, int options, compile_data *cd)
{
int next;


/* MJ: inserted here */
#ifdef NLBLOCK
#   undef NLBLOCK
#   undef PSSTART
#   undef PSEND
#endif

#define NLBLOCK cd             /* Block containing newline information */
#define PSSTART start_pattern  /* Field containing processed string start */
#define PSEND   end_pattern    /* Field containing processed string end */
/* end of MJ */



/* Skip whitespace and comments in extended mode */

if ((options & PCRE_EXTENDED) != 0)
  {
  for (;;)
    {
    while ((cd->ctypes[*ptr] & ctype_space) != 0) ptr++;
    if (*ptr == '#')
      {
      while (*(++ptr) != 0)
        if (IS_NEWLINE(ptr)) { ptr += cd->nllen; break; }
      }
    else break;
    }
  }

/* If the next item is one that we can handle, get its value. A non-negative
value is a character, a negative value is an escape value. */

if (*ptr == '\\')
  {
  int temperrorcode = 0;
  next = check_escape(&ptr, &temperrorcode, cd->bracount, options, FALSE);
  if (temperrorcode != 0) return FALSE;
  ptr++;    /* Point after the escape sequence */
  }

else if ((cd->ctypes[*ptr] & ctype_meta) == 0)
  {
#ifdef SUPPORT_UTF8
  if (utf8) { GETCHARINC(next, ptr); } else
#endif
  next = *ptr++;
  }

else return FALSE;

/* Skip whitespace and comments in extended mode */

if ((options & PCRE_EXTENDED) != 0)
  {
  for (;;)
    {
    while ((cd->ctypes[*ptr] & ctype_space) != 0) ptr++;
    if (*ptr == '#')
      {
      while (*(++ptr) != 0)
        if (IS_NEWLINE(ptr)) { ptr += cd->nllen; break; }
      }
    else break;
    }
  }

/* If the next thing is itself optional, we have to give up. */

if (*ptr == '*' || *ptr == '?' || strncmp((char *)ptr, "{0,", 3) == 0)
  return FALSE;

/* Now compare the next item with the previous opcode. If the previous is a
positive single character match, "item" either contains the character or, if
"item" is greater than 127 in utf8 mode, the character's bytes are in
utf8_char. */


/* Handle cases when the next item is a character. */

if (next >= 0) switch(op_code)
  {
  case OP_CHAR:
#ifdef SUPPORT_UTF8
  if (utf8 && item > 127) { GETCHAR(item, utf8_char); }
#else
  (void)(utf8_char);  /* Keep compiler happy by referencing function argument */
#endif
  return item != next;

  /* For CHARNC (caseless character) we must check the other case. If we have
  Unicode property support, we can use it to test the other case of
  high-valued characters. */

  case OP_CHARNC:
#ifdef SUPPORT_UTF8
  if (utf8 && item > 127) { GETCHAR(item, utf8_char); }
#endif
  if (item == next) return FALSE;
#ifdef SUPPORT_UTF8
  if (utf8)
    {
    unsigned int othercase;
    if (next < 128) othercase = cd->fcc[next]; else
#ifdef SUPPORT_UCP
    othercase = UCD_OTHERCASE((unsigned int)next);
#else
    othercase = NOTACHAR;
#endif
    return (unsigned int)item != othercase;
    }
  else
#endif  /* SUPPORT_UTF8 */
  return (item != cd->fcc[next]);  /* Non-UTF-8 mode */

  /* For OP_NOT, "item" must be a single-byte character. */

  case OP_NOT:
  if (item == next) return TRUE;
  if ((options & PCRE_CASELESS) == 0) return FALSE;
#ifdef SUPPORT_UTF8
  if (utf8)
    {
    unsigned int othercase;
    if (next < 128) othercase = cd->fcc[next]; else
#ifdef SUPPORT_UCP
    othercase = UCD_OTHERCASE(next);
#else
    othercase = NOTACHAR;
#endif
    return (unsigned int)item == othercase;
    }
  else
#endif  /* SUPPORT_UTF8 */
  return (item == cd->fcc[next]);  /* Non-UTF-8 mode */

  case OP_DIGIT:
  return next > 127 || (cd->ctypes[next] & ctype_digit) == 0;

  case OP_NOT_DIGIT:
  return next <= 127 && (cd->ctypes[next] & ctype_digit) != 0;

  case OP_WHITESPACE:
  return next > 127 || (cd->ctypes[next] & ctype_space) == 0;

  case OP_NOT_WHITESPACE:
  return next <= 127 && (cd->ctypes[next] & ctype_space) != 0;

  case OP_WORDCHAR:
  return next > 127 || (cd->ctypes[next] & ctype_word) == 0;

  case OP_NOT_WORDCHAR:
  return next <= 127 && (cd->ctypes[next] & ctype_word) != 0;

  case OP_HSPACE:
  case OP_NOT_HSPACE:
  switch(next)
    {
    case 0x09:
    case 0x20:
    case 0xa0:
    case 0x1680:
    case 0x180e:
    case 0x2000:
    case 0x2001:
    case 0x2002:
    case 0x2003:
    case 0x2004:
    case 0x2005:
    case 0x2006:
    case 0x2007:
    case 0x2008:
    case 0x2009:
    case 0x200A:
    case 0x202f:
    case 0x205f:
    case 0x3000:
    return op_code != OP_HSPACE;
    default:
    return op_code == OP_HSPACE;
    }

  case OP_VSPACE:
  case OP_NOT_VSPACE:
  switch(next)
    {
    case 0x0a:
    case 0x0b:
    case 0x0c:
    case 0x0d:
    case 0x85:
    case 0x2028:
    case 0x2029:
    return op_code != OP_VSPACE;
    default:
    return op_code == OP_VSPACE;
    }

  default:
  return FALSE;
  }


/* Handle the case when the next item is \d, \s, etc. */

switch(op_code)
  {
  case OP_CHAR:
  case OP_CHARNC:
#ifdef SUPPORT_UTF8
  if (utf8 && item > 127) { GETCHAR(item, utf8_char); }
#endif
  switch(-next)
    {
    case ESC_d:
    return item > 127 || (cd->ctypes[item] & ctype_digit) == 0;

    case ESC_D:
    return item <= 127 && (cd->ctypes[item] & ctype_digit) != 0;

    case ESC_s:
    return item > 127 || (cd->ctypes[item] & ctype_space) == 0;

    case ESC_S:
    return item <= 127 && (cd->ctypes[item] & ctype_space) != 0;

    case ESC_w:
    return item > 127 || (cd->ctypes[item] & ctype_word) == 0;

    case ESC_W:
    return item <= 127 && (cd->ctypes[item] & ctype_word) != 0;

    case ESC_h:
    case ESC_H:
    switch(item)
      {
      case 0x09:
      case 0x20:
      case 0xa0:
      case 0x1680:
      case 0x180e:
      case 0x2000:
      case 0x2001:
      case 0x2002:
      case 0x2003:
      case 0x2004:
      case 0x2005:
      case 0x2006:
      case 0x2007:
      case 0x2008:
      case 0x2009:
      case 0x200A:
      case 0x202f:
      case 0x205f:
      case 0x3000:
      return -next != ESC_h;
      default:
      return -next == ESC_h;
      }

    case ESC_v:
    case ESC_V:
    switch(item)
      {
      case 0x0a:
      case 0x0b:
      case 0x0c:
      case 0x0d:
      case 0x85:
      case 0x2028:
      case 0x2029:
      return -next != ESC_v;
      default:
      return -next == ESC_v;
      }

    default:
    return FALSE;
    }

  case OP_DIGIT:
  return next == -ESC_D || next == -ESC_s || next == -ESC_W ||
         next == -ESC_h || next == -ESC_v;

  case OP_NOT_DIGIT:
  return next == -ESC_d;

  case OP_WHITESPACE:
  return next == -ESC_S || next == -ESC_d || next == -ESC_w;

  case OP_NOT_WHITESPACE:
  return next == -ESC_s || next == -ESC_h || next == -ESC_v;

  case OP_HSPACE:
  return next == -ESC_S || next == -ESC_H || next == -ESC_d || next == -ESC_w;

  case OP_NOT_HSPACE:
  return next == -ESC_h;

  /* Can't have \S in here because VT matches \S (Perl anomaly) */
  case OP_VSPACE:
  return next == -ESC_V || next == -ESC_d || next == -ESC_w;

  case OP_NOT_VSPACE:
  return next == -ESC_v;

  case OP_WORDCHAR:
  return next == -ESC_W || next == -ESC_s || next == -ESC_h || next == -ESC_v;

  case OP_NOT_WORDCHAR:
  return next == -ESC_w || next == -ESC_d;

  default:
  return FALSE;
  }

/* Control does not reach here */
}


/*************************************************
*           Compile one branch                   *
*************************************************/

/* Scan the pattern, compiling it into the a vector. If the options are
changed during the branch, the pointer is used to change the external options
bits. This function is used during the pre-compile phase when we are trying
to find out the amount of memory needed, as well as during the real compile
phase. The value of lengthptr distinguishes the two phases.

Arguments:
  optionsptr     pointer to the option bits
  codeptr        points to the pointer to the current code point
  ptrptr         points to the current pattern pointer
  errorcodeptr   points to error code variable
  firstbyteptr   set to initial literal character, or < 0 (REQ_UNSET, REQ_NONE)
  reqbyteptr     set to the last literal character required, else < 0
  bcptr          points to current branch chain
  cd             contains pointers to tables etc.
  lengthptr      NULL during the real compile phase
                 points to length accumulator during pre-compile phase

Returns:         TRUE on success
                 FALSE, with *errorcodeptr set non-zero on error
*/

static BOOL
compile_branch(int *optionsptr, uschar **codeptr, const uschar **ptrptr,
  int *errorcodeptr, int *firstbyteptr, int *reqbyteptr, branch_chain *bcptr,
  compile_data *cd, int *lengthptr)
{
int repeat_type, op_type;
int repeat_min = 0, repeat_max = 0;      /* To please picky compilers */
int bravalue = 0;
int greedy_default, greedy_non_default;
int firstbyte, reqbyte;
int zeroreqbyte, zerofirstbyte;
int req_caseopt, reqvary, tempreqvary;
int options = *optionsptr;
int after_manual_callout = 0;
int length_prevgroup = 0;
register int c;
register uschar *code = *codeptr;
uschar *last_code = code;
uschar *orig_code = code;
uschar *tempcode;
BOOL inescq = FALSE;
BOOL groupsetfirstbyte = FALSE;
const uschar *ptr = *ptrptr;
const uschar *tempptr;
uschar *previous = NULL;
uschar *previous_callout = NULL;
uschar *save_hwm = NULL;
uschar classbits[32];

#ifdef SUPPORT_UTF8
BOOL class_utf8;
BOOL utf8 = (options & PCRE_UTF8) != 0;
uschar *class_utf8data;
uschar *class_utf8data_base;
uschar utf8_char[6];
#else
BOOL utf8 = FALSE;
uschar *utf8_char = NULL;
#endif

#ifdef DEBUG
if (lengthptr != NULL) DPRINTF((">> start branch\n"));
#endif

/* Set up the default and non-default settings for greediness */

greedy_default = ((options & PCRE_UNGREEDY) != 0);
greedy_non_default = greedy_default ^ 1;

/* Initialize no first byte, no required byte. REQ_UNSET means "no char
matching encountered yet". It gets changed to REQ_NONE if we hit something that
matches a non-fixed char first char; reqbyte just remains unset if we never
find one.

When we hit a repeat whose minimum is zero, we may have to adjust these values
to take the zero repeat into account. This is implemented by setting them to
zerofirstbyte and zeroreqbyte when such a repeat is encountered. The individual
item types that can be repeated set these backoff variables appropriately. */

firstbyte = reqbyte = zerofirstbyte = zeroreqbyte = REQ_UNSET;

/* The variable req_caseopt contains either the REQ_CASELESS value or zero,
according to the current setting of the caseless flag. REQ_CASELESS is a bit
value > 255. It is added into the firstbyte or reqbyte variables to record the
case status of the value. This is used only for ASCII characters. */

req_caseopt = ((options & PCRE_CASELESS) != 0)? REQ_CASELESS : 0;

/* Switch on next character until the end of the branch */

for (;; ptr++)
  {
  BOOL negate_class;
  BOOL should_flip_negation;
  BOOL possessive_quantifier;
  BOOL is_quantifier;
  BOOL is_recurse;
  BOOL reset_bracount;
  int class_charcount;
  int class_lastchar;
  int newoptions;
  int recno;
  int refsign;
  int skipbytes;
  int subreqbyte;
  int subfirstbyte;
  int terminator;
  int mclength;
  uschar mcbuffer[8];

  /* Get next byte in the pattern */

  c = *ptr;

  /* If we are in the pre-compile phase, accumulate the length used for the
  previous cycle of this loop. */

  if (lengthptr != NULL)
    {
#ifdef DEBUG
    if (code > cd->hwm) cd->hwm = code;                 /* High water info */
#endif
    if (code > cd->start_workspace + COMPILE_WORK_SIZE) /* Check for overrun */
      {
      *errorcodeptr = ERR52;
      goto FAILED;
      }

    /* There is at least one situation where code goes backwards: this is the
    case of a zero quantifier after a class (e.g. [ab]{0}). At compile time,
    the class is simply eliminated. However, it is created first, so we have to
    allow memory for it. Therefore, don't ever reduce the length at this point.
    */

    if (code < last_code) code = last_code;

    /* Paranoid check for integer overflow */

    if (OFLOW_MAX - *lengthptr < code - last_code)
      {
      *errorcodeptr = ERR20;
      goto FAILED;
      }

    *lengthptr += (int)(code - last_code);
    DPRINTF(("length=%d added %d c=%c\n", *lengthptr, code - last_code, c));

    /* If "previous" is set and it is not at the start of the work space, move
    it back to there, in order to avoid filling up the work space. Otherwise,
    if "previous" is NULL, reset the current code pointer to the start. */

    if (previous != NULL)
      {
      if (previous > orig_code)
        {
        memmove(orig_code, previous, code - previous);
        code -= previous - orig_code;
        previous = orig_code;
        }
      }
    else code = orig_code;

    /* Remember where this code item starts so we can pick up the length
    next time round. */

    last_code = code;
    }

  /* In the real compile phase, just check the workspace used by the forward
  reference list. */

  else if (cd->hwm > cd->start_workspace + COMPILE_WORK_SIZE)
    {
    *errorcodeptr = ERR52;
    goto FAILED;
    }

  /* If in \Q...\E, check for the end; if not, we have a literal */

  if (inescq && c != 0)
    {
    if (c == '\\' && ptr[1] == 'E')
      {
      inescq = FALSE;
      ptr++;
      continue;
      }
    else
      {
      if (previous_callout != NULL)
        {
        if (lengthptr == NULL)  /* Don't attempt in pre-compile phase */
          complete_callout(previous_callout, ptr, cd);
        previous_callout = NULL;
        }
      if ((options & PCRE_AUTO_CALLOUT) != 0)
        {
        previous_callout = code;
        code = auto_callout(code, ptr, cd);
        }
      goto NORMAL_CHAR;
      }
    }

  /* Fill in length of a previous callout, except when the next thing is
  a quantifier. */

  is_quantifier = c == '*' || c == '+' || c == '?' ||
    (c == '{' && is_counted_repeat(ptr+1));

  if (!is_quantifier && previous_callout != NULL &&
       after_manual_callout-- <= 0)
    {
    if (lengthptr == NULL)      /* Don't attempt in pre-compile phase */
      complete_callout(previous_callout, ptr, cd);
    previous_callout = NULL;
    }

  /* In extended mode, skip white space and comments */

  if ((options & PCRE_EXTENDED) != 0)
    {
    if ((cd->ctypes[c] & ctype_space) != 0) continue;
    if (c == '#')
      {
      while (*(++ptr) != 0)
        {
        if (IS_NEWLINE(ptr)) { ptr += cd->nllen - 1; break; }
        }
      if (*ptr != 0) continue;

      /* Else fall through to handle end of string */
      c = 0;
      }
    }

  /* No auto callout for quantifiers. */

  if ((options & PCRE_AUTO_CALLOUT) != 0 && !is_quantifier)
    {
    previous_callout = code;
    code = auto_callout(code, ptr, cd);
    }

  switch(c)
    {
    /* ===================================================================*/
    case 0:                        /* The branch terminates at string end */
    case '|':                      /* or | or ) */
    case ')':
    *firstbyteptr = firstbyte;
    *reqbyteptr = reqbyte;
    *codeptr = code;
    *ptrptr = ptr;
    if (lengthptr != NULL)
      {
      if (OFLOW_MAX - *lengthptr < code - last_code)
        {
        *errorcodeptr = ERR20;
        goto FAILED;
        }
      *lengthptr += (int)(code - last_code); /* To include callout length */
      DPRINTF((">> end branch\n"));
      }
    return TRUE;


    /* ===================================================================*/
    /* Handle single-character metacharacters. In multiline mode, ^ disables
    the setting of any following char as a first character. */

    case '^':
    if ((options & PCRE_MULTILINE) != 0)
      {
      if (firstbyte == REQ_UNSET) firstbyte = REQ_NONE;
      }
    previous = NULL;
    *code++ = OP_CIRC;
    break;

    case '$':
    previous = NULL;
    *code++ = OP_DOLL;
    break;

    /* There can never be a first char if '.' is first, whatever happens about
    repeats. The value of reqbyte doesn't change either. */

    case '.':
    if (firstbyte == REQ_UNSET) firstbyte = REQ_NONE;
    zerofirstbyte = firstbyte;
    zeroreqbyte = reqbyte;
    previous = code;
    *code++ = ((options & PCRE_DOTALL) != 0)? OP_ALLANY: OP_ANY;
    break;


    /* ===================================================================*/
    /* Character classes. If the included characters are all < 256, we build a
    32-byte bitmap of the permitted characters, except in the special case
    where there is only one such character. For negated classes, we build the
    map as usual, then invert it at the end. However, we use a different opcode
    so that data characters > 255 can be handled correctly.

    If the class contains characters outside the 0-255 range, a different
    opcode is compiled. It may optionally have a bit map for characters < 256,
    but those above are are explicitly listed afterwards. A flag byte tells
    whether the bitmap is present, and whether this is a negated class or not.

    In JavaScript compatibility mode, an isolated ']' causes an error. In
    default (Perl) mode, it is treated as a data character. */

    case ']':
    if ((cd->external_options & PCRE_JAVASCRIPT_COMPAT) != 0)
      {
      *errorcodeptr = ERR64;
      goto FAILED;
      }
    goto NORMAL_CHAR;

    case '[':
    previous = code;

    /* PCRE supports POSIX class stuff inside a class. Perl gives an error if
    they are encountered at the top level, so we'll do that too. */

    if ((ptr[1] == ':' || ptr[1] == '.' || ptr[1] == '=') &&
        check_posix_syntax(ptr, &tempptr))
      {
      *errorcodeptr = (ptr[1] == ':')? ERR13 : ERR31;
      goto FAILED;
      }

    /* If the first character is '^', set the negation flag and skip it. Also,
    if the first few characters (either before or after ^) are \Q\E or \E we
    skip them too. This makes for compatibility with Perl. */

    negate_class = FALSE;
    for (;;)
      {
      c = *(++ptr);
      if (c == '\\')
        {
        if (ptr[1] == 'E') ptr++;
          else if (strncmp((const char *)ptr+1, "Q\\E", 3) == 0) ptr += 3;
            else break;
        }
      else if (!negate_class && c == '^')
        negate_class = TRUE;
      else break;
      }

    /* Empty classes are allowed in JavaScript compatibility mode. Otherwise,
    an initial ']' is taken as a data character -- the code below handles
    that. In JS mode, [] must always fail, so generate OP_FAIL, whereas
    [^] must match any character, so generate OP_ALLANY. */

    if (c ==']' && (cd->external_options & PCRE_JAVASCRIPT_COMPAT) != 0)
      {
      *code++ = negate_class? OP_ALLANY : OP_FAIL;
      if (firstbyte == REQ_UNSET) firstbyte = REQ_NONE;
      zerofirstbyte = firstbyte;
      break;
      }

    /* If a class contains a negative special such as \S, we need to flip the
    negation flag at the end, so that support for characters > 255 works
    correctly (they are all included in the class). */

    should_flip_negation = FALSE;

    /* Keep a count of chars with values < 256 so that we can optimize the case
    of just a single character (as long as it's < 256). However, For higher
    valued UTF-8 characters, we don't yet do any optimization. */

    class_charcount = 0;
    class_lastchar = -1;

    /* Initialize the 32-char bit map to all zeros. We build the map in a
    temporary bit of memory, in case the class contains only 1 character (less
    than 256), because in that case the compiled code doesn't use the bit map.
    */

    memset(classbits, 0, 32 * sizeof(uschar));

#ifdef SUPPORT_UTF8
    class_utf8 = FALSE;                       /* No chars >= 256 */
    class_utf8data = code + LINK_SIZE + 2;    /* For UTF-8 items */
    class_utf8data_base = class_utf8data;     /* For resetting in pass 1 */
#endif

    /* Process characters until ] is reached. By writing this as a "do" it
    means that an initial ] is taken as a data character. At the start of the
    loop, c contains the first byte of the character. */

    if (c != 0) do
      {
      const uschar *oldptr;

#ifdef SUPPORT_UTF8
      if (utf8 && c > 127)
        {                           /* Braces are required because the */
        GETCHARLEN(c, ptr, ptr);    /* macro generates multiple statements */
        }

      /* In the pre-compile phase, accumulate the length of any UTF-8 extra
      data and reset the pointer. This is so that very large classes that
      contain a zillion UTF-8 characters no longer overwrite the work space
      (which is on the stack). */

      if (lengthptr != NULL)
        {
        *lengthptr += (int)(class_utf8data - class_utf8data_base);
        class_utf8data = class_utf8data_base;
        }

#endif

      /* Inside \Q...\E everything is literal except \E */

      if (inescq)
        {
        if (c == '\\' && ptr[1] == 'E')     /* If we are at \E */
          {
          inescq = FALSE;                   /* Reset literal state */
          ptr++;                            /* Skip the 'E' */
          continue;                         /* Carry on with next */
          }
        goto CHECK_RANGE;                   /* Could be range if \E follows */
        }

      /* Handle POSIX class names. Perl allows a negation extension of the
      form [:^name:]. A square bracket that doesn't match the syntax is
      treated as a literal. We also recognize the POSIX constructions
      [.ch.] and [=ch=] ("collating elements") and fault them, as Perl
      5.6 and 5.8 do. */

      if (c == '[' &&
          (ptr[1] == ':' || ptr[1] == '.' || ptr[1] == '=') &&
          check_posix_syntax(ptr, &tempptr))
        {
        BOOL local_negate = FALSE;
        int posix_class, taboffset, tabopt;
        register const uschar *cbits = cd->cbits;
        uschar pbits[32];

        if (ptr[1] != ':')
          {
          *errorcodeptr = ERR31;
          goto FAILED;
          }

        ptr += 2;
        if (*ptr == '^')
          {
          local_negate = TRUE;
          should_flip_negation = TRUE;  /* Note negative special */
          ptr++;
          }

        posix_class = check_posix_name(ptr, (int)(tempptr - ptr));
        if (posix_class < 0)
          {
          *errorcodeptr = ERR30;
          goto FAILED;
          }

        /* If matching is caseless, upper and lower are converted to
        alpha. This relies on the fact that the class table starts with
        alpha, lower, upper as the first 3 entries. */

        if ((options & PCRE_CASELESS) != 0 && posix_class <= 2)
          posix_class = 0;

        /* We build the bit map for the POSIX class in a chunk of local store
        because we may be adding and subtracting from it, and we don't want to
        subtract bits that may be in the main map already. At the end we or the
        result into the bit map that is being built. */

        posix_class *= 3;

        /* Copy in the first table (always present) */

        memcpy(pbits, cbits + posix_class_maps[posix_class],
          32 * sizeof(uschar));

        /* If there is a second table, add or remove it as required. */

        taboffset = posix_class_maps[posix_class + 1];
        tabopt = posix_class_maps[posix_class + 2];

        if (taboffset >= 0)
          {
          if (tabopt >= 0)
            for (c = 0; c < 32; c++) pbits[c] |= cbits[c + taboffset];
          else
            for (c = 0; c < 32; c++) pbits[c] &= ~cbits[c + taboffset];
          }

        /* Not see if we need to remove any special characters. An option
        value of 1 removes vertical space and 2 removes underscore. */

        if (tabopt < 0) tabopt = -tabopt;
        if (tabopt == 1) pbits[1] &= ~0x3c;
          else if (tabopt == 2) pbits[11] &= 0x7f;

        /* Add the POSIX table or its complement into the main table that is
        being built and we are done. */

        if (local_negate)
          for (c = 0; c < 32; c++) classbits[c] |= ~pbits[c];
        else
          for (c = 0; c < 32; c++) classbits[c] |= pbits[c];

        ptr = tempptr + 1;
        class_charcount = 10;  /* Set > 1; assumes more than 1 per class */
        continue;    /* End of POSIX syntax handling */
        }

      /* Backslash may introduce a single character, or it may introduce one
      of the specials, which just set a flag. The sequence \b is a special
      case. Inside a class (and only there) it is treated as backspace.
      Elsewhere it marks a word boundary. Other escapes have preset maps ready
      to 'or' into the one we are building. We assume they have more than one
      character in them, so set class_charcount bigger than one. */

      if (c == '\\')
        {
        c = check_escape(&ptr, errorcodeptr, cd->bracount, options, TRUE);
        if (*errorcodeptr != 0) goto FAILED;

        if (-c == ESC_b) c = '\b';       /* \b is backspace in a class */
        else if (-c == ESC_X) c = 'X';   /* \X is literal X in a class */
        else if (-c == ESC_R) c = 'R';   /* \R is literal R in a class */
        else if (-c == ESC_Q)            /* Handle start of quoted string */
          {
          if (ptr[1] == '\\' && ptr[2] == 'E')
            {
            ptr += 2; /* avoid empty string */
            }
          else inescq = TRUE;
          continue;
          }
        else if (-c == ESC_E) continue;  /* Ignore orphan \E */

        if (c < 0)
          {
          register const uschar *cbits = cd->cbits;
          class_charcount += 2;     /* Greater than 1 is what matters */

          /* Save time by not doing this in the pre-compile phase. */

          if (lengthptr == NULL) switch (-c)
            {
            case ESC_d:
            for (c = 0; c < 32; c++) classbits[c] |= cbits[c+cbit_digit];
            continue;

            case ESC_D:
            should_flip_negation = TRUE;
            for (c = 0; c < 32; c++) classbits[c] |= ~cbits[c+cbit_digit];
            continue;

            case ESC_w:
            for (c = 0; c < 32; c++) classbits[c] |= cbits[c+cbit_word];
            continue;

            case ESC_W:
            should_flip_negation = TRUE;
            for (c = 0; c < 32; c++) classbits[c] |= ~cbits[c+cbit_word];
            continue;

            case ESC_s:
            for (c = 0; c < 32; c++) classbits[c] |= cbits[c+cbit_space];
            classbits[1] &= ~0x08;   /* Perl 5.004 onwards omits VT from \s */
            continue;

            case ESC_S:
            should_flip_negation = TRUE;
            for (c = 0; c < 32; c++) classbits[c] |= ~cbits[c+cbit_space];
            classbits[1] |= 0x08;    /* Perl 5.004 onwards omits VT from \s */
            continue;

            default:    /* Not recognized; fall through */
            break;      /* Need "default" setting to stop compiler warning. */
            }

          /* In the pre-compile phase, just do the recognition. */

          else if (c == -ESC_d || c == -ESC_D || c == -ESC_w ||
                   c == -ESC_W || c == -ESC_s || c == -ESC_S) continue;

          /* We need to deal with \H, \h, \V, and \v in both phases because
          they use extra memory. */

          if (-c == ESC_h)
            {
            SETBIT(classbits, 0x09); /* VT */
            SETBIT(classbits, 0x20); /* SPACE */
            SETBIT(classbits, 0xa0); /* NSBP */
#ifdef SUPPORT_UTF8
            if (utf8)
              {
              class_utf8 = TRUE;
              *class_utf8data++ = XCL_SINGLE;
              class_utf8data += _pcre_ord2utf8(0x1680, class_utf8data);
              *class_utf8data++ = XCL_SINGLE;
              class_utf8data += _pcre_ord2utf8(0x180e, class_utf8data);
              *class_utf8data++ = XCL_RANGE;
              class_utf8data += _pcre_ord2utf8(0x2000, class_utf8data);
              class_utf8data += _pcre_ord2utf8(0x200A, class_utf8data);
              *class_utf8data++ = XCL_SINGLE;
              class_utf8data += _pcre_ord2utf8(0x202f, class_utf8data);
              *class_utf8data++ = XCL_SINGLE;
              class_utf8data += _pcre_ord2utf8(0x205f, class_utf8data);
              *class_utf8data++ = XCL_SINGLE;
              class_utf8data += _pcre_ord2utf8(0x3000, class_utf8data);
              }
#endif
            continue;
            }

          if (-c == ESC_H)
            {
            for (c = 0; c < 32; c++)
              {
              int x = 0xff;
              switch (c)
                {
                case 0x09/8: x ^= 1 << (0x09%8); break;
                case 0x20/8: x ^= 1 << (0x20%8); break;
                case 0xa0/8: x ^= 1 << (0xa0%8); break;
                default: break;
                }
              classbits[c] |= x;
              }

#ifdef SUPPORT_UTF8
            if (utf8)
              {
              class_utf8 = TRUE;
              *class_utf8data++ = XCL_RANGE;
              class_utf8data += _pcre_ord2utf8(0x0100, class_utf8data);
              class_utf8data += _pcre_ord2utf8(0x167f, class_utf8data);
              *class_utf8data++ = XCL_RANGE;
              class_utf8data += _pcre_ord2utf8(0x1681, class_utf8data);
              class_utf8data += _pcre_ord2utf8(0x180d, class_utf8data);
              *class_utf8data++ = XCL_RANGE;
              class_utf8data += _pcre_ord2utf8(0x180f, class_utf8data);
              class_utf8data += _pcre_ord2utf8(0x1fff, class_utf8data);
              *class_utf8data++ = XCL_RANGE;
              class_utf8data += _pcre_ord2utf8(0x200B, class_utf8data);
              class_utf8data += _pcre_ord2utf8(0x202e, class_utf8data);
              *class_utf8data++ = XCL_RANGE;
              class_utf8data += _pcre_ord2utf8(0x2030, class_utf8data);
              class_utf8data += _pcre_ord2utf8(0x205e, class_utf8data);
              *class_utf8data++ = XCL_RANGE;
              class_utf8data += _pcre_ord2utf8(0x2060, class_utf8data);
              class_utf8data += _pcre_ord2utf8(0x2fff, class_utf8data);
              *class_utf8data++ = XCL_RANGE;
              class_utf8data += _pcre_ord2utf8(0x3001, class_utf8data);
              class_utf8data += _pcre_ord2utf8(0x7fffffff, class_utf8data);
              }
#endif
            continue;
            }

          if (-c == ESC_v)
            {
            SETBIT(classbits, 0x0a); /* LF */
            SETBIT(classbits, 0x0b); /* VT */
            SETBIT(classbits, 0x0c); /* FF */
            SETBIT(classbits, 0x0d); /* CR */
            SETBIT(classbits, 0x85); /* NEL */
#ifdef SUPPORT_UTF8
            if (utf8)
              {
              class_utf8 = TRUE;
              *class_utf8data++ = XCL_RANGE;
              class_utf8data += _pcre_ord2utf8(0x2028, class_utf8data);
              class_utf8data += _pcre_ord2utf8(0x2029, class_utf8data);
              }
#endif
            continue;
            }

          if (-c == ESC_V)
            {
            for (c = 0; c < 32; c++)
              {
              int x = 0xff;
              switch (c)
                {
                case 0x0a/8: x ^= 1 << (0x0a%8);
                             x ^= 1 << (0x0b%8);
                             x ^= 1 << (0x0c%8);
                             x ^= 1 << (0x0d%8);
                             break;
                case 0x85/8: x ^= 1 << (0x85%8); break;
                default: break;
                }
              classbits[c] |= x;
              }

#ifdef SUPPORT_UTF8
            if (utf8)
              {
              class_utf8 = TRUE;
              *class_utf8data++ = XCL_RANGE;
              class_utf8data += _pcre_ord2utf8(0x0100, class_utf8data);
              class_utf8data += _pcre_ord2utf8(0x2027, class_utf8data);
              *class_utf8data++ = XCL_RANGE;
              class_utf8data += _pcre_ord2utf8(0x2029, class_utf8data);
              class_utf8data += _pcre_ord2utf8(0x7fffffff, class_utf8data);
              }
#endif
            continue;
            }

          /* We need to deal with \P and \p in both phases. */

#ifdef SUPPORT_UCP
          if (-c == ESC_p || -c == ESC_P)
            {
            BOOL negated;
            int pdata;
            int ptype = get_ucp(&ptr, &negated, &pdata, errorcodeptr);
            if (ptype < 0) goto FAILED;
            class_utf8 = TRUE;
            *class_utf8data++ = ((-c == ESC_p) != negated)?
              XCL_PROP : XCL_NOTPROP;
            *class_utf8data++ = ptype;
            *class_utf8data++ = pdata;
            class_charcount -= 2;   /* Not a < 256 character */
            continue;
            }
#endif
          /* Unrecognized escapes are faulted if PCRE is running in its
          strict mode. By default, for compatibility with Perl, they are
          treated as literals. */

          if ((options & PCRE_EXTRA) != 0)
            {
            *errorcodeptr = ERR7;
            goto FAILED;
            }

          class_charcount -= 2;  /* Undo the default count from above */
          c = *ptr;              /* Get the final character and fall through */
          }

        /* Fall through if we have a single character (c >= 0). This may be
        greater than 256 in UTF-8 mode. */

        }   /* End of backslash handling */

      /* A single character may be followed by '-' to form a range. However,
      Perl does not permit ']' to be the end of the range. A '-' character
      at the end is treated as a literal. Perl ignores orphaned \E sequences
      entirely. The code for handling \Q and \E is messy. */

      CHECK_RANGE:
      while (ptr[1] == '\\' && ptr[2] == 'E')
        {
        inescq = FALSE;
        ptr += 2;
        }

      oldptr = ptr;

      /* Remember \r or \n */

      if (c == '\r' || c == '\n') cd->external_flags |= PCRE_HASCRORLF;

      /* Check for range */

      if (!inescq && ptr[1] == '-')
        {
        int d;
        ptr += 2;
        while (*ptr == '\\' && ptr[1] == 'E') ptr += 2;

        /* If we hit \Q (not followed by \E) at this point, go into escaped
        mode. */

        while (*ptr == '\\' && ptr[1] == 'Q')
          {
          ptr += 2;
          if (*ptr == '\\' && ptr[1] == 'E') { ptr += 2; continue; }
          inescq = TRUE;
          break;
          }

        if (*ptr == 0 || (!inescq && *ptr == ']'))
          {
          ptr = oldptr;
          goto LONE_SINGLE_CHARACTER;
          }

#ifdef SUPPORT_UTF8
        if (utf8)
          {                           /* Braces are required because the */
          GETCHARLEN(d, ptr, ptr);    /* macro generates multiple statements */
          }
        else
#endif
        d = *ptr;  /* Not UTF-8 mode */

        /* The second part of a range can be a single-character escape, but
        not any of the other escapes. Perl 5.6 treats a hyphen as a literal
        in such circumstances. */

        if (!inescq && d == '\\')
          {
          d = check_escape(&ptr, errorcodeptr, cd->bracount, options, TRUE);
          if (*errorcodeptr != 0) goto FAILED;

          /* \b is backspace; \X is literal X; \R is literal R; any other
          special means the '-' was literal */

          if (d < 0)
            {
            if (d == -ESC_b) d = '\b';
            else if (d == -ESC_X) d = 'X';
            else if (d == -ESC_R) d = 'R'; else
              {
              ptr = oldptr;
              goto LONE_SINGLE_CHARACTER;  /* A few lines below */
              }
            }
          }

        /* Check that the two values are in the correct order. Optimize
        one-character ranges */

        if (d < c)
          {
          *errorcodeptr = ERR8;
          goto FAILED;
          }

        if (d == c) goto LONE_SINGLE_CHARACTER;  /* A few lines below */

        /* Remember \r or \n */

        if (d == '\r' || d == '\n') cd->external_flags |= PCRE_HASCRORLF;

        /* In UTF-8 mode, if the upper limit is > 255, or > 127 for caseless
        matching, we have to use an XCLASS with extra data items. Caseless
        matching for characters > 127 is available only if UCP support is
        available. */

#ifdef SUPPORT_UTF8
        if (utf8 && (d > 255 || ((options & PCRE_CASELESS) != 0 && d > 127)))
          {
          class_utf8 = TRUE;

          /* With UCP support, we can find the other case equivalents of
          the relevant characters. There may be several ranges. Optimize how
          they fit with the basic range. */

#ifdef SUPPORT_UCP
          if ((options & PCRE_CASELESS) != 0)
            {
            unsigned int occ, ocd;
            unsigned int cc = c;
            unsigned int origd = d;
            while (get_othercase_range(&cc, origd, &occ, &ocd))
              {
              if (occ >= (unsigned int)c &&
                  ocd <= (unsigned int)d)
                continue;                          /* Skip embedded ranges */

              if (occ < (unsigned int)c  &&
                  ocd >= (unsigned int)c - 1)      /* Extend the basic range */
                {                                  /* if there is overlap,   */
                c = occ;                           /* noting that if occ < c */
                continue;                          /* we can't have ocd > d  */
                }                                  /* because a subrange is  */
              if (ocd > (unsigned int)d &&
                  occ <= (unsigned int)d + 1)      /* always shorter than    */
                {                                  /* the basic range.       */
                d = ocd;
                continue;
                }

              if (occ == ocd)
                {
                *class_utf8data++ = XCL_SINGLE;
                }
              else
                {
                *class_utf8data++ = XCL_RANGE;
                class_utf8data += _pcre_ord2utf8(occ, class_utf8data);
                }
              class_utf8data += _pcre_ord2utf8(ocd, class_utf8data);
              }
            }
#endif  /* SUPPORT_UCP */

          /* Now record the original range, possibly modified for UCP caseless
          overlapping ranges. */

          *class_utf8data++ = XCL_RANGE;
          class_utf8data += _pcre_ord2utf8(c, class_utf8data);
          class_utf8data += _pcre_ord2utf8(d, class_utf8data);

          /* With UCP support, we are done. Without UCP support, there is no
          caseless matching for UTF-8 characters > 127; we can use the bit map
          for the smaller ones. */

#ifdef SUPPORT_UCP
          continue;    /* With next character in the class */
#else
          if ((options & PCRE_CASELESS) == 0 || c > 127) continue;

          /* Adjust upper limit and fall through to set up the map */

          d = 127;

#endif  /* SUPPORT_UCP */
          }
#endif  /* SUPPORT_UTF8 */

        /* We use the bit map for all cases when not in UTF-8 mode; else
        ranges that lie entirely within 0-127 when there is UCP support; else
        for partial ranges without UCP support. */

        class_charcount += d - c + 1;
        class_lastchar = d;

        /* We can save a bit of time by skipping this in the pre-compile. */

        if (lengthptr == NULL) for (; c <= d; c++)
          {
          classbits[c/8] |= (1 << (c&7));
          if ((options & PCRE_CASELESS) != 0)
            {
            int uc = cd->fcc[c];           /* flip case */
            classbits[uc/8] |= (1 << (uc&7));
            }
          }

        continue;   /* Go get the next char in the class */
        }

      /* Handle a lone single character - we can get here for a normal
      non-escape char, or after \ that introduces a single character or for an
      apparent range that isn't. */

      LONE_SINGLE_CHARACTER:

      /* Handle a character that cannot go in the bit map */

#ifdef SUPPORT_UTF8
      if (utf8 && (c > 255 || ((options & PCRE_CASELESS) != 0 && c > 127)))
        {
        class_utf8 = TRUE;
        *class_utf8data++ = XCL_SINGLE;
        class_utf8data += _pcre_ord2utf8(c, class_utf8data);

#ifdef SUPPORT_UCP
        if ((options & PCRE_CASELESS) != 0)
          {
          unsigned int othercase;
          if ((othercase = UCD_OTHERCASE(c)) != c)
            {
            *class_utf8data++ = XCL_SINGLE;
            class_utf8data += _pcre_ord2utf8(othercase, class_utf8data);
            }
          }
#endif  /* SUPPORT_UCP */

        }
      else
#endif  /* SUPPORT_UTF8 */

      /* Handle a single-byte character */
        {
        classbits[c/8] |= (1 << (c&7));
        if ((options & PCRE_CASELESS) != 0)
          {
          c = cd->fcc[c];   /* flip case */
          classbits[c/8] |= (1 << (c&7));
          }
        class_charcount++;
        class_lastchar = c;
        }
      }

    /* Loop until ']' reached. This "while" is the end of the "do" above. */

    while ((c = *(++ptr)) != 0 && (c != ']' || inescq));

    if (c == 0)                          /* Missing terminating ']' */
      {
      *errorcodeptr = ERR6;
      goto FAILED;
      }


/* This code has been disabled because it would mean that \s counts as
an explicit \r or \n reference, and that's not really what is wanted. Now
we set the flag only if there is a literal "\r" or "\n" in the class. */

#if 0
    /* Remember whether \r or \n are in this class */

    if (negate_class)
      {
      if ((classbits[1] & 0x24) != 0x24) cd->external_flags |= PCRE_HASCRORLF;
      }
    else
      {
      if ((classbits[1] & 0x24) != 0) cd->external_flags |= PCRE_HASCRORLF;
      }
#endif


    /* If class_charcount is 1, we saw precisely one character whose value is
    less than 256. As long as there were no characters >= 128 and there was no
    use of \p or \P, in other words, no use of any XCLASS features, we can
    optimize.

    In UTF-8 mode, we can optimize the negative case only if there were no
    characters >= 128 because OP_NOT and the related opcodes like OP_NOTSTAR
    operate on single-bytes only. This is an historical hangover. Maybe one day
    we can tidy these opcodes to handle multi-byte characters.

    The optimization throws away the bit map. We turn the item into a
    1-character OP_CHAR[NC] if it's positive, or OP_NOT if it's negative. Note
    that OP_NOT does not support multibyte characters. In the positive case, it
    can cause firstbyte to be set. Otherwise, there can be no first char if
    this item is first, whatever repeat count may follow. In the case of
    reqbyte, save the previous value for reinstating. */

#ifdef SUPPORT_UTF8
    if (class_charcount == 1 && !class_utf8 &&
      (!utf8 || !negate_class || class_lastchar < 128))
#else
    if (class_charcount == 1)
#endif
      {
      zeroreqbyte = reqbyte;

      /* The OP_NOT opcode works on one-byte characters only. */

      if (negate_class)
        {
        if (firstbyte == REQ_UNSET) firstbyte = REQ_NONE;
        zerofirstbyte = firstbyte;
        *code++ = OP_NOT;
        *code++ = (uschar)class_lastchar;
        break;
        }

      /* For a single, positive character, get the value into mcbuffer, and
      then we can handle this with the normal one-character code. */

#ifdef SUPPORT_UTF8
      if (utf8 && class_lastchar > 127)
        mclength = _pcre_ord2utf8(class_lastchar, mcbuffer);
      else
#endif
        {
        mcbuffer[0] = (uschar)class_lastchar;
        mclength = 1;
        }
      goto ONE_CHAR;
      }       /* End of 1-char optimization */

    /* The general case - not the one-char optimization. If this is the first
    thing in the branch, there can be no first char setting, whatever the
    repeat count. Any reqbyte setting must remain unchanged after any kind of
    repeat. */

    if (firstbyte == REQ_UNSET) firstbyte = REQ_NONE;
    zerofirstbyte = firstbyte;
    zeroreqbyte = reqbyte;

    /* If there are characters with values > 255, we have to compile an
    extended class, with its own opcode, unless there was a negated special
    such as \S in the class, because in that case all characters > 255 are in
    the class, so any that were explicitly given as well can be ignored. If
    (when there are explicit characters > 255 that must be listed) there are no
    characters < 256, we can omit the bitmap in the actual compiled code. */

#ifdef SUPPORT_UTF8
    if (class_utf8 && !should_flip_negation)
      {
      *class_utf8data++ = XCL_END;    /* Marks the end of extra data */
      *code++ = OP_XCLASS;
      code += LINK_SIZE;
      *code = negate_class? XCL_NOT : 0;

      /* If the map is required, move up the extra data to make room for it;
      otherwise just move the code pointer to the end of the extra data. */

      if (class_charcount > 0)
        {
        *code++ |= XCL_MAP;
        memmove(code + 32, code, class_utf8data - code);
        memcpy(code, classbits, 32);
        code = class_utf8data + 32;
        }
      else code = class_utf8data;

      /* Now fill in the complete length of the item */

      PUT(previous, 1, code - previous);
      break;   /* End of class handling */
      }
#endif

    /* If there are no characters > 255, set the opcode to OP_CLASS or
    OP_NCLASS, depending on whether the whole class was negated and whether
    there were negative specials such as \S in the class. Then copy the 32-byte
    map into the code vector, negating it if necessary. */

    *code++ = (negate_class == should_flip_negation) ? OP_CLASS : OP_NCLASS;
    if (negate_class)
      {
      if (lengthptr == NULL)    /* Save time in the pre-compile phase */
        for (c = 0; c < 32; c++) code[c] = ~classbits[c];
      }
    else
      {
      memcpy(code, classbits, 32);
      }
    code += 32;
    break;


    /* ===================================================================*/
    /* Various kinds of repeat; '{' is not necessarily a quantifier, but this
    has been tested above. */

    case '{':
    if (!is_quantifier) goto NORMAL_CHAR;
    ptr = read_repeat_counts(ptr+1, &repeat_min, &repeat_max, errorcodeptr);
    if (*errorcodeptr != 0) goto FAILED;
    goto REPEAT;

    case '*':
    repeat_min = 0;
    repeat_max = -1;
    goto REPEAT;

    case '+':
    repeat_min = 1;
    repeat_max = -1;
    goto REPEAT;

    case '?':
    repeat_min = 0;
    repeat_max = 1;

    REPEAT:
    if (previous == NULL)
      {
      *errorcodeptr = ERR9;
      goto FAILED;
      }

    if (repeat_min == 0)
      {
      firstbyte = zerofirstbyte;    /* Adjust for zero repeat */
      reqbyte = zeroreqbyte;        /* Ditto */
      }

    /* Remember whether this is a variable length repeat */

    reqvary = (repeat_min == repeat_max)? 0 : REQ_VARY;

    op_type = 0;                    /* Default single-char op codes */
    possessive_quantifier = FALSE;  /* Default not possessive quantifier */

    /* Save start of previous item, in case we have to move it up to make space
    for an inserted OP_ONCE for the additional '+' extension. */

    tempcode = previous;

    /* If the next character is '+', we have a possessive quantifier. This
    implies greediness, whatever the setting of the PCRE_UNGREEDY option.
    If the next character is '?' this is a minimizing repeat, by default,
    but if PCRE_UNGREEDY is set, it works the other way round. We change the
    repeat type to the non-default. */

    if (ptr[1] == '+')
      {
      repeat_type = 0;                  /* Force greedy */
      possessive_quantifier = TRUE;
      ptr++;
      }
    else if (ptr[1] == '?')
      {
      repeat_type = greedy_non_default;
      ptr++;
      }
    else repeat_type = greedy_default;

    /* If previous was a character match, abolish the item and generate a
    repeat item instead. If a char item has a minumum of more than one, ensure
    that it is set in reqbyte - it might not be if a sequence such as x{3} is
    the first thing in a branch because the x will have gone into firstbyte
    instead.  */

    if (*previous == OP_CHAR || *previous == OP_CHARNC)
      {
      /* Deal with UTF-8 characters that take up more than one byte. It's
      easier to write this out separately than try to macrify it. Use c to
      hold the length of the character in bytes, plus 0x80 to flag that it's a
      length rather than a small character. */

#ifdef SUPPORT_UTF8
      if (utf8 && (code[-1] & 0x80) != 0)
        {
        uschar *lastchar = code - 1;
        while((*lastchar & 0xc0) == 0x80) lastchar--;
        c = (int)(code - lastchar);     /* Length of UTF-8 character */
        memcpy(utf8_char, lastchar, c); /* Save the char */
        c |= 0x80;                      /* Flag c as a length */
        }
      else
#endif

      /* Handle the case of a single byte - either with no UTF8 support, or
      with UTF-8 disabled, or for a UTF-8 character < 128. */

        {
        c = code[-1];
        if (repeat_min > 1) reqbyte = c | req_caseopt | cd->req_varyopt;
        }

      /* If the repetition is unlimited, it pays to see if the next thing on
      the line is something that cannot possibly match this character. If so,
      automatically possessifying this item gains some performance in the case
      where the match fails. */

      if (!possessive_quantifier &&
          repeat_max < 0 &&
          check_auto_possessive(*previous, c, utf8, utf8_char, ptr + 1,
            options, cd))
        {
        repeat_type = 0;    /* Force greedy */
        possessive_quantifier = TRUE;
        }

      goto OUTPUT_SINGLE_REPEAT;   /* Code shared with single character types */
      }

    /* If previous was a single negated character ([^a] or similar), we use
    one of the special opcodes, replacing it. The code is shared with single-
    character repeats by setting opt_type to add a suitable offset into
    repeat_type. We can also test for auto-possessification. OP_NOT is
    currently used only for single-byte chars. */

    else if (*previous == OP_NOT)
      {
      op_type = OP_NOTSTAR - OP_STAR;  /* Use "not" opcodes */
      c = previous[1];
      if (!possessive_quantifier &&
          repeat_max < 0 &&
          check_auto_possessive(OP_NOT, c, utf8, NULL, ptr + 1, options, cd))
        {
        repeat_type = 0;    /* Force greedy */
        possessive_quantifier = TRUE;
        }
      goto OUTPUT_SINGLE_REPEAT;
      }

    /* If previous was a character type match (\d or similar), abolish it and
    create a suitable repeat item. The code is shared with single-character
    repeats by setting op_type to add a suitable offset into repeat_type. Note
    the the Unicode property types will be present only when SUPPORT_UCP is
    defined, but we don't wrap the little bits of code here because it just
    makes it horribly messy. */

    else if (*previous < OP_EODN)
      {
      uschar *oldcode;
      int prop_type, prop_value;
      op_type = OP_TYPESTAR - OP_STAR;  /* Use type opcodes */
      c = *previous;

      if (!possessive_quantifier &&
          repeat_max < 0 &&
          check_auto_possessive(c, 0, utf8, NULL, ptr + 1, options, cd))
        {
        repeat_type = 0;    /* Force greedy */
        possessive_quantifier = TRUE;
        }

      OUTPUT_SINGLE_REPEAT:
      if (*previous == OP_PROP || *previous == OP_NOTPROP)
        {
        prop_type = previous[1];
        prop_value = previous[2];
        }
      else prop_type = prop_value = -1;

      oldcode = code;
      code = previous;                  /* Usually overwrite previous item */

      /* If the maximum is zero then the minimum must also be zero; Perl allows
      this case, so we do too - by simply omitting the item altogether. */

      if (repeat_max == 0) goto END_REPEAT;

      /* All real repeats make it impossible to handle partial matching (maybe
      one day we will be able to remove this restriction). */

      if (repeat_max != 1) cd->external_flags |= PCRE_NOPARTIAL;

      /* Combine the op_type with the repeat_type */

      repeat_type += op_type;

      /* A minimum of zero is handled either as the special case * or ?, or as
      an UPTO, with the maximum given. */

      if (repeat_min == 0)
        {
        if (repeat_max == -1) *code++ = (uschar)(OP_STAR + repeat_type);
          else if (repeat_max == 1) *code++ = (uschar)(OP_QUERY + repeat_type);
        else
          {
          *code++ = (uschar)(OP_UPTO + repeat_type);
          PUT2INC(code, 0, repeat_max);
          }
        }

      /* A repeat minimum of 1 is optimized into some special cases. If the
      maximum is unlimited, we use OP_PLUS. Otherwise, the original item is
      left in place and, if the maximum is greater than 1, we use OP_UPTO with
      one less than the maximum. */

      else if (repeat_min == 1)
        {
        if (repeat_max == -1)
          *code++ = (uschar)(OP_PLUS + repeat_type);
        else
          {
          code = oldcode;                 /* leave previous item in place */
          if (repeat_max == 1) goto END_REPEAT;
          *code++ = (uschar)(OP_UPTO + repeat_type);
          PUT2INC(code, 0, repeat_max - 1);
          }
        }

      /* The case {n,n} is just an EXACT, while the general case {n,m} is
      handled as an EXACT followed by an UPTO. */

      else
        {
        *code++ = (uschar)(OP_EXACT + op_type);  /* NB EXACT doesn't have repeat_type */
        PUT2INC(code, 0, repeat_min);

        /* If the maximum is unlimited, insert an OP_STAR. Before doing so,
        we have to insert the character for the previous code. For a repeated
        Unicode property match, there are two extra bytes that define the
        required property. In UTF-8 mode, long characters have their length in
        c, with the 0x80 bit as a flag. */

        if (repeat_max < 0)
          {
#ifdef SUPPORT_UTF8
          if (utf8 && c >= 128)
            {
            memcpy(code, utf8_char, c & 7);
            code += c & 7;
            }
          else
#endif
            {
            *code++ = (uschar)c;
            if (prop_type >= 0)
              {
              *code++ = (uschar)prop_type;
              *code++ = (uschar)prop_value;
              }
            }
          *code++ = (uschar)(OP_STAR + repeat_type);
          }

        /* Else insert an UPTO if the max is greater than the min, again
        preceded by the character, for the previously inserted code. If the
        UPTO is just for 1 instance, we can use QUERY instead. */

        else if (repeat_max != repeat_min)
          {
#ifdef SUPPORT_UTF8
          if (utf8 && c >= 128)
            {
            memcpy(code, utf8_char, c & 7);
            code += c & 7;
            }
          else
#endif
          *code++ = (uschar)c;
          if (prop_type >= 0)
            {
            *code++ = (uschar)prop_type;
            *code++ = (uschar)prop_value;
            }
          repeat_max -= repeat_min;

          if (repeat_max == 1)
            {
            *code++ = (uschar)(OP_QUERY + repeat_type);
            }
          else
            {
            *code++ = (uschar)(OP_UPTO + repeat_type);
            PUT2INC(code, 0, repeat_max);
            }
          }
        }

      /* The character or character type itself comes last in all cases. */

#ifdef SUPPORT_UTF8
      if (utf8 && c >= 128)
        {
        memcpy(code, utf8_char, c & 7);
        code += c & 7;
        }
      else
#endif
      *code++ = (uschar)c;

      /* For a repeated Unicode property match, there are two extra bytes that
      define the required property. */

#ifdef SUPPORT_UCP
      if (prop_type >= 0)
        {
        *code++ = (uschar)(prop_type);
        *code++ = (uschar)(prop_value);
        }
#endif
      }

    /* If previous was a character class or a back reference, we put the repeat
    stuff after it, but just skip the item if the repeat was {0,0}. */

    else if (*previous == OP_CLASS ||
             *previous == OP_NCLASS ||
#ifdef SUPPORT_UTF8
             *previous == OP_XCLASS ||
#endif
             *previous == OP_REF)
      {
      if (repeat_max == 0)
        {
        code = previous;
        goto END_REPEAT;
        }

      /* All real repeats make it impossible to handle partial matching (maybe
      one day we will be able to remove this restriction). */

      if (repeat_max != 1) cd->external_flags |= PCRE_NOPARTIAL;

      if (repeat_min == 0 && repeat_max == -1)
        *code++ = (uschar)(OP_CRSTAR + repeat_type);
      else if (repeat_min == 1 && repeat_max == -1)
        *code++ = (uschar)(OP_CRPLUS + repeat_type);
      else if (repeat_min == 0 && repeat_max == 1)
        *code++ = (uschar)(OP_CRQUERY + repeat_type);
      else
        {
        *code++ = (uschar)(OP_CRRANGE + repeat_type);
        PUT2INC(code, 0, repeat_min);
        if (repeat_max == -1) repeat_max = 0;  /* 2-byte encoding for max */
        PUT2INC(code, 0, repeat_max);
        }
      }

    /* If previous was a bracket group, we may have to replicate it in certain
    cases. */

    else if (*previous == OP_BRA  || *previous == OP_CBRA ||
             *previous == OP_ONCE || *previous == OP_COND)
      {
      register int i;
      int ketoffset = 0;
      int len = (int)(code - previous);
      uschar *bralink = NULL;

      /* Repeating a DEFINE group is pointless */

      if (*previous == OP_COND && previous[LINK_SIZE+1] == OP_DEF)
        {
        *errorcodeptr = ERR55;
        goto FAILED;
        }

      /* If the maximum repeat count is unlimited, find the end of the bracket
      by scanning through from the start, and compute the offset back to it
      from the current code pointer. There may be an OP_OPT setting following
      the final KET, so we can't find the end just by going back from the code
      pointer. */

      if (repeat_max == -1)
        {
        register uschar *ket = previous;
        do ket += GET(ket, 1); while (*ket != OP_KET);
        ketoffset = (int)(code - ket);
        }

      /* The case of a zero minimum is special because of the need to stick
      OP_BRAZERO in front of it, and because the group appears once in the
      data, whereas in other cases it appears the minimum number of times. For
      this reason, it is simplest to treat this case separately, as otherwise
      the code gets far too messy. There are several special subcases when the
      minimum is zero. */

      if (repeat_min == 0)
        {
        /* If the maximum is also zero, we used to just omit the group from the
        output altogether, like this:

        ** if (repeat_max == 0)
        **   {
        **   code = previous;
        **   goto END_REPEAT;
        **   }

        However, that fails when a group is referenced as a subroutine from
        elsewhere in the pattern, so now we stick in OP_SKIPZERO in front of it
        so that it is skipped on execution. As we don't have a list of which
        groups are referenced, we cannot do this selectively.

        If the maximum is 1 or unlimited, we just have to stick in the BRAZERO
        and do no more at this point. However, we do need to adjust any
        OP_RECURSE calls inside the group that refer to the group itself or any
        internal or forward referenced group, because the offset is from the
        start of the whole regex. Temporarily terminate the pattern while doing
        this. */

        if (repeat_max <= 1)    /* Covers 0, 1, and unlimited */
          {
          *code = OP_END;
          adjust_recurse(previous, 1, utf8, cd, save_hwm);
          memmove(previous+1, previous, len);
          code++;
          if (repeat_max == 0)
            {
            *previous++ = OP_SKIPZERO;
            goto END_REPEAT;
            }
          *previous++ = (uschar)(OP_BRAZERO + repeat_type);
          }

        /* If the maximum is greater than 1 and limited, we have to replicate
        in a nested fashion, sticking OP_BRAZERO before each set of brackets.
        The first one has to be handled carefully because it's the original
        copy, which has to be moved up. The remainder can be handled by code
        that is common with the non-zero minimum case below. We have to
        adjust the value or repeat_max, since one less copy is required. Once
        again, we may have to adjust any OP_RECURSE calls inside the group. */

        else
          {
          int offset;
          *code = OP_END;
          adjust_recurse(previous, 2 + LINK_SIZE, utf8, cd, save_hwm);
          memmove(previous + 2 + LINK_SIZE, previous, len);
          code += 2 + LINK_SIZE;
          *previous++ = (uschar)(OP_BRAZERO + repeat_type);
          *previous++ = (uschar)OP_BRA;

          /* We chain together the bracket offset fields that have to be
          filled in later when the ends of the brackets are reached. */

          offset = (bralink == NULL)? 0 : (int)(previous - bralink);
          bralink = previous;
          PUTINC(previous, 0, offset);
          }

        repeat_max--;
        }

      /* If the minimum is greater than zero, replicate the group as many
      times as necessary, and adjust the maximum to the number of subsequent
      copies that we need. If we set a first char from the group, and didn't
      set a required char, copy the latter from the former. If there are any
      forward reference subroutine calls in the group, there will be entries on
      the workspace list; replicate these with an appropriate increment. */

      else
        {
        if (repeat_min > 1)
          {
          /* In the pre-compile phase, we don't actually do the replication. We
          just adjust the length as if we had. Do some paranoid checks for
          potential integer overflow. */

          if (lengthptr != NULL)
            {
            int delta = (repeat_min - 1)*length_prevgroup;
            if ((double)(repeat_min - 1)*(double)length_prevgroup >
                                                            (double)INT_MAX ||
                OFLOW_MAX - *lengthptr < delta)
              {
              *errorcodeptr = ERR20;
              goto FAILED;
              }
            *lengthptr += delta;
            }

          /* This is compiling for real */

          else
            {
            if (groupsetfirstbyte && reqbyte < 0) reqbyte = firstbyte;
            for (i = 1; i < repeat_min; i++)
              {
              uschar *hc;
              uschar *this_hwm = cd->hwm;
              memcpy(code, previous, len);
              for (hc = save_hwm; hc < this_hwm; hc += LINK_SIZE)
                {
                PUT(cd->hwm, 0, GET(hc, 0) + len);
                cd->hwm += LINK_SIZE;
                }
              save_hwm = this_hwm;
              code += len;
              }
            }
          }

        if (repeat_max > 0) repeat_max -= repeat_min;
        }

      /* This code is common to both the zero and non-zero minimum cases. If
      the maximum is limited, it replicates the group in a nested fashion,
      remembering the bracket starts on a stack. In the case of a zero minimum,
      the first one was set up above. In all cases the repeat_max now specifies
      the number of additional copies needed. Again, we must remember to
      replicate entries on the forward reference list. */

      if (repeat_max >= 0)
        {
        /* In the pre-compile phase, we don't actually do the replication. We
        just adjust the length as if we had. For each repetition we must add 1
        to the length for BRAZERO and for all but the last repetition we must
        add 2 + 2*LINKSIZE to allow for the nesting that occurs. Do some
        paranoid checks to avoid integer overflow. */

        if (lengthptr != NULL && repeat_max > 0)
          {
          int delta = repeat_max * (length_prevgroup + 1 + 2 + 2*LINK_SIZE) -
                      2 - 2*LINK_SIZE;   /* Last one doesn't nest */
          if ((double)repeat_max *
                (double)(length_prevgroup + 1 + 2 + 2*LINK_SIZE)
                  > (double)INT_MAX ||
              OFLOW_MAX - *lengthptr < delta)
            {
            *errorcodeptr = ERR20;
            goto FAILED;
            }
          *lengthptr += delta;
          }

        /* This is compiling for real */

        else for (i = repeat_max - 1; i >= 0; i--)
          {
          uschar *hc;
          uschar *this_hwm = cd->hwm;

          *code++ = (uschar)(OP_BRAZERO + repeat_type);

          /* All but the final copy start a new nesting, maintaining the
          chain of brackets outstanding. */

          if (i != 0)
            {
            int offset;
            *code++ = OP_BRA;
            offset = (bralink == NULL)? 0 : (int)(code - bralink);
            bralink = code;
            PUTINC(code, 0, offset);
            }

          memcpy(code, previous, len);
          for (hc = save_hwm; hc < this_hwm; hc += LINK_SIZE)
            {
            PUT(cd->hwm, 0, GET(hc, 0) + len + ((i != 0)? 2+LINK_SIZE : 1));
            cd->hwm += LINK_SIZE;
            }
          save_hwm = this_hwm;
          code += len;
          }

        /* Now chain through the pending brackets, and fill in their length
        fields (which are holding the chain links pro tem). */

        while (bralink != NULL)
          {
          int oldlinkoffset;
          int offset = (int)(code - bralink + 1);
          uschar *bra = code - offset;
          oldlinkoffset = GET(bra, 1);
          bralink = (oldlinkoffset == 0)? NULL : bralink - oldlinkoffset;
          *code++ = OP_KET;
          PUTINC(code, 0, offset);
          PUT(bra, 1, offset);
          }
        }

      /* If the maximum is unlimited, set a repeater in the final copy. We
      can't just offset backwards from the current code point, because we
      don't know if there's been an options resetting after the ket. The
      correct offset was computed above.

      Then, when we are doing the actual compile phase, check to see whether
      this group is a non-atomic one that could match an empty string. If so,
      convert the initial operator to the S form (e.g. OP_BRA -> OP_SBRA) so
      that runtime checking can be done. [This check is also applied to
      atomic groups at runtime, but in a different way.] */

      else
        {
        uschar *ketcode = code - ketoffset;
        uschar *bracode = ketcode - GET(ketcode, 1);
        *ketcode = (uschar)(OP_KETRMAX + repeat_type);
        if (lengthptr == NULL && *bracode != OP_ONCE)
          {
          uschar *scode = bracode;
          do
            {
            if (could_be_empty_branch(scode, ketcode, utf8))
              {
              *bracode += OP_SBRA - OP_BRA;
              break;
              }
            scode += GET(scode, 1);
            }
          while (*scode == OP_ALT);
          }
        }
      }

    /* If previous is OP_FAIL, it was generated by an empty class [] in
    JavaScript mode. The other ways in which OP_FAIL can be generated, that is
    by (*FAIL) or (?!) set previous to NULL, which gives a "nothing to repeat"
    error above. We can just ignore the repeat in JS case. */

    else if (*previous == OP_FAIL) goto END_REPEAT;

    /* Else there's some kind of shambles */

    else
      {
      *errorcodeptr = ERR11;
      goto FAILED;
      }

    /* If the character following a repeat is '+', or if certain optimization
    tests above succeeded, possessive_quantifier is TRUE. For some of the
    simpler opcodes, there is an special alternative opcode for this. For
    anything else, we wrap the entire repeated item inside OP_ONCE brackets.
    The '+' notation is just syntactic sugar, taken from Sun's Java package,
    but the special opcodes can optimize it a bit. The repeated item starts at
    tempcode, not at previous, which might be the first part of a string whose
    (former) last char we repeated.

    Possessifying an 'exact' quantifier has no effect, so we can ignore it. But
    an 'upto' may follow. We skip over an 'exact' item, and then test the
    length of what remains before proceeding. */

    if (possessive_quantifier)
      {
      int len;
      if (*tempcode == OP_EXACT || *tempcode == OP_TYPEEXACT ||
          *tempcode == OP_NOTEXACT)
        tempcode += _pcre_OP_lengths[*tempcode] +
          ((*tempcode == OP_TYPEEXACT &&
             (tempcode[3] == OP_PROP || tempcode[3] == OP_NOTPROP))? 2:0);
      len = (int)(code - tempcode);
      if (len > 0) switch (*tempcode)
        {
        case OP_STAR:  *tempcode = OP_POSSTAR; break;
        case OP_PLUS:  *tempcode = OP_POSPLUS; break;
        case OP_QUERY: *tempcode = OP_POSQUERY; break;
        case OP_UPTO:  *tempcode = OP_POSUPTO; break;

        case OP_TYPESTAR:  *tempcode = OP_TYPEPOSSTAR; break;
        case OP_TYPEPLUS:  *tempcode = OP_TYPEPOSPLUS; break;
        case OP_TYPEQUERY: *tempcode = OP_TYPEPOSQUERY; break;
        case OP_TYPEUPTO:  *tempcode = OP_TYPEPOSUPTO; break;

        case OP_NOTSTAR:  *tempcode = OP_NOTPOSSTAR; break;
        case OP_NOTPLUS:  *tempcode = OP_NOTPOSPLUS; break;
        case OP_NOTQUERY: *tempcode = OP_NOTPOSQUERY; break;
        case OP_NOTUPTO:  *tempcode = OP_NOTPOSUPTO; break;

        default:
        memmove(tempcode + 1+LINK_SIZE, tempcode, len);
        code += 1 + LINK_SIZE;
        len += 1 + LINK_SIZE;
        tempcode[0] = OP_ONCE;
        *code++ = OP_KET;
        PUTINC(code, 0, len);
        PUT(tempcode, 1, len);
        break;
        }
      }

    /* In all case we no longer have a previous item. We also set the
    "follows varying string" flag for subsequently encountered reqbytes if
    it isn't already set and we have just passed a varying length item. */

    END_REPEAT:
    previous = NULL;
    cd->req_varyopt |= reqvary;
    break;


    /* ===================================================================*/
    /* Start of nested parenthesized sub-expression, or comment or lookahead or
    lookbehind or option setting or condition or all the other extended
    parenthesis forms.  */

    case '(':
    newoptions = options;
    skipbytes = 0;
    bravalue = OP_CBRA;
    save_hwm = cd->hwm;
    reset_bracount = FALSE;

    /* First deal with various "verbs" that can be introduced by '*'. */

    if (*(++ptr) == '*' && (cd->ctypes[ptr[1]] & ctype_letter) != 0)
      {
      int i, namelen;
      const char *vn = verbnames;
      const uschar *name = ++ptr;
      previous = NULL;
      while ((cd->ctypes[*++ptr] & ctype_letter) != 0) {};
      if (*ptr == ':')
        {
        *errorcodeptr = ERR59;   /* Not supported */
        goto FAILED;
        }
      if (*ptr != ')')
        {
        *errorcodeptr = ERR60;
        goto FAILED;
        }
      namelen = (int)(ptr - name);
      for (i = 0; i < verbcount; i++)
        {
        if (namelen == verbs[i].len &&
            strncmp((char *)name, vn, namelen) == 0)
          {
          *code = (uschar)(verbs[i].op);
          if (*code++ == OP_ACCEPT) cd->had_accept = TRUE;
          break;
          }
        vn += verbs[i].len + 1;
        }
      if (i < verbcount) continue;
      *errorcodeptr = ERR60;
      goto FAILED;
      }

    /* Deal with the extended parentheses; all are introduced by '?', and the
    appearance of any of them means that this is not a capturing group. */

    else if (*ptr == '?')
      {
      int i, set, unset, namelen;
      int *optset;
      const uschar *name;
      uschar *slot;

      switch (*(++ptr))
        {
        case '#':                 /* Comment; skip to ket */
        ptr++;
        while (*ptr != 0 && *ptr != ')') ptr++;
        if (*ptr == 0)
          {
          *errorcodeptr = ERR18;
          goto FAILED;
          }
        continue;


        /* ------------------------------------------------------------ */
        case '|':                 /* Reset capture count for each branch */
        reset_bracount = TRUE;
        /* Fall through */

        /* ------------------------------------------------------------ */
        case ':':                 /* Non-capturing bracket */
        bravalue = OP_BRA;
        ptr++;
        break;


        /* ------------------------------------------------------------ */
        case '(':
        bravalue = OP_COND;       /* Conditional group */

        /* A condition can be an assertion, a number (referring to a numbered
        group), a name (referring to a named group), or 'R', referring to
        recursion. R<digits> and R&name are also permitted for recursion tests.

        There are several syntaxes for testing a named group: (?(name)) is used
        by Python; Perl 5.10 onwards uses (?(<name>) or (?('name')).

        There are two unfortunate ambiguities, caused by history. (a) 'R' can
        be the recursive thing or the name 'R' (and similarly for 'R' followed
        by digits), and (b) a number could be a name that consists of digits.
        In both cases, we look for a name first; if not found, we try the other
        cases. */

        /* For conditions that are assertions, check the syntax, and then exit
        the switch. This will take control down to where bracketed groups,
        including assertions, are processed. */

        if (ptr[1] == '?' && (ptr[2] == '=' || ptr[2] == '!' || ptr[2] == '<'))
          break;

        /* Most other conditions use OP_CREF (a couple change to OP_RREF
        below), and all need to skip 3 bytes at the start of the group. */

        code[1+LINK_SIZE] = OP_CREF;
        skipbytes = 3;
        refsign = -1;

        /* Check for a test for recursion in a named group. */

        if (ptr[1] == 'R' && ptr[2] == '&')
          {
          terminator = -1;
          ptr += 2;
          code[1+LINK_SIZE] = OP_RREF;    /* Change the type of test */
          }

        /* Check for a test for a named group's having been set, using the Perl
        syntax (?(<name>) or (?('name') */

        else if (ptr[1] == '<')
          {
          terminator = '>';
          ptr++;
          }
        else if (ptr[1] == '\'')
          {
          terminator = '\'';
          ptr++;
          }
        else
          {
          terminator = 0;
          if (ptr[1] == '-' || ptr[1] == '+') refsign = *(++ptr);
          }

        /* We now expect to read a name; any thing else is an error */

        if ((cd->ctypes[ptr[1]] & ctype_word) == 0)
          {
          ptr += 1;  /* To get the right offset */
          *errorcodeptr = ERR28;
          goto FAILED;
          }

        /* Read the name, but also get it as a number if it's all digits */

        recno = 0;
        name = ++ptr;
        while ((cd->ctypes[*ptr] & ctype_word) != 0)
          {
          if (recno >= 0)
            recno = ((digitab[*ptr] & ctype_digit) != 0)?
              recno * 10 + *ptr - '0' : -1;
          ptr++;
          }
        namelen = (int)(ptr - name);

        if ((terminator > 0 && *ptr++ != terminator) || *ptr++ != ')')
          {
          ptr--;      /* Error offset */
          *errorcodeptr = ERR26;
          goto FAILED;
          }

        /* Do no further checking in the pre-compile phase. */

        if (lengthptr != NULL) break;

        /* In the real compile we do the work of looking for the actual
        reference. If the string started with "+" or "-" we require the rest to
        be digits, in which case recno will be set. */

        if (refsign > 0)
          {
          if (recno <= 0)
            {
            *errorcodeptr = ERR58;
            goto FAILED;
            }
          recno = (refsign == '-')?
            cd->bracount - recno + 1 : recno +cd->bracount;
          if (recno <= 0 || recno > cd->final_bracount)
            {
            *errorcodeptr = ERR15;
            goto FAILED;
            }
          PUT2(code, 2+LINK_SIZE, recno);
          break;
          }

        /* Otherwise (did not start with "+" or "-"), start by looking for the
        name. */

        slot = cd->name_table;
        for (i = 0; i < cd->names_found; i++)
          {
          if (strncmp((char *)name, (char *)slot+2, namelen) == 0) break;
          slot += cd->name_entry_size;
          }

        /* Found a previous named subpattern */

        if (i < cd->names_found)
          {
          recno = GET2(slot, 0);
          PUT2(code, 2+LINK_SIZE, recno);
          }

        /* Search the pattern for a forward reference */

        else if ((i = find_parens(ptr, cd, name, namelen,
                        (options & PCRE_EXTENDED) != 0)) > 0)
          {
          PUT2(code, 2+LINK_SIZE, i);
          }

        /* If terminator == 0 it means that the name followed directly after
        the opening parenthesis [e.g. (?(abc)...] and in this case there are
        some further alternatives to try. For the cases where terminator != 0
        [things like (?(<name>... or (?('name')... or (?(R&name)... ] we have
        now checked all the possibilities, so give an error. */

        else if (terminator != 0)
          {
          *errorcodeptr = ERR15;
          goto FAILED;
          }

        /* Check for (?(R) for recursion. Allow digits after R to specify a
        specific group number. */

        else if (*name == 'R')
          {
          recno = 0;
          for (i = 1; i < namelen; i++)
            {
            if ((digitab[name[i]] & ctype_digit) == 0)
              {
              *errorcodeptr = ERR15;
              goto FAILED;
              }
            recno = recno * 10 + name[i] - '0';
            }
          if (recno == 0) recno = RREF_ANY;
          code[1+LINK_SIZE] = OP_RREF;      /* Change test type */
          PUT2(code, 2+LINK_SIZE, recno);
          }

        /* Similarly, check for the (?(DEFINE) "condition", which is always
        false. */

        else if (namelen == 6 && strncmp((char *)name, "DEFINE", 6) == 0)
          {
          code[1+LINK_SIZE] = OP_DEF;
          skipbytes = 1;
          }

        /* Check for the "name" actually being a subpattern number. We are
        in the second pass here, so final_bracount is set. */

        else if (recno > 0 && recno <= cd->final_bracount)
          {
          PUT2(code, 2+LINK_SIZE, recno);
          }

        /* Either an unidentified subpattern, or a reference to (?(0) */

        else
          {
          *errorcodeptr = (recno == 0)? ERR35: ERR15;
          goto FAILED;
          }
        break;


        /* ------------------------------------------------------------ */
        case '=':                 /* Positive lookahead */
        bravalue = OP_ASSERT;
        ptr++;
        break;


        /* ------------------------------------------------------------ */
        case '!':                 /* Negative lookahead */
        ptr++;
        if (*ptr == ')')          /* Optimize (?!) */
          {
          *code++ = OP_FAIL;
          previous = NULL;
          continue;
          }
        bravalue = OP_ASSERT_NOT;
        break;


        /* ------------------------------------------------------------ */
        case '<':                 /* Lookbehind or named define */
        switch (ptr[1])
          {
          case '=':               /* Positive lookbehind */
          bravalue = OP_ASSERTBACK;
          ptr += 2;
          break;

          case '!':               /* Negative lookbehind */
          bravalue = OP_ASSERTBACK_NOT;
          ptr += 2;
          break;

          default:                /* Could be name define, else bad */
          if ((cd->ctypes[ptr[1]] & ctype_word) != 0) goto DEFINE_NAME;
          ptr++;                  /* Correct offset for error */
          *errorcodeptr = ERR24;
          goto FAILED;
          }
        break;


        /* ------------------------------------------------------------ */
        case '>':                 /* One-time brackets */
        bravalue = OP_ONCE;
        ptr++;
        break;


        /* ------------------------------------------------------------ */
        case 'C':                 /* Callout - may be followed by digits; */
        previous_callout = code;  /* Save for later completion */
        after_manual_callout = 1; /* Skip one item before completing */
        *code++ = OP_CALLOUT;
          {
          int n = 0;
          while ((digitab[*(++ptr)] & ctype_digit) != 0)
            n = n * 10 + *ptr - '0';
          if (*ptr != ')')
            {
            *errorcodeptr = ERR39;
            goto FAILED;
            }
          if (n > 255)
            {
            *errorcodeptr = ERR38;
            goto FAILED;
            }
          *code++ = (uschar)n;
          PUT(code, 0, ptr - cd->start_pattern + 1);  /* Pattern offset */
          PUT(code, LINK_SIZE, 0);                    /* Default length */
          code += 2 * LINK_SIZE;
          }
        previous = NULL;
        continue;


        /* ------------------------------------------------------------ */
        case 'P':                 /* Python-style named subpattern handling */
        if (*(++ptr) == '=' || *ptr == '>')  /* Reference or recursion */
          {
          is_recurse = *ptr == '>';
          terminator = ')';
          goto NAMED_REF_OR_RECURSE;
          }
        else if (*ptr != '<')    /* Test for Python-style definition */
          {
          *errorcodeptr = ERR41;
          goto FAILED;
          }
        /* Fall through to handle (?P< as (?< is handled */


        /* ------------------------------------------------------------ */
        DEFINE_NAME:    /* Come here from (?< handling */
        case '\'':
          {
          terminator = (*ptr == '<')? '>' : '\'';
          name = ++ptr;

          while ((cd->ctypes[*ptr] & ctype_word) != 0) ptr++;
          namelen = (int)(ptr - name);

          /* In the pre-compile phase, just do a syntax check. */

          if (lengthptr != NULL)
            {
            if (*ptr != terminator)
              {
              *errorcodeptr = ERR42;
              goto FAILED;
              }
            if (cd->names_found >= MAX_NAME_COUNT)
              {
              *errorcodeptr = ERR49;
              goto FAILED;
              }
            if (namelen + 3 > cd->name_entry_size)
              {
              cd->name_entry_size = namelen + 3;
              if (namelen > MAX_NAME_SIZE)
                {
                *errorcodeptr = ERR48;
                goto FAILED;
                }
              }
            }

          /* In the real compile, create the entry in the table */

          else
            {
            slot = cd->name_table;
            for (i = 0; i < cd->names_found; i++)
              {
              int crc = memcmp(name, slot+2, namelen);
              if (crc == 0)
                {
                if (slot[2+namelen] == 0)
                  {
                  if ((options & PCRE_DUPNAMES) == 0)
                    {
                    *errorcodeptr = ERR43;
                    goto FAILED;
                    }
                  }
                else crc = -1;      /* Current name is substring */
                }
              if (crc < 0)
                {
                memmove(slot + cd->name_entry_size, slot,
                  (cd->names_found - i) * cd->name_entry_size);
                break;
                }
              slot += cd->name_entry_size;
              }

            PUT2(slot, 0, cd->bracount + 1);
            memcpy(slot + 2, name, namelen);
            slot[2+namelen] = 0;
            }
          }

        /* In both cases, count the number of names we've encountered. */

        ptr++;                    /* Move past > or ' */
        cd->names_found++;
        goto NUMBERED_GROUP;


        /* ------------------------------------------------------------ */
        case '&':                 /* Perl recursion/subroutine syntax */
        terminator = ')';
        is_recurse = TRUE;
        /* Fall through */

        /* We come here from the Python syntax above that handles both
        references (?P=name) and recursion (?P>name), as well as falling
        through from the Perl recursion syntax (?&name). We also come here from
        the Perl \k<name> or \k'name' back reference syntax and the \k{name}
        .NET syntax, and the Oniguruma \g<...> and \g'...' subroutine syntax. */

        NAMED_REF_OR_RECURSE:
        name = ++ptr;
        while ((cd->ctypes[*ptr] & ctype_word) != 0) ptr++;
        namelen = (int)(ptr - name);

        /* In the pre-compile phase, do a syntax check and set a dummy
        reference number. */

        if (lengthptr != NULL)
          {
          if (namelen == 0)
            {
            *errorcodeptr = ERR62;
            goto FAILED;
            }
          if (*ptr != terminator)
            {
            *errorcodeptr = ERR42;
            goto FAILED;
            }
          if (namelen > MAX_NAME_SIZE)
            {
            *errorcodeptr = ERR48;
            goto FAILED;
            }
          recno = 0;
          }

        /* In the real compile, seek the name in the table. We check the name
        first, and then check that we have reached the end of the name in the
        table. That way, if the name that is longer than any in the table,
        the comparison will fail without reading beyond the table entry. */

        else
          {
          slot = cd->name_table;
          for (i = 0; i < cd->names_found; i++)
            {
            if (strncmp((char *)name, (char *)slot+2, namelen) == 0 &&
                slot[2+namelen] == 0)
              break;
            slot += cd->name_entry_size;
            }

          if (i < cd->names_found)         /* Back reference */
            {
            recno = GET2(slot, 0);
            }
          else if ((recno =                /* Forward back reference */
                    find_parens(ptr, cd, name, namelen,
                      (options & PCRE_EXTENDED) != 0)) <= 0)
            {
            *errorcodeptr = ERR15;
            goto FAILED;
            }
          }

        /* In both phases, we can now go to the code than handles numerical
        recursion or backreferences. */

        if (is_recurse) goto HANDLE_RECURSION;
          else goto HANDLE_REFERENCE;


        /* ------------------------------------------------------------ */
        case 'R':                 /* Recursion */
        ptr++;                    /* Same as (?0)      */
        /* Fall through */


        /* ------------------------------------------------------------ */
        case '-': case '+':
        case '0': case '1': case '2': case '3': case '4':   /* Recursion or */
        case '5': case '6': case '7': case '8': case '9':   /* subroutine */
          {
          const uschar *called;
          terminator = ')';

          /* Come here from the \g<...> and \g'...' code (Oniguruma
          compatibility). However, the syntax has been checked to ensure that
          the ... are a (signed) number, so that neither ERR63 nor ERR29 will
          be called on this path, nor with the jump to OTHER_CHAR_AFTER_QUERY
          ever be taken. */

          HANDLE_NUMERICAL_RECURSION:

          if ((refsign = *ptr) == '+')
            {
            ptr++;
            if ((digitab[*ptr] & ctype_digit) == 0)
              {
              *errorcodeptr = ERR63;
              goto FAILED;
              }
            }
          else if (refsign == '-')
            {
            if ((digitab[ptr[1]] & ctype_digit) == 0)
              goto OTHER_CHAR_AFTER_QUERY;
            ptr++;
            }

          recno = 0;
          while((digitab[*ptr] & ctype_digit) != 0)
            recno = recno * 10 + *ptr++ - '0';

          if (*ptr != terminator)
            {
            *errorcodeptr = ERR29;
            goto FAILED;
            }

          if (refsign == '-')
            {
            if (recno == 0)
              {
              *errorcodeptr = ERR58;
              goto FAILED;
              }
            recno = cd->bracount - recno + 1;
            if (recno <= 0)
              {
              *errorcodeptr = ERR15;
              goto FAILED;
              }
            }
          else if (refsign == '+')
            {
            if (recno == 0)
              {
              *errorcodeptr = ERR58;
              goto FAILED;
              }
            recno += cd->bracount;
            }

          /* Come here from code above that handles a named recursion */

          HANDLE_RECURSION:

          previous = code;
          called = cd->start_code;

          /* When we are actually compiling, find the bracket that is being
          referenced. Temporarily end the regex in case it doesn't exist before
          this point. If we end up with a forward reference, first check that
          the bracket does occur later so we can give the error (and position)
          now. Then remember this forward reference in the workspace so it can
          be filled in at the end. */

          if (lengthptr == NULL)
            {
            *code = OP_END;
            if (recno != 0) called = find_bracket(cd->start_code, utf8, recno);

            /* Forward reference */

            if (called == NULL)
              {
              if (find_parens(ptr, cd, NULL, recno,
                    (options & PCRE_EXTENDED) != 0) < 0)
                {
                *errorcodeptr = ERR15;
                goto FAILED;
                }
              called = cd->start_code + recno;
              PUTINC(cd->hwm, 0, code + 2 + LINK_SIZE - cd->start_code);
              }

            /* If not a forward reference, and the subpattern is still open,
            this is a recursive call. We check to see if this is a left
            recursion that could loop for ever, and diagnose that case. */

            else if (GET(called, 1) == 0 &&
                     could_be_empty(called, code, bcptr, utf8))
              {
              *errorcodeptr = ERR40;
              goto FAILED;
              }
            }

          /* Insert the recursion/subroutine item, automatically wrapped inside
          "once" brackets. Set up a "previous group" length so that a
          subsequent quantifier will work. */

          *code = OP_ONCE;
          PUT(code, 1, 2 + 2*LINK_SIZE);
          code += 1 + LINK_SIZE;

          *code = OP_RECURSE;
          PUT(code, 1, called - cd->start_code);
          code += 1 + LINK_SIZE;

          *code = OP_KET;
          PUT(code, 1, 2 + 2*LINK_SIZE);
          code += 1 + LINK_SIZE;

          length_prevgroup = 3 + 3*LINK_SIZE;
          }

        /* Can't determine a first byte now */

        if (firstbyte == REQ_UNSET) firstbyte = REQ_NONE;
        continue;


        /* ------------------------------------------------------------ */
        default:              /* Other characters: check option setting */
        OTHER_CHAR_AFTER_QUERY:
        set = unset = 0;
        optset = &set;

        while (*ptr != ')' && *ptr != ':')
          {
          switch (*ptr++)
            {
            case '-': optset = &unset; break;

            case 'J':    /* Record that it changed in the external options */
            *optset |= PCRE_DUPNAMES;
            cd->external_flags |= PCRE_JCHANGED;
            break;

            case 'i': *optset |= PCRE_CASELESS; break;
            case 'm': *optset |= PCRE_MULTILINE; break;
            case 's': *optset |= PCRE_DOTALL; break;
            case 'x': *optset |= PCRE_EXTENDED; break;
            case 'U': *optset |= PCRE_UNGREEDY; break;
            case 'X': *optset |= PCRE_EXTRA; break;

            default:  *errorcodeptr = ERR12;
                      ptr--;    /* Correct the offset */
                      goto FAILED;
            }
          }

        /* Set up the changed option bits, but don't change anything yet. */

        newoptions = (options | set) & (~unset);

        /* If the options ended with ')' this is not the start of a nested
        group with option changes, so the options change at this level. If this
        item is right at the start of the pattern, the options can be
        abstracted and made external in the pre-compile phase, and ignored in
        the compile phase. This can be helpful when matching -- for instance in
        caseless checking of required bytes.

        If the code pointer is not (cd->start_code + 1 + LINK_SIZE), we are
        definitely *not* at the start of the pattern because something has been
        compiled. In the pre-compile phase, however, the code pointer can have
        that value after the start, because it gets reset as code is discarded
        during the pre-compile. However, this can happen only at top level - if
        we are within parentheses, the starting BRA will still be present. At
        any parenthesis level, the length value can be used to test if anything
        has been compiled at that level. Thus, a test for both these conditions
        is necessary to ensure we correctly detect the start of the pattern in
        both phases.

        If we are not at the pattern start, compile code to change the ims
        options if this setting actually changes any of them, and reset the
        greedy defaults and the case value for firstbyte and reqbyte. */

        if (*ptr == ')')
          {
          if (code == cd->start_code + 1 + LINK_SIZE &&
               (lengthptr == NULL || *lengthptr == 2 + 2*LINK_SIZE))
            {
            cd->external_options = newoptions;
            }
         else
            {
            if ((options & PCRE_IMS) != (newoptions & PCRE_IMS))
              {
              *code++ = OP_OPT;
              *code++ = (uschar)(newoptions & PCRE_IMS);
              }
            greedy_default = ((newoptions & PCRE_UNGREEDY) != 0);
            greedy_non_default = greedy_default ^ 1;
            req_caseopt = ((newoptions & PCRE_CASELESS) != 0)? REQ_CASELESS : 0;
            }

          /* Change options at this level, and pass them back for use
          in subsequent branches. When not at the start of the pattern, this
          information is also necessary so that a resetting item can be
          compiled at the end of a group (if we are in a group). */

          *optionsptr = options = newoptions;
          previous = NULL;       /* This item can't be repeated */
          continue;              /* It is complete */
          }

        /* If the options ended with ':' we are heading into a nested group
        with possible change of options. Such groups are non-capturing and are
        not assertions of any kind. All we need to do is skip over the ':';
        the newoptions value is handled below. */

        bravalue = OP_BRA;
        ptr++;
        }     /* End of switch for character following (? */
      }       /* End of (? handling */

    /* Opening parenthesis not followed by '?'. If PCRE_NO_AUTO_CAPTURE is set,
    all unadorned brackets become non-capturing and behave like (?:...)
    brackets. */

    else if ((options & PCRE_NO_AUTO_CAPTURE) != 0)
      {
      bravalue = OP_BRA;
      }

    /* Else we have a capturing group. */

    else
      {
      NUMBERED_GROUP:
      cd->bracount += 1;
      PUT2(code, 1+LINK_SIZE, cd->bracount);
      skipbytes = 2;
      }

    /* Process nested bracketed regex. Assertions may not be repeated, but
    other kinds can be. All their opcodes are >= OP_ONCE. We copy code into a
    non-register variable in order to be able to pass its address because some
    compilers complain otherwise. Pass in a new setting for the ims options if
    they have changed. */

    previous = (bravalue >= OP_ONCE)? code : NULL;
    *code = (uschar)bravalue;
    tempcode = code;
    tempreqvary = cd->req_varyopt;     /* Save value before bracket */
    length_prevgroup = 0;              /* Initialize for pre-compile phase */

    if (!compile_regex(
         newoptions,                   /* The complete new option state */
         options & PCRE_IMS,           /* The previous ims option state */
         &tempcode,                    /* Where to put code (updated) */
         &ptr,                         /* Input pointer (updated) */
         errorcodeptr,                 /* Where to put an error message */
         (bravalue == OP_ASSERTBACK ||
          bravalue == OP_ASSERTBACK_NOT), /* TRUE if back assert */
         reset_bracount,               /* True if (?| group */
         skipbytes,                    /* Skip over bracket number */
         &subfirstbyte,                /* For possible first char */
         &subreqbyte,                  /* For possible last char */
         bcptr,                        /* Current branch chain */
         cd,                           /* Tables block */
         (lengthptr == NULL)? NULL :   /* Actual compile phase */
           &length_prevgroup           /* Pre-compile phase */
         ))
      goto FAILED;

    /* At the end of compiling, code is still pointing to the start of the
    group, while tempcode has been updated to point past the end of the group
    and any option resetting that may follow it. The pattern pointer (ptr)
    is on the bracket. */

    /* If this is a conditional bracket, check that there are no more than
    two branches in the group, or just one if it's a DEFINE group. We do this
    in the real compile phase, not in the pre-pass, where the whole group may
    not be available. */

    if (bravalue == OP_COND && lengthptr == NULL)
      {
      uschar *tc = code;
      int condcount = 0;

      do {
         condcount++;
         tc += GET(tc,1);
         }
      while (*tc != OP_KET);

      /* A DEFINE group is never obeyed inline (the "condition" is always
      false). It must have only one branch. */

      if (code[LINK_SIZE+1] == OP_DEF)
        {
        if (condcount > 1)
          {
          *errorcodeptr = ERR54;
          goto FAILED;
          }
        bravalue = OP_DEF;   /* Just a flag to suppress char handling below */
        }

      /* A "normal" conditional group. If there is just one branch, we must not
      make use of its firstbyte or reqbyte, because this is equivalent to an
      empty second branch. */

      else
        {
        if (condcount > 2)
          {
          *errorcodeptr = ERR27;
          goto FAILED;
          }
        if (condcount == 1) subfirstbyte = subreqbyte = REQ_NONE;
        }
      }

    /* Error if hit end of pattern */

    if (*ptr != ')')
      {
      *errorcodeptr = ERR14;
      goto FAILED;
      }

    /* In the pre-compile phase, update the length by the length of the group,
    less the brackets at either end. Then reduce the compiled code to just a
    set of non-capturing brackets so that it doesn't use much memory if it is
    duplicated by a quantifier.*/

    if (lengthptr != NULL)
      {
      if (OFLOW_MAX - *lengthptr < length_prevgroup - 2 - 2*LINK_SIZE)
        {
        *errorcodeptr = ERR20;
        goto FAILED;
        }
      *lengthptr += length_prevgroup - 2 - 2*LINK_SIZE;
      *code++ = OP_BRA;
      PUTINC(code, 0, 1 + LINK_SIZE);
      *code++ = OP_KET;
      PUTINC(code, 0, 1 + LINK_SIZE);
      break;    /* No need to waste time with special character handling */
      }

    /* Otherwise update the main code pointer to the end of the group. */

    code = tempcode;

    /* For a DEFINE group, required and first character settings are not
    relevant. */

    if (bravalue == OP_DEF) break;

    /* Handle updating of the required and first characters for other types of
    group. Update for normal brackets of all kinds, and conditions with two
    branches (see code above). If the bracket is followed by a quantifier with
    zero repeat, we have to back off. Hence the definition of zeroreqbyte and
    zerofirstbyte outside the main loop so that they can be accessed for the
    back off. */

    zeroreqbyte = reqbyte;
    zerofirstbyte = firstbyte;
    groupsetfirstbyte = FALSE;

    if (bravalue >= OP_ONCE)
      {
      /* If we have not yet set a firstbyte in this branch, take it from the
      subpattern, remembering that it was set here so that a repeat of more
      than one can replicate it as reqbyte if necessary. If the subpattern has
      no firstbyte, set "none" for the whole branch. In both cases, a zero
      repeat forces firstbyte to "none". */

      if (firstbyte == REQ_UNSET)
        {
        if (subfirstbyte >= 0)
          {
          firstbyte = subfirstbyte;
          groupsetfirstbyte = TRUE;
          }
        else firstbyte = REQ_NONE;
        zerofirstbyte = REQ_NONE;
        }

      /* If firstbyte was previously set, convert the subpattern's firstbyte
      into reqbyte if there wasn't one, using the vary flag that was in
      existence beforehand. */

      else if (subfirstbyte >= 0 && subreqbyte < 0)
        subreqbyte = subfirstbyte | tempreqvary;

      /* If the subpattern set a required byte (or set a first byte that isn't
      really the first byte - see above), set it. */

      if (subreqbyte >= 0) reqbyte = subreqbyte;
      }

    /* For a forward assertion, we take the reqbyte, if set. This can be
    helpful if the pattern that follows the assertion doesn't set a different
    char. For example, it's useful for /(?=abcde).+/. We can't set firstbyte
    for an assertion, however because it leads to incorrect effect for patterns
    such as /(?=a)a.+/ when the "real" "a" would then become a reqbyte instead
    of a firstbyte. This is overcome by a scan at the end if there's no
    firstbyte, looking for an asserted first char. */

    else if (bravalue == OP_ASSERT && subreqbyte >= 0) reqbyte = subreqbyte;
    break;     /* End of processing '(' */


    /* ===================================================================*/
    /* Handle metasequences introduced by \. For ones like \d, the ESC_ values
    are arranged to be the negation of the corresponding OP_values. For the
    back references, the values are ESC_REF plus the reference number. Only
    back references and those types that consume a character may be repeated.
    We can test for values between ESC_b and ESC_Z for the latter; this may
    have to change if any new ones are ever created. */

    case '\\':
    tempptr = ptr;
    c = check_escape(&ptr, errorcodeptr, cd->bracount, options, FALSE);
    if (*errorcodeptr != 0) goto FAILED;

    if (c < 0)
      {
      if (-c == ESC_Q)            /* Handle start of quoted string */
        {
        if (ptr[1] == '\\' && ptr[2] == 'E') ptr += 2; /* avoid empty string */
          else inescq = TRUE;
        continue;
        }

      if (-c == ESC_E) continue;  /* Perl ignores an orphan \E */

      /* For metasequences that actually match a character, we disable the
      setting of a first character if it hasn't already been set. */

      if (firstbyte == REQ_UNSET && -c > ESC_b && -c < ESC_Z)
        firstbyte = REQ_NONE;

      /* Set values to reset to if this is followed by a zero repeat. */

      zerofirstbyte = firstbyte;
      zeroreqbyte = reqbyte;

      /* \g<name> or \g'name' is a subroutine call by name and \g<n> or \g'n'
      is a subroutine call by number (Oniguruma syntax). In fact, the value
      -ESC_g is returned only for these cases. So we don't need to check for <
      or ' if the value is -ESC_g. For the Perl syntax \g{n} the value is
      -ESC_REF+n, and for the Perl syntax \g{name} the result is -ESC_k (as
      that is a synonym for a named back reference). */

      if (-c == ESC_g)
        {
        const uschar *p;
        save_hwm = cd->hwm;   /* Normally this is set when '(' is read */
        terminator = (*(++ptr) == '<')? '>' : '\'';

        /* These two statements stop the compiler for warning about possibly
        unset variables caused by the jump to HANDLE_NUMERICAL_RECURSION. In
        fact, because we actually check for a number below, the paths that
        would actually be in error are never taken. */

        skipbytes = 0;
        reset_bracount = FALSE;

        /* Test for a name */

        if (ptr[1] != '+' && ptr[1] != '-')
          {
          BOOL isnumber = TRUE;
          for (p = ptr + 1; *p != 0 && *p != terminator; p++)
            {
            if ((cd->ctypes[*p] & ctype_digit) == 0) isnumber = FALSE;
            if ((cd->ctypes[*p] & ctype_word) == 0) break;
            }
          if (*p != terminator)
            {
            *errorcodeptr = ERR57;
            break;
            }
          if (isnumber)
            {
            ptr++;
            goto HANDLE_NUMERICAL_RECURSION;
            }
          is_recurse = TRUE;
          goto NAMED_REF_OR_RECURSE;
          }

        /* Test a signed number in angle brackets or quotes. */

        p = ptr + 2;
        while ((digitab[*p] & ctype_digit) != 0) p++;
        if (*p != terminator)
          {
          *errorcodeptr = ERR57;
          break;
          }
        ptr++;
        goto HANDLE_NUMERICAL_RECURSION;
        }

      /* \k<name> or \k'name' is a back reference by name (Perl syntax).
      We also support \k{name} (.NET syntax) */

      if (-c == ESC_k && (ptr[1] == '<' || ptr[1] == '\'' || ptr[1] == '{'))
        {
        is_recurse = FALSE;
        terminator = (*(++ptr) == '<')? '>' : (*ptr == '\'')? '\'' : '}';
        goto NAMED_REF_OR_RECURSE;
        }

      /* Back references are handled specially; must disable firstbyte if
      not set to cope with cases like (?=(\w+))\1: which would otherwise set
      ':' later. */

      if (-c >= ESC_REF)
        {
        recno = -c - ESC_REF;

        HANDLE_REFERENCE:    /* Come here from named backref handling */
        if (firstbyte == REQ_UNSET) firstbyte = REQ_NONE;
        previous = code;
        *code++ = OP_REF;
        PUT2INC(code, 0, recno);
        cd->backref_map |= (recno < 32)? (1 << recno) : 1;
        if (recno > cd->top_backref) cd->top_backref = recno;
        }

      /* So are Unicode property matches, if supported. */

#ifdef SUPPORT_UCP
      else if (-c == ESC_P || -c == ESC_p)
        {
        BOOL negated;
        int pdata;
        int ptype = get_ucp(&ptr, &negated, &pdata, errorcodeptr);
        if (ptype < 0) goto FAILED;
        previous = code;
        *code++ = ((-c == ESC_p) != negated)? OP_PROP : OP_NOTPROP;
        *code++ = ptype;
        *code++ = pdata;
        }
#else

      /* If Unicode properties are not supported, \X, \P, and \p are not
      allowed. */

      else if (-c == ESC_X || -c == ESC_P || -c == ESC_p)
        {
        *errorcodeptr = ERR45;
        goto FAILED;
        }
#endif

      /* For the rest (including \X when Unicode properties are supported), we
      can obtain the OP value by negating the escape value. */

      else
        {
        previous = (-c > ESC_b && -c < ESC_Z)? code : NULL;
        *code++ = (uschar)(-c);
        }
      continue;
      }

    /* We have a data character whose value is in c. In UTF-8 mode it may have
    a value > 127. We set its representation in the length/buffer, and then
    handle it as a data character. */

#ifdef SUPPORT_UTF8
    if (utf8 && c > 127)
      mclength = _pcre_ord2utf8(c, mcbuffer);
    else
#endif

     {
     mcbuffer[0] = (uschar)c;
     mclength = 1;
     }
    goto ONE_CHAR;


    /* ===================================================================*/
    /* Handle a literal character. It is guaranteed not to be whitespace or #
    when the extended flag is set. If we are in UTF-8 mode, it may be a
    multi-byte literal character. */

    default:
    NORMAL_CHAR:
    mclength = 1;
    mcbuffer[0] = (uschar)c;

#ifdef SUPPORT_UTF8
    if (utf8 && c >= 0xc0)
      {
      while ((ptr[1] & 0xc0) == 0x80)
        mcbuffer[mclength++] = *(++ptr);
      }
#endif

    /* At this point we have the character's bytes in mcbuffer, and the length
    in mclength. When not in UTF-8 mode, the length is always 1. */

    ONE_CHAR:
    previous = code;
    *code++ = ((options & PCRE_CASELESS) != 0)? OP_CHARNC : OP_CHAR;
    for (c = 0; c < mclength; c++) *code++ = mcbuffer[c];

    /* Remember if \r or \n were seen */

    if (mcbuffer[0] == '\r' || mcbuffer[0] == '\n')
      cd->external_flags |= PCRE_HASCRORLF;

    /* Set the first and required bytes appropriately. If no previous first
    byte, set it from this character, but revert to none on a zero repeat.
    Otherwise, leave the firstbyte value alone, and don't change it on a zero
    repeat. */

    if (firstbyte == REQ_UNSET)
      {
      zerofirstbyte = REQ_NONE;
      zeroreqbyte = reqbyte;

      /* If the character is more than one byte long, we can set firstbyte
      only if it is not to be matched caselessly. */

      if (mclength == 1 || req_caseopt == 0)
        {
        firstbyte = mcbuffer[0] | req_caseopt;
        if (mclength != 1) reqbyte = code[-1] | cd->req_varyopt;
        }
      else firstbyte = reqbyte = REQ_NONE;
      }

    /* firstbyte was previously set; we can set reqbyte only the length is
    1 or the matching is caseful. */

    else
      {
      zerofirstbyte = firstbyte;
      zeroreqbyte = reqbyte;
      if (mclength == 1 || req_caseopt == 0)
        reqbyte = code[-1] | req_caseopt | cd->req_varyopt;
      }

    break;            /* End of literal character handling */
    }
  }                   /* end of big loop */


/* Control never reaches here by falling through, only by a goto for all the
error states. Pass back the position in the pattern so that it can be displayed
to the user for diagnosing the error. */

FAILED:
*ptrptr = ptr;
return FALSE;
}


/*************************************************
*     Compile sequence of alternatives           *
*************************************************/

/* On entry, ptr is pointing past the bracket character, but on return it
points to the closing bracket, or vertical bar, or end of string. The code
variable is pointing at the byte into which the BRA operator has been stored.
If the ims options are changed at the start (for a (?ims: group) or during any
branch, we need to insert an OP_OPT item at the start of every following branch
to ensure they get set correctly at run time, and also pass the new options
into every subsequent branch compile.

This function is used during the pre-compile phase when we are trying to find
out the amount of memory needed, as well as during the real compile phase. The
value of lengthptr distinguishes the two phases.

Arguments:
  options        option bits, including any changes for this subpattern
  oldims         previous settings of ims option bits
  codeptr        -> the address of the current code pointer
  ptrptr         -> the address of the current pattern pointer
  errorcodeptr   -> pointer to error code variable
  lookbehind     TRUE if this is a lookbehind assertion
  reset_bracount TRUE to reset the count for each branch
  skipbytes      skip this many bytes at start (for brackets and OP_COND)
  firstbyteptr   place to put the first required character, or a negative number
  reqbyteptr     place to put the last required character, or a negative number
  bcptr          pointer to the chain of currently open branches
  cd             points to the data block with tables pointers etc.
  lengthptr      NULL during the real compile phase
                 points to length accumulator during pre-compile phase

Returns:         TRUE on success
*/

static BOOL
compile_regex(int options, int oldims, uschar **codeptr, const uschar **ptrptr,
  int *errorcodeptr, BOOL lookbehind, BOOL reset_bracount, int skipbytes,
  int *firstbyteptr, int *reqbyteptr, branch_chain *bcptr, compile_data *cd,
  int *lengthptr)
{
const uschar *ptr = *ptrptr;
uschar *code = *codeptr;
uschar *last_branch = code;
uschar *start_bracket = code;
uschar *reverse_count = NULL;
int firstbyte, reqbyte;
int branchfirstbyte, branchreqbyte;
int length;
int orig_bracount;
int max_bracount;
branch_chain bc;

bc.outer = bcptr;
bc.current = code;

firstbyte = reqbyte = REQ_UNSET;

/* Accumulate the length for use in the pre-compile phase. Start with the
length of the BRA and KET and any extra bytes that are required at the
beginning. We accumulate in a local variable to save frequent testing of
lenthptr for NULL. We cannot do this by looking at the value of code at the
start and end of each alternative, because compiled items are discarded during
the pre-compile phase so that the work space is not exceeded. */

length = 2 + 2*LINK_SIZE + skipbytes;

/* WARNING: If the above line is changed for any reason, you must also change
the code that abstracts option settings at the start of the pattern and makes
them global. It tests the value of length for (2 + 2*LINK_SIZE) in the
pre-compile phase to find out whether anything has yet been compiled or not. */

/* Offset is set zero to mark that this bracket is still open */

PUT(code, 1, 0);
code += 1 + LINK_SIZE + skipbytes;

/* Loop for each alternative branch */

orig_bracount = max_bracount = cd->bracount;
for (;;)
  {
  /* For a (?| group, reset the capturing bracket count so that each branch
  uses the same numbers. */

  if (reset_bracount) cd->bracount = orig_bracount;

  /* Handle a change of ims options at the start of the branch */

  if ((options & PCRE_IMS) != oldims)
    {
    *code++ = OP_OPT;
    *code++ = (uschar)(options & PCRE_IMS);
    length += 2;
    }

  /* Set up dummy OP_REVERSE if lookbehind assertion */

  if (lookbehind)
    {
    *code++ = OP_REVERSE;
    reverse_count = code;
    PUTINC(code, 0, 0);
    length += 1 + LINK_SIZE;
    }

  /* Now compile the branch; in the pre-compile phase its length gets added
  into the length. */

  if (!compile_branch(&options, &code, &ptr, errorcodeptr, &branchfirstbyte,
        &branchreqbyte, &bc, cd, (lengthptr == NULL)? NULL : &length))
    {
    *ptrptr = ptr;
    return FALSE;
    }

  /* Keep the highest bracket count in case (?| was used and some branch
  has fewer than the rest. */

  if (cd->bracount > max_bracount) max_bracount = cd->bracount;

  /* In the real compile phase, there is some post-processing to be done. */

  if (lengthptr == NULL)
    {
    /* If this is the first branch, the firstbyte and reqbyte values for the
    branch become the values for the regex. */

    if (*last_branch != OP_ALT)
      {
      firstbyte = branchfirstbyte;
      reqbyte = branchreqbyte;
      }

    /* If this is not the first branch, the first char and reqbyte have to
    match the values from all the previous branches, except that if the
    previous value for reqbyte didn't have REQ_VARY set, it can still match,
    and we set REQ_VARY for the regex. */

    else
      {
      /* If we previously had a firstbyte, but it doesn't match the new branch,
      we have to abandon the firstbyte for the regex, but if there was
      previously no reqbyte, it takes on the value of the old firstbyte. */

      if (firstbyte >= 0 && firstbyte != branchfirstbyte)
        {
        if (reqbyte < 0) reqbyte = firstbyte;
        firstbyte = REQ_NONE;
        }

      /* If we (now or from before) have no firstbyte, a firstbyte from the
      branch becomes a reqbyte if there isn't a branch reqbyte. */

      if (firstbyte < 0 && branchfirstbyte >= 0 && branchreqbyte < 0)
          branchreqbyte = branchfirstbyte;

      /* Now ensure that the reqbytes match */

      if ((reqbyte & ~REQ_VARY) != (branchreqbyte & ~REQ_VARY))
        reqbyte = REQ_NONE;
      else reqbyte |= branchreqbyte;   /* To "or" REQ_VARY */
      }

    /* If lookbehind, check that this branch matches a fixed-length string, and
    put the length into the OP_REVERSE item. Temporarily mark the end of the
    branch with OP_END. */

    if (lookbehind)
      {
      int fixed_length;
      *code = OP_END;
      fixed_length = find_fixedlength(last_branch, options);
      DPRINTF(("fixed length = %d\n", fixed_length));
      if (fixed_length < 0)
        {
        *errorcodeptr = (fixed_length == -2)? ERR36 : ERR25;
        *ptrptr = ptr;
        return FALSE;
        }
      PUT(reverse_count, 0, fixed_length);
      }
    }

  /* Reached end of expression, either ')' or end of pattern. In the real
  compile phase, go back through the alternative branches and reverse the chain
  of offsets, with the field in the BRA item now becoming an offset to the
  first alternative. If there are no alternatives, it points to the end of the
  group. The length in the terminating ket is always the length of the whole
  bracketed item. If any of the ims options were changed inside the group,
  compile a resetting op-code following, except at the very end of the pattern.
  Return leaving the pointer at the terminating char. */

  if (*ptr != '|')
    {
    if (lengthptr == NULL)
      {
      int branch_length = (int)(code - last_branch);
      do
        {
        int prev_length = GET(last_branch, 1);
        PUT(last_branch, 1, branch_length);
        branch_length = prev_length;
        last_branch -= branch_length;
        }
      while (branch_length > 0);
      }

    /* Fill in the ket */

    *code = OP_KET;
    PUT(code, 1, code - start_bracket);
    code += 1 + LINK_SIZE;

    /* Resetting option if needed */

    if ((options & PCRE_IMS) != oldims && *ptr == ')')
      {
      *code++ = OP_OPT;
      *code++ = (uschar)oldims;
      length += 2;
      }

    /* Retain the highest bracket number, in case resetting was used. */

    cd->bracount = max_bracount;

    /* Set values to pass back */

    *codeptr = code;
    *ptrptr = ptr;
    *firstbyteptr = firstbyte;
    *reqbyteptr = reqbyte;
    if (lengthptr != NULL)
      {
      if (OFLOW_MAX - *lengthptr < length)
        {
        *errorcodeptr = ERR20;
        return FALSE;
        }
      *lengthptr += length;
      }
    return TRUE;
    }

  /* Another branch follows. In the pre-compile phase, we can move the code
  pointer back to where it was for the start of the first branch. (That is,
  pretend that each branch is the only one.)

  In the real compile phase, insert an ALT node. Its length field points back
  to the previous branch while the bracket remains open. At the end the chain
  is reversed. It's done like this so that the start of the bracket has a
  zero offset until it is closed, making it possible to detect recursion. */

  if (lengthptr != NULL)
    {
    code = *codeptr + 1 + LINK_SIZE + skipbytes;
    length += 1 + LINK_SIZE;
    }
  else
    {
    *code = OP_ALT;
    PUT(code, 1, code - last_branch);
    bc.current = last_branch = code;
    code += 1 + LINK_SIZE;
    }

  ptr++;
  }
/* Control never reaches here */
}


/*************************************************
*          Check for anchored expression         *
*************************************************/

/* Try to find out if this is an anchored regular expression. Consider each
alternative branch. If they all start with OP_SOD or OP_CIRC, or with a bracket
all of whose alternatives start with OP_SOD or OP_CIRC (recurse ad lib), then
it's anchored. However, if this is a multiline pattern, then only OP_SOD
counts, since OP_CIRC can match in the middle.

We can also consider a regex to be anchored if OP_SOM starts all its branches.
This is the code for \G, which means "match at start of match position, taking
into account the match offset".

A branch is also implicitly anchored if it starts with .* and DOTALL is set,
because that will try the rest of the pattern at all possible matching points,
so there is no point trying again.... er ....

.... except when the .* appears inside capturing parentheses, and there is a
subsequent back reference to those parentheses. We haven't enough information
to catch that case precisely.

At first, the best we could do was to detect when .* was in capturing brackets
and the highest back reference was greater than or equal to that level.
However, by keeping a bitmap of the first 31 back references, we can catch some
of the more common cases more precisely.

Arguments:
  code           points to start of expression (the bracket)
  options        points to the options setting
  bracket_map    a bitmap of which brackets we are inside while testing; this
                  handles up to substring 31; after that we just have to take
                  the less precise approach
  backref_map    the back reference bitmap

Returns:     TRUE or FALSE
*/

static BOOL
is_anchored(register const uschar *code, int *options, unsigned int bracket_map,
  unsigned int backref_map)
{
do {
   const uschar *scode = first_significant_code(code + _pcre_OP_lengths[*code],
     options, PCRE_MULTILINE, FALSE);
   register int op = *scode;

   /* Non-capturing brackets */

   if (op == OP_BRA)
     {
     if (!is_anchored(scode, options, bracket_map, backref_map)) return FALSE;
     }

   /* Capturing brackets */

   else if (op == OP_CBRA)
     {
     int n = GET2(scode, 1+LINK_SIZE);
     int new_map = bracket_map | ((n < 32)? (1 << n) : 1);
     if (!is_anchored(scode, options, new_map, backref_map)) return FALSE;
     }

   /* Other brackets */

   else if (op == OP_ASSERT || op == OP_ONCE || op == OP_COND)
     {
     if (!is_anchored(scode, options, bracket_map, backref_map)) return FALSE;
     }

   /* .* is not anchored unless DOTALL is set (which generates OP_ALLANY) and
   it isn't in brackets that are or may be referenced. */

   else if ((op == OP_TYPESTAR || op == OP_TYPEMINSTAR ||
             op == OP_TYPEPOSSTAR))
     {
     if (scode[1] != OP_ALLANY || (bracket_map & backref_map) != 0)
       return FALSE;
     }

   /* Check for explicit anchoring */

   else if (op != OP_SOD && op != OP_SOM &&
           ((*options & PCRE_MULTILINE) != 0 || op != OP_CIRC))
     return FALSE;
   code += GET(code, 1);
   }
while (*code == OP_ALT);   /* Loop for each alternative */
return TRUE;
}



/*************************************************
*         Check for starting with ^ or .*        *
*************************************************/

/* This is called to find out if every branch starts with ^ or .* so that
"first char" processing can be done to speed things up in multiline
matching and for non-DOTALL patterns that start with .* (which must start at
the beginning or after \n). As in the case of is_anchored() (see above), we
have to take account of back references to capturing brackets that contain .*
because in that case we can't make the assumption.

Arguments:
  code           points to start of expression (the bracket)
  bracket_map    a bitmap of which brackets we are inside while testing; this
                  handles up to substring 31; after that we just have to take
                  the less precise approach
  backref_map    the back reference bitmap

Returns:         TRUE or FALSE
*/

static BOOL
is_startline(const uschar *code, unsigned int bracket_map,
  unsigned int backref_map)
{
do {
   const uschar *scode = first_significant_code(code + _pcre_OP_lengths[*code],
     NULL, 0, FALSE);
   register int op = *scode;

   /* Non-capturing brackets */

   if (op == OP_BRA)
     {
     if (!is_startline(scode, bracket_map, backref_map)) return FALSE;
     }

   /* Capturing brackets */

   else if (op == OP_CBRA)
     {
     int n = GET2(scode, 1+LINK_SIZE);
     int new_map = bracket_map | ((n < 32)? (1 << n) : 1);
     if (!is_startline(scode, new_map, backref_map)) return FALSE;
     }

   /* Other brackets */

   else if (op == OP_ASSERT || op == OP_ONCE || op == OP_COND)
     { if (!is_startline(scode, bracket_map, backref_map)) return FALSE; }

   /* .* means "start at start or after \n" if it isn't in brackets that
   may be referenced. */

   else if (op == OP_TYPESTAR || op == OP_TYPEMINSTAR || op == OP_TYPEPOSSTAR)
     {
     if (scode[1] != OP_ANY || (bracket_map & backref_map) != 0) return FALSE;
     }

   /* Check for explicit circumflex */

   else if (op != OP_CIRC) return FALSE;

   /* Move on to the next alternative */

   code += GET(code, 1);
   }
while (*code == OP_ALT);  /* Loop for each alternative */
return TRUE;
}



/*************************************************
*       Check for asserted fixed first char      *
*************************************************/

/* During compilation, the "first char" settings from forward assertions are
discarded, because they can cause conflicts with actual literals that follow.
However, if we end up without a first char setting for an unanchored pattern,
it is worth scanning the regex to see if there is an initial asserted first
char. If all branches start with the same asserted char, or with a bracket all
of whose alternatives start with the same asserted char (recurse ad lib), then
we return that char, otherwise -1.

Arguments:
  code       points to start of expression (the bracket)
  options    pointer to the options (used to check casing changes)
  inassert   TRUE if in an assertion

Returns:     -1 or the fixed first char
*/

static int
find_firstassertedchar(const uschar *code, int *options, BOOL inassert)
{
register int c = -1;
do {
   int d;
   const uschar *scode =
     first_significant_code(code + 1+LINK_SIZE, options, PCRE_CASELESS, TRUE);
   register int op = *scode;

   switch(op)
     {
     default:
     return -1;

     case OP_BRA:
     case OP_CBRA:
     case OP_ASSERT:
     case OP_ONCE:
     case OP_COND:
     if ((d = find_firstassertedchar(scode, options, op == OP_ASSERT)) < 0)
       return -1;
     if (c < 0) c = d; else if (c != d) return -1;
     break;

     case OP_EXACT:       /* Fall through */
     scode += 2;

     case OP_CHAR:
     case OP_CHARNC:
     case OP_PLUS:
     case OP_MINPLUS:
     case OP_POSPLUS:
     if (!inassert) return -1;
     if (c < 0)
       {
       c = scode[1];
       if ((*options & PCRE_CASELESS) != 0) c |= REQ_CASELESS;
       }
     else if (c != scode[1]) return -1;
     break;
     }

   code += GET(code, 1);
   }
while (*code == OP_ALT);
return c;
}



/*************************************************
*        Compile a Regular Expression            *
*************************************************/

/* This function takes a string and returns a pointer to a block of store
holding a compiled version of the expression. The original API for this
function had no error code return variable; it is retained for backwards
compatibility. The new function is given a new name.

Arguments:
  pattern       the regular expression
  options       various option bits
  errorcodeptr  pointer to error code variable (pcre_compile2() only)
                  can be NULL if you don't want a code value
  errorptr      pointer to pointer to error text
  erroroffset   ptr offset in pattern where error was detected
  tables        pointer to character tables or NULL

Returns:        pointer to compiled data block, or NULL on error,
                with errorptr and erroroffset set
*/
PCRE_EXP_DEFN pcre *
pcre_compile2(const char *pattern, int options, int *errorcodeptr,
  const char **errorptr, int *erroroffset, const unsigned char *tables);

PCRE_EXP_DEFN pcre *
pcre_compile(const char *pattern, int options, const char **errorptr,
  int *erroroffset, const unsigned char *tables)
{
return pcre_compile2(pattern, options, NULL, errorptr, erroroffset, tables);
}


PCRE_EXP_DEFN pcre *
pcre_compile2(const char *pattern, int options, int *errorcodeptr,
  const char **errorptr, int *erroroffset, const unsigned char *tables)
{
real_pcre *re;
int length = 1;  /* For final END opcode */
int firstbyte, reqbyte, newline;
int errorcode = 0;
int skipatstart = 0;
#ifdef SUPPORT_UTF8
BOOL utf8;
#endif
size_t size;
uschar *code;
const uschar *codestart;
const uschar *ptr;
compile_data compile_block;
compile_data *cd = &compile_block;

/* This space is used for "compiling" into during the first phase, when we are
computing the amount of memory that is needed. Compiled items are thrown away
as soon as possible, so that a fairly large buffer should be sufficient for
this purpose. The same space is used in the second phase for remembering where
to fill in forward references to subpatterns. */

uschar cworkspace[COMPILE_WORK_SIZE];

/* Set this early so that early errors get offset 0. */

ptr = (const uschar *)pattern;

/* We can't pass back an error message if errorptr is NULL; I guess the best we
can do is just return NULL, but we can set a code value if there is a code
pointer. */

if (errorptr == NULL)
  {
  if (errorcodeptr != NULL) *errorcodeptr = 99;
  return NULL;
  }

*errorptr = NULL;
if (errorcodeptr != NULL) *errorcodeptr = ERR0;

/* However, we can give a message for this error */

if (erroroffset == NULL)
  {
  errorcode = ERR16;
  goto PCRE_EARLY_ERROR_RETURN2;
  }

*erroroffset = 0;

/* Can't support UTF8 unless PCRE has been compiled to include the code. */

#ifdef SUPPORT_UTF8
utf8 = (options & PCRE_UTF8) != 0;
if (utf8 && (options & PCRE_NO_UTF8_CHECK) == 0 &&
     (*erroroffset = _pcre_valid_utf8((uschar *)pattern, -1)) >= 0)
  {
  errorcode = ERR44;
  goto PCRE_EARLY_ERROR_RETURN2;
  }
#else
if ((options & PCRE_UTF8) != 0)
  {
  errorcode = ERR32;
  goto PCRE_EARLY_ERROR_RETURN;
  }
#endif

if ((options & ~PUBLIC_OPTIONS) != 0)
  {
  errorcode = ERR17;
  goto PCRE_EARLY_ERROR_RETURN;
  }

/* Set up pointers to the individual character tables */

if (tables == NULL) tables = _pcre_default_tables;
cd->lcc = tables + lcc_offset;
cd->fcc = tables + fcc_offset;
cd->cbits = tables + cbits_offset;
cd->ctypes = tables + ctypes_offset;

/* Check for global one-time settings at the start of the pattern, and remember
the offset for later. */

while (ptr[skipatstart] == '(' && ptr[skipatstart+1] == '*')
  {
  int newnl = 0;
  int newbsr = 0;

  if (strncmp((char *)(ptr+skipatstart+2), "CR)", 3) == 0)
    { skipatstart += 5; newnl = PCRE_NEWLINE_CR; }
  else if (strncmp((char *)(ptr+skipatstart+2), "LF)", 3)  == 0)
    { skipatstart += 5; newnl = PCRE_NEWLINE_LF; }
  else if (strncmp((char *)(ptr+skipatstart+2), "CRLF)", 5)  == 0)
    { skipatstart += 7; newnl = PCRE_NEWLINE_CR + PCRE_NEWLINE_LF; }
  else if (strncmp((char *)(ptr+skipatstart+2), "ANY)", 4) == 0)
    { skipatstart += 6; newnl = PCRE_NEWLINE_ANY; }
  else if (strncmp((char *)(ptr+skipatstart+2), "ANYCRLF)", 8)  == 0)
    { skipatstart += 10; newnl = PCRE_NEWLINE_ANYCRLF; }

  else if (strncmp((char *)(ptr+skipatstart+2), "BSR_ANYCRLF)", 12) == 0)
    { skipatstart += 14; newbsr = PCRE_BSR_ANYCRLF; }
  else if (strncmp((char *)(ptr+skipatstart+2), "BSR_UNICODE)", 12) == 0)
    { skipatstart += 14; newbsr = PCRE_BSR_UNICODE; }

  if (newnl != 0)
    options = (options & ~PCRE_NEWLINE_BITS) | newnl;
  else if (newbsr != 0)
    options = (options & ~(PCRE_BSR_ANYCRLF|PCRE_BSR_UNICODE)) | newbsr;
  else break;
  }

/* Check validity of \R options. */

switch (options & (PCRE_BSR_ANYCRLF|PCRE_BSR_UNICODE))
  {
  case 0:
  case PCRE_BSR_ANYCRLF:
  case PCRE_BSR_UNICODE:
  break;
  default: errorcode = ERR56; goto PCRE_EARLY_ERROR_RETURN;
  }

/* Handle different types of newline. The three bits give seven cases. The
current code allows for fixed one- or two-byte sequences, plus "any" and
"anycrlf". */

switch (options & PCRE_NEWLINE_BITS)
  {
  case 0: newline = NEWLINE; break;   /* Build-time default */
  case PCRE_NEWLINE_CR: newline = '\r'; break;
  case PCRE_NEWLINE_LF: newline = '\n'; break;
  case PCRE_NEWLINE_CR+
       PCRE_NEWLINE_LF: newline = ('\r' << 8) | '\n'; break;
  case PCRE_NEWLINE_ANY: newline = -1; break;
  case PCRE_NEWLINE_ANYCRLF: newline = -2; break;
  default: errorcode = ERR56; goto PCRE_EARLY_ERROR_RETURN;
  }

if (newline == -2)
  {
  cd->nltype = NLTYPE_ANYCRLF;
  }
else if (newline < 0)
  {
  cd->nltype = NLTYPE_ANY;
  }
else
  {
  cd->nltype = NLTYPE_FIXED;
  if (newline > 255)
    {
    cd->nllen = 2;
    cd->nl[0] = (uschar)((newline >> 8) & 255);
    cd->nl[1] = (uschar)(newline & 255);
    }
  else
    {
    cd->nllen = 1;
    cd->nl[0] = (uschar)newline;
    }
  }

/* Maximum back reference and backref bitmap. The bitmap records up to 31 back
references to help in deciding whether (.*) can be treated as anchored or not.
*/

cd->top_backref = 0;
cd->backref_map = 0;

/* Reflect pattern for debugging output */

DPRINTF(("------------------------------------------------------------------\n"));
DPRINTF(("%s\n", pattern));

/* Pretend to compile the pattern while actually just accumulating the length
of memory required. This behaviour is triggered by passing a non-NULL final
argument to compile_regex(). We pass a block of workspace (cworkspace) for it
to compile parts of the pattern into; the compiled code is discarded when it is
no longer needed, so hopefully this workspace will never overflow, though there
is a test for its doing so. */

cd->bracount = cd->final_bracount = 0;
cd->names_found = 0;
cd->name_entry_size = 0;
cd->name_table = NULL;
cd->start_workspace = cworkspace;
cd->start_code = cworkspace;
cd->hwm = cworkspace;
cd->start_pattern = (const uschar *)pattern;
cd->end_pattern = (const uschar *)(pattern + strlen(pattern));
cd->req_varyopt = 0;
cd->external_options = options;
cd->external_flags = 0;

/* Now do the pre-compile. On error, errorcode will be set non-zero, so we
don't need to look at the result of the function here. The initial options have
been put into the cd block so that they can be changed if an option setting is
found within the regex right at the beginning. Bringing initial option settings
outside can help speed up starting point checks. */

ptr += skipatstart;
code = cworkspace;
*code = OP_BRA;
(void)compile_regex(cd->external_options, cd->external_options & PCRE_IMS,
  &code, &ptr, &errorcode, FALSE, FALSE, 0, &firstbyte, &reqbyte, NULL, cd,
  &length);
if (errorcode != 0) goto PCRE_EARLY_ERROR_RETURN;

DPRINTF(("end pre-compile: length=%d workspace=%d\n", length,
  cd->hwm - cworkspace));

if (length > MAX_PATTERN_SIZE)
  {
  errorcode = ERR20;
  goto PCRE_EARLY_ERROR_RETURN;
  }

/* Compute the size of data block needed and get it, either from malloc or
externally provided function. Integer overflow should no longer be possible
because nowadays we limit the maximum value of cd->names_found and
cd->name_entry_size. */

size = length + sizeof(real_pcre) + cd->names_found * (cd->name_entry_size + 3);
re = (real_pcre *)(pcre_malloc)(size);

if (re == NULL)
  {
  errorcode = ERR21;
  goto PCRE_EARLY_ERROR_RETURN;
  }

/* Put in the magic number, and save the sizes, initial options, internal
flags, and character table pointer. NULL is used for the default character
tables. The nullpad field is at the end; it's there to help in the case when a
regex compiled on a system with 4-byte pointers is run on another with 8-byte
pointers. */

re->magic_number = MAGIC_NUMBER;
re->size = (pcre_uint16)(size);
re->options = (pcre_uint16)(cd->external_options);
re->flags = (pcre_uint16)(cd->external_flags);
re->dummy1 = 0;
re->first_byte = 0;
re->req_byte = 0;
re->name_table_offset = (pcre_uint16)(sizeof(real_pcre));
re->name_entry_size = (pcre_uint16)(cd->name_entry_size);
re->name_count = (pcre_uint16)(cd->names_found);
re->ref_count = 0;
re->tables = (tables == _pcre_default_tables)? NULL : tables;
re->nullpad = NULL;

/* The starting points of the name/number translation table and of the code are
passed around in the compile data block. The start/end pattern and initial
options are already set from the pre-compile phase, as is the name_entry_size
field. Reset the bracket count and the names_found field. Also reset the hwm
field; this time it's used for remembering forward references to subpatterns.
*/

cd->final_bracount = cd->bracount;  /* Save for checking forward references */
cd->bracount = 0;
cd->names_found = 0;
cd->name_table = (uschar *)re + re->name_table_offset;
codestart = cd->name_table + re->name_entry_size * re->name_count;
cd->start_code = codestart;
cd->hwm = cworkspace;
cd->req_varyopt = 0;
cd->had_accept = FALSE;

/* Set up a starting, non-extracting bracket, then compile the expression. On
error, errorcode will be set non-zero, so we don't need to look at the result
of the function here. */

ptr = (const uschar *)pattern + skipatstart;
code = (uschar *)codestart;
*code = OP_BRA;
(void)compile_regex(re->options, re->options & PCRE_IMS, &code, &ptr,
  &errorcode, FALSE, FALSE, 0, &firstbyte, &reqbyte, NULL, cd, NULL);
re->top_bracket = (pcre_uint16)(cd->bracount);
re->top_backref = (pcre_uint16)(cd->top_backref);
re->flags = (pcre_uint16)(cd->external_flags);

if (cd->had_accept) reqbyte = -1;   /* Must disable after (*ACCEPT) */

/* If not reached end of pattern on success, there's an excess bracket. */

if (errorcode == 0 && *ptr != 0) errorcode = ERR22;

/* Fill in the terminating state and check for disastrous overflow, but
if debugging, leave the test till after things are printed out. */

*code++ = OP_END;

#ifndef DEBUG
if (code - codestart > length) errorcode = ERR23;
#endif

/* Fill in any forward references that are required. */

while (errorcode == 0 && cd->hwm > cworkspace)
  {
  int offset, recno;
  const uschar *groupptr;
  cd->hwm -= LINK_SIZE;
  offset = GET(cd->hwm, 0);
  recno = GET(codestart, offset);
  groupptr = find_bracket(codestart, (re->options & PCRE_UTF8) != 0, recno);
  if (groupptr == NULL) errorcode = ERR53;
    else PUT(((uschar *)codestart), offset, groupptr - codestart);
  }

/* Give an error if there's back reference to a non-existent capturing
subpattern. */

if (errorcode == 0 && re->top_backref > re->top_bracket) errorcode = ERR15;

/* Failed to compile, or error while post-processing */

if (errorcode != 0)
  {
  (pcre_free)(re);
  PCRE_EARLY_ERROR_RETURN:
  *erroroffset = (int)(ptr - (const uschar *)pattern);
  PCRE_EARLY_ERROR_RETURN2:
  *errorptr = find_error_text(errorcode);
  if (errorcodeptr != NULL) *errorcodeptr = errorcode;
  return NULL;
  }

/* If the anchored option was not passed, set the flag if we can determine that
the pattern is anchored by virtue of ^ characters or \A or anything else (such
as starting with .* when DOTALL is set).

Otherwise, if we know what the first byte has to be, save it, because that
speeds up unanchored matches no end. If not, see if we can set the
PCRE_STARTLINE flag. This is helpful for multiline matches when all branches
start with ^. and also when all branches start with .* for non-DOTALL matches.
*/

if ((re->options & PCRE_ANCHORED) == 0)
  {
  int temp_options = re->options;   /* May get changed during these scans */
  if (is_anchored(codestart, &temp_options, 0, cd->backref_map))
    re->options |= PCRE_ANCHORED;
  else
    {
    if (firstbyte < 0)
      firstbyte = find_firstassertedchar(codestart, &temp_options, FALSE);
    if (firstbyte >= 0)   /* Remove caseless flag for non-caseable chars */
      {
      int ch = firstbyte & 255;
      re->first_byte = ((firstbyte & REQ_CASELESS) != 0 &&
         cd->fcc[ch] == ch)? (pcre_uint16)(ch) : (pcre_uint16)(firstbyte);
      re->flags |= PCRE_FIRSTSET;
      }
    else if (is_startline(codestart, 0, cd->backref_map))
      re->flags |= PCRE_STARTLINE;
    }
  }

/* For an anchored pattern, we use the "required byte" only if it follows a
variable length item in the regex. Remove the caseless flag for non-caseable
bytes. */

if (reqbyte >= 0 &&
     ((re->options & PCRE_ANCHORED) == 0 || (reqbyte & REQ_VARY) != 0))
  {
  int ch = reqbyte & 255;
  re->req_byte = ((reqbyte & REQ_CASELESS) != 0 &&
    cd->fcc[ch] == ch)? (pcre_uint16)((reqbyte & ~REQ_CASELESS)) : (pcre_uint16)(reqbyte);
  re->flags |= PCRE_REQCHSET;
  }

/* Print out the compiled data if debugging is enabled. This is never the
case when building a production library. */

#ifdef DEBUG

printf("Length = %d top_bracket = %d top_backref = %d\n",
  length, re->top_bracket, re->top_backref);

printf("Options=%08x\n", re->options);

if ((re->flags & PCRE_FIRSTSET) != 0)
  {
  int ch = re->first_byte & 255;
  const char *caseless = ((re->first_byte & REQ_CASELESS) == 0)?
    "" : " (caseless)";
  if (isprint(ch)) printf("First char = %c%s\n", ch, caseless);
    else printf("First char = \\x%02x%s\n", ch, caseless);
  }

if ((re->flags & PCRE_REQCHSET) != 0)
  {
  int ch = re->req_byte & 255;
  const char *caseless = ((re->req_byte & REQ_CASELESS) == 0)?
    "" : " (caseless)";
  if (isprint(ch)) printf("Req char = %c%s\n", ch, caseless);
    else printf("Req char = \\x%02x%s\n", ch, caseless);
  }

pcre_printint(re, stdout, TRUE);

/* This check is done here in the debugging case so that the code that
was compiled can be seen. */

if (code - codestart > length)
  {
  (pcre_free)(re);
  *errorptr = find_error_text(ERR23);
  *erroroffset = ptr - (uschar *)pattern;
  if (errorcodeptr != NULL) *errorcodeptr = ERR23;
  return NULL;
  }
#endif   /* DEBUG */

return (pcre *)re;
}


#ifdef DEBUG
/*************************************************
*        Debugging function to print chars       *
*************************************************/

/* Print a sequence of chars in printable format, stopping at the end of the
subject if the requested.

Arguments:
  p           points to characters
  length      number to print
  is_subject  TRUE if printing from within md->start_subject
  md          pointer to matching data block, if is_subject is TRUE

Returns:     nothing
*/

static void
pchars(const uschar *p, int length, BOOL is_subject, match_data *md)
{
unsigned int c;
if (is_subject && length > md->end_subject - p) length = md->end_subject - p;
while (length-- > 0)
  if (isprint(c = *(p++))) printf("%c", c); else printf("\\x%02x", c);
}
#endif


/*************************************************
*          Match a back-reference                *
*************************************************/

/* If a back reference hasn't been set, the length that is passed is greater
than the number of characters left in the string, so the match fails.

Arguments:
  offset      index into the offset vector
  eptr        points into the subject
  length      length to be matched
  md          points to match data block
  ims         the ims flags

Returns:      TRUE if matched
*/

static BOOL
match_ref(int offset, register USPTR eptr, int length, match_data *md,
  unsigned long int ims)
{
USPTR p = md->start_subject + md->offset_vector[offset];

#ifdef DEBUG
if (eptr >= md->end_subject)
  printf("matching subject <null>");
else
  {
  printf("matching subject ");
  pchars(eptr, length, TRUE, md);
  }
printf(" against backref ");
pchars(p, length, FALSE, md);
printf("\n");
#endif

/* Always fail if not enough characters left */

if (length > md->end_subject - eptr) return FALSE;

/* Separate the caseless case for speed. In UTF-8 mode we can only do this
properly if Unicode properties are supported. Otherwise, we can check only
ASCII characters. */

if ((ims & PCRE_CASELESS) != 0)
  {
#ifdef SUPPORT_UTF8
#ifdef SUPPORT_UCP
  if (md->utf8)
    {
    USPTR endptr = eptr + length;
    while (eptr < endptr)
      {
      int c, d;
      GETCHARINC(c, eptr);
      GETCHARINC(d, p);
      if (c != d && c != UCD_OTHERCASE(d)) return FALSE;
      }
    }
  else
#endif
#endif

  /* The same code works when not in UTF-8 mode and in UTF-8 mode when there
  is no UCP support. */

  while (length-- > 0)
    { if (md->lcc[*p++] != md->lcc[*eptr++]) return FALSE; }
  }

/* In the caseful case, we can just compare the bytes, whether or not we
are in UTF-8 mode. */

else
  { while (length-- > 0) if (*p++ != *eptr++) return FALSE; }

return TRUE;
}

/*************************************************
*         Match from current position            *
*************************************************/

/* This function is called recursively in many circumstances. Whenever it
returns a negative (error) response, the outer incarnation must also return the
same response.

Performance note: It might be tempting to extract commonly used fields from the
md structure (e.g. utf8, end_subject) into individual variables to improve
performance. Tests using gcc on a SPARC disproved this; in the first case, it
made performance worse.

Arguments:
   eptr        pointer to current character in subject
   ecode       pointer to current position in compiled code
   mstart      pointer to the current match start position (can be modified
                 by encountering \K)
   offset_top  current top pointer
   md          pointer to "static" info for the match
   ims         current /i, /m, and /s options
   eptrb       pointer to chain of blocks containing eptr at start of
                 brackets - for testing for empty matches
   flags       can contain
                 match_condassert - this is an assertion condition
                 match_cbegroup - this is the start of an unlimited repeat
                   group that can match an empty string
   rdepth      the recursion depth

Returns:       MATCH_MATCH if matched            )  these values are >= 0
               MATCH_NOMATCH if failed to match  )
               a negative PCRE_ERROR_xxx value if aborted by an error condition
                 (e.g. stopped by repeated call or recursion limit)
*/

static int
match(REGISTER USPTR eptr, REGISTER const uschar *ecode, const uschar *mstart,
  int offset_top, match_data *md, unsigned long int ims, eptrblock *eptrb,
  int flags, unsigned int rdepth)
{
/* These variables do not need to be preserved over recursion in this function,
so they can be ordinary variables in all cases. Mark some of them with
"register" because they are used a lot in loops. */

register int  rrc;         /* Returns from recursive calls */
register int  i;           /* Used for loops not involving calls to RMATCH() */
register unsigned int c;   /* Character values not kept over RMATCH() calls */
register BOOL utf8;        /* Local copy of UTF-8 flag for speed */

BOOL minimize, possessive; /* Quantifier options */

/* MJ added here */
#ifdef NLBLOCK
#   undef NLBLOCK
#   undef PSSTART
#   undef PSEND
#endif

#define NLBLOCK md             /* Block containing newline information */
#define PSSTART start_subject  /* Field containing processed string start */
#define PSEND   end_subject    /* Field containing processed string end */
/* end of MJ */


/* When recursion is not being used, all "local" variables that have to be
preserved over calls to RMATCH() are part of a "frame" which is obtained from
heap storage. Set up the top-level frame here; others are obtained from the
heap whenever RMATCH() does a "recursion". See the macro definitions above. */

#ifdef NO_RECURSE
heapframe *frame = (pcre_stack_malloc)(sizeof(heapframe));
frame->Xprevframe = NULL;            /* Marks the top level */

/* Copy in the original argument variables */

frame->Xeptr = eptr;
frame->Xecode = ecode;
frame->Xmstart = mstart;
frame->Xoffset_top = offset_top;
frame->Xims = ims;
frame->Xeptrb = eptrb;
frame->Xflags = flags;
frame->Xrdepth = rdepth;

/* This is where control jumps back to to effect "recursion" */

HEAP_RECURSE:

/* Macros make the argument variables come from the current frame */

#define eptr               frame->Xeptr
#define ecode              frame->Xecode
#define mstart             frame->Xmstart
#define offset_top         frame->Xoffset_top
#define ims                frame->Xims
#define eptrb              frame->Xeptrb
#define flags              frame->Xflags
#define rdepth             frame->Xrdepth

/* Ditto for the local variables */

#ifdef SUPPORT_UTF8
#define charptr            frame->Xcharptr
#endif
#define callpat            frame->Xcallpat
#define data               frame->Xdata
#define next               frame->Xnext
#define pp                 frame->Xpp
#define prev               frame->Xprev
#define saved_eptr         frame->Xsaved_eptr

#define new_recursive      frame->Xnew_recursive

#define cur_is_word        frame->Xcur_is_word
#define condition          frame->Xcondition
#define prev_is_word       frame->Xprev_is_word

#define original_ims       frame->Xoriginal_ims

#ifdef SUPPORT_UCP
#define prop_type          frame->Xprop_type
#define prop_value         frame->Xprop_value
#define prop_fail_result   frame->Xprop_fail_result
#define prop_category      frame->Xprop_category
#define prop_chartype      frame->Xprop_chartype
#define prop_script        frame->Xprop_script
#define oclength           frame->Xoclength
#define occhars            frame->Xocchars
#endif

#define ctype              frame->Xctype
#define fc                 frame->Xfc
#define fi                 frame->Xfi
#define length             frame->Xlength
#define max                frame->Xmax
#define min                frame->Xmin
#define number             frame->Xnumber
#define offset             frame->Xoffset
#define op                 frame->Xop
#define save_capture_last  frame->Xsave_capture_last
#define save_offset1       frame->Xsave_offset1
#define save_offset2       frame->Xsave_offset2
#define save_offset3       frame->Xsave_offset3
#define stacksave          frame->Xstacksave

#define newptrb            frame->Xnewptrb

/* When recursion is being used, local variables are allocated on the stack and
get preserved during recursion in the normal way. In this environment, fi and
i, and fc and c, can be the same variables. */

#else         /* NO_RECURSE not defined */
#define fi i
#define fc c


#ifdef SUPPORT_UTF8                /* Many of these variables are used only  */
const uschar *charptr;             /* in small blocks of the code. My normal */
#endif                             /* style of coding would have declared    */
const uschar *callpat;             /* them within each of those blocks.      */
const uschar *data;                /* However, in order to accommodate the   */
const uschar *next;                /* version of this code that uses an      */
USPTR         pp;                  /* external "stack" implemented on the    */
const uschar *prev;                /* heap, it is easier to declare them all */
USPTR         saved_eptr;          /* here, so the declarations can be cut   */
                                   /* out in a block. The only declarations  */
recursion_info new_recursive;      /* within blocks below are for variables  */
                                   /* that do not have to be preserved over  */
BOOL cur_is_word;                  /* a recursive call to RMATCH().          */
BOOL condition;
BOOL prev_is_word;

unsigned long int original_ims;

#ifdef SUPPORT_UCP
int prop_type;
int prop_value;
int prop_fail_result;
int prop_category;
int prop_chartype;
int prop_script;
int oclength;
uschar occhars[8];
#endif

int ctype;
int length;
int max;
int min;
int number;
int offset;
int op;
int save_capture_last;
int save_offset1, save_offset2, save_offset3;
int stacksave[REC_STACK_SAVE_MAX];

eptrblock newptrb;
#endif     /* NO_RECURSE */

/* These statements are here to stop the compiler complaining about unitialized
variables. */

#ifdef SUPPORT_UCP
prop_value = 0;
prop_fail_result = 0;
#endif


/* This label is used for tail recursion, which is used in a few cases even
when NO_RECURSE is not defined, in order to reduce the amount of stack that is
used. Thanks to Ian Taylor for noticing this possibility and sending the
original patch. */

TAIL_RECURSE:

/* OK, now we can get on with the real code of the function. Recursive calls
are specified by the macro RMATCH and RRETURN is used to return. When
NO_RECURSE is *not* defined, these just turn into a recursive call to match()
and a "return", respectively (possibly with some debugging if DEBUG is
defined). However, RMATCH isn't like a function call because it's quite a
complicated macro. It has to be used in one particular way. This shouldn't,
however, impact performance when true recursion is being used. */

#ifdef SUPPORT_UTF8
utf8 = md->utf8;       /* Local copy of the flag */
#else
utf8 = FALSE;
#endif

/* First check that we haven't called match() too many times, or that we
haven't exceeded the recursive call limit. */

if (md->match_call_count++ >= md->match_limit) RRETURN(PCRE_ERROR_MATCHLIMIT);
if (rdepth >= md->match_limit_recursion) RRETURN(PCRE_ERROR_RECURSIONLIMIT);

original_ims = ims;    /* Save for resetting on ')' */

/* At the start of a group with an unlimited repeat that may match an empty
string, the match_cbegroup flag is set. When this is the case, add the current
subject pointer to the chain of such remembered pointers, to be checked when we
hit the closing ket, in order to break infinite loops that match no characters.
When match() is called in other circumstances, don't add to the chain. The
match_cbegroup flag must NOT be used with tail recursion, because the memory
block that is used is on the stack, so a new one may be required for each
match(). */

if ((flags & match_cbegroup) != 0)
  {
  newptrb.epb_saved_eptr = eptr;
  newptrb.epb_prev = eptrb;
  eptrb = &newptrb;
  }

/* Now start processing the opcodes. */

for (;;)
  {
  minimize = possessive = FALSE;
  op = *ecode;

  /* For partial matching, remember if we ever hit the end of the subject after
  matching at least one subject character. */

  if (md->partial &&
      eptr >= md->end_subject &&
      eptr > mstart)
    md->hitend = TRUE;

  switch(op)
    {
    case OP_FAIL:
    RRETURN(MATCH_NOMATCH);

    case OP_PRUNE:
    RMATCH(eptr, ecode + _pcre_OP_lengths[*ecode], offset_top, md,
      ims, eptrb, flags, RM51);
    if (rrc != MATCH_NOMATCH) RRETURN(rrc);
    RRETURN(MATCH_PRUNE);

    case OP_COMMIT:
    RMATCH(eptr, ecode + _pcre_OP_lengths[*ecode], offset_top, md,
      ims, eptrb, flags, RM52);
    if (rrc != MATCH_NOMATCH) RRETURN(rrc);
    RRETURN(MATCH_COMMIT);

    case OP_SKIP:
    RMATCH(eptr, ecode + _pcre_OP_lengths[*ecode], offset_top, md,
      ims, eptrb, flags, RM53);
    if (rrc != MATCH_NOMATCH) RRETURN(rrc);
    md->start_match_ptr = eptr;   /* Pass back current position */
    RRETURN(MATCH_SKIP);

    case OP_THEN:
    RMATCH(eptr, ecode + _pcre_OP_lengths[*ecode], offset_top, md,
      ims, eptrb, flags, RM54);
    if (rrc != MATCH_NOMATCH) RRETURN(rrc);
    RRETURN(MATCH_THEN);

    /* Handle a capturing bracket. If there is space in the offset vector, save
    the current subject position in the working slot at the top of the vector.
    We mustn't change the current values of the data slot, because they may be
    set from a previous iteration of this group, and be referred to by a
    reference inside the group.

    If the bracket fails to match, we need to restore this value and also the
    values of the final offsets, in case they were set by a previous iteration
    of the same bracket.

    If there isn't enough space in the offset vector, treat this as if it were
    a non-capturing bracket. Don't worry about setting the flag for the error
    case here; that is handled in the code for KET. */

    case OP_CBRA:
    case OP_SCBRA:
    number = GET2(ecode, 1+LINK_SIZE);
    offset = number << 1;

#ifdef DEBUG
    printf("start bracket %d\n", number);
    printf("subject=");
    pchars(eptr, 16, TRUE, md);
    printf("\n");
#endif

    if (offset < md->offset_max)
      {
      save_offset1 = md->offset_vector[offset];
      save_offset2 = md->offset_vector[offset+1];
      save_offset3 = md->offset_vector[md->offset_end - number];
      save_capture_last = md->capture_last;

      DPRINTF(("saving %d %d %d\n", save_offset1, save_offset2, save_offset3));
      md->offset_vector[md->offset_end - number] = (int)(eptr - md->start_subject);

      flags = (op == OP_SCBRA)? match_cbegroup : 0;
      do
        {
        RMATCH(eptr, ecode + _pcre_OP_lengths[*ecode], offset_top, md,
          ims, eptrb, flags, RM1);
        if (rrc != MATCH_NOMATCH && rrc != MATCH_THEN) RRETURN(rrc);
        md->capture_last = save_capture_last;
        ecode += GET(ecode, 1);
        }
      while (*ecode == OP_ALT);

      DPRINTF(("bracket %d failed\n", number));

      md->offset_vector[offset] = save_offset1;
      md->offset_vector[offset+1] = save_offset2;
      md->offset_vector[md->offset_end - number] = save_offset3;

      RRETURN(MATCH_NOMATCH);
      }

    /* FALL THROUGH ... Insufficient room for saving captured contents. Treat
    as a non-capturing bracket. */

    /* VVVVVVVVVVVVVVVVVVVVVVVVV */
    /* VVVVVVVVVVVVVVVVVVVVVVVVV */

    DPRINTF(("insufficient capture room: treat as non-capturing\n"));

    /* VVVVVVVVVVVVVVVVVVVVVVVVV */
    /* VVVVVVVVVVVVVVVVVVVVVVVVV */

    /* Non-capturing bracket. Loop for all the alternatives. When we get to the
    final alternative within the brackets, we would return the result of a
    recursive call to match() whatever happened. We can reduce stack usage by
    turning this into a tail recursion, except in the case when match_cbegroup
    is set.*/

    case OP_BRA:
    case OP_SBRA:
    DPRINTF(("start non-capturing bracket\n"));
    flags = (op >= OP_SBRA)? match_cbegroup : 0;
    for (;;)
      {
      if (ecode[GET(ecode, 1)] != OP_ALT)   /* Final alternative */
        {
        if (flags == 0)    /* Not a possibly empty group */
          {
          ecode += _pcre_OP_lengths[*ecode];
          DPRINTF(("bracket 0 tail recursion\n"));
          goto TAIL_RECURSE;
          }

        /* Possibly empty group; can't use tail recursion. */

        RMATCH(eptr, ecode + _pcre_OP_lengths[*ecode], offset_top, md, ims,
          eptrb, flags, RM48);
        RRETURN(rrc);
        }

      /* For non-final alternatives, continue the loop for a NOMATCH result;
      otherwise return. */

      RMATCH(eptr, ecode + _pcre_OP_lengths[*ecode], offset_top, md, ims,
        eptrb, flags, RM2);
      if (rrc != MATCH_NOMATCH && rrc != MATCH_THEN) RRETURN(rrc);
      ecode += GET(ecode, 1);
      }
    /* Control never reaches here. */

    /* Conditional group: compilation checked that there are no more than
    two branches. If the condition is false, skipping the first branch takes us
    past the end if there is only one branch, but that's OK because that is
    exactly what going to the ket would do. As there is only one branch to be
    obeyed, we can use tail recursion to avoid using another stack frame. */

    case OP_COND:
    case OP_SCOND:
    if (ecode[LINK_SIZE+1] == OP_RREF)         /* Recursion test */
      {
      offset = GET2(ecode, LINK_SIZE + 2);     /* Recursion group number*/
      condition = md->recursive != NULL &&
        (offset == RREF_ANY || offset == md->recursive->group_num);
      ecode += condition? 3 : GET(ecode, 1);
      }

    else if (ecode[LINK_SIZE+1] == OP_CREF)    /* Group used test */
      {
      offset = GET2(ecode, LINK_SIZE+2) << 1;  /* Doubled ref number */
      condition = offset < offset_top && md->offset_vector[offset] >= 0;
      ecode += condition? 3 : GET(ecode, 1);
      }

    else if (ecode[LINK_SIZE+1] == OP_DEF)     /* DEFINE - always false */
      {
      condition = FALSE;
      ecode += GET(ecode, 1);
      }

    /* The condition is an assertion. Call match() to evaluate it - setting
    the final argument match_condassert causes it to stop at the end of an
    assertion. */

    else
      {
      RMATCH(eptr, ecode + 1 + LINK_SIZE, offset_top, md, ims, NULL,
          match_condassert, RM3);
      if (rrc == MATCH_MATCH)
        {
        condition = TRUE;
        ecode += 1 + LINK_SIZE + GET(ecode, LINK_SIZE + 2);
        while (*ecode == OP_ALT) ecode += GET(ecode, 1);
        }
      else if (rrc != MATCH_NOMATCH && rrc != MATCH_THEN)
        {
        RRETURN(rrc);         /* Need braces because of following else */
        }
      else
        {
        condition = FALSE;
        ecode += GET(ecode, 1);
        }
      }

    /* We are now at the branch that is to be obeyed. As there is only one,
    we can use tail recursion to avoid using another stack frame, except when
    match_cbegroup is required for an unlimited repeat of a possibly empty
    group. If the second alternative doesn't exist, we can just plough on. */

    if (condition || *ecode == OP_ALT)
      {
      ecode += 1 + LINK_SIZE;
      if (op == OP_SCOND)        /* Possibly empty group */
        {
        RMATCH(eptr, ecode, offset_top, md, ims, eptrb, match_cbegroup, RM49);
        RRETURN(rrc);
        }
      else                       /* Group must match something */
        {
        flags = 0;
        goto TAIL_RECURSE;
        }
      }
    else                         /* Condition false & no 2nd alternative */
      {
      ecode += 1 + LINK_SIZE;
      }
    break;


    /* End of the pattern, either real or forced. If we are in a top-level
    recursion, we should restore the offsets appropriately and continue from
    after the call. */

    case OP_ACCEPT:
    case OP_END:
    if (md->recursive != NULL && md->recursive->group_num == 0)
      {
      recursion_info *rec = md->recursive;
      DPRINTF(("End of pattern in a (?0) recursion\n"));
      md->recursive = rec->prevrec;
      memmove(md->offset_vector, rec->offset_save,
        rec->saved_max * sizeof(int));
      mstart = rec->save_start;
      ims = original_ims;
      ecode = rec->after_call;
      break;
      }

    /* Otherwise, if PCRE_NOTEMPTY is set, fail if we have matched an empty
    string - backtracking will then try other alternatives, if any. */

    if (md->notempty && eptr == mstart) RRETURN(MATCH_NOMATCH);
    md->end_match_ptr = eptr;           /* Record where we ended */
    md->end_offset_top = offset_top;    /* and how many extracts were taken */
    md->start_match_ptr = mstart;       /* and the start (\K can modify) */
    RRETURN(MATCH_MATCH);

    /* Change option settings */

    case OP_OPT:
    ims = ecode[1];
    ecode += 2;
    DPRINTF(("ims set to %02lx\n", ims));
    break;

    /* Assertion brackets. Check the alternative branches in turn - the
    matching won't pass the KET for an assertion. If any one branch matches,
    the assertion is true. Lookbehind assertions have an OP_REVERSE item at the
    start of each branch to move the current point backwards, so the code at
    this level is identical to the lookahead case. */

    case OP_ASSERT:
    case OP_ASSERTBACK:
    do
      {
      RMATCH(eptr, ecode + 1 + LINK_SIZE, offset_top, md, ims, NULL, 0,
        RM4);
      if (rrc == MATCH_MATCH) break;
      if (rrc != MATCH_NOMATCH && rrc != MATCH_THEN) RRETURN(rrc);
      ecode += GET(ecode, 1);
      }
    while (*ecode == OP_ALT);
    if (*ecode == OP_KET) RRETURN(MATCH_NOMATCH);

    /* If checking an assertion for a condition, return MATCH_MATCH. */

    if ((flags & match_condassert) != 0) RRETURN(MATCH_MATCH);

    /* Continue from after the assertion, updating the offsets high water
    mark, since extracts may have been taken during the assertion. */

    do ecode += GET(ecode,1); while (*ecode == OP_ALT);
    ecode += 1 + LINK_SIZE;
    offset_top = md->end_offset_top;
    continue;

    /* Negative assertion: all branches must fail to match */

    case OP_ASSERT_NOT:
    case OP_ASSERTBACK_NOT:
    do
      {
      RMATCH(eptr, ecode + 1 + LINK_SIZE, offset_top, md, ims, NULL, 0,
        RM5);
      if (rrc == MATCH_MATCH) RRETURN(MATCH_NOMATCH);
      if (rrc != MATCH_NOMATCH && rrc != MATCH_THEN) RRETURN(rrc);
      ecode += GET(ecode,1);
      }
    while (*ecode == OP_ALT);

    if ((flags & match_condassert) != 0) RRETURN(MATCH_MATCH);

    ecode += 1 + LINK_SIZE;
    continue;

    /* Move the subject pointer back. This occurs only at the start of
    each branch of a lookbehind assertion. If we are too close to the start to
    move back, this match function fails. When working with UTF-8 we move
    back a number of characters, not bytes. */

    case OP_REVERSE:
#ifdef SUPPORT_UTF8
    if (utf8)
      {
      i = GET(ecode, 1);
      while (i-- > 0)
        {
        eptr--;
        if (eptr < md->start_subject) RRETURN(MATCH_NOMATCH);
        BACKCHAR(eptr);
        }
      }
    else
#endif

    /* No UTF-8 support, or not in UTF-8 mode: count is byte count */

      {
      eptr -= GET(ecode, 1);
      if (eptr < md->start_subject) RRETURN(MATCH_NOMATCH);
      }

    /* Skip to next op code */

    ecode += 1 + LINK_SIZE;
    break;

    /* The callout item calls an external function, if one is provided, passing
    details of the match so far. This is mainly for debugging, though the
    function is able to force a failure. */

    case OP_CALLOUT:
    if (pcre_callout != NULL)
      {
      pcre_callout_block cb;
      cb.version          = 1;   /* Version 1 of the callout block */
      cb.callout_number   = ecode[1];
      cb.offset_vector    = md->offset_vector;
      cb.subject          = (PCRE_SPTR)md->start_subject;
      cb.subject_length   = (int)(md->end_subject - md->start_subject);
      cb.start_match      = (int)(mstart - md->start_subject);
      cb.current_position = (int)(eptr - md->start_subject);
      cb.pattern_position = GET(ecode, 2);
      cb.next_item_length = GET(ecode, 2 + LINK_SIZE);
      cb.capture_top      = offset_top/2;
      cb.capture_last     = md->capture_last;
      cb.callout_data     = md->callout_data;
      if ((rrc = (*pcre_callout)(&cb)) > 0) RRETURN(MATCH_NOMATCH);
      if (rrc < 0) RRETURN(rrc);
      }
    ecode += 2 + 2*LINK_SIZE;
    break;

    /* Recursion either matches the current regex, or some subexpression. The
    offset data is the offset to the starting bracket from the start of the
    whole pattern. (This is so that it works from duplicated subpatterns.)

    If there are any capturing brackets started but not finished, we have to
    save their starting points and reinstate them after the recursion. However,
    we don't know how many such there are (offset_top records the completed
    total) so we just have to save all the potential data. There may be up to
    65535 such values, which is too large to put on the stack, but using malloc
    for small numbers seems expensive. As a compromise, the stack is used when
    there are no more than REC_STACK_SAVE_MAX values to store; otherwise malloc
    is used. A problem is what to do if the malloc fails ... there is no way of
    returning to the top level with an error. Save the top REC_STACK_SAVE_MAX
    values on the stack, and accept that the rest may be wrong.

    There are also other values that have to be saved. We use a chained
    sequence of blocks that actually live on the stack. Thanks to Robin Houston
    for the original version of this logic. */

    case OP_RECURSE:
      {
      callpat = md->start_code + GET(ecode, 1);
      new_recursive.group_num = (callpat == md->start_code)? 0 :
        GET2(callpat, 1 + LINK_SIZE);

      /* Add to "recursing stack" */

      new_recursive.prevrec = md->recursive;
      md->recursive = &new_recursive;

      /* Find where to continue from afterwards */

      ecode += 1 + LINK_SIZE;
      new_recursive.after_call = ecode;

      /* Now save the offset data. */

      new_recursive.saved_max = md->offset_end;
      if (new_recursive.saved_max <= REC_STACK_SAVE_MAX)
        new_recursive.offset_save = stacksave;
      else
        {
        new_recursive.offset_save =
          (int *)(pcre_malloc)(new_recursive.saved_max * sizeof(int));
        if (new_recursive.offset_save == NULL) RRETURN(PCRE_ERROR_NOMEMORY);
        }

      memcpy(new_recursive.offset_save, md->offset_vector,
            new_recursive.saved_max * sizeof(int));
      new_recursive.save_start = mstart;
      mstart = eptr;

      /* OK, now we can do the recursion. For each top-level alternative we
      restore the offset and recursion data. */

      DPRINTF(("Recursing into group %d\n", new_recursive.group_num));
      flags = (*callpat >= OP_SBRA)? match_cbegroup : 0;
      do
        {
        RMATCH(eptr, callpat + _pcre_OP_lengths[*callpat], offset_top,
          md, ims, eptrb, flags, RM6);
        if (rrc == MATCH_MATCH)
          {
          DPRINTF(("Recursion matched\n"));
          md->recursive = new_recursive.prevrec;
          if (new_recursive.offset_save != stacksave)
            (pcre_free)(new_recursive.offset_save);
          RRETURN(MATCH_MATCH);
          }
        else if (rrc != MATCH_NOMATCH && rrc != MATCH_THEN)
          {
          DPRINTF(("Recursion gave error %d\n", rrc));
          RRETURN(rrc);
          }

        md->recursive = &new_recursive;
        memcpy(md->offset_vector, new_recursive.offset_save,
            new_recursive.saved_max * sizeof(int));
        callpat += GET(callpat, 1);
        }
      while (*callpat == OP_ALT);

      DPRINTF(("Recursion didn't match\n"));
      md->recursive = new_recursive.prevrec;
      if (new_recursive.offset_save != stacksave)
        (pcre_free)(new_recursive.offset_save);
      RRETURN(MATCH_NOMATCH);
      }
    /* Control never reaches here */

    /* "Once" brackets are like assertion brackets except that after a match,
    the point in the subject string is not moved back. Thus there can never be
    a move back into the brackets. Friedl calls these "atomic" subpatterns.
    Check the alternative branches in turn - the matching won't pass the KET
    for this kind of subpattern. If any one branch matches, we carry on as at
    the end of a normal bracket, leaving the subject pointer. */

    case OP_ONCE:
    prev = ecode;
    saved_eptr = eptr;

    do
      {
      RMATCH(eptr, ecode + 1 + LINK_SIZE, offset_top, md, ims, eptrb, 0, RM7);
      if (rrc == MATCH_MATCH) break;
      if (rrc != MATCH_NOMATCH && rrc != MATCH_THEN) RRETURN(rrc);
      ecode += GET(ecode,1);
      }
    while (*ecode == OP_ALT);

    /* If hit the end of the group (which could be repeated), fail */

    if (*ecode != OP_ONCE && *ecode != OP_ALT) RRETURN(MATCH_NOMATCH);

    /* Continue as from after the assertion, updating the offsets high water
    mark, since extracts may have been taken. */

    do ecode += GET(ecode, 1); while (*ecode == OP_ALT);

    offset_top = md->end_offset_top;
    eptr = md->end_match_ptr;

    /* For a non-repeating ket, just continue at this level. This also
    happens for a repeating ket if no characters were matched in the group.
    This is the forcible breaking of infinite loops as implemented in Perl
    5.005. If there is an options reset, it will get obeyed in the normal
    course of events. */

    if (*ecode == OP_KET || eptr == saved_eptr)
      {
      ecode += 1+LINK_SIZE;
      break;
      }

    /* The repeating kets try the rest of the pattern or restart from the
    preceding bracket, in the appropriate order. The second "call" of match()
    uses tail recursion, to avoid using another stack frame. We need to reset
    any options that changed within the bracket before re-running it, so
    check the next opcode. */

    if (ecode[1+LINK_SIZE] == OP_OPT)
      {
      ims = (ims & ~PCRE_IMS) | ecode[4];
      DPRINTF(("ims set to %02lx at group repeat\n", ims));
      }

    if (*ecode == OP_KETRMIN)
      {
      RMATCH(eptr, ecode + 1 + LINK_SIZE, offset_top, md, ims, eptrb, 0, RM8);
      if (rrc != MATCH_NOMATCH) RRETURN(rrc);
      ecode = prev;
      flags = 0;
      goto TAIL_RECURSE;
      }
    else  /* OP_KETRMAX */
      {
      RMATCH(eptr, prev, offset_top, md, ims, eptrb, match_cbegroup, RM9);
      if (rrc != MATCH_NOMATCH) RRETURN(rrc);
      ecode += 1 + LINK_SIZE;
      flags = 0;
      goto TAIL_RECURSE;
      }
    /* Control never gets here */

    /* An alternation is the end of a branch; scan along to find the end of the
    bracketed group and go to there. */

    case OP_ALT:
    do ecode += GET(ecode,1); while (*ecode == OP_ALT);
    break;

    /* BRAZERO, BRAMINZERO and SKIPZERO occur just before a bracket group,
    indicating that it may occur zero times. It may repeat infinitely, or not
    at all - i.e. it could be ()* or ()? or even (){0} in the pattern. Brackets
    with fixed upper repeat limits are compiled as a number of copies, with the
    optional ones preceded by BRAZERO or BRAMINZERO. */

    case OP_BRAZERO:
      {
      next = ecode+1;
      RMATCH(eptr, next, offset_top, md, ims, eptrb, 0, RM10);
      if (rrc != MATCH_NOMATCH) RRETURN(rrc);
      do next += GET(next,1); while (*next == OP_ALT);
      ecode = next + 1 + LINK_SIZE;
      }
    break;

    case OP_BRAMINZERO:
      {
      next = ecode+1;
      do next += GET(next, 1); while (*next == OP_ALT);
      RMATCH(eptr, next + 1+LINK_SIZE, offset_top, md, ims, eptrb, 0, RM11);
      if (rrc != MATCH_NOMATCH) RRETURN(rrc);
      ecode++;
      }
    break;

    case OP_SKIPZERO:
      {
      next = ecode+1;
      do next += GET(next,1); while (*next == OP_ALT);
      ecode = next + 1 + LINK_SIZE;
      }
    break;

    /* End of a group, repeated or non-repeating. */

    case OP_KET:
    case OP_KETRMIN:
    case OP_KETRMAX:
    prev = ecode - GET(ecode, 1);

    /* If this was a group that remembered the subject start, in order to break
    infinite repeats of empty string matches, retrieve the subject start from
    the chain. Otherwise, set it NULL. */

    if (*prev >= OP_SBRA)
      {
      saved_eptr = eptrb->epb_saved_eptr;   /* Value at start of group */
      eptrb = eptrb->epb_prev;              /* Backup to previous group */
      }
    else saved_eptr = NULL;

    /* If we are at the end of an assertion group, stop matching and return
    MATCH_MATCH, but record the current high water mark for use by positive
    assertions. Do this also for the "once" (atomic) groups. */

    if (*prev == OP_ASSERT || *prev == OP_ASSERT_NOT ||
        *prev == OP_ASSERTBACK || *prev == OP_ASSERTBACK_NOT ||
        *prev == OP_ONCE)
      {
      md->end_match_ptr = eptr;      /* For ONCE */
      md->end_offset_top = offset_top;
      RRETURN(MATCH_MATCH);
      }

    /* For capturing groups we have to check the group number back at the start
    and if necessary complete handling an extraction by setting the offsets and
    bumping the high water mark. Note that whole-pattern recursion is coded as
    a recurse into group 0, so it won't be picked up here. Instead, we catch it
    when the OP_END is reached. Other recursion is handled here. */

    if (*prev == OP_CBRA || *prev == OP_SCBRA)
      {
      number = GET2(prev, 1+LINK_SIZE);
      offset = number << 1;

#ifdef DEBUG
      printf("end bracket %d", number);
      printf("\n");
#endif

      md->capture_last = number;
      if (offset >= md->offset_max) md->offset_overflow = TRUE; else
        {
        md->offset_vector[offset] =
          md->offset_vector[md->offset_end - number];
        md->offset_vector[offset+1] = (int)(eptr - md->start_subject);
        if (offset_top <= offset) offset_top = offset + 2;
        }

      /* Handle a recursively called group. Restore the offsets
      appropriately and continue from after the call. */

      if (md->recursive != NULL && md->recursive->group_num == number)
        {
        recursion_info *rec = md->recursive;
        DPRINTF(("Recursion (%d) succeeded - continuing\n", number));
        md->recursive = rec->prevrec;
        mstart = rec->save_start;
        memcpy(md->offset_vector, rec->offset_save,
          rec->saved_max * sizeof(int));
        ecode = rec->after_call;
        ims = original_ims;
        break;
        }
      }

    /* For both capturing and non-capturing groups, reset the value of the ims
    flags, in case they got changed during the group. */

    ims = original_ims;
    DPRINTF(("ims reset to %02lx\n", ims));

    /* For a non-repeating ket, just continue at this level. This also
    happens for a repeating ket if no characters were matched in the group.
    This is the forcible breaking of infinite loops as implemented in Perl
    5.005. If there is an options reset, it will get obeyed in the normal
    course of events. */

    if (*ecode == OP_KET || eptr == saved_eptr)
      {
      ecode += 1 + LINK_SIZE;
      break;
      }

    /* The repeating kets try the rest of the pattern or restart from the
    preceding bracket, in the appropriate order. In the second case, we can use
    tail recursion to avoid using another stack frame, unless we have an
    unlimited repeat of a group that can match an empty string. */

    flags = (*prev >= OP_SBRA)? match_cbegroup : 0;

    if (*ecode == OP_KETRMIN)
      {
      RMATCH(eptr, ecode + 1 + LINK_SIZE, offset_top, md, ims, eptrb, 0, RM12);
      if (rrc != MATCH_NOMATCH) RRETURN(rrc);
      if (flags != 0)    /* Could match an empty string */
        {
        RMATCH(eptr, prev, offset_top, md, ims, eptrb, flags, RM50);
        RRETURN(rrc);
        }
      ecode = prev;
      goto TAIL_RECURSE;
      }
    else  /* OP_KETRMAX */
      {
      RMATCH(eptr, prev, offset_top, md, ims, eptrb, flags, RM13);
      if (rrc != MATCH_NOMATCH) RRETURN(rrc);
      ecode += 1 + LINK_SIZE;
      flags = 0;
      goto TAIL_RECURSE;
      }
    /* Control never gets here */

    /* Start of subject unless notbol, or after internal newline if multiline */

    case OP_CIRC:
    if (md->notbol && eptr == md->start_subject) RRETURN(MATCH_NOMATCH);
    if ((ims & PCRE_MULTILINE) != 0)
      {
      if (eptr != md->start_subject &&
          (eptr == md->end_subject || !WAS_NEWLINE(eptr)))
        RRETURN(MATCH_NOMATCH);
      ecode++;
      break;
      }
    /* ... else fall through */

    /* Start of subject assertion */

    case OP_SOD:
    if (eptr != md->start_subject) RRETURN(MATCH_NOMATCH);
    ecode++;
    break;

    /* Start of match assertion */

    case OP_SOM:
    if (eptr != md->start_subject + md->start_offset) RRETURN(MATCH_NOMATCH);
    ecode++;
    break;

    /* Reset the start of match point */

    case OP_SET_SOM:
    mstart = eptr;
    ecode++;
    break;

    /* Assert before internal newline if multiline, or before a terminating
    newline unless endonly is set, else end of subject unless noteol is set. */

    case OP_DOLL:
    if ((ims & PCRE_MULTILINE) != 0)
      {
      if (eptr < md->end_subject)
        { if (!IS_NEWLINE(eptr)) RRETURN(MATCH_NOMATCH); }
      else
        { if (md->noteol) RRETURN(MATCH_NOMATCH); }
      ecode++;
      break;
      }
    else
      {
      if (md->noteol) RRETURN(MATCH_NOMATCH);
      if (!md->endonly)
        {
        if (eptr != md->end_subject &&
            (!IS_NEWLINE(eptr) || eptr != md->end_subject - md->nllen))
          RRETURN(MATCH_NOMATCH);
        ecode++;
        break;
        }
      }
    /* ... else fall through for endonly */

    /* End of subject assertion (\z) */

    case OP_EOD:
    if (eptr < md->end_subject) RRETURN(MATCH_NOMATCH);
    ecode++;
    break;

    /* End of subject or ending \n assertion (\Z) */

    case OP_EODN:
    if (eptr != md->end_subject &&
        (!IS_NEWLINE(eptr) || eptr != md->end_subject - md->nllen))
      RRETURN(MATCH_NOMATCH);
    ecode++;
    break;

    /* Word boundary assertions */

    case OP_NOT_WORD_BOUNDARY:
    case OP_WORD_BOUNDARY:
      {

      /* Find out if the previous and current characters are "word" characters.
      It takes a bit more work in UTF-8 mode. Characters > 255 are assumed to
      be "non-word" characters. */

#ifdef SUPPORT_UTF8
      if (utf8)
        {
        if (eptr == md->start_subject) prev_is_word = FALSE; else
          {
          const uschar *lastptr = eptr - 1;
          while((*lastptr & 0xc0) == 0x80) lastptr--;
          GETCHAR(c, lastptr);
          prev_is_word = c < 256 && (md->ctypes[c] & ctype_word) != 0;
          }
        if (eptr >= md->end_subject) cur_is_word = FALSE; else
          {
          GETCHAR(c, eptr);
          cur_is_word = c < 256 && (md->ctypes[c] & ctype_word) != 0;
          }
        }
      else
#endif

      /* More streamlined when not in UTF-8 mode */

        {
        prev_is_word = (eptr != md->start_subject) &&
          ((md->ctypes[eptr[-1]] & ctype_word) != 0);
        cur_is_word = (eptr < md->end_subject) &&
          ((md->ctypes[*eptr] & ctype_word) != 0);
        }

      /* Now see if the situation is what we want */

      if ((*ecode++ == OP_WORD_BOUNDARY)?
           cur_is_word == prev_is_word : cur_is_word != prev_is_word)
        RRETURN(MATCH_NOMATCH);
      }
    break;

    /* Match a single character type; inline for speed */

    case OP_ANY:
    if (IS_NEWLINE(eptr)) RRETURN(MATCH_NOMATCH);
    /* Fall through */

    case OP_ALLANY:
    if (eptr++ >= md->end_subject) RRETURN(MATCH_NOMATCH);
    if (utf8) while (eptr < md->end_subject && (*eptr & 0xc0) == 0x80) eptr++;
    ecode++;
    break;

    /* Match a single byte, even in UTF-8 mode. This opcode really does match
    any byte, even newline, independent of the setting of PCRE_DOTALL. */

    case OP_ANYBYTE:
    if (eptr++ >= md->end_subject) RRETURN(MATCH_NOMATCH);
    ecode++;
    break;

    case OP_NOT_DIGIT:
    if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
    GETCHARINCTEST(c, eptr);
    if (
#ifdef SUPPORT_UTF8
       c < 256 &&
#endif
       (md->ctypes[c] & ctype_digit) != 0
       )
      RRETURN(MATCH_NOMATCH);
    ecode++;
    break;

    case OP_DIGIT:
    if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
    GETCHARINCTEST(c, eptr);
    if (
#ifdef SUPPORT_UTF8
       c >= 256 ||
#endif
       (md->ctypes[c] & ctype_digit) == 0
       )
      RRETURN(MATCH_NOMATCH);
    ecode++;
    break;

    case OP_NOT_WHITESPACE:
    if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
    GETCHARINCTEST(c, eptr);
    if (
#ifdef SUPPORT_UTF8
       c < 256 &&
#endif
       (md->ctypes[c] & ctype_space) != 0
       )
      RRETURN(MATCH_NOMATCH);
    ecode++;
    break;

    case OP_WHITESPACE:
    if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
    GETCHARINCTEST(c, eptr);
    if (
#ifdef SUPPORT_UTF8
       c >= 256 ||
#endif
       (md->ctypes[c] & ctype_space) == 0
       )
      RRETURN(MATCH_NOMATCH);
    ecode++;
    break;

    case OP_NOT_WORDCHAR:
    if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
    GETCHARINCTEST(c, eptr);
    if (
#ifdef SUPPORT_UTF8
       c < 256 &&
#endif
       (md->ctypes[c] & ctype_word) != 0
       )
      RRETURN(MATCH_NOMATCH);
    ecode++;
    break;

    case OP_WORDCHAR:
    if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
    GETCHARINCTEST(c, eptr);
    if (
#ifdef SUPPORT_UTF8
       c >= 256 ||
#endif
       (md->ctypes[c] & ctype_word) == 0
       )
      RRETURN(MATCH_NOMATCH);
    ecode++;
    break;

    case OP_ANYNL:
    if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
    GETCHARINCTEST(c, eptr);
    switch(c)
      {
      default: RRETURN(MATCH_NOMATCH);
      case 0x000d:
      if (eptr < md->end_subject && *eptr == 0x0a) eptr++;
      break;

      case 0x000a:
      break;

      case 0x000b:
      case 0x000c:
      case 0x0085:
      case 0x2028:
      case 0x2029:
      if (md->bsr_anycrlf) RRETURN(MATCH_NOMATCH);
      break;
      }
    ecode++;
    break;

    case OP_NOT_HSPACE:
    if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
    GETCHARINCTEST(c, eptr);
    switch(c)
      {
      default: break;
      case 0x09:      /* HT */
      case 0x20:      /* SPACE */
      case 0xa0:      /* NBSP */
      case 0x1680:    /* OGHAM SPACE MARK */
      case 0x180e:    /* MONGOLIAN VOWEL SEPARATOR */
      case 0x2000:    /* EN QUAD */
      case 0x2001:    /* EM QUAD */
      case 0x2002:    /* EN SPACE */
      case 0x2003:    /* EM SPACE */
      case 0x2004:    /* THREE-PER-EM SPACE */
      case 0x2005:    /* FOUR-PER-EM SPACE */
      case 0x2006:    /* SIX-PER-EM SPACE */
      case 0x2007:    /* FIGURE SPACE */
      case 0x2008:    /* PUNCTUATION SPACE */
      case 0x2009:    /* THIN SPACE */
      case 0x200A:    /* HAIR SPACE */
      case 0x202f:    /* NARROW NO-BREAK SPACE */
      case 0x205f:    /* MEDIUM MATHEMATICAL SPACE */
      case 0x3000:    /* IDEOGRAPHIC SPACE */
      RRETURN(MATCH_NOMATCH);
      }
    ecode++;
    break;

    case OP_HSPACE:
    if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
    GETCHARINCTEST(c, eptr);
    switch(c)
      {
      default: RRETURN(MATCH_NOMATCH);
      case 0x09:      /* HT */
      case 0x20:      /* SPACE */
      case 0xa0:      /* NBSP */
      case 0x1680:    /* OGHAM SPACE MARK */
      case 0x180e:    /* MONGOLIAN VOWEL SEPARATOR */
      case 0x2000:    /* EN QUAD */
      case 0x2001:    /* EM QUAD */
      case 0x2002:    /* EN SPACE */
      case 0x2003:    /* EM SPACE */
      case 0x2004:    /* THREE-PER-EM SPACE */
      case 0x2005:    /* FOUR-PER-EM SPACE */
      case 0x2006:    /* SIX-PER-EM SPACE */
      case 0x2007:    /* FIGURE SPACE */
      case 0x2008:    /* PUNCTUATION SPACE */
      case 0x2009:    /* THIN SPACE */
      case 0x200A:    /* HAIR SPACE */
      case 0x202f:    /* NARROW NO-BREAK SPACE */
      case 0x205f:    /* MEDIUM MATHEMATICAL SPACE */
      case 0x3000:    /* IDEOGRAPHIC SPACE */
      break;
      }
    ecode++;
    break;

    case OP_NOT_VSPACE:
    if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
    GETCHARINCTEST(c, eptr);
    switch(c)
      {
      default: break;
      case 0x0a:      /* LF */
      case 0x0b:      /* VT */
      case 0x0c:      /* FF */
      case 0x0d:      /* CR */
      case 0x85:      /* NEL */
      case 0x2028:    /* LINE SEPARATOR */
      case 0x2029:    /* PARAGRAPH SEPARATOR */
      RRETURN(MATCH_NOMATCH);
      }
    ecode++;
    break;

    case OP_VSPACE:
    if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
    GETCHARINCTEST(c, eptr);
    switch(c)
      {
      default: RRETURN(MATCH_NOMATCH);
      case 0x0a:      /* LF */
      case 0x0b:      /* VT */
      case 0x0c:      /* FF */
      case 0x0d:      /* CR */
      case 0x85:      /* NEL */
      case 0x2028:    /* LINE SEPARATOR */
      case 0x2029:    /* PARAGRAPH SEPARATOR */
      break;
      }
    ecode++;
    break;

#ifdef SUPPORT_UCP
    /* Check the next character by Unicode property. We will get here only
    if the support is in the binary; otherwise a compile-time error occurs. */

    case OP_PROP:
    case OP_NOTPROP:
    if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
    GETCHARINCTEST(c, eptr);
      {
      const ucd_record * prop = GET_UCD(c);

      switch(ecode[1])
        {
        case PT_ANY:
        if (op == OP_NOTPROP) RRETURN(MATCH_NOMATCH);
        break;

        case PT_LAMP:
        if ((prop->chartype == ucp_Lu ||
             prop->chartype == ucp_Ll ||
             prop->chartype == ucp_Lt) == (op == OP_NOTPROP))
          RRETURN(MATCH_NOMATCH);
         break;

        case PT_GC:
        if ((ecode[2] != _pcre_ucp_gentype[prop->chartype]) == (op == OP_PROP))
          RRETURN(MATCH_NOMATCH);
        break;

        case PT_PC:
        if ((ecode[2] != prop->chartype) == (op == OP_PROP))
          RRETURN(MATCH_NOMATCH);
        break;

        case PT_SC:
        if ((ecode[2] != prop->script) == (op == OP_PROP))
          RRETURN(MATCH_NOMATCH);
        break;

        default:
        RRETURN(PCRE_ERROR_INTERNAL);
        }

      ecode += 3;
      }
    break;

    /* Match an extended Unicode sequence. We will get here only if the support
    is in the binary; otherwise a compile-time error occurs. */

    case OP_EXTUNI:
    if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
    GETCHARINCTEST(c, eptr);
      {
      int category = UCD_CATEGORY(c);
      if (category == ucp_M) RRETURN(MATCH_NOMATCH);
      while (eptr < md->end_subject)
        {
        int len = 1;
        if (!utf8) c = *eptr; else
          {
          GETCHARLEN(c, eptr, len);
          }
        category = UCD_CATEGORY(c);
        if (category != ucp_M) break;
        eptr += len;
        }
      }
    ecode++;
    break;
#endif


    /* Match a back reference, possibly repeatedly. Look past the end of the
    item to see if there is repeat information following. The code is similar
    to that for character classes, but repeated for efficiency. Then obey
    similar code to character type repeats - written out again for speed.
    However, if the referenced string is the empty string, always treat
    it as matched, any number of times (otherwise there could be infinite
    loops). */

    case OP_REF:
      {
      offset = GET2(ecode, 1) << 1;               /* Doubled ref number */
      ecode += 3;

      /* If the reference is unset, there are two possibilities:

      (a) In the default, Perl-compatible state, set the length to be longer
      than the amount of subject left; this ensures that every attempt at a
      match fails. We can't just fail here, because of the possibility of
      quantifiers with zero minima.

      (b) If the JavaScript compatibility flag is set, set the length to zero
      so that the back reference matches an empty string.

      Otherwise, set the length to the length of what was matched by the
      referenced subpattern. */

      if (offset >= offset_top || md->offset_vector[offset] < 0)
        length = (md->jscript_compat)? 0 : (int)(md->end_subject - eptr + 1);
      else
        length = md->offset_vector[offset+1] - md->offset_vector[offset];

      /* Set up for repetition, or handle the non-repeated case */

      switch (*ecode)
        {
        case OP_CRSTAR:
        case OP_CRMINSTAR:
        case OP_CRPLUS:
        case OP_CRMINPLUS:
        case OP_CRQUERY:
        case OP_CRMINQUERY:
        c = *ecode++ - OP_CRSTAR;
        minimize = (c & 1) != 0;
        min = rep_min[c];                 /* Pick up values from tables; */
        max = rep_max[c];                 /* zero for max => infinity */
        if (max == 0) max = INT_MAX;
        break;

        case OP_CRRANGE:
        case OP_CRMINRANGE:
        minimize = (*ecode == OP_CRMINRANGE);
        min = GET2(ecode, 1);
        max = GET2(ecode, 3);
        if (max == 0) max = INT_MAX;
        ecode += 5;
        break;

        default:               /* No repeat follows */
        if (!match_ref(offset, eptr, length, md, ims)) RRETURN(MATCH_NOMATCH);
        eptr += length;
        continue;              /* With the main loop */
        }

      /* If the length of the reference is zero, just continue with the
      main loop. */

      if (length == 0) continue;

      /* First, ensure the minimum number of matches are present. We get back
      the length of the reference string explicitly rather than passing the
      address of eptr, so that eptr can be a register variable. */

      for (i = 1; i <= min; i++)
        {
        if (!match_ref(offset, eptr, length, md, ims)) RRETURN(MATCH_NOMATCH);
        eptr += length;
        }

      /* If min = max, continue at the same level without recursion.
      They are not both allowed to be zero. */

      if (min == max) continue;

      /* If minimizing, keep trying and advancing the pointer */

      if (minimize)
        {
        for (fi = min;; fi++)
          {
          RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM14);
          if (rrc != MATCH_NOMATCH) RRETURN(rrc);
          if (fi >= max || !match_ref(offset, eptr, length, md, ims))
            RRETURN(MATCH_NOMATCH);
          eptr += length;
          }
        /* Control never gets here */
        }

      /* If maximizing, find the longest string and work backwards */

      else
        {
        pp = eptr;
        for (i = min; i < max; i++)
          {
          if (!match_ref(offset, eptr, length, md, ims)) break;
          eptr += length;
          }
        while (eptr >= pp)
          {
          RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM15);
          if (rrc != MATCH_NOMATCH) RRETURN(rrc);
          eptr -= length;
          }
        RRETURN(MATCH_NOMATCH);
        }
      }
    /* Control never gets here */



    /* Match a bit-mapped character class, possibly repeatedly. This op code is
    used when all the characters in the class have values in the range 0-255,
    and either the matching is caseful, or the characters are in the range
    0-127 when UTF-8 processing is enabled. The only difference between
    OP_CLASS and OP_NCLASS occurs when a data character outside the range is
    encountered.

    First, look past the end of the item to see if there is repeat information
    following. Then obey similar code to character type repeats - written out
    again for speed. */

    case OP_NCLASS:
    case OP_CLASS:
      {
      data = ecode + 1;                /* Save for matching */
      ecode += 33;                     /* Advance past the item */

      switch (*ecode)
        {
        case OP_CRSTAR:
        case OP_CRMINSTAR:
        case OP_CRPLUS:
        case OP_CRMINPLUS:
        case OP_CRQUERY:
        case OP_CRMINQUERY:
        c = *ecode++ - OP_CRSTAR;
        minimize = (c & 1) != 0;
        min = rep_min[c];                 /* Pick up values from tables; */
        max = rep_max[c];                 /* zero for max => infinity */
        if (max == 0) max = INT_MAX;
        break;

        case OP_CRRANGE:
        case OP_CRMINRANGE:
        minimize = (*ecode == OP_CRMINRANGE);
        min = GET2(ecode, 1);
        max = GET2(ecode, 3);
        if (max == 0) max = INT_MAX;
        ecode += 5;
        break;

        default:               /* No repeat follows */
        min = max = 1;
        break;
        }

      /* First, ensure the minimum number of matches are present. */

#ifdef SUPPORT_UTF8
      /* UTF-8 mode */
      if (utf8)
        {
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
          GETCHARINC(c, eptr);
          if (c > 255)
            {
            if (op == OP_CLASS) RRETURN(MATCH_NOMATCH);
            }
          else
            {
            if ((data[c/8] & (1 << (c&7))) == 0) RRETURN(MATCH_NOMATCH);
            }
          }
        }
      else
#endif
      /* Not UTF-8 mode */
        {
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
          c = *eptr++;
          if ((data[c/8] & (1 << (c&7))) == 0) RRETURN(MATCH_NOMATCH);
          }
        }

      /* If max == min we can continue with the main loop without the
      need to recurse. */

      if (min == max) continue;

      /* If minimizing, keep testing the rest of the expression and advancing
      the pointer while it matches the class. */

      if (minimize)
        {
#ifdef SUPPORT_UTF8
        /* UTF-8 mode */
        if (utf8)
          {
          for (fi = min;; fi++)
            {
            RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM16);
            if (rrc != MATCH_NOMATCH) RRETURN(rrc);
            if (fi >= max || eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
            GETCHARINC(c, eptr);
            if (c > 255)
              {
              if (op == OP_CLASS) RRETURN(MATCH_NOMATCH);
              }
            else
              {
              if ((data[c/8] & (1 << (c&7))) == 0) RRETURN(MATCH_NOMATCH);
              }
            }
          }
        else
#endif
        /* Not UTF-8 mode */
          {
          for (fi = min;; fi++)
            {
            RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM17);
            if (rrc != MATCH_NOMATCH) RRETURN(rrc);
            if (fi >= max || eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
            c = *eptr++;
            if ((data[c/8] & (1 << (c&7))) == 0) RRETURN(MATCH_NOMATCH);
            }
          }
        /* Control never gets here */
        }

      /* If maximizing, find the longest possible run, then work backwards. */

      else
        {
        pp = eptr;

#ifdef SUPPORT_UTF8
        /* UTF-8 mode */
        if (utf8)
          {
          for (i = min; i < max; i++)
            {
            int len = 1;
            if (eptr >= md->end_subject) break;
            GETCHARLEN(c, eptr, len);
            if (c > 255)
              {
              if (op == OP_CLASS) break;
              }
            else
              {
              if ((data[c/8] & (1 << (c&7))) == 0) break;
              }
            eptr += len;
            }
          for (;;)
            {
            RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM18);
            if (rrc != MATCH_NOMATCH) RRETURN(rrc);
            if (eptr-- == pp) break;        /* Stop if tried at original pos */
            BACKCHAR(eptr);
            }
          }
        else
#endif
          /* Not UTF-8 mode */
          {
          for (i = min; i < max; i++)
            {
            if (eptr >= md->end_subject) break;
            c = *eptr;
            if ((data[c/8] & (1 << (c&7))) == 0) break;
            eptr++;
            }
          while (eptr >= pp)
            {
            RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM19);
            if (rrc != MATCH_NOMATCH) RRETURN(rrc);
            eptr--;
            }
          }

        RRETURN(MATCH_NOMATCH);
        }
      }
    /* Control never gets here */


    /* Match an extended character class. This opcode is encountered only
    in UTF-8 mode, because that's the only time it is compiled. */

#ifdef SUPPORT_UTF8
    case OP_XCLASS:
      {
      data = ecode + 1 + LINK_SIZE;                /* Save for matching */
      ecode += GET(ecode, 1);                      /* Advance past the item */

      switch (*ecode)
        {
        case OP_CRSTAR:
        case OP_CRMINSTAR:
        case OP_CRPLUS:
        case OP_CRMINPLUS:
        case OP_CRQUERY:
        case OP_CRMINQUERY:
        c = *ecode++ - OP_CRSTAR;
        minimize = (c & 1) != 0;
        min = rep_min[c];                 /* Pick up values from tables; */
        max = rep_max[c];                 /* zero for max => infinity */
        if (max == 0) max = INT_MAX;
        break;

        case OP_CRRANGE:
        case OP_CRMINRANGE:
        minimize = (*ecode == OP_CRMINRANGE);
        min = GET2(ecode, 1);
        max = GET2(ecode, 3);
        if (max == 0) max = INT_MAX;
        ecode += 5;
        break;

        default:               /* No repeat follows */
        min = max = 1;
        break;
        }

      /* First, ensure the minimum number of matches are present. */

      for (i = 1; i <= min; i++)
        {
        if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
        GETCHARINC(c, eptr);
        if (!_pcre_xclass(c, data)) RRETURN(MATCH_NOMATCH);
        }

      /* If max == min we can continue with the main loop without the
      need to recurse. */

      if (min == max) continue;

      /* If minimizing, keep testing the rest of the expression and advancing
      the pointer while it matches the class. */

      if (minimize)
        {
        for (fi = min;; fi++)
          {
          RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM20);
          if (rrc != MATCH_NOMATCH) RRETURN(rrc);
          if (fi >= max || eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
          GETCHARINC(c, eptr);
          if (!_pcre_xclass(c, data)) RRETURN(MATCH_NOMATCH);
          }
        /* Control never gets here */
        }

      /* If maximizing, find the longest possible run, then work backwards. */

      else
        {
        pp = eptr;
        for (i = min; i < max; i++)
          {
          int len = 1;
          if (eptr >= md->end_subject) break;
          GETCHARLEN(c, eptr, len);
          if (!_pcre_xclass(c, data)) break;
          eptr += len;
          }
        for(;;)
          {
          RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM21);
          if (rrc != MATCH_NOMATCH) RRETURN(rrc);
          if (eptr-- == pp) break;        /* Stop if tried at original pos */
          if (utf8) BACKCHAR(eptr);
          }
        RRETURN(MATCH_NOMATCH);
        }

      /* Control never gets here */
      }
#endif    /* End of XCLASS */

    /* Match a single character, casefully */

    case OP_CHAR:
#ifdef SUPPORT_UTF8
    if (utf8)
      {
      length = 1;
      ecode++;
      GETCHARLEN(fc, ecode, length);
      if (length > md->end_subject - eptr) RRETURN(MATCH_NOMATCH);
      while (length-- > 0) if (*ecode++ != *eptr++) RRETURN(MATCH_NOMATCH);
      }
    else
#endif

    /* Non-UTF-8 mode */
      {
      if (md->end_subject - eptr < 1) RRETURN(MATCH_NOMATCH);
      if (ecode[1] != *eptr++) RRETURN(MATCH_NOMATCH);
      ecode += 2;
      }
    break;

    /* Match a single character, caselessly */

    case OP_CHARNC:
#ifdef SUPPORT_UTF8
    if (utf8)
      {
      length = 1;
      ecode++;
      GETCHARLEN(fc, ecode, length);

      if (length > md->end_subject - eptr) RRETURN(MATCH_NOMATCH);

      /* If the pattern character's value is < 128, we have only one byte, and
      can use the fast lookup table. */

      if (fc < 128)
        {
        if (md->lcc[*ecode++] != md->lcc[*eptr++]) RRETURN(MATCH_NOMATCH);
        }

      /* Otherwise we must pick up the subject character */

      else
        {
        unsigned int dc;
        GETCHARINC(dc, eptr);
        ecode += length;

        /* If we have Unicode property support, we can use it to test the other
        case of the character, if there is one. */

        if (fc != dc)
          {
#ifdef SUPPORT_UCP
          if (dc != UCD_OTHERCASE(fc))
#endif
            RRETURN(MATCH_NOMATCH);
          }
        }
      }
    else
#endif   /* SUPPORT_UTF8 */

    /* Non-UTF-8 mode */
      {
      if (md->end_subject - eptr < 1) RRETURN(MATCH_NOMATCH);
      if (md->lcc[ecode[1]] != md->lcc[*eptr++]) RRETURN(MATCH_NOMATCH);
      ecode += 2;
      }
    break;

    /* Match a single character repeatedly. */

    case OP_EXACT:
    min = max = GET2(ecode, 1);
    ecode += 3;
    goto REPEATCHAR;

    case OP_POSUPTO:
    possessive = TRUE;
    /* Fall through */

    case OP_UPTO:
    case OP_MINUPTO:
    min = 0;
    max = GET2(ecode, 1);
    minimize = *ecode == OP_MINUPTO;
    ecode += 3;
    goto REPEATCHAR;

    case OP_POSSTAR:
    possessive = TRUE;
    min = 0;
    max = INT_MAX;
    ecode++;
    goto REPEATCHAR;

    case OP_POSPLUS:
    possessive = TRUE;
    min = 1;
    max = INT_MAX;
    ecode++;
    goto REPEATCHAR;

    case OP_POSQUERY:
    possessive = TRUE;
    min = 0;
    max = 1;
    ecode++;
    goto REPEATCHAR;

    case OP_STAR:
    case OP_MINSTAR:
    case OP_PLUS:
    case OP_MINPLUS:
    case OP_QUERY:
    case OP_MINQUERY:
    c = *ecode++ - OP_STAR;
    minimize = (c & 1) != 0;
    min = rep_min[c];                 /* Pick up values from tables; */
    max = rep_max[c];                 /* zero for max => infinity */
    if (max == 0) max = INT_MAX;

    /* Common code for all repeated single-character matches. We can give
    up quickly if there are fewer than the minimum number of characters left in
    the subject. */

    REPEATCHAR:
#ifdef SUPPORT_UTF8
    if (utf8)
      {
      length = 1;
      charptr = ecode;
      GETCHARLEN(fc, ecode, length);
      if (min * length > md->end_subject - eptr) RRETURN(MATCH_NOMATCH);
      ecode += length;

      /* Handle multibyte character matching specially here. There is
      support for caseless matching if UCP support is present. */

      if (length > 1)
        {
#ifdef SUPPORT_UCP
        unsigned int othercase;
        if ((ims & PCRE_CASELESS) != 0 &&
            (othercase = UCD_OTHERCASE(fc)) != fc)
          oclength = _pcre_ord2utf8(othercase, occhars);
        else oclength = 0;
#endif  /* SUPPORT_UCP */

        for (i = 1; i <= min; i++)
          {
          if (memcmp(eptr, charptr, length) == 0) eptr += length;
#ifdef SUPPORT_UCP
          /* Need braces because of following else */
          else if (oclength == 0) { RRETURN(MATCH_NOMATCH); }
          else
            {
            if (memcmp(eptr, occhars, oclength) != 0) RRETURN(MATCH_NOMATCH);
            eptr += oclength;
            }
#else   /* without SUPPORT_UCP */
          else { RRETURN(MATCH_NOMATCH); }
#endif  /* SUPPORT_UCP */
          }

        if (min == max) continue;

        if (minimize)
          {
          for (fi = min;; fi++)
            {
            RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM22);
            if (rrc != MATCH_NOMATCH) RRETURN(rrc);
            if (fi >= max || eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
            if (memcmp(eptr, charptr, length) == 0) eptr += length;
#ifdef SUPPORT_UCP
            /* Need braces because of following else */
            else if (oclength == 0) { RRETURN(MATCH_NOMATCH); }
            else
              {
              if (memcmp(eptr, occhars, oclength) != 0) RRETURN(MATCH_NOMATCH);
              eptr += oclength;
              }
#else   /* without SUPPORT_UCP */
            else { RRETURN (MATCH_NOMATCH); }
#endif  /* SUPPORT_UCP */
            }
          /* Control never gets here */
          }

        else  /* Maximize */
          {
          pp = eptr;
          for (i = min; i < max; i++)
            {
            if (eptr > md->end_subject - length) break;
            if (memcmp(eptr, charptr, length) == 0) eptr += length;
#ifdef SUPPORT_UCP
            else if (oclength == 0) break;
            else
              {
              if (memcmp(eptr, occhars, oclength) != 0) break;
              eptr += oclength;
              }
#else   /* without SUPPORT_UCP */
            else break;
#endif  /* SUPPORT_UCP */
            }

          if (possessive) continue;
          for(;;)
           {
           RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM23);
           if (rrc != MATCH_NOMATCH) RRETURN(rrc);
           if (eptr == pp) RRETURN(MATCH_NOMATCH);
#ifdef SUPPORT_UCP
           eptr--;
           BACKCHAR(eptr);
#else   /* without SUPPORT_UCP */
           eptr -= length;
#endif  /* SUPPORT_UCP */
           }
          }
        /* Control never gets here */
        }

      /* If the length of a UTF-8 character is 1, we fall through here, and
      obey the code as for non-UTF-8 characters below, though in this case the
      value of fc will always be < 128. */
      }
    else
#endif  /* SUPPORT_UTF8 */

    /* When not in UTF-8 mode, load a single-byte character. */
      {
      if (min > md->end_subject - eptr) RRETURN(MATCH_NOMATCH);
      fc = *ecode++;
      }

    /* The value of fc at this point is always less than 256, though we may or
    may not be in UTF-8 mode. The code is duplicated for the caseless and
    caseful cases, for speed, since matching characters is likely to be quite
    common. First, ensure the minimum number of matches are present. If min =
    max, continue at the same level without recursing. Otherwise, if
    minimizing, keep trying the rest of the expression and advancing one
    matching character if failing, up to the maximum. Alternatively, if
    maximizing, find the maximum number of characters and work backwards. */

    DPRINTF(("matching %c{%d,%d} against subject %.*s\n", fc, min, max,
      max, eptr));

    if ((ims & PCRE_CASELESS) != 0)
      {
      fc = md->lcc[fc];
      for (i = 1; i <= min; i++)
        if (fc != md->lcc[*eptr++]) RRETURN(MATCH_NOMATCH);
      if (min == max) continue;
      if (minimize)
        {
        for (fi = min;; fi++)
          {
          RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM24);
          if (rrc != MATCH_NOMATCH) RRETURN(rrc);
          if (fi >= max || eptr >= md->end_subject ||
              fc != md->lcc[*eptr++])
            RRETURN(MATCH_NOMATCH);
          }
        /* Control never gets here */
        }
      else  /* Maximize */
        {
        pp = eptr;
        for (i = min; i < max; i++)
          {
          if (eptr >= md->end_subject || fc != md->lcc[*eptr]) break;
          eptr++;
          }
        if (possessive) continue;
        while (eptr >= pp)
          {
          RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM25);
          eptr--;
          if (rrc != MATCH_NOMATCH) RRETURN(rrc);
          }
        RRETURN(MATCH_NOMATCH);
        }
      /* Control never gets here */
      }

    /* Caseful comparisons (includes all multi-byte characters) */

    else
      {
      for (i = 1; i <= min; i++) if (fc != *eptr++) RRETURN(MATCH_NOMATCH);
      if (min == max) continue;
      if (minimize)
        {
        for (fi = min;; fi++)
          {
          RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM26);
          if (rrc != MATCH_NOMATCH) RRETURN(rrc);
          if (fi >= max || eptr >= md->end_subject || fc != *eptr++)
            RRETURN(MATCH_NOMATCH);
          }
        /* Control never gets here */
        }
      else  /* Maximize */
        {
        pp = eptr;
        for (i = min; i < max; i++)
          {
          if (eptr >= md->end_subject || fc != *eptr) break;
          eptr++;
          }
        if (possessive) continue;
        while (eptr >= pp)
          {
          RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM27);
          eptr--;
          if (rrc != MATCH_NOMATCH) RRETURN(rrc);
          }
        RRETURN(MATCH_NOMATCH);
        }
      }
    /* Control never gets here */

    /* Match a negated single one-byte character. The character we are
    checking can be multibyte. */

    case OP_NOT:
    if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
    ecode++;
    GETCHARINCTEST(c, eptr);
    if ((ims & PCRE_CASELESS) != 0)
      {
#ifdef SUPPORT_UTF8
      if (c < 256)
#endif
      c = md->lcc[c];
      if (md->lcc[*ecode++] == c) RRETURN(MATCH_NOMATCH);
      }
    else
      {
      if (*ecode++ == c) RRETURN(MATCH_NOMATCH);
      }
    break;

    /* Match a negated single one-byte character repeatedly. This is almost a
    repeat of the code for a repeated single character, but I haven't found a
    nice way of commoning these up that doesn't require a test of the
    positive/negative option for each character match. Maybe that wouldn't add
    very much to the time taken, but character matching *is* what this is all
    about... */

    case OP_NOTEXACT:
    min = max = GET2(ecode, 1);
    ecode += 3;
    goto REPEATNOTCHAR;

    case OP_NOTUPTO:
    case OP_NOTMINUPTO:
    min = 0;
    max = GET2(ecode, 1);
    minimize = *ecode == OP_NOTMINUPTO;
    ecode += 3;
    goto REPEATNOTCHAR;

    case OP_NOTPOSSTAR:
    possessive = TRUE;
    min = 0;
    max = INT_MAX;
    ecode++;
    goto REPEATNOTCHAR;

    case OP_NOTPOSPLUS:
    possessive = TRUE;
    min = 1;
    max = INT_MAX;
    ecode++;
    goto REPEATNOTCHAR;

    case OP_NOTPOSQUERY:
    possessive = TRUE;
    min = 0;
    max = 1;
    ecode++;
    goto REPEATNOTCHAR;

    case OP_NOTPOSUPTO:
    possessive = TRUE;
    min = 0;
    max = GET2(ecode, 1);
    ecode += 3;
    goto REPEATNOTCHAR;

    case OP_NOTSTAR:
    case OP_NOTMINSTAR:
    case OP_NOTPLUS:
    case OP_NOTMINPLUS:
    case OP_NOTQUERY:
    case OP_NOTMINQUERY:
    c = *ecode++ - OP_NOTSTAR;
    minimize = (c & 1) != 0;
    min = rep_min[c];                 /* Pick up values from tables; */
    max = rep_max[c];                 /* zero for max => infinity */
    if (max == 0) max = INT_MAX;

    /* Common code for all repeated single-byte matches. We can give up quickly
    if there are fewer than the minimum number of bytes left in the
    subject. */

    REPEATNOTCHAR:
    if (min > md->end_subject - eptr) RRETURN(MATCH_NOMATCH);
    fc = *ecode++;

    /* The code is duplicated for the caseless and caseful cases, for speed,
    since matching characters is likely to be quite common. First, ensure the
    minimum number of matches are present. If min = max, continue at the same
    level without recursing. Otherwise, if minimizing, keep trying the rest of
    the expression and advancing one matching character if failing, up to the
    maximum. Alternatively, if maximizing, find the maximum number of
    characters and work backwards. */

    DPRINTF(("negative matching %c{%d,%d} against subject %.*s\n", fc, min, max,
      max, eptr));

    if ((ims & PCRE_CASELESS) != 0)
      {
      fc = md->lcc[fc];

#ifdef SUPPORT_UTF8
      /* UTF-8 mode */
      if (utf8)
        {
        register unsigned int d;
        for (i = 1; i <= min; i++)
          {
          GETCHARINC(d, eptr);
          if (d < 256) d = md->lcc[d];
          if (fc == d) RRETURN(MATCH_NOMATCH);
          }
        }
      else
#endif

      /* Not UTF-8 mode */
        {
        for (i = 1; i <= min; i++)
          if (fc == md->lcc[*eptr++]) RRETURN(MATCH_NOMATCH);
        }

      if (min == max) continue;

      if (minimize)
        {
#ifdef SUPPORT_UTF8
        /* UTF-8 mode */
        if (utf8)
          {
          register unsigned int d;
          for (fi = min;; fi++)
            {
            RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM28);
            if (rrc != MATCH_NOMATCH) RRETURN(rrc);
            if (fi >= max || eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
            GETCHARINC(d, eptr);
            if (d < 256) d = md->lcc[d];
            if (fc == d) RRETURN(MATCH_NOMATCH);

            }
          }
        else
#endif
        /* Not UTF-8 mode */
          {
          for (fi = min;; fi++)
            {
            RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM29);
            if (rrc != MATCH_NOMATCH) RRETURN(rrc);
            if (fi >= max || eptr >= md->end_subject || fc == md->lcc[*eptr++])
              RRETURN(MATCH_NOMATCH);
            }
          }
        /* Control never gets here */
        }

      /* Maximize case */

      else
        {
        pp = eptr;

#ifdef SUPPORT_UTF8
        /* UTF-8 mode */
        if (utf8)
          {
          register unsigned int d;
          for (i = min; i < max; i++)
            {
            int len = 1;
            if (eptr >= md->end_subject) break;
            GETCHARLEN(d, eptr, len);
            if (d < 256) d = md->lcc[d];
            if (fc == d) break;
            eptr += len;
            }
        if (possessive) continue;
        for(;;)
            {
            RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM30);
            if (rrc != MATCH_NOMATCH) RRETURN(rrc);
            if (eptr-- == pp) break;        /* Stop if tried at original pos */
            BACKCHAR(eptr);
            }
          }
        else
#endif
        /* Not UTF-8 mode */
          {
          for (i = min; i < max; i++)
            {
            if (eptr >= md->end_subject || fc == md->lcc[*eptr]) break;
            eptr++;
            }
          if (possessive) continue;
          while (eptr >= pp)
            {
            RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM31);
            if (rrc != MATCH_NOMATCH) RRETURN(rrc);
            eptr--;
            }
          }

        RRETURN(MATCH_NOMATCH);
        }
      /* Control never gets here */
      }

    /* Caseful comparisons */

    else
      {
#ifdef SUPPORT_UTF8
      /* UTF-8 mode */
      if (utf8)
        {
        register unsigned int d;
        for (i = 1; i <= min; i++)
          {
          GETCHARINC(d, eptr);
          if (fc == d) RRETURN(MATCH_NOMATCH);
          }
        }
      else
#endif
      /* Not UTF-8 mode */
        {
        for (i = 1; i <= min; i++)
          if (fc == *eptr++) RRETURN(MATCH_NOMATCH);
        }

      if (min == max) continue;

      if (minimize)
        {
#ifdef SUPPORT_UTF8
        /* UTF-8 mode */
        if (utf8)
          {
          register unsigned int d;
          for (fi = min;; fi++)
            {
            RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM32);
            if (rrc != MATCH_NOMATCH) RRETURN(rrc);
            if (fi >= max || eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
            GETCHARINC(d, eptr);
            if (fc == d) RRETURN(MATCH_NOMATCH);
            }
          }
        else
#endif
        /* Not UTF-8 mode */
          {
          for (fi = min;; fi++)
            {
            RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM33);
            if (rrc != MATCH_NOMATCH) RRETURN(rrc);
            if (fi >= max || eptr >= md->end_subject || fc == *eptr++)
              RRETURN(MATCH_NOMATCH);
            }
          }
        /* Control never gets here */
        }

      /* Maximize case */

      else
        {
        pp = eptr;

#ifdef SUPPORT_UTF8
        /* UTF-8 mode */
        if (utf8)
          {
          register unsigned int d;
          for (i = min; i < max; i++)
            {
            int len = 1;
            if (eptr >= md->end_subject) break;
            GETCHARLEN(d, eptr, len);
            if (fc == d) break;
            eptr += len;
            }
          if (possessive) continue;
          for(;;)
            {
            RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM34);
            if (rrc != MATCH_NOMATCH) RRETURN(rrc);
            if (eptr-- == pp) break;        /* Stop if tried at original pos */
            BACKCHAR(eptr);
            }
          }
        else
#endif
        /* Not UTF-8 mode */
          {
          for (i = min; i < max; i++)
            {
            if (eptr >= md->end_subject || fc == *eptr) break;
            eptr++;
            }
          if (possessive) continue;
          while (eptr >= pp)
            {
            RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM35);
            if (rrc != MATCH_NOMATCH) RRETURN(rrc);
            eptr--;
            }
          }

        RRETURN(MATCH_NOMATCH);
        }
      }
    /* Control never gets here */

    /* Match a single character type repeatedly; several different opcodes
    share code. This is very similar to the code for single characters, but we
    repeat it in the interests of efficiency. */

    case OP_TYPEEXACT:
    min = max = GET2(ecode, 1);
    minimize = TRUE;
    ecode += 3;
    goto REPEATTYPE;

    case OP_TYPEUPTO:
    case OP_TYPEMINUPTO:
    min = 0;
    max = GET2(ecode, 1);
    minimize = *ecode == OP_TYPEMINUPTO;
    ecode += 3;
    goto REPEATTYPE;

    case OP_TYPEPOSSTAR:
    possessive = TRUE;
    min = 0;
    max = INT_MAX;
    ecode++;
    goto REPEATTYPE;

    case OP_TYPEPOSPLUS:
    possessive = TRUE;
    min = 1;
    max = INT_MAX;
    ecode++;
    goto REPEATTYPE;

    case OP_TYPEPOSQUERY:
    possessive = TRUE;
    min = 0;
    max = 1;
    ecode++;
    goto REPEATTYPE;

    case OP_TYPEPOSUPTO:
    possessive = TRUE;
    min = 0;
    max = GET2(ecode, 1);
    ecode += 3;
    goto REPEATTYPE;

    case OP_TYPESTAR:
    case OP_TYPEMINSTAR:
    case OP_TYPEPLUS:
    case OP_TYPEMINPLUS:
    case OP_TYPEQUERY:
    case OP_TYPEMINQUERY:
    c = *ecode++ - OP_TYPESTAR;
    minimize = (c & 1) != 0;
    min = rep_min[c];                 /* Pick up values from tables; */
    max = rep_max[c];                 /* zero for max => infinity */
    if (max == 0) max = INT_MAX;

    /* Common code for all repeated single character type matches. Note that
    in UTF-8 mode, '.' matches a character of any length, but for the other
    character types, the valid characters are all one-byte long. */

    REPEATTYPE:
    ctype = *ecode++;      /* Code for the character type */

#ifdef SUPPORT_UCP
    if (ctype == OP_PROP || ctype == OP_NOTPROP)
      {
      prop_fail_result = ctype == OP_NOTPROP;
      prop_type = *ecode++;
      prop_value = *ecode++;
      }
    else prop_type = -1;
#endif

    /* First, ensure the minimum number of matches are present. Use inline
    code for maximizing the speed, and do the type test once at the start
    (i.e. keep it out of the loop). Also we can test that there are at least
    the minimum number of bytes before we start. This isn't as effective in
    UTF-8 mode, but it does no harm. Separate the UTF-8 code completely as that
    is tidier. Also separate the UCP code, which can be the same for both UTF-8
    and single-bytes. */

    if (min > md->end_subject - eptr) RRETURN(MATCH_NOMATCH);
    if (min > 0)
      {
#ifdef SUPPORT_UCP
      if (prop_type >= 0)
        {
        switch(prop_type)
          {
          case PT_ANY:
          if (prop_fail_result) RRETURN(MATCH_NOMATCH);
          for (i = 1; i <= min; i++)
            {
            if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
            GETCHARINCTEST(c, eptr);
            }
          break;

          case PT_LAMP:
          for (i = 1; i <= min; i++)
            {
            if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
            GETCHARINCTEST(c, eptr);
            prop_chartype = UCD_CHARTYPE(c);
            if ((prop_chartype == ucp_Lu ||
                 prop_chartype == ucp_Ll ||
                 prop_chartype == ucp_Lt) == prop_fail_result)
              RRETURN(MATCH_NOMATCH);
            }
          break;

          case PT_GC:
          for (i = 1; i <= min; i++)
            {
            if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
            GETCHARINCTEST(c, eptr);
            prop_category = UCD_CATEGORY(c);
            if ((prop_category == prop_value) == prop_fail_result)
              RRETURN(MATCH_NOMATCH);
            }
          break;

          case PT_PC:
          for (i = 1; i <= min; i++)
            {
            if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
            GETCHARINCTEST(c, eptr);
            prop_chartype = UCD_CHARTYPE(c);
            if ((prop_chartype == prop_value) == prop_fail_result)
              RRETURN(MATCH_NOMATCH);
            }
          break;

          case PT_SC:
          for (i = 1; i <= min; i++)
            {
            if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
            GETCHARINCTEST(c, eptr);
            prop_script = UCD_SCRIPT(c);
            if ((prop_script == prop_value) == prop_fail_result)
              RRETURN(MATCH_NOMATCH);
            }
          break;

          default:
          RRETURN(PCRE_ERROR_INTERNAL);
          }
        }

      /* Match extended Unicode sequences. We will get here only if the
      support is in the binary; otherwise a compile-time error occurs. */

      else if (ctype == OP_EXTUNI)
        {
        for (i = 1; i <= min; i++)
          {
          GETCHARINCTEST(c, eptr);
          prop_category = UCD_CATEGORY(c);
          if (prop_category == ucp_M) RRETURN(MATCH_NOMATCH);
          while (eptr < md->end_subject)
            {
            int len = 1;
            if (!utf8) c = *eptr; else
              {
              GETCHARLEN(c, eptr, len);
              }
            prop_category = UCD_CATEGORY(c);
            if (prop_category != ucp_M) break;
            eptr += len;
            }
          }
        }

      else
#endif     /* SUPPORT_UCP */

/* Handle all other cases when the coding is UTF-8 */

#ifdef SUPPORT_UTF8
      if (utf8) switch(ctype)
        {
        case OP_ANY:
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject || IS_NEWLINE(eptr))
            RRETURN(MATCH_NOMATCH);
          eptr++;
          while (eptr < md->end_subject && (*eptr & 0xc0) == 0x80) eptr++;
          }
        break;

        case OP_ALLANY:
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
          eptr++;
          while (eptr < md->end_subject && (*eptr & 0xc0) == 0x80) eptr++;
          }
        break;

        case OP_ANYBYTE:
        eptr += min;
        break;

        case OP_ANYNL:
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
          GETCHARINC(c, eptr);
          switch(c)
            {
            default: RRETURN(MATCH_NOMATCH);
            case 0x000d:
            if (eptr < md->end_subject && *eptr == 0x0a) eptr++;
            break;

            case 0x000a:
            break;

            case 0x000b:
            case 0x000c:
            case 0x0085:
            case 0x2028:
            case 0x2029:
            if (md->bsr_anycrlf) RRETURN(MATCH_NOMATCH);
            break;
            }
          }
        break;

        case OP_NOT_HSPACE:
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
          GETCHARINC(c, eptr);
          switch(c)
            {
            default: break;
            case 0x09:      /* HT */
            case 0x20:      /* SPACE */
            case 0xa0:      /* NBSP */
            case 0x1680:    /* OGHAM SPACE MARK */
            case 0x180e:    /* MONGOLIAN VOWEL SEPARATOR */
            case 0x2000:    /* EN QUAD */
            case 0x2001:    /* EM QUAD */
            case 0x2002:    /* EN SPACE */
            case 0x2003:    /* EM SPACE */
            case 0x2004:    /* THREE-PER-EM SPACE */
            case 0x2005:    /* FOUR-PER-EM SPACE */
            case 0x2006:    /* SIX-PER-EM SPACE */
            case 0x2007:    /* FIGURE SPACE */
            case 0x2008:    /* PUNCTUATION SPACE */
            case 0x2009:    /* THIN SPACE */
            case 0x200A:    /* HAIR SPACE */
            case 0x202f:    /* NARROW NO-BREAK SPACE */
            case 0x205f:    /* MEDIUM MATHEMATICAL SPACE */
            case 0x3000:    /* IDEOGRAPHIC SPACE */
            RRETURN(MATCH_NOMATCH);
            }
          }
        break;

        case OP_HSPACE:
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
          GETCHARINC(c, eptr);
          switch(c)
            {
            default: RRETURN(MATCH_NOMATCH);
            case 0x09:      /* HT */
            case 0x20:      /* SPACE */
            case 0xa0:      /* NBSP */
            case 0x1680:    /* OGHAM SPACE MARK */
            case 0x180e:    /* MONGOLIAN VOWEL SEPARATOR */
            case 0x2000:    /* EN QUAD */
            case 0x2001:    /* EM QUAD */
            case 0x2002:    /* EN SPACE */
            case 0x2003:    /* EM SPACE */
            case 0x2004:    /* THREE-PER-EM SPACE */
            case 0x2005:    /* FOUR-PER-EM SPACE */
            case 0x2006:    /* SIX-PER-EM SPACE */
            case 0x2007:    /* FIGURE SPACE */
            case 0x2008:    /* PUNCTUATION SPACE */
            case 0x2009:    /* THIN SPACE */
            case 0x200A:    /* HAIR SPACE */
            case 0x202f:    /* NARROW NO-BREAK SPACE */
            case 0x205f:    /* MEDIUM MATHEMATICAL SPACE */
            case 0x3000:    /* IDEOGRAPHIC SPACE */
            break;
            }
          }
        break;

        case OP_NOT_VSPACE:
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
          GETCHARINC(c, eptr);
          switch(c)
            {
            default: break;
            case 0x0a:      /* LF */
            case 0x0b:      /* VT */
            case 0x0c:      /* FF */
            case 0x0d:      /* CR */
            case 0x85:      /* NEL */
            case 0x2028:    /* LINE SEPARATOR */
            case 0x2029:    /* PARAGRAPH SEPARATOR */
            RRETURN(MATCH_NOMATCH);
            }
          }
        break;

        case OP_VSPACE:
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
          GETCHARINC(c, eptr);
          switch(c)
            {
            default: RRETURN(MATCH_NOMATCH);
            case 0x0a:      /* LF */
            case 0x0b:      /* VT */
            case 0x0c:      /* FF */
            case 0x0d:      /* CR */
            case 0x85:      /* NEL */
            case 0x2028:    /* LINE SEPARATOR */
            case 0x2029:    /* PARAGRAPH SEPARATOR */
            break;
            }
          }
        break;

        case OP_NOT_DIGIT:
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
          GETCHARINC(c, eptr);
          if (c < 128 && (md->ctypes[c] & ctype_digit) != 0)
            RRETURN(MATCH_NOMATCH);
          }
        break;

        case OP_DIGIT:
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject ||
             *eptr >= 128 || (md->ctypes[*eptr++] & ctype_digit) == 0)
            RRETURN(MATCH_NOMATCH);
          /* No need to skip more bytes - we know it's a 1-byte character */
          }
        break;

        case OP_NOT_WHITESPACE:
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject ||
             (*eptr < 128 && (md->ctypes[*eptr] & ctype_space) != 0))
            RRETURN(MATCH_NOMATCH);
          while (++eptr < md->end_subject && (*eptr & 0xc0) == 0x80);
          }
        break;

        case OP_WHITESPACE:
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject ||
             *eptr >= 128 || (md->ctypes[*eptr++] & ctype_space) == 0)
            RRETURN(MATCH_NOMATCH);
          /* No need to skip more bytes - we know it's a 1-byte character */
          }
        break;

        case OP_NOT_WORDCHAR:
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject ||
             (*eptr < 128 && (md->ctypes[*eptr] & ctype_word) != 0))
            RRETURN(MATCH_NOMATCH);
          while (++eptr < md->end_subject && (*eptr & 0xc0) == 0x80);
          }
        break;

        case OP_WORDCHAR:
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject ||
             *eptr >= 128 || (md->ctypes[*eptr++] & ctype_word) == 0)
            RRETURN(MATCH_NOMATCH);
          /* No need to skip more bytes - we know it's a 1-byte character */
          }
        break;

        default:
        RRETURN(PCRE_ERROR_INTERNAL);
        }  /* End switch(ctype) */

      else
#endif     /* SUPPORT_UTF8 */

      /* Code for the non-UTF-8 case for minimum matching of operators other
      than OP_PROP and OP_NOTPROP. We can assume that there are the minimum
      number of bytes present, as this was tested above. */

      switch(ctype)
        {
        case OP_ANY:
        for (i = 1; i <= min; i++)
          {
          if (IS_NEWLINE(eptr)) RRETURN(MATCH_NOMATCH);
          eptr++;
          }
        break;

        case OP_ALLANY:
        eptr += min;
        break;

        case OP_ANYBYTE:
        eptr += min;
        break;

        /* Because of the CRLF case, we can't assume the minimum number of
        bytes are present in this case. */

        case OP_ANYNL:
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
          switch(*eptr++)
            {
            default: RRETURN(MATCH_NOMATCH);
            case 0x000d:
            if (eptr < md->end_subject && *eptr == 0x0a) eptr++;
            break;
            case 0x000a:
            break;

            case 0x000b:
            case 0x000c:
            case 0x0085:
            if (md->bsr_anycrlf) RRETURN(MATCH_NOMATCH);
            break;
            }
          }
        break;

        case OP_NOT_HSPACE:
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
          switch(*eptr++)
            {
            default: break;
            case 0x09:      /* HT */
            case 0x20:      /* SPACE */
            case 0xa0:      /* NBSP */
            RRETURN(MATCH_NOMATCH);
            }
          }
        break;

        case OP_HSPACE:
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
          switch(*eptr++)
            {
            default: RRETURN(MATCH_NOMATCH);
            case 0x09:      /* HT */
            case 0x20:      /* SPACE */
            case 0xa0:      /* NBSP */
            break;
            }
          }
        break;

        case OP_NOT_VSPACE:
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
          switch(*eptr++)
            {
            default: break;
            case 0x0a:      /* LF */
            case 0x0b:      /* VT */
            case 0x0c:      /* FF */
            case 0x0d:      /* CR */
            case 0x85:      /* NEL */
            RRETURN(MATCH_NOMATCH);
            }
          }
        break;

        case OP_VSPACE:
        for (i = 1; i <= min; i++)
          {
          if (eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
          switch(*eptr++)
            {
            default: RRETURN(MATCH_NOMATCH);
            case 0x0a:      /* LF */
            case 0x0b:      /* VT */
            case 0x0c:      /* FF */
            case 0x0d:      /* CR */
            case 0x85:      /* NEL */
            break;
            }
          }
        break;

        case OP_NOT_DIGIT:
        for (i = 1; i <= min; i++)
          if ((md->ctypes[*eptr++] & ctype_digit) != 0) RRETURN(MATCH_NOMATCH);
        break;

        case OP_DIGIT:
        for (i = 1; i <= min; i++)
          if ((md->ctypes[*eptr++] & ctype_digit) == 0) RRETURN(MATCH_NOMATCH);
        break;

        case OP_NOT_WHITESPACE:
        for (i = 1; i <= min; i++)
          if ((md->ctypes[*eptr++] & ctype_space) != 0) RRETURN(MATCH_NOMATCH);
        break;

        case OP_WHITESPACE:
        for (i = 1; i <= min; i++)
          if ((md->ctypes[*eptr++] & ctype_space) == 0) RRETURN(MATCH_NOMATCH);
        break;

        case OP_NOT_WORDCHAR:
        for (i = 1; i <= min; i++)
          if ((md->ctypes[*eptr++] & ctype_word) != 0)
            RRETURN(MATCH_NOMATCH);
        break;

        case OP_WORDCHAR:
        for (i = 1; i <= min; i++)
          if ((md->ctypes[*eptr++] & ctype_word) == 0)
            RRETURN(MATCH_NOMATCH);
        break;

        default:
        RRETURN(PCRE_ERROR_INTERNAL);
        }
      }

    /* If min = max, continue at the same level without recursing */

    if (min == max) continue;

    /* If minimizing, we have to test the rest of the pattern before each
    subsequent match. Again, separate the UTF-8 case for speed, and also
    separate the UCP cases. */

    if (minimize)
      {
#ifdef SUPPORT_UCP
      if (prop_type >= 0)
        {
        switch(prop_type)
          {
          case PT_ANY:
          for (fi = min;; fi++)
            {
            RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM36);
            if (rrc != MATCH_NOMATCH) RRETURN(rrc);
            if (fi >= max || eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
            GETCHARINC(c, eptr);
            if (prop_fail_result) RRETURN(MATCH_NOMATCH);
            }
          /* Control never gets here */

          case PT_LAMP:
          for (fi = min;; fi++)
            {
            RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM37);
            if (rrc != MATCH_NOMATCH) RRETURN(rrc);
            if (fi >= max || eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
            GETCHARINC(c, eptr);
            prop_chartype = UCD_CHARTYPE(c);
            if ((prop_chartype == ucp_Lu ||
                 prop_chartype == ucp_Ll ||
                 prop_chartype == ucp_Lt) == prop_fail_result)
              RRETURN(MATCH_NOMATCH);
            }
          /* Control never gets here */

          case PT_GC:
          for (fi = min;; fi++)
            {
            RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM38);
            if (rrc != MATCH_NOMATCH) RRETURN(rrc);
            if (fi >= max || eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
            GETCHARINC(c, eptr);
            prop_category = UCD_CATEGORY(c);
            if ((prop_category == prop_value) == prop_fail_result)
              RRETURN(MATCH_NOMATCH);
            }
          /* Control never gets here */

          case PT_PC:
          for (fi = min;; fi++)
            {
            RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM39);
            if (rrc != MATCH_NOMATCH) RRETURN(rrc);
            if (fi >= max || eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
            GETCHARINC(c, eptr);
            prop_chartype = UCD_CHARTYPE(c);
            if ((prop_chartype == prop_value) == prop_fail_result)
              RRETURN(MATCH_NOMATCH);
            }
          /* Control never gets here */

          case PT_SC:
          for (fi = min;; fi++)
            {
            RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM40);
            if (rrc != MATCH_NOMATCH) RRETURN(rrc);
            if (fi >= max || eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
            GETCHARINC(c, eptr);
            prop_script = UCD_SCRIPT(c);
            if ((prop_script == prop_value) == prop_fail_result)
              RRETURN(MATCH_NOMATCH);
            }
          /* Control never gets here */

          default:
          RRETURN(PCRE_ERROR_INTERNAL);
          }
        }

      /* Match extended Unicode sequences. We will get here only if the
      support is in the binary; otherwise a compile-time error occurs. */

      else if (ctype == OP_EXTUNI)
        {
        for (fi = min;; fi++)
          {
          RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM41);
          if (rrc != MATCH_NOMATCH) RRETURN(rrc);
          if (fi >= max || eptr >= md->end_subject) RRETURN(MATCH_NOMATCH);
          GETCHARINCTEST(c, eptr);
          prop_category = UCD_CATEGORY(c);
          if (prop_category == ucp_M) RRETURN(MATCH_NOMATCH);
          while (eptr < md->end_subject)
            {
            int len = 1;
            if (!utf8) c = *eptr; else
              {
              GETCHARLEN(c, eptr, len);
              }
            prop_category = UCD_CATEGORY(c);
            if (prop_category != ucp_M) break;
            eptr += len;
            }
          }
        }

      else
#endif     /* SUPPORT_UCP */

#ifdef SUPPORT_UTF8
      /* UTF-8 mode */
      if (utf8)
        {
        for (fi = min;; fi++)
          {
          RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM42);
          if (rrc != MATCH_NOMATCH) RRETURN(rrc);
          if (fi >= max || eptr >= md->end_subject ||
               (ctype == OP_ANY && IS_NEWLINE(eptr)))
            RRETURN(MATCH_NOMATCH);

          GETCHARINC(c, eptr);
          switch(ctype)
            {
            case OP_ANY:        /* This is the non-NL case */
            case OP_ALLANY:
            case OP_ANYBYTE:
            break;

            case OP_ANYNL:
            switch(c)
              {
              default: RRETURN(MATCH_NOMATCH);
              case 0x000d:
              if (eptr < md->end_subject && *eptr == 0x0a) eptr++;
              break;
              case 0x000a:
              break;

              case 0x000b:
              case 0x000c:
              case 0x0085:
              case 0x2028:
              case 0x2029:
              if (md->bsr_anycrlf) RRETURN(MATCH_NOMATCH);
              break;
              }
            break;

            case OP_NOT_HSPACE:
            switch(c)
              {
              default: break;
              case 0x09:      /* HT */
              case 0x20:      /* SPACE */
              case 0xa0:      /* NBSP */
              case 0x1680:    /* OGHAM SPACE MARK */
              case 0x180e:    /* MONGOLIAN VOWEL SEPARATOR */
              case 0x2000:    /* EN QUAD */
              case 0x2001:    /* EM QUAD */
              case 0x2002:    /* EN SPACE */
              case 0x2003:    /* EM SPACE */
              case 0x2004:    /* THREE-PER-EM SPACE */
              case 0x2005:    /* FOUR-PER-EM SPACE */
              case 0x2006:    /* SIX-PER-EM SPACE */
              case 0x2007:    /* FIGURE SPACE */
              case 0x2008:    /* PUNCTUATION SPACE */
              case 0x2009:    /* THIN SPACE */
              case 0x200A:    /* HAIR SPACE */
              case 0x202f:    /* NARROW NO-BREAK SPACE */
              case 0x205f:    /* MEDIUM MATHEMATICAL SPACE */
              case 0x3000:    /* IDEOGRAPHIC SPACE */
              RRETURN(MATCH_NOMATCH);
              }
            break;

            case OP_HSPACE:
            switch(c)
              {
              default: RRETURN(MATCH_NOMATCH);
              case 0x09:      /* HT */
              case 0x20:      /* SPACE */
              case 0xa0:      /* NBSP */
              case 0x1680:    /* OGHAM SPACE MARK */
              case 0x180e:    /* MONGOLIAN VOWEL SEPARATOR */
              case 0x2000:    /* EN QUAD */
              case 0x2001:    /* EM QUAD */
              case 0x2002:    /* EN SPACE */
              case 0x2003:    /* EM SPACE */
              case 0x2004:    /* THREE-PER-EM SPACE */
              case 0x2005:    /* FOUR-PER-EM SPACE */
              case 0x2006:    /* SIX-PER-EM SPACE */
              case 0x2007:    /* FIGURE SPACE */
              case 0x2008:    /* PUNCTUATION SPACE */
              case 0x2009:    /* THIN SPACE */
              case 0x200A:    /* HAIR SPACE */
              case 0x202f:    /* NARROW NO-BREAK SPACE */
              case 0x205f:    /* MEDIUM MATHEMATICAL SPACE */
              case 0x3000:    /* IDEOGRAPHIC SPACE */
              break;
              }
            break;

            case OP_NOT_VSPACE:
            switch(c)
              {
              default: break;
              case 0x0a:      /* LF */
              case 0x0b:      /* VT */
              case 0x0c:      /* FF */
              case 0x0d:      /* CR */
              case 0x85:      /* NEL */
              case 0x2028:    /* LINE SEPARATOR */
              case 0x2029:    /* PARAGRAPH SEPARATOR */
              RRETURN(MATCH_NOMATCH);
              }
            break;

            case OP_VSPACE:
            switch(c)
              {
              default: RRETURN(MATCH_NOMATCH);
              case 0x0a:      /* LF */
              case 0x0b:      /* VT */
              case 0x0c:      /* FF */
              case 0x0d:      /* CR */
              case 0x85:      /* NEL */
              case 0x2028:    /* LINE SEPARATOR */
              case 0x2029:    /* PARAGRAPH SEPARATOR */
              break;
              }
            break;

            case OP_NOT_DIGIT:
            if (c < 256 && (md->ctypes[c] & ctype_digit) != 0)
              RRETURN(MATCH_NOMATCH);
            break;

            case OP_DIGIT:
            if (c >= 256 || (md->ctypes[c] & ctype_digit) == 0)
              RRETURN(MATCH_NOMATCH);
            break;

            case OP_NOT_WHITESPACE:
            if (c < 256 && (md->ctypes[c] & ctype_space) != 0)
              RRETURN(MATCH_NOMATCH);
            break;

            case OP_WHITESPACE:
            if  (c >= 256 || (md->ctypes[c] & ctype_space) == 0)
              RRETURN(MATCH_NOMATCH);
            break;

            case OP_NOT_WORDCHAR:
            if (c < 256 && (md->ctypes[c] & ctype_word) != 0)
              RRETURN(MATCH_NOMATCH);
            break;

            case OP_WORDCHAR:
            if (c >= 256 || (md->ctypes[c] & ctype_word) == 0)
              RRETURN(MATCH_NOMATCH);
            break;

            default:
            RRETURN(PCRE_ERROR_INTERNAL);
            }
          }
        }
      else
#endif
      /* Not UTF-8 mode */
        {
        for (fi = min;; fi++)
          {
          RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM43);
          if (rrc != MATCH_NOMATCH) RRETURN(rrc);
          if (fi >= max || eptr >= md->end_subject ||
               (ctype == OP_ANY && IS_NEWLINE(eptr)))
            RRETURN(MATCH_NOMATCH);

          c = *eptr++;
          switch(ctype)
            {
            case OP_ANY:     /* This is the non-NL case */
            case OP_ALLANY:
            case OP_ANYBYTE:
            break;

            case OP_ANYNL:
            switch(c)
              {
              default: RRETURN(MATCH_NOMATCH);
              case 0x000d:
              if (eptr < md->end_subject && *eptr == 0x0a) eptr++;
              break;

              case 0x000a:
              break;

              case 0x000b:
              case 0x000c:
              case 0x0085:
              if (md->bsr_anycrlf) RRETURN(MATCH_NOMATCH);
              break;
              }
            break;

            case OP_NOT_HSPACE:
            switch(c)
              {
              default: break;
              case 0x09:      /* HT */
              case 0x20:      /* SPACE */
              case 0xa0:      /* NBSP */
              RRETURN(MATCH_NOMATCH);
              }
            break;

            case OP_HSPACE:
            switch(c)
              {
              default: RRETURN(MATCH_NOMATCH);
              case 0x09:      /* HT */
              case 0x20:      /* SPACE */
              case 0xa0:      /* NBSP */
              break;
              }
            break;

            case OP_NOT_VSPACE:
            switch(c)
              {
              default: break;
              case 0x0a:      /* LF */
              case 0x0b:      /* VT */
              case 0x0c:      /* FF */
              case 0x0d:      /* CR */
              case 0x85:      /* NEL */
              RRETURN(MATCH_NOMATCH);
              }
            break;

            case OP_VSPACE:
            switch(c)
              {
              default: RRETURN(MATCH_NOMATCH);
              case 0x0a:      /* LF */
              case 0x0b:      /* VT */
              case 0x0c:      /* FF */
              case 0x0d:      /* CR */
              case 0x85:      /* NEL */
              break;
              }
            break;

            case OP_NOT_DIGIT:
            if ((md->ctypes[c] & ctype_digit) != 0) RRETURN(MATCH_NOMATCH);
            break;

            case OP_DIGIT:
            if ((md->ctypes[c] & ctype_digit) == 0) RRETURN(MATCH_NOMATCH);
            break;

            case OP_NOT_WHITESPACE:
            if ((md->ctypes[c] & ctype_space) != 0) RRETURN(MATCH_NOMATCH);
            break;

            case OP_WHITESPACE:
            if  ((md->ctypes[c] & ctype_space) == 0) RRETURN(MATCH_NOMATCH);
            break;

            case OP_NOT_WORDCHAR:
            if ((md->ctypes[c] & ctype_word) != 0) RRETURN(MATCH_NOMATCH);
            break;

            case OP_WORDCHAR:
            if ((md->ctypes[c] & ctype_word) == 0) RRETURN(MATCH_NOMATCH);
            break;

            default:
            RRETURN(PCRE_ERROR_INTERNAL);
            }
          }
        }
      /* Control never gets here */
      }

    /* If maximizing, it is worth using inline code for speed, doing the type
    test once at the start (i.e. keep it out of the loop). Again, keep the
    UTF-8 and UCP stuff separate. */

    else
      {
      pp = eptr;  /* Remember where we started */

#ifdef SUPPORT_UCP
      if (prop_type >= 0)
        {
        switch(prop_type)
          {
          case PT_ANY:
          for (i = min; i < max; i++)
            {
            int len = 1;
            if (eptr >= md->end_subject) break;
            GETCHARLEN(c, eptr, len);
            if (prop_fail_result) break;
            eptr+= len;
            }
          break;

          case PT_LAMP:
          for (i = min; i < max; i++)
            {
            int len = 1;
            if (eptr >= md->end_subject) break;
            GETCHARLEN(c, eptr, len);
            prop_chartype = UCD_CHARTYPE(c);
            if ((prop_chartype == ucp_Lu ||
                 prop_chartype == ucp_Ll ||
                 prop_chartype == ucp_Lt) == prop_fail_result)
              break;
            eptr+= len;
            }
          break;

          case PT_GC:
          for (i = min; i < max; i++)
            {
            int len = 1;
            if (eptr >= md->end_subject) break;
            GETCHARLEN(c, eptr, len);
            prop_category = UCD_CATEGORY(c);
            if ((prop_category == prop_value) == prop_fail_result)
              break;
            eptr+= len;
            }
          break;

          case PT_PC:
          for (i = min; i < max; i++)
            {
            int len = 1;
            if (eptr >= md->end_subject) break;
            GETCHARLEN(c, eptr, len);
            prop_chartype = UCD_CHARTYPE(c);
            if ((prop_chartype == prop_value) == prop_fail_result)
              break;
            eptr+= len;
            }
          break;

          case PT_SC:
          for (i = min; i < max; i++)
            {
            int len = 1;
            if (eptr >= md->end_subject) break;
            GETCHARLEN(c, eptr, len);
            prop_script = UCD_SCRIPT(c);
            if ((prop_script == prop_value) == prop_fail_result)
              break;
            eptr+= len;
            }
          break;
          }

        /* eptr is now past the end of the maximum run */

        if (possessive) continue;
        for(;;)
          {
          RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM44);
          if (rrc != MATCH_NOMATCH) RRETURN(rrc);
          if (eptr-- == pp) break;        /* Stop if tried at original pos */
          if (utf8) BACKCHAR(eptr);
          }
        }

      /* Match extended Unicode sequences. We will get here only if the
      support is in the binary; otherwise a compile-time error occurs. */

      else if (ctype == OP_EXTUNI)
        {
        for (i = min; i < max; i++)
          {
          if (eptr >= md->end_subject) break;
          GETCHARINCTEST(c, eptr);
          prop_category = UCD_CATEGORY(c);
          if (prop_category == ucp_M) break;
          while (eptr < md->end_subject)
            {
            int len = 1;
            if (!utf8) c = *eptr; else
              {
              GETCHARLEN(c, eptr, len);
              }
            prop_category = UCD_CATEGORY(c);
            if (prop_category != ucp_M) break;
            eptr += len;
            }
          }

        /* eptr is now past the end of the maximum run */

        if (possessive) continue;
        for(;;)
          {
          RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM45);
          if (rrc != MATCH_NOMATCH) RRETURN(rrc);
          if (eptr-- == pp) break;        /* Stop if tried at original pos */
          for (;;)                        /* Move back over one extended */
            {
            int len = 1;
            if (!utf8) c = *eptr; else
              {
              BACKCHAR(eptr);
              GETCHARLEN(c, eptr, len);
              }
            prop_category = UCD_CATEGORY(c);
            if (prop_category != ucp_M) break;
            eptr--;
            }
          }
        }

      else
#endif   /* SUPPORT_UCP */

#ifdef SUPPORT_UTF8
      /* UTF-8 mode */

      if (utf8)
        {
        switch(ctype)
          {
          case OP_ANY:
          if (max < INT_MAX)
            {
            for (i = min; i < max; i++)
              {
              if (eptr >= md->end_subject || IS_NEWLINE(eptr)) break;
              eptr++;
              while (eptr < md->end_subject && (*eptr & 0xc0) == 0x80) eptr++;
              }
            }

          /* Handle unlimited UTF-8 repeat */

          else
            {
            for (i = min; i < max; i++)
              {
              if (eptr >= md->end_subject || IS_NEWLINE(eptr)) break;
              eptr++;
              while (eptr < md->end_subject && (*eptr & 0xc0) == 0x80) eptr++;
              }
            }
          break;

          case OP_ALLANY:
          if (max < INT_MAX)
            {
            for (i = min; i < max; i++)
              {
              if (eptr >= md->end_subject) break;
              eptr++;
              while (eptr < md->end_subject && (*eptr & 0xc0) == 0x80) eptr++;
              }
            }
          else eptr = md->end_subject;   /* Unlimited UTF-8 repeat */
          break;

          /* The byte case is the same as non-UTF8 */

          case OP_ANYBYTE:
          c = max - min;
          if (c > (unsigned int)(md->end_subject - eptr))
            c = (int)(md->end_subject - eptr);
          eptr += c;
          break;

          case OP_ANYNL:
          for (i = min; i < max; i++)
            {
            int len = 1;
            if (eptr >= md->end_subject) break;
            GETCHARLEN(c, eptr, len);
            if (c == 0x000d)
              {
              if (++eptr >= md->end_subject) break;
              if (*eptr == 0x000a) eptr++;
              }
            else
              {
              if (c != 0x000a &&
                  (md->bsr_anycrlf ||
                   (c != 0x000b && c != 0x000c &&
                    c != 0x0085 && c != 0x2028 && c != 0x2029)))
                break;
              eptr += len;
              }
            }
          break;

          case OP_NOT_HSPACE:
          case OP_HSPACE:
          for (i = min; i < max; i++)
            {
            BOOL gotspace;
            int len = 1;
            if (eptr >= md->end_subject) break;
            GETCHARLEN(c, eptr, len);
            switch(c)
              {
              default: gotspace = FALSE; break;
              case 0x09:      /* HT */
              case 0x20:      /* SPACE */
              case 0xa0:      /* NBSP */
              case 0x1680:    /* OGHAM SPACE MARK */
              case 0x180e:    /* MONGOLIAN VOWEL SEPARATOR */
              case 0x2000:    /* EN QUAD */
              case 0x2001:    /* EM QUAD */
              case 0x2002:    /* EN SPACE */
              case 0x2003:    /* EM SPACE */
              case 0x2004:    /* THREE-PER-EM SPACE */
              case 0x2005:    /* FOUR-PER-EM SPACE */
              case 0x2006:    /* SIX-PER-EM SPACE */
              case 0x2007:    /* FIGURE SPACE */
              case 0x2008:    /* PUNCTUATION SPACE */
              case 0x2009:    /* THIN SPACE */
              case 0x200A:    /* HAIR SPACE */
              case 0x202f:    /* NARROW NO-BREAK SPACE */
              case 0x205f:    /* MEDIUM MATHEMATICAL SPACE */
              case 0x3000:    /* IDEOGRAPHIC SPACE */
              gotspace = TRUE;
              break;
              }
            if (gotspace == (ctype == OP_NOT_HSPACE)) break;
            eptr += len;
            }
          break;

          case OP_NOT_VSPACE:
          case OP_VSPACE:
          for (i = min; i < max; i++)
            {
            BOOL gotspace;
            int len = 1;
            if (eptr >= md->end_subject) break;
            GETCHARLEN(c, eptr, len);
            switch(c)
              {
              default: gotspace = FALSE; break;
              case 0x0a:      /* LF */
              case 0x0b:      /* VT */
              case 0x0c:      /* FF */
              case 0x0d:      /* CR */
              case 0x85:      /* NEL */
              case 0x2028:    /* LINE SEPARATOR */
              case 0x2029:    /* PARAGRAPH SEPARATOR */
              gotspace = TRUE;
              break;
              }
            if (gotspace == (ctype == OP_NOT_VSPACE)) break;
            eptr += len;
            }
          break;

          case OP_NOT_DIGIT:
          for (i = min; i < max; i++)
            {
            int len = 1;
            if (eptr >= md->end_subject) break;
            GETCHARLEN(c, eptr, len);
            if (c < 256 && (md->ctypes[c] & ctype_digit) != 0) break;
            eptr+= len;
            }
          break;

          case OP_DIGIT:
          for (i = min; i < max; i++)
            {
            int len = 1;
            if (eptr >= md->end_subject) break;
            GETCHARLEN(c, eptr, len);
            if (c >= 256 ||(md->ctypes[c] & ctype_digit) == 0) break;
            eptr+= len;
            }
          break;

          case OP_NOT_WHITESPACE:
          for (i = min; i < max; i++)
            {
            int len = 1;
            if (eptr >= md->end_subject) break;
            GETCHARLEN(c, eptr, len);
            if (c < 256 && (md->ctypes[c] & ctype_space) != 0) break;
            eptr+= len;
            }
          break;

          case OP_WHITESPACE:
          for (i = min; i < max; i++)
            {
            int len = 1;
            if (eptr >= md->end_subject) break;
            GETCHARLEN(c, eptr, len);
            if (c >= 256 ||(md->ctypes[c] & ctype_space) == 0) break;
            eptr+= len;
            }
          break;

          case OP_NOT_WORDCHAR:
          for (i = min; i < max; i++)
            {
            int len = 1;
            if (eptr >= md->end_subject) break;
            GETCHARLEN(c, eptr, len);
            if (c < 256 && (md->ctypes[c] & ctype_word) != 0) break;
            eptr+= len;
            }
          break;

          case OP_WORDCHAR:
          for (i = min; i < max; i++)
            {
            int len = 1;
            if (eptr >= md->end_subject) break;
            GETCHARLEN(c, eptr, len);
            if (c >= 256 || (md->ctypes[c] & ctype_word) == 0) break;
            eptr+= len;
            }
          break;

          default:
          RRETURN(PCRE_ERROR_INTERNAL);
          }

        /* eptr is now past the end of the maximum run */

        if (possessive) continue;
        for(;;)
          {
          RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM46);
          if (rrc != MATCH_NOMATCH) RRETURN(rrc);
          if (eptr-- == pp) break;        /* Stop if tried at original pos */
          BACKCHAR(eptr);
          }
        }
      else
#endif  /* SUPPORT_UTF8 */

      /* Not UTF-8 mode */
        {
        switch(ctype)
          {
          case OP_ANY:
          for (i = min; i < max; i++)
            {
            if (eptr >= md->end_subject || IS_NEWLINE(eptr)) break;
            eptr++;
            }
          break;

          case OP_ALLANY:
          case OP_ANYBYTE:
          c = max - min;
          if (c > (unsigned int)(md->end_subject - eptr))
            c = (int)(md->end_subject - eptr);
          eptr += c;
          break;

          case OP_ANYNL:
          for (i = min; i < max; i++)
            {
            if (eptr >= md->end_subject) break;
            c = *eptr;
            if (c == 0x000d)
              {
              if (++eptr >= md->end_subject) break;
              if (*eptr == 0x000a) eptr++;
              }
            else
              {
              if (c != 0x000a &&
                  (md->bsr_anycrlf ||
                    (c != 0x000b && c != 0x000c && c != 0x0085)))
                break;
              eptr++;
              }
            }
          break;

          case OP_NOT_HSPACE:
          for (i = min; i < max; i++)
            {
            if (eptr >= md->end_subject) break;
            c = *eptr;
            if (c == 0x09 || c == 0x20 || c == 0xa0) break;
            eptr++;
            }
          break;

          case OP_HSPACE:
          for (i = min; i < max; i++)
            {
            if (eptr >= md->end_subject) break;
            c = *eptr;
            if (c != 0x09 && c != 0x20 && c != 0xa0) break;
            eptr++;
            }
          break;

          case OP_NOT_VSPACE:
          for (i = min; i < max; i++)
            {
            if (eptr >= md->end_subject) break;
            c = *eptr;
            if (c == 0x0a || c == 0x0b || c == 0x0c || c == 0x0d || c == 0x85)
              break;
            eptr++;
            }
          break;

          case OP_VSPACE:
          for (i = min; i < max; i++)
            {
            if (eptr >= md->end_subject) break;
            c = *eptr;
            if (c != 0x0a && c != 0x0b && c != 0x0c && c != 0x0d && c != 0x85)
              break;
            eptr++;
            }
          break;

          case OP_NOT_DIGIT:
          for (i = min; i < max; i++)
            {
            if (eptr >= md->end_subject || (md->ctypes[*eptr] & ctype_digit) != 0)
              break;
            eptr++;
            }
          break;

          case OP_DIGIT:
          for (i = min; i < max; i++)
            {
            if (eptr >= md->end_subject || (md->ctypes[*eptr] & ctype_digit) == 0)
              break;
            eptr++;
            }
          break;

          case OP_NOT_WHITESPACE:
          for (i = min; i < max; i++)
            {
            if (eptr >= md->end_subject || (md->ctypes[*eptr] & ctype_space) != 0)
              break;
            eptr++;
            }
          break;

          case OP_WHITESPACE:
          for (i = min; i < max; i++)
            {
            if (eptr >= md->end_subject || (md->ctypes[*eptr] & ctype_space) == 0)
              break;
            eptr++;
            }
          break;

          case OP_NOT_WORDCHAR:
          for (i = min; i < max; i++)
            {
            if (eptr >= md->end_subject || (md->ctypes[*eptr] & ctype_word) != 0)
              break;
            eptr++;
            }
          break;

          case OP_WORDCHAR:
          for (i = min; i < max; i++)
            {
            if (eptr >= md->end_subject || (md->ctypes[*eptr] & ctype_word) == 0)
              break;
            eptr++;
            }
          break;

          default:
          RRETURN(PCRE_ERROR_INTERNAL);
          }

        /* eptr is now past the end of the maximum run */

        if (possessive) continue;
        while (eptr >= pp)
          {
          RMATCH(eptr, ecode, offset_top, md, ims, eptrb, 0, RM47);
          eptr--;
          if (rrc != MATCH_NOMATCH) RRETURN(rrc);
          }
        }

      /* Get here if we can't make it match with any permitted repetitions */

      RRETURN(MATCH_NOMATCH);
      }
    /* Control never gets here */

    /* There's been some horrible disaster. Arrival here can only mean there is
    something seriously wrong in the code above or the OP_xxx definitions. */

    default:
    DPRINTF(("Unknown opcode %d\n", *ecode));
    RRETURN(PCRE_ERROR_UNKNOWN_OPCODE);
    }

  /* Do not stick any code in here without much thought; it is assumed
  that "continue" in the code above comes out to here to repeat the main
  loop. */

  }             /* End of main loop */
/* Control never reaches here */


/* When compiling to use the heap rather than the stack for recursive calls to
match(), the RRETURN() macro jumps here. The number that is saved in
frame->Xwhere indicates which label we actually want to return to. */

#ifdef NO_RECURSE
#define LBL(val) case val: goto L_RM##val;
HEAP_RETURN:
switch (frame->Xwhere)
  {
  LBL( 1) LBL( 2) LBL( 3) LBL( 4) LBL( 5) LBL( 6) LBL( 7) LBL( 8)
  LBL( 9) LBL(10) LBL(11) LBL(12) LBL(13) LBL(14) LBL(15) LBL(17)
  LBL(19) LBL(24) LBL(25) LBL(26) LBL(27) LBL(29) LBL(31) LBL(33)
  LBL(35) LBL(43) LBL(47) LBL(48) LBL(49) LBL(50) LBL(51) LBL(52)
  LBL(53) LBL(54)
#ifdef SUPPORT_UTF8
  LBL(16) LBL(18) LBL(20) LBL(21) LBL(22) LBL(23) LBL(28) LBL(30)
  LBL(32) LBL(34) LBL(42) LBL(46)
#ifdef SUPPORT_UCP
  LBL(36) LBL(37) LBL(38) LBL(39) LBL(40) LBL(41) LBL(44) LBL(45)
#endif  /* SUPPORT_UCP */
#endif  /* SUPPORT_UTF8 */
  default:
  DPRINTF(("jump error in pcre match: label %d non-existent\n", frame->Xwhere));
  return PCRE_ERROR_INTERNAL;
  }
#undef LBL
#endif  /* NO_RECURSE */
}


/*************************************************
*         Execute a Regular Expression           *
*************************************************/

/* This function applies a compiled re to a subject string and picks out
portions of the string if it matches. Two elements in the vector are set for
each substring: the offsets to the start and end of the substring.

Arguments:
  argument_re     points to the compiled expression
  extra_data      points to extra data or is NULL
  subject         points to the subject string
  length          length of subject string (may contain binary zeros)
  start_offset    where to start in the subject string
  options         option bits
  offsets         points to a vector of ints to be filled in with offsets
  offsetcount     the number of elements in the vector

Returns:          > 0 => success; value is the number of elements filled in
                  = 0 => success, but offsets is not big enough
                   -1 => failed to match
                 < -1 => some kind of unexpected problem
*/
PCRE_EXP_DEFN int
pcre_exec(const pcre *argument_re, const pcre_extra *extra_data,
  PCRE_SPTR subject, int length, int start_offset, int options, int *offsets,
  int offsetcount)
{
int rc, resetcount, ocount;
int first_byte = -1;
int req_byte = -1;
int req_byte2 = -1;
int newline;
unsigned long int ims;
BOOL using_temporary_offsets = FALSE;
BOOL anchored;
BOOL startline;
BOOL firstline;
BOOL first_byte_caseless = FALSE;
BOOL req_byte_caseless = FALSE;
BOOL utf8;
match_data match_block;
match_data *md = &match_block;
const uschar *tables;
const uschar *start_bits = NULL;
USPTR start_match = (USPTR)subject + start_offset;
USPTR end_subject;
USPTR req_byte_ptr = start_match - 1;

pcre_study_data internal_study;
const pcre_study_data *study;

real_pcre internal_re;
const real_pcre *external_re = (const real_pcre *)argument_re;
const real_pcre *re = external_re;

/* Plausibility checks */

if ((options & ~PUBLIC_EXEC_OPTIONS) != 0) return PCRE_ERROR_BADOPTION;
if (re == NULL || subject == NULL ||
   (offsets == NULL && offsetcount > 0)) return PCRE_ERROR_NULL;
if (offsetcount < 0) return PCRE_ERROR_BADCOUNT;

/* Fish out the optional data from the extra_data structure, first setting
the default values. */

study = NULL;
md->match_limit = MATCH_LIMIT;
md->match_limit_recursion = MATCH_LIMIT_RECURSION;
md->callout_data = NULL;

/* The table pointer is always in native byte order. */

tables = external_re->tables;

if (extra_data != NULL)
  {
  register unsigned int flags = extra_data->flags;
  if ((flags & PCRE_EXTRA_STUDY_DATA) != 0)
    study = (const pcre_study_data *)extra_data->study_data;
  if ((flags & PCRE_EXTRA_MATCH_LIMIT) != 0)
    md->match_limit = extra_data->match_limit;
  if ((flags & PCRE_EXTRA_MATCH_LIMIT_RECURSION) != 0)
    md->match_limit_recursion = extra_data->match_limit_recursion;
  if ((flags & PCRE_EXTRA_CALLOUT_DATA) != 0)
    md->callout_data = extra_data->callout_data;
  if ((flags & PCRE_EXTRA_TABLES) != 0) tables = extra_data->tables;
  }

/* If the exec call supplied NULL for tables, use the inbuilt ones. This
is a feature that makes it possible to save compiled regex and re-use them
in other programs later. */

if (tables == NULL) tables = _pcre_default_tables;

/* Check that the first field in the block is the magic number. If it is not,
test for a regex that was compiled on a host of opposite endianness. If this is
the case, flipped values are put in internal_re and internal_study if there was
study data too. */

if (re->magic_number != MAGIC_NUMBER)
  {
  re = _pcre_try_flipped(re, &internal_re, study, &internal_study);
  if (re == NULL) return PCRE_ERROR_BADMAGIC;
  if (study != NULL) study = &internal_study;
  }

/* Set up other data */

anchored = ((re->options | options) & PCRE_ANCHORED) != 0;
startline = (re->flags & PCRE_STARTLINE) != 0;
firstline = (re->options & PCRE_FIRSTLINE) != 0;

/* The code starts after the real_pcre block and the capture name table. */

md->start_code = (const uschar *)external_re + re->name_table_offset +
  re->name_count * re->name_entry_size;

md->start_subject = (USPTR)subject;
md->start_offset = start_offset;
md->end_subject = md->start_subject + length;
end_subject = md->end_subject;

md->endonly = (re->options & PCRE_DOLLAR_ENDONLY) != 0;
utf8 = md->utf8 = (re->options & PCRE_UTF8) != 0;
md->jscript_compat = (re->options & PCRE_JAVASCRIPT_COMPAT) != 0;

md->notbol = (options & PCRE_NOTBOL) != 0;
md->noteol = (options & PCRE_NOTEOL) != 0;
md->notempty = (options & PCRE_NOTEMPTY) != 0;
md->partial = (options & PCRE_PARTIAL) != 0;
md->hitend = FALSE;

md->recursive = NULL;                   /* No recursion at top level */

md->lcc = tables + lcc_offset;
md->ctypes = tables + ctypes_offset;

/* Handle different \R options. */

switch (options & (PCRE_BSR_ANYCRLF|PCRE_BSR_UNICODE))
  {
  case 0:
  if ((re->options & (PCRE_BSR_ANYCRLF|PCRE_BSR_UNICODE)) != 0)
    md->bsr_anycrlf = (re->options & PCRE_BSR_ANYCRLF) != 0;
  else
#ifdef BSR_ANYCRLF
  md->bsr_anycrlf = TRUE;
#else
  md->bsr_anycrlf = FALSE;
#endif
  break;

  case PCRE_BSR_ANYCRLF:
  md->bsr_anycrlf = TRUE;
  break;

  case PCRE_BSR_UNICODE:
  md->bsr_anycrlf = FALSE;
  break;

  default: return PCRE_ERROR_BADNEWLINE;
  }

/* Handle different types of newline. The three bits give eight cases. If
nothing is set at run time, whatever was used at compile time applies. */

switch ((((options & PCRE_NEWLINE_BITS) == 0)? re->options :
        (pcre_uint32)options) & PCRE_NEWLINE_BITS)
  {
  case 0: newline = NEWLINE; break;   /* Compile-time default */
  case PCRE_NEWLINE_CR: newline = '\r'; break;
  case PCRE_NEWLINE_LF: newline = '\n'; break;
  case PCRE_NEWLINE_CR+
       PCRE_NEWLINE_LF: newline = ('\r' << 8) | '\n'; break;
  case PCRE_NEWLINE_ANY: newline = -1; break;
  case PCRE_NEWLINE_ANYCRLF: newline = -2; break;
  default: return PCRE_ERROR_BADNEWLINE;
  }

if (newline == -2)
  {
  md->nltype = NLTYPE_ANYCRLF;
  }
else if (newline < 0)
  {
  md->nltype = NLTYPE_ANY;
  }
else
  {
  md->nltype = NLTYPE_FIXED;
  if (newline > 255)
    {
    md->nllen = 2;
    md->nl[0] = (uschar)((newline >> 8) & 255);
    md->nl[1] = (uschar)(newline & 255);
    }
  else
    {
    md->nllen = 1;
    md->nl[0] = (uschar)(newline);
    }
  }

/* Partial matching is supported only for a restricted set of regexes at the
moment. */

if (md->partial && (re->flags & PCRE_NOPARTIAL) != 0)
  return PCRE_ERROR_BADPARTIAL;

/* Check a UTF-8 string if required. Unfortunately there's no way of passing
back the character offset. */

#ifdef SUPPORT_UTF8
if (utf8 && (options & PCRE_NO_UTF8_CHECK) == 0)
  {
  if (_pcre_valid_utf8((uschar *)subject, length) >= 0)
    return PCRE_ERROR_BADUTF8;
  if (start_offset > 0 && start_offset < length)
    {
    int tb = ((uschar *)subject)[start_offset];
    if (tb > 127)
      {
      tb &= 0xc0;
      if (tb != 0 && tb != 0xc0) return PCRE_ERROR_BADUTF8_OFFSET;
      }
    }
  }
#endif

/* The ims options can vary during the matching as a result of the presence
of (?ims) items in the pattern. They are kept in a local variable so that
restoring at the exit of a group is easy. */

ims = re->options & (PCRE_CASELESS|PCRE_MULTILINE|PCRE_DOTALL);

/* If the expression has got more back references than the offsets supplied can
hold, we get a temporary chunk of working store to use during the matching.
Otherwise, we can use the vector supplied, rounding down its size to a multiple
of 3. */

ocount = offsetcount - (offsetcount % 3);

if (re->top_backref > 0 && re->top_backref >= ocount/3)
  {
  ocount = re->top_backref * 3 + 3;
  md->offset_vector = (int *)(pcre_malloc)(ocount * sizeof(int));
  if (md->offset_vector == NULL) return PCRE_ERROR_NOMEMORY;
  using_temporary_offsets = TRUE;
  DPRINTF(("Got memory to hold back references\n"));
  }
else md->offset_vector = offsets;

md->offset_end = ocount;
md->offset_max = (2*ocount)/3;
md->offset_overflow = FALSE;
md->capture_last = -1;

/* Compute the minimum number of offsets that we need to reset each time. Doing
this makes a huge difference to execution time when there aren't many brackets
in the pattern. */

resetcount = 2 + re->top_bracket * 2;
if (resetcount > offsetcount) resetcount = ocount;

/* Reset the working variable associated with each extraction. These should
never be used unless previously set, but they get saved and restored, and so we
initialize them to avoid reading uninitialized locations. */

if (md->offset_vector != NULL)
  {
  register int *iptr = md->offset_vector + ocount;
  register int *iend = iptr - resetcount/2 + 1;
  while (--iptr >= iend) *iptr = -1;
  }

/* Set up the first character to match, if available. The first_byte value is
never set for an anchored regular expression, but the anchoring may be forced
at run time, so we have to test for anchoring. The first char may be unset for
an unanchored pattern, of course. If there's no first char and the pattern was
studied, there may be a bitmap of possible first characters. */

if (!anchored)
  {
  if ((re->flags & PCRE_FIRSTSET) != 0)
    {
    first_byte = re->first_byte & 255;
    if ((first_byte_caseless = ((re->first_byte & REQ_CASELESS) != 0)) == TRUE)
      first_byte = md->lcc[first_byte];
    }
  else
    if (!startline && study != NULL &&
      (study->options & PCRE_STUDY_MAPPED) != 0)
        start_bits = study->start_bits;
  }

/* For anchored or unanchored matches, there may be a "last known required
character" set. */

if ((re->flags & PCRE_REQCHSET) != 0)
  {
  req_byte = re->req_byte & 255;
  req_byte_caseless = (re->req_byte & REQ_CASELESS) != 0;
  req_byte2 = (tables + fcc_offset)[req_byte];  /* case flipped */
  }


/* ==========================================================================*/

/* Loop for handling unanchored repeated matching attempts; for anchored regexs
the loop runs just once. */

for(;;)
  {
  USPTR save_end_subject = end_subject;
  USPTR new_start_match;

  /* Reset the maximum number of extractions we might see. */

  if (md->offset_vector != NULL)
    {
    register int *iptr = md->offset_vector;
    register int *iend = iptr + resetcount;
    while (iptr < iend) *iptr++ = -1;
    }

  /* Advance to a unique first char if possible. If firstline is TRUE, the
  start of the match is constrained to the first line of a multiline string.
  That is, the match must be before or at the first newline. Implement this by
  temporarily adjusting end_subject so that we stop scanning at a newline. If
  the match fails at the newline, later code breaks this loop. */

  if (firstline)
    {
    USPTR t = start_match;
#ifdef SUPPORT_UTF8
    if (utf8)
      {
      while (t < md->end_subject && !IS_NEWLINE(t))
        {
        t++;
        while (t < end_subject && (*t & 0xc0) == 0x80) t++;
        }
      }
    else
#endif
    while (t < md->end_subject && !IS_NEWLINE(t)) t++;
    end_subject = t;
    }

  /* Now advance to a unique first byte if there is one. */

  if (first_byte >= 0)
    {
    if (first_byte_caseless)
      while (start_match < end_subject && md->lcc[*start_match] != first_byte)
        start_match++;
    else
      while (start_match < end_subject && *start_match != first_byte)
        start_match++;
    }

  /* Or to just after a linebreak for a multiline match */

  else if (startline)
    {
    if (start_match > md->start_subject + start_offset)
      {
#ifdef SUPPORT_UTF8
      if (utf8)
        {
        while (start_match < end_subject && !WAS_NEWLINE(start_match))
          {
          start_match++;
          while(start_match < end_subject && (*start_match & 0xc0) == 0x80)
            start_match++;
          }
        }
      else
#endif
      while (start_match < end_subject && !WAS_NEWLINE(start_match))
        start_match++;

      /* If we have just passed a CR and the newline option is ANY or ANYCRLF,
      and we are now at a LF, advance the match position by one more character.
      */

      if (start_match[-1] == '\r' &&
           (md->nltype == NLTYPE_ANY || md->nltype == NLTYPE_ANYCRLF) &&
           start_match < end_subject &&
           *start_match == '\n')
        start_match++;
      }
    }

  /* Or to a non-unique first byte after study */

  else if (start_bits != NULL)
    {
    while (start_match < end_subject)
      {
      register unsigned int c = *start_match;
      if ((start_bits[c/8] & (1 << (c&7))) == 0) start_match++;
        else break;
      }
    }

  /* Restore fudged end_subject */

  end_subject = save_end_subject;

#ifdef DEBUG  /* Sigh. Some compilers never learn. */
  printf(">>>> Match against: ");
  pchars(start_match, end_subject - start_match, TRUE, md);
  printf("\n");
#endif

  /* If req_byte is set, we know that that character must appear in the subject
  for the match to succeed. If the first character is set, req_byte must be
  later in the subject; otherwise the test starts at the match point. This
  optimization can save a huge amount of backtracking in patterns with nested
  unlimited repeats that aren't going to match. Writing separate code for
  cased/caseless versions makes it go faster, as does using an autoincrement
  and backing off on a match.

  HOWEVER: when the subject string is very, very long, searching to its end can
  take a long time, and give bad performance on quite ordinary patterns. This
  showed up when somebody was matching something like /^\d+C/ on a 32-megabyte
  string... so we don't do this when the string is sufficiently long.

  ALSO: this processing is disabled when partial matching is requested.
  */

  if (req_byte >= 0 &&
      end_subject - start_match < REQ_BYTE_MAX &&
      !md->partial)
    {
    register USPTR p = start_match + ((first_byte >= 0)? 1 : 0);

    /* We don't need to repeat the search if we haven't yet reached the
    place we found it at last time. */

    if (p > req_byte_ptr)
      {
      if (req_byte_caseless)
        {
        while (p < end_subject)
          {
          register int pp = *p++;
          if (pp == req_byte || pp == req_byte2) { p--; break; }
          }
        }
      else
        {
        while (p < end_subject)
          {
          if (*p++ == req_byte) { p--; break; }
          }
        }

      /* If we can't find the required character, break the matching loop,
      forcing a match failure. */

      if (p >= end_subject)
        {
        rc = MATCH_NOMATCH;
        break;
        }

      /* If we have found the required character, save the point where we
      found it, so that we don't search again next time round the loop if
      the start hasn't passed this character yet. */

      req_byte_ptr = p;
      }
    }

  /* OK, we can now run the match. */

  md->start_match_ptr = start_match;
  md->match_call_count = 0;
  rc = match(start_match, md->start_code, start_match, 2, md, ims, NULL, 0, 0);

  switch(rc)
    {
    /* NOMATCH and PRUNE advance by one character. THEN at this level acts
    exactly like PRUNE. */

    case MATCH_NOMATCH:
    case MATCH_PRUNE:
    case MATCH_THEN:
    new_start_match = start_match + 1;
#ifdef SUPPORT_UTF8
    if (utf8)
      while(new_start_match < end_subject && (*new_start_match & 0xc0) == 0x80)
        new_start_match++;
#endif
    break;

    /* SKIP passes back the next starting point explicitly. */

    case MATCH_SKIP:
    new_start_match = md->start_match_ptr;
    break;

    /* COMMIT disables the bumpalong, but otherwise behaves as NOMATCH. */

    case MATCH_COMMIT:
    rc = MATCH_NOMATCH;
    goto ENDLOOP;

    /* Any other return is some kind of error. */

    default:
    goto ENDLOOP;
    }

  /* Control reaches here for the various types of "no match at this point"
  result. Reset the code to MATCH_NOMATCH for subsequent checking. */

  rc = MATCH_NOMATCH;

  /* If PCRE_FIRSTLINE is set, the match must happen before or at the first
  newline in the subject (though it may continue over the newline). Therefore,
  if we have just failed to match, starting at a newline, do not continue. */

  if (firstline && IS_NEWLINE(start_match)) break;

  /* Advance to new matching position */

  start_match = new_start_match;

  /* Break the loop if the pattern is anchored or if we have passed the end of
  the subject. */

  if (anchored || start_match > end_subject) break;

  /* If we have just passed a CR and we are now at a LF, and the pattern does
  not contain any explicit matches for \r or \n, and the newline option is CRLF
  or ANY or ANYCRLF, advance the match position by one more character. */

  if (start_match[-1] == '\r' &&
      start_match < end_subject &&
      *start_match == '\n' &&
      (re->flags & PCRE_HASCRORLF) == 0 &&
        (md->nltype == NLTYPE_ANY ||
         md->nltype == NLTYPE_ANYCRLF ||
         md->nllen == 2))
    start_match++;

  }   /* End of for(;;) "bumpalong" loop */

/* ==========================================================================*/

/* We reach here when rc is not MATCH_NOMATCH, or if one of the stopping
conditions is true:

(1) The pattern is anchored or the match was failed by (*COMMIT);

(2) We are past the end of the subject;

(3) PCRE_FIRSTLINE is set and we have failed to match at a newline, because
    this option requests that a match occur at or before the first newline in
    the subject.

When we have a match and the offset vector is big enough to deal with any
backreferences, captured substring offsets will already be set up. In the case
where we had to get some local store to hold offsets for backreference
processing, copy those that we can. In this case there need not be overflow if
certain parts of the pattern were not used, even though there are more
capturing parentheses than vector slots. */

ENDLOOP:

if (rc == MATCH_MATCH)
  {
  if (using_temporary_offsets)
    {
    if (offsetcount >= 4)
      {
      memcpy(offsets + 2, md->offset_vector + 2,
        (offsetcount - 2) * sizeof(int));
      DPRINTF(("Copied offsets from temporary memory\n"));
      }
    if (md->end_offset_top > offsetcount) md->offset_overflow = TRUE;
    DPRINTF(("Freeing temporary memory\n"));
    (pcre_free)(md->offset_vector);
    }

  /* Set the return code to the number of captured strings, or 0 if there are
  too many to fit into the vector. */

  rc = md->offset_overflow? 0 : md->end_offset_top/2;

  /* If there is space, set up the whole thing as substring 0. The value of
  md->start_match_ptr might be modified if \K was encountered on the success
  matching path. */

  if (offsetcount < 2) rc = 0; else
    {
    offsets[0] = (int)(md->start_match_ptr - md->start_subject);
    offsets[1] = (int)(md->end_match_ptr - md->start_subject);
    }

  DPRINTF((">>>> returning %d\n", rc));
  return rc;
  }

/* Control gets here if there has been an error, or if the overall match
attempt has failed at all permitted starting positions. */

if (using_temporary_offsets)
  {
  DPRINTF(("Freeing temporary memory\n"));
  (pcre_free)(md->offset_vector);
  }

if (rc != MATCH_NOMATCH)
  {
  DPRINTF((">>>> error: returning %d\n", rc));
  return rc;
  }
else if (md->partial && md->hitend)
  {
  DPRINTF((">>>> returning PCRE_ERROR_PARTIAL\n"));
  return PCRE_ERROR_PARTIAL;
  }
else
  {
  DPRINTF((">>>> returning PCRE_ERROR_NOMATCH\n"));
  return PCRE_ERROR_NOMATCH;
  }
}


/*+-------------------------------------------------------------------------+*/
/*| HOB added functions:                                                    |*/
/*+-------------------------------------------------------------------------+*/

/**
 * parse regular expression
 * cut off leading and trailing slash '/' and read following options
 *
 * @param[in]   const char*         ach_regexp          regular expression
 *                                                      example "/\s/g"
 * @param[in]   int                 in_len_regexp       length of regexp
 * @param[out]  char**              aach_out            changed reg exp
 * @param[out]  int*                ain_options         parsed options
 * @param[out]  BOOL*               abo_find_all        is option 'g' active?
 *
 * @return      BOOL
*/
BOOL m_parse_regexp( const char* ach_regexp, int in_len_regexp,
                     char** aach_out, int* ain_options, BOOL* abo_find_all )
{
    // initialize some variables:
    int  inl_start = 0;         // start position
    int  inl_end   = 0;         // end position
    BOOL bol_slash = FALSE;     // regular expressiong started with slash

    inl_end = in_len_regexp - 1;

    // find leading slash:
    for( ; inl_start < in_len_regexp; inl_start++ ) {
        switch ( ach_regexp[inl_start] ) {
            case '/':
                inl_start++;
                bol_slash = TRUE;
                break;
            case ' ':
            case '\t':
            case '\v':
            case '\r':
            case '\n':
            case '\f':
                // ignore whitespaces
                continue;
            default:
                break;
        } // end of switch
        break;
    } // end of for

    if ( bol_slash == TRUE ) {
        for ( ; inl_end >= 0; inl_end-- ) {
            switch( ach_regexp[inl_end] ) {
                case '/':
                    break;
                case 'g':
                case 'G':
                    *abo_find_all = TRUE;
                    continue;
                case 'f':
                    *ain_options |= PCRE_FIRSTLINE;
                    continue;
                case 'i':
                    *ain_options |= PCRE_CASELESS;
                    continue;
                case 'm':
                    *ain_options |= PCRE_MULTILINE;
                    continue;
                case 's':
                    *ain_options |= PCRE_DOTALL;
                    continue;
                case 'x':
                    *ain_options |= PCRE_EXTENDED;
                    continue;
                case 'A':
                    *ain_options |= PCRE_ANCHORED;
                    continue;
                case 'C':
                    *ain_options |= PCRE_AUTO_CALLOUT;
                    continue;
                case 'E':
                    *ain_options |= PCRE_DOLLAR_ENDONLY;
                    continue;
                case 'J':
                    *ain_options |= PCRE_DUPNAMES;
                    continue;
                case 'N':
                    *ain_options |= PCRE_NO_AUTO_CAPTURE;
                    continue;
                case 'U':
                    *ain_options |= PCRE_UNGREEDY;
                    continue;
                case 'X':
                    *ain_options |= PCRE_EXTRA;
                    continue;
                default:
                    continue;
            } // end of switch
            break;
        } // end of for
        if ( inl_end > inl_start ) {
            *aach_out = (char*)pcre_malloc( inl_end - inl_start + 1 );
            memset( *aach_out, 0, inl_end - inl_start + 1 );
            memcpy( *aach_out, &ach_regexp[inl_start], inl_end - inl_start );
        }
    } else {
        *aach_out = (char*)pcre_malloc( in_len_regexp + 1 );
        memset( *aach_out, 0, in_len_regexp + 1 );
        memcpy( *aach_out, &ach_regexp[inl_start], in_len_regexp );
    } // end of if ( bol_slash == TRUE )

    if ( *aach_out == NULL ) {
        return FALSE;
    }

    return TRUE;
} // end of m_parse_regexp


/**
 * search with a regular expression in an utf8 string
 * if bo_find_all_matches is false, option "g" in regexp will be ignored!
 *
 * @param[in]   const char*         ach_regexp          regular expression
 *                                                      example "/\s/g"
 * @param[in]   int                 in_len_regexp       length of regexp
 * @param[in]   const char*         ach_search_in       string to search in
 *                                                      must be utf8!
 * @param[in]   int                 in_search_len       ength of ach_search_in
 * @param[out]  dsd_regexp_match2*  ads_match           matching strings
 * @param[in]   BOOL                bo_find_all_matches TRUE = search recursiv
 *                                                      (only if 'g' option is set)
 *
 * @return      BOOL
*/
BOOL m_search_regexp3( const char* ach_regexp, int in_len_regexp,
                       const char* ach_search_in, int in_search_len,
                       struct dsd_regexp_match2* ads_match,
                       BOOL bo_find_all_matches )
{

    // initialize some variables:
    BOOL  bol_ret      = FALSE;
    char* achl_parsed  = NULL;          // parsed regular expression
    int   inl_offset   = 0;             // search offset (for recursive calls)
    BOOL  bol_find_all = FALSE;         // find all matches

    // compiling variables:
    int   inl_options  = 0;             // options for pcre_compile
    pcre* adsl_regexp = NULL;           // compiled regular expression
    char* achl_error  = NULL;           // error message
    int   inl_error   = -1;             // error position in reg exp

    // search variables:
    int   inl_ret     = -1;             // return value
    int   rinl_pos[2] = { -1, -1 };     // matching position index
    dsd_regexp_match2* ads_temp = NULL;  // helper struct for filling chain


    //--------------------------------------------------------------
    // check input data:
    //--------------------------------------------------------------
    if (    ach_regexp    == NULL || in_len_regexp < 1
         || ach_search_in == NULL || in_search_len < 1
         || ads_match     == NULL                      ) {
        return FALSE;
    }

    //--------------------------------------------------------------
    // parse regexp to get options and cut of leading & trailing "/"
    //--------------------------------------------------------------
    bol_ret = m_parse_regexp( ach_regexp, in_len_regexp, &achl_parsed,
                              &inl_options, &bol_find_all );
    if ( bol_ret == FALSE ) {
        return FALSE;
    }
    // we use utf8 by default:
    inl_options |= PCRE_UTF8;

    //--------------------------------------------------------------
    // compile regular expression:
    //--------------------------------------------------------------
    adsl_regexp = pcre_compile( achl_parsed, inl_options,
                                (const char**)&achl_error,
                                &inl_error, NULL );
    pcre_free( achl_parsed ); // not used anymore
    if ( adsl_regexp == NULL ) {
        // compilation error
        return FALSE;
    }

    //--------------------------------------------------------------
    // do search:
    //--------------------------------------------------------------
    inl_ret = pcre_exec( adsl_regexp, NULL, ach_search_in, in_search_len,
                         0, PCRE_NO_UTF8_CHECK,  rinl_pos, 2 );
    if ( inl_ret < -1 ) {
        // exec returns an error
        pcre_free( adsl_regexp ); // not used anymore
        return FALSE;
    } else if ( inl_ret == -1 ) {
        // exec found no match:
        ads_match->achc_match    = NULL;
        ads_match->inc_match_len = 0;
        pcre_free( adsl_regexp ); // not used anymore
        return TRUE;
    }

    //--------------------------------------------------------------
    // set matching positions:
    //--------------------------------------------------------------
    ads_match->achc_match    = (char*)ach_search_in + rinl_pos[0];
    ads_match->inc_match_len = rinl_pos[1] - rinl_pos[0];

    //--------------------------------------------------------------
    // find all matches:
    //--------------------------------------------------------------
    if ( bol_find_all == TRUE && bo_find_all_matches == TRUE ) {
        ads_temp = ads_match;
        inl_offset = rinl_pos[1] + 1;

        // search all matches:
        for ( ; ; ) {
            // search again:
            inl_ret  = pcre_exec( adsl_regexp, NULL, ach_search_in, in_search_len,
                                  inl_offset, PCRE_NO_UTF8_CHECK,  rinl_pos, 2 );
            if ( inl_ret < -1 ) {
                // exec returns an error
                return FALSE;
            } else if ( inl_ret == -1 ) {
                // exec found no match:
                break;
            }

            // something is found -> get memory:
            if ( ads_temp->adsc_next == NULL ) {
                ads_temp->adsc_next = (dsd_regexp_match2*)pcre_malloc( sizeof(dsd_regexp_match2) );
                memset( ads_temp->adsc_next, 0, sizeof(dsd_regexp_match2) );
            }

            // save in chain:
            ads_temp                = ads_temp->adsc_next;
            ads_temp->achc_match    = (char*)ach_search_in + rinl_pos[0];
            ads_temp->inc_match_len = rinl_pos[1] - rinl_pos[0];

            // set offset behind last match:
            inl_offset              = rinl_pos[1] + 1;
        } // end of for
    } // end of if ( bol_find_all == TRUE )

    pcre_free( adsl_regexp ); // not used anymore
    return TRUE;
} // end of BOOL m_search_regexp3


/**
 * search with a regular expression in an utf8 string
 * NOTE:
 *   if there is more than one match, dsd_regexp_match2 will be filled
 *   automaticly, but memory must be freed outside!
 *
 * @param[in]   const char*         ach_regexp          regular expression
 *                                                      example "/\s/g"
 * @param[in]   int                 in_len_regexp       length of regexp
 * @param[in]   const char*         ach_search_in       string to search in
 *                                                      must be utf8!
 * @param[in]   int                 in_search_len       ength of ach_search_in
 * @param[out]  dsd_regexp_match2*  ads_match           matching strings
 *
 * @return      BOOL
*/
extern PTYPE BOOL m_search_regexp2( const char* ach_regexp, int in_len_regexp,
                                    const char* ach_search_in, int in_search_len,
                                    struct dsd_regexp_match2* ads_match )
{
    return m_search_regexp3( ach_regexp, in_len_regexp, ach_search_in,
                             in_search_len, ads_match, TRUE );
} // end of extern PTYPE BOOL m_search_regexp2


/**
 * search with a regular expression in an utf8 string
 * only first match will be returned
 *
 * @param[in]   const char*         ach_regexp          regular expression
 *                                                      example "/\s[abc]/g"
 * @param[in]   int                 in_len_regexp       length of regexp
 * @param[in]   const char*         ach_search_in       string to search in
 *                                                      must be utf8!
 * @param[in]   int                 in_search_len       ength of ach_search_in
 * @param[out]  dsd_regexp_match1*  ads_match           first match
 *
 * @return      BOOL
*/
extern PTYPE BOOL m_search_regexp1( const char* ach_regexp, int in_len_regexp,
                                    const char* ach_search_in, int in_search_len,
                                    struct dsd_regexp_match1* ads_match )
{
    // initialize some variables:
    BOOL bo_ret = FALSE;
    struct dsd_regexp_match2 ds_temp;
    memset( &ds_temp, 0, sizeof( dsd_regexp_match2 ) );

    bo_ret = m_search_regexp3( ach_regexp, in_len_regexp, ach_search_in,
                               in_search_len, &ds_temp, FALSE );

    ads_match->achc_match    = ds_temp.achc_match;
    ads_match->inc_match_len = ds_temp.inc_match_len;
    return bo_ret;
} // end of extern PTYPE BOOL m_search_regexp1
