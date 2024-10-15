#ifndef TYPES_DEFINES_H
#define TYPES_DEFINES_H

//enum language {
//  en,
//  de,
//  fr,
//  es
//};

#ifdef HL_UNIX  // --------- UNIX
    #include <unistd.h>
    
    #ifndef BOOL // JF 25.07.06
    #define BOOL int
    #endif
    
    #ifndef ULONG // JF 29.01.07
    #define ULONG unsigned long
    #endif
    
    #ifndef PVOID // JF 29.01.07
    #define PVOID void *
    #endif        
    
//    #ifndef _MAX_PATH // JF
//    #define _MAX_PATH MAXPATHLEN
//    #endif
    
    #ifndef TRUE // JF
    #define TRUE 1
    #endif    
    #ifndef FALSE // JF
    #define FALSE 0
    #endif
    
    #ifndef WCHAR // JF
    #define WCHAR wchar_t
    #endif
    
    #ifndef PINT // MJ 25.01.08
    #define PINT int*
    #endif
    #ifndef PTCHAR // MJ 25.01.08: is this true in all cases?
        #ifdef UNICODE
        #define PTCHAR WCHAR*
        #else
        #define PTCHAR char*
        #endif
    #endif
    #ifndef _TCHAR // MJ 25.01.08: is this true in all cases?
    #define _TCHAR char
    #endif
    #ifndef LPCSTR // MJ 25.01.08
    #define LPCSTR const char*
    #endif
    #ifndef PBYTE // MJ 25.01.08
    #define PBYTE BYTE*
    #endif
    #ifndef byte // MJ 25.01.08
    #define byte unsigned char
    #endif
    
    #ifndef _tcslen // MJ 25.01.08
        #ifdef _UNICODE
        #define _tcslen wcslen
        #else
        #define _tcslen strlen
        #endif
    #endif
    
    
    
    #define __declspec( dllexport )
    
    #if defined HL_LINUX || defined HL_AIX || defined HL_SOLARIS || defined HL_HPUX || HL_FREEBSD
    #include <sys/param.h>
    #else
    #include <param.h>
    #endif

#define STRCASECMP(par1, par2)  strcasecmp( par1 , par2)
#define STRNCASECMP(par1, par2, len)  strncasecmp( par1 , par2, len)
#define    STRNCPY(ach_target, ach_src, max_size)  strncpy(ach_target, ach_src, max_size)

#else // ----------- WIN32 or WIN64

#define STRCASECMP(par1,par2)  _stricmp( par1 , par2)
#define STRNCASECMP(par1, par2, len)  _strnicmp( par1 , par2, len)
#define    STRNCPY(ach_target, ach_src, max_size)    strcpy_s(ach_target, max_size, ach_src);


#endif

#ifdef __GNUC__
#define HL_FUNC_FORMAT_PRINTF(pattern_pos, vaarg_pos) __attribute__ ((format (printf, pattern_pos, vaarg_pos)))
#else
#define HL_FUNC_FORMAT_PRINTF(pattern_pos, vaarg_pos)
#endif

#ifdef _MSC_VER 
//#define HL_FORMAT_STRING __format_string
#define HL_FORMAT_STRING _Printf_format_string_
#else
#define HL_FORMAT_STRING
#endif

typedef long long int hl_time_t;

#endif // TYPES_DEFINES_H
