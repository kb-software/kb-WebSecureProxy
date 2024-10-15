/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#ifndef HL_UNIX
    #include <windows.h>
#else
    #include <sys/types.h>
    #include <errno.h>
    #include <hob-unix01.h>
#endif

/*+-------------------------------------------------------------------+*/
/*| header files for authentication library:                          |*/
/*+-------------------------------------------------------------------+*/
#include <hob-libwspat.h>
#ifndef _HOB_XSCLIB01_H
    #define _HOB_XSCLIB01_H
    #include <hob-xsclib01.h>
#endif //_HOB_XSCLIB01_H

extern "C" HL_DLL_PUBLIC BOOL m_wspat3_config( struct dsd_hl_clib_dom_conf *adsp_conf )
{
    return m_wspat3_config_in( adsp_conf );
} // end of m_wspat3_config

extern "C" HL_DLL_PUBLIC void m_wspat3_proc( struct dsd_wspat3_1 *adsp_wspat3 )
{
    return m_wspat3_proc_in( adsp_wspat3 );
} // end of m_wspat3_proc
