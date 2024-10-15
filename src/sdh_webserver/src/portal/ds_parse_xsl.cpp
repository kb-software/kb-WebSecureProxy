/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#include "ds_parse_xsl.h"
#include <ds_hstring.h>
#ifdef HL_UNIX
    #include <ctype.h>
#endif

/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_parse_xsl::m_get_tag
 * get next tag
 *
 * @param[in]       char*   ach_data
 * @param[in]       int     in_len
 * @param[in/out]   int*    ain_pos
 * @param[out]      char**  aach_tag
 * @param[out]      int*    ain_len_tag
*/
bool ds_parse_xsl::m_get_tag( const char* ach_data, int in_len, int* ain_pos,
                              const char** aach_tag, int* ain_len_tag )
{
    // initialize some variables:
    bool bo_ret;
    bool bo_is_xsl;
    
    do {
        bo_ret = ds_xml::m_get_tag( ach_data, in_len, ain_pos, aach_tag, ain_len_tag );
        if ( bo_ret == false ) {
            break;
        }
        bo_is_xsl = m_is_ns_tag( *aach_tag, *ain_len_tag );
    } while ( bo_is_xsl == false );

    return bo_ret;
} // end of ds_parse_xsl::m_get_tag


/**
 * function ds_parse_xsl::m_is_ns_tag
 *
 * @param[in]   char*   ach_tag
 * @param[in]   int     in_len
 * @return      bool
*/
bool ds_parse_xsl::m_is_ns_tag( const char* ach_tag, int in_len )
{
    dsd_const_string dsl_nstag(ach_tag, in_len);
    dsl_nstag.m_trim_left("< \t\n\r");
    return dsl_nstag.m_starts_with_ic(XSL_NAMESPACE);
} // end of ds_parse_xsl::m_is_ns_tag
