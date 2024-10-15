#ifndef _DS_PARSE_XSL_H
#define _DS_PARSE_XSL_H
/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>
#include <ds_xml.h>

/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/
#ifndef XSL_NAMESPACE
    #define XSL_NAMESPACE       "xsl:"
#endif

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief xsl parser
 *
 * @ingroup landingpage
 *
 * parses xsl
 */
class ds_parse_xsl : public ds_xml
{
protected:
    virtual bool m_get_tag( const char* ach_data, int in_len, int* ain_pos,
                            const char** aach_tag, int* ain_len_tag );

private:
    bool m_is_ns_tag( const char* ach_tag, int in_len );
};
#endif // _DS_PARSE_XSL_H
