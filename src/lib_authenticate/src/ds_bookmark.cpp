/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| include headers                                                         |*/
/*+-------------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>
#include <ds_hstring.h>
#include <ds_bookmark.h>
#include <ds_xml.h>
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H

static const dsd_const_string achg_bm_tags[] = {
    "bookmark",
    "url",
    "name"
};

enum ied_bm_tags {
    ied_bm_tag_bookmark,
    ied_bm_tag_url,
    ied_bm_tag_name
};

/*+-------------------------------------------------------------------------+*/
/*| constructor:                                                            |*/
/*+-------------------------------------------------------------------------+*/


/*+-------------------------------------------------------------------------+*/
/*| public functions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/**
 * \ingroup authlib
 *
 * public function ds_bookmark::m_init
 *
 * @param[in]   ds_wsp_helper*  ads_wsp_helper
*/
void ds_bookmark::m_init( ds_wsp_helper* ads_wsp_helper )
{
    adsc_wsp_helper = ads_wsp_helper;
    dsc_name.m_init( ads_wsp_helper );
    dsc_url.m_init ( ads_wsp_helper );
    boc_is_own = false;
} // end of ds_bookmark::m_init


/**
 * \ingroup authlib
 *
 * public function ds_bookmark::m_reset
*/
void ds_bookmark::m_reset()
{
    dsc_name.m_reset();
    dsc_url.m_reset();
    boc_is_own = false;
} // end of ds_bookmark::m_reset


/**
 * \ingroup authlib
 *
 * public function ds_bookmark::m_from_xml
 * fill this class from xml data
 *
 * @param[in]   const char* ach_xml         pointer to xml
 * @param[in]   int         in_len          length of xml data
 * @return      bool                        true = success
*/
bool ds_bookmark::m_from_xml( const char* ach_xml, int in_len )
{
    // initialize some variables:
    ds_xml          dsl_parser;             // xml parser class
    dsd_xml_tag*    adsl_pnode;             // first tag

    //-------------------------------------------
    // init xml parser:
    //-------------------------------------------
    dsl_parser.m_init( adsc_wsp_helper );

    //-------------------------------------------
    // parse the data:
    //-------------------------------------------
    adsl_pnode = dsl_parser.m_from_xml( (char*)ach_xml, in_len );
    if ( adsl_pnode == NULL ) {
        return false;
    }
    return m_from_xml( adsl_pnode );
} // end of ds_bookmark::m_from_xml


/**
 * \ingroup authlib
 *
 * public function ds_bookmark::m_from_xml
 * fill this class from xml node
 *
 * @param[in]   dsd_xml_tag*    ads_pnode
 * @return      bool                        true = success
*/
bool ds_bookmark::m_from_xml( dsd_xml_tag* ads_pnode )
{
    // initialize some variables:
    ds_xml              dsl_xml;                // xml class
    dsd_unicode_string  dsl_url;                // url
    dsd_unicode_string  dsl_name;               // name
    
    //-------------------------------------------
    // init xml parser:
    //-------------------------------------------
    dsl_xml.m_init( adsc_wsp_helper );

    //-------------------------------------------
    // check name of tag:
    //-------------------------------------------
    dsl_xml.m_get_node_name( ads_pnode, (const char**) &dsl_name.ac_str, &dsl_name.imc_len_str );
    dsl_name.iec_chs_str = ied_chs_utf_8; //no escaped characters in tag name
    if ( !achg_bm_tags[ied_bm_tag_bookmark].m_equals(dsl_name) ) {
        return false;
    }

    //-------------------------------------------
    // get recommended values:
    //-------------------------------------------
    dsl_xml.m_get_value( ads_pnode, achg_bm_tags[ied_bm_tag_url], 
        (const char**) &dsl_url.ac_str, &dsl_url.imc_len_str );
    dsl_xml.m_get_value( ads_pnode, achg_bm_tags[ied_bm_tag_name],
        (const char**) &dsl_name.ac_str, &dsl_name.imc_len_str );
    if (    dsl_url.ac_str  == NULL || dsl_url.imc_len_str  < 1 
         || dsl_name.ac_str == NULL || dsl_name.imc_len_str < 1 ) {
        return false;
    }

    //-------------------------------------------
    // save url and name:
    //-------------------------------------------
    //values are converted to xml_utf_8 in write_xml but not converted back to utf_8 in get_value, so we do this now:
    dsl_url .iec_chs_str = ied_chs_xml_utf_8;
    dsl_name.iec_chs_str = ied_chs_xml_utf_8;
    dsc_url.m_set ( dsl_url );
    dsc_name.m_set( dsl_name );

    //-------------------------------------------
    // reset own flag
    //-------------------------------------------
    boc_is_own = false;
    return true;
} // end of ds_bookmark::m_from_xml

/**
 * \ingroup authlib
 *
 * function ds_bookmark::m_to_xml
 * create xml from class content
 *
 * @param[in/out]   ds_hstring* ads_xml     outbut buffer
 * @return          bool                    true = success
*/
bool ds_bookmark::m_to_xml( ds_hstring* ads_xml ) const
{
    //-------------------------------------------
    // check saved data:
    //-------------------------------------------
    if (    dsc_url.m_get_len()  < 1
         || dsc_name.m_get_len() < 1 ) {
        return false;
    }

    //-------------------------------------------
    // write the data:
    //-------------------------------------------
    ads_xml->m_write_xml_open_tag(achg_bm_tags[ied_bm_tag_bookmark]);
    ads_xml->m_write_xml_open_tag(achg_bm_tags[ied_bm_tag_url]);
    ads_xml->m_write_xml_text(dsc_url.m_const_str());
    ads_xml->m_write_xml_close_tag(achg_bm_tags[ied_bm_tag_url]);
    ads_xml->m_write_xml_open_tag(achg_bm_tags[ied_bm_tag_name]);
    ads_xml->m_write_xml_text(dsc_name.m_const_str());
    ads_xml->m_write_xml_close_tag(achg_bm_tags[ied_bm_tag_name]);
    ads_xml->m_write_xml_close_tag(achg_bm_tags[ied_bm_tag_bookmark]);
    return true;
} // end of ds_bookmark::m_to_xml


/**
 * \ingroup authlib
 *
 * public function ds_bookmark::m_get_url
 * get url
 *
 * @param[out]  char**      aach_url        will point to url
 * @param[out]  int*        ain_len         length of url
*/
bool ds_bookmark::m_get_url( const char** aach_url,  int* ain_len ) const
{
    *aach_url = dsc_url.m_get_ptr();
    *ain_len  = dsc_url.m_get_len();
    return ( *ain_len > 0 );
} // end of ds_bookmark::m_get_url


/**
 * \ingroup authlib
 *
 * public function ds_bookmark::m_get_name
 * get name
 *
 * @param[out]  char**      aach_name       will point to name
 * @param[out]  int*        ain_len         length of name
*/
bool ds_bookmark::m_get_name( const char** aach_name, int* ain_len ) const
{
    *aach_name = dsc_name.m_get_ptr();
    *ain_len   = dsc_name.m_get_len();
    return ( *ain_len > 0 );
} // end of ds_bookmark::m_get_name


/**
 * \ingroup authlib
 *
 * public function ds_bookmark::m_is_own
 * is this bookmark from current user
*/
bool ds_bookmark::m_is_own() const
{
    return boc_is_own;
} // end of ds_bookmark::m_is_own


/**
 * \ingroup authlib
 *
 * public function ds_bookmark::m_set_url
 * set url
 *
 * @param[in]   const char* ach_url        pointer to url
 * @param[in]   int         in_len         length of url
*/
void ds_bookmark::m_set_url( const char* ach_url, int in_len )
{
    dsc_url.m_set( ach_url, in_len );
} // end of ds_bookmark::m_set_url

/**
 * \ingroup authlib
 *
 * public function ds_bookmark::m_set_name
 * set name
 *
 * @param[in]   const char* ach_name       pointer to name
 * @param[in]   int         in_len         length of name
*/
void ds_bookmark::m_set_name( const char* ach_name, int in_len )
{
	/*do NOT convert to html_utf_8 when < or > contained: 
		done by write_xml on save/page generation so html entities would be double escaped*/
	//TODO is removing conversion to html compatible with EA-Admin?
    dsc_name.m_set( ach_name, in_len );
} // end of ds_bookmark::m_set_url


/**
 * \ingroup authlib
 *
 * public function ds_bookmark::m_set_own
 * set this bookmark as from current user
 *
 * @param[in]   bool        bo_own
*/
void ds_bookmark::m_set_own( bool bo_own )
{
    boc_is_own = bo_own;
} // end of ds_bookmark::m_is_own


/**
 * \ingroup authlib
 *
 * public function ds_bookmark::m_is_complete
 * check whether this bookmark is filled correctly
 *
 * @return bool
*/
bool ds_bookmark::m_is_complete()
{
    return (dsc_name.m_get_len() && dsc_url.m_get_len());
} // end of ds_bookmark::m_is_complete

/*+-------------------------------------------------------------------------+*/
/*| private functions:                                                      |*/
/*+-------------------------------------------------------------------------+*/
