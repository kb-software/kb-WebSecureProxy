/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| include headers                                                         |*/
/*+-------------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>
#include <ds_hstring.h>
#include <ds_xml.h>
#include <ds_portlet.h>

static const dsd_const_string achg_ptl_tags[] = {
    "portlet",
    "name",
    "open"
};

enum ied_ptl_tags {
    ied_ptl_tag_portlet,
    ied_ptl_tag_name,
    ied_ptl_tag_open
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
 * public function ds_portlet::m_init
 *
 * @param[in]   ds_wsp_helper*  ads_wsp_helper
*/
void ds_portlet::m_init( ds_wsp_helper* ads_wsp_helper )
{    
    adsc_wsp_helper = ads_wsp_helper;
    dsc_name.m_init ( ads_wsp_helper );
    boc_open  = true;
} // end of ds_portlet::m_init


/**
 * \ingroup authlib
 *
 * public function ds_portlet::m_is_complete
 * check if this class is completly filled
 *
 * @return  bool
*/
bool ds_portlet::m_is_complete() const
{
    return ( dsc_name.m_get_len() > 0 );
} // end of ds_portlet::m_is_complete


/**
 * \ingroup authlib
 *
 * public function ds_portlet::m_reset
 * clear saved values
*/
void ds_portlet::m_reset()
{
    dsc_name.m_reset();
    boc_open  = true;
} // end of ds_portlet::m_reset


/**
 * \ingroup authlib
 *
 * public function ds_portlet::m_from_xml
 * fill this class from xml data
 *
 * @param[in]   const char* ach_xml         pointer to xml
 * @param[in]   int         in_len          length of xml data
 * @return      bool                        true = success
*/
bool ds_portlet::m_from_xml( const char* ach_xml, int in_len )
{
    // initialize some variables:
    ds_xml          dsl_parser;             // xml parser class
    dsd_xml_tag*    adsl_pnode;             // first tag

    //-------------------------------------------
    // init xml parser:
    //-------------------------------------------
    dsl_parser.m_init( adsc_wsp_helper );

    //-------------------------------------------
    // parse the data and check name of tag:
    //-------------------------------------------
    adsl_pnode = dsl_parser.m_from_xml( (char*)ach_xml, in_len );
    if ( adsl_pnode == NULL ) {
        return false;
    }
    return m_from_xml( adsl_pnode );
} // end of ds_portlet::m_from_xml


/**
 * \ingroup authlib
 *
 * public function ds_portlet::m_from_xml
 * fill this class from xml node
 *
 * @param[in]   dsd_xml_tag* ads_pnode      xml parent node
 * @return      bool                        true = success
*/
bool ds_portlet::m_from_xml( dsd_xml_tag* ads_pnode )
{
    // initialize some variables:
    ds_xml          dsl_xml;                // xml class
    const char*           achl_name;              // name
    int             inl_len_name;           // length of name
    bool            bol_open;               // is open?

    //-------------------------------------------
    // init xml class:
    //-------------------------------------------
    dsl_xml.m_init( adsc_wsp_helper );

    //-------------------------------------------
    // check name of tag:
    //-------------------------------------------
    dsl_xml.m_get_node_name( ads_pnode, &achl_name, &inl_len_name );
    if ( !achg_ptl_tags[ied_ptl_tag_portlet].m_equals(dsd_const_string(achl_name, inl_len_name)) ) {
        return false;
    }

    //-------------------------------------------
    // get recommended values:
    //-------------------------------------------
    dsl_xml.m_get_value( ads_pnode,
                         achg_ptl_tags[ied_ptl_tag_name],
                         &achl_name, &inl_len_name );
    bol_open = dsl_xml.m_read_bool( ads_pnode,
                                    achg_ptl_tags[ied_ptl_tag_open],
                                    true );
    if ( achl_name  == NULL || inl_len_name  < 1 ) {
        return false;
    }

    //-------------------------------------------
    // save the data:
    //-------------------------------------------
    dsc_name.m_set ( achl_name,  inl_len_name );
    boc_open  = bol_open;
    return true;
} // end of ds_portlet::m_from_xml


/**
 * \ingroup authlib
 *
 * function ds_portlet::m_to_xml
 * create xml from class content
 *
 * @param[in/out]   ds_hstring* ads_xml     outbut buffer
 * @return          bool                    true = success
*/
bool ds_portlet::m_to_xml( ds_hstring* ads_xml ) const
{
    //-------------------------------------------
    // check saved data:
    //-------------------------------------------
    if ( dsc_name.m_get_len() < 1 ) {
        return false;
    }

    //-------------------------------------------
    // write the data:
    //-------------------------------------------
    ads_xml->m_write_xml_open_tag(achg_ptl_tags[ied_ptl_tag_portlet]);
    ads_xml->m_write_xml_open_tag(achg_ptl_tags[ied_ptl_tag_name]);
    ads_xml->m_write_xml_text(dsc_name.m_const_str());
    ads_xml->m_write_xml_close_tag(achg_ptl_tags[ied_ptl_tag_name]);
    ads_xml->m_write_xml_open_tag(achg_ptl_tags[ied_ptl_tag_open]);
    ads_xml->m_write_xml_text(boc_open ? dsd_const_string("YES") : dsd_const_string("NO"));
    ads_xml->m_write_xml_close_tag(achg_ptl_tags[ied_ptl_tag_open]);
    ads_xml->m_write_xml_close_tag(achg_ptl_tags[ied_ptl_tag_portlet]);
    return true;
} // end of ds_portlet::m_to_xml


/**
 * \ingroup authlib
 *
 * public function ds_portlet::m_get_name
 *
 * @param[in]   char**  aach_name
 * @param[in]   int*    ain_len
 * @return      bool
*/
bool ds_portlet::m_get_name( const char** aach_name,  int* ain_len ) const
{
    *aach_name = dsc_name.m_get_ptr();
    *ain_len   = dsc_name.m_get_len();
    return ( *ain_len > 0 );
} // end of ds_portlet::m_get_name


/**
 * \ingroup authlib
 *
 * public function ds_portlet::m_is_open()
 *
 * @return bool
*/
bool ds_portlet::m_is_open() const
{
    return boc_open;
} // end of ds_portlet::m_is_open


/**
 * \ingroup authlib
 *
 * public function ds_portlet::m_set_name
 *
 * @param[in]   const char* ach_name
 * @param[in]   int         in_len
*/
void ds_portlet::m_set_name( const char* ach_name, int in_len )
{
    dsc_name.m_set( ach_name, in_len );
} // end of ds_portlet::m_set_name

/**
 * \ingroup authlib
 *
 * public function ds_portlet::m_set_open
 *
 * @param[in]   bool bo_open
*/
void ds_portlet::m_set_open( bool bo_open )
{
    boc_open = bo_open;
} // end of ds_portlet::m_set_open
