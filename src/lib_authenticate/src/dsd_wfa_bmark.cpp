/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| include headers                                                         |*/
/*+-------------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>
#include <ds_hstring.h>
#include <ds_bookmark.h>
#include <dsd_wfa_bmark.h>
#include <ds_xml.h>
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H

static const dsd_const_string achg_bm_tags[] = {
    "bookmark",
    "url",
    "title",
    "user",
    "password",
    "domain",
    "position"
};

enum ied_bm_tags {
    ied_bm_tag_bookmark,
    ied_bm_tag_url,
    ied_bm_tag_name,
    ied_bm_tag_user,
    ied_bm_tag_pwd,
    ied_bm_tag_domain,
    ied_bm_tag_pos
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
 * public function dsd_wfa_bmark::m_init
 *
 * @param[in]   ds_wsp_helper*  ads_wsp_helper
*/
void dsd_wfa_bmark::m_init( ds_wsp_helper* ads_wsp_helper )
{
    adsc_wsp_helper = ads_wsp_helper;
    dsc_name.m_init  ( ads_wsp_helper );
    dsc_url.m_init   ( ads_wsp_helper );
    dsc_user.m_init  ( ads_wsp_helper );
    dsc_pwd.m_init   ( ads_wsp_helper );
    dsc_domain.m_init( ads_wsp_helper );
    boc_is_own   = false;
    inc_position = 0;
} // end of dsd_wfa_bmark::m_init


/**
 * \ingroup authlib
 *
 * public function dsd_wfa_bmark::m_reset
*/
void dsd_wfa_bmark::m_reset()
{
    dsc_name.m_reset();
    dsc_url.m_reset();
    dsc_user.m_reset();
    dsc_pwd.m_reset();
    dsc_domain.m_reset();
    boc_is_own   = false;
    inc_position = 0;
} // end of dsd_wfa_bmark::m_reset


/**
 * \ingroup authlib
 *
 * public function dsd_wfa_bmark::m_from_xml
 * fill this class from xml node
 *
 * @param[in]   dsd_xml_tag*    ads_pnode
 * @return      bool                        true = success
*/
bool dsd_wfa_bmark::m_from_xml( dsd_xml_tag* ads_pnode )
{
    // initialize some variables:
    ds_xml  dsl_xml;                        // xml class
    const char    *achl_value;                    // tag value
    int     inl_length;                     // length of value
    
    //--------------------------
    // init xml parser:
    //--------------------------
    dsl_xml.m_init( adsc_wsp_helper );

    //--------------------------
    // check name of tag:
    //--------------------------
    dsl_xml.m_get_node_name( ads_pnode, &achl_value, &inl_length );
    if ( !achg_bm_tags[ied_bm_tag_bookmark].m_equals(dsd_const_string(achl_value, inl_length)) ) {
        return false;
    }

    //--------------------------
    // get recommended values:
    //--------------------------
    dsl_xml.m_get_value( ads_pnode, 
                         achg_bm_tags[ied_bm_tag_url],
                         &achl_value, &inl_length );
#if 0
    if ( achl_value  == NULL || inl_length  < 1 ) {
        return false;
    }
#endif
    dsc_url.m_set ( achl_value,  inl_length );

    //--------------------------
    // get optional tags:
    //--------------------------
    dsl_xml.m_get_value( ads_pnode, 
                         achg_bm_tags[ied_bm_tag_name],
                         &achl_value, &inl_length );
    dsc_name.m_set( achl_value, inl_length );

    
    dsl_xml.m_get_value( ads_pnode, 
                         achg_bm_tags[ied_bm_tag_user],
                         &achl_value, &inl_length );
    dsc_user.m_set( achl_value, inl_length );

    dsl_xml.m_get_value( ads_pnode, 
                         achg_bm_tags[ied_bm_tag_pwd],
                         &achl_value, &inl_length );
    dsc_pwd.m_set( achl_value, inl_length );

    dsl_xml.m_get_value( ads_pnode, 
                         achg_bm_tags[ied_bm_tag_domain],
                         &achl_value, &inl_length );
    dsc_domain.m_set( achl_value, inl_length );
    
    inc_position = dsl_xml.m_read_int( ads_pnode, achg_bm_tags[ied_bm_tag_pos],
                                      0 );
    
    // reset own flag
    boc_is_own = false;
    return true;
} // end of dsd_wfa_bmark::m_from_xml


/**
 * \ingroup authlib
 *
 * function dsd_wfa_bmark::m_to_xml
 * create xml from class content
 *
 * @param[in/out]   ds_hstring* ads_xml     outbut buffer
 * @return          bool                    true = success
*/
bool dsd_wfa_bmark::m_to_xml( ds_hstring* ads_xml ) const
{
    //-------------------------------------------
    // check saved data:
    //-------------------------------------------
    if ( dsc_url.m_get_len() < 1) {
        return false;
    }

    //-------------------------------------------
    // write the data:
    //-------------------------------------------
    ads_xml->m_write_xml_open_tag(achg_bm_tags[ied_bm_tag_bookmark]);
    ads_xml->m_write_xml_open_tag(achg_bm_tags[ied_bm_tag_url]);
    ads_xml->m_write_xml_text(dsc_url.m_const_str());
    ads_xml->m_write_xml_close_tag(achg_bm_tags[ied_bm_tag_url]);
    if ( dsc_name.m_get_len() > 0 ) {
        ads_xml->m_write_xml_open_tag(achg_bm_tags[ied_bm_tag_name]);
        ads_xml->m_write_xml_text(dsc_name.m_const_str());
        ads_xml->m_write_xml_close_tag(achg_bm_tags[ied_bm_tag_name]);
    }
    if ( dsc_user.m_get_len() > 0 ) {
        ads_xml->m_write_xml_open_tag(achg_bm_tags[ied_bm_tag_user]);
        ads_xml->m_write_xml_text(dsc_user.m_const_str());
        ads_xml->m_write_xml_close_tag(achg_bm_tags[ied_bm_tag_user]);
    }
    if ( dsc_pwd.m_get_len() > 0 ) {
        ads_xml->m_write_xml_open_tag(achg_bm_tags[ied_bm_tag_pwd]);
        ads_xml->m_write_xml_text(dsc_pwd.m_const_str());
        ads_xml->m_write_xml_close_tag(achg_bm_tags[ied_bm_tag_pwd]);
    }
    if ( dsc_domain.m_get_len() > 0 ) {
        ads_xml->m_write_xml_open_tag(achg_bm_tags[ied_bm_tag_domain]);
        ads_xml->m_write_xml_text(dsc_domain.m_const_str());
        ads_xml->m_write_xml_close_tag(achg_bm_tags[ied_bm_tag_domain]);
    }
    ads_xml->m_write_xml_open_tag(achg_bm_tags[ied_bm_tag_pos]);
    ads_xml->m_write_int(inc_position);
    ads_xml->m_write_xml_close_tag(achg_bm_tags[ied_bm_tag_pos]);
    ads_xml->m_write_xml_close_tag(achg_bm_tags[ied_bm_tag_bookmark]);
    return true;
} // end of dsd_wfa_bmark::m_to_xml


/**
 * \ingroup authlib
 *
 * public function dsd_wfa_bmark::m_is_complete
 * check whether this bookmark is filled correctly
 *
 * @return bool
*/
bool dsd_wfa_bmark::m_is_complete()
{
    return (dsc_url.m_get_len() > 0);
} // end of dsd_wfa_bmark::m_is_complete


/**
 * \ingroup authlib
 *
 * public method dsd_wfa_bmark::m_set_user
 *  store userid for bookmark
 *
 * @param[in]   const char  *achp_user      userid
 * @param[in]   int         inp_length      length
*/
void dsd_wfa_bmark::m_set_user( const char *achp_user, int inp_length )
{
    dsc_user.m_set( achp_user, inp_length );
} // end of dsd_wfa_bmark::m_set_user


/**
 * \ingroup authlib
 *
 * public method dsd_wfa_bmark::m_set_pwd
 *  store password for bookmark
 *
 * @param[in]   const char  *achp_pwd       password
 * @param[in]   int         inp_length      length
*/
void dsd_wfa_bmark::m_set_pwd( const char *achp_pwd, int inp_length )
{
    dsc_pwd.m_set( achp_pwd, inp_length );
} // end of dsd_wfa_bmark::m_set_pwd


/**
 * \ingroup authlib
 *
 * public method dsd_wfa_bmark::m_set_domain
 *  store domain for bookmark
 *
 * @param[in]   const char  *achp_domain    domain
 * @param[in]   int         inp_length      length
*/
void dsd_wfa_bmark::m_set_domain( const char *achp_domain, int inp_length )
{
    dsc_domain.m_set( achp_domain, inp_length );
} // end of dsd_wfa_bmark::m_set_domain


/**
 * \ingroup authlib
 *
 * public method dsd_wfa_bmark::m_set_position
 *  store position for bookmark
 *
 * @param[in]   int         inp_pos
*/
void dsd_wfa_bmark::m_set_position( int inp_pos )
{
    inc_position = inp_pos;
} // end of dsd_wfa_bmark::m_set_position


/**
 * \ingroup authlib
 *
 * public method dsd_wfa_bmark::m_get_user
 *  get user id
 *
 * @param[out]  char    **aachp_user        userid
 * @param[out]  int     *ainp_length        length
 * @return      bool
*/
bool dsd_wfa_bmark::m_get_user( const char **aachp_user, int *ainp_length ) const
{
    *aachp_user  = dsc_user.m_get_ptr();
    *ainp_length = dsc_user.m_get_len();
    return ( *ainp_length > 0 );
} // end of dsd_wfa_bmark::m_get_user


/**
 * \ingroup authlib
 *
 * public method dsd_wfa_bmark::m_get_pwd
 *  get password
 *
 * @param[out]  char    **aachp_pwd        userid
 * @param[out]  int     *ainp_length        length
 * @return      bool
*/
bool dsd_wfa_bmark::m_get_pwd( const char **aachp_pwd, int *ainp_length ) const
{
    *aachp_pwd   = dsc_pwd.m_get_ptr();
    *ainp_length = dsc_pwd.m_get_len();
    return ( *ainp_length > 0 );
} // end of dsd_wfa_bmark::m_get_pwd


/**
 * \ingroup authlib
 *
 * public method dsd_wfa_bmark::m_get_domain
 *  get domain
 *
 * @param[out]  char    **aachp_pwd        userid
 * @param[out]  int     *ainp_length        length
 * @return      bool
*/
bool dsd_wfa_bmark::m_get_domain( const char **aachp_domain, int *ainp_length ) const
{
    *aachp_domain = dsc_domain.m_get_ptr();
    *ainp_length  = dsc_domain.m_get_len();
    return ( *ainp_length > 0 );
} // end of dsd_wfa_bmark::m_get_domain


/**
 * \ingroup authlib
 *
 * public method dsd_wfa_bmark::m_get_position
 *  get position
 *
 * @return      int
*/
int dsd_wfa_bmark::m_get_position() const
{
    return inc_position;
} // end of dsd_wfa_bmark::m_get_position

/*+-------------------------------------------------------------------------+*/
/*| private functions:                                                      |*/
/*+-------------------------------------------------------------------------+*/
