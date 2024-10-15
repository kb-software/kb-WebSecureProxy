/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>
#include <ds_hstring.h>
#include <ds_hashtable.h>
#include "ds_attributes.h"

/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
 * @ingroup dataprocessor
 *
 * @param[in]   ads_wsp_helper	
*/
void ds_attributes::m_setup( ds_wsp_helper* ads_wsp_helper )
{
    // setup hash tables:
    m_setup_html_table  ( ads_wsp_helper );
    m_setup_script_table( ads_wsp_helper );
} // end of ds_attributes::m_setup


/**
 * @ingroup dataprocessor
 *
 * @param[in]   achl_key	char pointer which points to the html attribute
 * @param[in]   in_len		int value representing the length of the attribute
 *
 * @return	value from attribute or a negative value if there was an error      
*/
int ds_attributes::m_get_htm_attr( const char* achl_key, int in_len ) const
{
    // initialize some variables:
    bool bo_ret;
    int  in_ret;

    // check input:
    if ( achl_key == NULL || in_len < 1 ) {
        return -2;
    }

    bo_ret = ds_htmlattributes.m_get( achl_key, in_len, &in_ret );
    if ( bo_ret == true ) {
        return in_ret;
    }
    return -1;
} // end of ds_attributes::m_get_htm_attr


/**
 * @ingroup dataprocessor
 *
 * @param[in]   achl_key	char pointer which points to the html attribute
 * @param[in]   in_len		int value representing the length of the attribute
 *
 * @return	value from attribute or a negative value if there was an error      
*/
int ds_attributes::m_get_htm_tag( const char* achl_key, int in_len ) const
{
    // initialize some variables:
    bool bo_ret;
    int  in_ret;

    // check input:
    if ( achl_key == NULL || in_len < 1 ) {
        return -2;
    }

    bo_ret = ds_htmltags.m_get( achl_key, in_len, &in_ret );
    if ( bo_ret == true ) {
        return in_ret;
    }
    return -1;
} // end of ds_attributes::m_get_htm_tag


/**
 * @ingroup dataprocessor
 *
 * @param[in]   achl_key	char pointer which points to the html attribute
 * @param[in]   in_len		int value representing the length of the attribute
 *
 * @return	value from attribute or a negative value if there was an error      
*/
int ds_attributes::m_get_htm_val( const char* achl_key, int in_len ) const
{
    // initialize some variables:
    bool bo_ret;
    int  in_ret;

    // check input:
    if ( achl_key == NULL || in_len < 1 ) {
        return -2;
    }

    bo_ret = ds_htmlspecialnamevalues.m_get( achl_key, in_len, &in_ret );
    if ( bo_ret == true ) {
        return in_ret;
    }
    return -1;
} // end of ds_attributes::m_get_htm_val


/**
 * @ingroup dataprocessor
 *
 * @param[in]   achl_key	char pointer which points to the html attribute
 * @param[in]   in_len		int value representing the length of the attribute
 *
 * @return	value from attribute or a negative value if there was an error      
*/
int ds_attributes::m_get_htm_rel( const char* achl_key, int in_len ) const
{
    // initialize some variables:
    bool bo_ret;
    int  in_ret;

    // check input:
    if ( achl_key == NULL || in_len < 1 ) {
        return -2;
    }

    bo_ret = ds_htmlrelvalues.m_get( achl_key, in_len, &in_ret );
    if ( bo_ret == true ) {
        return in_ret;
    }
    return -1;
} // end of ds_attributes::m_get_htm_rel


/**
 * @ingroup dataprocessor
 *
 * @param[in]   achl_key	char pointer which points to the html attribute
 * @param[in]   in_len		int value representing the length of the attribute
 *
 * @return	value from attribute or a negative value if there was an error      
*/
int ds_attributes::m_get_htm_sso( const char* achl_key, int in_len ) const
{
    // initialize some variables:
    bool bo_ret;
    int  in_ret;

    // check input:
    if ( achl_key == NULL || in_len < 1 ) {
        return -2;
    }

    bo_ret = ds_html_soo_list.m_get( achl_key, in_len, &in_ret );
    if ( bo_ret == true ) {
        return in_ret;
    }
    return -1;
} // end of ds_attributes::m_get_htm_sso


/**
 * @ingroup dataprocessor
 *
 * @param[in]   achl_key	char pointer which points to the html attribute
 * @param[in]   in_len		int value representing the length of the attribute
 *
 * @return	value from attribute or a negative value if there was an error      
*/
int ds_attributes::m_get_scr_attr( const char* achl_key, int in_len ) const
{
    // initialize some variables:
    bool bo_ret;
    int  in_ret;

    // check input:
    if ( achl_key == NULL || in_len < 1 ) {
        return -2;
    }

    bo_ret = ds_scriptattributes.m_get( achl_key, in_len, &in_ret );
    if ( bo_ret == true ) {
        return in_ret;
    }
    return -1;
} // end of ds_attributes::m_get_scr_attr


/**
 * @ingroup dataprocessor
 *
 * @param[in]   achl_key	char pointer which points to the html attribute
 * @param[in]   in_len		int value representing the length of the attribute
 *
 * @return	value from attribute or a negative value if there was an error      
*/
int ds_attributes::m_get_scr_cc( const char* achl_key, int in_len ) const
{
    // initialize some variables:
    bool bo_ret;
    int  in_ret;

    // check input:
    if ( achl_key == NULL || in_len < 1 ) {
        return -2;
    }

    bo_ret = ds_cond_comp_attr.m_get( achl_key, in_len, &in_ret );
    if ( bo_ret == true ) {
        return in_ret;
    }
    return -1;
} // end of ds_attributes::m_get_scr_cc


/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/
/**
 * private function ds_attributes::m_setup_html_table
 *
 * @param[in]   ds_wsp_helper* ads_wsp_helper
*/
void ds_attributes::m_setup_html_table( ds_wsp_helper* ads_wsp_helper )
{
    // Take care that all strings are in lower case!
    // (int) cast is needed, to make solaris compiler happy
    // attributes:
    ds_htmlattributes.m_setup( ads_wsp_helper, 100 );
    ds_htmlattributes.m_add( "action",         (int)ied_htm_attr_action );
    ds_htmlattributes.m_add( "archive",        (int)ied_htm_attr_archive );
    ds_htmlattributes.m_add( "background",     (int)ied_htm_attr_background );
    ds_htmlattributes.m_add( "cite",           (int)ied_htm_attr_cite );
    ds_htmlattributes.m_add( "classid",        (int)ied_htm_attr_classid );
    ds_htmlattributes.m_add( "code",           (int)ied_htm_attr_code );
    ds_htmlattributes.m_add( "codebase",       (int)ied_htm_attr_codebase );
    ds_htmlattributes.m_add( "content",        (int)ied_htm_attr_content );
    ds_htmlattributes.m_add( "data",           (int)ied_htm_attr_data );
    ds_htmlattributes.m_add( "datasrc",        (int)ied_htm_attr_datasrc );
    ds_htmlattributes.m_add( "href",           (int)ied_htm_attr_href );
    ds_htmlattributes.m_add( "xlink:href",     (int)ied_htm_attr_xlink_href );
    ds_htmlattributes.m_add( "implementation", (int)ied_htm_attr_implementation );
    ds_htmlattributes.m_add( "longdesc",       (int)ied_htm_attr_longdesc );
    ds_htmlattributes.m_add( "lowsrc",         (int)ied_htm_attr_lowsrc );
    ds_htmlattributes.m_add( "name",           (int)ied_htm_attr_name );
    ds_htmlattributes.m_add( "pluginspage",    (int)ied_htm_attr_pluginspage );
    ds_htmlattributes.m_add( "profile",        (int)ied_htm_attr_profile );
    ds_htmlattributes.m_add( "rel",            (int)ied_htm_attr_rel );
    ds_htmlattributes.m_add( "src",            (int)ied_htm_attr_src );
    ds_htmlattributes.m_add( "usemap",         (int)ied_htm_attr_usemap );
    ds_htmlattributes.m_add( "value",          (int)ied_htm_attr_value );
    ds_htmlattributes.m_add( "charset",        (int)ied_htm_attr_charset );
    ds_htmlattributes.m_add( "http-equiv",     (int)ied_htm_attr_http_equiv );
    ds_htmlattributes.m_add( "type",           (int)ied_htm_attr_type );
    ds_htmlattributes.m_add( "async",          (int)ied_htm_attr_async );
    ds_htmlattributes.m_add( "defer",          (int)ied_htm_attr_defer );
    ds_htmlattributes.m_add( "language",       (int)ied_htm_attr_language );
    ds_htmlattributes.m_add( "srcset",         (int)ied_htm_attr_srcset );
    ds_htmlattributes.m_add( "integrity",      (int)ied_htm_attr_integrity );
	ds_htmlattributes.m_add( "crossorigin",    (int)ied_htm_attr_crossorigin );
	ds_htmlattributes.m_add( "sandbox",        (int)ied_htm_attr_sandbox );
	ds_htmlattributes.m_add( "method",         (int)ied_htm_attr_method );
	ds_htmlattributes.m_add( "referrerpolicy", (int)ied_htm_attr_referrerpolicy );
	ds_htmlattributes.m_add( "srcdoc",         (int)ied_htm_attr_srcdoc );
	ds_htmlattributes.m_add( "as",	          (int)ied_htm_attr_as );
    // javascript:
    ds_htmlattributes.m_add( "onabort",     (int)ied_htm_attr_onabort );
	ds_htmlattributes.m_add( "onautocomplete", (int)ied_htm_attr_onautocomplete );
	ds_htmlattributes.m_add( "onautocompleteerror", (int)ied_htm_attr_onautocompleteerror );
	ds_htmlattributes.m_add( "onblur", (int)ied_htm_attr_onblur );
	ds_htmlattributes.m_add( "oncancel", (int)ied_htm_attr_oncancel );
	ds_htmlattributes.m_add( "oncanplay", (int)ied_htm_attr_oncanplay );
	ds_htmlattributes.m_add( "oncanplaythrough", (int)ied_htm_attr_oncanplaythrough );
	ds_htmlattributes.m_add( "onchange", (int)ied_htm_attr_onchange );
	ds_htmlattributes.m_add( "onclick", (int)ied_htm_attr_onclick );
	ds_htmlattributes.m_add( "onclose", (int)ied_htm_attr_onclose );
	ds_htmlattributes.m_add( "oncontextmenu", (int)ied_htm_attr_oncontextmenu );
	ds_htmlattributes.m_add( "oncuechange", (int)ied_htm_attr_oncuechange );
	ds_htmlattributes.m_add( "ondblclick", (int)ied_htm_attr_ondblclick );
	ds_htmlattributes.m_add( "ondrag", (int)ied_htm_attr_ondrag );
	ds_htmlattributes.m_add( "ondragend", (int)ied_htm_attr_ondragend );
	ds_htmlattributes.m_add( "ondragenter", (int)ied_htm_attr_ondragenter );
	ds_htmlattributes.m_add( "ondragexit", (int)ied_htm_attr_ondragexit );
	ds_htmlattributes.m_add( "ondragleave", (int)ied_htm_attr_ondragleave );
	ds_htmlattributes.m_add( "ondragover", (int)ied_htm_attr_ondragover );
	ds_htmlattributes.m_add( "ondragstart", (int)ied_htm_attr_ondragstart );
	ds_htmlattributes.m_add( "ondrop", (int)ied_htm_attr_ondrop );
	ds_htmlattributes.m_add( "ondurationchange", (int)ied_htm_attr_ondurationchange );
	ds_htmlattributes.m_add( "onemptied", (int)ied_htm_attr_onemptied );
	ds_htmlattributes.m_add( "onended", (int)ied_htm_attr_onended );
	ds_htmlattributes.m_add( "onerror", (int)ied_htm_attr_onerror );
	ds_htmlattributes.m_add( "onfocus", (int)ied_htm_attr_onfocus );
	ds_htmlattributes.m_add( "oninput", (int)ied_htm_attr_oninput );
	ds_htmlattributes.m_add( "oninvalid", (int)ied_htm_attr_oninvalid );
	ds_htmlattributes.m_add( "onkeydown", (int)ied_htm_attr_onkeydown );
	ds_htmlattributes.m_add( "onkeypress", (int)ied_htm_attr_onkeypress );
	ds_htmlattributes.m_add( "onkeyup", (int)ied_htm_attr_onkeyup );
	ds_htmlattributes.m_add( "onload", (int)ied_htm_attr_onload );
	ds_htmlattributes.m_add( "onloadeddata", (int)ied_htm_attr_onloadeddata );
	ds_htmlattributes.m_add( "onloadedmetadata", (int)ied_htm_attr_onloadedmetadata );
	ds_htmlattributes.m_add( "onloadstart", (int)ied_htm_attr_onloadstart );
	ds_htmlattributes.m_add( "onmousedown", (int)ied_htm_attr_onmousedown );
	ds_htmlattributes.m_add( "onmouseenter", (int)ied_htm_attr_onmouseenter );
	ds_htmlattributes.m_add( "onmouseleave", (int)ied_htm_attr_onmouseleave );
	ds_htmlattributes.m_add( "onmousemove", (int)ied_htm_attr_onmousemove );
	ds_htmlattributes.m_add( "onmouseout", (int)ied_htm_attr_onmouseout );
	ds_htmlattributes.m_add( "onmouseover", (int)ied_htm_attr_onmouseover );
	ds_htmlattributes.m_add( "onmouseup", (int)ied_htm_attr_onmouseup );
	ds_htmlattributes.m_add( "onmousewheel", (int)ied_htm_attr_onmousewheel );
	ds_htmlattributes.m_add( "onpause", (int)ied_htm_attr_onpause );
	ds_htmlattributes.m_add( "onplay", (int)ied_htm_attr_onplay );
	ds_htmlattributes.m_add( "onplaying", (int)ied_htm_attr_onplaying );
	ds_htmlattributes.m_add( "onprogress", (int)ied_htm_attr_onprogress );
	ds_htmlattributes.m_add( "onratechange", (int)ied_htm_attr_onratechange );
	ds_htmlattributes.m_add( "onreset", (int)ied_htm_attr_onreset );
	ds_htmlattributes.m_add( "onresize", (int)ied_htm_attr_onresize );
	ds_htmlattributes.m_add( "onscroll", (int)ied_htm_attr_onscroll );
	ds_htmlattributes.m_add( "onseeked", (int)ied_htm_attr_onseeked );
	ds_htmlattributes.m_add( "onseeking", (int)ied_htm_attr_onseeking );
	ds_htmlattributes.m_add( "onselect", (int)ied_htm_attr_onselect );
	ds_htmlattributes.m_add( "onshow", (int)ied_htm_attr_onshow );
	ds_htmlattributes.m_add( "onsort", (int)ied_htm_attr_onsort );
	ds_htmlattributes.m_add( "onstalled", (int)ied_htm_attr_onstalled );
	ds_htmlattributes.m_add( "onsubmit", (int)ied_htm_attr_onsubmit );
	ds_htmlattributes.m_add( "onsuspend", (int)ied_htm_attr_onsuspend );
	ds_htmlattributes.m_add( "ontimeupdate", (int)ied_htm_attr_ontimeupdate );
	ds_htmlattributes.m_add( "ontoggle", (int)ied_htm_attr_ontoggle );
	ds_htmlattributes.m_add( "onvolumechange", (int)ied_htm_attr_onvolumechange );
	ds_htmlattributes.m_add( "onwaiting", (int)ied_htm_attr_onwaiting );
    // css:
    ds_htmlattributes.m_add( "style",       (int)ied_htm_attr_style );
    // tags:
    ds_htmltags.m_setup( ads_wsp_helper, 20 );
    ds_htmltags.m_add( "base",     (int)ied_htm_tag_base );
    ds_htmltags.m_add( "meta",     (int)ied_htm_tag_meta );
    ds_htmltags.m_add( "body",     (int)ied_htm_tag_body );
    ds_htmltags.m_add( "/body",    (int)ied_htm_tag_bodyend );
    ds_htmltags.m_add( "frameset", (int)ied_htm_tag_frameset );
    ds_htmltags.m_add( "head",     (int)ied_htm_tag_head );
    ds_htmltags.m_add( "/head",    (int)ied_htm_tag_headend );
    ds_htmltags.m_add( "link",     (int)ied_htm_tag_link );
    ds_htmltags.m_add( "param",    (int)ied_htm_tag_param );
    ds_htmltags.m_add( "public",   (int)ied_htm_tag_public );
    ds_htmltags.m_add( "script",   (int)ied_htm_tag_script );
    ds_htmltags.m_add( "/script",  (int)ied_htm_tag_scriptend );
    ds_htmltags.m_add( "style",    (int)ied_htm_tag_style );
    ds_htmltags.m_add( "/style",   (int)ied_htm_tag_styleend );
    ds_htmltags.m_add( "iframe",    (int)ied_htm_tag_iframe );
    ds_htmltags.m_add( "/iframe",   (int)ied_htm_tag_iframeend );
    ds_htmltags.m_add( "a",   (int)ied_htm_tag_a );
    ds_htmltags.m_add( "area",   (int)ied_htm_tag_area );
    ds_htmltags.m_add( "audio",   (int)ied_htm_tag_audio );
    ds_htmltags.m_add( "embed",   (int)ied_htm_tag_embed );
    //ds_htmltags.m_add( "iframe",   (int)ied_htm_tag_iframe );
    ds_htmltags.m_add( "img",   (int)ied_htm_tag_img );
    ds_htmltags.m_add( "input",   (int)ied_htm_tag_input );
    ds_htmltags.m_add( "source",   (int)ied_htm_tag_source );
    ds_htmltags.m_add( "track",   (int)ied_htm_tag_track );
    ds_htmltags.m_add( "video",   (int)ied_htm_tag_video );
    ds_htmltags.m_add( "form",   (int)ied_htm_tag_form );
    ds_htmltags.m_add( "object",   (int)ied_htm_tag_object );
    ds_htmltags.m_add( "frame",   (int)ied_htm_tag_frame );
    ds_htmltags.m_add( "element",   (int)ied_htm_tag_element );
    ds_htmltags.m_add( "applet",   (int)ied_htm_tag_applet );
    ds_htmltags.m_add( "image",   (int)ied_htm_tag_svg_image );
    ds_htmltags.m_add( "use",   (int)ied_htm_tag_svg_use );
    ds_htmltags.m_add( "lineargradient",   (int)ied_htm_tag_svg_lineargradient );

    // special name values:
    ds_htmlspecialnamevalues.m_setup( ads_wsp_helper, 20 );
    ds_htmlspecialnamevalues.m_add( "dataurl",  (int)ied_htm_val_dataurl );
    ds_htmlspecialnamevalues.m_add( "dburl",    (int)ied_htm_val_dburl );
    ds_htmlspecialnamevalues.m_add( "cabbase",  (int)ied_htm_val_cabbase );
    ds_htmlspecialnamevalues.m_add( "filename", (int)ied_htm_val_filename );
    ds_htmlspecialnamevalues.m_add( "href",     (int)ied_htm_val_href );
    ds_htmlspecialnamevalues.m_add( "movie",    (int)ied_htm_val_movie );
    ds_htmlspecialnamevalues.m_add( "src",      (int)ied_htm_val_src );
    ds_htmlspecialnamevalues.m_add( "url",      (int)ied_htm_val_url );
    // link rel values:
    ds_htmlrelvalues.m_setup( ads_wsp_helper );
    ds_htmlrelvalues.m_add( "shortcut icon",  (int)ied_htm_rel_icon  );
    ds_htmlrelvalues.m_add( "stylesheet",     (int)ied_htm_rel_style );
    // single sign on list:
    ds_html_soo_list.m_setup( ads_wsp_helper );
    ds_html_soo_list.m_add( "form",       (int)ied_htm_sso_form );
    ds_html_soo_list.m_add( "action",     (int)ied_htm_sso_action );
    ds_html_soo_list.m_add( "input",      (int)ied_htm_sso_input );

} // end of ds_attributes::m_setup_html_table


/**
 * private function ds_attributes::m_setup_script_table
 *
 * @param[in]   ds_wsp_helper* ads_wsp_helper
*/
void ds_attributes::m_setup_script_table( ds_wsp_helper* ads_wsp_helper )
{
    // (int) cast is needed, to make solaris compiler happy
    // attributes:
    ds_scriptattributes.m_setup( ads_wsp_helper, 144 );
    ds_scriptattributes.m_add( "action",            (int)ied_scr_attr_action );
    ds_scriptattributes.m_add( "archive",           (int)ied_scr_attr_archive );
    ds_scriptattributes.m_add( "background",        (int)ied_scr_attr_background );
    ds_scriptattributes.m_add( "backgroundImage",   (int)ied_scr_attr_backgroundimage );
    ds_scriptattributes.m_add( "BaseURL",           (int)ied_scr_attr_baseurl );
    ds_scriptattributes.m_add( "behavior",          (int)ied_scr_attr_behavior );
    ds_scriptattributes.m_add( "cite",              (int)ied_scr_attr_cite );
    ds_scriptattributes.m_add( "classid",           (int)ied_scr_attr_classid );
    ds_scriptattributes.m_add( "code",              (int)ied_scr_attr_code );
    ds_scriptattributes.m_add( "codebase",          (int)ied_scr_attr_codebase );
    ds_scriptattributes.m_add( "content",           (int)ied_scr_attr_content );
    ds_scriptattributes.m_add( "cookie",            (int)ied_scr_attr_cookie );
    ds_scriptattributes.m_add( "cssText",           (int)ied_scr_attr_csstext );
    ds_scriptattributes.m_add( "cursor",            (int)ied_scr_attr_cursor );
    ds_scriptattributes.m_add( "datasrc",           (int)ied_scr_attr_datasrc );
    ds_scriptattributes.m_add( "DocumentHTML",      (int)ied_scr_attr_documenthtml );
    ds_scriptattributes.m_add( "domain",            (int)ied_scr_attr_domain );
    ds_scriptattributes.m_add( "filter",            (int)ied_scr_attr_filter );
    ds_scriptattributes.m_add( "hash",              (int)ied_scr_attr_hash );
    ds_scriptattributes.m_add( "host",              (int)ied_scr_attr_host );
    ds_scriptattributes.m_add( "hostname",          (int)ied_scr_attr_hostname );
    ds_scriptattributes.m_add( "href",              (int)ied_scr_attr_href );
    ds_scriptattributes.m_add( "innerHTML",         (int)ied_scr_attr_innerhtml );
#if SM_USE_ATTRIBUTE_LENGTH
    ds_scriptattributes.m_add( "length",            (int)ied_scr_attr_length );
#endif
    ds_scriptattributes.m_add( "listStyleImage",    (int)ied_scr_attr_liststyleimage );
    ds_scriptattributes.m_add( "location",          (int)ied_scr_attr_location );
    ds_scriptattributes.m_add( "longdesc",          (int)ied_scr_attr_longdesc );
    ds_scriptattributes.m_add( "lowsrc",            (int)ied_scr_attr_lowsrc );
    ds_scriptattributes.m_add( "nodeValue",         (int)ied_scr_attr_nodevalue );
    ds_scriptattributes.m_add( "outerHTML",         (int)ied_scr_attr_outerhtml );
    ds_scriptattributes.m_add( "pathname",          (int)ied_scr_attr_pathname );
    ds_scriptattributes.m_add( "pluginspage",       (int)ied_scr_attr_pluginspage );
    ds_scriptattributes.m_add( "port",              (int)ied_scr_attr_port );
    ds_scriptattributes.m_add( "profile",           (int)ied_scr_attr_profile );
    ds_scriptattributes.m_add( "protocol",          (int)ied_scr_attr_protcol );
    ds_scriptattributes.m_add( "referrer",          (int)ied_scr_attr_referrer );
    ds_scriptattributes.m_add( "search",            (int)ied_scr_attr_search );
    ds_scriptattributes.m_add( "setHomePage",       (int)ied_scr_attr_sethomepage );
    ds_scriptattributes.m_add( "sourceIndex",       (int)ied_scr_attr_sourceindex );
    ds_scriptattributes.m_add( "src",               (int)ied_scr_attr_src );
    ds_scriptattributes.m_add( "style",             (int)ied_scr_attr_style );
    ds_scriptattributes.m_add( "URL",               (int)ied_scr_attr_url );
    ds_scriptattributes.m_add( "usemap",            (int)ied_scr_attr_usemap );
    ds_scriptattributes.m_add( "value",             (int)ied_scr_attr_value );
    // functions:
    ds_scriptattributes.m_add( "addBehavior",           (int)ied_scr_attr_addbehavior );
    ds_scriptattributes.m_add( "AddChannel",            (int)ied_scr_attr_addchannel );
    ds_scriptattributes.m_add( "AddDesktopComponent",   (int)ied_scr_attr_adddesktopcomponent );
    ds_scriptattributes.m_add( "AddFavorite",           (int)ied_scr_attr_addfavorite );
    ds_scriptattributes.m_add( "addHierarchy",          (int)ied_scr_attr_addhierarchy );
    ds_scriptattributes.m_add( "addImport",             (int)ied_scr_attr_addimport );
    ds_scriptattributes.m_add( "addRule",               (int)ied_scr_attr_addrule );
    ds_scriptattributes.m_add( "AddSearchProvider",     (int)ied_scr_attr_addsearchprovider );
    ds_scriptattributes.m_add( "assign",                (int)ied_scr_attr_asign );
    ds_scriptattributes.m_add( "createStyleSheet",      (int)ied_scr_attr_createstylesheet );
    ds_scriptattributes.m_add( "doImport",              (int)ied_scr_attr_doimport );
    ds_scriptattributes.m_add( "eval",                  (int)ied_scr_attr_eval );
    ds_scriptattributes.m_add( "execCommand",           (int)ied_scr_attr_execcommand );
    ds_scriptattributes.m_add( "Function",              (int)ied_scr_attr_Function );
    ds_scriptattributes.m_add( "getAttribute",          (int)ied_scr_attr_getattribute );
    ds_scriptattributes.m_add( "getAttributeNode",      (int)ied_scr_attr_getattributenode );        
    ds_scriptattributes.m_add( "getElementsByTagName",  (int)ied_scr_attr_getelementsbytagname );
    ds_scriptattributes.m_add( "getResponseHeader",     (int)ied_scr_attr_getresponseheader );
    ds_scriptattributes.m_add( "go",                    (int)ied_scr_attr_go );
    //ds_scriptattributes.m_add( "ImportExportFavorites",(int)ied_scr_attr_importexportfavorites );
    ds_scriptattributes.m_add( "insertAdjacentHTML",    (int)ied_scr_attr_insertadjacenthtml );
    ds_scriptattributes.m_add( "insertRule",            (int)ied_scr_attr_insertrule );
    ds_scriptattributes.m_add( "item",                  (int)ied_scr_attr_item );
    ds_scriptattributes.m_add( "link",                  (int)ied_scr_attr_link );
    ds_scriptattributes.m_add( "load",                  (int)ied_scr_attr_load );
    ds_scriptattributes.m_add( "navigate",              (int)ied_scr_attr_navigate );
    ds_scriptattributes.m_add( "Navigate",              (int)ied_scr_attr_Navigate );
    ds_scriptattributes.m_add( "Navigate2",             (int)ied_scr_attr_navigate2 );
    ds_scriptattributes.m_add( "NavigateAndFind",       (int)ied_scr_attr_navigateandfind );
    ds_scriptattributes.m_add( "open",                  (int)ied_scr_attr_open );
    ds_scriptattributes.m_add( "pasteHTML",             (int)ied_scr_attr_pastehtml );
    ds_scriptattributes.m_add( "postMessage",           (int)ied_scr_attr_postmessage );
    ds_scriptattributes.m_add( "reload",                (int)ied_scr_attr_reload );
    ds_scriptattributes.m_add( "replace",               (int)ied_scr_attr_replace );
    ds_scriptattributes.m_add( "save",                  (int)ied_scr_attr_save );
    ds_scriptattributes.m_add( "setAttribute",          (int)ied_scr_attr_setattribute );
    ds_scriptattributes.m_add( "setAttributeNode",      (int)ied_scr_attr_setattributenode );
    ds_scriptattributes.m_add( "setExpression",         (int)ied_scr_attr_setexpression );
    ds_scriptattributes.m_add( "setInterval",           (int)ied_scr_attr_setinterval );   
    ds_scriptattributes.m_add( "setTimeout",            (int)ied_scr_attr_settimeout ); 
    ds_scriptattributes.m_add( "showHelp",              (int)ied_scr_attr_showhelp );
    ds_scriptattributes.m_add( "showModalDialog",       (int)ied_scr_attr_showmodaldialog );
    ds_scriptattributes.m_add( "showModelessDialog",    (int)ied_scr_attr_showmodelessdialog );
    ds_scriptattributes.m_add( "tags",                  (int)ied_scr_attr_tags );
    ds_scriptattributes.m_add( "write",                 (int)ied_scr_attr_write );
    ds_scriptattributes.m_add( "writeln",               (int)ied_scr_attr_writeln );
    // objects:
    ds_scriptattributes.m_add( "all",               (int)ied_scr_attr_all );
    ds_scriptattributes.m_add( "childNodes",        (int)ied_scr_attr_childnodes );
    ds_scriptattributes.m_add( "firstChild",        (int)ied_scr_attr_firstchild );
    ds_scriptattributes.m_add( "forms",             (int)ied_scr_attr_forms );
    ds_scriptattributes.m_add( "images",            (int)ied_scr_attr_images );
    ds_scriptattributes.m_add( "lastChild",         (int)ied_scr_attr_lastchild );
    ds_scriptattributes.m_add( "links",             (int)ied_scr_attr_links );
    ds_scriptattributes.m_add( "nextSibling",       (int)ied_scr_attr_nextsibling );
    ds_scriptattributes.m_add( "previousSibling",   (int)ied_scr_attr_previoussibling );
    // special handled words:
    ds_scriptattributes.m_add( "new",       (int)ied_scr_attr_new );
    ds_scriptattributes.m_add( "delete",    (int)ied_scr_attr_delete );
    ds_scriptattributes.m_add( "function",  (int)ied_scr_attr_function );
    ds_scriptattributes.m_add( "return",    (int)ied_scr_attr_return );
    ds_scriptattributes.m_add( "var",       (int)ied_scr_attr_var );
	ds_scriptattributes.m_add( "case",      (int)ied_scr_attr_case );

    // list of conditional compilation attributes:
    ds_cond_comp_attr.m_setup( ads_wsp_helper );
    ds_cond_comp_attr.m_add( "cc_on",   (int)ied_cc_cc_on );
    ds_cond_comp_attr.m_add( "if",      (int)ied_cc_if );
    ds_cond_comp_attr.m_add( "elif",    (int)ied_cc_elseif );
    ds_cond_comp_attr.m_add( "else",    (int)ied_cc_else );
    ds_cond_comp_attr.m_add( "end",     (int)ied_cc_end );
    ds_cond_comp_attr.m_add( "set",     (int)ied_cc_set );
} // end of ds_attributes::m_setup_script_table
