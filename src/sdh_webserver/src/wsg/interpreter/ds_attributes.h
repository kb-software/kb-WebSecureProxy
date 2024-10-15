#ifndef _DS_ATTRIBUTES_H
#define _DS_ATTRIBUTES_H
/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| PROGRAM:                                                            |*/
/*| =======                                                             |*/
/*|  ds_attributes - working strings for wsg interpreters               |*/
/*|                                                                     |*/
/*| AUTHOR:                                                             |*/
/*| ======                                                              |*/
/*|  Michael Jakobs, Nov. 2009                                          |*/
/*|                                                                     |*/
/*| VERSION:                                                            |*/
/*| =======                                                             |*/
/*|  0.1                                                                |*/
/*|                                                                     |*/
/*| COPYRIGHT:                                                          |*/
/*| =========                                                           |*/
/*|  HOB GmbH Germany                                                   |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
#define SM_USE_ATTRIBUTE_LENGTH   0

/*+---------------------------------------------------------------------+*/
/*| forward defintions:                                                 |*/
/*+---------------------------------------------------------------------+*/
class ds_wsp_helper;
template <class T> class ds_hashtable;

/*+---------------------------------------------------------------------+*/
/*| class defintion:                                                    |*/
/*+---------------------------------------------------------------------+*/
/*! \brief Contains working strings for WebServer Gate interpreters
 * 
 * @ingroup dataprocessor
 */
class ds_attributes {
public:
    // setup function like:
	//! Setup strings.
    void m_setup( ds_wsp_helper* ads_wsp_helper );
    
    // getter functions:
	//! Get value from html attribute
    int m_get_htm_attr( const char* achl_key, int in_len ) const;
	//! Get value from html tag
    int m_get_htm_tag ( const char* achl_key, int in_len ) const;
	//! Get value from html special values
    int m_get_htm_val ( const char* achl_key, int in_len ) const;
	//! Get value from html rel values
    int m_get_htm_rel ( const char* achl_key, int in_len ) const;
	//! Get value from html single sign on value
    int m_get_htm_sso ( const char* achl_key, int in_len ) const;
	//! Get value from script attribute
    int m_get_scr_attr( const char* achl_key, int in_len ) const;
	//! Get value from script conditional comments
    int m_get_scr_cc  ( const char* achl_key, int in_len ) const;


    // constants:
    enum ied_html_attributes {
        ied_htm_attr_start,    // DUMMY
        ied_htm_attr_action,
        ied_htm_attr_archive,
        ied_htm_attr_background,
        ied_htm_attr_cite,
        ied_htm_attr_classid,
        ied_htm_attr_code,
        ied_htm_attr_codebase,
        ied_htm_attr_content,
        ied_htm_attr_data,
        ied_htm_attr_datasrc,
        ied_htm_attr_href,
		  ied_htm_attr_xlink_href,
        ied_htm_attr_implementation,
        ied_htm_attr_longdesc,
        ied_htm_attr_lowsrc,
        ied_htm_attr_name,               // needed for special handling of value!!!
        ied_htm_attr_pluginspage,
        ied_htm_attr_profile,
        ied_htm_attr_rel,                // needed for detecting favicon
        ied_htm_attr_src,
        ied_htm_attr_usemap,
        ied_htm_attr_value,              // special handling depends of value of name (i.e. <param name="DataURL" value=uri> )
        ied_htm_attr_charset,
        ied_htm_attr_http_equiv,
        ied_htm_attr_type,
        ied_htm_attr_async,
        ied_htm_attr_defer,
        ied_htm_attr_language,
        ied_htm_attr_srcset,
		ied_htm_attr_integrity,
		ied_htm_attr_crossorigin,
		ied_htm_attr_sandbox,
		ied_htm_attr_method,
		ied_htm_attr_referrerpolicy,
		ied_htm_attr_srcdoc,
        ied_htm_attr_as,
        ied_htm_attr_end,      // DUMMY
        // javascript is following these attributes:
        ied_htm_attr_scr_start,    // DUMMY
        ied_htm_attr_onabort,
		ied_htm_attr_onautocomplete,
		ied_htm_attr_onautocompleteerror,
		ied_htm_attr_onblur,
		ied_htm_attr_oncancel,
		ied_htm_attr_oncanplay,
		ied_htm_attr_oncanplaythrough,
		ied_htm_attr_onchange,
		ied_htm_attr_onclick,
		ied_htm_attr_onclose,
		ied_htm_attr_oncontextmenu,
		ied_htm_attr_oncuechange,
		ied_htm_attr_ondblclick,
		ied_htm_attr_ondrag,
		ied_htm_attr_ondragend,
		ied_htm_attr_ondragenter,
		ied_htm_attr_ondragexit,
		ied_htm_attr_ondragleave,
		ied_htm_attr_ondragover,
		ied_htm_attr_ondragstart,
		ied_htm_attr_ondrop,
		ied_htm_attr_ondurationchange,
		ied_htm_attr_onemptied,
		ied_htm_attr_onended,
		ied_htm_attr_onerror,
		ied_htm_attr_onfocus,
		ied_htm_attr_oninput,
		ied_htm_attr_oninvalid,
		ied_htm_attr_onkeydown,
		ied_htm_attr_onkeypress,
		ied_htm_attr_onkeyup,
		ied_htm_attr_onload,
		ied_htm_attr_onloadeddata,
		ied_htm_attr_onloadedmetadata,
		ied_htm_attr_onloadstart,
		ied_htm_attr_onmousedown,
		ied_htm_attr_onmouseenter,
		ied_htm_attr_onmouseleave,
		ied_htm_attr_onmousemove,
		ied_htm_attr_onmouseout,
		ied_htm_attr_onmouseover,
		ied_htm_attr_onmouseup,
		ied_htm_attr_onmousewheel,
		ied_htm_attr_onpause,
		ied_htm_attr_onplay,
		ied_htm_attr_onplaying,
		ied_htm_attr_onprogress,
		ied_htm_attr_onratechange,
		ied_htm_attr_onreset,
		ied_htm_attr_onresize,
		ied_htm_attr_onscroll,
		ied_htm_attr_onseeked,
		ied_htm_attr_onseeking,
		ied_htm_attr_onselect,
		ied_htm_attr_onshow,
		ied_htm_attr_onsort,
		ied_htm_attr_onstalled,
		ied_htm_attr_onsubmit,
		ied_htm_attr_onsuspend,
		ied_htm_attr_ontimeupdate,
		ied_htm_attr_ontoggle,
		ied_htm_attr_onvolumechange,
		ied_htm_attr_onwaiting,
        ied_htm_attr_scr_end,    // DUMMY
        // css is following this attribute: 
        ied_htm_attr_css_start,    // DUMMY   
        ied_htm_attr_style,
        ied_htm_attr_css_end   // DUMMY
    };

    enum ied_html_tags {
        ied_htm_tag_base,
        ied_htm_tag_meta,
        ied_htm_tag_body,
        ied_htm_tag_frameset,
        ied_htm_tag_head,
        ied_htm_tag_link,
        ied_htm_tag_param,
        ied_htm_tag_public,
        ied_htm_tag_script,
        ied_htm_tag_style,
        ied_htm_tag_bodyend,
        ied_htm_tag_headend,
        ied_htm_tag_scriptend,
        ied_htm_tag_styleend,
        ied_htm_tag_scriptempty,       // like <script src=".." />
        ied_htm_tag_styleempty,         // like <style  src=".." />
        ied_htm_tag_iframe,
        ied_htm_tag_iframeend,
        ied_htm_tag_a,
        ied_htm_tag_area,
        ied_htm_tag_audio,
        ied_htm_tag_embed,
        ied_htm_tag_img,
        ied_htm_tag_input,
        ied_htm_tag_source,
        ied_htm_tag_track,
        ied_htm_tag_video,
        ied_htm_tag_form,
        ied_htm_tag_object,
        ied_htm_tag_frame,
        ied_htm_tag_element,
        ied_htm_tag_applet,
		  ied_htm_tag_svg_image,
		  ied_htm_tag_svg_use,
		  ied_htm_tag_svg_lineargradient,
    };

    enum ied_html_name_values {
        ied_htm_val_dataurl,
        ied_htm_val_dburl,
        ied_htm_val_cabbase,
        ied_htm_val_filename,
        ied_htm_val_href,
        ied_htm_val_movie,
        ied_htm_val_src,
        ied_htm_val_url
    };

    enum ied_html_rel_values {
        ied_htm_rel_icon,
        ied_htm_rel_style
    };

    enum ied_html_soo_list {
        ied_htm_sso_form,
        ied_htm_sso_action,
        ied_htm_sso_input,
        SOO_USERNAME,
        SOO_PASSWORD
    };


    enum ied_script_attributes
    {
        // attributes:
        ied_scr_attr_start,     // DUMMY
        ied_scr_attr_action,
        ied_scr_attr_archive,
        ied_scr_attr_background,
        ied_scr_attr_backgroundimage,
        ied_scr_attr_baseurl,
        ied_scr_attr_behavior,
        ied_scr_attr_cite,
        ied_scr_attr_classid,
        ied_scr_attr_code,
        ied_scr_attr_codebase,
        ied_scr_attr_content,
        ied_scr_attr_cookie,
        ied_scr_attr_csstext,
        ied_scr_attr_cursor,
        ied_scr_attr_datasrc,
        ied_scr_attr_documenthtml,
        ied_scr_attr_domain,
        ied_scr_attr_filter,
        ied_scr_attr_hash,
        ied_scr_attr_host,
        ied_scr_attr_hostname,
        ied_scr_attr_href,
        ied_scr_attr_innerhtml,
#if SM_USE_ATTRIBUTE_LENGTH
        ied_scr_attr_length,
#endif
        ied_scr_attr_liststyleimage,
        ied_scr_attr_location,
        ied_scr_attr_longdesc,
        ied_scr_attr_lowsrc,
        ied_scr_attr_nodevalue,
        ied_scr_attr_outerhtml,
        ied_scr_attr_pathname,
        ied_scr_attr_pluginspage,
        ied_scr_attr_port,
        ied_scr_attr_profile,
        ied_scr_attr_protcol,
        ied_scr_attr_referrer,
        ied_scr_attr_search,
        ied_scr_attr_sethomepage,
        ied_scr_attr_sourceindex,
        ied_scr_attr_src,
        ied_scr_attr_style,
        ied_scr_attr_url,
        ied_scr_attr_usemap,
        ied_scr_attr_value,
        ied_scr_attr_end,       // DUMMY

        // functions:
        ied_scr_attr_function_start,      // DUMMY
        ied_scr_attr_addbehavior,                    // IE only
        ied_scr_attr_addchannel,                     // IE only
        ied_scr_attr_adddesktopcomponent,            // IE only
        ied_scr_attr_addfavorite,                    // IE only
        ied_scr_attr_addhierarchy,                   // IE only
        ied_scr_attr_addimport,                      // IE only
        ied_scr_attr_addrule,                        // IE only
        ied_scr_attr_addsearchprovider,              // IE only
        ied_scr_attr_asign,                          // IE only
        ied_src_attr_createjicaapplet,               // MJ 13.10.2011, special for Citrix JICA integration
        ied_scr_attr_createstylesheet,               // IE only
        ied_scr_attr_doimport,                       // IE only
        ied_scr_attr_eval,
        ied_scr_attr_execcommand,
        ied_scr_attr_Function,                   // new Function( "var1", "var2", ..., "function" ) is special handled!!!
        ied_scr_attr_getattribute,
        ied_scr_attr_getattributenode,        
        ied_scr_attr_getelementsbytagname,
        ied_scr_attr_getresponseheader,              // IE only
        ied_scr_attr_go,                             // IE only
        ied_scr_attr_importexportfavorites,          // IE only
        ied_scr_attr_insertadjacenthtml,
        ied_scr_attr_insertrule,                     
        ied_scr_attr_item,
        ied_scr_attr_link,
        ied_scr_attr_load,
        ied_scr_attr_navigate,                       // IE only
        ied_scr_attr_Navigate,                       // IE only
        ied_scr_attr_navigate2,                      // IE only
        ied_scr_attr_navigateandfind,                // IE only
        ied_scr_attr_open,
        ied_scr_attr_pastehtml,                      // IE only
        ied_scr_attr_postmessage,
        ied_scr_attr_reload,
        ied_scr_attr_replace,
        ied_scr_attr_save,                           // IE only
        ied_scr_attr_setattribute,
        ied_scr_attr_setattributenode,
        ied_scr_attr_setexpression,                  // IE only
        ied_scr_attr_setinterval,
        ied_scr_attr_settimeout,
        ied_scr_attr_showhelp,                       // IE only
        ied_scr_attr_showmodaldialog,                // IE only
        ied_scr_attr_showmodelessdialog,             // IE only
        ied_scr_attr_tags,
        ied_scr_attr_write,
        ied_scr_attr_writeln,
        ied_scr_attr_function_end,        // DUMMY

        // objects:
        ied_scr_attr_obj_start,        // DUMMY
        ied_scr_attr_all,
        ied_scr_attr_childnodes,    
        ied_scr_attr_firstchild,
        ied_scr_attr_forms,
        ied_scr_attr_images,
        ied_scr_attr_lastchild,
        ied_scr_attr_links,
        ied_scr_attr_nextsibling,
        ied_scr_attr_previoussibling,
        ied_scr_attr_obj_end,          // DUMMY

        // special handled words:
        ied_scr_attr_new,
        ied_scr_attr_delete,
        ied_scr_attr_function,
        ied_scr_attr_return,
        ied_scr_attr_var,
		ied_scr_attr_case
    };

    enum ied_cc_on {
        ied_cc_cc_on,
        ied_cc_if,
        ied_cc_elseif,
        ied_cc_else,
        ied_cc_end,
        ied_cc_set 
    };

private:
    // variables:    
    ds_hashtable<int> ds_htmlattributes;
    ds_hashtable<int> ds_htmlspecialnamevalues;
    ds_hashtable<int> ds_htmlrelvalues;
    ds_hashtable<int> ds_htmltags;
    ds_hashtable<int> ds_html_soo_list;

    ds_hashtable<int> ds_scriptattributes;
    ds_hashtable<int> ds_cond_comp_attr;
    
    // functions:
    void m_setup_html_table  ( ds_wsp_helper* ads_wsp_helper );
    void m_setup_script_table( ds_wsp_helper* ads_wsp_helper );
};

#endif // _DS_ATTRIBUTES_H
