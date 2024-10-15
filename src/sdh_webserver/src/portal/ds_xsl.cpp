/*+-------------------------------------------------------------------------+*/
/*| include global headers                                                  |*/
/*+-------------------------------------------------------------------------+*/
#include <ds_ldap.h>    // must be first!!!
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H
#include <hob-libwspat.h>
#include <ds_hvector.h>
#include <ds_hstring.h>
#include <ds_portlet.h>
#include <ds_bookmark.h>
#include <dsd_wfa_bmark.h>
#include <ds_workstation.h>
#include <ds_jwtsa_conf.h>
#include <ds_hobte_conf.h>
#include <ds_wsp_admin.h>
#include <time.h>
#include <ds_usercma.h>
#include <ds_authenticate.h>
#ifdef HL_UNIX
    #include <ctype.h>
#endif
#ifdef HL_FREEBSD
#include <sys/socket.h>
#endif

#ifdef DS_PORTLET_FILTER_U_A
#include "xs_user_agent_worker.h"
#endif

// Includes neccesary only for having available the definitions of the WSP-Trace flags.
#define HOB_CONTR_TIMER
#include <hob-avl03.h>
#include <hob-wsppriv.h>
#include <hob-netw-01.h>
#include <hob-xslcontr.h>
#include <hob-xbipgw08-1.h>
#include <hob-xbipgw08-2.h>
/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "ds_xsl.h"
#include "hob-postparams.h"
#include "hob-xslvalues.h"

#include "../ds_session.h"

/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/
#ifndef XSL_NAMESPACE
    #define XSL_NAMESPACE       "xsl:"
#endif
#define PREFIX_CMA_NAME_IWS     "IWS/"
#define PREFIX_CMA_IWS_CACHE    "cache"

#define XSL_KEY_REVERSE         "not("
#define XSL_RES_YES             "yes"
#define XSL_RES_NO              "no"
#define XSL_ENCODING            "enc:"

#define XSL_KEY_WSPADMIN_PARAMS         "wspadmin/return/invalid-parameters"
#define XSL_KEY_WSPADMIN_EOF            "wspadmin/return/end-of-file"
#define XSL_KEY_WSPADMIN_INV_REQ        "wspadmin/return/invalid-request"
#define XSL_KEY_WSPADMIN_REC_UNAVAIL    "wspadmin/return/resource-unavailable"
#define XSL_KEY_WSPADMIN_TIMEOUT        "wspadmin/return/timeout"
#define XSL_KEY_WSPADMIN_INV_CLUSTER    "wspadmin/return/invalid-cluster"
#define XSL_KEY_WSPADMIN_MISC           "wspadmin/return/miscellaneous"
#define XSL_KEY_WSPADMIN_UNKNOWN        "wspadmin/return/unknown"

#define XSL_KEY_LANGNAME                "lang-name"

#define XSL_MAX_NUM_OF_REC_CALLS         200          // avoid "stack-overflow"

#define HL_WT_CORE_OTHERS (0xFFFF ^ (  HL_WT_CORE_DATA1    | HL_WT_CORE_DATA2     | HL_WT_CORE_CONSOLE | \
                                        HL_WT_CORE_CLUSTER  | HL_WT_CORE_UDP       | HL_WT_CORE_DOD | \
                                        HL_WT_CORE_RADIUS   | HL_WT_CORE_VIRUS_CH  | HL_WT_CORE_HOB_TUN | \
                                        HL_WT_CORE_LDAP     | HL_WT_CORE_KRB5      | HL_WT_CORE_MS_RPC  | \
                                        HL_WT_CORE_ADMIN    | HL_WT_CORE_LIGW))
#define HL_WT_SESS_OTHERS (0xFFFF ^ (  HL_WT_SESS_DATA1        | HL_WT_SESS_DATA2         | HL_WT_SESS_NETW | \
                                        HL_WT_SESS_SSL_EXT      | HL_WT_SESS_SSL_INT       | HL_WT_SESS_SSL_OCSP | \
                                        HL_WT_SESS_WSPAT3_EXT   | HL_WT_SESS_WSPAT3_INT    | HL_WT_SESS_SDH_EXT | \
                                        HL_WT_SESS_SDH_INT      | HL_WT_SESS_AUX           | HL_WT_SESS_MISC))
/*+-------------------------------------------------------------------------+*/
/*| for m_cb_print_bytes:                                                   |*/
/*+-------------------------------------------------------------------------+*/
static const char chrs_edit_sci[]     = { 'K', 'M', 'G' };
static const char chrs_edit_decimal[] = { '.', ',' };

/*+-------------------------------------------------------------------------+*/
/*| data structure definition:                                              |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief structure to cache the timestamp of creation
 *
 * @ingroup landingpage
 *
 * stores a timestamp
 */
struct ds_cache_header {
    hl_time_t  tm_created; // timestamp of creation
};

// known xsl tags (compare to enum ied_xsl_tags)
static const dsd_const_string achr_known_xsltags[] = {
    "value-of",
    "for-each",
    "if",
    "attribute",
    "template",
    "call-template",
    "variable",
    "include",
    "comment"
};

// valid xsl attributes in xsl tags for each tag
// (compare to achr_known_xsltags):
static const dsd_const_string achr_valid_xslattr[] = {
    "select",       // attribute for "value-of"
    "select",       // attribute for "for-each"
    "test",         // attribute for "if"
    "name",         // attribute for "attribute"
    "match",        // attribute for "template"
    "name",         // attribute for "call-template"
    "name",         // attribute for "variable"
    "href",         // attribute for "include"
    dsd_const_string(), // "comment" has no attribute
};

// known compare options (m_get_compare)
// (compare to enum ied_xsl_compare):
static const dsd_const_string achr_xsl_compare[] = {
    "&gt;",         // greater
    "&gt;=",        // greater equal
    "&lt;",         // lower
    "&lt;=",        // lower equal
    "==",           // equal
    "!="            // not equal
};

// known encoding options (m_get_encoding)
// (compare to enum ied_xsl_value_encoding):
static const dsd_const_string achr_xsl_value_encodings[] = {
    "html",
    "uri",
    "utf8",
    "js",
    "b64"
};

#define HL_DEF_UNICODE_STRING(x) (void*)x, sizeof(x)-1, ied_chs_utf_8

static const dsd_unicode_string DSRS_WEBTERM_LINKS[] = {
    { NULL, 0, ied_chs_utf_8 },                 // ied_webterm_subprotocol_unknown
    { HL_DEF_UNICODE_STRING("rdp/direct.hsl") }, // ied_webterm_subprotocol_rdp,
    { HL_DEF_UNICODE_STRING("ssh/default.hsl") }, // ied_webterm_subprotocol_ssh,
    { HL_DEF_UNICODE_STRING("VT525/default.hsl") }, // ied_webterm_subprotocol_vt525,
    { HL_DEF_UNICODE_STRING("TN3270/default.hsl") }, // ied_webterm_subprotocol_tn3270,
    { HL_DEF_UNICODE_STRING("TN5250/default.hsl") }, // ied_webterm_subprotocol_tn5250,
    { NULL, 0, ied_chs_utf_8  } // ied_webterm_subprotocol_tedefault,
};
static const size_t IMS_NUM_WEBTERM_LINKS = sizeof(DSRS_WEBTERM_LINKS)/sizeof(DSRS_WEBTERM_LINKS[0]);

/*! \brief attribute class
 *
 * @ingroup landingpage
 *
 * just stores a name / value pair
 */
class dsd_variable {
public:
    ds_hstring    dsc_name;
    ds_hstring    dsc_value;
};

/*+-------------------------------------------------------------------------+*/
/*| constructor:                                                            |*/
/*+-------------------------------------------------------------------------+*/
ds_xsl::ds_xsl(void) {
    ads_session    = NULL;
    ads_wsp_helper = NULL;
    ach_cache      = NULL;
    in_cache_len   = 0;
    adsc_msg       = NULL;
    inc_rec_call   = 0;
#ifdef _DEBUG
    inc_rec_peak   = 0;
#endif
	memset(&this->dsc_cma, 0, sizeof(this->dsc_cma));
}

/*+-------------------------------------------------------------------------+*/
/*| destructor:                                                             |*/
/*+-------------------------------------------------------------------------+*/
ds_xsl::~ds_xsl(void) {
}

/*+-------------------------------------------------------------------------+*/
/*| setup function:                                                         |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief XSL initialization function
 *
 * @ingroup landingpage
 *
 * function ds_xsl::m_init
 *
 * @param[in]   ds_session* ads_session_in
 * @return      nothing
*/
void ds_xsl::m_init( ds_session* ads_session_in )
{
    ads_session    = ads_session_in;
    ads_wsp_helper = ads_session->ads_wsp_helper;
    dsc_admin.m_init( ads_session->ads_wsp_helper, ads_session->dsc_webserver.ads_query );
    dsc_auth.m_init ( ads_wsp_helper );

    in_replaced_lang = -1;
} // end of ds_xsl::m_init


/*+-------------------------------------------------------------------------+*/
/*| public functions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief Get the xsl data
 *
 * @ingroup landingpage
 *
 * function ds_xsl::m_get_data
 *
 * @param[out]  ds_hstring*     ads_out             output buffer
 * @param[in]   const char*     ach_file            file name (full path)
 * @param[in]   int             in_len_file         length of file name
 * @param[in]   dsd_msg_t*      adsl_msg            message
 *                                                  default = NULL
 *
 * @return       bool           true = success
*/
bool ds_xsl::m_get_data( ds_hstring* ads_out,
                         const char* ach_file, int in_len_file, dsd_msg_t* adsl_msg )
{
    // initialize some variables;
    bool           bo_return       = false;         // return value
    ds_hstring     dsc_cache;                       // name of current cache
    char*          ach_fdata       = NULL;          // file content
    int            in_flen         = 0;             // length of file content
    void*          av_return       = NULL;          // return from parse
    int            in_len_head     = 0;             // length of cache header

    dsc_parser.m_init( ads_wsp_helper );
    ads_out->m_reset();

    //-----------------------------------------------
    // save message:
    //-----------------------------------------------
    adsc_msg = adsl_msg;

    //-----------------------------------------------
    // we will include whitespaces and data tags:
    //-----------------------------------------------
    dsc_parser.m_include_ws();
    dsc_parser.m_include_datatags();

    //-----------------------------------------------
    // check if data should be cached in cma:
    //-----------------------------------------------
    if ( (ads_session->ads_config->in_settings & SETTING_CACHE_XSL) == SETTING_CACHE_XSL ) {
        // setup cache name:
        dsc_cache.m_setup( ads_wsp_helper );

        //-------------------------------------------
        // get data from cache:
        //-------------------------------------------
        m_get_cache_name( ach_file, in_len_file, &dsc_cache );
        m_get_cache( dsc_cache.m_get_ptr(), dsc_cache.m_get_len() );

        //-------------------------------------------
        // check for file modifications:
        //-------------------------------------------
        if ( m_is_file_modified( ach_file, in_len_file ) == true ) {
            /*
                if there are some filemodifications, we will
                    parse file again
                    cache the data
                    generate output directly from parsed data (not from cache)

                therefore m_gen_output MUST be called inside this if statement
                this case is also valid if no cache is existing yet
            */

            //---------------------------------------
            // open file:
            //---------------------------------------
            bo_return = m_get_file( &ach_fdata, &in_flen );
            if ( bo_return == false ) {
                ads_out->m_write( MSG_FILE_NOT_FOUND );
                return false;
            }

            //---------------------------------------
            // parse file:
            //---------------------------------------
            av_return = (void*)dsc_parser.m_from_xml( ach_fdata, in_flen );
            if ( av_return == NULL ) {
                ads_out->m_write( MSG_PARSE_ERROR );
                m_release_file();
                return false;
            }

            //---------------------------------------
            // update cache:
            //---------------------------------------
            bo_return = m_update_cache( dsc_cache.m_get_ptr(),
                                        dsc_cache.m_get_len() );
            if ( bo_return == false ) {
                ads_out->m_write( MSG_CACHE_ERROR );
                m_release_file();
                return false;
            }

            //---------------------------------------
            // generate output parsed data:
            //---------------------------------------
            m_gen_output( ads_out );

            //---------------------------------------
            // close file:
            //---------------------------------------
            m_release_file();

        } else {
            /*
                if there are no filemodifications, we will
                    read data from cache
                    generate output from cache
            */

            //---------------------------------------
            // read cache:
            //---------------------------------------
            in_len_head = (((int)sizeof(ds_cache_header) + (ALIGN_SIZE-1)) & (~(ALIGN_SIZE-1)));
            av_return = (void*)dsc_parser.m_read_cache( &ach_cache[in_len_head],
                                                        in_cache_len - in_len_head );
            if ( av_return == NULL ) {
                ads_out->m_write( MSG_CACHE_ERROR );
                return false;
            }

            //---------------------------------------
            // generate output from cached data:
            //---------------------------------------
            m_gen_output( ads_out );
        }


        //-------------------------------------------
        // close cache:
        //-------------------------------------------
        m_close_cache();
    } else {
        //-------------------------------------------
        // init diskfile structure:
        //-------------------------------------------
        memset(&ds_file, 0, sizeof(struct dsd_hl_aux_diskfile_1));
#ifndef WSP_V24
        ds_file.iec_chs_name = ied_chs_utf_8;
        ds_file.ac_name      = (void*)ach_file;
        ds_file.inc_len_name = in_len_file;
#endif
#ifdef WSP_V24
        ds_file.dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;
        ds_file.dsc_ucs_file_name.ac_str      = (void*)ach_file;
        ds_file.dsc_ucs_file_name.imc_len_str = in_len_file;
#endif

        //-------------------------------------------
        // open file:
        //-------------------------------------------
        bo_return = m_get_file( &ach_fdata, &in_flen );
        if ( bo_return == false ) {
            ads_out->m_write( MSG_FILE_NOT_FOUND );
            return false;
        }

        //-------------------------------------------
        // parse file:
        //-------------------------------------------
        av_return = (void*)dsc_parser.m_from_xml( ach_fdata, in_flen );
        if ( av_return == NULL ) {
            ads_out->m_write( MSG_PARSE_ERROR );
            m_release_file();
            return false;
        }

        //-------------------------------------------
        // generate output parsed data:
        //-------------------------------------------
        m_gen_output( ads_out );

        //-------------------------------------------
        // close file:
        //-------------------------------------------
        m_release_file();
    }

    return true;
} // end of ds_xsl::m_get_data


/*! \brief Sets a back link
 *
 * @ingroup landingpage
 *
 * public function ds_xsl::m_set_ersb
 * set if back link should be shown on error page
 *
 * @param[in]   bool    bo_show_back
*/
void ds_xsl::m_set_ersb( bool bo_show_back )
{
    boc_show_back = bo_show_back;
} // end ds_xsl::m_set_ersb


/*+-------------------------------------------------------------------------+*/
/*| private functions:                                                      |*/
/*+-------------------------------------------------------------------------+*/
/**
 * function ds_xsl::m_cb_get_data
 * get data to insert in xsl
 * 
 * @param[in]   char*           ach_value       request value
 * @param[in]   int             in_len_val      length of request value
 * @param[out]  ds_hstring*     ads_out         output buffer
 * @param[in]   ds_hvector*     ads_element     element counter for "for-each" loop
*/
void ds_xsl::m_cb_get_data( const char* ach_value, int in_len_val,
                            ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element )
{
    // initialize some variables:
    const char*            ach_data     = NULL;               // output data
    int              in_len_data  = 0;                  // length of output data
    int              in_key       = 0;                  // start of key for resources
    dsd_xsl_iterator* adsl_member;                         // member of resources
    ied_xslvalue     ied_group;                         // main group of value
    ied_xslvalue     ied_type;                          // type of value
    ds_hvector_btype<int> dsc_type( ads_wsp_helper );

    //-----------------------------------------
    // get type of value:
    //-----------------------------------------
    m_get_type( &dsc_type, ach_value, in_len_val );
    if ( dsc_type.m_empty() == true ) {
        return;
    }
    ied_group = (ied_xslvalue)dsc_type.m_get_first();
    ied_type  = (ied_xslvalue)dsc_type.m_get_last ();    

    //-----------------------------------------
    // get data:
    //-----------------------------------------
    switch ( ied_group ) {
        //-------------------------------------
        // rdvpn product group:
        //-------------------------------------
        case ied_xslgrp_rdvpn:
            return m_cb_get_rdvpn_data( (int)ied_type, ads_out );
        
        //-------------------------------------
        // user group:
        //-------------------------------------
        case ied_xslgrp_usr:
            return m_cb_get_usr_data( (int)ied_type, ads_out, ads_element );

        //-------------------------------------
        // login group:
        //-------------------------------------
        case ied_xslgrp_login:
            return m_cb_get_login_data( (int)ied_type, ads_out, ads_element );

        //-------------------------------------
        // logout group:
        //-------------------------------------
        case ied_xslgrp_logout:
            return m_cb_get_logout_data( (int)ied_type, ads_out, ads_element );

        //-------------------------------------
        // ppptunnel group:
        //-------------------------------------
        case ied_xslgrp_ppptnl:
            return m_cb_get_ppptnl_data( (int)ied_type, ads_out, ads_element );

        //-------------------------------------
        // postparam group:
        //-------------------------------------
        case ied_xslgrp_queryparam:
            return m_cb_get_queryparam_data( (int)ied_type, ads_out );

        //-------------------------------------
        // wspadmin group:
        //-------------------------------------
        case ied_xslgrp_wspadmin:
            return m_cb_get_wspadmin_data( &dsc_type, ads_out, ads_element );
		case ied_xslgrp_wspadmin_trace:
			return m_cb_get_wspadmin_trace_data ( &dsc_type, ads_out, ads_element );

        //-------------------------------------
        // query group:
        //-------------------------------------
        case ied_xslgrp_query: {
            m_split_value( ach_value, in_len_val, &in_key );
            if ( in_key < in_len_val ) {
                in_key++; // go over '/'
                dsd_const_string dsl_query_key(&ach_value[in_key], in_len_val - in_key);
                dsd_const_string dsl_query_out;
                ads_session->dsc_webserver.m_get_query_value(dsl_query_key, &dsl_query_out);
                ads_out->m_write_html_text(dsl_query_out);
            }
        }

        //-------------------------------------
        // language group:
        //-------------------------------------
        case ied_xslgrp_lang:
            adsl_member = ads_element->m_get_last_ref();
            m_split_value( ach_value, in_len_val, &in_key );
            if ( in_key < in_len_val ) {
                in_key++; // go over '/'
                dsd_const_string dsl_lang_key(&ach_value[in_key], in_len_val - in_key);
                if ( adsl_member->dsc_rac.inc_cur >= 0 
                    && dsl_lang_key.m_equals(XSL_KEY_LANGNAME) )
                {
                    RESOURCES->m_get( adsl_member->dsc_rac.inc_cur,
                        dsl_lang_key.m_get_start(), dsl_lang_key.m_get_len(),
                        &ach_data, &in_len_data );
                }
                else {
                    GET_RESOURCE( dsl_lang_key.m_get_start(), dsl_lang_key.m_get_len(),
                                  ach_data, in_len_data );
                }
            } else {
#if 0
                if ( ads_session->dsc_control.in_cma_lang >= 0 ) {
                    if ( in_replaced_lang == -1 ) {
                        in_replaced_lang = adsl_member->dsc_rac.inc_cur;
                        adsl_member->dsc_rac.inc_cur = ads_session->dsc_control.in_cma_lang;
                        //ads_element->m_set_last( adsl_member );
                    } else if ( adsl_member->dsc_rac.inc_cur == ads_session->dsc_control.in_cma_lang ) {
                        adsl_member->dsc_rac.inc_cur = in_replaced_lang;
                        //ads_element->m_set_last( adsl_member );
                    }
                }
#endif
                RESOURCES->m_get_lang( adsl_member->dsc_rac.inc_cur, &ach_data, &in_len_data );
            }
            //TBD: do not html escape language date: should already be escaped (xml input)
            //ads_out->m_write_html_text( dsd_const_string(ach_data, in_len_data) );
            ads_out->m_write( ach_data, in_len_data );
            return;

        default:
            break;
    }
    
    return;
} // end of ds_xsl::m_cb_get_data


/**
 * function ds_xsl::m_cb_no_childs
 * get data to insert in xsl
 * 
 * @param[in]   char*           ach_value       request value
 * @param[in]   int             in_len_val      length of request value
 * @return      int                             number of child elements
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_element     element counter for "for-each" loop
*/
int ds_xsl::m_cb_no_childs( const char* ach_value, int in_len_val,
    ds_hstack_btype<dsd_xsl_iterator>* ads_element, dsd_xsl_iterator& rdsp_iter_out, int& riep_type )
{
    // initialize some variables:
    int                 in_count        = 0;                // number of elements
    dsd_xsl_iterator*   in_elem;                            // member
    ied_xslvalue        ied_type;                           // type of value
    dsd_cluster*        ads_cluster;                        // cluster list
    dsd_cluster_remote_01* ads_rem_cluster;                 // rem cluster element
    dsd_session_info*   ads_wsp_session;                    // session list
    dsd_listen*         ads_listen;                         // listen list
    dsd_each_listen*    ads_each;                           // each listen list
    dsd_perfdata*       ads_perfdata;                       // performance data
	dsd_wsptrace_info*	adsl_wsptrace;						// WSP Trace structure pointer
    dsd_log_info*       ads_loginfo;                        // logfile list
    dsd_query_uov_t     dsl_user_query;                     // user query structure
    ds_hvector_btype<int>    dsc_type( ads_wsp_helper );
    struct dsd_pppt*    adsl_ppptnl;                        // current ppptunnel structure
    dsd_wspat_pconf_t   *adsl_wspat_conf;

    //-----------------------------------------
    // get type of value:
    //-----------------------------------------
    m_get_type( &dsc_type, ach_value, in_len_val );
    ied_type = (ied_xslvalue)dsc_type.m_get_last();
    riep_type = ied_type;

	/* hofmants: only check if value is unknown, not if it is a group */
    if ( ied_type == ied_xslval_unknown ){ return 0; }

    rdsp_iter_out.iec_mode = ied_xsl_iterator_mode_random;
    rdsp_iter_out.avoc_user = NULL;
    rdsp_iter_out.dsc_rac.inc_cur = 0;
    rdsp_iter_out.dsc_rac.inc_end = 0;
    //-----------------------------------------
    // get data:
    //-----------------------------------------
    switch ( ied_type ) {
        //-------------------------------------
        // language group:
        //-------------------------------------
        case ied_xslgrp_lang:
            in_count = RESOURCES->m_count_lang();
            break;

        //-------------------------------------
        // user cookie sub group:
        //-------------------------------------
        case ied_xslgrp_usr_cookie:
			rdsp_iter_out.iec_mode = ied_xsl_iterator_mode_fwd;
            in_count = ads_session->dsc_ws_gate.dsc_ck_manager.m_count_cur_cookies(
				ads_session->dsc_auth.m_get_basename(), &rdsp_iter_out.dsc_fwd );
            return in_count;

        //-------------------------------------
        // user portlet sub group:
        //-------------------------------------
        case ied_xslgrp_usr_portlet:
            in_count = ads_session->dsc_auth.m_count_portlets(rdsp_iter_out.dsc_rac);
            break;

		//-------------------------------------
        // user bookmark sub group:
        //-------------------------------------
        case ied_xslgrp_usr_wsg_bmarks:
            in_count = ads_session->dsc_auth.m_count_wsg_bookmarks();
            break;

        case ied_xslgrp_usr_rdvpn_bmarks:
            in_count = ads_session->dsc_auth.m_count_rdvpn_bookmarks();
            break;

        case ied_xslgrp_usr_wfa_bmarks:
            in_count = ads_session->dsc_auth.m_count_wfa_bookmarks();
            break;

        //-------------------------------------
        // user workstation sub group:
        //-------------------------------------
        case ied_xslgrp_usr_wstats:
            in_count = ads_session->dsc_auth.m_count_workstations();
            break;

        //-------------------------------------
        // user jwtsa sub group:
        //-------------------------------------
		case ied_xslgrp_usr_jwtsa_config:
			in_count = ads_session->dsc_auth.m_jwtsa_count_configs();
			break;

#if 0
		//-------------------------------------
        // user webterm sub group:
        //-------------------------------------
		case ied_xslgrp_usr_webterm:
			in_count = ads_session->dsc_auth.m_webterm_count_server_entries();
			break;
#endif

		//-------------------------------------
        // user webterm sub group:
        //-------------------------------------
		case ied_xslgrp_usr_webterm_rdp:
			in_count = ads_session->dsc_auth.m_webterm_count_server_entries(ied_webterm_protogroup_rdp);
            rdsp_iter_out.avoc_user = (void*)ied_webterm_protogroup_rdp;
			break;
		case ied_xslgrp_usr_webterm_te:
#if BO_HOBTE_CONFIG      
			in_count = ads_session->dsc_auth.m_hobte_count_configs();
            rdsp_iter_out.avoc_user = (void*)ied_webterm_protogroup_te;
			break;
#else
            in_count = 0;
            break;
#endif

        case ied_xslgrp_usr_webterm_ssh:
            in_count = ads_session->dsc_auth.m_webterm_count_server_entries(ied_webterm_protogroup_ssh);
            rdsp_iter_out.avoc_user = (void*)ied_webterm_protogroup_ssh;
            break;

        //-------------------------------------
        // login domain sub group:
        //-------------------------------------
        case ied_xslgrp_login_domain:
            adsl_wspat_conf = ads_wsp_helper->m_get_wspat_config();
            if ( adsl_wspat_conf != NULL ) {
				rdsp_iter_out.iec_mode = ied_xsl_iterator_mode_fwd;
	            rdsp_iter_out.dsc_fwd.avoc_cur = adsl_wspat_conf->dsc_domains.adsc_domain;
		        rdsp_iter_out.dsc_fwd.avoc_end = NULL;
				return 0;
            }
            break;

        //-------------------------------------
        // login kickout sub group:
        //-------------------------------------
        case ied_xslgrp_login_kick_out:
            in_count = (int)ads_session->dscv_kick_out.m_size();
            break;

        //-------------------------------------
        // logout session sub group:
        //-------------------------------------
        case ied_xslgrp_logout_session:
            in_count = (int)ads_session->dsc_webserver.dsc_v_logout_connections.m_size();
            break;

        //-------------------------------------
        // ppptunnel group:
        //-------------------------------------
        case ied_xslgrp_ppptnl:
			adsl_ppptnl = ads_session->ads_config->adsl_pppt;
			while ( adsl_ppptnl != NULL ) {
				void*				avl_srv_handle		= NULL;
			    char                chrl_buffer[512];           // temp buffer for server name    
				int                 inl_len;
				int					inl_function		= -1;
				do {
					inl_len = 512;
					avl_srv_handle = ads_wsp_helper->m_cb_get_server_entry(NULL, NULL, ied_scp_hpppt1, NULL, 0, 
														  chrl_buffer,
														  &inl_len,
														  avl_srv_handle, &inl_function );
					if (avl_srv_handle == NULL) {
						break;
					}
					if(	( adsl_ppptnl->in_len_server_entry_name == inl_len )
						&&	( memcmp( adsl_ppptnl->ach_server_entry_name, chrl_buffer, inl_len ) == 0 ) ){

						in_count++;
						break;
					}
				} while (TRUE);
				adsl_ppptnl = adsl_ppptnl->adsc_next;
			}
			break;

        //-------------------------------------
        // wspadmin cluster sub group:
        //-------------------------------------
        case ied_xslgrp_wspadmin_cluster:
            ads_cluster = dsc_admin.m_get_cluster_info();
            if ( ads_cluster == NULL ) {
                return 0;
            }
            in_count = 1;
            ads_rem_cluster = ads_cluster->ads_next;
            while ( ads_rem_cluster != NULL ) {
                in_count++;
                ads_rem_cluster = ads_rem_cluster->ads_next;
            }            
            break;

        //-------------------------------------
        // wspadmin session sub group:
        //-------------------------------------
        case ied_xslgrp_wspadmin_session:
            ads_wsp_session = dsc_admin.m_get_session_info();
            while ( ads_wsp_session != NULL ) {
                in_count++;
                ads_wsp_session = ads_wsp_session->ads_next;
            }            
            break;

        //-------------------------------------
        // wspadmin listen sub group:
        //-------------------------------------
        case ied_xslgrp_wspadmin_listen:
            ads_listen = dsc_admin.m_get_listen_info();
            rdsp_iter_out.iec_mode = ied_xsl_iterator_mode_fwd;
            rdsp_iter_out.dsc_fwd.avoc_cur = ads_listen;
            rdsp_iter_out.dsc_fwd.avoc_end = NULL;
            return 0;

        //-------------------------------------
        // wspadmin listen ineta subsub group:
        //-------------------------------------
        case ied_xslgrp_wspadmin_listen_ineta:
            ads_listen = dsc_admin.m_get_listen_info();
            if ( ads_listen == NULL ) {
                return 0;
            }
            in_elem = ads_element->m_get_last_ref();
            for ( int in_1 = 0; in_1 < in_elem->dsc_rac.inc_cur; in_1++ ) {
                ads_listen = ads_listen->ads_next;
                if ( ads_listen == NULL ) {
                    return 0;
                }
            }
            ads_each = ads_listen->ads_each;
            while ( ads_each != NULL ) {
                in_count++;
                ads_each = ads_each->ads_next;
            }            
            break;

        //-------------------------------------
        // wspadmin performance sub group:
        //-------------------------------------
        case ied_xslgrp_wspadmin_perf:
            ads_perfdata = dsc_admin.m_get_perf_info();
            if ( ads_perfdata == NULL ) {
                return 0;
            }
            in_count = 1;
            break;

		//-------------------------------------
        // wspadmin WSP Trace sub group:
        //-------------------------------------
        case ied_xslgrp_wspadmin_trace:
			adsl_wsptrace = dsc_admin.m_get_wsptrace_info();
			while (adsl_wsptrace != NULL) {
				in_count++;
				adsl_wsptrace = adsl_wsptrace->ads_next;
			}
            break;

        //-------------------------------------
        // wspadmin logifle sub group:
        //-------------------------------------
        case ied_xslgrp_wspadmin_log:
            ads_loginfo = dsc_admin.m_get_log_info();
            while ( ads_loginfo != NULL ) {
                in_count++;
                ads_loginfo = ads_loginfo->ads_next;
            }
            break;

        //-------------------------------------
        // wspadmin users sub group:
        //-------------------------------------
        case ied_xslgrp_wspadmin_user:
            m_fill_user_query( &dsl_user_query );
            in_count = dsc_auth.m_count_users( &dsl_user_query );
            break;
		//-------------------------------------
        // all other sub groups:
        //-------------------------------------
        default:
		  {
#if 0
			   dsd_xsl_group* ads_current_grp = NULL;             // current sub group
				int in_grp_factor   = D_MAIN_GROUP_VAL; // group factor
				
            for ( HVECTOR_FOREACH(int, adsl_cur, dsc_type) ) {
                ied_xslvalue ied_group = (ied_xslvalue)HVECTOR_GET(adsl_cur);
                int inl_member  = (((int)ied_group)/in_grp_factor) - 1;
                in_grp_factor *= inl_member;

                if ( ads_current_grp == NULL ) {
                    ads_current_grp = (dsd_xsl_group*)&dsr_xslvalues[inl_member];
                } else if ( inl_member < ads_current_grp->in_no_groups ){
                    ads_current_grp = (dsd_xsl_group*)ads_current_grp->ads_subgroup;
                    for ( int in_1 = 0; in_1 < inl_member; in_1++ ) {
                        ads_current_grp++;
                    }
                } else {
                    return 0;
                }
            }
            in_count = ads_current_grp->in_no_childs;
            break;
#else
			   return 0;
#endif
		  }
    }
    rdsp_iter_out.dsc_rac.inc_end = in_count;
    return in_count;
} // end of ds_xsl::m_cb_no_childs

bool ds_xsl::m_cb_iterate_next(int inp_type, dsd_xsl_iterator* adsp_itr) {
    switch(inp_type) {
    case ied_xslgrp_wspadmin_listen:
        adsp_itr->dsc_fwd.avoc_cur = ((dsd_listen*)adsp_itr->dsc_fwd.avoc_cur)->ads_next;
        return true;
	case ied_xslgrp_login_domain:
        adsp_itr->dsc_fwd.avoc_cur = ((dsd_domain*)adsp_itr->dsc_fwd.avoc_cur)->adsc_next;
		return true;
	case ied_xslgrp_usr_cookie:
		return ads_session->dsc_ws_gate.dsc_ck_manager.m_cookies_next(&adsp_itr->dsc_fwd);
    default:
        return false;
    }
}

/**
 * function ds_xsl::m_cb_is_true
 * decide whether argument is true
 * 
 * @param[in]   char*           ach_value       request value
 * @param[in]   int             in_len_val      length of request value
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_element     element counter for "for-each" loop
 * @param[in]   dsd_variable*              ads_variable
 * @return      bool
*/
bool ds_xsl::m_cb_is_true( const char* ach_value, int in_len_val, ds_hstack_btype<dsd_xsl_iterator>* ads_element, dsd_variable* ads_variable )
{
    // initialize some variables:
    const char*         ach_data     = NULL;                // output data
    int                 in_len_data  = -1;                  // length of output data
    bool                bo_return    = false;               // return value
    int                 in_key       = 0;                   // start of key for resources
    bool                bo_reverse   = false;               // reverse return?
    ied_xsl_compare     ied_compare;                        // is compare?
    int                 in_cmp_with;                        // compare value (if number)
    ds_hstring          dsl_compare;                        // compare value (if string)
    ied_xslvalue        ied_group;                          // main group of value
    ied_xslvalue        ied_type;                           // type of value
    ds_hvector_btype<int>  dsc_type( ads_wsp_helper );
    dsd_xsl_iterator*   adsl_element = ads_element->m_get_last_ref();
    ds_cookie           dsl_cookie( ads_wsp_helper );
    dsd_msg_t           dsl_msg;
    dsd_wspat_pconf_t   *adsl_wspat_conf;
    ds_portlet          dsl_portlet;                        // portlet
    ds_bookmark         dsl_bmark;                          // bookmark
    dsd_wfa_bmark       dsl_wfa_bmark;                      // wfa bookmark
    ds_hstring          dsl_temp( ads_wsp_helper );
    const char *        ach_str;                            // working variable. just to get portlet name
    int                 inl_name_length;                    // length of name


    //---------------------------------
    // check for a "not(...)" value:
    //---------------------------------
    bo_reverse = m_is_not( &ach_value, &in_len_val );

    //---------------------------------
    // check for a compare in value:
    //---------------------------------
    dsl_compare.m_init( ads_wsp_helper );
    ied_compare = m_is_compare( ach_value, &in_len_val, &in_cmp_with, &dsl_compare );

    // check if value is a variable:
    if (    ach_value[0] == '$'
            && ads_variable->dsc_name.m_equals(&ach_value[1], in_len_val-1) ) {
        ach_value = ads_variable->dsc_value.m_get_ptr();
        in_len_val = ads_variable->dsc_value.m_get_len();
    }

    //---------------------------------
    // get type of value:
    //---------------------------------
    m_get_type( &dsc_type, ach_value, in_len_val );
    if ( dsc_type.m_empty() ) {
        return false;
    }
    ied_group = (ied_xslvalue)dsc_type.m_get_first();
    ied_type  = (ied_xslvalue)dsc_type.m_get_last ();

    //---------------------------------
    // get data:
    //---------------------------------
    switch ( ied_type ) {
        //-----------------------------
        // rdvpn product specific stuff
        //-----------------------------
        case ied_xslval_rdvpn_wsp_name:
            in_len_data = (int)strlen( ads_wsp_helper->m_cb_get_wsp_info() );
            break;
        case ied_xslval_rdvpn_iws_ver:
            in_len_data = (int)dsd_const_string( WS_VERSION_STRING ).m_get_len();
            break;
        case ied_xslval_rdvpn_iws_name:
            in_len_data = (int)dsd_const_string( WEBSERVER_NAME ).m_get_len();
            break;
        case ied_xslval_rdvpn_iws_architecture:
            in_len_data = (int)dsd_const_string(HL_CPUTYPE).m_get_len();
            break;
        case ied_xslval_rdvpn_iws_date:
            in_len_data = (int)dsd_const_string(__DATE__).m_get_len();
            break;
        case ied_xslval_rdvpn_iws_host:        
            if (ads_session->dsc_http_hdr_in.hstr_hf_host.m_get_len() > 0) {
                in_len_data = ads_session->dsc_http_hdr_in.hstr_hf_host.m_get_len();
            } else { // read from config-file; port is otherwise
                in_len_data = ads_session->hstr_conf_authority.m_get_len();
            }
            break;

        //-----------------------------
        // user specific stuff
        //-----------------------------
        case ied_xslval_usr_http_cookie:
            in_len_data = ads_session->dsc_auth.m_get_sticket().m_get_len();
            break;
        case ied_xslval_usr_url_session_id:
			if( ads_session->dsc_control.m_check_state( ST_HTTP_COOKIE_ENABLED ) == false )
			{
                in_len_data = ads_session->hstr_url_session_id.m_get_len();
            }
            break;
        case ied_xslval_usr_name:
        case ied_xslval_usr_hsocks_id:
            in_len_data = ads_session->dsc_auth.m_get_username().m_get_len();
            break;
        case ied_xslval_usr_password:
        case ied_xslval_usr_hsocks_pwd:
            in_len_data = ads_session->dsc_auth.m_get_password().m_get_len();
            break;
        case ied_xslval_usr_sessionticket:
        case ied_xslval_usr_hsocks_sticket:
            in_len_data = ads_session->dsc_auth.m_get_sticket().m_get_len();
            break;
        case ied_xslval_usr_logintime:
            in_len_data = (int)ads_session->dsc_auth.m_get_login_time();
            break;
        case ied_xslval_usr_welcomesite:
            in_len_data = ads_session->dsc_auth.m_get_welcomepage().m_get_len();
            break;
        case ied_xslval_usr_lastwebserver:
            in_len_data = ads_session->dsc_auth.m_get_lws( NULL, NULL ).m_get_len();
            break;
        case ied_xslval_usr_message:
            if ( adsc_msg == NULL ) {
                ads_session->dsc_auth.m_get_msg( &dsl_msg );
                if ( dsl_msg.hstr_msg.m_get_len() > 0 ) {
                    in_len_data = 1;
                }
            } else {
                if ( adsc_msg->hstr_msg.m_get_len() > 0 ) {
                    in_len_data = 1;
                }
            }
            break;
        case ied_xslval_usr_pwd_expires:
            in_len_data = ads_session->dsc_auth.m_pwd_expires();
            break;
        case ied_xslval_usr_is_selected_lang:
            if(adsl_element->dsc_rac.inc_cur == ads_session->dsc_control.in_cma_lang)
                in_len_data = 1;
            else
                in_len_data = 0;
            break;
        case ied_xslval_usr_adm_msg:
            ads_session->dsc_auth.m_get_adm_msg( &dsl_temp );
            if ( dsl_temp.m_get_len() > 0 ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_authenticated:
            in_len_data = (int)ads_session->dsc_auth.m_check_state( ST_AUTHENTICATED );
            break; 
        case ied_xslval_usr_end_ctrl_applet:
            if ( ads_session->dsc_auth.m_check_state(ST_COMPLCHECK_AST) == true ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_wsg_flyer:
            if ( ads_session->dsc_auth.m_show_flyer() ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_default_portlet:
            ads_session->dsc_auth.m_get_default_portlet( &dsl_temp );
            if ( dsl_temp.m_get_len() > 0 ) {
                in_len_data = 1;
            }
            break;
        case ied_xslgrp_usr_cookie:
			adsl_element->iec_mode = ied_xsl_iterator_mode_fwd;
            in_len_data = ads_session->dsc_ws_gate.dsc_ck_manager.m_count_cur_cookies(
                                        ads_session->dsc_auth.m_get_basename(), &adsl_element->dsc_fwd );
            break;
        case ied_xslval_usr_cookie_expires:
            dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            if ( dsl_cookie.m_get_expires() > 0 ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_cookie_port:
            dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            if ( dsl_cookie.m_get_port() > 0 ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_cookie_comment:
            dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            in_len_data = (int)dsl_cookie.m_get_comment().m_get_len();
            break;
        case ied_xslval_usr_cookie_commenturl:
            dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            in_len_data = (int)dsl_cookie.m_get_commenturl().m_get_len();
            break;
        case ied_xslval_usr_cookie_secure:
            dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            if ( dsl_cookie.m_is_secure() ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_cookie_httponly:
            dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            if ( dsl_cookie.m_is_httponly() ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_cookie_discard:
            dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            if ( dsl_cookie.m_is_discard() ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_cookie_domain_changed:
            if ( ads_session->dsc_ws_gate.dsc_ck_manager.m_cur_domain_changed(&adsl_element->dsc_fwd) ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_portlet_open:
            if (    ads_session->dsc_auth.m_get_portlet( adsl_element->dsc_rac, &dsl_portlet )
                 && dsl_portlet.m_is_open()                                         ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_portlet_hide:

#ifdef DS_PORTLET_FILTER_U_A

            ads_session->dsc_auth.m_get_portlet( adsl_element->dsc_rac, &dsl_portlet );  // get portlet
            dsl_portlet.m_get_name(&ach_str, &inl_name_length);                          // get his name

            if(m_is_portlet_to_hide(ads_session->dsc_auth.m_get_portlet_filter(),   // this method determinates if a portlet should be hidden.
                                    (char*)ach_str, inl_name_length))
                in_len_data = 1;

#endif

            break;
        case ied_xslval_usr_portlet_is_default:

            ads_session->dsc_auth.m_get_portlet( adsl_element->dsc_rac, &dsl_portlet );  // get portlet
            dsl_portlet.m_get_name(&ach_str, &inl_name_length);                          // get his name

            if(ads_session->dsc_auth.m_has_default_portlet() && ads_session->dsc_auth.m_get_default_portlet( &dsl_temp )  ) {
                if(dsl_temp.m_equals(ach_str, inl_name_length))
                    in_len_data = 1;
            }
            break;
        case ied_xslgrp_usr_wsg_bmarks:
            if ( ads_session->dsc_auth.m_count_wsg_bookmarks() > 0 ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_wsg_bmark_is_own:
            if (    ads_session->dsc_auth.m_get_wsg_bookmark( adsl_element->dsc_rac.inc_cur, &dsl_bmark ) 
                 && dsl_bmark.m_is_own() ) {
                in_len_data = 1;
            }
            break;
        
        case ied_xslgrp_usr_rdvpn_bmarks:
            if ( ads_session->dsc_auth.m_count_rdvpn_bookmarks() > 0 ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_rdvpn_bmark_is_own:
            if (    ads_session->dsc_auth.m_get_rdvpn_bookmark( adsl_element->dsc_rac.inc_cur, &dsl_bmark ) 
                 && dsl_bmark.m_is_own() ) {
                in_len_data = 1;
            }
            break;
        
		/* hofmants */
		case ied_xslgrp_usr_jwtsa_config:
			if ( ads_session->dsc_auth.m_jwtsa_count_configs() > 0 )
			{
                in_len_data = 1;
            }
            break;

        case ied_xslgrp_usr_wfa_bmarks:
            if ( ads_session->dsc_auth.m_count_wfa_bookmarks() > 0 ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_wfa_bmark_is_own:
            if (    ads_session->dsc_auth.m_get_wfa_bookmark( adsl_element->dsc_rac.inc_cur, &dsl_wfa_bmark ) 
                 && dsl_wfa_bmark.m_is_own() ) {
                in_len_data = 1;
            }
            break;

        case ied_xslgrp_usr_wstats:
            if ( ads_session->dsc_auth.m_count_workstations() > 0 ) {
                in_len_data = 1;
            }
            break;

        case ied_xslval_usr_allowed_wsg:
            if ( ads_session->dsc_auth.m_is_portlet_allowed(achg_known_portlets[ied_wsg_portlet]) ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_allowed_jterm:
            if ( ads_session->dsc_auth.m_is_portlet_allowed(achg_known_portlets[ied_jterm_portlet]) ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_allowed_wfa:
            if ( ads_session->dsc_auth.m_is_portlet_allowed(achg_known_portlets[ied_wfa_portlet]) ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_allowed_ppp:
            if ( ads_session->dsc_auth.m_is_portlet_allowed(achg_known_portlets[ied_ppp_portlet]) ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_allowed_settings:
            if ( ads_session->dsc_auth.m_is_portlet_allowed(achg_known_portlets[ied_settings_portlet]) ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_allowed_conf_wsg_bmarks:
            if ( ads_session->dsc_auth.m_is_config_allowed(DEF_UAC_WSG_BMARKS) ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_allowed_conf_rdvpn_bmarks:
            if ( ads_session->dsc_auth.m_is_config_allowed(DEF_UAC_RDVPN_BMARKS) ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_allowed_conf_wfa_bmarks:
            if ( ads_session->dsc_auth.m_is_config_allowed(DEF_UAC_WFA_BMARKS) ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_allowed_conf_dod:
            if ( ads_session->dsc_auth.m_is_config_allowed(DEF_UAC_DOD) ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_allowed_conf_others:
            if ( ads_session->dsc_auth.m_is_config_allowed(DEF_UAC_OTHERS) ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_allowed_wsg_input:
            if ( ads_session->dsc_auth.m_is_config_allowed(DEF_UAC_WSG_INPUT) ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_allowed_embedded_page:
            if ( (ads_session->ads_config->in_settings & SETTING_ALLOW_EMBEDDED_USE) == 0 ) {
                in_len_data = 1;
            }
            break;
        case ied_xslval_usr_bookmarkhostname:
            in_len_data = ads_session->ads_config->ach_bookmark_host.m_get_len();
            break;

        //-----------------------------
        // login domain sub group:
        //-----------------------------
        case ied_xslval_login_challenge:
#if SM_USE_CERT_AUTH_V2
			if( ads_session->boc_fixed_login && ads_session->dsc_username.m_get_len() > 0 ) {
			    in_len_data = 1;
				break;
			}
#endif
			if ( ads_session->dsc_auth.m_check_state( ST_CHALLENGE_IN_PROGRESS ) == true ) {
                in_len_data = 1;
            }
            break;

        case ied_xslval_login_change_pwd:
            if ( ads_session->dsc_auth.m_check_state( ST_CHANGE_PASSWORD ) == true ) {
                in_len_data = 1;
            }
            break;

        case ied_xslval_login_show_ssa_cbox:
            if ( ads_session->ads_config->bo_show_ssa_checkbox == true ) {
                in_len_data = 1;
            }
            break;

        case ied_xslgrp_login_kick_out:
            if ( ads_session->dsc_auth.m_check_state( ST_KICK_OUT ) == true ) {
                in_len_data = 1;
            }
            break;

        case ied_xslval_login_kick_out_multiple:
            adsl_wspat_conf = ads_wsp_helper->m_get_wspat_config();
            if (    adsl_wspat_conf                     != NULL
                 && adsl_wspat_conf->boc_multiple_login == true ) {
                in_len_data = 1;
            }
            break;

        case ied_xslgrp_login_kicked_out:
            if ( ads_session->dsc_auth.m_check_state( ST_KICKED_OUT ) == true ) {
                in_len_data = 1;
            }
            break;

        case ied_xslval_login_kicked_out_ineta:
            if ( ads_session->dsc_auth.m_check_state( ST_KICKED_OUT ) == true ) {
                in_len_data = ads_session->dsc_auth.m_get_kicked_out_ineta().m_get_len();
            }
            break;

        case ied_xslval_login_kicked_out_login_time:
            if (    ads_session->dsc_auth.m_check_state( ST_KICKED_OUT ) == true 
                 && ads_session->dsc_auth.m_get_kicked_out_time() > 0           ) {
                in_len_data = 1;
            }
            break;

        case ied_xslgrp_login_domain:
#if SM_USE_CERT_AUTH_V2
			if(ads_session->boc_fixed_login && ads_session->dsc_domain.m_get_len() > 0) {
                in_len_data = 0;
				break;
			}
#endif
			if ( ads_wsp_helper->m_get_wsp_auth() == 0 ) {
                break;
            }
            in_len_data = 0;
            adsl_wspat_conf = ads_wsp_helper->m_get_wspat_config();
            if ( adsl_wspat_conf != NULL ) {
                in_len_data = adsl_wspat_conf->dsc_domains.inc_num_domains;
			}
            break;

        case ied_xslval_login_domain_disp_list:
#if SM_USE_CERT_AUTH_V2
			if(ads_session->boc_fixed_login && ads_session->dsc_domain.m_get_len() > 0) {
                in_len_data = 0;
				break;
			}
#endif
			adsl_wspat_conf = ads_wsp_helper->m_get_wspat_config();
            if (    adsl_wspat_conf == NULL
                 || adsl_wspat_conf->dsc_domains.boc_show_list == false ) {
                in_len_data = -1;
            } else {
                in_len_data = 1;
            }
            break;

        case ied_xslval_login_domain_selected:
            if( ads_session->dsc_http_hdr_in.hstr_hdrline_cookie.m_get_len() > 0 )
			{
				/*A cookie is received*/
                dsd_const_string dsl_ldn("login/domain/name");
                ds_hstring ds_temp;
                m_cb_get_data( dsl_ldn.m_get_ptr(), dsl_ldn.m_get_len(), &ds_temp, ads_element );
                
				/* get beginning and end offset: ->H<-OBWSP_DOMAIN=OpenDS->;<- */
				dsd_const_string dsl_wspdomain(HOBWSP_DOMAIN);
                int inl_off1 = ads_session->dsc_http_hdr_in.hstr_hdrline_cookie.m_search( dsl_wspdomain );
				if( inl_off1 < 0 )
				{
					/*If the cookie does not carry any domain, it is still needed to check if there is a default domain has been read from the wsp.xml config file*/
					m_default_domain(ads_element, &in_len_data);
					break;
				}
                inl_off1 += dsl_wspdomain.m_get_len();
				int inl_off2 = ads_session->dsc_http_hdr_in.hstr_hdrline_cookie.m_search( inl_off1, ";" );
                if(inl_off2 < 0)
                    inl_off2 = ads_session->dsc_http_hdr_in.hstr_hdrline_cookie.m_get_len();
				dsd_const_string domain( ads_session->dsc_http_hdr_in.hstr_hdrline_cookie.m_substring( inl_off1, inl_off2 ) );
				
				if ( ds_temp.m_equals(domain) )
				{
                    in_len_data = 1;
                }
            }
			else{
				/*No cookie is received. Looking if a default domain has been read from the wsp.xml config file*/
				m_default_domain(ads_element,&in_len_data);
			}
            break;

		//-------------------------------------
        // user webterm sub group:
        //-------------------------------------
		case ied_xslgrp_usr_webterm: {
			int in_temp = ads_session->dsc_auth.m_webterm_count_server_entries(ied_webterm_protogroup_rdp)
#if BO_HOBTE_CONFIG      
                        + ads_session->dsc_auth.m_hobte_count_configs()
#endif
                        + ads_session->dsc_auth.m_webterm_count_server_entries(ied_webterm_protogroup_ssh);
            if(in_temp > 0) {
                in_len_data = 1;
            }
			break;
        }
		case ied_xslgrp_usr_webterm_rdp:
            if(ads_session->dsc_auth.m_webterm_count_server_entries(ied_webterm_protogroup_rdp) > 0) {
                in_len_data = 1;
            }
			break;
		case ied_xslgrp_usr_webterm_te:
#if BO_HOBTE_CONFIG
			if(ads_session->dsc_auth.m_hobte_count_configs() > 0) {
                in_len_data = 1;
            }
#endif
            break;
        case ied_xslgrp_usr_webterm_ssh:
            if(ads_session->dsc_auth.m_webterm_count_server_entries(ied_webterm_protogroup_ssh) > 0) {
                in_len_data = 1;
            }
            break;

        //-----------------------------
        // logout session sub group:
        //-----------------------------
        case ied_xslgrp_logout_session:
            if ( ads_session->dsc_webserver.dsc_v_logout_connections.m_empty() == false ) {
                in_len_data = 1;
            }
            break;

        //-------------------------------------
        // ppptunnel group:
        //-------------------------------------
        case ied_xslgrp_ppptnl:
            if ( ads_session->ads_config->adsl_pppt != NULL ) {
                in_len_data = 1;
            }
            break;

        //-----------------------------
        // wspadmin sub group:
        //-----------------------------
        case ied_xslgrp_wspadmin_cluster:
        case ied_xslgrp_wspadmin_session: {
            dsd_xsl_iterator dsl_itr;
            int inl_type;
            in_len_data = m_cb_no_childs( ach_value, in_len_val, ads_element, dsl_itr, inl_type );
            break;
        }

		//-----------------------------
        // wspadmin WSP Trace sub group:
        //-----------------------------
        case ied_xslgrp_wspadmin_trace: {
            dsd_xsl_iterator dsl_itr;
            int inl_type;
            in_len_data = m_cb_no_childs( ach_value, in_len_val, ads_element, dsl_itr, inl_type );
            break;
        }
        case ied_xslval_wspadmin_trace_enabled:
		case ied_xslval_wspadmin_trace_active:
		case ied_xslval_wspadmin_trace_all_sessions:
		case ied_xslval_wspadmin_trace_session_netw:
		case ied_xslval_wspadmin_trace_session_ssl_ext:
        case ied_xslval_wspadmin_trace_session_ssl_int:
        case ied_xslval_wspadmin_trace_session_ssl_ocsp:
		case ied_xslval_wspadmin_trace_session_wspat3_int:
		case ied_xslval_wspadmin_trace_session_wspat3_ext:
		case ied_xslval_wspadmin_trace_session_sdh_ext:
        case ied_xslval_wspadmin_trace_session_sdh_int:
        case ied_xslval_wspadmin_trace_session_aux:
		case ied_xslval_wspadmin_trace_session_misc:
        case ied_xslval_wspadmin_trace_session_others:
		case ied_xslval_wspadmin_trace_core_console:
		case ied_xslval_wspadmin_trace_core_cluster:
		case ied_xslval_wspadmin_trace_core_udp:
		case ied_xslval_wspadmin_trace_core_dod:
		case ied_xslval_wspadmin_trace_core_radius:
		case ied_xslval_wspadmin_trace_core_virus_ch:
		case ied_xslval_wspadmin_trace_core_hob_tun:
		case ied_xslval_wspadmin_trace_core_ldap:
		case ied_xslval_wspadmin_trace_core_krb5:
        case ied_xslval_wspadmin_trace_core_ms_rpc:
		case ied_xslval_wspadmin_trace_core_admin:
		case ied_xslval_wspadmin_trace_core_ligw:
        case ied_xslval_wspadmin_trace_core_others:
			if (m_cb_get_wspadmin_trace_booldata(&dsc_type, ads_element)){
                in_len_data = 1;
            }
			break;

        //-----------------------------
        // error page sub group:
        //-----------------------------
        case ied_xslval_error_show_back:
            if ( boc_show_back == true ) {
                in_len_data = 1;
            }
            break;

        //-----------------------------
        // language sub group
        //-----------------------------
        case ied_xslgrp_lang: {
            dsd_xsl_iterator* adsl_member = ads_element->m_get_last_ref();
            m_split_value( ach_value, in_len_val, &in_key );
            if ( in_key < in_len_val ) {
                in_key++; // go over '/'
                bo_return = GET_RESOURCE( &ach_value[in_key], in_len_val - in_key,
                                          ach_data, in_len_data );
                if ( bo_return == false ) {
                    return false;
                }
            } else {
                RESOURCES->m_get_lang( adsl_member->dsc_rac.inc_cur, &ach_data, &in_len_data );
            }
            break; }

        default:
            int        in_temp;
            bool       bo_ret;
            m_cb_get_data( ach_value, in_len_val,
                           &dsl_temp, ads_element );
            if ( dsl_temp.m_get_len() > 0 ) {
                in_len_data = dsl_temp.m_get_len();
                ach_data = dsl_temp.m_get_ptr();
            }
            if ( ied_compare != ied_xsl_cmp_not_set && dsl_compare.m_get_len() < 1) {
                bo_ret = dsl_temp.m_to_int( &in_temp );
                //skip conversion results of strings that aren't numbers -> silent error result 0
                if ( bo_ret == true && (in_temp!=0 || *dsl_temp.m_get_ptr() == '0')) {
                    in_len_data = in_temp;
                }
            }
            break;
    }

    //---------------------------------
    // reverse data:
    //---------------------------------
    if ( bo_reverse == true ) {
        in_len_data *= -1;
    }

    //---------------------------------
    // compare data:
    //---------------------------------
    if ( ied_compare != ied_xsl_cmp_not_set ) {
        in_len_data = m_compare( ied_compare,
                                 ach_data, in_len_data,
                                 in_cmp_with, &dsl_compare );
    }

    return (in_len_data > 0)?true:false;
} // end of ds_xsl::m_cb_is_true


/**
 * private function m_compare
 * compare given value by int or by string
 *
 * @param[in]   ied_xsl_compare ienp_comp       compare method
 * @param[in]   char*           achp_comp       compare value
 * @param[in]   int             inp_len_comp    length of compare value
 * @param[in]   int             inp_comp_to     compare with (if int)
 * @param[in]   ds_hstring*     adsp_comp       compare with (if string)
 * @return      int
*/
int ds_xsl::m_compare( ied_xsl_compare ienp_comp, 
                       const char* achp_comp, int inp_len_comp,
                       int inp_comp_to, ds_hstring* adsp_comp )
{
    if ( adsp_comp->m_get_len() < 1 ) {
        /*
            int compare:
        */
        switch ( ienp_comp ) {
            case ied_xsl_cmp_greater:
                if ( inp_len_comp > inp_comp_to ) {
                    return 1;
                }
                return -1;

            case ied_xsl_cmp_gr_equal:
                if ( inp_len_comp >= inp_comp_to ) {
                    return 1;
                }
                return -1;

            case ied_xsl_cmp_lower:
                if ( inp_len_comp < inp_comp_to ) {
                    return 1;
                }
                return -1;

            case ied_xsl_cmp_lw_equal: 
                if ( inp_len_comp <= inp_comp_to ) {
                    return 1;
                }
                return -1;

            case ied_xsl_cmp_equal:
                if ( inp_len_comp == inp_comp_to ) {
                    return 1;
                }
                return -1;
            case ied_xsl_cmp_not_equal:
                if ( inp_len_comp != inp_comp_to ) {
                    return 1;
                }
                return -1;
        }
    } else {
        /*
            string compare:
        */
        dsd_const_string dsl_key(achp_comp, inp_len_comp);
        int inl_cmp_result = dsl_key.m_compare(adsp_comp->m_const_str());
        switch ( ienp_comp ) {
            case ied_xsl_cmp_greater:
                if ( inl_cmp_result > 0 ) {
                    return 1;
                }
                return -1;

            case ied_xsl_cmp_gr_equal:
                if ( inl_cmp_result >= 0) {
                    return 1;
                }
                return -1;

            case ied_xsl_cmp_lower:
                if ( inl_cmp_result < 0 ) {
                    return 1;
                }
                return -1;

            case ied_xsl_cmp_lw_equal: 
                if ( inl_cmp_result <= 0 ) {
                    return 1;
                }
                return -1;

            case ied_xsl_cmp_equal:
                if ( inl_cmp_result == 0 ) {
                    return 1;
                }
                return -1;
            case ied_xsl_cmp_not_equal:
                if ( inl_cmp_result != 0 ) {
                    return 1;
                }
                return -1;
        }
    }
    return -1;
} // end of ds_xsl::m_compare


/**
 * function ds_xsl::m_cb_get_usr_data
 * get data from user group to insert in xsl
 * 
 * @param[in]   int                 in_type         value type
 * @param[out]  ds_hstring*         ads_out         output buffer
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*   ads_element     element counter for "for-each" loop
*/
void ds_xsl::m_cb_get_usr_data( int in_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element )
{
    // initialize some variables:
    ied_xslvalue        ied_type = (ied_xslvalue)in_type;
    char*               ach_data;                           // output data
    const char*         ach_cdata;                           // output data
    int                 in_len_data;                        // length of output data
    bool                bo_ret;                             // return for several functions
    int                 in_port;                            // port last webserver
    int                 in_proto;                           // protocol last webserver
    hl_time_t              t_tmp;                              // working var for time values
    unsigned short      uin_tmp;
    dsd_xsl_iterator*   adsl_element = ads_element->m_get_last_ref();
    dsd_msg_t           dsl_msg;
    ds_portlet          dsl_portlet;
    ds_bookmark         dsl_bmark;
    dsd_wfa_bmark       dsl_wfa_bmark;
    ds_workstation      dsl_wstat;
    ds_hstring          dsl_temp( ads_wsp_helper );
	ds_jwtsa_conf		dsl_jwtsa_conf;
#if BO_HOBTE_CONFIG
    ds_hobte_conf       dsl_hobte_conf;
#endif
	char				chrl_buffer[512];
	int					iml_len = 512;

    switch ( ied_type ) {        
        case ied_xslval_usr_http_cookie:
            ads_session->dsc_auth.m_get_http_cookie( ads_out );
            break;
        case ied_xslval_usr_url_session_id:
			if( ads_session->dsc_control.m_check_state( ST_HTTP_COOKIE_ENABLED ) == false )
			{
                ads_out->m_write(ads_session->hstr_url_session_id);
                }
            break;
        case ied_xslval_usr_name:
            ads_out->m_write_html_text( ads_session->dsc_auth.m_get_username() );
            break;

        case ied_xslval_usr_hsocks_id:
            ads_out->m_write_html_text( ads_session->dsc_auth.m_get_hobsocks_name() );
            break;

        case ied_xslval_usr_password: {
            ds_hstring ds_sticket = ads_session->dsc_auth.m_get_password();
            ds_hstring ds_user = ads_session->dsc_auth.m_get_username();
            in_len_data = ((ds_sticket.m_get_len() + 2) << 2);
            in_len_data += 1;
            ach_data = ads_wsp_helper->m_cb_get_memory(in_len_data, true);
            if (ach_data == NULL) {
                break;
            }
            ads_session->dsc_helper.AUrps1((LPCSTR)ds_sticket.m_get_ptr(), (LPCSTR)ds_user.m_get_ptr(), in_len_data, ach_data, (PINT)(&in_len_data));
            ads_out->m_write_html_text( dsd_const_string(ach_data, in_len_data) );
            ads_session->ads_wsp_helper->m_cb_free_memory(ach_data);
            break;
        }

        case ied_xslval_usr_hsocks_pwd: {
            ds_hstring ds_sticket = ads_session->dsc_auth.m_get_password();
            ds_hstring ds_user = ads_session->dsc_auth.m_get_hobsocks_name();
            in_len_data = ((ds_sticket.m_get_len() + 2) << 2);
            in_len_data += 1;
            ach_data = ads_wsp_helper->m_cb_get_memory(in_len_data, true);
            if (ach_data == NULL) {
                break;
            }
            ads_session->dsc_helper.AUrps1((LPCSTR)ds_sticket.m_get_ptr(), (LPCSTR)ds_user.m_get_ptr(), in_len_data, ach_data, (PINT)(&in_len_data));
            ads_out->m_write_html_text( dsd_const_string(ach_data, in_len_data) );
            ads_session->ads_wsp_helper->m_cb_free_memory(ach_data);
            break;
        }
        case ied_xslval_usr_domain:
            ads_out->m_write_html_text( ads_session->dsc_auth.m_get_domain() );
            break;

        case ied_xslval_usr_role:
            if ( ads_session->dsc_auth.m_get_role_name( &ach_cdata, &in_len_data ) ) {
                ads_out->m_write_html_text( ach_cdata, in_len_data );
            }
            break;

        case ied_xslval_usr_sessionticket: {// should be named differently
			ds_hstring ds_sticket = ads_session->dsc_auth.m_get_password();
            ds_hstring ds_user = ads_session->dsc_auth.m_get_hobsocks_name();
            in_len_data = ((ds_sticket.m_get_len() + 2) << 2);
            in_len_data += 1;
            ach_data = ads_wsp_helper->m_cb_get_memory(in_len_data, true);
            if ( ach_data == NULL ) {
                break;
            }
            ads_session->dsc_helper.AUrps1((LPCSTR)ds_sticket.m_get_ptr(), (LPCSTR)ds_user.m_get_ptr(), in_len_data, ach_data, (PINT)(&in_len_data));
            ads_out->m_write_html_text( ach_data, in_len_data );
            ads_session->ads_wsp_helper->m_cb_free_memory(ach_data);
            break;
        }
        case ied_xslval_usr_hsocks_sticket: {
            ds_hstring ds_sticket = ads_session->dsc_auth.m_get_sticket();
            ds_hstring ds_user = ads_session->dsc_auth.m_get_hobsocks_name();
            in_len_data = ((ds_sticket.m_get_len() + 2) << 2);
            in_len_data += 1;
            ach_data = ads_wsp_helper->m_cb_get_memory(in_len_data, true);
            if (ach_data == NULL) {
                break;
            }
            ads_session->dsc_helper.AUrps1((LPCSTR)ds_sticket.m_get_ptr(), (LPCSTR)ds_user.m_get_ptr(), in_len_data, ach_data, (PINT)(&in_len_data));
            ads_out->m_write_html_text( ach_data, in_len_data );
            ads_session->ads_wsp_helper->m_cb_free_memory(ach_data);
            break;
        }
        case ied_xslval_usr_logintime:
            t_tmp = ads_session->dsc_auth.m_get_login_time();
            ads_out->m_writef( "%lld", t_tmp );
            break;

        case ied_xslval_usr_welcomesite:
            bo_ret = ads_session->dsc_auth.m_get_welcomepage( &ach_cdata, &in_len_data );
            if ( !bo_ret ) { 
				ach_cdata = ads_session->ads_config->ach_site_after_auth.m_get_start();
				in_len_data = ads_session->ads_config->ach_site_after_auth.m_get_len();
			}

			/* hofmants: insert cookie here when HTTP cookies are disabled! */
			if( ads_session->dsc_control.m_check_state( ST_HTTP_COOKIE_ENABLED ) == false )
			{
				ds_hstring hstr_cookie( ads_session->ads_wsp_helper );
				ads_session->dsc_auth.m_get_http_cookie( &hstr_cookie );
				ads_out->m_write_html_text(ads_session->hstr_url_session_id);
			}

            ads_out->m_write_html_text( ach_cdata, in_len_data );
            break;

        case ied_xslval_usr_lastwebserver: {
            ds_hstring ds_lws = ads_session->dsc_auth.m_get_lws( &in_proto, &in_port );
            if ( in_proto == 0 ) {
                ads_out->m_write( "http://" );
            } else if ( in_proto == 1 ){
                ads_out->m_write( "https://" );
            } else {
                break;
            }
            ads_out->m_write_html_text( ds_lws );
            ads_out->m_write( ":" );
            ads_out->m_write_int(in_port);
            break;
        }
        case ied_xslval_usr_message:
            if ( adsc_msg == NULL ) {
                adsc_msg = &dsl_msg;
                ads_session->dsc_auth.m_get_msg( adsc_msg );
            }
            bo_ret = GET_RES( adsc_msg->hstr_msg.m_get_ptr(), ach_cdata, in_len_data );
            if ( bo_ret == false ) {
                ads_out->m_write_html_text( adsc_msg->hstr_msg );
            } else {
                ads_out->m_write_html_text( ach_cdata, in_len_data );
            }

            // write error code:
            if ( adsc_msg->inc_code > 0 ) {
                ads_out->m_writef( " (%03d", adsc_msg->inc_code );
                switch( adsc_msg->inc_type ) {
                    case (int)ied_sdh_log_info:
                        ads_out->m_write( "I)", 2 );
                        break;
                    case (int)ied_sdh_log_warning:
                        ads_out->m_write( "W)", 2 );
                        break;
                    case (int)ied_sdh_log_error:
                        ads_out->m_write( "E)", 2 );
                        break;
                }
            }

            if ( adsc_msg == &dsl_msg ) {
                adsc_msg = NULL;
            }            
            break;

        case ied_xslval_usr_adm_msg:
            ads_session->dsc_auth.m_get_adm_msg( &dsl_temp );
            if ( dsl_temp.m_get_len() > 0 ) {
                dsd_unicode_string dsl_text;
                dsl_text.ac_str = (void*)dsl_temp.m_get_ptr();
                dsl_text.imc_len_str = dsl_temp.m_get_len();
                dsl_text.iec_chs_str = ied_chs_xml_utf_8; 
                ads_out->m_write( &dsl_text, ied_chs_utf_8 );
            }
            break;

        case ied_xslval_usr_lang:
            if ( ads_session->dsc_control.in_cma_lang >= 0 ) {
                RESOURCES->m_get_lang( ads_session->dsc_control.in_cma_lang,
                                       &ach_cdata, &in_len_data );
                ads_out->m_write_html_text( ach_cdata, in_len_data );
            }
            break;

        case ied_xslval_usr_pwd_expires:
            in_len_data = ads_session->dsc_auth.m_pwd_expires();
            if (  in_len_data != DEF_DONT_EXPIRE ) {
                ads_out->m_writef( "%d", in_len_data );
            }
            break;
        case ied_xslval_usr_default_portlet:
            ads_session->dsc_auth.m_get_default_portlet( &dsl_temp );
            if ( dsl_temp.m_get_len() > 0 ) {
                dsd_unicode_string dsl_text;
                dsl_text.ac_str = (void*)dsl_temp.m_get_ptr();
                dsl_text.imc_len_str = dsl_temp.m_get_len();
                dsl_text.iec_chs_str = ied_chs_xml_utf_8; 
                ads_out->m_write( &dsl_text, ied_chs_utf_8 );
            }
            break;

        case ied_xslval_usr_skin:
            bo_ret = ads_session->dsc_auth.m_get_gui_skin( &ach_cdata, &in_len_data );
            if ( bo_ret == true ) {
                ads_out->m_write_html_text( ach_cdata, in_len_data );
            } else {
                ads_out->m_write_html_text( ads_session->ads_config->ach_gui_skin );
            }
            break;

        case ied_xslgrp_usr_cookie:
			adsl_element->iec_mode = ied_xsl_iterator_mode_fwd;
            ads_out->m_writef( "%d", ads_session->dsc_ws_gate.dsc_ck_manager.m_count_cur_cookies(
                                            ads_session->dsc_auth.m_get_basename(), &adsl_element->dsc_fwd ) );
            break;

        case ied_xslval_usr_cookie_name: {
            const ds_cookie& dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie( &adsl_element->dsc_fwd );
            const char* strl_name;
            dsl_cookie.m_get_name( &strl_name, &in_len_data );
            ads_out->m_write_html_text( strl_name, in_len_data );
            break;
        }
        case ied_xslval_usr_cookie_value: {
            const ds_cookie& dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            const char* strl_value;
            dsl_cookie.m_get_value( &strl_value, &in_len_data );
            ads_out->m_write_html_text( strl_value, in_len_data );
            break;
        }
        case ied_xslval_usr_cookie_version: {
            const ds_cookie& dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            ads_out->m_writef( "%d", dsl_cookie.m_get_version() );
            break;
		}
        case ied_xslval_usr_cookie_expires: {
            const ds_cookie& dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            ads_out->m_writef( "%lld", dsl_cookie.m_get_expires() );
            break;
		}
        case ied_xslval_usr_cookie_domain: {
            const ds_cookie& dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            ads_out->m_write_html_text( dsl_cookie.m_get_domain() );
            break;
		}
        case ied_xslval_usr_cookie_path: {
            const ds_cookie& dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            ads_out->m_write_html_text( dsl_cookie.m_get_path() );
            break;
		}
        case ied_xslval_usr_cookie_port: {
            const ds_cookie& dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            uin_tmp    = dsl_cookie.m_get_port();
            if ( uin_tmp > 0 ) {
                ads_out->m_writef( "%u", dsl_cookie.m_get_port() );
            }
            break;
		}
        case ied_xslval_usr_cookie_comment: {
            const ds_cookie& dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            ads_out->m_write_html_text( dsl_cookie.m_get_comment() );
            break;
		}
        case ied_xslval_usr_cookie_commenturl: {
            const ds_cookie& dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            ads_out->m_write_html_text( dsl_cookie.m_get_commenturl() );
            break;
		}
        case ied_xslval_usr_cookie_secure: {
            const ds_cookie& dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            m_cb_print_bool( ads_out, dsl_cookie.m_is_secure() );
            break;
		}
        case ied_xslval_usr_cookie_httponly: {
            const ds_cookie& dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            m_cb_print_bool( ads_out, dsl_cookie.m_is_httponly() );
            break;
		}
        case ied_xslval_usr_cookie_handle: {
            const ds_cookie& dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            ads_out->m_writef( "%d", dsl_cookie.m_get_stor_pos() );
            break;
		}
        case ied_xslval_usr_cookie_discard: {
            const ds_cookie& dsl_cookie = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cur_cookie(&adsl_element->dsc_fwd);
            m_cb_print_bool( ads_out, dsl_cookie.m_is_discard() );
            break;
		}
        case ied_xslval_usr_portlet_name:
            bo_ret = ads_session->dsc_auth.m_get_portlet( adsl_element->dsc_rac, &dsl_portlet );
            if ( bo_ret == true ) {
                const char* achl_name;
                dsl_portlet.m_get_name( &achl_name, &in_len_data );
                ads_out->m_write_html_text( achl_name, in_len_data );
            }
            break;

        case ied_xslval_usr_portlet_handle:
            ads_out->m_writef( "%d", adsl_element->dsc_rac.inc_cur );
            break;

        case ied_xslval_usr_wsg_bmark_name:
            bo_ret = ads_session->dsc_auth.m_get_wsg_bookmark( adsl_element->dsc_rac.inc_cur, &dsl_bmark );
            if ( bo_ret == true ) {
                const char* achl_name;
                dsl_bmark.m_get_name( &achl_name, &in_len_data );
                ads_out->m_write_html_text( achl_name, in_len_data );
            }
            break;

        case ied_xslval_usr_wsg_bmark_url:
            bo_ret = ads_session->dsc_auth.m_get_wsg_bookmark( adsl_element->dsc_rac.inc_cur, &dsl_bmark );
            if ( bo_ret == true ) {
                const char* achl_name;
                dsl_bmark.m_get_url( &achl_name, &in_len_data );
                ads_out->m_write_html_text( achl_name, in_len_data );
            }
            break;

        case ied_xslval_usr_rdvpn_bmark_name:
            bo_ret = ads_session->dsc_auth.m_get_rdvpn_bookmark( adsl_element->dsc_rac.inc_cur, &dsl_bmark );
            if ( bo_ret == true ) {
                const char* achl_name;
                dsl_bmark.m_get_name( &achl_name, &in_len_data );
                ads_out->m_write_html_text( achl_name, in_len_data );
            }
            break;

        case ied_xslval_usr_rdvpn_bmark_url:
            bo_ret = ads_session->dsc_auth.m_get_rdvpn_bookmark( adsl_element->dsc_rac.inc_cur, &dsl_bmark );
            if ( bo_ret == true ) {
                const char* achl_name;
                dsl_bmark.m_get_url( &achl_name, &in_len_data );
                ads_out->m_write_html_text( achl_name, in_len_data );
            }
            break;

        case ied_xslval_usr_wsg_bmark_handle:
        case ied_xslval_usr_rdvpn_bmark_handle:
            ads_out->m_writef( "%d", adsl_element->dsc_rac.inc_cur );
            break;

        case ied_xslval_usr_wfa_bmark_name:
            bo_ret = ads_session->dsc_auth.m_get_wfa_bookmark( adsl_element->dsc_rac.inc_cur, &dsl_wfa_bmark );
            if ( bo_ret == true ) {
                const char* achl_name;
                dsl_wfa_bmark.m_get_name( &achl_name, &in_len_data );
                ads_out->m_write_html_text( achl_name, in_len_data );
            }
            break;

        case ied_xslval_usr_wfa_bmark_url:
            bo_ret = ads_session->dsc_auth.m_get_wfa_bookmark( adsl_element->dsc_rac.inc_cur, &dsl_wfa_bmark );
            if ( bo_ret == true ) {
                const char* achl_name;
                dsl_wfa_bmark.m_get_url( &achl_name, &in_len_data );
                ads_out->m_write_html_text( achl_name, in_len_data );
            }
            break;

        case ied_xslval_usr_wfa_bmark_handle:
            ads_out->m_writef( "%d", adsl_element->dsc_rac.inc_cur );
            break;


        case ied_xslval_usr_wstat_name:
            bo_ret = ads_session->dsc_auth.m_get_workstation( adsl_element->dsc_rac.inc_cur, &dsl_wstat );
            if ( bo_ret == true ) {
                const char* achl_name;
                dsl_wstat.m_get_name( &achl_name, &in_len_data );
                ads_out->m_write_html_text( achl_name, in_len_data );
            }
            break;

        case ied_xslval_usr_wstat_ineta:
            bo_ret = ads_session->dsc_auth.m_get_workstation( adsl_element->dsc_rac.inc_cur, &dsl_wstat );
            if ( bo_ret == true ) {
                const char* achl_name;
                dsl_wstat.m_get_ineta( &achl_name, &in_len_data );
                ads_out->m_write_html_text( achl_name, in_len_data );
            }
            break;

        case ied_xslval_usr_wstat_mac:
            bo_ret = ads_session->dsc_auth.m_get_workstation( adsl_element->dsc_rac.inc_cur, &dsl_wstat );
            if ( bo_ret == true ) {
                dsl_wstat.m_write_mac( ads_out );
            }
            break;

        case ied_xslval_usr_wstat_port:
            bo_ret = ads_session->dsc_auth.m_get_workstation( adsl_element->dsc_rac.inc_cur, &dsl_wstat );
            if ( bo_ret == true ) {
                ads_out->m_writef( "%hu", dsl_wstat.m_get_port() );
            }
            break;

        case ied_xslval_usr_wstat_timeout:
            bo_ret = ads_session->dsc_auth.m_get_workstation( adsl_element->dsc_rac.inc_cur, &dsl_wstat );
            if ( bo_ret == true ) {
                ads_out->m_writef( "%d", dsl_wstat.m_get_wait() );
            }
            break;

        case ied_xslval_usr_wstat_handle:
            ads_out->m_writef( "%d", adsl_element->dsc_rac.inc_cur );
            break;

		/* insert jwtsa config here */
		case ied_xslval_usr_jwtsa_config_name:
			bo_ret = ads_session->dsc_auth.m_jwtsa_get_config( adsl_element->dsc_rac.inc_cur, &dsl_jwtsa_conf );
			if( bo_ret )
			{
                const char* achl_name;
				dsl_jwtsa_conf.m_get_name( &achl_name, &in_len_data );
                ads_out->m_write_html_text( achl_name, in_len_data );
			}
			break;

        case ied_xslgrp_usr_webterm_name: {
			dsd_webterm_server* adsl_entry = ads_session->dsc_auth.m_webterm_get_server_entry( adsl_element->dsc_rac.inc_cur, chrl_buffer, &iml_len, (ied_webterm_protogroup)(long long int)adsl_element->avoc_user );
			if( adsl_entry != NULL ) {
                ads_out->m_write_html_text( chrl_buffer, iml_len );
            }
			break;
        }
        case ied_xslgrp_usr_webterm_protocol_link: {
			dsd_webterm_server* adsl_entry = ads_session->dsc_auth.m_webterm_get_server_entry( adsl_element->dsc_rac.inc_cur, chrl_buffer, &iml_len, (ied_webterm_protogroup)(long long int)adsl_element->avoc_user );
			if( adsl_entry != NULL && adsl_entry->iec_subprotocol < IMS_NUM_WEBTERM_LINKS )
			{
                const dsd_unicode_string& rdsl_link = DSRS_WEBTERM_LINKS[adsl_entry->iec_subprotocol];
                ads_out->m_write_html_text(rdsl_link);
			}
			break;
        }
        case ied_xslval_usr_bookmarkhostname: {
            dsd_const_string dsl_bookmark_host = ads_session->ads_config->ach_bookmark_host;
            ads_out->m_write_html_text( dsl_bookmark_host );
            break;
        }
#if BO_HOBTE_CONFIG
        case ied_xslgrp_usr_webterm_te_name: {
            int iml_entries = ads_session->dsc_auth.m_webterm_count_server_entries(ied_webterm_protogroup_te_default);
            for (int imli=0; imli<iml_entries; imli++)
            {
                dsd_webterm_server* adsl_entry = ads_session->dsc_auth.m_webterm_get_server_entry( imli, chrl_buffer, &iml_len, ied_webterm_protogroup_te_default );
                if ( adsl_entry != NULL && adsl_entry->inc_len_session_name == 1 && adsl_entry->achc_session_name[0] == '*')
                {
                    ads_out->m_write_html_text( chrl_buffer, iml_len );
                }
            }
            
			break;
        }

        case ied_xslgrp_usr_webterm_te_protocol_link: {
            //dsd_webterm_server* adsl_entry = ads_session->dsc_auth.m_webterm_get_server_entry( adsl_element->dsc_rac.inc_cur, chrl_buffer, &iml_len, (ied_webterm_protogroup)(long long int)adsl_element->avoc_user );
            bo_ret = ads_session->dsc_auth.m_hobte_get_config( adsl_element->dsc_rac.inc_cur, &dsl_hobte_conf );
            if( bo_ret )
			{
				// dsl_hobte_conf.m_set_subprotocol(adsl_entry->iec_subprotocol);
        		int iml_subprotocol = dsl_hobte_conf.m_get_subprotocol();	
			    if( iml_subprotocol >= 0 && iml_subprotocol < IMS_NUM_WEBTERM_LINKS )
			    {
                    const dsd_unicode_string& rdsl_link = DSRS_WEBTERM_LINKS[iml_subprotocol];
                    ads_out->m_write_html_text(rdsl_link);
			    }
               
            }
			break;
        }
        case ied_xslgrp_usr_webterm_te_session: {            
            bo_ret = ads_session->dsc_auth.m_hobte_get_config( adsl_element->dsc_rac.inc_cur, &dsl_hobte_conf );
			if( bo_ret )
			{
                const char* achl_name;
				dsl_hobte_conf.m_get_name( &achl_name, &in_len_data );
                ads_out->m_write_html_text( achl_name, in_len_data );
			}
			break;
        }
#endif
    } // end of switch
} // end of ds_xsl::m_cb_get_usr_data


/**
 * function ds_xsl::m_cb_get_rdvpn_data
 * get data from rdvpn group to insert in xsl
 * 
 * @param[in]   int             in_type         value type
 * @param[out]  ds_hstring*     ads_out         output buffer
*/
void ds_xsl::m_cb_get_rdvpn_data( int in_type, ds_hstring* ads_out )
{
    // initialize some variables:
    ied_xslvalue ied_type = (ied_xslvalue)in_type;
    
    switch ( ied_type ) {  
        case ied_xslval_rdvpn_wsp_name:
            ads_out->m_write_html_text( dsd_const_string::m_from_zeroterm(ads_wsp_helper->m_cb_get_wsp_info()) );
            break;
        case ied_xslval_rdvpn_iws_ver:
            ads_out->m_write_html_text( WS_VERSION_STRING );
            break;

        case ied_xslval_rdvpn_iws_name:
            ads_out->m_write_html_text( WEBSERVER_NAME );
            break;

        case ied_xslval_rdvpn_iws_architecture:
#if defined WIN32 || defined WIN64
            ads_out->m_write_html_text( "Windows " );
#endif
            ads_out->m_write_html_text( HL_CPUTYPE );
            break;

        case ied_xslval_rdvpn_iws_date:
            ads_out->m_write_html_text( __DATE__ );
            break;

        case ied_xslval_rdvpn_iws_host:
            if (ads_session->dsc_http_hdr_in.hstr_hf_host.m_get_len() > 0) {
                ads_out->m_write_html_text( ads_session->dsc_http_hdr_in.hstr_hf_host );
            } else { // read from config-file; port is otherwise
                ads_out->m_write_html_text( ads_session->hstr_conf_authority );
            }
            break;
    } // end of switch
} // end of ds_xsl::m_cb_get_rdvpn_data


/**
 * function ds_xsl::m_cb_get_login_data
 * get data from login group to insert in xsl
 * 
 * @param[in]   int             in_type         value type
 * @param[out]  ds_hstring*     ads_out         output buffer
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_element     element counter for "for-each" loop
*/
void ds_xsl::m_cb_get_login_data( int in_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element )
{
    // initialize some variables:
    ied_xslvalue              ied_type     = (ied_xslvalue)in_type;
    dsd_xsl_iterator*         adsl_element;
    dsd_wspat_pconf_t         *adsl_wspat_conf;
    dsd_kick_out_t            dsl_kickout;
    struct dsd_domain         *adsl_domain;

    switch ( ied_type ) {


		/* hofmants: get the cookie user name which was set after successful authentication */
		case ied_xslval_login_cookie_user:
#if SM_USE_CERT_AUTH_V2
			if(ads_session->boc_fixed_login) {
				ads_out->m_write_html_text(ads_session->dsc_username);
				break;
			}
#endif
			if ( ads_session->dsc_http_hdr_in.hstr_hdrline_cookie.m_get_len() > 0 )
			{
				int inl_off1;
				int inl_off2;

				/* get beginning and end offset: ->H<-OBWSP_USER=prog01->;<- */
                dsd_const_string dsl_wspuser(HOBWSP_USER);
				inl_off1 = ads_session->dsc_http_hdr_in.hstr_hdrline_cookie.m_search( HOBWSP_USER );
				if( inl_off1 < 0 ){ break; }
                inl_off1 += dsl_wspuser.m_get_len();
				inl_off2 = ads_session->dsc_http_hdr_in.hstr_hdrline_cookie.m_search( inl_off1, ";" );
                if(inl_off2 < 0)
                    inl_off2 = ads_session->dsc_http_hdr_in.hstr_hdrline_cookie.m_get_len();
				ads_out->m_write_html_text( ads_session->dsc_http_hdr_in.hstr_hdrline_cookie.m_substring( inl_off1, inl_off2 ) );
			}
            break;

        case ied_xslval_login_query_username:
            ads_out->m_write_html_text( USERNAME );
            break;

        case ied_xslval_login_query_userdomain:
            ads_out->m_write_html_text( HL_WS_DOMAIN );
            break;

        case ied_xslval_login_query_password:
            ads_out->m_write_html_text( PASSWORD );
            break;

        case ied_xslval_login_query_kick_out:
            ads_out->m_write_html_text( KICKOUT );
            break;

        case ied_xslval_login_query_create_new:
            ads_out->m_write_html_text( DEF_CREATE_NEW );
            break;

        case ied_xslval_login_query_cancel:
            ads_out->m_write_html_text( CANCEL );
            break;

        case ied_xslval_login_query_show_homepage:
            ads_out->m_write_html_text( SHOW_HOMEPAGE );
            break;

        case ied_xslval_login_query_old_pwd:
            ads_out->m_write_html_text( OLD_PASSWORD );
            break;

        case ied_xslval_login_query_new_pwd:
            ads_out->m_write_html_text( NEW_PASSWORD );
            break;

        case ied_xslval_login_query_conf_pwd:
            ads_out->m_write_html_text( CONF_PASSWORD );
            break;

        case ied_xslval_login_domain_name:
#if SM_USE_CERT_AUTH_V2
			if(ads_session->boc_fixed_login) {
				ads_out->m_write_html_text(ads_session->dsc_domain);
				break;
			}
#endif
			adsl_element = ads_element->m_get_last_ref();
            adsl_wspat_conf = ads_wsp_helper->m_get_wspat_config();
            if ( adsl_wspat_conf == NULL ) {
                break;
            }
			adsl_domain = (dsd_domain*)adsl_element->dsc_fwd.avoc_cur;
            if ( adsl_domain != NULL ) {
                ads_out->m_write_html_text( adsl_domain->achc_disp_name, adsl_domain->inc_len_disp_name );
            }
            break;

        case ied_xslval_login_kick_out_ineta:
            adsl_element = ads_element->m_get_last_ref();
            dsl_kickout = ads_session->dscv_kick_out.m_get(adsl_element->dsc_rac.inc_cur);
            m_cb_print_ineta( ads_out, dsl_kickout.dsc_ineta );
            break;

        case ied_xslval_login_kick_out_login_time:
            adsl_element = ads_element->m_get_last_ref();
            dsl_kickout = ads_session->dscv_kick_out.m_get(adsl_element->dsc_rac.inc_cur);
            ads_out->m_writef( "%lld", dsl_kickout.tmc_login );
            break;

        case ied_xslval_login_kick_out_session:
            adsl_element = ads_element->m_get_last_ref();
            dsl_kickout = ads_session->dscv_kick_out.m_get(adsl_element->dsc_rac.inc_cur);
			ads_out->m_writef( "%d", (int)dsl_kickout.chc_session.ucc_session_no );
            break;

        case ied_xslval_login_kicked_out_ineta:
            ads_out->m_write_html_text( ads_session->dsc_auth.m_get_kicked_out_ineta() );
            break;

        case ied_xslval_login_kicked_out_login_time:
            ads_out->m_writef( "%lld", ads_session->dsc_auth.m_get_kicked_out_time() );
            break;
    } // end of switch
} // end of ds_xsl::m_cb_get_login_data


/**
 * function ds_xsl::m_cb_get_logout_data
 * get data from logout group to insert in xsl
 * 
 * @param[in]   int             in_type         value type
 * @param[out]  ds_hstring*     ads_out         output buffer
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_element     element counter for "for-each" loop
*/
void ds_xsl::m_cb_get_logout_data( int in_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element )
{
    // initialize some variables:
    ied_xslvalue              ienl_type = (ied_xslvalue)in_type;
    dsd_xsl_iterator*         inl_element;
    struct dsd_session_info*  adsl_sess;
    
    inl_element = ads_element->m_get_last_ref();
    adsl_sess  = ads_session->dsc_webserver.dsc_v_logout_connections.m_get( inl_element->dsc_rac.inc_cur );
    if ( adsl_sess == NULL ) {
        return;
    }

    switch ( ienl_type ) {
        case ied_xslval_logout_session_gate_name:
            ads_out->m_write_html_text( adsl_sess->ach_gate_name,
                              adsl_sess->ds_sess_info.imc_len_gate_name );
            break;

        case ied_xslval_logout_session_svr_entry:
            ads_out->m_write_html_text( adsl_sess->ach_serv_entry,
                              adsl_sess->ds_sess_info.imc_len_serv_ent );
            break;

        case ied_xslval_logout_session_proto:
            ads_out->m_write_html_text( adsl_sess->ach_protocol,
                              adsl_sess->ds_sess_info.imc_len_protocol );
            break;

        case ied_xslval_logout_session_srv_ip_port:
            short int is_port;
            if ( adsl_sess->ds_sess_info.imc_len_ineta_port > 2 ) {
                /*
                    we take the last 2 bytes as port number!
                */
                memcpy( &is_port,
                        &adsl_sess->ach_server_ineta[adsl_sess->ds_sess_info.imc_len_ineta_port - 2],
                        2 );
            } else {
                is_port = 0;
            }

            if ( adsl_sess->ds_sess_info.imc_len_ineta_port == 6 ) {
                /*
                    IPv4 with port (4+2 bytes)
                */
                ads_out->m_writef( "%u.%u.%u.%u:%d",
                                   (unsigned char)adsl_sess->ach_server_ineta[0],
                                   (unsigned char)adsl_sess->ach_server_ineta[1],
                                   (unsigned char)adsl_sess->ach_server_ineta[2],
                                   (unsigned char)adsl_sess->ach_server_ineta[3],
                                   is_port );
            } else if ( adsl_sess->ds_sess_info.imc_len_ineta_port == 18 ) {
                /*
                    IPv6 with port (16+2 bytes)
                */
                ads_out->m_writef( "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:[%d]",
                                   (unsigned char)adsl_sess->ach_server_ineta[ 0],
                                   (unsigned char)adsl_sess->ach_server_ineta[ 1],
                                   (unsigned char)adsl_sess->ach_server_ineta[ 2],
                                   (unsigned char)adsl_sess->ach_server_ineta[ 3],
                                   (unsigned char)adsl_sess->ach_server_ineta[ 4],
                                   (unsigned char)adsl_sess->ach_server_ineta[ 5],
                                   (unsigned char)adsl_sess->ach_server_ineta[ 6],
                                   (unsigned char)adsl_sess->ach_server_ineta[ 7],
                                   (unsigned char)adsl_sess->ach_server_ineta[ 8],
                                   (unsigned char)adsl_sess->ach_server_ineta[ 9],
                                   (unsigned char)adsl_sess->ach_server_ineta[10],
                                   (unsigned char)adsl_sess->ach_server_ineta[11],
                                   (unsigned char)adsl_sess->ach_server_ineta[12],
                                   (unsigned char)adsl_sess->ach_server_ineta[13],
                                   (unsigned char)adsl_sess->ach_server_ineta[14],
                                   (unsigned char)adsl_sess->ach_server_ineta[15],
                                   is_port );
            }
            break;

        case ied_xslval_logout_session_number:
            ads_out->m_writef( "%d", adsl_sess->ds_sess_info.imc_session_no );
            break;

        case ied_xslval_logout_session_clt_ip:
            ads_out->m_write_zeroterm( adsl_sess->ds_sess_info.chrc_ineta );
            break;

        case ied_xslval_logout_session_time_started:
            ads_out->m_writef( "%d", adsl_sess->ds_sess_info.imc_time_start );
            break;

        case ied_xslval_logout_session_no_rec_clt:
            ads_out->m_writef( "%d", adsl_sess->ds_sess_info.imc_c_ns_rece_c );
            break;

        case ied_xslval_logout_session_no_snd_clt:
            ads_out->m_writef( "%d", adsl_sess->ds_sess_info.imc_c_ns_send_c );
            break;

        case ied_xslval_logout_session_no_rec_srv:
            ads_out->m_writef( "%d", adsl_sess->ds_sess_info.imc_c_ns_rece_s );
            break;

        case ied_xslval_logout_session_no_snd_srv:
            ads_out->m_writef( "%d", adsl_sess->ds_sess_info.imc_c_ns_send_s );
            break;

        case ied_xslval_logout_session_no_rec_crypt:
            ads_out->m_writef( "%d", adsl_sess->ds_sess_info.imc_c_ns_rece_e );
            break;

        case ied_xslval_logout_session_no_snd_crypt:
            ads_out->m_writef( "%d", adsl_sess->ds_sess_info.imc_c_ns_send_e );
            break;

        case ied_xslval_logout_session_dt_rec_clt:
            m_cb_print_bytes( ads_out, adsl_sess->ds_sess_info.ilc_d_ns_rece_c );
            break;

        case ied_xslval_logout_session_dt_snd_clt:
            m_cb_print_bytes( ads_out, adsl_sess->ds_sess_info.ilc_d_ns_send_c );
            break;

        case ied_xslval_logout_session_dt_rec_srv:
            m_cb_print_bytes( ads_out, adsl_sess->ds_sess_info.ilc_d_ns_rece_s );
            break;

        case ied_xslval_logout_session_dt_snd_srv:
            m_cb_print_bytes( ads_out, adsl_sess->ds_sess_info.ilc_d_ns_send_s );
            break;

        case ied_xslval_logout_session_dt_rec_crypt:
            m_cb_print_bytes( ads_out, adsl_sess->ds_sess_info.ilc_d_ns_rece_e );
            break;

        case ied_xslval_logout_session_dt_snd_crypt:
            m_cb_print_bytes( ads_out, adsl_sess->ds_sess_info.ilc_d_ns_send_e );
            break;

        case ied_xslval_logout_session_cert_name:
            ads_out->m_write_html_text( adsl_sess->ach_cert_name,
                              adsl_sess->ds_sess_info.imc_len_name_cert );
            break;

        case ied_xslval_logout_session_user_name:
            ads_out->m_write_html_text( adsl_sess->ach_user,
                              adsl_sess->ds_sess_info.imc_len_userid );
            break;

        case ied_xslval_logout_session_user_group:
            ads_out->m_write_html_text( adsl_sess->ach_group,
                              adsl_sess->ds_sess_info.imc_len_user_group );
            break;

        case ied_xslval_logout_session_cur_handle:
            ads_out->m_writef( "%lld", adsl_sess->dsc_wsp.ilc_handle );
            break;

        case ied_xslval_logout_session_cur_srv_name:
            ads_out->m_write_html_text( adsl_sess->dsc_wsp.achc_srv_name,
                              adsl_sess->dsc_wsp.inc_len_srv_name );
            break;
    } // end of switch
} // end of ds_xsl::m_cb_get_logout_data


/**
 * function ds_xsl::m_cb_get_ppptnl_data
 * get data from ppptnl group to insert in xsl
 * 
 * @param[in]   int             in_type         value type
 * @param[out]  ds_hstring*     ads_out         output buffer
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_element     element counter for "for-each" loop
*/
void ds_xsl::m_cb_get_ppptnl_data( int in_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element )
{
    // initialize some variables:
    ied_xslvalue              ienl_type = (ied_xslvalue)in_type;
    dsd_xsl_iterator*         inl_element;
    int                       inl_pos;
    struct dsd_pppt           *adsl_ppptnl;
    
    // get current element:


    switch ( ienl_type ) {
        case ied_xslval_ppptnl_name:
            adsl_ppptnl = ads_session->ads_config->adsl_pppt;
            inl_element = ads_element->m_get_last_ref();

            if ( adsl_ppptnl == NULL ) {
                return;
            }

			inl_pos = inl_element->dsc_rac.inc_cur;

            do {
				// skip invalid tunnel configs 
				BOOL bol_found = FALSE;
				void*				avl_srv_handle		= NULL;
				do {
					int					inl_function		= -1;
					char                chrl_buffer[512];           // temp buffer for server name    
					int                 inl_len = 512;
					avl_srv_handle = ads_wsp_helper->m_cb_get_server_entry(NULL, NULL, ied_scp_hpppt1, NULL, 0, 
														  chrl_buffer,
														  &inl_len,
														  avl_srv_handle, &inl_function );
					if (avl_srv_handle == NULL) {
						break;
					}
					if(	( adsl_ppptnl->in_len_server_entry_name == inl_len )
						&&	( memcmp( adsl_ppptnl->ach_server_entry_name, chrl_buffer, inl_len ) == 0 ) ){
							bol_found = TRUE;
							break;
					}
				} while (TRUE);
				if (bol_found == FALSE) {
					adsl_ppptnl = adsl_ppptnl->adsc_next;
					if ( adsl_ppptnl == NULL ) {
						return;
					}
					continue;
				}
				if (inl_pos > 0) {
					inl_pos--;
					adsl_ppptnl = adsl_ppptnl->adsc_next;
					if ( adsl_ppptnl == NULL ) {
						return;
					}
					continue;
				}
				break;
            } while (TRUE);

            ads_out->m_write_html_text( adsl_ppptnl->ach_server_entry_name,
                              adsl_ppptnl->in_len_server_entry_name );
            break;

        case ied_xslval_ppptnl_id:
            adsl_ppptnl = ads_session->ads_config->adsl_pppt;
            inl_element = ads_element->m_get_last_ref();

            if ( adsl_ppptnl == NULL ) {
                return;
            }

			inl_pos = inl_element->dsc_rac.inc_cur;

			do {
				// skip invalid tunnel configs 
				BOOL bol_found = FALSE;
				void*				avl_srv_handle		= NULL;
				do {
					int					inl_function		= -1;
					char                chrl_buffer[512];           // temp buffer for server name    
					int                 inl_len = 512;
					avl_srv_handle = ads_wsp_helper->m_cb_get_server_entry(NULL, NULL, ied_scp_hpppt1, NULL, 0, 
														  chrl_buffer,
														  &inl_len,
														  avl_srv_handle, &inl_function );
					if (avl_srv_handle == NULL) {
						break;
					}
					if(	( adsl_ppptnl->in_len_server_entry_name == inl_len )
						&&	( memcmp( adsl_ppptnl->ach_server_entry_name, chrl_buffer, inl_len ) == 0 ) ){
							bol_found = TRUE;
							break;
					}
				} while (TRUE);
				if (bol_found == FALSE) {
					adsl_ppptnl = adsl_ppptnl->adsc_next;
					if ( adsl_ppptnl == NULL ) {
						return;
					}
					continue;
				}
				if (inl_pos > 0) {
					inl_pos--;
					adsl_ppptnl = adsl_ppptnl->adsc_next;
					if ( adsl_ppptnl == NULL ) {
						return;
					}
					continue;
				}
				break;
            } while (TRUE);

			ads_out->m_writef( "%d", adsl_ppptnl->in_id );
            break;

        case ied_xslval_ppptnl_ineta:
            adsl_ppptnl = m_get_tunnel_by_id();
            if ( adsl_ppptnl == NULL ) {
                return;
            }
            ads_out->m_write_html_text( adsl_ppptnl->ach_address, adsl_ppptnl->in_len_address );
            break;

        case ied_xslval_ppptnl_socks:
            adsl_ppptnl = m_get_tunnel_by_id();
            if ( adsl_ppptnl == NULL ) {
                return;
            }
            m_compose_socks_mode( ads_out, adsl_ppptnl->ach_server_entry_name,
                                  adsl_ppptnl->in_len_server_entry_name );
            break;

        case ied_xslval_ppptnl_localhost:
            adsl_ppptnl = m_get_tunnel_by_id();
            if ( adsl_ppptnl == NULL ) {
                return;
            }
            ads_out->m_write_html_text( adsl_ppptnl->ach_localhost, adsl_ppptnl->in_len_localhost );
            break;

        //case ied_xslval_ppptnl_sys_params: {
        //    adsl_ppptnl = m_get_tunnel_by_id();
        //    if ( adsl_ppptnl == NULL ) {
        //        return;
        //    }
        //    ds_hstring hstr_username(ads_session->ads_wsp_helper, ads_session->dsc_auth.m_get_username().m_get_ptr());
        //    if (hstr_username.m_search("%", true, 0, true) != -1) {
	       //     // JF 03.03.11 Ticket[21611]: On client side another Precomp runs, so we must duplicate twice.
        //        // hstr_username.m_replace("%", "%%", true, 0);
        //        hstr_username.m_replace("%", "%%%%", true, 0);
        //    }
        //    ds_hstring hstr_password(ads_session->ads_wsp_helper, ads_session->dsc_auth.m_get_password().m_get_ptr());
        //    if (hstr_password.m_search("%", true, 0, true) != -1) {
	       //     // JF 03.03.11 Ticket[21611]: hstr_password.m_replace("%", "%%", true, 0);
        //        hstr_password.m_replace("%", "%%%%", true, 0);
        //    }

        //    struct dsd_hl_clib_1 dsl_trans_precomp;
        //    memset( &dsl_trans_precomp, 0, sizeof(dsd_hl_clib_1) );
        //    int in_precomp = ads_session->dsc_webserver.m_use_precomp( adsl_ppptnl->ach_system_parameters,
        //                                                               (  adsl_ppptnl->ach_system_parameters
        //                                                                 + adsl_ppptnl->in_len_system_parameters),
        //                                                               &dsl_trans_precomp,
        //                                                               NULL,
        //                                                               hstr_username.m_get_ptr(),
        //                                                               hstr_password.m_get_ptr(),
        //                                                               NULL, NULL, NULL, NULL);
        //    if ( in_precomp > 1 ) {
        //        ads_out->m_write_b64(dsl_trans_precomp.adsc_gai1_out_to_client->achc_ginp_cur, in_precomp);
        //    }
        //    break; }
        case ied_xslval_ppptnl_server_name:
            adsl_ppptnl = m_get_tunnel_by_id();
            if ( adsl_ppptnl == NULL ) {
                return;
            }
            ads_out->m_write_html_text( adsl_ppptnl->ach_server_entry_name, adsl_ppptnl->in_len_server_entry_name );
            break;
    }
    return;
} // end of ds_xsl::m_cb_get_ppptnl_data


/**
 * function ds_xsl::m_get_tunnel_by_id
*/
struct dsd_pppt* ds_xsl::m_get_tunnel_by_id()
{
    if ( ads_session->dsc_http_hdr_in.dsc_url.hstr_query.m_get_len() < 4 ) {
        return NULL;
    }

    // Read the ID number from the query.
    dsd_const_string hstrl_query(ads_session->dsc_http_hdr_in.dsc_url.hstr_query);
    if (!hstrl_query.m_starts_with_ic("ID=")) { // Query must start with "ID="
        return NULL;
    }
    dsd_const_string hstr_idx = hstrl_query.m_substring(3);
    int in_idx = -1;
    if (!hstr_idx.m_parse_int(&in_idx)) { // Index number is no number.
        return NULL;
    }

    // Find the PPP-Tunnel-configuration according to this ID number.
    struct dsd_pppt* adsl_pppt = ads_session->ads_config->adsl_pppt;
    while(adsl_pppt != NULL) {
        if (adsl_pppt->in_id == in_idx) {
            break;
        }
        adsl_pppt = adsl_pppt->adsc_next;
    }
    return adsl_pppt;
} // end of ds_xsl::m_get_tunnel_by_id


/**
 * function ds_xsl::m_compose_socks_mode
 * Compose a string, which will be given to PPPTunnelClient.
 * The string must be encoded in base64.
*/
void ds_xsl::m_compose_socks_mode( ds_hstring* adsp_out, const char *achp_server, int inp_length )
{
    // 0x05 0x00  -> HOB-Socks-Protocol
    ds_hstring hstr(ads_session->ads_wsp_helper);
    char ch_to_write = 0x05;
    hstr.m_write(&ch_to_write, 1);
    ch_to_write = 0x00;
    hstr.m_write(&ch_to_write, 1);

    // Name of the protocol
    hstr.m_write("HOB-PPP-T1");
    ch_to_write = 0x00;
    hstr.m_write(&ch_to_write, 1);

	// userid
    hstr.m_write("userid=");
    hstr.m_write(ads_session->dsc_auth.m_get_hobsocks_name());
    ch_to_write = 0x00;
    hstr.m_write(&ch_to_write, 1);

    // password
    // Attention: We must use the sessionticket, which was created after successful authentication.
    hstr.m_write("password=");
    hstr.m_write(ads_session->dsc_auth.m_get_sticket());
    ch_to_write = 0x00;
    hstr.m_write(&ch_to_write, 1);

    // server (from serverlist)
    hstr.m_write("server=");
    hstr.m_write( achp_server, inp_length );
    ch_to_write = 0x00;
    hstr.m_write(&ch_to_write, 1);

    // close this section
    ch_to_write = 0x00;
    hstr.m_write(&ch_to_write, 1);

    //------------
    // Authentication methods
    //------------
    // Number of authentication methods (1 byte).
    ch_to_write = 0x03;
    hstr.m_write(&ch_to_write, 1);
    // No Authentication
    ch_to_write = 0x00;
    hstr.m_write(&ch_to_write, 1);
    // Authentication
    ch_to_write = (char)0x83;
    hstr.m_write(&ch_to_write, 1);
    // Display Servers
    ch_to_write = (char)0x84;
    hstr.m_write(&ch_to_write, 1);


    // Encode into base64
    adsp_out->m_write_b64(hstr.m_get_ptr(), hstr.m_get_len());
} // end of ds_xsl::m_compose_socks_mode


/**
 * function ds_xsl::m_cb_get_queryparam_data
 * get data from postparam group to insert in xsl
 * 
 * @param[in]   int             in_type         value type
 * @param[out]  ds_hstring*     ads_out         output buffer
*/
void ds_xsl::m_cb_get_queryparam_data( int in_type, ds_hstring* ads_out )
{
    // initialize some variables:
    ied_xslvalue ied_type = (ied_xslvalue)in_type;

    switch ( ied_type ) {
        case ied_xslval_queryparam_set_lang:
            ads_out->m_write( ach_tmp_post_params[(int)ied_post_language] );
            break;

        case ied_xslval_queryparam_save_lang:
            ads_out->m_write( ach_settings_params[(int)ied_set_save_lang] );
            break;

        case ied_xslval_queryparam_rm_cookie:
            ads_out->m_write( ach_tmp_post_params[(int)ied_post_rm_cookie] );
            break;

        case ied_xslval_queryparam_sett_task:
            ads_out->m_write( ach_settings_params[(int)ied_set_task] );
            break;

        case ied_xslval_queryparam_wsg_bmark:
            ads_out->m_write( ach_settings_params[(int)ied_set_wsg_bmark] );
            break;

        case ied_xslval_queryparam_rdvpn_bmark:
            ads_out->m_write( ach_settings_params[(int)ied_set_rdvpn_bmark] );
            break;

        case ied_xslval_queryparam_wfa_bmark:
            ads_out->m_write( ach_settings_params[(int)ied_set_wfa_bmark] );
            break;

        case ied_xslval_queryparam_bmark_name:
            ads_out->m_write( ach_settings_params[(int)ied_set_bmark_name] );
            break;

        case ied_xslval_queryparam_bmark_url:
            ads_out->m_write( ach_settings_params[(int)ied_set_bmark_url] );
            break;

        case ied_xslval_queryparam_wsg_flyer:
            ads_out->m_write( ach_settings_params[(int)ied_set_wsg_flyer] );
            break;

        case ied_xslval_queryparam_wstat:
            ads_out->m_write( ach_settings_params[(int)ied_set_dod_wstat] );
            break;

        case ied_xslval_queryparam_wstat_name:
            ads_out->m_write( ach_settings_params[(int)ied_set_wstat_name] );
            break;

        case ied_xslval_queryparam_wstat_ineta:
            ads_out->m_write( ach_settings_params[(int)ied_set_wstat_ineta] );
            break;

        case ied_xslval_queryparam_wstat_port:
            ads_out->m_write( ach_settings_params[(int)ied_set_wstat_port] );
            break;

        case ied_xslval_queryparam_wstat_mac:
            ads_out->m_write( ach_settings_params[(int)ied_set_wstat_mac] );
            break;

        case ied_xslval_queryparam_wstat_timeout:
            ads_out->m_write( ach_settings_params[(int)ied_set_wstat_tout] );
            break;

        case ied_xslval_queryparam_portlet:
            ads_out->m_write( ach_settings_params[(int)ied_set_portlet] );
            break;

        case ied_xslval_queryparam_portlet_state:
            ads_out->m_write( ach_settings_params[(int)ied_set_portlet_state] );
            break;

        case ied_xslval_queryparam_portlet_pos:
            ads_out->m_write( ach_settings_params[(int)ied_set_portlet_pos] );
            break;

        case ied_xslval_queryparam_edit_sett:
            ads_out->m_write( ach_settings_tasks[(int)ied_set_task_edit] );
            break;
        case ied_xslval_queryparam_default_portlet:
            ads_out->m_write( ach_settings_params[(int)ied_set_default_portlet] );
            break;
    } // end of switch
} // end of ds_xsl::m_cb_get_queryparam_data


/**
 * function ds_xsl::m_cb_get_wspadmin_data
 * get data from wspadmin group to insert in xsl
 * 
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_type        value type vector
 * @param[out]  ds_hstring*          ads_out         output buffer
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_element     element counter for "for-each" loop
*/
void ds_xsl::m_cb_get_wspadmin_data( ds_hvector_btype<int>* ads_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element )
{    
    if ( ads_type->m_size() < 2 ) {
        return;
    }
    switch ( ads_type->m_get(1) ) {
        case ied_xslval_wspadmin_return_code:
            return m_cb_print_wspadmin_rcode( ads_out );

        case ied_xslgrp_wspadmin_query:
            return m_cb_get_wspadmin_query_data( ads_type, ads_out );

        case ied_xslgrp_wspadmin_cluster:
            return m_cb_get_wspadmin_cluster_data( ads_type, ads_out, ads_element );

        case ied_xslgrp_wspadmin_session:
            return m_cb_get_wspadmin_session_data( ads_type, ads_out, ads_element );

        case ied_xslgrp_wspadmin_listen:
            return m_cb_get_wspadmin_listen_data( ads_type, ads_out, ads_element );

        case ied_xslgrp_wspadmin_perf:
            return m_cb_get_wspadmin_perf_data( ads_type, ads_out );

        case ied_xslgrp_wspadmin_log:
            return m_cb_get_wspadmin_log_data( ads_type, ads_out, ads_element );

        case ied_xslgrp_wspadmin_user:
            return m_cb_get_wspadmin_user_data( ads_type, ads_out, ads_element );

		case ied_xslgrp_wspadmin_trace:
			return m_cb_get_wspadmin_trace_data( ads_type, ads_out, ads_element );

    } // end of switch
} // end of ds_xsl::m_cb_get_wspadmin_data


/**
 * function ds_xsl::m_cb_get_wspadmin_query_data
 * get data from wspadmin cluster subgroup to insert in xsl
 * 
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_type        value type vector
 * @param[out]  ds_hstring*     ads_out         output buffer
*/
void ds_xsl::m_cb_get_wspadmin_query_data( ds_hvector_btype<int>* ads_type, ds_hstring* ads_out )
{
    switch ( ads_type->m_get_last() ) {
        case ied_xslval_wspadmin_query_sel_cluster:
            ads_out->m_write( achr_wspadmin_queries[(int)ied_wspadmin_query_handle] );
            break;

        case ied_xslval_wspadmin_query_disp_from:
            ads_out->m_write( achr_wspadmin_queries[(int)ied_wspadmin_query_start] );
            break;

        case ied_xslval_wspadmin_query_disp_total:
            ads_out->m_write( achr_wspadmin_queries[(int)ied_wspadmin_query_rec] );
            break;

        case ied_xslval_wspadmin_query_count_filled:
            ads_out->m_write( achr_wspadmin_queries[(int)ied_wspadmin_query_filled] );
            break;

        case ied_xslval_wspadmin_query_get_backward:
            ads_out->m_write( achr_wspadmin_queries[(int)ied_wspadmin_query_backward] );
            break;

        case ied_xslval_wspadmin_query_search_usr:
            ads_out->m_write( achr_wspadmin_queries[(int)ied_wspadmin_query_user] );
            break;

        case ied_xslval_wspadmin_query_search_usrgroup:
            ads_out->m_write( achr_wspadmin_queries[(int)ied_wspadmin_query_group] );
            break;

        case ied_xslval_wspadmin_query_search_time:
            ads_out->m_write( achr_wspadmin_queries[(int)ied_wspadmin_query_epoch] );
            break;

        case ied_xslval_wspadmin_query_search_word:
            ads_out->m_write( achr_wspadmin_queries[(int)ied_wspadmin_query_search] );
            break;

        case ied_xslval_wspadmin_query_search_wildcard:
            ads_out->m_write( achr_wspadmin_queries[(int)ied_wspadmin_query_wildcard] );
            break;

        case ied_xslval_wspadmin_query_search_regexp:
            ads_out->m_write( achr_wspadmin_queries[(int)ied_wspadmin_query_regexp] );
            break;

        case ied_xslval_wspadmin_query_disc_session:
            ads_out->m_write( achr_wspadmin_queries[(int)ied_wspadmin_query_session] );
            break;

        case ied_xslval_wspadmin_query_logout_usr:
            ads_out->m_write( ach_tmp_post_params[(int)ied_post_logout_usr] );
            break;

		case ied_xslval_wspadmin_query_trace_ineta:
			ads_out->m_write( achr_wspadmin_queries[(int)ied_wsptrace_query_single_ineta]);
			break;

        case ied_xslval_wspadmin_query_erase_inetas:
			ads_out->m_write( achr_wspadmin_queries[(int)ied_wspadmin_query_erase_inetas]);
			break;

        case ied_xslval_wspadmin_query_dump_cma:
            ads_out->m_write( achr_wspadmin_queries[(int)ied_wspadmin_query_dump_cma]);
			break;
    } // end of switch
} // end of ds_xsl::m_cb_get_wspadmin_query_data


/**
 * function ds_xsl::m_cb_get_wspadmin_cluster_data
 * get data from wspadmin cluster subgroup to insert in xsl
 * 
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_type        value type vector
 * @param[out]  ds_hstring*     ads_out         output buffer
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_element     element counter for "for-each" loop
*/
void ds_xsl::m_cb_get_wspadmin_cluster_data( ds_hvector_btype<int>* ads_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element )
{
    // initialize some variables:
    ied_xslvalue        ied_type = (ied_xslvalue)ads_type->m_get_last();
    dsd_xsl_iterator*   adsl_member;
    int                 in_count;
    dsd_cluster*        ads_cluster;                    // cluster list
    dsd_cluster_remote_01* ads_rem_cluster = NULL;      // rem cluster element

    //-----------------------------------------
    // get cluster list from wsp:
    //-----------------------------------------
    ads_cluster = dsc_admin.m_get_cluster_info();
    if ( ads_cluster == NULL ) {
        return;
    }

    //-----------------------------------------
    // get requested element:
    //-----------------------------------------
    adsl_member = ads_element->m_get_last_ref();
    if ( adsl_member->dsc_rac.inc_cur > 0 ) {
        ads_rem_cluster = ads_cluster->ads_next;
        for ( in_count = 1; in_count < adsl_member->dsc_rac.inc_cur; in_count++ ) {
            ads_rem_cluster = ads_rem_cluster->ads_next;
        }
    }

    if ( adsl_member->dsc_rac.inc_cur < 0 ) {
        //-------------------------------------
        // get requested cluster handle:
        //-------------------------------------
        dsd_const_string dsl_handle;
        ads_session->dsc_webserver.m_get_query_value( achr_wspadmin_queries[(int)ied_wspadmin_query_handle],
                                                      &dsl_handle );
        if ( dsl_handle.m_get_len() > 0 ) {
            long long int ill_handle;                     // cluster handle
            dsl_handle.m_parse_long( &ill_handle );

            if ( ill_handle > 0 ) {
                ads_rem_cluster = ads_cluster->ads_next;
                while( ads_rem_cluster != NULL ) {
                    if ( ads_rem_cluster->ds_remote.ilc_handle_cluster == ill_handle ) {
                        break;
                    }
                    ads_rem_cluster = ads_rem_cluster->ads_next;
                }
            }
        }
    }

    //-----------------------------------------
    // print data:
    //-----------------------------------------
    switch ( ied_type ) {
        case ied_xslval_wspadmin_cluster_select_handle:
            if ( ads_rem_cluster != NULL ) {
                ads_out->m_writef( "%lld", ads_rem_cluster->ds_remote.ilc_handle_cluster );
            } else {
                ads_out->m_write( "0" );
            }
            break;

        case ied_xslval_wspadmin_cluster_start_time:
            if ( ads_rem_cluster != NULL ) {
                ads_out->m_writef( "%lld", ads_rem_cluster->ds_remote.ilc_epoch_started );
            } else {
                ads_out->m_writef( "%lld", ads_cluster->ds_main.ilc_epoch_started );
            }
            break;

        case ied_xslval_wspadmin_cluster_server_name:
            if ( ads_rem_cluster != NULL ) {
                ads_out->m_write_zeroterm( ads_rem_cluster->ach_serv_name );
            } else {
                ads_out->m_write_zeroterm( ads_cluster->ach_serv_name );
            }
            break;

        case ied_xslval_wspadmin_cluster_conf_name:
            if ( ads_rem_cluster != NULL ) {
                ads_out->m_write_zeroterm( ads_rem_cluster->ach_conf_name );
            } else {
                ads_out->m_write_zeroterm( ads_cluster->ach_conf_name );
            }
            break;

        case ied_xslval_wspadmin_cluster_wsp_query:
            if ( ads_rem_cluster != NULL ) {
                ads_out->m_write_zeroterm( ads_rem_cluster->ach_wsp_query );
            } else {
                ads_out->m_write_zeroterm( ads_cluster->ach_wsp_query );
            }
            break;

		case ied_xslval_wspadmin_cluster_server_group:
            if ( ads_rem_cluster != NULL ) {
                ads_out->m_write_zeroterm( ads_rem_cluster->ach_serv_group );
            } else {
                ads_out->m_write_zeroterm( ads_cluster->ach_serv_group );
            }
            break;
		
		case ied_xslval_wspadmin_cluster_server_location:
            if ( ads_rem_cluster != NULL ) {
                ads_out->m_write_zeroterm( ads_rem_cluster->ach_serv_location );
            } else {
                ads_out->m_write_zeroterm( ads_cluster->ach_serv_location );
            }
            break;

        case ied_xslval_wspadmin_cluster_process_id:
            if ( ads_rem_cluster != NULL ) {
                ads_out->m_writef( "%d", ads_rem_cluster->ds_remote.imc_pid );
            } else {
                ads_out->m_writef( "%d", ads_cluster->ds_main.imc_pid );
            }
            break;

        case ied_xslval_wspadmin_cluster_connect_time:
            if ( ads_rem_cluster != NULL ) {
                ads_out->m_writef( "%d", ads_rem_cluster->ds_remote.imc_epoch_conn );
            } else {
                ads_out->m_write( "&nbsp;" );
            }
            break;

        case ied_xslval_wspadmin_cluster_lb_load:
            if ( ads_rem_cluster != NULL ) {
                ads_out->m_writef( "%d", ads_rem_cluster->ds_remote.imc_lb_load );
            } else {
                ads_out->m_writef( "%d", ads_cluster->ds_main.imc_lb_load );
            }
            break;

        case ied_xslval_wspadmin_cluster_lb_time:
            if ( ads_rem_cluster != NULL ) {
                ads_out->m_writef( "%d", ads_rem_cluster->ds_remote.imc_lb_epoch );
            } else {
                ads_out->m_writef( "%d", ads_cluster->ds_main.imc_lb_epoch );
            }
            break;

        case ied_xslval_wspadmin_cluster_active:
            if ( ads_rem_cluster != NULL ) {
                m_cb_print_bool( ads_out, (ads_rem_cluster->ds_remote.boc_listen_stopped == FALSE)?true:false );
            } else {
                m_cb_print_bool( ads_out, (ads_cluster->ds_main.boc_listen_stopped == FALSE)?true:false );
            }
            break;

        case ied_xslval_wspadmin_cluster_number_rec:
            if ( ads_rem_cluster != NULL ) {
                ads_out->m_writef( "%d", ads_rem_cluster->ds_remote.imc_stat_no_recv );
            } else {
                ads_out->m_write( "&nbsp;" );
            }
            break;

        case ied_xslval_wspadmin_cluster_length_rec:
            if ( ads_rem_cluster != NULL ) {
                ads_out->m_writef( "%lld", ads_rem_cluster->ds_remote.ilc_stat_len_recv );
            } else {
                ads_out->m_write( "&nbsp;" );
            }
            break;

        case ied_xslval_wspadmin_cluster_number_snd:
            if ( ads_rem_cluster != NULL ) {
                ads_out->m_writef( "%d", ads_rem_cluster->ds_remote.imc_stat_no_send );
            } else {
                ads_out->m_write( "&nbsp;" );
            }
            break;

        case ied_xslval_wspadmin_cluster_length_snd:
            if ( ads_rem_cluster != NULL ) {
                ads_out->m_writef( "%lld", ads_rem_cluster->ds_remote.ilc_stat_len_send );
            } else {
                ads_out->m_write( "&nbsp;" );
            }
            break;
    } // end of switch
} // end of ds_xsl::m_cb_get_wspadmin_cluster_data

/**
 * function ds_xsl::m_cb_get_wspadmin_trace_data
 * @DESC: Gets non boolean data from the current WSP Trace configuration to insert in xsl
 * 
 * @param[in]   ds_hvector_btype<int>*     adsp_type        value type vector
 * @param
 * @param[out]  ds_hstring*				   adsp_out         output buffer
*/
void ds_xsl::m_cb_get_wspadmin_trace_data( ds_hvector_btype<int>* adsp_type, ds_hstring* adsp_out, ds_hstack_btype<dsd_xsl_iterator>* adsp_element)
{
    // initialize some variables:
    ied_xslvalue					iedl_type = (ied_xslvalue)adsp_type->m_get_last();
	struct dsd_wsptrace_info*		adsl_wsptrace_info;
	dsd_xsl_iterator*       		inl_member;
	
    //-----------------------------------------
    // get WSP Trace settings data from wsp:
    //-----------------------------------------
  
	adsl_wsptrace_info = dsc_admin.m_get_wsptrace_info();
    if ( adsl_wsptrace_info == NULL ) {
        return;
    }
	
	//-----------------------------------------
    // get requested element:
    //-----------------------------------------
    inl_member = adsp_element->m_get_last_ref();
    for(int inl_i=0; inl_i<inl_member->dsc_rac.inc_cur; inl_i++ ) {
        adsl_wsptrace_info = adsl_wsptrace_info->ads_next;
    }

    //-----------------------------------------
    // print data:
    //-----------------------------------------
    switch ( iedl_type ) {
		case ied_xslval_wspadmin_trace_wsp_handle:
			// Writes the handle number of the WSP
			adsp_out->m_writef( "%llu", (unsigned long long)adsl_wsptrace_info->dsc_wsp.ilc_handle);
            break;
		case ied_xslval_wspadmin_trace_wsp_srv_name:
			// Writes the name of the server
			adsp_out->m_write_zeroterm(adsl_wsptrace_info->dsc_wsp.achc_srv_name);
            break;
		case ied_xslval_wspadmin_trace_wsp_wsp_name:
			// Writes the name of the WSP
			adsp_out->m_write_zeroterm(adsl_wsptrace_info->dsc_wsp.achc_wsp_name);
            break;
		case ied_xslval_wspadmin_trace_wsp_srv_location:
			// Writes the location of the WSP
			adsp_out->m_write_zeroterm(adsl_wsptrace_info->dsc_wsp.achc_srv_location);
            break;
		case ied_xslval_wspadmin_trace_wsp_srv_group:
			// Writes the name of WSP's group 
			adsp_out->m_write_zeroterm(adsl_wsptrace_info->dsc_wsp.achc_srv_group);
            break;
		case ied_xslval_wspadmin_trace_output:
			// Writes an integer stating the destination output used for tracing: console, ascii or bin file,...
			// There is no possibility yet to know the name of the file where data is being traced (if that is the case).
			adsp_out->m_writef("%u", (unsigned int)adsl_wsptrace_info->dsc_wsptrace_conf.iec_wtt);
            break;
        case ied_xslval_wspadmin_trace_core_data_amount:
			// The HL_WT_CORE_DATA1 and HL_WT_CORE_DATA2 which represent the depth of the 
			// data to be traced, are the least significant bits
			adsp_out->m_writef( "%u", (unsigned int)adsl_wsptrace_info->dsc_wsptrace_conf.imc_wsp_trace_core_flags1 & 3);
            break;
		case ied_xslval_wspadmin_trace_session_data_amount:
			// The HL_WT_SESS_DATA1 and HL_WT_SESS_DATA2 which represent the depth of the 
			// data to be traced, are the least significant bits
			adsp_out->m_writef( "%u", (unsigned int)adsl_wsptrace_info->dsc_wsptrace_conf.imc_sess_ia_trace_level & 3);
			break;
		case ied_xslval_wspadmin_trace_session_allsettings:
			// This prints all the settings for session traces stored in imc_trace_level
			adsp_out->m_writef( "%u", (unsigned int)adsl_wsptrace_info->dsc_wsptrace_conf.imc_sess_ia_trace_level & 0xffff);
			break;
		case ied_xslval_wspadmin_trace_core_allsettings:
			// This prints all the settings for core traces stored in img_trace_core_flags1
			adsp_out->m_writef( "%u", (unsigned int)adsl_wsptrace_info->dsc_wsptrace_conf.imc_wsp_trace_core_flags1 & 0xffff);
			break;
        case ied_xslval_wspadmin_trace_flag_sess_netw:
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_SESS_NETW);
			break;
        case ied_xslval_wspadmin_trace_flag_sess_ssl_ext:
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_SESS_SSL_EXT);
			break;
        case ied_xslval_wspadmin_trace_flag_sess_ssl_int:	
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_SESS_SSL_INT);
			break;
        case ied_xslval_wspadmin_trace_flag_sess_ssl_ocsp:
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_SESS_SSL_OCSP);
			break;
        case ied_xslval_wspadmin_trace_flag_sess_wspat3_ext:
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_SESS_WSPAT3_EXT);
			break;
        case ied_xslval_wspadmin_trace_flag_sess_wspat3_int:
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_SESS_WSPAT3_INT);
			break;
        case ied_xslval_wspadmin_trace_flag_sess_sdh_ext:
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_SESS_SDH_EXT);
			break;
        case ied_xslval_wspadmin_trace_flag_sess_sdh_int:
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_SESS_SDH_INT);
			break;
        case ied_xslval_wspadmin_trace_flag_sess_aux:
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_SESS_AUX);
			break;
        case ied_xslval_wspadmin_trace_flag_sess_misc:	
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_SESS_MISC);
			break;
        case ied_xslval_wspadmin_trace_flag_sess_others:	
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_SESS_OTHERS);
			break;
        case ied_xslval_wspadmin_trace_flag_core_console:
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_CORE_CONSOLE);
			break;
        case ied_xslval_wspadmin_trace_flag_core_cluster:
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_CORE_CLUSTER);
			break;
        case ied_xslval_wspadmin_trace_flag_core_udp:
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_CORE_UDP);
			break;
        case ied_xslval_wspadmin_trace_flag_core_dod:   
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_CORE_DOD);
			break;
        case ied_xslval_wspadmin_trace_flag_core_radius: 
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_CORE_RADIUS);
			break;
        case ied_xslval_wspadmin_trace_flag_core_virus_ch:
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_CORE_VIRUS_CH);
			break;
        case ied_xslval_wspadmin_trace_flag_core_hob_tun:
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_CORE_HOB_TUN);
			break;
        case ied_xslval_wspadmin_trace_flag_core_ldap:
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_CORE_LDAP);
			break;
        case ied_xslval_wspadmin_trace_flag_core_krb5:   
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_CORE_KRB5);
			break;
        case ied_xslval_wspadmin_trace_flag_core_ms_rpc:
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_CORE_MS_RPC);
			break;
        case ied_xslval_wspadmin_trace_flag_core_admin:
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_CORE_ADMIN);
			break;
        case ied_xslval_wspadmin_trace_flag_core_ligw:
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_CORE_LIGW);
			break;
        case ied_xslval_wspadmin_trace_flag_core_others:
            adsp_out->m_writef( "%u", (unsigned int)HL_WT_CORE_OTHERS);
			break;
		case ied_xslval_wspadmin_trace_individual_session:
			//DDTODO: This cannot be implemented because WSP does not return back a structure containing
			//			the INETAs that are already being traced... 
			break;
        case ied_xslval_wspadmin_trace_no_single_ineta:
			// Writes the amount of INETAS currently being traced. 
			adsp_out->m_writef("%u", (unsigned int)adsl_wsptrace_info->dsc_wsptrace_conf.imc_sess_no_single_ineta);
            break;

    } // end of switch
} // end of ds_xsl::m_cb_get_wspadmin_trace_data

/**
 * function: ds_xsl::m_cb_get_wspadmin_trace_booldata(int iep_type)
 * 
 * @DESC:	Gets the current WSP Trace configuration and returns a boolean indicating the status
 *				of the asked setting.
 * @param[in]   int			iep_type				ied_xslvalue of the flag to look for status in conf
 * @param[out]  boolean		bol_wsptrace_booldata   status of the required flag
*/
bool ds_xsl::m_cb_get_wspadmin_trace_booldata(ds_hvector_btype<int>* adsp_type , ds_hstack_btype<dsd_xsl_iterator>* adsp_element)
{
    // initialize some variables:
    ied_xslvalue					iedl_type = (ied_xslvalue)adsp_type->m_get_last();
	BOOL bol_wsptrace_booldata = FALSE;
	struct dsd_wsptrace_info*		adsl_wsptrace_info;
	dsd_xsl_iterator*               inl_member;


    //-----------------------------------------
    // get WSP Trace settings data from WSP:
    //-----------------------------------------

	adsl_wsptrace_info = dsc_admin.m_get_wsptrace_info();
    if ( adsl_wsptrace_info == NULL ) {
        return false;
    }

	//-----------------------------------------
    // get requested element:
    //-----------------------------------------
    inl_member = adsp_element->m_get_last_ref();
    for (int inl_i=0; inl_i<inl_member->dsc_rac.inc_cur; inl_i++ ) {
        adsl_wsptrace_info = adsl_wsptrace_info->ads_next;
    }

    //-----------------------------------------
    // Flag status:
    //-----------------------------------------
    switch ( iedl_type ) {
        case ied_xslval_wspadmin_trace_enabled:
			bol_wsptrace_booldata = adsl_wsptrace_info->dsc_wsptrace_conf.boc_allow_wsp_trace;
            break;
        case ied_xslval_wspadmin_trace_active:
			// TODO: this has to be changed in the future when a new flag indicating
			//		 whether the WSP Trace is active or not. As of today, enabled implies active.
			bol_wsptrace_booldata = adsl_wsptrace_info->dsc_wsptrace_conf.boc_allow_wsp_trace;
            break;
		case ied_xslval_wspadmin_trace_all_sessions:
			bol_wsptrace_booldata = adsl_wsptrace_info->dsc_wsptrace_conf.boc_sess_trace_ineta_all;
            break;
		case ied_xslval_wspadmin_trace_session_netw:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_sess_ia_trace_level & HL_WT_SESS_NETW);
			break;
		case ied_xslval_wspadmin_trace_session_ssl_ext:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_sess_ia_trace_level & HL_WT_SESS_SSL_EXT);
			break;
        case ied_xslval_wspadmin_trace_session_ssl_int:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_sess_ia_trace_level & HL_WT_SESS_SSL_INT);
			break;
       	case ied_xslval_wspadmin_trace_session_ssl_ocsp:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_sess_ia_trace_level & HL_WT_SESS_SSL_OCSP);
			break;
		case ied_xslval_wspadmin_trace_session_wspat3_ext:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_sess_ia_trace_level & HL_WT_SESS_WSPAT3_EXT);
			break;
		case ied_xslval_wspadmin_trace_session_wspat3_int:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_sess_ia_trace_level & HL_WT_SESS_WSPAT3_INT);
			break;
        case ied_xslval_wspadmin_trace_session_sdh_ext:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_sess_ia_trace_level & HL_WT_SESS_SDH_EXT);
			break;
        case ied_xslval_wspadmin_trace_session_sdh_int:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_sess_ia_trace_level & HL_WT_SESS_SDH_INT);
			break;
		case ied_xslval_wspadmin_trace_session_aux:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_sess_ia_trace_level & HL_WT_SESS_AUX);
			break;
		case ied_xslval_wspadmin_trace_session_misc:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_sess_ia_trace_level & HL_WT_SESS_MISC);
			break;
        case ied_xslval_wspadmin_trace_session_others:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_sess_ia_trace_level & HL_WT_SESS_OTHERS);
			break;
		case ied_xslval_wspadmin_trace_core_console:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_wsp_trace_core_flags1 & HL_WT_CORE_CONSOLE);
			break;
		case ied_xslval_wspadmin_trace_core_cluster:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_wsp_trace_core_flags1 & HL_WT_CORE_CLUSTER);
			break;
		case ied_xslval_wspadmin_trace_core_udp:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_wsp_trace_core_flags1 & HL_WT_CORE_UDP);
			break;
		case ied_xslval_wspadmin_trace_core_dod:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_wsp_trace_core_flags1 & HL_WT_CORE_DOD);
			break;
		case ied_xslval_wspadmin_trace_core_radius:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_wsp_trace_core_flags1 & HL_WT_CORE_RADIUS);
			break;
		case ied_xslval_wspadmin_trace_core_virus_ch:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_wsp_trace_core_flags1 & HL_WT_CORE_VIRUS_CH);
			break;
		case ied_xslval_wspadmin_trace_core_hob_tun:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_wsp_trace_core_flags1 & HL_WT_CORE_HOB_TUN);
			break;
		case ied_xslval_wspadmin_trace_core_ldap:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_wsp_trace_core_flags1 & HL_WT_CORE_LDAP);
			break;
        case ied_xslval_wspadmin_trace_core_krb5:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_wsp_trace_core_flags1 & HL_WT_CORE_KRB5);
			break;
        case ied_xslval_wspadmin_trace_core_ms_rpc:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_wsp_trace_core_flags1 & HL_WT_CORE_MS_RPC);
			break;
		case ied_xslval_wspadmin_trace_core_admin:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_wsp_trace_core_flags1 & HL_WT_CORE_ADMIN);
			break;
		case ied_xslval_wspadmin_trace_core_ligw:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_wsp_trace_core_flags1 & HL_WT_CORE_LIGW);
			break;
        case ied_xslval_wspadmin_trace_core_others:
			bol_wsptrace_booldata = (adsl_wsptrace_info->dsc_wsptrace_conf.imc_wsp_trace_core_flags1 & HL_WT_CORE_OTHERS);
			break;
	} // End of switch

	return (bol_wsptrace_booldata)?true:false;
} // End of bool ds_xsl::m_cb_get_wspadmin_trace_booldata(int iep_type)

/**
 * function ds_xsl::m_cb_get_wspadmin_session_data
 * get data from wspadmin session subgroup to insert in xsl
 * 
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_type        value type vector
 * @param[out]  ds_hstring*     ads_out         output buffer
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_element     element counter for "for-each" loop
*/
void ds_xsl::m_cb_get_wspadmin_session_data( ds_hvector_btype<int>* ads_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element )
{
    // initialize some variables:
    ied_xslvalue      ied_type = (ied_xslvalue)ads_type->m_get_last();
    dsd_session_info* ads_wsp_session;                  // session list
    dsd_xsl_iterator* adsl_member;

    //-----------------------------------------
    // get session list from wsp:
    //-----------------------------------------
    ads_wsp_session = dsc_admin.m_get_session_info();
    if ( ads_wsp_session == NULL ) {
        return;
    }

    //-----------------------------------------
    // get requested element:
    //-----------------------------------------
    adsl_member = ads_element->m_get_last_ref();
    for( int inl_i=0; inl_i<adsl_member->dsc_rac.inc_cur; inl_i++ ) {
        ads_wsp_session = ads_wsp_session->ads_next;
    }

    //-----------------------------------------
    // print data:
    //-----------------------------------------
    switch ( ied_type ) {
        case ied_xslval_wspadmin_session_gate_name:
            ads_out->m_write_html_text( ads_wsp_session->ach_gate_name,
                              ads_wsp_session->ds_sess_info.imc_len_gate_name );
            break;

        case ied_xslval_wspadmin_session_svr_entry:
            ads_out->m_write_html_text( ads_wsp_session->ach_serv_entry,
                              ads_wsp_session->ds_sess_info.imc_len_serv_ent );
            break;

        case ied_xslval_wspadmin_session_proto:
            ads_out->m_write_html_text( ads_wsp_session->ach_protocol,
                              ads_wsp_session->ds_sess_info.imc_len_protocol );
            break;

        case ied_xslval_wspadmin_session_srv_ip_port:
            short int is_port;
            if ( ads_wsp_session->ds_sess_info.imc_len_ineta_port > 2 ) {
                /*
                    we take the last 2 bytes as port number!
                */
                memcpy( &is_port,
                        &ads_wsp_session->ach_server_ineta[ads_wsp_session->ds_sess_info.imc_len_ineta_port - 2],
                        2 );
            } else {
                is_port = 0;
            }

            if ( ads_wsp_session->ds_sess_info.imc_len_ineta_port == 6 ) {
                /*
                    IPv4 with port (4+2 bytes)
                */
                ads_out->m_writef( "%u.%u.%u.%u:%d",
                                   (unsigned char)ads_wsp_session->ach_server_ineta[0],
                                   (unsigned char)ads_wsp_session->ach_server_ineta[1],
                                   (unsigned char)ads_wsp_session->ach_server_ineta[2],
                                   (unsigned char)ads_wsp_session->ach_server_ineta[3],
                                   is_port );
            } else if ( ads_wsp_session->ds_sess_info.imc_len_ineta_port == 18 ) {
                /*
                    IPv6 with port (16+2 bytes)
                */
                ads_out->m_writef( "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:[%d]",
                                   (unsigned char)ads_wsp_session->ach_server_ineta[ 0],
                                   (unsigned char)ads_wsp_session->ach_server_ineta[ 1],
                                   (unsigned char)ads_wsp_session->ach_server_ineta[ 2],
                                   (unsigned char)ads_wsp_session->ach_server_ineta[ 3],
                                   (unsigned char)ads_wsp_session->ach_server_ineta[ 4],
                                   (unsigned char)ads_wsp_session->ach_server_ineta[ 5],
                                   (unsigned char)ads_wsp_session->ach_server_ineta[ 6],
                                   (unsigned char)ads_wsp_session->ach_server_ineta[ 7],
                                   (unsigned char)ads_wsp_session->ach_server_ineta[ 8],
                                   (unsigned char)ads_wsp_session->ach_server_ineta[ 9],
                                   (unsigned char)ads_wsp_session->ach_server_ineta[10],
                                   (unsigned char)ads_wsp_session->ach_server_ineta[11],
                                   (unsigned char)ads_wsp_session->ach_server_ineta[12],
                                   (unsigned char)ads_wsp_session->ach_server_ineta[13],
                                   (unsigned char)ads_wsp_session->ach_server_ineta[14],
                                   (unsigned char)ads_wsp_session->ach_server_ineta[15],
                                   is_port );
            }
            break;

        case ied_xslval_wspadmin_session_number:
            ads_out->m_writef( "%d", ads_wsp_session->ds_sess_info.imc_session_no );
            break;

        case ied_xslval_wspadmin_session_clt_ip:
            ads_out->m_write_zeroterm( ads_wsp_session->ds_sess_info.chrc_ineta );
            break;

        case ied_xslval_wspadmin_session_time_started:
            ads_out->m_writef( "%d", ads_wsp_session->ds_sess_info.imc_time_start );
            break;

        case ied_xslval_wspadmin_session_no_rec_clt:
            ads_out->m_writef( "%d", ads_wsp_session->ds_sess_info.imc_c_ns_rece_c );
            break;

        case ied_xslval_wspadmin_session_no_snd_clt:
            ads_out->m_writef( "%d", ads_wsp_session->ds_sess_info.imc_c_ns_send_c );
            break;

        case ied_xslval_wspadmin_session_no_rec_srv:
            ads_out->m_writef( "%d", ads_wsp_session->ds_sess_info.imc_c_ns_rece_s );
            break;

        case ied_xslval_wspadmin_session_no_snd_srv:
            ads_out->m_writef( "%d", ads_wsp_session->ds_sess_info.imc_c_ns_send_s );
            break;

        case ied_xslval_wspadmin_session_no_rec_crypt:
            ads_out->m_writef( "%d", ads_wsp_session->ds_sess_info.imc_c_ns_rece_e );
            break;

        case ied_xslval_wspadmin_session_no_snd_crypt:
            ads_out->m_writef( "%d", ads_wsp_session->ds_sess_info.imc_c_ns_send_e );
            break;

        case ied_xslval_wspadmin_session_dt_rec_clt:
            //ads_out->m_writef( "%lld", ads_wsp_session->ds_sess_info.ilc_d_ns_rece_c );
            m_cb_print_bytes( ads_out, ads_wsp_session->ds_sess_info.ilc_d_ns_rece_c );
            break;

        case ied_xslval_wspadmin_session_dt_snd_clt:
            //ads_out->m_writef( "%lld", ads_wsp_session->ds_sess_info.ilc_d_ns_send_c );
            m_cb_print_bytes( ads_out, ads_wsp_session->ds_sess_info.ilc_d_ns_send_c );
            break;

        case ied_xslval_wspadmin_session_dt_rec_srv:
            //ads_out->m_writef( "%lld", ads_wsp_session->ds_sess_info.ilc_d_ns_rece_s );
            m_cb_print_bytes( ads_out, ads_wsp_session->ds_sess_info.ilc_d_ns_rece_s );
            break;

        case ied_xslval_wspadmin_session_dt_snd_srv:
            //ads_out->m_writef( "%lld", ads_wsp_session->ds_sess_info.ilc_d_ns_send_s );
            m_cb_print_bytes( ads_out, ads_wsp_session->ds_sess_info.ilc_d_ns_send_s );
            break;

        case ied_xslval_wspadmin_session_dt_rec_crypt:
            //ads_out->m_writef( "%lld", ads_wsp_session->ds_sess_info.ilc_d_ns_rece_e );
            m_cb_print_bytes( ads_out, ads_wsp_session->ds_sess_info.ilc_d_ns_rece_e );
            break;

        case ied_xslval_wspadmin_session_dt_snd_crypt:
            //ads_out->m_writef( "%lld", ads_wsp_session->ds_sess_info.ilc_d_ns_send_e );
            m_cb_print_bytes( ads_out, ads_wsp_session->ds_sess_info.ilc_d_ns_send_e );
            break;

        case ied_xslval_wspadmin_session_cert_name:
            ads_out->m_write_html_text( ads_wsp_session->ach_cert_name,
                              ads_wsp_session->ds_sess_info.imc_len_name_cert );
            break;

        case ied_xslval_wspadmin_session_user_name:
            ads_out->m_write_html_text( ads_wsp_session->ach_user,
                              ads_wsp_session->ds_sess_info.imc_len_userid );
            break;

        case ied_xslval_wspadmin_session_user_group:
            ads_out->m_write_html_text( ads_wsp_session->ach_group,
                              ads_wsp_session->ds_sess_info.imc_len_user_group );
            break;

        case ied_xslval_wspadmin_session_cur_handle:
            ads_out->m_writef( "%lld", ads_wsp_session->dsc_wsp.ilc_handle );
            break;

        case ied_xslval_wspadmin_session_cur_srv_name:
            ads_out->m_write_html_text( ads_wsp_session->dsc_wsp.achc_srv_name,
                              ads_wsp_session->dsc_wsp.inc_len_srv_name );
            break;
    } // end of switch
} // end of ds_xsl::m_cb_get_wspadmin_session_data


/**
 * function ds_xsl::m_cb_get_wspadmin_listen_data
 * get data from wspadmin listen subgroup to insert in xsl
 * 
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_type        value type vector
 * @param[out]  ds_hstring*     ads_out         output buffer
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_element     element counter for "for-each" loop
*/
void ds_xsl::m_cb_get_wspadmin_listen_data( ds_hvector_btype<int>* ads_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element )
{
    if ( ads_type->m_size() < 3 ) {
        return;
    }
    // initialize some variables:
    ied_xslvalue      ied_type = (ied_xslvalue)ads_type->m_get(2);
    dsd_listen*       ads_listen;                           // listen list
    dsd_xsl_iterator*     adsl_member;

    //-----------------------------------------
    // get listen list from wsp:
    //-----------------------------------------
    ads_listen = dsc_admin.m_get_listen_info();
    if ( ads_listen == NULL ) {
        return;
    }

    //-----------------------------------------
    // get requested element:
    //-----------------------------------------
    adsl_member = ads_element->m_get_last_ref();
    ads_listen = (dsd_listen*)adsl_member->dsc_fwd.avoc_cur;

    //-----------------------------------------
    // print data:
    //-----------------------------------------
    switch ( ied_type ) {
        case ied_xslval_wspadmin_listen_gate_name:
            ads_out->m_write_html_text( ads_listen->ach_gate_name,
                              ads_listen->ds_main.imc_len_gate_name );
            break;

        case ied_xslval_wspadmin_listen_tm_conf_loaded:
            ads_out->m_writef( "%d", ads_listen->ds_main.imc_epoch_conf_loaded );
            break;

        case ied_xslval_wspadmin_listen_active_conf:
            m_cb_print_bool( ads_out, (ads_listen->ds_main.boc_active_conf == TRUE)?true:false );
            break;

        case ied_xslval_wspadmin_listen_use_listen_gateway:
            m_cb_print_bool( ads_out, (ads_listen->ds_main.boc_use_listen_gw == TRUE)?true:false );
            break;

        case ied_xslval_wspadmin_listen_port:
            ads_out->m_writef( "%d", ads_listen->ds_main.imc_gateport );
            break;

        case ied_xslval_wspadmin_listen_backlog:
            ads_out->m_writef( "%d", ads_listen->ds_main.imc_backlog );
            break;

        case ied_xslval_wspadmin_listen_timeout:
            ads_out->m_writef( "%d", ads_listen->ds_main.imc_timeout );
            break;

        case ied_xslval_wspadmin_listen_threshold:
            ads_out->m_writef( "%d", ads_listen->ds_main.imc_thresh_session );
            break;

        case ied_xslval_wspadmin_listen_over_threshold:
            m_cb_print_bool( ads_out, (ads_listen->ds_main.boc_cur_thresh_session == TRUE)?true:false );
            break;

        case ied_xslval_wspadmin_listen_tm_last_threshold:
            ads_out->m_writef( "%d", ads_listen->ds_main.imc_epoch_thresh_se_notify );
            break;

        case ied_xslval_wspadmin_listen_max_sessions:
            ads_out->m_writef( "%d", ads_listen->ds_main.imc_session_max );
            break;

        case ied_xslval_wspadmin_listen_start_session:
            ads_out->m_writef( "%d", ads_listen->ds_main.imc_session_cos );
            break;

        case ied_xslval_wspadmin_listen_current_sessions:
            ads_out->m_writef( "%d", ads_listen->ds_main.imc_session_cur );
            break;

        case ied_xslval_wspadmin_listen_max_sessions_reached:
            ads_out->m_writef( "%d", ads_listen->ds_main.imc_session_mre );
            break;

        case ied_xslval_wspadmin_listen_max_sessions_exceeded:
            ads_out->m_writef( "%d", ads_listen->ds_main.imc_session_exc );
            break;

        case ied_xslval_wspadmin_listen_cur_handle:
            ads_out->m_writef( "%lld", ads_listen->dsc_wsp.ilc_handle );
            break;

        case ied_xslgrp_wspadmin_listen_ineta:
            m_cb_get_wspadmin_listen_ineta_data( ads_type, ads_out, ads_element );
            break;
    } // end of switch
} // end of ds_xsl::m_cb_get_wspadmin_listen_data


/**
 * function ds_xsl::m_cb_get_wspadmin_listen_ineta_data
 * get data from wspadmin listen ineta subsubgroup to insert in xsl
 * 
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_type        value type vector
 * @param[out]  ds_hstring*     ads_out         output buffer
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_element     element counter for "for-each" loop
*/
void ds_xsl::m_cb_get_wspadmin_listen_ineta_data( ds_hvector_btype<int>* ads_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element )
{
    // initialize some variables:
    ied_xslvalue      ied_type = (ied_xslvalue)ads_type->m_get_last();
    dsd_listen*       ads_listen;                           // listen list
    dsd_each_listen*  ads_each;                             // each listen list
    dsd_xsl_iterator* adsl_member;
    int               in_pos;

    //-----------------------------------------
    // get listen list from wsp:
    //-----------------------------------------
    ads_listen = dsc_admin.m_get_listen_info();
    if ( ads_listen == NULL ) {
        return;
    }
    
    //-----------------------------------------
    // get requested listen element:
    //-----------------------------------------
    //adsl_member = ads_element->m_get(ads_element->m_size() - 2);
    adsl_member = ads_element->m_get_prev_last_ref();

    for ( in_pos = 0; in_pos < adsl_member->dsc_rac.inc_cur; in_pos ++ ) {
        ads_listen = ads_listen->ads_next;
        if ( ads_listen == NULL ) {
            return;
        }
    }
    
    //-----------------------------------------
    // get requested ineta listen element:
    //-----------------------------------------
    ads_each = ads_listen->ads_each;
    if ( ads_each == NULL ) {
        return;
    }
    adsl_member = ads_element->m_get_last_ref();

    for ( in_pos = 0; in_pos < adsl_member->dsc_rac.inc_cur; in_pos ++ ) {
        ads_each = ads_each->ads_next;
        if ( ads_each == NULL ) {
            return;
        }
    }

    //-----------------------------------------
    // print data:
    //-----------------------------------------
    switch ( ied_type ) {
        case ied_xslval_wspadmin_listen_ineta_active:
            m_cb_print_bool( ads_out, (ads_each->ds_ineta.boc_listen_active==TRUE)?true:false );
            break;

        case ied_xslval_wspadmin_listen_ineta_ip_address:
            ads_out->m_write_html_text( ads_each->ach_ineta,
                              ads_each->ds_ineta.imc_len_ineta );
            break;
    } // end of switch
} // end of ds_xsl::m_cb_get_wspadmin_listen_ineta_data


/**
 * function ds_xsl::m_cb_get_wspadmin_perf_data
 * get data from wspadmin performance subgroup to insert in xsl
 * 
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_type        value type vector
 * @param[out]  ds_hstring*     ads_out         output buffer
*/
void ds_xsl::m_cb_get_wspadmin_perf_data( ds_hvector_btype<int>* ads_type, ds_hstring* ads_out )
{
    // initialize some variables:
    ied_xslvalue      ied_type = (ied_xslvalue)ads_type->m_get_last();
    dsd_perfdata*     ads_perfdata;                           // performace list

    //-----------------------------------------
    // get performance data from wsp:
    //-----------------------------------------
    ads_perfdata = dsc_admin.m_get_perf_info();
    if ( ads_perfdata == NULL ) {
        return;
    }

    //-----------------------------------------
    // print data:
    //-----------------------------------------
    switch ( ied_type ) {
        case ied_xslval_wspadmin_perf_used_cpu_time:
            break;

        case ied_xslval_wspadmin_perf_used_memory:
            break;

        case ied_xslval_wspadmin_perf_network_data:
            break;

        case ied_xslval_wspadmin_perf_loadbalancing:
            break;

        case ied_xslval_wspadmin_perf_cur_handle:
            ads_out->m_writef( "%lld", ads_perfdata->dsc_wsp.ilc_handle );
            break;
    } // end of switch
} // end of ds_xsl::m_cb_get_wspadmin_perf_data


/**
 * function ds_xsl::m_cb_get_wspadmin_log_data
 * get data from wspadmin logfile subgroup to insert in xsl
 * 
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_type        value type vector
 * @param[out]  ds_hstring*     ads_out         output buffer
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_element     element counter for "for-each" loop
*/
void ds_xsl::m_cb_get_wspadmin_log_data( ds_hvector_btype<int>* ads_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element )
{
    // initialize some variables:
    ied_xslvalue      ied_type = (ied_xslvalue)ads_type->m_get_last();
    dsd_log_info*     ads_loginfo;                              // logfile list
    dsd_xsl_iterator* adsl_member;
    ds_hstring        dsl_message( ads_wsp_helper );

    //-----------------------------------------
    // get logfile data from wsp:
    //-----------------------------------------
    ads_loginfo = dsc_admin.m_get_log_info();
    if ( ads_loginfo == NULL ) {
        return;
    }

    //-----------------------------------------
    // get requested element:
    //-----------------------------------------
    adsl_member = ads_element->m_get_last_ref();
    for( int inl_i=0; inl_i<adsl_member->dsc_rac.inc_cur; inl_i++ ) {
        ads_loginfo = ads_loginfo->ads_next;
    }

    //-----------------------------------------
    // print data:
    //-----------------------------------------
    switch ( ied_type ) {
        case ied_xslval_wspadmin_log_position:
            ads_out->m_writef( "%lld", ads_loginfo->ds_main.ilc_position );
            break;

        case ied_xslval_wspadmin_log_filled:
            ads_out->m_writef( "%d", ads_loginfo->ds_main.imc_count_filled );
            break;

        case ied_xslval_wspadmin_log_timestamp:
            ads_out->m_writef( "%lld", ads_loginfo->ds_main.ilc_epoch );
            break;

        case ied_xslval_wspadmin_log_message:
            ads_out->m_write_html_text( dsd_const_string(ads_loginfo->ach_message,
                                 ads_loginfo->ds_main.imc_len_msg) );
            break;

        case ied_xslval_wspadmin_log_cur_handle:
            ads_out->m_writef( "%lld", ads_loginfo->dsc_wsp.ilc_handle );
            break;
            
        case ied_xslval_wspadmin_log_cur_srv_name:
            ads_out->m_write_html_text( dsd_const_string(ads_loginfo->dsc_wsp.achc_srv_name,
                              ads_loginfo->dsc_wsp.inc_len_srv_name) );
            break;

        case ied_xslval_wspadmin_log_cur_conf_name:
            ads_out->m_write_html_text( dsd_const_string(ads_loginfo->dsc_wsp.achc_wsp_name,
                              ads_loginfo->dsc_wsp.inc_len_wsp_name) );
            break;
    } // end of switch
} // end of ds_xsl::m_cb_get_wspadmin_log_data


/**
 * function ds_xsl::m_cb_get_wspadmin_user_data
 * get data from wspadmin user subgroup to insert in xsl
 * 
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_type        value type vector
 * @param[out]  ds_hstring*     ads_out         output buffer
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_element     element counter for "for-each" loop
*/
void ds_xsl::m_cb_get_wspadmin_user_data( ds_hvector_btype<int>* ads_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element )
{
    // initialize some variables:
    ied_xslvalue       ied_type = (ied_xslvalue)ads_type->m_get_last();
    dsd_xsl_iterator*  adsl_member;
    dsd_user_overview* ads_userov;

    //-----------------------------------------
    // get user data authentication class:
    //-----------------------------------------
    dsd_query_uov_t dsl_user_query;
    m_fill_user_query( &dsl_user_query );
    ads_userov = dsc_auth.m_get_userov( &dsl_user_query );
    if ( ads_userov == NULL ) {
        return;
    }

    //-----------------------------------------
    // get requested element:
    //-----------------------------------------
    adsl_member = ads_element->m_get_last_ref();
    for( int inl_i=0; inl_i<adsl_member->dsc_rac.inc_cur; inl_i++ ) {
        ads_userov = ads_userov->ads_next;
    }

    //-----------------------------------------
    // print data:
    //-----------------------------------------
    switch ( ied_type ) {
        case ied_xslval_wspadmin_user_number:
            ads_out->m_writef( "%d", ads_userov->inc_number );
            break;

        case ied_xslval_wspadmin_user_name:
            ads_out->m_write_html_text( ads_userov->ds_user.dsc_username.m_get_ptr(), 
                              ads_userov->ds_user.dsc_username.m_get_len() );
            break;

        case ied_xslval_wspadmin_user_domain:
            ads_out->m_write_html_text( ads_userov->ds_user.dsc_userdomain.m_get_ptr(), 
                              ads_userov->ds_user.dsc_userdomain.m_get_len() );
            break;

        case ied_xslval_wspadmin_user_wspgroup:
            ads_out->m_write_html_text( ads_userov->ds_user.dsc_wspgroup.m_get_ptr(), 
                              ads_userov->ds_user.dsc_wspgroup.m_get_len() );
            break;

        case ied_xslval_wspadmin_user_role:
            ads_out->m_write_html_text( ads_userov->ds_user.dsc_role.m_get_ptr(),
                              ads_userov->ds_user.dsc_role.m_get_len() );
            break;

        case ied_xslval_wspadmin_user_logged_in:
            ads_out->m_writef( "%lld", ads_userov->ds_user.tmc_login );
            break;

        case ied_xslval_wspadmin_user_ineta:
            m_cb_print_ineta( ads_out, ads_userov->ds_user.dsc_client );
            break;

        case ied_xslval_wspadmin_user_session:
			  ads_out->m_writef( "%d", (int)ads_userov->ds_user.chc_session.ucc_session_no );
            break;
    } // end of switch
} // end of ds_xsl::m_cb_get_wspadmin_user_data


/**
 * function ds_xsl::m_split_value
 * 
 * @param[in]   char*           ach_value       request value
 * @param[in]   int             in_len_val      length of request value
 * @param[in]   int*            ain_pos         position to start
*/
void ds_xsl::m_split_value( const char* ach_value, int in_len_value, int* ain_pos )
{
    if ( ach_value[*ain_pos] == '/') {
        (*ain_pos)++;
    }
    for ( ; *ain_pos < in_len_value; (*ain_pos)++ ) {
        if ( ach_value[*ain_pos] == '/' ) {
            break;
        }
    }
} // end of ds_xsl::m_split_value


/**
 * function ds_xsl::m_is_not
 * check if value is a "not(...)" value
 * if true remove the "not" (and it's brackets) from value, return true
 * else keep value as is and return false
 * 
 * @param[in]   char**          aach_value      pointet request value
 * @param[in]   int*            ain_len_val     pointer to length of request value
 * @return      bool                            true = not in value
 *                                              false otherwise
*/
bool ds_xsl::m_is_not( const char** aach_value, int* ain_len_val )
{
    // check for minimal length:
    dsd_const_string dsl_value(*aach_value, *ain_len_val);
    dsd_const_string dsl_key_reverse(XSL_KEY_REVERSE);
    if(dsl_value.m_starts_with_ic(dsl_key_reverse)
        && dsl_value.m_ends_with(")"))
    {
        // move value pointer:
        *aach_value = &(*aach_value)[dsl_key_reverse.m_get_len()];
        *ain_len_val -= (int)(dsl_key_reverse.m_get_len() + 1);
        return true;
    }
    return false;
} // end of ds_xsl::m_is_not


/**
 * function ds_xsl::m_is_compare
 * check if value contains a compare
 * (right now members of 'achr_xsl_compare' are supported)
 * if true remove the compare from value
 * else keep value as is
 * 
 * @param[in]       char*       ach_value       request value
 * @param[in]       int*        ain_len_val     pointer to length of request value
 * @param[in/out]   int*        ain_cmp_to      compare value (if number)
 * @param[in/out]   ds_hstring* adsp_comp       compare value (if string)
 * @return          bool                        true = value
 *                                              false otherwise
*/
ied_xsl_compare ds_xsl::m_is_compare( const char* ach_value, int* ain_len_val,
                                      int* ain_cmp_to, ds_hstring* adsp_comp )
{
    // initialize some variables:
    int             in_pos;                             // working position in value
    int             in_end;                             // end position of compare sign
    int             in_new_len;                         // new length of value
    int             inl_temp;                           // temp compare value

    //---------------------------------------------
    // get first whitespace:
    //---------------------------------------------
    dsd_const_string dsl_value(ach_value, *ain_len_val);
    in_pos = dsl_value.m_find_first_of(" \n\r\t");
    if(in_pos < 0)
        return ied_xsl_cmp_not_set;
    in_new_len = in_pos;
    //---------------------------------------------
    // pass following whitespaces:
    //---------------------------------------------
    in_pos = dsl_value.m_find_first_not_of(" \n\r\t", in_pos+1);
    if(in_pos < 0)
        return ied_xsl_cmp_not_set;
    //---------------------------------------------
    // get next whitespace:
    //---------------------------------------------
    in_end = dsl_value.m_find_first_of(" \n\r\t", in_pos+1);
    if(in_end < 0)
        return ied_xsl_cmp_not_set;

    //---------------------------------------------
    // loop through all groups:
    //---------------------------------------------
    dsd_unicode_string dsl_key;
    dsl_key.ac_str = (char*)&ach_value[in_pos];
    dsl_key.imc_len_str = in_end - in_pos;
    dsl_key.iec_chs_str = dsc_parser.m_get_encoding();
    ied_xsl_compare ien_cmp = ds_wsp_helper::m_search_equals_ic2(achr_xsl_compare, dsl_key, ied_xsl_cmp_not_set);   // return value
    // have we found an entry:
    if ( ien_cmp == ied_xsl_cmp_not_set ) {
        return ied_xsl_cmp_not_set;
    }
    
    //---------------------------------------------
    // pass following whitespaces:
    //---------------------------------------------
    in_end = dsl_value.m_find_first_not_of(" \n\r\t", in_end+1);
    if(in_end < 0)
        return ied_xsl_cmp_not_set;

    //---------------------------------------------
    // get compare value and set new length:
    //---------------------------------------------
    adsp_comp->m_write( &ach_value[in_end], *ain_len_val - in_end );
    if ( adsp_comp->m_conv_int( &inl_temp ) == true ) {
        *ain_cmp_to = inl_temp;
        adsp_comp->m_reset();
    }
    *ain_len_val = in_new_len;

    return ien_cmp;
} // end of ds_xsl::m_is_compare


/**
 * function ds_xsl::m_get_encoding
 * check if value contains an encoding directive
 * (right now members of 'achr_xsl_value_encodings' are supported)
 * if true remove the encoding from value, else keep value as is
 * 
 * @param[in]       char*       ach_value       request value
 * @param[in]       int*        ain_len_val     pointer to length of request value
 * @return          ied_xsl_value_encoding      the parsed encoding, default (html) if not specified
*/
ied_xsl_value_encoding ds_xsl::m_get_encoding(const char* ach_value, int* ain_len_val) {
    dsd_const_string dsl_value(ach_value, *ain_len_val);
    int in_pos = dsl_value.m_find_first_of(" \n\r\t");
    if(in_pos < 0)
        return ied_xsl_enc_html;
    int inl_new_len = in_pos;

    int in_end = dsl_value.m_find_first_not_of(" \n\r\t", in_pos+1);
    if(in_end < 0)
        return ied_xsl_enc_html;
    if(dsl_value.m_substring(in_end).m_starts_with(XSL_ENCODING)) {
        in_pos = in_end + strlen(XSL_ENCODING);
        in_end = dsl_value.m_find_first_of(" \n\r\t", in_pos);
        if(in_end < 0)
            in_end = *ain_len_val;
        dsd_unicode_string dsl_key;
        dsl_key.ac_str = (char*)&ach_value[in_pos];
        dsl_key.imc_len_str = in_end - in_pos;
        dsl_key.iec_chs_str = dsc_parser.m_get_encoding();
        ied_xsl_value_encoding iel_enc = ds_wsp_helper::m_search_equals2(achr_xsl_value_encodings, dsl_key, ied_xsl_enc_unknown);

        *ain_len_val = inl_new_len;
        return iel_enc;
    } else {
        return ied_xsl_enc_unknown; //parse error
    }
}


/**
 * function ds_xsl::m_pass_ws
 * pass whitespaces
 *
 * @param[in]   char*   ach_data
 * @param[in]   int     in_len
 * @parma[in]   int*    ain_pos
*/
void ds_xsl::m_pass_ws( const char* ach_data, int in_len, int* ain_pos )
{
    for ( ; *ain_pos < in_len; (*ain_pos)++ ) {
        switch ( ach_data[*ain_pos] ) {
            case ' ':
            case '\n':
            case '\r':
            case '\t':
                continue;
            default:
                break;
        }
        break;
    }
} // end of ds_xsl::m_pass_ws


/**
 * function ds_xsl::m_get_type
 * 
 * @param[out]   ds_hvector*     ads_type        type vector
 * @param[in]   char*           ach_value       request value
 * @param[in]   int             in_len_val      length of request value
*/
void ds_xsl::m_get_type( ds_hvector_btype<int>* ads_type, const char* ach_value, int in_len_val )
{
    // initialize some variables:
    int            in_group        = 0;                     // found group in dsr_xslvalues
    int            in_size         = 0;                     // number of elements
    int            in_value        = 1;                     // value from group
    ied_xslvalue   ied_type        = ied_xslval_unknown;    // type of value
    int            in_start_gr     = 0;                     // start point of group
    int            in_len_gr       = 0;                     // length of group in value
    dsd_xsl_group* ads_current_grp = NULL;                  // current sub group

    if(!ads_type->m_empty())
        throw std::exception(/**"bad state"**/);

    //---------------------------------------------
    // get main list:
    //---------------------------------------------
    ads_current_grp = (dsd_xsl_group*)&dsr_xslvalues[0];
    in_size         = (int)(sizeof(dsr_xslvalues)/sizeof(dsd_xsl_group));

    m_split_value( ach_value, in_len_val, &in_len_gr );

    dsd_unicode_string dsl_value;
    dsl_value.ac_str = (void*)ach_value;
    dsl_value.imc_len_str = in_len_val;
    dsl_value.iec_chs_str = dsc_parser.m_get_encoding();

    //---------------------------------------------
    // there is no subgroup given:
    //---------------------------------------------
    if ( in_len_gr == in_len_val ) {
        // loop through all groups:
        for ( in_group = 0; in_group < in_size; in_group++ ) {
            if ( ads_current_grp->dsc_group_name.strc_name.m_equals_ic(dsl_value) ) {
                // save group type:
                ied_type = ads_current_grp->dsc_group_name.iec_enum_value;
                ads_type->m_add( ied_type );
                break;
            }
            if ( in_group < in_size - 1 ) {
                ads_current_grp++;
            }
        }
    }

    //---------------------------------------------
    // get subgroups:
    //---------------------------------------------
    while ( in_len_gr < in_len_val ) {
        dsd_unicode_string dsl_value_gr;
        dsl_value_gr.ac_str = (void*)&ach_value[in_start_gr];
        dsl_value_gr.imc_len_str = in_len_gr - in_start_gr;
        dsl_value_gr.iec_chs_str = dsc_parser.m_get_encoding();

        // loop through all groups:
        for ( in_group = 0; in_group < in_size; in_group++ ) {
            if ( ads_current_grp->dsc_group_name.strc_name.m_equals_ic(dsl_value_gr) ) {
                // save group type:
                ied_type = ads_current_grp->dsc_group_name.iec_enum_value;
                ads_type->m_add( ied_type );

                // save start of previous group:
                in_start_gr = in_len_gr + 1;

                // get next group name:
                m_split_value( ach_value, in_len_val, &in_len_gr );

                // in case of language/query, quit this loop!
                if ( ied_type == ied_xslgrp_lang || ied_type == ied_xslgrp_query) {
                    in_len_gr = in_len_val;
                }

                // get next element:
                if ( in_len_gr < in_len_val ) {
                    in_size         = ads_current_grp->in_no_groups;
                    ads_current_grp = (dsd_xsl_group*)ads_current_grp->ads_subgroup;
                }
                goto LBL_FOUND;
            }
            if ( in_group < in_size - 1 ) {
                ads_current_grp++;
            }
        }
        //-----------------------------------------
        // check if value was found in this run:
        //-----------------------------------------
        break;
LBL_FOUND:
        ;
    }

    dsd_unicode_string dsl_value_gr;
    dsl_value_gr.ac_str = (void*)&ach_value[in_start_gr];
    dsl_value_gr.imc_len_str = in_len_val - in_start_gr;
    dsl_value_gr.iec_chs_str = dsc_parser.m_get_encoding();
    //---------------------------------------------
    // get type of value:
    //---------------------------------------------
    if (    ied_type != ied_xslval_unknown /* unknown value */
         && ied_type != ied_xslgrp_lang  && ied_type != ied_xslgrp_query    /* language/query group */ ) {
        /*
            there are two posibilities:
            -> we have a value itself
            -> we have a subgroup itself
        */

        // loop through all child elements:
        for ( in_value = 0; in_value < ads_current_grp->in_no_childs; in_value++ ) {
            if ( ads_current_grp->adsc_childs[in_value].strc_name.m_equals_ic(dsl_value_gr) ) {
                ied_type = ads_current_grp->adsc_childs[in_value].iec_enum_value;
                ads_type->m_add( ied_type );
                break;
            }
        }
        
        // if nothing was found -> loop through subgroups:
        if ( in_value >= ads_current_grp->in_no_childs ) {
            in_size         = ads_current_grp->in_no_groups;
            ads_current_grp = (dsd_xsl_group*)ads_current_grp->ads_subgroup;

            for ( in_group = 0; in_group < in_size; in_group++ ) {
                /*bo_ret = m_cmpi_vx_vx( &in_compare,
                                       (char*)&ach_value[in_start_gr],
                                       in_len_gr - in_start_gr,
                                       dsc_parser.m_get_encoding(),
                                       (void*)ads_current_grp->ach_name,
                                       (int)strlen(ads_current_grp->ach_name),
                                       ied_chs_utf_8 );
                */
                if ( ads_current_grp->dsc_group_name.strc_name.m_equals_ic(dsl_value_gr) ) {
                    // save group type:
                    ied_type = ads_current_grp->dsc_group_name.iec_enum_value;
                    ads_type->m_add( ied_type );
                    break;
                }
                if ( in_group < in_size - 1 ) {
                    ads_current_grp++;
                }
            }
        }
    }

    return;
} // end of ds_xsl::m_get_type

#if u_think_this_stupid_check_makes_sense
/**
 * function ds_xsl::m_is_group
 * decide if given type is a group
 *
 * @param[in]   int         in_type
 *
 * @return      bool          
*/
bool ds_xsl::m_is_group( int in_type )
{
    if ( in_type%D_SUB_GROUP_DIV == 0 ) {
        return true;
    }
    return false;
} // end of ds_xsl::m_is_group
#endif

/**
 * function ds_xsl::m_cb_print_bool
 *
 * @param[in]   ds_hstring*     ads_out     output buffer
 * @param[in]   bool            bo_value
*/
void ds_xsl::m_cb_print_bool( ds_hstring* ads_out, bool bo_value )
{
    // initialize some variables:
    const char*   ach_value = NULL;
    int     in_len;

    if ( bo_value == true ) {
        GET_RES( XSL_RES_YES, ach_value, in_len );
    } else {
        GET_RES( XSL_RES_NO, ach_value, in_len );
    }

    ads_out->m_write( ach_value, in_len );
} // end of ds_xsl::m_cb_print_bool


/**
 * function ds_xsl::m_cb_print_ineta
 *
 * @param[in]   ds_hstring*     ads_out                         output buffer
 * @param[in]   unsigned char   uchr_client_ineta[LEN_INETA]    ineta
*/
void ds_xsl::m_cb_print_ineta( ds_hstring* ads_out, struct dsd_aux_query_client ds_client )
{
    switch ( ds_client.inc_addr_family ) {
        case AF_INET:
            // IPv4:
            ads_out->m_writef( "%u.%u.%u.%u", (unsigned char)ds_client.chrc_client_ineta[0],
                                              (unsigned char)ds_client.chrc_client_ineta[1],
                                              (unsigned char)ds_client.chrc_client_ineta[2],
                                              (unsigned char)ds_client.chrc_client_ineta[3] );
            break;
        default:
            ads_out->m_writef( "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                               (unsigned char)ds_client.chrc_client_ineta[ 0],
                               (unsigned char)ds_client.chrc_client_ineta[ 1],
                               (unsigned char)ds_client.chrc_client_ineta[ 2],
                               (unsigned char)ds_client.chrc_client_ineta[ 3],
                               (unsigned char)ds_client.chrc_client_ineta[ 4],
                               (unsigned char)ds_client.chrc_client_ineta[ 5],
                               (unsigned char)ds_client.chrc_client_ineta[ 6],
                               (unsigned char)ds_client.chrc_client_ineta[ 7],
                               (unsigned char)ds_client.chrc_client_ineta[ 8],
                               (unsigned char)ds_client.chrc_client_ineta[ 9],
                               (unsigned char)ds_client.chrc_client_ineta[10],
                               (unsigned char)ds_client.chrc_client_ineta[11],
                               (unsigned char)ds_client.chrc_client_ineta[12],
                               (unsigned char)ds_client.chrc_client_ineta[13],
                               (unsigned char)ds_client.chrc_client_ineta[14],
                               (unsigned char)ds_client.chrc_client_ineta[15] );
            break;
    }
} // end of ds_xsl::m_cb_print_ineta


/**
 * private function ds_xsl::m_cb_print_bytes
 *
 * @param[in]   ds_hstring*     ads_out         output buffer
 * @param[in]   HL_LONGLONG     il_bytes        bytes
*/
void ds_xsl::m_cb_print_bytes( ds_hstring* ads_out, HL_LONGLONG il_bytes )
{

    // initialize some variables:
    int         iml1;                        /* working-variable        */
    int         iml_shift;
    int         iml_decpoint;
    HL_LONGLONG ill1;
    char        *achl1, *achl2;
    char        achp_buffer[20]; // temp
    int         in_dec_sep = 0;

    iml_shift = 0;
    if (il_bytes >= ((HL_LONGLONG) 1000 * (HL_LONGLONG) 1024 * (HL_LONGLONG) 1024)) {
        iml_shift = 3;
    } else if (il_bytes >= ((HL_LONGLONG) 1000 * (HL_LONGLONG) 1024)) {
        iml_shift = 2;
    } else if (il_bytes >= (HL_LONGLONG) 1000) {
        iml_shift = 1;
    }
    /* count how many digits before decimal point                       */
    ill1 = il_bytes;
    if (iml_shift > 0) {                     /* do round up             */
        ill1 >>= iml_shift * 10;
    }
    iml1 = 0;
    do {
        iml1++;
        ill1 /= 10;
    } while (ill1 > 0);
    iml_decpoint = 4 - (iml1 + 3);
    if (iml_shift == 0) iml_decpoint = 0;
    ill1 = il_bytes;
    if (iml_shift > 0) {                     /* do round up             */
        ill1 *= 1000;
        ill1 >>= (iml_shift * 10);
    }
    achl1 = achp_buffer + 16;
    achl2 = achl1;                           /* set end of output       */
    *(achl1 + 0) = ' ';
    *(achl1 + 1) = 'B';
    *(achl1 + 2) = 0;                        /* make zero-terminated    */
    if (iml_shift > 0) {
        *(achl1 + 1) = chrs_edit_sci[ iml_shift - 1 ];
        *(achl1 + 2) = 'B';
        *(achl1 + 3) = 0;
        achl2 = achl1 - 4;     /* set end of output       */
    }
    iml1 = 0;
    do {
        if (iml1 == 3) {
            if (iml_decpoint > 0) {
                *(--achl1) = chrs_edit_decimal[ 0 ^ in_dec_sep ];  /* output separator */
                if ((ill1 == 0) && (in_dec_sep == 0)) break;
            }
            iml1 = 0;
        }
        iml1++;
        if (iml_decpoint >= 0) {
            *(--achl1) = (char)((ill1 % 10) + '0');
        }
        iml_decpoint++;
        ill1 /= 10;
    } while ((ill1 > 0) || (achl1 > achl2));

    ads_out->m_write_zeroterm( achl1 );
} // end of ds_xsl::m_cb_print_bytes


/**
 * function ds_xsl::m_cb_print_wspadmin_rcode
 *
 * @param[in]   ds_hstring*     ads_out     output buffer
*/
void ds_xsl::m_cb_print_wspadmin_rcode( ds_hstring* ads_out )
{
    // initialize some variables:
    const char*             ach_value = NULL;     // value
    int               in_len;               // value length
    ied_admin_rcode   ien_rcode;            // return code from wsp

    ien_rcode = dsc_admin.m_get_return_code();
    if ( ien_rcode == ied_wspadmin_unset ) {
        ien_rcode = dsc_auth.m_get_userov_rc();
    }
    switch ( ien_rcode ) {
        case ied_wspadmin_params:
            GET_RES( XSL_KEY_WSPADMIN_PARAMS, ach_value, in_len );
            break;

        case ied_wspadmin_end_of_file:
            GET_RES( XSL_KEY_WSPADMIN_EOF, ach_value, in_len );
            break;

        case ied_wspadmin_inv_request:
            GET_RES( XSL_KEY_WSPADMIN_INV_REQ, ach_value, in_len );
            break;

        case ied_wspadmin_rec_unavailable:
            GET_RES( XSL_KEY_WSPADMIN_REC_UNAVAIL, ach_value, in_len );
            break;

        case ied_wspadmin_timeout:
            GET_RES( XSL_KEY_WSPADMIN_TIMEOUT, ach_value, in_len );
            break;

        case ied_wspadmin_inv_cluster:
            GET_RES( XSL_KEY_WSPADMIN_INV_CLUSTER, ach_value, in_len );
            break;

        case ied_wspadmin_misc:
            GET_RES( XSL_KEY_WSPADMIN_MISC, ach_value, in_len );
            break;

        case ied_wspadmin_unknown:
            GET_RES( XSL_KEY_WSPADMIN_UNKNOWN, ach_value, in_len );
            break;

       default:
           return;
    }

    ads_out->m_write_html_text( ach_value, in_len );
} // end of ds_xsl::m_cb_print_wspadmin_rcode


/**
 * function ds_xsl::m_update_cache
 * put parse data into cache
 *
 * @param[in]   const char* ach_name    name of cache
 * @param[in]   int         in_len      length of cache name
 *
 * @return      bool          
*/
bool ds_xsl::m_update_cache( const char* ach_name, int in_len )
{
    // initialize some variables:
    bool             bo_return   = false;
    dsd_xml_tag*     ads_xml     = NULL;        // parsed file
    char*            ach_xml     = NULL;        // parsed data in cache
    int              in_len_xml  = 0;           // length of parsed data in cache
    int              in_len_head = 0;           // length of header in cache
    ds_cache_header* ads_cache   = NULL;        // cache header

    //-----------------------------------
    // get parsed data:
    //-----------------------------------
    ads_xml = dsc_parser.m_get_firstnode();

    //-----------------------------------
    // evalute length for cache:
    //-----------------------------------
    in_len_head  = (((int)sizeof(ds_cache_header) + (ALIGN_SIZE-1)) & (~(ALIGN_SIZE-1)));
    in_len_xml   = dsc_parser.m_get_cache_len( ads_xml );
    in_cache_len = in_len_head + in_len_xml;

#if 1
	bo_return = ads_wsp_helper->m_cb_open_or_create_cma(ach_name, in_len, &this->dsc_cma, 0);
	if(!bo_return)
		return false;
	if(this->dsc_cma.inc_len_cma_area != in_cache_len) {
		bo_return = ads_wsp_helper->m_cb_resize_cma2(&this->dsc_cma, in_cache_len);
		if(!bo_return)
			return false;
	}
	this->ach_cache = this->dsc_cma.achc_cma_area;
	this->in_cache_len = this->dsc_cma.inc_len_cma_area;
#else
    //-----------------------------------
    // check if cma is existings:
    //-----------------------------------
    bool bo_exists = ads_wsp_helper->m_cb_exist_cma( ach_name, in_len );
    if ( bo_exists == false ) {
        // create cma:
        bo_return = ads_wsp_helper->m_cb_create_cma( ach_name, in_len,
                                                     NULL, in_cache_len, 0 );
        if ( bo_return == false ) {
            return false;
        }
    }

    //-----------------------------------
    // set size of cma:
    //-----------------------------------
    bo_return = ads_wsp_helper->m_cb_resize_cma( ach_name, in_len, in_cache_len );
    if ( bo_return == false ) {
        return false;
    }

    //-----------------------------------
    // open cma for writing:
    //-----------------------------------
    av_cma_handle = ads_wsp_helper->m_cb_open_cma( ach_name, in_len,
                                                   (void**)(&ach_cache),
                                                   &in_cache_len );
    if ( av_cma_handle == NULL ) {
        return false;
    }
#endif
    //-----------------------------------
    // set time of creation:
    //-----------------------------------
    ads_cache = (ds_cache_header*)ach_cache;

    ads_cache->tm_created = ads_wsp_helper->m_cb_get_time();

    //-----------------------------------
    // write xml cache
    //-----------------------------------
    ach_xml = ach_cache + in_len_head;
    bo_return = dsc_parser.m_write_cache( ach_xml, in_len_xml, ads_xml );
    if ( bo_return == false ) {
        return false;
    }
   
    return true;
} // end of ds_xsl::m_update_cache


/**
 * function ds_xsl::m_gen_output
 * generate output from xml data
 *
 * @param[out]  ds_hstring*     ads_out         output buffer
*/
void ds_xsl::m_gen_output( ds_hstring* ads_out )
{
    // initialize some variables:
    dsd_variable          dsl_variable;
    ds_hstack_btype<dsd_xsl_iterator> ds_element( ads_wsp_helper );
    
    dsd_xsl_iterator dsl_dummy;
    dsl_dummy.dsc_rac.inc_cur = -1;
    dsl_dummy.dsc_rac.inc_end = -1;
    ds_element.m_add( dsl_dummy );
    dsl_variable.dsc_name.m_init( ads_wsp_helper );
    dsl_variable.dsc_value.m_init( ads_wsp_helper );
    
    dsc_included_parsers.m_init( ads_wsp_helper );
    dsc_included_parsers.m_clear();

    m_search_templates( dsc_parser.m_get_firstnode() );
    m_write_tag( dsc_parser.m_get_firstnode(), ads_out,
                 &ds_element, &dsl_variable );
    
    //clear included template files list
    if(!dsc_included_parsers.m_empty()) {
        for ( HVECTOR_FOREACH2(ds_parse_xsl*, adsl_cur, dsc_included_parsers) ) {
            ds_parse_xsl* adsl_parser = HVECTOR_GET(adsl_cur);
            adsl_parser->m_clear();
            ads_wsp_helper->m_cb_free_memory(adsl_parser, sizeof(ds_parse_xsl));
        }
    }

} // end of ds_xsl::m_gen_output( ds_hstring* )


/**
 * function ds_xsl::m_is_file_modified
 *
 * @param[in] const char*   ach_file
 * @param[in] int           in_len_file
 * @return    bool          
*/
bool ds_xsl::m_is_file_modified( const char* ach_file, int in_len_file )
{
    // initialize some variables:
    ds_cache_header* ads_cache = NULL;          // cache header
    bool bo_modified           = true;
    bool bo_diskfile           = false;

    // init diskfile structure:
    memset(&ds_file, 0, sizeof(struct dsd_hl_aux_diskfile_1));
#ifndef WSP_V24
    ds_file.iec_chs_name = ied_chs_utf_8;
    ds_file.ac_name      = (void*)ach_file;
    ds_file.inc_len_name = in_len_file;
#endif
#ifdef WSP_V24
    ds_file.dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;
    ds_file.dsc_ucs_file_name.ac_str      = (void*)ach_file;
    ds_file.dsc_ucs_file_name.imc_len_str = in_len_file;
#endif

    // no data in cache -> it must be updated
    if ( ach_cache == NULL ) {
        return true;
    }
    ads_cache = (ds_cache_header*)ach_cache;

    // ask wsp for last modified date:
    bo_diskfile = ads_wsp_helper->m_cb_file_lastmodified( &ds_file );
    if ( bo_diskfile == false ) {
        /*
            if cma was already existing, it was just opened for reading
            we will close it and reopen it later again
        */
        m_close_cache();

        // error occured: exit
        return true;
    }

    int in_diff = (int)(ads_cache->tm_created - (hl_time_t)ds_file.imc_time_last_mod);
    if ( in_diff > -1 ) {
        bo_modified = false;
    }

    if ( bo_modified == true ) {
        /*
            if cma was already existing, it was just opened for reading
            we will close it and reopen it for writing later again
        */
        m_close_cache();
    }

	this->m_release_file();
    return bo_modified;
} // end of ds_xsl::m_is_file_modified


/**
 * function ds_xsl::m_get_file
 *
 * @param[out]  char**      aach_data
 * @param[out]  int*        ain_len
 * @return      bool
*/
bool ds_xsl::m_get_file( char** aach_data, int* ain_len )
{
    bool bo_diskfile = ads_wsp_helper->m_cb_file_access( &ds_file );

    if ( bo_diskfile == true ) {
        *aach_data = ds_file.adsc_int_df1->achc_filecont_start;
        *ain_len   = (int)(ds_file.adsc_int_df1->achc_filecont_end - ds_file.adsc_int_df1->achc_filecont_start);
    }

    if ( *aach_data == NULL || *ain_len < 1 ) {
        bo_diskfile = false;
    }

    return bo_diskfile;
} // end of ds_xsl::m_get_file


/**
 * function ds_xsl::m_release_file
 *
 * @return      bool
*/
bool ds_xsl::m_release_file()
{
    return ads_wsp_helper->m_cb_file_release( &ds_file );
} // end of ds_xsl::m_release_file


/**
 * function ds_xsl::m_get_cache
 *
 * @param[in]   const char* ach_name    name of cache
 * @param[in]   int         in_len      length of cache name
 *
 * @return     bool
*/
bool ds_xsl::m_get_cache( const char* ach_name, int in_len )
{
    if ( in_len < 1 ) {
        return false;
    }
	if(!ads_wsp_helper->m_cb_open_cma2(ach_name, in_len, &this->dsc_cma, false)) {
		return false;
	}
	if(this->dsc_cma.inc_len_cma_area <= 0) {
		if(!ads_wsp_helper->m_cb_close_cma2(&this->dsc_cma))
			return false;
		return true;
	}
	this->ach_cache = this->dsc_cma.achc_cma_area;
	this->in_cache_len = this->dsc_cma.inc_len_cma_area;
    return true;
} // end of ds_xsl::m_get_cache


/**
 * function ds_xsl::m_close_cache
 *
 * @return     bool
*/
bool ds_xsl::m_close_cache()
{
#if 1
	if(this->dsc_cma.ac_cma_handle == NULL)
		return false;
	ach_cache    = NULL;
    in_cache_len = 0;
	return ads_wsp_helper->m_cb_close_cma2( &this->dsc_cma );
#else
	if ( av_cma_handle != NULL ) {
        ach_cache    = NULL;
        in_cache_len = 0;
        return ads_wsp_helper->m_cb_close_cma( &av_cma_handle );
    } else {
        return false;
    }
#endif
} // end of ds_xsl::m_close_cache


/**
 * function ds_xsl::m_get_cache_name
 *
 * @param[in]   const char* ach_file
 * @param[in]   int         in_len_file
 * @param[out]  ds_hstring* ads_name
*/
void ds_xsl::m_get_cache_name( const char* ach_file, int in_len_file,
                               ds_hstring* ads_name )
{
    // initialise some variables:
    int in_len_root = (int)ads_session->ads_config->ach_root_dir.m_get_len();

    // add webserver prefix:
    ads_name->m_set( PREFIX_CMA_NAME_IWS PREFIX_CMA_IWS_CACHE );
    if ( in_len_root < in_len_file ) {
        ads_name->m_write( &ach_file[in_len_root], in_len_file - in_len_root );
    }

#if defined WIN32 || defined WIN64
    ads_name->m_replace( "\\", "/" );
#endif

    // check for max cma len (information taken from "hob-wspsu1.h")
    if ( ads_name->m_get_len() > 128 ) {
        ads_name->m_reset();
    }
} // end of ds_xsl::m_get_cache_name


/**
 * function ds_xsl::m_is_ns_tag
 * is tag from xml namespace
 *
 * @param[in]   dsd_xml_tag*    ads_in
 * @return      ied_xsl_tags    
*/
ied_xsl_tags ds_xsl::m_is_ns_tag( dsd_xml_tag* ads_in )
{
    // initialize some variables:
    dsd_xml_attr* ads_attr   = NULL;            // tag attribute
    const char*   ach_aname  = NULL;            // attribute name
    int           in_alen    = 0;               // length of attribute name

    //---------------------------------
    // check if we have a tag:
    //---------------------------------
    if ( ads_in->ien_type != ied_tag ) {
        return ied_unknowntag;
    }

    //---------------------------------
    // check if tag is in namespace:
    //---------------------------------
    dsd_const_string dsl_tag(ads_in->ach_data, ads_in->in_len_data);
    if(!dsl_tag.m_starts_with_ic(XSL_NAMESPACE))
        return ied_unknowntag;
    dsd_const_string dsl_key(dsl_tag.m_substring(4));

    //---------------------------------
    // get type of tag:
    //---------------------------------
    dsd_unicode_string dsl_key2;
    dsl_key2.ac_str = (void*)dsl_key.m_get_ptr();
    dsl_key2.imc_len_str = dsl_key.m_get_len();
    dsl_key2.iec_chs_str = dsc_parser.m_get_encoding();
    ied_xsl_tags ied_type = ds_wsp_helper::m_search_equals_ic2(achr_known_xsltags, dsl_key2, ied_unknowntag);
    if(ied_type == ied_unknowntag)
        return ied_unknowntag;
    if(achr_valid_xslattr[ied_type].m_get_len() == 0) {
        //tag without attribute (comment), skip check
        return ied_type;
    }
    //---------------------------------
    // get type of attribute:
    //---------------------------------
    ads_attr = dsc_parser.m_get_attribute( ads_in );
    // each xsl tag must have excactly one attribute
    if (    ads_attr == NULL
         || dsc_parser.m_get_nextattr( ads_attr ) != NULL ) {
        return ied_unknowntag;
    }
    dsc_parser.m_get_attr_name( ads_attr, &ach_aname, &in_alen );
    int in_compare;
    BOOL bo_ret = m_cmpi_vx_vx( &in_compare,
                           ach_aname,
                           in_alen,
                           dsc_parser.m_get_encoding(),
                           achr_valid_xslattr[ied_type].m_get_ptr(),
                           achr_valid_xslattr[ied_type].m_get_len(),
                           ied_chs_utf_8 );
    if ( !bo_ret || in_compare != 0 )
        return ied_unknowntag;
    return ied_type;
} // end of ds_xsl::m_is_ns_tag


/**
 * function ds_xsl::m_write_tag
 * write a tag to xml
 *
 * @param[in]   dsd_xml_tag*               ads_in
 * @param[in]   ds_hstring*                ads_xml
 * @param[in]   ds_hstack_btype<dsd_xsl_iterator>*     ads_element      element (for "for:each" loops)
 * @param[in]   dsd_variable*              ads_variable
*/
void ds_xsl::m_write_tag( dsd_xml_tag* ads_in, ds_hstring* ads_xml,
                          ds_hstack_btype<dsd_xsl_iterator>* ads_element, dsd_variable* ads_variable )
{
    // initialize some variables:
    dsd_xml_attr* ads_tmp_attr = NULL;              // attribute
    ied_xsl_tags  ied_type;                         // namespace tag type
    int           in_pos;                           // search position
    int           in_childs;                        // number of childs entries (for-each)
    const char*         ach_value;                        // attribute value
    int           in_len_val;                       // length of attribute value
    bool          bo_write     = false;             // write if childs?

    // check number of recursiv calls:
    inc_rec_call++;
    if ( inc_rec_call > XSL_MAX_NUM_OF_REC_CALLS ) {
        ads_wsp_helper->m_logf( ied_sdh_log_error,
                                "HIWSE950E: ds_xsl::m_write_tag reached limit (%d) of recursiv calls",
                                XSL_MAX_NUM_OF_REC_CALLS );
        inc_rec_call--;
        return;
    }
#ifdef _DEBUG
    if ( inc_rec_peak < inc_rec_call ) {
        inc_rec_peak = inc_rec_call;
    }
#endif

    // check if tag is one to change
    ied_type = m_is_ns_tag( ads_in );

    switch ( ied_type ) {

        case ied_for_each: {
            // get attribute value:
            dsc_parser.m_get_attr_value( dsc_parser.m_get_attribute(ads_in),
                                         &ach_value, &in_len_val );
            if (    ((ach_value[0] == '"') && (ach_value[in_len_val-1] == '"'))
                 || ((ach_value[0] == '\'') && (ach_value[in_len_val-1] == '\'')) ) {
                 ach_value   = ach_value + 1;
                 in_len_val -= 2;
            }

            // loop over all entries:
            // TODO: Change stack container ds_hstack_btype<dsd_xsl_iterator>* to use a structure instead of int.
            // Then it should be possible to work with an iterator
            dsd_xsl_iterator dsl_new;
            int inl_type;
            in_childs = m_cb_no_childs( ach_value, in_len_val, ads_element, dsl_new, inl_type );
            //dsl_new.imc_count = in_childs;
            //dsl_new.imc_cur = 0;
            ads_element->m_add( dsl_new );
            dsd_xsl_iterator* adsl_cur = ads_element->m_get_last_ref();
            switch(adsl_cur->iec_mode) {
            case ied_xsl_iterator_mode_random:
                while ( adsl_cur->dsc_rac.inc_cur < adsl_cur->dsc_rac.inc_end ) {
                    // write child tag:
                    if ( ads_in->ads_child != NULL ) {
                        //ads_element->m_set_last( in_pos );
                        m_write_tag( ads_in->ads_child, ads_xml, ads_element, ads_variable );
                    }
                    adsl_cur->dsc_rac.inc_cur++;
                }
                break;
            case ied_xsl_iterator_mode_fwd:
                while ( adsl_cur->dsc_fwd.avoc_cur != adsl_cur->dsc_fwd.avoc_end ) {
                    // write child tag:
                    if ( ads_in->ads_child != NULL ) {
                        //ads_element->m_set_last( in_pos );
                        m_write_tag( ads_in->ads_child, ads_xml, ads_element, ads_variable );
                    }
                    if(!m_cb_iterate_next(inl_type, adsl_cur))
                        break;
                }
                break;
            }
            ads_element->m_delete_last();
            break;
        }
        case ied_value_of: {
            // get attribute value:
            dsc_parser.m_get_attr_value( dsc_parser.m_get_attribute(ads_in),
                                         &ach_value, &in_len_val );
            if (    ((ach_value[0] == '"') && (ach_value[in_len_val-1] == '"'))
                 || ((ach_value[0] == '\'') && (ach_value[in_len_val-1] == '\'')) ) {
                 ach_value   = ach_value + 1;
                 in_len_val -= 2;
            }

            ied_xsl_value_encoding iel_enc = m_get_encoding(ach_value, &in_len_val);

            // check if value is a variable:
            if (    ach_value[0] == '$'
                    && ads_variable->dsc_name.m_equals(&ach_value[1], in_len_val-1) ) {
                ach_value = ads_variable->dsc_value.m_get_ptr();
                in_len_val = ads_variable->dsc_value.m_get_len();
            }

            // insert requested data:
            if(ied_xsl_enc_html ==iel_enc || ied_xsl_enc_unknown == iel_enc ) {
                m_cb_get_data( ach_value, in_len_val, ads_xml, ads_element );
            } else {
                ds_hstring dsl_temp(ads_wsp_helper);
                m_cb_get_data( ach_value, in_len_val, &dsl_temp, ads_element );
                dsd_unicode_string dsl_val;
                dsl_val.ac_str = (void*)dsl_temp.m_get_ptr();
                dsl_val.imc_len_str = dsl_temp.m_get_len();
                dsl_val.iec_chs_str = ied_chs_html_1; //string ist html encoded utf8
                ds_hstring dsl_temp2(ads_wsp_helper); 
                dsl_temp2.m_set(dsl_val); //convert back from html encoded to utf8
                dsl_val.ac_str = (void*)dsl_temp2.m_get_ptr();
                dsl_val.imc_len_str = dsl_temp2.m_get_len();
                dsl_val.iec_chs_str = ied_chs_utf_8;

                switch (iel_enc)
                {
                case ied_xsl_enc_uri:
                    dsl_temp.m_reset();
                    dsl_temp.m_write(&dsl_val, ied_chs_uri_1);
                    dsl_temp.m_replace(" ", "%20"); //charset does not replace spaces ???
                    break;
                case ied_xsl_enc_utf8:
                    dsl_temp.m_set(dsl_temp2);
                    break;
                case ied_xsl_enc_js_string: {
                    //TODO implement and use proper charset
				    dsl_temp2.m_replace("\\", "\\\\");
                    dsl_temp2.m_replace("\"", "\\\"");
                    dsl_temp2.m_replace("\r", "\\r");
                    dsl_temp2.m_replace("\n", "\\n");
                    dsl_temp.m_set(dsl_temp2);
                    break;
                }
                case ied_xsl_enc_b64: {
                    ds_hstring dsl_temp2(ads_wsp_helper); 
                    dsl_temp2.m_set(dsl_val);

                    dsl_temp.m_reset();
                    dsl_temp.m_write_b64( dsl_temp2.m_get_ptr(), dsl_temp2.m_get_len() );
                    dsl_temp.m_trim("=", false, true); //only right
                    break;
                }
                default:
                    //should not happen
                    break;
                }
                ads_xml->m_write(dsl_temp);
            }

            // write child tag:
            if ( ads_in->ads_child != NULL ) {
                m_write_tag( ads_in->ads_child, ads_xml, ads_element, ads_variable );
            }
            break;
        }
        case ied_attribute:
            // find last tag:
            in_pos = ads_xml->m_search_last( ">" );
            if ( in_pos == -1 ) {
                inc_rec_call--;
                return;
            }
            // erase last data:
            ads_xml->m_erase( in_pos, ads_xml->m_get_len() - in_pos );

            // write a space:
            ads_xml->m_write( " " );

            // get attribute value:
            dsc_parser.m_get_attr_value( dsc_parser.m_get_attribute(ads_in),
                                         &ach_value, &in_len_val );
            if (    ((ach_value[0] == '"') && (ach_value[in_len_val-1] == '"'))
                 || ((ach_value[0] == '\'') && (ach_value[in_len_val-1] == '\'')) ) {
                 ach_value   = ach_value + 1;
                 in_len_val -= 2;
            }
            
            // write a value:
            ads_xml->m_write( ach_value, in_len_val );
            ads_xml->m_write( "=\"" );

            // write child tag:
            if ( ads_in->ads_child != NULL ) {
                m_write_tag( ads_in->ads_child, ads_xml, ads_element, ads_variable );
            }

            // write end of tag again:
            ads_xml->m_write( "\">" );
            break;

        case ied_if:
            // get attribute value:
            dsc_parser.m_get_attr_value( dsc_parser.m_get_attribute(ads_in),
                                         &ach_value, &in_len_val );
            if (    ((ach_value[0] == '"') && (ach_value[in_len_val-1] == '"'))
                 || ((ach_value[0] == '\'') && (ach_value[in_len_val-1] == '\'')) ) {
                 ach_value   = ach_value + 1;
                 in_len_val -= 2;
            }

            // check if we should write childs:
            bo_write =  m_cb_is_true( ach_value, in_len_val, ads_element, ads_variable );
            if (    bo_write == true
                 && ads_in->ads_child != NULL ) {
                m_write_tag( ads_in->ads_child, ads_xml, ads_element, ads_variable );
            }
            break;

        case ied_template:
        case ied_include:
        case ied_comment:
            // write nothing:
            break;

        case ied_call_template: {
            const char*        ach_template;
            int          in_len_template;

            if ( dsc_templates.m_empty() == true ) {
                break;
            }

            for ( HVECTOR_FOREACH2(dsd_xml_tag*, adsl_cur, dsc_templates) ) {
                dsd_xml_tag* adsl_template = HVECTOR_GET(adsl_cur);
                if (    adsl_template            != NULL    /* template is not null */
                     && adsl_template->ads_child != NULL    /* content is existing  */ ) {
                    // get name of current template:
                    dsc_parser.m_get_attr_value( dsc_parser.m_get_attribute(adsl_template),
                                                 &ach_template, &in_len_template );
                    if (    ((ach_template[0] == '"') && (ach_template[in_len_template-1] == '"'))
                         || ((ach_template[0] == '\'') && (ach_template[in_len_template-1] == '\'')) ) {
                        ach_template   = ach_template + 1;
                        in_len_template -= 2;
                    }

                    // get name of requested template:
                    dsc_parser.m_get_attr_value( dsc_parser.m_get_attribute(ads_in),
                                                 &ach_value, &in_len_val );
                    if (    ((ach_value[0] == '"') && (ach_value[in_len_val-1] == '"'))
                         || ((ach_value[0] == '\'') && (ach_value[in_len_val-1] == '\'')) ) {
                        ach_value   = ach_value + 1;
                        in_len_val -= 2;
                    }

                    // check if value is a variable:
                    if (    ach_value[0] == '$'
                         && ads_variable->dsc_name.m_equals(&ach_value[1], in_len_val-1) ) {
                        ach_value = ads_variable->dsc_value.m_get_ptr();
                        in_len_val = ads_variable->dsc_value.m_get_len();
                    }

                    // check name:
                    if (    in_len_template == in_len_val
                         && memcmp( ach_value, ach_template, in_len_val ) == 0 ) {
                        // write this template:
                        m_write_tag( adsl_template->ads_child, ads_xml, ads_element, ads_variable );
                        break;
                    }
                }
            }
            break;
        }

        case ied_variable:
            // get attribute value:
            dsc_parser.m_get_attr_value( dsc_parser.m_get_attribute(ads_in),
                                         &ach_value, &in_len_val );
            if (    ((ach_value[0] == '"') && (ach_value[in_len_val-1] == '"'))
                 || ((ach_value[0] == '\'') && (ach_value[in_len_val-1] == '\'')) ) {
                 ach_value   = ach_value + 1;
                 in_len_val -= 2;
            }

            ads_variable->dsc_name.m_set( ach_value, in_len_val );
            ads_variable->dsc_value.m_reset();
            if ( ads_in->ads_child != NULL ) {
                m_write_tag( ads_in->ads_child, &ads_variable->dsc_value,
                             ads_element, NULL );
            }
            break;

        default:
            // write start of tag
            if (    ads_in->ien_type == ied_tag
                 || ads_in->ien_type == ied_xmltype
                 || ads_in->ien_type == ied_data     ) {
                ads_xml->m_write( "<" );
            }
            ads_xml->m_write( ads_in->ach_data, ads_in->in_len_data );

            // write attributes
            if ( ads_in->ien_type == ied_tag || ads_in->ien_type == ied_xmltype ) {
                ads_tmp_attr = ads_in->ads_attr;
                while ( ads_tmp_attr != NULL ) {
                    ads_xml->m_write( " " );
                    ads_xml->m_write( ads_tmp_attr->ach_name, ads_tmp_attr->in_len_name );
                    ads_xml->m_write( "=" );
                    ads_xml->m_write( ads_tmp_attr->ach_value, ads_tmp_attr->in_len_value );
                    ads_tmp_attr = ads_tmp_attr->ads_next;
                }
            }


            if ( ads_in->ads_child != NULL ) {
                // write tag end:
                if ( ads_in->ien_type == ied_tag || ads_in->ien_type == ied_xmltype ) {
                    ads_xml->m_write( ">" );
                }
                    
                // write child tag:
                m_write_tag( ads_in->ads_child, ads_xml, ads_element, ads_variable );

                // write end tag:
                if ( ads_in->ien_type == ied_tag || ads_in->ien_type == ied_xmltype ) {
                    ads_xml->m_write( "</" );
                    ads_xml->m_write( ads_in->ach_data, ads_in->in_len_data );
                    ads_xml->m_write( ">" );
                }
            } else {
                // write tag end:
                switch ( ads_in->ien_type ) {
                    case ied_tag:
                        ads_xml->m_write( "/>" );
                        break;
                    case ied_xmltype:
                        ads_xml->m_write( " ?>" );
                        break;
                    case ied_data:
                        ads_xml->m_write( ">" );
                        break;
                }
            }
            break;
    } // end of switch

    // write next tag:
    if ( ads_in->ads_next != NULL ) {
        if (     (ads_in->ads_next->ien_type  == ied_value)
				 && ads_in->ads_next->ads_child == NULL
				 && ads_in->ads_next->ads_attr  == NULL       ) {
            ads_xml->m_write( ads_in->ads_next->ach_data,
                              ads_in->ads_next->in_len_data );
            if ( ads_in->ads_next->ads_next != NULL ) {
                m_write_tag( ads_in->ads_next->ads_next, ads_xml, ads_element, ads_variable );
            }

        } 
		else {
            m_write_tag( ads_in->ads_next, ads_xml, ads_element, ads_variable );
        }
    }

    inc_rec_call--;
    return;
} // end of ds_xsl::m_write_tag


/**
 * function ds_xsl::m_search_templates
 * write a tag to xml
 *
 * @param[in]   dsd_xml_tag*               ads_in
*/
void ds_xsl::m_search_templates( dsd_xml_tag* ads_in )
{
    // initialize some variables:
    ied_xsl_tags  ied_type;                         // namespace tag type
    const char*   ach_value;
    int           in_len_val;

    dsc_templates.m_init( ads_wsp_helper );
    dsc_templates.m_clear();

    while ( ads_in != NULL ) {
        // check if tag is one to change
        ied_type = m_is_ns_tag( ads_in );

        switch ( ied_type ) {

            case ied_template:
                dsc_templates.m_add( ads_in );
                break;
            case ied_include:
                dsc_parser.m_get_attr_value( dsc_parser.m_get_attribute(ads_in),
                                         &ach_value, &in_len_val );
                if (    ((ach_value[0] == '"') && (ach_value[in_len_val-1] == '"'))
                     || ((ach_value[0] == '\'') && (ach_value[in_len_val-1] == '\'')) ) {
                     ach_value   = ach_value + 1;
                     in_len_val -= 2;
                }
                m_include_template_file(ach_value, in_len_val);
                break;
            default:
                break;
        } // end of switch
        

        // get next tag:
        ads_in = ads_in->ads_next;
    }

    return;
} // end of ds_xsl::m_search_templates

/**
 * private function ds_xsl::m_innclude_template_file
 * read file, parse it and add its template definitions
 *
 * @param[in]    const char* ach_href
 * @param[in]    int in_href_len
*/
void ds_xsl::m_include_template_file( const char* ach_href, int in_href_len ) {
    //TODO XXX !!!!
    ds_hstring  ds_path;
    dsd_hl_aux_diskfile_1 ds_inc_file;
    dsd_xml_tag* ads_xml;
    ds_parse_xsl* adsl_parser;
    
    ied_xsl_tags  iel_type;                         // namespace tag type
    char* ach_data;
    int in_len;
    const char* ach_value;
    int in_len_val;

    ds_path.m_init( ads_wsp_helper );
    
    //simplified path resolution:
    if(ach_href[0] == '/') {
        //absolute path from www-root, no / at the end
        ds_path.m_write( ads_session->ads_config->ach_root_dir );
    } else {
        //path relative to file, get dir and let os handle the . and ..
#ifndef WSP_V24
        ds_path.m_write((char*)ds_file.ac_name, ds_file.inc_len_name);
#endif
#ifdef WSP_V24
        ds_path.m_write(ds_file.dsc_ucs_file_name.ac_str, ds_file.dsc_ucs_file_name.imc_len_str);
#endif
        //remove file name from path, keep ending /
#if defined WIN32 || defined WIN64
        in_len = ds_path.m_search_last("\\");
#else
        in_len = ds_path.m_search_last("/");
#endif
        ds_path.m_erase(in_len+1, ds_path.m_get_len() - in_len-1);
    }
    ds_path.m_write(ach_href, in_href_len);
#if defined WIN32 || defined WIN64
    ds_path.m_replace( "/", "\\" );
#endif

#ifndef WSP_V24
    ds_inc_file.iec_chs_name = ied_chs_utf_8;
    ds_inc_file.ac_name      = (void*)ds_path.m_get_ptr();
    ds_inc_file.inc_len_name = ds_path.m_get_len();
#endif
#ifdef WSP_V24
    ds_inc_file.dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;
    ds_inc_file.dsc_ucs_file_name.ac_str      = (void*)ds_path.m_get_ptr();
    ds_inc_file.dsc_ucs_file_name.imc_len_str = ds_path.m_get_len();
#endif

    bool bo_diskfile = ads_wsp_helper->m_cb_file_access( &ds_inc_file );

    if(bo_diskfile) {
        ach_data = ds_inc_file.adsc_int_df1->achc_filecont_start;
        in_len   = (int)(ds_inc_file.adsc_int_df1->achc_filecont_end - ds_inc_file.adsc_int_df1->achc_filecont_start);

        if ( ach_data == NULL || in_len < 1 ) {
            bo_diskfile = false;
            ds_inc_file.iec_dfar_def = (ied_dfar_def)100;
        }
    }

    if ( !bo_diskfile ) {
        ds_hstring hstr_msg(ads_session->ads_wsp_helper, "HIWSE530E: DEF_AUX_DISKFILE_ACCESS failed");
        if (ds_inc_file.iec_dfar_def != ied_dfar_ok) {
            hstr_msg.m_writef(" with error %d", ds_inc_file.iec_dfar_def);
        }
        hstr_msg.m_write(" (");
        hstr_msg.m_write(ds_path);
        hstr_msg.m_write(") [template include]");
        ads_wsp_helper->m_log( ied_sdh_log_error, hstr_msg.m_const_str() );
        return;
    }

    //---------------------------------------
    // parse file:
    // (we will include whitespaces and data tags)
    // the allocated parser is freed in m_gen_output, after output has been written
    //-----------------------------------------------
    adsl_parser = (ds_parse_xsl*)ads_wsp_helper->m_cb_get_memory(sizeof(ds_parse_xsl), true);
	new(adsl_parser) ds_parse_xsl();
    adsl_parser->m_init( ads_wsp_helper );
    dsc_included_parsers.m_add(adsl_parser);

    adsl_parser->m_include_ws();
    adsl_parser->m_include_datatags();
    ads_xml = adsl_parser->m_from_xml( ach_data, in_len );
    if ( ads_xml == NULL ) {
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error, "HIWSE531E: Could not parse template file: %.*s.", 
            ds_path.m_get_len(), ds_path.m_get_ptr() );
        goto LBL_ERROR;
    }

    while ( ads_xml != NULL ) {
        // check if tag is a template
        iel_type = m_is_ns_tag( ads_xml );

        switch ( iel_type ) {
            case ied_template:
                dsc_templates.m_add( ads_xml );
                break;
            case ied_include:
                //no recursive include
                dsc_parser.m_get_attr_value( dsc_parser.m_get_attribute(ads_xml),
                                         &ach_value, &in_len_val );
				if (    ((ach_value[0] == '"') && (ach_value[in_len_val-1] == '"'))
					 || ((ach_value[0] == '\'') && (ach_value[in_len_val-1] == '\'')) ) {
					 ach_value   = ach_value + 1;
					 in_len_val -= 2;
				}
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning, "HIWSW531W: Recursive template include not supported; file: %.*s; included: %.*s", 
					ds_path.m_get_len(), ds_path.m_get_ptr(), in_len_val, ach_value );
                break;
            default:
                break;
        } // end of switch
        
        // get next tag:
        ads_xml = ads_xml->ads_next;
    }

    

LBL_ERROR:
    if( !ads_wsp_helper->m_cb_file_release( &ds_inc_file )) {
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error, "HIWSE534E: Could not release file: %.*s.", 
            ds_path.m_get_len(), ds_path.m_get_ptr());
    }
}


/**
 * private function ds_xsl::m_fill_user_query
 * read user query from webserver query and fill structure
 *
 * @param[in/out]    struct dsd_q_user_overview* adsp_query
*/
void ds_xsl::m_fill_user_query( struct dsd_q_user_overview* adsp_query )
{
    // initialize some variables:
    int                       inl_temp;              // temp return value
    int                       inl_element = 0;       // element in achr_wspadmin_queries
    const char*               achl_value;            // query value
    int                       inl_len_val;           // length of query value
    enum ied_wspadmin_queries ienl_qtype;            // query type

    // set defaults:
    memset( adsp_query, 0, sizeof(struct dsd_q_user_overview) );
    adsp_query->inc_receive = 50;

    while ( achr_wspadmin_queries[inl_element].strc_ptr != NULL ) {
        ads_session->dsc_webserver.m_get_query_value( achr_wspadmin_queries[inl_element],
                                                      &achl_value, &inl_len_val );
        if ( inl_len_val > 0 ) {
            ienl_qtype = (ied_wspadmin_queries)inl_element;

            switch ( ienl_qtype ) {
                case ied_wspadmin_query_start:
                    adsp_query->inc_last_user = atoi( achl_value );
                    break;

                case ied_wspadmin_query_rec:
                    inl_temp = atoi( achl_value );
                    if ( inl_temp == -1 ) {
                        inl_temp = INT_MAX;
                    }
                    adsp_query->inc_receive = inl_temp;
                    break;

                case ied_wspadmin_query_user:
                    adsp_query->achc_search_user = achl_value;
                    adsp_query->inc_len_user     = inl_len_val;
                    break;

                case ied_wspadmin_query_group:
                    adsp_query->achc_search_domain = achl_value;
                    adsp_query->inc_len_domain     = inl_len_val;
                    break;

                case ied_wspadmin_query_wildcard:
                    adsp_query->boc_use_wildcard = (atoi(achl_value)>0)?true:false;
                    break;
            }
        }

        inl_element++;
    } // end of while loop

#ifdef MAX_ENTRIES_PER_PAGE
    // check maxsize for receives:
    if ( adsp_query->inc_receive > MAX_ENTRIES_PER_PAGE ) {
        adsp_query->inc_receive = MAX_ENTRIES_PER_PAGE;
    }
#endif
} // end of ds_xsl::m_fill_user_query

void ds_xsl::m_default_domain(ds_hstack_btype<dsd_xsl_iterator>* ads_element,int* in_len_data)
{
	/*
	  If the browser sends a cookie, and that cookie contains a domain, this domain has 
	  priority as a default domain over the default domain defined in the wsp.xml.
	  If there is no cookie, the default domain is read from the wsp.xml config file.
	  Note: could happens that there is no default domain defined, neither in the configuration
	  file or contained in a cookie. Then, the first domain represented in the html page is
	  the first readen in the wsp.xml configuration file
	*/
	ds_hstring domain( ads_session->ads_wsp_helper );
	dsd_wspat_pconf_t   *adsl_wspat_conf = ads_wsp_helper->m_get_wspat_config();
	struct dsd_domain *adsl_domain = adsl_wspat_conf->dsc_domains.adsc_domain;

    dsd_const_string dsl_ldn("login/domain/name");
	ds_hstring dsl_temp;
    m_cb_get_data( dsl_ldn.m_get_ptr(), dsl_ldn.m_get_len(), &dsl_temp, ads_element );

	while( adsl_domain )
	{
		if( adsl_domain->boc_default_enabled ){
            if( dsl_temp.m_equals(adsl_domain->achc_disp_name, adsl_domain->inc_len_disp_name)
                || dsl_temp.m_equals( adsl_domain->achc_name, adsl_domain->inc_len_name ))
            {
				*in_len_data = 1;
			}
		}
		adsl_domain = adsl_domain->adsc_next;
	}
}
