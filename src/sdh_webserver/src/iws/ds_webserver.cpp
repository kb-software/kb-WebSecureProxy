#include "../ds_session.h"
#include <ds_attribute_string.h>

#include "ds_webserver.h"
#include <ds_wsp_admin.h>
#include <ds_authenticate.h>
#include "../portal/ds_xsl.h"
#include "../portal/hob-postparams.h"
// time.h has to be included because cPrecomp included it, and J.F. used it in this file
#include <time.h>
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H
#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>
#include <hob-libwspat.h>
#include <auth_callback.h>
#include <ds_workstation.h>
#include <ds_bookmark.h>
#include <dsd_wfa_bmark.h>
#include <ds_portlet.h>
#include <stdint.h>
#include <hob-encry-1.h>
#ifdef HL_UNIX
    #include <ctype.h>
#endif
#if SM_USE_QUICK_LINK
#include <rdvpn_cma_content.h>
#endif
#include <hob-tk-gather-tools-01.h>
#include <xs-tk-gather-tools-01.cpp>

#ifdef _DEBUG
#define HL_DBG_PRINTF(x, ...)	/*printf(x, __VA_ARGS__)*/
#else
#define HL_DBG_PRINTF(x, ...)
#endif

#define HL_DBG_AUX_PIPE_STREAM	0

#define CK_DELETE_TIME      "Thu, 01 Jan 1970 01:00:00 UTC"

#define HL_GR_RET_GOTO(call, lbl) if(!(call)) goto lbl

/*+---------------------------------------------------------------------+*/
/*| helper structures:                                                  |*/
/*+---------------------------------------------------------------------+*/
// list of allowed post urls:
static const dsd_const_string achr_post_urls[] = {
    GLOBAL_START_SITE,                          // login page
    GLOBAL_LOGOUT_PAGE,                         // logout page
    QUARANTINE_HSL,                             // quarantine page
	"/protected/portlets/globaladmin/traces.hsl",		// WSP Trace Administration page: all WSPTrace settings for each individual WSP 
	"/protected/portlets/globaladmin/traces_all.hsl",	// WSP Trace Administration page: all WSPTrace settings from all WSPs in a same web
    "/protected/portlets/globaladmin/sessions.hsl",// disconnect session page
    "/protected/portlets/globaladmin/users.hsl",// logout user page
    "/protected/portlets/globaladmin/log.hsl",  // logfile page
    SETTINGS_PAGE,                              // user settings page
    CHANGE_PWD_PAGE,                            // change password page
    ICA_PORT_PAGE,                              // ica integration port
    ICA_CLOSE_PAGE,                             // ica integration close
    ICA_ALIVE_PAGE,                             // ica integration active
    FILE_EXT_TEMPLATE,                          // template pages
	JWTSAREQUEST,								// user requests a jwt standalone
	WEBTERMRDPPAGE
};

enum ied_post_urls {
    ied_posturl_unknown         = -1,   // unknown post url
    ied_posturl_login           =  0,   // login page
    ied_posturl_logout,                 // logout page
    ied_posturl_quarantine,             // quarantine  
	ied_posturl_wsptrace,               // WSP Trace admin page for a single WSP
	ied_posturl_wsptraceall,            // WSP Trace admin page to show all WSP's configuration
    ied_posturl_disconnect,             // disconnect session page
    ied_posturl_usr_logout,             // logout user page
    ied_posturl_logfile,                // logfile page
    ied_posturl_settings,               // user settings page
    ied_posturl_change_pwd,             // change password page
    ied_posturl_ica_port,               // ica integration port post
    ied_posturl_ica_close,              // ica integration close post
    ied_posturl_ica_alive,              // ica integration stillalive post
    ied_posturl_template,               // template pages
	ied_posturl_jwtsa,					// jwt sa request
	ied_posturl_webtermrdp
};

/*+---------------------------------------------------------------------+*/
/*| query data structure definition:                                    |*/
/*+---------------------------------------------------------------------+*/
#ifndef _DEF_QUERY_STRUCTURE
#define _DEF_QUERY_STRUCTURE

/*! \brief Query structure
 *
 * @ingroup webserver
 *
 * structure which holds the name and the value of a query 
 */
struct dsd_query {
    ds_hstring          ds_name;
    ds_hstring          ds_value;
    struct dsd_query*   ads_next;
};
#endif // _DEF_QUERY_STRUCTURE

/*+---------------------------------------------------------------------+*/
/*| functions:                                                          |*/
/*+---------------------------------------------------------------------+*/
ds_webserver::ds_webserver(void)
	: ads_session(NULL), ads_query(NULL)
{
    memset(&this->dsc_read_diskfile, 0, sizeof(struct dsd_hl_aux_diskfile_1));
}

ds_webserver::~ds_webserver(void)
{
    this->m_release_disk_file();
}

/*! \brief Class Initializer
 *
 * @ingroup webserver
 *
 * Sets up the members of the class after it is created
 */
bool ds_webserver::m_init(ds_session* ads_session_in)
{
    // set up the pointer to ds_session
    ads_session = ads_session_in;
    
    hstr_my_encoding.m_reset();
    hstr_message_body.m_init(ads_session->ads_wsp_helper);

    ds_path.hstr_path.m_setup(ads_session->ads_wsp_helper);

    dsc_v_logout_connections.m_init( ads_session->ads_wsp_helper );

    return true;
}


/*! \brief Post request handler
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_handle_post
 * handle post request
*/
void ds_webserver::m_handle_post( bool bo_authenticated )
{
    // initialize some variables:
    //const char*   ach_url;                           // post is for this url
    //int           in_url_len;                        // length of url
    const char*   ach_value;                         // query value
    int           in_len_val;                        // value length
    int           in_value;                          // language value
    ied_post_urls ien_url     = ied_posturl_unknown; // type of url
    int           in_element  = 0;                   // element of compare

    //-------------------------------------------
    // get post url:
    //-------------------------------------------
    //ach_url    = ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_ptr();
    //in_url_len = ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_len();
    dsd_const_string dsl_url(ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_const_str());

    //-------------------------------------------
    // check if we are in public folder
    // otherwise we will check authentication:
    //-------------------------------------------
    if (!bo_authenticated && !dsl_url.m_starts_with_ic(FOLDER_PUBLIC)) {
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                             "HIWSW240W: Not authenticated 'POST ' detected: %.*s",
                                             ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_len(),
                                             ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_ptr() );
        //m_forward_to_logout( MSG_POST_NO_AUTH, ied_sdh_log_warning, 240 );
        m_forward_to_logout( dsd_const_string::m_null(), 0, 0 );
        return;
    }

    //-------------------------------------------
    // get type of POST url:
    //-------------------------------------------
    int szl_num_post_urls = (int)(sizeof(achr_post_urls)/sizeof(achr_post_urls[0]));
    while ( in_element < szl_num_post_urls ) {
        const dsd_const_string& rdsl_cur = achr_post_urls[in_element];
        if ( in_element != (int)ied_posturl_template ) {
            if ( dsl_url.m_equals_ic(rdsl_cur) ) {
                ien_url = (ied_post_urls)in_element;
                break;
            }
        } else {
            if( dsl_url.m_ends_with_ic(rdsl_cur) ) {
                ien_url = (ied_post_urls)in_element;
                break;
            }
        }
        in_element++;
    }

    //-------------------------------------------
    // check for unknown POST url
    //-------------------------------------------
    if ( ien_url == ied_posturl_unknown ) {
        //---------------------------------------
        // check if this is a language post:
        //---------------------------------------
        m_get_query_value( POST_LANG,
                           &ach_value, &in_len_val );
        if ( in_len_val > 0 ) {
            in_value = RESOURCES->m_parse_lang( ach_value, in_len_val );
            if ( in_value > LANGUAGE_NOT_SET ) {
                 ads_session->dsc_auth.m_set_lang( in_value );
                 ads_session->dsc_control.in_cma_lang = in_value;
            }

            //-----------------------------------
            // create the page once again:
            //-----------------------------------
            m_file_proc(ds_path, NULL);
        } else {
            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning, "HIWSW654W: The passed URL was invalid: %.*s",
                dsl_url.m_get_len(), dsl_url.m_get_start() );
            m_forward_to_logout( MSG_INV_URL, ied_sdh_log_warning, 654 );
        }
        return;
    }
    
    //-------------------------------------------
    // parse message body:
    //-------------------------------------------
    if ( ads_query == NULL ) {
        return;
    }

    //-------------------------------------------
    // handle the different POST urls:
    //-------------------------------------------
    switch ( ien_url ) {
		/* 
			handle WSP Trace configuration change request
		*/
		case ied_posturl_wsptrace:
		case ied_posturl_wsptraceall:		
			m_handle_wsptrace_post();
			break;

        /*
            login or logout:
        */
        case ied_posturl_login:
            m_handle_login_post();
            break;

        /*
            end still existing sessions because logout:
        */
        case ied_posturl_logout:
            m_handle_logout_post();
            break;

        /*
            disconnect a session:
        */
        case ied_posturl_disconnect:
            m_handle_disconnect_post();
            break;

        /*
            admin logouts a given user:
        */
        case ied_posturl_usr_logout:
            m_handle_usr_logout_post();
            break;

        /*
            logfile post (like search):
        */
        case ied_posturl_logfile:
            m_handle_admin_post();
            break;

        /*
            post to a template page:
        */
        case ied_posturl_template:
            m_handle_template_post();
            break;

        /*
            quarantine:
        */
        case ied_posturl_quarantine:
            m_handle_quaratine_post();
            break;

        /*
            wsg bookmarks:
        */
        case ied_posturl_settings:
            m_handle_settings_post();
            break;

        /*
            change password:
        */
        case ied_posturl_change_pwd:
            m_handle_change_pwd_post();
            break;

        /*
            ica integration
        */
        case ied_posturl_ica_port:            
        case ied_posturl_ica_close:
        case ied_posturl_ica_alive:
            m_handle_ica_post( ien_url );
            break;

		/*
		 *	user requested a jwt standalone
		 */
		case ied_posturl_jwtsa:
			m_handle_jwtsa_request();
			break;

		case ied_posturl_webtermrdp:
			m_handle_webtermrdp_request();
			break;

    } // end of switch ( ien_url )

    return;
} // end of ds_webserver::m_handle_post()

/*! \brief WSP Trace configuration Handler
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_handle_wsptrace_post
 * Deals with the WSP Trace post request to change
 * WSP Trace state and/or parameters
*/
void ds_webserver::m_handle_wsptrace_post()
{
    // inititialize some variables:
    ds_wsp_admin dsl_admin;                 // wsp admin class

    dsl_admin.m_init( ads_session->ads_wsp_helper, ads_query );

    dsl_admin.m_wsptrace_modconf();

    //-----------------------------------
    // handle all other param like a 
    // normal template post:
    //-----------------------------------
    m_handle_template_post();

} // End of ds_webserver::m_handle_wsptrace_post()

/*! \brief Login Handler
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_handle_login_post
 * Deals with the login post request
*/
void ds_webserver::m_handle_login_post()
{
    // initialze some variables:
    bool bo_auth        = false;       // return from authentication
    bool bo_auth_called = false;
    const char *ach_pwd;
    int  in_len_pwd;
    const char *ach_lang;
    int  in_len_lang;
    int  in_len_cancel;
    int  in_len_logoff;
    int  inl_len_force_ssa;
    const char *achl_old_pwd;
    int  inl_len_old_pwd;
    const char *achl_confirm;
    int  inl_len_confirm;
    const char *achl_session;
    int  inl_slen;
    int  inl_create_new;
    const char *achl_temp;
    int  in_lang;                      // send language
#ifdef B20140805
    ds_hstring dsl_user;
    ds_hstring dsl_domain;
	ds_hstring dsl_userdn;
#else
    const char *achl_username;
    int  inl_len_username;
    const char *achl_domain;
    int  inl_len_domain;
#endif
    dsd_wspat_pconf_t *adsl_wspat_conf;
    
    //-----------------------------------
    // check for login or logout:
    //-----------------------------------
#ifdef B20140805
    m_get_query_value( USERNAME,       &ads_session->achc_username, &ads_session->inc_len_username );
#else
    m_get_query_value( USERNAME,       &achl_username,				&inl_len_username );
	if (!ads_session->boc_fixed_login && inl_len_username > 0) {
		ads_session->dsc_username = dsd_const_string(achl_username, inl_len_username);
	}
#endif
    m_get_query_value( PASSWORD,       &ach_pwd,                    &in_len_pwd    );
#ifdef B20140805
    m_get_query_value( HL_WS_DOMAIN,         &ads_session->achc_domain,   &ads_session->inc_len_domain );
#else
    m_get_query_value( HL_WS_DOMAIN,         &achl_domain,				&inl_len_domain );
	if (!ads_session->boc_fixed_login && inl_len_domain > 0) {
		ads_session->dsc_domain = dsd_const_string(achl_domain, inl_len_domain);
	}
#endif
    m_get_query_value( POST_LANG,      &ach_lang,                   &in_len_lang   );
    m_get_query_value( CANCEL,         &achl_temp,                  &in_len_cancel );
    m_get_query_value( SESSION,        &achl_session,               &inl_slen );
    m_get_query_value( DEF_CREATE_NEW, &achl_temp,                  &inl_create_new );
    m_get_query_value( LOGOFF,         &achl_temp,                  &in_len_logoff );

    if ( ads_session->ads_config->bo_show_ssa_checkbox == true ) {
        m_get_query_value( SHOW_HOMEPAGE, &achl_temp, &inl_len_force_ssa );
        if ( inl_len_force_ssa > 0 ) {
            ads_session->dsc_auth.m_set_state( ST_FORCE_SSA_PAGE );
        }
    }

	 HL_DBG_PRINTF("#m_handle_login_post 1 user=%.*s pwd=%.*s dom=%.*s\n",
		ads_session->dsc_username.m_get_len(), ads_session->dsc_username.m_get_ptr(),
		in_len_pwd, ach_pwd,
		ads_session->dsc_domain.m_get_len(), ads_session->dsc_domain.m_get_ptr());
    //---------------------------------------
    // change language:
    //---------------------------------------
    if ( in_len_lang > 0 ) {
        in_lang = RESOURCES->m_parse_lang( ach_lang, in_len_lang );
        if ( in_lang > LANGUAGE_NOT_SET ) {
             ads_session->dsc_auth.m_set_lang( in_lang );
             ads_session->dsc_control.in_cma_lang = in_lang;
        }
        //-----------------------------------
        // create the page once again:
        //-----------------------------------
#ifdef B20140805
        if (    ads_session->inc_len_username < 1
             && in_len_pwd                    < 1 
             && ads_session->inc_len_domain   < 1 ) {
            m_file_proc(ds_path);
            return;
        }
#else
		if (    ads_session->dsc_username.m_get_len() == 0
             && in_len_pwd                    < 1 
             && ads_session->dsc_domain.m_get_len()   == 0 ) {
            m_file_proc(ds_path, NULL);
            return;
        }
#endif
    }

    //---------------------------------------
    // change password:
    //---------------------------------------
    if ( ads_session->dsc_auth.m_check_state( ST_CHANGE_PASSWORD ) == true ) {
        m_get_query_value( NEW_PASSWORD,  &ach_pwd,      &in_len_pwd );
        m_get_query_value( CONF_PASSWORD, &achl_confirm, &inl_len_confirm );
        m_get_query_value( OLD_PASSWORD,  &achl_old_pwd, &inl_len_old_pwd );

        if (    in_len_pwd      < 1
             || inl_len_old_pwd < 1 ) {
            ads_session->dsc_auth.m_set_msg( 0, 0, MSG_INV_INPUT,
                                             ads_session->ads_config->ach_login_site );
            m_file_proc(ds_path, NULL);
            return;
        }

        if (    inl_len_confirm != in_len_pwd
             || memcmp( achl_confirm, ach_pwd, in_len_pwd) != 0 ) {
            ads_session->dsc_auth.m_set_msg( 0, 0, MSG_PWD_NOT_EQ,
                                             ads_session->ads_config->ach_login_site );
            m_file_proc(ds_path, NULL);
            return;
        }

#ifdef B20140805
        dsl_user.m_init( ads_session->ads_wsp_helper );
        dsl_domain.m_init( ads_session->ads_wsp_helper );
        dsl_userdn.m_init( ads_session->ads_wsp_helper );
        dsl_user  = ads_session->dsc_auth.m_get_username();
        dsl_domain = ads_session->dsc_auth.m_get_domain();
		dsl_userdn = ads_session->dsc_auth.m_get_userdn();
        ads_session->achc_username    = dsl_user.m_get_ptr();
        ads_session->inc_len_username = dsl_user.m_get_len();
        ads_session->achc_domain      = dsl_domain.m_get_ptr();
        ads_session->inc_len_domain   = dsl_domain.m_get_len();
		ads_session->achc_userdn      = dsl_userdn.m_get_ptr();
        ads_session->inc_len_userdn   = dsl_userdn.m_get_len();

		if (ads_session->inc_len_userdn > 0) {
			bo_auth = ads_session->dsc_auth.m_login( ads_session->achc_userdn,
													 ads_session->inc_len_userdn,
													 ach_pwd,   in_len_pwd,
													 achl_old_pwd, inl_len_old_pwd,
													 ads_session->achc_domain,
													 ads_session->inc_len_domain,
													 &ads_session->dscv_kick_out );
		} else {
			bo_auth = ads_session->dsc_auth.m_login( ads_session->achc_username,
													 ads_session->inc_len_username,
													 ach_pwd,   in_len_pwd,
													 achl_old_pwd, inl_len_old_pwd,
													 ads_session->achc_domain,
													 ads_session->inc_len_domain,
													 &ads_session->dscv_kick_out );
		}
#else
		ads_session->dsc_username = ads_session->dsc_auth.m_get_username();
		ads_session->dsc_domain = ads_session->dsc_auth.m_get_domain();
		ads_session->dsc_userdn = ads_session->dsc_auth.m_get_userdn();

		if (ads_session->dsc_userdn.m_get_len() > 0) {
			bo_auth = ads_session->dsc_auth.m_login( ads_session->dsc_userdn.m_get_ptr(),
 													 ads_session->dsc_userdn.m_get_len(),
													 ach_pwd,   in_len_pwd,
													 achl_old_pwd, inl_len_old_pwd,
													 ads_session->dsc_domain.m_get_ptr(),
													 ads_session->dsc_domain.m_get_len(),
													 &ads_session->dscv_kick_out );
		} else {
			bo_auth = ads_session->dsc_auth.m_login( ads_session->dsc_username.m_get_ptr(),
													 ads_session->dsc_username.m_get_len(),
													 ach_pwd,   in_len_pwd,
													 achl_old_pwd, inl_len_old_pwd,
													 ads_session->dsc_domain.m_get_ptr(),
													 ads_session->dsc_domain.m_get_len(),
													 &ads_session->dscv_kick_out );
		}
#endif

		bo_auth_called = true;
        ads_session->dsc_auth.m_unset_state( ST_CHANGE_PASSWORD );
    }

	 HL_DBG_PRINTF("m_handle_login_post 2\n");
    //---------------------------------------
    // login:
    //---------------------------------------
    if (    in_len_logoff < 1
         && ads_session->dsc_auth.m_check_state( ST_KICK_OUT ) == false  ) {
#ifdef B20140805
        bo_auth = ads_session->dsc_auth.m_login( ads_session->achc_username,
                                                 ads_session->inc_len_username,
                                                 ach_pwd, in_len_pwd, NULL, 0,
                                                 ads_session->achc_domain,
                                                 ads_session->inc_len_domain,
                                                 &ads_session->dscv_kick_out );
#else
        bo_auth = ads_session->dsc_auth.m_login( ads_session->dsc_username.m_get_ptr(),
                                                 ads_session->dsc_username.m_get_len(),
                                                 ach_pwd, in_len_pwd, NULL, 0,
                                                 ads_session->dsc_domain.m_get_ptr(),
                                                 ads_session->dsc_domain.m_get_len(),
                                                 &ads_session->dscv_kick_out );
#endif
        bo_auth_called = true;
			HL_DBG_PRINTF("m_handle_login_post 2 bo_auth=%d\n", bo_auth);

		/* hofmants: let user in without the "already loged in" dialogue screen */
		if( ads_session->dsc_auth.m_check_state( ST_KICK_OUT ) == true )
		{
			adsl_wspat_conf = ads_session->ads_wsp_helper->m_get_wspat_config();
			if( adsl_wspat_conf->boc_multiple_login == true )
			{
				/* just let the user in and create a new session */
				bo_auth = ads_session->dsc_auth.m_create_new();
			}
			else
			{
				/*
					if multiple sessions exist, because MULTIPLE_LOGIN was YES, and then the config was reloaded with NO,
					then only the first session is kicked out... if a customer complains, we have to change that.
				*/
				bo_auth = ads_session->dsc_auth.m_kick_out(dsd_cma_session_no((unsigned char)1));
                if ( bo_auth != false )
				{
					bo_auth = ads_session->dsc_auth.m_finish_kickout();
				}
			}
		}
		/* hofmants end */
    }

    //---------------------------------------
    // We are authenticated
    //---------------------------------------
    if ( bo_auth == true ) {
        
        ads_session->dsc_auth.m_finish_login();
        
        ds_hstring hstr_cookie(ads_session->ads_wsp_helper);
        ads_session->dsc_auth.m_get_http_cookie( &hstr_cookie );
        // Ticket[11985]: print to console/log that the nonce was created (this nonce is a NA=NotAuthenticated)
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                             "HIWSE245I: CMA with Accepted-Nonce was created: %.*s",
                                             hstr_cookie.m_get_len(), hstr_cookie.m_get_ptr() );
		HL_DBG_PRINTF("m_handle_login_post 3 hstr_cookie=%.*s\n", hstr_cookie.m_get_len(), hstr_cookie.m_get_ptr());

        // from now on we will send only short header field "Server"
        ads_session->dsc_auth.m_set_state( ST_SHORT_HF_SERVER );

        // Create the string for the http-cookie-header-line
        ds_hstring hstr_cookie_string(ads_session->ads_wsp_helper);
        int in_ret = m_setup_cookie_string(&hstr_cookie_string, hstr_cookie.m_const_str());
        if (in_ret != SUCCESS) {
            // no cookie string created -> return
            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                                 "HIWSE047E: Cookie could not be created. Error %d",
                                                 in_ret );
            m_send_error_page( ds_http_header::ien_status_internal_error, false,
                               MSG_COOKIE_NOT_CREATED, ied_sdh_log_error, 47   );

            // reset saved username and domain
#ifdef B20140805
			ads_session->achc_username    = NULL;
			ads_session->inc_len_username = 0;
			ads_session->achc_domain      = NULL;
			ads_session->inc_len_domain   = 0;
			ads_session->achc_userdn      = NULL;
			ads_session->inc_len_userdn   = 0;
#else
			ads_session->dsc_username.m_reset();
			ads_session->dsc_domain.m_reset();
			ads_session->dsc_userdn.m_reset();
#endif
            return;
        }

        //-----------------------------------
        // comliance check is needed?
        //-----------------------------------
        ds_hstring hstr_location( ads_session->ads_wsp_helper );
        if ( ads_session->dsc_auth.m_check_state(ST_ACCEPTED) == true ) {
            // forward to welcome or to booked page
            dsd_const_string hstr_next = ads_session->ads_config->ach_site_after_auth; // default welcome page:
            ds_hstring hstr_temp( ads_session->ads_wsp_helper );
			bool bol_use_default = true;
            if ( ads_session->dsc_auth.m_check_state( ST_FORCE_SSA_PAGE ) == false ) {
                if ( (hstr_temp=ads_session->dsc_auth.m_get_bookedpage()).m_get_len() > 0 ) {
                    // user has requested a special page:
                    hstr_next = hstr_temp.m_const_str();
                    ads_session->dsc_auth.m_set_bookedpage( NULL, 0 );
					bol_use_default = false;
                } else if ( (hstr_temp=ads_session->dsc_auth.m_get_welcomepage()).m_get_len() > 0 ) {
                    // user has his own welcome page:
                    hstr_next = hstr_temp.m_const_str();
					bol_use_default = false;
                }
            }
			if(bol_use_default && ads_session->dsc_auth.m_has_default_portlet()) {
				ads_session->dsc_auth.m_get_default_portlet(&hstr_temp);
				hstr_temp.m_insert_zeroterm(0, "#");
				hstr_temp.m_insert(0, hstr_next.m_get_ptr(), hstr_next.m_get_len());
				hstr_next = hstr_temp.m_const_str();
			}
            dsd_const_string dsl_cookie(hstr_cookie.m_const_str());
            hstr_location = m_create_location(hstr_next, dsd_const_string(), false, false, &dsl_cookie);
        } else {
            // forward to quaratine page:
            ads_session->dsc_auth.m_set_state(ST_COMPLCHECK_FORCE);
            dsd_const_string dsl_cookie(hstr_cookie.m_const_str());
            hstr_location = m_create_location(QUARANTINE_HSL, dsd_const_string(), false, false, &dsl_cookie);
        }
		
	    HL_DBG_PRINTF("m_handle_login_post 4 hstr_cookie_string=%.*s\n", hstr_cookie_string.m_get_len(), hstr_cookie_string.m_get_ptr());
        dsd_const_string dsl_cookie(hstr_cookie_string.m_const_str());
        dsd_const_string dsl_location(hstr_location.m_const_str());
        m_create_resp_header( ds_http_header::ien_status_found, 0, &dsl_location, NULL, &dsl_cookie, false, NULL, 42 );
        ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
        return;

    //---------------------------------------
    // error while authentication:
    //---------------------------------------
    } else if ( bo_auth_called == true ) {
        //-----------------------------------
        // send login page again:
        //-----------------------------------
        m_file_proc(ds_path, NULL);

        // reset saved username and domain
#ifdef B20140805
        ads_session->achc_username    = NULL;
        ads_session->inc_len_username = 0;
        ads_session->achc_domain      = NULL;
        ads_session->inc_len_domain   = 0;
		ads_session->achc_userdn      = NULL;
        ads_session->inc_len_userdn   = 0;
#else
		ads_session->dsc_username.m_reset();
		ads_session->dsc_domain.m_reset();
		ads_session->dsc_userdn.m_reset();
#endif
        return;
    }

    //---------------------------------------
    // everything else is a logout:
    //---------------------------------------
    ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                        "HIWSI523I: LOGOFF received -> forward to logout page" );
    m_forward_to_logout( dsd_const_string::m_null(), 0, 0 );

    // reset saved username and domain
#ifdef B20140805
    ads_session->achc_username    = NULL;
    ads_session->inc_len_username = 0;
    ads_session->achc_domain      = NULL;
    ads_session->inc_len_domain   = 0;
	ads_session->achc_userdn      = NULL;
    ads_session->inc_len_userdn   = 0;
#else
	ads_session->dsc_username.m_reset();
	ads_session->dsc_domain.m_reset();
	ads_session->dsc_userdn.m_reset();
#endif
    return;
} // end of ds_webserver::m_handle_login_post

/** \brief Logs out a user
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_handle_logout_post
 * Removes session attributes
*/
void ds_webserver::m_handle_logout_post()
{
    m_forward_to_logout( dsd_const_string::m_null(), 0, 0 );
    
    const char       *achl_lang;              // language name
    int        inl_len_lang;            // length of language
    m_get_query_value(POST_LANG, &achl_lang, &inl_len_lang);
    if(inl_len_lang > 0) {
        int in_lang = RESOURCES->m_parse_lang( achl_lang, inl_len_lang );
        if ( in_lang > LANGUAGE_NOT_SET ) {
             ads_session->dsc_auth.m_set_lang( in_lang );
             ads_session->dsc_control.in_cma_lang = in_lang;
        }
    }

	 this->m_logout_self();
    return;
} // end of ds_webserver::m_handle_logout_post

void ds_webserver::m_logout_self() {
    ads_session->dsc_auth.m_logout();

    // reset saved username and domain
#ifdef B20140805
	ads_session->achc_username    = NULL;
    ads_session->inc_len_username = 0;
    ads_session->achc_domain      = NULL;
    ads_session->inc_len_domain   = 0;
	ads_session->achc_userdn      = NULL;
    ads_session->inc_len_userdn   = 0;
#else
	ads_session->dsc_username.m_reset();
	ads_session->dsc_domain.m_reset();
	ads_session->dsc_userdn.m_reset();
#endif
}

/*! \brief Disconnect Handler
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_handle_disconnect_post
*/
void ds_webserver::m_handle_disconnect_post()
{
    // inititialize some variables:
    ds_wsp_admin dsl_admin;                 // wsp admin class

    dsl_admin.m_init( ads_session->ads_wsp_helper, ads_query );

    dsl_admin.m_disc_session();
        
    
    //-----------------------------------
    // handle all other param like a 
    // normal template post:
    //-----------------------------------
    m_handle_template_post();
} // end of ds_webserver::m_handle_disconnect_post


/*! \brief User Logout Handler
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_handle_usr_logout_post
 * admin logout a user and disconnect all user sessions
 *
 * we have decided to logout all user with the same name
 * means if multiple login is allowed and the user "guest"
 * is logged in twice, both users "guest" will be logged out.
*/
void ds_webserver::m_handle_usr_logout_post()
{
    //---------------------------------------------
    // get logout user:
    //---------------------------------------------
    m_logout_usr();

    //---------------------------------------
    // handle all other param like a normal
    // template post:
    //---------------------------------------
    m_handle_template_post();
} // end of ds_webserver::m_handle_usr_logout_post


/*! \brief Logout user via index
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_logout_usr
 * logout user with given user index
*/
void ds_webserver::m_logout_usr()
{
    // initialize some variables:
    const char*            ach_value;             // post value
    int              in_len;                // length of post value
    int              in_pos    = 0;         // position of value (might be present multiple times)
    bool             bol_ret;               // return from several function calls
    ds_usercma       dsl_usrcma;            // user cma class
    ds_authenticate  dsl_auth;              // authentication class
    dsd_auth_t       dsl_input;             // authentication structure
    char             *achl_domain;          // user domain
    int              inl_rlen;              // length user domain
    char             *achl_user;            // user name
    int              inl_ulen;              // length user name
    char             *achl_session;         // session number
    int              inl_slen;              // length session number
    int              inl_session;           // session number
    char             chrl_buffer[D_MAXCMA_NAME];    // cma name
    int              inl_blen;              // length of buffer

    //---------------------------------------
    // init usercma, admin and auth class:
    //---------------------------------------
    dsl_usrcma.m_init( ads_session->ads_wsp_helper );
    dsl_auth.m_init  ( ads_session->ads_wsp_helper );

    //---------------------------------------
    // loop through all send values:
    //---------------------------------------
    do {
        in_pos = m_get_query_value( POST_LOGOUT_USR,
                                    &ach_value, &in_len, in_pos );
        if (    ach_value == NULL
             || in_len       < 1
             || in_pos      == -1   ) {
            break;
        }
        in_pos++;

        // get username, domain and session number:
        m_split( ach_value, in_len, &achl_domain, &inl_rlen,
                 &achl_user, &inl_ulen, &achl_session, &inl_slen );
        if ( inl_ulen < 1 || inl_slen < 1 ) {
            continue;
        }

        // create main cma name:
        inl_session = atoi( achl_session );
        inl_blen = ds_usercma::m_create_name( achl_user, inl_ulen,
                                              achl_domain, inl_rlen,
                                              dsd_cma_session_no((unsigned char)inl_session),
                                              chrl_buffer, D_MAXCMA_NAME );
        if ( inl_blen < 1 ) {
            continue;
        }

        // check if user cma exists:
        int inl_ret = ds_usercma::m_exists_user( ads_session->ads_wsp_helper,
                                             chrl_buffer, inl_blen );
        if ( inl_ret > 0 ) {
            dsl_usrcma.m_set_name( chrl_buffer, inl_blen );

            // setup input for end session call:
            memset( &dsl_input, 0, sizeof(dsd_auth_t) );
            dsl_input.adsc_out_usr = &dsl_usrcma;
            dsl_input.avc_usrfield = (void*)ads_session;
            dsl_input.amc_callback = &m_auth_callback;
            
            // logout user and delete cma:
            bol_ret = dsl_auth.m_end_session( &dsl_input );
            if ( bol_ret == false ) {
                if ( inl_rlen > 0 ) {
                    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
                            "HIWSW901W: forced logout for group=%.*s userid=%.*s failed.",
                            inl_rlen, achl_domain, inl_ulen, achl_user );

                } else {
                    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
                            "HIWSW901W: forced logout for userid=%.*s failed.",
                            inl_ulen, achl_user );
                }
            }
        }
    } while ( in_len > 0 );
} // end of ds_webserver::m_logout_usr


/*! \brief Splitter function
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_split
 * splits a given path
*/
void ds_webserver::m_split( const char *achp_word, int inp_wlen,
                            char **aachp_p1, int *ainp_p1len,
                            char **aachp_p2, int *ainp_p2len,
                            char **aachp_p3, int *ainp_p3len )
{
    // initialize some variables:
    int inl_pos;

    *ainp_p1len = 0;
    *ainp_p2len = 0;
    *ainp_p3len = 0;

    *aachp_p1 = (char*)&achp_word[0];
    for ( inl_pos = 0; inl_pos < inp_wlen; inl_pos++ ) {
        if ( achp_word[inl_pos] == '/' ) {
            break;
        }
        (*ainp_p1len)++;
    }
    inl_pos++;
    if ( inl_pos == inp_wlen ) {
        return;
    }

    *aachp_p2 = (char*)&achp_word[inl_pos];
    for ( ; inl_pos < inp_wlen; inl_pos++ ) {
        if ( achp_word[inl_pos] == '/' ) {
            break;
        }
        (*ainp_p2len)++;
    }
    inl_pos++;
    if ( inl_pos == inp_wlen ) {
        return;
    }

    *aachp_p3   = (char*)&achp_word[inl_pos];
    *ainp_p3len = inp_wlen - inl_pos;
} // end of ds_webserver::m_split


/*! \brief Admin post handler
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_handle_admin_post
*/
void ds_webserver::m_handle_admin_post()
{
    // inititialize some variables:
    const char*               achl_lang;                  // lang value of post
    int                 inl_len_lang;               // length of lang value
    int                 inl_lang;                   // language key
    ds_hstring          ds_tmp;
    
    //-------------------------------------------
    // is this a language post?
    //-------------------------------------------
    m_get_query_value( POST_LANG,
                       &achl_lang, &inl_len_lang );
    if ( inl_len_lang > 0 ) {
        inl_lang = RESOURCES->m_parse_lang( achl_lang, inl_len_lang );
        if ( inl_lang > LANGUAGE_NOT_SET ) {
             ads_session->dsc_auth.m_set_lang( inl_lang );
             ads_session->dsc_control.in_cma_lang = inl_lang;
        }

        //---------------------------------------
        // send location moved header:
        //---------------------------------------
        ds_tmp.m_init( ads_session->ads_wsp_helper );
        ds_tmp = m_create_location( ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_const_str(),
                                    ads_session->dsc_http_hdr_in.dsc_url.hstr_query );
        dsd_const_string dsl_location(ds_tmp.m_const_str());
        m_create_resp_header( ds_http_header::ien_status_found,
                              0, &dsl_location, NULL, NULL, false, NULL );
        ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
        return;
    }

    //-------------------------------------------
    // call file proc:
    //-------------------------------------------
    m_file_proc( ds_path, NULL );
    return;
} // end of ds_webserver::m_handle_admin_post


/*! \brief Handles template posts
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_handle_template_post
*/
void ds_webserver::m_handle_template_post()
{
    // inititialize some variables:
    int                 in_size;                                    // number of possible post params
    int                 in_element;                                 // current element of post param array
    const char*         ach_value;                                  // value of post
    int                 in_len_val;                                 // length of value
    ied_tmp_post_params ien_param;                                  // type of param
    int                 in_value;                                   // value as int
    ds_hstring          ds_tmp;
    
    //-----------------------------------
    // init some classes:
    //-----------------------------------
    ds_tmp.m_init( ads_session->ads_wsp_helper );
        
    //-----------------------------------
    // get number of allowed post params:
    //-----------------------------------
    in_size = (int)(sizeof(ach_tmp_post_params)/sizeof(ach_tmp_post_params[0]));
    
	dsd_const_string dsl_cookie_domain;
	dsd_const_string dsl_cookie_path;
	dsd_const_string dsl_cookie_name;
    //-----------------------------------
    // handle all allowed post params:
    //-----------------------------------
    for ( in_element = 0; in_element < in_size; in_element++ ) {
        m_get_query_value( ach_tmp_post_params[in_element],
                           &ach_value, &in_len_val );
        
        //-------------------------------
        // a value is found -> eval it
        //-------------------------------
        if ( in_len_val > 0 ) {
            ien_param = (ied_tmp_post_params)in_element;

            switch ( ien_param ) {
                /*
                    set language
                */
                case ied_post_language:
                    in_value = RESOURCES->m_parse_lang( ach_value, in_len_val );
                    if ( in_value > LANGUAGE_NOT_SET ) {
                         ads_session->dsc_auth.m_set_lang( in_value );
                         ads_session->dsc_control.in_cma_lang = in_value;
                    }
                    break;
				case ied_post_cookie_domain:
					dsl_cookie_domain = dsd_const_string(ach_value, in_len_val);
					break;
				case ied_post_cookie_path:
					dsl_cookie_path = dsd_const_string(ach_value, in_len_val);
					break;
				case ied_post_cookie_name:
					dsl_cookie_name = dsd_const_string(ach_value, in_len_val);
					break;
                /*
                    delete cookie:
                */
                case ied_post_rm_cookie: {
                    ads_session->dsc_ws_gate.dsc_ck_manager.m_delete_cookie(
                        ads_session->dsc_auth.m_get_basename(),
						dsl_cookie_domain, dsl_cookie_path, dsl_cookie_name);
                    break;
				}
                /*
                    password will expire posts:
                */
                case ied_post_change_pwd_now: {
                    ds_tmp = m_create_location( CHANGE_PWD_PAGE, dsd_const_string(NULL, 0) );
                    dsd_const_string dsl_location(ds_tmp.m_const_str());
                    m_create_resp_header( ds_http_header::ien_status_found,
                                          0, &dsl_location, NULL, NULL, false, NULL );
                    ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
					ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
                    return;
                }
                case ied_post_change_pwd_later:
                    ads_session->dsc_auth.m_reset_pwd_expires();
                    break;
            }
        } // end of if ( in_len_val > 0 )
    } // end of for

    //-----------------------------------
    // send location moved header:
    //-----------------------------------
    ds_tmp = m_create_location( ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_const_str(),
                                ads_session->dsc_http_hdr_in.dsc_url.hstr_query );
    dsd_const_string dsl_location(ds_tmp.m_const_str());
    m_create_resp_header( ds_http_header::ien_status_found,
                          0, &dsl_location, NULL, NULL, false, NULL );
    ads_session->dsc_transaction.m_send_header( ied_sdh_dd_toclient );
	ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
} // end of ds_webserver::m_handle_template_post



/*! \brief Handles jwt sa request
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_handle_jwtsa_request
*/
void ds_webserver::m_handle_jwtsa_request()
{
	/* hofmants: modify JWT.jnlp and send it */
    m_setup_encoding_string( ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_const_str() );
	m_file_proc( ds_path, NULL );
}


void ds_webserver::m_handle_webtermrdp_request()
{
    m_setup_encoding_string( ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_const_str() ); /* html */
	m_file_proc( ds_path, NULL );
}


/*! \brief Gets the type of a given task
 *
 * @ingroup webserver
 *
 * private function ds_webserver::m_get_settings_task
 * get type for given command
 *
 * @param[in]   const char* ach_task        pointer to task
 * @param[in]   int         in_len          length of task
 * @return      int                         command key
*/
int ds_webserver::m_get_settings_task( const char* ach_task, int in_len )
{
    int inl_size = (int)(sizeof(ach_settings_tasks)/sizeof(ach_settings_tasks[0]));
    dsd_const_string dsl_task(ach_task, in_len);
    for ( int inl_pos = 0; inl_pos < inl_size; inl_pos++ ) {
        if(dsl_task.m_equals(ach_settings_tasks[inl_pos]))
            return inl_pos;
    }

    return -1;
} // end of ds_webserver::m_get_settings_task


/*! \brief Return check results to browser
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_handle_quaratine_post
 *
 * Ticket[16992]:
 * Quarantine: browser asks the result of checkings
 * ->  send him the status and/or send im a forward page
 *     site_after_auth (or a  bookmarked site)
*/
void ds_webserver::m_handle_quaratine_post()
{
    // initialize some variables:
    const char*      ach_value;                                   // post value
    int        in_len_value;                                // length of post value
    ds_hstring hstr_xml    ( ads_session->ads_wsp_helper ); // output buffer
    
    //--------------------------------------------
    // check for valid POST value
    // (quarantine=GetStatus)
    //--------------------------------------------
    m_get_query_value( QUARANTINE, &ach_value, &in_len_value );
    if (!dsd_const_string(ach_value, in_len_value).m_equals("GetStatus")) {
        return;
    }

    //--------------------------------------------
    // create answer:
    //--------------------------------------------
    hstr_xml.m_write( "<?xml version='1.0' encoding='UTF-8' ?>" );
    hstr_xml.m_write( "<quarantine>" );

    //--------------------------------------------
    // check for error:
    //--------------------------------------------
    if ( ads_session->dsc_auth.m_check_state(ST_COMPLCHECK_ERROR) == true ) {
        hstr_xml.m_write( "<error>YES</error>" );
    }

    dsd_const_string hstr_next; // next page
    ds_hstring hstr_temp( ads_session->ads_wsp_helper ); // temp page
    //--------------------------------------------
    // forward to page:
    //--------------------------------------------
    if ( ads_session->dsc_auth.m_check_state(ST_ACCEPTED) == true  ) {
        /*
            forward to welcome or to booked page
        */
        // default welcome page:
        hstr_next = ads_session->ads_config->ach_site_after_auth;
        if ( ads_session->dsc_auth.m_check_state( ST_FORCE_SSA_PAGE ) == false ) {
            if ( (hstr_temp=ads_session->dsc_auth.m_get_bookedpage()).m_get_len() > 0 ) {
                // user has requested a special page:
                hstr_next = hstr_temp.m_const_str();
                ads_session->dsc_auth.m_set_bookedpage( NULL, 0 );
            } else if ( (hstr_temp=ads_session->dsc_auth.m_get_welcomepage()).m_get_len() > 0 ) {
                // user has his own welcome page:
                hstr_next = hstr_temp.m_const_str();
            }
        }
    } 
#if 0  // anti-split-tunnel deactivated, Jun 2017 [#49556]
    else if ( ads_session->dsc_auth.m_check_state(ST_COMPLCHECK_INSTALL) == true ) {
        /*
            forward to installation page:
        */
        hstr_next = INSTALL_AST_HTML;
    }
#endif

    // insert forward:
    if ( hstr_next.m_get_len() > 0 ) {
        hstr_xml.m_write("<forward>");
        hstr_xml.m_write_xml_text(hstr_next);
        hstr_xml.m_write("</forward>");
    }

    //--------------------------------------------
    // end xml:
    //--------------------------------------------
    hstr_xml.m_write( "</quarantine>" );
                

    //--------------------------------------------
    // send answer:
    //--------------------------------------------
    hstr_my_encoding = "text/xml";
    m_create_resp_header( ds_http_header::ien_status_ok, hstr_xml.m_get_len(),
                          NULL, NULL, NULL, false, NULL, HDR_MODE_CONTENT_LENGTH );
    ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
	ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_sending_to_browser);
    ads_session->dsc_transaction.m_send_complete_file( &hstr_xml, ied_sdh_dd_toclient );
	ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
} // end of ds_webserver::m_handle_quaratine_post


/*! \brief Handle ICA post
 *
 * @ingroup webserver
 *
 * private method ds_webserver::m_handle_ica_post
 *  receive ica integration information
 *
 * @param[in]   int  iep_url
*/
void ds_webserver::m_handle_ica_post( int iep_url )
{
	dsd_const_string dsl_message;
    switch ( (enum ied_post_urls)iep_url ) {
        case ied_posturl_ica_port: {
			const char *achl_port;
			int inl_length;
            m_get_query_value( "port", &achl_port, &inl_length );

            if ( inl_length > 0 ) {
                ds_hstring dsl_port( ads_session->ads_wsp_helper );
                dsl_port.m_write( achl_port, inl_length );
			    int inl_port;
                bool bol_ret = dsl_port.m_conv_int( &inl_port );
                if (    bol_ret  == true
                     && inl_port  > 0
                     && inl_port  < 65535 ) {
                    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
                                                         "HIWSI348I received ica port %d from wsp-passtrough",
                                                         inl_port );
                    ads_session->dsc_auth.m_set_ica_port( inl_port );
                }
				dsl_message = "Port saved!";
            } else {
                if ( ads_session->dsc_auth.m_get_ica_port() > 0 ) {
					dsl_message = "Port received!";
                } else {
                    dsl_message = "Port not yet received!";
                }
            }

            //m_file_proc(ds_path);
            break;
		}
        case ied_posturl_ica_close: {
            ads_session->dsc_auth.m_decrease_ica_count();
			dsl_message = "closed";
            break;
		}
        case ied_posturl_ica_alive:
            if ( ads_session->dsc_auth.m_is_ica_active() == true ) {
                dsl_message = "open";
            } else {
                dsl_message = "closed";
            }
            break;
		default:
			return;
    }
	m_create_resp_header( ds_http_header::ien_status_ok, dsl_message.m_get_len(),
                            NULL, NULL, NULL, false, NULL, HDR_MODE_CONTENT_LENGTH );
    ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
	ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_sending_to_browser);
	ads_session->dsc_transaction.m_send_complete_file( dsl_message.m_get_ptr(), dsl_message.m_get_len(), false, ied_sdh_dd_toclient );
	ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
    return;
} // end of ds_webserver::m_handle_ica_port_post


/*! \brief Handles password change request
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_handle_change_pwd_post
 * change user password post
*/
void ds_webserver::m_handle_change_pwd_post()
{
    // initialize some variables:
    const char       *achl_lang;              // language name
    int        inl_len_lang;            // length of language
    int        inl_lang;                // language key
    const char       *achl_new;               // new password
    int        inl_len_new;             // length of new password
    const char       *achl_conf;              // confirmation of new password
    int        inl_len_conf;            // length of confirmation
    const char       *achl_old;               // old password
    int        inl_len_old;             // length of old password
    ds_hstring dsl_next;                // for location moved
	HL_UINT    uinl_auth;               // return of change password

    /*
        read needed parameters:
    */
    m_get_query_value( POST_LANG,     &achl_lang, &inl_len_lang );
    m_get_query_value( NEW_PASSWORD,  &achl_new,  &inl_len_new  );
    m_get_query_value( CONF_PASSWORD, &achl_conf, &inl_len_conf );
    m_get_query_value( OLD_PASSWORD,  &achl_old,  &inl_len_old  );


    /*
        check for change language:
    */
    if ( inl_len_lang > 0 ) {
        inl_lang = RESOURCES->m_parse_lang( achl_lang, inl_len_lang );
        if ( inl_lang > LANGUAGE_NOT_SET ) {
             ads_session->dsc_auth.m_set_lang( inl_lang );
             ads_session->dsc_control.in_cma_lang = inl_lang;
        }
        m_file_proc(ds_path, NULL);
        return;
    }

    /*
        check if old and new password are given:
    */
    if (    inl_len_old < 1
         || inl_len_new < 1 ) {
        ads_session->dsc_auth.m_set_msg( 0, 0, MSG_INV_INPUT, CHANGE_PWD_PAGE );
        m_file_proc(ds_path, NULL);
        return;
    }

    /*
        check if confirmation equals new password
    */
    if (    inl_len_conf != inl_len_new
         || memcmp(achl_conf, achl_new, inl_len_new) != 0 ) {
        ads_session->dsc_auth.m_set_msg( 0, 0, MSG_PWD_NOT_EQ, CHANGE_PWD_PAGE );
        m_file_proc(ds_path, NULL);
        return;
    }

    /*
        change the password
    */
	uinl_auth = ads_session->dsc_auth.m_change_password( achl_old, inl_len_old,
                                                         achl_new, inl_len_new );
	if ( (uinl_auth & AUTH_FAILED) == AUTH_FAILED ) {
		if ( ((uinl_auth & AUTH_METH_LDAP) == AUTH_METH_LDAP ) || 
				((uinl_auth & AUTH_METH_DYN_LDAP) == AUTH_METH_DYN_LDAP) ) {
			if ( (uinl_auth & AUTH_ERR_LDAP_UNWILL_TO_PERFORM) == AUTH_ERR_LDAP_UNWILL_TO_PERFORM ) {
				ads_session->dsc_auth.m_set_msg( 0, 0, MSG_LDAP_UNWILL_TO_PERFORM, CHANGE_PWD_PAGE );
			} else if ( (uinl_auth & AUTH_ERR_LDAP_INV_CRED) == AUTH_ERR_LDAP_INV_CRED ) {
				ads_session->dsc_auth.m_set_msg( 0, 0, MSG_LDAP_INV_CRED, CHANGE_PWD_PAGE );
			} else {
				ads_session->dsc_auth.m_set_msg( 0, 0, MSG_CHANGE_PWD_FAILED, CHANGE_PWD_PAGE );
			}
		}
		else {
			ads_session->dsc_auth.m_set_msg( 0, 0, MSG_CHANGE_PWD_FAILED, CHANGE_PWD_PAGE );
		}
        m_file_proc(ds_path, NULL);
        return;
    }

    /*
        forward to welcome page
    */
    dsl_next = m_create_location( ads_session->ads_config->ach_site_after_auth, dsd_const_string() );
    dsd_const_string dsl_location(dsl_next.m_const_str());
    m_create_resp_header(ds_http_header::ien_status_found, 0, &dsl_location, NULL, NULL, false, NULL);
    ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
	ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
    return;
} // end of ds_webserver::m_handle_change_pwd_post


/*! \brief Change user settings
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_handle_settings_post
 * change user settings post
*/
void ds_webserver::m_handle_settings_post()
{
    // initialize some variables:
    const char*                       achl_lang;                          // language post value
    int                         inl_len_lang;                       // length of language post value
    int                         inl_lang = LANGUAGE_NOT_SET;        // language key
    dsd_query*                  adsl_query;                         // current query param/value pair
    ds_bookmark                 dsl_bmark;                          // bookmark
    ds_hvector<ds_bookmark>     dsl_vwsg_bmarks;                    // wsg bookmarks
    ds_hvector<ds_bookmark>     dsl_rdvpn_bmarks;                   // rdvpn (user portal) bookmarks
#if SM_USE_OWN_WFA_BOOKMARKS    
    dsd_wfa_bmark               dsl_wfa_bmark;                      // wfa bookmark
    ds_hvector<dsd_wfa_bmark>   dsl_vwfa_bmarks;                    // wfa bookmarks
#endif
    ds_workstation              dsl_wstat;                          // single workstation
    ds_hvector<ds_workstation>  dsl_vwstats;                        // dod workstations
    ds_portlet                  dsl_portlet;                        // current portlet
    ds_hvector<ds_portlet>      dsl_vportlets;                      // portlets
    int                         inl_temp;                           // temp variable
    bool                        bol_ret;                            // return for several function calls
    ied_settings_tasks          ien_set_task = ied_set_task_unset;  // settings task (edit, add, delete)
    BOOL                        bol_show_flyer = TRUE;              // show wsg flyer?
    ds_hstring                  dsl_location;                       // forward to
    ds_hstring                  dsl_def_portlet;                    // name of default opened portlet

    //-------------------------------------------
    // init some classes:
    //-------------------------------------------
    dsl_bmark.m_init       ( ads_session->ads_wsp_helper );
    dsl_location.m_init    ( ads_session->ads_wsp_helper );
    dsl_def_portlet.m_setup( ads_session->ads_wsp_helper );
    dsl_vwsg_bmarks.m_setup( ads_session->ads_wsp_helper );
    dsl_rdvpn_bmarks.m_setup ( ads_session->ads_wsp_helper );
#if SM_USE_OWN_WFA_BOOKMARKS
    dsl_wfa_bmark.m_init   ( ads_session->ads_wsp_helper );
    dsl_vwfa_bmarks.m_setup( ads_session->ads_wsp_helper );
#endif
    dsl_wstat.m_init       ( ads_session->ads_wsp_helper );
    dsl_vwstats.m_setup    ( ads_session->ads_wsp_helper );
    dsl_portlet.m_init     ( ads_session->ads_wsp_helper );
    dsl_vportlets.m_setup  ( ads_session->ads_wsp_helper );

    //-------------------------------------------
    // check for a change language post:
    //-------------------------------------------
    m_get_query_value( POST_LANG,
                       &achl_lang, &inl_len_lang );
    if (    achl_lang   != NULL
         && inl_len_lang > 0    ) {
        return m_handle_template_post();
    }

    //-------------------------------------------
    // loop through all query:
    //-------------------------------------------
    adsl_query = ads_query;
    while ( adsl_query != NULL ) {

        /*
            wsg bookmark:
        */
        if ( adsl_query->ds_name.m_equals( PARAM_WSG_BMARK ) ) {
            if ( dsl_bmark.m_is_complete() ) {
                dsl_bmark.m_set_own( true );
                dsl_vwsg_bmarks.m_add( dsl_bmark );
                dsl_bmark.m_reset();
            }
        } else if ( adsl_query->ds_name.m_equals( PARAM_RDVPN_BMARK ) ) {
            if ( dsl_bmark.m_is_complete() ) {
                dsl_bmark.m_set_own( true );
                dsl_rdvpn_bmarks.m_add( dsl_bmark );
                dsl_bmark.m_reset();
            }

#if SM_USE_OWN_WFA_BOOKMARKS
        /*
            wfa bookmark:
        */
        } else if ( adsl_query->ds_name.m_equals( PARAM_WFA_BMARK ) ) {
            if ( dsl_wfa_bmark.m_is_complete() ) {
                dsl_wfa_bmark.m_set_own( true );
                dsl_vwfa_bmarks.m_add( dsl_wfa_bmark );
                dsl_wfa_bmark.m_reset();
            }
#endif
        } else if ( adsl_query->ds_name.m_equals( PARAM_BMARK_NAME ) ) {
            dsd_const_string dsl_bmark_name(adsl_query->ds_value.m_const_str());
            dsl_bmark_name.m_trim(" ");
            //do NOT save name html-escaped: double escaped when generating hsl page, not necessary for saving as xml
            dsl_bmark.m_set_name( dsl_bmark_name.m_get_ptr(), dsl_bmark_name.inc_length);
#if SM_USE_OWN_WFA_BOOKMARKS
            dsl_wfa_bmark.m_set_name( dsl_bmark_name.m_get_ptr(), dsl_bmark_name.inc_length);
#endif
        } else if ( adsl_query->ds_name.m_equals( PARAM_BMARK_URL ) ) {
            dsl_bmark.m_set_url( adsl_query->ds_value.m_get_ptr(),
                                 adsl_query->ds_value.m_get_len() );
#if SM_USE_OWN_WFA_BOOKMARKS
			dsl_wfa_bmark.m_set_url(adsl_query->ds_value.m_get_ptr(),
                                 adsl_query->ds_value.m_get_len() );
#endif
        /*
            workstation name:
        */
        } else if ( adsl_query->ds_name.m_equals( PARAM_WSTAT_NAME ) ) {
            dsd_const_string dsl_wstat_name(adsl_query->ds_value.m_const_str());
            dsl_wstat_name.m_trim(" ");
            dsl_wstat.m_set_name( dsl_wstat_name.m_get_ptr(),
                                  dsl_wstat_name.m_get_len() );

        /*
            workstation ineta:
        */
        } else if ( adsl_query->ds_name.m_equals( PARAM_WSTAT_INETA ) ) {
            dsl_wstat.m_set_ineta( adsl_query->ds_value.m_get_ptr(),
                                   adsl_query->ds_value.m_get_len() );

        /*
            workstation port:
        */
        } else if ( adsl_query->ds_name.m_equals( PARAM_WSTAT_PORT ) ) {
            bol_ret = adsl_query->ds_value.m_to_int( &inl_temp );
            if (    bol_ret == true 
                 && inl_temp > -1   ) {
                dsl_wstat.m_set_port( inl_temp );
            }

        /*
            workstation mac:
        */
        } else if ( adsl_query->ds_name.m_equals( PARAM_WSTAT_MAC ) ) {
            dsl_wstat.m_set_mac( adsl_query->ds_value.m_get_ptr(),
                                 adsl_query->ds_value.m_get_len() );

        /*
            workstation timeout:
        */
        } else if ( adsl_query->ds_name.m_equals( PARAM_WSTAT_TOUT ) ) {
            bol_ret = adsl_query->ds_value.m_to_int( &inl_temp );
            if (    bol_ret  == true
                 && inl_temp > 0     ) {
                dsl_wstat.m_set_wait( inl_temp );
            }

        /*
            dod workstation:
        */
        } else if ( adsl_query->ds_name.m_equals( PARAM_DOD_WSTAT ) ) {
            if ( dsl_wstat.m_is_complete() ) {
                dsl_vwstats.m_add( dsl_wstat );
                dsl_wstat.m_reset();
            }

        /*
            portlet name:
        */
        } else if ( adsl_query->ds_name.m_equals( PARAM_PORTLET ) ) {
            dsl_portlet.m_set_name( adsl_query->ds_value.m_get_ptr(),
                                    adsl_query->ds_value.m_get_len() );

        /*
            portlet state:
        */
        } else if ( adsl_query->ds_name.m_starts_with( PARAM_PORTLET_STATE ) ) {
            bol_ret = adsl_query->ds_value.m_to_int( &inl_temp );
            if (    bol_ret   == true
                 && inl_temp  >  -1   ) {
                dsl_portlet.m_set_open( inl_temp==1?true:false );

                if ( dsl_portlet.m_is_complete() ) {
                    dsl_vportlets.m_add( dsl_portlet );
                    dsl_portlet.m_reset();
                }
            }

        /*
            save language:
        */
        } else if ( adsl_query->ds_name.m_equals( PARAM_SAVE_LANG ) ) {
            inl_lang = RESOURCES->m_parse_lang( adsl_query->ds_value.m_get_ptr(),
                                                adsl_query->ds_value.m_get_len() );

        /*
            wsg flyer:
        */
        } else if ( adsl_query->ds_name.m_equals( PARAM_WSG_FLYER ) ) {
            bol_ret = adsl_query->ds_value.m_to_int( &bol_show_flyer );

        /*
            default portlet:
        */
        } else if ( adsl_query->ds_name.m_equals( PARAM_DEFAULT_PORTLET ) ) {
            dsl_def_portlet.m_set(adsl_query->ds_value);
        /*
            settings task:
        */
        } else if ( adsl_query->ds_name.m_equals( PARAM_SET_TASK ) ) {
            ien_set_task = (ied_settings_tasks)m_get_settings_task( adsl_query->ds_value.m_get_ptr(),
                                                                    adsl_query->ds_value.m_get_len() );
        }

        //---------------------------------------
        // get next query:
        //---------------------------------------
        adsl_query = adsl_query->ads_next;
    }

    switch ( ien_set_task ) {
        case ied_set_task_edit:
            //-----------------------------------
            // save settings in cma:
            //-----------------------------------
            if (    ads_session->dsc_auth.m_is_portlet_allowed(achg_known_portlets[ied_wsg_portlet])
                 && ads_session->dsc_auth.m_is_config_allowed (DEF_UAC_WSG_BMARKS)                   ) {
                bol_ret = ads_session->dsc_auth.m_set_own_wsg_bookmarks( &dsl_vwsg_bmarks );
                if ( bol_ret == false ) {
                    ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning,
                                        "HIWSW902W: edit wsg bookmarks failed" );
                }
            }
            if (    ads_session->dsc_auth.m_is_config_allowed (DEF_UAC_RDVPN_BMARKS)                   ) {
                bol_ret = ads_session->dsc_auth.m_set_own_rdvpn_bookmarks( &dsl_rdvpn_bmarks );
                if ( bol_ret == false ) {
                    ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning,
                                        "HIWSW907W: edit rdvpn bookmarks failed" );
                }
            }
#if SM_USE_OWN_WFA_BOOKMARKS
            if (    ads_session->dsc_auth.m_is_portlet_allowed(achg_known_portlets[ied_wfa_portlet])
                 && ads_session->dsc_auth.m_is_config_allowed (DEF_UAC_WFA_BMARKS)                   ) {
                bol_ret = ads_session->dsc_auth.m_set_own_wfa_bookmarks( &dsl_vwfa_bmarks );
                if ( bol_ret == false ) {
                    ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning,
                                        "HIWSW903W: edit wfa bookmarks failed" );
                }
            }
#endif

            if ( ads_session->dsc_auth.m_is_config_allowed(DEF_UAC_DOD) ) {
                bol_ret = ads_session->dsc_auth.m_set_workstations( &dsl_vwstats );
                if ( bol_ret == false ) {
                    ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning,
                                        "HIWSW905W: edit DoD workstations failed" );                    
                }
            }

            if ( ads_session->dsc_auth.m_is_config_allowed(DEF_UAC_OTHERS) ) {
                bol_ret = ads_session->dsc_auth.m_set_portlets( &dsl_vportlets );
                if ( bol_ret == false ) {
                    ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning,
                                        "HIWSW906W: edit portlets failed" ); 
                }

                if ( inl_lang > LANGUAGE_NOT_SET ) {
                     ads_session->dsc_auth.m_set_lang( inl_lang );
                     ads_session->dsc_control.in_cma_lang = inl_lang;
                }

                ads_session->dsc_auth.m_set_flyer( bol_show_flyer ? true : false );
                if (dsl_def_portlet.m_get_len() > 0 ) {
                    ads_session->dsc_auth.m_set_default_portlet(dsl_def_portlet.m_get_ptr(), dsl_def_portlet.m_get_len());
                } else {
                    ads_session->dsc_auth.m_set_default_portlet(NULL, 0);
                }
            }


            //-----------------------------------
            // save settings in ldap:
            //-----------------------------------
            bol_ret = ads_session->dsc_auth.m_save_settings();
            if ( bol_ret == false ) {
                ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning,
                                    "HIWSW904W: saving usersettings in LDAP failed" );
            }
            break;
    }

    //-------------------------------------------
    // send location moved header:
    //-------------------------------------------
    if ( ads_session->dsc_auth.m_get_welcomepage().m_get_len() > 0 ) {
        // user has his own welcome page:
        dsl_location = m_create_location( ads_session->dsc_auth.m_get_welcomepage().m_const_str(),
                                          dsd_const_string() );
    } else {
        // default welcome page:
        dsl_location = m_create_location( ads_session->ads_config->ach_site_after_auth,
                                          dsd_const_string() );
    }
    dsd_const_string dsl_location2(dsl_location.m_const_str());
    m_create_resp_header( ds_http_header::ien_status_found,
                          0, &dsl_location2, NULL, NULL, false, NULL );
    ads_session->dsc_transaction.m_send_header( ied_sdh_dd_toclient );
	ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
} // end of ds_webserver::m_handle_settings_post

#if SM_USE_VIRTUAL_LINK
int ds_webserver::m_handle_virtual_link(const dsd_const_string& rdsp_path, bool bo_authenticated) {
	ds_http_header::status_codes iel_status_code = ds_http_header::ien_status_not_found;
	{
		dsd_const_string dsl_prefix("protected/");
		dsd_const_string dsl_path = rdsp_path;
		if(dsl_path.m_starts_with(dsl_prefix)) {
			if(!bo_authenticated) {
				iel_status_code = ds_http_header::ien_status_forbidden;
				goto LBL_SEND_ERROR;
		}
			dsl_path = dsl_path.m_substring(dsl_prefix.m_get_len());
			{
				dsd_const_string dsl_prefix("portlets/webterm/rdp/");
				if(dsl_path.m_starts_with(dsl_prefix)) {
					iel_status_code = (ds_http_header::status_codes)this->m_handle_virtual_protected_portlets_webterm_rdp(
						dsl_path.m_substring(dsl_prefix.m_get_len()));
					if(iel_status_code == 0)
						return 0;
					goto LBL_SEND_ERROR;
	}
			}
#if SM_USE_AUX_PIPE_STREAM
	{
		dsd_const_string dsl_prefix("stream/");
				if(dsl_path.m_starts_with(dsl_prefix)) {
					return this->m_handle_stream_link(dsl_path.m_substring(dsl_prefix.m_get_len()), bo_authenticated);
				}
			}
#endif
			{
				dsd_const_string dsl_prefix("session/");
				if(dsl_path.m_starts_with(dsl_prefix)) {
					iel_status_code =  (ds_http_header::status_codes)this->m_handle_virtual_protected_session(dsl_path.m_substring(dsl_prefix.m_get_len()));
					if(iel_status_code == 0)
						return 0;
					goto LBL_SEND_ERROR;
				}
			}
			goto LBL_SEND_ERROR;
		}
	}
	{
		dsd_const_string dsl_prefix("public/");
		dsd_const_string dsl_path = rdsp_path;
		if(dsl_path.m_starts_with(dsl_prefix)) {
			dsl_path = dsl_path.m_substring(dsl_prefix.m_get_len());
			dsd_const_string dsl_prefix("portlets/webterm/rdp/");
			if(dsl_path.m_starts_with(dsl_prefix)) {
				iel_status_code = (ds_http_header::status_codes)this->m_handle_virtual_public_portlets_webterm_rdp(
					dsl_path.m_substring(dsl_prefix.m_get_len()), bo_authenticated);
				if(iel_status_code == 0)
					return 0;
				goto LBL_SEND_ERROR;
			}
#if 0
#if SM_USE_QUICK_LINK
			{
				dsd_const_string dsl_prefix("quicklink/");
				if(dsl_path.m_starts_with(dsl_prefix)) {
					return this->m_handle_quick_link(dsl_path.m_substring(dsl_prefix.m_get_len()), bo_authenticated);
		}
	}
#endif
#endif
			goto LBL_SEND_ERROR;
		}
	}
LBL_SEND_ERROR:
	ads_session->dsc_webserver.m_create_resp_header(iel_status_code,
		0, NULL, NULL, NULL, false, NULL);
	ads_session->dsc_transaction.m_send_header( ied_sdh_dd_toclient );
	ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
	return -1;
}
#endif /*SM_USE_VIRTUAL_LINK*/

#if SM_USE_QUICK_LINK
static int m_serialize_cma_string(char* achp_cma, int inp_offset, struct dsd_cma_string& rdsp_cma_string, const dsd_const_string rdsp_value) {
	rdsp_cma_string.inc_offset = inp_offset;
	rdsp_cma_string.inc_length = rdsp_value.m_get_len();
	memcpy(&achp_cma[inp_offset], rdsp_value.m_get_ptr(), rdsp_value.m_get_len());
	return inp_offset + rdsp_value.m_get_len();
}

#if 0
template<typename T> struct dsd_cma_ptr2;

#include <type_traits>

template<typename T> struct dsd_cma_ptr {
	int inc_offset;
public:
	dsd_cma_ptr() {
	}

	dsd_cma_ptr(int inp_offset) : inc_offset(inp_offset) {
	}

	template<typename U> dsd_cma_ptr(const dsd_cma_ptr<U>& rdsp_other) : inc_offset(rdsp_other.inc_offset) {
		static_assert(std::is_assignable<T, U>::value, "not assignable");
	}

	dsd_cma_ptr& operator=(const dsd_cma_ptr& rhs) {
		this->inc_offset = rhs.inc_offset;
		return *this;
	}

	dsd_cma_ptr& operator+=(int inp_dist) {
		this->inc_offset += inp_dist * sizeof(T);
		return *this;
	}

	dsd_cma_ptr2<T> map(void* base_addr) const {
		return dsd_cma_ptr2<T>(base_addr, this->inc_offset);
	}
};

template<typename T> struct dsd_cma_ptr2 : public dsd_cma_ptr<T> {
	void* base_addr;
public:
	dsd_cma_ptr2(void* base_addr) : dsd_cma_ptr<T>(), base_addr(base_addr) {
	}

	dsd_cma_ptr2(void* base_addr, int inp_offset) : dsd_cma_ptr<T>(inp_offset), base_addr(base_addr) {
	}

	operator T*() {
		return (T*)(((char*)this->base_addr) + this->inc_offset);
	}
};

struct dsd_datamodel_cma {
	template<typename T> struct ptr {
		typedef dsd_cma_ptr<T> rebind_t;
	};
};

struct dsd_datamodel_default {
	template<typename T> struct ptr {
		typedef T* rebind_t;
	};
};

template<typename M> struct dsd_datamodel_string
{
	typedef typename M::template ptr<const char*>::rebind_t x;
	typename M::template ptr<const char>::rebind_t achc_ptr;
	int inc_length;
	
	size_t m_get_extra_size() const {
		return inc_length;
	}
};

template<typename M, typename T> struct dsd_datamodel_slist {
	typename M::template ptr<T>::rebind_t adsc_head;
};


template<typename M> struct dsd_dm_webtermrdp_remoteapp2 {
	unsigned short usc_flags;
	struct dsd_datamodel_string<M> dsc_exe_or_file;
	struct dsd_datamodel_string<M> dsc_working_dir;
	struct dsd_datamodel_string<M> dsc_arguments;

	size_t m_get_extra_size() const {
		return dsc_exe_or_file.m_get_extra_size()
			+ dsc_working_dir.m_get_extra_size()
			+ dsc_arguments.m_get_extra_size();
	}
};

typedef dsd_dm_webtermrdp_remoteapp2<dsd_datamodel_default> dsd_webtermrdp_remoteapp_default;
typedef dsd_dm_webtermrdp_remoteapp2<dsd_datamodel_cma> dsd_webtermrdp_remoteapp_cma;
#endif

struct dsd_webtermrdp_remoteapp2 {
	unsigned short usc_flags;
	struct dsd_const_string dsc_exe_or_file;
	struct dsd_const_string dsc_working_dir;
	struct dsd_const_string dsc_arguments;
};

int ds_webserver::m_handle_virtual_public_portlets_webterm_rdp(const dsd_const_string& rdsp_path, bool bo_authenticated) {
	// TODO: Add JSON parser http://rapidjson.org/index.html
	ds_http_header::status_codes iel_status_code;

	ds_hstring dsl_tmp_query_in(ads_session->ads_wsp_helper);
	dsd_const_string dsl_query = this->m_get_query(dsl_tmp_query_in);
	ds_hstring dsl_tmp_query(ads_session->ads_wsp_helper, dsl_query.m_get_len());
	if(rdsp_path.m_equals("quicklink/direct.hsl")) {
		/**
		 * rdvpn_user - RDVPN user
		 * rdvpn_passwd - RDVPN password
		 * rdvpn_dom - RDVPN domain
		 * rdvpn_sessionid_url - Embed session-id in responded HTTP-Location URL (default is "no"). 
		 * rdvpn_sessionid_cookie - Issue session-id through HTTP-Cookie response (default is "yes"). 
		 * webterm_sid_lifetime - Lifetime of the passed information in seconds (default is 60).
		 *	webterm_name - WebTerm configuration name
		 *	user - RDP credentials user
		 *	dom - RDP credentials domain
		 *	passwd - RDP credentials password
		 *	startmode - Application mode DESKTOP or RAIL
		 *	remoteapp_flags - Remote app flags
		 *	remoteapp_flags - Remote app flags
		 *	remoteapp_exe - Remote app executable or file
		 *	remoteapp_args - Remote app arguments
		 *	remoteapp_workdir - Remote app working directory
		 */

		dsd_const_string dsl_rdvpn_user;
		dsd_const_string dsl_rdvpn_dom;
		dsd_const_string dsl_rdvpn_passwd;
		dsd_const_string dsl_rdvpn_sessionid_cookie = "yes";
		dsd_const_string dsl_rdvpn_sessionid_url;
		int inl_webterm_sid_lifetime = 60;

		dsd_const_string dsl_target;
		dsd_const_string dsl_user;
		dsd_const_string dsl_domain;
		dsd_const_string dsl_password;
		// Redirect hostname (optional)
		dsd_const_string dsl_hostname;
		dsd_const_string dsl_startmode;
		dsd_const_string dsl_serverineta;
		int inl_serverport = 0;
		struct dsd_webtermrdp_remoteapp2 dsl_remoteapp;
		dsl_remoteapp.usc_flags = 0;
		while(dsl_query.m_get_len() > 0) {
			int inl_pos = dsl_query.m_index_of("&");
			dsd_const_string dsl_value;
			if(inl_pos < 0) {
				dsl_value = dsl_query;
				dsl_query = "";
			}
			else {
				dsl_value = dsl_query.m_substring(0, inl_pos);
				dsl_query = dsl_query.m_substring(inl_pos+1);
			}
			inl_pos = dsl_value.m_index_of("=");
			if(inl_pos < 0)
				continue;
			dsd_const_string dsl_qk = dsl_value.m_substring(0, inl_pos);
			dsd_const_string dsl_qv = dsl_value.m_substring(inl_pos+1);
			if(m_conv_from_hexhexencoding(dsl_qv, dsl_tmp_query, dsl_qv) != SUCCESS) {
				continue;
			}
#if 0
			ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "[%d] #m_do_new_concept: K=%.*s V=%.*s\n",
				ads_session->ads_wsp_helper->m_get_session_id(), 
				dsl_qk.m_get_len(), dsl_qk.m_get_ptr(),
				dsl_qv.m_get_len(), dsl_qv.m_get_ptr());
#endif
			if(dsl_qk.m_equals("rdvpn_user")) {
				dsl_rdvpn_user = dsl_qv;
				continue;
			}
			if(dsl_qk.m_equals("rdvpn_dom")) {
				dsl_rdvpn_dom = dsl_qv;
				continue;
			}
			if(dsl_qk.m_equals("rdvpn_passwd")) {
				dsl_rdvpn_passwd = dsl_qv;
				continue;
			}
			if(dsl_qk.m_equals("rdvpn_sessionid_url")) {
				dsl_rdvpn_sessionid_url = dsl_qv;
				continue;
			}
			if(dsl_qk.m_equals("rdvpn_sessionid_cookie")) {
				dsl_rdvpn_sessionid_cookie = dsl_qv;
				continue;
			}
			if(dsl_qk.m_equals("webterm_sid_lifetime")) {
				int inl_value;
				if(!dsl_qv.m_parse_int(&inl_value) || inl_value <= 0) {
					ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error,
						"HIWSE692E: Bad value for parameter webterm_sid_lifetime '%.*s'",
						dsl_qv.m_get_len(), dsl_qv.m_get_ptr());
					continue;
				}
				inl_webterm_sid_lifetime = inl_value;
				continue;
			}

			if(dsl_qk.m_equals("webterm_name")) {
				dsl_target = dsl_qv;
				continue;
			}
			if(dsl_qk.m_equals("user")) {
				dsl_user = dsl_qv;
				continue;
			}
			if(dsl_qk.m_equals("dom")) {
				dsl_domain = dsl_qv;
				continue;
			}
			if(dsl_qk.m_equals("passwd")) {
				dsl_password = dsl_qv;
				continue;
			}
			if(dsl_qk.m_equals("hostname")) {
				dsl_hostname = dsl_qv;
				continue;
			}
			if(dsl_qk.m_equals("startmode")) {
				dsl_startmode = dsl_qv;
				continue;
			}
			if(dsl_qk.m_equals("serverineta")) {
				dsl_serverineta = dsl_qv;
				continue;
			}
			if(dsl_qk.m_equals("serverport")) {
				int inl_value;
				if(!dsl_qv.m_parse_int(&inl_value)) {
					ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error,
						"HIWSE692E: Bad value for parameter serverport '%.*s'",
						dsl_qv.m_get_len(), dsl_qv.m_get_ptr());
					continue;
				}
				inl_serverport = inl_value;
				continue;
			}
			if(dsl_qk.m_equals("remoteapp_flags")) {
				int inl_flags;
				if(!dsl_qv.m_parse_int(&inl_flags)) {
					ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error,
						"HIWSE692E: Bad value for parameter remoteapp_flags '%.*s'",
						dsl_qv.m_get_len(), dsl_qv.m_get_ptr());
					continue;
				}
				dsl_remoteapp.usc_flags = (unsigned int)inl_flags;
				continue;
			}
			if(dsl_qk.m_equals("remoteapp_exe")) {
				dsl_remoteapp.dsc_exe_or_file = dsl_qv;
				continue;
			}
			if(dsl_qk.m_equals("remoteapp_args")) {
				dsl_remoteapp.dsc_arguments = dsl_qv;
				continue;
			}
			if(dsl_qk.m_equals("remoteapp_workdir")) {
				dsl_remoteapp.dsc_working_dir = dsl_qv;
				continue;
			}

			ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error,
				"HIWSE691E: Unknown parameter '%.*s'",
				dsl_qk.m_get_len(), dsl_qk.m_get_ptr());
		}

		if(!bo_authenticated) {
			bool bo_auth = ads_session->dsc_auth.m_login(
				dsl_rdvpn_user.m_get_ptr(),
				dsl_rdvpn_user.m_get_len(),
				dsl_rdvpn_passwd.m_get_ptr(), dsl_rdvpn_passwd.m_get_len(),
				NULL, 0,
				dsl_rdvpn_dom.m_get_ptr(),
				dsl_rdvpn_dom.m_get_len(),
				&ads_session->dscv_kick_out );
			if(!bo_auth) {
				goto LBL_FORBIDDEN;
			}
		}
		char chrl_random[32];
		bool bol_res = ads_session->ads_wsp_helper->m_cb_get_random(chrl_random, sizeof(chrl_random));
		if(!bol_res) {
			goto LBL_INTERNAL_ERROR;
		}
		ds_hstring dsl_sid(ads_session->ads_wsp_helper);
		dsl_sid.m_write_rfc3548( chrl_random, sizeof(chrl_random) );

		int inl_remoteapp_size = 0;
		inl_remoteapp_size += dsl_remoteapp.dsc_exe_or_file.m_get_len()
			+ dsl_remoteapp.dsc_working_dir.m_get_len()
			+ dsl_remoteapp.dsc_arguments.m_get_len();
		int inl_size_needed = sizeof(struct dsd_webtermrdp_sid)
			+ dsl_user.m_get_len()
			+ dsl_password.m_get_len()
			+ dsl_domain.m_get_len()
			+ dsl_startmode.m_get_len()
			+ dsl_serverineta.m_get_len()
			+ inl_remoteapp_size
			;
		char chrl_temp[2048];
		if(inl_size_needed > sizeof(chrl_temp)) {
			goto LBL_INTERNAL_ERROR;
		}

		char* achl_out = chrl_temp;
		struct dsd_webtermrdp_sid* adsl_webterm_sid = (struct dsd_webtermrdp_sid*)achl_out;
		int inl_offset = sizeof(struct dsd_webtermrdp_sid);

		inl_offset = m_serialize_cma_string(achl_out, inl_offset, adsl_webterm_sid->dsc_user, dsl_user);
		inl_offset = m_serialize_cma_string(achl_out, inl_offset, adsl_webterm_sid->dsc_password, dsl_password);
		inl_offset = m_serialize_cma_string(achl_out, inl_offset, adsl_webterm_sid->dsc_domain, dsl_domain);
		inl_offset = m_serialize_cma_string(achl_out, inl_offset, adsl_webterm_sid->dsc_startmode, dsl_startmode);
		inl_offset = m_serialize_cma_string(achl_out, inl_offset, adsl_webterm_sid->dsc_serverineta, dsl_serverineta);
		adsl_webterm_sid->inc_serverport = inl_serverport;
		struct dsd_webtermrdp_remoteapp2* adsl_remoteapp_src = &dsl_remoteapp;
		adsl_webterm_sid->dsc_remoteapp.usc_flags = adsl_remoteapp_src->usc_flags;
		inl_offset = m_serialize_cma_string(achl_out, inl_offset, adsl_webterm_sid->dsc_remoteapp.dsc_exe_or_file, adsl_remoteapp_src->dsc_exe_or_file);
		inl_offset = m_serialize_cma_string(achl_out, inl_offset, adsl_webterm_sid->dsc_remoteapp.dsc_working_dir, adsl_remoteapp_src->dsc_working_dir);
		inl_offset = m_serialize_cma_string(achl_out, inl_offset, adsl_webterm_sid->dsc_remoteapp.dsc_arguments, adsl_remoteapp_src->dsc_arguments);

		ds_hstring dsl_sid_path(ads_session->ads_wsp_helper);
		dsl_sid_path.m_write(HL_CMA_NAME_WEBTERM_RDP_SID);
		dsl_sid_path.m_write_char(0);
		dsl_sid_path.m_write(dsl_sid);

#if 1
		struct dsd_aux_secure_xor_1 dsl_secure_xor;
		dsl_secure_xor.achc_destination	= achl_out;
		dsl_secure_xor.achc_post_key	= (char*)dsl_sid.m_get_ptr();
		dsl_secure_xor.imc_len_post_key	= dsl_sid.m_get_len();
		dsl_secure_xor.achc_source		= (char*)achl_out;
		dsl_secure_xor.imc_len_xor		= inl_offset;
		bool bol_ret = ads_session->ads_wsp_helper->m_cb_secure_aux( &dsl_secure_xor );
		if(!bol_ret) {
			goto LBL_INTERNAL_ERROR;
		}
#endif
		/********************************************************************************************/
		/* Create CMA																				*/
		/********************************************************************************************/
		bol_ret = ads_session->ads_wsp_helper->m_cb_create_cma(
			dsl_sid_path.m_get_ptr(), dsl_sid_path.m_get_len(), achl_out, inl_offset, inl_webterm_sid_lifetime);
		if(!bol_ret) {
			goto LBL_INTERNAL_ERROR;
		}
		//ads_session->ads_wsp_helper->m_cb_set_retention_cma(dsl_sid_path.m_get_ptr(), dsl_sid_path.m_get_len(), 60 );

		ds_hstring dsl_cookie(ads_session->ads_wsp_helper);
		if(!ads_session->dsc_auth.m_get_http_cookie(&dsl_cookie)) {
			goto LBL_INTERNAL_ERROR;
		}

		if(dsl_rdvpn_sessionid_url.m_equals("yes") && !ads_session->m_ensure_url_cookie()) {
			goto LBL_INTERNAL_ERROR;
		}

		ds_hstring strl_location(ads_session->ads_wsp_helper);
		if(dsl_hostname.m_get_len() > 0) {
			strl_location.m_write("https://");
			strl_location.m_write(dsl_hostname);
		}
		strl_location.m_write(ads_session->hstr_url_session_id);
		strl_location.m_write("/protected/portlets/webterm/rdp/cma.hsl?webterm_name=");
		strl_location.m_write(dsl_target);
		strl_location.m_write("&webterm_sid=");
		strl_location.m_write(dsl_sid);

		// Create the string for the http-cookie-header-line
		ds_hstring hstr_cookie_string(ads_session->ads_wsp_helper);
		dsd_const_string dsl_cookie_string;
		if(dsl_rdvpn_sessionid_cookie.m_equals("yes")) {
			int in_ret = ads_session->dsc_webserver.m_setup_cookie_string(&hstr_cookie_string, dsl_cookie.m_const_str());

			dsl_cookie_string = hstr_cookie_string.m_const_str();
			ads_session->dsc_control.in_cma_state |= ST_HTTP_COOKIE_ENABLED;
			//ads_session->dsc_auth.m_set_state( ST_HTTP_COOKIE_ENABLED );
		}
		dsd_const_string dsl_location = strl_location.m_const_str();
		ads_session->dsc_webserver.m_create_resp_header( ds_http_header::ien_status_found,
			0, &dsl_location, NULL, &dsl_cookie_string, false, NULL, HDR_MODE_NO_X_FRAME_OPTION);
		ads_session->dsc_transaction.m_send_header( ied_sdh_dd_toclient );
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
		return 0;
	}
	return ds_http_header::ien_status_not_found;
LBL_INTERNAL_ERROR:
	return ds_http_header::ien_status_internal_error;
LBL_FORBIDDEN:
	return ds_http_header::ien_status_forbidden;
}

int ds_webserver::m_handle_virtual_protected_portlets_webterm_rdp(const dsd_const_string& rdsp_path) {
	ds_hstring dsl_tmp_query_in(ads_session->ads_wsp_helper);
	dsd_const_string dsl_query = this->m_get_query(dsl_tmp_query_in);
	ds_hstring dsl_tmp_query(ads_session->ads_wsp_helper, dsl_query.m_get_len());
	
	if(rdsp_path.m_equals("functions/clear_sid")) {
		dsd_const_string dsl_webterm_sid;

		while(dsl_query.m_get_len() > 0) {
			int inl_pos = dsl_query.m_index_of("&");
			dsd_const_string dsl_value;
			if(inl_pos < 0) {
				dsl_value = dsl_query;
				dsl_query = "";
			}
			else {
				dsl_value = dsl_query.m_substring(0, inl_pos);
				dsl_query = dsl_query.m_substring(inl_pos+1);
			}
			inl_pos = dsl_value.m_index_of("=");
			if(inl_pos < 0)
				continue;
			dsd_const_string dsl_qk = dsl_value.m_substring(0, inl_pos);
			dsd_const_string dsl_qv = dsl_value.m_substring(inl_pos+1);
			if(m_conv_from_hexhexencoding(dsl_qv, dsl_tmp_query, dsl_qv) != SUCCESS) {
				continue;
			}
#if 0
			ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "[%d] #m_do_new_concept: K=%.*s V=%.*s\n",
				ads_session->ads_wsp_helper->m_get_session_id(), 
				dsl_qk.m_get_len(), dsl_qk.m_get_ptr(),
				dsl_qv.m_get_len(), dsl_qv.m_get_ptr());
#endif
			if(dsl_qk.m_equals("webterm_sid")) {
				dsl_webterm_sid = dsl_qv;
				continue;
			}
		}
		ds_hstring dsl_sid_path(ads_session->ads_wsp_helper);
		dsl_sid_path.m_write(HL_CMA_NAME_WEBTERM_RDP_SID);
		dsl_sid_path.m_write_char(0);
		dsl_sid_path.m_write(dsl_webterm_sid);

		bool bol_ret = ads_session->ads_wsp_helper->m_cb_delete_cma(
			dsl_sid_path.m_get_ptr(), dsl_sid_path.m_get_len());
		if(!bol_ret) {
			goto LBL_INTERNAL_ERROR;
		}
		return ds_http_header::ien_status_ok;
	}
	return ds_http_header::ien_status_not_found;
LBL_INTERNAL_ERROR:
	return ds_http_header::ien_status_internal_error;
}

int ds_webserver::m_handle_quick_link(const dsd_const_string& rdsp_path, bool bo_authenticated) {
#if 0
	char chrl_cma[1024];
	dsd_cma_ptr2<char> dsl_ptr2(chrl_cma);
	const char* abc = dsl_ptr2;
	
	dsd_webtermrdp_remoteapp_cma& dsl_cma = (dsd_webtermrdp_remoteapp_cma&)chrl_cma;
	memset(&dsl_cma, 0, sizeof(dsl_cma));
	dsl_ptr2 += sizeof(dsl_cma);
	dsl_cma.dsc_arguments.achc_ptr = dsl_ptr2;
	dsd_cma_ptr<const char> xyz = dsl_cma.dsc_arguments.achc_ptr;
	dsd_cma_ptr2<const char> dsl_ptr3 = dsl_cma.dsc_arguments.achc_ptr.map(chrl_cma);

	size_t szl_total = sizeof(dsd_webtermrdp_remoteapp_cma) + dsl_cma.m_get_extra_size();
#endif
	
	// TODO: Add JSON parser http://rapidjson.org/index.html
	ds_http_header::status_codes iel_status_code;
	if(rdsp_path.m_equals("webterm/rdp/direct.hsl")) {
		iel_status_code = (ds_http_header::status_codes)this->m_handle_virtual_public_portlets_webterm_rdp("quicklink/direct.hsl", bo_authenticated);
		if(iel_status_code == 0)
			return 0;
		goto LBL_SEND_ERROR;
	}
	iel_status_code = ds_http_header::ien_status_not_found;
	goto LBL_SEND_ERROR;
LBL_INTERNAL_ERROR:
	iel_status_code = ds_http_header::ien_status_internal_error;
	goto LBL_SEND_ERROR;
LBL_FORBIDDEN:
	iel_status_code = ds_http_header::ien_status_forbidden;
	goto LBL_SEND_ERROR;
LBL_SEND_ERROR:
	ads_session->dsc_webserver.m_create_resp_header(iel_status_code,
		0, NULL, NULL, NULL, false, NULL);
	ads_session->dsc_transaction.m_send_header( ied_sdh_dd_toclient );
	ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
	return -1;
}

int ds_webserver::m_handle_virtual_protected_session(const dsd_const_string& rdsp_path) {
	int iel_status_code = ds_http_header::ien_status_not_found;
	struct dsd_hl_clib_1* adsl_hl_clib = (struct dsd_hl_clib_1*)this->ads_session->ads_wsp_helper->m_get_structure();
	dsd_const_string dsl_path = rdsp_path;
	dsd_const_string dsl_prefix("functions/");
	if(dsl_path.m_starts_with(dsl_prefix)) {
		dsd_const_string dsl_path2 = dsl_path.m_substring(dsl_prefix.m_get_len());
		if(dsl_path2.m_equals("logout")) {
			this->m_logout_self();
			return ds_http_header::ien_status_ok;
		}
	}
	return ds_http_header::ien_status_not_found;
}
#endif // SM_USE_QUICK_LINK

#if SM_USE_AUX_PIPE_STREAM
#define HL_STREAM_PIPE_CMD_OPEN_REQ		0
#define HL_STREAM_PIPE_CMD_OPEN_RESP	1
#define HL_STREAM_PIPE_CMD_WRITE_REQ	2
#define HL_STREAM_PIPE_CMD_WRITE_RESP	3
#define HL_STREAM_PIPE_CMD_CLOSE_REQ	4
#define HL_STREAM_PIPE_CMD_CLOSE_RESP	5

#define HL_HTTP_STREAM_PIPE_OPEN_PROPERTY_CONTENT_TYPE		0

int ds_webserver::m_handle_stream_link(const dsd_const_string& rdsp_path, bool bo_authenticated) {
	int iel_status_code = ds_http_header::ien_status_not_found;
	struct dsd_hl_clib_1* adsl_hl_clib = (struct dsd_hl_clib_1*)this->ads_session->ads_wsp_helper->m_get_structure();
	dsd_const_string dsl_path = rdsp_path;
	dsd_const_string dsl_prefix("session/");
	if(!bo_authenticated)
		goto LBL_SEND_ERROR;
	if(dsl_path.m_starts_with(dsl_prefix)) {
		dsd_const_string dsl_pipe_request_name = dsl_path.m_substring(dsl_prefix.m_get_len());
		dsd_const_string dsl_http_cookie = ads_session->dsc_http_hdr_in.dsc_url.hstr_url_cookie;
		dsd_sdh_ident_set_1 dsl_ident;
		if(!this->ads_session->ads_wsp_helper->m_cb_get_ident(&dsl_ident))
			goto LBL_SEND_ERROR;
		struct dsd_aux_ident_session_info* adsl_aux_ident_session_info = (struct dsd_aux_ident_session_info*)dsl_ident.achc_userfld;
		ds_hstring hstr_temp(this->ads_session->ads_wsp_helper);
		hstr_temp.m_writef("/stream/session/%.*s/%.*s",
			(int)sizeof(adsl_aux_ident_session_info->chrc_session_ticket), adsl_aux_ident_session_info->chrc_session_ticket,
			dsl_pipe_request_name.m_get_len(), dsl_pipe_request_name.m_get_ptr());
		
		this->ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "ds_webserver::m_handle_stream_link AUX-PIPE name length=%d value=%.*s",
			 hstr_temp.m_get_len(), hstr_temp.m_get_len(), hstr_temp.m_get_ptr());

		//const char chrl_pipe_name[] = "/webtermrdp/print/001";
		struct dsd_aux_pipe_req_1 dsl_apr1;
		memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
		dsl_apr1.iec_apc = ied_apc_open;       /* create, server side open */
		dsl_apr1.achc_aux_pipe_name = (char*)hstr_temp.m_get_ptr();  /* address name of aux-pipe */
		dsl_apr1.imc_len_aux_pipe_name = hstr_temp.m_get_len();  /* length of name of aux-pipe */
		dsl_apr1.iec_aps = ied_aps_process;      /* for current process     */
		dsl_apr1.imc_signal = HL_AUX_SIGNAL_IO_2;  /* signal to set         */
		BOOL bol_rc = adsl_hl_clib->amc_aux( adsl_hl_clib->vpc_userfld,
							DEF_AUX_PIPE, /* aux-pipe          */
							&dsl_apr1,  /* aux-pipe request    */
							sizeof(struct dsd_aux_pipe_req_1) );
		if(!bol_rc) {
			goto LBL_SEND_ERROR;
		}
		if(dsl_apr1.iec_aprc != ied_aprc_ok) {
			ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE520E: DEF_AUX_PIPE failed with result %d",
				dsl_apr1.iec_aprc);
			goto LBL_SEND_ERROR;
		}
		struct dsd_aux_pipe_stream* adsl_aps = &this->dsc_aux_pipe_stream;
		adsl_aps->vpc_aux_pipe_handle = dsl_apr1.vpc_aux_pipe_handle;
		adsl_aps->iec_stream_state = ied_stream_pipe_state_head;
		adsl_aps->dsc_pending_writes.m_setup(this->ads_session->ads_wsp_helper);
#if 0
		struct dsd_aux_pipe_stream* adsl_aps = &this->dsc_aux_pipe_stream;
		adsl_aps->vpc_aux_pipe_handle = dsl_apr1.vpc_aux_pipe_handle;
		adsl_aps->iec_stream_state = ied_stream_pipe_state_head;
		adsl_aps->dsc_pending_writes.m_setup(this->ads_session->ads_wsp_helper);
		ads_session->dsc_webserver.hstr_my_encoding = "application/pdf";
		ads_session->dsc_webserver.m_create_resp_header( ds_http_header::ien_status_ok,
					-1, NULL, NULL, NULL, false, NULL);
		ads_session->dsc_transaction.m_send_header( ied_sdh_dd_toclient );
#endif
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_sending_stream_to_browser);
		return 0;
	}
LBL_SEND_ERROR:
	ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE520E: m_handle_stream_link failed for file %.*s",
		dsl_path.m_get_len(), dsl_path.m_get_ptr());
	ads_session->dsc_webserver.m_create_resp_header(iel_status_code,
        0, NULL, NULL, NULL, false, NULL);
   ads_session->dsc_transaction.m_send_header( ied_sdh_dd_toclient );
	ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
	return -1;
}

static BOOL m_gr_write_to_string(struct dsd_gather_i_1* adsp_data, void* avop_user)
{
	ds_hstring* adsl_hstring = (ds_hstring*)avop_user;
	adsl_hstring->m_write(adsp_data->achc_ginp_cur, adsp_data->achc_ginp_end-adsp_data->achc_ginp_cur);
	return TRUE;
}

bool ds_webserver::m_handle_stream_pipe_data(struct dsd_aux_pipe_stream* adsp_aps, struct dsd_gather_i_1 *adsp_gai1_data)
{
	struct dsd_hl_clib_1* adsl_hl_clib = (struct dsd_hl_clib_1*)this->ads_session->ads_wsp_helper->m_get_structure();
	
	struct dsd_gather_i_1_fifo dsl_fifo;
	m_gather_fifo_init(&dsl_fifo);
	m_gather_fifo_append_list2(&dsl_fifo, adsp_gai1_data);
	struct dsd_gather_reader dsl_gather_reader;
	m_gr_init(&dsl_gather_reader, &dsl_fifo);
	struct dsd_gather_i_1_pos dsl_lookahead_pos;
	
	while(m_gr_has_more(&dsl_gather_reader)) {
		switch(adsp_aps->iec_stream_state) {
		case ied_stream_pipe_state_head: {
			HL_GR_RET_GOTO(m_gr_begin_lookahead(&dsl_gather_reader, &dsl_lookahead_pos), LBL_FAILED);
			uint8_t inl_cmd;
			HL_GR_RET_GOTO(m_gr_read_uint8(&dsl_gather_reader, &inl_cmd), LBL_INCOMPLETE);
switch(inl_cmd) {
			case HL_STREAM_PIPE_CMD_OPEN_REQ: { // OPEN_REQ
				ds_hstring dsl_content_encoding(this->ads_session->ads_wsp_helper);
				//ads_session->dsc_webserver.hstr_my_encoding.m_reset();
				
				uint32_t uml_total_length;
				HL_GR_RET_GOTO(m_gr_read_uint32_le(&dsl_gather_reader, &uml_total_length), LBL_INCOMPLETE);
				uint32_t uml_num_properties;
				HL_GR_RET_GOTO(m_gr_read_hasn1_uint32_be(&dsl_gather_reader, &uml_num_properties), LBL_INCOMPLETE);
				for(uint32_t uml_p=0; uml_p<uml_num_properties; uml_p++) {
					uint8_t inl_property;
					HL_GR_RET_GOTO(m_gr_read_uint8(&dsl_gather_reader, &inl_property), LBL_INCOMPLETE);
					uint32_t uml_property_len;
					switch(inl_property) {
					case HL_HTTP_STREAM_PIPE_OPEN_PROPERTY_CONTENT_TYPE:
						HL_GR_RET_GOTO(m_gr_read_hasn1_uint32_be(&dsl_gather_reader, &uml_property_len), LBL_INCOMPLETE);
						HL_GR_RET_GOTO(m_gr_write_to(&dsl_gather_reader, uml_property_len, &m_gr_write_to_string, &dsl_content_encoding), LBL_INCOMPLETE);
						break;
					default:
						ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE524E: HL_STREAM_PIPE_CMD_OPEN_REQ unknown property %d",
							inl_property);
						goto LBL_FAILED;
					}
				}
				HL_GR_RET_GOTO(m_gr_end_lookahead(&dsl_gather_reader, &dsl_lookahead_pos), LBL_FAILED);

#if HL_DBG_AUX_PIPE_STREAM
				ads_session->ads_wsp_helper->m_log(ied_sdh_log_warning, "m_handle_stream_pipe_data: HL_STREAM_PIPE_CMD_OPEN_REQ");
#endif

				char chrl_temp[5];
				chrl_temp[0] = HL_STREAM_PIPE_CMD_OPEN_RESP;
				chrl_temp[1] = 0;
				chrl_temp[2] = 0;
				chrl_temp[3] = 0;
				chrl_temp[4] = 0;
				struct dsd_gather_i_1 dsl_head;
				dsl_head.achc_ginp_cur = chrl_temp;
				dsl_head.achc_ginp_end = chrl_temp + 5;
				dsl_head.adsc_next = NULL;
		
				struct dsd_aux_pipe_req_1 dsl_apr1;
				memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
				dsl_apr1.iec_apc = ied_apc_write;
				dsl_apr1.vpc_aux_pipe_handle = adsp_aps->vpc_aux_pipe_handle;  /* handle of aux-pipe */
				dsl_apr1.adsc_gai1_data = &dsl_head;
				BOOL bol_rc = adsl_hl_clib->amc_aux( adsl_hl_clib->vpc_userfld,
															DEF_AUX_PIPE, /* aux-pipe          */
															&dsl_apr1,  /* aux-pipe request    */
															sizeof(struct dsd_aux_pipe_req_1) );
				if(!bol_rc) {
					ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE518E: DEF_AUX_PIPE failed");
					return false;
				}
				
				ads_session->dsc_webserver.hstr_my_encoding = dsl_content_encoding.m_const_str();
				ads_session->dsc_webserver.bo_compress_makes_sense = true;
				ads_session->dsc_webserver.m_create_resp_header( ds_http_header::ien_status_ok,
							-1, NULL, NULL, NULL, false, NULL);
				ads_session->dsc_transaction.m_send_header( ied_sdh_dd_toclient );
				break;
			}
			case HL_STREAM_PIPE_CMD_WRITE_REQ: // WRITE_REQ
				HL_GR_RET_GOTO(m_gr_read_uint32_le(&dsl_gather_reader, &adsp_aps->umc_length_total), LBL_INCOMPLETE);
				HL_GR_RET_GOTO(m_gr_end_lookahead(&dsl_gather_reader, &dsl_lookahead_pos), LBL_FAILED);
#if HL_DBG_AUX_PIPE_STREAM
				ads_session->ads_wsp_helper->m_logf(ied_sdh_log_warning, "m_handle_stream_pipe_data: HL_STREAM_PIPE_CMD_WRITE_REQ total=%d", adsp_aps->umc_length_total);
#endif
				adsp_aps->iec_stream_state = ied_stream_pipe_state_write;
				adsp_aps->umc_length_pending = adsp_aps->umc_length_total;
				goto LBL_STREAM_WRITE;
			case HL_STREAM_PIPE_CMD_CLOSE_REQ: { // CLOSE_REQ
				uint32_t uml_status;
				HL_GR_RET_GOTO(m_gr_read_uint32_le(&dsl_gather_reader, &uml_status), LBL_INCOMPLETE);
				HL_GR_RET_GOTO(m_gr_end_lookahead(&dsl_gather_reader, &dsl_lookahead_pos), LBL_FAILED);
#if HL_DBG_AUX_PIPE_STREAM
				ads_session->ads_wsp_helper->m_logf(ied_sdh_log_warning, "m_handle_stream_pipe_data: HL_STREAM_PIPE_CMD_CLOSE_REQ status=%d", uml_status);
#endif
				ads_session->dsc_transaction.m_send_chunked_end(ied_sdh_dd_toclient);
				adsp_aps->iec_stream_state = ied_stream_pipe_state_close;
				break;
			}
			default:
				ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE521E: AUX-PIPE-STREAM unexpected command %d",
					inl_cmd);
				return false;
			}
			break;
		}
		case ied_stream_pipe_state_write: {
	LBL_STREAM_WRITE:
			while(adsp_aps->umc_length_pending > 0) {
				struct dsd_gather_i_1 dsl_tmp;
				if(!m_gr_read_gather(&dsl_gather_reader, adsp_aps->umc_length_pending, &dsl_tmp)) {
					ads_session->dsc_transaction.m_send_chunked_flush(ied_sdh_dd_toclient);
					goto LBL_INCOMPLETE;
				}
				dsd_const_string dsl_data(dsl_tmp.achc_ginp_cur, dsl_tmp.achc_ginp_end - dsl_tmp.achc_ginp_cur);
				//ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "adsp_aps->umc_length_pending=%d cur=%d\n",
				//	dsl_tmp.achc_ginp_end - dsl_tmp.achc_ginp_cur);
				ads_session->dsc_transaction.m_write_as_chunked(
					dsl_tmp.achc_ginp_cur, dsl_tmp.achc_ginp_end - dsl_tmp.achc_ginp_cur, true, ied_sdh_dd_toclient, true, false);
				adsp_aps->umc_length_pending -= dsl_tmp.achc_ginp_end - dsl_tmp.achc_ginp_cur;
			}
			ads_session->dsc_transaction.m_send_chunked_flush(ied_sdh_dd_toclient);
			adsp_aps->dsc_pending_writes.m_add(adsp_aps->umc_length_total);
			adsp_aps->iec_stream_state = ied_stream_pipe_state_head;
			break;
		}
		case ied_stream_pipe_state_close: {
			ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE522E: AUX-PIPE-STREAM received data after close");
			return false;
		}
		default:
			ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE522E: bad state");
			return false;
		}
	}
	return true;
LBL_INCOMPLETE:
	return true;
LBL_FAILED:
	return false;
}

bool ds_webserver::m_stream_to_browser_continue() {
	struct dsd_aux_pipe_stream* adsl_aps = &this->dsc_aux_pipe_stream;
	if(adsl_aps->vpc_aux_pipe_handle == NULL)
		return true;
	struct dsd_hl_clib_1* adsl_hl_clib = (struct dsd_hl_clib_1*)this->ads_session->ads_wsp_helper->m_get_structure();
	while(!adsl_aps->dsc_pending_writes.m_empty()) {
		uint32_t uml_total_length = adsl_aps->dsc_pending_writes.m_get_first();
		adsl_aps->dsc_pending_writes.m_delete_first();

#if HL_DBG_AUX_PIPE_STREAM
		ads_session->ads_wsp_helper->m_logf(ied_sdh_log_warning, "m_stream_to_browser_continue: HL_STREAM_PIPE_CMD_WRITE_RESP total=%d",
			uml_total_length);
#endif
		struct dsd_aux_pipe_req_1 dsl_apr1;
		memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
		dsl_apr1.iec_apc = ied_apc_write;
		char chrl_temp[5];
		chrl_temp[0] = HL_STREAM_PIPE_CMD_WRITE_RESP;
		chrl_temp[1] = uml_total_length;
		chrl_temp[2] = uml_total_length>>8;
		chrl_temp[3] = uml_total_length>>16;
		chrl_temp[4] = uml_total_length>>24;
		struct dsd_gather_i_1 dsl_head;
		dsl_head.achc_ginp_cur = chrl_temp;
		dsl_head.achc_ginp_end = chrl_temp + 5;
		dsl_head.adsc_next = NULL;
		dsl_apr1.vpc_aux_pipe_handle = adsl_aps->vpc_aux_pipe_handle;  /* handle of aux-pipe */
		dsl_apr1.adsc_gai1_data = &dsl_head;
		BOOL bol_rc = adsl_hl_clib->amc_aux( adsl_hl_clib->vpc_userfld,
													DEF_AUX_PIPE, /* aux-pipe          */
													&dsl_apr1,  /* aux-pipe request    */
													sizeof(struct dsd_aux_pipe_req_1) );
		if(!bol_rc) {
			ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE518E: DEF_AUX_PIPE failed");
			return false;
		}
	}
	if(adsl_aps->iec_stream_state == ied_stream_pipe_state_close) {
		char chrl_temp[5];
		chrl_temp[0] = HL_STREAM_PIPE_CMD_CLOSE_RESP;
		chrl_temp[1] = 0;
		chrl_temp[2] = 0;
		chrl_temp[3] = 0;
		chrl_temp[4] = 0;
		struct dsd_gather_i_1 dsl_head;
		dsl_head.achc_ginp_cur = chrl_temp;
		dsl_head.achc_ginp_end = chrl_temp + 5;
		dsl_head.adsc_next = NULL;
		
#if HL_DBG_AUX_PIPE_STREAM
		ads_session->ads_wsp_helper->m_logf(ied_sdh_log_warning, "m_stream_to_browser_continue: HL_STREAM_PIPE_CMD_CLOSE_RESP");
#endif
		struct dsd_aux_pipe_req_1 dsl_apr1;
		memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
		dsl_apr1.iec_apc = ied_apc_write;
		dsl_apr1.vpc_aux_pipe_handle = adsl_aps->vpc_aux_pipe_handle;  /* handle of aux-pipe */
		dsl_apr1.adsc_gai1_data = &dsl_head;
		BOOL bol_rc = adsl_hl_clib->amc_aux( adsl_hl_clib->vpc_userfld,
													DEF_AUX_PIPE, /* aux-pipe          */
													&dsl_apr1,  /* aux-pipe request    */
													sizeof(struct dsd_aux_pipe_req_1) );
		if(!bol_rc) {
			ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE518E: DEF_AUX_PIPE failed");
			return false;
		}

		memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
		dsl_apr1.iec_apc = ied_apc_close_conn;
		dsl_apr1.vpc_aux_pipe_handle = adsl_aps->vpc_aux_pipe_handle;  /* handle of aux-pipe */
		adsl_aps->vpc_aux_pipe_handle = NULL;
		bol_rc = adsl_hl_clib->amc_aux( adsl_hl_clib->vpc_userfld,
													DEF_AUX_PIPE, /* aux-pipe          */
													&dsl_apr1,  /* aux-pipe request    */
													sizeof(struct dsd_aux_pipe_req_1) );
		if(!bol_rc) {
			ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE518E: DEF_AUX_PIPE failed");
			return false;
		}
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_sending_to_browser);
	}
	return true;
}

bool ds_webserver::m_handle_signal(int imp_signal)
{
	struct dsd_hl_clib_1* adsl_hl_clib = (struct dsd_hl_clib_1*)this->ads_session->ads_wsp_helper->m_get_structure();
	if((imp_signal & HL_AUX_SIGNAL_IO_2) != 0) {
		struct dsd_aux_pipe_stream* adsl_aps = &this->dsc_aux_pipe_stream;

		struct dsd_aux_pipe_req_1 dsl_apr1;
		memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
		dsl_apr1.iec_apc = ied_apc_state;        /* check state session     */
		dsl_apr1.vpc_aux_pipe_handle = adsl_aps->vpc_aux_pipe_handle;  /* handle of aux-pipe */
		BOOL bol_rc = adsl_hl_clib->amc_aux( adsl_hl_clib->vpc_userfld,
													DEF_AUX_PIPE, /* aux-pipe          */
													&dsl_apr1,  /* aux-pipe request    */
													sizeof(struct dsd_aux_pipe_req_1) );
		if(!bol_rc) {
			ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE518E: DEF_AUX_PIPE failed");
			return false;
		}
		switch(dsl_apr1.iec_aprc) {
		case ied_aprc_idle:
			break;
		case ied_aprc_read_buf: {
			if(!this->m_handle_stream_pipe_data(adsl_aps, dsl_apr1.adsc_gai1_data)) {
				ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE519E: m_handle_stream_pipe_data failed");
				return false;
			}
			struct dsd_gather_i_1* adsl_rest = m_gather_i_1_skip_processed(dsl_apr1.adsc_gai1_data);
			if(adsl_rest != NULL)
				break;

			memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
			dsl_apr1.iec_apc = ied_apc_free_read_buffer;  /* free passed read buffers */
			dsl_apr1.vpc_aux_pipe_handle = adsl_aps->vpc_aux_pipe_handle;  /* handle of aux-pipe */
			bol_rc = adsl_hl_clib->amc_aux( adsl_hl_clib->vpc_userfld,
														DEF_AUX_PIPE, /* aux-pipe          */
														&dsl_apr1,  /* aux-pipe request    */
														sizeof(struct dsd_aux_pipe_req_1) );
			if(!bol_rc) {
				ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE519E: DEF_AUX_PIPE failed");
				return false;
			}
			break;
	   }
		default:
			ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE519E: DEF_AUX_PIPE returned unexpected state %d",
				dsl_apr1.iec_aprc);
			return false;
		}
		return true;
	}
	return false;
}
#endif

/*! \brief Reads file from disc
 *
 * @ingroup filereader
 *
 * function ds_webserver::m_file_proc
 * Read a file from disk (or cache) and do replacings, if necessary. Construct http-header and body for the response and send all to browser.
 * In case of error an error page will be sent to browser.
 *
 * @param[in]   dsd_path&   dsl_path          Holds the requested path.
 * @param[in]   const char* ach_cookie        Cookie to set (default = NULL)
 * @return      int                           0 = success; else error
*/
int ds_webserver::m_file_proc(const dsd_path& dsp_path, const dsd_const_string* adsp_cookie, ds_hstring* ahstr_last_modified, bool bop_no_error_resp) {
    // Check if requested path is in PORTLETS_DIRECTORY:
    // Files inside this directory will only be delivered to user, when the user's role allows access to it.
    // Example: /protected/portlets/JTerm/JLaunch.html is requested. We must pass "JTerm" to the check for access rights.
    ds_hstring hstr_portlets_dir(ads_session->ads_wsp_helper);
    hstr_portlets_dir.m_set(ads_session->ads_config->ach_root_dir);
    hstr_portlets_dir.m_write(PORTLETS_DIRECTORY);
#if defined WIN32 || defined WIN64
    hstr_portlets_dir.m_replace("/", "\\");
#endif
    if ( dsp_path.hstr_path.m_starts_with_ic( hstr_portlets_dir ) ) {

        dsd_const_string hstr_dir_name(dsp_path.hstr_path.m_substring(hstr_portlets_dir.m_get_len())); // Holds the portlet's name ('JTerm' in our example).
        int in_separator = hstr_dir_name.m_find_first_of("/\\"); // Find the separator behind the directory name
        if (in_separator == -1) {
            ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE516E: Invalid path for portlets: %.*s",
                                                dsp_path.hstr_path.m_get_len(), dsp_path.hstr_path.m_get_ptr());
            // access not allowed, return error page
            m_send_error_page( ds_http_header::ien_status_not_found, true, MSG_ACCESS_DENIED, 0, 0 );
            return 612;
        }
        hstr_dir_name = hstr_dir_name.m_substring(0, in_separator); // cut off the trailing part
        
        // Check access rights to the directory
        if (ads_session->dsc_auth.m_is_portlet_allowed(hstr_dir_name.m_get_ptr(), hstr_dir_name.m_get_len()) ==  false) {
            ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE517E: Access denied for portlet '%.*s'.",
                                                hstr_dir_name.m_get_len(), hstr_dir_name.m_get_ptr());
            // access not allowed, return error page
            m_send_error_page( ds_http_header::ien_status_not_found, true, MSG_ACCESS_DENIED, 0, 0 );
            return 613;
        }
    }


    // if a file ends with FILE_EXT_TEMPLATE parse it and return output:
    if ( dsp_path.hstr_path.m_ends_with_ic( FILE_EXT_TEMPLATE ) == true ) {
        ds_xsl     dsc_xsl;
        dsc_xsl.m_init ( ads_session );
        ds_hstring hstr_html( ads_session->ads_wsp_helper );
        hstr_my_encoding = ("text/html;charset=UTF-8"); // output is html

        // create page:
        int inl_ret = dsc_xsl.m_get_data( &hstr_html, dsp_path.hstr_path.m_get_ptr(), dsp_path.hstr_path.m_get_len() );
        if (inl_ret <= 0) {
			m_send_error_page( ds_http_header::ien_status_not_found, true, hstr_html.m_const_str(), ied_sdh_log_error, 0 );
            hstr_html += ads_session->dsc_http_hdr_in.dsc_url.hstr_path;
            ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, hstr_html.m_const_str() );
            return 703;
        }
		
		dsd_const_string hstr_insert;
		//m_get_query_value( "webterm_mode", &hstr_insert );
		//hstr_html.m_replace_ic( REPLACE_WEBTERM_MODE, hstr_insert.m_const_str() );
		//hstr_insert.m_reset();
		
        //m_get_query_value( "webterm_prot", &hstr_insert );
		//hstr_html.m_replace_ic( REPLACE_WEBTERM_PROT, hstr_insert.m_const_str() );
		//hstr_insert.m_reset();
        m_get_query_value( "webterm_session", &hstr_insert );
		hstr_html.m_replace_ic( REPLACE_WEBTERM_SESS, hstr_insert);
		hstr_insert.m_reset();

		m_get_query_value( "webterm_name", &hstr_insert );
        hstr_html.m_replace( REPLACE_WEBTERM_NAME, hstr_insert );

#if SM_USE_QUICK_LINK
        ds_hstring dsl_url(ads_session->ads_wsp_helper,
            (ads_session->ads_config->in_settings & SETTING_DISABLE_HTTPS) != 0 ? dsd_const_string("ws://") : dsd_const_string("wss://"));
        dsl_url.m_write(ads_session->hstr_hf_host_last_request);
		dsl_url.m_write(ads_session->hstr_url_session_id);
        dsl_url.m_write("/webterm");
        dsd_const_string dsl_query = ads_session->dsc_http_hdr_in.dsc_url.hstr_query;
        if(dsl_query.m_get_len() != 0) {
            dsl_url.m_write("?");
            dsl_url.m_write(dsl_query);
        }

        hstr_html.m_replace( REPLACE_WEBTERM_URL, dsl_url.m_const_str() );
#endif

        m_create_resp_header(ds_http_header::ien_status_ok, hstr_html.m_get_len(), NULL, NULL, adsp_cookie, true, NULL, HDR_MODE_NO_X_FRAME_OPTION);
        ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_sending_to_browser);
        if (hstr_html.m_get_len() > 0) {
            ads_session->dsc_transaction.m_send_complete_file(&hstr_html, ied_sdh_dd_toclient);
        }
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
        return 633;
    } // end of L_TEMPLATE_FILEENDING


    // If USERDATA_APPLET_PAGE is requested, build it and return it.
    // This html-page is requested by hob.tools.ca.CtrlApplet. If we will use hsl-format here, we must
    // change in the CtrlApplet, too. To avoid this we use the OLD-FASHIONED html-page!
    ds_hstring hstr_applet_page(ads_session->ads_wsp_helper);
    hstr_applet_page.m_set(ads_session->ads_config->ach_root_dir);
    hstr_applet_page.m_write(USERDATA_APPLET_PAGE);
#if defined WIN32 || defined WIN64
    hstr_applet_page.m_replace("/", "\\");
#endif
    if ( dsp_path.hstr_path.m_starts_with_ic( hstr_applet_page ) ) {
        //--------------------------------------------
        // create response: use format of Java class hob\tools\ca\ca_data.java
        //--------------------------------------------
        ds_hstring hstr_xml(ads_session->ads_wsp_helper, "<?xml version='1.0' encoding='UTF-8' ?>"); // output buffer

        // Write user name, password, passticket, domain.
        ds_hstring hstr_cookie( ads_session->ads_wsp_helper );       // cookie buffer
        ads_session->dsc_auth.m_get_http_cookie( &hstr_cookie );

        hstr_xml.m_write("<axss><versionwebserver>");
        hstr_xml.m_write(WS_VERSION_STRING);
        hstr_xml.m_write("</versionwebserver><username>");
        hstr_xml.m_write_xml_text(ads_session->dsc_auth.m_get_hobsocks_name().m_const_str());
        hstr_xml.m_write("</username><password>");
        hstr_xml.m_write_xml_text(ads_session->dsc_auth.m_get_sticket().m_const_str());
        hstr_xml.m_write("</password><cookie>");
        hstr_xml.m_write_xml_text(hstr_cookie.m_const_str());
        hstr_xml.m_write("</cookie></axss>");

        // send response header
        m_create_resp_header( ds_http_header::ien_status_ok, hstr_xml.m_get_len(),
            NULL, NULL, NULL, false, NULL );
        ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_sending_to_browser);

        // for HEAD: do not respond data; Attention: respond the correct length (in_len_html)!!!!
        if (ads_session->dsc_http_hdr_in.m_get_http_method() == ds_http_header::ien_meth_HEAD) {
			ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
            return 3;
        }

        // send the file data
        if (hstr_xml.m_get_len() > 0) {
            //ads_session->dsc_transaction.m_send(&hstr_xml, ds_control::ien_st_sending_to_browser, false, ied_sdh_dd_toclient);
            ads_session->dsc_transaction.m_send_complete_file(&hstr_xml, ied_sdh_dd_toclient);
        }
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
        return 52;
    }

    // If USERDATA_PASSWORD_PAGE is requested, build it and return it.
    ds_hstring hstr_pwd_page(ads_session->ads_wsp_helper);
    hstr_pwd_page.m_set(ads_session->ads_config->ach_root_dir);
    hstr_pwd_page.m_write(USERDATA_PASSWORD_PAGE);
#if defined WIN32 || defined WIN64
    hstr_pwd_page.m_replace("/", "\\");
#endif
    if ( dsp_path.hstr_path.m_starts_with_ic( hstr_pwd_page ) ) {
        ds_hstring dsl_pwd    ( ads_session->ads_wsp_helper );
        ds_hstring dsl_pwd_b64( ads_session->ads_wsp_helper );

        dsl_pwd = ads_session->dsc_auth.m_get_password();
        dsl_pwd_b64.m_write_b64( dsl_pwd.m_get_ptr(), dsl_pwd.m_get_len() );

        // send response header
        m_create_resp_header( ds_http_header::ien_status_ok, dsl_pwd_b64.m_get_len(),
            NULL, NULL, NULL, false, NULL );
        ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_sending_to_browser);

        // for HEAD: do not respond data; Attention: respond the correct length (in_len_html)!!!!
        if (ads_session->dsc_http_hdr_in.m_get_http_method() == ds_http_header::ien_meth_HEAD) {
			ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
            return 3;
        }

        // send the file data
        if (dsl_pwd_b64.m_get_len() > 0) {
			ads_session->dsc_transaction.m_send_complete_file( &dsl_pwd_b64, ied_sdh_dd_toclient);
        }
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
        return 52;
    }

    // JF 30.10.09 Ticket[15925]: Support of pack200
    // If a jar-file foo.jar is requested with Accept-Encoding "pack200-gzip" and compression is enabled for the WebServerDll, then we 
    // try to read the file foo.jar.pack.gz. If found, we send it with Content-Encoding 'pack200-gzip' and Content-Type 'application/x-java-archive'.
    // If we could not find the pack200-file, we try to read and send the jar-file.
    bool bo_process_pack200 = /*(((((struct ds_my_conf *)ads_session->dsc_transaction.ads_trans->ac_conf)->in_settings) & SETTING_ENABLE_COMPRESSION) != 0)
                           &&*/ (dsp_path.hstr_path.m_ends_with(FILE_EXT_JAR)) 
                           && ((ads_session->dsg_state.in_accept_encoding & ds_http_header::ien_ce_pack200) == ds_http_header::ien_ce_pack200);
    if (bo_process_pack200) {
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                             "HIWSI586I: Try to read the according pack.gz-file. (%.*s)",
                                             dsp_path.hstr_path.m_get_len(), dsp_path.hstr_path.m_get_ptr() );

        dsd_path dsl_path_pack200;
        dsl_path_pack200.hstr_path = dsp_path.hstr_path;
        // add the file extension ".pack.gz", because we want to read pack200.
        dsl_path_pack200.hstr_path.m_write(FILE_EXT_PACK_GZ);

        // Try to read the file foo.jar.pack.gz by a recursive call to m_file_procedure().
        ds_hstring hstr_last_modified(ads_session->ads_wsp_helper, "");
        ads_session->dsc_http_hdr_out.hstr_hdr_out.m_reset();
        int in_pack200 = m_file_proc(dsl_path_pack200, NULL, &hstr_last_modified, true);
        switch(in_pack200) {
        case (10000 + (int)ds_http_header::ien_status_not_modified):
            // (return value is created by method m_file_is_modified inside m_file_proc)
            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                                 "HIWSI577I: The pack.gz-file was not modified. (%.*s)",
                                                 dsp_path.hstr_path.m_get_len(), dsp_path.hstr_path.m_get_ptr() );
            break;
        case 48:
            // (return value is created by method m_file_is_modified inside m_file_proc)
            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                                 "HIWSI583I: The pack.gz-file was successfully read and will be transfered to client." );
            break;
        case 49:
            // The pack.gz-file was read, header and file were already sent to browser????????????????????????????????????????????????????????????????????????TODO
            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                                 "HIWSI573I: The pack.gz-file was successfully read and will be transfered to client (with Content-Length)." );
            break;
        }
        if(ads_session->dsc_http_hdr_out.hstr_hdr_out.m_get_len() > 0) {
            return in_pack200;
        }

        // error -> write to log; go on and read the originally requested jar-file
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                             "HIWSE532E: Error reading the pack.gz-file: %d. Try to read the jar-file.",
                                             in_pack200 );

        // If we get here, we could not read the pack.gz-file, but we will go on reading the jar-file.
        // To avoid sending the jar-file with the (wrong!) Content-Encoding 'HFV_PACK200' (when response header is created), we must reset ien_ce_pack200 in ads_session->dsg_state.
        ads_session->dsg_state.in_accept_encoding -= ds_http_header::ien_ce_pack200;
        // we must reset ien_ce_gzip, too, because otherwise we would send the jar-file with the Content-Encoding 'HFV_GZIP' (jar-files get never zipped).
        ads_session->dsg_state.in_accept_encoding -= ds_http_header::ien_ce_gzip;

        // The ContentType might be changed (because an error page was constructed meanwhile). Therefore we reset the Content-Type.
        m_setup_encoding_string(dsp_path.hstr_path.m_const_str());
    } // bo_process_pack200

    this->m_release_disk_file();
    struct dsd_hl_aux_diskfile_1& ds_read_diskfile = this->dsc_read_diskfile;
#ifndef WSP_V24
    ds_read_diskfile.iec_chs_name = ied_chs_utf_8;
    ds_read_diskfile.ac_name      = (void*)dsp_path.hstr_path.m_get_ptr();
    ds_read_diskfile.inc_len_name = dsp_path.hstr_path.m_get_len();
#endif
#ifdef WSP_V24
    ds_read_diskfile.dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;
    ds_read_diskfile.dsc_ucs_file_name.ac_str      = (void*)dsp_path.hstr_path.m_get_ptr();
    ds_read_diskfile.dsc_ucs_file_name.imc_len_str = dsp_path.hstr_path.m_get_len();
#endif


    //-------------------------------
    // Header field If-Modified-Since
    //-------------------------------
    // we must read/investigate the header-field 'If-Modified-Since' (if exists)
    int in_reason = 0;
    ds_hstring hstrl_last_modified(ads_session->ads_wsp_helper, "");
    if (ahstr_last_modified == NULL) {
        ahstr_last_modified = &hstrl_last_modified;
    }
    if (!m_file_is_modified(dsp_path.hstr_path.m_const_str(), ds_read_diskfile, &in_reason, ahstr_last_modified))
	{
        if (in_reason == (int)ds_http_header::ien_status_not_modified)
		{
            dsd_const_string dsl_last_mod(ahstr_last_modified->m_const_str());
            m_create_resp_header(ds_http_header::ien_status_not_modified, 0, NULL, &dsl_last_mod, 
											 NULL, false, NULL);
			ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
			ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
        }
        else {
            // Do not create a response header, if we want to read a pack.gz-file. We are then
            // in a recursive call to m_file_procedure. If we are not in this recursive call -> create the response header.
            //----------------------
            // tell browser, that the file could not be found/read
            //----------------------
            if(!bop_no_error_resp) {
                m_create_resp_header(in_reason, 0, NULL, NULL, NULL, false, NULL);
                ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
				ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
            }
        }

        ads_session->ads_wsp_helper->m_cb_file_release(&ds_read_diskfile);
        return 10000 + in_reason;
    }

    // read file from disk
    bool bo_ret = ads_session->ads_wsp_helper->m_cb_file_access(&ds_read_diskfile);
    if (!bo_ret) {
        ds_hstring hstr_msg(ads_session->ads_wsp_helper, "HIWSE326E: DEF_AUX_DISKFILE_ACCESS failed");
        if (ds_read_diskfile.iec_dfar_def != ied_dfar_ok) {
            hstr_msg.m_writef(" with error %d", ds_read_diskfile.iec_dfar_def);
        }
        hstr_msg.m_write(" (");
        hstr_msg.m_write(dsp_path.hstr_path);
        hstr_msg.m_write(")");
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, hstr_msg.m_const_str() );

        if(bop_no_error_resp) {
           return 2;
        }

        m_send_error_page( ds_http_header::ien_status_not_found, true, MSG_FILE_NOT_FOUND, 0, 0 );
        ads_session->ads_wsp_helper->m_cb_file_release(&ds_read_diskfile);

        // JF 20.03.09 RFC2616-9.4: The HEAD method is identical to GET except that the server MUST NOT return a message-body in the response.
        // What to do, if the file is not found? MS-IIS then responds 404, sends a html page (displaying the error) and then closes the connection.
        // We will also close the connection. This will solve Ticket[16517].
        if (ads_session->dsc_http_hdr_in.m_get_http_method() == ds_http_header::ien_meth_HEAD) {
            ads_session->dsc_transaction.m_mark_as_processed(NULL); // JF 24.03.11
            ads_session->dsc_transaction.m_close_connection();
        }
        return 2;
    }

    // get epoch of last modification -> will be set to response header as 'Last-Modified'
    int in_epoch_lm = ds_read_diskfile.adsc_int_df1->imc_time_last_mod;
    // get a RFC1123-formatted time string of in_epoch_lm
    struct dsd_hl_aux_epoch_1 ds_epoch_to_str;
    memset(&ds_epoch_to_str, 0, sizeof(struct dsd_hl_aux_epoch_1));
    ds_epoch_to_str.iec_chs_epoch = ied_chs_ascii_850;
    ds_epoch_to_str.imc_epoch_val = in_epoch_lm;
    const int in_len_buf = 30;
    ds_epoch_to_str.inc_len_epoch = in_len_buf;
    char ch_buf[in_len_buf];
    memset(&ch_buf, 0, in_len_buf);
    ds_epoch_to_str.ac_epoch_str = &ch_buf[0];
    bo_ret = ads_session->ads_wsp_helper->m_cb_string_from_epoch(&ds_epoch_to_str);
    if (!bo_ret) {
        // we cannot setup a header 'Last-Modified' later on
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE426E: m_cb_string_from_epoch failed" );
        m_send_error_page( ds_http_header::ien_status_not_found, false, MSG_LAST_MOD_FAILED, ied_sdh_log_error, 426 );
        ads_session->ads_wsp_helper->m_cb_file_release(&ds_read_diskfile);
        return 12;
    }

    // time string for 'Last Modified'
    dsd_const_string hstr_last_modified((const char*)ds_epoch_to_str.ac_epoch_str, ds_epoch_to_str.inc_len_epoch);

    // get length of file
    int in_len_file_to_load = (int)(ds_read_diskfile.adsc_int_df1->achc_filecont_end - ds_read_diskfile.adsc_int_df1->achc_filecont_start);

    // for HEAD: compose our response
    if (ads_session->dsc_http_hdr_in.m_get_http_method() == ds_http_header::ien_meth_HEAD) {
        /*
            create MD5 hash for Content-MD5
        */
        int  inrl_md5[MD5_ARRAY_SIZE];
        char chrl_md5[MD5_DIGEST_LEN + 1];
        chrl_md5[MD5_DIGEST_LEN] = 0;
        MD5_Init( inrl_md5 );
        MD5_Update( inrl_md5, ds_read_diskfile.adsc_int_df1->achc_filecont_start,
                    0, in_len_file_to_load );
        MD5_Final( inrl_md5, chrl_md5, 0 );

        ds_hstring dsl_b64(ads_session->ads_wsp_helper);
        dsl_b64.m_write_b64( chrl_md5, MD5_DIGEST_LEN );

        dsd_const_string dsl_b64str(dsl_b64.m_const_str());
        m_create_resp_header(ds_http_header::ien_status_ok,
            in_len_file_to_load, NULL, &hstr_last_modified, NULL, false, NULL, 0, NULL, &dsl_b64str );
        ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
        ads_session->ads_wsp_helper->m_cb_file_release(&ds_read_diskfile);
        return 3;
    }

    //-----------
    // only GET will come here
    //-----------
    // setup content of requested file
    // set bo_set_no_cache to true, when e.g. JLaunch.html is loaded; otherwise the browser (here: IE6) would not correctly update
    // the file: browser sends a GET and gets the file (with newly created PT written to it) but browser uses the older file of its cache
    const char* ach_file_start = ds_read_diskfile.adsc_int_df1->achc_filecont_start;

	HL_DBG_PRINTF("#m_file_proc: dsl_path=%.*s\n", dsl_path.hstr_path.m_get_len(), dsl_path.hstr_path.m_get_ptr());

    // JF 30.10.09 Ticket[15925]
    if (dsp_path.hstr_path.m_ends_with(FILE_EXT_PACK_GZ)) {
        // The file is already zipped. We send the data with Content-Length.
        ads_session->dsc_webserver.hstr_my_encoding = ("application/x-java-archive");
        ads_session->dsc_webserver.bo_compress_makes_sense = false; // disable zipping
        dsd_const_string dsl_encoding("pack200-gzip");
        m_create_resp_header(ds_http_header::ien_status_ok,
            in_len_file_to_load, NULL, &hstr_last_modified, NULL, false, NULL, HDR_MODE_CONTENT_LENGTH, &dsl_encoding);
        ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_sending_to_browser);
        ads_session->dsc_transaction.m_send_complete_file(ach_file_start, in_len_file_to_load, false, ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
        struct dsd_hl_clib_1* adsl_clib = (struct dsd_hl_clib_1*)this->ads_session->ads_wsp_helper->m_get_structure();
        adsl_clib->boc_notify_send_client_possible = TRUE;
        return 48; // We give back an explicit return value for this case.
    }


    // Ticket[14129]: we must replace "<%=url_jnlp%>" with the domain in jnlp-file
    // we use string-functions, which may be less performant, but more comfortable
    if ( dsp_path.hstr_path.m_ends_with( FILE_EXT_JNLP ) == true ) {
		dsd_const_string dsl_template(ach_file_start, in_len_file_to_load);
		ds_hstring hstr_jnlp(ads_session->ads_wsp_helper, in_len_file_to_load*2);
        int inl_search_pos = 0;
		while(true) {
			int inl_pos = dsl_template.m_index_of(inl_search_pos, "<%");
			if(inl_pos < 0)
				break;
			int inl_pos2 = dsl_template.m_index_of(inl_pos+2, "%>");
			if(inl_pos2 < 0)
				break;
			inl_pos2 += 2; 
			// Flush the prefix part
			hstr_jnlp.m_write(dsl_template.m_substring(inl_search_pos, inl_pos));
			inl_search_pos = inl_pos2;
			
			dsd_const_string dsl_key = dsl_template.m_substring(inl_pos, inl_pos2);
			if(dsl_key.m_equals(REPLACE_URL_JNLP)) {
				// do the replacement
				hstr_jnlp.m_write(ads_session->hstr_hf_host_last_request);
			}
			else if(dsl_key.m_equals(REPLACE_HIGH_ENTROPY)) {
				struct dsd_role* dsl_role = ads_session->dsc_auth.m_get_role();
				dsd_const_string hstr_value;
				if( dsl_role == NULL || dsl_role->boc_high_entropy )
				{
					hstr_value = "yes";
				}
				else
				{
					hstr_value = "no";
				}
				hstr_jnlp.m_write(hstr_value);
			}
			else if(dsl_key.m_equals(REPLACE_JWTSA_CONFIG)) {
				dsd_const_string dsl_insert;
				m_get_query_value( "jwtsa_config", &dsl_insert );
				hstr_jnlp.m_write(dsl_insert);
			}
			else if(dsl_key.m_equals(REPLACE_JWTSA_CONFIG_URL)) {
				dsd_const_string dsl_insert;
				m_get_query_value( "jwtsa_config", &dsl_insert );
				hstr_jnlp.m_write_uri1(dsl_insert);
			}
			else if(dsl_key.m_equals(REPLACE_HCLIENT_CFG)) {
				const char *achl_client;
				int  inl_length;
				ds_hstring hstr_insert(ads_session->ads_wsp_helper);
				if(!m_compress_www_file("/public/lib/sslpublic/hclient.cfg", &achl_client, &inl_length)) {
					goto LBL_ERROR;
				}
				hstr_jnlp.m_write_b64(achl_client, inl_length);
			}
			else if(dsl_key.m_equals(REPLACE_HCLIENT_CDB)) {
				const char *achl_client;
				int  inl_length;
				ds_hstring hstr_insert(ads_session->ads_wsp_helper);
				if(!m_compress_www_file("/public/lib/sslpublic/hclient.cdb", &achl_client, &inl_length))
					goto LBL_ERROR;
				hstr_jnlp.m_write_b64(achl_client, inl_length);
			}
			else if(dsl_key.m_equals(REPLACE_HCLIENT_PWD)) {
				const char *achl_client;
				int  inl_length;
				ds_hstring hstr_insert(ads_session->ads_wsp_helper);
				if(!m_compress_www_file("/public/lib/sslpublic/hclient.pwd", &achl_client, &inl_length))
					goto LBL_ERROR;
				hstr_jnlp.m_write_b64(achl_client, inl_length);
			}
			else if(dsl_key.m_equals(REPLACE_WSP_URL)) {
				if( ads_session->dsc_http_hdr_in.hstr_hf_host.m_get_len() > 0 )
				{
					// TODO: Use IP-Parser
					dsd_const_string dsl_host = ads_session->dsc_http_hdr_in.hstr_hf_host.m_const_str();
					int inl_offset = dsl_host.m_index_of(":");
					if ( inl_offset >= 0 )
						dsl_host = dsl_host.m_substring(0, inl_offset);
					hstr_jnlp.m_write(dsl_host);
				}
				else // if host length == 0
				{
					hstr_jnlp.m_write("No Host found");
				}
			}
			else if(dsl_key.m_equals(REPLACE_WSP_PORT)) {
				// TODO: Use IP-Parser
				dsd_const_string dsl_host = ads_session->dsc_http_hdr_in.hstr_hf_host.m_const_str();
				dsd_const_string dsl_port;
				int inl_offset = dsl_host.m_index_of(":");
				if ( inl_offset >= 0 )
					dsl_port = dsl_host.m_substring(inl_offset+1);
				ds_hstring hstr_temp(ads_session->ads_wsp_helper);
				if(dsl_port.m_get_len() == 0) {
					int inl_port = ads_session->ads_wsp_helper->m_get_listen_port();
					if ( inl_port > 0 ) {
						hstr_temp.m_write_int(inl_port);
						dsl_port = hstr_temp.m_const_str();
					}
				}
				hstr_jnlp.m_write(dsl_port);
			}
			else if(dsl_key.m_equals(REPLACE_HSOCKS_USER)) {
				hstr_jnlp.m_write(ads_session->dsc_auth.m_get_hobsocks_name().m_const_str());
			}
			else if(dsl_key.m_equals(REPLACE_SESSIONTICKET)) {
				ds_hstring ds_sticket = ads_session->dsc_auth.m_get_password();
				ds_hstring ds_user = ads_session->dsc_auth.m_get_hobsocks_name();
				int in_len_data = ((ds_sticket.m_get_len() + 2) << 2);
				in_len_data += 1;
				char* ach_data = ads_session->ads_wsp_helper->m_cb_get_memory(in_len_data, false);
				if(!ach_data)
					goto LBL_ERROR;
				if(!ads_session->dsc_helper.AUrps1((LPCSTR)ds_sticket.m_get_ptr(), (LPCSTR)ds_user.m_get_ptr(), in_len_data, ach_data, (PINT)(&in_len_data))) {
					ads_session->ads_wsp_helper->m_cb_free_memory( ach_data );
					goto LBL_ERROR;
				}
				hstr_jnlp.m_write_html_text(dsd_const_string(ach_data, in_len_data));
				ads_session->ads_wsp_helper->m_cb_free_memory( ach_data );
			}
			else if(dsl_key.m_equals(REPLACE_USERNAME)) {
				hstr_jnlp.m_write(ads_session->dsc_auth.m_get_username().m_const_str());
			}
			else if(dsl_key.m_equals(REPLACE_PASSWORD)) {
				hstr_jnlp.m_write(ads_session->dsc_auth.m_get_sticket().m_const_str());
			}
			else if(dsl_key.m_equals("<%=plain-password%>")) {
				hstr_jnlp.m_write(ads_session->dsc_auth.m_get_password().m_const_str());
			}
			else if(dsl_key.m_equals(REPLACE_HSOCKS_STICKET)) {
				ds_hstring ds_sticket = ads_session->dsc_auth.m_get_sticket();
				ds_hstring ds_user = ads_session->dsc_auth.m_get_hobsocks_name();
				int in_len_data = ((ds_sticket.m_get_len() + 2) << 2) + 1;
				char* ach_data = ads_session->ads_wsp_helper->m_cb_get_memory(in_len_data, true);
				if(!ach_data)
					goto LBL_ERROR;
				if(!ads_session->dsc_helper.AUrps1((LPCSTR)ds_sticket.m_get_ptr(), (LPCSTR)ds_user.m_get_ptr(), in_len_data, ach_data, (PINT)(&in_len_data))) {
					ads_session->ads_wsp_helper->m_cb_free_memory( ach_data );
					goto LBL_ERROR;
				}
				hstr_jnlp.m_write_html_text(dsd_const_string(ach_data, in_len_data));
				ads_session->ads_wsp_helper->m_cb_free_memory( ach_data );
			}
			else if(dsl_key.m_equals(REPLACE_HTTP_COOKIE)) {
				ds_hstring ds_cookie(ads_session->ads_wsp_helper);
				if (ads_session->dsc_auth.m_get_http_cookie( &ds_cookie )){
					hstr_jnlp.m_write(ds_cookie.m_const_str());
				}
			}
			else if(dsl_key.m_equals(REPLACE_CONTEXT)) {
				hstr_jnlp.m_write("");
			}
			else if(dsl_key.m_equals(REPLACE_SERVER_ENTRY_NAME)) {
				ds_hstring hstr_temp( ads_session->ads_wsp_helper );
				ads_session->m_get_server_entry_name( &hstr_temp );
				hstr_jnlp.m_write(hstr_temp.m_const_str());
			}
			else if(dsl_key.m_equals(REPLACE_SYSTEMPARAMS)) {
				// The qurey to the jnlp file contains a query (e.g. "?ID=1"), which tells the index of the tag <HOB-PPP-Tunnel>, which shall be used, inside the xml file.
				// If no query exists or the query is invalid, then take the tag at index 0.
				// Read the ID number from the query.
				int in_idx = 0;
				const dsd_const_string hstrl_query = ads_session->dsc_http_hdr_in.dsc_url.hstr_query;
				if (hstrl_query.m_starts_with_ic("ID=")) { // Query must start with "ID="
					if (!hstrl_query.m_substring(3).m_parse_int(&in_idx)) { // Index number is no number.
						in_idx = 0;
					}
				}

				// Find the PPP-Tunnel-configuration according to this ID number.
				dsd_pppt* adsl_pppt = ads_session->ads_config->adsl_pppt;
				while(adsl_pppt != NULL) {
					if (adsl_pppt->in_id == in_idx) {
						break;
					}
					adsl_pppt = adsl_pppt->adsc_next;
				}
				if ( (adsl_pppt != NULL) && (adsl_pppt->ach_system_parameters != NULL) ) { // No PPP-configuration with the matching ID was found.
					ds_hstring hstrl_sysparams(ads_session->ads_wsp_helper);
					hstrl_sysparams.m_write(adsl_pppt->ach_system_parameters, adsl_pppt->in_len_system_parameters);

					// Replace %% by % (because there is no run-thru-precomp, which would remove one '%'.
					hstrl_sysparams.m_replace("%%", "%");

					// System parameters must be encoded with base64
					hstr_jnlp.m_write_b64(hstrl_sysparams.m_get_ptr(), hstrl_sysparams.m_get_len());
				}
			}
			else if(dsl_key.m_equals(REPLACE_LANGUAGE)) {
				// JF 02.02.11 Ticket[21458] Find and replace placeholder for language.
        
				// Get the curent language
				int in_lang = ads_session->dsc_auth.m_get_lang();

				// MF 20.06.2016, Ticket[44365]: if dsc_auth.m_get_lang returns an error (-1), fallback to English (0)
				if (in_lang < 0) {
					in_lang = 0;
				}

				// Convert the int into text (e.g. 1 -> de).
				const char* ach_lang = NULL;
				int in_len_language = 0;
				RESOURCES->m_get_lang(in_lang, &ach_lang, &in_len_language);

				hstr_jnlp.m_write(dsd_const_string(ach_lang, in_len_language));
			}
			else if(dsl_key.m_equals(REPLACE_PROPS_FILE)){  // those two placeholders are needed for Compliance Check CtrlApplet so we put them back.
                hstr_jnlp.m_write(REPLACE_PROPS_FILE);
            }
            else if(dsl_key.m_equals(REPLACE_NAME_JWS)){
                hstr_jnlp.m_write(REPLACE_NAME_JWS);
            }
			else {
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning, "HIWSE427W: JNLP processing detected unknown key %.*s",
					dsl_key.m_get_len(), dsl_key.m_get_ptr() );
                hstr_jnlp.m_write(dsd_const_string(dsl_key.m_get_ptr(), dsl_key.m_get_len()));  // somtimes those placeholder are used somewhere else. so we put those back 
			}
			continue;
LBL_ERROR:
			ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error, "HIWSE427E: JNLP processing failed for key %.*s", dsl_key.m_get_len(), dsl_key.m_get_ptr() );
			m_send_error_page( ds_http_header::ien_status_not_found, true, MSG_FILE_NOT_FOUND, ied_sdh_log_error, 427 );
			ads_session->ads_wsp_helper->m_cb_file_release(&ds_read_diskfile);
			return 0;
		}
		// Flush the suffix part
		hstr_jnlp.m_write(dsl_template.m_substring(inl_search_pos));

#if 0
        ds_hstring hstr_jnlp(ads_session->ads_wsp_helper, ach_file_start, in_len_file_to_load);
        dsd_const_string dsl_insert(ads_session->ads_config->ach_hostname);
        // host from http-header
        if (ads_session->dsc_http_hdr_in.hstr_hf_host.m_get_len() > 0) {
            dsl_insert = ads_session->dsc_http_hdr_in.hstr_hf_host.m_const_str();
        }
        // do the replacement
        hstr_jnlp.m_replace(REPLACE_URL_JNLP, dsl_insert);

		// replace <%=high-entropy%>
		struct dsd_role* dsl_role = ads_session->dsc_auth.m_get_role();
		
		if( dsl_role == NULL || dsl_role->boc_high_entropy )
		{
			hstr_jnlp.m_replace( REPLACE_HIGH_ENTROPY, "yes" );
		}
		else
		{
			hstr_jnlp.m_replace(  REPLACE_HIGH_ENTROPY, "no" );
		}
		
		char chrl_buffer[1024];
		int iml_len;
		
		memset( chrl_buffer, 0, sizeof(chrl_buffer) );
		dsl_insert.m_reset();
		m_get_query_value( "jwtsa_config", &dsl_insert );

		// replace <%=jwtsa_config%>
        hstr_jnlp.m_replace( REPLACE_JWTSA_CONFIG, dsl_insert );

		// replace <%=jwtsa_config_url%>
		iml_len = m_cpy_vx_vx(	chrl_buffer,				sizeof(chrl_buffer),		ied_chs_uri_1,
								dsl_insert.m_get_ptr(),	dsl_insert.m_get_len(),	ied_chs_utf_8 );

		if( iml_len == -1 ){ return false; }
		hstr_jnlp.m_replace( REPLACE_JWTSA_CONFIG_URL, dsd_const_string(chrl_buffer, iml_len) );

        /*
            insert hclient certificates
        */
        const char *achl_client;
        int  inl_length;
        bool bol_ret;
        if ( hstr_jnlp.m_search(REPLACE_HCLIENT_CFG) >= 0 ) {
            ds_hstring hstr_insert(ads_session->ads_wsp_helper);
            bol_ret = m_compress_hclient_cfg( &achl_client, &inl_length );
            if ( bol_ret == true ) {
                hstr_insert.m_write_b64( achl_client, inl_length );
            }
            hstr_jnlp.m_replace( REPLACE_HCLIENT_CFG, hstr_insert.m_const_str() );
        }
        if ( hstr_jnlp.m_search(REPLACE_HCLIENT_CDB) >= 0 ) {
            ds_hstring hstr_insert(ads_session->ads_wsp_helper);
            bol_ret = m_compress_hclient_cdb( &achl_client, &inl_length );
            if ( bol_ret == true ) {
                hstr_insert.m_write_b64( achl_client, inl_length );
            }
            hstr_jnlp.m_replace( REPLACE_HCLIENT_CDB, hstr_insert.m_const_str() );
        }
        if ( hstr_jnlp.m_search(REPLACE_HCLIENT_PWD) >= 0 ) {
            ds_hstring hstr_insert(ads_session->ads_wsp_helper);
            bol_ret = m_compress_hclient_pwd( &achl_client, &inl_length );
            if ( bol_ret == true ) {
                hstr_insert.m_write_b64( achl_client, inl_length );
            }
            hstr_jnlp.m_replace( REPLACE_HCLIENT_PWD, hstr_insert.m_const_str() );
        }

        /*
            insert wsp url and port
        */

		// hofmants: replace REPLACE_WSP_URL with url hostname parameter in incoming header
        if ( hstr_jnlp.m_search(REPLACE_WSP_URL) >= 0 ) {
			if( ads_session->dsc_http_hdr_in.hstr_hf_host.m_get_len() > 0 )
			{
				// TODO: Use IP-Parser
                dsd_const_string dsl_host = ads_session->dsc_http_hdr_in.hstr_hf_host.m_const_str();
                int inl_offset = dsl_host.m_index_of(":");
				if ( inl_offset >= 0 )
                    dsl_host = dsl_host.m_substring(0, inl_offset);
                hstr_jnlp.m_replace( REPLACE_WSP_URL, dsl_host );
			}
			else // if host length == 0
			{
				hstr_jnlp.m_replace( REPLACE_WSP_URL, "No Host found" );
			}
        }

        if ( hstr_jnlp.m_search(REPLACE_WSP_PORT) >= 0 ) {
            // TODO: Use IP-Parser
            dsd_const_string dsl_host = ads_session->dsc_http_hdr_in.hstr_hf_host.m_const_str();
			dsd_const_string dsl_port;
            int inl_offset = dsl_host.m_index_of(":");
            if ( inl_offset >= 0 )
                dsl_port = dsl_host.m_substring(inl_offset+1);
            ds_hstring hstr_temp(ads_session->ads_wsp_helper);
            if(dsl_port.m_get_len() == 0) {
                int inl_port = ads_session->ads_wsp_helper->m_get_listen_port();
                if ( inl_port > 0 ) {
                    hstr_temp.m_write_int(inl_port);
                    dsl_port = hstr_temp.m_const_str();
                }
            }
            hstr_jnlp.m_replace( REPLACE_WSP_PORT, dsl_port );
        }

        hstr_jnlp.m_replace( REPLACE_HSOCKS_USER, ads_session->dsc_auth.m_get_hobsocks_name().m_const_str() );

        //jterm sessionticket
        if (hstr_jnlp.m_search(REPLACE_SESSIONTICKET) >= 0)
        {
            ds_hstring ds_sticket = ads_session->dsc_auth.m_get_password();
            ds_hstring ds_user = ads_session->dsc_auth.m_get_hobsocks_name();
            int in_len_data = ((ds_sticket.m_get_len() + 2) << 2);
            in_len_data += 1;
            char* ach_data = ads_session->ads_wsp_helper->m_cb_get_memory(in_len_data, true);
            if ( ach_data != NULL ) 
            {
                ads_session->dsc_helper.AUrps1((LPCSTR)ds_sticket.m_get_ptr(), (LPCSTR)ds_user.m_get_ptr(), in_len_data, ach_data, (PINT)(&in_len_data));

                int in_needed = m_len_vx_vx( ied_chs_html_1, ach_data, in_len_data, ied_chs_utf_8 );
                char* ach_data_html = ads_session->ads_wsp_helper->m_cb_get_memory( in_needed, true );

                if( ach_data_html != NULL )
                {
                    m_cpy_vx_vx( (void*)ach_data_html, in_needed, ied_chs_html_1,
                                 (void*)ach_data, in_len_data, ied_chs_utf_8 );

                    dsd_const_string dsl_result( ach_data_html, in_len_data );
                    hstr_jnlp.m_replace( REPLACE_SESSIONTICKET, dsl_result );

                    ads_session->ads_wsp_helper->m_cb_free_memory( ach_data_html );
                }
                
                ads_session->ads_wsp_helper->m_cb_free_memory( ach_data );
            }
        }


        // replace username, password, context, too
        // replace context with an empty string for the time beeing
        hstr_jnlp.m_replace(REPLACE_USERNAME, ads_session->dsc_auth.m_get_username().m_const_str());

        hstr_jnlp.m_replace(REPLACE_PASSWORD, ads_session->dsc_auth.m_get_sticket().m_const_str());
        hstr_jnlp.m_replace("<%=plain-password%>", ads_session->dsc_auth.m_get_password().m_const_str());

        ///replace session ticket and cookie - hobphone
        if (hstr_jnlp.m_search(REPLACE_HSOCKS_STICKET) >= 0) {
            ds_hstring ds_sticket = ads_session->dsc_auth.m_get_sticket();
            ds_hstring ds_user = ads_session->dsc_auth.m_get_hobsocks_name();
            int in_len_data = ((ds_sticket.m_get_len() + 2) << 2) + 1;
            char* ach_data_enc = ads_session->ads_wsp_helper->m_cb_get_memory(in_len_data, true);
            if (ach_data_enc != NULL) { 
                ads_session->dsc_helper.AUrps1((LPCSTR)ds_sticket.m_get_ptr(), (LPCSTR)ds_user.m_get_ptr(), in_len_data, ach_data_enc, (PINT)(&in_len_data));

                int in_needed = m_len_vx_vx( ied_chs_html_1, ach_data_enc, 
                             in_len_data, ied_chs_utf_8 );
                char* ach_data_html = ads_session->ads_wsp_helper->m_cb_get_memory(in_needed, true);
                if (ach_data_html != NULL) {
                    m_cpy_vx_vx( (void*)ach_data_html, in_needed, ied_chs_html_1,
                         (void*)ach_data_enc, in_len_data,
                         ied_chs_utf_8 );
                    dsd_const_string dsl_result(ach_data_html,in_needed);
                    hstr_jnlp.m_replace(REPLACE_HSOCKS_STICKET, dsl_result);
                    ads_session->ads_wsp_helper->m_cb_free_memory(ach_data_html);
                }
                ads_session->ads_wsp_helper->m_cb_free_memory(ach_data_enc);

            }
        }

        if (hstr_jnlp.m_search(REPLACE_HTTP_COOKIE) >= 0) {
            ds_hstring ds_cookie(ads_session->ads_wsp_helper);
            if (ads_session->dsc_auth.m_get_http_cookie( &ds_cookie )){
                hstr_jnlp.m_replace(REPLACE_HTTP_COOKIE, ds_cookie.m_const_str());
            }

        }

        hstr_jnlp.m_replace(REPLACE_CONTEXT, "");

        ds_hstring hstr_temp( ads_session->ads_wsp_helper );
        ads_session->m_get_server_entry_name( &hstr_temp );

        hstr_jnlp.m_replace( REPLACE_SERVER_ENTRY_NAME, hstr_temp.m_const_str() );


        // JF 24.01.11 Ticket[21382] Find and replace placeholder for SystemParameters
        if (hstr_jnlp.m_search(REPLACE_SYSTEMPARAMS) >= 0) {
            // The qurey to the jnlp file contains a query (e.g. "?ID=1"), which tells the index of the tag <HOB-PPP-Tunnel>, which shall be used, inside the xml file.
            // If no query exists or the query is invalid, then take the tag at index 0.
            // Read the ID number from the query.
            int in_idx = 0;
            const dsd_const_string hstrl_query = ads_session->dsc_http_hdr_in.dsc_url.hstr_query;
            if (hstrl_query.m_starts_with_ic("ID=")) { // Query must start with "ID="
                if (!hstrl_query.m_substring(3).m_parse_int(&in_idx)) { // Index number is no number.
                    in_idx = 0;
                }
            }

            // Find the PPP-Tunnel-configuration according to this ID number.
            dsd_pppt* adsl_pppt = ads_session->ads_config->adsl_pppt;
            while(adsl_pppt != NULL) {
                if (adsl_pppt->in_id == in_idx) {
                    break;
                }
                adsl_pppt = adsl_pppt->adsc_next;
            }
            if ( (adsl_pppt != NULL) && (adsl_pppt->ach_system_parameters != NULL) ) { // No PPP-configuration with the matching ID was found.
                ds_hstring hstrl_sysparams(ads_session->ads_wsp_helper);
                hstrl_sysparams.m_write(adsl_pppt->ach_system_parameters, adsl_pppt->in_len_system_parameters);

                // Replace %% by % (because there is no run-thru-precomp, which would remove one '%'.
                hstrl_sysparams.m_replace("%%", "%");

                // System parameters must be encoded with base64
                hstr_system_parameters_b64.m_write_b64(hstrl_sysparams.m_get_ptr(), hstrl_sysparams.m_get_len());
            }
            
            hstr_jnlp.m_replace(REPLACE_SYSTEMPARAMS, hstr_system_parameters_b64.m_const_str());
        }


        // JF 02.02.11 Ticket[21458] Find and replace placeholder for language.
        if (hstr_jnlp.m_search(REPLACE_LANGUAGE) >= 0) {
            // Get the curent language
            int in_lang = ads_session->dsc_auth.m_get_lang();

            // MF 20.06.2016, Ticket[44365]: if dsc_auth.m_get_lang returns an error (-1), fallback to English (0)
            if (in_lang < 0) {
                in_lang = 0;
            }

            // Convert the int into text (e.g. 1 -> de).
            const char* ach_lang = NULL;
            int in_len_language = 0;
            RESOURCES->m_get_lang(in_lang, &ach_lang, &in_len_language);

            hstr_jnlp.m_replace(REPLACE_LANGUAGE, dsd_const_string(ach_lang, in_len_language));
        }
#endif

        m_create_resp_header(ds_http_header::ien_status_ok,
            hstr_jnlp.m_get_len(), NULL, &hstr_last_modified, NULL, false, NULL);
        ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_sending_to_browser);
        ads_session->dsc_transaction.m_send_complete_file(&hstr_jnlp, ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
        //ads_session->dsc_transaction.m_send(&hstr_jnlp, ds_control::ien_st_sending_to_browser, false, ied_sdh_dd_toclient);
        ads_session->ads_wsp_helper->m_cb_file_release(&ds_read_diskfile);
        return 20;
    }


    // Ticket[6654]: we must replace "<%=home%>" with the user's site-after-auth
    // we use string-functions, which may be less performant, but more comfortable
    // (avoid that a cached script gives one user a wrong site after auth)
    if ( dsp_path.hstr_path.m_ends_with( FILE_HOBHOME_JS ) == true ) {
        ds_hstring hstr_html(ads_session->ads_wsp_helper, ach_file_start, in_len_file_to_load);
        ds_hstring hstr_insert(ads_session->ads_wsp_helper); // default
        hstr_insert.m_set(ads_session->ads_config->ach_site_after_auth);
        // user has a special page
        ds_hstring ds_welcome = ads_session->dsc_auth.m_get_welcomepage();
        if ( ds_welcome.m_get_len() > 0 ) {
            hstr_insert.m_set(ds_welcome);
        }
        // do the replacement
        hstr_html.m_replace_ic(REPLACE_HOME, hstr_insert.m_const_str());

        // avoid caching!
        m_create_resp_header(ds_http_header::ien_status_ok,
            hstr_html.m_get_len(), NULL, &hstr_last_modified, NULL, true, NULL);
        ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_sending_to_browser);
        ads_session->dsc_transaction.m_send_complete_file(&hstr_html, ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
        ads_session->ads_wsp_helper->m_cb_file_release(&ds_read_diskfile);
        return 21;
    }
#if 0 // MJ this will get replaced with some xsl/xml stuff
    else { // not L_FILE_HOBHOME_JS
        PPP-Tunnel !!!!!!!!!!!!!!!!!!!
    } // not L_FILE_HOBHOME_JS
#endif // MJ

#ifdef _DEBUG
#define HOB_WSG_FILE_NAME "HOBwsg_readable.js"
#else
#define HOB_WSG_FILE_NAME "HOBwsg_release.js"
#define HOB_WSG_FILE_NAME "HOBwsg_readable.js"
#endif
#if defined WIN32 || defined WIN64
#define HOB_PROTECTED_WSG_PATH "\\protected\\wsg\\"
#else
#define HOB_PROTECTED_WSG_PATH "/protected/wsg/"
#endif
#if HOB_WSG_DEVELOPMENT
	if ( dsp_path.hstr_path.m_ends_with(HOB_PROTECTED_WSG_PATH "HOBwsg.js") ) {
        dsd_const_string hstr_wsg_file_in(ach_file_start, in_len_file_to_load);
        ds_hstring hstr_html(ads_session->ads_wsp_helper);
        
        ds_hstring dsl_ext_file(ads_session->ads_wsp_helper, ads_session->ads_config->ach_root_dir); // default
        dsl_ext_file.m_write(HOB_PROTECTED_WSG_PATH HOB_WSG_FILE_NAME);
        struct dsd_hl_aux_diskfile_1 dsl_diskfile;
        dsl_diskfile.iec_chs_name = ied_chs_utf_8;
        dsl_diskfile.ac_name      = (void*)dsl_ext_file.m_get_ptr();
        dsl_diskfile.inc_len_name = dsl_ext_file.m_get_len();
        char* achl_content = NULL;
        int inl_length = 0;
        if(!ads_session->ads_wsp_helper->m_read_file(&dsl_diskfile, &achl_content, &inl_length))
            return -1;
        dsd_const_string dsl_wsg_code_in(achl_content, inl_length);
        ds_hstring hstr_wsg_file_out(ads_session->ads_wsp_helper);
		if(!m_build_hob_wsg_file(dsl_wsg_code_in, hstr_wsg_file_out))
			return -1;
        ds_hstring hstr_wsg_file_out64(ads_session->ads_wsp_helper);
        hstr_wsg_file_out64.m_write_b64(hstr_wsg_file_out.m_get_ptr(), hstr_wsg_file_out.m_get_len());
        
        ds_hstring hstr_wsg_code_out(ads_session->ads_wsp_helper);
        hstr_wsg_code_out.m_set(hstr_wsg_file_in);
        hstr_wsg_code_out.m_replace("/*<%=file64:HOBwsg.js%>*/", hstr_wsg_file_out64.m_const_str());
        ads_session->ads_wsp_helper->m_cb_file_release(&dsl_diskfile);

        // avoid caching!
        m_create_resp_header(ds_http_header::ien_status_ok,
            hstr_wsg_code_out.m_get_len(), NULL, &hstr_last_modified, NULL, false, NULL);
        ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_sending_to_browser);
        ads_session->dsc_transaction.m_send_complete_file(&hstr_wsg_code_out, ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
        ads_session->ads_wsp_helper->m_cb_file_release(&ds_read_diskfile);
        return 22;
    }
	if ( dsp_path.hstr_path.m_ends_with(HOB_PROTECTED_WSG_PATH HOB_WSG_FILE_NAME) ) {
		dsd_const_string hstr_wsg_file_in(ach_file_start, in_len_file_to_load);
        ds_hstring hstr_wsg_file_out(ads_session->ads_wsp_helper);
		if(!m_build_hob_wsg_file(hstr_wsg_file_in, hstr_wsg_file_out))
			return -1;
		// avoid caching!
        m_create_resp_header(ds_http_header::ien_status_ok,
            hstr_wsg_file_out.m_get_len(), NULL, &hstr_last_modified, NULL, false, NULL);
        ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_sending_to_browser);
        ads_session->dsc_transaction.m_send_complete_file(&hstr_wsg_file_out, ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
        ads_session->ads_wsp_helper->m_cb_file_release(&ds_read_diskfile);
		return 22;
	}
#endif

#if hofmants
	if( dsl_path.hstr_path.m_search( WEBTERMRDPPAGE ) )
	{
		ds_hstring hstr_html(ads_session->ads_wsp_helper, ach_file_start, in_len_file_to_load);

		ds_hstring hstr_insert(ads_session->ads_wsp_helper);
		m_get_query_value( "webtermdod_config", &hstr_insert );

		hstr_html.m_replace( REPLACE_WEBTERM_DOD_CONFIG, hstr_insert.m_const_str() );
		m_create_resp_header(ds_http_header::ien_status_ok,hstr_html.m_get_len(), NULL, hstr_last_modified.m_get_ptr(), NULL, true, NULL);
        ads_session->dsc_transaction.m_send_header(ds_control::ien_st_sending_to_browser);
        ads_session->dsc_transaction.m_send_complete_file(&hstr_html, ds_control::ien_st_sending_to_browser, ied_sdh_dd_toclient);
        ads_session->ads_wsp_helper->m_cb_file_release(&ds_read_diskfile);
		return 21;
	}
#endif

    if(dsp_path.hstr_path.m_search("welcome.hsl") >= 0) {
        int a = 0;
    }
    // File was unchanged -> send to browser
    m_create_resp_header(ds_http_header::ien_status_ok,
        in_len_file_to_load, NULL, &hstr_last_modified, NULL, false, NULL);
    ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
	ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_sending_to_browser);
    ads_session->dsc_transaction.m_send_complete_file(ach_file_start, in_len_file_to_load,
        false, ied_sdh_dd_toclient);
	ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
    struct dsd_hl_clib_1* adsl_clib = (struct dsd_hl_clib_1*)this->ads_session->ads_wsp_helper->m_get_structure();
    adsl_clib->boc_notify_send_client_possible = TRUE;

    //ads_session->ads_wsp_helper->m_cb_file_release(&ds_read_diskfile);
    return 4;
} // m_file_proc

bool ds_webserver::m_build_hob_wsg_file(const dsd_const_string& dsp_file_content, ds_hstring& hstr_wsg_file_out) {
	hstr_wsg_file_out.m_set(dsp_file_content);
    {
        ds_hstring dsl_ext_file(ads_session->ads_wsp_helper, ads_session->ads_config->ach_root_dir); // default
        dsl_ext_file.m_write(HOB_PROTECTED_WSG_PATH "uglifyjs.js");
        struct dsd_hl_aux_diskfile_1 dsl_diskfile1;
        dsl_diskfile1.iec_chs_name = ied_chs_utf_8;
        dsl_diskfile1.ac_name      = (void*)dsl_ext_file.m_get_ptr();
        dsl_diskfile1.inc_len_name = dsl_ext_file.m_get_len();
        char* achl_content = NULL;
        int inl_length = 0;
        if(!ads_session->ads_wsp_helper->m_read_file(&dsl_diskfile1, &achl_content, &inl_length))
            return false;
        dsd_const_string dsl_content1(achl_content, inl_length);
        hstr_wsg_file_out.m_replace("/*<%=file:uglifyjs.js%>*/", dsl_content1);
        ads_session->ads_wsp_helper->m_cb_file_release(&dsl_diskfile1);
    }

	{
        ds_hstring dsl_ext_file(ads_session->ads_wsp_helper, ads_session->ads_config->ach_root_dir); // default
        dsl_ext_file.m_write(HOB_PROTECTED_WSG_PATH "avl.js");
        struct dsd_hl_aux_diskfile_1 dsl_diskfile1;
        dsl_diskfile1.iec_chs_name = ied_chs_utf_8;
        dsl_diskfile1.ac_name      = (void*)dsl_ext_file.m_get_ptr();
        dsl_diskfile1.inc_len_name = dsl_ext_file.m_get_len();
        char* achl_content = NULL;
        int inl_length = 0;
        if(!ads_session->ads_wsp_helper->m_read_file(&dsl_diskfile1, &achl_content, &inl_length))
            return false;
        dsd_const_string dsl_content1(achl_content, inl_length);
        hstr_wsg_file_out.m_replace("/*<%=file:avl.js%>*/", dsl_content1);
        ads_session->ads_wsp_helper->m_cb_file_release(&dsl_diskfile1);
    }

	{
        ds_hstring dsl_ext_file(ads_session->ads_wsp_helper, ads_session->ads_config->ach_root_dir); // default
        dsl_ext_file.m_write(HOB_PROTECTED_WSG_PATH "MutationObserver.js");
        struct dsd_hl_aux_diskfile_1 dsl_diskfile1;
        dsl_diskfile1.iec_chs_name = ied_chs_utf_8;
        dsl_diskfile1.ac_name      = (void*)dsl_ext_file.m_get_ptr();
        dsl_diskfile1.inc_len_name = dsl_ext_file.m_get_len();
        char* achl_content = NULL;
        int inl_length = 0;
        if(!ads_session->ads_wsp_helper->m_read_file(&dsl_diskfile1, &achl_content, &inl_length))
            return false;
        dsd_const_string dsl_content1(achl_content, inl_length);
        hstr_wsg_file_out.m_replace("/*<%=file:MutationObserver.js%>*/", dsl_content1);
        ads_session->ads_wsp_helper->m_cb_file_release(&dsl_diskfile1);
    }

	{
        ds_hstring dsl_ext_file(ads_session->ads_wsp_helper, ads_session->ads_config->ach_root_dir); // default
        dsl_ext_file.m_write(HOB_PROTECTED_WSG_PATH "css-selector-parser.js");
        struct dsd_hl_aux_diskfile_1 dsl_diskfile1;
        dsl_diskfile1.iec_chs_name = ied_chs_utf_8;
        dsl_diskfile1.ac_name      = (void*)dsl_ext_file.m_get_ptr();
        dsl_diskfile1.inc_len_name = dsl_ext_file.m_get_len();
        char* achl_content = NULL;
        int inl_length = 0;
        if(!ads_session->ads_wsp_helper->m_read_file(&dsl_diskfile1, &achl_content, &inl_length))
            return false;
        dsd_const_string dsl_content1(achl_content, inl_length);
        hstr_wsg_file_out.m_replace("/*<%=file:css-selector-parser.js%>*/", dsl_content1);
        ads_session->ads_wsp_helper->m_cb_file_release(&dsl_diskfile1);
    }
	return true;
}

void ds_webserver::m_release_disk_file() {
    struct dsd_hl_aux_diskfile_1& ds_read_diskfile = this->dsc_read_diskfile;
    if(ds_read_diskfile.ac_handle == NULL) {
        return;
    }
    ads_session->ads_wsp_helper->m_cb_file_release(&ds_read_diskfile);
    memset(&ds_read_diskfile, 0, sizeof(struct dsd_hl_aux_diskfile_1));
}

/*! \brief Get value of a query
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_get_query_value
 *
 * @param[in]   struct dsd_query*   ads_query           query list
 * @param[in]   char*               ach_name            name of query to search
 * @param[in]   int                 in_len_name         length of name
 * @param[in]   char**              aach_value          pointer to value
 * @param[in]   int*                ain_len_value       length of value
 * @param[in]   int                 in_start_index      start index of search
 * @return      int                                     index of found value
*/
int ds_webserver::m_get_query_value( struct dsd_query* ads_query,
                                     const char* ach_name,    int in_len_name,
                                     const char** aach_value, int* ain_len_value,
                                     int in_start_index                     )
{
    // initialize some variables:
    struct dsd_query* ads_temp = ads_query;
    int               in_index = 0;

    *aach_value    = "";
    *ain_len_value = 0;

    while ( ads_temp != NULL ) {
        if (    in_start_index <= in_index
             && ads_temp->ds_name.m_equals( ach_name, in_len_name ) == true ) {
            *aach_value    = ads_temp->ds_value.m_get_ptr();
            *ain_len_value = ads_temp->ds_value.m_get_len();
            return in_index;
        }
        ads_temp = ads_temp->ads_next;
        in_index++;
    }
    return -1;
} // end of ds_webserver::m_get_query_value


/*! \brief Get value of a query
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_get_query_value
 *
 * @param[in]   const char* ach_name            name of query to search (zero termintated)
 * @param[in]   char**      aach_value          pointer to value
 * @param[in]   int*        ain_len_value       length of value
 * @param[in]   int         in_start_index      start index of search
 * @return      int                             index of found value
*/
int ds_webserver::m_get_query_value( const dsd_const_string& rdsp_name, const char** aach_value, int* ain_len_value, int in_start_index )
{
    return m_get_query_value( ads_query, rdsp_name.strc_ptr, rdsp_name.inc_length, aach_value, ain_len_value, in_start_index );
} // end of ds_webserver::m_get_query_value


/*! \brief Get value of a query
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_get_query_value
 *
 * @param[in]   const char* ach_name            name of query to search (zero termintated)
 * @param[in]   ds_hstring* ads_value           value
 * @return      int                             index of found value
*/
int ds_webserver::m_get_query_value( const dsd_const_string& rdsp_name, dsd_const_string* ads_value )
{
    // initialize some variables:
    struct dsd_query* ads_temp;
    int               in_index;


    ads_temp = ads_query;
    in_index = 0;

    while ( ads_temp != NULL ) {
        if ( ads_temp->ds_name.m_equals( rdsp_name ) == true ) {
            *ads_value = ads_temp->ds_value.m_const_str();
            return in_index;
        }
        ads_temp = ads_temp->ads_next;
        in_index++;
    }
    return -1;
} // end of ds_webserver::m_get_query_value


/*! \brief Parse a query
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_parse_query
 *
 * @param[in]       const char* ach_query       input query
 * @return          dsd_query*
*/
dsd_query* ds_webserver::m_parse_query( const dsd_const_string& rdsp_query )
{
    // initialize some variables:
    struct dsd_query *ads_out       = NULL;
    struct dsd_query *ads_temp      = NULL;
    int              in_start       = 0;
    int              in_pos         = 0;
    const char*      ach_query      = rdsp_query.m_get_start();
    int              in_len         = (int)rdsp_query.m_get_len();
    bool             bo_insert      = false;
    char*            ach_name       = NULL;
    char*            ach_value      = NULL;
    int              in_len_name    = 0;
    int              in_len_value   = 0;
    
    // check input data:
    if ( in_len < 1 ) {
        return NULL;
    }
    
    // parse data:
    for ( ; in_pos < in_len; in_pos++ ) {
        switch ( ach_query[in_pos] ) {
            case '?':
            case '&':
                ach_value    = (char*)&ach_query[in_start];
                in_len_value = in_pos - in_start;                
                in_start = in_pos + 1;
                bo_insert = true;
                break;
            case '=':
                ach_name    = (char*)&ach_query[in_start];
                in_len_name = in_pos - in_start;       
                in_start = in_pos + 1;
                break;
        }
        if ( bo_insert == true ) {
            bo_insert = false;
            if ( ads_out == NULL ) {
                ads_out  = m_get_new_query( ads_out );
                ads_temp = ads_out;
            } else {
                ads_temp = m_get_new_query( ads_out );
            }
            if ( ads_temp == NULL ) {
                m_free_query( ads_out );
                return NULL;
            }
            ads_temp->ds_name.m_setup ( ads_session->ads_wsp_helper );
            ads_temp->ds_value.m_setup( ads_session->ads_wsp_helper );
            ads_temp->ds_name.m_write ( ach_name,  in_len_name );
            ads_temp->ds_value.m_write( ach_value, in_len_value );
            int inl_ret = m_conv_from_hexhexencoding( &ads_temp->ds_name  );
            if (inl_ret != SUCCESS) {
                m_free_query( ads_out );
                return NULL;
            }
            inl_ret = m_conv_from_hexhexencoding( &ads_temp->ds_value );
            if (inl_ret != SUCCESS) {
                m_free_query( ads_out );
                return NULL;
            }
        }
    }

    if ( in_start < in_pos ) {
        if ( ads_out == NULL ) {
            ads_out  = m_get_new_query( ads_out );
            ads_temp = ads_out;
        } else {
            ads_temp = m_get_new_query( ads_out );
        }
        if ( ads_temp == NULL ) {
            m_free_query( ads_out );
            return NULL;
        }
        ads_temp->ds_name.m_setup ( ads_session->ads_wsp_helper );
        ads_temp->ds_value.m_setup( ads_session->ads_wsp_helper );
        ads_temp->ds_name.m_write ( ach_name,  in_len_name );
        ads_temp->ds_value.m_write( &ach_query[in_start], in_len - in_start );
        int inl_ret = m_conv_from_hexhexencoding( &ads_temp->ds_name  );
        if (inl_ret != SUCCESS) {
            m_free_query( ads_out );
            return NULL;
        }
        inl_ret = m_conv_from_hexhexencoding( &ads_temp->ds_value );
        if (inl_ret != SUCCESS) {
            m_free_query( ads_out );
            return NULL;
        }
    }

    return ads_out;
} // end of ds_webserver::m_parse_query

dsd_const_string ds_webserver::m_get_query(ds_hstring& hstr_temp) {
	dsd_const_string dsl_query = ads_session->dsc_http_hdr_in.dsc_url.hstr_query;
	dsd_const_string dsl_body = this->hstr_message_body.m_const_str();
	if(dsl_query.m_get_len() <= 0)
		return dsl_body;
	if(dsl_body.m_get_len() <= 0)
		return dsl_query;
    hstr_temp = dsl_query;
    hstr_temp += "&";
    hstr_temp += dsl_body;
	 return hstr_temp.m_const_str();
}

/*! \brief Get new query
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_get_new_query
 *
 * @param[in]   dsd_query*  ads_query
 * @return      dsd_query*
*/
dsd_query* ds_webserver::m_get_new_query( dsd_query* ads_in )
{
    // initialize some variables:
    dsd_query* ads_temp = NULL;
     
    if ( ads_in == NULL ) {
        ads_in = (dsd_query*)ads_session->ads_wsp_helper->m_cb_get_memory(
                                    (int)sizeof(dsd_query), true );
        return ads_in;
    } else {
        if ( ads_in->ads_next == NULL ) {
            ads_in->ads_next = (dsd_query*)ads_session->ads_wsp_helper->m_cb_get_memory( 
                                            (int)sizeof(dsd_query), true );
            return ads_in->ads_next;
        } else {
            ads_temp = ads_in->ads_next;
            for ( ; ; ) {
                if ( ads_temp->ads_next == NULL ) {
                    break;
                }
                ads_temp = ads_temp->ads_next;
            }
            ads_temp->ads_next = (dsd_query*)ads_session->ads_wsp_helper->m_cb_get_memory( 
                                            (int)sizeof(dsd_query), true );
            return ads_temp->ads_next;
        }
    }
} // end of ds_webserver::m_get_new_query

void ds_webserver::m_clear_query() {
	if(this->ads_query == NULL)
		return;
	this->m_free_query(this->ads_query);
	this->ads_query = NULL;
}

/*! \brief Releases a query
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_free_query
 *
 * @param[in]   dsd_query*  ads_query
*/
void ds_webserver::m_free_query( dsd_query* ads_in )
{
    if ( ads_in != NULL ) {
        m_free_query( ads_in->ads_next );
		ads_session->ads_wsp_helper->m_cb_free_memory(ads_in, sizeof(dsd_query));
    }
} // end of ds_webserver::m_free_query


/*! \brief Checks if a file is modified
 *
 * @ingroup filereader
 *
 * Check, whether a file was modified since the timestamp given in http header If-Modified-Since 
 *
 * @param[in]  dsd_path& dsl_path
 * @param[in]  struct dsd_hl_aux_diskfile_1& ds_read_diskfile
 * @param[out] int* ain_trans will be filled in some cases with a http-status-code, to specify, what happened (e.g. the file is not modified)
 * @param[out] string& str_last_modified will be filled with the time, when file was modified last
 *
 * @return bool whether or not the file was modified since the timestamp given in http header If-Modified-Since
*/
bool ds_webserver::m_file_is_modified(const dsd_const_string& strp_path, struct dsd_hl_aux_diskfile_1& ds_read_diskfile, int* ain_trans, ds_hstring* ahstr_last_modified) {
    //-------------------------------
    // Header field If-Modified-Since
    //-------------------------------
    // don't test html-files for 'Not Modified'; we must perhaps change the files content later on (inject passticket!)
    // JWT uses htm-files !!!
    if (   ( ads_session->dsc_http_hdr_in.hstr_hf_if_modified_since.m_get_len() != 0 ) 
        && ( strp_path.m_ends_with( FILE_EXT_HTML  ) == false )
        && ( strp_path.m_ends_with( FILE_EXT_HTM ) == false ) ) {

        // get epoch from ach_time_if_modified_since
        struct dsd_hl_aux_epoch_1 ds_epoch_from_str;
        memset(&ds_epoch_from_str, 0, sizeof(struct dsd_hl_aux_epoch_1));
        ds_epoch_from_str.iec_chs_epoch = ied_chs_ascii_850;
        ds_epoch_from_str.inc_len_epoch = (int)ads_session->dsc_http_hdr_in.hstr_hf_if_modified_since.m_get_len(); 
        ds_epoch_from_str.ac_epoch_str = (void*)ads_session->dsc_http_hdr_in.hstr_hf_if_modified_since.m_get_ptr();
        bool bol1 = ads_session->ads_wsp_helper->m_cb_epoch_from_string(&ds_epoch_from_str);
        if (!bol1) { // we cannot resolve the time stamp
            // we will ignore the If-Modified-Since-header
            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error, "HIWSE725E: DEF_AUX_EPOCH_FROM_STRING failed: %.*s",
                ads_session->dsc_http_hdr_in.hstr_hf_if_modified_since.m_get_len(),
                ads_session->dsc_http_hdr_in.hstr_hf_if_modified_since.m_get_ptr());
            return true;  // file shall be handled as 'modified'
        }

        // get the epoch of last modification to requested file
        bool bo_ret = ads_session->ads_wsp_helper->m_cb_file_lastmodified( &ds_read_diskfile );
        if ( bo_ret == false ) {
            ds_hstring hstr_msg(ads_session->ads_wsp_helper, "HIWSE025E: DEF_AUX_DISKFILE_TIME_LM failed");
            if (ds_read_diskfile.iec_dfar_def != ied_dfar_ok) {                
                hstr_msg.m_writef(" with error %d.", ds_read_diskfile.iec_dfar_def);
            }
             ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, hstr_msg.m_const_str() );

            //----------------------
            // tell browser, that the file could not be found/read
            //----------------------
            if (ain_trans != NULL) {
                *ain_trans = (int)ds_http_header::ien_status_not_found;
            }
            return false;
        }

        if (ahstr_last_modified != NULL) {
            ahstr_last_modified->m_write((const char*)ds_epoch_from_str.ac_epoch_str, ds_epoch_from_str.inc_len_epoch);
        }

        int in_diff = ds_read_diskfile.imc_time_last_mod - ds_epoch_from_str.imc_epoch_val;
        if(in_diff == 0) {
            ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI565I: File was not modified." );
			//----------------------
            // tell browser, that the file is not modified
            //----------------------
            if (ain_trans != NULL) {
                *ain_trans = (int)ds_http_header::ien_status_not_modified;
            }
			return false;
		}
		int inl_diff_abs = in_diff;
        // Ticket[9090]: KB158588 (daylight saving time problem)
        if (inl_diff_abs < 0) {
            inl_diff_abs = (-1) * in_diff;
        }
		// KB158588 (daylight saving time problem)  if (ds_read_diskfile.imc_time_last_mod <= ds_epoch_from_str.imc_epoch_val) {
        // JF 30.01.09 T.Jira reported: when he changes the last-modified-time of a file by a day, the webserver treats the file as 'Not modified'. Solution: allow uncertainties due
        // to daylight saving only for periods minor than 3hours
        // if ( (ds_read_diskfile.imc_time_last_mod <= ds_epoch_from_str.imc_epoch_val) || ((in_diff % 3600) == 0) ) {
        if ( ( ((inl_diff_abs % 3600) == 0) && (inl_diff_abs <= 3*3600) ) ) {
            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info, "HIWSI565I: File was not modified due to DST (delta %d).", in_diff );
            //----------------------
            // tell browser, that the file is not modified
            //----------------------
            if (ain_trans != NULL) {
                *ain_trans = (int)ds_http_header::ien_status_not_modified;
            }
            return false; // file was not modified
        }
    } // if (   ( ads_session->dsc_http_hdr_in.hstr_hf_if_modified_since.m_get_len() != 0 )...
    return true; // file was modified (or shall be handled as 'modified')
}


/*! \brief forwards to logout page
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_forward_to_logout
 * forward browser to logout page
 *
 * @author      Joachim Frank
 * @param[in]   const char* ach_msg     message resource
 * @param[in]   int         in_msg_type type of message
 * @param[in]   int         in_msg_code message code
*/
void ds_webserver::m_forward_to_logout( const dsd_const_string& ach_msg, int in_msg_type, int in_msg_code )
{
    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
                                         "HIWSW079W: Forward to logout. %.*s",
                                         ach_msg.m_get_len(), ach_msg.m_get_start() );

    if ( ach_msg.m_get_len() != 0 ) {
        // save message in cma:
        ads_session->dsc_auth.m_set_msg( in_msg_type, in_msg_code, ach_msg, GLOBAL_LOGOUT_PAGE );
    }

    ds_hstring hstr_location = m_create_location(GLOBAL_LOGOUT_PAGE, dsd_const_string());
    dsd_const_string dsl_location(hstr_location.m_const_str());
    m_create_resp_header(ds_http_header::ien_status_found, 0, &dsl_location, NULL, NULL, false, NULL);
    ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
	ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
} // end of ds_webserver::m_forward_to_logout



/*! \brief Sends the logout page to the browser
 *
 * @ingroup webserver
 *
 * function ds_webserver::m_send_logout_page
 * Send the logout page to the browser.
 *
 * @return      bool
*/
bool ds_webserver::m_send_logout_page()
{
    // initialize some variables:
    bool                bol_ret;        // return value for some func calls
    class  ds_wsp_admin dsl_admin;      // wsp admin class

    bol_ret = m_get_other_sessions( &dsl_admin );
    if (    bol_ret == true
         && dsc_v_logout_connections.m_empty() == false ) {
        /*
            there are currently some non webserver sessions active:
            -> ask user how to go on
        */
        hstr_my_encoding = ("text/html");
        bo_compress_makes_sense = true;
        m_file_proc( ds_path, NULL );
        dsc_v_logout_connections.m_clear();
    } else {
        /*
            there are no other sessions or closing them is disable (by config)
            -> normal logout
        */
        ads_session->dsc_auth.m_logout();
        //---------------------------------------
        // build the page, setup header:
        //---------------------------------------
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI521I: Create logout page" );

        ds_hstring hstr_cookie(ads_session->ads_wsp_helper);
        ds_hstring hstr_cookie2(ads_session->ads_wsp_helper);
        ads_session->dsc_auth.m_get_http_cookie( &hstr_cookie2 );
        if(hstr_cookie2.m_get_len() > 0) {
            this->m_setup_cookie_string(&hstr_cookie, hstr_cookie2.m_const_str());
        }
        else {
            this->m_setup_cookie_string(&hstr_cookie, "delete");
            hstr_cookie.m_write("; expires=" CK_DELETE_TIME);
        }

        hstr_my_encoding = ("text/html");
        bo_compress_makes_sense = true;
        m_file_proc(ds_path, NULL);
    }
    return true;
} // end of ds_webserver::m_send_logout_page


/*! \brief Get connections which are not from the webserver
 *
 * @ingroup webserver
 *
 * private function ds_webserver::m_get_other_sessions
 * get current user connections, that are not from webserver
 *
 * @param[in]   ds_wsp_admin*                           adsp_admin
 * @return      bool                                                    true = success
*/
bool ds_webserver::m_get_other_sessions( ds_wsp_admin* adsp_admin )
{

    // initialize some variables:
    struct dsd_session_info* adsl_con;              // all sessions of current user
    struct dsd_getuser       dsl_user;              // current user information
    bool                     bol_ret;               // return value for some func calls
    dsd_wspat_pconf_t        *adsl_wspat_conf;      // config from wspat
    char                     chrl_name[256];        // our server-entry name
    int                      inl_name;              // length of server-entry name
    char                     chrl_proto[256];       // our protocol
    int                      inl_proto;             // length of protocol
    BOOL                     bol_compare;           // compare return
    int                      inl_compare;           // compare result

    //-------------------------------------------
    // should session be ended at logout?
    //-------------------------------------------
    adsl_wspat_conf = ads_session->ads_wsp_helper->m_get_wspat_config();
    if (    adsl_wspat_conf == NULL
         || adsl_wspat_conf->boc_end_sessions == false ) {
        return false;
    }

    //-------------------------------------------
    // get name and protocol of our server-entry:
    //-------------------------------------------
    inl_name  = 0;
    inl_proto = 0;
    bol_ret = ads_session->ads_wsp_helper->m_get_own_srv_entry(
                            &chrl_name[0], sizeof(chrl_name), &inl_name,
                            &chrl_proto[0], sizeof(chrl_proto), &inl_proto );
    if (    bol_ret   == false
         || inl_name  <  1
         || inl_proto <  1     ) {
        return false;
    }

    //-------------------------------------------
    // get user information:
    //-------------------------------------------
    bol_ret = ads_session->dsc_auth.m_get_user( &dsl_user );
    if ( bol_ret == false ) {
        return false;
    }

    //-------------------------------------------
    // get all current user sessions:
    //-------------------------------------------
    adsp_admin->m_init( ads_session->ads_wsp_helper, NULL );
	 ds_hstring* adsl_group;
    if ( dsl_user.dsc_wspgroup.m_get_len() > 0 ) {
		 adsl_group = &dsl_user.dsc_wspgroup;
    } else {
		 adsl_group = &dsl_user.dsc_userdomain;
    }
    adsl_con = adsp_admin->m_get_user_sessions( 
        dsl_user.dsc_username.m_get_ptr(),
        dsl_user.dsc_username.m_get_len(),
        adsl_group->m_get_ptr(),
        adsl_group->m_get_len(),
		  &dsl_user.chc_session);

    //-------------------------------------------
    // check all sessions:
    //-------------------------------------------
    while ( adsl_con != NULL ) {
        if (    adsl_con->ach_protocol                  == NULL
             || adsl_con->ach_serv_entry                == NULL
             || adsl_con->ds_sess_info.imc_len_protocol < 1
             || adsl_con->ds_sess_info.imc_len_serv_ent < 1     ) {
            dsc_v_logout_connections.m_add( adsl_con );
            adsl_con = adsl_con->ads_next;
            continue;
        }
        bol_compare = m_cmp_vx_vx( &inl_compare, 
                                   adsl_con->ach_protocol,
                                   adsl_con->ds_sess_info.imc_len_protocol,
                                   ied_chs_utf_8,
                                   &chrl_proto[0], inl_proto, ied_chs_utf_8 );
        if (    bol_compare == FALSE
             || inl_compare != 0     ) {
            dsc_v_logout_connections.m_add( adsl_con );
            adsl_con = adsl_con->ads_next;
            continue;
        }

        bol_compare = m_cmp_vx_vx( &inl_compare, 
                                   adsl_con->ach_serv_entry,
                                   adsl_con->ds_sess_info.imc_len_serv_ent,
                                   ied_chs_utf_8,
                                   &chrl_name[0], inl_name, ied_chs_utf_8 );
        if (    bol_compare == FALSE
             || inl_compare != 0     ) {
            dsc_v_logout_connections.m_add( adsl_con );
        }        
        adsl_con = adsl_con->ads_next;
    }

    return true;
} // end of ds_webserver::m_get_other_sessions


/*! \brief Gets a full path
 *
 * @ingroup filereader
 *
 * function ds_webserver::m_get_fullpath
 * gets the full path of a request
*/
bool ds_webserver::m_get_fullpath(struct dsd_path* ds_path_ret)
{
    // setup return-structure
    ds_path_ret->hstr_path.m_init( ads_session->ads_wsp_helper );
    ds_path_ret->hstr_path.m_reset();
    ds_path_ret->in_state_path = PATH_ERROR; // signals error

    // MJ 09.01.12, Ticket[23332]:
    struct dsd_unicode_string dsl_utf32;
    dsl_utf32.imc_len_str = m_len_vx_vx( ied_chs_utf_32,
                                         ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_ptr(),
                                         ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_len(),
                                         ied_chs_utf_8 );
    if ( dsl_utf32.imc_len_str < 1 ) {
        // some unreadable signs or something simular -> someone wants to hack us
        // return error (and force to login page outside)
        ds_path_ret->in_state_path = PATH_ACCESS_DENIED;
        return false;
    }
    dsl_utf32.ac_str      = ads_session->ads_wsp_helper->m_cb_get_memory(   (dsl_utf32.imc_len_str + 1)
                                                                          * (int)sizeof(unsigned int),
                                                                          false );
    dsl_utf32.iec_chs_str = ied_chs_utf_32;
    if ( dsl_utf32.ac_str == NULL ) {
        // out of memory -> someone wants to hack us
        // return error (and force to login page outside)
        ds_path_ret->in_state_path = PATH_ACCESS_DENIED;
        return false;
    }
    int inl_ret = m_cpy_vx_vx( dsl_utf32.ac_str, dsl_utf32.imc_len_str + 1, dsl_utf32.iec_chs_str,
                               ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_ptr(),
                               ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_len(),
                               ied_chs_utf_8 );
    if ( inl_ret != dsl_utf32.imc_len_str ) {
        // some unreadable signs or something simular -> someone wants to hack us
        // return error (and force to login page outside)
        ds_path_ret->in_state_path = PATH_ACCESS_DENIED;
        return false;
    }
    ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_set( &dsl_utf32 );
    ads_session->ads_wsp_helper->m_cb_free_memory( dsl_utf32.ac_str );

    // MJ 23.09.08, Ticket[15852]:
    bool bo_ret = m_get_realpath( &ads_session->dsc_http_hdr_in.dsc_url.hstr_path );
    if ( bo_ret == false ) {
        // access outside root dir -> someone wants to hack us
        // return error (and force to login page outside)
        ds_path_ret->in_state_path = PATH_ACCESS_DENIED;
        return false;
    }
    const dsd_const_string ach_url(ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_const_str());

    //-----------------------------------------------------
    // investigate the URL (see RFC2396-5.2)
    //-----------------------------------------------------
    if (!ach_url.m_starts_with("/")) {
        // RFC2396-5.2-6
        // A relative-path reference. The relative path needs to be merged with the base URI's path.

        // TODO
        // the following is a temporary solution
        ds_path_ret->in_state_path = PATH_FORCE_LOGIN_PAGE;
        return true;
    }



    // The path component begins with a slash character ("/"), then
    // the reference is an absolute-path
    if (ach_url.m_equals("/")) { // URL is only "/" -> we force browser to get login page
        ds_path_ret->in_state_path = PATH_URL_IS_SLASH;
        return true;
    }
    
    // construct the full path
    // Ticket[14756]:
    if (ach_url.m_equals(PATH_FAVICON)) {
        ds_path_ret->in_state_path = PATH_GET_FAVICON;
        ds_path_ret->hstr_path.m_write( ads_session->ads_config->ach_root_dir );
        ds_path_ret->hstr_path.m_write( PATH_FAVICON );
        return true;
    }

    //------------------------------------
    // check whether URL starts with an alias
    //------------------------------------                        
    // loop through all aliases and compare with the URL
    ds_hstring hstr_tmp(ads_session->ads_wsp_helper, "");
    const char* ach_alias((ads_session->ads_config->ach_alias));
    const char* ach_path((ads_session->ads_config->ach_path));
    ds_hstring hstr_fold_public(ads_session->ads_wsp_helper);
    hstr_fold_public.m_set(ads_session->ads_config->ach_root_dir);
    hstr_fold_public.m_write(FOLDER_PUBLIC);
    
    for (int i=0; i<ads_session->ads_config->in_count_alias_path; i++) {
        dsd_const_string dsl_alias(dsd_const_string::m_from_zeroterm(ach_alias));
        dsd_const_string dsl_path(dsd_const_string::m_from_zeroterm(ach_path));
        hstr_tmp.m_set(dsl_alias);
        hstr_tmp.m_write("/"); // add "/" to alias to ensure that alias is completed (e.g. alias "/public" and URL "publictest" would match otherwise!!
        if (ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_starts_with_ic(hstr_tmp)) { // URL matches an alias -> construct fullpath with alias' representation
            // replace alias by its path and concatenate with rest of URL
            ds_path_ret->hstr_path.m_write( dsl_path );
            ds_path_ret->hstr_path.m_write(ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_substring(dsl_alias.m_get_len()));

            // Check, whether the resolved path is underneeth "/public"
            if (ds_path_ret->hstr_path.m_starts_with_ic(hstr_fold_public)) {
                ds_path_ret->in_state_path = PATH_PUBLIC;
                // check whether the start-site is requested or e.g. a picture, which shall be displayed on the start-site
                if ( ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_equals(GLOBAL_START_SITE) ) {
                    ds_path_ret->in_state_path = PATH_LOGIN_PAGE_REQUESTED;
                }
                if ( ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_equals(GLOBAL_LOGOUT_PAGE) ) {
                    ds_path_ret->in_state_path = PATH_LOGOUT_PAGE_REQUESTED;
                }
            }
            else { // The alias is not in "/public" -> authentication is required to get this page. 
                ds_path_ret->in_state_path = PATH_AUTHENICATION_REQUIRED;
            }
            break;
        }

        // set pointers to next tokens
        ach_alias += dsl_alias.m_get_len() + 1;                            
        ach_path += dsl_path.m_get_len() + 1;
    } // end of for

    // if URL contained no alias-path -> root directory is meant
    if (ds_path_ret->in_state_path == PATH_ERROR) {
        ds_path_ret->hstr_path.m_write( ads_session->ads_config->ach_root_dir );
        ds_path_ret->hstr_path.m_write( ach_url );
        ds_path_ret->in_state_path = PATH_AUTHENICATION_REQUIRED;

        // check whether path is public-dir
        if (ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_starts_with_ic(FOLDER_PUBLIC)) {
            ds_path_ret->in_state_path = PATH_PUBLIC;
            // check whether the start-site is requested or e.g. a picture, which shall be displayed on the start-site
            if ( ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_equals(GLOBAL_START_SITE) ) {
                ds_path_ret->in_state_path = PATH_LOGIN_PAGE_REQUESTED;
            }
            else if ( ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_equals(GLOBAL_LOGOUT_PAGE) ) {
                ds_path_ret->in_state_path = PATH_LOGOUT_PAGE_REQUESTED;
            }
        }
    }


    if ( ds_path_ret->hstr_path.m_get_len() < 1 ) { // error !
        ds_path_ret->in_state_path = PATH_ERROR;
        return false;
    }

    //-----------------------------------------------------
    // Replace "/" by "\" in case of windows
    //-----------------------------------------------------
#if defined WIN32 || defined WIN64
    ds_path_ret->hstr_path.m_replace( "/", "\\" );
#endif

    return true;
}


/*! \brief Get a real path
 *
 * @ingroup filereader
 *
 * private function ds_webserver::m_get_realpath
 * validate realpath
 * to avoid access to hole disk, see Ticket[15852] for details
 *
 * @param[in]   ds_hstring*         ads_path
 *
 * @return      bool                true  = success
 *                                  false = error
*/
bool ds_webserver::m_get_realpath( ds_hstring* ads_path )
{
    // check input:
    if (    ads_path == NULL 
         || ads_path->m_get_len() < 1 ) {
        return false;
    }

    // initialize some variables:
    int        in_offset     = 0;                   // working offset
    int        in_tmp;                              // tmp length
    int        in_segm_len;                         // length of a "folder" segment
    const char* ach_cur = NULL;                      // current byte
    const char* ach_segm;                            // segment working byte
    ds_hstring ds_tmp(ads_session->ads_wsp_helper); // tmp output buffer

    //-------------------------------------------
    // loop through the string:
    //-------------------------------------------
    while ( in_offset < ads_path->m_get_len() ) {
        //---------------------------------------
        // get current sign:
        //---------------------------------------
        ach_cur     = ads_path->m_get_from(in_offset);
        ach_segm    = ach_cur;
        in_segm_len = 0;

        //---------------------------------------
        // search next "/":
        //---------------------------------------
        while (    in_offset  < ads_path->m_get_len()
#if defined WIN32 || defined WIN64
                && ach_cur[0] != '\\'               // handle backslash under Windows like slash
                                                    // under unix a folder can be named "\.." i.e.
#endif
                && ach_cur[0] != '/' ) {
            in_offset++;
            in_segm_len++;
            ach_cur = ads_path->m_get_from(in_offset);
        } // end of segment loop

        if (    (in_segm_len == 0)
             || (in_segm_len == 1 && ach_segm[0] == '.' ) ) {
            // we have only on "/" or "./" 
            // -> do nothing, just read next sign
            /*if ( ds_tmp.m_get_len() < 1 ) {
                ds_tmp.m_write( "/", 1 );
            }*/
        } else if (    (in_segm_len == 2)
                    && (ach_segm[0] == '.')
                    && (ach_segm[1] == '.') ) {
            // we have something like "../"
            if ( ds_tmp.m_get_len() < 2 ) {
                // do not allow "../" at beginning of a path
                ads_session->ads_wsp_helper->m_log( ied_sdh_log_error,
                                                    "HIWSE577E: Access outside rootdir denied!" );
                return false;
            } else {
                // go an folder up:
                in_tmp = ds_tmp.m_search_last( "/" );
                if ( in_tmp == -1 ) {
                    return false;
                }
                //ds_tmp.m_erase( in_tmp + 1, ds_tmp.m_get_len() - in_tmp - 1 ); // 1 = keep last "/"
                ds_tmp.m_erase( in_tmp, ds_tmp.m_get_len() - in_tmp );
            }
        } else {
            if ( ds_tmp.m_get_len() != 1 ) {
                ds_tmp.m_write( "/", 1 );
            }
            ds_tmp.m_write( ach_segm, in_segm_len );
        }

        //---------------------------------------
        // skip over trailing "/":
        //---------------------------------------
        in_offset++;
    }

    //---------------------------------------
    // check for '/' at the end:
    //---------------------------------------
    if (    in_offset > 0
         && ach_cur
         && ach_cur[0] == '/' ) {
        ds_tmp.m_write( "/", 1 );
    }

    //---------------------------------------
    // overwrite old path:
    //---------------------------------------
    if ( ads_path->m_get_len() != ds_tmp.m_get_len() ) {
        ads_path->m_set( ds_tmp.m_get_ptr(), ds_tmp.m_get_len() );
    }
    return true;
} // end of ds_webserver::m_get_realpath

/*! \brief Reads body data of a POST request
 *
 * @ingroup webserver
 *
 * process data of a POST (GET with data is seldom)
 * we expect username/password/state/destination/etc in the message-body
 */
int ds_webserver::m_read_message_body(void)
{
	 if (!ads_session->dsc_http_hdr_in.m_is_chunked()) {
		 // read content-length-info
		 int in_cont_len = ads_session->dsc_http_hdr_in.m_get_content_length();
		 if (in_cont_len < 1) {
			  ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE630E: Invalid content-length in POST" );
			  return -2;
		 }
	 }
#if 0
    // JF 14.10.08: check, whether all announced data are available -> if not -> wait
    int in_data_available = ads_session->dsc_transaction.m_count_unprocessed_data();
    if (in_data_available < in_cont_len) {
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                             "HIWSI472I: Not all announced data available: %d of %d.",
                                             in_data_available, in_cont_len );
        return 0; // 0 means: we must wait for more data
    }

	 if(in_data_available > ads_session->ads_config->in_max_request_payload) {
		  ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error, "HIWSE523E: payload exceeds limit: %d.", in_data_available);
        return -2;
	 }

    // get data in a linear buffer/string
    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                         "HIWSI462I: All announced data are available: %d of %d.",
                                         in_data_available, in_cont_len );
#endif
	 int in_data_complete;
	 do {
		const char* ach_data = NULL;
		int   in_len_data = -1;
		in_data_complete = ads_session->dsc_transaction.m_get_data(&ach_data, &in_len_data, true);
		if(in_data_complete < 0)
			return in_data_complete;
		if ( (ach_data == NULL) || (in_len_data == -1) ) { // no data available
			if(in_data_complete != 0)
				break;
			// 0 means: we must wait for more data
			return 0;
		}
		if(hstr_message_body.m_get_len() + in_len_data > ads_session->ads_config->in_max_request_payload) {
			ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error, "HIWSE523E: payload exceeds limit: %d.",
				ads_session->ads_config->in_max_request_payload);
         return -2;
		}
		hstr_message_body.m_write(ach_data, in_len_data);
	 } while(in_data_complete == 0);
	 return +1;
}

struct dsd_file_extension
{
   dsd_const_string dsc_key;
   dsd_const_string dsc_encoding;
   bool boc_compress_makes_sense;
};

#define CS(x) dsd_const_string(x)

static const dsd_file_extension DSS_FILE_EXTENSIONS[] =
{
    { CS(".html"), CS("text/html"), true },
    { CS(".htm"), CS("text/html"), true },
    { CS(".html-pre"), CS("text/html"), true },
    { CS(".htm-pre"), CS("text/html"), true },
    { CS(".txt"), CS("text/plain"), true },
    // JF 23.11.05
    { CS(".css"), CS("text/css"), true },
    { CS(".zip"), CS("application/x-zip"), false },
    { CS(".doc"), CS("application/msword"), true },
    // JF 21.02.06
    { CS(".js"), CS("application/x-javascript;charset=UTF-8"), true },
    // JF 29.10.09
    // pure jar files will not get ziped! pack.gz-files are already ziped!
    { CS(".jar"), CS("application/x-java-archive"), false },
    // JF 21.02.06
    { CS(".pdf"), CS("application/pdf"), true },
    // JF 07.12.07
    // JF 22.02.08 Ticket[14492]: there are problems with compression of jnlp-files (WebStart cannot correctly decompress)
    // -> don't try to compress them
    // Annotation: the content type for pack.gz ("application/x-java-archive") is set otherwise!
    { CS(".jnlp"), CS("application/x-java-jnlp-file"), false },
    { CS(".jpg"), CS("image/jpeg"), false },
    { CS(".jpeg"), CS("image/jpeg"), false },
    { CS(".gif"), CS("image/gif"), false },
    // JF 02.04.08 Ticket[14756]
    { CS(".ico"), CS("image/x-icon"), false },
    // MJ 03.04.08, used for users.xml
    { CS(".xml"), CS("text/xml"), true },
    // MJ 03.04.08, used for users.xsl
    { CS(".xsl"), CS("text/xml"), true },
    // KK 04.12.17, used for icons and hob logo
    { CS(".png"), CS("image/png"), false },
    { CS(".svg"), CS("image/svg+xml"), true },
};

static const dsd_file_extension DSS_FILE_EXTENSIONS_DEFAULT =
    { CS(""), CS("application/octet-stream"), false };

/*! \brief Detect encoding
 *
 * @ingroup webserver
 *
 * read file-ending to determine the content-type/MIME-type, which will be set in the response
 * Attention: see also ds_http_header::m_get_int_for_content_type() !!
 */
void ds_webserver::m_setup_encoding_string(const dsd_const_string& ach_filepath) {
    int inl_pos = ach_filepath.m_last_index_of(".");
    const dsd_file_extension* adsp_ext = &DSS_FILE_EXTENSIONS_DEFAULT;
    if(inl_pos >= 0) {
        adsp_ext = ds_wsp_helper::m_search_equals(
            DSS_FILE_EXTENSIONS, ach_filepath.m_substring(inl_pos), &DSS_FILE_EXTENSIONS_DEFAULT);
    }

    hstr_my_encoding = (adsp_ext->dsc_encoding);
    bo_compress_makes_sense = adsp_ext->boc_compress_makes_sense;
}

/*! \brief Setup Cookie string
 *
 * @ingroup webserver
 *
 * Write some information in a cookie
 */
int ds_webserver::m_setup_cookie_string(ds_hstring* ahstr_cookie, const dsd_const_string& rdsp_wspsid) {
    ahstr_cookie->m_set(IDENT_HOBWSP_COOKIE "=");
    
    // ID for this cookie
    ahstr_cookie->m_write(rdsp_wspsid);

    // path for this cookie (always "/"
    ahstr_cookie->m_write("; Path=/");

    // Ticket[8924]: set secure flag
    if ((ads_session->ads_config->in_settings & SETTING_DISABLE_HTTPS) != SETTING_DISABLE_HTTPS) {
        ahstr_cookie->m_write("; Secure");
    }

    // MJ testing:
    ahstr_cookie->m_write( "; HttpOnly" );
    // end mj

    if (ahstr_cookie->m_get_len() > LEN_COOKIE_STRING-1) {
        return 2;
    }

    return 0;
}

/*! \brief Creates an error page
 *
 * @ingroup webserver
 *
 * Creates an error page if something goes wrong
 */
ds_hstring ds_webserver::m_setup_error_page( dsd_msg_t* ads_msg, bool bo_add_return_link )
{
    // initialize some variables
    dsd_path dsl_path;
    dsl_path.hstr_path.m_setup( ads_session->ads_wsp_helper );

    //------------------------------------
    // set content type:
    //------------------------------------
    hstr_my_encoding = ("text/html");
    bo_compress_makes_sense = true;

    //------------------------------------
    // create path:
    //------------------------------------
    dsl_path.hstr_path.m_set(ads_session->ads_config->ach_root_dir);
    dsl_path.hstr_path.m_write(FILE_ERROR_TEMPLATE);
#if defined WIN32 || defined WIN64
    dsl_path.hstr_path.m_replace( "/", "\\" );
#endif

    //------------------------------------
    // open file:
    //------------------------------------
    ds_xsl     dsl_xsl;
    ds_hstring dsl_html( ads_session->ads_wsp_helper );
    dsl_xsl.m_init ( ads_session );
    hstr_my_encoding = ("text/html;charset=UTF-8"); // output is html

    // should return link be displayed?
    dsl_xsl.m_set_ersb( bo_add_return_link );

    // create page:
    int inl_ret = dsl_xsl.m_get_data( &dsl_html, dsl_path.hstr_path.m_get_ptr(), dsl_path.hstr_path.m_get_len(), ads_msg );
    if (inl_ret <= 0) {
        return m_setup_error_page_fallback( ads_msg, false );
    }

    return dsl_html;
}

/*! \brief Creates an error page
 *
 * @ingroup webserver
 *
 * Creates an error page
 */
ds_hstring ds_webserver::m_setup_error_page_fallback( dsd_msg_t* ads_msg, bool bo_add_return_link ) {
    // Ticket[15446]
    ds_hstring hstr(ads_session->ads_wsp_helper, "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\"><HTML><HEAD><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"><TITLE>HOB WebSecureProxy</TITLE><script src=/public/HOBHome.js></script><script src=/protected/wsg/HOBwsg.js></script></HEAD><BODY><script>HOB.m_nav()</script><H1>");
    if ( ads_msg != NULL ) {
        hstr.m_write( ads_msg->hstr_msg.m_get_ptr(), ads_msg->hstr_msg.m_get_len() );
    }
    hstr.m_write("</H1><P><HR><ADDRESS>");
    // Ticket[8924]-L2
    if ((ads_session->ads_config->in_settings & SETTING_SEND_NO_SERVER_HF) == 0) { // user wants to send Server-info
        hstr.m_write_html_text(ads_session->ads_config->ach_hf_server);
        hstr.m_write("<br>");
    }
    hstr.m_write("   ");
    if (ads_session->dsc_http_hdr_in.hstr_hf_host.m_get_len() > 0) {
        hstr.m_write_html_text(ads_session->dsc_http_hdr_in.hstr_hf_host.m_const_str());
    }
    else { // read from config-file; port is otherwise
        hstr.m_write_html_text(ads_session->hstr_conf_authority.m_const_str());
    }
    hstr.m_write("</ADDRESS>");
    if (bo_add_return_link) {
        hstr.m_write("<br><br><a href=\"javascript:history.back()\">");
        const char* achl_msg;
        int   in_len_msg;
        GET_RES( MSG_PREV_PAGE, achl_msg, in_len_msg );
        hstr.m_write_html_text(dsd_const_string(achl_msg, in_len_msg));
        hstr.m_write("</a>");
    }
    hstr.m_write("</BODY></HTML>");

    // Ticket[15284]: HOB error pages must be padded to a minimum length of 513 bytes. Ohterwise they get not displayed by IE.
    while (hstr.m_get_len() < 513) {
        hstr.m_write("                    "); // we add chunks of 20 blanks
    }

    return hstr;
}

/*! \brief Setup commands
 *
 * @ingroup webserver
 *
 * Writes several commands in a string
 */
ds_hstring ds_webserver::m_setup_commands(int* ain_len_to_insert, const dsd_const_string& ach_new_message,
                                          const dsd_const_string& ach_new_username, const dsd_const_string& ach_password, const dsd_const_string& ach_sticket,
                                          const dsd_const_string& ach_wsp_ineta, const dsd_const_string& ach_wsp_socks_mode,
                                          const dsd_const_string& ach_wsp_localhost, const dsd_const_string& ach_ppp_system_parameters) {
    ds_hstring hstr_ret(ads_session->ads_wsp_helper);
    int in_len_insert = 0;
    const char* achl_skin;
    int   inl_len_skin;
    bool  bol_ret;

	if (ach_new_message.m_get_len() != 0) {
        hstr_ret.m_write_concat("%%DEFT message:", ach_new_message, "\r\n");
        in_len_insert += (int)ach_new_message.m_get_len();
	}
	if (ach_new_username.m_get_len() != 0) {
		// JF 07.03.11 Ticket[21611]: hstr_ret.m_writef("%%DEFT username:%s\r\n", ach_new_username);
        hstr_ret.m_write_concat("%%DEFT wsp_userid:", ach_new_username, "\r\n");
        in_len_insert += (int)ach_new_username.m_get_len();
	}
	if (ach_password.m_get_len() != 0) {
		// JF 07.03.11 Ticket[21611]: hstr_ret.m_writef("%%DEFT password:%s\r\n", ach_password);
        hstr_ret.m_write_concat("%%DEFT wsp_password:", ach_password, "\r\n");
        in_len_insert += (int)ach_password.m_get_len();
	}
	if (ach_sticket.m_get_len() != 0) {
        hstr_ret.m_write_concat("%%DEFT cookie:", ach_sticket, "\r\n");
        in_len_insert += (int)ach_sticket.m_get_len();
	}

    // gui skin:
    bol_ret = ads_session->dsc_auth.m_get_gui_skin( &achl_skin, &inl_len_skin );
    if ( bol_ret == false ) {
        achl_skin    = ads_session->ads_config->ach_gui_skin.m_get_start();
        inl_len_skin = ads_session->ads_config->ach_gui_skin.m_get_len();
    }
    if (    achl_skin != NULL
         && inl_len_skin > 0 ) {
        hstr_ret.m_write_concat("%%DEFT gui_skin:", dsd_const_string(achl_skin, inl_len_skin), "\r\n");
        in_len_insert += inl_len_skin;
    }

	// HOB PPP Tunnel
	if (ach_wsp_ineta.m_get_len() != 0) {
        hstr_ret.m_write_concat("%%DEFT wsp_ineta:", ach_wsp_ineta, "\r\n");
        in_len_insert += (int)ach_wsp_ineta.m_get_len();
	}
	if (ach_wsp_socks_mode.m_get_len() != 0) {
        hstr_ret.m_write_concat("%%DEFT wsp_socks_mode:", ach_wsp_socks_mode, "\r\n");
        in_len_insert += (int)ach_wsp_socks_mode.m_get_len();
	}
	if (ach_wsp_localhost.m_get_len() != 0) {
        hstr_ret.m_write_concat("%%DEFT wsp_localhost:", ach_wsp_localhost, "\r\n");
        in_len_insert += (int)ach_wsp_localhost.m_get_len();
	}
    if (ach_ppp_system_parameters.m_get_len() != 0) {
        hstr_ret.m_write_concat("%%DEFT wsp_system_parameters:", ach_ppp_system_parameters, "\r\n");
        in_len_insert += (int)ach_ppp_system_parameters.m_get_len();
	}

    if (ain_len_to_insert != NULL) {
		*ain_len_to_insert = in_len_insert;
	}

	return hstr_ret;
}


/*! \brief Sends an error page to the browser
 *
 * @ingroup webserver
 *
 * send a html-page to webbrowser, displaying error information
 */
int ds_webserver::m_send_error_page( int in_status_code, bool bo_add_return_link,
                                     const dsd_const_string& rdsp_msg, int in_msg_type, int in_msg_code )
{
    // initialize some variables:
    ds_hstring hstr_html;       // data to send
    dsd_msg_t  ds_msg;          // message structure

    //-------------------------------------------
    // setup message:
    //-------------------------------------------
    ds_msg.hstr_msg.m_setup( ads_session->ads_wsp_helper );
    ds_msg.hstr_msg.m_write( rdsp_msg );
    ds_msg.inc_type = in_msg_type;
    ds_msg.inc_code = in_msg_code;  

    //-------------------------------------------
    // create error page:
    //-------------------------------------------
    hstr_html = m_setup_error_page( &ds_msg, bo_add_return_link );
    
    //-------------------------------------------
    // create header and send header and page:
    //-------------------------------------------
    m_create_resp_header(in_status_code, hstr_html.m_get_len(), NULL, NULL, NULL, true, NULL);
    ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
	ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_sending_to_browser);
    if (hstr_html.m_get_len() > 0) {
        ads_session->dsc_transaction.m_send_complete_file(&hstr_html, ied_sdh_dd_toclient);
    }
	ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
    return 0;
}

/*! \brief Creates HTTP Header
 *
 * @ingroup webserver
 *
 * Creates an HTTP Header for a response to the browser
 */
int ds_webserver::m_create_resp_header(int in_status_code, int in_data_length, const dsd_const_string* ahstr_location, const dsd_const_string* ach_last_modified,
                                       const dsd_const_string* adsp_cookie, bool bo_prevent_caching, const dsd_const_string* ach_connection, int in_mode,
                                       const dsd_const_string* adsp_encoding, const dsd_const_string* adsp_content_md5 )
{
    //-------------------------------------
    // create status line (e.g. HTTP/1.1 200 OK)
    //-------------------------------------
    dsd_const_string hstr_version(HF_HTTP_1_1); // HTTP/1.1
    // JF Ticket[16052]: for the time being we always send "HTTP/1.1", although another version might be requested by browser
    //if (ads_session->dsc_http_hdr_in.in_http_version != 11) { 
    //    if (ads_session->dsc_http_hdr_in.in_http_version == 10) { // HTTP/1.0
    //        str_version = HF_HTTP_1_0;
    //    }
    //    else { // all others: we respond a HTTP/0.9-status-line
    //        str_version = HF_HTTP_0_9;
    //    }
    //}
    dsd_const_string hstr_phrase = ads_session->dsc_http_hdr_out.m_get_reasonphrase(in_status_code);
    ads_session->dsc_http_hdr_out.m_add_start_line_out(false, hstr_version, in_status_code, hstr_phrase);

    //-------------------------------------
    // create header lines
    //-------------------------------------
    // Server (server's name and version)
    if ((ads_session->ads_config->in_settings & SETTING_SEND_NO_SERVER_HF) == 0) { // user wants to send header field 'Server'
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_SERVER_VERSION, 
            (ads_session->dsc_control.m_check_state(ST_SHORT_HF_SERVER) ? ads_session->ads_config->ach_hf_server : SHORT_HF_SERVER));
    }
    // Location
    if ( (ahstr_location != NULL) && (ahstr_location->m_get_ptr() != NULL) && (ahstr_location->m_get_len() > 0) ) {
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_LOCATION, *ahstr_location);
    }
    // Last-Modified
    if (ach_last_modified != NULL) {
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_LAST_MODIFIED, *ach_last_modified);
        //ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_EXPIRES, "Mon, 01 Jan 2018 00:00:00 GMT");
    }

#ifndef _DEBUG
    ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_STRICT_TRANSPORT_SECURITY, "max-age=31536000"); //365 days
#endif
    if(hstr_my_encoding.m_starts_with("text/html")) {
        //save bandwidth by omitting these headers for any thing else
        //as they are only relevant for html documents, but not css, scripts, etc.
        if((in_mode & HDR_MODE_NO_X_FRAME_OPTION) == 0 &&
                (ads_session->ads_config->in_settings & SETTING_ALLOW_EMBEDDED_USE) == 0 ) {
	        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_X_FRAME_OPTIONS, "sameorigin"); //TODO deny for anything else than globaladmin
        }
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_REFERRER_POLICY, "no-referrer");
    }
    ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_X_XSS_PROTECTION, "1; mode=block");

    if(hstr_my_encoding.m_get_len() > 0 && ! hstr_my_encoding.m_equals(DSS_FILE_EXTENSIONS_DEFAULT.dsc_encoding)) {
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_X_CONTENT_TYPE_OPTIONS, "nosniff");
    }
        //ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_EXPIRES, "Mon, 01 Jan 2018 00:00:00 GMT");

#if 0
	//Test CSP with:  ; report-uri https://hobc02k.hob.de/keilerkn/csp.php
    //Why is there a blob script loaded -> AdBlock Plus + Webadmin (in future)
    ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONTENT_SECURITY_POLICY, "default-src 'self'; script-src 'self' 'unsafe-inline' blob: ; style-src 'self' 'unsafe-inline'");
#endif


    // MJ 12.06.08, Ticket[14905]:
    if (    (ads_session->dsc_auth.m_is_portlet_allowed(achg_known_portlets[ied_wsg_portlet]) == true)
         && ((ads_session->ads_config->in_settings & SETTING_DISABLE_COOKIE_STORAGE) == 0) )
    {
        ds_hvector<ds_hstring> ds_rm_cookies( ads_session->ads_wsp_helper );
        ads_session->dsc_ws_gate.dsc_ck_manager.m_rm_script_cookies(ds_rm_cookies);
        for (HVECTOR_FOREACH(ds_hstring, adsl_cur, ds_rm_cookies)) {
            const ds_hstring& rdsl_cookie = HVECTOR_GET(adsl_cur);
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_SET_COOKIE, rdsl_cookie.m_const_str());
        }
    }

	/* hofmants: setup login cookie !*/
	if( in_mode == 42 ) // im abusing in_mode, dont tell anyone!
	{
		dsd_role *adsl_role = ads_session->dsc_auth.m_get_role();
		if( adsl_role && adsl_role->boc_login_cookie )
		{
			ds_hstring cookie( ads_session->ads_wsp_helper );

			cookie.m_write( HOBWSP_USER );
#ifdef B20140805
			cookie.m_write( ads_session->achc_username );
#else
			cookie.m_write( ads_session->dsc_username );
#endif
			cookie.m_write( ";Max-Age=" );
			cookie.m_write( MAX_AGE_LOGIN_COOKIE );
			cookie.m_write( ";Path=/" );
			ads_session->dsc_http_hdr_out.m_add_hdr_line_out( HF_SET_COOKIE, cookie.m_const_str() );
			cookie.m_reset();

#ifdef B20140805
			if( ads_session->achc_domain != 0 && ads_session->inc_len_domain > 0 )
#else
			if( ads_session->dsc_domain.m_get_len() > 0 )
#endif
			{
				cookie.m_write( HOBWSP_DOMAIN );
#ifdef B20140805
				cookie.m_write( ads_session->achc_domain );
#else
				cookie.m_write( ads_session->dsc_domain );
#endif
				cookie.m_write( ";Max-Age=" );
				cookie.m_write( MAX_AGE_LOGIN_COOKIE );
				cookie.m_write( ";Path=/" );
				ads_session->dsc_http_hdr_out.m_add_hdr_line_out( HF_SET_COOKIE, cookie.m_const_str() );
			}
		}
	}

	 // Set-Cookie (our HOB cookie)
    if (adsp_cookie != NULL && adsp_cookie->m_get_len() > 0) {
        if (    (ads_session->dsc_http_hdr_in.in_http_version >= 10)
             && (ads_session->dsc_control.m_check_state(ST_HTTP_COOKIE_ENABLED) == true) ) {
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_SET_COOKIE, *adsp_cookie);
        }
        ads_session->dsc_auth.m_set_state( ST_HTTP_COOKIE_SENT );
    }
    else if ( ds_path.in_state_path != PATH_GET_FAVICON ) {
        // Opera first asks for /favicon.ico, but won't return with cookie 
        // after forwarding to login page, therefore send it later!

        // setup a test cookie and send it to the browser as http-header-field
        if (    /*(ads_session->dsc_control.m_check_state(ST_AUTHENTICATED)         == false)
             &&*/ (ads_session->dsc_control.m_check_state(ST_HTTP_COOKIE_SENT) == false) ) {
            /*
                we are not accepted and we did not send a cookie to browser before
                -> send it now
            */
            // get cookie:
            ds_hstring ds_cookie(ads_session->ads_wsp_helper);
            ads_session->dsc_auth.m_get_http_cookie( &ds_cookie );

            // create cookie:
            if ( ds_cookie.m_get_len() > 0 ) {
                ds_hstring hstr_na_cookie(ads_session->ads_wsp_helper); // na = not authenticated cookie
                int in_ret = m_setup_cookie_string(&hstr_na_cookie, ds_cookie.m_const_str());
                if (in_ret == SUCCESS) {
                    ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_SET_COOKIE, hstr_na_cookie.m_const_str());
                    ads_session->dsc_auth.m_set_state( ST_HTTP_COOKIE_SENT );
                } else {
                    ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE635E: Cannot create test-cookie" );
                }
            }
        }
    }

    // Cache-Control
    if (bo_prevent_caching) {
        if (ads_session->dsc_http_hdr_in.in_http_version == ds_http_header::ien_http_version_11) { // cache control only supported by HTTP/1.1
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CACHE_CONTROL, "no-cache, no-store, must-revalidate");
        }
        // for HTTP/1.0
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_PRAGMA, "no-cache");
    }
	// Last-Modified
	else if (ach_last_modified != NULL) {
		// Use a freshness lifetime of 60 seconds
		// TODO: Make max-age configurable
		if (ads_session->dsc_http_hdr_in.in_http_version >= ds_http_header::ien_http_version_11) { // cache control only supported by HTTP/1.1
#ifdef _DEBUG
			ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CACHE_CONTROL, "max-age=0");
#else
			ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CACHE_CONTROL, "max-age=60");
#endif
		}
	}

    // Content-Type
    if (hstr_my_encoding.m_get_len() > 0) {
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONTENT_TYPE, hstr_my_encoding);
    }

    // Content Encoding
    if ( adsp_encoding != NULL ) {
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONTENT_ENCODING, *adsp_encoding );
    }

    // Content-MD5
    if ( adsp_content_md5 != NULL ) {
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONTENT_MD5, *adsp_content_md5 );
    }

	dsd_const_string dsl_connection("keep-alive");
	if (ach_connection != NULL) {
		dsl_connection = *ach_connection;
	}
	if(dsl_connection.m_get_len() > 0) {
		ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONNECTION, dsl_connection);
		ads_session->dsc_control.boc_keep_alive = dsl_connection.m_equals_ic("keep-alive");
	}
#if 0
    // Connection
    if (ach_connection != NULL) {
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONNECTION, *ach_connection);
		ads_session->dsc_control.boc_keep_alive = (*ach_connection).m_equals_ic("keep-alive");
    }
    else {
        if (ads_session->dsc_http_hdr_in.in_http_version == 10) {
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONNECTION, "keep-alive");
			ads_session->dsc_control.boc_keep_alive = true;
        }
    }
#endif
    // Date
    time_t ltime;
    time(&ltime);
	struct tm dsl_today;
	// GreenwichMeanTime equals in HTTP the UTC-time (RFC2616-3.3.1)
#ifdef HL_UNIX
	gmtime_r(&ltime, &dsl_today);
#else
	gmtime_s(&dsl_today, &ltime);
#endif
    char tmpbuf[128];
    memset(&tmpbuf, 0, 128);
    size_t szl_date_len = strftime( tmpbuf, 128, "%a, %d %b %Y %H:%M:%S GMT", &dsl_today);
    dsd_const_string dsl_date(&tmpbuf[0], szl_date_len);
    ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_DATE, dsl_date);

#if 1
	 bool bol_chunked = (in_data_length != 0) && (in_mode & HDR_MODE_CONTENT_LENGTH) == 0;
	 if(ads_session->dsc_http_hdr_in.m_get_http_method() == ds_http_header::ien_meth_HEAD) { // HEAD: server MUST NOT return a message-body (RFC2616-9.4) -> return the correct content-length but omit encoding!!
		 bol_chunked = false;
	 }
	 else if((ads_session->ads_config->in_settings & SETTING_ENABLE_COMPRESSION) != 0
		 && this->bo_compress_makes_sense
		 && (ads_session->dsg_state.in_accept_encoding & ds_http_header::ien_ce_gzip) != 0)
	 {
		 bol_chunked = true;
		 ads_session->dsc_http_hdr_out.bo_hdr_gzip_set = true;
		 ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONTENT_ENCODING, HFV_GZIP);
	 }
	 if(bol_chunked) {
		 ads_session->dsc_http_hdr_out.bo_hdr_chunked_set = true;
		 ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_TRANSFER_ENCODING, "chunked");
	 }
	 else {
		 /* JF 07.10.08 Ticket[16052]: remove the prior changes, which were made for Ticket[16052]   
         || (ads_session->dsc_http_hdr_in.in_http_version == 10)*/ // JF 29.09.08 Ticket[16052]
        ds_hstring hstr_len(ads_session->ads_wsp_helper, "");
        hstr_len = in_data_length;
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONTENT_LENGTH, hstr_len.m_const_str());
	 }
#else
    // Content-Length / Transfer-Encoding / Content-Encoding
	 if( in_data_length < 0 ) {
			ads_session->dsc_http_hdr_out.bo_hdr_chunked_set = true;
         ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_TRANSFER_ENCODING, "chunked");
	 }
    else if ( ((ads_session->ads_config->in_settings & SETTING_ENABLE_COMPRESSION) == 0)
         || ((in_mode & HDR_MODE_CONTENT_LENGTH) != 0)
         /* JF 07.10.08 Ticket[16052]: remove the prior changes, which were made for Ticket[16052]   
         || (ads_session->dsc_http_hdr_in.in_http_version == 10)*/ ) { // JF 29.09.08 Ticket[16052]
        ds_hstring hstr_len(ads_session->ads_wsp_helper, "");
        hstr_len = in_data_length;
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONTENT_LENGTH, hstr_len.m_const_str());
    }
    else { // compression is enabled
        if ( (in_data_length == 0) ||
             (ads_session->dsc_http_hdr_in.m_get_http_method() == ds_http_header::ien_meth_HEAD) ) { // HEAD: server MUST NOT return a message-body (RFC2616-9.4) -> return the correct content-length but omit encoding!!
            ds_hstring hstr_len(ads_session->ads_wsp_helper, "");
            hstr_len = in_data_length;
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONTENT_LENGTH, hstr_len.m_const_str());
        }
        else { // write chunked data
            ads_session->dsc_http_hdr_out.bo_hdr_chunked_set = true;
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_TRANSFER_ENCODING, "chunked");
        }
    }
	 if(ads_session->dsc_http_hdr_out.bo_hdr_chunked_set) {
		 if ((ads_session->dsg_state.in_accept_encoding & ds_http_header::ien_ce_gzip) != 0) { // we can only send in gzip !!
				if (bo_compress_makes_sense) {
					ads_session->dsc_http_hdr_out.bo_hdr_gzip_set = true;
					ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONTENT_ENCODING, HFV_GZIP);
				}
		 }
	 }
#endif
    //-------------------------------------
    // terminate http-header
    //-------------------------------------
    ads_session->dsc_http_hdr_out.m_terminate_hdr_out();

	 if(ads_session->dsc_http_hdr_out.bo_hdr_chunked_set) {
		 ads_session->dsc_transaction.m_begin_chunked();
	 }
    
    return 0;
}  // m_create_resp_header


/*! \brief Creates a location string
 *
 * @ingroup webserver
 *
 * construct the string for the Location-header
 */
ds_hstring ds_webserver::m_create_location(const dsd_const_string& ach_path, const dsd_const_string& ach_query, bool bo_insert_ID_in_URL, bool bo_prevent_cookie_in_URL, const dsd_const_string* adsl_cookie)
{
    ds_hstring hstrl_location(ads_session->ads_wsp_helper);
#if 1
	// TODO: Check sense???
    hstrl_location.m_write("https://");
    if ((ads_session->ads_config->in_settings & SETTING_DISABLE_HTTPS) != 0) {
        hstrl_location.m_set("http://");
    }

    // Ticket[8758]  try to read hostname/port from http-header-field "host"; if not available -> hostname is read from configuration file (port must be added)
    if (ads_session->dsc_http_hdr_in.hstr_hf_host.m_get_len() > 0) {
        hstrl_location.m_write(ads_session->dsc_http_hdr_in.hstr_hf_host);
    }
    else { // read from config-file; port is otherwise
        hstrl_location.m_write(ads_session->hstr_conf_authority);
    }
#endif
    if (adsl_cookie != NULL) { // use this cookie-string (it was just created; e.g. after the authentication)
        if ( (!bo_prevent_cookie_in_URL) && (adsl_cookie->m_get_len() > 0) ) {
            if ( (ads_session->dsc_control.bo_cma_httpcookie_enabled == false) || (bo_insert_ID_in_URL) ) {
                hstrl_location.m_write("/(");
                hstrl_location.m_write(STRING_HOB);
                hstrl_location.m_write(*adsl_cookie);
                hstrl_location.m_write(")");
            }
        }
    }
    else {
    if ( (!bo_prevent_cookie_in_URL) && (ads_session->dsc_control.ds_cma_cookie.m_get_len() > 0) ) {
        if ( (ads_session->dsc_control.bo_cma_httpcookie_enabled == false) || (bo_insert_ID_in_URL) ) {
            hstrl_location.m_write("/(");
            hstrl_location.m_write(STRING_HOB);
            hstrl_location.m_write(ads_session->dsc_control.ds_cma_cookie);
            hstrl_location.m_write(")");
        }
    }
    }

    if ( (ach_path.m_get_len() > 0) ) {
        hstrl_location.m_write(ach_path);
    }

    if ( (ach_query.m_get_len() > 0) ) {
        // Ticket[12602, incorrect forum-display]:  ach_query already starts with '?'
        // so don't add another '?'
        if (ach_query[0] != '?') {
            hstrl_location.m_write("?");
        }
        hstrl_location.m_write(ach_query);
    }
    return hstrl_location;
}

int ds_webserver::m_conv_from_hexhexencoding(ds_hstring* ahstr_to_change)
{
	ds_hstring hstr_tmp(ads_session->ads_wsp_helper, ahstr_to_change->m_get_len()*2);
	dsd_const_string dsl_result;
	int inl_ret = m_conv_from_hexhexencoding(ahstr_to_change->m_const_str(), hstr_tmp, dsl_result);
	if(inl_ret != SUCCESS)
		return inl_ret;
	// copy data to output-string
   ahstr_to_change->m_set(dsl_result);
	return SUCCESS;
}

/*! \brief Converts Hexadecimal to characters
 *
 * @ingroup webserver
 *
 * replace the three bytes of '%HexHex' by one char (e.g. %20 = ' ')
 * additional: '+' to ' '
 */
int ds_webserver::m_conv_from_hexhexencoding(const dsd_const_string& hstr_src, ds_hstring& rdsp_tmp, dsd_const_string& rdsp_result)
{
	rdsp_result = hstr_src;
   if (hstr_src.m_get_len() <= 0) { // can be empty!
       return SUCCESS;
   }

   // The length of the string, on which we are working, can be changed.
   // So we must copy the data to a new string.
   // To avoid internal copying in hstr_ret, we setup to a twice length.
   //ds_hstring hstr_tmp(ads_session->ads_wsp_helper, hstr_src.m_get_len()*2);
	int iml_tmp_start = rdsp_tmp.m_get_len();
	if(!rdsp_tmp.m_ensure_size(iml_tmp_start+hstr_src.m_get_len(), true))
		return 6;

	// Construction area
	//char chrl_buffer[D_MAXCMA_NAME];
	//int inl_ret;
	//inl_ret = m_cpy_vx_vx( chrl_buffer, D_MAXCMA_NAME, ied_chs_utf_8, ahstr_to_change->m_get_ptr(), ahstr_to_change->m_get_len(), ied_chs_uri_1 );
	//if( inl_ret < 0 ){ return FALSE; }

	int inl_last_pos = 0;

    char ch;
    for (int i=0; i<hstr_src.m_get_len(); i++) {
        ch = hstr_src[i];

		  if (ch == '+') { // reconvert '+' to ' '
			   rdsp_tmp += hstr_src.m_substring(inl_last_pos, i);
				inl_last_pos = i + 1;
			   
				rdsp_tmp += ' ';
            continue;
        }
        if (ch == '%') { // reconvert %HexHex format
			   if (i > hstr_src.m_get_len()-3) { // at least 2 bytes must follow !!
                return 2;
            }
            // get first byte's int value
            int in_first = m_get_int_from_ASCII(hstr_src[i+1]);
            if (in_first < 0) { // invalid character
                return 3;
            }
            in_first = (in_first << 4); // first byte must be shifted to become the higher byte value

            // get second byte's int value
            int in_second = m_get_int_from_ASCII(hstr_src[i+2]);
            if (in_second < 0) { // invalid character
                return 4;
            }

            // JF 21.09.09 Reject URLs like /abc/file%00name.txt -> the URL would be cut by zero-termination!
            int in_hexhex = in_first | in_second;
            if (in_hexhex == 0x00) {
                return 5;
            }

            rdsp_tmp += hstr_src.m_substring(inl_last_pos, i);
				inl_last_pos = i + 3;
            
			// replace the three bytes of '%HexHex' by in_hexhex
            char ch_hex = (char)in_hexhex;
            rdsp_tmp += ch_hex;
            i+=2;

            continue;
        }

        // do not change this char
        // rdsp_tmp += ch;
    }

	 if(inl_last_pos <= 0) {
	    return SUCCESS;
	 }

	 rdsp_tmp += hstr_src.m_substring(inl_last_pos);

	 // copy data to output-string
	 rdsp_result = rdsp_tmp.m_const_str().m_substring(iml_tmp_start);
    return SUCCESS;
}

/*! \brief Converts ASCII to integer
 *
 * @ingroup webserver
 *
 * Gets Ascii characters and returns the value as integer
 */
int ds_webserver::m_get_int_from_ASCII(int in)
{
    if ( (in >= '0') && (in <= '9') ) {
        return (in - '0');
    }
    else if ( (in >= 'A') && (in <= 'F') ) {
        return (in - 'A' + 10);
    }
    else if ( (in >= 'a') && (in <= 'f') ) {
        return (in - 'a' + 10);
    }
    
    // invalid character !
    return -1;
}


/*! \brief Compresses Data
 *
 * @ingroup webserver
 *
 * private method ds_webserver::m_compress_data
 *  compress given data with zlib (zip) compression
 *
 * @param[in]   const char  *achp_data      data to get compressed
 * @param[in]   int         inp_len_data    length of data
 * @param[out]  char        **aachp_compr   compressed data
 * @param[out]  int         *ainp_len_compr length of compressed data
 * @return      bool                        true = success
 *                                          false otherwise
*/
bool ds_webserver::m_compress_data( const char *achp_data, int inp_len_data,
                                    const char **aachp_compr, int *ainp_len_compr )
{
    int inl_ret;

    inl_ret = ads_session->dsg_zlib_comp.m_do_work( (char*)achp_data,
                                                    ((char*)achp_data + inp_len_data),
                                                    true, true, true );
    if ( inl_ret < 0 ) {
        return false;
    }

    *ainp_len_compr = ads_session->dsg_zlib_comp.m_get_output_data( aachp_compr );
    ads_session->dsg_zlib_comp.m_reset();
    
    return ((*ainp_len_compr) > 0);
} /* end of ds_webserver::m_compress_data */


/*! \brief Compresses a file
 *
 * @ingroup webserver
 *
 * private method ds_webserver::m_compress_file
 *  compress file content
 *
 * @param[in]   const char  *achp_path      file path
 * @param[in]   int         inp_len_path    length of path
 * @param[out]  char        **aachp_compr   compressed file content
 * @param[out]  int         *ainp_len_compr length of compressed file content
 * @return      bool                        true = success
 *                                          false otherwise
*/
bool ds_webserver::m_compress_file( const char *achp_path, int inl_len_path,
                                    const char **aachp_compr, int *ainp_len_compr )
{
    void       *avl_file;
    char       *achl_content;
    int        inl_length;
    bool       bol_ret;

    /*
        open the file and read its content
    */
    avl_file = ads_session->ads_wsp_helper->m_open_file( achp_path, inl_len_path );
    if ( avl_file == NULL ) {
        return false;
    }

    bol_ret = ads_session->ads_wsp_helper->m_read_file( avl_file,
                                                        &achl_content,
                                                        &inl_length );
    if ( bol_ret == false ) {
        ads_session->ads_wsp_helper->m_close_file( avl_file );
        return false;
    }

    /*
        compress the file content
    */
    bol_ret = m_compress_data( achl_content, inl_length, aachp_compr, ainp_len_compr );
    ads_session->ads_wsp_helper->m_close_file( avl_file );
    return bol_ret;
} /* end of ds_webserver::m_compress_file */

bool ds_webserver::m_compress_www_file( const dsd_const_string& hstr_path, const char **aachp_file, int *ainp_length )
{
    ds_hstring dsl_path( ads_session->ads_wsp_helper );
    dsl_path.m_write( ads_session->ads_config->ach_root_dir );
	dsl_path.m_replace( "\\", "/" );
    dsl_path.m_write( hstr_path );
    return m_compress_file( dsl_path.m_get_ptr(), dsl_path.m_get_len(),
                            aachp_file, ainp_length );
} /* end of ds_webserver::m_compress_www_file */

#if 0
/*! \brief Compresses a special file
 *
 * @ingroup webserver
 *
 * private method ds_webserver::m_compress_hclient_cfg
 *  compress hclient cfg file
 *
 * @param[out]  char    **aachp_file    compressed file content
 * @param[out]  int     *ainp_length    length of compressed file content
 * @return      bool                    true = success
 *                                      false otherwise
*/
bool ds_webserver::m_compress_hclient_cfg( const char **aachp_file, int *ainp_length )
{
    ds_hstring dsl_path( ads_session->ads_wsp_helper );

    dsl_path.m_write( ads_session->ads_config->ach_root_dir );
	dsl_path.m_replace( "\\", "/" );
    dsl_path.m_write( "/public/lib/sslpublic/hclient.cfg" );
    

    return m_compress_file( dsl_path.m_get_ptr(), dsl_path.m_get_len(),
                            aachp_file, ainp_length );
} /* end of ds_webserver::m_compress_hlient_cfg */


/*! \brief Compresses a special file
 *
 * @ingroup webserver
 *
 * private method ds_webserver::m_compress_hclient_cdb
 *  compress hclient cdb file
 *
 * @param[out]  char    **aachp_file    compressed file content
 * @param[out]  int     *ainp_length    length of compressed file content
 * @return      bool                    true = success
 *                                      false otherwise
*/
bool ds_webserver::m_compress_hclient_cdb( const char **aachp_file, int *ainp_length )
{
    ds_hstring dsl_path( ads_session->ads_wsp_helper );

    dsl_path.m_write( ads_session->ads_config->ach_root_dir );
	dsl_path.m_replace( "\\", "/" );
    dsl_path.m_write( "/public/lib/sslpublic/hclient.cdb" );


    return m_compress_file( dsl_path.m_get_ptr(), dsl_path.m_get_len(),
                            aachp_file, ainp_length );
} /* end of ds_webserver::m_compress_hlient_cdb */


/*! \brief Compresses a special file
 *
 * @ingroup webserver
 *
 * private method ds_webserver::m_compress_hclient_pwd
 *  compress hclient pwd file
 *
 * @param[out]  char    **aachp_file    compressed file content
 * @param[out]  int     *ainp_length    length of compressed file content
 * @return      bool                    true = success
 *                                      false otherwise
*/
bool ds_webserver::m_compress_hclient_pwd( const char **aachp_file, int *ainp_length )
{
    ds_hstring dsl_path( ads_session->ads_wsp_helper );

    dsl_path.m_write(ads_session->ads_config->ach_root_dir);
	dsl_path.m_replace( "\\", "/" );
    dsl_path.m_write("/public/lib/sslpublic/hclient.pwd");


    return m_compress_file( dsl_path.m_get_ptr(), dsl_path.m_get_len(),
                            aachp_file, ainp_length );
} /* end of ds_webserver::m_compress_hlient_pwd */
#endif