/*+-------------------------------------------------------------------------+*/
/*| include global headers                                                  |*/
/*+-------------------------------------------------------------------------+*/
#include <rdvpn_globals.h>
#include "../ds_session.h"
#include <ds_hobte_conf.h>
#include <ds_wsp_helper.h>
#include <ds_hstring.h>
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H
#include <ds_usercma.h>
#include <ds_authenticate.h>
#include <auth_callback.h>
#include <hob-libwspat.h>
#ifdef HL_FREEBSD
#include <sys/socket.h>
#endif

#ifdef DS_PORTLET_FILTER_U_A
#include "xs_user_agent_worker.h"
#endif
/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "ds_pre_cma.h"
#include "ds_auth.h"

#ifdef _DEBUG
#define HL_DBG_PRINTF(x, ...)	/*printf(x, __VA_ARGS__)*/
#else
#define HL_DBG_PRINTF(x, ...)
#endif


/*+-------------------------------------------------------------------------+*/
/*| constructor:                                                            |*/
/*+-------------------------------------------------------------------------+*/
/**
 * ds_auth::ds_auth
*/
ds_auth::ds_auth(void)
{
    ien_workmode         = ied_pre_auth;
    inc_conn_state       = 0;
    dsc_logout.inc_state = 0;
    dsc_logout.inc_lang  = 0;

#ifdef DS_PORTLET_FILTER_U_A
    ibc_ua_portlet_filter = 0;
#endif
#if SM_USE_CERT_AUTH
	iec_certificate_auth = iec_cert_auth_result_not_checked;
	adsc_cert_auth_entry = NULL;
#endif

} //end of ds_auth::ds_auth


/*+-------------------------------------------------------------------------+*/
/*| destructor:                                                             |*/
/*+-------------------------------------------------------------------------+*/
/**
 * ds_auth::~ds_auth
*/
ds_auth::~ds_auth(void)
{
} //end of ds_auth::~ds_auth


/*+-------------------------------------------------------------------------+*/
/*| init function:                                                          |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief Class initialization method
 *
 * @ingroup authentication
 *
 * function ds_auth::m_init
 *
 * @param[in] ds_wsp_helper* ads_wsp_helper
*/
void ds_auth::m_init( ds_session* adsl_session )
{
    ads_session    = adsl_session;
    ads_wsp_helper = ads_session->ads_wsp_helper;
    dsc_pre_auth.m_init ( ads_wsp_helper );
    dsc_post_auth.m_init( ads_wsp_helper );
} // end of ds_auth::m_init

bool ds_auth::m_commit() {
	if(!this->dsc_pre_auth.m_commit())
		return false;
	return true;
}

/*+-------------------------------------------------------------------------+*/
/*| public functions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief Register a session
 *
 * @ingroup authentication
 *
 * function ds_auth::m_register
 * register a pre auth session to cma
 *
 * @param[in]   bool    bo_header_cookie        cookie in http header found?
*/
bool ds_auth::m_register( bool bo_header_cookie )
{
    // initialize some variables:
    bool bo_cma_created;                        // is cma created?

    //---------------------------------------------
    // check our work mode:
    //---------------------------------------------
    if ( ien_workmode != ied_pre_auth ) {
        ien_workmode = ied_pre_auth; //return false;
    }

    //---------------------------------------------
    // create cma:
    //---------------------------------------------
    bo_cma_created = dsc_pre_auth.m_create_cookie();

    //----------------------------------------------
    // init some states:
    //----------------------------------------------
    m_set_state( ST_OCCUPIED );
    if ( bo_header_cookie == true ) {
        m_set_state( ST_HTTP_COOKIE_ENABLED );
    }

    return bo_cma_created;
} // end of ds_auth::m_register

bool ds_auth::m_handle_login_cert() {
#if SM_USE_CERT_AUTH
     dsd_auth_t dsl_auth;
     memset( &dsl_auth, 0, sizeof(dsd_auth_t) );
     ds_wsp_helper* adsl_wsp_helper = ads_session->ads_wsp_helper;
     ds_authenticate ds_ident( adsl_wsp_helper ); // authentication class
	 struct dsd_wspat_public_config *adsp_wspat_conf = adsl_wsp_helper->m_get_wspat_config();
     if(!ds_ident.m_check_certificate_auth(adsp_wspat_conf, &dsl_auth))
         return false;
	 this->adsc_cert_auth_entry = dsl_auth.adsc_cert_auth_entry;
	 this->iec_certificate_auth = dsl_auth.iec_certificate_auth;
#if SM_USE_CERT_AUTH_V2
	 if(dsl_auth.iec_certificate_auth == iec_cert_auth_result_found) {
		ads_session->boc_fixed_login = true;
		ads_session->dsc_username = dsd_const_string(dsl_auth.achc_user, dsl_auth.inc_len_user);
		ads_session->dsc_domain = dsd_const_string(dsl_auth.achc_domain, dsl_auth.inc_len_domain);
		return false;
	 }
#endif

	 // Note: Password is optional (for SSO).
	 const char* achl_pwd = dsl_auth.inc_len_password > 0 ? dsl_auth.achc_password : NULL;
     bool bo_ret = this->ads_session->dsc_auth.m_login(
		 dsl_auth.achc_user, dsl_auth.inc_len_user, achl_pwd, dsl_auth.inc_len_password, NULL, 0, dsl_auth.achc_domain, dsl_auth.inc_len_domain, NULL);
	 ads_session->dsc_username = ads_session->dsc_auth.m_get_username();
	 ads_session->dsc_domain = ads_session->dsc_auth.m_get_domain();
	 ads_session->dsc_userdn = ads_session->dsc_auth.m_get_userdn();
     this->m_finish_login();
     return bo_ret;
#else
    return false;
#endif
}

void ds_auth::m_finish_login() {
        // from now on we will send only short header field "Server"
        ads_session->dsc_auth.m_set_state( ST_SHORT_HF_SERVER );

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



/*! \brief Login function
 *
 * @ingroup authentication
 *
 * function ds_auth::m_login
 * login user
 *
 * @param[in]   const char*     ach_usr         pointer to username
 * @param[in]   int             in_len_usr      length of username
 * @param[in]   const char*     ach_pwd         pointer to password
 * @param[in]   int             in_len_pwd      length of password
 * @param[in]   const char*     ach_old_pwd     pointer to old pwd (for changing)
 * @param[in]   int             in_len_old_pwd  length of old pwd
 * @param[in]   const char*     ach_domain      pointer to domain
 * @param[in]   int             in_len_domain   length of domain
 * @param[out]  dsd_kick_out_t* ads_kick_out
*/
bool ds_auth::m_login( const char *achp_usr,     int inp_len_usr,
                       const char *achp_pwd,     int inp_len_pwd,
                       const char *achp_old_pwd, int inp_len_old_pwd,
                       const char *achp_domain,  int inp_len_domain,
                       ds_hvector_btype<dsd_kick_out_t> *adsvp_kick_out )
{
    // initialize some variables:
    bool            bol_ret;                    // return for some funcs
    HL_UINT         uin_auth;                   // authentication return
    ds_authenticate ds_ident( ads_wsp_helper ); // authentication class
    dsd_auth_t      dsl_auth;                   // authentication structure
    ds_hstring      ds_user;                    // username
    ds_hstring      ds_domain;                  // user domain
#ifndef B20140805
    ds_hstring      ds_firstpassword;           // inital password for radius challenge
#endif
	ds_hstring      ds_msg( ads_wsp_helper );   // message
    ds_hstring      dsl_userdn(ads_wsp_helper); // user dn for password change
    ds_hstring      ds_state;                   // radius state
    ds_hstring      ds_bpage;                   // booked page
    int             inl_pos;                    // loop variable
    int             inl_same;                   // number of same users
    dsd_cma_session_no            chrl_session[256];          // session numbers of same users
	dsd_kick_out_t  dsl_kick_out;               // temp kickout structure

    //---------------------------------------------
    // check our work mode:
    //---------------------------------------------
    if ( ien_workmode != ied_pre_auth ) {
        m_logout();
    }

    //---------------------------------------------
    // fill authentication structure:
    //---------------------------------------------
    memset( &dsl_auth, 0, sizeof(dsd_auth_t) );

#if SM_USE_CERT_AUTH
	dsl_auth.iec_certificate_auth = this->iec_certificate_auth;
    /* Is special meaning for SSL client authentication? */
    if(achp_pwd == NULL) {
        //dsl_auth.iec_certificate_auth = iec_cert_auth_result_authenticated;
        achp_pwd = "";
        inp_len_pwd = 0;
    }
	/*else if(this->ads_session->boc_fixed_login) {
        dsl_auth.iec_certificate_auth = iec_cert_auth_result_found;
	}*/
#endif

    dsl_auth.adsc_out_usr     = &dsc_post_auth;
    if ( m_check_state( ST_CHALLENGE_IN_PROGRESS ) == false ) {
        dsl_auth.achc_user      = (char*)achp_usr;
        dsl_auth.inc_len_user   = inp_len_usr;
        dsl_auth.achc_domain    = (char*)achp_domain;
        dsl_auth.inc_len_domain = inp_len_domain;
    } else {
        ds_user = dsc_pre_auth.m_get_user();
        dsl_auth.achc_user    = ds_user.m_get_ptr();
        dsl_auth.inc_len_user = ds_user.m_get_len();
        ds_domain = dsc_pre_auth.m_get_domain();
        dsl_auth.achc_domain    = ds_domain.m_get_ptr();
        dsl_auth.inc_len_domain = ds_domain.m_get_len();       
#ifndef B20140805
		ds_firstpassword = dsc_pre_auth.m_get_password();
		dsl_auth.achc_firstpassword = ds_firstpassword.m_get_ptr();
		dsl_auth.inc_len_firstpassword = ds_firstpassword.m_get_len();
#endif
    }
    dsl_auth.achc_password    = (char*)achp_pwd;
    dsl_auth.inc_len_password = inp_len_pwd;
    dsl_auth.achc_old_pwd     = (char*)achp_old_pwd;
    dsl_auth.inc_len_old_pwd  = inp_len_old_pwd;

    // buffer for messages, challange:
    ds_state = dsc_pre_auth.m_get_radius();
    dsl_auth.adsc_state       = &ds_state;
    dsl_auth.adsc_out_msg     = &ds_msg;

    // userdn for forced ldap password change
    dsl_auth.adsc_userdn = &dsl_userdn;

    // callback:
    dsl_auth.avc_usrfield = (void*)ads_session;
    dsl_auth.amc_callback = &m_auth_callback;

    // connection state:
    dsl_auth.ainc_conn_state = &inc_conn_state;

    //---------------------------------------------
    // do authentication:
    //---------------------------------------------
    uin_auth = ds_ident.m_authenticate( &dsl_auth );

    if ( (uin_auth & AUTH_SUCCESS) == AUTH_SUCCESS ) {
        //-----------------------------------------
        // reset challenge and kickout state:
        //-----------------------------------------
        m_unset_state( ST_CHALLENGE_IN_PROGRESS );
        m_unset_state( ST_KICK_OUT );
        m_unset_state( ST_KICKED_OUT );

        //-----------------------------------------
        // set our work mode:
        //-----------------------------------------
        ien_workmode = ied_post_auth;

        //-----------------------------------------
        // get data from pre class:
        //-----------------------------------------
        ds_bpage = dsc_pre_auth.m_get_bpage();
        
        //-----------------------------------------
        // copy data from pre struct to post one:
        //-----------------------------------------
        m_set_state     ( ST_OCCUPIED );
        m_set_state     ( dsc_pre_auth.m_get_state() );
        m_set_bookedpage( ds_bpage.m_get_ptr(), ds_bpage.m_get_len() );
        if ( m_get_lang() == LANGUAGE_NOT_SET ) {
            m_set_lang( dsc_pre_auth.m_get_lang() );
        }

        if ( dsl_auth.inc_pw_expires != DEF_DONT_EXPIRE ) {
            dsc_post_auth.m_set_pwd_expires( dsl_auth.inc_pw_expires );
        }

        //-----------------------------------------
        // delete old pre auth cma:
        //-----------------------------------------
        dsc_pre_auth.m_delete_cookie();

    /*
        radius challenge:
    */
    } else if (    (uin_auth == (AUTH_FAILED | AUTH_METH_RADIUS     | AUTH_METH_CHALLENGE))
                || (uin_auth == (AUTH_FAILED | AUTH_METH_DYN_RADIUS | AUTH_METH_CHALLENGE)) ) {
        /*
            radius challenge:
            -> save user name
            -> save radius state
            -> set challenge state
        */
        if ( inp_len_usr > 0 ) {
            //dsc_pre_auth.m_set_user( ach_usr, in_len_usr );
            dsc_pre_auth.m_set_user( achp_domain, inp_len_domain,
                                     achp_usr,    inp_len_usr,
                                     achp_pwd,    inp_len_pwd,
									 NULL, 0);
        }
        if ( ds_msg.m_get_len() > 0 ) {
            dsc_pre_auth.m_set_message( 0, 0, ds_msg.m_const_str(),
                                        ads_session->ads_config->ach_login_site );
        }
        if ( ds_state.m_get_len() > 0 ) {
            dsc_pre_auth.m_set_radius( ds_state.m_get_ptr(),
                                       ds_state.m_get_len() );
        }
        m_set_state( ST_CHALLENGE_IN_PROGRESS );

    /*
        case of kick out:
    */
    } else if ( uin_auth == (AUTH_FAILED | AUTH_METH_CMA | AUTH_SAME_USER) ) {
        /*
            same user want's to login again:
            -> save users login data
            -> set state to kick out
            -> prepare kick out structure
        */

		if( inp_len_usr == 0 && dsl_auth.inc_len_user != 0 )
		{
			achp_usr	= dsl_auth.achc_user;
			inp_len_usr	= dsl_auth.inc_len_user;
		}
		// todo: if no user, return FALSE and setup a correct page

        dsc_pre_auth.m_set_user( dsl_auth.achc_domain,
                                 dsl_auth.inc_len_domain,
                                 achp_usr,    inp_len_usr,
                                 achp_pwd,    inp_len_pwd,
								 NULL, 0);
        m_set_state( ST_KICK_OUT );

        if ( adsvp_kick_out != NULL ) {
            adsvp_kick_out->m_init( ads_wsp_helper );
            if ( !adsvp_kick_out->m_empty() ) {
                adsvp_kick_out->m_clear();
            }

            // get all logged users:
            inl_same = ds_usercma::m_get_all_users( ads_wsp_helper,
                                                    achp_usr, inp_len_usr,
                                                    dsl_auth.achc_domain,
                                                    dsl_auth.inc_len_domain,
                                                    chrl_session,
                                                    sizeof(chrl_session) );
            for ( inl_pos = 0; inl_pos < inl_same; inl_pos++ ) {
                dsl_kick_out.chc_session = chrl_session[inl_pos];

                bol_ret = ds_usercma::m_get_login_info( ads_wsp_helper,
                                                        achp_usr, inp_len_usr,
                                                        dsl_auth.achc_domain,
                                                        dsl_auth.inc_len_domain,
                                                        chrl_session[inl_pos],
                                                        &dsl_kick_out.tmc_login,
                                                        &dsl_kick_out.dsc_ineta );
                if ( bol_ret == true ) {
                    adsvp_kick_out->m_add( dsl_kick_out );
                }
            }
        }

    /*
        no role possible role found:
    */
    } else if ( (uin_auth & AUTH_NO_ROLE_POSSIBLE) == AUTH_NO_ROLE_POSSIBLE ) {
        //-----------------------------------------
        // reset challenge and kickout state:
        //-----------------------------------------
        m_unset_state( ST_CHALLENGE_IN_PROGRESS );
        m_unset_state( ST_KICK_OUT );
        m_unset_state( ST_KICKED_OUT );
        dsc_pre_auth.m_clear_radius();

        //-----------------------------------------
        // set message:
        //-----------------------------------------
        m_set_msg( 0, 0, MSG_NO_ROLE_FOUND, ads_session->ads_config->ach_login_site );

    /*
        user has to change password:
    */
    } else if ( (uin_auth & AUTH_CHANGE_PWD) == AUTH_CHANGE_PWD ) {
        /*
            user has to change his password:
            -> save users login data
            -> set state to change password
        */
        if ( dsl_userdn.m_get_len() > 0 ) {
            dsc_pre_auth.m_set_user( achp_domain, inp_len_domain,
									 achp_usr,    inp_len_usr,
                                     NULL,        0,            
                                     dsl_userdn.m_get_ptr(),
                                     dsl_userdn.m_get_len());
        } else {
            dsc_pre_auth.m_set_user( achp_domain, inp_len_domain,
                                     achp_usr,    inp_len_usr,
                                     NULL,        0,
									 NULL,        0);
        }
        m_set_state( ST_CHANGE_PASSWORD );

    } else {
        //-----------------------------------------
        // reset challenge and kickout state:
        //-----------------------------------------
        m_unset_state( ST_CHALLENGE_IN_PROGRESS );
        m_unset_state( ST_KICK_OUT );
        m_unset_state( ST_KICKED_OUT );
        dsc_pre_auth.m_clear_radius();

        //-----------------------------------------
        // set message:
        //-----------------------------------------
        ads_session->dsc_auth.m_set_msg( ied_sdh_log_warning, 001, MSG_AUTH_FAILED,
                                         ads_session->ads_config->ach_login_site  );
    }
    return ((uin_auth & AUTH_SUCCESS) == AUTH_SUCCESS);
} // end of ds_auth::m_login


/*! \brief Ends a session
 *
 * @ingroup authentication
 *
 * function ds_auth::m_kick_out
 * kickout an existing session from same user
 *
 * @param[in]   char    chl_session         session number
 * @return      bool
*/
bool ds_auth::m_kick_out( const dsd_cma_session_no& chp_session )
{
    // initialize some variables:
    bool            bol_ret;                    // return from several function calls
    ds_hstring      dsl_domain;                 // users domain
    ds_hstring      dsl_user;                   // username
    char            chrl_name[D_MAXCMA_NAME];   // name of cma
    int             inl_nlen;                   // length of cma name

    //---------------------------------------------
    // check our work mode and state:
    //---------------------------------------------
    if (    ien_workmode               != ied_pre_auth
         || m_check_state(ST_KICK_OUT) == false ) {
        return false;
    }

    //---------------------------------------------
    // get userdata from pre cma:
    //---------------------------------------------
    dsl_domain   = dsc_pre_auth.m_get_domain();
    dsl_user     = dsc_pre_auth.m_get_user();
    if ( dsl_user.m_get_len() < 1 ) {
        return false;
    }
    
    //-------------------------------------------
    // create cma name:
    //-------------------------------------------
    inl_nlen = ds_usercma::m_create_name( dsl_user.m_get_ptr(),
                                          dsl_user.m_get_len(),
                                          dsl_domain.m_get_ptr(),
                                          dsl_domain.m_get_len(),
                                          chp_session,
                                          chrl_name, (int)sizeof(chrl_name) );
    if ( inl_nlen < 1 ) {
        return false;
    }

    //-------------------------------------------
    // user cma still existing?
    //-------------------------------------------
    int inl_ret = ds_usercma::m_exists_user( ads_wsp_helper,
                                         chrl_name, inl_nlen );
	if(inl_ret < 0)
		return false;
	if(inl_ret == 0)
		return true;
    //-----------------------------------------
    // logout currently loged in user:
    //-----------------------------------------
    dsc_post_auth.m_set_name( chrl_name, inl_nlen );
    ien_workmode = ied_post_auth; // otherwise logout will fail
    bol_ret      = m_logout();
    ien_workmode = ied_pre_auth;
    if ( bol_ret == false ) {
        return false;
    }
    return true;
} // end of ds_auth::m_kick_out


/*! \brief Cleanup after kickout
 *
 * @ingroup authentication
 *
 * function ds_auth::m_finish_kickout
 * move pre cma to post cma after kickout
*/
bool ds_auth::m_finish_kickout()
{    
    // initialize some variables:
    dsd_auth_t      dsl_auth;                   // authentication structure
    ds_hstring      dsl_domain;                 // users domain
    ds_hstring      dsl_user;                   // username
    ds_hstring      dsl_password;               // users password
    HL_UINT         uinl_auth;                  // auth return
    ds_authenticate dsl_ident( ads_wsp_helper );// authentication class
    ds_hstring      dsl_bpage;                  // bookmark

    //---------------------------------------------
    // check our work mode and state:
    //---------------------------------------------
    if (    ien_workmode               != ied_pre_auth
         || m_check_state(ST_KICK_OUT) == false ) {
        return false;
    }

    //---------------------------------------------
    // get userdata from pre cma:
    //---------------------------------------------
    dsl_domain   = dsc_pre_auth.m_get_domain();
    dsl_user     = dsc_pre_auth.m_get_user();
    dsl_password = dsc_pre_auth.m_get_password();
    if (    dsl_user.m_get_len()     < 1
         || dsl_password.m_get_len() < 1 ) {
        return false;
    }

    //---------------------------------------------
    // fill authentication structure:
    //---------------------------------------------
    memset( &dsl_auth, 0, sizeof(dsd_auth_t) );
    dsl_auth.achc_user        = dsl_user.m_get_ptr();
    dsl_auth.inc_len_user     = dsl_user.m_get_len();
    dsl_auth.achc_password    = dsl_password.m_get_ptr();
    dsl_auth.inc_len_password = dsl_password.m_get_len();
    dsl_auth.achc_domain      = dsl_domain.m_get_ptr();
    dsl_auth.inc_len_domain   = dsl_domain.m_get_len();
    dsl_auth.avc_usrfield     = (void*)ads_session;
    dsl_auth.amc_callback     = &m_auth_callback;
    dsl_auth.ainc_conn_state  = &inc_conn_state;
    dsl_auth.adsc_out_usr     = &dsc_post_auth;

    uinl_auth = dsl_ident.m_create_user( &dsl_auth );
    if ( (uinl_auth & AUTH_SUCCESS) == AUTH_SUCCESS ) {
        //-----------------------------------------
        // reset challenge and kickout state:
        //-----------------------------------------
        m_unset_state( ST_CHALLENGE_IN_PROGRESS );
        m_unset_state( ST_KICK_OUT );
        m_unset_state( ST_KICKED_OUT );

        //-----------------------------------------
        // set our work mode:
        //-----------------------------------------
        ien_workmode = ied_post_auth;

        //-----------------------------------------
        // get data from pre class:
        //-----------------------------------------
        dsl_bpage = dsc_pre_auth.m_get_bpage();
        
        //-----------------------------------------
        // copy data from pre struct to post one:
        //-----------------------------------------
        m_set_state     ( ST_OCCUPIED );
        m_set_state     ( dsc_pre_auth.m_get_state() );
        m_set_bookedpage( dsl_bpage.m_get_ptr(), dsl_bpage.m_get_len() );
        if ( m_get_lang() == LANGUAGE_NOT_SET ) {
            m_set_lang( dsc_pre_auth.m_get_lang() );
        }

        //-----------------------------------------
        // delete old pre auth cma:
        //-----------------------------------------
        dsc_pre_auth.m_delete_cookie();

    /*
        no possible role found:
    */
    } else if ( (uinl_auth & AUTH_NO_ROLE_POSSIBLE) == AUTH_NO_ROLE_POSSIBLE ) {
        //-----------------------------------------
        // reset challenge and kickout state:
        //-----------------------------------------
        m_unset_state( ST_CHALLENGE_IN_PROGRESS );
        m_unset_state( ST_KICK_OUT );
        m_unset_state( ST_KICKED_OUT );
        dsc_pre_auth.m_clear_radius();

        //-----------------------------------------
        // set message:
        //-----------------------------------------
        m_set_msg( 0, 0, MSG_NO_ROLE_FOUND, ads_session->ads_config->ach_login_site );

    } else {
        //-----------------------------------------
        // reset challenge and kickout state:
        //-----------------------------------------
        m_unset_state( ST_CHALLENGE_IN_PROGRESS );
        m_unset_state( ST_KICK_OUT );
        m_unset_state( ST_KICKED_OUT );
        dsc_pre_auth.m_clear_radius();

        //-----------------------------------------
        // set message:
        //-----------------------------------------
        ads_session->dsc_auth.m_set_msg( ied_sdh_log_warning, 001, MSG_AUTH_FAILED,
                                         ads_session->ads_config->ach_login_site  );
    }
    return ((uinl_auth & AUTH_SUCCESS) == AUTH_SUCCESS);
} // end of ds_auth::m_finish_kickout


/*! \brief Create new session
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_create_new
 * create a new session for the user who has seen kickout screen
*/
bool ds_auth::m_create_new()
{
    // initialize some variables:
    dsd_auth_t      dsl_auth;                   // authentication structure
    ds_hstring      dsl_domain;                 // users domain
    ds_hstring      dsl_user;                   // username
    ds_hstring      dsl_password;               // users password
    HL_UINT         uinl_auth;                  // auth return
    ds_authenticate dsl_ident( ads_wsp_helper );// authentication class
    ds_hstring      dsl_bpage;                  // bookmark

    //---------------------------------------------
    // check our work mode and state:
    //---------------------------------------------
    if (    ien_workmode               != ied_pre_auth
         || m_check_state(ST_KICK_OUT) == false        ) {
        return false;
    }

    //---------------------------------------------
    // get userdata from pre cma:
    //---------------------------------------------
    dsl_domain   = dsc_pre_auth.m_get_domain();
    dsl_user     = dsc_pre_auth.m_get_user();
    dsl_password = dsc_pre_auth.m_get_password();
    if (    dsl_user.m_get_len()     < 1
         || dsl_password.m_get_len() < 1 ) {
        return false;
    }

    //---------------------------------------------
    // fill authentication structure:
    //---------------------------------------------
    memset( &dsl_auth, 0, sizeof(dsd_auth_t) );
    dsl_auth.achc_user        = dsl_user.m_get_ptr();
    dsl_auth.inc_len_user     = dsl_user.m_get_len();
    dsl_auth.achc_password    = dsl_password.m_get_ptr();
    dsl_auth.inc_len_password = dsl_password.m_get_len();
    dsl_auth.achc_domain      = dsl_domain.m_get_ptr();
    dsl_auth.inc_len_domain   = dsl_domain.m_get_len();
    dsl_auth.avc_usrfield     = (void*)ads_session;
    dsl_auth.amc_callback     = &m_auth_callback;
    dsl_auth.ainc_conn_state  = &inc_conn_state;
    dsl_auth.adsc_out_usr     = &dsc_post_auth;
    
    uinl_auth = dsl_ident.m_create_user( &dsl_auth );
    if ( (uinl_auth & AUTH_SUCCESS) == AUTH_SUCCESS ) {
        //-----------------------------------------
        // reset challenge and kickout state:
        //-----------------------------------------
        m_unset_state( ST_CHALLENGE_IN_PROGRESS );
        m_unset_state( ST_KICK_OUT );
        m_unset_state( ST_KICKED_OUT );

        //-----------------------------------------
        // set our work mode:
        //-----------------------------------------
        ien_workmode = ied_post_auth;

        //-----------------------------------------
        // get data from pre class:
        //-----------------------------------------
        dsl_bpage = dsc_pre_auth.m_get_bpage();
        
        //-----------------------------------------
        // copy data from pre struct to post one:
        //-----------------------------------------
        m_set_state     ( ST_OCCUPIED );
        m_set_state     ( dsc_pre_auth.m_get_state() );
        m_set_bookedpage( dsl_bpage.m_get_ptr(), dsl_bpage.m_get_len() );
        if ( m_get_lang() == LANGUAGE_NOT_SET ) {
            m_set_lang( dsc_pre_auth.m_get_lang() );
        }

        //-----------------------------------------
        // delete old pre auth cma:
        //-----------------------------------------
        dsc_pre_auth.m_delete_cookie();

    /*
        no possible role found:
    */
    } else if ( (uinl_auth & AUTH_NO_ROLE_POSSIBLE) == AUTH_NO_ROLE_POSSIBLE ) {
        //-----------------------------------------
        // reset challenge and kickout state:
        //-----------------------------------------
        m_unset_state( ST_CHALLENGE_IN_PROGRESS );
        m_unset_state( ST_KICK_OUT );
        m_unset_state( ST_KICKED_OUT );
        dsc_pre_auth.m_clear_radius();

        //-----------------------------------------
        // set message:
        //-----------------------------------------
        m_set_msg( 0, 0, MSG_NO_ROLE_FOUND, ads_session->ads_config->ach_login_site );

    } else {
        //-----------------------------------------
        // reset challenge and kickout state:
        //-----------------------------------------
        m_unset_state( ST_CHALLENGE_IN_PROGRESS );
        m_unset_state( ST_KICK_OUT );
        m_unset_state( ST_KICKED_OUT );
        dsc_pre_auth.m_clear_radius();

        //-----------------------------------------
        // set message:
        //-----------------------------------------
        ads_session->dsc_auth.m_set_msg( ied_sdh_log_warning, 001, MSG_AUTH_FAILED,
                                         ads_session->ads_config->ach_login_site  );
    }
    return ((uinl_auth & AUTH_SUCCESS) == AUTH_SUCCESS);
} // end of ds_auth::m_create_new


/*! \brief Logout the current user
 *
 * @ingroup authentication
 *
 * function ds_auth::m_logout
 * logout current user
*/
bool ds_auth::m_logout()
{
    // initialize some variables:
    ds_authenticate ds_ident( ads_wsp_helper );     // authentication class
    dsd_auth_t      dsl_input;                      // authentication structure
    int             in_msg_type;                    // msg type, unused
    int             in_msg_code;                    // msg mode, unused

    //-------------------------------------------
    // check our work mode:
    //-------------------------------------------
    if ( ien_workmode != ied_post_auth ) {
        return false;
    }

    //-------------------------------------------
    // remove accepted state:
    //-------------------------------------------
    m_unset_state( ST_AUTHENTICATED );

    //-------------------------------------------
    // set our work mode:
    //-------------------------------------------
    ien_workmode = ied_post_logout;

    //-------------------------------------------
    // save states until end of session:
    //-------------------------------------------
    dsc_logout.inc_state = dsc_post_auth.m_get_state();

    //-------------------------------------------
    // save language until end of session:
    //-------------------------------------------
    dsc_logout.inc_lang = (int)dsc_post_auth.m_get_lang();
    
    //-------------------------------------------
    // save message until end of session:
    //-------------------------------------------
    dsc_logout.dsc_msg = dsc_post_auth.m_get_message( ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_ptr(),
                                                      ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_len(),
                                                      &in_msg_type, &in_msg_code );

    //-------------------------------------------
    // setup input for end session call:
    //-------------------------------------------
    memset( &dsl_input, 0, sizeof(dsd_auth_t) );
    dsl_input.adsc_out_usr = &dsc_post_auth;
    dsl_input.avc_usrfield = (void*)ads_session;
    dsl_input.amc_callback = &m_auth_callback;

    //-------------------------------------------
    // end session:
    //-------------------------------------------
    return ds_ident.m_end_session( &dsl_input );
} // end of ds_auth::m_logout


/*! \brief Change user password
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_change_password
 * change users password
 *
 * @param[in]   const char * const  achp_old        old password
 * @param[in]   int                 inp_old         old password length
 * @param[in]   const char * const  achp_new        new password
 * @param[in]   int                 inp_new         new password length
 * @return      bool
*/
HL_UINT ds_auth::m_change_password( const char * const achp_old, int inp_old,
                                 const char * const achp_new, int inp_new )
{
    ds_authenticate    dsl_ident( ads_wsp_helper ); // authentication class
    dsd_auth_t         dsl_input;                   // authentication structure
    struct dsd_getuser dsl_user;                    // user information
    bool               bol_ret;                     // return for some function calls
    HL_UINT            uinl_auth;                   // return of change password

    /*
        check for correct work mode
    */
    if ( ien_workmode != ied_post_auth ) {
		return AUTH_ERR_INTERNAL;
    }

    /*
        get and check user information
    */
    bol_ret = dsc_post_auth.m_get_user( &dsl_user );
    if (    bol_ret == false
         || dsl_user.dsc_username.m_get_len() < 1 ) {
	    return AUTH_ERR_USR;
    }

    /*
        try to change the password
    */
    memset( &dsl_input, 0, sizeof(dsd_auth_t) );
    dsl_input.achc_user        = dsl_user.dsc_username.m_get_ptr();
    dsl_input.inc_len_user     = dsl_user.dsc_username.m_get_len();
    dsl_input.achc_domain      = dsl_user.dsc_userdomain.m_get_ptr();
    dsl_input.inc_len_domain   = dsl_user.dsc_userdomain.m_get_len();
    dsl_input.achc_old_pwd     = (char*)achp_old;
    dsl_input.inc_len_old_pwd  = inp_old;
    dsl_input.achc_password    = (char*)achp_new;
    dsl_input.inc_len_password = inp_new;
    dsl_input.adsc_out_usr     = &dsc_post_auth;

    uinl_auth = dsl_ident.m_change_password( &dsl_input );
	return uinl_auth;
} // end of ds_auth::m_change_password


/*! \brief Store user settings in the LDAP
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_save_settings
 * save user settings in ldap
 *
 * @return bool                 true = success
 *                              false otherwise
*/
bool ds_auth::m_save_settings()
{
    // initialize some variables:
    ds_authenticate dsl_ident( ads_wsp_helper );
    dsd_auth_t      dsl_auth;

    if ( ien_workmode == ied_post_auth ) {
        memset( &dsl_auth, 0, sizeof(dsd_auth_t) );
        dsl_auth.adsc_out_usr = &dsc_post_auth;
        dsl_auth.avc_usrfield = (void*)ads_session;
        dsl_auth.amc_callback = &m_auth_callback;

        return dsl_ident.m_save_settings( &dsl_auth );
    }
    return false;
} // end of ds_auth::m_save_settings


/*! \brief Update the Common Memory Area
 *
 * @ingroup authentication
 *
 * function ds_auth::m_update
 * update cma with settings from our local structures
*/
void ds_auth::m_update()
{
    /*
        set workmode to pre auth (next call sets a new workmode)
        if we saved current state until end of session:
        -> reset saved state, lang and message
    */
    if ( ien_workmode == ied_post_logout ) {
        dsc_logout.inc_state = 0;
        dsc_logout.inc_lang  = 0;
        dsc_logout.dsc_msg.m_init ( ads_wsp_helper );
        dsc_logout.dsc_msg.m_reset();
    }
    ien_workmode = ied_pre_auth;
} // end of ds_auth::m_update


/*! \brief HTTP Cookie Reader
 *
 * @ingroup authentication
 *
 * function ds_auth::m_get_http_cookie
 *
 * @param[in] ds_hstring* ads_cookie
 * @return    bool                      true = success
*/
bool ds_auth::m_get_http_cookie( ds_hstring* ads_cookie )
{
    // initialize some variables:
    ds_hstring  dsl_decoded( ads_wsp_helper );
    ds_hstring  dsl_tmp( ads_wsp_helper );
    const char* ach_cookie;
    int         in_len;

    switch ( ien_workmode ) {
        case ied_pre_auth:
            dsc_pre_auth.m_get_cookie( &ach_cookie, &in_len );
            ads_cookie->m_write( ach_cookie, in_len );
            break;

        case ied_post_auth:
            dsl_decoded = dsc_post_auth.m_get_sticket();
            dsl_tmp = dsc_post_auth.m_get_username();

            dsl_decoded.m_write( dsl_tmp );       
            dsl_decoded.m_write( "/" );

            dsl_tmp = dsc_post_auth.m_get_userdomain();
            dsl_decoded.m_write( dsl_tmp );

            ads_cookie->m_write_rfc3548( dsl_decoded.m_get_ptr(), dsl_decoded.m_get_len() );
            break;

        default:
            return false;
    }
    return true;
} // end of ds_auth::m_get_http_cookie


/*! \brief Gets the length of the HTTP Cookie
 *
 * @ingroup authentication
 *
 * function ds_auth::m_get_len_http_cookie
 *
 * @return    int
*/
int ds_auth::m_get_len_http_cookie()
{
    // initialize some variables:
    ds_hstring ds_cookie;
    ds_cookie.m_setup( ads_wsp_helper );
    
    m_get_http_cookie( &ds_cookie );
    return ds_cookie.m_get_len();
} // end of ds_auth::m_get_len_http_cookie


/*! \brief Checks the HTTP cookie
 *
 * @ingroup authentication
 *
 * function ds_auth::m_check_http_cookie
 *
 * @param[in]   const char*       ach_cookie        pointer to cookie string
 * @param[in]   int               in_len_cookie     length of cookie
 * @param[out]  dsd_kicked_out_t* ads_kicked_out    if user was kicked out information about kicking out user
 * @return      bool                                true = success
*/
bool ds_auth::m_check_http_cookie( const char* ach_cookie, int in_len_cookie,
                                   dsd_kicked_out_t* ads_kicked_out           )
{
    // initialize some variables:
    int               in_pos;                       // working position in session ticket
    const char*       ach_decoded;                  // pointer to decoded session ticket
    int               in_len_decoded;               // length of decoded session ticket
    ds_authenticate   ds_ident( ads_wsp_helper );   // authentication class
    dsd_auth_t        dsl_auth;                     // authentication structure
    HL_UINT           uin_auth;                     // result from authentication
    ds_hstring        dsl_decoded;

#if 0
    //--------------------------------------
    // check length:
    //--------------------------------------
    if ( in_len_cookie < dsc_post_auth.m_size_sticket() ) {
#else
    //--------------------------------------
    // check if format is pre or post auth:
    //--------------------------------------
    if ( dsc_pre_auth.m_has_cookie_format(ach_cookie, in_len_cookie) ) {
#endif
        // open cma:
        dsc_pre_auth.m_set_name( ach_cookie, in_len_cookie );
        // it can't be a valid session ticket
        return false;
    }

    //--------------------------------------
    // encode imcomming cookie:
    //--------------------------------------
    dsl_decoded.m_setup( ads_wsp_helper );
    if(!dsl_decoded.m_from_rfc3548( ach_cookie, in_len_cookie ))
        return false;
    if (  dsl_decoded.m_get_len() < dsc_post_auth.m_size_sticket() + 1 ) {
        return false;
    }

    //--------------------------------------
    // parse cookie:
    //--------------------------------------
    ach_decoded    = dsl_decoded.m_get_ptr();
    in_len_decoded = dsl_decoded.m_get_len();
    memset( &dsl_auth, 0, sizeof(dsd_auth_t) );
    dsl_auth.achc_password    = ach_decoded;
    dsl_auth.inc_len_password = dsc_post_auth.m_size_sticket();

    dsl_auth.achc_user = &ach_decoded[dsl_auth.inc_len_password];
    for ( in_pos = dsl_auth.inc_len_password; in_pos < in_len_decoded; in_pos++ ) {
        if ( ach_decoded[in_pos] == '/' ) {
            break;
        }
    }
    if ( ach_decoded[in_pos] != '/' ) {
        // we have found no end of user name
        // it must be an invalid cookie
        return false;
    }
    dsl_auth.inc_len_user = in_pos - dsl_auth.inc_len_password;
    in_pos++;
    if ( in_pos < in_len_decoded ) {
        dsl_auth.achc_domain    = &ach_decoded[in_pos];
        dsl_auth.inc_len_domain = in_len_decoded - in_pos;
    }

    dsl_auth.adsc_out_usr = &dsc_post_auth;

    // connection state:
    dsl_auth.ainc_conn_state = &inc_conn_state;

    uin_auth = ds_ident.m_auth_session( &dsl_auth );
    if ( (uin_auth & AUTH_SUCCESS) == AUTH_SUCCESS ) {
        //--------------------------------------
        // set workmode:
        //--------------------------------------
        ien_workmode = ied_post_auth;
        return true;

    } else if ( uin_auth == (AUTH_FAILED | AUTH_METH_CMA | AUTH_KICKED_OUT) ) {
        /*
            user was kicked out by another user
            -> set kicked out state
            -> prepare kickout structure
        */
        if ( ads_kicked_out != NULL ) {
            // ineta:
            ads_kicked_out->ds_client = dsc_post_auth.m_get_client_ineta();
            // login time:
            ads_kicked_out->tm_login = dsc_post_auth.m_get_logintime();
        }
    } else {
        if ( uin_auth == (AUTH_FAILED | AUTH_METH_CMA | AUTH_ERR_CLIENTIP) ) {
            m_set_msg( ied_sdh_log_error, 100, MSG_CLIENT_ERROR, GLOBAL_LOGOUT_PAGE );
        }
    }
    
    return false;
} // end of ds_auth::m_check_http_cookie

/**
 * Check authentication by identity of session. 
 */
bool ds_auth::m_check_ident()
{
    switch(ien_workmode) {
    case ied_pre_auth:
    case ied_post_logout:
        if (!ds_usercma::m_get_usercma( ads_wsp_helper, &this->dsc_post_auth ))
            return false;
        ien_workmode = ied_post_auth;
        m_set_state( ST_OCCUPIED );
        m_set_state( dsc_pre_auth.m_get_state() );
        this->dsc_pre_auth.m_delete_cookie();
        return true;
    case ied_post_auth:
        return true;
    default:
        return false;
    }
}

/*! \brief Checks the state
 *
 * @ingroup authentication
 *
 * function ds_auth::m_check_state
 *
 * @param[in] int   in_state
 * @return    bool                      true = success
*/
bool ds_auth::m_check_state( int in_state )
{
    switch ( ien_workmode ) {
        case ied_pre_auth:
            return dsc_pre_auth.m_check_state( in_state );
        case ied_post_auth:
            return dsc_post_auth.m_check_state( in_state );
        case ied_post_logout:
            if ( (dsc_logout.inc_state & in_state) == in_state ) {
                return true;
            }
            return false;
        default:
            return false;
    }
} // end of ds_auth::m_check_state


/*! \brief Set a state
 *
 * @ingroup authentication
 *
 * function ds_auth::m_set_state
 *
 * @param[in] int   in_state
*/
void ds_auth::m_set_state( int in_state )
{
    if ( m_check_state( in_state ) == false ) {
        switch ( ien_workmode ) {
            case ied_pre_auth:
                dsc_pre_auth.m_set_state( in_state );
                break;
            case ied_post_auth:
                dsc_post_auth.m_set_state( in_state );
                break;
        }
    }
} // end of ds_auth::m_set_state


/*! \brief Unsets a state
 *
 * @ingroup authentication
 *
 * function ds_auth::m_unset_state
 *
 * @param[in] int   in_state
*/
void ds_auth::m_unset_state( int in_state )
{
    if ( m_check_state( in_state ) == true ) {
        switch ( ien_workmode ) {
            case ied_pre_auth:
                dsc_pre_auth.m_unset_state( in_state );
                break;
            case ied_post_auth:
                dsc_post_auth.m_unset_state( in_state );
                break;
        }
    }
} // end of ds_auth::m_unset_state


/*! \brief Initializes a state
 *
 * @ingroup authentication
 *
 * function ds_auth::m_init_state
 *
 * @param[in] int   in_state
*/
void ds_auth::m_init_state( int in_state )
{
    switch ( ien_workmode ) {
        case ied_pre_auth:
            dsc_pre_auth.m_init_state( in_state );
            break;
        case ied_post_auth:
            dsc_post_auth.m_init_state( in_state );
            break;
    }
} // end of ds_auth::m_init_state


/*! \brief Clears a state
 *
 * @ingroup authentication
 *
 * function ds_auth::m_clear_state
*/
void ds_auth::m_clear_state()
{
    return m_init_state( 0 );
} // end of ds_auth::m_clear_state


/*! \brief Get role of user
 *
 * @ingroup authentication
 *
 * public method ds_auth::m_get_role
 *  get role of current logged in user
 *
 * @return dsd_role*
*/
struct dsd_role* ds_auth::m_get_role()
{
	// hofmants: why only in post_auth? added pre_auth too!
    if ( ien_workmode == ied_post_auth || ien_workmode == ied_pre_auth )
	{
        return dsc_post_auth.m_get_role();
    }
    return NULL;
} /* end of ds_auth::m_get_role */


/*! \brief Get role name
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_role_name
 * get name of selected role
 * 
 * @param[out]  char**  aach_name
 * @param[out]  int*    ain_len
 * @return      bool
*/
bool ds_auth::m_get_role_name( const char** aach_name, int* ain_len )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_get_role_name( aach_name, ain_len );
    }
    return false;
} // end of ds_auth::m_get_role_name


/*! \brief Get configured portlets
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_portlets
 *
 * @return      dsd_role_portlet*
*/
bool ds_auth::m_get_portlets( ds_hvector<ds_portlet>* ads_vportlets )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_get_portlets( ads_vportlets );
    }
    return false;
} // end of ds_auth::m_get_portlets


/*! \brief Get single portlet
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_portlet
 * get portlet by index
 *
 * @param[in]       int         in_index        position index
 * @param[in/out]   ds_portlet* ads_portlet     output portlet
 * @return          bool                        true = success
*/
bool ds_auth::m_get_portlet( dsd_random_access_iterator& adsp_itr, ds_portlet* ads_portlet )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_get_portlet( adsp_itr.inc_cur, ads_portlet );
    }
    return false;
} // end of ds_auth::m_get_portlet


/*! \brief Count portlets
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_count_portlets
 * count portlets for current user
 *
 * @return  int
*/
int ds_auth::m_count_portlets(dsd_random_access_iterator& rdsp_iter_out)
{
    if ( ien_workmode == ied_post_auth ) {
        rdsp_iter_out.inc_cur = 0;
        rdsp_iter_out.inc_end = dsc_post_auth.m_count_portlets();
        return rdsp_iter_out.inc_end;
    }
    return 0;
} // end of ds_auth::m_count_portlets


/*! \brief Checks if a portlet is allowed
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_is_portlet_allowed
 *
 * @param[in]   const char* ach_name        portlet name
 * @return      bool
*/
bool ds_auth::m_is_portlet_allowed( const dsd_const_string& ach_name )
{
    return m_is_portlet_allowed(ach_name.m_get_start(), ach_name.m_get_len());
} // end of ds_auth::m_is_portlet_allowed


/*! \brief Checks if a portlet is allowed
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_is_portlet_allowed
 *
 * @param[in]   const char* ach_name        portlet name
 * @param[in]   int         in_len          length of name
 * @return      bool
*/
bool ds_auth::m_is_portlet_allowed( const char* ach_name, int in_len )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_is_portlet_allowed( ach_name, in_len );
    }
    return false;
} // end of ds_auth::m_is_portlet_allowed


/*! \brief Checks if caching is allowed
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_is_caching_allowed
 *
 * @return  bool
*/
bool ds_auth::m_is_caching_allowed()
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_is_caching_allowed();
    }
    return false;
} // end of ds_auth::m_is_caching_allowed


/*! \brief Checks if config is allowed
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_is_config_allowed
 *
 * @return  bool
*/
bool ds_auth::m_is_config_allowed( int inp_config )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_is_config_allowed( inp_config );
    }
    return false;
} // end of ds_auth::m_is_config_allowed

/*! \brief Get welcomepage
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_welcomepage
 *
 * @return  ds_hstring
*/
ds_hstring ds_auth::m_get_welcomepage()
{
    // initialize some variables:
    bool       bol_ret;
    const char*      achl_wpage;
    int        inl_wpage;
    ds_hstring dsl_ret( ads_wsp_helper );

    if ( ien_workmode == ied_post_auth ) {
        bol_ret = dsc_post_auth.m_get_welcomepage( &achl_wpage, &inl_wpage );
        if ( bol_ret == true ) {
            dsl_ret.m_write( achl_wpage, inl_wpage );
        }
    }
    return dsl_ret;
} // end of ds_auth::m_get_welcomepage

/*! \brief Get welcomepage
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_welcomepage
 *
 * @return  bool success
*/
bool ds_auth::m_get_welcomepage( const char **aachp_wpage, int *ainp_len )
{
    if ( ien_workmode == ied_post_auth )
	{
        return dsc_post_auth.m_get_welcomepage( aachp_wpage, ainp_len );
    }
    return false;
} // end of ds_auth::m_get_welcomepage


/*! \brief Get GUI skin
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_gui_skin
 *
 * @param[in]   char**  aach_skin
 * @param[in]   int*    ain_len
 * @return      bool
*/
bool ds_auth::m_get_gui_skin( const char** aach_skin, int* ain_len )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_get_gui_skin( aach_skin, ain_len );
    }
    return false;
} // end of ds_auth::m_get_gui_skin+


/*! \brief Get booked page
 *
 * @ingroup authentication
 *
 * function ds_auth::m_get_bookedpage
 *
 * return   ds_hstring
*/
ds_hstring ds_auth::m_get_bookedpage()
{
    // initialize some variables:
    ds_hstring ds_bpage( ads_wsp_helper );

    switch ( ien_workmode ) {
        case ied_pre_auth:
            return dsc_pre_auth.m_get_bpage();
        case ied_post_auth:
            return dsc_post_auth.m_get_bpage();
        default:
            break;
    }

    return ds_bpage;
} // end of ds_auth::m_get_bookedpage


/*! \brief Set booked page
 *
 * @ingroup authentication
 *
 * function ds_auth::m_set_bookedpage
 * 
 * @param[in]   const char* ach_page
 * @param[in]   int         in_len
*/
bool ds_auth::m_set_bookedpage( const char* ach_page, int in_len )
{
    switch ( ien_workmode ) {
        case ied_pre_auth:
            return dsc_pre_auth.m_set_bpage( ach_page, in_len );

        case ied_post_auth:
            return dsc_post_auth.m_set_bpage( ach_page, in_len );

        default:
            return false;
    }
} // end of ds_auth::m_set_bookedpage


/*! \brief Get message
 *
 * @ingroup authentication
 *
 * function ds_auth::m_get_msg
 *
 * @param[out]  dsd_msg_t* ads_msg
 * @return      bool
*/
bool ds_auth::m_get_msg( dsd_msg_t* ads_msg )
{
    // initialize some variables:
    int inl_type = 0;
    int inl_code = 0;

    switch ( ien_workmode ) {
        case ied_pre_auth:
            ads_msg->hstr_msg = dsc_pre_auth.m_get_message( ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_ptr(),
                                                            ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_len(),
                                                            &inl_type, &inl_code );
            ads_msg->inc_type = inl_type;
            ads_msg->inc_code = inl_code;
            return true;
        case ied_post_auth:
            ads_msg->hstr_msg = dsc_post_auth.m_get_message( ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_ptr(),
                                                             ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_len(),
                                                             &inl_type, &inl_code );
            ads_msg->inc_type = inl_type;
            ads_msg->inc_code = inl_code;
            return true;
        case ied_post_logout:
            dsc_logout.dsc_msg.m_init( ads_wsp_helper );
            ads_msg->hstr_msg = dsc_logout.dsc_msg;
            ads_msg->inc_type = 0;
            ads_msg->inc_code = 0;
            return true;
    }
    return false;
} // end of ds_auth::m_get_msg


/*! \brief Sets a message
 *
 * @ingroup authentication
 *
 * function ds_auth::m_set_msg
 * set a message for a given url
 * 
 * @param[in]   int           in_msg_type   message type ( 1=info, 2=warning, 4=error)
 * @param[in]   int           in_msg_code   message code (like error code)
 * @param[in]   const char*   ach_msg       message itself
 * @param[in]   const char*   ach_url       message url
*/
bool ds_auth::m_set_msg( int in_msg_type,     int in_msg_code,
                         const dsd_const_string& ach_msg, const dsd_const_string& ach_url )
{
    switch ( ien_workmode ) {
        case ied_pre_auth:
            return dsc_pre_auth.m_set_message( in_msg_type, in_msg_code,
                ach_msg, ach_url );
        case ied_post_auth:
            return dsc_post_auth.m_set_message( in_msg_type, in_msg_code,
                                                ach_msg, ach_url );
        default:
            return false;
    }
} // end of ds_auth::m_set_msg


/*! \brief Sets a language
 *
 * @ingroup authentication
 *
 * function ds_auth::m_set_lang
 * set language
 *
 * @param[in]   int in_lang
*/
void ds_auth::m_set_lang( int in_lang )
{
    switch ( ien_workmode ) {
        case ied_pre_auth:
            dsc_pre_auth.m_set_lang( in_lang );
            break;

        case ied_post_auth:
            dsc_post_auth.m_set_lang( in_lang );
            break;

        default:
            return;
    }
} // end of ds_auth::m_set_lang


/*! \brief Gets the language
 *
 * @ingroup authentication
 *
 * function ds_auth::m_get_lang
 * get language
 *
 * @return   int
*/
int ds_auth::m_get_lang()
{
    switch ( ien_workmode ) {
        case ied_post_logout:
            return dsc_logout.inc_lang;

        case ied_pre_auth:
            return dsc_pre_auth.m_get_lang();

        case ied_post_auth:
            return dsc_post_auth.m_get_lang();

        default:
            return -1;
    }
} // end of ds_auth::m_get_lang


/*! \brief Show the little flyer
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_show_flyer
 * show wsg flyer?
 *
 * @return  bool                    true = show flyer
*/
bool ds_auth::m_show_flyer()
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_show_flyer();
    }
    return false;
} // end of ds_auth::m_show_flyer


/*! \brief Set the flyer
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_set_flyer
 * save settings for wsg flyer
 *
 * @param[in]   bool    bo_show         true = show flyer
*/
void ds_auth::m_set_flyer( bool bo_show )
{
    if ( ien_workmode == ied_post_auth ) {
        dsc_post_auth.m_set_flyer( bo_show );
    }
} // end of ds_auth::m_set_flyer


/**
 * \ingroup authlib
 *
 * function ds_usercma::m_set_default_portlet
 * set default portlet
 *
 * @param[in]   const char* achp_default_portlet
 * @param[in]   int         inp_length
 * @return      bool
*/
bool ds_auth::m_set_default_portlet( const char* achp_default_portlet, int inp_length ) {
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_set_default_portlet(achp_default_portlet, inp_length);
    }
    return false;
}

/**
 * \ingroup authlib
 *
 * function ds_usercma::m_get_default_portlet
 * get default portlet
 *
 * @param[in]   ds_hstring* adsp_default_portlet
 * @return      bool
*/
bool ds_auth::m_get_default_portlet( ds_hstring* adsp_default_portlet ) {
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_get_default_portlet(adsp_default_portlet);
    }
    return false;
}

/**
 * \ingroup authlib
 *
 * function ds_auth::m_has_default_portlet
 * check if default portlet is set
 *
 * @return      bool
*/
bool ds_auth::m_has_default_portlet( ) {
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_has_default_portlet( );
    }
    return false;
}


/*! \brief Get the ICA port
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_ica_port
 *  get ica port
 *
 * @return  int
*/
int ds_auth::m_get_ica_port()
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_get_ica_port();
    }
    return -1;
} // end of ds_auth::m_get_ica_port


/*! \brief Set the ICA port
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_set_ica_port
 *  set ica port
 *
 * @param[in]   int     inp_port
 * @return      bool
*/
bool ds_auth::m_set_ica_port( int inp_port )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_set_ica_port( inp_port );
    }
    return false;
} // end of ds_auth::m_set_ica_port


/*! \brief Checks if the ICA is active
 *
 * @ingroup authentication
 *
 * public method ds_auth::m_is_ica_active
 *
 * @return bool
*/
bool ds_auth::m_is_ica_active()
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_is_ica_active();
    }
    return false;
} /* end of ds_auth::m_is_ica_active */


/*! \brief Increase the ICA count
 *
 * @ingroup authentication
 *
 * public method ds_auth::m_increase_ica_count
 *
 * @return bool
*/
bool ds_auth::m_increase_ica_count()
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_increase_ica_count();
    }
    return false;
} /* end of ds_auth::m_increase_ica_count */


/*! \brief Decrease the ICA count
 *
 * @ingroup authentication
 *
 * public method ds_auth::m_decrease_ica_count
 *
 * @return bool
*/
bool ds_auth::m_decrease_ica_count()
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_decrease_ica_count();
    }
    return false;
} /* end of ds_auth::m_decrease_ica_count */


/*! \brief Reset the ICA counter
 *
 * @ingroup authentication
 *
 * public method ds_auth::m_reset_ica_count
 *
 * @return bool
*/
bool ds_auth::m_reset_ica_count()
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_reset_ica_count();
    }
    return false;
} /* end of ds_auth::m_reset_ica_count */


/*! \brief Get the current state
 *
 * @ingroup authentication
 *
 * function ds_auth::m_get_state
 * get state
 *
 * @return   int
*/
int ds_auth::m_get_state()
{
	HL_DBG_PRINTF("ds_auth::m_get_state(): ien_workmode=%d\n", ien_workmode);
    switch ( ien_workmode ) {
        case ied_pre_auth:
            return dsc_pre_auth.m_get_state();

        case ied_post_auth:
            return dsc_post_auth.m_get_state();

        default:
            return 0;
    }
} // end of ds_auth::m_get_state


/*! \brief Get the last accessed webserver
 *
 * @ingroup authentication
 *
 * function ds_auth::m_get_lws
 * get last webserver
 *
 * @param[in]   int*        ain_proto
 * @param[in]   int*        ain_port
 * return       ds_hstring 
*/
ds_hstring ds_auth::m_get_lws( int* ain_proto, int* ain_port )
{
    ds_hstring ds_out( ads_wsp_helper );
    if ( ien_workmode != ied_post_auth ) {
        return ds_out;
    }

    return dsc_post_auth.m_get_lastws( ain_proto, ain_port );
} // end of ds_auth::m_get_lws


/*! \brief Set the last accessed webserver
 *
 * @ingroup authentication
 *
 * function ds_auth::m_set_lws
 * set last webserver
 *
 * @param[in]   int         in_proto
 * @param[in]   const char* ach_lws     pointer to last webserver
 * @param[in]   int         in_len      length of last webserver
 * @param[in]   int         in_port
 *
 * return       bool
*/
bool ds_auth::m_set_lws( int in_proto, const char* ach_lws, int in_len, int in_port )
{
    if ( ien_workmode != ied_post_auth ) {
        return false;
    }

    return dsc_post_auth.m_set_lastws( in_proto, ach_lws, in_len, in_port );
} // end of ds_auth::m_set_lws


/*! \brief Get Single Sign on timestamp
 *
 * @ingroup authentication
 *
 * function ds_auth::m_get_sso_time
 * get sso timestamp
 *
 * @param[in]   int     in_index
 * @return      hl_time_t
*/
hl_time_t ds_auth::m_get_sso_time( int in_index )
{
    if ( ien_workmode != ied_post_auth ) {
        return 0;
    }

    return dsc_post_auth.m_get_sso_time( in_index );
} // end of ds_auth::m_get_sso_time


/*! \brief Get Single Sign On timestamp
 *
 * @ingroup authentication
 *
 * function ds_auth::m_get_sso_time
 * get sso timestamp
 *
 * @param[in]   int     in_index
 * @param[in]   hl_time_t  il_time
 * @return      bool
*/
bool ds_auth::m_set_sso_time( int in_index, hl_time_t il_time )
{
    if ( ien_workmode != ied_post_auth ) {
        return false;
    }

    return dsc_post_auth.m_set_sso_time( in_index, il_time );
} // end of ds_auth::m_set_sso_time

/*! \brief Get complete user information
 *
 * @ingroup authentication
 *
 * public function m_get_user
 * get all current user information at once
 *
 * @param[out]  struct dsd_getuser* ads_user
 * @return      bool
*/
bool ds_auth::m_get_user( struct dsd_getuser* ads_user )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_get_user( ads_user );
    }
    return false;
} // end of ds_auth::m_get_user


/*! \brief Get user name
 *
 * @ingroup authentication
 *
 * function ds_auth::m_get_username
 * get current user name
 *
 * @return      ds_hstring
*/
ds_hstring ds_auth::m_get_username()
{
#ifdef B20140805
    ds_hstring ds_user( ads_wsp_helper );
    switch ( ien_workmode ) {
        case ied_pre_auth:
            if (    ads_session->achc_username != NULL
                 && ads_session->inc_len_username > 0 ) {
                ds_user.m_write( ads_session->achc_username, 
                                 ads_session->inc_len_username );
            } else {
                return dsc_pre_auth.m_get_user();
            }
            break;
        case ied_post_auth:
            return dsc_post_auth.m_get_username();
    }
    return ds_user;
#else
    switch ( ien_workmode ) {
        case ied_pre_auth:
			if (    ads_session->dsc_username.m_get_len() > 0 ) {
                return ads_session->dsc_username;
            } else {
                return dsc_pre_auth.m_get_user();
            }
            break;
        case ied_post_auth:
            return dsc_post_auth.m_get_username();
		  default:
			  return (ds_hstring());
	 }
#endif
} // end of ds_auth::m_get_username

/*! \brief Get userdn
 *
 * @ingroup authentication
 *
 * function ds_auth::m_get_userdn
 * get current userdn
 *
 * @return      ds_hstring
*/
ds_hstring ds_auth::m_get_userdn()
{
#ifdef B20140805
    ds_hstring ds_userdn( ads_wsp_helper );
    switch ( ien_workmode ) {
        case ied_pre_auth:
            if (    ads_session->achc_userdn != NULL
                 && ads_session->inc_len_userdn > 0 ) {
                ds_userdn.m_write( ads_session->achc_userdn, 
                                 ads_session->inc_len_userdn );
            } else {
                return dsc_pre_auth.m_get_userdn();
            }
            break;
        case ied_post_auth:
            return dsc_post_auth.m_get_userdn();
    }
    return ds_userdn;
#else
    switch ( ien_workmode ) {
        case ied_pre_auth:
			if (    ads_session->dsc_userdn.m_get_len() > 0 ) {
                return ads_session->dsc_userdn;
            } else {
                return dsc_pre_auth.m_get_userdn();
            }
            break;
        case ied_post_auth:
            return dsc_post_auth.m_get_userdn();
		  default:
			  return (ds_hstring());
    }
#endif
} // end of ds_auth::m_get_userdn

/*! \brief Get user domain
 *
 * @ingroup authentication
 *
 * function ds_auth::m_get_domain
 * get current user domain
 *
 * @return      ds_hstring
*/
ds_hstring ds_auth::m_get_domain()
{
#ifdef B20140805
    ds_hstring ds_domain( ads_wsp_helper );
    switch ( ien_workmode ) {
        case ied_pre_auth:
            if (    ads_session->achc_domain != NULL
                 && ads_session->inc_len_domain > 0 ) {
                ds_domain.m_write( ads_session->achc_domain, 
                                   ads_session->inc_len_domain );
            } else {
                return dsc_pre_auth.m_get_domain();
            }
            break;
        case ied_post_auth:
            return dsc_post_auth.m_get_userdomain();
    }
    return ds_domain;
#else
    switch ( ien_workmode ) {
        case ied_pre_auth:
			if (    ads_session->dsc_domain.m_get_len() > 0 ) {
                return ads_session->dsc_domain;
            } else {
                return dsc_pre_auth.m_get_domain();
            }
            break;
        case ied_post_auth:
            return dsc_post_auth.m_get_userdomain();
		  default:
			  return (ds_hstring());
    }
#endif
} // end of ds_auth::m_get_domain


/*! \brief Get user name
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_hobsocks_name
 * get username for hobsocks protocol
 *
 * @return      ds_hstring
*/
ds_hstring ds_auth::m_get_hobsocks_name()
{
    ds_hstring ds_user( ads_wsp_helper );
    switch ( ien_workmode ) {
        case ied_pre_auth:
            break;
        case ied_post_auth:
            return dsc_post_auth.m_get_hobsocks_name();
    }
    return ds_user;
} // end of ds_auth::m_get_hobsocks_name()


/*! \brief Get password
 *
 * @ingroup authentication
 *
 * function ds_auth::m_get_password
 * get current user password
 *
 * @return      ds_hstring
*/
ds_hstring ds_auth::m_get_password()
{
    ds_hstring ds_pwd( ads_wsp_helper );
    switch ( ien_workmode ) {
        case ied_pre_auth:
            break;
        case ied_post_auth:
            return dsc_post_auth.m_get_password();
    }
    return ds_pwd;
} // end of ds_auth::m_get_password


/*! \brief Get Session Ticket
 *
 * @ingroup authentication
 *
 * function ds_auth::m_get_sticket
 * get current session ticket
 *
 * @return      ds_hstring
*/
ds_hstring ds_auth::m_get_sticket()
{
    ds_hstring ds_sticket( ads_wsp_helper );
    const char* ach_cookie;
    int       in_len;

    switch ( ien_workmode ) {
        case ied_pre_auth:
            dsc_pre_auth.m_get_cookie( &ach_cookie, &in_len );
            ds_sticket.m_write( ach_cookie, in_len );
            break;
        case ied_post_auth:
            return dsc_post_auth.m_get_sticket();
    }
    return ds_sticket;
} // end of ds_auth::m_get_sticket


/*! \brief Get authentication method
 *
 * @ingroup authentication
 *
 * function ds_auth::m_get_authmethod
 * get current auth method
 *
 * @return      int
*/
int ds_auth::m_get_authmethod()
{
    if( ien_workmode == ied_post_auth ) {
        enum ied_usercma_login_flags iep_auth_flags;
        return dsc_post_auth.m_get_authmethod(iep_auth_flags);
    }
    return -1;
} // end of ds_auth::m_get_authmethod

/*! \brief Check password expiry
 *
 * @ingroup authentication
 *
 * function ds_auth::m_pwd_expires
 *
 * @return      int
*/
int ds_auth::m_pwd_expires()
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_pwd_expires();
    }
    return DEF_DONT_EXPIRE;
} // end of ds_auth::m_pwd_expires


/*! \brief Reset password expiry
 *
 * @ingroup authentication
 *
 * function ds_auth::m_reset_pwd_expires
 *
 * @return      bool
*/
bool ds_auth::m_reset_pwd_expires()
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_reset_pwd_expires();
    }
    return false;
} // end of ds_auth::m_reset_pwd_expires


/*! \brief Save kickout information
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_saved_kicked_out
 * save kicked out information
 *
 * @param[in] dsd_kicked_out_t* ads_kicked_out
 * @return    bool
*/
bool ds_auth::m_save_kicked_out( dsd_kicked_out_t* ads_kicked_out )
{
    switch( ien_workmode ) {
        case ied_pre_auth:
            return dsc_pre_auth.m_save_kicked_out( ads_kicked_out );
        default:
            return false;
    }
} // end of ds_auth::m_save_kicked_out


/*! \brief Get the IP address
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_kicked_out_ineta
 * get ineta of the client who kicked us out
 *
 * @return    ds_hstring
*/
ds_hstring ds_auth::m_get_kicked_out_ineta()
{
    // initialize some variables:
    ds_hstring       dsl_ineta( ads_wsp_helper );
    dsd_kicked_out_t dsl_kicked_out;
    bool             bol_ret;

    switch( ien_workmode ) {
        case ied_pre_auth:
            bol_ret = dsc_pre_auth.m_get_kicked_out( &dsl_kicked_out );
            if ( bol_ret == true ) {
                m_print_ineta( &dsl_ineta, dsl_kicked_out.ds_client );
            }
            break;
    }
    return dsl_ineta;
} // end of ds_auth::m_get_kicked_out


/*! \brief Get the time someone was kicked out
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_kicked_out_time
 * get time of our kick out
 *
 * @return    hl_time_t
*/
hl_time_t ds_auth::m_get_kicked_out_time()
{
    // initialize some variables:
    hl_time_t           tml_time;
    dsd_kicked_out_t dsl_kicked_out;
    bool             bol_ret;

    switch( ien_workmode ) {
        case ied_pre_auth:
            bol_ret = dsc_pre_auth.m_get_kicked_out( &dsl_kicked_out );
            if ( bol_ret == true ) {
                tml_time = dsl_kicked_out.tm_login;
            } else {
                tml_time = 0;
            }
            break;
        default:
            tml_time = 0;
    }
    return tml_time;
} // end of ds_auth::m_get_kicked_out


/*! \brief Get the time the user logged in
 *
 * @ingroup authentication
 *
 * function ds_auth::m_get_login_time
 * get login time of user
 *
 * @return hl_time_t       time in seconds since 01.01.1970 GMT
*/
hl_time_t ds_auth::m_get_login_time()
{
    switch ( ien_workmode ) {
        case ied_pre_auth:
            return 0;
        case ied_post_auth:
            return dsc_post_auth.m_get_logintime();
    }
    return 0;
} // end of ds_auth::m_get_login_time


/*! \brief Count the WebServer Gate bookmarks
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_count_wsg_bookmarks
 * count wsg bookmarks
 *
 * @return      int
*/
int ds_auth::m_count_wsg_bookmarks()
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_count_wsg_bookmarks();
    }
    return 0;
} // end of ds_auth::m_count_wsg_bookmarks


/*! \brief Get the WebServer Gate bookmarks
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_wsg_bookmark
 * get one wsg bookmark by index
 *
 * @param[in]   ds_bookmark*    ads_bmark   output
 * @return      bool                        true = success
*/
bool ds_auth::m_get_wsg_bookmark( int in_index, ds_bookmark* ads_bmark )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_get_wsg_bookmark( in_index, ads_bmark );
    }
    return false;
} // end of ds_auth::m_get_wsg_bookmark



/*! \brief Count the WebServerProxy (global) bookmarks
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_count_wsg_bookmarks
 * count wsg bookmarks
 *
 * @return      int
*/
int ds_auth::m_count_rdvpn_bookmarks()
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_count_rdvpn_bookmarks();
    }
    return 0;
} // end of ds_auth::m_count_rdvpn_bookmarks

/*! \brief Get the WebServerProxy (global) bookmarks
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_wsg_bookmark
 * get one wsg bookmark by index
 *
 * @param[in]   ds_bookmark*    ads_bmark   output
 * @return      bool                        true = success
*/
bool ds_auth::m_get_rdvpn_bookmark( int in_index, ds_bookmark* ads_bmark )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_get_rdvpn_bookmark( in_index, ads_bmark );
    }
    return false;
} // end of ds_auth::m_get_rdvpn_bookmark





/*! \brief Count the JWT Standalone configurations
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_jwtsa_count_configs
 * count jwt sa configs
 *
 * @return      int
*/
int ds_auth::m_jwtsa_count_configs()
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_jwtsa_count_configs();
    }
    return 0;
} // end of ds_auth::m_jwtsa_count_configs


/*! \brief Get the JWT Standalone configuration
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_jwtsa_get_config
 * get one jwtsa config by index
 *
 * @param[out]	ds_jwtsa_conf*		adsp_jwtsa_config		output
 * @return		bool										true = success
*/
bool ds_auth::m_jwtsa_get_config( int in_index, ds_jwtsa_conf* adsp_jwtsa_config )
{
    if ( ien_workmode == ied_post_auth ) {
		return dsc_post_auth.m_jwtsa_get_config( in_index, adsp_jwtsa_config );
    }
    return false;
} // end of ds_auth::m_jwtsa_get_config

#if BO_HOBTE_CONFIG
int ds_auth::m_hobte_count_configs()
{
    int					inl_function		= -1;
	int					inl_len_out			= 512;
	int					iml_count			= 0;
	void*				avl_srv_handle		= NULL;
	dsd_webterm_server	*adsl_wt_server;
	char				chrl_buffer[512];

    if ( ien_workmode != ied_post_auth )
    {
        return 0;
    }

    while(true)
	{
		avl_srv_handle = this->ads_wsp_helper->m_cb_get_server_entry(	NULL,
																		NULL,
																		ied_scp_websocket,
																		NULL,
																		0,
																		chrl_buffer,
																		&inl_len_out,
																		avl_srv_handle,
																		&inl_function );

		if( avl_srv_handle == NULL ){ break; }
		
		if( inl_function == DEF_FUNC_DIR)
		{
			adsl_wt_server = ads_session->ads_config->adsc_webterm_list;
			while( adsl_wt_server )
			{
				/* compare if we have the same protocol name */
				if(	(adsl_wt_server->iec_protogroup == ied_webterm_protogroup_te_default)
                    &&  ( adsl_wt_server->inc_len_server_name == inl_len_out )
					&&	( strncmp( adsl_wt_server->achc_server_name, chrl_buffer, inl_len_out ) == 0 ))
				{
					//iml_count++;
                    //found server entry - get dynamic list size
                    return dsc_post_auth.m_hobte_count_configs();

				}
				adsl_wt_server = adsl_wt_server->adsc_next;
			}
		}
		inl_len_out = 512;
	}
	
	return 0;

} // end of ds_auth::m_hobte_count_configs


/*! \brief Get the JTerm configuration
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_hobte_get_config
 * get one hobte config by index
 *
 * @param[out]	ds_hobte_conf*		adsp_hobte_config		output
 * @return		bool										true = success
*/
bool ds_auth::m_hobte_get_config( int in_index, ds_hobte_conf* adsp_hobte_config )
{
    if ( ien_workmode == ied_post_auth ) {
		return dsc_post_auth.m_hobte_get_config( in_index, adsp_hobte_config );
    }
    return false;
}
#endif
/* TODO: merge functions *_rdp and *_ssh */
int ds_auth::m_webterm_count_server_entries(ied_webterm_protogroup iep_protogroup)
{
	int					inl_function		= -1;
	int					inl_len_out			= 512;
	int					iml_count			= 0;
	void*				avl_srv_handle		= NULL;
	dsd_webterm_server	*adsl_wt_server;
	char				chrl_buffer[512];
	

	while(true)
	{
		avl_srv_handle = this->ads_wsp_helper->m_cb_get_server_entry(	NULL,
																		NULL,
																		ied_scp_websocket,
																		NULL,
																		0,
																		chrl_buffer,
																		&inl_len_out,
																		avl_srv_handle,
																		&inl_function );

		if( avl_srv_handle == NULL ){ break; }
		
		if( inl_function == DEF_FUNC_DIR || inl_function == DEF_FUNC_WTS || inl_function == DEF_FUNC_VDI_WSP )
		{
			adsl_wt_server = ads_session->ads_config->adsc_webterm_list;
			while( adsl_wt_server )
			{
				/* compare if we have the same protocol name */
				if(	(adsl_wt_server->iec_protogroup == iep_protogroup)
                    &&  ( adsl_wt_server->inc_len_server_name == inl_len_out )
					&&	( strncmp( adsl_wt_server->achc_server_name, chrl_buffer, inl_len_out ) == 0 ))
				{
					iml_count++;
					break;
				}
				adsl_wt_server = adsl_wt_server->adsc_next;
			}
		}
		inl_len_out = 512;
	}
	
	return iml_count;
}

#if 0

int ds_auth::m_webterm_count_server_entries_ssh()
{
	int					inl_function		= -1;
	int					inl_len_out			= 512;
	int					iml_count			= 0;
	void*				avl_srv_handle		= NULL;
	dsd_webterm_server	*adsl_wt_server;
	char				chrl_buffer[512];
	

	while(true)
	{
		avl_srv_handle = this->ads_wsp_helper->m_cb_get_server_entry(	NULL,
																		NULL,
																		ied_scp_websocket,
																		NULL,
																		0,
																		chrl_buffer,
																		&inl_len_out,
																		avl_srv_handle,
																		&inl_function );

		if( avl_srv_handle == NULL ){ break; }
		
		if( inl_function == DEF_FUNC_DIR )
		{
			adsl_wt_server = ads_session->ads_config->adsc_webterm_list;
			while( adsl_wt_server )
			{
				/* compare if we have the same protocol name */
				if(		( adsl_wt_server->inc_len_server_name == inl_len_out )
					&&	( strncmp( adsl_wt_server->achc_server_name, chrl_buffer, inl_len_out ) == 0 )
					&&	( adsl_wt_server->inc_len_protocol_name == 3 )
					&&	( strncmp( "SSH", adsl_wt_server->achc_protocol_name, 3 ) == 0 ) )
				{
					iml_count++;
				}
				adsl_wt_server = adsl_wt_server->adsc_next;
			}
		}
		inl_len_out = 512;
	}
	
	return iml_count;
}
#endif

dsd_webterm_server* ds_auth::m_webterm_get_server_entry( int inp_index, char* achp_name, int* inp_len, ied_webterm_protogroup iep_protogroup )
{
    int					inl_function		= -1;
	int					iml_count			= 0;
	void*				avl_srv_handle		= NULL;
	int					iml_start			= *inp_len;
	dsd_webterm_server	*adsl_wt_server;

	while(true)
	{
		avl_srv_handle = this->ads_wsp_helper->m_cb_get_server_entry(	NULL, NULL,
																		ied_scp_websocket,
																		NULL,
																		0,
																		achp_name,
																		inp_len,
																		avl_srv_handle,
																		&inl_function );

		if( avl_srv_handle == NULL )
            return NULL;
		
		if( inl_function == DEF_FUNC_DIR || inl_function == DEF_FUNC_WTS || inl_function == DEF_FUNC_VDI_WSP )
		{
			adsl_wt_server = ads_session->ads_config->adsc_webterm_list;
			while( adsl_wt_server )
			{
				/* compare if we have the same protocol name */
				if(	( adsl_wt_server->iec_protogroup == iep_protogroup )
                    &&	( adsl_wt_server->inc_len_server_name == *inp_len )
					&&	( strncmp( adsl_wt_server->achc_server_name, achp_name, *inp_len ) == 0 ) )
				{
					if( iml_count == inp_index ) {
                        return adsl_wt_server;
                    }
					iml_count++;
					break;
				}
				adsl_wt_server = adsl_wt_server->adsc_next;
			}
			
			
		}
		*inp_len = iml_start;
	}
	return NULL;
}

#if 0
bool ds_auth::m_webterm_get_server_entry_rdp( int inp_index, char* achp_name, int* inp_len )
{
    int					inl_function		= -1;
	int					iml_count			= 0;
	void*				avl_srv_handle		= NULL;
	int					iml_start			= *inp_len;
	dsd_webterm_server	*adsl_wt_server;

	while(true)
	{
		avl_srv_handle = this->ads_wsp_helper->m_cb_get_server_entry(	NULL, NULL,
																		ied_scp_websocket,
																		NULL,
																		NULL,
																		achp_name,
																		inp_len,
																		avl_srv_handle,
																		&inl_function );

		if( avl_srv_handle == NULL ){ return false; }
		
		if( inl_function == DEF_FUNC_DIR || inl_function == DEF_FUNC_WTS || inl_function == DEF_FUNC_VDI_WSP )
		{
			adsl_wt_server = ads_session->ads_config->adsc_webterm_list;
			while( adsl_wt_server )
			{
				/* compare if we have the same protocol name */
				if(		( adsl_wt_server->inc_len_server_name == *inp_len )
					&&	( strncmp( adsl_wt_server->achc_server_name, achp_name, *inp_len ) == 0 )
					&&	( adsl_wt_server->inc_len_protocol_name == 3 )
					&&	( strncmp( "RDP", adsl_wt_server->achc_protocol_name, 3 ) == 0 ) )
				{
					if( iml_count == inp_index ){ return true; }
					iml_count++;
					break;
				}
				adsl_wt_server = adsl_wt_server->adsc_next;
			}
			
			
		}
		*inp_len = iml_start;
	}
	return false;
}


bool ds_auth::m_webterm_get_server_entry_ssh( int inp_index, char* achp_name, int* inp_len )
{
    int					inl_function		= -1;
	int					iml_count			= 0;
	void*				avl_srv_handle		= NULL;
	int					iml_start			= *inp_len;
	dsd_webterm_server	*adsl_wt_server;

	while(true)
	{
		avl_srv_handle = this->ads_wsp_helper->m_cb_get_server_entry(	NULL, NULL,
																		ied_scp_websocket,
																		NULL,
																		0,
																		achp_name,
																		inp_len,
																		avl_srv_handle,
																		&inl_function );

		if( avl_srv_handle == NULL ){ return false; }
		
		if( inl_function == DEF_FUNC_DIR )
		{
			adsl_wt_server = ads_session->ads_config->adsc_webterm_list;
			while( adsl_wt_server )
			{
				/* compare if we have the same protocol name */
				if(		( adsl_wt_server->inc_len_server_name == *inp_len )
					&&	( strncmp( adsl_wt_server->achc_server_name, achp_name, *inp_len ) == 0 )
					&&	( adsl_wt_server->inc_len_protocol_name == 3 )
					&&	( strncmp( "SSH", adsl_wt_server->achc_protocol_name, 3 ) == 0 ) )
				{
					if( iml_count == inp_index ){ return true; }
					iml_count++;
					break;
				}
				adsl_wt_server = adsl_wt_server->adsc_next;
			}
		}
		*inp_len = iml_start;
	}
	return false;
}
#endif




/*! \brief Get the list of WebServer Gate bookmarks
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_wsg_bookmarks
 * get wsg bookmarks
 *
 * @param[in]   ds_hvector<ds_bookmark>*    ads_bmarks  output
 * @return      bool                                    true = success
*/
bool ds_auth::m_get_wsg_bookmarks( ds_hvector<ds_bookmark>* ads_bmarks )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_get_wsg_bookmarks( ads_bmarks );
    }
    return false;
} // end of ds_auth::m_get_wsg_bookmarks

/*! \brief Set WebServer Gate bookmarks
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_set_own_wsg_bookmarks
 * set own wsg bookmarks
 *
 * @param[in]   ds_hvector<ds_bookmark>*    ads_bmarks  output
 * @return      bool                                    true = success
*/
bool ds_auth::m_set_own_wsg_bookmarks( ds_hvector<ds_bookmark>* ads_bmarks )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_set_own_wsg_bookmarks( ads_bmarks );
    }
    return false;
} // end of ds_auth::m_set_own_wsg_bookmarks

/*! \brief Get the list of RDVPN (user portal) bookmarks
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_rdvpn_bookmarks
 * get wsg bookmarks
 *
 * @param[in]   ds_hvector<ds_bookmark>*    ads_bmarks  output
 * @return      bool                                    true = success
*/
bool ds_auth::m_get_rdvpn_bookmarks( ds_hvector<ds_bookmark>* ads_bmarks )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_get_rdvpn_bookmarks( ads_bmarks );
    }
    return false;
} // end of ds_auth::m_get_rdvpn_bookmarks

/*! \brief Set RDVPN (user portal) bookmarks
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_set_own_rdvpn_bookmarks
 * set own wsg bookmarks
 *
 * @param[in]   ds_hvector<ds_bookmark>*    ads_bmarks  output
 * @return      bool                                    true = success
*/
bool ds_auth::m_set_own_rdvpn_bookmarks( ds_hvector<ds_bookmark>* ads_bmarks )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_set_own_rdvpn_bookmarks( ads_bmarks );
    }
    return false;
} // end of ds_auth::m_set_own_rdvpn_bookmarks


/*! \brief Count the WebFileAccess bookmarks
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_count_wfa_bookmarks
 * count wfa bookmarks
 *
 * @return      int
*/
int ds_auth::m_count_wfa_bookmarks()
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_count_wfa_bookmarks();
    }
    return 0;
} // end of ds_auth::m_count_wfa_bookmarks


/*! \brief Get the WebFileAccess bookmarks
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_wfa_bookmark
 * get one wfa bookmark by index
 *
 * @param[in]   dsd_wfa_bmark*    ads_bmark   output
 * @return      bool                        true = success
*/
bool ds_auth::m_get_wfa_bookmark( int in_index, dsd_wfa_bmark* ads_bmark )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_get_wfa_bookmark( in_index, ads_bmark );
    }
    return false;
} // end of ds_auth::m_get_wfa_bookmark


/*! \brief Get the list of existing WebFileAccess bookmarks
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_wfa_bookmarks
 * get wfa bookmarks
 *
 * @param[in]   ds_hvector<dsd_wfa_bmark>*    ads_bmarks  output
 * @return      bool                                    true = success
*/
bool ds_auth::m_get_wfa_bookmarks( ds_hvector<dsd_wfa_bmark>* ads_bmarks )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_get_wfa_bookmarks( ads_bmarks );
    }
    return false;
} // end of ds_auth::m_get_wfa_bookmarks

#if SM_USE_OWN_WFA_BOOKMARKS
/*! \brief Set the own WFA bookmark
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_set_own_wfa_bookmarks
 * set own wfa bookmarks
 *
 * @param[in]   ds_hvector<dsd_wfa_bmark>*    ads_bmarks  output
 * @return      bool                          true = success
*/
bool ds_auth::m_set_own_wfa_bookmarks( ds_hvector<dsd_wfa_bmark>* ads_bmarks )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_set_own_wfa_bookmarks( ads_bmarks );
    }
    return false;
} // end of ds_auth::m_set_own_wfa_bookmarks
#endif

/*! \brief Set the WFA bookmarks
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_set_wfa_bookmarks
 * set wfa bookmarks
 *
 * @param[in]   ds_hvector<dsd_wfa_bmark>*    ads_bmarks  output
 * @return      bool                          true = success
*/
bool ds_auth::m_set_wfa_bookmarks( ds_hvector<dsd_wfa_bmark>* ads_bmarks )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_set_wfa_bookmarks( ads_bmarks );
    }
    return false;
} // end of ds_auth::m_set_wfa_bookmarks


/*! \brief Add a WFA bookmark
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_add_wfa_bookmark
 * add wfa bookmark to cma
 *
 * @param[in]   ds_bookmark*    ads_bmark
 * @return      bool
*/
bool ds_auth::m_add_wfa_bookmark( dsd_wfa_bmark* ads_bmark )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_add_wfa_bookmark( ads_bmark );
    }
    return false;
} // end of ds_auth::m_add_wfa_bookmark


/*! \brief Count workstations
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_count_workstations
 * count number of workstations for current user
 *
 * @return  int
*/
int ds_auth::m_count_workstations()
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_count_workstations();
    }
    return 0;
} // end of ds_auth::m_count_workstations


/*! \brief Get a workstation
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_workstation
 * get one workstation by index
 *
 * @param[in]   ds_workstation* ads_wstat   output
 * @return      bool                        true = success
*/
bool ds_auth::m_get_workstation( int in_index, ds_workstation* ads_wstat )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_get_workstation( in_index, ads_wstat );
    }
    return false;
} // end of ds_auth::m_get_workstation


/*! \brief Get list of workstations
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_workstations
 * get workstations
 *
 * @param[in]   ds_hvector<ds_workstation>* ads_wstats  output
 * @return      bool                                    true = success
*/
bool ds_auth::m_get_workstations( ds_hvector<ds_workstation>* ads_wstats )
{
    switch ( ien_workmode ) {
        case ied_pre_auth:
            return false;
        case ied_post_auth:
            return dsc_post_auth.m_get_workstations( ads_wstats );
    }
    return false;
} // end of ds_auth::m_get_workstations


/*! \brief Set workstations
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_set_workstations
 * set workstations
 *
 * @param[in]   ds_hvector<ds_workstation>* ads_wstats  input
 * @return      bool                                    true = success
*/
bool ds_auth::m_set_workstations( ds_hvector<ds_workstation>* ads_wstats )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_set_workstations( ads_wstats );
    }
    return false;
} // end of ds_auth::m_set_workstations


/*! \brief Set portlets
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_set_portlets
 * set user portlets
 *
 * @param[in]   ds_hvector<ds_portlet>* ads_vportlets
 * @return      bool                                    true = success
*/
bool ds_auth::m_set_portlets( ds_hvector<ds_portlet>* ads_vportlets )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_set_portlets( ads_vportlets );
    }
    return false;
} // end of ds_auth::m_set_portlets


/*! \brief Get the admin message
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_adm_msg
 * get admin message
 *
 * @param[in]   ds_hstring  *adsp_msg
 * @return      bool
*/
bool ds_auth::m_get_adm_msg( ds_hstring *adsp_msg )
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_get_usr_msg( adsp_msg );
    }
    return false;
} // end of ds_auth::m_get_adm_msg


/*! \brief Get the basename
 *
 * @ingroup authentication
 *
 * function ds_auth::m_get_basename
 *
 * @return  char*
*/
dsd_const_string ds_auth::m_get_basename()
{
    if ( ien_workmode == ied_post_auth ) {
        return dsc_post_auth.m_get_basename();
    }
    return dsd_const_string("");
} // end of ds_auth::m_get_basename


#ifdef _DEBUG
/*! \brief Get workmode
 *
 * @ingroup authentication
 *
 * public function ds_auth::m_get_workmode
*/
ied_auth_state ds_auth::m_get_workmode()
{
    return ien_workmode;
} // end of ds_auth::m_get_workmode
#endif


#ifdef DS_PORTLET_FILTER_U_A
/** \brief set portlet filter enum variable
* set portlet filter bitfield member variable for filtering out portlets, that would not work on user's machine.
*/
void ds_auth::m_set_portlet_filter(int ibp_portlet_filter)
{
    ibc_ua_portlet_filter = ibp_portlet_filter;
}

/**
* return if portlet filter bitfield was already set
*/
int ds_auth::m_is_portlet_filter_set(void)
{
    return ibc_ua_portlet_filter & UA_CHECKED;
}

/** \brief get portlet filter enum variable
* get portlet filter bitfield member variable for filtering out portlets, that would not work on user's machine.
*/
int ds_auth::m_get_portlet_filter(void)
{
    return ibc_ua_portlet_filter;
}
#endif


/*+-------------------------------------------------------------------------+*/
/*| private functions:                                                      |*/
/*+-------------------------------------------------------------------------+*/
/**
 * function ds_auth::m_print_ineta
 *
 * @param[in]   ds_hstring*     ads_out                         output buffer
 * @param[in]   unsigned char   uchr_client_ineta[LEN_INETA]    ineta
*/
void ds_auth::m_print_ineta( ds_hstring* ads_out, struct dsd_aux_query_client ds_client )
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
} // end of ds_auth::m_print_ineta
