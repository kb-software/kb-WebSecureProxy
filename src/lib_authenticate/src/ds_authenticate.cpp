/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/
static const char chr_b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#if 0
/*+-------------------------------------------------------------------------+*/
/*| user counter cma:                                                       |*/
/*+-------------------------------------------------------------------------+*/
#define DEF_USR_COUNTER_CMA "usr/counter"

struct dsd_usr_cnt_cma {
    int inc_current;
    int inc_peak;
};
#endif

/*+-------------------------------------------------------------------------+*/
/*| include headers                                                         |*/
/*+-------------------------------------------------------------------------+*/
#define HOB_CONTR_TIMER
#ifndef BOOL
    typedef int BOOL;
#endif

#ifndef HL_UNIX
    #include <winsock2.h>
    #include <Ws2tcpip.h>
    #include <windows.h>
#else
    #include <netinet/in.h>
    #include <hob-unix01.h>
#endif

#include <ds_attribute_string.h>
#include <rdvpn_globals.h>
#include <hob-libwspat.h>
#include <ds_hstring.h>
#include <ds_hobte_conf.h>
#include <ds_usercma.h>
#include <ds_authenticate.h>
#ifndef HOB_XSLUNIC1_H
	#define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H
#include <ds_bookmark.h>
#include <dsd_wfa_bmark.h>
#include <ds_jwtsa_conf.h>
#include <ds_workstation.h>
#include <ds_portlet.h>
#include <ds_xml.h>
#include <ds_cookie.h>
#include <ds_ck_mgmt.h>
#include <ds_wsp_admin.h>
#include <auth_callback.h>
#include <hob-stor-sdh.h>
#include <ds_ldap.h>
#ifdef HL_UNIX
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

//extern struct dsd_ldap_template;
#include <hob-netw-01.h>
#include <hob-wsppriv.h>
#include <hob-xslcontr.h>
#include <hob-avl03.h>
#include <hob-xbipgw08-1.h>
#include <hob-xbipgw08-2.h>     // for struct dsd_ldap_template

/*+-------------------------------------------------------------------------+*/
/*| ordering of authentication method                                       |*/
/*+-------------------------------------------------------------------------+*/
static const int inr_auth_methods[] = {
    DEF_CLIB1_CONF_LDAP,
    DEF_CLIB1_CONF_RADIUS,
    DEF_CLIB1_CONF_KRB5,
    DEF_CLIB1_CONF_USERLI,
    DEF_CLIB1_CONF_DYN_KRB5,
    DEF_CLIB1_CONF_DYN_LDAP,
    DEF_CLIB1_CONF_DYN_RADIUS
};

/*+-------------------------------------------------------------------------+*/
/*| declarations:                                                           |*/
/*+-------------------------------------------------------------------------+*/
#define DEF_LEN_B64CS 8
struct dsd_sticket_cs {
    union {
        unsigned int uinc_checksum;
        char         chrc_checksum[sizeof(unsigned int)];
    };
    char         chc_session;
};

static const char *achg_objectsid = "objectSid";

/*+-------------------------------------------------------------------------+*/
/*| constructor:                                                            |*/
/*+-------------------------------------------------------------------------+*/
ds_authenticate::ds_authenticate( ds_wsp_helper* ads_wsp_helper )
{
    adsc_wsp_helper   = ads_wsp_helper;
    adsc_userov       = NULL;
    ienc_adm_ret_code = ied_wspadmin_unset;
    inc_sel_srv       = -1;
    memset( &dsc_authinfo, 0, sizeof(struct dsd_ldap_userinfo) );
	memset( &dsc_stor_jwtsa, 0, sizeof(struct dsd_stor_sdh_1) );
    dsc_authinfo.dsc_auth.boc_filled = FALSE;
    //dsc_userdn.m_init( ads_wsp_helper );
} // end of ds_authenticate::ds_authenticate


ds_authenticate::ds_authenticate()
{
    adsc_wsp_helper   = NULL;
    adsc_userov       = NULL;
    ienc_adm_ret_code = ied_wspadmin_unset;
    inc_sel_srv       = -1;
    memset( &dsc_authinfo, 0, sizeof(struct dsd_ldap_userinfo) );
	memset( &dsc_stor_jwtsa, 0, sizeof(struct dsd_stor_sdh_1) );
} // end of ds_authenticate::ds_authenticate

/*+-------------------------------------------------------------------------+*/
/*| destructor:                                                             |*/
/*+-------------------------------------------------------------------------+*/
ds_authenticate::~ds_authenticate()
{
    m_free_userov();
	this->adsc_wsp_helper->m_del_storage_cont(&dsc_authinfo.dsc_stor);
	this->adsc_wsp_helper->m_del_storage_cont(&dsc_stor_jwtsa);
} // end of ds_authenticate::~ds_authenticate


/*+-------------------------------------------------------------------------+*/
/*| public functions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief Initialization function for ds_authenticate
 *
 * \ingroup authlib
 *
 * function ds_authenticate::m_init
 * just stores a pointer to a ds_wsp_helper class
 *
 * @param[in]   ds_wsp_helper* ads_wsp_helper
*/
void ds_authenticate::m_init( ds_wsp_helper* ads_wsp_helper )
{
    adsc_wsp_helper = ads_wsp_helper;
    inc_sel_srv     = -1;
    //dsc_userdn.m_init( ads_wsp_helper );
} // end of ds_authenticate::m_init


/*! \brief authenticate user with password
 *
 * \ingroup authlib
 *
 * function ds_authenticate::m_authenticate
 * authenticate user with password
 *
 * @param[in]   dsd_auth_t* adsp_auth       pointer to authentication input structure
 * @return      HL_UINT                     compare authentication code (header file)
*/
HL_UINT ds_authenticate::m_authenticate( dsd_auth_t* adsp_auth )
{
    // initialize some variables:
    int               inl_wsp_auth;         // configured authentication methods in wsp
    int               inl_domain_auth;      // selected auth method by profile
    dsd_wspat_pconf_t *adsl_wspat_conf;     // config from wspat
    ds_hstring        dsl_user;             // user name in lowercase
    HL_UINT           uinl_auth;            // return from authentication
    const char        *achl_user;           // org user name pointer
    struct dsd_domain *adsl_domain;         // selected domain

    //-------------------------------------------
    // check input data:
    //-------------------------------------------
            /* check NULL pointer           */    /* check min length          */
    if (    adsp_auth                  == NULL
         || adsp_auth->adsc_out_usr    == NULL
         || adsp_auth->achc_user       == NULL || adsp_auth->inc_len_user     < 1
         || adsp_auth->achc_password   == NULL || adsp_auth->inc_len_password < 0
         ||                                       adsp_auth->inc_len_domain   < 0 ) {
        m_print_err_msg( AUTH_FAILED | AUTH_ERR_INPUT, adsp_auth, NULL );
        return AUTH_FAILED | AUTH_ERR_INPUT;
    }
    adsp_auth->inc_pw_expires = DEF_DONT_EXPIRE;

    //-------------------------------------------
    // username is case insensitive
    //   -> convert it to lowercase
    //   -> otherwise multiple login with 
    //      "user" and "User" is possible
    //-------------------------------------------
    dsl_user.m_setup( adsc_wsp_helper );
    achl_user = adsp_auth->achc_user;
#if SM_AUTHENTICATE_CASE_SENSITIVE
    dsl_user.m_write( achl_user, adsp_auth->inc_len_user );
#else
    dsl_user.m_write_lower( achl_user, adsp_auth->inc_len_user );
#endif
    adsp_auth->achc_user = dsl_user.m_get_ptr();

    //-------------------------------------------
    // get configured auth methods
    // and wspat configuration
    //-------------------------------------------
    inl_wsp_auth = adsc_wsp_helper->m_get_wsp_auth();
    if ( inl_wsp_auth == -1 ) {
        m_print_err_msg( AUTH_FAILED | AUTH_ERR_INTERNAL, adsp_auth, NULL );
        /*
            reset org pointer, cause the modified
            one will be invalid
        */
        adsp_auth->achc_user = achl_user;
        return AUTH_FAILED | AUTH_ERR_INTERNAL;
    }
    adsl_wspat_conf = adsc_wsp_helper->m_get_wspat_config();

    //-------------------------------------------
    // initialize user and userdomain pointers:
    //-------------------------------------------
    adsp_auth->avc_userentry = NULL;
    adsp_auth->avc_usergroup = NULL;

    //-------------------------------------------
    // select authentication method from domain:
    //-------------------------------------------
    inl_domain_auth = m_get_domain_auth( adsp_auth, inl_wsp_auth,
                                         adsl_wspat_conf, &adsl_domain );
    if ( inl_domain_auth == -1 ) {
        m_print_err_msg( AUTH_FAILED | AUTH_ERR_AUTH_TYPE, adsp_auth, NULL );
        /*
            reset org pointer, cause the modified
            one will be invalid
        */
        adsp_auth->achc_user = achl_user;
        return AUTH_FAILED | AUTH_ERR_AUTH_TYPE;
    }

    //-------------------------------------------
    // do authentication:
    //-------------------------------------------
    if (    adsl_wspat_conf                     != NULL
         && adsl_wspat_conf->boc_multiple_login == true
#if SM_USE_QUICK_LINK
         && !adsp_auth->boc_force_session_id
#endif
         )
    {
        /*
            user can login multiple times
        */
        uinl_auth = m_auth_multiple( adsp_auth, inl_wsp_auth, inl_domain_auth,
                                     adsl_wspat_conf, adsl_domain );
    } else {
        /*
            user can login just once
        */
        uinl_auth = m_auth_single( adsp_auth, inl_wsp_auth, inl_domain_auth,
                                   adsl_wspat_conf, adsl_domain );
    }



    /*
        close ldap connection again
    */
    m_close_ldap();

    /*
        reset org pointer, cause the modified
        one will be invalid
    */
    adsp_auth->achc_user = achl_user;
    return uinl_auth;
} // end of ds_authenticate::m_authenticate


/*! \brief authenticate user with an already existing session id
 *
 * \ingroup authlib
 *
 * function ds_authenticate::m_auth_session
 * authenticate user with session id (for example from Webserver Cookie)
 * this way of authenticication will only work, if m_authenticate was called once successfully
 * otherwise it must fail!
 *
 * @param[in]   dsd_auth_t* ads_auth        pointer to authentication input structure
 * @return      HL_UINT                     compare authentication code (header file)
*/
HL_UINT ds_authenticate::m_auth_session( dsd_auth_t *adsp_auth )
{
    // initialize some variables:
    bool              bol_ret;              // return for several func calls
    HL_UINT           uinl_auth;            // authentication status
    int               inl_wsp_auth;         // configured authentication methods in wsp
    int               inl_domain_auth;      // authentication method from domain
    dsd_wspat_pconf_t *adsl_wspat_conf;     // config from wspat
    char              chrl_bname[D_MAXCMA_NAME]; // name of base cma
    int               inl_bname;            // length of base cma name
    dsd_cma_session_no              chl_session;          // session number
    struct dsd_domain *adsl_domain;         // selected domain       

    //-------------------------------------------
    // check input data:
    //-------------------------------------------
            /* check NULL pointer         */    /* check min length          */
    if (    adsp_auth                == NULL
         || adsp_auth->achc_user     == NULL || adsp_auth->inc_len_user     < 1
         || adsp_auth->achc_password == NULL || adsp_auth->inc_len_password < 1
         ||                                     adsp_auth->inc_len_domain   < 0 ) {
        m_print_err_msg( AUTH_FAILED | AUTH_ERR_INPUT, adsp_auth, NULL );
        return AUTH_FAILED | AUTH_ERR_INPUT;
    }
    adsp_auth->inc_pw_expires = DEF_DONT_EXPIRE;

    //-------------------------------------------
    // get configured auth methods
    // and wspat configuration
    //-------------------------------------------
    inl_wsp_auth = adsc_wsp_helper->m_get_wsp_auth();
    if ( inl_wsp_auth == -1 ) {
        m_print_err_msg( AUTH_FAILED | AUTH_ERR_INTERNAL, adsp_auth, NULL );
        return AUTH_FAILED | AUTH_ERR_INTERNAL;
    }
    adsl_wspat_conf = adsc_wsp_helper->m_get_wspat_config();

    //-------------------------------------------
    // initialize user and userdomain pointers:
    //-------------------------------------------
    adsp_auth->avc_userentry = NULL;
    adsp_auth->avc_usergroup = NULL;

    //-------------------------------------------
    // select authentication method from domain:
    //-------------------------------------------
    inl_domain_auth = m_get_domain_auth( adsp_auth, inl_wsp_auth,
                                         adsl_wspat_conf, &adsl_domain );
    if ( inl_domain_auth == -1 ) {
        m_print_err_msg( AUTH_FAILED | AUTH_ERR_AUTH_TYPE, adsp_auth, NULL );
        return AUTH_FAILED | AUTH_ERR_AUTH_TYPE;
    }

    //-------------------------------------------
    // do authentication:
    //-------------------------------------------
    if (    adsl_wspat_conf                     != NULL
         && adsl_wspat_conf->boc_multiple_login == true ) {
        /*
            user can login multiple times
        */
        // is given password is a session ticket:
        bol_ret = ds_usercma::m_is_sticket( &chl_session,
                                            adsp_auth->achc_password,
                                            adsp_auth->inc_len_password );
        if ( bol_ret == true ) {
            // create basecma name:
            inl_bname = ds_usercma::m_create_name( adsp_auth->achc_user,
                                                   adsp_auth->inc_len_user,
                                                   adsl_domain->achc_disp_name,
                                                   adsl_domain->inc_len_disp_name,
                                                   chl_session,
                                                   chrl_bname,
                                                   (int)sizeof(chrl_bname) );
            if ( inl_bname < 1 ) {
                m_print_err_msg( AUTH_FAILED | AUTH_ERR_INTERNAL, adsp_auth, adsl_domain );
                return AUTH_FAILED | AUTH_ERR_INTERNAL;
            }

            // user cma existing?
            int inl_ret = ds_usercma::m_exists_user( adsc_wsp_helper,
                                                 chrl_bname, inl_bname );
			if(inl_ret < 0)
				return AUTH_FAILED | AUTH_ERR_INTERNAL;
			if(inl_ret == 0) {
				// cma is not existing:
				return (AUTH_FAILED | AUTH_METH_CMA | AUTH_ERR_EXPIRED);
			}
			adsp_auth->adsc_out_usr->m_set_name( chrl_bname, inl_bname );
            uinl_auth = m_auth_cma( adsp_auth, chl_session, adsl_wspat_conf, adsl_domain );
            if ( uinl_auth == (AUTH_FAILED | AUTH_METH_CMA | AUTH_ERR_STICKET) ) {
                return AUTH_FAILED | AUTH_METH_CMA | AUTH_KICKED_OUT;
            }
            return uinl_auth;
        }
    } else {
        /*
            user can login just once
        */
        // create basecma name:
        inl_bname = ds_usercma::m_create_name( adsp_auth->achc_user,
                                               adsp_auth->inc_len_user,
                                               adsl_domain->achc_disp_name,
                                               adsl_domain->inc_len_disp_name,
                                               dsd_cma_session_no((unsigned char)1), chrl_bname,
                                               (int)sizeof(chrl_bname) );
        if ( inl_bname < 1 ) {
            m_print_err_msg( AUTH_FAILED | AUTH_ERR_INTERNAL, adsp_auth, adsl_domain );
            return AUTH_FAILED | AUTH_ERR_INTERNAL;
        }

        //---------------------------------------
        // check against user cma (if existing):
        //---------------------------------------
        int inl_ret = ds_usercma::m_exists_user( adsc_wsp_helper,
                                             chrl_bname, inl_bname );
		if(inl_ret < 0)
			return AUTH_FAILED | AUTH_ERR_INTERNAL;
        if (inl_ret == 1) {
            adsp_auth->adsc_out_usr->m_set_name( chrl_bname, inl_bname );
            uinl_auth = m_auth_cma( adsp_auth, dsd_cma_session_no((unsigned char)1), adsl_wspat_conf, adsl_domain );
            if ( uinl_auth == (AUTH_FAILED | AUTH_METH_CMA | AUTH_ERR_STICKET) ) {
                // check if given password is a session ticket:
                bol_ret = ds_usercma::m_is_sticket( NULL,
                                                    adsp_auth->achc_password,
                                                    adsp_auth->inc_len_password );
                if ( bol_ret == true ) {
                    return AUTH_FAILED | AUTH_METH_CMA | AUTH_KICKED_OUT;
                }
            }
            return uinl_auth;
        } // end of cma authentication
    }

    m_print_err_msg( AUTH_FAILED | AUTH_METH_CMA, adsp_auth, adsl_domain );
    return AUTH_FAILED | AUTH_METH_CMA;
} // end of ds_authenticate::m_auth_session


/*! \brief ends a session
 *
 * \ingroup authlib
 *
 * public function ds_authenticate::m_end_session
 * end given session, means:
 *      > increase counter
 *      > delete cmas
 *      > export settings to ldap
 *
 * @param[in]   dsd_auth_t*     ads_auth        authentication structure
 * @return      bool                            true = success
*/
bool ds_authenticate::m_end_session( dsd_auth_t *adsp_auth )
{
    // initialize some variables:
    bool             bol_ret;                       // return from several function calls
    dsd_getuser      dsl_user;                      // current user information
#if 0
    dsd_usr_cnt_cma  dsl_usr_cnt;                   // user counter
#endif
    int              inl_domain_auth;               // selected auth method
    ds_wsp_admin     dsl_admin(adsc_wsp_helper);    // wsp admin class
    dsd_wspat_pconf_t* adsl_wspat_conf;             // config from wspat
    ds_ck_mgmt       dsl_ck_manager;                // cookie manager class

    //-------------------------------------------
    // get user information:
    //-------------------------------------------
    bol_ret = adsp_auth->adsc_out_usr->m_get_user( &dsl_user );
    if ( bol_ret == false ) {
        adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                "HAUTHW001W no user information found" );
        return false;
    }

    //-------------------------------------------
    // end all existing connections from user:
    //-------------------------------------------
    adsl_wspat_conf = adsc_wsp_helper->m_get_wspat_config();
    if (    adsl_wspat_conf != NULL
         && adsl_wspat_conf->boc_end_sessions == true ) {
			ds_hstring* adsl_group;
        if ( dsl_user.dsc_wspgroup.m_get_len() > 0 ) {
           adsl_group = &dsl_user.dsc_wspgroup;
        } else {
			  adsl_group = &dsl_user.dsc_userdomain;
        }
		  bol_ret = dsl_admin.m_disc_user( dsl_user.dsc_username.m_get_ptr(),
                                          dsl_user.dsc_username.m_get_len(),
                                          adsl_group->m_get_ptr(),
                                          adsl_group->m_get_len(),
														&dsl_user.chc_session);
        if ( bol_ret == false ) {
            if ( adsl_group->m_get_len() > 0 ) {
                adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                         "HAUTHW002W closing sessions for group=%.*s userid=%.*s failed",
                                         adsl_group->m_get_len(),
                                         adsl_group->m_get_ptr(),
                                         dsl_user.dsc_username.m_get_len(),
                                         dsl_user.dsc_username.m_get_ptr() );
            } else {
                adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                         "HAUTHW003W closing sessions for userid=%.*s failed",
                                         dsl_user.dsc_username.m_get_len(),
                                         dsl_user.dsc_username.m_get_ptr() );
            }
        }
    }

    if ( (dsl_user.iec_auth_flags & ied_usercma_login_anonymous) == 0 ) {
        //---------------------------------------
        // save user settings and cookies:
        //---------------------------------------
        // TODO
        // save user language
        bol_ret = m_prepare_ldap( adsp_auth, &dsl_user );
        if ( bol_ret == true ) {            
            m_insert_objectclass( "hoboc", dsl_user.dsc_userdn.m_get_ptr(),
                                   dsl_user.dsc_userdn.m_get_len() );
#ifdef DEF_SAVE_SETTINGS_AT_LOGOUT
            m_save_user_settings( ads_auth, &dsl_user );
#endif
            m_save_user_cookies ( adsp_auth, &dsl_user );
        } else {
            // delete cookies for non ldap users:
            dsl_ck_manager.m_init( adsc_wsp_helper, false );
            dsl_ck_manager.m_delete_cookies( adsp_auth->adsc_out_usr->m_get_basename() );
        }
    } else {
        dsl_ck_manager.m_init( adsc_wsp_helper, false );
        dsl_ck_manager.m_delete_cookies( adsp_auth->adsc_out_usr->m_get_basename() );
    }

    //-------------------------------------------
    // if krb5 authentication -> delete TGT cma:
    //-------------------------------------------
    enum ied_usercma_login_flags iel_auth_flags;
    inl_domain_auth = adsp_auth->adsc_out_usr->m_get_authmethod(iel_auth_flags);
    if (    inl_domain_auth == DEF_CLIB1_CONF_KRB5
         || inl_domain_auth == DEF_CLIB1_CONF_DYN_KRB5 ) {
        bol_ret = adsc_wsp_helper->m_cb_logout_krb5();
        if ( bol_ret == false ) {
            adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                    "HAUTHW004W krb5 logout failed" );
        }
    }
    
    //-------------------------------------------
    // delete cmas:
    //-------------------------------------------
    bol_ret = adsp_auth->adsc_out_usr->m_delete();

    if ( bol_ret == true ) {
#if 0
        //-------------------------------------------
        // encrease user counters:
        //-------------------------------------------
        m_decrease_usr_cnt( &dsl_usr_cnt );
#endif

        //-------------------------------------------
        // do a print out for logout:
        //-------------------------------------------
        if ( dsl_user.dsc_userdomain.m_get_len() > 0 ) {
            adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                     "HAUTHI100I group=%.*s userid=%.*s logged out"/*, current %d, peak %d"*/,
                                     dsl_user.dsc_userdomain.m_get_len(), dsl_user.dsc_userdomain.m_get_ptr(),
                                     dsl_user.dsc_username.m_get_len(),  dsl_user.dsc_username.m_get_ptr()/*,
                                     dsl_usr_cnt.inc_current,            dsl_usr_cnt.inc_peak*/ );
        } else {
            adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                     "HAUTHI101I userid=%.*s logged out"/*, current %d, peak %d"*/,
                                     dsl_user.dsc_username.m_get_len(), dsl_user.dsc_username.m_get_ptr()/*,
                                     dsl_usr_cnt.inc_current,           dsl_usr_cnt.inc_peak*/ );
        }
    }

    return bol_ret;
} // end of ds_authenticate::m_end_session


/*! \brief creates a user and stores all information in the common memory area ( cma )
 *
 * \ingroup authlib
 *
 * public function ds_authenticate::m_create_user
 * this function will create a user with all required cmas WITHOUT
 * authentication. It is needed for creation of users after kickout,
 * cause we cannot call authentication twice (may fail in case of
 * RADIUS).
 *
 * ATTENTION:
 * ----------
 *      DO NOT CALL WITHOUT A PRIOR CALL TO M_AUTHENTICATE
 *
 * @param[in]   dsd_auth_t*     ads_auth        authentication structure
 * @return      bool                            true = success
*/
HL_UINT ds_authenticate::m_create_user( dsd_auth_t *adsp_auth )
{
    // initialize some variables:
    bool              bol_ret;              // return for some function calls
    HL_UINT           uinl_auth;            // authentication status
    int               inl_wsp_auth;         // configured authentication methods in wsp
    int               inl_domain_auth;      // selected auth method by profile
    dsd_wspat_pconf_t *adsl_wspat_conf;     // config from wspat
    ds_hstring        dsl_user;             // user name in lowercase
    dsd_cma_session_no              chl_session;          // selected session number
    bool              bol_multiple;         // multiple login?
    const char        *achl_user;           // pointer to org username
    struct dsd_domain *adsl_domain;         // selected domain

    //-------------------------------------------
    // check input data:
    //-------------------------------------------
            /* check NULL pointer           */    /* check min length          */
    if (    adsp_auth                  == NULL
         || adsp_auth->adsc_out_usr    == NULL
         || adsp_auth->achc_user       == NULL || adsp_auth->inc_len_user     < 1
         || adsp_auth->achc_password   == NULL || adsp_auth->inc_len_password < 0
         ||                                       adsp_auth->inc_len_domain   < 0 ) {
        m_print_err_msg( AUTH_FAILED | AUTH_ERR_INPUT, adsp_auth, NULL );
        return AUTH_FAILED | AUTH_ERR_INPUT;
    }
    adsp_auth->inc_pw_expires = DEF_DONT_EXPIRE;

    //-------------------------------------------
    // username is case insensitive
    //   -> convert it to lowercase
    //   -> otherwise multiple login with 
    //      "user" and "User" is possible
    //-------------------------------------------
    dsl_user.m_setup( adsc_wsp_helper );
    achl_user = adsp_auth->achc_user;
#if SM_AUTHENTICATE_CASE_SENSITIVE
    dsl_user.m_write( achl_user, adsp_auth->inc_len_user );
#else
    dsl_user.m_write_lower( achl_user, adsp_auth->inc_len_user );
#endif
    adsp_auth->achc_user = dsl_user.m_get_ptr();

    //-------------------------------------------
    // get configured auth methods
    // and wspat configuration
    //-------------------------------------------
    inl_wsp_auth = adsc_wsp_helper->m_get_wsp_auth();
    if ( inl_wsp_auth == -1 ) {
        m_print_err_msg( AUTH_FAILED | AUTH_ERR_INTERNAL, adsp_auth, NULL );
        /*
            reset org pointer, cause the modified
            one will be invalid
        */
        adsp_auth->achc_user = achl_user;
        return AUTH_FAILED | AUTH_ERR_INTERNAL;
    }
    adsl_wspat_conf = adsc_wsp_helper->m_get_wspat_config();

    //-------------------------------------------
    // initialize user and userdomain pointers:
    //-------------------------------------------
    adsp_auth->avc_userentry = NULL;
    adsp_auth->avc_usergroup = NULL;

    //-------------------------------------------
    // select authentication method from domain:
    //-------------------------------------------
    inl_domain_auth = m_get_domain_auth( adsp_auth, inl_wsp_auth,
                                         adsl_wspat_conf, &adsl_domain );
    if ( inl_domain_auth == -1 ) {
        m_print_err_msg( AUTH_FAILED | AUTH_ERR_AUTH_TYPE, adsp_auth, NULL );
        /*
            reset org pointer, cause the modified
            one will be invalid
        */
        adsp_auth->achc_user = achl_user;
        return AUTH_FAILED | AUTH_ERR_AUTH_TYPE;
    }


    //-------------------------------------------
    // multiple login:
    //-------------------------------------------
    if (    adsl_wspat_conf                     != NULL
         && adsl_wspat_conf->boc_multiple_login == true ) {
        bol_multiple = true;
    } else {
        bol_multiple = false;
    }

    /*
        bind to conf ldap if it is equal to auth LDAP,
        cause in this case we had no LDAP call yet
    */
    if ( adsl_domain->boc_ldap_eq_name == true ) {
        if ( inl_domain_auth == DEF_CLIB1_CONF_DYN_LDAP ) {
            bol_ret = adsc_wsp_helper->m_set_ldap_srv( adsl_domain->achc_ldap,
                                                       adsl_domain->inc_len_ldap );
            if ( bol_ret == false ) {
                adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                         "HAUTHE229E cannot select configuration ldap" );
                return false;
            }
        }
        bol_ret = m_bind_conf_ldap( adsl_domain );
        if ( bol_ret == false ) {
            adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                     "HAUTHE228E bind to configuration ldap failed" );
            return false;
        }
    }

    /*
        switch ldap means:
        -> select which ldap is used for role selection and configuration
        -> bind to new ldap
        -> auto create user(and group) entries if needed
    */
    m_switch_ldap( adsp_auth, adsl_domain, inl_domain_auth, inl_wsp_auth );

    /*
        init user means:
        -> get possible roles
        -> get user settings from ldap
        -> get user cookies  from ldap
        -> create cmas
    */
    uinl_auth = AUTH_SUCCESS;

    int iel_auth_flags = 0;
#if SM_USE_CERT_AUTH
    if(adsp_auth->iec_certificate_auth == iec_cert_auth_result_authenticated)
        iel_auth_flags |= ied_usercma_login_cert_auth;
#endif
    bol_ret = m_init_user( adsp_auth, &chl_session, inl_domain_auth,
                           adsl_wspat_conf, &uinl_auth, bol_multiple, (enum ied_usercma_login_flags)iel_auth_flags,
                           adsl_domain );
    if ( bol_ret == false ) {
        /*
            reset org pointer, cause the modified
            one will be invalid
        */
        adsp_auth->achc_user = achl_user;
        return uinl_auth;
    }

    /*
        finsh authentication means:
        -> increase user counter
        -> create a successful printout
    */
    m_finish_auth( adsp_auth, adsl_wspat_conf, uinl_auth, adsl_domain );

    /*
        set wsp ident
    */
    m_set_ident( adsp_auth, adsl_domain );

    /*
        close ldap connection
    */
    m_close_ldap();

    /*
        reset org pointer, cause the modified
        one will be invalid
    */
    adsp_auth->achc_user = achl_user;
    return uinl_auth;
} // end of ds_authenticate::m_create_user


/*! \brief changes a password
 *
 * \ingroup authlib
 *
 * public function ds_authenticate::m_change_password
 * this function change password of an already authenticated user
 * there will be no authentication or cma created.
 *
 * @param[in]   dsd_auth_t *adsp_auth       authentication structure
 * @return      HL_UINT
*/
HL_UINT ds_authenticate::m_change_password( dsd_auth_t *adsp_auth )
{
    // initialize some variables:
    int               inl_wsp_auth;         // configured authentication methods in wsp
    int               inl_domain_auth;      // selected auth method by profile
    dsd_wspat_pconf_t *adsl_wspat_conf;     // config from wspat
    HL_UINT           uinl_auth;            // return from authentication
    struct dsd_domain *adsl_domain;         // selected domain

    //-------------------------------------------
    // check input data:
    //-------------------------------------------
            /* check NULL pointer           */    /* check min length          */
    if (    adsp_auth                  == NULL
         || adsp_auth->adsc_out_usr    == NULL
         || adsp_auth->achc_user       == NULL || adsp_auth->inc_len_user     < 1
         || adsp_auth->achc_password   == NULL || adsp_auth->inc_len_password < 0
         ||                                       adsp_auth->inc_len_domain   < 0 ) {
        m_print_err_msg( AUTH_FAILED | AUTH_ERR_INPUT, adsp_auth, NULL );
        return AUTH_FAILED | AUTH_ERR_INPUT;
    }
    adsp_auth->inc_pw_expires = DEF_DONT_EXPIRE;

    //-------------------------------------------
    // get configured auth methods
    // and wspat configuration
    //-------------------------------------------
    inl_wsp_auth = adsc_wsp_helper->m_get_wsp_auth();
    if ( inl_wsp_auth == -1 ) {
        m_print_err_msg( AUTH_FAILED | AUTH_ERR_INTERNAL, adsp_auth, NULL );
        return AUTH_FAILED | AUTH_ERR_INTERNAL;
    }
    adsl_wspat_conf = adsc_wsp_helper->m_get_wspat_config();

    //-------------------------------------------
    // initialize user and userdomain pointers:
    //-------------------------------------------
    adsp_auth->avc_userentry = NULL;
    adsp_auth->avc_usergroup = NULL;

    //-------------------------------------------
    // select authentication method from domain:
    //-------------------------------------------
    inl_domain_auth = m_get_domain_auth( adsp_auth, inl_wsp_auth,
                                         adsl_wspat_conf, &adsl_domain );
    if ( inl_domain_auth == -1 ) {
        m_print_err_msg( AUTH_FAILED | AUTH_ERR_AUTH_TYPE, adsp_auth, NULL );
        /*
            reset org pointer, cause the modified
            one will be invalid
        */
        return AUTH_FAILED | AUTH_ERR_AUTH_TYPE;
    }

    //-------------------------------------------
    // change password:
    //-------------------------------------------
    uinl_auth = m_change_ext_pwd( adsp_auth, inl_wsp_auth,
                                  inl_domain_auth, adsl_domain );
    if ( (uinl_auth & AUTH_SUCCESS) == AUTH_SUCCESS ) {
        // TODO: save new password in cma!
    }

    m_close_ldap();

    return uinl_auth;
} // end of ds_authenticate::m_change_password


/*! \brief store the settings in the LDAP
 *
 * \ingroup authlib
 *
 * public function ds_authenticate::m_save_settings
 * save user settings to ldap
 *
 * @param[in]   dsd_auth_t*     ads_auth        authentication structure
 * @return      bool                            true = success
*/
bool ds_authenticate::m_save_settings( dsd_auth_t* ads_auth )
{
    // initialize some variables:
    bool             bol_ret;                   // return from several function calls
    dsd_getuser      dsl_user;                  // current user information

    //-------------------------------------------
    // get user information:
    //-------------------------------------------
    bol_ret = ads_auth->adsc_out_usr->m_get_user( &dsl_user );
    if ( bol_ret == false ) {
        adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                "HAUTHW005W no user information found" );
        return false;
    }

    if ( (dsl_user.iec_auth_flags & ied_usercma_login_anonymous) == 0 ) {
        //---------------------------------------
        // prepare ldap and save user settings:
        //---------------------------------------
        bol_ret = m_prepare_ldap( ads_auth, &dsl_user );
        if ( bol_ret == true ) {
            bol_ret = m_save_user_settings( ads_auth, &dsl_user );
            m_close_ldap();
            return bol_ret;
        }
    }
    return false;
} // end of ds_authenticate::m_save_settings


/*! \brief get an overview over all users which are currently logged in
 *
 * \ingroup authlib
 *
 * public function ds_authenticate::m_get_userov
 * get an overview off logged users
 * ATTENTION: a call to m_free_userov is needed after calling this function
 *
 * @param[in]   dsd_query_uov_t*        ads_query       user query structure; give NULL to retrieve all users
 * @return      dsd_user_overview*
*/
dsd_user_overview* ds_authenticate::m_get_userov( dsd_query_uov_t* ads_query )
{
    // initialize some variables:
    char               chl_found[D_MAXCMA_NAME];    // buffer for found name
    int                inl_len_found;               // length of found name
    bool               bol_ret;                     // return value for several function calls
    dsd_user_overview* adsl_user;                   // user overview structure
    struct dsd_getuser dsl_user;                    // user data
    int                inl_counter;                 // counter variable

    /*
        cma orders entries by length of their names
        -> we will start searching at USERCMA_NAME_PREFIX
        -> parse the returning names for our name syntax
    */

    //-------------------------------------------
    // check if we have already read in data:
    //-------------------------------------------
    if ( adsc_userov != NULL ) {
        return adsc_userov;
    }

    //-------------------------------------------
    // reset error code:
    //-------------------------------------------
    ienc_adm_ret_code = ied_wspadmin_unset;

    //-------------------------------------------
    // check input:
    //-------------------------------------------
    if (    ads_query != NULL
         && (    ads_query->inc_last_user < 0
              || ads_query->inc_receive   < 1 ) ) {
        return NULL;
    }



    //-------------------------------------------
    // search entry following USERCMA_NAME_PREFIX:
    //-------------------------------------------
    inl_counter   = 1;
    inl_len_found = adsc_wsp_helper->m_cb_get_next_cma( USERCMA_NAME_PREFIX,
                                                        strlen(USERCMA_NAME_PREFIX),
                                                        &chl_found[0], D_MAXCMA_NAME );
    while ( inl_len_found > 0 ) {
        if (    ds_usercma::m_is_user( &chl_found[0], inl_len_found )           /* name is valid    */
             && adsc_wsp_helper->m_cb_exist_cma( &chl_found[0], inl_len_found ) /* cma realy exists */ ) {
            //-----------------------------------
            // check if there is a search todo:
            //-----------------------------------
            if (    ads_query != NULL
                 && (    ads_query->inc_len_user   > 0
                      || ads_query->inc_len_domain > 0 ) ) {
                // get user information:
                bol_ret = ds_usercma::m_get_user( adsc_wsp_helper,
                                                  &chl_found[0], inl_len_found,
                                                  &dsl_user );
                if ( bol_ret == true ) {
                    // check session timeouts:
                    bol_ret = ds_usercma::m_check_timeouts( adsc_wsp_helper, &dsl_user );
                }
                if ( bol_ret == true ) {
                    bol_ret = m_search( &dsl_user, ads_query );
                }
                if ( bol_ret == false ) {
                    //---------------------------
                    // search next cma entry:
                    //---------------------------
                    inl_len_found = adsc_wsp_helper->m_cb_get_next_cma( &chl_found[0],
                                                                        inl_len_found,
                                                                        &chl_found[0],
                                                                        D_MAXCMA_NAME );
                    continue;
                }
            }

            /*
                overread first entries until we find ads_query->inc_last_user
            */
            if (    ads_query                == NULL
                 || ads_query->inc_last_user <  inl_counter ) {
                adsl_user = (dsd_user_overview*)adsc_wsp_helper->m_cb_get_memory( sizeof(dsd_user_overview), true );
                if ( adsl_user == NULL ) {
                    return NULL;
                }
                adsl_user->inc_number = inl_counter;
                bol_ret = ds_usercma::m_get_user( adsc_wsp_helper,
                                                  &chl_found[0], inl_len_found,
                                                  &adsl_user->ds_user );
                if ( bol_ret == true ) {                    
                    // check session timeouts:
                    bol_ret = ds_usercma::m_check_timeouts( adsc_wsp_helper, &adsl_user->ds_user );
                }
                if ( bol_ret == false ) {
                    adsc_wsp_helper->m_cb_free_memory( adsl_user );
                } else {
                    //-------------------------------
                    // fill user information tree:
                    //-------------------------------
                    if ( adsc_userov == NULL ) {
                        adsc_userov = adsl_user;
                    } else {
                        dsd_user_overview* ads_temp = adsc_userov;
                        while ( ads_temp->ads_next != NULL ) {
                            ads_temp = ads_temp->ads_next;
                        }
                        ads_temp->ads_next = adsl_user;
                    }
                }

                if (    ads_query                                         != NULL
                     && ads_query->inc_last_user + ads_query->inc_receive == inl_counter ) {
                    break;
                }
            }

            inl_counter++;
        }

        //---------------------------------------
        // search next cma entry:
        //---------------------------------------
        inl_len_found = adsc_wsp_helper->m_cb_get_next_cma( &chl_found[0], inl_len_found,
                                                            &chl_found[0], D_MAXCMA_NAME );
    }
    
    if ( inl_len_found == 0 ) {
        ienc_adm_ret_code = ied_wspadmin_end_of_file;
    }
    return adsc_userov;
} // end of ds_authenticate::m_get_userov()


/*! \brief frees the memory of ds_authenticate::m_get_userov
 *
 * \ingroup authlib
 *
 * function ds_authenticate::m_free_userov
 * free useroverview memory
*/
void ds_authenticate::m_free_userov()
{
    if ( adsc_userov != NULL ) {
        m_free_userov( adsc_userov );
        adsc_userov = NULL;
    }
} // end of ds_authenticate::m_free_userov


/*! \brief count all logged in users
 *
 * \ingroup authlib
 *
 * function ds_authenticate::m_count_users
 * count logged users
 *
 * @param[in]   dsd_query_uov_t*        ads_query       user query structure; give NULL to retrieve all users
 * @return int
*/
int ds_authenticate::m_count_users( dsd_query_uov_t* ads_query )
{
    // initialize some variables:
    int                inl_ret = 0;                     // number of users
    dsd_user_overview* adsl_oview;                      // useroverview

    adsl_oview = m_get_userov( ads_query );
    while ( adsl_oview != NULL ) {
        inl_ret++;
        adsl_oview = adsl_oview->ads_next;
    }
    return inl_ret;
} // end of ds_authenticate::m_count_users()


/*! \brief get the returncode of the m_get_userov function
 *
 * \ingroup authlib
 *
 * public function ds_authenticate::m_get_userov_rc
 *
 * @return enum ied_admin_rcode
*/
enum ied_admin_rcode ds_authenticate::m_get_userov_rc()
{
    return ienc_adm_ret_code;
} // end of ds_authenticate::m_get_userov_rc

/*+-------------------------------------------------------------------------+*/
/*| private functions:                                                      |*/
/*+-------------------------------------------------------------------------+*/
/**
 * private function ds_authenticate::m_auth_single
 * do single user authentication
 * (means every user can have on session)
 * 
 * @param[in]       dsd_auth_t        *adsp_auth
 * @param[in]       int               inp_wsp_auth
 * @param[in]       int               inp_domain_auth
 * @param[in]       dsd_wspat_pconf_t *adsp_wspat_conf
 * @param[in/out]   HL_UINT           *ainp_auth
 * @param[in]       bool              bop_anonymous
*/
HL_UINT ds_authenticate::m_auth_single( dsd_auth_t *adsp_auth,
                                        int inp_wsp_auth, int inp_domain_auth,
                                        struct dsd_wspat_public_config *adsp_wspat_conf,
                                        struct dsd_domain *adsp_domain )
{
    // initialize some variables:
    bool       bol_ret;                     // return for several func calls
    HL_UINT    uinl_auth;                   // authentication status
    char       chrl_bname[D_MAXCMA_NAME];   // name of base cma
    int        inl_bname;                   // length of base cma name
    ds_hstring dsl_state;                   // temp buffer for external auth
    dsd_cma_session_no       chl_session;                 // session number

    /*
        user can just login once:

                                 |
                        +--------+--------+
                        | exists user cma |
                        +--------+--------+
                        YES      |       NO
                  +--------------+--------------+
          +-------+------+                 +----+-----+
          | pw = sticket |                 | ext auth |
          +-------+------+                 +----+-----+
             YES  |   NO                   YES  |    NO
          +-------+-------+             +-------+-------+
        +-+--+       +----+-----+     +-+--+         +--+-+
        | OK |       | ext auth |     | OK |         | KO | 
        +----+       +----+-----+     +----+         +----+
                     YES  |    NO
                    +-----+-----+
               +----+----+   +--+-+
               | kickout |   | KO |
               +---------+   +----+
    */
    chl_session = dsd_cma_session_no((unsigned char)1);

	 //-------------------------------------------
    // create basecma name:
    //-------------------------------------------
    inl_bname = ds_usercma::m_create_name( adsp_auth->achc_user,
                                           adsp_auth->inc_len_user,
                                           adsp_domain->achc_disp_name,
                                           adsp_domain->inc_len_disp_name,
                                           chl_session, chrl_bname,
                                           (int)sizeof(chrl_bname) );
    if ( inl_bname < 1 ) {
        m_print_err_msg( AUTH_FAILED | AUTH_ERR_INTERNAL, adsp_auth, adsp_domain );
        return AUTH_FAILED | AUTH_ERR_INTERNAL;
    }

    //-------------------------------------------
    // check against user cma (if existing):
    //-------------------------------------------
    int inl_ret = ds_usercma::m_exists_user( adsc_wsp_helper,
                                         chrl_bname, inl_bname );
	if(inl_ret < 0)
        return AUTH_FAILED | AUTH_ERR_INTERNAL;
    if(inl_ret == 1) {
        //---------------------------------------
        // set cma name:
        //---------------------------------------
        adsp_auth->adsc_out_usr->m_set_name( chrl_bname, inl_bname );

        //---------------------------------------
        // do cma authentication:
        //---------------------------------------
        uinl_auth = m_auth_cma( adsp_auth, chl_session, adsp_wspat_conf, adsp_domain );
        if ( uinl_auth == (AUTH_FAILED | AUTH_METH_CMA | AUTH_ERR_STICKET) ) {
            /*
                if we come here:
                 -> given password was not a valid session ticket
                 -> there are two possibilties:
                    1. user wants to kick-out same users (but older) session
                    2. kicked-out user does another request

                 1. -> check if password is orginal password
                       if so, it is same user which tries to login twice
                       if not, it is a hacker
                 2. -> check if given password is a session ticket
                       if so, give a special return
                       if not, return an error
            */

            //-----------------------------------
            // check if given password is a session ticket:
            //-----------------------------------
            bol_ret = adsp_auth->adsc_out_usr->m_is_sticket( NULL, 
                                                             adsp_auth->achc_password,
                                                             adsp_auth->inc_len_password );
            if ( bol_ret == true ) {
                // case 2.)
                return AUTH_FAILED | AUTH_METH_CMA | AUTH_KICKED_OUT;
            }
            
            //-----------------------------------
            // fill missing parameters:
            //-----------------------------------
            if ( adsp_auth->adsc_state == NULL ) {
                dsl_state.m_setup( adsc_wsp_helper );
                adsp_auth->adsc_state = &dsl_state;
            }

            //-----------------------------------
            // do external authentication:
            //-----------------------------------
            uinl_auth = m_do_ext_auth( adsp_auth, inp_wsp_auth,
                                       inp_domain_auth, adsp_domain );
            if ( (uinl_auth & AUTH_SUCCESS) == AUTH_SUCCESS )
				{
					if ( adsp_auth->inc_len_domain < 1 )
					{
                    adsp_auth->achc_domain    = adsp_domain->achc_disp_name;
                    adsp_auth->inc_len_domain = adsp_domain->inc_len_disp_name;
                }
                return AUTH_FAILED | AUTH_METH_CMA | AUTH_SAME_USER;
            }
        }
        return uinl_auth;
    } // end of cma authentication

    //-------------------------------------------
    // do authentication:
    //-------------------------------------------
    uinl_auth = m_do_ext_auth( adsp_auth, inp_wsp_auth,
                               inp_domain_auth, adsp_domain );
    if ( (uinl_auth & AUTH_SUCCESS) == AUTH_SUCCESS ) {
        /*
            switch ldap means:
            -> select which ldap is used for role selection and configuration
            -> auto create user(and group) entries if needed
            -> bind to new ldap
        */
        m_switch_ldap( adsp_auth, adsp_domain, inp_domain_auth, inp_wsp_auth );


        /*
            init user means:
            -> get possible roles
            -> get user settings from ldap
            -> get user cookies  from ldap
            -> create cmas
        */
        int iel_auth_flags = 0;
#if SM_USE_CERT_AUTH
        if(adsp_auth->iec_certificate_auth == iec_cert_auth_result_authenticated)
            iel_auth_flags |= ied_usercma_login_cert_auth;
#endif
        bol_ret = m_init_user( adsp_auth, &chl_session, inp_domain_auth,
                               adsp_wspat_conf, &uinl_auth, false, (enum ied_usercma_login_flags)iel_auth_flags,
                               adsp_domain );
        if ( bol_ret == false ) {
            return uinl_auth;
        }

        /*
            finsh authentication means:
            -> increase user counter
            -> create a successful printout
        */
        m_finish_auth( adsp_auth, adsp_wspat_conf, uinl_auth, adsp_domain );

        /*
            set wsp ident
        */
        m_set_ident( adsp_auth, adsp_domain );
    } else {
        if (    uinl_auth != (AUTH_METH_RADIUS     | AUTH_FAILED | AUTH_METH_CHALLENGE)
             && uinl_auth != (AUTH_METH_DYN_RADIUS | AUTH_FAILED | AUTH_METH_CHALLENGE) ) {
            m_print_err_msg( uinl_auth, adsp_auth, adsp_domain );
        }
    }
    return uinl_auth;
} // end of ds_authenticate::m_auth_single

bool ds_authenticate::m_check_certificate_auth( const struct dsd_wspat_public_config *adsp_wspat_conf, dsd_auth_t *adsp_auth ) {
#if SM_USE_CERT_AUTH
    adsp_auth->iec_certificate_auth = iec_cert_auth_result_not_found;
	adsp_auth->adsc_cert_auth_entry = NULL;
    if(!adsp_wspat_conf->dsc_certificate_auth.boc_enabled)
        return false;
    dsd_certificate_auth_entry* adsl_auth = adsp_wspat_conf->dsc_certificate_auth.adsc_entries;
    if(adsl_auth == NULL)
        return false;
    void* avol_cert;
    int inl_length;
    bool bol_res = this->adsc_wsp_helper->m_cb_get_certificate(&avol_cert, &inl_length);
    if(!bol_res)
        return false;
    //m_console_out((char*)avol_cert, inl_length);
    struct dsd_sha1 dsl_sha1;
    ds_wsp_helper::m_sha1_init(dsl_sha1);
    ds_wsp_helper::m_sha1_update(dsl_sha1, avol_cert, inl_length);
    char chrl_digest[SHA1_DIGEST_LEN];
    ds_wsp_helper::m_sha1_final(dsl_sha1, chrl_digest);
    //printf("SHA-1 DIGEST:\n");
    //m_console_out((char*)chrl_digest, SHA1_DIGEST_LEN);
    while(adsl_auth != NULL) {
        if(memcmp(adsl_auth->chrc_sha1_hash, chrl_digest, SHA1_DIGEST_LEN) == 0) {
            adsp_auth->achc_user             = adsl_auth->dsc_user.achc_data;
            adsp_auth->inc_len_user          = adsl_auth->dsc_user.inc_len;
            adsp_auth->achc_domain           = adsl_auth->dsc_domain.achc_data;
            adsp_auth->inc_len_domain        = adsl_auth->dsc_domain.inc_len;
#if SM_USE_CERT_AUTH_V2
			adsp_auth->achc_password         = adsl_auth->dsc_password.achc_data;
            adsp_auth->inc_len_password      = adsl_auth->dsc_password.inc_len;
#else
			adsp_auth->achc_password         = NULL;
            adsp_auth->inc_len_password      = 0;
#endif
			adsp_auth->adsc_cert_auth_entry = adsl_auth;
#if SM_USE_CERT_AUTH_V2
			BOOL bol_password_auth = HL_TROOLEAN_TO_BOOL(adsl_auth->iec_password_auth, adsp_wspat_conf->dsc_certificate_auth.boc_password_auth);
			if(bol_password_auth) {
				adsp_auth->iec_certificate_auth = iec_cert_auth_result_found;
				return true;
			}
#endif
            adsp_auth->iec_certificate_auth = iec_cert_auth_result_authenticated;
            return true;
        }
        adsl_auth = adsl_auth->adsc_next;
    }
#endif
    return false;
}

/**
 * private function ds_authenticate::m_auth_multiple
 * do multiple user authentication
 * (means every user can have more than one session)
 * 
 * @param[in]       dsd_auth_t      *adsp_auth
 * @param[in]       int             inp_wsp_auth
 * @param[in]       int             inp_domain_auth
 * @param[in]       dsd_wspat_pconf_t *adsp_wspat_conf
 * @param[in/out]   HL_UINT         *ainp_auth
 * @param[in]       bool            bop_anonymous
*/
HL_UINT ds_authenticate::m_auth_multiple( dsd_auth_t *adsp_auth,
                                          int inp_wsp_auth, int inp_domain_auth,
                                          struct dsd_wspat_public_config *adsp_wspat_conf,
                                          struct dsd_domain *adsp_domain )
{
    // initialize some variables:
    bool    bol_ret;                        // return for several func calls
    bool    bol_anonymous;                  // anonymous login?
    HL_UINT uinl_auth;                      // authentication status
    dsd_cma_session_no    chl_session;                    // session number
    char    chrl_bname[D_MAXCMA_NAME];      // name of base cma
    int     inl_bname;                      // length of base cma name

    /*
        user can login multiple times:
                                       |
                              +--------+--------+
                              | pw is a sticket |
                              +--------+--------+
                              YES      |       NO
                        +--------------+--------------+
               +--------+--------+               +----+-----+
               | exists user cma |               | ext auth |
               +--------+--------+               +----+-----+
               YES      |       NO               YES  |    NO
                +-------+-------+             +-------+-------+
        +-------+------+     +--+-+   +-------+------+     +--+-+
        | pw = sticket |     | KO |   | search exist |     | KO |
        +-------+------+     +----+   +-------+------+     +----+
        YES     |     NO              FOUND   |    NOT
          +-----+-----+               +-------+------+
        +-+--+     +--+-+      +------+-----+     +--+-+
        | OK |     | KO |      | create new |     | OK |
        +----+     +----+      | or use old |     +----+
                               +------------+
    */
    //---------------------------------------
    // is given password is a session ticket:
    //---------------------------------------
    bol_ret = ds_usercma::m_is_sticket( &chl_session,
                                        adsp_auth->achc_password,
                                        adsp_auth->inc_len_password );
    if ( bol_ret == true ) {
        //-----------------------------------
        // create basecma name:
        //-----------------------------------
        inl_bname = ds_usercma::m_create_name( adsp_auth->achc_user,
                                               adsp_auth->inc_len_user,
                                               adsp_domain->achc_disp_name,
                                               adsp_domain->inc_len_disp_name,
                                               chl_session,
                                               chrl_bname,
                                               (int)sizeof(chrl_bname) );
        if ( inl_bname < 1 ) {
            m_print_err_msg( AUTH_FAILED | AUTH_ERR_INTERNAL, adsp_auth, adsp_domain );
            return AUTH_FAILED | AUTH_ERR_INTERNAL;
        }

        //-----------------------------------
        // user cma existing?
        //-----------------------------------
        int inl_ret = ds_usercma::m_exists_user( adsc_wsp_helper,
                                             chrl_bname, inl_bname );
		if ( inl_ret < 1 ) {
            return AUTH_FAILED | AUTH_ERR_INTERNAL;
        }
		if ( inl_ret == 0 ) {
            //-------------------------------
            // cma is not existing:
            //-------------------------------
            return (AUTH_FAILED | AUTH_METH_CMA | AUTH_ERR_EXPIRED);
        }
        //-------------------------------
        // set cma name:
        //-------------------------------
        adsp_auth->adsc_out_usr->m_set_name( chrl_bname, inl_bname );

        //-------------------------------
        // do cma authentication:
        //-------------------------------
        uinl_auth = m_auth_cma( adsp_auth, chl_session, adsp_wspat_conf, adsp_domain );
        return uinl_auth;
    } // end of cma authentication

    //-------------------------------------------
    // do authentication:
    //-------------------------------------------
    bol_anonymous = false;
    
#if SM_USE_CERT_AUTH
    if(adsp_auth->iec_certificate_auth == iec_cert_auth_result_not_checked)
        this->m_check_certificate_auth(adsp_wspat_conf, adsp_auth);

    if(adsp_auth->iec_certificate_auth == iec_cert_auth_result_authenticated) {
        uinl_auth = (AUTH_METH_CERTIFICATE | AUTH_SUCCESS);
    }
    else
#endif
    if ( !m_is_anonymous( adsp_auth, adsp_wspat_conf ) ) {
        //---------------------------------------
        // external (normal case):
        //---------------------------------------
        uinl_auth = m_do_ext_auth( adsp_auth, inp_wsp_auth,
                                   inp_domain_auth, adsp_domain );
    } else {
        //---------------------------------------
        // anonymous login:
        //---------------------------------------
        uinl_auth = m_auth_anonymous( adsp_auth, inp_wsp_auth, &inp_domain_auth,
                                      adsp_wspat_conf );
        bol_anonymous = true;
    }

    //-------------------------------------------
    // if auth successful, create user cma
    //-------------------------------------------
    if ( (uinl_auth & AUTH_SUCCESS) == AUTH_SUCCESS ) {
        if ( bol_anonymous == false ) {
            //-----------------------------------
            // search for same users:
            //-----------------------------------
            bol_ret = ds_usercma::m_exists_same_user( adsc_wsp_helper,
                                                      adsp_auth->achc_user,
                                                      adsp_auth->inc_len_user,
                                                      adsp_domain->achc_disp_name,
                                                      adsp_domain->inc_len_disp_name );
            if ( bol_ret == true )
			{

				uinl_auth = m_create_user( adsp_auth );
				if( (uinl_auth & AUTH_SUCCESS) != 0 ) {
					return AUTH_SUCCESS;
				}
#if hofmants				
				if ( adsp_auth->inc_len_domain < 1 ) {
                    adsp_auth->achc_domain    = adsp_domain->achc_disp_name;
                    adsp_auth->inc_len_domain = adsp_domain->inc_len_disp_name;
                }
                return AUTH_FAILED | AUTH_METH_CMA | AUTH_SAME_USER;
#endif
            }
        }

        /*
            switch ldap means:
            -> select which ldap is used for role selection and configuration
            -> bind to new ldap
            -> auto create user(and group) entries if needed
        */
        m_switch_ldap( adsp_auth, adsp_domain, inp_domain_auth, inp_wsp_auth );

        /*
            init user means:
            -> get possible roles
            -> get user settings from ldap
            -> get user cookies  from ldap
            -> create cmas
        */
        int iel_auth_flags = 0;
        if(bol_anonymous)
            iel_auth_flags |= ied_usercma_login_anonymous;
#if SM_USE_CERT_AUTH
        if(adsp_auth->iec_certificate_auth == iec_cert_auth_result_authenticated)
            iel_auth_flags |= ied_usercma_login_cert_auth;
#endif
        bol_ret = m_init_user( adsp_auth, &chl_session, inp_domain_auth,
                               adsp_wspat_conf, &uinl_auth, true, (enum ied_usercma_login_flags)iel_auth_flags,
                               adsp_domain );
        if ( bol_ret == false ) {
            return uinl_auth;
        }

        /*
            finish authentication means:
            -> increase user counter
            -> create a successful printout
        */
        m_finish_auth( adsp_auth, adsp_wspat_conf, uinl_auth, adsp_domain );

        /*
            set wsp ident
        */
        m_set_ident( adsp_auth, adsp_domain );
    } else {
        if (    uinl_auth != (AUTH_METH_RADIUS     | AUTH_FAILED | AUTH_METH_CHALLENGE)
             && uinl_auth != (AUTH_METH_DYN_RADIUS | AUTH_FAILED | AUTH_METH_CHALLENGE) ) {
            m_print_err_msg( uinl_auth, adsp_auth, adsp_domain );
        }
    }
    return uinl_auth;
} // end of ds_authenticate::m_auth_multiple


/**
 * private function ds_authenticate::m_init_user
 *  -> get possible roles
 *  -> get user settings from ldap
 *  -> get user cookies  from ldap
 *  -> create cmas
 *  -> do user statistics
 *
 * @param[in]       dsd_auth_t      *adsp_auth
 * @param[out]      char            *achp_session   assigned session number
 * @param[in]       int             inp_domain_auth
 * @param[in]       dsd_wspat_pconf_t *adsp_wspat_conf
 * @param[in/out]   HL_UINT         *ainp_auth
 * @param[in]       bool            bop_multiple
 * @param[in]       bool            bop_anonymous
 * @return          bool
*/
bool ds_authenticate::m_init_user( dsd_auth_t *adsp_auth, dsd_cma_session_no *achp_session,
                                   int inp_domain_auth,
                                   struct dsd_wspat_public_config *adsp_wspat_conf,
                                   HL_UINT *ainp_auth,
                                   bool bop_multiple, enum ied_usercma_login_flags iep_auth_flags,
                                   struct dsd_domain *adsp_domain )
{
    // initialize some variables:
    bool     bol_ret;                       // return for several functions
    int      inl_idle_tout;                 // idle timeout
    dsd_role *adsl_selected;                // selected role
    char     chrl_buffer[D_MAXCMA_NAME];    // cma name
    int      inl_blen;                      // length of cma name

    //-------------------------------------------
    // get session index:
    //-------------------------------------------
LBL_AGAIN:
	 if ( bop_multiple == true ) {
        //---------------------------------------
        // search first free session number:
        //---------------------------------------
		bol_ret = ds_usercma::m_get_free_user( adsc_wsp_helper, 
                                                     adsp_auth->achc_user,
                                                     adsp_auth->inc_len_user,
                                                     adsp_domain->achc_disp_name,
                                                     adsp_domain->inc_len_disp_name,
																	  achp_session );
		  if ( !bol_ret ) {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                 "HAUTHI103I session limit reached for group=%.*s userid=%.*s",
                                 adsp_domain->inc_len_disp_name, adsp_domain->achc_disp_name,
                                 adsp_auth->inc_len_user,        adsp_auth->achc_user);
				*ainp_auth = AUTH_FAILED | AUTH_METH_CMA | AUTH_SAME_USER;
				return false;
          }
#if 0
		  static bool boc_collision = false;
		  if(boc_collision) {
			  int a = 0;
		  }
		  printf("Sleeping ... achp_session=%d\n", achp_session->ucc_session_no);
		  boc_collision = true;
		  Sleep(500);
		  boc_collision = false;
		  printf("Sleeping done!\n");
#endif
    } else {
        *achp_session = dsd_cma_session_no((unsigned char)1);
    }

    //-------------------------------------------
    // create cma name:
    //-------------------------------------------
    inl_blen = ds_usercma::m_create_name( adsp_auth->achc_user,
                                          adsp_auth->inc_len_user,
                                          adsp_domain->achc_disp_name,
                                          adsp_domain->inc_len_disp_name,
                                          *achp_session, chrl_buffer,
                                          D_MAXCMA_NAME );
    if ( inl_blen < 1 ) {
        return false;
    }
    bol_ret = adsp_auth->adsc_out_usr->m_set_name( chrl_buffer, inl_blen );
    if ( bol_ret == false ) {
        return false;
    }
    
    //-------------------------------------------
    // search all possible roles:
    //-------------------------------------------
    bol_ret = m_get_possible_roles( adsp_auth, adsp_wspat_conf,
                                    ainp_auth, &adsl_selected, adsp_domain );
    if ( bol_ret == false ) {
        m_print_err_msg( *ainp_auth, adsp_auth, adsp_domain );

        //---------------------------------------
        // reset dynamic servers:
        //---------------------------------------
        switch ( inp_domain_auth ) {
#if 0
            case DEF_CLIB1_CONF_DYN_LDAP:
                adsc_wsp_helper->m_reset_ldap_srv();
                break;
#endif
            case DEF_CLIB1_CONF_DYN_KRB5:
                adsc_wsp_helper->m_reset_krb5_srv();
                break;
        }
        return false;
    }

    //-------------------------------------------
    // get idle timeout:
    //-------------------------------------------
    if ( adsl_selected != NULL ) {
        /*
            we have already selected a role
             -> use timeout from this role
        */
        inl_idle_tout = adsl_selected->dsc_time_limits.in_max_period;
    } else {
        /*
            we have not yet selected a role
            we want to avoid that cma exists for ever, if user just closes browser.
             -> use an default timeout and set real timeout later
        */
        inl_idle_tout = AT_DEF_MAX_PERIOD;
    }

    //-------------------------------------------
    // create user cma:
    //-------------------------------------------
	 ds_wsp_helper::ied_cma_result iel_ret = m_create_usr_cma( adsp_auth, *achp_session, inp_domain_auth,
                                iep_auth_flags, adsl_selected,
                                adsp_domain );
	 switch(iel_ret) {
	 case ds_wsp_helper::iec_cma_exists: {
		 if(bop_multiple)
			 goto LBL_AGAIN;
	    return false;
	 }
	 case ds_wsp_helper::iec_cma_success:
		 break;
	 default:
	 case ds_wsp_helper::iec_cma_failed: {
        *ainp_auth  = *ainp_auth & ~AUTH_SUCCESS;
        *ainp_auth |= AUTH_ERR_CMA_CREATE;
        m_print_err_msg( *ainp_auth, adsp_auth, adsp_domain );
        return false;
    }
	 }
    if ( (iep_auth_flags & ied_usercma_login_anonymous) == 0 ) {
        //---------------------------------------
        // get user settings:
        //---------------------------------------
        bol_ret = m_get_user_settings( adsp_auth );
        if ( bol_ret == true ) {
            *ainp_auth |= AUTH_SETTINGS_SAVED;
        }

        //---------------------------------------
        // get user cookies:
        //---------------------------------------
        bol_ret = m_get_user_cookies( adsp_auth );
        if ( bol_ret == true ) {
            *ainp_auth |= AUTH_COOKIES_SAVED;
        }
    }

    return true;
} // end of ds_authenticate::m_init_user


/**
 * private function ds_authenticate::m_finish_auth
 *
 * @param[in]   dsd_auth_t      *adsp_auth
 * @param[in]   dsd_wspat_pconf_t *adsp_wspat_conf
 * @param[in]   HL_UINT         uinp_auth
*/
void ds_authenticate::m_finish_auth( dsd_auth_t *adsp_auth,
                                     struct dsd_wspat_public_config *adsp_wspat_conf,
                                     HL_UINT uinp_auth, struct dsd_domain *adsp_domain )
{
    // initialize some variables:
#if 0
    dsd_usr_cnt_cma  dsl_usr_cnt;               // user counter
#endif
    dsd_role*        adsl_sel_role;             // selected user role

#if 0
    //-------------------------------------------
    // count current user/peak of users
    //-------------------------------------------
    m_increase_usr_cnt( &dsl_usr_cnt );
#endif

    //-------------------------------------------
    // do a nice print out:
    //-------------------------------------------
    if (    adsp_wspat_conf                  != NULL
         && (uinp_auth & AUTH_ROLE_SELECTED) == AUTH_ROLE_SELECTED ) {
        adsp_auth->adsc_out_usr->m_set_state( ST_ACCEPTED );
        adsp_auth->adsc_out_usr->m_set_role ( NULL, 0     );

        // do a print out for login:
        adsl_sel_role = adsp_auth->adsc_out_usr->m_get_role();
        adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                 "HAUTHI102I group=%.*s userid=%.*s logged on, Role %.*s"/*, current %d, peak %d"*/,
                                 adsp_domain->inc_len_disp_name, adsp_domain->achc_disp_name,
                                 adsp_auth->inc_len_user,        adsp_auth->achc_user,
                                 adsl_sel_role->inc_len_name,    adsl_sel_role->achc_name/*,
                                 dsl_usr_cnt.inc_current,        dsl_usr_cnt.inc_peak*/ );

        // configure session:
        m_config_session( adsp_auth );
    } else {
        if ( adsp_wspat_conf == NULL ) {
            // avoid compliance check in this case!
            adsp_auth->adsc_out_usr->m_set_state( ST_ACCEPTED );
        }

        // do a print out for login:
        adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                 "HAUTHI104I group=%.*s userid=%.*s logged on"/*, current %d, peak %d"*/,
                                 adsp_domain->inc_len_disp_name,  adsp_domain->achc_disp_name,
                                 adsp_auth->inc_len_user,         adsp_auth->achc_user/*,
                                 dsl_usr_cnt.inc_current,         dsl_usr_cnt.inc_peak*/  );
    }
} // end of ds_authenticate::m_finish_auth


/**
 * function ds_authenticate::m_free_userov
 *
 * @param[in]   dsd_user_overview* ads_uov
*/
void ds_authenticate::m_free_userov( dsd_user_overview* ads_uov )
{
    // initialize some variables:
    dsd_user_overview* adsl_temp;

    while ( ads_uov != NULL ) {
        adsl_temp = ads_uov->ads_next;
        adsc_wsp_helper->m_cb_free_memory( ads_uov );
        ads_uov = adsl_temp;
    }
} // end of ds_authenticate::m_free_userov


/**
 * function ds_authenticate::m_get_domain_auth
 * get authentication method from given domain
 *
 * @param[in]   dsd_auth_t      *adsp_auth      pointer to current auth structure
 * @param[in]   int             inp_wsp_auth    in wsp configured auth methods
 * @param[in]   dsd_wspat_pconf_t   *adsp_wspat_conf    config from wspat
 * @param[out]  dsd_domain      **aadsp_domain  found domain
 * @return      int
*/
int ds_authenticate::m_get_domain_auth( dsd_auth_t *adsp_auth, int inp_wsp_auth,
                                        struct dsd_wspat_public_config *adsp_wspat_conf,
                                        struct dsd_domain **aadsp_domain )
{
    // initialize some variables:
    int                       inl_pos;
    int                       inl_srv;
    bool                      bol_ret;
    struct dsd_unicode_string dsl_srv_name;
    int                       inl_count;
    BOOL                      bol_comp;
    int                       inl_comp;

    /*
        check if we have a wspat config
         -> if not select first configured method
            from inr_auth_methods
    */
    if (    adsp_wspat_conf == NULL
         || adsp_wspat_conf->dsc_domains.adsc_domain == NULL ) {
        for ( inl_pos = 0; inl_pos < (int)(sizeof(inr_auth_methods)/sizeof(int)); inl_pos++ ) {
            if ( (inp_wsp_auth & inr_auth_methods[inl_pos]) == inr_auth_methods[inl_pos] ) {
                *aadsp_domain = NULL;
                return inr_auth_methods[inl_pos];
            }
        }
        return -1;
    }

    /*
        we have a valid wspat config
         -> go through configured domains
            and compare their display names with given one
         -> check if these domains are realy configured in wsp (inp_wsp_auth)
    */
    (*aadsp_domain) = adsp_wspat_conf->dsc_domains.adsc_domain;
    if (    adsp_auth->inc_len_domain  > 0
         && adsp_auth->achc_domain    != NULL ) {
        while ( (*aadsp_domain) != NULL ) {
            if (    adsp_auth->inc_len_domain == (*aadsp_domain)->inc_len_disp_name
                && memcmp( (*aadsp_domain)->achc_disp_name,
                            adsp_auth->achc_domain,
                            (*aadsp_domain)->inc_len_disp_name) == 0 ) {
                break;
            }
            (*aadsp_domain) = (*aadsp_domain)->adsc_next;
        }
        if ( (*aadsp_domain) == NULL ) {
            // not found
            return -1;
        }
    } else if (    (*aadsp_domain)            == NULL
                || (*aadsp_domain)->adsc_next != NULL ) {
        return -1;
    }

    switch( (*aadsp_domain)->inc_auth_type ) {
        case DEF_CLIB1_CONF_USERLI:
            /*
                check if userlist is really configured in wsp
            */
            if ( (inp_wsp_auth & DEF_CLIB1_CONF_USERLI) == DEF_CLIB1_CONF_USERLI ) {
                return DEF_CLIB1_CONF_USERLI;
            }
            break;

        default:
            /*
                in case of all other auth methods:
                   -> go trough configured auth methods
                   -> check if one is our domain
                   -> get its type
            */
            for ( inl_pos = 0; inl_pos < (int)(sizeof(inr_auth_methods)/sizeof(int)); inl_pos++ ) {
                switch ( (inp_wsp_auth & inr_auth_methods[inl_pos]) ) {
                    case DEF_CLIB1_CONF_RADIUS:
                        /*
                            check if we have really just ONE radius server
                        */
                        if ( (inp_wsp_auth & DEF_CLIB1_CONF_DYN_RADIUS) != DEF_CLIB1_CONF_DYN_RADIUS ) {
                            bol_ret = adsc_wsp_helper->m_cb_get_radius_srv( 0, &dsl_srv_name, NULL );
                            if (    bol_ret                       == true
                                 && (*aadsp_domain)->inc_len_name == m_len_vx_ucs( ied_chs_utf_8,
                                                                                   &dsl_srv_name ) ) {
                                bol_comp = m_cmp_vx_vx( &inl_comp,
                                                        (*aadsp_domain)->achc_name,
                                                        (*aadsp_domain)->inc_len_name,
                                                        ied_chs_utf_8,
                                                        dsl_srv_name.ac_str,
                                                        dsl_srv_name.imc_len_str,
                                                        dsl_srv_name.iec_chs_str  );
                                if ( bol_comp == TRUE && inl_comp == 0 ) {
                                    return DEF_CLIB1_CONF_RADIUS;
                                }
                            }
                        }
                        break;

                    case DEF_CLIB1_CONF_DYN_RADIUS:
                        inl_count = adsc_wsp_helper->m_cb_count_radius_srv();
                        for ( inl_srv = 0; inl_srv < inl_count; inl_srv++ ) {
                            bol_ret = adsc_wsp_helper->m_cb_get_radius_srv( inl_srv, &dsl_srv_name, NULL );
                            if (    bol_ret                       == true
                                 && (*aadsp_domain)->inc_len_name == m_len_vx_ucs( ied_chs_utf_8,
                                                                                   &dsl_srv_name ) ) {
                                bol_comp = m_cmp_vx_vx( &inl_comp,
                                                        (*aadsp_domain)->achc_name,
                                                        (*aadsp_domain)->inc_len_name,
                                                        ied_chs_utf_8,
                                                        dsl_srv_name.ac_str,
                                                        dsl_srv_name.imc_len_str,
                                                        dsl_srv_name.iec_chs_str  );
                                if ( bol_comp == TRUE && inl_comp == 0 ) {
                                    inc_sel_srv = inl_srv;  // save matching server index
                                    return DEF_CLIB1_CONF_DYN_RADIUS;
                                }
                            }

                        }
                        break;

                    case DEF_CLIB1_CONF_KRB5:
                        /*
                            check if we have really just ONE kerberos server
                        */
                        if ( (inp_wsp_auth & DEF_CLIB1_CONF_DYN_KRB5) != DEF_CLIB1_CONF_DYN_KRB5 ) {
                            bol_ret = adsc_wsp_helper->m_cb_get_krb5_srv( 0, &dsl_srv_name, NULL );
                            if (    bol_ret                       == true
                                 && (*aadsp_domain)->inc_len_name == m_len_vx_ucs( ied_chs_utf_8,
                                                                                   &dsl_srv_name ) ) {
                                bol_comp = m_cmp_vx_vx( &inl_comp,
                                                        (*aadsp_domain)->achc_name,
                                                        (*aadsp_domain)->inc_len_name,
                                                        ied_chs_utf_8,
                                                        dsl_srv_name.ac_str,
                                                        dsl_srv_name.imc_len_str,
                                                        dsl_srv_name.iec_chs_str  );
                                if ( bol_comp == TRUE && inl_comp == 0 ) {
                                    return DEF_CLIB1_CONF_KRB5;
                                }
                            }
                        }
                        break;

                    case DEF_CLIB1_CONF_DYN_KRB5:
                        inl_count = adsc_wsp_helper->m_cb_count_krb5_srv();
                        for ( inl_srv = 0; inl_srv < inl_count; inl_srv++ ) {
                            bol_ret = adsc_wsp_helper->m_cb_get_krb5_srv( inl_srv, &dsl_srv_name, NULL );
                            if (    bol_ret                       == true
                                 && (*aadsp_domain)->inc_len_name == m_len_vx_ucs( ied_chs_utf_8,
                                                                                   &dsl_srv_name ) ) {
                                bol_comp = m_cmp_vx_vx( &inl_comp,
                                                        (*aadsp_domain)->achc_name,
                                                        (*aadsp_domain)->inc_len_name,
                                                        ied_chs_utf_8,
                                                        dsl_srv_name.ac_str,
                                                        dsl_srv_name.imc_len_str,
                                                        dsl_srv_name.iec_chs_str  );
                                if ( bol_comp == TRUE && inl_comp == 0 ) {
                                    inc_sel_srv = inl_srv;  // save matching server index
                                    return DEF_CLIB1_CONF_DYN_KRB5;
                                }
                            }

                        }
                        break;

                    case DEF_CLIB1_CONF_LDAP:
                        /*
                            check if we have really just ONE ldap server
                        */
                        if ( (inp_wsp_auth & DEF_CLIB1_CONF_DYN_LDAP) != DEF_CLIB1_CONF_DYN_LDAP ) {
                            bol_ret = adsc_wsp_helper->m_cb_get_ldap_srv( 0, &dsl_srv_name, NULL );
                            if (    bol_ret                       == true
                                 && (*aadsp_domain)->inc_len_name == m_len_vx_ucs( ied_chs_utf_8,
                                                                                   &dsl_srv_name ) ) {
                                bol_comp = m_cmp_vx_vx( &inl_comp,
                                                        (*aadsp_domain)->achc_name,
                                                        (*aadsp_domain)->inc_len_name,
                                                        ied_chs_utf_8,
                                                        dsl_srv_name.ac_str,
                                                        dsl_srv_name.imc_len_str,
                                                        dsl_srv_name.iec_chs_str  );
                                if ( bol_comp == TRUE && inl_comp == 0 ) {
                                    return DEF_CLIB1_CONF_LDAP;
                                }
                            }
                        }
                        break;

                    case DEF_CLIB1_CONF_DYN_LDAP:
                        inl_count = adsc_wsp_helper->m_cb_count_ldap_srv();
                        for ( inl_srv = 0; inl_srv < inl_count; inl_srv++ ) {
                            bol_ret = adsc_wsp_helper->m_cb_get_ldap_srv( inl_srv, &dsl_srv_name, NULL );
                            if (    bol_ret                       == true
                                 && (*aadsp_domain)->inc_len_name == m_len_vx_ucs( ied_chs_utf_8,
                                                                                   &dsl_srv_name ) ) {
                                bol_comp = m_cmp_vx_vx( &inl_comp,
                                                        (*aadsp_domain)->achc_name,
                                                        (*aadsp_domain)->inc_len_name,
                                                        ied_chs_utf_8,
                                                        dsl_srv_name.ac_str,
                                                        dsl_srv_name.imc_len_str,
                                                        dsl_srv_name.iec_chs_str  );
                                if ( bol_comp == TRUE && inl_comp == 0 ) {
                                    inc_sel_srv = inl_srv;  // save matching server index
                                    return DEF_CLIB1_CONF_DYN_LDAP;
                                }
                            }

                        }
                        break;
                }
            } // end of for
            break;
    }
    return -1;
} // end of ds_authenticate::m_get_domain_auth


/**
 * function ds_authenticate::m_do_ext_auth
 * select method and do authentication
 *
 * @param[in]   dsd_auth_t  *adsp_auth      pointer to current auth structure
 * @param[in]   int         inp_wsp_auth    in wsp configured auth methods
 * @param[in]   int         inp_domain_auth from context selected auth method
 * @return      HL_UINT
*/
HL_UINT ds_authenticate::m_do_ext_auth( dsd_auth_t *adsp_auth,
                                        int inp_wsp_auth, int inp_domain_auth,
                                        struct dsd_domain *adsp_domain )
{
    // initializse some variables:
    HL_UINT uin_auth;                  // return value

    switch ( inp_wsp_auth & inp_domain_auth ) {
        /*
            do radius authentication:
        */
        case DEF_CLIB1_CONF_RADIUS:
            uin_auth = m_auth_radius( adsp_auth );
            break;

        /*
            do authentication against dynamic radius:
        */
        case DEF_CLIB1_CONF_DYN_RADIUS:
            uin_auth = m_auth_dyn_radius( adsp_auth );
            break;

        /*
            do authentication against wsp.xml:
        */
        case DEF_CLIB1_CONF_USERLI:
            uin_auth = m_auth_userlist( adsp_auth );
            break;

        /*
            do authentication against kerberos:
        */
        case DEF_CLIB1_CONF_KRB5:
            uin_auth = m_auth_krb5( adsp_auth, adsp_domain );
            break;

        /*
            do authentication against dynamic kerberos:
        */
        case DEF_CLIB1_CONF_DYN_KRB5:
            uin_auth = m_auth_dyn_krb5( adsp_auth, adsp_domain );
            break;

        /*
            do authentication against ldap:
        */
        case DEF_CLIB1_CONF_LDAP:
            uin_auth = m_auth_ldap( adsp_auth, adsp_domain );
            break;

        /*
            do authentication against dynamic ldap:
        */
        case DEF_CLIB1_CONF_DYN_LDAP:
            uin_auth = m_auth_dyn_ldap( adsp_auth, adsp_domain );
            break;

        /*
            unknown authentication method:
        */
        default:
            uin_auth = (AUTH_FAILED | AUTH_METH_UNKNOWN);
    }
    return uin_auth;
} // end of ds_authenticate::m_do_ext_auth


/**
 * function ds_authenticate::m_change_ext_pwd
 * select method and change password
 *
 * @param[in]   dsd_auth_t  *adsp_auth      pointer to current auth structure
 * @param[in]   int         inp_wsp_auth    in wsp configured auth methods
 * @param[in]   int         inp_domain_auth  from context selected auth method
 * @return      HL_UINT
*/
HL_UINT ds_authenticate::m_change_ext_pwd( dsd_auth_t *adsp_auth,
                                           int inp_wsp_auth, int inp_domain_auth,
                                           struct dsd_domain *adsp_domain )
{
    // initializse some variables:
    HL_UINT uinl_auth;

    switch ( inp_wsp_auth & inp_domain_auth ) {
        case DEF_CLIB1_CONF_RADIUS:
            uinl_auth = m_auth_radius( adsp_auth );
			break;

        case DEF_CLIB1_CONF_DYN_RADIUS:
            uinl_auth = m_chpwd_dyn_radius( adsp_auth, adsp_domain );
            break;

        case DEF_CLIB1_CONF_USERLI:
            uinl_auth = (AUTH_FAILED | AUTH_METH_USERLIST | AUTH_ERR_NO_SUPPORTED);
            break;

        case DEF_CLIB1_CONF_KRB5:
            uinl_auth = (AUTH_FAILED | AUTH_METH_KRB5 | AUTH_ERR_NO_SUPPORTED);
            break;

        case DEF_CLIB1_CONF_DYN_KRB5:
            uinl_auth = (AUTH_FAILED | AUTH_METH_DYN_KRB5 | AUTH_ERR_NO_SUPPORTED);
            break;

        case DEF_CLIB1_CONF_LDAP:
            uinl_auth = m_chpwd_ldap( adsp_auth, adsp_domain );
            break;

        case DEF_CLIB1_CONF_DYN_LDAP:
            uinl_auth = m_chpwd_dyn_ldap( adsp_auth, adsp_domain );
            break;

        default:
            uinl_auth = (AUTH_FAILED | AUTH_METH_UNKNOWN | AUTH_ERR_NO_SUPPORTED);
            break;
    }
    return uinl_auth;
} // end of ds_authenticate::m_do_ext_auth


/**
 * function ds_authenticate::m_auth_cma
 * do authentication against cma
 *
 * @param[in]   dsd_auth_t*         ads_auth        pointer to current auth structure
 * @param[in]   char                chp_session     session number
 * @param[in]   dsd_wspat_pconf_t*  ads_wspat_conf  config from wspat
 * @return      HL_UINT
*/
HL_UINT ds_authenticate::m_auth_cma( dsd_auth_t *adsp_auth,
                                     const dsd_cma_session_no& chp_session,
                                     struct dsd_wspat_public_config *adsp_wspat_conf,
                                     struct dsd_domain *adsp_domain )
{
    // initialize some variables:
    unsigned char        uchrl_sav_ip[LEN_INETA];   // saved client ip
    dsd_aux_query_client dsl_client;                // current client information
    int                  inl_pos;                   // position in client ip
    ds_hstring           dsl_value;                 // value
    hl_time_t               tml_current;               // current time
    dsd_role*            adsl_role;                 // role

    /*
        authenticate user against cma
        =============================
            we will check several conditions:
            -> users state:
                if state is not accepted, there is no need to keep this cma.
                delete it.

            -> max session lifetime:
                session is older than max session lifetime
                delete cma

            -> password (or better session ticket):
                there are two possible reasons for an incompatible password:
                1.) somebody want's to hack us
                2.) multiple login for users are allowed
                In both cases, just return failed authentication, but 
                do NOT affect current users with same name.

            -> check clients ip address:
                clients ip address must be equal to saved one
                if not just return failed authentication, but
                do NOT affect current user with same name.

    */

    //-------------------------------------------
    // check state (must be authenticated)
    //-------------------------------------------
    if ( adsp_auth->adsc_out_usr->m_check_state( ST_AUTHENTICATED ) == false ) {
        // logout this user:
        adsp_auth->adsc_out_usr->m_delete();
        return AUTH_FAILED | AUTH_METH_CMA | AUTH_ERR_STATE;
    }

    //-------------------------------------------
    // check listen port:
    //-------------------------------------------
    if ( adsp_auth->adsc_out_usr->m_check_port( adsc_wsp_helper->m_get_listen_port() ) == false ) {
        // logout this user:
        adsp_auth->adsc_out_usr->m_delete();
        return AUTH_FAILED | AUTH_METH_CMA | AUTH_ERR_OTHER_PORT;
    }

    //-------------------------------------------
    // check timestamps:
    //-------------------------------------------
    adsl_role   = m_get_role_by_name( adsp_auth, adsp_wspat_conf );
    tml_current = adsc_wsp_helper->m_cb_get_time();
    if ( adsl_role != NULL ) {
        if (    /* check idle period */ 
                (    adsl_role->dsc_time_limits.in_idle_period > 0
                  &&   adsp_auth->adsc_out_usr->m_get_lastaction()
                     + adsl_role->dsc_time_limits.in_idle_period  <= tml_current )
             || /* check max session lifetime */
                (    adsl_role->dsc_time_limits.in_max_period  > 0
                  &&   adsp_auth->adsc_out_usr->m_get_logintime()
                     + adsl_role->dsc_time_limits.in_max_period   <= tml_current ) ) {
            // logout this user:
            adsp_auth->adsc_out_usr->m_delete();
            return AUTH_FAILED | AUTH_METH_CMA | AUTH_ERR_EXPIRED;
        }
    }

    //-------------------------------------------
    // check antixss timestamp (if set)
    //-------------------------------------------
    if (    adsp_auth->adsc_out_usr->m_get_axss_time() >  0           /* 0 is not set       */
         && adsp_auth->adsc_out_usr->m_get_axss_time() <= tml_current /* smaller as current */ ) {
        // logout this user:
        adsp_auth->adsc_out_usr->m_delete();
        return AUTH_FAILED | AUTH_METH_CMA | AUTH_ERR_AXSS_EXPIRED;
    }

    //-------------------------------------------
    // check session ticket (must be equal)
    //-------------------------------------------
	if ( adsp_auth->adsc_out_usr->m_check_sticket( adsp_auth->achc_password, adsp_auth->inc_len_password ) == false ) {
	    return AUTH_FAILED | AUTH_METH_CMA | AUTH_ERR_STICKET;
	}

    if (    adsp_wspat_conf != NULL
            && adsp_wspat_conf->boc_check_cl_ineta == true ) {
        // check client ip address:
        if (    adsp_auth->adsc_out_usr->m_get_clientip( uchrl_sav_ip )
                && adsc_wsp_helper->m_cb_get_clientip     ( &dsl_client  ) ) {
            for ( inl_pos = 0; inl_pos < LEN_INETA; inl_pos++ ) {
                if ( (char)uchrl_sav_ip[inl_pos] != dsl_client.chrc_client_ineta[inl_pos] ) {
                    return AUTH_FAILED | AUTH_METH_CMA | AUTH_ERR_CLIENTIP;
                }
            }
        }
    } // end of if check client ineta

	 memcpy(adsp_auth->dsc_aux_ident_session_info.chrc_session_ticket, adsp_auth->achc_password, adsp_auth->inc_len_password);
	 adsp_auth->dsc_aux_ident_session_info.ucc_session_no = chp_session.ucc_session_no;
    m_set_ident( adsp_auth, adsp_domain );
	
	adsp_auth->adsc_out_usr->m_select_role(adsl_role);
	adsp_auth->adsc_out_usr->m_select_domain( adsp_domain );
	//---------------------------------------
    // set target filters and server lists:
    //---------------------------------------
    m_config_session( adsp_auth );
    //---------------------------------------
    // set last action timestamp:
    //---------------------------------------
    adsp_auth->adsc_out_usr->m_set_lastaction();
    return AUTH_SUCCESS | AUTH_METH_CMA;
} // end of ds_authenticate::m_auth_cma


/**
 * function ds_authenticate::m_auth_dyn_radius
 * do dynamic radius authentication
 *
 * @param[in]   dsd_auth_t          *adsp_auth        pointer to current auth structure
 * @return      HL_UINT
*/
HL_UINT ds_authenticate::m_auth_dyn_radius( dsd_auth_t *adsp_auth )
{
    bool    bol_ret;
    HL_UINT uinl_auth;

    //--------------------------------------
    // select radius server:
    //--------------------------------------
    bol_ret = adsc_wsp_helper->m_cb_set_radius_srv( inc_sel_srv );
    if ( bol_ret == false ) {
        adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                "HAUTHW038W select dynamic radius server failed" );
        return (AUTH_METH_DYN_RADIUS | AUTH_FAILED | AUTH_ERR_DYN_SEL);
    }

    //--------------------------------------
    // call ldap authentication
    //--------------------------------------
    uinl_auth = m_auth_radius( adsp_auth );

    //--------------------------------------
    // change auth method in return:
    //--------------------------------------
    uinl_auth = uinl_auth & ~AUTH_METH_RADIUS;
    uinl_auth |= AUTH_METH_DYN_RADIUS;

    //--------------------------------------
    // reset ldap server if auth failed:
    //--------------------------------------
    if ( (uinl_auth & AUTH_FAILED) == AUTH_FAILED ) {
        adsc_wsp_helper->m_reset_radius_srv();
    }
    return uinl_auth;
} // end of ds_authenticate::m_auth_dyn_radius


/**
 * function ds_authenticate::m_auth_radius
 * do radius authentication
 *
 * @param[in]   dsd_auth_t          *adsp_auth        pointer to current auth structure
 * @return      HL_UINT
*/
HL_UINT ds_authenticate::m_auth_radius( dsd_auth_t *adsp_auth )                                    
{
    // initialize some variables:
    HL_UINT             uinl_ret        = AUTH_METH_RADIUS; // return value
    bool                bol_ret;                            // return for aux call
    dsd_hl_aux_radius_1 dsl_auth_radius;                    // radius query structure
    ds_hstring          dsl_rad_attr( adsc_wsp_helper );    // radius attribute


    //--------------------------------------
    // setup radius structure:
    //--------------------------------------
    memset( &dsl_auth_radius, 0, sizeof(struct dsd_hl_aux_radius_1) );
    dsl_auth_radius.dsc_ucs_userid.ac_str      = (void*)adsp_auth->achc_user;
    dsl_auth_radius.dsc_ucs_userid.imc_len_str = adsp_auth->inc_len_user;
    dsl_auth_radius.dsc_ucs_userid.iec_chs_str = ied_chs_utf_8;
	if (adsp_auth->inc_len_old_pwd > 0) {
		dsl_auth_radius.dsc_ucs_password.ac_str      = const_cast<char*>(adsp_auth->achc_old_pwd);
		dsl_auth_radius.dsc_ucs_password.imc_len_str = adsp_auth->inc_len_old_pwd;
		dsl_auth_radius.dsc_ucs_password.iec_chs_str = ied_chs_utf_8;
		dsl_auth_radius.dsc_ucs_new_password.ac_str  = const_cast<char*>(adsp_auth->achc_password);
		dsl_auth_radius.dsc_ucs_new_password.imc_len_str = adsp_auth->inc_len_password;
		dsl_auth_radius.dsc_ucs_new_password.iec_chs_str = ied_chs_utf_8;
	} else {
		dsl_auth_radius.dsc_ucs_password.ac_str      = const_cast<char*>(adsp_auth->achc_password);
		dsl_auth_radius.dsc_ucs_password.imc_len_str = adsp_auth->inc_len_password;
		dsl_auth_radius.dsc_ucs_password.iec_chs_str = ied_chs_utf_8;
	}
    dsl_auth_radius.boc_send_nas_ineta = TRUE;  // force WSP to send NAS IP Address

	if (adsp_auth->inc_len_old_pwd == 0) {
		//--------------------------------------
		// write state attribute to output:
		//--------------------------------------
		if ( adsp_auth->adsc_state->m_get_len() > 0 ) {
			// write number of state attribute (0x18)
			dsl_rad_attr.m_write_char( 0x18 );
			// write length of this attribute (including number and this length-byte)
			dsl_rad_attr.m_write_char( (char)(adsp_auth->adsc_state->m_get_len() + 2) );
			// write state-string
			dsl_rad_attr.m_write( adsp_auth->adsc_state->m_get_ptr(),
								  adsp_auth->adsc_state->m_get_len() );
			// set output:
			dsl_auth_radius.achc_attr_out    = const_cast<char*>(dsl_rad_attr.m_get_ptr());
			dsl_auth_radius.imc_len_attr_out = dsl_rad_attr.m_get_len();

			// reset incoming radius:
			adsp_auth->adsc_state->m_reset();
		}
	}

    //--------------------------------------
    // do radius request:
    //--------------------------------------
    bol_ret = adsc_wsp_helper->m_cb_call_radius( &dsl_auth_radius );
    if ( bol_ret == false ) {
        return AUTH_FAILED | AUTH_METH_RADIUS | AUTH_ERR_AUX;
    }

    //--------------------------------------
    // handle response code:
    //--------------------------------------
    switch ( dsl_auth_radius.iec_radius_resp ) {
        /*
           invalid parameters:
        */
        case ied_rar_invalid:
            uinl_ret |= (AUTH_FAILED | AUTH_ERR_INV_PARAMS);
            adsc_wsp_helper->m_cb_free_radius( &dsl_auth_radius );
            break;

        /*
           no valid response:
        */
        case ied_rar_error:
            uinl_ret |= (AUTH_FAILED | AUTH_ERR_INV_RESP);
            adsc_wsp_helper->m_cb_free_radius( &dsl_auth_radius );
            break;

        /*
           reject access:
        */
        case ied_rar_access_reject:
            uinl_ret |= (AUTH_FAILED | AUTH_ERR_REJECT);
            adsc_wsp_helper->m_cb_free_radius( &dsl_auth_radius );
            break;

        /*
           request challenge:
        */
        case ied_rar_challenge:
            if ( dsl_auth_radius.imc_attr_in > 0 ) {
                // get RADIUS-state attribute (Type: 0x18):
                bol_ret = m_read_rad_attr( dsl_auth_radius.achc_attr_in, dsl_auth_radius.imc_attr_in,
                                           0x18, adsp_auth->adsc_state );
                if ( bol_ret == false ) {
                    adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                            "HAUTHW006W RADIUS-query failed: no state attribute found" );
                    break;
                }

                // get RADIUS-message attribute (Type: 0x12):
                m_read_rad_attr( dsl_auth_radius.achc_attr_in, dsl_auth_radius.imc_attr_in,
                                 0x12, adsp_auth->adsc_out_msg );
            } else {
                adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                        "HAUTHW007W RADIUS-query failed: no state attribute found" );
            }
            uinl_ret |= (AUTH_FAILED | AUTH_METH_CHALLENGE);
            break;

        /*
           accept sign on:
        */
        case ied_rar_access_accept:
            uinl_ret |= AUTH_SUCCESS;
            adsc_wsp_helper->m_cb_free_radius( &dsl_auth_radius );
            break;

		/*
           new password needed:
        */
        case ied_rar_need_new_password:
            uinl_ret |= ( AUTH_FAILED | AUTH_CHANGE_PWD );
            adsc_wsp_helper->m_cb_free_radius( &dsl_auth_radius );
            break;

        default:
            uinl_ret |= AUTH_FAILED;
            adsc_wsp_helper->m_cb_free_radius( &dsl_auth_radius );
            break;
    } // end of switch

    return uinl_ret;
} // end of ds_authenticate::m_auth_radius


/**
 * function ds_authenticate::m_auth_userlist
 * authenticate against wsp.xml userlist
 *
 * @param[in]   dsd_auth_t*         ads_auth        pointer to current auth structure
*/
HL_UINT ds_authenticate::m_auth_userlist( dsd_auth_t* ads_auth )
{
    // initialize some variables:
    HL_UINT             uin_ret         = AUTH_METH_USERLIST;   // return value
    bool                bo_ret          = false;                // return value for aux call
    dsd_hl_aux_ch_ident ds_auth_usrlist;                        // userlist radius query structure

    memset( &ds_auth_usrlist, 0, sizeof(dsd_hl_aux_ch_ident) );

    // fill structure:
    ds_auth_usrlist.ac_userid        = (void*)ads_auth->achc_user;
    ds_auth_usrlist.inc_len_userid   = ads_auth->inc_len_user;
    ds_auth_usrlist.iec_chs_userid   = ied_chs_utf_8;
    ds_auth_usrlist.ac_password      = (void*)ads_auth->achc_password;
    ds_auth_usrlist.inc_len_password = ads_auth->inc_len_password;
    ds_auth_usrlist.iec_chs_password = ied_chs_utf_8;
    ds_auth_usrlist.avpc_usent       = &ads_auth->avc_userentry;
    ds_auth_usrlist.avpc_usgro       = &ads_auth->avc_usergroup;

    bo_ret = adsc_wsp_helper->m_cb_check_ident( &ds_auth_usrlist );
    if ( bo_ret == false ) {
        return AUTH_FAILED | AUTH_METH_USERLIST | AUTH_ERR_AUX;
    }

    switch ( ds_auth_usrlist.iec_chid_ret ) {
        /*
            userid and password valid
        */
        case ied_chid_ok:
            uin_ret |= AUTH_SUCCESS;
            break;

        /*
            userid invalid - not known in system
        */
        case ied_chid_inv_userid:
            uin_ret |= (AUTH_FAILED | AUTH_ERR_USR);
            break;

        /*
            password invalid - does not match
        */
        case ied_chid_inv_password:
            uin_ret |= (AUTH_FAILED | AUTH_ERR_PWD);
            break;

        default:
            uin_ret |= AUTH_FAILED;
            break;
    }
    return uin_ret;
} // end of ds_authenticate::m_auth_userlist


/**
 * function ds_authenticate::m_auth_krb5
 * authenticate against kerberos
 *
 * @param[in]   dsd_auth_t*         ads_auth        pointer to current auth structure
 * @return      HL_UINT
*/
HL_UINT ds_authenticate::m_auth_krb5( dsd_auth_t* ads_auth, struct dsd_domain *adsp_domain )
{
    // initialize some variables:
    bool                   bo_ret;
    HL_UINT                uin_auth;
    dsd_aux_krb5_sign_on_1 ds_krb5_auth;

    ds_krb5_auth.iec_ret_krb5 = ied_ret_krb5_misc;

    //--------------------------------------
    // set username:
    //--------------------------------------
    ds_krb5_auth.dsc_user_name.ac_str      = const_cast<char*>(ads_auth->achc_user);
    ds_krb5_auth.dsc_user_name.imc_len_str = ads_auth->inc_len_user;
    ds_krb5_auth.dsc_user_name.iec_chs_str = ied_chs_utf_8;

    //--------------------------------------
    // set usergroup (needed for storing TGT in CMA(part of name))
    //--------------------------------------
    ds_krb5_auth.dsc_user_group.ac_str      = adsp_domain->achc_disp_name;
    ds_krb5_auth.dsc_user_group.imc_len_str = adsp_domain->inc_len_disp_name;
    ds_krb5_auth.dsc_user_group.iec_chs_str = ied_chs_utf_8;

    //--------------------------------------
    // set password:
    //--------------------------------------
    ds_krb5_auth.dsc_password.ac_str       = const_cast<char*>(ads_auth->achc_password);
    ds_krb5_auth.dsc_password.imc_len_str  = ads_auth->inc_len_password;
    ds_krb5_auth.dsc_password.iec_chs_str  = ied_chs_utf_8;

    //--------------------------------------
    // do the auth call:
    //--------------------------------------
    bo_ret = adsc_wsp_helper->m_cb_auth_krb5( &ds_krb5_auth );
    if ( bo_ret == true ) {
        // success!
        return (AUTH_METH_KRB5 | AUTH_SUCCESS);
    }

    //--------------------------------------
    // auth failed -> get detailed error
    //--------------------------------------
    uin_auth = (AUTH_METH_KRB5 | AUTH_FAILED);
    switch ( ds_krb5_auth.iec_ret_krb5 ) {
        case ied_ret_krb5_kdc_not_conf:
            uin_auth |= AUTH_KRB5_NOKDC_CONF;
            break;

        case ied_ret_krb5_kdc_not_sel:
            uin_auth |= AUTH_KRB5_NOKDC_SEL;
            break;

        case ied_ret_krb5_no_sign_on:
            uin_auth |= AUTH_KRB5_NO_SESS;
            break;

        case ied_ret_krb5_kdc_inv:
            uin_auth |= AUTH_KRB5_KDC_INV;
            break;

        case ied_ret_krb5_userid_unknown:
            uin_auth |= AUTH_ERR_USR;
            break;

        case ied_ret_krb5_password:
            uin_auth |= AUTH_ERR_PWD;
            break;

        case ied_ret_krb5_no_tgt:
            uin_auth |= AUTH_KRB5_NO_TGT;
            break;

        case ied_ret_krb5_misc:
            uin_auth |= AUTH_KRB5_MISC;
            break;
    }
    return uin_auth;
} // end of ds_authenticate::m_auth_krb5


/**
 * function ds_authenticate::m_auth_dyn_krb5
 * authenticate against dynamic kerberos
 *
 * @param[in]   dsd_auth_t*         ads_auth        pointer to current auth structure
 * @return      HL_UINT
*/
HL_UINT ds_authenticate::m_auth_dyn_krb5( dsd_auth_t* ads_auth, struct dsd_domain *adsp_domain )
{
    // initialize some variables:
    bool    bo_ret;
    HL_UINT uin_auth;

    //--------------------------------------
    // select ldap server:
    //--------------------------------------
    bo_ret = adsc_wsp_helper->m_cb_set_krb5_srv( inc_sel_srv );
    if ( bo_ret == false ) {
        adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                "HAUTHW008W select dynamic krb5 server failed" );
        return (AUTH_METH_DYN_KRB5 | AUTH_FAILED | AUTH_ERR_DYN_SEL);
    }

    //--------------------------------------
    // call ldap authentication
    //--------------------------------------
    uin_auth = m_auth_krb5( ads_auth, adsp_domain );

    //--------------------------------------
    // change auth method in return:
    //--------------------------------------
    uin_auth = uin_auth & ~AUTH_METH_KRB5;
    uin_auth |= AUTH_METH_DYN_KRB5;

    //--------------------------------------
    // reset ldap server if auth failed:
    //--------------------------------------
    if ( (uin_auth & AUTH_FAILED) == AUTH_FAILED ) {
        adsc_wsp_helper->m_reset_krb5_srv();
    }
    return uin_auth;
} // end of ds_authenticate::m_auth_dyn_krb5


/**
 * private function ds_authenticate::m_save_ldap_info
 *  save ldap information about user from ldap bind
 *
 * @param[in]   dsd_co_ldap_1   *adsp_ldap_cm   ldap command structure
 * @return      bool                            success or not
*/
bool ds_authenticate::m_save_ldap_info( struct dsd_co_ldap_1 *adsp_ldap_cm )
{
    bool                        bol_ret;        /* return for sev. funcs */
    struct dsd_ldap_attr        *adsl_attr;     /* found attributes      */
#ifdef SH_NESTED_GROUPS
    struct dsd_ldap_groups      *adsl_group_dns;/*!< group dns                 */
	int                         inl_groups;     /* number of group dns */
#endif
	
#define ADSL_STOR (&dsc_authinfo.dsc_stor)
#define DSL_AUTHINFO (dsc_authinfo.dsc_auth)
		
    bol_ret = adsc_wsp_helper->m_new_storage_cont( ADSL_STOR, 2048 );
    if ( bol_ret == false ) {
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HAUTHE201E cannot create new storage container" );                                 
        return false;
    }

	/*	frailejs:
		Temporary change added: For fixing the explode_dn() problem, a local dsd_ldap_attr link list has been created,
		as a copy of the input adsp_ldap_cm->adsc_attr_desc->adsc_attr, so that now the functions m_get_objectsid() and
		m_get_groups() can be called properly. 
		All the content is going to be copied within dsl_temp_ldap_attr in the following code
			
	*/

	//struct dsd_ldap_attr dsl_temp_ldap_attr;
	
	/*Pointers for managing the entire ldap attributes link list copy to the local structure dsl_temp_ldap_attr*/
    struct dsd_ldap_attr *adsl_original_ldap_ini = NULL;
    if(adsp_ldap_cm->adsc_attr_desc != NULL)
        adsl_original_ldap_ini = adsp_ldap_cm->adsc_attr_desc->adsc_attr;
	//struct dsd_ldap_attr *adsl_temp_ldap_attr = &dsl_temp_ldap_attr;
	struct dsd_ldap_attr *adsl_first_ldap_attr = NULL;
    struct dsd_ldap_attr *adsl_last_ldap_attr = NULL;

	/*Storing the ldap attributes link list into the local link list*/
	for( ;adsl_original_ldap_ini != NULL; adsl_original_ldap_ini = adsl_original_ldap_ini->adsc_next_attr) {
		struct dsd_ldap_attr *adsl_temp_ldap_attr = (dsd_ldap_attr*)m_aux_stor_alloc( ADSL_STOR ,sizeof(dsd_ldap_attr ));
		/*Copying the attributes content fields*/
		adsl_temp_ldap_attr->iec_chs_attr = adsl_original_ldap_ini->iec_chs_attr;
		adsl_temp_ldap_attr->imc_len_attr = adsl_original_ldap_ini->imc_len_attr;

		adsl_temp_ldap_attr->ac_attr = (char *)m_aux_stor_alloc ( ADSL_STOR ,adsl_temp_ldap_attr->imc_len_attr);

		memcpy(	adsl_temp_ldap_attr->ac_attr,
				adsl_original_ldap_ini->ac_attr,
				adsl_original_ldap_ini->imc_len_attr);

		/*
			Inside every attribute there is an structure called dsc_val.
			This dsc_val structure is a link list as well, so that inside every ldap attribute node,
			every node of dsc_val has to be copied.
		*/

		/*Pointers for managing the entire ldap dsc_val link list copy to the local structure dsc_val, inside dsl_temp_ldap_attr*/
		struct dsd_ldap_val adsl_ldap_val_ini = adsl_original_ldap_ini->dsc_val;			
		struct dsd_ldap_val *adsl_temp_ldap_val = &adsl_temp_ldap_attr->dsc_val;
		struct dsd_ldap_val *adsl_temp_original_ldap_ini_val = &adsl_original_ldap_ini->dsc_val;

		while(adsl_temp_original_ldap_ini_val){
			
			/*Storing the ldap values of every attribute node*/
			adsl_temp_ldap_val->iec_chs_val = adsl_temp_original_ldap_ini_val->iec_chs_val;
			adsl_temp_ldap_val->imc_len_val = adsl_temp_original_ldap_ini_val->imc_len_val;
			adsl_temp_ldap_val->iec_chs_val_old = adsl_temp_original_ldap_ini_val->iec_chs_val_old;
			//adsl_temp_ldap_val->imc_len_val_old = adsl_temp_original_ldap_ini_val->imc_len_val_old;
						
			/*	
				dsc_val.ac_val
			*/
			if(adsl_temp_original_ldap_ini_val->imc_len_val > 0){
				adsl_temp_ldap_val->ac_val = (char*)m_aux_stor_alloc( ADSL_STOR ,adsl_temp_original_ldap_ini_val->imc_len_val ) ;

				if(adsl_temp_ldap_val->ac_val){
					if(adsl_temp_original_ldap_ini_val->ac_val){
						memcpy(	adsl_temp_ldap_val->ac_val,
								adsl_temp_original_ldap_ini_val->ac_val,
								adsl_temp_original_ldap_ini_val->imc_len_val);
					}
					
				}
			}
			else if(adsl_temp_original_ldap_ini_val->imc_len_val == 0){
				adsl_temp_ldap_val->ac_val = NULL;
			}

			/*
				dsc_val.ac_val_old
			*/
			//if(adsl_original_ldap_ini->dsc_val.imc_len_val_old > 0){
			//		adsl_temp_ldap_val->ac_val_old = (char*)m_aux_stor_alloc( ADSL_STOR ,adsl_temp_original_ldap_ini_val->imc_len_val_old  ) ;
		
			//				memcpy(	adsl_temp_ldap_val->ac_val_old,
			//						adsl_temp_original_ldap_ini_val->ac_val_old,
			//						adsl_temp_original_ldap_ini_val->imc_len_val_old);

			//}	
			///*Following the original source adsl_original_ldap_ini, it is copied in the same way*/
			//else if(adsl_temp_original_ldap_ini_val->imc_len_val_old == 0){
			//	adsl_temp_ldap_val->ac_val_old = NULL;
			//}
			
			/*dsc_val link list copied*/

			/*Examining the next dsc_val link list node*/
			adsl_temp_original_ldap_ini_val = adsl_temp_original_ldap_ini_val->adsc_next_val;
			/*	
				If a next node exist in the original dsc_val link list, more memory has to be allocated in order to copy the original 
				dsc_val next node into the local dsc_val next node
			*/
			if(adsl_temp_original_ldap_ini_val){
				adsl_temp_ldap_val->adsc_next_val = (dsd_ldap_val*)m_aux_stor_alloc( ADSL_STOR ,sizeof(dsd_ldap_val)) ;
			}
			else{
				adsl_temp_ldap_val->adsc_next_val = NULL;
			}

			/*Next dsc_val link list node*/
			adsl_temp_ldap_val = adsl_temp_ldap_val->adsc_next_val;
			
		}//while

		/*Allocating memory for the next attribute node*/
        adsl_temp_ldap_attr->adsc_next_attr = NULL;
        if(adsl_first_ldap_attr == NULL) {
            adsl_first_ldap_attr = adsl_temp_ldap_attr;
            adsl_last_ldap_attr = adsl_temp_ldap_attr;
		}
        else 
		{
            adsl_last_ldap_attr->adsc_next_attr = adsl_temp_ldap_attr;
			adsl_last_ldap_attr = adsl_temp_ldap_attr;
		}
	}//for


    /*
        save dn complete and in exploded form
    */
    DSL_AUTHINFO.achc_dn = (const char*)m_aux_stor_alloc( ADSL_STOR,
                                                          adsp_ldap_cm->imc_len_dn );

    if ( DSL_AUTHINFO.achc_dn == NULL ) {
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HAUTHE202E cannot allocate memory for userdn '%.*s'",
                                 adsp_ldap_cm->imc_len_dn, adsp_ldap_cm->ac_dn );
        adsc_wsp_helper->m_del_storage_cont( ADSL_STOR );
        return false;
    }

    memcpy( (void*)DSL_AUTHINFO.achc_dn, adsp_ldap_cm->ac_dn, adsp_ldap_cm->imc_len_dn );
    DSL_AUTHINFO.inc_len_dn = adsp_ldap_cm->imc_len_dn;

    DSL_AUTHINFO.adsc_dn = m_explode_dn( ADSL_STOR,
                                         DSL_AUTHINFO.achc_dn,
                                         DSL_AUTHINFO.inc_len_dn );
    if ( DSL_AUTHINFO.adsc_dn == NULL ) {
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HAUTHE203E cannot explode userdn '%.*s'",
                                 DSL_AUTHINFO.inc_len_dn, 
                                 DSL_AUTHINFO.achc_dn );
        adsc_wsp_helper->m_del_storage_cont( ADSL_STOR );
        return false;
    }

    /*
        save objectSid also (if available = ActiveDirectory)
    */
    DSL_AUTHINFO.achc_osid    = NULL;
    DSL_AUTHINFO.inc_len_osid = 0;
	/*
	 * do not use this function after a further ldap call, because then 
	 * "adsp_ldap_cm->adsc_attr_desc->adsc_attr" will be overwritten
	 */

	//adsl_attr = m_get_objectsid( adsp_ldap_cm->adsc_attr_desc->adsc_attr );	
	adsl_attr = m_get_objectsid( adsl_first_ldap_attr );
	

    if ( adsl_attr != NULL ) {
        DSL_AUTHINFO.achc_osid = (const char*)m_aux_stor_alloc( ADSL_STOR,
                                                                         adsl_attr->dsc_val.imc_len_val );
        if ( DSL_AUTHINFO.achc_osid != NULL ) {
            memcpy( (void*)DSL_AUTHINFO.achc_osid, adsl_attr->dsc_val.ac_val,
                    adsl_attr->dsc_val.imc_len_val );
            DSL_AUTHINFO.inc_len_osid = adsl_attr->dsc_val.imc_len_val;
        }
    }

    /*
        get all groups and save their dn and exploded from
    */
    if ( DSL_AUTHINFO.adsc_lconf != NULL && DSL_AUTHINFO.adsc_lconf->imc_len_mship_attr > 0 ) {

       /* adsl_attr = m_get_groups( adsp_ldap_cm->adsc_attr_desc->adsc_attr,
                                  DSL_AUTHINFO.adsc_lconf->achc_mship_attr,
                                  DSL_AUTHINFO.adsc_lconf->imc_len_mship_attr );*/

		adsl_attr = m_get_groups( adsl_first_ldap_attr,
                                  DSL_AUTHINFO.adsc_lconf->achc_mship_attr,
                                  DSL_AUTHINFO.adsc_lconf->imc_len_mship_attr );

        if ( adsl_attr != NULL ) {
#ifdef SH_NESTED_GROUPS
			adsl_group_dns =              m_get_group_dns( ADSL_STOR,
                                                           adsl_attr,
                                                           &inl_groups );
			DSL_AUTHINFO.adsc_group_dns = m_search_groups( ADSL_STOR, NULL,
														   DSL_AUTHINFO.adsc_lconf,
														   DSL_AUTHINFO.achc_dn,
														   DSL_AUTHINFO.inc_len_dn,
														   DSL_AUTHINFO.achc_basedn,
														   DSL_AUTHINFO.inc_len_basedn,
														   &DSL_AUTHINFO.inc_groups,
														   adsl_group_dns, inl_groups);
            if ( DSL_AUTHINFO.adsc_group_dns != NULL ) {
                DSL_AUTHINFO.adsc_groups = m_explode_groups( ADSL_STOR,
                                                             DSL_AUTHINFO.adsc_group_dns,
                                                             DSL_AUTHINFO.inc_groups );
            }
#else
            DSL_AUTHINFO.adsc_group_dns = m_get_group_dns( ADSL_STOR,
                                                           adsl_attr,
                                                           &DSL_AUTHINFO.inc_groups );
            if ( DSL_AUTHINFO.adsc_group_dns != NULL ) {
                DSL_AUTHINFO.adsc_groups = m_explode_groups( ADSL_STOR,
                                                             adsl_attr,
                                                             DSL_AUTHINFO.inc_groups );
            }
#endif
        }
    } else {
#ifdef SH_NESTED_GROUPS
        DSL_AUTHINFO.adsc_group_dns = m_search_groups( ADSL_STOR, NULL,
                                                       DSL_AUTHINFO.adsc_lconf,
                                                       DSL_AUTHINFO.achc_dn,
                                                       DSL_AUTHINFO.inc_len_dn,
                                                       DSL_AUTHINFO.achc_basedn,
                                                       DSL_AUTHINFO.inc_len_basedn,
                                                       &DSL_AUTHINFO.inc_groups,
													   NULL, 0);
#else
        DSL_AUTHINFO.adsc_group_dns = m_search_groups( ADSL_STOR, NULL,
                                                       DSL_AUTHINFO.adsc_lconf,
                                                       DSL_AUTHINFO.achc_dn,
                                                       DSL_AUTHINFO.inc_len_dn,
                                                       DSL_AUTHINFO.achc_basedn,
                                                       DSL_AUTHINFO.inc_len_basedn,
                                                       &DSL_AUTHINFO.inc_groups );
#endif
        if ( DSL_AUTHINFO.adsc_group_dns != NULL ) {
            DSL_AUTHINFO.adsc_groups = m_explode_groups( ADSL_STOR,
                                                         DSL_AUTHINFO.adsc_group_dns,
                                                         DSL_AUTHINFO.inc_groups );
        }
    }

    DSL_AUTHINFO.boc_filled = TRUE;

#undef ADSL_STOR
#undef DSL_AUTHINFO
    return true;
} // end of ds_authenticate::m_save_ldap_info


/**
 * private function ds_authenticate::m_get_objectsid
 *  get objectSid from ldap info (if available)
 *
 * @param[in]       dsd_ldap_attr       *adsp_lattr     list of all attributes
 * @param[in/out]   dsd_unicode_string  *adsp_sid       objectSid
 * @return          bool                                true = found
 *                                                      false otherwise
*/
struct dsd_ldap_attr* ds_authenticate::m_get_objectsid( struct dsd_ldap_attr *adsp_lattr )
{
    struct dsd_ldap_attr *adsl_attr;
    int                  inl_comp;
    BOOL                 bol_ret;

    adsl_attr = adsp_lattr;
    while ( adsl_attr != NULL ) {
        bol_ret = m_cmp_vx_vx( &inl_comp, (void*)achg_objectsid, -1,
                               ied_chs_utf_8, adsl_attr->ac_attr,
                               adsl_attr->imc_len_attr, adsl_attr->iec_chs_attr );
        if (    bol_ret  == TRUE
             && inl_comp == 0    ) {
            break;
        }
        adsl_attr = adsl_attr->adsc_next_attr;
    }
    return adsl_attr;
} // end of ds_authenticate::m_get_objectsid


/**
 * private function ds_authenticate::m_get_groups
 *  get group membership information from ldap info
 *
 * @param[in]   dsd_ldap_attr   *adsp_lattr         list of all attributes
 * @param[in]   const char      *achp_mship_attr    member ship attribute
 * @param[in]   int             inp_len_mship_attr  length of membership attr
 * @return      dsd_ldap_attr*                      attr with group infos
*/
struct dsd_ldap_attr* ds_authenticate::m_get_groups( struct dsd_ldap_attr *adsp_lattr,
                                                     const char *achp_mship_attr,
                                                     int inp_len_mship_attr )
{
    struct dsd_ldap_attr *adsl_attr;
    int                  inl_comp;
    BOOL                 bol_ret;

    adsl_attr = adsp_lattr;
    while ( adsl_attr != NULL ) {
        bol_ret = m_cmp_vx_vx( &inl_comp, (void*)achp_mship_attr,
                               inp_len_mship_attr, ied_chs_utf_8,
                               adsl_attr->ac_attr, adsl_attr->imc_len_attr,
                               adsl_attr->iec_chs_attr );
        if (    bol_ret  == TRUE
             && inl_comp == 0    ) {
            break;
        }
        adsl_attr = adsl_attr->adsc_next_attr;
    }
    return adsl_attr;
} // end of ds_authenticate::m_get_groups


/**
 * function ds_authenticate::m_auth_ldap
 * authenticate against ldap
 *
 * @param[in]   dsd_auth_t  *adsp_auth          pointer to current auth structure
 * @return      HL_UINT                         return from auth
*/
HL_UINT ds_authenticate::m_auth_ldap( dsd_auth_t *adsp_auth, struct dsd_domain *adsp_domain )
{
    struct dsd_co_ldap_1   dsl_ldap_auth;       // ldap auth structure
    struct dsd_co_ldap_1   dsl_ldap_exp;        // ldap expires structure
    dsd_ldap_pwd           dsl_expires;         // ldap expires structure
    dsd_wspat_pconf_t      *adsl_wspat_conf;    // config from wspat
    bool                   bol_ret;             // return from ldap call

    /*
        get ldap sysinfo
    */
    memset( &dsl_ldap_auth, 0, sizeof(dsd_co_ldap_1) );
    dsl_ldap_auth.iec_co_ldap = ied_co_ldap_get_sysinfo;
    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap_auth );
    if (    bol_ret                     == true
         && dsl_ldap_auth.iec_ldap_resp == ied_ldap_success
         && dsl_ldap_auth.adsc_sysinfo  != NULL             ) {
        dsc_authinfo.dsc_auth.adsc_lconf  = dsl_ldap_auth.adsc_sysinfo->adsc_ldap_template;
		/* AKre: use  "adsc_base_dn_def" instead of adsc_base_dn*/
        if ( dsl_ldap_auth.adsc_sysinfo->adsc_base_dn_def != NULL ) { 
            dsc_authinfo.dsc_auth.achc_basedn    = dsl_ldap_auth.adsc_sysinfo->adsc_base_dn_def->ac_val;
            dsc_authinfo.dsc_auth.inc_len_basedn = dsl_ldap_auth.adsc_sysinfo->adsc_base_dn_def->imc_len_val;
		} else { /* take configured base */
			dsc_authinfo.dsc_auth.achc_basedn    = dsl_ldap_auth.adsc_sysinfo->adsc_base_dn_conf->ac_val;
            dsc_authinfo.dsc_auth.inc_len_basedn = dsl_ldap_auth.adsc_sysinfo->adsc_base_dn_conf->imc_len_val;
		}
    }
	else {
        if ((bol_ret != false) && (dsl_ldap_auth.ac_errmsg != NULL)) {
            if (dsl_ldap_auth.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap_auth.ac_errmsg);
            }
            else {
                adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap_auth.imc_len_errmsg, dsl_ldap_auth.ac_errmsg);
            }
        }
        m_close_ldap();
        return ( AUTH_METH_LDAP | AUTH_FAILED );
	}

    /*
        do authentication
    */
    memset( &dsl_ldap_auth, 0, sizeof(dsd_co_ldap_1) );
    dsl_ldap_auth.iec_co_ldap      = ied_co_ldap_bind;
    dsl_ldap_auth.ac_userid        = const_cast<char*>(adsp_auth->achc_user);
    dsl_ldap_auth.imc_len_userid   = adsp_auth->inc_len_user;
    dsl_ldap_auth.iec_chs_userid   = ied_chs_utf_8;
    if (    adsp_domain                  != NULL
         && adsp_domain->boc_search_base == true ) {
        dsl_ldap_auth.dsc_add_dn.ac_str      = adsp_domain->achc_base;
        dsl_ldap_auth.dsc_add_dn.imc_len_str = adsp_domain->inc_len_base;
        dsl_ldap_auth.dsc_add_dn.iec_chs_str = ied_chs_utf_8;
    }
    if (    adsp_auth->achc_old_pwd == NULL
         || adsp_auth->inc_len_old_pwd < 1  ) {
        /* normal authentication */
        dsl_ldap_auth.iec_ldap_auth  = ied_auth_user;
        dsl_ldap_auth.ac_passwd      = const_cast<char*>(adsp_auth->achc_password);
        dsl_ldap_auth.imc_len_passwd = adsp_auth->inc_len_password;
        dsl_ldap_auth.iec_chs_passwd = ied_chs_utf_8;
    } else {
        /* password change */
        dsl_ldap_auth.iec_ldap_auth      = ied_auth_user_pwd_change;
        dsl_ldap_auth.ac_passwd_new      = const_cast<char*>(adsp_auth->achc_password);
        dsl_ldap_auth.imc_len_passwd_new = adsp_auth->inc_len_password;
        dsl_ldap_auth.iec_chs_passwd_new = ied_chs_utf_8;
        dsl_ldap_auth.ac_passwd          = const_cast<char*>(adsp_auth->achc_old_pwd);
        dsl_ldap_auth.imc_len_passwd     = adsp_auth->inc_len_old_pwd;
        dsl_ldap_auth.iec_chs_passwd     = ied_chs_utf_8;
    }
    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap_auth );
    if ( bol_ret == false ) {
        m_close_ldap();
        return ( AUTH_METH_LDAP | AUTH_FAILED );
    }    

    switch ( dsl_ldap_auth.iec_ldap_resp ) {
        case ied_ldap_success:
			if (dsl_ldap_auth.iec_ldap_auth != ied_auth_user_pwd_change) {
				bol_ret = m_save_ldap_info( &dsl_ldap_auth );
				if ( bol_ret == false ) {
					return ( AUTH_METH_LDAP | AUTH_FAILED );
				}
				/* check password age */
				if (    adsp_auth->achc_old_pwd == NULL
					 || adsp_auth->inc_len_old_pwd < 1  ) {
					adsl_wspat_conf = adsc_wsp_helper->m_get_wspat_config();
					memset( &dsl_ldap_exp, 0, sizeof(dsd_co_ldap_1) );
					dsl_ldap_exp.iec_co_ldap    = ied_co_ldap_check_pwd_age;
					dsl_ldap_exp.ac_userid      = const_cast<char*>(adsp_auth->achc_user);
					dsl_ldap_exp.imc_len_userid = adsp_auth->inc_len_user;
					dsl_ldap_exp.iec_chs_userid = ied_chs_utf_8;
					dsl_ldap_exp.adsc_pwd_info  = &dsl_expires;
					bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap_exp );
					if (    bol_ret == true
						 && dsl_ldap_exp.iec_ldap_resp       == ied_ldap_success
						 && dsl_expires.iec_account_control == ied_ldap_success ) {
						if (   (   adsl_wspat_conf
								&& dsl_expires.ilc_exp_days < adsl_wspat_conf->inc_pwd_expires)
							 || dsl_expires.ilc_exp_days         < DEF_LIMIT_EXPIRES_DAYS  ) {
							adsp_auth->inc_pw_expires = (int)dsl_expires.ilc_exp_days;
						}
					} else {
						// Question: do we have to return an error here?
						// Answer: No, if there is no password expiration set for the user, we just don't care about that.
                        /*
				        if ((bol_ret != false) && (dsl_ldap_exp.ac_errmsg != NULL)) {
							if (dsl_ldap_exp.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
								adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap_exp.ac_errmsg);
							}
							else {
								adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap_exp.imc_len_errmsg, dsl_ldap_exp.ac_errmsg);
							}
						}
						*/
					}
				}
			}
            return ( AUTH_METH_LDAP | AUTH_SUCCESS );

        case ied_ldap_password_change:
            if (    adsp_auth->adsc_userdn  != NULL
                 && dsl_ldap_auth.imc_len_dn > 0    ) {
                adsp_auth->adsc_userdn->m_write( dsl_ldap_auth.ac_dn,
                                                 dsl_ldap_auth.imc_len_dn );
            }
            return ( AUTH_METH_LDAP | AUTH_FAILED | AUTH_CHANGE_PWD );

        default:
			if (dsl_ldap_auth.ac_errmsg != NULL) {
				if (dsl_ldap_auth.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
					adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap_auth.ac_errmsg);
				}
				else {
					adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap_auth.imc_len_errmsg, dsl_ldap_auth.ac_errmsg);
				}
			}
            m_close_ldap();
            return ( AUTH_METH_LDAP | AUTH_FAILED );
    }
} // end if ds_authenticate::m_auth_ldap


/**
 * function ds_authenticate::m_auth_dyn_ldap
 * authenticate against dynamic ldap
 *
 * @param[in]   dsd_auth_t*         ads_auth        pointer to current auth structure
 * @return      HL_UINT
*/
HL_UINT ds_authenticate::m_auth_dyn_ldap( dsd_auth_t* ads_auth, struct dsd_domain *adsp_domain )
{
    // initialize some variables:
    bool    bo_ret;
    HL_UINT uin_auth;

    //--------------------------------------
    // select ldap server:
    //--------------------------------------
    bo_ret = adsc_wsp_helper->m_cb_set_ldap_srv( inc_sel_srv );
    if ( bo_ret == false ) {
        adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                "HAUTHW009W select dynamic ldap server failed" );
        return (AUTH_METH_DYN_LDAP | AUTH_FAILED | AUTH_ERR_DYN_SEL);
    }

    //--------------------------------------
    // call ldap authentication
    //--------------------------------------
    uin_auth = m_auth_ldap( ads_auth, adsp_domain ); // here dn is correct!

    //--------------------------------------
    // change auth method in return:
    //--------------------------------------
    uin_auth = uin_auth & ~AUTH_METH_LDAP;
    uin_auth |= AUTH_METH_DYN_LDAP;

    //--------------------------------------
    // reset ldap server if auth failed:
    //--------------------------------------
    if ( (uin_auth & AUTH_FAILED) == AUTH_FAILED ) {
        adsc_wsp_helper->m_reset_ldap_srv();
    }
    return uin_auth;
} // end of ds_authenticate::m_auth_dyn_ldap


/**
 * function ds_authenticate::m_chpwd_ldap
 * change password in ldap
 *
 * @param[in]   dsd_auth_t  *adsp_auth
 * @return      HL_UINT
*/
HL_UINT ds_authenticate::m_chpwd_ldap( dsd_auth_t *adsp_auth, struct dsd_domain *adsp_domain )
{
    struct dsd_co_ldap_1 dsl_ldap;              /* ldap command struct   */
    bool                 bol_ret;               /* return for ldap call  */
    ds_hstring           dsl_userdn;            /* user dn               */

    dsl_userdn = adsp_auth->adsc_out_usr->m_get_userdn();

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap        = ied_co_ldap_bind;
    dsl_ldap.iec_ldap_auth      = ied_auth_user_pwd_change;
    if ( dsl_userdn.m_get_len() > 0 ) {
        dsl_ldap.ac_userid      = const_cast<char*>(dsl_userdn.m_get_ptr());
        dsl_ldap.imc_len_userid = dsl_userdn.m_get_len();
    } else {
        dsl_ldap.ac_userid      = const_cast<char*>(adsp_auth->achc_user);
        dsl_ldap.imc_len_userid = adsp_auth->inc_len_user;
    }
    dsl_ldap.iec_chs_userid     = ied_chs_utf_8;
    dsl_ldap.ac_passwd          = const_cast<char*>(adsp_auth->achc_old_pwd);
    dsl_ldap.imc_len_passwd     = adsp_auth->inc_len_old_pwd;
    dsl_ldap.iec_chs_passwd     = ied_chs_utf_8;
    dsl_ldap.ac_passwd_new      = const_cast<char*>(adsp_auth->achc_password);
    dsl_ldap.imc_len_passwd_new = adsp_auth->inc_len_password;
    dsl_ldap.iec_chs_passwd_new = ied_chs_utf_8;
    if (    adsp_domain                  != NULL
         && adsp_domain->boc_search_base == true ) {
        dsl_ldap.dsc_add_dn.ac_str      = adsp_domain->achc_base;
        dsl_ldap.dsc_add_dn.imc_len_str = adsp_domain->inc_len_base;
        dsl_ldap.dsc_add_dn.iec_chs_str = ied_chs_utf_8;
    }

    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
    if (    bol_ret                == false
         || dsl_ldap.iec_ldap_resp != ied_ldap_success ) {
			if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
				if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
					adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
				}
				else {
					adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
				}
			}
			if (dsl_ldap.iec_ldap_resp == ied_ldap_unwill_to_perform)
			 return (AUTH_METH_LDAP | AUTH_ERR_LDAP_UNWILL_TO_PERFORM | AUTH_FAILED);
			else if (dsl_ldap.iec_ldap_resp == ied_ldap_inv_cred)
			 return (AUTH_METH_LDAP | AUTH_ERR_LDAP_INV_CRED | AUTH_FAILED);
			else
			 return (AUTH_METH_LDAP | AUTH_FAILED);
    }
    return (AUTH_METH_LDAP | AUTH_SUCCESS);
} // end of ds_authenticate::m_chpwd_ldap


/**
 * function ds_authenticate::m_chpwd_ldap
 * change password in dynamic ldap
 *
 * @param[in]   dsd_auth_t  *adsp_auth
 * @return      HL_UINT
*/
HL_UINT ds_authenticate::m_chpwd_dyn_ldap( dsd_auth_t *adsp_auth, struct dsd_domain *adsp_domain  )
{
    // initialize some variables:
    bool    bol_ret;
    HL_UINT uinl_auth;

    //--------------------------------------
    // select ldap server:
    //--------------------------------------
    bol_ret = adsc_wsp_helper->m_cb_set_ldap_srv( inc_sel_srv );
    if ( bol_ret == false ) {
        adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                "HAUTHW010W select dynamic ldap server failed" );
        return (AUTH_METH_DYN_LDAP | AUTH_FAILED | AUTH_ERR_DYN_SEL);
    }

    //--------------------------------------
    // call ldap change password:
    //--------------------------------------
    uinl_auth = m_chpwd_ldap( adsp_auth, adsp_domain );

    //--------------------------------------
    // change auth method in return:
    //--------------------------------------
    uinl_auth = uinl_auth & ~AUTH_METH_LDAP;
    uinl_auth |= AUTH_METH_DYN_LDAP;

    //--------------------------------------
    // reset ldap server if auth failed:
    //--------------------------------------
    if ( (uinl_auth & AUTH_FAILED) == AUTH_FAILED ) {
        adsc_wsp_helper->m_reset_ldap_srv();
    }
    return uinl_auth;
} // end of ds_authenticate::m_chpwd_dyn_ldap


/**
 * function ds_authenticate::m_chpwd_dyn_radius
 * change password in dynamic radius
 *
 * @param[in]   dsd_auth_t  *adsp_auth
 * @return      HL_UINT
*/
HL_UINT ds_authenticate::m_chpwd_dyn_radius( dsd_auth_t *adsp_auth, struct dsd_domain *adsp_domain  )
{
    // initialize some variables:
    bool    bol_ret;
    HL_UINT uinl_auth;

    //--------------------------------------
    // select radius server:
    //--------------------------------------
    bol_ret = adsc_wsp_helper->m_cb_set_radius_srv( inc_sel_srv );
    if ( bol_ret == false ) {
        adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                "HAUTHW028W select dynamic radius server failed" );
        return (AUTH_METH_DYN_RADIUS | AUTH_FAILED | AUTH_ERR_DYN_SEL);
    }

    //--------------------------------------
    // call radius change password:
    //--------------------------------------
	uinl_auth = m_auth_radius( adsp_auth );

    //--------------------------------------
    // change auth method in return:
    //--------------------------------------
    uinl_auth = uinl_auth & ~AUTH_METH_RADIUS;
    uinl_auth |= AUTH_METH_DYN_RADIUS;

    //--------------------------------------
    // reset radius server if auth failed:
    //--------------------------------------
    if ( (uinl_auth & AUTH_FAILED) == AUTH_FAILED ) {
        adsc_wsp_helper->m_reset_radius_srv();
    }
    return uinl_auth;
} // end of ds_authenticate::m_chpwd_dyn_radius


/**
 * function ds_authenticate::m_set_ident
 * read user settings from wsp.xml userlist or just set users identiy
 *
 * @param[in]   dsd_auth_t*     adsp_auth       pointer to current auth structure
 * @param[in]   char            chp_session     session number
 *
*/
void ds_authenticate::m_set_ident( dsd_auth_t *adsp_auth,
                                   struct dsd_domain *adsp_domain )
{
    if (    adsp_auth->ainc_conn_state != NULL
         && (*(adsp_auth->ainc_conn_state) & DEF_CONN_STAT_IDENTIFIED) == DEF_CONN_STAT_IDENTIFIED ) {
        return;
    }

#if 0
    /*
        In case that there are some usersettings in wsp.xml (like targetfilter or dod)
        wsp can only use this settings when the (tcp) session is registerd to the current user.
        (This will only work, if user has the same name (and password!) in wsp file.)

        Register User with the session can be done in two different ways:
            > call DEF_AUX_CHECK_IDENT to do a dummy authentication
            > call DEF_AUX_SET_IDENT

        The problem is:
            If a user exists in wsps userlist, we don't know his group (cause wsp selects
            the first one, where he finds the right username/password).
            For datahooks that will call DEF_AUX_GET_IDENT_SETTINGS (i.e. hobphone) it is
            required that wsp registers the right (!not a dummy) group to find user settings
            again.

        Our solution:
            > If domain forces configuration by wsp.xml and if DEF_CLIB1_CONF_USERLI
              is set, we will do a call to DEF_AUX_CHECK_IDENT.
              WSP will select the "right" userdomain and register it with the session.
              If this call fails, we will set identity for wsp manually.
            > If domain forces any other configuration method or if DEF_CLIB1_CONF_USERLI
              is not set, we will set an identity for wsp.
              For group we will us our profile (or domain), which might be NULL if only one
              profile is configured.
              With this call we will get a nichs print out at wsp-admin.
              If a datahook call DEF_AUX_GET_IDENT_SETTINGS in that case, he will get no data.        
    */

    if ( (inp_wsp_auth & inp_domain_auth) == DEF_CLIB1_CONF_USERLI ) {
        /*
            userlist authentication is configured
        */
        if ( adsp_auth->avc_userentry == NULL || adsp_auth->avc_usergroup == NULL ) {
            if ( inp_len_pwd > 0 && achp_org_pwd != NULL ) {
                dsd_auth_t dsl_auth;
                memcpy( &dsl_auth, adsp_auth, sizeof(dsd_auth_t) );
                dsl_auth.achc_password    = achp_org_pwd;
                dsl_auth.inc_len_password = inp_len_pwd;
                m_auth_userlist( &dsl_auth );
                adsp_auth->avc_userentry = dsl_auth.avc_userentry;
                adsp_auth->avc_usergroup = dsl_auth.avc_usergroup;
            } else {
                m_auth_userlist( adsp_auth );
            }
        }
    } else {
        /*
            no userlist authentication configured
        */
        adsc_wsp_helper->m_cb_set_ident( adsp_auth->achc_user,  adsp_auth->inc_len_user,
                                         adsp_auth->achc_domain, adsp_auth->inc_len_domain,
                                         &chp_session, 1 );
    }
#endif
    adsc_wsp_helper->m_cb_set_ident( adsp_auth->achc_user,        adsp_auth->inc_len_user,
                                     adsp_domain->achc_disp_name, adsp_domain->inc_len_disp_name,
												 (const char*)&adsp_auth->dsc_aux_ident_session_info, sizeof(adsp_auth->dsc_aux_ident_session_info) );

    if ( adsp_auth->ainc_conn_state != NULL ) {
        *(adsp_auth->ainc_conn_state) |= DEF_CONN_STAT_IDENTIFIED;
    }
} // end of ds_authenticate::m_set_ident


/**
 * function ds_authenticate::m_create_usr_cma
 * create users cma name
 *
 * @param[in]   dsd_auth_t*         adsp_auth           pointer to current auth structure
 * @param[out]  char                chp_session         assigned session number
 * @param[in]   int                 inp_domain_auth     used authentication method
 * @param[in]   int                 inp_idle_tout       idle timeout (inactive user)
 * @param[in]   bool                bop_anonymous       anonymous login?
 * @param[in]   dsd_role            *adsp_selected      selected role
 * @return      bool                                    true = success
*/
ds_wsp_helper::ied_cma_result ds_authenticate::m_create_usr_cma( dsd_auth_t *adsp_auth, const dsd_cma_session_no& chp_session,
                                        int inp_domain_auth, enum ied_usercma_login_flags iep_auth_flags,
                                        dsd_role *adsp_selected,
                                        struct dsd_domain *adsp_domain )
{
    // initialize some variables:
    dsd_sdh_ident_set_1 dsl_ident;          // wsp identity settings
    char*               achl_wspgroup;      // user wspgroup
    int                 inl_len_wspgroup;   // length of user wspgroup
    BOOL                inl_ret;            // return for compare
    int                 inl_compare;        // return for compare

    /*
        if userlist authentication was selected, it is possible that
        wsp saved has not saved our userdomain but a different USERGROUP.
        This is necessary to find the correct setting with DEF_AUX_GET_IDENT_SETTINGS.

        So we will save our domain and wsp usergroup name.
    */
    achl_wspgroup    = NULL;
    inl_len_wspgroup = 0;
    if ( inp_domain_auth == DEF_CLIB1_CONF_USERLI ) {
        //---------------------------------------
        // get current wsp ident settings:
        //---------------------------------------
        memset( &dsl_ident, 0, sizeof(dsd_sdh_ident_set_1) );
        adsc_wsp_helper->m_cb_get_ident( &dsl_ident );

        if ( adsp_domain->inc_len_name > 0 ) {
            //-----------------------------------
            // compare wspgroup with domain:
            //-----------------------------------
            inl_ret = m_cmp_vx_vx( &inl_compare,
                                   adsp_domain->achc_disp_name,
                                   adsp_domain->inc_len_disp_name,
                                   ied_chs_utf_8,
                                   dsl_ident.dsc_user_group.ac_str,
                                   dsl_ident.dsc_user_group.imc_len_str,
                                   dsl_ident.dsc_user_group.iec_chs_str );
        } else {
            inl_ret     = FALSE;
            inl_compare = 1;
        }

        //---------------------------------------
        // set wspgroup if not equal:
        //---------------------------------------
        if ( inl_ret == FALSE || inl_compare != 0 ) {
            achl_wspgroup    = (char*)dsl_ident.dsc_user_group.ac_str;
            inl_len_wspgroup = dsl_ident.dsc_user_group.imc_len_str;
        }
    }

    if ( (iep_auth_flags & ied_usercma_login_anonymous) != 0 ) {
        adsp_auth->achc_user     = DEF_ANONYMOUS_USER;
        adsp_auth->inc_len_user  = (int)strlen(DEF_ANONYMOUS_USER);
#if 0
        adsp_auth->achc_domain    = NULL;
        adsp_auth->inc_len_domain = 0;
#endif
    }

    adsp_auth->adsc_out_usr->m_select_role( adsp_selected );
    //-------------------------------------------
    // create cma:
    //-------------------------------------------
	dsd_const_string dsl_password(adsp_auth->achc_password,    adsp_auth->inc_len_password);
#ifndef B20140805
	if(adsp_auth->inc_len_firstpassword > 0)
		dsl_password = dsd_const_string(adsp_auth->achc_firstpassword, adsp_auth->inc_len_firstpassword);
#endif
	ds_wsp_helper::ied_cma_result iel_ret = adsp_auth->adsc_out_usr->m_create(
                        adsp_auth->achc_user,        adsp_auth->inc_len_user,
                        adsp_domain->achc_disp_name, adsp_domain->inc_len_disp_name,
                        chp_session,
								dsl_password.m_get_ptr(),    dsl_password.m_get_len(),
                        dsc_authinfo.dsc_conf.achc_dn,
                        dsc_authinfo.dsc_conf.inc_len_dn,
                        achl_wspgroup,               inl_len_wspgroup,
                        inp_domain_auth, iep_auth_flags, &adsp_auth->dsc_aux_ident_session_info );
	if(iel_ret != ds_wsp_helper::iec_cma_success)
		return iel_ret;
    adsp_auth->adsc_out_usr->m_select_domain( adsp_domain );

    //-------------------------------------------
    // set state and last action timestamp:
    //-------------------------------------------
    adsp_auth->adsc_out_usr->m_set_state( ST_AUTHENTICATED );
    adsp_auth->adsc_out_usr->m_set_lastaction();
    return ds_wsp_helper::iec_cma_success;
} // end of ds_authenticate::m_create_usr_cma


/**
 * function ds_authenticate::m_read_rad_attr
 * read radius attribute
 *
 * @param[in]   char*       ach_rad_attr        radius attributes
 * @param[in]   int         in_len_attr         length of radius attributes
 * @param[in]   int         in_search           type to search
 * @param[in]   ds_hstring* ads_out             output for found attribute value
 * @return      bool                            true = success
*/
bool ds_authenticate::m_read_rad_attr( char* ach_rad_attr, int in_len_attr,
                                       int in_search,
                                       ds_hstring* ads_out )
{
    /*
        summary of the RADIUS attribute format:  
         0 1 2 3 4 5 6 7 8 9 A B C D E F 0 1 2 3 4 5 6 7
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
        |     Type      |    Length     | Value...
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    */

    // initialize some variables:
    int   in_rest = in_len_attr;        // count of not processed bytes
    int   in_type_curr;                 // type of the current atribute
    int   in_len_curr;                  // len of the current atribute
    char* ach_curr  = ach_rad_attr;

    //----------------------------
    // loop through attributes:
    //----------------------------
    while ( in_rest >= 2 ) { // 2 is minimum len of a RADIUS attribute
        // check for invalid parameters:
        if (ach_curr == NULL) {
            return false;
        }

        //----------------------------
        // read current type:
        //----------------------------
        in_type_curr = *((unsigned char *) ach_curr);

        //----------------------------
        // read current length:
        //----------------------------
        ach_curr++;
        in_len_curr  = *((unsigned char *) ach_curr);
        if ( in_len_curr > in_rest ) {
            // attr-len-info is bigger than available data -> error
            return false;
        }

        //---------------------------------
        // copy data into session buffer, if this is the searched attribute
        //---------------------------------

        if ( in_type_curr == in_search ) {
            switch ( in_search ) {
                /*
                   Reply Message
                */
                case 0x12:
                    // -2 because we must skip attribute-number and length-info
                    ads_out->m_write( ach_curr + 1, in_len_curr - 2 );
                    break;
                
                /*
                   Radius state
                */
                case 0x18:
                    // -2 because we must skip attribute-number and length-info
                    ads_out->m_write( ach_curr + 1, in_len_curr - 2 );
                    // RADIUS state info is unique -> we can leave !!
                    return true;
                
                default:
                    return false;
            }
        }

        //----------------------------
        // get next attribute:
        //----------------------------
        in_rest  -= in_len_curr;
        ach_curr += in_len_curr - 1;
    }

    return true;
} // end of ds_authenticate::m_read_rad_attr

#if 0
/**
 * private function ds_authenticate::m_select_role
 *
 * @param[in]   dsd_auth_t*        adsp_auth       pointer to authentication input structure
 * @param[in]   dsd_wspat_pconf_t* adsp_wspat_conf wspat configuration
 * @return      bool
*/
bool ds_authenticate::m_select_role( dsd_auth_t *adsp_auth,
                                     struct dsd_wspat_public_config *adsp_wspat_conf )
{
    // initialize some variables:
    dsd_role*  adsl_role;

    //-------------------------------------------
    // get role by its name:
    //-------------------------------------------
    adsl_role = m_get_role_by_name( adsp_auth, adsp_wspat_conf );
    if ( adsl_role != NULL ) {
        //---------------------------------------
        // save selected role:
        //---------------------------------------
        adsp_auth->adsc_out_usr->m_select_role( adsl_role );

        //---------------------------------------
        // set target filters and server lists:
        //---------------------------------------
        m_config_session( adsp_auth );
        return true;
    }
    return false;
} // end of ds_authenticate::m_select_role
#endif

/**
 * private function ds_authenticate::m_get_role_by_name
 *
 * @param[in]   dsd_auth_t        *adsp_auth        pointer to authentication input structure
 * @param[in]   dsd_wspat_pconf_t *adsp_wspat_conf  wspat configuration
 * @return      dsd_role*                       pointer to role (NULL in error cases)
*/
dsd_role* ds_authenticate::m_get_role_by_name( dsd_auth_t *adsp_auth,
                                               struct dsd_wspat_public_config *adsp_wspat_conf )
{
    // initialize some variables:
    ds_hstring dsl_role( adsc_wsp_helper );
    dsd_role*  adsl_cur_role;

    //-------------------------------------------
    // check if user is already accepted:
    //-------------------------------------------
    if ( adsp_auth->adsc_out_usr->m_check_state(ST_ACCEPTED) == true ) {
        //---------------------------------------
        // get role name:
        //---------------------------------------
        dsl_role = adsp_auth->adsc_out_usr->m_get_userrole();
        if ( dsl_role.m_get_len() < 1 ) {
            return NULL;
        }

        //---------------------------------------
        // loop through all roles:
        //---------------------------------------
        adsl_cur_role = adsp_wspat_conf->adsc_roles;
        while ( adsl_cur_role != NULL ) {
            if ( dsl_role.m_equals( adsl_cur_role->achc_name,
                                    adsl_cur_role->inc_len_name ) == true ) {
                 break;
            }

            // get next element:
            adsl_cur_role = adsl_cur_role->adsc_next;
        }
        
        return adsl_cur_role;
    }
    return NULL;
} // end of ds_authenticate::m_get_role_by_name


/**
 * private function ds_authenticate::m_get_possible_roles
 * get all possible roles for given user
 * if the one with highest priority doesn't need a compliance check select this one
 * if there is no role for user, return false
 *
 * @param[in]   dsd_auth_t        *adsp_auth        pointer to authentication input structure
 * @param[in]   dsd_wspat_pconf_t *adsp_wspat_conf  wspat configuration
 * @param[out]  HL_UINT         *auin_ret           return value
 * @param[out]  dsd_role        **aadsp_selected    selected role
 * @return      bool
*/
bool ds_authenticate::m_get_possible_roles( dsd_auth_t *adsp_auth,
                                            struct dsd_wspat_public_config *adsp_wspat_conf,
                                            HL_UINT *auinp_ret, dsd_role **aadsp_selected,
                                            struct dsd_domain *adsp_domain )
{
    // initialize some variables:
    dsd_role*                   adsl_cur_role;                  // current working role
    ds_hvector_btype<dsd_role*> dsl_vroles( adsc_wsp_helper );  // all possibles roles

    //-------------------------------------------
    // check input data:
    //-------------------------------------------
    *aadsp_selected = NULL;
    if ( adsp_wspat_conf == NULL ) { /* no wspat config    */
        *auinp_ret |= AUTH_ROLE_SELECTED;
        return true;
    }
    if (    adsp_auth                 == NULL /* no user info        */
         || adsp_wspat_conf->adsc_roles == NULL /* no roles configured */ ) {
        *auinp_ret  = *auinp_ret & ~AUTH_SUCCESS;
        *auinp_ret |= (AUTH_FAILED | AUTH_NO_ROLE_POSSIBLE);
        return false;
    }

    //-------------------------------------------
    // loop through all configured roles:
    //-------------------------------------------
    adsl_cur_role = adsp_wspat_conf->adsc_roles;
    while ( adsl_cur_role != NULL ) {
        // check if role is possible for user:
        if ( m_is_role_for_user( adsp_auth, adsl_cur_role, adsp_domain ) == true ) {
            dsl_vroles.m_add( adsl_cur_role );
        }

        // get next element:
        adsl_cur_role = adsl_cur_role->adsc_next;
    }

    //-------------------------------------------
    // check if there is min one role:
    //-------------------------------------------
    if ( dsl_vroles.m_empty() ) {
        *auinp_ret  = *auinp_ret & ~AUTH_SUCCESS;
        *auinp_ret |= (AUTH_FAILED | AUTH_NO_ROLE_POSSIBLE);
        return false;
    }

    //-------------------------------------------
    // should we avoid compliance check?
    //   -> select first role without check
    //-------------------------------------------
    if ( adsp_auth->boc_avoid_compl_check == true ) {
        // loop through ALL possible roles:
        for ( HVECTOR_FOREACH2(dsd_role*, adsl_cur, dsl_vroles) ) {
            adsl_cur_role = HVECTOR_GET(adsl_cur);
            if (    adsl_cur_role->achc_check    == NULL
                 || adsl_cur_role->inc_len_check  < 1    ) {
                /*
                    we have found a role without check
                    -> select this role
                */
                *aadsp_selected = adsl_cur_role;
                *auinp_ret |= AUTH_ROLE_SELECTED;
                return true;
            }
        }

        /*
            there exists no role without check
            -> return failure
        */
        *auinp_ret  = *auinp_ret & ~AUTH_SUCCESS;
        *auinp_ret |= (AUTH_FAILED | AUTH_NO_ROLE_POSSIBLE);
        return false;
    }


    //-------------------------------------------
    // check highest role:
    //-------------------------------------------
    adsl_cur_role = dsl_vroles.m_get_first();
    if (    adsl_cur_role->achc_check    == NULL
         || adsl_cur_role->inc_len_check  < 1    ) {
        /*
            role with highest priority has no compliance check
            configured
            -> select this role
        */
        *aadsp_selected = adsl_cur_role;
        *auinp_ret |= AUTH_ROLE_SELECTED;
        return true;
    }

    /*
        highest role requires a check
        -> save all role names in rolescma
    */
    adsp_auth->adsc_out_usr->m_add_roles( &dsl_vroles );
    return true;
} // end of ds_authenticate::m_get_possible_roles


/**
 * private function ds_authenticate::m_is_role_for_user
 *
 * @param[in]   dsd_auth_t*      adsp_auth       pointer to authentication input structure
 * @param[in]   dsd_role*        adsp_role       current role
 * @return      bool
*/
bool ds_authenticate::m_is_role_for_user( dsd_auth_t *adsp_auth, dsd_role *adsp_role,
                                          const struct dsd_domain *adsp_domain )
{
    // initialize some variables:
    struct dsd_role_list    *adsl_domain;       // allowed domains in cur role
    struct dsd_role_member  *adsl_member;       // allowed members in cur role
    bool                    bol_ret;            // return for some function calls
    ds_hstring hstr_last_error;

#ifdef SH_NESTED_GROUPS
    dsd_co_ldap_1 adsl_co_ldap;                 // LDAP request structure to get nested groups
    memset( &adsl_co_ldap, 0, sizeof(dsd_co_ldap_1) );
	bool bol_nested_search_done;


	bol_nested_search_done = false;

#endif
    /*
        check for allowed domains (if configured)
    */
    adsl_domain = adsp_role->adsc_domains;
#if 0
    adsc_wsp_helper->m_cb_printf_out("m_is_role_for_user: adsp_domain->achc_name=%.*s adsp_domain->achc_disp_name=%.*s",
        adsp_domain->inc_len_name, adsp_domain->achc_name,
        adsp_domain->inc_len_disp_name, adsp_domain->achc_disp_name);
#endif
    if (    adsp_domain != NULL
         && adsl_domain != NULL ) {
        do {
#if 0
            adsc_wsp_helper->m_cb_printf_out("   adsl_domain->entry=%.*s",
                adsl_domain->inc_len_entry, adsl_domain->achc_entry);
#endif            
            if (    adsl_domain->achc_entry    != NULL
                 && adsl_domain->inc_len_entry == adsp_domain->inc_len_name
                 && memcmp( adsl_domain->achc_entry,
                             adsp_domain->achc_name,
                             adsp_domain->inc_len_name ) == 0 ) {
                break;
            }
            adsl_domain = adsl_domain->adsc_next;
        } while ( adsl_domain != NULL );
        if ( adsl_domain == NULL ) {
            return false;
        }
    }

    /*
        check for certificate
    */
    if ( adsp_role->boc_require_cert == true ) {
        bol_ret = adsc_wsp_helper->m_cb_get_certificate( NULL, NULL );
        if ( bol_ret == false ) {
            return false;
        }
    }

    /*
        check if user is a role member:
    */
    adsl_member = adsp_role->adsc_members;
    while ( adsl_member != NULL ) {
        if (    adsl_member->achc_name    == NULL
             || adsl_member->inc_len_name <  0    ) {
            adsl_member = adsl_member->adsc_next;
            continue;
        }
        dsd_const_string dsl_member(adsl_member->achc_name, adsl_member->inc_len_name);
		switch ( adsl_member->ienc_type ) {
            /*
                userdn
            */
            case ied_role_mem_dn:
				if ( dsc_authinfo.dsc_conf.inc_len_dn > 0 ) {
					dsd_const_string dsl_cur(dsc_authinfo.dsc_conf.achc_dn, dsc_authinfo.dsc_conf.inc_len_dn);
					if (dsl_member.m_equals_ic(dsl_cur)) {
						return true;
					}
                }
                break;

            /*
                usergroup
            */
			case ied_role_mem_group: {
                if ( dsc_authinfo.dsc_conf.inc_groups > 0 ) {
                    dsd_ldap_groups* adsl_cur = dsc_authinfo.dsc_conf.adsc_group_dns;
                    dsd_ldap_groups* adsl_end = adsl_cur + dsc_authinfo.dsc_conf.inc_groups;
                    for ( ;adsl_cur < adsl_end; adsl_cur++ ) {
						dsd_const_string dsl_cur(adsl_cur->achc_dn, adsl_cur->inc_len_dn);
                        if(dsl_member.m_equals_ic(dsl_cur)) {
                            return true;
                        }
                    }
                }
			}
            /*
                organisation unit
            */
            case ied_role_mem_ou:
                if ( dsc_authinfo.dsc_conf.inc_tree >  0 ) {
                    dsd_ldap_groups* adsl_cur = dsc_authinfo.dsc_conf.adsc_tree_dns;
                    dsd_ldap_groups* adsl_end = adsl_cur + dsc_authinfo.dsc_conf.inc_tree;
                    for ( ;adsl_cur < adsl_end; adsl_cur++ ) {
						dsd_const_string dsl_cur(adsl_cur->achc_dn, adsl_cur->inc_len_dn);
						if (dsl_member.m_equals_ic(dsl_cur)) {
							return true;
						}
                    }
                }
                break;

            /*
                user name
            */
            case ied_role_mem_name:
                if ( adsp_auth->inc_len_user == adsl_member->inc_len_name ) {
                    dsd_const_string dsl_cur(adsp_auth->achc_user, adsp_auth->inc_len_user);
					if (dsl_member.m_equals_ic(dsl_cur)) {
						return true;
					}
                }
                break;
        }

        adsl_member = adsl_member->adsc_next;
    }
    return false;
} // end of ds_authenticate::m_is_role_for_user


/**
 * private function ds_authenticate::m_config_session
 *
 * @param[in]   dsd_auth_t* ads_auth        pointer to authentication input structure
 * @return      bool                        true = success
*/
bool ds_authenticate::m_config_session( dsd_auth_t* ads_auth )
{
    // initialize some variables:
    struct dsd_aux_session_conf_1 dsl_config;       // session configuration structure
    struct dsd_config_ineta_1*    adsl_htcp_inetas; // inetas for htcp
    struct dsd_config_ineta_1*    adsl_ppp_inetas;  // inetas for ppp
    struct dsd_role*              adsl_role;        // current role
    bool                          bol_ret;          // return value
    bool                          bol_call = false; // do the aux call?

    //---------------------------------------
    // is this connection already cofnigured?
    //---------------------------------------
    if (    ads_auth->ainc_conn_state    != NULL
         && (*(ads_auth->ainc_conn_state) & DEF_CONN_STAT_CONFIGURED) == DEF_CONN_STAT_CONFIGURED ) {
        return true;
    }

    //-------------------------------------------
    // init call structure:
    //-------------------------------------------
    memset( &dsl_config, 0, sizeof(dsd_aux_session_conf_1) );

    //-------------------------------------------
    // get current role:
    //-------------------------------------------
    adsl_role = ads_auth->adsc_out_usr->m_get_role();

    if ( adsl_role != NULL ) {
        //---------------------------------------
        // fill target filter:
        //---------------------------------------
        if (    adsl_role->achc_target_filter    != NULL
             && adsl_role->inc_len_target_filter >  0    ) {
            bol_call = true;
            dsl_config.dsc_targfi_1_name.ac_str      = adsl_role->achc_target_filter;
            dsl_config.dsc_targfi_1_name.imc_len_str = adsl_role->inc_len_target_filter;
            dsl_config.dsc_targfi_1_name.iec_chs_str = ied_chs_utf_8;
        }

        //---------------------------------------
        // fill server list:
        //---------------------------------------
        if ( adsl_role->adsc_srv_list != NULL ) {
            bol_call = true;
            dsl_config.adsc_servli_1 = adsl_role->adsc_srv_list;
        }
    }

    //-------------------------------------------
    // open PPP and HTCP INETAs:
    //-------------------------------------------
    bol_ret = ads_auth->adsc_out_usr->m_open_inetas( &adsl_ppp_inetas,
                                                     &adsl_htcp_inetas );
    if ( bol_ret == true ) {
        bol_call = true;
        dsl_config.adsc_co_ineta_ppp  = adsl_ppp_inetas;
        dsl_config.adsc_co_ineta_appl = adsl_htcp_inetas;
    }

    if ( bol_call == true ) {
        /*
            set use default servli always, otherwise
            we will not find any servers.
        */
        dsl_config.boc_use_default_servli = TRUE;

        //---------------------------------------
        // config session:
        //---------------------------------------
        bol_ret = adsc_wsp_helper->m_cb_config_session( &dsl_config );

        //---------------------------------------
        // close PPP and HTCP INETAs:
        //---------------------------------------
        ads_auth->adsc_out_usr->m_close_inetas( &adsl_ppp_inetas,
                                                &adsl_htcp_inetas );
    } else {
        bol_ret = true;
    }

    //---------------------------------------
    // mark this connection as already congigured:
    //---------------------------------------
    if ( ads_auth->ainc_conn_state != NULL ) {
        *(ads_auth->ainc_conn_state) |= DEF_CONN_STAT_CONFIGURED;
    }

    return bol_ret;
} // end of ds_authenticate::m_config_session


/**
 * private function ds_authenticate::m_get_user_settings
 * get settings for given user
 *
 * @param[in]   dsd_auth_t*      adsp_auth      pointer to authentication input structure
 * @return      bool
*/
bool ds_authenticate::m_get_user_settings( dsd_auth_t *adsp_auth )
{
    // initialize some variables:
    bool                    bol_ret;            /* return for sev funcs  */
    struct dsd_ldap_value   *adsl_own;          /* own user settings     */
    int                     inl_group;          /* number attr from grps */
    struct dsd_ldap_value   *adsl_group;        /* attr from groups      */
    int                     inl_tree;           /* number attr from tree */
    struct dsd_ldap_value   *adsl_tree;         /* attr from tree        */
    struct dsd_ldap_val     *adsl_value;        /* attr value            */

    //-------------------------------------------
    // get inheritable attributes from ldap:
    //-------------------------------------------
    /*
        WSG-Bookmarks:
    */
    bol_ret = m_collect_attribute( &dsc_authinfo.dsc_stor,
                                   DEF_ATTR_USET_WSG_BMARKS,
                                   (int)sizeof(DEF_ATTR_USET_WSG_BMARKS) - 1,
                                   &adsl_own, &inl_group, &adsl_group,
                                   &inl_tree, &adsl_tree );
    if ( bol_ret == true ) {
        bol_ret = m_import_ws_bmarks(  ied_bookmark_wsg,
                                       adsp_auth, adsl_own,
                                       inl_group, adsl_group,
                                       inl_tree, adsl_tree );
        if ( bol_ret == false ) {
            adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                    "HAUTHW011W import WSG-Bookmarks failed" );
        }
    } else {
        adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                 "HAUTHW012W getting WSG-Bookmarks failed" );
    }

    /*
        RDVPN-Bookmarks:
    */
    bol_ret = m_collect_attribute( &dsc_authinfo.dsc_stor,
                                   DEF_ATTR_USET_RDVPN_BMARKS,
                                   (int)sizeof(DEF_ATTR_USET_RDVPN_BMARKS) - 1,
                                   &adsl_own, &inl_group, &adsl_group,
                                   &inl_tree, &adsl_tree );
    if ( bol_ret == true ) {
        bol_ret = m_import_ws_bmarks(  ied_bookmark_rdvpn,
                                       adsp_auth, adsl_own,
                                       inl_group, adsl_group,
                                       inl_tree, adsl_tree );
        if ( bol_ret == false ) {
            adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                    "HAUTHW011W import RDVPN-Bookmarks failed" );
        }
    } else {
        adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                 "HAUTHW012W getting RDVPN-Bookmarks failed" );
    }
    
    /*
        WFA-Bookmarks:
    */
    bol_ret = m_collect_attribute( &dsc_authinfo.dsc_stor,
                                   DEF_ATTR_USET_WFA_BMARKS,
                                   (int)sizeof(DEF_ATTR_USET_WFA_BMARKS) - 1,
                                   &adsl_own, &inl_group, &adsl_group,
                                   &inl_tree, &adsl_tree );
    if ( bol_ret == true ) {
        bol_ret = m_import_wfa_bmarks( adsp_auth, adsl_own,
                                       inl_group, adsl_group,
                                       inl_tree, adsl_tree );
        if ( bol_ret == false ) {
            adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                    "HAUTHW013W import WFA-Bookmarks failed" );
        }
    } else {
        adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                 "HAUTHW014W getting WFA-Bookmarks failed" );
    }

    /*
        user messages:
    */
    bol_ret = m_collect_attribute( &dsc_authinfo.dsc_stor,
                                   DEF_ATTR_USR_MSG,
                                   (int)sizeof(DEF_ATTR_USR_MSG) - 1,
                                   &adsl_own, &inl_group, &adsl_group,
                                   &inl_tree, &adsl_tree );
    if ( bol_ret == true ) {
        bol_ret = m_import_usr_msg( adsp_auth, adsl_own, inl_group,
                                    adsl_group, inl_tree, adsl_tree );
        if ( bol_ret == false ) {
            adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                    "HAUTHW017W import user messages failed" );
        }
    } else {
        adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                 "HAUTHW018W getting user messages failed" );
    }


	/*
		hofmants:
		Get JWT SA configuration from LDAP
	*/

	m_jwtsa_find_configs( adsp_auth );
	//m_jwtsa_read_config( adsp_auth );		// read the config from LDAP
#if BO_HOBTE_CONFIG
    m_hobte_find_configs(adsp_auth);
#endif	

    //-------------------------------------------
    // get NOT inheritable attributes from ldap:
    //-------------------------------------------
    /*
        Desktop-On-Demand:
    */
    adsl_value = m_get_attribute( dsc_authinfo.dsc_conf.achc_dn,
                                  dsc_authinfo.dsc_conf.inc_len_dn,
                                  DEF_ATTR_USET_DOD,
                                  (int)sizeof(DEF_ATTR_USET_DOD) - 1 );
    if ( adsl_value != NULL ) {
        bol_ret = m_import_dod( adsp_auth, adsl_value );
        if ( bol_ret == false ) {
            adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                    "HAUTHW019W import DOD workstations failed" );
        }
    }

    /*
        personal IPs
    */
    adsl_value = m_get_attribute( dsc_authinfo.dsc_conf.achc_dn,
                                  dsc_authinfo.dsc_conf.inc_len_dn,
                                  DEF_ATTR_USET_HTCP,
                                  (int)sizeof(DEF_ATTR_USET_HTCP) - 1 );
    if ( adsl_value != NULL ) {
        bol_ret = m_import_htcp( adsp_auth, adsl_value );
        if ( bol_ret == false ) {
            adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                    "HAUTHW020W import personal IPs failed" );
        }
    }

    /*
        other user settings:
    */
    adsl_value = m_get_attribute( dsc_authinfo.dsc_conf.achc_dn,
                                  dsc_authinfo.dsc_conf.inc_len_dn,
                                  DEF_ATTR_USET_OTHERS,
                                  (int)sizeof(DEF_ATTR_USET_OTHERS) - 1 );
    if ( adsl_value != NULL ) {
        bol_ret = m_import_others( adsp_auth, adsl_value );
        if ( bol_ret == false ) {
            adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                    "HAUTHW021W import other usersettings failed" );
        }
    }
    return true;
} // end of ds_authenticate::m_get_user_settings


/**
 * private function ds_authenticate::m_import_wsg_bmarks
 * save wsg bmarks for given user in cma
 *
 * @param[in]   ied_us_tags     ien_tag         known tag
 * @param[in]   dsd_ldap_value  *adsp_own       own bookmarks
 * @param[in]   int             inp_groups      number of group entries
 * @param[in]   dsd_ldap_value  *adsp_group     inherited from groups
 * @param[in]   int             inp_tree        number of tree entries
 * @param[in]   dsd_ldap_value  *adsp_tree      inherited from tree
 * @return      bool
*/
bool ds_authenticate::m_import_ws_bmarks( enum ied_bookmark_type ienp_type, dsd_auth_t* adsp_auth,
                                           struct dsd_ldap_value *adsp_own,
                                           int inp_groups, struct dsd_ldap_value *adsp_group,
                                           int inp_tree,   struct dsd_ldap_value *adsp_tree  )
{
    ds_xml                  dsl_parser;         /* xml parser            */
    dsd_xml_tag*            adsl_node;          /* xml node              */
    ds_hvector<ds_bookmark> dsl_bmarks;         /* bmarks itself         */
    int                     inl_pos;            /* loop counter          */

    //-------------------------------------------
    // init variables:
    //-------------------------------------------
    dsl_parser.m_init( adsc_wsp_helper );
    dsl_bmarks.m_init( adsc_wsp_helper );

    //-------------------------------------------
    // read bookmarks from tree:
    //-------------------------------------------
#define ADSL_CUR_VALUE (adsp_tree + inl_pos)
    for ( inl_pos = 0; inl_pos < inp_tree; inl_pos++ ) {
        if ( ADSL_CUR_VALUE->inc_len_value > 0 ) {
            adsl_node = m_check_ws_bmarks( ienp_type, &dsl_parser,
                                            ADSL_CUR_VALUE->achc_value,
                                            ADSL_CUR_VALUE->inc_len_value );
            if ( adsl_node != NULL ) {
                m_read_ws_bmarks( ienp_type, false, adsl_node->ads_child, &dsl_bmarks );
            }
            dsl_parser.m_clear();
        }
    }
#undef ADSL_CUR_VALUE

    //-------------------------------------------
    // read bookmarks from group:
    //-------------------------------------------
#define ADSL_CUR_VALUE (adsp_group + inl_pos)
    for ( inl_pos = 0; inl_pos < inp_groups; inl_pos++ ) {
        if ( ADSL_CUR_VALUE->inc_len_value > 0 ) {
            adsl_node = m_check_ws_bmarks( ienp_type, &dsl_parser,
                                            ADSL_CUR_VALUE->achc_value,
                                            ADSL_CUR_VALUE->inc_len_value );
            if ( adsl_node != NULL ) {
                m_read_ws_bmarks( ienp_type, false, adsl_node->ads_child, &dsl_bmarks );
            }
            dsl_parser.m_clear();
        }
    }
#undef ADSL_CUR_VALUE

    //-------------------------------------------
    // read own bookmarks:
    //-------------------------------------------
    if (    adsp_own                != NULL
         && adsp_own->inc_len_value > 0     ) {
        adsl_node = m_check_ws_bmarks( ienp_type, &dsl_parser,
                                        adsp_own->achc_value, 
                                        adsp_own->inc_len_value );
        if ( adsl_node != NULL ) {
            m_read_ws_bmarks( ienp_type, true, adsl_node->ads_child, &dsl_bmarks );
        }
    }

    if ( dsl_bmarks.m_empty() == false ) {
        switch (ienp_type)
        {
        case ied_bookmark_wsg:
            return adsp_auth->adsc_out_usr->m_set_wsg_bookmarks( &dsl_bmarks );
        case ied_bookmark_rdvpn:
            return adsp_auth->adsc_out_usr->m_set_rdvpn_bookmarks( &dsl_bmarks );
        default:
            false;
        }
    }
    return true;
} // end of ds_authenticate::m_import_wsg_bmarks


/**
 * private function ds_authenticate::m_import_wfa_bmarks
 * save wfa bmarks for given user in cma
 *
 * @param[in]   dsd_ldap_value  *adsp_own       own bookmarks
 * @param[in]   int             inp_groups      number of group entries
 * @param[in]   dsd_ldap_value  *adsp_group     inherited from groups
 * @param[in]   int             inp_tree        number of tree entries
 * @param[in]   dsd_ldap_value  *adsp_tree      inherited from tree
 * @return      bool
*/
bool ds_authenticate::m_import_wfa_bmarks( dsd_auth_t* adsp_auth,
                                           struct dsd_ldap_value *adsp_own,
                                           int inp_groups, struct dsd_ldap_value *adsp_group,
                                           int inp_tree,   struct dsd_ldap_value *adsp_tree  )
{
    ds_xml                    dsl_parser;       /* xml parser            */
    dsd_xml_tag*              adsl_node;        /* xml node              */
    ds_hvector<dsd_wfa_bmark> dsl_bmarks;       /* bmarks itself         */
    int                       inl_pos;          /* loop counter          */

    //-------------------------------------------
    // init variables:
    //-------------------------------------------
    dsl_parser.m_init( adsc_wsp_helper );
    dsl_bmarks.m_init( adsc_wsp_helper );

    //-------------------------------------------
    // read bookmarks from tree:
    //-------------------------------------------
#define ADSL_CUR_VALUE (adsp_tree + inl_pos)
    for ( inl_pos = 0; inl_pos < inp_tree; inl_pos++ ) {
        if ( ADSL_CUR_VALUE->inc_len_value > 0 ) {
            adsl_node = m_check_wfa_bmarks( &dsl_parser,
                                           ADSL_CUR_VALUE->achc_value,
                                           ADSL_CUR_VALUE->inc_len_value );
            if ( adsl_node != NULL ) {
                m_read_wfa_bmarks( false, adsl_node->ads_child, &dsl_bmarks );
            }
            dsl_parser.m_clear();
        }
    }
#undef ADSL_CUR_VALUE

    //-------------------------------------------
    // read bookmarks from group:
    //-------------------------------------------
#define ADSL_CUR_VALUE (adsp_group + inl_pos)
    for ( inl_pos = 0; inl_pos < inp_groups; inl_pos++ ) {
        if ( ADSL_CUR_VALUE->inc_len_value > 0 ) {
            adsl_node = m_check_wfa_bmarks( &dsl_parser,
                                            ADSL_CUR_VALUE->achc_value,
                                            ADSL_CUR_VALUE->inc_len_value );
            if ( adsl_node != NULL ) {
                m_read_wfa_bmarks( false, adsl_node->ads_child, &dsl_bmarks );
            }
            dsl_parser.m_clear();
        }
    }
#undef ADSL_CUR_VALUE

    //-------------------------------------------
    // read own bookmarks:
    //-------------------------------------------
    if (    adsp_own                != NULL
         && adsp_own->inc_len_value > 0     ) {
        adsl_node = m_check_wfa_bmarks( &dsl_parser,
                                        adsp_own->achc_value, 
                                        adsp_own->inc_len_value );
        if ( adsl_node != NULL ) {
            m_read_wfa_bmarks( true, adsl_node->ads_child, &dsl_bmarks );
        }
    }

    if ( dsl_bmarks.m_empty() == false ) {
        return adsp_auth->adsc_out_usr->m_set_wfa_bookmarks( &dsl_bmarks );
    }
    return true;
} // end of ds_authenticate::m_import_wfa_bmarks


/**
 * private function ds_authenticate::m_check_wsg_bmarks
 *  check wsg bookmarks for given user in cma
 *
 * @param[in]   ds_xml*             adsp_parser     parser class
 * @param[in]   const char*         achp_xml        xml data
 * @param[in]   int                 inp_len_xml     length of xml data
 * @return      dsd_xml_tag*                        NULL in error cases
*/
dsd_xml_tag* ds_authenticate::m_check_ws_bmarks( enum ied_bookmark_type ienp_type, ds_xml* adsp_parser,
                                                  const char* achp_xml, int inp_len_xml )
{
    // initialize some variables:
    dsd_xml_tag*            adsl_node;              // xml node
    const char*                   achl_name;              // node name
    int                     inl_len_name;           // length of name
    int                     inl_version;            // version number
    enum ied_us_tags        inl_tag_type;               //type of wrapping tag

    switch(ienp_type) {
    case ied_bookmark_wsg:
        inl_tag_type = ied_us_tag_wsg_bm;
        break;
    case ied_bookmark_rdvpn:
        inl_tag_type = ied_us_tag_rdvpn_bm;
        break;
    default:
        return NULL;
    }

    adsl_node = adsp_parser->m_from_xml( (char*)achp_xml, inp_len_xml );
    if ( adsl_node == NULL ) {
        return NULL;
    }

    // check name of tag:
    adsp_parser->m_get_node_name( adsl_node, &achl_name, &inl_len_name );
    if (    achl_name == NULL
        || m_equals( inl_tag_type, achl_name, inl_len_name ) == false ) {
        return NULL;
    }

    // check version:
    inl_version = adsp_parser->m_read_int( adsl_node,
                                           achg_us_tags[ied_us_tag_version],
                                           0 );
    if ( inl_version != DEF_VERS_USET_WSG_BMARKS ) {
        return NULL;
    }
    return adsl_node;
} // end of ds_authenticate::m_check_wsg_bmarks


/**
 * private function ds_authenticate::m_check_wfa_bmarks
 *  check wsg bookmarks for given user in cma
 *
 * @param[in]   ds_xml*             adsp_parser     parser class
 * @param[in]   const char*         achp_xml        xml data
 * @param[in]   int                 inp_len_xml     length of xml data
 * @return      dsd_xml_tag*                        NULL in error cases
*/
dsd_xml_tag* ds_authenticate::m_check_wfa_bmarks( ds_xml* adsp_parser,
                                                  const char* achp_xml, int inp_len_xml )
{
    // initialize some variables:
    dsd_xml_tag*            adsl_node;              // xml node
    const char*                   achl_name;              // node name
    int                     inl_len_name;           // length of name
    int                     inl_version;            // version number

    adsl_node = adsp_parser->m_from_xml( (char*)achp_xml, inp_len_xml );
    if ( adsl_node == NULL ) {
        return NULL;
    }

    // check name of tag:
    adsp_parser->m_get_node_name( adsl_node, &achl_name, &inl_len_name );
    if (    achl_name == NULL
         || m_equals( ied_us_tag_wfa_bm, achl_name, inl_len_name ) == false ) {
        return NULL;
    }

    // check version:
    inl_version = adsp_parser->m_read_int( adsl_node,
                                           achg_us_tags[ied_us_tag_version],
                                           0 );

    if ( inl_version != DEF_VERS_USET_WFA_BMARKS ) {
        return NULL;
    }
    return adsl_node;
} // end of ds_authenticate::m_check_wfa_bmarks


/**
 * private function ds_authenticate::m_read_wsg_bmarks
 *
 * @param[in]   bool                        bo_own          config is from user himself
 * @param[in]   dsd_xml_tag*                ads_pnode       parent xml node
 * @param[out]   ds_hvector<ds_bookmark>*    ads_out         output vector
*/
void ds_authenticate::m_read_ws_bmarks( enum ied_bookmark_type iep_type, bool bop_own, dsd_xml_tag* adsp_node,
                                         ds_hvector<ds_bookmark>* adsp_out )
{
    // initialize some variables:
    bool        bol_ret;            // return value
    ds_bookmark dsl_bookmark;       // bookmark class

    //-------------------------------------------
    // init some classes:
    //-------------------------------------------
    dsl_bookmark.m_init( adsc_wsp_helper );

    while ( adsp_node != NULL ) {
        // get bookmark from xml:
        bol_ret = dsl_bookmark.m_from_xml( adsp_node );
        if ( bol_ret == true ) {
            // add it to vector:
            dsl_bookmark.m_set_own( bop_own );
            adsp_out->m_add( dsl_bookmark );
        }
        // get next bookmark:
        adsp_node = adsp_node->ads_next;
    }
} // end of ds_authenticate::m_read_wsg_bmarks


/**
 * private function ds_authenticate::m_read_wfa_bmarks
 *
 * @param[in]   bool                        bo_own          config is from user himself
 * @param[in]   dsd_xml_tag*                ads_pnode       parent xml node
 * @param[in]   ds_hvector<ds_bookmark>*    ads_out         output vector
*/
void ds_authenticate::m_read_wfa_bmarks( bool bop_own, dsd_xml_tag* adsp_node,
                                         ds_hvector<dsd_wfa_bmark>* adsp_out )
{
    // initialize some variables:
    bool          bol_ret;            // return value
    dsd_wfa_bmark dsl_bookmark;       // bookmark class

    //-------------------------------------------
    // init some classes:
    //-------------------------------------------
    dsl_bookmark.m_init( adsc_wsp_helper );

    while ( adsp_node != NULL ) {
        // get bookmark from xml:
        bol_ret = dsl_bookmark.m_from_xml( adsp_node );
        if ( bol_ret == true ) {
            // add it to vector:
            dsl_bookmark.m_set_own( bop_own );
            adsp_out->m_add( dsl_bookmark );
        }
        // get next bookmark:
        adsp_node = adsp_node->ads_next;
    }
} // end of ds_authenticate::m_read_wfa_bmarks


/**
 * private function ds_authenticate::m_import_usr_msg
 * save user messages for given user in cma
 *
 * @param[in]   ied_us_tags     ien_tag         known tag
 * @param[in]   dsd_ldap_value  *adsp_own       own messages
 * @param[in]   int             inp_groups      number of group entries
 * @param[in]   dsd_ldap_value  *adsp_group     inherited from groups
 * @param[in]   int             inp_tree        number of tree entries
 * @param[in]   dsd_ldap_value  *adsp_tree      inherited from tree
 * @return      bool
*/
bool ds_authenticate::m_import_usr_msg( dsd_auth_t *adsp_auth,
                                        struct dsd_ldap_value *adsp_own,
                                        int inp_groups, struct dsd_ldap_value *adsp_group,
                                        int inp_tree,   struct dsd_ldap_value *adsp_tree  )
{
    ds_xml                      dsl_parser;     /* xml parser            */
    dsd_xml_tag*                adsl_node;      /* xml node              */
    ds_hstring                  dsl_msg;        /* total message for user*/
    int                         inl_pos;        /* loop counter          */
    const char                        *achl_msg;      /* current message       */
    int                         inl_length;     /* length message        */

    //-------------------------------------------
    // init variables:
    //-------------------------------------------
    dsl_parser.m_init( adsc_wsp_helper );
    dsl_msg.m_init   ( adsc_wsp_helper );

    //-------------------------------------------
    // read messages from tree:
    //-------------------------------------------
#define ADSL_CUR_VALUE (adsp_tree + inl_pos)
    for ( inl_pos = 0; inl_pos < inp_tree; inl_pos++ ) {
        if ( ADSL_CUR_VALUE->inc_len_value > 0 ) {
            adsl_node = m_check_usr_msg( &dsl_parser,
                                         ADSL_CUR_VALUE->achc_value,
                                         ADSL_CUR_VALUE->inc_len_value );
            if ( adsl_node != NULL ) {
                dsl_parser.m_get_value( adsl_node,
                                        achg_us_tags[ied_us_tag_usr_msg],
                                        &achl_msg, &inl_length );
                if ( inl_length > 0 ) {
                    if ( dsl_msg.m_get_len() > 0 ) {
                        dsl_msg.m_write( "<br/>" );
                    }
                    dsl_msg.m_write( achl_msg, inl_length );
                }                
            }
            dsl_parser.m_clear();
        }
    }
#undef ADSL_CUR_VALUE

    //-------------------------------------------
    // read messages from group:
    //-------------------------------------------
#define ADSL_CUR_VALUE (adsp_group + inl_pos)
    for ( inl_pos = 0; inl_pos < inp_groups; inl_pos++ ) {
        if ( ADSL_CUR_VALUE->inc_len_value > 0 ) {
            adsl_node = m_check_usr_msg( &dsl_parser,
                                         ADSL_CUR_VALUE->achc_value,
                                         ADSL_CUR_VALUE->inc_len_value );
            if ( adsl_node != NULL ) {
                dsl_parser.m_get_value( adsl_node,
                                        achg_us_tags[ied_us_tag_usr_msg],
                                        &achl_msg, &inl_length );
                if ( inl_length > 0 ) {
                    if ( dsl_msg.m_get_len() > 0 ) {
                        dsl_msg.m_write( "<br/>" );
                    }
                    dsl_msg.m_write( achl_msg, inl_length );
                }                
            }
            dsl_parser.m_clear();
        }
    }
#undef ADSL_CUR_VALUE

    //-------------------------------------------
    // read own message:
    //-------------------------------------------
    if (    adsp_own                != NULL
         && adsp_own->inc_len_value > 0     ) {
        adsl_node = m_check_usr_msg( &dsl_parser,
                                     adsp_own->achc_value, 
                                     adsp_own->inc_len_value );
        if ( adsl_node != NULL ) {
            dsl_parser.m_get_value( adsl_node,
                                    achg_us_tags[ied_us_tag_usr_msg],
                                    &achl_msg, &inl_length );
            if ( inl_length > 0 ) {
                if ( dsl_msg.m_get_len() > 0 ) {
                    dsl_msg.m_write( "<br/>" );
                }
                dsl_msg.m_write( achl_msg, inl_length );
            }                
        }
    }

    if ( dsl_msg.m_get_len() > 0 ) {
        return adsp_auth->adsc_out_usr->m_set_usr_msg( dsl_msg.m_get_ptr(),
                                                       dsl_msg.m_get_len() );
    }
    return true;
} // end of ds_authenticate::m_import_usr_msg


/**
 * private function ds_authenticate::m_check_usr_msg
 *
 * @param[in]   ds_xml*             adsp_parser     xml parser class
 * @param[in]   const char*         achp_xml        xml data
 * @param[in]   int                 inp_len_xml     length of xml data
 * @return      dsd_xml_tag*                        NULL in error cases
*/
dsd_xml_tag* ds_authenticate::m_check_usr_msg( ds_xml* adsp_parser,
                                               const char* achp_xml,
                                               int inp_len_xml )
{
    // initialize some variables:
    dsd_xml_tag*            adsl_node;              // xml node
    const char*                   achl_name;              // node name
    int                     inl_len_name;           // length of name
    int                     inl_version;            // version number

    adsl_node = adsp_parser->m_from_xml( (char*)achp_xml, inp_len_xml );
    if ( adsl_node == NULL ) {
        return NULL;
    }

    // check name of tag:
    adsp_parser->m_get_node_name( adsl_node, &achl_name, &inl_len_name );
    if (    achl_name == NULL
         || m_equals( ied_us_tag_message, achl_name, inl_len_name ) == false ) {
        return NULL;
    }

    // check version:
    inl_version = adsp_parser->m_read_int( adsl_node,
                                           achg_us_tags[ied_us_tag_version],
                                           0 );
    if ( inl_version != DEF_VERS_USR_MSG ) {
        return NULL;
    }
    return adsl_node;
} // end of ds_authenticate::m_check_usr_msg


/**
 * private function ds_authenticate::m_import_dod
 * save dod workstation for given user in cma
 *
 * @param[in]   dsd_auth_t      *adsp_auth      user information
 * @param[in]   dsd_ldap_val    *adsp_own       ldap xml data
 * @return      bool
*/
bool ds_authenticate::m_import_dod( dsd_auth_t* adsp_auth,
                                    struct dsd_ldap_val *adsp_own )
{
    bool                       bol_ret;                 // return value for func calls
    ds_xml                     dsl_parser;              // xml parser class
    dsd_xml_tag*               adsl_node;               // xml node
    const char*                      achl_name;               // node name
    int                        inl_len_name;            // length of name
    int                        inl_version;             // version number
    ds_workstation             dsl_wstat;               // single workstation
    ds_hvector<ds_workstation> dsl_wstats;              // wstats itself
    
    //-------------------------------------------
    // init variables:
    //-------------------------------------------
    dsl_parser.m_init( adsc_wsp_helper );
    dsl_wstat.m_init ( adsc_wsp_helper );
    dsl_wstats.m_init( adsc_wsp_helper );

    //-------------------------------------------
    // check xml format:
    //-------------------------------------------
    if ( adsp_own->imc_len_val < 1 ) {
        return false;
    }
    adsl_node = dsl_parser.m_from_xml( adsp_own->ac_val, adsp_own->imc_len_val );
    if ( adsl_node == NULL ) {
        return false;
    }

    // check name of tag:
    dsl_parser.m_get_node_name( adsl_node, &achl_name, &inl_len_name );
    if (    achl_name == NULL
         || m_equals( ied_us_tag_dod, achl_name, inl_len_name ) == false ) {
        return false;
    }

    // check version:
    inl_version = dsl_parser.m_read_int( adsl_node,
                                         achg_us_tags[ied_us_tag_version],
                                         0 );
    if ( inl_version != DEF_VERS_USET_DOD ) {
        return false;
    }

    //-------------------------------------------
    // read the data:
    //-------------------------------------------
    adsl_node = adsl_node->ads_child;
    while ( adsl_node != NULL ) {
        // get workstation from xml:
        bol_ret = dsl_wstat.m_from_xml( adsl_node );
        if ( bol_ret == true ) {
            // add it to vector
            dsl_wstats.m_add( dsl_wstat );
        }
        // get next workstation:
        adsl_node = adsl_node->ads_next;
    }

    if ( dsl_wstats.m_empty() == false ) {
        return adsp_auth->adsc_out_usr->m_set_workstations( &dsl_wstats );
    }
    return true;
} // end of ds_authenticate::m_import_dod


/**
 * private function ds_authenticate::m_import_htcp
 * save htcp personal IPs for given user in cma
 *
 * @param[in]   dsd_auth_t      *adsp_auth      user information
 * @param[in]   dsd_ldap_val    *adsp_own       ldap xml data
 * @return      bool
*/
bool ds_authenticate::m_import_htcp( dsd_auth_t *adsp_auth,
                                     struct dsd_ldap_val *adsp_own )
{
    // initialize some variables:
    ds_xml                           dsl_parser;        // xml parser class
    dsd_xml_tag*                     adsl_pnode;        // xml parent node
    dsd_xml_tag*                     adsl_cnode;        // xml child node
    const char*                            achl_name;         // node name
    int                              inl_len_name;      // length of name
    int                              inl_version;       // version number
    ds_hvector_btype<dsd_ineta_temp> dsl_vppp;          // ppp inetas
    ds_hvector_btype<dsd_ineta_temp> dsl_vappl;         // appl inetas
    
    //-------------------------------------------
    // init variables:
    //-------------------------------------------
    dsl_parser.m_init( adsc_wsp_helper );
    dsl_vppp.m_init  ( adsc_wsp_helper );
    dsl_vappl.m_init ( adsc_wsp_helper );

    //-------------------------------------------
    // check xml format:
    //-------------------------------------------
    if ( adsp_own->imc_len_val < 1 ) {
        return false;
    }
    adsl_pnode = dsl_parser.m_from_xml( adsp_own->ac_val, adsp_own->imc_len_val );
    if ( adsl_pnode == NULL ) {
        return false;
    }

    // check name of tag:
    dsl_parser.m_get_node_name( adsl_pnode, &achl_name, &inl_len_name );
    if (    achl_name == NULL
         || m_equals( ied_us_tag_htcp, achl_name, inl_len_name ) == false ) {
        return false;
    }

    // check version:
    inl_version = dsl_parser.m_read_int( adsl_pnode,
                                         achg_us_tags[ied_us_tag_version],
                                         0 );
    if ( inl_version != DEF_VERS_USET_HTCP ) {
        return false;
    }

    //-------------------------------------------
    // read the data:
    //-------------------------------------------
    adsl_pnode = adsl_pnode->ads_child;
    while ( adsl_pnode != NULL ) {
        //---------------------------------------
        // get node name:
        //---------------------------------------
        dsl_parser.m_get_node_name( adsl_pnode, &achl_name, &inl_len_name );
        if ( m_equals( ied_us_tag_tnl_endpoints, achl_name, inl_len_name ) == true ) {
            adsl_cnode = dsl_parser.m_get_firstchild( adsl_pnode );

            while ( adsl_cnode != NULL ) {
                m_read_ineta( adsl_cnode, &dsl_vppp );
                adsl_cnode = dsl_parser.m_get_nextsibling( adsl_cnode );
            }
        } else if ( m_equals( ied_us_tag_applications, achl_name, inl_len_name ) == true ) {
            adsl_cnode = dsl_parser.m_get_firstchild( adsl_pnode );

            while ( adsl_cnode != NULL ) {
                m_read_ineta( adsl_cnode, &dsl_vappl );
                adsl_cnode = dsl_parser.m_get_nextsibling( adsl_cnode );
            }
        }

        //---------------------------------------
        // get next child element
        //---------------------------------------
        adsl_pnode = dsl_parser.m_get_nextsibling( adsl_pnode );
    }

    if (    dsl_vppp.m_empty()  == false
         || dsl_vappl.m_empty() == false ) {
        return adsp_auth->adsc_out_usr->m_import_inetas( &dsl_vppp, &dsl_vappl );
    }
    return true;
} // end of ds_authenticate::m_import_htcp


/**
 * private function ds_authenticate::m_read_ineta
 *
 * @param[in]   ied_us_tags     ien_type    type of node
 * @param[in]   dsd_xml_tag*                parent xml node
*/
void ds_authenticate::m_read_ineta( dsd_xml_tag* ads_pnode,
                                    ds_hvector_btype<dsd_ineta_temp>* ads_out )
{
    // initialize some variables:
    bool                       bol_ret;         // return value
    ds_xml                     dsl_parser;      // xml parser class
    dsd_xml_tag*               adsl_cnode;      // child node
    const char*                      achl_name;       // name of tag
    int                        inl_name;        // length of name
    const char*                      achl_value;      // value of tag
    int                        inl_value;       // length of value
    dsd_ineta_temp             dsl_ineta;       // working ineta variable

    //-------------------------------------------
    // init some classes:
    //-------------------------------------------
    dsl_parser.m_init( adsc_wsp_helper );

    //-------------------------------------------
    // get ineta from xml:
    //-------------------------------------------
    if ( ads_pnode != NULL ) {
        adsl_cnode = dsl_parser.m_get_firstchild( ads_pnode );
    } else {
        return;
    }

    //-------------------------------------------
    // loop through all subnodes
    //-------------------------------------------
    while ( adsl_cnode != NULL ) {
        //---------------------------------------
        // get node name:
        //---------------------------------------
        dsl_parser.m_get_node_name( adsl_cnode, &achl_name, &inl_name );
        if ( m_equals( ied_us_tag_ineta, achl_name, inl_name ) == true ) {
            //-----------------------------------
            // get node value:
            //-----------------------------------
            dsl_parser.m_get_node_value( adsl_cnode, &achl_value, &inl_value );
            if (    achl_value != NULL
                 && inl_value   > 0    ) {
                bol_ret = m_parse_ineta( achl_value, inl_value, &dsl_ineta );
                if ( bol_ret == true ) {
                    ads_out->m_add( dsl_ineta );
                }
            }
        }

        //---------------------------------------
        // get next child element
        //---------------------------------------
        adsl_cnode = dsl_parser.m_get_nextsibling( adsl_cnode );
    }
} // end of ds_authenticate::m_read_ineta


/**
 * private function ds_authenticate::m_import_others
 * save other settings for given user in cma
 *
 * @param[in]   dsd_auth_t      *adsp_auth      user information
 * @param[in]   dsd_ldap_val    *adsp_own       ldap xml data
 * @return      bool
*/
bool ds_authenticate::m_import_others( dsd_auth_t *adsp_auth,
                                       struct dsd_ldap_val *adsp_own )
{
    // initialize some variables:
    bool                       bol_ret;                 // return value for func calls
    int                        inl_ret;                 // return value for func calls
    ds_xml                     dsl_parser;              // xml parser class
    dsd_xml_tag*               adsl_pnode;              // parent xml node
    dsd_xml_tag*               adsl_cnode;              // child xml node
    const char*                      achl_name;               // node name
    int                        inl_len_name;            // length of name
    const char*                      achl_value;              // node value
    int                        inl_len_value;           // length of value
    int                        inl_version;             // version number
    ds_portlet                 dsl_portlet;             // single portlets
    ds_hvector<ds_portlet>     dsl_portlets;            // portlets itself
    dsd_acb_language           dsl_lang;                // language structure
    bool                       bol_flyer;               // language key
    
    //-------------------------------------------
    // init variables:
    //-------------------------------------------
    dsl_parser.m_init  ( adsc_wsp_helper );
    dsl_portlet.m_init ( adsc_wsp_helper );
    dsl_portlets.m_init( adsc_wsp_helper );

    //-------------------------------------------
    // check xml format:
    //-------------------------------------------
    if ( adsp_own->imc_len_val < 1 ) {
        return false;
    }
    adsl_pnode = dsl_parser.m_from_xml( adsp_own->ac_val, adsp_own->imc_len_val );
    if ( adsl_pnode == NULL ) {
        return false;
    }

    // check name of tag:
    dsl_parser.m_get_node_name( adsl_pnode, &achl_name, &inl_len_name );
    if (    achl_name == NULL
         || m_equals( ied_us_tag_usr_sett, achl_name, inl_len_name ) == false ) {
        return false;
    }

    // check version:
    inl_version = dsl_parser.m_read_int( adsl_pnode,
                                         achg_us_tags[ied_us_tag_version],
                                         0 );
    if ( inl_version != DEF_VERS_USET_OTHERS ) {
        return false;
    }

    //-------------------------------------------
    // read the data:
    //-------------------------------------------
    bol_ret = true;
    /*
        portlets settings:
    */
    adsl_cnode = dsl_parser.m_get_value( adsl_pnode,
                                         achg_us_tags[ied_us_tag_portlets],
                                         &achl_value, &inl_len_value );
    if ( adsl_cnode != NULL ) {
        adsl_cnode = adsl_cnode->ads_child;
        while ( adsl_cnode != NULL ) {
            // get portlet from xml:
            bol_ret = dsl_portlet.m_from_xml( adsl_cnode );
            if ( bol_ret == true ) {
                // add it to vector
                dsl_portlets.m_add( dsl_portlet );
            }
            // get next portlet:
            adsl_cnode = adsl_cnode->ads_next;
        }

        if ( dsl_portlets.m_empty() == false ) {
            bol_ret = adsp_auth->adsc_out_usr->m_set_portlets( &dsl_portlets );
        }
    }

    /*
        other settings:
    */
    adsl_cnode = dsl_parser.m_get_value( adsl_pnode,
                                         achg_us_tags[ied_us_tag_others],
                                         &achl_value, &inl_len_value );
    if ( adsl_cnode != NULL ) {
        if ( adsp_auth->amc_callback != NULL ) {
            //-----------------------------------
            // read language:
            //-----------------------------------
            dsl_parser.m_get_value( adsl_cnode,
                                    achg_us_tags[ied_us_tag_lang],
                                    &dsl_lang.achc_lang, &dsl_lang.inc_len_lang );

            if (    dsl_lang.achc_lang    != NULL
                 && dsl_lang.inc_len_lang > 0     ) {
                //-------------------------------
                // parse language:
                //-------------------------------
                inl_ret = adsp_auth->amc_callback( adsp_auth->avc_usrfield,
                                                   DEF_AUTH_CB_PARSE_LANG,
                                                   &dsl_lang, (int)sizeof(dsl_lang) );
                if ( inl_ret == 0 ) {
                    adsp_auth->adsc_out_usr->m_set_lang( dsl_lang.inc_key );
                }
            }
        } // end of if ( adsp_auth->amc_callback != NULL )

        //---------------------------------------
        // read flyer:
        //---------------------------------------
        bol_flyer = dsl_parser.m_read_bool( adsl_cnode,
                                            achg_us_tags[ied_us_tag_flyer],
                                            true );
        adsp_auth->adsc_out_usr->m_set_flyer( bol_flyer );

        // read default portlet (may be NULL)
        dsl_parser.m_get_value( adsl_cnode,
                        achg_us_tags[ied_us_tag_default_portlet],
                        &achl_value, &inl_len_value );
        adsp_auth->adsc_out_usr->m_set_default_portlet( achl_value, inl_len_value );


    }
    return bol_ret;
} // end of ds_authenticate::m_import_others


/**
 * private function ds_authenticate::m_equals
 * check if given string equals known tag name
 *
 * @param[in]   emum ied_us_tags    ien_tag         known tag
 * @param[in]   const char*         ach_compare     string to compare
 * @param[in]   int                 in_len_comp     length of string
 * @return      bool                                true = equals
*/
bool ds_authenticate::m_equals( enum ied_us_tags ien_tag, const char* ach_compare, int in_len_comp )
{
    return achg_us_tags[ien_tag].m_equals(dsd_const_string(ach_compare, in_len_comp));
} // end of ds_authenticate::m_equals


/**
 * private function ds_authenticate::m_get_user_cookies
 * get cookies for given user
 *
 * @param[in]   dsd_auth_t*      ads_auth       pointer to authentication input structure
 * @return      bool
*/
bool ds_authenticate::m_get_user_cookies( dsd_auth_t* ads_auth )
{
    ds_ck_mgmt          dsl_ck_manager;         /* cookie manager class  */
    struct dsd_ldap_val *adsl_cookies;          /* cookies to import     */

    //-------------------------------------------
    // read attribute from ldap:
    //-------------------------------------------
    adsl_cookies = m_get_attribute( dsc_authinfo.dsc_conf.achc_dn,
                                    dsc_authinfo.dsc_conf.inc_len_dn,
                                    DEF_ATTR_USR_COOKIES,
                                    (int)sizeof(DEF_ATTR_USR_COOKIES) - 1 );
    if (    adsl_cookies == NULL
         || adsl_cookies->imc_len_val < 1 ) {
        /* no cookies existing to import */
        return true;
    }

    //-------------------------------------------
    // import cookies:
    //-------------------------------------------
    dsl_ck_manager.m_init( adsc_wsp_helper, false );
    return dsl_ck_manager.m_import_cookies( adsl_cookies->ac_val,
                                            adsl_cookies->imc_len_val,
                                            ads_auth->adsc_out_usr->m_get_basename() );
} // end of ds_authenticate::m_get_user_cookies


/**
 * private function ds_authenticate::m_create_default_tree_rdn
 *  create the default tree rdn in case of Kerberos or Radius
 *  authentication
 *
 * @param[in]   dsd_auth_t          *adsp_auth          login information
 * @param[in]   dsd_domain          *adsp_domain        selected domain config
 * @param[in]   ds_hstring           dsp_config_base    base of user domain
*/
bool ds_authenticate::m_create_default_tree_rdn ( dsd_auth_t *adsp_auth, dsd_domain *adsp_domain, const dsd_const_string& dsp_config_base)
{

    /* initialize some variables */
    bool bol_ret;
    ds_hstring dsl_tmp ( adsc_wsp_helper );
    struct dsd_ldap_attr_desc *adsl_rdn;  /* the exploded dn       */
    struct dsd_co_ldap_1 dsl_ldap;        /* ldap command struct   */

    dsl_tmp.m_writef("cn=%.*s,%.*s,%.*s", adsp_auth->inc_len_user, adsp_auth->achc_user, 
                                          adsp_domain->inc_len_tree_rdn_group, adsp_domain->achc_tree_rdn_group,
                                          (int)dsp_config_base.m_get_len(), dsp_config_base.m_get_ptr());

    adsl_rdn = m_explode_dn ( NULL, dsl_tmp.m_get_ptr(), dsl_tmp.m_get_len());
    /* and now clone the dn into our OpenDS */

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap          = ied_co_ldap_clone_dn;
    dsl_ldap.adsc_attr_desc       = adsl_rdn;
    dsl_ldap.iec_objectclass      = ied_objectclass_person;

    dsl_ldap.ac_attrlist          = (char*)"hoboc,hobphone";
    dsl_ldap.imc_len_attrlist     = (int)sizeof("hoboc,hobphone") - 1;
    dsl_ldap.iec_chs_attrlist     = ied_chs_utf_8;

    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );  
    if (    bol_ret == true
         && dsl_ldap.iec_ldap_resp == ied_ldap_success) { /* user was correctly created, delete the old user entry in the root */
        ds_hstring dsl_old_place_of_storage ( adsc_wsp_helper, 
                                     dsc_authinfo.dsc_conf.achc_dn, 
                                     dsc_authinfo.dsc_conf.inc_len_dn);

        memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
        dsl_ldap.iec_co_ldap    = ied_co_ldap_delete;

        dsl_ldap.iec_chs_dn     = ied_chs_utf_8;
        dsl_ldap.imc_len_dn     = dsl_old_place_of_storage.m_get_len();
        dsl_ldap.ac_dn          = const_cast<char*>(dsl_old_place_of_storage.m_get_ptr());

        bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
		if (    bol_ret == true
             && dsl_ldap.iec_ldap_resp == ied_ldap_success) {
	        return true;
		}
    } 
    if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
        if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
            adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
        }
        else {
            adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
        }
    }
    return false;
    
}

/**
 * private function ds_authenticate::m_create_default_grpoup
 *  create the default group in case of Kerberos or Radius
 *  authentication
 *
 * @param[in]   dsd_domain          *adsp_domain        selected domain config
 * @param[in]   ds_hstring           dsp_config_base    base of user domain
*/
bool ds_authenticate::m_create_default_group ( dsd_domain *adsp_domain, const dsd_const_string& dsp_config_base)
{

    /* initialize some variables */
    bool bol_ret;
    ds_hstring dsl_tmp ( adsc_wsp_helper );
    struct dsd_ldap_attr_desc *adsl_rdn;  /* the exploded dn       */
    struct dsd_co_ldap_1 dsl_ldap;        /* ldap command struct   */

    dsl_tmp.m_writef("cn=%.*s,ou=groups,%.*s", adsp_domain->inc_len_default_group, adsp_domain->achc_default_group,
                                          (int)dsp_config_base.m_get_len(), dsp_config_base.m_get_ptr());

    adsl_rdn = m_explode_dn ( NULL, dsl_tmp.m_get_ptr(), dsl_tmp.m_get_len());
    /* and now clone the dn into our OpenDS */

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap          = ied_co_ldap_clone_dn;
    dsl_ldap.adsc_attr_desc       = adsl_rdn;
    dsl_ldap.iec_objectclass      = ied_objectclass_group;

    dsl_ldap.ac_attrlist          = (char*)"hoboc,hobphone";
    dsl_ldap.imc_len_attrlist     = (int)sizeof("hoboc,hobphone") - 1;
    dsl_ldap.iec_chs_attrlist     = ied_chs_utf_8;

    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );  
    if (( bol_ret == false ) || ( dsl_ldap.iec_ldap_resp != ied_ldap_success)) {
		if (( bol_ret != false ) && (dsl_ldap.ac_errmsg != NULL) ){
			if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
			}
			else {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
			}
		}
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                             "HAUTHE213E cannot create group '%.*s' in config ldap",
                             adsp_domain->inc_len_default_group,
                             adsp_domain->achc_default_group );
    }
    return bol_ret;
}

/**
 * private function ds_authenticate::m_set_domainadmin_group
 *  creates the domainadmin group and sets the attributes for this group
 *
 * @param[in]   ds_hstring           dsp_config_base    base of user domain
*/
void ds_authenticate::m_set_domainadmin_group ( const dsd_const_string& dsp_config_base )
{

    /* initialize some variable */

    struct dsd_co_ldap_1 dsl_ldap;                                  /* ldap command struct                          */
    struct dsd_ldap_attr_desc  *adsl_rdn;                           /* the exploded dn                              */
    ds_hstring dsl_aci         (adsc_wsp_helper, "aci");            /* attribute aci                                */
    ds_hstring dsl_domadmin    (adsc_wsp_helper);                   /* domainAdministrators group                   */ 
    ds_hstring dsl_value_aci   (adsc_wsp_helper);
    ds_hstring dsl_complete_dn ( adsc_wsp_helper, dsc_authinfo.dsc_conf.achc_basedn,
                                 dsc_authinfo.dsc_conf.inc_len_basedn);
    /* first aci */
    dsl_value_aci.m_writef( "(targetattr=\"*\")(version 3.0; acl \"domainAdministrators\"; allow(all) groupdn=\"ldap:///cn=domainAdministrators,ou=groups,%.*s\";)", 
                             (int)dsp_config_base.m_get_len(), dsp_config_base.m_get_ptr()  );

    m_set_attribute( dsp_config_base.m_get_ptr(), dsp_config_base.m_get_len(), 
                     dsl_aci.m_get_ptr(), dsl_aci.m_get_len(), 
                     dsl_value_aci.m_get_ptr(), dsl_value_aci.m_get_len() );

    /* second aci */
    dsl_value_aci.m_reset();
    dsl_value_aci.m_writef( "(targetattr=\"*\")(version 3.0; acl \"restrictAccess\"; deny(all) userdn!=\"ldap:///%.*s??sub?\" and  groupdn!=\"ldap:///cn=globalAdministrators,ou=groups,dc=internal,dc=root\" and userdn!=\"ldap:/// cn=WebSecureProxy,ou=servers,dc=internal,dc=root\" and userdn!=\"ldap:///self\";)",
                             (int)dsp_config_base.m_get_len(), dsp_config_base.m_get_ptr()  );

    m_set_attribute( dsp_config_base.m_get_ptr(), dsp_config_base.m_get_len(), 
                     dsl_aci.m_get_ptr(), dsl_aci.m_get_len(), 
                     dsl_value_aci.m_get_ptr(), dsl_value_aci.m_get_len() );

    /* write the domainAdministrator group */
    dsl_domadmin.m_writef("cn=domainAdministrators,ou=groups,%.*s", dsp_config_base.m_get_len(), dsp_config_base.m_get_ptr());
    adsl_rdn = m_explode_dn( NULL, dsl_domadmin.m_get_ptr(), dsl_domadmin.m_get_len() );

    /* and now clone the dn into our OpenDS */

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap          = ied_co_ldap_clone_dn;
    dsl_ldap.adsc_attr_desc       = adsl_rdn;
    dsl_ldap.iec_objectclass      = ied_objectclass_group;
    
    dsl_ldap.ac_attrlist          = (char*)"hoboc,hobphone";
    dsl_ldap.imc_len_attrlist     = (int)sizeof("hoboc,hobphone") - 1;
    dsl_ldap.iec_chs_attrlist     = ied_chs_utf_8;

    bool bol_ret;
    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );                               
    if (( bol_ret == false ) || ( dsl_ldap.iec_ldap_resp != ied_ldap_success)) {
		if (( bol_ret != false ) && (dsl_ldap.ac_errmsg != NULL)) {
			if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
			}
			else {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
			}
		}
	}
    /* end of cloning */
                    
}
/**
 * private function ds_authenticate::m_switch_ldap
 *  select which ldap is used for role selection and configuration
 *  bind to new ldap
 *  auto create user(and group) entries if needed
 *
 * @param[in]   dsd_auth_t          *adsp_auth          login information
 * @param[in]   dsd_domain          *adsp_domain        selected domain config
 * @param[in]   int                 inp_domain_auth     selected method type
 * @param[in]   int                 inp_wsp_auth        configured auth methods
 * @return      bool
*/
bool ds_authenticate::m_switch_ldap( dsd_auth_t *adsp_auth,
                                     struct dsd_domain *adsp_domain,
                                     int inp_domain_auth, int inp_wsp_auth )
{
    // initialize some variables:
    bool                 bol_ret;               /* return from sev funcs */
    char                 *achl_user;            /* found user name       */
    int                  inl_len_user;          /* length of user name   */
    int                  inl_ldap_type;          /* the ldap server type  */
    bool                 bol_create_user;       /* create user also?     */
    bool                 bol_usr_changed_dn = false; /* was DN of user changed? */
    struct dsd_co_ldap_1 dsl_ldap;              /* ldap command struct   */
    struct dsd_co_ldap_1 dsl_ldap_tmp;
    struct dsd_co_ldap_1 dsl_ldap_request;

    if ( adsp_domain == NULL ) {
        return true; // ? what will we do if we have no valid config?
    }

    /*
        get auth ldap info in case of kickout
    */
    if (    (   inp_domain_auth  == DEF_CLIB1_CONF_LDAP
              || inp_domain_auth == DEF_CLIB1_CONF_DYN_LDAP )
         && dsc_authinfo.dsc_auth.boc_filled == FALSE
#if SM_USE_CERT_AUTH
         && adsp_auth->iec_certificate_auth != iec_cert_auth_result_authenticated
#endif
         )
    {

        //AKRE mustn? we call select ldap server?
        /*bol_ret = adsc_wsp_helper->m_cb_set_ldap_srv( inc_sel_srv );
            if ( bol_ret == false ) {
            adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                    "HAUTHW109W select dynamic ldap server failed" );
            return (AUTH_METH_DYN_LDAP | AUTH_FAILED | AUTH_ERR_DYN_SEL);
        }*/
        //END AKRE
        memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
        dsl_ldap.iec_co_ldap = ied_co_ldap_get_sysinfo;
        bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
        if (    bol_ret                == true
             && dsl_ldap.iec_ldap_resp == ied_ldap_success
             && dsl_ldap.adsc_sysinfo  != NULL             ) {
            dsc_authinfo.dsc_auth.adsc_lconf  = dsl_ldap.adsc_sysinfo->adsc_ldap_template;
			/* AKre: use  "adsc_base_dn_def" instead of adsc_base_dn*/
			if ( dsl_ldap.adsc_sysinfo->adsc_base_dn_def != NULL ) { 
				dsc_authinfo.dsc_auth.achc_basedn    = dsl_ldap.adsc_sysinfo->adsc_base_dn_def->ac_val;
				dsc_authinfo.dsc_auth.inc_len_basedn = dsl_ldap.adsc_sysinfo->adsc_base_dn_def->imc_len_val;
			} else { /* take configured base */
				dsc_authinfo.dsc_auth.achc_basedn    = dsl_ldap.adsc_sysinfo->adsc_base_dn_conf->ac_val;
				dsc_authinfo.dsc_auth.inc_len_basedn = dsl_ldap.adsc_sysinfo->adsc_base_dn_conf->imc_len_val;
			}
		} else {
			if (( bol_ret != false ) && (dsl_ldap.ac_errmsg != NULL)) {
				if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
					adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
				}
				else {
					adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
				}
			}
		}

        memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
        dsl_ldap.iec_co_ldap      = ied_co_ldap_bind;
        dsl_ldap.ac_userid        = const_cast<char*>(adsp_auth->achc_user);
        dsl_ldap.imc_len_userid   = adsp_auth->inc_len_user;
        dsl_ldap.iec_chs_userid   = ied_chs_utf_8;
        if (    adsp_domain                  != NULL
             && adsp_domain->boc_search_base == true ) {
            dsl_ldap.dsc_add_dn.ac_str      = adsp_domain->achc_base;
            dsl_ldap.dsc_add_dn.imc_len_str = adsp_domain->inc_len_base;
            dsl_ldap.dsc_add_dn.iec_chs_str = ied_chs_utf_8;
        }
        dsl_ldap.ac_passwd      = const_cast<char*>(adsp_auth->achc_password);
        dsl_ldap.imc_len_passwd = adsp_auth->inc_len_password;
        dsl_ldap.iec_chs_passwd = ied_chs_utf_8;
        dsl_ldap.iec_ldap_auth  = ied_auth_user;
        bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
        if (    bol_ret                == true
             && dsl_ldap.iec_ldap_resp == ied_ldap_success ) {
            m_save_ldap_info( &dsl_ldap );
		} else {
			if (( bol_ret != false ) && (dsl_ldap.ac_errmsg != NULL)) {
				if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
					adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
				}
				else {
					adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
				}
			}
		}
    }

    if (    dsc_authinfo.dsc_auth.boc_filled != FALSE
         && adsp_domain->boc_ldap_eq_name    != false ) {
        dsc_authinfo.dsc_conf.adsc_lconf     = dsc_authinfo.dsc_auth.adsc_lconf;
        dsc_authinfo.dsc_conf.achc_basedn    = dsc_authinfo.dsc_auth.achc_basedn;
        dsc_authinfo.dsc_conf.inc_len_basedn = dsc_authinfo.dsc_auth.inc_len_basedn;
        dsc_authinfo.dsc_conf.achc_dn        = dsc_authinfo.dsc_auth.achc_dn;
        dsc_authinfo.dsc_conf.inc_len_dn     = dsc_authinfo.dsc_auth.inc_len_dn;
        dsc_authinfo.dsc_conf.inc_groups     = dsc_authinfo.dsc_auth.inc_groups;
        dsc_authinfo.dsc_conf.adsc_group_dns = dsc_authinfo.dsc_auth.adsc_group_dns;

        dsc_authinfo.dsc_conf.adsc_tree_dns  = m_get_tree_dns( &dsc_authinfo.dsc_stor,
                                                               dsc_authinfo.dsc_conf.achc_dn,
                                                               dsc_authinfo.dsc_conf.inc_len_dn,
                                                               &dsc_authinfo.dsc_conf.inc_tree );
        return true;
    }

    /* init storage container if not existing yet */
    if ( dsc_authinfo.dsc_auth.boc_filled == FALSE ) {
        bol_ret = adsc_wsp_helper->m_new_storage_cont( &dsc_authinfo.dsc_stor, 2048 );
        if ( bol_ret == false ) {
            adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                     "HAUTHE204E cannot create new storage container" );                                 
            return false;
        }
    }

    /*
        select configuration ldap by domain, bind to it and get sysinfo
    */
    bol_ret = m_select_ldap( adsp_domain, inp_domain_auth, inp_wsp_auth );
    if ( bol_ret == false ) {
        return false;
    }
    bol_ret = m_bind_conf_ldap( adsp_domain );
    if ( bol_ret == false ) {
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HAUTHE205E bind to configuration ldap failed" );
        return false;
    }
    bol_ret = m_get_conf_sysinfo();
    if ( bol_ret == false ) {
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HAUTHE206E cannot get sysinfo from configuration ldap" );
        return false;
    }


    if ( dsc_authinfo.dsc_auth.boc_filled != FALSE ) {
        /*
            we have a different authentication and configuration ldap
             -> search if user already exists in conf ldap
             -> clone him and his groups if not already there
        */
        bol_create_user = true;
        ds_hstring dsl_org_user_conf_dn;

        /* search if user is already existing */
        if ( dsc_authinfo.dsc_auth.inc_len_osid > 0 ) {
            /* search user by sid */
            bol_ret = m_search_by_sid( &dsc_authinfo.dsc_stor,
                                       dsc_authinfo.dsc_auth.achc_osid,
                                       dsc_authinfo.dsc_auth.inc_len_osid,
                                       (char**)&dsc_authinfo.dsc_conf.achc_dn,
                                       &dsc_authinfo.dsc_conf.inc_len_dn,
                                       &achl_user, &inl_len_user,
                                       adsp_domain );

            
            dsl_org_user_conf_dn.m_write( dsc_authinfo.dsc_conf.achc_dn, dsc_authinfo.dsc_conf.inc_len_dn);

            if ( bol_ret == true ) {
				dsd_const_string dsl_auth_userdn(dsc_authinfo.dsc_auth.achc_dn, dsc_authinfo.dsc_auth.inc_len_dn - dsc_authinfo.dsc_auth.inc_len_basedn);
                dsd_const_string dsl_conf_dn(dsc_authinfo.dsc_conf.achc_dn, dsc_authinfo.dsc_conf.inc_len_dn);
				dsd_const_string dsl_conf_userdn(dsc_authinfo.dsc_conf.achc_dn, 
					                             dsc_authinfo.dsc_conf.inc_len_dn - 
												 dsc_authinfo.dsc_conf.inc_len_basedn - adsp_domain->inc_len_name - sizeof(",dc=") + 1);
                //bol_create_user = false;

                /* inception AKre 07.02.2013 */
                /* we have to check if the dn of the user was changed in the auth ldap 
                 *
                 * if yes:
                 * -> create user in conf ldap again with new group dn
                 * -> copy the whole config from the old to new user
                 * -> delete old user and delete his membership from groups
                 *
                 */

                //bol_usr_changed_dn = true;
                /* user has changed dn  
                 *  -> clone user
                 *  -> get ldap attributes
                 *  -> clone attributes
                 *  -> delete old dn from conf ldap
                 */

                /* clone user and save his dn in conf ldap */
                bol_ret = m_clone_dn( &dsc_authinfo.dsc_stor, 
                                      dsc_authinfo.dsc_auth.adsc_dn,
                                      ied_objectclass_person,
                                      (char**)&dsc_authinfo.dsc_conf.achc_dn,
                                      &dsc_authinfo.dsc_conf.inc_len_dn,
                                      adsp_domain );

                dsd_const_string dsl_new_conf_dn(dsc_authinfo.dsc_conf.achc_dn, 
                                             dsc_authinfo.dsc_conf.inc_len_dn);
				/* Does user already exist? */
                if ( !dsl_auth_userdn.m_equals_ic(dsl_conf_userdn) ) {
					 /*
						DNs are not euqual ==> user DN in auth was changed!
					 */

					bol_usr_changed_dn = true;

					/* delete dn */
					memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
					dsl_ldap.iec_co_ldap    = ied_co_ldap_delete;

					dsl_ldap.iec_chs_dn     = ied_chs_utf_8;
					dsl_ldap.imc_len_dn     = dsl_new_conf_dn.m_get_len();
					dsl_ldap.ac_dn          = const_cast<char*>(dsl_new_conf_dn.m_get_ptr());
                    
					bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
					if (( bol_ret == false ) || ( dsl_ldap.iec_ldap_resp != ied_ldap_success)) {
						if (( bol_ret != false ) && (dsl_ldap.ac_errmsg != NULL)) {
							if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
								adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
							}
							else {
								adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
							}
						}
					}
				}
                /* modify dn */
                memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );

                dsl_ldap.iec_co_ldap = ied_co_ldap_modify_dn;

                dsl_ldap.iec_chs_dn  = ied_chs_utf_8;
				dsl_ldap.imc_len_dn  = dsl_conf_dn.m_get_len();
				dsl_ldap.ac_dn       = const_cast<char*>(dsl_conf_dn.m_get_ptr());

                dsl_ldap.iec_chs_newrdn = ied_chs_utf_8;
                dsl_ldap.imc_len_newrdn = dsl_new_conf_dn.m_get_len();
                dsl_ldap.ac_newrdn      = const_cast<char*>(dsl_new_conf_dn.m_get_ptr());

                bol_ret = adsc_wsp_helper->m_cb_ldap_request ( &dsl_ldap );

                if (( bol_ret == false ) || ( dsl_ldap.iec_ldap_resp != ied_ldap_success)) {
					if (( bol_ret != false ) && (dsl_ldap.ac_errmsg != NULL)) {
						if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
							adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
						}
						else {
							adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
						}
					}
                    adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                             "HAUTHE279W cannot modify dn '%.*s'",
                                             dsc_authinfo.dsc_conf.inc_len_dn,
                                             dsc_authinfo.dsc_conf.achc_dn );
                }

                /* end AKre */
            }
        } else {
            /* search user by name */
            bol_ret = m_search_user( &dsc_authinfo.dsc_stor,
                                     adsp_auth->achc_user, adsp_auth->inc_len_user,
                                     (char**)&dsc_authinfo.dsc_conf.achc_dn,
                                     &dsc_authinfo.dsc_conf.inc_len_dn,
                                     adsp_domain );
            if ( bol_ret == true ) {
                /*
                    user already exists in conf ldap
                     -> user doesn't need to be recreated!
                     -> create his groups if allowed!
                */
                bol_create_user = false;
            }
        }


        /* create user and his groups if allowed */
        if ( adsp_domain->boc_create_users != false ) {
        
            /* get the ldap type */
            bool bol_ldap_srv;
			memset( &dsl_ldap_request, 0, sizeof(struct dsd_co_ldap_1) );
            dsl_ldap_request.iec_co_ldap = ied_co_ldap_get_sysinfo;
            bol_ldap_srv                 = adsc_wsp_helper->m_cb_ldap_request(&dsl_ldap_request);
			if ( (bol_ldap_srv != false ) && ( dsl_ldap_request.iec_ldap_resp != ied_ldap_success ) && (dsl_ldap_request.ac_errmsg != NULL)) {
				if (dsl_ldap_request.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
					adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap_request.ac_errmsg);
				}
				else {
					adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap_request.imc_len_errmsg, dsl_ldap_request.ac_errmsg);
				}
				bol_ldap_srv = FALSE;
			}
            inl_ldap_type                = dsl_ldap_request.adsc_sysinfo->iec_type;

            if ( bol_create_user == true ) {

                /* inception AKre 09.10.2012
                 *
                 * If the User DN Prefix is not 'cn' then we have to switch
                 * this into 'cn' because this is the way we want to store it
                 * in our LDAP OpenDJ
                 *
                 */

                BOOL bol_switched_cn     = FALSE;
                ds_hstring dsl_old_uid(adsc_wsp_helper, dsc_authinfo.dsc_auth.adsc_dn->ac_dn, dsc_authinfo.dsc_auth.adsc_dn->imc_len_dn);
                ds_hstring dsl_new_cn (adsc_wsp_helper);
                    
                if ( (inl_ldap_type == ied_sys_ldap_opendj || 
                      inl_ldap_type == ied_sys_ldap_opends ) &&
                      bol_ldap_srv  == true) {
                    if ( !dsl_old_uid.m_starts_with("cn=") ) {
						// TODO: Is this working in all cases!!!
                        int inl_return = dsl_old_uid.m_search("=");
                        dsl_new_cn     = "cn";
                        dsl_new_cn     += dsl_old_uid.m_substring(inl_return);
                        int inl_pos = dsl_new_cn.m_find_first_of(",");
                        if(inl_pos < 0)
                            inl_pos = dsl_new_cn.m_get_len();

                        /*dsl_new_cn = dsl_old_uid;
                        dsl_new_cn.m_replace("uid=", "cn=", false, 0);*/

                        dsc_authinfo.dsc_auth.adsc_dn->ac_dn      = NULL;
                        dsc_authinfo.dsc_auth.adsc_dn->ac_dn      = const_cast<char*>(dsl_new_cn.m_get_ptr());
                        dsc_authinfo.dsc_auth.adsc_dn->imc_len_dn = inl_pos;

                        bol_switched_cn = TRUE;
                    }
                }
                /* end AKre 09.10.2012 */

                /* clone user and save his dn in conf ldap */
                bol_ret = m_clone_dn( &dsc_authinfo.dsc_stor, 
                                      dsc_authinfo.dsc_auth.adsc_dn,
                                      ied_objectclass_person,
                                      (char**)&dsc_authinfo.dsc_conf.achc_dn,
                                      &dsc_authinfo.dsc_conf.inc_len_dn,
                                      adsp_domain );
                if ( bol_ret == false ) {
                    adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                             "HAUTHE207E cannot clone dn '%.*s'",
                                             dsc_authinfo.dsc_auth.inc_len_dn,
                                             dsc_authinfo.dsc_auth.achc_dn );
                    return false;
                }
                /* Inception AKre 09.10.12 
                 *
                 * firstly we create the aci for our domain
                 * secondly we create a "domainAdministrators" group (explode and clone)
                 *
                 */

                if ( (inl_ldap_type == ied_sys_ldap_opendj   || 
                      inl_ldap_type == ied_sys_ldap_opends ) &&
                      bol_ldap_srv  == true ) {

                    dsd_const_string dsl_tmp(dsc_authinfo.dsc_conf.achc_dn, dsc_authinfo.dsc_conf.inc_len_dn);            

                    /* complete dn of the user */
                    dsd_const_string dsl_complete_dn = dsl_tmp;
                    while ( !dsl_complete_dn.m_starts_with("dc=") ) {
                        int inl_dc      = dsl_complete_dn.m_index_of(",");
                        if(inl_dc < 0)
                            break;
                        dsl_complete_dn = dsl_complete_dn.m_substring( inl_dc + 1 );
                    }
                    
                    /* get the configured base */
                    /*if ( adsp_domain->achc_base != NULL ) {
                        dsl_config_base.m_writef("%.*s,%.*s", adsp_domain->inc_len_base, adsp_domain->achc_base,
                                                              dsc_authinfo.dsc_auth.inc_len_basedn, dsc_authinfo.dsc_auth.achc_basedn);
                    } else {*/
                    /* the configured base in the xml               */
                    //}

                    if ( !dsl_complete_dn.m_equals( dsl_tmp ) ) { /* otherwise the user is direct under the root 
                                                                        * and we shouldn? write on the root */
                        m_set_domainadmin_group ( dsl_complete_dn );
                    }
                 
                /*  
                 * after we switched from e.g. 'uid' to 'cn', we have to revert this
                 * because otherwise possible groups couldn? be cloned anymore
                 */
                    if ( bol_switched_cn == TRUE ) {
                    dsc_authinfo.dsc_auth.adsc_dn->ac_dn      = NULL;
                    dsc_authinfo.dsc_auth.adsc_dn->ac_dn      = const_cast<char*>(dsl_old_uid.m_get_ptr());
                    dsc_authinfo.dsc_auth.adsc_dn->imc_len_dn = dsl_old_uid.m_find_first_of(",");
                    bol_switched_cn = FALSE;
                    }
                }
                /* end AKre 09.10.12 */

                /* save objectsid */
                if ( dsc_authinfo.dsc_auth.inc_len_osid > 0 ) {
                    bol_ret = m_set_attribute( dsc_authinfo.dsc_conf.achc_dn,
                                               dsc_authinfo.dsc_conf.inc_len_dn,
                                               "hobsid", sizeof("hobsid") - 1,
                                               dsc_authinfo.dsc_auth.achc_osid,
                                               dsc_authinfo.dsc_auth.inc_len_osid );
                    if ( bol_ret == false ) {
                        adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                                 "HAUTHW022W cannot save hobsid for '%.*s'",
                                                 dsc_authinfo.dsc_conf.inc_len_dn,
                                                 dsc_authinfo.dsc_conf.achc_dn );
                        /* this is not a bad error! */
                    }
                }
            }
            /*
             * AKre 20.11.2012
             *
             * If extern auth ldap and config ldap is opends/opendj
             * we have to use the groupmembership of our extern ldap
             * so delete all current memeberships in config ldap
             * and create the membership configuration of extern ldap
             *
            */
            if ( (inl_ldap_type == ied_sys_ldap_opendj   || 
                      inl_ldap_type == ied_sys_ldap_opends ) &&
                      bol_ldap_srv  == true ) {

                struct dsd_co_ldap_1 dsl_membership;
                ds_hstring dsl_uniqemember (adsc_wsp_helper, "uniqueMember");

                ds_hstring dsl_user_dn;
                if ( bol_usr_changed_dn == true ) {
                    dsl_user_dn.m_write( dsl_org_user_conf_dn.m_get_ptr(), dsl_org_user_conf_dn.m_get_len() );
                } else {
                    dsl_user_dn.m_write( dsc_authinfo.dsc_conf.achc_dn, dsc_authinfo.dsc_conf.inc_len_dn );
                }
                /* get the membership of the logged user from config */

				memset( &dsl_membership, 0, sizeof(struct dsd_co_ldap_1) );
                dsl_membership.iec_co_ldap    = ied_co_ldap_get_membership;
                dsl_membership.iec_chs_dn     = ied_chs_utf_8;
                dsl_membership.imc_len_dn     = dsl_user_dn.m_get_len();
                dsl_membership.ac_dn          = const_cast<char*>(dsl_user_dn.m_get_ptr());
                dsl_membership.iec_sear_scope = ied_sear_basedn;
                bol_ret = adsc_wsp_helper->m_cb_ldap_request(&dsl_membership);  // TODO: initialize
				if ( (bol_ret != false ) && ( dsl_membership.iec_ldap_resp != ied_ldap_success ) 
					&& ( dsl_membership.iec_ldap_resp != ied_ldap_no_results ) 
					&& (dsl_membership.ac_errmsg != NULL) ) {
					if (dsl_membership.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
						adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_membership.ac_errmsg);
					}
					else {
						adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_membership.imc_len_errmsg, dsl_membership.ac_errmsg);
					}
				}

				// TODO: This can be optimized, now all groups are "unlinked" and added later on again
				// maybe we could only maintain the changes (add/remove 1 or more groups)
                ds_hvector<ds_hstring> adsl_v_groups;
                adsl_v_groups.m_init( adsc_wsp_helper );

                while ( dsl_membership.adsc_memship_desc != NULL ) {

                    ds_hstring dsl_group_dn (adsc_wsp_helper, dsl_membership.adsc_memship_desc->ac_val, 
                                               dsl_membership.adsc_memship_desc->imc_len_val );

                    adsl_v_groups.m_add( dsl_group_dn );

                    dsl_membership.adsc_memship_desc = dsl_membership.adsc_memship_desc->adsc_next_val;
                }
                for ( HVECTOR_FOREACH(ds_hstring, adsl_cur, adsl_v_groups) ) {
                    const ds_hstring& dsl_cur = HVECTOR_GET(adsl_cur);
                    m_del_attribute( dsl_cur.m_get_ptr(), dsl_cur.m_get_len(),
                                                   dsl_uniqemember.m_get_ptr(), dsl_uniqemember.m_get_len(),
                                                   dsl_user_dn.m_get_ptr(), dsl_user_dn.m_get_len() );
        
                }
            }

            /*
                clone all groups of user
                 -> we are just cloning (without any check), cause the
                    ldap modul will check existence of groups itself
            */
            dsc_authinfo.dsc_conf.adsc_group_dns = m_clone_groups( &dsc_authinfo.dsc_stor,
                                                                   dsc_authinfo.dsc_auth.inc_groups,
                                                                   dsc_authinfo.dsc_auth.adsc_groups,
                                                                   dsc_authinfo.dsc_auth.adsc_group_dns,
                                                                   &dsc_authinfo.dsc_conf.inc_groups,
                                                                   adsp_domain );
        }

    } else {
        /*
            we have another authentication method (krb5, radius, userlist)
            and configuration ldap
             -> search if user already exists in conf ldap
             -> create him if not already there
        */
        bol_ret = m_search_user( &dsc_authinfo.dsc_stor,
                                 adsp_auth->achc_user, adsp_auth->inc_len_user,
                                 (char**)&dsc_authinfo.dsc_conf.achc_dn,
                                 &dsc_authinfo.dsc_conf.inc_len_dn,
                                 adsp_domain );
        if ( bol_ret == true ) {
            /*
                user already exists in our configuration ldap
                -> get all his groups
            */
#ifdef SH_NESTED_GROUPS
            dsc_authinfo.dsc_conf.adsc_group_dns = m_search_groups( &dsc_authinfo.dsc_stor, adsp_domain,
                                                                    dsc_authinfo.dsc_conf.adsc_lconf,
                                                                    dsc_authinfo.dsc_conf.achc_dn,
                                                                    dsc_authinfo.dsc_conf.inc_len_dn,
                                                                    dsc_authinfo.dsc_conf.achc_basedn,
                                                                    dsc_authinfo.dsc_conf.inc_len_basedn,
                                                                    &dsc_authinfo.dsc_conf.inc_groups,
																	NULL, 0);
#else
            dsc_authinfo.dsc_conf.adsc_group_dns = m_search_groups( &dsc_authinfo.dsc_stor, adsp_domain,
                                                                    dsc_authinfo.dsc_conf.adsc_lconf,
                                                                    dsc_authinfo.dsc_conf.achc_dn,
                                                                    dsc_authinfo.dsc_conf.inc_len_dn,
                                                                    dsc_authinfo.dsc_conf.achc_basedn,
                                                                    dsc_authinfo.dsc_conf.inc_len_basedn,
                                                                    &dsc_authinfo.dsc_conf.inc_groups );
#endif
            /*
                it is superflous to create some groups in this case,
                cause we are getting the groups from conf ldap!
            */
        } else {
            /*
                user does not exist in our configuration ldap
                 -> clone him
                 -> get his groups (there might be some already existing)
            */

            bol_ret = m_clone_ext_user( &dsc_authinfo.dsc_stor,
                                        adsp_auth->achc_user, adsp_auth->inc_len_user,
                                        (char**)&dsc_authinfo.dsc_conf.achc_dn,
                                        &dsc_authinfo.dsc_conf.inc_len_dn,
                                        adsp_domain );
            if ( bol_ret == false ) {
                adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                         "HAUTHE208E cannot create user '%.*s' in config ldap",
                                         adsp_auth->inc_len_user,
                                         adsp_auth->achc_user );
                return false;
            }
            /* Inception AKre 09.10.12 
             *
             * firstly we create the aci for our domain
             * secondly we create a "domainAdministrators" group (explode and clone)
             *
             */

            /* get the ldap type */
            bool bol_ldap_serv;
			memset( &dsl_ldap_tmp, 0, sizeof(struct dsd_co_ldap_1) );
            dsl_ldap_tmp.iec_co_ldap = ied_co_ldap_get_sysinfo;
            bol_ldap_serv            = adsc_wsp_helper->m_cb_ldap_request(&dsl_ldap_tmp);
			if ( (bol_ldap_serv != false ) && ( dsl_ldap_tmp.iec_ldap_resp != ied_ldap_success ) && (dsl_ldap_tmp.ac_errmsg != NULL) ) {
				if (dsl_ldap_tmp.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
					adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap_tmp.ac_errmsg);
				}
				else {
					adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap_tmp.imc_len_errmsg, dsl_ldap_tmp.ac_errmsg);
				}
			}
            inl_ldap_type            = dsl_ldap_tmp.adsc_sysinfo->iec_type;
            if ( ( bol_ldap_serv  == true )                &&
				 ( dsl_ldap_tmp.iec_ldap_resp == ied_ldap_success ) &&
				 ( inl_ldap_type  == ied_sys_ldap_opendj   || 
                   inl_ldap_type  == ied_sys_ldap_opends ) &&
                 ( adsp_domain->boc_create_users == true )    ) {

                const dsd_const_string dsl_complete_dn(dsc_authinfo.dsc_conf.achc_dn, dsc_authinfo.dsc_conf.inc_len_dn);
                dsd_const_string dsl_dn(dsl_complete_dn);
                while ( !dsl_dn.m_starts_with("dc=") ) {
                    int inl_dc = dsl_dn.m_index_of(",");
                    if(inl_dc < 0)
                        break;
                    dsl_dn = dsl_dn.m_substring( inl_dc + 1 );
                }
                
                /* get the configured base */
                /*if ( adsp_domain->achc_base != NULL ) {
                    dsl_config_base.m_writef("%.*s,%.*s", adsp_domain->inc_len_base, adsp_domain->achc_base,
                                                          dsc_authinfo.dsc_auth.inc_len_basedn, dsc_authinfo.dsc_auth.achc_basedn);
                } else {*/
                /* the configured base in the xml               */
                //}
            
                //19.11.2013 
                   /* create user in default-tree-rdn, if we have no success, then create user in root 
                      if default-tree-rdn does not exist, user was already created */
                bool bol_user_in_default = false;
                if ( adsp_domain->inc_len_tree_rdn_group > 0 ) {
                    
                    bol_user_in_default = m_create_default_tree_rdn ( adsp_auth, adsp_domain, dsl_dn);
                }

                //end 19.11.2013


                if ( !dsl_dn.m_equals(dsl_complete_dn) ) { /* otherwise the user is direct under the root 
                                                                    * and we shouldn? write on the root */
                    m_set_domainadmin_group ( dsl_dn );
                }
                
                /* 20.11.2013 
                   create default group into our internal ldap*/
                if ( adsp_domain->inc_len_default_group > 0 ) { //we have an entry for the default group
                    m_create_default_group ( adsp_domain, dsl_dn);
                    /* add user to this created group*/
                    ds_hstring dsl_group_dn(adsc_wsp_helper);
                    ds_hstring dsl_user_dn (adsc_wsp_helper);

                    dsl_group_dn.m_writef("cn=%.*s,ou=groups,%.*s", adsp_domain->inc_len_default_group, adsp_domain->achc_default_group,
                                          dsl_dn.m_get_len(), dsl_dn.m_get_ptr());
                    if ( bol_user_in_default ) {
                        dsl_user_dn.m_writef("cn=%.*s,%.*s,%.*s", adsp_auth->inc_len_user, adsp_auth->achc_user, 
                                          adsp_domain->inc_len_tree_rdn_group, adsp_domain->achc_tree_rdn_group,
                                          dsl_dn.m_get_len(), dsl_dn.m_get_ptr());
                    } else {
                        dsl_user_dn.m_write( dsc_authinfo.dsc_conf.achc_dn, dsc_authinfo.dsc_conf.inc_len_dn );
                    }
                    m_add_member( dsl_user_dn.m_get_ptr(),
                                  dsl_user_dn.m_get_len(),
                                  dsl_group_dn.m_get_ptr(), dsl_group_dn.m_get_len(),
                                  dsc_authinfo.dsc_conf.adsc_lconf->achc_member_attr,
                                  dsc_authinfo.dsc_conf.adsc_lconf->imc_len_member_attr);
                }
                /* 20.11.2013 */
            }
            /* end AKre 09.10.12 */

#ifdef SH_NESTED_GROUPS
            dsc_authinfo.dsc_conf.adsc_group_dns = m_search_groups( &dsc_authinfo.dsc_stor, adsp_domain,
                                                                    dsc_authinfo.dsc_conf.adsc_lconf,
                                                                    dsc_authinfo.dsc_conf.achc_dn,
                                                                    dsc_authinfo.dsc_conf.inc_len_dn,
                                                                    dsc_authinfo.dsc_conf.achc_basedn,
                                                                    dsc_authinfo.dsc_conf.inc_len_basedn,
                                                                    &dsc_authinfo.dsc_conf.inc_groups,
																	NULL, 0);
#else
            dsc_authinfo.dsc_conf.adsc_group_dns = m_search_groups( &dsc_authinfo.dsc_stor, adsp_domain,
                                                                    dsc_authinfo.dsc_conf.adsc_lconf,
                                                                    dsc_authinfo.dsc_conf.achc_dn,
                                                                    dsc_authinfo.dsc_conf.inc_len_dn,
                                                                    dsc_authinfo.dsc_conf.achc_basedn,
                                                                    dsc_authinfo.dsc_conf.inc_len_basedn,
                                                                    &dsc_authinfo.dsc_conf.inc_groups );
#endif
        }
    }

    dsc_authinfo.dsc_conf.adsc_tree_dns = m_get_tree_dns( &dsc_authinfo.dsc_stor,
                                                          dsc_authinfo.dsc_conf.achc_dn,
                                                          dsc_authinfo.dsc_conf.inc_len_dn,
                                                          &dsc_authinfo.dsc_conf.inc_tree );

    return true;
} // end of ds_authenticate::m_switch_ldap


/**
 * private function ds:authenticate::m_get_tree_dns
 *
 * @param[in]   const char          *achp_dn    dn to split
 * @param[in]   int                 inp_len_dn  length of dn
 * @param[out]  int                 *ainp_tree  number of splited elements
 * @return      dsd_ldap_groups*                tree dns
*/
struct dsd_ldap_groups* ds_authenticate::m_get_tree_dns( struct dsd_stor_sdh_1 *adsp_stor,
                                                         const char *achp_dn, int inp_len_dn,
                                                         int *ainp_tree )
{
    struct dsd_ldap_groups    *adsl_out;        /* return structure      */
    struct dsd_ldap_groups    *adsl_insert;     /* insert structure      */
    struct dsd_ldap_attr_desc *adsl_dns;        /* eploded dns chain     */
    struct dsd_ldap_attr_desc *adsl_loop;       /* loop variable         */
    int                       inl_length;       /* needed length         */

    adsl_dns = m_explode_dn( NULL, achp_dn, inp_len_dn );
    if (    adsl_dns                      == NULL
         || adsl_dns->adsc_next_attr_desc == NULL ) {
        return NULL;
    }
    /* ignore first entry, cause this will be object name */
    adsl_dns = adsl_dns->adsc_next_attr_desc;

    /* count entries */
    adsl_loop = adsl_dns;
    *ainp_tree = 0;
    do {
        (*ainp_tree)++;
        adsl_loop = adsl_loop->adsc_next_attr_desc;
    } while ( adsl_loop != NULL );

    adsl_out = (struct dsd_ldap_groups*)m_aux_stor_alloc( adsp_stor,
                                                            (*ainp_tree)
                                                          * (int)sizeof(struct dsd_ldap_groups) );
    if ( adsl_out == NULL ) {
        return NULL;
    }

    adsl_insert = adsl_out;
    do {
        inl_length = 0;
        adsl_loop  = adsl_dns;
        do {
            inl_length += adsl_loop->imc_len_dn + 1; /* +1 for comma */
            adsl_loop = adsl_loop->adsc_next_attr_desc;
        } while ( adsl_loop != NULL );
        inl_length--;
#ifdef SH_NESTED_GROUPS
		memset(adsl_insert, 0, sizeof(struct dsd_ldap_groups));
#endif
        adsl_insert->achc_dn = (const char*)m_aux_stor_alloc( adsp_stor, inl_length );
        if ( adsl_insert->achc_dn == NULL ) {
            return NULL;
        }
        adsl_insert->inc_len_dn = inl_length;

        inl_length = 0;
        adsl_loop  = adsl_dns;
        do {
            memcpy( (void*)(&adsl_insert->achc_dn[inl_length]),
                    adsl_loop->ac_dn, adsl_loop->imc_len_dn );
            inl_length += adsl_loop->imc_len_dn;
            if ( adsl_loop->adsc_next_attr_desc != NULL ) {
                *((char*)&adsl_insert->achc_dn[inl_length]) = ',';
                inl_length++;
            }

            adsl_loop = adsl_loop->adsc_next_attr_desc;
        } while ( adsl_loop != NULL );

        adsl_insert++;
        adsl_dns = adsl_dns->adsc_next_attr_desc;
    } while ( adsl_dns != NULL );
    return adsl_out;
} // end of ds_authenticate::m_get_tree_dns


/**
 * private function ds_authenticate::m_bind_conf_ldap
 *
 * @param[in]   dsd_domain      *adsp_domain
 * @return      bool
*/
bool ds_authenticate::m_bind_conf_ldap( struct dsd_domain *adsp_domain )
{
    struct dsd_co_ldap_1 dsl_ldap;              /* ldap command struct   */
    bool                 bol_ret;               /* return from ldap      */

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap = ied_co_ldap_bind;
    if ( adsp_domain->inc_len_dn_admin > 0 ) {
        dsl_ldap.iec_ldap_auth  = ied_auth_dn;
        dsl_ldap.ac_userid      = adsp_domain->achc_dn_admin;
        dsl_ldap.imc_len_userid = adsp_domain->inc_len_dn_admin;
        dsl_ldap.iec_chs_userid = ied_chs_utf_8;
        dsl_ldap.ac_passwd      = adsp_domain->achc_pwd_admin;
        dsl_ldap.imc_len_passwd = adsp_domain->inc_len_pwd_admin;
        dsl_ldap.iec_chs_passwd = ied_chs_utf_8;
    } else {
        dsl_ldap.iec_ldap_auth = ied_auth_admin;
    }
    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
    if (    bol_ret                     == false
         || (    dsl_ldap.iec_ldap_resp != ied_ldap_success 
              && dsl_ldap.iec_ldap_resp != ied_ldap_no_results ) ) {
		if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
			if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
			}
			else {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
			}
		}
        return false;
    }
    return true;
} // end of ds_authenticate::m_bind_conf_ldap

static BOOL m_ldap_request_aux(void* avop_userfld, int inp_func, void* avop_param1, int inp_param2) {
	dsd_stor_sdh_1* adsl_stor_sdh_1 = (dsd_stor_sdh_1*)avop_userfld;

	switch(inp_func) {
	case DEF_AUX_MEMGET:
		*(void**)avop_param1 = m_aux_stor_alloc(adsl_stor_sdh_1, inp_param2);
		return *(void**)avop_param1 != NULL;
	case DEF_AUX_MEMFREE:
		m_aux_stor_free(adsl_stor_sdh_1, avop_param1);
		return TRUE;
	default:
		return FALSE;
	}
}

/**
 * private function ds_authenticate::m_get_conf_sysinfo()
 *  get system information from configuration ldap
 *
 * @return  bool
*/
bool ds_authenticate::m_get_conf_sysinfo()
{
    struct dsd_co_ldap_1 dsl_ldap;              /* ldap command struct   */
    bool                 bol_ret;               /* ldap return           */

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap = ied_co_ldap_get_sysinfo;

	dsl_ldap.amc_aux = m_ldap_request_aux;
	dsl_ldap.vpc_userfld = &dsc_authinfo.dsc_stor;

    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
    if (    bol_ret                == true
         && dsl_ldap.iec_ldap_resp == ied_ldap_success
         && dsl_ldap.adsc_sysinfo  != NULL             ) {
        dsc_authinfo.dsc_conf.adsc_lconf  = dsl_ldap.adsc_sysinfo->adsc_ldap_template;
		/* AKre: use  "adsc_base_dn_def" instead of adsc_base_dn*/
        if ( dsl_ldap.adsc_sysinfo->adsc_base_dn_def != NULL ) { 
            dsc_authinfo.dsc_conf.achc_basedn    = dsl_ldap.adsc_sysinfo->adsc_base_dn_def->ac_val;
            dsc_authinfo.dsc_conf.inc_len_basedn = dsl_ldap.adsc_sysinfo->adsc_base_dn_def->imc_len_val;
		} else { /* take configured base */
			dsc_authinfo.dsc_conf.achc_basedn    = dsl_ldap.adsc_sysinfo->adsc_base_dn_conf->ac_val;
            dsc_authinfo.dsc_conf.inc_len_basedn = dsl_ldap.adsc_sysinfo->adsc_base_dn_conf->imc_len_val;
		}
        return true;
    }
	if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
		if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
			adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
		}
		else {
			adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
		}
	}
    return false;
} // end of ds_authenticate::m_get_conf_sysinfo


/**
 * private function ds_authenticate::m_search_by_sid
 *  search object by its objectsid (case of AD)
 *  we have saved the org objectsid in our configuration ldap!
 *
 * @param[in]   dsd_stor_sdh_1  *adsp_stor      storage container
 * @param[in]   const char      *achp_sid       objectsid
 * @param[in]   int             inp_len_sid     length of objectsid
 * @param[out]  char            **aachp_ndn     whole dn of found object
 * @param[out]  int             *ainp_len_ndn   length of dn
 * @param[out]  char            **aachp_name    found name of object (cn=xyz)
 * @param[out]  int             *ainp_len_name  length of found name     ---
 * @return      bool                            true = object found
 *                                              false otherwise
*/
bool ds_authenticate::m_search_by_sid( struct dsd_stor_sdh_1 *adsp_stor,
                                       const char *achp_sid, int inp_len_sid,
                                       char **aachp_ndn, int *ainp_len_ndn,
                                       char **aachp_name, int *ainp_len_name,
                                       struct dsd_domain *adsp_domain )
{
    struct dsd_co_ldap_1 dsl_ldap;              /* ldap command          */
    struct dsd_ldap_attr *adsl_attr;            /* found user attributes */
    bool                 bol_ret;               /* return for ldap call  */
    const char           *achl_uprefix;         /* user prefix           */
    int                  inp_len_uprefix;       /* length user prefix    */
    ds_hstring dsl_filter(adsc_wsp_helper);     /* search filter         */

    if ( dsc_authinfo.dsc_conf.adsc_lconf->imc_len_user_attr > 0 ) {
        dsl_filter.m_writef( "(&(objectclass=%.*s)(hobsid=%.*s))",
                             dsc_authinfo.dsc_conf.adsc_lconf->imc_len_user_attr,
                             dsc_authinfo.dsc_conf.adsc_lconf->achc_user_attr,
                             inp_len_sid, achp_sid );
    } else {
        dsl_filter.m_writef( "(&(objectclass=person)(hobsid=%.*s))",
                             inp_len_sid, achp_sid );
    }
    
    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap    = ied_co_ldap_search;
    dsl_ldap.iec_sear_scope = ied_sear_sublevel;
    dsl_ldap.ac_dn          = (char*)dsc_authinfo.dsc_conf.achc_basedn;
    dsl_ldap.imc_len_dn     = dsc_authinfo.dsc_conf.inc_len_basedn;
    dsl_ldap.iec_chs_dn     = ied_chs_utf_8;
    if (    adsp_domain
         && adsp_domain->inc_len_base > 0 ) {
        dsl_ldap.dsc_add_dn.ac_str      = adsp_domain->achc_base;
        dsl_ldap.dsc_add_dn.imc_len_str = adsp_domain->inc_len_base;
        dsl_ldap.dsc_add_dn.iec_chs_str = ied_chs_utf_8;
    }
    dsl_ldap.iec_chs_filter = ied_chs_utf_8;
    dsl_ldap.imc_len_filter = dsl_filter.m_get_len();
    dsl_ldap.ac_filter      = const_cast<char*>(dsl_filter.m_get_ptr());

    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
    if (    bol_ret                 == false
         || dsl_ldap.iec_ldap_resp  != ied_ldap_success
         || dsl_ldap.adsc_attr_desc == NULL             ) {
		if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
			if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
			}
			else {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
			}
		}
        return false;
    }

    if ( dsl_ldap.adsc_attr_desc->adsc_next_attr_desc != NULL ) {
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HAUTHE209E user with sid '%.*s' exists mutliple times",
                                 inp_len_sid, achp_sid );
        return false;
    }

    /* save whole dn */
    *aachp_ndn = (char*)m_aux_stor_alloc( adsp_stor, dsl_ldap.adsc_attr_desc->imc_len_dn );
    if ( *aachp_ndn == NULL ) {
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HAUTHE210E cannot get memory for saving dn '%.*s'",
                                 dsl_ldap.adsc_attr_desc->imc_len_dn,
                                 dsl_ldap.adsc_attr_desc->ac_dn       );
        return false;
    }
    *ainp_len_ndn = dsl_ldap.adsc_attr_desc->imc_len_dn;
    memcpy( *aachp_ndn, dsl_ldap.adsc_attr_desc->ac_dn, *ainp_len_ndn );

    /* get username */
    if ( dsc_authinfo.dsc_conf.adsc_lconf->imc_len_upref > 0 ) {
        achl_uprefix    = (const char*)dsc_authinfo.dsc_conf.adsc_lconf->achc_upref;
        inp_len_uprefix = dsc_authinfo.dsc_conf.adsc_lconf->imc_len_upref;
    } else {
        achl_uprefix    = "cn";
        inp_len_uprefix = sizeof("cn") - 1;
    }

    adsl_attr = dsl_ldap.adsc_attr_desc->adsc_attr;
    while ( adsl_attr != NULL ) {
        if (    adsl_attr->imc_len_attr == inp_len_uprefix
             && memcmp( adsl_attr->ac_attr, achl_uprefix, inp_len_uprefix ) == 0 ) {
            *aachp_name = adsl_attr->dsc_val.ac_val;
            *ainp_len_name = adsl_attr->dsc_val.imc_len_val;
            break;
        }
        adsl_attr = adsl_attr->adsc_next_attr;
    }

    return true;
} // end of ds_authenticate::m_search_by_sid


/**
 * private function ds_authenticate::m_search_user
 * search a user in configuration ldap
 *
 * @param[in]   dsd_stor_sdh_1  *adsp_stor      storage container
 * @param[in]   const char      *achp_name      user name
 * @param[in]   int             inp_len_name    length of name
 * @param[out]  char            **aachp_ndn     found dn
 * @param[out]  int             *ainp_len_ndn   length of found dn
 * @return      bool                            true = success
 *                                              false otherwise
*/
bool ds_authenticate::m_search_user( struct dsd_stor_sdh_1 *adsp_stor,
                                     const char *achp_name, int inp_len_name,
                                     char **aachp_ndn, int *ainp_len_ndn,
                                     struct dsd_domain *adsp_domain )
{
    bool                      bol_ret;          /* return for sev. funcs */
    struct dsd_co_ldap_1      dsl_ldap;         /* ldap structure        */
    const char                *achl_person;     /* person part of filter */
    int                       inp_len_person;   /* length of person part */
    ds_hstring dsl_filter(adsc_wsp_helper);     /* ldap filter           */

    if ( dsc_authinfo.dsc_conf.adsc_lconf->imc_len_user_attr > 0 ) {
        achl_person    = dsc_authinfo.dsc_conf.adsc_lconf->achc_user_attr;
        inp_len_person = dsc_authinfo.dsc_conf.adsc_lconf->imc_len_user_attr;
    } else {
        achl_person    = "person";
        inp_len_person = sizeof("person") - 1;
    }
    // Ticket [23724] use default search attribute!
    if ( dsc_authinfo.dsc_conf.adsc_lconf->imc_len_search_d_a > 0 ) {
        dsl_filter.m_writef( "(&(objectclass=%.*s)(%.*s=%.*s))",
                             inp_len_person, achl_person,
                             dsc_authinfo.dsc_conf.adsc_lconf->imc_len_search_d_a,
                             dsc_authinfo.dsc_conf.adsc_lconf->achc_search_d_a,
                             inp_len_name, achp_name );
    } else if ( dsc_authinfo.dsc_conf.adsc_lconf->imc_len_upref > 0 ) {
        dsl_filter.m_writef( "(&(objectclass=%.*s)(%.*s=%.*s))",
                             inp_len_person, achl_person,
                             dsc_authinfo.dsc_conf.adsc_lconf->imc_len_upref,
                             dsc_authinfo.dsc_conf.adsc_lconf->achc_upref,
                             inp_len_name, achp_name );
    } else {
        dsl_filter.m_writef( "(&(objectclass=%.*s)(cn=%.*s))",
                             inp_len_person, achl_person,
                             inp_len_name, achp_name );
    }

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap    = ied_co_ldap_search;
    dsl_ldap.iec_sear_scope = ied_sear_sublevel; //ied_sear_root;
    dsl_ldap.ac_dn          = (char*)dsc_authinfo.dsc_conf.achc_basedn;
    dsl_ldap.imc_len_dn     = dsc_authinfo.dsc_conf.inc_len_basedn;
    dsl_ldap.iec_chs_dn     = ied_chs_utf_8;
    if (    adsp_domain
         && adsp_domain->inc_len_base > 0 ) {
        dsl_ldap.dsc_add_dn.ac_str      = adsp_domain->achc_base;
        dsl_ldap.dsc_add_dn.imc_len_str = adsp_domain->inc_len_base;
        dsl_ldap.dsc_add_dn.iec_chs_str = ied_chs_utf_8;
    }
    dsl_ldap.iec_chs_filter = ied_chs_utf_8;
    dsl_ldap.imc_len_filter = dsl_filter.m_get_len();
    dsl_ldap.ac_filter      = const_cast<char*>(dsl_filter.m_get_ptr());

    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
    if (    bol_ret                 == false
         || dsl_ldap.iec_ldap_resp  != ied_ldap_success
         || dsl_ldap.adsc_attr_desc == NULL             ) {
		if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
			if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
			}
			else {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
			}
		}
        return false;
    }

    if ( dsl_ldap.adsc_attr_desc->adsc_next_attr_desc != NULL ) {
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HAUTHE211E user '%.*s' exists mutliple times",
                                 inp_len_name, achp_name );
        return false;
    }

    *aachp_ndn = (char*)m_aux_stor_alloc( adsp_stor, dsl_ldap.adsc_attr_desc->imc_len_dn );
    if ( *aachp_ndn == NULL ) {
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HAUTHE212E cannot get memory for saving dn '%.*s'",
                                 dsl_ldap.adsc_attr_desc->imc_len_dn,
                                 dsl_ldap.adsc_attr_desc->ac_dn       );
        return false;
    }
    *ainp_len_ndn = dsl_ldap.adsc_attr_desc->imc_len_dn;
    memcpy( *aachp_ndn, dsl_ldap.adsc_attr_desc->ac_dn, *ainp_len_ndn );
    return true;
} // end of ds_authenticate::m_search_user


#ifdef SH_NESTED_GROUPS
/**
 * private function ds_authenticate::m_search_groups
 * search a users groups in configuration ldap
 *
 * @param[in]   dsd_stor_sdh_1    *adsp_stor    storage container
 * @param[in]   dsd_domain        *adsp_domain  currently selected domain
 * @param[in]   dsd_ldap_template *adsp_conf    ldap config
 * @param[in]   const char        *achp_dn      user dn
 * @param[in]   int               inp_len_dn    length of dn
 * @param[in]   const char        *achp_base    base dn
 * @param[in]   int               inp_len_base  length of base dn
 * @param[out]  int               *ainp_groups  number of groups
 * @param[in]   bool              bop_nested    true=groups of groups (... and so on) are also returned
 * @return      dsd_ldap_groups*                found groups
 *                                              null if nothing found
*/
struct dsd_ldap_groups* ds_authenticate::m_search_groups( struct dsd_stor_sdh_1    *adsp_stor,
                                                          struct dsd_domain        *adsp_domain,
                                                          struct dsd_ldap_template *adsp_conf,
                                                          const char *achp_dn,   int inp_len_dn,
                                                          const char *achp_base, int inp_len_base,
                                                          int *ainp_groups, 
														  dsd_ldap_groups* adsp_group_dns, int inp_groups)
{
    struct dsd_ldap_groups    *adsl_out;        /* return value          */
    struct dsd_co_ldap_1      dsl_ldap;         /* ldap structure        */
	
	if (achp_dn==NULL) {
		adsc_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD029D: m_get_membership()");
	} else {
		adsc_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD029D: m_get_membership() for '%.*s';", inp_len_dn, achp_dn);
	}

    memset( &dsl_ldap, 0, sizeof(dsd_co_ldap_1) );
    if ( (achp_dn == NULL) || (inp_len_dn <= 0) ) {
        // Determine the groups, where the logged user is a member of.
        dsl_ldap.ac_dn = NULL;
        dsl_ldap.imc_len_dn = 0;
    }
    else { // Determine membership relations (groups) for a special DN
        dsl_ldap.ac_dn = const_cast<char*>(achp_dn);
        dsl_ldap.imc_len_dn = inp_len_dn;
    }
    dsl_ldap.iec_chs_dn     = ied_chs_utf_8;

	if (    adsp_domain != NULL
         && adsp_domain->inc_len_base > 0 ) {
        dsl_ldap.dsc_add_dn.ac_str      = adsp_domain->achc_base;
        dsl_ldap.dsc_add_dn.imc_len_str = adsp_domain->inc_len_base;
        dsl_ldap.dsc_add_dn.iec_chs_str = ied_chs_utf_8;
    }

	dsl_ldap.iec_co_ldap = ied_co_ldap_get_membership_nested;
    
    dsl_ldap.iec_sear_scope = ied_sear_basedn; // We search the groups in a specified folder (in some LDAPs the member-relation is only stored at the groups)!
                                                   // The name 'ied_sear_basedn' is miss-leading: it really means the folder, where the search shall be done (not the LDAP-base!).
                                                   // The entry in wsp.xml is '<base-dn>' (miss-leading!!).

    bool bo_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
    if (bo_ret == false) {
        adsc_wsp_helper->m_log(ied_sdh_log_error, "HLDAE875E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_get_membership) failed: method returned false");
        return NULL;
    }
    if ((dsl_ldap.iec_ldap_resp != ied_ldap_success) && (dsl_ldap.iec_ldap_resp != ied_ldap_no_results)) {
        if (dsl_ldap.ac_errmsg != NULL) {
            if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                adsc_wsp_helper->m_logf(ied_sdh_log_error, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
            }
            else {
                adsc_wsp_helper->m_logf(ied_sdh_log_error, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
            }
        }
        adsc_wsp_helper->m_logf(ied_sdh_log_error, "HLDAE876E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_get_membership) failed with error %d.", dsl_ldap.iec_ldap_resp);
        return NULL;
    }

	dsd_const_string hstr_dn_print_name(achp_dn, inp_len_dn);
	if(hstr_dn_print_name.m_get_ptr() == NULL)
		hstr_dn_print_name = "<null>";
    if (dsl_ldap.iec_ldap_resp == ied_ldap_no_results) { // no results were found -> this is not an error
        adsc_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD027D: No memberships detected for '%.*s'.",
			hstr_dn_print_name.m_get_len(), hstr_dn_print_name.m_get_ptr());
        return NULL;
    }

    // The delivered data are organized as follows:
    // adsc_co_ldap.adsc_memship_desc is the start point of a chain of dsd_ldap_val, which hold dn,length of dn, charset and a next-pointer.
    /*
        count groups
    */
	int iml_sum_len_dn = 0;
	*ainp_groups = 0;
    dsd_ldap_val* adsl_cur = dsl_ldap.adsc_memship_desc;
    do {
        (*ainp_groups)++;
		iml_sum_len_dn += adsl_cur->imc_len_val;
		adsl_cur = adsl_cur->adsc_next_val;
    } while ( adsl_cur != NULL );


	int iml_alloc_size = (*ainp_groups) * (int)sizeof(struct dsd_ldap_groups) + iml_sum_len_dn;
    adsl_out = (struct dsd_ldap_groups*)m_aux_stor_alloc( adsp_stor, iml_alloc_size);
    if ( adsl_out == NULL ) {
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HAUTHE213E cannot get memory for storing groups of dn '%.*s'.",
								 hstr_dn_print_name.m_get_len(), hstr_dn_print_name.m_get_ptr());
        return NULL;
    }

	memset(adsl_out, 0, iml_alloc_size);

    /*
        save groups
    */
    adsl_cur    = dsl_ldap.adsc_memship_desc;
    dsd_ldap_groups *adsl_insert = adsl_out;
	char* adsl_dn_cur = (char*)adsl_out + (*ainp_groups) * (int)sizeof(struct dsd_ldap_groups);
    do {
		adsl_insert->achc_dn = adsl_dn_cur;
		memcpy( (void*)adsl_insert->achc_dn, adsl_cur->ac_val, adsl_cur->imc_len_val );
		adsl_insert->inc_len_dn = adsl_cur->imc_len_val;
		if (adsp_group_dns != NULL) {
			// We got "direct" Groups from caller
			dsd_const_string dsl_cur(adsl_cur->ac_val, adsl_cur->imc_len_val);
			// search for the group in the "direct" groups array
			struct dsd_ldap_groups* adsl_tmp_cur = adsp_group_dns;
			struct dsd_ldap_groups* adsl_tmp_end = adsl_tmp_cur + inp_groups;
			for ( ;adsl_tmp_cur < adsl_tmp_end; adsl_tmp_cur++ ) {
				dsd_const_string dsl_tmp_cur(adsl_tmp_cur->achc_dn, adsl_tmp_cur->inc_len_dn);
				if(dsl_tmp_cur.m_equals_ic(dsl_cur)) {
					adsl_insert->boc_direct = TRUE;
					break;
				}
			}
		}
   	    adsl_dn_cur += adsl_cur->imc_len_val;
		adsl_insert++;
        adsl_cur = adsl_cur->adsc_next_val;
    } while ( adsl_cur != NULL );

    if (*ainp_groups == 0) // no entries -> We are done
	    return adsl_out;

	// first search was done nested -> now get the "direct" groups
	if ((adsp_group_dns == NULL) && (inp_groups == 0)) {
		dsl_ldap.iec_co_ldap = ied_co_ldap_get_membership;
	    
		dsl_ldap.iec_sear_scope = ied_sear_basedn; // We search the groups in a specified folder (in some LDAPs the member-relation is only stored at the groups)!
													   // The name 'ied_sear_basedn' is miss-leading: it really means the folder, where the search shall be done (not the LDAP-base!).
													   // The entry in wsp.xml is '<base-dn>' (miss-leading!!).

		bo_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
		if (bo_ret == false) {
			adsc_wsp_helper->m_log(ied_sdh_log_error, "HLDAE875E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_get_membership) failed: method returned false");
			return NULL;
		}
		if ((dsl_ldap.iec_ldap_resp != ied_ldap_success) && (dsl_ldap.iec_ldap_resp != ied_ldap_no_results)) {
			if (dsl_ldap.ac_errmsg != NULL) {
				if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
					adsc_wsp_helper->m_logf(ied_sdh_log_error, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
				}
				else {
					adsc_wsp_helper->m_logf(ied_sdh_log_error, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
				}
			}
			adsc_wsp_helper->m_logf(ied_sdh_log_error, "HLDAE876E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_get_membership) failed with error %d.", dsl_ldap.iec_ldap_resp);
			return NULL;
		}

		if (dsl_ldap.iec_ldap_resp == ied_ldap_no_results) { // no results were found -> this is not an error
			adsc_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD027D: No memberships detected for '%.*s'.",
				hstr_dn_print_name.m_get_len(), hstr_dn_print_name.m_get_ptr());
			return NULL;
		}

		// The delivered data are organized as follows:
		// adsc_co_ldap.adsc_memship_desc is the start point of a chain of dsd_ldap_val, which hold dn,length of dn, charset and a next-pointer.
		adsl_cur = dsl_ldap.adsc_memship_desc;
		do {
			dsd_const_string dsl_cur(adsl_cur->ac_val, adsl_cur->imc_len_val);
			// search for the group in the output array
			dsd_ldap_groups* adsl_tmp_cur = adsl_out;
			dsd_ldap_groups* adsl_tmp_end = adsl_tmp_cur + *ainp_groups;
			for ( ;adsl_tmp_cur < adsl_tmp_end; adsl_tmp_cur++ ) {
				dsd_const_string dsl_tmp_cur(adsl_tmp_cur->achc_dn, adsl_tmp_cur->inc_len_dn);
				if(dsl_tmp_cur.m_equals_ic(dsl_cur)) {
					adsl_tmp_cur->boc_direct = TRUE;
					break;
				}
			}
			adsl_cur = adsl_cur->adsc_next_val;
		} while ( adsl_cur != NULL );
	} 

	// Next Step: Store the values of the group to group membership
	// Loop over all groups in output array
    struct dsd_ldap_groups* adsl_tmp_cur = adsl_out;
    struct dsd_ldap_groups* adsl_tmp_end = adsl_tmp_cur + *ainp_groups;
    for ( ;adsl_tmp_cur < adsl_tmp_end; adsl_tmp_cur++ ) {
		dsl_ldap.ac_dn = const_cast<char*>(adsl_tmp_cur->achc_dn);
		dsl_ldap.imc_len_dn = adsl_tmp_cur->inc_len_dn;
		dsl_ldap.iec_co_ldap = ied_co_ldap_get_membership;
		bo_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
		if (bo_ret == false) {
			adsc_wsp_helper->m_log(ied_sdh_log_error, "HLDAE875E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_get_membership) failed: method returned false");
			continue;
		}
		if ((dsl_ldap.iec_ldap_resp != ied_ldap_success) && (dsl_ldap.iec_ldap_resp != ied_ldap_no_results)) {
			if (dsl_ldap.ac_errmsg != NULL) {
				if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
					adsc_wsp_helper->m_logf(ied_sdh_log_error, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
				}
				else {
					adsc_wsp_helper->m_logf(ied_sdh_log_error, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
				}
			}
			adsc_wsp_helper->m_logf(ied_sdh_log_error, "HLDAE876E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_get_membership) failed with error %d.", dsl_ldap.iec_ldap_resp);
			continue;
		}

		if (dsl_ldap.iec_ldap_resp == ied_ldap_no_results) { // no results were found -> this is not an error
			adsc_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD027D: No memberships detected for '%.*s'.",
				hstr_dn_print_name.m_get_len(), hstr_dn_print_name.m_get_ptr());
			continue;
		}

		adsl_tmp_cur->inc_count_parents = 0;
		// count parent groups
		adsl_cur = dsl_ldap.adsc_memship_desc;
		do {
			adsl_tmp_cur->inc_count_parents++;
			adsl_cur = adsl_cur->adsc_next_val;
		} while ( adsl_cur != NULL );

		dsd_ldap_groups **avo_insert;
        // search parent groups
		if (adsl_tmp_cur->inc_count_parents != 0) {
			adsl_tmp_cur->ads_parents = (struct dsd_ldap_groups**)m_aux_stor_alloc( adsp_stor, 
																	(adsl_tmp_cur->inc_count_parents) * (int)sizeof(void *) 
																  );
			if ( adsl_tmp_cur->ads_parents == NULL ) {
				adsc_wsp_helper->m_logf( ied_sdh_log_error,
										 "HAUTHE213E cannot get memory for storing groups of dn '%.*s'.",
										 hstr_dn_print_name.m_get_len(), hstr_dn_print_name.m_get_ptr());
				break;
			}
			avo_insert = adsl_tmp_cur->ads_parents;
			adsl_cur = dsl_ldap.adsc_memship_desc;
			do {
				dsd_const_string dsl_cur(adsl_cur->ac_val, adsl_cur->imc_len_val);
				// search for the group in the output array
				dsd_ldap_groups* adsl_tmp2_cur = adsl_out;
				dsd_ldap_groups* adsl_tmp2_end = adsl_tmp2_cur + *ainp_groups;
				for ( ;adsl_tmp2_cur < adsl_tmp2_end; adsl_tmp2_cur++ ) {
					dsd_const_string dsl_tmp_cur(adsl_tmp2_cur->achc_dn, adsl_tmp2_cur->inc_len_dn);
					if(dsl_tmp_cur.m_equals_ic(dsl_cur)) {
						*avo_insert = adsl_tmp2_cur;
						avo_insert++;
						break;

					}
				}
				adsl_cur = adsl_cur->adsc_next_val;
			} while ( adsl_cur != NULL );
		}
	}
	return adsl_out;
} // end of ds_authenticate::m_search_groups
#else
/**
 * private function ds_authenticate::m_search_groups
 * search a users groups in configuration ldap
 *
 * @param[in]   dsd_stor_sdh_1    *adsp_stor    storage container
 * @param[in]   dsd_domain        *adsp_domain  currently selected domain
 * @param[in]   dsd_ldap_template *adsp_conf    ldap config
 * @param[in]   const char        *achp_dn      user dn
 * @param[in]   int               inp_len_dn    length of dn
 * @param[in]   const char        *achp_base    base dn
 * @param[in]   int               inp_len_base  length of base dn
 * @param[out]  int               *ainp_groups  number of groups
 * @return      dsd_ldap_groups*                found groups
 *                                              null if nothing found
*/
struct dsd_ldap_groups* ds_authenticate::m_search_groups( struct dsd_stor_sdh_1    *adsp_stor,
                                                          struct dsd_domain        *adsp_domain,
                                                          struct dsd_ldap_template *adsp_conf,
                                                          const char *achp_dn,   int inp_len_dn,
                                                          const char *achp_base, int inp_len_base,
                                                          int *ainp_groups)
{
	bool                      bol_ret;          /* return for sev. funcs */
    struct dsd_co_ldap_1      dsl_ldap;         /* ldap structure        */
    const char                *achl_group;      /* group objectclass     */
    int                       inl_len_group;    /* length grp objectcl.  */
    const char                *achl_member;     /* member attribute      */
    int                       inl_len_member;   /* length member attr.   */
    ds_hstring dsl_filter(adsc_wsp_helper);     /* ldap filter           */
    struct dsd_ldap_attr_desc *adsl_cur;        /* current group         */
    struct dsd_ldap_groups    *adsl_out;        /* return value          */
    struct dsd_ldap_groups    *adsl_insert;     /* insert position       */

    /* setup search filter */
    if ( adsp_conf->imc_len_group_attr > 0 ) {
        achl_group    = adsp_conf->achc_group_attr;
        inl_len_group = adsp_conf->imc_len_group_attr;
    } else {
        achl_group    = "groupofuniquenames";
        inl_len_group = (int)sizeof("groupofuniquenames") - 1;
    }

    if ( adsp_conf->imc_len_member_attr > 0 ) {
        achl_member    = adsp_conf->achc_member_attr;
        inl_len_member = adsp_conf->imc_len_member_attr;
    } else {
        achl_member    = "uniqueMember";
        inl_len_member = (int)sizeof("uniqueMember") - 1;
    }
    dsl_filter.m_writef( "(&(objectclass=%.*s)(%.*s=%.*s))",
                         inl_len_group, achl_group,
                         inl_len_member, achl_member,
                         inp_len_dn, achp_dn );

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap    = ied_co_ldap_search;
    dsl_ldap.iec_sear_scope = ied_sear_sublevel; //ied_sear_root;
    dsl_ldap.ac_dn          = (char*)achp_base;
    dsl_ldap.imc_len_dn     = inp_len_base;
    dsl_ldap.iec_chs_dn     = ied_chs_utf_8;
    if (    adsp_domain != NULL
         && adsp_domain->inc_len_base > 0 ) {
        dsl_ldap.dsc_add_dn.ac_str      = adsp_domain->achc_base;
        dsl_ldap.dsc_add_dn.imc_len_str = adsp_domain->inc_len_base;
        dsl_ldap.dsc_add_dn.iec_chs_str = ied_chs_utf_8;
    }
    dsl_ldap.iec_chs_filter = ied_chs_utf_8;
    dsl_ldap.imc_len_filter = dsl_filter.m_get_len();
    dsl_ldap.ac_filter      = const_cast<char*>(dsl_filter.m_get_ptr());

    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
    if (    bol_ret                 == false
         || dsl_ldap.iec_ldap_resp  != ied_ldap_success
         || dsl_ldap.adsc_attr_desc == NULL             ) {
		if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
			if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
			}
			else {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
			}
		}
        return NULL;
    }

    /*
        count groups
    */
    *ainp_groups = 0;
    adsl_cur     = dsl_ldap.adsc_attr_desc;
    do {
        (*ainp_groups)++;
        adsl_cur = adsl_cur->adsc_next_attr_desc;
    } while ( adsl_cur != NULL );


    adsl_out = (struct dsd_ldap_groups*)m_aux_stor_alloc( adsp_stor, 
                                                            (*ainp_groups)
                                                          * (int)sizeof(struct dsd_ldap_groups) );
    if ( adsl_out == NULL ) {
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HAUTHE213E cannot get memory for storing groups of dn '%.*s'",
                                 inp_len_dn, achp_dn );
        return NULL;
    }

    /*
        save groups
    */
    adsl_cur    = dsl_ldap.adsc_attr_desc;
    adsl_insert = adsl_out;
    do {
        adsl_insert->achc_dn = (const char*)m_aux_stor_alloc( adsp_stor,
                                                              adsl_cur->imc_len_dn );
        if ( adsl_insert->achc_dn == NULL ) {
            adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                     "HAUTHE214E cannot get memory for storing group dn '%.*s'",
                                     adsl_cur->imc_len_dn, adsl_cur->ac_dn );
            continue;
        }

        memcpy( (void*)adsl_insert->achc_dn, adsl_cur->ac_dn, adsl_cur->imc_len_dn );
        adsl_insert->inc_len_dn = adsl_cur->imc_len_dn;

        adsl_insert++;
        adsl_cur = adsl_cur->adsc_next_attr_desc;
    } while ( adsl_cur != NULL );
    return adsl_out;
} // end of ds_authenticate::m_search_groups
#endif


/**
 * private function ds_authenticate::m_clone_groups
 *
 * @param[in]   dsd_stor_sdh_1      *adsp_stor      storage container
 * @param[in]   int                 inp_groups      number of input groups
 * @param[in]   dsd_ldap_attr_desc  *adsp_expl_grps exploded group dns
 * @param[in]   dsd_ldap_groups     *adsp_dn_grps   group dns
 * @param[out]  int                 *ainp_created   number of cloned groups
 * @return      dsd_ldap_groups*                    list of created goup dns
 *                                                  NULL in error cases
*/
struct dsd_ldap_groups* ds_authenticate::m_clone_groups( struct dsd_stor_sdh_1     *adsp_stor,
                                                         int                       inp_groups,
                                                         struct dsd_ldap_attr_desc *adsp_expl_grps,
                                                         struct dsd_ldap_groups    *adsp_dn_grps,
                                                         int                       *ainp_created,
                                                         struct dsd_domain         *adsp_domain )
{
    struct dsd_ldap_groups *adsl_created;       /* cloned groups         */
    struct dsd_ldap_groups *adsl_insert;        /* inser position        */
    int                    inl_group;           /* loop variable         */
    bool                   bol_ret;             /* return for sev. funcs */

    adsl_created = (struct dsd_ldap_groups*)m_aux_stor_alloc( adsp_stor,
                                                                inp_groups
                                                              * (int)sizeof(struct dsd_ldap_groups) );
    if ( adsl_created == NULL ) {
        adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                 "HAUTHW023W cannot get memory for storing config group dns for '%.*s'",
                                 dsc_authinfo.dsc_conf.inc_len_dn, dsc_authinfo.dsc_conf.achc_dn );
        return NULL;
    }

	memset(adsl_created, 0, inp_groups * (int)sizeof(struct dsd_ldap_groups));

    adsl_insert = adsl_created;
#define ADSL_CUR_GRP_DN (adsp_dn_grps + inl_group)
#define ADSL_CUR_GRP_EXP (adsp_expl_grps + inl_group)
    for ( inl_group = 0; inl_group < inp_groups; inl_group++ ) {
        /* clone each group, add user as a member and save group dn */
        bol_ret = m_clone_dn( adsp_stor, ADSL_CUR_GRP_EXP,
                              ied_objectclass_group,
                              (char**)&adsl_insert->achc_dn,
                              &adsl_insert->inc_len_dn,
                              adsp_domain );
        if ( bol_ret == false ) {
            adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                     "HAUTHW024W cannot clone group '%.*s'",
                                     ADSL_CUR_GRP_DN->inc_len_dn,
                                     ADSL_CUR_GRP_DN->achc_dn );
            return NULL;
        }
#ifdef SH_NESTED_GROUPS
		if (ADSL_CUR_GRP_DN->boc_direct != FALSE) {
			adsl_insert->boc_direct = TRUE;
			bol_ret = m_add_member( dsc_authinfo.dsc_conf.achc_dn,
									dsc_authinfo.dsc_conf.inc_len_dn,
									adsl_insert->achc_dn, adsl_insert->inc_len_dn,
									dsc_authinfo.dsc_conf.adsc_lconf->achc_member_attr,
									dsc_authinfo.dsc_conf.adsc_lconf->imc_len_member_attr );
			if ( bol_ret == false ) {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning,
										 "HAUTHW025W couldn't add member '%.*s' to group '%.*s'",
										 dsc_authinfo.dsc_conf.inc_len_dn, dsc_authinfo.dsc_conf.achc_dn,
										 adsl_insert->inc_len_dn, adsl_insert->achc_dn );
			}
		}
		adsl_insert->inc_count_parents = ADSL_CUR_GRP_DN->inc_count_parents;
		if (adsl_insert->inc_count_parents != 0) {
			dsd_ldap_groups **avo_cur_parent;
			dsd_ldap_groups **avo_new_parent;
			dsd_ldap_groups **avo_last_parent;
			avo_cur_parent = ADSL_CUR_GRP_DN->ads_parents;
			avo_last_parent = avo_cur_parent + adsl_insert->inc_count_parents;
			adsl_insert->ads_parents = (dsd_ldap_groups **) m_aux_stor_alloc( adsp_stor, adsl_insert->inc_count_parents * (int)sizeof(void*) );
			if ( adsl_insert->ads_parents == NULL ) {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning,
										 "HAUTHW023W cannot get memory for storing parent groups links for '%.*s'",
										 dsc_authinfo.dsc_conf.inc_len_dn, dsc_authinfo.dsc_conf.achc_dn );
			} else {
				avo_new_parent = adsl_insert->ads_parents;
				while(avo_cur_parent < avo_last_parent) {
					*avo_new_parent = (dsd_ldap_groups *)((char *)(*avo_cur_parent) - (char *)adsp_dn_grps + (char *)adsl_created);
                    avo_new_parent++;
					avo_cur_parent++;
				}
			}
		}
#else
		bol_ret = m_add_member( dsc_authinfo.dsc_conf.achc_dn,
								dsc_authinfo.dsc_conf.inc_len_dn,
								adsl_insert->achc_dn, adsl_insert->inc_len_dn,
								dsc_authinfo.dsc_conf.adsc_lconf->achc_member_attr,
								dsc_authinfo.dsc_conf.adsc_lconf->imc_len_member_attr );
		if ( bol_ret == false ) {
			adsc_wsp_helper->m_logf( ied_sdh_log_warning,
									 "HAUTHW025W couldn't add member '%.*s' to group '%.*s'",
									 dsc_authinfo.dsc_conf.inc_len_dn, dsc_authinfo.dsc_conf.achc_dn,
									 adsl_insert->inc_len_dn, adsl_insert->achc_dn );
			continue;
		}
#endif
        adsl_insert++;
        (*ainp_created)++;
    }
#undef ADSL_CUR_GRP_DN
#undef ADSL_CUR_GRP_EXP
#ifdef SH_NESTED_GROUPS
	// Groups are created, now update the membership structure.
    ds_hvector<ds_hstring> adsl_v_groups;
    adsl_v_groups.m_init( adsc_wsp_helper );
	// get membership relations currently stored in OpenDJ
#define ADSL_CUR_GRP_DN (adsl_created + inl_group)
#define ADSL_INP_GRP_DN (adsp_dn_grps + inl_group)
	// loop through all the groups
    for ( inl_group = 0; inl_group < inp_groups; inl_group++ ) {
		adsl_v_groups.m_clear();
        struct dsd_co_ldap_1 dsl_membership;

        /* get the membership of the group from config */
		memset( &dsl_membership, 0, sizeof(struct dsd_co_ldap_1) );
        dsl_membership.iec_co_ldap    = ied_co_ldap_get_membership;
        dsl_membership.iec_chs_dn     = ied_chs_utf_8;
		dsl_membership.imc_len_dn     = ADSL_CUR_GRP_DN->inc_len_dn;
		dsl_membership.ac_dn          = const_cast<char*>(ADSL_CUR_GRP_DN->achc_dn);
        dsl_membership.iec_sear_scope = ied_sear_basedn;
        bol_ret = adsc_wsp_helper->m_cb_ldap_request(&dsl_membership); // TODO: Initialize
		if ( (bol_ret != false ) && ( dsl_membership.iec_ldap_resp != ied_ldap_success ) 
			&& (dsl_membership.iec_ldap_resp != ied_ldap_no_results) && (dsl_membership.ac_errmsg != NULL) ) {
			if (dsl_membership.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_membership.ac_errmsg);
			}
			else {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_membership.imc_len_errmsg, dsl_membership.ac_errmsg);
			}
		} else {
			// Store current Groups in Vector
			if (dsl_membership.iec_ldap_resp != ied_ldap_no_results) { // results were found 
				while ( dsl_membership.adsc_memship_desc != NULL ) {
					ds_hstring dsl_group_dn (adsc_wsp_helper, dsl_membership.adsc_memship_desc->ac_val, 
											   dsl_membership.adsc_memship_desc->imc_len_val );
					adsl_v_groups.m_add( dsl_group_dn );
					dsl_membership.adsc_memship_desc = dsl_membership.adsc_memship_desc->adsc_next_val;
				}
			}
		}
		// Check if groups have to be added
		if (ADSL_INP_GRP_DN->inc_count_parents != 0) {
			dsd_ldap_groups **avo_cur_parent;
			dsd_ldap_groups **avo_last_parent;
			BOOL bol_found;
			avo_cur_parent = ADSL_CUR_GRP_DN->ads_parents;
			avo_last_parent = ADSL_CUR_GRP_DN->ads_parents + ADSL_INP_GRP_DN->inc_count_parents;
			while(avo_cur_parent < avo_last_parent) {
				bol_found = FALSE;
				dsd_hvec_elem<ds_hstring>* adsl_before = NULL;
				for ( HVECTOR_FOREACH2(ds_hstring, adsl_cur, adsl_v_groups) ) {
					const ds_hstring& dsl_cur = HVECTOR_GET(adsl_cur);
					if (dsl_cur.m_equals_ic((*avo_cur_parent)->achc_dn, (*avo_cur_parent)->inc_len_dn)) {
						bol_found = TRUE;
						// remove from Vector
						adsl_v_groups.m_delete(adsl_before, adsl_cur);
						break;
					}
					adsl_before = adsl_cur;
				}
				if (bol_found == FALSE) {
					// create membership relation
					bol_ret = m_add_member( ADSL_CUR_GRP_DN->achc_dn, ADSL_CUR_GRP_DN->inc_len_dn,
											(*avo_cur_parent)->achc_dn,
											(*avo_cur_parent)->inc_len_dn,
											dsc_authinfo.dsc_conf.adsc_lconf->achc_member_attr,
											dsc_authinfo.dsc_conf.adsc_lconf->imc_len_member_attr );
					if ( bol_ret == false ) {
						adsc_wsp_helper->m_logf( ied_sdh_log_warning,
												 "HAUTHW025W couldn't add member(group) '%.*s' to group '%.*s'",
												 ADSL_CUR_GRP_DN->inc_len_dn, ADSL_CUR_GRP_DN->achc_dn,
												 (*avo_cur_parent)->inc_len_dn, (*avo_cur_parent)->achc_dn);
					}
				}
				avo_cur_parent++;
			}
		}
		// Check if groups have to be removed
        ds_hstring dsl_uniqemember (adsc_wsp_helper, "uniqueMember");
        for ( HVECTOR_FOREACH(ds_hstring, adsl_cur, adsl_v_groups) ) {
            const ds_hstring& dsl_cur = HVECTOR_GET(adsl_cur);
			//Not valid anymore: delete membership
            m_del_attribute( dsl_cur.m_get_ptr(), dsl_cur.m_get_len(),
                                           dsl_uniqemember.m_get_ptr(), dsl_uniqemember.m_get_len(),
                                           ADSL_CUR_GRP_DN->achc_dn, ADSL_CUR_GRP_DN->inc_len_dn );
        }
	}
#endif
    return adsl_created;
} // end of ds_authenticate::m_clone_groups


/**
 * private ds_authenticate::m_add_member
 *
 * @param[in]   const char  *achp_user          user dn
 * @param[in]   int         inp_len_user        length of user dn
 * @param[in]   const char  *achp_group         group dn
 * @param[in]   int         inp_len_group       length of group dn
 * @param[in]   const char  *achp_mship_attr    membership attribute
 * @param[in]   int         inp_len_mship_attr  length of mship attr
 * @return      bool
*/
bool ds_authenticate::m_add_member( const char *achp_user, int inp_len_user,
                                    const char *achp_group, int inp_len_group,
                                    const char *achp_mship_attr, int inp_len_mship_attr )
{
    return m_set_attribute( achp_group, inp_len_group,
                            achp_mship_attr, inp_len_mship_attr,
                            achp_user, inp_len_user );
} // end of ds_authenticate::m_add_member


/**
 * private function ds_authenticate::m_set_attribute
 *
 * @param[in]   const char  *achp_dn        dn to set attribute for
 * @param[in]   int         inp_len_dn      length of dn
 * @param[in]   const char  *achp_attr      attribute to set
 * @param[in]   int         inp_len_attr    length of attribute
 * @param[in]   const char  *achp_value     value to set
 * @param[in]   int         inp_len_val     length of value
 * @return      bool
*/
bool ds_authenticate::m_set_attribute( const char *achp_dn, int inp_len_dn,
                                       const char *achp_attr, int inp_len_attr,
                                       const char *achp_value, int inp_len_val )
{
    bool                      bol_ret;          /* return for sev. funcs */
    struct dsd_co_ldap_1      dsl_ldap;         /* ldap structure        */
    struct dsd_ldap_attr_desc dsl_attr_desc;    /* ldap attribute descr  */
    struct dsd_ldap_attr      dsl_attr;         /* ldap attribute itself */

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap    = ied_co_ldap_modify;
    dsl_ldap.adsc_attr_desc = &dsl_attr_desc;

    memset( &dsl_attr_desc, 0, sizeof(struct dsd_ldap_attr_desc) );
    dsl_attr_desc.ac_dn      = (char*)achp_dn;
    dsl_attr_desc.imc_len_dn = inp_len_dn;
    dsl_attr_desc.iec_chs_dn = ied_chs_utf_8;
    dsl_attr_desc.adsc_attr  = &dsl_attr;

    memset( &dsl_attr, 0, sizeof(struct dsd_ldap_attr) );
    dsl_attr.ac_attr             = (char*)achp_attr;
    dsl_attr.imc_len_attr        = inp_len_attr;
    dsl_attr.iec_chs_attr        = ied_chs_utf_8;
    dsl_attr.dsc_val.ac_val      = (char*)achp_value;
    dsl_attr.dsc_val.imc_len_val = inp_len_val;
    dsl_attr.dsc_val.iec_chs_val = ied_chs_utf_8;

    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
    if (    bol_ret                == true
         && (    dsl_ldap.iec_ldap_resp == ied_ldap_success
              || dsl_ldap.iec_ldap_resp == ied_ldap_attr_or_val_exist ) ) {
        return true;
    }
	if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
		if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
			adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
		}
		else {
			adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
		}
	}
    return false;
} // end of ds_authenticate::m_set_attribute

/**
 * private function ds_authenticate::m_del_attribute
 *
 * @param[in]   const char  *achp_dn        dn to delete attribute for
 * @param[in]   int         inp_len_dn      length of dn
 * @param[in]   const char  *achp_attr      attribute to delete
 * @param[in]   int         inp_len_attr    length of attribute
 * @param[in]   const char  *achp_value     value to delete
 * @param[in]   int         inp_len_val     length of value
 * @return      bool
*/
bool ds_authenticate::m_del_attribute( const char *achp_dn, int inp_len_dn,
                                       const char *achp_attr, int inp_len_attr,
                                       const char *achp_value, int inp_len_val )
{
    bool                      bol_ret;          /* return for sev. funcs */
    struct dsd_co_ldap_1      dsl_ldap;         /* ldap structure        */
    struct dsd_ldap_attr_desc dsl_attr_desc;    /* ldap attribute descr  */
    struct dsd_ldap_attr      dsl_attr;         /* ldap attribute itself */

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap    = ied_co_ldap_modify;
    dsl_ldap.adsc_attr_desc = &dsl_attr_desc;

    memset( &dsl_attr_desc, 0, sizeof(struct dsd_ldap_attr_desc) );
    dsl_attr_desc.ac_dn      = (char*)achp_dn;
    dsl_attr_desc.imc_len_dn = inp_len_dn;
    dsl_attr_desc.iec_chs_dn = ied_chs_utf_8;
    dsl_attr_desc.adsc_attr  = &dsl_attr;

    memset( &dsl_attr, 0, sizeof(struct dsd_ldap_attr) );
    dsl_attr.ac_attr                 = (char*)achp_attr;
    dsl_attr.imc_len_attr            = inp_len_attr;
    dsl_attr.iec_chs_attr            = ied_chs_utf_8;
    dsl_attr.dsc_val.ac_val_old      = (char*)achp_value;
    dsl_attr.dsc_val.imc_len_val_old = inp_len_val;
    dsl_attr.dsc_val.iec_chs_val_old = ied_chs_utf_8;

    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
    if (    bol_ret                == true
         && (    dsl_ldap.iec_ldap_resp == ied_ldap_success
              || dsl_ldap.iec_ldap_resp == ied_ldap_attr_or_val_exist ) ) {
        return true;
    }
	if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
		if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
			adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
		}
		else {
			adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
		}
	}
    return false;
} // end of ds_authenticate::m_set_attribute

/**
 * private function ds_authenticate::m_collect_attribute
 *  get attribute data from user itself, all his groups and from tree
 *
 * @param[in]   dsd_stor_sdh_1  *adsp_stor      storage container
 * @param[in]   const char      *achp_attr      attribute to read
 * @param[in]   int             inp_len_attr    length of attribute
 * @param[out]  dsd_ldap_value  **aadsp_own     own user attribute value
 * @param[out]  int             *ainp_group     number of attr from groups
 * @param[out]  dsd_ldap_value  **aadsp_group   group attribute values
 * @param[out]  int             *ainp_tree      number of attr from tree
 * @param[out]  dsd_ldap_value  **aadsp_tree    tree attribute values
 * @return      bool
*/
bool ds_authenticate::m_collect_attribute( struct dsd_stor_sdh_1 *adsp_stor,
                                           const char *achp_attr, int inp_len_attr,
                                           struct dsd_ldap_value **aadsp_own,
                                           int *ainp_group, struct dsd_ldap_value **aadsp_group,
                                           int *ainp_tree,  struct dsd_ldap_value **aadsp_tree )
{
    int                     inl_count;          /* number of found value */
    struct dsd_ldap_val     *adsl_value;        /* attribute value       */

    /*
        read own attribute
        -> there can be only one value, since we have no
           multivalued attributes
    */
    adsl_value = m_get_attribute( dsc_authinfo.dsc_conf.achc_dn,
                                  dsc_authinfo.dsc_conf.inc_len_dn,
                                  achp_attr, inp_len_attr );
    if ( adsl_value != NULL ) {
        *aadsp_own = (struct dsd_ldap_value*)m_aux_stor_alloc( adsp_stor,
                                                               (int)sizeof(struct dsd_ldap_value) );
        if ( *aadsp_own == NULL ) {
            adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                     "HAUTHE215E cannot get memory to store attribute '%.*s' from '%.*s'",
                                     inp_len_attr, achp_attr,
                                     dsc_authinfo.dsc_conf.inc_len_dn,
                                     dsc_authinfo.dsc_conf.achc_dn );
            return false;
        }

        (*aadsp_own)->achc_value = (const char*)m_aux_stor_alloc( adsp_stor,
                                                                  adsl_value->imc_len_val );
        if ( (*aadsp_own)->achc_value == NULL ) {
            adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                     "HAUTHE216E cannot get memory to store attribute '%.*s' from '%.*s'",
                                     inp_len_attr, achp_attr,
                                     dsc_authinfo.dsc_conf.inc_len_dn,
                                     dsc_authinfo.dsc_conf.achc_dn );
            return false;
        }
        memcpy( (void*)(*aadsp_own)->achc_value, adsl_value->ac_val,
                adsl_value->imc_len_val );
        (*aadsp_own)->inc_len_value = adsl_value->imc_len_val;
    } else {
        *aadsp_own = NULL;
    }

    if ( dsc_authinfo.dsc_conf.inc_groups > 0 ) {
        /*
            read attributes from group
            -> there might be one attribute per group
            -> since ldap modul keeps the memory just until the next ldap call
               we need to allocate memory for every group in advance
        */
        *aadsp_group = (struct dsd_ldap_value*)m_aux_stor_alloc( adsp_stor,
                                                                   dsc_authinfo.dsc_conf.inc_groups
                                                                   * (int)sizeof(struct dsd_ldap_value) );
        if ( *aadsp_group == NULL ) {
            adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                     "HAUTHE217E cannot get memory to store attribute '%.*s' from groups",
                                     inp_len_attr, achp_attr );
            return false;
        }
        *ainp_group = 0;
#define ADSL_CUR_GROUP (dsc_authinfo.dsc_conf.adsc_group_dns + inl_count)
#define ADSL_CUR_VALUE (*aadsp_group + *ainp_group)
        for ( inl_count = 0; inl_count < dsc_authinfo.dsc_conf.inc_groups; inl_count++ ) {
            adsl_value = m_get_attribute( ADSL_CUR_GROUP->achc_dn,
                                          ADSL_CUR_GROUP->inc_len_dn,
                                          achp_attr, inp_len_attr );
            if ( adsl_value == NULL ) {
                continue;
            }

            ADSL_CUR_VALUE->achc_value = (const char*)m_aux_stor_alloc( adsp_stor,
                                                                        adsl_value->imc_len_val );
            if ( ADSL_CUR_VALUE->achc_value == NULL ) {
                adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                         "HAUTHE218E cannot get memory to store attribute '%.*s' from '%.*s'",
                                         inp_len_attr, achp_attr,
                                         ADSL_CUR_GROUP->inc_len_dn,
                                         ADSL_CUR_GROUP->achc_dn );
                return false;
            }
            memcpy( (void*)ADSL_CUR_VALUE->achc_value, adsl_value->ac_val,
                    adsl_value->imc_len_val );
            ADSL_CUR_VALUE->inc_len_value = adsl_value->imc_len_val;
            (*ainp_group)++;
        }
#undef ADSL_CUR_VALUE
#undef ADSL_CUR_GROUP
    } else {
        *aadsp_group = NULL;
        *ainp_group  = 0;
    }

    if ( dsc_authinfo.dsc_conf.inc_tree > 0 ) {
        /*
            read attributes from tree
            -> there might be one attribute per tree element
            -> since ldap modul keeps the memory just until the next ldap call
               we need to allocate memory for every group in advance
        */
        *aadsp_tree = (struct dsd_ldap_value*)m_aux_stor_alloc( adsp_stor,
                                                                  dsc_authinfo.dsc_conf.inc_tree
                                                                * (int)sizeof(struct dsd_ldap_value) );
        if ( *aadsp_tree == NULL ) {
            adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                     "HAUTHE219E cannot get memory to store attribute '%.*s' from tree",
                                     inp_len_attr, achp_attr );
            return false;
        }
        *ainp_tree = 0;
#define ADSL_CUR_TREE (dsc_authinfo.dsc_conf.adsc_tree_dns + inl_count)
#define ADSL_CUR_VALUE (*aadsp_tree + *ainp_tree)
        for ( inl_count = 0; inl_count < dsc_authinfo.dsc_conf.inc_tree; inl_count++ ) {
            adsl_value = m_get_attribute( ADSL_CUR_TREE->achc_dn,
                                          ADSL_CUR_TREE->inc_len_dn,
                                          achp_attr, inp_len_attr );
            if ( adsl_value == NULL ) {
                continue;
            }

            ADSL_CUR_VALUE->achc_value = (const char*)m_aux_stor_alloc( adsp_stor,
                                                                        adsl_value->imc_len_val );
            if ( ADSL_CUR_VALUE->achc_value == NULL ) {
                adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                         "HAUTHE220E cannot get memory to store attribute '%.*s' from '%.*s'",
                                         inp_len_attr, achp_attr,
                                         ADSL_CUR_TREE->inc_len_dn,
                                         ADSL_CUR_TREE->achc_dn );
                return false;
            }
            memcpy( (void*)ADSL_CUR_VALUE->achc_value, adsl_value->ac_val,
                    adsl_value->imc_len_val );
            ADSL_CUR_VALUE->inc_len_value = adsl_value->imc_len_val;
            (*ainp_tree)++;
        }
#undef ADSL_CUR_VALUE
#undef ADSL_CUR_TREE
    } else {
        *aadsp_tree = NULL;
        *ainp_tree  = 0;
    }

    return true;
} // end of ds_authenticate::m_collect_attribute


/**
 * private function ds_authenticate::m_get_attribute
 *
 * @param[in]   const char      *achp_dn        dn to read attribute from
 * @param[in]   int             inp_len_dn      length of dn
 * @param[in]   const char      *achp_attr      attribute to read
 * @param[in]   int             inp_len_attr    length of attribute
 * @return      dsd_ldap_val*                   values
 *                                              NULL if nothing found
*/
struct dsd_ldap_val* ds_authenticate::m_get_attribute( const char *achp_dn, int inp_len_dn,
                                                       const char *achp_attr, int inp_len_attr )
{
    struct dsd_co_ldap_1    dsl_ldap;           /* ldap command struct   */
    bool                    bol_ret;            /* return from ldap call */

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap      = ied_co_ldap_search;
    dsl_ldap.iec_sear_scope   = ied_sear_baseobject;//ied_sear_basedn;
    dsl_ldap.ac_dn            = (char*)achp_dn;
    dsl_ldap.imc_len_dn       = inp_len_dn;
    dsl_ldap.iec_chs_dn       = ied_chs_utf_8;
    dsl_ldap.ac_attrlist      = (char*)achp_attr;
    dsl_ldap.imc_len_attrlist = inp_len_attr;
    dsl_ldap.iec_chs_attrlist = ied_chs_utf_8;
    memset( &dsl_ldap.dsc_add_dn, 0, sizeof(struct dsd_unicode_string) );

    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
    if (    (bol_ret != false)
		&&  (dsl_ldap.iec_ldap_resp == ied_ldap_no_results)) {
        return NULL;
	}
    if (    bol_ret                     == false
         || dsl_ldap.iec_ldap_resp != ied_ldap_success
         || dsl_ldap.adsc_attr_desc            == NULL
         || dsl_ldap.adsc_attr_desc->adsc_attr == NULL   ) {
		if (   (bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
			if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
			}
			else {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
			}
		}
        return NULL;
    }
    return &dsl_ldap.adsc_attr_desc->adsc_attr->dsc_val;
} // end of ds_authenticate::m_get_attribute


/** \brief Stores the groups in our JWTSA container
 *
 *	Takes a dsd_co_ldap_1* pointer and checks the groups. then it stores
 *  all the groups in a storage container, which is member of the class
 *
*/
 struct dsd_ldap_val* ds_authenticate::m_jwtsa_save_groups( dsd_co_ldap_1 *adsp_co_ldap )
{
	char					*achl_own;
	struct dsd_ldap_val		*adsl_attr_start = 0;
	struct dsd_ldap_val		*adsl_attr_current = 0;
	struct dsd_ldap_val		*adsl_attr_old = 0;

	adsl_attr_current = adsp_co_ldap->adsc_memship_desc;

	while( adsl_attr_current != NULL )
	{
		/* get some memory from our container */
		achl_own = (char*)m_aux_stor_alloc( &dsc_stor_jwtsa, sizeof( struct dsd_ldap_val ) + adsl_attr_current->imc_len_val );
		if( achl_own == NULL ){ return NULL; }
		
		/* save our data, otherwise it will be lost with the next LDAP call */
		memcpy( achl_own, adsl_attr_current, sizeof ( struct dsd_ldap_val ) );
		memcpy( achl_own + sizeof( struct dsd_ldap_val ), adsl_attr_current->ac_val , adsl_attr_current->imc_len_val );

		/* create linked list */
		if( adsl_attr_start == NULL )
		{
			adsl_attr_start	= ( struct dsd_ldap_val* )achl_own;
			adsl_attr_start->ac_val = (char*)( achl_own + sizeof( struct dsd_ldap_val ) ); /* data is stored in the memory behind the structure */
		}
		else{ adsl_attr_old->adsc_next_val = ( struct dsd_ldap_val* )achl_own; }
		
		adsl_attr_old = ( struct dsd_ldap_val* )achl_own;
		adsl_attr_old->ac_val = (char*)( achl_own + sizeof( struct dsd_ldap_val ) ); /* data is stored in the memory behind the structure */

		adsl_attr_current = adsl_attr_current->adsc_next_val;
	}

	return adsl_attr_start;
}

#if BO_HOBTE_CONFIG

#if BO_LDAP_USE_COLLECT_ATTRIBUTES

bool m_get_connection(ds_hstring ds_jterm_config, ds_wsp_helper* dsp_wsp_helper,                     
                     const char *ach_connid_value, int im_connid_len,
                     ds_hobte_conf* adsp_hobte_conf
                     )
{
    ds_xml dsl_xml;
    
    dsl_xml.m_init(dsp_wsp_helper);

    dsd_xml_tag *ads_jterm_root = dsl_xml.m_from_xml(ds_jterm_config.m_const_str());
    if (!ads_jterm_root) 
    {        
        dsp_wsp_helper->m_logf( ied_sdh_log_warning, "ds_authenticate l%05d Specified Webterm dn has no root ",
                        __LINE__ );
        return false;
    }

    const char *ach_tmp_value;
    int im_tmp_len;

    dsd_xml_tag* adsl_schemes = dsl_xml.m_get_value(ads_jterm_root, "Schemes", &ach_tmp_value, &im_tmp_len);
    if (!adsl_schemes)
    {        
        dsp_wsp_helper->m_logf( ied_sdh_log_warning, "ds_authenticate l%05d Specified Webterm dn has no schemes ",
                __LINE__ );
        return false;
    }

    dsd_xml_tag* adsl_connection = dsl_xml.m_get_value(adsl_schemes, "Connection", &ach_tmp_value, &im_tmp_len);
    if (!adsl_connection)
    {
        return false;
    }
    dsd_xml_tag* adsl_next_scheme = adsl_connection->ads_child;
    
    BOOL bol_found = FALSE;
 
    while (adsl_next_scheme && !bol_found)
    {

        if (adsl_next_scheme->in_len_data == im_connid_len+2 &&
            adsl_next_scheme->ach_data[0] == '_' && 
            adsl_next_scheme->ach_data[1] == '_' &&
            !memcmp(&(adsl_next_scheme->ach_data[2]),ach_connid_value,adsl_next_scheme->in_len_data-2) )
        {
            bol_found = TRUE;
            break;
        }

        adsl_next_scheme = adsl_next_scheme->ads_next;
    }

    if (!bol_found)
    {        
        dsp_wsp_helper->m_logf( ied_sdh_log_warning, "ds_authenticate l%05d Webterm Connection Scheme not found ",
                __LINE__ );
        return false;

    }

    const char* achl_schemestart = adsl_next_scheme->ach_data - 1; //start from initial "<" - this is not included in ach_data

    int iml_remaining_len = ds_jterm_config.m_get_ptr()+ds_jterm_config.m_get_len() - achl_schemestart;
    int iml_endtagend = 0; //has to be 0 before calling m_get_end_tag
    int iml_endtagstart = 0;//has to be 0 before calling m_get_end_tag
    bool bol_ret = dsl_xml.m_get_end_tag(adsl_next_scheme->ach_data,iml_remaining_len,&iml_endtagend,&iml_endtagstart,adsl_next_scheme->ach_data,adsl_next_scheme->in_len_data);

    //get the connection type - required for rights
   
    
    dsd_xml_tag* adsl_subprotocol = dsl_xml.m_get_value(adsl_next_scheme,"SubConnType", &ach_tmp_value, &im_tmp_len);
    if (adsl_subprotocol)
    {
        adsp_hobte_conf->m_set_subprotocol(ach_tmp_value,im_tmp_len);

        //we only add the session if we found the connection and the subprotocol 
        return true;
       
    }
    return false;
    

}


 int m_search_sessions(ds_hstring ds_jterm_config, ds_wsp_helper*   dsp_wsp_helper,                                           
                     ds_attribute_string* dsl_config_attribute_own,
                    ds_hvector<ds_attribute_string>* dsl_config_attributes_tree,
                    ds_hvector<ds_attribute_string>* dsl_config_attributes_group,
                    ds_hvector<ds_hobte_conf> *adsp_configs
                     )
{
// build an object structure from xml
    ds_xml dsl_xml;
    ds_hobte_conf dsl_hobte_conf;
    dsl_xml.m_init(dsp_wsp_helper);
    
    ds_hstring ds_conn_scheme(dsp_wsp_helper);

    dsd_xml_tag *ads_jterm_root = dsl_xml.m_from_xml(ds_jterm_config.m_const_str());
    if (!ads_jterm_root) {        
        return -7;
    }
    // it the structure is not valid return exception
    if (memcmp(ads_jterm_root->ach_data, "root", ads_jterm_root->in_len_data) != 0) {        
        return -8;
    }

    //get the Sessions attribute
    const char *ach_tmp_value;
    int im_tmp_len;
    dsd_xml_tag* adsl_sessions = dsl_xml.m_get_value(ads_jterm_root, "Sessions", &ach_tmp_value, &im_tmp_len);
    if (!adsl_sessions)
    {        
        return -10;
    }

    /*const char* ach_display_value;
    int im_display_len;*/
    dsd_xml_tag* adsl_display = dsl_xml.m_get_value(adsl_sessions, "Display", &ach_tmp_value, &im_tmp_len);
    if (!adsl_display)
    {
        return -11;
    }
    dsd_xml_tag* adsl_next_session = adsl_display->ads_child;
    
      
    const char* ach_ssname_value;
    int im_ssname_len;

    while (adsl_next_session)
    {
        
        dsd_xml_tag* adsl_session_name = dsl_xml.m_get_value(adsl_next_session, "SSName", &ach_ssname_value, &im_ssname_len);

        if (adsl_session_name)
        {
            
            dsl_hobte_conf.m_set_name(ach_ssname_value,im_ssname_len);
           
            //if found get the connection ID
            const char* achl_connid_value;
            int iml_connid_len;
            dsd_xml_tag* adsl_connection = dsl_xml.m_get_value(adsl_next_session, "Connection", &achl_connid_value, &iml_connid_len);

            if (!adsl_connection || !achl_connid_value || iml_connid_len == 0)
            {             
                //skip session if no connection is specified
                dsp_wsp_helper->m_logf( ied_sdh_log_warning, "ds_authenticate l%05d  no connection found for session: \"%.*s\" ",
                            __LINE__, im_ssname_len, ach_ssname_value );
            }
            else
            {
                //check if the scheme is in another level            
                const char* achl_loconn_value;
                int iml_loconn_len;
                dsd_xml_tag* dsl_loconn = dsl_xml.m_get_value(adsl_next_session, "LO_Connection", &achl_loconn_value, &iml_loconn_len);
                BOOL bol_dn_found = FALSE;
                if (dsl_loconn && achl_loconn_value && iml_loconn_len > 0)
                {
                
                    //the connection is at another LDAP level
                    {
                        const ds_hstring dsl_dn = dsl_config_attribute_own->m_get_dn();
                        if (dsl_dn.m_get_len() == iml_loconn_len)
                        {
                            if (!memcmp(dsl_dn.m_get_ptr(),achl_loconn_value,iml_loconn_len))
                            {
                                ds_conn_scheme = dsl_config_attribute_own->m_get_value_at(0);
                                bol_dn_found = true;         
                            }
                        }
                    }
                    if (!bol_dn_found)
                    {
                        size_t iml_config_count = dsl_config_attributes_group->m_size();
                        size_t iml_nextconfig = 0;
                        while (iml_nextconfig < iml_config_count && !bol_dn_found)
                        {
                            const ds_hstring dsl_dn = dsl_config_attributes_group->m_get(iml_nextconfig).m_get_dn();                        
                            if (dsl_dn.m_get_len() == iml_loconn_len)
                            {
                                if (!memcmp(dsl_dn.m_get_ptr(),achl_loconn_value,iml_loconn_len))
                                {
                                    ds_conn_scheme = dsl_config_attributes_group->m_get(iml_nextconfig).m_get_value_at(0);
                                    bol_dn_found = true;
                                }
                            } 
                            iml_nextconfig++;
                        }      
                    }
                    if (!bol_dn_found)
                    {
                        size_t iml_config_count = dsl_config_attributes_tree->m_size();
                        size_t iml_nextconfig = 0;
                        while (iml_nextconfig < iml_config_count && !bol_dn_found)
                        {
                            const ds_hstring dsl_dn = dsl_config_attributes_tree->m_get(iml_nextconfig).m_get_dn();                        
                            if (dsl_dn.m_get_len() == iml_loconn_len)
                            {
                                if (!memcmp(dsl_dn.m_get_ptr(),achl_loconn_value,iml_loconn_len))
                                {
                                    ds_conn_scheme = dsl_config_attributes_tree->m_get(iml_nextconfig).m_get_value_at(0);
                                    bol_dn_found = true;
                                }
                            } 
                            iml_nextconfig++;
                        }      
                    }   
                    if (!bol_dn_found)
                    {
                        //if we had an LO_Connection but did not find the relevant dn with the specified connection number in the user/tree/group return error
                        dsp_wsp_helper->m_logf( ied_sdh_log_warning, "ds_authenticate l%05d  LO_Connection specified but no connection found for session: \"%.*s\" ",
                            __LINE__, im_ssname_len, ach_ssname_value );
                    }
                
        
                }  //end LO_connection
                else
                {
                    bol_dn_found = true; //no LO_connection - try to get scheme from own attribute
                    ds_conn_scheme = ds_jterm_config;
                }
            

                if (bol_dn_found)
                {
                    if (m_get_connection(ds_conn_scheme,dsp_wsp_helper,achl_connid_value,iml_connid_len, &dsl_hobte_conf))
                    {
                         adsp_configs->m_add( dsl_hobte_conf );
                    }
                }
            } //end else
        }
        adsl_next_session = adsl_next_session->ads_next;
    }
    
    return 0;
}


 
#endif

bool ds_authenticate::m_hobte_find_configs( dsd_auth_t* adsp_auth )
{
	dsd_co_ldap_1					dsl_co_ldap;
	bool							bol_ret;
	ds_hvector<ds_hobte_conf>		dsl_configs;
	struct dsd_ldap_val				*adsl_attr_current = NULL;
	int								iml_offset = 0;

	adsc_wsp_helper->m_new_storage_cont( &dsc_stor_hobte, HOBTE_STORAGE_SIZE );
	dsl_configs.m_init( adsc_wsp_helper );

#if BO_LDAP_USE_COLLECT_ATTRIBUTES
    ds_ldap ds_ldap_instance;
    ds_ldap_instance.m_init(adsc_wsp_helper);

    int inl_ret = ds_ldap_instance.m_simple_bind();
    if (inl_ret != SUCCESS) {
        ds_hstring hstr = ds_ldap_instance.m_get_last_error();

        adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: unable to connect to LDAP \"%.*s\"",
            __LINE__, hstr.m_get_len(), hstr.m_get_ptr()  );
       

        return false;
    }
        
    const ds_hstring hstr_hobhobte(adsc_wsp_helper,"hobhobte");
    ds_hvector<ds_attribute_string> dsl_config_attributes_tree(adsc_wsp_helper);
    ds_hvector<ds_attribute_string> dsl_config_attributes_group(adsc_wsp_helper);
    ds_attribute_string dsl_config_attribute_own(adsc_wsp_helper);

    
    //int inl_domain_auth = dsl_user.inc_auth_method;
    //const ds_hstring hstr_our_dn = dsl_user.dsc_userdn;

    //int im_ret = ds_ldap_instance.m_read_attributes(&hstr_hobhobte, NULL, &hstr_our_dn, ied_sear_superlevel,&dsl_config_attributes);
    const ds_hstring hstr_our_dn(adsc_wsp_helper, dsc_authinfo.dsc_conf.achc_dn, dsc_authinfo.dsc_conf.inc_len_dn);
    int im_ret = ds_ldap_instance.m_collect_attributes( &hstr_our_dn, 
                                                        &hstr_hobhobte,
                                                        &dsl_config_attribute_own,
                                                        &dsl_config_attributes_group,
                                                        &dsl_config_attributes_tree
                                                                  );
    if (im_ret)
    {
        ds_hstring hstr = ds_ldap_instance.m_get_last_error();
        adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: \"%.*s\"",
            __LINE__, hstr.m_get_len(), hstr.m_get_ptr() );
  
        return false;
    }

    
    int iml_ret = 0;
    if (dsl_config_attribute_own.m_get_values().m_size())
    {
    
        // parse the attribute
        ds_hstring ds_jterm_config = dsl_config_attribute_own.m_get_value_at(0);

        iml_ret = m_search_sessions(ds_jterm_config, adsc_wsp_helper,
            &dsl_config_attribute_own,&dsl_config_attributes_tree,&dsl_config_attributes_group,&dsl_configs);
        if (iml_ret > 0)
        {

        }
    }

    int iml_config_count = dsl_config_attributes_tree.m_size();
    int iml_nextconfig = 0;
    while (iml_nextconfig < iml_config_count)
    {
        // parse the attribute
        ds_hstring ds_jterm_config = dsl_config_attributes_tree.m_get(iml_nextconfig).m_get_value_at(0);
     
  
        iml_ret = m_search_sessions(ds_jterm_config, adsc_wsp_helper, 
            &dsl_config_attribute_own,&dsl_config_attributes_tree,&dsl_config_attributes_group,&dsl_configs);
        
        if (iml_ret > 0)
        {
  
        }
  

        iml_nextconfig++;
    }


    iml_config_count = dsl_config_attributes_group.m_size();
    iml_nextconfig = 0;
    while (iml_nextconfig < iml_config_count)
    {
        // parse the attribute
        ds_hstring ds_jterm_config = dsl_config_attributes_group.m_get(iml_nextconfig).m_get_value_at(0);
      
        iml_ret = m_search_sessions(ds_jterm_config, adsc_wsp_helper,
            &dsl_config_attribute_own,&dsl_config_attributes_tree,&dsl_config_attributes_group, &dsl_configs);
        if (iml_ret > 0)
        {
      
        }
      
        iml_nextconfig++;
    }
#else
	/*----------*/
	/* OWN 		*/
	/*----------*/
	m_hobte_read_config( dsc_authinfo.dsc_conf.achc_dn, dsc_authinfo.dsc_conf.inc_len_dn, &dsl_configs );

	/*----------*/
	/* TREE		*/
	/*----------*/
	while( iml_offset < dsc_authinfo.dsc_conf.inc_len_dn )
	{
		if( *(dsc_authinfo.dsc_conf.achc_dn + iml_offset) == ',' )
		{
			++iml_offset;
			m_hobte_read_config(	dsc_authinfo.dsc_conf.achc_dn + iml_offset,
									dsc_authinfo.dsc_conf.inc_len_dn - iml_offset,
									&dsl_configs );
		}
		++iml_offset;
	}

	/*----------*/
	/* GROUPS	*/
	/*----------*/
	/* prepare LDAP access */
	memset( &dsl_co_ldap, 0, sizeof( dsd_co_ldap_1 ) );

#ifdef OLD_LDAP_CALL_FOR_GROUP_MEMBERSHIP
	dsl_co_ldap.ac_dn = NULL;
	dsl_co_ldap.imc_len_dn = 0;
	dsl_co_ldap.iec_co_ldap = ied_co_ldap_get_membership;   
    dsl_co_ldap.iec_sear_scope = ied_sear_root;
#else
    dsl_co_ldap.iec_co_ldap = ied_co_ldap_get_membership_nested;
	dsl_co_ldap.iec_chs_dn  = ied_chs_utf_8;
    dsl_co_ldap.ac_dn       = (char*)dsc_authinfo.dsc_conf.achc_dn;
	dsl_co_ldap.imc_len_dn  = dsc_authinfo.dsc_conf.inc_len_dn;
	dsl_co_ldap.iec_sear_scope = ied_sear_basedn;
#endif

	bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_co_ldap );
	if( !bol_ret ){ 
		return false; 
	}
    if (( dsl_co_ldap.iec_ldap_resp  != ied_ldap_success ) && ( dsl_co_ldap.iec_ldap_resp  != ied_ldap_no_results )) {
		if (dsl_co_ldap.ac_errmsg != NULL) {
			if (dsl_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_co_ldap.ac_errmsg);
			}
			else {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_co_ldap.imc_len_errmsg, dsl_co_ldap.ac_errmsg);
			}
		}
	}

	/* save the results, otherwise they are lost with the next LDAP call! */
	adsl_attr_current = m_hobte_save_groups( &dsl_co_ldap );

	/* loop through all group memberships and give the cn to the function */
	/* maybe todo: check tree of every group */
	while( adsl_attr_current != NULL )
	{
		m_hobte_read_config( adsl_attr_current->ac_val, adsl_attr_current->imc_len_val, &dsl_configs );
		adsl_attr_current = adsl_attr_current->adsc_next_val;
	}

#endif
	/*---------------------------------------*/
	/* add all collected configuration names */
	/*---------------------------------------*/
	if( !dsl_configs.m_empty() )
	{
		adsp_auth->adsc_out_usr->m_hobte_set_configs( &dsl_configs );
	}
	
	adsc_wsp_helper->m_del_storage_cont( &dsc_stor_hobte );
	return true;
}


bool ds_authenticate::m_hobte_read_config( const char *achp_dn, int inp_len_dn, ds_hvector<ds_hobte_conf> *adsp_configs )
{
    struct dsd_ldap_val			*adsl_value;            /* attribute value        */
    char						*achl_own;              /* own hobte configuration  */
	ds_xml						dsl_xml_parser;			/* get a XML parser class */
	//dsd_xml_tag					*adsl_node;
	ds_hobte_conf				dsl_hobte_conf;
	bool						bol_found = false;

    /*
        read hobte settings
        -> there can be only one value, since we have no
           multivalued attributes
    */
    adsl_value = m_get_attribute( achp_dn,
                                  inp_len_dn,
                                  DEF_ATTR_HOBTE_CONFIG,
                                  (int)sizeof(DEF_ATTR_HOBTE_CONFIG) - 1 );




    if( adsl_value == NULL )
	{
		achl_own = NULL;
		return false;
	}

    achl_own = (char*)m_aux_stor_alloc( &dsc_stor_hobte, adsl_value->imc_len_val );
    if( achl_own == NULL )
	{
		adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HAUTHE600E cannot get memory to store hobte configuraton from '%.*s'",
                                 inp_len_dn,
                                 achp_dn );
        return false;
    }
    memcpy( (void*)achl_own, adsl_value->ac_val, adsl_value->imc_len_val );

	dsl_xml_parser.m_init( adsc_wsp_helper ); // wsp helper provides memory management
	 dsd_xml_tag * ads_jterm_root = dsl_xml_parser.m_from_xml( achl_own, adsl_value->imc_len_val );

	/* return false, if there is no data available */
	if( ads_jterm_root == NULL || ads_jterm_root->ads_child == NULL ){ return false; }	

    // it the structure is not valid return exception
    if (memcmp(ads_jterm_root->ach_data, "root", ads_jterm_root->in_len_data) != 0) {
        adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d invalid jterm config found for DN \"%.*s\" root:\"%.*s\"",
            __LINE__, inp_len_dn,achp_dn,ads_jterm_root->in_len_data, ads_jterm_root->ach_data );
        return false;
    }

    //get the Sessions attribute
    const char *ach_tmp_value;
    int im_tmp_len;
    dsd_xml_tag* adsl_sessions = dsl_xml_parser.m_get_value(ads_jterm_root, "Sessions", &ach_tmp_value, &im_tmp_len);
    if (!adsl_sessions)
    {
         adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d no Sessions found for DN \"%.*s\"",
            __LINE__, inp_len_dn,achp_dn );
        return false;
    }

    /*const char* ach_display_value;
    int im_display_len;*/
    dsd_xml_tag* adsl_display = dsl_xml_parser.m_get_value(adsl_sessions, "Display", &ach_tmp_value, &im_tmp_len);
    if (!adsl_display)
    {
        adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d no Display Session found for DN \"%.*s\"",
            __LINE__, inp_len_dn,achp_dn );
        return false;
    }
    dsd_xml_tag* adsl_next_session = adsl_display->ads_child;
    
    if (!adsl_display)
    {
        adsc_wsp_helper->m_logf( ied_sdh_log_warning, "ds_authenticate l%05d no JTerm Display Sessions found",__LINE__);
        return false;
    }
    
    const char* ach_ssname_value;
    int im_ssname_len;

    //get the schemes - needed for the protocol type
    
    dsd_xml_tag* adsl_schemes = dsl_xml_parser.m_get_value(ads_jterm_root, "Schemes", &ach_tmp_value, &im_tmp_len);
    if (!adsl_schemes)
    {
        adsc_wsp_helper->m_logf( ied_sdh_log_warning, "ds_authenticate l%05d no JTerm Schemes found",__LINE__);
        return false;
    }

    while (adsl_next_session)
    {
        
        dsd_xml_tag* adsl_session_name = dsl_xml_parser.m_get_value(adsl_next_session, "SSName", &ach_ssname_value, &im_ssname_len);
        //compare
        if (adsl_session_name)
        {
            dsl_hobte_conf.m_set_name(ach_ssname_value,im_ssname_len);

            //get the connection ID for the session
            const char* ach_sconnid_value;
            int im_sconnid_len;
            dsd_xml_tag* adsl_connection = dsl_xml_parser.m_get_value(adsl_next_session, "Connection", &ach_sconnid_value, &im_sconnid_len);

            //LO_Connection not taken into consideration!

            if (!adsl_connection || !ach_sconnid_value || im_sconnid_len == 0)
            {      
                //skip session if no connection is specified
                adsc_wsp_helper->m_logf( ied_sdh_log_warning, "ds_authenticate l%05d  no connection found for session: \"%.*s\" ",
                    __LINE__, im_ssname_len, ach_ssname_value );
            }
            else
            {
                //Connection attribute in the Schemes
                dsd_xml_tag* adsl_connection2 = dsl_xml_parser.m_get_value(adsl_schemes, "Connection", &ach_tmp_value, &im_tmp_len);
				if(adsl_connection2 == NULL)
					goto LBL_NEXT_SESSION;
                dsd_xml_tag* adsl_next_scheme = adsl_connection2->ads_child;

                bol_found = FALSE;      

                while (adsl_next_scheme != NULL)
                {
                    //compare current connection scheme name and connection name from session
                    if (adsl_next_scheme->in_len_data == im_sconnid_len+2 &&
                        adsl_next_scheme->ach_data[0] == '_' && 
                        adsl_next_scheme->ach_data[1] == '_' &&
                        !memcmp(&(adsl_next_scheme->ach_data[2]),ach_sconnid_value,adsl_next_scheme->in_len_data-2) )
                    {
                        bol_found = TRUE;
                        break;
                    }

                    adsl_next_scheme = adsl_next_scheme->ads_next;
                }

				if(!bol_found)
					goto LBL_NEXT_SESSION;

                dsd_xml_tag* adsl_subprotocol = dsl_xml_parser.m_get_value(adsl_next_scheme, "SubConnType", &ach_tmp_value, &im_tmp_len);

                if (adsl_subprotocol)
                {
                    dsl_hobte_conf.m_set_subprotocol(ach_tmp_value,im_tmp_len);

                    //we only add the session if we found the connection and the subprotocol 
                    adsp_configs->m_add( dsl_hobte_conf );//M.S. 20161024: m_add makes a copy (otherwise this wouldn't work)
                }
            }
        }
LBL_NEXT_SESSION:
        //next session
        adsl_next_session = adsl_next_session->ads_next;
    }
        
	m_aux_stor_free( &dsc_stor_hobte, (void*)achl_own );

	return true;
} /* end of ds_authenticate::m_hobte_read_config */

struct dsd_ldap_val* ds_authenticate::m_hobte_save_groups( dsd_co_ldap_1 *adsp_co_ldap )
{
	char					*achl_own;
	struct dsd_ldap_val		*adsl_attr_start = 0;
	struct dsd_ldap_val		*adsl_attr_current = 0;
	struct dsd_ldap_val		*adsl_attr_old = 0;

	adsl_attr_current = adsp_co_ldap->adsc_memship_desc;

	while( adsl_attr_current != NULL )
	{
		/* get some memory from our container */
		achl_own = (char*)m_aux_stor_alloc( &dsc_stor_hobte, sizeof( struct dsd_ldap_val ) + adsl_attr_current->imc_len_val );
		if( achl_own == NULL ){ return NULL; }
		
		/* save our data, otherwise it will be lost with the next LDAP call */
		memcpy( achl_own, adsl_attr_current, sizeof ( struct dsd_ldap_val ) );
		memcpy( achl_own + sizeof( struct dsd_ldap_val ), adsl_attr_current->ac_val , adsl_attr_current->imc_len_val );

		/* create linked list */
		if( adsl_attr_start == NULL )
		{
			adsl_attr_start	= ( struct dsd_ldap_val* )achl_own;
			adsl_attr_start->ac_val = (char*)( achl_own + sizeof( struct dsd_ldap_val ) ); /* data is stored in the memory behind the structure */
		}
		else{ adsl_attr_old->adsc_next_val = ( struct dsd_ldap_val* )achl_own; }
		
		adsl_attr_old = ( struct dsd_ldap_val* )achl_own;
		adsl_attr_old->ac_val = (char*)( achl_own + sizeof( struct dsd_ldap_val ) ); /* data is stored in the memory behind the structure */

		adsl_attr_current = adsl_attr_current->adsc_next_val;
	}

	return adsl_attr_start;
}

//end HOBTE config
#endif
/*! \brief Searches all available JWT SA configs
 *
 * private function ds_authenticate::m_jwtsa_find_configs
 * this function connects to LDAP and searches the users tree and
 * his group memberships for configurations of JWTSA
 *
 * @param[in]	dsd_auth_t *adsp_auth		authentication structure
 * @return      bool						reading of the configuration successful?
*/
bool ds_authenticate::m_jwtsa_find_configs( dsd_auth_t* adsp_auth )
{
	dsd_co_ldap_1					dsl_co_ldap;
	bool							bol_ret;
	ds_hvector<ds_jwtsa_conf>		dsl_configs;
	struct dsd_ldap_val				*adsl_attr_current = NULL;
	int								iml_offset = 0;

	adsc_wsp_helper->m_new_storage_cont( &dsc_stor_jwtsa, JWTSA_STORAGE_SIZE );
	dsl_configs.m_init( adsc_wsp_helper );

	/*----------*/
	/* OWN 		*/
	/*----------*/
	m_jwtsa_read_config( dsc_authinfo.dsc_conf.achc_dn, dsc_authinfo.dsc_conf.inc_len_dn, &dsl_configs );

	/*----------*/
	/* TREE		*/
	/*----------*/
	while( iml_offset < dsc_authinfo.dsc_conf.inc_len_dn )
	{
		if( *(dsc_authinfo.dsc_conf.achc_dn + iml_offset) == ',' )
		{
			++iml_offset;
			m_jwtsa_read_config(	dsc_authinfo.dsc_conf.achc_dn + iml_offset,
									dsc_authinfo.dsc_conf.inc_len_dn - iml_offset,
									&dsl_configs );
		}
		++iml_offset;
	}

	/*----------*/
	/* GROUPS	*/
	/*----------*/
	/* prepare LDAP access */
	memset( &dsl_co_ldap, 0, sizeof( dsd_co_ldap_1 ) );

#ifdef OLD_LDAP_CALL_FOR_GROUP_MEMBERSHIP
	dsl_co_ldap.ac_dn = NULL;
	dsl_co_ldap.imc_len_dn = 0;
	dsl_co_ldap.iec_co_ldap = ied_co_ldap_get_membership;   
    dsl_co_ldap.iec_sear_scope = ied_sear_root;
#else
    dsl_co_ldap.iec_co_ldap = ied_co_ldap_get_membership_nested;
	dsl_co_ldap.iec_chs_dn  = ied_chs_utf_8;
    dsl_co_ldap.ac_dn       = (char*)dsc_authinfo.dsc_conf.achc_dn;
	dsl_co_ldap.imc_len_dn  = dsc_authinfo.dsc_conf.inc_len_dn;
	dsl_co_ldap.iec_sear_scope = ied_sear_basedn;
#endif

	bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_co_ldap );
	if( !bol_ret ){ 
		return false; 
	}
    if (( dsl_co_ldap.iec_ldap_resp  != ied_ldap_success ) && ( dsl_co_ldap.iec_ldap_resp  != ied_ldap_no_results )) {
		if (dsl_co_ldap.ac_errmsg != NULL) {
			if (dsl_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_co_ldap.ac_errmsg);
			}
			else {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_co_ldap.imc_len_errmsg, dsl_co_ldap.ac_errmsg);
			}
		}
	}

	/* save the results, otherwise they are lost with the next LDAP call! */
	adsl_attr_current = m_jwtsa_save_groups( &dsl_co_ldap );

	/* loop through all group memberships and give the cn to the function */
	/* maybe todo: check tree of every group */
	while( adsl_attr_current != NULL )
	{
		m_jwtsa_read_config( adsl_attr_current->ac_val, adsl_attr_current->imc_len_val, &dsl_configs );
		adsl_attr_current = adsl_attr_current->adsc_next_val;
	}

	/*---------------------------------------*/
	/* add all collected configuration names */
	/*---------------------------------------*/
	if( !dsl_configs.m_empty() )
	{
		adsp_auth->adsc_out_usr->m_jwtsa_set_configs( &dsl_configs );
	}
	
	adsc_wsp_helper->m_del_storage_cont( &dsc_stor_jwtsa );
	return true;
}

/*! \brief checks if the configuration is active
 *
 * private function ds_authenticate::m_jwtsa_config_active
 *
 * @param[in]	dsd_xml_tag* adsp_pnode		xml string with the configuration
 * @return      bool						active?
*/
bool ds_authenticate::m_jwtsa_config_active( dsd_xml_tag* adsp_pnode )
{
	ds_xml          dsl_xml;							/* XML parsing									*/
	const char			*achl_name;							/* the config name								*/
	int             inl_len_name;						/* len of the config name						*/
	dsd_xml_tag		*adsl_temp_tag;						/* check return value of the xml parser			*/

	dsl_xml.m_init( adsc_wsp_helper );

	adsl_temp_tag = dsl_xml.m_get_value(	adsp_pnode,
											JWTSA_ACTIVE,
											&achl_name,
											&inl_len_name );

	if( adsl_temp_tag == NULL || achl_name == NULL ){ return false; }

    int imp_result;
    if(!m_cmpi_u8l_u8l(&imp_result, JWTSA_YES, sizeof(JWTSA_YES)-1, (char*)achl_name, inl_len_name))
        return false;
    return imp_result == 0;
#if 0
	/* convert every letter to lowercase */
	for( int i = 0; i < inl_len_name; i++ ){
		achl_name[i] = (char)tolower( achl_name[i] );
	}

	/* check if value is YES */
	if( memcmp( achl_name, JWTSA_YES, inl_len_name ) == 0 ){ return true; }
	return false;
#endif
}

/*! \brief get jwt configuration from LDAP server and store it
 *
 * private function ds_authenticate::m_jwtsa_read_config
 *
 * @param[in]	dsd_auth_t *adsp_auth		authentication structure
 * @return      bool
*/
bool ds_authenticate::m_jwtsa_read_config( const char *achp_dn, int inp_len_dn, ds_hvector<ds_jwtsa_conf> *adsp_configs )
{
    struct dsd_ldap_val			*adsl_value;            /* attribute value        */
    char						*achl_own;              /* own jwt configuration  */
	ds_xml						dsl_xml_parser;			/* get a XML parser class */
	dsd_xml_tag					*adsl_node;
	ds_jwtsa_conf				dsl_jwtsa_conf;
	bool						bol_found = false;

    /*
        read jwtsa settings
        -> there can be only one value, since we have no
           multivalued attributes
    */
    adsl_value = m_get_attribute( achp_dn,
                                  inp_len_dn,
                                  DEF_ATTR_JWT_CONFIG,
                                  (int)sizeof(DEF_ATTR_JWT_CONFIG) - 1 );

    if( adsl_value == NULL )
	{
		achl_own = NULL;
		return false;
	}

    achl_own = (char*)m_aux_stor_alloc( &dsc_stor_jwtsa, adsl_value->imc_len_val );
    if( achl_own == NULL )
	{
		adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HAUTHE600E cannot get memory to store jwt configuraton from '%.*s'",
                                 inp_len_dn,
                                 achp_dn );
        return false;
    }
    memcpy( (void*)achl_own, adsl_value->ac_val, adsl_value->imc_len_val );

	dsl_xml_parser.m_init( adsc_wsp_helper ); // wsp helper provides memory management
	adsl_node = dsl_xml_parser.m_from_xml( achl_own, adsl_value->imc_len_val );

	/* return false, if there is no data available */
	if( adsl_node == NULL || adsl_node->ads_child == NULL ){ return false; }
	
	/* from <jwtsa-cfg> to <session-list> */
	adsl_node = adsl_node->ads_child;
	while( adsl_node != NULL )
	{
		/* check if we have a valid entry */
		if( memcmp( adsl_node->ach_data, JWTSA_SESSION_LIST, adsl_node->in_len_data ) == 0 )
		{
			bol_found = true; /* yes we have! */
			break;
		}
		adsl_node = adsl_node->ads_next;
	}
	if( !bol_found ){ return false; }

	/* from <session-list> to <session-entry> */
	adsl_node = adsl_node->ads_child;

	/* loop through all available nodes*/	
	while( adsl_node != NULL )
	{
		/* check if data is still a session entry */
		if( memcmp( adsl_node->ach_data, JWTSA_SESSION_ENTRY, adsl_node->in_len_data ) != 0 )
		{
			return false;
		}
		
		/* check if the configuration is active */
		bol_found = m_jwtsa_config_active( adsl_node );
		if( !bol_found )
		{
			adsl_node = adsl_node->ads_next;
			continue;
		}

		/* adsl_node is now surely pointing to a <session-entry> */
		bol_found = dsl_jwtsa_conf.m_from_xml( adsl_node );
		
		/* no valid name found */
		if( !bol_found ){ return false; }

		/* add it to the vector */
		adsp_configs->m_add( dsl_jwtsa_conf );

		/* and get next node */
		adsl_node = adsl_node->ads_next;
	}

	m_aux_stor_free( &dsc_stor_jwtsa, (void*)achl_own );

	return true;
} /* end of ds_authenticate::m_jwtsa_read_config */

/**
 * private function ds_authenticate::m_insert_objectclass
 *
 * @param[in]   const char  *achp_oclass        object class
 * @param[in]   const char  *achp_dn            dn
 * @param[in]   int         inp_length          length of dn
 * @return      bool
*/
bool ds_authenticate::m_insert_objectclass( const char *achp_oclass,
                                            const char *achp_dn, int inp_length )
{
    bool                      bol_ret;          /* return for sev. funcs */
    struct dsd_co_ldap_1      dsl_ldap;         /* ldap structure        */
    struct dsd_ldap_attr_desc dsl_attr_desc;    /* ldap attribute descr  */
    struct dsd_ldap_attr      dsl_attr;         /* ldap attribute itself */

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap    = ied_co_ldap_modify;
    dsl_ldap.adsc_attr_desc = &dsl_attr_desc;

    memset( &dsl_attr_desc, 0, sizeof(struct dsd_ldap_attr_desc) );
    dsl_attr_desc.ac_dn      = (char*)achp_dn;
    dsl_attr_desc.imc_len_dn = inp_length;
    dsl_attr_desc.iec_chs_dn = ied_chs_utf_8;
    dsl_attr_desc.adsc_attr  = &dsl_attr;

    memset( &dsl_attr, 0, sizeof(struct dsd_ldap_attr) );
    dsl_attr.ac_attr             = (char*)"objectclass";
    dsl_attr.imc_len_attr        = -1;
    dsl_attr.iec_chs_attr        = ied_chs_utf_8;
    dsl_attr.dsc_val.ac_val      = (char*)achp_oclass;
    dsl_attr.dsc_val.imc_len_val = -1;
    dsl_attr.dsc_val.iec_chs_val = ied_chs_utf_8;

    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
    if (    bol_ret                == true
         && (   dsl_ldap.iec_ldap_resp == ied_ldap_success 
		     || dsl_ldap.iec_ldap_resp == ied_ldap_attr_or_val_exist )) {
        return true;
    }
	if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
		if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
			adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
		}
		else {
			adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
		}
	}
    return false;
} // end of ds_authenticate::m_insert_objectclass


/**
 * private function ds_authenticate::m_explode_dn
 *
 * @param[in]   dsd_stor_sdh_1      *adsp_stor  storage container
 * @param[in]   const char          *achp_dn    ptr to orginal dn
 * @param[in]   int                 inp_length  length of dn
 * @return      dsd_ldap_attr_desc*             exploded dn
 *                                              null in error cases
*/
struct dsd_ldap_attr_desc* ds_authenticate::m_explode_dn( struct dsd_stor_sdh_1 *adsp_stor,
                                                          const char *achp_dn, int inp_length )
{
    bool                      bol_ret;          /* return for sev. funcs */
    struct dsd_co_ldap_1      dsl_ldap;         /* ldap structure        */

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap          = ied_co_ldap_explode_dn;
    if ( adsp_stor != NULL ) {
		dsl_ldap.amc_aux = m_ldap_request_aux;
		dsl_ldap.vpc_userfld = adsp_stor;
    }
    dsl_ldap.iec_chs_dn           = ied_chs_utf_8;
    dsl_ldap.imc_len_dn           = inp_length;
    dsl_ldap.ac_dn                = (char*)achp_dn;
    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
    if (    bol_ret                 == false
         || dsl_ldap.adsc_attr_desc == NULL
         || dsl_ldap.iec_ldap_resp  != ied_ldap_success ) {
		if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
			if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
			}
			else {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
			}
		}
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HAUTHE221E clone dn failed - cannot explode dn '%.*s'",
                                 inp_length, achp_dn );
        return NULL;
    }
    return dsl_ldap.adsc_attr_desc;
} // end of ds_authenticate::m_explode_dn


/**
 * private function ds_authenticate::m_get_group_dns
 *
 * @param[in]   dsd_stor_sdh_1      *adsp_stor      storage container
 * @param[in]   dsd_ldap_attr       *adsp_groups    groups
 * @param[out]  int                 *ainp_count     number of groups
 * @return      dsd_ldap_attr_desc*                 exploded dns
 *                                                  null in error cases
*/
struct dsd_ldap_groups* ds_authenticate::m_get_group_dns( struct dsd_stor_sdh_1 *adsp_stor,
                                                          struct dsd_ldap_attr  *adsp_groups,
                                                          int *ainp_count )
{
    struct dsd_ldap_val     *adsl_loop;         /* loop variable         */
    struct dsd_ldap_groups  *adsl_out;          /* return value          */
    struct dsd_ldap_groups  *adsl_insert;       /* insert position       */
#ifdef SH_NESTED_GROUPS
	int inl_sum_dn_len;
	char *achl_dn_cur;
#endif

    /*
        count groups
    */
    *ainp_count = 0;
#ifdef SH_NESTED_GROUPS
	inl_sum_dn_len = 0;
#endif
    adsl_loop   = &adsp_groups->dsc_val;
    while ( adsl_loop != NULL ) {
        (*ainp_count)++;
#ifdef SH_NESTED_GROUPS
		inl_sum_dn_len += adsl_loop->imc_len_val;
#endif
        adsl_loop = adsl_loop->adsc_next_val;
    }

    /*
        alocate memory
    */
#ifdef SH_NESTED_GROUPS
    adsl_out = (struct dsd_ldap_groups*) m_aux_stor_alloc( adsp_stor,
                                                           (*ainp_count) * (int)sizeof(struct dsd_ldap_groups) 
														   + inl_sum_dn_len);
#else
    adsl_out = (struct dsd_ldap_groups*) m_aux_stor_alloc( adsp_stor,
                                                             (*ainp_count)
                                                           * (int)sizeof(struct dsd_ldap_groups) );
#endif
    if ( adsl_out == NULL ) {
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HAUTHE222E cannot get memory for group dns" );
        return NULL;
    }

#ifdef SH_NESTED_GROUPS
    adsl_insert = adsl_out;
	achl_dn_cur = (char*) adsl_out + (*ainp_count) * (int)sizeof(struct dsd_ldap_groups);
    adsl_loop   = &adsp_groups->dsc_val;
    while ( adsl_loop != NULL ) {
		memset(adsl_insert, 0, sizeof(struct dsd_ldap_groups));
        adsl_insert->achc_dn = achl_dn_cur;
		achl_dn_cur += adsl_loop->imc_len_val;
        memcpy( (void*)adsl_insert->achc_dn, adsl_loop->ac_val, adsl_loop->imc_len_val );
        adsl_insert->inc_len_dn = adsl_loop->imc_len_val;
		adsl_insert->boc_direct = TRUE;

        adsl_insert++;
        adsl_loop = adsl_loop->adsc_next_val;
    }
#else
    adsl_insert = adsl_out;
    adsl_loop   = &adsp_groups->dsc_val;
    while ( adsl_loop != NULL ) {
        adsl_insert->achc_dn = (const char*) m_aux_stor_alloc( adsp_stor, adsl_loop->imc_len_val );
        if ( adsl_insert->achc_dn == NULL ) {
            adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                     "HAUTHE223E cannot get memory for group dn '%.*s'",
                                     adsl_loop->imc_len_val, adsl_loop->ac_val );
            return NULL;
        }

        memcpy( (void*)adsl_insert->achc_dn, adsl_loop->ac_val, adsl_loop->imc_len_val );
        adsl_insert->inc_len_dn = adsl_loop->imc_len_val;

        adsl_insert++;
        adsl_loop = adsl_loop->adsc_next_val;
    }
#endif
    return adsl_out;
} // end of ds_authenticate::m_get_group_dns


/**
 * private function ds_authenticate::m_explode_groups
 *
 * @param[in]   dsd_stor_sdh_1      *adsp_stor      storage container
 * @param[in]   dsd_ldap_attr       *adsp_groups    groups
 * @param[in]   int                 inp_count       number of groups
 * @return      dsd_ldap_attr_desc*                 exploded dns
 *                                                  null in error cases
*/
struct dsd_ldap_attr_desc* ds_authenticate::m_explode_groups( struct dsd_stor_sdh_1 *adsp_stor,
                                                              struct dsd_ldap_attr  *adsp_groups,
                                                              int inp_count )
{
    int                         inl_count;      /* loop variable         */
    struct dsd_ldap_val         *adsl_loop;     /* loop variable         */
    struct dsd_ldap_attr_desc   *adsl_out;      /* return value          */
    struct dsd_ldap_attr_desc   *adsl_insert;   /* insert position       */

    /*
        allocate memory for all exploded dns
    */
    adsl_out = (struct dsd_ldap_attr_desc*) m_aux_stor_alloc( adsp_stor,
                                                                inp_count
                                                              * (int)sizeof(struct dsd_ldap_attr_desc) );
    if ( adsl_out == NULL ) {
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HAUTHE224E cannot get memory for exploding group dns" );
        return NULL;
    }

    adsl_insert = adsl_out;
    inl_count   = 0;
    adsl_loop   = &adsp_groups->dsc_val;
    while (    adsl_loop != NULL
            && inl_count < inp_count ) {
        *adsl_insert = *m_explode_dn( adsp_stor, adsl_loop->ac_val,
                                      adsl_loop->imc_len_val );
        adsl_insert++;
        inl_count++;
        adsl_loop = adsl_loop->adsc_next_val;
    }
    return adsl_out;
} // end of ds_authenticate::m_explode_groups

                                                              
/**
 * private function ds_authenticate::m_explode_groups
 *
 * @param[in]   dsd_stor_sdh_1      *adsp_stor      storage container
 * @param[in]   dsd_ldap_group      *adsp_groups    groups
 * @param[in]   int                 inp_count       number of groups
 * @return      dsd_ldap_attr_desc*                 exploded dns
 *                                                  null in error cases
*/
struct dsd_ldap_attr_desc* ds_authenticate::m_explode_groups( struct dsd_stor_sdh_1 *adsp_stor,
                                                              struct dsd_ldap_groups *adsp_groups,
                                                              int inp_count )
{
    int                         inl_count;      /* loop variable         */
    struct dsd_ldap_attr_desc   *adsl_out;      /* return value          */
    struct dsd_ldap_attr_desc   *adsl_insert;   /* insert position       */

    /*
        allocate memory for all exploded dns
    */
    adsl_out = (struct dsd_ldap_attr_desc*) m_aux_stor_alloc( adsp_stor,
                                                                inp_count
                                                              * (int)sizeof(struct dsd_ldap_attr_desc) );
    if ( adsl_out == NULL ) {
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HAUTHE225E cannot get memory for exploding group dns" );
        return NULL;
    }

    adsl_insert = adsl_out;
#define ADSL_CUR_GROUP (adsp_groups + inl_count)
    for ( inl_count = 0; inl_count < inp_count; inl_count++ ) {
        *adsl_insert = *m_explode_dn( adsp_stor,
                                      ADSL_CUR_GROUP->achc_dn,
                                      ADSL_CUR_GROUP->inc_len_dn );
        adsl_insert++;
    }
#undef ADLS_CUR_GROUP
    return adsl_out;
} // end of ds_authenticate::m_explode_groups

/**
 * private function ds_authenticate::m_clone_ext_user
 *  clone user from external authentication method (nonLDAP)
 *
 * @param[in]   dsd_stor_sdh_1      *adsp_stor      storage container
 * @param[in]   const char          *achp_user      user name
 * @param[in]   int                 inp_len_user    length of username
 * @param[out]  char                **aachp_ndn     new created dn
 * @param[out]  int                 *ainp_len_ndn   length of created dn
 * @return      bool                                true = success
 *                                                  false otherwise
*/
bool ds_authenticate::m_clone_ext_user( struct dsd_stor_sdh_1 *adsp_stor,
                                        const char *achp_user, int inp_len_user,
                                        char **aachp_ndn, int *ainp_len_ndn,
                                        struct dsd_domain *adsp_domain )
{
    struct dsd_ldap_attr_desc dsl_user;         /* user port of dn       */
    struct dsd_ldap_attr_desc dsl_base;         /* base part of dn       */
    ds_hstring dsl_user_rdn( adsc_wsp_helper ); /* user relative dn      */

    if ( dsc_authinfo.dsc_conf.adsc_lconf->imc_len_upref > 0 ) {
        dsl_user_rdn.m_writef( "%.*s=%.*s",
                               dsc_authinfo.dsc_conf.adsc_lconf->imc_len_upref,
                               dsc_authinfo.dsc_conf.adsc_lconf->achc_upref,
                               inp_len_user, achp_user );
    } else {
        dsl_user_rdn.m_writef( "cn=%.*s", inp_len_user, achp_user );
    }

    memset( &dsl_user, 0, sizeof(struct dsd_ldap_attr_desc) );
    dsl_user.ac_dn      = const_cast<char*>(dsl_user_rdn.m_get_ptr());
    dsl_user.imc_len_dn = dsl_user_rdn.m_get_len();
    dsl_user.iec_chs_dn = ied_chs_utf_8;
    
    memset( &dsl_base, 0, sizeof(struct dsd_ldap_attr_desc) );
    if ( dsc_authinfo.dsc_conf.inc_len_basedn > 0 ) {
        dsl_base.ac_dn      = (char*)dsc_authinfo.dsc_conf.achc_basedn;
        dsl_base.imc_len_dn = dsc_authinfo.dsc_conf.inc_len_basedn;
        dsl_base.iec_chs_dn = ied_chs_utf_8;
    }
    dsl_user.adsc_next_attr_desc = &dsl_base;

    
    /* the additional base will be added inside m_clone_dn! */
    return m_clone_dn( adsp_stor, &dsl_user, ied_objectclass_person,
                       aachp_ndn, ainp_len_ndn, adsp_domain );
} // end of ds_authenticate::m_clone_ext_user


/**
 * private function ds_authenticate::m_clone_dn
 *  clone a given dn to our configuration ldap
 *
 * @param[in]   dsd_stor_sdh_1      *adsp_stor      storage container
 * @param[in]   dsd_ldap_attr_desc  *adsp_exploded  exploded dn to clone
 * @param[in]   ied_objectclass     iep_objectclass type of object to be created
 * @param[out]  char                **aachp_ndn     new created dn
 * @param[out]  int                 *ainp_len_ndn   length of created dn
 * @return      bool                                true = success
 *                                                  false otherwise
*/
bool ds_authenticate::m_clone_dn( struct dsd_stor_sdh_1 *adsp_stor,
                                  struct dsd_ldap_attr_desc *adsp_exploded,
                                  enum ied_objectclass iep_objectclass,
                                  char **aachp_ndn, int *ainp_len_ndn,
                                  struct dsd_domain *adsp_domain )
{
    bool                      bol_ret;          /* return for sev. funcs */
    struct dsd_co_ldap_1      dsl_ldap;         /* ldap structure        */

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap          = ied_co_ldap_clone_dn;
    dsl_ldap.adsc_attr_desc       = adsp_exploded;
    if ( ainp_len_ndn != NULL ) {
		dsl_ldap.amc_aux = m_ldap_request_aux;
		dsl_ldap.vpc_userfld = adsp_stor;
	 }
    dsl_ldap.iec_objectclass      = iep_objectclass;
    if (    adsp_domain              != NULL
         && adsp_domain->inc_len_base > 0 ) {
        dsl_ldap.iec_chs_dn       = ied_chs_utf_8;
        dsl_ldap.imc_len_dn       = adsp_domain->inc_len_base;
        dsl_ldap.ac_dn            = adsp_domain->achc_base;
    }
    dsl_ldap.ac_attrlist          = (char*)"hoboc,hobphone";
    dsl_ldap.imc_len_attrlist     = (int)sizeof("hoboc,hobphone") - 1;
    dsl_ldap.iec_chs_attrlist     = ied_chs_utf_8;

    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
    if (    bol_ret                == false
         || dsl_ldap.iec_ldap_resp != ied_ldap_success ) {
		if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
			if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
			}
			else {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
			}
		}
        return false;
    }
    if ( ainp_len_ndn != NULL ) {
        *aachp_ndn     = dsl_ldap.ac_dn;
        *ainp_len_ndn = dsl_ldap.imc_len_dn;
    }
    return true;
} // end of ds_authenticate::m_clone_dn


/**
 * private function ds_authenticate::m_select_ldap
 * select ldap server by domain
 * will return false if no ldap can be selected
 *
 * @param[in]   dsd_domain          *adsp_domain        selected domain config
 * @param[in]   int                 inp_domain_auth     selected method type
 * @param[in]   int                 inp_wsp_auth        configured auth methods
 * @return      bool
*/
bool ds_authenticate::m_select_ldap( struct dsd_domain *adsp_domain,
                                     int inp_domain_auth, int inp_wsp_auth )
{
    // initialize some variables:
    bool                 bol_ret;               /* return for sev funcs  */

    /*
        reset already set ldap server
    */
    if ( inp_domain_auth == DEF_CLIB1_CONF_DYN_LDAP ) {
        m_close_ldap();
    }


    if (    adsp_domain->inc_len_ldap  > 0
         && adsp_domain->achc_ldap    != NULL ) {
        /*
            we have a corresponding ldap configured in domain
               -> select this one
                  if this is successful we are ready
                  if not configuration is wrong
        */
        bol_ret = adsc_wsp_helper->m_set_ldap_srv( adsp_domain->achc_ldap,
                                                   adsp_domain->inc_len_ldap );
        if ( bol_ret == true ) {
            return true;
        }
    }

    /*
        we have no corrensponding ldap configured
        or select failed
    */
    switch ( inp_domain_auth ) {
        case DEF_CLIB1_CONF_RADIUS:
        case DEF_CLIB1_CONF_USERLI:
            /*
                if there are one ldap server configured
                we select the one and only ldap server
                otherwise we cannot go on
            */
            if ( (inp_wsp_auth & DEF_CLIB1_CONF_DYN_LDAP) != DEF_CLIB1_CONF_DYN_LDAP ) {
                return adsc_wsp_helper->m_cb_set_ldap_srv( 0 );
            }
            return false;

        case DEF_CLIB1_CONF_KRB5:
        case DEF_CLIB1_CONF_DYN_KRB5:
            /*
                we use the wsp configuration "corresponding-LDAP-service"
                WSP should select LDAP by itself
            */
            return true;

        case DEF_CLIB1_CONF_LDAP:
        case DEF_CLIB1_CONF_DYN_LDAP:
            /*
                we use the same ldap server we have used for authentication
            */
            return adsc_wsp_helper->m_set_ldap_srv( adsp_domain->achc_name,
                                                    adsp_domain->inc_len_name );
    }
    return false;
} // end of ds_authenticate::m_select_ldap


/**
 * private function ds_authenticate::m_close_ldap
*/
void ds_authenticate::m_close_ldap()
{
    bool                 bol_ret;               /* return for sev funcs  */
    struct dsd_co_ldap_1 dsl_ldap;              /* ldap structure        */

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap    = ied_co_ldap_close;
    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
    //if (    bol_ret                == false
    //     || dsl_ldap.iec_ldap_resp != ied_ldap_success ) {
    //    adsc_wsp_helper->m_logf( ied_sdh_log_error,
    //                             "HAUTHE226E closing ldap connection failed" );
    //}
    adsc_wsp_helper->m_reset_ldap_srv();
} // end of ds_authenticate::m_close_ldap


/**
 * private function ds_authenticate::m_prepare_ldap
 * prepare ldap connection for saving some data for user
 *
 * @param[in]   dsd_auth_t      *adsp_auth      pointer to authentication input structure
 * @param[in]   dsd_getuser     *adsp_user      user information 
 * @return      bool                            true = success    
*/
bool ds_authenticate::m_prepare_ldap( dsd_auth_t* adsp_auth, dsd_getuser *adsp_user )
{
    // initialize some variables:
    bool                 bol_ret;               /* return for some funcs */
    int                  inl_domain_auth;       /* selected auth method  */
    int                  inl_wsp_auth;          /* configured auth meth. */
    struct dsd_domain    *adsl_domain;          /* domain configuration  */
    dsd_wspat_pconf_t    *adsl_wspat_conf;      /* wspat configuration   */
    struct dsd_co_ldap_1 dsl_ldap;              /* ldap command struct   */
    ds_hstring           dsl_pwd;               /* user password         */

    //-------------------------------------------
    // get configured and selected auth methods:
    //-------------------------------------------
    inl_wsp_auth    = adsc_wsp_helper->m_get_wsp_auth();
    enum ied_usercma_login_flags iel_auth_flags;
    inl_domain_auth = adsp_auth->adsc_out_usr->m_get_authmethod(iel_auth_flags);
    adsl_domain     = adsp_auth->adsc_out_usr->m_get_domain();
    if ( adsl_domain == NULL ) {
        /*
            we were not able to read domain configuration
            (case of kickout)
            so we will search it by hand:
        */
        adsl_wspat_conf = adsc_wsp_helper->m_get_wspat_config();
        if ( adsl_wspat_conf == NULL ) {
            return false;
        }
        adsl_domain = adsl_wspat_conf->dsc_domains.adsc_domain;
        while ( adsl_domain != NULL ) {
            if ( adsp_user->dsc_userdomain.m_equals( adsl_domain->achc_disp_name,
                                                     adsl_domain->inc_len_disp_name) ) {
                break;
            }
            adsl_domain = adsl_domain->adsc_next;
        }
        if ( adsl_domain == NULL ) {
            // not found
            return false;
        }
    }

    //-------------------------------------------
    // select configuration ldap:
    //-------------------------------------------
    bol_ret = m_select_ldap( adsl_domain, inl_domain_auth, inl_wsp_auth );
    if ( bol_ret == false ) {
        return false;
    }

    //-------------------------------------------
    // bind to ldap:
    //-------------------------------------------
    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap = ied_co_ldap_bind;
    if ( adsl_domain->boc_ldap_eq_name == false
#if SM_USE_CERT_AUTH
        || (iel_auth_flags & ied_usercma_login_cert_auth) != 0
#endif
        )
    {
        /* do an administration bind to config ldap */
        if ( adsl_domain->inc_len_dn_admin > 0 ) {
            dsl_ldap.iec_ldap_auth  = ied_auth_dn;
            dsl_ldap.ac_userid      = adsl_domain->achc_dn_admin;
            dsl_ldap.imc_len_userid = adsl_domain->inc_len_dn_admin;
            dsl_ldap.iec_chs_userid = ied_chs_utf_8;
            dsl_ldap.ac_passwd      = adsl_domain->achc_pwd_admin;
            dsl_ldap.imc_len_passwd = adsl_domain->inc_len_pwd_admin;
            dsl_ldap.iec_chs_passwd = ied_chs_utf_8;
        } else {
            dsl_ldap.iec_ldap_auth = ied_auth_admin;
        }
    } else {
        /* do a bind with current user to config ldap */
        dsl_pwd = adsp_auth->adsc_out_usr->m_get_password();
        dsl_ldap.iec_ldap_auth  = ied_auth_dn;
        dsl_ldap.ac_userid      = const_cast<char*>(adsp_user->dsc_userdn.m_get_ptr());
        dsl_ldap.imc_len_userid = adsp_user->dsc_userdn.m_get_len();
        dsl_ldap.iec_chs_userid = ied_chs_utf_8;
        dsl_ldap.ac_passwd      = const_cast<char*>(dsl_pwd.m_get_ptr());
        dsl_ldap.imc_len_passwd = dsl_pwd.m_get_len();
        dsl_ldap.iec_chs_passwd = ied_chs_utf_8;
    }
    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
    if (    bol_ret                     == false
         || (    dsl_ldap.iec_ldap_resp != ied_ldap_success 
              && dsl_ldap.iec_ldap_resp != ied_ldap_no_results ) ) {
		if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
			if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %s.", __LINE__, dsl_ldap.ac_errmsg);
			}
			else {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " ds_authenticate l%05d LDAP message: %.*s.", __LINE__, dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
			}
		}
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HAUTHE227E admin bind to configuration ldap failed" );
        return false;
    }
    return true;
} // end of ds_authenticate::m_prepare_ldap


/**
 * private function ds_authenticate::m_save_user_settings
 *
 * @param[in]   dsd_auth_t*      ads_auth       pointer to authentication input structure
 * @param[in]   const char*      ach_userdn     current user dn
 * @param[in]   int              in_len_dn      length of current dn
 * @return      bool                            true = success             
*/
bool ds_authenticate::m_save_user_settings( dsd_auth_t* ads_auth,
                                            dsd_getuser* ads_user )
{
    // initialize some variables:
    bool             bol_ldap;              // return from all ldap calls
    bool             bol_ret;               // return value for several functions
    int              inl_ret;               // return value for several functions
    bool             bol_main_added;        // xml main tag added?
    int              inl_pos;               // element position in cma
    int              inl_count;             // number of elements in cma
    ds_hstring       dsl_xml;               // xml data to be exported to ldap
    ds_bookmark      dsl_bmark;             // single bookmark
    dsd_wfa_bmark    dsl_wfa_bmark;         // single webfileaccess bookmark
    ds_workstation   dsl_wstat;             // single workstation
    ds_portlet       dsl_portlet;           // single portlet
    dsd_acb_language dsl_lang;              // language structure
    dsd_ldap_attr    dsl_lp_attr;           // ldap attribute list

    //---------------------------------------
    // init some variables:
    //---------------------------------------
    bol_ldap = true;
    dsl_xml.m_init      ( adsc_wsp_helper );
    dsl_bmark.m_init    ( adsc_wsp_helper );
    dsl_wfa_bmark.m_init( adsc_wsp_helper );
    dsl_wstat.m_init    ( adsc_wsp_helper );
    dsl_portlet.m_init  ( adsc_wsp_helper );

    //---------------------------------------
    // add hoboc objectclass:
    //---------------------------------------
    m_insert_objectclass( "hoboc", ads_user->dsc_userdn.m_get_ptr(),
                                   ads_user->dsc_userdn.m_get_len() );

    //---------------------------------------
    // setup attribute structure:
    //---------------------------------------
    memset( &dsl_lp_attr, 0, sizeof(dsl_lp_attr) );
    dsl_lp_attr.imc_len_attr        = -1; // sign for zero termination
    dsl_lp_attr.iec_chs_attr        = ied_chs_utf_8;
    dsl_lp_attr.dsc_val.iec_chs_val = ied_chs_utf_8;

    /*
        WSG-Bookmarks:
    */
    if ( ads_auth->adsc_out_usr->m_is_config_allowed(DEF_UAC_WSG_BMARKS) ) {
        bol_main_added = false;
        inl_count      = ads_auth->adsc_out_usr->m_count_wsg_bookmarks();

        for ( inl_pos = 0; inl_pos < inl_count; inl_pos++ ) {
            // get current bookmark from cma:
            bol_ret = ads_auth->adsc_out_usr->m_get_wsg_bookmark( inl_pos, &dsl_bmark );
            if (    bol_ret == true
                && dsl_bmark.m_is_own() ) {
                // add "<WSG-bookmarks>" tag if not existing yet:
                if ( bol_main_added == false ) {
                    dsl_xml.m_write_xml_open_tag(achg_us_tags[ied_us_tag_wsg_bm]);
                    dsl_xml.m_write_xml_open_tag(achg_us_tags[ied_us_tag_version]);
                    dsl_xml.m_write_int(DEF_VERS_USET_WSG_BMARKS);
                    dsl_xml.m_write_xml_close_tag(achg_us_tags[ied_us_tag_version]);
                    bol_main_added = true;
                }
                // add bookmark itself in xml:
                dsl_bmark.m_to_xml( &dsl_xml );
            }
        } // end of loop through all WSG bookmarks
                
        // add "</WSG-bookmarks>" tag if not existing yet:
        if ( bol_main_added == true ) {
            dsl_xml.m_write_xml_close_tag(achg_us_tags[ied_us_tag_wsg_bm]);
            
            // save data to ldap:
            bol_ret = m_set_attribute( ads_user->dsc_userdn.m_get_ptr(),
                                       ads_user->dsc_userdn.m_get_len(),
                                       DEF_ATTR_USET_WSG_BMARKS,
                                       (int)sizeof(DEF_ATTR_USET_WSG_BMARKS) - 1,
                                       dsl_xml.m_get_ptr(), dsl_xml.m_get_len() );
		} else {
			//delete bookmarks
            bol_ret = m_del_attribute( ads_user->dsc_userdn.m_get_ptr(),
                                       ads_user->dsc_userdn.m_get_len(),
                                       DEF_ATTR_USET_WSG_BMARKS,
                                       (int)sizeof(DEF_ATTR_USET_WSG_BMARKS) - 1,
                                       NULL, 0 ); //value ignored, because single value attribute
		}
        if ( bol_ret == false ) {
            bol_ldap = false;
            adsc_wsp_helper->m_logf( ied_sdh_log_warning, 
                                        "HAUTHW026W saving WSG-bookmarks in ldap failed" );
        }
        dsl_xml.m_reset();
    }

    /*
        RDVPN-Bookmarks:
    */
    if ( ads_auth->adsc_out_usr->m_is_config_allowed(DEF_UAC_RDVPN_BMARKS) ) {
        bol_main_added = false;
        inl_count      = ads_auth->adsc_out_usr->m_count_rdvpn_bookmarks();

        for ( inl_pos = 0; inl_pos < inl_count; inl_pos++ ) {
            // get current bookmark from cma:
            bol_ret = ads_auth->adsc_out_usr->m_get_rdvpn_bookmark( inl_pos, &dsl_bmark );
            if (    bol_ret == true
                && dsl_bmark.m_is_own() ) {
                // add "<RDVPN-bookmarks>" tag if not existing yet:
                if ( bol_main_added == false ) {
                    dsl_xml.m_write_xml_open_tag(achg_us_tags[ied_us_tag_rdvpn_bm]);
                    dsl_xml.m_write_xml_open_tag(achg_us_tags[ied_us_tag_version]);
                    dsl_xml.m_write_int(DEF_VERS_USET_WSG_BMARKS);
                    dsl_xml.m_write_xml_close_tag(achg_us_tags[ied_us_tag_version]);
                    bol_main_added = true;
                }
                // add bookmark itself in xml:
                dsl_bmark.m_to_xml( &dsl_xml );
            }
        } // end of loop through all RDVPN bookmarks
                
        // add "</RDVPN-bookmarks>" tag if opened:
        if ( bol_main_added == true ) {
            dsl_xml.m_write_xml_close_tag(achg_us_tags[ied_us_tag_rdvpn_bm]);
            
            // save data to ldap:
            bol_ret = m_set_attribute( ads_user->dsc_userdn.m_get_ptr(),
                                       ads_user->dsc_userdn.m_get_len(),
                                       DEF_ATTR_USET_RDVPN_BMARKS,
                                       (int)sizeof(DEF_ATTR_USET_RDVPN_BMARKS) - 1,
                                       dsl_xml.m_get_ptr(), dsl_xml.m_get_len() );
		} else {
			//delete bookmarks
            bol_ret = m_del_attribute( ads_user->dsc_userdn.m_get_ptr(),
                                       ads_user->dsc_userdn.m_get_len(),
                                       DEF_ATTR_USET_RDVPN_BMARKS,
                                       (int)sizeof(DEF_ATTR_USET_RDVPN_BMARKS) - 1,
                                       NULL, 0 ); //value ignored, because single value attribute
		}
        if ( bol_ret == false ) {
            bol_ldap = false;
            adsc_wsp_helper->m_logf( ied_sdh_log_warning, 
                                         "HAUTHW031W saving RDVPN-bookmarks in ldap failed" );
        }
        dsl_xml.m_reset();
    }

    
    /*
        WFA-Bookmarks:
    */
    if ( ads_auth->adsc_out_usr->m_is_config_allowed(DEF_UAC_WFA_BMARKS) ) {
        bol_main_added = false;
        inl_count      = ads_auth->adsc_out_usr->m_count_wfa_bookmarks();

        for ( inl_pos = 0; inl_pos < inl_count; inl_pos++ ) {
            // get current bookmark from cma:
            bol_ret = ads_auth->adsc_out_usr->m_get_wfa_bookmark( inl_pos, &dsl_wfa_bmark );
            if (    bol_ret == true
                && dsl_wfa_bmark.m_is_own() ) {
                // add "<WFA-bookmarks>" tag if not existing yet:
                if ( bol_main_added == false ) {
                    dsl_xml.m_write_xml_open_tag(achg_us_tags[ied_us_tag_wfa_bm]);
                    dsl_xml.m_write_xml_open_tag(achg_us_tags[ied_us_tag_version]);
                    dsl_xml.m_write_int(DEF_VERS_USET_WFA_BMARKS);
                    dsl_xml.m_write_xml_close_tag(achg_us_tags[ied_us_tag_version]);
                    bol_main_added = true;
                }
                // add bookmark itself in xml:
                dsl_wfa_bmark.m_to_xml( &dsl_xml );
            }
        } // end of loop through all WFA bookmarks
                
        // add "</WFA-bookmarks>" tag if not existing yet:
        if ( bol_main_added == true ) {
            dsl_xml.m_write_xml_close_tag(achg_us_tags[ied_us_tag_wfa_bm]);

            // save data to ldap:
            bol_ret = m_set_attribute( ads_user->dsc_userdn.m_get_ptr(),
                                       ads_user->dsc_userdn.m_get_len(),
                                       DEF_ATTR_USET_WFA_BMARKS,
                                       (int)sizeof(DEF_ATTR_USET_WFA_BMARKS) - 1,
                                       dsl_xml.m_get_ptr(), dsl_xml.m_get_len() );
        } else {
            // delete all bookmarks!
            bol_ret = m_del_attribute( ads_user->dsc_userdn.m_get_ptr(),
                                       ads_user->dsc_userdn.m_get_len(),
                                       DEF_ATTR_USET_WFA_BMARKS,
                                       (int)sizeof(DEF_ATTR_USET_WFA_BMARKS) - 1,
                                       NULL, 0 ); //value ignored, because single value attribute
        }
        if ( bol_ret == false ) {
            bol_ldap = false;
            adsc_wsp_helper->m_logf( ied_sdh_log_warning, 
                                        "HAUTHW027W saving WFA-bookmarks in ldap failed" );
        }
        dsl_xml.m_reset();
    }

    /*
        Desktop-On-Demand:
    */
    if ( ads_auth->adsc_out_usr->m_is_config_allowed(DEF_UAC_DOD) ) {
        bol_main_added = false;
        inl_count      = ads_auth->adsc_out_usr->m_count_workstations();

        for ( inl_pos = 0; inl_pos < inl_count; inl_pos++ ) {
            bol_ret = ads_auth->adsc_out_usr->m_get_workstation( inl_pos, &dsl_wstat );
            if ( bol_ret == true ) {
                // add "<desktop-on-demand>" tag if not existing yet:
                if ( bol_main_added == false ) {
                    dsl_xml.m_write_xml_open_tag(achg_us_tags[ied_us_tag_dod]);
                    dsl_xml.m_write_xml_open_tag(achg_us_tags[ied_us_tag_version]);
                    dsl_xml.m_write_int(DEF_VERS_USET_DOD);
                    dsl_xml.m_write_xml_close_tag(achg_us_tags[ied_us_tag_version]);
                    bol_main_added = true;
                }
                dsl_wstat.m_to_xml( &dsl_xml );
            }
        } // end of loop through all workstations

        // add "</desktop-on-demand>" tag if not existing yet:
        if ( bol_main_added == true ) {
            dsl_xml.m_write_xml_close_tag(achg_us_tags[ied_us_tag_dod]);

            // save data to ldap:
            bol_ret = m_set_attribute( ads_user->dsc_userdn.m_get_ptr(),
                                       ads_user->dsc_userdn.m_get_len(),
                                       DEF_ATTR_USET_DOD,
                                       (int)sizeof(DEF_ATTR_USET_DOD) - 1,
                                       dsl_xml.m_get_ptr(), dsl_xml.m_get_len() );
		} else {
			//delete bookmarks
            bol_ret = m_del_attribute( ads_user->dsc_userdn.m_get_ptr(),
                                       ads_user->dsc_userdn.m_get_len(),
                                       DEF_ATTR_USET_DOD,
                                       (int)sizeof(DEF_ATTR_USET_DOD) - 1,
                                       NULL, 0 ); //value ignored, because single value attribute
		}
        if ( bol_ret == false ) {
            bol_ldap = false;
            adsc_wsp_helper->m_logf( ied_sdh_log_warning, 
                                         "HAUTHW029W saving desktop-on-demand in ldap failed" );
        }
        dsl_xml.m_reset();
    }

    /*
        other user settings:
    */
    if ( ads_auth->adsc_out_usr->m_is_config_allowed(DEF_UAC_OTHERS) ) {
        dsl_xml.m_write_xml_open_tag(achg_us_tags[ied_us_tag_usr_sett]);
        dsl_xml.m_write_xml_open_tag(achg_us_tags[ied_us_tag_version]);
        dsl_xml.m_write_int(DEF_VERS_USET_OTHERS);
        dsl_xml.m_write_xml_close_tag(achg_us_tags[ied_us_tag_version]);

        /* portlets */
        inl_count = ads_auth->adsc_out_usr->m_count_portlets();
        if ( inl_count > 0 ) {
            dsl_xml.m_write_xml_open_tag(achg_us_tags[ied_us_tag_portlets]);
            for ( inl_pos = 0; inl_pos < inl_count; inl_pos++ ) {
                bol_ret = ads_auth->adsc_out_usr->m_get_portlet( inl_pos, &dsl_portlet );
                if ( bol_ret == true ) {
                    dsl_portlet.m_to_xml( &dsl_xml );
                }
            } // end of loop through all portlets
            dsl_xml.m_write_xml_close_tag(achg_us_tags[ied_us_tag_portlets]);
        }

        /* others */
        dsl_xml.m_write_xml_open_tag(achg_us_tags[ied_us_tag_others]);
        // flyer:
        dsl_xml.m_write_xml_open_tag(achg_us_tags[ied_us_tag_flyer]);
        dsl_xml.m_write_xml_text(ads_auth->adsc_out_usr->m_show_flyer() ? dsd_const_string("YES") : dsd_const_string("NO"));
        dsl_xml.m_write_xml_close_tag(achg_us_tags[ied_us_tag_flyer]);

        // language
        if ( ads_auth->amc_callback != NULL ) {
            dsl_lang.inc_key = ads_auth->adsc_out_usr->m_get_lang();

            inl_ret = ads_auth->amc_callback( ads_auth->avc_usrfield,
                                              DEF_AUTH_CB_GET_LANG,
                                              (void*)&dsl_lang,
                                              (int)sizeof(dsl_lang) );
            if (    inl_ret == 0
                 && dsl_lang.inc_len_lang > 1 ) {
                dsl_xml.m_write_xml_open_tag(achg_us_tags[ied_us_tag_lang]);
                dsl_xml.m_write_xml_text(dsd_const_string(dsl_lang.achc_lang, dsl_lang.inc_len_lang));
                dsl_xml.m_write_xml_close_tag(achg_us_tags[ied_us_tag_lang]);
            }
        }
		//default portlet
		if(ads_auth->adsc_out_usr->m_has_default_portlet()) {
			ds_hstring dsl_tmp(adsc_wsp_helper);
			ads_auth->adsc_out_usr->m_get_default_portlet(&dsl_tmp);
            dsl_xml.m_write_xml_open_tag(achg_us_tags[ied_us_tag_default_portlet]);
			dsl_xml.m_write_xml_text(dsl_tmp.m_const_str());
            dsl_xml.m_write_xml_close_tag(achg_us_tags[ied_us_tag_default_portlet]);
		}
        dsl_xml.m_write_xml_close_tag(achg_us_tags[ied_us_tag_others]);
        dsl_xml.m_write_xml_close_tag(achg_us_tags[ied_us_tag_usr_sett]);

        // save data to ldap:
        bol_ret = m_set_attribute( ads_user->dsc_userdn.m_get_ptr(),
                                   ads_user->dsc_userdn.m_get_len(),
                                   DEF_ATTR_USET_OTHERS,
                                   (int)sizeof(DEF_ATTR_USET_OTHERS) - 1,
                                   dsl_xml.m_get_ptr(), dsl_xml.m_get_len() );
        if ( bol_ret == false ) {
            bol_ldap = false;
            adsc_wsp_helper->m_logf( ied_sdh_log_warning, 
                                     "HAUTHW030W saving other user-settings in ldap failed" );
        }
    }
    return bol_ldap;
} // end of ds_authenticate::m_save_user_settings


/**
 * private function ds_authenticate::m_save_user_cookies
 *
 * @param[in]   dsd_auth_t*      ads_auth       pointer to authentication input structure
 * @param[in]   const char*      ach_userdn     current user dn
 * @param[in]   int              in_len_dn      length of current dn
 * @return      bool                            true = success             
*/
bool ds_authenticate::m_save_user_cookies( dsd_auth_t* ads_auth,
                                           dsd_getuser* ads_user )
{   
    // initialize some variables:
    ds_hstring       dsl_xml;                   // user cookies in xml
    bool             bol_ret;                   // return from several function calls
    ds_ck_mgmt       dsl_ck_manager;            // cookie manager class

    //-------------------------------------------
    // init some classes:
    //-------------------------------------------
    dsl_xml.m_init       ( adsc_wsp_helper );
    dsl_ck_manager.m_init( adsc_wsp_helper, false );

    //-------------------------------------------
    // add hoboc objectclass:
    //-------------------------------------------
    m_insert_objectclass( "hoboc", ads_user->dsc_userdn.m_get_ptr(),
                                   ads_user->dsc_userdn.m_get_len() );

    //-------------------------------------------
    // get user cookies as xml:
    //-------------------------------------------
    bol_ret = dsl_ck_manager.m_export_cookies( &dsl_xml, 
                                               ads_auth->adsc_out_usr->m_get_basename() );
    if ( bol_ret == true ) {
        //---------------------------------------
        // save attributes to ldap:
        //---------------------------------------
        bol_ret = m_set_attribute( ads_user->dsc_userdn.m_get_ptr(),
                                   ads_user->dsc_userdn.m_get_len(),
                                   DEF_ATTR_USR_COOKIES,
                                   (int)sizeof(DEF_ATTR_USR_COOKIES) - 1,
                                   dsl_xml.m_get_ptr(), dsl_xml.m_get_len() );
        if ( bol_ret == false ) {
            adsc_wsp_helper->m_logf( ied_sdh_log_warning, 
                                     "HAUTHW031W saving cookies in ldap failed" );
        }
        return bol_ret;
    }

    return false;
} // end of ds_authenticate::m_save_user_cookies


/**
 * function ds_authenticate::m_print_err_msg
 * print an error message for authentication return
 *
 * @param[in]   HL_UINT     uin_auth    return from auth call
 * @param[in]   dsd_auth_t* adsp_auth   pointer to authentication input structure
*/
void ds_authenticate::m_print_err_msg( HL_UINT uin_auth, dsd_auth_t* adsp_auth,
                                       struct dsd_domain *adsp_domain )
{
    // initialize some variables:
    const char* achl_success;
    const char* achl_method;
    const char* achl_error;

    //---------------------------------------
    // get success:
    //---------------------------------------
    if ( (uin_auth & AUTH_SUCCESS) == AUTH_SUCCESS ) {
        achl_success = "succeeded";
    } else {
        achl_success = "failed";
    }

    //---------------------------------------
    // get selected method:
    //---------------------------------------
    if ( (uin_auth & AUTH_METH_CMA) == AUTH_METH_CMA ) {
        achl_method = "cma";
    } else if ( (uin_auth & AUTH_METH_RADIUS) == AUTH_METH_RADIUS ) {
        achl_method = "radius";
    } else if ( (uin_auth & AUTH_METH_DYN_RADIUS) == AUTH_METH_DYN_RADIUS ) {
        achl_method = "dynamic radius";
    } else if ( (uin_auth & AUTH_METH_USERLIST) == AUTH_METH_USERLIST ) {
        achl_method = "userlist";
    } else if ( (uin_auth & AUTH_METH_KRB5) == AUTH_METH_KRB5 ) {
        achl_method = "kerberos";
    } else if ( (uin_auth & AUTH_METH_DYN_KRB5) == AUTH_METH_DYN_KRB5 ) {
        achl_method = "dynamic kerberos";
    } else if ( (uin_auth & AUTH_METH_LDAP) == AUTH_METH_LDAP ) {
        achl_method = "ldap";
    } else if ( (uin_auth & AUTH_METH_DYN_LDAP) == AUTH_METH_DYN_LDAP ) {
        achl_method = "dynamic ldap";
    } else if ( (uin_auth & AUTH_METH_CHALLENGE) == AUTH_METH_CHALLENGE ) {
        achl_method = "challenge";
    } else if ( (uin_auth & AUTH_METH_ANONYMOUS) == AUTH_METH_ANONYMOUS ) {
        achl_method = "anonymous";
    } else {
        achl_method = "unknown";
    }

    //---------------------------------------
    // get error reason:
    //---------------------------------------
    if ( (uin_auth & AUTH_ERR_INTERNAL) == AUTH_ERR_INTERNAL ) {
        achl_error = "internal error";
    } else if ( (uin_auth & AUTH_ERR_AUX) == AUTH_ERR_AUX ) {
        achl_error = "aux function error";
    } else if ( (uin_auth & AUTH_ERR_INPUT) == AUTH_ERR_INPUT ) {
        achl_error = "invalid input data";
    } else if ( (uin_auth & AUTH_ERR_USR) == AUTH_ERR_USR ) {
        achl_error = "invalid user name";
    } else if ( (uin_auth & AUTH_ERR_PWD) == AUTH_ERR_PWD ) {
        achl_error = "invalid password";
    } else if ( (uin_auth & AUTH_ERR_STICKET) == AUTH_ERR_STICKET ) {
        achl_error = "invalid session ticket";
    } else if ( (uin_auth & AUTH_ERR_CTXT) == AUTH_ERR_CTXT ) {
        achl_error = "invalid domain";
    } else if ( (uin_auth & AUTH_ERR_SID) == AUTH_ERR_SID ) {
        achl_error = "invalid session id";
    } else if ( (uin_auth & AUTH_ERR_EXPIRED) == AUTH_ERR_EXPIRED ) {
        achl_error = "maximal cookie lifetime expired";
    } else if ( (uin_auth & AUTH_ERR_STATE) == AUTH_ERR_STATE ) {
        achl_error = "wrong state set";
    } else if ( (uin_auth & AUTH_ERR_INV_PARAMS) == AUTH_ERR_INV_PARAMS ) {
        achl_error = "invalid parameters (server)";
    } else if ( (uin_auth & AUTH_ERR_INV_RESP) == AUTH_ERR_INV_RESP ) {
        achl_error = "invalid response from server";
    } else if ( (uin_auth & AUTH_ERR_REJECT) == AUTH_ERR_REJECT ) {
        achl_error = "login rejected (server)";
    } else if ( (uin_auth & AUTH_ERR_CMA_CREATE) == AUTH_ERR_CMA_CREATE ) {
        achl_error = "cma creation failed";
    } else if ( (uin_auth & AUTH_ERR_INV_CTXT_TYPE) == AUTH_ERR_INV_CTXT_TYPE ) {
        achl_error = "invalid authentication domain";
    } else if ( (uin_auth & AUTH_ERR_AUTH_TYPE) == AUTH_ERR_AUTH_TYPE ) {
        achl_error = "cannot find a valid auth method";
    } else if ( (uin_auth & AUTH_ERR_VERSION) == AUTH_ERR_VERSION ) {
        achl_error = "unknown cma version detected";
    } else if ( (uin_auth & AUTH_ERR_CLIENTIP) == AUTH_ERR_CLIENTIP ) {
        achl_error = "HIWSE100E: saved clientip and incoming ip are not equal";
    } else if ( (uin_auth & AUTH_INV_USERDN) == AUTH_INV_USERDN ) {
        achl_error = "invalid userdn";
    } else if ( (uin_auth & AUTH_SAME_USER) == AUTH_SAME_USER ) {
        achl_error = "user already logged in";
    } else if ( (uin_auth & AUTH_KICKED_OUT) == AUTH_KICKED_OUT ) {
        achl_error = "user has been kicked out";
    } else if ( (uin_auth & AUTH_KRB5_NOKDC_CONF) == AUTH_KRB5_NOKDC_CONF ) {
        achl_error = "KDC not configured";
    } else if ( (uin_auth & AUTH_KRB5_NOKDC_SEL) == AUTH_KRB5_NOKDC_SEL ) {
        achl_error = "KDC not selected";
    } else if ( (uin_auth & AUTH_KRB5_NO_SESS) == AUTH_KRB5_NO_SESS ) {
        achl_error = "KDC session not signed on";
    } else if ( (uin_auth & AUTH_KRB5_KDC_INV) == AUTH_KRB5_KDC_INV ) {
        achl_error = "KDC invalid";
    } else if ( (uin_auth & AUTH_KRB5_NO_TGT) == AUTH_KRB5_NO_TGT ) {
        achl_error = "TGT not found";
    } else if ( (uin_auth & AUTH_KRB5_MISC) == AUTH_KRB5_MISC ) {
        achl_error = "miscellaneous error";
    } else if ( (uin_auth & AUTH_ERR_DYN_SEL) == AUTH_ERR_DYN_SEL ) {
        achl_error = "dynamic select server failed";
    } else if ( (uin_auth & AUTH_ERR_AXSS_EXPIRED) == AUTH_ERR_AXSS_EXPIRED ) {
        achl_error = "axss has expired";
    } else if ( (uin_auth & AUTH_ERR_OTHER_PORT) == AUTH_ERR_OTHER_PORT ) {
        achl_error = "other incoming port selected";
    } else if ( (uin_auth & AUTH_NO_ROLE_POSSIBLE) == AUTH_NO_ROLE_POSSIBLE ) {
        achl_error = "no role for given user found";
    } else if ( (uin_auth & AUTH_CHANGE_PWD) == AUTH_CHANGE_PWD ) {
        achl_error =  "password must be changed";
    } else {
        achl_error = NULL;
    }

    //---------------------------------------
    // print message:
    //---------------------------------------
    if (    adsp_auth->achc_user    == NULL
         || adsp_auth->inc_len_user <  1    ) {
        if ( achl_error != NULL ) {
            adsc_wsp_helper->m_logf( ied_sdh_log_warning, 
                                     "HAUTHW032W %s authentication %s with error '%s'",
                                     achl_method, achl_success, achl_error );
        } else {
            adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                     "HAUTHW033W %s authentication %s",
                                     achl_method, achl_success );
        }
    } else if ( adsp_domain == NULL ) {
        if ( achl_error != NULL ) {
            adsc_wsp_helper->m_logf( ied_sdh_log_warning, 
                                     "HAUTHW034W %s authentication %s for userid=%.*s with error '%s'",
                                     achl_method, achl_success,
                                     adsp_auth->inc_len_user, adsp_auth->achc_user, achl_error );
        } else {
            adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                     "HAUTHW035W %s authentication %s for userid=%.*s",
                                     achl_method, achl_success,
                                     adsp_auth->inc_len_user, adsp_auth->achc_user );
        }
    } else {
        if ( achl_error != NULL ) {
            adsc_wsp_helper->m_logf( ied_sdh_log_warning, 
                                     "HAUTHW036W %s authentication %s for group=%.*s userid=%.*s with error '%s'",
                                     achl_method, achl_success,
                                     adsp_domain->inc_len_disp_name, adsp_domain->achc_disp_name,
                                     adsp_auth->inc_len_user,        adsp_auth->achc_user, achl_error );
        } else {
            adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                     "HAUTHW037W %s authentication %s for group=%.*s userid=%.*s ",
                                     achl_method, achl_success,
                                     adsp_domain->inc_len_disp_name, adsp_domain->achc_disp_name,
                                     adsp_auth->inc_len_user,        adsp_auth->achc_user   );
        }
    }
} // end of ds_authenticate::m_print_err_msg


#if 0
/**
 * private function ds_authenticate::m_increase_usr_cnt
 * increase user counter (peak and current)
 *
 * @param[in]   dsd_usr_cnt_cma*    ads_out     if given, filled with copy of current counters
*/
void ds_authenticate::m_increase_usr_cnt( dsd_usr_cnt_cma* ads_out )
{
    // initialize some variables:
    int              inl_len_name;              // length of cma name
    bool             bol_ret;                   // return for several function calls
    void*            avl_cma_handle;            // cma handle
    dsd_usr_cnt_cma* adsl_cma;                  // pointer to cma data
    int              inl_len_cma;               // length of cma data
    bool             bol_init = false;          // init cma?


    //-------------------------------------------
    // calculate length of name:
    //-------------------------------------------
    inl_len_name = (int)strlen(DEF_USR_COUNTER_CMA);

    //-------------------------------------------
    // check if cma exists:
    //-------------------------------------------
    bol_ret = adsc_wsp_helper->m_cb_exist_cma( DEF_USR_COUNTER_CMA, inl_len_name );
    if ( bol_ret == false ) {
        //---------------------------------------
        // create cma if not existing:
        //---------------------------------------
        bol_ret = adsc_wsp_helper->m_cb_create_cma( DEF_USR_COUNTER_CMA, inl_len_name,
                                                    NULL, (int)sizeof(dsd_usr_cnt_cma) );
        if ( bol_ret == false ) {
            if ( ads_out != NULL ) {
                memset( ads_out, 0, sizeof(dsd_usr_cnt_cma) );
            }
            return;
        }
        bol_init = true;
    }

    //-------------------------------------------
    // open cma for writing:
    //-------------------------------------------
    avl_cma_handle = adsc_wsp_helper->m_cb_open_cma( DEF_USR_COUNTER_CMA, inl_len_name,
                                                     (void**)&adsl_cma, &inl_len_cma, true );
    if (    avl_cma_handle == NULL
         || inl_len_cma    != (int)sizeof(dsd_usr_cnt_cma) ) {
        if ( ads_out != NULL ) {
            memset( ads_out, 0, sizeof(dsd_usr_cnt_cma) );
        }
        return;
    }

    //-------------------------------------------
    // init cma:
    //-------------------------------------------
    if ( bol_init == true ) {
        memset( adsl_cma, 0, sizeof(dsd_usr_cnt_cma) );
    }

    //-------------------------------------------
    // increase the counters:
    //-------------------------------------------
    adsl_cma->inc_current = m_count_users( NULL );
    if ( adsl_cma->inc_peak < adsl_cma->inc_current ) {
        adsl_cma->inc_peak = adsl_cma->inc_current;
    }

    //-------------------------------------------
    // copy data to output:
    //-------------------------------------------
    if ( ads_out != NULL ) {
        memcpy( ads_out, adsl_cma, inl_len_cma );
    }

    //-------------------------------------------
    // close cma again:
    //-------------------------------------------
    adsc_wsp_helper->m_cb_close_cma( &avl_cma_handle );
} // end of ds_authenticate::m_increase_usr_cnt


/**
 * private function ds_authenticate::m_decrease_usr_cnt
 * decrease user counter (current)
 *
 * @param[in]   dsd_usr_cnt_cma*    ads_out     if given, filled with copy of current counters
*/
void ds_authenticate::m_decrease_usr_cnt( dsd_usr_cnt_cma* ads_out )
{
    // initialize some variables:
    void*            avl_cma_handle;            // cma handle
    dsd_usr_cnt_cma* adsl_cma;                  // pointer to cma data
    int              inl_len_cma;               // length of cma data

    //-------------------------------------------
    // open cma for writing:
    //-------------------------------------------
    avl_cma_handle = adsc_wsp_helper->m_cb_open_cma( DEF_USR_COUNTER_CMA, 
                                                     (int)strlen(DEF_USR_COUNTER_CMA),
                                                     (void**)&adsl_cma,
                                                     &inl_len_cma, true );
    if (    avl_cma_handle == NULL
         || inl_len_cma    != (int)sizeof(dsd_usr_cnt_cma) ) {
        if ( ads_out != NULL ) {
            memset( ads_out, 0, sizeof(dsd_usr_cnt_cma) );
        }
        return;
    }

    //-------------------------------------------
    // decrease the counters:
    //-------------------------------------------
    adsl_cma->inc_current = m_count_users( NULL );

    //-------------------------------------------
    // copy data to output:
    //-------------------------------------------
    if ( ads_out != NULL ) {
        memcpy( ads_out, adsl_cma, inl_len_cma );
    }

    //-------------------------------------------
    // close cma again:
    //-------------------------------------------
    adsc_wsp_helper->m_cb_close_cma( &avl_cma_handle );
} // end of ds_authenticate::m_decrease_usr_cnt
#endif


/**
 * private function ds_authenticate::m_search
 * check if given search matches given user
 *
 * @param[in]   struct dsd_getuser* adsp_user       user structure
 * @param[in]   dsd_query_uov_t*    adsp_query      user query structure
 * @return      bool                                true = user matches search
*/
bool ds_authenticate::m_search( struct dsd_getuser* adsp_user, dsd_query_uov_t* adsp_query )
{
    // initialize some variables:
    bool bol_ret;
    int  inl_compare;
    BOOL bol_comp;

    if (    adsp_query->inc_len_user   < 1
         && adsp_query->inc_len_domain < 1 ) {
        // no search requested -> everything matches:
        return true;
    }

    bol_ret = true;
    if ( adsp_query->boc_use_wildcard == false ) {
        // search username:
        if ( adsp_query->inc_len_user > 0 ) {
            bol_ret = adsp_user->dsc_username.m_equals_ic( adsp_query->achc_search_user,
                                                        adsp_query->inc_len_user );
        }

        // search user domain:
        if (    bol_ret                               == true
             && adsp_query->inc_len_domain            >  0
             && adsp_user->dsc_userdomain.m_get_len() >  0    ) {
            if ( adsp_user->dsc_wspgroup.m_get_len()  >  0 ) {
                bol_ret = adsp_user->dsc_wspgroup.m_equals_ic( adsp_query->achc_search_domain,
                                                            adsp_query->inc_len_domain );
            } else {
                bol_ret = adsp_user->dsc_userdomain.m_equals_ic( adsp_query->achc_search_domain,
                                                             adsp_query->inc_len_domain );
            }
        }
    } else {
        // search username:
        if ( adsp_query->inc_len_user > 0 ) {
            bol_comp = m_cmp_wc_i_vx_vx( &inl_compare,
                                         adsp_user->dsc_username.m_get_ptr(),
                                         adsp_user->dsc_username.m_get_len(),
                                         ied_chs_utf_8,
                                         adsp_query->achc_search_user,
                                         adsp_query->inc_len_user,
                                         ied_chs_utf_8 );
            bol_ret = ( bol_comp == TRUE && inl_compare == 0 );
        }

        // search user domain:
        if (    bol_ret                               == true
             && adsp_query->inc_len_domain            >  0
             && adsp_user->dsc_userdomain.m_get_len() >  0    ) {
            if ( adsp_user->dsc_wspgroup.m_get_len()  >  0 ) {
                bol_comp = m_cmp_wc_i_vx_vx( &inl_compare,
                                             adsp_user->dsc_wspgroup.m_get_ptr(),
                                             adsp_user->dsc_wspgroup.m_get_len(),
                                             ied_chs_utf_8,
                                             adsp_query->achc_search_domain,
                                             adsp_query->inc_len_domain,
                                             ied_chs_utf_8 );
            } else {
                bol_comp = m_cmp_wc_i_vx_vx( &inl_compare,
                                             adsp_user->dsc_userdomain.m_get_ptr(),
                                             adsp_user->dsc_userdomain.m_get_len(),
                                             ied_chs_utf_8,
                                             adsp_query->achc_search_domain,
                                             adsp_query->inc_len_domain,
                                             ied_chs_utf_8 );
            }
            bol_ret = ( bol_comp == TRUE && inl_compare == 0 );
        }
    }

    return bol_ret;
} // end of ds_authenticate::m_search


/**
 * private function ds_authenticate::m_is_anonymous
 * check if given username is anonymous user
 *
 * @param[in]   dsd_auth_t*                     adsp_auth       auth input structure
 * @param[in]   struct dsd_wspat_public_config* adsp_wspat_conf wspat configuration
*/
bool ds_authenticate::m_is_anonymous( dsd_auth_t* adsp_auth,
                                      struct dsd_wspat_public_config *adsp_wspat_conf )
{
#define DSL_ANONYMOUS (adsp_wspat_conf->dsc_anonymous)
    if (    adsp_wspat_conf            != NULL
         && DSL_ANONYMOUS.boc_enabled  == true
         && adsp_auth->inc_len_user    == (int)strlen(DEF_ANONYMOUS_USER)
         && memcmp(adsp_auth->achc_user, DEF_ANONYMOUS_USER, adsp_auth->inc_len_user) == 0  ) {
        return true;
    }
#undef DSL_ANONYMOUS
    return false;
} // end of ds_authenticate::m_is_anonymous


/**
 * private function ds_authenticate::m_auth_anonymous
 *
 * @param[in]   dsd_auth_t*                     adsp_auth        auth input structure
 * @param[in]   int                             in_wsp_auth      wsp configured auth methods
 * @param[in]   int*                            ainp_domain_auth domain auth method
 * @param[in]   struct dsd_wspat_public_config* adsp_wspat_conf  wspat configuration
*/
HL_UINT ds_authenticate::m_auth_anonymous( dsd_auth_t* adsp_auth,
                                           int inp_wsp_auth, int* ainp_domain_auth,
                                           struct dsd_wspat_public_config *adsp_wspat_conf )
{
    struct dsd_domain *adsl_domain;
#define DSL_ANONYMOUS (adsp_wspat_conf->dsc_anonymous)
    adsp_auth->achc_user      = DSL_ANONYMOUS.achc_mp_user;
    adsp_auth->inc_len_user   = DSL_ANONYMOUS.inc_len_user;
    adsp_auth->achc_domain    = DSL_ANONYMOUS.achc_mp_domain;
    adsp_auth->inc_len_domain = DSL_ANONYMOUS.inc_len_domain;

    *ainp_domain_auth = m_get_domain_auth( adsp_auth, inp_wsp_auth,
                                           adsp_wspat_conf, &adsl_domain );
    if ( *ainp_domain_auth == -1 ) {
        m_print_err_msg( AUTH_FAILED | AUTH_METH_ANONYMOUS, adsp_auth, NULL );
        return AUTH_FAILED | AUTH_METH_ANONYMOUS;
    }

    //-------------------------------------------
    // select ldap server
    //-------------------------------------------
    if ( *ainp_domain_auth == DEF_CLIB1_CONF_DYN_LDAP ) {
        adsc_wsp_helper->m_set_ldap_srv( DSL_ANONYMOUS.achc_mp_domain,
                                         DSL_ANONYMOUS.inc_len_domain );
    }
#undef DSL_ANONYMOUS
    return ( AUTH_SUCCESS | AUTH_METH_ANONYMOUS );
} // end of ds_authenticate::m_auth_anonymous


/**
 * private function ds_authenticate::m_parse_ineta
 *
 * @param[in]   const char*     ach_ineta           ineta as string
 * @param[in]   int             in_length           length of ineta
 * @param[out]  dsd_ineta_temp* ads_ineta           ineta structure
 * @return      bool                                true = valid ineta
*/
bool ds_authenticate::m_parse_ineta( const char* ach_ineta, int in_length,
                                     dsd_ineta_temp* ads_ineta )
{
    /*
        this function decides whether a given ineta (as string)
        is an IPv4 or IPv6 ineta.

        Valid addresses should look like:
            IPv4: 123.111.222.101
            IPv6: 2001:0db8:85a3::1319:8a2e:0370:7344
    */

    // initialize some variables:
    bool                bol_valid    = true;        // valid ineta?
    int                 inl_ret;                    // return value
    int                 inl_pos;                    // current pos in input
    int                 inl_dots     = 0;           // count dots
    int                 inl_two_dots = 0;           // count double dots "::"
    int                 inl_nums     = 0;           // count numbers between dots
    int                 inl_value;                  // value for checking
    unsigned short int  uisl_type    = 0;           // type of ineta

    //-------------------------------------------
    // do IPv4 or IPv6 validation:
    //-------------------------------------------
    for ( inl_pos = 0; inl_pos < in_length; inl_pos++ ) {
        if ( ach_ineta[inl_pos] == '.' ) {
            uisl_type = AF_INET;
            break;
        } else if (  ach_ineta[inl_pos] == ':' ) {
            uisl_type = AF_INET6;
            break;
        }
    }

    if ( uisl_type == AF_INET ) {
        //---------------------------------------
        // do IPv4 validation:
        //---------------------------------------
        for ( inl_pos = 0; inl_pos < in_length; inl_pos++ ) {
            switch ( ach_ineta[inl_pos] ) {
                case '.': 
                    inl_dots++;
                    if (    inl_dots < 4     /* IPv4 has exact 3 dots      */
                         && inl_nums < 4     /* max 3 numbers between dots */
                         && inl_nums > 0     /* min 1 number between dots  */ )
                    {
                        inl_value = atoi(&ach_ineta[inl_pos - inl_nums]);  
                        if ( inl_value < 0 || inl_value > 255 ) {
                            break;
                        }
                        inl_nums = 0;
                        continue;
                    }
                    break; // otherwise error
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    inl_nums++;
                    if ( inl_nums < 4 /* max 3 numbers between dots */ ) {
                        continue;
                    }
                    break; // otherwise error
                default:
                    // other char as number, '.' or ':' -> invalid address
                    break; 
            }
            bol_valid = false; // an error occurred
            break;
        } // end of for loop

        if ( bol_valid == true ) {
            if (    inl_dots == 3    /* exactly 3 dots             */
                 && inl_nums < 4     /* max 3 numbers between dots */
                 && inl_nums > 0     /* min 1 number between dots  */ )
            {
                inl_value = atoi(&ach_ineta[inl_pos - inl_nums]);    
                if ( inl_value < 0 || inl_value > 255 ) {
                    bol_valid = false;
                }
            }
        }

    } // end of IPv4 validation
    
    else if ( uisl_type == AF_INET6 ) {
        //---------------------------------------
        // do IPv6 validation:
        //---------------------------------------        
        for ( inl_pos = 0; inl_pos < in_length; inl_pos++ ) {
            switch ( ach_ineta[inl_pos] ) {
                case ':':
                    inl_dots++;
                    if (    inl_two_dots < 2 /* "::" is allowed only once  */
                         && inl_dots < 8     /* max 7 dots                 */
                         && inl_nums < 5     /* max 4 numbers between dots */ )
                    {
                        if ( inl_nums == 0 ) {
                            inl_two_dots++;
                        }
                        inl_nums = 0;
                        continue;
                    }
                    break; // otherwise error
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                case 'a':
                case 'b':
                case 'c':
                case 'd':
                case 'e':
                case 'f':
                case 'A':
                case 'B':
                case 'C':
                case 'D':
                case 'E':
                case 'F':
                    inl_nums++;
                    if ( inl_nums < 5     /* max 4 numbers between dots */ ) {
                        continue;
                    }
                    break; // otherwise error
                default:
                    // other char as number or ':' -> invalid address
                    break; 
            }
            bol_valid = false; // an error occurred
            break;
        } // end of for loop

        if ( bol_valid == true ) {
            if (    inl_two_dots < 2 /* "::" is allowed only once  */
                 && inl_dots < 8     /* max 7 dots                 */
                 && inl_nums < 5     /* max 4 numbers between dots */ )
            {
            } else {
                bol_valid = false;
            }
        }
    } // end of IPv6 validation
    else {
        return false;
    }

    //-------------------------------------------
    // fill output structure:
    //-------------------------------------------
    if ( bol_valid == true ) {
        struct addrinfo  dsl_addr_hints;
        struct addrinfo* adsl_addrinfo = NULL;
        ds_hstring dsl_ineta( adsc_wsp_helper, ach_ineta, in_length );

        memset( &dsl_addr_hints, 0, sizeof(dsl_addr_hints) );
        dsl_addr_hints.ai_family = uisl_type;

        inl_ret = getaddrinfo( dsl_ineta.m_get_ptr(), NULL, &dsl_addr_hints, &adsl_addrinfo );
        if (    inl_ret       != 0
             || adsl_addrinfo == NULL ) {
            return false;
        }

        switch ( adsl_addrinfo->ai_family ) {
            case AF_INET:
                ads_ineta->usc_family = AF_INET;
                ads_ineta->usc_length = 4;
                memcpy( ads_ineta->chrc_ineta,
                        &(((struct sockaddr_in*)adsl_addrinfo->ai_addr)->sin_addr.s_addr),
                        ads_ineta->usc_length );
                break;

            case AF_INET6:
                ads_ineta->usc_family = AF_INET6;
                ads_ineta->usc_length = 16;
                memcpy( ads_ineta->chrc_ineta,
                        &(((struct sockaddr_in6*)adsl_addrinfo->ai_addr)->sin6_addr),
                        ads_ineta->usc_length );
                break;

            default:
                bol_valid = false;
                break;
        }

        freeaddrinfo( adsl_addrinfo );
    }

    return bol_valid;
} // end of ds_authenticate::m_parse_ineta
