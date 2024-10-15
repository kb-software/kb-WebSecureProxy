/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
#define SUP_PROTOCOL_VERSION 1

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#include <ds_ldap.h>
#include <time.h>
#include <rdvpn_globals.h>
#include <ds_wsp_helper.h>
#include <hob-libwspat.h>
#include <ds_hstring.h>
#include <ds_hvector.h>
#include <ds_usercma.h>
#include <ds_authenticate.h>
#include "sdh_compl_check.h"
#include "ds_compl_check.h"
#include <ds_xml.h>
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H

#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>
#ifdef HL_FREEBSD
#include <sys/socket.h>
#endif

/*+---------------------------------------------------------------------+*/
/*| constructor:                                                        |*/
/*+---------------------------------------------------------------------+*/
ds_compl_check::ds_compl_check( void )
{
    adsc_wsp_helper = NULL;
    adsc_config     = NULL;
    avc_storage     = NULL;
    ienc_state      = ied_read_len;
} // end of ds_compl_check::ds_compl_check


/*+---------------------------------------------------------------------+*/
/*| destructor:                                                         |*/
/*+---------------------------------------------------------------------+*/
ds_compl_check::~ds_compl_check()
{
} // end of ds_compl_check::~ds_compl_check


/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
 * public function ds_compl_check::m_init
 *
 * @param[in]   ds_wsp_helper*  ads_wsp_helper_in
*/
void ds_compl_check::m_init( ds_wsp_helper* ads_wsp_helper_in )
{
    adsc_wsp_helper = ads_wsp_helper_in;
    dsc_user.m_init( adsc_wsp_helper );
} // end of ds_compl_check::m_init


/**
 * public function ds_compl_check::m_run
 * our start entry as sdh working class
 *
 * @return      bool                                    true = success
*/
bool ds_compl_check::m_run()
{
    // initialize some variables:
    bool                   bo_ret     = true;           // our return value
    struct dsd_gather_i_1* ads_gather;                  // input data


    //----------------------------------------------------
    // init our helper class and config pointer:
    //----------------------------------------------------
    adsc_config = (dsd_sdh_config_t*)adsc_wsp_helper->m_get_config();

    //----------------------------------------------------
    // log incoming data:
    //----------------------------------------------------
    adsc_wsp_helper->m_log_input();

    //----------------------------------------------------
    // handle data:
    //----------------------------------------------------
    ads_gather = adsc_wsp_helper->m_get_input();
    if ( ads_gather != NULL ) {
        bo_ret = m_handle_data( ads_gather );
    }

    //----------------------------------------------------
    // log outgoing data:
    //----------------------------------------------------
    adsc_wsp_helper->m_log_output();

    return bo_ret;
} // end of ds_compl_check::m_run


/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/
/**
 * private function ds_compl_check::m_handle_data
 * general data handling
 * 
 * @param[in]   struct dsd_gather_i_1*  ads_gather      input data
 * @return      bool                                    true = success
*/
bool ds_compl_check::m_handle_data( struct dsd_gather_i_1* ads_gather )
{
    // initialize some variables:
    int        in_length;               // total length of incoming data
    int        in_offset    = 0;        // reading position in data
    int        in_read      = 0;        // read bytes (for m_get_buf)
    bool       bo_ret;                  // return for several function calls

    /*
        our protocol looks like this
        +----------+---------- ... -+
        | len xml  | xml data       |
        +----------+---------- ... -+
        | nhasn    | variable len   |

        length is always in little endian
    */

    //---------------------------------------------
    // evalute input gather length:
    //---------------------------------------------
    in_length = adsc_wsp_helper->m_get_gather_len( ads_gather );

    //---------------------------------------------
    // loop through the data:
    //---------------------------------------------
    while ( in_offset < in_length ) {

        switch ( ienc_state ) {

            //-------------------------------------
            // read xml length information:
            //-------------------------------------
            case ied_read_len:
                if ( m_from_nhasn( &dsc_recxml.in_expected, ads_gather, &in_offset ) == true ) {
                    ienc_state = ied_read_xml;
                }
                continue;

            //-------------------------------------
            // read xml:
            //-------------------------------------
            case ied_read_xml:
                //---------------------------------
                // get buffer from gather:
                //---------------------------------
                dsc_recxml.ach_ptr = adsc_wsp_helper->m_get_buf( ads_gather, in_offset,
                                                                 dsc_recxml.in_expected - dsc_recxml.in_received,
                                                                 &in_read );
                if ( dsc_recxml.ach_ptr == NULL ) {
                    break;
                }
                dsc_recxml.in_received += in_read;

                //---------------------------------
                // check if we have presaved data:
                //---------------------------------
                if ( dsc_xmlbuf.ach_ptr != NULL ) {
                    memcpy( &dsc_xmlbuf.ach_ptr[dsc_xmlbuf.in_received],
                            dsc_recxml.ach_ptr, in_read );
                    dsc_xmlbuf.in_received = dsc_recxml.in_received;
                    dsc_recxml.ach_ptr     = dsc_xmlbuf.ach_ptr;
                }

                //---------------------------------
                // check if everything is received:
                //---------------------------------
                if ( dsc_recxml.in_expected == dsc_recxml.in_received ) {
                    // set new state:
                    ienc_state = ied_handle_input;
                } else if ( dsc_xmlbuf.ach_ptr == NULL ) {
                    // get receive buffer:
                    dsc_xmlbuf.ach_ptr = adsc_wsp_helper->m_cb_get_memory( dsc_recxml.in_expected, false );
                    if ( dsc_xmlbuf.ach_ptr == NULL ) {
                        return false;
                    }
                    memcpy( dsc_xmlbuf.ach_ptr, dsc_recxml.ach_ptr, in_read );
                    dsc_recxml.ach_ptr     = dsc_xmlbuf.ach_ptr;
                    dsc_xmlbuf.in_expected = dsc_recxml.in_expected;
                    dsc_xmlbuf.in_received = dsc_recxml.in_received;
                }

                // update offset:
                in_offset += in_read;
                continue;
            
            //-------------------------------------
            // handle input:
            //   if we come here, there are more 
            //   than one packet in gather
            //   we break the loop, handle the
            //   data and don't mark apppended
            //   data as processed, so wsp will 
            //   give us this packet again
            //-------------------------------------
            case ied_handle_input:
                ienc_state = ied_read_len;
                break;

        } // end of switch
        break;

    } // end of while( in_offset < in_length )
    
    //---------------------------------------------
    // mark data as processed until offset:
    //---------------------------------------------
    adsc_wsp_helper->m_mark_processed( ads_gather, &in_offset, &in_length );

    //---------------------------------------------
    // handle read data:
    //---------------------------------------------
    if ( dsc_recxml.in_expected  == dsc_recxml.in_received ) {
        //-----------------------------------------
        // read xml data:
        //-----------------------------------------
        bo_ret = m_read_xml( dsc_recxml.ach_ptr,
                             dsc_recxml.in_expected );
        if ( bo_ret == false ) {
            adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                    "HCOCW004W error while reading xml data" );
            return false;
        }

        //-----------------------------------------
        // free presaved data (if used):
        //-----------------------------------------
        if ( dsc_xmlbuf.ach_ptr != NULL ) {
            adsc_wsp_helper->m_cb_free_memory( dsc_xmlbuf.ach_ptr,
                                               dsc_xmlbuf.in_expected );
            dsc_xmlbuf.ach_ptr     = NULL;
            dsc_xmlbuf.in_expected = 0;
            dsc_xmlbuf.in_received = 0;
        }

        //-----------------------------------------
        // send response:
        //-----------------------------------------
        m_create_response();

        //-----------------------------------------
        // reset state and read length:
        //-----------------------------------------
        ienc_state = ied_read_len;
        dsc_recxml.in_expected = -1;
        dsc_recxml.in_received =  0;

        //-----------------------------------------
        // check command handle return value:
        //-----------------------------------------
        if ( bo_ret == false ) {
            adsc_wsp_helper->m_log( ied_sdh_log_info,
                                    "HCOCI002I error while handling command" );
            return false;
        }
        
    } // end of if ( ds_rec.ds_hash.in_expected = ...

    return true;
} // end of ds_compl_check::m_handle_data


/**
 * private function ds_coml_check::m_get_logged_user
 * get information about logged user and his group
 *
 * @return      bool
*/
bool ds_compl_check::m_get_logged_user()
{
    // initialize some variables:
    int               in_pos;                       // working position in session ticket
    const char*       ach_decoded;                  // pointer to decoded session ticket
    int               in_len_decoded;               // length of decoded session ticket
    ds_authenticate   ds_ident( adsc_wsp_helper );  // authentication class
    dsd_auth_t        dsl_auth;                     // authentication structure
    HL_UINT           uin_auth;                     // result from authentication
    ds_hstring        dsc_decoded;


    //--------------------------------------
    // decode imcomming cookie:
    //--------------------------------------
    dsc_decoded.m_setup( adsc_wsp_helper );
    if(!dsc_decoded.m_from_rfc3548( dsc_recdata.achc_cookie, dsc_recdata.inc_len_cookie ))
        return false;
    if ( dsc_decoded.m_get_len() < dsc_user.m_size_sticket() + 1 ) {
        return false;
    }

    //--------------------------------------
    // parse cookie:
    //--------------------------------------
    memset( &dsl_auth, 0, sizeof(dsd_auth_t) );
    ach_decoded    = dsc_decoded.m_get_ptr();
    in_len_decoded = dsc_decoded.m_get_len();

    // set password:
    dsl_auth.achc_password    = ach_decoded;
    dsl_auth.inc_len_password = dsc_user.m_size_sticket();

    // set user:
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

    // set domain:
    in_pos++;
    if ( in_pos < in_len_decoded ) {
        dsl_auth.achc_domain    = &ach_decoded[in_pos];
        dsl_auth.inc_len_domain = in_len_decoded - in_pos;
    }

    dsl_auth.adsc_out_usr = &dsc_user;

    //--------------------------------------
    // check cookie and get cma class:
    //--------------------------------------
    uin_auth = ds_ident.m_auth_session( &dsl_auth );
    return ( (uin_auth & AUTH_SUCCESS) == AUTH_SUCCESS );
} // end of ds_compl_check::m_get_logged_user


/**
 * private function ds_compl_check::m_get_checks
 * get matching checks for given user
 *
 * @param[out]  ds_hvector_btype<dsd_cc_to_send>
 * @return      bool
*/
bool ds_compl_check::m_get_checks( ds_hvector_btype<dsd_cc_to_send>* ads_vchecks )
{
    // initialize some variables:
    bool                        bo_ret;             // return value
    dsd_role*                   ads_cur_role;       // role working variable
    dsd_compl_check*            ads_cur_check;      // check working variable
    dsd_cc_to_send              ds_tosend;          // to send structure
    size_t                      uin_pos;            // position in vector
    ds_hvector_btype<dsd_role*> ds_vroles( adsc_wsp_helper );

    //-------------------------------------------
    // get roles from rolescma:
    //-------------------------------------------
    bo_ret = dsc_user.m_get_roles( &ds_vroles );
    if ( bo_ret == false ) {
        return false;
    }

    //-------------------------------------------
    // loop through possible user roles:
    //-------------------------------------------
    for ( uin_pos = 0; uin_pos < ds_vroles.m_size(); uin_pos++ ) {
        ads_cur_role = ds_vroles.m_get( uin_pos );
        //---------------------------------------
        // search check with given name:
        //---------------------------------------
        ads_cur_check = m_search_check( ads_cur_role->achc_check,
                                        ads_cur_role->inc_len_check );
        if ( ads_cur_check == NULL ) {
            // stop if role contains no compliance check
            break;
        }
        ds_tosend.achc_role    = ads_cur_role->achc_name;
        ds_tosend.inc_len_role = ads_cur_role->inc_len_name;
        ds_tosend.adsc_check   = ads_cur_check;
        ads_vchecks->m_add( ds_tosend );
    }

    return !ads_vchecks->m_empty();
} // end of ds_compl_check::m_get_checks


/**
 * private function ds_compl_check::m_role_without_check
 * check if there exists an possible
 * role for given user without a compliance check
 *
 * @return  dsd_role*                   role if existing
 *                                      NULL otherwise
*/
dsd_role* ds_compl_check::m_role_without_check()
{
    // initialize some variables:
    bool                        bo_ret;             // return value
    dsd_role*                   ads_cur_role;       // role working variable
    size_t                      uin_pos;            // position in vector
    ds_hvector_btype<dsd_role*> ds_vroles( adsc_wsp_helper );

    //-------------------------------------------
    // get roles from rolescma:
    //-------------------------------------------
    bo_ret = dsc_user.m_get_roles( &ds_vroles );
    if ( bo_ret == false ) {
        return NULL;
    }

    //-------------------------------------------
    // loop through possible user roles:
    //-------------------------------------------
    for ( uin_pos = 0; uin_pos < ds_vroles.m_size(); uin_pos++ ) {
        ads_cur_role = ds_vroles.m_get( uin_pos );

        if (    ads_cur_role->achc_check == NULL
             || ads_cur_role->inc_len_check < 1 ) {
            return ads_cur_role;
        }
    }

    return NULL;
} // end of ds_compl_check::m_role_without_check


/**
 * private function ds_compl_check::m_search_check
 * search compliance check with given name
 *
 * @param[in]   const char*     ach_name
 * @param[in]   int             in_len_name
 * @return      dsd_compl_check*
*/
dsd_compl_check* ds_compl_check::m_search_check( const char* ach_name,
                                                 int         in_len   )
{
    // initialize some variables:
    dsd_compl_check*  ads_check;

    ads_check = adsc_config->ads_check;
    while ( ads_check != NULL ) {
        if (    in_len == ads_check->inc_len_name
             && memcmp( ach_name, ads_check->achc_name, in_len ) == 0 ) {
             break;
        }

        // get next element:
        ads_check = ads_check->adsc_next;
    }

    return ads_check;
} // end of ds_compl_check::m_search_check


/**
 * private function ds_compl_check::m_save_role
 * save received role for given user
 *
 * @return      bool                            true = success
*/
bool ds_compl_check::m_save_role()
{
    // initialize some variables:
    bool       bol_ret;                         // return value
    ds_hstring dsl_username;                    // username
    ds_hstring dsl_domain;                      // domain

    //-------------------------------------------
    // check if role is valid:
    //-------------------------------------------
    bol_ret = dsc_user.m_is_in_list( dsc_recdata.achc_role,
                                     dsc_recdata.inc_len_role );
    if ( bol_ret == false ) {
        return false;
    }

    //-------------------------------------------
    // delete roles cma:
    //-------------------------------------------
    dsc_user.m_delete_roles();

    //-------------------------------------------
    // print out:
    //-------------------------------------------
    dsl_username = dsc_user.m_get_username();
    dsl_domain   = dsc_user.m_get_userdomain();
    adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                             "HC0CI100I group=%.*s userid=%.*s reached role %.*s",
                             dsl_domain.m_get_len(),   dsl_domain.m_get_ptr(),
                             dsl_username.m_get_len(), dsl_username.m_get_ptr(),
                             dsc_recdata.inc_len_role, dsc_recdata.achc_role );

    //-------------------------------------------
    // save role in cma:
    //-------------------------------------------
    return dsc_user.m_set_role( dsc_recdata.achc_role, dsc_recdata.inc_len_role );
} // end of ds_compl_check::m_save_role


/**
 * private function ds_compl_check::m_set_role_checks
 * search successful check for return role and create state
*/
void ds_compl_check::m_set_role_checks()
{
    // initialize some variables:
    dsd_compl_check   *adsl_check;              // current compliance check
    dsd_role          *adsl_cur_role;           // current role configuration
    dsd_wspat_pconf_t *adsl_wspat_conf;         // config from wspat

    //-------------------------------------------
    // get successful compliance check name:
    //-------------------------------------------
    adsl_wspat_conf = adsc_wsp_helper->m_get_wspat_config();
    if ( adsl_wspat_conf == NULL ) {
        return;
    }
    
    // loop through all roles:
    adsl_cur_role = adsl_wspat_conf->adsc_roles;
    while ( adsl_cur_role != NULL ) {
        if (    dsc_recdata.inc_len_role == adsl_cur_role->inc_len_name
             && memcmp( adsl_cur_role->achc_name,
                         dsc_recdata.achc_role,
                         dsc_recdata.inc_len_role ) == 0 ) {
             break;
        }

        // get next element:
        adsl_cur_role = adsl_cur_role->adsc_next;
    }
    if (    adsl_cur_role                == NULL
         || adsl_cur_role->achc_check    == NULL
         || adsl_cur_role->inc_len_check < 1     ) {
        return;
    }

    //-------------------------------------------
    // search check in configuration:
    //-------------------------------------------
    adsl_check = m_search_check( adsl_cur_role->achc_check,
                                 adsl_cur_role->inc_len_check );
    if ( adsl_check == NULL ) {
        return;
    }

    if ( (adsl_check->inc_checks & HL_COMP_CHECK_INTEGRITY) == HL_COMP_CHECK_INTEGRITY ) {
        dsc_user.m_set_state( ST_COMPLCHECK_INTEGRITY );
    }
#if 0  // anti-split-tunnel deactivated, Jun 2017 [#49556]
    if ( (adsl_check->inc_checks & HL_COMP_CHECK_AST) == HL_COMP_CHECK_AST ) {
        dsc_user.m_set_state( ST_COMPLCHECK_AST );
    }
#endif
    if ( (adsl_check->inc_checks & HL_COMP_CHECK_RULE) == HL_COMP_CHECK_RULE ) {
        dsc_user.m_set_state( ST_COMPLCHECK_RULE );
    }
    return;
} // end of ds_compl_check::m_set_role_checks


/**
 * private function ds_compl_check::m_create_response()
 * create answer for compliance check client
 *
 * @return      bool
*/
bool ds_compl_check::m_create_response()
{
    // initialize some variables:
    ds_hvector_btype<dsd_cc_to_send> ds_checks( adsc_wsp_helper );
    bool                             bo_ret;
    dsd_role*                        adsl_no_check;

    //-------------------------------------------
    // check for a valid request:
    //-------------------------------------------
    if ( dsc_recdata.inc_version != SUP_PROTOCOL_VERSION ) {
        adsc_wsp_helper->m_logf( ied_sdh_log_warning, 
                                 "HCOCW005W: unsupported protcol version %d found",
                                 dsc_recdata.inc_version );
        m_send_error( "unsupported protcol version found" );
        return false;
    }
    if ( dsc_recdata.ienc_state  == ied_pstate_req_unknown ) {
        adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                "HCOCW006W unknown state found" );
        m_send_error( "unknown state found" );
        return false;
    }

    //-------------------------------------------
    // print the message (if existing):
    //-------------------------------------------
    if ( dsc_recdata.inc_len_msg > 0 ) {
        adsc_wsp_helper->m_logf( ied_sdh_log_info,
                                 "HCOCI003I message from client: %.*s",
                                 dsc_recdata.inc_len_msg,
                                 dsc_recdata.achc_msg );
    }

    //-------------------------------------------
    // get user information:
    //-------------------------------------------
    bo_ret = m_get_logged_user();
    if ( bo_ret == false ) {
        adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                "HCOCW007W invalid usercookie received" );
        m_send_error( "invalid usercookie received" );
        return false;
    }

    //-------------------------------------------
    // switch state:
    //-------------------------------------------
    switch ( dsc_recdata.ienc_state ) {
        /*
            send list of compliance checks to client:
        */
        case ied_pstate_req_config:
            //-----------------------------------
            // get checks for current user:
            //  -> even send if there are no 
            //     checks for this user
            //  -> ignore return value
            //-----------------------------------
            m_get_checks( &ds_checks );

            //-----------------------------------
            // send the checks:
            //-----------------------------------
            m_send_checks( &ds_checks );
            break;

        /*
            set found user role:
        */
        case ied_pstate_req_result:
            //-----------------------------------
            // is there a successful check?
            //-----------------------------------
            if ( dsc_recdata.inc_len_role < 1 ) {
                //-------------------------------
                // search if there is a role without check:
                //-------------------------------
                adsl_no_check = m_role_without_check();

                if ( adsl_no_check == NULL ) {
                    adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                            "HCOCW008W no successful compliance check found" );

                    //---------------------------
                    // set error state:
                    //---------------------------
                    dsc_user.m_set_state( ST_COMPLCHECK_ERROR );

                    //---------------------------
                    // send ack:
                    //---------------------------
                    m_send_ack( dsd_const_string::m_null() );
                    break;
                }
                dsc_recdata.achc_role = adsl_no_check->achc_name;
                dsc_recdata.inc_len_role = adsl_no_check->inc_len_name;
            }
            //-----------------------------------
            // save role in cma:
            //-----------------------------------
            bo_ret = m_save_role();
            if ( bo_ret == false ) {
                adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                        "HCOCW009W saving role failed" );
                dsc_user.m_set_state( ST_COMPLCHECK_ERROR );
                break;
            }

            //-----------------------------------
            // set state for successful checks:
            //-----------------------------------
            m_set_role_checks();

            //-----------------------------------
            // set successful states:
            //-----------------------------------
            dsc_user.m_set_state  ( ST_ACCEPTED );
            dsc_user.m_set_state  ( ST_COMPLCHECK_SUCCESS );
            dsc_user.m_unset_state( ST_COMPLCHECK_FORCE );

            //-----------------------------------
            // send ack:
            //-----------------------------------
            m_send_ack( dsd_const_string::m_null() );
            break;

        /*
            there is some installation required:
        */
        case ied_pstate_req_install:
            //-----------------------------------
            // set install state:
            //-----------------------------------
            dsc_user.m_set_state( ST_COMPLCHECK_INSTALL );

            //-----------------------------------
            // send ack:
            //-----------------------------------
            m_send_ack( dsd_const_string::m_null() );
            break;

        /*
            normal antixss polling:
        */
        case ied_pstate_req_axss_ok:
            //-----------------------------------
            // checks were already finished?
            //-----------------------------------
            if ( dsc_user.m_check_state( ST_COMPLCHECK_SUCCESS ) == false ) {
                adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                        "HCOCW010W no compliance check finished yet" );
                m_send_error( "no compliance check finished yet" );
                dsc_user.m_set_state( ST_COMPLCHECK_ERROR );
                bo_ret = false;
                break;
            }

            //-----------------------------------
            // check polling interval:
            //-----------------------------------
            if ( dsc_recdata.inc_interval < 1 ) {
                adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                         "HCOCW011W: invalid polling interval \"%d\" received",
                                         dsc_recdata.inc_interval );
                m_send_error( "invalid polling interval received" );
                dsc_user.m_set_state( ST_COMPLCHECK_ERROR );
                bo_ret = false;
                break;
            }

            //-----------------------------------
            // set new timeout:
            //-----------------------------------
            dsc_user.m_set_axss_time(   adsc_wsp_helper->m_cb_get_time()
                                      + dsc_recdata.inc_interval         );

            //-----------------------------------
            // send ack:
            //-----------------------------------
            m_send_ack( dsd_const_string::m_null() );
            break;

        /*
            antixss returning an error:
        */
        case ied_pstate_req_axss_err:
            //-----------------------------------
            // checks were already finished?
            //-----------------------------------
            if ( dsc_user.m_check_state( ST_COMPLCHECK_SUCCESS ) == false ) {
                adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                        "HCOCW012W no compliance check finished yet" );
                m_send_error( "no compliance check finished yet" );
                dsc_user.m_set_state( ST_COMPLCHECK_ERROR );
                bo_ret = false;
                break;
            }

            // print a message:
            adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                    "HCOCW013W AntiXSS returned an error - delete accepted state" );

            //-----------------------------------
            // reset states:
            //-----------------------------------
            dsc_user.m_unset_state( ST_ACCEPTED );
            dsc_user.m_set_state  ( ST_COMPLCHECK_ERROR );
            dsc_user.m_set_state  ( ST_COMPLCHECK_FORCE );

            //-----------------------------------
            // send ack:
            //-----------------------------------
            m_send_ack( dsd_const_string::m_null() );
            break;
    } // end of switch

    return bo_ret;
} // end of ds_compl_check::m_create_response


/**
 * private function ds_compl_check::m_send_error()
 * send an error message to client
 *
 * @param[in]   const char* ach_message
*/
void ds_compl_check::m_send_error( const dsd_const_string& rdsp_message )
{
    // initialize some variables:
    ds_hstring ds_length( adsc_wsp_helper );
    ds_hstring ds_data  ( adsc_wsp_helper );

    ds_data.m_write ( "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" );
    ds_data.m_write_xml_open_tag(achr_proto_nodes[ied_pnode_quarantine]);
    ds_data.m_write_xml_open_tag(achr_proto_nodes[ied_pnode_state]);
    ds_data.m_write_xml_text(achr_proto_resp_states[ied_pstate_resp_invalid]);
    ds_data.m_write_xml_close_tag(achr_proto_nodes[ied_pnode_state]);
    if ( rdsp_message.m_get_len() > 0 ) {
        ds_data.m_write_xml_open_tag(achr_proto_nodes[ied_pnode_message]);
        ds_data.m_write_xml_text(rdsp_message);
        ds_data.m_write_xml_close_tag(achr_proto_nodes[ied_pnode_message]);
    }
    ds_data.m_write_xml_close_tag(achr_proto_nodes[ied_pnode_quarantine]);

    //---------------------------------------
    // evaluate length in nhash:
    //---------------------------------------
    ds_length.m_write_nhasn( ds_data.m_get_len() );
    
    //---------------------------------------
    // send length and data:
    //---------------------------------------
    adsc_wsp_helper->m_send_data( ds_length.m_get_ptr(), ds_length.m_get_len() );
    adsc_wsp_helper->m_send_data( ds_data.m_get_ptr(),   ds_data.m_get_len()   );
} // end of ds_compl_check::m_send_error


/**
 * private function ds_compl_check::m_send_checks()
 * send a list of checks to client
 *
 * @param[in]   ds_hvector_btype<dsd_cc_to_send>*   ads_vchecks
*/
void ds_compl_check::m_send_checks( ds_hvector_btype<dsd_cc_to_send>* ads_vchecks )
{
    // initialize some variables:
    ds_hstring           ds_length ( adsc_wsp_helper );
    ds_hstring           ds_data   ( adsc_wsp_helper );
    dsd_cc_to_send       ds_to_send;
    size_t               uin_pos;
    dsd_aux_query_client dsl_ineta;

    ds_data.m_write ( "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" );

    // <quarantine>
    ds_data.m_write_xml_open_tag(achr_proto_nodes[ied_pnode_quarantine]);

    // <state>%s</state>
    ds_data.m_write_xml_open_tag(achr_proto_nodes[ied_pnode_state]);
    ds_data.m_write_xml_text(achr_proto_resp_states[ied_pstate_resp_config]);
    ds_data.m_write_xml_close_tag(achr_proto_nodes[ied_pnode_state]);

    // write incoming ip address:
    dsl_ineta = dsc_user.m_get_client_ineta();
    if ( dsl_ineta.inc_addr_family == AF_INET ) {
        // <myip4>%s</myipv4>
        ds_data.m_write_xml_open_tag(achr_proto_nodes[ied_pnode_myip4]);
        m_print_ineta( &ds_data, &dsl_ineta );
        ds_data.m_write_xml_close_tag(achr_proto_nodes[ied_pnode_myip4]);
    } else if ( dsl_ineta.inc_addr_family == AF_INET6 ) {
        // <myip6>%s</myipv6>
        ds_data.m_write_xml_open_tag(achr_proto_nodes[ied_pnode_myip6]);
        m_print_ineta( &ds_data, &dsl_ineta );
        ds_data.m_write_xml_close_tag(achr_proto_nodes[ied_pnode_myip6]);
    }

    // <compliance_list>
    ds_data.m_write_xml_open_tag(achr_proto_nodes[ied_pnode_compl_list]);

    for ( uin_pos = 0; uin_pos < ads_vchecks->m_size(); uin_pos++ ) {
        ds_to_send = ads_vchecks->m_get(uin_pos);

        // <compliance check>
        ds_data.m_write_xml_open_tag(achr_proto_nodes[ied_pnode_compl_check]);

        // <role_name>%s</role_name>
        ds_data.m_write_xml_open_tag(achr_proto_nodes[ied_pnode_role_name]);
        ds_data.m_write_xml_text(dsd_const_string(ds_to_send.achc_role, ds_to_send.inc_len_role));
        ds_data.m_write_xml_close_tag(achr_proto_nodes[ied_pnode_role_name]);

        ds_data.m_write(ds_to_send.adsc_check->achc_str_xml,                          // m_write_xml_text() sems to be wrong here.
                         ds_to_send.adsc_check->inc_len_xml);

        // </compliance check>
        ds_data.m_write_xml_close_tag(achr_proto_nodes[ied_pnode_compl_check]);
    }

    // </compliance_list>
    ds_data.m_write_xml_close_tag(achr_proto_nodes[ied_pnode_compl_list]);

    // </quarantine>
    ds_data.m_write_xml_close_tag(achr_proto_nodes[ied_pnode_quarantine]);

    //---------------------------------------
    // evaluate length in nhash:
    //---------------------------------------
    ds_length.m_write_nhasn( ds_data.m_get_len() );
    
    //---------------------------------------
    // send length and data:
    //---------------------------------------
    adsc_wsp_helper->m_send_data( ds_length.m_get_ptr(), ds_length.m_get_len() );
    adsc_wsp_helper->m_send_data( ds_data.m_get_ptr(),   ds_data.m_get_len()   );
} // end of ds_compl_check::m_send_checks


/**
 * private function ds_compl_check::m_print_ineta
 *
 * @param[in]   ds_hstring                  *adsp_out       output buffer
 * @param[in]   struct dsd_aux_query_client *adsp_client    ineta
*/
void ds_compl_check::m_print_ineta( ds_hstring* adsp_out,
                                    struct dsd_aux_query_client *adsp_client )
{
    switch ( adsp_client->inc_addr_family ) {
        case AF_INET:
            // IPv4:
            adsp_out->m_writef( "%d.%d.%d.%d",
                                (unsigned char)adsp_client->chrc_client_ineta[0],
                                (unsigned char)adsp_client->chrc_client_ineta[1],
                                (unsigned char)adsp_client->chrc_client_ineta[2],
                                (unsigned char)adsp_client->chrc_client_ineta[3] );
            break;
        default:
            adsp_out->m_writef( "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                                (unsigned char)adsp_client->chrc_client_ineta[ 0],
                                (unsigned char)adsp_client->chrc_client_ineta[ 1],
                                (unsigned char)adsp_client->chrc_client_ineta[ 2],
                                (unsigned char)adsp_client->chrc_client_ineta[ 3],
                                (unsigned char)adsp_client->chrc_client_ineta[ 4],
                                (unsigned char)adsp_client->chrc_client_ineta[ 5],
                                (unsigned char)adsp_client->chrc_client_ineta[ 6],
                                (unsigned char)adsp_client->chrc_client_ineta[ 7],
                                (unsigned char)adsp_client->chrc_client_ineta[ 8],
                                (unsigned char)adsp_client->chrc_client_ineta[ 9],
                                (unsigned char)adsp_client->chrc_client_ineta[10],
                                (unsigned char)adsp_client->chrc_client_ineta[11],
                                (unsigned char)adsp_client->chrc_client_ineta[12],
                                (unsigned char)adsp_client->chrc_client_ineta[13],
                                (unsigned char)adsp_client->chrc_client_ineta[14],
                                (unsigned char)adsp_client->chrc_client_ineta[15] );
            break;
    }
} // end of ds_compl_check::m_print_ineta


/**
 * private function ds_compl_check::m_send_ack
 * send a ack to client
 *
 * @param[in]   const char* ach_message
*/
void ds_compl_check::m_send_ack( const dsd_const_string& rdsp_message )
{
    // initialize some variables:
    ds_hstring       ds_length ( adsc_wsp_helper );
    ds_hstring       ds_data   ( adsc_wsp_helper );

    ds_data.m_write ( "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" );

    // <quarantine>
    ds_data.m_write_xml_open_tag(achr_proto_nodes[ied_pnode_quarantine]);

    // <state>%s</state>
    ds_data.m_write_xml_open_tag(achr_proto_nodes[ied_pnode_state]);
    ds_data.m_write_xml_text(achr_proto_resp_states[ied_pstate_resp_ack]);
    ds_data.m_write_xml_close_tag(achr_proto_nodes[ied_pnode_state]);
    
    // <message>%s</message>
    if ( rdsp_message.m_get_len() > 0 ) {
        ds_data.m_write_xml_open_tag(achr_proto_nodes[ied_pnode_message]);
        ds_data.m_write_xml_text(rdsp_message);
        ds_data.m_write_xml_close_tag(achr_proto_nodes[ied_pnode_message]);
    }

    // </quarantine>
    ds_data.m_write_xml_close_tag(achr_proto_nodes[ied_pnode_quarantine]);

    //---------------------------------------
    // evaluate length in nhash:
    //---------------------------------------
    ds_length.m_write_nhasn( ds_data.m_get_len() );
    
    //---------------------------------------
    // send length and data:
    //---------------------------------------
    adsc_wsp_helper->m_send_data( ds_length.m_get_ptr(), ds_length.m_get_len() );
    adsc_wsp_helper->m_send_data( ds_data.m_get_ptr(),   ds_data.m_get_len()   );
} // end of ds_compl_check::m_send_checks


/**
 * private function ds_compl_check::m_read_xml
 * read xml data and get our command structure back
 *
 * @param[in]   char*               ach_xml             pointer to xml data
 * @param[in]   int                 in_len              length of xml data
 * @return      bool                                    true = success
*/
bool ds_compl_check::m_read_xml( const char* ach_xml, int in_len )
{
    // initialize some variables:
    ds_xml          dsl_xml;            // xml parser class
    dsd_xml_tag*    ads_pnode;          // xml parent node
    const char*           ach_node;           // node name
    int             in_len_node;        // length of node name
    const char*           ach_value;          // node value
    int             in_len_val;         // length of node value
    ied_charset     ien_xml_encoding;   // encoding of xml data
    ied_proto_nodes ien_key;            // node key

    //--------------------------------------
    // parse xml data:
    //--------------------------------------
    dsl_xml.m_init( adsc_wsp_helper );
    ads_pnode        = dsl_xml.m_from_xml( ach_xml, in_len );
    ien_xml_encoding = dsl_xml.m_get_encoding();

    //--------------------------------------
    // read our commands from xml:
    //--------------------------------------
    if ( ads_pnode == NULL ) {
        adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                "HCOCW014W xml parser returned error" );
        return false;
    }
    dsl_xml.m_get_node_name( ads_pnode, &ach_node, &in_len_node );
    ien_key = m_get_node_key( ach_node, in_len_node, ien_xml_encoding );
    if ( ien_key != ied_pnode_quarantine ) {
        adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                "HCOCW015W first tag must be <quarantine>" );
        return false;
    }
    ads_pnode = dsl_xml.m_get_firstchild( ads_pnode );

    //--------------------------------------
    // reset received data:
    //--------------------------------------
    memset( &dsc_recdata, 0, sizeof(dsd_req_data) );
    dsc_recdata.ienc_state = ied_pstate_req_unknown;

    //--------------------------------------
    // loop through the nodes
    //--------------------------------------
    while ( ads_pnode != NULL ) {
        if ( dsl_xml.m_get_node_type( ads_pnode ) == ied_tag ) {
            //------------------------------
            // get node name:
            //------------------------------
            dsl_xml.m_get_node_name( ads_pnode, &ach_node, &in_len_node );
            if ( ach_node == NULL || in_len_node == 0 ) {
                ads_pnode = dsl_xml.m_get_nextsibling( ads_pnode );
                continue;
            }

            //------------------------------
            // get node key:
            //------------------------------
            ien_key = m_get_node_key( ach_node, in_len_node, ien_xml_encoding );
            switch ( ien_key ) {
                case ied_pnode_cookie:
                    //----------------------
                    // get node value:
                    //----------------------
                    dsl_xml.m_get_node_value( ads_pnode, &ach_value, &in_len_val );
                    if ( ach_value == NULL || in_len_val < 1 ) {
                        ads_pnode = dsl_xml.m_get_nextsibling( ads_pnode );
                        continue;
                    }
                    dsc_recdata.achc_cookie    = ach_value;
                    dsc_recdata.inc_len_cookie = in_len_val;
                    break;

                case ied_pnode_version:
                    //----------------------
                    // get node value:
                    //----------------------
                    dsl_xml.m_get_node_value( ads_pnode, &ach_value, &in_len_val );
                    if ( ach_value == NULL || in_len_val < 1 ) {
                        ads_pnode = dsl_xml.m_get_nextsibling( ads_pnode );
                        continue;
                    }
                    dsc_recdata.inc_version = atoi( ach_value );
                    break;

                case ied_pnode_message:
                    //----------------------
                    // get node value:
                    //----------------------
                    dsl_xml.m_get_node_value( ads_pnode, &ach_value, &in_len_val );
                    if ( ach_value == NULL || in_len_val < 1 ) {
                        ads_pnode = dsl_xml.m_get_nextsibling( ads_pnode );
                        continue;
                    }
                    dsc_recdata.achc_msg    = ach_value;
                    dsc_recdata.inc_len_msg = in_len_val;
                    break;

                case ied_pnode_state:
                    //----------------------
                    // get node value:
                    //----------------------
                    dsl_xml.m_get_node_value( ads_pnode, &ach_value, &in_len_val );
                    if ( ach_value == NULL || in_len_val < 1 ) {
                        ads_pnode = dsl_xml.m_get_nextsibling( ads_pnode );
                        continue;
                    }
                    dsc_recdata.ienc_state = m_get_state( ach_value, in_len_val,
                                                          ien_xml_encoding );
                    break;

                case ied_pnode_interval:
                    //----------------------
                    // get node value:
                    //----------------------
                    dsl_xml.m_get_node_value( ads_pnode, &ach_value, &in_len_val );
                    if ( ach_value == NULL || in_len_val < 1 ) {
                        ads_pnode = dsl_xml.m_get_nextsibling( ads_pnode );
                        continue;
                    }
                    dsc_recdata.inc_interval = atoi( ach_value );
                    break;

                case ied_pnode_compl_list:
                    m_read_compl_list( &dsl_xml, ads_pnode );
                    break;

                default:
                    adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                             "HCOCW016W unknown tag found '%.*s' - ignored",
                                             in_len_node, ach_node );
                    break;
            }
        }
        ads_pnode = dsl_xml.m_get_nextsibling( ads_pnode );
    }
    return true;
} // end of ds_compl_check::m_read_xml


/**
 * private function ds_compl_check::m_read_compl_list
 * read compliance list
 *
 * @param[in]   ds_xml*             ads_xml             xml parser class
 * @param[in]   dsd_xml_tag*        ads_node            current tag
 * @return      bool                                    true = success
*/
bool ds_compl_check::m_read_compl_list( ds_xml* ads_xml, dsd_xml_tag* ads_node )
{
    // initialize some variables:
    const char*           ach_node;           // node name
    int             in_len_node;        // length of node name
    ied_proto_nodes ien_key;            // node key
    ied_charset     ien_xml_encoding;   // encoding of xml data

    ien_xml_encoding = ads_xml->m_get_encoding();
    ads_node         = ads_xml->m_get_firstchild( ads_node );

    //--------------------------------------
    // loop through the nodes
    //--------------------------------------
    while ( ads_node != NULL ) {
        if ( ads_xml->m_get_node_type( ads_node ) == ied_tag ) {
            //------------------------------
            // get node name:
            //------------------------------
            ads_xml->m_get_node_name( ads_node, &ach_node, &in_len_node );
            if ( ach_node == NULL || in_len_node == 0 ) {
                ads_node = ads_xml->m_get_nextsibling( ads_node );
                continue;
            }

            //------------------------------
            // get node key:
            //------------------------------
            ien_key = m_get_node_key( ach_node, in_len_node, ien_xml_encoding );
            switch ( ien_key ) {
                case ied_pnode_compl_check:
                    m_read_compl_check( ads_xml, ads_node );
                    break;

                default:
                    adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                                             "HCOCW017W unknown tag '%.*s' in compliance_list found - ignored",
                                             in_len_node, ach_node );
                    break;
            }
        }
        ads_node = ads_xml->m_get_nextsibling( ads_node );
    }

    return true;
} // end of ds_compl_check::m_read_compl_list


/**
 * private function ds_compl_check::m_read_compl_check
 * read xml data and get our command structure back
 *
 * @param[in]   ds_xml*             ads_xml             xml parser class
 * @param[in]   dsd_xml_tag*        ads_node            current tag
 * @return      bool                                    true = success
*/
bool ds_compl_check::m_read_compl_check( ds_xml* ads_xml, dsd_xml_tag* ads_node )
{
    // initialize some variables:
    const char*           ach_node;           // node name
    int             in_len_node;        // length of node name
    const char*           ach_value;          // node value
    int             in_len_val;         // length of node value
    ied_proto_nodes ien_key;            // node key
    ied_charset     ien_xml_encoding;   // encoding of xml data

    ien_xml_encoding = ads_xml->m_get_encoding();
    ads_node         = ads_xml->m_get_firstchild( ads_node );

    //--------------------------------------
    // loop through the nodes
    //--------------------------------------
    while ( ads_node != NULL ) {
        if ( ads_xml->m_get_node_type( ads_node ) == ied_tag ) {
            //------------------------------
            // get node name:
            //------------------------------
            ads_xml->m_get_node_name( ads_node, &ach_node, &in_len_node );
            if ( ach_node == NULL || in_len_node == 0 ) {
                ads_node = ads_xml->m_get_nextsibling( ads_node );
                continue;
            }

            //------------------------------
            // get node key:
            //------------------------------
            ien_key = m_get_node_key( ach_node, in_len_node, ien_xml_encoding );
            switch ( ien_key ) {
                case ied_pnode_role_name:
                    if ( dsc_recdata.inc_len_role < 1 ) {
                        //------------------
                        // get node value:
                        //------------------
                        ads_xml->m_get_node_value( ads_node, &ach_value, &in_len_val );
                        if ( ach_value == NULL || in_len_val < 1 ) {
                            ads_node = ads_xml->m_get_nextsibling( ads_node );
                            continue;
                        }
                        dsc_recdata.achc_role    = ach_value;
                        dsc_recdata.inc_len_role = in_len_val;
                    } else {
                        adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                                "HCOCW018W only one compliance_check allowed" );
                    }
                    break;

                default:
                    adsc_wsp_helper->m_logf( ied_sdh_log_warning,
                        "HCOCW019W: unknown tag '%.*s' in compliance_check found - ignored",
                        in_len_node, ach_node );
                    break;
            }
        }
        ads_node = ads_xml->m_get_nextsibling( ads_node );
    }

    return true;
} // end of ds_compl_check::m_read_compl_check


/**
 * private function ds_compl_check::m_get_node_key
 * get node key by name
 *
 * @param[in]   char*           ach_node            node name
 * @param[in]   int             in_len_node         length of node name
 * @param[in]   ied_charset     ien_encoding        encoding of node name
 * @return      ied_proto_nodes                     node key
*/
ied_proto_nodes ds_compl_check::m_get_node_key( const char* ach_node, int in_len_node,
                                                ied_charset ien_encoding )
{
    for ( int in_element=0; in_element<SZS_NUM_PROTO_NODES; in_element++ ) {
        int  in_compare = 0;                  // result of compare
        BOOL bo_ret = m_cmpi_vx_vx( &in_compare,
                               ach_node, in_len_node,
                               ien_encoding,
                               achr_proto_nodes[in_element].m_get_ptr(),
                               achr_proto_nodes[in_element].m_get_len(),
                               ied_chs_utf_8 );

        if ( bo_ret == TRUE && in_compare == 0 ) {
            // we found an known node
            return (ied_proto_nodes)in_element;
        }
    }

    return ied_pnode_unknown;
} // end of ds_compl_check::m_get_node_key


/**
 * private function ds_compl_check::m_get_state
 *
 * @param[in]   const char*             ach_state           pointer to state
 * @param[in]   int                     in_len              length of state
 * @param[in]   ied_charset             ien_encoding        encoding of state
 * @return      ied_proto_req_state                         state key
*/
ied_proto_req_state ds_compl_check::m_get_state( const char* ach_state, int in_len,
                                                 ied_charset ien_encoding )
{
    dsd_unicode_string dsl_key;
    dsl_key.ac_str = (void*)ach_state;
    dsl_key.imc_len_str = in_len;
    dsl_key.iec_chs_str = ien_encoding;
    return ds_wsp_helper::m_search_equals2(achr_proto_req_states, dsl_key, ied_pstate_req_unknown);
} // end of ds_compl_check::m_get_state


/**
 * private function ds_compl_check::m_from_nhasn
 *
 * @param[out]      int*                ain_num         output 
 * @param[in]       dsd_gather_i_1*     ads_gather      input buffer
 * @param[in/out]   int*                ain_offset      position in gather
 *
 * @return          bool                                true = success
*/
bool ds_compl_check::m_from_nhasn( int* ain_num,
                                   struct dsd_gather_i_1 * ads_gather,
                                   int* ain_offset )
{
    // initialize some variables:
    bool    bo_ret    = false;
    int     in_return = 0;
    char*   ach_ptr   = adsc_wsp_helper->m_get_end_ptr( ads_gather, *ain_offset );
    if ( ach_ptr == NULL ) {
        return false;
    }

    for ( ; ; ) {
        in_return |= (*ach_ptr &0x7F );
        (*ain_offset)++;
        if ( (*ach_ptr & 0x80) == 0 ) {
            bo_ret = true;
            break;
        }
        ach_ptr = adsc_wsp_helper->m_get_end_ptr( ads_gather, *ain_offset );
        if ( ach_ptr == NULL ) {
            break;
        }
        in_return <<= 7;
    }

    if ( *ain_num < 0 ) {
        *ain_num = 0;
    }
    (*ain_num) += in_return;

    return bo_ret;
} // end of ds_compl_check::m_from_nhasn


/**
 * private function ds_compl_check::m_count_nhasn_len
 * get needed buffer length for in_input in nhasn format
 *
 * @param[in]   int     in_input
 *
 * @return      int                 needed buffer len
 *                                  or error code
*/
int ds_compl_check::m_count_nhasn_len( int in_input )
{
    int in_bytenum = 0;

    do {  //get the number of bytes needed for nhasn number encoded
        in_input >>= 7;
        in_bytenum++;
    } while (in_input);

    return in_bytenum;
} // end of ds_compl_check::m_count_nhasn_len
