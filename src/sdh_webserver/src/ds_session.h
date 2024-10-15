#ifndef DS_SESSION_H
#define DS_SESSION_H

#include <ds_ldap.h> // insure that no "windows.h" is included infront of this file!

// Ticket[15874]
#include <ds_wsp_helper.h>
#include <ds_usercma.h>
#include <ds_authenticate.h>
#include "./login/ds_pre_cma.h"
#include "./login/ds_auth.h"
#include "ds_control.h"
#include "ds_transaction.h"
#include "ds_http_header.h"
#include "ds_zlib.h"
#include "ds_id.h"
#include "./iws/ds_webserver.h"
#include "./wsg/ds_ws_gate.h"
#include "./utils/helper.h"
#include "./ds_state.h"

#ifndef _HOB_AVL03_H
    #define _HOB_AVL03_H
    #include <hob-avl03.h>
#endif //_HOB_AVL03_H
#include <ds_resource.h>


#define RESOURCES ((ds_resource*)(ads_session->ads_config->av_resource))
#define GET_RESOURCE(ach_key, in_key_len, ach_res, in_len_res) RESOURCES->m_get(ads_session->dsc_control.in_cma_lang, ach_key, in_key_len, &ach_res, &in_len_res)
#define GET_RES(ach_key, ach_res, in_len_res) RESOURCES->m_get(ads_session->dsc_control.in_cma_lang, ach_key, &ach_res, &in_len_res)


/*! \brief Session class
 *
 * @ingroup webserver
 *
 * Holds all the information about a session
 */
class ds_session
{
public:

    enum state_auth_basic {
       ien_st_auth_basic_not_active         =  0,
       ien_st_auth_basic_sent_authorization =  1,  // Authorization was sent to web server.
       ien_st_auth_basic_failed             =  2,
       ien_st_auth_basic_succeeded          =  3
    };

    enum state_auth_negotiate {
       ien_st_auth_nego_not_active                     =  0,
       ien_st_auth_nego_sent_avail_mechs               =  1,  // Available mechanisms were sent to web server.
       ien_st_auth_nego_sent_mech_tok                  =  2,  // MechToken (=ServiceTicket) was sent to web server.
       ien_st_auth_nego_succeeded                      =  3
    };

    ds_session();
    ~ds_session(void);

    void* operator new(size_t, void* av_location) {
        return av_location;
    }

    // avoid warning:
    void operator delete( void*, void* ) {};

    void m_init(ds_wsp_helper* adsl_wsp_helper);
    void m_set_conf_authority(ds_hstring* ahstr_conf_authority);
	 bool m_ensure_url_cookie();

    // get the IDs, which must be processed by WSG to enable SSO
    const ds_hvector<ds_id>& m_get_sso_ids(void);
    ds_hvector<ds_id> ds_v_sso_ids;

    void m_get_server_entry_name( ds_hstring * ahstrp_sen );

    void* av_storage;       // use storage container
    ds_control dsc_control;
    ds_transaction dsc_transaction;
    ds_state dsg_state;

    const struct ds_my_conf* ads_config;

    ds_zlib dsg_zlib_comp;
    ds_zlib dsg_zlib_decomp;

    // authority defined in config-file (e.g. hobc02k.hob.de:45678) (no protocol!)
    ds_hstring hstr_conf_authority;

    bool bog_pipelining_detected; // JF 10.12.10 Ticket[21184]

    ds_http_header dsc_http_hdr_in;
    ds_http_header dsc_http_hdr_out;

    ds_webserver dsc_webserver;
    ds_ws_gate dsc_ws_gate;
    bool bo_nonce_already_printed;
    helper dsc_helper;

    // Ticket[15874]:
    ds_wsp_helper* ads_wsp_helper;
    ds_auth        dsc_auth;        // authentication class
#ifdef B20140805
	char*          achc_username;       // username (for creating login page again)
    int            inc_len_username;    // length of username
    char*          achc_domain;         // domain (for creating login page again)
    int            inc_len_domain;      // length of domain
	char*          achc_userdn;
	int			   inc_len_userdn;
#else
	ds_hstring     dsc_username;        // username (for creating login page again)
    ds_hstring     dsc_domain;			// domain (for creating login page again)
	ds_hstring     dsc_userdn;          
#endif
	bool           boc_fixed_login;

    // the nonce (delivered in URL) is already printed
    bool bo_nonce_url_already_printed;

    ds_hstring hstr_data_last_request;

	dsd_const_string hstr_hf_host_last_request;
	ds_hstring hstr_user_agent_last_req;
    int in_http_method_last_request;
	ds_hstring hstr_prot_authority_ws;
	ds_hstring hstr_prot_authority_ws_ext;
	ds_hstring hstr_url_session_id;

    ds_hstring hstr_authorization_basic;
    ds_hstring hstr_data_to_ext_ws_before_negotiate; // Holds the http-header, which was sent to external web server, which then started
                                                       // WWW-Auth-Negotiate. This header will be sent to external web server again, when the Negotiate failed.
    int  in_state_auth_basic, in_state_auth_negotiate;

    bool bog_nego_first_reply; // SSO-Authentication 'Negotiate': First reply of the web server must be treated in special way.

    void *     vpc_krb5_handle;

    // kickout handling:
    ds_hvector_btype<dsd_auth_kick_out> dscv_kick_out;  // we want to kick out someone
    dsd_auth_kicked_out                 dsc_kicked_out; // we are kicked out by someone
	bool boc_watch_session;
};


#endif  // DS_SESSION_H
