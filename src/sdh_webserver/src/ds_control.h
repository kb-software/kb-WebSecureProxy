#ifndef DS_CONTROL_H
#define DS_CONTROL_H

#include "./sdh_web_server.h"
#include "./utils/helper.h"
#include "spnego/ds_spnego_reader.h"
#include <ds_spnego.hpp>

class ds_session; //forward-definition!!  #include "ds_session.h"

/*! \brief Control class
 *
 * @ingroup creator
 *
 * Controls the state of the HTTP processing
 */
class ds_control
{
public:
    enum states {
       ien_st_xxxxxx=1, // JF 14.10.08 for Ticket[16210] sending_to_webserver was moved to a higher value
       ien_st_waiting_for_header_from_browser,        // waiting for a http-header from a webbrowser
       ien_st_skip_message_body_of_request,    // we expect the message-body of a request and will wait until it is complete
	   ien_st_collect_message_body_of_request,    // we expect the message-body of a request and will wait until it is complete
	   ien_st_process_message_body,                // process the received message-body
       ien_st_sending_to_webserver, // JF 14.10.08
       ien_st_body_sent_to_server,   // JF 14.10.08
	   ien_st_waiting_for_header_from_webserver,    // (in case of WSG) waiting for a http-header from webserver: the response-header from a webserver
		ien_st_collect_message_body_from_webserver,    
       ien_st_sending_to_browser,
		 ien_st_sending_stream_to_browser,
	   ien_st_wsg_sending_header_of_data_to_browser,  // WSG sends a header to browser; data are announced!
       ien_st_wsg_sending_body_to_browser,   // WSG just sent the header and there is message-body, which is not sent
       //ien_st_wsg_body_sent_to_browser,
       ien_st_body_sent_to_browser,
       ien_st_websocket,        // websocket mode
       
       //ien_st_copy_in_to_out,                    // normal processing; just copy incoming data to output
       //ien_st_4_first_byte,                     // Socks4: first byte of Socks4-communication must be 0x04
       //ien_st_4_second_byte,                    // Socks4: command code must be 0x01 for CONNECT
       ien_st_free
    };

	enum ied_header_states {
	   ien_st_collect_start_line,               // collect the first line of a http-header
       ien_st_header_not_complete,              // a http-header is partly received
       ien_st_header_complete,                  // a http-header is completly received
	};

    // the tasks, which must be processed after reading/writing CMA was done.
    enum tasks {
        ien_task_invalid                 = 0,
        ien_task_forward_to_login_page   = 1,
        ien_task_forward_to_logout_page  = 2,
        ien_task_send_login_page         = 3,
        ien_task_send_requested_file     = 4,
        ien_task_send_forbidden          = 5,
        //ien_task_send_logout_page        = 6,
        ien_task_send_welcome_page       = 7,
    };

    // These values can be ORed (instead of the values ied_spnego_mech_oid in spnego_defines.hpp).
    typedef enum nego_mechtypes {
        ien_nego_mech_invalid       = 0,
        ien_nego_mech_kerb5         = 1,
        ien_nego_mech_kerb_ms       = 2,
        ien_nego_mech_max           = (ien_nego_mech_kerb5 | ien_nego_mech_kerb_ms)
    } NEGO_MECHTYPES;

    NEGO_MECHTYPES nego_mechtype;

    ds_hstring ds_cma_cookie;

    bool bo_cma_httpcookie_enabled;
    int in_cma_state;
    int in_cma_lang;

    ds_control();
    ~ds_control(void);

    void* operator new(size_t, void* av_location) {
        return av_location;
    }

private:
    bool bo_ws_sent_during_client_sending; // JF 27.01.09: External webserver sent data, during the client sends data (POST to Exchange)
    bool bo_read_complete;
    enum states in_current_state;
	enum ied_header_states iec_header_state;
    int in_http_status_code;
    int in_expected_len;
	ds_session* ads_session;
    bool m_authenticate(const dsd_const_string& ahstr_cookie_line, bool bo_cookie_in_url);
    bool m_authenticate_by_ident();
    // handle a response from an external webserver
    int m_handle_ext_ws_response();
	int  m_collect_complete_message_body();
    void m_do_new_concept(void);
    int  m_read_complete_ws();

    bool m_register_to_cma         ();
    bool m_check_hob_net           ( int in_http_method );
    bool m_is_request_for_wfa      (const dsd_virtual_link* adsl_vir_lnk);
    bool m_is_request_for_globaladm(const dsd_virtual_link* adsp_vir_lnk);
    bool m_is_wsg_enabled          (bool bol_auth_header, bool bo_req_wfa);
    
    // HTTP authentication methods
	 void  m_inject_authorization    (ds_hstring* ahstr_send_to_ws, const dsd_const_string& rdsp_field, const dsd_const_string& ahstr_authenticate);
    void  m_auth_basic              (ds_hstring* ahstr_send_to_ws);
    void  m_auth_negotiate          (ds_hstring* ahstr_send_to_ws, const ds_hstring* ahstr_negotiate_b64);
    
    int  m_read_nego_token_from_ws (ds_spnego_reader* adsl_spnego_reader);
    int  m_cancel_negotiate        (int inl_err_idx);
    int  m_get_kerb_service_ticket (ds_hstring* ahstr_service_ticket);
    int  m_check_kerb_mutual_auth  (const dsd_const_string& ahstr_resp_token);
    
    dsd_const_string m_obtain_hob_cookie(const dsd_const_string& ahstr_cookie_line, dsd_const_string& ahstr_leading_hob_cookie, dsd_const_string& ahstr_trailing_hob_cookie);
public:
    // // process received data
    void m_process(void);
    // if this is done at the constructor, the compiler complains C4355
    void m_init(ds_session* ads_session_in);
    // set the state (e.g. when we want to read message-body-data)
    int m_set_ctrl_state(states in_state);
    int m_get_state();
    bool m_to_ext_server();
    int m_read_http_header();
    // authenticated via WSP identity
    bool bo_authenticated_ident;
    // authenticated via URL
    bool bo_authenticated_url;
    // authenticated via http-header
    bool bo_authenticated_header;
    // authenticated via URL
    bool bo_authenticated_certificate;
    // no 'Content-Length' and no 'Transfer-Encoding:chunked' is found
    bool bo_data_until_close;
    bool boc_keep_alive;
    
    int  m_get_lang();
    bool m_check_state(int in_state);
	const dsd_virtual_link* m_check_virtual_link(const dsd_const_string& rdsp_url, dsd_const_string& rdsp_rest);
    const dsd_virtual_link* m_check_virtual_link_rev(const dsd_const_string& rdsp_url, dsd_const_string& rdsp_rest);

    int m_create_nego_token       (bool bo_init, ds_hstring* ahstr_nego_token, NEGO_MECHTYPES inl_mechtypes, bool bol_include_optimistic_token);
};

#endif // DS_CONTROL_H
