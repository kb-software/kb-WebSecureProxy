#ifndef DS_WS_GATE_H
#define DS_WS_GATE_H

#include "./interpreter/ds_interpret_html.h"
#include "./interpreter/ds_interpret_css.h"
#include "./interpreter/ds_interpret_script.h"
#include "./interpreter/ds_interpret_xml.h"
#include "./interpreter/dsd_interpret_ica.h"

#include <ds_ck_mgmt.h>
#include <ds_cookie.h>

class ds_session; //forward-definition!!

/*! \brief Main class of the Web Server Gate.
 *
 * @ingroup webservergate
 *
 * This contains all information regarding the communication between the server and the client
 */
class ds_ws_gate
{
public:
	//! Mode of data given to the interpreter.
    enum data_modes {
        ien_data_until_close = 0,	/**< All remaining data until the connection is closed represents the message-body. */
        ien_data_chunked,		  	/**< Data is sent in chunks */
        ien_data_content_length		/**< When data is sent in this mode, the content length field contains the size of the whole message. */
    };

	enum hob_types {
        ien_hobtype_not_defined = -1,
        ien_hobtype_js,
        ien_hobtype_css,
		ien_hobtype_html,
		ien_hobtype_ws,
        ien_hobtype_any,
        ien_hobtype_none
    };

	enum ied_request_type {
		ien_request_type_unknown,
		ien_request_type_wsg_external,
		ien_request_type_wsg_action,
		ien_request_type_vlink,
	};

	enum ied_request_subtype {
		ien_request_subtype_unknown,
		ien_request_subtype_wfa_login,
		ien_request_subtype_wfa_bookmarks,
	};

	struct dsd_wsg_url {
		ds_hstring hstr_url_patch;
		ied_request_type iec_request_type;
		ied_request_subtype iec_request_subtype;

		ds_hstring hstr_temp_path1;
		ds_hstring hstr_temp_path2;

		dsd_const_string hstr_protocol;
		dsd_const_string hstr_authority_of_webserver; // Authority of a webserver (e.g. google.de in '/http://google.de')
		dsd_const_string hstr_hostname_of_webserver;
		dsd_const_string hstr_port_of_webserver; // Port as string (always valid).
		dsd_const_string hstr_path;
		dsd_const_string hstr_query;
		// request for WSG; protocol to webserver is https!!
		bool bo_ssl_to_ext_ws;
		// request from browser with absolute URL and no SSL (e.g. GET http://abc...)
		// bool bo_abs_url_no_ssl;
		int in_port_of_webserver;
		// SM move to here
		int in_hob_type;
		// SM charset of hob resource
		ied_charset iec_hob_type_charset;
		// SM origin of hob resource
		dsd_const_string hstr_hob_type_origin;
		// SM worker type of hob resource (JS)
		dsd_const_string hstr_hob_type_worker;
		// SM HOB query part
		dsd_const_string hstr_hob_query;       // Query part of the URL.
	};

	//! Constructor
    ds_ws_gate(void);
    //! Destructor
	~ds_ws_gate(void);

    // here is the staff...
    //! Initialises the cookie manager.
	bool m_setup();
	//! Initialises the WebServer Gate class
    bool m_init (ds_session* ads_session_in);
    //! Handle the response-header of an external webserver
    int m_handle_response_header(int in_content_type, bool bo_send_www_auth_to_client);
    //! Handle the message-body of a response of an external webserver
    int m_begin_response_data();
    //! Handle the message-body of a response of an external webserver
    int m_handle_response_data(bool bo_data_until_close, bool bo_send = true);
	int m_accept_request(const dsd_virtual_link**);
#if SM_USE_OLD_HOBNET
	//! Handle a request from the browser
    int m_handle_request(bool bo_https_to_ws_hob_net=false, const dsd_const_string* ahstr_host_hob_net=NULL, int in_port_hob_net=0, const dsd_const_string* ahstr_path=NULL);
#else
    int m_handle_request();
#endif
	//! Determine, whether the data has to be changed by the WebServer Gate
	ds_interpret* m_get_interpreter(int inl_content_type);
    //! Close TCP connection to external webserver server
	void m_close_conn_to_ext_server();

    //! Indicates whether a TCP-connection to an external webserver is established.
    bool bo_connected;
	//! Indicates if we have a special URL, for which we must activate SSO-procedure (insert e.g. username and password into a login page and press the OK button).
    bool bo_do_sso;
	//! Indicates whether the interpreter shall be ignored during the communication.
    bool bo_ignore_interpreter;
	//! Indicates whether the client has requested a WebSocket upgrade.
	bool boc_websocket_upgrade;
	//! Indicates whether the server has switched to WebSocket.
	bool boc_websocket_protocol;
	//! Indicates whether the interpreter has returned an error during processing.
	bool boc_interpret_failed;
	//! Indicates whether the response data should be skip.
    bool bo_skip_response_data;
	//! Indicates whether the connection has to be kept alive after transmission.
   bool boc_keep_alive;

	const struct dsd_virtual_link* adsc_virtual_link;
	struct dsd_wsg_url dsc_url;
	
	//! Clears data within this class
    int m_clear(void);

	ds_hstring hstr_hdrline_cookie;
	ds_hstring hstr_prot_authority_ext_ws;
    ds_interpret_html dsc_interpret_html;     //!< Interpreter class for html-pages
    ds_interpret_xml dsc_interpret_xml;       //!< Interpreter class for xml-pages
    ds_interpret_css dsc_interpret_css;       //!< Interpreter-class for css-files
    ds_interpret_script dsc_interpret_script; //!< Interpreter-class for javascript-files
    dsd_interpret_ica   dsc_interpret_ica;    //!< Interpreter-class for ica files
    ds_interpret dsc_interpret_pass;          //!< Interpreter class for decompress/compress mode
	ds_interpret* adsc_interpreter;

    ds_ck_mgmt dsc_ck_manager;	//!< The cookie manager class.

	//! Length of data which must be sent unchanged to server
    int in_len_to_send_unchanged_to_server; // JF 14.10.008 Ticket[16210]
private:
	// session class
    ds_session* ads_session;

    // length of data, which must be sent unchanged to client
    int in_len_to_send_unchanged_to_browser;

    // send received chunked data unchnaged to browser in chunked format
    int m_send_chunked_unchanged(void);
    // call the concerned interpreter-class, which will e.g. chnage hyperlinks
    int m_call_interpreter(int in_data_mode, bool bo_send_as_chunked);
    // we received chunked data of a file, which need not to be changed -> pass the data unchanged
    int m_pass_chunked_unchanged(void);
    // call interpreter-class for received data in chunked format
    int m_interpret_chunked();
    bool m_is_sso(void);
    bool m_is_virtual_link(const dsd_const_string& rhstr_org_url, const dsd_const_string& rhstr_target_url);
#if SM_USE_OLD_HOBNET
	int m_send_to_ext_ws(const dsd_const_string& rhstr_to_send,
		bool bo_https_to_ws_hob_net, const dsd_const_string* ahstr_host_hob_net, int in_port_hob_net);
#else
	int m_send_to_ext_ws(const dsd_const_string& rhstr_to_send);
#endif
	bool m_do_connect(bool bo_https, const dsd_const_string& rhstr_host, int in_port, ds_hstring& ahstr_err_msg, dsd_const_string& adsp_error_key );
    bool m_connection_changed(bool bo_https, const dsd_const_string& rhstr_host, int in_port);
    // process the header field 'Set-Cookie'
    ds_hstring m_change_set_cookie(const dsd_const_string& hstr_set_cookie);
    // store protocol, domain, port of the last connected webserver
    bool bo_last_ws_prot_https;
    ds_hstring hstr_last_ws_str_host;
    int in_last_ws_port;

    // ica stuff
    bool m_is_ica_srv();
	bool m_resolve_wsg_encoding(ds_url::dsd_base_url& rdsp_base_url_out, const dsd_const_string& rdsp_base_path, const dsd_const_string& rdsp_file_path, ds_hstring& rdsp_temp);
	bool m_parse_wsg_url(const dsd_const_string& rdsp_resource, dsd_wsg_url& rdsp_wsg_url);
};

#endif // DS_WS_GATE_H
