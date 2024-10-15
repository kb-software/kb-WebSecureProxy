#define DEF_HL_INCL_INET
#include "ds_session.h"
#include "sdh_web_server.h"
#include "ds_control.h"
#include "ds_url_parser.h"
#include "iws/ds_webserver.h"
#include "wsg/ds_ws_gate.h"
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H
#include <rdvpn_globals.h>
#include <hob-libwspat.h>
#include <ds_usercma.h>
#include <ds_authenticate.h>

#ifdef DS_PORTLET_FILTER_U_A
#include "xs_user_agent_worker.h"
#endif

//#define USE_KB_HTTP_PARSER
#ifdef USE_KB_HTTP_PARSER
#define LEN_HTTP_PATH_CHECK    128          /* length HTTP path to check */
#include <hob-http-header-1.h>
static const struct dsd_proc_http_header_server_1 dss_phhs1_check_01 = {
   NULL,                                    /* amc_store_alloc - storage container allocate memory */
   NULL,                                    /* amc_store_free - storage container free memory */
   FALSE,                                   /* boc_consume_input - consume input */
   FALSE,                                   /* boc_store_cookies - store cookies */
   FALSE                                    /* boc_out_os - output fields for other side */
};
#endif

#define HTTP_VERSION_PREFIX  "HTTP/"

#ifdef _DEBUG
#define HL_DBG_PRINTF(x, ...)	/*printf(x, __VA_ARGS__)*/
#else
#define HL_DBG_PRINTF(x, ...)
#endif


ds_control::ds_control()
: ads_session(NULL)
, bo_authenticated_url(false)
, bo_data_until_close(false)
{
    in_current_state = ien_st_waiting_for_header_from_browser;
    nego_mechtype = ien_nego_mech_invalid;
}


ds_control::~ds_control(void)
{
}


/*! \brief Process received data
 *
 * @ingroup creator
 *
 * Checks the current processing state and processes the data
 */
void ds_control::m_process(void)
{
	struct dsd_aux_get_session_info ds_sessinfo; /* retrieve session-information */
    struct dsd_aux_get_domain_info_1 dsl_gdi1;  /* retrieve domain-information of connection - gate */
	BOOL bol_ret;
	int iml_1;

#ifdef USE_KB_HTTP_PARSER
    char       chrl_http_url_path[ LEN_HTTP_PATH_CHECK ];  /* HTTP path to check */
    char       chrl_hostname[ 512 ];         /* HTTP Host:              */
    struct dsd_call_http_header_server_1 dsl_chhs1;  /* call HTTP processing at server */
    struct dsd_http_header_server_1 dsl_hhs1;  /* HTTP processing at server */
#endif
#if 0
	if(ads_session->dsc_transaction.ads_trans->boc_eof_server) {
        switch(in_current_state) {
		case ien_st_sending_to_browser: {
			ads_session->dsc_transaction.ads_trans->boc_eof_server = FALSE; 
			return;
		}
		case ien_st_body_sent_to_browser: {
			ads_session->dsc_transaction.ads_trans->boc_eof_server = FALSE; 
			return;
		}
		case ien_st_body_sent_to_server:
			ads_session->dsc_webserver.m_create_resp_header( ds_http_header::ien_status_internal_error,
                0, NULL, NULL, NULL, false, NULL);
            ads_session->dsc_transaction.m_send_header( ied_sdh_dd_toclient );
			m_set_ctrl_state(ien_st_body_sent_to_browser);
			return;
		case ien_st_sending_to_webserver:
			break;
		}
		int a = 0;
    }

	if(ads_session->dsc_transaction.ads_trans->adsc_gather_i_1_in == NULL) {
		return;
	}
#endif
#if 0
	ien_st_xxxxxx=1, // JF 14.10.08 for Ticket[16210] sending_to_webserver was moved to a higher value
       ien_st_waiting_for_header_from_browser,        // waiting for a http-header from a webbrowser
       ien_st_collect_message_body_of_request,    // we expect the message-body of a request and will wait until it is complete
	   ien_st_process_message_body,                // process the received message-body
       ien_st_sending_to_webserver, // JF 14.10.08
       ien_st_body_sent_to_server,   // JF 14.10.08
	   ien_st_waiting_for_header_from_webserver,    // (in case of WSG) waiting for a http-header from webserver: the response-header from a webserver
       ien_st_sending_to_browser,
	   ien_st_wsg_sending_header_of_data_to_browser,  // WSG sends a header to browser; data are announced!
       ien_st_wsg_sending_body_to_browser,   // WSG just sent the header and there is message-body, which is not sent
       //ien_st_wsg_body_sent_to_browser,
       ien_st_body_sent_to_browser,
       
       //ien_st_copy_in_to_out,                    // normal processing; just copy incoming data to output
       //ien_st_4_first_byte,                     // Socks4: first byte of Socks4-communication must be 0x04
       //ien_st_4_second_byte,                    // Socks4: command code must be 0x01 for CONNECT
       ien_st_free
#endif
LBL_AGAIN:
	switch(in_current_state) {
	case ien_st_waiting_for_header_from_browser:
	{
		if(ads_session->dsc_transaction.ads_trans->boc_eof_server) {
			ads_session->dsc_transaction.ads_trans->boc_eof_server = !this->boc_keep_alive;
			ads_session->dsc_ws_gate.m_close_conn_to_ext_server();
			//return;
		}
		if(!ads_session->dsc_transaction.m_has_unprocessed_data())
			return;
		ads_session->dsc_http_hdr_out.m_clear(true); // true: clear all, because the transaction starts here from new
        ads_session->hstr_data_last_request.m_reset();

		// the output to a request or to a response is sent -> reset variables
        ads_session->dsc_webserver.bo_compress_makes_sense = true;
        ads_session->dsc_http_hdr_in.m_clear(false);
        ads_session->dsc_webserver.hstr_message_body.m_reset();

		if (ads_session->dsc_transaction.m_get_callmode() != DEF_IFUNC_TOSERVER
			&& ads_session->dsc_transaction.m_get_callmode() != DEF_IFUNC_REFLECT) { // wrong connection-direction -> go back
            ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE053E: called in unexpected direction" );
            ads_session->dsc_transaction.m_set_callrevdir(true);
            return;
        }
		int in_ret = m_read_http_header();
        if (in_ret != SUCCESS) {
            // prevent too many printouts  HIWSW812W -> HIWSI753I
            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info, "HIWSI753I: m_read_http_header failed with error %d\n", in_ret );
            return; // perhaps no input data -> go back to WSP
        }
		if(this->iec_header_state != ien_st_header_complete) {
			return;
		}
		ads_session->dsc_transaction.bo_resolve_from_chunked_format = ads_session->dsc_http_hdr_in.m_is_chunked();
		ads_session->dsc_transaction.in_len_data_to_deliver = ads_session->dsc_http_hdr_in.m_get_content_length();
		if(ads_session->dsc_transaction.in_len_data_to_deliver < 0)
			ads_session->dsc_transaction.in_len_data_to_deliver = 0;
		if (ads_session->dsc_transaction.bo_resolve_from_chunked_format) {
			ads_session->dsc_transaction.in_len_data_to_deliver = -1;
		}
		ads_session->dsc_transaction.bo_read_chunked_data_done = false;

		ads_session->hstr_hf_host_last_request = ads_session->dsc_http_hdr_in.hstr_hf_host.m_const_str();
		// Ticket[8758]  try to read hostname (port?) from http-header-field "host"; if not available -> hostname is read from configuration file (port must be added)
		if(ads_session->hstr_hf_host_last_request.m_get_len() <= 0) {
			ads_session->hstr_hf_host_last_request = ads_session->hstr_conf_authority.m_const_str();
		}
		ads_session->hstr_user_agent_last_req = ads_session->dsc_http_hdr_in.hstr_hf_user_agent;
		ads_session->in_http_method_last_request = ads_session->dsc_http_hdr_in.in_http_method;
		ads_session->hstr_prot_authority_ws = (ads_session->ads_config->in_settings & SETTING_DISABLE_HTTPS) != 0 ? dsd_const_string("http://") : dsd_const_string("https://");
		ads_session->hstr_prot_authority_ws += ads_session->hstr_hf_host_last_request;
		ads_session->hstr_url_session_id.m_reset();

		this->boc_keep_alive = false;
		m_set_ctrl_state(ien_st_collect_message_body_of_request);
		if ( (ads_session->dsc_http_hdr_in.in_http_version == ds_http_header::ien_http_version_11) )  /* check http version */
		{
			// On primary connection, send a temp move to the browser. 
			do {
				//  1. call DEF_AUX_GET_SESSION_INFO, if session type is primary, do 2. - 4. 
				//	2. parse url out of http reqest.
				//	3. Call DEF_AUX_GET_DOMAIN_INFO
				//	4. Send Temporarily moved to the browser according to the info received.
				//  5. Close the session ???
				memset(&ds_sessinfo, 0, sizeof( ds_sessinfo ));
				bol_ret = ads_session->dsc_transaction.ads_trans->amc_aux( ads_session->dsc_transaction.ads_trans->vpc_userfld, 
					DEF_AUX_GET_SESSION_INFO, &ds_sessinfo, sizeof(ds_sessinfo));
				if (bol_ret == FALSE)
					break;
				if (ds_sessinfo.iec_coty == ied_coty_primary) {
					// Get Domain information and check if we have to do a temp move
					memset( &dsl_gdi1, 0, sizeof(struct dsd_aux_get_domain_info_1) );  /* retrieve domain-information of connection - gate */
#ifdef USE_KB_HTTP_PARSER
				    dsl_gdi1.dsc_ucs_hostname.ac_str = dsl_hhs1.achc_hostname;  /* memory for hostname */
				    dsl_gdi1.dsc_ucs_hostname.imc_len_str = dsl_hhs1.imc_stored_hostname;  /* stored part of hostname */
#else
					// check for IPV6 notation like [<address>]:<port>
					iml_1 = -1;
					if (ads_session->dsc_http_hdr_in.hstr_hf_host[0] == '[') {
						iml_1 = ads_session->dsc_http_hdr_in.hstr_hf_host.m_find_first_of("]", false, iml_1 + 1);
						if (iml_1 >= 0) {  // found closing bracket, search for colon from next position
							dsl_gdi1.dsc_ucs_hostname.ac_str = const_cast<char*>(ads_session->dsc_http_hdr_in.hstr_hf_host.m_get_ptr() + 1);  /* memory for hostname */
							dsl_gdi1.dsc_ucs_hostname.imc_len_str = iml_1 - 1;
						}
					}
					if (iml_1 < 0) {
						// No IPV6, search colon to cut IPV4 address
                        iml_1 = ads_session->dsc_http_hdr_in.hstr_hf_host.m_find_first_of(":");
						dsl_gdi1.dsc_ucs_hostname.ac_str = const_cast<char*>(ads_session->dsc_http_hdr_in.hstr_hf_host.m_get_ptr());  /* memory for hostname */
						if (iml_1 < 0) {
							dsl_gdi1.dsc_ucs_hostname.imc_len_str = ads_session->dsc_http_hdr_in.hstr_hf_host.m_get_len();  /* stored part of hostname */
						} else {
							dsl_gdi1.dsc_ucs_hostname.imc_len_str = iml_1;  /* stored part of hostname */
						}
					}
#endif
					// dsl_gdi1.dsc_ucs_hostname.iec_chs_str = ied_chs_idna_1;  /* IDNA RFC 3492 etc; Punycode */
					dsl_gdi1.dsc_ucs_hostname.iec_chs_str = ied_chs_utf_8;  /* character set string */

					bol_ret = ads_session->dsc_transaction.ads_trans->amc_aux( ads_session->dsc_transaction.ads_trans->vpc_userfld,
						DEF_AUX_GET_DOMAIN_INFO, &dsl_gdi1, sizeof(dsl_gdi1));
					if (bol_ret == FALSE) {                   /* returned error          */
						ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
															 "HIWSE384E: get domain information returned error" );
						break;
					}
				    if (   (   (dsl_gdi1.iec_dir != ied_dir_found)  /* domain information found */
							&& (dsl_gdi1.iec_dir != ied_dir_default))  /* returned domain information default values */
#ifndef WSP_V24
						|| (dsl_gdi1.dsc_ucs_permmov_url.imc_len_str == 0)) {  /* permanently-moved-URL */
#endif
#ifdef WSP_V24
						|| (dsl_gdi1.dsc_ucs_moved_url.imc_len_str == 0)) {  /* moved-URL          */
#endif
						break;
					}

					ds_hstring hstr_location( ads_session->ads_wsp_helper );
#ifndef WSP_V24
					if (dsl_gdi1.boc_use_full_pm_url) {
						hstr_location.m_write(&dsl_gdi1.dsc_ucs_permmov_url);
#endif
#ifdef WSP_V24
					if (dsl_gdi1.boc_use_full_moved_url) {
						hstr_location.m_write(&dsl_gdi1.dsc_ucs_moved_url);
#endif
					} else {
						if ((ads_session->ads_config->in_settings & SETTING_DISABLE_HTTPS) != 0) {
							hstr_location.m_write( "http://" );
						} else {
							hstr_location.m_write( "https://" );
						}
#ifndef WSP_V24
						hstr_location.m_write(&dsl_gdi1.dsc_ucs_permmov_url);
#endif
#ifdef WSP_V24
						hstr_location.m_write(&dsl_gdi1.dsc_ucs_moved_url);
#endif
						hstr_location.m_write ( "/" );
					}

					dsd_const_string dsl_location(hstr_location.m_const_str());
                    ads_session->dsc_webserver.m_create_resp_header(ds_http_header::ien_status_found, 0, &dsl_location, NULL, NULL, false, NULL);
					ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);

					// JF 24.03.11: Read the complete message body, if there is any (e.g. when we received a POST).
					m_set_ctrl_state(ien_st_skip_message_body_of_request);
					goto LBL_AGAIN;
				}
			} while (FALSE);
        }
	    m_do_new_concept();
		goto LBL_AGAIN;
	}
	case ien_st_skip_message_body_of_request: {
		if (ads_session->dsc_http_hdr_in.m_is_message_body_announced()) {
			int in_ret = ads_session->dsc_webserver.m_read_message_body(); // This method marks data 'as processed', when all announced data are available.
			if (in_ret < 0) { // error
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
														"HIWSE383E: ds_webserver.m_read_message_body() returned error %d.",
														in_ret );
				ads_session->ads_wsp_helper->m_return_error(); 
				return;
			}
			if (in_ret == 0) {// not an error; we must wait for more data
				return; 
			}
		}
		m_set_ctrl_state(ien_st_body_sent_to_browser);
		goto LBL_AGAIN;
	}
	case ien_st_collect_message_body_of_request: {
		if (ads_session->dsc_transaction.m_get_callmode() != DEF_IFUNC_TOSERVER
			&& ads_session->dsc_transaction.m_get_callmode() != DEF_IFUNC_REFLECT) { // wrong connection-direction -> go back
            ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE053E: called in unexpected direction" );
            ads_session->dsc_transaction.m_set_callrevdir(true);
            return;
        }
		if (ads_session->dsc_http_hdr_in.m_is_message_body_announced()) {
			int in_ret = ads_session->dsc_webserver.m_read_message_body(); // This method marks data 'as processed', when all announced data are available.
			if (in_ret < 0) { // error
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
														"HIWSE383E: ds_webserver.m_read_message_body() returned error %d.",
														in_ret );
				ads_session->ads_wsp_helper->m_return_error(); 
				return;
			}
			if (in_ret == 0) {// not an error; we must wait for more data
				return; 
			}
		}
		m_set_ctrl_state(ien_st_process_message_body);
		goto LBL_AGAIN;
	}
	case ien_st_process_message_body: {
		if (ads_session->dsc_transaction.m_get_callmode() != DEF_IFUNC_TOSERVER
			&& ads_session->dsc_transaction.m_get_callmode() != DEF_IFUNC_REFLECT) { // wrong connection-direction -> go back
            ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE053E: called in unexpected direction" );
            ads_session->dsc_transaction.m_set_callrevdir(true);
            return;
        }
		m_do_new_concept();
		goto LBL_AGAIN;
	}
	case ien_st_sending_to_webserver: {
		// TODO: Can this condition be removed?
		if(ads_session->dsc_transaction.ads_trans->boc_eof_server) {
			return;
		}
		if (ads_session->dsc_transaction.m_get_callmode() == DEF_IFUNC_FROMSERVER) { // we received data from web server, while the browser is sending data to server -> do not process this data now; wait until the clients request is done
            // we send all available data unchanged to browser
            bo_ws_sent_during_client_sending = true;

            ads_session->ads_wsp_helper->m_log ( ied_sdh_log_error, "HIWSE764E: Data from webserver, while sending data to server." );
            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error, "HIWSE765E: %d bytes were passed unchanged to browser.",
                                                                    ads_session->dsc_transaction.m_pass_all_available_data() );

            return;
        }
		// we get here, when a browser sent a POST and (AT LEAST!) the header is completely sent to webserver
        // Attention: this takes place without authentication, because the concerned http-header (including Cookie) is already processed
        // if just the header was receive-> we do not get here, because in_current_state has another value 

        //---------------------------
        // pass data unchanged to server
        //---------------------------
		bool bol_can_send = !ads_session->dsc_transaction.ads_trans->boc_eof_server;
        if (ads_session->dsc_ws_gate.in_len_to_send_unchanged_to_server > 0) { // to avoid copying of data, we write the pointers into workarea
            int in_len_passed_data = ads_session->dsc_transaction.m_pass_data(ads_session->dsc_ws_gate.in_len_to_send_unchanged_to_server, bol_can_send, &ads_session->hstr_data_last_request);
            if (in_len_passed_data < 0) { // error occurred
                return ;
            }
            // in_len_passed_data were passed to server -> diminish the outstanding data
            ads_session->dsc_ws_gate.in_len_to_send_unchanged_to_server = ads_session->dsc_ws_gate.in_len_to_send_unchanged_to_server - in_len_passed_data;
            if (ads_session->dsc_ws_gate.in_len_to_send_unchanged_to_server < 0) {
                ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error, "HIWSE130E: %d  <--->  %d",
                                                     in_len_passed_data,
                                                     (ads_session->dsc_ws_gate.in_len_to_send_unchanged_to_server - in_len_passed_data) );
                return ;
            }
            if (ads_session->dsc_ws_gate.in_len_to_send_unchanged_to_server > 0) { // no or not all data available/were sent to server -> we must wait for more data
                ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info, "HIWSI383I: Not all announced data are available - outstanding %d.",
                                                     ads_session->dsc_ws_gate.in_len_to_send_unchanged_to_server );
                return ;
            }
            // in_len_to_send_unchanged_to_server is 0: all data are passed to client
            ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI444I: Data completly passed" );
        }
        ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_server);
		goto LBL_AGAIN;
	}
	case ien_st_body_sent_to_server: {
		if(ads_session->dsc_transaction.ads_trans->boc_eof_server) {
			ads_session->dsc_ws_gate.m_close_conn_to_ext_server();
			ads_session->dsc_webserver.m_create_resp_header( ds_http_header::ien_status_internal_error,
				0, NULL, NULL, NULL, false, NULL);
			ads_session->dsc_transaction.m_send_header( ied_sdh_dd_toclient );
			ads_session->dsc_transaction.ads_trans->boc_eof_server = !this->boc_keep_alive;
			m_set_ctrl_state(ien_st_body_sent_to_browser);
			return;
		}
		if(ads_session->dsc_transaction.ads_trans->adsc_gai1_out_to_server != NULL)
			return;
		// the output to a request or to a response is sent -> reset variables
        ads_session->dsc_webserver.bo_compress_makes_sense = false;
        ads_session->dsc_http_hdr_in.m_clear(false);
        ads_session->dsc_webserver.hstr_message_body.m_reset();

		m_set_ctrl_state(ien_st_waiting_for_header_from_webserver);
		this->iec_header_state = ien_st_collect_start_line;
		goto LBL_AGAIN;
	}
	case ien_st_waiting_for_header_from_webserver: {
		if(!ads_session->dsc_transaction.m_has_unprocessed_data())
			return;
		if (ads_session->dsc_transaction.m_get_callmode() != DEF_IFUNC_FROMSERVER) { // wrong connection-direction -> go back
            ds_hstring hstr_msg(ads_session->ads_wsp_helper, "HIWSI054I: called in unexpected direction");
            if (bo_ws_sent_during_client_sending) { // JF 27.01.09
                hstr_msg.m_write(" -> ignored.");
            }
			ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, hstr_msg.m_const_str() );
            if (!bo_ws_sent_during_client_sending) { // JF 27.01.09
                return;
            }
			// SM NEW
			return;
        }
		this->boc_keep_alive = false;
		int in_ret = m_read_http_header();
        if (in_ret != SUCCESS) {
            if (ads_session->dsc_transaction.ads_trans->boc_eof_server) {
                // WSP told us that a remote peer (usual the webserver) closed the connection
                // -> we must send all outstanding data to the other peer)
                ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning, "HIWSI773I webserver closed connection" );
            }
            else {
                // prevent too many printouts  HIWSW812W -> HIWSI753I
                ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info, "HIWSI753I: m_read_http_header failed with error %d\n", in_ret );
                return; // perhaps no input data -> go back to WSP
            }
        }
		if(this->iec_header_state != ien_st_header_complete) {
			return;
		}
		
		ads_session->dsc_transaction.bo_resolve_from_chunked_format = ads_session->dsc_http_hdr_in.m_is_chunked();
		ads_session->dsc_transaction.in_len_data_to_deliver = ads_session->dsc_http_hdr_in.m_get_content_length();
		if(ads_session->dsc_transaction.in_len_data_to_deliver < 0)
			ads_session->dsc_transaction.in_len_data_to_deliver = 0;
		if (ads_session->dsc_transaction.bo_resolve_from_chunked_format) {
			ads_session->dsc_transaction.in_len_data_to_deliver = -1;
		}
		ads_session->dsc_transaction.bo_read_chunked_data_done = false;

		if (!ads_session->dsc_http_hdr_in.m_is_webserver_response()) {
			ads_session->ads_wsp_helper->m_log ( ied_sdh_log_error, "HIWSE764E: Data from client, while receiving data from server." );
		}
		int inl_ret = m_handle_ext_ws_response();
		if(inl_ret < 0) {
			ads_session->ads_wsp_helper->m_return_error(); 
			return;
		}
		if(inl_ret == 0) {
			ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_collect_message_body_from_webserver);
			goto LBL_AGAIN;
		}
		goto LBL_AGAIN;
	}
	case ien_st_collect_message_body_from_webserver: {
		int inl_ret = m_handle_ext_ws_response();
		if(inl_ret < 0) {
			ads_session->ads_wsp_helper->m_return_error(); 
			return;
		}
		goto LBL_AGAIN;
   }
    case ien_st_wsg_sending_header_of_data_to_browser: {
        m_set_ctrl_state(ien_st_wsg_sending_body_to_browser);
		  goto LBL_AGAIN;
    }
    case ien_st_wsg_sending_body_to_browser: {
		 struct dsd_hl_clib_1* adsl_hl_clib = (struct dsd_hl_clib_1*)ads_session->ads_wsp_helper->m_get_structure();
		 if(adsl_hl_clib->boc_send_client_blocked) {
			 adsl_hl_clib->boc_notify_send_client_possible = TRUE;
			 return;
		 }
		 //adsl_hl_clib->boc_notify_send_client_possible = TRUE;
		 // http-header from webserver is delivered to browser; body is outstanding or in progress
		int in_ret = ads_session->dsc_ws_gate.m_handle_response_data(bo_data_until_close);
		if (in_ret == 0) { // wait for more data (0 means: more data outstanding; because we don't know the data-end!)
			ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI612I: not all response data available or data end is not known." );
			return;
		}
		ads_session->dsg_zlib_comp.m_reset();
		if (in_ret < 0) { // error
			ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error, "HIWSE512E: error in ds_ws_gate::m_handle_response_data: %d.", in_ret );
			ads_session->ads_wsp_helper->m_return_error(); 
			return;
		}
		ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI613I: response data are complete and processed." );
		ads_session->dsc_ws_gate.m_clear();
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
		goto LBL_AGAIN;
	}
	case ien_st_sending_to_browser: {
		if(ads_session->dsc_transaction.ads_trans->adsc_gai1_out_to_client != NULL)
			return;
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
		goto LBL_AGAIN;
	}
	case ien_st_sending_stream_to_browser: {
		struct dsd_hl_clib_1* adsl_hl_clib = (struct dsd_hl_clib_1*)ads_session->ads_wsp_helper->m_get_structure();
		if(ads_session->dsc_transaction.ads_trans->adsc_gai1_out_to_client != NULL) {
			adsl_hl_clib->boc_notify_send_client_possible = TRUE;
			return;
		}
		if(adsl_hl_clib->boc_send_client_blocked) {
			adsl_hl_clib->boc_notify_send_client_possible = TRUE;
			return;
		}
		if(!ads_session->dsc_webserver.m_stream_to_browser_continue()) {
			ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error, "HIWSE512E: error in ds_webserver::m_stream_to_browser_continue: failed");
			ads_session->ads_wsp_helper->m_return_error(); 
			return;
		}
		break;
	}
	case ien_st_body_sent_to_browser: {
		if(ads_session->dsc_transaction.ads_trans->boc_eof_server) {
			ads_session->dsc_transaction.ads_trans->boc_eof_server = !this->boc_keep_alive;
			ads_session->dsc_ws_gate.m_close_conn_to_ext_server();
		}
		if(ads_session->dsc_transaction.ads_trans->adsc_gai1_out_to_client != NULL)
			return;
		if(ads_session->dsc_ws_gate.boc_websocket_protocol) {
			ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_websocket);
			goto LBL_AGAIN;
		}
		if(!ads_session->dsc_ws_gate.boc_keep_alive) {
			ads_session->dsc_ws_gate.m_close_conn_to_ext_server();
		}
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_waiting_for_header_from_browser);
		this->iec_header_state = ien_st_collect_start_line;
		goto LBL_AGAIN;
	}
	case ien_st_websocket: {
		if(!ads_session->dsc_transaction.m_has_unprocessed_data())
			return;
		// TODO: Take gathers directly from input for output without copying! 
		ads_session->dsc_transaction.m_pass_all_available_data();
		break;
    }
	default:
		break;
	}
#if 0
    // change state-variable
    // here: sending-queue is empty
    if ( (in_current_state == ien_st_sending_to_browser) || (in_current_state == ien_st_sending_to_webserver)
        || (in_current_state == ien_st_body_sent_to_browser)
        || (in_current_state == ien_st_body_sent_to_server)) { // goto processing
        if ( (in_current_state == ien_st_sending_to_browser) || (in_current_state == ien_st_body_sent_to_browser)
             ) { // sending_to_browser is done -> we expect a ClientRequest
            m_set_ctrl_state(ien_st_waiting_for_header_from_browser);
            // reset zlib
            ads_session->dsg_zlib_comp.m_reset();
            ads_session->dsg_zlib_decomp.m_reset();
            ads_session->dsc_ws_gate.bo_do_sso = false;
            ads_session->dsc_ws_gate.bo_ignore_interpreter = false;
            ads_session->dsg_state.m_reset();
			this->iec_header_state = ien_st_collect_start_line;
        }
        else if (in_current_state == ien_st_body_sent_to_server) { // ien_st_sending_to_webserver is done -> we expect a ServerResponse
            m_set_ctrl_state(ien_st_waiting_for_header_from_webserver);
			this->iec_header_state = ien_st_collect_start_line;
        }

        if (in_current_state == ien_st_waiting_for_header_from_browser) {
            ads_session->dsc_http_hdr_out.m_clear(true); // true: clear all, because the transaction starts here from new
            ads_session->hstr_data_last_request.m_reset();
        }

        // the output to a request or to a response is sent -> reset variables
        ads_session->dsc_webserver.bo_compress_makes_sense = false;
        ads_session->dsc_http_hdr_in.m_clear(false);
        ads_session->dsc_webserver.hstr_message_body.m_reset();
        bo_interpreter_was_called = false;
    }

	if(in_current_state == ien_st_waiting_for_header_from_browser) {
		
	}

	if(in_current_state == ien_st_waiting_for_header_from_webserver) {
		if (ads_session->dsc_transaction.m_get_callmode() != DEF_IFUNC_FROMSERVER) { // wrong connection-direction -> go back
            ds_hstring hstr_msg(ads_session->ads_wsp_helper, "HIWSI054I: called in unexpected direction");
            if (bo_ws_sent_during_client_sending) { // JF 27.01.09
                hstr_msg.m_write(" -> ignored.");
            }
            ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, hstr_msg.m_get_ptr() );
            if (!bo_ws_sent_during_client_sending) { // JF 27.01.09
                return;
            }
			// SM NEW
			return;
        }
		int in_ret = m_read_http_header();
        if (in_ret != SUCCESS) {
            if (ads_session->dsc_transaction.ads_trans->boc_eof_server) {
                // WSP told us that a remote peer (usual the webserver) closed the connection
                // -> we must send all outstanding data to the other peer)
                ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning, "HIWSI773I webserver closed connection" );
            }
            else {
                // prevent too many printouts  HIWSW812W -> HIWSI753I
                ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info, "HIWSI753I: m_read_http_header failed with error %d\n", in_ret );
                return; // perhaps no input data -> go back to WSP
            }
        }
		if(this->iec_header_state != ien_st_header_complete) {
			return;
		}
	}

    if (in_current_state == ien_st_wsg_sending_header_of_data_to_browser) {
        m_set_ctrl_state(ien_st_wsg_sending_body_to_browser);
    }

#if 0
    // header is not complete -> read it
    if (in_current_state < ien_st_header_complete) {
        //----------------
        // read the http-header
        //----------------
#ifdef USE_KB_HTTP_PARSER
		do {
			memset( &dsl_chhs1, 0, sizeof(struct dsd_call_http_header_server_1) );  /* call HTTP processing at server */
			dsl_chhs1.adsc_gai1_in = ads_session->dsc_transaction.ads_trans->adsc_gather_i_1_in;  /* get input from client */
			dsl_chhs1.achc_url_path = chrl_http_url_path;  /* memory for URL path */
			dsl_chhs1.imc_length_url_path_buffer = sizeof(chrl_http_url_path);  /* length memory for URL path */
			dsl_chhs1.achc_hostname = chrl_hostname;  /* memory for hostname    */
			dsl_chhs1.imc_length_hostname_buffer = sizeof(chrl_hostname);  /* length memory for hostname */
			bol_ret = m_proc_http_header_server( &dss_phhs1_check_01,  /* HTTP processing at server */
		 									   &dsl_chhs1,  /* call HTTP processing at server */
	 										   &dsl_hhs1 );  /* HTTP processing at server */
			if (bol_ret == FALSE) {                   /* returned error          */
				ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning, "HIWSI773I plain-HTTP check HTTP header returned error" );
				break;                                /* nothing more to do      */
			}
			if (dsl_hhs1.imc_length_http_header == 0) {  /* length of HTTP header */
				return;                                /* wait for more data      */
			}
 			if (dsl_hhs1.imc_length_hostname > dsl_hhs1.imc_stored_hostname) {
				ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning, "HIWSI773I plain-HTTP HTTP Host: too long" );
				break;
			}
		} while(FALSE);
#endif
		int in_ret = m_read_http_header();
        if (in_ret != SUCCESS) {
            if (ads_session->dsc_transaction.ads_trans->boc_eof_server) {
                // WSP told us that a remote peer (usual the webserver) closed the connection
                // -> we must send all outstanding data to the other peer)
                ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning, "HIWSI773I webserver closed connection" );
            }
            else {
                // prevent too many printouts  HIWSW812W -> HIWSI753I
                ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info, "HIWSI753I: m_read_http_header failed with error %d\n", in_ret );
                return; // perhaps no input data -> go back to WSP
            }
        }
        if (in_current_state < ien_st_header_complete  // header is not yet complete -> we must wait for more data -> go back to WSP
            && !ads_session->dsc_transaction.ads_trans->boc_eof_server ) { // if boc_eof_server -> go on
            return;
        }
    }
#endif

    /*-----------------------------*/
    /* all header data are read in */
    /*-----------------------------*/

#ifdef DS_PORTLET_FILTER_U_A

    if(!ads_session->dsc_auth.m_is_portlet_filter_set())  // check if user agent was already checked
    {
        ads_session->dsc_auth.m_set_portlet_filter(            // set bitfield
            m_check_user_agent(                                // with result from check_user_agent method.
            ads_session->hstr_user_agent_last_req.m_get_ptr(), 
            ads_session->hstr_user_agent_last_req.m_get_len()
            )
        );
    }

#endif

 
#ifdef OLD_HTTP_MOVE
	// If the delivered http header 'Host' does not match the configured one, forward to the configured host name (works only with HTTP1.1).
    if ( (in_current_state == ds_control::ien_st_header_complete)
    ||   (in_current_state == ds_control::ien_st_collect_message_body_of_request) ){
        if (    (ads_session->dsc_http_hdr_in.in_http_version == ds_http_header::ien_http_version_11)  /* check http version */
             && (ads_session->dsc_http_hdr_in.hstr_hf_host.m_starts_with( ads_session->ads_config->ach_hostname, true ) == false)
             && (ads_session->dsc_transaction.m_get_callmode() != DEF_IFUNC_FROMSERVER) ) {

            // JF 24.03.11: Read the complete message body, if there is any (e.g. when we received a POST).
            if (ads_session->dsc_http_hdr_in.m_is_message_body_announced()) {
                if (ads_session->dsc_control.m_get_state() < ds_control::ien_st_collect_message_body_of_request) {
                    // set control state (to avoid superfluous parsing of data in ds_control)
                    ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_collect_message_body_of_request);
                }

                if (ads_session->dsc_control.m_get_state() == ds_control::ien_st_collect_message_body_of_request) {
                    int in_ret = ads_session->dsc_webserver.m_read_message_body(); // This method marks data 'as processed', when all announced data are available.
                    if (in_ret < 0) { // error
                        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                                             "HIWSE383E: ds_webserver.m_read_message_body() returned error %d.",
                                                             in_ret );
                        return;
                    }
                    if (in_ret == 0) {// not an error; we must wait for more data
                        return; 
                    }
                    // next state
                    ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_process_message_body);
                }
            }

            ds_hstring hstr_location( ads_session->ads_wsp_helper );
            if ((ads_session->ads_config->in_settings & SETTING_DISABLE_HTTPS) != 0) {
                hstr_location.m_write( "http://" );
            } else {
                hstr_location.m_write( "https://" );
            }
            hstr_location.m_write( ads_session->hstr_conf_authority.m_get_ptr(), 
                                   ads_session->hstr_conf_authority.m_get_len() );
            hstr_location.m_write ( "/", 1 );

            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
                                         "HIWSW080W: Host name (%s) does not match the configured one (%s). Forward to host '%s'.",
                                         ads_session->dsc_http_hdr_in.hstr_hf_host.m_get_ptr(),
                                         ads_session->ads_config->ach_hostname,
                                         hstr_location.m_get_ptr() );
            ads_session->dsc_webserver.m_create_resp_header(ds_http_header::ien_status_found, 0, &hstr_location, NULL, NULL, false, NULL);
            ads_session->dsc_transaction.m_send_header(ds_control::ien_st_body_sent_to_browser);
            return;
        }
    }
#endif

    // Ticket[16975]; Szenario with MS-Exchange: The webbrowser has started the uploading of a (large) file. During this upload the external webserver sends data ('Unauthorized...').
    // This disturbs our state machine.
    // Solution: 1) Pass the data from the server to client WITHOUT ANY CHANGES.
    //           2) Set the flag bo_ws_sent_during_client_sending. This will prevent checking for the correct data direction -> we will accept data from both sides ON THIS CONNECTION.
    if (in_current_state == ds_control::ien_st_sending_to_webserver) {
        if (ads_session->dsc_transaction.m_get_callmode() == DEF_IFUNC_FROMSERVER) { // we received data from web server, while the browser is sending data to server -> do not process this data now; wait until the clients request is done
            // we send all available data unchanged to browser
            bo_ws_sent_during_client_sending = true;

            ads_session->ads_wsp_helper->m_log ( ied_sdh_log_error, "HIWSE764E: Data from webserver, while sending data to server." );
            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error, "HIWSE765E: %d bytes were passed unchanged to browser.",
                                                                    ads_session->dsc_transaction.m_pass_all_available_data() );

            return;
        }
    }


    //-------------
    // handle response from an external webserver
    //-------------
    if (ads_session->dsc_http_hdr_in.m_is_webserver_response()) {
        if (ads_session->dsc_transaction.m_get_callmode() == DEF_IFUNC_TOSERVER) {
            ads_session->ads_wsp_helper->m_log ( ied_sdh_log_error, "HIWSE764E: Data from client, while receiving data from server." );
            return;
        }
#if 0
        if (ads_session->dsc_transaction.ads_trans->boc_eof_server) { // webserver closed connection -> if we are not sending data to client (e.g. all data are already processed) -> go back
            if (in_current_state != ien_st_wsg_sending_body_to_browser) {
                // TODO:
                //return;
                int a = 0;
            }
        }
#endif
        m_handle_ext_ws_response();

        // JF 20.12.10 Pipelining for WSG
        if (ads_session->bog_pipelining_detected) {
            if ( (in_current_state == ien_st_sending_to_browser) || (in_current_state == ien_st_body_sent_to_browser) ) {        
                ads_session->bog_pipelining_detected = false; // Reset this flag.
                ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI743I: Pipelining was detected -> force call-again.");
                ads_session->dsc_transaction.m_set_callagain(true);
                // WSG is running, we must reverse the direction, too.
                ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI744I: Pipelining was detected -> force call-reverse-direction.");
                ads_session->dsc_transaction.m_set_callrevdir(true);
            }
        }

        return;
    }

    // Ticket[16210]
    if (in_current_state == ds_control::ien_st_sending_to_webserver) {
        // we get here, when a browser sent a POST and (AT LEAST!) the header is completely sent to webserver
        // Attention: this takes place without authentication, because the concerned http-header (including Cookie) is already processed
        // if just the header was receive-> we do not get here, because in_current_state has another value 

        if (ads_session->dsc_ws_gate.in_len_to_send_unchanged_to_server == 0) { // this is the first sending 
            if (ads_session->dsc_http_hdr_in.m_get_content_length() >= 0) {
                ads_session->dsc_ws_gate.in_len_to_send_unchanged_to_server = ads_session->dsc_http_hdr_in.m_get_content_length();
            }
        }
        //---------------------------
        // pass data unchanged to server
        //---------------------------
		bool bol_can_send = !ads_session->dsc_transaction.ads_trans->boc_eof_server;
        if (ads_session->dsc_ws_gate.in_len_to_send_unchanged_to_server > 0) { // to avoid copying of data, we write the pointers into workarea
            int in_len_passed_data = ads_session->dsc_transaction.m_pass_data(ads_session->dsc_ws_gate.in_len_to_send_unchanged_to_server, bol_can_send, &ads_session->hstr_data_last_request);
            if (in_len_passed_data < 0) { // error occurred
                return ;
            }
            // in_len_passed_data were passed to server -> diminish the outstanding data
            ads_session->dsc_ws_gate.in_len_to_send_unchanged_to_server = ads_session->dsc_ws_gate.in_len_to_send_unchanged_to_server - in_len_passed_data;
            if (ads_session->dsc_ws_gate.in_len_to_send_unchanged_to_server < 0) {
                ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error, "HIWSE130E: %d  <--->  %d",
                                                     in_len_passed_data,
                                                     (ads_session->dsc_ws_gate.in_len_to_send_unchanged_to_server - in_len_passed_data) );
                return ;
            }
            if (ads_session->dsc_ws_gate.in_len_to_send_unchanged_to_server > 0) { // no or not all data available/were sent to server -> we must wait for more data
                ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info, "HIWSI383I: Not all announced data are available - outstanding %d.",
                                                     ads_session->dsc_ws_gate.in_len_to_send_unchanged_to_server );
                return ;
            }
            // in_len_to_send_unchanged_to_server is 0: all data are passed to client
            ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI444I: Data completly passed" );
            ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_server);
        }
        return ;
    }

    if(ads_session->dsc_transaction.ads_trans->boc_eof_server) {
        return;
    }

    // JF 10.12.10 Ticket[21184]: Support of pipelining.
    // When we detected a pipelining and the transaction is done (means the answer was sent/will be sent to browser (attention: this can be
    // the response of an external webserver!), we force WSP to call us again, so we can process the outstanding requests.
    // So we do not really support pipelining, but we are not disturbed by it. We process the pipelined requests one-by-one.    
    if (ads_session->bog_pipelining_detected) {
        if ( (in_current_state == ien_st_sending_to_browser) || (in_current_state == ien_st_body_sent_to_browser) ) {        
            ads_session->bog_pipelining_detected = false; // Reset this flag.
            ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning, "HIWSW741W: Pipelining was detected -> force call-again."); // JF 23.03.11 HIWSI741I -> HIWSW741W, so this message will be print to console, too.
            ads_session->dsc_transaction.m_set_callagain(true);
        }
    }

    return;
#endif
}

#if SM_USE_OLD_HOBNET
/*! \brief Check, whether it makes sense, to activate HOB_NET.
 *
 * @ingroup creator
 *
 * private
 * Check, whether it makes sense, to activate HOB_NET.
 */
bool ds_control::m_check_hob_net( int in_http_method )
{
    if (    (in_http_method == ds_http_header::ien_meth_HEAD)
         || (in_http_method == ds_http_header::ien_meth_GET)
         || (in_http_method == ds_http_header::ien_meth_POST) ) 
    {
        if ( ads_session->dsc_webserver.ds_path.hstr_path.m_ends_with_ic(FILE_HOBSCRIPT_JS) == false // "HOBScript.js" is always on WebServer !!
             && ads_session->dsc_webserver.ds_path.hstr_path.m_ends_with_ic(FILE_HOBHOME_JS) == false // MJ 15.07.08 "HOBHome.js" is always on WebServer!!
             && ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_equals(ICA_PORT_PAGE) == false
             && ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_equals(ICA_CLOSE_PAGE)  == false
             && ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_equals(ICA_ALIVE_PAGE) == false
             && ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_starts_with(VIRTUAL_DIRECTORY) == false )
        {
            if (    (ads_session->dsc_webserver.ds_path.in_state_path == PATH_AUTHENICATION_REQUIRED)
                 || (ads_session->dsc_webserver.ds_path.in_state_path == PATH_PUBLIC) )
            {

#if 0
                if (    in_http_method == ds_http_header::ien_meth_POST
                     && ads_session->dsc_webserver.ds_path.hstr_path.m_ends_with( "ck_post", true ) ) {
                    return false;
                }
#endif
                return true;
            }
        }
    }

    return false;
} // end of ds_control::m_check_hob_net
#endif


/*! \brief Handle a response from an external webserver
 *
 * @ingroup creator
 *
 * private
 * handle a response from an external webserver
 */
int ds_control::m_handle_ext_ws_response() {
    // a webserver's response can be:
    // 1) just a header; no message-body
    //        -> compose header for client
    // 2) header + body, which needs not be investigated (e.g. gif-file)
    //        -> compose header; pass body unchanged
    // 3) header + body, which must be investigated (html/css/script-file)
    //        a) css/script-file
    //            -> collect message-body into a linear buffer
    //            -> compose header
    //            -> process data
    //        b) html-file
    // Attention to 2+3: data can be chunked


    // true: data to browser will be sent as chunked
    bool bo_body_announced = ads_session->dsc_http_hdr_in.m_is_message_body_announced();
	int in_content_type = ads_session->dsc_http_hdr_in.m_get_content_type();
#if 0
    if (in_content_type == ds_http_header::ien_ct_not_set) { // webserver forgot to set a content-type -> perhaps hob_type was set
        // attention: this will implicitly set ds_http_header::in_content_type and fill ads_session->dsc_http_hdr_in.str_hf_content_type
        in_content_type = ads_session->dsc_http_hdr_in.m_get_int_for_content_type(
            ads_session->dsc_http_hdr_in.hstr_hf_content_type.m_const_str());
    }
#endif
    int in_cont_len = ads_session->dsc_http_hdr_in.m_get_content_length();

    bo_data_until_close = false;
    // the length of the message-body can be determined by closing the connection by webserver (RFC2616-4.4.5) 
    // in this case we assume
    // 1) that a header 'Content-Type' exists <-- this fails, when e.g. response is NOT Modified of a gif !!!
    // 2) or that 'Connection: close' (RFC2616-8.1.2.1) exists
    // RFC2616-4.3 states: a) All responses to the HEAD request method MUST NOT include a message-body, even though the
    //                          presence of entity-header fields might lead one to believe they do.
    //                       b) All 1xx (informational), 204 (no content), and 304 (Not Modified) responses MUST NOT include a message-body
    if ( (ads_session->in_http_method_last_request != ds_http_header::ien_meth_HEAD)
         && ((ads_session->dsc_http_hdr_in.in_http_status_code < 100) || (ads_session->dsc_http_hdr_in.in_http_status_code > 199))
         && (ads_session->dsc_http_hdr_in.in_http_status_code != 204)
         && (ads_session->dsc_http_hdr_in.in_http_status_code != 304)
        ) {
        if ( (!bo_body_announced) &&
             (in_cont_len < 0) && // bo_body_announced is false when Content-Length: 0 is in the header; therefore check in_cont_len
             ((ads_session->dsc_http_hdr_in.hstr_hf_connection.m_get_len() > 0) && 
              (ads_session->dsc_http_hdr_in.hstr_hf_connection.m_equals_ic(HFV_CLOSE))
             || (in_content_type > ds_http_header::ien_ct_not_set))
             ) {
            bo_data_until_close = true; // the length of the message-body is determined by closing the connection by webserver (RFC2616-4.4.5)
            ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI512I: bo_data_until_close activated" );
        }


        // JF 08.09.08 Ticket[15859]: in case of 1.0-response -> be prepared that data may follow without announcing!
        if ( (!bo_body_announced) && (!bo_data_until_close) ) {
            if (ads_session->dsc_http_hdr_in.in_http_version_webserver == ds_http_header::ien_http_version_10) {
                bo_data_until_close = true;
            }
        }
    }


    bool bo_unauthorized = (ads_session->dsc_http_hdr_in.in_http_status_code == ds_http_header::ien_status_unauthorized);


    if (ads_session->in_state_auth_basic == ds_session::ien_st_auth_basic_sent_authorization) {
        // We tried SSO for 'Basic Authentication'. If we receive '401', then SSO failed. Otherwise SSO was successful.
        if (bo_unauthorized) {
            // We tried SSO, but it failed. Set state for this.
            ads_session->in_state_auth_basic = ds_session::ien_st_auth_basic_failed;
            ads_session->hstr_authorization_basic.m_reset();
            ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSI653I: SSO with 'Basic Authentication' failed.");
        }
        else {
            // SSO with 'Basic Authentication' succeeded.
            // ads_session->hstr_authorization_basic holds the value for the header field HF_AUTHORIZATION. The according header line shall be 
            // inserted into all headers, which are sent to the external webserver on this ds_session.
            ads_session->in_state_auth_basic = ds_session::ien_st_auth_basic_succeeded;
            ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSI652I: SSO with 'Basic Authentication' succeeded.");
        }
    }

    ads_session->ads_wsp_helper->m_logf(ied_sdh_log_info, "HIWSI982I: Negotiation state: %d", ads_session->in_state_auth_negotiate);


    // Annotation: RFC 4559-4.1:
    // A status code 200 status response can also carry a "WWW-Authenticate" response header containing the final leg of
    // an authentication. In this case, the gssapi-data will be present. Before using the contents of the response, the
    // gssapi-data should be processed by gss_init_security_context to determine the state of the security context. If
    // this function indicates success, the response can be used by the application. Otherwise, an appropriate action, based on
    // the authentication status, should be taken.
    // For example, the authentication could have failed on the final leg if mutual authentication was requested and the server
    // was not able to prove its identity. In this case, the returned results are suspect.


    bool bo_send_www_auth_to_client = true;
    bo_read_complete = false;
    if ( (ads_session->in_state_auth_negotiate == ds_session::ien_st_auth_nego_sent_avail_mechs)
    ||   (ads_session->in_state_auth_negotiate == ds_session::ien_st_auth_nego_sent_mech_tok) ) {
        // We tried SSO for 'Authentication: Negotiate'.

        // In the first reply from the target some fields must be set, which can miss in later replies!
        // Attention: The 'first reply' does not mean the first 401 by the server. It means the first 'Negotiate' with a value!
        bool bol_nego_first_reply = ads_session->bog_nego_first_reply;
        ads_session->bog_nego_first_reply = false;

        // Parse the negTokenResp.
        // First reply of the web server must be treated in special way, therefore we have to concern ads_session->bog_nego_first_reply.
        ds_spnego_reader dsl_spnego_reader(ads_session);
        int inl_ret = m_read_nego_token_from_ws(&dsl_spnego_reader);
        if (inl_ret != SUCCESS) { // Error during parsing.
            ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE687E: SPNEGO: m_read_nego_token_from_ws failed with error %d.", inl_ret);
            return m_cancel_negotiate(1);
        }

        //---------------------------------
        // React to the server's response.
        //---------------------------------
        SPNEGO_NEGRESULT dsl_neg_state = dsl_spnego_reader.m_get_neg_state();
        SPNEGO_MECH_OID  dsl_supp_mech = dsl_spnego_reader.m_get_supported_mech();

        // The value must be valid in the first reply!
        // Attention: 'request-mic' is NOT SUPPORTED and will result in a ien_spnego_negresult_not_used!
        if ( (bol_nego_first_reply) && (dsl_neg_state == ien_spnego_negresult_not_used) ) { // It is invalid -> error;
            ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE251E: SPNEGO: Target's first response does not contain a valid 'negState'.");
            return m_cancel_negotiate(2);
        }

        // RFC4178-3.2c-I: REJECT
        if (dsl_neg_state == ien_spnego_negresult_rejected) {
            ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE851E: SPNEGO: Target server rejects.");
            return m_cancel_negotiate(3);
        }

        // RFC4178-3.2c-II: negState is 'request-mic'
        // negState 'request-mic' is NOT SUPPORTED. dsl_neg_state is ien_spnego_negresult_not_used in this case. This was processed some lines up.


        // RFC4178-3.2c-III: INCOMPLETE
        if (dsl_neg_state == ien_spnego_negresult_incomplete) {
            if (ads_session->in_state_auth_negotiate == ds_session::ien_st_auth_nego_sent_avail_mechs) {
                // We sent our available mechanisms without the optimistic token. Server's response MUST contain the selected mechanism.
                // We will send the ServiceTicket with this mechanism.
                if ( (dsl_supp_mech != ien_spnego_mech_oid_kerberos_v5_legacy)
                &&   (dsl_supp_mech != ien_spnego_mech_oid_kerberos_v5) ) {
                    // Selected mech type is not valid.
                    ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE892E: SPNEGO: Selected mech type is not valid: %d", dsl_supp_mech);
                    return m_cancel_negotiate(4);
                }
                ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSI792I: SPNEGO: Selected mech type: %s",
                    (dsl_supp_mech==ien_spnego_mech_oid_kerberos_v5?"Kerberos v5":"Microsoft Kerberos"));
                nego_mechtype = (dsl_supp_mech==ien_spnego_mech_oid_kerberos_v5?ien_nego_mech_kerb5:ien_nego_mech_kerb_ms);

                // Create our negTokenResp.
                // The SPNEGO data must be sent as base64.
                ds_hstring hstr_negotiate_b64(ads_session->ads_wsp_helper);
                inl_ret = m_create_nego_token(false, &hstr_negotiate_b64, nego_mechtype, false);
                if (inl_ret != SUCCESS)  {
                    ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE333E: Creation of SPNEGO/Kerberos token failed with error %d.", inl_ret);
                    return m_cancel_negotiate(5);
                }

					 inl_ret = m_read_complete_ws();
                if (inl_ret <= 0) {
                   // Error or more data must be read.
                   return inl_ret;
                }

                ds_hstring hstr_authorization(ads_session->ads_wsp_helper);
                hstr_authorization.m_write(HF_AUTHORIZATION ": " HFV_WWWAUTH_NEGOTIATE " ");
                hstr_authorization.m_write(hstr_negotiate_b64);
                hstr_authorization.m_write(CRLF);
#if OLD
                ds_hstring hstr_send_to_ws(ads_session->ads_wsp_helper);
                hstr_send_to_ws.m_write(ads_session->hstr_data_to_ext_ws_before_negotiate.m_get_ptr(), false);
                hstr_send_to_ws.m_insert(hstr_send_to_ws.m_get_len()-2, hstr_authorization.m_get_ptr(), hstr_authorization.m_get_len()); // -2: insert before terminating CRLF.
#else
                dsd_const_string dsl_orig_data(ads_session->hstr_data_to_ext_ws_before_negotiate.m_const_str());
                ds_hstring hstr_send_to_ws(ads_session->ads_wsp_helper, dsl_orig_data.m_substring(0, dsl_orig_data.m_get_len()-2));
                // -2: insert before terminating CRLF.
                hstr_send_to_ws.m_write(hstr_authorization);
                hstr_send_to_ws.m_write(dsl_orig_data.m_substring(dsl_orig_data.m_get_len()-2));
#endif
                bool bo_ret = ads_session->ads_wsp_helper->m_send_data(hstr_send_to_ws.m_get_ptr(),
                                                                       hstr_send_to_ws.m_get_len(),
                                                                       ied_sdh_dd_toserver);
                if (bo_ret == false) {
                    ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE750E: Sending to external webserver failed.");
                    // WHAT TO DO ??
						  return -1;
                }
                ads_session->dsc_transaction.m_mark_as_processed(NULL);
                m_set_ctrl_state(ien_st_body_sent_to_server);
                ads_session->in_state_auth_negotiate = ds_session::ien_st_auth_nego_sent_mech_tok;
                return 1;
            }
            
            // The server needs more information from us.
            // I don't know what to do, so we terminate here.
            ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE891E: SPNEGO: Target server requests more information. This is not supported.");
            return m_cancel_negotiate(6);
        }
        
        if (dsl_neg_state == ien_spnego_negresult_success) {
            ads_session->in_state_auth_negotiate = ds_session::ien_st_auth_nego_succeeded;
            bo_send_www_auth_to_client = false; // Do not send this header to client any more ON THIS CONNECTION.

            // If the server's response contains a valid selected mechanism (e.g. we sent a mechanism together with the optimistic token),
            // we must adopt this selected mechanism.
            if ( (dsl_supp_mech == ien_spnego_mech_oid_kerberos_v5_legacy)
            ||   (dsl_supp_mech == ien_spnego_mech_oid_kerberos_v5) ) {
                ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSI648I: SPNEGO: Selected mech type: %s",
                (dsl_supp_mech==ien_spnego_mech_oid_kerberos_v5?"Kerberos v5":"Microsoft Kerberos"));
                nego_mechtype = (dsl_supp_mech==ien_spnego_mech_oid_kerberos_v5?ien_nego_mech_kerb5:ien_nego_mech_kerb_ms);
            }
        }


        // If we required MUTUAL authentication -> check the response token.
        if ((ads_session->ads_config->in_settings & SETTING_KERB5_NO_MUTUAL) == 0) {
            ads_session->ads_wsp_helper->m_log(ied_sdh_log_info, "HIWSI391I: SPNEGO: Mutual authentication started.");
            dsd_const_string hstr_resp_token(dsl_spnego_reader.m_get_reponse_token());
            if (hstr_resp_token.m_get_len() < 1) {
                ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE391E: SPNEGO: Mutual authentication failed. The response tokebn is empty.");
                return m_cancel_negotiate(7);
            }

            inl_ret = m_check_kerb_mutual_auth(hstr_resp_token);
            if (inl_ret != SUCCESS) {
                ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE391E: SPNEGO: Mutual authentication failed with error %d.", inl_ret);
                return m_cancel_negotiate(8);
            }
        }


    } // state ien_st_auth_nego_sent_mech_tok


    //--------------------------------------------------------------------------------------------------------------------------//
    // ATTENTION:                                                                                                               //
    // RFC 4559-4.2 says: "Any returned code other than a success 2xx code represents an authentication error. If a 401         //
    // containing a 'WWW-Authenticate' header with 'Negotiate' and gssapi-data is returned from the server, it is a             //
    // continuation of the authentication request."                                                                             //
    // The RFC says nothing about response codes like Moved Permanently(301) / Found(302) / Not Modified(304) / Not Found(404). //
    // We treat these (e.g. redirections) as OK. The authenticatíon was successful, but the web server wants to forward us.     //
    //--------------------------------------------------------------------------------------------------------------------------//


    if (bo_unauthorized) {
        // RFC 2616: If 401 Unauthorized is returned, the response of the external webserver MUST include a WWW-Authenticate header field!
        // For some kinds of authentication (e.g. 'Basic', 'Negotiate') we try to perform a SingleSignOn to the external webserver.
        // Attention: The elements of the vector were sorted by ds_http_header.m_parse_header_line() in a priority order:
        //    1) Negotiate
        //    2) Digest, NTLM, etc (for these we do not try SSO up to now)
        //    3) Basic
        // If all SSO trials failed, we send the webserver's last response to the client.
        for (HVECTOR_FOREACH(ds_hstring, adsl_cur, ads_session->dsc_http_hdr_in.ds_v_hf_www_authenticate)) {
            const ds_hstring& hstr_value = HVECTOR_GET(adsl_cur);

            //-------------------------------------------------------------//
            // External webserver requests Authentication with 'Negotiate' //
            //-------------------------------------------------------------//
            if (hstr_value.m_starts_with_ic(HFV_WWWAUTH_NEGOTIATE)) {

                int inl_authmethod = ads_session->dsc_auth.m_get_authmethod();
                if ( (inl_authmethod != DEF_CLIB1_CONF_KRB5) && (inl_authmethod != DEF_CLIB1_CONF_DYN_KRB5) ) {
                    // The user was not authenticated against Kerberos at the login, so it makes no sense to try Kerberos.
                    // We ignore 'Negotiate' and check, whether another mechanism is suggested by web server.
                    ads_session->in_state_auth_negotiate = ds_session::ien_st_auth_nego_not_active; // Flag, that we will not try SSO with Negotiate on this session any more.
                    ads_session->ads_wsp_helper->m_log(ied_sdh_log_info, "HIWSI467I: There was no Kerberos authentication. Authentication 'Negotiate' is skipped. Will try another authentication.");
                    continue;
                }

                if ( ((ads_session->ads_config->in_settings & SETTING_DISABLE_SSO_AUTH_NEGOTIATE) == 0)
                &&   (ads_session->in_state_auth_negotiate == ds_session::ien_st_auth_nego_not_active) ) {  // We did not try a SSO for this web server on this ds_session.
                    // RFC4178-3.1: "Note that in order to avoid an extra round trip, the first context establishment token of the initiator's preferred
                    // mechanism SHOULD be embedded in the initial negotiation message".
                    // If you want to negotiate the mechanism type, the according setting must be made in configuration file, to avoid inclusion of the optimistic token in first request to server.
                    bool bo_send_optimistic_token = ((ads_session->ads_config->in_settings & SETTING_AUTH_NEGO_NO_OPTIMI_TOKEN) == 0);
                    
                    // The SPNEGO data must be sent as base64.
                    ds_hstring hstr_negotiate_b64(ads_session->ads_wsp_helper);
                    int inl_ret = m_create_nego_token(true, &hstr_negotiate_b64, (NEGO_MECHTYPES)(ien_nego_mech_kerb5 | ien_nego_mech_kerb_ms), bo_send_optimistic_token);
                    if (inl_ret != SUCCESS)  {
                        ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE256E: Creation of SPNEGO/Kerberos token failed with error %d.", inl_ret);
                        // If something goes wrong, we ignore 'Negotiate' and check, whether another mechanism is suggested by web server.
                        ads_session->in_state_auth_negotiate = ds_session::ien_st_auth_nego_not_active; // Flag, that we will not try SSO with Negotiate on this session any more.
                        ads_session->ads_wsp_helper->m_logf(ied_sdh_log_warning, "HIWSW667W: m_auth_negotiate() failed with error %d. Try another authentication.", inl_ret);
                        continue;
                    }
                    
                    // Attention: Perhaps not all data are received (e.g. a very long html page is delivered). Ensure, that all data from external WS are read.
						  inl_ret = m_read_complete_ws();
                    if (inl_ret <= 0) {
                        // Error or more data must be read.
                        return inl_ret;
                    }

                    // Print to log after we received the whole data. Otherwise this will be logged several times until we received all of a very long page.s
                    ads_session->ads_wsp_helper->m_log(ied_sdh_log_info, "HIWSI633I: Start SSO for authentication 'Negotiate'.");

                    // Create the whole http-header (and the body, if exists), which shall be sent to external web server. This header
                    // is the header, which was just sent to web server, plus the created header line 'Authorization: Negotiate <base64 SPNEGO>'.
                    ds_hstring hstr_send_to_ws(ads_session->ads_wsp_helper);
                    m_auth_negotiate(&hstr_send_to_ws, &hstr_negotiate_b64);
                    // Send the authentication to external web server.
                    ads_session->ads_wsp_helper->m_log ( ied_sdh_log_info, "HIWSI651I: Data shall be sent to external webserver." );

                    bool bo_ret = ads_session->ads_wsp_helper->m_send_data(hstr_send_to_ws.m_get_ptr(),
                                                                           hstr_send_to_ws.m_get_len(),
                                                                           ied_sdh_dd_toserver);
                    if (bo_ret == false) {
                        ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE751E: Sending to external webserver failed.");
                        // WHAT TO DO ??
								return -1;
                    }

							m_set_ctrl_state(ien_st_sending_to_webserver);
							dsd_const_string dsl_payload = ads_session->hstr_data_last_request.m_const_str();
							bo_ret = ads_session->ads_wsp_helper->m_send_data(dsl_payload.m_get_ptr(),
																								dsl_payload.m_get_len(),
																								ied_sdh_dd_toserver);
							if (!bo_ret) {
								ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE754E: Sending to external webserver failed.");
								// WHAT TO DO ??
								return -1;
							}
                    m_set_ctrl_state(ien_st_body_sent_to_server);
                    if (bo_send_optimistic_token) {
                        ads_session->in_state_auth_negotiate = ds_session::ien_st_auth_nego_sent_mech_tok;
                    }
                    else {
                        ads_session->in_state_auth_negotiate = ds_session::ien_st_auth_nego_sent_avail_mechs;
                    }
                    return 1;
                }

                ads_session->ads_wsp_helper->m_log(ied_sdh_log_info, "HIWSI567I: Authentication 'Negotiate' is skipped. Will try another authentication.");
                continue;
            }

            //----------------------------------------------------//
            // External webserver requests a Digest Authentication //
            //----------------------------------------------------//
            if (hstr_value.m_starts_with_ic(HFV_WWWAUTH_DIGEST)) {
                ads_session->ads_wsp_helper->m_log(ied_sdh_log_info, "HIWSI566I: Authentication 'Digest' is not supported for SSO. Will try another authentication.");
                continue;
            }

            //----------------------------------------------------//
            // External webserver requests a NTLM Authentication //
            //----------------------------------------------------//
            if (hstr_value.m_starts_with_ic(HFV_WWWAUTH_NTLM)) {
                ads_session->ads_wsp_helper->m_log(ied_sdh_log_info, "HIWSI465I: Authentication 'NTLM' is not supported for SSO. Will try another authentication.");
                continue;
            }
            
            //----------------------------------------------------//
            // External webserver requests a Basic Authentication //
            //----------------------------------------------------//
            if (hstr_value.m_starts_with_ic(HFV_WWWAUTH_BASIC)) {
                // External webserver requests a basic authentication (RFC 2617) by sending a response like:
                //     HTTP/1.1 401 Unauthorized
                //     WWW-Authenticate: Basic realm="hob.de"
                // The realm parameter will be ignored!

                if ( ((ads_session->ads_config->in_settings & SETTING_DISABLE_SSO_AUTH_BASIC) == 0)
                &&   (ads_session->in_state_auth_basic == ds_session::ien_st_auth_basic_not_active) ) {
                    // We did not try a SSO for this web server on this ds_session.
                    
                    // Attention: Perhaps not all data are received (e.g. a very long html page is delivered). Ensure, that all data from external WS are read.
						  int inl_ret = m_read_complete_ws();
                    if (inl_ret <= 0) {
                        // Error or more data must be read.
                        return inl_ret;
                    }

                    // Print to log after we received the whole data. Otherwise this will be logged several times until we received all of a very long page.
                    ads_session->ads_wsp_helper->m_log(ied_sdh_log_info, "HIWSI635I: Start SSO for basic authentication.");


                    // Create the whole http-header (no body), which shall be sent to external web server. This header is the header, which was
                    // just sent to web server, plus the created header line 'Authorization: <base64 of username:password>'.
                    // The global ds_hstring ads_session->hstr_authorization_basic is setup. It holds the value, which will be included
                    // in former requests to the web server as 'Authorization' (when SSO will succeed).
                    ds_hstring hstr_send_to_ws(ads_session->ads_wsp_helper);
                    m_auth_basic(&hstr_send_to_ws);
                     // Send the authentication to external web server.
                     ads_session->ads_wsp_helper->m_log ( ied_sdh_log_info, "HIWSI654I: Data shall be sent to external webserver." );

                     bool bo_ret = ads_session->ads_wsp_helper->m_send_data(hstr_send_to_ws.m_get_ptr(),
                                                                            hstr_send_to_ws.m_get_len(),
                                                                            ied_sdh_dd_toserver);
                     if (!bo_ret) {
								ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE754E: Sending to external webserver failed.");
								return -1;
							}
							m_set_ctrl_state(ien_st_sending_to_webserver);
							dsd_const_string dsl_payload = ads_session->hstr_data_last_request.m_const_str();
							bo_ret = ads_session->ads_wsp_helper->m_send_data(dsl_payload.m_get_ptr(),
                                                                       dsl_payload.m_get_len(),
                                                                       ied_sdh_dd_toserver);
                     if (!bo_ret) {
								ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE754E: Sending to external webserver failed.");
								// WHAT TO DO ??
								return -1;
							}
#if 0
							ads_session->dsc_transaction.m_mark_as_processed(NULL);
#endif
                     m_set_ctrl_state(ien_st_body_sent_to_server);
                     ads_session->in_state_auth_basic = ds_session::ien_st_auth_basic_sent_authorization;
                     return 1;
                }
                ads_session->ads_wsp_helper->m_log(ied_sdh_log_info, "HIWSI367I: Authentication 'Basic' is skipped. Will try another authentication.");
                // We already tried SSO. It failed. We pass the Unauthorized to the browser, so the user can insert his credentials there.
                continue;
            }
        }
    }

    ads_session->ads_wsp_helper->m_logf(ied_sdh_log_info, "HIWSI552I: WWW-Authenticate will be sent to client, if exists: %d", bo_send_www_auth_to_client);

    ads_session->dsg_zlib_decomp.m_reset();
    ads_session->dsg_zlib_comp.m_reset();
        
#if 0
    bool bo_send_chunked_to_browser = ads_session->dsc_http_hdr_in.m_is_chunked();
	if (ads_session->dsc_ws_gate.adsc_interpreter == NULL) {
    //if ((in_content_type > ds_http_header::ien_ct_not_set) && (in_content_type < ds_http_header::ien_ct_text_html) ) { // data can be passed unchanged
        bo_send_chunked_to_browser = false;
    }
    // de.wikipedia.org sends a 'Location moved' with Content-Length=0 over HTTP/1.0
    // in this scenario, we didn't send Content-Length=0 to the browser, which then waited and waited...
    bool bol_message_body = bo_body_announced;
    if (ads_session->dsc_http_hdr_in.m_get_content_length() != 0 && bo_data_until_close) {
        bol_message_body = true;
    }
#endif
    ads_session->dsc_ws_gate.m_handle_response_header(
        in_content_type, bo_send_www_auth_to_client);
	 return 1;
}

/*! \brief Register to CMA
 *
 * @ingroup creator
 *
 * private
 */
bool ds_control::m_register_to_cma()
{
    bool bo_register = ads_session->dsc_auth.m_register( ads_session->dsc_http_hdr_in.bo_cookie_header_exists );
    if ( bo_register == false ) {
        return false;
    }

    // MJ: check if user was kicked out:
    if ( ads_session->dsc_kicked_out.tm_login > 0 ) {
        ads_session->dsc_auth.m_set_state( ST_KICKED_OUT );
        ads_session->dsc_auth.m_save_kicked_out( &ads_session->dsc_kicked_out );
    }    

    // Ticket[11985]: print to console/log that the nonce was created (this nonce is a NA=NotAuthenticated)
    ds_hstring ds_cookie( ads_session->ads_wsp_helper );
    ads_session->dsc_auth.m_get_http_cookie( &ds_cookie );
    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info, "HIWSE045I: CMA with nonce was created: %.*s",
                                         ds_cookie.m_get_len(), ds_cookie.m_get_ptr() );

    // MJ 24.09.2009, set language:
    ads_session->dsc_auth.m_set_lang( ads_session->dsc_http_hdr_in.in_language );
    in_cma_lang = ads_session->dsc_http_hdr_in.in_language;
    return true;
}

/*! \brief Authenticate
 *
 * @ingroup creator
 *
 * private
 */
bool ds_control::m_authenticate(const dsd_const_string& ahstr_hob_cookie, bool bo_cookie_in_url)
{
    bool bol_ret_validate = false;

    if (bo_cookie_in_url) {
        //----------------------------
        // cookie from URL
        //----------------------------
        // http-header has higher priority than url cookie
		bol_ret_validate = ads_session->dsc_auth.m_check_http_cookie( ahstr_hob_cookie.m_get_ptr(), ahstr_hob_cookie.m_get_len(), &ads_session->dsc_kicked_out );
        // Ticket[11985]: print to console/log: incoming connection with nonce in URL
        if (!ads_session->bo_nonce_url_already_printed) {
            ds_hstring hstr_nonce_incoming(ads_session->ads_wsp_helper, "HIWSI049I: connection with nonce in URL: ");
            hstr_nonce_incoming.m_write(ahstr_hob_cookie);
            if ( bol_ret_validate == false ) {
                hstr_nonce_incoming.m_write(" (state is NOT ACCEPTED; perhaps nonce is invalid)");
            }
            else { // set the flag only in case it was a valid cookie-string
                ads_session->bo_nonce_url_already_printed = true;
            }
            ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, hstr_nonce_incoming.m_const_str() );
        }

        return bol_ret_validate;
    }

    //----------------------------
    // cookie from http-header (str_cookie_line is the complete header-line)
    //----------------------------
    if (ahstr_hob_cookie.m_get_len() <= 0) {    // empty !!
        return false;
    }
    //-------------------------
    // we must cut out HOB's cookie (and in case of WSG replace its value with XXX)
    //-------------------------
    bol_ret_validate = ads_session->dsc_auth.m_check_http_cookie(
		ahstr_hob_cookie.m_get_ptr(), ahstr_hob_cookie.m_get_len(), &ads_session->dsc_kicked_out);

#if !SM_USE_NEW_WSG
    // Ticket [14905]:
    if ((ads_session->ads_config->in_settings & SETTING_DISABLE_COOKIE_STORAGE) == 0) {
        // get cookies:
        if ( bol_ret_validate == true ) { // authentication succeeded with this cookie
            // TODO: check hstr_before && hstr_behind for new cookies from client!!!
            if ( hstr_behind.m_get_len() > 0 || hstr_before.m_get_len() > 0 ) {
                ds_hstring hstr_script_cookie(ads_session->ads_wsp_helper, "");
                hstr_script_cookie += hstr_before;
                hstr_script_cookie += hstr_behind;
                
                dsd_const_string dsl_domain(ads_session->dsc_http_hdr_in.dsc_url.hstr_authority_of_webserver);
                dsd_const_string dsl_path(ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_const_str());
#if 0 
                const char* ach_domain;
                int         in_len_domain;
                const char* ach_path;
                int         in_len_path;
                ach_domain    = ads_session->dsc_http_hdr_in.dsc_url.hstr_authority_of_webserver.m_get_ptr();
                in_len_domain = ads_session->dsc_http_hdr_in.dsc_url.hstr_authority_of_webserver.m_get_len();
                ach_path      = ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_ptr();
                in_len_path   = ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_len();
#endif

#if 0
                if(ads_session->dsc_http_hdr_in.m_get_http_method() == ds_http_header::ien_meth_POST 
                    && ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_ends_with("ck_post", true))
                {
                    ach_domain = ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_ptr();
                    in_len_domain = 
                }
#endif
                ads_session->dsc_ws_gate.dsc_ck_manager.m_set_script_cookie( hstr_script_cookie.m_const_str(),
                                                                             dsl_domain,
                                                                             dsl_path,
                                                                             ads_session->dsc_auth.m_get_basename() );
            }
        }
    }
#endif

    if (!ads_session->bo_nonce_already_printed) {
        // Ticket[11985]: print to console/log: incoming connection with nonce in http-header
        ds_hstring hstr_nonce_incoming(ads_session->ads_wsp_helper, "HIWSI048I: connection with nonce in http-header: ");        
        ds_hstring ds_sticket = ads_session->dsc_auth.m_get_sticket();
        if ( ds_sticket.m_get_len() > 0 ) {
            hstr_nonce_incoming.m_write( ds_sticket );
        }
        if ( bol_ret_validate == false ) {
            hstr_nonce_incoming.m_write( " (state is NOT ACCEPTED; perhaps nonce is invalid)");
        }
        else { // set the flag only in case it was a valid cookie-string
            ads_session->bo_nonce_already_printed = true;
        }
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, hstr_nonce_incoming.m_const_str() );
    }
    
    return bol_ret_validate;
}

bool ds_control::m_authenticate_by_ident()
{
    return this->ads_session->dsc_auth.m_check_ident();
}


/*! \brief Initialize with session
 *
 * @ingroup creator
 */
void ds_control::m_init(ds_session* ads_session_in)
{
    ads_session = ads_session_in;
}

/*! \brief Set the state
 *
 * @ingroup creator
 *
 * set the state (e.g. when we want to read message-body-data)
 */
int ds_control::m_set_ctrl_state(states in_state)
{
    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info, "HIWSI711I: SET in_current_state from  %d  to  %d.",
                                         in_current_state, in_state );
	 switch(in_state) {
	 case ien_st_body_sent_to_browser:
		 this->ads_session->dsc_transaction.m_send_chunked_end(ied_sdh_dd_toclient);
		 break;
	 default:
		 break;
	 }

    in_current_state = in_state;

    return in_current_state;
}

/*! \brief Get current state
 *
 * @ingroup creator
 *
 * get the current state
 */
int ds_control::m_get_state()
{
    return in_current_state;
}


/*! \brief Gets the working direction
 *
 * @ingroup creator
 *
 * public function ds_control::m_to_ext_server
 * is working direction to external webserver?
 *
 * @return  bool
 */
bool ds_control::m_to_ext_server()
{
    if (    in_current_state == ien_st_sending_to_webserver
         || in_current_state == ien_st_body_sent_to_server ) {
        return true;
    }
    return false;
} // end of ds_control::m_to_ext_server


/*! \brief Read the HTTP Header
 *
 * @ingroup creator
 *
 * Read the HTTP header
 */
int ds_control::m_read_http_header()
{
    char * ach_current; // current reading position
    // loop over input data
    ds_datablock ds_data = ads_session->dsc_transaction.m_get_next_block();
    if (ds_data.m_get_length() == -1) { // no input-data...
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI153I: no input-data..." );
        return 1;
    }

    char ch_curr = 0x00; // current char
    ds_hstring hstr_line(ads_session->ads_wsp_helper, "");
    while (ds_data.m_get_length() > -1) {
        ach_current = ds_data.m_get_start();
        while (ach_current < (ds_data.m_get_start() + ds_data.m_get_length())) {
			switch (this->iec_header_state) {

// !!! TODO !!!
// if we are in state, that a GET was received but the server's response is not processed
// we MUST NOT receive another GET from browser !!

                case ien_st_collect_start_line:
                case ien_st_header_not_complete:    {
                    // Read in data and set forward pointer of current position
                    ch_curr = *ach_current;
                    ach_current++;
                    // JF 21.01.11 Only look for 0x0a as line separators. Ignore 0x0d.
                    if (ch_curr == 0x0d) {
                        // Ignore this character
                        break;
                    }

                    // collect data of a headerline, but don't write 0x0D or 0x0A to the headerline
                    if (ch_curr != 0x0a) {
                        hstr_line += ch_curr;
                        // Ticket[16125]
                        if (ads_session->ads_config->in_max_len_header_line > 0) {
                            if (hstr_line.m_get_len() > ads_session->ads_config->in_max_len_header_line) {
                                ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error, "HIWSE494E: header line is too long: %d.", hstr_line.m_get_len() );
                                ads_session->dsc_transaction.m_mark_as_processed(NULL);
                                ads_session->dsc_webserver.m_send_error_page( ds_http_header::ien_status_bad_request, false,
                                                                              MSG_HDR_TO_LONG, ied_sdh_log_error, 494 );
                                ads_session->dsc_transaction.m_close_connection();
                                return 4;  // close connection anyway !!
                            }
                        }
                    }

                    // RFC 2616-4.2: a header line can be extended over multiple lines by preceding the following line with 0x20 or 0x09
                    if (ch_curr == 0x0a
                        && (ach_current < (ds_data.m_get_start() + ds_data.m_get_length())) // More data are available
                        && ((*ach_current==0x20) || (*ach_current==0x09)) ) {
                            // Attention: CRLFCRLF is followed by 0x20 -> we would interpret as folded header-line
                            // but it is a correct header end and data starting with 0x20/0x09; therefore we need the following code!!
                            if ( (*(ach_current-4) != 0x0d) && (*(ach_current-3) != 0x0a) ) {
                                // JF 21.01.11: check for LFLF, too.
								if (*(ach_current-2) != 0x0a) {
									break; // this headerline is extended over multiple lines -> just go on reading this line
								}
                            }
                    }

                    if (ch_curr == 0x0a) { // header line is complete
                        // mark gathers as processed (until the current position)
                        ads_session->dsc_transaction.m_mark_as_processed(ach_current);

                        if (hstr_line.m_get_len() == 0) { // header end -> header is completly read
                            if (ads_session->dsc_http_hdr_in.m_get_count_lines() == 0) {
                                ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI354I: received HTTP-header is empty" );
                                // this could happen, if CRLFs are at the beginning of the header; we will ignore them (marked as processed)
                                // go back to WSP with the flag 'callagain' to get the remaining data
                                // JF 17.05.10 Ticket[19966]: Do not return to WSP. Instead go on with parsing.
                                //ads_session->dsc_transaction.m_set_callagain(true);
                                //return 5;
                                break;
                            }
                            this->iec_header_state = ien_st_header_complete;
 
                            // JF 10.12.10 Ticket[21184]: Support of pipelining.
                            // When there is a GET/HEAD (pipelined POST is not supported!) and there are outstanding input data, we assume that
                            // the client sent a pipelined request. Set a flag for this.
                            if ( (ads_session->dsc_http_hdr_in.m_get_http_method() == ds_http_header::ien_meth_GET)
                              || (ads_session->dsc_http_hdr_in.m_get_http_method() == ds_http_header::ien_meth_HEAD) ) {
                                  if (ads_session->dsc_transaction.m_count_unprocessed_data() > 0) {
                                      ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI740I: Pipelining detected.");
                                      if ((ads_session->ads_config->in_settings & SETTING_DISABLE_SUPPORT_PIPELINING) != 0) {
                                          ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI739I: Pipelining shall not be supported.");
                                      }
                                      else {
                                          ads_session->bog_pipelining_detected = true;
                                      }
                                  }
                            }

                            return SUCCESS;
                        }
                        
                        // There are still unprocessed header lines.
                        // cut off leading and trailing blanks from the headerline
                        hstr_line.m_trim(" ");

                        if (this->iec_header_state == ien_st_collect_start_line) { // it's the startline -> parse it
                            dsd_const_string strl_line = hstr_line.m_const_str();
#if 0
                            if(strl_line.m_equals("GET /http://s.onvista.de/js-66937/jwplayerLib.js?HOB_type=js,charset=utf-8 HTTP/1.1"))
                                strl_line = "GET /http://hobc02k.hob.de/martin/wsg/OnVista/jwplayerLib.js?HOB_type=js,charset=utf-8 HTTP/1.1";
                            if(strl_line.m_equals("GET /http://s.onvista.de/js-66937/base/src/lib/highstock.src.js?HOB_type=js,charset=utf-8 HTTP/1.1"))
                                strl_line = "GET /http://hobc02k.hob.de/martin/wsg/OnVista/highstock.src.js?HOB_type=js,charset=utf-8 HTTP/1.1";
                            if(strl_line.m_starts_with("GET /http://pixel.adsafeprotected.com/jload?anId=9659"))
                                strl_line = "GET /http://hobc02k.hob.de/martin/wsg/Focus/jload01.js?HOB_type=js,charset=utf-8 HTTP/1.1";
#endif
                            if (!ads_session->dsc_http_hdr_in.m_parse_start_line(strl_line)) {
                                ads_session->dsc_transaction.m_mark_as_processed(NULL); // JF 24.03.11
                                ads_session->dsc_transaction.m_close_connection();
                                return 6;  // close connection anyway !!
                            }
							this->iec_header_state = ien_st_header_not_complete; // read the other header-lines
                        }
                        else { // it's a normal headerline -> parse it
                            if (!ads_session->dsc_http_hdr_in.m_parse_header_line(hstr_line.m_const_str())) {
                                ads_session->dsc_transaction.m_mark_as_processed(NULL); // JF 24.03.11
                                ads_session->dsc_transaction.m_close_connection();
                                return 7;  // close connection anyway !!
                            }

                            // Ticket[16125] 
                            if (ads_session->ads_config->in_max_count_header_lines > 0) {
                                if (ads_session->dsc_http_hdr_in.m_get_count_lines() > ads_session->ads_config->in_max_count_header_lines) {
                                    ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE493E: too many header lines" );
                                    ads_session->dsc_transaction.m_mark_as_processed(NULL);
                                    ads_session->dsc_webserver.m_send_error_page( ds_http_header::ien_status_bad_request, false,
                                                                                  MSG_HDR_TO_LONG, ied_sdh_log_error, 493 );
                                    ads_session->dsc_transaction.m_close_connection();
                                    return 8;  // close connection anyway !!
                                }
                            }
                        }

                        // reset variables
                        hstr_line.m_reset();
                        ch_curr = 0x00;
                    }

                    break;
                }
            } // switch (in_current_state)
        } //while (ach_current < adsl_curr_in_gath->achc_ginp_end)

        ds_data = ads_session->dsc_transaction.m_get_next_block();

    } // while (ds_data.m_get_length() > -1)

    return SUCCESS;
} // m_read_http_header


/*! \brief Get the HOB cookie
 *
 * @ingroup creator
 *
 * private
 */
dsd_const_string ds_control::m_obtain_hob_cookie(const dsd_const_string& rdsp_cookie_line, dsd_const_string& ahstr_leading_hob_cookie, dsd_const_string& ahstr_trailing_hob_cookie)
{
	// remove spaces and ; at the end of leading cookie 
	dsd_const_string dsl_cookie_line = rdsp_cookie_line;
	dsl_cookie_line.m_trim(" ;");

	const dsd_const_string dsl_hobwsp_cookie(IDENT_HOBWSP_COOKIE);
	dsd_tokenizer dsl_tok(dsl_cookie_line, ";");
	while(true) {
		dsd_const_string dsl_cookie;
		bool bol_more_tokens = dsl_tok.m_next(dsl_cookie);
		dsd_const_string dsl_cookie2 = dsl_cookie;
		dsl_cookie2.m_trim(" ");
		if(dsl_cookie2.m_starts_with(dsl_hobwsp_cookie)) {
			dsd_const_string dsl_value = dsl_cookie2.m_substring(dsl_hobwsp_cookie.m_get_len());
			dsl_value.m_trim(" ");
			if(!dsl_value.m_starts_with("=")) {
				goto LBL_NEXT;
			}
			dsl_value = dsl_value.m_substring(1);
			dsl_value.m_trim(" ");
			ahstr_leading_hob_cookie = dsd_const_string(dsl_cookie_line.m_get_start(), dsl_cookie.m_get_start()-dsl_cookie_line.m_get_start());
			if(!bol_more_tokens) {
				ahstr_trailing_hob_cookie = "";
				return dsl_value;
			}
			dsd_const_string dsl_cookie3;
			dsl_tok.m_next(dsl_cookie3);
			dsl_cookie3.m_trim(" ");
			ahstr_trailing_hob_cookie = dsd_const_string(dsl_cookie3.m_get_start(), dsl_cookie_line.m_get_end()-dsl_cookie3.m_get_start());
			return dsl_value;
		}
LBL_NEXT:
		if(!bol_more_tokens)
			break;
	}
	ahstr_leading_hob_cookie = rdsp_cookie_line;
	ahstr_trailing_hob_cookie = "";
	return dsd_const_string();
    
#if 0
    //-------------------------
    // we must cut out HOB's cookie
    //-------------------------
    int iPos = dsl_cookie_line.m_index_of(IDENT_HOBWSP_COOKIE);
    if (iPos <= 0) { // no HOB-cookie-identifier found
        return "";
    }

    // return all before HOB-cookie
    ahstr_leading_hob_cookie = dsl_cookie_line.m_substring(0, iPos);

    iPos = dsl_cookie_line.m_index_of(iPos, "=");
    if (iPos <= 0) { // no '=' found
        return "";
    }
    iPos++; // skip '='

    // skip leading blanks
    iPos = ahstr_cookie_line.m_find_first_not_of(" ", iPos);
    if (iPos <= 0) {
        return hstr_ret;
    }
    dsd_const_string hstr_rest = ahstr_cookie_line.m_substring(iPos);

    // check for termination with ';', meaning that other cookies are delivered, too
    int iPosCookieEnd = hstr_rest.m_index_of(";");
    if (iPosCookieEnd <= 0) {
        // no terminating ';', means no other cookies behind WSP-cookie
        hstr_ret = hstr_rest;
        return hstr_ret;
    }

    // return all behind HOB-cookie
    if ( ahstr_leading_hob_cookie->m_get_len() > 0 ) {
        // insert "; " if leading cookie exists!
        ahstr_trailing_hob_cookie->m_set("; ");
        ahstr_trailing_hob_cookie->m_write(hstr_rest.m_substring(iPosCookieEnd+1)); // +1 to hop behind ';'
    } else {
        ahstr_trailing_hob_cookie->m_set(hstr_rest.m_substring(iPosCookieEnd+1)); // +1 to hop behind ';'
    }
    
    hstr_ret.m_set(hstr_rest.m_get_ptr(), iPosCookieEnd);
    return hstr_ret;
#endif
}

int ds_control::m_collect_complete_message_body() {
	/*-------------------------------------------------*/
    /* read the complete message body, if there is any */
    /*-------------------------------------------------*/
    if (ads_session->dsc_http_hdr_in.m_is_message_body_announced()) {
        if (ads_session->dsc_control.m_get_state() < ds_control::ien_st_collect_message_body_of_request) {
            // set control state (to avoid superfluous parsing of data in ds_control)
			ads_session->dsc_webserver.hstr_message_body.m_reset();
            ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_collect_message_body_of_request);
        }

        if (ads_session->dsc_control.m_get_state() == ds_control::ien_st_collect_message_body_of_request) {
            int in_ret = ads_session->dsc_webserver.m_read_message_body();
            if (in_ret < 0) { // error
                ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                                        "HIWSE679E: ds_webserver.m_read_message_body() returned error %d.",
                                                        in_ret );
                return -1;
            }
            if (in_ret == 0) {// not an error; we must wait for more data
                return 0; 
            }

            // next state
            ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_process_message_body);
        }
    }
	return 1;
}

/*! \brief Session Handler
 *
 * \public
 *
 * @ingroup sessionhandler
 *
 * Decides what to do with the data, and which component is responsible to process it
 */
void ds_control::m_do_new_concept(void) {
    int in_http_method = ads_session->dsc_http_hdr_in.m_get_http_method();

    //-------------------------------
    // authenticate...  (from now on we have an open CMA)
    //-------------------------------
    bo_authenticated_url    = false;
    bo_authenticated_header = false;
    bo_authenticated_certificate = false;
    bo_authenticated_ident  = false;

#ifdef _DEBUG
    dsd_const_string dsl_http_method = ads_session->dsc_http_hdr_in.m_get_http_method_char();
    ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "[%d] #m_do_new_concept: METHOD=%.*s URL=%.*s\n",
        ads_session->ads_wsp_helper->m_get_session_id(), 
        dsl_http_method.m_get_len(), dsl_http_method.m_get_ptr(),
	    ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_get_len(),  ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_get_ptr());
    if(ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_ends_with("uglobal.js?HOB_type=js")) {
        int a = 0;
    }
    if(ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_starts_with("/wsg/https://account.hanatrial.ondemand.com/ajax/getBootstrapConfiguration?HOB_type=none,origin=https://account.hanatrial.ondemand.com")) {
        int a = 0;
    }
	if(ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_equals("/")) {
        int a = 0;
    }
#endif

	if (!ads_session->dsc_http_hdr_in.m_is_webserver_response()) { // request by client -> verify the delivered cookie
        // Suppress error message, when a file from folder FOLDER_PUBLIC is requested
        bool bo_suppress_err_msg = false;
        if (ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_starts_with_ic(FOLDER_PUBLIC)) {
            bo_suppress_err_msg = true;
        }
          

		dsd_const_string hstr_hdrline_cookie = ads_session->dsc_http_hdr_in.hstr_hdrline_cookie.m_const_str();
		dsd_const_string hstr_before; // will be ignored
	    dsd_const_string hstr_behind; // will be ignored
		dsd_const_string hstr_HOB_cookie = m_obtain_hob_cookie(hstr_hdrline_cookie, hstr_before, hstr_behind);

        HL_DBG_PRINTF("#m_do_new_concept: Cookie=%.*s\n", hstr_hdrline_cookie.m_get_len(), hstr_hdrline_cookie.m_get_ptr());
        bool bo_ret_validate = false;

          if (!bo_ret_validate && ads_session->dsc_http_hdr_in.bo_cookie_header_exists) { // cookie from http-header
              bo_ret_validate = this->m_authenticate(hstr_HOB_cookie, false);
            
				HL_DBG_PRINTF("#m_do_new_concept: bo_ret_validate=%d\n", bo_ret_validate);
            //--------------------------------------
            // set http cookie state:
            //--------------------------------------
            ads_session->dsc_auth.m_set_state( ST_HTTP_COOKIE_ENABLED );
            if ( bo_ret_validate == false ) { // authentication failed
                if (!bo_suppress_err_msg) { // suppress error message, when a file from folder FOLDER_PUBLIC is requested
                    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                                         "HIWSE048E: Authentication (HTTP-header) failed for %s",
                                                         ads_session->dsc_http_hdr_in.hstr_hdrline_cookie.m_get_ptr() );
                }
            }
            else {
                ads_session->dsc_auth.m_set_state( ST_OCCUPIED );
                bo_authenticated_header = true;
            }
        }
        if ( bo_ret_validate == false && ads_session->dsc_http_hdr_in.dsc_url.bo_url_cookie) { // not authenticated by http-header -> look in URL
            bo_ret_validate = this->m_authenticate(
                ads_session->dsc_http_hdr_in.dsc_url.hstr_url_cookie, true);
            if ( bo_ret_validate == false /* authentication failed */ ) { 
                if (!bo_suppress_err_msg) { // suppress error message, when a file from folder FOLDER_PUBLIC is requested
                    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                                         "HIWSE049E: Authentication (URL) failed for %s",
                                                         ads_session->dsc_http_hdr_in.hstr_hdrline_cookie.m_get_ptr() );
                }
            }
            else {
                bo_authenticated_url = true;
            }
        }
#if 1
        if( bo_ret_validate == false ) {
            bo_ret_validate = this->m_authenticate_by_ident();
            if(bo_ret_validate) {
                bo_authenticated_ident = true;
            }
        }
#endif
        if( bo_ret_validate == false ) {
            // Check login via client certificate
			bo_ret_validate = this->ads_session->dsc_auth.m_handle_login_cert();
            if(bo_ret_validate) {
                ads_session->dsc_auth.m_set_state( ST_OCCUPIED );
                bo_authenticated_certificate = true;
            }
        }

		ads_session->dsc_ws_gate.hstr_hdrline_cookie = hstr_before;
		ads_session->dsc_ws_gate.hstr_hdrline_cookie.m_write(hstr_behind);
	}

    // If no language is set up to now -> take the one, which is accepted by browser
    int inl_language = ads_session->dsc_auth.m_get_lang();
    if ( inl_language == LANGUAGE_NOT_SET ) {
        inl_language = ads_session->dsc_http_hdr_in.in_language;
        ads_session->dsc_auth.m_set_lang(inl_language);
    }
    // read the language
    this->in_cma_lang = inl_language;

	bool bo_authenticated = bo_authenticated_header
        || bo_authenticated_url
        || bo_authenticated_certificate
        || bo_authenticated_ident;
	dsd_const_string dsl_prefix;
#if SM_USE_QUICK_LINK
	 dsl_prefix = "/quicklink/";
    if(ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_starts_with(dsl_prefix)) {
		 dsd_const_string dsl_remainder = ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_substring(dsl_prefix.m_get_len());
		 ads_session->dsc_webserver.m_handle_quick_link(dsl_remainder, bo_authenticated);
		 return;
    }
#endif
#if SM_USE_AUX_PIPE_STREAM && !SM_USE_VIRTUAL_LINK
	 dsl_prefix = "/stream/";
    if(ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_starts_with(dsl_prefix)) {
		 dsd_const_string dsl_remainder = ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_substring(dsl_prefix.m_get_len());
		 ads_session->dsc_webserver.m_handle_stream_link(dsl_remainder, bo_authenticated);
		 return;
    }
#endif
#if SM_USE_VIRTUAL_LINK
	 dsl_prefix = "/virtual/";
    if(ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_starts_with("/virtual/")) {
		 int inl_ret = this->m_collect_complete_message_body();
		 if(inl_ret < 0)
          return;
		 if(inl_ret == 0) {
		    return;
		 }
		 dsd_const_string dsl_remainder = ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_substring(dsl_prefix.m_get_len());
		 ads_session->dsc_webserver.m_handle_virtual_link(dsl_remainder, bo_authenticated);
		 return;
    }
#endif

#if SM_USE_HOBLAUNCH_REDIRECT
	dsl_prefix = "/hoblaunch/";
    if(ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_starts_with(dsl_prefix)) {
        dsd_const_string dsl_remainder = ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_substring(dsl_prefix.m_get_len()-1);
        
        // Send the response (only header containing "Location moved")
        ds_hstring hstr_location = ads_session->dsc_webserver.m_create_location(
            dsl_remainder, ads_session->dsc_http_hdr_in.dsc_url.hstr_query,
            true);
        hstr_location.m_insert_zeroterm(0, "hobweblaunch:/jws/url/");

        dsd_const_string dsl_location(hstr_location.m_const_str());
        ads_session->dsc_webserver.m_create_resp_header(ds_http_header::ien_status_found, 0, &dsl_location, NULL, NULL, true, NULL);
        ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
		m_set_ctrl_state(ien_st_body_sent_to_browser);

        return;
    }
#endif
	 int in_task = ien_task_invalid;
    bool bo_insert_id_in_url = false;
    bool bo_prevent_caching = false;
    ds_hstring hstr_msg_errorpage(ads_session->ads_wsp_helper, "");
    
    // No CMA exists for this user -> create it.
    if ( ads_session->dsc_auth.m_check_state( ST_OCCUPIED ) == false ) {
        if (!m_register_to_cma()) {
            // creation of CMA failed
			ads_session->dsc_webserver.m_clear_query();

            ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE087E: CMA could not be created" );
            ads_session->dsc_webserver.m_send_error_page( ds_http_header::ien_status_internal_error, false,
                                                          MSG_CREATE_CMA_ERR, ied_sdh_log_error, 87 );
            return;
        }
    }

	 if(!ads_session->m_ensure_url_cookie()) {
			ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE087E: CMA session id not available" );
			ads_session->dsc_webserver.m_send_error_page( ds_http_header::ien_status_internal_error, false,
															MSG_CREATE_CMA_ERR, ied_sdh_log_error, 87 );
			return;
	 }

	const dsd_virtual_link* adsl_vir_lnk = NULL;
	int inl_ret = ads_session->dsc_ws_gate.m_accept_request(&adsl_vir_lnk);
	if(inl_ret != 0) {
		if(inl_ret < 0)
			return;
		if(inl_ret == 2) {
			inl_ret = this->m_collect_complete_message_body();
			if(inl_ret < 0)
				return;
			if(inl_ret == 0) {
				return;
			}
		}
		if (!bo_authenticated) { // User is not authenticated -> forward to login page (with a message) and remember the requested page.
#if 0
			// Problem with this scenario: Connection via WSG is running, and now the browser does not deliver the HOB-cookie any more !!
            // Then we will forward to login-page, but these data will get sent to webserver! Therefore we must change the direction.
            if (ads_session->dsc_transaction.m_get_callmode() == DEF_IFUNC_TOSERVER) {
                ads_session->dsc_transaction.m_set_callrevdir(true);
                ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning, "HIWSW627W: Changing call-mode from DEF_IFUNC_TOSERVER to callrevdir" );
                return;
            }
#endif
            ads_session->dsc_auth.m_set_msg( ied_sdh_log_warning, 627, MSG_AUTH_REQUIRED, ads_session->ads_config->ach_login_site );
            if (ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_get_len() > 0) {
                ads_session->dsc_auth.m_set_bookedpage(
					ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_get_ptr(),
					ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_get_len());
            }
            in_task = ien_task_forward_to_login_page;
            goto LBL_PROCESS_TASK;
        }

        // WebFileAccess
        bool bo_req_wfa = m_is_request_for_wfa(adsl_vir_lnk);
        if (bo_req_wfa) {
            // Request for WFA -> check whether WebFileAccess is enabled and requested
            if (ads_session->dsc_auth.m_is_portlet_allowed(achg_known_portlets[ied_wfa_portlet]) == false) { // WebFileAccess is disabled
                // Display error page to client
                ads_session->ads_wsp_helper->m_log(ied_sdh_log_warning, "HIWSE282E: Access denied to Web File Access.");
                ads_session->dsc_webserver.m_send_error_page( ds_http_header::ien_status_not_found, false, MSG_NO_WFA, 0, 0 );
                return;
            }
        }

        // gloabl admin request
        bool bol_req_globaladm = m_is_request_for_globaladm(adsl_vir_lnk);
        if ( bol_req_globaladm ) {
            // Request for RDVPNUpdater -> check whether Admin is enabled
            if (ads_session->dsc_auth.m_is_portlet_allowed(achg_known_portlets[ied_globaladm_portlet]) == false) {
                // Display error page to client
                ads_session->ads_wsp_helper->m_log(ied_sdh_log_warning, "HIWSE283E: Access denied.");
                ads_session->dsc_webserver.m_send_error_page( ds_http_header::ien_status_not_found, false, MSG_ACCESS_DENIED, 0, 0 );
                return;
            }
        }


        // Do some checkings (e.g. whether WSG is enabled) before we go to WSG
        // Attention: If WebServerGate is disabled, WebFileAccess must be accessible, if desired!
        if (!m_is_wsg_enabled(bo_authenticated, bo_req_wfa | bol_req_globaladm )) {
            // Check failed. An error message was already sent to browser -> we can return here.
            return;
        }

#if SM_USE_OLD_HOBNET
		// WebServerGate-class will process the data
        if (bo_do_hob_net) {
#if 0
			ds_hstring& rhstr_authority_of_webserver = ads_session->dsc_http_hdr_in.dsc_url.hstr_authority_of_webserver;
            // Write the authority of the WebServer (it was not contained in the WRONG url!).
            rhstr_authority_of_webserver.m_reset();
            if ( ((in_protocol_last_webserver == PROTO_HTTP)  && (in_port_last_webserver == 80))      // http
              || ((in_protocol_last_webserver == PROTO_HTTPS) && (in_port_last_webserver == 443)) ) { // https
                rhstr_authority_of_webserver = hstr_last_ws; // default ports -> no port number needed
            }
            else {
                rhstr_authority_of_webserver.m_write(hstr_last_ws);
                rhstr_authority_of_webserver.m_write(":");
                rhstr_authority_of_webserver.m_write_int(in_port_last_webserver);
            }
#endif
            dsd_const_string dsl_last_ws(hstr_last_ws.m_const_str());
            ads_session->dsc_ws_gate.m_handle_request((in_protocol_last_webserver!=PROTO_HTTP), &dsl_last_ws, in_port_last_webserver);
        }
#endif
        ads_session->dsc_ws_gate.m_handle_request();
        return;
	}
	else {
#if 0
    // MJ avoid storing of the whole message body in case of
    // virutal links like wfa ...
    //-----------------------------
    // Check for virtual links
    //-----------------------------
    bool bo_virtual_link = false;
    const dsd_virtual_link* adsl_vir_lnk = NULL;
    if ( (ads_session->dsc_auth.m_check_state(ST_ACCEPTED))    // WSG can be used only, when we are logged in.
      && (ads_session->ads_config->adsl_vi_lnk != NULL)    ) { // Virtual links must be configured.
          bo_virtual_link = m_check_virtual_link(ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_const_str(), &adsl_vir_lnk);
    } // ST_ACCEPTED and adsl_vi_lnk != NULL
#endif

    //-------------------------------
    // construct full path of the file to load
    //-------------------------------
    // ??? if ( (in_http_method == ds_http_header::ien_meth_HEAD) || (in_http_method == ds_http_header::ien_meth_GET) ) {  ???
    ads_session->dsc_webserver.m_get_fullpath(&ads_session->dsc_webserver.ds_path);

    /*-------------------------------------------------*/
    /* read the complete message body, if there is any */
    /*-------------------------------------------------*/
	inl_ret = this->m_collect_complete_message_body();
	if(inl_ret < 0)
		return;
	if(inl_ret == 0)
		return;
    if (in_http_method == ds_http_header::ien_meth_POST && ads_session->dsc_webserver.hstr_message_body.m_get_len() <= 0) { // we expect username/password/state/destination/etc in the POST-message-body
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE629E: No message-body announced in POST" );
        ads_session->dsc_webserver.m_send_error_page( ds_http_header::ien_status_bad_request, true,
                                                      MSG_MESSAGE_BODY, ied_sdh_log_error, 629 );
        return;
    }

    //---------------------------------------------
    // get query from both url and message body:
    //---------------------------------------------
	ads_session->dsc_webserver.m_clear_query();
    ds_hstring hstr_query(ads_session->ads_wsp_helper, ""); // must be setup here, so it remains. This are the data, where the pointers of ads_session->dsc_webserver.ads_query shall point to.
    hstr_query.m_set(ads_session->dsc_http_hdr_in.dsc_url.hstr_query);
    if (    hstr_query.m_get_len() > 0 
            && ads_session->dsc_webserver.hstr_message_body.m_get_len() > 0 ) {
        hstr_query.m_write("&");
    }
    hstr_query += ads_session->dsc_webserver.hstr_message_body;
    if (hstr_query.m_get_len() > 0) {
        ads_session->dsc_webserver.ads_query = ads_session->dsc_webserver.m_parse_query( hstr_query.m_const_str() );
        inl_ret = ads_session->dsc_webserver.m_conv_from_hexhexencoding( &hstr_query );
        if (inl_ret != SUCCESS) {
            ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE429E: m_conv_from_hexhexencoding failed with error %d.", inl_ret);
            ads_session->dsc_webserver.m_send_error_page( ds_http_header::ien_status_bad_request, true,
                                                            "ERROR", ied_sdh_log_error, 429 );
            return;
        }
    }

    // Detailed print out.
    if ( (in_http_method == ds_http_header::ien_meth_HEAD) || (in_http_method == ds_http_header::ien_meth_GET) ) {
        if ((ads_session->ads_config->in_flags & FLAG_WRITE_COMPLETE_FILENAME) == FLAG_WRITE_COMPLETE_FILENAME) {
            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info, "HIWSI630I: URL: %s; state: %d",
                                                    ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_ptr(),
                                                    ads_session->dsc_webserver.ds_path.in_state_path );
        }
    }

    // Variables , which will be filled during working inside CMAs and used after CMAs are closed.
    // Attention: not all variables may get filled for different scenarios!
    bo_cma_httpcookie_enabled = ads_session->dsc_auth.m_check_state(ST_HTTP_COOKIE_ENABLED);    

    // read the cookie
    ds_cma_cookie.m_setup(ads_session->ads_wsp_helper);
    ads_session->dsc_auth.m_get_http_cookie( &ds_cma_cookie );
	 HL_DBG_PRINTF("#m_do_new_concept: ds_cma_cookie=%.*s\n", ds_cma_cookie.m_get_len(), ds_cma_cookie.m_get_ptr());

    // ads_session->dsc_webserver.ds_path.in_state_path was set to a temporarily value, which must now be refined in dependency of the CMA-state.
    if ( ads_session->dsc_webserver.ds_path.in_state_path == PATH_URL_IS_SLASH ) {
        // Ticket[14678]: After successful authentication we forward browser to the site-after-auth by 'Location moved';
        // IE requests this page, all is ok. But when in mode "Content Advisor/Inhaltsratgeber" IE sends a 'GET /' after it
        // got the response -> this will be interpreted as 'Logoff' and communication is cancelled. To avoid this the settings-value
        // must be ORed with SETTING_GET_SLASH_IS_NOT_LOGOFF. Then we will respond with '404 Not found' in this case. However, the
        // session must be in ACCEPTED state for this feature.
        if ( (ads_session->dsc_auth.m_check_state(ST_AUTHENTICATED) == true) ) {
            ads_session->dsc_webserver.ds_path.in_state_path = PATH_GET_SLASH_IS_NOT_LOGOFF; 
        }
        else {
            ads_session->dsc_webserver.ds_path.in_state_path = PATH_FORCE_LOGIN_PAGE;
        }
    }

    // Ticket[16992]
    bool bo_force_quarantine = false;
    if (    ads_session->dsc_auth.m_check_state( ST_AUTHENTICATED )    == true
         && ads_session->dsc_auth.m_check_state( ST_COMPLCHECK_FORCE ) == true ) {
        bo_force_quarantine = true;
    }

#if SM_USE_OLD_HOBNET
    //-------------------------------------------------------
    // Check, whether HOB_NET must process the request
    //-------------------------------------------------------
    // the URL is for own webserver, but might be for an external webserver ...
    bool bo_do_hob_net = false;
    if ((ads_session->ads_config->in_settings & SETTING_HOB_NET_OFF) == 0) {
        int in_protocol_last_webserver = 0;
		int in_port_last_webserver     = 0;            
		// check, whether we are already ACCEPTED (then WSG might be on) and WSG was active
        ds_hstring hstr_last_ws = ads_session->dsc_auth.m_get_lws(&in_protocol_last_webserver, &in_port_last_webserver);
		if ( (ads_session->dsc_auth.m_check_state( ST_ACCEPTED ))
          && (!bo_force_quarantine)
          && (hstr_last_ws.m_get_len() > 0) ) {
            // get http-method (e.g. ds_http_header::ien_meth_POST)
            if ( m_check_hob_net( in_http_method ) ) {
                // only in this cases it makes sense to check whether the file exists
                struct dsd_hl_aux_diskfile_1 ds_check_exist;
                memset(&ds_check_exist, 0, sizeof(struct dsd_hl_aux_diskfile_1));
#ifndef WSP_V24
                ds_check_exist.iec_chs_name = ied_chs_utf_8;
                ds_check_exist.ac_name = (void*)ads_session->dsc_webserver.ds_path.hstr_path.m_get_ptr();
                ds_check_exist.inc_len_name = ads_session->dsc_webserver.ds_path.hstr_path.m_get_len();
#endif
#ifdef WSP_V24
                ds_check_exist.dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;
                ds_check_exist.dsc_ucs_file_name.ac_str = (void*)ads_session->dsc_webserver.ds_path.hstr_path.m_get_ptr();
                ds_check_exist.dsc_ucs_file_name.imc_len_str = ads_session->dsc_webserver.ds_path.hstr_path.m_get_len();
#endif

                ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info, "HIWSI253I: HOB_net is checking file-existance: %s",
                                                     ads_session->dsc_webserver.ds_path.hstr_path.m_get_ptr() );

                bool bo_ret = ads_session->ads_wsp_helper->m_cb_file_access(&ds_check_exist);
                if (!bo_ret) { // file is not found on the disk  -> this request might be for an external webserver -> forward it
                    //---------------------------
                    // request was to webserver, but shall be forwarded to WebServerGate
                    //---------------------------
                    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info, "HIWSI254I: HOB_net forwards request to %s%s:%d",
                                                         (in_protocol_last_webserver==0?"http://":"https://"),
                                                         hstr_last_ws.m_get_ptr(), in_port_last_webserver );

                    // We will do HOB_NET
                    bo_do_hob_net = true;
                }
                else {
                    // Give free memory of file access. If file access fails, no freeing is necessary.
                    if (!ads_session->ads_wsp_helper->m_cb_file_release(&ds_check_exist)) {
                        ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE329E: DEF_AUX_DISKFILE_RELEASE failed" );
                    }
                }
            }
        }
    } // HOB_NET is on
#endif /*SM_USE_OLD_HOBNET*/

    // read the state
    in_cma_state = ads_session->dsc_auth.m_get_state();
	 HL_DBG_PRINTF("m_do_new_concept: in_cma_state=%08X\n", in_cma_state);

#if 0
    // scenario: user browsed to a web-page with WebServerGate and forces browser to refresh the site
    // then the file HOBScript.js is requested from WebServer, but inc_func is DEF_IFUNC_TOSERVER (WSG-functionality)
    // therefore we must do the following:
    // Caution: in case of POST (logoff!!) the payload-data must be collected; otherwise they will be lost!!!!
    if ( (ads_session->dsc_transaction.m_get_callmode() == DEF_IFUNC_TOSERVER)
      && (!ads_session->dsc_http_hdr_in.dsc_url.bo_data_for_wsg) // for webserver
      && (!bo_do_hob_net)
      && (!bo_virtual_link) ) {
        ads_session->dsc_transaction.m_set_callrevdir(true);
        //ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning, "HIWSW629W: Changing call-mode from DEF_IFUNC_TOSERVER to callrevdir" );
        return;
    }
#endif

    //--------------------------------//
    // Tasks during the CMAs are open //
    //--------------------------------//
    // POSTs for the webserver will be completly processed during the CMAs are open!
    if ( (in_http_method == ds_http_header::ien_meth_POST)
#if SM_USE_OLD_HOBNET
		&&   (!bo_do_hob_net)
#endif
		)
	{
        ads_session->dsc_webserver.m_handle_post( bo_authenticated );
		ads_session->dsc_webserver.m_clear_query();
        return;
    }

#if 0
	/*------------------------*/
    /* Data for WebServerGate */
    /*------------------------*/
    // We use a while-loop instead  of 'if', because we leave this loop via 'break' (simulation of a 'switch')
    while (ads_session->dsc_http_hdr_in.dsc_url.bo_data_for_wsg || bo_do_hob_net || bo_virtual_link ) {
        if (!bo_authenticated) { // User is not authenticated -> forward to login page (with a message) and remember the requested page.
#if 0
			// Problem with this scenario: Connection via WSG is running, and now the browser does not deliver the HOB-cookie any more !!
            // Then we will forward to login-page, but these data will get sent to webserver! Therefore we must change the direction.
            if (ads_session->dsc_transaction.m_get_callmode() == DEF_IFUNC_TOSERVER) {
                ads_session->dsc_transaction.m_set_callrevdir(true);
                ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning, "HIWSW627W: Changing call-mode from DEF_IFUNC_TOSERVER to callrevdir" );
                return;
            }
#endif
            ads_session->dsc_auth.m_set_msg( ied_sdh_log_warning, 627, MSG_AUTH_REQUIRED, ads_session->ads_config->ach_login_site );
            if (ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_get_len() > 0) {
                ads_session->dsc_auth.m_set_bookedpage(ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_get_ptr(), ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_get_len());
            }
            in_task = ien_task_forward_to_login_page;
            goto LBL_PROCESS_TASK;
        }

        // WebFileAccess
        bool bo_req_wfa = m_is_request_for_wfa(adsl_vir_lnk);
        if (bo_req_wfa) {
            // Request for WFA -> check whether WebFileAccess is enabled and requested
            if (ads_session->dsc_auth.m_is_portlet_allowed(achg_known_portlets[ied_wfa_portlet]) == false) { // WebFileAccess is disabled
                // Display error page to client
                ads_session->ads_wsp_helper->m_log(ied_sdh_log_warning, "HIWSE282E: Access denied to Web File Access.");
                ads_session->dsc_webserver.m_send_error_page( ds_http_header::ien_status_not_found, false, MSG_NO_WFA, 0, 0 );
                return;
            }
        }

        // gloabl admin request
        bool bol_req_globaladm = m_is_request_for_globaladm(adsl_vir_lnk);
        if ( bol_req_globaladm ) {
            // Request for RDVPNUpdater -> check whether Admin is enabled
            if (ads_session->dsc_auth.m_is_portlet_allowed(achg_known_portlets[ied_globaladm_portlet]) == false) {
                // Display error page to client
                ads_session->ads_wsp_helper->m_log(ied_sdh_log_warning, "HIWSE283E: Access denied.");
                ads_session->dsc_webserver.m_send_error_page( ds_http_header::ien_status_not_found, false, MSG_ACCESS_DENIED, 0, 0 );
                return;
            }
        }


        // Do some checkings (e.g. whether WSG is enabled) before we go to WSG
        // Attention: If WebServerGate is disabled, WebFileAccess must be accessible, if desired!
        if (!m_is_wsg_enabled(bo_authenticated, bo_req_wfa | bol_req_globaladm )) {
            // Check failed. An error message was already sent to browser -> we can return here.
            return;
        }

        // WebServerGate-class will process the data
        if (bo_do_hob_net) {
#if 0
			ds_hstring& rhstr_authority_of_webserver = ads_session->dsc_http_hdr_in.dsc_url.hstr_authority_of_webserver;
            // Write the authority of the WebServer (it was not contained in the WRONG url!).
            rhstr_authority_of_webserver.m_reset();
            if ( ((in_protocol_last_webserver == PROTO_HTTP)  && (in_port_last_webserver == 80))      // http
              || ((in_protocol_last_webserver == PROTO_HTTPS) && (in_port_last_webserver == 443)) ) { // https
                rhstr_authority_of_webserver = hstr_last_ws; // default ports -> no port number needed
            }
            else {
                rhstr_authority_of_webserver.m_write(hstr_last_ws);
                rhstr_authority_of_webserver.m_write(":");
                rhstr_authority_of_webserver.m_write_int(in_port_last_webserver);
            }
#endif
            dsd_const_string dsl_last_ws(hstr_last_ws.m_const_str());
            ads_session->dsc_ws_gate.m_handle_request((in_protocol_last_webserver!=PROTO_HTTP), &dsl_last_ws, in_port_last_webserver);
        }
        else if (bo_virtual_link) {
#if 0
			ds_hstring& rhstr_authority_of_webserver = ads_session->dsc_http_hdr_in.dsc_url.hstr_authority_of_webserver;
            // Write the authority of the WebServer.
            if ( ((dsl_vir_lnk.in_protocol == PROTO_HTTP)  && (dsl_vir_lnk.in_port == 80))      // http
              || ((dsl_vir_lnk.in_protocol == PROTO_HTTPS) && (dsl_vir_lnk.in_port == 443)) ) { // https
                  rhstr_authority_of_webserver.m_set(dsl_vir_lnk.ach_authority, dsl_vir_lnk.in_len_authority); // default ports -> no port number needed
            }
            else {
                rhstr_authority_of_webserver.m_reset();
                rhstr_authority_of_webserver.m_write(dsl_vir_lnk.ach_authority, dsl_vir_lnk.in_len_authority);
                rhstr_authority_of_webserver.m_write(":");
                rhstr_authority_of_webserver.m_write_int(dsl_vir_lnk.in_port);
            }
#endif
            dsd_const_string hstr_auth(adsl_vir_lnk->ach_authority, adsl_vir_lnk->in_len_authority);
            ds_hstring hstr_path_replaced(ads_session->ads_wsp_helper, ads_session->dsc_http_hdr_in.dsc_url.hstr_path);
            hstr_path_replaced.m_replace(dsd_const_string(adsl_vir_lnk->ach_alias, adsl_vir_lnk->in_len_alias), dsd_const_string(adsl_vir_lnk->ach_path, adsl_vir_lnk->in_len_path));
            dsd_const_string hstr_path_replaced2(hstr_path_replaced.m_const_str());
            ads_session->dsc_ws_gate.m_handle_request((adsl_vir_lnk->in_protocol!=PROTO_HTTP), &hstr_auth, adsl_vir_lnk->in_port, &hstr_path_replaced2);
        }
#if 0
        else if(ads_session->dsc_http_hdr_in.m_get_http_method() == ds_http_header::ien_meth_POST 
            && ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_ends_with_ic("ck_post") )
        {
			ads_session->dsc_webserver.hstr_my_encoding = "text/plain";
            ads_session->dsc_webserver.m_create_resp_header( ds_http_header::ien_status_ok,
                                                             0, NULL, NULL, NULL, false, NULL);
            ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
			m_set_ctrl_state(ien_st_body_sent_to_browser);
            return;
        }
#endif
        else {
            ads_session->dsc_ws_gate.m_handle_request();
        }

        return;
    }
#endif

    //**********************
    // Data for WebServer
    //**********************

    // Determine, how to go on after the CMAs will be closed.
    switch (ads_session->dsc_webserver.ds_path.in_state_path) {
    case PATH_ERROR: { // forward to login page (??? 27.08.09 shall we send an error page instead ???)
        in_task = ien_task_forward_to_login_page;
        break;
    }
    case PATH_GET_SLASH_IS_NOT_LOGOFF: {
        in_task = ien_task_send_welcome_page;
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI657I: ien_task_get_slash_is_not_logoff; 'GET /' forward to site-after-auth" );
        break;
    }
    case PATH_ACCESS_DENIED: { // send an error page
        hstr_msg_errorpage.m_writef("Access denied: %.*s",
            ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_len(), ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_ptr());
        in_task = ien_task_send_forbidden;
        break;
    }
    case PATH_FORCE_LOGIN_PAGE: {
        in_task = ien_task_forward_to_login_page;
        break;
    }
    case PATH_LOGIN_PAGE_REQUESTED: {
        if(bo_authenticated) {
            in_task = ien_task_send_welcome_page;
            break;
        }
        // login page was requested; if no ID was in URL we must forward to /(HOB..)/public/login.hsl
        if (!ads_session->dsc_http_hdr_in.dsc_url.bo_url_cookie) {
            bo_insert_id_in_url = true;
            bo_prevent_caching = true;
            in_task = ien_task_forward_to_login_page;
        }
        else { // send the login page
            in_task = ien_task_send_login_page;
        }
        break;
    }
    case PATH_AUTHENICATION_REQUIRED: { // user must be authenticated to get this page
        if (bo_authenticated) {
            in_task = ien_task_send_requested_file;
        }
        else { // User is not authenticated -> forward to login page (with a message) and remember the requested page.
            ads_session->dsc_auth.m_set_msg( 0, 0, MSG_AUTH_REQUIRED, ads_session->ads_config->ach_login_site );
            if (ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_get_len() > 0) {
                ads_session->dsc_auth.m_set_bookedpage(ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_get_ptr(), ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_get_len());
            }
            in_task = ien_task_forward_to_login_page;
        }
        break;
    }
    case PATH_GET_FAVICON: { // user must be authenticated to get this page
        if (bo_authenticated) {
            in_task = ien_task_send_requested_file;
        }
        else { // User is not authenticated -> forward to login page (with a message) and DO NOT remember the requested page (=favicon).
            ads_session->dsc_auth.m_set_msg( 0, 0, MSG_AUTH_REQUIRED, ads_session->ads_config->ach_login_site );
            in_task = ien_task_forward_to_login_page;
        }
        break;
    }
    case PATH_PUBLIC: { // A file underneeth folder "/public" was requested.
        in_task = ien_task_send_requested_file;
        break;
    }
    case PATH_FORCE_LOGOUT_PAGE: {
        in_task = ien_task_forward_to_logout_page;
        break;
    }
    case PATH_LOGOUT_PAGE_REQUESTED: {
        //in_task = ien_task_send_logout_page;
        // Problem: There are lots of calls into CMA during Logout. Therefore I do the complete logout procedure while we are working in CMA.
        // But the CMAs get not closed (number is 7!!)   ???????

        //-------------------------------
        // prepare and send the logout-page
        //-------------------------------
        ads_session->dsc_webserver.m_send_logout_page();
        // This TCP-connection shall be closed.
        ads_session->dsc_transaction.m_mark_as_processed(NULL); // JF 24.03.11
        ads_session->dsc_transaction.m_close_connection();
        return;
    }
    default: {
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning, 
                                                "HIWSE197E: Unknown ds_path.in_state_path %d",
                                                ads_session->dsc_webserver.ds_path.in_state_path );
        in_task = ien_task_invalid;
        break;
    }
    } // switch (ads_session->dsc_webserver.ds_path.in_state_path)

// <<<<<<<<<<<<<  end of work in CMA


    //-------------------------------
    // Process the tasks after the CMA was closed.
    //-------------------------------


    // Check, whether AntiXss and other check are completed
    // TODO: If-Conditions seem to be wrong?
    if (    bo_force_quarantine == true 
         && (ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_starts_with_ic("/protected/quarantine/"))
         && (ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_starts_with_ic(FOLDER_PUBLIC)) 
         && (ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_starts_with_ic("/favicon.ico")) ) { //  client checking is not completed -> display error-page to client
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE474E: Your machine needs some security checks." );
        ads_session->dsc_webserver.m_forward_to_logout( MSG_CHECKS_REQ, ied_sdh_log_error, 474 );
		ads_session->dsc_webserver.m_clear_query();
        return;
    }
	}

LBL_PROCESS_TASK:
    switch (in_task) {
    case ien_task_invalid: {
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE187E: Invalid task detected." );
        ads_session->dsc_webserver.m_send_error_page( ds_http_header::ien_status_internal_error, false,
                                              "HIWSE187E: Invalid task detected.", ied_sdh_log_error, 187 );
        break;
    }
    case ien_task_send_forbidden: {
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning, "HIWSW185W: %s", hstr_msg_errorpage.m_get_ptr() );
        ads_session->dsc_webserver.m_send_error_page( ds_http_header::ien_status_forbidden, false,
                                                      MSG_ACCESS_DENIED, ied_sdh_log_warning, 185 );
        break;
    }
    case ien_task_forward_to_login_page: {
        /********************************************************/
        /* force browser to get login page (no special message)    */
        /********************************************************/
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI120I: ien_task_forward_to_login_page" );
        
        // Send the response (only header containing "Location moved")
        ds_hstring hstr_location = ads_session->dsc_webserver.m_create_location(
            ads_session->ads_config->ach_login_site, dsd_const_string(),
            bo_insert_id_in_url);
        dsd_const_string dsl_location(hstr_location.m_const_str());
        ads_session->dsc_webserver.m_create_resp_header(ds_http_header::ien_status_found, 0, &dsl_location, NULL, NULL, bo_prevent_caching, NULL);
        ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
		  m_set_ctrl_state(ien_st_body_sent_to_browser);
        break;
    }
    case ien_task_send_welcome_page: {
        // forward to welcome or to booked page
        dsd_const_string hstr_next(ads_session->ads_config->ach_site_after_auth); // default welcome page
        ds_hstring dsl_temp(ads_session->dsc_auth.m_get_bookedpage());
        if ( dsl_temp.m_get_len() > 0 ) {
            // user has requested a special page:
            hstr_next = dsl_temp.m_const_str();
            ads_session->dsc_auth.m_set_bookedpage( NULL, 0 );
        } else if ( (dsl_temp=ads_session->dsc_auth.m_get_welcomepage()).m_get_len() > 0 ) {
            // user has his own welcome page:
            hstr_next = dsl_temp.m_const_str();
        }
        ds_hstring hstr_location = ads_session->dsc_webserver.m_create_location(hstr_next, dsd_const_string(), false, false, NULL );
        dsd_const_string dsl_location(hstr_location.m_const_str());
        ads_session->dsc_webserver.m_create_resp_header(ds_http_header::ien_status_found, 0, &dsl_location, NULL, NULL, false, NULL);
        ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
		m_set_ctrl_state(ien_st_body_sent_to_browser);
#if 0
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI657I: ien_task_get_slash_is_not_logoff; 'GET /' answered by 404" );

        // Ticket[14678]: After successful authentication we forward browser to the site-after-auth by 'Location moved';
        // IE requests this page, all is ok. But when in mode "Content Advisor/Inhaltsratgeber" IE sends a 'GET /' after it
        // got the response -> this will be interpreted as 'Logoff' and communication is cancelled. To avoid this the settings-value
        // must be ORed with SETTING_GET_SLASH_IS_NOT_LOGOFF. Then we will respond with '404 Not found' in this case. However, the
        // session must be in ACCEPTED state for this feature.
        ads_session->dsc_webserver.m_create_resp_header(ds_http_header::ien_status_not_found, 0, NULL, NULL, NULL, false, NULL);
        ads_session->dsc_transaction.m_send_header(ds_control::ien_st_body_sent_to_browser);
#endif
        break;
    }
    case ien_task_forward_to_logout_page: {
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI957I: ien_task_forward_to_logout_page" );

        ads_session->dsc_webserver.m_forward_to_logout( dsd_const_string::m_null(), 0, 0 );
        break;
    }
    // This is done during working in CMA !!
    //case ien_task_send_logout_page: {
    //    //-------------------------------
    //    // prepare and send the logout-page
    //    //-------------------------------
    //    string str_html_to_browser = "";
    //    bool bo_send_to_browser = ads_session->dsc_webserver.m_create_logout_page(str_html_to_browser);
    //    if (bo_send_to_browser) { // true: a response for browser was created; this response must be sent to client
    //        ads_session->dsc_transaction.m_send_header(ads_session->dsc_http_hdr_out.str_hdr_out,  ds_control::ien_st_body_sent_to_browser);
    //        if (str_html_to_browser.length() > 0) { // there is a message-body, which must be sent, too
    //            ads_session->dsc_transaction.m_send( str_html_to_browser, ds_control::ien_st_body_sent_to_browser );
    //        }
    //    }
 //       break;
    //}
    case ien_task_send_login_page: {
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI958I: ien_task_send_login_page" );

        /***********************************************************************************************/
        /* browser requested our login-page; setup the site with header, message and a blank username; */
        /***********************************************************************************************/
        // create the response: header+html-page, which is login-page or contains an error message
        ads_session->dsc_webserver.hstr_my_encoding = "text/html";
        ads_session->dsc_webserver.bo_compress_makes_sense = true;
        ads_session->dsc_webserver.m_file_proc( ads_session->dsc_webserver.ds_path, NULL );
        break;
    }
    case ien_task_send_requested_file: {
        //-------------------------------
        // read the file
        //-------------------------------
        // read extension of requested file to determine the content-type to respond
        ads_session->dsc_webserver.m_setup_encoding_string(ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_const_str());
        // read in file, its date, etc
        ads_session->dsc_webserver.m_file_proc(ads_session->dsc_webserver.ds_path, NULL);
        break;
    }
    default: {
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error, "HIWSE387E: Unknown task %d", in_task );
        break;
    }
    } // switch (in_task)

    return;
}


/*! \brief Checks, whether a url (usually delivered by webbrowser) starts with one of the aliases of the configured virtual links. If true, the according data will be returned.
 *
 * @ingroup creator
 *
 * private
 * @param[in]  ds_hstring* ahstr_url           Url to be tested (usually the url delivered by web browser).
 * @param[out] dsd_virtual_link* adsl_vir_lnk  Gets filled, when a virtual link (configured in wsp.xml) matches the directory-path
 *                                             of the url, which was delivered by webbrowser.
 * @return      bool true = A virtual link matches the directory-path; else false.
 */
const dsd_virtual_link* ds_control::m_check_virtual_link(const dsd_const_string& rdsp_url, dsd_const_string& rdsp_rest) {
    // Get the directory-part of the delivered url. That is the part before the second '/' (if exists).
    // Only search, if path is not empty and starts with '/'.
    dsd_const_string hstr_dir_part(rdsp_url);
    if ( (hstr_dir_part.m_get_len() > 0) && (hstr_dir_part.m_starts_with("/")) ) {
#if 0
        int in_pos = hstr_dir_part.m_last_index_of(hstr_dir_part.m_get_len()-1, "/");
        if ( (in_pos != -1)    // a second '/' was found -> the dir-path is the string before this '/'
        &&   (in_pos != 0) ) { // The slash at the start is the only one -> then we take the whole string.
            hstr_dir_part = hstr_dir_part.m_substring(0, in_pos);
        }
#endif
        // Loop through all aliases and compare with the delivered url.
        dsd_virtual_link* adsl_lnk_curr = ads_session->ads_config->adsl_vi_lnk;
        while (adsl_lnk_curr != NULL) {
            dsd_const_string dsl_alias(adsl_lnk_curr->ach_alias, adsl_lnk_curr->in_len_alias);
            if (hstr_dir_part.m_starts_with_ic(dsl_alias)) { // URL starts with this alias.
				dsd_const_string dsl_rest = hstr_dir_part.m_substring(dsl_alias.m_get_len());
				// Problem: The requested alias is "test-wfa". If there is another alias configured with alias "test", it will be used!
                // More sophisticated check: The character behind the alias must be a '/' or the url must end with the alias. Then the url matches the alias.
                if (dsl_rest.m_get_len() == 0 || dsl_rest.m_starts_with("/")) {
                    // Copy the data to the local structure.
					ads_session->ads_wsp_helper->m_logf(ied_sdh_log_info, "HIWSI235I: Virtual link detected with alias=%.*s url=%.*s",
                                                     adsl_lnk_curr->in_len_alias, adsl_lnk_curr->ach_alias,
                                                     adsl_lnk_curr->in_len_url, adsl_lnk_curr->ach_url);
					rdsp_rest = dsl_rest;
                    return adsl_lnk_curr;
                }
            }

            adsl_lnk_curr = adsl_lnk_curr->adsc_next;
        }
    }

    return NULL;
}


/*! \brief check if the given url ("http://localhost:8080/foo/bar/") is the full url of a virtual link
 *
 * @ingroup creator
 *
 * @param[in]   const char          *achp_url       pointer to url
 * @param[in]   int                 inp_length      length of url
 * @return      dsd_virtual_link                    NULL = url does not match virual link
 *                                                  found virtual link otherwise
 */
const dsd_virtual_link* ds_control::m_check_virtual_link_rev(const dsd_const_string& rdsp_url, dsd_const_string& rdsp_rest)
{
    struct dsd_virtual_link *adsl_cur;          /* current virtual link  */
    
    adsl_cur = ads_session->ads_config->adsl_vi_lnk;
    while ( adsl_cur != NULL ) {
        /*
            after reading from config the virtual link url always starts
            with a slash and ends without slash, while the incoming url
            should start without a slash and end with one
            -> length must be equal but while comparing, we need to ignore
               leading slash but check for on at the end
        */
		dsd_const_string dsl_vlink_url(adsl_cur->ach_url, adsl_cur->in_len_url);
		if(dsl_vlink_url.m_starts_with("/"))
			dsl_vlink_url = dsl_vlink_url.m_substring(1);
		if ( rdsp_url.m_starts_with(dsl_vlink_url) ) {
			dsd_const_string dsl_rest = rdsp_url.m_substring(dsl_vlink_url.m_get_len());
			if (dsl_rest.m_get_len() == 0
				|| dsl_rest.m_starts_with("/")
				|| dsl_rest.m_starts_with("?"))
			{
				rdsp_rest = dsl_rest;
				break;
            }
        }
        adsl_cur = adsl_cur->adsc_next;
    }
    return adsl_cur;
} /* end of ds_control::m_check_virtual_link_rev */


/*! \brief Checks, whether a browser request is for WebFileAccess
 *
 * @ingroup creator
 *
 * private
 * Checks, whether a browser request is for WebFileAccess. At first the passed virtual link (indeed the alias of it) gets investigated, then the url delivered by browser.
 * If one of these starts with HOBWEBFILEACCESS, it is a request for WFA. 
 * private function
 *
 * @param[in] dsd_virtual_link* adsl_vir_lnk  Its alias will get checked.
 * @return    bool true = A virtual link matches the directory-path; else false.
 */
bool ds_control::m_is_request_for_wfa(const dsd_virtual_link* adsl_vir_lnk) {
	if(!adsl_vir_lnk)
		return NULL;
    // The browser requested a virtual directory -> check, whether it is WFA.
    ds_hstring hstr_url(ads_session->ads_wsp_helper, adsl_vir_lnk->ach_alias, adsl_vir_lnk->in_len_alias);
    if (hstr_url.m_starts_with(HOBWEBFILEACCESS)) {
        // Url starts with HOBWEBFILEACCESS -> request is for WebFileAccess.
        return true;
    }
    
    // Check the original url.
    if (ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_starts_with(HOBWEBFILEACCESS)) {
        // Url starts with HOBWEBFILEACCESS -> request is for WebFileAccess.
        return true;
    }

    // Url does not start with HOBWEBFILEACCESS -> request is NOT for WebFileAccess.
    return false;
}

/**
 
*/
/*! \brief Checks if its a request for administration
 *
 * @ingroup creator
 *
 * private
 * Checks, whether a browser request is for global administration
 * extensions like RDVPNUpdater
 */
bool ds_control::m_is_request_for_globaladm(const dsd_virtual_link* adsp_vir_lnk)
{
	if(adsp_vir_lnk == NULL)
		return false;

    // The browser requested a virtual directory
    dsd_const_string hstr_url(adsp_vir_lnk->ach_alias, adsp_vir_lnk->in_len_alias);
    if ( hstr_url.m_starts_with(RDVPNUpdater) ) {
        return true;
    } else if ( hstr_url.m_starts_with(RDVPNDirectoryServices) ) {
        return true;
    } else if ( hstr_url.m_starts_with(RDVPNCertificateManager) ) {
        return true;
    } else if ( hstr_url.m_starts_with(RDVPNPluginManager) ) {
        return true;
    }

    // Check the original url.
	dsd_const_string hstr_url2(ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id);
    if ( hstr_url2.m_starts_with(RDVPNUpdater) ) {
        return true;
    } else if ( hstr_url2.m_starts_with(RDVPNDirectoryServices) ) {
        return true;
    } else if ( hstr_url2.m_starts_with(RDVPNCertificateManager) ) {
        return true;
    } else if ( hstr_url2.m_starts_with(RDVPNPluginManager) ) {
        return true;
    }
    return false;
}


/*! \brief Checks if WebServer Gate is enabled
 *
 * @ingroup creator
 *
 * private
 * return false, if one of the checks failed. In case of false a complete answer gets sent to browser inside this method.
 */
bool ds_control::m_is_wsg_enabled(bool bol_auth_header, bool bo_req_wfa) {
    // Check, whether WSG is enabled: general and for the particular user(in this case we forward the key word PORTLET_WEBSERVERGATE to the check routine)
    // Attention: If WebServerGate is disabled, WebFileAccess must be accessible, if desired!
    if (!bo_req_wfa) {
        // Request is NOT for WebFileAccess. It is a WSG request -> check whether WSG can be done
        if ( ads_session->dsc_auth.m_is_portlet_allowed(achg_known_portlets[ied_wsg_portlet]) == false ) {                  
            // Display error page to client
            ads_session->ads_wsp_helper->m_log(ied_sdh_log_warning, "HIWSE281E: Access denied to Web Server Gate.");
            ads_session->dsc_webserver.m_send_error_page( ds_http_header::ien_status_not_found, false,
                                                          MSG_NO_GATE, 0, 0 );
            // Attention: if there are more input-data (e.g. a POST for a webserver), these data must be marked as processed!
            // But how??!!  TODO (less priority)
            return false;
        }
    }

    // Attention: the following if-statement will usually not be reached, because "GET /HOB000000dgher.../http://www.google.de" will go
    // into ds_webserver and there the correct error message will be created and displayed
    if (!bol_auth_header) { // WSG only works with activated HTTP-cookies!! -> display an error page to user
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning, "HIWSE921E: WSG/WFA only works with activated HTTP-cookies!" );
        ads_session->dsc_webserver.m_send_error_page( ds_http_header::ien_status_ok, true,
                                                      MSG_ENABLE_COOKIE, ied_sdh_log_error, 921 );
        return false;
    }

#if !SM_USE_NEW_WSG
    // redirect the client, because server names must always be a director
    // example: Get /http://www.kbservices.com --> /http://www.kbservices.com/
	if (ads_session->dsc_http_hdr_in.dsc_url.in_hob_type != ds_http_header::ien_hobtype_ws
		&& ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_len() == 0)
	{
        // we must forward browser to address which is terminated by '/'. This is done via Location-header
        // Attention: if there was already a connection to a webserver in this TCP-session, our output (intended for the browser)
        // will be sent to the server. A solution would be to remember our output and let us be called by WSP in other direction.
        // Here we do another way: we close the connection to the webserver -> our output will be sent to client!!
#if 0
        if (ads_session->dsc_ws_gate.bo_connected) {
            ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning, "HIWSW049W: URL-path for WSG is empty -> close the connection and redirect" );
            ads_session->dsc_ws_gate.m_close_conn_to_ext_server();
        }
#endif
		// TODO: Can this be handled by WSG either during request or response?
        ds_hstring hstr_address(ads_session->ads_wsp_helper, "/wsg/");
        ds_hstring hstr_port(ads_session->ads_wsp_helper, ":"); // this string will be added to host, when port is not the default port
        hstr_port += ads_session->dsc_http_hdr_in.dsc_url.in_port_of_webserver;
        // don't send port-number, when a default port is requested
        int in_dest_port = ads_session->dsc_http_hdr_in.dsc_url.in_port_of_webserver;
        if ( (in_dest_port == 80) && (!ads_session->dsc_http_hdr_in.dsc_url.bo_ssl_to_ext_ws) ) {
            hstr_port.m_reset();
        }
        if ( (in_dest_port == 443) && (ads_session->dsc_http_hdr_in.dsc_url.bo_ssl_to_ext_ws) ) {
            hstr_port.m_reset();
        }
		hstr_address.m_write(ads_session->dsc_http_hdr_in.dsc_url.hstr_protocol);
        hstr_address.m_write("://");
        hstr_address += ads_session->dsc_http_hdr_in.dsc_url.hstr_hostname_of_webserver;
        hstr_address.m_write(hstr_port);
        hstr_address.m_write("/"); // that's the stuff: we want to add '/'

        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info, "HIWSW649W: URL without terminating '/' -> redirect to %s", hstr_address.m_get_ptr());

        // create the response (only header containing "Location moved"); don't forget the query if exists
        ds_hstring hstr_location = ads_session->dsc_webserver.m_create_location(hstr_address.m_const_str(),
            ads_session->dsc_http_hdr_in.dsc_url.hstr_query);
        dsd_const_string dsl_location(hstr_location.m_const_str());
        ads_session->dsc_webserver.m_create_resp_header(ds_http_header::ien_status_found, 0, &dsl_location, NULL, NULL, false, NULL);
        ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
		m_set_ctrl_state(ien_st_skip_message_body_of_request);
        return false;
    }
#endif

    return true;
}

/*! \brief Get language
 *
 * @ingroup creator
 *
 * get language
 */
int ds_control::m_get_lang()
{
    return in_cma_lang;
} // end of ds_control::m_get_lang


/*! \brief Check state
 *
 * @ingroup creator
 */
bool ds_control::m_check_state(int in_state)
{
    // check state:
	HL_DBG_PRINTF("ds_control::m_check_state: in_cma_state=%08X in_state=%08X\n", in_cma_state, in_state);
    if ( (in_cma_state & in_state) == in_state ) {
        return true;
    }
    return false;
} // end of ds_control::m_check_state


void ds_control::m_inject_authorization(
	 ds_hstring* ahstr_send_to_ws, const dsd_const_string& rdsp_field, const dsd_const_string& ahstr_authenticate)
{
	 dsd_tokenizer dsl_tok(ads_session->dsc_http_hdr_out.hstr_hdr_out.m_const_str(), CRLF);
	 while(true) {
		dsd_const_string dsl_line;
		bool bol_more_tokens = dsl_tok.m_next(dsl_line);
		//ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "XXX: dsl_line=%.*s", dsl_line.m_get_len(), dsl_line.m_get_ptr());
		if(dsl_line.m_starts_with(rdsp_field)) {
			goto LBL_NEXT;
		}
		if(dsl_line.m_get_len() <= 0)
			break;
		ahstr_send_to_ws->m_write(dsl_line);
		ahstr_send_to_ws->m_write(CRLF);
LBL_NEXT:
		if(!bol_more_tokens)
			break;
	 }

	 ahstr_send_to_ws->m_write(rdsp_field);
	 ahstr_send_to_ws->m_write(" ");
	 ahstr_send_to_ws->m_write(ahstr_authenticate);
	 ahstr_send_to_ws->m_write(CRLF);
	 ahstr_send_to_ws->m_write(CRLF);
}

/*! \brief
 *
 * @ingroup creator
 *
 * private
 * Create the whole http-header (no body), which shall be sent to external web server. This header is the header, which was
 * just sent to web server, plus the created header line 'Authorization: <base64 of username:password>'.
 * The global ds_hstring ads_session->hstr_authorization_basic is setup. It holds the value, which will be included
 * in former requests to the web server as 'Authorization' (when SSO will succeed).
 */
void ds_control::m_auth_basic(ds_hstring* ahstr_send_to_ws)
{
   // RFC 2617
   //Basic Authentication Scheme
   //The "basic" authentication scheme is based on the model that the client must authenticate itself with a user-ID and a password for
   //each realm.  The realm value should be considered an opaque string which can only be compared for equality with other realms on that
   //server. The server will service the request only if it can validate the user-ID and password for the protection space of the Request-URI.
   //There are no optional authentication parameters.
   //
   //For Basic, the framework above is utilized as follows:
   //   challenge   = "Basic" realm
   //   credentials = "Basic" basic-credentials
   //
   //Upon receipt of an unauthorized request for a URI within the protection space, the origin server MAY respond with a challenge like
   //the following:
   //   WWW-Authenticate: Basic realm="WallyWorld"
   //where "WallyWorld" is the string assigned by the server to identify the protection space of the Request-URI. A proxy may respond with the
   //same challenge using the Proxy-Authenticate header field.
   //
   //To receive authorization, the client sends the userid and password, separated by a single colon (":") character, within a base64
   //encoded string in the credentials.
   //   basic-credentials = base64-user-pass
   //   base64-user-pass  = <base64 [4] encoding of user-pass, except not limited to 76 char/line>
   //   user-pass   = userid ":" password
   //   userid      = *<TEXT excluding ":">
   //   password    = *TEXT
   //
   //Userids might be case sensitive.
   //
   //If the user agent wishes to send the userid "Aladdin" and password "open sesame", it would use the following header field:
   //   Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
   //
   //A client SHOULD assume that all paths at or deeper than the depth of the last symbolic element in the path field of the Request-URI also
   //are within the protection space specified by the Basic realm value of the current challenge. A client MAY preemptively send the
   //corresponding Authorization header with requests for resources in that space without receipt of another challenge from the server.
   //Similarly, when a client sends a request to a proxy, it may reuse a userid and password in the Proxy-Authorization header field without
   //receiving another challenge from the proxy server.

    // Insert user's credentials as 'Authorization: <base64 of username:password>' into the http-header, which shall be sent to external webserver.
    // We use the same header, which was previously sent to web server It is stored in ads_session->dsc_http_hdr_out.hstr_hdr_out and should have a certain minimum length.
    
	 ds_hstring hstr_credentials(ads_session->ads_wsp_helper);
    hstr_credentials.m_write(ads_session->dsc_auth.m_get_username());
    hstr_credentials.m_write(":");
    hstr_credentials.m_write(ads_session->dsc_auth.m_get_password());
    
    // Global string: Value for the header field HF_AUTHORIZATION. The according header line shall be inserted into all headers, which
    // are sent to the external webserver on this ds_session.
    ads_session->hstr_authorization_basic.m_reset();
    ads_session->hstr_authorization_basic.m_write(HFV_WWWAUTH_BASIC " ");
    ads_session->hstr_authorization_basic.m_write_b64(hstr_credentials.m_get_ptr(), hstr_credentials.m_get_len());

	 m_inject_authorization(ahstr_send_to_ws, HF_AUTHORIZATION ":", ads_session->hstr_authorization_basic.m_const_str());
} // end of ds_control::m_auth_basic


/*! \brief Creates SPNEGO token
 *
 * @ingroup creator
 *
 * Create the SPNEGO token, which shall be sent to web server.
 *
 * @param[in] bo_init true: create a negTokenInit. false: create a negTokenResp.
 * @param[out] ahstr_nego_token Filled with the created token. The token is base64-encoded.
 * @param[in] inl_mechtypes Which MechTypes are added into MechTypesList (defined as ds_control::nego_mechtypes):
 *     ien_nego_mech_kerb5   = 1 = Kerberos v5;
 *     ien_nego_mech_kerb_ms = 2 = Microsoft-Kerberos.
 *     Values can be ORed if bol_include_optimistic_token is false.
 * @param[in] bol_include_optimistic_token true: Request a 'ServiceTicket' from KDC and add it to the token. We ALWAYS request a new TGS, because sending the same TGS each time did not work.
 *                                         false: The created token will contain only the available mechanisms 'Kerberos v5' and 'Microsoft-Kerberos'.
 *                                         This flag is only of interest, if bo_init is true.
 * @return SUCCESS (=0), if successful; otherwise an error number.
 */

int ds_control::m_create_nego_token(bool bo_init, ds_hstring* ahstr_nego_token, NEGO_MECHTYPES inl_mechtypes, bool bol_include_optimistic_token) {
    if ( (inl_mechtypes <= ien_nego_mech_invalid) || (inl_mechtypes > ien_nego_mech_max) ) {
        return 1;
    }

    ds_spnego dsl_spnego;
    dsl_spnego.m_init(ads_session->ads_wsp_helper);
    SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle;
    SPNEGO_MECH_OID dsl_mech_type = ien_spnego_mech_oid_not_used;
    dsd_const_string hstr_mechtypes;
    if (inl_mechtypes == ien_nego_mech_kerb5) {
        dsl_mech_type = ien_spnego_mech_oid_kerberos_v5;
        hstr_mechtypes = "Kerberos v5";
    }
    else if (inl_mechtypes == ien_nego_mech_kerb_ms) {
        dsl_mech_type = ien_spnego_mech_oid_kerberos_v5_legacy;
        hstr_mechtypes = "Kerberos Microsoft";
    }
    else if (inl_mechtypes == (ien_nego_mech_kerb5 | ien_nego_mech_kerb_ms)) {
        hstr_mechtypes = "Kerberos v5 and Kerberos Microsoft";
    }
    ads_session->ads_wsp_helper->m_logf(ied_sdh_log_info,
        "HIWSI287I: SPNEGO: Create a NegoToken with MechType %.*s. Init %d. OptimisticToken %d.",
        hstr_mechtypes.m_get_len(), hstr_mechtypes.m_get_ptr(), bo_init, bol_include_optimistic_token);

    // Ensure, that the string is empty.
    ahstr_nego_token->m_reset();

    if (bo_init) {
        //------------------------
        // Create a negTokenInit
        //------------------------
        if (bol_include_optimistic_token) {
            //--------------------------------
            // Send the optimistic token, too
            //--------------------------------
            if (inl_mechtypes == (ien_nego_mech_kerb5 | ien_nego_mech_kerb_ms)) {
                // The SPNEGO-LIB allows only ONE MechType to be set !! We use Kerberos_v5 as default.
                dsl_mech_type = ien_spnego_mech_oid_kerberos_v5;
                if ((ads_session->ads_config->in_settings & SETTING_AUTH_NEGO_USE_MS_KERB) != 0) {
                    dsl_mech_type = ien_spnego_mech_oid_kerberos_v5_legacy; // Use Microsoft's Kerberos OID (1.2.840.48018.1.2.2) instead of MIT Kerberos v5 (1.2.840.113554.1.2.2).
                }
                ads_session->ads_wsp_helper->m_logf(ied_sdh_log_info, "HIWSI087I: SPNEGO: MechType was ambigous. Set to %d.", dsl_mech_type);
            }

            // Request a service ticket from KDC.
            ds_hstring hstr_service_ticket(ads_session->ads_wsp_helper, MAX_KRB5_SE_TI);
            int inl_ret = m_get_kerb_service_ticket(&hstr_service_ticket);
            if (inl_ret != SUCCESS)  {
                ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE356E: SPNEGO: Retrieving a Kerberos service ticket failed with error %d.", inl_ret);
                return 3;
            }

            // melzeraa-3 will respond a 'reject' if ien_spnego_mech_oid_kerberos_v5_legacy is used!
            inl_ret = dsl_spnego.m_spnego_create_neg_token_init(dsl_mech_type,
                                        0, // SPNEGO_NEGINIT_CONTEXT_DELEG_FLAG
                                        (unsigned char *)hstr_service_ticket.m_get_ptr(), hstr_service_ticket.m_get_len(),  // NULL, 0L,  
                                        NULL, 0L, &dsl_spnego_token_handle);
            if (inl_ret != SUCCESS)  {
                ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE355E: SPNEGO: Creation of NegInitToken failed with error %d.", inl_ret);
                return 4;
            }

            // The SPNEGO data must be sent as base64.
            ahstr_nego_token->m_write_b64((const char*)((SPNEGO_TOKEN*)dsl_spnego_token_handle)->auc_binary_data, ((SPNEGO_TOKEN*)dsl_spnego_token_handle)->ul_binary_data_len);

            dsl_spnego.m_spnego_free_data(dsl_spnego_token_handle);

            return SUCCESS;
        }

        //--------------------------------
        // NO optimistic token shall be sent.
        // Only propose the available MechTypes to the web server
        //--------------------------------
        if (inl_mechtypes == (ien_nego_mech_kerb5 | ien_nego_mech_kerb_ms)) {
            // SPNEGO-LIB does not support a MechTypeList of more than one element. Therefore we do it hardcoded.
            unsigned char ucr_nego_init_mechlist[] = {
                0x60, 0x26,                                                         // Application Constructed Object, length 0x26
                0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02,                     // SPNEGO OID
                0xa0, 0x1C,                         	                            // NegTokenInit (0xa0), length 0x1C
                0x30, 0x1A,                	                                        // Constructed Sequence, length 0x1A
                0xA0, 0x18,                                                         // Seq. Element 0, MechTypeList, length 0x18
                0x30, 0x16,	                                                        // Sequence length 0x16
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,   // Kerberos V5 OID
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02    // Microsoft Kerberos OID            
            };
            // The SPNEGO data must be sent as base64.
            ahstr_nego_token->m_write_b64((const char*)&ucr_nego_init_mechlist, sizeof(ucr_nego_init_mechlist));
            return SUCCESS;
        }

        // melzeraa-3 will respond a 'reject' if ien_spnego_mech_oid_kerberos_v5_legacy is uesd!
        int inl_ret = dsl_spnego.m_spnego_create_neg_token_init(dsl_mech_type,
                                    0,
                                    NULL, 0L,  
                                    NULL, 0L, &dsl_spnego_token_handle);
        if (inl_ret != SUCCESS)  {
            ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE155E: SPNEGO: Creation of NegInitToken failed with error %d.", inl_ret);
            return 5;
        }

        // The SPNEGO data must be sent as base64.
        ahstr_nego_token->m_write_b64((const char*)((SPNEGO_TOKEN*)dsl_spnego_token_handle)->auc_binary_data, ((SPNEGO_TOKEN*)dsl_spnego_token_handle)->ul_binary_data_len);

        dsl_spnego.m_spnego_free_data(dsl_spnego_token_handle);
        return SUCCESS;
    }

    //---------------------------
    // Create a negTokenTarg
    //---------------------------
    if (inl_mechtypes == (ien_nego_mech_kerb5 | ien_nego_mech_kerb_ms)) {
        // MechType must not be ORed.
        return 20;
    }

    // Request a service ticket from KDC.
    ds_hstring hstr_service_ticket(ads_session->ads_wsp_helper, MAX_KRB5_SE_TI);
    int inl_ret = m_get_kerb_service_ticket(&hstr_service_ticket);
    if (inl_ret != SUCCESS)  {
        ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE856E: SPNEGO: Retrieving a Kerberos service ticket failed with error %d.", inl_ret);
        return 21;
    }
    
    inl_ret = dsl_spnego.m_spnego_create_neg_token_targ(dsl_mech_type, (SPNEGO_NEGRESULT)0,
                                        (unsigned char *)hstr_service_ticket.m_get_ptr(), hstr_service_ticket.m_get_len(), 
                                        NULL, 0L, &dsl_spnego_token_handle);
    if (inl_ret != SUCCESS)  {
        ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE855E: SPNEGO: Creation of NegTokenResp failed with error %d.", inl_ret);
        return 22;
    }

    // The SPNEGO data must be sent as base64.
    ahstr_nego_token->m_write_b64((const char*)((SPNEGO_TOKEN*)dsl_spnego_token_handle)->auc_binary_data, ((SPNEGO_TOKEN*)dsl_spnego_token_handle)->ul_binary_data_len);

    dsl_spnego.m_spnego_free_data(dsl_spnego_token_handle);
    return SUCCESS;
}

/*! \brief Authentication Negotiation
 *
 * @ingroup creator
 *
 * private
 * Create the whole http-header (and the body, if exists), which shall be sent to external web server. This header
 * is the header, which was just sent to web server, plus the created header line 'Authorization: Negotiate <base64 SPNEGO>'.
 */
void ds_control::m_auth_negotiate(ds_hstring* ahstr_send_to_ws, const ds_hstring* ahstr_negotiate_b64) {
    ds_hstring hstr_authorization(ads_session->ads_wsp_helper);
    hstr_authorization.m_write(HFV_WWWAUTH_NEGOTIATE " ");
    hstr_authorization.m_write(ahstr_negotiate_b64);

	 m_inject_authorization(ahstr_send_to_ws, HF_AUTHORIZATION ":", hstr_authorization.m_const_str());

	 // Get a copy of the http-header (and data), which was sent first to external webserver. This header (and data) will be sent to external web server again, when the Negotiate failed.
    ads_session->hstr_data_to_ext_ws_before_negotiate.m_set(ads_session->dsc_http_hdr_out.hstr_hdr_out);
    // If there was data for the webserver, send them and store them, too.
    ads_session->hstr_data_to_ext_ws_before_negotiate.m_write(ads_session->hstr_data_last_request);
}

/*! \brief Get Kerberos service ticket
 *
 * @ingroup creator
 *
 * private
 */
int ds_control::m_get_kerb_service_ticket(ds_hstring* ahstr_service_ticket) {
    // Read the server name from the used URL.
    // The authority could be "hobrd.hob.de:8088". We must cut the port, if it exists.
	dsd_const_string hstr_authority(ads_session->dsc_ws_gate.dsc_url.hstr_authority_of_webserver);
    // TODO: Use IP-Address parser
	int in_pos = hstr_authority.m_find_first_of(":");
    if (in_pos >= 0) {
        hstr_authority = hstr_authority.m_substring(0, in_pos); // cut out port
    }

    // Compose the service name.
    ds_hstring hstr_service_name(ads_session->ads_wsp_helper);
    hstr_service_name.m_write("HTTP/");
    hstr_service_name.m_write(hstr_authority);

    // Setup the structure, which shall be passwed to WSP.
    struct dsd_aux_krb5_se_ti_get_1 dsl_aux_krb5_se_ti_get_1;
    memset(&dsl_aux_krb5_se_ti_get_1, 0, sizeof(struct dsd_aux_krb5_se_ti_get_1));
    dsl_aux_krb5_se_ti_get_1.dsc_server_name.ac_str      = const_cast<char*>(hstr_service_name.m_get_ptr());
    dsl_aux_krb5_se_ti_get_1.dsc_server_name.imc_len_str = hstr_service_name.m_get_len();
    dsl_aux_krb5_se_ti_get_1.dsc_server_name.iec_chs_str = ied_chs_utf_8;

    // JF 01.06.10: Up to now imc_options is not investigated by WSP::xs-gw-krb5-control.cpp. Mutual authentication is ALWAYS requested.
    if ((ads_session->ads_config->in_settings & SETTING_KERB5_NO_MUTUAL) != 0) {
        // Mutual authentication is not requested.
        dsl_aux_krb5_se_ti_get_1.imc_options = 2; // defined as wsp\src\xs-gw-krb5-control.cpp::NO_AP_OPTS_MUTUAL_REQUIRED_e 
    }
    else { // Mutual authentication required.
        dsl_aux_krb5_se_ti_get_1.imc_options = 1; // defined as wsp\src\xs-gw-krb5-control.cpp::AP_OPTS_MUTUAL_REQUIRED_e; 
    }

    char byr_service_ticket[MAX_KRB5_SE_TI];
    dsl_aux_krb5_se_ti_get_1.achc_ticket_buffer    = byr_service_ticket; // Buffer for service ticket
    dsl_aux_krb5_se_ti_get_1.imc_ticket_buffer_len = MAX_KRB5_SE_TI;             // Maximum length for Kerberos 5 Service Ticket

    ads_session->ads_wsp_helper->m_logf2(ied_sdh_log_info, "HIWSI182I: Retrieving a Kerberos service ticket for server %(ucs)s.", 
        &dsl_aux_krb5_se_ti_get_1.dsc_server_name);
    bool bol = ads_session->ads_wsp_helper->m_cb_krb5_get_service_ticket(&dsl_aux_krb5_se_ti_get_1);
    if (!bol || (dsl_aux_krb5_se_ti_get_1.iec_ret_krb5 != ied_ret_krb5_ok) ) {
        ds_hstring hstr_human_readable_err(ads_session->ads_wsp_helper, ""); // JF 22.03.11 Give user a human-readable error string.
        switch (dsl_aux_krb5_se_ti_get_1.iec_ret_krb5) {
        case ied_ret_krb5_kdc_not_conf:
            hstr_human_readable_err.m_write("KDC not configured");
            break;
        case ied_ret_krb5_kdc_not_sel:
            hstr_human_readable_err.m_write("KDC not selected");
            break;
        case ied_ret_krb5_no_sign_on:
            hstr_human_readable_err.m_write("session not signed on");
            break;
        case ied_ret_krb5_kdc_inv:
            hstr_human_readable_err.m_write("KDC invalid");
            break;
        case ied_ret_krb5_userid_unknown:
            hstr_human_readable_err.m_write("Userid unknown");
            break;
        case ied_ret_krb5_password:
            hstr_human_readable_err.m_write("password invalid");
            break;
        case ied_ret_krb5_no_tgt:
            hstr_human_readable_err.m_write("TGT not found");
            break;
        case ied_ret_krb5_buf_too_sm:
            hstr_human_readable_err.m_write("buffer size is too small");
            break;
        case ied_ret_krb5_decrypt_err:
            hstr_human_readable_err.m_write("decryption error");
            break;
        case ied_ret_krb5_kdc_not_found:
            hstr_human_readable_err.m_write("previously used KDC not found");
            break;
        case ied_ret_krb5_conf_already_set:
            hstr_human_readable_err.m_write("KDC already set");
            break;
        case ied_ret_krb5_not_mult_conf:
            hstr_human_readable_err.m_write("not multiple KDC configured");
            break;
        case ied_ret_krb5_misc:
            hstr_human_readable_err.m_write("miscellaneous error");
            break;
        }
        ads_session->ads_wsp_helper->m_logf2(ied_sdh_log_warning, "HIWSE549E: Getting a service ticket for server %(ucs)s failed with error %d (%.*s).",
            &dsl_aux_krb5_se_ti_get_1.dsc_server_name,
            dsl_aux_krb5_se_ti_get_1.iec_ret_krb5,
            hstr_human_readable_err.m_get_len(), hstr_human_readable_err.m_get_ptr());
        return 1;
    }

    ads_session->vpc_krb5_handle = dsl_aux_krb5_se_ti_get_1.vpc_handle;  // Kerberos handle

    ahstr_service_ticket->m_set(dsl_aux_krb5_se_ti_get_1.achc_ticket_buffer, dsl_aux_krb5_se_ti_get_1.imc_ticket_length);

    return SUCCESS;
} // end of  ds_control::m_get_kerb_service_ticket


/*! \brief Read data from webserver
 *
 * @ingroup creator
 *
 * private
 * Read all data from web server.
 * Attention: Perhaps not all data are received (e.g. a very long html page is delivered).
 */
int ds_control::m_read_complete_ws() {
    // If we already have completly read, we would get stuck, when we do it again!!
    if (bo_read_complete) {
        return 2;
    }

    // We use m_handle_response_data() to read all data, but we set a flag, that no data shall be sent to client. The flag
    // ien_ct_not_set avoids calls to the interpreter classes.
	 ads_session->dsc_ws_gate.bo_skip_response_data = true;
    int inl_ret = ads_session->dsc_ws_gate.m_handle_response_data(bo_data_until_close, false);
    if (inl_ret == 0) { // wait for more data (0 means: more data outstanding; because we don't know the data-end!)
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI675I: not all response data available or data end is not known. Wait for all data." );
        return inl_ret;
    }
    if (inl_ret < 0) { // error
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error, "HIWSE612E: error in ds_ws_gate::m_handle_response_data: %d.", inl_ret);
        return inl_ret;
    }

    bo_read_complete = true;

    // When we get here, the whole response by the external web server is received.
    return inl_ret;
}


/*! \brief Read negotiation value
 *
 * @ingroup creator
 *
 * private
 * Read the value of WWW-Authenticate: Negotiate <value>
 */
int ds_control::m_read_nego_token_from_ws(ds_spnego_reader* adsl_spnego_reader) {
    int in_size_auth_meth = (int)ads_session->dsc_http_hdr_in.ds_v_hf_www_authenticate.m_size();
    if (in_size_auth_meth < 1) {
        return 1;
    }
    
    // Find the correct header (value starts with HFV_WWWAUTH_NEGOTIATE) and read its value.
    for (HVECTOR_FOREACH(ds_hstring, adsl_cur, ads_session->dsc_http_hdr_in.ds_v_hf_www_authenticate)) {
        const ds_hstring& hstr_value = HVECTOR_GET(adsl_cur);
        dsd_const_string dsl_negotiate(HFV_WWWAUTH_NEGOTIATE);
        if (!hstr_value.m_starts_with_ic(dsl_negotiate)) {
            continue;
        }

        // Read the value.
        dsd_const_string hstr_nego_response_b64 = hstr_value.m_substring(dsl_negotiate.m_get_len());
        hstr_nego_response_b64.m_trim(" ");
        if (hstr_nego_response_b64.m_get_len() < 1) { // Empty string -> error.
            return 2;
        }

        // The response data are in base64 -> decode it.
        ds_hstring hstr_nego_response(ads_session->ads_wsp_helper);
        if(!hstr_nego_response.m_from_b64(hstr_nego_response_b64.m_get_start(), hstr_nego_response_b64.m_get_len())) {
            ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE550E: Decoding the SPNEGO token failed");
            return 3;
        }   

        // Convert the string into a class.
        int inl_ret = adsl_spnego_reader->m_parse((unsigned char*)hstr_nego_response.m_get_ptr(), hstr_nego_response.m_get_len());
        if (inl_ret != SUCCESS) {
            ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE550E: Parsing the SPNEGO token failed with error %d.", inl_ret);
            return 3;
        }

        return SUCCESS;
    } // for

    // When we get here, we did not find the expected header.
    return 10;
}

/*! \brief Cancels negotiation
 *
 * @ingroup creator
 *
 * private
 * 'Negotiate' failed. We send the original request to the external web server.
 * We will not try SSO on this session any more.
 * inl_err_idx shall help to detect from where this method was called
 */

int ds_control::m_cancel_negotiate(int inl_err_idx) {
    ads_session->ads_wsp_helper->m_logf(ied_sdh_log_info, "HIWSI312I: Negotiation terminated with error index %d. Receive all outstanding data. Then send original request to webserver.", inl_err_idx);
    
    // Read all outstanding data, so these will not disturb the next communication.
    // Perhaps not all data are received (e.g. a very long html page is delivered). Ensure, that all data from external WS are read.
    int inl_ret = m_read_complete_ws();
	 if (inl_ret <= 0) {
        // Error or more data must be read.
        return inl_ret;
    }

    // Send the original request to external web server.
    ads_session->ads_wsp_helper->m_log ( ied_sdh_log_info, "HIWSI650I: Original request shall be sent to external webserver." );

    bool bo_ret = ads_session->ads_wsp_helper->m_send_data(ads_session->hstr_data_to_ext_ws_before_negotiate.m_get_ptr(),
                                                           ads_session->hstr_data_to_ext_ws_before_negotiate.m_get_len(),
                                                           ied_sdh_dd_toserver);
    if (bo_ret == false) {
        ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE751E: Sending to external webserver failed.");
        // WHAT TO DO ??
		  return -1;
    }
#if 0
    ads_session->dsc_transaction.m_mark_as_processed(NULL);
#endif
    m_set_ctrl_state(ien_st_body_sent_to_server);
    ads_session->in_state_auth_negotiate = ds_session::ien_st_auth_nego_not_active;
    return 1;
}


/*! \brief Check Kerberos mutual authentication
 *
 * @ingroup creator
 *
 * private
 * Kerberos required mutual authentication. Pass the web server's response token to WSP, which shall investigate it.
 *
 * @param[in] ahstr_resp_token The response token to be investigated.
 * @return SUCCESS (=0), if successful; otherwise an error number.
 */
int ds_control::m_check_kerb_mutual_auth(const dsd_const_string& rdsp_resp_token) {
    dsd_aux_krb5_se_ti_c_r_1 dsl_check_mutual;
    memset(&dsl_check_mutual, 0, sizeof(struct dsd_aux_krb5_se_ti_c_r_1));
    dsl_check_mutual.achc_response_buffer = const_cast<char*>(rdsp_resp_token.m_get_ptr());
    dsl_check_mutual.imc_response_length  = rdsp_resp_token.m_get_len();
    dsl_check_mutual.vpc_handle           = ads_session->vpc_krb5_handle;

    ads_session->ads_wsp_helper->m_log(ied_sdh_log_info, "HIWSI082I: Check mutual authentication.");
    bool bol = ads_session->ads_wsp_helper->m_cb_krb5_check_service_ticket_response(&dsl_check_mutual);
    if (!bol || (dsl_check_mutual.iec_ret_krb5 != ied_ret_krb5_ok) ) {
        ads_session->ads_wsp_helper->m_logf(ied_sdh_log_warning, "HIWSE349E: Checking mutual authentication failed with %d.",
            dsl_check_mutual.iec_ret_krb5);
        return 1;
    }

    return SUCCESS;
}
