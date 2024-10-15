#include "../ds_session.h"
#include "ds_ws_gate.h"
#include "../ds_url_parser.h"
#include "./interpreter/ds_interpret_css.h"
#include "./interpreter/ds_interpret_script.h"
#include "./interpreter/ds_interpret_html.h"
#include "./interpreter/ds_interpret_xml.h"
#include "../portal/hob-postparams.h"
#include <ds_bookmark.h>
#include <dsd_wfa_bmark.h>
#include <hob-libwspat.h>
#include <ds_xml.h>
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H



#define TIME_TO_SUPPRESS_SSO     15     // seconds

static const char *achs_wfa_commands[] = {
    "add",
    "remove"
};

/*+-------------------------------------------------------------------------+*/
/*| constructor:                                                            |*/
/*+-------------------------------------------------------------------------+*/

/**
 *
 * @ingroup webservergate
 *
*/
ds_ws_gate::ds_ws_gate(void)
: bo_connected(false)
, bo_do_sso(false)
, bo_ignore_interpreter(false)
, dsc_interpret_html()
, dsc_interpret_xml()
, dsc_interpret_css()
, dsc_interpret_script()
, dsc_interpret_ica()
, dsc_interpret_pass()
, adsc_interpreter(NULL)
, in_len_to_send_unchanged_to_server(0)
, boc_websocket_upgrade(false)
, boc_websocket_protocol(false)
, boc_interpret_failed(false)
, bo_skip_response_data(false)
, boc_keep_alive(false)

// private members
, ads_session(NULL)
, in_len_to_send_unchanged_to_browser(0)
{
}

/*+-------------------------------------------------------------------------+*/
/*| destructor:                                                             |*/
/*+-------------------------------------------------------------------------+*/

/**
 *
 * @ingroup webservergate
 *
*/
ds_ws_gate::~ds_ws_gate(void)
{
}

/*+-------------------------------------------------------------------------+*/
/*| functions:                                                              |*/
/*+-------------------------------------------------------------------------+*/

/**
 * @ingroup webservergate
 *
 * @param [in]   ads_session_in	A pointer to the input session class (ds_session)
 *
 * @return	TRUE
 *
*/
bool ds_ws_gate::m_init( ds_session* ads_session_in )
{
    ads_session = ads_session_in;

    if ((ads_session->ads_config->in_settings & SETTING_DISABLE_COOKIE_STORAGE) == 0) {
        dsc_ck_manager.m_init( ads_session->ads_wsp_helper,
                               ((ads_session->ads_config->in_flags & FLAG_TRACE_COOKIES) != 0) );
    }

    hstr_last_ws_str_host.m_init(ads_session->ads_wsp_helper);
	hstr_hdrline_cookie.m_init(ads_session->ads_wsp_helper);
	hstr_prot_authority_ext_ws.m_init(ads_session->ads_wsp_helper);

    return true;
} // end of ds_ws_gate::m_init

/**
 *
 * @ingroup webservergate
 *
 * @return      TRUE
 *
*/
bool ds_ws_gate::m_setup()
{
    // MJ 03.06.08, Ticket [14905]:
    if ((ads_session->ads_config->in_settings & SETTING_DISABLE_COOKIE_STORAGE) == 0) {
        dsc_ck_manager.m_init( ads_session->ads_wsp_helper,
                               ((ads_session->ads_config->in_flags & FLAG_TRACE_COOKIES) != 0) );
    }
    return true;
}

static bool m_create_normalized_url(const ds_url::dsd_base_url& rdsp_url,
							 const ds_url::dsd_base_url& rdsp_base_url,
							 ds_url::dsd_base_url& rdsp_out,
							 ds_hstring& rdsp_tmp_out)
{
	ds_url::m_make_absolute_url(rdsp_url, rdsp_base_url, rdsp_out);
	if(rdsp_out.dsc_path.m_starts_with("/") || rdsp_out.dsc_path.m_starts_with("\\")) {
		return true;
	}
	rdsp_tmp_out.m_reset();
	rdsp_tmp_out.m_write(rdsp_base_url.dsc_path);
	rdsp_tmp_out.m_write(rdsp_out.dsc_path);
	rdsp_out.dsc_path = rdsp_tmp_out.m_const_str();
	return true;
}

int m_parse_url_port(const dsd_const_string& rdsp_port, int inp_default) {
	if (rdsp_port.m_get_len() > 0) {  // port number is set in URL -> convert to integer
        int inl_port;
		if (!rdsp_port.m_parse_int(&inl_port)) {
            //ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
            //                                        "HIWSE337E: Invalid port-number in URL: %.*s",
            //                                        dsc_url.hstr_url_no_id.m_get_len(), dsc_url.hstr_url_no_id.m_get_ptr() );
            return -1;
        }
        if ( (inl_port < 1) || (inl_port > 65535)) {
            //ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
            //                                        "HIWSE338E: Invalid port-number in URL: %.*s",
            //                                        dsc_url.hstr_url_no_id.m_get_len(), dsc_url.hstr_url_no_id.m_get_ptr() );
            return -1;
        }
		return inl_port;
    }
    // no port number in URL -> set the default values
    return inp_default;
}

static bool m_init_from_base(ds_url::dsd_base_url& rdsp_base_url, ds_ws_gate::dsd_wsg_url& rdsp_wsg_url) {
	dsd_const_string hstr_protocol = rdsp_base_url.dsc_protocol;
	rdsp_wsg_url.hstr_protocol = hstr_protocol;
	if(hstr_protocol.m_equals_ic("http") || hstr_protocol.m_equals_ic("ws")) {
		rdsp_wsg_url.bo_ssl_to_ext_ws = false;
	}
	else if(hstr_protocol.m_equals_ic("https") || hstr_protocol.m_equals_ic("wss")) {
		rdsp_wsg_url.bo_ssl_to_ext_ws = true;
	}
	else {
		return false;
	}
	const char* achl_start = rdsp_base_url.dsc_user.m_get_start();
	if(achl_start == NULL)
		achl_start = rdsp_base_url.dsc_host.m_get_start();
	const char* achl_end = rdsp_base_url.dsc_host.m_get_end();
	rdsp_wsg_url.hstr_authority_of_webserver = dsd_const_string(achl_start, achl_end-achl_start);
	rdsp_wsg_url.hstr_hostname_of_webserver = rdsp_base_url.dsc_hostname;
	if(rdsp_base_url.dsc_port.m_get_len() > 0) {
		rdsp_wsg_url.in_port_of_webserver = m_parse_url_port(rdsp_base_url.dsc_port, -1);
		if(rdsp_wsg_url.in_port_of_webserver < 0)
			return false;
		rdsp_wsg_url.hstr_port_of_webserver = rdsp_base_url.dsc_port;
	}
	else {
		if(rdsp_wsg_url.bo_ssl_to_ext_ws) {
			rdsp_wsg_url.in_port_of_webserver = 443;
			rdsp_wsg_url.hstr_port_of_webserver = "443";
		}
		else {
			rdsp_wsg_url.in_port_of_webserver = 80;
			rdsp_wsg_url.hstr_port_of_webserver = "80";
		}
	}
	rdsp_wsg_url.hstr_path = rdsp_base_url.dsc_path;
	return true;
}

bool ds_ws_gate::m_resolve_wsg_encoding(ds_url::dsd_base_url& rdsp_base_url_out, const dsd_const_string& rdsp_base_path, const dsd_const_string& rdsp_file_path, ds_hstring& rdsp_temp) {
	dsd_const_string dsl_token("/:WSG:");
	int inl_base_url_token = rdsp_file_path.m_index_of(dsl_token);
	if(inl_base_url_token >= 0) {
	//if(rdsp_file_path.m_starts_with(dsl_token)) {
		dsd_const_string dsl_path_base1 = rdsp_file_path.m_substring(0, inl_base_url_token+1);
		//dsd_const_string dsl_path4 = dsl_path.m_substring(inl_base_url_token+1);
		//
		dsd_const_string dsl_path4 = rdsp_file_path.m_substring(inl_base_url_token+dsl_token.m_get_len());
		int inl_next = dsl_path4.m_index_of("/");
		if(inl_next < 0)
			return false;
		dsd_const_string dsl_dir = dsl_path4.m_substring(0, inl_next);
		dsd_const_string dsl_file = dsl_path4.m_substring(inl_next);
		ds_hstring dsl_temp_dir(ads_session->ads_wsp_helper);
		if(!dsl_temp_dir.m_from_rfc3548(dsl_dir.m_get_ptr(), dsl_dir.m_get_len())) {
			return false;
		}
		//dsl_temp_dir.m_write("/");
		ds_url::dsd_base_url dsl_base_url3;
		ds_hstring dsl_temp2(ads_session->ads_wsp_helper);
		if(!m_resolve_wsg_encoding(dsl_base_url3, dsl_temp_dir.m_const_str(), dsl_file, dsl_temp2)) {
			return false;
		}
		ds_url::dsd_base_url dsl_base_url_path2;
		ds_hstring dsl_temp(ads_session->ads_wsp_helper);
		dsl_temp.m_write(rdsp_base_path);
		dsl_temp.m_write(dsl_path_base1);
		dsl_temp.m_replace_char('\\', '/', 0);
		if(!ds_url::m_parse_base_url(dsl_temp.m_const_str(), dsl_base_url_path2)) {
			return false;
		}
		ds_hstring dsl_temp3(ads_session->ads_wsp_helper);
		if(!m_create_normalized_url(dsl_base_url3, dsl_base_url_path2, rdsp_base_url_out, dsl_temp3)) {
			return false;
		}
		ds_url::m_write_base_url(rdsp_base_url_out, rdsp_temp);
	}
	else {
		rdsp_temp.m_write(rdsp_base_path);
		rdsp_temp.m_write(rdsp_file_path);
		rdsp_temp.m_replace_char('\\', '/', 0);
	}
	if(!ds_url::m_parse_base_url(rdsp_temp.m_const_str(), rdsp_base_url_out)) {
		return false;
	}
	return true;
}

bool ds_ws_gate::m_parse_wsg_url(const dsd_const_string& rdsp_resource, ds_ws_gate::dsd_wsg_url& rdsp_wsg_url) {
	const dsd_const_string hstrl_wsg_path("/wsg/");
	this->adsc_virtual_link = NULL;
	if(!rdsp_resource.m_starts_with(hstrl_wsg_path)) {
		dsd_const_string dsl_vlink_rest;
		this->adsc_virtual_link = this->ads_session->dsc_control.m_check_virtual_link(
			ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_const_str(), dsl_vlink_rest);
		if(this->adsc_virtual_link != NULL) {
			rdsp_wsg_url.iec_request_type = ien_request_type_vlink;
			rdsp_wsg_url.hstr_temp_path1.m_setup(ads_session->ads_wsp_helper);
			dsd_const_string hstr_vlink_url(this->adsc_virtual_link->ach_url, this->adsc_virtual_link->in_len_url);
			if(hstr_vlink_url.m_starts_with("/"))
				hstr_vlink_url = hstr_vlink_url.m_substring(1);
			rdsp_wsg_url.hstr_temp_path1.m_write(hstr_vlink_url);
			rdsp_wsg_url.hstr_temp_path1.m_write(dsl_vlink_rest);
			ds_url::dsd_base_url dsl_vlink_url;
			if(!ds_url::m_parse_base_url(rdsp_wsg_url.hstr_temp_path1.m_const_str(), dsl_vlink_url)) {
				return false;
			}
			if(!m_init_from_base(dsl_vlink_url, rdsp_wsg_url))
				return false;
			rdsp_wsg_url.in_hob_type = ien_hobtype_none;
			rdsp_wsg_url.hstr_query = ads_session->dsc_http_hdr_in.dsc_url.hstr_query;
			return true;
		}
		rdsp_wsg_url.iec_request_type = ien_request_type_unknown;
		return true;
	}
	dsd_const_string hstr_url = rdsp_resource.m_substring(hstrl_wsg_path.m_get_len());

	if(hstr_url.m_starts_with("http:/")) {
		if(!hstr_url.m_starts_with("http://")) {
			int a = 0;
			this->dsc_url.hstr_url_patch.m_init(this->ads_session->ads_wsp_helper);
			this->dsc_url.hstr_url_patch = "http://";
			this->dsc_url.hstr_url_patch += hstr_url.m_substring(6);
			hstr_url = this->dsc_url.hstr_url_patch.m_const_str();
		}
	}
	else if(hstr_url.m_starts_with("https:/")) {
		if(!hstr_url.m_starts_with("https://")) {
			int a = 0;
			this->dsc_url.hstr_url_patch.m_init(this->ads_session->ads_wsp_helper);
			this->dsc_url.hstr_url_patch = "http://";
			this->dsc_url.hstr_url_patch += hstr_url.m_substring(7);
			hstr_url = this->dsc_url.hstr_url_patch.m_const_str();
		}
	}

	ds_url::dsd_base_url dsl_base_url;
	if(!ds_url::m_parse_base_url(hstr_url, dsl_base_url)) {
		return false;
	}
	rdsp_wsg_url.iec_hob_type_charset = ied_chs_invalid;
	rdsp_wsg_url.hstr_hob_type_origin = "";
	rdsp_wsg_url.hstr_hob_type_worker = "";

	dsd_const_string hstr_query(dsl_base_url.dsc_search);
	if(hstr_query.m_starts_with("?"))
		hstr_query = hstr_query.m_substring(1);
	rdsp_wsg_url.hstr_query = hstr_query;
	rdsp_wsg_url.in_hob_type = ien_hobtype_not_defined;
	rdsp_wsg_url.hstr_hob_query = "";

	const dsd_const_string hstrl_wsg_action("action/");
	if(dsl_base_url.dsc_path.m_starts_with(hstrl_wsg_action)) {
		rdsp_wsg_url.iec_request_type = ien_request_type_wsg_action;
		rdsp_wsg_url.hstr_path = dsl_base_url.dsc_path.m_substring(hstrl_wsg_action.m_get_len());
		return true;
	}

	if(!m_init_from_base(dsl_base_url, rdsp_wsg_url))
		return false;
	rdsp_wsg_url.iec_request_type = ien_request_type_wsg_external;

	// get last field-value pair of the query (no '&' yields whole query (substring starting at -1+1=0))
    int inl_pos = hstr_query.m_find_last_of("?&");
    const dsd_const_string dsl_query_end = hstr_query.m_substring(inl_pos+1);
    dsd_tokenizer dsl_tok(dsl_query_end, ",");
    dsd_const_string dsl_query_end1;
    bool bol_more_tokens = dsl_tok.m_next(dsl_query_end1);

	// original query may have 'HOB_type=js' or 'HOB_type=css' AT ITS END
    // -> cut off and remember this state; when webserver sends the response to this request, we must forward the data (omitting the
    // delivered MIME type) to the interpreter class for css/js
    dsd_const_string hstr_hob_query;
	if(dsl_query_end1.m_starts_with("HOB_type=")) {
		const dsd_const_string dsl_hob_type = dsl_query_end1.m_substring(9);
		int in_hob_type = ien_hobtype_not_defined;
		if (dsl_hob_type.m_equals("js")) {
			in_hob_type = ien_hobtype_js;
		}
		else if(dsl_hob_type.m_equals("css")) {
			in_hob_type = ien_hobtype_css;
		}
		else if(dsl_hob_type.m_equals("any")) {
			in_hob_type = ien_hobtype_any;
		}
		else if(dsl_hob_type.m_equals("none")) {
			in_hob_type = ien_hobtype_none;
		}
		else if(dsl_hob_type.m_equals("html")) {
			in_hob_type = ien_hobtype_html;
		}
		else if(dsl_hob_type.m_equals("ws")) {
			in_hob_type = ien_hobtype_ws;
		}
		while(bol_more_tokens) {
			bol_more_tokens = dsl_tok.m_next(dsl_query_end1);
			if(dsl_query_end1.m_starts_with("charset=")) {
				const dsd_const_string dsl_charset(dsl_query_end1.m_substring(8));
				rdsp_wsg_url.iec_hob_type_charset = ds_http_header::m_get_charset(dsl_charset);
				continue;
			}
			if(dsl_query_end1.m_starts_with("origin=")) {
				rdsp_wsg_url.hstr_hob_type_origin = dsl_query_end1.m_substring(7);
				continue;
			}
			if(dsl_query_end1.m_starts_with("worker=")) {
				rdsp_wsg_url.hstr_hob_type_worker = dsl_query_end1.m_substring(7);
				continue;
			}
		}

		hstr_hob_query = hstr_query.m_substring(inl_pos+1);
		if (inl_pos < 0) // only HOB_type -> no original query remains
			inl_pos = 0;
		// strip off HOB_type from query
		hstr_query = hstr_query.m_substring(0, inl_pos);
		rdsp_wsg_url.hstr_query = hstr_query;
		rdsp_wsg_url.in_hob_type = in_hob_type;
		rdsp_wsg_url.hstr_hob_query = hstr_hob_query;
	}

#if SM_USE_BASEURL_SUPPORT
	dsd_const_string dsl_path(rdsp_wsg_url.hstr_path);
	dsd_const_string dsl_token("/:WSG:");
	int inl_base_url_token = dsl_path.m_index_of(dsl_token);
	if(inl_base_url_token >= 0) {
		dsd_const_string dsl_path_base1 = dsl_path.m_substring(0, inl_base_url_token);
		dsd_const_string dsl_path4 = dsl_path.m_substring(inl_base_url_token);
		ds_url::dsd_base_url dsl_base_url2;
		rdsp_wsg_url.hstr_temp_path1.m_setup(ads_session->ads_wsp_helper);
		//rdsp_wsg_url.hstr_temp_paths[0] = dsl_path_base1;
		if(!m_resolve_wsg_encoding(dsl_base_url2, dsl_path_base1, dsl_path4, rdsp_wsg_url.hstr_temp_path1)) {
			ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE255E: Parsing of URL failed (%.*s)",
				dsl_base_url.dsc_path.m_get_len(), dsl_base_url.dsc_path.m_get_ptr());
			return false;
		}
		ds_url::dsd_base_url dsl_normalized;
		ds_url::m_make_absolute_url(dsl_base_url2, dsl_base_url, dsl_normalized);
		if(!m_init_from_base(dsl_normalized, rdsp_wsg_url))
			return false;
		rdsp_wsg_url.hstr_temp_path2.m_setup(ads_session->ads_wsp_helper);
		bool bol_changed = ds_interpret::m_normalize_path(dsl_normalized.dsc_path, rdsp_wsg_url.hstr_temp_path2);
		rdsp_wsg_url.hstr_path = bol_changed ? rdsp_wsg_url.hstr_temp_path2.m_const_str() : dsl_normalized.dsc_path;
#ifdef _DEBUG
		ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "[%d] #WSG.m_handle_request: Reconstructed URL: %.*s\n",
			ads_session->ads_wsp_helper->m_get_session_id(), 
			rdsp_wsg_url.hstr_path.m_get_len(), rdsp_wsg_url.hstr_path.m_get_ptr());
#endif
	}
#endif /*SM_USE_BASEURL_SUPPORT*/
	return true;
}

int ds_ws_gate::m_accept_request(const dsd_virtual_link** aadsp_vlink)
{
	dsd_const_string hstr_original_url(ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id);
	if(!m_parse_wsg_url(hstr_original_url, this->dsc_url)) {
		ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
				"HIWSE348E: Bad URL for WSG: %.*s.", hstr_original_url.m_get_len(), hstr_original_url.m_get_ptr() );
		ads_session->dsc_transaction.m_mark_as_processed(NULL); // JF 24.03.11
        ads_session->dsc_webserver.m_send_error_page(ds_http_header::ien_status_not_found, false, "Bad URL", 0, 0 );
		return -1;
	}
	if(this->dsc_url.iec_request_type == ien_request_type_unknown)
		return 0;
	*aadsp_vlink = this->adsc_virtual_link;
    this->hstr_prot_authority_ext_ws.m_reset();
	this->hstr_prot_authority_ext_ws.m_write(this->dsc_url.hstr_protocol);
	this->hstr_prot_authority_ext_ws.m_write("://");
	this->hstr_prot_authority_ext_ws.m_write(this->dsc_url.hstr_authority_of_webserver);
	if(this->dsc_url.iec_request_type == ien_request_type_vlink) {
		dsd_const_string hstr_url_in(this->ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_const_str());
		bool bol_wfa_login = (ads_session->dsc_http_hdr_in.m_get_http_method() == ds_http_header::ien_meth_POST)
							 && ads_session->dsc_auth.m_is_portlet_allowed(achg_known_portlets[ied_wfa_portlet])
							 && hstr_url_in.m_equals( HOBWFA_LOGIN );
		if(bol_wfa_login) {
			this->dsc_url.iec_request_subtype = ien_request_subtype_wfa_login;
			return 2;
		}
		bool bol_wfa_bmarks = (ads_session->dsc_http_hdr_in.m_get_http_method() == ds_http_header::ien_meth_POST)
                          && ads_session->dsc_auth.m_is_config_allowed(DEF_UAC_WFA_BMARKS)
                          && ads_session->dsc_auth.m_is_portlet_allowed(achg_known_portlets[ied_wfa_portlet])
                          && hstr_url_in.m_equals( HOBWFA_SAVE_BMARKS );
		if(bol_wfa_bmarks) {
			this->dsc_url.iec_request_subtype = ien_request_subtype_wfa_bookmarks;
			return 2;
		}
	}
	this->dsc_url.iec_request_subtype = ien_request_subtype_unknown;
	return 1;
}

/**
 * @ingroup webservergate
 *
 * if str_new_host is not empty it will be written to ied_scr_attr_host-header
 * (needed, when HOB_net detected a request to WS, which must be forwarded to WSG)
 * if ahstr_path!=NULL, this path will be used in status-line of http-header.
 *
 * @param [in]	bo_https_to_ws_hob_net
 * @param [in]	ahstr_host_hob_net		A pointer to a ds_hstring class. When this is not NULL it means that we were called by HOB_net.
 * @param [in]	in_port_hob_net			An int representing the port number used on HOB_net.
 * @param [in]	ahstr_path				A pointer to a ds_hstring class which contains the path to be used in status-line of http-header.
 *
 * @return  
 *
*/
#if SM_USE_OLD_HOBNET
int ds_ws_gate::m_handle_request(bool bo_https_to_ws_hob_net, const dsd_const_string* ahstr_host_hob_net, int in_port_hob_net, const dsd_const_string* ahstr_path)
#else
int ds_ws_gate::m_handle_request()
#endif
{
	bool bo_ignore_interpreter = false;
	bool bol_virtual_link = false;
    switch(this->dsc_url.iec_request_type) {
	case ien_request_type_wsg_external: {
	    if ((ads_session->ads_config->in_settings & SETTING_DISABLE_COOKIE_STORAGE) == 0) {
			dsd_const_string dsl_domain(this->dsc_url.hstr_hostname_of_webserver);
            dsd_const_string dsl_path(this->dsc_url.hstr_path);
			ads_session->dsc_ws_gate.dsc_ck_manager.m_set_script_cookie(
				this->hstr_hdrline_cookie.m_const_str(),
				dsl_domain, dsl_path, ads_session->dsc_auth.m_get_basename());
		}
		break;
	}
	case ien_request_type_wsg_action: {
		dsd_const_string dsl_path_token("sync-cookies/");
		if(this->dsc_url.hstr_path.m_starts_with(dsl_path_token)) {
			dsd_const_string dsl_cookie_path = this->dsc_url.hstr_path.m_substring(dsl_path_token.m_get_len());

			// Ticket [14905]:
		    if ((ads_session->ads_config->in_settings & SETTING_DISABLE_COOKIE_STORAGE) == 0) {
				ds_url::dsd_base_url dsl_cookie_url;
				if(!ds_url::m_parse_base_url(dsl_cookie_path, dsl_cookie_url)) {
					return false;
				}
				ads_session->dsc_ws_gate.dsc_ck_manager.m_set_script_cookie(
					this->hstr_hdrline_cookie.m_const_str(),
					dsl_cookie_url.dsc_hostname, dsl_cookie_url.dsc_path, ads_session->dsc_auth.m_get_basename());
            }

			ads_session->dsc_webserver.hstr_my_encoding = "text/plain";
         ads_session->dsc_webserver.m_create_resp_header( ds_http_header::ien_status_ok,
                                                             0, NULL, NULL, NULL, false, NULL);
         ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
			ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
			return 0;
		}
#ifdef _DEBUG
		if(this->dsc_url.hstr_path.m_starts_with("dummy/")) {
			ads_session->dsc_webserver.hstr_my_encoding = "text/plain";
         ads_session->dsc_webserver.m_create_resp_header( ds_http_header::ien_status_ok,
                                                             0, NULL, NULL, NULL, false, NULL);
         ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
			ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
			return 0;
		}
#endif
		return -1;
	}
	case ien_request_type_vlink: {
		bo_ignore_interpreter = true;
		bol_virtual_link = true;
		break;
	}
	default:
		return -1;
	}

	bool bol_allow_empty_path;
	switch(this->dsc_url.in_hob_type) {
	case ien_hobtype_css:
	case ien_hobtype_js:
	case ien_hobtype_ws:
	case ien_hobtype_none:
		bol_allow_empty_path = true;
		break;
	case ien_hobtype_html:
	case ien_hobtype_any:
		bol_allow_empty_path = false;
		break;
	default:
		bol_allow_empty_path = false;
		break;
	}
	// redirect the client, because server names must always be a director
    // example: Get /http://www.kbservices.com --> /http://www.kbservices.com/
	if (!bol_allow_empty_path && this->dsc_url.hstr_path.m_get_len() <= 0)
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
		ds_hstring hstr_address(ads_session->ads_wsp_helper);
		hstr_address.m_write(ads_session->dsc_http_hdr_in.dsc_url.hstr_path);
		hstr_address.m_write("/"); // that's the stuff: we want to add '/'

        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info, "HIWSW649W: URL without terminating '/' -> redirect to %s", hstr_address.m_get_ptr());

        // create the response (only header containing "Location moved"); don't forget the query if exists
        ds_hstring hstr_location = ads_session->dsc_webserver.m_create_location(
			hstr_address.m_const_str(), ads_session->dsc_http_hdr_in.dsc_url.hstr_query);
        dsd_const_string dsl_location(hstr_location.m_const_str());
        ads_session->dsc_webserver.m_create_resp_header(ds_http_header::ien_status_found, 0, &dsl_location, NULL, NULL, false, NULL);
        ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_skip_message_body_of_request);
        return 0;
    }

#if 0
	bool bol_is_ica = m_is_ica_srv();
	if(this->dsc_url.hstr_path.m_ends_with("launch.ica")) {
		this->dsc_interpret_ica.m_setup(
			ads_session, "", "",
			this->dsc_url.hstr_path );
		int inl_port = this->ads_session->dsc_auth.m_get_ica_port();
		if(inl_port <= 0) {
			ads_session->dsc_transaction.m_mark_as_processed(NULL); // JF 24.03.11
			ads_session->dsc_webserver.m_send_error_page(ds_http_header::ien_status_not_found, false, "Bad URL", 0, 0 );
			return -1;
		}
	}
#endif

	// Is this a special URL, for which we must activate SSO-procedure (insert e.g. username and password into a login page and press the OK button)
    bo_do_sso = m_is_sso();
#if 0
	ads_session->ads_wsp_helper->m_logf(ied_sdh_log_info, "m_handle_request to %.*s",
          hstr_original_url.m_get_len(), hstr_original_url.m_get_ptr());
#endif
    // Create url for status line.
	dsd_const_string hstr_url_in(this->ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_const_str());
    ds_hstring hstr_url(ads_session->ads_wsp_helper, this->dsc_url.hstr_path);
#if SM_USE_OLD_HOBNET
	if (ahstr_path != NULL) {
        hstr_url.m_set(*ahstr_path);
        ads_session->ads_wsp_helper->m_logf(ied_sdh_log_info, "HIWSI234I: Replacing url of status line to %.*s",
            hstr_url.m_get_len(), hstr_url.m_get_ptr());
    }
#endif
    if (hstr_url.m_get_len() == 0) {
        hstr_url.m_set("/");
    }
    if (this->dsc_url.hstr_query.m_get_len() > 0) {
		hstr_url.m_write("?");
        hstr_url.m_write(this->dsc_url.hstr_query);
    }

    //-------------
    // compose the out-http-header
    //-------------
    ds_hstring hstr_value(ads_session->ads_wsp_helper, "");
    // compose the start-line
    dsd_const_string hstr_version(HF_HTTP_1_1); // HTTP/1.1
    if (ads_session->dsc_http_hdr_in.in_http_version != ds_http_header::ien_http_version_11) { 
        if (ads_session->dsc_http_hdr_in.in_http_version == ds_http_header::ien_http_version_10) { // HTTP/1.0
            hstr_version = HF_HTTP_1_0;
        }
        else { // all others: we go on with HTTP/0.9
            hstr_version = HF_HTTP_0_9;
        }
    }

    ads_session->dsc_http_hdr_out.m_add_start_line_out(true, hstr_version, 
        ads_session->dsc_http_hdr_in.m_get_http_method(), hstr_url.m_const_str());

    //-----------
    // create header lines
    //-----------

    // ACCEPT-LANGUAGE
    ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_ACCEPT_LANGUAGE, ads_session->dsc_http_hdr_in.hstr_hf_accept_language.m_const_str());

#if SM_USE_OLD_HOBNET
	// HOST
    if (ahstr_host_hob_net != NULL) { // called by HOB_net
        hstr_value.m_reset();
        hstr_value.m_write(*ahstr_host_hob_net);
        hstr_value.m_write(":");
        hstr_value.m_write_int(in_port_hob_net);
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_HOST, hstr_value.m_const_str()); 
    }
    else
#endif
	{
	    ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_HOST, this->dsc_url.hstr_authority_of_webserver);
    }
    

    // ACCEPT-ENCODING:
    // Ticket[14237]: we don't support compression method 'compress' and 'deflate'(=zLib); 'gzip' is supported
    ds_hstring hstr_accept_encodings(ads_session->ads_wsp_helper, "");
	int inl_encodings = 0;
	if((ads_session->ads_config->in_settings & SETTING_ENABLE_DECOMPRESSION) != 0) {
		hstr_accept_encodings.m_write(HFV_GZIP);
		inl_encodings |= ds_http_header::ien_ce_gzip;
	}
    // Ticket[14237]: add compression
    if ((ads_session->ads_config->in_settings & SETTING_ENABLE_COMPRESSION) == 0) {
#if 0
        if(!ads_session->dsc_http_hdr_in.ds_v_hf_accept_encoding.m_empty()) {
            // the header Accept-Encoding is read but not passed to external webserver or evaluated by in case of internal webserver; that means, that only 'identity'-encoding is passed to webserver

            // JF 22.06.10 Ticket[20167]: deliver in case of compression=OFF the headerline 'Accept-Encoding: identity' for clearity, that we do not support any encoding.
            // RFC2616-14.3 says:
            // "If no Accept-Encoding field is present in a request, the server MAY assume that the client will accept any content coding." 
            // and 
            // "If the request does not include an Accept-Encoding field, and if the "identity" content-coding is unavailable, then content-codings commonly
            // understood by HTTP/1.0 clients (i.e., "gzip" and "compress") are preferred; some older clients improperly display messages sent with other
            // content-codings. The server might also make this decision based on information about the particular user-agent or client."
            // (--> pay attention to the last sentence!) 
			if (hstr_accept_encodings.m_get_len() != 0)
				hstr_accept_encodings.m_write(",");
            hstr_accept_encodings.m_write(HFV_IDENTITY);
        }
#endif
    }
    else {
        for (HVECTOR_FOREACH(dsd_const_string, adsl_cur, ads_session->dsc_http_hdr_in.ds_v_hf_accept_encoding)) {
            const dsd_const_string& hstr_tmp = HVECTOR_GET(adsl_cur);
			int inl_enc = ds_http_header::m_get_encoding(hstr_tmp);
			if((inl_encodings & inl_enc) != 0)
				continue;
			switch(inl_enc) {
			case ds_http_header::ien_ce_identity:
				break;
			case ds_http_header::ien_ce_gzip:
				break;
            // deflate is not implemented -> do not deliver method 'deflate' to server
			case ds_http_header::ien_ce_deflate:
            // do not deliver method 'compress' to server
			case ds_http_header::ien_ce_compress:
            // JF 30.10.09 pack200 is not supported by most web servers -> we do not transfer pack200 to the web server.
			case ds_http_header::ien_ce_pack200:
			default:
				continue;
			}
			if (hstr_accept_encodings.m_get_len() != 0) { // add token separator
                hstr_accept_encodings.m_write(",");
            }
            hstr_accept_encodings += hstr_tmp;
			inl_encodings |= inl_enc;
        }
    }
	if(hstr_accept_encodings.m_get_len() <= 0) {
		hstr_accept_encodings.m_write(HFV_IDENTITY);
	}
    if (hstr_accept_encodings.m_get_len() > 0) { // add accept-encoding header
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_ACCEPT_ENCODING, hstr_accept_encodings.m_const_str());
    }

    // USER-AGENT
    // (directly adopted from ws3)
    hstr_value.m_reset();
    hstr_value = ads_session->dsc_http_hdr_in.hstr_hf_user_agent;
    bool bo_cut_ie = false;
    if ((ads_session->ads_config->in_settings & SETTING_ACT_AS_MOZILLA) != 0) {
        bo_cut_ie = true;
    }
    if (bo_cut_ie) {
        int in_pos = hstr_value.m_search(")");
        if (in_pos != -1)
        {  // set always "Mozilla" agent without detailed distinction between IE or firefox
           // User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.8.1.1) Gecko/20061204 Firefox/2.0.0.1
           // myContext.Stream.Write("Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.8.1.1)");    // cause "Bad Request" with TAZ
           dsd_const_string hstr_temp(hstr_value.m_substring(0, in_pos+1));
           in_pos = hstr_temp.m_index_of("MSIE");
           if (in_pos >= 0) { // remove the "MSIE x.y;" from the User-Agent string
               int in_start = in_pos;
               in_pos = hstr_temp.m_index_of(in_start, ";");
               dsd_const_string hstr_temp1(hstr_temp);
               if (in_pos >= 0) {
                   hstr_value = hstr_temp.m_substring(0, in_start);
                   hstr_value += hstr_temp.m_substring(in_pos+1);
               }
               else {
                   hstr_value = hstr_temp1;  // don't cut "Gecko/xyz Firefox/x.y.z"! No Bad request with TAZ!
               }
           }
        }
    }
    ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_USER_AGENT, hstr_value.m_const_str());

    // REFERER
    // JF 23.01.08 cut out the 'https://wsp.de/' and leave query if exists
	ds_hstring hstr_new_origin(ads_session->ads_wsp_helper);
    if (ads_session->dsc_http_hdr_in.hstr_hf_referer.m_get_len() > 0) {
		ds_url::dsd_base_url dsl_base_url;
		if(!ds_url::m_parse_base_url(ads_session->dsc_http_hdr_in.hstr_hf_referer.m_const_str(), dsl_base_url))
			goto LBL_REFERRER_DONE;
		//if(!dsl_base_url.dsc_resource.m_starts_with("/wsg/"))
		//	goto LBL_REFERRER_DONE;
        ds_url_parser ads_url_parser(ads_session);
        ds_url dsl_url;
        dsl_url.m_setup(ads_session->ads_wsp_helper);
		// TODO: Remove protocol detection from URL parser
        int in_ret = ads_url_parser.m_parse(dsl_url, dsl_base_url.dsc_resource);
		if(in_ret < 0)
			goto LBL_REFERRER_DONE;
		// only if the referer contains 'https://wsp.de/http' the part from http is of interest to the webserver
		// there could be a referer like "https://hobc02k.hob.de/site_after_auth_test.html", which contains no information for webserver
		if(!dsl_url.bo_data_for_wsg) {
			goto LBL_REFERRER_DONE;
		}
		dsd_wsg_url dsl_wsg_url;
		if(!m_parse_wsg_url(dsl_base_url.dsc_resource, dsl_wsg_url)) {
			goto LBL_REFERRER_DONE;
		}

        ds_hstring hstr_new_referer(ads_session->ads_wsp_helper);
		hstr_new_referer.m_write(dsl_wsg_url.hstr_protocol);
		hstr_new_referer.m_write("://");
		hstr_new_referer.m_write(dsl_wsg_url.hstr_authority_of_webserver);
		hstr_new_origin = hstr_new_referer;
		hstr_new_referer.m_write(dsl_wsg_url.hstr_path);
        if (hstr_new_referer.m_get_len() == 0) {
            hstr_new_referer.m_set("/");
        }
        if (dsl_wsg_url.hstr_query.m_get_len() > 0) {
            hstr_new_referer.m_write("?", 1);
            hstr_new_referer.m_write(dsl_wsg_url.hstr_query);
        }
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_REFERER, hstr_new_referer.m_const_str());
    }
LBL_REFERRER_DONE:

	// ORIGIN
	if(ads_session->dsc_http_hdr_in.hstr_hf_origin.m_get_len() > 0) {
		dsd_const_string dsl_new_orgin = this->dsc_url.hstr_hob_type_origin;
		if(dsl_new_orgin.m_get_len() <= 0) {
			dsl_new_orgin = hstr_new_origin.m_const_str();
			if (dsl_new_orgin.m_get_len() <= 0) {
				dsd_const_string dsl_url = ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id;
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
					"HWSGI800W missing HTTP referer for resource '%.*s'",
					dsl_url.m_get_len(), dsl_url.m_get_ptr() );
			}
			dsl_new_orgin = this->dsc_url.hstr_hob_type_origin;
		}
		ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_ORIGIN, dsl_new_orgin);
	}

    //---------------------------------------
    // get cookies from cookie storage:
    //---------------------------------------
    if ( (ads_session->ads_config->in_settings & SETTING_DISABLE_COOKIE_STORAGE) == 0 ) {
        dsd_const_string dsl_domain = this->dsc_url.hstr_authority_of_webserver;
        dsd_const_string dsl_path = this->dsc_url.hstr_path;

#if SM_USE_OLD_HOBNET
		if ( ahstr_host_hob_net != NULL ) {
            // called by HOB_net
            dsl_domain    = *ahstr_host_hob_net;
            dsl_path      = this->dsc_url.hstr_path;
        }
#endif

        const ds_hvector<ds_cookie>* adsl_cookies = dsc_ck_manager.m_get_cookies(dsl_domain, dsl_path,
                                                   ads_session->dsc_auth.m_get_basename(),
												   this->dsc_url.bo_ssl_to_ext_ws );
#if 0
		dsd_const_string dsl_directory = dsl_path;
		int inl_pos = dsl_directory.m_last_index_of("/");
		if(inl_pos >= 0)
			dsl_directory = dsl_path.m_substring(0, inl_pos+1);
#endif
        ads_session->dsc_http_hdr_out.hstr_cookie_line_to_webserver.m_reset();
        if(adsl_cookies != NULL) {
            int in_pos = 0;
            for(HVECTOR_FOREACH(ds_cookie, adsl_cookie, *adsl_cookies)) {
                const ds_cookie& rdsl_cookie = HVECTOR_GET(adsl_cookie);
#if 1
				const dsd_const_string dsl_cookie_path = rdsl_cookie.m_get_path();
				if(!rdsl_cookie.m_matches_path(dsl_path)) {
					int a = 0;
					continue;
				}
#endif
                if ( in_pos > 0 ) {
                    ads_session->dsc_http_hdr_out.hstr_cookie_line_to_webserver.m_write( "; " );
                }
#ifdef _DEBUG
				ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "[%d] #WSG.m_handle_request: Cookie=%.*s Path=%.*s Domain=%.*s\n",
					ads_session->ads_wsp_helper->m_get_session_id(), 
					rdsl_cookie.m_get_cookie().m_get_len(), rdsl_cookie.m_get_cookie().m_get_ptr(),
					rdsl_cookie.m_get_path().m_get_len(), rdsl_cookie.m_get_path().m_get_ptr(),
					rdsl_cookie.m_get_domain().m_get_len(), rdsl_cookie.m_get_domain().m_get_ptr());
#endif
                ads_session->dsc_http_hdr_out.hstr_cookie_line_to_webserver.m_write( rdsl_cookie.m_get_cookie() );
                in_pos++;
            }
        }
		/*
			if virtual link, add our HOBWSP_SID cookie!
		*/
        dsd_const_string hstr_original_url(ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id);
        ds_hstring hstr_cookie;

		if( bol_virtual_link )
		{
			ads_session->dsc_auth.m_get_http_cookie( &hstr_cookie );
            if (ads_session->dsc_http_hdr_out.hstr_cookie_line_to_webserver.m_get_len() > 0 ) {
                ads_session->dsc_http_hdr_out.hstr_cookie_line_to_webserver.m_write( "; " );
            }
			ads_session->dsc_http_hdr_out.hstr_cookie_line_to_webserver.m_write( IDENT_HOBWSP_COOKIE );
			ads_session->dsc_http_hdr_out.hstr_cookie_line_to_webserver.m_write( "=" );
			ads_session->dsc_http_hdr_out.hstr_cookie_line_to_webserver.m_write( hstr_cookie );
		}
    }
    if (ads_session->dsc_http_hdr_out.hstr_cookie_line_to_webserver.m_get_len() > 0) {
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_COOKIE, ads_session->dsc_http_hdr_out.hstr_cookie_line_to_webserver.m_const_str());
    }

    
    /*
        MJ 23.06.10: WFA login concept:
        -------------------------------

      When user clicks on WFA link, browser will send a
        POST /http://127.0.0.1:8080/HOBWFA_LOGIN

      WebServer will detect this request as a special one and modify the request to
        POST HOBWFA_LOGIN

      with xml message body:

        <webfileaccess>
          <user>jakobsml</user>
          <password>hob</password>
          <domain>hob01</domain>

          <bookmark>
            <url>hobc02k.hob.de</url>
            <name>hobc02k</name>
          </bookmark>
          <bookmark>
            <url>hobc02p.hob.de</url>
            <name>tausch</name>
          </bookmark>
        </webfileaccess>

      WFA will detect this request, try to login with given information and save
      bookmarks somewhere in its HTTP Cookie. If login is successful, WFA will
      forward browser to a working page. If not, WFA will forward browser to login
      page.
    */
    bool bol_wfa_login = (this->dsc_url.iec_request_subtype == ien_request_subtype_wfa_login);
    ds_hstring dsl_wfa_data( ads_session->ads_wsp_helper );
	if ( this->dsc_url.iec_request_subtype == ien_request_subtype_wfa_login ) {        
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                            "HWSGI794I detected WFA start post" );
		ads_session->dsc_webserver.hstr_message_body.m_reset();
#if 0
        // wait until the message body is completed:
        int inl_content_length = ads_session->dsc_http_hdr_in.m_get_content_length();
        int inl_available      = ads_session->dsc_transaction.m_count_unprocessed_data();
        if ( inl_available < inl_content_length ) {
            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                                 "HWSGI795I not all announced data available: %d of %d",
                                                 inl_available, inl_content_length );
            return 0;
        }

        char *achl_body = ads_session->ads_wsp_helper->m_cb_get_memory( inl_content_length, false );
        ads_session->dsc_transaction.m_get_linear_data( achl_body, inl_content_length, true );
        ads_session->ads_wsp_helper->m_cb_free_memory( achl_body );
#endif
        bool                      bol_ret;
        ds_hvector<dsd_wfa_bmark> dsl_bmarks( ads_session->ads_wsp_helper );
        ds_hstring                dsl_length( ads_session->ads_wsp_helper );

        // TODO: Wrong encoding of XML content
        dsl_wfa_data.m_write ( "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<webfileaccess><default-credentials>" );
        dsl_wfa_data.m_write( "<user>" );
        dsl_wfa_data.m_write_xml_text( ads_session->dsc_auth.m_get_username().m_const_str() );
        dsl_wfa_data.m_write( "</user>" );
        dsl_wfa_data.m_write( "<password>" );
        dsl_wfa_data.m_write_xml_text( ads_session->dsc_auth.m_get_password().m_const_str() );
        dsl_wfa_data.m_write( "</password>" );
        dsl_wfa_data.m_write( "<domain>" );
        dsl_wfa_data.m_write_xml_text( ads_session->dsc_auth.m_get_domain().m_const_str() );
        dsl_wfa_data.m_write( "</domain>" );
        dsl_wfa_data.m_write ( "</default-credentials>" );

        bol_ret = ads_session->dsc_auth.m_get_wfa_bookmarks( &dsl_bmarks );
        if ( bol_ret == true ) {
            for (HVECTOR_FOREACH(dsd_wfa_bmark, adsl_cur, dsl_bmarks)) {
                const dsd_wfa_bmark& dsl_current = HVECTOR_GET(adsl_cur);
                dsl_current.m_to_xml( &dsl_wfa_data );
            }
        }

        dsl_wfa_data.m_write( "</webfileaccess>" );

        // set CONTENT-LENGTH and CONTENT-TYPE here, because we have "faked" content
        dsl_length.m_write_int(dsl_wfa_data.m_get_len());
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out( HF_CONTENT_LENGTH, dsl_length.m_const_str() );
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out( HF_CONTENT_TYPE, "text/xml" );

        // delete org message body:
        //ads_session->dsc_webserver.hstr_message_body.m_reset();
        ads_session->dsc_http_hdr_in.m_reset_content_length();
    }

    if ( !bol_wfa_login ) { // if we have an WFA login ignore original content-length and content-type, cause we have "faked" content
        // Content-Length (if exist)
        if (ads_session->dsc_http_hdr_in.m_get_content_length() >= 0) { // JF 15.01.08 '>' -> '>=', because we must forward 'Content-Length: 0' to the server
            ds_hstring hstr_len(ads_session->ads_wsp_helper, "");
            hstr_len = ads_session->dsc_http_hdr_in.m_get_content_length();
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONTENT_LENGTH, hstr_len.m_const_str());
        }

        // Content-Type
        if (ads_session->dsc_http_hdr_in.hstr_hf_content_type.m_get_len() > 0) {
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONTENT_TYPE, ads_session->dsc_http_hdr_in.hstr_hf_content_type.m_const_str());
        }
    }

    /*
        MJ 23.06.10: WFA save bookmarks:
        --------------------------------
          WFA can provide some functionality to add, delete or edit bookmarks.
          If user has changed some bookmarks, WFA (from browser) will send a

            POST HOBWFA_SAVE_BMARKS

          WebServer will detect this request, save bookmarks in LDAP and forward the
          request to WFA.
    */
    bool bol_wfa_bmarks = (this->dsc_url.iec_request_subtype == ien_request_subtype_wfa_bookmarks);
    if ( bol_wfa_bmarks ) {
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                            "HWSGI796I detected WFA bookmark post" );

#if 0
        // wait until the message body is completed:
        int inl_content_length = ads_session->dsc_http_hdr_in.m_get_content_length();
        int inl_available      = ads_session->dsc_transaction.m_count_unprocessed_data();
        if ( inl_available < inl_content_length ) {
            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                                 "HWSGI797I not all announced data available: %d of %d",
                                                 inl_available, inl_content_length );
            return 0;
        }
#endif
		dsd_const_string dsl_body = ads_session->dsc_webserver.hstr_message_body.m_const_str();

        // read the xml
        ds_xml dsl_parser;
        dsl_parser.m_init( ads_session->ads_wsp_helper );
		dsd_xml_tag *adsl_node = dsl_parser.m_from_xml(dsl_body);
        if ( adsl_node != NULL ) {
            const char *achl_command;
            int   inl_len_command;

            // read bookmark:
            dsd_xml_tag *adsl_bookmark = dsl_parser.m_get_value( adsl_node, (char*)"bookmark",
                                                                 (int)(sizeof("bookmark") - 1),
                                                                 &achl_command,
                                                                 &inl_len_command );
            // read command:
            dsl_parser.m_get_value( adsl_node, (char*)"command", (int)(sizeof("command") - 1),
                                    &achl_command, &inl_len_command );
            if (    adsl_bookmark  != NULL
                 && inl_len_command > 0    ) {
                dsd_wfa_bmark dsl_bmark;
                dsl_bmark.m_init( ads_session->ads_wsp_helper );
                bool bol_ret = dsl_bmark.m_from_xml( adsl_bookmark );
                if ( bol_ret == true) {
                    if (    dsl_bmark.m_is_complete()
                         && inl_len_command == (int)strlen(achs_wfa_commands[0])
                         && memcmp(achl_command, achs_wfa_commands[0], inl_len_command) == 0 ) {
                        // add command:
                        // save bookmark in cma (as own one):
                        dsl_bmark.m_set_own( true );
                        bol_ret = ads_session->dsc_auth.m_add_wfa_bookmark( &dsl_bmark );
                        if ( bol_ret == true ) {
                            // save settings in ldap:
                            bol_ret = ads_session->dsc_auth.m_save_settings();
                            if ( bol_ret == true ) {
                                const char *achl_url;
                                int  inl_url = 0;
                                dsl_bmark.m_get_url( &achl_url, &inl_url );
                                ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
                                                                     "HWSGI798I added wfa bookmark '%.*s'",
                                                                     inl_url, achl_url );
                            }
                        }
                    } else if (    inl_len_command == (int)strlen(achs_wfa_commands[1])
                                && memcmp(achl_command, achs_wfa_commands[1], inl_len_command) == 0 ) {
                        // remove command:
                        // this solution  will not be the fasted, but it is the easiest
                        // currently we are getting all bookmarks from cma, removing the one
                        // and saving all again.
                        // in the future we should add a function to delete wfa bookmarks in
                        // cma by index
                        int inl_pos = dsl_bmark.m_get_position();
                        ds_hvector<dsd_wfa_bmark> dsl_bmarks(ads_session->ads_wsp_helper);
                        bol_ret = ads_session->dsc_auth.m_get_wfa_bookmarks( &dsl_bmarks );
                        if (    bol_ret             == true
                             && dsl_bmarks.m_size() >  (size_t)inl_pos ) {
                            dsl_bmark = dsl_bmarks.m_get( inl_pos );
                            if ( dsl_bmark.m_is_own() ) {
                                dsl_bmarks.m_delete( inl_pos );
                                // save bookmarks in cma:
                                bol_ret = ads_session->dsc_auth.m_set_wfa_bookmarks( &dsl_bmarks );
                                if ( bol_ret == true ) {
                                    // save settings in ldap:
                                    bol_ret = ads_session->dsc_auth.m_save_settings();
                                    if ( bol_ret == true ) {
                                        const char *achl_url;
                                        int  inl_url = 0;
                                        dsl_bmark.m_get_url( &achl_url, &inl_url );
                                        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
                                                                             "HWSGI799I removed wfa bookmark '%.*s'",
                                                                             inl_url, achl_url );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

		ads_session->dsc_webserver.hstr_message_body.m_reset();
    }

    // MJ 15.06.09, Ticket [17845]:
    for ( HVECTOR_FOREACH(ds_hstring, adsl_cur, ads_session->dsc_http_hdr_in.ds_v_hf_cache_control) ) {
        const ds_hstring& hstr_tmp = HVECTOR_GET(adsl_cur);
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CACHE_CONTROL, hstr_tmp.m_const_str());
    }
    if (ads_session->dsc_http_hdr_in.hstr_hf_pragma.m_get_len() > 0) {
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_PRAGMA, ads_session->dsc_http_hdr_in.hstr_hf_pragma.m_const_str());
    }

	 bool bol_has_authorization = false;
    // Ticket[19819]
    if (ads_session->in_state_auth_basic == ds_session::ien_st_auth_basic_succeeded) {
        // A SSO with 'Basic Authentication' was successful on this connection. Insert the authorization to all requests ON THIS COONECTION.
        // Attention: More correctly would be to insert only, when the URL belongs to a certain webserver/path !!
        if (ads_session->hstr_authorization_basic.m_get_len() > 0) {
            ads_session->ads_wsp_helper->m_log(ied_sdh_log_info, "HIWSI421I: Inserting header field " HF_AUTHORIZATION " for 'Basic'.");
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_AUTHORIZATION, ads_session->hstr_authorization_basic.m_const_str());
				bol_has_authorization = true;
        }
    }

    if (ads_session->in_state_auth_negotiate == ds_session::ien_st_auth_nego_succeeded) {
        if ((ads_session->ads_config->in_settings & SETTING_AUTH_NEGO_ONLY_ONCE) != 0) {
            ads_session->ads_wsp_helper->m_log(ied_sdh_log_info,
                "HIWSI452I: Inserting header field " HF_AUTHORIZATION " for 'Negotiate' is skipped, because this is not the first request on this connection.");
        }
        else {
            // A SSO with 'Negotiate Authentication' was successful on this connection. Insert the authorization to all requests ON THIS CONNECTION.
            // This will avoid the round-trip, that the web server first sends 'Unauthorized'.
            // Attention: More correctly would be to insert only, when the URL belongs to a certain webserver/path !!
            ads_session->ads_wsp_helper->m_log(ied_sdh_log_info, "HIWSI422I: Inserting header field " HF_AUTHORIZATION " for 'Negotiate'.");
            // The SPNEGO data must be sent as base64.
            ds_hstring hstr_negotiate_b64(ads_session->ads_wsp_helper);
            int inl_ret = ads_session->dsc_control.m_create_nego_token(true, &hstr_negotiate_b64, ads_session->dsc_control.nego_mechtype, true);
            if (inl_ret != SUCCESS)  {
                ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE255E: Creation of SPNEGO/Kerberos token failed with error %d.", inl_ret);
            }
            else {
                ds_hstring hstr_to_insert(ads_session->ads_wsp_helper, 8096);
                hstr_to_insert.m_write(HFV_WWWAUTH_NEGOTIATE " ");
                hstr_to_insert.m_write(hstr_negotiate_b64);
                ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_AUTHORIZATION, hstr_to_insert.m_const_str());
					 bol_has_authorization = true;
            }
        }
    }

	 if(!bol_has_authorization && ads_session->dsc_http_hdr_in.hstr_hf_authorization.m_get_len() > 0)
		 ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_AUTHORIZATION, ads_session->dsc_http_hdr_in.hstr_hf_authorization.m_const_str());


    // write UNPROCESSED header-lines
    ds_hstring hstr_unprocessed = ads_session->dsc_http_hdr_in.m_get_unprocessed_headerlines();
    ads_session->dsc_http_hdr_out.m_add_hdr_unprocessed_lines_out(&hstr_unprocessed);

    // terminate http-header
    ads_session->dsc_http_hdr_out.m_terminate_hdr_out();

    // send the header data
    int in_ret = m_send_to_ext_ws(ads_session->dsc_http_hdr_out.hstr_hdr_out.m_const_str()
#if SM_USE_OLD_HOBNET
		, bo_https_to_ws_hob_net, ahstr_host_hob_net, in_port_hob_net
#endif
	);
    if (in_ret != 0) { // error
        ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "m_send_to_ext_ws() failed with error %d.", in_ret);
        return -25;
    }
	ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_sending_to_webserver);

    if ( bol_wfa_login == true ) {
        ads_session->ads_wsp_helper->m_send_data( dsl_wfa_data.m_get_ptr(), dsl_wfa_data.m_get_len() );
    }

#if SM_USE_OLD_HOBNET
	if (ahstr_host_hob_net != NULL) { // called by HOB_net
        // ds_webserver already has read a possible existing message body (e.g. in case of a POST)!
        if (ads_session->dsc_webserver.hstr_message_body.m_get_len() > 0) {
            dsd_const_string hstr_message_body(ads_session->dsc_webserver.hstr_message_body.m_const_str());
            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                   "HOB_Net: Send the message_body (length %d) in ds_ws_gate",
                                   hstr_message_body.m_get_len() );
            in_ret = ads_session->dsc_transaction.m_send_data(hstr_message_body, ied_sdh_dd_toserver);
            if (in_ret != 0) { // error
                ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE231E: m_send_to_ext_ws() failed with error %d.", in_ret);
                return -225;
            }
			ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_server);
            return 0;
        }
    }
#endif
	this->boc_websocket_upgrade = ads_session->dsc_http_hdr_in.bo_upgrade_websocket;

	in_len_to_send_unchanged_to_server = ads_session->dsc_http_hdr_in.m_get_content_length();
	if(in_len_to_send_unchanged_to_server < 0)
		in_len_to_send_unchanged_to_server = 0;

    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                         "HIWSI231I: in_len_to_send_unchanged_to_server %d",
                                         in_len_to_send_unchanged_to_server );
    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                         "HIWSI232I: ads_session->dsc_http_hdr_in.m_get_content_length() %d",
                                         ads_session->dsc_http_hdr_in.m_get_content_length() );
    return 0;
}  // m_handle_request

/**
 *
 * ds_ws_gate::m_send_to_ext_ws
 *
 * @param [in]	ahstr_to_send			A pointer to a ds_hstring class containing data to be sent to the external webserver.
 * @param [in]	bo_https_to_ws_hob_net
 * @param [in]	ahstr_host_hob_net		A pointer to a ds_hstring class. When this is not NULL it means that we were called by HOB_net.
 * @param [in]	in_port_hob_net			An int representing the port number used on HOB_net.
 *
 * @return  An int value is returned. When this is not 0 it means that there was an error in the function.
 *
*/
int ds_ws_gate::m_send_to_ext_ws(const dsd_const_string& rhstr_to_send
#if SM_USE_OLD_HOBNET
	, bool bo_https_to_ws_hob_net, const dsd_const_string* ahstr_host_hob_net, int in_port_hob_net
#endif
	)
{
    // check for the TCP-connection
    dsd_const_string dsl_error_key = MSG_SERVER_UNREACHABLE;
    bool bo_ssl_to_server = this->dsc_url.bo_ssl_to_ext_ws;
    dsd_const_string hstr_server_ip(this->dsc_url.hstr_hostname_of_webserver);
    int in_server_port = this->dsc_url.in_port_of_webserver;
#if SM_USE_OLD_HOBNET
	if (ahstr_host_hob_net != NULL) { // called by HOB_net -> set other values
        bo_ssl_to_server = bo_https_to_ws_hob_net;
        hstr_server_ip = *ahstr_host_hob_net;
        in_server_port = in_port_hob_net;
    }
#endif
    ds_hstring hstr_err_msg(ads_session->ads_wsp_helper);
    if (!bo_connected) { // there is no connection -> establish it
        bo_connected = m_do_connect(bo_ssl_to_server, hstr_server_ip, in_server_port, hstr_err_msg, dsl_error_key);
    }
    else { // a connection already exists
        if (m_connection_changed(bo_ssl_to_server, hstr_server_ip, in_server_port)) { // existing connection is to another destination
            // close this connection and establish another one
            ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI255I: connection must be closed and opened again." );
            m_close_conn_to_ext_server();
            if ( bo_connected == true ) { // Error: we could not close the connection to the web server. We close the connection to the browser and hope,
                                          // that the browser will retry this request.
                ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE444E: Closing (for reopen) connection to web server failed." );
                ads_session->dsc_transaction.m_mark_as_processed(NULL); // JF 24.03.11
                ads_session->dsc_transaction.m_close_connection();
                return -2;
            }
            bo_connected = m_do_connect(bo_ssl_to_server, hstr_server_ip, in_server_port, hstr_err_msg, dsl_error_key);

            ads_session->in_state_auth_basic = ds_session::ien_st_auth_basic_not_active; // Reset the state. Perhaps there was SSO 'Basic Authentication' on this connection before!
            ads_session->hstr_authorization_basic.m_reset();
            ads_session->in_state_auth_negotiate = ds_session::ien_st_auth_nego_not_active;
        }
    }

    if (!bo_connected) { // we are not connected -> give back an error-page
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, hstr_err_msg.m_const_str() );
        ads_session->dsc_webserver.m_send_error_page(ds_http_header::ien_status_not_found, false, dsl_error_key, 0, 0 );
        return -1;
    }

    // send data to external webserver ('send' means 'put into wa or into sending queue')
    ads_session->dsc_transaction.m_send_data(rhstr_to_send, ied_sdh_dd_toserver);
	return 0;
}

/**
 *
 * ds_ws_gate::m_do_connect
 *
 * @param [in]	bo_https			A bool flag which indicates whether the protocol is HTTPS.
 * @param [in]	ahstr_host			A pointer to a ds_hstring class containing info about the host.
 * @param [in]	in_port				Int value indicating the port number used.
 * @param [in]	ahstr_err_msg		A pointer to a ds_hstring class containing error messages.
 * @param [out]	aachp_error_key		A char** in which an error key is returned.
 *
 * @return  TRUE is returned when the TCP connectin is handled successfully and FALSE otherwise.
 *
*/
bool ds_ws_gate::m_do_connect(bool bo_https, const dsd_const_string& rhstr_host, int in_port, ds_hstring& ahstr_err_msg, dsd_const_string& adsp_error_key ) {
#if 0
    // PVA
	bool bol_use_ssl = true;
    bool bo_ret = ads_session->dsc_transaction.m_tcp_connect(bol_use_ssl ? true : bo_https, ahstr_host, bol_use_ssl ? 443 : in_port, ahstr_err_msg, aachp_error_key );
#else
    bool bo_ret = ads_session->dsc_transaction.m_tcp_connect(bo_https, rhstr_host, in_port, ahstr_err_msg, adsp_error_key );
#endif
    if (bo_ret) { // store protocol, domain, port of the last connected webserver
        bo_last_ws_prot_https = bo_https;
        hstr_last_ws_str_host = rhstr_host;
        in_last_ws_port = in_port;

        dsd_const_string hstr_prot("http://"); // http
        if (bo_https){ // https
            hstr_prot = "https://";
        }
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                             "HIWSI266I: connected to %.*s%.*s:%d",
                                             hstr_prot.m_get_len(), hstr_prot.m_get_ptr(),
                                             rhstr_host.m_get_len(), rhstr_host.m_get_ptr(),
                                             in_port );
        
        // we are connected -> store address and port of this webserver into CMA
        if ((ads_session->ads_config->in_settings & SETTING_HOB_NET_OFF) == 0) {
            // if default-file or a html/htm-file is requested -> store address and port of this webserver into CMA
            if ( (ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_ends_with_ic(".html"))
              || (ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_ends_with_ic(".htm"))
              || (ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_ends_with_ic(HOBWFA_LOGIN)) // JF 24.02.10
              || (ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_get_len() == 0) 
              || (ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_ends_with("/"))
              ) {
                // write IP and port into CMA
                  if (rhstr_host.m_get_len() > 0) {  // do not overwrite with an empty string!!
                    ads_session->dsc_auth.m_set_lws( bo_https ? 1 : 0, rhstr_host.m_get_ptr(), rhstr_host.m_get_len(), in_port );
                    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                                         "HIWSI256I: storing last webserver as %.*s%.*s:%d",
                                                         hstr_prot.m_get_len(), hstr_prot.m_get_ptr(),
                                                         rhstr_host.m_get_len(), rhstr_host.m_get_ptr(),
                                                         in_port );
                }
            }            
        }
    }
    return bo_ret;
}

/**
 * @ingroup webservergate
 *
 * close TCP connection to external webserver server
 *
 **
*/
void ds_ws_gate::m_close_conn_to_ext_server() {
    if (!bo_connected) {
        return;
    }
#ifdef _DEBUG
    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error, "Closing dynamic connection to external server" );
#endif
    bool bo_ret = ads_session->ads_wsp_helper->m_cb_tcp_close();
	 bo_connected = !bo_ret;
}

/**
 *
 * ds_ws_gate::m_connection_changed
 *
 * check whether the webserver, to which we want to send data, is the same, to which we sent data
 * returns true, if something changed
 *
 * @param	bo_https	A bool flag which indicates whether the protocol is HTTPS.
 * @param	ahstr_host	A pointer to a ds_hstring class containing info about the host.
 * @param	in_port		Int value indicating the port number used.
 *
 * @return	TRUE is returned when the webserver to which we want to send data, is not 
 *			the same as that to which we already sent data
 *
 **
*/
bool ds_ws_gate::m_connection_changed(bool bo_https, const dsd_const_string& rhstr_host, int in_port)
{
    if (bo_last_ws_prot_https != bo_https) {
        return true;
    }
    if (in_last_ws_port != in_port) {
        return true;
    }
    if (!hstr_last_ws_str_host.m_equals_ic(rhstr_host)) {
        return true;
    }
    return false;
}

/**
 * @ingroup webservergate
 *
 * @param [in]	bo_send_chunked_to_browser	A bool flag which indicates whether data must be sent as chunks to the browser
 * @param [in]	bo_message_body_announced	
 * @param [in]	bo_send_www_auth_to_client	A bool flag which indicates whether to send WWW-Authenticate to client
 *
 * @return	Returns 0
 *
 **
*/
int ds_ws_gate::m_handle_response_header(int in_content_type, bool bo_send_www_auth_to_client)
{
    /* check if given url is an ica server */
	bool bol_is_ica = m_is_ica_srv();
    this->adsc_interpreter = this->m_get_interpreter(in_content_type);
	this->boc_interpret_failed = false;
	this->bo_skip_response_data = false;
	dsd_const_string dsl_content_type = ads_session->dsc_http_hdr_in.hstr_hf_content_type.m_const_str();
	if(this->adsc_interpreter == &this->dsc_interpret_script) {
		dsl_content_type = "application/javascript;charset=utf-8";
	}

	int inl_accept_encoding = ads_session->dsg_state.in_accept_encoding;
	int inl_content_encoding = ads_session->dsc_http_hdr_in.in_content_encoding;
	int inl_pass_encoding = inl_accept_encoding & inl_content_encoding;
	/* DO we have a transfer encoding mismatch between client and server? */
	if(this->adsc_interpreter == NULL && inl_pass_encoding == 0) {
		this->adsc_interpreter = &this->dsc_interpret_pass;
	}
	// Use this for setup by default (see Location conversion m_change_url)
	ds_interpret* adsl_interpreter = &this->dsc_interpret_pass;
	/* Do we an active interpreter? */
	bool bo_send_chunked_to_browser = ads_session->dsc_http_hdr_in.m_is_chunked();
	if(this->adsc_interpreter != NULL) {
		adsl_interpreter = this->adsc_interpreter;
		bo_send_chunked_to_browser = true;
		if ((ads_session->ads_config->in_settings & SETTING_ENABLE_COMPRESSION) == 0)
			inl_accept_encoding = ds_http_header::ien_ce_identity;
	}
	//-------------
    // compose the out-http-header
    //-------------
    // compose the start-line
    dsd_const_string hstr_version(HF_HTTP_1_1); // HTTP/1.1
    if (!bo_send_chunked_to_browser) { // when we send 'chunked', we must use HTTP/1.1 (otherwise browser does not correctly interpret the data)
        if (ads_session->dsc_http_hdr_in.in_http_version_webserver != ds_http_header::ien_http_version_11) { 
            if (ads_session->dsc_http_hdr_in.in_http_version_webserver == ds_http_header::ien_http_version_10) { // HTTP/1.0
                hstr_version = HF_HTTP_1_0;
            }
            else { // all others: we go on with HTTP/0.9
                hstr_version = HF_HTTP_0_9;
            }
        }
    }

	int inl_status_code = ads_session->dsc_http_hdr_in.in_http_status_code;
	dsd_const_string hstr_http_reason_phrase = ads_session->dsc_http_hdr_in.hstr_http_reason_phrase.m_const_str();
#if 0
	// Experimental for Microsoft Edge to avoid display of Micrsofts HTTP error pages.
	if(inl_status_code == 403 && this->dsc_url.in_hob_type == ds_http_header::ien_hobtype_html) {
		inl_status_code = 200;
	}
#endif
	adsl_interpreter->m_setup(ads_session);
	if(adsl_interpreter == &this->dsc_interpret_html)
		this->dsc_interpret_html.m_set_ica(bol_is_ica);

	if(adsl_interpreter == &this->dsc_interpret_ica) {
		int inl_port = 0;
		if(inl_status_code == ds_http_header::ien_status_ok) {
			// Check if WSP-passthrough listen port is available 
			inl_port = this->ads_session->dsc_auth.m_get_ica_port();
			if(inl_port <= 0) {
				inl_status_code = ds_http_header::ien_status_not_found;
				hstr_http_reason_phrase = ads_session->dsc_http_hdr_out.m_get_reasonphrase(inl_status_code);
				this->bo_skip_response_data = true;
				adsl_interpreter->m_set_skip_output(true);
			}
		}
		this->dsc_interpret_ica.m_set_port(inl_port);
	}

	ads_session->dsc_http_hdr_out.m_add_start_line_out(false, hstr_version,
        inl_status_code, hstr_http_reason_phrase);

	// de.wikipedia.org sends a 'Location moved' with Content-Length=0 over HTTP/1.0
    // in this scenario, we didn't send Content-Length=0 to the browser, which then waited and waited...
    bool bo_message_body_announced = ads_session->dsc_http_hdr_in.m_is_message_body_announced();
	bool bo_data_until_close = ads_session->dsc_control.bo_data_until_close;
    if (ads_session->dsc_http_hdr_in.m_get_content_length() != 0 && bo_data_until_close) {
        bo_message_body_announced = true;
    }
	if(this->bo_skip_response_data) {
		// when not sending 'Content-Length: 0', browser will wait in 'Loading'
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONTENT_LENGTH, "0");
		ads_session->dsc_http_hdr_in.hstr_hf_content_type.m_reset();
		ads_session->dsc_http_hdr_in.hstr_hf_content_encoding.m_reset();
	}
	else if (bo_message_body_announced) {
        if (!ads_session->dsc_control.bo_data_until_close) { // no header-line will be written, when ads_session->dsc_control.bo_data_until_close
            // kind of transporting data to browser (chunked or content-length)
            if ( (bo_send_chunked_to_browser) && (ads_session->in_http_method_last_request != ds_http_header::ien_meth_HEAD) ) { // Transfer-Encoding: chunked
                ads_session->dsc_http_hdr_out.bo_hdr_chunked_set = true;
                ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_TRANSFER_ENCODING, "chunked");
            }
            else { // Content-Length
                ds_hstring hstr_len(ads_session->ads_wsp_helper, "");
                hstr_len = ads_session->dsc_http_hdr_in.m_get_content_length();
                ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONTENT_LENGTH, hstr_len.m_const_str());
            }
        }
        else {
             ads_session->dsc_http_hdr_out.bo_hdr_chunked_set = true;
             ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_TRANSFER_ENCODING, "chunked");
        }
    }
    else {
        if (ads_session->dsc_http_hdr_in.m_get_content_length() == 0) { // scenario amazon.de: status 301; Content-Type=text/html; Content-Length=0;
            // when not sending 'Content-Length: 0', browser will wait in 'Loading'
            ds_hstring hstr_len(ads_session->ads_wsp_helper, "");
            hstr_len = ads_session->dsc_http_hdr_in.m_get_content_length();
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONTENT_LENGTH, hstr_len.m_const_str());
        }
    }

	 if(ads_session->dsc_http_hdr_out.bo_hdr_chunked_set) {
		 this->ads_session->dsc_transaction.m_begin_chunked();
	 }

#if 0
	if(this->adsc_interpreter != NULL) {
		this->adsc_interpreter->m_set_write_mode(ads_session->dsc_http_hdr_out.bo_hdr_chunked_set);
	}
#endif
#if 0
	//---------------------------
    // the data have to be investigated
    //---------------------------
    ads_session->dsc_transaction.bo_resolve_from_chunked_format = ads_session->dsc_http_hdr_in.m_is_chunked();
    ads_session->dsc_transaction.in_len_data_to_deliver = ads_session->dsc_http_hdr_in.m_get_content_length();
    if (ads_session->dsc_transaction.bo_resolve_from_chunked_format) {
        ads_session->dsc_transaction.in_len_data_to_deliver = -1;
    }
    ads_session->dsc_transaction.bo_read_chunked_data_done = false;
#endif    

    // Content-Type
    if (ads_session->dsc_http_hdr_in.hstr_hf_content_type.m_get_len() > 0) {
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONTENT_TYPE, dsl_content_type);
    }
    // Location (if exists, we must change the URL)
    if (ads_session->dsc_http_hdr_in.hstr_hf_location.m_get_len() > 0) {
		ds_url::dsd_base_url dsl_base_url;
		dsd_const_string hstr_location = ads_session->dsc_http_hdr_in.hstr_hf_location.m_const_str();
		if(!ds_url::m_parse_base_url(hstr_location, dsl_base_url)) {
			ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error,
				"HIWSE823E: HTTP-Location URL could not be parsed %.*s",
				hstr_location.m_get_len(), hstr_location.m_get_ptr());
			goto LBL_LOCATION_DONE;
		}
		ds_url::dsd_base_url dsl_root_url;
		dsl_root_url.dsc_protocol = this->dsc_url.hstr_protocol;
		dsl_root_url.dsc_host = this->dsc_url.hstr_authority_of_webserver;
		dsl_root_url.dsc_hostname = this->dsc_url.hstr_hostname_of_webserver;
		dsl_root_url.dsc_port = this->dsc_url.hstr_port_of_webserver;
		ds_url::dsd_base_url dsl_abs_url;
		ds_url::m_make_absolute_url(dsl_base_url, dsl_root_url, dsl_abs_url);
		ds_hstring hstr_abs_location(ads_session->ads_wsp_helper, "");
		ds_url::m_write_base_url(dsl_abs_url, hstr_abs_location);

		ds_hstring hstr_new_location(ads_session->ads_wsp_helper, "");
		dsd_const_string dsl_vlink_rest;
		const dsd_virtual_link* adsl_vir_lnk = ads_session->dsc_control.m_check_virtual_link_rev(hstr_abs_location.m_const_str(), dsl_vlink_rest);
        if ( adsl_vir_lnk != NULL ) {
            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info, "HIWSI236I Virtual Link '%.*s' detected and mapped to %.*s%.*s",
                                                 adsl_vir_lnk->in_len_path, adsl_vir_lnk->ach_path,
												 adsl_vir_lnk->in_len_alias, adsl_vir_lnk->ach_alias,
												 dsl_vlink_rest.m_get_len(), dsl_vlink_rest.m_get_ptr());

            //hstr_new_location.m_write(hstr_prot_authority_ws);
			hstr_new_location.m_write(adsl_vir_lnk->ach_alias, adsl_vir_lnk->in_len_alias);
            hstr_new_location.m_write(dsl_vlink_rest);
        } else {
			ds_hstring hstr_location_in(ads_session->ads_wsp_helper, "");
			if(dsl_base_url.dsc_port.m_get_len() > 0) {
				// Workaround for https://myaccount.cloud.oracle.com.
				// Location is sometimes "https://myaccount.cloud.oracle.com:443", but browsers seems to remove the port if it's a default.
				if((dsl_base_url.dsc_protocol.m_equals("http") && dsl_base_url.dsc_port.m_equals("80"))
					|| (dsl_base_url.dsc_protocol.m_equals("https") && dsl_base_url.dsc_port.m_equals("443")))
				{
					dsl_base_url.dsc_port.m_reset();
					ds_url::m_write_base_url(dsl_base_url, hstr_location_in);
					hstr_location = hstr_location_in.m_const_str();
				}
			}
			ds_interpret::ied_change_url_result iel_result = adsl_interpreter->m_change_url(hstr_location, ds_interpret::ied_change_url_flag_absolute, hstr_new_location);
			if(iel_result == ds_interpret::ied_change_url_error)
				goto LBL_LOCATION_DONE;
			// URL was not changed?
			if(iel_result != ds_interpret::ied_change_url_changed)
	            hstr_new_location = hstr_location;
			if(this->dsc_url.hstr_hob_query.m_get_len() > 0) {
				if(hstr_new_location.m_search_last("?") < 0)
					hstr_new_location.m_write("?");
				else
					hstr_new_location.m_write("&");
				hstr_new_location.m_write(this->dsc_url.hstr_hob_query);
			}
        }
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_LOCATION, hstr_new_location.m_const_str());
    }
LBL_LOCATION_DONE:
    // For example used by: https://www.facebook.com
    if(ads_session->dsc_http_hdr_in.hstr_hf_content_security_policy.m_get_len() > 0) {
        int a = 0;
        // TODO:
    }

    // MJ 03.06.08, Ticket[14905]:
    if ((ads_session->ads_config->in_settings & SETTING_DISABLE_COOKIE_STORAGE) == 0) {
		// MJ 03.06.08, Ticket [14905]:
        for ( HVECTOR_FOREACH(ds_hstring, adsl_cookie, ads_session->dsc_http_hdr_in.ds_v_hf_set_cookie) ) {
            const ds_hstring& hstr_tmp = HVECTOR_GET(adsl_cookie);
#ifdef _DEBUG
			ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "[%d] #WSG.m_handle_response: Set-Cookie: %.*s\n",
				ads_session->ads_wsp_helper->m_get_session_id(), 
				hstr_tmp.m_const_str().m_get_len(), hstr_tmp.m_const_str().m_get_ptr());
#endif
			ads_session->dsc_ws_gate.dsc_ck_manager.m_set_cookie(hstr_tmp.m_const_str(),
                this->dsc_url.hstr_authority_of_webserver,
                this->dsc_url.hstr_path,
                ads_session->dsc_auth.m_get_basename() );
        }
        // use set cookie header for deleting cookies set from a javascript
        ads_session->dsc_http_hdr_in.ds_v_hf_set_cookie.m_clear();
        ds_hvector<ds_hstring> ds_rm_cookies( ads_session->ads_wsp_helper );
        ads_session->dsc_ws_gate.dsc_ck_manager.m_rm_script_cookies(ds_rm_cookies);
        for ( HVECTOR_FOREACH(ds_hstring, adsl_cookie, ds_rm_cookies) ) {
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_SET_COOKIE, HVECTOR_GET(adsl_cookie).m_const_str());
        }
    }
    else {
        for ( HVECTOR_FOREACH(ds_hstring, adsl_cur, ads_session->dsc_http_hdr_in.ds_v_hf_set_cookie) ) {
            const ds_hstring& hstr_tmp = HVECTOR_GET(adsl_cur);
            ds_hstring hstr_value = m_change_set_cookie( hstr_tmp.m_const_str() );
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_SET_COOKIE, hstr_value.m_const_str() );
        }
    }

    // Connection (if exists) (Attention: multi-valued variable)
	dsd_const_string hstr_hf_connection = ads_session->dsc_http_hdr_in.hstr_hf_connection.m_const_str();
	// Default value is keep-alive since HTTP 1.1
	if(ads_session->dsc_http_hdr_in.in_http_version >= ds_http_header::ien_http_version_11 && hstr_hf_connection.m_get_len() <= 0)
		hstr_hf_connection = "keep-alive";
	// Keep alive for outgoing connection
	this->boc_keep_alive = hstr_hf_connection.m_equals_ic("keep-alive");
	
	if(hstr_hf_connection.m_equals_ic("close"))
		hstr_hf_connection = "keep-alive";
	// SM: Enable to force closing of HTTP connection
#if 0
     ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONNECTION, "close");
#else
     ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONNECTION, hstr_hf_connection);
	 ads_session->dsc_control.boc_keep_alive = hstr_hf_connection.m_equals_ic("keep-alive");
#endif

    // JF 15.10.07 Ticket[13733]: WWW-Authenticate (if exists)
    if (true && bo_send_www_auth_to_client) {
        for (HVECTOR_FOREACH(ds_hstring, adsl_cur, ads_session->dsc_http_hdr_in.ds_v_hf_www_authenticate)) {
            const ds_hstring& hstr_value = HVECTOR_GET(adsl_cur);
#if 1
				// do not deliver 'Negotiate' to client if there are other authentication methods (huge problems with IE and Negotiate)
            if (ads_session->dsc_http_hdr_in.ds_v_hf_www_authenticate.m_size() > 1) {
                if (hstr_value.m_equals_ic(HFV_WWWAUTH_NEGOTIATE)) {
                    ads_session->ads_wsp_helper->m_log(ied_sdh_log_info, "HIWSI433I: Authentication 'Negotiate' will not be sent to client. Other mechanisms are available.");
                    continue;
                }
            }
#endif
#if 0
				if (hstr_value.m_equals_ic(HFV_WWWAUTH_NTLM)) {
               ads_session->ads_wsp_helper->m_log(ied_sdh_log_info, "HIWSI433I: Authentication 'NTLM' will not be sent to client.");
               continue;
            }
#endif
#if 1
				// Digest is not working because of "digest-uri-value" (see https://tools.ietf.org/html/rfc2617)
				if (hstr_value.m_starts_with_ic(HFV_WWWAUTH_DIGEST))
				{
					continue;
				}
#else
				// Ticket[23584] - The opera browser gives problems with a Digest authentication.
				if (ads_session->hstr_user_agent_last_req.m_starts_with_ic("Opera")
						 && hstr_value.m_starts_with_ic(HFV_WWWAUTH_DIGEST))
				{
					continue;
				}
#endif
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_WWW_AUTHENTICATE, hstr_value.m_const_str());
        }
    }

    // Ticket[14237]: Content-Encoding
    int inl_content_type = ads_session->dsc_http_hdr_in.m_get_content_type();
	if (this->adsc_interpreter == NULL) { // pass data unchanged to client
		dsd_const_string hstr_hf_content_encoding = ads_session->dsc_http_hdr_in.hstr_hf_content_encoding.m_const_str();
		if(hstr_hf_content_encoding.m_get_len() <= 0)
			hstr_hf_content_encoding = HFV_IDENTITY;
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONTENT_ENCODING, hstr_hf_content_encoding);
    }
    else if(ads_session->dsc_http_hdr_out.bo_hdr_chunked_set) { // data are changed by interpreter; data are sent as chunked, when there was a length info
		// when we send chunked data, we can compress it; in the other case NOT !!
        // there are problems with compression of jnlp-files (WebStart cannot correctly decompress)
        // -> don't try to compress them
        if (inl_content_type == ds_http_header::ien_ct_application_x_java_jnlp_file)
			inl_accept_encoding &= ~ds_http_header::ien_ce_gzip;
        if ((inl_accept_encoding & ds_http_header::ien_ce_gzip) != 0) { // browser supports gzip
            ads_session->dsc_http_hdr_out.bo_hdr_gzip_set = true; // flag will be investigated by ds_transaction
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONTENT_ENCODING, HFV_GZIP);
        }
		else if ((inl_accept_encoding & ds_http_header::ien_ce_identity) != 0) { // browser supports gzip
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CONTENT_ENCODING, HFV_IDENTITY);
        }
    }

    bool bo_no_cache = false;
    if (bo_do_sso) { // the browser shall not cache the SSO-login-page to avoid, that one user can see the password of another user in browser cahce
        bo_no_cache = true;
    }
    // Ticket[17845]
    if ( ads_session->dsc_auth.m_is_caching_allowed() == false ) {
        bo_no_cache = true;
    }

    // Ticket[17845]:
    if ( bo_no_cache == true ) {
        // send no cache header fields and ignore original cache-control and pragma header fields
        if (ads_session->dsc_http_hdr_in.in_http_version == ds_http_header::ien_http_version_11) { // cache control only supported by HTTP/1.1
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CACHE_CONTROL, "no-cache");
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CACHE_CONTROL, "max-age=0, no-store");
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CACHE_CONTROL, "must-revalidate");
        }
        // for HTTP/1.0
        ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_PRAGMA, "no-cache");
    }
    else {
        // insert original cache-control and pragma header fields
        for (HVECTOR_FOREACH(ds_hstring, adsl_cur, ads_session->dsc_http_hdr_in.ds_v_hf_cache_control)) {
            const ds_hstring& hstr_tmp = HVECTOR_GET(adsl_cur);
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_CACHE_CONTROL, hstr_tmp.m_const_str());
        }
        if (ads_session->dsc_http_hdr_in.hstr_hf_pragma.m_get_len() > 0) {
            ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_PRAGMA, ads_session->dsc_http_hdr_in.hstr_hf_pragma.m_const_str());
        }
        //ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_EXPIRES, "Mon, 01 Jan 2018 00:00:00 GMT");
    }

#if 1
	 dsd_const_string hstr_hf_x_ua_compatible = ads_session->dsc_http_hdr_in.hstr_hf_x_ua_compatible.m_const_str();
	 ds_hstring hstr_hf_x_ua_compatible2(ads_session->ads_wsp_helper);
	 ds_interpret_html::m_filter_xua_compatible(hstr_hf_x_ua_compatible, hstr_hf_x_ua_compatible2);
	 ads_session->dsc_http_hdr_out.m_add_hdr_line_out(HF_X_UA_COMPATIBLE, hstr_hf_x_ua_compatible2.m_const_str());
#endif

    // write unprocessed header-lines
    ds_hstring hstr_unprocessed = ads_session->dsc_http_hdr_in.m_get_unprocessed_headerlines();
    ads_session->dsc_http_hdr_out.m_add_hdr_unprocessed_lines_out(&hstr_unprocessed);

    // write HEADER-END
    ads_session->dsc_http_hdr_out.m_terminate_hdr_out();

    // send the header
	ds_control::states in_next_state = ds_control::ien_st_body_sent_to_browser;
#if 0
	if (ads_session->in_http_method_last_request == ds_http_header::ien_meth_HEAD) { // HEAD must not send a body !!
        in_next_state = ds_control::ien_st_sending_to_browser;
    }
#endif
	if(bo_message_body_announced) {
		in_next_state = ds_control::ien_st_wsg_sending_header_of_data_to_browser;
	}

    // Ticket[14835]: RFC2616-8.2.3 states, that "for compatibility with RFC 2068, a server MAY send a 100 (Continue)
    // status in response to an HTTP/1.1 PUT or POST request that does not include an Expect request-header field with the "100-continue" expectation."
    if ( (ads_session->dsc_http_hdr_in.in_http_status_code == ds_http_header::ien_status_continue)
      && (ads_session->dsc_http_hdr_in.in_http_version == ds_http_header::ien_http_version_11)
      && ((ads_session->in_http_method_last_request == ds_http_header::ien_meth_POST) || (ads_session->in_http_method_last_request == ds_http_header::ien_meth_PUT) )
       ) {
#if 0
        in_next_state = ds_control::ien_st_waiting_for_header_from_webserver;
#endif
		ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                            "HIWSI785I: two consecutive server-responses including '100 Continue'" );
		// SM-NEW - Don't change the state
		return 0;
    }

	if (this->boc_websocket_upgrade && ads_session->dsc_http_hdr_in.in_http_status_code == ds_http_header::ien_status_switching_protocols) {
		this->boc_websocket_protocol = true;
	}

    ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
	ads_session->dsc_control.m_set_ctrl_state(in_next_state);
    return 0;
} // m_handle_response_header

/**
 * @ingroup webservergate
 *
 * @param [in]	bo_data_until_close		All remaining data until the connection is closed represents the message-body.
 *										When this bool flag is false, no data will be sent to the client
 * @param [in]	bo_send					When this flag is FALSE, it implies that we only want to read the data.
 *
 * @return	An int value is returned. When the return value is 0 it means that we have to wait for more data 
 *			(0 means: more data outstanding; because we don't know the data-end!). When the value is smaller
 *			than 0, it means that there was an error.
 *
 **
*/
int ds_ws_gate::m_handle_response_data(bool bo_data_until_close, bool bo_send)
{
    int in_content_length = 0;

	ds_interpret* adsl_interpreter = this->adsc_interpreter;
	if(this->bo_skip_response_data) {
		bo_send = false;
	}

    if (bo_data_until_close) { // all remaining data until the connection is closed represent the message-body
        // determine, whether the data have to be changed by WSG
        if (adsl_interpreter == NULL) { 
            //---------------------------
            // pass data unchanged to client
            //---------------------------
            ads_session->dsc_transaction.m_pass_all_available_data(bo_send);
            if (ads_session->dsc_transaction.ads_trans->boc_eof_server) { // webserver closed connection -> all data are processed now
                if(ads_session->dsc_transaction.ads_trans->adsc_gai1_out_to_client != NULL)
                    ads_session->dsc_transaction.ads_trans->boc_callagain = TRUE;
                return 10;
            }
            return 0; // we don't know, whether data are complete, so we return 0 (means: not all data processed) and don't set the state forward
        }

        ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                            "HIWSI821I: data to <interpreter>.m_process_data() (bo_data_until_close) - don't send chunked data" );
        int in_ret = m_call_interpreter(ds_ws_gate::ien_data_until_close, ads_session->dsc_http_hdr_out.bo_hdr_chunked_set);
        if (in_ret < 0) { // error
            return -110;
        }
        if (!ads_session->dsc_transaction.ads_trans->boc_eof_server) {
            ads_session->dsc_transaction.m_send_chunked_flush(ied_sdh_dd_toclient);
            // 0 means: more data outstanding; because we don't know the data-end!
            return 0;
        }
        // webserver closed connection -> all data are processed now
        if(ads_session->dsc_http_hdr_out.bo_hdr_chunked_set) {
            ads_session->dsc_transaction.m_send_chunked_end(ied_sdh_dd_toclient);
            return 10;
        }
        if(ads_session->dsc_transaction.ads_trans->adsc_gai1_out_to_client != NULL)
            ads_session->dsc_transaction.ads_trans->boc_callagain = TRUE;
        return 10;
    }

    // message-body is announced by 'chunked' or 'Content-Length'
    if (ads_session->dsc_http_hdr_in.m_is_chunked()) { // chunked data
        // determine, whether the data have to be changed by WSG
        if (adsl_interpreter == NULL) {

            if (!bo_send) { // We only want to read the whole data.
                ads_session->ads_wsp_helper->m_log( ied_sdh_log_error,
                                            "HIWSE822E: Chunked data are not supported, when reading a complete response from extrenal webserver." );
                return 1; // Signals, that all is done.
            } 

            //---------------------------
            // pass chunked data unchanged to client
            //---------------------------
            return m_pass_chunked_unchanged();
        }

        //---------------------------
        // the data have to be investigated
        //---------------------------
        return m_interpret_chunked();

    }
    
    // Content-length
    in_content_length = ads_session->dsc_http_hdr_in.m_get_content_length();
    if (!bo_send && (in_content_length == 0) ) {
        return 1; // Signals, that all is done.
    }
    if (in_content_length < 1) {
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_error,
                                            "HIWSE730E: Invalid content-length detected" );
        return -1;
    }
    if (in_len_to_send_unchanged_to_browser == 0) { // this is the first sending 
        in_len_to_send_unchanged_to_browser = in_content_length;
    }
    // determine, whether the data have to be changed by WSG
    if (adsl_interpreter == NULL) { 
        //---------------------------
        // pass data unchanged to client
        //---------------------------
        if (in_len_to_send_unchanged_to_browser > 0) { // to avoid copying of data, we write the pointers into workarea
            int in_len_passed_data = ads_session->dsc_transaction.m_pass_data(in_len_to_send_unchanged_to_browser, bo_send);
            if (in_len_passed_data < 0) { // error occurred
                return -2;
            }
            // in_len_passed_data were passed to browser -> diminish the outstanding data
            in_len_to_send_unchanged_to_browser = in_len_to_send_unchanged_to_browser - in_len_passed_data;
            if (in_len_to_send_unchanged_to_browser < 0) {
                ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                                     "HIWSE731E: %d <---> %d",
                                                     in_len_passed_data,
                                                     (in_len_to_send_unchanged_to_browser-in_len_passed_data) );
                return -17;
            }
            if (in_len_to_send_unchanged_to_browser > 0) { // no or not all data available/were sent to browser -> we must wait for more data
                return 0;
            }
            // in_len_to_send_unchanged_to_browser is 0: all data are passed to client
            /*if (bo_send) {
                ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_wsg_body_sent_to_browser);
            }*/
        }
        return 1;
    }

#if 0
    //---------------------------
    // the data have to be investigated
    //---------------------------
    ads_session->dsc_transaction.bo_resolve_from_chunked_format = false;
    if (ads_session->dsc_transaction.in_len_data_to_deliver == 0) {
        int a = 0;
    }
    if (ads_session->dsc_transaction.in_len_data_to_deliver == -1) {
        ads_session->dsc_transaction.in_len_data_to_deliver = in_content_length;
    }
#endif
    int in_ret = m_call_interpreter(ds_ws_gate::ien_data_content_length, true);
    if (in_ret < 0) { // error
        return -1;
    }

    // reset variables
    //int in_len_written_chunked = ads_session->dsc_transaction.in_len_chunked_out;
    //ads_session->dsc_transaction.bo_placeholder_written = false;
    //ads_session->dsc_transaction.in_len_chunked_out = 0;
    if (ads_session->dsc_transaction.in_len_data_to_deliver == 0) { // all data are processed
        ads_session->dsc_transaction.m_send_chunked_end(ied_sdh_dd_toclient);
        return 1;
    }
    ads_session->dsc_transaction.m_send_chunked_flush(ied_sdh_dd_toclient);
    return 0;
}

/**
 * @ingroup dataprocessor
 *
 * @param[in]   bo_allow_wsp_subdomains     Bool flag to indicate whether to allow wsp subdomains
 *											(true:  Domain will be set to ".wsp.de"; 
 *                                          false: Domain will be set to "www.wsp.de")
*/
static dsd_const_string m_get_cookie_domain( const dsd_const_string& rdsp_hostname, bool bo_allow_wsp_subdomains ) {
    if ( bo_allow_wsp_subdomains ) {
        // remove subdomain
		int in_pos = rdsp_hostname.m_index_of( "." );
        if ( in_pos >= -1 ) {
			return rdsp_hostname.m_substring(in_pos);
        }
    }
    return rdsp_hostname;
} // end of ds_interpret::m_get_cookie_domain

// process the header field 'Set-Cookie'
// adopted from ws3: the section COOKIE_PATH is very mysterious !!
ds_hstring ds_ws_gate::m_change_set_cookie(const dsd_const_string& rdsp_set_cookie)
{
	ds_url::dsd_base_url dsl_wsp_url;
	if(ds_url::m_parse_base_url(ads_session->hstr_prot_authority_ws.m_const_str(), dsl_wsp_url))
		return ds_hstring();
	dsd_const_string dsl_wsp_cookie_domain = m_get_cookie_domain(dsl_wsp_url.dsc_hostname, false);

    int in_pos, in_pos_end;
    dsd_const_string hstr_org_domain_value("");

    ds_hstring dsl_tmp_set_cookie(ads_session->ads_wsp_helper);
    dsd_const_string ahstr_set_cookie = rdsp_set_cookie;
    // remove an existing "domain" option, because the original domain will never match to WSP-Proxy Domain
    const dsd_const_string dsl_cookie_domain(COOKIE_DOMAIN);
    in_pos = rdsp_set_cookie.m_index_of_ic(dsl_cookie_domain);
    if (in_pos != -1) {
        in_pos_end = rdsp_set_cookie.m_index_of(in_pos, ";");
        if(in_pos_end < 0)
            in_pos_end = rdsp_set_cookie.m_get_len();
        hstr_org_domain_value = rdsp_set_cookie.m_substring(in_pos + dsl_cookie_domain.m_get_len(), in_pos_end);
        ds_hstring hstr_domain(ads_session->ads_wsp_helper, dsl_cookie_domain);
        hstr_domain.m_write(dsl_wsp_cookie_domain);
        hstr_domain.m_write(";");
        // remove domain option from str_set_cookie_org
        dsl_tmp_set_cookie = rdsp_set_cookie.m_substr(0, in_pos);
        dsl_tmp_set_cookie += hstr_domain;
        if (in_pos_end >= 0) {
            dsl_tmp_set_cookie += rdsp_set_cookie.m_substring(in_pos_end+1);
        }
        ahstr_set_cookie = dsl_tmp_set_cookie.m_const_str();
    }

    // - write new cookie-path
    // - cookie domain will be removed
    const dsd_const_string dsl_cookie_path(COOKIE_PATH);
    in_pos = ahstr_set_cookie.m_index_of_ic(dsl_cookie_path);
    if (in_pos == -1) {
        return ds_hstring(ads_session->ads_wsp_helper, ahstr_set_cookie);
    }

    // Ticket[13202]: improved handling of Set-Cookie: the path contains a URL, which must be changed as all other URLs
    // get cookie-path, which can be terminated by
    //        1) ';': attributes follow 
    //        2) ',': other cookies follow
    //        3) CRLF
    // 
    dsd_const_string hstr_cookie_path = ahstr_set_cookie.m_substring(in_pos + dsl_cookie_path.m_get_len());
    int in_terminator = hstr_cookie_path.m_find_first_of(",;");
    if (in_terminator != -1) {
        hstr_cookie_path = hstr_cookie_path.m_substring(0, in_terminator);
    }
    ds_hstring ds_cookie_path(ads_session->ads_wsp_helper);
    // str_cookie_path contains an URL, which must be changed by WSG
    if ( (hstr_org_domain_value[0] != '.') && !bo_ignore_interpreter ) {
		if(dsc_interpret_html.m_change_url( hstr_cookie_path, ds_interpret::ied_change_url_flags_default, ds_cookie_path ) == ds_interpret::ied_change_url_changed)
			hstr_cookie_path = ds_cookie_path.m_const_str();
    } else {
        hstr_cookie_path = "/";
    }
    ds_hstring hstr_ret_set_cookie(ads_session->ads_wsp_helper, ahstr_set_cookie.m_substring(0, in_pos));
    hstr_ret_set_cookie.m_write(dsl_cookie_path);
    hstr_ret_set_cookie += hstr_cookie_path;

    int in_pos_base = ahstr_set_cookie.m_index_of(in_pos+1, ";");
    if (in_pos_base != -1) { // if there is another cookie-option -> write it to header as well
        hstr_ret_set_cookie += ahstr_set_cookie.m_substring(in_pos_base);
    }
    return hstr_ret_set_cookie;
}

/**
 *
 * ds_ws_gate::m_clear
 *
 * @return	Returns 0
 *
 **
*/
int ds_ws_gate::m_clear(void)
{
	this->adsc_interpreter = NULL;
    this->in_len_to_send_unchanged_to_browser = 0;
    this->in_len_to_send_unchanged_to_server = 0;
	this->boc_websocket_upgrade = false;
	this->boc_websocket_protocol = false;
    return 0;
}


// send received chunked data unchanged to browser in chunked format
int ds_ws_gate::m_send_chunked_unchanged(void)
{
    const char* ach_data;
    int   in_len_data;
    int   in_data_complete = 0;
    int   in_data_written  = 0;

    while (in_data_complete == 0) {
        ach_data = NULL;
        in_len_data = -1;
        in_data_complete = ads_session->dsc_transaction.m_get_data(&ach_data, &in_len_data, false);
		if(in_data_complete < 0)
			return in_data_complete;
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                             "ds_wsg_gate: m_get_data() returned %d",
                                             in_len_data );

        if ( (ach_data == NULL) || (in_len_data == -1) ) { // no data available
            break;
        }
        ads_session->dsc_transaction.m_write_as_chunked(ach_data, in_len_data, true, ied_sdh_dd_auto, false, in_data_complete > 0);
        in_data_written = 1;
    }
    return in_data_written;
}

// call the concerned interpreter-class, which will e.g. change hyperlinks
int ds_ws_gate::m_call_interpreter(int in_data_mode, bool bo_send_as_chunked)
{
	if(this->boc_interpret_failed) {
		ads_session->dsc_transaction.m_pass_all_available_data(false);
		ads_session->dsc_transaction.ads_trans->inc_return = DEF_IRET_ERRAU;
		return 0;
	}
	if(this->bo_skip_response_data) {
		int   in_data_complete = 0;
		while (in_data_complete == 0) {
			const char* ach_data;
			int   in_len_data;
			in_data_complete = ads_session->dsc_transaction.m_get_data(&ach_data, &in_len_data, false);
			if(in_data_complete < 0)
				return in_data_complete;
			if ( (ach_data == NULL) || (in_len_data == -1) ) { // no data available
				break;
			}
		}
		return in_data_complete;
	}
    int in_content_type = ads_session->dsc_http_hdr_in.m_get_content_type();
	ds_hstring hstr_msg(ads_session->ads_wsp_helper, "HIWSI820I: data to <interpreter>.m_process_data() content-type: ");
    hstr_msg.m_writef("%d  in_data_mode: %d", in_content_type, in_data_mode);
    if (!bo_send_as_chunked) {
        hstr_msg.m_write(" don't send chunked data");
    }
    ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, hstr_msg.m_const_str() );
	int in_ret = this->adsc_interpreter->m_process_data();
    if (in_ret < 0) { // error
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                             "HIWSE861E: <interpreter>.m_process_data() returned error %d",
                                             in_ret );
		ads_session->dsc_transaction.ads_trans->inc_return = DEF_IRET_ERRAU;
		this->boc_interpret_failed = true;
        return -1;
    }

#ifndef NEW_WSP_1102
    // detailed tracings...
    if ( (in_data_mode == ds_ws_gate::ien_data_chunked) || (in_data_mode == ds_ws_gate::ien_data_content_length) ) {
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
            "HIWSI831I: <interpreter>.m_process_data() returned %d  ads_session->dsc_transaction.in_len_data_to_deliver: %d",
            in_ret, ads_session->dsc_transaction.in_len_data_to_deliver );

        if (in_data_mode == ds_ws_gate::ien_data_content_length) {
        // count bytes of chain of OUTPUT
        int in_output_gath_number = 0;
        int in_len_output = 0;
        if (ads_session->dsc_transaction.ads_trans->adsc_gather_i_1_out != NULL) {
            struct dsd_gather_i_1* ads_gath_tmp = ads_session->dsc_transaction.ads_trans->adsc_gather_i_1_out;
            while (ads_gath_tmp != NULL) {
                in_len_output += (int)(ads_gath_tmp->achc_ginp_end - ads_gath_tmp->achc_ginp_cur);
                ads_gath_tmp = ads_gath_tmp->adsc_next;
                in_output_gath_number++;
            }
        }
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                             "HIWSI7812I: output chain gathers / bytes: %d / %d",
                                             in_output_gath_number, in_len_output );
        }
    }
#endif
    return in_ret;
}

// we received chunked data of a file, which need not to be changed -> pass the data unchanged
int ds_ws_gate::m_pass_chunked_unchanged(void)
{
    int in_ret = m_send_chunked_unchanged();
    if (in_ret < 0) { // error
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                             "HIWSE961E: error during passing unchanged chunked data: %d",
                                             in_ret );
        return -1;
    }
    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                          "HIWSI631I: m_send_chunked_unchanged() returned %d   ads_session->dsc_transaction.in_len_data_to_deliver: %d",
                                          in_ret, ads_session->dsc_transaction.in_len_data_to_deliver );

    if (ads_session->dsc_transaction.in_len_data_to_deliver != 0) { // not all data are processed
        // more data must be processed; data were sent to client -> close the chunked format with CRLF
        in_ret = ads_session->dsc_transaction.m_send_chunked_flush(ied_sdh_dd_toclient);
        if(in_ret < 0)
            return in_ret;
        return 0;
    }
    // terminates chunked format
    in_ret = ads_session->dsc_transaction.m_send_chunked_end(ied_sdh_dd_toclient);
    if(in_ret < 0)
        return in_ret;
    return 1;
}

/**
 * @ingroup webservergate
 *
 * @param [in]	inl_content_type		An int value which defines the type of the data to be sent.
 *
 * @return	FALSE is returned when the content type is not valid for any interpreters or if the bo_ignore_interpreter is set to TRUE 			
 *
 **
*/
ds_interpret* ds_ws_gate::m_get_interpreter(int inp_http_content_type) {
    if (bo_ignore_interpreter) {
        return NULL;
    }

	// TODO: Use "X-Content-Type-Options: nosniff"

    int inl_content_type = inp_http_content_type;
	// if there was an HOB_type -> we must use it
    if (this->dsc_url.in_hob_type != ien_hobtype_not_defined) { // we must send this file to the specified parser
        // (e.g. when webserver sent a script file with the WRONG mime-type 'html'
		switch(this->dsc_url.in_hob_type) {
		case ien_hobtype_js:
            // there is unsureness, whether we shall correct the content-type, which we received from server
            // there might arise problems for the case that the webserver (correctly) sent "application/javascript"
            // -> then we would change to "text/javascript"
            inl_content_type = ds_http_header::ien_ct_application_javascript;
			break;
        case ien_hobtype_css:
            // there is unsureness, whether we shall correct the content-type, which we received from server
            inl_content_type = ds_http_header::ien_ct_text_css;
			break;
		case ien_hobtype_html:
            // there is unsureness, whether we shall correct the content-type, which we received from server
            inl_content_type = ds_http_header::ien_ct_text_html;
			break;
        }
    }
	if ( (inl_content_type >= ds_http_header::ien_ct_not_set/*ien_ct_unknown*/) && (inl_content_type < ds_http_header::ien_ct_text_html) ) {
        return NULL;
    }
    int inl_hobtype = this->dsc_url.in_hob_type;
LBL_AGAIN:
    switch(inl_content_type) {
    case ds_http_header::ien_ct_application_javascript: // application-javascript-file
    //case ds_http_header::ien_ct_application_json:
	{
        if(inl_hobtype != ien_hobtype_js)
           return NULL;
		switch(this->ads_session->dsc_http_hdr_in.in_http_status_code) {
        case 200:
            break;
        case 404:
			goto LBL_HTTP_FAILED;
        default:
			switch(inp_http_content_type) {
			case ds_http_header::ien_ct_not_set:
			case ds_http_header::ien_ct_application_javascript:
				break;
			default:
				goto LBL_HTTP_FAILED;
			}
        }
		switch(inp_http_content_type) {
		case ds_http_header::ien_ct_not_set:
		case ds_http_header::ien_ct_application_javascript:
		case ds_http_header::ien_ct_text_plain:
			break;
		default:
			ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
                "HIWSW630W unexpected content type '%.*s'",
				ads_session->dsc_http_hdr_in.hstr_hf_content_type.m_get_len(),
				ads_session->dsc_http_hdr_in.hstr_hf_content_type.m_get_ptr());
			break;
		}
		ied_charset iel_content_type_charset = ads_session->dsc_http_hdr_in.iec_content_type_charset;
		if(iel_content_type_charset == ied_chs_invalid)
            iel_content_type_charset = this->dsc_url.iec_hob_type_charset;
        if(iel_content_type_charset == ied_chs_invalid)
            iel_content_type_charset = ied_chs_utf_8;
        this->dsc_interpret_script.m_init(
            iel_content_type_charset, NULL, ds_interpret_script::IMC_FLAG_TOP_LEVEL);
		return &this->dsc_interpret_script;
	}
    case ds_http_header::ien_ct_text_css:
        if(inl_hobtype != ien_hobtype_css)
           return NULL;
        return &this->dsc_interpret_css;
    case ds_http_header::ien_ct_text_html:
    case ds_http_header::ien_ct_text_x_component:
	case ds_http_header::ien_ct_application_xhtml: {
		switch(inl_hobtype) {
		case ien_hobtype_any:
		case ien_hobtype_not_defined:
		case ien_hobtype_html:
			break;
		default:
			return NULL;
		}
		ied_charset iel_content_type_charset = ads_session->dsc_http_hdr_in.iec_content_type_charset;
        if(iel_content_type_charset == ied_chs_invalid)
            iel_content_type_charset = this->dsc_url.iec_hob_type_charset;
#if 0
        if(iel_content_type_charset == ied_chs_invalid)
            iel_content_type_charset = ied_chs_utf_8;
#endif
		this->dsc_interpret_html.m_init();
		this->dsc_interpret_html.m_set_content_type(ads_session->dsc_http_hdr_in.m_get_content_type());
		this->dsc_interpret_html.m_set_charset(iel_content_type_charset);
		return &this->dsc_interpret_html;
	}
    case ds_http_header::ien_ct_application_x_java_jnlp_file:
		return &this->dsc_interpret_xml;
	case ds_http_header::ien_ct_text_xml:
		return &this->dsc_interpret_xml;
    case ds_http_header::ien_ct_application_x_ica:
		return &this->dsc_interpret_ica;
	default:
		break;
    }
    return NULL;
LBL_HTTP_FAILED:
	if(inp_http_content_type == inl_content_type)
		return NULL;
	inl_hobtype = ien_hobtype_not_defined;
	inl_content_type = inp_http_content_type;
    goto LBL_AGAIN;
}

// call interpreter-class for received data in chunked format
int ds_ws_gate::m_interpret_chunked()
{
#if 0
    ads_session->dsc_transaction.bo_resolve_from_chunked_format = true;

    // in_len_data_to_deliver will be set to 0 by transaction-class, when all chunked data are processed
    ads_session->dsc_transaction.in_len_data_to_deliver = -1;
    ads_session->dsc_transaction.bo_read_chunked_data_done = false;
#endif   
    //ds_hstring hstr_chunked_end(ads_session->ads_wsp_helper, CRLF); // terminates the (last) datablock
    int in_ret = m_call_interpreter(ds_ws_gate::ien_data_chunked, true);
    if (in_ret < 0) { //
        return -1;
    }
#if 0
    if (in_ret == 0) { // no data were written to output
        if (ads_session->dsc_transaction.in_len_data_to_deliver != 0) { // more data must be received
            return 0;
        }
        // scenario: html-page is done; we received 0x30 0x0D 0x0A 0x0D 0x0A from webserver -> then we must not terminated data with CRLF !!
        if (ads_session->dsc_transaction.bo_read_chunked_data_done) {
            hstr_chunked_end.m_reset();
        }
    }
#endif
    if (ads_session->dsc_transaction.in_len_data_to_deliver != 0) { // not all data are processed
        // more data must be processed; data were sent to client -> close the chunked format with CRLF
        in_ret = ads_session->dsc_transaction.m_send_chunked_flush(ied_sdh_dd_toclient);
        if(in_ret < 0)
            return in_ret;
        return 0;
    }
    // terminates chunked format
    in_ret = ads_session->dsc_transaction.m_send_chunked_end(ied_sdh_dd_toclient);
    if(in_ret < 0)
        return in_ret;
    return 1;
}

static bool m_matches_origin(const struct ds_ws_gate::dsd_wsg_url& rdsp_wsg_url, ds_url::dsd_base_url& rdp_other_url) {
	dsd_const_string hstr_entry_port = ds_url::m_get_valid_port(rdp_other_url);
	/* AKre 19.12.2012: not case-sensitive: we need
    * m_cmpi_vx_vx which is comparing everything in lowercases
    */
	if(rdsp_wsg_url.hstr_protocol.m_equals(rdp_other_url.dsc_protocol)
		&& hstr_entry_port.m_equals(rdsp_wsg_url.hstr_port_of_webserver)
		&& rdp_other_url.dsc_hostname.m_equals_ic(rdsp_wsg_url.hstr_hostname_of_webserver))
	{
		return true;
	}
	return false;
}

bool ds_ws_gate::m_is_sso(void)
{
    // reset container
    ads_session->ds_v_sso_ids.m_clear();

    // Loop thru pages and compare their URLs with the URL requested by browser.
    // The comparison supports both: url with and without a trailing "/".
	 dsd_const_string hstr_path = this->dsc_url.hstr_path;;

    dsd_page* adsl_page_curr = ads_session->ads_config->dsl_sso.adsc_page;
    int i = 0;
    while (adsl_page_curr != NULL) {
        dsd_const_string dsl_url(adsl_page_curr->achc_url, adsl_page_curr->inc_len_url);
        // the URL matches one of the configured SSO-urls
        if ( m_matches_origin(this->dsc_url, adsl_page_curr->dsc_url)
			    && hstr_path.m_equals_ic(adsl_page_curr->dsc_url.dsc_path) )
        {   
            // check whether there was a SSO procedure not long ago; if there was one, then do not process SSO again
            // this will avoid an endless loop: in the case that the SSO fails, we would try and try to set the credentials into the loginpage !!
            hl_time_t ds_tm_suppress = ads_session->dsc_auth.m_get_sso_time( i );
            hl_time_t ltime_current = ads_session->ads_wsp_helper->m_cb_get_time(); // get current time
            if (ltime_current < ds_tm_suppress) { // we must suppress SSO
                return false;
            }

            // Do SSO procedure.
            // Fill a vector with the IDs, which must be processed by SSO-procedure
            dsd_id* ads_id_curr = adsl_page_curr->adsc_ids;
            while (ads_id_curr != NULL) {
                ds_id dsl_id;
                dsl_id.m_setup(ads_session->ads_wsp_helper);
                // name
                dsl_id.m_set_name(dsd_const_string(ads_id_curr->achc_name, ads_id_curr->inc_len_name));
                // value
                dsl_id.m_set_value(dsd_const_string(ads_id_curr->achc_value, ads_id_curr->inc_len_value));
                // type
                dsl_id.m_set_type(dsd_const_string(ads_id_curr->achc_type, ads_id_curr->inc_len_type));
                ads_session->ds_v_sso_ids.m_add(dsl_id);

                ads_id_curr = ads_id_curr->adsc_next;
            }
            
            // set this value local and in CMA
            hl_time_t ds_tm_to_set = ltime_current + TIME_TO_SUPPRESS_SSO; // seconds
            ads_session->dsc_auth.m_set_sso_time( i, ds_tm_to_set );

            return true;
        }
        adsl_page_curr = adsl_page_curr->adsc_next;
        i++;
    }

    return false;
}

//bool ds_ws_gate::m_get_ignore_interpreter(ds_hstring* ahstr_org_url, ds_hstring* ahstr_target_url)
bool ds_ws_gate::m_is_virtual_link(const dsd_const_string& rhstr_org_url, const dsd_const_string& rhstr_target_url)
{
    /*
        we will ignore wsg for all virtual links!
    */
    struct dsd_virtual_link *adsl_cur;
    adsl_cur = ads_session->ads_config->adsl_vi_lnk;

    while ( adsl_cur != NULL ) {
        if ( rhstr_target_url.m_index_of( dsd_const_string(adsl_cur->ach_alias, adsl_cur->in_len_alias) ) >= 0 ) {
            ads_session->ads_wsp_helper->m_logf(ied_sdh_log_info,
                                                "HWSGI698I: ignoring interpreter for url '%.*s'",
                                                rhstr_target_url.m_get_len(),
                                                rhstr_target_url.m_get_ptr() );
            return true;
        }

        if ( rhstr_org_url.m_index_of( dsd_const_string(adsl_cur->ach_path, adsl_cur->in_len_path) ) >= 0 ) {
            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                                 "HWSGI699I: ignoring interpreter for url '%.*s'",
                                                 rhstr_org_url.m_get_len(),
                                                 rhstr_org_url.m_get_ptr() );
            return true;
        }
        adsl_cur = adsl_cur->adsc_next;
    }
    return false;
}


/**
 * private method ds_ws_gate::m_is_ica_srv
 *  check if given server is an ica server
 *
 * @param[in]   const char  *achp_srv       server url
 * @param[in]   int         inp_len_srv     length of server url
 * @param[in]   const char  *achp_path      server path
 * @param[in]   int         inp_len_path    length of path
 * @return      bool                        true = is ica srv
 *                                          false otherwise
*/
bool ds_ws_gate::m_is_ica_srv()
{
    /*
        check role
    */
    struct dsd_role* adsl_role = ads_session->dsc_auth.m_get_role();
    if (    adsl_role == NULL
         || adsl_role->adsc_ws_srv_list == NULL ) {
        /* no role or now allowed server entries */
        return false;
    }

	dsd_const_string dsl_path = this->dsc_url.hstr_path;

    /*
        check path
    */
    struct dsd_named_list* adsl_path = ads_session->ads_config->adsc_ica_session_pages;
    while ( adsl_path != NULL ) {
		if(dsl_path.m_starts_with(dsd_const_string(adsl_path->achc_name, adsl_path->inc_len_name))) {
            break;
        }
        adsl_path = adsl_path->adsc_next;
    } /* end of loop over session pages */

    if ( adsl_path == NULL ) {
        return false;
    }
    
	 dsd_const_string hstr_path = this->dsc_url.hstr_path;
    struct dsd_ws_srv_lst* adsl_srv_lst = ads_session->ads_config->adsc_ws_srv_lst;
    for ( ; adsl_srv_lst != NULL; adsl_srv_lst = adsl_srv_lst->adsc_next ) {
        /*
            check if this server list is allowed by role
        */
        bool bol_allowed  = false;
        struct dsd_aux_conf_servli_1* adsl_allowed = adsl_role->adsc_ws_srv_list;
        while ( adsl_allowed != NULL ) {
			int inl_comp;
			BOOL bol_ret = m_cmp_vx_vx( &inl_comp,
                                   adsl_srv_lst->achc_name,
                                   adsl_srv_lst->inc_len_name,
                                   ied_chs_utf_8,
                                   adsl_allowed->dsc_servli_name.ac_str,
                                   adsl_allowed->dsc_servli_name.imc_len_str,
                                   adsl_allowed->dsc_servli_name.iec_chs_str  );
            if ( bol_ret == TRUE
                 && inl_comp == 0 ) {
                bol_allowed = true;
                break;
            }
            adsl_allowed = adsl_allowed->adsc_next;
        }
		if(!bol_allowed)
			continue;

        /*
            check if a server entry inside server list matches
        */
        struct dsd_ws_srv_entry* adsl_srv_ety = adsl_srv_lst->adsc_entries;
        for ( ; adsl_srv_ety != NULL; adsl_srv_ety = adsl_srv_ety->adsc_next ) {
            if (adsl_srv_ety->iec_func != ied_ws_srv_func_ica)
					continue;
				if(!m_matches_origin(this->dsc_url, adsl_srv_ety->dsc_url))
					continue;
				dsd_const_string hstr_entry_port = ds_url::m_get_valid_port(adsl_srv_ety->dsc_url);
				  /* AKre 19.12.2012: not case-sensitive: we need
					 * m_cmpi_vx_vx which is comparing everything in lowercases
					 */
				if(hstr_path.m_starts_with_ic(adsl_srv_ety->dsc_url.dsc_path)) {
					return true;
				}
        } /* end of loop over server entries */
    } /* end of loop over server lists */

    return false;
} /* end of ds_ws_gate::m_is_ica_srv */


