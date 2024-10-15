#include "ds_session.h"

#include "ds_http_header.h"
#include "ds_url_parser.h"
#include <ds_wsp_helper.h>

#define HTTP_VERSION_PREFIX  "HTTP/"


// must be conform with 'enum http_methodes' in ds_http_header.h !!!
static const dsd_const_string HTTP_METHODS[] =
{
    "GET",                
    "HEAD",
    "POST",
    "PUT",
    "OPTIONS",
    "DELETE",
    "TRACE",
    "CONNECT",
    //---------  BEGIN WEBDAV Methods ----------------------
    "BDELETE",
    "BMOVE",
    "BPROPPATCH",
    "COPY",
    "LOCK",
    "MKCOL",
    "MOVE",
    "POLL",
    "PROPFIND",
    "PROPPATCH",
    "SUBSCRIBE",
    "SEARCH",

    // eh: 22.03.07 keep attention to the appropriate values of "enum HeaderCommand"
    "BCOPY",
    /*"BDELETE",*/
    /*"BMOVE",*/
    "BPROPFIND",
    /*"BPROPPATCH",*/
    /*"COPY",*/
    "DELETE",
    /*"LOCK",*/
    /*"MKCOL",*/
    /*"MOVE",*/
    "NOTIFY",
    /*"POLL",*/
    /*"PROPFIND",*/
    /*"PROPPATCH",*/
    /*"SEARCH",*/
    /*"SUBSCRIBE",*/
    "UNLOCK",
    "UNSUBSCRIBE",
    "X-MS-ENUMATTS"
    //---------- END   WEBDAV Methods -----------------
};



ds_http_header::ds_http_header(void)
:in_http_version_webserver(0)
, in_http_status_code(0)
, bo_hdr_chunked_set(false)
, bo_hdr_gzip_set(false)
, ads_session(NULL)
, in_count_lines(0)
, in_http_method(-1)
, in_url_type(-1)
, bo_webserver_response(false)
, in_content_length(-1)
, bo_chunked_data(false)
, in_content_type(ien_ct_not_set)
, iec_content_type_charset(ied_chs_invalid)
, bo_message_body_announced(false)
, in_language(-1)
, in_content_encoding(0)
, bo_cookie_header_exists(false)
{
    // Call the setup-method without a ds_wsp_helper. This will avoid m_alloc inside the ds_hstring
    hstr_hf_accept_language.m_setup(NULL);
    hstr_hf_connection.m_setup(NULL);
    hstr_hf_content_type.m_setup(NULL);
    hstr_hf_host.m_setup(NULL);
    hstr_hf_if_modified_since.m_setup(NULL);
    hstr_hf_location.m_setup(NULL);
    hstr_hf_pragma.m_setup(NULL);
    hstr_hf_referer.m_setup(NULL);
    hstr_hf_user_agent.m_setup(NULL);
    hstr_hf_content_security_policy.m_setup(NULL);
	hstr_hf_content_security_policy_report_only.m_setup(NULL);
	hstr_hf_referrer_policy.m_setup(NULL);
	hstr_hf_x_frame_options.m_setup(NULL);
	hstr_hf_x_ua_compatible.m_setup(NULL);
	hstr_hf_origin.m_setup(NULL);

    m_clear(true);
}

ds_http_header::~ds_http_header(void)
{
}

/*! \brief Class Initializer
 *
 * @ingroup creator
 *
 * Sets up all needed attributes
*/
bool ds_http_header::m_init(ds_session* ads_session_in)
{
    ads_session = ads_session_in;

    // ds_hstring
    hstr_hdr_out.m_init(ads_session->ads_wsp_helper);
    hstr_hdrline_cookie.m_init(ads_session->ads_wsp_helper);
    hstr_http_reason_phrase.m_init(ads_session->ads_wsp_helper);
    hstr_cookie_line_to_webserver.m_init(ads_session->ads_wsp_helper);

    hstr_hf_accept_language.m_init(ads_session->ads_wsp_helper);
    hstr_hf_connection.m_init(ads_session->ads_wsp_helper);
    hstr_hf_content_type.m_init(ads_session->ads_wsp_helper);
    hstr_hf_host.m_init(ads_session->ads_wsp_helper);
    hstr_hf_if_modified_since.m_init(ads_session->ads_wsp_helper);
    hstr_hf_location.m_init(ads_session->ads_wsp_helper);
    hstr_hf_pragma.m_init(ads_session->ads_wsp_helper);
    hstr_hf_referer.m_init(ads_session->ads_wsp_helper);
    hstr_hf_user_agent.m_init(ads_session->ads_wsp_helper);
    hstr_hf_content_security_policy.m_init(ads_session->ads_wsp_helper);
	hstr_hf_content_security_policy_report_only.m_init(ads_session->ads_wsp_helper);
	hstr_hf_referrer_policy.m_init(ads_session->ads_wsp_helper);
	hstr_hf_x_frame_options.m_init(ads_session->ads_wsp_helper);
	hstr_hf_x_ua_compatible.m_init(ads_session->ads_wsp_helper);
	hstr_hf_origin.m_init(ads_session->ads_wsp_helper);

    // ds_hvector
    ds_v_hf_set_cookie.m_init(ads_session->ads_wsp_helper);
    ds_v_hf_cache_control.m_init(ads_session->ads_wsp_helper);
    ds_v_hf_www_authenticate.m_init(ads_session->ads_wsp_helper);
    ds_v_hf_accept_encoding.m_init(ads_session->ads_wsp_helper);
    ds_v_hf_accept_encoding.m_init(ads_session->ads_wsp_helper);
    hstr_hf_content_encoding.m_init(ads_session->ads_wsp_helper);
    //ds_v_hf_content_encoding.m_init(ads_session->ads_wsp_helper);
	 hstr_hf_authorization.m_init(ads_session->ads_wsp_helper);

    dsv_unprocessed_headerlines.m_init(ads_session->ads_wsp_helper);

    // initialize variables of class ds_url, too
    dsc_url.m_init(ads_session->ads_wsp_helper);
    return true;
}

/*! \brief Clear variables
 *
 * @ingroup creator
 *
 * clear variables
*/
int ds_http_header::m_clear(bool bo_all)
{
	 hstr_hdrline_cookie.m_reset();

    in_content_type = ien_ct_not_set;
    iec_content_type_charset = ied_chs_invalid;
    in_language = -1;
    in_content_encoding = 0;
    in_count_lines = 0;
    in_content_length = -1;
    in_http_version_webserver = 0;
    in_http_status_code = 0;
    in_http_method = -1;
    in_url_type = -1;
    bo_webserver_response = false;
    bo_hdr_chunked_set = false;
    bo_hdr_gzip_set = false;
    bo_chunked_data = false;
    bo_message_body_announced = false;
    bo_cookie_header_exists = false;
	bo_upgrade_websocket = false;
    dsv_unprocessed_headerlines.m_clear();
    hstr_hf_accept_language.m_set("");
    hstr_hf_connection.m_set("");
    hstr_hf_content_type.m_set("");
    hstr_hf_host.m_set("");
    hstr_hf_if_modified_since.m_set("");
    hstr_hf_location.m_set("");
    hstr_hf_pragma.m_set("");
    hstr_hf_referer.m_set("");
    hstr_hf_user_agent.m_set("");
    hstr_hf_content_security_policy.m_set("");
	hstr_hf_content_security_policy_report_only.m_set("");
	hstr_hf_referrer_policy.m_set("");
	hstr_hf_x_frame_options.m_set("");
	hstr_hf_x_ua_compatible.m_set("");
	hstr_hf_origin.m_set("");

    ds_v_hf_set_cookie.m_clear();
    ds_v_hf_cache_control.m_clear();
    ds_v_hf_www_authenticate.m_clear();
    ds_v_hf_accept_encoding.m_clear();
    hstr_hf_accept_encoding.m_reset();
    //ds_v_hf_content_encoding.m_clear();    
    hstr_hf_content_encoding.m_reset();
	 hstr_hf_authorization.m_reset();

    if(bo_all)
        dsc_url.m_clear(true);

    return 0;
}

/*! \brief Parse the first header line
 *
 * @ingroup creator
 *
 * investigate first line of header ("start-line") for correctness, HTTP-version, etc
*/
bool ds_http_header::m_parse_start_line(const dsd_const_string& ahstr_start_line)
{
    in_count_lines++;

    // request-line (from browser) and status-line (response from server) both have 3 items
    // request: Method, URL, HTTP-version
    // response: HTTP-version, Status-Code, Reason-Phrase
    // Attention: start-line of ws-response can contain more than 3 tokens (e.g. 4 tokens in "HTTP/1.0 302 Moved Temporarily")
    // a huge response string was seen in WebFile!!!!
    ds_hvector<dsd_const_string> ads_v_tokens(ads_session->ads_wsp_helper);
    if (ads_session->dsc_helper.m_tokenize(ahstr_start_line, " \t", &ads_v_tokens, false, false, false) <= 1) { // at least 2 tokens are expected!
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                             "HIWSE321E: first headerline seems to be invalid: %.*s",
                                             ahstr_start_line.m_get_len(), ahstr_start_line.m_get_ptr() );
        return false;
    }

    // if first token starts with 'HTTP', it's a response
    const dsd_hvec_elem<dsd_const_string>* adsl_cur_token = ads_v_tokens.m_get_first_element();
    const dsd_const_string& hstr_first_token = adsl_cur_token->dsc_element;
    adsl_cur_token = adsl_cur_token->ads_next;
    const dsd_const_string& hstr_second_tok = adsl_cur_token->dsc_element;
    adsl_cur_token = adsl_cur_token->ads_next;
    if ( (ads_session->dsc_transaction.ads_trans->inc_func == DEF_IFUNC_FROMSERVER)  // JF 17.12.09: In former times inc_func was not usable for this decision. With newer WSPs it can be used.
        && hstr_first_token.m_starts_with_ic(HTTP_VERSION_PREFIX) ) {
        //-------------------------//
        // it is a server-response //
        //-------------------------//
        // get the http-version
        in_http_version_webserver = m_get_http_version(hstr_first_token);
        if (in_http_version_webserver < 10) { // message is already written to console
            return false;
        }

        // get status-code
        if (!hstr_second_tok.m_parse_int(&in_http_status_code)) {
            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                                 "HIWSE323E: Invalid status-code-string detected: %.*s",
                                                 ahstr_start_line.m_get_len(), ahstr_start_line.m_get_ptr() );
            return false;
        }

        // reason-phrase
        hstr_http_reason_phrase.m_reset();
        while (adsl_cur_token != NULL) {
            if(hstr_http_reason_phrase.m_get_len() != 0)
                hstr_http_reason_phrase.m_write(" ");
            hstr_http_reason_phrase.m_write(adsl_cur_token->dsc_element);
            adsl_cur_token = adsl_cur_token->ads_next;
        }

        // set a flag, that this data are a response from a webserver
        bo_webserver_response = true;

        return true;
    }

    //------------------------------------//
    // it is a browser-request or INVALID //
    //------------------------------------//

    //  -> check for valid method (GET, HEAD, etc)
    in_http_method = m_get_index(hstr_first_token);
    if ( (in_http_method < ien_meth_GET) || (in_http_method >= ien_meth_not_supported) ) { 
        // unknown http-method -> INVALID REQUEST!!!
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                             "HIWSE324E: Unknown/invalid http-method: %.*s",
                                             hstr_first_token.m_get_len(), hstr_first_token.m_get_ptr() );

        //----------------------
        // tell browser, that the URL could not be found/read
        // adding a html-page is helpless, because we will not handle the outstanding rest of the http header
        //----------------------
        ads_session->dsc_webserver.m_create_resp_header(ds_http_header::ien_status_not_found, 0,
            NULL, NULL, NULL, true, NULL);
        ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
        return false;
    }
    //ads_session->in_http_method_last_request = in_http_method;

    // parse URL
    ds_url_parser ads_url_parser(ads_session);
    dsc_url.m_clear(true);
	
	dsd_const_string hstr_dummy = hstr_second_tok;
#if 0
	// Use this code to redirect requests to own server
	if(hstr_second_tok.m_equals("/wsg/https://ace-cdn.atlassian.com/stp/current/analytics/js/atl-analytics.min.js?HOB_type=js,charset=utf-8")) {
		hstr_dummy = "/wsg/https://hobc02k.hob.de/martin/wsg/atlassian/analytics.min-formatted.js?HOB_type=js,charset=utf-8";
	}
	if(hstr_second_tok.m_equals("/wsg/https://ace-cdn.atlassian.com/stp/current/analytics/js/atl-analytics.min.js?HOB_type=js,charset=utf-8")) {
		hstr_dummy = "/wsg/https://hobc02k.hob.de/martin/wsg/atlassian/atl-analytics.min-formatted.js?HOB_type=js,charset=utf-8";
	}
	if(hstr_second_tok.m_equals("/wsg/https://www.atlassian.com/sc-shared/scripts/48e0ff7d1d06.od.scripts.min.js?HOB_type=js,charset=utf-8")) {
		hstr_dummy = "/wsg/https://hobc02k.hob.de/martin/wsg/atlassian/48e0ff7d1d06.od.scripts.min-formatted.js?HOB_type=js,charset=utf-8";
	}
#endif
    int in_ret = ads_url_parser.m_parse(dsc_url, hstr_dummy);
    if (in_ret < 0) {
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error, 
                                             "HIWSE325E: Invalid URL detected: %.*s (Error: %d).",
                                             hstr_second_tok.m_get_len(), hstr_second_tok.m_get_ptr(), in_ret );

        // Closing the connection is not at once be done by WSP;
        // therefore we send a http-answer, clear the input and try to close the connection
        ads_session->dsc_transaction.m_mark_as_processed(NULL);

        //----------------------
        // tell browser, that the URL could not be found/read
        //----------------------
        ads_session->dsc_webserver.m_send_error_page( ds_http_header::ien_status_not_found, false,
                                                      MSG_INV_URL, ied_sdh_log_error, 325 );
        return false;
    }

    // get the http-version of the browser
    dsd_const_string hstr_version("");
    const dsd_const_string* adsl_version = &hstr_version;
    if (adsl_cur_token != NULL) {
        adsl_version = &adsl_cur_token->dsc_element;
        adsl_cur_token = adsl_cur_token->ads_next;
    }
    in_http_version = m_get_http_version(*adsl_version);
    if (in_http_version < 10) { // message is already written to console
        //----------------------
        // tell browser, that the URL could not be found/read
        // adding a html-page is helpless, because we will not handle the outstanding rest of the http header
        //----------------------
        ads_session->dsc_webserver.m_create_resp_header(ds_http_header::ien_status_not_found, 0,
            NULL, NULL, NULL, true, NULL);
        ads_session->dsc_transaction.m_send_header(ied_sdh_dd_toclient);
		ads_session->dsc_control.m_set_ctrl_state(ds_control::ien_st_body_sent_to_browser);
        return false;
    }

    return true;
}


/*! \brief Get HTTP version
 *
 * @ingroup creator
 *
 * intern
*/
// // get the http-version; return 10=1.0; 11=1.1
int ds_http_header::m_get_http_version(const dsd_const_string& ahstr_http_version)
{
    int in_len_prefix = (int)strlen(HTTP_VERSION_PREFIX);
    if (ahstr_http_version.m_get_len() < (in_len_prefix+3)) {
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                             "HIWSE322E: Invalid HTTP-version-string: %.*s",
                                             ahstr_http_version.m_get_len(), ahstr_http_version.m_get_ptr() );
        return -1;
    }

    dsd_const_string hstr_version = ahstr_http_version.m_substr(in_len_prefix, 3);
    if (hstr_version.m_equals("1.1")) {
        return ds_http_header::ien_http_version_11;
    }
    if (hstr_version.m_equals("1.0")) {
        return ds_http_header::ien_http_version_10;
    }
    // other HTTP-versions are not supported !!
    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                         "HIWSE372E: Unsupported HTTP-version: %.*s",
                                         ahstr_http_version.m_get_len(), ahstr_http_version.m_get_ptr() );
    return -2;
}

/*! \brief Get index
 *
 * @ingroup creator
 *
 * intern
*/
int ds_http_header::m_get_index(const dsd_const_string& ahstr)
{
    return ds_wsp_helper::m_search_equals_ic2(HTTP_METHODS, ahstr, ien_meth_unknown);
}

/*! \brief Header line parser
 *
 * @ingroup creator
 *
 * parse a header-line; fill variables (e.g. int_data_len)
*/
bool ds_http_header::m_parse_header_line(const dsd_const_string& ahstr_header_line)
{
    in_count_lines++;

    // get the 2 tokens: field-name and field-value
    // Attention: the values of the headers, which we must investigate, have only one token !! (e.g. 'key-name: abc def' would have two tokens!)

    ds_hvector<dsd_const_string> ds_v_line_tokens(ads_session->ads_wsp_helper);
    if (ads_session->dsc_helper.m_tokenize(ahstr_header_line, ":", &ds_v_line_tokens, true, true, true) != 2) {
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                             "HIWSE431E: Malformed headerline; token count not equal 2: %.*s",
                                             ahstr_header_line.m_get_len(), ahstr_header_line.m_get_ptr() );
        return false;
    }

    const dsd_const_string& hstr_hdr_key  (ds_v_line_tokens.m_get_first_element()->dsc_element);
    const dsd_const_string& hstr_hdr_value(ds_v_line_tokens.m_get_first_element()->ads_next->dsc_element);

    // Ticket[17898]
    if (hstr_hdr_key.m_get_len() == 0) {
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                             "HIWSE831E: Malformed headerline; first token is empty! %.*s",
                                             ahstr_header_line.m_get_len(), ahstr_header_line.m_get_ptr() );
        return false;
    }

    //--------------------------------------------
    // check for message-length-info (RFC2616-4.4)
    //--------------------------------------------
    // 1) always (!) look for 'Transfer-Encoding: chunked' (has priority over 'Content-Length')
    if (!bo_chunked_data) { 
        if ( hstr_hdr_key.m_equals_ic(HF_TRANSFER_ENCODING) ) {
            // header-field 'Transfer-Encoding' -> read it's value
            if ( hstr_hdr_value.m_equals_ic(HFV_CHUNKED) ) {
                // header-field-value is "chunked"
                bo_chunked_data = true;
                bo_message_body_announced = true;
                return true;
            }
        }
        else { //2) if no chunked data -> look for Content-Length
            if (in_content_length == -1) { // content-length was yet not found
                if ( hstr_hdr_key.m_equals_ic(HF_CONTENT_LENGTH) ) {
                    // header-field 'Content-Length' -> convert the string-value to in_content_length
                    if (!hstr_hdr_value.m_parse_int(&in_content_length)) {
                        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                                              "HIWSE529E: Invalid content-length-value: %.*s",
                                                              hstr_hdr_value.m_get_len(), hstr_hdr_value.m_get_ptr() );
                        return false;
                    }
                    if (in_content_length > 0) {
                        bo_message_body_announced = true;
                    }
                    return true;
                }
            }
        }
    }

    //--------------------------------------------
    // get Content-Type (as string and as int; see enumeration content_types)
    //--------------------------------------------
    if ( hstr_hdr_key.m_equals_ic(HF_CONTENT_TYPE) ) {
        this->hstr_hf_content_type = hstr_hdr_value;
		m_get_content_type(hstr_hdr_value, this->in_content_type, this->iec_content_type_charset);
        return true;
    }

	if ( hstr_hdr_key.m_equals_ic(HF_UPGRADE) ) {
		if(hstr_hdr_value.m_equals_ic("websocket")) {
			this->bo_upgrade_websocket = true;
		}
		goto LBL_UNPROCESSED;
    }

	//--------------------------------------------
    // get header fields, which will be interesting for us
    //--------------------------------------------
    if (!bo_webserver_response) { // ClientRequest
        // cookies of http-header
        // get cookies, which are delivered in http-header by the webbrowser
        if ( hstr_hdr_key.m_equals_ic(HF_COOKIE) ) {
            hstr_hdrline_cookie = hstr_hdr_value;
            bo_cookie_header_exists = true;
            return true;
        }
        // Host
        if ( hstr_hdr_key.m_equals_ic(HF_HOST) ) {
            hstr_hf_host = hstr_hdr_value;
            return true;
        }

        // Accept-Language (as int; see enumeration ds_http_header::languages)
        if ( hstr_hdr_key.m_equals_ic(HF_ACCEPT_LANGUAGE) ) {
            hstr_hf_accept_language = hstr_hdr_value;
            in_language = m_get_int_for_accept_language(hstr_hf_accept_language.m_const_str());
            return true;
        }

        // we read header-lines, which concern to WSG in the case of IWS, too
        // because the request could wrongly be for IWS and HOB_net will forward it to WSG; then the
        // header would not be read in !!!
        // If-Modified-Since
        if ( hstr_hdr_key.m_equals_ic(HF_IF_MODIFIED_SINCE) ) {
            hstr_hf_if_modified_since = hstr_hdr_value;
            return true;
        }

        // User-Agent
        if ( hstr_hdr_key.m_equals_ic(HF_USER_AGENT) ) {
            hstr_hf_user_agent = hstr_hdr_value;
			//ads_session->hstr_user_agent_last_req = hstr_hf_user_agent;
            return true;
        }

        // Accept-Encoding
        if ( hstr_hdr_key.m_equals_ic(HF_ACCEPT_ENCODING) ) {
            ads_session->dsg_state.in_accept_encoding = ds_http_header::ien_ce_identity;
            // compression is activated
            this->hstr_hf_accept_encoding = hstr_hdr_value;
            if (ads_session->dsc_helper.m_tokenize(this->hstr_hf_accept_encoding.m_const_str(), ",", &this->ds_v_hf_accept_encoding, true, false, false) <= 0) {
                return true; // ignore this header line (e.g. there were no entries, which is allowed!)
            }

            for (HVECTOR_FOREACH(dsd_const_string, adsl_cur, this->ds_v_hf_accept_encoding)) {
                const dsd_const_string& hstr_tmp = HVECTOR_GET(adsl_cur);
                // TODO: Why is this not case-insensitive????
				int inl_encoding = m_get_encoding(hstr_tmp);
				ads_session->dsg_state.in_accept_encoding |= inl_encoding;
            }

            return true; // all is ok
        }

        // Referer
        if ( hstr_hdr_key.m_equals_ic(HF_REFERER) ) {
            hstr_hf_referer = hstr_hdr_value;
            return true;
        }

        // Origin
		if ( hstr_hdr_key.m_equals_ic(HF_ORIGIN) ) {
			this->hstr_hf_origin = hstr_hdr_value;
			return true;
		}
    }
    else { // response from webserver
        // Location
        if ( hstr_hdr_key.m_equals_ic(HF_LOCATION) ) {
            hstr_hf_location = hstr_hdr_value;
            return true;
        }
        if ( hstr_hdr_key.m_equals_ic(HF_CONTENT_SECURITY_POLICY) ) {
            hstr_hf_content_security_policy = hstr_hdr_value;
            return true;
        }
        if ( hstr_hdr_key.m_equals_ic(HF_CONTENT_SECURITY_POLICY_REPORT_ONLY) ) {
            hstr_hf_content_security_policy_report_only = hstr_hdr_value;
            return true;
        }
		if ( hstr_hdr_key.m_equals_ic(HF_REFERRER_POLICY) ) {
			hstr_hf_referrer_policy = hstr_hdr_value;
            return true;
        }
        if ( hstr_hdr_key.m_equals_ic(HF_X_FRAME_OPTIONS) ) {
            hstr_hf_x_frame_options = hstr_hdr_value;
            return true;
        }
        if ( hstr_hdr_key.m_equals_ic(HF_X_UA_COMPATIBLE) ) {
            hstr_hf_x_ua_compatible = hstr_hdr_value;
            return true;
        }
        // Set-Cookie (multi-valued!!)
        if ( hstr_hdr_key.m_equals_ic(HF_SET_COOKIE) ) {
            ds_v_hf_set_cookie.m_add3(hstr_hdr_value);
            return true;
        }

        // Connection (Attention: field is multi-valued!! -> TODO (see WWW-Authenticate as example) !!!)
        if ( hstr_hdr_key.m_equals_ic(HF_CONNECTION) ) {
			if(hstr_hf_connection.m_get_len() <= 0) {
				hstr_hf_connection = hstr_hdr_value;
				return true;
			}
			goto LBL_UNPROCESSED;
        }
        
        // Ticket[13733]: WWW-Authenticate (multi-valued!!)
        if ( hstr_hdr_key.m_equals_ic(HF_WWW_AUTHENTICATE) ) {
            // Add according to priority:
            // 1) Negotiate
            // 2) Digest, NTLM, etc (for these we do not try SSO up to now)
            // 3) Basic
            if (hstr_hdr_value.m_starts_with_ic(HFV_WWWAUTH_NEGOTIATE)) {
                // Negotiate: Add at first position
                ds_v_hf_www_authenticate.m_add_first(ds_hstring(ads_session->ads_wsp_helper, hstr_hdr_value));
            }
            else if (hstr_hdr_value.m_starts_with_ic(HFV_WWWAUTH_BASIC)) {
                // Basic: Add at last position
                ds_v_hf_www_authenticate.m_add3(hstr_hdr_value);
            }
            else { // Add before 'Basic'
                // Get index of first 'Basic'
                dsd_hvec_elem<ds_hstring>* adsl_prev = NULL;
                for (HVECTOR_FOREACH2(ds_hstring, adsl_cur, ds_v_hf_www_authenticate)) {
                    const ds_hstring& hstr_value = HVECTOR_GET(adsl_cur);
                    if (hstr_value.m_starts_with_ic(HFV_WWWAUTH_BASIC)) {
                        // Add before the basic
                        break;  
                    }
                    adsl_prev = adsl_cur;
                }
                // No Basic was found -> add at the end.
                ds_v_hf_www_authenticate.m_insert_after(adsl_prev, ds_hstring(ads_session->ads_wsp_helper, hstr_hdr_value));
            }
            return true;
        }

        if ( hstr_hdr_key.m_equals_ic(HF_AUTHORIZATION) ) {
            this->hstr_hf_authorization = hstr_hdr_value;
				return true;
        }

        // Ticket[14237]: Content-Encoding
        if ( hstr_hdr_key.m_equals_ic(HF_CONTENT_ENCODING) ) {
				// Ticket[14237]: we support only one encoding at a time! (for the time being)            
				//in_content_encoding = ds_http_header::ien_ce_unknown;
				this->hstr_hf_content_encoding = hstr_hdr_value;
				this->in_content_encoding = m_get_encoding(hstr_hdr_value);
				return true;
        }

        // Ticket[17845]
        if ( hstr_hdr_key.m_equals_ic(HF_CACHE_CONTROL) ) {
            ds_v_hf_cache_control.m_add3(hstr_hdr_value);        
			return true;
        }
		if ( hstr_hdr_key.m_equals_ic(HF_PRAGMA) ) {
			if(hstr_hdr_value.m_equals_ic("no-cache")) {
				hstr_hf_pragma = hstr_hdr_value;
				return true;
			}
			goto LBL_UNPROCESSED;
        }
    } // response from webserver

LBL_UNPROCESSED: 
	// collect the header-lines, which are not processed
    dsv_unprocessed_headerlines.m_add3(hstr_hdr_key);
    dsv_unprocessed_headerlines.m_add3(hstr_hdr_value);

    return true;
}

/*! \brief Get language
 *
 * @ingroup creator
 *
 * intern
 * convert the Accept-Language-string to an integer
 * very simple; must be refined
*/
int ds_http_header::m_get_int_for_accept_language(const dsd_const_string& ahstr)
{
    return RESOURCES->m_parse_lang(ahstr.m_get_ptr(), ahstr.m_get_len() );
}

bool ds_http_header::m_get_content_type(
    const dsd_const_string& ahstr,
    enum content_types& riep_ct, enum ied_charset& riep_charset)
{
    riep_charset = ied_chs_invalid;
    
    if ( ahstr.m_get_len() == 0 ) {
        riep_ct = ien_ct_not_set;
        return true;
    }

    dsd_tokenizer dsl_tok(ahstr, ";");
    dsd_const_string dsl_query_end1;
    dsd_const_string dsl_content_type;
    bool bol_more_tokens = dsl_tok.m_next(dsl_content_type);
    while(bol_more_tokens) {
        dsd_const_string dsl_param;
        bol_more_tokens = dsl_tok.m_next(dsl_param);
        dsl_param.m_trim(" ");
        if(dsl_param.m_starts_with_ic("charset=")) {
            dsd_const_string dsl_charset(dsl_param.m_substring(8));
            riep_charset = ds_http_header::m_get_charset(dsl_charset);
        }
    }

    // text
    // TODO: Is this search correct?
	dsl_content_type.m_trim(" ");
    if (dsl_content_type.m_equals_ic("text/html"))    {
        riep_ct = ien_ct_text_html;
        return true;
    }
    if (dsl_content_type.m_equals_ic("text/x-component"))    {
        riep_ct = ien_ct_text_x_component;
        return true;
    }
    if (dsl_content_type.m_equals_ic("text/plain"))    {
        riep_ct = ien_ct_text_plain;
        return true;
    } 
    if (dsl_content_type.m_equals_ic("text/javascript")) {
        riep_ct = ien_ct_application_javascript;
        return true;
    }
    if (dsl_content_type.m_equals_ic("text/x-js")) {
        riep_ct = ien_ct_application_javascript;
        return true;
    }
    if (dsl_content_type.m_equals_ic("text/css"))    {
        riep_ct = ien_ct_text_css;
        return true;
    }
    if (dsl_content_type.m_equals_ic("text/xml")) {
        riep_ct = ien_ct_text_xml;
        return true;
    }
    // application            
    if (dsl_content_type.m_equals_ic("application/x-javascript")) {
        riep_ct = ien_ct_application_javascript;
        return true;
    }
    if (dsl_content_type.m_equals_ic("application/javascript")) {
        riep_ct = ien_ct_application_javascript;
        return true;
    }
    if (dsl_content_type.m_equals_ic("module")) {
        riep_ct = ien_ct_application_javascript;
        return true;
    }
    if (dsl_content_type.m_equals_ic("application/json")) {
        riep_ct = ien_ct_application_json;
        return true;
    }
    if (dsl_content_type.m_equals_ic("application/ld+json")) {
        riep_ct = ien_ct_application_json;
        return true;
    }
    if (dsl_content_type.m_equals_ic("application/xhtml+xml"))    {
        riep_ct = ien_ct_application_xhtml;
        return true;
    }
    if (dsl_content_type.m_equals_ic("application/xml"))    {
        riep_ct = ien_ct_text_html;
        return true;
    }
    if (dsl_content_type.m_equals_ic("application/x-java-jnlp-file"))    {
        riep_ct = ien_ct_application_x_java_jnlp_file;
        return true;
    }
    if (dsl_content_type.m_equals_ic("application/x-ica")) {
        riep_ct = ien_ct_application_x_ica;
        return true;
    }
    
    riep_ct = ien_ct_unknown;
    return false; // unknown
}

ied_charset ds_http_header::m_get_charset(const dsd_const_string& rdsp_charset) {
    if(rdsp_charset.m_get_len() <= 0)
        return ied_chs_invalid;
    if((rdsp_charset.m_equals_ic("utf-8")) || (rdsp_charset.m_equals_ic("utf8")) || (rdsp_charset.m_equals_ic("unicode-1-1-utf-8")))
        return ied_chs_utf_8;
    if(rdsp_charset.m_equals_ic("utf-16"))
        return ied_chs_utf_16;
    if(rdsp_charset.m_equals_ic("utf-16be"))
        return ied_chs_be_utf_16;
    if(rdsp_charset.m_equals_ic("utf-16le"))
        return ied_chs_le_utf_16;
    if(rdsp_charset.m_equals_ic("utf-32"))
        return ied_chs_be_utf_32;
    if(rdsp_charset.m_equals_ic("utf-32be"))
        return ied_chs_be_utf_32;
    if(rdsp_charset.m_equals_ic("utf-32le"))
        return ied_chs_le_utf_32;
    if((rdsp_charset.m_equals_ic("windows-874"))      || (rdsp_charset.m_equals_ic("dos-874"))     || (rdsp_charset.m_equals_ic("iso-8859-11"))
        || (rdsp_charset.m_equals_ic("iso8859-11"))   || (rdsp_charset.m_equals_ic("iso885911"))   || (rdsp_charset.m_equals_ic("tis-620")))
        return ied_chs_wcp_874;
    if((rdsp_charset.m_equals_ic("windows-1250"))     || (rdsp_charset.m_equals_ic("cp1250"))      || (rdsp_charset.m_equals_ic("x-cp1250")))
        return ied_chs_wcp_1250;
    if((rdsp_charset.m_equals_ic("windows-1251"))     || (rdsp_charset.m_equals_ic("cp1251"))      || (rdsp_charset.m_equals_ic("x-cp1251")))
        return ied_chs_wcp_1251;
    if((rdsp_charset.m_equals_ic("ansi_x3.4-1968"))   || (rdsp_charset.m_equals_ic("ascii"))       || (rdsp_charset.m_equals_ic("cp1252"))
        || (rdsp_charset.m_equals_ic("cp819"))        || (rdsp_charset.m_equals_ic("csisolatin1")) || (rdsp_charset.m_equals_ic("ibm819"))
        || (rdsp_charset.m_equals_ic("iso-8859-1"))   || (rdsp_charset.m_equals_ic("iso-ir-100"))  || (rdsp_charset.m_equals_ic("iso8859-1"))
        || (rdsp_charset.m_equals_ic("iso88591"))     || (rdsp_charset.m_equals_ic("iso_8859-1"))  || (rdsp_charset.m_equals_ic("iso_8859-1:1987"))
        || (rdsp_charset.m_equals_ic("l1"))           || (rdsp_charset.m_equals_ic("latin1"))      || (rdsp_charset.m_equals_ic("us-ascii"))
        || (rdsp_charset.m_equals_ic("windows-1252")) || (rdsp_charset.m_equals_ic("x-cp1252")))
        return ied_chs_wcp_1252;
    if((rdsp_charset.m_equals_ic("windows-1253"))     || (rdsp_charset.m_equals_ic("cp1253"))      || (rdsp_charset.m_equals_ic("x-cp1253")))
        return ied_chs_wcp_1253;
    if((rdsp_charset.m_equals_ic("windows-1255"))     || (rdsp_charset.m_equals_ic("cp1255"))      || (rdsp_charset.m_equals_ic("x-cp1255")))
        return ied_chs_wcp_1255;
    if((rdsp_charset.m_equals_ic("windows-1256"))     || (rdsp_charset.m_equals_ic("cp1256"))      || (rdsp_charset.m_equals_ic("x-cp1256")))
        return ied_chs_wcp_1256;
    if((rdsp_charset.m_equals_ic("windows-1257"))     || (rdsp_charset.m_equals_ic("cp1257"))      || (rdsp_charset.m_equals_ic("x-cp1257")))
        return ied_chs_wcp_1257;
    if((rdsp_charset.m_equals_ic("windows-1258"))     || (rdsp_charset.m_equals_ic("cp1258"))      || (rdsp_charset.m_equals_ic("x-cp1258")))
        return ied_chs_wcp_1258;
    if((rdsp_charset.m_equals_ic("Shift_JIS"))        || (rdsp_charset.m_equals_ic("csshiftjis"))  || (rdsp_charset.m_equals_ic("ms932"))
        || (rdsp_charset.m_equals_ic("ms_kanji"))     || (rdsp_charset.m_equals_ic("shift_jis"))   || (rdsp_charset.m_equals_ic("sjis"))
        || (rdsp_charset.m_equals_ic("windows-31j"))  || (rdsp_charset.m_equals_ic("x-sjis")))
        return ied_chs_wcp_932;
    if((rdsp_charset.m_equals_ic("GBK"))              || (rdsp_charset.m_equals_ic("csgb2312"))    || (rdsp_charset.m_equals_ic("csiso58gb231280"))
        || (rdsp_charset.m_equals_ic("chinese"))      || (rdsp_charset.m_equals_ic("gb2312"))      || (rdsp_charset.m_equals_ic("gb_2312"))
        || (rdsp_charset.m_equals_ic("gb_2312-80"))   || (rdsp_charset.m_equals_ic("iso-ir-58"))   || (rdsp_charset.m_equals_ic("x-gbk")))
        return ied_chs_wcp_936;
    if((rdsp_charset.m_equals_ic("EUC-KR"))           || (rdsp_charset.m_equals_ic("cseuckr"))     || (rdsp_charset.m_equals_ic("csksc56011987"))
        || (rdsp_charset.m_equals_ic("iso-ir-149"))   || (rdsp_charset.m_equals_ic("korean"))      || (rdsp_charset.m_equals_ic("ks_c_5601-1987"))
        || (rdsp_charset.m_equals_ic("ksc_5601"))     || (rdsp_charset.m_equals_ic("ksc5601"))     || (rdsp_charset.m_equals_ic("ks_c_5601-1989"))
        || (rdsp_charset.m_equals_ic("windows-949")))
        return ied_chs_wcp_949;
    if((rdsp_charset.m_equals_ic("ISO-8859-2"))       || (rdsp_charset.m_equals_ic("csisolatin2")) || (rdsp_charset.m_equals_ic("iso_8859-2:1987"))
        || (rdsp_charset.m_equals_ic("iso-ir-101"))   || (rdsp_charset.m_equals_ic("iso8859-2"))   || (rdsp_charset.m_equals_ic("iso88592"))
        || (rdsp_charset.m_equals_ic("iso_8859-2"))   || (rdsp_charset.m_equals_ic("latin2"))      || (rdsp_charset.m_equals_ic("l2")))
        return ied_chs_iso8859_2;
    if((rdsp_charset.m_equals_ic("ISO-8859-3"))       || (rdsp_charset.m_equals_ic("csisolatin3")) || (rdsp_charset.m_equals_ic("iso_8859-3:1988"))
        || (rdsp_charset.m_equals_ic("iso-ir-109"))   || (rdsp_charset.m_equals_ic("iso8859-3"))   || (rdsp_charset.m_equals_ic("iso88593"))
        || (rdsp_charset.m_equals_ic("iso_8859-3"))   || (rdsp_charset.m_equals_ic("latin3"))      || (rdsp_charset.m_equals_ic("l3")))
        return ied_chs_iso8859_3;
    if((rdsp_charset.m_equals_ic("ISO-8859-4"))       || (rdsp_charset.m_equals_ic("csisolatin4")) || (rdsp_charset.m_equals_ic("iso_8859-4:1988"))
        || (rdsp_charset.m_equals_ic("iso-ir-110"))   || (rdsp_charset.m_equals_ic("iso8859-4"))   || (rdsp_charset.m_equals_ic("iso88594"))
        || (rdsp_charset.m_equals_ic("iso_8859-4"))   || (rdsp_charset.m_equals_ic("latin4"))      || (rdsp_charset.m_equals_ic("l4")))
        return ied_chs_iso8859_4;
    if((rdsp_charset.m_equals_ic("ISO-8859-5"))       || (rdsp_charset.m_equals_ic("cyrillic"))    || (rdsp_charset.m_equals_ic("csisolatincyrillic"))
        || (rdsp_charset.m_equals_ic("iso_8859-5"))   || (rdsp_charset.m_equals_ic("iso-ir-144"))  || (rdsp_charset.m_equals_ic("iso8859-5"))
        || (rdsp_charset.m_equals_ic("iso88595"))     || (rdsp_charset.m_equals_ic("iso_8859-5:1988")))
        return ied_chs_iso8859_5;
    if((rdsp_charset.m_equals_ic("ISO-8859-6"))       || (rdsp_charset.m_equals_ic("arabic"))      || (rdsp_charset.m_equals_ic("asmo-708"))
        || (rdsp_charset.m_equals_ic("csiso88596e"))  || (rdsp_charset.m_equals_ic("csiso88596i")) || (rdsp_charset.m_equals_ic("csisolatinarabic"))
        || (rdsp_charset.m_equals_ic("ecma-114"))     || (rdsp_charset.m_equals_ic("iso-8859-6-e"))|| (rdsp_charset.m_equals_ic("iso-8859-6-i"))
        || (rdsp_charset.m_equals_ic("iso-ir-127"))   || (rdsp_charset.m_equals_ic("iso8859-6"))   || (rdsp_charset.m_equals_ic("iso88596"))
        || (rdsp_charset.m_equals_ic("iso_8859-6"))   || (rdsp_charset.m_equals_ic("iso_8859-6:1987")))
        return ied_chs_iso8859_6;
    if((rdsp_charset.m_equals_ic("ISO-8859-7"))       || (rdsp_charset.m_equals_ic("ecma-118"))    || (rdsp_charset.m_equals_ic("csisolatingreek"))
        || (rdsp_charset.m_equals_ic("elot_928"))     || (rdsp_charset.m_equals_ic("greek"))       || (rdsp_charset.m_equals_ic("iso_8859-7:1987"))
        || (rdsp_charset.m_equals_ic("greek8"))       || (rdsp_charset.m_equals_ic("iso-ir-126"))  || (rdsp_charset.m_equals_ic("iso8859-7"))
        || (rdsp_charset.m_equals_ic("iso88597"))     || (rdsp_charset.m_equals_ic("iso_8859-7"))  || (rdsp_charset.m_equals_ic("sun_eu_greek")))
        return ied_chs_iso8859_7;
    if((rdsp_charset.m_equals_ic("ISO-8859-8"))       || (rdsp_charset.m_equals_ic("csiso88598e")) || (rdsp_charset.m_equals_ic("csisolatinhebrew"))
        || (rdsp_charset.m_equals_ic("hebrew"))       || (rdsp_charset.m_equals_ic("iso-8859-8-e"))|| (rdsp_charset.m_equals_ic("iso-ir-138"))
        || (rdsp_charset.m_equals_ic("iso8859-8"))    || (rdsp_charset.m_equals_ic("iso88598"))    || (rdsp_charset.m_equals_ic("iso_8859-8"))
        || (rdsp_charset.m_equals_ic("visual"))       || (rdsp_charset.m_equals_ic("iso_8859-8:1988")))
        return ied_chs_iso8859_8;
    if((rdsp_charset.m_equals_ic("windows-1254"))     || (rdsp_charset.m_equals_ic("cp1254"))      || (rdsp_charset.m_equals_ic("csisolatin5"))
        || (rdsp_charset.m_equals_ic("iso-8859-9"))   || (rdsp_charset.m_equals_ic("iso-ir-148"))  || (rdsp_charset.m_equals_ic("iso8859-9"))
        || (rdsp_charset.m_equals_ic("iso88599"))     || (rdsp_charset.m_equals_ic("iso_8859-9"))  || (rdsp_charset.m_equals_ic("iso_8859-9:1989"))
        || (rdsp_charset.m_equals_ic("l5"))           || (rdsp_charset.m_equals_ic("x-cp1254"))    || (rdsp_charset.m_equals_ic("latin5")))
        return ied_chs_iso8859_9;
    if((rdsp_charset.m_equals_ic("ISO-8859-10"))      || (rdsp_charset.m_equals_ic("csisolatin6")) || (rdsp_charset.m_equals_ic("iso-ir-157"))
        || (rdsp_charset.m_equals_ic("iso8859-10"))   || (rdsp_charset.m_equals_ic("iso885910"))   || (rdsp_charset.m_equals_ic("l6"))
        || (rdsp_charset.m_equals_ic("latin6")))
        return ied_chs_iso8859_10;
    if((rdsp_charset.m_equals_ic("windows-874"))      || (rdsp_charset.m_equals_ic("dos-874"))     || (rdsp_charset.m_equals_ic("iso-8859-11"))
        || (rdsp_charset.m_equals_ic("iso8859-11"))   || (rdsp_charset.m_equals_ic("iso885911"))   || (rdsp_charset.m_equals_ic("tis-620")))
        return ied_chs_iso8859_11;
    if((rdsp_charset.m_equals_ic("ISO-8859-13"))      || (rdsp_charset.m_equals_ic("iso8859-13"))  || (rdsp_charset.m_equals_ic("iso885913")))
        return ied_chs_iso8859_13;
    if((rdsp_charset.m_equals_ic("ISO-8859-14"))      || (rdsp_charset.m_equals_ic("iso8859-14"))  || (rdsp_charset.m_equals_ic("iso885914")))
        return ied_chs_iso8859_14;
    if((rdsp_charset.m_equals_ic("ISO-8859-15"))      || (rdsp_charset.m_equals_ic("csisolatin9")) || (rdsp_charset.m_equals_ic("iso8859-15"))
        || (rdsp_charset.m_equals_ic("iso885915"))    || (rdsp_charset.m_equals_ic("iso_8859-15")) || (rdsp_charset.m_equals_ic("l9")))
        return ied_chs_iso8859_15;
    if(rdsp_charset.m_equals_ic("ISO-8859-16"))
        return ied_chs_iso8859_16;
    return ied_chs_invalid;
}

const dsd_const_string ds_http_header::m_get_charset_name(ied_charset iep_charset) {
    switch(iep_charset) {
        case ied_chs_utf_8:
            return dsd_const_string("UTF-8");
        case ied_chs_utf_16:
            return dsd_const_string("UTF-16");
        case ied_chs_be_utf_16:
            return dsd_const_string("UTF-16BE");
        case ied_chs_le_utf_16:
            return dsd_const_string("UTF-16LE");
        case ied_chs_utf_32:
            return dsd_const_string("UTF-32");
        case ied_chs_be_utf_32:
            return dsd_const_string("UTF-32BE");
        case ied_chs_le_utf_32:
            return dsd_const_string("UTF-32LE");
        case ied_chs_wcp_874:
            return dsd_const_string("windows-874");
        case ied_chs_wcp_1250:
            return dsd_const_string("windows-1250");
        case ied_chs_wcp_1251:
            return dsd_const_string("windows-1251");
        case ied_chs_wcp_1252:
            return dsd_const_string("windows-1252");
        case ied_chs_wcp_1253:
            return dsd_const_string("windows-1253");
        case ied_chs_wcp_1255:
            return dsd_const_string("windows-1255");
        case ied_chs_wcp_1256:
            return dsd_const_string("windows-1256");
        case ied_chs_wcp_1257:
            return dsd_const_string("windows-1257");
        case ied_chs_wcp_1258:
            return dsd_const_string("windows-1258");
        case ied_chs_wcp_932:
            return dsd_const_string("Shift_JIS");
        case ied_chs_wcp_936:
            return dsd_const_string("GBK");
        case ied_chs_wcp_949:
            return dsd_const_string("EUC-KR");
        case ied_chs_iso8859_2:
            return dsd_const_string("ISO-8859-2");
        case ied_chs_iso8859_3:
            return dsd_const_string("ISO-8859-3");
        case ied_chs_iso8859_4:
            return dsd_const_string("ISO-8859-4");
        case ied_chs_iso8859_5:
            return dsd_const_string("ISO-8859-5");
        case ied_chs_iso8859_6:
            return dsd_const_string("ISO-8859-6");
        case ied_chs_iso8859_7:
            return dsd_const_string("ISO-8859-7");
        case ied_chs_iso8859_8:
            return dsd_const_string("ISO-8859-8");
        case ied_chs_iso8859_9:
            return dsd_const_string("windows-1254");
        case ied_chs_iso8859_10:
            return dsd_const_string("ISO-8859-10");
        case ied_chs_iso8859_11:
            return dsd_const_string("windows-874");
        case ied_chs_iso8859_13:
            return dsd_const_string("ISO-8859-13");
        case ied_chs_iso8859_14:
            return dsd_const_string("ISO-8859-14");
        case ied_chs_iso8859_15:
            return dsd_const_string("ISO-8859-15");
        case ied_chs_iso8859_16:
            return dsd_const_string("ISO-8859-16");
        case ied_chs_invalid:
        default:
            return dsd_const_string::m_null();
    }
}

ds_http_header::content_encodings ds_http_header::m_get_encoding(const dsd_const_string& rdsp_enc) {
	// TODO: Why is this not case-insensitive????
	if (rdsp_enc.m_equals(HFV_IDENTITY)) { 
        return ds_http_header::ien_ce_identity;
    }
    if (rdsp_enc.m_equals(HFV_GZIP)) { 
        return ds_http_header::ien_ce_gzip;
    }
    if (rdsp_enc.m_equals(HFV_DEFLATE)) {
		return ds_http_header::ien_ce_deflate;
    }
    if (rdsp_enc.m_equals(HFV_COMPRESS)) { 
		return ds_http_header::ien_ce_compress;
    }
    if (rdsp_enc.m_equals(HFV_PACK200)) { // JF 30.10.09 Ticket[15925]: Support of pack200
		return ds_http_header::ien_ce_pack200;
    }
	return ds_http_header::ien_ce_unknown;
}

/*! \brief Count header lines
 *
 * @ingroup creator
 *
 * returns count of lines of this header
*/
int ds_http_header::m_get_count_lines(void)
{
    return in_count_lines;
}

/*! \brief Check if its a chunked content type
 *
 * @ingroup creator
 *
 * returns true, if received header contains 'Content-Type:chunked'
*/
bool ds_http_header::m_is_chunked(void)
{
    return bo_chunked_data;
}

/*! \brief Get content length
 *
 * @ingroup creator
 *
 * returns the value of "Content-Length"-header (may be -1 !!)
*/
int ds_http_header::m_get_content_length(void)
{
    return in_content_length;
}

/*! \brief Reset Content length
 *
 * @ingroup creator
 *
 * Reset the content length attribute
*/
void ds_http_header::m_reset_content_length()
{
    in_content_length = 0;
}

/*! \brief Check if response is from a webserver
 *
 * @ingroup creator
 *
 * return true, if the received data are a response by a webserver
*/
bool ds_http_header::m_is_webserver_response(void)
{
    return bo_webserver_response;
}

/*! \brief Check for message body
 *
 * @ingroup creator
 *
 * returns true, when this request/response envelopes a message body
*/
bool ds_http_header::m_is_message_body_announced(void)
{
    return bo_message_body_announced;
}

/*! \brief Get HTTP method
 *
 * @ingroup creator
 *
 * return http_method (e.g. GET <-> ien_meth_GET) 
*/
int ds_http_header::m_get_http_method(void)
{
    return in_http_method;
}

// MJ 05.11.08, Ticket[16425]:
/*! \brief Get HTTP method char
 *
 * @ingroup creator
 *
 * Get HTTP method char
*/
dsd_const_string ds_http_header::m_get_http_method_char(void)
{
    if ( in_http_method <= -1 ) {
        return dsd_const_string("");
    }
    return HTTP_METHODS[in_http_method];
} // end of ds_http_header::m_get_http_method_char

/*! \brief Adds a start line
 *
 * @ingroup creator
 *
 * add the startline to the out-header
*/
int ds_http_header::m_add_start_line_out(bool bo_request, const dsd_const_string& ahstr_http_version, int in_method_or_statuscode, const dsd_const_string& ahstr_url_or_reasonphrase)
{
    // ensure that str_hdr_out is empty
    hstr_hdr_out.m_reset();

    if (bo_request) { // add to str_hdr_out the start-line of a http-REQUEST:   Method SP Request-URI SP HTTP-Version CRLF
        hstr_hdr_out.m_write(HTTP_METHODS[in_method_or_statuscode]);
        hstr_hdr_out.m_write(" ");
        hstr_hdr_out.m_write(ahstr_url_or_reasonphrase);
        hstr_hdr_out.m_write(" ");
        hstr_hdr_out.m_write(ahstr_http_version);
        hstr_hdr_out.m_write("\r\n");
    }
    else { // add to str_hdr_out the start-line of a http-RESPONSE:   HTTP-Version SP Status-Code SP Reason-Phrase CRLF
        hstr_hdr_out.m_write(ahstr_http_version);
        hstr_hdr_out.m_write(" ");
        hstr_hdr_out.m_write_int(in_method_or_statuscode);
        hstr_hdr_out.m_write(" ");
        hstr_hdr_out.m_write(ahstr_url_or_reasonphrase);
        hstr_hdr_out.m_write("\r\n");
    }
    return 0;
}

/*! \brief Get reason phrase
 *
 * @ingroup creator
 *
 * get the reasonphrase to a status-code-number
*/
dsd_const_string ds_http_header::m_get_reasonphrase(int in_status_code)
{
    switch (in_status_code) {
        case ds_http_header::ien_status_continue: { // 100
            return dsd_const_string("Continue");
        }
        case ds_http_header::ien_status_ok: { // 200
            return dsd_const_string("OK");
        }
        case ds_http_header::ien_status_found: { // 302
            return dsd_const_string("Found");
        }
        case ds_http_header::ien_status_see_other: { // 303
            return dsd_const_string("See Other");
        }
        case ds_http_header::ien_status_not_modified: { // 304
            return dsd_const_string("Not Modified");
        }
        case ds_http_header::ien_status_bad_request: { // 400  // JF 07.10.08 Ticket[16125]
            return dsd_const_string("Bad Request");
        }
        case ds_http_header::ien_status_forbidden: { // 403
            return dsd_const_string("Forbidden");
        }
        case ds_http_header::ien_status_not_found: { // 404
            return dsd_const_string("Not found");
        }
        case ds_http_header::ien_status_method_not_allowed: { // 405
            return dsd_const_string("Method Not Allowed");
        }
    }

    return dsd_const_string("");
}

// add a headerline to the out-header
int ds_http_header::m_add_hdr_line_out(const dsd_const_string& ach_field_name, const dsd_const_string& ach_field_value)
{
    if ( ach_field_name.m_get_len() == 0 ) {
        return -1;
    }
    hstr_hdr_out.m_write(ach_field_name);
    hstr_hdr_out.m_write(": ");
    hstr_hdr_out.m_write(ach_field_value);
    hstr_hdr_out.m_write("\r\n");
    return 0;
}


/*! \brief Add unprocessed header lines
 *
 * @ingroup creator
 *
 * add unprocessed headerlines to the out-header
*/
int ds_http_header::m_add_hdr_unprocessed_lines_out(ds_hstring* ahstr_lines)
{
    hstr_hdr_out += *ahstr_lines;
    return 0;
}

/*! \brief Terminate outgoing header
 *
 * @ingroup creator
 *
 * terminate the out-header by adding CRLF
*/
int ds_http_header::m_terminate_hdr_out()
{
    hstr_hdr_out.m_write(CRLF);
    return 0;
}

/*! \brief Get unprocessed header lines
 *
 * @ingroup creator
 *
 * get those header-lines, which are not investigated
 * returned string may be empty
*/
ds_hstring ds_http_header::m_get_unprocessed_headerlines(void)
{
    // write the vector's data into a string
    ds_hstring hstr_ret(ads_session->ads_wsp_helper, 1000); // should be enough to avoid resizing of string
    const dsd_hvec_elem<ds_hstring>* adsl_elem = dsv_unprocessed_headerlines.m_get_first_element();
    while(adsl_elem != NULL) {
        const ds_hstring& rdsl_tmp = adsl_elem->dsc_element;
        adsl_elem = adsl_elem->ads_next;
        if(adsl_elem == NULL)
            break;
        const ds_hstring& rdsl_tmp2 = adsl_elem->dsc_element;
        hstr_ret.m_write(rdsl_tmp);
        hstr_ret.m_write(": ");
        hstr_ret.m_write(rdsl_tmp2);
        hstr_ret.m_write("\r\n");
        
        adsl_elem = adsl_elem->ads_next;
    }
    return hstr_ret;
}

/*! \brief Get content type
 *
 * @ingroup creator
 *
 * return the content-type-integer
*/
ds_http_header::content_types ds_http_header::m_get_content_type(void)
{
    return in_content_type;
}