#include "ds_session.h"
#include "ds_url_parser.h"
#include "ds_http_header.h"


#include <types_defines.h>


// MJ 05.05.09:
#define PROT_HTTP_FOR_WSG       "/HTTP://"
#define PROT_HTTP_FOR_WSG2       "/HTTP:/"
#define PROT_HTTPS_FOR_WSG      "/HTTPS://"
#define PROT_HTTPS_FOR_WSG2      "/HTTPS:/"
#define PROT_WS_FOR_WSG      "/ws://"
#define PROT_WS_FOR_WSG2      "/ws:/"
#define PROT_HTTP_FROM_BROWSER  "HTTP://"
#define PROT_HTTPS_FROM_BROWSER "HTTPS://"

//The four options for Request-URI are dependent on the nature of the
//   request. The asterisk "*" means that the request does not apply to a
//   particular resource, but to the server itself, and is only allowed
//   when the method used does not necessarily apply to a resource. One
//   example would be
//
//       OPTIONS * HTTP/1.1
//
//   The absoluteURI form is REQUIRED when the request is being made to a
//   proxy. The proxy is requested to forward the request or service it
//   from a valid cache, and return the response. Note that the proxy MAY
//   forward the request on to another proxy or directly to the server
//
//   specified by the absoluteURI. In order to avoid request loops, a
//   proxy MUST be able to recognize all of its server names, including
//   any aliases, local variations, and the numeric IP address. An example
//   Request-Line would be:
//
//       GET http://www.w3.org/pub/WWW/TheProject.html HTTP/1.1
//
//   To allow for transition to absoluteURIs in all requests in future
//   versions of HTTP, all HTTP/1.1 servers MUST accept the absoluteURI
//   form in requests, even though HTTP/1.1 clients will only generate
//   them in requests to proxies.
//
//   The authority form is only used by the CONNECT method (section 9.9).
//
//   The most common form of Request-URI is that used to identify a
//   resource on an origin server or gateway. In this case the absolute
//   path of the URI MUST be transmitted (see section 3.2.1, abs_path) as
//   the Request-URI, and the network location of the URI (authority) MUST
//   be transmitted in a Host header field. For example, a client wishing
//   to retrieve the resource above directly from the origin server would
//   create a TCP connection to port 80 of the host "www.w3.org" and send
//   the lines:
//
//       GET /pub/WWW/TheProject.html HTTP/1.1
//       Host: www.w3.org
//
//   followed by the remainder of the Request. Note that the absolute path
//   cannot be empty; if none is present in the original URI, it MUST be
//   given as "/" (the server root).

ds_url_parser::ds_url_parser(ds_session* ads_session_in)
: ads_session(NULL)
{
    ads_session = ads_session_in;
}

ds_url_parser::~ds_url_parser(void)
{
}

/*! \brief Parses an URL
 *
 * @ingroup webserver
 *
 * parse the URL; if something fails, the return value is negative
 * return value is the detected URL-type
 * 0=abs_path
 * 1=absoluteURI
 * 2=asterisk ('*')
 * 3=authority (is not suported!!)
 * 4=abs_path_for_wsg ('/http://www.google.de')
 * 5=abs_path_for_wsg_ssl ('/https://sparkasse.de')
*/
int ds_url_parser::m_parse(ds_url& dsc_url, const dsd_const_string& ahstr_url)
{
    dsc_url.hstr_url = ahstr_url;
#if !SM_USE_NEW_WSG 
	dsc_url.in_hob_type = ds_http_header::ien_hobtype_not_defined;
#endif
	if ( dsc_url.hstr_url.m_get_len() == 0 ) {
        return -1;
    }

    // Get a local copy, because this string might be changed here!
    dsd_const_string hstr_url(dsc_url.hstr_url.m_const_str());


    // JF 29.10.08 Ticket[16379]: cut out cookie_in_url; str_url could be "/(HOB...)/http://web.de/" (user inserted https://hobc02k.hob.de:4433/http://web.de
    // (no trailing '/') into browser before being logged in)
    
	dsc_url.in_url_type = ien_url_type_abs_path;
#if 0
    // absoluteURI: "GET https://OurAdress.de/folder/file.html HTTP/1.1"
    if (hstr_url.m_starts_with_ic(PROT_HTTPS_FROM_BROWSER)) { // 'https://OurAdress.de/'
        //dsc_url.bo_abs_url_no_ssl = false;
        dsc_url.in_url_type = ien_url_type_absolute_uri;
		hstr_url = hstr_url.m_substring(strlen(PROT_HTTPS_FROM_BROWSER));
    }
    else {
        // absoluteURI: "GET http://OurAdress.de/folder/file.html HTTP/1.1"
        // Attention: this should be supported only for testing !!
        if (hstr_url.m_starts_with_ic(PROT_HTTP_FROM_BROWSER)) { // 'http://OurAdress.de/'
            //dsc_url.bo_abs_url_no_ssl = true;
            dsc_url.in_url_type = ien_url_type_absolute_uri;
			hstr_url = hstr_url.m_substring(strlen(PROT_HTTP_FROM_BROWSER));
        }
    }
	if (dsc_url.in_url_type == ien_url_type_absolute_uri) { // data for webserver: absoluteURI
		int in_pos = hstr_url.m_index_of("/");
		if(in_pos < 0) {
			ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
				"HIWSE348E: Bad URL for WSG: %.*s.", hstr_url.m_get_len(), hstr_url.m_get_ptr() );
			return -2;
		}
		hstr_url = hstr_url.m_substring(in_pos);
		return m_parse(dsc_url, hstr_url);
    }
#endif
    dsd_const_string hstr_search(hstr_url);
	if ( hstr_url.m_starts_with("/(HOB") ) {
        int in_pos = hstr_url.m_index_of(")");
        if ( in_pos >= 0 ) {
            hstr_url = hstr_search.m_substring(in_pos + 1);
            dsc_url.hstr_url_cookie = hstr_search.m_substring(5, in_pos);
            dsc_url.bo_url_cookie = true;
        }
    }

    dsc_url.hstr_url_no_id = hstr_url;
    dsd_const_string hstr_temp(hstr_url);
    // request for WSG (noSSL): 'GET /http://www.google.de/'
    // Note: We are checking for "/http:/" only because of a bug in Microsoft Edge
    // request for WSG (SSL): 'GET /https://MyBank.de/'
    // Note: We are checking for "/https:/" only because of a bug in Microsoft Edge
	const dsd_const_string hstrl_wsg_path("/wsg/");
	if(hstr_url.m_starts_with(hstrl_wsg_path)) {
#if SM_USE_NEW_WSG 
		dsc_url.bo_data_for_wsg = true;
#else
		int inl_pos = hstr_url.m_index_of(hstrl_wsg_path.m_get_len(), ":/");
		if(inl_pos >= 0) {
			dsd_const_string hstr_protocol = hstr_url.m_substring(hstrl_wsg_path.m_get_len(), inl_pos);
			dsc_url.hstr_protocol = hstr_protocol;
			hstr_temp = hstr_url.m_substring(inl_pos+2);
			if(hstr_temp.m_starts_with("/"))
				hstr_temp = hstr_temp.m_substring(1);
			dsc_url.bo_data_for_wsg = true;
			if(hstr_protocol.m_equals_ic("ws") || hstr_protocol.m_equals_ic("wss")) {
				int a = 0;
			}
			if(hstr_protocol.m_equals_ic("http") || hstr_protocol.m_equals_ic("ws")) {
				dsc_url.bo_ssl_to_ext_ws = false;
				dsc_url.in_url_type = ien_url_type_abs_path_for_wsg;
			}
			else if(hstr_protocol.m_equals_ic("https") || hstr_protocol.m_equals_ic("wss")) {
				dsc_url.bo_ssl_to_ext_ws = true;
				dsc_url.in_url_type = ien_url_type_abs_path_for_wsg;
			}
			else {
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
					"HIWSE348E: Bad URL for WSG: %.*s.", hstr_url.m_get_len(), hstr_url.m_get_ptr() );
				return -2;
			}
		}
#endif
	}
#if 0
	else {
		int inl_pos = hstr_url.m_index_of(0, "://");
		if(inl_pos >= 0) {
			dsd_const_string hstr_protocol = hstr_url.m_substring(1, inl_pos);
			hstr_temp = hstr_url.m_substring(inl_pos+3);
			dsc_url.in_url_type = ien_url_type_absolute_uri;
		}
	}
#endif
#if 0
	if(dsc_url.in_url_type == ien_url_type_abs_path) {
		if(!(hstr_url.m_equals("/") || hstr_url.m_starts_with("/public/") || hstr_url.m_starts_with("/protected/"))) {
			ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
				"HIWSE348W: Bad URL for WSG: %.*s.", hstr_url.m_get_len(), hstr_url.m_get_ptr() );
		}
	}
#endif
#if 0
    // request for WSG (noSSL): 'GET /http://www.google.de/'
    // Note: We are checking for "/http:/" only because of a bug in Microsoft Edge
    if (hstr_url.m_starts_with_ic(PROT_HTTP_FOR_WSG2)) {
        dsc_url.bo_data_for_wsg = true;
        dsc_url.in_url_type = ien_url_type_abs_path_for_wsg;
        // skip leading '/' and protocol
        hstr_temp = hstr_url.m_substring(strlen(PROT_HTTP_FOR_WSG2));
        if(hstr_temp.m_starts_with("/"))
            hstr_temp = hstr_temp.m_substring(1);
    }
    // request for WSG (SSL): 'GET /https://MyBank.de/'
    // Note: We are checking for "/https:/" only because of a bug in Microsoft Edge
    else if (hstr_url.m_starts_with_ic(PROT_HTTPS_FOR_WSG2)) {
        dsc_url.bo_data_for_wsg = true;
        dsc_url.bo_ssl_to_ext_ws = true;
        dsc_url.in_url_type = ien_url_type_abs_path_for_wsg_ssl;
        // skip leading '/' and protocol
        hstr_temp = hstr_url.m_substring(strlen(PROT_HTTPS_FOR_WSG2));
        if(hstr_temp.m_starts_with("/"))
            hstr_temp = hstr_temp.m_substring(1);
    }
    else { // should never happen... (happens in case of a 'Referer'!)
        // absoluteURI: "GET https://OurAdress.de/folder/file.html HTTP/1.1"
        if (hstr_url.m_starts_with_ic(PROT_HTTPS_FROM_BROWSER)) { // 'https://OurAdress.de/'
            dsc_url.bo_abs_url_no_ssl = false;
            dsc_url.in_url_type = ien_url_type_absolute_uri;
        }
        else {
            // absoluteURI: "GET http://OurAdress.de/folder/file.html HTTP/1.1"
            // Attention: this should be supported only for testing !!
            if (hstr_url.m_starts_with_ic(PROT_HTTP_FROM_BROWSER)) { // 'http://OurAdress.de/'
                dsc_url.bo_abs_url_no_ssl = true;
                dsc_url.in_url_type = ien_url_type_absolute_uri;
            }
        }
    }
#endif
#if !SM_USE_NEW_WSG
    if ( (dsc_url.bo_data_for_wsg) ) {
        // read authority (is terminated by '/'; consists of "hostname:port")
        if (hstr_temp.m_get_len() == 0) { // no authority specified -> error
            return -2;
        }

        // 21.02.08 problem with /http://www.iewatch.com?gclid=CKa8qLO71ZECFR5FZwodMxOMZQ/
        int in_pos = hstr_temp.m_find_first_of("/?");
        dsd_const_string hstr_author("");
        if (in_pos < 0) { // no terminating '/' or '?' -> the remaining string is the authority; e.g. in 'http://www.google.de'
            hstr_author = hstr_temp;
            hstr_temp.m_reset();
        }
        else { // e.g. 'http://www.google.de/abc.html'
            hstr_author = hstr_temp.m_substring(0, in_pos); // cut out authority
            hstr_temp = hstr_temp.m_substring(in_pos); // skip hostname
        }

        //------------------------------------------
        // Get hostname and port out of hstr_author
        //------------------------------------------
        dsd_const_string hstr_tok_host("");
        dsd_const_string hstr_tok_port("");

        const dsd_const_string ach_start_ipv6_bracket = "%5B"; // '['
        const dsd_const_string ach_close_ipv6_bracket = "%5D"; // ']'
        if (hstr_author.m_starts_with_ic(ach_start_ipv6_bracket)) {
            // IPv6 address. Example: %5B2003:100:1000:e40:f171:9052:9abd:b142%5D:12345 (attention: 12345 is the port!)

            ads_session->ads_wsp_helper->m_log(ied_sdh_log_info, "HIWSI484I: URL contains IPv6 address.");
            int in_closing_bracket = hstr_author.m_last_index_of_ic(ach_close_ipv6_bracket);
            if (in_closing_bracket == -1) {
                ads_session->ads_wsp_helper->m_log(ied_sdh_log_info, "HIWSE483E: ']' not found in IPv6-URL.");
                return -20;
            }

            hstr_tok_host = (hstr_author.m_substr(ach_start_ipv6_bracket.m_get_len(), in_closing_bracket-ach_close_ipv6_bracket.m_get_len()));
            
            if (hstr_author.m_get_len() > (hstr_tok_host.m_get_len()+(int)ach_start_ipv6_bracket.m_get_len()+(int)ach_close_ipv6_bracket.m_get_len())) {
                // There is a port number specified in URL, too. It is separated by a ':'.
                dsd_const_string hstr_rest = hstr_author.m_substring(in_closing_bracket + ach_close_ipv6_bracket.m_get_len());
                if (hstr_rest[0] != ':') {
                    ads_session->ads_wsp_helper->m_log(ied_sdh_log_info, "HIWSE482E: Invalid IPv6-URL.");
                    return -21;
                }
                hstr_tok_port = hstr_rest.m_substring(1);
            }
            dsc_url.bo_ext_ws_ipv6 = true;
        }
        else { // IPv4 address or a normal hostname.
            ds_hvector_btype<dsd_const_string> ds_v_tokens(ads_session->ads_wsp_helper);
            int in_count_tokens = ads_session->dsc_helper.m_tokenize(hstr_author, ":", &ds_v_tokens, false, true, false);
            // in_count_tokens must be 1 (authority without a port) or 2 (authority with a port)
            if ( (in_count_tokens < 1) || (in_count_tokens > 2) ) {
                return -3;
            }
            hstr_tok_host = ds_v_tokens.m_get_first();
            if (ds_v_tokens.m_size() == 2) {
                hstr_tok_port = ds_v_tokens.m_get_first_element()->ads_next->dsc_element;
            }
        }

        if (hstr_tok_host.m_get_len() == 0) { // e.g. "/http://:?HOB_type=js"
            return -10;
        }

        // URL for WSG
        dsc_url.hstr_authority_of_webserver = hstr_author;
        dsc_url.hstr_hostname_of_webserver = hstr_tok_host;

        if (hstr_tok_port.m_get_len() > 0) {  // port number is set in URL -> convert to integer
            if (!hstr_tok_port.m_parse_int(&dsc_url.in_port_of_webserver)) {
                ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                                        "HIWSE337E: Invalid port-number in URL: %.*s",
                                                        dsc_url.hstr_url_no_id.m_get_len(), dsc_url.hstr_url_no_id.m_get_ptr() );
                ads_session->dsc_transaction.m_mark_as_processed(NULL); // JF 24.03.11
                ads_session->dsc_transaction.m_close_connection();  // close connection
                return -6;
            }
            if ( (dsc_url.in_port_of_webserver < 1) || (dsc_url.in_port_of_webserver > 65535)) {
                ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                                        "HIWSE338E: Invalid port-number in URL: %.*s",
                                                        dsc_url.hstr_url_no_id.m_get_len(), dsc_url.hstr_url_no_id.m_get_ptr() );
                ads_session->dsc_transaction.m_mark_as_processed(NULL); // JF 24.03.11
                ads_session->dsc_transaction.m_close_connection();  // close connection
                return -5;
            }
        }
        else { // no port number in URL -> set the default values
            dsc_url.in_port_of_webserver = (dsc_url.bo_ssl_to_ext_ws ? 443 : 80);
        }
    }
#endif

    // e.g. "OPTIONS * HTTP/1.1"
    // no parsing required
    if (hstr_url.m_equals("*")) {
        return ien_url_type_asterisk;
    }

    // now str_temp contains the <path> and the <query>, which are separated by '?'
    dsc_url.hstr_path.m_reset();
    dsc_url.hstr_query.m_reset();

    // ????  WHAT TODO  ????
    ////if (str_temp.empty()) { // no URL or '/http://www.google.de' (missing trailing '/'!!!)
    ////    // this is not allowed by RFC!!!
    ////    // but I think we should be tolerant -> don't return error-value
    ////}


    if(hstr_temp.m_get_len() == 0)
        goto LBL_DONE;

    // handle HOB_type in URL queries
    {
        // tokenize URL into parts before and after the '?' (if none present -> only one token)
        ds_hvector_btype<dsd_const_string> ds_v_tokens(ads_session->ads_wsp_helper);
        int in_count_tokens = ads_session->dsc_helper.m_tokenize(hstr_temp, "?", &ds_v_tokens, false, true, false);
        // in_count_tokens must be 1 (URL without a query) or 2 (URL with a query)
        if ( (in_count_tokens < 1) || (in_count_tokens > 2) ) {
            return -4;
        }
        // get and write part before '?'
        const dsd_hvec_elem<dsd_const_string>* adsl_cur_token = ds_v_tokens.m_get_first_element();
        dsc_url.hstr_path = adsl_cur_token->dsc_element;
        // get query string (part after '?')
        adsl_cur_token = adsl_cur_token->ads_next;
        if (adsl_cur_token == NULL)
            goto LBL_DONE;
        dsd_const_string hstr_query(adsl_cur_token->dsc_element);
#if !SM_USE_NEW_WSG
        // get last field-value pair of the query (no '&' yields whole query (substring starting at -1+1=0))
        int inl_pos = hstr_query.m_find_last_of("&");
        const dsd_const_string dsl_query_end = hstr_query.m_substring(inl_pos+1);
        dsd_tokenizer dsl_tok(dsl_query_end, ",");
        dsd_const_string dsl_query_end1;
        bool bol_more_tokens = dsl_tok.m_next(dsl_query_end1);
#if 0
        if(hstr_query.m_index_of("#") >= 0) {
            int a = 0;
        }
#endif
        // original query may have 'HOB_type=js' or 'HOB_type=css' AT ITS END
        // -> cut off and remember this state; when webserver sends the response to this request, we must forward the data (omitting the
        // delivered MIME type) to the interpreter class for css/js
        int in_hob_type = ds_http_header::ien_hobtype_not_defined;
		if(dsl_query_end1.m_starts_with("HOB_type=")) {
			const dsd_const_string dsl_hob_type = dsl_query_end1.m_substring(9);
			if (dsl_hob_type.m_equals("js")) {
				in_hob_type = ds_http_header::ien_hobtype_js;
			}
			else if(dsl_hob_type.m_equals("css")) {
				in_hob_type = ds_http_header::ien_hobtype_css;
			}
			else if(dsl_hob_type.m_equals("any")) {
				in_hob_type = ds_http_header::ien_hobtype_any;
			}
			else if(dsl_hob_type.m_equals("none")) {
				in_hob_type = ds_http_header::ien_hobtype_none;
			}
			else if(dsl_hob_type.m_equals("html")) {
				in_hob_type = ds_http_header::ien_hobtype_html;
			}
			else if(dsl_hob_type.m_equals("ws")) {
				in_hob_type = ds_http_header::ien_hobtype_ws;
			}
			dsd_const_string hstr_hob_query;
			while(bol_more_tokens) {
				bol_more_tokens = dsl_tok.m_next(dsl_query_end1);
				if(dsl_query_end1.m_starts_with("charset=")) {
					const dsd_const_string dsl_charset(dsl_query_end1.m_substring(8));
					dsc_url.iec_hob_type_charset = ds_http_header::m_get_charset(dsl_charset);
					continue;
				}
				if(dsl_query_end1.m_starts_with("origin=")) {
					dsc_url.hstr_hob_type_origin = dsl_query_end1.m_substring(7);
					continue;
				}
				if(dsl_query_end1.m_starts_with("worker=")) {
					dsc_url.hstr_hob_type_worker = dsl_query_end1.m_substring(7);
					continue;
				}
			}

			hstr_hob_query = hstr_query.m_substring(inl_pos+1);
			if (inl_pos < 0) // only HOB_type -> no original query remains
				inl_pos = 0;
			// strip off HOB_type from query
			hstr_query = hstr_query.m_substring(0, inl_pos);
	        dsc_url.in_hob_type = in_hob_type;
			dsc_url.hstr_hob_query = hstr_hob_query;
		}
#endif
		// set original query in dsc_url
		dsc_url.hstr_query = hstr_query;
    }
LBL_DONE:
    if (!dsc_url.bo_data_for_wsg) { // URL for IntegratedWebServer -> reconvert hexhex-encoding
        int inl_ret = ads_session->dsc_webserver.m_conv_from_hexhexencoding(&dsc_url.hstr_path);
        if (inl_ret != SUCCESS) {
            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                                 "HIWSE348E: Converting of URL failed with error %d: %.*s.",
                                                 inl_ret, ahstr_url.m_get_len(), ahstr_url.m_get_ptr() );
            return -7;
        }
    }

    // here we can split into the folder-path and file
    return dsc_url.in_url_type;
}

