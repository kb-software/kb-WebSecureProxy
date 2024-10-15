#ifndef DS_HTTP_HEADER_H
#define DS_HTTP_HEADER_H

#include <rdvpn_globals.h>
#include "ds_url.h"
#include "ds_hvector.h"

class ds_session; //forward-definition!!

/*! \brief HTTP header class
 *
 * @ingroup creator
 *
 * Deals with HTTP headers
 */
class ds_http_header
{
public:
    enum content_types {
       ien_ct_not_set = -1,                 //!< not set
       ien_ct_unknown = 0,                  //!< unknown
       ien_ct_text_plain,                   //!< text/plain
       // content-types, which WSG must process
       ien_ct_text_html = 100,              //!< text/html
       ien_ct_text_x_component,             //!< shall be handled by html-interpreter
       ien_ct_text_css,                     //!< text/css
       //ien_ct_text_javascript,              //!< text/javascript
       ien_ct_text_xml,                     //!< text/xml
       //ien_ct_application_x_javascript,     //!< application/x-javascript
       ien_ct_application_javascript,       //!< application/javascript
       ien_ct_application_json,				//!< JSON data
       ien_ct_application_x_java_jnlp_file, //!< Java Webstart
       ien_ct_application_x_ica,            //!< MJ 17.10.2011 for JICA integration
       ien_ct_application_xhtml,			//!< application/xhtml+xml
    };

    enum content_encodings {  // see RFC2616-3.5
       ien_ce_unknown   = 0,
       ien_ce_identity  = 1,
       ien_ce_gzip      = 2,
       ien_ce_deflate   = 4,
       ien_ce_compress  = 8,
       ien_ce_pack200   = 16
    };

    enum http_versions {
       ien_http_version_09 =  9, // 0.9
       ien_http_version_10 = 10, // 1.0
       ien_http_version_11 = 11  // 1.1
    };

    enum status_codes {
       ien_status_continue =           100,
       ien_status_switching_protocols = 101,
       ien_status_ok =                 200,
       ien_status_found =              302,
       ien_status_see_other =          303,
       ien_status_not_modified =       304,
       ien_status_bad_request =        400, // Ticket[16125]
       ien_status_unauthorized =       401, // Ticket[19810]
       ien_status_forbidden =          403,
       ien_status_not_found =          404,
       ien_status_method_not_allowed = 405,
       ien_status_internal_error =     500
    };

    // must be conform with 'const char* HTTP_METHODS' in ds_http_header.cpp !!!
    enum http_methodes {
       ien_meth_unknown = -1,        // unknown/invalid
       ien_meth_GET,                // GET
       ien_meth_HEAD,                // HEAD
       ien_meth_POST,               // POST
       ien_meth_PUT,                // PUT
       ien_meth_OPTIONS,            // OPTIONS
       ien_meth_DELETE,             // DELETE
       ien_meth_TRACE,                // TRACE
       ien_meth_CONNECT,            // CONNECT
       // WEBDAV Methods:
       ien_meth_BDELETE,            // BDELETE; only MS
       ien_meth_BMOVE,              // BMOVE; only MS
       ien_meth_BPROPPATCH,         // BPROPPATCH; only MS
       ien_meth_COPY,               // COPY; only MS
       ien_meth_LOCK,               // LOCK; only MS
       ien_meth_MKCOL,              // MKCOL; only MS
       ien_meth_MOVE,               // MOVE; only MS
       ien_meth_POLL,                // POLL; only MS
       ien_meth_PROPFIND,           // PROPFIND; only MS
       ien_meth_PROPPATCH,          // PROPPATCH; only MS
       ien_meth_SUBSCRIBE,            // SUBSCRIPE; only MS
       ien_meth_SEARCH,                // SEARCH; only MS
       ien_meth_not_supported        // not supported
    };

    enum field_types {
        ien_ft_int,
        ien_ft_string
    };

    static ied_charset m_get_charset(const dsd_const_string& rdsp_charset);
    static const dsd_const_string m_get_charset_name(ied_charset iep_charset);
	static content_encodings m_get_encoding(const dsd_const_string& rdsp_enc);

    ds_http_header(void);
    ~ds_http_header(void);
    // clear variables
    int m_clear(bool bo_all);
    // investigate first line of header ("start-line") for correctness, HTTP-version, etc
    bool m_parse_start_line(const dsd_const_string& ahstr_start_line);
    bool m_init(ds_session* ads_session_in);
    // parse a header-line; fill variables (e.g. int_data_len)
    bool m_parse_header_line(const dsd_const_string& ahstr_header_line);
    static bool m_get_content_type(const dsd_const_string& ahstr,
        enum content_types& riep_ct, enum ied_charset& riep_charset);
    // convert the content-type-string to an integer
    content_types m_get_int_for_content_type(const dsd_const_string& ahstr);
    // returns count of lines of this header
    int m_get_count_lines(void);
    // returns true, if received header contains 'Content-Type:chunked'
    bool m_is_chunked(void);
    // returns the value of "Content-Length"-header (may be -1 !!)
    int m_get_content_length(void);
    void m_reset_content_length();
    // return true, if the received data are a response by a webserver
    bool m_is_webserver_response(void);
    // return the content-type-integer
    content_types m_get_content_type(void);

    // method of the start-line (e.g. GET, POST, etc)
    int in_http_method;
    // http-version, which the webbrowser or webserver uses
    int in_http_version;
    // reason phrase returned by the webserver
    ds_hstring hstr_http_reason_phrase;
    // http-version, which the webserver uses
    int in_http_version_webserver;
    // status code returned by webserver
    int in_http_status_code;
    bool bo_hdr_chunked_set;
    bool bo_hdr_gzip_set;
private:
    // convert the Accept-Language-string to an integer
    int m_get_int_for_accept_language(const dsd_const_string& ahstr);
    // get the http-version; return 10=1.0; 11=1.1
    int m_get_http_version(const dsd_const_string& ahstr_http_version);
    int m_get_index(const dsd_const_string& ahstr);

    ds_session* ads_session;
    // count of header-lines; needed to detect leading CRLFs in received headers
    int in_count_lines;
    // URL-type (abs_path, absoluteURI, asterisk ('*'), authority (is not suported!!), abs_path_for_wsg ('/http://www.google.de'), abs_path_for_wsg_ssl ('/https://sparkasse.de')
    int in_url_type;
    // false=data are a request from a browser; true=data are a response from a webserver
    bool bo_webserver_response;
    // field value of header-field "Content-Length"
    int in_content_length;
    // true=header-field 'transfer-Encoding : chunked' was detected
    bool bo_chunked_data;
    content_types in_content_type;
    // header-lines, which are of no interest for us; they are not processed; (even index: key; odd index: value)
    ds_hvector<ds_hstring> dsv_unprocessed_headerlines;
    // true=this request/response envelopes a message body
    bool bo_message_body_announced;
public:
    ds_url dsc_url;

    // the http-header-line containing cookies
    ds_hstring hstr_hdrline_cookie;
    // contains header to be sent
    ds_hstring hstr_hdr_out;

    // Header 'Cookie', which is passed to webserver
    ds_hstring hstr_cookie_line_to_webserver;

    // language, which the browser accepts; language of the communication/error messages/etc
    int in_language;
    int in_content_encoding; // content-encoding; set by the webserver
    // true=there is a header-line "Cookie:..."
    bool bo_cookie_header_exists;
	bool bo_upgrade_websocket;

    ied_charset iec_content_type_charset;

    // field values of the header-line (e.g. 'Content-Type')
    ds_hstring hstr_hf_accept_language,
               hstr_hf_connection,
               hstr_hf_content_type,
               hstr_hf_host,
               hstr_hf_if_modified_since,
               hstr_hf_location,
               hstr_hf_pragma,
               hstr_hf_referer,
               hstr_hf_user_agent,
               hstr_hf_content_security_policy,
			   hstr_hf_content_security_policy_report_only,
			   hstr_hf_referrer_policy,
			   hstr_hf_x_frame_options,
			   hstr_hf_x_ua_compatible,
               hstr_hf_origin;

    ds_hvector<ds_hstring> ds_v_hf_set_cookie;
    ds_hstring             hstr_hf_accept_encoding;
    ds_hvector_btype<dsd_const_string> ds_v_hf_accept_encoding;
    ds_hvector<ds_hstring> ds_v_hf_cache_control; // Ticket[17845]
    ds_hstring             hstr_hf_content_encoding;
    //ds_hvector_btype<dsd_const_string> ds_v_hf_content_encoding;
    ds_hvector<ds_hstring> ds_v_hf_www_authenticate;
	 ds_hstring             hstr_hf_authorization;

    // returns true, when this request/response envelopes a message body
    bool m_is_message_body_announced(void);
    // // return http_method (e.g. GET = ien_meth_GET)
    int m_get_http_method(void);
    // MJ 05.11.08, Ticket[16425]: 
    dsd_const_string m_get_http_method_char(void);

    // add the startline to the out-header
    int m_add_start_line_out(bool bo_request, const dsd_const_string& ahstr_http_version, int in_method_or_statuscode, const dsd_const_string& ahstr_url_or_reasonphrase);
    // get the reasonphrase to a status-code-number
    dsd_const_string m_get_reasonphrase(int in_status_code);
    // add a headerline to the out-header
    int m_add_hdr_line_out(const dsd_const_string& ach_field_name, const dsd_const_string& ach_field_value);
    // add unprocessed headerlines to the out-header
    int m_add_hdr_unprocessed_lines_out(ds_hstring* ahstr_lines);
    // terminate the out-header by adding CRLF
    int m_terminate_hdr_out();
    // get those header-lines, which are not investigated as string
    ds_hstring m_get_unprocessed_headerlines(void);
};

#endif // DS_HTTP_HEADER_H
