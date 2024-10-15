#ifndef DS_URL_H
#define DS_URL_H

#include <ds_hstring.h>
#include <ds_wsp_helper.h>

#define SM_USE_NEW_WSG	1

/*! \brief URL class
 *
 * @ingroup webserver
 *
 * Holds an URL and provides methods to work on it
 */
class ds_url
{
public:
	struct dsd_base_url {
		// Protocol scheme of the URL (e.g. "http")
		dsd_const_string dsc_protocol;
		// Hostname of the URL (e.g. "www.example.com")
		dsd_const_string dsc_hostname;
		// Port of the URL (e.g. "8080")
		dsd_const_string dsc_port;
		// User and password of the URL (e.g. "user:pwd")
		dsd_const_string dsc_user;
		// Path of the URL (e.g. "/page1.html")
		dsd_const_string dsc_path;
		// Search of the URL (e.g. "?query1=value1")
		dsd_const_string dsc_search;
		// Hash of the URL (e.g. "#anchor1")
		dsd_const_string dsc_hash;
		// Not used for output: Host of the URL (e.g. "www.example.com:8080")
		dsd_const_string dsc_host;
		// Not used for output: Resource of the URL (e.g. "/page1.html?query1=value1#anchor1")
		dsd_const_string dsc_resource;
	};

	static dsd_const_string m_get_valid_port(const dsd_base_url& rdsp_base_url);
	static void m_reset_base_url(struct dsd_base_url& rdsp_base_url);
	static bool m_parse_base_url(const dsd_const_string& rdsp_url, struct dsd_base_url& rdsp_base_url);
	static void m_write_base_url(const dsd_base_url& rdsp_base_url, ds_hstring& rdsp_out);
	static void m_make_absolute_url(const dsd_base_url& rdsp_base_url, const dsd_base_url& rdsp_root_url, dsd_base_url& rdsp_out);
	static void m_test_parse(ds_wsp_helper* ads_wsp_helper);

	struct dsd_data_url {
		dsd_const_string dsc_mimetype;
		dsd_const_string dsc_charset;
		bool boc_base64;
		dsd_const_string dsc_content;
	};

	static bool m_parse_data_url(const dsd_const_string& rdsp_url, struct dsd_data_url& rdsp_base_url);
	static void m_write_data_url(const dsd_data_url& rdsp_base_url, ds_hstring& rdsp_out);

public:
    ds_url(void);
    ~ds_url(void);
    void m_init(ds_wsp_helper* ads_wsp_helper);
    void m_setup(ds_wsp_helper* ads_wsp_helper);

    void m_clear(bool bo_all);
    int in_url_type;
    
    ds_hstring hstr_url;               // Entire URL
    dsd_const_string hstr_url_no_id;   // URL as it appears in the http header. HOB-Id "/(HOB...)" is already cut out !!
    ds_hstring hstr_path;        // Path part of the URL. HOB-Id "/(HOB...)" is already cut out !!
#if !SM_USE_NEW_WSG
	dsd_const_string hstr_protocol;    // Protocol of the URL.
#endif
	dsd_const_string hstr_query;       // Query part of the URL.
    //dsd_const_string hstr_authority_abs_url; // Authority of an absolute URL
    dsd_const_string hstr_url_cookie;  // Cookie, which is delivered in URL: Example: "(HOB00000001sL8FVNoh)" in URL will result in a hstr_url_cookie of "00000001sL8FVNoh"
    // true=a cookie is delivered in URL
    bool bo_url_cookie;

    // it is a request for WSG
    bool bo_data_for_wsg;
#if !SM_USE_NEW_WSG    
	dsd_const_string hstr_authority_of_webserver; // Authority of a webserver (e.g. google.de in '/http://google.de')
    dsd_const_string hstr_hostname_of_webserver;
    // request for WSG; protocol to webserver is https!!
    bool bo_ssl_to_ext_ws;
    // request from browser with absolute URL and no SSL (e.g. GET http://abc...)
    // bool bo_abs_url_no_ssl;
    int in_port_of_webserver;
    // JF 22.03.11 Ticket[21567]: URL to external webserver contains a IPv6 address.
    bool bo_ext_ws_ipv6;
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
#endif
};

#endif // DS_URL_H
