#include "ds_url.h"

#include <types_defines.h>
#include "ds_http_header.h"

ds_url::ds_url(void)
: in_url_type(0)
, bo_data_for_wsg(false)
, bo_url_cookie(false)
//, bo_abs_url_no_ssl(false)
#if !SM_USE_NEW_WSG  
, bo_ssl_to_ext_ws(false)
, bo_ext_ws_ipv6(false)
, in_port_of_webserver(0)
#endif
{
}

/*! \brief Creates URL
 *
 * @ingroup webserver
 *
 * This method shall be called, when a ds_url is created on the stack (see ds_ws_gate::m_handle_request).
 */
void ds_url::m_setup(ds_wsp_helper* ads_wsp_helper) {
    hstr_url.m_setup(ads_wsp_helper);
    hstr_url_no_id.m_reset();
    hstr_path.m_setup(ads_wsp_helper);
#if !SM_USE_NEW_WSG  
	hstr_protocol.m_reset();
#endif
	hstr_query.m_reset();
    hstr_url_cookie.m_reset();
    //hstr_authority_abs_url.m_reset();
#if !SM_USE_NEW_WSG  
    hstr_authority_of_webserver.m_reset();
    hstr_hostname_of_webserver.m_reset();
    hstr_hob_query.m_reset();
#endif
}

/*! \brief Class Initializer
 *
 * @ingroup webserver
 *
 * Initializes the class
 */
void ds_url::m_init(ds_wsp_helper* ads_wsp_helper) {
    hstr_url.m_init(ads_wsp_helper);
    //hstr_url_no_id.m_init(ads_wsp_helper);
    hstr_path.m_init(ads_wsp_helper);
    //hstr_query.m_init(ads_wsp_helper);
    //hstr_authority_of_webserver.m_init(ads_wsp_helper);
    //hstr_authority_abs_url.m_init(ads_wsp_helper);
    //hstr_hostname_of_webserver.m_init(ads_wsp_helper);
    //hstr_url_cookie.m_init(ads_wsp_helper);
}

ds_url::~ds_url(void)
{
}


/*! \brief Clear the attributes
 *
 * @ingroup webserver
 *
 * Clear the variables of the class
 */
void ds_url::m_clear(bool bo_all)
{
    in_url_type = 0;
    bo_data_for_wsg = false;
    bo_url_cookie = false;
    //bo_abs_url_no_ssl = false;
#if !SM_USE_NEW_WSG 
	bo_ssl_to_ext_ws = false;
    bo_ext_ws_ipv6 = false;
	in_port_of_webserver = 0;
    in_hob_type = ds_http_header::ien_hobtype_not_defined;
    iec_hob_type_charset = ied_chs_invalid;
	hstr_hob_type_origin.m_reset();
	hstr_hob_type_worker.m_reset();
#endif

    if (bo_all) {
        hstr_url.m_reset();
        hstr_url_no_id.m_reset();
        hstr_path.m_reset();
#if !SM_USE_NEW_WSG
		hstr_protocol.m_reset();
#endif
		hstr_query.m_reset();
        hstr_url_cookie.m_reset();
        //hstr_authority_abs_url.m_reset();
#if !SM_USE_NEW_WSG 
        hstr_authority_of_webserver.m_reset();
        hstr_hostname_of_webserver.m_reset();
        hstr_hob_query.m_reset();
#endif
	}
}

void ds_url::m_reset_base_url(struct ds_url::dsd_base_url& rdsp_base_url) {
	rdsp_base_url.dsc_protocol.m_reset();
	rdsp_base_url.dsc_hostname.m_reset();
	rdsp_base_url.dsc_port.m_reset();
	rdsp_base_url.dsc_user.m_reset();
	rdsp_base_url.dsc_path.m_reset();
	rdsp_base_url.dsc_search.m_reset();
	rdsp_base_url.dsc_hash.m_reset();
	rdsp_base_url.dsc_host.m_reset();
	rdsp_base_url.dsc_resource.m_reset();
}

bool ds_url::m_parse_base_url(const dsd_const_string& rdsp_url, struct ds_url::dsd_base_url& rdsp_base_url) {
	char chl_cur;
	dsd_const_string dsl_resource;
	dsd_const_string dsl_cur = rdsp_url;
	int inl_pos = dsl_cur.m_find_first_of(":/\\?#");
	if(inl_pos < 0) {
		rdsp_base_url.dsc_path = dsl_cur;
		goto LBL_PARSE_RESOURCE4;
	}
	if(inl_pos > 0) {
		chl_cur = dsl_cur[inl_pos];
		if(chl_cur == ':') {
			rdsp_base_url.dsc_protocol = dsl_cur.m_substring(0, inl_pos);
			dsl_cur = dsl_cur.m_substring(inl_pos+1);
		}
	}
	dsl_resource = dsl_cur;
	if(dsl_resource.m_starts_with("//") || dsl_resource.m_starts_with("\\\\")) {
		dsl_cur = dsl_resource.m_substring(2);
		dsl_resource = dsl_cur.m_substring(dsl_cur.m_get_len());
		inl_pos = dsl_cur.m_find_first_of("@/\\?#");
		if(inl_pos < 0)
			goto LBL_PARSE_RESOURCE2;
		chl_cur = dsl_cur[inl_pos];
		if(chl_cur == '@') {
			rdsp_base_url.dsc_user = dsl_cur.m_substring(inl_pos);
			dsl_cur = dsl_cur.m_substring(inl_pos+1);
			inl_pos = dsl_cur.m_find_first_of("/\\?#");
			if(inl_pos < 0) {
				goto LBL_PARSE_RESOURCE2;
			}
		}
		// Save resource for later analyzing
		dsl_resource = dsl_cur.m_substring(inl_pos); 
		dsl_cur = dsl_cur.m_substring(0, inl_pos);
LBL_PARSE_RESOURCE2:
		rdsp_base_url.dsc_host = dsl_cur;		
		// Is IPv6 address?
		if(dsl_cur.m_starts_with("[")) {
			inl_pos = dsl_cur.m_index_of("]");
			if(inl_pos < 0)
				return false;
			rdsp_base_url.dsc_hostname = dsl_cur.m_substring(0, inl_pos+1);				
			dsl_cur = dsl_cur.m_substring(inl_pos+1);
			inl_pos = dsl_cur.m_last_index_of(":");
			if(inl_pos < 0)
				goto LBL_PARSE_RESOURCE3;
			rdsp_base_url.dsc_port = dsl_cur.m_substring(inl_pos+1);				
			goto LBL_PARSE_RESOURCE3;
		}
		inl_pos = dsl_cur.m_last_index_of(":");
		if(inl_pos < 0) {
			rdsp_base_url.dsc_hostname = dsl_cur;				
			goto LBL_PARSE_RESOURCE3;
		}
		rdsp_base_url.dsc_hostname = dsl_cur.m_substring(0, inl_pos);				
		rdsp_base_url.dsc_port = dsl_cur.m_substring(inl_pos+1);
		goto LBL_PARSE_RESOURCE3;
	}
LBL_PARSE_RESOURCE3:
	rdsp_base_url.dsc_resource = dsl_resource;
	dsl_cur = dsl_resource;
	inl_pos = dsl_cur.m_find_first_of("?#");
	if(inl_pos < 0) {
		rdsp_base_url.dsc_path = dsl_cur;
		goto LBL_PARSE_RESOURCE4;
	}
	rdsp_base_url.dsc_path = dsl_cur.m_substring(0, inl_pos);
	chl_cur = dsl_cur[inl_pos];
	if(chl_cur == '?') {
		dsl_cur = dsl_cur.m_substring(inl_pos);
		inl_pos = dsl_cur.m_find_first_of("#", 1);
		if(inl_pos < 0) {
			rdsp_base_url.dsc_search = dsl_cur;
			goto LBL_PARSE_RESOURCE4;
		}
		rdsp_base_url.dsc_search = dsl_cur.m_substring(0, inl_pos);
		chl_cur = dsl_cur[inl_pos];
	}
	if(chl_cur == '#') {
		rdsp_base_url.dsc_hash = dsl_cur.m_substring(inl_pos);
	}
LBL_PARSE_RESOURCE4:
	return true;
}

void ds_url::m_write_base_url(const ds_url::dsd_base_url& rdsp_base_url, ds_hstring& rdsp_out) {
	if(rdsp_base_url.dsc_protocol.m_get_len() > 0) {
		rdsp_out.m_write(rdsp_base_url.dsc_protocol);
		rdsp_out.m_write(":");
	}
	if(rdsp_base_url.dsc_hostname.m_get_len() > 0) {
		rdsp_out.m_write("//");
		if(rdsp_base_url.dsc_user.m_get_len() > 0) {
			rdsp_out.m_write(rdsp_base_url.dsc_user);
			rdsp_out.m_write("@");
		}
		rdsp_out.m_write(rdsp_base_url.dsc_hostname);
		if(rdsp_base_url.dsc_port.m_get_len() > 0) {
			rdsp_out.m_write(":");
			rdsp_out.m_write(rdsp_base_url.dsc_port);
		}
	}
	rdsp_out.m_write(rdsp_base_url.dsc_path);
	rdsp_out.m_write(rdsp_base_url.dsc_search);
	rdsp_out.m_write(rdsp_base_url.dsc_hash);
}

dsd_const_string ds_url::m_get_valid_port(const dsd_base_url& rdsp_base_url)
{
	if(rdsp_base_url.dsc_port.m_get_len() > 0)
		return rdsp_base_url.dsc_port;
	if(rdsp_base_url.dsc_protocol.m_equals("http")) {
		return dsd_const_string("80");
	}
	if(rdsp_base_url.dsc_protocol.m_equals("ws")) {
		return dsd_const_string("80");
	}
	if(rdsp_base_url.dsc_protocol.m_equals("https")) {
		return dsd_const_string("443");
	}
	if(rdsp_base_url.dsc_protocol.m_equals("wss")) {
		return dsd_const_string("443");
	}
	return dsd_const_string::m_null();
}

void ds_url::m_make_absolute_url(const dsd_base_url& rdsp_base_url, const dsd_base_url& rdsp_root_url, dsd_base_url& rdsp_out) {
	rdsp_out = rdsp_base_url;
	if(rdsp_base_url.dsc_protocol.m_get_len() > 0) {
		return;
	}
	rdsp_out.dsc_protocol = rdsp_root_url.dsc_protocol;
	// kind of "//www.google.de/" -> insert net_protocol!
	if(rdsp_base_url.dsc_hostname.m_get_len() > 0) {
		return;
	}

	rdsp_out.dsc_hostname = rdsp_root_url.dsc_hostname;
	rdsp_out.dsc_host = rdsp_root_url.dsc_host;
	rdsp_out.dsc_port = rdsp_root_url.dsc_port;
}

bool ds_url::m_parse_data_url(const dsd_const_string& rdsp_url, struct dsd_data_url& rdsp_base_url) {
	struct ds_url::dsd_base_url dsl_base_url;
	if(!m_parse_base_url(rdsp_url, dsl_base_url))
		return false;
	if(!dsl_base_url.dsc_protocol.m_equals("data"))
		return false;
	dsd_const_string strl_path = dsl_base_url.dsc_path;
	int inl_pos = strl_path.m_index_of(",");
	if(inl_pos < 0)
		return false;
	dsd_const_string strl_params = strl_path.m_substring(0, inl_pos);
	dsd_const_string strl_data = strl_path.m_substring(inl_pos+1);
	dsd_const_string dsl_cur;
	
	rdsp_base_url.dsc_charset.m_reset();
	rdsp_base_url.dsc_mimetype.m_reset();
	rdsp_base_url.boc_base64 = false;
	inl_pos = strl_params.m_last_index_of(";");
	if(inl_pos < 0)
		goto LBL_DONE;
	dsl_cur = strl_params.m_substring(inl_pos+1);
	if(dsl_cur.m_equals("base64")) {
		strl_params = strl_params.m_substring(0, inl_pos);
		rdsp_base_url.boc_base64 = true;
		inl_pos = strl_params.m_last_index_of(";");
		if(inl_pos < 0)
			goto LBL_DONE;
		dsl_cur = strl_params.m_substring(inl_pos+1);
	}
	if(dsl_cur.m_starts_with("charset=")) {
		strl_params = strl_params.m_substring(0, inl_pos);
		rdsp_base_url.dsc_charset = dsl_cur.m_substring(8);
		inl_pos = strl_params.m_last_index_of(";");
		if(inl_pos < 0)
			goto LBL_DONE;
		dsl_cur = strl_params.m_substring(inl_pos+1);
	}

LBL_DONE:
	rdsp_base_url.dsc_mimetype = strl_params;
	rdsp_base_url.dsc_content = strl_data;
	return true;
}

void ds_url::m_write_data_url(const dsd_data_url& rdsp_data_url, ds_hstring& rdsp_out) {
	rdsp_out.m_write("data:");
	rdsp_out.m_write(rdsp_data_url.dsc_mimetype);
	if(rdsp_data_url.dsc_charset.m_get_len() > 0) {
		rdsp_out.m_write(";charset=");
		rdsp_out.m_write(rdsp_data_url.dsc_charset);
	}
	if(rdsp_data_url.boc_base64) {
		rdsp_out.m_write(";base64");
	}
	rdsp_out.m_write(",");
	rdsp_out.m_write(rdsp_data_url.dsc_content);
}

static void m_test_parse_simple(const dsd_const_string& rdsp_url, ds_wsp_helper* ads_wsp_helper) {
	struct ds_url::dsd_base_url dsl_base_url;
	if(!ds_url::m_parse_base_url(rdsp_url, dsl_base_url))
		exit(1);
	printf("m_parse_base_url %.*s:\n", rdsp_url.m_get_len(), rdsp_url.m_get_ptr());
	printf("   protocol=%.*s\n", dsl_base_url.dsc_protocol.m_get_len(), dsl_base_url.dsc_protocol.m_get_ptr());
	printf("   user=%.*s\n", dsl_base_url.dsc_user.m_get_len(), dsl_base_url.dsc_user.m_get_ptr());
	printf("   hostname=%.*s\n", dsl_base_url.dsc_hostname.m_get_len(), dsl_base_url.dsc_hostname.m_get_ptr());
	printf("   port=%.*s\n", dsl_base_url.dsc_port.m_get_len(), dsl_base_url.dsc_port.m_get_ptr());
	printf("   host=%.*s\n", dsl_base_url.dsc_host.m_get_len(), dsl_base_url.dsc_host.m_get_ptr());
	printf("   resource=%.*s\n", dsl_base_url.dsc_resource.m_get_len(), dsl_base_url.dsc_resource.m_get_ptr());
	printf("   path=%.*s\n", dsl_base_url.dsc_path.m_get_len(), dsl_base_url.dsc_path.m_get_ptr());
	printf("   search=%.*s\n", dsl_base_url.dsc_search.m_get_len(), dsl_base_url.dsc_search.m_get_ptr());
	printf("   hash=%.*s\n", dsl_base_url.dsc_hash.m_get_len(), dsl_base_url.dsc_hash.m_get_ptr());
	ds_hstring hstr_tmp(ads_wsp_helper, "");
	ds_url::m_write_base_url(dsl_base_url, hstr_tmp);
	if(!hstr_tmp.m_const_str().m_equals(rdsp_url))
		exit(1);
}

void ds_url::m_test_parse(ds_wsp_helper* ads_wsp_helper) {
	m_test_parse_simple("https://www.example.com:443/path/file.html?query=value#hash1", ads_wsp_helper);
	m_test_parse_simple("//www.example.com:443/path/file.html?query=value#hash1", ads_wsp_helper);
	m_test_parse_simple("/path/file.html?query=value#hash1", ads_wsp_helper);
	m_test_parse_simple("?query=value#hash1", ads_wsp_helper);
	m_test_parse_simple("#hash1", ads_wsp_helper);
	m_test_parse_simple("https://www.example.com:443?query=value#hash1", ads_wsp_helper);
	m_test_parse_simple("https://www.example.com:443", ads_wsp_helper);
	m_test_parse_simple("/abc", ads_wsp_helper);
	m_test_parse_simple("", ads_wsp_helper);
	m_test_parse_simple("data:text/plain;charset=iso-8859-7,%be%fa%be", ads_wsp_helper);
}
