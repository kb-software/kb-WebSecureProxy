/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/
//#include <stdio.h>
#define FILE_GET  "interpreter.getmem"      // file handles for memory overview
#define FILE_FREE "interpreter.freemem"

/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "../../ds_session.h"
#include "ds_interpret.h"
#ifdef HL_UNIX
#include <ctype.h>
#endif

/*+-------------------------------------------------------------------------+*/
/*| constructor:                                                            |*/
/*+-------------------------------------------------------------------------+*/
/**
* @ingroup dataprocessor
*/
ds_interpret::ds_interpret(void)
	:ads_session(NULL)
{
} //end of ds_interpret_html::ds_interpret_html

/*+-------------------------------------------------------------------------+*/
/*| destructor:                                                             |*/
/*+-------------------------------------------------------------------------+*/
/**
* @ingroup dataprocessor
*/
ds_interpret::~ds_interpret(void)
{} //end of ds_interpret::~ds_interpret

/*+-------------------------------------------------------------------------+*/
/*| functions:                                                              |*/
/*+-------------------------------------------------------------------------+*/
/**
* @ingroup dataprocessor
*
* @param[in]   ads_session_in		A pointer to the ds_session class
* @param[in]   ach_address_wsp_in	A const char pointer
* @param[in]   ach_address_ext_in	A const char pointer
* @param[in]   ach_path_ext_in		A const char pointer
*
* @return      TRUE    
*
*/
bool ds_interpret::m_setup( ds_session* ads_session_in )
{
	// check incoming data:
	assert( ads_session_in != NULL );

	// initialize some variables:
	ads_session = ads_session_in;
	ads_attr    = &(ads_session->ads_config->ds_wsg_attr);
#if !SM_USE_BASEURL_SUPPORT
	bool bol_negative;
	in_num_directories = m_count_directories( ads_session_in->dsc_ws_gate.dsc_url.hstr_path, 0, bol_negative, NULL );
#endif
	boc_skip_output = false;
	return true;
}

const dsd_const_string ds_interpret::m_escape_js_string(const dsd_const_string& rdsp_src, ds_hstring& rdsp_dst) {
	//    const char CHRL_TMP[] = { '\', ''', '"' };
	rdsp_dst.m_reset();
	int inl_src_len = rdsp_src.m_get_len();
	int inl_src_off = 0;
	int inl_src_last = 0;
	while(inl_src_off < inl_src_len) {
		char chl_value = rdsp_src[inl_src_off];
		dsd_const_string dsl_escape;
		switch(chl_value) {
		case '\\':
			dsl_escape = "\\\\";
			break;
		case '\'':
			dsl_escape = "\\'";
			break;
		case '"':
			dsl_escape = "\\\"";
			break;
		case '\r':
			dsl_escape = "\\r";
			break;
		case '\t':
			dsl_escape = "\\t";
			break;
		case '\n':
			dsl_escape = "\\n";
			break;
		default:
			goto LBL_NEXT;
		}
		if(!rdsp_dst.m_ensure_size(inl_src_len<<1, true))
			return dsd_const_string::m_null();
		rdsp_dst.m_write(rdsp_src.m_get_ptr()+inl_src_last, inl_src_off-inl_src_last);
		rdsp_dst.m_write(dsl_escape);
		inl_src_last = inl_src_off + 1;
LBL_NEXT:
		inl_src_off++;
	}
	if(inl_src_last == 0)
		return rdsp_src;
	rdsp_dst.m_write(rdsp_src.m_get_ptr()+inl_src_last, inl_src_off-inl_src_last);
	return rdsp_dst.m_const_str();
	//dsl_path.m_replace( "\\", "/" );
}

void ds_interpret::m_write_hob_initialize(ds_hstring& dc_insert, const dsd_const_string& dsp_unique_id, const dsd_const_string& dsp_function_name, const dsd_const_string& dsp_html_charset, const dsd_const_string& dsp_worker_type)
{
	// initialize some variables:
	int in_flags = 0;                // flags should be set
	// 0 = use default settings
	// 1 = DEBUG mode (some alerts in script)
	// 2 = free (further: use drag&drop script from walter zorn)
	// 4 = don't add "HOB_type=..." to related urls
	// 8 = don't use cookie storage (use brower as cookie handler)
	ds_hstring ds_welcome = ads_session->dsc_auth.m_get_welcomepage();
	dsd_const_string ach_home   = ads_session->ads_config->ach_site_after_auth;
	if ( ds_welcome.m_get_len() > 0 ) {
		ach_home = ds_welcome.m_const_str();
	}

	// set flag:
#ifdef _DEBUG
	in_flags |= 1;
#endif //_DEBUG

	if ((ads_session->ads_config->in_settings & SETTING_DISABLE_COOKIE_STORAGE) != 0) {
		in_flags |= 8;
	}

	// build stuff to insert:
#ifdef _DEBUG
	static int ins_counter = 0;
	int inl_cur = ins_counter++;
#endif

	dc_insert.m_write( dsp_function_name );
	dc_insert.m_write( "({" );
#ifdef _DEBUG
	dc_insert.m_writef( " inc_cur: %d, ", inl_cur );
#endif

	ds_hstring dsl_temp(ads_session->ads_wsp_helper);
	dsd_const_string adsl_temp = m_escape_js_string(ads_session->dsc_ws_gate.hstr_prot_authority_ext_ws.m_const_str(), dsl_temp);
	dc_insert.m_writef( " strc_address_ext: \"%.*s\",", adsl_temp.m_get_len(), adsl_temp.m_get_ptr() );
	adsl_temp = m_escape_js_string(ads_session->hstr_prot_authority_ws.m_const_str(), dsl_temp);
	dc_insert.m_writef( " strc_address_wsp: \"%.*s\",", adsl_temp.m_get_len(), adsl_temp.m_get_ptr() );
	adsl_temp = m_escape_js_string(ads_session->hstr_prot_authority_ws_ext.m_const_str(), dsl_temp);
	dc_insert.m_writef( " strc_address_wsp2: \"%.*s\",", adsl_temp.m_get_len(), adsl_temp.m_get_ptr() );
	if(ads_session->ads_config->ach_cluster_url.m_get_len() > 0)
	{
		adsl_temp = m_escape_js_string(ads_session->ads_config->ach_cluster_url, dsl_temp);
		dc_insert.m_writef( " strc_cluster_url: \"%.*s\",", adsl_temp.m_get_len(), adsl_temp.m_get_ptr() );
	}
	//adsl_temp = m_escape_js_string(this->ds_net_protocol.m_const_str(), dsl_temp);
	//dc_insert.m_writef( " strc_net_protocol: \"%.*s\",", adsl_temp.m_get_len(), adsl_temp.m_get_ptr() );
	dc_insert.m_writef( " strc_home: \"%.*s\",", ach_home.m_get_len(), ach_home.m_get_ptr() );
	dc_insert.m_write( " strc_hobwsg_file: \"" "/protected/wsg/HOBwsg.js" "\"," );
	dc_insert.m_write( " dsc_cookies: " );
	if ((ads_session->ads_config->in_settings & SETTING_DISABLE_COOKIE_STORAGE) == 0) {
		dsd_const_string dsl_domain = ads_session->dsc_ws_gate.dsc_url.hstr_authority_of_webserver;
		dsd_const_string dsl_path = ads_session->dsc_ws_gate.dsc_url.hstr_path;

		const ds_hvector<ds_cookie>* adsl_cookies = ads_session->dsc_ws_gate.dsc_ck_manager.m_get_cookies(
			dsl_domain, dsl_path, ads_session->dsc_auth.m_get_basename(), ads_session->dsc_ws_gate.dsc_url.bo_ssl_to_ext_ws );

		dc_insert.m_write( "new Array(" );
		if(adsl_cookies != NULL) {
			int in_pos = 0;
			for(HVECTOR_FOREACH(ds_cookie, adsl_cookie, *adsl_cookies)) {
				const ds_cookie& rdsl_cookie = HVECTOR_GET(adsl_cookie);
				if(!rdsl_cookie.m_matches_path(dsl_path)) {
					int a = 0;
					continue;
				}
				if(rdsl_cookie.m_is_httponly())
					continue;
				if ( in_pos > 0 ) {
					dc_insert.m_write( ", " );
				}
				dc_insert.m_write( "'" );
				adsl_temp = m_escape_js_string(rdsl_cookie.m_get_cookie(), dsl_temp);
				dc_insert.m_write( adsl_temp );
				dc_insert.m_write( "; Path=" );
				adsl_temp = m_escape_js_string(rdsl_cookie.m_get_path(), dsl_temp);
				dc_insert.m_write( adsl_temp );
				dc_insert.m_write( "; Domain=" );
				adsl_temp = m_escape_js_string(rdsl_cookie.m_get_domain(), dsl_temp);
				dc_insert.m_write( adsl_temp );
				dc_insert.m_write( "'" );
				in_pos++;
			}
		}
		dc_insert.m_write( ")," );
	}
	else {
		dc_insert.m_write( "null," );
	}
	const dsd_const_string adsl_bookmark_host = ads_session->ads_config->ach_bookmark_host;
	adsl_temp = m_escape_js_string(adsl_bookmark_host, dsl_temp);
	dc_insert.m_writef( " strc_address_bookmark: \"%.*s\",", adsl_temp.m_get_len(), adsl_temp.m_get_ptr() );
	dc_insert.m_writef( " strc_html_charset: \"%.*s\",", dsp_html_charset.m_get_len(), dsp_html_charset.m_get_ptr() );
	if(dsp_unique_id.m_get_len() > 0)
		dc_insert.m_writef( " strc_unique_id: \"%.*s\",", dsp_unique_id.m_get_len(), dsp_unique_id.m_get_ptr() );
	dc_insert.m_writef( " inc_flags: %d", in_flags );
	dc_insert.m_write( "},");
	dc_insert.m_write(dsp_worker_type.m_get_len() <= 0 ? dsd_const_string("window") : dsd_const_string("self"));
	dc_insert.m_write(");" );
}

static void m_write_wsg_base_url(const dsd_const_string& rdsp_url, const ds_url::dsd_base_url& rdsp_base_url, ds_hstring& rdsp_tmp) {
	dsd_const_string dsl_path = rdsp_base_url.dsc_path;
	int inl_path = dsl_path.m_find_last_of("/\\");
	if(inl_path >= 0) {
		dsd_const_string dsl_dir = dsl_path.m_substring(0, inl_path);
		dsd_const_string dsl_file = dsl_path.m_substring(inl_path);

		rdsp_tmp.m_write(":WSG:");
		rdsp_tmp.m_write_rfc3548(rdsp_url.m_get_ptr(), dsl_dir.m_get_end() - rdsp_url.m_get_ptr());
		rdsp_tmp.m_write(dsl_file);
	}
	ds_url::dsd_base_url dsl_base_rest;
	dsl_base_rest.dsc_search = rdsp_base_url.dsc_search;
	dsl_base_rest.dsc_hash = rdsp_base_url.dsc_hash;
	ds_url::m_write_base_url(dsl_base_rest, rdsp_tmp);
}

ds_interpret::ied_change_url_result ds_interpret::m_change_url(const dsd_const_string& rdsp_src, enum ied_change_url_flags iep_flags, ds_hstring& rdsp_tmp) {
	if(rdsp_src.m_get_len() <= 0)
		return ied_change_url_unchanged;
	bool bo_absolute_mode = (iep_flags & ied_change_url_flag_absolute) != 0;

	dsd_const_string dsl_url = rdsp_src;
	dsl_url.m_trim_left(" \f\n\r\t\v\"'");
	// check what kind of url is ads_url:
	rdsp_tmp.m_reset();
#if SM_USE_BASEURL_SUPPORT
	ds_ws_gate::dsd_wsg_url& rdsl_wsg_url = this->ads_session->dsc_ws_gate.dsc_url;
	ds_url::dsd_base_url dsl_base_url;
	if(!ds_url::m_parse_base_url(dsl_url, dsl_base_url)) {
		return ied_change_url_error;
	}
	dsd_const_string dsl_path = dsl_base_url.dsc_path;
	// TODO: Not working yet!
#if 0
	int in_pos = dsl_path.m_index_of(":WSG:");
	if(in_pos >= 0) {
		if (bo_absolute_mode) {
			rdsp_tmp.m_write(this->ads_session->hstr_prot_authority_ws);
			rdsp_tmp.m_write("/wsg/");
		}
		m_write_wsg_base_url(dsl_url, dsl_base_url, rdsp_tmp);
		return rdsp_tmp.m_get_len();
	}
#endif
	if(dsl_base_url.dsc_protocol.m_get_len() > 0) {
		if ( dsl_base_url.dsc_protocol.m_equals_ic("http")
			|| dsl_base_url.dsc_protocol.m_equals_ic("https"))  // MJ 12.08.09, Ticket [18274]
		{
			// kind of "http://www.irgendwas.de/links/page.html" -> insert WSP
			if ( bo_absolute_mode ) {
				rdsp_tmp.m_write(this->ads_session->hstr_prot_authority_ws);
			}
			rdsp_tmp.m_write("/wsg/");
			rdsp_tmp.m_write(dsl_url);
			if ( bo_absolute_mode && dsl_base_url.dsc_path.m_find_first_of("/\\") < 0 ) {
				rdsp_tmp.m_write("/");
			}
			return ied_change_url_changed;
		}
		return ied_change_url_other_protocol;
	}
	// kind of "//www.google.de/" -> insert net_protocol!
	if(dsl_base_url.dsc_hostname.m_get_len() > 0) {
		if(bo_absolute_mode) {
			rdsp_tmp.m_write(this->ads_session->hstr_prot_authority_ws);
			rdsp_tmp.m_write("/wsg/");
			rdsp_tmp.m_write(rdsl_wsg_url.hstr_protocol);
			rdsp_tmp.m_write(":");
			rdsp_tmp.m_write(dsl_url);
			return ied_change_url_changed;
		}
	}
	// kind of "/images/picture.jpg" -> insert root dir!
	else if(dsl_base_url.dsc_path.m_starts_with("/") || dsl_base_url.dsc_path.m_starts_with("\\")) {
		if(bo_absolute_mode) {
			rdsp_tmp.m_write(this->ads_session->hstr_prot_authority_ws);
			rdsp_tmp.m_write("/wsg/");
			rdsp_tmp.m_write(this->ads_session->dsc_ws_gate.hstr_prot_authority_ext_ws);
			rdsp_tmp.m_write(dsl_url);
			return ied_change_url_changed;
		}
	}
	else {
		int in_pos2 = dsl_path.m_index_of("../");
		if(in_pos2 < 0) {
			in_pos2 = dsl_path.m_index_of("..\\");
			if(in_pos2 < 0) {
				return ied_change_url_unchanged;
			}
		}
	}
	if((iep_flags & ied_change_url_flag_prevent_immediate) != 0) {
		return ied_change_url_prevent_immediate;
	}
	m_write_wsg_base_url(dsl_url, dsl_base_url, rdsp_tmp);
	return ied_change_url_changed;
#else
	if ( dsl_url.m_starts_with("//") ) {
		// kind of "//www.google.de/" -> insert net_protocol!
		if ( bo_absolute_mode ) {
			rdsp_tmp.m_write(this->ds_wsp_address);
		}
		rdsp_tmp.m_write("/wsg/");
		rdsp_tmp.m_write(this->ds_net_protocol);
		rdsp_tmp.m_write(dsl_url);
		return rdsp_tmp.m_get_len();
	}
	if ( dsl_url.m_starts_with( "/" ) || dsl_url.m_starts_with( "\\" ) ) {
		// kind of "/images/picture.jpg" -> insert root dir!
		if ( bo_absolute_mode ) {
			rdsp_tmp.m_write(this->ds_wsp_address);
		}
		rdsp_tmp.m_write("/wsg/");
		rdsp_tmp.m_write(this->ds_ext_address);
		rdsp_tmp.m_write(dsl_url);
		return rdsp_tmp.m_get_len();
	}
	if ( dsl_url.m_starts_with_ic( ds_wsp_address.m_const_str() ) ) {
		// our proxy already stands at the beginning -> nothing to do!
		dsd_const_string dsl_path = dsl_url.m_substring(ds_wsp_address.m_get_len());
		if(dsl_path.m_get_len() <= 0)
			return 0;
		if(dsl_path.m_starts_with("/"))
			return 0;
	}
	if ( dsl_url.m_starts_with_ic("http://")
		|| dsl_url.m_starts_with_ic("https://")
		|| dsl_url.m_starts_with_ic("http:\\\\")
		|| dsl_url.m_starts_with_ic("https:\\\\"))  // MJ 12.08.09, Ticket [18274]
	{
		// kind of "http://www.irgendwas.de/links/page.html" -> insert WSP
		if ( bo_absolute_mode ) {
			rdsp_tmp.m_write(this->ds_wsp_address);
		}
		rdsp_tmp.m_write("/wsg/");
		rdsp_tmp.m_write(dsl_url);
		if ( bo_absolute_mode && !dsl_base_url.dsc_path.m_ends_with("/") ) {
			rdsp_tmp.m_write("/");
		}
		return rdsp_tmp.m_get_len();
	}
	int inl_pos = dsl_url.m_index_of(":");
	if(inl_pos >= 0) {
		dsd_const_string dsl_protocol = dsl_url.m_substring(0, inl_pos);
		return -1;
	}
	inl_pos = dsl_url.m_find_first_of("?#");
	dsd_const_string dsl_path = dsl_url;
	if(inl_pos >= 0) {
		dsl_path = dsl_url.m_substring(0, inl_pos);
	}
	if(dsl_path.m_get_len() <= 0) {
		return 0;
	}
	bool bol_negative;
	int in_num_back = m_count_directories(dsl_url, this->in_num_directories, bol_negative, &rdsp_tmp);
	if(bol_negative) {
		return rdsp_tmp.m_get_len();
	}
	/*int in_dir_depth = in_num_directories + in_num_back;
	if(in_dir_depth < 0) {
	return -1;
	}*/
	return 0;
#endif
}

int ds_interpret::m_add_hobtype(ds_hstring& rdsp_url, const dsd_hobtype_data& rdsp_data)
{
	if(rdsp_data.dsc_hobtype.m_get_len() <= 0)
		return 0;
	if ( rdsp_url.m_search_last("?") < 0 ) {
		rdsp_url.m_write("?");
	} else {
		rdsp_url.m_write("&");
	}
	rdsp_url.m_write(rdsp_data.dsc_hobtype);
	if(rdsp_data.dsc_charset.m_get_len() > 0) {
		rdsp_url.m_write(",charset=");
		rdsp_url.m_write(rdsp_data.dsc_charset);
	}
	if(rdsp_data.dsc_origin.m_get_len() > 0) {
		rdsp_url.m_write(",origin=");
		rdsp_url.m_write(rdsp_data.dsc_origin);
	}
	return 1;
}

ds_interpret::ied_change_url_result ds_interpret::m_change_url_ex(const dsd_const_string& rdsp_src, enum ied_change_url_flags iep_flags, const dsd_const_string& dsp_hob_type, ds_hstring& rdsp_tmp) {
	ied_change_url_result iml_res = this->m_change_url(rdsp_src, iep_flags, rdsp_tmp);
	if(iml_res == ied_change_url_error)
		return iml_res;
	if(iml_res == ied_change_url_other_protocol)
		return iml_res;
	dsd_const_string dsl_origin = ads_session->dsc_ws_gate.dsc_url.hstr_hob_type_origin;
	if(dsl_origin.m_get_len() <= 0 && dsp_hob_type.m_equals(HOB_TYPE "any"))
		return iml_res;
	if(iml_res == ied_change_url_unchanged) {
		rdsp_tmp.m_set(rdsp_src);
	}
	dsd_hobtype_data dsl_hobtype_data;
	dsl_hobtype_data.dsc_hobtype = dsp_hob_type;
	dsl_hobtype_data.dsc_origin = dsl_origin;
	int iml_res2 = m_add_hobtype(rdsp_tmp, dsl_hobtype_data);
	if(iml_res2 < 0)
		return ied_change_url_error;
	return ied_change_url_changed;
}

/**
* @ingroup dataprocessor
*
* @param[in]    ach_data            Pointer to the data to be sent
* @param[in]    in_len_data         Int representing the length of the data
* @param[out]   ads_output          Pointer to a ds_hstring class. If ads_output != NULL, all data
*                                   is written to this buffer instead of being sent
* @param[in]    in_send_mode        Int representing the send mode (param for transaction class)
*                                   (default value -1)
*
* @return       1 if data is sent, 0 otherwise 
*/
int ds_interpret::m_send_data( const char* ach_data, int in_len_data, ds_hstring* ads_output )
{
	if ( in_len_data <= 0 ) {
		return 0;
	}
	if (this->boc_skip_output)
		return 0;

	if ( ads_output == NULL ) {
		dsd_const_string dsl_data(ach_data, in_len_data);
		return ads_session->dsc_transaction.m_send_data(dsl_data, ied_sdh_dd_auto);
	} else {
		ads_output->m_write( ach_data, in_len_data );
	}
	return 0;
} // end of ds_interpret::m_send_data

int ds_interpret::m_send_data2( const dsd_const_string& rdsp_const, ds_hstring* ads_output )
{
	return m_send_data(rdsp_const.m_get_ptr(), rdsp_const.m_get_len(), ads_output);
}

void ds_interpret::m_cdata_active(bool bop_state) {
	this->boc_cdata_active = bop_state;
}

void ds_interpret::m_set_skip_output(bool bop_skip) 
{
	this->boc_skip_output = bop_skip;
}

/**
* @ingroup dataprocessor
*
* @param[in]       ach_data		Pointer to the data to be sent
* @param[in]       in_len_data		int value representing the length of the data
* @param[in,out]   ain_position	Position in data
* @param[in]       chr_sign_list	List of signs to look for
* @param[in]       bo_forward      Bool flag indicating the working direction
*/
void ds_interpret::m_pass_signs( const char* ach_data, int in_len_data,
										  int* ain_position, const dsd_const_string& chr_sign_list,
										  bool bo_forward )
{
	// initialize some variables:
	int  in_len_signs  = chr_sign_list.m_get_len();
	if (    in_len_signs < 1 
		|| *ain_position > in_len_data
		|| *ain_position < 0 ) {
			return;
	}

	dsd_const_string dsl_data(ach_data, in_len_data);
	if ( bo_forward == true ) {
		int inl_pos = dsl_data.m_find_first_not_of(chr_sign_list, *ain_position);
		if(inl_pos < 0)
			inl_pos = in_len_data;
		*ain_position = inl_pos;
	} else {
		int inl_pos = dsl_data.m_find_last_not_of(chr_sign_list, *ain_position);
		// Note: The returned position must be exclusive
		inl_pos += 1;
		*ain_position = inl_pos;
	}
	return;
} // end of ds_interpret::m_pass_signs


/**
* @ingroup dataprocessor
*
* @param[in,out]   ads_to_change	String which has to be modified.
* @param[in]       ch_to_remove	Sign which has to be removed from the string.
*
* @return          number of removed signs
*/
int ds_interpret::m_remove_first_last_sign( dsd_const_string& rdsp_to_change, char ch_to_remove )
{
	if ( rdsp_to_change.m_get_len() < 2 ) {
		return 0;
	}
	if ( rdsp_to_change[0] == ch_to_remove
		&& rdsp_to_change[rdsp_to_change.m_get_len()-1] == ch_to_remove ) {
			rdsp_to_change.strc_ptr++;
			rdsp_to_change.inc_length -= 2;
			return 2;
	}
	return 0;
} // end of ds_interpret::m_remove_first_last_sign


/**
* @ingroup dataprocessor
*
* @param[in,out]   ads_to_change	String which has to be modified.
* @param[in]       ch_to_remove	Sign which has to be removed from the string.
*
* @return          number of removed signs
*/
int ds_interpret::m_remove_first_sign( dsd_const_string& rdsp_to_change, char ch_to_remove )
{
	if ( rdsp_to_change.m_get_len() <= 0 ) {
		return 0;
	}
	if ( rdsp_to_change[0] == ch_to_remove ) {
		rdsp_to_change.strc_ptr++;
		rdsp_to_change.inc_length--;
		return 1;
	}
	return 0;
} // end of ds_interpret::m_remove_first_sign


/**
* @ingroup dataprocessor
*
* @param[in,out]   ads_to_change	String which has to be modified.
* @param[in]       ch_to_remove	Sign which has to be removed from the string.
*
* @return          number of removed signs
*/
int ds_interpret::m_remove_last_sign( dsd_const_string& rdsp_to_change, char ch_to_remove )
{
	if ( rdsp_to_change.m_get_len() <= 0 ) {
		return 0;
	}
	if ( rdsp_to_change[rdsp_to_change.m_get_len()-1] == ch_to_remove ) {
		rdsp_to_change.inc_length--;
		return 1;
	}
	return 0;
} // end of ds_interpret::m_remove_last_sign


/**
* @ingroup dataprocessor
*
* @param[in,out] aach_data       pointer to data
* @param[in,out] ain_len_data    pointer to length of data
* @param[in,out] ain_position    position in data
*/
void ds_interpret::m_move_char_pointer( const char** aach_data, int* ain_len_data, int* ain_position )
{
	if ( *aach_data == NULL || *ain_len_data <= 0 ) {
		return;
	}
	if ( *ain_position <= *ain_len_data ) {
		*aach_data    += *ain_position;
		*ain_len_data -= *ain_position;
		*ain_position  = 0;
	} else {
		*aach_data += (*ain_len_data - 1);
		*ain_len_data = 0;
		*ain_position = 0;
	}
} // end of ds_interpret::m_move_char_pointer


/**
* @ingroup dataprocessor
*/
int ds_interpret::m_process_data()
{
	// initialize some variables:
	int in_ret = 0;
	const char* ach_data;
	int   in_len_data      = 0;
	int   in_data_complete = 0;
	int   in_data_written  = 0;

	while ( in_data_complete == 0 && in_len_data >= 0 ) {
		// reset ach_data, in_len_data
		ach_data    = NULL;
		in_len_data = -1;
		// get data
		in_data_complete = ads_session->dsc_transaction.m_get_data( &ach_data, &in_len_data );
		if(in_data_complete < 0)
			return in_data_complete;
		in_ret = m_send_data( ach_data, in_len_data );
		if(in_ret < 0)
			return -1;
		in_data_written += in_ret;
	}
	return (in_data_written > 0);
} // end of ds_interpret::m_process_data_simu()

/**
* @ingroup dataprocessor
*
* @param[in]   achp_data			A pointer to the input data
* @param[in]   inp_len_data		The length of the input data
* @param[in]   bop_data_complete	A bool flag to indicate whether data is complete
*									(default value = false)
* @param[out]  adsp_output			If this pointer is NOT NULL, data will be written 
*                                  in this buffer instead of being send to browser
*                                  (default value = NULL)
*
* @return      1 if data was sent, 0 otherwise
* 
*/
int ds_interpret::m_parse_data( const char *achp_data, int inp_len_data,
										 bool bop_data_complete, ds_hstring *adsp_output )
{
	m_send_data( achp_data, inp_len_data, adsp_output );
	return 1;
} // end of dsd_interpret_ica::m_parse_data

/**
* @ingroup dataprocessor
*
* @param[in]   a_address		Address of memory being traced
* @param[in]   in_len_data		Length of data within a_address
* @param[in]   bo_free_memory	Bool flag indicating whether the memory was freed
*/
void ds_interpret::m_trace_memory( void* a_address, int in_len_data, bool bo_free_memory )
{
	FILE* out;
	if ( bo_free_memory ) {
		out = fopen( FILE_FREE, "a" );
		fprintf( out, "address: %p \t length: %d\n", a_address, in_len_data );
	} else {
		out = fopen( FILE_GET, "a" );
		fprintf( out, "address: %p \t length: %d\n", a_address, in_len_data );
	}
	fclose(out);
} // end of ds_interpret::m_trace_memory

/**
* @ingroup dataprocessor
*
* @param[in]   ach_path  Pointer to a path (like "/images/large/bild.gif")
*
* @return      number of folders (would be two in this example)
*/
int ds_interpret::m_count_directories( const dsd_const_string& rdsp_path, int inp_depth, bool& rbop_negative, ds_hstring* adsp_normalized )
{
	// initialize some variables:
	int inl_dirs = inp_depth;
	dsd_const_string dsl_path = rdsp_path;
	int in_pos = 0;
	bool bol_negative = false;
	while (true) {
		int in_pos2 = dsl_path.m_index_of(in_pos, "/");
		if(in_pos2 < 0)
			break;
		dsd_const_string dsl_pc = dsl_path.m_substring(in_pos, in_pos2);
		if(dsl_pc.m_equals(""))
			goto LBL_NEXT;
		if(dsl_pc.m_equals("."))
			goto LBL_NEXT;
		if(dsl_pc.m_equals("..")) {
			inl_dirs--;
			if(inl_dirs < 0) {
				if(!bol_negative && adsp_normalized != NULL)
					adsp_normalized->m_write(rdsp_path.m_substring(0, in_pos));
				bol_negative = true;
				goto LBL_NEXT2;
			}
			goto LBL_NEXT;
		}
		inl_dirs++;
LBL_NEXT:
		if(bol_negative && adsp_normalized != NULL) {
			dsd_const_string dsl_pc2 = dsl_path.m_substring(in_pos, in_pos2+1);
			adsp_normalized->m_write(dsl_pc2);
		}
LBL_NEXT2:
		in_pos = in_pos2 + 1;
	}
	if(bol_negative && adsp_normalized != NULL) {
		dsd_const_string dsl_pc2 = dsl_path.m_substring(in_pos);
		adsp_normalized->m_write(dsl_pc2);
	}
	rbop_negative = bol_negative;
	return inl_dirs;
} // end of ds_interpret::m_count_directories

bool ds_interpret::m_normalize_path( const dsd_const_string& rdsp_path, ds_hstring& rdsp_normalized )
{
	// initialize some variables:
	//int inl_dirs = 0;
	dsd_const_string dsl_path = rdsp_path;
	int in_pos = 0;
	bool bol_negative = false;
	while (true) {
		int in_pos2 = dsl_path.m_index_of(in_pos, "/");
		if(in_pos2 < 0)
			break;
		dsd_const_string dsl_pc = dsl_path.m_substring(in_pos, in_pos2);
		if(dsl_pc.m_equals(""))
			goto LBL_WRITE;
		if(dsl_pc.m_equals("."))
			goto LBL_NEXT;
		if(dsl_pc.m_equals("..")) {
			int inl_pos = rdsp_normalized.m_search_last(rdsp_normalized.m_get_len()-2, "/");
			// Have we reached the root?
			if(inl_pos < 0)
				goto LBL_NEXT;
			inl_pos++;
			int inl_num_erase = rdsp_normalized.m_get_len() - inl_pos;
			rdsp_normalized.m_erase(inl_pos, inl_num_erase);
			goto LBL_NEXT;
		}
LBL_WRITE:
		rdsp_normalized.m_write(dsl_path.m_substring(in_pos, in_pos2+1));
LBL_NEXT:
		in_pos = in_pos2 + 1;
	}
	dsd_const_string dsl_pc2 = dsl_path.m_substring(in_pos);
	rdsp_normalized.m_write(dsl_pc2);
	return true;
} // end of ds_interpret::m_normalize_path

/**
* @ingroup dataprocessor
*
* @param[in]   ads_path     Pointer to a path (like "../../images/large/bild.gif")
* @param[in]   in_offset    Int value representing start point of search
*
* @return      number of "../" (would be two in this example)
*
*/
int ds_interpret::m_count_dotdotslash( const dsd_const_string& rdsp_path )
{
	// initialize some variables:
	int in_return = 0;
	int in_pos    = rdsp_path.m_index_of("../");

	while ( in_pos != -1 ) {
		in_return++;
		in_pos++;
		in_pos = rdsp_path.m_index_of(in_pos, "../");
	}
	return in_return;
} // end of ds_interpret::m_count_dotdotslash

/**
* @ingroup dataprocessor
*
* @param[in] ach_org         Pointer to a string to search in
* @param[in] in_len_org      Int value representing length of ach_org
* @param[in] ach_search      Pointer to a string to search for (zero terminated!)
* @param[in] bo_ignore_case  Bool flag indicating whether to ignore case
*
* @return    found position of ach_search, -1 if not found
*
*/
int ds_interpret::m_search_ic( const char* ach_org, int in_len_org,
										const dsd_const_string& rdsp_search )
{
	dsd_const_string dsl_org(ach_org, in_len_org);
	return dsl_org.m_index_of_ic(rdsp_search);
} // end of ds_interpret::m_search


/**
* @ingroup dataprocessor
*
* @param[in] ach_org         Pointer to a string to search in
* @param[in] in_len_org      Int value representing length of ach_org
* @param[in] ach_search      Pointer to a string to search for (zero terminated!)
* @param[in] bo_ignore_case  Bool flag indicating whether to ignore case
*
* @return    found position of ach_search, -1 if not found
*
*/
int ds_interpret::m_search_ic( const char* ach_org,    int in_len_org,
										const char* ach_search, int in_len_search )
{
	return this->m_search_ic(ach_org, in_len_org, dsd_const_string(ach_search, in_len_search));
} // end of ds_interpret::m_search


/**
* @ingroup dataprocessor
*
* @param[in]    ach_org			Pointer to a string
* @param[in]    in_len_org			Int value representing length of ach_org
* @param[in]    ach_comp			Pointer to string to compare (zero terminated)
* @param[in]    bo_ignore_case		Bool flag indicating whether to ignore case
*
* @return       TRUE if strings are equal, FALSE otherwise
*
*/
bool ds_interpret::m_equals_ic( const char* ach_org, int in_len_org,
										 const dsd_const_string& rdsp_comp )
{
	dsd_const_string dsl_org(ach_org, in_len_org);
	return dsl_org.m_equals_ic(rdsp_comp);
} // end of ds_interpret::m_equals


/**
* @ingroup dataprocessor
*
* @param[in]    ach_org			Pointer to a string
* @param[in]    in_len_org			Int value representing length of ach_org
* @param[in]    ach_comp			Pointer to string to compare 
* @param[in]    in_len_comp		Int value representing length of ach_comp
* @param[in]    bo_ignore_case		Bool flag indicating whether to ignore case
*
* @return       TRUE if strings are equal, FALSE otherwise
*
*/
bool ds_interpret::m_equals_ic( const char* ach_org, int in_len_org,
										 const char* ach_comp, int in_len_comp )
{
	return this->m_equals_ic(ach_org, in_len_org, dsd_const_string(ach_comp, in_len_comp));
} // end of ds_interpret::m_equals

//! Search for a string (ach_search) within another string (ach_org).
int ds_interpret::m_search( const char* ach_org, int in_len_org, const dsd_const_string& ach_search )
{
	dsd_const_string dsl_org(ach_org, in_len_org);
	return dsl_org.m_index_of(ach_search);
}

//! Comparte two strings together. Returns TRUE if the strings match.
bool ds_interpret::m_equals( const char* ach_org, int in_len_org, const dsd_const_string& ach_comp ) 
{
	dsd_const_string dsl_org(ach_org, in_len_org);
	return dsl_org.m_equals(ach_comp);
}

//! Comparte two strings together. Returns TRUE if the strings match.
bool ds_interpret::m_equals ( const char* ach_org, int in_len_org, const char* ach_comp, int in_len_comp )
{
	return this->m_equals(ach_org, in_len_org, dsd_const_string(ach_comp, in_len_comp));
}
