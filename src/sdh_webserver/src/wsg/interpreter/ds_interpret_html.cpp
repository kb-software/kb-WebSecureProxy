/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "../../ds_session.h"
#include "ds_interpret_html.h"
#ifndef HOB_XSLUNIC1_H
#define HOB_XSLUNIC1_H
#include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H

/*+-------------------------------------------------------------------------+*/
/*| constructor:                                                            |*/
/*+-------------------------------------------------------------------------+*/

/**
* @ingroup dataprocessor
*/
ds_interpret_html::ds_interpret_html(void) : ds_interpret()
{
#if 0
	in_state             = HTML_NORMAL;
	in_get_tag_state     = HTML_GET_TAG;
	bo_icon_found        = false;
	bo_head_found        = false;
	bo_hobscript_added   = false;
	bo_change_data       = true;
	bo_in_comments       = false;
	bo_back_slash_ending = false;
	boc_xua_compatible_found = false;
	inc_iframe_depth      = 0;
#if 0
	ach_start_comment    = NULL;
#endif
	ch_last_sign         = 0;
	boc_insert_ica_call  = false;
	iec_meta_charset     = ied_chs_invalid;
#endif
} //end of ds_interpret_html::ds_interpret_html

/*+-------------------------------------------------------------------------+*/
/*| destructor:                                                             |*/
/*+-------------------------------------------------------------------------+*/

/**
* @ingroup dataprocessor
*/
ds_interpret_html::~ds_interpret_html(void)
{
} //end of ds_interpret_html::~ds_interpret_html

/*+-------------------------------------------------------------------------+*/
/*| functions:                                                              |*/
/*+-------------------------------------------------------------------------+*/

/**
* @ingroup dataprocessor
*
* @return      int     1 if some data is written, 0 otherwise
*
*/
int ds_interpret_html::m_process_data( )
{
	// initialize some variables:
	const char* ach_data;
	int   in_len_data      = 0;
	int   in_data_complete = 0;
	int   in_sum_written  = 0;

	while ( in_data_complete == 0 && in_len_data > -1 ) {
		// reset ach_data, in_len_data
		ach_data    = NULL;
		in_len_data = -1;
		// get data
		in_data_complete = ads_session->dsc_transaction.m_get_data( &ach_data, &in_len_data );
		if(in_data_complete < 0)
			return in_data_complete;
		if(in_len_data <= 0) {
			if(in_data_complete == 0)
				break;
			int in_data_written = m_parse_data( NULL, 0, true );
			if(in_data_written < 0)
				return -1;
			in_sum_written += in_data_written;
			break;
		}
		ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
			"html-interpreter: m_get_data() returned %d",
			in_len_data );
		// parse data
#if SM_INTERPRET_PUSH_SINGLE
		for(int i=0;i<(in_len_data-1); i++) {
			int in_data_written = m_parse_data( &ach_data[i], 1, false );
			if(in_data_written < 0)
				return -1;
			in_sum_written += in_data_written;
		}
		int in_data_written = m_parse_data( &ach_data[in_len_data-1], 1, in_data_complete > 0 );
		if(in_data_written < 0)
			return -1;
		in_sum_written += in_data_written;
#else
		int in_data_written = m_parse_data( ach_data, in_len_data, in_data_complete > 0 );
		if(in_data_written < 0)
			return -1;
		in_sum_written += in_data_written;
#endif
	}
	return (in_sum_written > 0);    
} // end of m_process_data

/**
* @ingroup dataprocessor
*
* @param[in]   ach_data           char pointer which points to the input data
* @param[in]   in_len_data        int value representing the length of the input data
* @param[in]   bo_data_complete   Bool flag indicating if data is complete (whole file not whole gather!)
*                                 (default value = false)
* @param[out]  ads_output         If this pointer is NOT NULL, data will be written in this buffer
*                                 instead of being send to browser (default value = NULL)
*
* @return      1 if data was sent, 0 otherwise
*
*/
int ds_interpret_html::m_parse_data( const char* ach_data, int in_len_data, bool bo_data_complete, ds_hstring* ads_output ) 
{
	int    in_ret = 0;     // signal for transaction class
	int    in_parser_return = 0;     // return from the other interpreter

	ds_tag.m_init( ads_session->ads_wsp_helper );

#if 0
	ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "[%d] HTML.m_parse_data: in_len_data=%d\n",
		ads_session->ads_wsp_helper->m_get_session_id(), in_len_data);
	ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, dsd_const_string(ach_data, in_len_data));
	int inl_lookup = dsd_const_string(ach_data, in_len_data).m_index_of("_.Ux=/</g");
	const char* achl_lookup = NULL;
	if(inl_lookup >= 0) {
		int a = 0;
		achl_lookup = &ach_data[inl_lookup];
	}
#endif

#if 0
	if ( (ach_data == NULL) || (in_len_data == -1) ) {
		if ( bo_data_complete ) {
			// case of data sent by webserver without length information! 
			// send all data, that was saved in current session, free memory, quit.
			if ( ds_tag.m_get_len() != 0 ) {
				// in this case probably an error in data occured, because a tag is not closed!
				ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning,
					"HWSGW105W: supposed error in html data, last tag not closed" );
				if ( ach_start_comment != NULL ) {
					// MJ 31.03.09, Ticket[17234]:
					ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning,
						"HWSGW112W: not ending comment tag found." );
					ds_hstring ds_temp;
					ds_temp.m_setup( ads_session->ads_wsp_helper, ds_tag.m_get_len() );
					m_send_data( ds_tag.m_get_ptr(), 1, ads_output );
					ds_temp.m_write( ds_tag.m_get_ptr() + 1, ds_tag.m_get_len() - 1 );
					ach_start_comment = NULL;
					in_get_tag_state  = HTML_GET_TAG;
#if 0
					// we must change working state from cut states to non cut:
					switch ( in_state ) {
					case HTML_CUT_TAG_SCRIPT_DATA:
						in_state = HTML_SCRIPT_DATA;
						break;
					}
#endif
					ds_tag.m_reset();
					m_parse_data( ds_temp.m_get_ptr(), ds_temp.m_get_len(), true, ads_output );
				} else {
					m_send_data( ds_tag.m_get_ptr(), ds_tag.m_get_len(), ads_output );
					ds_tag.m_reset();
				}
			}
		} 
		// no data available
		return in_ret;
	}
#endif

	// initialize some variables:
	int    in_position           = 0;           // actual position in data
	int    in_tag_start          = 0;           // start position of tag in data
	//int    in_tag_key            = 0;           // key for tagname
	int    in_process_tag_return = 0;           // return of m_process_tag
	const char*  ach_tag         = NULL;        // pointer to found tag
	int    in_len_tag            = 0;           // length of found tag
	const char*  ach_tag_name    = NULL;        // pointer to tag name
	int    in_len_name           = 0;           // length of tag name
	ds_hstring dc_changed_tag;                  // buffer for changed tag
	dc_changed_tag.m_setup( ads_session->ads_wsp_helper, HTML_DEFAULT_TAG_SIZE );

	// start parsing:
	while ( in_position < in_len_data ) {
		switch ( in_state ) {

		case HTML_NORMAL: {
LBL_AGAIN:
			int inl_last_pos = in_position;
			ied_html_tag_states in_tag_return = m_get_tag( ach_data, in_len_data, &in_position, &in_tag_start, &ach_tag, &in_len_tag );
			switch ( in_tag_return ) {
			case HTML_NO_TAG:
				m_send_data( ds_tag.m_get_ptr(), ds_tag.m_get_len() );
				ds_tag.m_reset();
				//m_send_data( ach_data, in_len_data, ads_output ); // send hole data and return
				//in_state = HTML_NORMAL;
				goto LBL_COMPLETE; // -> exit
			case HTML_TAG_PARTIAL:
#if 0
				/* Is HTML comment? */
				if(this->bo_in_comments) {
					m_send_data( ds_tag.m_get_ptr(), ds_tag.m_get_len() );
					ds_tag.m_reset();
					m_send_data( ach_data, in_position, ads_output ); // send hole data and return
					m_move_char_pointer( &ach_data, &in_len_data, &in_position );
					return in_ret;
				}
#endif
				m_send_data( ach_data, in_tag_start, ads_output ); // send data until start of tag "<"
				ds_tag.m_write( ach_tag, in_len_tag );
				return in_ret; // -> exit
			case HTML_TAG_COMMENT_PARTIAL:
				m_send_data( ds_tag.m_get_ptr(), ds_tag.m_get_len() );
				ds_tag.m_reset();
				m_send_data( ach_data, in_position, ads_output ); // send hole data and return
				m_move_char_pointer( &ach_data, &in_len_data, &in_position );
				return in_ret;
			case HTML_TAG_COMMENT_COMPLETE:
				m_send_data( ach_data, in_position, ads_output ); // send hole data and return
				m_move_char_pointer( &ach_data, &in_len_data, &in_position );
				ds_tag.m_reset();
				goto LBL_AGAIN;
			case HTML_TAG_COMPLETE:
				break;
			}
			dsd_const_string hstr_tag(ach_tag, in_len_tag); 
			if(ds_tag.m_get_len() > 0) {
				ds_tag.m_write(ach_tag, in_len_tag);
				//m_move_char_pointer( &ach_data, &in_len_data, &in_position );
				hstr_tag = ds_tag.m_const_str();
			}
			struct dsd_attr_info dsl_info;
			in_process_tag_return = m_process_tag( hstr_tag.m_get_ptr(), hstr_tag.m_get_len(), dsl_info, &dc_changed_tag );
			if(ds_tag.m_get_len() > 0 && dsl_info.inc_tag_key >= 0) {
				int a = 0;
			}
			//m_send_data( ds_tag.m_get_ptr(), ds_tag.m_get_len() );
			switch ( dsl_info.inc_tag_key ) {
			case ds_attributes::ied_htm_tag_script:
				if ( !bo_hobscript_added ) {
					bo_hobscript_added = true;
					m_send_data( ach_data, in_tag_start, ads_output ); // send data until start of script tag
					in_position -= in_tag_start;
					m_move_char_pointer( &ach_data, &in_len_data, &in_tag_start );
					m_insert_HOB_script( !bo_head_found, ads_output );
					bo_head_found = true;
				}
				// TODO: Check for script language (e.g. VBScript)
				in_state = HTML_SCRIPT_DATA;
				switch(dsl_info.iec_script_content_type) {
				case ds_http_header::ien_ct_not_set:
				case ds_http_header::ien_ct_application_javascript:
					if ( bo_change_data ) {
						int inl_flags = ds_interpret_script::IMC_FLAG_TOP_LEVEL | ds_interpret_script::IMC_FLAG_HTML_SCRIPT;
						if(this->boc_is_xhtml)
							inl_flags |= ds_interpret_script::IMC_FLAG_HTML_XHTML;
						ads_session->dsc_ws_gate.dsc_interpret_script.m_init(
							this->m_get_charset(), NULL, inl_flags);
						ads_session->dsc_ws_gate.dsc_interpret_script.m_set_unique_id(dsl_info.inc_unique_id);
						adsc_interpreter = &ads_session->dsc_ws_gate.dsc_interpret_script;
						break;
					}
					adsc_interpreter = &ads_session->dsc_ws_gate.dsc_interpret_pass;
					break;
				default:
					adsc_interpreter = &ads_session->dsc_ws_gate.dsc_interpret_pass;
					break;
				}
				break;
			case ds_attributes::ied_htm_tag_style:
				in_state = HTML_STYLE_DATA;
				switch(dsl_info.iec_script_content_type) {
				case ds_http_header::ien_ct_not_set:
				case ds_http_header::ien_ct_text_css:
					if ( bo_change_data ) {
						adsc_interpreter = &ads_session->dsc_ws_gate.dsc_interpret_css;
						break;
					}
					adsc_interpreter = &ads_session->dsc_ws_gate.dsc_interpret_pass;
					break;
				default:
					adsc_interpreter = &ads_session->dsc_ws_gate.dsc_interpret_pass;
					break;
				}
				break;
			case ds_attributes::ied_htm_tag_body:
				this->inc_body_depth++;
				if ( !bo_hobscript_added ) {
#if 0
					bo_hobscript_added = true;
					m_send_data( ach_data, in_position, ads_output ); // send data until end of <tag>
					m_move_char_pointer( &ach_data, &in_len_data, &in_position );
					//    
					//in_position -= in_tag_start;
					//m_move_char_pointer( &ach_data, &in_len_data, &in_position );
					m_insert_HOB_script( !bo_head_found, ads_output );
					bo_head_found = true;
#endif
				}
				in_state = HTML_BODY_TAG;
				break;
			case ds_attributes::ied_htm_tag_head:
				in_state = HTML_HEAD_TAG;
				bo_head_found = true;
				this->inc_head_depth++;
				break;
			case ds_attributes::ied_htm_tag_headend: {
				bo_head_found = true;
				this->inc_head_depth--;
				if(this->inc_head_depth < 0)
					this->inc_head_depth = 0;
				if(!bo_change_data)
					break;
				if( !this->boc_xua_compatible_found ) {
					m_send_data( ach_data, in_tag_start, ads_output ); // send data until start of head end tag
					in_position -= in_tag_start;
					m_move_char_pointer( &ach_data, &in_len_data, &in_tag_start );
					dsd_const_string dsl_meta("<meta http-equiv=\"X-UA-Compatible\" content=\"IE=11; IE=EDGE\" />");
					m_send_data( dsl_meta.m_get_ptr(), dsl_meta.m_get_len(), ads_output );
					this->boc_xua_compatible_found = true;
				}
				if ( bo_icon_found == false ) {
					m_send_data( ach_data, in_tag_start, ads_output ); // send data until start of head end tag
					in_position -= in_tag_start;
					m_move_char_pointer( &ach_data, &in_len_data, &in_tag_start );
					m_insert_favicon( ads_output );
				}
#if 1
				if ( !bo_hobscript_added ) {
					bo_hobscript_added = true;
					m_send_data( ach_data, in_tag_start, ads_output ); // send data until start of script tag
					in_position -= in_tag_start;
					m_move_char_pointer( &ach_data, &in_len_data, &in_tag_start );
					m_insert_HOB_script( false, ads_output );
				}
#endif
				m_send_data( ach_data, in_tag_start, ads_output );
				in_position -= in_tag_start;
				m_move_char_pointer( &ach_data, &in_len_data, &in_tag_start );
				
				int iml_unique_id = this->imc_uniqueid_counter++;
				ds_hstring dsl_temp(this->ads_session->ads_wsp_helper);
				dsl_temp.m_writef("<script id=\"HOBinserted\" type=\"text/javascript\" HOB_uniqueid='S%d'>HOB.m_head_end('S%d')</script>",
					iml_unique_id, iml_unique_id);
				m_send_data2(dsl_temp.m_const_str(), ads_output);
				break;
																  }
			case ds_attributes::ied_htm_tag_frameset:
				if ( !bo_hobscript_added ) {
					bo_hobscript_added = true;
					m_send_data( ach_data, in_tag_start, ads_output ); // send data until start of script tag
					in_position -= in_tag_start;
					m_move_char_pointer( &ach_data, &in_len_data, &in_tag_start );
					m_insert_HOB_script( !bo_head_found, ads_output );
					bo_head_found = true;
				}
				break;
			case ds_attributes::ied_htm_tag_public:
				if ( !bo_hobscript_added ) {
					bo_hobscript_added = true;
					m_send_data( ach_data, in_tag_start, ads_output ); // send data until start of script tag
					in_position -= in_tag_start;
					m_move_char_pointer( &ach_data, &in_len_data, &in_tag_start );
					m_insert_HOB_script( !bo_head_found, ads_output );
					bo_head_found = true;
				}
				break;
			case ds_attributes::ied_htm_tag_bodyend: {
				this->inc_body_depth--;
				if(this->inc_body_depth < 0)
					this->inc_body_depth = 0;
				if ( ads_session->dsc_ws_gate.bo_do_sso ) {
					m_send_data( ach_data, in_tag_start, ads_output ); // send data until start of script tag
					in_position -= in_tag_start;
					m_move_char_pointer( &ach_data, &in_len_data, &in_tag_start );
					m_insert_HOB_login_init( ads_output );
				}
				m_send_data( ach_data, in_tag_start, ads_output );
				in_position -= in_tag_start;
				m_move_char_pointer( &ach_data, &in_len_data, &in_tag_start );
				
				int iml_unique_id = this->imc_uniqueid_counter++;
				ds_hstring dsl_temp(this->ads_session->ads_wsp_helper);
				dsl_temp.m_writef("<script id=\"HOBinserted\" type=\"text/javascript\" HOB_uniqueid='S%d'>HOB.m_body_end('S%d')</script>",
					iml_unique_id, iml_unique_id);
				m_send_data2(dsl_temp.m_const_str(), ads_output);
				break;
																  }
			case ds_attributes::ied_htm_tag_meta:
				if(dsl_info.boc_is_meta_xua_compatible)
					this->boc_xua_compatible_found = true;
				break;
			case ds_attributes::ied_htm_tag_iframe:
				this->inc_iframe_depth++;
				break;
			case ds_attributes::ied_htm_tag_iframeend:
				this->inc_iframe_depth--;
				if(this->inc_iframe_depth < 0)
					this->inc_iframe_depth = 0;
				break;
			default:
				in_state = HTML_NORMAL;
				break;
			}
			// Is cached mode?
			if(ds_tag.m_get_len() > 0) {
				dsd_const_string hstr_tag2 = hstr_tag;
				if(in_process_tag_return == HTML_CHANGED)
					hstr_tag2 = dc_changed_tag.m_const_str();
				m_send_data( hstr_tag2.m_get_ptr(), hstr_tag2.m_get_len(), ads_output );
				m_move_char_pointer( &ach_data, &in_len_data, &in_position );
				ds_tag.m_reset();
				dc_changed_tag.m_reset();
				break;
			}
			switch ( in_process_tag_return ) {
			case HTML_NOT_CHANGED:
				switch ( dsl_info.inc_tag_key ) {
				case ds_attributes::ied_htm_tag_script:
				case ds_attributes::ied_htm_tag_style:
				case ds_attributes::ied_htm_tag_body:
				case ds_attributes::ied_htm_tag_head:
					m_send_data( ach_data, in_position, ads_output ); // send data until end of <tag>
					m_move_char_pointer( &ach_data, &in_len_data, &in_position );
					break;
				default:
					break;
				}
				break;
			case HTML_CHANGED:
				m_send_data( ach_data, in_tag_start, ads_output ); // send data until start of tag "<"
				m_send_data( dc_changed_tag.m_get_ptr(), dc_changed_tag.m_get_len(), ads_output ); // send changed tag
				m_move_char_pointer( &ach_data, &in_len_data, &in_position );
				// reset some variables:
				dc_changed_tag.m_reset();
				in_tag_start    = 0;
				break;
			}                                
			break;
		}
		case HTML_SCRIPT_DATA:
		case HTML_STYLE_DATA:
			{
				int inl_position_in = in_position;
				ied_html_tag_states in_tag_return = m_get_end_tag( ach_data, in_len_data, &in_position, &in_tag_start, &ach_tag, &in_len_tag, false );
#if 0
				if(&ach_data[inl_position_in] < achl_lookup && &ach_data[in_position] > achl_lookup) {
					int a = 0;
				}
#endif
				bool bol_must_interpret = false;
				bool bol_cdata_new;
				switch ( in_tag_return ) {
				case HTML_NO_TAG:
					if(ds_tag.m_get_len() > 0) {
						in_parser_return = this->m_interpreter_parse_data(
							ds_tag.m_get_ptr(), ds_tag.m_get_len(), false, ads_output);
						ds_tag.m_reset();
						if(in_parser_return < 0)
							return in_parser_return;
						in_ret += in_parser_return;
					}
					// give data to script interpreter, this will send data itself!!!
					//ads_session->dsc_ws_gate.dsc_interpret_script.m_set_write_mode( bo_write_data_chunked );
					in_parser_return = this->m_interpreter_parse_data(
						ach_data, in_len_data, bo_data_complete, ads_output );
					if(in_parser_return < 0)
						return in_parser_return;
					in_ret += in_parser_return;
					//in_tag_start = in_position;
					return in_ret; // -> exit
				case HTML_TAG_PARTIAL:
					/* Is HTML comment? */
					if(this->bo_in_comments) {
						in_parser_return = this->m_interpreter_parse_data(
							ds_tag.m_get_ptr(), ds_tag.m_get_len(), false, ads_output);
						ds_tag.m_reset();
						if(in_parser_return < 0)
							return in_parser_return;
						in_ret += in_parser_return;

						in_parser_return = this->m_interpreter_parse_data(
							ach_data, in_position, bo_data_complete, ads_output);
						if(in_parser_return < 0)
							return in_parser_return;
						in_ret += in_parser_return;
						return in_ret;
					}
					if(inl_position_in != in_tag_start) {
						in_parser_return = this->m_interpreter_parse_data(
							ds_tag.m_get_ptr(), ds_tag.m_get_len(), false, ads_output);
						ds_tag.m_reset();
						if(in_parser_return < 0)
							return in_parser_return;
					}
					ds_tag.m_write( ach_tag, in_len_tag );
					// give data to script interpreter, this will send data itself!!!
					// ads_session->dsc_ws_gate.dsc_interpret_script.m_set_write_mode( bo_write_data_chunked );
					in_parser_return = this->m_interpreter_parse_data(
						ach_data, in_tag_start, bo_data_complete, ads_output );
					if(in_parser_return < 0)
						return in_parser_return;
					in_ret += in_parser_return;
					//m_move_char_pointer( &ach_data, &in_len_data, &in_tag_start );
					return in_ret; // -> exit
				case HTML_TAG_COMPLETE:
					break;
				case HTML_TAG_CDATA_START:
					bol_cdata_new = true;
					bol_must_interpret = true;
					break;
				case HTML_TAG_CDATA_END:
					bol_cdata_new = false;
					bol_must_interpret = true;
					break;
				}

				dsd_const_string hstr_tag(ach_tag, in_len_tag); 
				if(ds_tag.m_get_len() > 0) {
					if(inl_position_in == in_tag_start) {
						ds_tag.m_write(ach_tag, in_len_tag);
						m_move_char_pointer( &ach_data, &in_len_data, &in_position );
						hstr_tag = ds_tag.m_const_str();
					}
					else {
						in_parser_return = this->m_interpreter_parse_data(
							ds_tag.m_get_ptr(), ds_tag.m_get_len(), false, ads_output);
						ds_tag.m_reset();
						if(in_parser_return < 0)
							return in_parser_return;
					}
				}
				m_get_tag_name( hstr_tag.m_get_ptr(), hstr_tag.m_get_len(), NULL, &ach_tag_name, &in_len_name );
				int in_tag_key = m_is_tag_in_list(ach_tag_name, in_len_name);
				bool bol_complete = false;
				switch (in_tag_key) {
				case ds_attributes::ied_htm_tag_scriptend:
					if(in_state != HTML_SCRIPT_DATA)
						goto LBL_NEXT2;
					bol_complete = true;
					break;
				case ds_attributes::ied_htm_tag_styleend:
					if(in_state != HTML_STYLE_DATA)
						goto LBL_NEXT2;
					bol_complete = true;
					break;
				default:
					goto LBL_NEXT2;
				}
				// give data to script interpreter, this will send data itself!!!
				in_parser_return = this->m_interpreter_parse_data(
					ach_data, in_tag_start, true, ads_output );
				if(in_parser_return < 0)
					return in_parser_return;
				in_ret += in_parser_return;
				//if(!bol_complete)
				//	break;
				m_send_data( hstr_tag.m_get_ptr(), hstr_tag.m_get_len(), ads_output ); // send tag
				ds_tag.m_reset();
				m_move_char_pointer( &ach_data, &in_len_data, &in_position );
				m_insert_HOB_write( ads_output );
				in_state = HTML_NORMAL;
				break;
LBL_NEXT2:
				if(bol_must_interpret) {
					// give data to script interpreter, this will send data itself!!!
					in_parser_return = this->m_interpreter_parse_data(
						ach_data, in_tag_start, false, ads_output );
					if(in_parser_return < 0)
						return in_parser_return;
					in_ret += in_parser_return;
					adsc_interpreter->m_cdata_active(bol_cdata_new);
					this->boc_is_cdata = bol_cdata_new;

					// give data to script interpreter, this will send data itself!!!
					in_parser_return = this->m_interpreter_parse_data(
						hstr_tag.m_get_ptr(), hstr_tag.m_get_len(), false, ads_output );
					if(in_parser_return < 0)
						return in_parser_return;
					in_ret += in_parser_return;
					m_move_char_pointer( &ach_data, &in_len_data, &in_position );
					ds_tag.m_reset();
					break;
				}
				if(ds_tag.m_get_len() > 0) {
					in_parser_return = this->m_interpreter_parse_data(
						ds_tag.m_get_ptr(), ds_tag.m_get_len(), false, ads_output );
					if(in_parser_return < 0)
						return in_parser_return;
					in_ret += in_parser_return;
					//m_move_char_pointer( &ach_data, &in_len_data, &in_position );
					ds_tag.m_reset();
				}
				break;
			}
		case HTML_HEAD_TAG:
			//m_insert_HOB_script( false, ads_output );
			if ( boc_is_ica_srv == true ) {
				m_insert_ica_decl( ads_output );
				if ( ads_session->dsc_auth.m_is_ica_active() == false ) {
					boc_insert_ica_call = true;
				}
				ads_session->dsc_auth.m_increase_ica_count();
			}
			in_state = HTML_NORMAL;
			break;

		case HTML_BODY_TAG:
			if( !this->boc_xua_compatible_found ) {
				dsd_const_string dsl_meta("<meta http-equiv=\"X-UA-Compatible\" content=\"IE=11; IE=EDGE\" />");
				m_send_data( dsl_meta.m_get_ptr(), dsl_meta.m_get_len(), ads_output );
				this->boc_xua_compatible_found = true;
			}
			if ( !bo_hobscript_added ) {
				bo_hobscript_added = true;
				m_insert_HOB_script( !bo_head_found, ads_output );
				bo_head_found = true;
			}
			m_insert_HOB_nav_init( ads_output );
			if ( boc_insert_ica_call == true ) {
				boc_insert_ica_call = false;
				m_insert_ica_call( ads_output );
			}
			in_state = HTML_NORMAL;
			break;

		default:
			ads_session->ads_wsp_helper->m_log( ied_sdh_log_error,
				"HWSGE104E: invalid state in ds_interpret_html::m_parse_data" );
			in_state = HTML_NORMAL;
			return in_ret; // -> exit

		} // end of switch
	} // end of while
LBL_COMPLETE:
	//if ( in_state == HTML_NORMAL ) {
	switch(in_state) {
	case HTML_NORMAL:
		if(in_len_data > 0) {
			m_send_data( ach_data, in_len_data, ads_output );
		}
		if(!bo_data_complete)
			break;
		if(this->inc_head_depth > 0) {
			int iml_unique_id = this->imc_uniqueid_counter++;
			ds_hstring dsl_temp(this->ads_session->ads_wsp_helper);
			dsl_temp.m_writef("<script id=\"HOBinserted\" type=\"text/javascript\" HOB_uniqueid='S%d'>HOB.m_head_end('S%d')</script>",
				iml_unique_id, iml_unique_id);
			m_send_data2(dsl_temp.m_const_str(), ads_output);
			this->inc_head_depth = 0;
		}
		if(this->inc_body_depth > 0) {
			int iml_unique_id = this->imc_uniqueid_counter++;
			ds_hstring dsl_temp(this->ads_session->ads_wsp_helper);
			dsl_temp.m_writef("<script id=\"HOBinserted\" type=\"text/javascript\" HOB_uniqueid='S%d'>HOB.m_body_end('S%d')</script>",
				iml_unique_id, iml_unique_id);
			m_send_data2(dsl_temp.m_const_str(), ads_output);
			this->inc_body_depth = 0;
		}
		break;
	case HTML_SCRIPT_DATA:
	case HTML_STYLE_DATA:
		in_parser_return = this->m_interpreter_parse_data(
			ach_data, in_len_data, bo_data_complete, ads_output);
		if(in_parser_return < 0)
			return in_parser_return;
		in_ret += in_parser_return;
		break;
	default:
		if(in_len_data > 0) {
			m_send_data( ach_data, in_len_data, ads_output );
		}
		break;
	}
	return in_ret;
} // end of m_parse_data


/**
*
* function ds_interpret_html::m_get_tag
*
* @param[in]       char*  ach_data           data, in which will be search in
* @param[in]       int    in_len_data        length of ach_data
* @param[in,out]   int*   ain_position       actual position in data
* @param[out]      int*   ain_tag_start      start pos of tag in data
* @param[out]      char** aach_tag           pointer to tag
* @param[out]      int*   ain_len_tag        length of tag
*
* @return          int                       key:
*                                              HTML_NO_TAG       = no tag is found in data
*                                              HTML_TAG_PARTIAL  = tag is found partial
*                                              HTML_TAG_COMPLETE = tag is found complete
*
*/
ds_interpret_html::ied_html_tag_states ds_interpret_html::m_get_tag(
	const char* ach_data, int in_len_data, int *ain_position, int* ain_tag_start,
	const char** aach_tag,  int *ain_len_tag )
{
	ied_html_tag_states in_return;
	switch(in_get_tag_state) {
	case HTML_GET_TAG:
	case HTML_END_CDATA_0:
		in_return = HTML_NO_TAG;
		break;
	case HTML_CHECK_COMMENT_TAG_3:
	case HTML_CHECK_COMMENT_TAG_4:
		in_return = HTML_TAG_COMMENT_PARTIAL;
		break;
	default:
		in_return = HTML_TAG_PARTIAL;
		break;
	}

	if (    ach_data == NULL || ain_tag_start == NULL || in_len_data <= 0
		|| *ain_position >= in_len_data ) {
			// only a small security check
			return in_return;
	}

	if ( in_get_tag_state == HTML_IN_DOUBLE_QUOTES || in_get_tag_state == HTML_IN_SINGLE_QUOTES ) {
		if ( bo_back_slash_ending == true ) {
			(*ain_position)++;
			bo_back_slash_ending = false;
		}
	} else {
		bo_back_slash_ending = false;
	}

	for ( ; *ain_position < in_len_data; (*ain_position)++ ) {
		switch ( in_get_tag_state ) {
		case HTML_GET_TAG:
			switch ( ach_data[*ain_position] ) {
			case '<':
				*ain_tag_start = *ain_position;
				in_return = HTML_TAG_PARTIAL;
				in_get_tag_state = HTML_CHECK_COMMENT_TAG_0;//HTML_GET_TAG_END;
				break;
			default:
				break;
			}
			m_save_sign( ach_data[*ain_position] );
			continue;
		case HTML_GET_TAG_END:
			switch ( ach_data[*ain_position] ) {
			case '<': // search even for a "<" in a tag (to be shure, not having a "1<2" like in jscript)
				*ain_tag_start = *ain_position;
				m_save_sign( ach_data[*ain_position] );
				continue;
			case '"':
#if 0
				if ( bo_in_comments ) {
					m_save_sign( ach_data[*ain_position] );
					continue;
				}
#endif
				// MJ 12.05.09, Ticket[17623]:
				if ( ch_last_sign == '=' ) {
					in_old_tag_state = HTML_GET_TAG_END;
					in_get_tag_state = HTML_IN_DOUBLE_QUOTES;
				} else {
					ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
						"HWSGW110W: ignoring double quote in data - data: '%.*s'",
						*ain_position + 1 - *ain_tag_start, &ach_data[*ain_tag_start]);
				}
				m_save_sign( ach_data[*ain_position] );
				continue;
			case '\'':
#if 0
				if ( bo_in_comments ) {
					m_save_sign( ach_data[*ain_position] );
					continue;
				}
#endif
				// MJ 12.05.09, Ticket[17623]:
				if ( ch_last_sign == '=' ) {
					in_old_tag_state = HTML_GET_TAG_END;
					in_get_tag_state = HTML_IN_SINGLE_QUOTES;
				} else {
					ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
						"HWSGW111W: ignoring single quote in data - data: \"%.*s\"",
						*ain_position + 1 - *ain_tag_start, &ach_data[*ain_tag_start]);
				}
				m_save_sign( ach_data[*ain_position] );
				continue;
			case '>':
				(*ain_position)++;
				in_get_tag_state = HTML_GET_TAG;
				in_return = HTML_TAG_COMPLETE;
				goto LBL_END;
			default:
				m_save_sign( ach_data[*ain_position] );
				continue;
			}
			break;
		case HTML_GET_ABS_TAG_END:
			switch ( ach_data[*ain_position] ) {
			case '"':
				if ( bo_in_comments == false && ch_last_sign == '=' ) {
					in_old_tag_state = HTML_GET_ABS_TAG_END;
					in_get_tag_state = HTML_IN_DOUBLE_QUOTES;
				}
				m_save_sign( ach_data[*ain_position] );
				continue;
			case '\'':
				if ( bo_in_comments == false && ch_last_sign == '=' ) {
					in_old_tag_state = HTML_GET_ABS_TAG_END;
					in_get_tag_state = HTML_IN_SINGLE_QUOTES;
				}
				m_save_sign( ach_data[*ain_position] );
				continue;
			case '>':
				(*ain_position)++;
				in_get_tag_state = HTML_GET_TAG;
				in_return = HTML_TAG_COMPLETE;
				goto LBL_END;
			default:
				m_save_sign( ach_data[*ain_position] );
				continue;
			}
			break;
		case HTML_IN_DOUBLE_QUOTES:
			switch ( ach_data[*ain_position] ) {
			case '"':
				in_get_tag_state = in_old_tag_state;
				break;
#ifdef BREAK_QUOTE_WITH_TAG_END
				// ein Notaustieg:
			case '>':
				str_msg = "HWSGW107W: double quote was broken by '>' - data: '";
				str_msg.append( &ach_data[*ain_tag_start], *ain_position + 1 - *ain_tag_start );
				str_msg += "' - try to handle error";
				ads_session->dsc_transaction.m_print_to_console(str_msg, helper::ien_level_warning);
				in_get_tag_state = HTML_GET_TAG_END;
				break;
#endif //BREAK_QUOTE_WITH_TAG_END
			case '\\':
				(*ain_position)++;  // don't read next sign
				if ( *ain_position > in_len_data - 1 ) {
					bo_back_slash_ending = true;
					(*ain_position)--;
				}
				break;
			default:
				break;
			}
			m_save_sign( ach_data[*ain_position] );
			continue;
		case HTML_IN_SINGLE_QUOTES:
			switch ( ach_data[*ain_position] ) {
			case '\'':
				in_get_tag_state = in_old_tag_state;
				break;
#ifdef BREAK_QUOTE_WITH_TAG_END
				// ein Notaustieg:
			case '>':
				str_msg = "HWSGW108W: single quote was broken by '>' - data: '";
				str_msg.append( &ach_data[*ain_tag_start], *ain_position + 1 - *ain_tag_start );
				str_msg += "' - try to handle error";
				ads_session->dsc_transaction.m_print_to_console(str_msg, helper::ien_level_warning);
				in_get_tag_state = HTML_GET_TAG_END;
				break;
#endif //BREAK_QUOTE_WITH_TAG_END
			case '\\':
				(*ain_position)++;  // don't read next sign
				if ( *ain_position > in_len_data - 1 ) {
					bo_back_slash_ending = true;
					(*ain_position)--;
				}
				break;
			default:
				break;
			}
			m_save_sign( ach_data[*ain_position] );
			continue;
#if 0
		case HTML_AFTER_QUOTES:
			switch ( ach_data[*ain_position] ) {
			case '\'':
			case '"':
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
					"HWSGW109W: quote was followed by quote - data: %.*s - try to handle error",
					in_len_data - *ain_position, &ach_data[*ain_position]);
				in_get_tag_state = HTML_GET_TAG_END;
				m_save_sign( ach_data[*ain_position] );
				continue;
			case '>':
				(*ain_position)++;
				in_get_tag_state = HTML_GET_TAG;
				in_return = HTML_TAG_COMPLETE;
				break;
			default:
				in_get_tag_state = HTML_GET_TAG_END;
				m_save_sign( ach_data[*ain_position] );
				continue;
			}
			break;
#endif
		case HTML_CHECK_COMMENT_TAG_0:
			switch( ach_data[*ain_position] ) {
			case '!':
				in_get_tag_state = HTML_CHECK_COMMENT_TAG_1;
				break;
			default:
				(*ain_position)--;
				in_get_tag_state = HTML_GET_ABS_TAG_END;
				break;
			}
			m_save_sign( ach_data[*ain_position] );
			continue;
		case HTML_CHECK_COMMENT_TAG_1:
			switch( ach_data[*ain_position] ) {
			case '-':
				in_get_tag_state = HTML_CHECK_COMMENT_TAG_2;
				continue;
			case '[':
				if(this->boc_is_xhtml) {
					in_get_tag_state = HTML_IN_CDATA_0;
					continue;
				}
				break;
			default:
				break;
			}
			(*ain_position)--;
			in_get_tag_state = HTML_GET_ABS_TAG_END;
			//m_save_sign( ach_data[*ain_position] );
			continue;
		case HTML_CHECK_COMMENT_TAG_2:
			switch( ach_data[*ain_position] ) {
			case '-':
				bo_in_comments = true;
				in_return        = HTML_TAG_COMMENT_PARTIAL;
				in_get_tag_state = HTML_CHECK_COMMENT_TAG_3;
				break;
			default:
				(*ain_position)--;
				in_get_tag_state = HTML_GET_ABS_TAG_END;
				break;
			}
			//m_save_sign( ach_data[*ain_position] );
			continue;
		case HTML_CHECK_COMMENT_TAG_3:
			switch( ach_data[*ain_position] ) {
			case '-':
				in_get_tag_state = HTML_CHECK_COMMENT_TAG_4;
				break;
			default:
				break;
			}
			//m_save_sign( ach_data[*ain_position] );
			continue;
		case HTML_CHECK_COMMENT_TAG_4:
			switch( ach_data[*ain_position] ) {
			case '-':
				break;
			case '>':
				bo_in_comments = false;
				in_return         = HTML_TAG_COMMENT_COMPLETE;
				in_get_tag_state  = HTML_GET_TAG;
				(*ain_position)++;
				goto LBL_END;
			default:
				in_get_tag_state = HTML_CHECK_COMMENT_TAG_3;
				break;
			}
			continue;
			// CDATA[
		case HTML_IN_CDATA_0:
			switch ( ach_data[*ain_position] ) {
			case 'C':
				in_get_tag_state = HTML_IN_CDATA_1;
				break;
			default:
				(*ain_position)--;
				in_get_tag_state = HTML_GET_ABS_TAG_END;
				break;
			}
			continue;
		case HTML_IN_CDATA_1:
			switch ( ach_data[*ain_position] ) {
			case 'D':
				in_get_tag_state = HTML_IN_CDATA_2;
				break;
			default:
				(*ain_position)--;
				in_get_tag_state = HTML_GET_ABS_TAG_END;
				break;
			}
			continue;
		case HTML_IN_CDATA_2:
			switch ( ach_data[*ain_position] ) {
			case 'A':
				in_get_tag_state = HTML_IN_CDATA_3;
				break;
			default:
				(*ain_position)--;
				in_get_tag_state = HTML_GET_ABS_TAG_END;
				break;
			}
			continue;
		case HTML_IN_CDATA_3:
			switch ( ach_data[*ain_position] ) {
			case 'T':
				in_get_tag_state = HTML_IN_CDATA_4;
				break;
			default:
				(*ain_position)--;
				in_get_tag_state = HTML_GET_ABS_TAG_END;
				break;
			}
			continue;
		case HTML_IN_CDATA_4:
			switch ( ach_data[*ain_position] ) {
			case 'A':
				in_get_tag_state = HTML_IN_CDATA_5;
				break;
			default:
				(*ain_position)--;
				in_get_tag_state = HTML_GET_ABS_TAG_END;
				break;
			}
			continue;
		case HTML_IN_CDATA_5:
			switch ( ach_data[*ain_position] ) {
			case '[':
				in_return         = HTML_TAG_COMPLETE;
				in_get_tag_state  = HTML_END_CDATA_0;
				(*ain_position)++;
				goto LBL_END;
			default:
				(*ain_position)--;
				in_get_tag_state = HTML_GET_ABS_TAG_END;
				continue;
			}
			break;
		case HTML_END_CDATA_0:
			switch ( ach_data[*ain_position] ) {
			case ']':
				*ain_tag_start = *ain_position;
				in_return        = HTML_TAG_PARTIAL;
				in_get_tag_state = HTML_END_CDATA_1;
				break;
			default:
				break;
			}
			continue;
		case HTML_END_CDATA_1:
			switch ( ach_data[*ain_position] ) {
			case ']':
				in_get_tag_state = HTML_END_CDATA_2;
				break;
			default:
				in_return        = HTML_NO_TAG;
				in_get_tag_state = HTML_END_CDATA_0;
				break;
			}
			continue;
		case HTML_END_CDATA_2:
			switch ( ach_data[*ain_position] ) {
			case '>':
				in_return         = HTML_TAG_COMPLETE;
				in_get_tag_state  = HTML_GET_TAG;
				(*ain_position)++;
				goto LBL_END;
			default:
				in_return        = HTML_NO_TAG;
				in_get_tag_state = HTML_END_CDATA_0;
				continue;
			}
			break;
		}
		break;
	}

LBL_END:
	*aach_tag = &ach_data[*ain_tag_start];
	if ( in_return == HTML_NO_TAG ) {
		*ain_len_tag = 0;
	} else {
		*ain_len_tag = *ain_position - *ain_tag_start;
	}

	if ( in_return == HTML_TAG_COMPLETE ) {
		ch_last_sign   = 0; 
	}

	return in_return;
} // end of ds_interpret_html::m_get_tag


/**
* function ds_interpret_html::m_save_sign
*
* @param[in]   char    ch_sign
*/
void ds_interpret_html::m_save_sign( char ch_sign )
{
	switch ( ch_sign ) {
	case '\f':
	case '\n':
	case '\r':
	case '\t':
	case '\v':
	case ' ':
		break;
	default:
		ch_last_sign = ch_sign;
		break;
	}
} // end of ds_interpret_html::m_save_sign


/**
*
* function ds_interpret_html::m_get_end_tag
*
* @param[in]       char*  ach_data           data, in which will be search in
* @param[in]       int    in_len_data        length of ach_data
* @param[in,out]   int*   ain_position       actual position in data
* @param[out]      int*   ain_tag_start      start pos of tag in data
* @param[out]      char** aach_tag           pointer to tag
* @param[out]      int*   ain_len_tag        length of tag
*
* @return          int                       key:
*                                              HTML_NO_TAG       = no tag is found in data
*                                              HTML_TAG_PARTIAL  = tag is found partial
*                                              HTML_TAG_COMPLETE = tag is found complete
*
*/
ds_interpret_html::ied_html_tag_states ds_interpret_html::m_get_end_tag(
	const char* ach_data, int in_len_data, int *ain_position, int* ain_tag_start,
	const char** aach_tag,  int *ain_len_tag, bool bop_parse_html_comments )
{
	ds_interpret_html::ied_html_tag_states in_return;
	switch(in_get_tag_state) {
	case HTML_GET_TAG:
	case HTML_END_CDATA_0:
		in_return = HTML_NO_TAG;
		break;
	default:
		in_return = HTML_TAG_PARTIAL;
		break;
	}

	if (    ach_data == NULL || ain_tag_start == NULL || in_len_data <= 0
		|| *ain_position >= in_len_data ) {
			// only a small security check
			return in_return;
	}

	for ( ; *ain_position < in_len_data; (*ain_position)++ ) {
		switch ( in_get_tag_state ) {
		case HTML_GET_TAG:
			switch ( ach_data[*ain_position] ) {
			case '<':
				*ain_tag_start   = *ain_position;
				in_return        = HTML_TAG_PARTIAL;
				in_get_tag_state = HTML_CHECK_END_TAG;
				break;
			default:
				break;
			}
			continue;

		case HTML_CHECK_END_TAG:
			switch( ach_data[*ain_position] ) {
			case '/':
				in_get_tag_state = HTML_GET_TAG_END;
				break;
			case '!':
#if 0
				ach_start_comment = &ach_data[*ain_position];
#endif
				in_get_tag_state  = HTML_CHECK_COMMENT;
				break;
			default:
				in_return        = HTML_NO_TAG;
				in_get_tag_state = HTML_GET_TAG;
				break;
			}
			continue;

		case HTML_GET_TAG_END:
			switch ( ach_data[*ain_position] ) {
			case '<': // search even for a "<" in a tag (to be sure, not having a "1<2" like in jscript)
				*ain_tag_start = *ain_position;
				continue;
			case '"':
				if ( bop_parse_html_comments && !bo_in_comments ) {
					in_get_tag_state = HTML_IN_DOUBLE_QUOTES;
				}
				continue;
			case '\'':
				if ( bop_parse_html_comments && !bo_in_comments ) {
					in_get_tag_state = HTML_IN_SINGLE_QUOTES;
				}
				continue;
			case '>':
				in_get_tag_state = HTML_GET_TAG;
				in_return = HTML_TAG_COMPLETE;
				(*ain_position)++;
				goto LBL_END;
			default:
				continue;
			}
			break;
		case HTML_IN_DOUBLE_QUOTES:
			switch ( ach_data[*ain_position] ) {
			case '"':
				in_get_tag_state = HTML_GET_TAG_END;
				break;
			case '\\':
				(*ain_position)++;  // don't read next sign
				break;
			default:
				break;
			}
			continue;
		case HTML_IN_SINGLE_QUOTES:
			switch ( ach_data[*ain_position] ) {
			case '\'':
				in_get_tag_state = HTML_GET_TAG_END;
				break;
			case '\\':
				(*ain_position)++;  // don't read next sign
				break;
			default:
				break;
			}
			continue;
#if 0
		case HTML_CHECK_COMMENT_TAG_0:
			switch( ach_data[*ain_position] ) {
			case '!':
				in_get_tag_state = HTML_CHECK_COMMENT_TAG_1;
				break;
			default:
				(*ain_position)--;
				in_get_tag_state = HTML_GET_TAG_END;
				break;
			}
			m_save_sign( ach_data[*ain_position] );
			continue;
		case HTML_CHECK_COMMENT_TAG_1:
			switch( ach_data[*ain_position] ) {
			case '-':
				in_get_tag_state = HTML_CHECK_COMMENT_TAG_2;
				break;
			default:
				in_return        = HTML_NO_TAG;
				in_get_tag_state = HTML_GET_TAG;
				break;
			}
			//m_save_sign( ach_data[*ain_position] );
			continue;
#endif
		case HTML_CHECK_COMMENT:
			switch ( ach_data[*ain_position] ) {
			case '[':
				if(this->boc_is_xhtml) {
					in_get_tag_state = HTML_IN_CDATA_0;
					continue;
				}
				break;
			case '-':
				if(this->boc_is_xhtml) {
					in_get_tag_state = HTML_CHECK_COMMENT_TAG_2;
					continue;
				}
				break;
			default:
				break;
			}
#if 0
			ach_start_comment = NULL;
#endif
			in_return         = HTML_NO_TAG;
			in_get_tag_state  = HTML_GET_TAG;
			continue;
		case HTML_CHECK_COMMENT_TAG_2:
			switch( ach_data[*ain_position] ) {
			case '-':
				bo_in_comments = true;
				in_get_tag_state = HTML_CHECK_COMMENT_TAG_3;
				break;
			default:
				in_return        = HTML_NO_TAG;
				in_get_tag_state = HTML_GET_TAG;
				break;
			}
			//m_save_sign( ach_data[*ain_position] );
			continue;
		case HTML_CHECK_COMMENT_TAG_3:
			switch( ach_data[*ain_position] ) {
			case '-':
				in_get_tag_state = HTML_CHECK_COMMENT_TAG_4;
				break;
			default:
				break;
			}
			//m_save_sign( ach_data[*ain_position] );
			continue;
		case HTML_CHECK_COMMENT_TAG_4:
			switch ( ach_data[*ain_position] ) {
			case '-':
				continue;
			case '>':
#if 0
				ach_start_comment = NULL;
#endif
				bo_in_comments = false;
				in_return         = HTML_TAG_COMPLETE;
				in_get_tag_state  = HTML_GET_TAG;
				(*ain_position)++;
				goto LBL_END;
			default:
				in_get_tag_state = HTML_CHECK_COMMENT_TAG_3;
				continue;
			}
			break;
#if 0
		case HTML_IN_COMMENTS:
			switch ( ach_data[*ain_position] ) {
			case '-':
				in_get_tag_state = HTML_END_COMMENTS;
				break;
			default:
				break;
			}
			continue;
		case HTML_END_COMMENTS:
			switch ( ach_data[*ain_position] ) {
			case '-':
				continue;
			case '>':
				ach_start_comment = NULL;
				//in_return         = HTML_NO_TAG;
				in_return         = HTML_TAG_COMPLETE;
				in_get_tag_state  = HTML_GET_TAG;
				(*ain_position)++;
				break;
			default:
				in_get_tag_state = HTML_IN_COMMENTS;
				continue;
			}
			break;
#endif
			// CDATA[
		case HTML_IN_CDATA_0:
			switch ( ach_data[*ain_position] ) {
			case 'C':
				in_get_tag_state = HTML_IN_CDATA_1;
				break;
			default:
				in_return        = HTML_NO_TAG;
				in_get_tag_state = HTML_GET_TAG;
				break;
			}
			continue;
		case HTML_IN_CDATA_1:
			switch ( ach_data[*ain_position] ) {
			case 'D':
				in_get_tag_state = HTML_IN_CDATA_2;
				break;
			default:
				in_return        = HTML_NO_TAG;
				in_get_tag_state = HTML_GET_TAG;
				break;
			}
			continue;
		case HTML_IN_CDATA_2:
			switch ( ach_data[*ain_position] ) {
			case 'A':
				in_get_tag_state = HTML_IN_CDATA_3;
				break;
			default:
				in_return        = HTML_NO_TAG;
				in_get_tag_state = HTML_GET_TAG;
				break;
			}
			continue;
		case HTML_IN_CDATA_3:
			switch ( ach_data[*ain_position] ) {
			case 'T':
				in_get_tag_state = HTML_IN_CDATA_4;
				break;
			default:
				in_return        = HTML_NO_TAG;
				in_get_tag_state = HTML_GET_TAG;
				break;
			}
			continue;
		case HTML_IN_CDATA_4:
			switch ( ach_data[*ain_position] ) {
			case 'A':
				in_get_tag_state = HTML_IN_CDATA_5;
				break;
			default:
				in_return        = HTML_NO_TAG;
				in_get_tag_state = HTML_GET_TAG;
				break;
			}
			continue;
		case HTML_IN_CDATA_5:
			switch ( ach_data[*ain_position] ) {
			case '[':
				in_return         = HTML_TAG_CDATA_START;
				in_get_tag_state  = HTML_END_CDATA_0;
				(*ain_position)++;
				goto LBL_END;
			default:
				in_return        = HTML_NO_TAG;
				in_get_tag_state = HTML_GET_TAG;
				continue;
			}
			break;
		case HTML_END_CDATA_0:
			switch ( ach_data[*ain_position] ) {
			case ']':
				*ain_tag_start   = *ain_position;
				in_return        = HTML_TAG_PARTIAL;
				in_get_tag_state = HTML_END_CDATA_1;
				break;
			default:
				break;
			}
			continue;
		case HTML_END_CDATA_1:
			switch ( ach_data[*ain_position] ) {
			case ']':
				in_get_tag_state = HTML_END_CDATA_2;
				break;
			default:
				in_return        = HTML_NO_TAG;
				in_get_tag_state = HTML_END_CDATA_0;
				break;
			}
			continue;
		case HTML_END_CDATA_2:
			switch ( ach_data[*ain_position] ) {
			case '>':
				in_return         = HTML_TAG_CDATA_END;
				in_get_tag_state  = HTML_GET_TAG;
				(*ain_position)++;
				goto LBL_END;
			default:
				in_return        = HTML_NO_TAG;
				in_get_tag_state = HTML_END_CDATA_0;
				continue;
			}
			break;
#if 0
		case HTML_END_CDATA:
			switch ( ach_data[*ain_position] ) {
			case ']':
				continue;
			case '>':
				//in_return        = HTML_NO_TAG;
				in_return        = HTML_TAG_COMPLETE;
				in_get_tag_state = HTML_GET_TAG;
				break;
			default:
				in_get_tag_state = HTML_IN_CDATA;
				continue;
			}
			break;
#endif
		}
		break;
	}

LBL_END:
	*aach_tag = &ach_data[*ain_tag_start];
	if ( in_return == HTML_NO_TAG ) {
		*ain_len_tag = 0;
	} else {
		*ain_len_tag = *ain_position - *ain_tag_start;
	}

	return in_return;
} // end of ds_interpret_html::m_get_end_tag

static dsd_const_string m_unquote(const dsd_const_string& rdsp_value, char& rchp_quote) {
	if(rdsp_value.m_starts_with("\"") && rdsp_value.m_ends_with("\"")) {
		rchp_quote = '\"';
		return rdsp_value.m_substring(1, rdsp_value.m_get_len()-1);
	}
	else if(rdsp_value.m_starts_with("'") && rdsp_value.m_ends_with("'")) {
		rchp_quote = '\'';
		return rdsp_value.m_substring(1, rdsp_value.m_get_len()-1);
	}
	rchp_quote = 0;
	return rdsp_value;
}

dsd_const_string ds_interpret_html::m_unescape_attr_value(const dsd_const_string& rdsp_value, ds_hstring& rdsp_replaced) {
	int iml_last_copy = 0;
	int iml_pos = 0;

	int iml_replaced_pos = rdsp_replaced.m_get_len();
	//rdsp_replaced.m_reset();
	do {
		int iml_i = rdsp_value.m_index_of(iml_pos, "&");
		if(iml_i < 0)
			break;
		int iml_i2 = rdsp_value.m_find_first_of(";&", iml_i+1);
		if(iml_i2 < 0)
			break;
		if(rdsp_value[iml_i2] == '&') {
			iml_pos = iml_i2;
			continue;
		}
		// Set pos to next character
		iml_pos = iml_i2+1;
#if 0
		dsd_const_string strl_esc = rdsp_value.m_substring(iml_i+1, iml_i2);
		if(strl_esc.m_starts_with("#")) {
			dsd_const_string dsl_num = strl_esc.m_substring(1);
			int iml_value;
			if(!dsl_num.m_parse_int(&iml_value)) {
				// TODO: Log error message
				continue;
			}

			rdsp_replaced += rdsp_value.m_substring(iml_last_copy, iml_i);
			iml_last_copy = iml_i;

			dsd_unicode_string dsl_ucs;
			unsigned int uml_value = iml_value;
			dsl_ucs.ac_str = &uml_value;
			dsl_ucs.imc_len_str = 1;
			dsl_ucs.iec_chs_str = ied_chs_utf_32;
			if(rdsp_replaced.m_write(&dsl_ucs, this->iec_meta_charset) < 0) {
				// TODO: Log error message
				continue;
			}
			iml_last_copy = iml_pos;
			continue;
		}
#endif
		rdsp_replaced += rdsp_value.m_substring(iml_last_copy, iml_i);
		iml_last_copy = iml_i;

		dsd_const_string strl_esc2 = rdsp_value.m_substring(iml_i, iml_i2+1);
#if 1
#if 1
		unsigned int uml_value;
		int iml_nused = m_get_vc_ch_ex( &uml_value, strl_esc2.m_get_start(),
			strl_esc2.m_get_end(), ied_chs_html_1 );
		if(iml_nused < 0)
			continue;
		if(iml_nused != strl_esc2.m_get_len())
			continue;
		dsd_unicode_string dsl_ucs;
		dsl_ucs.ac_str = &uml_value;
		dsl_ucs.imc_len_str = 1;
		dsl_ucs.iec_chs_str = ied_chs_utf_32;
		if(rdsp_replaced.m_write(&dsl_ucs, this->m_get_charset()) < 0) {
			// TODO: Log error message
			continue;
		}
		iml_last_copy = iml_pos;
#else
		char chrl_temp[32];
		int inl_temp_needed = m_cpy_vx_vx( chrl_temp,
			sizeof(chrl_temp),
			this->m_get_charset(),
			strl_esc2.m_get_ptr(), strl_esc2.m_get_len(),
			ied_chs_html_1 );
		if(inl_temp_needed < 0) {
			continue;
		}
		rdsp_replaced.m_write(chrl_temp, inl_temp_needed);
#endif
#else
		dsd_unicode_string dsl_ucs;
		dsl_ucs.ac_str = (void*)strl_esc2.m_get_ptr();
		dsl_ucs.imc_len_str = strl_esc2.m_get_len();
		dsl_ucs.iec_chs_str = ied_chs_html_1;
		if(rdsp_replaced.m_write(&dsl_ucs, this->m_get_charset()) < 0) {
			continue;
		}
#endif
#if 0
		dsd_const_string strl_value;
		if(strl_esc.m_equals("quot")) {
			strl_value = "\"";
		}
		else if(strl_esc.m_equals("amp")) {
			strl_value = "&";
		}
		else if(strl_esc.m_equals("apos")) {
			strl_value = "'";
		}
		else if(strl_esc.m_equals("lt")) {
			strl_value = "<";
		}
		else if(strl_esc.m_equals("gt")) {
			strl_value = ">";
		}
		/*else if(strl_esc.m_equals("nbsp")) {
		strl_value = "\u00a0";
		}*/
		else {
			// TODO: Log error message
			continue;
		}
		rdsp_replaced += rdsp_value.m_substring(iml_last_copy, iml_i);
		rdsp_replaced += strl_value;
#endif
		iml_last_copy = iml_pos;
	} while(true);
	if(rdsp_replaced.m_get_len() <= iml_replaced_pos)
		return rdsp_value;
	rdsp_replaced += rdsp_value.m_substring(iml_last_copy);
	return rdsp_replaced.m_substring(iml_replaced_pos);
}

dsd_const_string ds_interpret_html::m_escape_attr_value(const dsd_const_string& rdsp_value, ds_hstring& rdsp_replaced) {
	rdsp_replaced.m_reset();
	rdsp_replaced.m_write_html_text(rdsp_value);
	return rdsp_replaced.m_const_str();
}

int ds_interpret_html::m_interpreter_parse_data(
	const char* ach_data, int in_len_data, bool bo_data_complete, ds_hstring* ads_output)
{
	if(in_len_data <= 0 && !bo_data_complete)
		return 0;
#if 0
	ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "[%d] HTML.m_interpreter_parse_data: in_len_data=%d\n",
		ads_session->ads_wsp_helper->m_get_session_id(), in_len_data);
	ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, dsd_const_string(ach_data, in_len_data));
	if(dsd_const_string(ach_data, in_len_data).m_ends_with("/g;_.Ux=/")) {
		int a = 0;
	}
	if(dsd_const_string(ach_data, in_len_data).m_starts_with(")vy);vy.prototype.ab=function(){return this.j};")) {
		int a = 0;
	}
#endif
	//this->adsc_interpreter->m_reset_return();
#if 0
	dsd_const_string dsl_tmp(ach_data, in_len_data);
	int inl_p = dsl_tmp.m_index_of("var decodedString");
	if(inl_p >= 0) {
		int a = 0;
	}
#endif
	if(!this->boc_is_xhtml || this->adsc_interpreter == &this->ads_session->dsc_ws_gate.dsc_interpret_pass) {
		int in_parser_return = this->adsc_interpreter->m_parse_data(
			ach_data, in_len_data, bo_data_complete, ads_output );
		return in_parser_return;
	}
	dsd_const_string dsl_value(ach_data, in_len_data);

	if(this->boc_is_cdata) {
		return this->adsc_interpreter->m_parse_data(
			ach_data, in_len_data, bo_data_complete, ads_output );
	}

	int iml_last_copy = 0;
	int iml_pos = 0;

	//rdsp_replaced.m_reset();
	unsigned int uml_value;
	do {
LBL_AGAIN:
		switch(this->iec_unescape_state) {
		case iec_unescape_html_default: {
			int iml_i = dsl_value.m_index_of(iml_pos, "&");
			if(iml_i < 0)
				goto LBL_END;
			// Set pos to next character
			iml_pos = iml_i;
			this->iec_unescape_state = iec_unescape_html_findend;
			goto LBL_AGAIN;
												  }
		case iec_unescape_html_findend: {
			int iml_end = dsl_value.m_find_first_of(";&", iml_pos+1);
			if(iml_end < 0) {
				dsd_const_string dsl_rest = dsl_value.m_substring(iml_pos);
				if(dsl_rest.m_get_len() > 8)
					goto LBL_END;
				this->dsc_unescape_tag.m_write(dsl_rest);
				this->iec_unescape_state = iec_unescape_html_collect;
				iml_pos = in_len_data;
				iml_last_copy = iml_pos;
				goto LBL_END;
			}
			if(dsl_value[iml_end] == '&') {
				iml_pos = iml_end;
				goto LBL_AGAIN;
			}

			dsd_const_string strl_esc2 = dsl_value.m_substring(iml_pos, iml_end+1);;
			int iml_nused = m_get_vc_ch_ex( &uml_value, strl_esc2.m_get_start(),
				strl_esc2.m_get_end(), ied_chs_html_1 );
			if(iml_nused < 0 || iml_nused != strl_esc2.m_get_len()) {
				this->iec_unescape_state = iec_unescape_html_default;
				iml_pos = iml_end+1;
				continue;
			}

			dsd_const_string dsl_last_chunk = dsl_value.m_substring(iml_last_copy, iml_pos);
			int inl_ret = this->adsc_interpreter->m_parse_data(
				dsl_last_chunk.m_get_ptr(), dsl_last_chunk.m_get_len(), false, ads_output );
			if(inl_ret < 0)
				return inl_ret;
			this->iec_unescape_state = iec_unescape_html_default;
			iml_pos = iml_end+1;
			iml_last_copy = iml_pos;
			goto LBL_ENCODE;
												  }
		case iec_unescape_html_collect: {
			int iml_end = dsl_value.m_find_first_of(";&", iml_pos);
			if(iml_end < 0) {
				this->dsc_unescape_tag.m_write(dsl_value.m_substring(iml_pos));
				iml_last_copy = dsl_value.m_get_len();
				goto LBL_END;
			}
			switch(dsl_value[iml_end]) {
			case ';': {
				this->dsc_unescape_tag.m_write(dsl_value.m_substring(iml_pos, iml_end+1));
				this->iec_unescape_state = iec_unescape_html_default;
				iml_pos = iml_end+1;
				iml_last_copy = iml_pos;

				dsd_const_string strl_esc2 = this->dsc_unescape_tag.m_const_str();
				int iml_nused = m_get_vc_ch_ex( &uml_value, strl_esc2.m_get_start(),
					strl_esc2.m_get_end(), ied_chs_html_1 );
				if(iml_nused < 0 || iml_nused != strl_esc2.m_get_len()) {
					int inl_ret = this->adsc_interpreter->m_parse_data(
						strl_esc2.m_get_ptr(), strl_esc2.m_get_len(), false, ads_output );
					this->dsc_unescape_tag.m_reset();
					if(inl_ret < 0)
						return inl_ret;
					continue;
				}
				this->dsc_unescape_tag.m_reset();
				goto LBL_ENCODE;
						 }
			case '&':
				this->adsc_interpreter->m_parse_data(
					this->dsc_unescape_tag.m_get_ptr(), this->dsc_unescape_tag.m_get_len(), false, ads_output);
				this->dsc_unescape_tag.m_reset();
				this->iec_unescape_state = iec_unescape_html_findend;
				iml_pos = iml_end;
				iml_last_copy = iml_end;
				goto LBL_AGAIN;
			}
			return -1;
												  }
		default:
			return -1;
		}
LBL_ENCODE:
		dsd_unicode_string dsl_ucs;
		dsl_ucs.ac_str = &uml_value;
		dsl_ucs.imc_len_str = 1;
		dsl_ucs.iec_chs_str = ied_chs_utf_32;

		char chrl_temp[8];
		int in_needed = m_cpy_vx_vx( chrl_temp,
			sizeof(chrl_temp),
			this->m_get_charset(),
			dsl_ucs.ac_str, dsl_ucs.imc_len_str,
			dsl_ucs.iec_chs_str );
		if(in_needed < 0) {
			// TODO: Log error message
			continue;
		}
		int inl_ret = this->adsc_interpreter->m_parse_data(
			chrl_temp, in_needed, false, ads_output );
		if(inl_ret < 0)
			return inl_ret;
	} while(true);
LBL_END:
	dsd_const_string dsl_last_chunk = dsl_value.m_substring(iml_last_copy);
	int inl_ret = this->adsc_interpreter->m_parse_data(
		dsl_last_chunk.m_get_ptr(), dsl_last_chunk.m_get_len(), bo_data_complete, ads_output );
	return inl_ret;
}

ds_interpret_html::ied_html_doctype ds_interpret_html::m_get_doctype(const dsd_const_string& rdsp_doctype) {
	const dsd_const_string dsl_doctype_key("<!DOCTYPE ");
	if(!rdsp_doctype.m_starts_with_ic(dsl_doctype_key))
		return iec_html_doctype_invalid;
	dsd_const_string dsl_rest = rdsp_doctype.m_substring(dsl_doctype_key.m_get_len());
	dsl_rest.m_trim_left(" ");
	
	int inl_pos = dsl_rest.m_find_first_of(" >");
	if(inl_pos < 0)
		return iec_html_doctype_invalid;
	dsd_const_string dsl_word = dsl_rest.m_substring(0, inl_pos);
	dsl_rest = dsl_rest.m_substring(inl_pos);

	if(!dsl_word.m_equals_ic("HTML"))
		return iec_html_doctype_other;
	dsl_rest.m_trim_left(" ");
	// Is HTML5?
	if(dsl_rest.m_equals(">"))
		return iec_html_doctype_html_5;
	inl_pos = dsl_rest.m_find_first_of(" >");
	if(inl_pos < 0)
		return iec_html_doctype_invalid;
	dsl_word = dsl_rest.m_substring(0, inl_pos);
	dsl_rest = dsl_rest.m_substring(inl_pos);
	dsl_rest.m_trim_left(" ");
	if(dsl_word.m_equals_ic("PUBLIC")) {
		inl_pos = dsl_rest.m_index_of("\"");
		if(inl_pos < 0)
			return iec_html_doctype_invalid;
		int inl_pos2 = dsl_rest.m_index_of(inl_pos+1, "\"");
		if(inl_pos2 < 0)
			return iec_html_doctype_invalid;

		dsl_word = dsl_rest.m_substring(inl_pos, inl_pos2 + 1);
		dsl_rest = dsl_rest.m_substring(inl_pos2 + 1);
		dsl_rest.m_trim_left(" ");

		inl_pos = dsl_rest.m_index_of("\"");
		if(inl_pos < 0)
			return iec_html_doctype_invalid;
		inl_pos2 = dsl_rest.m_index_of(inl_pos+1, "\"");
		if(inl_pos2 < 0)
			return iec_html_doctype_invalid;

		inl_pos = dsl_rest.m_find_first_of(" >\"");
		if(inl_pos < 0)
			return iec_html_doctype_invalid;
		dsd_const_string dsl_word2 = dsl_rest.m_substring(inl_pos, inl_pos2 + 1);
		dsl_rest = dsl_rest.m_substring(inl_pos2 + 1);
		dsl_rest.m_trim_left(" ");
		
		if(dsl_word.m_starts_with_ic("\"-//W3C//DTD HTML 4.01")) {
			// HTML 4.01 Strict
			if(dsl_word.m_equals("\"-//W3C//DTD HTML 4.01//EN\"") && dsl_word2.m_equals_ic("\"http://www.w3.org/TR/html4/strict.dtd\"")) {
				return iec_html_doctype_html_4_01_strict;
			}
			// HTML 4.01 Transitional
			if(dsl_word.m_equals("\"-//W3C//DTD HTML 4.01 Transitional//EN\"") && dsl_word2.m_equals_ic("\"http://www.w3.org/TR/html4/loose.dtd\"")) {
				return iec_html_doctype_html_4_01_transitional;
			}
			// HTML 4.01 Frameset
			if(dsl_word.m_equals("\"-//W3C//DTD HTML 4.01 Frameset//EN\"") && dsl_word2.m_equals_ic("\"http://www.w3.org/TR/html4/frameset.dtd\"")) {
				return iec_html_doctype_html_4_01_frameset;
			}
			return iec_html_doctype_html_4_01_other;
		}
		if(dsl_word.m_starts_with_ic("\"-//W3C//DTD XHTML ")) {
			// XHTML 1.0 Strict
			if(dsl_word.m_equals("\"-//W3C//DTD XHTML 1.0 Strict//EN\"") && dsl_word2.m_equals_ic("\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\"")) {
				return iec_html_doctype_xhtml_1_0_strict;
			}
			// XHTML 1.0 Transitional
			if(dsl_word.m_equals("\"-//W3C//DTD XHTML 1.0 Transitional//EN\"") && dsl_word2.m_equals_ic("\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\"")) {
				return iec_html_doctype_xhtml_1_0_transitional;
			}
			// XHTML 1.0 Frameset
			if(dsl_word.m_equals("\"-//W3C//DTD XHTML 1.0 Frameset//EN\"") && dsl_word2.m_equals_ic("\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-frameset.dtd\"")) {
				return iec_html_doctype_xhtml_1_0_frameset;
			}
			// XHTML 1.1
			if(dsl_word.m_equals("\"-//W3C//DTD XHTML 1.1//EN\"") && dsl_word2.m_equals_ic("\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\"")) {
				return iec_html_doctype_xhtml_1_1;
			}
			return iec_html_doctype_xhtml_other;
		}
		return iec_html_doctype_other;
	}
	return iec_html_doctype_other;
}

#ifdef _DEBUG
static bool m_test_doctype() {
	if(ds_interpret_html::m_get_doctype("<!DOCTYPE html>") != ds_interpret_html::iec_html_doctype_html_5)
		return false;
	if(ds_interpret_html::m_get_doctype("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">") != ds_interpret_html::iec_html_doctype_html_4_01_strict)
		return false;
	if(ds_interpret_html::m_get_doctype("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">") != ds_interpret_html::iec_html_doctype_html_4_01_transitional)
		return false;
	if(ds_interpret_html::m_get_doctype("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Frameset//EN\" \"http://www.w3.org/TR/html4/frameset.dtd\">") != ds_interpret_html::iec_html_doctype_html_4_01_frameset)
		return false;

	if(ds_interpret_html::m_get_doctype("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">") != ds_interpret_html::iec_html_doctype_xhtml_1_0_strict)
		return false;
	if(ds_interpret_html::m_get_doctype("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">") != ds_interpret_html::iec_html_doctype_xhtml_1_0_transitional)
		return false;
	if(ds_interpret_html::m_get_doctype("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD XHTML 1.0 Frameset//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-frameset.dtd\">") != ds_interpret_html::iec_html_doctype_xhtml_1_0_frameset)
		return false;
	if(ds_interpret_html::m_get_doctype("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">") != ds_interpret_html::iec_html_doctype_xhtml_1_1)
		return false;
	return true;
}

static bool init = m_test_doctype();
#endif

/**
*
* function ds_interpret_html::m_process_tag
*
* @param[in]   char*       ach_tag         pointer to tag
* @param[in]   int         in_len_tag      pointer to length of tag
* @param[out]  int*        ain_tag_key     int key of tag
* @param[out]  ds_hstring*  ads_changed_tag changed tag
*
* return           int                     key:
*                                           HTML_NOT_CHANGED = tag not changed
*                                           HTML_CHANGED     = tag changed  
*
*/
int ds_interpret_html::m_process_tag(const char* ach_tag, int in_len_tag,
	struct dsd_attr_info& rdsp_info,
	ds_hstring* ads_changed_tag)
{
	if ( *ach_tag == 0x00 || in_len_tag <= 0 ) {
		return HTML_NOT_CHANGED;
	}
	// reset changed tag:
	ads_changed_tag->m_reset();

	// initialize some variables:
	int    in_return        = HTML_NOT_CHANGED; // return value
	int    in_position      = 0;                // actual reading position in tag
	int    in_value_start   = 0;                // start position of value
	int    in_attr_number   = -1;               // int key for attribute
	int    in_start_insert  = 0;                // start position for inserten ach_tag in str_changed_tag
	int    in_start_pos     = 0;                // for saving position index after tag name
	bool   bo_name_value_is_special = false;    // true if name value is in list -> value contains an uri and must be changed!
	const char*  ach_tag_name = NULL;           // pointer to tag name
	int    in_len_name      = 0;                // length of tag name
	const char*  ach_attr   = NULL;             // pointer to attribute
	int    in_len_attr      = 0;                // length of attribute
	//bool   bo_is_style      = false;            // tag is a link tag which contains a stylesheet
	bool   bo_script_is_async = false;            // script is async HTML5
	//bool   bo_is_meta_refresh = false;           // tag is a meta tag with http-equiv="refresh"
	ds_hstring dc_attr_value;                    // buffer for changed attribute value
	dc_attr_value.m_setup( ads_session->ads_wsp_helper );
	ds_hstring dc_attr_value2;                    // buffer for changed attribute value
	dc_attr_value2.m_setup( ads_session->ads_wsp_helper );

	m_get_tag_name( ach_tag, in_len_tag, &in_position, &ach_tag_name, &in_len_name );

	ied_charset iel_tag_charset = this->m_get_charset();

	rdsp_info.inc_tag_key = m_is_tag_in_list( ach_tag_name, in_len_name );
	rdsp_info.boc_is_style = false;
	rdsp_info.boc_is_meta_refresh = false;
	rdsp_info.boc_is_meta_xua_compatible = false;
	rdsp_info.boc_is_crossorigin = false;
	rdsp_info.boc_is_form_method_get = false;
	rdsp_info.iec_script_content_type = ds_http_header::ien_ct_not_set;
	rdsp_info.iec_script_charset = iel_tag_charset;
	rdsp_info.inc_unique_id = -1;

	if ( !bo_change_data ) {
		return HTML_NOT_CHANGED;
	}

	dsd_const_string dsl_tag(ach_tag, in_len_tag);
	dsd_const_string dsl_tag_name(ach_tag_name, in_len_name);
	if ( dsl_tag_name.m_equals_ic("!DOCTYPE") && this->iec_doctype == iec_html_doctype_not_set ) {
		ied_html_doctype iel_doctype = m_get_doctype(dsl_tag);
		this->iec_doctype = iel_doctype; 
	}

	if ( (ach_tag_name[0] == '!') || (ach_tag_name[0] == '/') ) {
		// <!--comment-->, <!doctype> or </end> tag => nothing to do
		return in_return;
	}

	switch(rdsp_info.inc_tag_key) {
	case ds_attributes::ied_htm_tag_script:
	case ds_attributes::ied_htm_tag_style:
	case ds_attributes::ied_htm_tag_meta:
	case ds_attributes::ied_htm_tag_link:
	case ds_attributes::ied_htm_tag_param:
	case ds_attributes::ied_htm_tag_form:
#if 0
	case ds_attributes::ied_htm_tag_a:
#endif
		{
			dsd_const_string dsl_http_equiv;
			dsd_const_string dsl_content;
			dsd_const_string dsl_charset;
			dsd_const_string dsl_type;
			dsd_const_string dsl_language;
			dsd_const_string dsl_crossorigin;
			dsd_const_string dsl_rel;
			dsd_const_string dsl_as;
			dsd_const_string dsl_name;
			dsd_const_string dsl_method;
			int inl_pos = in_position;
			while ( inl_pos < in_len_tag ) {
				const char*  ach_value  = NULL;             // pointer to attribute value
				int    in_len_value     = 0;                // length of attribute value

				m_get_attribute ( ach_tag, in_len_tag, &inl_pos, &ach_attr, &in_len_attr );
				m_get_attr_value( ach_tag, in_len_tag, &inl_pos, &in_value_start, &ach_value, &in_len_value );
				in_attr_number = m_is_attribute_in_list( ach_attr, in_len_attr );
				if ( in_attr_number < 0 ) {
					continue;
				}
				dsd_const_string* adsl_save = NULL;
				switch(in_attr_number) {
				case ds_attributes::ied_htm_attr_charset:
					adsl_save = &dsl_charset;
					goto LBL_SAVE;
				case ds_attributes::ied_htm_attr_http_equiv:
					adsl_save = &dsl_http_equiv;
					goto LBL_SAVE;
				case ds_attributes::ied_htm_attr_content:
					adsl_save = &dsl_content;
					goto LBL_SAVE;
				case ds_attributes::ied_htm_attr_rel:
					adsl_save = &dsl_rel;
					goto LBL_SAVE;
				case ds_attributes::ied_htm_attr_type:
					adsl_save = &dsl_type;
					goto LBL_SAVE;
				case ds_attributes::ied_htm_attr_language:
					adsl_save = &dsl_language;
					goto LBL_SAVE;
				case ds_attributes::ied_htm_attr_crossorigin:
					adsl_save = &dsl_crossorigin;
					goto LBL_SAVE;
				case ds_attributes::ied_htm_attr_async:
					if(rdsp_info.inc_tag_key == ds_attributes::ied_htm_tag_script)
						bo_script_is_async = true;
					break;
				case ds_attributes::ied_htm_attr_defer:
					break;
				case ds_attributes::ied_htm_attr_name:
					adsl_save = &dsl_name;
					goto LBL_SAVE;
				case ds_attributes::ied_htm_attr_method:
					adsl_save = &dsl_method;
					goto LBL_SAVE;
				case ds_attributes::ied_htm_attr_as:
					adsl_save = &dsl_as;
					goto LBL_SAVE;
				default:
					break;
				}
				continue;
LBL_SAVE:
				dsd_const_string dsl_value(m_unescape_attr_value(
					dsd_const_string(ach_value, in_len_value), dc_attr_value2));
				*adsl_save = dsl_value;
			}
			char chl_quote;
			dsl_charset = m_unquote(dsl_charset, chl_quote);
			ied_charset iel_charset_basic = ied_chs_invalid;
			if(dsl_charset.m_get_len() > 0) {
				iel_charset_basic = ds_http_header::m_get_charset(dsl_charset);
			}
			switch(rdsp_info.inc_tag_key) {
			case ds_attributes::ied_htm_tag_meta:
				dsl_http_equiv = m_unquote(dsl_http_equiv, chl_quote);
				if(dsl_http_equiv.m_equals_ic("Content-Type")) {
					ied_charset iel_charset = ds_http_header::m_get_charset(dsl_charset);
					//this->iec_meta_charset = ds_http_header::m_get_charset(dsl_charset);
					dsl_content = m_unquote(dsl_content, chl_quote);
					if(iel_charset == ied_chs_invalid && dsl_content.m_get_len() > 0) {
						ds_http_header::content_types iel_ct;
						ds_http_header::m_get_content_type(dsl_content, iel_ct, iel_charset);
					}
					if(iel_charset != ied_chs_invalid) {
						iel_tag_charset = iel_charset;
						this->iec_meta_charset = iel_tag_charset;
					}
				}
				else if(dsl_http_equiv.m_equals_ic("refresh")) {
					rdsp_info.boc_is_meta_refresh = true;
				}
				else if(dsl_http_equiv.m_equals_ic("X-UA-Compatible")) {
					rdsp_info.boc_is_meta_xua_compatible = true;
				}
				else {
					if(iel_charset_basic != ied_chs_invalid) {
						iel_tag_charset = iel_charset_basic;
						this->iec_meta_charset = iel_tag_charset;
					}
				}
				dsl_name = m_unquote(dsl_name, chl_quote);
				if(dsl_name.m_equals_ic("referrer")) {
					// TODO:
					ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
						"HWSGW119W: Detected new HTML5 attribute 'referrer' in <meta> content=\"%.*s\"",
						dsl_content.m_get_len(), dsl_content.m_get_ptr());
				}
				break;
#if 0
			case ds_attributes::ied_htm_tag_a:
				if(iel_charset_basic != ied_chs_invalid) {
					iel_tag_charset = iel_charset_basic;
				}
				break;
#endif
			case ds_attributes::ied_htm_tag_link: {
				dsl_rel = m_unquote(dsl_rel, chl_quote);
				dsd_tokenizer dsl_tok(dsl_rel, " ");
				bool bol_more_tokens;
				bool bol_is_preload = false;
				do {
					dsd_const_string dsl_rel_element;
					bol_more_tokens = dsl_tok.m_next(dsl_rel_element);
					dsl_rel_element.m_trim(" ");
					if(dsl_rel.m_equals("stylesheet")) {
						rdsp_info.boc_is_style = true;
					}
					else if(dsl_rel.m_equals("preload")) {
						bol_is_preload = true;
					}
				} while(bol_more_tokens);
				if(dsl_rel.m_equals("shortcut icon"))
					this->bo_icon_found = true;
				dsl_type = m_unquote(dsl_type, chl_quote);
				if(dsl_type.m_get_len() > 0) {
					ds_http_header::content_types iel_ct;
					ied_charset iel_charset;
					if(!ds_http_header::m_get_content_type(dsl_type, iel_ct, iel_charset)) {
						ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
							"HWSGW117W: unknown type attribute in link tag value=\"%.*s\"",
							dsl_type.m_get_len(), dsl_type.m_get_ptr());
					}
					rdsp_info.iec_script_content_type = iel_ct;
					if(iel_charset != ied_chs_invalid)
						rdsp_info.iec_script_charset = iel_charset;
					if(iel_ct == ds_http_header::ien_ct_text_css)
						rdsp_info.boc_is_style = true;
				}
				// if(dsl_type.m_equals("text/css"))
				//    rdsp_info.boc_is_style = true;
				if(bol_is_preload) {
					dsl_as = m_unquote(dsl_as, chl_quote);
					if(dsl_as.m_equals("style")) {
						rdsp_info.boc_is_style = true;
					}
					else if(dsl_as.m_equals("script")) {
						rdsp_info.iec_script_content_type = ds_http_header::ien_ct_application_javascript;
					}
				}
				break;
			}
			case ds_attributes::ied_htm_tag_param:
				if(m_is_name_value_in_list(dsl_name) >= 0)
					bo_name_value_is_special = true;
				break;
			case ds_attributes::ied_htm_tag_script:
				// Script charset does
				iel_tag_charset = this->iec_meta_charset;
				//if(iel_tag_charset == ied_chs_invalid)
				//	iel_tag_charset =  ied_chs_utf_8;
				if(iel_charset_basic != ied_chs_invalid) {
					iel_tag_charset = iel_charset_basic;
				}
				rdsp_info.iec_script_charset = iel_tag_charset;
				if(rdsp_info.iec_script_charset == ied_chs_invalid)
					rdsp_info.iec_script_charset = ied_chs_utf_8;
				dsl_type = m_unquote(dsl_type, chl_quote);
				if(dsl_type.m_get_len() > 0) {
					ds_http_header::content_types iel_ct;
					ied_charset iel_charset;
					if(!ds_http_header::m_get_content_type(dsl_type, iel_ct, iel_charset)) {
						ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
							"HWSGW117W: unknown type attribute in script tag value=\"%.*s\"",
							dsl_type.m_get_len(), dsl_type.m_get_ptr());
					}
					rdsp_info.iec_script_content_type = iel_ct;
					if(iel_charset != ied_chs_invalid)
						rdsp_info.iec_script_charset = iel_charset;
				}
				dsl_language = m_unquote(dsl_language, chl_quote);
				if(dsl_language.m_get_len() > 0) {
					if(dsl_language.m_equals_ic("vbscript")) {
						rdsp_info.iec_script_content_type = ds_http_header::ien_ct_unknown;
					}
					else if(dsl_language.m_equals_ic("javascript")) {
						rdsp_info.iec_script_content_type = ds_http_header::ien_ct_application_javascript;
					}
					else if(dsl_language.m_equals_ic("javascript1.2")) {
						rdsp_info.iec_script_content_type = ds_http_header::ien_ct_application_javascript;
					}
					else {
						ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
							"HWSGW118W: unknown language attribute in script tag value=\"%.*s\"",
							dsl_language.m_get_len(), dsl_language.m_get_ptr());
					}
				}
				rdsp_info.boc_is_crossorigin = (dsl_crossorigin.m_get_len() > 0);
				rdsp_info.dsc_crossorigin = dsl_crossorigin;
				break;
			case ds_attributes::ied_htm_tag_style:
				//rdsp_info.iec_script_charset = iel_charset;
				dsl_type = m_unquote(dsl_type, chl_quote);
				if(dsl_type.m_get_len() > 0) {
					ds_http_header::content_types iel_ct;
					ied_charset iel_charset;
					if(!ds_http_header::m_get_content_type(dsl_type, iel_ct, iel_charset)) {
						ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
							"HWSGW117W: unknown type attribute in style tag value=\"%.*s\"",
							dsl_type.m_get_len(), dsl_type.m_get_ptr());
					}
					rdsp_info.iec_script_content_type = iel_ct;
					//if(iel_charset != ied_chs_invalid)
					//    rdsp_info.iec_script_charset = iel_charset;
				}
				break;
			case ds_attributes::ied_htm_tag_form:
				dsl_method = m_unquote(dsl_method, chl_quote);
				rdsp_info.boc_is_form_method_get = dsl_method.m_equals_ic("GET");
				break;
			default:
				break;
			}
			break;
		}
	default:
		break;
	}
	rdsp_info.dsc_charset = ds_http_header::m_get_charset_name(iel_tag_charset);

	in_start_pos = in_position;

	if ( rdsp_info.inc_tag_key == ds_attributes::ied_htm_tag_script) {
		int a = 0;
	}

	bool bol_has_src_attribute = false;
	while ( in_position < in_len_tag ) {
		const char*  ach_value  = NULL;             // pointer to attribute value
		int    in_len_value     = 0;                // length of attribute value

		m_get_attribute ( ach_tag, in_len_tag, &in_position, &ach_attr, &in_len_attr );
		dsd_const_string dsl_attr(ach_attr, in_len_attr);
		m_get_attr_value( ach_tag, in_len_tag, &in_position, &in_value_start, &ach_value, &in_len_value );
		dsd_const_string dsl_original_value(ach_value, in_len_value);

		// search in list for attribute:
		in_attr_number = m_is_attribute_in_list( ach_attr, in_len_attr );
		if ( in_attr_number < 0 ) {
			continue;
		}

		dc_attr_value2.m_reset();
		dsd_const_string dsl_value(m_unescape_attr_value(dsl_original_value, dc_attr_value2));

		bool bo_attr_changed = false;            // is attribute changed?
		switch (in_attr_number) {
		case ds_attributes::ied_htm_attr_name:
			break;
		case ds_attributes::ied_htm_attr_value:
			if(!bo_name_value_is_special)
				break;
			bo_attr_changed = m_change_attr_value( &dc_attr_value, dsl_value, in_attr_number, rdsp_info );
			break;
		case ds_attributes::ied_htm_attr_background:
			bo_attr_changed = m_change_attr_value( &dc_attr_value, dsl_value, in_attr_number, rdsp_info );
			break;
		case ds_attributes::ied_htm_attr_rel:
			break;
		case ds_attributes::ied_htm_attr_as:
			break;
		case ds_attributes::ied_htm_attr_charset:
			break;
		case ds_attributes::ied_htm_attr_language:
			break;
		case ds_attributes::ied_htm_attr_type:
			break;
		case ds_attributes::ied_htm_attr_method:
			break;
		case ds_attributes::ied_htm_attr_href:
			switch(rdsp_info.inc_tag_key) {
			case ds_attributes::ied_htm_tag_a:
			case ds_attributes::ied_htm_tag_area:
			case ds_attributes::ied_htm_tag_base:
			case ds_attributes::ied_htm_tag_link:
				bo_attr_changed = m_change_attr_value( &dc_attr_value, dsl_value, in_attr_number, rdsp_info );
				break;
			default: {
				int a = 0;
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
					"HWSGW101W: unknown attribute constellation tag=\"%.*s\" attribute=\"%.*s\"",
					in_len_tag, ach_tag,
					dsl_attr.m_get_len(), dsl_attr.m_get_ptr());
				break;
						}
			}
			break;
		case ds_attributes::ied_htm_attr_xlink_href:
			switch(rdsp_info.inc_tag_key) {
			case ds_attributes::ied_htm_tag_svg_image:
			case ds_attributes::ied_htm_tag_svg_use:
			case ds_attributes::ied_htm_tag_svg_lineargradient:
				bo_attr_changed = m_change_attr_value( &dc_attr_value, dsl_value, in_attr_number, rdsp_info );
				break;
			default: {
				int a = 0;
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
					"HWSGW101W: unknown attribute constellation tag=\"%.*s\" attribute=\"%.*s\"",
					in_len_tag, ach_tag,
					dsl_attr.m_get_len(), dsl_attr.m_get_ptr());
				break;
						}
			}
			break;
		case ds_attributes::ied_htm_attr_src:
			switch(rdsp_info.inc_tag_key) {
			case ds_attributes::ied_htm_tag_audio:
			case ds_attributes::ied_htm_tag_embed:
			case ds_attributes::ied_htm_tag_iframe:
			case ds_attributes::ied_htm_tag_img:
			case ds_attributes::ied_htm_tag_input:
			case ds_attributes::ied_htm_tag_source:
			case ds_attributes::ied_htm_tag_track:
			case ds_attributes::ied_htm_tag_video:
			case ds_attributes::ied_htm_tag_script:
			case ds_attributes::ied_htm_tag_frame:
			case ds_attributes::ied_htm_tag_element:
				bo_attr_changed = m_change_attr_value( &dc_attr_value, dsl_value, in_attr_number, rdsp_info );
				break;
			default: {
				int a = 0;
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
					"HWSGW101W: unknown attribute constellation tag=\"%.*s\" attribute=\"%.*s\"",
					in_len_tag, ach_tag,
					dsl_attr.m_get_len(), dsl_attr.m_get_ptr());
				break;
						}
			}
			bol_has_src_attribute = true;
			break;
		case ds_attributes::ied_htm_attr_srcset:
			switch(rdsp_info.inc_tag_key) {
			case ds_attributes::ied_htm_tag_img:
			case ds_attributes::ied_htm_tag_source:
				bo_attr_changed = m_change_attr_value( &dc_attr_value, dsl_value, in_attr_number, rdsp_info );
				break;
			default: {
				int a = 0;
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
					"HWSGW101W: unknown attribute constellation tag=\"%.*s\" attribute=\"%.*s\"",
					in_len_tag, ach_tag,
					dsl_attr.m_get_len(), dsl_attr.m_get_ptr());
				break;
						}
			}
			break;
		case ds_attributes::ied_htm_attr_action:
			switch(rdsp_info.inc_tag_key) {
			case ds_attributes::ied_htm_tag_form:
				bo_attr_changed = m_change_attr_value( &dc_attr_value, dsl_value, in_attr_number, rdsp_info );
				break;
			default: {
				int a = 0;
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
					"HWSGW101W: unknown attribute constellation tag=\"%.*s\" attribute=\"%.*s\"",
					in_len_tag, ach_tag,
					dsl_attr.m_get_len(), dsl_attr.m_get_ptr());
				break;
						}
			}
			break;
		case ds_attributes::ied_htm_attr_data:
			switch(rdsp_info.inc_tag_key) {
			case ds_attributes::ied_htm_tag_object:
				bo_attr_changed = m_change_attr_value( &dc_attr_value, dsl_value, in_attr_number, rdsp_info );
				break;
			default: {
				int a = 0;
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
					"HWSGW101W: unknown attribute constellation tag=\"%.*s\" attribute=\"%.*s\"",
					in_len_tag, ach_tag,
					dsl_attr.m_get_len(), dsl_attr.m_get_ptr());
				break;
						}
			}
			break;
		case ds_attributes::ied_htm_attr_style:
			bo_attr_changed = m_change_attr_value( &dc_attr_value, dsl_value, in_attr_number, rdsp_info );
			break;
		case ds_attributes::ied_htm_attr_code:
			switch(rdsp_info.inc_tag_key) {
			case ds_attributes::ied_htm_tag_applet:
				bo_attr_changed = m_change_attr_value( &dc_attr_value, dsl_value, in_attr_number, rdsp_info );
				break;
			default: {
				int a = 0;
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
					"HWSGW101W: unknown attribute constellation tag=\"%.*s\" attribute=\"%.*s\"",
					in_len_tag, ach_tag,
					dsl_attr.m_get_len(), dsl_attr.m_get_ptr());
				break;
						}
			}
			break;
		case ds_attributes::ied_htm_attr_codebase:
			switch(rdsp_info.inc_tag_key) {
			case ds_attributes::ied_htm_tag_applet:
			case ds_attributes::ied_htm_tag_object:
				bo_attr_changed = m_change_attr_value( &dc_attr_value, dsl_value, in_attr_number, rdsp_info );
				break;
			default: {
				int a = 0;
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
					"HWSGW101W: unknown attribute constellation tag=\"%.*s\" attribute=\"%.*s\"",
					in_len_tag, ach_tag,
					dsl_attr.m_get_len(), dsl_attr.m_get_ptr());
				break;
						}
			}
			break;
		case ds_attributes::ied_htm_attr_profile:
			switch(rdsp_info.inc_tag_key) {
			case ds_attributes::ied_htm_tag_head:
				// TODO: Is a DOMString representing the URIs of one or more metadata profiles (white space separated).
				bo_attr_changed = m_change_attr_value( &dc_attr_value, dsl_value, in_attr_number, rdsp_info );
				break;
			default: {
				int a = 0;
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
					"HWSGW101W: unknown attribute constellation tag=\"%.*s\" attribute=\"%.*s\"",
					in_len_tag, ach_tag,
					dsl_attr.m_get_len(), dsl_attr.m_get_ptr());
				break;
						}
			}
			break;
		case ds_attributes::ied_htm_attr_http_equiv:
			break;
		case ds_attributes::ied_htm_attr_async:
			break;
		case ds_attributes::ied_htm_attr_integrity:
#if 1
			ads_changed_tag->m_write(&ach_tag[in_start_insert], dsl_attr.strc_ptr-&ach_tag[in_start_insert]);
			ads_changed_tag->m_write("HOB_integrity");
			if(dsl_original_value.m_get_len() > 0) {
				ads_changed_tag->m_write("=");
				ads_changed_tag->m_write(dsl_original_value);
			}
			in_start_insert = in_position;
			in_return = HTML_CHANGED;
#endif
			// TODO: Check values!
			ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
				"HWSGW120W: Detected new HTML5 attribute 'integrity' in tag <%.*s> value=\"%.*s\"",
				in_len_name, ach_tag_name,
				dsl_value.m_get_len(), dsl_value.m_get_ptr());
			break;
		case ds_attributes::ied_htm_attr_sandbox:
#if 1
			ads_changed_tag->m_write(&ach_tag[in_start_insert], dsl_attr.strc_ptr-&ach_tag[in_start_insert]);
			ads_changed_tag->m_write("HOB_sandbox");
			if(dsl_original_value.m_get_len() > 0) {
				ads_changed_tag->m_write("=");
				ads_changed_tag->m_write(dsl_original_value);
			}
			in_start_insert = in_position;
			in_return = HTML_CHANGED;
#endif
			break;
		case ds_attributes::ied_htm_attr_crossorigin:
#if 1
			ads_changed_tag->m_write(&ach_tag[in_start_insert], dsl_attr.strc_ptr-&ach_tag[in_start_insert]);
			ads_changed_tag->m_write("HOB_crossorigin");
			if(dsl_original_value.m_get_len() > 0) {
				ads_changed_tag->m_write("=");
				ads_changed_tag->m_write(dsl_original_value);
			}
			in_start_insert = in_position;
			in_return = HTML_CHANGED;
#endif
			break;
		case ds_attributes::ied_htm_attr_referrerpolicy:
			// TODO: Check values!
			ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
				"HWSGW120W: Detected new HTML5 attribute 'referrerpolicy' in tag <%.*s> value=\"%.*s\"",
				in_len_name, ach_tag_name,
				dsl_value.m_get_len(), dsl_value.m_get_ptr());
			break;
		case ds_attributes::ied_htm_attr_srcdoc:
			switch(rdsp_info.inc_tag_key) {
			case ds_attributes::ied_htm_tag_iframe: {
				// TODO: Is a DOMString representing the HTML content of the iframe.
				bo_attr_changed = m_change_attr_value( &dc_attr_value, dsl_value, in_attr_number, rdsp_info );
				break;
																 }
			default: {
				int a = 0;
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
					"HWSGW101W: unknown attribute constellation tag=\"%.*s\" attribute=\"%.*s\"",
					in_len_tag, ach_tag,
					dsl_attr.m_get_len(), dsl_attr.m_get_ptr());
				break;
						}
			}
			break;
		default: {
			if(in_attr_number > ds_attributes::ied_htm_attr_scr_start
				&& in_attr_number < ds_attributes::ied_htm_attr_scr_end)
			{
				bo_attr_changed = m_change_attr_value( &dc_attr_value, dsl_value, in_attr_number, rdsp_info );
				break;
			}
			if(rdsp_info.inc_tag_key < 0) {
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
					"HWSGW116W: unknown attribute constellation tag=\"%.*s\" attribute=\"%.*s\"",
					in_len_tag, ach_tag,
					dsl_attr.m_get_len(), dsl_attr.m_get_ptr());
				break;
			}
			bo_attr_changed = m_change_attr_value( &dc_attr_value, dsl_value, in_attr_number, rdsp_info );
			break;
					}
		}
		if ( bo_attr_changed ) {
			m_put_tag_together( ads_changed_tag, ach_tag, in_len_tag,
				dc_attr_value.m_get_ptr(), dc_attr_value.m_get_len(),
				in_start_insert, in_value_start );
			in_start_insert  = in_position;
			in_return        = HTML_CHANGED;
		}
	}
	bool bol_is_javascript_tag = rdsp_info.inc_tag_key == ds_attributes::ied_htm_tag_script
		&& (rdsp_info.iec_script_content_type == ds_http_header::ien_ct_not_set || rdsp_info.iec_script_content_type == ds_http_header::ien_ct_application_javascript);
	if ( bol_is_javascript_tag && !bol_has_src_attribute ) {
		m_put_tag_together( ads_changed_tag, ach_tag, in_len_tag, NULL, 0,
			in_start_insert, in_len_tag-1 );
		in_start_insert  = in_len_tag-1;

		int iml_unique_id = this->imc_uniqueid_counter++;
		rdsp_info.inc_unique_id = iml_unique_id;
		ads_changed_tag->m_write(" HOB_uniqueid='S");
		ads_changed_tag->m_write_int(iml_unique_id);
		ads_changed_tag->m_write("'");

		m_put_tag_together( ads_changed_tag, ach_tag, in_len_tag, NULL, 0,
			in_start_insert, in_len_tag );
		in_start_insert  = in_len_tag;
		in_return        = HTML_CHANGED;
	}
	if ( in_return == HTML_CHANGED ) {
		// put end of ach_tag to str_tag_changed
		m_put_tag_together( ads_changed_tag, ach_tag, in_len_tag, NULL, 0, in_start_insert, in_len_tag );
	}
	if ( rdsp_info.inc_tag_key == ds_attributes::ied_htm_tag_script ) {
		if ( m_check_for_empty_tag( ach_tag, in_len_tag ) ) {
			rdsp_info.inc_tag_key = ds_attributes::ied_htm_tag_scriptempty;
		}
	}
	else if ( rdsp_info.inc_tag_key == ds_attributes::ied_htm_tag_style ) {
		if ( m_check_for_empty_tag( ach_tag, in_len_tag ) ) {
			rdsp_info.inc_tag_key = ds_attributes::ied_htm_tag_styleempty;
		}
	}

	return in_return;
} // end of ds_interpret_html::m_process_tag


/**
*
* function ds_interpret_html::m_put_tag_together
*
* @param[out]  ds_hstring*  ads_out                 output memory
* @param[in]   char*       ach_tag                 actual tag
* @param[in]   int         in_len_tag              length of tag
* @param[in]   char*       ach_new_value           new value
* @param[in]   int         in_len_new_val          length of new value
* @param[in]   int         in_start_insert         insert tag from this position
* @param[in]   int         in_end_insert           insert tag until this position                         
*
*/
void ds_interpret_html::m_put_tag_together( ds_hstring* ads_out,
														 const char* ach_tag, int in_len_tag,
														 const char* ach_new_value, int in_len_new_val,
														 int in_start_insert, int in_end_insert )
{
	if (    ach_tag == NULL
		|| in_len_tag <= 0
		|| in_start_insert > in_len_tag
		|| in_end_insert > in_len_tag 
		|| in_start_insert >= in_end_insert ) {
			return;
	}

	ads_out->m_write( &ach_tag[in_start_insert], in_end_insert - in_start_insert );
	ads_out->m_write( ach_new_value, in_len_new_val );

	return;
} // end of ds_interpret_html::m_put_tag_together


void ds_interpret_html::m_filter_xua_compatible(const dsd_const_string& dsl_value2, ds_hstring& ads_out) {
	dsd_tokenizer dsl_tok(dsl_value2, ";");
	bool bol_more_tokens;
	bool bol_compatible = false;
	do {
		dsd_const_string dsl_param;
		bol_more_tokens = dsl_tok.m_next(dsl_param);
		dsl_param.m_trim(" ");
		if(dsl_param.m_equals_ic("IE=edge")) {
			ads_out.m_write(dsl_param);
			ads_out.m_write("; ");
			bol_compatible = true;
		}
		else if(dsl_param.m_equals_ic("IE=11")) {
			ads_out.m_write(dsl_param);
			ads_out.m_write("; ");
			bol_compatible = true;
		}
	} while(bol_more_tokens);
	if(!bol_compatible) {
		ads_out.m_write("IE=edge; IE=11");
	}
}

/**
*
* function ds_interpret_html::m_change_attr_value
*
* @param[out]  ds_hstring*  ads_out         changed attribute value (if existing)
* @param[in]   char*       ach_value       attribute value
* @param[in]   int         in_len_val      length of attribute value
* @param[in]   int         in_attr_number  key of attribute
* @param[in]   int         in_tag_key      key of tag
* @param[in]   bool        bo_is_style     key is link tag which contains a stylesheet
*
* return        bool                       key:
*                                           false = value not changed
*                                           true  = value changed
*
*/
bool ds_interpret_html::m_change_attr_value( ds_hstring* ads_out,
														  const dsd_const_string& dsp_value,
														  int in_attr_number,
														  const struct dsd_attr_info& rdsp_info )
{
	// TODO: Split function into independent sections
	if ( in_attr_number < 0 || dsp_value.m_get_len() <= 0) {
		return false;
	}
	// initialze some variables:
	bool   bo_data_complete = true;         // signal for the other interpreter
	int    in_url_pos       = 0;            // position marker for url in "content='0; URL=http://www.google.de'"

	ads_out->m_reset();

	char chl_quote;
	dsd_const_string dsl_value2 = m_unquote(dsp_value, chl_quote);

	if(in_attr_number == ds_attributes::ied_htm_attr_srcdoc) {
		ds_interpret_html dsl_interpret_html;
		// TODO: Is the path correct?
		dsl_interpret_html.m_init();
		dsl_interpret_html.m_set_content_type(ds_http_header::ien_ct_text_html);
		dsl_interpret_html.m_set_charset(this->m_get_charset());
		dsl_interpret_html.m_set_iframe_depth(this->inc_iframe_depth + 1);
		dsl_interpret_html.m_setup(this->ads_session);

		ds_hstring dsl_html(this->ads_session->ads_wsp_helper);
		dsl_interpret_html.m_parse_data( dsl_value2.m_get_ptr(), dsl_value2.m_get_len(),
			true, &dsl_html );
		ads_out->m_write( dsp_value.m_get_ptr(), dsl_value2.m_get_ptr()-dsp_value.m_get_ptr() );
		ads_out->m_write_html_text(dsl_html);
		ads_out->m_write( dsl_value2.m_get_end(), dsp_value.m_get_end()-dsl_value2.m_get_end() );

		return true;
	}

	if (    in_attr_number > ds_attributes::ied_htm_attr_start
		&& in_attr_number < ds_attributes::ied_htm_attr_end ) {
			if( in_attr_number == ds_attributes::ied_htm_attr_srcset)
			{
				dsd_const_string dsl_cur = dsl_value2;
				bool bo_return = false;
				while(dsl_cur.m_get_len() > 0) {
					int inl_pos = dsl_cur.m_index_of(", ");
					dsd_const_string dsl_value = dsl_cur;
					dsd_const_string dsl_src = dsl_value;
					if(inl_pos >= 0) {
						dsl_src = dsl_cur.m_substring(0, inl_pos);
						dsl_cur = dsl_cur.m_substring(inl_pos+2);
					}
					else {
						dsl_cur = dsl_cur.m_substring(dsl_cur.m_get_len());
					}

					dsl_src.m_trim(" ");
					inl_pos = dsl_src.m_index_of(" ");
					dsd_const_string dsl_url = dsl_src;
					if(inl_pos >= 0) {
						dsl_url = dsl_src.m_substring(0, inl_pos);
					}
					ds_hstring dsl_url2(this->ads_session->ads_wsp_helper, dsl_url);
					ied_change_url_result in_added_signs = m_change_url( dsl_url, ds_interpret::ied_change_url_flags_default, dsl_url2 );
					if(!bo_return) {
						if( in_added_signs != ied_change_url_changed )
							continue;
						ads_out->m_write( dsp_value.m_get_ptr(), dsl_value.m_get_ptr()-dsp_value.m_get_ptr() );
						bo_return = true;
					}
					ads_out->m_write( dsl_value.m_get_ptr(), dsl_url.m_get_ptr()-dsl_value.m_get_ptr() );
					ads_out->m_write( dsl_url2 );
					ads_out->m_write( dsl_url.m_get_end(), dsl_cur.m_get_ptr()-dsl_url.m_get_end() );
				}
				if(!bo_return)
					return false;
				ads_out->m_write( dsl_value2.m_get_end(), dsp_value.m_get_end()-dsl_value2.m_get_end() );
				return true;
			}

			if(in_attr_number == ds_attributes::ied_htm_attr_background) {
				dsd_const_string dsl_value4 = dsl_value2;
				dsl_value4.m_trim(" ");
				if(dsl_value4.m_equals("transparent"))
					return false;
			}

			dsd_const_string dsl_url = dsl_value2;
			// get cases like content = "0; URL='http://www.google.de'"
			if ( in_attr_number == ds_attributes::ied_htm_attr_content ) {
				// Is meta http-equiv=X-UA-Compatible?
				if(rdsp_info.boc_is_meta_xua_compatible) {
					ads_out->m_write( dsp_value.m_get_ptr(), dsl_value2.m_get_ptr()-dsp_value.m_get_ptr() );
					m_filter_xua_compatible(dsl_value2, *ads_out);
					ads_out->m_write( dsl_value2.m_get_end(), dsp_value.m_get_end()-dsl_value2.m_get_end() );
					return true;
				}
				// Only valid for meta http-equiv="refresh"!!!!
				else if(rdsp_info.boc_is_meta_refresh) {
					in_url_pos = dsl_url.m_index_of_ic( "url" );
					if(in_url_pos < 0)
						return false;
					in_url_pos += 3;    // plus length of "url"
					m_pass_signs( dsl_url.m_get_ptr(), dsl_url.m_get_len(), &in_url_pos, " \n\r\t\v\f\"'<>=!" );
					// TODO: Check for '='???
					if(in_url_pos >= dsl_url.m_get_len())
						return false;
					dsl_url = dsl_url.m_substring(in_url_pos);
					dsl_value2 = dsl_url;
					//bo_url_mode = true;
				}
				else {
					return false;
				}
			}

			dsd_const_string dsl_value3 = dsl_value2;
			dsl_value3.m_trim_left(" ");
			// our attribute is a "normal" html attribute
			if (dsl_value3.m_starts_with_ic("javascript:")) {
				// case of href="javascript:xyz" -> call javascript interpreter:
				dsd_const_string dsl_jscript = dsl_value3.m_substring(11);
#if 0
				if(dsl_jscript.m_equals("void(0)")) {
					ads_out->m_set( "/protected/wsg/empty_script.js" );
					return true;
				}
#endif
				ads_session->dsc_ws_gate.dsc_interpret_script.m_init(
					this->m_get_charset(), &chl_quote, ds_interpret_script::IMC_FLAG_TOP_LEVEL | ds_interpret_script::IMC_FLAG_HTML_ATTRIBUTE);
				ads_out->m_write( dsp_value.m_get_ptr(), dsl_jscript.m_get_ptr()-dsp_value.m_get_ptr() );
				//ads_out->m_write("javascript:");
				if(rdsp_info.inc_tag_key == ds_attributes::ied_htm_tag_iframe) {
					ads_out->m_write("window.top.HOB.m_ensure_hob_context(window),");   
				}
				ads_session->dsc_ws_gate.dsc_interpret_script.m_parse_data(
					dsl_jscript.m_get_start(), dsl_jscript.m_get_len(),
					bo_data_complete, ads_out );
				ads_out->m_write( dsl_jscript.m_get_end(), dsp_value.m_get_end()-dsl_jscript.m_get_end() );
				return true;
			} 

			//int inl_end_of_value = in_len_val;
			//m_pass_signs( ach_value, in_len_val, &inl_end_of_value, " \f\n\r\t\v\"'", false );
#if 0
			// get cases like "src=javascript:void()" and "src=about:blank"
			if ( in_attr_number == ds_attributes::ied_htm_attr_src ) {
				if ( dsl_url.m_starts_with_ic( "about:blank" ) ) {
					ads_out->m_set( "/protected/wsg/empty_site.htm" );
					return true;
				}
			}
#endif  
			if (dsl_value3.m_starts_with_ic("data:")) {
				ds_url::dsd_data_url dsl_data_url;
				if(!ds_url::m_parse_data_url(dsl_value3, dsl_data_url))
					return false;
				// Try to get the charset
				ied_charset iel_charset = ds_http_header::m_get_charset(dsl_data_url.dsc_charset);
				if(iel_charset == ied_chs_invalid)
					iel_charset = this->m_get_charset();
				ds_interpret* adsl_interpreter = NULL;
#if 0
				ds_interpret_html dsl_interpret_html;
#endif
				switch(in_attr_number) {
				case ds_attributes::ied_htm_attr_src:
					switch(rdsp_info.inc_tag_key) {
					case ds_attributes::ied_htm_tag_script:
						ads_session->dsc_ws_gate.dsc_interpret_script.m_init(iel_charset, &chl_quote, 0);
						adsl_interpreter = &ads_session->dsc_ws_gate.dsc_interpret_script;
						break;
					case ds_attributes::ied_htm_tag_style:
						adsl_interpreter = &ads_session->dsc_ws_gate.dsc_interpret_css;
						break;
					case ds_attributes::ied_htm_tag_iframe:
#if 1
						ads_out->m_write( dsp_value.m_get_ptr(), dsl_value2.m_get_ptr()-dsp_value.m_get_ptr() );
						ads_out->m_write("javascript:window.top.HOB.m_rewrite_data_url(\"");
						ds_hstring dsl_temp(ads_session->ads_wsp_helper);
						dsl_temp.m_write_b64(dsl_value3.m_get_start(), dsl_value3.m_get_len());
						ads_out->m_write(dsl_temp);
						ads_out->m_write("\")");
						ads_out->m_write( dsl_value2.m_get_end(), dsp_value.m_get_end()-dsl_value2.m_get_end() );
						return true;
#else
						dsl_interpret_html.m_setup(this->ads_session,
							this->ds_wsp_address.m_const_str(),
							this->ds_ext_address.m_const_str(),
							ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_const_str());
						dsl_interpret_html.m_set_content_type(ds_http_header::ien_ct_text_html);
						dsl_interpret_html.m_set_charset(iel_charset);
						dsl_interpret_html.m_set_iframe_depth(this->inc_iframe_depth + 1);
						adsl_interpreter = &dsl_interpret_html;
						break;
#endif
					}
					break;
				case ds_attributes::ied_htm_attr_href:
					switch(rdsp_info.inc_tag_key) {
					case ds_attributes::ied_htm_tag_link:
						if(rdsp_info.boc_is_style) {
							adsl_interpreter = &ads_session->dsc_ws_gate.dsc_interpret_css;
							//dsl_hobtype_data.dsc_hobtype = HOB_TYPE "css";
							//bol_origin = true;
							break;
						}
						if(rdsp_info.iec_script_content_type == ds_http_header::ien_ct_application_javascript) {
							adsl_interpreter = &ads_session->dsc_ws_gate.dsc_interpret_script;
							break;
						}
						break;
					default:
						break;
					}
					break;
				}
				if(adsl_interpreter == NULL)
					return false;
				ds_hstring hstr_content(this->ads_session->ads_wsp_helper);
				dsd_const_string dsl_content;
				if(dsl_data_url.boc_base64) {
					hstr_content.m_from_b64(dsl_data_url.dsc_content.m_get_start(), dsl_data_url.dsc_content.m_get_len());
				}
				else {
					if(ds_webserver::m_conv_from_hexhexencoding(dsl_data_url.dsc_content, hstr_content, dsl_content) != SUCCESS)
						return false;
				}
				ds_hstring dsl_content2(this->ads_session->ads_wsp_helper);
				adsl_interpreter->m_parse_data( dsl_content.m_get_ptr(), dsl_content.m_get_len(), bo_data_complete, &dsl_content2 );
				ds_hstring dsl_url2(this->ads_session->ads_wsp_helper);
				hstr_content.m_reset();
				hstr_content.m_write_b64(dsl_content2.m_get_ptr(), dsl_content2.m_get_len());
				dsl_data_url.dsc_content = hstr_content.m_const_str();
				dsl_data_url.boc_base64 = true;
				ads_out->m_write( dsp_value.m_get_ptr(), dsl_value2.m_get_ptr()-dsp_value.m_get_ptr() );
				ds_url::m_write_data_url(dsl_data_url, *ads_out);
				ads_out->m_write( dsl_value2.m_get_end(), dsp_value.m_get_end()-dsl_value2.m_get_end() );
				return true;
			}

			if(dsl_url.m_get_len() <= 0) {
				return false;
			}

			dsd_hobtype_data dsl_hobtype_data;
			bool bol_origin = rdsp_info.boc_is_crossorigin;
			switch(in_attr_number) {
			case ds_attributes::ied_htm_attr_src:
				switch(rdsp_info.inc_tag_key) {
				case ds_attributes::ied_htm_tag_script:
					dsl_hobtype_data.dsc_hobtype = HOB_TYPE "js";
					dsl_hobtype_data.dsc_charset = rdsp_info.dsc_charset;
					break;
				case ds_attributes::ied_htm_tag_style:
					dsl_hobtype_data.dsc_hobtype = HOB_TYPE "css";
					break;
				case ds_attributes::ied_htm_tag_iframe:
					dsl_hobtype_data.dsc_hobtype = HOB_TYPE "html";
					break;
				}
				break;
			case ds_attributes::ied_htm_attr_href:
				switch(rdsp_info.inc_tag_key) {
				case ds_attributes::ied_htm_tag_link:
					if(rdsp_info.boc_is_style) {
						dsl_hobtype_data.dsc_hobtype = HOB_TYPE "css";
						bol_origin = true;
						break;
					}
					if(rdsp_info.iec_script_content_type == ds_http_header::ien_ct_application_javascript) {
						dsl_hobtype_data.dsc_hobtype = HOB_TYPE "js";
						// No charset
						dsl_hobtype_data.dsc_charset = dsd_const_string::m_null();
						break;
					}
					break;
#if 0
				case ds_attributes::ied_htm_tag_a:
					dsl_hobtype_data.dsc_hobtype = HOB_TYPE "any";
					dsl_hobtype_data.dsc_charset = rdsp_info.dsc_charset;
					break;
#endif
				}
				break;
			case ds_attributes::ied_htm_attr_action:
				switch(rdsp_info.inc_tag_key) {
				case ds_attributes::ied_htm_tag_form:
					dsl_hobtype_data.dsc_hobtype = HOB_TYPE "any";
					bol_origin = !rdsp_info.boc_is_form_method_get;
					break;
				}
				break;
			}
			if(bol_origin && dsl_hobtype_data.dsc_hobtype.m_get_len() <= 0) {
				dsl_hobtype_data.dsc_hobtype = HOB_TYPE "any";
			}
			ds_hstring dsl_origin(this->ads_session->ads_wsp_helper);
			if(bol_origin) {
				dsl_origin.m_write(ads_session->dsc_ws_gate.dsc_url.hstr_protocol);
				dsl_origin.m_write("://");
				dsl_origin.m_write(ads_session->dsc_ws_gate.dsc_url.hstr_authority_of_webserver);
				dsl_hobtype_data.dsc_origin = dsl_origin.m_const_str();
			}
			const bool bol_hobtype_needed = dsl_hobtype_data.dsc_hobtype.m_get_len() > 0;

			//ads_out->m_write( ach_value, in_len_val );
			ied_change_url_flags iel_url_flags = ied_change_url_flags_default;        // (false/true) = (relativ/absolut)
			if ( rdsp_info.inc_tag_key == ds_attributes::ied_htm_tag_base ) {
				iel_url_flags = (ied_change_url_flags)(iel_url_flags | ied_change_url_flag_absolute);
			}
			dsd_const_string dsl_immediate_call1 = "javascript:window.parent.HOB.m_set_iframe_src(this,";
			dsd_const_string dsl_immediate_call2 = ")";
			if ( rdsp_info.inc_tag_key == ds_attributes::ied_htm_tag_iframe ) {
				iel_url_flags = (ied_change_url_flags)(iel_url_flags | ied_change_url_flag_prevent_immediate);
			}

			ds_hstring dsl_url2(this->ads_session->ads_wsp_helper);
			ds_interpret::ied_change_url_result inl_result = m_change_url( dsl_url, iel_url_flags, dsl_url2 );
			dsd_const_string hstrl_url2 = dsl_url;
			switch(inl_result) {
			case ied_change_url_error:
				if(!bol_hobtype_needed)
					return false;
				break;
			case ied_change_url_unchanged:
				if(!bol_hobtype_needed)
					return false;
				break;
			case ied_change_url_other_protocol:
				return false;
			case ied_change_url_changed:
				hstrl_url2 = dsl_url2.m_const_str();
				break;
			case ied_change_url_prevent_immediate: {
				ads_out->m_write(dsl_immediate_call1);
				char chl_anti_quote = chl_quote != '"' ? '"' : '\'';
				ads_out->m_write(&chl_anti_quote, 1);
				ds_hstring dsl_temp(this->ads_session->ads_wsp_helper);
				dsd_const_string adsl_temp = m_escape_js_string(dsl_url, dsl_temp);
				ads_out->m_write(adsl_temp);
				ads_out->m_write(&chl_anti_quote, 1);
				ads_out->m_write(",");
				ads_out->m_write(&chl_anti_quote, 1);
				this->m_add_hobtype(*ads_out, dsl_hobtype_data);
				ads_out->m_write(&chl_anti_quote, 1);
				ads_out->m_write(dsl_immediate_call2);
				return true;
																}
			}
			// set return value:
			ads_out->m_write( dsp_value.m_get_ptr(), dsl_value2.m_get_ptr()-dsp_value.m_get_ptr() );
			if(chl_quote == 0) {
				ads_out->m_write("\"");
			}
			int inl_hashpos = hstrl_url2.m_last_index_of("#");
			dsd_const_string strl_url2a = hstrl_url2;
			dsd_const_string strl_url2b = "";
			if(inl_hashpos >= 0) {
				strl_url2a = hstrl_url2.m_substring(0, inl_hashpos);
				strl_url2b = hstrl_url2.m_substring(inl_hashpos);
			}
			ads_out->m_write( strl_url2a );
			// add "?HOB_type=js" or "?HOB_type=css" to url:
			int inl_res = this->m_add_hobtype(*ads_out, dsl_hobtype_data);
			ads_out->m_write( strl_url2b );
			if(chl_quote == 0) {
				ads_out->m_write("\"");
			}
			ads_out->m_write( dsl_value2.m_get_end(), dsp_value.m_get_end()-dsl_value2.m_get_end() );
			return true;
	}
	else if (    in_attr_number > ds_attributes::ied_htm_attr_scr_start
		&& in_attr_number < ds_attributes::ied_htm_attr_scr_end ) {
			// our attribute is a javascript "onXYZ=" attribute -> call javascript interpreter
			//int in_start = 0;
			//int in_end   = in_len_val;

			// MJ 16.09.10, Ticket [20581]: set quote sign
			ads_session->dsc_ws_gate.dsc_interpret_script.m_init(this->m_get_charset(), &chl_quote, ds_interpret_script::IMC_FLAG_HTML_EVENT | ds_interpret_script::IMC_FLAG_HTML_ATTRIBUTE);

#if 0
			m_pass_signs( ach_value, in_len_val, &in_start,  "\"'", true );
			m_pass_signs( ach_value, in_len_val, &in_end,    "\"'", false );
			if ( in_start != in_len_val - in_end ) {
				// something like this: "new Image().src='/images/nav_logo3.png'"
				// choose the smallest one:
				if ( in_start < in_len_val - in_end ) {
					in_end = in_len_val - in_start;
				} else {
					in_start = in_len_val -in_end;
				}
			}

#endif
			// MJ, 12.05.09, Ticket[17623], empty value -> do nothing!
			if ( dsl_value2.m_get_len() <= 0 ) {
				return false;
			}

			ads_out->m_write( dsp_value.m_get_ptr(), dsl_value2.m_get_ptr()-dsp_value.m_get_ptr() );
			ads_session->dsc_ws_gate.dsc_interpret_script.m_parse_data( dsl_value2.m_get_ptr(), dsl_value2.m_get_len(),
				bo_data_complete, ads_out );
			ads_out->m_write( dsl_value2.m_get_end(), dsp_value.m_get_end()-dsl_value2.m_get_end() );

			return true;
	}
	else if (    in_attr_number > ds_attributes::ied_htm_attr_css_start
		&& in_attr_number < ds_attributes::ied_htm_attr_css_end ) {
			// our attribute is a css "style=" attribute -> call css interpreter

			// MJ, 12.05.09, Ticket[17623], empty value -> do nothing!
			if ( dsl_value2.m_get_len() <= 0 ) {
				return false;
			}

			ads_out->m_write( dsp_value.m_get_ptr(), dsl_value2.m_get_ptr()-dsp_value.m_get_ptr() );
			ads_session->dsc_ws_gate.dsc_interpret_css.m_parse_data( dsl_value2.m_get_ptr(), dsl_value2.m_get_len(),
				bo_data_complete, ads_out );
			ads_out->m_write( dsl_value2.m_get_end(), dsp_value.m_get_end()-dsl_value2.m_get_end() );
			return true;
	}
	return false;
} // end of ds_interpret_html::m_change_attr_value


/**
*
* function ds_interpret_html::m_check_for_empty_tag
*
* @param[in]     char*  ach_tag        tag
* @param[in]     int    in_len_tag     length of tag
*
* @return        bool                  true  = empty tag (like <br\>) 
*                                      false = non empty tag (like <br>)
*/
bool ds_interpret_html::m_check_for_empty_tag( const char* ach_tag, int in_len_tag )
{
	if ( ach_tag == NULL || in_len_tag <= 0 ) {
		return false;
	}
	int in_position = in_len_tag - 2;
	for ( ; in_position > 0; in_position-- ) {
		switch ( ach_tag[in_position] ) {
		case '\f':
		case '\n':
		case '\r':
		case '\t':
		case '\v':
		case ' ':
			continue;
		case '/':
			break;
		default:
			in_position--;
			break;
		}
		break;
	}
	return ( ach_tag[in_position] == '/' );
} // end of ds_interpret_html::m_check_for_empty_tag


/**
*
* function ds_interpret_html::m_get_tag_name
*
* @param[out]    ds_hstring* ads_out
* @param[in]     char*      ach_tag        tag
* @param[in]     int        in_len_tag     length of tag
* @param[in,out] int*       ain_position   actual position in tag
* @param[out]    char**     aach_name      pointer to name pointer
* @param[out]    int*       ain_len_name   length of name
*
*/
void ds_interpret_html::m_get_tag_name( const char* ach_tag, int in_len_tag,
													int* ain_position,
													const char** aach_name, int* ain_len_name )
{
	assert( ach_tag != NULL && in_len_tag > 0 );
	if ( ain_position != NULL ) {
		assert( *ain_position < in_len_tag && *ain_position >= 0 ); 
	}

	// initialize some variables: 
	int in_start_pos = 0;
	int in_name_start;
	int in_name_end;

	if ( ain_position != NULL ) {
		in_start_pos = *ain_position;
	}
	for ( in_name_start = in_start_pos; in_name_start < in_len_tag; in_name_start++ ) {
		switch ( ach_tag[in_name_start] ) {
		case '<':
		case ' ':
		case '\n':
		case '\r':
		case '\t':
		case '\v':
			continue;
		default:
			break;
		}
		break;
	}
	for ( in_name_end = in_name_start + 1; in_name_end < in_len_tag; in_name_end++ ) {
		switch ( ach_tag[in_name_end] ) {
		case '>':
		case ' ':
		case ':':
		case '\n':
		case '\r':
		case '\t':
		case '\v':
			break;
		default:
			continue;
		}
		break;
	}

	*aach_name = &ach_tag[in_name_start];
	*ain_len_name = in_name_end - in_name_start;
	if ( ain_position != NULL ) {
		*ain_position += in_name_end + 1;
	}
	return;
} // end of ds_interpret_html::m_get_tag_name


/**
*
* function ds_interpret_html::m_get_attribute
*
* @param[in]     char*      ach_tag        tag
* @param[in]     int        in_len_tag     length of tag
* @param[in,out] int*       ain_position   actual position in tag
* @param[out]    char**     aach_attr      pointer to attribute
* @param[out]    int*       ain_len_attr   length of attribute
*
*/
void ds_interpret_html::m_get_attribute( const char* ach_tag, int in_len_tag,
													 int *ain_position,
													 const char** aach_attr, int* ain_len_attr )
{
	assert( ach_tag != NULL && *ain_position < in_len_tag && in_len_tag > 0 && *ain_position >= 0 );

	// initialize some variables:
	int in_attr_start;
	int in_attr_end;

	for ( ; *ain_position < in_len_tag; (*ain_position)++ ) {
		switch ( ach_tag[*ain_position] ) {
		case ')':
		case '}':
		case ']':
		case '"':
		case '\'':
		case '/':
		case '>':
			continue;
		default:
			break;
		}
		break;
	}
	m_pass_signs( ach_tag, in_len_tag, ain_position, " \n\r\t\v\f" );
	in_attr_start = *ain_position;
	for ( in_attr_end = in_attr_start + 1; in_attr_end < in_len_tag; in_attr_end++ ) {
		switch ( ach_tag[in_attr_end] ) {
		case ' ':
		case '\n':
		case '\r':
		case '\t':
		case '\v':
		case '=':
			break;
		default:
			continue;
		}
		break;
	}
	*ain_position = in_attr_end;
	if ( in_attr_end <= in_len_tag ) {
		*aach_attr    = &ach_tag[in_attr_start];
		*ain_len_attr = in_attr_end - in_attr_start;
	} else {
		*aach_attr    = NULL;
		*ain_len_attr = 0;
	}
	return;
} // end of ds_interpret_html::m_get_attribute


/**
*
* function ds_interpret_html::m_get_attr_value
*
* @param[out]    ds_hstring* ads_out
* @param[in]     char*  ach_tag            tag
* @param[in]     int    in_len_tag         length of tag
* @param[in,out] int*   ain_position       actual position in tag
* @param[out]    int*   ain_value_start    start position of found value
*                                          default value NULL
* @param[out]    char** aach_value         pointer to found value
* @param[out]    int*   ain_len_val        length of found value
*
*/
void ds_interpret_html::m_get_attr_value( const char* ach_tag, int in_len_tag,
													  int *ain_position,
													  int* ain_value_start,
													  const char** aach_value, int* ain_len_val )
{
	assert( ach_tag != NULL && in_len_tag > 0 && *ain_position >= 0 );

	if ( *ain_position >= in_len_tag ) {
		return;
	}

	// move until equal:
	int in_value_start = *ain_position;
	m_pass_signs( ach_tag, in_len_tag, ain_position, " \n\r\t\v\f" );
	if ( ach_tag[*ain_position] != '=' ) {
		*ain_position = in_value_start;
		return;
	}
	(*ain_position)++;
	// move until first following sign:
	m_pass_signs( ach_tag, in_len_tag, ain_position, " \n\r\t\v\f" );
	in_value_start = *ain_position;
	if ( ain_value_start != NULL ) {
		*ain_value_start = in_value_start;
	}

	for ( ; *ain_position < in_len_tag; (*ain_position)++ ) {
		switch ( ach_tag[*ain_position] ) {
		case '"':
			m_handle_double_quote( ach_tag, in_len_tag, ain_position );
			(*ain_position)++;
			break;
		case '\'':
			m_handle_single_quote( ach_tag, in_len_tag, ain_position );
			(*ain_position)++;
			break;
#if 0
		case '(':
			m_handle_round_bracket( ach_tag, in_len_tag, ain_position );
			continue;
		case '{':
			m_handle_curly_bracket( ach_tag, in_len_tag, ain_position );
			continue;
		case '[':
			m_handle_square_bracket( ach_tag, in_len_tag, ain_position );
			continue;
#endif
		case ' ':
		case '\n':
		case '\r':
		case '\t':
		case '\v':
		case '\f':
		case '>':
			break;
		case '/':
			if ( *ain_position + 1 < in_len_tag && ach_tag[*ain_position + 1] == '>' ) {
				break;
			} else {
				continue;
			}
		default:
			continue;
		}
		break;
	}

	if ( *ain_position <= in_len_tag ) {
		*aach_value  = &ach_tag[in_value_start];
		*ain_len_val = *ain_position - in_value_start;
	} else {
		*aach_value  = NULL;
		*ain_len_val = 0;
	}
	return;
} // end of ds_interpret_html::m_get_attr_value


/**
*
* function ds_interpret_html::m_handle_double_quote
*
* @param[in]     char*  ach_data        data
* @param[in]     int    in_len_data     length of data
* @param[in,out] int*   ain_position    actual position in data
*
* @return        int                    end position = ain_position
*
*/
int ds_interpret_html::m_handle_double_quote( const char* ach_data, int in_len_data, int *ain_position )
{
	assert ( ach_data != NULL && *ain_position < in_len_data && in_len_data > 0 && *ain_position >= 0 );
	if ( ach_data[*ain_position] != '"') {
		// security check
		return *ain_position;
	}
	(*ain_position)++;
	for ( ; *ain_position < in_len_data; (*ain_position)++ ) {
		switch ( ach_data[*ain_position] ) {
		case '"':
			break;
		case '\\':
			(*ain_position)++;  // don't read next sign
			continue;
		default:
			continue;
		}
		break;
	}
	return *ain_position;
} // end of ds_interpret_html::m_handle_double_quote


/**
*
* function ds_interpret_html::m_handle_single_quote
*
* @param[in]     char*  ach_data        data
* @param[in]     int    in_len_data     length of data
* @param[in,out] int*   ain_position    actual position in data
*
* @return        int                    end position = ain_position
*
*/
int ds_interpret_html::m_handle_single_quote( const char* ach_data, int in_len_data, int *ain_position )
{
	assert ( ach_data != NULL && *ain_position < in_len_data && in_len_data > 0 && *ain_position >= 0 );
	if ( ach_data[*ain_position] != '\'' ) {
		// security check
		return *ain_position;
	}
	(*ain_position)++;
	for ( ; *ain_position < in_len_data; (*ain_position)++ ) {
		switch ( ach_data[*ain_position] ) {
		case '\'':
			break;
		case '\\':
			(*ain_position)++;  // don't read next sign
			continue;
		default:
			continue;
		}
		break;
	}
	return *ain_position;
} // end of ds_interpret_html::m_handle_single_quote


/**
*
* function ds_interpret_html::m_handle_round_bracket
*
* @param[in]     char*  ach_data        data
* @param[in]     int    in_len_data     length of data
* @param[in,out] int*   ain_position    actual position in data
*
* @return        int                    end position = ain_position
*
*/
int ds_interpret_html::m_handle_round_bracket( const char* ach_data, int in_len_data, int *ain_position )
{
	assert ( ach_data != NULL && *ain_position < in_len_data && in_len_data > 0 && *ain_position >= 0 );
	if ( ach_data[*ain_position] != '(' ) {
		// security check
		return *ain_position;
	}
	int in_nest_bracket = 0;
	(*ain_position)++;
	for ( ; *ain_position < in_len_data; (*ain_position)++ ) {
		switch ( ach_data[*ain_position] ) {
		case '(':
			in_nest_bracket++;
			continue;
		case ')':
			if ( in_nest_bracket == 0 ) {
				break;
			} else {
				in_nest_bracket--;
				continue;
			}
		case '\'':
			m_handle_single_quote( ach_data, in_len_data, ain_position );
			continue;
		case '"':
			m_handle_double_quote( ach_data, in_len_data, ain_position );
			continue;
		case '{':
			m_handle_curly_bracket( ach_data, in_len_data, ain_position );
			continue;
		case '[':
			m_handle_square_bracket( ach_data, in_len_data, ain_position );
			continue;
		case '\\':
			(*ain_position)++;  // don't read next sign
			continue;
		default:
			continue;
		}
		break;
	}
	return *ain_position;
} // end of ds_interpret_html::m_handle_round_bracket


/**
*
* function ds_interpret_html::m_handle_curly_bracket
*
* @param[in]     char*  ach_data        data
* @param[in]     int    in_len_data     length of data
* @param[in,out] int*   ain_position    actual position in data
*
* @return        int                    end position = ain_position
*
*/
int ds_interpret_html::m_handle_curly_bracket( const char* ach_data, int in_len_data, int *ain_position )
{
	assert ( ach_data != NULL && *ain_position < in_len_data && in_len_data > 0 && *ain_position >= 0 );
	if ( ach_data[*ain_position] != '{' ) {
		// security check
		return *ain_position;
	}
	int in_nest_bracket = 0;
	(*ain_position)++;
	for ( ; *ain_position < in_len_data; (*ain_position)++ ) {
		switch ( ach_data[*ain_position] ) {
		case '{':
			in_nest_bracket++;
			continue;
		case '}':
			if ( in_nest_bracket == 0 ) {
				break;
			} else {
				in_nest_bracket--;
				continue;
			}
		case '\'':
			m_handle_single_quote( ach_data, in_len_data, ain_position );
			continue;
		case '"':
			m_handle_double_quote( ach_data, in_len_data, ain_position );
			continue;
		case '(':
			m_handle_round_bracket( ach_data, in_len_data, ain_position );
			continue;
		case '[':
			m_handle_square_bracket( ach_data, in_len_data, ain_position );
			continue;
		case '\\':
			(*ain_position)++;  // don't read next sign
			continue;
		default:
			continue;
		}
		break;
	}
	return *ain_position;
} // end of ds_interpret_html::m_handle_curly_bracket


/**
*
* function ds_interpret_html::m_handle_square_bracket
*
* @param[in]     char*  ach_data        data
* @param[in]     int    in_len_data     length of data
* @param[in,out] int*   ain_position    actual position in data
*
* @return        int                    end position = ain_position
*
*/
int ds_interpret_html::m_handle_square_bracket( const char* ach_data, int in_len_data, int *ain_position )
{
	assert ( ach_data != NULL && *ain_position < in_len_data && in_len_data > 0 && *ain_position >= 0 );
	if ( ach_data[*ain_position] != '[' ) {
		// security check
		return *ain_position;
	}
	int in_nest_bracket = 0;
	(*ain_position)++;
	for ( ; *ain_position < in_len_data; (*ain_position)++ ) {
		switch ( ach_data[*ain_position] ) {
		case '[':
			in_nest_bracket++;
			continue;
		case ']':
			if ( in_nest_bracket == 0 ) {
				break;
			} else {
				in_nest_bracket--;
				continue;
			}
		case '\'':
			m_handle_single_quote( ach_data, in_len_data, ain_position );
			continue;
		case '"':
			m_handle_double_quote( ach_data, in_len_data, ain_position );
			continue;
		case '{':
			m_handle_curly_bracket( ach_data, in_len_data, ain_position );
			continue;
		case '(':
			m_handle_round_bracket( ach_data, in_len_data, ain_position );
			continue;
		case '\\':
			(*ain_position)++;  // don't read next sign
			continue;
		default:
			continue;
		}
		break;
	}
	return *ain_position;
} // end of ds_interpret_html::m_handle_square_bracket


/**
*
* function ds_interpret_html::m_is_attribute_in_list
*   
* @param[in] char* ach_attr
* @param[in] int   in_len
*
* @return    int                       enum type of attribute, if attribute is in list, 
*                                      -2 if empty, -1 otherwise.
*
*/
int ds_interpret_html::m_is_attribute_in_list( const char* ach_attr, int in_len )
{
	if ( in_len < 1 ) {
		return -2;
	}
	// initialize some variables:
	ds_hstring ds_word( ads_session->ads_wsp_helper );
	// convert attribute to lower case:
	ds_word.m_write_lower( ach_attr, in_len );

	return ads_attr->m_get_htm_attr( ds_word.m_get_ptr(), ds_word.m_get_len() );
} // end of m_is_attribute_in_list


/**
*
* function ds_interpret_html::m_is_tag_in_list
*
* @param[in] char* ach_name            tag name
* @param[in] int   in_len              length of tag name
*
* @return    int                       enum type of tag, if tag is in list, 
*                                      -2 if empty, -1 otherwise.
*
*/
int ds_interpret_html::m_is_tag_in_list( const char* ach_name,  int in_len )
{
	if ( in_len < 1 ) {
		return -2;
	}
	// initialize some variables:
	ds_hstring ds_word( ads_session->ads_wsp_helper );
	// convert attribute to lower case:
	ds_word.m_write_lower( ach_name, in_len );

	return ads_attr->m_get_htm_tag( ds_word.m_get_ptr(), ds_word.m_get_len() );
} // end of m_is_tag_in_list


/**
*
* function ds_interpret_html::m_is_name_value_in_list
*
* @param[in]   char*   ach_value
* @param[in]   int     in_len
*
* @return      int                     enum type of tag, if value is in list, 
*                                      -2 if empty, -1 otherwise.
*
*/
int ds_interpret_html::m_is_name_value_in_list( const dsd_const_string& rdsp_value ) {
	if ( rdsp_value.m_get_len() < 1 ) {
		return -2;
	}
	// initialize some variables:
	ds_hstring ds_word( ads_session->ads_wsp_helper );
	// convert to lower case:
	ds_word.m_write_lower( rdsp_value.m_get_ptr(), rdsp_value.m_get_len() );

	return ads_attr->m_get_htm_val( ds_word.m_get_ptr(), ds_word.m_get_len() );
} // end of ds_interpret_html::m_is_name_value_in_list


/**
*
* function ds_interpret_html::m_is_rel_in_list
*
* @param[in]   char*   ach_value
* @param[in]   int     in_len
*
* @return      int                     enum type of tag, if value is in list, 
*                                      -2 if empty, -1 otherwise.
*
*/
int ds_interpret_html::m_is_rel_in_list( const char* ach_value, int in_len )
{
	if ( in_len < 1 ) {
		return -2;
	}
	// initialize some variables:
	ds_hstring ds_word( ads_session->ads_wsp_helper );
	int    in_count  = 0;

	m_pass_signs( ach_value, in_len, &in_count, "\"'", true );
	if ( in_count > 0 ) {
		in_len -= 2*in_count;
	}

	// convert to lower case:
	ds_word.m_write_lower( &ach_value[in_count], in_len );

	return ads_attr->m_get_htm_rel( ds_word.m_get_ptr(), ds_word.m_get_len() );
} // end of ds_interpret_html::m_is_rel_in_list

/**
*
* function ds_interpret_html::m_insert_HOB_script
*
* @param[in]   bool        bo_insert_head  true = insert <head>
*                                          false = just insert HOB_Script
* @param[in]   ds_hstring*  ads_output     if this pointer is NOT NULL,
*                                          data will be written in this buffer
*                                          instead of being sent to browser
*                                          ( compare m_send_data(...) )
*                                          default value = NULL
*
*/
void ds_interpret_html::m_insert_HOB_script( bool bo_insert_head, ds_hstring* ads_output )
{
	ds_hstring dc_insert(ads_session->ads_wsp_helper);
	// build stuff to insert:
	dsd_const_string dsl_function_name;
	int iml_unique_id = this->imc_uniqueid_counter++;
	ds_hstring hstr_unique_id(ads_session->ads_wsp_helper);
	hstr_unique_id.m_writef("S%d", iml_unique_id);
	if(this->inc_iframe_depth <= 0) {
		dc_insert.m_write("<script id=\"HOBinserted\" type=\"text/javascript\" src=\"" "/protected/wsg/HOBwsg.js" " \"></script>");
		dc_insert.m_writef("<script id=\"HOBinserted\" HOB_uniqueid='%.*s' type=\"text/javascript\">",
			hstr_unique_id.m_get_len(), hstr_unique_id.m_get_ptr() );
		dsl_function_name = "HOB.m_initialize";
	}
	else {
		dc_insert.m_writef( "<script id=\"HOBinserted\" HOB_uniqueid='%.*s' type=\"text/javascript\">",
			hstr_unique_id.m_get_len(), hstr_unique_id.m_get_ptr());
		dc_insert.m_write( "window.top.HOB.m_ensure_hob_context(window);" );
		dsl_function_name = "HOB.m_initialize2";
	}
	dsd_const_string dsl_charset = ds_http_header::m_get_charset_name(this->m_get_charset());
	m_write_hob_initialize(dc_insert, hstr_unique_id.m_const_str(), dsl_function_name, dsl_charset, "");
	dc_insert.m_write( "</script>" );

	m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
} // end of m_insert_HOB_script


/**
*
* function ds_interpret_html::m_insert_HOB_write
*
* @param[in]   ds_hstring*   ads_output     if this pointer is NOT NULL,
*                                          data will be written in this buffer
*                                          instead of being send to browser
*                                          ( compare m_send_data(...) )
*                                          default value = NULL
*
*/
void ds_interpret_html::m_insert_HOB_write( ds_hstring* ads_output )
{
#if !SM_USE_WSG_V2
	const char* ach_send = "<script id=\"HOBinserted\" type=\"text/javascript\">HOB_write();</script>";
	m_send_data( (char*)ach_send, (int)strlen(ach_send), ads_output );
#endif
} // end of m_insert_HOB_write


/**
*
* function ds_interpret_html::m_insert_HOB_nav_init
*
* @param[in]   ds_hstring*   ads_output     if this pointer is NOT NULL,
*                                          data will be written in this buffer
*                                          instead of being send to browser
*                                          ( compare m_send_data(...) )
*                                          default value = NULL
*
*/
void ds_interpret_html::m_insert_HOB_nav_init( ds_hstring* ads_output )
{
	// initialize some variables:
	ds_hstring dc_insert;                // data to insert

	// check if flyer should be inserted:
	if ( ads_session->dsc_auth.m_show_flyer() == false ) {
		return;
	}

	/* hofmants: if WFA, then return	*/
	/* flyer should not be shown		*/
	if( ads_session->dsc_http_hdr_in.dsc_url.hstr_path.m_starts_with( HOBWEBFILEACCESS ) )
	{
		return;
	}

	if(this->inc_iframe_depth > 0)
		return;

	// setup some classes:
	dc_insert.m_setup( ads_session->ads_wsp_helper );
	int iml_unique_id = this->imc_uniqueid_counter++;
	dc_insert.m_writef ( "<script id=\"HOBinserted\" type=\"text/javascript\" HOB_uniqueid='S%d'>", iml_unique_id );
	if(ads_session->ads_config->ach_cluster_url.m_get_len() > 0) // because pointer is not null even if there was no cluster url in config.
	{
		dc_insert.m_writef ( "HOB.m_nav_bookmark('S%d');</script>", iml_unique_id );
	}
	else
	{
		dc_insert.m_writef ( "HOB.m_nav('S%d');</script>", iml_unique_id );
	}

	m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
} // end of ds_interpret_html::m_insert_HOB_nav_init


/**
*
* function ds_interpret_html::m_insert_HOB_login_init
*
* @param[in]   ds_hstring*   ads_output     if this pointer is NOT NULL,
*                                          data will be written in this buffer
*                                          instead of being send to browser
*                                          ( compare m_send_data(...) )
*                                          default value = NULL
*
*/
void ds_interpret_html::m_insert_HOB_login_init( ds_hstring* ads_output ) 
{
	ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
		"HWSGI101I: inserting function call for single-sign-on" );

	// intialize some variables:
	dsd_const_string dc_form_id;             // buffer for form id
	dsd_const_string dc_action_id;           // buffer for action id
	ds_hstring dc_array_list;                // array containing pairs of {id, value}
	ds_hstring dc_insert;                    // buffer for inserting
	ds_hstring dc_value;                     // value form config file
	int in_type_key     = -1;
	class ds_id ds_id_list;

	// setup memory classes:
	dc_value.m_setup     ( ads_session->ads_wsp_helper );
	dc_insert.m_setup    ( ads_session->ads_wsp_helper, 512 );
	dc_array_list.m_setup( ads_session->ads_wsp_helper, 256 );
	dc_array_list.m_write( "[" );

	const ds_hvector<ds_id>& v_arg_list = ads_session->m_get_sso_ids();
	int inl_array_list_count = 0;
	for (HVECTOR_FOREACH(ds_id, adsl_cur, v_arg_list)) {
		const ds_id& ds_id_list = HVECTOR_GET(adsl_cur);
		in_type_key = m_is_type_in_list( (char*)ds_id_list.m_get_type().m_get_ptr(),
			(int)ds_id_list.m_get_type().m_get_len() );
		switch ( in_type_key ) {
		case ds_attributes::ied_htm_sso_form:
			dc_form_id = ds_id_list.m_get_name().m_const_str();
			break;
		case ds_attributes::ied_htm_sso_action:
			dc_action_id = ds_id_list.m_get_name().m_const_str();
			break;
		case ds_attributes::ied_htm_sso_input: {
			dc_value.m_set( ds_id_list.m_get_value() );
			// we must replace SSO_USERNAME and SSO_PASSWORD in value:
			dc_value.m_replace( SSO_USERNAME, ads_session->dsc_auth.m_get_username().m_const_str() );
			dc_value.m_replace( SSO_PASSWORD, ads_session->dsc_auth.m_get_password().m_const_str() );

			if ( inl_array_list_count > 0 ) {
				dc_array_list.m_write( "," );
			}
			const ds_hstring& rdsl_name = ds_id_list.m_get_name();
			dc_array_list.m_write( "['" );
			dc_array_list.m_write( rdsl_name );
			dc_array_list.m_write( "','" );
			dc_array_list.m_write( dc_value );
			dc_array_list.m_write( "']" );
			inl_array_list_count++;
			break;
															}
		default:
			ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning,
				"HWSGW106W: unknown single-sign-on type found - ignored" );
			break;
		}
	}
	dc_array_list.m_write( "]" );

	// set login script:
	dc_insert.m_write( "<script id=\"HOBinserted\" type=\"text/javascript\">" );
	dc_insert.m_write( "HOB.m_sso_login('" );
	dc_insert.m_write( dc_form_id );
	dc_insert.m_write( "','");
	dc_insert.m_write( dc_action_id );
	dc_insert.m_write( "'," );
	dc_insert.m_write( dc_array_list );
	dc_insert.m_write( ");</script>" );
	m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
} // end of ds_interpret_html::m_insert_HOB_login_init


/**
*
* function ds_interpret_html::m_insert_favicon
*
* @param[in]   ds_hstring*   ads_output     if this pointer is NOT NULL,
*                                          data will be written in this buffer
*                                          instead of being send to browser
*                                          ( compare m_send_data(...) )
*                                          default value = NULL
*
*/
void ds_interpret_html::m_insert_favicon( ds_hstring* ads_output )
{
	if ((ads_session->ads_config->in_settings & SETTING_DONT_INSERT_FAVICON) == 0) { // MJ 14.08.09 Ticket[18274]
		// initialize some variables:
		ds_hstring dc_insert;                    // buffer for inserting
		dc_insert.m_setup( ads_session->ads_wsp_helper );
		dsd_const_string ds_ext_address = ads_session->dsc_ws_gate.hstr_prot_authority_ext_ws.m_const_str();
		dc_insert.m_writef( "<link rel=\"shortcut icon\" type=\"image/x-icon\" href=\"/wsg/%.*s/favicon.ico\" />",
			ds_ext_address.m_get_len(), ds_ext_address.m_get_ptr() );
		m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
	}
} // end of ds_interpret_html::m_insert_favicon


/**
* private method ds_interpret_html::m_insert_ica_decl
*  insert declarations which are needed for wsp_passthrough
*
* @param[in]   ds_hstring  *adsp_output    if this pointer is NOT NULL,
*                                          data will be written in this buffer
*                                          instead of being send to browser
*                                          ( compare m_send_data(...) )
*/
void ds_interpret_html::m_insert_ica_decl( ds_hstring* adsp_output )
{
#define DEF_ICA_DECL "<script type=\"text/javascript\" src=\"/public/js/slide.js\"></script>\
<link rel=\"stylesheet\" href=\"/public/css/slide.css\"/>\
<script type=\"text/javascript\" src=\"/protected/wsg/wsp-passthrough.js\"></script>"

	m_send_data( DEF_ICA_DECL, (int)sizeof(DEF_ICA_DECL) - 1, adsp_output );

#undef DEF_ICA_DECL
} /* end of ds_interpret_html::m_inset_ica_decl */


/**
* private method ds_interpret_html::m_insert_ica_decl
*  insert call to activate wsp_passthrough
*
* @param[in]   ds_hstring  *adsp_output    if this pointer is NOT NULL,
*                                          data will be written in this buffer
*                                          instead of being send to browser
*                                          ( compare m_send_data(...) )
*/
void ds_interpret_html::m_insert_ica_call( ds_hstring* adsp_output )
{
#define DEF_ICA_CALL "<iframe id=\"wsp-passthrough\" style=\"display: none\"></iframe>\
<script type=\"text/javascript\">m_show_overlay();</script>"

	m_send_data( DEF_ICA_CALL, (int)sizeof(DEF_ICA_CALL) - 1, adsp_output );

#undef DEF_ICA_CALL
} /* end if ds_interpret_html::m_insert_ica_call */


/**
*
* function ds_interpret_html::m_is_type_in_list
*
* @param[in]   ach_type
* @param[in]   in_len
*
* @return      word_key
*
*/
int ds_interpret_html::m_is_type_in_list( const char* ach_type,  int in_len ) 
{
	if ( ach_type == NULL || in_len < 1 ) {
		return -2;
	}    
	// initialize some variables:
	ds_hstring ds_word( ads_session->ads_wsp_helper );
	// convert attribute to lower case:
	ds_word.m_write_lower( ach_type, in_len );

	return ads_attr->m_get_htm_sso( ds_word.m_get_ptr(), ds_word.m_get_len() );
} // end of ds_interpret_html::m_is_type_in_list

void ds_interpret_html::m_init() {
	in_state             = HTML_NORMAL;
	in_get_tag_state     = HTML_GET_TAG;
	bo_icon_found        = false;
	bo_head_found        = false;
	bo_hobscript_added   = false;
	bo_change_data       = true;
	bo_in_comments       = false;
	bo_back_slash_ending = false;
	boc_xua_compatible_found = false;
	inc_iframe_depth      = 0;
#if 0
	ach_start_comment    = NULL;
#endif
	ch_last_sign         = 0;
	boc_insert_ica_call  = false;
	iec_page_charset     = ied_chs_invalid;
	iec_meta_charset     = ied_chs_invalid;
	imc_uniqueid_counter = 0;
	inc_head_depth       = 0;
	inc_body_depth       = 0;

	this->iec_doctype    = iec_html_doctype_not_set;

	this->bo_change_data = true;
	this->iec_unescape_state = iec_unescape_html_default;
	this->boc_is_ica_srv = false;

	this->boc_is_xhtml = false; 
	this->boc_is_cdata = false;
}

/**
* @ingroup dataprocessor
*
* @param[in]   ads_session_in		A pointer to the ds_session class
* @param[in]   ach_address_wsp_in	A const char pointer
* @param[in]   ach_address_ext_in	A const char pointer
* @param[in]   ach_path_ext_in		A const char pointer
*
* @return      bool    
*/
bool ds_interpret_html::m_setup( ds_session* ads_session_in )
{
	this->ds_tag.m_setup( ads_session_in->ads_wsp_helper, HTML_MEMORY_SIZE);
	this->dsc_unescape_tag.m_setup( ads_session_in->ads_wsp_helper, 32);

	// just for secure, set default state!
	ads_session_in->dsc_ws_gate.dsc_interpret_script.m_setup(ads_session_in);
	ads_session_in->dsc_ws_gate.dsc_interpret_css.m_setup(ads_session_in);
	ads_session_in->dsc_ws_gate.dsc_interpret_pass.m_setup(ads_session_in);
	return ds_interpret::m_setup( ads_session_in );
} // end of ds_interpret_html::m_setup

void ds_interpret_html::m_set_ica( bool bop_is_ica ) {
	boc_is_ica_srv = bop_is_ica;
}

void ds_interpret_html::m_set_content_type( ds_http_header::content_types iep_content_type )
{
	this->boc_is_xhtml = (iep_content_type == ds_http_header::ien_ct_application_xhtml); 
}

void ds_interpret_html::m_set_charset( ied_charset iep_charset )
{
	//if(iep_charset == ied_chs_invalid)
	//	return;
	this->iec_page_charset = iep_charset;
	//this->iec_meta_charset = iep_charset; 
}

ied_charset ds_interpret_html::m_get_charset() {
	// https://wiki.selfhtml.org/wiki/HTML/Kopfdaten/meta
	// Grundsätzlich gibt es drei Möglichkeiten zur Festlegung der Zeichencodierung:
	// 1. das BOM,
	// 2. eine Kodierungs-Angabe im HTTP-Header der Datei (im Webserver oder einem Skript festgelegt),
	// 3. eine Meta-Angabe charset wie im folgenden Beispiel.
	// Beachten Sie: Eine Angabe zur Zeichencodierung durch ein BOM hat Vorrang vor einer Angabe im HTTP-Header und diese wiederum hat Vorrang vor der Meta-Angabe.
	// Eine zusätzliche Meta-Angabe ist in solchen Fällen wirkungslos, aber als Zusatz-Information hilfreich.

	if(this->iec_page_charset != ied_chs_invalid)
		return this->iec_page_charset;
	if(this->iec_meta_charset != ied_chs_invalid)
		return this->iec_meta_charset;
	return ied_chs_wcp_1252;
}

void ds_interpret_html::m_set_iframe_depth( int inp_iframe_depth )
{
	this->inc_iframe_depth = inp_iframe_depth; 
}

/**
* @ingroup dataprocessor
*/
void ds_interpret_html::m_not_change_data() {
	bo_change_data = false;
} // end of ds_interpret_html::m_not_change_data()


