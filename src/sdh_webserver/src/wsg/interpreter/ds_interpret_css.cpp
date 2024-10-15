/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "../../ds_session.h"
#include "ds_interpret_css.h"

/*+-------------------------------------------------------------------------+*/
/*| constructor:                                                            |*/
/*+-------------------------------------------------------------------------+*/

/**
* A rewrite seems to be necessary: https://www.w3.org/TR/css-syntax/
*/

/**
* @ingroup dataprocessor
*/
ds_interpret_css::ds_interpret_css(void) : ds_interpret()
{
	ch_symbol = ' ';
	ch_in_string = 0;
	iec_word_function1 = iec_word_function_invalid;
	iec_word_function2 = iec_word_function_invalid;
} //end of ds_interpret_css::ds_interpret_css


/*+-------------------------------------------------------------------------+*/
/*| destructor:                                                             |*/
/*+-------------------------------------------------------------------------+*/

/**
* @ingroup dataprocessor
*/
ds_interpret_css::~ds_interpret_css(void)
{
} //end of ds_interpret_css::~ds_interpret_css


/*+-------------------------------------------------------------------------+*/
/*| functions:                                                              |*/
/*+-------------------------------------------------------------------------+*/

/**
* @ingroup dataprocessor
*
* @return      1 if data was sent, 0 otherwise                   
* 
*/
int ds_interpret_css::m_process_data()
{
	// initialize some variables:
	const char* ach_data;
	int   in_len_data      = 0;
	int   in_data_complete = 0;
	int   in_sum_written   = 0;

	while ( in_data_complete == 0 && in_len_data > -1 ) {
		// reset ach_data, in_len_data
		ach_data    = NULL;
		in_len_data = -1;
		// get data:
		in_data_complete = ads_session->dsc_transaction.m_get_data( &ach_data, &in_len_data );
		if(in_data_complete < 0)
			return in_data_complete;
		ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
			"css-interpreter: m_get_data() returned %d.",
			in_len_data );
		if(in_len_data <= 0) {
            if(in_data_complete == 0)
                break;
            int in_data_written = m_parse_data( NULL, 0, true );
            if(in_data_written < 0)
                return -1;
            in_sum_written += in_data_written;
            break;
       }
#if SM_INTERPRET_PUSH_SINGLE
        for(int i=0;i<(in_len_data); i++) {
            int in_data_written = m_parse_data( &ach_data[i], 1, false );
            if(in_data_written < 0)
                return -1;
            in_sum_written += in_data_written;
        }
#else
			// parse data:
			int in_data_written = m_parse_data( ach_data, in_len_data, false );
			if(in_data_written < 0)
				return -1;
			in_sum_written += in_data_written;
#endif
		  if(in_data_complete > 0) {
			  int in_data_written = m_parse_data( &ach_data[in_len_data], 0, true );
			  if(in_data_written < 0)
					return -1;
			  in_sum_written += in_data_written;
		  }
	}  
	return (in_sum_written > 0);
} // end of ds_interpret_css::m_process_data

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


static dsd_const_string m_unescape_url(const dsd_const_string& rdsp_value, ds_hstring& rdsp_dst, char& rchp_quote) {
	dsd_const_string rdsp_src = m_unquote(rdsp_value, rchp_quote);
	rdsp_dst.m_reset();
	int inl_src_len = rdsp_src.m_get_len();
	int inl_src_off = 0;
	int inl_src_last = 0;
	// TODO:
#if 0
	while(inl_src_off < inl_src_len) {
		char chl_value = rdsp_src[inl_src_off];
		dsd_const_string dsl_escape;
		switch(chl_value) {
		case '\\':
			break;
		default:
			goto LBL_NEXT;
		}
		inl_src_off++;
		if(inl_src_off >= inl_src_len) {
			break;
		}
		chl_value = rdsp_src[inl_src_off];
		switch(chl_value) {
		case 'u':
			break;
		case 'n':
			dsl_escape = "\n";
			break;
		case 'r':
			dsl_escape = "\r";
			break;
		case 'f':
			dsl_escape = "\f";
			break;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
			break;
		}
		if(!rdsp_dst.m_ensure_size(inl_src_len, true))
			return dsd_const_string::m_null();
		rdsp_dst.m_write(rdsp_src.m_get_ptr()+inl_src_last, inl_src_off-inl_src_last);
		rdsp_dst.m_write(dsl_escape);
		inl_src_last = inl_src_off + 1;
LBL_NEXT:
		inl_src_off++;
	}
#endif
	if(inl_src_last == 0)
		return rdsp_src;
	rdsp_dst.m_write(rdsp_src.m_get_ptr()+inl_src_last, inl_src_off-inl_src_last);
	return rdsp_dst.m_const_str();
}

static dsd_const_string m_escape_url(const dsd_const_string& rdsp_src, ds_hstring& rdsp_dst, const char& rchp_quote) {
	rdsp_dst.m_reset();
	int inl_src_len = rdsp_src.m_get_len();
	int inl_src_off = 0;
	int inl_src_last = 0;
#if 0
	while(inl_src_off < inl_src_len) {
		char chl_value = rdsp_src[inl_src_off];
LBL_NEXT:
		inl_src_off++;
	}
#endif
	if(inl_src_last == 0)
		return rdsp_src;
	rdsp_dst.m_write(rdsp_src.m_get_ptr()+inl_src_last, inl_src_off-inl_src_last);
	return rdsp_dst.m_const_str();
}

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
int ds_interpret_css::m_parse_data( const char* ach_data, int in_len_data,
											  bool bo_data_complete, ds_hstring* ads_output )
{
	int in_ret = 0;     // signal for transaction class

	ds_word.m_init( ads_session->ads_wsp_helper );
	ds_argument.m_init( ads_session->ads_wsp_helper );

	if ( (ach_data == NULL) || (in_len_data == -1) ) {
		if ( bo_data_complete ) {
			// case of data sent by webserver without length information! 
			// send all data, that was saved in current session, free memory, quit.
			if ( ds_word.m_get_len() > 0 ) {
				m_send_data( ds_word.m_get_ptr(), ds_word.m_get_len(), ads_output );
				ds_word.m_reset();
				ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning,
					"HWSGW301W: probably error in css-data, last word cut off" );
			}
			if ( ds_argument.m_get_len() > 0 ) {
				m_send_data( ds_argument.m_get_ptr(), ds_argument.m_get_len(), ads_output );
				ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning,
					"HWSGW302W: probably error in css-data, last argument cut off" );
			}
		}
		// no data available
		return in_ret;
	}

	// initialze some variables:
	int    in_position       = 0;         // actual position in data
	int    in_added_signs    = 0;         // count added signs in m_change_url
	int    in_word_return    = 0;         // return of m_get_next_word
	int    in_word_start_pos = 0;         // start position of current word
	int    in_arg_return     = 0;         // state of m_get_argument
	int    in_arg_start_pos  = 0;         // start position of current argument
	int    in_len_word       = 0;         // length of actual word
	const char*  ach_word    = NULL;      // pointer to found word

	ds_hstring dsl_temp1(this->ads_session->ads_wsp_helper);
	ds_hstring dsl_temp2(this->ads_session->ads_wsp_helper);

	while ( in_position < in_len_data ) {
		switch ( in_state ) {

		case CSS_NORMAL: {
			in_word_return = m_get_next_word( ach_data, in_len_data, &in_position, &ach_word, &in_len_word, &in_word_start_pos );
			switch ( in_word_return ) {
			case CSS_NO_WORD:
				m_send_data( ach_data, in_len_data, ads_output ); // send whole data and return
				return in_ret;
			case CSS_WORD_PARTIAL:
				if ( in_len_word <= 0 || in_len_word > 7 || bo_data_complete ) {
					// if length > 7, the word can't be interesting for us!
					m_send_data( ach_data, in_len_data, ads_output ); // send whole data
				} else {
					m_send_data( ach_data, in_word_start_pos, ads_output ); // send data until word start
					ds_word.m_write( ach_word, in_len_word ); // save partial word
					in_state = CSS_WORD_CUT;
				}
				return in_ret;
			case CSS_WORD_COMPLETE:
				break;
			}
			ied_word_function in_word_number = m_is_word_in_list( ach_word, in_len_word );
			if ( in_word_number == iec_word_function_invalid ) {
				continue; // -> get next word
			}
			this->iec_word_function2 = this->iec_word_function1;
			this->iec_word_function1 = in_word_number;
			in_arg_return = m_get_argument( ach_data, in_len_data, &in_position, &in_arg_start_pos, false );
			switch ( in_arg_return ) {
			case CSS_NO_ARG:
				m_send_data( ach_data, in_len_data, ads_output ); // send whole data and return
				in_state = CSS_ARGUMENT_CUT;
				return in_ret;
			case CSS_ARG_PARTIAL:
				m_send_data( ach_data, in_arg_start_pos, ads_output ); // send data until argument start and return
				in_state = CSS_ARGUMENT_CUT;
				return in_ret;
			case CSS_ARG_COMPLETE:
				break;
			}
			// normally css arguments look like ("http://hob.de")
			dsd_const_string dsl_uncut = this->ds_argument.m_const_str();
			dsd_const_string dsl_cut = dsl_uncut;
			m_remove_signs(dsl_cut);

			// check if our argument start with "url" (case of @import url(...) )
			if ( m_arg_starts_with_url(dsl_cut) ) {
				in_position = in_arg_start_pos;
				continue; // -> get next word (should be url)
			}

			char chl_quote;
			dsd_const_string dsl_word2 = m_unescape_url(dsl_cut, dsl_temp1, chl_quote);
			if(chl_quote == 0)
				chl_quote = '\'';

			dsd_const_string dsl_hob_type = HOB_TYPE "any";
			if(this->iec_word_function2 == iec_word_function_import)
				dsl_hob_type = HOB_TYPE "css";
			in_added_signs = m_change_url_ex(dsl_word2, ds_interpret::ied_change_url_flags_default, dsl_hob_type, ds_word);
			if ( in_added_signs == ied_change_url_changed ) {
				m_send_data( ach_data, in_arg_start_pos, ads_output ); // send data until argument start
				m_send_data( dsl_uncut.m_get_start(), dsl_cut.m_get_start()-dsl_uncut.m_get_start(), ads_output );
				dsd_const_string dsl_word3 = m_escape_url(ds_word.m_const_str(), dsl_temp2, chl_quote);
				m_send_data( &chl_quote, 1, ads_output );
				m_send_data( dsl_word3.m_get_ptr(), dsl_word3.m_get_len(), ads_output ); // send changed argument
				m_send_data( &chl_quote, 1, ads_output );
				m_send_data( dsl_cut.m_get_end(), dsl_uncut.m_get_end()-dsl_cut.m_get_end(), ads_output );
				m_move_char_pointer( &ach_data, &in_len_data, &in_position );
				ds_word.m_reset();
			}
			ds_argument.m_reset();
			in_state = CSS_NORMAL;
			break;
							  }
		case CSS_WORD_CUT: {
			in_word_return = m_get_next_word( ach_data, in_len_data, &in_position, &ach_word, &in_len_word, &in_word_start_pos, true );
			switch ( in_word_return ) {
			case CSS_NO_WORD:
				//SM??? m_send_data( ach_data, in_len_data, ads_output ); // send whole data and return
				break;
			case CSS_WORD_PARTIAL:
				if ( ds_word.m_get_len() + in_len_word > 7 || bo_data_complete ) {
					// if length > 7, the word can't be interesting for us!
					m_send_data( ds_word.m_get_ptr(), ds_word.m_get_len(), ads_output ); // send saved word
					m_send_data( ach_data, in_len_data, ads_output ); // send whole data
					ds_word.m_reset();
					in_state = CSS_NORMAL;
				} else {
					ds_word.m_write( ach_word, in_len_word );
				}
				return in_ret;
			case CSS_WORD_COMPLETE:
				if ( ds_word.m_get_len() + in_len_word > 7 || bo_data_complete ) {
					// if length > 7, the word can't be interesting for us!
					m_send_data( ds_word.m_get_ptr(), ds_word.m_get_len(), ads_output ); // send saved word
					m_send_data( ach_data, in_position, ads_output ); // send data until end of word
					m_move_char_pointer( &ach_data, &in_len_data, &in_position );
					ds_word.m_reset();
					in_state = CSS_NORMAL;
					continue;
				} else {
					ds_word.m_write( ach_word, in_len_word );
				}
				break;
			}
			m_send_data( ds_word.m_get_ptr(), ds_word.m_get_len(), ads_output ); // send saved word
			m_move_char_pointer ( &ach_data, &in_len_data, &in_position );
			ied_word_function in_word_number = m_is_word_in_list( ds_word.m_get_ptr(), ds_word.m_get_len() );
			ds_word.m_reset();
			if ( in_word_number == iec_word_function_invalid ) {
				in_state = CSS_NORMAL;
				continue; // -> get next word
			}
			this->iec_word_function2 = this->iec_word_function1;
			this->iec_word_function1 = in_word_number;
			in_arg_return = m_get_argument( ach_data, in_len_data, &in_position, &in_arg_start_pos, false );
			switch ( in_arg_return ) {
			case CSS_NO_ARG:
				m_send_data( ach_data, in_len_data, ads_output ); // send whole data and return
				in_state = CSS_ARGUMENT_CUT;
				ch_symbol = 0;
				return in_ret;
			case CSS_ARG_PARTIAL:
				m_send_data( ach_data, in_arg_start_pos, ads_output ); // send data until argument start
				in_state = CSS_ARGUMENT_CUT;
				return in_ret;
			case CSS_ARG_COMPLETE:
				break;
			}
			// normally css arguments look like ("http://hob.de")
			dsd_const_string dsl_uncut = this->ds_argument.m_const_str();
			dsd_const_string dsl_cut = dsl_uncut;
			m_remove_signs(dsl_cut);

			// check if our argument start with "url" (case of @import url(...) )
			if ( m_arg_starts_with_url(dsl_cut) ) {
				in_position = in_arg_start_pos;
				in_state = CSS_NORMAL;
				continue; // -> get next word
			}


			char chl_quote;
			dsd_const_string dsl_word2 = m_unescape_url(dsl_cut, dsl_temp1, chl_quote);
			if(chl_quote == 0)
				chl_quote = '\'';

			dsd_const_string dsl_hob_type = HOB_TYPE "any";
			if(this->iec_word_function2 == iec_word_function_import)
				dsl_hob_type = HOB_TYPE "css";
			in_added_signs = m_change_url_ex(dsl_word2, ds_interpret::ied_change_url_flags_default, dsl_hob_type, ds_word);
			if ( in_added_signs == ied_change_url_changed ) {
				m_send_data( ach_data, in_arg_start_pos, ads_output ); // send data until argument start
				m_send_data( dsl_uncut.m_get_start(), dsl_cut.m_get_start()-dsl_uncut.m_get_start(), ads_output );
				dsd_const_string dsl_word3 = m_escape_url(ds_word.m_const_str(), dsl_temp2, chl_quote);
				m_send_data( &chl_quote, 1, ads_output );
				m_send_data( dsl_word3.m_get_ptr(), dsl_word3.m_get_len(), ads_output ); // send changed argument
				m_send_data( &chl_quote, 1, ads_output );
				m_send_data( dsl_cut.m_get_end(), dsl_uncut.m_get_end()-dsl_cut.m_get_end(), ads_output );
				m_move_char_pointer( &ach_data, &in_len_data, &in_position );
				ds_word.m_reset();
			}
			ds_argument.m_reset();
			in_state = CSS_NORMAL;
			break;
								 }
		case CSS_ARGUMENT_CUT: {
			in_arg_return = m_get_argument( ach_data, in_len_data, &in_position, &in_arg_start_pos, ch_symbol != 0 );
			switch ( in_arg_return ) {
			case CSS_NO_ARG:
				if(this->ds_argument.m_get_len() > 0) {
					this->ds_argument.m_write(ach_data, in_len_data);
					return in_ret;
				}
				m_send_data( ach_data, in_len_data, ads_output ); // send whole data and return
				return in_ret;
			case CSS_ARG_PARTIAL:
				return in_ret;
			case CSS_ARG_COMPLETE:
				break;
			}
			// normally css arguments look like ("http://hob.de")
			dsd_const_string dsl_uncut = this->ds_argument.m_const_str();
			dsd_const_string dsl_cut = dsl_uncut;
			m_remove_signs(dsl_cut);

			m_send_data( ach_data, in_arg_start_pos, ads_output ); // send data until argument start
			// check if our argument start with "url" (case of @import url(...) )
			dsd_const_string hstrl_url = dsl_cut;
			if ( m_arg_starts_with_url(dsl_cut) ) {
				dsl_cut = dsl_cut.m_substring(4);
				m_remove_signs(dsl_cut);
				hstrl_url = dsl_cut;
				this->iec_word_function2 = this->iec_word_function1;
				this->iec_word_function1 = iec_word_function_url;
#if 0
				m_send_data( dsl_uncut.m_get_start(), dsl_cut.m_get_start()-dsl_uncut.m_get_start(), ads_output );
				//ds_argument.m_erase( 0, 4 );
				dsd_const_string hstrl_url = dsl_cut;
				if(m_change_url_ex(hstrl_url, ds_interpret::ied_change_url_flags_default, ds_word) == ied_change_url_changed)
					hstrl_url = ds_word.m_const_str();
				m_send_data( hstrl_url.m_get_ptr(), hstrl_url.m_get_len(), ads_output ); // send saved/changed argument
				m_send_data( dsl_cut.m_get_end(), dsl_uncut.m_get_end()-dsl_cut.m_get_end(), ads_output );
				m_move_char_pointer( &ach_data, &in_len_data, &in_position );
				ds_word.m_reset();
				ds_argument.m_reset();
				in_state = CSS_NORMAL;
				continue; // -> get next word
#endif
			}
			m_send_data( dsl_uncut.m_get_start(), dsl_cut.m_get_start()-dsl_uncut.m_get_start(), ads_output );

			char chl_quote;
			dsd_const_string dsl_word2 = m_unescape_url(dsl_cut, dsl_temp1, chl_quote);
			if(chl_quote == 0)
				chl_quote = '\'';

			dsd_const_string dsl_hob_type = HOB_TYPE "any";
			if(this->iec_word_function2 == iec_word_function_import)
				dsl_hob_type = HOB_TYPE "css";
			in_added_signs = m_change_url_ex(dsl_word2, ds_interpret::ied_change_url_flags_default, dsl_hob_type, ds_word);
			if(in_added_signs == ied_change_url_changed)
				hstrl_url = ds_word.m_const_str();
			dsd_const_string dsl_word3 = m_escape_url(hstrl_url, dsl_temp2, chl_quote);
			m_send_data( &chl_quote, 1, ads_output );
			m_send_data( dsl_word3.m_get_ptr(), dsl_word3.m_get_len(), ads_output ); // send saved/changed argument
			m_send_data( &chl_quote, 1, ads_output );
			m_send_data( dsl_cut.m_get_end(), dsl_uncut.m_get_end()-dsl_cut.m_get_end(), ads_output );
			m_move_char_pointer( &ach_data, &in_len_data, &in_position );
			ds_argument.m_reset();
			ds_word.m_reset();
			in_state = CSS_NORMAL;
			break;
		}
		default:
			ads_session->ads_wsp_helper->m_log( ied_sdh_log_error,
				"HWSGE301E: invalid state in ds_interpret_css::m_parse_data" );
			in_state = CSS_NORMAL;
			break;

		} // end of switch
	} // end of while
	if ( in_state == CSS_NORMAL ) {
		// send rest of data:
		m_send_data( ach_data, in_len_data, ads_output );
	} else if ( bo_data_complete ) {
		if ( ds_word.m_get_len() > 0 ) {
			m_send_data( ds_word.m_get_ptr(), ds_word.m_get_len(), ads_output );
			ds_word.m_reset();
		}
		// send rest of data:
		m_send_data( ach_data, in_len_data, ads_output );
	}
	return in_ret;
} // end of ds_interpret_css::m_parse_data


/**
*
* function ds_interpret_css::m_arg_starts_with_url
*
* check for an argument like @import url(...)
*
*
* @return        bool          true = url occures at beginning of argument
*                              false otherwise
*
*/
bool ds_interpret_css::m_arg_starts_with_url(const dsd_const_string& rdsp_argument)
{
	// initialize some variables:
	bool   bo_return      = false;
	int    in_len_arg     = rdsp_argument.m_get_len();
	int    in_position    = 0;
	int    in_start_pos   = 0;

	m_pass_signs( rdsp_argument.m_get_ptr(), in_len_arg, &in_start_pos, " \n\r\t\v\f" );
	for ( in_position = in_start_pos; in_position < in_len_arg; in_position++ ) {
		switch ( rdsp_argument[in_position] ) {
		case '\f':
		case '\n':
		case '\r':
		case '\t':
		case '\v':
		case ' ':
		case '(':
			break;
		default:
			continue;
		}
		break;
	}
	if ( in_position - in_start_pos > 3 ) {
		return bo_return;
	}
	if ( m_is_word_in_list( &rdsp_argument[in_start_pos], in_position - in_start_pos ) == iec_word_function_url ) {
		// first word in argument is "url"! -> check for bracket:
		m_pass_signs( rdsp_argument.m_get_ptr(), in_len_arg, &in_position, " \n\r\t\v\f" );
		if ( rdsp_argument[in_position] == '(' ) {
			bo_return = true;
		}
	}
	return bo_return;
} // end of ds_interpret_css::m_arg_starts_with_url


/**
*
* ds_interpret_css::m_get_next_word
*
* @param[in]     char*    ach_data              actual data
* @param[in]     int      in_len_data           length of data
* @param[in,out] int*     ain_position          actual position in data
* @param[out]    char**   aach_word             pointer to found word (or parts of it)
* @param[out]    int*     ain_len_word          length of found word
* @param[out]    int*     ain_word_start        start position of word in data
* @param[in]     bool     bo_get_cut_word       true = get cut word
*                                               default value = false
*
* @return        int                            key:
*                                                CSS_NO_WORD       = no word found
*                                                CSS_WORD_PARTIAL  = word found partial
*                                                CSS_WORD_COMPLETE = word found complete
*
*/
int ds_interpret_css::m_get_next_word( const char* ach_data, int in_len_data, int* ain_position,
												  const char** aach_word, int* ain_len_word, int* ain_word_start, bool bo_get_cut_word )
{
	assert ( ach_data != NULL && in_len_data > 0 );
	// initialize some variables:
	int in_return     = CSS_NO_WORD;
	*ain_word_start   = 0;

	if ( !bo_get_cut_word ) {
		m_pass_signs( ach_data, in_len_data, ain_position, " \n\r\t\v\f" );
	}
	if ( *ain_position >= in_len_data ) {
		return in_return;
	}

	if ( !bo_get_cut_word ) {
		switch ( ach_data[*ain_position] ) {
		case '(':
		case '\'':
		case '\"':
		case ',':
		case ';':
		case ':':
		case '}':
			(*ain_position)++;
		}
	}

	*aach_word = ach_data + *ain_position;
	*ain_word_start = *ain_position;

	for ( ; *ain_position < in_len_data; (*ain_position)++ ) {
		switch ( ach_data[*ain_position] ) {
		case '\f':
		case '\n':
		case '\r':
		case '\t':
		case '\v':
		case '(':
		case '\'':
		case '"':
		case ' ':
		case ',':
		case ';':
		case ':':
		case '}':
			break;
		default:                
			continue;
		}
		break;
	}

	if ( *ain_position >= in_len_data ) {
		*ain_position = in_len_data;
		in_return    = CSS_WORD_PARTIAL;
	} else {
		in_return = CSS_WORD_COMPLETE;
	}
	*ain_len_word = *ain_position - *ain_word_start;
	return in_return;
} // end of ds_interpret_css::m_get_next_word

#if 0
ds_interpret_css::ied_char_result ds_interpret_css::m_get_next_char(struct dsd_string_data& rdsp_data, char& rchp_next) 
{
LBL_AGAIN:
	switch(this->iec_word_state) {
	case ied_ws_start:
		if(!rdsp_data.m_has_more())
			return iec_no_more_data;
		rchp_next = rdsp_data.m_next();
		switch(rchp_next) {
		case '/':
			this->dsc_comment.m_reset();
			this->dsc_comment.m_write(&rchp_next, 1);
			this->iec_word_state = ied_ws_comment1;
			goto LBL_AGAIN;
		}
		return iec_char_found;
	case ied_ws_comment1:
		if(!rdsp_data.m_has_more())
			return iec_pending;
		rchp_next = rdsp_data.m_peek();
		switch(rchp_next) {
		case '*':
			rchp_next = rdsp_data.m_next();
			this->dsc_comment.m_write(&rchp_next, 1);
			this->iec_word_state = ied_ws_comment2;
			return iec_comment_start;
		default:
			this->iec_word_state = ied_ws_no_comment;
			goto LBL_AGAIN;
		}
		break;
	case ied_ws_comment2:
		if(!rdsp_data.m_has_more())
			return iec_no_more_data;
		rchp_next = rdsp_data.m_next();
		switch(rchp_next) {
		case '*':
			this->dsc_comment.m_reset();
			this->dsc_comment.m_write(&rchp_next, 1);
			this->iec_word_state = ied_ws_comment3;
			goto LBL_AGAIN;
		default:
			return iec_commented_char;
		}
		break;
	case ied_ws_comment3:
		if(!rdsp_data.m_has_more())
			return iec_pending;
		rchp_next = rdsp_data.m_next();
		this->dsc_comment.m_write(&rchp_next, 1);
		switch(rchp_next) {
		case '/':
			this->iec_word_state = ied_ws_start;
			return iec_comment_end;
		default:
			this->iec_word_state = ied_ws_no_comment;
			goto LBL_AGAIN;
		}
		break;
	case ied_ws_no_comment: {
		class ds_hstring dsc_comment2 = this->dsc_comment;
		struct dsd_string_data dsl_data;
		dsl_data.achc_data = dsc_comment2.m_get_ptr();
		dsl_data.inc_len_data = dsc_comment2.m_get_len();
		dsl_data.inc_position = 0;
		ied_char_result iel_result = this->m_get_next_char(dsl_data, rchp_next);
		switch(iel_result) {
		case iec_pending:
		case iec_no_more_data:
			this->iec_word_state = ied_ws_start;
			break;
		default:
			break;
		}
		return iel_result;
									}
	default:
		return iec_error;
	}
}
#endif

/**
*
* ds_interpret_css::m_get_argument
*
* @param[in]       char*     ach_data          actual data
* @param[in]       int       in_len_data       length of data
* @param[in,out]   int*      ain_position      actual position in data
* @param[out]      int*      ain_arg_start     start position of argument
* @param[in]       bool      bo_get_cut_arg    true = search for cut argument
*                                              default value = false
*
* @return          int                         key:
*                                                CSS_NO_ARG       = no argument found
*                                                CSS_ARG_PARTIAL  = argument found partial
*                                                CSS_ARG_COMPLETE = argument found complete
*
*/
#if 0
int ds_interpret_css::m_get_argument( const char* ach_data, int in_len_data, int *ain_position,
												 int *ain_arg_start, bool bo_get_cut_arg )
{
	assert ( ach_data != NULL && in_len_data > 0 );
	// initialize some variables:
	int in_return      = CSS_NO_ARG;
	*ain_arg_start = 0;

	m_pass_signs( ach_data, in_len_data, ain_position, " \n\r\t\v\f" );
	if ( *ain_position >= in_len_data ) {
		return in_return;
	}
	dsd_string_data dsl_data;
	dsl_data.achc_data = ach_data;
	dsl_data.inc_len_data = in_len_data;
	dsl_data.inc_position = *ain_position;
	char chl_cur;

	if ( !bo_get_cut_arg ) {
		ds_argument.m_reset();
LBL_AGAIN:
		ied_char_result iel_result = m_get_next_char(dsl_data, chl_cur);
		switch(iel_result) {
		case iec_error:
			return -1;
		case iec_no_more_data:
			return CSS_NO_ARG;
		case iec_pending:
			return CSS_ARG_PARTIAL;
		case iec_comment_start:
		case iec_commented_char:
		case iec_comment_end:
			goto LBL_AGAIN;
		case iec_char_found:
			break;
		}

		switch ( chl_cur ) {
		case '(':
			ch_symbol = ')';
			(*ain_position)++;
			break;
		case '\"':
			ch_symbol = '\"';
			(*ain_position)++;
			break;
		case '\'':
			ch_symbol = '\'';
			(*ain_position)++;
			break;
		default:
			ch_symbol = ';';
			break;
		}
	}
	*ain_arg_start = dsl_data.inc_position;


	while (dsl_data.m_has_more()) {
		char chl_cur = dsl_data.m_next();
		if( chl_cur == ch_symbol )
			break;
		switch (chl_cur) {
		case '\\':
			// TODO: State?
			dsl_data.m_next();
			break;
		default:
			continue;
		case '}':
			if ( ch_symbol == ';' ) {
				ch_symbol = '}';
				(*ain_position)--;
				continue;
			}
			break;
		}
	}


	if ( *ain_position >= in_len_data ) {
		in_return = CSS_ARG_PARTIAL;
		*ain_position = in_len_data;
	} else {
		in_return = CSS_ARG_COMPLETE;
	}
	ds_argument.m_write( &ach_data[*ain_arg_start], *ain_position - *ain_arg_start );
	return in_return;
} // end of ds_interpret_css::m_get_argument
#else
int ds_interpret_css::m_get_argument( const char* ach_data, int in_len_data, int *ain_position,
												 int *ain_arg_start, bool bo_get_cut_arg )
{
	assert ( ach_data != NULL && in_len_data > 0 );
	// initialize some variables:
	int in_return      = CSS_NO_ARG;
	*ain_arg_start = 0;

	*ain_arg_start = *ain_position;
	if ( !bo_get_cut_arg ) {
		m_pass_signs( ach_data, in_len_data, ain_position, " \n\r\t\v\f" );
		if ( *ain_position >= in_len_data ) {
			return in_return;
		}
		this->ds_argument.m_reset();
		this->ch_in_string = 0;
		switch ( ach_data[*ain_position] ) {
		case '(':
			this->ch_symbol = ')';
			(*ain_position)++;
			*ain_arg_start = *ain_position;
			break;
		case '\"':
			this->ch_symbol = '\"';
			*ain_arg_start = *ain_position;
			(*ain_position)++;
			this->ch_in_string = ch_symbol;
			break;
		case '\'':
			this->ch_symbol = '\'';
			*ain_arg_start = *ain_position;
			(*ain_position)++;
			this->ch_in_string = ch_symbol;
			break;
		default:
			this->ch_symbol = ';';
			*ain_arg_start = *ain_position;
			break;
		}
	}
	if(*ain_position >= in_len_data)
		goto LBL_NEED_MORE;
	switch(this->ch_in_string) {
	case '\'':
		goto LBL_CONTINUE_SINGLE_QUOTE;
	case '\"':
		goto LBL_CONTINUE_DOUBLE_QUOTE;
	}

	for ( ; *ain_position < in_len_data; (*ain_position)++) {
		if(ach_data[*ain_position] == this->ch_symbol)
			goto LBL_DONE3;
		switch ( ach_data[*ain_position] ) {
		case '\\':
			(*ain_position)++;
			continue;
		case '\'': {
			this->ch_in_string = '\'';
			(*ain_position)++;
LBL_CONTINUE_SINGLE_QUOTE:
			for(;*ain_position < in_len_data; (*ain_position)++) {
				switch(ach_data[*ain_position]) {
					case '\'':
						this->ch_in_string = 0;
						goto LBL_DONE;
					case '\\':
						(*ain_position)++;
						continue;
					default:
						break;
				}
			}
			goto LBL_NEED_MORE;
LBL_DONE:
			if(ach_data[*ain_position] == this->ch_symbol) {
				(*ain_position)++;
				goto LBL_DONE3;
			}
			continue;
		}
		case '\"': {
			this->ch_in_string = '\"';
			(*ain_position)++;
LBL_CONTINUE_DOUBLE_QUOTE:
			for(;*ain_position < in_len_data; (*ain_position)++) {
				switch(ach_data[*ain_position]) {
				case '\"':
					this->ch_in_string = 0;
					goto LBL_DONE2;
				case '\\':
					(*ain_position)++;
					continue;
				default:
					break;
				}
			}
			goto LBL_NEED_MORE;
LBL_DONE2:
			if(ach_data[*ain_position] == this->ch_symbol) {
				(*ain_position)++;
				goto LBL_DONE3;
			}
			continue;
		}
		default:
			continue;
		case '}':
			if ( this->ch_symbol == ';' ) {
				this->ch_symbol = '}';
				(*ain_position)--;
				continue;
			}
			goto LBL_DONE3;
		}
		break;
	}
LBL_NEED_MORE:
	*ain_position = in_len_data;
	this->ds_argument.m_write( &ach_data[*ain_arg_start], *ain_position - *ain_arg_start );
	return CSS_ARG_PARTIAL;
LBL_DONE3:
	this->ds_argument.m_write( &ach_data[*ain_arg_start], *ain_position - *ain_arg_start );
	return CSS_ARG_COMPLETE;
} // end of ds_interpret_css::m_get_argument
#endif

/**
*
* function ds_interpret_css::m_is_word_in_list
*
* @param[in] char* ach_word     word, which will be saved
* @param[in] int   in_len_word  length of ach_word
*
* @return    int                key:
*                                -1 = not in list
*                                 0 = "url"
*                                 1 = "@import"
*                                 2 = "src="
*
*/
ds_interpret_css::ied_word_function ds_interpret_css::m_is_word_in_list( const char* ach_word, int in_len_word )
{
	dsd_const_string dsl_word(ach_word, in_len_word);
	return m_is_word_in_list(dsl_word);
} // end of ds_interpret_css::m_is_word_in_list

ds_interpret_css::ied_word_function ds_interpret_css::m_is_word_in_list( const dsd_const_string& rdsp_word ) {
	if(rdsp_word.m_equals("url"))
		return iec_word_function_url;
	if(rdsp_word.m_equals("src="))
		return iec_word_function_src;
	if(rdsp_word.m_equals("@import"))
		return iec_word_function_import;
	return iec_word_function_invalid;
}

/**
*
* ds_interpret_css::m_remove_first_sign
*
* @return      int                         number of removed signs
*
*/
int ds_interpret_css::m_remove_signs(dsd_const_string& rdsp_argument)
{
	if ( rdsp_argument.m_get_len() < 1 ) {
		return 0;
	}

	int in_del = 0;
	int in_old = 0;

	for ( ; ; ) {
		in_del += m_remove_first_sign( rdsp_argument, ' ' );
		in_del += m_remove_last_sign ( rdsp_argument, ' ' );
		in_del += m_remove_first_sign( rdsp_argument, '(' );
		in_del += m_remove_last_sign ( rdsp_argument, ')' );
#if 0
		in_del += m_remove_first_last_sign( rdsp_argument, '"' );
		in_del += m_remove_first_last_sign( rdsp_argument, '\'' );
#endif
		if ( in_del > in_old ) {
			in_old = in_del;
		} else {
			break;
		}
	}

	return in_del;
} // end of ds_interpret_css::m_remove_signs


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
bool ds_interpret_css::m_setup( ds_session* ads_session_in )
{
	ds_word.m_setup( ads_session_in->ads_wsp_helper, CSS_MEMORY_SIZE);
	ds_argument.m_setup( ads_session_in->ads_wsp_helper, CSS_ARGUMENT_SIZE );
#if 0
	this->iec_word_state = ied_ws_start;
	this->dsc_comment.m_setup( ads_session_in->ads_wsp_helper, CSS_ARGUMENT_SIZE );
#endif
	return ds_interpret::m_setup( ads_session_in );
} // end of ds_interpret_css::m_setup
