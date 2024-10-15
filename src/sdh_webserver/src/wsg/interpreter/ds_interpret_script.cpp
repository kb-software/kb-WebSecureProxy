/*+-------------------------------------------------------------------------+*/
/*| defines                                                                 |*/
/*+-------------------------------------------------------------------------+*/
#define SM_USE_FUNCTION2	1

#define HOB_SET_ATTRIBUTE               "HOB_set_attr("
#define HOB_GET_ATTRIBUTE               "HOB_get_attr("
#define HOB_FUNCTION                    "HOB_func("
#define HOB_FUNCTION2                   "HOB_func2("
#define HOB_OBJECT                      "HOB_object("
#define HOB_JS                          "HOB_js("
#define HOB_STYLE                       "HOB_set_style("
#define HOB_CHECK_PROPERTY              "HOB_check_property("
#define HOB_TMP_OBJECT                  "HOB_tmp_object"
#define MIN_SIZE_FOR_RECURSIVE_CALL     2
#define MAX_NUM_OF_RECURSIVE_CALLS      128          // avoid "stack-overflow"
#define DEFAULT_INSERT_BUFFER_SIZE      256

/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "../../ds_session.h"
#include "ds_interpret_script.h"
#include "ds_attributes.h"
#ifdef HL_UNIX
    #include <ctype.h>
#endif
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
ds_interpret_script::ds_interpret_script(void) : ds_interpret()
{
#if SM_USE_WSG_V2
#if SM_INTERPRET_SCRIPT_V2
    iec_parser_state = ied_parser_state_init;
#endif
#if SM_INTERPRET_SCRIPT_V3
    iec_parser_state = ied_parser_state_init;
#endif
#endif
    ienc_in_quotes = ied_in_no_quotes;
    iec_charset = ied_chs_invalid;
	 imc_unique_id = 0;
}

/*+-------------------------------------------------------------------------+*/
/*| destructor:                                                             |*/
/*+-------------------------------------------------------------------------+*/
/**
 * @ingroup dataprocessor
*/
ds_interpret_script::~ds_interpret_script(void)
{
#if !SM_USE_WSG_V2
	if ( ads_session ) {
        dsc_variables.m_init( ads_session->ads_wsp_helper );
    }
#endif
}

/*+-------------------------------------------------------------------------+*/
/*| public functions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/**
 * @ingroup dataprocessor
 *
 * @return      1 if data was sent, 0 otherwise
*/
int ds_interpret_script::m_process_data( )
{
    // initialize some variables:
    const char* ach_data;
    int   in_len_data      = 0;
    int   in_data_complete = 0;
    int   in_sum_written  = 0;

    while ( in_data_complete == 0 ) {
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
} // end of ds_interpret_script::m_process_data

void ds_interpret_script::m_init( ied_charset iep_charset, const char* achp_quote, int imp_flags ) {
#if 0
    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
        "#ds_interpret_script::m_init iep_charset=%d achp_quote=0x%02X flags=%08X", iep_charset, *achp_quote, imp_flags);
#endif
    if(iep_charset == ied_chs_invalid) {
        iep_charset = ied_chs_wcp_1252;
    }
    this->m_set_charset(iep_charset);
#if SM_USE_WSG_V2
	 this->inc_input_rest = 0;
    this->inc_output_rest = 0;
    this->iec_parser_state = ied_parser_state_init;
#endif
	this->imc_flags = imp_flags;
	this->inc_bom_rest = -1;
	if((imp_flags & IMC_FLAG_TOP_LEVEL) != 0)
		this->inc_bom_rest = 0;

    if ( achp_quote == NULL ) {
        this->ienc_in_quotes = ied_in_no_quotes;
    } else if ( achp_quote[0] == '\'' ) {
        this->ienc_in_quotes = ied_in_single_quotes;
    } else if ( achp_quote[0] == '"' ) {
        this->ienc_in_quotes = ied_in_double_quotes;
    }
#if SM_USE_INTERPRET_SCRIPT_SHA256
	 SHA256_Init(this->inrc_sha256_state);
#endif
}

void ds_interpret_script::m_set_charset(ied_charset iep_charset) {
	this->iec_charset = iep_charset;
	int iml_elem_size = m_cs_elem_size(iep_charset);
	int iml_elem_size_mask;
	switch(iml_elem_size) {
	case 1:
		iml_elem_size_mask = 0x1;
		break;
	case 2:
		iml_elem_size_mask = 0x3;
		break;
	case 4:
		iml_elem_size_mask = 0x7;
		break;
	default:
		iml_elem_size_mask = 0x1;
		break;
	}
	this->inc_elem_size = iml_elem_size;
	this->inc_elem_size_mask = iml_elem_size_mask;
}

void ds_interpret_script::m_set_unique_id(int imp_id) {
	this->imc_unique_id = imp_id;
}

#if SM_USE_WSG_V2
extern "C" int m_u8l_from_u32l( char *achp_target, int inp_max_len_target,
                                const int *aimp_source, int inp_len_source );

#if SM_INTERPRET_SCRIPT_V3
template<bool BO_ESCAPE_HTML> int ds_interpret_script::m_convert_to_utf8(
    const char* achp_in_cur, const char* achp_in_end )
{
    const char* achl_in_cur = achp_in_cur;
    char* achl_out_cur = this->chrc_output + this->inc_output_rest;
    char* achl_out_end = this->chrc_output + sizeof(this->chrc_output);
    char* achl_out_limit = achl_out_end - 6;

	if(this->inc_bom_rest >= 0) {
		/*Kodierung	hexadezimale Darstellung	dezimale Darstellung	Darstellung nach Windows-1252
		UTF-8	EF BB BF[4]	239 187 191	
		UTF-16 (BE)	FE FF	254 255	
		UTF-16 (LE)	FF FE	255 254
		UTF-32 (BE)	00 00 FE FF	0 0 254 255	
		UTF-32 (LE)	FF FE 00 00	255 254 0 0	
		UTF-7	2B 2F 76, und ein Zeichen aus: [ 38 | 39 | 2B | 2F ][5]	43 47 118, und ein Zeichen aus: [ 56 | 57 | 43 | 47 ]	+/v, und ein Zeichen aus: 8 9 + /
		UTF-1	F7 64 4C	247 100 76	
		UTF-EBCDIC	DD 73 66 73	221 115 102 115	
		SCSU	0E FE FF (von anderen möglichen Bytefolgen wird abgeraten)[6]	14 254 255	
		BOCU-1	FB EE 28 optional gefolgt von FF[7]	251 238 40 optional gefolgt von 255	ûî( optional gefolgt von
		GB 18030	84 31 95 33*/
		int inl_tmp;
		do {
			if(achl_in_cur >= achp_in_end)
				return achl_in_cur-achp_in_cur;
			this->chrc_bom[this->inc_bom_rest++] = *achl_in_cur++;
			switch(this->chrc_bom[0]) {
			case 0xEF: // UTF-8 (1/3)
				if(this->inc_bom_rest <= 1)
					continue;
				if(this->chrc_bom[1] != 0xBB)
					goto LBL_NO_BOM;
				if(this->inc_bom_rest <= 2)
					continue;
				if(this->chrc_bom[2] != 0xBF)
					goto LBL_NO_BOM;
				this->m_set_charset(ied_chs_utf_8);
				goto LBL_FOUND_BOM;
			case 0xFE: // UTF-16 (BE)	
				if(this->inc_bom_rest <= 1)
					continue;
				if(this->chrc_bom[1] != 0xFF)
					goto LBL_NO_BOM;
				this->m_set_charset(ied_chs_be_utf_16);
				goto LBL_FOUND_BOM;
			case 0xFF: // UTF-16 (LE)	
				if(this->inc_bom_rest <= 1)
					continue;
				if(this->chrc_bom[1] != 0xFE)
					goto LBL_NO_BOM;
				this->m_set_charset(ied_chs_le_utf_16);
				goto LBL_FOUND_BOM;
			default:
				achl_in_cur--;
				goto LBL_FOUND_BOM;
			}
		} while(true);
LBL_NO_BOM:
		{
			inl_tmp = this->inc_bom_rest;
			this->inc_bom_rest = -1;
			int inl_res = this->m_convert_to_utf8<BO_ESCAPE_HTML>((const char*)this->chrc_bom, (const char*)this->chrc_bom+inl_tmp);
			if(inl_res != this->inc_bom_rest)
				return -1;
		}
LBL_FOUND_BOM:
		this->inc_bom_rest = -1;
	}

    int inl_elem_size = this->inc_elem_size;
    int inl_elem_size_mask = this->inc_elem_size_mask;
	 do {
        if(achl_in_cur >= achp_in_end)
            break;
        if(achl_out_cur >= achl_out_limit)
            break;
        if(this->inc_input_rest >= sizeof(this->chrc_input))
            return -1;
        this->chrc_input[this->inc_input_rest++] = *achl_in_cur++;
		  if((this->inc_input_rest % inl_elem_size_mask) != 0)
			  continue;
		  do {
				unsigned int uml_ucs_char = 0;
				int iml_res = m_get_vc_ch_ex(&uml_ucs_char, this->chrc_input, this->chrc_input+this->inc_input_rest,
					this->iec_charset);
				// Not enough input?
				if(iml_res > this->inc_input_rest)
					break;
				if(iml_res < 0) {
					// Not enough input?
					if(iml_res == -1)
						break;
					//this->inc_input_rest = 0;
					this->inc_input_rest -= inl_elem_size;
					memmove(this->chrc_input, this->chrc_input+inl_elem_size, this->inc_input_rest);
					uml_ucs_char = 0xFFFD;
				}
				else {
					this->inc_input_rest = 0;
				}
				int inl_res = m_u8l_from_u32l(achl_out_cur, achl_out_end-achl_out_cur,
										(int*)&uml_ucs_char, 1);
				if(inl_res == 0)
					goto LBL_DONE;
				if(inl_res < 0)
					return -1;
				achl_out_cur += inl_res;
		  } while(this->inc_input_rest > 0);
    } while(true);
LBL_DONE:

    this->inc_output_rest = achl_out_cur - this->chrc_output;

    return achl_in_cur-achp_in_cur;
}
#endif
#endif /*SM_USE_WSG_V2*/

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
int ds_interpret_script::m_parse_data( const char* ach_data, int in_len_data, bool bo_data_complete, ds_hstring* ads_output )
{
#if SM_USE_WSG_V2
#if SM_INTERPRET_SCRIPT_V2

#define SM_FLUSH_DATA(ACHP_CUR) \
    do { \
        int iml_ret = m_send_data( achl_sync_last, (ACHP_CUR)-achl_sync_last, ads_output ); \
        if(iml_ret < 0) \
            return iml_ret; \
        achl_sync_last = ACHP_CUR; \
    } while(false)

    if(true) {
        const char* achl_sync_last = ach_data;
        const char* achl_cur = ach_data;
        const char* achl_end = ach_data + in_len_data;
        switch(iec_parser_state) {
        case ied_parser_state_init: {
            m_send_data2("HOB.m_parse_script(\"", ads_output);
            this->iec_parser_state = ied_parser_state_default;
            goto LBL_parser_state_default;
        }
        case ied_parser_state_default:
LBL_parser_state_default:
            while(achl_cur < achl_end) {
                switch(*achl_cur++) {
                case '\\':
                    SM_FLUSH_DATA(achl_cur-1);
                    achl_sync_last = achl_cur;
                    this->iec_parser_state = ied_parser_state_escape;
                    goto LBL_parser_state_escape;
                case '\r':
                    SM_FLUSH_DATA(achl_cur-1);
                    m_send_data2("\\\r", ads_output);
                    achl_sync_last = achl_cur;
                    break;
                case '\n':
                    SM_FLUSH_DATA(achl_cur-1);
                    m_send_data2("\\\n", ads_output);
                    achl_sync_last = achl_cur;
                    break;
                case '\t':
                    SM_FLUSH_DATA(achl_cur-1);
                    m_send_data2("\\\t", ads_output);
                    achl_sync_last = achl_cur;
                    break;
                case '\"':
                    SM_FLUSH_DATA(achl_cur-1);
                    m_send_data2("\\\"", ads_output);
                    achl_sync_last = achl_cur;
                    this->iec_parser_state = ied_parser_state_string;
                    goto LBL_parser_state_default;
                default:
                    break;
                }
            }
            goto LBL_end;
        case ied_parser_state_escape:
LBL_parser_state_escape:
            if(achl_cur >= achl_end)
                goto LBL_end;
            switch(*achl_cur++) {
            case '\\':
                SM_FLUSH_DATA(achl_cur-1);
                m_send_data2("\\", ads_output);
                achl_sync_last = achl_cur;
                this->iec_parser_state = ied_parser_state_default;
                goto LBL_parser_state_default;
            default:
                return -1;
            }
            break;
        case ied_parser_state_string:
            if(achl_cur >= achl_end)
                goto LBL_end;
            while(achl_cur < achl_end) {
                switch(*achl_cur++) {
                }
            }
            break;
        default:
            return -1;
        }
LBL_end:
        int iml_ret = m_send_data( achl_sync_last, achl_cur-achl_sync_last, ads_output );
        if(iml_ret < 0)
            return iml_ret;
        achl_sync_last = achl_cur;
        if(bo_data_complete) {
            iml_ret = m_send_data2("\");", ads_output);
        }
        return iml_ret;
        //return m_send_data( ach_data, in_len_data, ads_output );
    }
#endif
#if SM_INTERPRET_SCRIPT_V3
    if(in_len_data < 0)
        in_len_data = 0;

#if 0
    dsd_const_string dsl_test(ach_data, in_len_data);
    /*if(dsl_test.m_index_of("for(var f=2;f<d.length;f++){var g=d[f];!_.Tc(g)||_.Kc(g)&&") >= 0) {
        int a = 0;
    }*/
    int inl_p = dsl_test.m_index_of("for(d in e)a[d]=e[d]");
    if(inl_p >= 0) {
        int a = 0;
    }
#endif
    /*ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
        "#ds_interpret_script::m_parse_data in_len_data=%d", in_len_data );
    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_warning,
        "#ds_interpret_script::m_parse_data: %.*s", in_len_data, ach_data );
    */
    if(true) {
        const char* achl_in_cur = ach_data;
        const char* achl_in_end = ach_data + in_len_data;
LBL_AGAIN:            
        char* achl_out_cur = this->chrc_output + this->inc_output_rest;
        int iml_res = this->m_convert_to_utf8<false>(achl_in_cur, achl_in_end);
		//if((this->imc_flags & IMC_FLAG_HTML_ENTITIES) != 0 && ) {
		//}
        if(iml_res < 0)
            return iml_res;
        achl_in_cur += iml_res;
        const char* achl_cur = this->chrc_output;
        const char* achl_end = achl_cur + this->inc_output_rest;
        this->inc_output_rest = 0;
        //const char* achl_sync_last = ach_data;
        //const char* achl_cur = ach_data;
        //const char* achl_end = ach_data + in_len_data;

        switch(iec_parser_state) {
        case ied_parser_state_init: {
            if(achl_cur >= achl_end)
                return 0;
            // Does the string contain only white characters?
            dsd_const_string dsl_test(achl_cur, achl_end-achl_cur);
            if(dsl_test.m_find_first_not_of(" \t\r\n") < 0) {
                // Send white characters unchanged to avoid problems with script tags containing
                // a "src" attribute and code in form of white characters.
                m_send_data2(dsl_test, ads_output);
                return 0;
            }
			if(ads_session->dsc_ws_gate.dsc_url.hstr_hob_type_worker.m_get_len() > 0) {
				m_send_data2("importScripts(\"/protected/wsg/HOBwsg.js\");", ads_output);
				ds_hstring dc_insert(ads_session->ads_wsp_helper);
				this->m_write_hob_initialize(dc_insert,
					dsd_const_string::m_null(),
					"HOB.m_initialize", "",
					ads_session->dsc_ws_gate.dsc_url.hstr_hob_type_worker);
				m_send_data2(dc_insert.m_const_str(), ads_output);
			}
#if 0
			if((this->imc_flags & IMC_FLAG_TOP_LEVEL) != 0 && (this->imc_flags & IMC_FLAG_HTML_SCRIPT) == 0)
				m_send_data2("if(!HOB) debugger; HOB.m_parse_script({dsc_this:this,", ads_output);
			else
				m_send_data2("HOB.m_parse_script({dsc_this:this,", ads_output);
#else
			if((this->imc_flags & IMC_FLAG_HTML_EVENT) != 0)
				m_send_data2("return ", ads_output);
			m_send_data2("HOB.m_parse_script({dsc_this:this,", ads_output);
#endif
			if(this->imc_flags == IMC_FLAG_TOP_LEVEL) {
				ds_hstring dsl_temp(ads_session->ads_wsp_helper);
				dsl_temp.m_write(ads_session->dsc_ws_gate.hstr_prot_authority_ext_ws);
				dsl_temp.m_write(ads_session->dsc_ws_gate.dsc_url.hstr_path);
				ds_hstring dsl_temp2(ads_session->ads_wsp_helper);
				dsd_const_string adsl_temp = m_escape_js_string(dsl_temp.m_const_str(), dsl_temp2);
    			m_send_data2(" strc_name:'", ads_output);
				m_send_data2(adsl_temp, ads_output);
				m_send_data2("',", ads_output);
			}
			if((this->imc_flags & IMC_FLAG_HTML_EVENT) != 0) {
				m_send_data2(" dsc_arguments:arguments,", ads_output);
			}
			if((this->imc_flags & IMC_FLAG_HTML_SCRIPT) != 0) {
				m_send_data2(" strc_unique_id:'S", ads_output);
				ds_hstring dsl_temp2(ads_session->ads_wsp_helper);
				dsl_temp2.m_write_int(this->imc_unique_id);
				m_send_data2(dsl_temp2.m_const_str(), ads_output);
				m_send_data2("',", ads_output);
			}
            switch( ienc_in_quotes ) {
            case ied_in_double_quotes:
				m_send_data2("}, '", ads_output);
                break;
            case ied_in_single_quotes:
            case ied_in_no_quotes:
            default:
				m_send_data2("}, \"", ads_output);
                break;
            }
            this->iec_parser_state = ied_parser_state_default;
            this->inc_triplet_rest = 0;
            goto LBL_parser_state_default;
        }
        case ied_parser_state_default:
LBL_parser_state_default:
        {
#if 1
#endif        
            const int IN_OUTPUT_MAX = 512;
            const int IN_INPUT_MAX = (IN_OUTPUT_MAX*3)/4;
            BYTE chrl_base64[512];
            BYTE* achl_base64_cur = chrl_base64;
            BYTE* achl_base64_end = chrl_base64 + sizeof(chrl_base64);
            if(this->inc_triplet_rest > 0) {
                do {
                    if(achl_cur >= achl_end)
                        goto LBL_end;
                    this->chrc_triplet[this->inc_triplet_rest++] = *achl_cur++;
                } while(this->inc_triplet_rest < 3);

#if SM_USE_INTERPRET_SCRIPT_SHA256
					 SHA256_Update(this->inrc_sha256_state, (const char*)this->chrc_triplet, 0, 3);
#endif
					 int inl_out = 0;
					 if(!helper::ConHTBa(this->chrc_triplet, 3, achl_base64_end-achl_base64_cur,
                    achl_base64_cur, &inl_out)) {
                    return -1;
                }
                achl_base64_cur += inl_out;
                this->inc_triplet_rest = 0;
            }
            while(achl_cur+2 < achl_end) {
                int inl_len = ((achl_end - achl_cur)/3)*3;
                int inl_input_max = ((achl_base64_end-achl_base64_cur)*3)/4;
                if(inl_len > inl_input_max) {
                    inl_len = inl_input_max;
                }
#if SM_USE_INTERPRET_SCRIPT_SHA256
					 SHA256_Update(this->inrc_sha256_state, achl_cur, 0, inl_len);
#endif
                int inl_out = 0;
                if(!helper::ConHTBa((const BYTE*)achl_cur, inl_len, achl_base64_end-achl_base64_cur,
                    achl_base64_cur, &inl_out)) {
                    return -1;
                }
                achl_base64_cur += inl_out;
                achl_cur += inl_len;
                int iml_ret = m_send_data( (const char*)chrl_base64, achl_base64_cur-chrl_base64, ads_output );
                if(iml_ret < 0)
                    return iml_ret;
                achl_base64_cur = chrl_base64;
            }
            int inl_rest_len = achl_base64_cur-chrl_base64;
            if(inl_rest_len > 0) {
                int iml_ret = m_send_data( (const char*)chrl_base64, inl_rest_len, ads_output );
                if(iml_ret < 0)
                    return iml_ret;
            }
            do {
                if(achl_cur >= achl_end)
                    goto LBL_end;
                this->chrc_triplet[this->inc_triplet_rest++] = *achl_cur++;
            } while(this->inc_triplet_rest < 3);
            break;
        }
        }
LBL_end:
        if(achl_in_cur < achl_in_end)
            goto LBL_AGAIN;
        if(!bo_data_complete)
            return 1;
        if(this->inc_triplet_rest > 0) {
            BYTE chrl_base64[4];
#if SM_USE_INTERPRET_SCRIPT_SHA256
				SHA256_Update(this->inrc_sha256_state, (const char*)this->chrc_triplet, 0, this->inc_triplet_rest);
#endif
            int inl_out = 0;
            if(!helper::ConHTBa(this->chrc_triplet, this->inc_triplet_rest, 4,
                chrl_base64, &inl_out)) {
                return -1;
            }
            int iml_ret = m_send_data( (const char*)chrl_base64, inl_out, ads_output );
            if(iml_ret < 0)
                return iml_ret;
#if 0
            char chrl_buf[32];
            switch( ienc_in_quotes ) {
            case ied_in_no_quotes:
            default:
            case ied_in_single_quotes:
                sprintf_s(chrl_buf, "\" /**/ + \"");
                break;
            case ied_in_double_quotes:
                sprintf_s(chrl_buf, "' /**/ + '");
                break;
            }
            iml_ret = m_send_data2(chrl_buf, ads_output);
            if(iml_ret < 0)
                return iml_ret;
#endif
        }
#if SM_USE_INTERPRET_SCRIPT_SHA256
		  char chrl_sha256[32];
		  char chrl_sha256_hex[64+1];
		  SHA256_Final(this->inrc_sha256_state, chrl_sha256, 0);
		  helper::m_to_lowercase_hex_string(chrl_sha256, sizeof(chrl_sha256), chrl_sha256_hex);
		  chrl_sha256_hex[64] = 0;
#endif
		 
		  char chrl_temp[128];
		  const char* strl_pattern = NULL;
#if SM_USE_PARSE_SCRIPT_PARAMS2
#define MAKE_PATTERN(quote) (quote ", {" quote "imc_flags" quote ":%d," quote "strc_sha256" quote ":" quote "%s" quote "});")
#else
#define MAKE_PATTERN(quote) (quote ", %d);")
#endif
		  switch( ienc_in_quotes ) {
		  case ied_in_double_quotes:
			  strl_pattern = MAKE_PATTERN("'");
			  break;
		  case ied_in_single_quotes:
		  case ied_in_no_quotes:
		  default:
			  strl_pattern = MAKE_PATTERN("\"");
			  break;
		  }
#if SM_USE_PARSE_SCRIPT_PARAMS2
		  int inl_len = sprintf(chrl_temp, strl_pattern, this->imc_flags, chrl_sha256_hex);
#else
		  int inl_len = sprintf(chrl_temp, strl_pattern, this->imc_flags);
#endif
		  int iml_ret = m_send_data2(dsd_const_string(chrl_temp, inl_len), ads_output);
		  if(iml_ret < 0)
			  return iml_ret;
		  this->iec_parser_state = ied_parser_state_init;
		  return 1;
    }

#endif
#else
    // initialize some variables:
    ds_hstring dc_insert;            // buffer for inserting data
    ds_hstring dc_temp;              // buffer for temporary saving data (needed for overwriting dc_insert)
    int        in_len_vars = (int)sizeof(ds_scriptvariables);
    dc_insert.m_setup( ads_session->ads_wsp_helper, DEFAULT_INSERT_BUFFER_SIZE );

    dsc_variables.m_init( ads_session->ads_wsp_helper );

    if ( (ach_data == NULL) || (in_len_data == -1) ) {
        if ( bo_data_complete ) {
            // case of data sent by webserver without length information! 
            // send all data, that was saved in current session, free memory, quit.
            while ( !dsc_variables.m_empty() ) {
                adsc_var_cur = dsc_variables.m_stack_current();
                dc_insert.m_write( "" );
                m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_sign.m_get_ptr(), adsc_var_cur->ds_sign.m_get_len(), adsc_var_cur->ds_argument.m_get_ptr(), adsc_var_cur->ds_argument.m_get_len() );
                if ( adsc_var_cur->ds_sign.m_get_len() > 0 && adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos] == '(' ) {
                    m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_argument.m_get_ptr(), adsc_var_cur->ds_argument.m_get_len() );
                }
                m_free_all_data();
                adsc_var_cur->dsc_arg_state.m_clear();
                
                adsc_var_cur->in_state = SCRIPT_NORMAL;
                if ( m_parse_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), true ) == 1 ) {
                    in_ret = 1;
                }
                dc_insert.m_reset();
            }
        } else {
            in_ret = 0;
        }
        // no data available
        return in_ret;
    }

    // initialize some variables:
    int    in_position         = 0;         // actual position in data
    int    in_pos_insert       = 0;         // position to insert our HOB_functions
    int    in_func_return      = 0;         // return value for several functions
    bool   bo_arg_changed      = false;     // true if argument is changed in recursiv call
    ds_hstring ds_changed_arg;               // buffer for changed argument in recursiv call
    const char*  ach_word      = NULL;      // pointer to word
    int    in_len_word         = 0;         // length of ach_word
    int    in_word_pos         = 0;         // position of ach_word in data
    int    in_word_key         = -2;        // word key from m_is_word_in_list
    int    in_arg_key          = -2;        // arguments key from m_is_argument_in_attr_list
    const char*  ach_sign      = NULL;      // pointer to sign after a word
    int    in_len_sign         = 0;         // length of ach_sign (be carefull: sign can also be "==")
    const char*  ach_arg_sign  = NULL;      // pointer to sign after an argument
    int    in_len_arg_sign     = 0;         // length of ach_arg_sign (be carefull: sign can also be ").")
    const char*  ach_object    = NULL;      // pointer to object
    int    in_len_object       = 0;         // length of ach_object
    const char*  ach_argument  = NULL;      // pointer to argument
    int    in_len_argument     = 0;         // length of ach_argument
    int    in_pos_arg_sign     = 0;         // position of sign after argument
    const char*  ach_white_spaces = NULL;      // pointer to white_spaces
    int    in_len_white_spaces = 0;         // length of ach_white_spaces
    const char*  ach_arg_spaces = NULL;      // pointer to white spaces after argument
    int    in_len_arg_spaces   = 0;         // length of white spaces after argument
    bool   bol_is_condition		= false;	// to prevent false parsing when syntax is like: if(a)(new obj).load(x);
#ifndef B140716
    bool   bol_with_doublesign  = false;	// to prevent false parsing when syntax is like: ++b.length; or --b.length;
#endif
	ds_scriptvariables* ads_tempvars;

    ds_changed_arg.m_setup( ads_session->ads_wsp_helper );

    if ( dsc_variables.m_empty() ) {
        in_ret = 0;
        // get memory for ds_scriptvariables:
        ads_tempvars = (ds_scriptvariables*)ads_session->ads_wsp_helper->m_cb_get_memory( in_len_vars, false );
#ifdef TRACE_MEMORY        
        m_trace_memory( ads_tempvars, in_len_vars, false );
#endif // TRACE_MEMORY
        // put ds_scriptvariables in this memory:
        ads_tempvars = new(ads_tempvars) ds_scriptvariables( ads_session->ads_wsp_helper );
        dsc_variables.m_stack_push(ads_tempvars);
        ads_tempvars = NULL;
    }
    adsc_var_cur = dsc_variables.m_stack_current();

    // start work here:
    while ( in_position < in_len_data )
	{
#ifdef B140716
		if ( adsc_var_cur->in_state != SCRIPT_NORMAL) {
			bol_with_doublesign  = false;	// to prevent false parsing when syntax is like: ++b.length; or --b.length;
		}
#endif
            
		bol_is_condition = false;

		switch ( adsc_var_cur->in_state )
		{
// ----------------------------------------------------------------------------
// handle normal data:
// ----------------------------------------------------------------------------
            case SCRIPT_NORMAL:
                /*+----------+*/
                /*| get word |*/
                /*+----------+*/
                in_func_return = m_get_next_word( ach_data, in_len_data, &in_position, in_word_key, &ach_word, &in_len_word, &in_word_pos );
#ifdef B20140804
				if( memcmp( ach_word, "if", 2 ) == 0 ){ bol_is_condition = true; }
#else
				if( (in_len_word == 2) && (*ach_word == 'i') && (*(ach_word + 1) == 'f')) { 
					bol_is_condition = true; 
				} 
#endif
                
				if ( in_len_object == 0 ) {
                    in_pos_insert = in_word_pos;
                }
                switch ( in_func_return ) {
                    case SCRIPT_NO_WORD:
                        if ( in_len_object > 0 ) {
                            adsc_var_cur->ds_object.m_write( ach_object, in_len_object );
                            m_send_data( ach_data, in_pos_insert, ads_output );
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                        } else {
                            m_send_data( ach_data, in_len_data, ads_output ); // send hole data and return
                            // free memory:
                            m_free_vars();
                        }
                        return in_ret; // -> exit
                    case SCRIPT_WORD_PARTIAL:
                        if ( !bo_data_complete ) {
                            // save word and object (more doesn't exist yet):
                            adsc_var_cur->ds_word.m_write( ach_word, in_len_word );
                            adsc_var_cur->ds_object.m_write( ach_object, in_len_object );
                            m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                            adsc_var_cur->in_state = SCRIPT_CUT_WORD;
                        } else {
                            in_word_key = m_is_word_in_list( ach_word, in_len_word );
                            if ( m_is_word_attribute( in_word_key ) && in_word_key != ds_attributes::ied_scr_attr_value ) {
                                if ( in_len_object == 0 ) {
                                    in_pos_insert = in_word_pos;
                                }
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_build_HOB_get_attr( &dc_insert, ach_object, in_len_object, ach_word, in_len_word, NULL, 0);
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                dc_insert.m_reset();
                            } else if ( m_is_word_object( in_word_key ) && in_word_key != ds_attributes::ied_scr_attr_all ) {
                                if ( in_len_object == 0 ) {
                                    in_pos_insert = in_word_pos;
                                }
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_build_HOB_object( &dc_insert, ach_object, in_len_object, ach_word, in_len_word,  NULL, 0 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                dc_insert.m_reset();
                            } else if ( adsc_var_cur->ds_last_pos_key.in_key > -1 ) {
	                            adsc_var_cur->ds_last_pos_key.in_key = -2;
		                        if ( adsc_var_cur->ds_last_pos_key.in_pos_in_object != 0 ) {
									// send data before the current object
									m_send_data( ach_data, in_pos_insert, ads_output );
									m_move_char_pointer( &ach_data, &in_len_data, &in_position );
						            // get attribute via hob function
									m_build_HOB_get_attr( &dc_insert, ach_object, adsc_var_cur->ds_last_pos_key.in_pos_in_object, ach_object + adsc_var_cur->ds_last_pos_key.in_pos_in_object, in_len_object - adsc_var_cur->ds_last_pos_key.in_pos_in_object - 1, NULL, 0 );
									m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
									// append the word including "." and the following sign
									m_send_data( ach_word - 1, in_len_word + 1, ads_output );

									// reset variables:
									dc_insert.m_reset();
								}
								in_len_object = 0;
#ifndef B140716
  								bol_with_doublesign  = false;	// to prevent false parsing when syntax is like: ++b.length; or --b.length;
#endif
							} else {
                                m_send_data( ach_data, in_len_data, ads_output );
                            }
                            // free memory:
                            m_free_vars();
                        }
                        return in_ret; // -> exit
                    case SCRIPT_WORD_COMPLETE:
                        break; // -> continue after this switch
                }
                in_word_key = m_is_word_in_list( ach_word, in_len_word ); // check if word is in list

                if ( in_word_key == ds_attributes::ied_scr_attr_return ) {
                    // MJ 03.06.09, Ticket [17724]
                    // case of return(A.replace(...)).replace
                    // we must insert a space, otherwise we will end up in a
                    // returnHOB_func(...)
                    if ( ach_data[in_position] != ' ' ) {
                        m_send_data( ach_data, in_position, ads_output );
                        m_send_data( " ", 1, ads_output );
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                    }
                    continue; //-> get next word
                } else if ( in_word_key == ds_attributes::ied_scr_attr_delete ) {
                    adsc_var_cur->in_state = SCRIPT_IGNORE_COMMAND;
                    continue;
                }
				else if( in_word_key == ds_attributes::ied_scr_attr_case )
				{
					adsc_var_cur->in_state = SCRIPT_CASE_STATEMENT;
					continue;
				}
				else if( in_word_key == ds_attributes::ied_scr_attr_function )
				{
				    m_pass_signs( ach_data, in_len_data, &in_position, " \n\r\t\v\f" );
                    if ( ach_data[in_position] != '(' ) {  // After 'function' there is a function name or '('
                        // check, if next symbol may start a function name; 
                        // otherwise, reset our state (avoid an endless loop, in case of broken syntax [Ticket 36233])
                        if (   (ach_data[in_position] >= 'A' && ach_data[in_position] <= 'Z' )
                            || (ach_data[in_position] >= 'a' && ach_data[in_position] <= 'z')
                            || ( ach_data[in_position] == '_' )
                            || ( ach_data[in_position] == '$' ) ) {
                            continue; // read function name
                        } else {
                            in_word_key = -2; // reset word state: the word is not considered a function
                        }
					}
				}

                /*+----------+*/
                /*| get sign |*/
                /*+----------+*/

                in_func_return = m_get_next_sign( ach_data, in_len_data, &in_position, &ach_sign, &in_len_sign, &adsc_var_cur->in_sign_pos, &ach_white_spaces, &in_len_white_spaces );
#ifndef B140716
				if (in_len_sign >=2) {
					if ((!memcmp(ach_sign + in_len_sign - 2, "++" ,2)) || (!memcmp(ach_sign + in_len_sign - 2, "--" ,2))) {
						bol_with_doublesign  = true;	// to prevent false parsing when syntax is like: ++b.length; or --b.length;
					}
				}
#endif				
				switch ( in_func_return ) {
                    case SCRIPT_NO_SIGN:
                        if ( !bo_data_complete ) {
                            // save word, sign, object and white spaces (more doesn't exist yet):
                            adsc_var_cur->ds_word.m_write( ach_word, in_len_word );
                            adsc_var_cur->ds_sign.m_write( ach_sign, in_len_sign );
                            adsc_var_cur->ds_object.m_write( ach_object, in_len_object );
                            adsc_var_cur->ds_spaces.m_write( ach_white_spaces, in_len_white_spaces );
                            if ( in_len_object == 0 ) {
                                in_pos_insert = in_word_pos;
                            }
                            m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                            adsc_var_cur->in_state = SCRIPT_CUT_SIGN;
                        } else {
                            if ( m_is_word_attribute( in_word_key ) && in_word_key != ds_attributes::ied_scr_attr_value ) {
#ifndef B140716
								if (bol_with_doublesign) {
									bol_with_doublesign  = false;	// to prevent false parsing when syntax is like: ++b.length; or --b.length;
									continue;
								}
#endif
                                if ( in_len_object == 0 ) {
                                    in_pos_insert = in_word_pos;
                                }
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_build_HOB_get_attr( &dc_insert, ach_object, in_len_object, ach_word, in_len_word, NULL, 0);
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                dc_insert.m_reset();
                            } else if ( m_is_word_object( in_word_key ) && in_word_key != ds_attributes::ied_scr_attr_all ) {
                                if ( in_len_object == 0 ) {
                                    in_pos_insert = in_word_pos;
                                }
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_build_HOB_object( &dc_insert, ach_object, in_len_object, ach_word, in_len_word,  NULL, 0 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                dc_insert.m_reset();
                            } else {
                                m_send_data( ach_data, in_len_data, ads_output );
                            }
                            // free memory:
                            m_free_vars();
                        }
                        return in_ret; // -> exit
                    case SCRIPT_SIGN_FOUND:
                        break; // -> continue after this switch
                }
                
                if ( in_word_key == ds_attributes::ied_scr_attr_function || in_word_key == ds_attributes::ied_scr_attr_var ) {
                    continue;
                }
                
                switch ( ach_sign[adsc_var_cur->in_sign_pos] ) {
                    case '.':
                        if ( m_is_word_attribute(in_word_key) && m_rec_attribute(in_word_key) ) {
                            // for case like "document.location.href.indexOf('foo')"
                            adsc_var_cur->ds_last_pos_key.in_key = in_word_key;
                            if ( ach_object == NULL || in_len_object == 0 ) {
                                adsc_var_cur->ds_last_pos_key.in_pos_in_object = 0;
                            } else {
                                adsc_var_cur->ds_last_pos_key.in_pos_in_object = (int) ( ach_word - ach_object );
                            }
                            adsc_var_cur->ds_last_pos_key.in_length = in_len_word;
                        } else if ( m_is_word_object(in_word_key) && m_rec_object(in_word_key) ) {
                            // for case like "document.firstChild.id  ... "
                            m_build_HOB_object( &dc_insert, ach_object, in_len_object, ach_word, in_len_word, ach_sign, in_len_sign );
                            adsc_var_cur->ds_object.m_write( dc_insert.m_get_ptr(), dc_insert.m_get_len() );
                            m_send_data( ach_data, in_pos_insert, ads_output );
                            m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                            // reset some variables:
                            in_pos_insert = 0;
                            dc_insert.m_reset();
                            adsc_var_cur->ds_last_pos_key.in_key = -2;
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                            continue; // -> handle saved object
                        }

                        // set object:
                        if ( in_len_object == 0 ) { // no object exists -> set a new one
                            ach_object    = ach_word;
                            in_pos_insert = in_word_pos;
                        }
                        in_len_object += (in_position - in_word_pos);

                        if ( in_position < in_len_data ) {
                            continue; // -> get next word                            
                        } 
                        if ( bo_data_complete ) {
                            ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                                                "HWSGI201I: found dot at end of data in ds_interpret_script::m_parse_data" );
                            m_send_data( ach_data, in_len_data, ads_output ); // send hole data
                            // free memory:
                            m_free_vars();
                        } else {
                            // save object, don't save word and sign, they are saved in object ("word.")!
                            adsc_var_cur->ds_object.m_write( ach_object, in_len_object );
                            m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert and return
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                        }
                        return in_ret; // -> exit
                    case '(':
                    case '[':
                        in_position--;  // argument search need the bracket in this case ( ... argument ... )
                        break;  // -> continue after this switch: get argument
                    case '?':
                        in_position--;  // argument search need the bracket in this case ( ... argument ... )
                        break;  // -> continue after this switch: get argument
                    case '=':
                        m_pass_signs( ach_data, in_len_data, &in_position, " \n\r\t\v\f" );
                        break;  // -> continue after this switch: get argument
                    case '"':
                        in_pos_insert = in_position;
                        adsc_var_cur->in_state = SCRIPT_DOUBLE_QUOTES;
                        continue; // -> handle double quotes
                    case '\'':
                        in_pos_insert = in_position;
                        adsc_var_cur->in_state = SCRIPT_SINGLE_QUOTES;
                        continue; // -> handle single quotes
                    case '/':
                        in_func_return = m_is_slash_comment( ach_data, in_len_data, &in_position );
                        switch ( in_func_return ) {
                            case SCRIPT_NOT_DECIDED:
                                m_send_data( ach_data, in_len_data, ads_output );
                                if ( bo_data_complete ) {
                                    // free memory:
                                    m_free_vars();
                                } else {
                                    adsc_var_cur->in_state = SCRIPT_CUT_AFTER_SLASH;
                                }
                                return in_ret;
                            case SCRIPT_ASTERISK_COMMENT:
                                in_pos_insert = in_position;
                                adsc_var_cur->in_state = SCRIPT_C_COMMENT_1;
                                continue; // -> handle "/*...*/" comment
                            case SCRIPT_SLASH_COMMENT:
                                in_pos_insert = in_position;
                                adsc_var_cur->in_state = SCRIPT_CPP_COMMENT;
                                continue; // -> handle "//..." comment
                            case SCRIPT_NO_COMMENT:
                                if ( m_check_for_reg_exp( ach_data, in_len_data, in_position - 1 ) ) {
                                    adsc_var_cur->in_state = SCRIPT_REG_EXP;
                                    continue;
                                }
                                break; // goto default case
                        }
                        // break is missing on purpose!!!
                    default:
						if ( m_is_word_attribute( in_word_key ) && in_word_key != ds_attributes::ied_scr_attr_value ) {
#ifndef B140716
							if (bol_with_doublesign) {
								bol_with_doublesign  = false;	// to prevent false parsing when syntax is like: ++b.length; or --b.length;
								continue;
							}
#endif
                            m_send_data( ach_data, in_pos_insert, ads_output );
                            m_move_char_pointer( &ach_data, &in_len_data, &in_position );

							/* hofmants: change that sign is not printed now */
							m_build_HOB_get_attr( &dc_insert, ach_object, in_len_object, ach_word, in_len_word, NULL, 0 );
							m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
							// MJ 26.06.12, Ticket [23699]
                            if ( in_len_white_spaces > 0 ) {
                                m_send_data( ach_white_spaces, in_len_white_spaces, ads_output );
                            }
                            // end Ticket [23699]
							m_send_data( ach_sign, in_len_sign, ads_output );
							/* hofmants end */

                            // reset variables:
                            in_len_object = 0;
                            dc_insert.m_reset();
                            adsc_var_cur->ds_last_pos_key.in_key = -2;
                        } else if ( m_is_word_object( in_word_key ) && in_word_key != ds_attributes::ied_scr_attr_all ) {
                            m_send_data( ach_data, in_pos_insert, ads_output );
                            m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                            m_build_HOB_object( &dc_insert, ach_object, in_len_object, ach_word, in_len_word, ach_sign, in_len_sign );
                            m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                            // reset variables:
                            in_len_object = 0;
#ifndef B140716
							bol_with_doublesign  = false;	// to prevent false parsing when syntax is like: ++b.length; or --b.length;
#endif
                            dc_insert.m_reset();
                            adsc_var_cur->ds_last_pos_key.in_key = -2;
                        } else if ( in_word_key == ds_attributes::ied_scr_attr_new ) {
                            if ( in_len_object == 0 ) { // no object exists -> set a new one
                                ach_object    = ach_word;
                                in_pos_insert = in_word_pos;
                            }
                            in_len_object += (in_position - in_word_pos);
                        } else if ( adsc_var_cur->ds_last_pos_key.in_key > -1 ) {
                            adsc_var_cur->ds_last_pos_key.in_key = -2;
                            if ( adsc_var_cur->ds_last_pos_key.in_pos_in_object != 0 ) {
								// send data before the current object
								m_send_data( ach_data, in_pos_insert, ads_output );
								m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                // get attribute via hob function
								m_build_HOB_get_attr( &dc_insert, ach_object, adsc_var_cur->ds_last_pos_key.in_pos_in_object, ach_object + adsc_var_cur->ds_last_pos_key.in_pos_in_object, in_len_object - adsc_var_cur->ds_last_pos_key.in_pos_in_object - 1, NULL, 0 );
								m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
								// append the word including "." and the following sign
								m_send_data( ach_word - 1, in_len_word + 1, ads_output );
								if ( in_len_white_spaces > 0 ) {
									m_send_data( ach_white_spaces, in_len_white_spaces, ads_output );
								}
								m_send_data( ach_sign, in_len_sign, ads_output );

								// reset variables:
								dc_insert.m_reset();
							}
                            in_len_object = 0;
#ifndef B140716
  							bol_with_doublesign  = false;	// to prevent false parsing when syntax is like: ++b.length; or --b.length;
#endif
                        } else {
                            // reset variables:
                            in_len_object = 0;
#ifndef B140716
  							bol_with_doublesign  = false;	// to prevent false parsing when syntax is like: ++b.length; or --b.length;
#endif
                        }
                        continue; // -> get next word
                    case 'p':       // case of "++"
                    case 'm':       // case of "--"
                        // reset variables:
                        in_len_object = 0;
#ifndef B140716
						bol_with_doublesign = true;
#endif
                        continue; // -> get next word
                }
                if ( in_len_object == 0 ) {
                    // if no object exists ( i.e. eval(..) ), insert position is pos of found word:
                    in_pos_insert = in_word_pos;
                }
                /*+--------------+*/
                /*| get argument |*/
                /*+--------------+*/
                in_func_return = m_get_argument( ach_data, in_len_data, &in_position, ach_sign[adsc_var_cur->in_sign_pos], &ach_argument, &in_len_argument );

				switch ( in_func_return ) {
                    case SCRIPT_NO_ARG:
                        // we must also save data, because in next step we must search for argument again!
                        // break is missing on purpose!!!
                    case SCRIPT_ARG_PARTIAL:
                        if ( !bo_data_complete ) {
                            // save data:
                            adsc_var_cur->ds_sign.m_write( ach_sign, in_len_sign );
                            adsc_var_cur->ds_word.m_write( ach_word, in_len_word );
                            adsc_var_cur->ds_object.m_write( ach_object, in_len_object );
                            adsc_var_cur->ds_spaces.m_write( ach_white_spaces, in_len_white_spaces );
                            adsc_var_cur->ds_argument.m_write( ach_argument, in_len_argument );
                            m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert and return
                            adsc_var_cur->in_state = SCRIPT_CUT_ARGUMENT;
                            return in_ret; // -> exit
                        } else {
                            // otherwise don't exit, we must change our data!!!
                            break; // -> continue after this switch
                        }
                    case SCRIPT_ARG_COMPLETE:
                        break; // -> continue after this switch
                }

                if ( ach_argument[0] == '/' ) {
                    // argument seems to be a regular expression
                    continue; // get next word
                }

                if ( m_is_sign_bracket(ach_sign[adsc_var_cur->in_sign_pos]) ) {
                    // check sign after argument:
                    in_pos_arg_sign = in_position;
                    in_func_return = m_get_next_sign( ach_data, in_len_data, &in_pos_arg_sign, &ach_arg_sign, &in_len_arg_sign, NULL, &ach_arg_spaces, &in_len_arg_spaces );
                    switch ( in_func_return ) {
                        case SCRIPT_NO_SIGN:
                            if ( !bo_data_complete ) {
                                // save data:
                                adsc_var_cur->ds_arg_sign.m_write( ach_arg_sign, in_len_arg_sign );
                                adsc_var_cur->ds_sign.m_write( ach_sign, in_len_sign );
                                adsc_var_cur->ds_word.m_write( ach_word, in_len_word );
                                adsc_var_cur->ds_object.m_write( ach_object, in_len_object );
                                adsc_var_cur->ds_spaces.m_write( ach_white_spaces, in_len_white_spaces );
                                adsc_var_cur->ds_arg_spaces.m_write( ach_arg_spaces, in_len_arg_spaces );
                                adsc_var_cur->ds_argument.m_write( ach_argument, in_len_argument );
                                m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert and return
                                adsc_var_cur->in_state = SCRIPT_CUT_ARG_SIGN;
                                return in_ret; // -> exit
                            } else {
                                // otherwise don't exit, we must change our data!!!
                                break; // -> continue after this switch
                            }
                            break;
                        case SCRIPT_SIGN_FOUND:
                            break; // -> continue after this switch
                    }                    
                    if ( in_len_arg_sign > 1 ) {
                        // after argument, only the first occuring sign is important! 
                        // so don't move data more than one sign!
                        in_pos_arg_sign -= ( in_len_arg_sign - 1 ); 
                    }
                    // remove first and last bracket from ach_argument
                    (ach_argument)++;
                    in_len_argument -= 2;

                    // MJ 15.09.10, Ticket[20581]:
                    if (    in_len_arg_sign == 1
                         && ach_arg_sign[0] == '/' ) {
                        switch( ach_sign[adsc_var_cur->in_sign_pos] ) {
                            case '(':
                                adsc_var_cur->ch_last_sign = ')';
                                break;
                            case '[':
                                adsc_var_cur->ch_last_sign = ']';
                                break;
                            case '?':
								adsc_var_cur->ch_last_sign = ':';
                                break;
                        }
                    }
                    // end MJ 15.09.10
                } else {
                    in_len_arg_sign = 0;
                }

                // get cases like "document['URL'] = 'http://...'":
                if ( ach_sign[adsc_var_cur->in_sign_pos] == '[' ) {
                    in_arg_key = m_is_argument_in_attr_list( ach_argument, in_len_argument );
                    if ( in_arg_key > -1 ) {
                        adsc_var_cur->ds_word.m_write( &ach_argument[1], in_len_argument - 2 );
                        if ( in_len_object > 0 && ach_object != NULL ) {
                            dc_insert.m_write( ach_object, in_len_object );
                        }
                        dc_insert.m_write( ach_word, in_len_word );
                        dc_insert.m_write( "." );
                        in_len_object = dc_insert.m_get_len();
                        if ( in_position >= in_len_data ) {
                            if ( m_is_word_attribute( in_arg_key ) && in_arg_key != ds_attributes::ied_scr_attr_value ) {
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                dc_temp = dc_insert;
                                m_build_HOB_get_attr( &dc_insert, dc_temp.m_get_ptr(), dc_temp.m_get_len(), &ach_argument[1], in_len_argument - 2, NULL, 0 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                // reset variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                adsc_var_cur->ds_last_pos_key.in_key = -2;
                            } else if ( m_is_word_object( in_arg_key ) && in_arg_key != ds_attributes::ied_scr_attr_all ) {
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                dc_temp = dc_insert;
                                m_build_HOB_object( &dc_insert, dc_temp.m_get_ptr(), dc_temp.m_get_len(), &ach_argument[1], in_len_argument - 2, NULL, 0 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                // reset variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                adsc_var_cur->ds_last_pos_key.in_key = -2;
                            }
                        } else {
                            adsc_var_cur->ds_object.m_write( dc_insert.m_get_ptr(), in_len_object );
                            adsc_var_cur->in_state = SCRIPT_CUT_WORD;
                        }
                        continue;
                    } else if ( in_word_key == ds_attributes::ied_scr_attr_style && in_len_arg_sign == 1 && ach_arg_sign[0] == '=' ) {
                        // document.getElementById("id").style[property] = "value"
                        // is more browser compatible then document.getElementById("id").style.property = "value"
                        // => insert a special function "HOB_set_style(...)"
                        if ( in_position < in_len_data ) {
                            if ( in_len_object == 0 ) {
                                ach_object = ach_word;
                            }
                            in_len_object += in_len_word;
                            ach_word    = ach_argument;
                            in_len_word = in_len_argument;
                            in_position = in_pos_arg_sign;
                            adsc_var_cur->in_state = SCRIPT_SPEC_STYLE;
                        }
                        continue;
                    }
                }

                
                if ( in_len_argument > MIN_SIZE_FOR_RECURSIVE_CALL ) {
                    if ( dsc_variables.m_size() < MAX_NUM_OF_RECURSIVE_CALLS - 1 ) {
                        /*+------------------------------+*/
                        /*| call m_parse_data RECURSIVE: |*/
                        /*+------------------------------+*/
                        // get memory for ds_scriptvariables:
                        ads_tempvars = (ds_scriptvariables*)ads_session->ads_wsp_helper->m_cb_get_memory( in_len_vars, false );
#ifdef TRACE_MEMORY
                        m_trace_memory( ads_tempvars, in_len_vars, false );
#endif // TRACE_MEMORY
                        // put ds_scriptvariables in this memory:
                        ads_tempvars = new(ads_tempvars) ds_scriptvariables( ads_session->ads_wsp_helper );
#if 0 // MJ 16.09.10 Ticket [20581]
                        // MJ 26.05.09, Ticket[17724]:
                        if ( in_len_sign > 0 ) {
                            ads_tempvars->ch_last_sign = ach_sign[in_len_sign - 1];
                        }
#endif
                        dsc_variables.m_stack_push(ads_tempvars);
                        ads_tempvars = NULL;
                        m_parse_data( ach_argument, in_len_argument, true, &ds_changed_arg );  // output is written into ds_changed_arg!
                        adsc_var_cur = dsc_variables.m_stack_current();
                        if ( ds_changed_arg.m_get_len() > in_len_argument ) {
                            ach_argument    = ds_changed_arg.m_get_ptr();
                            in_len_argument = ds_changed_arg.m_get_len();
                            bo_arg_changed  = true;
                        }
                    } else {
                        ads_session->ads_wsp_helper->m_log( ied_sdh_log_error,
                                                            "HWSGE204E: stack-size reached limit - no recursive call" );
                    }
                }

                /*+-----------------------------+*/
                /*| change data (if necessary): |*/
                /*+-----------------------------+*/
                if ( m_is_word_attribute( in_word_key ) 
#if SM_USE_ATTRIBUTE_LENGTH
                    && in_word_key != ds_attributes::ied_scr_attr_length
#endif
                    && ach_sign[adsc_var_cur->in_sign_pos] == '=' ) {
                    m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                    m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                    // send HOB_set_attribute:
                    m_build_HOB_set_attr( &dc_insert, adsc_var_cur->in_append_data, ach_object, in_len_object, ach_word, in_len_word, in_word_key, ach_argument, in_len_argument );
                    m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                    dc_insert.m_reset();
                    // reset variables:
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    in_len_object = 0;
#ifndef B140716
					bol_with_doublesign = false;
#endif

                } else if ( m_is_word_function( in_word_key, ach_sign[adsc_var_cur->in_sign_pos] ) ) {
                    if ( adsc_var_cur->ds_last_pos_key.in_key > -1 && adsc_var_cur->ds_last_pos_key.in_key != ds_attributes::ied_scr_attr_location ) {
                        adsc_var_cur->ds_last_pos_key.in_key = -1;
                        m_build_HOB_get_attr( &dc_insert, ach_object, adsc_var_cur->ds_last_pos_key.in_pos_in_object, &ach_object[adsc_var_cur->ds_last_pos_key.in_pos_in_object], adsc_var_cur->ds_last_pos_key.in_length, ".", 1 );
						
						if(	! (	dc_insert.m_ends_with(".") && ach_object[adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1] == '.' ) )
						{
							dc_insert.m_write( &ach_object[adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1], in_len_object - (adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1) );
						}
						
						dc_temp = dc_insert;
                        ach_object = dc_temp.m_get_ptr();
                        in_len_object = dc_temp.m_get_len();
                    }
                    m_build_HOB_function( &dc_insert, ach_data, ach_object, in_len_object, ach_word, in_len_word, in_word_key, ach_argument, in_len_argument );
                    // check if our function must be nested:
					if ( in_len_arg_sign > 0 ) {
						switch (ach_arg_sign[0]) {
						case '.':
							if ( in_word_key != ds_attributes::ied_scr_attr_tags ) {
								dc_insert.m_write( "." );
								adsc_var_cur->ds_object.m_write( dc_insert.m_get_ptr(), dc_insert.m_get_len() );
								in_position = in_pos_arg_sign;
								adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
							}
							goto LBL_TEST01;
						case '[':
							adsc_var_cur->ds_object.m_write( dc_insert.m_get_ptr(), dc_insert.m_get_len() );
							adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
							goto LBL_TEST01;
						default:
							break;
						}
					}
					// send HOB_function:
					m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
					m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
					m_move_char_pointer( &ach_data, &in_len_data, &in_position );
LBL_TEST01:
					// reset some variables:
                    in_len_object = 0;
#ifndef B140716
					bol_with_doublesign = false;
#endif
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    dc_insert.m_reset();

                } else if ( m_is_word_object( in_word_key, ach_argument, in_len_argument ) && ach_sign[adsc_var_cur->in_sign_pos] == '[' ) {
                    m_build_HOB_object( &dc_insert, ach_object, in_len_object, ach_word, in_len_word,  ach_sign, in_len_sign );
                    dc_insert.m_write( ach_argument, in_len_argument );
                    dc_insert.m_write( "]" );
                    // check if our object must be nested:
                    if ( in_len_arg_sign > 0 && ach_arg_sign[0] == '.' ) {
                        dc_insert.m_write( "." );
                        adsc_var_cur->ds_object.m_write( dc_insert.m_get_ptr(), dc_insert.m_get_len() );
                        m_send_data( ach_data, in_pos_insert, ads_output );
                        in_pos_insert = 0;
                        in_position = in_pos_arg_sign;
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                    } else if ( in_len_arg_sign > 0 && ach_arg_sign[0] == '[' ) {
                        adsc_var_cur->ds_object.m_write( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                    } else {
                        // send HOB_object:
                        m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                    }
                    // reset some variables:
                    in_len_object = 0;
#ifndef B140716
					bol_with_doublesign = false;
#endif
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    dc_insert.m_reset();

#if 0
                } else if ( in_word_key == ds_attributes::ied_scr_attr_with && ach_sign[adsc_var_cur->in_sign_pos] == '(' ) {
                    // case of "with(object) { ... }":
                    m_add_withobject( ach_argument, in_len_argument, (ach_arg_sign[0] == '{') );
                    if ( ach_arg_sign[0] == '{' ) {
                        in_position = in_pos_arg_sign;
                    } 
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    in_len_object = 0;
#endif

                } else {
                    // word is NOT in list
                    if ( adsc_var_cur->ds_last_pos_key.in_key > -1 ) {
                        adsc_var_cur->ds_last_pos_key.in_key = -1;
                        m_build_HOB_get_attr( &dc_insert, ach_object, adsc_var_cur->ds_last_pos_key.in_pos_in_object, &ach_object[adsc_var_cur->ds_last_pos_key.in_pos_in_object], adsc_var_cur->ds_last_pos_key.in_length, ".", 1 );
                        dc_insert.m_write( &ach_object[adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1], in_len_object - (adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1) );
                        dc_insert.m_write( ach_word, in_len_word );
                        dc_insert.m_write( ach_sign, in_len_sign );
                        dc_insert.m_write( ach_argument, in_len_argument );
                        
                        switch(ach_sign[adsc_var_cur->in_sign_pos]) {
					    case '(':
                            dc_insert.m_write( ")" );
						    break;
					    case '[':
                            dc_insert.m_write( "]" );
						    break;
					    case '?':
						    dc_insert.m_write( ":" );
						    break;
					    default:
						    break;
                        }
                        if ( m_is_sign_bracket(ach_sign[adsc_var_cur->in_sign_pos]) &&  in_len_arg_sign > 0 && ach_arg_sign[0] == '.' ) {
                            // check if function must be nested:
                            dc_insert.m_write( "." );
                            adsc_var_cur->ds_object.m_set( dc_insert );
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                            in_position   = in_pos_arg_sign;
                        } else if ( m_is_sign_bracket(ach_sign[adsc_var_cur->in_sign_pos]) && in_len_arg_sign > 0 && ach_arg_sign[0] == '[' ) {
                            adsc_var_cur->ds_object.m_set( dc_insert );
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                        } else {
                            m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                            m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                            m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        }
                        // reset some variables:
                        in_len_object = 0;
#ifndef B140716
						bol_with_doublesign = false;
#endif
                        dc_insert.m_reset();
                    }
                    else if ( bo_arg_changed ) {
                        // if argument was changed (in recursiv call), we must insert the changed argument!
                        bo_arg_changed = false;
                        m_build_string( &dc_insert, ach_object, in_len_object, ach_word, in_len_word, ach_sign, in_len_sign, ach_argument, in_len_argument );
						switch(ach_sign[adsc_var_cur->in_sign_pos]) {
						case '(':
                            dc_insert.m_write( ")" );
							break;
						case '[':
                            dc_insert.m_write( "]" );
							break;
						case '?':
							dc_insert.m_write( ":" );
							break;
						default:
							break;
						}
                        if ( m_is_sign_bracket(ach_sign[adsc_var_cur->in_sign_pos]) &&  in_len_arg_sign > 0 && ach_arg_sign[0] == '.' ) {
                            // check if function must be nested:
                            dc_insert.m_write( "." );
                            adsc_var_cur->ds_object.m_set( dc_insert );
                            in_position   = in_pos_arg_sign;
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                        } else if ( m_is_sign_bracket(ach_sign[adsc_var_cur->in_sign_pos]) && in_len_arg_sign > 0 && ach_arg_sign[0] == '[' ) {
                            //m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                            adsc_var_cur->ds_object.m_set( dc_insert );
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                        } else {
                            m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                            m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                            m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        }
                        // reset some variables:
                        in_len_object = 0;
#ifndef B140716
						bol_with_doublesign = false;
#endif
                        dc_insert.m_reset();
                    } else if ( m_is_sign_bracket(ach_sign[adsc_var_cur->in_sign_pos]) && in_len_arg_sign > 0 && ach_arg_sign[0] == '.' ) {
                        // otherwise check for nested function!
                        in_position   = in_pos_arg_sign;
                        if ( in_len_object == 0 ) {
                            ach_object = ach_word;
                        }
                        in_len_object = in_position - in_pos_insert;
                    } else if ( m_is_sign_bracket(ach_sign[adsc_var_cur->in_sign_pos]) && in_len_arg_sign > 0 && ach_arg_sign[0] == '[' ) {
                        if ( in_len_object == 0 ) {
                            ach_object = ach_word;
                        }
                        in_len_object = in_position - in_pos_insert;
                    } else if ( m_is_sign_bracket(ach_sign[adsc_var_cur->in_sign_pos]) && in_len_arg_sign > 0 && ach_arg_sign[0] == '(' ) {
						if( bol_is_condition )
						{
							in_len_object = 0;
#ifndef B140716
							bol_with_doublesign = false;
#endif
						}
						else
						{
							if ( in_len_object == 0 ) {
								ach_object = ach_word;
							}
							in_len_object = in_position - in_pos_insert;
						}
                    } else {
                        in_len_object = 0;
#ifndef B140716
						bol_with_doublesign = false;
#endif
                    }
                }
                ds_changed_arg.m_reset();
                break;
			case SCRIPT_CASE_STATEMENT:
				// hofmants: ignore the expression behind case and before ':' sign
				// eg: case "Empfänger:".replace(":", ""):
				// -> this will lead to wrong parsing
				// dont think this case will never ever happen... i implemented it because this nonsense was in iNotes...
				if( m_handle_funny_cases( ach_data, in_len_data, &in_position ) )
				{
					in_len_object = 0;
#ifndef B140716
					bol_with_doublesign = false;
#endif
					in_position++;
					adsc_var_cur->in_state = SCRIPT_NORMAL;
				}
				else // write current data to output
				{
					in_pos_insert = in_position ;
				}
				break;
// ----------------------------------------------------------------------------
// ignore the command line:
// ----------------------------------------------------------------------------
            case SCRIPT_IGNORE_COMMAND:
                switch ( ach_data[in_position] ) {
                    case '\n':
                    case '\r':
                    case '}':
                    case ';':
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                        break;

                    default:                        
                        break;
                }
                in_position++;
                break;

// ----------------------------------------------------------------------------
// handle cut word:
// ----------------------------------------------------------------------------
            case SCRIPT_CUT_WORD:
                /*+----------+*/
                /*| get word |*/
                /*+----------+*/
                in_func_return = m_get_next_word( ach_data, in_len_data, &in_position, in_word_key, &ach_word, &in_len_word, &in_word_pos, true );
                switch ( in_func_return ) {
                    case SCRIPT_NO_WORD:
                        ads_session->ads_wsp_helper->m_log( ied_sdh_log_warning,
                                                            "HWSGE201E: impractical state in ds_interpret_script::m_get_next_word" );
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                        // free memory:
                        m_free_all_data();
                        m_free_vars();
                        return in_ret; // -> exit
                    case SCRIPT_WORD_PARTIAL:
                        if ( !bo_data_complete ) {
                            adsc_var_cur->ds_word.m_write( ach_word, in_len_word );
                        } else {
                            adsc_var_cur->ds_word.m_write( ach_word, in_len_word );
                            in_word_key = m_is_word_in_list( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() );
                            if ( m_is_word_attribute( in_word_key ) && in_word_key != ds_attributes::ied_scr_attr_value ) {
                                if ( in_len_object == 0 ) {
                                    in_pos_insert = in_word_pos;
                                }
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_build_HOB_get_attr( &dc_insert, ach_object, in_len_object, adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), NULL, 0);
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                dc_insert.m_reset();
                            } else if ( m_is_word_object( in_word_key ) && in_word_key != ds_attributes::ied_scr_attr_all ) {
                                if ( in_len_object == 0 ) {
                                    in_pos_insert = in_word_pos;
                                }
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_build_HOB_object( &dc_insert, ach_object, in_len_object, adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), NULL, 0 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                dc_insert.m_reset();
                            } else {
                                m_send_data( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), ads_output );
                                m_send_data( ach_data, in_len_data, ads_output );
                            }
                            // free memory:
                            m_free_all_data();
                            m_free_vars();
                        }
                        return in_ret; // -> exit
                    case SCRIPT_WORD_COMPLETE:
                        adsc_var_cur->ds_word.m_write( ach_word, in_len_word );
                        break; // -> continue after this switch
                }
                in_word_key = m_is_word_in_list( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() );
                /*+----------+*/
                /*| get sign |*/
                /*+----------+*/
                in_func_return = m_get_next_sign( ach_data, in_len_data, &in_position, &ach_sign, &in_len_sign, &adsc_var_cur->in_sign_pos, &ach_white_spaces, &in_len_white_spaces );
                switch ( in_func_return ) {
                    case SCRIPT_NO_SIGN:
                        if ( !bo_data_complete ) {
                            // save sign and white spaces (rest is already saved):
                            adsc_var_cur->ds_sign.m_write( ach_sign, in_len_sign );
                            adsc_var_cur->ds_spaces.m_write( ach_white_spaces, in_len_white_spaces );
                            m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                            adsc_var_cur->in_state = SCRIPT_CUT_SIGN;
                        } else {
                            // if bo_data_complete == true, send word, object, white spaces and rest of data
                            m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_spaces.m_get_ptr(), adsc_var_cur->ds_spaces.m_get_len(), ach_sign, in_len_sign );
                            m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                            m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                            m_send_data( ach_data, in_len_data, ads_output ); // send rest of data and return
                            // free memory:
                            m_free_all_data();
                            m_free_vars();
                        }
                        return in_ret; // -> exit
                    case SCRIPT_SIGN_FOUND:
                        break; // -> continue after this switch
                }
                
                if ( in_word_key == ds_attributes::ied_scr_attr_function || in_word_key == ds_attributes::ied_scr_attr_var ) {
                    in_word_key = -1; //continue;
                }

                switch ( ach_sign[adsc_var_cur->in_sign_pos] ) {
                    case '.':
                        // for case like "document.location.href.indexOf('foo')"
                        if ( m_is_word_attribute(in_word_key) && m_rec_attribute(in_word_key) ) {
                            adsc_var_cur->ds_last_pos_key.in_key = in_word_key;
                            adsc_var_cur->ds_last_pos_key.in_pos_in_object = adsc_var_cur->ds_object.m_get_len();
                            adsc_var_cur->ds_last_pos_key.in_length = adsc_var_cur->ds_word.m_get_len();
                        } else if ( m_is_word_object(in_word_key) && m_rec_object(in_word_key) ) {
                            // for case like "document.firstChild.id  ... "
                            m_build_HOB_object( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), ach_sign, in_len_sign );
                            m_free_all_data();
                            adsc_var_cur->ds_object.m_write( dc_insert );
                            m_send_data( ach_data, in_pos_insert, ads_output );
                            m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                            // reset some variables:
                            in_pos_insert = 0;
                            dc_insert.m_reset();
                            adsc_var_cur->ds_last_pos_key.in_key = -2;
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                            continue; // -> handle saved object
                        }

                        adsc_var_cur->ds_object.m_write( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() );
                        adsc_var_cur->ds_object.m_write( ".", 1 );
                        adsc_var_cur->ds_word.m_reset();
                        adsc_var_cur->ds_spaces.m_reset();

                        if ( in_position < in_len_data ) {
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                            continue; // -> get next word
                        } else {
                            if ( bo_data_complete ) {
                                ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                                                    "HWSGI202I: found dot at end of data in ds_interpret_script::m_parse_data" );
                                m_send_data( ach_data, in_len_data, ads_output ); // send hole data
                                // free memory:
                                m_free_all_data();
                                m_free_vars();
                            } else {
                                m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert and return
                                adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                            }
                            return in_ret; // -> exit
                        }
                    case '(':
                    case '[':
                        in_position--;  // argument search need the bracket in this case ( ... argument ... )
                        break; // -> continue after this switch: get argument
                    case '?':
                        in_position--;  // argument search need the bracket in this case ( ... argument ... )
                        break;  // -> continue after this switch: get argument
                    case '=':
                        m_pass_signs( ach_data, in_len_data, &in_position, " \n\r\t\v\f" );
                        break; // -> continue after this switch: get argument
                    case '"':
                        // send object, word, white spaces and rch_sign:
                        m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_spaces.m_get_ptr(), adsc_var_cur->ds_spaces.m_get_len(), &ach_sign[adsc_var_cur->in_sign_pos], 1  );
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        m_free_all_data();
                        // reset some variables:
                        in_len_object = 0;
#ifndef B140716
						bol_with_doublesign = false;
#endif
                        dc_insert.m_reset();
                        adsc_var_cur->in_state = SCRIPT_DOUBLE_QUOTES;
                        continue; // -> handle double quotes
                    case '\'':
                        // send object, word, white spaces and rch_sign:
                        m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_spaces.m_get_ptr(), adsc_var_cur->ds_spaces.m_get_len(), &ach_sign[adsc_var_cur->in_sign_pos], 1 );
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        m_free_all_data();
                        // reset some variables:
                        in_len_object = 0;
#ifndef B140716
						bol_with_doublesign = false;
#endif
                        dc_insert.m_reset();
                        adsc_var_cur->in_state = SCRIPT_SINGLE_QUOTES;
                        continue; // -> handle single quotes
                    case '/':
                        in_func_return = m_is_slash_comment( ach_data, in_len_data, &in_position );
                        switch ( in_func_return ) {
                            case SCRIPT_NOT_DECIDED:
                                // send object, word, white spaces and rch_sign:
                                m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_spaces.m_get_ptr(), adsc_var_cur->ds_spaces.m_get_len(), &ach_sign[adsc_var_cur->in_sign_pos], 1 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                m_free_all_data();
                                m_send_data( ach_data, in_len_data, ads_output );
                                if ( bo_data_complete ) {
                                    // free memory:
                                    m_free_vars();
                                } else {
                                    adsc_var_cur->in_state = SCRIPT_CUT_AFTER_SLASH;
                                }
                                return in_ret;
                            case SCRIPT_ASTERISK_COMMENT:
                                // send object, word, white spaces and rch_sign:
                                m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_spaces.m_get_ptr(), adsc_var_cur->ds_spaces.m_get_len(), &ach_sign[adsc_var_cur->in_sign_pos], 1, "*", 1 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                m_free_all_data();
                                // reset some variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                adsc_var_cur->in_state = SCRIPT_C_COMMENT_1;
                                continue; // -> handle "/*...*/" comment
                            case SCRIPT_SLASH_COMMENT:
                                // send object, word, white spaces and rch_sign:
                                m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_spaces.m_get_ptr(), adsc_var_cur->ds_spaces.m_get_len(), &ach_sign[adsc_var_cur->in_sign_pos], 1, "/", 1 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                m_free_all_data();
                                // reset some variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                adsc_var_cur->in_state = SCRIPT_CPP_COMMENT;
                                continue; // -> handle "//..." comment
                            case SCRIPT_NO_COMMENT:
                                break; // goto default case
                        }
                        // break is missing on purpose!!!
                    default:
                        if ( m_is_word_attribute( in_word_key ) && in_word_key != ds_attributes::ied_scr_attr_value ) {
                            m_send_data( ach_data, in_pos_insert, ads_output );
                            m_build_HOB_get_attr( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), ach_sign, in_len_sign );
                            m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                            dc_insert.m_reset();
                            m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                            adsc_var_cur->ds_last_pos_key.in_key = -2;
                        } else if ( in_word_key == ds_attributes::ied_scr_attr_new ) {
                            adsc_var_cur->ds_object.m_write( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() );
                            adsc_var_cur->ds_object.m_write( " ", 1 );
                            adsc_var_cur->ds_word.m_reset();
                            adsc_var_cur->ds_spaces.m_reset();
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                            continue; // -> get next word
                        } else if ( adsc_var_cur->ds_last_pos_key.in_key > -1 ) {
                            adsc_var_cur->ds_last_pos_key.in_key = -2;
                        } else {
                            m_send_data( ach_data, in_pos_insert, ads_output );
                            m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), ach_white_spaces, in_len_white_spaces, ach_sign, in_len_sign );
                            m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                            m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                            dc_insert.m_reset();
                        }
                        // reset variables:
                        m_free_all_data();
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                        continue; // -> get next word
                    case 'p':       // case of "++"
                    case 'm':       // case of "--"
                        m_send_data( ach_data, in_pos_insert, ads_output );
                        m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), ach_white_spaces, in_len_white_spaces, ach_sign, in_len_sign );
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
#ifndef B140716
						bol_with_doublesign = true;
#endif
                        dc_insert.m_reset();
                        // reset variables:
                        m_free_all_data();
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                        continue; // -> get next word
                }
                if ( in_len_object == 0 ) {
                    // if no object exists ( i.e. eval(..) ), insert position is pos of found word:
                    in_pos_insert = in_word_pos;
                }
                /*+--------------+*/
                /*| get argument |*/
                /*+--------------+*/
                in_func_return = m_get_argument( ach_data, in_len_data, &in_position, ach_sign[adsc_var_cur->in_sign_pos], &ach_argument, &in_len_argument );
                switch ( in_func_return ) {
                    case SCRIPT_NO_ARG:
                        // we must also save data, because in next step we must search for argument again!
                        // therefore, break is missing on purpose!!!
                    case SCRIPT_ARG_PARTIAL:
                        if ( !bo_data_complete ) {
                            // save argument and sign ( rest is already saved )
                            adsc_var_cur->ds_sign.m_write( ach_sign, in_len_sign );
                            adsc_var_cur->ds_argument.m_write( ach_argument, in_len_argument );
                            m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert and return
                            adsc_var_cur->in_state = SCRIPT_CUT_ARGUMENT;
                            return in_ret; // -> exit
                        } else {
                            // otherwise don't exit, we must change our data!!!
                            break; // -> continue after this switch
                        }
                    case SCRIPT_ARG_COMPLETE:
                        break; // -> continue after this switch
                }

                if ( m_is_sign_bracket(ach_sign[adsc_var_cur->in_sign_pos]) ) { 
                    // check sign after argument:
                    in_pos_arg_sign = in_position;
                    in_func_return = m_get_next_sign( ach_data, in_len_data, &in_pos_arg_sign, &ach_arg_sign, &in_len_arg_sign, NULL, &ach_arg_spaces, &in_len_arg_spaces );
                    switch ( in_func_return ) {
                        case SCRIPT_NO_SIGN:
                            if ( !bo_data_complete ) {
                                // save argument, sign and arg_sign ( rest is already saved )
                                adsc_var_cur->ds_sign.m_write    ( ach_sign, in_len_sign );
                                adsc_var_cur->ds_arg_sign.m_write( ach_arg_sign, in_len_arg_sign );
                                adsc_var_cur->ds_argument.m_write( ach_argument, in_len_argument );
                                adsc_var_cur->ds_arg_spaces.m_write( ach_arg_spaces, in_len_arg_spaces );
                                m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert and return
                                adsc_var_cur->in_state = SCRIPT_CUT_ARG_SIGN;
                                return in_ret; // -> exit
                            } else {
                                // otherwise don't exit, we must change our data!!!
                                break; // -> continue after this switch
                            }
                            break;
                        case SCRIPT_SIGN_FOUND:
                            break; // -> continue after this switch
                    }
                    if ( in_len_arg_sign > 1 ) {
                        // after argument, only the first occuring sign is important! 
                        // so don't move data more than one sign!
                        in_pos_arg_sign -= ( in_len_arg_sign - 1 ); 
                    }
                    // remove first and last bracket from ach_argument
                    (ach_argument)++;
                    in_len_argument -= 2;
                } else {
                    in_len_arg_sign = 0;
                }

                // get cases like "document['URL'] = 'http://...'":
                if ( ach_sign[adsc_var_cur->in_sign_pos] == '[' ) {
                    in_arg_key = m_is_argument_in_attr_list( ach_argument, in_len_argument );
                    if ( in_arg_key > -1 ) {
                        if ( adsc_var_cur->ds_object.m_get_len() > 0 ) {
                            dc_insert.m_write( adsc_var_cur->ds_object );
                            adsc_var_cur->ds_object.m_reset();
                        }
                        dc_insert.m_write( adsc_var_cur->ds_word );
                        dc_insert.m_write( "." );
                        in_len_object = dc_insert.m_get_len();
                        adsc_var_cur->ds_word.m_reset();
                        adsc_var_cur->ds_word.m_write( &ach_argument[1], in_len_argument - 2 );
                        if ( in_position >= in_len_data ) {
                            if ( m_is_word_attribute( in_arg_key ) && in_arg_key != ds_attributes::ied_scr_attr_value ) {
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                dc_temp = dc_insert;
                                m_build_HOB_get_attr( &dc_insert, dc_temp.m_get_ptr(), dc_temp.m_get_len(), &ach_argument[1], in_len_argument - 2, NULL, 0 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                // reset variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                adsc_var_cur->ds_last_pos_key.in_key = -2;
                            } else if ( m_is_word_object( in_arg_key ) && in_arg_key != ds_attributes::ied_scr_attr_all ) {
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                m_build_HOB_object( &dc_insert, dc_insert.m_get_ptr(), dc_insert.m_get_len(), &ach_argument[1], in_len_argument - 2, NULL, 0 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                // reset variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                adsc_var_cur->ds_last_pos_key.in_key = -2;
                            }
                        } else {
                            adsc_var_cur->ds_object.m_write( dc_insert.m_get_ptr(), in_len_object );
                            adsc_var_cur->in_state = SCRIPT_CUT_WORD;
                        }
                        continue;
                    } else if ( in_word_key == ds_attributes::ied_scr_attr_style && in_len_arg_sign == 1 && ach_arg_sign[0] == '=' ) {
                        // document.getElementById("id").style[property] = "value"
                        // is more browser compatible then document.getElementById("id").style.property = "value"
                        // => insert a special function "HOB_set_style(...)"
                        if ( in_position < in_len_data ) {
                            adsc_var_cur->ds_object.m_write( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() );
                            adsc_var_cur->ds_word.m_set( ach_argument, in_len_argument );
                            in_position = in_pos_arg_sign;
                            adsc_var_cur->in_state = SCRIPT_CUT_SPEC_STYLE;
                        }
                        continue;
                    }
                }
                
                if ( in_len_argument > MIN_SIZE_FOR_RECURSIVE_CALL ) {
                    if ( dsc_variables.m_size() < MAX_NUM_OF_RECURSIVE_CALLS - 1 ) {
                        /*+------------------------------+*/
                        /*| call m_parse_data RECURSIVE: |*/
                        /*+------------------------------+*/
                        // get memory for ds_scriptvariables:
                        ads_tempvars = (ds_scriptvariables*)ads_session->ads_wsp_helper->m_cb_get_memory( in_len_vars, false );
#ifdef TRACE_MEMORY
                        m_trace_memory( ads_tempvars, in_len_vars, false );
#endif // TRACE_MEMORY
                        // put ds_scriptvariables in this memory:
                        ads_tempvars = new(ads_tempvars) ds_scriptvariables( ads_session->ads_wsp_helper );
                        // MJ 26.05.09, Ticket[17724]:
                        if ( in_len_sign > 0 ) {
                            ads_tempvars->ch_last_sign = ach_sign[in_len_sign - 1]; 
                        }
                        dsc_variables.m_stack_push(ads_tempvars);
                        ads_tempvars = NULL;
                        m_parse_data( ach_argument, in_len_argument, true, &ds_changed_arg );  //output is written into ds_changed_arg!
                        adsc_var_cur = dsc_variables.m_stack_current();
                        if ( ds_changed_arg.m_get_len() > in_len_argument ) {
                            ach_argument    = ds_changed_arg.m_get_ptr();
                            in_len_argument = ds_changed_arg.m_get_len();
                        }
                    } else {
                        ads_session->ads_wsp_helper->m_log( ied_sdh_log_error,
                                                            "HWSGE205E: stack-size reached limit - no recursive call" );
                    }
                }

                /*+-----------------------------+*/
                /*| change data (if necessary): |*/
                /*+-----------------------------+*/
                if ( m_is_word_attribute( in_word_key )
#if SM_USE_ATTRIBUTE_LENGTH
                    && in_word_key != ds_attributes::ied_scr_attr_length
#endif
                    && ach_sign[adsc_var_cur->in_sign_pos] == '=' )
                {
                    m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                    m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                    // send HOB_set_attribute
                    m_build_HOB_set_attr( &dc_insert, adsc_var_cur->in_append_data, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), in_word_key, ach_argument, in_len_argument );
                    m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                    dc_insert.m_reset();
                    m_free_all_data();
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    adsc_var_cur->in_state = SCRIPT_NORMAL;

                } else if ( m_is_word_function( in_word_key, ach_sign[adsc_var_cur->in_sign_pos] ) ) {
                    if ( adsc_var_cur->ds_last_pos_key.in_key > -1 ) {
                        adsc_var_cur->ds_last_pos_key.in_key = -1;
                        m_build_HOB_get_attr( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_last_pos_key.in_pos_in_object, &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object], adsc_var_cur->ds_last_pos_key.in_length, ".", 1 );
                        dc_insert.m_write( &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1], adsc_var_cur->ds_object.m_get_len() - (adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1) );
                        adsc_var_cur->ds_object.m_set( dc_insert );
                    }
                    m_build_HOB_function( &dc_insert, ach_data, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), in_word_key, ach_argument, in_len_argument );
                    // check if our function must be nested:
                    if ( in_len_arg_sign > 0 && ach_arg_sign[0] == '.' ) {
                        if ( in_word_key != ds_attributes::ied_scr_attr_tags ) {
                            dc_insert.m_write( "." );
                            m_free_all_data();
                            adsc_var_cur->ds_object.m_set( dc_insert );
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                            in_position   = in_pos_arg_sign;
                        }
                    } else if ( in_len_arg_sign > 0 && ach_arg_sign[0] == '[' ) {
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                    } else {
                        // send HOB_function:
                        m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                        m_free_all_data();
                    }
                    // reset some variables:
                    in_len_object = 0;
#ifndef B140716
					bol_with_doublesign = false;
#endif
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    dc_insert.m_reset();

                } else if ( m_is_word_object( in_word_key, ach_argument, in_len_argument ) && ach_sign[adsc_var_cur->in_sign_pos] == '[' ) {
                    m_build_HOB_object( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(),  ach_sign, in_len_sign );
                    dc_insert.m_write( ach_argument, in_len_argument );
                    dc_insert.m_write( "]" );
                    // check if our object must be nested:
                    if ( in_len_arg_sign > 0 && ach_arg_sign[0] == '.' ) {
                        dc_insert.m_write( "." );
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                        in_position   = in_pos_arg_sign;
                    } else if ( in_len_arg_sign > 0 && ach_arg_sign[0] == '[' ) {
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                    } else {
                        // send HOB_object:
                        m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                        m_free_all_data();
                    }
                    // reset some variables:
                    in_len_object = 0;
#ifndef B140716
					bol_with_doublesign = false;
#endif
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    dc_insert.m_reset();

#if 0
				} else if ( in_word_key == ds_attributes::ied_scr_attr_with && ach_sign[adsc_var_cur->in_sign_pos] == '(' ) {
                    // case of "with(object) { ... }":
                    m_add_withobject( ach_argument, in_len_argument, (ach_arg_sign[0] == '{') );
                    m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), ach_sign, in_len_sign, ach_argument, in_len_argument, ")", 1 );
                    m_free_all_data();
                    if ( ach_arg_sign[0] == '{' ) {
                        dc_insert.m_write( "{" );
                        in_position = in_pos_arg_sign;
                    }
                    m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                    m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                    m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                    adsc_var_cur->in_state = SCRIPT_NORMAL;
                    // reset some variables:
                    in_len_object = 0;
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    dc_insert.m_reset();
#endif
                } else {
                    // word is NOT in list, NO CHANGE!
                    if ( adsc_var_cur->ds_last_pos_key.in_key > -1 ) {
                        adsc_var_cur->ds_last_pos_key.in_key = -1;
                        m_build_HOB_get_attr( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_last_pos_key.in_pos_in_object, &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object], adsc_var_cur->ds_last_pos_key.in_length, ".", 1 );
                        dc_insert.m_write( &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1], adsc_var_cur->ds_object.m_get_len() - (adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1) );
                        dc_insert.m_write( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() );
                        dc_insert.m_write( ach_sign, in_len_sign );
                        dc_insert.m_write( ach_argument, in_len_argument );
                    } else {
                        m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), ach_sign, in_len_sign, ach_argument, in_len_argument );
                    }
                    switch(ach_sign[adsc_var_cur->in_sign_pos]) {
					case '(':
                        dc_insert.m_write( ")" );
						break;
					case '[':
                        dc_insert.m_write( "]" );
						break;
					case '?':
						dc_insert.m_write( ":" );
						break;
					default:
						break;
                    }
                    if ( m_is_sign_bracket(ach_sign[adsc_var_cur->in_sign_pos]) && in_len_arg_sign > 0 && ach_arg_sign[0] == '.' ) {
                        // check if function must be nested:
                        dc_insert.m_write( "." );
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                        in_position   = in_pos_arg_sign;
                    } else if (  m_is_sign_bracket(ach_sign[adsc_var_cur->in_sign_pos]) && in_len_arg_sign > 0 && ach_arg_sign[0] == '[' ) {
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                    } else {
                        m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        m_free_all_data();
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                    }
                    // reset some variables:
                    in_len_object = 0;
#ifndef B140716
					bol_with_doublesign = false;
#endif
                    dc_insert.m_reset();
                }
                ds_changed_arg.m_reset();
                break;

// ----------------------------------------------------------------------------
// handle cut sign:
// ----------------------------------------------------------------------------
            case SCRIPT_CUT_SIGN:
                in_word_key = m_is_word_in_list( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() );
                /*+----------+*/
                /*| get sign |*/
                /*+----------+*/
                in_func_return = m_get_next_sign( ach_data, in_len_data, &in_position, &ach_sign, &in_len_sign, &adsc_var_cur->in_sign_pos, &ach_white_spaces, &in_len_white_spaces );
                switch ( in_func_return ) {
                    case SCRIPT_NO_SIGN:
                        if ( !bo_data_complete ) {
                            // save sign and white spaces (rest is already saved):
                            adsc_var_cur->ds_sign.m_write( ach_sign, in_len_sign );
                            adsc_var_cur->ds_spaces.m_write( ach_white_spaces, in_len_white_spaces );
                            m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                            adsc_var_cur->in_state = SCRIPT_CUT_SIGN;
                        } else {
                            // if bo_data_complete == true, send word, object, white spaces, sign and rest of data
                            m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_spaces.m_get_ptr(), adsc_var_cur->ds_spaces.m_get_len(), adsc_var_cur->ds_sign.m_get_ptr(), adsc_var_cur->ds_sign.m_get_len(), ach_sign, in_len_sign );
                            m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                            m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                            m_send_data( ach_data, in_len_data, ads_output ); // send rest of data and return
                            // free memory:
                            m_free_all_data();
                            m_free_vars();
                        }
                        return in_ret; // -> exit
                    case SCRIPT_SIGN_FOUND:
                        adsc_var_cur->ds_sign.m_write( ach_sign, in_len_sign );
                        break; // -> continue after this switch
                }
                
                switch ( adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos] ) {
                    case '.':
                        // for case like "document.location.href.indexOf('foo')"
                        if ( m_is_word_attribute(in_word_key) && m_rec_attribute(in_word_key) ) {
                            adsc_var_cur->ds_last_pos_key.in_key = in_word_key;
                            adsc_var_cur->ds_last_pos_key.in_pos_in_object = adsc_var_cur->ds_object.m_get_len();
                            adsc_var_cur->ds_last_pos_key.in_length = adsc_var_cur->ds_word.m_get_len();
                        } else if ( m_is_word_object(in_word_key) && m_rec_object(in_word_key) ) {
                            // for case like "document.firstChild.id  ... "
                            m_build_HOB_object( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_sign.m_get_ptr(), adsc_var_cur->ds_sign.m_get_len() );
                            m_free_all_data();
                            adsc_var_cur->ds_object.m_write( dc_insert );
                            m_send_data( ach_data, in_pos_insert, ads_output );
                            m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                            // reset some variables:
                            in_pos_insert = 0;
                            dc_insert.m_reset();
                            adsc_var_cur->ds_last_pos_key.in_key = -2;
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                            continue; // -> handle saved object
                        }

                        adsc_var_cur->ds_object.m_write( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() );
                        adsc_var_cur->ds_object.m_write( ".", 1 );
                        adsc_var_cur->ds_word.m_reset();
                        adsc_var_cur->ds_spaces.m_reset();
                        adsc_var_cur->ds_sign.m_reset();

                        if ( in_position < in_len_data ) {
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                            continue; // -> get next word
                        } else {
                            if ( bo_data_complete ) {
                                ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                                                    "HWSGI203I: found dot at end of data in ds_interpret_script::m_parse_data" );
                                m_send_data( ach_data, in_len_data, ads_output ); // send hole data
                                // free memory:
                                m_free_all_data();
                                m_free_vars();
                            } else {
                                m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert and return
                                adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                            }
                            return in_ret; // -> exit
                        }
                    case '(':
                    case '[':
                        in_position--;  // argument search need the bracket in this case ( ... argument ... )
                        break; // -> continue after this switch: get argument
                    case '?':
                        in_position--;  // argument search need the bracket in this case ( ... argument ... )
                        break;  // -> continue after this switch: get argument
                    case '=':
                        m_pass_signs( ach_data, in_len_data, &in_position, " \n\r\t\v\f" );
                        break; // -> continue after this switch: get argument
                    case '"':
                        // send object, word, white spaces and rch_sign:
                        m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_spaces.m_get_ptr(), adsc_var_cur->ds_spaces.m_get_len(), &adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos], 1 );
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        m_free_all_data();
                        // reset some variables:
                        in_len_object = 0;
#ifndef B140716
						bol_with_doublesign = false;
#endif
                        dc_insert.m_reset();
                        adsc_var_cur->in_state = SCRIPT_DOUBLE_QUOTES;
                        continue; // -> handle double quotes
                    case '\'':
                        // send object, word, white spaces and rch_sign:
                        m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_spaces.m_get_ptr(), adsc_var_cur->ds_spaces.m_get_len(), &adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos], 1 );
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        m_free_all_data();
                        // reset some variables:
                        in_len_object = 0;
#ifndef B140716
						bol_with_doublesign = false;
#endif
                        dc_insert.m_reset();
                        adsc_var_cur->in_state = SCRIPT_SINGLE_QUOTES;
                        continue; // -> handle single quotes
                    case '/':
                        in_func_return = m_is_slash_comment( ach_data, in_len_data, &in_position );
                        switch ( in_func_return ) {
                            case SCRIPT_NOT_DECIDED:
                                // send object, word, white spaces and rch_sign:
                                m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_spaces.m_get_ptr(), adsc_var_cur->ds_spaces.m_get_len(), &adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos], 1 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                m_send_data( ach_data, in_len_data, ads_output );
                                m_free_all_data();
                                // reset some variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                if ( bo_data_complete ) {
                                    // free memory:
                                    m_free_vars();
                                } else {
                                    adsc_var_cur->in_state = SCRIPT_CUT_AFTER_SLASH;
                                }
                                return in_ret;
                            case SCRIPT_ASTERISK_COMMENT:
                                // send object, word, white spaces and rch_sign:
                                m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_spaces.m_get_ptr(), adsc_var_cur->ds_spaces.m_get_len(), &adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos], 1, "*", 1 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                m_free_all_data();
                                // reset some variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                adsc_var_cur->in_state = SCRIPT_C_COMMENT_1;
                                continue; // -> handle "/*...*/" comment
                            case SCRIPT_SLASH_COMMENT:
                                // send object, word, white spaces and rch_sign:
                                m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_spaces.m_get_ptr(), adsc_var_cur->ds_spaces.m_get_len(), &adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos], 1, "/", 1 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                m_free_all_data();
                                // reset some variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                adsc_var_cur->in_state = SCRIPT_CPP_COMMENT;
                                continue; // -> handle "//..." comment
                            case SCRIPT_NO_COMMENT:
                                break; // goto default case
                        }
                        // break is missing on purpose!!!
                    default:
                        if ( m_is_word_attribute( in_word_key ) && in_word_key != ds_attributes::ied_scr_attr_value ) {
                            m_send_data( ach_data, in_pos_insert, ads_output );
                            m_build_HOB_get_attr( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_sign.m_get_ptr(), adsc_var_cur->ds_sign.m_get_len() );
                            m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                            dc_insert.m_reset();
                            m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                            adsc_var_cur->ds_last_pos_key.in_key = -2;
                        } else if ( in_word_key == ds_attributes::ied_scr_attr_new ) {
                            adsc_var_cur->ds_object.m_write( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() );
                            adsc_var_cur->ds_object.m_write( " ", 1 );
                            adsc_var_cur->ds_word.m_reset();
                            adsc_var_cur->ds_spaces.m_reset();
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                            continue; // -> get next word
                        } else if ( adsc_var_cur->ds_last_pos_key.in_key > -1 ) {
                            adsc_var_cur->ds_last_pos_key.in_key = -2;
                        } else {
                            m_send_data( ach_data, in_pos_insert, ads_output );
                            m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_spaces.m_get_ptr(), adsc_var_cur->ds_spaces.m_get_len(), adsc_var_cur->ds_sign.m_get_ptr(), adsc_var_cur->ds_sign.m_get_len() );
                            m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                            m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                            dc_insert.m_reset();
                            in_word_key = -2; // MJ 01.12.2011, Ticket[23016]
                        }
                        // reset variables:
                        m_free_all_data();
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                        continue; // -> get next word
                    case 'p':       // case of "++"
                    case 'm':       // case of "--"
                        // reset variables:
                        m_free_all_data();
#ifndef B140716
						bol_with_doublesign = true;
#endif
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                        continue; // -> get next word
                }
                if ( in_len_object == 0 ) {
                    // if no object exists ( i.e. eval(..) ), insert position is pos of found word:
                    in_pos_insert = in_word_pos;
                }
                /*+--------------+*/
                /*| get argument |*/
                /*+--------------+*/
                in_func_return = m_get_argument( ach_data, in_len_data, &in_position, adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos], &ach_argument, &in_len_argument );
                switch ( in_func_return ) {
                    case SCRIPT_NO_ARG:
                        // we must also save data, because in next step we must search for argument again!
                        // therefore, break is missing on purpose!!!
                    case SCRIPT_ARG_PARTIAL:
                        if ( !bo_data_complete ) {
                            // save argument( rest is already saved )
                            adsc_var_cur->ds_argument.m_write( ach_argument, in_len_argument );
                            m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert and return
                            adsc_var_cur->in_state = SCRIPT_CUT_ARGUMENT;
                            return in_ret; // -> exit
                        } else {
                            // otherwise don't exit, we must change our data!!!
                            break; // -> continue after this switch
                        }
                    case SCRIPT_ARG_COMPLETE:
                        break; // -> continue after this switch
                }

                if ( m_is_sign_bracket(adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos]) ) {
                    // check sign after argument:
                    in_pos_arg_sign = in_position;
                    in_func_return = m_get_next_sign( ach_data, in_len_data, &in_pos_arg_sign, &ach_arg_sign, &in_len_arg_sign, NULL, &ach_arg_spaces, &in_len_arg_spaces );
                    switch ( in_func_return ) {
                        case SCRIPT_NO_SIGN:
                            if ( !bo_data_complete ) {
                                // save argument and arg_sign ( rest is already saved )
                                adsc_var_cur->ds_arg_sign.m_write( ach_arg_sign, in_len_arg_sign );
                                adsc_var_cur->ds_argument.m_write( ach_argument, in_len_argument );
                                adsc_var_cur->ds_arg_spaces.m_write( ach_arg_spaces, in_len_arg_spaces );
                                m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert and return
                                adsc_var_cur->in_state = SCRIPT_CUT_ARG_SIGN;
                                return in_ret; // -> exit
                            } else {
                                // otherwise don't exit, we must change our data!!!
                                break; // -> continue after this switch
                            }
                            break;
                        case SCRIPT_SIGN_FOUND:
                            break; // -> continue after this switch
                    }                            
                    if ( in_len_arg_sign > 1 ) {
                        // after argument, only the first occuring sign is important! 
                        // so don't move data more than one sign!
                        in_pos_arg_sign -= ( in_len_arg_sign - 1 ); 
                    }
                    // remove first and last bracket from ach_argument
                    (ach_argument)++;
                    in_len_argument -= 2;
                } else {
                    in_len_arg_sign = 0;
                }

                // get cases like "document['URL'] = 'http://...'":
                if ( adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos] == '[' ) {
                    in_arg_key = m_is_argument_in_attr_list( ach_argument, in_len_argument );
                    if ( in_arg_key > -1 ) {
                        if ( adsc_var_cur->ds_object.m_get_len() > 0 ) {
                            dc_insert.m_write( adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len() );
                            adsc_var_cur->ds_object.m_reset();
                        }
                        dc_insert.m_write( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() );
                        dc_insert.m_write( "." );
                        in_len_object = dc_insert.m_get_len();
                        adsc_var_cur->ds_word.m_reset();
                        adsc_var_cur->ds_word.m_write( &ach_argument[1], in_len_argument - 2 );
                        adsc_var_cur->ds_sign.m_reset();
                        adsc_var_cur->ds_spaces.m_reset();
                        if ( in_position >= in_len_data ) {
                            if ( m_is_word_attribute( in_arg_key ) && in_arg_key != ds_attributes::ied_scr_attr_value ) {
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                dc_temp = dc_insert;
                                m_build_HOB_get_attr( &dc_insert, dc_temp.m_get_ptr(), dc_temp.m_get_len(), &ach_argument[1], in_len_argument - 2, NULL, 0 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                // reset variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                adsc_var_cur->ds_last_pos_key.in_key = -2;
                            } else if ( m_is_word_object( in_arg_key ) && in_arg_key != ds_attributes::ied_scr_attr_all ) {
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                dc_temp = dc_insert;
                                m_build_HOB_object( &dc_insert, dc_temp.m_get_ptr(), dc_temp.m_get_len(), &ach_argument[1], in_len_argument - 2, NULL, 0 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                // reset variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                adsc_var_cur->ds_last_pos_key.in_key = -2;
                            }
                        } else {
                            adsc_var_cur->ds_object.m_write( dc_insert.m_get_ptr(), in_len_object );
                            adsc_var_cur->in_state = SCRIPT_CUT_WORD;
                        }
                        continue;
                    } else if ( in_word_key == ds_attributes::ied_scr_attr_style && in_len_arg_sign == 1 && ach_arg_sign[0] == '=' ) {
                        // document.getElementById("id").style[property] = "value"
                        // is more browser compatible then document.getElementById("id").style.property = "value"
                        // => insert a special function "HOB_set_style(...)"
                        if ( in_position < in_len_data ) {
                            adsc_var_cur->ds_object.m_write( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() );
                            adsc_var_cur->ds_word.m_set( ach_argument, in_len_argument );
                            adsc_var_cur->ds_sign.m_reset();
                            adsc_var_cur->ds_spaces.m_reset();
                            in_position = in_pos_arg_sign;
                            adsc_var_cur->in_state = SCRIPT_CUT_SPEC_STYLE;
                        }
                        continue;
                    }
                }
                
                if ( in_len_argument > MIN_SIZE_FOR_RECURSIVE_CALL ) {
                    if ( dsc_variables.m_size() < MAX_NUM_OF_RECURSIVE_CALLS - 1 ) {
                        /*+------------------------------+*/
                        /*| call m_parse_data RECURSIVE: |*/
                        /*+------------------------------+*/
                        // get memory for ds_scriptvariables:
                        ads_tempvars = (ds_scriptvariables*)ads_session->ads_wsp_helper->m_cb_get_memory( in_len_vars, false );
#ifdef TRACE_MEMORY
                        m_trace_memory( ads_tempvars, in_len_vars, false );
#endif // TRACE_MEMORY
                        // put ds_scriptvariables in this memory:
                        ads_tempvars = new(ads_tempvars) ds_scriptvariables( ads_session->ads_wsp_helper );
                        // MJ 26.05.09, Ticket[17724]:
                        if ( adsc_var_cur->ds_sign.m_get_len() > 0 ) {
                            ads_tempvars->ch_last_sign = adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->ds_sign.m_get_len() - 1];
                        }
                        dsc_variables.m_stack_push(ads_tempvars);
                        ads_tempvars = NULL;
                        m_parse_data( ach_argument, in_len_argument, true, &ds_changed_arg );  //output is written into ds_changed_arg!
                        adsc_var_cur = dsc_variables.m_stack_current();
                        if ( ds_changed_arg.m_get_len() > in_len_argument ) {
                            ach_argument    = ds_changed_arg.m_get_ptr();
                            in_len_argument = ds_changed_arg.m_get_len();
                        }
                    } else {
                        ads_session->ads_wsp_helper->m_log( ied_sdh_log_error,
                                                            "HWSGE206E: stack-size reached limit - no recursive call" );
                    }
                }

                /*+-----------------------------+*/
                /*| change data (if necessary): |*/
                /*+-----------------------------+*/
                if ( m_is_word_attribute( in_word_key )
#if SM_USE_ATTRIBUTE_LENGTH
                    && in_word_key != ds_attributes::ied_scr_attr_length
#endif
                    && adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos] == '=' ) 
                {
                    m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                    m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                    // send HOB_set_attribute
                    m_build_HOB_set_attr( &dc_insert, adsc_var_cur->in_append_data, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), in_word_key, ach_argument, in_len_argument );
                    m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                    dc_insert.m_reset();
                    m_free_all_data();
                    adsc_var_cur->in_state = SCRIPT_NORMAL;

                } else if ( m_is_word_function( in_word_key, adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos] ) ) {
                    if ( adsc_var_cur->ds_last_pos_key.in_key > -1 ) {
                        adsc_var_cur->ds_last_pos_key.in_key = -1;
                        m_build_HOB_get_attr( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_last_pos_key.in_pos_in_object, &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object], adsc_var_cur->ds_last_pos_key.in_length, ".", 1 );
                        dc_insert.m_write( &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1], adsc_var_cur->ds_object.m_get_len() - (adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1) );
                        adsc_var_cur->ds_object.m_set( dc_insert );
                    }
                    m_build_HOB_function( &dc_insert, ach_data, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), in_word_key, ach_argument, in_len_argument );
                    // check if our function must be nested:
                    if ( in_len_arg_sign > 0 && ach_arg_sign[0] == '.' ) {
                        if ( in_word_key != ds_attributes::ied_scr_attr_tags ) {
                            dc_insert.m_write( "." );
                            m_free_all_data();
                            adsc_var_cur->ds_object.m_set( dc_insert );
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                            in_position   = in_pos_arg_sign;
                        }
                    } else if ( in_len_arg_sign > 0 && ach_arg_sign[0] == '[' ) {
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                    } else {
                        // send HOB_function:
                        m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        m_free_all_data();
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                    }
                    // reset some variables:
                    in_len_object = 0;
#ifndef B140716
					bol_with_doublesign = false;
#endif
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    dc_insert.m_reset();

                } else if ( m_is_word_object( in_word_key, ach_argument, in_len_argument ) && adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos] == '[' ) {
                    m_build_HOB_object( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_sign.m_get_ptr(), adsc_var_cur->ds_sign.m_get_len() );
                    dc_insert.m_write( ach_argument, in_len_argument );
                    dc_insert.m_write( "]" );
                    // check if our object must be nested:
                    if ( in_len_arg_sign > 0 && ach_arg_sign[0] == '.' ) {
                        dc_insert.m_write( "." );
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                        in_position   = in_pos_arg_sign;
                    } else if ( in_len_arg_sign > 0 && ach_arg_sign[0] == '[' ) {
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                    } else {
                        // send HOB_object:
                        m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        m_free_all_data();
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                    }
                    // reset some variables:
                    in_len_object = 0;
#ifndef B140716
					bol_with_doublesign = false;
#endif
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    dc_insert.m_reset();

#if 0
                } else if ( in_word_key == ds_attributes::ied_scr_attr_with && adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos] == '(' ) {
                    // case of "with(object) { ... }":
                    m_add_withobject( ach_argument, in_len_argument, (ach_arg_sign[0] == '{') );
                    m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_sign.m_get_ptr(), adsc_var_cur->ds_sign.m_get_len(), ach_argument, in_len_argument, ")", 1 );
                    m_free_all_data();
                    if ( ach_arg_sign[0] == '{' ) {
                        dc_insert.m_write( "{" );
                        in_position = in_pos_arg_sign;
                    }
                    m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                    m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                    m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                    adsc_var_cur->in_state = SCRIPT_NORMAL;
                    // reset some variables:
                    in_len_object = 0;
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    dc_insert.m_reset();
#endif

                } else {
                    // word is NOT in list, NO CHANGE!
                    if ( adsc_var_cur->ds_last_pos_key.in_key > -1 ) {
                        adsc_var_cur->ds_last_pos_key.in_key = -1;
                        m_build_HOB_get_attr( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_last_pos_key.in_pos_in_object, &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object], adsc_var_cur->ds_last_pos_key.in_length, ".", 1 );
                        dc_insert.m_write( &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1], adsc_var_cur->ds_object.m_get_len() - (adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1) );
                        dc_insert.m_write( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() );
                        dc_insert.m_write( adsc_var_cur->ds_sign.m_get_ptr(), adsc_var_cur->ds_sign.m_get_len() );
                        dc_insert.m_write( ach_argument, in_len_argument );
                    } else {
                        m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_sign.m_get_ptr(), adsc_var_cur->ds_sign.m_get_len(), ach_argument, in_len_argument );
                    }
                    switch(adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos]) {
					case '(':
                        dc_insert.m_write( ")" );
						break;
					case '[':
                        dc_insert.m_write( "]" );
						break;
					case '?':
						dc_insert.m_write( ":" );
						break;
					default:
						break;
                    }
                    if ( m_is_sign_bracket(adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos]) && in_len_arg_sign > 0 && ach_arg_sign[0] == '.' ) {
                        // check if function must be nested:
                        dc_insert.m_write( "." );
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                        in_position   = in_pos_arg_sign;
                    } else if ( m_is_sign_bracket(adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos]) && in_len_arg_sign > 0 && ach_arg_sign[0] == '[' ) {
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                    } else {
                        m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        m_free_all_data();
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                    }
                    // reset some variables:
                    in_len_object = 0;
#ifndef B140716
					bol_with_doublesign = false;
#endif
                    dc_insert.m_reset();
                }
                ds_changed_arg.m_reset();
                break;

// ----------------------------------------------------------------------------
// handle saved object:
// ----------------------------------------------------------------------------
            case SCRIPT_SAVED_OBJECT:
                /*+----------+*/
                /*| get word |*/
                /*+----------+*/
                in_func_return = m_get_next_word( ach_data, in_len_data, &in_position, in_word_key, &ach_word, &in_len_word, &in_word_pos );
                switch ( in_func_return ) {
                    case SCRIPT_NO_WORD:
                        // TODO!!!!!
                        // free memory:
                        m_free_all_data();
                        m_free_vars();
                        return in_ret; // -> exit
                    case SCRIPT_WORD_PARTIAL:
                        if ( !bo_data_complete ) {
                            // save word, don't save object, it is already saved!
                            adsc_var_cur->ds_word.m_write( ach_word, in_len_word );
                            m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                            adsc_var_cur->in_state = SCRIPT_CUT_WORD;
                        } else {
                            in_word_key = m_is_word_in_list( ach_word, in_len_word );
                            if ( m_is_word_attribute( in_word_key ) && in_word_key != ds_attributes::ied_scr_attr_value ) {
                                if ( adsc_var_cur->ds_object.m_get_len() == 0 ) {
                                    in_pos_insert = in_word_pos;
                                }
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_build_HOB_get_attr( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), ach_word, in_len_word, NULL, 0);
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                dc_insert.m_reset();
                            } else if ( m_is_word_object( in_word_key ) && in_word_key != ds_attributes::ied_scr_attr_all ) {
                                if ( adsc_var_cur->ds_object.m_get_len() == 0 ) {
                                    in_pos_insert = in_word_pos;
                                }
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_build_HOB_object( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), ach_word, in_len_word, NULL, 0 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                dc_insert.m_reset();
                            } else {
                                // if bo_data_complete == true, just send saved and rest data, nothing to do
                                m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                                m_move_char_pointer( &ach_data, &in_len_data, &in_pos_arg_sign );
                                m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), ach_word, in_len_word );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                dc_insert.m_reset();
                                //m_send_data( adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), ads_output );
                                //m_send_data( ach_data, in_len_data, ads_output );
                            }
                            // free memory:
                            m_free_all_data();
                            m_free_vars();
                        }
                        return in_ret; // -> exit
                    case SCRIPT_WORD_COMPLETE:
                        break; // -> continue after this switch
                }
                in_word_key = m_is_word_in_list( ach_word, in_len_word );
                /*+----------+*/
                /*| get sign |*/
                /*+----------+*/
                in_func_return = m_get_next_sign( ach_data, in_len_data, &in_position, &ach_sign, &in_len_sign, &adsc_var_cur->in_sign_pos, &ach_white_spaces, &in_len_white_spaces );
                switch ( in_func_return ) {
                    case SCRIPT_NO_SIGN:
                        if ( !bo_data_complete ) {
                            // save word, sign and white spaces, don't save object, it is already saved!
                            adsc_var_cur->ds_word.m_write( ach_word, in_len_word );
                            adsc_var_cur->ds_sign.m_write( ach_sign, in_len_sign );
                            adsc_var_cur->ds_spaces.m_write( ach_white_spaces, in_len_white_spaces );
                            m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                            adsc_var_cur->in_state = SCRIPT_CUT_SIGN;
                        } else {
                            if ( m_is_word_attribute( in_word_key ) && in_word_key != ds_attributes::ied_scr_attr_value ) {
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                m_build_HOB_get_attr( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), ach_word, in_len_word, ach_sign, in_len_sign );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                            } else {
                                m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                                m_move_char_pointer( &ach_data, &in_len_data, &in_pos_arg_sign );
                                // if bo_data_complete == true, just send saved and rest data, nothing to do
                                m_send_data( adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), ads_output );
                                m_send_data( ach_data, in_len_data, ads_output );
                            }
                            // free memory:
                            m_free_all_data();
                            m_free_vars();
                        }
                        return in_ret; // -> exit
                    case SCRIPT_SIGN_FOUND:
                        break; // -> continue after this switch
                }
                
                switch ( ach_sign[adsc_var_cur->in_sign_pos] ) {
                    case '.':
                        // for case like "document.location.href.indexOf('foo')"
                        if ( m_is_word_attribute(in_word_key)  && m_rec_attribute(in_word_key) ) {
                            adsc_var_cur->ds_last_pos_key.in_key = in_word_key;
                            adsc_var_cur->ds_last_pos_key.in_pos_in_object = adsc_var_cur->ds_object.m_get_len();
                            adsc_var_cur->ds_last_pos_key.in_length = in_len_word;
                        } else if ( m_is_word_object(in_word_key) && m_rec_object(in_word_key) ) {
                            // for case like "document.firstChild.id  ... "
                            m_build_HOB_object( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), ach_word, in_len_word, ach_sign, in_len_sign );
                            m_free_all_data();
                            adsc_var_cur->ds_object.m_write( dc_insert.m_get_ptr(), dc_insert.m_get_len() );
                            m_send_data( ach_data, in_pos_insert, ads_output );
                            m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                            // reset some variables:
                            in_pos_insert = 0;
                            dc_insert.m_reset();
                            adsc_var_cur->ds_last_pos_key.in_key = -2;
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                            continue; // -> handle saved object
                        }

                        adsc_var_cur->ds_object.m_write( ach_word, in_len_word );
                        adsc_var_cur->ds_object.m_write( ".", 1 );

                        if ( in_position < in_len_data ) {
                            continue; // -> get next word
                        } else {
                            if ( bo_data_complete ) {
                                ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                                                    "HWSGI204I: found dot at end of data in ds_interpret_script::m_parse_data" );
                                m_send_data( adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), ads_output ); // send object
                                m_send_data( ach_data, in_len_data, ads_output ); // send hole data
                                // free memory:
                                m_free_all_data();
                                m_free_vars();
                            } else {
                                m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert and return
                                //adsc_var_cur->ds_object.m_reset();
                            }
                            return in_ret; // -> exit
                        }
                    case '(':
                    case '[':
                        in_position--;  // argument search need the bracket in this case ( ... argument ... )
                        break;  // -> continue after this switch: get argument
                    case '?':
                        in_position--;  // argument search need the bracket in this case ( ... argument ... )
                        break;  // -> continue after this switch: get argument
                    case '=':
                        m_pass_signs( ach_data, in_len_data, &in_position, " \n\r\t\v\f" );
                        break;  // -> continue after this switch: get argument
                    case '"':
                        m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), ach_word, in_len_word, ach_white_spaces, in_len_white_spaces, &ach_sign[adsc_var_cur->in_sign_pos], 1 );
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        m_free_all_data();
                        // reset some variables:
                        in_len_object = 0;
#ifndef B140716
						bol_with_doublesign = false;
#endif
                        dc_insert.m_reset();
                        adsc_var_cur->in_state = SCRIPT_DOUBLE_QUOTES;
                        continue; // -> handle double quotes
                    case '\'':
                        m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), ach_word, in_len_word, ach_white_spaces, in_len_white_spaces, &ach_sign[adsc_var_cur->in_sign_pos], 1 );
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        m_free_all_data();
                        // reset some variables:
                        in_len_object = 0;
#ifndef B140716
						bol_with_doublesign = false;
#endif
                        dc_insert.m_reset();
                        adsc_var_cur->in_state = SCRIPT_SINGLE_QUOTES;
                        continue; // -> handle single quotes
                    case '/':
                        in_func_return = m_is_slash_comment( ach_data, in_len_data, &in_position );
                        switch ( in_func_return ) {
                            case SCRIPT_NOT_DECIDED:
                                m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), ach_word, in_len_word, ach_white_spaces, in_len_white_spaces, &ach_sign[adsc_var_cur->in_sign_pos], 1 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                m_free_all_data();
                                m_send_data( ach_data, in_len_data, ads_output );
                                // reset some variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                if ( bo_data_complete ) {
                                    // free memory:
                                    m_free_vars();
                                } else {
                                    adsc_var_cur->in_state = SCRIPT_CUT_AFTER_SLASH;
                                }
                                return in_ret;
                            case SCRIPT_ASTERISK_COMMENT:
                                m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), ach_word, in_len_word, ach_white_spaces, in_len_white_spaces, &ach_sign[adsc_var_cur->in_sign_pos], 1, "*", 1 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                m_free_all_data();
                                // reset some variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                adsc_var_cur->in_state = SCRIPT_C_COMMENT_1;
                                continue; // -> handle "/*...*/" comment
                            case SCRIPT_SLASH_COMMENT:
                                m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), ach_word, in_len_word, ach_white_spaces, in_len_white_spaces, &ach_sign[adsc_var_cur->in_sign_pos], 1, "/", 1 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                m_free_all_data();
                                // reset some variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                adsc_var_cur->in_state = SCRIPT_CPP_COMMENT;
                                continue; // -> handle "//..." comment
                            case SCRIPT_NO_COMMENT:
                                break; // goto default case
                        }
                        // break is missing on purpose!!!
                    default:
                        if ( m_is_word_attribute( in_word_key ) && in_word_key != ds_attributes::ied_scr_attr_value ) {
                            m_send_data( ach_data, in_pos_insert, ads_output );
                            m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                            m_build_HOB_get_attr( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), ach_word, in_len_word, ach_sign, in_len_sign );
                            m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                            dc_insert.m_reset();
                            adsc_var_cur->ds_last_pos_key.in_key = -2;
                        } else if ( in_word_key == ds_attributes::ied_scr_attr_new ) {
                            adsc_var_cur->ds_object.m_write( ach_word, in_len_word );
                            adsc_var_cur->ds_object.m_write( " ", 1 );
                            continue; // -> get next word
                        } else if ( adsc_var_cur->ds_last_pos_key.in_key > -1 ) {
                            adsc_var_cur->ds_last_pos_key.in_key = -2;
                        } else {
                            m_send_data( ach_data, in_pos_insert, ads_output );
                            dc_insert.m_write( adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len() );
                            dc_insert.m_write( ach_word, in_len_word );
                            dc_insert.m_write( ach_sign, in_len_sign );
                            m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len() , ads_output );
                            m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                            dc_insert.m_reset();
                        }
                        // reset variables:
                        adsc_var_cur->ds_object.m_reset();
                        in_len_object = 0;
#ifndef B140716
						bol_with_doublesign = false;
#endif
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                        continue; // -> get next word
                    case 'p':       // case of "++"
                    case 'm':       // case of "--"
                        // reset variables:
                        adsc_var_cur->ds_object.m_reset();
                        in_len_object = 0;
#ifndef B140716
						bol_with_doublesign = true;
#endif
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                        continue; // -> get next word
                }
                /*+--------------+*/
                /*| get argument |*/
                /*+--------------+*/
                in_func_return = m_get_argument( ach_data, in_len_data, &in_position, ach_sign[adsc_var_cur->in_sign_pos], &ach_argument, &in_len_argument );
                switch ( in_func_return ) {
                    case SCRIPT_NO_ARG:
                        // we must also save data, because in next step we must search for argument again!
                        // break is missing on purpose!!!
                    case SCRIPT_ARG_PARTIAL:
                        if ( !bo_data_complete ) {
                            // save data (don't save object, it is already saved) :
                            adsc_var_cur->ds_sign.m_write    ( ach_sign, in_len_sign );
                            adsc_var_cur->ds_word.m_write    ( ach_word, in_len_word );
                            adsc_var_cur->ds_spaces.m_write  ( ach_white_spaces, in_len_white_spaces );
                            adsc_var_cur->ds_argument.m_write( ach_argument, in_len_argument );
                            m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert and return
                            adsc_var_cur->in_state = SCRIPT_CUT_ARGUMENT;
                            return in_ret; // -> exit
                        } else {
                            // otherwise don't exit, we must change our data!!!
                            break; // -> continue after this switch
                        }
                    case SCRIPT_ARG_COMPLETE:
                        break; // -> continue after this switch
                }

                if ( m_is_sign_bracket(ach_sign[adsc_var_cur->in_sign_pos]) ) {
                    // check sign after argument:
                    in_pos_arg_sign = in_position;
                    in_func_return = m_get_next_sign( ach_data, in_len_data, &in_pos_arg_sign, &ach_arg_sign, &in_len_arg_sign, NULL, &ach_arg_spaces, &in_len_arg_spaces );
                    switch ( in_func_return ) {
                        case SCRIPT_NO_SIGN:
                            if ( !bo_data_complete ) {
                                // save data (don't save object, it is already saved) :
                                adsc_var_cur->ds_sign.m_write    ( ach_sign, in_len_sign );
                                adsc_var_cur->ds_arg_sign.m_write( ach_arg_sign, in_len_arg_sign );
                                adsc_var_cur->ds_word.m_write    ( ach_word, in_len_word );
                                adsc_var_cur->ds_spaces.m_write  ( ach_white_spaces, in_len_white_spaces );
                                adsc_var_cur->ds_argument.m_write( ach_argument, in_len_argument );
                                adsc_var_cur->ds_arg_spaces.m_write( ach_arg_spaces, in_len_arg_spaces );
                                m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert and return
                                adsc_var_cur->in_state = SCRIPT_CUT_ARG_SIGN;
                                return in_ret; // -> exit
                            } else {
                                // otherwise don't exit, we must change our data!!!
                                break; // -> continue after this switch
                            }
                            break;
                        case SCRIPT_SIGN_FOUND:
                            break; // -> continue after this switch
                    }
                    if ( in_len_arg_sign > 1 ) {
                        // after argument, only the first occuring sign is important! 
                        // so don't move data more than one sign!
                        in_pos_arg_sign -= ( in_len_arg_sign - 1 ); 
                    }
                    // remove first and last bracket from ach_argument
                    (ach_argument)++;
                    in_len_argument -= 2;
                } else {
                    in_len_arg_sign = 0;
                }

                // get cases like "document['URL'] = 'http://...'":
                if ( ach_sign[adsc_var_cur->in_sign_pos] == '[' ) {
                    in_arg_key = m_is_argument_in_attr_list( ach_argument, in_len_argument );
                    if ( in_arg_key > -1 ) {
                        if ( adsc_var_cur->ds_object.m_get_len() > 0 ) {
                            dc_insert.m_write( adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len() );
                            adsc_var_cur->ds_object.m_reset();
                        }
                        dc_insert.m_write( ach_word, in_len_word );
                        dc_insert.m_write( "." );
                        in_len_object = dc_insert.m_get_len();
                        adsc_var_cur->ds_word.m_write( &ach_argument[1], in_len_argument - 2 );
                        adsc_var_cur->ds_sign.m_reset();
                        adsc_var_cur->ds_spaces.m_reset();
                        if ( in_position >= in_len_data ) {
                            if ( m_is_word_attribute( in_arg_key ) && in_arg_key != ds_attributes::ied_scr_attr_value ) {
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                dc_temp = dc_insert;
                                m_build_HOB_get_attr( &dc_insert, dc_temp.m_get_ptr(), dc_temp.m_get_len(), &ach_argument[1], in_len_argument - 2, NULL, 0 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                // reset variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                adsc_var_cur->ds_last_pos_key.in_key = -2;
                            } else if ( m_is_word_object( in_arg_key ) && in_arg_key != ds_attributes::ied_scr_attr_all ) {
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                dc_temp = dc_insert;
                                m_build_HOB_object( &dc_insert, dc_temp.m_get_ptr(), dc_temp.m_get_len(), &ach_argument[1], in_len_argument - 2, NULL, 0 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                // reset variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                adsc_var_cur->ds_last_pos_key.in_key = -2;
                            }
                        } else {
                            adsc_var_cur->ds_object.m_write( dc_insert.m_get_ptr(), in_len_object );
                            adsc_var_cur->in_state = SCRIPT_CUT_WORD;
                        }
                        continue;
                    } else if ( in_word_key == ds_attributes::ied_scr_attr_style && in_len_arg_sign == 1 && ach_arg_sign[0] == '=' ) {
                        // document.getElementById("id").style[property] = "value"
                        // is more browser compatible then document.getElementById("id").style.property = "value"
                        // => insert a special function "HOB_set_style(...)"
                        if ( in_position < in_len_data ) {
                            adsc_var_cur->ds_object.m_write( ach_word, in_len_word );
                            adsc_var_cur->ds_word.m_set( ach_argument, in_len_argument );
                            adsc_var_cur->ds_sign.m_reset();
                            adsc_var_cur->ds_spaces.m_reset();
                            in_position = in_pos_arg_sign;
                            adsc_var_cur->in_state = SCRIPT_CUT_SPEC_STYLE;
                        }
                        continue;
                    }
                }
                
                if ( in_len_argument > MIN_SIZE_FOR_RECURSIVE_CALL ) {
                    if ( dsc_variables.m_size() < MAX_NUM_OF_RECURSIVE_CALLS - 1 ) {
                        /*+------------------------------+*/
                        /*| call m_parse_data RECURSIVE: |*/
                        /*+------------------------------+*/
                        // get memory for ds_scriptvariables:
                        ads_tempvars = (ds_scriptvariables*)ads_session->ads_wsp_helper->m_cb_get_memory( in_len_vars, false );
#ifdef TRACE_MEMORY
                        m_trace_memory( ads_tempvars, in_len_vars, false );
#endif // TRACE_MEMORY
                        // put ds_scriptvariables in this memory:
                        ads_tempvars = new(ads_tempvars) ds_scriptvariables( ads_session->ads_wsp_helper );
                        // MJ 26.05.09, Ticket[17724]:
                        if ( in_len_sign > 0 ) {
                            ads_tempvars->ch_last_sign = ach_sign[in_len_sign - 1];
                        }
                        dsc_variables.m_stack_push(ads_tempvars);
                        ads_tempvars = NULL;
                        m_parse_data( ach_argument, in_len_argument, true, &ds_changed_arg );  //output is written into ds_changed_arg!
                        adsc_var_cur = dsc_variables.m_stack_current();
                        if ( ds_changed_arg.m_get_len() > in_len_argument ) {
                            ach_argument    = ds_changed_arg.m_get_ptr();
                            in_len_argument = ds_changed_arg.m_get_len();
                        }
                    } else {
                        ads_session->ads_wsp_helper->m_log( ied_sdh_log_error,
                                                            "HWSGE207E: stack-size reached limit - no recursive call" );
                    }
                }

                /*+-----------------------------+*/
                /*| change data (if necessary): |*/
                /*+-----------------------------+*/
                if ( m_is_word_attribute( in_word_key )
#if SM_USE_ATTRIBUTE_LENGTH
                    && in_word_key != ds_attributes::ied_scr_attr_length
#endif
                    && ach_sign[adsc_var_cur->in_sign_pos] == '=' )
                {
                    //m_send_data( adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), ads_output ); // send saved object
                    m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                    m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                    // send HOB_set_attribute
                    m_build_HOB_set_attr( &dc_insert, adsc_var_cur->in_append_data, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), ach_word, in_len_word, in_word_key, ach_argument, in_len_argument );
                    m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                    dc_insert.m_reset();
                    // reset variables:
                    in_len_object = 0;
#ifndef B140716
					bol_with_doublesign = false;
#endif
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    adsc_var_cur->ds_object.m_reset();
                    adsc_var_cur->in_state = SCRIPT_NORMAL;

                } else if ( m_is_word_function( in_word_key, ach_sign[adsc_var_cur->in_sign_pos] ) ) {
                    if ( adsc_var_cur->ds_last_pos_key.in_key > -1 ) {
                        adsc_var_cur->ds_last_pos_key.in_key = -1;
                        m_build_HOB_get_attr( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_last_pos_key.in_pos_in_object, &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object], adsc_var_cur->ds_last_pos_key.in_length, ".", 1 );
                        dc_insert.m_write( &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1], adsc_var_cur->ds_object.m_get_len() - (adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1) );
                        adsc_var_cur->ds_object.m_set( dc_insert );
                    }
                    m_build_HOB_function( &dc_insert, ach_data, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), ach_word, in_len_word, in_word_key, ach_argument, in_len_argument );
                    // check if our function must be nested:
                    if ( in_len_arg_sign > 0 && ach_arg_sign[0] == '.' ) {
                        if ( in_word_key != ds_attributes::ied_scr_attr_tags ) {
                            dc_insert.m_write( "." );
                            m_free_all_data();
                            adsc_var_cur->ds_object.m_set( dc_insert );
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                            in_position   = in_pos_arg_sign;
                        }
                    } else if ( in_len_arg_sign > 0 && ach_arg_sign[0] == '[' ) {
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                    } else {
                        // send HOB_function:
                        m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        in_len_object = 0;
#ifndef B140716
						bol_with_doublesign = false;
#endif
                        adsc_var_cur->ds_object.m_reset();
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                    }
                    // reset some variables:
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    dc_insert.m_reset();

                } else if ( m_is_word_object( in_word_key, ach_argument, in_len_argument ) && ach_sign[adsc_var_cur->in_sign_pos] == '[' ) {
                    m_build_HOB_object( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), ach_word, in_len_word, ach_sign, in_len_sign );
                    dc_insert.m_write( ach_argument, in_len_argument );
                    dc_insert.m_write( "]" );
                    // check if our object must be nested:
                    if ( in_len_arg_sign > 0 && ach_arg_sign[0] == '.' ) {
                        dc_insert.m_write( "." );
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                        in_position   = in_pos_arg_sign;
                    } else if ( in_len_arg_sign > 0 && ach_arg_sign[0] == '[' ) {
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                    } else {
                        // send HOB_object:
                        m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        in_len_object = 0;
#ifndef B140716
						bol_with_doublesign = false;
#endif
                        adsc_var_cur->ds_object.m_reset();
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                    }
                    // reset some variables:
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    dc_insert.m_reset();

#if 0
                } else if ( in_word_key == ds_attributes::ied_scr_attr_with && ach_sign[adsc_var_cur->in_sign_pos] == '(' ) {
                    // case of "with(object) { ... }":
                    m_add_withobject( ach_argument, in_len_argument, (ach_arg_sign[0] == '{') );
                    m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len() ,ach_word, in_len_word ,ach_sign, in_len_sign ,ach_argument, in_len_argument, ")", 1 );
                    m_free_all_data();
                    if ( ach_arg_sign[0] == '{' ) {
                        dc_insert.m_write( "{" );
                        in_position = in_pos_arg_sign;
                    }
                    m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                    m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                    m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                    adsc_var_cur->in_state = SCRIPT_NORMAL;
                    // reset some variables:
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    in_len_object = 0;
                    dc_insert.m_reset();
#endif

                } else {
                    // word is NOT in list, NO CHANGE!
                    if ( adsc_var_cur->ds_last_pos_key.in_key > -1 ) {
                        adsc_var_cur->ds_last_pos_key.in_key = -1;
                        m_build_HOB_get_attr( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_last_pos_key.in_pos_in_object, &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object], adsc_var_cur->ds_last_pos_key.in_length, ".", 1 );
                        dc_insert.m_write( &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1], adsc_var_cur->ds_object.m_get_len() - (adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1) );
                        dc_insert.m_write( ach_word, in_len_word );
                        dc_insert.m_write( ach_sign, in_len_sign );
                        dc_insert.m_write( ach_argument, in_len_argument );
                    } else {
                        m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len() ,ach_word, in_len_word ,ach_sign, in_len_sign ,ach_argument, in_len_argument );
                    }
                    switch(ach_sign[adsc_var_cur->in_sign_pos]) {
					case '(':
                        dc_insert.m_write( ")" );
						break;
					case '[':
                        dc_insert.m_write( "]" );
						break;
					case '?':
						dc_insert.m_write( ":" );
						break;
					default:
						break;
                    }
                    if ( m_is_sign_bracket(ach_sign[adsc_var_cur->in_sign_pos]) && in_len_arg_sign > 0 && ach_arg_sign[0] == '.' ) {
                        // check if function must be nested:
                        dc_insert.m_write( "." );
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                        in_position   = in_pos_arg_sign;
                        //m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                    } else if ( m_is_sign_bracket(ach_sign[adsc_var_cur->in_sign_pos]) && in_len_arg_sign > 0 && ach_arg_sign[0] == '[' ) {
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        // MJ Ticket[21993]: m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                    } else {
                        m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        adsc_var_cur->ds_object.m_reset();
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                    }
                    // reset some variables:
                    in_len_object = 0;
#ifndef B140716
					bol_with_doublesign = false;
#endif
                    dc_insert.m_reset();
                }
                ds_changed_arg.m_reset();
                break;

// ----------------------------------------------------------------------------
// handle cut argument:
// ----------------------------------------------------------------------------
            case SCRIPT_CUT_ARGUMENT:
                in_word_key = m_is_word_in_list( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() );
                /*+--------------+*/
                /*| get argument |*/
                /*+--------------+*/
                in_func_return = m_get_argument( ach_data, in_len_data, &in_position, adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos], &ach_argument, &in_len_argument );
                switch ( in_func_return ) {
                    case SCRIPT_NO_ARG:
                        // we must also save data, because in next step we must search for argument again!
                        // break is missing on purpose!!!
                    case SCRIPT_ARG_PARTIAL:
                        if ( !bo_data_complete ) {
                            // save argument (don't save word, object and sign, they are already saved):
                            adsc_var_cur->ds_argument.m_write( ach_argument, in_len_argument );
                            return in_ret; // -> exit
                        } else {
                            // otherwise don't exit, we must change our data!!!
                            adsc_var_cur->ds_argument.m_write( ach_argument, in_len_argument );
                            break; // -> continue after this switch
                        }
                    case SCRIPT_ARG_COMPLETE:
                        adsc_var_cur->ds_argument.m_write( ach_argument, in_len_argument );
                        break; // -> continue after this switch
                }

                ach_argument    = adsc_var_cur->ds_argument.m_get_ptr();
                in_len_argument = adsc_var_cur->ds_argument.m_get_len();

                if ( m_is_sign_bracket(adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos]) ) {
                    in_pos_arg_sign = in_position;
                    in_func_return = m_get_next_sign( ach_data, in_len_data, &in_pos_arg_sign, &ach_arg_sign, &in_len_arg_sign, NULL, &ach_arg_spaces, &in_len_arg_spaces );
                    switch ( in_func_return ) {
                        case SCRIPT_NO_SIGN:
                            if ( !bo_data_complete ) {
                                // save arg sign (don't save word, object, argument and sign, they are already saved):
                                adsc_var_cur->ds_arg_sign.m_write( ach_arg_sign, in_len_arg_sign );
                                adsc_var_cur->ds_arg_spaces.m_write( ach_arg_spaces, in_len_arg_spaces );
                                adsc_var_cur->in_state = SCRIPT_CUT_ARG_SIGN;
                                return in_ret; // -> exit
                            } else {
                                // otherwise don't exit, we must change our data!!!
                                break; // -> continue after this switch
                            }
                            break;
                        case SCRIPT_SIGN_FOUND:
                            break; // -> continue after this switch
                    }
                    if ( in_len_arg_sign > 1 ) {
                        // after argument, only the first occuring sign is important! 
                        // so don't move data more than one sign!
                        in_pos_arg_sign -= ( in_len_arg_sign - 1 ); 
                    }
                    // remove first and last bracket from ach_argument
                    (ach_argument)++;
                    in_len_argument -= 2;
                } else {
                    in_len_arg_sign = 0;
                }

                // get cases like "document['URL'] = 'http://...'":
                if ( adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos] == '[' ) {
                    in_arg_key = m_is_argument_in_attr_list( ach_argument, in_len_argument );
                    if ( in_arg_key > -1 ) {
                        if ( adsc_var_cur->ds_object.m_get_len() > 0 ) {
                            dc_insert.m_write( adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len() );
                            adsc_var_cur->ds_object.m_reset();
                        }
                        dc_insert.m_write( adsc_var_cur->ds_word );
                        dc_insert.m_write( "." );
                        in_len_object = dc_insert.m_get_len();
                        adsc_var_cur->ds_word.m_reset();
                        adsc_var_cur->ds_word.m_write( &ach_argument[1], in_len_argument - 2 );
                        adsc_var_cur->ds_argument.m_reset();
                        adsc_var_cur->ds_sign.m_reset();
                        if ( in_position >= in_len_data ) {
                            if ( m_is_word_attribute( in_arg_key ) && in_arg_key != ds_attributes::ied_scr_attr_value ) {
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                dc_temp = dc_insert;
                                m_build_HOB_get_attr( &dc_insert, dc_temp.m_get_ptr(), dc_temp.m_get_len(), &ach_argument[1], in_len_argument - 2, NULL, 0 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                // reset variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                adsc_var_cur->ds_last_pos_key.in_key = -2;
                            } else if ( m_is_word_object( in_arg_key ) && in_arg_key != ds_attributes::ied_scr_attr_all ) {
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                dc_temp = dc_insert;
                                m_build_HOB_object( &dc_insert, dc_temp.m_get_ptr(), dc_temp.m_get_len(), &ach_argument[1], in_len_argument - 2, NULL, 0 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                // reset variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                adsc_var_cur->ds_last_pos_key.in_key = -2;
                            }
                        } else {
                            adsc_var_cur->ds_object.m_write( dc_insert.m_get_ptr(), in_len_object );
                            adsc_var_cur->in_state = SCRIPT_CUT_WORD;
                        }
                        continue;
                    } else if ( in_word_key == ds_attributes::ied_scr_attr_style && in_len_arg_sign == 1 && ach_arg_sign[0] == '=' ) {
                        // document.getElementById("id").style[property] = "value"
                        // is more browser compatible then document.getElementById("id").style.property = "value"
                        // => insert a special function "HOB_set_style(...)"
                        if ( in_position < in_len_data ) {
                            adsc_var_cur->ds_object.m_write( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() );
                            adsc_var_cur->ds_word.m_set( ach_argument, in_len_argument );
                            adsc_var_cur->ds_argument.m_reset();
                            adsc_var_cur->ds_sign.m_reset();
                            in_position = in_pos_arg_sign;
                            adsc_var_cur->in_state = SCRIPT_CUT_SPEC_STYLE;
                        }
                        continue;
                    }
                }
                
                if ( in_len_argument > MIN_SIZE_FOR_RECURSIVE_CALL ) {
                    if ( dsc_variables.m_size() < MAX_NUM_OF_RECURSIVE_CALLS - 1 ) {
                        /*+------------------------------+*/
                        /*| call m_parse_data RECURSIVE: |*/
                        /*+------------------------------+*/
                        // get memory for ds_scriptvariables:
                        ads_tempvars = (ds_scriptvariables*)ads_session->ads_wsp_helper->m_cb_get_memory( in_len_vars, false );
#ifdef TRACE_MEMORY
                        m_trace_memory( ads_tempvars, in_len_vars, false );
#endif // TRACE_MEMORY
                        // put ds_scriptvariables in this memory:
                        ads_tempvars = new(ads_tempvars) ds_scriptvariables( ads_session->ads_wsp_helper );
                        // MJ 26.05.09, Ticket[17724]:
                        if ( adsc_var_cur->ds_sign.m_get_len() > 0 ) {
                            ads_tempvars->ch_last_sign = adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->ds_sign.m_get_len() - 1];
                        }
                        dsc_variables.m_stack_push(ads_tempvars);
                        ads_tempvars = NULL;
                        m_parse_data( ach_argument, in_len_argument, true, &ds_changed_arg );  //output is written into ds_changed_arg!
                        adsc_var_cur = dsc_variables.m_stack_current();
                        if ( ds_changed_arg.m_get_len() > adsc_var_cur->ds_argument.m_get_len() ) {
                            adsc_var_cur->ds_argument.m_set( ds_changed_arg );
                            ach_argument = adsc_var_cur->ds_argument.m_get_ptr();
                            in_len_argument = adsc_var_cur->ds_argument.m_get_len();
                        }
                        ds_changed_arg.m_reset();
                    } else {
                        ads_session->ads_wsp_helper->m_log( ied_sdh_log_error,
                                                            "HWSGE208E: stack-size reached limit - no recursive call" );
                    }
                }

                /*+-----------------------------+*/
                /*| change data (if necessary): |*/
                /*+-----------------------------+*/
                if ( m_is_word_attribute( in_word_key )
#if SM_USE_ATTRIBUTE_LENGTH
                    && in_word_key != ds_attributes::ied_scr_attr_length
#endif
                    && adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos] == '=' )
                {
                    m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                    // send HOB_set_attribute
                    m_build_HOB_set_attr( &dc_insert, adsc_var_cur->in_append_data, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), in_word_key, ach_argument, in_len_argument );
                    m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                    // reset variables:
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    dc_insert.m_reset();
                    m_free_all_data();
                    adsc_var_cur->in_state = SCRIPT_NORMAL;

                } else if ( m_is_word_function( in_word_key, adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos] ) ) {
                    if ( adsc_var_cur->ds_last_pos_key.in_key > -1 ) {
                        adsc_var_cur->ds_last_pos_key.in_key = -1;
                        m_build_HOB_get_attr( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_last_pos_key.in_pos_in_object, &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object], adsc_var_cur->ds_last_pos_key.in_length, ".", 1 );
                        dc_insert.m_write( &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1], adsc_var_cur->ds_object.m_get_len() - (adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1) );
                        adsc_var_cur->ds_object.m_set( dc_insert );
                    }
                    m_build_HOB_function( &dc_insert, ach_data, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), in_word_key, ach_argument, in_len_argument );
                    // check if our function must be nested:
                    if ( in_len_arg_sign > 0 && ach_arg_sign[0] == '.' ) {
                        if ( in_word_key != ds_attributes::ied_scr_attr_tags ) {
                            dc_insert.m_write( "." );
                            m_free_all_data();
                            adsc_var_cur->ds_object.m_set( dc_insert );
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                            in_position   = in_pos_arg_sign;
                        }
                    } else if ( in_len_arg_sign > 0 && ach_arg_sign[0] == '[' ) {
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                    } else {
                        // send HOB_function:
                        m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        m_free_all_data();
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                    }
                    // reset some variables:
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    dc_insert.m_reset();

                } else if ( m_is_word_object( in_word_key, ach_argument, in_len_argument ) && adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos] == '[' ) {
                    m_build_HOB_object( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_sign.m_get_ptr(), adsc_var_cur->ds_sign.m_get_len() );
                    dc_insert.m_write( ach_argument, in_len_argument );
                    dc_insert.m_write( "]" );
                    // check if our object must be nested:
                    if ( in_len_arg_sign > 0 && ach_arg_sign[0] == '.' ) {
                        dc_insert.m_write( "." );
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                        in_position   = in_pos_arg_sign;
                    } else if ( in_len_arg_sign > 0 && ach_arg_sign[0] == '[' ) {
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                    } else {
                        // send HOB_object:
                        m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        m_free_all_data();
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                    }
                    // reset some variables:
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    dc_insert.m_reset();

#if 0
                } else if ( in_word_key == ds_attributes::ied_scr_attr_with && adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos] == '(' ) {
                    // case of "with(object) { ... }":
                    m_add_withobject( ach_argument, in_len_argument, (ach_arg_sign[0] == '{') );
                    m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_sign.m_get_ptr(), adsc_var_cur->ds_sign.m_get_len(), ach_argument, in_len_argument, ")", 1 );
                    m_free_all_data();
                    if ( ach_arg_sign[0] == '{' ) {
                        dc_insert.m_write( "{" );
                        in_position = in_pos_arg_sign;
                    }
                    m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                    m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                    m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                    adsc_var_cur->in_state = SCRIPT_NORMAL;
                    // reset some variables:
                    in_len_object = 0;
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    dc_insert.m_reset();
#endif

                } else {
                    // word is NOT in list, NO CHANGE!
                    if ( adsc_var_cur->ds_last_pos_key.in_key > -1 ) {
                        adsc_var_cur->ds_last_pos_key.in_key = -1;
                        m_build_HOB_get_attr( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_last_pos_key.in_pos_in_object, &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object], adsc_var_cur->ds_last_pos_key.in_length, ".", 1 );
                        dc_insert.m_write( &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1], adsc_var_cur->ds_object.m_get_len() - (adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1) );
                        dc_insert.m_write( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() );
                        dc_insert.m_write( adsc_var_cur->ds_sign.m_get_ptr(), adsc_var_cur->ds_sign.m_get_len() );
                        dc_insert.m_write( ach_argument, in_len_argument );
                    } else {
                        m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_sign.m_get_ptr(), adsc_var_cur->ds_sign.m_get_len(), ach_argument, in_len_argument );
                    }
                    switch(adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos]) {
					case '(':
                        dc_insert.m_write( ")" );
						break;
					case '[':
                        dc_insert.m_write( "]" );
						break;
					case '?':
						dc_insert.m_write( ":" );
						break;
					default:
						break;
                    }
                    if ( m_is_sign_bracket(adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos]) && in_len_arg_sign > 0 && ach_arg_sign[0] == '.' ) {
                        // check if function must be nested:
                        dc_insert.m_write( "." );
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                        in_position = in_pos_arg_sign;
                    } else if ( m_is_sign_bracket(adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos]) && in_len_arg_sign > 0 && ach_arg_sign[0] == '[' ) {
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                    } else {
                        m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                        if ( adsc_var_cur->ds_arg_spaces.m_get_len() > 0 ) {
                            dc_insert.m_write( adsc_var_cur->ds_arg_spaces.m_get_ptr(), adsc_var_cur->ds_arg_spaces.m_get_len() );
                        }
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        m_free_all_data();
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                    }
                    // reset some variables:
                    in_len_object = 0;
#ifndef B140716
					bol_with_doublesign = false;
#endif
                    dc_insert.m_reset();
                }
                break;

// ----------------------------------------------------------------------------
// handle cut arg sign:
// ----------------------------------------------------------------------------
            case SCRIPT_CUT_ARG_SIGN:
				switch (adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos]) {
				case '(':
				case '[':
				case '?':
					break;
				default:
                    ads_session->ads_wsp_helper->m_log( ied_sdh_log_error,
                                                        "HWSGE203E: no need to search for sign after argument in ds_interpret_script::m_parse_data" );
                    m_free_all_data();
                    m_free_vars();
                    return in_ret;
				}
                in_word_key = m_is_word_in_list( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() );
                in_pos_arg_sign = in_position;
                in_func_return = m_get_next_sign( ach_data, in_len_data, &in_pos_arg_sign, &ach_arg_sign, &in_len_arg_sign, NULL, &ach_arg_spaces, &in_len_arg_spaces );
                switch ( in_func_return ) {
                    case SCRIPT_NO_SIGN:
                        if ( !bo_data_complete ) {
                            adsc_var_cur->ds_arg_sign.m_write( ach_arg_sign, in_len_arg_sign );
                            adsc_var_cur->ds_arg_spaces.m_write( ach_arg_spaces, in_len_arg_spaces );
                            adsc_var_cur->in_state = SCRIPT_CUT_ARG_SIGN;
                            return in_ret; // -> exit
                        } else {
                            // otherwise don't exit, we must change our data!!!
                            adsc_var_cur->ds_arg_sign.m_write( ach_arg_sign, in_len_arg_sign );
                            adsc_var_cur->ds_arg_spaces.m_write( ach_arg_spaces, in_len_arg_spaces );
                            break; // -> continue after this switch
                        }
                        break;
                    case SCRIPT_SIGN_FOUND:
                        adsc_var_cur->ds_arg_sign.m_write( ach_arg_sign, in_len_arg_sign );
                        adsc_var_cur->ds_arg_spaces.m_write( ach_arg_spaces, in_len_arg_spaces );
                        break; // -> continue after this switch
                }
                
                if ( adsc_var_cur->ds_arg_sign.m_get_len() > 1 ) {
                    // after argument, only the first occuring sign is important! 
                    // so don't move data more than one sign!
                    in_pos_arg_sign -= ( adsc_var_cur->ds_arg_sign.m_get_len() - 1 ); 
                }

                ach_argument    = adsc_var_cur->ds_argument.m_get_ptr();
                in_len_argument = adsc_var_cur->ds_argument.m_get_len();

                // remove first and last bracket from ach_argument
                (ach_argument)++;
                in_len_argument -= 2;

                // get cases like "document['URL'] = 'http://...'":
                if ( adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos] == '[' ) {
                    in_arg_key = m_is_argument_in_attr_list( ach_argument, in_len_argument );
                    if ( in_arg_key > -1 ) {
                        if ( adsc_var_cur->ds_object.m_get_len() > 0 ) {
                            dc_insert.m_write( adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len() );
                            adsc_var_cur->ds_object.m_reset();
                        }
                        dc_insert.m_write( adsc_var_cur->ds_word );
                        dc_insert.m_write( "." );
                        in_len_object = dc_insert.m_get_len();
                        adsc_var_cur->ds_word.m_reset();
                        adsc_var_cur->ds_word.m_write( &ach_argument[1], in_len_argument - 2 );
                        adsc_var_cur->ds_argument.m_reset();
                        adsc_var_cur->ds_sign.m_reset();
                        adsc_var_cur->ds_spaces.m_reset();
                        adsc_var_cur->ds_arg_sign.m_reset();
                        adsc_var_cur->ds_arg_spaces.m_reset();
                        if ( in_position >= in_len_data ) {
                            if ( m_is_word_attribute( in_arg_key ) && in_arg_key != ds_attributes::ied_scr_attr_value ) {
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                dc_temp = dc_insert;
                                m_build_HOB_get_attr( &dc_insert, dc_temp.m_get_ptr(), dc_temp.m_get_len(), &ach_argument[1], in_len_argument - 2, NULL, 0 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                // reset variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                adsc_var_cur->ds_last_pos_key.in_key = -2;
                            } else if ( m_is_word_object( in_arg_key ) && in_arg_key != ds_attributes::ied_scr_attr_all ) {
                                m_send_data( ach_data, in_pos_insert, ads_output );
                                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                                dc_temp = dc_insert;
                                m_build_HOB_object( &dc_insert, dc_temp.m_get_ptr(), dc_temp.m_get_len(), &ach_argument[1], in_len_argument - 2, NULL, 0 );
                                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                                // reset variables:
                                in_len_object = 0;
#ifndef B140716
								bol_with_doublesign = false;
#endif
                                dc_insert.m_reset();
                                adsc_var_cur->ds_last_pos_key.in_key = -2;
                            }
                        } else {
                            adsc_var_cur->ds_object.m_write( dc_insert.m_get_ptr(), in_len_object );
                            adsc_var_cur->in_state = SCRIPT_CUT_WORD;
                        }
                        continue;
                    } else if ( in_word_key == ds_attributes::ied_scr_attr_style && adsc_var_cur->ds_arg_sign.m_get_len() == 1 && adsc_var_cur->ds_arg_sign.m_get_ptr()[0] == '=' ) {
                        // document.getElementById("id").style[property] = "value"
                        // is more browser compatible then document.getElementById("id").style.property = "value"
                        // => insert a special function "HOB_set_style(...)"
                        if ( in_position < in_len_data ) {
                            adsc_var_cur->ds_object.m_write( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() );
                            adsc_var_cur->ds_word.m_set( ach_argument, in_len_argument );
                            adsc_var_cur->ds_argument.m_reset();
                            adsc_var_cur->ds_sign.m_reset();
                            adsc_var_cur->ds_spaces.m_reset();
                            adsc_var_cur->ds_arg_sign.m_reset();
                            adsc_var_cur->ds_arg_spaces.m_reset();
                            in_position = in_pos_arg_sign;
                            adsc_var_cur->in_state = SCRIPT_CUT_SPEC_STYLE;
                        }
                        continue;
                    }
                }
                
                if ( in_len_argument > MIN_SIZE_FOR_RECURSIVE_CALL ) {
                    if ( dsc_variables.m_size() < MAX_NUM_OF_RECURSIVE_CALLS - 1 ) {
                        /*+------------------------------+*/
                        /*| call m_parse_data RECURSIVE: |*/
                        /*+------------------------------+*/
                        // get memory for ds_scriptvariables:
                        ads_tempvars = (ds_scriptvariables*)ads_session->ads_wsp_helper->m_cb_get_memory( in_len_vars, false );
#ifdef TRACE_MEMORY
                        m_trace_memory( ads_tempvars, in_len_vars, false );
#endif // TRACE_MEMORY
                        // put ds_scriptvariables in this memory:
                        ads_tempvars = new(ads_tempvars) ds_scriptvariables( ads_session->ads_wsp_helper );
                        // MJ 26.05.09, Ticket[17724]:
                        if ( adsc_var_cur->ds_sign.m_get_len() > 0 ) {
                            ads_tempvars->ch_last_sign = adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->ds_sign.m_get_len() - 1];
                        }
                        dsc_variables.m_stack_push(ads_tempvars);
                        ads_tempvars = NULL;
                        m_parse_data( ach_argument, in_len_argument, true, &ds_changed_arg );  //output is written into ds_changed_arg!
                        adsc_var_cur = dsc_variables.m_stack_current();
                        if ( ds_changed_arg.m_get_len() > adsc_var_cur->ds_argument.m_get_len() ) {
                            adsc_var_cur->ds_argument.m_set( ds_changed_arg );
                            ach_argument    = adsc_var_cur->ds_argument.m_get_ptr();
                            in_len_argument = adsc_var_cur->ds_argument.m_get_len();
                        }
                        ds_changed_arg.m_reset();
                    } else {
                        ads_session->ads_wsp_helper->m_log( ied_sdh_log_error,
                                                            "HWSGE209E: stack-size reached limit - no recursive call" );
                    }
                }

                /*+-----------------------------+*/
                /*| change data (if necessary): |*/
                /*+-----------------------------+*/
                if ( m_is_word_attribute( in_word_key )
#if SM_USE_ATTRIBUTE_LENGTH
                    && in_word_key != ds_attributes::ied_scr_attr_length
#endif
                    && adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos] == '=' )
                {
                    // send "object.word="
                    //m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_sign.m_get_ptr(), adsc_var_cur->ds_sign.m_get_len() );
                    //m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                    m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                    // send HOB_set_attribute
                    m_build_HOB_set_attr( &dc_insert, adsc_var_cur->in_append_data, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), in_word_key, ach_argument, in_len_argument );
                    m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                    // reset variables:
                    dc_insert.m_reset();
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    m_free_all_data();
                    adsc_var_cur->in_state = SCRIPT_NORMAL;

                } else if ( m_is_word_function( in_word_key, adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos] ) ) {
                    if ( adsc_var_cur->ds_last_pos_key.in_key > -1 ) {
                        adsc_var_cur->ds_last_pos_key.in_key = -1;
                        m_build_HOB_get_attr( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_last_pos_key.in_pos_in_object, &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object], adsc_var_cur->ds_last_pos_key.in_length, ".", 1 );
                        dc_insert.m_write( &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1], adsc_var_cur->ds_object.m_get_len() - (adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1) );
                        adsc_var_cur->ds_object.m_set( dc_insert );
                    }
                    m_build_HOB_function( &dc_insert, ach_data, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), in_word_key, ach_argument,in_len_argument );
                    // check if our function must be nested:
                    if ( adsc_var_cur->ds_arg_sign.m_get_ptr()[0] == '.' ) {
                        if ( in_word_key != ds_attributes::ied_scr_attr_tags ) {
                            dc_insert.m_write( "." );
                            m_free_all_data();
                            adsc_var_cur->ds_object.m_set( dc_insert );
                            adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                            in_position   = in_pos_arg_sign;
                        }
                    } else if ( adsc_var_cur->ds_arg_sign.m_get_ptr()[0] == '[' ) {
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                    } else {
                        // send HOB_function:
                        if ( adsc_var_cur->ds_arg_spaces.m_get_len() > 0 ) {
                            dc_insert.m_write( adsc_var_cur->ds_arg_spaces.m_get_ptr(), adsc_var_cur->ds_arg_spaces.m_get_len() );
                        }
                        m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        m_free_all_data();
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                    }
                    // reset some variables:
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    dc_insert.m_reset();

                } else if ( m_is_word_object( in_word_key, ach_argument, in_len_argument ) && adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos] == '[' ) {
                    m_build_HOB_object( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_sign.m_get_ptr(), adsc_var_cur->ds_sign.m_get_len() );
                    dc_insert.m_write( ach_argument, in_len_argument );
                    dc_insert.m_write( "]" );
                    // check if our object must be nested:
                    if ( adsc_var_cur->ds_arg_sign.m_get_ptr()[0] == '.' ) {
                        dc_insert.m_write( "." );
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                        in_position   = in_pos_arg_sign;
                    } else if ( adsc_var_cur->ds_arg_sign.m_get_ptr()[0] == '[' ) {
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                    } else {
                        // send HOB_object:
                        if ( adsc_var_cur->ds_arg_spaces.m_get_len() > 0 ) {
                            dc_insert.m_write( adsc_var_cur->ds_arg_spaces.m_get_ptr(), adsc_var_cur->ds_arg_spaces.m_get_len() );
                        }
                        m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        m_free_all_data();
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                    }
                    // reset some variables:
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    dc_insert.m_reset();

#if 0
                } else if ( in_word_key == ds_attributes::ied_scr_attr_with && adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos] == '(' ) {
                    // case of "with(object) { ... }":
                    m_add_withobject( ach_argument, in_len_argument, (ach_arg_sign[0] == '{') );
                    m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_sign.m_get_ptr(), adsc_var_cur->ds_sign.m_get_len(), ach_argument, in_len_argument, ")", 1 );
                    m_free_all_data();
                    if ( ach_arg_sign[0] == '{' ) {
                        dc_insert.m_write( "{" );
                        in_position = in_pos_arg_sign;
                    }
                    m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                    m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                    m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                    adsc_var_cur->in_state = SCRIPT_NORMAL;
                    // reset some variables:
                    adsc_var_cur->ds_last_pos_key.in_key = -1;
                    in_len_object = 0;
                    dc_insert.m_reset();
#endif

                } else {
                    // word is NOT in list, NO CHANGE!
                    if ( adsc_var_cur->ds_last_pos_key.in_key > -1 ) {
                        adsc_var_cur->ds_last_pos_key.in_key = -1;
                        m_build_HOB_get_attr( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_last_pos_key.in_pos_in_object, &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object], adsc_var_cur->ds_last_pos_key.in_length, ".", 1 );
                        dc_insert.m_write( &adsc_var_cur->ds_object.m_get_ptr()[adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1], adsc_var_cur->ds_object.m_get_len() - (adsc_var_cur->ds_last_pos_key.in_pos_in_object + adsc_var_cur->ds_last_pos_key.in_length + 1) );
                        dc_insert.m_write( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() );
                        dc_insert.m_write( adsc_var_cur->ds_sign.m_get_ptr(), adsc_var_cur->ds_sign.m_get_len() );
                        dc_insert.m_write( ach_argument, in_len_argument );
                    } else {
                        m_build_string( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_sign.m_get_ptr(), adsc_var_cur->ds_sign.m_get_len(), ach_argument, in_len_argument );
                    }
                    switch(adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos]) {
					case '(':
                        dc_insert.m_write( ")" );
						break;
					case '[':
                        dc_insert.m_write( "]" );
						break;
					case '?':
						dc_insert.m_write( ":" );
						break;
					default:
						break;
                    }
                    if ( m_is_sign_bracket(adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos]) && adsc_var_cur->ds_arg_sign.m_get_ptr()[0] == '.' ) {
                        // check if function must be nested:
                        dc_insert.m_write( "." );
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                        in_position   = in_pos_arg_sign;
                    } else if ( m_is_sign_bracket(adsc_var_cur->ds_sign.m_get_ptr()[adsc_var_cur->in_sign_pos]) && adsc_var_cur->ds_arg_sign.m_get_ptr()[0] == '[' ) {
                        m_free_all_data();
                        adsc_var_cur->ds_object.m_set( dc_insert );
                        adsc_var_cur->in_state = SCRIPT_SAVED_OBJECT;
                    } else {
                        m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                        if ( adsc_var_cur->ds_arg_spaces.m_get_len() > 0 ) {
                            dc_insert.m_write( adsc_var_cur->ds_arg_spaces.m_get_ptr(), adsc_var_cur->ds_arg_spaces.m_get_len() );
                        }
                        m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output ); // send str_insert
                        m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                        m_free_all_data();
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                    }
                    // reset some variables:
                    in_len_object = 0;
#ifndef B140716
					bol_with_doublesign = false;
#endif
                    dc_insert.m_reset();
                }
                break;

// ----------------------------------------------------------------------------
// handle special Style notation: "object.style[var1]='value';"
// ----------------------------------------------------------------------------
            case SCRIPT_SPEC_STYLE:
                in_func_return = m_get_argument( ach_data, in_len_data, &in_position, '=', &ach_argument, &in_len_argument );
                switch ( in_func_return ) {
                    case SCRIPT_NO_ARG:
                        // we must also save data, because in next step we must search for argument again!
                        // break is missing on purpose!!!
                    case SCRIPT_ARG_PARTIAL:
                        if ( !bo_data_complete ) {
                            // save data:
                            adsc_var_cur->ds_word.m_write( ach_word, in_len_word );
                            adsc_var_cur->ds_object.m_write( ach_object, in_len_object );
                            adsc_var_cur->ds_argument.m_write( ach_argument, in_len_argument );
                            m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert and return
                            adsc_var_cur->in_state = SCRIPT_CUT_SPEC_STYLE;
                            return in_ret; // -> exit
                        } else {
                            // otherwise don't exit, we must change our data!!!
                            break; // -> continue after this switch
                        }
                    case SCRIPT_ARG_COMPLETE:
                        break; // -> continue after this switch
                }
                m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                // move pointer and reset position variables:
                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                in_pos_insert = 0;
                m_build_HOB_style( &dc_insert, ach_object, in_len_object, ach_word, in_len_word, ach_argument, in_len_argument );
                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
				
				/* hofmants: fixed that old object data is taken */
				in_len_object = 0;
#ifndef B140716
				bol_with_doublesign = false;
#endif
				/* hofmants end */

                dc_insert.m_reset();
                adsc_var_cur->in_state = SCRIPT_NORMAL;
                break;

// ----------------------------------------------------------------------------
// handle cut special Style notation
// ----------------------------------------------------------------------------
            case SCRIPT_CUT_SPEC_STYLE:
                in_func_return = m_get_argument( ach_data, in_len_data, &in_position, '=', &ach_argument, &in_len_argument );
                switch ( in_func_return ) {
                    case SCRIPT_NO_ARG:
                        // we must also save data, because in next step we must search for argument again!
                        // break is missing on purpose!!!
                    case SCRIPT_ARG_PARTIAL:
                        if ( !bo_data_complete ) {
                            // save data:
                            adsc_var_cur->ds_argument.m_write( ach_argument, in_len_argument );
                            m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert and return
                            adsc_var_cur->in_state = SCRIPT_CUT_SPEC_STYLE;
                            return in_ret; // -> exit
                        } else {
                            // otherwise don't exit, we must change our data!!!
                            break; // -> continue after this switch
                        }
                    case SCRIPT_ARG_COMPLETE:
                        break; // -> continue after this switch
                }
                adsc_var_cur->ds_argument.m_write( ach_argument, in_len_argument );
                m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                // move pointer and reset position variables:
                m_move_char_pointer( &ach_data, &in_len_data, &in_position );
                in_pos_insert = 0;
                m_build_HOB_style( &dc_insert, adsc_var_cur->ds_object.m_get_ptr(), adsc_var_cur->ds_object.m_get_len(), adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len(), adsc_var_cur->ds_argument.m_get_ptr(), adsc_var_cur->ds_argument.m_get_len() );
                m_send_data( dc_insert.m_get_ptr(), dc_insert.m_get_len(), ads_output );
                dc_insert.m_reset();
                m_free_all_data();
                adsc_var_cur->in_state = SCRIPT_NORMAL;
                break;

// ----------------------------------------------------------------------------
// handle cut data after "/":
// ----------------------------------------------------------------------------
            case SCRIPT_CUT_AFTER_SLASH:
                in_func_return = m_is_slash_comment( ach_data, in_len_data, &in_position );
                switch ( in_func_return ) {
                    case SCRIPT_NOT_DECIDED:
                        m_send_data( ach_data, in_len_data, ads_output );
                        if ( bo_data_complete ) {
                            // free memory:
                            m_free_vars();
                        } else {
                            adsc_var_cur->in_state = SCRIPT_CUT_AFTER_SLASH;
                        }
                        return in_ret;
                    case SCRIPT_ASTERISK_COMMENT:
                        in_pos_insert = in_position;
                        adsc_var_cur->in_state = SCRIPT_C_COMMENT_1;
                        continue; // -> handle "/*...*/" comment
                    case SCRIPT_SLASH_COMMENT:
                        in_pos_insert = in_position;
                        adsc_var_cur->in_state = SCRIPT_CPP_COMMENT;
                        continue; // -> handle "//..." comment
                    case SCRIPT_NO_COMMENT:
                        // MJ 19.05.09:
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                        break; // goto default case
                }
                break;

// ----------------------------------------------------------------------------
// handle "/*" comment:
// ----------------------------------------------------------------------------
            case SCRIPT_C_COMMENT_1:
                if ( ach_data[in_position] == '@' && adsc_var_cur->bo_comment == false ) {
                    adsc_var_cur->in_state = SCRIPT_COND_COMP;
                    in_position++;
                    continue;
                }
                adsc_var_cur->bo_comment = true;
                for( ; in_position < in_len_data; in_position++ ) {
                    switch ( ach_data[in_position] ) {
                        case '*':
                            in_position++;
                            adsc_var_cur->in_state = SCRIPT_C_COMMENT_2;
                            break;
                        default:
                            continue;
                    }
                    break;
                }
                if ( in_position >= in_len_data ) {
                    m_send_data( ach_data, in_len_data, ads_output );
                    if ( bo_data_complete ) {
                        ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                                            "HWSGI205I: no end of data found in ds_interpret_script::m_parse_data" );
                        // free memory:
                        m_free_all_data();
                        m_free_vars();
                    }
                    return in_ret;
                }
                break;

            case SCRIPT_C_COMMENT_2:
                for( ; in_position < in_len_data; in_position++ ) {
                    switch ( ach_data[in_position] ) {
                        case '*':
                            continue;
                        case '/':
                            in_position++;
                            adsc_var_cur->bo_comment = false;
                            adsc_var_cur->in_state = SCRIPT_NORMAL;
                            break;
                        default:
                            in_position++;
                            adsc_var_cur->in_state = SCRIPT_C_COMMENT_1;
                            break;
                    }
                    break;
                }
                if ( in_position >= in_len_data ) {
                    m_send_data( ach_data, in_len_data, ads_output );
                    if ( bo_data_complete ) {
                        ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                                            "HWSGI210I: no end of data found in ds_interpret_script::m_parse_data" );
                        // free memory:
                        m_free_all_data();
                        m_free_vars();
                    }
                    return in_ret;
                }
                break;

// ----------------------------------------------------------------------------
// handle "//" comment:
// ----------------------------------------------------------------------------
            case SCRIPT_CPP_COMMENT:
                in_func_return = m_handle_cpp_comment( ach_data, in_len_data, &in_position );
                switch ( in_func_return ) {
                    case SCRIPT_COMMENT_NO_END_FOUND:
                        m_send_data( ach_data, in_len_data, ads_output );
                        if ( bo_data_complete ) {
                            ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                                                "HWSGI206I: no end of data found in ds_interpret_script::m_handle_cpp_comment" );
                            // free memory:
                            m_free_all_data();
                            m_free_vars();
                        }
                        return in_ret;
                    case SCRIPT_COMMENT_END_FOUND:
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                        break;
                }
                break;

// ----------------------------------------------------------------------------
// handle conditional compilation "/*@cc_on ... @*/
// ----------------------------------------------------------------------------
            case SCRIPT_COND_COMP:
                in_pos_insert = in_position;
                in_func_return = m_get_next_word( ach_data, in_len_data, &in_position, in_word_key, &ach_word, &in_len_word, &in_word_pos );
                switch ( in_func_return ) {
                    case SCRIPT_NO_WORD:
                        m_send_data( ach_data, in_len_data, ads_output ); // send hole data and return
                        // free memory:
                        adsc_var_cur->in_state = SCRIPT_C_COMMENT_1;
                        m_free_vars();
                        return in_ret; // -> exit
                    case SCRIPT_WORD_PARTIAL:
                        if ( !bo_data_complete ) {
                            // save word:
                            adsc_var_cur->ds_word.m_write( ach_word, in_len_word );
                            m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                            adsc_var_cur->in_state = SCRIPT_CUT_COND_COMP;
                        } else {
                            m_send_data( ach_data, in_len_data, ads_output );
                            // free memory:
                            m_free_vars();
                            adsc_var_cur->in_state = SCRIPT_C_COMMENT_1;
                        }
                        return in_ret; // -> exit
                    case SCRIPT_WORD_COMPLETE:
                        break; // -> continue after this switch
                }
                if ( m_is_word_cc_on ( ach_word, in_len_word ) ) {
                    adsc_var_cur->in_state = SCRIPT_NORMAL;
                } else {
                    adsc_var_cur->in_state = SCRIPT_C_COMMENT_1;
                }
                break;

            case SCRIPT_CUT_COND_COMP:
                in_func_return = m_get_next_word( ach_data, in_len_data, &in_position, in_word_key, &ach_word, &in_len_word, &in_word_pos, true );
                switch ( in_func_return ) {
                    case SCRIPT_NO_WORD:
                        m_send_data( ach_data, in_len_data, ads_output ); // send hole data and return
                        // free memory:
                        m_free_vars();
                        adsc_var_cur->in_state = SCRIPT_C_COMMENT_1;
                        return in_ret; // -> exit
                    case SCRIPT_WORD_PARTIAL:
                        if ( !bo_data_complete ) {
                            // save word:
                            adsc_var_cur->ds_word.m_write( ach_word, in_len_word );
                            m_send_data( ach_data, in_pos_insert, ads_output ); // send data until in_pos_insert
                            adsc_var_cur->in_state = SCRIPT_CUT_COND_COMP;
                        } else {
                            m_send_data( ach_data, in_len_data, ads_output );
                            // free memory:
                            m_free_vars();
                            adsc_var_cur->in_state = SCRIPT_C_COMMENT_1;
                        }
                        return in_ret; // -> exit
                    case SCRIPT_WORD_COMPLETE:
                        break; // -> continue after this switch
                }
                if ( m_is_word_cc_on ( adsc_var_cur->ds_word.m_get_ptr(), adsc_var_cur->ds_word.m_get_len() ) ) {
                    adsc_var_cur->in_state = SCRIPT_NORMAL;
                } else {
                    adsc_var_cur->in_state = SCRIPT_C_COMMENT_1;
                }
                m_free_all_data();
                break;

// ----------------------------------------------------------------------------
// handle regular expression:
// ----------------------------------------------------------------------------
            case SCRIPT_REG_EXP:
                in_func_return = m_handle_regexp( ach_data, in_len_data, &in_position );
                switch ( in_func_return ) {
                    case SCRIPT_REGEXP_NO_END_FOUND:
                        m_send_data( ach_data, in_len_data, ads_output );
                        if ( bo_data_complete ) {
                            ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                                                "HWSGI211I: no end of data found in ds_interpret_script::m_handle_regexp" );
                            // free memory:
                            m_free_all_data();
                            m_free_vars();
                        }
                        return in_ret;
                    case SCRIPT_REGEXP_END_FOUND:
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                        break;
                }
                break;

// ----------------------------------------------------------------------------
// handle single quotes:
// ----------------------------------------------------------------------------
            case SCRIPT_SINGLE_QUOTES:
                in_func_return = m_handle_single_quotes( ach_data, in_len_data, &in_position );
                switch ( in_func_return ) {
                    case SCRIPT_QUOTE_NO_END_FOUND:
                        m_send_data( ach_data, in_len_data, ads_output ); // send hole data and return
                        if ( bo_data_complete ) {
                            ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                                                "HWSGI207I: no end of data found in ds_interpret_script::m_handle_single_quotes" );
                            // free memory:
                            m_free_all_data();
                            m_free_vars();
                        }
                        return in_ret;
                    case SCRIPT_QUOTE_END_FOUND:
                        if ( in_len_object == 0 ) {
                            ach_object = ach_word;
                            in_pos_insert = in_word_pos;
                        }
                        in_len_object += (in_position - in_word_pos);
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                        break;
                }
                break;

// ----------------------------------------------------------------------------
// handle double quotes:
// ----------------------------------------------------------------------------
            case SCRIPT_DOUBLE_QUOTES:
                in_func_return = m_handle_double_quotes( ach_data, in_len_data, &in_position );
                switch ( in_func_return ) {
                    case SCRIPT_QUOTE_NO_END_FOUND:
                        m_send_data( ach_data, in_len_data, ads_output ); // send hole data and return
                        if ( bo_data_complete ) {
                            ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                                                "HWSGI208I: no end of data found in ds_interpret_script::m_handle_double_quotes" );
                            // free memory:
                            m_free_all_data();
                            m_free_vars();
                        }
                        return in_ret;
                    case SCRIPT_QUOTE_END_FOUND:
                        if ( in_len_object == 0 ) {
                            ach_object = ach_word;
                            in_pos_insert = in_word_pos;
                        }
                        in_len_object += (in_position - in_word_pos);
                        adsc_var_cur->in_state = SCRIPT_NORMAL;
                        break;
                }
                break;

            default:
                ads_session->ads_wsp_helper->m_log( ied_sdh_log_error,
                                                    "HWSGE202E: invalid state in ds_interpret_script::m_parse_data" );
                adsc_var_cur->in_state = SCRIPT_NORMAL;
                break;
        } // end of switch
    } // end of while

    if ( adsc_var_cur->in_state == SCRIPT_NORMAL || adsc_var_cur->in_state == SCRIPT_IGNORE_COMMAND ) {
        // send rest of data
        m_send_data( ach_data, in_len_data, ads_output );
        if ( dsc_variables.m_size() >= 1 || adsc_var_cur->dsc_vwith.m_empty() ) {
            // free memory:
            m_free_vars();
        }
    } else {
        m_send_data( ach_data, in_pos_insert, ads_output );
        if ( bo_data_complete ) {
            m_move_char_pointer( &ach_data, &in_len_data, &in_pos_insert );
            m_send_data( ach_data, in_len_data, ads_output );
            ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                                "HWSGI209I: no end of data found in ds_interpret_script::m_parse_data" );
            m_send_data( ach_data, in_len_data, ads_output ); // send hole data
            // free memory:
            m_free_all_data();
            m_free_vars();
        }
    }
    return in_ret;
#endif /*SM_USE_WSG_V2*/
} // end of ds_interpret_script::m_parse_data


/*+-------------------------------------------------------------------------+*/
/*| private functions:                                                      |*/
/*+-------------------------------------------------------------------------+*/
#if !SM_USE_WSG_V2
/**
 *
 * ds_interpret_script::m_is_word_object
 *
 * @param[in]   int     in_word_key         integer key for words
 * @param[in]   char*   ach_argument        pointer to argument
 * @param[in]   int     in_len_argument     length of ach_argument
 *
 * @return      bool                        true if word is an attribute
 *                                          false otherwise
 *
*/
bool ds_interpret_script::m_is_word_object( int in_word_key, const char* ach_argument, int in_len_argument )
{
    bool bo_return = false;
    int  in_pos    = 0;
    if ( in_word_key > ds_attributes::ied_scr_attr_obj_start && in_word_key < ds_attributes::ied_scr_attr_obj_end ) {
        bo_return = true;
    }
    if ( in_word_key != ds_attributes::ied_scr_attr_childnodes && ach_argument != NULL && in_len_argument > -1 && bo_return ) {
        // check if argument is number -> otherwise there is no need for changing object => return false
        for ( ; in_pos < in_len_argument; in_pos++ ) {
            if ( (ach_argument[in_pos] > 0) && !isdigit( ach_argument[in_pos] ) ) {
                bo_return = false;
                break;
            }
        }
    }
    return bo_return;
} // end of ds_interpret_script::m_is_word_object


/**
 *
 * ds_interpret_script::m_is_word_attribute
 *
 * @param[in]   int     in_word_key         integer key for words
 *
 * @return      bool                        true if word is an attribute
 *                                          false otherwise
 *
*/
bool ds_interpret_script::m_is_word_attribute( int in_word_key )
{
    bool bo_return = false;
    if ( in_word_key > ds_attributes::ied_scr_attr_start && in_word_key < ds_attributes::ied_scr_attr_end ) {
        bo_return = true;
    }
    return bo_return;
} // end of ds_interpret_script::m_is_word_attribute


/**
 *
 * ds_interpret_script::m_is_word_function
 *
 * @param[in]   int     in_word_key         integer key for words
 * @param[in]   char    ch_sign             sign after word
 *
 * @return      bool                        true if word is an function
 *                                          false otherwise
 *
*/
bool ds_interpret_script::m_is_word_function( int in_word_key, char ch_sign )
{
    bool bo_return = false;
    if ( in_word_key > ds_attributes::ied_scr_attr_function_start && in_word_key < ds_attributes::ied_scr_attr_function_end && ch_sign == '(' ) {
        bo_return = true;
    }
    return bo_return;
} // end of ds_interpret_script::m_is_word_function


/**
 *
 * ds_interpret_script::m_get_argument
 *
 * @param[in]       char*               ach_data            pointer to data
 * @param[in]       int                 in_len_data         length of data
 * @param[in,out]   int*                ain_position        actual position in data
 * @param[in]       char                ch_sign             sign after word
 * @param[out]      char**              aach_argument       pointer to argument
 * @param[out]      int*                ain_len_arg         length of *aach_argument
 *
 * @return          int                                     key:
 *                                                            SCRIPT_NO_ARG       = no argument found
 *                                                            SCRIPT_ARG_PARTIAL  = partial argument found
 *                                                            SCRIPT_ARG_COMPLETE = complete argument found
 *
*/
int ds_interpret_script::m_get_argument( const char* ach_data, int in_len_data, int* ain_position, char ch_sign,
                                         const char** aach_argument, int* ain_len_arg )
{
    // initialize some variables:
    int    in_return    = SCRIPT_NO_ARG;    // return value
    int    in_arg_start = *ain_position;    // start pos of argument
    char   ch_last_sign;                    // last sign in data
    char   ch_next_sign;                    // next sign in data
	bool	bol_ignore_slash = false;		// prevent that the second '/' in ( /[a-z/+=]/ ) doesnt break the regexp,
											// because '/' is allowed in []

    // set pointer to argument:
    *aach_argument = ach_data + *ain_position;
    *ain_len_arg   = 0;

    if ( ach_data == NULL || in_len_data <= 0 || *ain_position >= in_len_data ) {
        return in_return;
    }

    if ( adsc_var_cur->dsc_arg_state.m_empty() ) {
        adsc_var_cur->bo_not_read_next_sign = false;
        adsc_var_cur->dsc_arg_state.m_stack_push(SCRIPT_ARG_NORMAL);
    }
        
    if ( adsc_var_cur->bo_not_read_next_sign ) {
        (*ain_position)++; // case of "...\"..." cut directly after "\": don't read next sign
        adsc_var_cur->bo_not_read_next_sign = false;
    }

    for ( ; *ain_position < in_len_data; (*ain_position)++ ) {
        if ( adsc_var_cur->dsc_arg_state.m_empty() ) {
            break;
        }

		switch ( adsc_var_cur->dsc_arg_state.m_stack_current() ) {

            case SCRIPT_ARG_NORMAL:
                switch ( ach_data[*ain_position] ) {
                    case '(':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_ROUND_BRACKET );
                        continue; //-> check next sign
                    case '[':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_SQUARE_BRACKET );
                        continue; //-> check next sign
                    case '{':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_CURLY_BRACKET );
                        continue; //-> check next sign
                    case '"':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_DOUBLE_QUOTE );
                        continue; //-> check next sign
                    case '\'':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_SINGLE_QUOTE );
                        continue; //-> check next sign
                    case '&':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_AMPERS_AND );
                        continue; //-> check next sign
                    case '/':
                        (*ain_position)++;
                        switch ( m_is_slash_comment( ach_data, in_len_data, ain_position ) ) {
                            case SCRIPT_NOT_DECIDED:
                                adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_CUT_AFTER_SLASH );
                                continue;
                            case SCRIPT_ASTERISK_COMMENT:
                                adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_C_COMMENT_1 );
                                continue;
                            case SCRIPT_SLASH_COMMENT:
                                adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_CPP_COMMENT );
                                continue;
                            case SCRIPT_NO_COMMENT:
                                (*ain_position)--;
                                break;
                        }
                        if ( m_check_for_reg_exp( ach_data, in_len_data, *ain_position ) ) {
                            adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_REG_EXP );
                        }
                        continue; //-> check next sign
                    case '?':  
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_QUESTIONMARK );
                        continue; //-> check next sign
                    //case ':':      // we assume this is a : of a case statement (?/: is handled separately)
                    case '\n':
                    case '\r':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_NEWLINE );
                        continue; //-> check next sign
                    case '}':
                    case ';':
                    case '\f':
                    case ',': // MJ Ticket[22698]
                        break;
                    default:
                        continue; //-> check next sign
                }
                adsc_var_cur->dsc_arg_state.m_stack_pop();
                break;

            case SCRIPT_ARG_NEWLINE:
                // a newline doesn't end command line, if '+', '-', '|', '&', ':' is last sign in line
                if ( m_get_last_sign_before_newline( ach_data, *ain_position, &ch_last_sign ) ) {
                    switch ( ch_last_sign ) {
                        case '+':
                        case '-':
                        case '|':
                        case '&':
                        case '{':
                        case '(':
                        case '[':
                        case '=':
                        case '.':
						case ':':
						case '?':
                            (*ain_position)--;  // next for loop will increase *ain_position again!
                            adsc_var_cur->dsc_arg_state.m_stack_pop();  // ignore newline
                            continue; //-> check next sign
                        default:
                            break;
                    }
                }
                if ( m_get_following_sign( ach_data, in_len_data, *ain_position, &ch_next_sign ) ) {
                    switch ( ch_next_sign ) {
                        case '+':
                        case '-':
                        case '|':
                        case '&':
                        case '{':
                        case '(':
                        case '[':
                        case '=':
                        case '.':
						case '?':
						case ':':
                            adsc_var_cur->dsc_arg_state.m_stack_pop(); // ignore newline
                            continue; //-> check next sign
                        default:
                            break;
                    }
                } else {
                    *ain_position = in_len_data;  // error: skip remainder of data
                    continue;
                }
                adsc_var_cur->dsc_arg_state.m_stack_pop();
                if ( adsc_var_cur->dsc_arg_state.m_stack_current() == SCRIPT_ARG_NORMAL ) {
                    adsc_var_cur->dsc_arg_state.m_stack_pop();
                    (*ain_position)--;
                }
                break;

            case SCRIPT_ARG_ROUND_BRACKET:
                switch ( ach_data[*ain_position] ) {
                    case '{':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_CURLY_BRACKET );
                        continue; //-> check next sign
                    case '(':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_ROUND_BRACKET );
                        continue; //-> check next sign
                    case '[':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_SQUARE_BRACKET );
                        continue; //-> check next sign
                    case '"':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_DOUBLE_QUOTE );
                        continue; //-> check next sign
                    case '\'':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_SINGLE_QUOTE );
                        continue; //-> check next sign
                    case '/':
                        (*ain_position)++;
                        switch ( m_is_slash_comment( ach_data, in_len_data, ain_position ) ) {
                            case SCRIPT_NOT_DECIDED:
                                adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_CUT_AFTER_SLASH );
                                continue;
                            case SCRIPT_ASTERISK_COMMENT:
                                adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_C_COMMENT_1 );
                                continue;
                            case SCRIPT_SLASH_COMMENT:
                                adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_CPP_COMMENT );
                                (*ain_position)--;
                                continue;
                            case SCRIPT_NO_COMMENT:
                                (*ain_position)--;
                                break;
                        }
                        if ( m_check_for_reg_exp( ach_data, in_len_data, *ain_position ) ) {
                            adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_REG_EXP );
                        }
                        continue; //-> check next sign
                    case '?':  
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_QUESTIONMARK );
                        continue; //-> check next sign
                    case ')':
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        if ( ch_sign == '(' && adsc_var_cur->dsc_arg_state.m_size() == 1 ) {
                            (*ain_position)++;
                            break;
                        } else {
                            continue; //-> check next sign
                        }
                    default:
                        continue; //-> check next sign
                }
                adsc_var_cur->dsc_arg_state.m_stack_pop();
                break;

            case SCRIPT_ARG_SQUARE_BRACKET:
                switch ( ach_data[*ain_position] ) {
                    case '{':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_CURLY_BRACKET );
                        continue; //-> check next sign
                    case '[':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_SQUARE_BRACKET );
                        continue; //-> check next sign
                    case '(':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_ROUND_BRACKET );
                        continue; //-> check next sign
                    case '"':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_DOUBLE_QUOTE );
                        continue; //-> check next sign
                    case '\'':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_SINGLE_QUOTE );
                        continue; //-> check next sign
                    case '/':
                        (*ain_position)++;
                        switch ( m_is_slash_comment( ach_data, in_len_data, ain_position ) ) {
                            case SCRIPT_NOT_DECIDED:
                                adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_CUT_AFTER_SLASH );
                                continue;
                            case SCRIPT_ASTERISK_COMMENT:
                                adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_C_COMMENT_1 );
                                continue;
                            case SCRIPT_SLASH_COMMENT:
                                adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_CPP_COMMENT );
                                continue;
                            case SCRIPT_NO_COMMENT:
                                (*ain_position)--;
                                break;
                        }
                        if ( m_check_for_reg_exp( ach_data, in_len_data, *ain_position ) ) {
                            adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_REG_EXP );
                        }
                        continue; //-> check next sign
                    case '?':  
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_QUESTIONMARK );
                        continue; //-> check next sign
                    case ']':
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        if ( ch_sign == '[' && adsc_var_cur->dsc_arg_state.m_size() == 1 ) {
                            (*ain_position)++;
                            break;
                        } else {
                            continue; //-> check next sign
                        }
                    default:
                        continue; //-> check next sign
                }
                adsc_var_cur->dsc_arg_state.m_stack_pop();
                break;

            case SCRIPT_ARG_CURLY_BRACKET:
                switch ( ach_data[*ain_position] ) {
                    case '{':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_CURLY_BRACKET );
                        continue; //-> check next sign
                    case '[':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_SQUARE_BRACKET );
                        continue; //-> check next sign
                    case '(':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_ROUND_BRACKET );
                        continue; //-> check next sign
                    case '"':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_DOUBLE_QUOTE );
                        continue; //-> check next sign
                    case '\'':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_SINGLE_QUOTE );
                        continue; //-> check next sign
                    case '/':
                        (*ain_position)++;
                        switch ( m_is_slash_comment( ach_data, in_len_data, ain_position ) ) {
                            case SCRIPT_NOT_DECIDED:
                                adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_CUT_AFTER_SLASH );
                                continue;
                            case SCRIPT_ASTERISK_COMMENT:
                                adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_C_COMMENT_1 );
                                continue;
                            case SCRIPT_SLASH_COMMENT:
                                adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_CPP_COMMENT );
                                continue;
                            case SCRIPT_NO_COMMENT:
                                (*ain_position)--;
                                break;
                        }
                        if ( m_check_for_reg_exp( ach_data, in_len_data, *ain_position ) ) {
                            adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_REG_EXP );
                        }
                        continue; //-> check next sign
                    case '?':  
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_QUESTIONMARK );
                        continue; //-> check next sign
                    case '}':
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        if ( ch_sign == '{' && adsc_var_cur->dsc_arg_state.m_size() == 1 ) {
                            (*ain_position)++;
                            break;
                        } else {
                            continue; //-> check next sign
                        }
                    default:
                        continue; //-> check next sign
                }
                adsc_var_cur->dsc_arg_state.m_stack_pop();
                break;
            case SCRIPT_ARG_QUESTIONMARK:
                switch ( ach_data[*ain_position] ) {
                    case '{':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_CURLY_BRACKET );
                        continue; //-> check next sign
                    case '[':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_SQUARE_BRACKET );
                        continue; //-> check next sign
                    case '(':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_ROUND_BRACKET );
                        continue; //-> check next sign
                    case '"':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_DOUBLE_QUOTE );
                        continue; //-> check next sign
                    case '\'':
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_SINGLE_QUOTE );
                        continue; //-> check next sign
                    case '/':
                        (*ain_position)++;
                        switch ( m_is_slash_comment( ach_data, in_len_data, ain_position ) ) {
                            case SCRIPT_NOT_DECIDED:
                                adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_CUT_AFTER_SLASH );
                                continue;
                            case SCRIPT_ASTERISK_COMMENT:
                                adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_C_COMMENT_1 );
                                continue;
                            case SCRIPT_SLASH_COMMENT:
                                adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_CPP_COMMENT );
                                continue;
                            case SCRIPT_NO_COMMENT:
                                (*ain_position)--;
                                break;
                        }
                        if ( m_check_for_reg_exp( ach_data, in_len_data, *ain_position ) ) {
                            adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_REG_EXP );
                        }
                        continue; //-> check next sign
                    case '?':  
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_QUESTIONMARK );
                        continue; //-> check next sign
					case ':':
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
						if ( ch_sign == '?' && adsc_var_cur->dsc_arg_state.m_size() == 1 ) {
                            (*ain_position)++;
                            break;
                        } else {
                            continue; //-> check next sign
                        }
                        continue; //-> check next sign
                    default:
						continue;
                }
				adsc_var_cur->dsc_arg_state.m_stack_pop();
				break;
            case SCRIPT_ARG_DOUBLE_QUOTE:
                switch ( ach_data[*ain_position] ) {
                    case '\\':
                        adsc_var_cur->bo_not_read_next_sign = true;
                        (*ain_position)++;
                        if ( *ain_position == in_len_data - 1 ) {
                            adsc_var_cur->bo_not_read_next_sign = false;
                        }
                        break;
                    case '"':
                        adsc_var_cur->bo_not_read_next_sign = false;
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        break;
                    default:
                        adsc_var_cur->bo_not_read_next_sign = false;
                        break;
                }
                continue; //-> check next sign

            case SCRIPT_ARG_SINGLE_QUOTE:
                switch ( ach_data[*ain_position] ) {
                    case '\\':
                        adsc_var_cur->bo_not_read_next_sign = true;
                        (*ain_position)++;
                        if ( *ain_position == in_len_data - 1 ) {
                            adsc_var_cur->bo_not_read_next_sign = false;
                        }
                        break;
                    case '\'':
                        adsc_var_cur->bo_not_read_next_sign = false;
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        break;
                    default:
                        adsc_var_cur->bo_not_read_next_sign = false;
                        break;
                }
                continue; //-> check next sign

            case SCRIPT_ARG_REG_EXP:
                switch ( ach_data[*ain_position] ) {
					case '[':
						bol_ignore_slash = true;
						break;
					case ']':
						bol_ignore_slash = false;
						break;
					case '\\':
                        (*ain_position)++;
                        break;
                    case '/':
						if( !bol_ignore_slash )
						{
							adsc_var_cur->dsc_arg_state.m_stack_pop();
						}
                        break;
                    default:
                        break;
                }
                continue; //-> check next sign

            case SCRIPT_ARG_CUT_AFTER_SLASH:
                switch ( m_is_slash_comment( ach_data, in_len_data, ain_position ) ) {
                    case SCRIPT_NOT_DECIDED:
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_CUT_AFTER_SLASH );
                        continue;
                    case SCRIPT_ASTERISK_COMMENT:
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_C_COMMENT_1 );
                        continue;
                    case SCRIPT_SLASH_COMMENT:
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_CPP_COMMENT );
                        continue;
                    case SCRIPT_NO_COMMENT:
                        break;
                }
                if ( m_check_for_reg_exp( ach_data, in_len_data, *ain_position ) ) {
                    adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_REG_EXP );
                } else {
                    adsc_var_cur->dsc_arg_state.m_stack_pop();
                }
                continue; //-> check next sign

            case SCRIPT_ARG_C_COMMENT_1:
                switch ( ach_data[*ain_position] ) {
                    case '*':
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_C_COMMENT_2 );
                        break;
                    default:
                        break;
                }
                continue;

            case SCRIPT_ARG_C_COMMENT_2:
                switch ( ach_data[*ain_position] ) {
                    case '*':
                        break;
                    case '/':
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        break;
                    default:
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_C_COMMENT_1 );
                        break;
                }
                continue;

            case SCRIPT_ARG_CPP_COMMENT:
                switch ( ach_data[*ain_position] ) {
                    case '\n':
                    case '\r':
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        break;
                    default:
                        break;
                }
                continue;
            case SCRIPT_ARG_AMPERS_AND:
                switch ( ach_data[*ain_position] ) {
                    case '#':
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_GET_SEMICOLON );
                        break;
                    case 'A':
                    case 'a':
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_AMPERS_AND_A );
                        break;
                    case 'Q':
                    case 'q':
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_AMPERS_AND_Q );
                        break;
                    default:
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        break;
                }
                continue;

            case SCRIPT_ARG_AMPERS_AND_A:
                switch ( ach_data[*ain_position] ) {
                    case 'M':
                    case 'm':
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_AMPERS_AND_AM );
                        break;
                    default:
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        break;
                }
                continue;

            case SCRIPT_ARG_AMPERS_AND_AM:
                switch ( ach_data[*ain_position] ) {
                    case 'P':
                    case 'p':
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_AMPERS_AND_END );
                        break;
                    default:
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        break;
                }
                continue;

            case SCRIPT_ARG_AMPERS_AND_Q:
                switch ( ach_data[*ain_position] ) {
                    case 'U':
                    case 'u':
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_AMPERS_AND_QU );
                        break;
                    default:
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        break;
                }
                continue;

            case SCRIPT_ARG_AMPERS_AND_QU:
                switch ( ach_data[*ain_position] ) {
                    case 'O':
                    case 'o':
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_AMPERS_AND_QUO );
                        break;
                    default:
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        break;
                }
                continue;

            case SCRIPT_ARG_AMPERS_AND_QUO:
                switch ( ach_data[*ain_position] ) {
                    case 'T':
                    case 't':
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        adsc_var_cur->dsc_arg_state.m_stack_push( SCRIPT_ARG_AMPERS_AND_END );
                        break;
                    default:
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        break;
                }
                continue;

            case SCRIPT_ARG_AMPERS_AND_END:
                switch ( ach_data[*ain_position] ) {
                    case ';':
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        break;
                    default:
                        (*ain_position)--;
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        break;
                }
                continue;

            case SCRIPT_ARG_GET_SEMICOLON:
                switch ( ach_data[*ain_position] ) {
                    case ';':
                        adsc_var_cur->dsc_arg_state.m_stack_pop();
                        break;
                    default:
                        break;
                }
                continue;

            default:
                adsc_var_cur->dsc_arg_state.m_stack_pop();
                continue; //-> check next sign
        }
        break;
    }

    if ( *ain_position >= in_len_data ) {
        *ain_position = in_len_data;
        if ( adsc_var_cur->dsc_arg_state.m_empty() ) {
            in_return = SCRIPT_ARG_COMPLETE;
        } else {
            // save last sign: (needed in case of slash at beginning of next data block)
            m_get_last_sign( ach_data, *ain_position - 1, &adsc_var_cur->ch_last_sign );
            in_return = SCRIPT_ARG_PARTIAL;
        }
    } else {
        in_return = SCRIPT_ARG_COMPLETE;
    }
   *ain_len_arg = *ain_position - in_arg_start;
   if ( *ain_len_arg < 0 ) {
       *ain_len_arg = 0;
   }

   return in_return;
} // end of ds_interpret_script::m_get_argument


/**
 *
 * ds_interpret_script::m_check_for_reg_exp
 *
 * @param[in]       char*       ach_data            pointer to data
 * @param[in]       int         in_len_data         length of data
 * @param[in]       int         in_position         actual position in data
 *
 * @return          bool                            true if expression is reg exp
 *                                                  false otherwise
*/
bool ds_interpret_script::m_check_for_reg_exp( const char* ach_data, int in_len_data, int in_position )
{
    if ( ach_data == NULL || in_position >= in_len_data ) {
        return false;
    }
    in_position --;
    if ( in_position >= 0 ) { /* MJ Ticket [21953] */
        in_position = m_get_last_sign( ach_data, in_position, &adsc_var_cur->ch_last_sign );        
    }

#if 0
    // MJ 28.03.2011: google fix
    if (    in_position                 < 0
         && adsc_var_cur->ch_last_sign == 'e'
         && dsc_variables.m_size()      >  1 ) {
        //ds_scriptvariables *adsl_var = dsc_variables.m_get( dsc_variables.m_size() - 2 );
        ds_scriptvariables *adsl_var = dsc_variables.m_stack_current_element()->ads_next->dsc_element;
        adsc_var_cur->ch_last_sign = adsl_var->ch_last_sign;
    }
#endif

    switch ( adsc_var_cur->ch_last_sign ) {
        case '[':
        case ',':
        case '(':
        case '=':
        case ':':
        case '&':
        case '|': // SH&SM 
        case '?':
        case '+': // MJ 08.09.09, Ticket [18424]
        case '-': // SH&SM 
        case '!': // MJ 18.06.10, Ticket [20152]
        case ';': // MJ 18.06.10, Ticket [20152]
        case '^': // SH&SM 
        case '%': // SH&SM 
        case '>': // SH&SM 
        case '<': // SH&SM 
        case '/': // SH&SM 
        case '~': // SH&SM 
			return true;
        case 'n':
            if ( m_last_word_equals( ach_data, in_position, "return" ) == true ) {
                return true;
            }
            break;
        case 'f':
            if ( m_last_word_equals( ach_data, in_position, "typeof" ) == true ) {
                return true;
            }
            if ( m_last_word_equals( ach_data, in_position, "instanceof" ) == true ) {
                return true;
            }
            break;
        case 'e':
            if ( m_last_word_equals( ach_data, in_position, "delete" ) == true ) {
                return true;
            }
            break;
        case 'w':
            if ( m_last_word_equals( ach_data, in_position, "new" ) == true ) {
                return true;
            }
            if ( m_last_word_equals( ach_data, in_position, "throw" ) == true ) {
                return true;
            }
            break;
        default:
            break;
    }

    return false;
} // end of ds_interpret_script::m_check_for_reg_exp


/**
 * private function ds_interpret_script::m_last_word_equals
 *
 * @param[in]       char*       ach_data            pointer to data
 * @param[in]       int         in_position         actual position in data
 * @param[in]       const char* ach_compare         compare with this
 * @return          bool
*/
bool ds_interpret_script::m_last_word_equals( const char* ach_data, int in_position,
                                              const dsd_const_string& rdsp_compare )
{
    // initialize some variables:
    ds_hstring ds_lword( ads_session->ads_wsp_helper );
    int        in_word_end = in_position + 1;

    for ( ; in_position >= 0; in_position-- ) {
        switch ( ach_data[in_position] ) {
            case ' ':
            case '\t':
            case '\n':
            case '\r':
            case '{':
            case '(':
            case '[':
            case '=':
            case '?':
            case '/':
                in_position++;
                break;
            default:
                continue;
        }
        break;
    }

    ds_lword.m_write( &ach_data[in_position], in_word_end - in_position );
    return ds_lword.m_equals( rdsp_compare );
} // end of ds_interpret_script::m_last_word_equals


/**
 *
 * ds_interpret_script::m_get_last_sign
 *
 * @param[in]       char*       ach_data            pointer to data
 * @param[in]       int         in_position         actual position in data
 * @param[out]      char*       ach_last_sign       last sign of data (except white spaces)
 *
 * @return          bool                            true = last sign found
 *                                                  false otherwise
 *
*/
int ds_interpret_script::m_get_last_sign( const char* ach_data, int in_position, char* ach_last_sign )
{
    for ( ; in_position >= 0; in_position-- ) {
        switch ( ach_data[in_position] ) {
            case ' ':
            case '\t':
            case '\n':
            case '\r':
                continue;
            default:
                *ach_last_sign = ach_data[in_position];
                return in_position;
        }
        break;
    }
    return -1;
} // end of ds_interpret_script::m_get_last_sign


/**
 *
 * ds_interpret_script::m_get_last_sign_before_newline
 *
 * @param[in]       char*       ach_data            pointer to data
 * @param[in]       int         in_position         actual position in data
 * @param[out]      char*       ach_last_sign       last sign of data (except white spaces)
 *
 * @return          bool                            true = last sign found
 *                                                  false otherwise
 *
*/
bool ds_interpret_script::m_get_last_sign_before_newline( const char* ach_data, int in_position, char* ach_last_sign )
{
    bool bo_return = false;

    for ( ; in_position >= 0; in_position-- ) {
        switch ( ach_data[in_position] ) {
            case '\n':
            case '\r':
                break;
            default:
                continue;
        }
        break;
    }

    for ( ; in_position >= 0; in_position-- ) {
        switch ( ach_data[in_position] ) {
            case ' ':
            case '\t':
            case '\n':
            case '\r':
                continue;
            default:
                *ach_last_sign = ach_data[in_position];
                bo_return = true;
                break;
        }
        break;
    }
    return bo_return;
} // end of ds_interpret_script::m_get_last_sign_before_newline


/**
 *
 * ds_interpret_script::m_get_following_sign
 *
 * @param[in]       char*       ach_data            pointer to data
 * @param[in]       int         in_len_data         length of ach_data
 * @param[in]       int         in_position         actual position in data
 * @param[out]      char*       ach_next_sign       next sign in data (except white spaces)
 *
 * @return          bool                            true = next sign found
 *                                                  false otherwise
 *
*/
bool ds_interpret_script::m_get_following_sign( const char* ach_data, int in_len_data, int in_position, char* ach_next_sign ) 
{
    bool bo_return = false;
    for ( ; in_position < in_len_data; in_position++ ) {
        switch ( ach_data[in_position] ) {
            case ' ':
            case '\t':
            case '\n':
            case '\r':
                continue;
            default:
                *ach_next_sign = ach_data[in_position];
                bo_return = true;
                break;
        }
        break;
    }
    return bo_return;
} // end of ds_interpret_script::m_get_following_sign


/**
 *
 * ds_interpret_script::m_get_next_word
 *
 * @param[in]       char*       ach_data            pointer to data
 * @param[in]       int         in_len_data         length of data
 * @param[in,out]   int*        ain_position        actual position in data
 * @param[in]       int         in_word_key         word key of last found word
 * @param[out]      char**      aach_word           pointer to word
 * @param[out]      int*        ain_len_word        length of word
 * @param[out]      int*        ain_word_start      start position of word
 * @param[in]       bool        bo_get_cut_word     search cut word?
 *                                                  default value = false
 *
 * @return          int                             key:
 *                                                    SCRIPT_NO_WORD       = no word found
 *                                                    SCRIPT_WORD_PARTIAL  = word partial found
 *                                                    SCRIPT_WORD_COMPLETE = word completely found
 *
*/
int ds_interpret_script::m_get_next_word( const char* ach_data, int in_len_data, int* ain_position, int in_word_key,
                                          const char** aach_word, int* ain_len_word, int* ain_word_start,
                                          bool bo_get_cut_word )
{
    // initialize some variables:
    int in_return     = SCRIPT_NO_WORD;
    
    if ( ach_data == NULL || in_len_data <= 0 || *ain_position >= in_len_data ) {
        return in_return;
    }

	if ( ((*ain_position) + 4 <= in_len_data) && (memcmp(ach_data, "++b.", 4)==0)) {
		in_return     = SCRIPT_NO_WORD;
	}

    if ( !bo_get_cut_word ) {
        m_pass_signs( ach_data, in_len_data, ain_position, " \n\r\t\v\f" );
    }
    if ( in_word_key != ds_attributes::ied_scr_attr_function && in_word_key != ds_attributes::ied_scr_attr_var ) {
        *ain_word_start = *ain_position;
        *aach_word      = ach_data + *ain_position;
    }
    if ( *ain_position < in_len_data && (unsigned)(ach_data[*ain_position] + 1) < 257 && isdigit(ach_data[*ain_position]) ) { 
        while ( *ain_position < in_len_data && ach_data[*ain_position] > 0 && isdigit(ach_data[*ain_position]) ) {
            (*ain_position)++;
        }
    } else {
        for ( ; *ain_position < in_len_data; (*ain_position)++ ) {
            switch ( ach_data[*ain_position] ) {
                case '\f':
                case '\n':
                case '\r':
                case '\t':
                case '\v':
                case ' ':
                case '(':
                case ')':
                case '{':
                case '}':
                case '[':
                case ']':
                case '.':
                case ';':
                case ',':
                case '=':
                case '<':
                case '>':
                case '+':
                case '-':
                case '*':
                case '/':
                case '&':
                case '?':
                case '!':
                case ':':
                case '|':
                case '"':
                case '\'':
                case '%':
                case '@':
                    break;
                default:
                    continue;
            }
            break;
        }
    }
    if ( *ain_position >= in_len_data ) {
        in_return = SCRIPT_WORD_PARTIAL;
    } else {
        in_return = SCRIPT_WORD_COMPLETE;
    }
    *ain_len_word = *ain_position - *ain_word_start;
    if ( *ain_len_word < 0 ) {
        *ain_len_word = 0;
    }
    return in_return;
} // end of ds_interpret_script::m_get_next_word


/**
 *
 * ds_interpret_script::m_get_next_sign
 *
 * @param[in]       char*   ach_data                pointer to data
 * @param[in]       int     in_len_data             length of data
 * @param[in,out]   int*    ain_position            actual position in data
 * @param[out]      char**  aach_sign               pointer to found sign
 * @param[out]      int*    ain_len_sign            length of aach_sign
 * @param[out]      int*    ain_sign_position       relevant position in ach_sign
 * @param[out]      char**  aach_white_spaces       pointer to white spaces
 * @param[out]      int*    ain_len_white_spaces    length of *aach_white_spaces
 *
 * @return          int                             key:
 *                                                    SCRIPT_NO_SIGN    = no sign found
 *                                                    SCRIPT_SIGN_FOUND = sign found
 *
*/
int ds_interpret_script::m_get_next_sign( const char* ach_data, int in_len_data, int* ain_position, 
                                          const char** aach_sign, int* ain_len_sign, int* ain_sign_position,
                                          const char** aach_white_spaces, int* ain_len_white_spaces )
{
    // initialize some variables:
    int  in_return           = SCRIPT_NO_SIGN;
    int  in_start_sign       = *ain_position;
    adsc_var_cur->in_append_data = 0;
    *aach_sign               = "e";
    *ain_len_sign            = 0;
    if ( ain_sign_position != NULL ) {
         *ain_sign_position = 0;
    }

    if ( ain_len_white_spaces != NULL ) {
        // reset *aach_white_spaces:
        *aach_white_spaces = NULL;
        *ain_len_white_spaces = 0;
    }
    m_pass_signs( ach_data, in_len_data, ain_position, " \n\r\t\v\f" );
    if ( in_start_sign < *ain_position && ain_len_white_spaces != NULL ) {
        // set pointer to white spaces:
        *aach_white_spaces    = ach_data + in_start_sign;
        *ain_len_white_spaces = *ain_position - in_start_sign;
    }
    if ( ach_data == NULL || in_len_data <= 0 || *ain_position >= in_len_data ) {
        return in_return;
    }
    in_return     = SCRIPT_SIGN_FOUND;
    *aach_sign    = &ach_data[*ain_position];
    in_start_sign = *ain_position;
	switch(ach_data[*ain_position]) {
	case '/':                  // Slash Comment/Regexp will be handled by caller.
	case ':':                  
	case '?':                  
		(*ain_position)++;
        *ain_len_sign = 1;      
		return in_return;
	default:
		break;
	}

    if ( (ach_data[*ain_position] > 0) && !isalpha( ach_data[*ain_position] ) ) {
        if ( ach_data[*ain_position] != '_' ) {
            (*ain_position)++;
            if ( ach_data[*ain_position - 1] != '(' && ach_data[*ain_position - 1] != '[' ) {
                while ( ach_data[*ain_position] == '=' || ach_data[*ain_position] == '+' || ach_data[*ain_position] == '-' ) {
                    (*ain_position)++;
                    if ( (*ain_position) >= in_len_data ) {
                        break;
                    }
                }
            }
            *ain_len_sign = *ain_position - in_start_sign;
        }
    }

    // get sign position:
    const char* ach_test = *aach_sign;
    if ( ain_sign_position != NULL && *ain_len_sign > 1 ) {
        switch ( *aach_sign[0] ) {
            case '+':
                if ( ach_test[1] == '=' ) {
                    *ain_sign_position = 1;
                    adsc_var_cur->in_append_data = 1;
                } else if ( ach_test[1] == '+' ) {
	                *aach_sign    = "++p";
                    *ain_len_sign = 2;      // for writing "++" if sign must be inserted
                    *ain_sign_position = 2; // not handle as normal "+"
                }
                break;
            case '-':
                if ( ach_test[1] == '=' ) {
                    *ain_sign_position = 1;
                    adsc_var_cur->in_append_data = -1;
                } else if ( ach_test[1] == '-' ) {
                    *aach_sign    = "--m";
                    *ain_len_sign = 2;      // for writing "--" if sign must be inserted
                    *ain_sign_position = 2; // not handle as normal "-"
                }
                break;
            case '=':
                if ( ach_test[1] == '=' ) {
                    if ( *ain_len_sign > 2 ) {
                        switch ( ach_test[2] ){
                            case '=':
                                if ( *ain_len_sign > 3 ) {
                                    switch ( ach_test[3] ){
                                        case '+':
                                            if ( *ain_len_sign > 4 ) {
                                                if ( ach_test[4] == '+' ){
                                                    *aach_sign    = "===++e";
                                                    *ain_len_sign = 5;
                                                    *ain_sign_position = 5;
                                                }
                                            } else {
                                                *ain_len_sign = 4;
                                                *ain_sign_position = 4;
                                                *aach_sign    = "===+e";
                                            }
                                            break;
                                        case '-':
                                            if ( *ain_len_sign > 4 ) {
                                                if ( ach_test[4] == '-' ){
                                                    *aach_sign    = "===--e";
                                                    *ain_len_sign = 5;
                                                    *ain_sign_position = 5;
                                                }
                                            } else {
                                                *ain_len_sign = 4;
                                                *ain_sign_position = 4;
                                                *aach_sign    = "===-e";
                                            }
                                            break;
                                        default:
                                            *ain_len_sign = 3;
                                            *ain_sign_position = 3;
                                            *aach_sign    = "===e";
                                            break;
                                    }
                                } else {
                                    *ain_len_sign = 3;
                                    *ain_sign_position = 3;
                                    *aach_sign    = "===e";
                                }
                                break;
                            case '+':
                                if ( *ain_len_sign > 3 ) {
                                    if ( ach_test[3] == '+' ){
                                        *aach_sign    = "==++e";
                                        *ain_len_sign = 4;
                                        *ain_sign_position = 4;
                                    }
                                } else {
                                    *ain_len_sign = 3;
                                    *ain_sign_position = 3;
                                    *aach_sign    = "==+e";
                                }
                                break;
                            case '-':
                                if ( *ain_len_sign > 3 ) {
                                    if ( ach_test[3] == '-' ){
                                        *aach_sign    = "==--e";
                                        *ain_len_sign = 4; 
                                        *ain_sign_position = 4;
                                    }
                                } else {
                                    *ain_len_sign = 3;      // for writing "===" if sign must be inserted
                                    *ain_sign_position = 3; // not handle as normal "=" or "=="
                                    *aach_sign    = "==-e";
                                }
                                break;
                        }
                    } else {
                        // case of compares!!!
                        *aach_sign    = "==e";
                        *ain_len_sign = 2;      // for writing "==" if sign must be inserted
                        *ain_sign_position = 2; // not handle as normal "="
                    }
                }
                break;
            default:
                break;
        } 
    }
    return in_return;
} // end of ds_interpret_script::m_get_next_sign


/**
 *
 * ds_interpret_script::m_handle_double_quotes
 *
 * @param[in]       char*   ach_data        pointer to data
 * @param[in]       int     in_len_data     length of data
 * @param[in,out]   int*    ain_position    actual position in data
 *
 * @return          int                     key:
 *                                            SCRIPT_QUOTE_END_FOUND    = end of quotes found
 *                                            SCRIPT_QUOTE_NO_END_FOUND = end of quotes not found
 *
*/
int ds_interpret_script::m_handle_double_quotes( const char* ach_data, int in_len_data, int* ain_position )
{
    // initialize some variables:
    int in_return = SCRIPT_QUOTE_NO_END_FOUND;

    if ( adsc_var_cur->bo_not_read_next_sign ) {
        (*ain_position)++; // case of "...\"..." cut directly after "\": don't read next sign
        adsc_var_cur->bo_not_read_next_sign = false;
    }

    for ( ; *ain_position < in_len_data; (*ain_position)++ ) {
        switch ( ach_data[*ain_position] ) {
        case '\\':
            (*ain_position)++;
            adsc_var_cur->bo_not_read_next_sign = true;
            if ( *ain_position == in_len_data - 1 ) {
                adsc_var_cur->bo_not_read_next_sign = false;
            }
            continue;
        case '"':
            (*ain_position)++;
            adsc_var_cur->bo_not_read_next_sign = false;
            in_return = SCRIPT_QUOTE_END_FOUND;
            break;
        default:
            adsc_var_cur->bo_not_read_next_sign = false;
            continue;
        }
        break;
    }
    if ( *ain_position < in_len_data ) {
        adsc_var_cur->bo_not_read_next_sign = false;
    } else {
        *ain_position = in_len_data;
    }
    return in_return;
} // end of ds_interpret_script::m_handle_double_quotes


/**
 *
 * ds_interpret_script::m_handle_single_quotes
 *
 * @param[in]       char*   ach_data        pointer to data
 * @param[in]       int     in_len_data     length of data
 * @param[in,out]   int*    ain_position    actual position in data
 *
 * @return          int                     key:
 *                                            SCRIPT_QUOTE_END_FOUND    = end of quotes found
 *                                            SCRIPT_QUOTE_NO_END_FOUND = end of quotes not found
 *
*/
int ds_interpret_script::m_handle_single_quotes( const char* ach_data, int in_len_data, int* ain_position )
{
    // initialize some variables:
    int in_return = SCRIPT_QUOTE_NO_END_FOUND;

    if ( adsc_var_cur->bo_not_read_next_sign ) {
        (*ain_position)++; // case of '...\'...' cut directly after "\": don't read next sign
        adsc_var_cur->bo_not_read_next_sign = false;
    }

    for ( ; *ain_position < in_len_data; (*ain_position)++ ) {
        switch ( ach_data[*ain_position] ) {
        case '\\':
            (*ain_position)++;
            adsc_var_cur->bo_not_read_next_sign = true;
            if ( *ain_position == in_len_data - 1 ) {
                adsc_var_cur->bo_not_read_next_sign = false;
            }
            continue;
        case '\'':
            (*ain_position)++;
            adsc_var_cur->bo_not_read_next_sign = false;
            in_return = SCRIPT_QUOTE_END_FOUND;
            break;
        default:
            adsc_var_cur->bo_not_read_next_sign = false;
            continue;
        }
        break;
    }
    if ( *ain_position < in_len_data ) {
        adsc_var_cur->bo_not_read_next_sign = false;
    } else {
        *ain_position = in_len_data;
    }
    return in_return;
} // end of ds_interpret_script::m_handle_single_quotes


/**
 *
 * ds_interpret_script::m_is_word_in_list
 *
 * @param[in]   char* ach_word
 * @param[in]   int   in_len_word
 *
 * @return      int                 word number
 *
*/
int ds_interpret_script::m_is_word_in_list( const char* ach_word, int in_len_word )
{
    return ads_attr->m_get_scr_attr( ach_word, in_len_word );
} // end of ds_interpret_script::m_is_word_in_list


/**
 *
 * ds_interpret_script::m_is_argument_in_attr_list
 *
 * @param[in]   char* ach_argument
 * @param[in]   int   in_len_argument
 *
 * @return      int                 word number
 *
*/
int ds_interpret_script::m_is_argument_in_attr_list( const char* ach_argument, int in_len_argument )
{
    if ( ach_argument == NULL || in_len_argument < 1 ){
        return -2;
    }

    // initialize some variables:
    int in_return = -1;

    switch ( ach_argument[0] ) {
        case '"':
            if ( ach_argument[in_len_argument - 1] == '"' ) {
                in_return = m_is_word_in_list( &ach_argument[1], in_len_argument - 2 );
            }
            break;
        case '\'':
            if ( ach_argument[in_len_argument - 1] == '\'' ) {
                in_return = m_is_word_in_list( &ach_argument[1], in_len_argument - 2 );
            }
            break;
        default:
            break;
    }
    if ( in_return > ds_attributes::ied_scr_attr_start && in_return < ds_attributes::ied_scr_attr_end ) {
        return in_return;
    } else {
        return -1;
    }
} // end of ds_interpret_script::m_is_argument_in_attr_list


/**
 *
 * function ds_interpret_script::m_free_all_data
 *
 * free all data
 *
*/
void ds_interpret_script::m_free_all_data( )
{
    adsc_var_cur->ds_word.m_reset();
    adsc_var_cur->ds_object.m_reset();
    adsc_var_cur->ds_argument.m_reset();
    adsc_var_cur->ds_spaces.m_reset();
    adsc_var_cur->ds_sign.m_reset();
    adsc_var_cur->ds_arg_sign.m_reset();
    adsc_var_cur->ds_arg_spaces.m_reset();
} // end of ds_interpret_script::m_free_all_data


/**
 *
 * function ds_interpret_script::m_free_vars
 *
 * free all memory
 *
 *
*/
void ds_interpret_script::m_free_vars() 
{
    // call destructor explizit:
    adsc_var_cur->~ds_scriptvariables();
    // free vars itself:
#ifdef TRACE_MEMORY
    m_trace_memory( adsc_var_cur, sizeof(ds_scriptvariables), true );
#endif // TRACE_MEMORY
    ads_session->ads_wsp_helper->m_cb_free_memory( adsc_var_cur, sizeof(ds_scriptvariables) );
    dsc_variables.m_stack_pop();
} // end of ds_interpret_script::m_free_vars


/**
 *
 * function ds_interpret_script::m_get_last_argument
 *
 * @param[in]   char*    ach_argument           pointer to argument
 * @param[in]   int      in_len_argument        length of ach_argument
 *
 * @return      int                             start position of last argument part until ","
 *
*/
int ds_interpret_script::m_get_last_argument( const char* ach_argument, int in_len_argument )
{
    // initialize some variables:
    int in_pos    = in_len_argument;
    int in_return = -1;

    for( ; in_pos > 0; in_pos-- ) {
        switch ( ach_argument[in_pos] ) {
            case ',':
                in_return = in_pos + 1;
                break;
            case '"':
                in_pos--;
                for( ; in_pos > 0; in_pos-- ) {
                    switch ( ach_argument[in_pos] ) {
                        case '"':
                            if (   (in_pos > 0)
                                && (ach_argument[in_pos-1] == '\\') ) {
                                continue;
                            }
                            break;
                        default:
                            continue;
                    }
                    break;
                }
                continue;
            case '\'':
                in_pos--;
                for( ; in_pos > 0; in_pos-- ) {
                    switch ( ach_argument[in_pos] ) {
                        case '\'':
                            if (   (in_pos > 0)
                                && (ach_argument[in_pos-1] == '\\') ) {
                                continue;
                            }
                            break;
                        default:
                            continue;
                    }
                    break;
                }
                continue;
            case ')':
                if ( in_pos < in_len_argument ) {
                    for( ; in_pos > 0; in_pos-- ) {
                        switch ( ach_argument[in_pos] ) {
                            case '(':
                                break;
                            default:
                                continue;
                        }
                        break;
                    }
                }
                continue;
            default:
                continue;
        }
        break;
    }    
    return in_return;
} // end of ds_interpret_script::m_get_last_argument


/**
 *
 * function ds_interpret_script::m_get_sign_position
 *
 * @param[in]   char*    ach_data           pointer to data
 * @param[in]   int      in_len_data        length of ach_data
 * @param[out]  int*     ain_position       actual position in ach_data
 *
 * @return      int                     key:
 *                                        SCRIPT_NOT_DECIDED      = no sign after slash, no decision yet
 *                                        SCRIPT_NO_COMMENT       = slash don't mark start of comment
 *                                        SCRIPT_ASTERISK_COMMENT = slash mark the start of asterisk comment
 *                                        SCRIPT_SLASH_COMMENT    = slash mark the start of slash comment
 *
*/
int ds_interpret_script::m_is_slash_comment( const char* ach_data, int in_len_data, int* ain_position )
{
    int in_return = SCRIPT_NOT_DECIDED;
    if ( *ain_position < in_len_data ) {
        switch ( ach_data[*ain_position] ) {
            case '*':
                (*ain_position)++;
                in_return = SCRIPT_ASTERISK_COMMENT;
                break;
            case '/':
                (*ain_position)++;
                in_return = SCRIPT_SLASH_COMMENT;
                break;
            default:
                in_return = SCRIPT_NO_COMMENT;
                break;
        }
    }
    return in_return;
} // end of ds_interpret_script::m_is_slash_comment


/**
 *
 * function ds_interpret_script::m_handle_c_comment
 *
 * @param[in]   char*    ach_data           pointer to data
 * @param[in]   int      in_len_data        length of ach_data
 * @param[out]  int*     ain_position       actual position in ach_data
 *
 * @return      int                         key:
 *                                           SCRIPT_COMMENT_NO_END_FOUND = end of comment not found
 *                                           SCRIPT_COMMENT_END_FOUND    = end of comment found
 *
*/
int ds_interpret_script::m_handle_c_comment( const char* ach_data, int in_len_data, int* ain_position )
{
    int in_return = SCRIPT_COMMENT_NO_END_FOUND;
	bool bol_asterisk = false;

    for ( ; *ain_position < in_len_data; (*ain_position)++ )
	{    
		switch ( ach_data[*ain_position] )
		{
            case '/':
				if( !bol_asterisk ){ continue; }
				(*ain_position)++;
				in_return = SCRIPT_COMMENT_END_FOUND;
				break;
			case '*':
				bol_asterisk = true;
				continue;
            default:
				bol_asterisk = false;
                continue;
        }
        break;
    }
    return in_return;
} // end of ds_interpret_script::m_handle_c_comment


/**
 *
 * function ds_interpret_script::m_handle_cpp_comment
 *
 * @param[in]   char*    ach_data           pointer to data
 * @param[in]   int      in_len_data        length of ach_data
 * @param[out]  int*     ain_position       actual position in ach_data
 *
 * @return      int                         key:
 *                                           SCRIPT_COMMENT_NO_END_FOUND = end of comment not found
 *                                           SCRIPT_COMMENT_END_FOUND    = end of comment found
 *
*/
int ds_interpret_script::m_handle_cpp_comment( const char* ach_data, int in_len_data, int* ain_position )
{
    int in_return = SCRIPT_COMMENT_NO_END_FOUND;
    for ( ; *ain_position < in_len_data; (*ain_position)++ ) {
        switch ( ach_data[*ain_position] ) {
            case '\n':
            case '\r':
                (*ain_position)++;
                in_return = SCRIPT_COMMENT_END_FOUND;
                break;
            default:
                continue;
        }
        break;
    }
    return in_return;
} // end of ds_interpret_script::m_handle_cpp_comment


/**
 *
 * function ds_interpret_script::m_handle_regexp
 *
 * @param[in]   char*    ach_data           pointer to data
 * @param[in]   int      in_len_data        length of ach_data
 * @param[out]  int*     ain_position       actual position in ach_data
 *
 * @return      int                         key:
 *                                           SCRIPT_REGEXP_NO_END_FOUND = end of regexp not found
 *                                           SCRIPT_REGEXP_END_FOUND    = end of regexp found
 *
*/
int ds_interpret_script::m_handle_regexp( const char* ach_data, int in_len_data, int* ain_position )
{
    int in_return = SCRIPT_REGEXP_NO_END_FOUND;
    for ( ; *ain_position < in_len_data; (*ain_position)++ ) {
        switch ( ach_data[*ain_position] ) {
            case '/':
                in_return = SCRIPT_REGEXP_END_FOUND;
                break;
            case '\\':
                (*ain_position)++;
                continue;
            default:
                continue;
        }
        break;
    }
    return in_return;
} // end of ds_interpret_script::m_handle_regexp


/**
 *
 * function ds_interpret_script::m_is_sign_bracket
 * 
 * @param[in]   char    ch_sign         sign
 *
 * @return      bool                    true = sign is '(' or '['
 *                                      false otherwise
 *
*/
bool ds_interpret_script::m_is_sign_bracket( char ch_sign )
{
	if ( ch_sign == '?' )
		return true;
    if ( ch_sign == '(' || ch_sign == '[' ) 
		return true;
	return false;
} // end of ds_interpret_script::m_is_sign_bracket


/**
 *
 * function ds_interpret_script::m_is_sign_bracket
 * 
 * @param[in]   char* ach_white_spaces
 * @param[in]   int   in_len_white_spaces   
 *
 * @return      bool
 *
*/
bool ds_interpret_script::m_is_newline_in_spaces( const char* ach_white_spaces, int in_len_white_spaces )
{
    bool bo_return = false;
    int  in_counter;
    for ( in_counter = 0; in_counter < in_len_white_spaces; in_counter++ ) {
        switch ( ach_white_spaces[in_counter] ) {
            case '\n':
            case '\r':
                bo_return = true;
                break;
            default:
                continue;
        }
        break;
    }
    return bo_return;
} // end of ds_interpret_script::m_is_newline_in_spaces


/**
 *
 * function ds_interpret_script::m_append_space
 * 
 * @param[in]   char* ach_data
 * @param[in]   char* ach_object
 *
 * @return      bool
 *
*/
bool ds_interpret_script::m_append_space( const char* ach_data, const char* ach_object ) {
    // initialize some variables:
    bool bo_return = false;
    char ch_test;

    if ( ach_object == NULL ) {
        return bo_return;
    }
    if ( ach_data == ach_object ) {
        bo_return = true;
    } else {
        switch ( ach_object[0] ) {
            case '(':
            case '{':
            case '[':
                ch_test = (ach_object - 1)[0];
                if ( (ch_test > 0) && isalpha(ch_test) ) {
                    bo_return = true;
                }
                break;
            default:
                break;
        }
    }
    return bo_return;
} // end of ds_interpret_script::m_append_space


/**
 *
 * function ds_interpret_script::m_rec_attribute
 * 
 * @param[in]   int     in_word_key
 *
 * @return      bool    true:  attribute shoul be handled recursiv
 *                             means document.location.anything will be
 *                             changed to HOB_get_attr(document.location,"args").anything
 *                      false: otherwise
 *
*/
bool ds_interpret_script::m_rec_attribute( int in_word_key )
{
    bool bo_return = false;
    
    switch ( in_word_key ) {
        case ds_attributes::ied_scr_attr_style:
        case ds_attributes::ied_scr_attr_value:
            break;
        default:
            bo_return = true;
            break;
    }
    return bo_return;
} // end of ds_interpret_script::m_rec_attribute


/**
 *
 * function ds_interpret_script::m_rec_object
 * 
 * @param[in]   int     in_word_key
 *
 * @return      bool    true:  attribute shoul be handled recursiv
 *                             means document.firstchild.anything will be
 *                             changed to HOB_object(document.firstchild).anything
 *                      false: otherwise
 *
*/
bool ds_interpret_script::m_rec_object( int in_word_key )
{
    // TAKE CARE: special handling for "images", "forms" and "all":
    //  if "images" or "forms" is followed by a word, in all (but one) cases this will be
    //  the "name" Attribute of the tags. The only word, this is not right is "length".
    //  But "length" is also in our list (as attribute), so we will get something like
    //  "HOB_get_attr( document.images, 'length' )".
    //  this function takes care of this case and gives back the right value!!! 
    //  therefore, we don't insert the "HOB_object" function in this case!
    bool bo_return = false;

    switch ( in_word_key ) {
        case ds_attributes::ied_scr_attr_forms:
        case ds_attributes::ied_scr_attr_images:
        case ds_attributes::ied_scr_attr_all:
            break;
        default:
            bo_return = true;
            break;
    }
    return bo_return;
} // end of ds_interpret_script::m_rec_object


/**
 *
 * function
 *
 * @param[in]   char*   ach_word
 * @param[in]   int     in_len_word
 *
 * @return      bool
 *
*/
bool ds_interpret_script::m_is_word_cc_on( const char* ach_word, int in_len_word )
{
    // initialize some variables:
    bool bo_ret = false;
    int  in_ret;

    in_ret = ads_attr->m_get_scr_cc( ach_word, in_len_word );
    if ( in_ret > -1 ) {
        bo_ret = true;
    }

    if ( in_ret == ds_attributes::ied_cc_cc_on ) {
        adsc_var_cur->bo_cc_on = true;
    }

    // all other expressions only count, if "/*@cc_on ... */" occurred!
    if ( bo_ret && !adsc_var_cur->bo_cc_on ) {
        bo_ret = false;
    }

    return bo_ret;
} // end of ds_interpret_script::m_is_word_cc_on


/**
 *
 * function ds_interpret_script::m_add_withobject
 *
 * @param[in]   char*   ach_add         data to add
 * @param[in]   int     in_len          length of ach_add
 * @param[in]   bool    bo_bracket      true = add bracket
 *
*/
void ds_interpret_script::m_add_withobject( char* ach_add, int in_len, bool bo_bracket )
{
    // initialize some variables:
    ds_with_variables*  ads_oldvar     = NULL;  // last vars in stack
    ds_with_variables*  ads_newvar     = NULL;  // new vars for inserting in stack
    int                 in_needed_size = 0;     // needed memory size for new entry
                                                // cause we do not want to resize memory

    // evalute needed memory size:
    in_needed_size = in_len;
    if ( ads_oldvar != NULL ) {
        in_needed_size += ads_oldvar->ds_object.m_get_len() + 1;   // 1 for inserting "." between to objects
    }

    // insert some new element pointer
    ads_newvar = (ds_with_variables*)ads_session->ads_wsp_helper->m_cb_get_memory( sizeof(ds_with_variables), true );
#ifdef TRACE_MEMORY        
    m_trace_memory( ads_newvar, sizeof(ds_with_variables), false );
#endif // TRACE_MEMORY
    ads_newvar->ds_object.m_setup( ads_session->ads_wsp_helper, in_needed_size );
    ads_newvar->in_brackets = -1;

    // save old value + "."
    if ( ads_oldvar != NULL ) {
        ads_newvar->ds_object.m_write( ads_oldvar->ds_object.m_get_ptr(),
                                       ads_oldvar->ds_object.m_get_len()   );
        ads_newvar->ds_object.m_write( ".", 1 );
    }

    // save new value:
    ads_newvar->ds_object.m_write( ach_add, in_len );

    // set bracket if wanted:
    if ( bo_bracket == true ) {
        ads_newvar->in_brackets = 1;
    }

    // push newvar into stack:
    adsc_var_cur->dsc_vwith.m_stack_push( ads_newvar );
    ads_newvar = NULL; // pointer is now saved in stack

    return;
} // end of ds_interpret_script::m_add_withobject

#if 0
/**
 *
 * function ds_interpret_script::m_free_withobject
 *
 * @param[in]   ds_with_variables* ads_free
 *
*/
void ds_interpret_script::m_free_withobject( ds_with_variables* ads_free )
{
    // call memory class destructor explizit:
    ads_free->ds_object.~ds_hstring();

    // free memory itself:
    ads_session->ads_wsp_helper->m_cb_free_memory( ads_free, sizeof(ds_with_variables) );
} // end of ds_interpret_script::m_free_withobject
#endif

/**
 *
 * function ds_interpret_script::m_build_HOB_set_attr
 *
 * @param[out]  ds_hstring*  ads_out             pointer to output memory
 * @param[in]   int         in_append_data      sign for using =, += or -=
 * @param[in]   char*       ach_object          pointer to object
 * @param[in]   int         in_len_object       length of ach_object
 * @param[in]   char*       ach_word            pointer to word
 * @param[in]   int         in_len_word         length of ach_word
 * @param[in]   int         in_word_key         word key (from list)
 * @param[in]   char*       ach_argument        pointer to argument
 * @param[in]   int         in_len_argument     length of argument
 *
*/
void ds_interpret_script::m_build_HOB_set_attr( ds_hstring* ads_out, 
                                                int in_append_data,
                                                const char* ach_object,   int in_len_object,
                                                const char* ach_word,     int in_len_word, 
                                                int in_word_key, 
                                                const char* ach_argument, int in_len_argument )
{
    // initialize some variables:
    bool       bo_insert_prop    = false;   // is HOB_CHECK_PROPERTY needed?
    ds_hstring ds_prop;                     // output buffer for m_build_HOB_check_property
    ds_prop.m_setup( ads_session->ads_wsp_helper );

    // check if we have an withobject set:
    bo_insert_prop = m_build_HOB_check_property( &ds_prop, 
                                                 ach_object, in_len_object,
                                                 ach_word,   in_len_word );
    if ( bo_insert_prop == true ) {
        ach_object    = ds_prop.m_get_ptr();
        in_len_object = ds_prop.m_get_len();
    }
    
    // no object and/or with object exists -> return orginal data:
    if (    in_len_object == 0
         && in_word_key != ds_attributes::ied_scr_attr_location ) {
        ads_out->m_set( ach_word, in_len_word );   // false for overwrite data!
        switch ( in_append_data ) {
            case 1:
                ads_out->m_write( "+=" );
                break;
            case -1:
                ads_out->m_write( "-=" );
                break;
            default:
                ads_out->m_write( "=" );
                break;
        }
        ads_out->m_write( ach_argument, in_len_argument );
        return;
    }

    // intialize ads_out (false for overwrite existing data):
    ads_out->m_set( HOB_SET_ATTRIBUTE );

    // insert in_append_data (as char* !)
    switch ( in_append_data ) {
        case 1:
            ads_out->m_write( "1," );
            break;
        case -1:
            ads_out->m_write( "-1," );
            break;
        default:
            ads_out->m_write( "0," );
            break;
    }


    // append object:
    if ( in_len_object > 0 ) {            
        if ( ach_object[in_len_object - 1] == '.' ) {
            in_len_object--;
        }
        ads_out->m_write( ach_object, in_len_object );
    }

    // insert '' if no object exists
    if ( in_len_object == 0 ) {
#if SM_USE_FUNCTION2
        ads_out->m_write( "this" );
#else
        // MJ 16.09.10, Ticket[20581]:
        switch( ienc_in_quotes ) {
            case ied_in_single_quotes:
                ads_out->m_write( "\"\"" );
                break;
            default:
                ads_out->m_write( "''" );
                break;
        }
#if 0
        ads_out->m_write( "''" );
#endif
#endif
    }

    // append word:
    // MJ 16.09.10, Ticket[20581]:
    switch( ienc_in_quotes ) {
        case ied_in_single_quotes:
            ads_out->m_write( ",\"" );
            ads_out->m_write( ach_word, in_len_word );
            ads_out->m_write( "\"" );
            break;
        default:
            ads_out->m_write( ",'" );
            ads_out->m_write( ach_word, in_len_word );
            ads_out->m_write( "'" );
            break;
    }
    if ( in_len_argument > 0 ) {
        ads_out->m_write( "," );
        // append argument:
        ads_out->m_write( ach_argument, in_len_argument );
    }
    ads_out->m_write( ")" );
    return;
} // end of ds_interpret_script::m_build_HOB_set_attr


/**
 *
 * function ds_interpret_script::m_build_HOB_get_attr
 *
 * @param[out]  ds_hstring*  ads_out             pointer to output memory
 * @param[in]   char*       ach_object          pointer to object
 * @param[in]   int         in_len_object       length of ach_object
 * @param[in]   char*       ach_word            pointer to word
 * @param[in]   int         in_len_word         length of ach_word
 * @param[in]   char*       ach_sign            pointer to signs after ach_word
 * @param[in]   int         in_len_sign         length of ach_sign
 *
*/
void ds_interpret_script::m_build_HOB_get_attr( ds_hstring* ads_out,
                                                const char* ach_object, int in_len_object, 
                                                const char* ach_word,   int in_len_word,
                                                const char* ach_sign,   int in_len_sign )
{
    // initialize some variables:
    bool       bo_insert_prop    = false;   // is HOB_CHECK_PROPERTY needed?
    ds_hstring ds_prop;                     // output buffer for m_build_HOB_check_property
    ds_prop.m_setup( ads_session->ads_wsp_helper );

	if ((in_len_object > 0) && (*ach_object == 'b')){
		bo_insert_prop = true;
	}

	// check if we have an withobject set:
    bo_insert_prop = m_build_HOB_check_property( &ds_prop, 
                                                 ach_object, in_len_object,
                                                 ach_word,   in_len_word );
    if ( bo_insert_prop == true ) {
        ach_object    = ds_prop.m_get_ptr();
        in_len_object = ds_prop.m_get_len();
    }

    // no object and/or with object exists -> return orginal data:
    if ( (in_len_object == 0) || 
         (in_len_object == 1 && ach_object[0] == '.') ) {
        ads_out->m_reset(); // clear existing data in memory!
        if ( in_len_object > 0 ) {
            ads_out->m_write( ach_object, in_len_object );
        }
        ads_out->m_write( ach_word, in_len_word );
        if ( ach_sign != NULL && in_len_sign > 0 ) {
            ads_out->m_write( ach_sign, in_len_sign );
        }
        return;
    }

    
    // intialize ads_out (false for overwrite existing data):
    ads_out->m_set( HOB_GET_ATTRIBUTE );

    // append object:
    if ( in_len_object > 0 ) {
#ifndef B141112
        if ( ach_object[in_len_object - 1] == '.' ) {
            in_len_object--;
		}
		BOOL bol_finished = FALSE;
		int inl_word_key;   // keyword enumeration 
		int iml_tail = in_len_object; // part at end of object to be written without changes
		while (iml_tail > 0) {        // search to the beginning
			int iml_dot = iml_tail;
			while (--iml_dot > 0) {   // search for dot
				if ( ach_object[iml_dot] == '.' ) {
					inl_word_key = m_is_word_in_list( &ach_object[iml_dot + 1], iml_tail - iml_dot - 1);
					if ( m_is_word_attribute( inl_word_key ) && inl_word_key != ds_attributes::ied_scr_attr_value ) {
						ds_hstring ds_temp;                     // output buffer for m_build_HOB_get_attr
						ds_temp.m_setup( ads_session->ads_wsp_helper );
						m_build_HOB_get_attr( &ds_temp, ach_object, iml_dot, &ach_object[iml_dot + 1], iml_tail - iml_dot -1, NULL, 0);
						ads_out->m_write( ds_temp.m_get_ptr(), ds_temp.m_get_len());
						bol_finished = TRUE;  // all done
						break;
					} 
					break;
				}
			};
			if (bol_finished) {    // all done?
				break;
			}
			iml_tail = iml_dot; // part to be appended later
		}
		if (iml_tail < in_len_object) {
	        ads_out->m_write( &ach_object[iml_tail], in_len_object - iml_tail);   
		}
#else
        if ( ach_object[in_len_object - 1] == '.' ) {
            in_len_object--;
		}
        ads_out->m_write( ach_object, in_len_object );   
#endif
    }
    else {
#if SM_USE_FUNCTION2
        ads_out->m_write( "this" );
#endif
    }

    // append word:
    // MJ 16.09.10, Ticket [20581]:
    switch( ienc_in_quotes ) {
        case ied_in_single_quotes:
            ads_out->m_write( ",\"" );
            ads_out->m_write( ach_word, in_len_word );
            ads_out->m_write( "\")" );
            break;
        default:
            ads_out->m_write( ",'" );
            ads_out->m_write( ach_word, in_len_word );
            ads_out->m_write( "')" );
            break;
    }
#if 0
    ads_out->m_write( ",'" );
    ads_out->m_write( ach_word, in_len_word );
    ads_out->m_write( "')" );
#endif
    if ( ach_sign != NULL && in_len_sign > 0 ) {
        ads_out->m_write( ach_sign, in_len_sign );
    }
    return;
} // end of ds_interpret_script::m_build_HOB_get_attr


/**
 *
 * function ds_interpret_script::m_build_HOB_function
 *
 * @param[out]  ds_hstring*  ads_out             pointer to output memory
 * @param[in]   char*       ach_data            pointer to data
 * @param[in]   char*       ach_object          pointer to object
 * @param[in]   int         in_len_object       length of ach_object
 * @param[in]   char*       ach_word            pointer to word
 * @param[in]   int         in_len_word         length of ach_word
 * @param[in]   int         in_word_key         word key (from list)
 * @param[in]   char*       ach_argument        pointer to argument
 * @param[in]   int         in_len_argument     length of argument
 *
*/
void ds_interpret_script::m_build_HOB_function( ds_hstring* ads_out,
                                                const char* ach_data,
                                                const char* ach_object,   int in_len_object,
                                                const char* ach_word,     int in_len_word,
                                                int in_word_key, 
                                                const char* ach_argument, int in_len_argument )
{
    // initialize some variables:
    int        in_arg_cut        = 0;
    int        in_old_obj        = in_len_object;   // old length of object (needed in case of change)
    bool       bo_insert_prop    = false;           // is HOB_CHECK_PROPERTY needed?
    ds_hstring ds_prop;                             // output buffer for m_build_HOB_check_property
    ds_prop.m_setup( ads_session->ads_wsp_helper );

    // check if we have an withobject set:
    bo_insert_prop = m_build_HOB_check_property( &ds_prop, 
                                                 ach_object, in_len_object,
                                                 ach_word,   in_len_word );
    if ( bo_insert_prop == true ) {
        ach_object    = ds_prop.m_get_ptr();
        in_len_object = ds_prop.m_get_len();
    }

    // intialize ads_out:
    ads_out->m_reset();

    switch ( in_word_key ) {
        case ds_attributes::ied_scr_attr_eval:
            if ( in_old_obj > 0 ) {
                ads_out->m_write( ach_object, in_len_object );
            }
            ads_out->m_write( "eval(" );
            break;

        case ds_attributes::ied_scr_attr_Function:
            if ( in_old_obj > 0 ) {
                ads_out->m_write( ach_object, in_len_object );
            }
            ads_out->m_write( "Function(" );
            in_arg_cut = m_get_last_argument( ach_argument, in_len_argument );
            if ( in_arg_cut > -1 ) {
                ads_out->m_write( ach_argument, in_arg_cut );
                ads_out->m_write( HOB_JS );
                ads_out->m_write( &ach_argument[in_arg_cut], in_len_argument - in_arg_cut );
            } else {
                ads_out->m_write( HOB_JS );
                ads_out->m_write( ach_argument, in_len_argument );
            }
            ads_out->m_write( "))" );
            return;

        case ds_attributes::ied_scr_attr_replace:
            if ( in_len_object == 0 ) {
                ads_out->m_write( ach_word, in_len_word );
                ads_out->m_write( "(" );
                if ( in_len_argument > 0 ) {
                    ads_out->m_write( ach_argument, in_len_argument );
                }
                ads_out->m_write( ")" ); 
                return;
            }
            break;

        default:
            break;
    }

    if ( in_len_object > 0 && m_append_space( ach_data, ach_object ) ) {
        ads_out->m_write( " " );
    }



    // append object:
    if ( in_len_object <= 0 ) {
#if SM_USE_FUNCTION2
        ads_out->m_write( HOB_FUNCTION2 );
        ads_out->m_write( ach_word, in_len_word );
#else
		  ads_out->m_write( HOB_FUNCTION );
		  // case of empty object (i.e. eval(...) )
        // MJ 16.09.10, Ticket [20581]:
        switch( ienc_in_quotes ) {
            case ied_in_single_quotes:
                ads_out->m_write( "\"\"" );
                break;
            default:
                ads_out->m_write( "\'\'" );
                break;
        }
#if 0
        ads_out->m_write( "\'\'" );
#endif
#endif
	 } else {
        ads_out->m_write( HOB_FUNCTION );
        if ( ach_object[in_len_object - 1] == '.' ) {
            in_len_object--;
        }
        ads_out->m_write( ach_object, in_len_object );
    }

    // append word:
    // MJ 16.09.10, Ticket [20581]:
    switch( ienc_in_quotes ) {
        case ied_in_single_quotes:
            ads_out->m_write( ",\"" );
            ads_out->m_write( ach_word, in_len_word );
            ads_out->m_write( "\"" );
            break;
        default:
            ads_out->m_write( ",'" );
            ads_out->m_write( ach_word, in_len_word );
            ads_out->m_write( "'" );
            break;
    }
#if 0
    ads_out->m_write( ",'" );
    ads_out->m_write( ach_word, in_len_word );
    ads_out->m_write( "'" );
#endif

    // append argument:
    if ( in_len_argument > 0 ) {
        ads_out->m_write( "," );
        ads_out->m_write( ach_argument, in_len_argument );
    }

    ads_out->m_write( ")" );    
    if ( in_word_key == ds_attributes::ied_scr_attr_eval ) {
        ads_out->m_write( ")" );
    }

    return;
} // end of ds_interpret_script::m_build_HOB_function


/**
 *
 * function ds_interpret_script::m_build_HOB_object
 *
 * @param[out]  ds_hstring*  ads_out             pointer to output memory
 * @param[in]   char*       ach_object          pointer to object
 * @param[in]   int         in_len_object       length of ach_object
 * @param[in]   char*       ach_word            pointer to word
 * @param[in]   int         in_len_word         length of ach_word
 * @param[in]   char*       ach_sign            pointer to signs after ach_word
 * @param[in]   int         in_len_sign         length of ach_sign
 *
*/
void ds_interpret_script::m_build_HOB_object( ds_hstring* ads_out, 
                                              const char* ach_object, int in_len_object,
                                              const char* ach_word,   int in_len_word,
                                              const char* ach_sign,   int in_len_sign )
{
    // initialize some variables:
    bool       bo_insert_prop    = false;   // is HOB_CHECK_PROPERTY needed?
    ds_hstring ds_prop;                     // output buffer for m_build_HOB_check_property
    ds_prop.m_setup( ads_session->ads_wsp_helper );

    // check if we have an withobject set:
    bo_insert_prop = m_build_HOB_check_property( &ds_prop, 
                                                 ach_object, in_len_object,
                                                 ach_word,   in_len_word );
    if ( bo_insert_prop == true ) {
        ach_object    = ds_prop.m_get_ptr();
        in_len_object = ds_prop.m_get_len();
    }


    // no object and/or with object exists -> return orginal data:
    if ( in_len_object == 0 ) {
        ads_out->m_write( ach_word, in_len_word );    // false for overwrite existing data
        if ( ach_sign != NULL && in_len_sign > 0 ) {
            ads_out->m_write( ach_sign, in_len_sign );
        }
        return;
    }

    // intialize ads_out (false for overwrite existing data):
    ads_out->m_set( HOB_OBJECT );

    // append object:
    if ( in_len_object > 0 ) {
        if ( ach_object[in_len_object - 1] == '.' ) {
            in_len_object--;
        }
        ads_out->m_write( ach_object, in_len_object );   
    }

    // append word:
    // MJ 16.09.10, Ticket [20581]:
    switch( ienc_in_quotes ) {
        case ied_in_single_quotes:
            ads_out->m_write( ",\"" );
            ads_out->m_write( ach_word, in_len_word );
            ads_out->m_write( "\")" );
            break;
        default:
            ads_out->m_write( ",'" );
            ads_out->m_write( ach_word, in_len_word );
            ads_out->m_write( "')" );
            break;
    }
#if 0
    ads_out->m_write( ",'" );
    ads_out->m_write( ach_word, in_len_word );
    ads_out->m_write( "')" );
#endif

    // append sign:
    if ( ach_sign != NULL && in_len_sign > 0 ) {
        ads_out->m_write( ach_sign, in_len_sign );
    }
    return;
} // end of ds_interpret_script::m_build_HOB_object


/**
 *
 * function ds_interpret_script::m_build_HOB_style
 *
 * @param[out]  ds_hstring*  ads_out             pointer to output memory
 * @param[in]   char*       ach_object          pointer to object
 * @param[in]   int         in_len_object       length of ach_object
 * @param[in]   char*       ach_word            pointer to word
 * @param[in]   int         in_len_word         length of ach_word
 * @param[in]   char*       ach_argument        pointer to argument
 * @param[in]   int         in_len_argument     length of argument
 *
*/
void ds_interpret_script::m_build_HOB_style( ds_hstring* ads_out,
                                             const char* ach_object,   int in_len_object,
                                             const char* ach_word,     int in_len_word,
                                             const char* ach_argument, int in_len_argument )
{
    // initialize some variables:
    bool       bo_insert_prop    = false;   // is HOB_CHECK_PROPERTY needed?
    ds_hstring ds_prop;                     // output buffer for m_build_HOB_check_property
    ds_prop.m_setup( ads_session->ads_wsp_helper );

    // check if we have an withobject set:
    bo_insert_prop = m_build_HOB_check_property( &ds_prop, 
                                                 ach_object, in_len_object,
                                                 ach_word,   in_len_word );
    if ( bo_insert_prop == true ) {
        ach_object    = ds_prop.m_get_ptr();
        in_len_object = ds_prop.m_get_len();
    }


    // intialize ads_out (false for overwrite existing data):
    ads_out->m_set( HOB_STYLE );

    // append object:
    if ( in_len_object > 0 ) {     
        if ( ach_object[in_len_object - 1] == '.' ) {
            in_len_object--;
        }
        ads_out->m_write( ach_object, in_len_object );
    }

    // append word:
    ads_out->m_write( "," );
    ads_out->m_write( ach_word, in_len_word );

    // append argument:
    if ( in_len_argument > 0 ) {
        ads_out->m_write( "," );
        // append argument:
        ads_out->m_write( ach_argument, in_len_argument );
    }
    ads_out->m_write( ")" );

    return;
} // end of ds_interpret_script::m_build_HOB_style


/**
 *
 * function ds_interpret_script::m_build_string
 *
 * @param[out]  ds_hstring*  ads_out          pointer to output memory
 * @param[in]   char*       ach_input1       pointer to input1
 * @param[in]   int         in_len_input1    length of ach_input1
 * @param[in]   char*       ach_input2       pointer to input2
 * @param[in]   int         in_len_input2    length of ach_input2
 * @param[in]   char*       ach_input3       pointer to input3,    default value = NULL
 * @param[in]   int         in_len_input3    length of ach_input3, default value = 0
 * @param[in]   char*       ach_input4       pointer to input4,    default value = NULL
 * @param[in]   int         in_len_input4    length of ach_input4, default value = 0
 * @param[in]   char*       ach_input5       pointer to input5,    default value = NULL
 * @param[in]   int         in_len_input5    length of ach_input5, default value = 0
 *
*/
void ds_interpret_script::m_build_string( ds_hstring* ads_out,
                                          const char* ach_input1, int in_len_input1, 
                                          const char* ach_input2, int in_len_input2,
                                          const char* ach_input3, int in_len_input3, 
                                          const char* ach_input4, int in_len_input4,
                                          const char* ach_input5, int in_len_input5 )
{
    // initialize output memory:
    ads_out->m_reset();

    // append data:
    ads_out->m_write( ach_input1, in_len_input1 );
    ads_out->m_write( ach_input2, in_len_input2 );
    ads_out->m_write( ach_input3, in_len_input3 );
    ads_out->m_write( ach_input4, in_len_input4 );
    ads_out->m_write( ach_input5, in_len_input5 );
    return;
} // end of ds_interpret_script::m_build_string


/**
 * function ds_interpret_script::m_build_HOB_check_property
 *
 * Ticket[17965]: for javscript with. we must check if property exists for the object chain
 *                this check will be done on client (javascript)
 *                this function will create the javascript function call
 *
 * @param[in]   ds_hstring*     ads_out         output data
 * @param[in]   char*           ach_object      pointer to current object
 * @param[in]   int             in_len_object   length of current object
 * @param[in]   char*           ach_property    pointer to property
 * @param[in]   int             in_len_property length of property
 *
 * @return      bool                            true  = insert required
 *                                              false = nothing to insert
*/
bool ds_interpret_script::m_build_HOB_check_property( ds_hstring* ads_out,
                                                      const char* ach_object,   int in_len_object,
                                                      const char* ach_property, int in_len_property )
{
    //-------------------------------------------
    // check if there are existing with objects:
    //-------------------------------------------
    if ( adsc_var_cur->dsc_vwith.m_empty() ) {
        return false;
    }

    //-------------------------------------------
    // write function start:
    //-------------------------------------------
    ads_out->m_write( HOB_CHECK_PROPERTY );

    //-------------------------------------------
    // start object array:
    //-------------------------------------------
    ads_out->m_write( "new Array(" );

    //-------------------------------------------
    // insert object itself:
    //-------------------------------------------
    if ( ach_object != NULL && in_len_object > 0 ) {
        if (    in_len_object > 1 
             && ach_object[in_len_object - 1] == '.' ) {
            in_len_object--;
        }
        ads_out->m_write( ach_object, in_len_object );
        ads_out->m_write( "," );
    }

    //-------------------------------------------
    // loop through the stack elements: STACK works backwards
    //-------------------------------------------
    int uinl_pos = 0;
    for ( HVECTOR_FOREACH(ds_with_variables*, adsl_cur, adsc_var_cur->dsc_vwith) ) {
        const ds_with_variables* ads_with = HVECTOR_GET(adsl_cur);
        if ( uinl_pos > 0 ) {
            ads_out->m_write( "," );
        }
        // insert element:
        ads_out->m_write( ads_with->ds_object.m_get_ptr(),
                          ads_with->ds_object.m_get_len() );
        uinl_pos++;
    } // end of for

    //-------------------------------------------
    // end object array:
    //-------------------------------------------
    ads_out->m_write( ")" );

    //-------------------------------------------
    // insert property:
    //-------------------------------------------
    // MJ 16.09.10, Ticket [20581]:
    switch( ienc_in_quotes ) {
        case ied_in_single_quotes:
            ads_out->m_write( ",\"" );
            ads_out->m_write( ach_property, in_len_property );
            ads_out->m_write( "\"" );
            break;
        default:
            ads_out->m_write( ",'" );
            ads_out->m_write( ach_property, in_len_property );
            ads_out->m_write( "'" );
            break;
    }
#if 0
    ads_out->m_write( ",'" );
    ads_out->m_write( ach_property, in_len_property );
    ads_out->m_write( "'" );
#endif

    //-------------------------------------------
    // write function end:
    //-------------------------------------------
    ads_out->m_write(")");
    return true;
} // end of ds_interpret_script::m_build_HOB_check_property



bool ds_interpret_script::m_handle_funny_cases( const char* achp_data, int inp_len, int* ainp_pos )
{
	bool bol_ret;
	char chl_cur;
	bool bol_dont_use_data = false; // dont use data from ach_data, because we still have a character from the last datablock

	if( adsc_var_cur->boc_funny_resume ) // we resume parsing from previous datablock
	{
		adsc_var_cur->boc_funny_resume	= false;

		switch( adsc_var_cur->iec_funny_states )
		{
			case iec_comment_slash:
			case iec_comment_asterisk:			
				// we stopped parsing in the middle of a comment like: // bla bla
				bol_ret = m_skip_comments( achp_data, inp_len, ainp_pos );
				if( !bol_ret ){ goto save_status; } // no end of data found -> look in next chunk
				chl_cur = achp_data[ *ainp_pos ];
				break;
			case iec_string_single:
			case iec_string_double:
				bol_ret = m_skip_strings( achp_data, inp_len, ainp_pos );
				if( !bol_ret ){ goto save_status; } // no end of data found -> look in next chunk
				(*ainp_pos)++;
				break;
			default:
				bol_dont_use_data = true;
				break;			
		}
	}

	while( *ainp_pos < inp_len )
	{
		if( bol_dont_use_data )
		{
			bol_dont_use_data = false;
			chl_cur = adsc_var_cur->ch_last_sign;
			(*ainp_pos)--;
		}
		else
		{
			chl_cur = achp_data[ *ainp_pos ];
		}

		switch ( chl_cur )
		{
			case '/':
				// check for comments
				if( (*ainp_pos) + 1 == inp_len ){ goto save_status; } // end of data reached
				(*ainp_pos)++;
				bol_ret = m_skip_comments( achp_data, inp_len, ainp_pos );
				if( !bol_ret ){ goto save_status; } // no end of data found -> look in next chunk
				break;
			case '"':
			case '\'':			
				// check for strings
				bol_ret = m_skip_strings( achp_data, inp_len, ainp_pos );
				if( !bol_ret ){ goto save_status; } // no end of data found -> look in next chunk
				break;
			case ':':
				return true;
			default:                        
				break;
		}
		(*ainp_pos)++;
	}

	save_status:
	adsc_var_cur->boc_funny_resume	= true;
	adsc_var_cur->ch_last_sign		= achp_data[ *ainp_pos ];

	return false;
}


/*!
 *
 *	returns true if end found, otherwise false
*/

bool ds_interpret_script::m_skip_comments( const char* achp_data, int inp_len, int* ainp_pos )
{
	bool bol_asterisk = false;

	// if we ARE NOT resuming parsing from a previous block, check if we have a comment
	if( adsc_var_cur->iec_funny_states != iec_comment_asterisk && adsc_var_cur->iec_funny_states != iec_comment_slash )
	{
		switch ( achp_data[ *ainp_pos ] )
		{
			case '*':
				adsc_var_cur->iec_funny_states = iec_comment_asterisk; // comment like /* blabla */
				break;
			case '/':
				adsc_var_cur->iec_funny_states = iec_comment_slash; // comment like // blabla
				break;
			default:
				return true; // no comment
		}
	}

	while( *ainp_pos < inp_len )
	{		
		switch ( achp_data[ *ainp_pos ] )
		{
			case '*':
				bol_asterisk = true;
				break;
			case '/':
				if( bol_asterisk ) // we are already in a comment
				{
					adsc_var_cur->iec_funny_states = iec_normal;
					return true;
				}
				break;
			case '\n':
			case '\r':
				if( adsc_var_cur->iec_funny_states == iec_comment_slash )
				{
					adsc_var_cur->iec_funny_states = iec_normal;
					return true;
				}
				bol_asterisk = false;
				break;
			default:
				bol_asterisk = false;
				break;
		}

		(*ainp_pos)++;
	}

	return false;
}

/*!
 *
 *	returns true if end found, otherwise false
*/
bool ds_interpret_script::m_skip_strings( const char* achp_data, int inp_len, int* ainp_pos )
{
	bool bol_escape	= false;
	char chl_end;
	char chl_cur;

	// resume from previous block
	if( adsc_var_cur->iec_funny_states == iec_string_single )
	{
		chl_end = '\'';
	}
	else if( adsc_var_cur->iec_funny_states == iec_string_double  )
	{
		chl_end = '"';
	}
	else // start parsing a new string
	{
		chl_end = achp_data[ *ainp_pos ];
		if( chl_end == '\'' )
		{
			adsc_var_cur->iec_funny_states = iec_string_single;
		}
		else if( chl_end == '"' )
		{
			adsc_var_cur->iec_funny_states = iec_string_double;
		}
		(*ainp_pos)++;
	}

	while( *ainp_pos < inp_len )
	{		
		chl_cur = achp_data[ *ainp_pos ];

		if( chl_cur == '\\' )
		{
			bol_escape = !bol_escape;
		}
		else if( chl_cur == chl_end )
		{
			if( !bol_escape )
			{
				adsc_var_cur->iec_funny_states = iec_normal;
				return true;
			}
			bol_escape = false;
		}
		else{ bol_escape = false; }

		(*ainp_pos)++;
	}
	return false;
}
#endif /*!SM_USE_WSG_V2*/
