#ifndef HL_UNIX
    #include <windows.h>
#else
    #include <sys/types.h>
    #include <errno.h>
    #include <hob-unix01.h>
#endif
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <hob-avl03.h>
#include <hob-xsclib01.h>
#include <hob-webterm-rdp-svc-rail.h>

#include <hob-encry-1.h>
#include <hob-cd-record-1.h>
#include <hob-webterm-rdp-01.h>

#include <xs-tk-gather-tools-01.cpp>
#include <xs-tk-aux-tools-01.cpp>

#define HL_GR_RET_GOTO(call, lbl) if(!(call)) goto lbl

static BOOL m_gr_read_utf16le_string(struct dsd_gather_reader* adsp_gr, uint16_t ump_len_bytes, struct dsd_unicode_string_gather_pos* adsp_out) {
	adsp_out->iec_chs_str = ied_chs_le_utf_16;
	adsp_out->imc_len_str = ump_len_bytes >> 1;
	m_gr_get_position(adsp_gr, &adsp_out->dsc_data);
	if(!m_gr_skip(adsp_gr, ump_len_bytes))
		return FALSE;
	return TRUE;
}

struct dsd_data {
	char* achc_start;
	char* achc_end;
};

struct dsd_convert_context {
	char chrc_input[5];
	int inc_input_rest;
};

template<typename DSD_RECEIVER> static BOOL m_scan_vx_universal(
	enum ied_charset iep_chs, const char* achp_in_start, const char* achp_in_end, struct dsd_convert_context* adsp_context,
	DSD_RECEIVER& rdsp_receiver)
{
	const char* achl_in_cur = achp_in_start;
	do {
        if(achl_in_cur >= achp_in_end)
            break;
#if 0
		  if(achl_out_cur >= achl_out_limit)
            break;
#endif
        if(adsp_context->inc_input_rest >= sizeof(adsp_context->chrc_input))
            return FALSE;
        adsp_context->chrc_input[adsp_context->inc_input_rest++] = *achl_in_cur++;
        unsigned int uml_ucs_char = 0;
        int iml_res = m_get_vc_ch_ex(&uml_ucs_char, adsp_context->chrc_input, adsp_context->chrc_input+adsp_context->inc_input_rest,
			  iep_chs);
        // Not enough input?
        if(iml_res > adsp_context->inc_input_rest)
            continue;
        if(iml_res < 0) {
            // Not enough input?
            if(iml_res == -1)
                continue;
            //this->inc_input_rest = 0;
            uml_ucs_char = 0xFFFD;
        }
        adsp_context->inc_input_rest = 0;
		  if(!rdsp_receiver.m_next_ucs_char(uml_ucs_char))
			  return FALSE;
    } while(true);

	 return TRUE;
}

template<size_t MAX_BUFFER> struct dsd_ucs_count_receiver {
private:
	unsigned int umcr_buffer[MAX_BUFFER];
	int inc_num_buffer;
	ied_charset iec_cs_target;
public:
	int inc_len_elements;

	dsd_ucs_count_receiver(ied_charset iep_cs_target) {
		inc_num_buffer = 0;
		inc_len_elements = 0;
		iec_cs_target = iep_cs_target;
	}

	BOOL m_flush() {
		int inl_ret = m_len_vx_vx(this->iec_cs_target, &this->umcr_buffer, this->inc_num_buffer, ied_chs_utf_32);
		if(inl_ret < 0)
			return FALSE;
		this->inc_num_buffer = 0;
		this->inc_len_elements += inl_ret;
		return TRUE;
	}

	BOOL m_next_ucs_char(unsigned int ump_ucs_char) {
		this->umcr_buffer[this->inc_num_buffer++] = ump_ucs_char;
		if(this->inc_num_buffer < MAX_BUFFER)
			return TRUE;
		return m_flush();
	}
};

template<typename DSD_RECEIVER, size_t MAX_BUFFER> struct dsd_ucs_write_receiver {
private:
	DSD_RECEIVER& rdsc_receiver;
	unsigned int umcr_buffer[MAX_BUFFER];
	int inc_num_buffer;
	ied_charset iec_cs_target;
	int inc_element_size;

public:
	dsd_ucs_write_receiver(DSD_RECEIVER& rdsp_receiver, ied_charset iep_cs_target)
		: rdsc_receiver(rdsp_receiver)
	{
		inc_num_buffer = 0;
		iec_cs_target = iep_cs_target;
		inc_element_size = m_cs_elem_size(iep_cs_target);
	}

	BOOL m_flush() {
		unsigned char chrl_buffer2[MAX_BUFFER*5];
		int inl_ret = m_cpy_vx_vx(chrl_buffer2, sizeof(chrl_buffer2)/this->inc_element_size,
			this->iec_cs_target, &this->umcr_buffer, this->inc_num_buffer, ied_chs_utf_32);
		if(inl_ret < 0)
			return FALSE;
		this->inc_num_buffer = 0;
		if(!this->rdsc_receiver.m_write(chrl_buffer2, inl_ret*this->inc_element_size))
			return FALSE;
		return TRUE;
	}

	BOOL m_next_ucs_char(unsigned int ump_ucs_char) {
		this->umcr_buffer[this->inc_num_buffer++] = ump_ucs_char;
		if(this->inc_num_buffer < MAX_BUFFER)
			return TRUE;
		return m_flush();
	}
};

struct dsd_gather_writer_receiver {
	struct dsd_gather_writer* adsc_gw;

	dsd_gather_writer_receiver(struct dsd_gather_writer* adsp_gw) : adsc_gw(adsp_gw) {
	}

	BOOL m_write(void* avop_data, int inp_len_bytes) {
		if(!m_gw_write_bytes(this->adsc_gw, avop_data, inp_len_bytes))
			return FALSE;
		return TRUE;
	}
};

static BOOL m_gw_write_utf16le_string(struct dsd_gather_writer* adsp_gw, const struct dsd_unicode_string_gather_pos* adsp_value) {
	struct dsd_gather_i_1 dsl_gather;
	m_gather_i_1_pos_to_gather(&adsp_value->dsc_data, &dsl_gather);

	dsd_gather_writer_receiver dsl_gwr(adsp_gw);
	dsd_ucs_write_receiver<dsd_gather_writer_receiver, 128> dsl_write_receiver(dsl_gwr, ied_chs_le_utf_16);
	struct dsd_convert_context dsl_convert_context;
	memset(&dsl_convert_context, 0, sizeof(dsl_convert_context));
	int inl_length = adsp_value->imc_len_str * m_cs_elem_size(adsp_value->iec_chs_str);
	struct dsd_gather_i_1* adsl_gather = &dsl_gather;
	while(inl_length > 0) {
		char* achl_cur = adsl_gather->achc_ginp_cur;
		char* achl_end = adsl_gather->achc_ginp_end;
		if(achl_cur + inl_length < achl_end)
			achl_end = achl_cur + inl_length;
		if(!m_scan_vx_universal(adsp_value->iec_chs_str, achl_cur, achl_end, &dsl_convert_context, dsl_write_receiver))
			return FALSE;
		inl_length -= achl_end - achl_cur;
		if(inl_length <= 0)
			break;
		adsl_gather = adsl_gather->adsc_next;
		if(adsl_gather == NULL)
			return FALSE;
	}
	return dsl_write_receiver.m_flush();
}

void m_svc_rail_init(
	struct dsd_svc_rail *adsp_rail,
	struct dsd_aux_helper *adsp_aux,
	struct dsd_rdp_vc_1 *adsp_rdp_vc_1)
{
	//adsp_rdpdr->inc_state = ied_rdpdr_state_start;
	adsp_rail->adsc_rdp_vc_1 = adsp_rdp_vc_1;
	m_gather_fifo_init(&adsp_rail->dsc_fifo);
}

int m_svc_rail_receive_message(
	struct dsd_svc_rail *adsp_rail, 
	struct dsd_aux_helper *adsp_aux,
   struct dsd_rdp_vch_io* adsp_message,
	struct dsd_svc_rail_message* adsp_result)
{
	struct dsd_gather_i_1_fifo dsl_fifo;
	m_gather_fifo_init(&dsl_fifo);
	if(adsp_rail->dsc_fifo.adsc_first != NULL) {
		m_gather_fifo_foreach(&adsp_rail->dsc_fifo, &m_gather_i_1_ref_dec, adsp_aux);
		m_gather_fifo_append_fifo(&dsl_fifo, &adsp_rail->dsc_fifo);
	}
	m_gather_fifo_append_list2(&dsl_fifo, adsp_message->adsc_gai1_data);
	
	struct dsd_gather_reader dsl_gather_reader;
	m_gr_init(&dsl_gather_reader, &dsl_fifo);
	struct dsd_gather_i_1_pos dsl_lookahead_pos;
	uint16_t usl_order_type;
	uint16_t usl_order_length;
	
	// Start lookahead mode
	HL_GR_RET_GOTO(m_gr_begin_lookahead(&dsl_gather_reader, &dsl_lookahead_pos), LBL_FAILED);
	HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &usl_order_type), LBL_READ_INCOMPLETE);
	HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &usl_order_length), LBL_READ_INCOMPLETE);
	
	adsp_result->usc_order_type = usl_order_type;
	switch(usl_order_type) {
	case TS_RAIL_ORDER_SYSPARAM: {
		dsd_svc_rail_order_sysparam* adsl_order = &adsp_result->dsc_order.dsc_sysparam;
		HL_GR_RET_GOTO(m_gr_read_uint32_le(&dsl_gather_reader, &adsl_order->umc_system_parameter), LBL_READ_INCOMPLETE);
		switch(adsl_order->umc_system_parameter) {
		case UM_SPI_SETSCREENSAVEACTIVE:
			HL_GR_RET_GOTO(m_gr_read_uint8(&dsl_gather_reader, &adsl_order->dsc_body.dsc_setscreensaveactive.boc_enabled), LBL_READ_INCOMPLETE);
			break;
		case UM_SPI_SETSCREENSAVESECURE:
			HL_GR_RET_GOTO(m_gr_read_uint8(&dsl_gather_reader, &adsl_order->dsc_body.dsc_setscreensavesecure.boc_enabled), LBL_READ_INCOMPLETE);
			break;
		default:
			m_aux_printf(adsp_aux, "xl-rdp-svc-rail-l%05d-E - TS_RAIL_ORDER_SYSPARAM unknown system parameter %d\n",
				__LINE__, adsl_order->umc_system_parameter);
			goto LBL_FAILED;
		}
		break;
	}
	case TS_RAIL_ORDER_HANDSHAKE: {
		dsd_svc_rail_order_handshake* adsl_order = &adsp_result->dsc_order.dsc_handshake;
		HL_GR_RET_GOTO(m_gr_read_uint32_le(&dsl_gather_reader, &adsl_order->umc_build_number), LBL_READ_INCOMPLETE);
#if 0
		// 2.2.2.2 Initialization Messages
		// 2.2.2.2.1 Handshake PDU (TS_RAIL_ORDER_HANDSHAKE)
		this.send_handshake_pdu(this.dsc_rdpoptions.get_build_number());
		// 2.2.2.2.2 Client Information PDU (TS_RAIL_ORDER_CLIENTSTATUS)
		this.send_client_information_pdu(en_ts_rail_clientstatus.UM_TS_RAIL_CLIENTSTATUS_ALLOWLOCALMOVESIZE);
#endif
		break;
	}
	case TS_RAIL_ORDER_EXEC_RESULT: {
		dsd_svc_rail_order_exec_result* adsl_order = &adsp_result->dsc_order.dsc_exec_result;
		HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &adsl_order->usc_flags), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &adsl_order->usc_exec_result), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint32_le(&dsl_gather_reader, &adsl_order->umc_raw_result), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &adsl_order->usc_padding), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &adsl_order->usc_exe_or_file_length), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_utf16le_string(&dsl_gather_reader, adsl_order->usc_exe_or_file_length, &adsl_order->dsc_exe_or_file), LBL_READ_INCOMPLETE);
		break;
	}
	case TS_RAIL_ORDER_LOCALMOVESIZE: {
		dsd_svc_rail_order_localmovesize* adsl_order = &adsp_result->dsc_order.dsc_localmovesize;
		HL_GR_RET_GOTO(m_gr_read_uint32_le(&dsl_gather_reader, &adsl_order->umc_window_id), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &adsl_order->usc_is_move_size_start), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &adsl_order->usc_move_size_type), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &adsl_order->usc_pos_x), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &adsl_order->usc_pos_y), LBL_READ_INCOMPLETE);
		break;
	}
	case TS_RAIL_ORDER_MINMAXINFO: {
		dsd_svc_rail_order_minmaxinfo* adsl_order = &adsp_result->dsc_order.dsc_minmaxinfo;
		HL_GR_RET_GOTO(m_gr_read_uint32_le(&dsl_gather_reader, &adsl_order->umc_window_id), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &adsl_order->usc_max_width), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &adsl_order->usc_max_height), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &adsl_order->usc_max_pos_x), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &adsl_order->usc_max_pos_y), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &adsl_order->usc_min_track_width), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &adsl_order->usc_min_track_height), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &adsl_order->usc_max_track_width), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &adsl_order->usc_max_track_height), LBL_READ_INCOMPLETE);
		break;
	}
	case TS_RAIL_ORDER_UNKNOWN1: {
		break;
	}
	default:
		m_aux_printf(adsp_aux, "xl-rdp-svc-rail-l%05d-E - unknown order type %d\n",
			__LINE__, usl_order_type);
		goto LBL_FAILED;
	}
	
	// End lookahead mode
	//HL_GR_RET_GOTO(m_gr_end_lookahead(&dsl_gather_reader, &dsl_lookahead_pos), LBL_FAILED);
	dsd_gather_i_1_pos dsl_pos;
	m_gr_commit(&dsl_gather_reader, &dsl_pos);
#if 0
	adsp_rdpdr->inc_state = ied_rdpdr_state_head;
#endif
	return 1;
LBL_READ_INCOMPLETE:
	if((adsp_message->chrc_vch_flags[0] & CHANNEL_FLAG_LAST) != 0)
		goto LBL_FAILED;
	m_gather_fifo_init(&adsp_rail->dsc_fifo);
	m_gather_fifo_append_fifo(&adsp_rail->dsc_fifo, &dsl_fifo);
	m_gather_fifo_foreach(&adsp_rail->dsc_fifo, &m_gather_i_1_ref_inc, adsp_aux);
#if 0
	adsp_rdpdr->inc_state = ied_rdpdr_state_start;
#endif
	return 0;
LBL_FAILED:
	return -1;
}

int m_svc_rail_process_commands(
	struct dsd_svc_rail *adsp_rail, 
	struct dsd_workarea_allocator *adsp_wa_alloc,
	const struct dsd_svc_rail_command* adsrp_commands,
	int inp_num_commands,
	struct dsd_svc_command_result* adsp_result)
{
	struct dsd_gather_i_1_fifo dsl_fifo_out;

	struct dsd_cc_co1** aadsl_vc_out = &adsp_result->adsc_vc_out_first;
	adsp_result->adsc_vc_out_first = NULL;
	adsp_result->adsc_vc_out_last = NULL;
	for(int inl_c=0; inl_c<inp_num_commands; inl_c++) {
		const struct dsd_svc_rail_command* adsl_cmd = &adsrp_commands[inl_c];

		struct dsd_gather_writer dsl_gw;
		m_gw_init(&dsl_gw, adsp_wa_alloc);
		HL_GR_RET_GOTO(m_gw_mark_start(&dsl_gw), LBL_FAILED);
		switch(adsl_cmd->usc_order_type) {
		case TS_RAIL_ORDER_EXEC: {
			const struct dsd_svc_rail_order_exec* adsl_order = &adsl_cmd->dsc_order.dsc_exec;
			uint32_t uml_order_length = 12 + adsl_order->usc_exe_or_file_length + adsl_order->usc_working_dir_length + adsl_order->usc_arguments_length;
			if(uml_order_length > 0xffff) {
				m_aux_printf(adsp_wa_alloc->adsc_aux, "m_svc_rail_process_commands: TS_RAIL_ORDER_EXEC length exceeded %d\n",
					uml_order_length);
				goto LBL_FAILED;
			}
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, TS_RAIL_ORDER_EXEC), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, uml_order_length), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, adsl_order->usc_flags), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, adsl_order->usc_exe_or_file_length), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, adsl_order->usc_working_dir_length), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, adsl_order->usc_arguments_length), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_utf16le_string(&dsl_gw, &adsl_order->dsc_exe_or_file), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_utf16le_string(&dsl_gw, &adsl_order->dsc_working_dir), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_utf16le_string(&dsl_gw, &adsl_order->dsc_arguments), LBL_FAILED);
			break;
		}
		case TS_RAIL_ORDER_SYSPARAM: {
			const struct dsd_svc_rail_order_sysparam* adsl_order = &adsl_cmd->dsc_order.dsc_sysparam;
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, TS_RAIL_ORDER_SYSPARAM), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, 8 + 1), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_order->umc_system_parameter), LBL_FAILED);
			switch(adsl_order->umc_system_parameter) {
			case UM_SPI_SETSCREENSAVEACTIVE:
				HL_GR_RET_GOTO(m_gw_write_uint8(&dsl_gw, adsl_order->dsc_body.dsc_setscreensaveactive.boc_enabled), LBL_FAILED);
				break;
			case UM_SPI_SETSCREENSAVESECURE:
				HL_GR_RET_GOTO(m_gw_write_uint8(&dsl_gw, adsl_order->dsc_body.dsc_setscreensavesecure.boc_enabled), LBL_FAILED);
				break;
			default:
				m_aux_printf(adsp_wa_alloc->adsc_aux, "xl-rdp-svc-rail-l%05d-E - TS_RAIL_ORDER_SYSPARAM unknown system parameter %d\n",
					__LINE__, adsl_order->umc_system_parameter);
				goto LBL_FAILED;
			}
			break;
		}
		case TS_RAIL_ORDER_HANDSHAKE: {
			const struct dsd_svc_rail_order_handshake* adsl_order = &adsl_cmd->dsc_order.dsc_handshake;
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, TS_RAIL_ORDER_HANDSHAKE), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, 8), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_order->umc_build_number), LBL_FAILED);
			break;
		}
		case TS_RAIL_ORDER_CLIENTSTATUS: {
			const struct dsd_svc_rail_order_clientstatus* adsl_order = &adsl_cmd->dsc_order.dsc_clientstatus;
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, TS_RAIL_ORDER_CLIENTSTATUS), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, 8), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_order->umc_flags), LBL_FAILED);
			break;
		}
		default:
			m_aux_printf(adsp_wa_alloc->adsc_aux, "m_svc_rail_process_commands: unknown order type %d\n",
				adsl_cmd->usc_order_type);
			goto LBL_FAILED;
		}
		HL_GR_RET_GOTO(m_gw_mark_end(&dsl_gw), LBL_FAILED);
		int inl_num_bytes = m_gw_get_abs_pos(&dsl_gw);
		m_gather_fifo_init(&dsl_fifo_out);
		m_gather3_list_release(&dsl_gw.dsc_fifo, &dsl_fifo_out);

		m_gw_destroy(&dsl_gw);
#if 0
		m_aux_printf(adsp_aux, "m_svc_rail_process_commands: adsl_cmd->iec_command=%d inl_num_bytes=%d\n",
			adsl_cmd->iec_command, inl_num_bytes);
		m_aux_dump_gather(adsp_aux, dsl_fifo_out.adsc_first, -1);
#endif
		struct dsd_cc_co1* adsl_cc_co1 = (struct dsd_cc_co1*)m_wa_allocator_alloc_lower(adsp_wa_alloc,
			sizeof(struct dsd_cc_co1) + sizeof(struct dsd_rdp_vch_io),
			HL_ALIGNOF(struct dsd_rdp_vch_io));
		adsl_cc_co1->iec_cc_command = ied_ccc_vch_out;
		adsl_cc_co1->adsc_next = NULL;
		struct dsd_rdp_vch_io* adsl_cc_vch_io = (struct dsd_rdp_vch_io*)(adsl_cc_co1+1);
		adsl_cc_vch_io->adsc_gai1_data = dsl_fifo_out.adsc_first;
		adsl_cc_vch_io->umc_vch_ulen = inl_num_bytes;
		memset(adsl_cc_vch_io->chrc_vch_flags, 0, sizeof(adsl_cc_vch_io->chrc_vch_flags));
		adsl_cc_vch_io->chrc_vch_flags[0] = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST | CHANNEL_FLAG_SHOW_PROTOCOL;
		adsl_cc_vch_io->adsc_rdp_vc_1 = adsp_rail->adsc_rdp_vc_1;

		*aadsl_vc_out = adsl_cc_co1;
		aadsl_vc_out = &adsl_cc_co1->adsc_next;
		adsp_result->adsc_vc_out_last = adsl_cc_co1;
	}
	return 0;
LBL_FAILED:
	return -1;
}

void m_svc_rail_destroy(
	struct dsd_svc_rail *adsp_rail,
	struct dsd_aux_helper *adsp_aux)
{
}
