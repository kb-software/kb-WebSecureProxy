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
#include <hob-tk-gather-tools-01.h>
#include <hob-webterm-rdp-svc-rdpdr.h>

#include <hob-encry-1.h>
#include <hob-cd-record-1.h>
#include <hob-webterm-rdp-01.h>

#include <xs-tk-gather-tools-01.cpp>

#define HL_GR_RET_GOTO(call, lbl) if(!(call)) goto lbl

/** Device redirector core component */
static const uint16_t IM_RDPDR_CTYP_CORE = 0x4472;
static const uint16_t IM_RDPDR_CTYP_PRN = 0x5052;

static const uint16_t IM_PAKID_CORE_SERVER_ANNOUNCE = 0x496E;
static const uint16_t IM_PAKID_CORE_CLIENTID_CONFIRM = 0x4343;
static const uint16_t IM_PAKID_CORE_CLIENT_NAME = 0x434E;
static const uint16_t IM_PAKID_CORE_DEVICELIST_ANNOUNCE = 0x4441;
static const uint16_t IM_PAKID_CORE_DEVICE_REPLY = 0x6472;
static const uint16_t IM_PAKID_CORE_DEVICE_IOREQUEST = 0x4952;
static const uint16_t IM_PAKID_CORE_DEVICE_IOCOMPLETION = 0x4943;
static const uint16_t IM_PAKID_CORE_SERVER_CAPABILITY = 0x5350;
static const uint16_t IM_PAKID_CORE_CLIENT_CAPABILITY = 0x4350;
static const uint16_t IM_PAKID_CORE_DEVICELIST_REMOVE = 0x444D;
static const uint16_t IM_PAKID_PRN_CACHE_DATA = 0x5043;
static const uint16_t IM_PAKID_CORE_USER_LOGGEDON = 0x554C;
static const uint16_t IM_PAKID_PRN_USING_XPS = 0x5543;

// Capability Type
static const uint16_t IM_CAP_GENERAL_TYPE = 0x0001;
static const uint16_t IM_CAP_PRINTER_TYPE = 0x0002;
static const uint16_t IM_CAP_PORT_TYPE = 0x0003;
static const uint16_t IM_CAP_DRIVE_TYPE = 0x0004;
static const uint16_t IM_CAP_SMARTCARD_TYPE = 0x0005;

enum ied_rdpdr_state {
	ied_rdpdr_state_start,
	ied_rdpdr_state_head,
	ied_rdpdr_state_skip,
	ied_rdpdr_state_continuation,
};

enum ied_rdpdr_result {
	ied_rdpdr_result_failed = -1,
	ied_rdpdr_result_success,
	ied_rdpdr_result_incomplete,
};

void m_svc_rdpdr_init(
	struct dsd_svc_rdpdr *adsp_rdpdr,
	struct dsd_aux_helper *adsp_aux,
	struct dsd_rdp_vc_1 *adsp_rdp_vc_1)
{
	adsp_rdpdr->inc_state = ied_rdpdr_state_start;
	adsp_rdpdr->adsc_rdp_vc_1 = adsp_rdp_vc_1;
	m_gather_fifo_init(&adsp_rdpdr->dsc_fifo);
}

static enum ied_rdpdr_result m_handle_core_server_announce(
	struct dsd_svc_rdpdr *adsp_rdpdr, 
	struct dsd_aux_helper *adsp_aux,
	struct dsd_gather_reader *adsp_gr,
	struct dsd_svc_rdpdr_message* adsp_result)
{
	// sent version numbers: 2.1 on W2K, 5.1 on .net
	/* VersionMajor */
	HL_GR_RET_GOTO(m_gr_read_uint16_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_announce.usc_version_major), LBL_READ_INCOMPLETE);
	HL_GR_RET_GOTO(m_gr_read_uint16_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_announce.usc_version_minor), LBL_READ_INCOMPLETE);
	HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_announce.umc_client_id), LBL_READ_INCOMPLETE);
	adsp_result->iec_message = iec_svc_rdpdr_message_server_announce_req;
	return ied_rdpdr_result_success;
LBL_READ_INCOMPLETE:
	return ied_rdpdr_result_incomplete;
LBL_FAILED:
	return ied_rdpdr_result_failed;
} // private void handle_core_server_announce(c_datareader ds_dr)

static enum ied_rdpdr_result m_handle_core_server_capability(
	struct dsd_svc_rdpdr *adsp_rdpdr, 
	struct dsd_aux_helper *adsp_aux,
	struct dsd_gather_reader *adsp_gr,
	struct dsd_svc_rdpdr_message* adsp_result)
{
	struct dsd_svc_rdpdr_capabilities* adsl_caps = &adsp_result->dsc_message.dsc_core_server_capability.dsc_caps;
	HL_GR_RET_GOTO(m_gr_read_uint16_le(adsp_gr, &adsl_caps->usc_num_capabilities), LBL_READ_INCOMPLETE);
	HL_GR_RET_GOTO(m_gr_skip(adsp_gr, 2), LBL_READ_INCOMPLETE);
	adsl_caps->boc_general = FALSE;
	adsl_caps->boc_printer = FALSE;
	adsl_caps->boc_port = FALSE;
	adsl_caps->boc_drive = FALSE;
	adsl_caps->boc_smartcard = FALSE;
	for(int im_c = 0; im_c < adsl_caps->usc_num_capabilities; im_c++) {
		/* CapabilityType */
		uint16_t im_capability_type;
		HL_GR_RET_GOTO(m_gr_read_uint16_le(adsp_gr, &im_capability_type), LBL_READ_INCOMPLETE);
		uint16_t im_capabilty_len;
		HL_GR_RET_GOTO(m_gr_read_uint16_le(adsp_gr, &im_capabilty_len), LBL_READ_INCOMPLETE);
		if(im_capabilty_len < 8)
			goto LBL_FAILED;
		im_capabilty_len -= 8;
		uint32_t im_version;
		HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &im_version), LBL_READ_INCOMPLETE);
		int im_capabilty_end = m_gr_get_abs_position(adsp_gr) + im_capabilty_len;
		switch(im_capability_type) {
		case IM_CAP_GENERAL_TYPE:
			adsl_caps->boc_general = TRUE;
			adsl_caps->dsc_general.umc_version = im_version;
			HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsl_caps->dsc_general.umc_os_type), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsl_caps->dsc_general.umc_os_version), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_uint16_le(adsp_gr, &adsl_caps->dsc_general.usc_protocol_major_version), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_uint16_le(adsp_gr, &adsl_caps->dsc_general.usc_protocol_minor_version), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsl_caps->dsc_general.umc_io_code1), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsl_caps->dsc_general.umc_io_code2), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsl_caps->dsc_general.umc_extended_pdu), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsl_caps->dsc_general.umc_extra_flag1), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsl_caps->dsc_general.umc_extra_flag2), LBL_READ_INCOMPLETE);
			adsl_caps->dsc_general.umc_special_type_device_cap = 0;
			if(im_version > 1) {
				/* SpecialTypeDeviceCap */
				HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsl_caps->dsc_general.umc_special_type_device_cap), LBL_READ_INCOMPLETE);
			}
			break;
		case IM_CAP_PRINTER_TYPE:
			adsl_caps->boc_printer = TRUE;
			adsl_caps->dsc_printer.umc_version = im_version;
			break;
		case IM_CAP_PORT_TYPE:
			adsl_caps->boc_port = TRUE;
			adsl_caps->dsc_port.umc_version = im_version;
			break;
		case IM_CAP_DRIVE_TYPE:
			adsl_caps->boc_drive = TRUE;
			adsl_caps->dsc_drive.umc_version = im_version;
			break;
		case IM_CAP_SMARTCARD_TYPE:
			adsl_caps->boc_smartcard = TRUE;
			adsl_caps->dsc_smartcard.umc_version = im_version;
			break;
		default:
			goto LBL_FAILED;
		} // switch (im_capability_type)
		/* Seek to next capability. */
		HL_GR_RET_GOTO(m_gr_seek(adsp_gr, im_capabilty_end), LBL_READ_INCOMPLETE);
	} // for (int im_c = 0; im_c < im_num_caps; im_c++)
	adsp_result->iec_message = iec_svc_rdpdr_message_server_capability_req;
	return ied_rdpdr_result_success;
LBL_READ_INCOMPLETE:
	return ied_rdpdr_result_incomplete;
LBL_FAILED:
	return ied_rdpdr_result_failed;
}

static enum ied_rdpdr_result m_handle_core_server_clientid_confirm(
	struct dsd_svc_rdpdr *adsp_rdpdr, 
	struct dsd_aux_helper *adsp_aux,
	struct dsd_gather_reader *adsp_gr,
	struct dsd_svc_rdpdr_message* adsp_result)
{
	HL_GR_RET_GOTO(m_gr_read_uint16_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_clientid_confirm.usc_version_major), LBL_READ_INCOMPLETE);
	HL_GR_RET_GOTO(m_gr_read_uint16_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_clientid_confirm.usc_version_minor), LBL_READ_INCOMPLETE);
	HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_clientid_confirm.umc_client_id), LBL_READ_INCOMPLETE);
	adsp_result->iec_message = iec_svc_rdpdr_message_server_clientid_confirm;
	return ied_rdpdr_result_success;
LBL_READ_INCOMPLETE:
	return ied_rdpdr_result_incomplete;
LBL_FAILED:
	return ied_rdpdr_result_failed;
}

static enum ied_rdpdr_result m_handle_core_server_device_announce_resp(
	struct dsd_svc_rdpdr *adsp_rdpdr, 
	struct dsd_aux_helper *adsp_aux,
	struct dsd_gather_reader *adsp_gr,
	struct dsd_svc_rdpdr_message* adsp_result)
{
	HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_announce.umc_device_id), LBL_READ_INCOMPLETE);
	HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_announce.umc_error_code), LBL_READ_INCOMPLETE);
	adsp_result->iec_message = iec_svc_rdpdr_message_server_device_announce_resp;
	return ied_rdpdr_result_success;
LBL_READ_INCOMPLETE:
	return ied_rdpdr_result_incomplete;
LBL_FAILED:
	return ied_rdpdr_result_failed;
}

static enum ied_rdpdr_result m_handle_core_server_device_io_req(
	struct dsd_svc_rdpdr *adsp_rdpdr, 
	struct dsd_aux_helper *adsp_aux,
	struct dsd_gather_reader *adsp_gr,
	struct dsd_svc_rdpdr_message* adsp_result)
{
	HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.umc_device_id), LBL_READ_INCOMPLETE);
	HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.umc_file_id), LBL_READ_INCOMPLETE);
	HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.umc_completion_id), LBL_READ_INCOMPLETE);
	HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.umc_major_function), LBL_READ_INCOMPLETE);
	HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.umc_minor_function), LBL_READ_INCOMPLETE);
	switch(adsp_result->dsc_message.dsc_core_server_device_io_req.umc_major_function) {
	case IRP_MJ_CREATE:
		HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_create.umc_desired_access), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint64_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_create.ulc_allocation_size), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_create.umc_file_attributes), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_create.umc_shared_access), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_create.umc_create_disposition), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_create.umc_create_options), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_create.umc_path_length), LBL_READ_INCOMPLETE);
		m_gr_get_position(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_create.dsc_path);
		HL_GR_RET_GOTO(m_gr_skip(adsp_gr, adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_create.umc_path_length), LBL_READ_INCOMPLETE);
		break;
	case IRP_MJ_CLOSE:
		HL_GR_RET_GOTO(m_gr_skip(adsp_gr, 32), LBL_READ_INCOMPLETE);
		break;
	case IRP_MJ_READ:
		HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_read.umc_length), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint64_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_read.ulc_offset), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_skip(adsp_gr, 20), LBL_READ_INCOMPLETE);
		break;
	case IRP_MJ_WRITE:
		HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_write.umc_length), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint64_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_write.ulc_offset), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_skip(adsp_gr, 20), LBL_READ_INCOMPLETE);
		m_gr_get_position(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_write.dsc_data);
		adsp_rdpdr->umc_continuation_pos = m_gather_i_1_pos_count_data_len(&adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_write.dsc_data);
		adsp_rdpdr->umc_continuation_total = adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_write.umc_length;
		break;
	case IRP_MJ_DEVICE_CONTROL:
		HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_device_control.umc_output_buffer_length), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_device_control.umc_input_buffer_length), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_device_control.umc_io_control_code), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_skip(adsp_gr, 20), LBL_READ_INCOMPLETE);
		m_gr_get_position(adsp_gr, &adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_device_control.dsc_input_buffer);
		adsp_rdpdr->umc_continuation_pos = m_gather_i_1_pos_count_data_len(&adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_device_control.dsc_input_buffer);
		adsp_rdpdr->umc_continuation_total = adsp_result->dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_write.umc_length;
		break;
	default:
		goto LBL_FAILED;
	}
	adsp_result->iec_message = iec_svc_rdpdr_message_server_device_io_req;
	return ied_rdpdr_result_success;
LBL_READ_INCOMPLETE:
	return ied_rdpdr_result_incomplete;
LBL_FAILED:
	return ied_rdpdr_result_failed;
}

static enum ied_rdpdr_result m_handle_core_server_printer_cache_event(
	struct dsd_svc_rdpdr *adsp_rdpdr, 
	struct dsd_aux_helper *adsp_aux,
	struct dsd_gather_reader *adsp_gr,
	struct dsd_svc_rdpdr_message* adsp_result)
{
	HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsp_result->dsc_message.dsc_core_server_printer_cache_event.umc_event), LBL_READ_INCOMPLETE);
	switch(adsp_result->dsc_message.dsc_core_server_printer_cache_event.umc_event) {
	case RDPDR_UPDATE_PRINTER_EVENT: {
		struct dsd_svc_rdpdr_message_core_server_printer_cache_event::dsd_event::dsd_update_printer* adsl_update_printer =
			&adsp_result->dsc_message.dsc_core_server_printer_cache_event.dsc_event.dsc_update_printer;
		HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsl_update_printer->umc_print_name_len), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint32_le(adsp_gr, &adsl_update_printer->umc_cached_fields_len), LBL_READ_INCOMPLETE);
		m_gr_get_position(adsp_gr, &adsl_update_printer->dsc_printer_name);
		HL_GR_RET_GOTO(m_gr_skip(adsp_gr, adsl_update_printer->umc_print_name_len), LBL_READ_INCOMPLETE);
		m_gr_get_position(adsp_gr, &adsl_update_printer->dsc_cached_printer_config_data);
		adsp_rdpdr->umc_continuation_pos = m_gather_i_1_pos_count_data_len(&adsl_update_printer->dsc_cached_printer_config_data);
		adsp_rdpdr->umc_continuation_total = adsl_update_printer->umc_cached_fields_len;
		break;
	}
	default:
		goto LBL_FAILED;
	}
	// TODO:
	adsp_result->iec_message = iec_svc_rdpdr_message_server_printer_cache_event;
	return ied_rdpdr_result_success;
LBL_READ_INCOMPLETE:
	return ied_rdpdr_result_incomplete;
LBL_FAILED:
	return ied_rdpdr_result_failed;
}

int m_svc_rdpdr_receive_message(
	struct dsd_svc_rdpdr *adsp_rdpdr, 
	struct dsd_aux_helper *adsp_aux,
   struct dsd_rdp_vch_io* adsp_message,
	struct dsd_svc_rdpdr_message* adsp_result)
{
	struct dsd_gather_i_1_fifo dsl_fifo;
	m_gather_fifo_init(&dsl_fifo);
	if(adsp_rdpdr->dsc_fifo.adsc_first != NULL) {
		m_gather_fifo_foreach(&adsp_rdpdr->dsc_fifo, &m_gather_i_1_ref_dec, adsp_aux);
		m_gather_fifo_append_fifo(&dsl_fifo, &adsp_rdpdr->dsc_fifo);
	}
	m_gather_fifo_append_list2(&dsl_fifo, adsp_message->adsc_gai1_data);
#if 0
	int inl_count = 0;
	int inl_gathers = 0;
	struct dsd_gather_i_1* adsl_cur = dsl_fifo.adsc_first;
	struct dsd_gather_i_1* adsl_last = adsl_cur;
	while(adsl_cur != NULL) {
		adsl_last = adsl_cur;
		m_aux_printf(adsp_aux, "m_svc_rdpdr_receive_message: adsl_cur=%p len=%d\n",
			adsl_cur, adsl_cur->achc_ginp_end - adsl_cur->achc_ginp_cur);
		inl_count += adsl_cur->achc_ginp_end - adsl_cur->achc_ginp_cur;
		struct dsd_gather_i_1* adsl_next = adsl_cur->adsc_next;
        adsl_cur = adsl_next;
		inl_gathers++;
    }
	m_aux_printf(adsp_aux, "m_svc_rdpdr_receive_message: inl_gathers=%d inl_count=%d first=%p last=%p\n",
		inl_gathers, inl_count, dsl_fifo.adsc_first, adsl_last);
#endif	
	struct dsd_gather_reader dsl_gather_reader;
	m_gr_init(&dsl_gather_reader, &dsl_fifo);
	struct dsd_gather_i_1_pos dsl_lookahead_pos;
	enum ied_rdpdr_result iel_res;
	switch(adsp_rdpdr->inc_state) {
	case ied_rdpdr_state_start: {
#if 0
		m_aux_printf(adsp_aux, "m_svc_rdpdr_receive_message: HEAD\n");
		m_aux_dump_gather(&dsl_aux, dsl_fifo.adsc_first, 32);
#endif
		goto LBL_STATE_START;
	}
	case ied_rdpdr_state_head:
		goto LBL_STATE_HEAD;
	case ied_rdpdr_state_skip:
		if((adsp_message->chrc_vch_flags[0] & CHANNEL_FLAG_FIRST) != 0)
			goto LBL_FAILED;
		if((adsp_message->chrc_vch_flags[0] & CHANNEL_FLAG_LAST) == 0)
			return 0;
		adsp_rdpdr->inc_state = ied_rdpdr_state_start;
		return 0;
	case ied_rdpdr_state_continuation: {
		if((adsp_message->chrc_vch_flags[0] & CHANNEL_FLAG_FIRST) != 0)
			goto LBL_FAILED;
		int inl_result = 0;
		switch(adsp_rdpdr->iec_continuation_message) {
		case iec_svc_rdpdr_message_server_printer_cache_event:
			adsp_result->iec_message = iec_svc_rdpdr_message_server_printer_cache_event_continuation;
			adsp_result->dsc_message.dsc_core_server_printer_cache_event_continuation.umc_offset = adsp_rdpdr->umc_continuation_pos;
			adsp_result->dsc_message.dsc_core_server_printer_cache_event_continuation.umc_length = adsp_message->umc_vch_ulen;
			adsp_result->dsc_message.dsc_core_server_printer_cache_event_continuation.umc_total = adsp_rdpdr->umc_continuation_total;
			m_gather_i_1_pos_from_gather(&adsp_result->dsc_message.dsc_core_server_printer_cache_event_continuation.dsc_cached_printer_config_data, adsp_message->adsc_gai1_data);
			adsp_rdpdr->umc_continuation_pos += adsp_message->umc_vch_ulen;
			inl_result = 1;
			break;
		case iec_svc_rdpdr_message_server_device_io_req:
			adsp_result->iec_message = iec_svc_rdpdr_message_server_device_io_continuation;
			adsp_result->dsc_message.dsc_core_server_device_io_continuation.umc_offset = adsp_rdpdr->umc_continuation_pos;
			adsp_result->dsc_message.dsc_core_server_device_io_continuation.umc_length = adsp_message->umc_vch_ulen;
			adsp_result->dsc_message.dsc_core_server_device_io_continuation.umc_total = adsp_rdpdr->umc_continuation_total;
			m_gather_i_1_pos_from_gather(&adsp_result->dsc_message.dsc_core_server_device_io_continuation.dsc_data, adsp_message->adsc_gai1_data);
			adsp_rdpdr->umc_continuation_pos += adsp_message->umc_vch_ulen;
			inl_result = 1;
			break;
		default:
			break;
		}
		if((adsp_message->chrc_vch_flags[0] & CHANNEL_FLAG_LAST) == 0)
			return inl_result;
		adsp_rdpdr->inc_state = ied_rdpdr_state_start;
		return inl_result;
	}
	default:
		goto LBL_FAILED;
	}
LBL_STATE_START:
	// Start lookahead mode
	HL_GR_RET_GOTO(m_gr_begin_lookahead(&dsl_gather_reader, &dsl_lookahead_pos), LBL_FAILED);
	HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &adsp_rdpdr->usc_component), LBL_READ_INCOMPLETE);
	HL_GR_RET_GOTO(m_gr_read_uint16_le(&dsl_gather_reader, &adsp_rdpdr->usc_packetid), LBL_READ_INCOMPLETE);
	// End lookahead mode
	HL_GR_RET_GOTO(m_gr_end_lookahead(&dsl_gather_reader, &dsl_lookahead_pos), LBL_FAILED);
	adsp_rdpdr->inc_state = ied_rdpdr_state_head;
LBL_STATE_HEAD:
	HL_GR_RET_GOTO(m_gr_begin_lookahead(&dsl_gather_reader, &dsl_lookahead_pos), LBL_FAILED);
	switch(adsp_rdpdr->usc_component) {
	case IM_RDPDR_CTYP_CORE:
		switch(adsp_rdpdr->usc_packetid) {
		case IM_PAKID_CORE_SERVER_ANNOUNCE:
			iel_res = m_handle_core_server_announce(adsp_rdpdr, adsp_aux, &dsl_gather_reader, adsp_result);
			break;
		case IM_PAKID_CORE_SERVER_CAPABILITY:
			iel_res = m_handle_core_server_capability(adsp_rdpdr, adsp_aux, &dsl_gather_reader, adsp_result);
			break;
		case IM_PAKID_CORE_CLIENTID_CONFIRM:
			iel_res = m_handle_core_server_clientid_confirm(adsp_rdpdr, adsp_aux, &dsl_gather_reader, adsp_result);
			break;
		case IM_PAKID_CORE_USER_LOGGEDON:
			adsp_result->iec_message = iec_svc_rdpdr_message_server_user_loggedon;
			iel_res = ied_rdpdr_result_success;
			break;
		case IM_PAKID_CORE_DEVICE_REPLY:
			iel_res = m_handle_core_server_device_announce_resp(adsp_rdpdr, adsp_aux, &dsl_gather_reader, adsp_result);
			break;
		case IM_PAKID_CORE_DEVICE_IOREQUEST:
			iel_res = m_handle_core_server_device_io_req(adsp_rdpdr, adsp_aux, &dsl_gather_reader, adsp_result);
			break;
		default:
			goto LBL_FAILED;
		}
		break;
	case IM_RDPDR_CTYP_PRN: {
		switch(adsp_rdpdr->usc_packetid) {
		case IM_PAKID_PRN_CACHE_DATA:
			iel_res = m_handle_core_server_printer_cache_event(adsp_rdpdr, adsp_aux, &dsl_gather_reader, adsp_result);
			break;
		default:
			goto LBL_FAILED;
		}
		break;
	}
	default:
		goto LBL_FAILED;
	}
	switch(iel_res) {
	case ied_rdpdr_result_failed:
	default:
		goto LBL_FAILED;
	case ied_rdpdr_result_success:
		break;
	case ied_rdpdr_result_incomplete:
		goto LBL_READ_INCOMPLETE;
	}
	//HL_GR_RET_GOTO(m_gr_end_lookahead(&dsl_gather_reader, &dsl_lookahead_pos), LBL_FAILED);
	dsd_gather_i_1_pos dsl_pos;
	m_gr_commit(&dsl_gather_reader, &dsl_pos);
	if((adsp_message->chrc_vch_flags[0] & CHANNEL_FLAG_LAST) == 0) {
		adsp_rdpdr->iec_continuation_message = adsp_result->iec_message;
		adsp_rdpdr->inc_state = ied_rdpdr_state_continuation;
		return 1;
	}
	adsp_rdpdr->inc_state = ied_rdpdr_state_start;
	return 1;
LBL_READ_INCOMPLETE:
	if((adsp_message->chrc_vch_flags[0] & CHANNEL_FLAG_LAST) != 0)
		goto LBL_FAILED;
	m_gather_fifo_init(&adsp_rdpdr->dsc_fifo);
	m_gather_fifo_append_fifo(&adsp_rdpdr->dsc_fifo, &dsl_fifo);
	m_gather_fifo_foreach(&adsp_rdpdr->dsc_fifo, &m_gather_i_1_ref_inc, adsp_aux);
	adsp_rdpdr->inc_state = ied_rdpdr_state_start;
	return 0;
LBL_FAILED:
	return -1;
}

int m_svc_rdpdr_process_commands(
	struct dsd_svc_rdpdr *adsp_rdpdr, 
   struct dsd_aux_helper *adsp_aux,
   const struct dsd_svc_rdpdr_command* adsrp_commands,
	int inp_num_commands,
	struct dsd_svc_command_result* adsp_result)
{
	struct dsd_workarea_allocator dsl_wa_alloc;
	m_wa_allocator_init(&dsl_wa_alloc);
	dsl_wa_alloc.adsc_aux = adsp_aux;

	struct dsd_gather_i_1_fifo dsl_fifo_out;

	struct dsd_cc_co1** aadsl_vc_out = &adsp_result->adsc_vc_out_first;
	adsp_result->adsc_vc_out_first = NULL;
	adsp_result->adsc_vc_out_last = NULL;
	for(int inl_c=0; inl_c<inp_num_commands; inl_c++) {
		const struct dsd_svc_rdpdr_command* adsl_cmd = &adsrp_commands[inl_c];

		struct dsd_gather_writer dsl_gw;
		m_gw_init(&dsl_gw, &dsl_wa_alloc);
		HL_GR_RET_GOTO(m_gw_mark_start(&dsl_gw), LBL_FAILED);
		switch(adsl_cmd->iec_command) {
		case iec_svc_rdpdr_command_client_announce_resp:
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, IM_RDPDR_CTYP_CORE), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, IM_PAKID_CORE_CLIENTID_CONFIRM), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, adsl_cmd->dsc_message.dsc_core_client_announce.usc_version_major), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, adsl_cmd->dsc_message.dsc_core_client_announce.usc_version_minor), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_cmd->dsc_message.dsc_core_client_announce.umc_client_id), LBL_FAILED);
			break;
		case iec_svc_rdpdr_command_client_name_req:
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, IM_RDPDR_CTYP_CORE), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, IM_PAKID_CORE_CLIENT_NAME), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_cmd->dsc_message.dsc_core_client_name.umc_unicode_flag), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_cmd->dsc_message.dsc_core_client_name.umc_code_page), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_cmd->dsc_message.dsc_core_client_name.umc_computer_name_len), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_bytes(&dsl_gw, adsl_cmd->dsc_message.dsc_core_client_name.avoc_computer_name,
				adsl_cmd->dsc_message.dsc_core_client_name.umc_computer_name_len), LBL_FAILED);
			break;
		case iec_svc_rdpdr_command_client_capability_resp: {
			const struct dsd_svc_rdpdr_capabilities* adsl_caps = &adsl_cmd->dsc_message.dsc_core_client_capability.dsc_caps;
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, IM_RDPDR_CTYP_CORE), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, IM_PAKID_CORE_CLIENT_CAPABILITY), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, adsl_caps->usc_num_capabilities), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, 0), LBL_FAILED);
			if(adsl_caps->boc_general) {
				HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, IM_CAP_GENERAL_TYPE), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, adsl_caps->dsc_general.umc_version >= 0x0002 ? 44 : 40), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_caps->dsc_general.umc_version), LBL_FAILED);

				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_caps->dsc_general.umc_os_type), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_caps->dsc_general.umc_os_version), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, adsl_caps->dsc_general.usc_protocol_major_version), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, adsl_caps->dsc_general.usc_protocol_minor_version), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_caps->dsc_general.umc_io_code1), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_caps->dsc_general.umc_io_code2), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_caps->dsc_general.umc_extended_pdu), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_caps->dsc_general.umc_extra_flag1), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_caps->dsc_general.umc_extra_flag2), LBL_FAILED);
				if(adsl_caps->dsc_general.umc_version >= 0x0002) {
					HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_caps->dsc_general.umc_special_type_device_cap), LBL_FAILED);
				}
			}
			if(adsl_caps->boc_printer) {
				HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, IM_CAP_PRINTER_TYPE), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, 8), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_caps->dsc_printer.umc_version), LBL_FAILED);
			}
			if(adsl_caps->boc_port) {
				HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, IM_CAP_PORT_TYPE), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, 8), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_caps->dsc_port.umc_version), LBL_FAILED);
			}
			if(adsl_caps->boc_drive) {
				HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, IM_CAP_DRIVE_TYPE), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, 8), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_caps->dsc_drive.umc_version), LBL_FAILED);
			}
			if(adsl_caps->boc_smartcard) {
				HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, IM_CAP_SMARTCARD_TYPE), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, 8), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_caps->dsc_smartcard.umc_version), LBL_FAILED);
			}
			break;
	    }
		case iec_svc_rdpdr_command_client_device_list_announce_req: {
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, IM_RDPDR_CTYP_CORE), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, IM_PAKID_CORE_DEVICELIST_ANNOUNCE), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_cmd->dsc_message.dsc_core_client_device_list_announce.umc_device_count), LBL_FAILED);
			for(uint32_t uml_d=0; uml_d<adsl_cmd->dsc_message.dsc_core_client_device_list_announce.umc_device_count; uml_d++) {
				struct dsd_device_announce* adsl_dev = adsl_cmd->dsc_message.dsc_core_client_device_list_announce.adsrc_devices[uml_d];
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_dev->umc_device_type), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_dev->umc_device_id), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_bytes(&dsl_gw, adsl_dev->ucrc_preferred_dos_name, 8), LBL_FAILED);
				switch(adsl_dev->umc_device_type) {
				case RDPDR_DTYP_PRINT: {
					struct dsd_svc_rdpdr_device_annouce_data_printer* adsl_print = (struct dsd_svc_rdpdr_device_annouce_data_printer*)adsl_dev;
					uint32_t uml_device_data_len = 24 + adsl_print->umc_pnp_name_len + adsl_print->umc_driver_name_len
						+ adsl_print->umc_print_name_len + adsl_print->umc_cached_fields_len;
					HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, uml_device_data_len), LBL_FAILED);
					HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_print->umc_flags), LBL_FAILED);
					HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_print->umc_code_page), LBL_FAILED);
					HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_print->umc_pnp_name_len), LBL_FAILED);
					HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_print->umc_driver_name_len), LBL_FAILED);
					HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_print->umc_print_name_len), LBL_FAILED);
					HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_print->umc_cached_fields_len), LBL_FAILED);
					HL_GR_RET_GOTO(m_gw_write_bytes(&dsl_gw, adsl_print->avoc_pnp_name, adsl_print->umc_pnp_name_len), LBL_FAILED);
					HL_GR_RET_GOTO(m_gw_write_bytes(&dsl_gw, adsl_print->avoc_driver_name, adsl_print->umc_driver_name_len), LBL_FAILED);
					HL_GR_RET_GOTO(m_gw_write_bytes(&dsl_gw, adsl_print->avoc_print_name, adsl_print->umc_print_name_len), LBL_FAILED);
					HL_GR_RET_GOTO(m_gw_write_bytes(&dsl_gw, adsl_print->avoc_cached_fields, adsl_print->umc_cached_fields_len), LBL_FAILED);
					break;
				}
				default:
					goto LBL_FAILED;
				}
			}
			break;
		}
		case iec_svc_rdpdr_command_core_device_io_resp: {
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, IM_RDPDR_CTYP_CORE), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint16_le(&dsl_gw, IM_PAKID_CORE_DEVICE_IOCOMPLETION), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_cmd->dsc_message.dsc_core_device_io.umc_device_id), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_cmd->dsc_message.dsc_core_device_io.umc_completion_id), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_cmd->dsc_message.dsc_core_device_io.umc_io_status), LBL_FAILED);
			switch(adsl_cmd->dsc_message.dsc_core_device_io.iec_function) {
			case ied_device_io_function_create:
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_cmd->dsc_message.dsc_core_device_io.dsc_function.dsc_create.umc_file_id), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint8(&dsl_gw, adsl_cmd->dsc_message.dsc_core_device_io.dsc_function.dsc_create.ucc_information), LBL_FAILED);
				break;
			case ied_device_io_function_write:
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_cmd->dsc_message.dsc_core_device_io.dsc_function.dsc_write.umc_length), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint8(&dsl_gw, 0), LBL_FAILED);
				break;
			case ied_device_io_function_close:
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, 0), LBL_FAILED);
				break;
			case ied_device_io_function_device_io:
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_cmd->dsc_message.dsc_core_device_io.dsc_function.dsc_device_io.umc_output_buffer_length), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_gather_list(&dsl_gw, adsl_cmd->dsc_message.dsc_core_device_io.dsc_function.dsc_device_io.adsc_output_buffer,
					adsl_cmd->dsc_message.dsc_core_device_io.dsc_function.dsc_device_io.umc_output_buffer_length), LBL_FAILED);
				break;
			default:
				goto LBL_FAILED;
			}
			break;
		}
		default:
			goto LBL_FAILED;
		}
		HL_GR_RET_GOTO(m_gw_mark_end(&dsl_gw), LBL_FAILED);
		int inl_num_bytes = m_gw_get_abs_pos(&dsl_gw);
		m_gather_fifo_init(&dsl_fifo_out);
		m_gather3_list_release(&dsl_gw.dsc_fifo, &dsl_fifo_out);

		m_gw_destroy(&dsl_gw);
#if 0
		m_aux_printf(adsp_aux, "m_svc_rdpdr_process_commands: adsl_cmd->iec_command=%d inl_num_bytes=%d\n",
			adsl_cmd->iec_command, inl_num_bytes);
		m_aux_dump_gather(adsp_aux, dsl_fifo_out.adsc_first, -1);
#endif
		struct dsd_cc_co1* adsl_cc_co1 = (struct dsd_cc_co1*)m_wa_allocator_alloc_lower(&dsl_wa_alloc,
			sizeof(struct dsd_cc_co1) + sizeof(struct dsd_rdp_vch_io),
			HL_ALIGNOF(struct dsd_rdp_vch_io));
		adsl_cc_co1->iec_cc_command = ied_ccc_vch_out;
		adsl_cc_co1->adsc_next = NULL;
		struct dsd_rdp_vch_io* adsl_cc_vch_io = (struct dsd_rdp_vch_io*)(adsl_cc_co1+1);
		adsl_cc_vch_io->adsc_gai1_data = dsl_fifo_out.adsc_first;
		adsl_cc_vch_io->umc_vch_ulen = inl_num_bytes;
		memset(adsl_cc_vch_io->chrc_vch_flags, 0, sizeof(adsl_cc_vch_io->chrc_vch_flags));
		adsl_cc_vch_io->chrc_vch_flags[0] = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST;
		adsl_cc_vch_io->adsc_rdp_vc_1 = adsp_rdpdr->adsc_rdp_vc_1;

		*aadsl_vc_out = adsl_cc_co1;
		aadsl_vc_out = &adsl_cc_co1->adsc_next;
		adsp_result->adsc_vc_out_last = adsl_cc_co1;
	}
	return 0;
LBL_FAILED:
	return -1;
}

void m_svc_rdpdr_destroy(
	struct dsd_svc_rdpdr *adsp_rdpdr,
	struct dsd_aux_helper *adsp_aux)
{
}
