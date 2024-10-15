// Source file for the implementation of the Remote Desktop Protocol: Input Virtual Channel Extension ([MS-RDPEI]).

#define DVC_INPUT_EVENTID_SC_READY 0x0001
#define DVC_INPUT_EVENTID_CS_READY 0x0002
#define DVC_INPUT_EVENTID_TOUCH 0x0003
#define DVC_INPUT_EVENTID_SUSPEND_INPUT 0x0004
#define DVC_INPUT_EVENTID_RESUME_INPUT 0x0005
#define DVC_INPUT_EVENTID_DISMISS_HOVERING_TOUCH_CONTACT 0x0006
#define DVC_INPUT_EVENTID_PEN 0x0008

#define DVC_INPUT_READY_FLAGS_SHOW_TOUCH_VISUALS 0x00000001
#define DVC_INPUT_READY_FLAGS_DISABLE_TIMESTAMP_INJECTION 0x00000002

#define DVC_INPUT_RDPINPUT_PROTOCOL_V100 0x00010000
#define DVC_INPUT_RDPINPUT_PROTOCOL_V101 0x00010001
#define DVC_INPUT_RDPINPUT_PROTOCOL_V200 0x00020000
#define DVC_INPUT_RDPINPUT_PROTOCOL_V300 0x00030000

#define DVC_INPUT_TOUCH_CONTACT_CONTACTRECT_PRESENT 0x0001 // The optional contactRectLeft, contactRectTop, contactRectRight, and contactRectBottom fields are all present.
#define DVC_INPUT_TOUCH_CONTACT_ORIENTATION_PRESENT 0x0002 // The optional orientation field is present.
#define DVC_INPUT_TOUCH_CONTACT_PRESSURE_PRESENT 0x0004 // The optional pressure field is present.

#define DVC_INPUT_PEN_CONTACT_PENFLAGS_PRESENT 0x0001 // The optional penFlags field is present.
#define DVC_INPUT_PEN_CONTACT_PRESSURE_PRESENT 0x0002 // The optional pressure field is present.
#define DVC_INPUT_PEN_CONTACT_ROTATION_PRESENT 0x0004 // The optional rotation field is present.
#define DVC_INPUT_PEN_CONTACT_TILTX_PRESENT 0x0008 // The optional tiltX field is present.
#define DVC_INPUT_PEN_CONTACT_TILTY_PRESENT 0x0010 // The optional tiltY field is present

#define DVC_INPUT_SC_READY_MULTIPEN_INJECTION_SUPPORTED 0x00000001

/*===================
    INCLUDES
===================*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef HL_UNIX
    #include <windows.h>
#else
    #include <sys/types.h>
    #include <errno.h>
    #include <hob-unix01.h>
    #include <stdarg.h>
#endif

#ifndef LEN_SECURE_XOR_PWD
// hack: missing header guards in hob-xsclib01.h
#include <hob-xsclib01.h>
#endif
#include <hob-datarw.h>
#include <hob-avl03.h>
#include <hob-dynvc-common.h>
#include <hob-webterm-rdp-svc-dynvc.h>
#include <hob-dynvc-input.h>
#include <xs-tk-gather-tools-01.cpp>

#define DEBUG_TOUCH 1
#if DEBUG_TOUCH
// hack: missing header guards in hob-xslunic1.h
#ifndef MAX_IDNAPART_LENGTH
#include <hob-xslunic1.h>
#endif
struct dsd_sdh_call_1 {                     /* structure call in SDH   */
   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     vpc_userfld;                  /* User Field Subroutine   */
};
/* subroutine for output to console                                    */
static int m_sdh_printf( struct dsd_sdh_call_1 *adsp_sdh_call_1, const char *achptext, ... ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   va_list    dsl_argptr;
   char       chrl_out1[512];

   va_start( dsl_argptr, achptext );
   iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8, achptext, dsl_argptr );
   va_end( dsl_argptr );
   bol1 = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                       DEF_AUX_CONSOLE_OUT,  /* output to console */
                                       chrl_out1, iml1 );
   return iml1;
} /* end m_sdh_printf()*/

#endif /* DEBUG_TOUCH */


// 2.2.3.2 RDPINPUT_CS_READY_PDU
static enum ied_dynvc_result m_send_rdpinput_cs_ready(struct dsd_dvc_input* adsp_input, struct dsd_dynvc_listener_event* adsp_event) {
	struct dsd_gather_writer* adsl_gw_server = adsp_event->adsc_gw_server;
	static const uint32_t uml_pdu_length = 2 + 4 + 4 + 4 + 2;

	// Prepare flags
	unsigned int unl_flags = 0x0;
	if (adsp_input->boc_show_touch_visuals > 0) {
		unl_flags |= DVC_INPUT_READY_FLAGS_SHOW_TOUCH_VISUALS;
	}
	// TODO: Remember to check for "This flag SHOULD NOT be sent to a server that only supports version 1.0.0 of the input remoting protocol." 
	// prior to calling this function.
	if (adsp_input->boc_disable_ts_injection > 0) {
		unl_flags |= DVC_INPUT_READY_FLAGS_DISABLE_TIMESTAMP_INJECTION;
	}

	HL_GR_RET_GOTO(m_svc_dynvc_write_data_header(adsl_gw_server, adsp_input->dsc_common.dsc_channel_context.umc_channel_id), LBL_FAILED);

	HL_GR_RET_GOTO(m_gw_write_uint16_le(adsl_gw_server, DVC_INPUT_EVENTID_CS_READY), LBL_FAILED);
	HL_GR_RET_GOTO(m_gw_write_uint32_le(adsl_gw_server, uml_pdu_length), LBL_FAILED);
	HL_GR_RET_GOTO(m_gw_write_uint32_le(adsl_gw_server, unl_flags), LBL_FAILED);
	HL_GR_RET_GOTO(m_gw_write_uint32_le(adsl_gw_server, adsp_input->umc_cl_version), LBL_FAILED);
	HL_GR_RET_GOTO(m_gw_write_uint16_le(adsl_gw_server, adsp_input->usc_max_touch_contacts), LBL_FAILED);

	return ied_success;
LBL_FAILED:
	return ied_error;
}

static enum ied_dynvc_result m_handle_event(void* avop_this, enum ied_dynvc_msg_type iep_type, struct dsd_dynvc_listener_event* adsp_event) {
	struct dsd_dvc_input* adsl_this = (struct dsd_dvc_input*)avop_this;
	struct dsd_gather_reader* adsl_reader = adsp_event->adsc_reader;
	struct dsd_gather_writer* adsl_gw_client = adsp_event->adsc_gw_client;

	switch (iep_type) {
	case ied_create: {
		//adsl_this->dsc_common.umc_channel_id = adsp_event->umc_channel_id;
		int inl_name_len = strlen(STR_DYNVC_NAME_INPUT);
		HL_GR_RET_GOTO(m_gw_write_hasn1(adsl_gw_client, adsp_event->umc_channel_id), LBL_FAILED);
		HL_GR_RET_GOTO(m_gw_write_hasn1(adsl_gw_client, inl_name_len), LBL_FAILED);
		HL_GR_RET_GOTO(m_gw_write_bytes(adsl_gw_client, STR_DYNVC_NAME_INPUT, inl_name_len), LBL_FAILED);
		break;
	}
	case ied_close:
		HL_GR_RET_GOTO(m_gw_write_hasn1(adsl_gw_client, adsp_event->umc_channel_id), LBL_FAILED);
		//adsl_this->dsc_common.umc_channel_id = -1;
		break;
	case ied_data:
	case ied_datafirst: {
		// segmentation should not happen, because all packets are tiny
		uint16_t usl_event_id = 0;
		uint32_t uml_pdu_length = 0;
		HL_GR_RET_GOTO(m_gr_read_uint16_le(adsl_reader, &usl_event_id), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint32_le(adsl_reader, &uml_pdu_length), LBL_READ_INCOMPLETE);
		switch (usl_event_id) {
		case DVC_INPUT_EVENTID_SC_READY: {
			uint32_t uml_protocol_version = 0;
			HL_GR_RET_GOTO(m_gr_read_uint32_le(adsl_reader, &uml_protocol_version), LBL_READ_INCOMPLETE);
			if (uml_protocol_version != DVC_INPUT_RDPINPUT_PROTOCOL_V100 &&
				uml_protocol_version != DVC_INPUT_RDPINPUT_PROTOCOL_V101 &&
				uml_protocol_version != DVC_INPUT_RDPINPUT_PROTOCOL_V200 &&
				uml_protocol_version != DVC_INPUT_RDPINPUT_PROTOCOL_V300) {
				return ied_error; // Error: Invalid Protocol Version
			}
			if (uml_protocol_version == DVC_INPUT_RDPINPUT_PROTOCOL_V300) {
				uint32_t uml_supported_features = 0;
				HL_GR_RET_GOTO(m_gr_read_uint32_le(adsl_reader, &uml_supported_features), LBL_READ_INCOMPLETE);
				adsl_this->umc_supported_features = uml_supported_features;
			}
			adsl_this->umc_se_version = uml_protocol_version;
			adsl_this->boc_input_transmission_suspended = 0;
			return m_send_rdpinput_cs_ready(adsl_this, adsp_event);
		}
		case DVC_INPUT_EVENTID_SUSPEND_INPUT:
			adsl_this->boc_input_transmission_suspended = 1;
			break;
		case DVC_INPUT_EVENTID_RESUME_INPUT:
			adsl_this->boc_input_transmission_suspended = 0;
			break;
		default:
			return ied_error;
		}
		if (usl_event_id == DVC_INPUT_EVENTID_SUSPEND_INPUT || usl_event_id == DVC_INPUT_EVENTID_RESUME_INPUT) {
			HL_GR_RET_GOTO(m_gw_write_hasn1(adsl_gw_client, adsp_event->umc_channel_id), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_hasn1(adsl_gw_client, adsp_event->umc_packet_length), LBL_FAILED);
			if (iep_type == ied_datafirst) {
				HL_GR_RET_GOTO(m_gw_write_hasn1(adsl_gw_client, adsp_event->umc_total_length), LBL_FAILED);
			}
			HL_GR_RET_GOTO(m_gw_write_uint16_le(adsl_gw_client, usl_event_id), LBL_FAILED);
		}
		break;
	}
	default:
		break;
	}

	return ied_success;
LBL_READ_INCOMPLETE:
	return ied_incomplete;
LBL_FAILED:
	return ied_error;
}

// NOTE: Initialization function for RDPEI.
void m_init_rdpei(struct dsd_dynvc_context* adsp_drdynvc, struct dsd_dvc_input* adsp_dvc_input) {

	adsp_dvc_input->dsc_common.adsc_svc = adsp_drdynvc;
	//adsp_dvc_input->dsc_common.umc_channel_id = (unsigned int)-1;
	adsp_dvc_input->umc_se_version = 0;
	adsp_dvc_input->umc_cl_version = DVC_INPUT_RDPINPUT_PROTOCOL_V100;

	adsp_dvc_input->boc_show_touch_visuals = 1;
	adsp_dvc_input->boc_disable_ts_injection = 0;
	adsp_dvc_input->usc_max_touch_contacts = DVC_INPUT_MAX_CONTACTS;
	adsp_dvc_input->boc_pen_allowed = 0;
	adsp_dvc_input->boc_input_transmission_suspended = 1;
	adsp_dvc_input->ullc_prev_frame_time = 0;

	memset(&adsp_dvc_input->dsl_active_touch_frame, 0, sizeof(dsd_input_touch_frame));

	adsp_dvc_input->umc_supported_features = 0;
	adsp_dvc_input->dsc_common.dsc_channel_context.dsc_listener.avoc_context = adsp_dvc_input;
	adsp_dvc_input->dsc_common.dsc_channel_context.dsc_listener.m_receive = &m_handle_event;
#if 0
	// Set up Touch Redirection Listener
    struct dsd_dynvc_listener dsc_listener;
    dsc_listener.achc_name = STR_DYNVC_NAME_INPUT;
    dsc_listener.avoc_context = adsp_dvc_input;
	dsc_listener.m_receive = &m_handle_event;
	// Register Touch Redirection Listener
	m_register_listener(adsp_drdynvc, dsc_listener);
#endif
}

static BOOL m_gw_write_2b_uint(struct dsd_gather_writer* adsl_writer, uint16_t usp_val) {
	unsigned char uchrl_integer_buf[8];
	unsigned char* aucl_buf_end = uchrl_integer_buf + 8;
	unsigned char* aucl_buf_data_end = m_write_two_byte_uint(uchrl_integer_buf, aucl_buf_end, usp_val);
	if (aucl_buf_data_end == NULL) {
		return FALSE;
	}
	return m_gw_write_bytes(adsl_writer, uchrl_integer_buf, aucl_buf_data_end - uchrl_integer_buf);
}

static BOOL m_gw_write_2b_sint(struct dsd_gather_writer* adsl_writer, int16_t isp_val) {
	unsigned char uchrl_integer_buf[8];
	unsigned char* aucl_buf_end = uchrl_integer_buf + 8;
	unsigned char* aucl_buf_data_end = m_write_two_byte_sint(uchrl_integer_buf, aucl_buf_end, isp_val);
	if (aucl_buf_data_end == NULL) {
		return FALSE;
	}
	return m_gw_write_bytes(adsl_writer, uchrl_integer_buf, aucl_buf_data_end - uchrl_integer_buf);
}

static BOOL m_gw_write_4b_uint(struct dsd_gather_writer* adsl_writer, uint32_t ump_val) {
	unsigned char uchrl_integer_buf[8];
	unsigned char* aucl_buf_end = uchrl_integer_buf + 8;
	unsigned char* aucl_buf_data_end = m_write_four_byte_uint(uchrl_integer_buf, aucl_buf_end, ump_val);
	if (aucl_buf_data_end == NULL) {
		return FALSE;
	}
	return m_gw_write_bytes(adsl_writer, uchrl_integer_buf, aucl_buf_data_end - uchrl_integer_buf);
}

static BOOL m_gw_write_4b_sint(struct dsd_gather_writer* adsl_writer, int32_t imp_val) {
	unsigned char uchrl_integer_buf[8];
	unsigned char* aucl_buf_end = uchrl_integer_buf + 8;
	unsigned char* aucl_buf_data_end = m_write_four_byte_sint(uchrl_integer_buf, aucl_buf_end, imp_val);
	if (aucl_buf_data_end == NULL) {
		return FALSE;
	}
	return m_gw_write_bytes(adsl_writer, uchrl_integer_buf, aucl_buf_data_end - uchrl_integer_buf);
}

static BOOL m_gw_write_8b_uint(struct dsd_gather_writer* adsl_writer, uint64_t ulp_val) {
	unsigned char uchrl_integer_buf[8];
	unsigned char* aucl_buf_end = uchrl_integer_buf + 8;
	unsigned char* aucl_buf_data_end = m_write_eight_byte_uint(uchrl_integer_buf, aucl_buf_end, ulp_val);
	if (aucl_buf_data_end == NULL) {
		return FALSE;
	}
	return m_gw_write_bytes(adsl_writer, uchrl_integer_buf, aucl_buf_data_end - uchrl_integer_buf);
}

int m_send_rdpinput_touch_event(struct dsd_dvc_input* adsp_input, struct dsd_aux_helper* adsp_aux,
	struct dsd_input_touch_frame* adsp_touch_frame, struct dsd_gather_i_1_fifo* adsp_fifo_out)
{
	if (adsp_input->boc_input_transmission_suspended == TRUE) {
		// transmission of touch events is suspended!
		return -2;
	}
	if (adsp_input->dsc_common.adsc_svc == NULL) {
		// virtual channel is not opened!
		return -3;
	}
	uint32_t uml_encode_time = 0;
	uint16_t usl_frame_count = 1;
	int inl_writer_pos_start = 0;
	int inl_writer_pos_end = 0;
	int inl_num_bytes = 0;
	uint32_t uml_pdu_len = 0;

	// Prepare writer
	struct dsd_workarea_allocator dsl_wa_alloc;
	m_wa_allocator_init(&dsl_wa_alloc);
	dsl_wa_alloc.adsc_aux = adsp_aux;

	struct dsd_gather_writer dsl_writer;
	m_gw_init(&dsl_writer, &dsl_wa_alloc);
	HL_GR_RET_GOTO(m_gw_mark_start(&dsl_writer), LBL_FAILED);
	inl_writer_pos_start = m_gw_get_abs_pos(&dsl_writer);

	struct dsd_gather_writer dsl_writer_header;
	m_gw_init(&dsl_writer_header, &dsl_wa_alloc);

	HL_GR_RET_GOTO(m_gw_write_4b_uint(&dsl_writer, uml_encode_time), LBL_FAILED);
	HL_GR_RET_GOTO(m_gw_write_2b_uint(&dsl_writer, usl_frame_count), LBL_FAILED);

	for (uint16_t usl_frame=0; usl_frame<usl_frame_count; usl_frame++) {
		uint16_t usl_contact_count = adsp_touch_frame->usc_contact_count;
		HL_GR_RET_GOTO(m_gw_write_2b_uint(&dsl_writer, usl_contact_count), LBL_FAILED);
		uint64_t ull_frame_offset = 0;
		HL_GR_RET_GOTO(m_gw_write_8b_uint(&dsl_writer, ull_frame_offset), LBL_FAILED);

		uint16_t usl_actual_contact_count = 0;
		for (uint16_t usl_contact=0; usl_contact<DVC_INPUT_MAX_CONTACTS; usl_contact++) {
			struct dsd_input_touch_contact* adsl_contact = &adsp_touch_frame->dsrc_touch_contacts[usl_contact];
			if (adsl_contact->boc_active == FALSE) {
				continue;
			}
			// If contactFlag includes UP, set as inactive.
			if ((adsl_contact->umc_contact_flags & DVC_INPUT_CONTACT_FLAG_UP) != 0) {
				adsl_contact->boc_active = FALSE;
			}
			uint16_t usl_fields_present = adsl_contact->usc_fields_present_flag;

			HL_GR_RET_GOTO(m_gw_write_uint8(&dsl_writer, adsl_contact->ucc_contact_id), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_2b_uint(&dsl_writer, usl_fields_present), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_4b_sint(&dsl_writer, adsl_contact->ilc_x_coord), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_4b_sint(&dsl_writer, adsl_contact->ilc_y_coord), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_4b_uint(&dsl_writer, adsl_contact->umc_contact_flags), LBL_FAILED);
			
			if ((usl_fields_present & DVC_INPUT_TOUCH_CONTACT_CONTACTRECT_PRESENT) != 0) {
				HL_GR_RET_GOTO(m_gw_write_2b_sint(&dsl_writer, adsl_contact->isc_contact_rect_left), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_2b_sint(&dsl_writer, adsl_contact->isc_contact_rect_top), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_2b_sint(&dsl_writer, adsl_contact->isc_contact_rect_right), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_2b_sint(&dsl_writer, adsl_contact->isc_contact_rect_bottom), LBL_FAILED);
			}
			
			if ((usl_fields_present & DVC_INPUT_TOUCH_CONTACT_ORIENTATION_PRESENT) != 0) {
				HL_GR_RET_GOTO(m_gw_write_4b_uint(&dsl_writer, adsl_contact->umc_orientation), LBL_FAILED);
			}
			
			if ((usl_fields_present & DVC_INPUT_TOUCH_CONTACT_PRESSURE_PRESENT) != 0) {
				HL_GR_RET_GOTO(m_gw_write_4b_uint(&dsl_writer, adsl_contact->umc_pressure), LBL_FAILED);
			}

			usl_actual_contact_count++;
			if (usl_actual_contact_count > usl_contact_count) {
				// Frame contains more active contacts than usc_contact_count
				goto LBL_FAILED;
			}
		}
	}


	// Write back phase
	HL_GR_RET_GOTO(m_gw_mark_end(&dsl_writer), LBL_FAILED);
	inl_writer_pos_end = m_gw_get_abs_pos(&dsl_writer);

	inl_num_bytes = inl_writer_pos_end - inl_writer_pos_start;

	uml_pdu_len = 6 + (inl_writer_pos_end - inl_writer_pos_start); // header size
	HL_GR_RET_GOTO(m_gw_mark_end(&dsl_writer_header), LBL_FAILED);
	inl_writer_pos_end = m_gw_get_abs_pos(&dsl_writer_header);
	HL_GR_RET_GOTO(m_gw_prepend_uint32_le(&dsl_writer_header, uml_pdu_len), LBL_FAILED);
	HL_GR_RET_GOTO(m_gw_prepend_uint16_le(&dsl_writer_header, DVC_INPUT_EVENTID_TOUCH), LBL_FAILED);
	HL_GR_RET_GOTO(m_svc_dynvc_prepend_data_header(&dsl_writer_header, adsp_input->dsc_common.dsc_channel_context.umc_channel_id), LBL_FAILED);
	HL_GR_RET_GOTO(m_gw_mark_start(&dsl_writer_header), LBL_FAILED);
	inl_writer_pos_start = m_gw_get_abs_pos(&dsl_writer_header);
	inl_num_bytes += inl_writer_pos_end - inl_writer_pos_start;
	m_gather3_list_release(&dsl_writer_header.dsc_fifo, adsp_fifo_out);
	m_gw_destroy(&dsl_writer_header);

	m_gather3_list_release(&dsl_writer.dsc_fifo, adsp_fifo_out);
	m_gw_destroy(&dsl_writer);

	return inl_num_bytes;

LBL_FAILED:
	return -1;
}
