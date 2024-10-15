#include <hob-sdh-gwt-rdp-1.h>

#include <hob-datarw.h>
#include <hob-dynvc-common.h>
#include <hob-dynvc-disp.h>
#include <hob-webterm-rdp-svc-dynvc.h>

#include <xs-tk-gather-tools-01.cpp>

static const uint32_t DISPLAYCONTROL_PDU_TYPE_CAPS = 0x00000005;
	
static enum ied_dynvc_result m_handle_event(void* avop_this, enum ied_dynvc_msg_type iep_type, struct dsd_dynvc_listener_event* adsp_event) {
	struct dsd_dvc_disp* adsl_this = (struct dsd_dvc_disp*)avop_this;
	struct dsd_gather_reader* adsl_reader = adsp_event->adsc_reader;
	struct dsd_gather_writer* adsl_gw_client = adsp_event->adsc_gw_client;
	//adsl_this->dsc_common.umc_channel_id = adsp_event->umc_channel_id;

	switch (iep_type) {
	case ied_create: {
		break;
	}
	case ied_data:
	case ied_datafirst: {
		uint32_t uml_type;
		uint32_t uml_length;
		HL_GR_RET_GOTO(m_gr_read_uint32_le(adsl_reader, &uml_type), LBL_READ_INCOMPLETE);
		HL_GR_RET_GOTO(m_gr_read_uint32_le(adsl_reader, &uml_length), LBL_READ_INCOMPLETE);
		switch(uml_type) {
		case DISPLAYCONTROL_PDU_TYPE_CAPS: {
			HL_GR_RET_GOTO(m_gr_read_uint32_le(adsl_reader, &adsl_this->umc_max_num_monitors), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_uint32_le(adsl_reader, &adsl_this->umc_max_monitor_area_factor_a), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_uint32_le(adsl_reader, &adsl_this->umc_max_monitor_area_factor_b), LBL_READ_INCOMPLETE);
			break;
		}
		default:
			goto LBL_FAILED;
		}
		break;
	}
	case ied_close: {
		break;
	}
	default:
		break;
	}
	return ied_success;

LBL_FAILED:
	return ied_error;
LBL_READ_INCOMPLETE:
	return ied_incomplete;
}


void m_init_dvc_disp(struct dsd_dynvc_context* adsp_drdynvc, struct dsd_dvc_disp* adsp_dvc_disp){
    adsp_dvc_disp->dsc_common.adsc_svc = adsp_drdynvc;
    //adsp_dvc_disp->dsc_common.umc_channel_id = (unsigned int)-1;
    //adsp_dvc_disp->dsc_common.umc_se_version = 0;
    //adsp_dvc_disp->dsc_common.umc_cl_version = 0;
	 adsp_dvc_disp->dsc_common.dsc_channel_context.dsc_listener.avoc_context = adsp_dvc_disp;
	 adsp_dvc_disp->dsc_common.dsc_channel_context.dsc_listener.m_receive = &m_handle_event;
#if 0
    struct dsd_dynvc_listener dsc_listener;
    dsc_listener.achc_name = STR_DYNVC_NAME_DISP;
    dsc_listener.avoc_context = adsp_dvc_disp;
    dsc_listener.m_receive = &m_handle_event;

    m_register_listener(adsp_drdynvc, dsc_listener);
#endif
}

int m_dvc_disp_process_command(
	struct dsd_dvc_disp* adsp_dvc_disp, struct dsd_workarea_allocator* adsp_wa_alloc, const struct dsd_dvc_input_command* adsp_command, struct dsd_gather_i_1_fifo* adsp_fifo_out)
{
	// Prepare writer
	struct dsd_gather_writer dsl_gw;
	m_gw_init(&dsl_gw, adsp_wa_alloc);
	{
		HL_GR_RET_GOTO(m_gw_mark_start(&dsl_gw), LBL_FAILED);
		int inl_writer_pos_start = m_gw_get_abs_pos(&dsl_gw);

		switch(adsp_command->umc_command) {
		case DVC_DISP_DISPLAYCONTROL_PDU_TYPE_MONITOR_LAYOUT: {
			int iml_pdu_length = 8 + 4 + 4 + adsp_command->dsc_monitor_layout.umc_num_monitors * 40;
			// write header
			HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, DVC_DISP_DISPLAYCONTROL_PDU_TYPE_MONITOR_LAYOUT), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, iml_pdu_length), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, 40), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsp_command->dsc_monitor_layout.umc_num_monitors), LBL_FAILED);
			for(int iml_i = 0; iml_i < adsp_command->dsc_monitor_layout.umc_num_monitors; iml_i++) {
				const dsd_monitor_def_ex* adsl_mon = &adsp_command->dsc_monitor_layout.adsrc_monitors[iml_i];
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_mon->imc_flags), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_sint32_le(&dsl_gw, adsl_mon->imc_left), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_sint32_le(&dsl_gw, adsl_mon->imc_top), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_mon->imc_width), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_mon->imc_height), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_mon->imc_physical_width), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_mon->imc_physical_height), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_mon->imc_orientation), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_mon->imc_desktop_scale_factor), LBL_FAILED);
				HL_GR_RET_GOTO(m_gw_write_uint32_le(&dsl_gw, adsl_mon->imc_device_scale_factor), LBL_FAILED);
			}
			break;
		}
		default:
			goto LBL_FAILED;
		}
		HL_GR_RET_GOTO(m_gw_mark_end(&dsl_gw), LBL_FAILED);
		int inl_num_bytes = m_gw_get_abs_pos(&dsl_gw);
		m_gather_fifo_init(adsp_fifo_out);
		m_gather3_list_release(&dsl_gw.dsc_fifo, adsp_fifo_out);
		m_gw_destroy(&dsl_gw);
	}
	return 0;
LBL_FAILED:
	m_gw_destroy(&dsl_gw);
	return -1;
}
