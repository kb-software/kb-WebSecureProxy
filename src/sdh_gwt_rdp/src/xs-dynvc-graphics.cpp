
#include <hob-sdh-gwt-rdp-1.h>

#include <hob-datarw.h>
#include <hob-dynvc-common.h>
#include <hob-dynvc-graphics.h>
#include "hob-webterm-rdp-svc-dynvc.h"

//stuff required by hob-webterm-rdp-01.h
#include <stdint.h>
#include "hob-encry-1.h"
#include "hob-cd-record-1.h"
#include <hob-webterm-rdp-01.h>

#include <xs-tk-gather-tools-01.cpp>

//caps versions:
#define RDPGFX_CAPVERSION_8 0x00080004
#define RDPGFX_CAPVERSION_81 0x00080105
#define RDPGFX_CAPVERSION_10 0x000A0002
#define RDPGFX_CAPVERSION_102 0x000A0200
#define RDPGFX_CAPVERSION_103 0x000A0301

static enum ied_dynvc_result m_handle_event(void* avop_this, enum ied_dynvc_msg_type iep_type, struct dsd_dynvc_listener_event* adsp_event) {
	struct dsd_dvc_graphics* adsl_this = (struct dsd_dvc_graphics*)avop_this;
	struct dsd_gather_writer* adsl_gw_client = adsp_event->adsc_gw_client;
	//adsl_this->dsc_common.umc_channel_id = adsp_event->umc_channel_id;

	switch (iep_type) {
	case ied_create: {
		int inl_name_len = strlen(STR_DYNVC_NAME_EGFX);
		HL_GR_RET_GOTO(m_gw_write_hasn1(adsl_gw_client, adsp_event->umc_channel_id), LBL_FAILED);
		HL_GR_RET_GOTO(m_gw_write_hasn1(adsl_gw_client, inl_name_len), LBL_FAILED);
		HL_GR_RET_GOTO(m_gw_write_bytes(adsl_gw_client, STR_DYNVC_NAME_EGFX, inl_name_len), LBL_FAILED);
		break;
	}
	case ied_data:
	case ied_datafirst:
		HL_GR_RET_GOTO(m_gw_write_hasn1(adsl_gw_client, adsp_event->umc_channel_id), LBL_FAILED);
		HL_GR_RET_GOTO(m_gw_write_hasn1(adsl_gw_client, adsp_event->umc_packet_length), LBL_FAILED);
		if (iep_type == ied_datafirst) {
			HL_GR_RET_GOTO(m_gw_write_hasn1(adsl_gw_client, adsp_event->umc_total_length), LBL_FAILED);
		}
		//TODO: append payload without copying. this is just for a functional test
		dsd_gather_i_1_pos dsl_pos;
		m_gr_commit(adsp_event->adsc_reader, &dsl_pos);
		dsl_pos.adsc_gather->achc_ginp_cur = dsl_pos.achc_pos;
		HL_GR_RET_GOTO(m_gw_write_gather_list(adsl_gw_client, dsl_pos.adsc_gather, adsp_event->umc_packet_length), LBL_FAILED);
		break;
	case ied_close: {
		HL_GR_RET_GOTO(m_gw_write_hasn1(adsl_gw_client, adsp_event->umc_channel_id), LBL_FAILED);
		break;
	}
	default:
		break;
	}
	return ied_success;

LBL_FAILED:
	return ied_error;
}

void m_init_dvc_graphics(struct dsd_dynvc_context* adsp_drdynvc, struct dsd_dvc_graphics* adsp_dvc_graphics){
    adsp_dvc_graphics->dsc_common.adsc_svc = adsp_drdynvc;
    //adsp_dvc_graphics->dsc_common.umc_channel_id = (unsigned int)-1;
    //adsp_dvc_graphics->dsc_common.umc_se_version = 0;
    //adsp_dvc_graphics->dsc_common.umc_cl_version = RDPGFX_CAPVERSION_8;
	 adsp_dvc_graphics->dsc_common.dsc_channel_context.dsc_listener.avoc_context = adsp_dvc_graphics;
	 adsp_dvc_graphics->dsc_common.dsc_channel_context.dsc_listener.m_receive = &m_handle_event;
#if 0
    struct dsd_dynvc_listener dsc_listener;
    dsc_listener.achc_name = STR_DYNVC_NAME_EGFX;
    dsc_listener.avoc_context = adsp_dvc_graphics;
    dsc_listener.m_receive = &m_handle_event;

    m_register_listener(adsp_drdynvc, dsc_listener);
#endif
}
