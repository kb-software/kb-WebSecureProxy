
// Source file for the implementation of the Remote Desktop Protocol: Dynamic Channel Virtual Channel Extension ([MS-RDPEDYC]).

/*===================
DEFINES
===================*/

#define DVC_CMD_CREATE          0x01
#define DVC_CMD_DATA_FIRST      0x02
#define DVC_CMD_DATA            0x03
#define DVC_CMD_CLOSE           0x04
#define DVC_CMD_CAPS            0x05
#define DVC_CMD_DATA_FIRST_COMP 0x06
#define DVC_CMD_DATA_COMP    0x07
#define DVC_CMD_SOFT_SYNC_REQ  0x08
#define DVC_CMD_SOFT_SYNC_RESP  0x09

#define DVC_CB_CH_ID_1      0x00
#define DVC_CB_CH_ID_2      0x01
#define DVC_CB_CH_ID_3      0x02
#define DVC_CB_CH_ID_4      0x03

/* 2.2.5.2 Soft-Sync Response PDU (DYNVC_SOFT_SYNC_RESPONSE) */

#define TUNNELTYPE_UDPFECR    0x00000001
#define TUNNELTYPE_UDPFECL      0x00000003

#define MAX_PDU_SIZE 1600
#define PDU_SPLIT_LIMIT 1590
#define MAX_MESSAGE 
#define MAX_CL_VERSION 1

#define DEBUG_DATA_RECEIVED 0

//#define SUPPORTS_SYNC // This is not as of yet supported.
/*===================
INCLUDES
===================*/

#include <hob-sdh-gwt-rdp-1.h>
#include <hob-tk-aux-tools-01.h>

#ifndef HL_UNIX
#include <windows.h>
#else
#include <sys/types.h>
#include <errno.h>
#include <hob-unix01.h>
#endif // HL_UNIX

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <hob-datarw.h>
#include <hob-webterm-rdp-svc-dynvc.h>
#include <hob-dynvc-common.h>

//stuff required by hob-webterm-rdp-01.h
#include <stdint.h>
#include "hob-encry-1.h"
#include "hob-cd-record-1.h"
#include <hob-webterm-rdp-01.h>

#include <xs-tk-gather-tools-01.cpp>

#ifndef HL_LONGLONG
#ifdef _WIN32
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif // _WIN32
#endif // HL_LONGLONG
#ifdef UNUSED
#error UNUSED macro already defined
#else
#if 1
#define UNUSED(x)
#else
#define UNUSED(x) x
#endif
#endif // UNUSED

#define HL_DYNVC_RET_GOTO(call, lbl_err, lbl_again, lbl_succ) do {\
	switch (call) {\
	case ied_error:\
		goto lbl_err;\
	case ied_incomplete:\
		goto lbl_again;\
	case ied_success:\
		goto lbl_succ;\
	default:\
		break;\
	}\
} while(0)

struct dsd_process_params {
	char chc_cmd;
	char chc_sp;
	char chc_cb_ch_id;
	struct dsd_gather_reader* adsc_reader;
	struct dsd_gather_writer* adsc_gw_server;
	struct dsd_gather_writer* adsc_gw_client;
	struct dsd_aux_helper* adsc_aux;
	int inc_reader_total_length;
	struct dsd_dynvc_command* adsc_dynvc_command;
};

static void* m_memget(struct dsd_aux_helper* adsp_aux, size_t unp_size) {
	void* avol_ret = NULL;
	if (FALSE == adsp_aux->amc_aux(adsp_aux->vpc_userfld, DEF_AUX_MEMGET, &avol_ret, unp_size)) {
		return NULL;
	}
	return avol_ret;
}

static BOOL m_memfree(struct dsd_aux_helper* adsp_aux, void** aavop_ptr) {
	return adsp_aux->amc_aux(adsp_aux->vpc_userfld, DEF_AUX_MEMFREE, aavop_ptr, 0);
}

static int m_string_equals(const char* achp_a, const char* achp_b) {
	if (achp_a == NULL || achp_b == NULL) {
		return FALSE;
	}
	size_t ill_len_a = strlen(achp_a);
	size_t ill_len_b = strlen(achp_b);
	if (ill_len_a != ill_len_b) {
		return FALSE;
	}
	return 0 == strncmp(achp_a, achp_b, ill_len_b);
}

// Parameters: ump_value: Value to generate flag for (Channel Id or Length) according to MS-DRDYNVC.pdf
// Return: Byte flag
static unsigned char m_get_size_flag(uint32_t ump_value) {
	if (ump_value > 0xFFFF)
		return DVC_CB_CH_ID_3; // Req 4 bytes
	if (ump_value > 0xFF)
		return DVC_CB_CH_ID_2; // Req 2 bytes
	return DVC_CB_CH_ID_1;
}

// Parameters: ump_flag: Flag to calculate length for
// Return: Length in bytes taken up by value represented by ump_flag
static char m_get_size_from_flag(unsigned char ucp_flag) {
	if (ucp_flag == DVC_CB_CH_ID_1)
		return 1;
	if (ucp_flag == DVC_CB_CH_ID_2)
		return 2;
	if (ucp_flag == DVC_CB_CH_ID_3 || ucp_flag == DVC_CB_CH_ID_4)
		return 4;
	return -1;
}

static BOOL m_write_variable_length_field(struct dsd_gather_writer* adsp_writer, uint32_t ump_value) {
	unsigned char ucl_size_flag = m_get_size_flag(ump_value);
	char cl_size = m_get_size_from_flag(ucl_size_flag);

	switch(cl_size) {
	case 1:
		return m_gw_write_uint8(adsp_writer, ump_value & 0xFF);
	case 2:
		return m_gw_write_uint16_le(adsp_writer, ump_value & 0xFFFF);
	case 4:
		return m_gw_write_uint32_le(adsp_writer, ump_value);
	}
}

static BOOL m_prepend_variable_length_field(struct dsd_gather_writer* adsp_writer, uint32_t ump_value) {
	unsigned char ucl_size_flag = m_get_size_flag(ump_value);
	char cl_size = m_get_size_from_flag(ucl_size_flag);

	switch(cl_size) {
	case 1:
		return m_gw_prepend_byte(adsp_writer, ump_value & 0xFF);
	case 2:
		return m_gw_prepend_uint16_le(adsp_writer, ump_value & 0xFFFF);
	case 4:
		return m_gw_prepend_uint32_le(adsp_writer, ump_value);
	}
}

static BOOL m_read_variable_length_field(struct dsd_gather_reader* adsp_gather_reader, unsigned char ucp_flag, unsigned int* aunp_out) {
	int inl_chl_id_size = m_get_size_from_flag(ucp_flag);
	switch(inl_chl_id_size) {
	case 1: {
		uint8_t inl_tmp;
		if (!m_gr_read_uint8(adsp_gather_reader, &inl_tmp))
			return FALSE;
		*aunp_out = inl_tmp;
		break;
	}
	case 2: {
		uint16_t usl_tmp;
		if(!m_gr_read_uint16_le(adsp_gather_reader, &usl_tmp))
			return FALSE;
		*aunp_out = usl_tmp;
		break;
	}
	case 4: {
		uint32_t uml_tmp;
		if(!m_gr_read_uint32_le(adsp_gather_reader, &uml_tmp))
			return FALSE;
		*aunp_out = uml_tmp;
		break;
	}
	default:
		return FALSE;
	}
	return TRUE;
}

BOOL m_gw_write_hasn1(struct dsd_gather_writer* adsp_writer, int inp_number) {
	uint8_t usl_buf[5];
	int inl_size = m_out_nhasn1((char*)usl_buf, inp_number);
	switch(inl_size) {
	case 1:
		HL_GR_RET_GOTO(m_gw_write_uint8(adsp_writer, usl_buf[0]), LBL_FAILED);
		break;
	case 2:
		HL_GR_RET_GOTO(m_gw_write_uint8(adsp_writer, usl_buf[0]), LBL_FAILED);
		HL_GR_RET_GOTO(m_gw_write_uint8(adsp_writer, usl_buf[1]), LBL_FAILED);
		break;
	case 3:
		HL_GR_RET_GOTO(m_gw_write_uint8(adsp_writer, usl_buf[0]), LBL_FAILED);
		HL_GR_RET_GOTO(m_gw_write_uint8(adsp_writer, usl_buf[1]), LBL_FAILED);
		HL_GR_RET_GOTO(m_gw_write_uint8(adsp_writer, usl_buf[2]), LBL_FAILED);
		break;
	case 4:
		HL_GR_RET_GOTO(m_gw_write_uint8(adsp_writer, usl_buf[0]), LBL_FAILED);
		HL_GR_RET_GOTO(m_gw_write_uint8(adsp_writer, usl_buf[1]), LBL_FAILED);
		HL_GR_RET_GOTO(m_gw_write_uint8(adsp_writer, usl_buf[2]), LBL_FAILED);
		HL_GR_RET_GOTO(m_gw_write_uint8(adsp_writer, usl_buf[3]), LBL_FAILED);
		break;
	case 5:
		HL_GR_RET_GOTO(m_gw_write_uint8(adsp_writer, usl_buf[0]), LBL_FAILED);
		HL_GR_RET_GOTO(m_gw_write_uint8(adsp_writer, usl_buf[1]), LBL_FAILED);
		HL_GR_RET_GOTO(m_gw_write_uint8(adsp_writer, usl_buf[2]), LBL_FAILED);
		HL_GR_RET_GOTO(m_gw_write_uint8(adsp_writer, usl_buf[3]), LBL_FAILED);
		HL_GR_RET_GOTO(m_gw_write_uint8(adsp_writer, usl_buf[4]), LBL_FAILED);
		break;
	}
	return TRUE;
LBL_FAILED:
	return FALSE;
}

static void m_init_channel(struct dsd_channel_context* adsp_channel, unsigned long ulp_id, unsigned short usp_priority) {
#if MH_DYNVC_USE_AVL_TREE
	// Set the sort entry
	memset(&adsp_channel->dsc_sort, 0x0, sizeof(adsp_channel->dsc_sort));
#endif
	adsp_channel->umc_channel_id = ulp_id;
	adsp_channel->usc_priority = usp_priority;
}

#if MH_DYNVC_USE_AVL_TREE
// NOTE: Compare function for AVL tree. Compares by channel id.
static int m_cmp_channels(void* UNUSED(ap_option), struct dsd_htree1_avl_entry* adsp_entry_1, struct dsd_htree1_avl_entry* adsp_entry_2 ) {
	struct dsd_channel_context *adsl_dvc_1, *adsl_dvc_2;
	adsl_dvc_1 = (struct dsd_channel_context *) ((char *) adsp_entry_1 - offsetof(struct dsd_channel_context, dsc_sort));
	adsl_dvc_2 = (struct dsd_channel_context *) ((char *) adsp_entry_2 - offsetof(struct dsd_channel_context, dsc_sort));

	if (adsl_dvc_1->umc_channel_id > adsl_dvc_2->umc_channel_id)
		return 1;
	if (adsl_dvc_1->umc_channel_id < adsl_dvc_2->umc_channel_id)
		return -1;
	return 0;
}
#endif

static BOOL m_insert_channel(struct dsd_dynvc_context* adsp_drdynvc, dsd_channel_context* adsp_channel) {
#if MH_DYNVC_USE_AVL_TREE
	struct dsd_htree1_avl_work dsl_htree1_work;
	BOOL bol_ret = m_htree1_avl_search(NULL, &adsp_drdynvc->dsc_htree1_avl_cntl_channels, &dsl_htree1_work, &adsp_channel->dsc_sort); 
	if (!bol_ret) {
		return FALSE; // Error: Search Failed.
	}
	bol_ret = m_htree1_avl_insert(NULL, &adsp_drdynvc->dsc_htree1_avl_cntl_channels, &dsl_htree1_work, &adsp_channel->dsc_sort);
	if (!bol_ret) {
		return FALSE; // Error: Search Failed.
	}
#else
	if (adsp_drdynvc->inc_active_channels_count == INS_MAX_DYNAMIC_CHANNELS) {
		for (int inl_i = 0; inl_i < adsp_drdynvc->inc_active_channels_count; inl_i++) {
			struct dsd_channel_context* adsl_channel = adsp_drdynvc->adsrc_channels[inl_i];
			if (adsl_channel == NULL) {
				adsp_drdynvc->adsrc_channels[inl_i] = adsp_channel;
				return true;
			}
		}
		return FALSE;
	}
	adsp_drdynvc->adsrc_channels[adsp_drdynvc->inc_active_channels_count] = adsp_channel;
	adsp_drdynvc->inc_active_channels_count++;
#endif
	return TRUE;
}

// Parameters: ump_cid: ID of requested channel.
// Return: On Channel Not Found/Error: 0, On Success: Pointer to requested DVC
static struct dsd_channel_context* m_get_channel(struct dsd_dynvc_context* adsp_drdynvc, unsigned int ump_cid) {
#if MH_DYNVC_USE_AVL_TREE
	struct dsd_channel_context dsl_dvc;
	memset(&dsl_dvc.dsc_sort, 0, sizeof(struct dsd_htree1_avl_entry));
	dsl_dvc.umc_channel_id = ump_cid;

	struct dsd_htree1_avl_work dsl_htree1_work;
	int inl_status = m_htree1_avl_search(NULL, &adsp_drdynvc->dsc_htree1_avl_cntl_channels, &dsl_htree1_work, &dsl_dvc.dsc_sort); 
	if (inl_status == FALSE) {
		return NULL; // Error: Search Failed.
	}
	if (dsl_htree1_work.adsc_found == NULL) {
		return NULL;
	}
	// Return the channel address
	struct dsd_channel_context *adsl_dvc;
	adsl_dvc = (struct dsd_channel_context *) ((char *) dsl_htree1_work.adsc_found - offsetof(struct dsd_channel_context, dsc_sort));
	return adsl_dvc;
#else
	for (int inl_i = 0; inl_i < adsp_drdynvc->inc_active_channels_count; inl_i++) {
		struct dsd_channel_context* adsl_channel = adsp_drdynvc->adsrc_channels[inl_i];
		if (adsl_channel != NULL && adsl_channel->umc_channel_id == ump_cid) {
			return adsl_channel;
		}
	}
	return NULL;
#endif
}

// Return: On Fail: 0/-1, On Success: 1
static int m_remove_channel(struct dsd_dynvc_context* adsp_drdynvc, struct dsd_channel_context* adsp_channel) {
#if MH_DYNVC_USE_AVL_TREE
	struct dsd_htree1_avl_work dsl_htree1_work;
	BOOL inl_status = m_htree1_avl_search(NULL, &adsp_drdynvc->dsc_htree1_avl_cntl_channels, &dsl_htree1_work, &adsp_channel->dsc_sort); 
	if (inl_status == FALSE)
		return -1; // Error: Search Failed.
	if (dsl_htree1_work.adsc_found == NULL) {
		return 0;
	}
	// Delete the channel found
	inl_status = m_htree1_avl_delete( NULL, &adsp_drdynvc->dsc_htree1_avl_cntl_channels, &dsl_htree1_work);
	if (inl_status == FALSE) {
		return -1;
	}
	memset(&adsp_channel->dsc_sort, 0, sizeof(struct dsd_htree1_avl_entry));
	return 1; // Success
#else
	for (int inl_i = 0; inl_i < adsp_drdynvc->inc_active_channels_count; inl_i++) {
		struct dsd_channel_context* adsl_channel = adsp_drdynvc->adsrc_channels[inl_i];
		if (adsl_channel == adsp_channel) {
			adsp_drdynvc->adsrc_channels[inl_i] = NULL;
			if (inl_i == adsp_drdynvc->inc_active_channels_count - 1) {
				adsp_drdynvc->inc_active_channels_count = inl_i;
			}
			return 1;
		}
	}
	return 0;
#endif
}

// Return: On Fail: 0/-1, On Success: 1
static int m_remove_channel(struct dsd_dynvc_context* adsp_drdynvc, unsigned int ump_cid) {
	return m_remove_channel(adsp_drdynvc, m_get_channel(adsp_drdynvc, ump_cid));
}

static enum ied_dynvc_result m_process_data2(struct dsd_dynvc_context* adsp_drdynvc, struct dsd_process_params* adsp_params) {

	dsd_gather_reader* adsl_reader = adsp_params->adsc_reader;

	// Read ChannelId from message
	unsigned int uml_channel_id;
	if (!m_read_variable_length_field(adsl_reader, adsp_params->chc_cb_ch_id, &uml_channel_id)) {
		return ied_incomplete;
	}
#if DEBUG_DATA_RECEIVED
	adsp_drdynvc->amc_sdh_printf(adsp_drdynvc->avoc_context, "Received data for: channel %d\n", uml_channel_id);
#endif

	// Get the respective DVC channel
	struct dsd_channel_context* adsl_channel = m_get_channel(adsp_drdynvc, uml_channel_id);
	if (adsl_channel == NULL) {
		return ied_error;
	}

	enum ied_dynvc_msg_type iel_type = ied_invalid;
	struct dsd_dynvc_listener_event dsl_event;
	dsl_event.umc_channel_id = uml_channel_id;
	dsl_event.adsc_reader = adsp_params->adsc_reader;
	dsl_event.adsc_gw_client = adsp_params->adsc_gw_client;
	dsl_event.adsc_gw_server = adsp_params->adsc_gw_server;
	dsl_event.adsc_dynvc_command = adsp_params->adsc_dynvc_command;

	switch (adsp_params->chc_cmd) {
	case DVC_CMD_DATA: {
		iel_type = ied_data;
		dsl_event.umc_packet_length = adsp_params->inc_reader_total_length - m_gr_get_abs_position(adsl_reader);
		if (dsl_event.umc_packet_length > MAX_PDU_SIZE - (1 + m_get_size_from_flag(adsp_params->chc_cb_ch_id))) {
			// more input data available than maximum pdu size
			return ied_error;
		}
		break;
	}
	case DVC_CMD_DATA_FIRST: {
		iel_type = ied_datafirst;

		unsigned int unl_total_length;
		if (!m_read_variable_length_field(adsl_reader, adsp_params->chc_sp, &unl_total_length)) {
			return ied_incomplete;
		}
		dsl_event.umc_total_length = unl_total_length;

		unsigned int unl_dvc_header_size = 1 + m_get_size_from_flag(adsp_params->chc_sp) + m_get_size_from_flag(adsp_params->chc_cb_ch_id);
		if (unl_dvc_header_size + unl_total_length < MAX_PDU_SIZE) {
			/* If the sum of the DVC header size and the value specified by the Length field is less than 
			   1,600 bytes, then the actual data length equals the value specified by the Length field. */
			dsl_event.umc_packet_length = unl_total_length;
		} else {
			/* If the sum of the DVC header size and the value specified by the Length field is equal to or
			   larger than 1,600 bytes, then the actual data length equals 1,600 bytes minus the DVC header
			   size. */
			dsl_event.umc_packet_length = MAX_PDU_SIZE - unl_dvc_header_size;
		}
		
		if (dsl_event.umc_packet_length < adsp_params->inc_reader_total_length - m_gr_get_abs_position(adsl_reader)) {
			return ied_incomplete;
		}
		break;
	}
	default:
		return ied_error;
	}

	struct dsd_dynvc_listener* adsl_listener = &adsl_channel->dsc_listener;
	return adsl_listener->m_receive(adsl_listener->avoc_context, iel_type, &dsl_event);
}

// Return: On Fail: -1, On Success: 0
int m_register_listener(struct dsd_dynvc_context *adsp_drdynvc, struct dsd_dynvc_create_listener* adsp_listener) {
	if (adsp_drdynvc->inc_listeners_count + 1 < DVC_MAX_LISTENERS) {
		adsp_drdynvc->dsrc_active_listeners[adsp_drdynvc->inc_listeners_count] = adsp_listener;
		adsp_drdynvc->inc_listeners_count++;
		int inl_name_length = strlen(adsp_listener->achc_name);
		if (inl_name_length > adsp_drdynvc->inc_dynvc_max_name_length) {
			adsp_drdynvc->inc_dynvc_max_name_length = inl_name_length;
		}
		return 0;
	}
	return -1;
}

// Parameters: achp_name: Name of requested listener.
// Return: On Channel Not Found: 0, On Success: Pointer to requested DVC listener
static struct dsd_dynvc_create_listener* m_get_listener(struct dsd_dynvc_context* adsp_drdynvc, const char* achp_name) {
	for (int inl1 = 0; inl1 < adsp_drdynvc->inc_listeners_count; inl1++) {
		struct dsd_dynvc_create_listener* adsl_listener  = adsp_drdynvc->dsrc_active_listeners[inl1];

		int inl_compare = strcmp(adsl_listener->achc_name, achp_name);
		if (inl_compare == 0) {
			return adsl_listener;
		}
	}
	return NULL; // Warning: Listener Not Found.
}


static enum ied_dynvc_result m_process_create(struct dsd_dynvc_context* adsp_drdynvc, struct dsd_process_params* adsp_params) {


	// copied from JWT4.1 hob.rdp.c_vcdrdynvc
	static const HRESULT E_SUCCESS = 0;
#ifdef HL_UNIX
	static const HRESULT E_FAIL = 0x80000008;
#endif

	HRESULT dsl_creation_status = E_FAIL;
	struct dsd_gather_reader* adsl_reader = adsp_params->adsc_reader;
	struct dsd_gather_writer* adsl_gw_server = adsp_params->adsc_gw_server;
	unsigned short usl_priority = 0;
	struct dsd_channel_context* adsl_channel = NULL;
	const int inl_bufsize = adsp_drdynvc->inc_dynvc_max_name_length + 1;
	static const int ins_max_bufsize = 4096;
	if (inl_bufsize > ins_max_bufsize) {
		// cannot create channel with name longer than 4096 bytes
		return ied_error;
	}
	char chrl_name_buf[ins_max_bufsize];
	struct dsd_dynvc_create_listener* adsl_listener = NULL;

	// Read ChannelId from message
	unsigned int uml_channel_id = 0;
	if (!m_read_variable_length_field(adsl_reader, adsp_params->chc_cb_ch_id, &uml_channel_id)) {
		return ied_incomplete;
	}
	unsigned char ucl_cb_ch_id = m_get_size_flag(uml_channel_id);
	char ucl_header = (DVC_CMD_CREATE << 4) | (0x00 << 2) | (ucl_cb_ch_id & 0x03);

	if (m_get_channel(adsp_drdynvc, uml_channel_id)) {
		goto LBL_PROTOCOL_ERROR; // Error: Channel already in use
	}

	if (!m_gr_read_string(adsl_reader, chrl_name_buf, inl_bufsize)) {
		return ied_incomplete;
	}
#if DEBUG_DATA_RECEIVED
	adsp_drdynvc->amc_sdh_printf(adsp_drdynvc->avoc_context, "Received create for: channel %d name: %s\n", uml_channel_id, chrl_name_buf);
#endif
	adsl_listener = m_get_listener(adsp_drdynvc, chrl_name_buf);
	if (adsl_listener == NULL) {
		goto LBL_PROTOCOL_ERROR; // Error: Listener not found
	}

	// Create the channel and add it to the list of active channels.
	struct dsd_dynvc_create_context dsl_create_context;
	dsl_create_context.adsc_drdynvc = adsp_drdynvc;
	adsl_channel = adsl_listener->m_create(adsl_listener, &dsl_create_context);
	if (adsl_channel == NULL) {
		return ied_error;
	}
	if (adsl_channel->adsc_parent != NULL) {
		return ied_error;
	}
	adsl_channel->adsc_parent = adsp_drdynvc;
	// Set priority charge for channel if the protocol version is 2
	if (adsp_drdynvc->usc_cl_version == 2) {
		usl_priority = adsp_params->chc_sp;  
	}
	m_init_channel(adsl_channel, uml_channel_id, usl_priority);
	if (FALSE == m_insert_channel(adsp_drdynvc, adsl_channel)) {
		return ied_error;
	}

	struct dsd_dynvc_listener_event dsl_event;
	dsl_event.umc_channel_id = uml_channel_id;
	dsl_event.umc_packet_length = 0;
	dsl_event.umc_total_length = 0;
	dsl_event.adsc_reader = adsl_reader;
	dsl_event.adsc_gw_client = adsp_params->adsc_gw_client;
	dsl_event.adsc_gw_server = NULL;
	dsl_event.adsc_dynvc_command = adsp_params->adsc_dynvc_command;

	HL_DYNVC_RET_GOTO(adsl_channel->dsc_listener.m_receive(
		adsl_channel->dsc_listener.avoc_context, ied_create, &dsl_event), LBL_RETURN, LBL_READ_INCOMPLETE, LBL_SUCCESS);
	
LBL_SUCCESS:
	dsl_creation_status = E_SUCCESS;

LBL_PROTOCOL_ERROR:
	// Write DYNVC_CREATE_RSP
	HL_GR_RET_GOTO(m_gw_write_uint8(adsl_gw_server, ucl_header), LBL_RETURN);
	HL_GR_RET_GOTO(m_write_variable_length_field(adsl_gw_server, uml_channel_id), LBL_RETURN);
	HL_GR_RET_GOTO(m_gw_write_uint32_le(adsl_gw_server, dsl_creation_status), LBL_RETURN);
	return ied_success;
LBL_READ_INCOMPLETE:
	return ied_incomplete;
LBL_RETURN:
	return ied_error;
}

static enum ied_dynvc_result m_process_close(struct dsd_dynvc_context* adsp_drdynvc, struct dsd_process_params* adsp_params) {
	struct dsd_gather_reader* adsl_reader = adsp_params->adsc_reader;

	// Read ChannelId from message
	unsigned int uml_channel_id = 0;
	if (!m_read_variable_length_field(adsl_reader, adsp_params->chc_cb_ch_id, &uml_channel_id)) {
		return ied_incomplete;
	}

#if DEBUG_DATA_RECEIVED
	adsp_drdynvc->amc_sdh_printf(adsp_drdynvc->avoc_context, "Received close for channel: %d\n", uml_channel_id);
#endif
	struct dsd_channel_context* adsl_channel = m_get_channel(adsp_drdynvc, uml_channel_id);
	if (adsl_channel == NULL) {
		//if we have not opened the channel ignore the close request
		return ied_success;
	}

	int inl_status = m_remove_channel(adsp_drdynvc, adsl_channel);
	if (inl_status <= 0) {
		return ied_error;
	}
	memset(&adsl_channel->dsc_listener, 0, sizeof(adsl_channel->dsc_listener));
	adsl_channel->adsc_parent = NULL;
	//TODO forward close to client if needed
	return ied_success;
}

static enum ied_dynvc_result m_process_caps(struct dsd_dynvc_context* adsp_drdynvc, struct dsd_process_params* adsp_params) {
	struct dsd_gather_reader* adsl_reader = adsp_params->adsc_reader;
	struct dsd_gather_writer* adsl_writer = adsp_params->adsc_gw_server;
	if (adsp_params->chc_cb_ch_id != 0x00)
		return ied_error; // Error: Unused. MUST be set to 0x00.

	uint8_t inl_pad = 0;
	if (!m_gr_read_uint8(adsl_reader, &inl_pad)) {
		return ied_incomplete;
	}
	if (inl_pad != 0x00) {
		return ied_error; // Error: An 8-bit unsigned integer. Unused. MUST be set to 0x00.
	}

	uint16_t uml_version = 0;
	if (!m_gr_read_uint16_le(adsl_reader, &uml_version)) {
		return ied_incomplete;
	}
	adsp_drdynvc->usc_se_version = uml_version;

	switch (adsp_drdynvc->usc_se_version) {
	case 0x0001:
		break;
	case 0x0002:
	case 0x0003: {
		uint16_t uml_tmp = 0;
		if (!m_gr_read_uint16_le(adsl_reader, &uml_tmp)) { return ied_incomplete; }
		adsp_drdynvc->usc_priority_charge_0 = uml_tmp;
		if (!m_gr_read_uint16_le(adsl_reader, &uml_tmp)) { return ied_incomplete; }
		adsp_drdynvc->usc_priority_charge_1 = uml_tmp;
		if (!m_gr_read_uint16_le(adsl_reader, &uml_tmp)) { return ied_incomplete; }
		adsp_drdynvc->usc_priority_charge_2 = uml_tmp;
		if (!m_gr_read_uint16_le(adsl_reader, &uml_tmp)) { return ied_incomplete; }
		adsp_drdynvc->usc_priority_charge_3 = uml_tmp;
		break;
	}
	default:
		return ied_error; // Error: Invalid version number.
	}

#if DEBUG_DATA_RECEIVED
	adsp_drdynvc->amc_sdh_printf(adsp_drdynvc->avoc_context, "Received caps");
#endif
	adsp_drdynvc->usc_cl_version = ((adsp_drdynvc->usc_se_version > MAX_CL_VERSION) ? MAX_CL_VERSION : adsp_drdynvc->usc_se_version);

	// Write caps response
	// header
	static const char ucl_header = (DVC_CMD_CAPS << 4) | (0x00 << 2) | DVC_CB_CH_ID_1;
	HL_GR_RET_GOTO(m_gw_write_uint8(adsl_writer, ucl_header), LBL_FAILED);
	static char ucl_pad = 0x0;
	HL_GR_RET_GOTO(m_gw_write_uint8(adsl_writer, ucl_pad), LBL_FAILED);
	HL_GR_RET_GOTO(m_gw_write_uint16_le(adsl_writer, MAX_CL_VERSION), LBL_FAILED);
	
	return ied_success;

LBL_FAILED:
	return ied_error;
}

void m_dynvc_command_init(struct dsd_dynvc_command* adsp_cmd) {
	adsp_cmd->adsc_data_to_server = NULL;
	adsp_cmd->adsc_data_to_client = NULL;
	adsp_cmd->umc_to_server_length_total = 0;
	adsp_cmd->umc_to_server_length_current = 0;
	adsp_cmd->umc_to_client_length = 0;
	adsp_cmd->ucc_record_type = ie_wtsc_rdp_dynchannel_cmd_none;
}

int m_svc_dynvc_receive_message(struct dsd_dynvc_context* adsp_context,
	struct dsd_aux_helper* adsp_aux, struct dsd_rdp_vch_io* adsp_in_message, struct dsd_dynvc_command* adsp_output_command)
{
	int inl_num_bytes_client = 0;
	int inl_num_bytes_server = 0;
	unsigned int unl_record_type = ie_wtsc_rdp_dynchannel_cmd_none;
	int inl_reader_total_length = 0;

	m_dynvc_command_init(adsp_output_command);

	// Prepare writer
	struct dsd_workarea_allocator dsl_wa_alloc;
	m_wa_allocator_init(&dsl_wa_alloc);
	dsl_wa_alloc.adsc_aux = adsp_aux;

	struct dsd_gather_writer dsl_gw_server;
	m_gw_init(&dsl_gw_server, &dsl_wa_alloc);
	HL_GR_RET_GOTO(m_gw_mark_start(&dsl_gw_server), LBL_FAILED);
	struct dsd_gather_writer dsl_gw_client;
	m_gw_init(&dsl_gw_client, &dsl_wa_alloc);
	HL_GR_RET_GOTO(m_gw_mark_start(&dsl_gw_client), LBL_FAILED);

	// Prepare reader
	struct dsd_gather_i_1_fifo dsl_fifo;
	m_gather_fifo_init(&dsl_fifo);
	if(adsp_context->dsc_fifo.adsc_first != NULL) {
		m_gather_fifo_foreach(&adsp_context->dsc_fifo, &m_gather_i_1_ref_dec, adsp_aux);
		m_gather_fifo_append_fifo(&dsl_fifo, &adsp_context->dsc_fifo);
	}
	// append new data
	m_gather_fifo_append_list2(&dsl_fifo, adsp_in_message->adsc_gai1_data);

	// count total data size
	inl_reader_total_length = m_gather_i_1_count_data_len(dsl_fifo.adsc_first);
	
	struct dsd_gather_reader dsl_gather_reader;
	m_gr_init(&dsl_gather_reader, &dsl_fifo);
	struct dsd_gather_i_1_pos dsl_lookahead_pos;

	// Start lookahead mode
	HL_GR_RET_GOTO(m_gr_begin_lookahead(&dsl_gather_reader, &dsl_lookahead_pos), LBL_FAILED);

	// Start parsing
	uint8_t inl_header;
	HL_GR_RET_GOTO(m_gr_read_uint8(&dsl_gather_reader, &inl_header), LBL_READ_INCOMPLETE);

	struct dsd_process_params dsl_params;
	dsl_params.chc_cmd = (inl_header & 0xF0) >> 4;
	dsl_params.chc_sp = (inl_header & 0x0C) >> 2;
	dsl_params.chc_cb_ch_id = inl_header & 0x03;
	dsl_params.adsc_reader = &dsl_gather_reader;
	dsl_params.adsc_gw_client = &dsl_gw_client;
	dsl_params.adsc_gw_server = &dsl_gw_server;
	dsl_params.adsc_aux = adsp_aux;
	dsl_params.inc_reader_total_length = inl_reader_total_length;
	dsl_params.adsc_dynvc_command = adsp_output_command;

	switch (dsl_params.chc_cmd) {
	case DVC_CMD_CREATE:
		unl_record_type = ie_wtsc_rdp_dynchannel_create;
		HL_DYNVC_RET_GOTO(m_process_create(adsp_context, &dsl_params), LBL_FAILED, LBL_READ_INCOMPLETE, LBL_SUCCESS);
		// never reached
		break;
	case DVC_CMD_DATA_FIRST:
		unl_record_type = ie_wtsc_rdp_dynchannel_datafirst;
		HL_DYNVC_RET_GOTO(m_process_data2(adsp_context, &dsl_params), LBL_FAILED, LBL_READ_INCOMPLETE, LBL_SUCCESS);
		// never reached
		break;
	case DVC_CMD_DATA:
		unl_record_type = ie_wtsc_rdp_dynchannel_data;
		HL_DYNVC_RET_GOTO(m_process_data2(adsp_context, &dsl_params), LBL_FAILED, LBL_READ_INCOMPLETE, LBL_SUCCESS);
		// never reached
		break;
	case DVC_CMD_CLOSE:
		unl_record_type = ie_wtsc_rdp_dynchannel_close;
		HL_DYNVC_RET_GOTO(m_process_close(adsp_context, &dsl_params), LBL_FAILED, LBL_READ_INCOMPLETE, LBL_SUCCESS);
		// never reached
		break;
	case DVC_CMD_CAPS:
		HL_DYNVC_RET_GOTO(m_process_caps(adsp_context, &dsl_params), LBL_FAILED, LBL_READ_INCOMPLETE, LBL_SUCCESS);
		// never reached
		break;
	case DVC_CMD_DATA_FIRST_COMP:
	case DVC_CMD_DATA_COMP:
	case DVC_CMD_SOFT_SYNC_REQ:
	default:
		goto LBL_FAILED;
	}

LBL_SUCCESS:
	// Write back phase
	HL_GR_RET_GOTO(m_gw_mark_end(&dsl_gw_server), LBL_FAILED);
	inl_num_bytes_server = m_gw_get_abs_pos(&dsl_gw_server);
	if (inl_num_bytes_server > 0) {
		struct dsd_gather_i_1_fifo dsl_fifo_out;
		m_gather_fifo_init(&dsl_fifo_out);
		m_gather3_list_release(&dsl_gw_server.dsc_fifo, &dsl_fifo_out);
		adsp_output_command->adsc_data_to_server = dsl_fifo_out.adsc_first;
		adsp_output_command->umc_to_server_length_total = inl_num_bytes_server;
		adsp_output_command->umc_to_server_length_current = inl_num_bytes_server;
	}
	m_gw_destroy(&dsl_gw_server);

	HL_GR_RET_GOTO(m_gw_mark_end(&dsl_gw_client), LBL_FAILED);
	inl_num_bytes_client = m_gw_get_abs_pos(&dsl_gw_client);
	if (inl_num_bytes_client > 0) {
		struct dsd_gather_i_1_fifo dsl_fifo_out;
		m_gather_fifo_init(&dsl_fifo_out);
		m_gather3_list_release(&dsl_gw_client.dsc_fifo, &dsl_fifo_out);
		adsp_output_command->adsc_data_to_client = dsl_fifo_out.adsc_first;
		adsp_output_command->umc_to_client_length = inl_num_bytes_client;
		adsp_output_command->ucc_record_type = unl_record_type;
	}
	m_gw_destroy(&dsl_gw_client);
	
	m_wa_allocator_destroy(&dsl_wa_alloc);

	// End lookahead mode
	HL_GR_RET_GOTO(m_gr_end_lookahead(&dsl_gather_reader, &dsl_lookahead_pos), LBL_FAILED);
	dsd_gather_i_1_pos dsl_pos;
	m_gr_commit(&dsl_gather_reader, &dsl_pos);

	return ied_success;
LBL_READ_INCOMPLETE:
	if((adsp_in_message->chrc_vch_flags[0] & CHANNEL_FLAG_LAST) != 0) {
		goto LBL_FAILED;
	}
	// keep incomplete input data
	m_gather_fifo_init(&adsp_context->dsc_fifo);
	m_gather_fifo_append_fifo(&adsp_context->dsc_fifo, &dsl_fifo);
	m_gather_fifo_foreach(&adsp_context->dsc_fifo, &m_gather_i_1_ref_inc, adsp_aux);
	return ied_incomplete;
LBL_FAILED:
	return ied_error;
}

void m_init_drdynvc(struct dsd_dynvc_context* adsp_drdynvc) {
	static const char* achl_name = "drdynvc";
	memcpy(adsp_drdynvc->chrc_channel_name, achl_name, 8);
	// Do not set CHANNEL_OPTION_SHOW_PROTOCOL!
	// The static virtual channel DRDYNVC will not work if this flag is set.
	adsp_drdynvc->umc_options = CHANNEL_OPTION_INITIALIZED |  CHANNEL_OPTION_PRI_LOW;
	adsp_drdynvc->inc_listeners_count = 0;
	adsp_drdynvc->inc_dynvc_max_name_length = 64;
#if MH_DYNVC_USE_AVL_TREE
	m_htree1_avl_init(NULL, &adsp_drdynvc->dsc_htree1_avl_cntl_channels, &m_cmp_channels);
#else
	adsp_drdynvc->inc_active_channels_count = 0;
#endif
}

BOOL m_svc_dynvc_write_data_header(struct dsd_gather_writer* adsp_writer, uint32_t ump_channel_id) {
	unsigned char ucl_channel_id_size_flag = m_get_size_flag(ump_channel_id);
	char cl_header_size = m_get_size_from_flag(ucl_channel_id_size_flag);
	// header
	uint8_t uchl_header = (DVC_CMD_DATA << 4) | (0x00 << 2) | (ucl_channel_id_size_flag & 0x03);
	HL_GR_RET_GOTO(m_gw_write_uint8(adsp_writer, uchl_header), LBL_FAILED);
	HL_GR_RET_GOTO(m_write_variable_length_field(adsp_writer, ump_channel_id), LBL_FAILED);
	return TRUE;
LBL_FAILED:
	return FALSE;
}

BOOL m_svc_dynvc_prepend_data_header(struct dsd_gather_writer* adsp_writer, uint32_t ump_channel_id) {
	unsigned char ucl_channel_id_size_flag = m_get_size_flag(ump_channel_id);
	char cl_header_size = m_get_size_from_flag(ucl_channel_id_size_flag);
	// header
	uint8_t uchl_header = (DVC_CMD_DATA << 4) | (0x00 << 2) | (ucl_channel_id_size_flag & 0x03);
	HL_GR_RET_GOTO(m_prepend_variable_length_field(adsp_writer, ump_channel_id), LBL_FAILED);
	HL_GR_RET_GOTO(m_gw_prepend_byte(adsp_writer, uchl_header), LBL_FAILED);
	return TRUE;
LBL_FAILED:
	return FALSE;
}

static int m_read_hasn1_uint32_be(uint32_t* aump_out, const char* achp_in, const char* achp_in_end) {
	uint32_t uml_out = 0;
	static const int inl_max_iterations = 5;
	if (achp_in + inl_max_iterations < achp_in_end) {
		achp_in_end = achp_in + inl_max_iterations;
	}

	const char* achl_cur = achp_in;
	while (achl_cur < achp_in_end) {
		uml_out <<= 7;                /* shift old value         */
		uml_out |= (*achl_cur) & 0x7f;    /* apply new bits          */
		if ((*achl_cur & 0x80) == 0) {        /* more bit not set      */
			// the length is complete
			*aump_out = uml_out;
			return (achl_cur - achp_in) + 1;
		}
		achl_cur++;
	}
	return -1;
}

BOOL m_receive_client_data(struct dsd_dynvc_context* adsp_context, const char* achp_data_in, int inp_data_length, struct dsd_dynvc_client_command* adsp_cmd) {
	if (adsp_context == NULL || achp_data_in == NULL || adsp_cmd == NULL) {
		return FALSE;
	}

	//get channel id
	uint32_t uml_channel_id = 0;
	int inl_nbytes = m_read_hasn1_uint32_be(&uml_channel_id, achp_data_in, achp_data_in + inp_data_length);
	if (inl_nbytes < 0) {
		return FALSE;
	}
	achp_data_in += inl_nbytes;
	inp_data_length -= inl_nbytes;

	//get payload length
	uint32_t uml_datalen = 0;
	inl_nbytes = m_read_hasn1_uint32_be(&uml_datalen, achp_data_in, achp_data_in + inp_data_length);
	if (inl_nbytes < 0) {
		return FALSE;
	}
	achp_data_in += inl_nbytes;
	inp_data_length -= inl_nbytes;

	if (uml_datalen != inp_data_length) {
		return FALSE;
	}

	adsp_cmd->umc_channel_id = uml_channel_id;
	adsp_cmd->umc_payload_length = uml_datalen;
	adsp_cmd->achc_payload = achp_data_in;
	return TRUE;
}

int m_svc_dynvc_send_data(struct dsd_dynvc_context* adsp_context,
	struct dsd_aux_helper* adsp_aux, struct dsd_dynvc_client_command* adsp_cmd, struct dsd_gather_i_1_fifo* adsp_fifo_out)
{
	int inl_ret = -1;
	int inl_pos_start = 0;
	int inl_pos_header = 0;
	int inl_num_bytes = 0;

	// Prepare writer
	struct dsd_workarea_allocator dsl_wa_alloc;
	m_wa_allocator_init(&dsl_wa_alloc);
	dsl_wa_alloc.adsc_aux = adsp_aux;

	struct dsd_gather_writer dsl_writer;
	m_gw_init(&dsl_writer, &dsl_wa_alloc);
	inl_pos_start = m_gw_get_abs_pos(&dsl_writer);

	HL_GR_RET_GOTO(m_svc_dynvc_write_data_header(&dsl_writer, adsp_cmd->umc_channel_id), LBL_FAILED);
	inl_pos_header = m_gw_get_abs_pos(&dsl_writer);

	if (adsp_cmd->umc_payload_length > MAX_PDU_SIZE - (inl_pos_header - inl_pos_start)) {
		// packet is too large! the client needs to do segmentation
		inl_ret = -2;
		goto LBL_FAILED;
	}

	HL_GR_RET_GOTO(m_gw_write_bytes(&dsl_writer, adsp_cmd->achc_payload, adsp_cmd->umc_payload_length), LBL_FAILED);

LBL_SUCCESS:
	// Write back phase
	HL_GR_RET_GOTO(m_gw_mark_end(&dsl_writer), LBL_FAILED);
	inl_num_bytes = m_gw_get_abs_pos(&dsl_writer);
	if (inl_num_bytes > 0) {
		m_gather3_list_release(&dsl_writer.dsc_fifo, adsp_fifo_out);
	}
	inl_ret = inl_num_bytes;

LBL_FAILED:
	m_gw_destroy(&dsl_writer);
	m_wa_allocator_destroy(&dsl_wa_alloc);

	return inl_ret;
}

int m_svc_dynvc_send_data2(struct dsd_dynvc_context* adsp_context,
	struct dsd_aux_helper* adsp_aux, struct dsd_dynvc_client_command2* adsp_cmd, struct dsd_gather_i_1_fifo* adsp_fifo_out)
{
	int inl_pos_start = 0;
	int inl_pos_header = 0;
	int inl_num_bytes = 0;

	// Prepare writer
	struct dsd_workarea_allocator dsl_wa_alloc;
	m_wa_allocator_init(&dsl_wa_alloc);
	dsl_wa_alloc.adsc_aux = adsp_aux;

	struct dsd_gather_writer dsl_writer;
	m_gw_init(&dsl_writer, &dsl_wa_alloc);
	inl_pos_start = m_gw_get_abs_pos(&dsl_writer);

	struct dsd_channel_context* adsl_channel = adsp_cmd->adsc_channel;
	HL_GR_RET_GOTO(m_svc_dynvc_write_data_header(&dsl_writer, adsl_channel->umc_channel_id), LBL_FAILED);
	inl_pos_header = m_gw_get_abs_pos(&dsl_writer);

	if (adsp_cmd->umc_payload_length > MAX_PDU_SIZE - (inl_pos_header - inl_pos_start)) {
		// packet is too large! the client needs to do segmentation
		return -2;
	}

	HL_GR_RET_GOTO(m_gw_write_gather_list(&dsl_writer, adsp_cmd->adsc_payload, adsp_cmd->umc_payload_length), LBL_FAILED);

LBL_SUCCESS:
	// Write back phase
	HL_GR_RET_GOTO(m_gw_mark_end(&dsl_writer), LBL_FAILED);
	inl_num_bytes = m_gw_get_abs_pos(&dsl_writer);
	if (inl_num_bytes > 0) {
		m_gather3_list_release(&dsl_writer.dsc_fifo, adsp_fifo_out);
	}
	m_gw_destroy(&dsl_writer);

	return inl_num_bytes;

LBL_FAILED:
	return -1;
}

