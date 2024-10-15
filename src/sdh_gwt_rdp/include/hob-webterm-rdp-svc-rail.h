#ifndef _HOB_WEBTERM_RDP_SVC_RAIL_H_
#define _HOB_WEBTERM_RDP_SVC_RAIL_H_

#if !HOB_TK_NO_INCLUDE
#include <stdint.h>
#include <hob-tk-gather-tools-01.h>
#include <hob-webterm-rdp-svc.h>
#endif

struct dsd_svc_rail {
	struct dsd_rdp_vc_1 *adsc_rdp_vc_1;
	struct dsd_gather_i_1_fifo dsc_fifo;
};

const uint16_t TS_RAIL_ORDER_EXEC = 0x0001;
const uint16_t TS_RAIL_ORDER_ACTIVATE = 0x0002;
const uint16_t TS_RAIL_ORDER_SYSPARAM = 0x0003;
const uint16_t TS_RAIL_ORDER_SYSCOMMAND = 0x0004;
const uint16_t TS_RAIL_ORDER_HANDSHAKE = 0x0005;
const uint16_t TS_RAIL_ORDER_NOTIFY_EVENT = 0x0006;
const uint16_t TS_RAIL_ORDER_WINDOWMOVE = 0x0008;
const uint16_t TS_RAIL_ORDER_LOCALMOVESIZE = 0x0009;
const uint16_t TS_RAIL_ORDER_MINMAXINFO = 0x000a;
const uint16_t TS_RAIL_ORDER_CLIENTSTATUS = 0x000b;
const uint16_t TS_RAIL_ORDER_SYSMENU = 0x000c;
const uint16_t TS_RAIL_ORDER_LANGBARINFO = 0x000d;
const uint16_t TS_RAIL_ORDER_GET_APPID_REQ = 0x000e;
const uint16_t TS_RAIL_ORDER_GET_APPID_RESP = 0x000f;
const uint16_t TS_RAIL_ORDER_UNKNOWN1 = 0x0010;
const uint16_t TS_RAIL_ORDER_EXEC_RESULT = 0x0080;

const uint32_t UM_SPI_SETSCREENSAVEACTIVE = 0x00000011;
const uint32_t UM_SPI_SETSCREENSAVESECURE = 0x00000077;

const uint32_t TS_RAIL_CLIENTSTATUS_ALLOWLOCALMOVESIZE = 0x00000001;
const uint32_t TS_RAIL_CLIENTSTATUS_AUTORECONNECT = 0x00000002;

const uint16_t TS_RAIL_EXEC_FLAG_EXPAND_WORKINGDIRECTORY = 0x0001;
const uint16_t TS_RAIL_EXEC_FLAG_TRANSLATE_FILES = 0x0002;
const uint16_t TS_RAIL_EXEC_FLAG_FILE = 0x0004;
const uint16_t TS_RAIL_EXEC_FLAG_EXPAND_ARGUMENTS = 0x0008;

const uint16_t TS_RAIL_EXEC_S_OK = 0x0000;
const uint16_t TS_RAIL_EXEC_E_HOOK_NOT_LOADED = 0x0001;
const uint16_t TS_RAIL_EXEC_E_DECODE_FAILED = 0x0002;
const uint16_t TS_RAIL_EXEC_E_NOT_IN_ALLOWLIST = 0x0003;
const uint16_t TS_RAIL_EXEC_E_FILE_NOT_FOUND = 0x0005;
const uint16_t TS_RAIL_EXEC_E_FAIL = 0x0006;
const uint16_t TS_RAIL_EXEC_E_SESSION_LOCKED = 0x0007;

struct dsd_svc_rail_order_sysparam {
	uint32_t umc_system_parameter;
	union {
		struct dsd_setscreensaveactive {
			uint8_t boc_enabled;
		} dsc_setscreensaveactive;
		struct dsd_setscreensavesecure {
			uint8_t boc_enabled;
		} dsc_setscreensavesecure;
	} dsc_body;
};

struct dsd_svc_rail_order_handshake {
	uint32_t umc_build_number;
};

struct dsd_svc_rail_order_exec {
	uint16_t usc_flags;
	uint16_t usc_exe_or_file_length;
	uint16_t usc_working_dir_length;
	uint16_t usc_arguments_length;
	struct dsd_unicode_string_gather_pos dsc_exe_or_file;
	struct dsd_unicode_string_gather_pos dsc_working_dir;
	struct dsd_unicode_string_gather_pos dsc_arguments;
};

struct dsd_svc_rail_order_clientstatus {
	uint32_t umc_flags;
};

struct dsd_svc_rail_order_exec_result {
	uint16_t usc_flags;
	uint16_t usc_exec_result;
	uint32_t umc_raw_result;
	uint16_t usc_padding;
	uint16_t usc_exe_or_file_length;
	struct dsd_unicode_string_gather_pos dsc_exe_or_file;
};

struct dsd_svc_rail_order_localmovesize {
	uint32_t umc_window_id;
	uint16_t usc_is_move_size_start;
	uint16_t usc_move_size_type;
	uint16_t usc_pos_x;
	uint16_t usc_pos_y;
};

struct dsd_svc_rail_order_minmaxinfo {
	uint32_t umc_window_id;
	uint16_t usc_max_width;
	uint16_t usc_max_height;
	uint16_t usc_max_pos_x;
	uint16_t usc_max_pos_y;
	uint16_t usc_min_track_width;
	uint16_t usc_min_track_height;
	uint16_t usc_max_track_width;
	uint16_t usc_max_track_height;
};

struct dsd_svc_rail_message {
	uint16_t usc_order_type;
	union {
		struct dsd_svc_rail_order_sysparam dsc_sysparam;
		struct dsd_svc_rail_order_handshake dsc_handshake;
		struct dsd_svc_rail_order_exec_result dsc_exec_result;
		struct dsd_svc_rail_order_localmovesize dsc_localmovesize;
		struct dsd_svc_rail_order_minmaxinfo dsc_minmaxinfo;
	} dsc_order;
};

struct dsd_svc_rail_command {
	uint16_t usc_order_type;
	union {
		struct dsd_svc_rail_order_exec dsc_exec;
		struct dsd_svc_rail_order_sysparam dsc_sysparam;
		struct dsd_svc_rail_order_handshake dsc_handshake;
		struct dsd_svc_rail_order_clientstatus dsc_clientstatus;
	} dsc_order;
};

void m_svc_rail_init(
	struct dsd_svc_rail *adsp_rail,
	struct dsd_aux_helper *adsp_aux,
	struct dsd_rdp_vc_1 *adsp_rdp_vc_1);
int m_svc_rail_receive_message(
	struct dsd_svc_rail *adsp_rail, 
	struct dsd_aux_helper *adsp_aux,
   struct dsd_rdp_vch_io* adsp_message,
	struct dsd_svc_rail_message* adsp_result);
int m_svc_rail_process_commands(
	struct dsd_svc_rail *adsp_drdynvc, 
	struct dsd_workarea_allocator *adsp_wa_alloc,
	const struct dsd_svc_rail_command* adsrp_commands,
	int inp_num_commands,
	struct dsd_svc_command_result* adsp_result);
void m_svc_rail_destroy(
	struct dsd_svc_rail *adsp_rail,
	struct dsd_aux_helper *adsp_aux);

#endif // !_HOB_WEBTERM_RDP_SVC_RAIL_H_
