#ifndef _HOB_WEBTERM_RDP_SVC_RDPDR_H_
#define _HOB_WEBTERM_RDP_SVC_RDPDR_H_

#if !HOB_TK_NO_INCLUDE
#include <stdint.h>
#include <hob-tk-gather-tools-01.h>
#include <hob-webterm-rdp-svc.h>
#endif

#define RDPDR_DEVICE_REMOVE_PDUS 0x00000001
#define RDPDR_CLIENT_DISPLAY_NAME_PDU 0x00000002
#define RDPDR_USER_LOGGEDON_PDU 0x00000004

#define RDPDR_DTYP_SERIAL 0x00000001
#define RDPDR_DTYP_PARALLEL 0x00000002
#define RDPDR_DTYP_PRINT 0x00000004
#define RDPDR_DTYP_FILESYSTEM 0x00000008
#define RDPDR_DTYP_SMARTCARD 0x00000020

// The DriverName field MUST be in ASCII characters. If not set, it MUST be in Unicode.
#define RDPDR_PRINTER_ANNOUNCE_FLAG_ASCII 0x00000001
// The printer is set as default. There MUST be only one printer with this flag set.
#define RDPDR_PRINTER_ANNOUNCE_FLAG_DEFAULTPRINTER 0x00000002
// This printer is from the network.
#define RDPDR_PRINTER_ANNOUNCE_FLAG_NETWORKPRINTER 0x00000004
// This flag is set when the printer to be redirected is not a local or network printer but is a terminal server client printer. This can happen in nested TS sessions; that is, this can happen when a TS connection is made from within a TS session.
#define RDPDR_PRINTER_ANNOUNCE_FLAG_TSPRINTER 0x00000008
// This client/printer supports XML Paper Specification (XPS) format.
#define RDPDR_PRINTER_ANNOUNCE_FLAG_XPSFORMAT 0x00000010

// Add printer cachedata event.
#define RDPDR_ADD_PRINTER_EVENT 0x00000001
// Update printer cachedata event.
#define RDPDR_UPDATE_PRINTER_EVENT 0x00000002
// Delete printer cachedata event.
#define RDPDR_DELETE_PRINTER_EVENT 0x00000003
// Rename printer cachedata event
#define RDPDR_RENAME_PRINTER_EVENT 0x00000004

// Create request
#define IRP_MJ_CREATE 0x00000000
// Close request
#define IRP_MJ_CLOSE 0x00000002
// Read request
#define IRP_MJ_READ  0x00000003
// Write request
#define IRP_MJ_WRITE 0x00000004
// Device control request
#define IRP_MJ_DEVICE_CONTROL 0x0000000E

#define HL_STATUS_E_FAIL               	0x80004005
#define HL_STATUS_OBJECT_NAME_COLLISION	0XC0000035
#define HL_STATUS_ERROR_NOT_SUPPORTED     0x00000032
#define HL_STATUS_ERROR_BROKEN_PIPE			0x0000006D

enum ied_svc_rdpdr_message {
	iec_svc_rdpdr_message_server_announce_req,
	iec_svc_rdpdr_message_server_capability_req,
	iec_svc_rdpdr_message_server_clientid_confirm,
	iec_svc_rdpdr_message_server_user_loggedon,
	iec_svc_rdpdr_message_server_device_announce_resp,
	iec_svc_rdpdr_message_server_device_io_req,
	iec_svc_rdpdr_message_server_device_io_continuation,
	iec_svc_rdpdr_message_server_printer_cache_event,
	iec_svc_rdpdr_message_server_printer_cache_event_continuation,
};

struct dsd_svc_rdpdr {
	struct dsd_rdp_vc_1 *adsc_rdp_vc_1;
	int inc_state;
	uint16_t usc_component;
	uint16_t usc_packetid;
	struct dsd_gather_i_1_fifo dsc_fifo;
	enum ied_svc_rdpdr_message iec_continuation_message;
	uint32_t umc_continuation_pos;
	uint32_t umc_continuation_total;
};

struct dsd_svc_rdpdr_message_core_server_announce_req {
	/* VersionMajor */
	uint16_t usc_version_major;
	/* VersionMinor */
	uint16_t usc_version_minor;
	/* ClientId (The WTS session id) */
	uint32_t umc_client_id;
};

struct dsd_svc_rdpdr_capabilities {
	/* VersionMajor */
	uint16_t usc_num_capabilities;
	BOOL boc_general : 1;
	BOOL boc_printer : 1;
	BOOL boc_port : 1;
	BOOL boc_drive : 1;
	BOOL boc_smartcard : 1;
	struct dsd_general {
		uint32_t umc_version;
		uint32_t umc_os_type;
		uint32_t umc_os_version;
		uint16_t usc_protocol_major_version;
		uint16_t usc_protocol_minor_version;
		uint32_t umc_io_code1;
		uint32_t umc_io_code2;
		uint32_t umc_extended_pdu;
		uint32_t umc_extra_flag1;
		uint32_t umc_extra_flag2;
		uint32_t umc_special_type_device_cap;
	} dsc_general;
	struct dsd_printer {
		uint32_t umc_version;
	} dsc_printer;
	struct dsd_port {
		uint32_t umc_version;
	} dsc_port;
	struct dsd_drive {
		uint32_t umc_version;
	} dsc_drive;
	struct dsd_smartcard {
		uint32_t umc_version;
	} dsc_smartcard;
};

struct dsd_svc_rdpdr_message_core_server_capability_req {
	struct dsd_svc_rdpdr_capabilities dsc_caps;
};

struct dsd_svc_rdpdr_message_core_server_clientid_confirm {
	uint16_t usc_version_major;
	uint16_t usc_version_minor;
	uint32_t umc_client_id;
};

struct dsd_svc_rdpdr_message_core_server_device_announce_resp {
	uint32_t umc_device_id;
	uint32_t umc_error_code;
};

struct dsd_svc_rdpdr_message_core_server_device_io_req {
	uint32_t umc_device_id;
	uint32_t umc_file_id;
	uint32_t umc_completion_id;
	uint32_t umc_major_function;
	uint32_t umc_minor_function;
	union dsd_function {
		struct dsd_create {
			uint32_t umc_desired_access;
			uint64_t ulc_allocation_size;
			uint32_t umc_file_attributes;
			uint32_t umc_shared_access;
			uint32_t umc_create_disposition;
			uint32_t umc_create_options;
			uint32_t umc_path_length;
			struct dsd_gather_i_1_pos dsc_path;
		} dsc_create;
		struct dsd_read {
			uint32_t umc_length;
			uint64_t ulc_offset;
		} dsc_read;
		struct dsd_write {
			uint32_t umc_length;
			uint64_t ulc_offset;
			struct dsd_gather_i_1_pos dsc_data;
		} dsc_write;
		struct dsd_device_control {
			uint32_t umc_output_buffer_length;
			uint32_t umc_input_buffer_length;
			uint32_t umc_io_control_code;
			struct dsd_gather_i_1_pos dsc_input_buffer;
		} dsc_device_control;
		struct dsd_close {
		} dsc_close;
	} dsc_function;
};

struct dsd_svc_rdpdr_message_core_server_printer_cache_event {
	uint32_t umc_event;
	union dsd_event {
		struct dsd_add_printer {
			char chrc_port_dos_name[8];
			uint32_t umc_pnp_name_len;
			uint32_t umc_driver_name_len;
			uint32_t umc_print_name_len;
			uint32_t umc_cached_fields_len;
			struct dsd_gather_i_1_pos dsc_pnp_name;
			struct dsd_gather_i_1_pos dsc_driver_name;
			struct dsd_gather_i_1_pos dsc_print_name;
			struct dsd_gather_i_1_pos dsc_data;
		} dsc_add_printer;
		struct dsd_update_printer {
			uint32_t umc_print_name_len;
			uint32_t umc_cached_fields_len;
			struct dsd_gather_i_1_pos dsc_printer_name;
			struct dsd_gather_i_1_pos dsc_cached_printer_config_data;
		} dsc_update_printer;
		struct dsd_delete_printer {
			uint32_t umc_print_name_len;
			struct dsd_gather_i_1_pos dsc_print_name;
		} dsc_delete_printer;
		struct dsd_rename_printer {
			uint32_t umc_old_printer_name_len;
			uint32_t umc_new_printer_name_len;
			struct dsd_gather_i_1_pos dsc_old_printer_name;
			struct dsd_gather_i_1_pos dsc_new_printer_name;
		} dsc_rename_printer;
	} dsc_event;
};

struct dsd_svc_rdpdr_message_core_server_printer_cache_event_continuation {
	uint32_t umc_offset;
	uint32_t umc_length;
	uint32_t umc_total;
	struct dsd_gather_i_1_pos dsc_cached_printer_config_data;
};

struct dsd_svc_rdpdr_message_core_server_device_io_req_continuation {
	uint32_t umc_offset;
	uint32_t umc_length;
	uint32_t umc_total;
	struct dsd_gather_i_1_pos dsc_data;
};

struct dsd_svc_rdpdr_message {
	enum ied_svc_rdpdr_message iec_message;
	union dsd_message {
		struct dsd_svc_rdpdr_message_core_server_announce_req dsc_core_server_announce;
		struct dsd_svc_rdpdr_message_core_server_capability_req dsc_core_server_capability;
		struct dsd_svc_rdpdr_message_core_server_clientid_confirm dsc_core_server_clientid_confirm;
		struct dsd_svc_rdpdr_message_core_server_device_announce_resp dsc_core_server_device_announce;
		struct dsd_svc_rdpdr_message_core_server_device_io_req dsc_core_server_device_io_req;
		struct dsd_svc_rdpdr_message_core_server_device_io_req_continuation dsc_core_server_device_io_continuation;
		struct dsd_svc_rdpdr_message_core_server_printer_cache_event dsc_core_server_printer_cache_event;
		struct dsd_svc_rdpdr_message_core_server_printer_cache_event_continuation dsc_core_server_printer_cache_event_continuation;
	} dsc_message;
};

// CORE_CLIENT_ANNOUNCE_RSP
struct dsd_svc_rdpdr_command_core_client_announce_resp {
	/* VersionMajor */
	uint16_t usc_version_major;
	/* VersionMinor */
	uint16_t usc_version_minor;
	/* ClientId (The WTS session id) */
	uint32_t umc_client_id;
};

struct dsd_svc_rdpdr_command_core_client_name_req {
	uint32_t umc_unicode_flag;
	uint32_t umc_code_page;
	uint32_t umc_computer_name_len;
	const void* avoc_computer_name;
};

struct dsd_svc_rdpdr_command_core_client_capability_resp {
	struct dsd_svc_rdpdr_capabilities dsc_caps;
};

struct dsd_device_announce {
	uint32_t umc_device_type;
	uint32_t umc_device_id;
	char ucrc_preferred_dos_name[8];
};

struct dsd_svc_rdpdr_device_annouce_data_printer {
	struct dsd_device_announce dsc_device_announce;
	uint32_t umc_flags;
	uint32_t umc_code_page;
	uint32_t umc_pnp_name_len;
	uint32_t umc_driver_name_len;
	uint32_t umc_print_name_len;
	uint32_t umc_cached_fields_len;
	const void* avoc_pnp_name;
	const void* avoc_driver_name;
	const void* avoc_print_name;
	const void* avoc_cached_fields;
};

struct dsd_svc_rdpdr_command_core_client_device_list_announce_req {
	uint32_t umc_device_count;
	struct dsd_device_announce** adsrc_devices;
};

enum ied_svc_rdpdr_command_core_device_io_function {
	ied_device_io_function_create,
	ied_device_io_function_write,
	ied_device_io_function_close,
	ied_device_io_function_device_io,
};

struct dsd_svc_rdpdr_command_core_device_io_resp {
	uint32_t umc_device_id;
	uint32_t umc_completion_id;
	uint32_t umc_io_status;
	enum ied_svc_rdpdr_command_core_device_io_function iec_function;
	union dsd_function {
		struct dsd_create {
			uint32_t umc_file_id;
			uint8_t ucc_information;
		} dsc_create;
		struct dsd_write {
			uint32_t umc_length;
		} dsc_write;
		struct dsd_device_io {
			uint32_t umc_output_buffer_length;
			struct dsd_gather_i_1* adsc_output_buffer;
		} dsc_device_io;
		struct dsd_close {
		} dsc_close;
	} dsc_function;
};

enum ied_svc_rdpdr_command {
	iec_svc_rdpdr_command_client_announce_resp,
	iec_svc_rdpdr_command_client_name_req,
	iec_svc_rdpdr_command_client_capability_resp,
	iec_svc_rdpdr_command_client_device_list_announce_req,
	iec_svc_rdpdr_command_core_device_io_resp,
};

struct dsd_svc_rdpdr_command {
	enum ied_svc_rdpdr_command iec_command;
	union dsd_message {
		struct dsd_svc_rdpdr_command_core_client_announce_resp dsc_core_client_announce;
		struct dsd_svc_rdpdr_command_core_client_name_req dsc_core_client_name;
		struct dsd_svc_rdpdr_command_core_client_capability_resp dsc_core_client_capability;
		struct dsd_svc_rdpdr_command_core_client_device_list_announce_req dsc_core_client_device_list_announce;
		struct dsd_svc_rdpdr_command_core_device_io_resp dsc_core_device_io;
	} dsc_message;
};

void m_svc_rdpdr_init(
	struct dsd_svc_rdpdr *adsp_rdpdr,
	struct dsd_aux_helper *adsp_aux,
	struct dsd_rdp_vc_1 *adsp_rdp_vc_1);
int m_svc_rdpdr_receive_message(
	struct dsd_svc_rdpdr *adsp_drdynvc, 
	struct dsd_aux_helper *adsp_aux,
   struct dsd_rdp_vch_io* adsp_message,
	struct dsd_svc_rdpdr_message* adsp_result);
int m_svc_rdpdr_process_commands(
	struct dsd_svc_rdpdr *adsp_drdynvc, 
	struct dsd_aux_helper *adsp_aux,
   const struct dsd_svc_rdpdr_command* adsrp_commands,
	int inp_num_commands,
	struct dsd_svc_command_result* adsp_result);
void m_svc_rdpdr_destroy(
	struct dsd_svc_rdpdr *adsp_rdpdr,
	struct dsd_aux_helper *adsp_aux);

#endif // !_HOB_WEBTERM_RDP_SVC_RDPDR_H_
