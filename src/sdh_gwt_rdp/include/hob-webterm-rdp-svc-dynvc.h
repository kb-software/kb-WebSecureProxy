#ifndef HOB_WEBTERM_RDP_SVC_DYNVC
#define HOB_WEBTERM_RDP_SVC_DYNVC

#if 0
#include <hob-avl03.h>
#endif
#include <hob-webterm-rdp-svc.h>
#include <hob-tk-gather-tools-01.h>

/*
  Header file for the implementation of the Remote Desktop Protocol: Dynamic Channel Virtual Channel Extension ([MS-RDPEDYC]).
  Limitations:
    - Only Single Packets supported (< 1590 bytes). Fragmented Packets must be handled differently.
*/

/*===================
    DEFINES
===================*/
#ifndef _HRESULT_DEFINED
typedef long HRESULT;
#endif

// Application specific (can be changed)
#define DVC_MAX_LISTENERS 16
#define DVC_MAX_CHANNELS 32

#define HL_GR_RET_GOTO(call, lbl) if(!(call)) goto lbl

#define MH_DYNVC_USE_AVL_TREE 1

/*===================
STRUCTURE DEFINITIONS
===================*/

enum ied_dynvc_result {
	ied_error = -1,
	ied_incomplete = 0,
	ied_success = 1,
};

enum ied_dynvc_msg_type {
	ied_invalid = -1,
	ied_create = 1,
	ied_data = 2,
	ied_datafirst = 3,
	ied_close = 4,
};

struct dsd_dynvc_listener_event {
	uint32_t umc_channel_id;
	uint32_t umc_packet_length;
	uint32_t umc_total_length;

	struct dsd_gather_reader* adsc_reader;
	struct dsd_gather_writer* adsc_gw_client;
	struct dsd_gather_writer* adsc_gw_server;
	struct dsd_dynvc_command* adsc_dynvc_command;
	//struct dsd_aux_helper* adsc_aux;
};

// Structure for all dynamic virtual channels listeners.
struct dsd_dynvc_create_context {
	struct dsd_dynvc_context* adsc_drdynvc;
};

struct dsd_dynvc_create_listener {
	const char* achc_name;
	void* avoc_context;
	struct dsd_channel_context* (*m_create)(struct dsd_dynvc_create_listener* adsp_this, struct dsd_dynvc_create_context* adsp_context);
};

struct dsd_dynvc_listener {
	//const char* achc_name;
	void* avoc_context;
	enum ied_dynvc_result (*m_receive)(void* avop_this, enum ied_dynvc_msg_type iep_type, struct dsd_dynvc_listener_event* adsp_event);
};

// Structure for a dynamic channel.
struct dsd_channel_context {
	struct dsd_dynvc_context* adsc_parent;
#if MH_DYNVC_USE_AVL_TREE
	struct dsd_htree1_avl_entry dsc_sort; // Sorting entry
#endif
	unsigned long umc_channel_id; // Channel id (unique)

	unsigned short usc_priority; // Priority class, unused?

	struct dsd_dynvc_listener dsc_listener;
};

static const int INS_MAX_DYNAMIC_CHANNELS = 64;

// Structure for "DRDYNVC"
struct dsd_dynvc_context {
  char chrc_channel_name[8]; // Channel Name
  unsigned long umc_options; // Options
  
  unsigned short usc_se_version; // Server version
  unsigned short usc_cl_version; // Client version 
  unsigned short usc_priority_charge_0; // Priority Charges
  unsigned short usc_priority_charge_1; // Priority Charges 
  unsigned short usc_priority_charge_2; // Priority Charges
  unsigned short usc_priority_charge_3; // Priority Charges

  /*- DVC Manager data -*/

  // Listeners
  int inc_listeners_count;
  struct dsd_dynvc_create_listener* dsrc_active_listeners[DVC_MAX_LISTENERS]; // The client maintains a list of active listeners
  int inc_dynvc_max_name_length;

  // Channels
#if MH_DYNVC_USE_AVL_TREE
  //struct dsd_htree1_avl_work dsc_htree1_work; // Work area for avl tree with active dvc channels
  struct dsd_htree1_avl_cntl dsc_htree1_avl_cntl_channels; // Control structure for avl tree with active dvc channels
#else
  int inc_active_channels_count;
  struct dsd_channel_context* adsrc_channels[INS_MAX_DYNAMIC_CHANNELS];
#endif

  struct dsd_gather_i_1_fifo dsc_fifo;

  int (*amc_sdh_printf)(void*, const char *, ... );
  void* avoc_context;
};

struct dsd_dynvc_command {
	struct dsd_gather_i_1* adsc_data_to_server;
	uint32_t umc_to_server_length_total;
	uint32_t umc_to_server_length_current;

	struct dsd_gather_i_1* adsc_data_to_client;
	uint32_t umc_to_client_length;
	unsigned char ucc_record_type;
};

struct dsd_dynvc_client_command {
	uint32_t umc_channel_id;
	uint32_t umc_payload_length;
	const char* achc_payload;
};

struct dsd_dynvc_client_command2 {
	struct dsd_channel_context* adsc_channel;
	uint32_t umc_payload_length;
	struct dsd_gather_i_1* adsc_payload;
};


/*===================
  PUBLIC FUNCTIONS
===================*/

void m_init_drdynvc(struct dsd_dynvc_context *adsp_drdynvc);

int m_register_listener(struct dsd_dynvc_context *adsp_drdynvc, struct dsd_dynvc_create_listener* adsp_listener);

int m_svc_dynvc_receive_message(struct dsd_dynvc_context* adsp_context,
	struct dsd_aux_helper* adsp_aux, struct dsd_rdp_vch_io* adsp_message, struct dsd_dynvc_command* adsp_output_command);

BOOL m_svc_dynvc_write_data_header(struct dsd_gather_writer* adsp_writer, uint32_t ump_channel_id);
BOOL m_svc_dynvc_prepend_data_header(struct dsd_gather_writer* adsp_writer, uint32_t ump_channel_id);

BOOL m_receive_client_data(struct dsd_dynvc_context* adsp_context, const char* achp_data_in, int inp_data_length, struct dsd_dynvc_client_command* adsp_cmd);
int m_svc_dynvc_send_data(struct dsd_dynvc_context* adsp_context,
	struct dsd_aux_helper* adsp_aux, struct dsd_dynvc_client_command* adsp_cmd, struct dsd_gather_i_1_fifo* adsp_fifo_out);
int m_svc_dynvc_send_data2(struct dsd_dynvc_context* adsp_context,
	struct dsd_aux_helper* adsp_aux, struct dsd_dynvc_client_command2* adsp_cmd, struct dsd_gather_i_1_fifo* adsp_fifo_out);

BOOL m_gw_write_hasn1(struct dsd_gather_writer* adsp_writer, int inp_number);

#endif // HOB_WEBTERM_RDP_SVC_DYNVC