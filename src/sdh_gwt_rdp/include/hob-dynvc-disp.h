#ifndef HOB_DYNVC_DISP
#define HOB_DYNVC_DISP

#include "hob-dynvc-common.h"
#include <hob-webterm-rdp-svc-dynvc.h>

#define STR_DYNVC_NAME_DISP "Microsoft::Windows::RDS::DisplayControl"

struct dsd_dvc_disp {
	struct dsd_dvc_common dsc_common; //common must be first member of struct
	uint32_t umc_max_num_monitors;
	uint32_t umc_max_monitor_area_factor_a;
	uint32_t umc_max_monitor_area_factor_b;
};

static const int DVC_DISP_DISPLAYCONTROL_MONITOR_PRIMARY = 0x00000001;
static const int DVC_DISP_ORIENTATION_LANDSCAPE = 0;
static const int DVC_DISP_ORIENTATION_PORTRAIT = 90;
static const int DVC_DISP_ORIENTATION_LANDSCAPE_FLIPPED = 180;
static const int DVC_DISP_ORIENTATION_PORTRAIT_FLIPPED = 270;

static const int DVC_DISP_DISPLAYCONTROL_PDU_TYPE_MONITOR_LAYOUT = 0x00000002;

struct dsd_monitor_def_ex {
	uint32_t imc_flags;
	int32_t imc_left;
	int32_t imc_top;
	uint32_t imc_width;
	uint32_t imc_height;
	uint32_t imc_physical_width;
	uint32_t imc_physical_height;
	uint32_t imc_orientation;
	uint32_t imc_desktop_scale_factor;
	uint32_t imc_device_scale_factor;
};

struct dsd_dvc_input_monitor_layout {
	uint32_t umc_num_monitors;
	struct dsd_monitor_def_ex* adsrc_monitors;
};

struct dsd_dvc_input_command {
	uint32_t umc_command;
	struct dsd_dvc_input_monitor_layout dsc_monitor_layout;
};

void m_init_dvc_disp(struct dsd_dynvc_context* adsp_drdynvc, struct dsd_dvc_disp* adsp_dvc_disp);
int m_dvc_disp_process_command(struct dsd_dvc_disp* adsp_dvc_disp, struct dsd_workarea_allocator* adsp_wa_alloc, const struct dsd_dvc_input_command* adsp_command, struct dsd_gather_i_1_fifo* adsp_fifo_out);

#endif // HOB_DYNVC_DISP
