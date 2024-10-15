#ifndef HOB_DYNVC_GRAPHICS
#define HOB_DYNVC_GRAPHICS

#include "hob-dynvc-common.h"
#include <hob-webterm-rdp-svc-dynvc.h>

#define STR_DYNVC_NAME_EGFX "Microsoft::Windows::RDS::Graphics"

struct dsd_dvc_graphics {
	struct dsd_dvc_common dsc_common; //common must be first member of struct
};

void m_init_dvc_graphics(struct dsd_dynvc_context* adsp_drdynvc, struct dsd_dvc_graphics* adsp_dvc_graphics);

#endif // HOB_DYNVC_GRAPHICS