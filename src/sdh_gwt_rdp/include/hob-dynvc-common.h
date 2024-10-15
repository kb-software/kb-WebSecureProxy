#ifndef HOB_DYNVC_COMMON
#define HOB_DYNVC_COMMON

#include <hob-webterm-rdp-svc-dynvc.h>

struct dsd_dvc_common {
  struct dsd_channel_context dsc_channel_context; // Parent Static Virtual Channel
  struct dsd_dynvc_context *adsc_svc; // Parent Static Virtual Channel
};

#endif