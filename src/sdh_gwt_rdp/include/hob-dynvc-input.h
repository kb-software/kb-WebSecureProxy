#ifndef HOB_DYNVC_INPUT_H
#define HOB_DYNVC_INPUT_H

#include <hob-tk-gather-tools-01.h>

/*
  Header file for the implementation of the Remote Desktop Protocol: Input Virtual Channel Extension ([MS-RDPEI]).
*/

/*===================
    DEFINES
===================*/

#define STR_DYNVC_NAME_INPUT "Microsoft::Windows::RDS::Input"

#define DVC_INPUT_CONTACT_FLAG_DOWN 0x0001 // The contact transitioned to the engaged state (made contact).
#define DVC_INPUT_CONTACT_FLAG_UPDATE 0x0002 // Contact update.
#define DVC_INPUT_CONTACT_FLAG_UP 0x0004 // The contact transitioned from the engaged state (broke contact).
#define DVC_INPUT_CONTACT_FLAG_INRANGE 0x0008 // The contact has not departed and is still in range.
#define DVC_INPUT_CONTACT_FLAG_INCONTACT 0x0010 //The contact is in the engaged state.
#define DVC_INPUT_CONTACT_FLAG_CANCELED 0x0020 //The contact has been canceled

#define DVC_INPUT_MAX_FRAMES 0x7FFF
#define DVC_INPUT_MAX_CONTACTS 10 // Max Contacts 1 byte (255)

/*===================
STRUCTURE DEFINITIONS
===================*/

struct dsd_input_touch_contact {
  unsigned char ucc_contact_id;
  unsigned short usc_fields_present_flag;
  
  int ilc_x_coord;
  int ilc_y_coord;

  unsigned int umc_contact_flags;

  signed short isc_contact_rect_left;
  signed short isc_contact_rect_top;
  signed short isc_contact_rect_right;
  signed short isc_contact_rect_bottom;

  unsigned int umc_orientation;
  unsigned int umc_pressure;

  BOOL boc_active;
};

struct dsd_input_touch_frame {
  unsigned short usc_contact_count;
  unsigned long long ullc_frame_offset; // The time offset from the previous frame (in microseconds)
  unsigned short usc_active_count;

  // Contacts
  struct dsd_input_touch_contact dsrc_touch_contacts[DVC_INPUT_MAX_CONTACTS];
};

struct dsd_input_pen_contact {
  unsigned char ucc_contact_id;
  unsigned short usc_fields_present_flag;
  
  int ilc_x_coord;
  int ilc_y_coord;

  unsigned int umc_contact_flags;
  unsigned int umc_pen_flags;

  unsigned int umc_pressure;
  unsigned short usc_rotation;

  signed short isc_tilt_x;
  signed short isc_tilt_y;
};

struct dsd_input_pen_frame {
  unsigned short usc_contact_count;
  unsigned long long ullc_frame_offset;

  // Contacts
  struct dsd_input_pen_contact *adsc_pen_contacts;
};

struct dsd_dvc_input {
  struct dsd_dvc_common dsc_common; //common must be first member of struct

  unsigned int umc_se_version; // Server version
  unsigned int umc_cl_version; // Client version 
  
  // Client Properties
  BOOL boc_show_touch_visuals;
  BOOL boc_disable_ts_injection;
  unsigned short usc_max_touch_contacts;

  // Pen Input Allow ADM
  BOOL boc_pen_allowed;
  BOOL boc_input_transmission_suspended;

  // Active Frames
  struct dsd_input_touch_frame dsl_active_touch_frame;
  struct dsd_input_pen_frame dsl_active_pen_frame;
  unsigned long long ullc_prev_frame_time;

  uint32_t umc_supported_features;
};

/*===================
  PUBLIC FUNCTIONS
===================*/
void m_init_rdpei(struct dsd_dynvc_context *adsp_drdynvc, struct dsd_dvc_input *adsp_dvc_input);

// Return: Number of bytes in fifo on success. Negative error code otherwise.
int m_send_rdpinput_touch_event(struct dsd_dvc_input* adsp_dvc, struct dsd_aux_helper* adsp_aux,
	struct dsd_input_touch_frame* adsp_touch_frame, struct dsd_gather_i_1_fifo* adsp_fifo_out);


#endif /* HOB_DYNVC_INPUT_H */