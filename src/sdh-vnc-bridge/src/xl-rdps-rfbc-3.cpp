/*
__   ___  _  ___   ___     _    _          
\ \ / / \| |/ __| | _ )_ _(_)__| |__ _ ___ 
 \ V /| .` | (__  | _ \ '_| / _` / _` / -_)
  \_/ |_|\_|\___| |___/_| |_\__,_\__, \___|
                                 |___/      
*/
 
/*  
    +-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
    |#|d|e|f|i|n|e| |S|w|i|t|c|h|e|s|
    +-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ 
*/

/* Tracing Defines */
//#define ALLOW_SDH_PRINTF_I  /* Printf Info messages  */
//#define ALLOW_SDH_PRINTF_W  /* Printf Other messages */
//#define ALLOW_SDH_PRINTF_T  /* Printf Trace messages */
//#define TRACEHL1            /* Printf other misc messages */


#if (defined HL_LINUX || HL_LINUX64 || HL_UNIX)
    #define DLL_EXPORT __attribute__ ((visibility ("default")))
#else
    #define DLL_EXPORT __declspec( dllexport )
#endif

#if defined __cplusplus
    extern "C" DLL_EXPORT void m_hlclib01( struct dsd_hl_clib_1 * );
#else
    extern DLL_EXPORT void m_hlclib01( struct dsd_hl_clib_1 * );
#endif // cplusplus

#if  defined(_WIN64)

typedef unsigned __int64 UINT_PTR; 

#else

typedef unsigned int UINT_PTR; 

#endif


/* Encodings supported by the VNC Bridge: */
#define ENABLE_ZLIB         /* Enable Zlib Encoding   */
//#define ENABLE_RRE          /* Enable RRE Encoding    */
#define ENABLE_COPYRECT
#define ENABLE_ZRLE

#define VNC_USE_ORDERQUEUE 

//Switches to be probably removed ...

//#define ALLOW_GET_MORE_WORKAREA_WHEN_FULL /*Requested by Mr Bauer, Ticket 22664*/

//#define DEBUG_110620_01
//#define DEBUG_110620_02
#define DEBUG_110719_01    /* fixed password */


//Futher RRE Switches - needed until an optimum settings are found
//TODO: Implementation of offscreen drawing
//RRE drawing modes
//#define RRE_OPAQUERECT //Converts All VNC subrectangles to opaque_rect commands
#define OPAQUERECT_THRESHOLD //use draw_screen_buffer or opaque_rect commands based on the "Threshold" value.
#ifdef OPAQUERECT_THRESHOLD
#define AVG_RRE_SUBRECT_SIZE 1 //The "Threshold"; Average RRE subrectangle pixel Area. 
//if the average subrectangle size in the rre frame update is less than the value set, the drawsceen buffer command 
//is used, else the opaquerect commands are used. 
//Note: if set to 1, only opaquerect commands will be sent to the RDPACC when the vncserver uses the RRE Encoding
#endif

//#define JSDEBUG //Debugging Statements switch - Must be switched off before committing 
//#define JBDEBUG

/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xl-rdps-rfbc-1                                      |*/
/*| -------------                                                     |*/
/*|  DLL / Library for HOB WebSecureProxy                             |*/
/*|  RDP server - RFB (= VNC) client                                  |*/
/*|    using RDP-ACC RDP-server                                       |*/
/*|  KB 28.05.10                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  Unix / Linux GCC                                                 |*/
/*|                                                                   |*/
/*|                                                                   |*/
/*| FUNCTION:                                                         |*/
/*| ---------                                                         |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/*
    +-+-+-+-+-+-+-+ +-+-+-+-+-+-+
    |#|d|e|f|i|n|e| |M|a|c|r|o|s|
    +-+-+-+-+-+-+-+ +-+-+-+-+-+-+
*/

#define VERSION_THIS_FILE "2.3.0343 "

#ifdef ENABLE_ZLIB         /* Enable Zlib Encoding   */
#undef NO_ZLIB_110622
#else
#define NO_ZLIB_110622
#endif 

#define OUT_ERROR_NO_SPACE_IN_WORKAREA m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E connect failed - no space in work area - failed to obtain more work area",__LINE__ )

//#if !(defined HL_LINUX)
    #define CONVERT_W64_TO_INT(WORD64) ((int) (UINT_PTR) (WORD64))
//#else
//    #define CONVERT_W64_TO_INT(WORD64) ((int) (unsigned int) (WORD64))
//#endif

//Ticket 22664 
//DEF_DEBUG_PRINTF("\nGetting More WorkArea through #defined call"); 
#define GET_MORE_WORKAREA {                                                    \
    memset (&dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );    \
    bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld, DEF_AUX_GET_WORKAREA, &dsl_aux_get_workarea, sizeof(struct dsd_aux_get_workarea));   \
    if(bol1 == FALSE){                                                          \
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;                            \
        OUT_ERROR_NO_SPACE_IN_WORKAREA; \
        return; \
    }                                                                          \
    achl_work_1 = dsl_aux_get_workarea.achc_work_area;                  /* addr work-area   */ \
    achl_work_2 = achl_work_1 + dsl_aux_get_workarea.imc_len_work_area; /* length work-area */ \
}   

#define ENSURE_SPACE_ON_WORKAREA(SIZE_NEEDED){                                  \
   if( (CONVERT_W64_TO_INT(achl_work_2 - achl_work_1)) < (SIZE_NEEDED)){        \
      GET_MORE_WORKAREA;                                                        \
      if( ( CONVERT_W64_TO_INT(achl_work_2 - achl_work_1)) < (SIZE_NEEDED)){    \
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;                           \
         OUT_ERROR_NO_SPACE_IN_WORKAREA;                                        \
         return;                                                                \
      }                                                                         \
   }                                                                            \
}

#define GET_GATHER_ON_WA                                                        \
   ENSURE_SPACE_ON_WORKAREA(sizeof(dsd_gather_i_1));                            \
   achl_work_2 -= sizeof(dsd_gather_i_1);                                       \
   adsl_gai1_w1 = (dsd_gather_i_1*) achl_work_2;

#define GET_GATHER(SIZE_NEEDED) {                                               \
   ENSURE_SPACE_ON_WORKAREA(SIZE_NEEDED + sizeof(dsd_gather_i_1));              \
   achl_work_2 -= sizeof(dsd_gather_i_1);                                       \
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;                     \
   adsl_gai1_out_1->adsc_next = NULL;                                           \
   adsl_gai1_out_1->achc_ginp_cur = (char*) achl_work_1;                        \
   adsl_gai1_out_1->achc_ginp_end = (char*) achl_work_1 + (SIZE_NEEDED);        \
   achl_work_1 += (SIZE_NEEDED);                                                \
   achl1 = adsl_gai1_out_1->achc_ginp_cur;                                      \
}

#define ADD_GATHER_TO_VNC_OUTPUT(ADS_GATHER){                                   \
   if(adsl_gai1_out_server == NULL){                                            \
      adsp_hl_clib_1->adsc_gai1_out_to_server = ADS_GATHER;                     \
   } else {                                                                     \
      adsl_gai1_out_server->adsc_next = ADS_GATHER;                             \
   }                                                                            \
   adsl_gai1_out_server = ADS_GATHER;                                           \
}

#define GET_VNC_OUTPUT_GATHER(SIZE_NEEDED) {                                    \
   GET_GATHER(SIZE_NEEDED);                                                     \
   ADD_GATHER_TO_VNC_OUTPUT(adsl_gai1_out_1);                                   \
}

#define SEND_FRAMEBUFFER_UPDATE_REQUEST(INCREMENTAL) \
   GET_VNC_OUTPUT_GATHER(0xa);                       \
   *achl1++ = 0x3;                                   \
   *achl1++ = INCREMENTAL ? 1 : 0;                   \
   write_16_be(&achl1, 0);                           \
   write_16_be(&achl1, 0);                           \
   write_16_be(&achl1, adsl_session->usc_fb_width);  \
   write_16_be(&achl1, adsl_session->usc_fb_height);               

#define CLEAR_FBU_RECTS {                                                                                         \
   adsl_session->adsc_fbu_changes[0].isc_left   = adsl_session->dsc_fbu.usc_x + adsl_session->dsc_fbu.usc_width;  \
   adsl_session->adsc_fbu_changes[0].isc_top    = adsl_session->dsc_fbu.usc_y + adsl_session->dsc_fbu.usc_height; \
   adsl_session->adsc_fbu_changes[0].isc_right  = 0;                                                              \
   adsl_session->adsc_fbu_changes[0].isc_bottom = 0;                                                              \
   iml1 = 1;                                                                                                      \
   while(true){                                                                                                   \
      iml2 = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_num_rects - iml1;                                             \
      if(iml2 < iml1){                                                                                            \
         memcpy(adsl_session->adsc_fbu_changes + iml1, adsl_session->adsc_fbu_changes, sizeof(dsd_rectrb) * iml2);\
         break;                                                                                                   \
      }                                                                                                           \
      memcpy(adsl_session->adsc_fbu_changes + iml1, adsl_session->adsc_fbu_changes, sizeof(dsd_rectrb) * iml1);   \
      iml1 *= 2;                                                                                                  \
   }                                                                                                              \
}

#define DEBUG_STOP_RFB  adsl_session->boc_rfb_error = true; goto p_proc_inp_70;



//#define PRINTF_DEF_IRET_END m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E Connection Should End", __LINE__ )
#if !(defined HL_UNIX)
    #define ERROR_MACRO(MESSAGE, ...) { m_sdh_printf_tl( &dsl_sdh_call_1, "E", __LINE__, MESSAGE, __VA_ARGS__); \
                                      adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU; \
                                      goto p_cleanup_00;}

    #define ERROR_MACRO_RDP(ADMIN, MESSAGE, ...) {if(m_rfb_error(&dsl_sdh_call_1, __FUNCTION__, __LINE__, ADMIN, MESSAGE, __VA_ARGS__)){ \
                                                     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;                                 \
                                                     goto p_cleanup_00;                                                           \
                                                  }                                                                               \
                                                  goto p_rdpserv_40;}

    #define ERROR_MACRO_SUB(MESSAGE, ...) { m_sdh_printf_tl( adsl_sdh_call_1, "E", __LINE__, MESSAGE, __VA_ARGS__); \
                                            return false; }
#else
// In C++ the '##' removes the preceding coma in variadic macros when there is no variable argument (...).
//     For more info: http://www.delorie.com/gnu/docs/gcc/gcc_44.html 
    #define ERROR_MACRO(MESSAGE, ...) { m_sdh_printf_tl( &dsl_sdh_call_1, "E", __LINE__, MESSAGE, ##__VA_ARGS__); \
                                      adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU; \
                                      goto p_cleanup_00;}

    #define ERROR_MACRO_RDP(ADMIN, MESSAGE, ...) {if(m_rfb_error(&dsl_sdh_call_1, __FUNCTION__, __LINE__, ADMIN, MESSAGE, ##__VA_ARGS__)){ \
                                                     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;                                 \
                                                     goto p_cleanup_00;                                                           \
                                                  }                                                                               \
                                                  goto p_rdpserv_40;}


    #define ERROR_MACRO_SUB(MESSAGE, ...) { m_sdh_printf_tl( adsl_sdh_call_1, "E", __LINE__, MESSAGE, ##__VA_ARGS__); \
                                            return false; }
#endif

#define CHECK_RETURN_SUB(CALL) if((CALL) == false){                            \
                                  adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU; \
                                  goto p_cleanup_00;}                         

#ifdef PROCESS_RRE_IMMEDIATELY //Processing of rectangles in batches of RRE_SUBRECTS_BUFFER_LEN or less
#define RRE_SUBRECTS_BUFFER_LEN 100
#define RRE_CODE_REVIEW 4
#endif


#ifdef JSDEBUG
#define DEF_DEBUG_PRINTF(...) std::cerr << __VA_ARGS__ << std::endl;
#else
#define DEF_DEBUG_PRINTF(...)
#endif

#ifdef ALLOW_SDH_PRINTF_I  /* Printf Info messages  */
#define M_SDH_PRINTF_I(MESSAGE, ...) {m_sdh_printf_tl( &dsl_sdh_call_1, "I", __LINE__, MESSAGE, __VA_ARGS__);}
#else
#define M_SDH_PRINTF_I(...)
#endif

#ifdef ALLOW_SDH_PRINTF_W   /* Printf W-messages */
#define M_SDH_PRINTF_W(MESSAGE, ...) {m_sdh_printf_tl( &dsl_sdh_call_1, "W", __LINE__, MESSAGE, __VA_ARGS__);}
#else
#define M_SDH_PRINTF_W(...)
#endif

#ifdef ALLOW_SDH_PRINTF_T  /* Printf Trace Messages */
#define M_SDH_PRINTF_T(MESSAGE, ...) {m_sdh_printf_tl( &dsl_sdh_call_1, "T", __LINE__, MESSAGE, __VA_ARGS__);}
#else
#define M_SDH_PRINTF_T(...)
#endif

#define CHECK_RETURN(CALL) if((CALL) == false){ERROR_MACRO_RDP(true, "Parse Error");}

/*
    +-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+
    |#|d|e|f|i|n|e| |C|o|n|s|t|a|n|t|s|
    +-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+
*/

#define DEF_MAX_LEN_CO           256          /* maximum length console output */
#define NORM_LEN_RBF_PASSWORD      8          /* length password RFB     */
#define NORM_LEN_HOST_PASSWORD    30          /* length password host     */
#define NORM_LEN_HOST_USER        30          /* length user host     */
#define MAX_LEN_USER_PASSWORD     2000
#define IMS_SCREEN_UPDATE_WIDTH   32
#define IMS_SCREEN_UPDATE_HEIGHT  32

#define rfbEncodingRaw             0
#define rfbEncodingCopyRect        1
#define rfbEncodingRRE             2
#define rfbEncodingZlib            6 
#define rfbEncodingZlibHex         8
#define rfbEncodingZRLE           16
#define rfbPseudoEncodingCursor -239
#define rfbPseudoEncodingDesktopSize -223

#define rfbKeyPress     1
#define rfbKeyRelease   0

//RFB Protocol v3.8
//6.4 Client to server messages
#define rfb_cl2sc_SetPixelFormat            0
#define rfb_cl2sc_SetEncodings              2
#define rfb_cl2sc_FramebufferUpdateRequest  3
#define rfb_cl2sc_KeyEvent                  4
#define rfb_cl2sc_PointerEvent              5
#define rfb_cl2sc_ClientCutText             6

//6.5 Server to client messages
#define rfb_sc2cl_FramebufferUpdate     0
#define rfb_sc2cl_SetColourMapEntries   1
#define rfb_sc2cl_Bell                  2
#define rfb_sc2cl_ServerCutText         3

//6.1.2 RFB Security Types
#define rfb_sectype_Invalid          0x00
#define rfb_sectype_None             0x01
#define rfb_sectype_VNCAthentication 0x02
#define rfb_sectype_ra2              0x05
#define rfb_sectype_ra2ne            0x06
#define rfb_sectype_ra2_256          0x81
#define rfb_sectype_ra2ne_256        0x82

static const char* m_get_text_security_type(int inl_sectype){
   switch(inl_sectype){
      case rfb_sectype_None:             return "No Authentication";
      case rfb_sectype_VNCAthentication: return "VNC Authentication";
      case rfb_sectype_ra2:              return "RSA/AES-EAX 128 bit encrypted (RA2)";
      case rfb_sectype_ra2ne:            return "only authentication RSA/AES-EAX 128 bit encrypted (RA2ne)";
      case rfb_sectype_ra2_256:          return "RSA/AES-EAX 256 bit encrypted (RA2)";
      case rfb_sectype_ra2ne_256:        return "only authentication RSA/AES-EAX 256 bit encrypted (RA2ne)";
      default:                           return "unknown security type";
   }
}

//mouse events flags received from rdpacc
#define rdp_mouse_flag_move             0x08
#define rdp_mouse_flag_leftpress        0x90
#define rdp_mouse_flag_leftrelease      0x10
#define rdp_mouse_flag_rightpress       0xA0
#define rdp_mouse_flag_rightrelease     0x20
#define rdp_mouse_flag_middlepress      0xC0
#define rdp_mouse_flag_middlerelease    0x40
#define rdp_mouse_flag_wheelup          0x02
#define rdp_mouse_flag_wheeldown        0x03

//clipboard states
#define M_ON_COPY_FMTS_CB 1
#define M_ON_COPY_DATA_CB 2
#define M_ON_PASTE_CB     3

//clipboard constants
#define MAX_CLIPBARD_SIZE (0xff *  0x400) /* maximum size of clipboard buffer on VNC bridge*/

//Offscreen buffer ID used for RRE
#define RRE_OFFSCREEN_ID 0  /* ID of the offscreen bitmap used in RRE - OpaqueRect drawing */

/*+-------------------------------------------------------------------+*/
/*| X11 Keysym Values                                                 |*/
/*+-------------------------------------------------------------------+*/
#define XK_BackSpace                     0xff08  /* Back space, back char */
#define XK_Tab                           0xff09
#define XK_Linefeed                      0xff0a  /* Linefeed, LF */
#define XK_Clear                         0xff0b
#define XK_Return                        0xff0d  /* Return, enter */
#define XK_Pause                         0xff13  /* Pause, hold */
#define XK_Scroll_Lock                   0xff14
#define XK_Sys_Req                       0xff15
#define XK_Escape                        0xff1b
#define XK_Delete                        0xffff  /* Delete, rubout */
#define XK_Shift_L                       0xffe1  /* Left shift */
#define XK_Shift_R                       0xffe2  /* Right shift */
#define XK_Control_L                     0xffe3  /* Left control */
#define XK_Control_R                     0xffe4  /* Right control */
#define XK_Caps_Lock                     0xffe5  /* Caps lock */
#define XK_Shift_Lock                    0xffe6  /* Shift lock */
#define XK_Meta_L                        0xffe7  /* Left meta */
#define XK_Meta_R                        0xffe8  /* Right meta */
#define XK_Alt_L                         0xffe9  /* Left alt */
#define XK_Alt_R                         0xffea  /* Right alt */
#define XK_Super_L                       0xffeb  /* Left super */
#define XK_Super_R                       0xffec  /* Right super */
#define XK_Hyper_L                       0xffed  /* Left hyper */
#define XK_Hyper_R                       0xffee  /* Right hyper */
#define XK_Menu                          0xff67
#define XK_Home                          0xff50
#define XK_Left                          0xff51  /* Move left, left arrow */
#define XK_Up                            0xff52  /* Move up, up arrow */
#define XK_Right                         0xff53  /* Move right, right arrow */
#define XK_Down                          0xff54  /* Move down, down arrow */
#define XK_Prior                         0xff55  /* Prior, previous */
#define XK_Page_Up                       0xff55
#define XK_Next                          0xff56  /* Next */
#define XK_Page_Down                     0xff56
#define XK_End                           0xff57  /* EOL */
#define XK_Begin                         0xff58  /* BOL */
#define XK_Select                        0xff60  /* Select, mark */
#define XK_Print                         0xff61
#define XK_Execute                       0xff62  /* Execute, run, do */
#define XK_Insert                        0xff63  /* Insert, insert here */
#define XK_Undo                          0xff65
#define XK_Redo                          0xff66  /* Redo, again */
#define XK_Menu                          0xff67
#define XK_Find                          0xff68  /* Find, search */
#define XK_Cancel                        0xff69  /* Cancel, stop, abort, exit */
#define XK_Help                          0xff6a  /* Help */
#define XK_Break                         0xff6b
#define XK_Mode_switch                   0xff7e  /* Character set switch */
#define XK_script_switch                 0xff7e  /* Alias for mode_switch */
#define XK_Num_Lock                      0xff7f
#define XK_F1                            0xffbe
#define XK_F2                            0xffbf
#define XK_F3                            0xffc0
#define XK_F4                            0xffc1
#define XK_F5                            0xffc2
#define XK_F6                            0xffc3
#define XK_F7                            0xffc4
#define XK_F8                            0xffc5
#define XK_F9                            0xffc6
#define XK_F10                           0xffc7
#define XK_F11                           0xffc8
#define XK_L1                            0xffc8
#define XK_F12                           0xffc9
#define XK_L2                            0xffc9
#define XK_F13                           0xffca
#define XK_L3                            0xffca
#define XK_F14                           0xffcb
#define XK_L4                            0xffcb
#define XK_F15                           0xffcc
#define XK_L5                            0xffcc
#define XK_F16                           0xffcd
#define XK_L6                            0xffcd
#define XK_F17                           0xffce
#define XK_L7                            0xffce
#define XK_F18                           0xffcf
#define XK_L8                            0xffcf
#define XK_F19                           0xffd0
#define XK_L9                            0xffd0
#define XK_F20                           0xffd1
#define XK_L10                           0xffd1
#define XK_F21                           0xffd2
#define XK_R1                            0xffd2
#define XK_F22                           0xffd3
#define XK_R2                            0xffd3
#define XK_F23                           0xffd4
#define XK_R3                            0xffd4
#define XK_F24                           0xffd5
#define XK_R4                            0xffd5
#define XK_F25                           0xffd6
#define XK_R5                            0xffd6
#define XK_F26                           0xffd7
#define XK_R6                            0xffd7
#define XK_F27                           0xffd8
#define XK_R7                            0xffd8
#define XK_F28                           0xffd9
#define XK_R8                            0xffd9
#define XK_F29                           0xffda
#define XK_R9                            0xffda
#define XK_F30                           0xffdb
#define XK_R10                           0xffdb
#define XK_F31                           0xffdc
#define XK_R11                           0xffdc
#define XK_F32                           0xffdd
#define XK_R12                           0xffdd
#define XK_F33                           0xffde
#define XK_R13                           0xffde
#define XK_F34                           0xffdf
#define XK_R14                           0xffdf
#define XK_F35                           0xffe0
#define XK_R15                           0xffe0
#define XK_KP_Multiply                   0xffaa
#define XK_KP_Add                        0xffab
#define XK_KP_Separator                  0xffac  /* Separator, often comma */
#define XK_KP_Subtract                   0xffad
#define XK_KP_Decimal                    0xffae
#define XK_KP_Divide                     0xffaf
#define XK_KP_0                          0xffb0
#define XK_KP_1                          0xffb1
#define XK_KP_2                          0xffb2
#define XK_KP_3                          0xffb3
#define XK_KP_4                          0xffb4
#define XK_KP_5                          0xffb5
#define XK_KP_6                          0xffb6
#define XK_KP_7                          0xffb7
#define XK_KP_8                          0xffb8
#define XK_KP_9                          0xffb9

#if (defined HL_UNIX)
    #define VK_BACK      0x08
    #define VK_TAB       0x09
    #define VK_ESCAPE    0x1b
    #define VK_RETURN    0x0d 
    #define VK_LSHIFT    0xa0
    #define VK_RSHIFT    0xa1
    #define VK_LCONTROL  0xa2
    #define VK_RCONTROL  0xa3
    #define VK_LMENU     0xa4
    #define VK_RMENU     0xa5
    #define VK_CAPITAL   0x14
    #define VK_F1        0x70
    #define VK_F2        0x71
    #define VK_F3        0x72
    #define VK_F4        0x73
    #define VK_F5        0x74
    #define VK_F6        0x75
    #define VK_F7        0x76
    #define VK_F8        0x77
    #define VK_F9        0x78
    #define VK_F10       0x79
    #define VK_F11       0x7a
    #define VK_F12       0x7b
    #define VK_NUMLOCK   0x90
    #define VK_NUMPAD0   0x60
    #define VK_NUMPAD1   0x61
    #define VK_NUMPAD2   0x62
    #define VK_NUMPAD3   0x63
    #define VK_NUMPAD4   0x64
    #define VK_NUMPAD5   0x65
    #define VK_NUMPAD6   0x66
    #define VK_NUMPAD7   0x67
    #define VK_NUMPAD8   0x68
    #define VK_NUMPAD9   0x69
    #define VK_DECIMAL   0x6e
    #define VK_SUBTRACT  0x6d
    #define VK_ADD       0x6b
    #define VK_MULTIPLY  0x6a
    #define VK_DIVIDE    0x6f
    #define VK_DELETE    0x2e
    #define VK_INSERT    0x2d
    #define VK_PRIOR     0x21
    #define VK_NEXT      0x22
    #define VK_LEFT      0x25
    #define VK_UP        0x26
    #define VK_RIGHT     0x27
    #define VK_DOWN      0x28
    #define VK_END       0x23
    #define VK_HOME      0x24
    #define VK_SNAPSHOT  0x2c
    #define VK_SCROLL    0x91
    #define VK_PAUSE     0x13
// Virtual key code values taken from http://msdn.microsoft.com/en-us/library/cc248947.aspx
    #define VK_CLEAR     0x000C
    #define VK_LWIN      0x005B
    #define VK_RWIN      0x005C
    #define VK_APPS      0x005D
    #define VK_SELECT    0x0029
    #define VK_EXECUTE   0x002B
    #define VK_HELP      0x002F
    #define VK_CANCEL    0x0003
    #define VK_F13       0x007C
    #define VK_F14       0x007D
    #define VK_F15       0x007E
    #define VK_F16       0x007F
    #define VK_F17       0x0080
    #define VK_F18       0x0081
    #define VK_F19       0x0082
    #define VK_F20       0x0083
    #define VK_F21       0x0084
    #define VK_F22       0x0085
    #define VK_F23       0x0086
    #define VK_F24       0x0087
    #define VK_SEPARATOR 0x006C

#endif

#define MAX_POSSIBLE_VNC_MAJOR_VERSION 3
#define MAX_POSSIBLE_VNC_MINOR_VERSION 7

// Security types
static const unsigned char ucr_sec_types_all[] = {
   rfb_sectype_None,
   rfb_sectype_VNCAthentication,
   rfb_sectype_ra2,
   rfb_sectype_ra2ne,
   rfb_sectype_ra2_256,
   rfb_sectype_ra2ne_256,
};

static const unsigned char ucr_prefer_off[] = {
   rfb_sectype_ra2ne,
   rfb_sectype_ra2ne_256,
   rfb_sectype_ra2,
   rfb_sectype_ra2_256,
   rfb_sectype_VNCAthentication,
   rfb_sectype_None,
};

static const unsigned char ucr_prefer_on[] = {
   rfb_sectype_ra2,
   rfb_sectype_ra2_256,
   rfb_sectype_ra2ne,
   rfb_sectype_ra2ne_256,
   rfb_sectype_VNCAthentication,
   rfb_sectype_None,
};

static const unsigned char ucr_always_on[] = {
   rfb_sectype_ra2,
   rfb_sectype_ra2_256,
};

static const unsigned char ucr_always_max[] = {
   rfb_sectype_ra2_256,
};

struct dsd_security_type_setting {
   const unsigned char* uchc_allowed_security_types;
   const int            inc_num_allowed_security_types;
};

// Security types
static const char* achrs_security_type_settings[] = {
   "none",
   "let-vnc-server-choose",
   "prefer-off", 
   "prefer-on",
   "always-on",
   "always-maximum"
};

static const dsd_security_type_setting dsds_security_type_settings[] = {
   {ucr_sec_types_all, sizeof(ucr_sec_types_all) / sizeof(unsigned char)},
   {ucr_sec_types_all, sizeof(ucr_sec_types_all) / sizeof(unsigned char)},
   {ucr_prefer_off,    sizeof(ucr_prefer_off)    / sizeof(unsigned char)},
   {ucr_prefer_on,     sizeof(ucr_prefer_on)     / sizeof(unsigned char)},
   {ucr_always_on,     sizeof(ucr_always_on)     / sizeof(unsigned char)},
   {ucr_always_max,    sizeof(ucr_always_max)    / sizeof(unsigned char)}
};

// Setting, where to get the credentials from 
static const char* achrs_authentication_settings[] = {
   "WSP-configuration",    // default
   "dynamic-connetion", 
   "RD-VPN-credentials",
   "RDP-credentials"
};
static const char* achrs_authentication_settings_test[] = {
   "WSP configuration",    // default
   "dynamic VNC-connection", 
   "RD VPN credentials",
   "RDP credentials"
};

enum ied_auth_setting {
   ied_auth_setting_wsp_config = 0,
   ied_auth_setting_dynamic    = 1,
   ied_auth_setting_rd_vpn     = 2,
   ied_auth_setting_rdp        = 3
};

#define INS_AES_TAG_LEN 0x10

/*+--------------------------------------------------------------------------+*/
/*| Include hob-rdpserver1.h and all the includes, it requires               |*/
/*+--------------------------------------------------------------------------+*/

#ifndef HL_UNIX
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <conio.h>    
#else
    #include <unistd.h>
    #include <sys/sem.h>
    #include <errno.h>
    #include <arpa/inet.h>
    #include <hob-unix01.h>
    #include <stdarg.h> 
    #include <strings.h>
#ifdef HL_FREEBSD
    #include <sys/socket.h>
#endif
#endif

#include "hob-cdrdef1.h"
//#include "hmd5.h"
//#include "hsha.h"
#include <hob-encry-1.h>
#include "hrc4cons.h"
#include <hob-avl03.h>

#pragma warning(disable:4005)
#include <hob-rdpserver1.h>
#pragma warning(default:4005)

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <string.h>
#include <time.h>
//#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>
#include <hob-xslunic1.h>
//#include "hrc4cons.h"
//#include "hsha2.h"
#pragma warning(disable:4005)
//#include <hobdes.h>
#pragma warning(default:4005)
//#include <rsaraw.h>
//#include <aes.h>
//#include <eax.h>

#define HL_COMP_MULTI  //JS added on 05/07/2011 to avoid second linking error
#include "hob-cd-record-1.h"

#include "hob-bitswaptab.h"
#define HOB_LITTLE_ENDIAN 1
#include "hob-pixel-converter-2.hpp"

#include <hob-gather_reader.hpp>
#include <hob/util/hob-tk-queue.hpp>
#include <hob-rdpacc_orderqueue.hpp>
#include <hob-rdp_keymapping.hpp>

#include <hob-rdpacc_vector.hpp>
#include <hob-rdpacc_clipboard.h>
#include <hob-rdpacc_tahoma.hpp>

#include <hobeax.h>


/*+-------------------------------------------------------------------+*/
/*| System and library header files for XERCES.                       |*/
/*+-------------------------------------------------------------------+*/

#include <xercesc/dom/DOMAttr.hpp>
#define DOMNode XERCES_CPP_NAMESPACE::DOMNode

/*+-------------------------------------------------------------------+*/
/*| header files for Server-Data-Hook.                                |*/
/*+-------------------------------------------------------------------+*/

#define DEF_HL_INCL_DOM
#define DEF_HL_INCL_INET
#include "hob-xsclib01.h"
#include <hob-get_rdvpn_credentials.hpp>

//#define DEF_DEBUG_PRINTF // use this to disable the DEF_DEBUG_PRINTF 

/*+-------------------------------------------------------------------+*/
/*| Pixel-converter-settings                                          |*/
/*+-------------------------------------------------------------------+*/

using namespace hob::graphics::cc;
static const c_colormodel dss_colormodel_15_16(15, 16, 0x7c00, 0x03e0, 0x001f, 0, ie_endian_little);
static const c_colormodel dss_colormodel_16_16(16, 16, 0xf800, 0x07e0, 0x001f, 0, ie_endian_little);
static const c_colormodel dss_colormodel_24_24(24, 24, 0x00ff0000, 0x0000ff00, 0x000000ff, 0, ie_endian_little);
static const c_colormodel dss_colormodel_24_32(24, 32, 0x00ff0000, 0x0000ff00, 0x000000ff, 0xff000000, ie_endian_little);
static const c_colormodel dss_colormodel_32_32(32, 32, 0x00ff0000, 0x0000ff00, 0x000000ff, 0xff000000, ie_endian_little);

typedef c_statcon_colormodel_direct<15, 16, 0x007c00, 0x03e0, 0x1f, 0x00000000, ie_endian_little> dsd_colormodel_15_16;
typedef c_statcon_colormodel_direct<16, 16, 0x00f800, 0x07e0, 0x1f, 0x00000000, ie_endian_little> dsd_colormodel_16_16;
typedef c_statcon_colormodel_direct<24, 24, 0xff0000, 0xff00, 0xff, 0x00000000, ie_endian_little> dsd_colormodel_24_24;
typedef c_statcon_colormodel_direct<24, 32, 0xff0000, 0xff00, 0xff, 0x00000000, ie_endian_little> dsd_colormodel_24_32;
typedef c_statcon_colormodel_direct<32, 32, 0xff0000, 0xff00, 0xff, 0xff000000, ie_endian_little> dsd_colormodel_32_32;

typedef TYPE_LIST2(dsd_colormodel_16_16, dsd_colormodel_24_32) dsd_colormodel_list_src;
typedef TYPE_LIST5(dsd_colormodel_15_16, dsd_colormodel_16_16, dsd_colormodel_24_24, dsd_colormodel_24_32, dsd_colormodel_32_32) dsd_colormodel_list_dst;

typedef c_static_config<dsd_colormodel_list_src, dsd_colormodel_list_dst, NULL_CLASS,
   IN_DYNAMIC_SOURCE_ENDIAN_LITTLE |
   IN_DYNAMIC_SOURCE_ENDIAN_BIG    |
   IN_DYNAMIC_TARGET_ENDIAN_LITTLE |
   //IN_DYNAMIC_TARGET_ENDIAN_BIG    |

   IN_DYNAMIC_REDUCE |
   IN_DYNAMIC_EXTEND | // Do I need this?

   IN_STATIC_ALU |

   IN_TABLE_1 |
   IN_TABLE_2 |
   IN_TABLE_4 |
   IN_TABLE_8 |

   0,
   IN_READ_ALIGNED, IN_WRITE_ALIGNED>
dsd_pixel_converter_config;

/*+-------------------------------------------------------------------+*/
/*| Internal used structures and classes.                             |*/
/*+-------------------------------------------------------------------+*/

struct dsd_clib1_conf {                     /* configuration data      */
   int        inc_len_vnc_password;
   dsd_rdpacc_vector<char, NORM_LEN_RBF_PASSWORD + 3>  dsc_vnc_password;  /* password          */
   int        inc_len_host_password;
   dsd_rdpacc_vector<char, NORM_LEN_HOST_PASSWORD> dsc_host_password;  /* host-password          */
   int        inc_len_host_user;
   dsd_rdpacc_vector<char, NORM_LEN_HOST_USER >    dsc_host_user;  /* host-user          */
   char       chc_co_shared;                /* VNC-SHARED-FLAG         */
   BOOL       boc_server_maps_keys;         /* true, if server maps keys on its own */
   BOOL       boc_server_maps_capslock;     /* true, if server takes care for the capslock */
   int        inc_major_version;            /* VNC-major-version, used for this connection */
   int        inc_minor_version;            /* VNC-minor-version, used for this connection */
   int        inc_sec_type_setting;         /* Nr. of the setting of the set encryption */
   int        inc_authentication_setting;   /* Nr. of the setting of the authentication */
   BOOL       boc_cursor_encoding;          /* TRUE, if the VNC-cursor pseudo-encoding is turned on. */
   BOOL       boc_use_clipboard;            /* TRUE, if the clipboard is turned on. */
   int        inc_max_size_clipbard;        /* maximum size of clibpard in bytes. */
   int        inc_show_splash_screen;       /* Time, the splash_screen is shown after initialisation, for debug-reasons. */
   int        inc_fbu_behavior;             /* Frame-buffer-update-behavior: 0=imideately 1=after we can send again */
};

enum ied_state_client_conn_1 {              /* state of the client connection */
   ied_scc1_start = 0,                      /* client not yet started  */
   ied_scc1_wait_conn,                      /* wait for CONNECT command from client */
   ied_scc1_conn_act                        /* connection is active    */
};

enum ied_state_rdp {
   ied_state_rdp_start = 0,
   ied_state_rdp_received_capabilities,
   ied_state_rdp_finalized,
   ied_state_rdp_send_change_screen,
   ied_state_rdp_change_screen_is_send,
   ied_state_rdp_finalized_change_screen
};

typedef hob::memory::c_memory_provider_stack <c_converter_size<dsd_pixel_converter_config>::IN_SIZE_MAX * 2> dsd_stack_allocator ;
enum ied_state_rfc_client_1 {               /* state of this RFC client */
    ied_srfbc_start = 0,                     /* client not yet started  */
    // Version < 3.7
    ied_srfbc_wait_sec_type,                 /* wait security types supported */
    // Version >= 3.7
    ied_srfbc_wait_sec_type_3_7,             /* >= V3.7 wait security types supported from Procotol 3.7 on */
    // Security-type 02, (VNC-Authentication) 
    ied_srfbc_getchallenge,
    ied_srfbc_wait_auth_resp,                /* wait authentication response */
    // Only Security-types 05, 0x6, 0x81, 0x82: (Only Real-VNC?)
    ied_srfbc_rsa_key,                       /* for the RSA-key */
    ied_srfbc_aes_key,                       /* for the AES-key */
    ied_srfbc_turnon_aes,                    /* turn on the AES-encryption for the next input-package */
    ied_srfbc_rsa_digest,                    /* Receive the digest of the rsa-keys */
    ied_srfbc_aes_auth_type,                 /* Wait for authentication type */

    ied_srfbc_wait_server_init,              /* wait ServerInitialisation message */
    ied_srfbc_wait_server_init_name,         /* wait ServerInitialisation message, last field (name) */
    ied_srfbc_conn,                          /* session is connected    */

    ied_srfbc_fu_rect,                       /* framebuffer update get rectangle */
    ied_srfbc_fu_raw,                        /* framebuffer update raw  */
    ied_srfbc_fu_zlib_init,                  /* framebuffer update zLib init */
    ied_srfbc_fu_zlib_new_data,              /* framebuffer update zLib normal */
    ied_srfbc_fu_zlib_call_zlib,             /* call zLib again */
    ied_srfbc_fu_copyrect,                   /* framebuffer update copyrect  */
    ied_srfbc_fu_rre,                        /* framebuffer update RRE      */
    ied_srfbc_fu_rre_subrect,                /* framebuffer update RRE sub-rectangles */
    ied_srfbc_fu_zrle_init,                  /* framebuffer update ZRLE init */
    ied_srfbc_fu_zrle_new_data,              /* framebuffer update ZRLE normal */
    ied_srfbc_fu_zrle_call_zlib,             /* framebuffer update ZRLE call zLib again */
    ied_srfbc_fu_cursor,                     // Cursor poseudo-encoding
    ied_srfbc_server_cut_text,               // ServerCutText-message
    ied_srfbc_set_colormap_entries,          // SetColourMapEntries - message
    ied_srfbc_xyz
};

enum ied_state_rfb_zrle {
   ied_zrle_read_subencoding,
   ied_zrle_raw,
   ied_zrle_palette_palette,
   ied_zrle_palette_data,
   ied_zrle_plain_rle_color,
   ied_zrle_plain_rle_length,
   ied_zrle_palette_rle_palette,
   ied_zrle_palette_rle_index,
   ied_zrle_palette_rle_length,

};

struct dsd_rfb_pixel_format {               /* PIXEL_FORMAT sent from the RFB server */
   unsigned char chc_bits_per_pixel;
   unsigned char chc_depth;
   unsigned char chc_big_endian_flag;
   unsigned char chc_true_colour_flag;
   unsigned short usc_red_max;
   unsigned short usc_green_max;
   unsigned short usc_blue_max;
   unsigned char chc_red_shift;
   unsigned char chc_green_shift;
   unsigned char chc_blue_shift;
};

class dsd_memory_provider{
	unsigned char*    achc_mem;
	unsigned int		unc_available;
public:
	dsd_memory_provider(unsigned char* achc_memory, unsigned int unc_available) 
    : achc_mem(achc_memory), 
      unc_available(unc_available)
	{
	}
	void* m_allocate(std::size_t unl_count, const std::nothrow_t&) throw(){ 
		if (unl_count > this->unc_available)			// not enough memory
			return NULL;
		void * avol_return = this->achc_mem;
      this->unc_available -= unl_count;
		this->achc_mem += unl_count;
		return avol_return;
	}
    void* m_allocate(std::size_t unl_count){
		if (unl_count > this->unc_available)			// not enough memory
			return NULL;
		void * avol_return = this->achc_mem;
      this->unc_available -= unl_count;
		this->achc_mem += unl_count;
		return avol_return;
    }

	void m_deallocate(void *avop_buffer) throw() {
		return;							// do nothing
	}
};

struct dsd_gw_ctrl_1 {                      /* structure session control */

   BOOL       boc_error;                    /* error displayed         */
   BOOL       boc_server_connected;         /* connected to server     */
   BOOL       boc_csssl;                    /* with client-side SSL    */
   bool       boc_send_update_request;      /* send an update request */
   enum ied_state_client_conn_1 iec_scc1;   /* state of the client connection */
   ied_state_rdp iec_state_rdp;             /* State of RDP connection */
   int        imc_rdp_prot_1;               /* RDP protocol status     */
                                            /* only for TOSERVER       */
/**
   //State Value for iml_rdp_prot_1 used when the JWT connection with the wsp is dynamic and VNC server is 
   //specified at runtime. 
   0X80000000   T.123 first byte, reserved
   0X80000001   T.123 first byte length
   0X80000002   T.123 second byte length
   0X80004000   T.123 HOB special
   0X80002000   T.123 HOB special command
   0X80008000   RDP-5 first byte, length
   0X80008001   RDP-5 second byte length
*/
   // Used VNC-version
   int                  inc_major_version;             /* VNC-major-version, used for this connection */
   int                  inc_minor_version;             /* VNC-minor-version, used for this connection */

   // Security: security types
   int                  inc_sec_type_setting;         /* Nr. of the setting of the set encryption */
   unsigned char        ucc_chosen_sec_type;       /* The security type, which was chosen */

   // Security: RSA - AES- encryption
   unsigned char        uchr_server_public[0x200];
   int                  inc_len_server_public_bytes;
   char                 chrc_rsa_keys_digest_check[SHA256_DIGEST_LEN];
   char                 chrc_rsa_keys_digest_send[SHA256_DIGEST_LEN];
   BOOL                 boc_use_sha_256;
   int                  inc_len_aes_key;
   BOOL                 boc_do_aes; // TRUE, if aes-encryption and decryption is on
   int                  inc_authentication; 
   // AES-decryption -> dsd_eax_ctx needs to be 16-byte-alligned
   char                 chr_eax_dec[sizeof(dsd_eax_ctx) + 0xf];
   dsd_eax_ctx*         adsc_eax_dec; 
   HL_LONGLONG          ilc_aes_dec_counter;
   // AES-encryption -> dsd_eax_ctx needs to be 16-byte-alligned
   char                 chr_eax_enc[sizeof(dsd_eax_ctx) + 0xf];
   dsd_eax_ctx*         adsc_eax_enc; 
   HL_LONGLONG          ilc_aes_enc_counter; 

   // Memory to save decrypted data
   char*                achc_mem_data;
   int                  inc_size_mem;
   int                  inc_len_mem_data;

   // Security: passwords 
   int                  inc_authentication_setting;   /* Nr. of the setting of the authentication */
   int                  inc_len_vnc_password;
   dsd_rdpacc_vector<char, NORM_LEN_RBF_PASSWORD + 3>  dsc_vnc_password;  /* password          */
   int                  inc_len_host_password;
   dsd_rdpacc_vector<char, NORM_LEN_HOST_PASSWORD> dsc_host_password;  /* host-password          */
   int                  inc_len_host_user;
   dsd_rdpacc_vector<char, NORM_LEN_HOST_USER >    dsc_host_user;  /* host-user          */

   // Information about screensize, colordeph ...
   unsigned short int   usc_fb_width;              // framebuffer-width    
   unsigned short int   usc_fb_height;             // framebuffer-height     
   int                  imc_bpp_rfb;               // bytes per pixel RFB     
   dsd_rfb_pixel_format dsc_rfb_pixel_format;      // PIXEL_FORMAT sent from the RFB server 
   int                  inc_coldep_rdp;            // Colordeph RDP
   int                  imc_bpp_rdp;               // bytes per pixel RDP    
   int                  inc_scanline_rdp_screen;   // usc_fb_width * imc_bpp_rdp 

   // Pixelconverter: RDP-colormodel, allocator for converter, converter, colormap of rfb (for index-based rfb-colormodel)
   const c_colormodel* adsc_colormodel_rdp; // The RDP-colormodel
   dsd_stack_allocator  dsc_pixel_converter_store;
   c_converter *adsc_pixel_converter;
   c_converter *adsc_cpixel_converter; // Converter for CPIXEL, used in ZRLE
   c_colormap* adsc_colormap_rfb;   // colormap for rfb index-based colormodels
   
   // other settings
   BOOL                 boc_cursor_encoding;          /* TRUE, if the VNC-cursor pseudo-encoding is turned on. */
   char                 chc_co_shared;                /* VNC-SHARED-FLAG         */

   // Calling structures
   struct dsd_call_rdpserv_1 dsc_crdps_1;   /* call RDP Server 1       */
   struct dsd_cdr_ctrl dsc_cdr_ctrl;        /* zLib decompression      */

   // structure used to keep the current state of mouse flags
   // and to store the last coordinates of the mouse (mouse coordinates x and y)
   // When the mouse wheel is moved the mouse coordinates are given from RDP as (0, 0),
   // but the real coordinates have to be handed to the RFB-server, so they have to be stored here. 
   struct {
      unsigned char uc_state;
      unsigned short int usc_last_pos_x;
      unsigned short int usc_last_pos_y;
   } dsc_mouse_state;

   // keyboardmapping
   struct dsd_keyboardmapping ads_keyboardmapping;  /* keyboardmapping tool */
   const struct dsd_keyboard* dsd_keyboard_capslock_behaviour; 
   bool bo_return_control_characters;  // true by default, if set to false the keyboard mapper
                                       // will return ied_no_unicode (if there was a control-character),
                                       // and the right unicode. 
   BOOL                 boc_server_maps_keys;
   BOOL                 boc_server_maps_capslock;

   // Clipboard
   BOOL                 boc_use_clipboard;            /* TRUE, if the clipboard is turned on. */
   BOOL                 boc_clipboard_is_init;        /* TRUE, after initialization of the clipboard */
   int                  inc_max_size_clipbard;        /* maximum size of clibpard in bytes. */
   struct dsd_rdp_vc_1 *adsc_rdp_vc_cb; //clipboard virtual channel 
   struct dsd_rdpacc_clipboard dsc_rdpacc_clipboard;
   int                  inc_rdpclip_state;
   dsd_rdpacc_vector<char, 0x100> dsc_rdpclip_buffer; 
   int                  inc_rdpclip_num_data;    /* length of clipboard data recieved from VNC server (within Max Clipboard Size) */
   int                  inc_rdpclip_num_skip;    /* number of bytes received from vnc server that exceed Max Clipboard Size */

   // Printing out Messages and Errors for RDP
   dsd_font             dsc_rdpacc_font; 
   bool                 boc_rfb_error;
   int                  inc_message_x;
   int                  inc_message_y; 
   int                  inc_message_width; 
   int                  inc_message_height; 
   int                  inc_show_splash_screen;       /* Time, the splash_screen is shown after initialisation, for debug-reasons. */
   int                  inc_fbu_behavior;             /* Frame-buffer-update-behavior: 0=imideately 1=after we can send again */
   time_t               ilc_wait_until;               /* connections waits until this time is reached. */

   // States for parsing the RFB-protocol 
   enum ied_state_rfc_client_1 iec_srfbc;   /* state of this RFC client */

   dsd_rectrb*          adsc_fbu_changes; 
   int                  inc_num_fbu_changes;

   // We're using unions here for command, which cannot be parsed at the same time
   union {
      // 6.3.2 ServerInit
      int in_serverinit_len_name;                  // Length of name-string, send in Server-Init. 

      // 6.5.1 FramebufferUpdate
      struct {                                     /* FramebufferUpdate       */
         unsigned short int usc_no_rect;           /* number-of-rectangles    */
         unsigned short int usc_x;                 /* x-position              */
         unsigned short int usc_y;                 /* y-position              */
         unsigned short int usc_width;             /* width                   */
         unsigned short int usc_height;            /* height                  */
         
         union{
            // Encoding raw or zLib
            struct {
               // Variables, used for raw, zLib and ZRLE encoding:
               unsigned short inc_act_x;
               unsigned short inc_act_y;
               int            imc_draw_remaing;            /* remaining bytes pixel to draw */
               char*          ach_dest_act_line;
               char*          ach_dest_act;
               int            inc_next_line_update; 
               int            inc_num_rects; 
               // Variables, used for zLib and ZRLE encoding: 
               int            imc_zlib_length;             /* Bytes left for zLib input     */
               char           chrc_zlib_buffer[5];         /* Unparsed bytes from zLib output */
               int            imc_zlib_buffer_copied;      /* Bytes in chrc_zlib_buffer */
               // Variables, only used for ZRLE
               ied_state_rfb_zrle iec_state_zrle;          /* The sub-state of the zrle */
               int            inc_wfbu_left;               /* The left edge of the whole framebuffer update   */
               int            inc_wfbu_right;              /* The right edge of the whole framebuffer update  */
               int            inc_wfbu_bottom;             /* The bottom edge of the whole framebuffer update */
               union {
                  // Palette
                  struct {
                     int           inc_pal_pal_size;
                     uint32_t      umrc_pal_palette[0x10];
                     int           inc_pal_act_color;
                     int           inc_bpp_src; 
                     unsigned char chrc_mem_for_converter[c_converter_size<dsd_pixel_converter_config>::IN_SIZE_MAX * 2];
                     c_converter   *adsc_pixel_converter;
                  };
                  // runnlength subencoding
                  struct {
                     // runnlength raw and palette
                     int      inc_rle_length;
                     uint32_t imc_rle_color;
                     // palette rle
                     int      inc_pal_rle_pal_size;
                     uint32_t inrc_pal_rle_palette[0x80];
                     int      inc_pal_rle_act_color;
                  };
               };

            } dsc_raw_zlib_zrle;

            // Encoding RRE
            struct {                               /* Structure used for RRE encoding */
               unsigned int umc_no_rre_sub_rect;   /* no of sub rectangles    */ 
               unsigned int umc_pixel_value;       /* can be background or subrect pixel value */         
               unsigned short int usc_x;           /* x-position relative to FrameBuffer usc_x */
               unsigned short int usc_y;           /* y-position relative to FrameBuffer usc_y */        
               unsigned short int usc_width;       /* width                   */
               unsigned short int usc_height;      /* height                  */
               bool boc_use_offscreencache;        /* if true use offscreen cache to draw opaque rect commands*/
            } dsc_rre;

            // EncodingCopyRect and PseudoEncodingCursor are parsed in one step (short commands!)
            // and because of that they don't have to save states here. 
         };

 
      } dsc_fbu;

      // 6.5.2 SetColourMapEntries
      struct {
         int inc_act_color;                               // SetColourMapEntries: number of colors
         int inc_number_colors_send;                         // SetColourMapEntries: number of colors
      } dsc_scme;
      
      // 6.5.4 ServerCutText
      struct {
         int   inc_bytes_to_parse; 
         char* achc_copy_to;
      } dsc_sct;
   };

    // to-do 27.06.11 KB when zLib hex is used, a second struct dsd_cdr_ctrl is needed

};

#define DEF_CHAR             'a'
#define DEF_REVE             'r'
#define DEF_NO_COPY          128
#define CHAR_CR        0X0D                 /* carriage-return         */
#define CHAR_LF        0X0A                 /* line-feed               */

struct dsd_sdh_call_1 {                     /* structure call in SDH   */
    BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
    void *     vpc_userfld;                  /* User Field Subroutine   */
    struct dsd_gw_ctrl_1 *adsc_ctrl_1;       /* for addressing the data */
    dsd_rdpacc_orderqueue* adsc_orderqueue; 
};

struct dsd_pixel_24 {
  unsigned char ucc_red;
  unsigned char ucc_green;
  unsigned char ucc_blue;

  bool operator!=(dsd_pixel_24 const& ds_other){
     if(ds_other.ucc_red   != this->ucc_red)   return true;
     if(ds_other.ucc_green != this->ucc_green) return true;
     if(ds_other.ucc_blue  != this->ucc_blue)  return true;
     return false; 
  }
};


/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

static const char chrs_out_t123_1[] = { 0X03 };

static const unsigned char ucrs_out_ack_conn[] = { 0X03, 0XFF, 0X00, 0X05, 0X00 };

static const unsigned char ucrs_out_no_server_rfb_n[] = {
    0X03, 0XFF, 0X00, 0X06, 0X01, 0X01
};

static const unsigned char ucrs_out_no_server_rfb_ssl[] = {
    0X03, 0XFF, 0X00, 0X06, 0X01, 0X03
};

static const unsigned char ucrs_comm_connect[] = {
    'C', 'O', 'N', 'N', 'E', 'C', 'T', ' '
};

static const unsigned char ucrs_comm_ineta[] = {
    'I', 'N', 'E', 'T', 'A', '='
};

static const unsigned char ucrs_comm_port[] = {
    'P', 'O', 'R', 'T', '='
};

static const unsigned char ucrs_comm_password[] = {
    'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D', '='
};

static const unsigned char ucrs_comm_ssl[] = {
    'S', 'S', 'L', '='
};

static const unsigned char ucrs_comm_share[] = {
    'V', 'N', 'C', '-', 'S', 'H', 'A', 'R',
    'E', 'D', '-', 'F', 'L', 'A', 'G', '='
};

static const unsigned char ucrs_comm_yes[] = {
    'Y', 'E', 'S'
};

static const unsigned char ucrs_comm_no[] = {
    'N', 'O'
};

static struct dsd_conf_rdpserv_1 dss_conf_rdpserv_1 = {  /* configuration RDP Server 1 */
    // int        imc_sec_level;                /* security level          */
    1
};

static const unsigned char ucrs_des_fixedkey[8] = {
    23, 82, 107, 6, 35, 78, 88, 7
};

static const char chrstrans[]
= { '0', '1', '2', '3', '4', '5', '6', '7',
'8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

static const unsigned char usrs_rsa_modul[] = {
   0xb0, 0x79, 0xf0, 0x4c,  0x5a, 0x4e, 0x7b, 0x70,  0xa9, 0xd0, 0xcb, 0x4d,  0x16, 0x55, 0xca, 0x15,  
   0x5e, 0xb3, 0xd6, 0xe6,  0x96, 0xb4, 0x04, 0x3c,  0x67, 0x8a, 0xbc, 0xcd,  0x7f, 0xee, 0x6b, 0x2b,  
   0x3a, 0x2c, 0x2f, 0x2a,  0xc1, 0x1d, 0xaf, 0x52,  0xfe, 0x81, 0x82, 0xe0,  0x37, 0x1c, 0x24, 0xf5,  
   0xb0, 0xb4, 0x0c, 0x19,  0x05, 0xfe, 0x44, 0x68,  0x33, 0x06, 0xe4, 0x72,  0xdd, 0x7b, 0x0f, 0x5f,  
   0xcc, 0xcf, 0x90, 0x28,  0xfd, 0x63, 0xd4, 0x48,  0x16, 0x87, 0x74, 0x00,  0xcb, 0xf2, 0x0a, 0x41,  
   0x32, 0xd1, 0xd5, 0x5a,  0xc6, 0x1e, 0x6a, 0xd4,  0x1a, 0xd3, 0x9b, 0x88,  0x93, 0x93, 0x4b, 0x6a,  
   0xe9, 0x7f, 0x83, 0xdb,  0xee, 0x66, 0x32, 0x03,  0x99, 0x4d, 0x73, 0x84,  0x93, 0x5b, 0x42, 0x54,  
   0x1c, 0x04, 0xfe, 0xd5,  0xca, 0xf0, 0x90, 0x36,  0xba, 0xa8, 0x27, 0x53,  0x38, 0x78, 0xb7, 0xba,  
   0x9c, 0x6b, 0xf3, 0x2a,  0xf6, 0x99, 0xa1, 0x4e,  0x75, 0xf6, 0xa6, 0x45,  0x52, 0xe2, 0x60, 0xf0,  
   0x72, 0x91, 0xca, 0x7b,  0x01, 0xe0, 0x07, 0x20,  0xc3, 0x3f, 0x5c, 0xc8,  0xa6, 0xe4, 0x76, 0xb5,  
   0x5a, 0xbc, 0x24, 0x68,  0x86, 0xc7, 0xff, 0xba,  0x2d, 0x93, 0xc3, 0xdb,  0x77, 0x67, 0xf3, 0x5b,  
   0x0e, 0x6a, 0x77, 0x20,  0x2b, 0xa9, 0x43, 0xcb,  0xd8, 0x00, 0x54, 0x7c,  0xea, 0xf6, 0xcd, 0xc8,  
   0x90, 0x3f, 0xfd, 0x3d,  0x8b, 0x5e, 0xa5, 0x39,  0x79, 0x8d, 0x75, 0xef,  0xef, 0x6a, 0xb5, 0x71,  
   0xde, 0x9f, 0xd8, 0x9c,  0xcb, 0xe3, 0x0a, 0x0b,  0x7a, 0xe5, 0xd8, 0x29,  0x52, 0xe9, 0x5f, 0x52,  
   0x52, 0x22, 0xa3, 0xbb,  0xcd, 0x17, 0x55, 0x2b,  0xd6, 0x89, 0x9b, 0x19,  0x4e, 0x40, 0xfe, 0x05,  
   0xde, 0xe7, 0xa8, 0x36,  0x9a, 0x0b, 0xfc, 0x04,  0xec, 0xcd, 0x78, 0x19,  0x43, 0xe3, 0x99, 0x11
};

static const unsigned char usrs_rsa_pubexp[] = {
   0x01, 0x00, 0x01
};

static const unsigned char usrs_rsa_privexp[] = {
   0xe2, 0x1b, 0x59, 0xc6,  0x79, 0xee, 0x14, 0x3a,  0x45, 0x59, 0x3f, 0x21,  0x85, 0x7c, 0x65, 0x6e,  
   0xfb, 0xe7, 0x6f, 0x70,  0x01, 0xa6, 0xa3, 0xc6,  0xc0, 0xe3, 0x01, 0x04,  0x4a, 0xe5, 0x2e, 0x6a,  
   0x34, 0x1e, 0x68, 0x50,  0x5f, 0x1d, 0xa9, 0x84,  0xac, 0x91, 0x43, 0x1e,  0x03, 0x7e, 0x0b, 0xdc,  
   0xbe, 0x89, 0xf0, 0xf6,  0x1e, 0xb7, 0xa8, 0xed,  0xd8, 0x72, 0xfc, 0x40,  0x2f, 0x85, 0x7c, 0x2d,  
   0x42, 0x3c, 0xae, 0x77,  0xd6, 0x30, 0x11, 0xcc,  0x4b, 0x11, 0x41, 0x8f,  0xc3, 0xbe, 0x59, 0x65,  
   0x2f, 0xb7, 0xa9, 0xa4,  0xa4, 0x32, 0x54, 0xad,  0x6d, 0xb1, 0xb1, 0x95,  0x4b, 0x7f, 0x6d, 0x21,  
   0x8e, 0x09, 0xd2, 0xe7,  0xf6, 0x8a, 0xf9, 0x89,  0xa2, 0xe1, 0x99, 0x20,  0x43, 0xac, 0xa9, 0x4f,  
   0x1a, 0x97, 0x4b, 0xea,  0xa0, 0x19, 0x98, 0xac,  0x86, 0x7a, 0xeb, 0xe7,  0xb4, 0x72, 0xf6, 0xf2,  
   0x00, 0xb8, 0x3c, 0x77,  0xec, 0xe4, 0xbb, 0x67,  0xe4, 0xfe, 0xf1, 0x66,  0x9b, 0x74, 0xa7, 0xb6,  
   0x67, 0x8f, 0x9a, 0x97,  0x9f, 0xba, 0x09, 0xd0,  0x99, 0x21, 0x93, 0xcd,  0xd4, 0xa0, 0x53, 0x39,  
   0xb2, 0xe1, 0x69, 0x59,  0xbd, 0xa4, 0x3b, 0x71,  0xb3, 0xfa, 0xc8, 0x60,  0x3a, 0xd5, 0x03, 0x34,  
   0x21, 0x4d, 0x41, 0x18,  0x84, 0xc7, 0xf1, 0xdc,  0x68, 0xc7, 0x02, 0x2e,  0xdb, 0x54, 0xf7, 0x4a,  
   0x1b, 0xec, 0x94, 0x21,  0x8b, 0x6f, 0xb6, 0x27,  0x09, 0xc8, 0x0f, 0x93,  0xf8, 0xa3, 0xe7, 0x1d,  
   0x24, 0xaa, 0xe5, 0x01,  0xb2, 0xd0, 0xdb, 0xe7,  0x24, 0xee, 0x54, 0x2a,  0xc3, 0xd1, 0x6c, 0x77,  
   0xda, 0x8f, 0x78, 0xda,  0x55, 0x5a, 0xfc, 0xe8,  0x32, 0x0e, 0xb1, 0x1a,  0x69, 0x81, 0x78, 0x68,  
   0x62, 0x9b, 0x23, 0xbf,  0x02, 0xf3, 0xe1, 0x81,  0x40, 0xf0, 0xf2, 0xd4,  0x37, 0x24, 0x21
}; // RSA value usaully refered to as "d". It is a "private" number. 

//for testing create colour map conts to be passed as parameter
static const uint32_t umrc_rgbtable_default[] = {
    0x00000000, 0x00800000, 0x00008000, 0x00808000, 0x00000080, 0x00800080, 0x00008080, 0x00C0C0C0,
    0x00ACA899, 0x00ECE9D8, 0x00000033, 0x00330000, 0x00330033, 0x00003333, 0x00161616, 0x001C1C1C,
    0x00222222, 0x00292929, 0x00555555, 0x004D4D4D, 0x00424242, 0x00393939, 0x00FF7C80, 0x00FF5050,
    0x00D60093, 0x00CCECFF, 0x00EFD6C6, 0x00E7E7D6, 0x00ADA990, 0x0033FF00, 0x00660000, 0x00990000,
    0x00CC0000, 0x00003300, 0x00333300, 0x00663300, 0x00993300, 0x00CC3300, 0x00FF3300, 0x00006600,
    0x00336600, 0x00666600, 0x00996600, 0x00CC6600, 0x00FF6600, 0x00009900, 0x00339900, 0x00669900,
    0x00999900, 0x00CC9900, 0x00FF9900, 0x0000CC00, 0x0033CC00, 0x0066CC00, 0x0099CC00, 0x00CCCC00,
    0x00FFCC00, 0x0066FF00, 0x0099FF00, 0x00CCFF00, 0x0000FF33, 0x003300FF, 0x00660033, 0x00990033,
    0x00CC0033, 0x00FF0033, 0x000033FF, 0x00333333, 0x00663333, 0x00993333, 0x00CC3333, 0x00FF3333,
    0x00006633, 0x00336633, 0x00666633, 0x00996633, 0x00CC6633, 0x00FF6633, 0x00009933, 0x00339933,
    0x00669933, 0x00999933, 0x00CC9933, 0x00FF9933, 0x0000CC33, 0x0033CC33, 0x0066CC33, 0x0099CC33,
    0x00CCCC33, 0x00FFCC33, 0x0033FF33, 0x0066FF33, 0x0099FF33, 0x00CCFF33, 0x00FFFF33, 0x00000066,
    0x00330066, 0x00660066, 0x00990066, 0x00CC0066, 0x00FF0066, 0x00003366, 0x00333366, 0x00663366,
    0x00993366, 0x00CC3366, 0x00FF3366, 0x00006666, 0x00336666, 0x00666666, 0x00996666, 0x00CC6666,
    0x00009966, 0x00339966, 0x00669966, 0x00999966, 0x00CC9966, 0x00FF9966, 0x0000CC66, 0x0033CC66,
    0x0099CC66, 0x00CCCC66, 0x00FFCC66, 0x0000FF66, 0x0033FF66, 0x0099FF66, 0x00CCFF66, 0x00FF00CC,
    0x00CC00FF, 0x00009999, 0x00993399, 0x00990099, 0x00CC0099, 0x00000099, 0x00333399, 0x00660099,
    0x00CC3399, 0x00FF0099, 0x00006699, 0x00336699, 0x00663399, 0x00996699, 0x00CC6699, 0x00FF3399,
    0x00339999, 0x00669999, 0x00999999, 0x00CC9999, 0x00FF9999, 0x0000CC99, 0x0033CC99, 0x0066CC66,
    0x0099CC99, 0x00CCCC99, 0x00FFCC99, 0x0000FF99, 0x0033FF99, 0x0066CC99, 0x0099FF99, 0x00CCFF99,
    0x00FFFF99, 0x000000CC, 0x00330099, 0x006600CC, 0x009900CC, 0x00CC00CC, 0x00003399, 0x003333CC,
    0x006633CC, 0x009933CC, 0x00CC33CC, 0x00FF33CC, 0x000066CC, 0x003366CC, 0x00666699, 0x009966CC,
    0x00CC66CC, 0x00FF6699, 0x000099CC, 0x003399CC, 0x006699CC, 0x009999CC, 0x00CC99CC, 0x00FF99CC,
    0x0000CCCC, 0x0033CCCC, 0x0066CCCC, 0x0099CCCC, 0x00CCCCCC, 0x00FFCCCC, 0x0000FFCC, 0x0033FFCC,
    0x0066FF99, 0x0099FFCC, 0x00CCFFCC, 0x00FFFFCC, 0x003300CC, 0x006600FF, 0x009900FF, 0x000033CC,
    0x003333FF, 0x006633FF, 0x009933FF, 0x00CC33FF, 0x00FF33FF, 0x000066FF, 0x003366FF, 0x006666CC,
    0x009966FF, 0x00CC66FF, 0x00FF66CC, 0x000099FF, 0x003399FF, 0x006699FF, 0x009999FF, 0x00CC99FF,
    0x00FF99FF, 0x0000CCFF, 0x0033CCFF, 0x0066CCFF, 0x0099CCFF, 0x00CCCCFF, 0x00FFCCFF, 0x0033FFFF,
    0x0066FFCC, 0x0099FFFF, 0x00CCFFFF, 0x00FF6666, 0x0066FF66, 0x00FFFF66, 0x006666FF, 0x00FF66FF,
    0x0066FFFF, 0x00A50021, 0x005F5F5F, 0x00777777, 0x00868686, 0x00969696, 0x00CBCBCB, 0x00B2B2B2,
    0x00D7D7D7, 0x00DDDDDD, 0x00E3E3E3, 0x00EAEAEA, 0x00F1F1F1, 0x00F8F8F8, 0x00FFFBF0, 0x00004E98,
    0x00808080, 0x00FF0000, 0x0000FF00, 0x00FFFF00, 0x000000FF, 0x00FF00FF, 0x0000FFFF, 0x00FFFFFF
};

extern const unsigned char* m_get_splash_screen();

// +----------+
// | Settings |
// +----------+

static const char * achrs_node_main[] = {
    "vnc-shared-flag",           // 1
    "vnc-password-plain",        // 2
    "vnc-password-encrypted",    // 3
    "host-password-plain",       // 4
    "host-password-encrypted",   // 5
    "host-user",                 // 6
    "server-maps-keys",          // 7
    "server-maps-capslock",      // 8
    "vnc-version",               // 9
    "encryption",                // 10
    "use-local-cursor",          // 11
    "use-clipboard",             // 12
    "max-cut-text",              // 13
    "authentication",            // 14
    "show-splash-screen",        // 15
    "fbu-behavior"               // 16
};

#define DEF_XML_M_SHARED                   1    /* <vnc-shared-flag>        */
#define DEF_XML_M_VNC_PASSWORD_PLAIN       2    /* <vnc-password-plain>     */
#define DEF_XML_M_VNC_PASSWORD_ENCRYPTED   3    /* <vnc-password-plain>     */
#define DEF_XML_M_HOST_PASSWORD_PLAIN      4    /* <host-password-plain>    */
#define DEF_XML_M_HOST_PASSWORD_ENCRYPTED  5    /* <host-password-plain>    */
#define DEF_XML_M_HOST_USER                6    /* <host-user>              */
#define DEF_XML_M_SERVER_MAPS_KEYS         7    /* <server-maps-keys>       */
#define DEF_XML_M_SERVER_MAPS_CAPSLOCK     8    /* <server-maps-capslock>   */
#define DEF_XML_M_VNC_VERSION              9    /* <vnc-version>            */
#define DEF_XML_M_ENCRYTION               10    /* <encryption>             */
#define DEF_XML_M_LOCAL_CURSOR            11    /* <use-local-cursor>       */
#define DEF_XML_M_USE_CLIPBOARD           12    /* <use-clipboard>          */
#define DEF_XML_M_MAX_CUT_TEXT            13    /* <max-cut-text>           */
#define DEF_XML_M_AUTHENTICATION          14    /* <authentication>         */
#define DEF_XML_M_SHOW_SPLASH_SCREEN      15    /* <show-splash-screen>     */
#define DEF_XML_M_FBU_BEHAVIOR            16    /* <fbu-behavior>           */
#define DEF_XML_M_MAX                     16    /* number of entries        */

#ifdef DEBUG_110719_01                      /* fixed password           */
static unsigned char ucrs_pwd[8] = {
   'p', '1', '2', '3',
   'p', '1', '2', '3'
};
#endif

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

static inline short int m_get_be2( char * );
static void m_create_converter(dsd_gw_ctrl_1* adsl_session, c_colormodel& dsl_colormodel_rfb);
static bool m_create_colormap(dsd_sdh_call_1* dsl_sdh_call_1);
static bool m_create_converter_colormap(dsd_sdh_call_1* dsl_sdh_call_1);
static int m_sdh_printf( struct dsd_sdh_call_1 *, char *, ... );
static int m_sdh_printf_tl( struct dsd_sdh_call_1 *adsp_sdh_call_1, const char* ach_type, int in_line, char *achptext, ... );
static void m_rdp_send_splash_screen(dsd_sdh_call_1 *adsl_sdh_call_1);
static bool m_rfb_error(dsd_sdh_call_1 *adsl_sdh_call_1, const char* achl_function, int inl_line, bool bol_admin, const char* ach_message, ...);
static void m_rdp_printf(struct dsd_sdh_call_1 *adsp_sdh_call_1, char *achptext, ...);
static void m_sdh_console_out( struct dsd_sdh_call_1 *, char *, int );
static void m_keyevent_msg( char *, int, int );
static inline bool m_get_rdpcolour_int(int, int, unsigned int *);

static void m_clipboard_callback_format_list(void* avol_usrfld, int inl_number_formats, dsd_format_list_entry* adsl_format_list);
static bool m_clipboard_callback_copy_data_cb(void* avo_usrfld, dsd_gather_reader* ads_reader);
static bool m_clipboard_callback_on_paste_cb(void* avol_usrfld, dsd_format_list_entry* adsl_format);
static bool m_clipboard_callback_log(void* avo_usrfld, int in_lvl, const char *ach_fmt, int inl_bytes);
static dsd_sc_vch_out* m_clipboard_callback_get_rdpacc_command(void* avo_usrfld, int inl_addbytes_bytes);
static bool m_callback_get_mem (void* avo_usrfld, char** aach_memory, int inl_size);
static bool m_callback_free_mem(void* avo_usrfld, void*  avol_memory, int inl_size);

template<typename T> static inline void m_compare_and_copy(T* axx_dst, T* axx_src, int in_num_compare, T** aaxx_first_diff, T** aaxx_last_diff){
   *aaxx_first_diff = NULL;
   T* axx_end = axx_dst + in_num_compare;
   while(axx_dst < axx_end){
      if(*axx_dst != *axx_src){
         *aaxx_last_diff = axx_dst;
         if(*aaxx_first_diff == NULL)
            *aaxx_first_diff = *aaxx_last_diff;
         *axx_dst = *axx_src;
      }
      axx_dst++;
      axx_src++;
   }
}

// fill a number of bytes in a row, with the same colour value.
template<typename T> static inline void m_fill_row(T* axx_dst, T uxx_colour, int in_num){
   T* axx_end = axx_dst + in_num;
   while(axx_dst < axx_end){
      *axx_dst = uxx_colour;
      axx_dst++;
   }
}


// copying a row to multiple rows. 
template<typename T> static inline void m_copy_row(T* axx_src, int in_src_len_bytes, T* axx_dst, int in_write_reps, int in_write_step){
   while (in_write_reps > 0){
      memcpy( axx_dst, axx_src, in_src_len_bytes );    
      axx_dst += in_write_step;
      in_write_reps--;
   }
}

// Fill 64 x 64 pixels rectangle with same color
template<typename T> static inline void m_fill_rect(void* avol_screen_buffer, T uxl_color, 
   unsigned short usl_x, unsigned short usl_y, unsigned short usl_width, unsigned short usl_height, int inl_width_screen){
   T* axl_dst_start = ((T*) avol_screen_buffer) + usl_y * inl_width_screen + usl_x;
   // make one row
   T* axl_x_act = axl_dst_start;
   T* axl_x_end = axl_dst_start + usl_width;
   while(axl_x_act < axl_x_end){
      *axl_x_act++ = uxl_color;
   }
   // now copy this row
   T* axl_y_act = axl_dst_start + inl_width_screen;
   T* axl_y_end = axl_dst_start + usl_height * inl_width_screen;
   uint32_t uml_copy = usl_width * sizeof(T);
   while(axl_y_act < axl_y_end){
      memcpy(axl_y_act, axl_dst_start, uml_copy);
      axl_y_act += inl_width_screen;
   }
}


extern "C" void m_cdr_zlib_1_dec( struct dsd_cdr_ctrl * );  /* zLib record-oriented decode = decompression */

/*+-------------------------------------------------------------------+*/
/*| Entry for the Server-Data-Hook.                                   |*/
/*+-------------------------------------------------------------------+*/

/* subroutine to process the configuration data                        */
extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf( struct dsd_hl_clib_dom_conf *adsp_hlcldomf ) {
    BOOL       bol1;                         /* working variable        */
    int        iml1; //iml2, iml3;           /* working variables       */
    int        iml_cmp;                      /* compare values          */
    int        iml_val;                      /* value in array          */

    DOMNode    *adsl_node_1;                 /* node for navigation     */
    DOMNode    *adsl_node_2;                 /* node for navigation     */
    HL_WCHAR   *awcl_name;                   /* name of Node            */
    HL_WCHAR   *awcl_value;                  /* value of Node           */
    BOOL       borl_double[ DEF_XML_M_MAX ];  /* number of entries      */
    struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
    struct dsd_clib1_conf dsl_clco;          /* configuration data      */

//#if (defined HL_LINUX)
   int inl_minor_version;
   int in_i;
   int inl_major_version;
//#endif 

#ifdef TRACEHL1
     printf( "xl-rdps-rfbc-1-l%05d-T m_hlclib_conf() called adsp_hlcldomf=%p\n",
           __LINE__, adsp_hlcldomf );
#endif
    dsl_sdh_call_1.amc_aux = adsp_hlcldomf->amc_aux;  /* auxiliary subroutine */
    dsl_sdh_call_1.vpc_userfld = adsp_hlcldomf->vpc_userfld;  /* User Field Subroutine */
    dsl_sdh_call_1.adsc_orderqueue = NULL;
    dsl_sdh_call_1.adsc_ctrl_1 = NULL;

    M_SDH_PRINTF_I("V1.1 " __DATE__ " m_hlclib_conf() called" );
    
    if (adsp_hlcldomf->adsc_node_conf == NULL) {      
        M_SDH_PRINTF_W( "m_hlclib_conf() no Node configured");    
        return TRUE;
    }

    /* getFirstChild()                                                  */
    adsl_node_1 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsp_hlcldomf->adsc_node_conf,
        ied_hlcldom_get_first_child );
    if (adsl_node_1 == NULL) {               /* no Node returned        */
        M_SDH_PRINTF_W( "m_hlclib_conf() no getFirstChild()");
        return FALSE;
    }

    memset( &dsl_clco, 0, sizeof(struct dsd_clib1_conf) );  /* configuration data */
    memset( borl_double, 0, sizeof(borl_double) );  /* number of entries */

   // Dummy-values:
   dsl_clco.inc_major_version = MAX_POSSIBLE_VNC_MAJOR_VERSION;
   dsl_clco.inc_minor_version = MAX_POSSIBLE_VNC_MINOR_VERSION;
   dsl_clco.inc_sec_type_setting = 0;
   dsl_clco.inc_authentication_setting = ied_auth_setting_wsp_config;
   dsl_clco.boc_cursor_encoding = TRUE;
   dsl_clco.boc_use_clipboard = TRUE;
   dsl_clco.inc_max_size_clipbard = MAX_CLIPBARD_SIZE;

   dsl_clco.dsc_vnc_password.init();
   dsl_clco.dsc_host_password.init();
   dsl_clco.dsc_host_user.init();

pdomc20:                                 /* process DOM node        */
    if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_1, ied_hlcldom_get_node_type ))
        != DOMNode::ELEMENT_NODE) {
            goto pdomc80;                          /* get next sibling        */
    }
    awcl_name = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_1, ied_hlcldom_get_node_name );
#ifdef TRACEHL1
    printf( "xl-rdps-rfbc-1-l%05d-T m_hlclib_conf() found node %S\n", __LINE__, awcl_name );
#endif
    iml_val = sizeof(achrs_node_main) / sizeof(achrs_node_main[0]);
    do {
        bol1 = m_cmp_vx_vx( &iml_cmp,
            awcl_name, -1, ied_chs_utf_16,
            (void *) achrs_node_main[ iml_val - 1 ], -1, ied_chs_utf_8 );
        if ((bol1) && (iml_cmp == 0)) break;   /* strings are equal       */
        iml_val--;
    } while (iml_val > 0);
    if (iml_val == 0) {                      /* keyword not found       */ 
        M_SDH_PRINTF_W("Error first element name \"%(ux)s\" undefined - ignored", awcl_name );
        goto pdomc80;                          /* DOM node processed - next */
    }
    if (borl_double[ iml_val - 1 ]) {        /* already defined         */
        M_SDH_PRINTF_W( "Error element \"%(ux)s\" defined double - ignored", awcl_name );
    }
    adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_1,
        ied_hlcldom_get_first_child );  /* getFirstChild() */
    if (adsl_node_2 == NULL) {               /* no child found          */
        M_SDH_PRINTF_W( "Error \"%(ux)s\" has no child - ignored", awcl_name );
        goto pdomc80;                          /* DOM node processed - next */
    }
    while (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type ))
        != DOMNode::TEXT_NODE) {
            adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                ied_hlcldom_get_next_sibling );
            if (adsl_node_2 == NULL) {             /* cannot process DOM node stage 2 */
                M_SDH_PRINTF_W( "Error \"%(ux)s\" no value found - ignored", awcl_name );
                goto pdomc80;                        /* DOM node processed - next */
            }
    }
    awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_value );  /* getNodeValue() */
    switch (iml_val) {                       /* check keyword           */
     case DEF_XML_M_SHARED:                 /* <vnc-shared-flag>       */
         bol1 = m_cmp_vx_vx( &iml_cmp,
             awcl_value, -1, ied_chs_utf_16,
             (void *) "YES", -1, ied_chs_utf_8 );
         if ((bol1) && (iml_cmp == 0)) {      /* strings are equal       */
             dsl_clco.chc_co_shared = 1;        /* VNC-SHARED-FLAG         */
             break;
         }
         bol1 = m_cmp_vx_vx( &iml_cmp,
             awcl_value, -1, ied_chs_utf_16,
             (void *) "NO", -1, ied_chs_utf_8 );
         if ((bol1) && (iml_cmp == 0)) {      /* strings are equal       */
             dsl_clco.chc_co_shared = 0;        /* VNC-SHARED-FLAG         */
             break;
         }

         M_SDH_PRINTF_W( "Error Node \"%(ux)s\" value \"%(ux)s\" neither YES nor NO - ignored", awcl_name, awcl_value );
         goto pdomc80;                        /* DOM node processed - next */
     case DEF_XML_M_SERVER_MAPS_KEYS:
         dsl_clco.boc_server_maps_keys = FALSE;
         bol1 = m_cmp_vx_vx( &iml_cmp,
             awcl_value, -1, ied_chs_utf_16,
             (void *) "YES", -1, ied_chs_utf_8 );
         if ((bol1) && (iml_cmp == 0)) {      /* strings are equal       */
             dsl_clco.boc_server_maps_keys = TRUE;        /* server maps the keys on it's own       */
             break;
         }
         break;
     case DEF_XML_M_SERVER_MAPS_CAPSLOCK:
         dsl_clco.boc_server_maps_capslock = FALSE;
         bol1 = m_cmp_vx_vx( &iml_cmp,
             awcl_value, -1, ied_chs_utf_16,
             (void *) "YES", -1, ied_chs_utf_8 );
         if ((bol1) && (iml_cmp == 0)) {      /* strings are equal       */
             dsl_clco.boc_server_maps_capslock = TRUE;        /* server maps capslock        */
             break;
         }
         break;
      case DEF_XML_M_VNC_PASSWORD_PLAIN:               /* <vnc-password-plain>              */
         if(dsl_clco.inc_len_vnc_password > 0){
            M_SDH_PRINTF_W( "Error Node \"%(ux)s\" value \"%(ux)s\" password double - plain and encrypted - ignored!", awcl_name, awcl_value);
            goto pdomc80;                     
         }
         dsl_clco.inc_len_vnc_password = m_len_vx_vx( ied_chs_ascii_850,  /* ASCII 850            */
             awcl_value, -1, ied_chs_utf_16 );
         if (dsl_clco.inc_len_vnc_password > MAX_LEN_USER_PASSWORD) {       /* password too long       */
             M_SDH_PRINTF_W( &dsl_sdh_call_1, "xl-rdps-rfbc-1-%05d-W Error Node \"%(ux)s\" value \"%(ux)s\" length %d longer than allowed %d - ignored",
                 __LINE__, awcl_name, awcl_value, iml1, MAX_LEN_USER_PASSWORD );
             goto pdomc80;                      /* DOM node processed - next */
         }
         // If we convert to ied_chs_ansi_819, than REAL-VNC for windows can do ö's and ß's. But KB says, we don't need that right now. 
         dsl_clco.dsc_vnc_password.ensure_elements(dsl_clco.inc_len_vnc_password, m_callback_get_mem, m_callback_free_mem, &dsl_sdh_call_1);
         m_cpy_vx_vx( dsl_clco.dsc_vnc_password.get_data(), dsl_clco.inc_len_vnc_password, ied_chs_ascii_850,
             awcl_value, -1, ied_chs_utf_16 );
         break;
      case DEF_XML_M_VNC_PASSWORD_ENCRYPTED: {
         if(dsl_clco.inc_len_vnc_password > 0){
            M_SDH_PRINTF_W( "Error Node \"%(ux)s\" value \"%(ux)s\" password double - plain and encrypted - ignored!", awcl_name, awcl_value);
            goto pdomc80;                     
         }

         int inl_len = dsl_clco.inc_len_vnc_password = m_len_vx_vx(ied_chs_ascii_850, awcl_value, -1, ied_chs_utf_16);
         int inl_len_pad3 = (inl_len + 3) / 4 * 3;
         dsl_clco.dsc_vnc_password.ensure_elements(inl_len_pad3, m_callback_get_mem, m_callback_free_mem, &dsl_sdh_call_1);

         dsd_unicode_string dsl_ucs;
         dsl_ucs.ac_str = awcl_value;
         dsl_ucs.iec_chs_str = ied_chs_utf_16;
         dsl_ucs.imc_len_str = inl_len;
         int inl_err;
         int inl_err_pos;
         dsl_clco.inc_len_vnc_password = m_get_ucs_base64(&inl_err, &inl_err_pos, dsl_clco.dsc_vnc_password.get_data(), inl_len_pad3, &dsl_ucs);
         if(dsl_clco.inc_len_vnc_password < 0){
            M_SDH_PRINTF_W( "Error Node \"%(ux)s\" value \"%(ux)s\" decrypting password error %d position %d!", awcl_name, awcl_value, inl_err, inl_err_pos);
            dsl_clco.inc_len_vnc_password = 0;
            goto pdomc80;    
         }
         
      } break;

      case DEF_XML_M_HOST_PASSWORD_PLAIN:
         if(dsl_clco.inc_len_host_password > 0){
            M_SDH_PRINTF_W( "Error Node \"%(ux)s\" value \"%(ux)s\" password double - plain and encrypted - ignored!", awcl_name, awcl_value);
            goto pdomc80;                     
         }
         dsl_clco.inc_len_host_password = m_len_vx_vx( ied_chs_ascii_850, awcl_value, -1, ied_chs_utf_16 );
         if (dsl_clco.inc_len_host_password > MAX_LEN_USER_PASSWORD) {       /* password too long       */

             M_SDH_PRINTF_W( "Error Node \"%(ux)s\" value \"%(ux)s\" length %d longer than allowed %d - ignored",
                 awcl_name, awcl_value, dsl_clco.inc_len_host_password, LEN_RBF_PASSWORD );
             goto pdomc80;                      /* DOM node processed - next */
         }
         dsl_clco.dsc_host_password.ensure_elements(dsl_clco.inc_len_host_password, m_callback_get_mem, m_callback_free_mem, &dsl_sdh_call_1);
         m_cpy_vx_vx( dsl_clco.dsc_host_password.get_data(), dsl_clco.inc_len_host_password, ied_chs_ascii_850,
             awcl_value, -1, ied_chs_utf_16 );
         break;
         if(dsl_clco.inc_len_vnc_password > 0){
            M_SDH_PRINTF_W( "Error Node \"%(ux)s\" value \"%(ux)s\" password double - plain and encrypted - ignored!", awcl_name, awcl_value);
            goto pdomc80;                     
         }

      case DEF_XML_M_HOST_PASSWORD_ENCRYPTED: {
         int inl_len = dsl_clco.inc_len_host_password = m_len_vx_vx(ied_chs_ascii_850, awcl_value, -1, ied_chs_utf_16);
         int inl_len_pad3 = (inl_len + 3) / 4 * 3;
         dsl_clco.dsc_host_password.ensure_elements(inl_len_pad3, m_callback_get_mem, m_callback_free_mem, &dsl_sdh_call_1);

         dsd_unicode_string dsl_ucs;
         dsl_ucs.ac_str = awcl_value;
         dsl_ucs.iec_chs_str = ied_chs_utf_16;
         dsl_ucs.imc_len_str = inl_len;
         int inl_err;
         int inl_err_pos;
         dsl_clco.inc_len_host_password = m_get_ucs_base64(&inl_err, &inl_err_pos, dsl_clco.dsc_host_password.get_data(), inl_len_pad3, &dsl_ucs);
         if(dsl_clco.inc_len_host_password < 0){
            M_SDH_PRINTF_W( "Error Node \"%(ux)s\" value \"%(ux)s\" decrypting password error %d position %d!", awcl_name, awcl_value, inl_err, inl_err_pos);
            dsl_clco.inc_len_host_password = 0;
            goto pdomc80;    
         }
      } break;
      case DEF_XML_M_HOST_USER:
         dsl_clco.inc_len_host_user = m_len_vx_vx( ied_chs_ascii_850,  /* ASCII 850            */
             awcl_value, -1, ied_chs_utf_16 );
         if (dsl_clco.inc_len_host_user > MAX_LEN_USER_PASSWORD) {       /* password too long       */

             M_SDH_PRINTF_W( "Error Node \"%(ux)s\" value \"%(ux)s\" length %d longer than allowed %d - ignored",
                 awcl_name, awcl_value, dsl_clco.inc_len_host_user, LEN_RBF_PASSWORD );
             goto pdomc80;                      /* DOM node processed - next */
         }
         dsl_clco.dsc_host_user.ensure_elements(dsl_clco.inc_len_host_user, m_callback_get_mem, m_callback_free_mem, &dsl_sdh_call_1);
         m_cpy_vx_vx( dsl_clco.dsc_host_user.get_data(), dsl_clco.inc_len_host_user, ied_chs_ascii_850,
             awcl_value, -1, ied_chs_utf_16 );
         break;

     case DEF_XML_M_VNC_VERSION: {
         unsigned char uch_work[0x100];
         iml1 = m_len_vx_vx( ied_chs_ascii_850, awcl_value, -1, ied_chs_utf_16 ); /* ASCII 850            */
         if(iml1 > 0x100)
            goto pdomc_version_error;
         m_cpy_vx_vx( uch_work, iml1, ied_chs_ascii_850, awcl_value, -1, ied_chs_utf_16 );

         // Get major version
//#if !(defined HL_LINUX)
//         int inl_major_version = 0;
//         int in_i = 0;
//#else
         inl_major_version = 0;
         in_i = 0;
//#endif
         while(true){
            char ch_digit = uch_work[in_i];
            if(ch_digit == '.')
               break;
            if((ch_digit < '0') || (ch_digit > '9'))
               goto pdomc_version_error;
            inl_major_version *= 10;
            inl_major_version += ch_digit - '0';
            in_i++;
            if(in_i >= iml1)
               break;            // no minor version
         }
         // Get minor version
//#if !(defined HL_LINUX)
//         int inl_minor_version = 0;
//#else
         inl_minor_version = 0;
//#endif 
         in_i++;
         while(in_i < iml1){
            char ch_digit = uch_work[in_i];
            if((ch_digit < '0') || (ch_digit > '9'))
               goto pdomc_version_error;
            inl_minor_version *= 10;
            inl_minor_version += ch_digit - '0';
            in_i++;
         }

         if(inl_major_version > MAX_POSSIBLE_VNC_MAJOR_VERSION){
            inl_major_version = MAX_POSSIBLE_VNC_MAJOR_VERSION;
            inl_minor_version = MAX_POSSIBLE_VNC_MINOR_VERSION;
         } else if(inl_major_version == MAX_POSSIBLE_VNC_MAJOR_VERSION){
            if(inl_minor_version > MAX_POSSIBLE_VNC_MINOR_VERSION)
               inl_minor_version = MAX_POSSIBLE_VNC_MINOR_VERSION;
         } else {
            if(inl_minor_version > 999)
               inl_minor_version = 999;
         }
         
         dsl_clco.inc_major_version = inl_major_version;
         dsl_clco.inc_minor_version = inl_minor_version;
         break;
pdomc_version_error:
          m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-%05d-W Error Node \"%(ux)s\" value \"%(ux)s\" unknown format. Use \"3.007\". Ignored",
              __LINE__, awcl_name, awcl_value );

          goto pdomc80;                      /* DOM node processed - next */
       } break;
     case DEF_XML_M_ENCRYTION: {
         unsigned char uch_work[0x100];
         iml1 = m_len_vx_vx( ied_chs_ascii_850, awcl_value, -1, ied_chs_utf_16 ); /* ASCII 850            */
         uch_work[0xFF] = 0;
         if(iml1 >= 0x100)
            goto pdomc_encrytion_error;                               
         m_cpy_vx_vx( uch_work, iml1, ied_chs_ascii_850, awcl_value, -1, ied_chs_utf_16 );

         for(int inl_i = 0; inl_i < (sizeof(dsds_security_type_settings) / sizeof(dsd_security_type_setting)); inl_i++){
            if(memcmp(uch_work, achrs_security_type_settings[inl_i], strlen(achrs_security_type_settings[inl_i])) == 0){
               dsl_clco.inc_sec_type_setting = inl_i;
               break;
            }
         }

pdomc_encrytion_error:
          M_SDH_PRINTF_W( "Error Node \"%(ux)s\" value \"%(ux)s\" unknown format. Ignored.", awcl_name, awcl_value );
     } break;
      case DEF_XML_M_LOCAL_CURSOR:
         bol1 = m_cmp_vx_vx( &iml_cmp,
             awcl_value, -1, ied_chs_utf_16,
             (void *) "NO", -1, ied_chs_utf_8 );
         if ((bol1) && (iml_cmp == 0)) {                  /* strings are equal       */
             dsl_clco.boc_cursor_encoding = FALSE;        /* RFB-pseudo-cursor-encoding is not supported      */
             break;
         }
         break;

      case DEF_XML_M_USE_CLIPBOARD:
         bol1 = m_cmp_vx_vx( &iml_cmp,
             awcl_value, -1, ied_chs_utf_16,
             (void *) "NO", -1, ied_chs_utf_8 );
         if ((bol1) && (iml_cmp == 0)) {                  /* strings are equal       */
             dsl_clco.boc_use_clipboard = FALSE;          /* clipboard is not used   */
             break;
         }
         break;

      case DEF_XML_M_MAX_CUT_TEXT: {
         int inl_max_size = m_get_wc_number( awcl_value ) * 0x400;  /* max size of clipbard */
         if(inl_max_size > 0){     /* value is valid        */
            if(inl_max_size > MAX_CLIPBARD_SIZE)
               inl_max_size = MAX_CLIPBARD_SIZE;
            dsl_clco.inc_max_size_clipbard = inl_max_size;
            break;
         }
         M_SDH_PRINTF_W( &dsl_sdh_call_1, "xl-rdps-rfbc-1-%05d-W Error Node \"%(ux)s\" value \"%(ux)s\" not valid number greater zero - ignored",
             __LINE__, awcl_name, awcl_value );
      } break;

      case DEF_XML_M_AUTHENTICATION:{
         unsigned char uchrl_work[0x100];
         iml1 = m_len_vx_vx( ied_chs_ascii_850, awcl_value, -1, ied_chs_utf_16 ); /* ASCII 850            */
         uchrl_work[0xFF] = 0;
         if(iml1 >= 0x100)
            goto pdomc_encrytion_error;                               
         m_cpy_vx_vx( uchrl_work, iml1, ied_chs_ascii_850, awcl_value, -1, ied_chs_utf_16 );

         for(int inl_i = 0; inl_i < (sizeof(achrs_authentication_settings) / sizeof(char*)); inl_i++){
            if(memcmp(uchrl_work, achrs_authentication_settings[inl_i], strlen(achrs_authentication_settings[inl_i])) == 0){
               dsl_clco.inc_authentication_setting = inl_i;
               break;
            }
         }

      } break; 

      case DEF_XML_M_SHOW_SPLASH_SCREEN: {
         dsl_clco.inc_show_splash_screen = m_get_wc_number( awcl_value );
         if(dsl_clco.inc_show_splash_screen > 60)
            dsl_clco.inc_show_splash_screen = 60;
      } break;

      case DEF_XML_M_FBU_BEHAVIOR: {
         dsl_clco.inc_fbu_behavior = m_get_wc_number( awcl_value );
      } break;
   }
   borl_double[ iml_val - 1 ] = TRUE;       /* set already defined     */

pdomc80:                                 /* DOM node processed - next */
    adsl_node_1 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_1,
        ied_hlcldom_get_next_sibling );
    if (adsl_node_1) goto pdomc20;           /* process DOM node        */

    /* check if something configured                                    */
    iml1 = DEF_XML_M_MAX;
    do {
        if (borl_double[ iml1 - 1 ]) break;    /* is defined              */
        iml1--;                                /* decrement index         */
    } while (iml1 > 0);
    if (iml1 = 0) {                          /* no value configured     */

        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-%05d-W no valid values found in configuration - ignored",
            __LINE__ );
        return TRUE;
    }
#define AADSL_STOR_NEW adsp_hlcldomf->aac_conf
    bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
        DEF_AUX_MEMGET,
        AADSL_STOR_NEW,
        sizeof(struct dsd_clib1_conf) );
    if (bol1 == FALSE) {                     /* error occured           */
        M_SDH_PRINTF_W( &dsl_sdh_call_1, "xl-rdps-rfbc-1-%05d-W Error in DEF_AUX_MEMGET amc_aux call", __LINE__ );
        return FALSE;
    }

   dsd_clib1_conf* adsl_conf_dst = (dsd_clib1_conf*) *AADSL_STOR_NEW;
   memcpy( *AADSL_STOR_NEW, &dsl_clco, sizeof(struct dsd_clib1_conf) );
   if(dsl_clco.inc_authentication_setting == ied_auth_setting_wsp_config){
      adsl_conf_dst->dsc_vnc_password.init_and_copyfrom (&dsl_clco.dsc_vnc_password,  m_callback_get_mem, &dsl_sdh_call_1);
      adsl_conf_dst->dsc_host_password.init_and_copyfrom(&dsl_clco.dsc_host_password, m_callback_get_mem, &dsl_sdh_call_1);
      adsl_conf_dst->dsc_host_user.init_and_copyfrom    (&dsl_clco.dsc_host_user,     m_callback_get_mem, &dsl_sdh_call_1);
   } else {
      // If authentication infos come from RDP or RD VPN, clear passwords.
      adsl_conf_dst->inc_len_host_password = 0;
      adsl_conf_dst->inc_len_host_user     = 0;
      adsl_conf_dst->inc_len_vnc_password  = 0;
      adsl_conf_dst->dsc_vnc_password.init();
      adsl_conf_dst->dsc_host_password.init();
      adsl_conf_dst->dsc_host_user.init();
   }
   dsl_clco.dsc_vnc_password.close (m_callback_free_mem, &dsl_sdh_call_1, true);
   dsl_clco.dsc_host_password.close(m_callback_free_mem, &dsl_sdh_call_1, true);
   dsl_clco.dsc_host_user.close    (m_callback_free_mem, &dsl_sdh_call_1, true);

#ifdef TRACEHL1
    m_sdh_console_out( &dsl_sdh_call_1,
        (char *) *AADSL_STOR_NEW,
        sizeof(struct dsd_clib1_conf) );
#endif
    return TRUE;
#undef AADSL_STOR_NEW
} /* end m_hlclib_conf()   */

extern "C" HL_DLL_PUBLIC void m_hlclib01( struct dsd_hl_clib_1 *adsp_hl_clib_1 ) {
    BOOL       bol1;                         /* working variable        */
    int        iml1, iml2, iml3, iml4, iml5;  /* working variables      */
    unsigned char ucl_w1;                    /* working variables       */
    int        iml_rdp_prot_1;               /* RDP protocol status     */
    int        iml_ineta_len;                /* length INETA            */
    int        iml_port;                     /* port to connect to      */
    int        iml_co_ssl;                   /* SSL requested           */
    int        iml_co_shared;                /* VNC-SHARED-FLAG         */
    BOOL       bol_co_password;              /* password found          */
    int        inl_bpp_rfb;                  // bytes per pixel rfb     
    int        inl_bpp_rdp;                  // bytes per pixel rdb    
    int        iml_pixel_input;              /* length pixel input      */
    int        iml_draw_line;                /* current line to draw    */
    BOOL       bol_cont;                     /* continue call RDP server */
    char achl_rfb_colour[4];                 /* hold 1 rfb pixel         */
    uint32_t   uml_color_rfb;                 /* also hold 1 rfb pixel :-) */
    char achl_rdp_colour[4];                 /* hold 1 rdp pixel         */
    unsigned int uml_colour;                 /* rdp colour               */

//#if (defined HL_LINUX)
   const char* achl_auth_from;
   char* ach_first_diff;
   int inl_consumed;
   int inl_num_bytes_out;
   int inl_rest_pixels_line;
   int inl_rest_pixels_tile;
   int inl_num_tile;
   int inl_num_pixels;
   int iml_bpp;
   dsd_sc_order_scrblt* ads_scrblt;

   dsd_sc_mpoi_pointer* ads_rdp_pointer;
   int inl_skip_bytes;
   int inl_copy_bytes;
   int inl_parse_bytes;
   char* achl_and_mask;
   int in_len_and_mask;
   int inl_padd_width_bytes_and;
   char* achl_xor_mask;
   int in_len_xor_mask;
   int inl_padd_height;
   int inl_padd_width_bytes;
   int inl_padd_width;
   int inl_cursor_height;
   int inl_cursor_width;
   int inl_max_cursor_height;
   int inl_max_cursor_width;
   int inl_bytes_needed;
   dsd_sc_order_opaquerect* ads_opaquerect;
   uint32_t uml_color;

   dsd_change_screen* ads_change_screen;

   int inl_len_new_input=0;

   bool bol_ret;
   dsd_gather_reader dsl_input(adsp_hl_clib_1->adsc_gather_i_1_in);
   dsd_gather_reader dsl_input_dec(&dsl_input, inl_len_new_input, &bol_ret);


//#endif 

#ifdef TRACEHL1
    char       chl1;                         /* working variable        */
#endif
    enum ied_state_rfc_client_1 iel_srfbc_temp;  /* state of this RFC client */
    char       *achl1, *achl2, *achl3, *achl4;  /* working variables    */
    char       *achl_work_1;
    char       *achl_work_2;
    char       *achl_ineta_start;            /* start of INETA          */
    char       *achl_pixel_input;            /* byte pixel input        */
    int        *aiml_w1;                     /* working variable        */

#if !defined B140825DD
    union {
        struct {
            unsigned char *aucl_fu_line;         /* framebuffer update start of line    */
            unsigned char *aucl_fu_cur;          /* framebuffer update current position */
            unsigned char *aucl_fu_end;          /* framebuffer update current position */
            unsigned char *aucl_fu_ch_start;     /* framebuffer update changes start    */
            unsigned char *aucl_fu_ch_end;       /* framebuffer update changes end      */
        };
        struct {
            unsigned short int *ausl_fu_line;        /* framebuffer update start of line    */
            unsigned short int *ausl_fu_cur;         /* framebuffer update current position */
            unsigned short int *ausl_fu_end;         /* framebuffer update current position */
            unsigned short int *ausl_fu_ch_start;    /* framebuffer update changes start    */
            unsigned short int *ausl_fu_ch_end;      /* framebuffer update changes end      */
        };
        struct {
            unsigned int *auml_fu_line;          /* framebuffer update start of line    */
            unsigned int *auml_fu_cur;           /* framebuffer update current position */
            unsigned int *auml_fu_end;           /* framebuffer update current position */
            unsigned int *auml_fu_ch_start;      /* framebuffer update changes start    */
            unsigned int *auml_fu_ch_end;        /* framebuffer update changes end      */
        };
    } usl_framebuffer_update;
#else
            unsigned char *aucl_fu_line;         /* framebuffer update start of line    */
            unsigned char *aucl_fu_cur;          /* framebuffer update current position */
            unsigned char *aucl_fu_end;          /* framebuffer update current position */
            unsigned char *aucl_fu_ch_start;     /* framebuffer update changes start    */
            unsigned char *aucl_fu_ch_end;       /* framebuffer update changes end      */
            unsigned short int *ausl_fu_line;        /* framebuffer update start of line    */
            unsigned short int *ausl_fu_cur;         /* framebuffer update current position */
            unsigned short int *ausl_fu_end;         /* framebuffer update current position */
            unsigned short int *ausl_fu_ch_start;    /* framebuffer update changes start    */
            unsigned short int *ausl_fu_ch_end;      /* framebuffer update changes end      */
            unsigned int *auml_fu_line;          /* framebuffer update start of line    */
            unsigned int *auml_fu_cur;           /* framebuffer update current position */
            unsigned int *auml_fu_end;           /* framebuffer update current position */
            unsigned int *auml_fu_ch_start;      /* framebuffer update changes start    */
            unsigned int *auml_fu_ch_end;        /* framebuffer update changes end      */
#endif 

    struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
    struct dsd_gather_i_1 *adsl_gai1_inp_1;  /* input data              */
    struct dsd_gather_i_1 *adsl_gai1_inp_2;  /* input data              */
    struct dsd_gather_i_1 *adsl_gai1_inp_3;  /* input data              */

    struct dsd_gather_i_1 *adsl_gai1_out_1;  /* output data             */
    struct dsd_gather_i_1 *adsl_gai1_out_client;  /* output data to client */
    struct dsd_gather_i_1 *adsl_gai1_out_server;  /* output data to client */
    struct dsd_gather_i_1 **aadsl_gai1_w1;   /* pointer to output data  */
    struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
    struct dsd_aux_get_workarea dsl_aux_get_workarea;  /* acquire additional work area */
    struct dsd_aux_tcp_conn_1 dsl_tc1_l;     /* TCP Connect to Server   */
    int    imrl_des_key_array[ DES_SUBKEY_ARRAY_SIZE ];


#ifndef PROCESS_RRE_IMMEDIATELY
    union {                  
        char   chrl_work1[ 4 * 0x1000 ];              /* work area               */
        struct dsd_aux_get_session_info dsl_agsi;  /* get information about the session */
    };
    struct dsd_out_rre_opaquerect {         /*Structure used to reserve memory for a linked list of opaque rect commands */
        struct dsd_sc_co1 dsc_sc_co1;                       /* server component command */             
        struct dsd_sc_order_opaquerect dsc_sc_opaquerect;   /* draw opaque rectangle parameters */
    }dsl_out_rre_opaquerect; 


#else // include dsl_out_rre_opaqurect in union
 union {                  
        char   chrl_work1[ 512 ];              /* work area               */
        struct dsd_aux_get_session_info dsl_agsi;  /* get information about the session */
        struct {
            char     chrl_colormodel_rfb[ sizeof(class c_colormodel) ];
            char     chrl_colormodel_rdp[ sizeof(class c_colormodel) ];
            struct dsd_out_dap {                       /* demand active PDU       */
                struct dsd_sc_co1 dsc_sc_co1;          /* server component command */
                struct dsd_d_act_pdu dsc_d_act_pdu;    /* send demand active PDU  */
                struct dsd_sc_draw_sc dsc_sc_draw_sc;  /* coordinates draw        */
            } dsl_out_dap;
        };
        struct dsd_out_dsc {                       /* draw screen              */
            struct dsd_sc_co1 dsc_sc_co1;          /* server component command */
            struct dsd_sc_draw_sc dsc_sc_draw_sc;  /* coordinates draw         */
        } dsl_out_dsc;
        struct dsd_out_scrblt {                         /* copy rect                */
            struct dsd_sc_co1 dsc_sc_co1;               /* server component command */
            struct dsd_sc_order_scrblt dsc_sc_scrblt;   /* copy rect parameters     */
        }dsl_out_scrblt;
        struct dsd_out_rre_opaquerect {         /*Structure used to reserve memory for a linked list of opaque rect commands */
            struct dsd_sc_co1 dsc_sc_co1;                       /* server component command */
            struct dsd_sc_order_opaquerect dsc_sc_opaquerect;   /* draw opaque rectangle parameters */
        }dsl_out_rre_opaquerect;
    }; //end union
   
    //Structure used to fill the opaquerect commands linked-list
    struct dsd_out_rre_subrect_opaquerect{
        struct dsd_sc_co1 dsc_sc_co1;                       /* server component command */
        struct dsd_sc_order_opaquerect dsc_sc_opaquerect;   /* draw opaque rectangle parameters */
    };

#endif

    char       chrl_work2[ 16 * 1024 ];      /* work area               */

    char       *achl_rre_work_1;
    char       *achl_rre_work_2;

    unsigned char uc_flags;
    signed char uc_key;
    enum ied_keymapping_return iel_return;
    int iml_xkcode;
    BOOL bol_turnoff_aes_encryption_after_sending = FALSE;
    struct dsd_gw_ctrl_1* adsl_session = NULL;
    bool bol_return_to_copyrect = false; 
  
   // Init aux-function and userfield for RDPACC
   dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */

#ifdef TRACEHL1
    {
        char *achh_text = "invalid function";
        switch (adsp_hl_clib_1->inc_func) {
    case DEF_IFUNC_START:
        achh_text = "DEF_IFUNC_START";
        break;
    case DEF_IFUNC_CLOSE:
        achh_text = "DEF_IFUNC_CLOSE";
        break;
    case DEF_IFUNC_FROMSERVER:
        achh_text = "DEF_IFUNC_FROMSERVER";
        break;
    case DEF_IFUNC_TOSERVER:
        achh_text = "DEF_IFUNC_TOSERVER";
        break;
    case DEF_IFUNC_REFLECT:
        achh_text = "DEF_IFUNC_REFLECT";
        break;
        }
        iml1 = iml2 = 0;                       /* length input data       */
        adsl_gai1_inp_1 = adsp_hl_clib_1->adsc_gather_i_1_in;
        bol1 = FALSE;
        chl1 = 0;
        while (adsl_gai1_inp_1) {
            iml2++;
            iml1 += adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
            if (   (adsl_gai1_inp_1->achc_ginp_end > adsl_gai1_inp_1->achc_ginp_cur)
                && (bol1 == FALSE)) {
                    chl1 = *adsl_gai1_inp_1->achc_ginp_cur;
                    bol1 = TRUE;
            }
            adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
        }
        M_SDH_PRINTF_T( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-T m_hlclib01() called inc_func=%d %s input=%p len=%d pieces=%d cont=0X%02X.",
            __LINE__, adsp_hl_clib_1->inc_func, achh_text,
            adsp_hl_clib_1->adsc_gather_i_1_in, iml1, iml2, (unsigned char) chl1 );
    }
#endif
    
    
    switch (adsp_hl_clib_1->inc_func) {
    case DEF_IFUNC_START: 
        goto p_ifunc_start_00;
    
    case DEF_IFUNC_CLOSE:
        goto p_ifunc_close_00; 

    default:
        goto p_ifunc_default_00;
    }// end switch (adsp_hl_clib_1->inc_func)
         
      

p_ifunc_start_00:

 //Start of ifunc_start block   

    bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
        DEF_AUX_MEMGET,
        &adsp_hl_clib_1->ac_ext,
        sizeof(struct dsd_gw_ctrl_1) );
    if (bol1 == FALSE) {
        ERROR_MACRO("Failed to allocate memory for the Session Control Structure");           

    }
    memset( adsp_hl_clib_1->ac_ext, 0, sizeof(struct dsd_gw_ctrl_1) );
    bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
        DEF_AUX_GET_SESSION_INFO,  /* get information about the session */
        &dsl_agsi,  /* get information about the session */
        sizeof(struct dsd_aux_get_session_info) );
    if (bol1 == FALSE) {
        ERROR_MACRO("Failed to allocate memory for the Session Info Structure"); 
    }
    if (dsl_agsi.iec_ass == ied_ass_invalid) {  /* invalid          */
        ERROR_MACRO("dsl_agsi.iec_ass == ied_ass_invalid"); 
    }

   dsl_sdh_call_1.adsc_ctrl_1 = (struct dsd_gw_ctrl_1 *) adsp_hl_clib_1->ac_ext;
   adsl_session = dsl_sdh_call_1.adsc_ctrl_1;  /* for addressing the data */

    if (dsl_agsi.iec_ass != ied_ass_not_conf) {  /* not server not configured */
        adsl_session->boc_server_connected = TRUE;  /* connected to server */
        adsl_session->iec_scc1 = ied_scc1_conn_act;  /* connection is active */
        adsl_session->chc_co_shared = 1;        /* VNC-SHARED-FLAG         */
    }
    adsl_session->boc_csssl = dsl_agsi.boc_csssl;  /* with client-side SSL */
    // EAX-structure needs to be aligned by 16 bytes, so we set the pointer here. 
    adsl_session->adsc_eax_dec = (dsd_eax_ctx*)(((long long int)(adsl_session->chr_eax_dec + 0xf)) & (0 - 0x10));
    adsl_session->adsc_eax_enc = (dsd_eax_ctx*)(((long long int)(adsl_session->chr_eax_enc + 0xf)) & (0 - 0x10));

#define ADSL_CONF ((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)
#ifndef DEBUG_110719_01                     /* fixed password          */
    if (ADSL_CONF == NULL) return;
#else
   if (ADSL_CONF == NULL) {
      adsl_session->inc_len_vnc_password = NORM_LEN_RBF_PASSWORD;
      adsl_session->inc_major_version = MAX_POSSIBLE_VNC_MAJOR_VERSION;
      adsl_session->inc_minor_version = MAX_POSSIBLE_VNC_MINOR_VERSION;
      adsl_session->inc_sec_type_setting = 0;
      adsl_session->inc_authentication_setting = adsl_session->boc_server_connected ? ied_auth_setting_rdp : ied_auth_setting_dynamic;
      adsl_session->boc_cursor_encoding = TRUE;
      adsl_session->boc_use_clipboard = TRUE;
      adsl_session->inc_max_size_clipbard = MAX_CLIPBARD_SIZE;
      adsl_session->dsc_vnc_password.init();
      adsl_session->dsc_host_password.init();
      adsl_session->dsc_host_user.init();
      memcpy( adsl_session->dsc_vnc_password.get_data(), ucrs_pwd, NORM_LEN_RBF_PASSWORD);
      adsl_session->inc_show_splash_screen = 0;
      adsl_session->inc_fbu_behavior = 0;
      return;
   }
#endif
   adsl_session->inc_authentication_setting = adsl_session->boc_server_connected ? ADSL_CONF->inc_authentication_setting : ied_auth_setting_dynamic;
   if(adsl_session->inc_authentication_setting == ied_auth_setting_wsp_config){
      adsl_session->inc_len_vnc_password       = ADSL_CONF->inc_len_vnc_password;
      adsl_session->dsc_vnc_password.init_and_copyfrom(&ADSL_CONF->dsc_vnc_password, m_callback_get_mem, &dsl_sdh_call_1);
      adsl_session->inc_len_host_password      = ADSL_CONF->inc_len_host_password;
      adsl_session->dsc_host_password.init_and_copyfrom(&ADSL_CONF->dsc_host_password, m_callback_get_mem, &dsl_sdh_call_1);
      adsl_session->inc_len_host_user          = ADSL_CONF->inc_len_host_user;
      adsl_session->dsc_host_user.init_and_copyfrom(&ADSL_CONF->dsc_host_user, m_callback_get_mem, &dsl_sdh_call_1);
   } else {
      adsl_session->dsc_vnc_password.init();
      adsl_session->dsc_host_password.init();
      adsl_session->dsc_host_user.init();
   }
   adsl_session->chc_co_shared              = ADSL_CONF->chc_co_shared;  /* VNC-SHARED-FLAG */
   adsl_session->boc_server_maps_keys       = ADSL_CONF->boc_server_maps_keys;
   adsl_session->boc_server_maps_capslock   = ADSL_CONF->boc_server_maps_capslock;
   adsl_session->inc_major_version          = ADSL_CONF->inc_major_version;
   adsl_session->inc_minor_version          = ADSL_CONF->inc_minor_version;
   adsl_session->inc_sec_type_setting       = ADSL_CONF->inc_sec_type_setting;
   adsl_session->boc_cursor_encoding        = ADSL_CONF->boc_cursor_encoding;
   adsl_session->boc_use_clipboard          = ADSL_CONF->boc_use_clipboard;
   adsl_session->inc_max_size_clipbard      = ADSL_CONF->inc_max_size_clipbard;
   adsl_session->inc_show_splash_screen     = ADSL_CONF->inc_show_splash_screen;
   adsl_session->inc_fbu_behavior           = ADSL_CONF->inc_fbu_behavior;

   // Init memory to save decrypted data
   adsl_session->achc_mem_data = NULL;
   adsl_session->inc_size_mem  = 0;
   adsl_session->inc_len_mem_data  = 0;

   return;
#undef ADSL_CONF

//End of ifunc_start block     
    

p_ifunc_close_00:
// start of case DEF_IFUNC_CLOSE
    goto p_cleanup_00;                   /* do clean-up             */
//end of case DEF_IFUNC_CLOSE


p_ifunc_default_00: {
    
   // Init session
   dsl_sdh_call_1.adsc_ctrl_1 = (struct dsd_gw_ctrl_1 *) adsp_hl_clib_1->ac_ext;
   adsl_session = dsl_sdh_call_1.adsc_ctrl_1;  /* for addressing the data */

   // Init orderqueue for RDPACC
   dsd_dummy_workareaprovider dsl_vnc_wa_provider(adsp_hl_clib_1->amc_aux, adsp_hl_clib_1->vpc_userfld);
   dsd_rdpacc_orderqueue dsl_orderqueue(&dsl_vnc_wa_provider);
   dsl_sdh_call_1.adsc_orderqueue = &dsl_orderqueue;

  // Init 
   adsl_session->dsc_crdps_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* pointer for this session */
   adsl_session->dsc_crdps_1.adsc_gather_i_1_in = NULL;
   achl_work_1 = adsp_hl_clib_1->achc_work_area;  /* addr work-area    */
   achl_work_2 = achl_work_1 + adsp_hl_clib_1->inc_len_work_area;  /* length work-area */
   adsl_gai1_out_client = NULL;             /* output data to client   */
   adsl_gai1_out_server = NULL;             /* output data to server   */
   adsl_gai1_inp_1 = adsp_hl_clib_1->adsc_gather_i_1_in;
    

    switch(adsl_session->iec_scc1){
        case ied_scc1_conn_act:     /* connection is active */
            goto p_session_00;      /* RFB session exists      */
        case ied_scc1_wait_conn:    /* wait for CONNECT command from client */
            goto p_conn_20;         /* connection part two     */
        default:

            adsl_session->iec_scc1 = ied_scc1_wait_conn;  /* wait for CONNECT command from client */
            achl1 = (char *) ucrs_out_no_server_rfb_n;
            iml1 = sizeof(ucrs_out_no_server_rfb_n);
            if (adsl_session->boc_csssl) {                /* with client-side SSL    */
                achl1 = (char *) ucrs_out_no_server_rfb_ssl;
                iml1 = sizeof(ucrs_out_no_server_rfb_ssl);
            }
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) adsp_hl_clib_1->achc_work_area)
            memset( ADSL_GAI1_G, 0, sizeof(struct dsd_gather_i_1) );
            ADSL_GAI1_G->achc_ginp_cur = achl1;
            ADSL_GAI1_G->achc_ginp_end = achl1 + iml1;

            adsp_hl_clib_1->adsc_gai1_out_to_client = ADSL_GAI1_G;  /* output data to client */
            return;
#undef ADSL_GAI1_G
    } //end switch (adsl_session->iec_scc1)


p_conn_20:                               /* connection part two     */
    if (adsl_gai1_inp_1 == NULL) {           /* no more input data      */
        return;                                /* wait for more input     */
    }
    iml_rdp_prot_1 = adsl_session->imc_rdp_prot_1;  /* RDP protocol status   */

pne_gath_00:                             /* next gather             */
    achl1 = adsl_gai1_inp_1->achc_ginp_cur;  /* get start of data       */
    if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) goto pne_gath_80;

pne_gath_20:                             /* check input             */
    if (iml_rdp_prot_1 > 0) {                /* search more in frame    */
        achl1 += iml_rdp_prot_1;               /* add to pointer input    */
        if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {  /* at or after end of input data */
//#if !(defined HL_LINUX)
            iml_rdp_prot_1 = (int)(UINT_PTR)(achl1 - adsl_gai1_inp_1->achc_ginp_end);
//#else
//            iml_rdp_prot_1 = (int)(unsigned int)(achl1 - adsl_gai1_inp_1->achc_ginp_end);
//#endif
            goto pne_gath_60;                    /* copy all data           */
        }
        iml_rdp_prot_1 = 0;                    /* now at start of frame   */
    }
    if (iml_rdp_prot_1 == 0) {               /* at start of frame       */
        iml_rdp_prot_1 = 0X80008000;           /* set RDP-5 default       */
        if (*achl1 == 0X03) {                  /* found T.123             */
            iml_rdp_prot_1 = 0X80000000;         /* set T.123 reserved      */
        }
        achl1++;                               /* next input              */
        if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {
            if (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER) {
                goto pne_gath_60;                  /* copy all data           */
            }
            if (iml_rdp_prot_1 == 0X80008000) {  /* RDP-5                   */
                goto pne_gath_60;                  /* copy all data           */
            }
            achl1--;                             /* byte before             */
            if (achl1 == adsl_gai1_inp_1->achc_ginp_cur) {  /* only this byte */
                adsl_gai1_inp_1->achc_ginp_cur = adsl_gai1_inp_1->achc_ginp_end;
                goto pne_gath_80;                  /* ignore this input       */
            }
            goto pne_gath_80;                    /* get next input          */
        }
    }
    if (iml_rdp_prot_1 == 0X80008000) {      /* RDP-5 first byte length */
        if ((*achl1 & 0X80) == 0) {            /* length in one bytes     */
            iml_rdp_prot_1 = *achl1 - 2;         /* set length to follow    */
            if (iml_rdp_prot_1 <= 0) {           /* length too short        */
                if (adsl_session->boc_error == FALSE) {  /* error not yet displayed */
#ifdef B101218
                    iml_out = sprintf( chrl_out, "xl-rdps-rfbc-1-l%05d-W m_rdp1_hlclib01() invalid frame sequence",
                        __LINE__ );
                    bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                        DEF_AUX_CONSOLE_OUT,
                        chrl_out,
                        iml_out );
#else
                    M_SDH_PRINTF_W( "RDP input data invalid frame sequence");
#endif
                    adsl_session->boc_error = TRUE;       /* error displayed now     */
                }
                iml_rdp_prot_1 = 0;                /* try frame boundary to synchronize */
            }
            achl1++;                             /* next input              */
            if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {
                goto pne_gath_60;                  /* copy all data           */
            }
            goto pne_gath_20;                    /* check input             */
        }
        iml_rdp_prot_1++;                      /* then second byte length */
        iml_rdp_prot_1 |= *achl1 << 24;          /* save length             */
#ifdef TRACEHL1
        M_SDH_PRINTF_T( "m_rdp1_hlclib01() iml_rdp_prot_1 == 0X80008000 new=%02X result=%08X.",
            (unsigned char) *achl1, iml_rdp_prot_1 );
#endif
        achl1++;                               /* next input              */
        if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {
            goto pne_gath_60;                    /* copy all data           */
        }
    }
    if ((iml_rdp_prot_1 & 0X80FFFFFF) == 0X80008001) {  /* RDP-5 second byte length */
        iml_rdp_prot_1 >>= 16;                 /* make length             */
        iml_rdp_prot_1 |= (unsigned char) *achl1;  /* save length         */
        iml_rdp_prot_1 &= 0X00007FFF;          /* only 15 bit             */
        iml_rdp_prot_1 -= 3;                   /* set length to follow    */
#ifdef TRACEHL1
        M_SDH_PRINTF_T( "m_rdp1_hlclib01() iml_rdp_prot_1 == 0X80008001 new=%02X result=%08X.",
            (unsigned char) *achl1, iml_rdp_prot_1 );
#endif
        if (iml_rdp_prot_1 <= 0) {             /* length too short        */
            if (adsl_session->boc_error == FALSE) {   /* error not yet displayed */
#ifdef B101218
                iml_out = sprintf( chrl_out, "xl-rdps-rfbc-1-l%05d-T m_rdp1_hlclib01() invalid frame sequence",
                    __LINE__ );
                bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                    DEF_AUX_CONSOLE_OUT,
                    chrl_out,
                    iml_out );
#else
                M_SDH_PRINTF_W( "RDP input data invalid frame sequence");
#endif
                adsl_session->boc_error = TRUE;         /* error displayed now     */
            }
            iml_rdp_prot_1 = 0;                  /* try frame boundary to synchronize */
        }
        achl1++;                               /* next input              */
        if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {
            goto pne_gath_60;                    /* copy all data           */
        }
        goto pne_gath_20;                      /* check input             */
    }
    if (iml_rdp_prot_1 == 0X80002000) {      /* is at T.123 HOB special command */
        goto pne_comm_00;                      /* command found           */
    }
    if (iml_rdp_prot_1 == 0X80000000) {      /* is at T.123 reserved    */
        iml_rdp_prot_1++;                      /* set T.123 first byte length */
        if (adsp_hl_clib_1->inc_func != DEF_IFUNC_FROMSERVER) {
            if ((unsigned char) *achl1 == 0XFF) {  /* found HOB special     */
#ifdef TRACEHL1
                M_SDH_PRINTF_T( "m_rdp1_hlclib01() HOB special found");
#endif
                iml_rdp_prot_1 = 0X80004000;       /* INETA follows           */
                achl1++;                           /* next input              */
                if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) goto pne_gath_80;
                goto pne_gath_40;                  /* get INETA               */
            }
        }
        achl1++;                               /* next input              */
        if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) goto pne_gath_60;
    }
    if (iml_rdp_prot_1 == 0X80000001) {      /* is at T.123 first byte length */
        if (*achl1 & 0X80) {                   /* length too high         */
            if (adsl_session->boc_error == FALSE) {   /* error not yet displayed */
#ifdef B101218
                iml_out = sprintf( chrl_out, "xl-rdps-rfbc-1-l%05d-T m_rdp1_hlclib01() invalid frame sequence",
                    __LINE__ );
                bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                    DEF_AUX_CONSOLE_OUT,
                    chrl_out,
                    iml_out );
#else
                M_SDH_PRINTF_W( "RDP input data invalid frame sequence");
#endif
                adsl_session->boc_error = TRUE;         /* error displayed now     */
            }
            iml_rdp_prot_1 = 0;                  /* try frame boundary to synchronize */
        }
        iml_rdp_prot_1 |= *achl1 << 24;        /* save length             */
        iml_rdp_prot_1++;                      /* then second byte length */
#ifdef TRACEHL1
        M_SDH_PRINTF_T( "m_rdp1_hlclib01() iml_rdp_prot_1 == 0X80000001 new=%02X result=%08X.",(unsigned char) *achl1, iml_rdp_prot_1 );
#endif
        achl1++;                               /* next input              */
        if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) goto pne_gath_80;
    }
    if ((iml_rdp_prot_1 & 0X80FFFFFF) == 0X80000002) {  /* is at T.123 second byte length */
        iml_rdp_prot_1 >>= 16;                 /* make length             */
        iml_rdp_prot_1 |= (unsigned char) *achl1;  /* save length         */
        iml_rdp_prot_1 &= 0X00007FFF;          /* only 15 bit             */
        iml_rdp_prot_1 -= 4;                   /* set length to follow    */
#ifdef TRACEHL1
        M_SDH_PRINTF_T( "m_rdp1_hlclib01() iml_rdp_prot_1 == 0X80000002 new=%02X result=%08X.", (unsigned char) *achl1, iml_rdp_prot_1 );
#endif
        if (iml_rdp_prot_1 <= 0) {             /* new length of frame invalid */
            if (adsl_session->boc_error == FALSE) {  /* error not yet displayed */
#ifdef B101218
                iml_out = sprintf( chrl_out, "xl-rdps-rfbc-1-l%05d-T m_rdp1_hlclib01() invalid frame sequence",
                    __LINE__ );
                bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                    DEF_AUX_CONSOLE_OUT,
                    chrl_out,
                    iml_out );
#else

                M_SDH_PRINTF_W( "RDP input data invalid frame sequence");
#endif
                adsl_session->boc_error = TRUE;    /* error displayed now     */
            }
            iml_rdp_prot_1 = 0;                    /* try frame boundary to synchronize */
        }
        achl1++;                               /* next input              */
        if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {
            goto pne_gath_60;                    /* copy all data           */
        }
        goto pne_gath_20;                      /* check input             */
    }
    if ((iml_rdp_prot_1 & 0XFFFFF000) != 0X80004000) {
        if (adsl_session->boc_error == FALSE) {  /* error not yet displayed */
#ifdef B101218
            iml_out = sprintf( chrl_out, "xl-rdps-rfbc-1-l%05d-T m_rdp1_hlclib01() logic-error invalid length %08X",
                __LINE__, iml_rdp_prot_1 );
            bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                DEF_AUX_CONSOLE_OUT,
                chrl_out,
                iml_out );
#else

            M_SDH_PRINTF_W( "RDP input logic-error invalid length %08X.", iml_rdp_prot_1 );
#endif
            adsl_session->boc_error = TRUE;           /* error displayed now     */
        }
        iml_rdp_prot_1 = 0;                    /* try frame boundary to synchronize */
        goto pne_gath_20;                      /* check input             */
    }

pne_gath_40:                             /* get INETA               */

    iml1 = iml_rdp_prot_1 - 0X80004000;      /* position in area        */
    if (iml1 == 0) {                         /* is at start of area     */
        ucl_w1 = (unsigned char) *achl1++;     /* get first byte        */
        iml1 = 1;                              /* now after first position */
    }
    switch (ucl_w1) {                        /* command received        */

    case 3:                                /* is command              */
        iml_rdp_prot_1 = 0X80002000;         /* command follows         */
        adsl_gai1_inp_2 = adsp_hl_clib_1->adsc_gather_i_1_in;
        while (adsl_gai1_inp_2 != adsl_gai1_inp_1) {
            adsl_gai1_inp_2->achc_ginp_cur = adsl_gai1_inp_2->achc_ginp_end;
            adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
        }
        adsl_gai1_inp_1->achc_ginp_cur = achl1;  /* processed so far    */
        goto pne_comm_00;                    /* command found           */
    default:
        if (adsl_session->boc_error == FALSE) {   /* error not yet displayed */

            M_SDH_PRINTF_W( "RDP received from client invalid control character HOB special %02X.", ucl_w1 );
            adsl_session->boc_error = TRUE;         /* error displayed now     */
        }
        iml_rdp_prot_1 = 0;                  /* try frame boundary to synchronize */
        goto pne_gath_20;                    /* check input             */
    }
    iml2 -= iml1 - 1;                        /* compute what is missing */
    if (iml2 > 0) {                          /* get more data           */
//#if !(defined HL_LINUX)
        iml3 =  (int) (UINT_PTR) (adsl_gai1_inp_1->achc_ginp_end - achl1);  /* so much in block */
//#else
//        iml3 =  (int) (unsigned int) (adsl_gai1_inp_1->achc_ginp_end - achl1);  /* so much in block */
//#endif
        if (iml3 > iml2) iml3 = iml2;          /* only to fill area       */

        achl1 += iml3;                         /* increment input         */
        iml_rdp_prot_1 += iml3;                /* increment position      */
        iml2 -= iml3;                          /* decrement remainder     */
    }
    adsl_gai1_inp_1->achc_ginp_cur = achl1;  /* data processed so far   */
    if (iml2 > 0) goto pne_gath_80;          /* needs more data         */
    adsl_session->imc_rdp_prot_1 = 0;             /* now next frame          */
    // iml_rdp_prot_1 = 0;                      /* now next frame          */
    // adsl_session->boc_do_conn = TRUE;             /* do new connect now      */
    // adsp_hl_clib_1->boc_callrevdir = TRUE;   /* call on reverse direction */
    return;                                  /* do connect in other direction */

pne_gath_60:                             /* copy all data           */

pne_gath_80:                             /* end of input gather     */
    adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
    if (adsl_gai1_inp_1 != NULL) goto pne_gath_00;  /* next gather      */
    return;

pne_comm_00:                             /* command found           */
    iml1 = 0;                                /* clear result            */
    iml2 = 4;                                /* set maximum number of digits */
    while (TRUE) {                           /* loop to decode length NHASN */
        while (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {
            adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
            if (adsl_gai1_inp_1 == NULL) return;  /* wait for more data     */
            achl1 = adsl_gai1_inp_1->achc_ginp_cur;  /* get start of data   */
        }
        iml3 = (signed char) *achl1++;         /* get next character      */
        iml1 <<= 7;                            /* shift old value         */
        iml1 |= iml3 & 0X7F;                   /* apply new bits          */
        if (iml3 >= 0) break;                  /* end of NHASN            */
        iml2--;                                /* decrement number of digits */
        if (iml2 <= 0) {                       /* too many digits NHASN   */

            m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command too many digits length NHASN",
                __LINE__ );

#ifdef B110628
            adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end   */
            PRINTF_DEF_IRET_END;
            return;
#endif
            goto p_cleanup_00;                   /* do clean-up             */
        }
    }
    if (iml1 <= 0) {                         /* invalid value length NHASN */

        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command too short",
            __LINE__ );

#ifdef B110628
        adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
        PRINTF_DEF_IRET_END;
        return;
#endif
        goto p_cleanup_00;                     /* do clean-up             */
    }
    while (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {
        adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
        if (adsl_gai1_inp_1 == NULL) return;   /* wait for more data      */
        achl1 = adsl_gai1_inp_1->achc_ginp_cur;  /* get start of data     */
    }
    iml2 = (int) (adsl_gai1_inp_1->achc_ginp_end - achl1);  /* how much in this chunk */
    if (iml2 >= iml1) {                      /* command in one chunk    */
        achl2 = achl1;                         /* here is command         */
        achl1 += iml1;                         /* the command has been processed */
        goto p_comm_20;                        /* achl2 and iml1 point to command */
    }
    if (iml1 > sizeof(chrl_work1)) {         /* command too long        */
        ERROR_MACRO("command CONNECT too long");
    }
    achl2 = achl3 = chrl_work1;
    iml2 = iml1;                             /* get length total        */
    while (TRUE) {
        while (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {
            adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
            if (adsl_gai1_inp_1 == NULL) return;  /* wait for more data     */
            achl1 = adsl_gai1_inp_1->achc_ginp_cur;  /* get start of data   */
        }
        iml3 = CONVERT_W64_TO_INT(adsl_gai1_inp_1->achc_ginp_end - achl1);  /* how much in this chunk */
        if (iml3 > iml2) iml3 = iml2;
        memcpy( achl3, achl1, iml3 );          /* copy input area         */
        achl3 += iml3;                         /* increment output        */
        achl1 += iml3;                         /* increment input         */
        iml2 -= iml3;                          /* subtract from length    */
        if (iml2 <= 0) break;
    }

p_comm_20:                               /* achl2 and iml1 point to command */
    iml_rdp_prot_1 = 0;                      /* record processed        */
    adsl_gai1_inp_2 = adsp_hl_clib_1->adsc_gather_i_1_in;
    while (adsl_gai1_inp_2 != adsl_gai1_inp_1) {
        adsl_gai1_inp_2->achc_ginp_cur = adsl_gai1_inp_2->achc_ginp_end;
        adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
    }
    adsl_gai1_inp_1->achc_ginp_cur = achl1;  /* processed so far        */
    iml2 = memcmp( achl2, ucrs_comm_connect, sizeof(ucrs_comm_connect) );
    if (iml2) {                              /* does not compare        */

        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT not found",
            __LINE__ );

#ifdef B110628
        adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
        PRINTF_DEF_IRET_END;
        return;
#endif
        goto p_cleanup_00;                     /* do clean-up             */
    }
    achl3 = achl2 + sizeof(ucrs_comm_connect);
    iml_ineta_len = -1;                      /* length INETA            */
    iml_port = -1;                           /* port to connect to      */
    iml_co_ssl = -1;                         /* SSL requested           */
    iml_co_shared = -1;                      /* VNC-SHARED-FLAG         */
    bol_co_password = FALSE;                 /* password found          */

p_comm_40:                               /* search keyword          */
    iml3 = memcmp( achl3, ucrs_comm_ineta, sizeof(ucrs_comm_ineta) );
    if (iml3 == 0) goto p_comm_ineta_00;     /* INETA found             */
    iml3 = memcmp( achl3, ucrs_comm_port, sizeof(ucrs_comm_port) );
    if (iml3 == 0) goto p_comm_port_00;      /* port found              */
    aiml_w1 = &iml_co_ssl;                   /* SSL requested           */
    iml2 = sizeof(ucrs_comm_ssl);
    achl1 = "SSL";
    iml3 = memcmp( achl3, ucrs_comm_ssl, sizeof(ucrs_comm_ssl) );
    if (iml3 == 0) goto p_comm_yes_no_00;    /* check YES or NO         */
    aiml_w1 = &iml_co_shared;                /* VNC-SHARED-FLAG         */
    iml2 = sizeof(ucrs_comm_share);
    achl1 = "VNC-SHARED-FLAG";
    iml3 = memcmp( achl3, ucrs_comm_share, sizeof(ucrs_comm_share) );
    if (iml3 == 0) goto p_comm_yes_no_00;    /* check YES or NO         */
    iml3 = memcmp( achl3, ucrs_comm_password, sizeof(ucrs_comm_password) );
    if (iml3 == 0) goto p_comm_password_00;  /* password found          */

    m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT invalid keyword",
        __LINE__ );

#ifdef B110628
    adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end       */
    PRINTF_DEF_IRET_END;
    return;
#endif
    goto p_cleanup_00;                       /* do clean-up             */

p_comm_ineta_00:                         /* INETA found             */
    if (iml_ineta_len >= 0) {                /* length INETA            */
        ERROR_MACRO("command CONNECT INETA double");
    }
    achl3 += sizeof(ucrs_comm_ineta);
    iml2 = CONVERT_W64_TO_INT((achl2 + iml1) - achl3);
    if (iml2 <= 0) {                         /* length too short        */

        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT INETA not complete",
            __LINE__ );

#ifdef B110628
        adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
        PRINTF_DEF_IRET_END;
        return;
#endif
        goto p_cleanup_00;                     /* do clean-up             */
    }
    achl4 = (char *) memchr( achl3, ' ', iml2 );
    if (achl4 == NULL) {                     /* till end of input       */
        achl4 = achl3 + iml2;                  /* set end of input        */
    }
    achl_ineta_start = achl3;                /* start of INETA          */
    iml_ineta_len = CONVERT_W64_TO_INT(achl4 - achl3);           /* length INETA            */
    achl3 = achl4 + 1;                       /* position on next keyword */
    if (achl3 < (achl2 + iml1)) goto p_comm_40;  /* search keyword      */
    achl3--;                                 /* set on end              */
    if (achl4 != achl3) {                    /* is not end              */

        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT no end found",
            __LINE__ );

#ifdef B110628
        adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
        PRINTF_DEF_IRET_END;
        return;
#endif
        goto p_cleanup_00;                     /* do clean-up             */
    }
    goto p_comm_60;                          /* all parameters scanned  */

p_comm_port_00:                          /* port found              */
    if (iml_port >= 0) {                     /* port to connect to      */

        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT PORT double",
            __LINE__ );

#ifdef B110628
        adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
        PRINTF_DEF_IRET_END;
        return;
#endif
        goto p_cleanup_00;                     /* do clean-up             */
    }
    achl3 += sizeof(ucrs_comm_port);
    achl4 = achl2 + iml1;                    /* end of command          */
    if (achl4 > (achl3 + 8)) achl4 = achl3 + 8;  /* maximum length number */
    iml_port = 0;                            /* port to connect to      */
    while (   (achl3 < achl4)
        && (*achl3 >= '0')
        && (*achl3 <= '9')) {
            iml_port *= 10;                        /* shift result            */
            iml_port += *achl3++ - '0';
    }
    if (iml_port <= 0) {                     /* port too small          */

        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT received PORT too small",
            __LINE__ );

#ifdef B110628
        adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
        PRINTF_DEF_IRET_END;
        return;
#endif
        goto p_cleanup_00;                     /* do clean-up             */
    }
    if (iml_port >= 0X010000) {              /* port too high           */

        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT received PORT too high",
            __LINE__ );

#ifdef B110628
        adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
        PRINTF_DEF_IRET_END;
        return;
#endif
        goto p_cleanup_00;                     /* do clean-up             */
    }
    if (achl3 >= (achl2 + iml1)) {           /* end of command reached  */
        goto p_comm_60;                        /* all parameters scanned  */
    }
    if (*achl3 != ' ') {                     /* not followed by space   */

        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT received PORT not followed by space",
            __LINE__ );

#ifdef B110628
        adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
        PRINTF_DEF_IRET_END;
        return;
#endif
        goto p_cleanup_00;                     /* do clean-up             */
    }
    achl3++;                                 /* after space             */
    if (achl3 >= (achl2 + iml1)) {           /* end of command reached  */

        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT not complete",
            __LINE__ );

#ifdef B110628
        adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
        PRINTF_DEF_IRET_END;
        return;
#endif
        goto p_cleanup_00;                     /* do clean-up             */
    }
    goto p_comm_40;                          /* search keyword          */

p_comm_yes_no_00:                        /* check YES or NO         */
    if (*aiml_w1 >= 0) {                     /* check if parameter double */

        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT %s double",
            __LINE__, achl1 );

#ifdef B110628
        adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
        PRINTF_DEF_IRET_END;
        return;
#endif
        goto p_cleanup_00;                     /* do clean-up             */
    }
    achl3 += iml2;
    iml2 = CONVERT_W64_TO_INT((achl2 + iml1) - achl3);
    if (iml2 <= 0) {                         /* length too short        */
        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT %s not complete",
            __LINE__, achl1 );
#ifdef B110628
        adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
        PRINTF_DEF_IRET_END;
        return;
#endif
        goto p_cleanup_00;                     /* do clean-up             */
    }
    achl4 = (char *) memchr( achl3, ' ', iml2 );
    if (achl4 == NULL) {                     /* till end of input       */
        achl4 = achl3 + iml2;                  /* set end of input        */
    }
    iml2 = CONVERT_W64_TO_INT(achl4 - achl3);                    /* length of parameter     */
    if (   (iml2 == sizeof(ucrs_comm_yes))
        && (!memcmp( achl3, ucrs_comm_yes, sizeof(ucrs_comm_yes) ))) {
            *aiml_w1 = 1;                          /* set YES                 */
    } else if (   (iml2 == sizeof(ucrs_comm_no))
        && (!memcmp( achl3, ucrs_comm_no, sizeof(ucrs_comm_no) ))) {
            *aiml_w1 = 0;                          /* set NO                  */
    } else {

        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT parameter %s value %.s neither YES nor NO",
            __LINE__, achl1, iml2, achl3 );

#ifdef B110628
        adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
        PRINTF_DEF_IRET_END;
        return;
#endif
        goto p_cleanup_00;                     /* do clean-up             */
    }
    achl3 = achl4 + 1;                       /* position on next keyword */
    if (achl3 < (achl2 + iml1)) goto p_comm_40;  /* search keyword      */
    achl3--;                                 /* set on end              */
    if (achl4 != achl3) {                    /* is not end              */

        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT no end found",
            __LINE__ );

#ifdef B110628
        adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
        PRINTF_DEF_IRET_END;
        return;
#endif
        goto p_cleanup_00;                     /* do clean-up             */
    }
    goto p_comm_60;                          /* all parameters scanned  */

p_comm_password_00:                      /* password found          */
    if (bol_co_password) {                   /* command parameter PASSWORD */

        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT PASSWORD double",
            __LINE__ );

#ifdef B110628
        adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
        PRINTF_DEF_IRET_END;
        return;
#endif
        goto p_cleanup_00;                     /* do clean-up             */
    }
    achl3 += sizeof(ucrs_comm_password);
    iml2 = CONVERT_W64_TO_INT ((achl2 + iml1) - achl3);
    if (iml2 <= 0) {                         /* length too short        */
        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT PASSWORD not complete",
            __LINE__ );

    //in cases when "CONNECT PASSWORD="
    //when the PASSWORD element is the last element in the CONNECT command
        if (iml2 == 0){      /* No password has been entered */
        DEF_DEBUG_PRINTF("\nPassword has not been entered");
        //@Joseph: Does this make sense? Can the password not be given in the configuration?
        memset( adsl_session->dsc_vnc_password.get_data(), 0, adsl_session->inc_len_vnc_password);  /* clear password */
        goto p_comm_password_20;
    }

        goto p_cleanup_00;                     /* do clean-up             */
    }
    achl4 = (char *) memchr( achl3, ' ', iml2 );

    //in cases when CONNECT PASSWORD= OTHER=VALUE"
    //when the PASSWORD element is followed by other elements seperated with a space (' ').
    if (achl4 == achl3){      /* No password has been entered */
        //DEF_DEBUG_PRINTF("\nSame Location");
        memset( adsl_session->dsc_vnc_password.get_data(), 0, adsl_session->inc_len_vnc_password);  /* clear password */
        goto p_comm_password_20;
    }
    
    if (achl4 == NULL) {                     /* till end of input       */
        achl4 = achl3 + iml2;                  /* set end of input        */
    }
    iml2 = (CONVERT_W64_TO_INT(achl4 - achl3) * 3) / 4;
    adsl_session->dsc_vnc_password.ensure_elements(iml2, m_callback_get_mem, m_callback_free_mem, &dsl_sdh_call_1);
    memset( adsl_session->dsc_vnc_password.get_data(), 0, adsl_session->dsc_vnc_password.get_act_size());  /* clear password */
    achl1 = adsl_session->dsc_vnc_password.get_data();          /* output                  */
    iml2 = 4;                                /* set number of characters */
    iml3 = 0;                                /* clear akkumulator       */
    iml5 = 0;                                /* delimiting equals       */
    while (TRUE) {                           /* loop to decode password mime base64 */
        iml4 = scrs_from_base64[ *((unsigned char *) achl3++) ];  /* get translation */
        if (iml4 < 0) {                        /* invalid character found */
            if (iml4 == -2) {                    /* delimiting equals found */
                iml5++;                            /* count delimiting equals */
            } else {

                m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT PASSWORD invalid character 0X%02X found",__LINE__, *((unsigned char *) achl3) );

#ifdef B110628
                // to-do 28.06.11 KB free resources
                adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end   */
                PRINTF_DEF_IRET_END;
                return;
#endif
                goto p_cleanup_00;                 /* do clean-up             */
            }
        } else {
            //     achl3++;                             /* this input character processed */
            if (iml5 != 0) {                     /* delimiting equals       */

                m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT PASSWORD valid character after delimiting equals \"=\" found",__LINE__ );

#ifdef B110628
                // to-do 28.06.11 KB free resources
                adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end   */
                PRINTF_DEF_IRET_END;
                return;
#endif
                goto p_cleanup_00;                 /* do clean-up             */
            }
            iml3 <<= 6;                            /* shift old bits          */
            iml3 |= iml4;                          /* apply new bits          */
            iml2--;                                /* decrement number of characters */
        }
        iml4 = 3;                              /* set number of output characters */
        if (achl3 >= achl4) {                  /* end of input reached    */
            if (iml2 > 0) {                      /* not complete sequence   */
                if (iml2 >= 3) {                   /* last bundle one a single input character */

                    m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT PASSWORD last bundle MIME base64 too short",__LINE__ );

#ifdef B110628
                    // to-do 28.06.11 KB free resources
                    adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end */
                    PRINTF_DEF_IRET_END;
                    return;
#endif
                    goto p_cleanup_00;               /* do clean-up             */
                }
                iml3 <<= iml2 * 6;                 /* shift akkumulator to correct position */
                iml4 -= iml2 - 1;                  /* less output characters  */
                iml5 -= iml2;                      /* control delimiting characters */
                iml2 = 0;                          /* bundle is complete      */
            }
            if (iml5 != 0) {                     /* wrong number of delimiting characters */
 
                m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT PASSWORD invalid number of delimiting equals \"=\" found",
                    __LINE__ );

#ifdef B110628
                // to-do 28.06.11 KB free resources
                adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end */
                PRINTF_DEF_IRET_END;
                return;
#endif
                goto p_cleanup_00;                 /* do clean-up             */
            }
        }
        if (iml2 <= 0) {                       /* all digits found        */
            //iml2 = CONVERT_W64_TO_INT( (adsl_session->chrc_vnc_password + sizeof(adsl_session->chrc_vnc_password)) - (achl1 + iml4));
            //if (iml2 < 0) {                      /* output too long         */
            //    iml4--;                            /* shorted the output      */
            //    if (   (achl3 < achl4)             /* not end of input reached */
            //        || (iml2 != -1)                /* more than one character */
            //        || (iml3 & (0X00FFFFFF >> (iml4 * 8)))) {  /* too many input characters */

            //            m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E command CONNECT PASSWORD too long",
            //                __LINE__ );

            //            adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end */
            //            PRINTF_DEF_IRET_END;
            //            return;
            //    }
            //    // to-do 28.12.10 KB check last character zero
            //}
            do {
               if(((unsigned char)(iml3 >> 16)) > 0){
                   *achl1++ = (unsigned char) (iml3 >> 16);
                   adsl_session->inc_len_vnc_password++;
               }
                iml3 <<= 8;                        /* shift bits              */
                iml4--;                            /* output done             */
            } while (iml4 > 0);
            if (achl3 >= achl4) break;           /* all input processed     */
            iml2 = 4;                            /* set number of characters */
            iml3 = 0;                            /* clear akkumulator       */
        }
    }

p_comm_password_20:
    
    bol_co_password = TRUE;                  /* password found          */
    achl3 = achl4 + 1;                       /* position on next keyword */
    if (achl3 < (achl2 + iml1)) goto p_comm_40;  /* search keyword      */
    achl3--;                                 /* set on end              */
    if (achl4 != achl3) {                    /* is not end              */

        ERROR_MACRO("command CONNECT no end found");
    }
    // goto p_comm_60;                          /* all parameters scanned  */

p_comm_60:                               /* all parameters scanned  */
    if (iml_ineta_len < 0) {                 /* INETA not found         */

       ERROR_MACRO("command CONNECT received without INETA");
    }
    if (iml_port < 0) {                      /* port to connect to      */

        ERROR_MACRO("command CONNECT received without PORT");
        return;
    }
    if (iml_co_ssl < 0) {                    /* SSL requested           */
      

        ERROR_MACRO("command CONNECT received without SSL");
    }
    if (iml_co_shared < 0) {                 /* VNC-SHARED-FLAG         */

        ERROR_MACRO("command CONNECT received without VNC-SHARED-FLAG");
    }
    if (bol_co_password == FALSE) {          /* no password found       */     
        ERROR_MACRO("command CONNECT received without PASSWORD");
    }
    /* do connect now                                                   */
    memset( &dsl_tc1_l, 0, sizeof(struct dsd_aux_tcp_conn_1) );  /* TCP Connect to Server */
    dsl_tc1_l.dsc_target_ineta.ac_str = achl_ineta_start;  /* start of INETA */
    dsl_tc1_l.dsc_target_ineta.imc_len_str = iml_ineta_len;  /* length INETA */
    dsl_tc1_l.dsc_target_ineta.iec_chs_str = ied_chs_utf_8;  /* Unicode UTF-8 */
    dsl_tc1_l.imc_server_port = iml_port;    /* port of server          */
    if (   (adsl_session->boc_csssl)              /* with client-side SSL    */
        || (iml_co_ssl > 0)) {               /* SSL requested           */
            dsl_tc1_l.dsc_aux_tcp_def.ibc_ssl_client = 1;  /* may use client side SSL */
    }
    bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
        DEF_AUX_TCP_CONN,  /* TCP Connect to Server */
        &dsl_tc1_l,
        sizeof(struct dsd_aux_tcp_conn_1) );
    if (bol1 == FALSE) {                     /* error occured           */
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;

        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E connect failed - failed to TCP connet to Server",
                __LINE__ );

        return;
    }
    if (dsl_tc1_l.iec_tcpconn_ret == ied_tcr_ok) {  /* connect successful */
        adsl_session->chc_co_shared = (unsigned char) iml_co_shared;  /* VNC-SHARED-FLAG */

#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) adsp_hl_clib_1->achc_work_area)
        memset( ADSL_GAI1_G, 0, sizeof(struct dsd_gather_i_1) );
        ADSL_GAI1_G->achc_ginp_cur = (char *) ucrs_out_ack_conn;
        ADSL_GAI1_G->achc_ginp_end = (char *) ucrs_out_ack_conn + sizeof(ucrs_out_ack_conn);
        adsp_hl_clib_1->adsc_gai1_out_to_client = ADSL_GAI1_G;  /* output data to client */
#undef ADSL_GAI1_G
        adsl_session->iec_scc1 = ied_scc1_conn_act;  /* connection is active   */
        return;
    }
    switch (dsl_tc1_l.iec_tcpconn_ret) {
    case ied_tcr_invalid:                  /* parameter is invalid    */
        achl1 = "error ied_tcr_invalid - parameter is invalid";
        break;
    case ied_tcr_no_ocos:                  /* option-connect-other-server not configured */
        achl1 = "error ied_tcr_no_ocos - option-connect-other-server not configured";
        break;
    case ied_tcr_no_cs_ssl:                /* no Client-Side SSL configured */
        achl1 = "error ied_tcr_no_cs_ssl - no Client-Side SSL configured";
        break;
    case ied_tcr_denied_tf:                /* access denied because of target-filter */
        achl1 = "error ied_tcr_denied_tf - access denied because of target-filter";
        break;
    case ied_tcr_hostname:                 /* host-name not in DNS    */
        achl1 = "error ied_tcr_hostname - host-name not in DNS";
        break;
    case ied_tcr_no_route:                 /* no route to host        */
        achl1 = "error ied_tcr_no_route - no route to host";
        break;
    case ied_tcr_refused:                  /* connection refused      */
        achl1 = "error ied_tcr_refused - connection refused";
        break;
    case ied_tcr_timeout:                  /* connection timed out    */
        achl1 = "error ied_tcr_timeout - connection timed out";
        break;
    case ied_tcr_error:                    /* other error             */
        achl1 = "error ied_tcr_error - error not specified";
        break;
    default:                               /* error undefined         */
        achl1 = "error undefined";
        break;
    }
        
    ENSURE_SPACE_ON_WORKAREA(2 * sizeof(struct dsd_gather_i_1) + 8); 
        achl_work_2 -= 2 * sizeof(struct dsd_gather_i_1) + 8;
    
#define ADSL_GAI1_OUT_G1 ((struct dsd_gather_i_1 *) achl_work_2)
#define ADSL_GAI1_OUT_G2 ((struct dsd_gather_i_1 *) achl_work_2 + 1)
#define ACHL_OUT_G       ((char *) (ADSL_GAI1_OUT_G2 + 1))
    iml1 = (int) strlen( achl1 );
    iml2 = iml1 + 5;
    *(ACHL_OUT_G + 0) = (unsigned char) 0X03;
    *(ACHL_OUT_G + 1) = (unsigned char) 0XFF;
    *(ACHL_OUT_G + 2) = (unsigned char) (iml2 >> 8);
    *(ACHL_OUT_G + 3) = (unsigned char) iml2;
    *(ACHL_OUT_G + 4) = (unsigned char) 0X02;
    ADSL_GAI1_OUT_G1->adsc_next = ADSL_GAI1_OUT_G2;
    ADSL_GAI1_OUT_G1->achc_ginp_cur = ACHL_OUT_G;
    ADSL_GAI1_OUT_G1->achc_ginp_end = ACHL_OUT_G + 5;
    ADSL_GAI1_OUT_G2->adsc_next = NULL;
    ADSL_GAI1_OUT_G2->achc_ginp_cur = achl1;
    ADSL_GAI1_OUT_G2->achc_ginp_end = achl1 + iml1;
    if (adsl_gai1_out_client == NULL) {

        adsp_hl_clib_1->adsc_gai1_out_to_client = ADSL_GAI1_OUT_G1;  /* output data to client */
    } else {
        adsl_gai1_out_client->adsc_next = ADSL_GAI1_OUT_G1;
    }
    return;
#undef ADSL_GAI1_OUT_G1
#undef ADSL_GAI1_OUT_G2
#undef ACHL_OUT_G

//  _____  ______ ____                      _                         _     _       
// |  __ \|  ____|  _ \                    (_)                       (_)   | |      
// | |__) | |__  | |_) |  ___  ___  ___ ___ _  ___  _ __     _____  ___ ___| |_ ___ 
// |  _  /|  __| |  _ <  / __|/ _ \/ __/ __| |/ _ \| '_ \   / _ \ \/ / / __| __/ __|
// | | \ \| |    | |_) | \__ \  __/\__ \__ \ | (_) | | | | |  __/>  <| \__ \ |_\__ \
// |_|  \_\_|    |____/  |___/\___||___/___/_|\___/|_| |_|  \___/_/\_\_|___/\__|___/


p_session_00:                            /* RFB session exists      */
   switch(adsp_hl_clib_1->inc_func){
      case DEF_IFUNC_TOSERVER:
         goto p_ifunc_to_server;
      case DEF_IFUNC_FROMSERVER:
         goto p_ifunc_from_server;
      default:
         ERROR_MACRO_RDP(true, "adsp_hl_clib_1->inc_func=0x%x, which is not allowed here!", adsp_hl_clib_1->inc_func);
   }

//  ______ _____   ____  __  __    _____ ______ _______      ________ _____  
// |  ____|  __ \ / __ \|  \/  |  / ____|  ____|  __ \ \    / /  ____|  __ \ 
// | |__  | |__) | |  | | \  / | | (___ | |__  | |__) \ \  / /| |__  | |__) |
// |  __| |  _  /| |  | | |\/| |  \___ \|  __| |  _  / \ \/ / |  __| |  _  / 
// | |    | | \ \| |__| | |  | |  ____) | |____| | \ \  \  /  | |____| | \ \ 
// |_|    |_|  \_\\____/|_|  |_| |_____/|______|_|  \_\  \/   |______|_|  \_\
//                           ______                                          
//                          |______|                                         


p_ifunc_from_server: 

{ // From RFB-server 

   // Wait for parsing RFB, until RDP-session is finalized, so that error-messages can be print out. 
   if((adsl_session->iec_state_rdp < ied_state_rdp_finalized) || 
      (adsl_session->iec_state_rdp == ied_state_rdp_change_screen_is_send)){
         goto p_proc_inp_80;
   }

   // Get the input - old and new
//#if !(defined HL_LINUX)
//   dsd_gather_reader dsl_input(adsp_hl_clib_1->adsc_gather_i_1_in);
//#else
   dsl_input.m_copy_input_gather(adsp_hl_clib_1->adsc_gather_i_1_in);
//#endif
   if(adsl_session->boc_rfb_error){
      dsl_input.skip_rest();
   }
//#if !(defined HL_LINUX)
//   int inl_len_new_input = dsl_input.get_bytes_left();
//#else
   inl_len_new_input = dsl_input.get_bytes_left();
//#endif
   if(inl_len_new_input == 0) {           /* no more input data      */
      goto p_proc_inp_80;                    /* the input has been processed */
   }

//    _   ___ ___        _                      _   _          
//   /_\ | __/ __|___ __| |___ __ _ _ _  _ _ __| |_(_)___ _ _  
//  / _ \| _|\__ \___/ _` / -_) _| '_| || | '_ \  _| / _ \ ' \ 
// /_/ \_\___|___/   \__,_\___\__|_|  \_, | .__/\__|_\___/_||_|
//                                    |__/|_|                  
//AES decryption

   if(adsl_session->boc_do_aes){
      if(inl_len_new_input < 2)
         goto p_proc_inp_80;                    // Wait for the AES-len 
      int inl_aes_len;
      CHECK_RETURN(dsl_input.peek_16_be(&inl_aes_len));
      if(inl_len_new_input < 2 + inl_aes_len + INS_AES_TAG_LEN)
         goto p_proc_inp_80;                    // Wait for all the bytes before decrypting
      // Init message
      achl1 = chrl_work1;
      memset(achl1, 0, 0x10);
      write_64_le(&achl1, adsl_session->ilc_aes_dec_counter);
      adsl_session->ilc_aes_dec_counter++;
      m_eax_init_msg((unsigned char*) chrl_work1, 0x10, adsl_session->adsc_eax_dec);
      // Authentication header       
      CHECK_RETURN(dsl_input.copy_to(chrl_work1, 2)); // copy len
      m_eax_update_header_omac((unsigned char*) chrl_work1, 2, adsl_session->adsc_eax_dec);
      // Decrypt now
      dsd_gather_i_1* ads_gather = dsl_input.get_gather();
      iml2 = inl_aes_len;
      int in_act_input_gather = 0;
      while(iml2){
//#if !(defined HL_LINUX)
         iml3 = (int) (UINT_PTR)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
//#else
//         iml3 = (int) (unsigned int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
//#endif
         if(iml3 > iml2)
            iml3 = iml2; 
         m_eax_decrypt((unsigned char*) ads_gather->achc_ginp_cur, iml3, adsl_session->adsc_eax_dec);
         iml2 -= iml3;
         ads_gather = ads_gather->adsc_next;
      }

      // Calculate tag
      unsigned char uchr_tag_calculated[INS_AES_TAG_LEN];
      m_eax_generate_tag(uchr_tag_calculated, INS_AES_TAG_LEN, adsl_session->adsc_eax_dec);

      // Compare tag
      char chr_tag_send[INS_AES_TAG_LEN];
      CHECK_RETURN(dsl_input.peek_data((char*) chr_tag_send, inl_aes_len, INS_AES_TAG_LEN));
      if(memcmp(uchr_tag_calculated, chr_tag_send, INS_AES_TAG_LEN))
         ERROR_MACRO_RDP(true, "AES-decryption #%i, check of tag failed!", adsl_session->ilc_aes_dec_counter);

      inl_len_new_input = inl_aes_len;
   }

//           _        _                      _          _   _                _   
//  __ _ ___| |_   __| |___ __ _ _ _  _ _ __| |_ ___ __| | (_)_ _  _ __ _  _| |_ 
// / _` / -_)  _| / _` / -_) _| '_| || | '_ \  _/ -_) _` | | | ' \| '_ \ || |  _|
// \__, \___|\__| \__,_\___\__|_|  \_, | .__/\__\___\__,_| |_|_||_| .__/\_,_|\__|
// |___/                           |__/|_|                        |_|            

{ // parse decrypted input here

   bool bol_ret;
//#if !(defined HL_LINUX)
//   dsd_gather_reader dsl_input_dec(&dsl_input, inl_len_new_input, &bol_ret);
//#else 
   dsl_input_dec.m_copy_gather_reader(&dsl_input,inl_len_new_input, &bol_ret);
//#endif

   CHECK_RETURN(bol_ret);

   dsd_gather_i_1 ds_gather_old_mem;
   if(adsl_session->inc_len_mem_data > 0){
      ds_gather_old_mem.achc_ginp_cur = adsl_session->achc_mem_data;
      ds_gather_old_mem.achc_ginp_end = adsl_session->achc_mem_data + adsl_session->inc_len_mem_data;
      ds_gather_old_mem.adsc_next = NULL; 
      dsl_input_dec.add_front(&ds_gather_old_mem);
   }
   adsl_session->inc_len_mem_data = 0;

//   __                                           ___ _        _                 _    _          
//  / _|_ _ ___ _ __    ___ ___ _ ___ _____ _ _  / __| |_ __ _| |_ _ __  __ _ __| |_ (_)_ _  ___ 
// |  _| '_/ _ \ '  \  (_-</ -_) '_\ V / -_) '_| \__ \  _/ _` |  _| '  \/ _` / _| ' \| | ' \/ -_)
// |_| |_| \___/_|_|_|_/__/\___|_|  \_/\___|_|   |___/\__\__,_|\__|_|_|_\__,_\__|_||_|_|_||_\___|
//                  |___|                                                                        

p_ifunc_from_server_20: 
   //printf("adsl_session->iec_srfbc = %d\n", adsl_session->iec_srfbc); fflush(stdout);
   switch (adsl_session->iec_srfbc) {            /* state of this RFB client */
   case ied_srfbc_start:                  /* client not yet started  */
      goto p_cl_start_00;                  /* read start message      */
   // Version < 3.7
   case ied_srfbc_wait_sec_type:          /* wait security types supported */
      goto p_cl_auth_before_3_7;                   /* read authentication message */
   // Version >= 3.7
   case ied_srfbc_wait_sec_type_3_7:      /* wait security types supported from 3.7 on */
      goto p_cl_auth_3_7;             /* read authentication message */
   // VNC-Authentication: 
   case ied_srfbc_getchallenge:  /* Read challenge for VNC Authentication (SecType 2)*/
      goto p_cl_challenge;
   case ied_srfbc_wait_auth_resp:         /* wait authentication response */
      goto p_cl_auth_resp;                   /* read response authentication */
   // RSA/AES-Authentication: 
   case ied_srfbc_rsa_key:                /* wait for the rsa-key */
      goto p_cl_rsa_key;
   case ied_srfbc_aes_key:                /* wait for the aes-key */
      goto p_cl_aes_key;
   case ied_srfbc_turnon_aes:             /* truen on AES */
      goto p_cl_turnon_aes;
   case ied_srfbc_rsa_digest:             /* wait for the digest of the rsa-keys */
      goto p_cl_rsa_digest;
   case ied_srfbc_aes_auth_type:          /* server sent the authentication type, it whants */
      goto p_cl_aes_auth_type;

   case ied_srfbc_wait_server_init:       /* wait ServerInitialisation message */
      goto p_cl_seri_00;                  /* read ServerInitialisation */
   case ied_srfbc_wait_server_init_name:  /* Read the name-field in the ServerInitialisation message */
      goto p_cl_seri_20;
   case ied_srfbc_conn:                   /* session is connected    */
      goto p_cl_mt_00;                    /* decode message-type                 */
   case ied_srfbc_fu_rect:                /* framebuffer update get rectangle      */
      goto p_cl_fuh_20;                   /* decode rectangle                    */
   case ied_srfbc_fu_raw:                 /* framebuffer update raw                */
      goto p_cl_fu_raw_20;                /* framebuffer update raw              */
   case ied_srfbc_fu_zlib_init:           /* Read init of zlib: len 32 be */
      goto p_cl_fu_zlib_init;
   case ied_srfbc_fu_zlib_new_data:       /* framebuffer update zLib normal */
      goto p_cl_fu_zlib_new_data;         /* framebuffer update zLib normal */
   case ied_srfbc_fu_zlib_call_zlib:      /* continue to call zLib */
      goto p_cl_fu_zn_zlib_call_zlib; 
   case ied_srfbc_fu_copyrect:            /* framebuffer update copyrect request   */
      goto p_cl_fu_copyrect;              /* receive data for CopyRect     */
   case ied_srfbc_fu_rre:                 /* frambuffer update rre                 */ 
      goto p_cl_fu_rre_00;                /* decode rre rectangle                */
   case ied_srfbc_fu_rre_subrect:         /* reading rre subrectangles */
      goto p_cl_fu_rre_20;                /* decode subrectanlge data */
   case ied_srfbc_fu_zrle_init:
      goto p_cl_fu_zrle_init;
   case ied_srfbc_fu_zrle_new_data:
      goto p_cl_fu_zrle_new_data;
   case ied_srfbc_fu_zrle_call_zlib:
      goto p_cl_fu_zrle_call_zlib;
   case ied_srfbc_fu_cursor:
      goto p_cl_fu_cursor;
   case ied_srfbc_server_cut_text:
      goto p_cl_sct_20;
   case ied_srfbc_set_colormap_entries:
      goto p_cl_scme_20;
   default:
      ERROR_MACRO_RDP(true, "Unknown VNC-state: 0x%x", adsl_session->iec_srfbc);
   } 

p_cl_start_00:                                     // read start message
   if(dsl_input_dec.get_bytes_left() < 0xc)        // Start message always has 12 bytes 
      goto p_proc_inp_70;                          // wait for more data

   // Get start-package
   CHECK_RETURN(dsl_input_dec.copy_to(chrl_work1, 0xc));
   chrl_work1[0xc] = 0;

   // Check first 4 bytes
   static const char ach_comp[] = {'R', 'F', 'B', ' '};
   iml4 = memcmp(ach_comp, chrl_work1, sizeof(ach_comp));
   if(iml4 != 0) {
      ERROR_MACRO_RDP(true, "Wrong format of server protocol version: \"%s\"\nThe destination server is probably no VNC-server.", chrl_work1);
   }

   // Get version number
   iml4 = 0;
   for(int in_i = 4; in_i < 7; in_i++){
      iml4 *= 10;
      char ach_digit = chrl_work1[in_i];
      if((ach_digit < '0') || (ach_digit > '9'))
         ERROR_MACRO_RDP(true, "Wrong format of server protocol version: \"%s\"", chrl_work1);
      iml4 += ach_digit - '0';
   }

   // Get subversion number
   iml3 = 0;
   for(int in_i = 8; in_i < 11; in_i++){
      iml3 *= 10;
      char ach_digit = chrl_work1[in_i];
      if((ach_digit < '0') || (ach_digit > '9'))
         ERROR_MACRO_RDP(true, "Wrong format of server protocol version: \"%s\"", chrl_work1);
      iml3 += ach_digit - '0';
   }

   M_SDH_PRINTF_I("contacted RFB server version %d.%d.", iml4, iml3 );

   // Check, if there is still data
   if(!dsl_input_dec.empty()){

      // Sometimes there is a message, which we want to print out. 
      iml1 = dsl_input_dec.get_bytes_left();
      iml2 = 0; iml3 = 0;
      if(iml1 > 8){
         // Real-VNC-type-messages?
         CHECK_RETURN(dsl_input_dec.read_32_be(&iml2));
         CHECK_RETURN(dsl_input_dec.read_32_be(&iml3));
         if(iml2 == 0){
            if(iml3 > dsl_input_dec.get_bytes_left())
               iml3 = dsl_input_dec.get_bytes_left();
            if(iml3 > 0xff)
               iml3 = 0xff;
            char achr_message[0x100];
            achr_message[iml3] = 0;
            dsl_input_dec.copy_to(achr_message, iml3);

            ERROR_MACRO_RDP(false, "VNC-Server send message: %s", achr_message);

         }
      }

      ERROR_MACRO_RDP(true, "Still Data left at end of first message: 0x%x bytes (iml2=0x%x iml3=0x%x)", iml1, iml2, iml3);
   }

   // Decide on version
   if(iml4 < adsl_session->inc_major_version){
      adsl_session->inc_major_version = iml4;
      adsl_session->inc_minor_version = iml3;
   } else if(iml4 == adsl_session->inc_major_version){
      if(iml3 < adsl_session->inc_minor_version)
         adsl_session->inc_minor_version = iml3; 
   }

   // Send version
   GET_VNC_OUTPUT_GATHER(0xc);       
#if !(defined HL_UNIX)
   sprintf_s(achl1, 0xc, "RFB %03i.%03i", adsl_session->inc_major_version, adsl_session->inc_minor_version);
#else
   sprintf(achl1, "RFB %03i.%03i", adsl_session->inc_major_version, adsl_session->inc_minor_version);
#endif   
   achl1[0xb] = 0xa;
   
   // Print out version
   m_rdp_printf(&dsl_sdh_call_1, "Using VNC-Version %d.%d.\n", adsl_session->inc_major_version, adsl_session->inc_minor_version);
   if(adsl_session->inc_fbu_behavior > 0)
      m_rdp_printf(&dsl_sdh_call_1, "<fbu-behavior>%d</fbu-behavior>", adsl_session->inc_fbu_behavior);  
   
   // check version number and decide how to go on from here
   adsl_session->iec_srfbc = ied_srfbc_wait_sec_type;  /* wait security types supported */
   // Different security-type-message from version 3.7 on.
   if((adsl_session->inc_major_version > 3) || ((adsl_session->inc_major_version == 3) && (adsl_session->inc_minor_version > 6))){
      // Version >= 3.007: [RFB Protocol] 6.1.2 Security: Version 3.7 onwards: The server lists the security types which it supports: 
      adsl_session->iec_srfbc = ied_srfbc_wait_sec_type_3_7;  /* wait security types supported */
   }
   goto p_proc_inp_70;                      /* the input has been processed */

//  ___                  _ _          _                     
// / __| ___ __ _  _ _ _(_) |_ _  _  | |_ _  _ _ __  ___ ___
// \__ \/ -_) _| || | '_| |  _| || | |  _| || | '_ \/ -_|_-<
// |___/\___\__|\_,_|_| |_|\__|\_, |  \__|\_, | .__/\___/__/
//                             |__/       |__/|_|           

// Receive Security type for Versions < 3.7
p_cl_auth_before_3_7:                            /* read authentication message */
   if(dsl_input_dec.get_bytes_left() < 4) // wait until all bytes are here
      goto p_proc_inp_70;
   CHECK_RETURN(dsl_input_dec.read_32_be(&iml1));
   adsl_session->ucc_chosen_sec_type = (unsigned char) iml1;
   goto p_cl_after_sec_type;

// Negotiate Security type for Versions >= 3.7
p_cl_auth_3_7: {
   CHECK_RETURN(dsl_input_dec.peek_8(&iml1));
   //DEF_DEBUG_PRINTF("No of security types: " << iml1);
   if(dsl_input_dec.get_bytes_left() < iml1 + 1) // wait until all bytes are here
      goto p_proc_inp_70;

   dsl_input_dec.skip(1); // Skip Number of bytes
   dsl_input_dec.copy_to(chrl_work1, iml1);

   // Decide on security type
   dsd_security_type_setting dsl_sec_type_setting = dsds_security_type_settings[adsl_session->inc_sec_type_setting];
   if(adsl_session->inc_sec_type_setting)
      m_rdp_printf(&dsl_sdh_call_1, "Encryption set to: %s", achrs_security_type_settings[adsl_session->inc_sec_type_setting]);

   // VNC-Server chooses
   if(adsl_session->inc_sec_type_setting == 1){
      for(int in_i = 0; in_i < iml1; in_i++){
         for(int in_u = 0; in_u < dsl_sec_type_setting.inc_num_allowed_security_types; in_u++){
            if(((unsigned char) chrl_work1[in_i]) == dsl_sec_type_setting.uchc_allowed_security_types[in_u]){
               adsl_session->ucc_chosen_sec_type = chrl_work1[in_i];
               goto p_cl_auth_3_7_send_sec_type;
            }
         }
      }
   } else {
      for(int in_u = 0; in_u < dsl_sec_type_setting.inc_num_allowed_security_types; in_u++){
        for(int in_i = 0; in_i < iml1; in_i++){
            if(((unsigned char) chrl_work1[in_i]) == dsl_sec_type_setting.uchc_allowed_security_types[in_u]){
               adsl_session->ucc_chosen_sec_type = chrl_work1[in_i];
               goto p_cl_auth_3_7_send_sec_type;
            }
         }
      }
   }

   // No matching security type. Print out good error-message.
   char achrl_server[0x80];
   iml2 = 0;
   for(int inl_i = 0; inl_i < iml1; inl_i++)
#if !(defined HL_UNIX)
      iml2 += sprintf_s(achrl_server + iml2, 0x80 - iml2, "%02x ", chrl_work1[inl_i] & 0xff);
#else
      iml2 += sprintf(achrl_server + iml2, "%02x ", chrl_work1[inl_i] & 0xff);
#endif

   char achrl_client[0x80];
   iml2 = 0;
   for(int inl_i = 0; inl_i < dsl_sec_type_setting.inc_num_allowed_security_types; inl_i++)
#if !(defined HL_UNIX)
      iml2 += sprintf_s(achrl_client + iml2, 0x80 - iml2, "%02x ", dsl_sec_type_setting.uchc_allowed_security_types[inl_i] & 0xff);
#else
      iml2 += sprintf(achrl_client + iml2, "%02x ", dsl_sec_type_setting.uchc_allowed_security_types[inl_i] & 0xff);
#endif

   // Encryption always on and VNC-server cannot do encryption?
   if(adsl_session->inc_sec_type_setting > 3){
      for(int in_i = 0; in_i < iml1; in_i++){
         if(((unsigned char) chrl_work1[in_i]) == rfb_sectype_VNCAthentication)
            ERROR_MACRO_RDP(true, "This VNC-Server does not support the implemented encryption, but the regular VNC-Authentication.\nChange the setting \"<encryption>\" to \"prefer-on\" and try again!"
            "\n\nSecurity-types, offered by server: %s\nSecurity-types, supported by VNC-Bridge with setting \"%s\": %s",
               achrl_server, achrs_security_type_settings[adsl_session->inc_sec_type_setting], achrl_client);
      }
      for(int in_i = 0; in_i < iml1; in_i++){
         if(((unsigned char) chrl_work1[in_i]) == rfb_sectype_None)
            ERROR_MACRO_RDP(true, "This VNC-Server does not support the implemented encryption, but can be reached without any Authentication.\nChange the setting \"<encryption>\" to \"prefer-on\" and try again!"
            "\n\nSecurity-types, offered by server: %s\nSecurity-types, supported by VNC-Bridge with setting \"%s\": %s",
               achrl_server, achrs_security_type_settings[adsl_session->inc_sec_type_setting], achrl_client);
      }
   }

   ERROR_MACRO_RDP(true, "No matching security type!"
            "\n\nSecurity-types, offered by server: %s\nSecurity-types, supported by VNC-Bridge with setting \"%s\": %s",
      achrl_server, achrs_security_type_settings[adsl_session->inc_sec_type_setting], achrl_client);
   }

p_cl_auth_3_7_send_sec_type:

   //DEF_DEBUG_PRINTF("Sending security type 0x%02x" << (int) adsl_session->ucc_chosen_sec_type);
   GET_VNC_OUTPUT_GATHER(1);
   *achl1 = adsl_session->ucc_chosen_sec_type;
   goto p_cl_after_sec_type;

p_cl_after_sec_type:

   // Print out information about security type
   M_SDH_PRINTF_I("received authentication scheme 0X%02X.", adsl_session->ucc_chosen_sec_type );
   m_rdp_printf(&dsl_sdh_call_1, "Using security type (0x%x) %s.", adsl_session->ucc_chosen_sec_type, m_get_text_security_type(adsl_session->ucc_chosen_sec_type));
   
   // Decide how to go on
   switch(adsl_session->ucc_chosen_sec_type){
      case rfb_sectype_None:
         adsl_session->inc_authentication = 0;
         goto p_cl_send_client_init;
      case rfb_sectype_VNCAthentication:
         adsl_session->iec_srfbc = ied_srfbc_getchallenge;
         adsl_session->inc_authentication = 2;
         goto p_ifunc_from_server_20;

      case rfb_sectype_ra2:
      case rfb_sectype_ra2ne:
         adsl_session->boc_use_sha_256 = FALSE;
         adsl_session->inc_len_aes_key = 0x10;
         adsl_session->iec_srfbc = ied_srfbc_rsa_key;
         goto p_ifunc_from_server_20;

      case rfb_sectype_ra2_256:
      case rfb_sectype_ra2ne_256:
         adsl_session->boc_use_sha_256 = TRUE;
         adsl_session->inc_len_aes_key = 0x20;
         adsl_session->iec_srfbc = ied_srfbc_rsa_key;
         goto p_ifunc_from_server_20;

      case rfb_sectype_Invalid: {
         // Sometimes there is a message, which we want to print out. 
         // Known messages: 
         // usrs_error_no_supp_sec_type_3_3: No configured security type is supported by 3.3 viewer

         if(dsl_input_dec.get_bytes_left() > 4){
            CHECK_RETURN(dsl_input_dec.read_32_be(&iml1));
            if(iml1 > dsl_input_dec.get_bytes_left())
               iml1 = dsl_input_dec.get_bytes_left();
            if(iml1 > 0x100)
               iml1 = 0x100;
            char achr_message[0x100];
            memset(achr_message, 0, 0x100);
            CHECK_RETURN(dsl_input_dec.copy_to(achr_message, iml1));

            ERROR_MACRO_RDP(false, "VNC-server send message: %s", achr_message);
         }
      } 
      default:
         ERROR_MACRO_RDP(true, "Unknown security type: 0x%02x", adsl_session->ucc_chosen_sec_type);
   }

// __   ___  _  ___     _       _   _            _   _  __ _         _   _          
// \ \ / / \| |/ __|   /_\ _  _| |_| |_  ___ _ _| |_(_)/ _(_)__ __ _| |_(_)___ _ _  
//  \ V /| .` | (__   / _ \ || |  _| ' \/ -_) ' \  _| |  _| / _/ _` |  _| / _ \ ' \ 
//   \_/ |_|\_|\___| /_/ \_\_,_|\__|_||_\___|_||_\__|_|_| |_\__\__,_|\__|_\___/_||_|
// VNC Authentication

p_cl_challenge:                              /* get challenge           */
   if(dsl_input_dec.get_bytes_left() < 0x10) // 6.2.2 VNC Authentication: always 16 bytes
      goto p_proc_inp_70;

   m_rdp_printf(&dsl_sdh_call_1, "Authenticating with VNC-password from %s.", achrs_authentication_settings_test[adsl_session->inc_authentication_setting]);
   char chrl_vnc_auth_challenge[0x10];  /* received VNC authentication challenge */
   CHECK_RETURN(dsl_input_dec.copy_to(chrl_vnc_auth_challenge, 0x10));
   GET_VNC_OUTPUT_GATHER(0x10);

   for( iml1 = 0; iml1 < NORM_LEN_RBF_PASSWORD; iml1++ ) {
      chrl_work1[iml1] = uchg_bitswap_tab[ *((unsigned char *) adsl_session->dsc_vnc_password.get_data() + iml1) ];
   }
   GenDESSubKeys( (unsigned char *) chrl_work1, (unsigned int *) imrl_des_key_array );
   DES_ecb_encrypt_decrypt( (unsigned char *) chrl_vnc_auth_challenge,
        (unsigned char *) achl1,
        (unsigned int *) imrl_des_key_array, 2, DES_ENCRYPT );

   adsl_session->iec_srfbc = ied_srfbc_wait_auth_resp;  /* wait authentication response */
   goto p_proc_inp_70;                      /* the input has been processed */

//  ___    _    ___     ___  ___   _                  _     _   ___ ___   _      _ _   
// | _ \  /_\  |_  )   | _ \/ __| /_\    __ _ _ _  __| |   /_\ | __/ __| (_)_ _ (_) |_ 
// |   / / _ \  / /    |   /\__ \/ _ \  / _` | ' \/ _` |  / _ \| _|\__ \ | | ' \| |  _|
// |_|_\/_/ \_\/___|   |_|_\|___/_/ \_\ \__,_|_||_\__,_| /_/ \_\___|___/ |_|_||_|_|\__|
// RA2: RSA and AES init
p_cl_rsa_key: {

   if(dsl_input_dec.get_bytes_left() < 0x204) // wait until all bytes are here
      goto p_proc_inp_70;

   // Send our rsa public key 
   GET_VNC_OUTPUT_GATHER(0x4);
   write_32_be(&achl1, sizeof(usrs_rsa_modul) * 8);
   GET_VNC_OUTPUT_GATHER(0x0);
   adsl_gai1_out_1->achc_ginp_cur = (char*) usrs_rsa_modul;
   adsl_gai1_out_1->achc_ginp_end = (char*) usrs_rsa_modul + sizeof(usrs_rsa_modul);
   const int in_number_zeros = 0x200 - sizeof(usrs_rsa_modul) - sizeof(usrs_rsa_pubexp);
   GET_VNC_OUTPUT_GATHER(in_number_zeros);
   memset(achl1, 0, in_number_zeros);
   GET_VNC_OUTPUT_GATHER((int)sizeof(usrs_rsa_pubexp));
   adsl_gai1_out_1->achc_ginp_cur = (char*) usrs_rsa_pubexp;
   adsl_gai1_out_1->achc_ginp_end = (char*) usrs_rsa_pubexp + sizeof(usrs_rsa_pubexp);

   // Read and check length of server public key
   int in_len_server_public;
   CHECK_RETURN(dsl_input_dec.read_32_be(&in_len_server_public));
   adsl_session->inc_len_server_public_bytes = (in_len_server_public + 7) / 8;
   if((adsl_session->inc_len_server_public_bytes > 0x200) || (adsl_session->inc_len_server_public_bytes > sizeof(chrl_work1))){
      ERROR_MACRO_RDP(true, "RSA public from server too big: 0x%x", in_len_server_public);
   }

   // Copy server RSA public key and modulos
   CHECK_RETURN(dsl_input_dec.copy_to((char*) adsl_session->uchr_server_public, adsl_session->inc_len_server_public_bytes));
   CHECK_RETURN(dsl_input_dec.skip(0x200 - 4 - adsl_session->inc_len_server_public_bytes));
   unsigned char uchr_server_modulos[0x4];
   CHECK_RETURN(dsl_input_dec.copy_to((char*) uchr_server_modulos, 4));

   // Calculate digests of RSA-keys
   memset(chrl_work1, 0x0, sizeof(chrl_work1));
   char chrl_len_our_modul[0x4];
   achl1 = chrl_len_our_modul;
   write_32_be(&achl1, sizeof(usrs_rsa_modul) * 8);
   char chrl_len_server_modul[0x4];
   achl1 = chrl_len_server_modul;
   write_32_be(&achl1, in_len_server_public);

   if(adsl_session->boc_use_sha_256){
      int inrl_sha[SHA256_ARRAY_SIZE];
      // Calculate digest of RSA-keys to send
      SHA256_Init(inrl_sha);
      // Our packet
      SHA256_Update(inrl_sha, chrl_len_our_modul, 0, 0x4);
      SHA256_Update(inrl_sha, (char*) usrs_rsa_modul, 0, sizeof(usrs_rsa_modul));
      SHA256_Update(inrl_sha, chrl_work1, 0, 0x200 - sizeof(usrs_rsa_modul) - sizeof(usrs_rsa_pubexp));
      SHA256_Update(inrl_sha, (char*) usrs_rsa_pubexp, 0, sizeof(usrs_rsa_pubexp));
      // Server packet
      SHA256_Update(inrl_sha, chrl_len_server_modul, 0, 0x4);
      SHA256_Update(inrl_sha, (char*) adsl_session->uchr_server_public, 0, adsl_session->inc_len_server_public_bytes);
      SHA256_Update(inrl_sha, chrl_work1, 0, 0x200 - 4 - adsl_session->inc_len_server_public_bytes);
      SHA256_Update(inrl_sha, (char*) uchr_server_modulos, 0, 0x4);
      // Final 
      SHA256_Final(inrl_sha, adsl_session->chrc_rsa_keys_digest_send, 0);

      // Calculate digest of RSA-keys to check
      SHA256_Init(inrl_sha);
      // Server packet
      SHA256_Update(inrl_sha, chrl_len_server_modul, 0, 0x4);
      SHA256_Update(inrl_sha, (char*) adsl_session->uchr_server_public, 0, adsl_session->inc_len_server_public_bytes);
      SHA256_Update(inrl_sha, chrl_work1, 0, 0x200 - 4 - adsl_session->inc_len_server_public_bytes);
      SHA256_Update(inrl_sha, (char*) uchr_server_modulos, 0, 0x4);
      // Our packet
      SHA256_Update(inrl_sha, chrl_len_our_modul, 0, 0x4);
      SHA256_Update(inrl_sha, (char*) usrs_rsa_modul, 0, sizeof(usrs_rsa_modul));
      SHA256_Update(inrl_sha, chrl_work1, 0, 0x200 - sizeof(usrs_rsa_modul) - sizeof(usrs_rsa_pubexp));
      SHA256_Update(inrl_sha, (char*) usrs_rsa_pubexp, 0, sizeof(usrs_rsa_pubexp));
      // Final 
      SHA256_Final(inrl_sha, adsl_session->chrc_rsa_keys_digest_check, 0);
   } else {
      int inrl_sha[SHA_ARRAY_SIZE];
      // Calculate digest of RSA-keys to send
      SHA1_Init(inrl_sha);
      // Our packet
      SHA1_Update(inrl_sha, chrl_len_our_modul, 0, 0x4);
      SHA1_Update(inrl_sha, (char*) usrs_rsa_modul, 0, sizeof(usrs_rsa_modul));
      SHA1_Update(inrl_sha, chrl_work1, 0, 0x200 - sizeof(usrs_rsa_modul) - sizeof(usrs_rsa_pubexp));
      SHA1_Update(inrl_sha, (char*) usrs_rsa_pubexp, 0, sizeof(usrs_rsa_pubexp));
      // Server packet
      SHA1_Update(inrl_sha, chrl_len_server_modul, 0, 0x4);
      SHA1_Update(inrl_sha, (char*) adsl_session->uchr_server_public, 0, adsl_session->inc_len_server_public_bytes);
      SHA1_Update(inrl_sha, chrl_work1, 0, 0x200 - 4 - adsl_session->inc_len_server_public_bytes);
      SHA1_Update(inrl_sha, (char*) uchr_server_modulos, 0, 0x4);
      // Final 
      SHA1_Final(inrl_sha, adsl_session->chrc_rsa_keys_digest_send, 0);

      // Calculate digest of RSA-keys to check
      SHA1_Init(inrl_sha);
      // Server packet
      SHA1_Update(inrl_sha, chrl_len_server_modul, 0, 0x4);
      SHA1_Update(inrl_sha, (char*) adsl_session->uchr_server_public, 0, adsl_session->inc_len_server_public_bytes);
      SHA1_Update(inrl_sha, chrl_work1, 0, 0x200 - 4 - adsl_session->inc_len_server_public_bytes);
      SHA1_Update(inrl_sha, (char*) uchr_server_modulos, 0, 0x4);
      // Our packet
      SHA1_Update(inrl_sha, chrl_len_our_modul, 0, 0x4);
      SHA1_Update(inrl_sha, (char*) usrs_rsa_modul, 0, sizeof(usrs_rsa_modul));
      SHA1_Update(inrl_sha, chrl_work1, 0, 0x200 - sizeof(usrs_rsa_modul) - sizeof(usrs_rsa_pubexp));
      SHA1_Update(inrl_sha, (char*) usrs_rsa_pubexp, 0, sizeof(usrs_rsa_pubexp));
      // Final 
      SHA1_Final(inrl_sha, adsl_session->chrc_rsa_keys_digest_check, 0);
   }

   adsl_session->iec_srfbc = ied_srfbc_aes_key;
   goto p_proc_inp_70;
   }

p_cl_aes_key: {
   if(dsl_input_dec.get_bytes_left() < 0x2) // wait until two bytes of len are there
      goto p_proc_inp_70;
   int inl_len_encr;
   CHECK_RETURN(dsl_input_dec.peek_16_be(&inl_len_encr));
   if(dsl_input_dec.get_bytes_left() < 0x2 + inl_len_encr) // wait until complete package is there
      goto p_proc_inp_70;
   CHECK_RETURN(dsl_input_dec.skip(2));   // Skip len

   // Copy package into workarea
   CHECK_RETURN(dsl_input_dec.copy_to(chrl_work1, inl_len_encr));

   // Decyrpt data
   unsigned char uchrl_decrypted[0x100];
   int in_len_decr = sizeof(uchrl_decrypted);
#ifdef XH_INTERFACE
   ds__hmem dsl_new_struct;
   memset(&dsl_new_struct, 0, sizeof(ds__hmem));
   dsl_new_struct.in__aux_up_version = 1;
   dsl_new_struct.am__aux2 = adsp_hl_clib_1->amc_aux;
   dsl_new_struct.in__flags = 0;
   dsl_new_struct.vp__context = adsp_hl_clib_1->vpc_userfld;
#endif
#ifdef __INSURE__
	//disables Insure++ checking (m_rsa_crypt_raw_big uses lnum, which cause an Insure-error)
	_Insure_checking_enable(0); 
#endif
   iml1 = m_rsa_crypt_raw_big(
#ifdef XH_INTERFACE
                              &dsl_new_struct,
#endif
                              (unsigned char*) chrl_work1, inl_len_encr, 
                              (unsigned char*) usrs_rsa_privexp, sizeof(usrs_rsa_privexp),
                              (unsigned char*) usrs_rsa_modul, sizeof(usrs_rsa_modul),
                              uchrl_decrypted, &in_len_decr);

#ifdef __INSURE__
	//enables Insure++ checking
	_Insure_checking_enable(1);
#endif
#ifdef XH_INTERFACE
   HMemMgrFree(&dsl_new_struct);
#endif
   if(iml1 != 0)
      ERROR_MACRO_RDP(true, "Error in RSA-decryption. 0x%x", iml1);

   // Check the decrypted data
   if((in_len_decr != 0xff) || (uchrl_decrypted[0] != 0x2)) // Decrypted package starts with 0x00 0x02, so len = 0xff. 
      ERROR_MACRO_RDP(true, "Error RSA-decryption. in_len_decr=0x%x uchrl_decrypted[0]=0x%02x", in_len_decr, uchrl_decrypted[0]);
   if(uchrl_decrypted[in_len_decr - 1 - adsl_session->inc_len_aes_key] != 0)
      ERROR_MACRO_RDP(true, "Error RSA-decryption. in_len_decr=0x%x", in_len_decr);

   // Copy server AES-key
   char chrl_server_aes_key[0x20];
   memcpy(chrl_server_aes_key, uchrl_decrypted + in_len_decr - adsl_session->inc_len_aes_key, adsl_session->inc_len_aes_key);

   // Get randoms for our AES-key
   char chrl_our_aes_key[0x20];
   CHECK_RETURN((*adsp_hl_clib_1->amc_aux)(adsp_hl_clib_1->vpc_userfld, 
      DEF_AUX_RANDOM_RAW, chrl_our_aes_key, adsl_session->inc_len_aes_key));

   // copy our AES-key
   memcpy(uchrl_decrypted + in_len_decr - adsl_session->inc_len_aes_key, chrl_our_aes_key, adsl_session->inc_len_aes_key);

   // Get secure randoms for our AES-key
   int inl_len_randoms = in_len_decr - 2 - adsl_session->inc_len_aes_key;
   unsigned char* auch_start_randoms = uchrl_decrypted + 1;
   BOOL bol_new_randoms = TRUE;
   while(bol_new_randoms){
      CHECK_RETURN((*adsp_hl_clib_1->amc_aux)(adsp_hl_clib_1->vpc_userfld, 
         DEF_AUX_RANDOM_RAW, auch_start_randoms, inl_len_randoms));
      bol_new_randoms = FALSE;
      for(int inl_i = 0; inl_i < inl_len_randoms; inl_i++){
         if(auch_start_randoms[inl_i] == 0x00){
            bol_new_randoms = TRUE;
            break;
         }
      }
   }

   // Send our AES-key
   GET_VNC_OUTPUT_GATHER(0x202);  // Make space for now, adsl_gai1_out_1->achc_ginp_end is set later

   // Encrypt our AES-key direcly into output-area
   inl_len_encr = 0x200;
#ifdef XH_INTERFACE
   memset(&dsl_new_struct, 0, sizeof(ds__hmem));
   dsl_new_struct.in__aux_up_version = 1;
   dsl_new_struct.am__aux2 = adsp_hl_clib_1->amc_aux;
   dsl_new_struct.in__flags = 0;
   dsl_new_struct.vp__context = adsp_hl_clib_1->vpc_userfld;
#endif
#ifdef __INSURE__
	//disables Insure++ checking (m_rsa_crypt_raw_big uses lnum, which cause an Insure-error)
	_Insure_checking_enable(0); 
#endif
   iml1 = m_rsa_crypt_raw_big(
#ifdef XH_INTERFACE
                              &dsl_new_struct,
#endif
	                         (unsigned char*) uchrl_decrypted, in_len_decr, 
                              (unsigned char*) usrs_rsa_pubexp, sizeof(usrs_rsa_pubexp),
                              adsl_session->uchr_server_public, adsl_session->inc_len_server_public_bytes,
                             (unsigned char*) achl1 + 2, &inl_len_encr);
#ifdef __INSURE__
	//enables Insure++ checking
	_Insure_checking_enable(1);
#endif
#ifdef XH_INTERFACE
   HMemMgrFree(&dsl_new_struct);
#endif
   if(iml1 != 0)
      ERROR_MACRO_RDP(true, "RSA-encryption returned 0x%x", iml1);

   write_16_be(&achl1, inl_len_encr);
   adsl_gai1_out_1->achc_ginp_end = achl1 + inl_len_encr;

   // Get digests over the two AES-keys and set up AES-decryptiont and encryption
   if(adsl_session->boc_use_sha_256){
      int inrl_sha[SHA256_ARRAY_SIZE];
      // Decryption:
      SHA256_Init(inrl_sha);
      SHA256_Update(inrl_sha, chrl_our_aes_key, 0, adsl_session->inc_len_aes_key);
      SHA256_Update(inrl_sha, chrl_server_aes_key, 0, adsl_session->inc_len_aes_key);
      SHA256_Final(inrl_sha, chrl_work1, 0);
      m_eax_init_ctx((unsigned char*) chrl_work1, adsl_session->inc_len_aes_key, adsl_session->adsc_eax_dec);
      // Encryption:
      SHA256_Init(inrl_sha);
      SHA256_Update(inrl_sha, chrl_server_aes_key, 0, adsl_session->inc_len_aes_key);
      SHA256_Update(inrl_sha, chrl_our_aes_key, 0, adsl_session->inc_len_aes_key);
      SHA256_Final(inrl_sha, chrl_work1, 0);
      m_eax_init_ctx((unsigned char*) chrl_work1, adsl_session->inc_len_aes_key, adsl_session->adsc_eax_enc);
   } else {
      int inrl_sha[SHA_ARRAY_SIZE];
      // Decryption:
      SHA1_Init(inrl_sha);
      SHA1_Update(inrl_sha, chrl_our_aes_key, 0, adsl_session->inc_len_aes_key);
      SHA1_Update(inrl_sha, chrl_server_aes_key, 0, adsl_session->inc_len_aes_key);
      SHA1_Final(inrl_sha, chrl_work1, 0);
      m_eax_init_ctx((unsigned char*) chrl_work1, adsl_session->inc_len_aes_key, adsl_session->adsc_eax_dec);
      // Encryption:
      SHA1_Init(inrl_sha);
      SHA1_Update(inrl_sha, chrl_server_aes_key, 0, adsl_session->inc_len_aes_key);
      SHA1_Update(inrl_sha, chrl_our_aes_key, 0, adsl_session->inc_len_aes_key);
      SHA1_Final(inrl_sha, chrl_work1, 0);
      m_eax_init_ctx((unsigned char*) chrl_work1, adsl_session->inc_len_aes_key, adsl_session->adsc_eax_enc);
   }
   adsl_session->ilc_aes_dec_counter = 0;
   adsl_session->ilc_aes_enc_counter = 0;

   adsl_session->iec_srfbc = ied_srfbc_turnon_aes;
   goto p_proc_inp_70;
   }

p_cl_turnon_aes:
   // Turn on aes and decrypt actual data
   adsl_session->boc_do_aes = TRUE;
   adsl_session->iec_srfbc = ied_srfbc_rsa_digest;
   goto p_ifunc_from_server;

p_cl_rsa_digest: 
   // Get the digest of the RSA-keys
   if(adsl_session->boc_use_sha_256){
      if(dsl_input_dec.get_bytes_left() < 0x20) // wait until two bytes of len are there
         goto p_proc_inp_70;
   } else {
      if(dsl_input_dec.get_bytes_left() < 0x14) // wait until two bytes of len are there
         goto p_proc_inp_70;
   }

   // Now send our key
   GET_VNC_OUTPUT_GATHER(0);
   adsl_gai1_out_1->achc_ginp_cur = adsl_session->chrc_rsa_keys_digest_send;

   // Compare session key, which was send and set end of the key, we send
   if(adsl_session->boc_use_sha_256){
      CHECK_RETURN(dsl_input_dec.memcomp(adsl_session->chrc_rsa_keys_digest_check, 0x20, &iml1));
      adsl_gai1_out_1->achc_ginp_end = adsl_session->chrc_rsa_keys_digest_send + 0x20;
   } else {
      CHECK_RETURN(dsl_input_dec.memcomp(adsl_session->chrc_rsa_keys_digest_check, 0x14, &iml1));
      adsl_gai1_out_1->achc_ginp_end = adsl_session->chrc_rsa_keys_digest_send + 0x14;
   }
   if(iml1 != 0)
      ERROR_MACRO_RDP(true, "RA2: Session keys mismatch!");

   // Report success
   m_rdp_printf(&dsl_sdh_call_1, "RA2: Session keys o.k.");

   adsl_session->iec_srfbc = ied_srfbc_aes_auth_type;
   goto p_proc_inp_70;

//  ___    _    ___     _       _   _            _   _         _   _          
// | _ \  /_\  |_  )   /_\ _  _| |_| |_  ___ _ _| |_(_)__ __ _| |_(_)___ _ _  
// |   / / _ \  / /   / _ \ || |  _| ' \/ -_) ' \  _| / _/ _` |  _| / _ \ ' \ 
// |_|_\/_/ \_\/___| /_/ \_\_,_|\__|_||_\___|_||_\__|_\__\__,_|\__|_\___/_||_|
//
// RA2 Authentication
//
p_cl_aes_auth_type:
   CHECK_RETURN(dsl_input_dec.read_8(&adsl_session->inc_authentication));
//#if !(defined HL_LINUX)
//   const char* achl_auth_from = achrs_authentication_settings_test[adsl_session->inc_authentication_setting];
//#else
   achl_auth_from = achrs_authentication_settings_test[adsl_session->inc_authentication_setting];
//#endif
   switch(adsl_session->inc_authentication){
      case 2: // VNC-Authentication
         if(adsl_session->inc_len_vnc_password == 0){
            bol1 = m_rfb_error(&dsl_sdh_call_1, __FUNCTION__, __LINE__, false, "No VNC-password set in %s.",  
               achrs_authentication_settings_test[adsl_session->inc_authentication_setting]);
            goto p_cl_auth_error;
         }
         GET_VNC_OUTPUT_GATHER(adsl_session->inc_len_vnc_password + 2);
         write_16_be(&achl1, adsl_session->inc_len_vnc_password);
         memcpy(achl1, adsl_session->dsc_vnc_password.get_data(), adsl_session->inc_len_vnc_password);
         m_rdp_printf(&dsl_sdh_call_1, "Authenticating with VNC-password from %s.", achl_auth_from);
         break;
      case 1: // User + Password Authentication
         if((adsl_session->inc_len_host_user == 0) || (adsl_session->inc_len_host_password == 0)){
            bol1 = false;
            if(adsl_session->inc_len_host_user == 0){
               bol1 = m_rfb_error(&dsl_sdh_call_1, __FUNCTION__, __LINE__, false, "No host-user set in %s.", 
                  achrs_authentication_settings_test[adsl_session->inc_authentication_setting]);
            }
            if(adsl_session->inc_len_host_password == 0){
               bol1 |= m_rfb_error(&dsl_sdh_call_1, __FUNCTION__, __LINE__, false, "No host-password set in %s.",
                  achrs_authentication_settings_test[adsl_session->inc_authentication_setting]);
            }
            goto p_cl_auth_error;
         }
         GET_VNC_OUTPUT_GATHER(1 + adsl_session->inc_len_host_user + 1 + adsl_session->inc_len_host_password);
         *achl1++ = (unsigned char) adsl_session->inc_len_host_user;
         memcpy(achl1, adsl_session->dsc_host_user.get_data(), adsl_session->inc_len_host_user);
         achl1 += adsl_session->inc_len_host_user;
         *achl1++ = (unsigned char) adsl_session->inc_len_host_password;
         memcpy(achl1, adsl_session->dsc_host_password.get_data(), adsl_session->inc_len_host_password);
         m_rdp_printf(&dsl_sdh_call_1, "Authenticating with host-user and host-password from %s", achl_auth_from);
         break;
      case 0: // No authentication -> server sends authentifaction response immediately. We don't have to send anything
         M_SDH_PRINTF_I("RA2 authentication Scheme - authentication type 0 (No Password)");
         m_rdp_printf(&dsl_sdh_call_1, "No Authentication required from server.");
         break;
      default: 
         ERROR_MACRO_RDP(true, "Unknown authentication in RA2: 0x%x", iml1);
   }
   adsl_session->iec_srfbc = ied_srfbc_wait_auth_resp;
   
   // Turn off AES-Encryption after sending the authentication?
   // Decide how to go on
   switch(adsl_session->ucc_chosen_sec_type){
      case rfb_sectype_ra2:
      case rfb_sectype_ra2_256:
         break;
      case rfb_sectype_ra2ne:
      case rfb_sectype_ra2ne_256:
         // This is a special case:
         // -> The outgoing data has to be encrypted
         // -> There could be still inputdata (no authentication -> authentication response is already there), which is unencrypted.
         bol_turnoff_aes_encryption_after_sending = TRUE;
         m_rdp_printf(&dsl_sdh_call_1, "Info: The connection between the VNC-Server and the VNC-Bridge is not encrypted.");
         break;
      default:
         ERROR_MACRO_RDP(true, "This security type is not allowed at this point: 0x%02x", adsl_session->ucc_chosen_sec_type);
   }

   // In case of no authentication the authentication response could be already there. 
   goto p_cl_auth_resp;

//  ___                                   _       _   _            _   _         _   _          
// | _ \___ ____ __  ___ _ _  ___ ___    /_\ _  _| |_| |_  ___ _ _| |_(_)__ __ _| |_(_)___ _ _  
// |   / -_|_-< '_ \/ _ \ ' \(_-</ -_)  / _ \ || |  _| ' \/ -_) ' \  _| / _/ _` |  _| / _ \ ' \ 
// |_|_\___/__/ .__/\___/_||_/__/\___| /_/ \_\_,_|\__|_||_\___|_||_\__|_\__\__,_|\__|_\___/_||_|
//            |_|                                                                               

p_cl_auth_resp: {                          /* read response authentication */
   if(dsl_input_dec.get_bytes_left() < 0x4) // wait until all bytes are there
      goto p_proc_inp_70;

   // Now read the message
   CHECK_RETURN(dsl_input_dec.read_32_be(&iml3));
   
   M_SDH_PRINTF_I("received response authentication 0X%08X.", iml3 );
   if(iml3 == 0){
      if(adsl_session->inc_authentication != 0)
         m_rdp_printf(&dsl_sdh_call_1, "Authentication successful.");
      goto p_cl_send_client_init;
   }
   
   bol1 = false;
   switch(adsl_session->inc_authentication){
      case 2: // VNC-Authentication
         bol1 = m_rfb_error(&dsl_sdh_call_1, __FUNCTION__, __LINE__, false, "Authentication failed (0x%x). Wrong VNC-Password in %s.", iml3, 
         achrs_authentication_settings_test[adsl_session->inc_authentication_setting]);
         break;
      case 1: // User + Password Authentication
         bol1 = m_rfb_error(&dsl_sdh_call_1, __FUNCTION__, __LINE__, false, "Authentication failed (0x%x). Wrong host-user or host-password in %s.", iml3, 
         achrs_authentication_settings_test[adsl_session->inc_authentication_setting]);
         break;
      case 0:
         bol1 = m_rfb_error(&dsl_sdh_call_1, __FUNCTION__, __LINE__, true, "Authentication failed (0x%x), even though no authentification was needed!");
         break;
      default: 
         bol1 = m_rfb_error(&dsl_sdh_call_1, __FUNCTION__, __LINE__, true, "Authentication failed (0x%x) with unknown authentication method 0x%x.",
            iml3, adsl_session->inc_authentication);
         break;
   }

p_cl_auth_error:

   if(adsl_session->inc_authentication_setting == ied_auth_setting_rdp){
      // If the authentication works through RDP-Credentials we tell JWT/MSTSC that the authentication 
      // failed through error 9. This will make JWT to ask the user to re-enter the credentials and to try to connect again. 
      dsl_orderqueue.new_command<dsd_sc_error_info>()->umc_error_info = 9;
      dsl_orderqueue.new_command<dsd_sc_order_end_shutdown>();
   } else if (adsl_session->inc_authentication_setting == ied_auth_setting_dynamic){
      ////  JB: UUU todo: The dynamic connection has to be done better and differently
      //adsl_session->boc_rfb_error = false;
      //adsl_session->iec_scc1  = ied_scc1_start;
      //GET_GATHER(0);
      //adsl_gai1_out_1->achc_ginp_cur = (char*) ucrs_out_no_server_rfb_n;
      //adsl_gai1_out_1->achc_ginp_end = adsl_gai1_out_1->achc_ginp_cur + sizeof(ucrs_out_no_server_rfb_n);
      //adsp_hl_clib_1->adsc_gai1_out_to_client = adsl_gai1_out_1;
      //return;
   }

   if(bol1){
      // No message could be printed on the splash-screen -> end the connection immediately. 
      adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
      goto p_cleanup_00;
   }
      //TODO: Future Update
      //Version 3.8: onwards If unsuccessful, the server sends a string describing the reason
      //for the failure, and then closes the connection:
      // ---------------+------------------+---------------
      //  No. of bytes  | Type     [Value] | Description
      // ---------------+------------------+---------------
      //  4             | U32              | reason-length
      //  reason-length | U8 array         | reason-string
      // ---------------+------------------+---------------
	  // JB: Than can be done with the m_rfb_error() function above. 

   goto p_rdpserv_40;
   
}

//     _ _         _                      _                               _      _ _   
//  __| (_)___ _ _| |_ ___   __ _ _ _  __| |  ___ ___ _ ___ _____ _ _ ___(_)_ _ (_) |_ 
// / _| | / -_) ' \  _|___| / _` | ' \/ _` | (_-</ -_) '_\ V / -_) '_|___| | ' \| |  _|
// \__|_|_\___|_||_\__|     \__,_|_||_\__,_| /__/\___|_|  \_/\___|_|     |_|_||_|_|\__|

p_cl_send_client_init:

   // Clear passwords from memory
   adsl_session->dsc_vnc_password.close (m_callback_free_mem, &dsl_sdh_call_1, true);
   adsl_session->dsc_host_password.close(m_callback_free_mem, &dsl_sdh_call_1, true);
   adsl_session->dsc_host_user.close    (m_callback_free_mem, &dsl_sdh_call_1, true);

   // send 6.3.1 ClientInit
   GET_VNC_OUTPUT_GATHER(1);
   *achl1 = adsl_session->chc_co_shared;
   adsl_session->iec_srfbc = ied_srfbc_wait_server_init;  /* wait ServerInitialisation message */
   m_rdp_printf(&dsl_sdh_call_1, "Sending client-init message. Shared-flag=0x%d", adsl_session->chc_co_shared);
   goto p_proc_inp_70;                      /* the input has been processed */

p_cl_seri_00:                            /* read ServerInitialisation */
   // 6.3.2 ServerInit
   if(dsl_input_dec.get_bytes_left() < 0x18) // wait until the first bytes are there (include len of name)
      goto p_proc_inp_70;
   CHECK_RETURN(dsl_input_dec.read_16_be((short*) &adsl_session->usc_fb_width));
   CHECK_RETURN(dsl_input_dec.read_16_be((short*) &adsl_session->usc_fb_height));
   CHECK_RETURN(dsl_input_dec.read_8(&adsl_session->dsc_rfb_pixel_format.chc_bits_per_pixel));
   CHECK_RETURN(dsl_input_dec.read_8(&adsl_session->dsc_rfb_pixel_format.chc_depth));
   CHECK_RETURN(dsl_input_dec.read_8(&adsl_session->dsc_rfb_pixel_format.chc_big_endian_flag));
   CHECK_RETURN(dsl_input_dec.read_8(&adsl_session->dsc_rfb_pixel_format.chc_true_colour_flag));
   CHECK_RETURN(dsl_input_dec.read_16_be(&adsl_session->dsc_rfb_pixel_format.usc_red_max));
   CHECK_RETURN(dsl_input_dec.read_16_be(&adsl_session->dsc_rfb_pixel_format.usc_green_max));
   CHECK_RETURN(dsl_input_dec.read_16_be(&adsl_session->dsc_rfb_pixel_format.usc_blue_max));
   CHECK_RETURN(dsl_input_dec.read_8(&adsl_session->dsc_rfb_pixel_format.chc_red_shift));
   CHECK_RETURN(dsl_input_dec.read_8(&adsl_session->dsc_rfb_pixel_format.chc_green_shift));
   CHECK_RETURN(dsl_input_dec.read_8(&adsl_session->dsc_rfb_pixel_format.chc_blue_shift));
   CHECK_RETURN(dsl_input_dec.skip(3));

   CHECK_RETURN(dsl_input_dec.read_32_be(&adsl_session->in_serverinit_len_name));
   adsl_session->iec_srfbc = ied_srfbc_wait_server_init_name;  

p_cl_seri_20:                               // Read the name (last field, size not known before.)

   // 6.3.2 ServerInit
   if(dsl_input_dec.get_bytes_left() < adsl_session->in_serverinit_len_name) // wait until the whole name is here
      goto p_proc_inp_70;
   CHECK_RETURN(dsl_input_dec.copy_to(chrl_work1, adsl_session->in_serverinit_len_name));

   if (adsl_session->dsc_rfb_pixel_format.chc_bits_per_pixel <= 8) {
      adsl_session->imc_bpp_rfb = 1;              /* bytes per pixel RFB     */
   } else if (adsl_session->dsc_rfb_pixel_format.chc_bits_per_pixel <= 16) {
      adsl_session->imc_bpp_rfb = 2;              /* bytes per pixel RFB     */
   } else if (adsl_session->dsc_rfb_pixel_format.chc_bits_per_pixel <= 24) {
      adsl_session->imc_bpp_rfb = 3;              /* bytes per pixel RFB     */
   } else if (adsl_session->dsc_rfb_pixel_format.chc_bits_per_pixel <= 32) {
      adsl_session->imc_bpp_rfb = 4;              /* bytes per pixel RFB     */
   } else {
      ERROR_MACRO_RDP(true, "Invalid RFB (VNC) bits per pixel value"); 
   }

   //Tracing Printf
   //DEF_DEBUG_PRINTF("ServerInitmessage: Pixel Format");
   //DEF_DEBUG_PRINTF("bits-per-pixel  : " << (int) adsl_session->dsc_rfb_pixel_format.chc_bits_per_pixel);
   //DEF_DEBUG_PRINTF("depth           : " << (int) adsl_session->dsc_rfb_pixel_format.chc_depth);
   //DEF_DEBUG_PRINTF("big-endian-flag : " << (int) adsl_session->dsc_rfb_pixel_format.chc_big_endian_flag);
   //DEF_DEBUG_PRINTF("true-colour-flag: " << (int) adsl_session->dsc_rfb_pixel_format.chc_true_colour_flag);
   //DEF_DEBUG_PRINTF("red-max         : " << (int) adsl_session->dsc_rfb_pixel_format.usc_red_max);
   //DEF_DEBUG_PRINTF("green-max       : " << (int) adsl_session->dsc_rfb_pixel_format.usc_green_max);
   //DEF_DEBUG_PRINTF("blue-max        : " << (short int) adsl_session->dsc_rfb_pixel_format.usc_blue_max);
   //DEF_DEBUG_PRINTF("red-shift       : " << (int) adsl_session->dsc_rfb_pixel_format.chc_red_shift);
   //DEF_DEBUG_PRINTF("green-shift     : " << (int) adsl_session->dsc_rfb_pixel_format.chc_green_shift);
   //DEF_DEBUG_PRINTF("blue-shift      : " << (int) adsl_session->dsc_rfb_pixel_format.chc_blue_shift);
    
   M_SDH_PRINTF_I("received session width=%d/0X%04X height=%d/0X%04X.",
      adsl_session->usc_fb_width,
      adsl_session->usc_fb_width,
      adsl_session->usc_fb_height,
      adsl_session->usc_fb_height );

   if(adsl_session->dsc_crdps_1.adsc_rdp_co->imc_cl_coldep < 15){
      m_rdp_printf(&dsl_sdh_call_1, "RDP-colordeph %i not supported, changed to 16 bpp", adsl_session->dsc_crdps_1.adsc_rdp_co->imc_cl_coldep);
      adsl_session->dsc_crdps_1.adsc_rdp_co->imc_cl_coldep = 16;
   }
   
   m_rdp_printf(&dsl_sdh_call_1, "Received ServerInitMessage. %s", 
      adsl_session->dsc_rfb_pixel_format.chc_true_colour_flag == 0 ? "" : ", true-color-flag is set.");
   m_rdp_printf(&dsl_sdh_call_1, "   Name: %.*s.", adsl_session->in_serverinit_len_name, chrl_work1);
   m_rdp_printf(&dsl_sdh_call_1, "   Screen: %d x %d, VNC-bpp: %d, VNC-colordeph: %d, RDP-coldeph: %d.", 
      adsl_session->usc_fb_width, adsl_session->usc_fb_height,
      adsl_session->dsc_rfb_pixel_format.chc_bits_per_pixel, 
      adsl_session->dsc_rfb_pixel_format.chc_depth, 
      ((adsl_session->imc_bpp_rfb <= 2) && (adsl_session->inc_coldep_rdp > 16)) ? 16 : adsl_session->dsc_crdps_1.adsc_rdp_co->imc_cl_coldep);
   
   adsl_session->iec_srfbc = ied_srfbc_conn;     /* session is connected    */
   adsl_session->iec_state_rdp = ied_state_rdp_send_change_screen;
   // Init waiting to see splash-screen
   if(adsl_session->inc_show_splash_screen > 0){
      time_t dsl_time; 
      if(adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld, DEF_AUX_GET_TIME, &dsl_time, sizeof(time_t)))
         adsl_session->ilc_wait_until = dsl_time + adsl_session->inc_show_splash_screen;
   }

   goto p_proc_inp_70;                           /* the input has been processed */

// ===================================================================================   
//     _                _                                          _                  
//  __| |___ __ ___  __| |___   _ __  ___ ______ __ _ __ _ ___ ___| |_ _  _ _ __  ___ 
// / _` / -_) _/ _ \/ _` / -_) | '  \/ -_|_-<_-</ _` / _` / -_)___|  _| || | '_ \/ -_)
// \__,_\___\__\___/\__,_\___| |_|_|_\___/__/__/\__,_\__, \___|    \__|\_, | .__/\___|
//                                                   |___/             |__/|_|        
//
// ===================================================================================   

p_cl_mt_00:                                     /* decode message-type     */
   if(dsl_input_dec.get_bytes_left() < 0x1) // wait until the first byte (=command) is there
      goto p_proc_inp_70;
   unsigned char uch_sc2cl_msg_id;
   CHECK_RETURN(dsl_input_dec.peek_8(&uch_sc2cl_msg_id));
   //DEF_DEBUG_PRINTF("Server to Client Message ID: " << (int) (UINT8) uch_sc2cl_msg_id);

   switch(uch_sc2cl_msg_id){
      case rfb_sc2cl_FramebufferUpdate:   // 6.5.1 FramebufferUpdate
         goto p_cl_framebuffer_update;

      case rfb_sc2cl_SetColourMapEntries: // 6.5.2 SetColourMapEntries
         goto p_cl_scme_00; 

      case rfb_sc2cl_Bell:                // 6.5.3 Bell
         M_SDH_PRINTF_I("bell received" );
         dsl_input_dec.skip(1); 
         goto p_cl_mt_00;           

      case rfb_sc2cl_ServerCutText:       // 6.5.4 ServerCutText - Clipboard Update from VNC Server
         goto p_cl_sct_00; 

      default: 
         ERROR_MACRO_RDP(true, "received unknown message-type 0X%02X.", uch_sc2cl_msg_id);

   }//end switch(uch_sc2cl_msg_id)

//   __                    _          __  __                         _      _       
//  / _|_ _ __ _ _ __  ___| |__ _  _ / _|/ _|___ _ _   _  _ _ __  __| |__ _| |_ ___ 
// |  _| '_/ _` | '  \/ -_) '_ \ || |  _|  _/ -_) '_| | || | '_ \/ _` / _` |  _/ -_)
// |_| |_| \__,_|_|_|_\___|_.__/\_,_|_| |_| \___|_|    \_,_| .__/\__,_\__,_|\__\___|
//                                                         |_|                      
// 6.5.1 FramebufferUpdate
p_cl_framebuffer_update: //Start Reading & Processing of a Framebuffer Update Message from the VNC Server
   if(dsl_input_dec.get_bytes_left() < 0x4) // wait until all bytes are there
      goto p_proc_inp_70;
   CHECK_RETURN(dsl_input_dec.skip(2)); // skip message-type and padding
   CHECK_RETURN(dsl_input_dec.read_16_be(&adsl_session->dsc_fbu.usc_no_rect));
   adsl_session->iec_srfbc = ied_srfbc_fu_rect;  /* framebuffer update get rectangle */

p_cl_fuh_20:                             /* decode rectangle        */
   if(dsl_input_dec.get_bytes_left() < 0xc) // wait until all bytes for rectangle are there
      goto p_proc_inp_70;
   CHECK_RETURN(dsl_input_dec.read_16_be(&adsl_session->dsc_fbu.usc_x));
   CHECK_RETURN(dsl_input_dec.read_16_be(&adsl_session->dsc_fbu.usc_y));
   CHECK_RETURN(dsl_input_dec.read_16_be(&adsl_session->dsc_fbu.usc_width));
   CHECK_RETURN(dsl_input_dec.read_16_be(&adsl_session->dsc_fbu.usc_height));
   int in_fbu_encoding; 
   CHECK_RETURN(dsl_input_dec.read_32_be(&in_fbu_encoding));

   // check, if rectangle is in screen
   if((adsl_session->dsc_fbu.usc_x + adsl_session->dsc_fbu.usc_width > adsl_session->usc_fb_width) ||
      (adsl_session->dsc_fbu.usc_y + adsl_session->dsc_fbu.usc_height > adsl_session->usc_fb_height)){

      //if encoding is rfbPseudoEncodingDesktopSize
      //    allow Update outside of screen - new desktop size will be specified 
      //         in dsc_fbu.usc_width and usc_height
      // else 
      //    return with error
  
      if(in_fbu_encoding != rfbPseudoEncodingDesktopSize){
         ERROR_MACRO_RDP(true, "Update outside of screen. screen: %ix%i, update: left=%i top=%i right=%i bottom=%i",
            adsl_session->usc_fb_width, adsl_session->usc_fb_height, 
            adsl_session->dsc_fbu.usc_x, adsl_session->dsc_fbu.usc_y,
            adsl_session->dsc_fbu.usc_x + adsl_session->dsc_fbu.usc_width - 1, 
            adsl_session->dsc_fbu.usc_y + adsl_session->dsc_fbu.usc_height - 1);
      }
   }

   M_SDH_PRINTF_T( "received draw x=%d y=%d width=%d height=%d encoding 0X%08X.",
      adsl_session->dsc_fbu.usc_x, adsl_session->dsc_fbu.usc_y,
      adsl_session->dsc_fbu.usc_width, adsl_session->dsc_fbu.usc_height,
      in_fbu_encoding );

   if((adsl_session->dsc_fbu.usc_width == 0) ||
      (adsl_session->dsc_fbu.usc_height == 0)){
         // Happens with multimonitor and zrle
         goto p_cl_fu_end_20;
   }

#ifdef DEBUG_BRAKING_DOWN_UPDATE_IN_SMALL_RECTS
   // DEBUG

   dsd_sc_order_opaquerect* ds_opaquerect =  dsl_orderqueue.new_command<dsd_sc_order_opaquerect>();
   ds_opaquerect->dsc_rectangle.isc_left   = adsl_session->dsc_fbu.usc_x;
   ds_opaquerect->dsc_rectangle.isc_top    = adsl_session->dsc_fbu.usc_y;
   ds_opaquerect->dsc_rectangle.isc_width  = adsl_session->dsc_fbu.usc_width;
   ds_opaquerect->dsc_rectangle.isc_height = adsl_session->dsc_fbu.usc_height;
   ds_opaquerect->boc_has_bounds           = FALSE;
   ds_opaquerect->boc_update_scrbuf        = FALSE;
   ds_opaquerect->umc_color                = get_rdpcolor(adsl_session->inc_coldep_rdp, 0x00, 0x00, 0xff);
   ds_opaquerect->imc_no_color_bytes       = 3;

#define DRAW_LINE(INL_X, INL_Y, INL_XE, INL_YE) {                                            \
   dsd_sc_order_lineto* adsl_lineto = dsl_orderqueue.new_command<dsd_sc_order_lineto>();     \
   adsl_lineto->isc_nxstart       = INL_X;                                                   \
   adsl_lineto->isc_nystart       = INL_Y;                                                   \
   adsl_lineto->isc_nxend         = INL_XE;                                                  \
   adsl_lineto->isc_nyend         = INL_YE;                                                  \
   adsl_lineto->imc_pencolor      = get_rdpcolor(adsl_session->inc_coldep_rdp, 0xff, 0, 0);  \
   adsl_lineto->iec_brop2         = ied_scc_r2_copypen;                                      \
   adsl_lineto->iec_backmode      = ied_scc_transparent;                                     \
   adsl_lineto->boc_has_bounds    = FALSE;                                                   \
   adsl_lineto->boc_update_scrbuf = FALSE;                                                   \
   }
   DRAW_LINE(adsl_session->dsc_fbu.usc_x, adsl_session->dsc_fbu.usc_y, adsl_session->dsc_fbu.usc_x + adsl_session->dsc_fbu.usc_width, adsl_session->dsc_fbu.usc_y);
   DRAW_LINE(adsl_session->dsc_fbu.usc_x + adsl_session->dsc_fbu.usc_width, adsl_session->dsc_fbu.usc_y, adsl_session->dsc_fbu.usc_x + adsl_session->dsc_fbu.usc_width, adsl_session->dsc_fbu.usc_y + adsl_session->dsc_fbu.usc_height);
   DRAW_LINE(adsl_session->dsc_fbu.usc_x + adsl_session->dsc_fbu.usc_width, adsl_session->dsc_fbu.usc_y + adsl_session->dsc_fbu.usc_height, adsl_session->dsc_fbu.usc_x, adsl_session->dsc_fbu.usc_y + adsl_session->dsc_fbu.usc_height);
   DRAW_LINE(adsl_session->dsc_fbu.usc_x, adsl_session->dsc_fbu.usc_y + adsl_session->dsc_fbu.usc_height, adsl_session->dsc_fbu.usc_x, adsl_session->dsc_fbu.usc_y);

#undef DRAW_LINE
#endif


   switch (in_fbu_encoding) {    // check encoding  
    
   case rfbEncodingRaw:          // 6.6.1 Raw encoding
      goto p_cl_fu_raw_00;                   

   case rfbEncodingZlib:         // Encoding zLib
      goto p_cl_fu_zlib_init;

   case rfbEncodingCopyRect:     // 6.6.2 CopyRect encoding
      goto p_cl_fu_copyrect;                

   case rfbEncodingRRE:          // 6.6.3 RRE encoding (Rise and Run Length Encoding)*/
        goto p_cl_fu_rre_00 ;           

   case rfbEncodingZRLE:         // 6.6.5 ZRLE encoding
      goto p_cl_fu_zrle_init;

   case rfbPseudoEncodingCursor: // 6.7.1 Cursor pseudo-encoding
      goto p_cl_fu_cursor;

   case rfbPseudoEncodingDesktopSize: //6.7.2 DesktopSize pseudo-encoding
      goto p_cl_fu_dektopsize;

   default:

      ERROR_MACRO_RDP(true, "Encoding not recognized: received draw x=%d y=%d width=%d height=%d encoding 0X%08X.",
        adsl_session->dsc_fbu.usc_x, adsl_session->dsc_fbu.usc_y,
        adsl_session->dsc_fbu.usc_width, adsl_session->dsc_fbu.usc_height,
        in_fbu_encoding);
        break;
    
    }//end switch (in_fbu_encoding) 

//  ___        _                  _        __ _      _    _           _ 
// | _ \___ __| |_ __ _ _ _  __ _| |___   / _(_)_ _ (_)__| |_  ___ __| |
// |   / -_) _|  _/ _` | ' \/ _` | / -_) |  _| | ' \| (_-< ' \/ -_) _` |
// |_|_\___\__|\__\__,_|_||_\__, |_\___| |_| |_|_||_|_/__/_||_\___\__,_|
//                          |___/                                       

p_cl_fu_end_20:                          /* this rectangle has been drawn */

   adsl_session->dsc_fbu.usc_no_rect--;           /* number-of-rectangles    */
   adsl_session->iec_srfbc = ied_srfbc_fu_rect;  /* framebuffer update get rectangle */
   //DEF_DEBUG_PRINTF("\nNo of remaining rectangle: %d",adsl_session->dsc_fbu.usc_no_rect );
   if (adsl_session->dsc_fbu.usc_no_rect == 0) {  /* number-of-rectangles    */
      adsl_session->boc_send_update_request = true;
      adsl_session->iec_srfbc = ied_srfbc_conn;   /* session is connected    */
   }

   goto p_ifunc_from_server_20;                    /* process the input       */

//                      _ _                             
//  ___ _ _  __ ___  __| (_)_ _  __ _   _ _ __ ___ __ __
// / -_) ' \/ _/ _ \/ _` | | ' \/ _` | | '_/ _` \ V  V /
// \___|_||_\__\___/\__,_|_|_||_\__, | |_| \__,_|\_/\_/ 
//                              |___/                   
// 6.6.1 Raw encoding

p_cl_fu_raw_00:                          /* framebuffer update raw  */
   adsl_session->iec_srfbc = ied_srfbc_fu_raw;   /* framebuffer update raw  */
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_draw_remaing                /* remaining bytes pixel to draw */
      = adsl_session->imc_bpp_rfb * adsl_session->dsc_fbu.usc_width * adsl_session->dsc_fbu.usc_height;
   // included by JB
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x = 0;
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_y = 0;
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act_line = (char*) adsl_session->dsc_crdps_1.ac_screen_buffer +
      adsl_session->dsc_fbu.usc_y *  adsl_session->inc_scanline_rdp_screen + adsl_session->dsc_fbu.usc_x * adsl_session->imc_bpp_rdp;
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act_line; 
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_next_line_update = IMS_SCREEN_UPDATE_HEIGHT;
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_num_rects = (adsl_session->dsc_fbu.usc_width + IMS_SCREEN_UPDATE_WIDTH - 1) / IMS_SCREEN_UPDATE_WIDTH;

   CLEAR_FBU_RECTS;
 
p_cl_fu_raw_20:                          /* framebuffer update raw  */
#ifdef TRACEHL1
    M_SDH_PRINTF_T( "p_cl_fu_raw_20 adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_draw_remaing=%d/0X%X.",
        adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_draw_remaing, adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_draw_remaing );
#endif
   if(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_draw_remaing == 0)
      goto p_cl_fu_end_20;       // Whole rect processed

   inl_bpp_rfb = adsl_session->imc_bpp_rfb;
   if(dsl_input_dec.get_bytes_left() < inl_bpp_rfb) // we need minimum one pixel to convert
      goto p_proc_inp_70;
   inl_bpp_rdp = adsl_session->imc_bpp_rdp;

   // Get contiguous memory out of reader
   dsl_input_dec.get_max_contiguous_bytes(&iml_pixel_input, &achl_pixel_input);
   if (iml_pixel_input > adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_draw_remaing) {  /* compare remaining bytes pixel to draw */
      iml_pixel_input = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_draw_remaing;  /* only remaining bytes pixel to draw */
   }
   
   // less contiguous bytes than one pixel -> copy one pixel and process it
   if(iml_pixel_input < inl_bpp_rfb){
      dsl_input_dec.copy_to(chrl_work2, inl_bpp_rfb);
      achl_pixel_input = chrl_work2;  /* process one pixel at boundary */
      iml_pixel_input  = inl_bpp_rfb;               /* length pixel input, one pixel */
      goto p_pixel_00;                              /* process sequence of pixels */
   }

   iml_pixel_input = ((int) (iml_pixel_input / inl_bpp_rfb)) * inl_bpp_rfb;
   dsl_input_dec.skip(iml_pixel_input);   
   goto p_pixel_00;

//                      _ _                _    _ _    
//  ___ _ _  __ ___  __| (_)_ _  __ _   __| |  (_) |__ 
// / -_) ' \/ _/ _ \/ _` | | ' \/ _` | |_ / |__| | '_ \
// \___|_||_\__\___/\__,_|_|_||_\__, | /__|____|_|_.__/
//                              |___/                  

// Init this zLib frame
p_cl_fu_zlib_init:                           /* framebuffer update zLib normal */
   if(dsl_input_dec.get_bytes_left() < 4){   // we need minimum four bytes of length
      adsl_session->iec_srfbc = ied_srfbc_fu_zlib_init; // come back here, after data is available
      goto p_proc_inp_70;
   }

   CHECK_RETURN(dsl_input_dec.read_32_be(&adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_length));

   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_draw_remaing                /* remaining bytes pixel to draw */
      = adsl_session->imc_bpp_rfb * adsl_session->dsc_fbu.usc_width * adsl_session->dsc_fbu.usc_height;
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_buffer_copied = 0;            /* temporary bytes needed  */
   // included by JB
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x = 0;
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_y = 0;
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act_line = (char*) adsl_session->dsc_crdps_1.ac_screen_buffer +
      adsl_session->dsc_fbu.usc_y *  adsl_session->inc_scanline_rdp_screen + adsl_session->dsc_fbu.usc_x * adsl_session->imc_bpp_rdp;
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act_line; 
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_next_line_update = IMS_SCREEN_UPDATE_HEIGHT;
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_num_rects = (adsl_session->dsc_fbu.usc_width + IMS_SCREEN_UPDATE_WIDTH - 1) / IMS_SCREEN_UPDATE_HEIGHT;

   // Start zLib if necessary
   if (adsl_session->dsc_cdr_ctrl.imc_func == DEF_IFUNC_START) {  /* start of processing, initialize */
      adsl_session->dsc_cdr_ctrl.imc_param_1 = 1;  /* parameter value 1, SYNC-FLUSH */
      adsl_session->dsc_cdr_ctrl.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary helper routine pointer */
      adsl_session->dsc_cdr_ctrl.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
      m_cdr_zlib_1_dec( &adsl_session->dsc_cdr_ctrl );
      if (adsl_session->dsc_cdr_ctrl.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
         ERROR_MACRO_RDP(true, "zLib init returned 0x%x", adsl_session->dsc_cdr_ctrl.imc_return);
      }
   }
   CLEAR_FBU_RECTS;

// New Data for zLib
p_cl_fu_zlib_new_data: {                         /* framebuffer update zLib normal */
   if(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_draw_remaing == 0){
      // JB: We used to have a zLib-error, as we were ending zLib, when adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_draw_remaing == 0.
      // But it's possible, that there is still data for zLib, even if all of the output is already there. 
      if(adsl_session->dsc_cdr_ctrl.boc_sr_flush == TRUE){
         if(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_length != 0)
            ERROR_MACRO_RDP(true, "zLib: adsl_session->dsc_cdr_ctrl.boc_sr_flush == TRUE, but adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_length=%i",
               adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_length);
         goto p_cl_fu_end_20;
      }
   }

   if (dsl_input_dec.get_bytes_left() <= 0) {                         /* no input data           */
      adsl_session->iec_srfbc = ied_srfbc_fu_zlib_new_data;     // come back here, after data is available
      goto p_proc_inp_70;                    /* the input has been processed */
   }
   
   // JB: copy dsd_gathers
   dsd_gather_i_1* ads_gather_first = NULL;
   dsd_gather_i_1* ads_gather_act = NULL;
   while((dsl_input_dec.get_bytes_left() > 0) && 
         (adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_length > 0)){
      ENSURE_SPACE_ON_WORKAREA(sizeof(dsd_gather_i_1));      
      achl_work_2 -= sizeof(dsd_gather_i_1);
	  dsd_gather_i_1* ads_gather = (dsd_gather_i_1*) achl_work_2;
      CHECK_RETURN(dsl_input_dec.other_gather_takes_data(ads_gather, adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_length, &iml1));
      if(ads_gather_first == NULL){
         // first gather
         ads_gather_first = ads_gather;
      } else {
         ads_gather_act->adsc_next = ads_gather;
      }
      ads_gather_act = ads_gather;
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_length -= iml1;
   }

   adsl_session->dsc_cdr_ctrl.amc_aux      = adsp_hl_clib_1->amc_aux;  /* auxiliary helper routine pointer */
   adsl_session->dsc_cdr_ctrl.vpc_userfld  = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
   adsl_session->dsc_cdr_ctrl.adsc_gai1_in = ads_gather_first;
}

// Call zLib decompression
p_cl_fu_zn_zlib_call_zlib: {                          /* call zLib decompression */

   adsl_session->dsc_cdr_ctrl.achc_out_cur = chrl_work2 + adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_buffer_copied;  // leave space for bytes from last time
   adsl_session->dsc_cdr_ctrl.achc_out_end = chrl_work2 + sizeof(chrl_work2);  /* end of buffer for output data */

   adsl_session->dsc_cdr_ctrl.boc_mp_flush = FALSE;  /* end-of-record input */
   if (adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_length == 0) {     /* no more remaining data  */
      adsl_session->dsc_cdr_ctrl.boc_mp_flush = TRUE;  /* end-of-record input */
   }
   char* achl_out_before = adsl_session->dsc_cdr_ctrl.achc_out_cur;
   m_cdr_zlib_1_dec( &adsl_session->dsc_cdr_ctrl );
   if (adsl_session->dsc_cdr_ctrl.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
      ERROR_MACRO_RDP(true, "zLib decompression returned %i", adsl_session->dsc_cdr_ctrl.imc_return);
   }
   iml_pixel_input = CONVERT_W64_TO_INT(adsl_session->dsc_cdr_ctrl.achc_out_cur - achl_out_before);  /* length of output */
#ifdef TRACEHL1
    M_SDH_PRINTF_T( "m_cdr_zlib_1_dec() returned %d len-output=%d/0X%X remaining-input=%d/0X%X boc_sr_flush=%d.",
        adsl_session->dsc_cdr_ctrl.imc_return, iml_pixel_input, iml_pixel_input, 
        m_gather_count(adsl_session->dsc_cdr_ctrl.adsc_gai1_in), m_gather_count(adsl_session->dsc_cdr_ctrl.adsc_gai1_in), adsl_session->dsc_cdr_ctrl.boc_sr_flush );
#endif
   if(iml_pixel_input <= 0) {              /* nothing decompressed    */
      goto p_cl_fu_zlib_new_data;          // Need new data for decompression
   }

   // Where there bytes left from last time?
   if(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_buffer_copied > 0){
      memcpy(chrl_work2, adsl_session->dsc_fbu.dsc_raw_zlib_zrle.chrc_zlib_buffer, adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_buffer_copied);
      iml_pixel_input += adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_buffer_copied;
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_buffer_copied = 0;
   }

   // Too much data output from zLib?
   if(iml_pixel_input > adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_draw_remaing) {  /* remaining bytes pixel to draw */
      ERROR_MACRO_RDP(true, "zLib decompression output too long iml_pixel_input=%d adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_draw_remaing=%d.", 
         iml_pixel_input, adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_draw_remaing );
   }

   // Calculate complete pixels and copy rest
   inl_bpp_rfb = adsl_session->imc_bpp_rfb;
   inl_bpp_rdp = adsl_session->imc_bpp_rdp;

   iml1 = iml_pixel_input;
   iml_pixel_input = ((int) (iml_pixel_input / inl_bpp_rfb)) * inl_bpp_rfb;
   iml1 -= iml_pixel_input;

   // Bytes left at the end
   if(iml1 > 0){
      memcpy(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.chrc_zlib_buffer, chrl_work2 + iml_pixel_input, iml1);
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_buffer_copied = iml1; 
   }

   // Get more data, if there wasn't a whole pixel. 

   // Call the converter
   achl_pixel_input = chrl_work2;   /* byte pixel input        */
   adsl_session->iec_srfbc = ied_srfbc_fu_zlib_call_zlib; /* state of this RFC client: continue to call cLib */
   goto p_pixel_00;
}

//                      _    _ _      ___                                                                  __        _         _    
//  _ _ __ ___ __ __ __| |  (_) |__  | _ \_ _ ___  __ ___ ______  ___ ___ __ _ _  _ ___ _ _  __ ___   ___ / _|  _ __(_)_ _____| |___
// | '_/ _` \ V  V /|_ / |__| | '_ \ |  _/ '_/ _ \/ _/ -_|_-<_-< (_-</ -_) _` | || / -_) ' \/ _/ -_) / _ \  _| | '_ \ \ \ / -_) (_-<
// |_| \__,_|\_/\_/_/__|____|_|_.__/ |_| |_| \___/\__\___/__/__/ /__/\___\__, |\_,_\___|_||_\__\___| \___/_|   | .__/_/_\_\___|_/__/
//               |___|                                                      |_|                                |_|                  

p_pixel_00:                              /* process sequence of pixels */
    // Calculate number of pixels to convert
   
/*#if !(defined HL_LINUX)
   int inl_num_pixels = iml_pixel_input / inl_bpp_rfb;
   int inl_num_tile = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x / IMS_SCREEN_UPDATE_WIDTH;
   int inl_rest_pixels_tile = ((inl_num_tile + 1) * IMS_SCREEN_UPDATE_WIDTH) - adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x;
#else */
   inl_num_pixels = iml_pixel_input / inl_bpp_rfb;
   inl_num_tile = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x / IMS_SCREEN_UPDATE_WIDTH;
   inl_rest_pixels_tile = ((inl_num_tile + 1) * IMS_SCREEN_UPDATE_WIDTH) - adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x;
//#endif
   if(inl_num_pixels > inl_rest_pixels_tile)
      inl_num_pixels = inl_rest_pixels_tile;

/*#if !(defined HL_LINUX)
   int inl_rest_pixels_line = adsl_session->dsc_fbu.usc_width - adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x;
#else */
   inl_rest_pixels_line = adsl_session->dsc_fbu.usc_width - adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x;
//#endif

   if(inl_num_pixels > inl_rest_pixels_line){
      inl_num_pixels = inl_rest_pixels_line;
   }

   // Do output-bytes fit in workarea
/*#if !(defined HL_LINUX)
   int inl_num_bytes_out = inl_num_pixels * inl_bpp_rdp;
#else */
   inl_num_bytes_out = inl_num_pixels * inl_bpp_rdp;
//#endif
   if(inl_num_bytes_out > (sizeof(chrl_work1))){ // Calculate with maximal bpp
      inl_num_pixels = sizeof(chrl_work1) / inl_bpp_rdp;
      inl_num_bytes_out = inl_num_pixels * inl_bpp_rdp;
   }

   // Convert pixels now
   adsl_session->adsc_pixel_converter->convert(achl_pixel_input, chrl_work1, inl_num_pixels);

   // bytes, consumed from input
/*#if !(defined HL_LINUX)
   int inl_consumed = inl_num_pixels * inl_bpp_rfb;
#else*/
   inl_consumed = inl_num_pixels * inl_bpp_rfb;
//#endif
   achl_pixel_input += inl_consumed;
   iml_pixel_input -= inl_consumed;
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_draw_remaing -= inl_consumed;  /* remaining bytes pixel to draw */
   
   // compare and comp pixels
//#if !(defined HL_LINUX)
//   char* ach_first_diff = NULL;                 /* framebuffer update changes start */
//#else
   ach_first_diff = NULL;                 /* framebuffer update changes start */
//#endif
   char* ach_last_diff;
   switch (adsl_session->imc_bpp_rdp) {      /* bytes per pixel RDP     */
      case 2:                            /* 15 or 16 bits           */
         m_compare_and_copy((uint16_t*) adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act, (uint16_t*) chrl_work1, inl_num_pixels,
            (uint16_t**) (&ach_first_diff), (uint16_t**) (&ach_last_diff));
            break;
      case 3:       
         m_compare_and_copy((dsd_pixel_24*) adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act, (dsd_pixel_24*) chrl_work1, inl_num_pixels,
            (dsd_pixel_24**) (&ach_first_diff), (dsd_pixel_24**) (&ach_last_diff));
         break;
      case 4:                            /* 32 bits                 */
         m_compare_and_copy((uint32_t*) adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act, (uint32_t*) chrl_work1, inl_num_pixels,
            (uint32_t**) (&ach_first_diff), (uint32_t**) (&ach_last_diff));
         break;
      default:
         ERROR_MACRO_RDP(true, "Invalid RDP bytes-per-pixel value: adsl_session->imc_bpp_rdp=0%x", adsl_session->imc_bpp_rdp);
   }// end switch (adsl_session->imc_bpp_rdp)
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act += inl_num_bytes_out;

   // New min/max x/y
   if (ach_first_diff) {                  /* framebuffer update changed */
      dsd_rectrb* adsl_rect = &adsl_session->adsc_fbu_changes[inl_num_tile];
      iml1 = CONVERT_W64_TO_INT(ach_first_diff - adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act_line) / inl_bpp_rdp + adsl_session->dsc_fbu.usc_x;
      if (adsl_rect->isc_left > iml1) 
         adsl_rect->isc_left = iml1;

      iml1 = (CONVERT_W64_TO_INT(ach_last_diff - adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act_line) / inl_bpp_rdp) + 1 + adsl_session->dsc_fbu.usc_x;
      if (adsl_rect->isc_right < iml1) 
         adsl_rect->isc_right = iml1;

      iml1 = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_y + adsl_session->dsc_fbu.usc_y;
      if (adsl_rect->isc_top > iml1) 
         adsl_rect->isc_top = iml1;

      if(adsl_rect->isc_bottom < iml1)
         adsl_rect->isc_bottom = iml1;
   }

   // Increase act x and check for new line
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x += inl_num_pixels;
   if(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x >= adsl_session->dsc_fbu.usc_width){
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x = 0;
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act_line += adsl_session->inc_scanline_rdp_screen;
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act_line;
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_y++;

      // update, if IMS_SCREEN_UPDATE_HEIGHT lines updated. 
      if((adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_next_line_update <= adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_y) ||
         (adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_y == adsl_session->dsc_fbu.usc_height)){

         for(int inl_num = 0; inl_num < adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_num_rects; inl_num++){
            dsd_rectrb* adsl_rect = &adsl_session->adsc_fbu_changes[inl_num];

            if(adsl_rect->isc_left < adsl_rect->isc_right){
               dsd_sc_draw_sc* ads_draw_sc = dsl_orderqueue.new_command<dsd_sc_draw_sc>();
               ads_draw_sc->imc_left   = adsl_rect->isc_left;
               ads_draw_sc->imc_top    = adsl_rect->isc_top;
               ads_draw_sc->imc_right  = adsl_rect->isc_right; 
               ads_draw_sc->imc_bottom = adsl_rect->isc_bottom + 1;
            } 
         }
         adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_next_line_update += IMS_SCREEN_UPDATE_HEIGHT;

         // Clear bounds again
         CLEAR_FBU_RECTS;
      }
   }

   // Check, how to go on 
   if(iml_pixel_input > 0)
      goto p_pixel_00;           // Still input
   goto p_ifunc_from_server_20;  // Get more input

//                      _ _              ___               ___        _   
//  ___ _ _  __ ___  __| (_)_ _  __ _   / __|___ _ __ _  _| _ \___ __| |_ 
// / -_) ' \/ _/ _ \/ _` | | ' \/ _` | | (__/ _ \ '_ \ || |   / -_) _|  _|
// \___|_||_\__\___/\__,_|_|_||_\__, |  \___\___/ .__/\_, |_|_\___\__|\__|
//                              |___/           |_|   |__/                
//
// 6.6.2 CopyRect encoding
//
// No. of bytes  Type [Value]  Description
// ------------  ------------  --------------
//  2             U16           src-x-position
//  2             U16           src-y-position

p_cl_fu_copyrect:                                  /* copy rect initialisation */
   if(dsl_input_dec.get_bytes_left() < 4){         // The CopyRect-command is four bytes long
      adsl_session->iec_srfbc = ied_srfbc_fu_copyrect;  // come back here, after data is available
      goto p_proc_inp_70;
   }
   if(!dsl_orderqueue.is_empty()){                      // JB 19.03.12: Painting errors otherwise, as
      bol_return_to_copyrect = true;                    // there still could be dsd_sc_draw_sc-commands in the
      adsl_session->iec_srfbc = ied_srfbc_fu_copyrect;  // queue, using the area of the copyrect, and they have
      goto p_rdpserv_40;                                // to process the old data, not the copied one. 
   }                                                    // Error occured with insure, which slows down the process. 
   unsigned short int usc_src_x, usc_src_y;
   CHECK_RETURN(dsl_input_dec.read_16_be(&usc_src_x));
   CHECK_RETURN(dsl_input_dec.read_16_be(&usc_src_y));

   // building up of data structure to be passed to the rdp accelarator 
   // [MS-RDPEGDI] 2.2.2.2.1.1.2.7 ScrBlt (SCRBLT_ORDER)
/*#if !(defined HL_LINUX)
   dsd_sc_order_scrblt* ads_scrblt = dsl_orderqueue.new_command<dsd_sc_order_scrblt>();
#else */
   ads_scrblt = dsl_orderqueue.new_command<dsd_sc_order_scrblt>();
//#endif
   ads_scrblt->dsc_rectangle.isc_left   = adsl_session->dsc_fbu.usc_x;
   ads_scrblt->dsc_rectangle.isc_top    = adsl_session->dsc_fbu.usc_y;
   ads_scrblt->dsc_rectangle.isc_width  = adsl_session->dsc_fbu.usc_width;
   ads_scrblt->dsc_rectangle.isc_height = adsl_session->dsc_fbu.usc_height;
   ads_scrblt->isc_x_src                = usc_src_x;
   ads_scrblt->isc_y_src                = usc_src_y;
   ads_scrblt->ucc_brop3                = 0xCC;
   ads_scrblt->boc_has_bounds           = FALSE;
   ads_scrblt->boc_update_scrbuf        = FALSE;

   //screen buffer update:
   //coding idea obtained from the implementation of the screen-buffer update in xsrdpse1.cpp:m_send_order_scrblt()   
   
   char       *achl_s1;                     /* address source          */
   char       *achl_t1;                     /* address target          */
//#if !(defined HL_LINUX)
//   int iml_bpp = adsl_session->imc_bpp_rdp; /* number of bytes per pixel */
//#else
   iml_bpp = adsl_session->imc_bpp_rdp;
//#endif
   //iml1: pixel height of area to be updated
   iml1 = adsl_session->dsc_fbu.usc_height;
   if (iml1 <= 0)  /* nothing to copy */
      goto p_cl_fu_end_20;

   //iml2: bytes to be copied in one line
   iml2 = adsl_session->dsc_fbu.usc_width * iml_bpp;
   if (iml2 <= 0) /* nothing to copy */
      goto p_cl_fu_end_20;

   //iml3: byte width of whole screen 
   iml3 = adsl_session->usc_fb_width * iml_bpp;

   if(usc_src_y < adsl_session->dsc_fbu.usc_y) {
    
       /* copy from bottom to top */
       achl_s1 = (char *) adsl_session->dsc_crdps_1.ac_screen_buffer
          + (  (usc_src_y + adsl_session->dsc_fbu.usc_height) *  adsl_session->usc_fb_width
               + usc_src_x)
            * iml_bpp;

       achl_t1 = (char *) adsl_session->dsc_crdps_1.ac_screen_buffer
         + (  (adsl_session->dsc_fbu.usc_y + adsl_session->dsc_fbu.usc_height) * adsl_session->usc_fb_width
               + adsl_session->dsc_fbu.usc_x )
            * iml_bpp;
      
      do {
         achl_t1 -= iml3;                     /* previous line target    */
         achl_s1 -= iml3;                     /* previous line source    */
         memcpy( achl_t1, achl_s1, iml2 );   /* copy in this line       */
         iml1--;                              /* decrement number of lines */
      } while (iml1 > 0);
   } else if (usc_src_y > adsl_session->dsc_fbu.usc_y){
      /* copy from top to bottom                                        */
      achl_s1 = (char *) adsl_session->dsc_crdps_1.ac_screen_buffer
         + ( usc_src_y * adsl_session->usc_fb_width
               + usc_src_x)
            * iml_bpp;

      achl_t1 = (char *) adsl_session->dsc_crdps_1.ac_screen_buffer
         + ( adsl_session->dsc_fbu.usc_y * adsl_session->usc_fb_width
               + adsl_session->dsc_fbu.usc_x)
            * iml_bpp;

      do{
        memcpy( achl_t1, achl_s1, iml2 );    /* copy in this line       */
        achl_t1 += iml3;                     /* next line target        */
        achl_s1 += iml3;                     /* next line source        */
        iml1--;                              /* decrement number of lines */
      } while (iml1 > 0);  
   
   } else {
      // JB 19.03.12: Use memmove only, if copying in the same line. 
      achl_s1 = (char *) adsl_session->dsc_crdps_1.ac_screen_buffer
         + ( usc_src_y * adsl_session->usc_fb_width
               + usc_src_x)
            * iml_bpp;

      achl_t1 = (char *) adsl_session->dsc_crdps_1.ac_screen_buffer
         + ( adsl_session->dsc_fbu.usc_y * adsl_session->usc_fb_width
               + adsl_session->dsc_fbu.usc_x)
            * iml_bpp;

      do{
        memmove( achl_t1, achl_s1, iml2 );    /* copy in this line       */
        achl_t1 += iml3;                     /* next line target        */
        achl_s1 += iml3;                     /* next line source        */
        iml1--;                              /* decrement number of lines */
      } while (iml1 > 0);  
   }
   
   goto p_cl_fu_end_20;

//                      _ _             ___ ___ ___ 
//  ___ _ _  __ ___  __| (_)_ _  __ _  | _ \ _ \ __|
// / -_) ' \/ _/ _ \/ _` | | ' \/ _` | |   /   / _| 
// \___|_||_\__\___/\__,_|_|_||_\__, | |_|_\_|_\___|
//                              |___/            
// 6.6.3 RRE encoding
//
//  On the wire, the data begins with the header:
//
//  ---------------+---------------+-------------------------   
//   No. of bytes  | Type  [Value] | Description              
//  ---------------+---------------+-------------------------
//   4             | U32           | number-of-subrectangles  
//   bytesPerPixel | PIXEL         | background-pixel-value   
//  ---------------+---------------+-------------------------
//  
//  This is followed by "number-of-subrectangles" instances of the following structure:
//
// ----------------+---------------+---------------------
//   No. of bytes  | Type  [Value] | Description
// ----------------+---------------+---------------------  
//   bytesPerPixel | PIXEL         | subrect-pixel-value
//   2             | U16           | x-position
//   2             | U16           | y-position
//   2             | U16           | width
//   2             | U16           | height
// ----------------+---------------+---------------------

p_cl_fu_rre_00: 
{
   DEF_DEBUG_PRINTF("RRE_Encoding");
  
   if(dsl_input_dec.get_bytes_left() < (4 + adsl_session->imc_bpp_rfb) ){       
      adsl_session->iec_srfbc = ied_srfbc_fu_rre;    // come back here, after data is available
      goto p_proc_inp_70;
   }

   inl_bpp_rfb = adsl_session->imc_bpp_rfb;
   inl_bpp_rdp = adsl_session->imc_bpp_rdp;

   
   //Read number of subrectangles
   CHECK_RETURN(dsl_input_dec.read_32_be(&adsl_session->dsc_fbu.dsc_rre.umc_no_rre_sub_rect));
   
   //colour reading and convertion
   uml_color_rfb = 0;
   CHECK_RETURN(dsl_input_dec.copy_to((char*) (&uml_color_rfb), inl_bpp_rfb));
//#if !(defined HL_LINUX)
//   uint32_t uml_color = adsl_session->adsc_pixel_converter->convert(uml_color_rfb);
//#else
   uml_color = adsl_session->adsc_pixel_converter->convert(uml_color_rfb);
//#endif
   
   
   //Check wheter to use offscrren buffering
   //if RRE consists of just one backgroung rectangle without any subrectangles
   //do not use offscreen caching
   
   adsl_session->dsc_fbu.dsc_rre.boc_use_offscreencache = false;

   if (adsl_session->dsc_fbu.dsc_rre.umc_no_rre_sub_rect > 0){
      int iml_bytes_needed_for_rre_update = adsl_session->dsc_fbu.usc_width * adsl_session->dsc_fbu.usc_height * inl_bpp_rdp;
      int iml_bytes_in_offscreen_cache = adsl_session->dsc_crdps_1.adsc_rdp_co->dsc_caps.dsc_offscreen_cache.imc_size * 1000;

      //DEF_DEBUG_PRINTF("Offscreen buff size: " << iml_bytes_in_offscreen_cache << "; RRE Buff Needed: " << iml_bytes_needed_for_rre_update);
      if(iml_bytes_in_offscreen_cache >= iml_bytes_needed_for_rre_update){
      
         adsl_session->dsc_fbu.dsc_rre.boc_use_offscreencache = true;

         //createoffbitmap (RRE_OFFSCREEN_ID)
         dsd_sc_order_createoffbitmap* ads_createoffbitmap = dsl_orderqueue.new_command<dsd_sc_order_createoffbitmap>();
         ads_createoffbitmap->usc_cx = adsl_session->dsc_fbu.usc_width;
         ads_createoffbitmap->usc_cy = adsl_session->dsc_fbu.usc_height;
         ads_createoffbitmap->usc_offscreenbitmapid = RRE_OFFSCREEN_ID;
         ads_createoffbitmap->usc_numdelindices = 0; // no offscreen caches to delete

         //switch surface to offbitmap (RRE_OFFSCREEN_ID)
         dsd_sc_order_switchsurface* ads_switchsurface = dsl_orderqueue.new_command<dsd_sc_order_switchsurface>();
         ads_switchsurface->usc_bitmapid = RRE_OFFSCREEN_ID;
         //DEF_DEBUG_PRINTF("switchsurface to rre_offscreen (ID: 0)");
     
      }else{ //area required to buffer rre update is bigger than available screen buffer
             //use frame marker order to avoid screen update flickering
         
         //Set start the frame marker to stop the rdp from drawing on the cliet screen
         if (adsl_session->dsc_crdps_1.adsc_rdp_co->dsc_caps.dsc_orders.boc_altsec_frame_marker_support){
            dsd_sc_order_framemarker* ads_framemarker = dsl_orderqueue.new_command<dsd_sc_order_framemarker>();
            ads_framemarker->iec_action = ied_scc_frame_start;
         }
      }  //end  if(iml_bytes_in_offscreen_cache >= iml_bytes_needed_for_rre_update)
   } // end if (adsl_session->dsc_fbu.dsc_rre.umc_no_rre_sub_rect > 0)
   
   
  

   
   //Add opaquerect command to orderqueue
   // [MS-RDPEGDI] 2.2.2.2.1.1.2.5 OpaqueRect (OPAQUERECT_ORDER)
//#if !(defined HL_LINUX)
//   dsd_sc_order_opaquerect* ads_opaquerect = dsl_orderqueue.new_command<dsd_sc_order_opaquerect>();
//#else
   ads_opaquerect = dsl_orderqueue.new_command<dsd_sc_order_opaquerect>();
//#endif
   
   if (adsl_session->dsc_fbu.dsc_rre.boc_use_offscreencache){
      ads_opaquerect->dsc_rectangle.isc_left = 0;
      ads_opaquerect->dsc_rectangle.isc_top = 0;
   }else{
      ads_opaquerect->dsc_rectangle.isc_left = adsl_session->dsc_fbu.usc_x;
      ads_opaquerect->dsc_rectangle.isc_top = adsl_session->dsc_fbu.usc_y;
   }

   ads_opaquerect->dsc_rectangle.isc_width = adsl_session->dsc_fbu.usc_width;
   ads_opaquerect->dsc_rectangle.isc_height = adsl_session->dsc_fbu.usc_height;
   ads_opaquerect->imc_no_color_bytes =  adsl_session->inc_coldep_rdp <= 16 ? 2 : 3;
   
   CHECK_RETURN_SUB(m_get_rdpcolour_int(uml_color, adsl_session->inc_coldep_rdp, &ads_opaquerect->umc_color));
   
   ads_opaquerect->boc_has_bounds = FALSE;
   ads_opaquerect->boc_update_scrbuf = FALSE;

   //Update screen buffer
  
   char* ach_dest_act;
   char* ach_src_act;
      
   ach_dest_act = (char*) adsl_session->dsc_crdps_1.ac_screen_buffer
      + ( adsl_session->dsc_fbu.usc_y * adsl_session->usc_fb_width
            + adsl_session->dsc_fbu.usc_x )
         * inl_bpp_rdp;

   //fill one row of the area to be updated, with same pixel value.

   switch (inl_bpp_rdp) {      /* bytes per pixel RDP     */
      case 2:                            /* 15 or 16 bits           */
         m_fill_row( (uint16_t*) ach_dest_act, (uint16_t) uml_color, adsl_session->dsc_fbu.usc_width );
         break;
       case 3:                           /* 24 bits                 */
         dsd_pixel_24 dsl_pix24_colour;
         dsl_pix24_colour.ucc_red = (uml_color >> 0) & 0xFF;
         dsl_pix24_colour.ucc_green = (uml_color >> 8) & 0xFF;
         dsl_pix24_colour.ucc_blue = (uml_color >> 16) & 0xFF;

         m_fill_row( (dsd_pixel_24*) ach_dest_act, dsl_pix24_colour, adsl_session->dsc_fbu.usc_width );
         break;
      case 4:                            /* 32 bits                 */
         m_fill_row( (uint32_t*) ach_dest_act, (uint32_t) uml_color, adsl_session->dsc_fbu.usc_width );
         break;
      default:
         ERROR_MACRO_RDP(true, "Invalid RDP bytes-per-pixel value: adsl_session->imc_bpp_rdp=0x%x", inl_bpp_rdp);
   }// end switch (inl_bpp_rdp)

   int in_no_of_write_reps = adsl_session->dsc_fbu.usc_height - 1;
   
   if(in_no_of_write_reps > 0){
      int in_screen_witdh_bytes = adsl_session->usc_fb_width * inl_bpp_rdp; 
      int in_line_bytes_to_copy = adsl_session->dsc_fbu.usc_width * inl_bpp_rdp;
      
      //copy line multiple times

      ach_src_act = (char*) adsl_session->dsc_crdps_1.ac_screen_buffer
         + ( adsl_session->dsc_fbu.usc_y * adsl_session->usc_fb_width
            + adsl_session->dsc_fbu.usc_x )
         * inl_bpp_rdp;
  
      
      // copy destination = src + length in bytes of screen width
      ach_dest_act = ach_src_act + in_screen_witdh_bytes;
      
      do { 
         memcpy( ach_dest_act, ach_src_act, in_line_bytes_to_copy);
         ach_dest_act += in_screen_witdh_bytes;
         in_no_of_write_reps--;
      }while ( in_no_of_write_reps > 0);
   }// end if(in_no_of_write_reps > 0){

   if(adsl_session->dsc_fbu.dsc_rre.umc_no_rre_sub_rect == 0){
      goto p_cl_fu_end_20;
   }

} //end of p_cl_fu_rre_00 scope

p_cl_fu_rre_20:
   //process RRE subrectangles 

   if(dsl_input_dec.get_bytes_left() < (8 + adsl_session->imc_bpp_rfb) ){       
      adsl_session->iec_srfbc = ied_srfbc_fu_rre_subrect;    // come back here, after data is available
      goto p_proc_inp_70;
   }

   inl_bpp_rfb = adsl_session->imc_bpp_rfb;
   inl_bpp_rdp = adsl_session->imc_bpp_rdp;

   
   //colour reading and convertion
   uml_color_rfb = 0;
   CHECK_RETURN(dsl_input_dec.copy_to((char*) (&uml_color_rfb), inl_bpp_rfb));
//#if !(defined HL_LINUX)
//   uint32_t uml_color = adsl_session->adsc_pixel_converter->convert(uml_color_rfb);
//#else
   uml_color = adsl_session->adsc_pixel_converter->convert(uml_color_rfb);
//#endif
   CHECK_RETURN(dsl_input_dec.read_16_be(&adsl_session->dsc_fbu.dsc_rre.usc_x));
   CHECK_RETURN(dsl_input_dec.read_16_be(&adsl_session->dsc_fbu.dsc_rre.usc_y));
   CHECK_RETURN(dsl_input_dec.read_16_be(&adsl_session->dsc_fbu.dsc_rre.usc_width));
   CHECK_RETURN(dsl_input_dec.read_16_be(&adsl_session->dsc_fbu.dsc_rre.usc_height));

   //build up opaquerect commad on orderqueue

   //Add opaquerect command to orderqueue
   // [MS-RDPEGDI] 2.2.2.2.1.1.2.5 OpaqueRect (OPAQUERECT_ORDER)
//#if !(defined HL_LINUX)
//   dsd_sc_order_opaquerect* ads_opaquerect = dsl_orderqueue.new_command<dsd_sc_order_opaquerect>();
//#else
   ads_opaquerect = dsl_orderqueue.new_command<dsd_sc_order_opaquerect>();
//#endif
   //RRE subrectangle coordinates are sent with reference to the background rectangle
   //if the opaqueue rects are being drawn in the offscreen cache, the subrectangle coordinates
   // must be set with reference to 0,0
   if(adsl_session->dsc_fbu.dsc_rre.boc_use_offscreencache){
      ads_opaquerect->dsc_rectangle.isc_left = adsl_session->dsc_fbu.dsc_rre.usc_x;
      ads_opaquerect->dsc_rectangle.isc_top = adsl_session->dsc_fbu.dsc_rre.usc_y ;
   }else{
      ads_opaquerect->dsc_rectangle.isc_left = adsl_session->dsc_fbu.usc_x + adsl_session->dsc_fbu.dsc_rre.usc_x;
      ads_opaquerect->dsc_rectangle.isc_top = adsl_session->dsc_fbu.usc_y + adsl_session->dsc_fbu.dsc_rre.usc_y ;
   }

   ads_opaquerect->dsc_rectangle.isc_width = adsl_session->dsc_fbu.dsc_rre.usc_width;
   ads_opaquerect->dsc_rectangle.isc_height = adsl_session->dsc_fbu.dsc_rre.usc_height;
   ads_opaquerect->imc_no_color_bytes = adsl_session->inc_coldep_rdp <= 16 ? 2 : 3;
   
   CHECK_RETURN_SUB(m_get_rdpcolour_int(uml_color, adsl_session->inc_coldep_rdp, &ads_opaquerect->umc_color));
   
   ads_opaquerect->boc_has_bounds = FALSE;
   ads_opaquerect->boc_update_scrbuf = FALSE;

   //update screen buffer

  switch (inl_bpp_rdp){
      case 2:{
         usl_framebuffer_update.ausl_fu_cur =  ((unsigned short int*) adsl_session->dsc_crdps_1.ac_screen_buffer)
            + (adsl_session->dsc_fbu.usc_y + adsl_session->dsc_fbu.dsc_rre.usc_y) * adsl_session->usc_fb_width
            + (adsl_session->dsc_fbu.usc_x + adsl_session->dsc_fbu.dsc_rre.usc_x);
         unsigned short int* ausl_end = usl_framebuffer_update.ausl_fu_cur + adsl_session->usc_fb_width * adsl_session->dsc_fbu.dsc_rre.usc_height; 
         while(usl_framebuffer_update.ausl_fu_cur < ausl_end){
            unsigned short int* ausl_fu_cur_x = usl_framebuffer_update.ausl_fu_cur;
            unsigned short int* ausl_fu_end_x = ausl_fu_cur_x + adsl_session->dsc_fbu.dsc_rre.usc_width;
            while(ausl_fu_cur_x < ausl_fu_end_x){
               *ausl_fu_cur_x++ = (unsigned short int) uml_color ;
            }
            usl_framebuffer_update.ausl_fu_cur += adsl_session->usc_fb_width;
         } // while(ausl_fu_cur_x < ausl_fu_end_x)
         break;
      }// end case 2
             
      case 3:{
          usl_framebuffer_update.aucl_fu_cur =  ((unsigned char *) adsl_session->dsc_crdps_1.ac_screen_buffer)
            + (adsl_session->dsc_fbu.usc_y + adsl_session->dsc_fbu.dsc_rre.usc_y) * adsl_session->usc_fb_width * 3
            + (adsl_session->dsc_fbu.usc_x + adsl_session->dsc_fbu.dsc_rre.usc_x) * 3;
         unsigned char* aucl_end = usl_framebuffer_update.aucl_fu_cur + adsl_session->usc_fb_width * adsl_session->dsc_fbu.dsc_rre.usc_height * 3; 
         while(usl_framebuffer_update.aucl_fu_cur < aucl_end){
            unsigned char* aucl_fu_cur_x = usl_framebuffer_update.aucl_fu_cur;
            unsigned char* aucl_fu_end_x = aucl_fu_cur_x + adsl_session->dsc_fbu.dsc_rre.usc_width * 3;
            while(aucl_fu_cur_x < aucl_fu_end_x){
               *aucl_fu_cur_x++ = (unsigned char) (uml_color >> 0);
               *aucl_fu_cur_x++ = (unsigned char) (uml_color >> 8);
               *aucl_fu_cur_x++ = (unsigned char) (uml_color >> 16);
            }
            usl_framebuffer_update.aucl_fu_cur += adsl_session->usc_fb_width * 3;
         } // while(aucl_fu_cur_x < aucl_fu_end_x)
         break;
      }// end case 3
        
      case 4:{
          usl_framebuffer_update.auml_fu_cur = ((unsigned int*) adsl_session->dsc_crdps_1.ac_screen_buffer)
            + (adsl_session->dsc_fbu.usc_y + adsl_session->dsc_fbu.dsc_rre.usc_y) * adsl_session->usc_fb_width
            + (adsl_session->dsc_fbu.usc_x + adsl_session->dsc_fbu.dsc_rre.usc_x);
         unsigned int* auml_end = usl_framebuffer_update.auml_fu_cur + adsl_session->usc_fb_width * adsl_session->dsc_fbu.dsc_rre.usc_height; 
         while(usl_framebuffer_update.auml_fu_cur < auml_end){
            unsigned int* auml_fu_cur_x = usl_framebuffer_update.auml_fu_cur;
            unsigned int* auml_fu_end_x = auml_fu_cur_x + adsl_session->dsc_fbu.dsc_rre.usc_width;
            while(auml_fu_cur_x < auml_fu_end_x){
               *auml_fu_cur_x++ = (unsigned int) uml_color;
            }
            usl_framebuffer_update.auml_fu_cur += adsl_session->usc_fb_width;
         } // while(auml_fu_cur_x < auml_fu_end_x)
         break;
     }// end case 4
          
      default:
         ERROR_MACRO_RDP(true, "Invalid Value for RDP Bytes Per Pixel Attribute: %d", inl_bpp_rdp);
         break;
   }// end switch( inl_bpp_rdp )
   
   adsl_session->dsc_fbu.dsc_rre.umc_no_rre_sub_rect--;

   if( adsl_session->dsc_fbu.dsc_rre.umc_no_rre_sub_rect == 0){
      
      if (adsl_session->dsc_fbu.dsc_rre.boc_use_offscreencache){
         adsl_session->dsc_fbu.dsc_rre.boc_use_offscreencache = false;

         //switch drawing surface back to screen
         dsd_sc_order_switchsurface* ads_switchsurface = dsl_orderqueue.new_command<dsd_sc_order_switchsurface>();
         ads_switchsurface->usc_bitmapid = screen_bitmap_surface;
         //DEF_DEBUG_PRINTF("order_switchsurface to screen_bitmap_surface");

         //use memblt to draw offscreen buffer to main screen
         dsd_sc_order_memblt* ads_memblt = dsl_orderqueue.new_command<dsd_sc_order_memblt>();
         ads_memblt->ucc_index_colortable = 0;
         ads_memblt->ucc_id_bitmapcache = ied_scc_bitmapcache_screen_id;
         ads_memblt->dsc_destination_rec.isc_top = adsl_session->dsc_fbu.usc_y;
         ads_memblt->dsc_destination_rec.isc_left = adsl_session->dsc_fbu.usc_x;
         ads_memblt->dsc_destination_rec.isc_width = adsl_session->dsc_fbu.usc_width;
         ads_memblt->dsc_destination_rec.isc_height = adsl_session->dsc_fbu.usc_height;
         ads_memblt->ucc_brop3 = 0xCC;
         ads_memblt->isc_x_src = 0;
         ads_memblt->isc_y_src = 0;
         ads_memblt->usc_cacheindex = RRE_OFFSCREEN_ID;
         ads_memblt->boc_has_bounds = FALSE;
         ads_memblt->boc_update_scrbuf = FALSE;

         //clear offscreen bitmap (RRE_OFFSCREEN_ID)
         dsd_sc_order_createoffbitmap* ads_createoffbitmap = dsl_orderqueue.new_command<dsd_sc_order_createoffbitmap>(sizeof(int));
         ads_createoffbitmap->usc_cx = 0;
         ads_createoffbitmap->usc_cy = 0;
         ads_createoffbitmap->usc_offscreenbitmapid = 0;
         ads_createoffbitmap->usc_numdelindices = 1;
         *((int*) (ads_createoffbitmap + 1)) = RRE_OFFSCREEN_ID;
      }else{
         //switched off while testing of offscreen caching. 
         if (adsl_session->dsc_crdps_1.adsc_rdp_co->dsc_caps.dsc_orders.boc_altsec_frame_marker_support){
            dsd_sc_order_framemarker* ads_framemarker = dsl_orderqueue.new_command<dsd_sc_order_framemarker>();
            ads_framemarker->iec_action = ied_scc_frame_end;
         }
      }//end if (adsl_session->dsc_fbu.dsc_rre.boc_use_offscreencache)
    
      goto p_cl_fu_end_20;
   }else {
      goto p_cl_fu_rre_20;
   } //end if( adsl_session->dsc_fbu.dsc_rre.umc_no_rre_sub_rect == 0)

//                      _ _             _______ _    ___ 
//  ___ _ _  __ ___  __| (_)_ _  __ _  |_  / _ \ |  | __|
// / -_) ' \/ _/ _ \/ _` | | ' \/ _` |  / /|   / |__| _| 
// \___|_||_\__\___/\__,_|_|_||_\__, | /___|_|_\____|___|
//                              |___/                    
// encoding ZRLEFTI
p_cl_fu_zrle_init:
   if(dsl_input_dec.get_bytes_left() < 4){         // The ZRLE-command is four bytes long
      adsl_session->iec_srfbc = ied_srfbc_fu_zrle_init;  // come back here, after data is available
      goto p_proc_inp_70;
   }

   CHECK_RETURN(dsl_input_dec.read_32_be(&adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_length));

   // JB: ? is this the same zlib as the regular zlib or do we need an own calling-structure?
   if (adsl_session->dsc_cdr_ctrl.imc_func == DEF_IFUNC_START) {  /* start of processing, initialize */
      adsl_session->dsc_cdr_ctrl.imc_param_1 = 1;  /* parameter value 1, SYNC-FLUSH */
      adsl_session->dsc_cdr_ctrl.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary helper routine pointer */
      adsl_session->dsc_cdr_ctrl.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
      m_cdr_zlib_1_dec( &adsl_session->dsc_cdr_ctrl );
      if (adsl_session->dsc_cdr_ctrl.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
         ERROR_MACRO_RDP(true, "zLib init returned 0x%x", adsl_session->dsc_cdr_ctrl.imc_return);
      }
   }

   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.iec_state_zrle  = ied_zrle_read_subencoding;
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_wfbu_left   = adsl_session->dsc_fbu.usc_x;
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_wfbu_right  = adsl_session->dsc_fbu.usc_x + adsl_session->dsc_fbu.usc_width;
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_wfbu_bottom = adsl_session->dsc_fbu.usc_y + adsl_session->dsc_fbu.usc_height;
   if(adsl_session->dsc_fbu.usc_width > 0x40)
      adsl_session->dsc_fbu.usc_width = 0x40;
   if(adsl_session->dsc_fbu.usc_height > 0x40)
      adsl_session->dsc_fbu.usc_height = 0x40;

// +------------------------+
// | ZRLE new data for zLib |
// +------------------------+
p_cl_fu_zrle_new_data: {

   if(adsl_session->dsc_fbu.usc_y >= adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_wfbu_bottom){
      // JB: We used to have a zLib-error, as we were ending zLib, when adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_draw_remaing == 0.
      // But it's possible, that there is still data for zLib, even if all of the output is already there. 
      if(adsl_session->dsc_cdr_ctrl.boc_sr_flush == TRUE){
         if(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_length != 0)
            ERROR_MACRO_RDP(true, "zLib: adsl_session->dsc_cdr_ctrl.boc_sr_flush == TRUE, but adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_length=%i",
               adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_length);
         goto p_cl_fu_end_20;
      }
   }

   if (dsl_input_dec.get_bytes_left() <= 0) {                         /* no input data           */
      adsl_session->iec_srfbc = ied_srfbc_fu_zrle_new_data;     // come back here, after data is available
      goto p_proc_inp_70;                    /* the input has been processed */
   }
   
   if(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_length == 0){
      // UUU todo JB 07.03.12: This is an error, which occures randomly, width Multimonitor (REAL VNC Enterprise) 
      // By doing this, at least there is no loop.
      goto p_cl_fu_end_20;
   }
   
   // JB: copy dsd_gathers
   dsd_gather_i_1* ads_gather_first = NULL;
   dsd_gather_i_1* ads_gather_act = NULL;
   while((dsl_input_dec.get_bytes_left() > 0) && 
         (adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_length > 0)){
      ENSURE_SPACE_ON_WORKAREA(sizeof(dsd_gather_i_1));    
      achl_work_2 -= sizeof(dsd_gather_i_1);
	  dsd_gather_i_1* ads_gather = (dsd_gather_i_1*) achl_work_2;
	  CHECK_RETURN(dsl_input_dec.other_gather_takes_data(ads_gather, adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_length, &iml1));
	  if(ads_gather_first == NULL){
         // first gather
         ads_gather_first = ads_gather;
      } else {
         ads_gather_act->adsc_next = ads_gather;
      }
      ads_gather_act = ads_gather;
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_length -= iml1;
   }

   adsl_session->dsc_cdr_ctrl.amc_aux      = adsp_hl_clib_1->amc_aux;  /* auxiliary helper routine pointer */
   adsl_session->dsc_cdr_ctrl.vpc_userfld  = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
   adsl_session->dsc_cdr_ctrl.adsc_gai1_in = ads_gather_first;
}

// Call zLib decompression
p_cl_fu_zrle_call_zlib: {                         /* call zLib decompression */
   adsl_session->iec_srfbc = ied_srfbc_fu_zrle_call_zlib; /* state of this RFC client: continue to call zLib */

   adsl_session->dsc_cdr_ctrl.achc_out_cur = chrl_work2 + adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_buffer_copied;  
   adsl_session->dsc_cdr_ctrl.achc_out_end = chrl_work2 + sizeof(chrl_work2);  /* end of buffer for output data */

   adsl_session->dsc_cdr_ctrl.boc_mp_flush = FALSE;  /* end-of-record input */
   if (adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_length == 0) {     /* no more remaining data  */
      adsl_session->dsc_cdr_ctrl.boc_mp_flush = TRUE;  /* end-of-record input */
   }
   char* achl_out_before = adsl_session->dsc_cdr_ctrl.achc_out_cur;
   m_cdr_zlib_1_dec( &adsl_session->dsc_cdr_ctrl );
   if (adsl_session->dsc_cdr_ctrl.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
      ERROR_MACRO_RDP(true, "zLib decompression returned %i", adsl_session->dsc_cdr_ctrl.imc_return);
   }
   if(achl_out_before == adsl_session->dsc_cdr_ctrl.achc_out_cur) {              /* nothing decompressed    */
      goto p_cl_fu_zrle_new_data;          // Need new data for decompression
   }

   // Copy bytes from last time
   if(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_buffer_copied > 0){
      memcpy(chrl_work2, adsl_session->dsc_fbu.dsc_raw_zlib_zrle.chrc_zlib_buffer, adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_buffer_copied);
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_buffer_copied = 0;
   }

   // Make zrle_reader
   dsd_gather_i_1 dsl_zlib_gather_out;
   dsl_zlib_gather_out.achc_ginp_cur = chrl_work2;
   dsl_zlib_gather_out.achc_ginp_end = adsl_session->dsc_cdr_ctrl.achc_out_cur;
   dsl_zlib_gather_out.adsc_next = NULL;
   dsd_gather_reader adsl_zlib_out(&dsl_zlib_gather_out);

   // CPIXEL: bpp_rfb is 24, if deph = 24
   inl_bpp_rdp = adsl_session->imc_bpp_rdp;
   inl_bpp_rfb = adsl_session->imc_bpp_rfb;
   if(adsl_session->adsc_cpixel_converter!= adsl_session->adsc_pixel_converter)
      inl_bpp_rfb = 3;

// +-----------------------+
// | ZRLE switch sub-state |
// +-----------------------+
p_cl_fu_zrle_switch_state:

   // Switch state
   switch(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.iec_state_zrle){
      case ied_zrle_read_subencoding:
         goto p_cl_fu_zrle_read_subencoding;
      case ied_zrle_raw:
         goto p_cl_fu_zrle_raw;
      case ied_zrle_palette_palette:
         goto p_cl_fu_zrle_palette_palette;
      case ied_zrle_palette_data:
         goto p_cl_fu_zrle_palette_raw;
      case ied_zrle_plain_rle_color:
         goto p_cl_fu_zrle_plain_rle_color;
      case ied_zrle_plain_rle_length:
         goto p_cl_fu_zrle_plain_rle_length;
      case ied_zrle_palette_rle_palette:
         goto p_cl_fu_zrle_palette_rle_palette;
      case ied_zrle_palette_rle_index:
         goto p_cl_fu_zrle_palette_rle_index;
      case ied_zrle_palette_rle_length:
         goto p_cl_fu_zrle_palette_rle_length;
      
      default:
         ERROR_MACRO_RDP(true, "Unknown ZRLE-state 0x%x", adsl_session->dsc_fbu.dsc_raw_zlib_zrle.iec_state_zrle);
   };

// +-----------------------+
// | ZRLE read subencoding |
// +-----------------------+
p_cl_fu_zrle_read_subencoding:

   if(adsl_zlib_out.empty()){
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.iec_state_zrle = ied_zrle_read_subencoding;
      goto p_cl_fu_zrle_call_zlib; 
   }
   int inl_subencoding;
   CHECK_RETURN(adsl_zlib_out.peek_8(&inl_subencoding));
//   m_sdh_printf_tl( &dsl_sdh_call_1, "I", __LINE__, "ZRLE tile: %03x %03x %03x %03x Subencoding: 0x%x, bytes left: %d", 
//      adsl_session->dsc_fbu.usc_x, adsl_session->dsc_fbu.usc_y,
//      adsl_session->dsc_fbu.usc_width, adsl_session->dsc_fbu.usc_height, inl_subencoding, adsl_zlib_out.get_bytes_left());

   // whole tile has a solid color
   if(inl_subencoding == 0x1)
      goto p_cl_fu_zrle_solid_tile;

   // skip subencoding (all the following subencodings use states)
   adsl_zlib_out.skip(1);

   // Set start-values
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x = 0;
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_y = 0;
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act_line = (char*) adsl_session->dsc_crdps_1.ac_screen_buffer +
      adsl_session->dsc_fbu.usc_y *  adsl_session->inc_scanline_rdp_screen + adsl_session->dsc_fbu.usc_x * adsl_session->imc_bpp_rdp;
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act_line; 

   adsl_session->adsc_fbu_changes->isc_left   = adsl_session->dsc_fbu.usc_width;
   adsl_session->adsc_fbu_changes->isc_top    = adsl_session->dsc_fbu.usc_height;
   adsl_session->adsc_fbu_changes->isc_right  = 0;
   adsl_session->adsc_fbu_changes->isc_bottom = 0;

   // raw encoding
   if(inl_subencoding == 0x0){
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.iec_state_zrle = ied_zrle_raw;
      goto p_cl_fu_zrle_raw;
   }

   // packed palette subencoding
   if(inl_subencoding < 0x16){
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_pal_pal_size  = inl_subencoding;
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_pal_act_color = 0;
      goto p_cl_fu_zrle_palette_palette;
   }

   if((inl_subencoding < 0x80) || (inl_subencoding == 0x81))
      ERROR_MACRO_RDP(true, "Unknown ZRLE subencoding 0x%x", inl_subencoding);

   // Runnlength encoding
   // -------------------

   // raw rle
   if(inl_subencoding == 0x80)  
      goto p_cl_fu_zrle_plain_rle_color;

   // palette RLE
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_pal_rle_pal_size  = inl_subencoding - 0x80;
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_pal_rle_act_color = 0;
   goto p_cl_fu_zrle_palette_rle_palette;

// +----------+
// | ZRLE raw |
// +----------+
p_cl_fu_zrle_raw:
   if(adsl_zlib_out.get_bytes_left() < inl_bpp_rfb){
      goto p_cl_fu_zrle_data_consumed;
   }
   adsl_zlib_out.get_max_contiguous_bytes(&iml1, &achl1);
   inl_num_pixels = iml1 / inl_bpp_rfb;
   iml1 = adsl_session->dsc_fbu.usc_width - adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x;
   if(inl_num_pixels > iml1)
      inl_num_pixels = iml1; 
   adsl_zlib_out.skip(inl_num_pixels * inl_bpp_rfb);
   ENSURE_SPACE_ON_WORKAREA(inl_num_pixels * adsl_session->imc_bpp_rdp);
   adsl_session->adsc_cpixel_converter->convert(achl1, achl_work_1, inl_num_pixels);
   goto p_cl_fu_zrle_raw_process_pixels; 

// +---------------------+
// | ZRLE packed palette |
// +---------------------+
p_cl_fu_zrle_palette_palette:
   if(adsl_zlib_out.get_bytes_left() < inl_bpp_rfb){
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.iec_state_zrle = ied_zrle_palette_palette;
      goto p_cl_fu_zrle_data_consumed;
   }

   uml_color_rfb = 0;
   CHECK_RETURN(adsl_zlib_out.copy_to((char*)(&uml_color_rfb), inl_bpp_rfb));
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.umrc_pal_palette[
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_pal_act_color++] = 
      adsl_session->adsc_cpixel_converter->convert(uml_color_rfb);
   if(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_pal_act_color < adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_pal_pal_size)
      goto p_cl_fu_zrle_palette_palette;

   // palette complete -> make converter
   if(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_pal_pal_size == 2){
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_bpp_src = 1;
   } else if(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_pal_pal_size <= 4){
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_bpp_src = 2;
   } else {
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_bpp_src = 4;
   }

   //ZRLE colormodel setup
   {  //emclosing the definition and use of:
      //dsl_colormap, dsl_memory_provider, and dsl_colormodel_src
      //to avoid using the variables later or without proper initialisation (and avoiding warnings ;-) )
      c_colormap dsl_colormap(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.umrc_pal_palette, adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_pal_pal_size);
      dsd_memory_provider dsl_memory_provider(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.chrc_mem_for_converter, 
         sizeof(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.chrc_mem_for_converter));
      c_colormodel dsl_colormodel_src(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_bpp_src, 
                                  adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_bpp_src,
                                  ie_endian_big, dsl_colormap, *adsl_session->adsc_colormodel_rdp,
                                  dsl_memory_provider);

      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.adsc_pixel_converter = 
      c_converter_factory<dsd_pixel_converter_config>::create_converter(dsl_colormodel_src, 
      *adsl_session->adsc_colormodel_rdp, dsl_memory_provider);
   }// end scope ZRLE colormodel setup
      
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.iec_state_zrle = ied_zrle_palette_data;

p_cl_fu_zrle_palette_raw:      
   if(adsl_zlib_out.empty()){
      goto p_cl_fu_zrle_data_consumed;
   }

   // Require number of available pixels
   adsl_zlib_out.get_max_contiguous_bytes(&iml1, &achl1);
   inl_num_pixels = iml1 * 8 / adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_bpp_src;
   iml1 = adsl_session->dsc_fbu.usc_width - adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x;
   if(inl_num_pixels > iml1)
      inl_num_pixels = iml1; 
   adsl_zlib_out.skip((inl_num_pixels * adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_bpp_src + 7) / 8);
   ENSURE_SPACE_ON_WORKAREA(inl_num_pixels * adsl_session->imc_bpp_rdp);
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.adsc_pixel_converter->convert(achl1, achl_work_1, inl_num_pixels);
   goto p_cl_fu_zrle_raw_process_pixels; 

// +-----------------+
// | ZRLE plain draw |
// +-----------------+
p_cl_fu_zrle_raw_process_pixels: 

   // compare and comp pixels
//#if !(defined HL_LINUX)
//   char* ach_first_diff = NULL;                 /* framebuffer update changes start */
//#else
   ach_first_diff = NULL;                 /* framebuffer update changes start */
//#endif
   char* ach_last_diff;
   switch (adsl_session->imc_bpp_rdp) {      /* bytes per pixel RDP     */
      case 2:                            /* 15 or 16 bits           */
         m_compare_and_copy((uint16_t*) adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act, (uint16_t*) achl_work_1, inl_num_pixels,
            (uint16_t**) (&ach_first_diff), (uint16_t**) (&ach_last_diff));
            break;
      case 3:       
         m_compare_and_copy((dsd_pixel_24*) adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act, (dsd_pixel_24*) achl_work_1, inl_num_pixels,
            (dsd_pixel_24**) (&ach_first_diff), (dsd_pixel_24**) (&ach_last_diff));
         break;
      case 4:                            /* 32 bits                 */
         m_compare_and_copy((uint32_t*) adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act, (uint32_t*) achl_work_1, inl_num_pixels,
            (uint32_t**) (&ach_first_diff), (uint32_t**) (&ach_last_diff));
         break;
      default:
         ERROR_MACRO_RDP(true, "Invalid RDP bytes-per-pixel value: adsl_session->imc_bpp_rdp=0%x", adsl_session->imc_bpp_rdp);
   }// end switch (adsl_session->imc_bpp_rdp)
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act += inl_num_pixels * inl_bpp_rdp;

   // New min/max x/y
   if (ach_first_diff) {                  /* framebuffer update changed */
      iml1 = CONVERT_W64_TO_INT(ach_first_diff - adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act_line) / inl_bpp_rdp;
      if (adsl_session->adsc_fbu_changes->isc_left > iml1) 
         adsl_session->adsc_fbu_changes->isc_left = iml1;

      iml1 = (CONVERT_W64_TO_INT(ach_last_diff - adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act_line) / inl_bpp_rdp) + 1;
      if (adsl_session->adsc_fbu_changes->isc_right < iml1) 
         adsl_session->adsc_fbu_changes->isc_right = iml1;

      iml1 = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_y;
      if (adsl_session->adsc_fbu_changes->isc_top > iml1) 
         adsl_session->adsc_fbu_changes->isc_top = iml1;

      if(adsl_session->adsc_fbu_changes->isc_bottom < iml1)
         adsl_session->adsc_fbu_changes->isc_bottom = iml1;
   }

   // Increase act x and check for new line
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x += inl_num_pixels;
   if(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x >= adsl_session->dsc_fbu.usc_width){
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x = 0;
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act_line += adsl_session->inc_scanline_rdp_screen;
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act_line;
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_y++;

      // update, if IMS_SCREEN_UPDATE_HEIGHT lines updated. 
      if(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_y >= adsl_session->dsc_fbu.usc_height){
         if(adsl_session->adsc_fbu_changes->isc_left < adsl_session->adsc_fbu_changes->isc_right){
            dsd_sc_draw_sc* ads_draw_sc = dsl_orderqueue.new_command<dsd_sc_draw_sc>();
            ads_draw_sc->imc_left   = adsl_session->dsc_fbu.usc_x + adsl_session->adsc_fbu_changes->isc_left;
            ads_draw_sc->imc_top    = adsl_session->dsc_fbu.usc_y + adsl_session->adsc_fbu_changes->isc_top;
            ads_draw_sc->imc_right  = adsl_session->dsc_fbu.usc_x + adsl_session->adsc_fbu_changes->isc_right; 
            ads_draw_sc->imc_bottom = adsl_session->dsc_fbu.usc_y + adsl_session->adsc_fbu_changes->isc_bottom + 1;
         } 
         goto p_cl_fu_zrle_end_of_tile;
      }
   }
   
   if(adsl_zlib_out.empty())
      goto p_cl_fu_zrle_data_consumed;
   goto p_cl_fu_zrle_switch_state;

// +-----------------+
// | ZRLE solid tile |
// +-----------------+
p_cl_fu_zrle_solid_tile:
   if(adsl_zlib_out.get_bytes_left() < 1 + inl_bpp_rfb){
      // Subencoding is not skipped yet, so we don't have an own state for this small subencoding
      // But we have to set this state here. Weird error occured otherwise in several random situation. JB 08.03.2012
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.iec_state_zrle = ied_zrle_read_subencoding;
      goto p_cl_fu_zrle_data_consumed;
   }
   adsl_zlib_out.skip(1); // Skip subencoding
   
   uml_color_rfb = 0;
   CHECK_RETURN(adsl_zlib_out.copy_to((char*) (&uml_color_rfb), inl_bpp_rfb));
//#if !(defined HL_LINUX)
//   uint32_t uml_color = adsl_session->adsc_cpixel_converter->convert(uml_color_rfb);
//
//   dsd_sc_order_opaquerect* ads_opaquerect  = dsl_orderqueue.new_command<dsd_sc_order_opaquerect>();
//#else
   uml_color = adsl_session->adsc_cpixel_converter->convert(uml_color_rfb);
   ads_opaquerect  = dsl_orderqueue.new_command<dsd_sc_order_opaquerect>();
//#endif
   ads_opaquerect->dsc_rectangle.isc_left   = adsl_session->dsc_fbu.usc_x;
   ads_opaquerect->dsc_rectangle.isc_top    = adsl_session->dsc_fbu.usc_y;
   ads_opaquerect->dsc_rectangle.isc_width  = adsl_session->dsc_fbu.usc_width;
   ads_opaquerect->dsc_rectangle.isc_height = adsl_session->dsc_fbu.usc_height;
   CHECK_RETURN_SUB(m_get_rdpcolour_int(uml_color, adsl_session->inc_coldep_rdp, &ads_opaquerect->umc_color));
   ads_opaquerect->imc_no_color_bytes       = 3;           
   ads_opaquerect->boc_has_bounds           = FALSE;
   ads_opaquerect->boc_update_scrbuf        = FALSE;
   
   switch (adsl_session->imc_bpp_rdp) {      /* bytes per pixel RDP     */
      case 2: 
         m_fill_rect(adsl_session->dsc_crdps_1.ac_screen_buffer, *((uint16_t*) &uml_color), adsl_session->dsc_fbu.usc_x, adsl_session->dsc_fbu.usc_y, 
            adsl_session->dsc_fbu.usc_width, adsl_session->dsc_fbu.usc_height, adsl_session->usc_fb_width);
         break;
      case 3: 
         m_fill_rect(adsl_session->dsc_crdps_1.ac_screen_buffer, *((dsd_pixel_24*) &uml_color), adsl_session->dsc_fbu.usc_x, adsl_session->dsc_fbu.usc_y, 
            adsl_session->dsc_fbu.usc_width, adsl_session->dsc_fbu.usc_height, adsl_session->usc_fb_width);
         break;
      case 4: 
         m_fill_rect(adsl_session->dsc_crdps_1.ac_screen_buffer, uml_color, adsl_session->dsc_fbu.usc_x, adsl_session->dsc_fbu.usc_y, 
            adsl_session->dsc_fbu.usc_width, adsl_session->dsc_fbu.usc_height, adsl_session->usc_fb_width);
         break;
            ERROR_MACRO_RDP(true, "Invalid RDP bytes-per-pixel value: adsl_session->imc_bpp_rdp=0%x", adsl_session->imc_bpp_rdp);
   }// end switch (adsl_session->imc_bpp_rdp)

   goto p_cl_fu_zrle_end_of_tile;

// +---------------------+
// | ZRLE runnlength raw |
// +---------------------+
p_cl_fu_zrle_plain_rle_color:

   if(adsl_zlib_out.get_bytes_left() < inl_bpp_rfb){
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.iec_state_zrle = ied_zrle_plain_rle_color;
      goto p_cl_fu_zrle_data_consumed;
   }

   uml_color_rfb = 0;
   CHECK_RETURN(adsl_zlib_out.copy_to((char*)(&uml_color_rfb), inl_bpp_rfb));
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_rle_color = 
      adsl_session->adsc_cpixel_converter->convert(uml_color_rfb);
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_rle_length = 1;

p_cl_fu_zrle_plain_rle_length:
   if(adsl_zlib_out.empty()){
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.iec_state_zrle = ied_zrle_plain_rle_length;
      goto p_cl_fu_zrle_call_zlib; 
   }

   CHECK_RETURN(adsl_zlib_out.read_8(&iml1));
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_rle_length += iml1;
   if(iml1 == 0xff)
      goto p_cl_fu_zrle_plain_rle_length;

   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.iec_state_zrle = ied_zrle_plain_rle_color;
   iml3 = get_rdpcolor(adsl_session->inc_coldep_rdp, 0xff, 0, 0);
   goto p_cl_fu_zrle_rle_draw;

// +-------------------------+
// | ZRLE runnlength palette |
// +-------------------------+
p_cl_fu_zrle_palette_rle_palette:

   if(adsl_zlib_out.get_bytes_left() < inl_bpp_rfb){
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.iec_state_zrle = ied_zrle_palette_rle_palette;
      goto p_cl_fu_zrle_data_consumed;
   }

   uml_color_rfb = 0;
   CHECK_RETURN(adsl_zlib_out.copy_to((char*) &uml_color_rfb, inl_bpp_rfb));
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inrc_pal_rle_palette[
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_pal_rle_act_color++] = 
         adsl_session->adsc_cpixel_converter->convert(uml_color_rfb);
   if(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_pal_rle_act_color < adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_pal_rle_pal_size)
      goto p_cl_fu_zrle_palette_rle_palette;

   // palette complete

p_cl_fu_zrle_palette_rle_index:
   if(adsl_zlib_out.empty()){
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.iec_state_zrle = ied_zrle_palette_rle_index;
      goto p_cl_fu_zrle_call_zlib; 
   }

   int inl_index;
   CHECK_RETURN(adsl_zlib_out.read_8(&inl_index));

   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_rle_color = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inrc_pal_rle_palette[inl_index & 0x7F];
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_rle_length = 1;

   if(inl_index < 0x80){ // Just one pixel
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.iec_state_zrle = ied_zrle_palette_rle_index;
      goto p_cl_fu_zrle_rle_draw;
   }

p_cl_fu_zrle_palette_rle_length:
   if(adsl_zlib_out.empty()){
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.iec_state_zrle = ied_zrle_palette_rle_length;
      goto p_cl_fu_zrle_call_zlib; 
   }

   CHECK_RETURN(adsl_zlib_out.read_8(&iml1));
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_rle_length += iml1;
   if(iml1 == 0xff)
      goto p_cl_fu_zrle_palette_rle_length;

   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.iec_state_zrle = ied_zrle_palette_rle_index;
   iml3 = get_rdpcolor(adsl_session->inc_coldep_rdp, 0, 0, 0xff);
   goto p_cl_fu_zrle_rle_draw;

// +----------------------+
// | ZRLE runnlength draw |
// +----------------------+
p_cl_fu_zrle_rle_draw:

   while(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_rle_length > 0){

      int inl_pixels_now = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_rle_length;
      int inl_pixels_line = adsl_session->dsc_fbu.usc_width - adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x;
      if(inl_pixels_now > inl_pixels_line)
         inl_pixels_now = inl_pixels_line;

//#if !(defined HL_LINUX)
//   char* ach_first_diff = NULL;                 /* framebuffer update changes start */
//#else
   ach_first_diff = NULL;                 /* framebuffer update changes start */
//#endif
      char* ach_last_diff;
      switch (adsl_session->imc_bpp_rdp) {      /* bytes per pixel RDP     */
         case 2: {                           /* 15 or 16 bits           */
            uint16_t* ausl_act = (uint16_t*) adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act;
            uint16_t* ausl_end = ausl_act + inl_pixels_now;
            uint16_t usl_color = *((uint16_t*) &adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_rle_color);
            while(ausl_act < ausl_end){
               if(*ausl_act != usl_color){
                  *ausl_act = usl_color;
                  if(ach_first_diff == NULL)
                     ach_first_diff = (char*) ausl_act;
                  ach_last_diff = (char*) ausl_act; 
               }
               ausl_act++;
            }
            adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act = (char*) ausl_end; 
         } break; 
         case 3: {                        
            dsd_pixel_24* adsl_act = (dsd_pixel_24*) adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act;
            dsd_pixel_24* adsl_end = adsl_act + inl_pixels_now;
            dsd_pixel_24 dsl_color = *((dsd_pixel_24*) &adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_rle_color);
            while(adsl_act < adsl_end){
               if(*adsl_act != dsl_color){
                  *adsl_act = dsl_color;
                  if(ach_first_diff == NULL)
                     ach_first_diff = (char*) adsl_act;
                  ach_last_diff = (char*) adsl_act; 
               }
               adsl_act++;
            }
            adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act = (char*) adsl_end; 
         } break; 
         case 4: {                        
            uint32_t* aiml_act = (uint32_t*) adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act;
            uint32_t* aiml_end = aiml_act + inl_pixels_now;
            uint32_t iml_color = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_rle_color;
            while(aiml_act < aiml_end){
               if(*aiml_act != iml_color){
                  *aiml_act = iml_color;
                  if(ach_first_diff == NULL)
                     ach_first_diff = (char*) aiml_act;
                  ach_last_diff = (char*) aiml_act; 
               }
               aiml_act++;
            }
            adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act = (char*) aiml_end; 
         } break; 
         default:
            ERROR_MACRO_RDP(true, "Invalid RDP bytes-per-pixel value: adsl_session->imc_bpp_rdp=0%x", adsl_session->imc_bpp_rdp);
      }// end switch (adsl_session->imc_bpp_rdp)

      if (ach_first_diff) {                  /* framebuffer update changed */
         iml1 = CONVERT_W64_TO_INT(ach_first_diff - adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act_line) / inl_bpp_rdp;
         if (adsl_session->adsc_fbu_changes->isc_left > iml1) 
            adsl_session->adsc_fbu_changes->isc_left = iml1;

         iml1 = (CONVERT_W64_TO_INT(ach_last_diff - adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act_line) / inl_bpp_rdp) + 1;
         if(adsl_session->adsc_fbu_changes->isc_right < iml1) 
            adsl_session->adsc_fbu_changes->isc_right = iml1;

         if(adsl_session->adsc_fbu_changes->isc_top > adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_y) 
            adsl_session->adsc_fbu_changes->isc_top = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_y;

         if(adsl_session->adsc_fbu_changes->isc_bottom < adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_y)
            adsl_session->adsc_fbu_changes->isc_bottom = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_y;
      }

      // Increase act_x and check, if end of line
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x += inl_pixels_now;
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_rle_length -= inl_pixels_now; 
      if(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x < adsl_session->dsc_fbu.usc_width)
         continue; 

      // End of line: increase act_y and check, if end of tile
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_y++;
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_x = 0;
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act_line += adsl_session->inc_scanline_rdp_screen;
      adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.ach_dest_act_line;
      if(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_act_y < adsl_session->dsc_fbu.usc_height)
         continue; 

      // End of tile
      if(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_rle_length > 0)
         ERROR_MACRO_RDP(true, "ZRLE: End of tile plain rle reached, but still 0x%x bytes left in run.", adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_rle_length);
      
      if(adsl_session->adsc_fbu_changes->isc_left < adsl_session->adsc_fbu_changes->isc_right){
         dsd_sc_draw_sc* ads_draw_sc = dsl_orderqueue.new_command<dsd_sc_draw_sc>();
         ads_draw_sc->imc_left   = adsl_session->dsc_fbu.usc_x + adsl_session->adsc_fbu_changes->isc_left;
         ads_draw_sc->imc_top    = adsl_session->dsc_fbu.usc_y + adsl_session->adsc_fbu_changes->isc_top;
         ads_draw_sc->imc_right  = adsl_session->dsc_fbu.usc_x + adsl_session->adsc_fbu_changes->isc_right; 
         ads_draw_sc->imc_bottom = adsl_session->dsc_fbu.usc_y + adsl_session->adsc_fbu_changes->isc_bottom + 1;
     }

      goto p_cl_fu_zrle_end_of_tile; 
   }
   goto p_cl_fu_zrle_switch_state; // next run


p_cl_fu_zrle_end_of_tile:
   adsl_session->dsc_fbu.usc_x += adsl_session->dsc_fbu.usc_width;
   adsl_session->dsc_fbu.usc_width = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_wfbu_right - adsl_session->dsc_fbu.usc_x;
   if(adsl_session->dsc_fbu.usc_width > 0x40)
      adsl_session->dsc_fbu.usc_width = 0x40;

   if(adsl_session->dsc_fbu.usc_width > 0)
      goto p_cl_fu_zrle_read_subencoding;

   // End of this line of tiles reached

   // Revert usc_width to width of first tile
   adsl_session->dsc_fbu.usc_x = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_wfbu_left;
   adsl_session->dsc_fbu.usc_width = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_wfbu_right - adsl_session->dsc_fbu.usc_x;
   if(adsl_session->dsc_fbu.usc_width > 0x40)
      adsl_session->dsc_fbu.usc_width = 0x40;

   // Eincrease usc_y
   adsl_session->dsc_fbu.usc_y += adsl_session->dsc_fbu.usc_height;
   adsl_session->dsc_fbu.usc_height = adsl_session->dsc_fbu.dsc_raw_zlib_zrle.inc_wfbu_bottom - adsl_session->dsc_fbu.usc_y;
   if(adsl_session->dsc_fbu.usc_height > 0x40)
      adsl_session->dsc_fbu.usc_height = 0x40;
  
   if(adsl_session->dsc_fbu.usc_height > 0)
      goto p_cl_fu_zrle_read_subencoding; 

   // everything done
   goto p_cl_fu_zrle_call_zlib; 

p_cl_fu_zrle_data_consumed:
   adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_buffer_copied = adsl_zlib_out.get_bytes_left();
   if(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_buffer_copied > sizeof(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_buffer_copied))
      ERROR_MACRO_RDP(true, "ZRLE-error: imc_zlib_buffer_copied too small! Needed: 0x%x", adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_buffer_copied);
   adsl_zlib_out.copy_to(adsl_session->dsc_fbu.dsc_raw_zlib_zrle.chrc_zlib_buffer, adsl_session->dsc_fbu.dsc_raw_zlib_zrle.imc_zlib_buffer_copied);
   goto p_cl_fu_zrle_call_zlib;

}

//                      _ _              ___                     
//  ___ _ _  __ ___  __| (_)_ _  __ _   / __|  _ _ _ ___ ___ _ _ 
// / -_) ' \/ _/ _ \/ _` | | ' \/ _` | | (_| || | '_(_-</ _ \ '_|
// \___|_||_\__\___/\__,_|_|_||_\__, |  \___\_,_|_| /__/\___/_|  
//                              |___/         

p_cl_fu_cursor: 
  
   //check size of cursor
   if (adsl_session->dsc_fbu.usc_width * adsl_session->dsc_fbu.usc_height == 0){
      //Size of cursor is ZERO. It means that the cursor must be hidden. 
      
      //Create System Hidden Pointer RDP-Command
      dsd_sc_mpoi_system* ads_rdp_pointer = dsl_orderqueue.new_command<dsd_sc_mpoi_system>();
      ads_rdp_pointer->iec_system_pointer_type = ied_sysptr_null;  //hidden system cursor
      
      goto p_cl_fu_end_20;
   }
   
   //size of cursor is NOT ZERO
//#if !(defined HL_LINUX)
//   int inl_bytes_needed = adsl_session->dsc_fbu.usc_width * adsl_session->dsc_fbu.usc_height * adsl_session->imc_bpp_rfb + 
//                          ((int) ((adsl_session->dsc_fbu.usc_width + 7) / 8)) * adsl_session->dsc_fbu.usc_height;
//#else
inl_bytes_needed = adsl_session->dsc_fbu.usc_width * adsl_session->dsc_fbu.usc_height * adsl_session->imc_bpp_rfb + 
                          ((int) ((adsl_session->dsc_fbu.usc_width + 7) / 8)) * adsl_session->dsc_fbu.usc_height;
//#endif
   if(dsl_input_dec.get_bytes_left() < inl_bytes_needed){   // wait until all the bytes are there
      adsl_session->iec_srfbc = ied_srfbc_fu_cursor;              // come back here, after data is available
      goto p_proc_inp_70;
   }

   // Get max height and width of cursors
//#if !(defined HL_LINUX)
//   int inl_max_cursor_width  = 32;
//   int inl_max_cursor_height = 32;
//#else
   inl_max_cursor_width  = 32;
   inl_max_cursor_height = 32;
//#endif
   if(adsl_session->dsc_crdps_1.adsc_rdp_co->dsc_caps.dsc_pointer.boc_large_pointer_supported){
      inl_max_cursor_width  = 96;
      inl_max_cursor_height = 96;
   }

   // Calculate real width and padding
   // adsl_session->dsc_fbu.usc_width, adsl_session->dsc_fbu.usc_height: This pixels have to be parsed from dsl_input_dec, regardless if used or not.
   // inl_cursor_width, inl_cursor height: Data, which is copied to the destination. Can be smaller than adsl_session->dsc_fbu.usc_width and 
   //   adsl_session->dsc_fbu.usc_height, but not bigger. 
   // inl_padd_width, inl_padd_height: Sizes, given to RDP. Can be bigger than the others, but not smaller.
/*#if !(defined HL_LINUX)
   int inl_cursor_width  = adsl_session->dsc_fbu.usc_width  > inl_max_cursor_width ? inl_max_cursor_width : adsl_session->dsc_fbu.usc_width;
   int inl_cursor_height = adsl_session->dsc_fbu.usc_height > inl_max_cursor_height ? inl_max_cursor_height : adsl_session->dsc_fbu.usc_height;

   int inl_padd_width = ((int)((inl_cursor_width + 7) / 8)) * 8;
   int inl_padd_width_bytes = inl_padd_width * adsl_session->imc_bpp_rdp; 
   int inl_padd_height = ((int)((inl_cursor_height + 7) / 8)) * 8;
#else */
   inl_cursor_width  = adsl_session->dsc_fbu.usc_width  > inl_max_cursor_width ? inl_max_cursor_width : adsl_session->dsc_fbu.usc_width;
   inl_cursor_height = adsl_session->dsc_fbu.usc_height > inl_max_cursor_height ? inl_max_cursor_height : adsl_session->dsc_fbu.usc_height;

   inl_padd_width = ((int)((inl_cursor_width + 7) / 8)) * 8;
   inl_padd_width_bytes = inl_padd_width * adsl_session->imc_bpp_rdp; 
   inl_padd_height = ((int)((inl_cursor_height + 7) / 8)) * 8;
//#endif
   // XOR-MASK
   // --------

   // Does xor-mask fit in workarea?
   if(achl_work_2 - achl_work_1 < inl_padd_width_bytes * inl_padd_height){
      GET_MORE_WORKAREA;
      if(achl_work_2 - achl_work_1 < inl_padd_width_bytes * inl_padd_height){
         inl_padd_height = CONVERT_W64_TO_INT(achl_work_2 - achl_work_1) / inl_padd_width_bytes;
         if(inl_padd_height < inl_cursor_height)
            inl_cursor_height = inl_padd_height;
      }
   }

   // Get space on workarea for xor-mask
/*#if !(defined HL_LINUX)
   int in_len_xor_mask = inl_padd_width_bytes * inl_padd_height;
   char* achl_xor_mask = achl_work_1;
#else */
   in_len_xor_mask = inl_padd_width_bytes * inl_padd_height;
   achl_xor_mask = achl_work_1;
//#endif
   achl_work_1 += in_len_xor_mask;
   memset(achl_xor_mask, 0x00, in_len_xor_mask); // necessary, so that padding is not visible

   // Now convert xor-mask (xor-mask is converted into colormodel of screen)
   for(int in_y = 0; in_y < adsl_session->dsc_fbu.usc_height; in_y++){
      // Start of destination line
      achl1 = achl_xor_mask + (inl_padd_height - in_y - 1) * inl_padd_width_bytes; 
      if(in_y < inl_cursor_height){
         // Convert one line
         int in_x = 0;
         while(in_x < adsl_session->dsc_fbu.usc_width){
            int inl_pixels_left = inl_cursor_width - in_x;
            if(inl_pixels_left > 0){
               dsl_input_dec.get_max_contiguous_bytes(&iml_pixel_input, &achl_pixel_input);
               if(iml_pixel_input > adsl_session->imc_bpp_rfb){
                  int inl_pixels = iml_pixel_input / adsl_session->imc_bpp_rfb;
                  if(inl_pixels > adsl_session->dsc_fbu.usc_width - in_x)
                     inl_pixels = adsl_session->dsc_fbu.usc_width - in_x; 
                  if(inl_pixels > inl_pixels_left)
                     inl_pixels = inl_pixels_left;
                  adsl_session->adsc_pixel_converter->convert(achl_pixel_input, achl1, inl_pixels);
                  dsl_input_dec.skip(inl_pixels * adsl_session->imc_bpp_rfb);
                  achl1 += inl_pixels * adsl_session->imc_bpp_rdp;
                  in_x += inl_pixels;
               } else {
                  CHECK_RETURN(dsl_input_dec.copy_to(chrl_work2, adsl_session->imc_bpp_rfb));
                  adsl_session->adsc_pixel_converter->convert(chrl_work2, achl1, 1);
                  achl1 += adsl_session->imc_bpp_rdp;
                  in_x++;
               }
            } else {
               dsl_input_dec.skip((adsl_session->dsc_fbu.usc_width - in_x) * adsl_session->imc_bpp_rfb);
               in_x += adsl_session->dsc_fbu.usc_width - in_x;
            }
         }
      } else {
         dsl_input_dec.skip(adsl_session->dsc_fbu.usc_width * adsl_session->imc_bpp_rfb);
      }
   }

   // AND-MASK
   // --------

   // RDP and VNC are quite different here: 
   // VNC: Sends cursor-pixels and bitmask, where 1 = bit is valid, 0 = bit is not valid. 
   // RDP: Sends cursor-pixels (=xor-maks) and bitmasp (=and-maks), where 
   //      0 = pixel is drawn like send in cursor-pixels, background does not matter for this pixel. 
   //      1 = pixel is xor-d with background.
   //      => When a pixel is transparent, in RDP the and-mask is 1 and the xor-mask is set to 0.
   // This leads to the following conversion:
   // (CASE 1) 1 in VNC-bitmask => 0 in RDP-and-mask and the color of the cursor-pixels is the same.
   // (CASE 0) 0 in VNC-bitmask (transparent!) => 1 in RDP-and-mask and 0 in cursor-pixels of RDP.

   // Get space on workarea
/*#if !(defined HL_LINUX)
   int inl_padd_width_bytes_and = ((((int) ((inl_padd_width + 7) / 8)) + 1) & (0 - 2)); //rounding up to the next even number of bytes
   int in_len_and_mask = inl_padd_width_bytes_and * inl_padd_height;
#else */
   inl_padd_width_bytes_and = ((((int) ((inl_padd_width + 7) / 8)) + 1) & (0 - 2)); //rounding up to the next even number of bytes
   in_len_and_mask = inl_padd_width_bytes_and * inl_padd_height;
//#endif
   ENSURE_SPACE_ON_WORKAREA(in_len_and_mask);
//#if !(defined HL_LINUX)
//   char* achl_and_mask = achl_work_1;
//#else
   achl_and_mask = achl_work_1;
//#endif
   memset(achl_and_mask, 0xff, in_len_and_mask); // necessary, so that padding is not visible
   achl_work_1 += in_len_and_mask;
   // Calculates

/*#if !(defined HL_LINUX)
   int inl_parse_bytes = (adsl_session->dsc_fbu.usc_width + 7) / 8;   
   int inl_skip_bytes = 0;
   int inl_copy_bytes = inl_parse_bytes;
#else */
   inl_parse_bytes = (adsl_session->dsc_fbu.usc_width + 7) / 8;
   inl_skip_bytes = 0;
   inl_copy_bytes = inl_parse_bytes;
//#endif

   if(inl_parse_bytes > inl_padd_width_bytes_and){
      inl_copy_bytes = inl_padd_width_bytes_and;
      inl_skip_bytes = inl_parse_bytes - inl_padd_width_bytes_and;
   }

   // Now copy and-mask
   for(int in_y = 0; in_y < adsl_session->dsc_fbu.usc_height; in_y++){
      char* achl_and_dst = achl_and_mask + (inl_padd_height - in_y - 1) * inl_padd_width_bytes_and;
      char* achl_xor_dst = achl_xor_mask + (inl_padd_height - in_y - 1) * inl_padd_width_bytes;
      if(in_y < inl_cursor_height){

         int inl_bit = 0;
         for(int inl_byte = 0; inl_byte < inl_copy_bytes; inl_byte++){
            char chl_byte;
            CHECK_RETURN(dsl_input_dec.read_8(&chl_byte));

            int inl_bitmask = 0x80; 
            while(inl_bitmask >0){
               if(chl_byte & inl_bitmask){
                  // (CASE 1) 1 in VNC-bitmask => 0 in RDP-and-mask and the color of the cursor-pixels is the same.
                  achl_and_dst[inl_byte] &= ~inl_bitmask; // cursor pixels were copied before
               } else {
                  // (CASE 0) 0 in VNC-bitmask (transparent!) => 1 in RDP-and-mask and 0 in cursor-pixels of RDP.
                  memset(&achl_xor_dst[inl_bit * adsl_session->imc_bpp_rdp], 0, adsl_session->imc_bpp_rdp); // And-maks was completely set to 0xff before. 
               }
               inl_bitmask >>= 1; 
               inl_bit++;
            }
         }

         CHECK_RETURN(dsl_input_dec.skip(inl_skip_bytes));
         achl_and_dst -= inl_padd_width_bytes_and;
         achl_xor_dst -= inl_padd_width_bytes;
      } else {
         dsl_input_dec.skip(inl_parse_bytes);
      }
   }

   // Now create RDP-Command
/*#if !(defined HL_LINUX)
   dsd_sc_mpoi_pointer* ads_rdp_pointer = dsl_orderqueue.new_command<dsd_sc_mpoi_pointer>();
#else */
   ads_rdp_pointer = dsl_orderqueue.new_command<dsd_sc_mpoi_pointer>();
//#endif

   switch(adsl_session->imc_bpp_rdp){
      case 2: ads_rdp_pointer->usc_xor_bpp = 16; break;
      case 3: ads_rdp_pointer->usc_xor_bpp = 24; break;
      case 4: ads_rdp_pointer->usc_xor_bpp = 32; break;
      default:
         ERROR_MACRO_RDP(true, "Invalid RDP-colordeph: adsl_session->imc_bpp_rdp=%i", adsl_session->imc_bpp_rdp);
   }
   
   ads_rdp_pointer->dsc_color_ptr_attr.usc_cache_index     = 0;
   ads_rdp_pointer->dsc_color_ptr_attr.isc_hotspot_x       = adsl_session->dsc_fbu.usc_x;
   ads_rdp_pointer->dsc_color_ptr_attr.isc_hotspot_y       = adsl_session->dsc_fbu.usc_y;
   ads_rdp_pointer->dsc_color_ptr_attr.usc_width           = inl_padd_width;
   ads_rdp_pointer->dsc_color_ptr_attr.usc_height          = inl_padd_height;
   ads_rdp_pointer->dsc_color_ptr_attr.usc_length_and_mask = in_len_and_mask;
   ads_rdp_pointer->dsc_color_ptr_attr.usc_length_xor_mask = in_len_xor_mask;
   ads_rdp_pointer->dsc_color_ptr_attr.ac_xor_mask_data    = achl_xor_mask;
   ads_rdp_pointer->dsc_color_ptr_attr.ac_and_mask_data    = achl_and_mask;
   
   goto p_cl_fu_end_20;


//  ___          _    _                          _        
// |   \ ___ ___| |__| |_ ___ _ __   _ _ ___ ___(_)______ 
// | |) / -_|_-<| / /|  _/ _ \ '_ \ | '_/ -_|_-<| |_ / -_)
// |___/\___/__/|_\_\ \__\___/ .__/ |_| \___/__/|_/__\___|
//                           |_|                          
// 6.7.2 Desktop resize
  
p_cl_fu_dektopsize:
   
   DEF_DEBUG_PRINTF("A change size encoding has been sent by VNC server");
   
   //no bytes related to desktop re-size will follow
   
  
    DEF_DEBUG_PRINTF("desktop resize supported");
      
      
      //Modify screen width and height.
    adsl_session->usc_fb_width  = adsl_session->dsc_fbu.usc_width;
    adsl_session->usc_fb_height = adsl_session->dsc_fbu.usc_height;
      
      //set screen size change flag
    adsl_session->iec_state_rdp = ied_state_rdp_send_change_screen;
      
    //This type of encoding should always be sent as the last rectangle in an update
    // as stated in the RFB protocol 6.7.2 DesktopSize pseudo-encoding

    if(adsl_session->dsc_fbu.usc_no_rect != 1){
       ERROR_MACRO_RDP(true, "Desktop re-size VNC message, is not last rectangle in update. RFB protocol Error.");
    }

    
    //after that the screen-resize command is processed the rdp will send an (ied_clc_conn_fin) command
    //and a NON-Incremental Framebuffer update request is sent to the server.
    //There is no need to go through p_cl_fu_end_20 now 
    //as at p_cl_fu_end_20 an Incremental FramebufferUpdateRequest will be initailised. 
    //It is better to avoid new FramebufferUpdate Requests until the screen size change is completely executed
    

   adsl_session->dsc_fbu.usc_no_rect = 0;          
   adsl_session->iec_srfbc = ied_srfbc_conn;       /* session is connected    */
   goto p_ifunc_from_server_20;                    /* process the input       */


         
      


//  ___      _    ___     _              __  __           ___     _       _        
// / __| ___| |_ / __|___| |___ _  _ _ _|  \/  |__ _ _ __| __|_ _| |_ _ _(_)___ ___
// \__ \/ -_)  _| (__/ _ \ / _ \ || | '_| |\/| / _` | '_ \ _|| ' \  _| '_| / -_|_-<
// |___/\___|\__|\___\___/_\___/\_,_|_| |_|  |_\__,_| .__/___|_||_\__|_| |_\___/__/
//                                                  |_|                            
// 6.5.2 SetColourMapEntries

p_cl_scme_00: //start process the SetColourMapEntries Message

//  --------------+---------------+-------------------
//   No. of bytes | Type  [Value] | Description
//  --------------+---------------+-------------------       
//   1            | U8       1    | message-type
//   1            |               | padding
//   2            | U16           | first-colour
//   2            | U16           | number-of-colours
//  --------------+---------------+-------------------

   if(dsl_input_dec.get_bytes_left() < 0x6) // wait until the length is there
      goto p_proc_inp_70;

   CHECK_RETURN(dsl_input_dec.skip(2)); // skip message-type and padding (message-type was only peeked before)
   CHECK_RETURN(dsl_input_dec.read_16_be(&adsl_session->dsc_scme.inc_act_color));
   CHECK_RETURN(dsl_input_dec.read_16_be(&adsl_session->dsc_scme.inc_number_colors_send));

p_cl_scme_20:                                           /* running through the received data */
   if(dsl_input_dec.get_bytes_left() < adsl_session->dsc_scme.inc_number_colors_send * 2 * 3){ // wait until all the colors are there
      adsl_session->iec_srfbc = ied_srfbc_set_colormap_entries;   // come back here
      goto p_proc_inp_70;
   }

   if(m_create_colormap(&dsl_sdh_call_1) == false){
      ERROR_MACRO_RDP(true, "Error creating colormap"); // does not work. UUU todo
   }

   // Read the colors
   while(adsl_session->dsc_scme.inc_number_colors_send > 0){
      unsigned short usl_red, usl_green, usl_blue;
      CHECK_RETURN(dsl_input_dec.read_16_be(&usl_red));
      CHECK_RETURN(dsl_input_dec.read_16_be(&usl_green));
      CHECK_RETURN(dsl_input_dec.read_16_be(&usl_blue));

      if(adsl_session->dsc_scme.inc_act_color >= sizeof(umrc_rgbtable_default) / sizeof(uint32_t))
         adsl_session->dsc_scme.inc_act_color = 0;
      (*adsl_session->adsc_colormap_rfb)[adsl_session->dsc_scme.inc_act_color++] = (uint32_t)(
         ((usl_red   & 0xff00) << 8) |
         ((usl_green & 0xff00) << 0) |
         ((usl_blue  & 0xff00) >> 8));

      adsl_session->dsc_scme.inc_number_colors_send--;
   }

   // Now create converter
   if(m_create_converter_colormap(&dsl_sdh_call_1) == false){
      ERROR_MACRO_RDP(true, "Error creating converter width colormap. adsl_session->inc_coldep_rdp=%i adsl_session->imc_bpp_rfb=%i", 
         adsl_session->inc_coldep_rdp, adsl_session->imc_bpp_rfb);                          
   }

   adsl_session->iec_srfbc = ied_srfbc_conn;  
   goto p_cl_mt_00; 
            
//  ___                       ___     _  _____        _   
// / __| ___ _ ___ _____ _ _ / __|  _| ||_   _|____ _| |_ 
// \__ \/ -_) '_\ V / -_) '_| (_| || |  _|| |/ -_) \ /  _|
// |___/\___|_|  \_/\___|_|  \___\_,_|\__||_|\___/_\_\\__|
//
// 6.5.4 ServerCutText
            
p_cl_sct_00: //start processing the ServerCutText Message
       
//    +-----------------------------------------+
//    | RFB protocol 6.5.4 ServerCutText        |
//    +-----------------------------------------+

//    --------------+-------------------+--------------
//     No. of bytes | Type      [Value] | Description  
//    --------------+-------------------+--------------
//     1            | U8           3    | message-type 
//     3            |                   | padding      
//     4            | U32               | length       
//     length       | U8 array          | text         
//    --------------+-------------------+--------------

   if(dsl_input_dec.get_bytes_left() < 0x8) // wait until the length is there
      goto p_proc_inp_70;

   CHECK_RETURN(dsl_input_dec.skip(4)); // skip message-type and padding
   CHECK_RETURN(dsl_input_dec.read_32_be(&adsl_session->dsc_sct.inc_bytes_to_parse));

   //TODO: Get current clipboard limit.
   //Read either max bytes or else limit bytes to max clipboard bytes
   //if more bytes - read the Max clipboard bytes, then traverse skip rest. 
   //adsl_session->inc_max_size_clipbard
   
   
   
   // Make space in buffer
   if(adsl_session->boc_use_clipboard){
      // Add Zero terminated Char      
      adsl_session->inc_rdpclip_num_data = adsl_session->dsc_sct.inc_bytes_to_parse + 1;
      adsl_session->inc_rdpclip_num_skip = 0;
      
      //if send bytes are more than the maximum supported
      if (adsl_session->dsc_sct.inc_bytes_to_parse > adsl_session->inc_max_size_clipbard){
        adsl_session->inc_rdpclip_num_data = adsl_session->inc_max_size_clipbard + 1;
        adsl_session->inc_rdpclip_num_skip = 
            (adsl_session->dsc_sct.inc_bytes_to_parse - adsl_session->inc_max_size_clipbard);
             
        //limit number of bytes to read 
        adsl_session->dsc_sct.inc_bytes_to_parse -= adsl_session->inc_rdpclip_num_skip;
      
      }  
      
      adsl_session->dsc_rdpclip_buffer.ensure_elements(adsl_session->inc_rdpclip_num_data,
         m_callback_get_mem, m_callback_free_mem, &dsl_sdh_call_1);
      adsl_session->dsc_sct.achc_copy_to = adsl_session->dsc_rdpclip_buffer.get_data();
   }

p_cl_sct_20: //running through the bytes
   // Clipboard is turned off
   if(!adsl_session->boc_use_clipboard){
      int in_skip = dsl_input_dec.get_bytes_left();
      if(in_skip > adsl_session->dsc_sct.inc_bytes_to_parse)
         in_skip = adsl_session->dsc_sct.inc_bytes_to_parse;
      CHECK_RETURN(dsl_input_dec.skip(in_skip));
      adsl_session->dsc_sct.inc_bytes_to_parse -= in_skip;
      if(adsl_session->dsc_sct.inc_bytes_to_parse > 0){
         adsl_session->iec_srfbc = ied_srfbc_server_cut_text;       // come back here
         goto p_proc_inp_70;
      }
      adsl_session->iec_srfbc = ied_srfbc_conn;
      goto p_ifunc_from_server_20;
   }

//Read up to clipboard data to be used 

   if (adsl_session->dsc_sct.inc_bytes_to_parse > 0){

       // Clipboard is turned on -> Store the data, until RDP-client requests it. 
       int inl_copy = dsl_input_dec.get_bytes_left();
       if(inl_copy > adsl_session->dsc_sct.inc_bytes_to_parse)
           inl_copy = adsl_session->dsc_sct.inc_bytes_to_parse;
       CHECK_RETURN(dsl_input_dec.copy_to(adsl_session->dsc_sct.achc_copy_to, inl_copy));
       adsl_session->dsc_sct.inc_bytes_to_parse -= inl_copy;
       if(adsl_session->dsc_sct.inc_bytes_to_parse > 0){
           // needs more data
           adsl_session->dsc_sct.achc_copy_to += inl_copy; 
           adsl_session->iec_srfbc = ied_srfbc_server_cut_text;          // come back here
           goto p_proc_inp_70;
       }

       *(adsl_session->dsc_sct.achc_copy_to + inl_copy) = '\0'; //zero terminated charachter.
   }
   
   //skip unneeded bytes
   if (adsl_session->inc_rdpclip_num_skip > 0){
        int inl_skip = dsl_input_dec.get_bytes_left();
        if(inl_skip > adsl_session->inc_rdpclip_num_skip)
            inl_skip = adsl_session->inc_rdpclip_num_skip;
        
        CHECK_RETURN(dsl_input_dec.skip(inl_skip));
        adsl_session->inc_rdpclip_num_skip -= inl_skip;
        
        if(adsl_session->inc_rdpclip_num_skip > 0){
            //need more data
            adsl_session->iec_srfbc = ied_srfbc_server_cut_text;
            goto p_proc_inp_70;
        }
   }
   
   // Now tell RDP-Client about the new contents in the clipboard
   if(adsl_session->iec_state_rdp >= ied_state_rdp_finalized){
       //DEF_DEBUG_PRINTF("\nNew clipboard data available on server.\n"
        // "Sending CLIPBOARD FORMAT LIST PDU\n");

      dsd_format_list_entry dsc_format_text = {ied_cf_text, 0, NULL};
      if(m_rdpacc_clipboard_srvr_copy(&adsl_session->dsc_rdpacc_clipboard, &dsl_sdh_call_1, 1, &dsc_format_text) == false){
         M_SDH_PRINTF_I("m_rdpacc_clipboard_srvr_copy returned false. Clipboard is turned off!");
         adsl_session->boc_use_clipboard = false;
      }
   }

   adsl_session->iec_srfbc = ied_srfbc_conn;
   goto p_ifunc_from_server_20;

//     _                      _          _   _                _     _                                         _ 
//  __| |___ __ _ _ _  _ _ __| |_ ___ __| | (_)_ _  _ __ _  _| |_  (_)___  _ __ _ _ ___  __ ___ ______ ___ __| |
// / _` / -_) _| '_| || | '_ \  _/ -_) _` | | | ' \| '_ \ || |  _| | (_-< | '_ \ '_/ _ \/ _/ -_|_-<_-</ -_) _` |
// \__,_\___\__|_|  \_, | .__/\__\___\__,_| |_|_||_| .__/\_,_|\__| |_/__/ | .__/_| \___/\__\___/__/__/\___\__,_|
//                  |__/|_|                        |_|                    |_|                                   

p_proc_inp_70:                           /* the decrypted input has been processed */
   if(adsl_session->boc_do_aes){
      if(!dsl_input_dec.empty()){
         // copy data, if there is still unprocessed decrypted data
         adsl_session->inc_len_mem_data = dsl_input_dec.get_bytes_left();

         // Get memory, if necessary
         bool bol_delete_old_mem_later = false;
         char* ach_old_memory;
         if(adsl_session->inc_size_mem < adsl_session->inc_len_mem_data){
            // Memorize old memory, to delete it later
            ach_old_memory = adsl_session->achc_mem_data;
            bol_delete_old_mem_later = (adsl_session->inc_size_mem > 0);
            if(adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld, DEF_AUX_MEMGET,
               &adsl_session->achc_mem_data, adsl_session->inc_len_mem_data ) == FALSE){
                  ERROR_MACRO_RDP(true, "Requested 0x%x bytes from WSP and WSP returned false.", adsl_session->inc_len_mem_data);
            }
            adsl_session->inc_size_mem = adsl_session->inc_len_mem_data;
         }

         // Copy data
         dsl_input_dec.copy_to(adsl_session->achc_mem_data, adsl_session->inc_len_mem_data); 

         // Delete old memory, if it was replaced
         if(bol_delete_old_mem_later){
            if(adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld, DEF_AUX_MEMFREE, &ach_old_memory, 0 ) == FALSE){
               ERROR_MACRO_RDP(true, "Error returning memory to WSP. ach_old_memory=%p", ach_old_memory);
            }
         }
      }

      // Skip AES-tag
      dsl_input.skip(INS_AES_TAG_LEN);
      if(bol_turnoff_aes_encryption_after_sending)
         goto p_proc_inp_90;
	  }

   if(!dsl_input.empty())
      goto p_ifunc_from_server;

} // end of parsing decrypted input
} // end of parsing unencrypted input


//                          _   _                _     _                                         _ 
//  _ _  ___ _ _ _ __  __ _| | (_)_ _  _ __ _  _| |_  (_)___  _ __ _ _ ___  __ ___ ______ ___ __| |
// | ' \/ _ \ '_| '  \/ _` | | | | ' \| '_ \ || |  _| | (_-< | '_ \ '_/ _ \/ _/ -_|_-<_-</ -_) _` |
// |_||_\___/_| |_|_|_\__,_|_| |_|_||_| .__/\_,_|\__| |_/__/ | .__/_| \___/\__\___/__/__/\___\__,_|
//                                    |_|                    |_|                                   

p_proc_inp_80:                           /* the input has been processed */

if(!dsl_orderqueue.is_empty())
goto p_rdpserv_40;

// Do we have to send the change-screen-command now?
// This has to be done with an empty orderqueue, as change_screen reinits the fonts, and there
// could be still drawing-command for the splash-sceen. (For example the ServerInit-message
if(adsl_session->iec_state_rdp == ied_state_rdp_send_change_screen) {   /* RFB-Server init received */
    // Get the actual time
    time_t dsl_time; 
    bol1 = adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld, DEF_AUX_GET_TIME, &dsl_time, sizeof(time_t));
    if (bol1 == FALSE){
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E auxiliary call with DEF_AUX_GET_TIME parameter Failed.",
            __LINE__ );
        return;
    }
    if(adsl_session->ilc_wait_until > dsl_time){
        bol1 = adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld, DEF_AUX_TIMER1_SET, NULL, (adsl_session->ilc_wait_until - dsl_time) * 1000);
        if (bol1 == FALSE){
            adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
            m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E auxiliary call with DEF_AUX_TIMER1_SET parameter Failed.",
                __LINE__ );
            return;
        }
        adsl_session->inc_show_splash_screen = 0;
        return;
    }
    adsl_session->ilc_wait_until = 0;
    goto p_rdpserv_00;                                                   /* RDP server send change screen */
   }

   if (adsp_hl_clib_1->boc_eof_server) {    /* End-of-File Server      */
        adsl_session->dsc_crdps_1.boc_eof_client = TRUE;  /* End-of-File Client */
        // JB 19.03.12: This happens with dynamic connections, when the server does not accept the connection. In my example, the trial-license was not valid any more. 
        // This will probably not be needed any more, once Joeseph changes the behavior (start VNC before RDP...). 
        if(adsl_session->dsc_crdps_1.inc_func == DEF_IFUNC_START){
           adsl_session->dsc_crdps_1.adsc_conf = &dss_conf_rdpserv_1;  /* configuration RDP Server 1 */
           adsl_session->dsc_crdps_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* pointer to subroutine */
           // JB 05.10.11: call RDP-Server with DEF_IFUNC_START now. If there is already input, we have a problem otherwise. (Problem with dynamic connection...)
           GET_MORE_WORKAREA;
           adsl_session->dsc_crdps_1.achc_work_area = achl_work_1;
           adsl_session->dsc_crdps_1.inc_len_work_area = CONVERT_W64_TO_INT(achl_work_2 - achl_work_1);
           //1st call of rdpserv, must contain NO input data/commands
           m_rdpserv_1( &adsl_session->dsc_crdps_1 ); 
           adsl_session->dsc_crdps_1.inc_func = DEF_IFUNC_REFLECT;
        }
        goto p_rdpserv_40;                     /* call the RDP server     */
    }


   // Did an error occur? Then don't send anything to VNC-Server
   if(adsl_session->boc_rfb_error){
      adsp_hl_clib_1->adsc_gai1_out_to_server = NULL;
      return; 
   }

   switch(adsl_session->inc_fbu_behavior){
      case 0: // Always send the framebuffer update request, if boc_send_update_request = true
         if(adsl_session->boc_send_update_request){
            SEND_FRAMEBUFFER_UPDATE_REQUEST(TRUE);
            adsl_session->boc_send_update_request = false;
         }
         break;
      case 1: // Only send the framebuffer update request, if we can send
         if(adsl_session->boc_send_update_request){
            if(adsp_hl_clib_1->boc_send_client_blocked){
               adsp_hl_clib_1->boc_notify_send_client_possible = TRUE;
               break; 
            }
            SEND_FRAMEBUFFER_UPDATE_REQUEST(TRUE);
            adsl_session->boc_send_update_request = false;
         }
         break;
      case 2: // Always send the framebuffer update request. Attention: Only for debug-reasons. 
         if(adsl_session->iec_state_rdp == ied_state_rdp_finalized_change_screen){
            SEND_FRAMEBUFFER_UPDATE_REQUEST(TRUE);
         }
         break;
      default: 
         ERROR_MACRO_RDP(true, "Unknown value in configuration-property fbu-behavior: 0x%x", adsl_session->inc_fbu_behavior);
   }

//    _   ___ ___                               _   _          
//   /_\ | __/ __|___ ___ _ _  __ _ _ _  _ _ __| |_(_)___ _ _  
//  / _ \| _|\__ \___/ -_) ' \/ _| '_| || | '_ \  _| / _ \ ' \ 
// /_/ \_\___|___/   \___|_||_\__|_|  \_, | .__/\__|_\___/_||_|
//                                    |__/|_|                  
p_proc_inp_90:

   // Is the AES-encryption on?
   if(!adsl_session->boc_do_aes)
      return;

   // AES-encryption
   if(adsp_hl_clib_1->adsc_gai1_out_to_server != NULL){

      // Hold unencrypted data in ads_gather
      dsd_gather_i_1* ads_gather = adsp_hl_clib_1->adsc_gai1_out_to_server;
      adsp_hl_clib_1->adsc_gai1_out_to_server = NULL;
      adsl_gai1_out_server = NULL;

      int inl_encrypt = m_gather_count(ads_gather);
      while(inl_encrypt){
         int inl_encrypt_now = inl_encrypt;
         // Real VNC Enterprise edition always encrypts 6600 bytes
         // Error otherwise, rising in clipboard. 
         if(inl_encrypt_now > 6600)
            inl_encrypt_now = 6600;
         inl_encrypt-= inl_encrypt_now;

         // Write length
         GET_VNC_OUTPUT_GATHER(2);
         achl2 = achl1;
         write_16_be(&achl2, inl_encrypt_now);

         // Init message
         achl2 = chrl_work1;
         memset(achl2, 0, 0x10);
         write_64_le(&achl2, adsl_session->ilc_aes_enc_counter);
         adsl_session->ilc_aes_enc_counter++;
         m_eax_init_msg((unsigned char*) chrl_work1, 0x10, adsl_session->adsc_eax_enc);
         // Authentication header       
         m_eax_update_header_omac((unsigned char*) achl1, 2, adsl_session->adsc_eax_enc);

         // Encrypt
         while(inl_encrypt_now > 0){
            dsd_gather_i_1* ads_this_gather = ads_gather;
//#if !(defined HL_LINUX)
            int inl_this_gather = (UINT_PTR)(ads_this_gather->achc_ginp_end - ads_this_gather->achc_ginp_cur);
//#else
//            int inl_this_gather = (unsigned int)(ads_this_gather->achc_ginp_end - ads_this_gather->achc_ginp_cur);
//#endif
            if(inl_this_gather <= inl_encrypt_now){
               // encrypt whole gather
               m_eax_encrypt((unsigned char*) ads_this_gather->achc_ginp_cur, inl_this_gather, adsl_session->adsc_eax_enc);
               inl_encrypt_now -= inl_this_gather;
               ads_gather = ads_gather->adsc_next;
               ads_this_gather->adsc_next = NULL;
               ADD_GATHER_TO_VNC_OUTPUT(ads_this_gather);
               continue; 
            } 

            // Only encrypt part of gather, inl_encrypt_now bytes
            GET_GATHER_ON_WA;
            adsl_gai1_w1->achc_ginp_cur = ads_this_gather->achc_ginp_cur;
            adsl_gai1_w1->achc_ginp_end = adsl_gai1_w1->achc_ginp_cur + inl_encrypt_now;
            adsl_gai1_w1->adsc_next = NULL;
            ADD_GATHER_TO_VNC_OUTPUT(adsl_gai1_w1);
            ads_gather->achc_ginp_cur += inl_encrypt_now;

            m_eax_encrypt((unsigned char*) adsl_gai1_w1->achc_ginp_cur, inl_encrypt_now, adsl_session->adsc_eax_enc);
            break;
         }

         // Commute tag
         GET_VNC_OUTPUT_GATHER(INS_AES_TAG_LEN);
         m_eax_generate_tag((unsigned char*) achl1, INS_AES_TAG_LEN, adsl_session->adsc_eax_enc);
      }
   }

   if(bol_turnoff_aes_encryption_after_sending == TRUE){
      adsl_session->boc_do_aes = FALSE;
      // If there is no authentication, the authentication response is normaly already there. 
      goto p_ifunc_from_server;
   }

   return;

//  _______ ____    _____ ______ _______      ________ _____  
// |__   __/ __ \  / ____|  ____|  __ \ \    / /  ____|  __ \ 
//    | | | |  | || (___ | |__  | |__) \ \  / /| |__  | |__) |
//    | | | |  | | \___ \|  __| |  _  / \ \/ / |  __| |  _  / 
//    | | | |__| | ____) | |____| | \ \  \  /  | |____| | \ \ 
//    |_|  \____/ |_____/|______|_|  \_\  \/   |______|_|  \_\
//            ______                                          
//           |______|                                         

p_ifunc_to_server:

    if(adsl_session->dsc_crdps_1.inc_func == DEF_IFUNC_START){
       adsl_session->dsc_crdps_1.adsc_conf = &dss_conf_rdpserv_1;  /* configuration RDP Server 1 */
       adsl_session->dsc_crdps_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* pointer to subroutine */
       // JB 05.10.11: call RDP-Server with DEF_IFUNC_START now. If there is already input, we have a problem otherwise. (Problem with dynamic connection...)
       GET_MORE_WORKAREA;
       adsl_session->dsc_crdps_1.achc_work_area = achl_work_1;
       adsl_session->dsc_crdps_1.inc_len_work_area = CONVERT_W64_TO_INT(achl_work_2 - achl_work_1);
       //1st call of rdpserv, must contain NO input data/commands
       m_rdpserv_1( &adsl_session->dsc_crdps_1 ); 
       adsl_session->dsc_crdps_1.inc_func = DEF_IFUNC_REFLECT;
    }

   if(m_gather_is_empty(adsp_hl_clib_1->adsc_gather_i_1_in))
      goto p_proc_inp_80;
   adsl_session->dsc_crdps_1.adsc_gather_i_1_in = adsp_hl_clib_1->adsc_gather_i_1_in;
   goto p_rdpserv_40;                     /* call the RDP server     */

p_rdpserv_00:                            /* RDP server send a change screen   */
   //DEF_DEBUG_PRINTF("rdp_coldep = " << adsl_session->dsc_crdps_1.adsc_rdp_co->imc_cl_coldep);
   if(adsl_session->iec_state_rdp != ied_state_rdp_send_change_screen)
      ERROR_MACRO("Wrong state of RDP-session at this point! adsl_session->iec_state_rdp = 0x%x", adsl_session->iec_state_rdp);
   adsl_session->iec_state_rdp = ied_state_rdp_finalized; // Only needed in case of an error. 
   M_SDH_PRINTF_T( "ied_clc_capabilities coldep=%d supported=0X%X early-cf=0X%X.",
      adsl_session->dsc_crdps_1.adsc_rdp_co->imc_cl_coldep,
      adsl_session->dsc_crdps_1.adsc_rdp_co->usc_cl_supported_color_depth,
      adsl_session->dsc_crdps_1.adsc_rdp_co->usc_cl_early_capability_flag );

   // Change the screen to screen size of RFB
   // Note: From here on the initialisation-screen is not shown any more. Initialization-messages cannot be printed out any more. 
/*#if !(defined HL_LINUX)
   dsd_change_screen* ads_change_screen  = dsl_orderqueue.new_command<dsd_change_screen>();
#else */
   ads_change_screen  = dsl_orderqueue.new_command<dsd_change_screen>();
//#endif
   ads_change_screen->imc_dim_x  = adsl_session->usc_fb_width;  /* framebuffer-width */
   ads_change_screen->imc_dim_y  = adsl_session->usc_fb_height;  /* framebuffer-height */
   ads_change_screen->imc_coldep = adsl_session->dsc_crdps_1.adsc_rdp_co->imc_cl_coldep;
   if((adsl_session->dsc_crdps_1.adsc_rdp_co->imc_cl_coldep == 24) && 
      (adsl_session->dsc_crdps_1.adsc_rdp_co->usc_cl_supported_color_depth & RNS_UD_32BPP_SUPPORT) && 
      (adsl_session->dsc_crdps_1.adsc_rdp_co->usc_cl_early_capability_flag & RNS_UD_CS_WANT_32BPP_SESSION)){
      ads_change_screen->imc_coldep = 32;
   }

   /* reduce number of bits per pixel of RDP if less bits on RFB       */
   if((adsl_session->imc_bpp_rfb <= 2) && (ads_change_screen->imc_coldep > 16)) {      /* bytes per pixel RFB     */
      ads_change_screen->imc_coldep = 16;
   }

   if(ads_change_screen->imc_coldep <= 8) {
      dsl_orderqueue.release_orders();
      ERROR_MACRO_RDP(true, "RDP-Accelerator does not support colordeph %i", ads_change_screen->imc_coldep);
   } else if (ads_change_screen->imc_coldep <= 16) {
      adsl_session->imc_bpp_rdp = 2;              /* bytes per pixel RDP     */
   } else if (ads_change_screen->imc_coldep <= 24) {
      adsl_session->imc_bpp_rdp = 3;              /* bytes per pixel RDP     */
   } else if (ads_change_screen->imc_coldep <= 32) {
      adsl_session->imc_bpp_rdp = 4;              /* bytes per pixel RDP     */
   } else {
      dsl_orderqueue.release_orders();
      ERROR_MACRO_RDP(true, "RDP-Accelerator does not support colordeph %i", ads_change_screen->imc_coldep);
   }
   adsl_session->inc_coldep_rdp = ads_change_screen->imc_coldep;
   adsl_session->inc_scanline_rdp_screen = adsl_session->imc_bpp_rdp * adsl_session->usc_fb_width;
    
   //Set the rdp colour model
   //DEF_DEBUG_PRINTF("Setting RDP Colour Model");
   try{  // JB: the following constructors don't throw, but for the case, something changes in the future, I include the try-catch-block      
      switch (adsl_session->inc_coldep_rdp) {
      case 15:
         adsl_session->adsc_colormodel_rdp = &dss_colormodel_15_16;
         break;
      case 16:
         adsl_session->adsc_colormodel_rdp = &dss_colormodel_16_16;
         break;
      case 24:
         adsl_session->adsc_colormodel_rdp = &dss_colormodel_24_24;
         break;
      case 32:
         adsl_session->adsc_colormodel_rdp = &dss_colormodel_32_32;
         break;
      default:
         ERROR_MACRO_RDP(true, "create pixel-converter invalid colour-depth %d.", adsl_session->inc_coldep_rdp);
      }
   } catch (std::exception dsl_e){
      dsl_orderqueue.release_orders();
      ERROR_MACRO_RDP(true, "Error creating RDP-colormodel imc_coldep=%i, %s.", adsl_session->inc_coldep_rdp, dsl_e.what());
   }

   //if true_colour_flag is Zero : colour map is to be used
   if (adsl_session->dsc_rfb_pixel_format.chc_true_colour_flag){
      dsd_rfb_pixel_format* adsc_rfb_fp = &adsl_session->dsc_rfb_pixel_format;
      uint32_t uml_rmask = adsc_rfb_fp->usc_red_max   << adsc_rfb_fp->chc_red_shift;
      uint32_t uml_gmask = adsc_rfb_fp->usc_green_max << adsc_rfb_fp->chc_green_shift;
      uint32_t uml_bmask = adsc_rfb_fp->usc_blue_max  << adsc_rfb_fp->chc_blue_shift;
      en_endianess ds_endian = adsc_rfb_fp->chc_big_endian_flag ? ie_endian_big : ie_endian_little;
      try{
         c_colormodel dsl_colormodel_rfb(adsc_rfb_fp->chc_depth, adsc_rfb_fp->chc_bits_per_pixel,
                                                        uml_rmask, uml_gmask, uml_bmask, 0, ds_endian);
         m_create_converter(adsl_session, dsl_colormodel_rfb);
      } catch (std::exception dsl_e){
         dsl_orderqueue.release_orders();
         ERROR_MACRO_RDP(true, "Error creating converter. adsl_session->inc_coldep_rdp=%i adsl_session->imc_bpp_rfb=%i", 
            adsl_session->inc_coldep_rdp, adsl_session->imc_bpp_rfb);                          
      }
      // Make a converter for CPIXEL for ZRLE-encoding
      // @see: Definition of CPIXEL, 6.6.5 ZRLE encoding
      // Exception: width Ultra-VNC, CPIXEL also has 3 bytes, if deph == 32!!!
      if(adsc_rfb_fp->chc_bits_per_pixel == 32){
         try{
            if(((uml_rmask | uml_gmask | uml_bmask) & 0xff000000) == 0){
               c_colormodel dsl_colormodel_c_pixel_rfb(
                  24, 24, uml_rmask, uml_gmask, uml_bmask, 0, ds_endian);
               adsl_session->adsc_cpixel_converter = c_converter_factory<dsd_pixel_converter_config>::create_converter(                              
                  dsl_colormodel_c_pixel_rfb, *adsl_session->adsc_colormodel_rdp, adsl_session->dsc_pixel_converter_store); 
            } else if(((uml_rmask | uml_gmask | uml_bmask) & 0xff) == 0){
               c_colormodel dsl_colormodel_c_pixel_rfb(
                  24, 24, uml_rmask >> 8, uml_gmask >> 8, uml_bmask >> 8, 0, ds_endian);
               adsl_session->adsc_cpixel_converter = c_converter_factory<dsd_pixel_converter_config>::create_converter(                              
                  dsl_colormodel_c_pixel_rfb, *adsl_session->adsc_colormodel_rdp, adsl_session->dsc_pixel_converter_store); 
            }
         } catch (std::exception dsl_e){
            dsl_orderqueue.release_orders();
            ERROR_MACRO_RDP(true, "Error creating converter for CPIXEL. adsl_session->inc_coldep_rdp=%i adsl_session->imc_bpp_rfb=%i", 
               adsl_session->inc_coldep_rdp, adsl_session->imc_bpp_rfb);                          
         }
      } else {
         adsl_session->adsc_cpixel_converter = adsl_session->adsc_pixel_converter; // CPIXEL is the same as PIXEL, if not the following case: 
      }
   } else {
      if(m_create_colormap(&dsl_sdh_call_1) == false){
         dsl_orderqueue.release_orders();
         ERROR_MACRO_RDP(true, "Error creating colormap");
      }
      if(m_create_converter_colormap(&dsl_sdh_call_1) == false){
         dsl_orderqueue.release_orders();
         ERROR_MACRO_RDP(true, "Error creating converter width colormap. adsl_session->inc_coldep_rdp=%i adsl_session->imc_bpp_rfb=%i", 
            adsl_session->inc_coldep_rdp, adsl_session->imc_bpp_rfb);                          
      }
      adsl_session->adsc_cpixel_converter = adsl_session->adsc_pixel_converter; // CPIXEL is the same as PIXEL, if not the following case: 
   } //end if (adsl_session->dsc_rfb_pixel_format.chc_true_colour_flag)
  
#ifdef DEBUG_110620_01
    dsl_out_dap.dsc_d_act_pdu.imc_coldep = 15;
#endif
   if(adsl_session->dsc_crdps_1.ac_screen_buffer != NULL){
      if(adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld, DEF_AUX_MEMFREE, &adsl_session->dsc_crdps_1.ac_screen_buffer, 0) == FALSE)
         ERROR_MACRO_RDP(true, "Aux function for DEF_AUX_MEMFREE did return FALSE.");
    }

    iml1 = adsl_session->usc_fb_width
         * adsl_session->usc_fb_height
         * ((adsl_session->inc_coldep_rdp + 7) / 8);
    bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
        DEF_AUX_MEMGET,
        &adsl_session->dsc_crdps_1.ac_screen_buffer,
        iml1 );
   if (bol1 == FALSE) {
      dsl_orderqueue.release_orders();
      ERROR_MACRO_RDP(true, "Aux function for DEF_AUX_MEMGET did return FALSE. Requested memory: 0x%x bytes.", iml1);
   }
   ads_change_screen->ac_screen_buffer = adsl_session->dsc_crdps_1.ac_screen_buffer;
   memset( adsl_session->dsc_crdps_1.ac_screen_buffer, 0, iml1 );
   adsl_session->iec_state_rdp = ied_state_rdp_change_screen_is_send;
    
   // Get rectangles for screen changes
   adsl_session->inc_num_fbu_changes = (adsl_session->usc_fb_width / IMS_SCREEN_UPDATE_WIDTH) + 1;
   if(!adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld, DEF_AUX_MEMGET, &adsl_session->adsc_fbu_changes, adsl_session->inc_num_fbu_changes * sizeof(dsd_rectrb)))
      ERROR_MACRO_RDP(true, "Aux function for DEF_AUX_MEMGET did return FALSE. Requested memory: 0x%x bytes.", iml1 * sizeof(dsd_rectrb));

   // Init font again (necessary, after a change screen)
   // We are doing it here, to be able to do the ERROR_MACRO_RDP above
   memset(&adsl_session->dsc_rdpacc_font, 0, sizeof(dsd_font));
   adsl_session->dsc_rdpacc_font.amc_cs_getglyph = amc_getglyphpattern_tahoma;
   dsl_orderqueue.new_command<dsd_sc_order_new_font>()->adsc_font = &adsl_session->dsc_rdpacc_font;

    /* send to RFB server the client messages                           */
    
    //DEF_DEBUG_PRINTF("Pixel Format is sent to the server");

    // 6.4.1 SetPixelFormat
    GET_VNC_OUTPUT_GATHER(1 + 3 + 16);
    memset(adsl_gai1_out_1->achc_ginp_cur, 0, 1+ 3); // Message-type + padding
    achl1+=4;
    write_8(&achl1, adsl_session->dsc_rfb_pixel_format.chc_bits_per_pixel);
    write_8(&achl1, adsl_session->dsc_rfb_pixel_format.chc_depth);
    write_8(&achl1, adsl_session->dsc_rfb_pixel_format.chc_big_endian_flag);
    write_8(&achl1, adsl_session->dsc_rfb_pixel_format.chc_true_colour_flag);
    write_16_be(&achl1, adsl_session->dsc_rfb_pixel_format.usc_red_max);
    write_16_be(&achl1, adsl_session->dsc_rfb_pixel_format.usc_green_max);
    write_16_be(&achl1, adsl_session->dsc_rfb_pixel_format.usc_blue_max);
    write_8(&achl1, adsl_session->dsc_rfb_pixel_format.chc_red_shift);
    write_8(&achl1, adsl_session->dsc_rfb_pixel_format.chc_green_shift);
    write_8(&achl1, adsl_session->dsc_rfb_pixel_format.chc_blue_shift);
    memset(achl1, 0, 3); // Padding

    //memcpy(adsl_gai1_out_1->achc_ginp_cur + 4, 
    //    &adsl_session->dsc_rfb_pixel_format, sizeof(adsl_session->dsc_rfb_pixel_format) );

    // 6.4.2 SetEncodings

    // Number of encodings 
    iml1 = 1;   //Counting Raw 
#ifdef ENABLE_COPYRECT
    iml1++;
#endif
#ifdef ENABLE_RRE
    iml1++;
#endif
#ifdef ENABLE_ZLIB
    iml1++;
#endif
#ifdef ENABLE_ZRLE
    iml1++;
#endif
   if(adsl_session->dsc_crdps_1.adsc_rdp_co->dsc_caps.dsc_bitmap.boc_desktop_resize_flag){
      DEF_DEBUG_PRINTF("@Line " << __LINE__ << ": boc_desktop_resize_flag is TRUE");
      iml1++;
   }else{
      DEF_DEBUG_PRINTF("@Line " << __LINE__ << ": boc_desktop_resize_flag is FALSE");
   }

    if(adsl_session->boc_cursor_encoding)
      iml1++;
    // Get gather
    GET_VNC_OUTPUT_GATHER(1 + 1 + 2 + 4 * iml1);
    achl1 = adsl_gai1_out_1->achc_ginp_cur;

    *achl1++ = 2;           // Message-type
    *achl1++ = 0;           // padding
    write_16_be(&achl1, iml1);  // Number of encodings
    if(adsl_session->boc_cursor_encoding)
      write_32_be(&achl1, rfbPseudoEncodingCursor); //Pseudo Cursor Encoding
    // JB 15.03.12: Oder of encodings says, which encodings are preferred. We want to prefer ZRLE
#ifdef ENABLE_ZRLE
    write_32_be(&achl1, rfbEncodingZRLE);  // encoding copy rect
#endif
#ifdef ENABLE_COPYRECT
    write_32_be(&achl1, rfbEncodingCopyRect);  // encoding copy rect
#endif
#ifdef ENABLE_RRE
    write_32_be(&achl1, rfbEncodingRRE);  // encoding RRE
#endif
#ifdef ENABLE_ZLIB
    write_32_be(&achl1, rfbEncodingZlib);  // encoding zlib
   if(adsl_session->dsc_crdps_1.adsc_rdp_co->dsc_caps.dsc_bitmap.boc_desktop_resize_flag){
      write_32_be(&achl1, rfbPseudoEncodingDesktopSize);
   }
#endif
    write_32_be(&achl1, rfbEncodingRaw);  // encoding raw

p_rdpserv_40:                            /* call the RDP server     */
   adsl_session->dsc_crdps_1.adsc_sc_co1_ch = dsl_orderqueue.release_orders();
   
p_rdpserv_60:                            /* call the RDP server again */
   memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
   bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
      DEF_AUX_GET_WORKAREA,  /* get additional work area */
      &dsl_aux_get_workarea,
      sizeof(struct dsd_aux_get_workarea) );
   if (bol1 == FALSE){
      // If there is no Workarea, we cannot user ERROR_MACRO_RDP, as the RDP-Accelerator does not work any more
      ERROR_MACRO("Aux-function returned false for DEF_AUX_GET_WORKAREA.");
   }

   adsl_session->dsc_crdps_1.achc_work_area = dsl_aux_get_workarea.achc_work_area;
   adsl_session->dsc_crdps_1.inc_len_work_area = dsl_aux_get_workarea.imc_len_work_area;
   adsl_session->dsc_crdps_1.adsc_gather_i_1_out = NULL;
   adsl_session->dsc_crdps_1.boc_callagain = FALSE;  /* reset call again    */

   
   
   //call rdpacc
   m_rdpserv_1( &adsl_session->dsc_crdps_1 ); //<===================================================
    
   if (adsl_session->dsc_crdps_1.inc_return != DEF_IRET_NORMAL) {  /* o.k. returned */
      // If there is an RDP-Error, we can't use ERROR_MACRO_RDP, as RDP does not work any more!
      ERROR_MACRO("m_rdpserv_1 error, adsl_session->dsc_crdps_1.inc_return=%i", adsl_session->dsc_crdps_1.inc_return);
   } 
    bol_cont = FALSE;                        /* continue call RDP server */
   while (adsl_session->dsc_crdps_1.adsc_cl_co1_ch) {  /* chain of command from client, output */
#define ADSL_CL_CO1 adsl_session->dsc_crdps_1.adsc_cl_co1_ch
      
      M_SDH_PRINTF_T( "ADSL_CL_CO1->iec_cl_command=%d.", ADSL_CL_CO1->iec_cl_command );

         switch (ADSL_CL_CO1->iec_cl_command) {
            case ied_clc_capabilities: {           /* received capabilities   */
               //DEF_DEBUG_PRINTF("\nReceived capabilities");
               // Change state
               if(adsl_session->iec_state_rdp != ied_state_rdp_start)
                  ERROR_MACRO("Wrong state of RDP-session at this point! adsl_session->iec_state_rdp = 0x%x", adsl_session->iec_state_rdp);
               adsl_session->iec_state_rdp = ied_state_rdp_received_capabilities;
        
               // Send a dummy demand active PDU
               
               adsl_session->usc_fb_width   = adsl_session->dsc_crdps_1.adsc_rdp_co->imc_dim_x;
               adsl_session->usc_fb_height  = adsl_session->dsc_crdps_1.adsc_rdp_co->imc_dim_y;
               adsl_session->inc_coldep_rdp = 16;
               adsl_session->imc_bpp_rdp = 2;              /* bytes per pixel RDP     */
               if(adsl_session->dsc_crdps_1.adsc_rdp_co->imc_cl_coldep == 24){
                  if((adsl_session->dsc_crdps_1.adsc_rdp_co->usc_cl_supported_color_depth & RNS_UD_32BPP_SUPPORT) && 
                     (adsl_session->dsc_crdps_1.adsc_rdp_co->usc_cl_early_capability_flag & RNS_UD_CS_WANT_32BPP_SESSION)) {
                     adsl_session->inc_coldep_rdp = 32;
                     adsl_session->imc_bpp_rdp = 4;              /* bytes per pixel RDP     */
                  } else {
                     adsl_session->inc_coldep_rdp = 24;
                     adsl_session->imc_bpp_rdp = 3;              /* bytes per pixel RDP     */
                  }
               }
               adsl_session->inc_scanline_rdp_screen = adsl_session->imc_bpp_rdp * adsl_session->usc_fb_width;


               dsd_d_act_pdu* ads_d_act_pdu = dsl_orderqueue.new_command<dsd_d_act_pdu>();
               ads_d_act_pdu->imc_dim_x  = adsl_session->usc_fb_width;  /* framebuffer-width */
               ads_d_act_pdu->imc_dim_y  = adsl_session->usc_fb_height;  /* framebuffer-height */
               ads_d_act_pdu->imc_coldep = adsl_session->inc_coldep_rdp;
               
               iml1 = adsl_session->usc_fb_width * adsl_session->usc_fb_height * ((adsl_session->inc_coldep_rdp + 7) / 8);
               bol1 = adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld, DEF_AUX_MEMGET, &adsl_session->dsc_crdps_1.ac_screen_buffer, iml1);
               if (bol1 == FALSE)
                  ERROR_MACRO_RDP(true, "Aux function for DEF_AUX_MEMGET did return FALSE. Requested memory: 0x%x bytes.", iml1);
            } break;
    
            case ied_clc_conn_fin: {              /* Connection Finalization done */
               M_SDH_PRINTF_T( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-T ied_clc_conn_fin / Connection Finalization done", __LINE__ );

               switch(adsl_session->iec_state_rdp){
                  case ied_state_rdp_received_capabilities: {

                     // 1st Finalisation: RDP is active now. Error messages are possible. 
                     adsl_session->iec_state_rdp = ied_state_rdp_finalized;

                     // Init font
                     adsl_session->dsc_rdpacc_font.amc_cs_getglyph = amc_getglyphpattern_tahoma;
                     dsl_orderqueue.new_command<dsd_sc_order_new_font>()->adsc_font = &adsl_session->dsc_rdpacc_font;

                     // Make background color
/*#if !(defined HL_LINUX)
                     dsd_sc_order_opaquerect* ads_opaquerect  = dsl_orderqueue.new_command<dsd_sc_order_opaquerect>();
#else */
                     ads_opaquerect  = dsl_orderqueue.new_command<dsd_sc_order_opaquerect>();
//#endif                     
                     ads_opaquerect->dsc_rectangle.isc_left   = 0;
                     ads_opaquerect->dsc_rectangle.isc_top    = 0;
                     ads_opaquerect->dsc_rectangle.isc_width  = adsl_session->usc_fb_width;
                     ads_opaquerect->dsc_rectangle.isc_height = adsl_session->usc_fb_height;
                     ads_opaquerect->umc_color                = get_rdpcolor(adsl_session->inc_coldep_rdp, 0x1d, 0x5f, 0x7a);
                     ads_opaquerect->imc_no_color_bytes       = 3;           
                     ads_opaquerect->boc_has_bounds           = FALSE;
                     ads_opaquerect->boc_update_scrbuf        = FALSE;

                     // Send init screen 
                     m_rdp_send_splash_screen(&dsl_sdh_call_1);

                     m_rdp_printf(&dsl_sdh_call_1, "Starting HOB RD VPN VNC-Bridge V %s\n"
                        "---------------------------------------------------------------", VERSION_THIS_FILE);

                     // Initialize keyboard
                     adsl_session->bo_return_control_characters = false;
                
                     iml1 = adsl_session->dsc_crdps_1.adsc_rdp_co->imc_keyboard_layout;
                     if(adsl_session->boc_server_maps_keys != FALSE){
                        if(adsl_session->boc_server_maps_capslock != FALSE){
                           iml1 = 0x409;
                        } else {
                           dsl_sdh_call_1.adsc_ctrl_1->dsd_keyboard_capslock_behaviour = m_keyboardmapping_get_keyboard(iml1);
                           iml1 = 0x1; // Hob special keyboard: capslock = shift. 
                        }
                     }

                     if(m_keyboardmapping_init(&dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping, iml1, adsl_session->bo_return_control_characters)!= FALSE){
                        M_SDH_PRINTF_I("V1.1 " __DATE__ " Keyboard layout set: 0x%x server-maps-keys=%s server-maps-capslock=%s",
                           dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping.adsc_keyboard->in_id,
                           adsl_session->boc_server_maps_keys     ? "YES" : "NO",
                           adsl_session->boc_server_maps_capslock ? "YES" : "NO");

                        m_rdp_printf(&dsl_sdh_call_1, "Initialization of keyboard layout 0x%x%s%s (%s) succeeded. ", 
                           adsl_session->ads_keyboardmapping.adsc_keyboard->in_id,
                           adsl_session->boc_server_maps_keys     ? ", server maps keys" : "",
                           adsl_session->boc_server_maps_capslock ? ", server maps capslock" : "",
                           adsl_session->ads_keyboardmapping.adsc_keyboard->ach_language);

                     } else {
                        ERROR_MACRO_RDP(&dsl_sdh_call_1, "Initialisation of keyboard layout 0x%x%s%s failed. ", 
                           iml1,
                           adsl_session->boc_server_maps_keys     ? ", server maps keys" : "",
                           adsl_session->boc_server_maps_capslock ? ", server maps capslock" : "");
                     }
           
                     //initialise mouse state
                     adsl_session->dsc_mouse_state.uc_state = 0X00;
                     adsl_session->dsc_mouse_state.usc_last_pos_x = 0;
                     adsl_session->dsc_mouse_state.usc_last_pos_y = 0; 

                     // Call in reverse direction to start parsing the VNC-data
                     adsp_hl_clib_1->boc_callrevdir = TRUE; 

                     // Get password, if password from RDP
                     switch(adsl_session->inc_authentication_setting){
                        case ied_auth_setting_rdp: {
                           dsd_rdp_co* ads_rdp_co = adsl_session->dsc_crdps_1.adsc_rdp_co;

                           adsl_session->inc_len_vnc_password = ads_rdp_co->usc_loinf_pwd_len / sizeof(HL_WCHAR);
                           adsl_session->dsc_vnc_password.reset(adsl_session->inc_len_vnc_password, m_callback_get_mem, m_callback_free_mem, &dsl_sdh_call_1);
                           m_sbc_from_u16z(adsl_session->dsc_vnc_password.get_data(), adsl_session->inc_len_vnc_password, 
                              ads_rdp_co->awcc_loinf_pwd_a, ied_chs_ansi_819);

                           adsl_session->inc_len_host_user = ads_rdp_co->usc_loinf_userna_len / sizeof(HL_WCHAR);
                           adsl_session->dsc_host_user.reset(adsl_session->inc_len_host_user, m_callback_get_mem, m_callback_free_mem, &dsl_sdh_call_1);
                           m_sbc_from_u16z(adsl_session->dsc_host_user.get_data(), adsl_session->inc_len_host_user, 
                              ads_rdp_co->awcc_loinf_userna_a, ied_chs_ansi_819);

                           adsl_session->inc_len_host_password = ads_rdp_co->usc_loinf_pwd_len / sizeof(HL_WCHAR);
                           adsl_session->dsc_host_password.reset(adsl_session->inc_len_host_password, m_callback_get_mem, m_callback_free_mem, &dsl_sdh_call_1);
                           m_sbc_from_u16z(adsl_session->dsc_host_password.get_data(), adsl_session->inc_len_host_password, 
                              ads_rdp_co->awcc_loinf_pwd_a, ied_chs_ansi_819);
                        } break;
                        case ied_auth_setting_rd_vpn: {
                           dsd_unicode_string dsl_userid;
                           dsd_unicode_string dsl_group;
                           dsd_unicode_string dsl_password;
                           if(!m_get_user_credentials(adsp_hl_clib_1, &dsl_userid, &dsl_group, &dsl_password)){
                              ERROR_MACRO_RDP(true, "RD VPN credentials can not be received!\nThe setting \"RD-VPN-credentials\" "
                                 "is only allowed, if used in RD VPN, not with a normal WSP.\nChange the setting in the WSP configuration to \"WSP-configuration\" or \"RD-VPN-credentials\"!");
                           }

                           adsl_session->inc_len_vnc_password = dsl_password.imc_len_str;
                           adsl_session->dsc_vnc_password.reset(adsl_session->inc_len_vnc_password, m_callback_get_mem, m_callback_free_mem, &dsl_sdh_call_1);
                           m_cpy_vx_ucs(adsl_session->dsc_vnc_password.get_data(), adsl_session->inc_len_vnc_password, ied_chs_ansi_819, &dsl_password);

                           adsl_session->inc_len_host_user = dsl_userid.imc_len_str;
                           adsl_session->dsc_host_user.reset(adsl_session->inc_len_host_user, m_callback_get_mem, m_callback_free_mem, &dsl_sdh_call_1);
                           m_cpy_vx_ucs(adsl_session->dsc_host_user.get_data(), adsl_session->inc_len_host_user, ied_chs_ansi_819, &dsl_userid);

                           adsl_session->inc_len_host_password = dsl_password.imc_len_str;
                           adsl_session->dsc_host_password.reset(adsl_session->inc_len_host_password, m_callback_get_mem, m_callback_free_mem, &dsl_sdh_call_1);
                           m_cpy_vx_ucs(adsl_session->dsc_host_password.get_data(), adsl_session->inc_len_host_password, ied_chs_ansi_819, &dsl_password);

                           if(!m_release_user_credentials(adsp_hl_clib_1, &dsl_userid, &dsl_group, &dsl_password)){
                              ERROR_MACRO_RDP(true, "Error freeing memory for RD VPN credentials");
                           }

                        } break;

                        case ied_auth_setting_dynamic:
                        case ied_auth_setting_wsp_config:
                           break; // do nothing, as user and password is already there from configuration or dynamic connection
                           
                        default:
                           ERROR_MACRO_RDP(true, "Unknown authentication setting 0x%x", adsl_session->inc_authentication_setting); 
                     }//end  switch(adsl_session->inc_authentication_setting)
                  
                  }// end case ied_state_rdp_received_capabilities: 
                  break;

                  case ied_state_rdp_change_screen_is_send: {

                     // 2nd finalization: this occurs, after the screensize has been changed to the RFB's screensize. 
                     adsl_session->iec_state_rdp = ied_state_rdp_finalized_change_screen;

                     //DEF_DEBUG_PRINTF("Sending first FrameBuffer Update Request");
                     SEND_FRAMEBUFFER_UPDATE_REQUEST(FALSE);
                  
                     // Initialize Clipboard
                     if(adsl_session->boc_use_clipboard){
                        adsl_session->boc_use_clipboard = FALSE;

                        for(int inl_i = adsl_session->dsc_crdps_1.adsc_rdp_co->imc_no_virt_ch - 1; inl_i >= 0; inl_i--){
#if !(defined HL_UNIX)
                           if(_memicmp(adsl_session->dsc_crdps_1.adsc_rdp_co->adsrc_vc_1[inl_i].byrc_name, 
                              achrs_clipe_name, sizeof(achrs_clipe_name)) == 0){
#else
                           if(strcasecmp(adsl_session->dsc_crdps_1.adsc_rdp_co->adsrc_vc_1[inl_i].byrc_name, 
                              achrs_clipe_name) == 0){
#endif
                              adsl_session->adsc_rdp_vc_cb = &adsl_session->dsc_crdps_1.adsc_rdp_co->adsrc_vc_1[inl_i];

                              dsd_rdpacc_clipboard_callbacks dsl_cpb_callbacks = {
                                 m_clipboard_callback_format_list,
                                 m_clipboard_callback_copy_data_cb, 
                                 m_clipboard_callback_on_paste_cb,
                                 m_clipboard_callback_log,
                                 m_clipboard_callback_get_rdpacc_command,
                                 m_callback_get_mem,
                                 m_callback_free_mem
                              };
                           
                              if(m_rdpacc_clipboard_init(&adsl_session->dsc_rdpacc_clipboard, &dsl_sdh_call_1, 
                                 adsl_session->adsc_rdp_vc_cb, &dsl_cpb_callbacks) == false)
                                 break;  // break without activating clipboard

                              adsl_session->dsc_rdpclip_buffer.init();
                              adsl_session->boc_use_clipboard = TRUE;
                              adsl_session->boc_clipboard_is_init = TRUE; 
                              break;
                           } //end if(strcasecmp(adsl_session->dsc_crdps_1.adsc_rdp ... sizeof(achrs_clipe_name)) == 0)
                        }//end  for(int inl_i = adsl_session->dsc_crdps_1.adsc_rdp_co->imc_no_virt_ch - 1; inl_i >= 0; inl_i--)
                     }// end if(adsl_session->boc_use_clipboard)

                     // Send a dummy-cursor (if local cursor is not used, this avoids the "double-cursor-effect"
                     if(!adsl_session->boc_cursor_encoding){
                        dsd_sc_mpoi_color* ads_rdp_pointer = dsl_orderqueue.new_command<dsd_sc_mpoi_color>(8 * 8 * 3 + 8 * 2);
                        char* ach_xor = (char*)(ads_rdp_pointer + 1);
                        char* ach_and = ach_xor + 8 * 8 * 3;
                        ads_rdp_pointer->dsc_color_ptr_attr.usc_cache_index     = 0;
                        ads_rdp_pointer->dsc_color_ptr_attr.isc_hotspot_x       = 1;
                        ads_rdp_pointer->dsc_color_ptr_attr.isc_hotspot_y       = 1;
                        ads_rdp_pointer->dsc_color_ptr_attr.usc_width           = 8;
                        ads_rdp_pointer->dsc_color_ptr_attr.usc_height          = 8;
                        ads_rdp_pointer->dsc_color_ptr_attr.usc_length_and_mask = 8 * 2;
                        ads_rdp_pointer->dsc_color_ptr_attr.usc_length_xor_mask = 8 * 8 * 3;
                        ads_rdp_pointer->dsc_color_ptr_attr.ac_xor_mask_data    = ach_xor;
                        ads_rdp_pointer->dsc_color_ptr_attr.ac_and_mask_data    = ach_and;

                        memset(ach_xor, 0x00, 8 * 8 * 3);
                        memset(ach_and, 0xff, 8 * 8 * 2);
                        memset(ach_xor + 7 * 8 * 3, 0xff, 3 * 3);
                        memset(ach_xor + 6 * 8 * 3, 0xff, 3 * 3);
                        memset(ach_xor + 5 * 8 * 3, 0xff, 3 * 3);
                     }

                  } //end case ied_state_rdp_change_screen_is_send:
                  break;
                  
                  default:
                     ERROR_MACRO_RDP(true, "Wrong state of RDP-session at this point! adsl_session->iec_state_rdp = 0x%x", adsl_session->iec_state_rdp);
               }
            } // end case ied_clc_conn_fin:
            break;
    
case ied_clc_key_ud:                 /* key up or down          */
         
         // Don't send key-events before the rfb-session is not initialized. 
         if(adsl_session->iec_state_rdp < ied_state_rdp_finalized_change_screen)
            break; 
 
        M_SDH_PRINTF_T( "keyboard-event flags=%02X key-code=%02X ucc_keyboard_status=%02X.",
            (unsigned char) ((struct dsd_cl_keyb_eve *) (ADSL_CL_CO1 + 1))->chc_flags,  /* flags */
            (unsigned char) ((struct dsd_cl_keyb_eve *) (ADSL_CL_CO1 + 1))->chc_keycode,  /* key code */
            (unsigned char) ((struct dsd_cl_keyb_eve *) (ADSL_CL_CO1 + 1))->ucc_keyboard_status );

#ifdef NOT_YET_100531
        if ((unsigned char) ((struct dsd_cl_keyb_eve *) (ADSL_CL_CO1 + 1))->chc_flags != 0) break;  /* not key down */
        if ((unsigned char) ((struct dsd_cl_keyb_eve *) (ADSL_CL_CO1 + 1))->chc_keycode == 0X10) {  /* Germany key code Q */
            bol_end_session = TRUE;          /* end of session requested */
        }
        if ((unsigned char) ((struct dsd_cl_keyb_eve *) (ADSL_CL_CO1 + 1))->chc_keycode == 0X1E) {  /* Germany key code A */
            if (iml_draw == 1) iml_draw = 2;  /* draw another colour now */
        }
#ifdef D_VCH_HOB_LDM
        if ((unsigned char) ((struct dsd_cl_keyb_eve *) (ADSL_CL_CO1 + 1))->chc_keycode == 0X21) {  /* Germany key code F */
            if (ADSL_CONN_1->imc_state_hldm == 0X10) {  /* state HOB local-drive-mapping - LDM ready */
                ADSL_CONN_1->imc_state_hldm = 0X20;  /* state HOB local-drive-mapping - LDM open file */
            }
        }
        if ((unsigned char) ((struct dsd_cl_keyb_eve *) (ADSL_CL_CO1 + 1))->chc_keycode == 0X2F) {  /* Germany key code V */
            if (ADSL_CONN_1->imc_state_hldm == 0X10) {  /* state HOB local-drive-mapping - LDM ready */
                ADSL_CONN_1->imc_state_hldm = 0X30;  /* state HOB local-drive-mapping - LDM open file Virus */
            }
        }
#endif
#endif
        iml1 = 0;
        do {
            //DEF_DEBUG_PRINTF("\n\nKeyPressDetected");
            //uc_flags;
            // unsigned char uc_key;
            struct dsd_keyboardmapping_return dsl_return;
            // enum ied_keymapping_return iel_return;

            uc_flags = (unsigned char) ((struct dsd_cl_keyb_eve *) (ADSL_CL_CO1 + 1))->chc_flags;
            uc_key = (unsigned char) ((struct dsd_cl_keyb_eve *) (ADSL_CL_CO1 + 1))->chc_keycode;
#ifdef JBDEBUG
            if(uc_key == 0x58){
               dsd_sc_draw_sc* ads_draw_sc = dsl_orderqueue.new_command<dsd_sc_draw_sc>();
               ads_draw_sc->imc_left   = 0;
               ads_draw_sc->imc_top    = 0;
               ads_draw_sc->imc_right  = adsl_session->usc_fb_width;
               ads_draw_sc->imc_bottom = adsl_session->usc_fb_height;
               break;
            }
#endif

            //Keyboard syncing no longer need here based on svn update on 17/11/2011
            
            if(adsl_session->boc_server_maps_capslock != FALSE){
               m_keyboardmapping_sync_capital(&dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping, false);
            } else if(adsl_session->boc_server_maps_keys != FALSE){
               unsigned char uc_status = (unsigned char) ((struct dsd_cl_keyb_eve *) (ADSL_CL_CO1 + 1))->ucc_keyboard_status;
               m_keyboardmapping_sync_capital(&dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping, (uc_status & 0x4) != 0);
               if(!m_keyboardmapping_key_changes_on_capslock(dsl_sdh_call_1.adsc_ctrl_1->dsd_keyboard_capslock_behaviour, uc_flags, uc_key)){
                  m_keyboardmapping_sync_capital(&dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping, false);
               }
            }

            
            // Call keymapper
            iel_return = m_keyboardmapping_map(&dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping, &dsl_return, uc_flags, uc_key);
            iml_xkcode = 0;

            // Hack: If server maps capslock, num-keys have to be send as xcodes,
            // so that shift and capslock don't change num-keys, and that they are not remapped (for /*-+,)
            if((adsl_session->boc_server_maps_capslock != FALSE) && 
                (dsl_return.ut_virtual_keycode <= VK_DIVIDE) && 
                (dsl_return.ut_virtual_keycode >= VK_NUMPAD0)){
                iel_return = ied_no_unicode;
            }
            
            //DEF_DEBUG_PRINTF("\nKeyEvent Detected: iel_return %d",iel_return); 
            achl1 = achl_work_1;   /* save output area */ 

            switch (iel_return){
                case ied_no_mapping:
                    //DEF_DEBUG_PRINTF("\nno mapping");
                    iml1 = 0;
                    break; // end case no_mapping

                case ied_no_unicode:
                    //DEF_DEBUG_PRINTF("\nno unicode");
                    /*
                    
                    If m_keyboardmapping_map returns ied_no_unicode, wstcr_unicodes 
                    contains the unicode with ONLY the Shift and Capslock modifiers. 
                    (update by JBauer on 21 September 2011)
                    */

                    // a modifier of function key event
                    // read virtual key and convert it to KeySym

                    switch(dsl_return.ut_virtual_keycode){
                        case VK_BACK     : iml_xkcode = XK_BackSpace;    break;
                        case VK_TAB      : iml_xkcode = XK_Tab;          break;
                        case VK_CLEAR    : iml_xkcode = XK_Clear;        break;
                        case VK_RETURN   : iml_xkcode = XK_Return;       break;
                        case VK_PAUSE    : iml_xkcode = XK_Pause;        break;
                        case VK_SCROLL   : iml_xkcode = XK_Scroll_Lock;  break;
                        case VK_ESCAPE   : iml_xkcode = XK_Escape;       break;
                        case VK_DELETE   : iml_xkcode = XK_Delete;       break;
                        case VK_SHIFT    : iml_xkcode = XK_Shift_L;      break;
                        case VK_LSHIFT   : iml_xkcode = XK_Shift_L;      break;
                        case VK_RSHIFT   : iml_xkcode = XK_Shift_R;      break;
                        case VK_CONTROL  : iml_xkcode = XK_Control_L;    break;
                        case VK_LCONTROL : iml_xkcode = XK_Control_L;    break;
                        case VK_RCONTROL : iml_xkcode = XK_Control_R;    break;
                        case VK_MENU     : iml_xkcode = XK_Alt_L;        break;
                        case VK_LMENU    : iml_xkcode = XK_Alt_L;        break;
                        case VK_RMENU    : iml_xkcode = XK_Alt_R;        break;
                        case VK_CAPITAL  : iml_xkcode = XK_Caps_Lock;    break;
                        case VK_LWIN     : iml_xkcode = XK_Super_L;      break;
                        case VK_RWIN     : iml_xkcode = XK_Super_R;      break;
                        case VK_APPS     : iml_xkcode = XK_Menu;         break;
                        case VK_HOME     : iml_xkcode = XK_Home;         break;
                        case VK_LEFT     : iml_xkcode = XK_Left;         break;
                        case VK_UP       : iml_xkcode = XK_Up;           break;
                        case VK_RIGHT    : iml_xkcode = XK_Right;        break;
                        case VK_DOWN     : iml_xkcode = XK_Down;         break;
                        case VK_PRIOR    : iml_xkcode = XK_Page_Up;      break;
                        case VK_NEXT     : iml_xkcode = XK_Page_Down;    break;
                        case VK_END      : iml_xkcode = XK_End;          break;
                        case VK_SELECT   : iml_xkcode = XK_Select;       break;
                        case VK_SNAPSHOT : iml_xkcode = XK_Print;        break;
                        case VK_EXECUTE  : iml_xkcode = XK_Execute;      break;
                        case VK_INSERT   : iml_xkcode = XK_Insert;       break;
                        case VK_HELP     : iml_xkcode = XK_Help;         break;
                        case VK_CANCEL   : iml_xkcode = XK_Break;        break;
                        case VK_NUMLOCK  : iml_xkcode = XK_Num_Lock;     break;
                        case VK_F1       : iml_xkcode = XK_F1;           break;
                        case VK_F2       : iml_xkcode = XK_F2;           break;
                        case VK_F3       : iml_xkcode = XK_F3;           break;
                        case VK_F4       : iml_xkcode = XK_F4;           break;
                        case VK_F5       : iml_xkcode = XK_F5;           break;
                        case VK_F6       : iml_xkcode = XK_F6;           break;
                        case VK_F7       : iml_xkcode = XK_F7;           break;
                        case VK_F8       : iml_xkcode = XK_F8;           break;
                        case VK_F9       : iml_xkcode = XK_F9;           break;
                        case VK_F10      : iml_xkcode = XK_F10;          break;
                        case VK_F11      : iml_xkcode = XK_F11;          break;
                        case VK_F12      : iml_xkcode = XK_F12;          break;
                        case VK_F13      : iml_xkcode = XK_F13;          break;
                        case VK_F14      : iml_xkcode = XK_F14;          break;
                        case VK_F15      : iml_xkcode = XK_F15;          break;
                        case VK_F16      : iml_xkcode = XK_F16;          break;
                        case VK_F17      : iml_xkcode = XK_F17;          break;
                        case VK_F18      : iml_xkcode = XK_F18;          break;
                        case VK_F19      : iml_xkcode = XK_F19;          break;
                        case VK_F20      : iml_xkcode = XK_F20;          break;
                        case VK_F21      : iml_xkcode = XK_F21;          break;
                        case VK_F22      : iml_xkcode = XK_F22;          break;
                        case VK_F23      : iml_xkcode = XK_F23;          break;
                        case VK_F24      : iml_xkcode = XK_F24;          break;
                        case VK_MULTIPLY : iml_xkcode = XK_KP_Multiply;  break;
                        case VK_ADD      : iml_xkcode = XK_KP_Add;       break;
                        case VK_SEPARATOR: iml_xkcode = XK_KP_Separator; break;
                        case VK_SUBTRACT : iml_xkcode = XK_KP_Subtract;  break;
                        case VK_DECIMAL  : iml_xkcode = XK_KP_Decimal;   break;
                        case VK_DIVIDE   : iml_xkcode = XK_KP_Divide;    break;
                        case VK_NUMPAD0  : iml_xkcode = XK_KP_0;         break;
                        case VK_NUMPAD1  : iml_xkcode = XK_KP_1;         break;
                        case VK_NUMPAD2  : iml_xkcode = XK_KP_2;         break;
                        case VK_NUMPAD3  : iml_xkcode = XK_KP_3;         break;
                        case VK_NUMPAD4  : iml_xkcode = XK_KP_4;         break;
                        case VK_NUMPAD5  : iml_xkcode = XK_KP_5;         break;
                        case VK_NUMPAD6  : iml_xkcode = XK_KP_6;         break;
                        case VK_NUMPAD7  : iml_xkcode = XK_KP_7;         break;
                        case VK_NUMPAD8  : iml_xkcode = XK_KP_8;         break;
                        case VK_NUMPAD9  : iml_xkcode = XK_KP_9;         break;
                        default: 
                            //DEF_DEBUG_PRINTF("\n\tNO VK to XK code mapping, sending unicode of key"); 
                            iml_xkcode = dsl_return.wstcr_unicodes[0];
                            break;
                    }//end switch (dsl_return.ut_virtual_keycode) 

                    if (iml_xkcode == 0){
                        break;
                    }
                    
                    ENSURE_SPACE_ON_WORKAREA(sizeof(struct dsd_gather_i_1) + 8);
                    achl1 = achl_work_1;   /* save output area        */
                    achl_work_1 += 8;      /* after this area         */
                    
                    *(achl1 + 0) = rfb_cl2sc_KeyEvent;             /* command KeyEvent        */
                    memset(achl1 + 1, 0, 8 - 1 - 2 );
                    if ((((unsigned char) ((struct dsd_cl_keyb_eve *) (ADSL_CL_CO1 + 1))->chc_flags) & 0x01) == 0) {  /* key down */
                        *(achl1 + 1) = 1;              /* down-flag               */
                    }
                    *(achl1 + 6 + 0) = (unsigned char) (iml_xkcode >> 8);
                    *(achl1 + 6 + 1) = (unsigned char) iml_xkcode;

                    iml1 = 1;// do not break
                    break; //end case no unicode

                case ied_deadkey:
                    //DEF_DEBUG_PRINTF("\ndeadkey");
                    iml1 = 0;
                    break; // end case deadkey

                case ied_unicode:
                case ied_pending_deadkey_no_combination:
                case ied_pending_deadkey_combination:
                case ied_pending_deadkey_deadkey:
                {
                    
                    bool boc_ctrl_alt_release_press = false;
                    
                    //DEF_DEBUG_PRINTF("\nUnicode " << dsl_return.wstcr_unicodes[0]);
                    achl1 = achl_work_1;             /* save output area        */
                    //check for need to send fake keypresses
                    // if character is printable and a modifer is pressed, the modifer must be released
                    if ((dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping.inc_state & 0x0C) == 0x0C){
                        //modifiers alt and ctrl are pressed.

                        //check if character produced is in printable range
                        //check on first charachter of unicode array should be enough
                        iml1 = dsl_return.wstcr_unicodes[0];
                        if (((iml1 >= 32) && (iml1 <= 126)) ||
                            (iml1 >=160)){
                                
                             boc_ctrl_alt_release_press = true;
                                
                             // in printable range
                                            
                        }//end if (((iml1 >= 32) && (iml1 <= 126)) || (iml1 >=160)){

                    }//modifiers alt and ctrl have been pressed to produce a printable character. 
                    
                    iml1 = dsl_return.wstcr_unicodes[0];    
                    achl2 = achl_work_1; /* save output area in achl2       */

                    // If server maps keys, it ignores capital, and shift+capital is pressed, we have to fake "nothing is pressed" by releasing the shift. 
                    bool bo_release_shift = (adsl_session->boc_server_maps_keys != FALSE) && 
                       ((dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping.inc_state & (INS_FLAG_SHIFT + INS_FLAG_CAPITAL)) == (INS_FLAG_SHIFT + INS_FLAG_CAPITAL));

                    ENSURE_SPACE_ON_WORKAREA((8 * dsl_return.in_number_unicodes) +
                       sizeof(struct dsd_gather_i_1) +
                        (bo_release_shift ? 4 * 8 : 0) + 
                       (boc_ctrl_alt_release_press ? 6 * 8 :0)
                    );

                    //added the facility to send multiple keys after each other
                        achl_work_1 += (8 * dsl_return.in_number_unicodes);      /* after this area         */
                    
                    if(bo_release_shift){
                        if((dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping.inc_state & INS_FLAG_LSHIFT) != 0){
                           m_keyevent_msg(achl2, rfbKeyRelease, XK_Shift_L); // produce fake release of left shift
                           achl2 += 8;
                           achl_work_1 += 8;
                       }
                       if((dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping.inc_state & INS_FLAG_RSHIFT) != 0){
                           m_keyevent_msg(achl2, rfbKeyRelease, XK_Shift_R);
                           achl2 += 8;
                           achl_work_1 += 8;
                       }
                    }

                    if(boc_ctrl_alt_release_press){
                        if((dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping.inc_state & INS_FLAG_LMENU) != 0){ 
                            m_keyevent_msg(achl2, rfbKeyRelease, XK_Alt_L);
                            //memcpy(achl2, ucrs_release_lalt,8); //produce fake release of left alt key
                            achl2 += 8;
                            achl_work_1 += 8;
                        }
                        if((dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping.inc_state & INS_FLAG_RMENU) != 0){ 
                            m_keyevent_msg(achl2, rfbKeyRelease, XK_Alt_R);
                            //memcpy(achl2, ucrs_release_ralt,8); //produce fake release of right alt key
                            achl2 += 8;
                            achl_work_1 += 8;
                        }
                        if((dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping.inc_state & INS_FLAG_LCONTROL) != 0){ 
                            m_keyevent_msg(achl2, rfbKeyRelease, XK_Control_L);
                            //memcpy(achl2, ucrs_release_lctrl,8); //produce fake release of ctrl key
                            achl2 += 8;
                            achl_work_1 += 8;
                        }
                    }

                    
                    for (iml2 = 0; iml2 < dsl_return.in_number_unicodes; iml2++){
                        iml1 = dsl_return.wstcr_unicodes[iml2];
                        *(achl2 + (0 + (8*iml2))) = rfb_cl2sc_KeyEvent;           /* command KeyEvent        */

                        //check if unicode is printable latin-1
                        //if true the unicode and X11 keysym are the same
                        if (((iml1 >= 32) && (iml1 <= 126)) ||
                            ((iml1 >=160) && (iml1 <= 255))){

                                //if true the unicode and X11 keysym are the same
                                memset( achl2 + 1+(8*iml2), 0, 8 - 1 - 2 );
                                if ((((unsigned char) ((struct dsd_cl_keyb_eve *) (ADSL_CL_CO1 + 1))->chc_flags) & 0x01) == 0) {  /* key down */
                                    *(achl2 + 1+(8*iml2)) = 1;              /* down-flag               */
                                }
                                *(achl2 + 6 + 0 + (8*iml2)) = (unsigned char) (iml1 >> 8);
                                *(achl2 + 6 + 1 + (8*iml2)) = (unsigned char) iml1;
                        }else if (iml1 > 255){
                            //convert to symkey by adding 0100 in front on the 2byte unicode
                            memset( achl2 + 1+(8*iml2), 0, 8 - 1 - 4 ); //set only 3 bytes to zero
                            if ((((unsigned char) ((struct dsd_cl_keyb_eve *) (ADSL_CL_CO1 + 1))->chc_flags) & 0x01) == 0) {  /* key down */
                                *(achl2 + 1+(8*iml2)) = 1;              /* down-flag               */
                            }
                            *(achl2 + 4 + 0 + (8*iml2)) = (unsigned char) (0x01);
                            *(achl2 + 4 + 1 + (8*iml2)) = (unsigned char) (0x00);
                            *(achl2 + 4 + 2 + (8*iml2)) = (unsigned char) (iml1 >> 8);
                            *(achl2 + 4 + 3 + (8*iml2)) = (unsigned char) iml1;

 
                            //0x0D - is a combination of shift, control and alt modifiers
                        }else if ((dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping.inc_state & 0x0D) == 0x0){
                            // iml1 < 32 and no modifiers are pressed
                            // add ff in front of the 1 byte code
                            // example U09 -> 0x0000FF09
                            memset( achl2 + 1+(8*iml2), 0, 8 - 1 - 2 );
                            if ((((unsigned char) ((struct dsd_cl_keyb_eve *) (ADSL_CL_CO1 + 1))->chc_flags) & 0x01) == 0) {  /* key down */
                                *(achl2 + 1+(8*iml2)) = 1;              /* down-flag               */
                            }
                            *(achl2 + 6 + 0 + (8*iml2)) = (unsigned char) (0xFF);
                            *(achl2 + 6 + 1 + (8*iml2)) = (unsigned char) iml1;
                        }else{
                            // modifier have been pressed. get unicode of key without modifiers

                            //DEF_DEBUG_PRINTF("\nProcessing keyboard unicode less than 32, with modifiers");
                            //it is assumed that the virtual_keycode and unicode are the same for the keypress without modifiers. 
                            //problem virtual_keycode usually is same as the unicode for the capitalised letter. 
                            //having trouble to distinguish between ctrl+shift+p with ctrl+p.

                            iml1 = 0;
                            if(dsl_return.ut_virtual_keycode){
                                iml1 = dsl_return.ut_virtual_keycode;
                            }else {
                                iml1 =  1;
                                break;
                            }

                            memset( achl2 + 1+(8*iml2), 0, 8 - 1 - 2 );
                            if ((((unsigned char) ((struct dsd_cl_keyb_eve *) (ADSL_CL_CO1 + 1))->chc_flags) & 0x01) == 0) {  /* key down */
                                *(achl2 + 1+(8*iml2)) = 1;              /* down-flag               */
                            }
                            *(achl2 + 6 + 0 + (8*iml2)) = (unsigned char) (iml1 >> 8);
                            *(achl2 + 6 + 1 + (8*iml2)) = (unsigned char) iml1;
                        }//end if else
                    }// end for    

                    if(bo_release_shift){
                       if((dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping.inc_state & INS_FLAG_LSHIFT) != 0){
                           m_keyevent_msg(achl2 + (8*iml2), rfbKeyPress, XK_Shift_L);
                           //memcpy(achl2 + (8*iml2), ucrs_press_lshift, 8); // produce fake press of left shift
                           achl2 += 8;
                           achl_work_1 += 8;
                       }
                       if((dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping.inc_state & INS_FLAG_RSHIFT) != 0){
                           m_keyevent_msg(achl2 + (8*iml2), rfbKeyPress, XK_Shift_R);
                           //memcpy(achl2 + (8*iml2), ucrs_press_rshift, 8); // produce fake press of right shift
                           achl2 += 8;
                           achl_work_1 += 8;
                       }
                    }

                    if(boc_ctrl_alt_release_press){
                        if((dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping.inc_state & INS_FLAG_LMENU) != 0){ 
                            m_keyevent_msg(achl2 + (8*iml2), rfbKeyPress, XK_Alt_L);
                            //memcpy(achl2 + (8*iml2), ucrs_press_lalt,8); //produce fake press of left alt key
                            achl2 += 8;
                            achl_work_1 += 8;

                        }
                        if((dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping.inc_state & INS_FLAG_RMENU) != 0){ 
                            m_keyevent_msg(achl2 + (8*iml2), rfbKeyPress, XK_Alt_R);
                            //memcpy(achl2 + (8*iml2), ucrs_press_ralt,8); //produce fake press of right alt key
                            achl2 += 8;
                            achl_work_1 += 8;
                        }
                        if((dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping.inc_state & INS_FLAG_LCONTROL) != 0){ 
                            m_keyevent_msg(achl2 + (8*iml2), rfbKeyPress, XK_Control_L);
                            //memcpy(achl2 + (8*iml2), ucrs_press_lctrl,8); //produce fake press of ctrl key
                            achl2 += 8;
                            achl_work_1 += 8;
                        }
                    }


                } break; // end case unicode
                default:
                    iml1 = 0;
                    break;
            }//end switch iel_return

            if (iml1 == 0){
                break;
            }
            achl_work_2 -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) achl_work_2)
            ADSL_GAI1_OUT_G->adsc_next = NULL;
            ADSL_GAI1_OUT_G->achc_ginp_cur = achl1;  /* area to be sent to the server */
            ADSL_GAI1_OUT_G->achc_ginp_end = achl_work_1;  /* end area to be sent to the server */
            if (adsl_gai1_out_server == NULL) {
                adsp_hl_clib_1->adsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
            } else {
                adsl_gai1_out_server->adsc_next = ADSL_GAI1_OUT_G;
            }
            adsl_gai1_out_server = ADSL_GAI1_OUT_G;  /* save last in chain */
#undef ADSL_GAI1_OUT_G

        } while (FALSE);          
        
        //DEF_DEBUG_PRINTF("\nKey Sent to Server: " << iml1);
        break;

//  __  __                                  _   
// |  \/  |___ _  _ ___ ___ _____ _____ _ _| |_ 
// | |\/| / _ \ || (_-</ -_) -_) V / -_) ' \  _|
// |_|  |_\___/\_,_/__/\___\___|\_/\___|_||_\__|

   case ied_clc_mouse: {                  /* mouse event             */
      dsd_cl_mouse_eve* adsl_mouse_eve = ((dsd_cl_mouse_eve*) (ADSL_CL_CO1 + 1));

#ifdef  TRACEHL1
        M_SDH_PRINTF_T( "mouse-event flags=%02X coord-x=%d coord-y=%d.",
            (unsigned char) adsl_mouse_eve->chc_flags,  /* flags */
            (unsigned short int) adsl_mouse_eve->isc_coord_x,  /* x coordinate */
            (unsigned short int) adsl_mouse_eve->isc_coord_y );  /* y coordinate */
#endif

    /*
        RFB PointerEvent button-mask

        +------------+---+---+---+---+---+---+---+---+
        |Bit order   | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
        +------------+---+---+---+---+---+---+---+---+
        |Bit value   |128| 64| 32| 16| 8 | 4 | 2 | 1 |
        +------------+---+---+---+---+---+---+---+---+
        |VNC Mapping |NU |NU |NU |WD |WU |RP |MP |LP |
        +------------+---+---+---+---+---+---+---+---+       
        |VNC BitMask | 8 | 7 | 6 | 5 | 4 | 3 | 2 | 1 |
        +------------+---+---+---+---+---+---+---+---+  

        VNC Mapping Legend:

        NU - Not Used
        WD - Wheel Down
        WU - Wheel Up
        RP - Right Mouse Button Pressed
        MP - Middle Mouse Button Pressed
        LP - Left Mouse Button Pressed
    */
        
      bool bol_mousewheel = false;
      switch((unsigned char) adsl_mouse_eve->chc_flags){
         case rdp_mouse_flag_move:
         //no change in mouse state
         break;
      case rdp_mouse_flag_leftpress:
         if(adsl_session->boc_rfb_error)
            dsl_orderqueue.new_command<dsd_sc_order_end_session>(); 
         adsl_session->dsc_mouse_state.uc_state |= 0X01;
         break;
      case rdp_mouse_flag_leftrelease:
         adsl_session->dsc_mouse_state.uc_state &= 0XFE;
         break;
      case rdp_mouse_flag_rightpress:
         if(adsl_session->boc_rfb_error)
            dsl_orderqueue.new_command<dsd_sc_order_end_session>(); 
         adsl_session->dsc_mouse_state.uc_state |= 0X04;
         break;
      case rdp_mouse_flag_rightrelease:
         adsl_session->dsc_mouse_state.uc_state &= 0XFB;
         break;
      case rdp_mouse_flag_middlepress:
         adsl_session->dsc_mouse_state.uc_state |= 0X02;
         break;
      case rdp_mouse_flag_middlerelease:
         adsl_session->dsc_mouse_state.uc_state &= 0XFD;
         break;
      case rdp_mouse_flag_wheeldown:
         adsl_session->dsc_mouse_state.uc_state |= 0X10;
         adsl_mouse_eve->isc_coord_x = adsl_session->dsc_mouse_state.usc_last_pos_x;
         adsl_mouse_eve->isc_coord_y = adsl_session->dsc_mouse_state.usc_last_pos_y;
         bol_mousewheel = true;
         break;
      case rdp_mouse_flag_wheelup:
         adsl_session->dsc_mouse_state.uc_state |= 0X08;
         adsl_mouse_eve->isc_coord_x = adsl_session->dsc_mouse_state.usc_last_pos_x;
         adsl_mouse_eve->isc_coord_y = adsl_session->dsc_mouse_state.usc_last_pos_y;
         bol_mousewheel = true;
         break;
      } // switch(adsl_mouse_eve->chc_flags)

      // Don't send mouse-events before the rfb-session is not initialized. 
      if(adsl_session->iec_state_rdp < ied_state_rdp_finalized_change_screen)
         break; 
 
      // Write 6.4.5 PointerEvent
      GET_VNC_OUTPUT_GATHER(0x6);
      *achl1++ = rfb_cl2sc_PointerEvent;   
      *achl1++ = adsl_session->dsc_mouse_state.uc_state;
      write_16_be(&achl1, adsl_mouse_eve->isc_coord_x);
      write_16_be(&achl1, adsl_mouse_eve->isc_coord_y);

      if(!bol_mousewheel){
         adsl_session->dsc_mouse_state.usc_last_pos_x = adsl_mouse_eve->isc_coord_x;
         adsl_session->dsc_mouse_state.usc_last_pos_y = adsl_mouse_eve->isc_coord_y;
         break;
      }

      // For mouse-wheel-events, a second RFP-Event is needed. 
      // reset wheel up/down event
      adsl_session->dsc_mouse_state.uc_state &= 0XE7;
      GET_VNC_OUTPUT_GATHER(0x6);
      *achl1++ = rfb_cl2sc_PointerEvent;   
      *achl1++ = adsl_session->dsc_mouse_state.uc_state;
      write_16_be(&achl1, adsl_mouse_eve->isc_coord_x);
      write_16_be(&achl1, adsl_mouse_eve->isc_coord_y);

   } break; // Mouse-event
    
    case ied_clc_sync:  /* event that triggers keyboard_mapping syncronisation */
        {
        
            m_keyboardmapping_reset(&dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping);
        
            // sync status of numlock and capslock
            unsigned char uc_status = (unsigned char) ((struct dsd_cl_sync_eve *) (ADSL_CL_CO1 + 1))->chc_flags;
            m_keyboardmapping_sync(&dsl_sdh_call_1.adsc_ctrl_1->ads_keyboardmapping, uc_status);
        }
        break;
    


   case ied_clc_vch_in: {                /* input from virtual channel */
      M_SDH_PRINTF_T( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-T ied_clc_vch_in", __LINE__ );

      dsd_cl_vch_in* adsl_cl_vch_in = (dsd_cl_vch_in*)(adsl_session->dsc_crdps_1.adsc_cl_co1_ch + 1);

      //     _ _      _                      _ 
      //  __| (_)_ __| |__  ___  __ _ _ _ __| |
      // / _| | | '_ \ '_ \/ _ \/ _` | '_/ _` |
      // \__|_|_| .__/_.__/\___/\__,_|_| \__,_|
      //        |_|                            
      
      if((adsl_cl_vch_in->adsc_rdp_vc_1 == adsl_session->adsc_rdp_vc_cb) &&
         (adsl_session->boc_use_clipboard)){

         adsl_session->inc_rdpclip_state = 0;
         if(m_rdpacc_clipboard_process_and_reply(&adsl_session->dsc_rdpacc_clipboard, &dsl_sdh_call_1, adsl_cl_vch_in) == false){
            M_SDH_PRINTF_I("m_rdpacc_clipboard_process_and_reply returned false. Clipboard is turned off!");
            adsl_session->boc_use_clipboard = false;
            break;
         }
         
         ///DEF_DEBUG_PRINTF("\nRETURN from clipbaord callback no: %d",adsl_session->inc_rdpclip_state);

         // Evaluate result of clipboard-call
         switch(adsl_session->inc_rdpclip_state){

            case 0:
               break;
                     
            case M_ON_COPY_DATA_CB: {
               //build up ClientCutText Message and sent to VNC server

               /*
               RFB Protocol 6.4.6: ClientCutText
               Supports ONLY transfer of ISO 8859-1 (Latin-1) text.  

               --------------+------------------+--------------
                No. of bytes | Type     [Value] | Description
               --------------+------------------+-------------- 
                1            | U8          6    | message-type
                3            |                  | padding
                4            | U32              | <length>
                <length>     | U8 array         | text
               --------------+------------------+--------------
               */

               GET_VNC_OUTPUT_GATHER(1 + 3 + 4);
               write_8(&achl1, 0x06);  // message-type
               write_24_be(&achl1, 0); // padding
               write_32_be(&achl1, adsl_session->inc_rdpclip_num_data); // length

               GET_VNC_OUTPUT_GATHER(0x0);
               adsl_gai1_out_1->achc_ginp_cur = adsl_session->dsc_rdpclip_buffer.get_data();
               adsl_gai1_out_1->achc_ginp_end = adsl_gai1_out_1->achc_ginp_cur + adsl_session->inc_rdpclip_num_data;
               
               int inl_x = m_gather_count(adsp_hl_clib_1->adsc_gai1_out_to_server);

            } break; // case M_ON_COPY_DATA_CB
            
            // If we receive a format-list from the RDP-client, we immediately request the data, 
            // as VNC always sends the copied data immediately. 
            case M_ON_COPY_FMTS_CB: {
               if(m_rdpacc_clipboard_server_paste(&adsl_session->dsc_rdpacc_clipboard, &dsl_sdh_call_1, ied_cf_text) == false){
                  // ied_cf_text was not in format-list, or other error!
                  M_SDH_PRINTF_I("m_rdpacc_clipboard_server_paste returned false. Nothing is done!");
                  break;
               }
            } break; // case M_ON_COPY_FMTS_CB

            case M_ON_PASTE_CB: {
                               
               char* achl_buffer = adsl_session->dsc_rdpclip_buffer.get_data();

               //Traverse the data, byte by byte,
               //VNC server - uses only the Line Feed to break lines (LF 0x0A)

               //Windows machines, need Carriage Return followed by a Line Feed Character
               //(CR+LF 0x0D 0x0A) to display a line break 

               //Search text from VNC for '0x0A' charachters, and place a '0x0D' before.
               GET_GATHER_ON_WA;
               dsd_gather_i_1* ads_gather_first = adsl_gai1_w1;
               dsd_gather_i_1* ads_gather_act = ads_gather_first;
               ads_gather_act->achc_ginp_cur = achl_buffer; 

               // The aim of this routine is to have all occurances of 0x0A to 0x0D0A
               char* achl_end = achl_buffer + adsl_session->inc_rdpclip_num_data;
               while(achl_buffer < achl_end){
                  if(*achl_buffer == 0x0D){
                     //No need to check next char because, 
                     //If next char is an 0x0A, it is already preceeded by an '0x0D'
                     if((achl_buffer + 1) < achl_end)
                        achl_buffer++;
                  } else if (*achl_buffer == 0x0A){
                     // 0xA found, without 0xD! -> insert 0xD. 
                     ads_gather_act->achc_ginp_end = achl_buffer;
                     GET_GATHER(1);
                     *adsl_gai1_out_1->achc_ginp_cur = 0xD;
                     ads_gather_act->adsc_next = adsl_gai1_out_1;
                     GET_GATHER_ON_WA;
                     ads_gather_act = adsl_gai1_w1;
                     adsl_gai1_out_1->adsc_next = ads_gather_act;
                     ads_gather_act->achc_ginp_cur = achl_buffer;
                  }

                  achl_buffer++;
               }
               ads_gather_act->achc_ginp_end = achl_buffer;
               ads_gather_act->adsc_next = NULL;

               if(m_rdpacc_clipboard_srvr_data(&adsl_session->dsc_rdpacc_clipboard, &dsl_sdh_call_1, ads_gather_first) == false){
                  adsl_session->boc_use_clipboard = false;
                  break; 
               }

            } break; // case M_ON_PASTE_CB

            default: 
               ERROR_MACRO_RDP(true, "Unknown clipboard-state: 0x%x", adsl_session->inc_rdpclip_state);
         } // switch(adsl_session->inc_rdpclip_state)

         break;
      } // Clipboard data from RDP-Client

      // Virtual channel data, other than from clipboard. Ignored. 
   } break; // case ied_clc_vch_in

    case ied_clc_shutdown_requ:          /* shutdown request from client side */
        M_SDH_PRINTF_T( "ied_clc_shutdown_requ");

        //       goto pctend00;                     /* end of session          */
        //create a ied_scc_order_shutdown_deny
        //build up command and pass to accelerator.
        //command has no parameters!
        //DEF_DEBUG_PRINTF("\nShutdown Request Detected:");
        dsl_orderqueue.new_command<dsd_sc_order_end_shutdown_deny>();
    
    case ied_clc_end_session:            /* end of session client side */
        M_SDH_PRINTF_T( "ied_clc_end_session");

        //       goto pctend00;                     /* end of session          */
        break;
    default:

        M_SDH_PRINTF_T( "unknown event iec_cl_command=%d.", ADSL_CL_CO1->iec_cl_command );
        break;
        } //end switch (ADSL_CL_CO1->iec_cl_command)
#undef ADSL_CL_CO1
        adsl_session->dsc_crdps_1.adsc_cl_co1_ch = adsl_session->dsc_crdps_1.adsc_cl_co1_ch->adsc_next;
    }// end while (adsl_session->dsc_crdps_1.adsc_cl_co1_ch)
    if (adsl_session->dsc_crdps_1.adsc_gather_i_1_out) {


        if (adsl_gai1_out_client == NULL) {    /* data to be sent to the RDP client */
            //ooooooooooooooooooooooooooooooooooooooooooooooooout
            adsp_hl_clib_1->adsc_gai1_out_to_client = adsl_session->dsc_crdps_1.adsc_gather_i_1_out;
            //DEF_DEBUG_PRINTF("\tC: %d", GetTickCount());
            adsl_gai1_out_client = adsl_session->dsc_crdps_1.adsc_gather_i_1_out;
        } else {
            adsl_gai1_out_client->adsc_next = adsl_session->dsc_crdps_1.adsc_gather_i_1_out;
        }
        while (adsl_gai1_out_client->adsc_next) adsl_gai1_out_client = adsl_gai1_out_client->adsc_next;

    }

    // Check, if we have to call RDP-Acc again
   if (adsl_session->dsc_crdps_1.boc_callagain || bol_cont)   /* call again            */
      goto p_rdpserv_60;                                 /* call the RDP server     */

   // Check, if there are still commands for RDP-ACC
   if(adsl_session->dsc_crdps_1.adsc_sc_co1_ch != NULL)
      goto p_rdpserv_60;                                 /* call the RDP server     */
   if(!dsl_orderqueue.is_empty())
      goto p_rdpserv_40; 

   if(bol_return_to_copyrect){
      bol_return_to_copyrect = false; 
      goto p_cl_fu_copyrect;
   }

   if (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER) {  /* data from client */
      adsl_gai1_inp_1 = NULL;                /* input data processed    */
      goto p_proc_inp_80;                    /* the input has been processed */
   }
   goto p_ifunc_from_server;                      /* process the input       */

} // p_ifunc_default_00

p_cleanup_00:                            /* do clean-up             */
    //DEF_DEBUG_PRINTF("Starting Cleanup");
    dsl_sdh_call_1.adsc_ctrl_1 = (struct dsd_gw_ctrl_1 *) adsp_hl_clib_1->ac_ext;

    adsl_session = dsl_sdh_call_1.adsc_ctrl_1;    /* for addressing the data */

    if(adsl_session->boc_clipboard_is_init){
      adsl_session->boc_use_clipboard = false;
      m_rdpacc_clipboard_close(&adsl_session->dsc_rdpacc_clipboard, &dsl_sdh_call_1);
      adsl_session->dsc_rdpclip_buffer.close(m_callback_free_mem, &dsl_sdh_call_1);
   }
            
    /* end of zLib de-compression                                       */
    if (adsl_session->dsc_cdr_ctrl.imc_func != DEF_IFUNC_START) {  /* is initialized */
        adsl_session->dsc_cdr_ctrl.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary helper routine pointer */
        adsl_session->dsc_cdr_ctrl.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
        adsl_session->dsc_cdr_ctrl.imc_func = DEF_IFUNC_END;  /* end of de-compression */
        m_cdr_zlib_1_dec( &adsl_session->dsc_cdr_ctrl );
        if (adsl_session->dsc_cdr_ctrl.imc_return != DEF_IRET_END) {  /* not normal end */
            M_SDH_PRINTF_W( "zLib close returned %d.", adsl_session->dsc_cdr_ctrl.imc_return );
        }
    }
    /* end of RDP server                                                */
    if (adsl_session->dsc_crdps_1.inc_func != DEF_IFUNC_START) {  /* is initialized */
        adsl_session->dsc_crdps_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* pointer for this session */
        adsl_session->dsc_crdps_1.inc_func = DEF_IFUNC_CLOSE;  /* close RDP server */
        m_rdpserv_1( &adsl_session->dsc_crdps_1 );
        if (adsl_session->dsc_crdps_1.inc_return != DEF_IRET_END) {  /* not normal end */
            M_SDH_PRINTF_W( "RDP server close returned %d.", adsl_session->dsc_crdps_1.inc_return );
        }
    }
    adsp_hl_clib_1->adsc_gai1_out_to_client = adsl_session->dsc_crdps_1.adsc_gather_i_1_out;
    adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection should be ended */
    //PRINTF_DEF_IRET_END;

    if (adsl_session->dsc_crdps_1.ac_screen_buffer) {
        bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
            DEF_AUX_MEMFREE,
            &adsl_session->dsc_crdps_1.ac_screen_buffer,
            0 );
        if (bol1 == FALSE) {
            adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
            m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E connect failed - error while freeing aux memory",
                __LINE__ );
        }
    }
    bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
        DEF_AUX_MEMFREE,
        &adsp_hl_clib_1->ac_ext,
        sizeof(struct dsd_gw_ctrl_1) );
    if (bol1 == FALSE) {
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;       
        m_sdh_printf( &dsl_sdh_call_1, "xl-rdps-rfbc-1-l%05d-E error while freeing auxiliary memory",
            __LINE__ );
    }
    return;                                  /* all done                */
} /* end m_hlclib01()                                                  */


/* get colour int to be used by rdp */
static inline bool m_get_rdpcolour_int(int ump_colour_in, int imp_colour_depth, unsigned int* umr_rdpcolour_int){
   switch(imp_colour_depth){
      case 15:
      case 16:
         {
            *umr_rdpcolour_int = ump_colour_in;
            return true;
         }
      case 24:
      case 32:
         {
           *umr_rdpcolour_int = (((ump_colour_in & 0xFF0000) >> 16) |
                                 ((ump_colour_in & 0x00FF00)      ) | 
                                 ((ump_colour_in & 0x0000FF) << 16)
                                 );
            return true;
         }
      default:
         return false;
         break;
   }//end switch(imp_colour_depth)
} //end m_get_rdpcolour_int(...)


/* input two bytes big endian                                          */
static inline short int m_get_be2( char *achp_source ) {
    return (*((unsigned char *) achp_source) << 8)
        | *((unsigned char *) achp_source + 1);
} /* end m_get_be2() */

//build up a key event
static void m_keyevent_msg(char *achp_keyevent_msg, int imp_press_or_release, int imp_x11key){
   
    *(achp_keyevent_msg)++ = (char) rfb_cl2sc_KeyEvent;
    *(achp_keyevent_msg)++ = (char) imp_press_or_release;
    *(achp_keyevent_msg)++ = 0x00;
    *(achp_keyevent_msg)++ = 0x00;
    *(achp_keyevent_msg)++ = (unsigned char) (imp_x11key >> 24);
    *(achp_keyevent_msg)++ = (unsigned char) (imp_x11key >> 16);
    *(achp_keyevent_msg)++ = (unsigned char) (imp_x11key >> 8);
    *(achp_keyevent_msg)++ = (unsigned char) (imp_x11key);
}

//                  _              _         _                            _           
//  __ _ _ ___ __ _| |_ ___   _ __(_)_ _____| |___ __ ___ _ ___ _____ _ _| |_ ___ _ _ 
// / _| '_/ -_) _` |  _/ -_) | '_ \ \ \ / -_) |___/ _/ _ \ ' \ V / -_) '_|  _/ -_) '_|
// \__|_| \___\__,_|\__\___| | .__/_/_\_\___|_|   \__\___/_||_\_/\___|_|  \__\___|_|  
//                           |_|                                                      
//
// The colormodels are just needed locally for the creation of the converter. Because of that the RFB-colormodel is local here.
// The RDP-colormodel is kept as member of adsl_session, as it's used again for the SetColourMapEntries order.
// The colormap is also kept, as SetColourMapEntries might only update a few colors, and leave the others. 

// Create the converter - only call this function in a try-catch-block!
static void m_create_converter(dsd_gw_ctrl_1* adsl_session, c_colormodel& dsl_colormodel_rfb) {
   if(adsl_session->adsc_pixel_converter != NULL){                                                    
      adsl_session->adsc_pixel_converter->~c_converter();                                             
      adsl_session->dsc_pixel_converter_store.~c_memory_provider_stack();                                         
   }                                                                                                  
   new (&adsl_session->dsc_pixel_converter_store) dsd_stack_allocator();                              
   adsl_session->adsc_pixel_converter = c_converter_factory<dsd_pixel_converter_config>::create_converter(                              
      dsl_colormodel_rfb, *adsl_session->adsc_colormodel_rdp, adsl_session->dsc_pixel_converter_store); 
} // m_create_converter()

static bool m_create_colormap(dsd_sdh_call_1* adsl_sdh_call_1){
   dsd_gw_ctrl_1* adsl_session = adsl_sdh_call_1->adsc_ctrl_1;
   if(adsl_session->adsc_colormap_rfb != NULL)
      return true; 

   if(adsl_sdh_call_1->amc_aux(adsl_sdh_call_1->vpc_userfld, DEF_AUX_MEMGET,
                               &adsl_session->adsc_colormap_rfb, sizeof(c_colormap)) == FALSE){
      return false; 
   }

   // First get default colormap
   new (adsl_session->adsc_colormap_rfb) c_colormap(umrc_rgbtable_default, sizeof(umrc_rgbtable_default) / sizeof(uint32_t));
   return true; 
}

// Create converter with a colormap in the RDP-Colormodel 
static bool m_create_converter_colormap(dsd_sdh_call_1* adsl_sdh_call_1){
   dsd_gw_ctrl_1* adsl_session = adsl_sdh_call_1->adsc_ctrl_1;

   try{
      
      // Create RFB colormodel 
      dsd_stack_allocator dsl_colormodel_allocator; // Local allocator, as dsl_colormodel is not needed after creation of converter any more. 
      c_colormodel dsl_colormodel_map_rfb(32, 32, 0x00FF0000, 0x0000FF00, 0x000000FF, 0x00000000, ie_endian_little); 
      c_colormodel dsl_colormodel_rfb(adsl_session->dsc_rfb_pixel_format.chc_bits_per_pixel,
                                                     adsl_session->dsc_rfb_pixel_format.chc_depth,
                                                     ie_endian_big, 
                                                     *adsl_session->adsc_colormap_rfb, 
                                                     dsl_colormodel_map_rfb, 
                                                     dsl_colormodel_allocator);

      if(dsl_colormodel_rfb.colormodel_map() == NULL){
         ERROR_MACRO_SUB("colormodel_map not initialized, probably not enough memory in allocator.\n");
      }
      m_create_converter(adsl_session, dsl_colormodel_rfb);

   } catch (std::runtime_error dsl_e){
      ERROR_MACRO_SUB("Error creating converter. adsl_session->inc_coldep_rdp=%i adsl_session->imc_bpp_rfb=%i %s)", adsl_session->inc_coldep_rdp, adsl_session->imc_bpp_rfb, dsl_e.what());                                \
   }
   return true; 
}

/* subroutine for output to console                                    */
static int m_sdh_printf( struct dsd_sdh_call_1 *adsp_sdh_call_1, char *achptext, ... ) {
    BOOL       bol1;                         /* working variable        */
    int        iml1;                         /* working variable        */
    va_list    dsl_argptr;
    char       chrl_out1[512];

    va_start( dsl_argptr, achptext );
    iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8, achptext, dsl_argptr );
    va_end( dsl_argptr );
    (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
        DEF_AUX_CONSOLE_OUT,  /* output to console */
        chrl_out1, iml1 );    
    return iml1;
} /* end m_sdh_printf()                                                */

/* subroutine for output to console width file and line        */
static int m_sdh_printf_tl( struct dsd_sdh_call_1 *adsp_sdh_call_1, const char* ach_type, int in_line, char *achptext, ... ) {
    BOOL       bol1;                         /* working variable        */
    int        iml1;                         /* working variable        */
    va_list    dsl_argptr;
    char       chrl_out1[512];

    va_start( dsl_argptr, achptext );
    iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8, achptext, dsl_argptr );
    va_end( dsl_argptr );
   
    return m_sdh_printf(adsp_sdh_call_1, "xl-rdps-rfbc-3-l%05d-%s %s", in_line, ach_type, chrl_out1);
} // end m_sdh_printf()   

static void m_rdp_send_splash_screen(dsd_sdh_call_1 *adsl_sdh_call_1){
   if(adsl_sdh_call_1->adsc_orderqueue == NULL)
      return;
   dsd_gw_ctrl_1* adsl_session = adsl_sdh_call_1->adsc_ctrl_1;

   // Create converter
   dsd_stack_allocator dsl_converter_store;
   c_converter* adsl_converter = NULL;
   ied_sc_bitsperpixel iel_bitsperpixelid;
   try{
      c_colormodel dsl_cm_src(24, 24, 0x00ff0000, 0x0000ff00, 0x000000ff, 0, ie_endian_little);
      char chrl_cm_rdp[sizeof(c_colormodel)];
      switch(adsl_session->inc_coldep_rdp){
         case 15:
            new (chrl_cm_rdp) c_colormodel(15, 16, 0x7C00, 0x03E0, 0x001F, 0, ie_endian_little);
            iel_bitsperpixelid = ied_scc_cbr2_16bpp;
            break;
         case 16:
            new (chrl_cm_rdp) c_colormodel(16, 16, 0xF800, 0x07E0, 0x001F, 0, ie_endian_little);
            iel_bitsperpixelid = ied_scc_cbr2_16bpp;
            break;
         case 24:
            new (chrl_cm_rdp) c_colormodel(24, 24, 0x00ff0000, 0x0000ff00, 0x000000ff, 0, ie_endian_little);
            iel_bitsperpixelid = ied_scc_cbr2_24bpp;
            break;
         case 32:
            iel_bitsperpixelid = ied_scc_cbr2_32bpp;
            new (chrl_cm_rdp) c_colormodel(32, 32, 0x00ff0000, 0x0000ff00, 0x000000ff, 0xff000000, ie_endian_little);
            break;
         default:
            return; 
      }
      adsl_converter = c_converter_factory<dsd_pixel_converter_config>::create_converter(dsl_cm_src, *((c_colormodel*) chrl_cm_rdp), dsl_converter_store); 
      if(adsl_converter == NULL)
         return;
   } catch (std::exception dsl_e){
      return;
   }

   // Print Picture
   const int inl_width_src   = 608;
   const int inl_height_src  = 93;
   const int inl_height_rest = 363;
   int inl_scanline_src = inl_width_src * 3;
   const unsigned char* achl_buffer_src = m_get_splash_screen() + inl_height_src * inl_scanline_src;
   const int inl_dst_x = (adsl_session->usc_fb_width - inl_width_src) / 2;
   const int inl_dst_y = (adsl_session->usc_fb_height - inl_height_src - inl_height_rest) / 2;

   adsl_session->inc_message_x      = inl_dst_x + 10;
   adsl_session->inc_message_y      = inl_dst_y + 5 + 100;
   adsl_session->inc_message_width  = inl_width_src - 20;
   adsl_session->inc_message_height = inl_height_src + inl_height_rest - 20; 

   unsigned char* ach_buffer_dst = ((unsigned char*) adsl_session->dsc_crdps_1.ac_screen_buffer) 
      + inl_dst_x * adsl_session->imc_bpp_rdp + inl_dst_y * adsl_session->inc_scanline_rdp_screen;
   for(int inl_height = inl_height_src; inl_height > 0; inl_height--){
      achl_buffer_src -= inl_scanline_src;
      adsl_converter->convert(achl_buffer_src, ach_buffer_dst, inl_width_src);
      ach_buffer_dst += adsl_session->inc_scanline_rdp_screen;
   }


   // Send update screenbuffer
   dsd_sc_draw_sc* ads_draw_sc = adsl_sdh_call_1->adsc_orderqueue->new_command<dsd_sc_draw_sc>();
   ads_draw_sc->imc_left   = inl_dst_x;
   ads_draw_sc->imc_top    = inl_dst_y;
   ads_draw_sc->imc_right  = inl_dst_x + inl_width_src;
   ads_draw_sc->imc_bottom = inl_dst_y + inl_height_src;

   // Now draw rest of spash screen
   // white opaquerect
   dsd_sc_order_opaquerect* adsl_opaquerect  = adsl_sdh_call_1->adsc_orderqueue->new_command<dsd_sc_order_opaquerect>();
   adsl_opaquerect->dsc_rectangle.isc_left   = inl_dst_x;
   adsl_opaquerect->dsc_rectangle.isc_top    = inl_dst_y + inl_height_src;
   adsl_opaquerect->dsc_rectangle.isc_width  = inl_width_src;
   adsl_opaquerect->dsc_rectangle.isc_height = inl_height_rest;
   adsl_opaquerect->boc_has_bounds           = FALSE;
   adsl_opaquerect->boc_update_scrbuf        = FALSE;
   adsl_opaquerect->umc_color                = get_rdpcolor(adsl_session->inc_coldep_rdp, 0xff, 0xff, 0xff);
   adsl_opaquerect->imc_no_color_bytes       = 3;

#define DRAW_LINE(INL_X, INL_Y, INL_XE, INL_YE, CH_RED, CH_GREEN, CH_BLUE) {                                \
   dsd_sc_order_lineto* adsl_lineto = adsl_sdh_call_1->adsc_orderqueue->new_command<dsd_sc_order_lineto>(); \
   adsl_lineto->isc_nxstart       = INL_X;                                                                  \
   adsl_lineto->isc_nystart       = INL_Y;                                                                  \
   adsl_lineto->isc_nxend         = INL_XE;                                                                 \
   adsl_lineto->isc_nyend         = INL_YE;                                                                 \
   adsl_lineto->imc_pencolor      = get_rdpcolor(adsl_session->inc_coldep_rdp, CH_RED, CH_GREEN, CH_BLUE);  \
   adsl_lineto->iec_brop2         = ied_scc_r2_copypen;                                                     \
   adsl_lineto->iec_backmode      = ied_scc_transparent;                                                    \
   adsl_lineto->boc_has_bounds    = FALSE;                                                                  \
   adsl_lineto->boc_update_scrbuf = FALSE;                                                                  \
   }

   // left borders
   int inl_y0 = inl_dst_y + inl_height_src;
   int inl_y1 = inl_dst_y + inl_height_src + inl_height_rest - 1;
   DRAW_LINE(inl_dst_x + 0, inl_y0, inl_dst_x + 0, inl_y1 - 0, 0xd6, 0xd3, 0xce);
   DRAW_LINE(inl_dst_x + 2, inl_y0, inl_dst_x + 2, inl_y1 - 1, 0xd6, 0xd3, 0xce);
   DRAW_LINE(inl_dst_x + 3, inl_y0, inl_dst_x + 3, inl_y1 - 2, 0xd6, 0xd3, 0xce);
   DRAW_LINE(inl_dst_x + 4, inl_y0, inl_dst_x + 4, inl_y1 - 5, 0x7b, 0x8a, 0x9c);
   // bottom borders
   int inl_x1 = inl_dst_x + inl_width_src - 1;
   DRAW_LINE(inl_dst_x + 0, inl_y1 - 0, inl_x1 + 1, inl_y1 - 0, 0x42, 0x41, 0x42);
   DRAW_LINE(inl_dst_x + 1, inl_y1 - 1, inl_x1 - 0, inl_y1 - 1, 0x84, 0x82, 0x84);
   DRAW_LINE(inl_dst_x + 3, inl_y1 - 2, inl_x1 - 1, inl_y1 - 2, 0xd6, 0xd3, 0xce);
   DRAW_LINE(inl_dst_x + 4, inl_y1 - 3, inl_x1 - 2, inl_y1 - 3, 0xd6, 0xd3, 0xce);
   DRAW_LINE(inl_dst_x + 4, inl_y1 - 4, inl_x1 - 2, inl_y1 - 4, 0xef, 0xef, 0xef);
   DRAW_LINE(inl_dst_x + 5, inl_y1 - 6, inl_x1 - 4, inl_y1 - 6, 0x7b, 0x8a, 0x9c);
   // right borders
   DRAW_LINE(inl_x1 - 0, inl_y0, inl_x1 - 0, inl_y1 - 0, 0x42, 0x41, 0x42);
   DRAW_LINE(inl_x1 - 1, inl_y0, inl_x1 - 1, inl_y1 - 1, 0x84, 0x82, 0x84);
   DRAW_LINE(inl_x1 - 2, inl_y0, inl_x1 - 2, inl_y1 - 2, 0xd6, 0xd3, 0xce);
   DRAW_LINE(inl_x1 - 3, inl_y0, inl_x1 - 3, inl_y1 - 3, 0xd6, 0xd3, 0xce);
   DRAW_LINE(inl_x1 - 5, inl_y0, inl_x1 - 5, inl_y1 - 5, 0x7b, 0x8a, 0x9c);

#undef DRAW_LINE
} // static void m_rdp_message(dsd_sdh_call_1 *adsl_sdh_call_1, const char* achl_message, ...)

static void m_rdp_printf(struct dsd_sdh_call_1 *adsl_sdh_call_1, char *achl_message, ...){
//static int m_rdp_printf(dsd_rdpacc_orderqueue* adsl_orderqueue, dsd_font* ads_font, int inl_color, 
//                         int inl_x, int inl_y, int inl_width, int inl_height, int inl_dy, const char* achl_message, ...){
   if(adsl_sdh_call_1->adsc_orderqueue == NULL)
      return;
   dsd_gw_ctrl_1* adsl_session = adsl_sdh_call_1->adsc_ctrl_1;

   // Print text to workarea
   char       chrl_out1[1024];
   va_list    dsl_argptr;
   va_start( dsl_argptr, achl_message );
   int inl_len = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_ansi_819, achl_message, dsl_argptr );
   va_end( dsl_argptr );

   int inl_start = 0;
   for(int inl_i = 0; inl_i <= inl_len; inl_i++){
      if((chrl_out1[inl_i] == '\n') || (chrl_out1[inl_i] == 0)){
         int inl_thislen = inl_i - inl_start;
         if(inl_thislen > 0){
            dsd_sc_order_drawstring* ads_drawstring = adsl_sdh_call_1->adsc_orderqueue->new_command<dsd_sc_order_drawstring>(inl_thislen);

            char* ach_keystore = (char*)(ads_drawstring + 1);
            ads_drawstring->adsc_font = &adsl_session->dsc_rdpacc_font;

            ads_drawstring->dsc_backrect.isc_left   = adsl_session->inc_message_x;
            ads_drawstring->dsc_backrect.isc_top    = adsl_session->inc_message_y;
            ads_drawstring->dsc_backrect.isc_right  = adsl_session->inc_message_x  + adsl_session->inc_message_width - 1;
            ads_drawstring->dsc_backrect.isc_bottom = adsl_session->inc_message_y + adsl_session->inc_message_height - 1;

            ads_drawstring->dsc_opaqrect.isc_left = 0;
            ads_drawstring->dsc_opaqrect.isc_top = 0;
            ads_drawstring->dsc_opaqrect.isc_right = 0;
            ads_drawstring->dsc_opaqrect.isc_bottom = 0;
            ads_drawstring->umc_backcolor = 0;
            ads_drawstring->umc_forecolor = 0;

            ads_drawstring->dsc_unicode_string.iec_chs_str = ied_chs_ansi_819;
            ads_drawstring->dsc_unicode_string.ac_str      = ach_keystore;
            ads_drawstring->dsc_unicode_string.imc_len_str = inl_thislen;
            ads_drawstring->isc_glyph_x                    = adsl_session->inc_message_x;
            ads_drawstring->isc_glyph_y                    = adsl_session->inc_message_y;

            ads_drawstring->ucc_flaccel                    = ied_scc_so_horizontal;
            ads_drawstring->boc_has_bounds                 = FALSE;
            ads_drawstring->boc_update_scrbuf              = FALSE;

            memcpy(ach_keystore, chrl_out1 + inl_start, inl_thislen);
         }
         inl_start = inl_i + 1;
         adsl_session->inc_message_y      += 17;
         adsl_session->inc_message_height -= 17;

      }
   }
} // static void m_rdp_message(dsd_sdh_call_1 *adsl_sdh_call_1, const char* achl_message, ...)


// returns true, if no RDP-message could be printed on the splash-screen, meaning, the connection should end automatically. 
static bool m_rfb_error(dsd_sdh_call_1 *adsl_sdh_call_1, const char* achl_function, int inl_line, bool bol_admin, const char* achl_message, ...){
   dsd_gw_ctrl_1* adsl_session = adsl_sdh_call_1->adsc_ctrl_1;

   va_list    dsl_argptr;
   char       chrl_out1[512];

   adsl_session->boc_rfb_error = true;
   adsl_session->dsc_crdps_1.adsc_cl_co1_ch = NULL;

   va_start( dsl_argptr, achl_message );
   int inl_len = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8, achl_message, dsl_argptr );
   va_end( dsl_argptr );

   // Print message on console
   m_sdh_printf(adsl_sdh_call_1, "xl-rdps-rfbc-3-l%05d-%s %s", inl_line, "E", chrl_out1);

   // Send message to RDP?
   switch(adsl_session->iec_state_rdp){
      case ied_state_rdp_start:
      case ied_state_rdp_received_capabilities:
      case ied_state_rdp_change_screen_is_send:
         return true;
      default: 
         m_sdh_printf(adsl_sdh_call_1, "xl-rdps-rfbc-3-l%05d-%s %s", inl_line, "E", "Unknown rdp-state");
         return true;

      case ied_state_rdp_finalized:
      case ied_state_rdp_send_change_screen:
         m_rdp_printf(adsl_sdh_call_1, "\nError in VNC-Bridge:\n---------------------------");
         break;
      case ied_state_rdp_finalized_change_screen:
         // Make screen lighter
         dsd_sc_order_patblt* ads_patblt      = adsl_sdh_call_1->adsc_orderqueue->new_command<dsd_sc_order_patblt>();
         ads_patblt->dsc_rectangle.isc_left   = 0;
         ads_patblt->dsc_rectangle.isc_width  = adsl_session->usc_fb_width;
         ads_patblt->dsc_rectangle.isc_top    = 0;
         ads_patblt->dsc_rectangle.isc_height = adsl_session->usc_fb_height;
         ads_patblt->ucc_brop3                = 0xfa;
         ads_patblt->dsc_brush.umc_forecolor  = get_rdpcolor(adsl_session->inc_coldep_rdp, 0x80, 0x80, 0x80);
         ads_patblt->dsc_brush.umc_backcolor  = get_rdpcolor(adsl_session->inc_coldep_rdp, 0x80, 0x80, 0x80);
         ads_patblt->dsc_brush.ucc_brushstyle = 0;
         ads_patblt->boc_has_bounds           = FALSE;
         ads_patblt->boc_update_scrbuf        = FALSE;
         // Now send the frame
         m_rdp_send_splash_screen(adsl_sdh_call_1);
         m_rdp_printf(adsl_sdh_call_1, "Error in VNC-Bridge V %s:\n--------------------------------------------", VERSION_THIS_FILE);
         break;
   }

   // Normal cursor again
   dsd_sc_mpoi_system* ads_mpoi_system = adsl_sdh_call_1->adsc_orderqueue->new_command<dsd_sc_mpoi_system>();
   ads_mpoi_system->iec_system_pointer_type = ied_sysptr_default;

   // Send error to RDP
   if(!bol_admin){
      m_rdp_printf(adsl_sdh_call_1, "%s", chrl_out1);
      return false;
   }

   m_rdp_printf(adsl_sdh_call_1, "%s\nPlease report this error to your administrator.\nfunction: %s, line: %i, iec_srfbc=0x%x.", 
      chrl_out1, achl_function, inl_line, adsl_sdh_call_1->adsc_ctrl_1->iec_srfbc);
   return false;
}


/* subroutine to dump storage-content to console                       */
static void m_sdh_console_out( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                              char *achp_buff, int implength ) {
                                  int        iml1, iml2, iml3, iml4, iml5, iml6;  /* working variable */
                                  char       byl1;                         /* working-variable        */
                                  char       chrlwork1[ 76 ];              /* buffer to print         */

                                  iml1 = 0;
                                  while (iml1 < implength) {
                                      iml2 = iml1 + 16;
                                      if (iml2 > implength) iml2 = implength;
                                      for ( iml3 = 4; iml3 < 75; iml3++ ) {
                                          chrlwork1[iml3] = ' ';
                                      }
                                      chrlwork1[58] = '*';
                                      chrlwork1[75] = '*';
                                      iml3 = 4;
                                      do {
                                          iml3--;
                                          chrlwork1[ iml3 ] = chrstrans[ (iml1 >> ((4 - 1 - iml3) << 2)) & 0X0F ];
                                      } while (iml3 > 0);
                                      iml4 = 6;                              /* start hexa digits here  */
                                      iml5 = 59;                             /* start ASCII here        */
                                      iml6 = 4;                              /* times normal            */
                                      do {
                                          byl1 = achp_buff[ iml1++ ];
                                          chrlwork1[ iml4++ ] = chrstrans[ (byl1 >> 4) & 0X0F ];
                                          chrlwork1[ iml4++ ] = chrstrans[ byl1 & 0X0F ];
                                          iml4++;
                                          if (byl1 > 0X20) {
                                              chrlwork1[ iml5 ] = byl1;
                                          }
                                          iml5++;
                                          iml6--;
                                          if (iml6 == 0) {
                                              iml4++;
                                              iml6 = 4;
                                          }
                                      } while (iml1 < iml2);
                                      m_sdh_printf( adsp_sdh_call_1, "%.*s", sizeof(chrlwork1), chrlwork1 );
                                  }
} /* end m_sdh_console_out()                                           */


/*+--------------------------------------------------------------------------+*/
/*| CLIPBOARD CALLBACKS                                                      |*/
/*+--------------------------------------------------------------------------+*/

/**
 *
 */
static void m_clipboard_callback_format_list(void* avol_usrfld, int inl_number_formats, dsd_format_list_entry* adsl_format_list){
   if (!avol_usrfld)
      return;
   dsd_sdh_call_1* adsl_sdh_call = (dsd_sdh_call_1*) avol_usrfld;
   dsd_gw_ctrl_1* adsl_session = adsl_sdh_call->adsc_ctrl_1;
   adsl_session->inc_rdpclip_state = 0;


   for(int inl1 = 0; inl1 < inl_number_formats; inl1++){
      dsd_format_list_entry* adsl_entry = adsl_format_list + inl1;
      char achr_name[0x100];
      m_sbc_from_u16z(achr_name, 0x100, adsl_entry->awcc_format_name, ied_chs_ansi_819);
      if(adsl_entry->inc_format_id == (int) ied_cf_text){
         adsl_session->inc_rdpclip_state = M_ON_COPY_FMTS_CB;
         // return; 
      }
	}
} /* end m_clipboard_callback_format_list() */

/**
 *
 */
static bool m_clipboard_callback_copy_data_cb(void* avol_usrfld, dsd_gather_reader* adsl_reader){

   dsd_sdh_call_1* adsl_sdh_call = (dsd_sdh_call_1*) avol_usrfld;
   dsd_gw_ctrl_1* adsl_session = adsl_sdh_call->adsc_ctrl_1;

   int inl_num_data = adsl_reader->get_bytes_left();
   int inl_send_data_to_vnc_server = inl_num_data;
   if(inl_send_data_to_vnc_server > adsl_session->inc_max_size_clipbard)
      inl_send_data_to_vnc_server = adsl_session->inc_max_size_clipbard;
   if(adsl_session->dsc_rdpclip_buffer.ensure_elements(inl_send_data_to_vnc_server, 
      m_callback_get_mem, m_callback_free_mem, avol_usrfld) == false)
      return false;
   if(adsl_reader->copy_to(adsl_session->dsc_rdpclip_buffer.get_data(), inl_send_data_to_vnc_server) == false)
      return false;
   if(adsl_reader->skip(inl_num_data - inl_send_data_to_vnc_server) == false)
      return false; 
   adsl_session->inc_rdpclip_num_data = inl_send_data_to_vnc_server;
   adsl_session->inc_rdpclip_state = M_ON_COPY_DATA_CB;
   return true; 
} // static bool m_clipboard_callback_copy_data_cb(void* avo_usrfld, dsd_gather_reader* ads_reader)

/**
 *
 */
static bool m_clipboard_callback_on_paste_cb(void* avol_usrfld, dsd_format_list_entry* adsl_format){
    //DEF_DEBUG_PRINTF("\nm_on_paste_cb");
   dsd_sdh_call_1* adsl_sdh_call = (dsd_sdh_call_1*) avol_usrfld;
   dsd_gw_ctrl_1* adsl_session = adsl_sdh_call->adsc_ctrl_1;
   if(adsl_format->inc_format_id != (int) ied_cf_text){
      adsl_session->inc_rdpclip_state = 0;
      return false; 
   }
   adsl_session->inc_rdpclip_state = M_ON_PASTE_CB;
   return true;   
} // bool m_clipboard_callback_on_paste_cb(void* avol_usrfld, dsd_format_list_entry* adsl_format)

static bool m_clipboard_callback_log(void* avol_usrfld, int inl_lvl, const char *achl_message, int inl_bytes){
   if(inl_lvl < 900)
      return true; 
   dsd_sdh_call_1* adsl_sdh_call = (dsd_sdh_call_1*) avol_usrfld;
   BOOL bol1 = (*adsl_sdh_call->amc_aux)(adsl_sdh_call->vpc_userfld,
        DEF_AUX_CONSOLE_OUT,  /* output to console */
        (void*) achl_message, inl_bytes );
   return bol1;
}

static dsd_sc_vch_out* m_clipboard_callback_get_rdpacc_command(void* avo_usrfld, int inl_bytes){
   dsd_sdh_call_1* adsl_sdh_call = (dsd_sdh_call_1*) avo_usrfld;

   // Get command and additional bytes for gather and for data
   dsd_sc_vch_out* adsl_sc_vch_out = adsl_sdh_call->adsc_orderqueue->new_command<dsd_sc_vch_out>(sizeof(dsd_gather_i_1) + inl_bytes);
   if(adsl_sc_vch_out == NULL)
      return NULL;

   dsd_gather_i_1* ads_gather = (dsd_gather_i_1*)(adsl_sc_vch_out + 1);
   ads_gather->adsc_next      = NULL;
   ads_gather->achc_ginp_cur  = (char*)(ads_gather + 1);
   ads_gather->achc_ginp_end  = ads_gather->achc_ginp_cur + inl_bytes;

   adsl_sc_vch_out->adsc_gai1_out = ads_gather;
   return adsl_sc_vch_out;
}

/*+--------------------------------------------------------------------------+*/
/*| MEMORY CALLBACKS avo_usrfld: dsd_sdh_call, with amc_aux and usrfld set.  |*/
/*+--------------------------------------------------------------------------+*/

static bool m_callback_get_mem(void* avo_usrfld, char** aach_memory, int inl_size){
   dsd_sdh_call_1* adsl_sdh_call = (dsd_sdh_call_1*) avo_usrfld;
   return adsl_sdh_call->amc_aux(adsl_sdh_call->vpc_userfld, DEF_AUX_MEMGET, aach_memory, inl_size) != FALSE;
}
static bool m_callback_free_mem(void* avo_usrfld, void* avol_memory, int inl_size){
   dsd_sdh_call_1* adsl_sdh_call = (dsd_sdh_call_1*) avo_usrfld;
   return adsl_sdh_call->amc_aux(adsl_sdh_call->vpc_userfld, DEF_AUX_MEMFREE, &avol_memory, 0) != FALSE;
}

