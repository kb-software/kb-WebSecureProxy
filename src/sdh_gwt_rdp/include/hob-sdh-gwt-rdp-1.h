#ifndef HOB_SDH_GWT_RDP_1_H
#define HOB_SDH_GWT_RDP_1_H

#ifndef CV_TOUCH_REDIR
#define CV_TOUCH_REDIR 1
#endif

#ifndef DVC_GRAPHICS
#define DVC_GRAPHICS 0
#endif

#ifndef CV_DYN_CHANNEL
#define CV_DYN_CHANNEL (DVC_GRAPHICS || CV_TOUCH_REDIR)
#endif

#ifndef SM_RAIL_CHANNEL
#define SM_RAIL_CHANNEL 1
#endif

#ifndef SM_USE_MULTI_MONITOR
#define SM_USE_MULTI_MONITOR 1
#endif

#ifndef SM_DYNVC_DISP
#define SM_DYNVC_DISP 1
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef HL_UNIX
#include <conio.h>
#endif
#include <time.h>
#ifndef HL_UNIX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif
#ifdef HL_UNIX
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "hob-unix01.h"
#ifdef HL_FREEBSD
#include <netinet/in.h>
#endif
#endif

#include <xercesc/dom/DOMAttr.hpp>
#ifndef HL_LONGLONG
#define DOMNode XERCES_CPP_NAMESPACE::DOMNode
#define DEF_HL_INCL_DOM
#define DEF_HL_INCL_INET
#define DEF_HL_INCL_SSL
#include <hob-xsclib01.h>
#endif
#include <hob-tk-aux-tools-01.h>
#include <hob-tk-gather-tools-01.h>

enum ied_webterm_server_command { /*command from SDH to client*/
	ie_wtsc_rdp_dynchannel_cmd_none = 0xFF,
	ie_wtsc_begin_dod = 2,
	ie_wtsc_rdp_authenticate = 7,
	ie_wtsc_rdp_connect_success,
	ie_wtsc_rdp_connect_failed,
	ie_wtsc_rdp_connect_switch_server,
	ie_wtsc_rdp_initialize_session = 0x10,
	ie_wtsc_rdp_monitor_layout = 0x11,
	ie_wtsc_rdp_monitor_layout_support = 0x12,
	ie_wtsc_rdp_fastpath_updatetype_orders = 0x20,
	ie_wtsc_rdp_fastpath_updatetype_bitmap,
	ie_wtsc_rdp_fastpath_updatetype_palette,
	ie_wtsc_rdp_fastpath_updatetype_synchronize,
	ie_wtsc_rdp_fastpath_updatetype_surfcmds,
	ie_wtsc_rdp_fastpath_updatetype_ptr_null,
	ie_wtsc_rdp_fastpath_updatetype_ptr_default,
	ie_wtsc_rdp_fastpath_updatetype_ptr_position = 0x28,
	ie_wtsc_rdp_fastpath_updatetype_colour,
	ie_wtsc_rdp_fastpath_updatetype_cached,
	ie_wtsc_rdp_fastpath_updatetype_pointer,
	ie_wtsc_rdp_dynchannel_create = 0x81,
	ie_wtsc_rdp_dynchannel_datafirst,
	ie_wtsc_rdp_dynchannel_data,
	ie_wtsc_rdp_dynchannel_close,
	/* ie_wtsc_rdp_dynchannel_capreq,
	ie_wtsc_rdp_dynchannel_datafirst_comp,
	ie_wtsc_rdp_dynchannel_data_comp,
	ie_wtsc_rdp_dynchannel_softsync_request,
	ie_wtsc_rdp_dynchannel_softsync_response,    */
	ie_wtsc_rdpdr_print_document_req = 0x85,
};

struct dsd_sdh_call_1 {                     /* structure call in SDH   */
   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     vpc_userfld;                  /* User Field Subroutine   */
   struct dsd_clib1_contr_1 *adsc_contr_1;  /* for addressing          */
   char       *achc_lower;                  /* lower addr output area  */
   char       *achc_upper;                  /* higher addr output area */
   struct dsd_gather_i_1 **aadsrc_gai1_client;  /* output data to client */
   int        imc_sno;                      /* session number          */
   int        imc_trace_level;              /* WSP trace level         */
#if SM_USE_NLA
   char       chrl_work1[ 32 * 2048 ];      /* work area               */
   char       chrl_work2[ 32 * 2048 ];      /* work area               */
   char       chrl_work3[ 1024 ];           /* work area               */
#endif
   struct dsd_hl_clib_1* adsc_hl_clib_1;
   struct dsd_cc_co1 **  aadsc_cc_co1_ch;
	struct dsd_aux_helper dsc_aux_helper;
	struct dsd_se_co1 *   adsc_se_co1_ch_first;
	struct dsd_se_co1 **  adsc_se_co1_ch_end;
	struct dsd_workarea_chain dsc_wa_chain_extern;
	struct dsd_aux_helper dsc_wa_aux_extern;
	struct dsd_workarea_allocator dsc_wa_alloc_extern;
};

BOOL m_get_new_workarea( struct dsd_sdh_call_1 * );
int m_out_nhasn1( char *achp_out, int imp_number );

#endif /* HOB_SDH_GWT_RDP_1_H */