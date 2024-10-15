#define SM_USE_NLA	1
#define SM_USE_CLIENT_PARAMS	1
#define HOB_TK_NO_INCLUDE	1
#define DEBUG_150221_01                     /* problem gather          */
#define WA_150216_02
//#define PROBLEM_JS_140205
#define PROBLEM_KB_140210
#define PROBLEM_WS_140212

// All changed for the new keyboard implementation are marked by this tag:
#define CV_KEYBOARD


#define DEBUG_WEBSOCKETS 0

//#define TRACEHL2X
/**
   do-to 06.02.14 KB
   configure RDP colour-depth
*/
//#define NO_WT_COMPRESSION
//#define RDP_COMPRESSION
//#define TRY_NO_VIRCH_01                     /* 23.04.12 KB - try without virtual channels */
#define DEBUG_120330_01 10
#define DEBUG_130324_01
//#define TRACEHL1
#define HCOMPR2
//#define TRY_120407_01                       /* ied_clc_conn_fin / Connection Finalization done */
#ifdef DO_TO
16.04.15 KB
XML-configuration error messages - line=%d col=%d
   "sign-on-use-domain",
#endif
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xl-webterm-rdp-01.cpp                               |*/
/*| -------------                                                     |*/
/*|  Server-Data-Hook (SDH) for HOB WebTerm RDP                       |*/
/*|    HTML5 / WebSocket server                                       |*/
/*|  KB 18.10.13                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  GCC all platforms                                                |*/
/*|                                                                   |*/
/*| FUNCTION:                                                         |*/
/*| ---------                                                         |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/* #define TRACEHL1 */

/**
   <single-sign-on>
      none
      insert-userid
      credential-cache
   <RDP-compression-level> 0 / n
   <WebSocket-compression-level> 0 / n
*/

/**
   protocol with JavaScript client

   see HOBTEXT SOFTWARE.HLSEC.WEBTRDP1
   or HOBC02K D:\AKBI62\HOBTEXT\SOFTWARE.HLSEC.WEBTRDP1.act.txt

   load-balancing / VDI

   see HOBTEXT SOFTWARE.HLJWT.IBSELBXX
   or HOBC02K D:\AKBI62\HOBTEXT\SOFTWARE.HLJWT.IBSELBXX.act.txt

   see HOBTEXT SOFTWARE.HLJWT.XSLBGW01
   or HOBC02K SOFTWARE.HLJWT.XSLBGW01.act.txt
*/

#define DEFAULT_WEBSO_COMPR    1            /* default value for <WebSocket-compression-level> */
#define SM_USE_PRINTING		   1
#define SM_RDPDR_CHANNEL		(SM_USE_PRINTING)
// Note: RDPSND channel is required by RDPDR!!! 
#define SM_RDPSND_CHANNEL		(SM_RDPDR_CHANNEL)
#define SM_USE_CONFIG_RDP_CREDENTIALS	1

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

//#define WIN32_LEAN_AND_MEAN

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
/*+-------------------------------------------------------------------+*/
/*| System and library header files for XERCES.                       |*/
/*+-------------------------------------------------------------------+*/
#include <xercesc/dom/DOMAttr.hpp>
#define DOMNode XERCES_CPP_NAMESPACE::DOMNode
#define DEF_HL_INCL_DOM
#define DEF_HL_INCL_INET
#define DEF_HL_INCL_SSL
#include <hob-xsclib01.h>
#include <hob-xslunic1.h>
#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>
#include "hob-stor-sdh.h"
#include <stdint.h>
#include "hob-encry-1.h"
#include "hob-cd-record-1.h"
#include <hob-avl03.h>
#include <hob-http-header-1.h>

#include <hob-sdh-gwt-rdp-1.h>
#include <rdvpn_globals.h>
#if CV_DYN_CHANNEL
#include <hob-webterm-rdp-svc-dynvc.h>
#endif // CV_DYN_CHANNEL

#include <hob-tk-aux-tools-01.h>
#include <hob-tk-gather-tools-01.h>
#include <hob-webterm-rdp-svc.h>

#if SM_RDPDR_CHANNEL
#include <hob-webterm-rdp-svc-rdpdr.h>
#endif /* SM_RDPDR_CHANNEL */

#if SM_RAIL_CHANNEL
#include <hob-webterm-rdp-svc-rail.h>
#endif /* SM_RAIL_CHANNEL */

#if CV_TOUCH_REDIR
#include <hob-dynvc-common.h>
#include <hob-dynvc-input.h>
#endif /* CV_TOUCH_REDIR */

#if DVC_GRAPHICS
#include <hob-dynvc-common.h>
#include <hob-dynvc-graphics.h>
#endif

#ifdef CV_KEYBOARD
#include <string.h>
#include <hob-browser-data.h>
#include <hob-keyboard-handle.h>
#include <hob-proc-mouse-keyboard.h>
#endif /* CV_KEYBOARD */

#if SM_DYNVC_DISP
#include <hob-dynvc-disp.h>
#endif // CV_DYN_CHANNEL

/*+-------------------------------------------------------------------+*/
/*| header files for Server-Data-Hook.                                |*/
/*+-------------------------------------------------------------------+*/

#include "hob-webterm-rdp-01.h"
#ifndef HL_UNIX
#ifndef COMP_J023
#include "hob-wsp-ext-comp-01.h"
//"D:\AKBI62\SOURCE-WSP-23\hob-wsp-ext-comp-01.h"
#else
#include "hob-wsp-ext-comp-01.h"
#endif
#endif
#ifdef HL_UNIX
#include "hob-wsp-ext-comp-01.h"
#endif

#if SM_USE_NLA
#include <hob-ssl-01.h>
#include <hob-cert-ext.h>
#include <hob-ntlm-01.h>
#include <hob-tk-gather-tools-01.h>
#include <hob-rdpclient2.h>
#endif

#if SM_USE_QUICK_LINK
#define HOB_XSLUNIC1_H
#include <ds_hstring.h>
#include <rdvpn_cma_content.h>
#endif

#if SM_RDPDR_CHANNEL
#include <assert.h>
#include <xs-tk-aux-tools-01.cpp>
#include <xs-tk-gather-tools-01.cpp>
#endif /* SM_RDPDR_CHANNEL */

#define SM_USE_GATHER_TRACER	0
#define SM_USE_GATHER_TRACER_REPLAY 0

#if SM_USE_GATHER_TRACER
#include <xs-gather-tracer.hpp>
#endif

#ifdef CV_KEYBOARD
#define HL_WT_JS_VERSION       2            /* version of WT JS client */
#else
#define HL_WT_JS_VERSION       1            /* version of WT JS client */
#endif

#define MAX_INP_GATHER         16           /* number of input gather to be processed */

#if CV_DYN_CHANNEL
#define CV_DYN_CHANNEL_BUFFER_SIZE 1590
#endif /* CV_DYN_CHANNEL*/

#if SM_USE_NLA
#define HL_RDPACC_AUXH(rdpacc) ((rdpacc).dsc_aux)
#define HL_RDPACC_L1(rdpacc) ((rdpacc).dsc_rdpacc)
#else
#define HL_RDPACC_AUXH(rdpacc) rdpacc
#define HL_RDPACC_L1(rdpacc) rdpacc
#endif

#ifdef XYZ1
#define D_M_CDX_ENC m_cdr_dummy_enc
#define D_M_CDX_DEC m_cdr_dummy_dec
#endif

#define D_M_CDX_ENC m_cdr_zlib_1_enc
#define D_M_CDX_DEC m_cdr_zlib_1_dec

#define MAX_EVENTS_MOUSE_KEYB 256

#define M_AWCS_SERVER_1 m_rdpserv_1

#ifndef HL_UNIX
#define D_CHARSET_IP ied_chs_ansi_819       /* ANSI 819                */
#define D_TCP_ERROR WSAGetLastError()
#else
#define D_CHARSET_IP ied_chs_ascii_850      /* ASCII 850               */
#define D_TCP_ERROR errno
#endif

#define D_UCS_INIT_CONST(ucs, string, charset) \
	do { \
		(ucs).iec_chs_str = charset; \
		(ucs).ac_str = (void*)string; \
		(ucs).imc_len_str = HL_CONST_STRING_LEN(string); \
	} while(false)

#define D_UCS_INITIALIZE_U8(string) { (void*)string, sizeof(string)-1, ied_chs_utf_8 }

#define HL_GR_RET_GOTO(call, lbl) if(!(call)) goto lbl
#define HL_INT_ALIGN_TO(length, align) ((length+(align-1))&(~(align-1)))
#define HL_PTR_ALIGN_TO(ptr, align) ((((size_t)ptr)+(align-1))&(~(align-1)))

#define CHAR_CR                0X0D         /* carriage-return         */
#define CHAR_LF                0X0A         /* line-feed               */

#ifndef CV_KEYBOARD
extern "C" int m_proc_mouse_keyboard( char *achp_out, int imp_len_out,
                                      int *aimp_keyboard_mouse,
                                      char *achp_inp, int imp_len_inp );

#endif

enum ied_d_sso_config {                     /* SSO - single-sign-on configuration */
   ied_d_sso_none = 0,                      /* no SSO                  */
   ied_d_sso_insert_userid,                 /* insert-userid           */
   ied_d_sso_cred_cache                     /* credential-cache        */
};

struct dsd_conf_sso_tab {                   /* SSO configuration       */
   const char       *achc_name;
   enum ied_d_sso_config iec_d_sso;         /* SSO - single-sign-on configuration */
};

#if SM_USE_PRINTING
#define HL_DEF_PRINTER_REQUEST_TIMEOUT			10000

struct dsd_clib_conf_printer {
	struct dsd_unicode_string dsc_name;			/* Name of the printer */
	struct dsd_unicode_string dsc_driver_name;	/* Driver name. */
	struct dsd_unicode_string dsc_file_name;	/* File name for HTTP-request. */
	struct dsd_unicode_string dsc_mime_type;	/* Mime type of requested document in HTTP. */
	BOOL boc_default;									/* Default printer flag */
	int imc_request_timeout;						/* HTTP-Request timeout in milliseconds */
};
#endif

#if SM_USE_CONFIG_RDP_CREDENTIALS
struct dsd_clib_conf_rdp_credentials {
	struct dsd_unicode_string dsc_user;
	struct dsd_unicode_string dsc_password;
	struct dsd_unicode_string dsc_password_enc;
	struct dsd_unicode_string dsc_domain;
};
#endif

enum ied_d_start_mode {
	ied_d_start_mode_desktop,
	ied_d_start_mode_rail
};

#if SM_RAIL_CHANNEL
struct dsd_clib_conf_remote_app {
	unsigned short usc_flags;
	struct dsd_unicode_string dsc_exe_or_file;	/* Exe or file */
	struct dsd_unicode_string dsc_working_dir;	/* Working directory */
	struct dsd_unicode_string dsc_arguments;	   /* Arguments */
};
#endif

//position of PerformanceFlags in ucrs_loinf_extra
#define PERFORMANCE_FLAGS_POS 176 

static const unsigned char ucrs_loinf_extra[] = { //partial Extended Info Packet starts with timezone
   0XC4, 0XFF, 0XFF, 0XFF, 0X57, 0X00, 0X2E, 0X00, //TS_TIMEZONE_INFORMATION(172): Bias(4)- -60mins,StandardName(64)(W... .E.u.r.o.p.e. .S.t.a.n.d.a.r.d. .T.i.m.e.)
   0X20, 0X00, 0X45, 0X00, 0X75, 0X00, 0X72, 0X00, //StandardName
   0X6F, 0X00, 0X70, 0X00, 0X65, 0X00, 0X20, 0X00, //StandardName
   0X53, 0X00, 0X74, 0X00, 0X61, 0X00, 0X6E, 0X00, //StandardName
   0X64, 0X00, 0X61, 0X00, 0X72, 0X00, 0X64, 0X00, //StandardName
   0X20, 0X00, 0X54, 0X00, 0X69, 0X00, 0X6D, 0X00, //StandardName
   0X65, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, //StandardName
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, //StandardName
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X0A, 0X00, //StandardName(..4),StandardDate(16):Year(2),Month(2) - Oct-5-03:00:00
   0X00, 0X00, 0X05, 0X00, 0X03, 0X00, 0X00, 0X00, //StandardDate(cont):DayofWeek(2),Day(2),Hour(2),Min(2),
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, //StandardDate(cont):Sec(2),MS(2); StandardBias(4) 
   0X57, 0X00, 0X2E, 0X00, 0X20, 0X00, 0X45, 0X00, //DaylightName(64); W... .E.u.r.o.p.e. .D.a.y.l.i.g.h.t. .T.i.m.e.
   0X75, 0X00, 0X72, 0X00, 0X6F, 0X00, 0X70, 0X00, //DaylightName
   0X65, 0X00, 0X20, 0X00, 0X44, 0X00, 0X61, 0X00, //DaylightName
   0X79, 0X00, 0X6C, 0X00, 0X69, 0X00, 0X67, 0X00, //DaylightName
   0X68, 0X00, 0X74, 0X00, 0X20, 0X00, 0X54, 0X00, //DaylightName
   0X69, 0X00, 0X6D, 0X00, 0X65, 0X00, 0X00, 0X00, //DaylightName
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, //DaylightName
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, //DaylightName
   0X00, 0X00, 0X03, 0X00, 0X00, 0X00, 0X05, 0X00, //DaylightDate(16) Mar-5-:02:00:00
   0X02, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, //DaylightDate(cont)
   0XC4, 0XFF, 0XFF, 0XFF, 0X01, 0X00, 0X00, 0X00, //DaylightBias(4) -60mins -END TS_TIMEZONE_INFORMATION; ClientSessionId(4) !!Should be 0 but is 1 !!
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X64, 0X00, //PerformanceFlags(4),cbAutoReconnectCookie(2),[autoReconnectCookie(0)],reserved1(2) !SHOULD be 0, but MS clients set to 0x64
   0X00, 0X00                                      //reserverd2(2)
}; 



struct dsd_clib1_conf_1 {                   /* structure configuration */
   enum ied_d_sso_config iec_d_sso;         /* SSO - single-sign-on configuration */
   BOOL       boc_so_without_domain;        /* <sign-on-without-domain> */
   int        imc_rdp_compr;                /* <RDP-compression-level> */
   int        imc_webso_compr;              /* <WebSocket-compression-level> */
   int        imc_default_locale;           /* <default-keyboard-layout> */   
#if SM_USE_NLA
   struct dsd_aux_ssl_functions dsc_aux_ssl_functions;
   int        imc_rdp_security_flags;       /* <RDP-security-flags> */
   struct dsd_unicode_string dsc_ssl_config_file;
   struct dsd_unicode_string dsc_ssl_certdb_file;
   struct dsd_unicode_string dsc_ssl_password_file;
   ds__hmem   dsc_hmem;
#endif
#if SM_USE_PRINTING
	struct dsd_clib_conf_printer* adsc_printers;
	int inc_num_printers;
#endif
	enum ied_d_start_mode iec_start_mode;
#if SM_RAIL_CHANNEL
	struct dsd_clib_conf_remote_app* adsc_remote_app;
	int inc_num_remote_apps;
#endif
   BOOL boc_custom_infoextra;
   unsigned char ucrc_loinf_extra[sizeof(ucrs_loinf_extra)];
#if SM_USE_CONFIG_RDP_CREDENTIALS
	struct dsd_clib_conf_rdp_credentials* adsc_rdp_credentials;
#endif
};

#ifdef XYZ1
struct dsd_rdpcs1_session {                 /* structure subroutine session */
   BOOL       boc_start;                    /* start is active         */
   int        imc_ret_len_name;             /* returned length of name in bytes */
};
#endif

#ifdef XYZ1
static const char chrs_start_msg[] =
   "xl-webterm-rdp-01 - Telnet Server to RDP Client\r\n"
   "HOB Server-Data-Hook " __DATE__ "\r\n"
   "s = start RDP session\r\n"
   "--- enter q for quit ---\r\n";

static const unsigned char ucrs_loinf_ineta[] = {
   0X31, 0X00, 0X32, 0X00, 0X37, 0X00, 0X2E, 0X00,
   0X30, 0X00, 0X2E, 0X00, 0X30, 0X00, 0X2E, 0X00,
   0X30, 0X00, 0X2E, 0X00, 0X31, 0X00, 0X00, 0X00
};

static const unsigned char ucrs_loinf_path[] = {
   0X43, 0X00, 0X3A, 0X00, 0X5C, 0X00, 0X57, 0X00,
   0X69, 0X00, 0X6E, 0X00, 0X64, 0X00, 0X6F, 0X00,
   0X77, 0X00, 0X73, 0X00, 0X5C, 0X00, 0X73, 0X00,
   0X79, 0X00, 0X73, 0X00, 0X74, 0X00, 0X65, 0X00,
   0X6D, 0X00, 0X33, 0X00, 0X32, 0X00, 0X5C, 0X00,
   0X6D, 0X00, 0X73, 0X00, 0X74, 0X00, 0X73, 0X00,
   0X63, 0X00, 0X61, 0X00, 0X78, 0X00, 0X2E, 0X00,
   0X64, 0X00, 0X6C, 0X00, 0X6C, 0X00, 0X00, 0X00
};



static const unsigned char ucrs_send_key_t[] = {
   0X00, 0X14, 0X01, 0X14
};
#endif

/* MJ 27.01.09: config structure definition                            */
struct dsd_server {
    char* ach_ip;
    int   in_port;
};

struct dsd_config {
    struct dsd_server ds_server;
};

struct dsd_subaux_userfld {                 /* for aux calls           */
   struct dsd_hl_clib_1 *adsc_hl_clib_1;
};

enum ied_cl_compression {                   /* compression with WebSocket client */
   ied_clcomp_none = 0,                     /* no compression          */
   ied_clcomp_xwdf,                         /* x-webkit-deflate-frame  */
   ied_clcomp_pmd_2                         /* permessage-deflate      */
};

enum ied_stream_pipe_state {
	ied_stream_pipe_state_head = 0,
	ied_stream_pipe_state_write_resp,
};

struct dsd_aux_pipe_stream {
	void* vpc_aux_pipe_handle;
	ied_stream_pipe_state iec_stream_state;
	uint32_t umc_length_total;
	uint32_t umc_length_pending;
};

#if SM_USE_PRINTING
#define HL_RDPDR_MAX_PRINTERS	8
#else
#define HL_RDPDR_MAX_PRINTERS	0
#endif
#define HL_RDPDR_MAX_DEVICES	(HL_RDPDR_MAX_PRINTERS)
#define HL_RDPDR_SIGNALS_START 1
#define HL_RDPDR_SIGNALS_END (HL_RDPDR_SIGNALS_START + HL_RDPDR_MAX_DEVICES)
#define HL_RDPDR_SIGNALS_MASK ((0xFFFFFFFFu)>>(32-HL_RDPDR_MAX_DEVICES))
#define HL_RDPDR_WEBSOCKET_SIGNAL HL_RDPDR_SIGNALS_END

#if SM_RAIL_CHANNEL
#define HL_RDPDR_MAX_REMOTE_APPS	8
#endif

#if SM_RDPDR_CHANNEL
enum ied_rdpdr_device_type {
	ied_rdpdr_device_type_printer,
};

struct dsd_rdpdr_device_context {
	enum ied_rdpdr_device_type iec_device_type;
	struct dsd_svc_rdpdr_message_core_server_device_io_req dsc_pending_device_io_req;
	struct dsd_svc_rdpdr_message_core_server_device_io_req* adsc_pending_device_io_req;
};
#endif /*SM_RDPDR_CHANNEL*/

typedef BOOL (*amd_aux_timer_entry2_proc)(struct dsd_sdh_call_1*, struct dsd_aux_timer_entry2*);

struct dsd_aux_timer_entry2 {
	struct dsd_aux_timer_entry dsc_base;
	amd_aux_timer_entry2_proc amc_proc;
};

#if SM_USE_PRINTING
struct dsd_rdpdr_device_context_printer {
	struct dsd_rdpdr_device_context dsc_device_context;
	void* vpc_aux_pipe_handle;
	struct dsd_aux_timer_entry2 dsc_timer_entry;
	struct dsd_aux_pipe_stream dsc_aux_pipe_stream;
	const struct dsd_clib_conf_printer* adsc_conf_printer;
};
#endif /*SM_USE_PRINTING*/

#if SM_USE_CLIENT_PARAMS
struct dsd_webterm_client_params {
	int imc_default_locale;
	int iml_wt_js_version;
	int imc_wt_js_width;
	int imc_wt_js_height;
	int imc_wt_js_locale_id;
	struct dsd_unicode_string dsl_client_userid;
   struct dsd_unicode_string dsl_client_password;
   struct dsd_unicode_string dsl_client_domain;
	struct dsd_browser_data dsc_browser_data;
};

static int m_parse_webterm_client_params(struct dsd_aux_helper* adsp_aux_helper, char* achl_w1, int iml_len_payload, struct dsd_webterm_client_params* adsp_params);
#endif

#if SM_USE_MULTI_MONITOR
#define HL_RDP_MAX_MONITORS	16
#else
#define HL_RDP_MAX_MONITORS	0
#endif

struct dsd_dvc_disp_ex {
	struct dsd_dvc_disp dsc_dvc;
	struct dsd_dynvc_listener dsc_super;
};

struct dsd_dynvc_command2 {
	struct dsd_dynvc_command dsc_base;
	struct dsd_sdh_call_1* adsc_output_area_1;
};

struct dsd_clib1_contr_1 {                  /* structure session control */
   BOOL       boc_started;                  /* connection to client has been started */
   BOOL       boc_conn_close_sent;          /* has already sent connection close */
   char       chrc_ws_mask[ 4 ];            /* mask for WebSocket input */
   enum ied_cl_compression iec_clcomp;      /* compression with client WebSocket */
   struct dsd_aux_webso_conn_1 dsc_awc1;    /* connect for WebSocket applications */
	struct dsd_sdh_ident_set_1 dsc_sdh_ident_set_1; /* user identity for this SDH session */
   int        imc_wt_js_width;              /* WT-JS screen width      */
   int        imc_wt_js_height;             /* WT-JS screen height     */
#ifdef CV_KEYBOARD
   int      imc_wt_js_locale_id;            /* WT-JS locale id         */
   struct   dsd_browser_data dsc_browser_data;  /* Browser Data        */
#endif /* CV_KEYBOARD */
#if SM_USE_NLA
   void*      vpc_ssl_config;
   struct dsd_gssapi_ntlm_params_01 dsc_ntlm_params;
   struct dsd_gssapi_credssp_params_01 dsc_credssp_params;
   struct dsd_gssapi_ntlm_01 dsc_ntlm;
   struct dsd_unicode_string dsc_client_userid;
   struct dsd_unicode_string dsc_client_password;
   struct dsd_unicode_string dsc_client_domain;
#endif
#if SM_USE_QUICK_LINK
   struct dsd_webtermrdp_sid* adsc_sid_data;
#endif
	struct dsd_aux_timer_handler dsc_timer_handler;

   int        imc_wts_port;                 /* port of the WSP         */
   int        imc_len_wts_ineta;            /* length of INETA WTS     */
   char       chrc_wts_ineta[ 16 ];         /* INETA IPV4 / IPV6 to connect to */
   struct dsd_se_switch_server *adsc_se_switch_server;  /* switch to other RDP server - session broker */
   char       *achc_rdp_cred;               /* RDP credentials         */
#ifdef XYZ1
   struct dsd_call_rdpclient_1 dsc_c_rdp_cl_1;  /* pass parameters to RDP client */
// struct dsd_call_rdpserv_1 dsc_c_rdp_se_1;  /* pass parameters to RDP server */
   struct dsd_call_awcs_server_1 dsc_c_awcs_se_1;  /* call abstrace window call syntax (RDP / HTML5) Server 1 */
#endif
#if SM_USE_NLA
   struct dsd_call_rdpclient_2 dsc_c_wtrc1;
#else
   struct dsd_call_wt_rdp_client_1 dsc_c_wtrc1;  /* pass parameters to RDP client */
#endif
#ifdef XYZ1
   struct dsd_rdp_vc_1 *adsc_rdp_vc_1_client;  /* RDP virtual channel  */
#endif
   struct dsd_cdr_ctrl dsc_cdrf_dec;        /* compress data record oriented control - decode, input */
   struct dsd_cdr_ctrl dsc_cdrf_enc;        /* compress data record oriented control - encode, output */

#ifdef CV_KEYBOARD
   struct dsd_keyboard_data dsc_keyboard_data;  /* keyboard information */
#endif /* CV_KEYBOARD */

   //RDP ACC Channels
   struct dsd_rdp_vc_1 dsrc_rdpacc_svc[4];    /* RDP-ACC static channels */
#if CV_DYN_CHANNEL
   // Static Channels Extensions
   struct dsd_dynvc_context dsc_svc_drdynvc;      /* extension for the "DRDYNVC" static virtual channel */

    //RDP ACC Channels
   struct dsd_rdp_vc_1 *adsp_rdpacc_drdynvc;    /* RDP-ACC channel for "DRDYNVC" */

#if CV_TOUCH_REDIR
	struct dsd_dynvc_create_listener dsc_dvc_create_listener_input;
   // Dynamic Channel Extensions
   struct dsd_dvc_input dsc_dvc_input_ex;   /* entension for the RDPEI dynamic virtual channel (touch/pen) */

   // Dynamic Channel Listeners
   //struct dsd_dynvc_listener dsc_dvc_input_listener;  /* client listener for the RDPEI dynamic virtual channel */

#endif /* CV_TOUCH_REDIR */

#if DVC_GRAPHICS
	struct dsd_dynvc_create_listener dsc_dvc_create_listener_graphics;
   struct dsd_dvc_graphics dsc_dvc_graphics_ex;
 
#endif

#endif /* CV_DYN_CHANNEL */

#if SM_RDPDR_CHANNEL
   struct dsd_svc_rdpdr dsc_svc_rdpdr;
   struct dsd_rdp_vc_1* adsp_rdpacc_rdpdr;
   uint32_t umc_total_length;
	uint32_t umc_pending_length;
	struct dsd_rdpdr_device_context* adsrc_rdpdr_devices[HL_MAX(HL_RDPDR_MAX_DEVICES, 1)];
	int imc_num_devices;
	struct dsd_rdpdr_device_context* adsc_pending_device;
#endif
#if SM_USE_PRINTING
	struct dsd_rdpdr_device_context_printer dsrc_rdpdr_printing_devices[HL_RDPDR_MAX_PRINTERS];
#endif

#if SM_RDPDR_CHANNEL
   struct dsd_rdp_vc_1* adsp_rdpacc_rdpsnd;
#endif

	enum ied_d_start_mode iec_start_mode;
#if SM_RAIL_CHANNEL
   struct dsd_svc_rail dsc_svc_rail;
   struct dsd_rdp_vc_1* adsp_rdpacc_rail;
#endif

#if SM_USE_MULTI_MONITOR
	int imc_monitor_count;
	struct dsd_ts_monitor_def dsrc_ts_monitor[HL_RDP_MAX_MONITORS];
	struct dsd_ts_monitor_attributes dsrc_ts_monitor_attributes[HL_RDP_MAX_MONITORS];
#endif

#if SM_DYNVC_DISP
	struct dsd_dynvc_create_listener dsc_dvc_create_listener_disp;
	struct dsd_dvc_disp_ex dsc_dvc_disp;
#endif

   int        imc_len_client_ineta;         /* length INETA client     */
   char       chrc_client_ineta[ 128 ];     /* INETA to be passed      */
#ifdef TRY_120407_01                        /* ied_clc_conn_fin / Connection Finalization done */
   BOOL       boc_flag1;
#endif
#if SM_USE_GATHER_TRACER
	dsd_gather_tracer dsc_compress_to_client;
#endif
};

enum ied_proc_cont {                        /* continue in program     */
   ied_pc_idle = 0,                         /* nothing to do           */
   ied_pc_start_client,                     /* start the RDP client    */
   ied_pc_act_pdu_client                    /* send confirm active PDU to the RDP server */
};


static int m_get_number( const HL_WCHAR *awcp_input, int inp_max_digits );
static int m_get_unicode_number( const HL_WCHAR *awcp_input );
static BOOL m_reply_http( struct dsd_sdh_call_1 *, char *, int );
static BOOL m_send_websocket_data( struct dsd_sdh_call_1 *, struct dsd_clib1_contr_1 *, struct dsd_wt_record_1 * );
static BOOL m_send_websocket_error(struct dsd_sdh_call_1* adsp_output_area_1, int imp_flags, const char* strp_msg, int inp_msg_len);
static BOOL m_send_websocket_rdp_synchronize(struct dsd_sdh_call_1* adsp_output_area_1);
static BOOL m_send_websocket_monitor_layout(struct dsd_sdh_call_1* adsp_output_area_1, const struct dsd_sc_monitor_layout_pdu* adsp_layout);

static BOOL m_sub_aux( void * vpp_userfld, int imp_func, void * ap_param, int imp_length );
static int m_sdh_printf( struct dsd_sdh_call_1 *, const char *, ... );
static int m_sdh_printf2(void* avop_ptr, const char *achptext, ... ) ;
static int m_get_date_time( char *achp_buff );
static void m_sdh_console_out( struct dsd_sdh_call_1 *, char *achp_buff, int implength );
static void m_dump_gather( struct dsd_sdh_call_1 *, struct dsd_gather_i_1 *, int );
#if SM_USE_NLA
static BOOL m_read_single_signon_credentials(struct dsd_hl_clib_1 *adsp_hl_clib_1, struct dsd_sdh_call_1 * adsp_output_area_1);
static unsigned int m_get_inclusive_hasn1_uint32_be(unsigned int im_val);
#endif

#if SM_RDPDR_CHANNEL
static BOOL m_rdpdr_device_cleanup_printer(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_rdpdr_device_context_printer* adsp_printer);
static BOOL m_rdpdr_device_cleanup(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_rdpdr_device_context* adsp_device);
static BOOL m_rdpdr_process_irp_create(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_svc_rdpdr_message_core_server_device_io_req* adsp_devio_req);
static BOOL m_rdpdr_process_irp_write(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_gather_i_1_pos* adsp_pos);
static BOOL m_rdpdr_process_irp_device_control(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_gather_i_1_pos* adsp_pos);
static BOOL m_rdpdr_process_irp_close(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_svc_rdpdr_message_core_server_device_io_req* adsp_devio_req);
static BOOL m_stream_pipe_handle_signal(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_rdpdr_device_context* adsl_device);
static BOOL m_rdpdr_send_commands(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_svc_rdpdr_command* adsp_commands, int inp_num_commands);
#endif

#if SM_RAIL_CHANNEL
static BOOL m_rail_send_commands(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_svc_rail_command* adsp_commands, int inp_num_commands);
static BOOL m_rail_start_remote_app(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_clib_conf_remote_app& dsl_remote_app);
#endif

#if DVC_GRAPHICS
static struct dsd_channel_context* m_dynvc_create_graphics(struct dsd_dynvc_create_listener* avop_this, struct dsd_dynvc_create_context* adsp_context);
#endif

#if CV_TOUCH_REDIR
static struct dsd_channel_context* m_dynvc_create_input(struct dsd_dynvc_create_listener* avop_this, struct dsd_dynvc_create_context* adsp_context);
#endif

#if SM_DYNVC_DISP
static struct dsd_channel_context* m_dynvc_create_disp(struct dsd_dynvc_create_listener* avop_this, struct dsd_dynvc_create_context* adsp_context);
static BOOL m_monitor_layout_changed(struct dsd_sdh_call_1* adsp_output_area_1, const char* achl_w1, int iml_len_payload);
#endif

#ifdef XYZ1
static struct dsd_conf_rdpserv_1 dss_conf_rdpserv_1 = { 1 };  /* configuration RDP Server 1 */
#endif

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

enum ied_conf_parameter {
	iec_conf_single_sign_on,
	iec_conf_sign_on_without_domain,
	iec_conf_sign_on_use_domain,
	iec_conf_rdp_compression_level,
	iec_conf_websocket_compression_level,
	iec_conf_default_keyboard_layout,
	iec_conf_rdp_performance_flags,
#if SM_USE_NLA
	iec_conf_rdp_security_flags,
	iec_conf_ssl_config_file,
	iec_conf_ssl_certdb_file,
	iec_conf_ssl_password_file,
#endif
#if SM_USE_PRINTING
	iec_conf_printer,
#endif
	iec_conf_start_mode,
#if SM_RAIL_CHANNEL
	iec_conf_remote_app,
#endif
#if SM_USE_CONFIG_RDP_CREDENTIALS
	iec_conf_rdp_credentials,
#endif
};

#if SM_USE_PRINTING
enum ied_conf_parameter_printer {
	iec_conf_printer_name,
	iec_conf_printer_driver_name,
	iec_conf_printer_file_name,
	iec_conf_printer_mime_type,
	iec_conf_printer_default,
	iec_conf_printer_request_timeout,
};
#endif

#if SM_RAIL_CHANNEL
enum ied_conf_parameter_remote_app {
	iec_conf_remote_app_flags,
	iec_conf_remote_app_exe_or_file,
	iec_conf_remote_app_working_dir,
	iec_conf_remote_app_arguments,
};
#endif

#if SM_USE_CONFIG_RDP_CREDENTIALS
enum ied_conf_parameter_rdp_credentials {
	iec_conf_rdp_credentials_user,
	iec_conf_rdp_credentials_password,
	iec_conf_rdp_credentials_password_enc,
	iec_conf_rdp_credentials_domain,
};
#endif

struct dsd_conf_parameter {
	struct dsd_unicode_string dsc_key;
	int iec_type;
};

static const HL_WCHAR dss_wchar_empty_string[] = { 0 };

static struct dsd_conf_parameter dss_node_conf[] = {
	{D_UCS_INITIALIZE_U8("single-sign-on"), iec_conf_single_sign_on},
	{D_UCS_INITIALIZE_U8("sign-on-without-domain"), iec_conf_sign_on_without_domain},
	{D_UCS_INITIALIZE_U8("sign-on-use-domain"), iec_conf_sign_on_use_domain},
	{D_UCS_INITIALIZE_U8("RDP-compression-level"), iec_conf_rdp_compression_level},
	{D_UCS_INITIALIZE_U8("WebSocket-compression-level"), iec_conf_websocket_compression_level},
	{D_UCS_INITIALIZE_U8("default-keyboard-layout"), iec_conf_default_keyboard_layout},
	{D_UCS_INITIALIZE_U8("RDP-performance-flags"), iec_conf_rdp_performance_flags},
#if SM_USE_NLA
	{D_UCS_INITIALIZE_U8("RDP-security-flags"), iec_conf_rdp_security_flags},
	{D_UCS_INITIALIZE_U8("SSL-config-file"), iec_conf_ssl_config_file},
	{D_UCS_INITIALIZE_U8("SSL-certdb-file"), iec_conf_ssl_certdb_file},
	{D_UCS_INITIALIZE_U8("SSL-password-file"), iec_conf_ssl_password_file},
#endif
#if SM_USE_PRINTING
	{D_UCS_INITIALIZE_U8("printer"), iec_conf_printer},
#endif
	{D_UCS_INITIALIZE_U8("start-mode"), iec_conf_start_mode},
#if SM_RAIL_CHANNEL
	{D_UCS_INITIALIZE_U8("remote-app"), iec_conf_remote_app},
#endif
	{D_UCS_INITIALIZE_U8("remote-app"), iec_conf_remote_app},
#if SM_USE_CONFIG_RDP_CREDENTIALS
	{D_UCS_INITIALIZE_U8("RDP-credentials"), iec_conf_rdp_credentials},
#endif
};

#if SM_USE_PRINTING
static struct dsd_conf_parameter dss_node_conf_printer[] = {
	{D_UCS_INITIALIZE_U8("name"), iec_conf_printer_name},
	{D_UCS_INITIALIZE_U8("driver-name"), iec_conf_printer_driver_name},
	{D_UCS_INITIALIZE_U8("file-name"), iec_conf_printer_file_name},
	{D_UCS_INITIALIZE_U8("mime-type"), iec_conf_printer_mime_type},
	{D_UCS_INITIALIZE_U8("default"), iec_conf_printer_default},
	{D_UCS_INITIALIZE_U8("request-timeout"), iec_conf_printer_request_timeout},
};
#endif

#if SM_RAIL_CHANNEL
static struct dsd_conf_parameter dss_node_conf_remote_app[] = {
	{D_UCS_INITIALIZE_U8("flags"), iec_conf_remote_app_flags},
	{D_UCS_INITIALIZE_U8("exe-or-file"), iec_conf_remote_app_exe_or_file},
	{D_UCS_INITIALIZE_U8("working-dir"), iec_conf_remote_app_working_dir},
	{D_UCS_INITIALIZE_U8("arguments"), iec_conf_remote_app_arguments},
};
#endif

#if SM_USE_CONFIG_RDP_CREDENTIALS
static struct dsd_conf_parameter dss_node_conf_rdp_credentials[] = {
	{D_UCS_INITIALIZE_U8("user"), iec_conf_rdp_credentials_user},
	{D_UCS_INITIALIZE_U8("password"), iec_conf_rdp_credentials_password},
	{D_UCS_INITIALIZE_U8("password-encrypted"), iec_conf_rdp_credentials_password_enc},
	{D_UCS_INITIALIZE_U8("domain"), iec_conf_rdp_credentials_domain},
};
#endif

static const struct dsd_conf_sso_tab dsrs_conf_sso_tab[] = {  /* SSO configuration */
   {
     "none",
     ied_d_sso_none                         /* no SSO                  */
   },
   {
     "insert-userid",
     ied_d_sso_insert_userid                /* insert-userid           */
   },
   {
     "credential-cache",
     ied_d_sso_cred_cache                   /* credential-cache        */
   }
};

static const struct dsd_proc_http_header_server_1 dss_phhs1 = {
   NULL,                                    /* amc_stor_alloc - storage container allocate memory */
   NULL,                                    /* amc_stor_free - storage container free memory */
   TRUE,                                    /* boc_consume_input - consume input */
   FALSE,                                   /* boc_store_cookies - store cookies */
   FALSE                                    /* boc_out_os - output fields for other side */
};

static const unsigned char ucrs_http_reply_01[] = {
   'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '1', '0', '1', ' ', 'S', 'w', 'i',
   't', 'c', 'h', 'i', 'n', 'g', ' ', 'P', 'r', 'o', 't', 'o', 'c', 'o', 'l', 's',
   CHAR_CR, CHAR_LF,
   'U', 'p', 'g', 'r', 'a', 'd', 'e', ':', ' ', 'w', 'e', 'b', 's', 'o',
   'c', 'k', 'e', 't',
   CHAR_CR, CHAR_LF,
   'C', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n',
   ':', ' ', 'U', 'p', 'g', 'r', 'a', 'd', 'e',
   CHAR_CR, CHAR_LF,
   'S', 'e', 'c', '-', 'W',
   'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '-', 'A', 'c', 'c', 'e', 'p', 't', ':',
   ' '
};

static const unsigned char ucrs_http_reply_02[] = {
   CHAR_CR, CHAR_LF,
   'S',
   'e', 'c', '-', 'W', 'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '-', 'P', 'r', 'o',
   't', 'o', 'c', 'o', 'l', ':', ' ',
   'w', 'e', 'b', 't', 'e', 'r', 'm', '0', '1', '.', 'h', 'o', 'b', 's', 'o', 'f',
   't', '.', 'c', 'o', 'm',
   CHAR_CR, CHAR_LF,
   CHAR_CR, CHAR_LF
};

static const unsigned char ucrs_http_reply_03[] = {
   CHAR_CR, CHAR_LF,
   'S',
   'e', 'c', '-', 'W', 'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '-', 'P', 'r', 'o',
   't', 'o', 'c', 'o', 'l', ':', ' ',
   'w', 'e', 'b', 't', 'e', 'r', 'm', '0', '1', '.', 'h', 'o', 'b', 's', 'o', 'f',
   't', '.', 'c', 'o', 'm',
   CHAR_CR, CHAR_LF,
   'S', 'e', 'c', '-', 'W', 'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '-',
   'E', 'x', 't', 'e', 'n', 's', 'i', 'o', 'n', 's', ':', ' ',
   'x', '-', 'w', 'e', 'b', 'k', 'i', 't', '-', 'd', 'e', 'f', 'l', 'a', 't', 'e', '-', 'f', 'r', 'a', 'm', 'e',
   CHAR_CR, CHAR_LF,
   CHAR_CR, CHAR_LF
};

#ifdef XYZ1
static const unsigned char ucrs_http_reply_04[] = {
   CHAR_CR, CHAR_LF,
   'S',
   'e', 'c', '-', 'W', 'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '-', 'P', 'r', 'o',
   't', 'o', 'c', 'o', 'l', ':', ' ',
   'w', 'e', 'b', 't', 'e', 'r', 'm', '0', '1', '.', 'h', 'o', 'b', 's', 'o', 'f',
   't', '.', 'c', 'o', 'm',
   CHAR_CR, CHAR_LF,
   'S', 'e', 'c', '-', 'W', 'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '-',
   'E', 'x', 't', 'e', 'n', 's', 'i', 'o', 'n', 's', ':', ' ',
   'p', 'e', 'r', 'm', 'e', 's', 's', 'a', 'g', 'e', '-', 'd', 'e', 'f', 'l', 'a', 't', 'e', ';', ' ',
   'c', 'l', 'i', 'e', 'n', 't', '_', 'm', 'a', 'x', '_', 'w', 'i', 'n', 'd', 'o', 'w', '_', 'b', 'i', 't', 's',
   CHAR_CR, CHAR_LF,
   CHAR_CR, CHAR_LF
};
#endif
static const unsigned char ucrs_http_reply_04[] = {
   CHAR_CR, CHAR_LF,
   'S',
   'e', 'c', '-', 'W', 'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '-', 'P', 'r', 'o',
   't', 'o', 'c', 'o', 'l', ':', ' ',
   'w', 'e', 'b', 't', 'e', 'r', 'm', '0', '1', '.', 'h', 'o', 'b', 's', 'o', 'f',
   't', '.', 'c', 'o', 'm',
   CHAR_CR, CHAR_LF,
   'S', 'e', 'c', '-', 'W', 'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '-',
   'E', 'x', 't', 'e', 'n', 's', 'i', 'o', 'n', 's', ':', ' ',
   'p', 'e', 'r', 'm', 'e', 's', 's', 'a', 'g', 'e', '-', 'd', 'e', 'f', 'l', 'a', 't', 'e',
   CHAR_CR, CHAR_LF,
   CHAR_CR, CHAR_LF
};

static const unsigned char ucrs_websocket_reply_key[] = {
   '2', '5', '8', 'E', 'A', 'F', 'A', '5', '-', 'E', '9', '1', '4', '-', '4', '7',
   'D', 'A', '-', '9', '5', 'C', 'A', '-', 'C', '5', 'A', 'B', '0', 'D', 'C', '8',
   '5', 'B', '1', '1'
};

static const char chrs_cma_pwd_prefix[] = {
  'U', 'S', 'E', 'R', '-', 'P', 'W', 'D', 0
};

enum ied_parameter_type {
	iec_parameter_type_integer,
	iec_parameter_type_utf8_string
};

struct dsd_parameter {
	const char* achc_name;
	int inc_len;
	ied_parameter_type iec_type;
};

#if 0
static const char * achrs_wt_js_first[] = {
   "version",
   "width",
   "height",
#ifdef CV_KEYBOARD
   "locale",
   "useragent",
   "platform"
#endif /* CV_KEYBOARD */
};
#endif

static dsd_parameter dss_wt_js_first[] = {
	{"version", sizeof("version")-1, iec_parameter_type_integer},
	{"width", sizeof("width")-1, iec_parameter_type_integer},
	{"height", sizeof("height")-1, iec_parameter_type_integer},
#ifdef CV_KEYBOARD
	{"locale", sizeof("locale")-1, iec_parameter_type_integer},
	{"useragent", sizeof("useragent")-1, iec_parameter_type_utf8_string},
	{"platform", sizeof("platform")-1, iec_parameter_type_utf8_string},
#endif /* CV_KEYBOARD */
#if SM_USE_NLA
	{"userid", sizeof("userid")-1, iec_parameter_type_utf8_string},
	{"password", sizeof("password")-1, iec_parameter_type_utf8_string},
	{"domain", sizeof("domain")-1, iec_parameter_type_utf8_string},
#endif
};

static const unsigned char chrs_lbal_01[] = {
   0X0F,                     /* length following data including length */
   0X48, 0X4F, 0X42, 0X20, 0X4C, 0X42, 0X00, 0X51, 0X00,
   0X02, 0X00,
   0X03, 0X40, 0X03
};

static struct dsd_cc_co1 dss_cc_co1_start_client = {
   NULL,
   ied_ccc_start_rdp_client                 /* start the RDP client    */
};


/*
double definition!!
static const unsigned char ucrs_loinf_extra[] = {
   0XC4, 0XFF, 0XFF, 0XFF, 0X57, 0X00, 0X2E, 0X00,
   0X20, 0X00, 0X45, 0X00, 0X75, 0X00, 0X72, 0X00,
   0X6F, 0X00, 0X70, 0X00, 0X65, 0X00, 0X20, 0X00,
   0X53, 0X00, 0X74, 0X00, 0X61, 0X00, 0X6E, 0X00,
   0X64, 0X00, 0X61, 0X00, 0X72, 0X00, 0X64, 0X00,
   0X20, 0X00, 0X54, 0X00, 0X69, 0X00, 0X6D, 0X00,
   0X65, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X0A, 0X00,
   0X00, 0X00, 0X05, 0X00, 0X03, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X57, 0X00, 0X2E, 0X00, 0X20, 0X00, 0X45, 0X00,
   0X75, 0X00, 0X72, 0X00, 0X6F, 0X00, 0X70, 0X00,
   0X65, 0X00, 0X20, 0X00, 0X44, 0X00, 0X61, 0X00,
   0X79, 0X00, 0X6C, 0X00, 0X69, 0X00, 0X67, 0X00,
   0X68, 0X00, 0X74, 0X00, 0X20, 0X00, 0X54, 0X00,
   0X69, 0X00, 0X6D, 0X00, 0X65, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X03, 0X00, 0X00, 0X00, 0X05, 0X00,
   0X02, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0XC4, 0XFF, 0XFF, 0XFF, 0X01, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X64, 0X00,
   0X00, 0X00
};*/

static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

#ifdef DEBUG_120330_01
static int ims_debug_1_01;
#endif

static const struct dsd_conf_parameter* m_find_conf_parameter(const struct dsd_conf_parameter* adsrp_params, int inp_num_params, const HL_WCHAR* achp_key) {
	for(int inl_p=0; inl_p<inp_num_params; inl_p++) {
		struct dsd_unicode_string dsl_tmp;
		dsl_tmp.ac_str = (void*)achp_key;
		dsl_tmp.imc_len_str = -1;
		dsl_tmp.iec_chs_str = ied_chs_utf_16;
		int iml_cmp;
		BOOL bol1 = m_cmp_ucs_ucs( &iml_cmp, &dsl_tmp, &adsrp_params[inl_p].dsc_key );
		if(!bol1)
			return NULL;
	   if (iml_cmp == 0)
			return &adsrp_params[inl_p];
   }
	return NULL;
}

static int m_get_bool(const HL_WCHAR* achp_value, int inp_default) {
	int iml_cmp;
	BOOL bol_rc = m_cmp_vx_vx( &iml_cmp,
                           achp_value, -1, ied_chs_utf_16,  /* Unicode UTF-16 = WCHAR */
                           "YES", -1, ied_chs_utf_8 );  /* Unicode UTF-8 */
   if (bol_rc && (iml_cmp == 0)) {
		return TRUE;
   }
   bol_rc = m_cmp_vx_vx( &iml_cmp,
                        achp_value, -1, ied_chs_utf_16,  /* Unicode UTF-16 = WCHAR */
                        "NO", -1, ied_chs_utf_8 );  /* Unicode UTF-8 */
   if (bol_rc && (iml_cmp == 0)) {
		return FALSE;
   }
	return inp_default;
}

static BOOL m_ucs_ensure_length(struct dsd_unicode_string* adsp_value) {
	if(adsp_value->imc_len_str >= 0)
		return TRUE;
	if(adsp_value->ac_str == NULL) {
		adsp_value->imc_len_str = 0;
		return TRUE;
	}
	int inl_value = m_len_vx_ucs(adsp_value->iec_chs_str, adsp_value);
	if(inl_value < 0)
		return FALSE;
	adsp_value->imc_len_str = inl_value;
	return TRUE;
}

static BOOL m_is_ucs_null_or_empty(const struct dsd_unicode_string* adsp_value) {
	if(adsp_value->ac_str == NULL)
		return TRUE;
	int inl_value = m_len_vx_ucs(adsp_value->iec_chs_str, adsp_value);
	if(inl_value <= 0)
		return TRUE;
	return FALSE;
}

static int m_len_bytes_ucs_no_zero(const struct dsd_unicode_string* adsp_value) {
	int inl_element_size = m_cs_elem_size(adsp_value->iec_chs_str);
	if(adsp_value->imc_len_str >= 0) {
		return adsp_value->imc_len_str * inl_element_size;
	}
	int inl_value = m_len_vx_ucs(adsp_value->iec_chs_str, adsp_value);
	if(inl_value < 0)
		return -1;
	return inl_value * inl_element_size;
}

static char* m_cpy_string2(char* achl_extra, char* achl_extra2, struct dsd_unicode_string* adsp_dst, enum ied_charset iec_chs_dst, struct dsd_unicode_string* adsp_src) {
	if(adsp_src->ac_str == NULL) {
		adsp_dst->iec_chs_str = iec_chs_dst;
		adsp_dst->ac_str = NULL;
		adsp_dst->imc_len_str = 0;
		return achl_extra;
	}
	int inl_elem_size = m_get_chs_unit_size(iec_chs_dst);
	int iml2 = m_cpy_vx_ucs(
		achl_extra, (achl_extra2-achl_extra)/inl_elem_size, iec_chs_dst, adsp_src);
	if(iml2 < 0) {
		return NULL;
	}
	adsp_dst->iec_chs_str = iec_chs_dst;
	adsp_dst->ac_str = achl_extra;
	adsp_dst->imc_len_str = iml2;
	achl_extra += iml2 * inl_elem_size;
	return achl_extra;
}

static char* m_cpy_string(char* achl_extra, char* achl_extra2, struct dsd_unicode_string* adsp_dst, struct dsd_unicode_string* adsp_src) {
	return m_cpy_string2(achl_extra, achl_extra2, adsp_dst, adsp_src->iec_chs_str, adsp_src);
}

#define HL_UCS_INIT_UTF8_EMPTY(ucs) \
	do { \
		(ucs)->ac_str = NULL; \
		(ucs)->imc_len_str = 0; \
	   (ucs)->iec_chs_str = ied_chs_utf_8; \
	} while(false)

/** subroutine to process the configuration data                       */
extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf( struct dsd_hl_clib_dom_conf *adsp_hlcldomf ) {
   BOOL       bol_rc;                       /* return code             */
   BOOL       bol1, bol2;                   /* working variables       */
   int        iml_cmp;                      /* compare values          */
   int        iml1;                         /* working variable        */
   BOOL       borl_double[sizeof(dss_node_conf) / sizeof(dss_node_conf[0])]; /* check if defined double */
   int        iml_val;                      /* value in array          */
   DOMNode    *adsl_node_1;                 /* node for navigation     */
   DOMNode    *adsl_node_2;                 /* node for navigation     */
   const HL_WCHAR   *awcl1;                 /* working variable        */
   const HL_WCHAR   *awcl_value;            /* value of Node           */
   struct dsd_sdh_call_1 dsl_output_area_1;  /* SDH call structure     */
   struct dsd_clib1_conf_1 dsl_cc_l;        /* configuration           */
   struct dsd_unicode_string dsrl_ssl_client[3];
#if SM_USE_PRINTING
	struct dsd_clib_conf_printer dsrl_printers[HL_RDPDR_MAX_PRINTERS];
	int inl_num_printers = 0;
	int inl_printer_extra_len = 0;
#endif
#if SM_RAIL_CHANNEL
	struct dsd_clib_conf_remote_app dsrl_remote_apps[HL_RDPDR_MAX_REMOTE_APPS];
	int inl_num_remote_apps = 0;
	int inl_remote_app_extra_len = 0;
#endif
#if SM_USE_CONFIG_RDP_CREDENTIALS
	struct dsd_clib_conf_rdp_credentials dsl_rdp_credentials;
	struct dsd_clib_conf_rdp_credentials* adsl_rdp_credentials = NULL;
	int inl_rdp_credentials_extra_len = 0;
#endif

#ifdef TRACEHL1
   printf( "xl-webterm-rdp-01-l%05d-T m_hlclib_conf() called adsp_hlcldomf=%p.\n",
           __LINE__, adsp_hlcldomf );
#endif
   dsl_output_area_1.amc_aux = adsp_hlcldomf->amc_aux;  /* auxiliary subroutine */
   dsl_output_area_1.vpc_userfld = adsp_hlcldomf->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-I V1.1 " __DATE__ " m_hlclib_conf() called - WT-JS client version %d.",
                 __LINE__, HL_WT_JS_VERSION );

   if (adsp_hlcldomf->adsc_node_conf == NULL) {
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_hlclib_conf() no Node configured",
                   __LINE__ );
     return TRUE;
   }

   /* getFirstChild()                                                  */
   adsl_node_1 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsp_hlcldomf->adsc_node_conf,
                                                          ied_hlcldom_get_first_child );
   if (adsl_node_1 == NULL) {               /* no Node returned        */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_hlclib_conf() no getFirstChild()",
                   __LINE__ );
     return FALSE;
   }

   memset( &dsl_cc_l, 0, sizeof(struct dsd_clib1_conf_1) );  /* configuration */
   dsl_cc_l.imc_default_locale = 1033;//use US as default to avoid uncertain states - but should be set in config or by client
	dsl_cc_l.iec_start_mode = ied_d_start_mode_desktop;
#ifdef XYZ1
   awcl_file_vch_serv = NULL;               /* reset file virus-checking service name */
#endif
   memset( borl_double, 0, sizeof(borl_double) );  /* reset check if defined double */
#if SM_USE_NLA
	HL_UCS_INIT_UTF8_EMPTY(&dsrl_ssl_client[0]);
	HL_UCS_INIT_UTF8_EMPTY(&dsrl_ssl_client[1]);
	HL_UCS_INIT_UTF8_EMPTY(&dsrl_ssl_client[2]);
#endif
#if SM_USE_CONFIG_RDP_CREDENTIALS
	HL_UCS_INIT_UTF8_EMPTY(&dsl_rdp_credentials.dsc_user);
	HL_UCS_INIT_UTF8_EMPTY(&dsl_rdp_credentials.dsc_password);
	HL_UCS_INIT_UTF8_EMPTY(&dsl_rdp_credentials.dsc_password_enc);
	HL_UCS_INIT_UTF8_EMPTY(&dsl_rdp_credentials.dsc_domain);
#endif

   pdomc20:                                 /* process DOM node        */
   if (((long long int) adsp_hlcldomf->amc_call_dom( adsl_node_1, ied_hlcldom_get_node_type ))
         != DOMNode::ELEMENT_NODE) {
     goto pdomc80;                          /* get next sibling        */
   }
   awcl1 = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_1, ied_hlcldom_get_node_name );
#ifdef TRACEHL1
   printf( "xl-webterm-rdp-01-l%05d-T m_hlclib_conf() found node %S\n", __LINE__, awcl1 );
#endif
   iml_val = sizeof(dss_node_conf) / sizeof(dss_node_conf[0]);
   do {
		struct dsd_unicode_string dsl_tmp;
		dsl_tmp.ac_str = (void*)awcl1;
		dsl_tmp.imc_len_str = -1;
		dsl_tmp.iec_chs_str = ied_chs_utf_16;
		bol1 = m_cmp_ucs_ucs( &iml_cmp, &dsl_tmp, &dss_node_conf[ iml_val - 1 ].dsc_key );
     if ((bol1) && (iml_cmp == 0)) break;   /* strings are equal       */
     iml_val--;                             /* decrement index         */
   } while (iml_val > 0);
   if (iml_val == 0) {                      /* parameter not found     */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" not defined - ignored",
                   __LINE__, awcl1 );
     goto pdomc80;                          /* DOM node processed - next */
   }
   adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_1,
                                                          ied_hlcldom_get_first_child );  /* getFirstChild() */
   if (adsl_node_2 == NULL) {               /* no child found          */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" has no child - ignored",
                   __LINE__, awcl1 );
     goto pdomc80;                          /* DOM node processed - next */
   }
   do {                                     /* search value            */
     if (((long long int) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) break;
     adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                            ied_hlcldom_get_next_sibling );
   } while (adsl_node_2);
   if (adsl_node_2 == NULL) {
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" no value found - ignored",
                   __LINE__, awcl1 );
     goto pdomc80;                          /* DOM node processed - next */
   }
   awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_value );  /* getNodeValue() */
   bol1 = TRUE;                             /* value not double        */
	iml_val--;
	switch (dss_node_conf[iml_val].iec_type) {                       /* depending on keyword found */
     case iec_conf_single_sign_on:          /* <single-sign-on>        */
       if (borl_double[iml_val]) {                /* check if defined double */
         bol1 = FALSE;                      /* value double            */
         break;
       }
		 iml1 = sizeof(dsrs_conf_sso_tab) / sizeof(dsrs_conf_sso_tab[0]);
		while (TRUE) {
			iml1--;                                /* decrement index         */
			if (iml1 < 0) break;                   /* not found in table      */
			bol_rc = m_cmp_vx_vx( &iml_cmp,
										awcl_value, -1, ied_chs_utf_16,  /* Unicode UTF-16 = WCHAR */
										dsrs_conf_sso_tab[ iml1 ].achc_name, -1, ied_chs_utf_8 );  /* Unicode UTF-8 */
			if (bol_rc && (iml_cmp == 0)) break;
		}
		if (iml1 < 0) {                          /* not found in table      */
			m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" value not valid SSO configuration - \"%(ux)s\" - ignored",
								__LINE__, awcl1, awcl_value );
			goto pdomc80;                          /* DOM node processed - next */
		}
		dsl_cc_l.iec_d_sso = dsrs_conf_sso_tab[ iml1 ].iec_d_sso;  /* SSO - single-sign-on configuration */
		borl_double[0] = TRUE;                   /* check if defined double */
       break;                   /* process SSO             */
     case iec_conf_sign_on_without_domain:  /* <sign-on-without-domain> */
       if (borl_double[iml_val]) {                /* check if defined double */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       bol_rc = m_cmp_vx_vx( &iml_cmp,
                             awcl_value, -1, ied_chs_utf_16,  /* Unicode UTF-16 = WCHAR */
                             "YES", -1, ied_chs_utf_8 );  /* Unicode UTF-8 */
       if (bol_rc && (iml_cmp == 0)) {
         dsl_cc_l.boc_so_without_domain = TRUE;  /* <sign-on-without-domain> */
         borl_double[iml_val] = TRUE;             /* check if defined double */
         break;
       }
       bol_rc = m_cmp_vx_vx( &iml_cmp,
                             awcl_value, -1, ied_chs_utf_16,  /* Unicode UTF-16 = WCHAR */
                             "NO", -1, ied_chs_utf_8 );  /* Unicode UTF-8 */
       if (bol_rc && (iml_cmp == 0)) {
         borl_double[iml_val] = TRUE;             /* check if defined double */
         break;
       }
       m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" value neither YES nor NO - \"%(ux)s\" - ignored",
                     __LINE__, awcl1, awcl_value );
       break;
     case iec_conf_sign_on_use_domain:      /* <sign-on-use-domain>    */
// to-do 16.04.15 KB
       m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" not yet implemented - \"%(ux)s\" - ignored",
                     __LINE__, awcl1, awcl_value );
       break;
     case iec_conf_rdp_compression_level:   /* <RDP-compression-level> */
       if (borl_double[iml_val]) {                /* check if defined double */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       dsl_cc_l.imc_rdp_compr = m_get_unicode_number( awcl_value );  /* RDP-compression-level */
       borl_double[iml_val] = TRUE;               /* check if defined double */
       if (dsl_cc_l.imc_rdp_compr >= 0) break;  /* value is valid      */
       m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" value not valid level - \"%(ux)s\" - ignored",
                     __LINE__, awcl1, awcl_value );
       borl_double[iml_val] = FALSE;              /* check if defined double */
       break;
     case iec_conf_websocket_compression_level: /* <WebSocket-compression-level> */
       if (borl_double[iml_val]) {                /* check if defined double */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       dsl_cc_l.imc_webso_compr = m_get_unicode_number( awcl_value );  /* WebSocket-compression-level */
       borl_double[iml_val] = TRUE;               /* check if defined double */
       if (dsl_cc_l.imc_webso_compr >= 0) break;  /* value is valid    */
       m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" value not valid level - \"%(ux)s\" - ignored",
                     __LINE__, awcl1, awcl_value );
       borl_double[iml_val] = FALSE;              /* check if defined double */
       break;
     case iec_conf_default_keyboard_layout:
       if (borl_double[iml_val]) {                /* check if defined double */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       dsl_cc_l.imc_default_locale = m_get_number( awcl_value, 5 );  /* default-keyboard-layout */
       borl_double[iml_val] = TRUE;               /* check if defined double */
       if (dsl_cc_l.imc_default_locale >= 0) break;  /* value is valid    */
       m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" value not valid  - \"%(ux)s\" - ignored",
                     __LINE__, awcl1, awcl_value );
       borl_double[iml_val] = FALSE;              /* check if defined double */
       break;
     case iec_conf_rdp_performance_flags: {
         if (borl_double[iml_val]) {
            bol1 = FALSE;
            break;
         }
         int iml_perf_flags = m_get_unicode_number( awcl_value );  /* RDP-performance-flags */
         iml_perf_flags &= 0xEF;//6F to disable font smoothing
         borl_double[iml_val] = TRUE;               /* check if defined double */
         if (iml_perf_flags >= 0)
         {
            dsl_cc_l.boc_custom_infoextra = TRUE;
            memcpy(&(dsl_cc_l.ucrc_loinf_extra),ucrs_loinf_extra,sizeof(ucrs_loinf_extra));           
            dsl_cc_l.ucrc_loinf_extra[PERFORMANCE_FLAGS_POS] = iml_perf_flags;
            break;  /* value is valid    */
         }
         m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" value not valid  - \"%(ux)s\" - ignored",
            __LINE__, awcl1, awcl_value );
         borl_double[iml_val] = FALSE;              /* check if defined double */
      }
      break;
#if SM_USE_NLA
     case iec_conf_rdp_security_flags:
			if (borl_double[iml_val]) {                /* check if defined double */
				bol1 = FALSE;                      /* value double            */
				break;
			}
			dsl_cc_l.imc_rdp_security_flags = m_get_unicode_number( awcl_value );
			borl_double[iml_val] = TRUE;               /* check if defined double */
			if ((dsl_cc_l.imc_rdp_security_flags & ~(PROTOCOL_RDP | PROTOCOL_SSL | PROTOCOL_HYBRID)) == 0) break;  /* value is valid    */
			m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" value not valid  - \"%(ux)s\" - ignored",
							__LINE__, awcl1, awcl_value );
			borl_double[iml_val] = FALSE;              /* check if defined double */
			break;
     case iec_conf_ssl_config_file:
     case iec_conf_ssl_certdb_file:
     case iec_conf_ssl_password_file:
			if (borl_double[iml_val]) {                /* check if defined double */
				bol1 = FALSE;                      /* value double            */
				break;
			}
			dsrl_ssl_client[iml_val - iec_conf_ssl_config_file].iec_chs_str = ied_chs_utf_16;
			dsrl_ssl_client[iml_val - iec_conf_ssl_config_file].ac_str = (void*)awcl_value;
			dsrl_ssl_client[iml_val - iec_conf_ssl_config_file].imc_len_str = -1;
			borl_double[iml_val] = TRUE;               /* check if defined double */
			break;
#endif /*SM_USE_NLA*/
#if SM_USE_PRINTING
	  case iec_conf_printer: {
			if(inl_num_printers >= HL_RDPDR_MAX_PRINTERS) {
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Maximum number of printers reached - ignored",
											__LINE__ );
				break;
			}
		   struct dsd_clib_conf_printer* adsl_printer = &dsrl_printers[inl_num_printers];
			memset(adsl_printer, 0, sizeof(*adsl_printer));
			adsl_printer->imc_request_timeout = HL_DEF_PRINTER_REQUEST_TIMEOUT;
		   DOMNode* adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom(adsl_node_1, ied_hlcldom_get_first_child);
			while(adsl_node_3 != NULL) {
				int inl_node_type;
				DOMNode* adsl_node_4;
				const struct dsd_conf_parameter* adsl_conf_param;
				
				inl_node_type = (size_t) adsp_hlcldomf->amc_call_dom(adsl_node_3, ied_hlcldom_get_node_type);
				if(inl_node_type != DOMNode::ELEMENT_NODE)
					goto LBL_CONF_PRINTER_NEXT1;
				awcl1 = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_3, ied_hlcldom_get_node_name );
				adsl_node_4 = (DOMNode *) adsp_hlcldomf->amc_call_dom(adsl_node_3, ied_hlcldom_get_first_child);
				while(adsl_node_4 != NULL) {
					int inl_node_type = (size_t) adsp_hlcldomf->amc_call_dom(adsl_node_4, ied_hlcldom_get_node_type);
					if(inl_node_type == DOMNode::TEXT_NODE)
						break;
					adsl_node_4 = (DOMNode *) adsp_hlcldomf->amc_call_dom(adsl_node_4, ied_hlcldom_get_next_sibling);
				}
#if 0
				if(adsl_node_4 == NULL) {
					  m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" has no child - ignored",
										 __LINE__, awcl1 );
				}
#endif
				adsl_conf_param = m_find_conf_parameter(
					dss_node_conf_printer, sizeof(dss_node_conf_printer)/sizeof(dss_node_conf_printer[0]), awcl1);
				if(adsl_conf_param == NULL) {
					m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" no value found - ignored",
                   __LINE__, awcl1 );
					goto LBL_CONF_PRINTER_NEXT1;
				}
				awcl_value = dss_wchar_empty_string;
				if(adsl_node_4 != NULL)
					awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_4, ied_hlcldom_get_node_value );
				struct dsd_unicode_string dsl_value;
			   dsl_value.ac_str = (void*)awcl_value;
			   dsl_value.iec_chs_str = ied_chs_utf_16;
			   dsl_value.imc_len_str = -1;
				if(!m_ucs_ensure_length(&dsl_value)) {
					m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E m_ucs_ensure_length failed",
                     __LINE__ );
					goto LBL_CONF_PRINTER_NEXT1;
				}

				switch(adsl_conf_param->iec_type) {
				case iec_conf_printer_name:
					if(m_is_ucs_null_or_empty(&dsl_value)) {
						m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Printer element <name> is empty - ignored",
                     __LINE__ );
						break;
					}
					adsl_printer->dsc_name = dsl_value;
					break;
				case iec_conf_printer_driver_name:
					if(m_is_ucs_null_or_empty(&dsl_value)) {
						m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Printer element <driver-name> is empty - ignored",
                     __LINE__ );
						break;
					}
					adsl_printer->dsc_driver_name = dsl_value;
					break;
				case iec_conf_printer_file_name:
					if(m_is_ucs_null_or_empty(&dsl_value)) {
						m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Printer element <file-name> is empty - ignored",
                     __LINE__ );
						break;
					}
					adsl_printer->dsc_file_name = dsl_value;
					break;
				case iec_conf_printer_mime_type:
					if(m_is_ucs_null_or_empty(&dsl_value)) {
						m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Printer element <mime-type> is empty - ignored",
                     __LINE__ );
						break;
					}
					adsl_printer->dsc_mime_type = dsl_value;
					break;
				case iec_conf_printer_default: {
					int inl_value = m_get_bool(awcl_value, -1);
					if(inl_value < 0) {
						m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Printer element <default> value neither YES nor NO - \"%(ux)s\" - ignored",
                     __LINE__, awcl_value );
						break;
					}
					adsl_printer->boc_default = (BOOL)inl_value;
					break;
				}
				case iec_conf_printer_request_timeout:
					adsl_printer->imc_request_timeout = m_get_number( awcl_value, 10 );
					break;
				}
LBL_CONF_PRINTER_NEXT1:
				adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom(adsl_node_3, ied_hlcldom_get_next_sibling);
			}
			if(adsl_printer->dsc_name.ac_str == NULL) {
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Print element has no <name> - ignored",
                     __LINE__ );
				break;
			}
			if(adsl_printer->dsc_driver_name.ac_str == NULL) {
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Print element has no <driver-name> - ignored",
                     __LINE__ );
				break;
			}
			if(adsl_printer->dsc_file_name.ac_str == NULL) {
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Print element has no <file-name> - ignored",
                     __LINE__ );
				break;
			}
			if(adsl_printer->dsc_mime_type.ac_str == NULL) {
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Print element has no <mime-type> - ignored",
                     __LINE__ );
				break;
			}
			int inl_printer_len = sizeof(*adsl_printer);
			inl_printer_len += m_len_bytes_ucs(&adsl_printer->dsc_name);
			inl_printer_len += m_len_bytes_ucs(&adsl_printer->dsc_driver_name);
			inl_printer_len += m_len_bytes_ucs(&adsl_printer->dsc_file_name);
			inl_printer_len += m_len_bytes_ucs(&adsl_printer->dsc_mime_type);
			inl_printer_extra_len += inl_printer_len;
			inl_num_printers++;
		   break;
	  }
#endif /*SM_USE_PRINTING*/
	  case iec_conf_start_mode: {
		  if (borl_double[iml_val]) {                /* check if defined double */
			  bol1 = FALSE;                      /* value double            */
			  break;
		  }
		  struct dsd_unicode_string dsl_value;
		  dsl_value.ac_str = (void*)awcl_value;
		  dsl_value.iec_chs_str = ied_chs_utf_16;
		  dsl_value.imc_len_str = -1;

		  struct dsd_unicode_string dsl_desktop = D_UCS_INITIALIZE_U8("DESKTOP");
		  bol_rc = m_cmp_ucs_ucs( &iml_cmp, &dsl_value, &dsl_desktop );
		  if (bol_rc && (iml_cmp == 0)) {
			  dsl_cc_l.iec_start_mode = ied_d_start_mode_desktop;
			  borl_double[iml_val] = TRUE;             /* check if defined double */
			  break;
		  }
#if SM_RAIL_CHANNEL
		  struct dsd_unicode_string dsl_rail = D_UCS_INITIALIZE_U8("RAIL");
		  bol_rc = m_cmp_ucs_ucs( &iml_cmp, &dsl_value, &dsl_rail );
		  if (bol_rc && (iml_cmp == 0)) {
			  dsl_cc_l.iec_start_mode = ied_d_start_mode_rail;
			  borl_double[iml_val] = TRUE;             /* check if defined double */
			  break;
		  }
#endif
		  m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" value neither DESKTOP nor RAIL - \"%(ux)s\" - ignored",
			  __LINE__, awcl1, awcl_value );
		  break;
	  }
#if SM_RAIL_CHANNEL
	  case iec_conf_remote_app: {
			if(inl_num_printers >= HL_RDPDR_MAX_REMOTE_APPS) {
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Maximum number of remote apps reached - ignored",
											__LINE__ );
				break;
			}
			struct dsd_clib_conf_remote_app* adsl_remote_app = &dsrl_remote_apps[inl_num_remote_apps];
			memset(adsl_remote_app, 0, sizeof(*adsl_remote_app));
			//adsl_printer->usc_flags = 0;
		   DOMNode* adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom(adsl_node_1, ied_hlcldom_get_first_child);
			while(adsl_node_3 != NULL) {
				int inl_node_type;
				DOMNode* adsl_node_4;
				const struct dsd_conf_parameter* adsl_conf_param;
				
				inl_node_type = (size_t) adsp_hlcldomf->amc_call_dom(adsl_node_3, ied_hlcldom_get_node_type);
				if(inl_node_type != DOMNode::ELEMENT_NODE)
					goto LBL_CONF_REMOTE_APP_NEXT1;
				awcl1 = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_3, ied_hlcldom_get_node_name );
				adsl_node_4 = (DOMNode *) adsp_hlcldomf->amc_call_dom(adsl_node_3, ied_hlcldom_get_first_child);
				while(adsl_node_4 != NULL) {
					int inl_node_type = (size_t) adsp_hlcldomf->amc_call_dom(adsl_node_4, ied_hlcldom_get_node_type);
					if(inl_node_type == DOMNode::TEXT_NODE)
						break;
					adsl_node_4 = (DOMNode *) adsp_hlcldomf->amc_call_dom(adsl_node_4, ied_hlcldom_get_next_sibling);
				}
#if 0
				if(adsl_node_4 == NULL) {
					  m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" has no child - ignored",
										 __LINE__, awcl1 );
					  break;
				}
#endif
				adsl_conf_param = m_find_conf_parameter(
					dss_node_conf_remote_app, sizeof(dss_node_conf_remote_app)/sizeof(dss_node_conf_remote_app[0]), awcl1);
				if(adsl_conf_param == NULL) {
					m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" no value found - ignored",
                   __LINE__, awcl1 );
					goto LBL_CONF_REMOTE_APP_NEXT1;
				}
				awcl_value = dss_wchar_empty_string;
				if(adsl_node_4 != NULL)
					awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_4, ied_hlcldom_get_node_value );
				struct dsd_unicode_string dsl_value;
			   dsl_value.ac_str = (void*)awcl_value;
			   dsl_value.iec_chs_str = ied_chs_utf_16;
			   dsl_value.imc_len_str = -1;
				if(!m_ucs_ensure_length(&dsl_value)) {
					m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E m_ucs_ensure_length failed",
                     __LINE__ );
					goto LBL_CONF_REMOTE_APP_NEXT1;
				}
				
				switch(adsl_conf_param->iec_type) {
				case iec_conf_remote_app_exe_or_file:
					if(m_is_ucs_null_or_empty(&dsl_value)) {
						m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W RemoteApp element <exe-or-file> is empty - ignored",
                     __LINE__ );
						break;
					}
					adsl_remote_app->dsc_exe_or_file = dsl_value;
					break;
				case iec_conf_remote_app_working_dir:
					adsl_remote_app->dsc_working_dir = dsl_value;
					break;
				case iec_conf_remote_app_arguments:
					adsl_remote_app->dsc_arguments = dsl_value;
					break;
				case iec_conf_remote_app_flags: {
					int inl_flags = m_get_number( awcl_value, 5 );
					if(inl_flags < 0) {
						m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W RemoteApp element <flags> invalid - \"%(ux)s\" - ignored",
                     __LINE__, awcl_value );
						break;
					}
					adsl_remote_app->usc_flags = inl_flags;
					break;
				}
				}
LBL_CONF_REMOTE_APP_NEXT1:
				adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom(adsl_node_3, ied_hlcldom_get_next_sibling);
			}
			if(adsl_remote_app->dsc_exe_or_file.ac_str == NULL) {
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W RemoteApp element has no <exe-or-file> - ignored",
                     __LINE__ );
				break;
			}
#if 0
			if(adsl_printer->dsc_working_dir.ac_str == NULL) {
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W RemoteApp element has no <working-dir> - ignored",
                     __LINE__ );
				break;
			}
			if(adsl_printer->dsc_arguments.ac_str == NULL) {
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W RemoteApp element has no <arguments> - ignored",
                     __LINE__ );
				break;
			}
#endif
			int inl_remote_app_len = sizeof(*adsl_remote_app);
			inl_remote_app_len += m_len_bytes_ucs(&adsl_remote_app->dsc_exe_or_file);
			inl_remote_app_len += m_len_bytes_ucs(&adsl_remote_app->dsc_working_dir);
			inl_remote_app_len += m_len_bytes_ucs(&adsl_remote_app->dsc_arguments);
			inl_remote_app_extra_len += inl_remote_app_len;
			inl_num_remote_apps++;
		   break;
	  }
#endif /*SM_RAIL_CHANNEL*/
#if SM_USE_CONFIG_RDP_CREDENTIALS
	  case iec_conf_rdp_credentials: {
			//adsl_printer->usc_flags = 0;
		   DOMNode* adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom(adsl_node_1, ied_hlcldom_get_first_child);
			while(adsl_node_3 != NULL) {
				int inl_node_type;
				DOMNode* adsl_node_4;
				const struct dsd_conf_parameter* adsl_conf_param;
				
				inl_node_type = (size_t) adsp_hlcldomf->amc_call_dom(adsl_node_3, ied_hlcldom_get_node_type);
				if(inl_node_type != DOMNode::ELEMENT_NODE)
					goto LBL_CONF_RDP_CREDENTIALS_NEXT1;
				awcl1 = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_3, ied_hlcldom_get_node_name );
				adsl_node_4 = (DOMNode *) adsp_hlcldomf->amc_call_dom(adsl_node_3, ied_hlcldom_get_first_child);
				while(adsl_node_4 != NULL) {
					int inl_node_type = (size_t) adsp_hlcldomf->amc_call_dom(adsl_node_4, ied_hlcldom_get_node_type);
					if(inl_node_type == DOMNode::TEXT_NODE)
						break;
					adsl_node_4 = (DOMNode *) adsp_hlcldomf->amc_call_dom(adsl_node_4, ied_hlcldom_get_next_sibling);
				}
#if 0
				if(adsl_node_4 == NULL) {
					  m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" has no child - ignored",
										 __LINE__, awcl1 );
					  break;
				}
#endif
				adsl_conf_param = m_find_conf_parameter(
					dss_node_conf_rdp_credentials, sizeof(dss_node_conf_rdp_credentials)/sizeof(dss_node_conf_rdp_credentials[0]), awcl1);
				if(adsl_conf_param == NULL) {
					m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" no value found - ignored",
                   __LINE__, awcl1 );
					goto LBL_CONF_RDP_CREDENTIALS_NEXT1;
				}
				awcl_value = dss_wchar_empty_string;
				if(adsl_node_4 != NULL)
					awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_4, ied_hlcldom_get_node_value );
				struct dsd_unicode_string dsl_value;
			   dsl_value.ac_str = (void*)awcl_value;
			   dsl_value.iec_chs_str = ied_chs_utf_16;
			   dsl_value.imc_len_str = -1;
				if(!m_ucs_ensure_length(&dsl_value)) {
					m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E m_ucs_ensure_length failed",
                     __LINE__ );
					goto LBL_CONF_RDP_CREDENTIALS_NEXT1;
				}
				
				switch(adsl_conf_param->iec_type) {
				case iec_conf_rdp_credentials_user:
					dsl_rdp_credentials.dsc_user = dsl_value;
					break;
				case iec_conf_rdp_credentials_password:
					dsl_rdp_credentials.dsc_password = dsl_value;
					break;
				case iec_conf_rdp_credentials_password_enc:
					dsl_rdp_credentials.dsc_password_enc = dsl_value;
					break;
				case iec_conf_rdp_credentials_domain:
					dsl_rdp_credentials.dsc_domain = dsl_value;
					break;
				}
LBL_CONF_RDP_CREDENTIALS_NEXT1:
				adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom(adsl_node_3, ied_hlcldom_get_next_sibling);
			}
			int inl_extra_len = sizeof(dsl_rdp_credentials);
			inl_extra_len += m_len_bytes_ucs(&dsl_rdp_credentials.dsc_user);
			inl_extra_len += m_len_bytes_ucs(&dsl_rdp_credentials.dsc_password);
			inl_extra_len += m_len_bytes_ucs(&dsl_rdp_credentials.dsc_password_enc);
			inl_extra_len += m_len_bytes_ucs(&dsl_rdp_credentials.dsc_domain);
			inl_rdp_credentials_extra_len = inl_extra_len;
			adsl_rdp_credentials = &dsl_rdp_credentials;
		   break;
	  }
#endif
   }
   if (bol1 == FALSE) {                     /* value is double         */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error element \"%(ux)s\" value \"%(ux)s\" already defined before - ignored",
                   __LINE__, awcl1, awcl_value );
   }

   pdomc80:                                 /* DOM node processed - next */
   adsl_node_1 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_1,
                                                          ied_hlcldom_get_next_sibling );
   if (adsl_node_1) goto pdomc20;           /* process DOM node        */

#ifdef XYZ1
   while (awcl_file_vch_serv) {             /* file virus-checking service name */
     if (   (dsl_cc_l.boc_virch_local == FALSE)  /* virus checking data from local / client */
         && (dsl_cc_l.boc_virch_server == FALSE)) {  /* virus checking data from server / WSP */
       m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W \"file-virus-checking-service\" set but neither \"virus-checking-files-from-client\" nor \"virus-checking-files-from-server\" - Virus-Checking not activated",
                     __LINE__ );
       break;
     }
     dsl_cc_l.imc_len_file_vch_serv = m_len_vx_vx( ied_chs_utf_8,
                                                   awcl_file_vch_serv, -1, ied_chs_utf_16 );
     break;
   }
   if (   (dsl_cc_l.ilc_max_file_size)      /* maximum file-size       */
       && (dsl_cc_l.imc_len_file_vch_serv == 0)) {  /* no virus checking */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W no \"file-virus-checking-service\" but \"file-virus-checking-maximum-file-size\" - file-virus-checking-maximum-file-size ignored",
                   __LINE__ );
     dsl_cc_l.ilc_max_file_size = 0;        /* maximum file-size       */
   }
#endif

    int iml_extra_len = 0;
#if SM_USE_NLA
	for(int iml1=0; iml1<3; iml1++) {
		if(dsrl_ssl_client[iml1].imc_len_str == 0)
		   continue;
		int iml2 = m_len_vx_ucs(ied_chs_utf_8, &dsrl_ssl_client[iml1]);
		if(iml2 < 0) {
			return FALSE;
		}
		iml_extra_len += iml2;
	}
	iml_extra_len++;
#if 1
	struct dsd_aux_get_cs_ssl_addr dsl_aux_get_cs_ssl_addr;
	bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                       DEF_AUX_GET_CS_SSL_ADDR,
                                       &dsl_aux_get_cs_ssl_addr,
                                       sizeof(dsl_aux_get_cs_ssl_addr) );  /* structure configuration */
	if(!bol_rc) {
     m_sdh_printf(&dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_hlclib_conf() DEF_AUX_GET_CS_SSL_ADDR failed",
                   __LINE__);
     return FALSE;
	}
   dsl_cc_l.dsc_aux_ssl_functions.m_cl_registerconfig = dsl_aux_get_cs_ssl_addr.amc_cl_registerconfig;
   dsl_cc_l.dsc_aux_ssl_functions.m_release_config = dsl_aux_get_cs_ssl_addr.amc_release_config;
   dsl_cc_l.dsc_aux_ssl_functions.m_hlcl01 = dsl_aux_get_cs_ssl_addr.amc_hlcl01;
   dsl_cc_l.dsc_aux_ssl_functions.FromASN1_DNCommonNameToString = dsl_aux_get_cs_ssl_addr.amc_FromASN1_DNCommonNameToString;
   dsl_cc_l.dsc_aux_ssl_functions.FromASN1CertToCertStruc = dsl_aux_get_cs_ssl_addr.amc_FromASN1CertToCertStruc;
   dsl_cc_l.dsc_aux_ssl_functions.FreeCertStruc = dsl_aux_get_cs_ssl_addr.amc_FreeCertStruc;
#else
   dsl_cc_l.dsc_aux_ssl_functions.m_cl_registerconfig = &m_cl_registerconfig;
   dsl_cc_l.dsc_aux_ssl_functions.m_release_config = &m_release_config;
   dsl_cc_l.dsc_aux_ssl_functions.m_hlcl01 = &m_hlcl01;
   dsl_cc_l.dsc_aux_ssl_functions.FromASN1_DNCommonNameToString = &FromASN1_DNCommonNameToString;
   dsl_cc_l.dsc_aux_ssl_functions.FromASN1CertToCertStruc = &FromASN1CertToCertStruc;
   dsl_cc_l.dsc_aux_ssl_functions.FreeCertStruc = &FreeCertStruc;
#endif
#endif /*SM_USE_NLA*/
#if SM_USE_PRINTING
	iml_extra_len = HL_INT_ALIGN_TO(iml_extra_len, sizeof(void*));
	iml_extra_len += inl_printer_extra_len;
#endif
#if SM_RAIL_CHANNEL
	iml_extra_len = HL_INT_ALIGN_TO(iml_extra_len, sizeof(void*));
	iml_extra_len += inl_remote_app_extra_len;
#endif
#if SM_USE_CONFIG_RDP_CREDENTIALS
	iml_extra_len = HL_INT_ALIGN_TO(iml_extra_len, sizeof(void*));
	iml_extra_len += inl_rdp_credentials_extra_len;
#endif
	// Two extra bytes required - thanks to the odd behavior of m_len_bytes_ucs and m_cpy_vx_ucs
	iml_extra_len += sizeof(HL_WCHAR);
   bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                       DEF_AUX_MEMGET,
                                       adsp_hlcldomf->aac_conf,
                                       sizeof(struct dsd_clib1_conf_1) + iml_extra_len );  /* structure configuration */
   if (bol_rc == FALSE) {                   /* error occured           */
     return FALSE;
   }


#define ADSL_CC1 ((struct dsd_clib1_conf_1 *) (*adsp_hlcldomf->aac_conf))  /* structure configuration */
   memcpy( ADSL_CC1, &dsl_cc_l, sizeof(struct dsd_clib1_conf_1) );

#if SM_USE_NLA
   char* achl_extra = (char*)(ADSL_CC1 + 1);
   char* achl_extra2 = achl_extra + iml_extra_len;
   for(int iml1=0; iml1<3; iml1++) {
	    if(dsrl_ssl_client[iml1].imc_len_str == 0)
		   continue;
	    int iml2 = m_cpy_vx_ucs(
			achl_extra, achl_extra2-achl_extra, ied_chs_utf_8, &dsrl_ssl_client[iml1]);
		if(iml2 < 0) {
			return FALSE;
		}
		dsrl_ssl_client[iml1].iec_chs_str = ied_chs_utf_8;
		dsrl_ssl_client[iml1].ac_str = achl_extra;
		dsrl_ssl_client[iml1].imc_len_str = iml2;
		achl_extra += iml2;
	}
   ADSL_CC1->dsc_ssl_config_file = dsrl_ssl_client[0];
   ADSL_CC1->dsc_ssl_certdb_file = dsrl_ssl_client[1];
   ADSL_CC1->dsc_ssl_password_file = dsrl_ssl_client[2];

   memset(&ADSL_CC1->dsc_hmem, 0, sizeof(ds__hmem));
   ADSL_CC1->dsc_hmem.in__aux_up_version = 1;
   ADSL_CC1->dsc_hmem.am__aux2 = dsl_output_area_1.amc_aux;
   ADSL_CC1->dsc_hmem.in__flags = 0;
   ADSL_CC1->dsc_hmem.vp__context = dsl_output_area_1.vpc_userfld;
   iml1 = SecDrbgInit(&ADSL_CC1->dsc_hmem);
   if (iml1 <= 0) {                   /* error occured           */
     m_sdh_printf(&dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_hlclib_conf() SecDrbgInit failed (%d)",
                   __LINE__, iml1);
     return FALSE;
   }
#endif /*SM_USE_NLA*/
#if SM_USE_PRINTING
	achl_extra = (char*)HL_PTR_ALIGN_TO(achl_extra, sizeof(void*));
	struct dsd_clib_conf_printer* adsrl_printer_dst = (struct dsd_clib_conf_printer*)achl_extra;
	achl_extra += sizeof(dsd_clib_conf_printer)*inl_num_printers;
	ADSL_CC1->adsc_printers = adsrl_printer_dst;
	ADSL_CC1->inc_num_printers = inl_num_printers;
   for(int iml1=0; iml1<inl_num_printers; iml1++) {
		struct dsd_clib_conf_printer* adsl_printer_src = &dsrl_printers[iml1];
		achl_extra = m_cpy_string(achl_extra, achl_extra2, &adsrl_printer_dst->dsc_name, &adsl_printer_src->dsc_name);
		if(achl_extra == NULL) {
			return FALSE;
		}
		achl_extra = m_cpy_string(achl_extra, achl_extra2, &adsrl_printer_dst->dsc_driver_name, &adsl_printer_src->dsc_driver_name);
		if(achl_extra == NULL) {
			return FALSE;
		}
		achl_extra = m_cpy_string(achl_extra, achl_extra2, &adsrl_printer_dst->dsc_file_name, &adsl_printer_src->dsc_file_name);
		if(achl_extra == NULL) {
			return FALSE;
		}
		achl_extra = m_cpy_string(achl_extra, achl_extra2, &adsrl_printer_dst->dsc_mime_type, &adsl_printer_src->dsc_mime_type);
		if(achl_extra == NULL) {
			return FALSE;
		}
		adsrl_printer_dst->boc_default = adsl_printer_src->boc_default;
		adsrl_printer_dst->imc_request_timeout = adsl_printer_src->imc_request_timeout;
		adsrl_printer_dst++;
	}
#endif
#if SM_RAIL_CHANNEL
	achl_extra = (char*)HL_PTR_ALIGN_TO(achl_extra, sizeof(void*));
	struct dsd_clib_conf_remote_app* adsrl_remote_app_dst = (struct dsd_clib_conf_remote_app*)achl_extra;
	achl_extra += sizeof(dsd_clib_conf_remote_app)*inl_num_remote_apps;
	ADSL_CC1->adsc_remote_app = adsrl_remote_app_dst;
	ADSL_CC1->inc_num_remote_apps = inl_num_remote_apps;
   for(int iml1=0; iml1<inl_num_remote_apps; iml1++) {
		struct dsd_clib_conf_remote_app* adsl_remote_app_src = &dsrl_remote_apps[iml1];
		adsrl_remote_app_dst->usc_flags = adsl_remote_app_src->usc_flags;
		achl_extra = m_cpy_string(achl_extra, achl_extra2, &adsrl_remote_app_dst->dsc_exe_or_file, &adsl_remote_app_src->dsc_exe_or_file);
		if(achl_extra == NULL) {
			return FALSE;
		}
		achl_extra = m_cpy_string(achl_extra, achl_extra2, &adsrl_remote_app_dst->dsc_working_dir, &adsl_remote_app_src->dsc_working_dir);
		if(achl_extra == NULL) {
			return FALSE;
		}
		achl_extra = m_cpy_string(achl_extra, achl_extra2, &adsrl_remote_app_dst->dsc_arguments, &adsl_remote_app_src->dsc_arguments);
		if(achl_extra == NULL) {
			return FALSE;
		}
		adsrl_remote_app_dst++;
	}
#endif
#if SM_USE_CONFIG_RDP_CREDENTIALS
	if(adsl_rdp_credentials != NULL) {
		achl_extra = (char*)HL_PTR_ALIGN_TO(achl_extra, sizeof(void*));
		struct dsd_clib_conf_rdp_credentials* adsl_rdp_credentials_dst = (struct dsd_clib_conf_rdp_credentials*)achl_extra;
		achl_extra += sizeof(dsd_clib_conf_rdp_credentials);
		ADSL_CC1->adsc_rdp_credentials = adsl_rdp_credentials_dst;
		achl_extra = m_cpy_string(achl_extra, achl_extra2, &adsl_rdp_credentials_dst->dsc_user, &adsl_rdp_credentials->dsc_user);
		if(achl_extra == NULL) {
			return FALSE;
		}

		achl_extra = m_cpy_string(achl_extra, achl_extra2, &adsl_rdp_credentials_dst->dsc_password, &adsl_rdp_credentials->dsc_password);
		if(achl_extra == NULL) {
			return FALSE;
		}

		int inl_error = 0;
		int inl_pos_error = 0;
		char chrl_password[256];
		int inl_ret = m_get_ucs_base64(&inl_error, &inl_pos_error, chrl_password, sizeof(chrl_password), &adsl_rdp_credentials->dsc_password_enc);
		struct dsd_unicode_string dsl_password;
		HL_UCS_INIT_UTF8_EMPTY(&dsl_password);
		if(inl_ret >= 0) {
			dsl_password.ac_str = chrl_password;
			dsl_password.imc_len_str = inl_ret;
			dsl_password.iec_chs_str = ied_chs_utf_8;
		}
		achl_extra = m_cpy_string(achl_extra, achl_extra2, &adsl_rdp_credentials_dst->dsc_password_enc, &dsl_password);
		if(achl_extra == NULL) {
			return FALSE;
		}

		achl_extra = m_cpy_string(achl_extra, achl_extra2, &adsl_rdp_credentials_dst->dsc_domain, &adsl_rdp_credentials->dsc_domain);
		if(achl_extra == NULL) {
			return FALSE;
		}
	}
#endif
   return TRUE;
#undef ADSL_CC1
} /* end m_hlclib_conf()                                               */

static int m_get_number( const HL_WCHAR *awcp_input, int inp_max_digits ) {
   int        iml1, iml2;                   /* working variables       */

   iml1 = iml2 = 0;
   while (*awcp_input) {
     if (iml2 >= inp_max_digits) return -1;
     if ((*awcp_input < '0') || (*awcp_input > '9')) {
       return -1;
     }
     iml1 *= 10;
     iml1 += *awcp_input - '0';
     iml2++;                                /* count digits            */
     awcp_input++;                          /* next input character    */
   }
   return iml1;
} /* end m_get_number()                                        */

static int m_get_unicode_number( const HL_WCHAR *awcp_input ) {
   return m_get_number(awcp_input, 4);
} /* end m_get_unicode_number()                                        */

#if SM_USE_QUICK_LINK
#define WEBTERM_SID  "webterm_sid="

static BOOL m_check_cma_bounds(const dsd_cma_string* adsp_string, int inp_total_size) {
	if(adsp_string->inc_offset < 0)
		return FALSE;
	if(adsp_string->inc_length < 0)
		return FALSE;
	if(adsp_string->inc_offset+adsp_string->inc_length > inp_total_size)
		return FALSE;
	return TRUE;
}

static BOOL m_get_security_context_id(struct dsd_http_header_server_1* adsp_hhs1, dsd_const_string& rdsp_webterm_sid) {
	dsd_const_string dsl_url_path(adsp_hhs1->achc_url_path, adsp_hhs1->imc_length_url_path);
	int inl_index = dsl_url_path.m_index_of("?");
	if(inl_index < 0)
		return FALSE;
	dsd_const_string dsl_url_search(dsl_url_path.m_substring(inl_index+1));
	/* webterm_sid */
	dsd_const_string dsl_webterm_sid_key(WEBTERM_SID);
	inl_index = dsl_url_search.m_index_of(dsl_webterm_sid_key);
	if(inl_index < 0)
		return FALSE;
	inl_index += dsl_webterm_sid_key.m_get_len();
	int inl_index2 = dsl_url_search.m_index_of(inl_index, "&");
	if(inl_index2 < 0)
		inl_index2 = dsl_url_search.m_get_len();
	rdsp_webterm_sid = dsl_url_search.m_substring(inl_index, inl_index2);
	return TRUE;
}

static BOOL m_read_security_id_context(struct dsd_sdh_call_1* adsp_output_area_1, const dsd_const_string& rdsp_webterm_sid, struct dsd_clib1_contr_1 *adsp_contr_1) {
	struct dsd_webtermrdp_sid* adsl_sid_data = NULL;

	dsd_const_string dsl_sid(HL_CMA_NAME_WEBTERM_RDP_SID);
    // Prefix
    char chrl_pwcma_name[128];
    memcpy( chrl_pwcma_name, dsl_sid.m_get_ptr(), dsl_sid.m_get_len()+1 );
    int inl_pwcma_namelen = dsl_sid.m_get_len()+1;
    // SID
    int inl_ret = m_cpy_vx_vx( chrl_pwcma_name + inl_pwcma_namelen,
        sizeof(chrl_pwcma_name) - inl_pwcma_namelen, ied_chs_utf_8,
        (void*)rdsp_webterm_sid.m_get_ptr(), rdsp_webterm_sid.m_get_len(), ied_chs_utf_8 );
    if( inl_ret < 0 )
		return FALSE;
	inl_pwcma_namelen += inl_ret;

	dsd_hl_aux_c_cma_1 dsl_accma1;
	memset( &dsl_accma1, 0, sizeof(struct dsd_hl_aux_c_cma_1) );  /* command common memory area */
	dsl_accma1.ac_cma_name = chrl_pwcma_name; /* cma name                */
	dsl_accma1.iec_chs_name = ied_chs_utf_8;  /* character set          */
	dsl_accma1.inc_len_cma_name = inl_pwcma_namelen;  /* length cma name in elements */
	dsl_accma1.iec_ccma_def = ied_ccma_lock_global;  /* set global lock */
	dsl_accma1.imc_lock_type = D_CMA_READ_DATA | D_CMA_SHARE_READ;
	BOOL bol_rc = (adsp_output_area_1->amc_aux)( adsp_output_area_1->vpc_userfld,
										DEF_AUX_COM_CMA,  /* command common memory area */
										&dsl_accma1,
										sizeof(struct dsd_hl_aux_c_cma_1) );
	if(!bol_rc) {
		m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d DEF_AUX_COM_CMA returned error",
                   __LINE__ );
		return FALSE;
	}

	if(dsl_accma1.inc_len_cma_area <= 0) {
		m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d WebTerm-SID does not exist",
                   __LINE__ );
		goto LBL_CLEANUP3;
	}

	bol_rc = adsp_output_area_1->amc_aux( adsp_output_area_1->vpc_userfld,
                                       DEF_AUX_MEMGET,
                                       &adsl_sid_data,  /* RDP credentials */
													dsl_accma1.inc_len_cma_area );  /* length area */
	if (bol_rc == FALSE) {                   /* error occured           */
		goto LBL_CLEANUP3;
	}
	adsp_contr_1->adsc_sid_data = adsl_sid_data;

#if 1
	dsd_aux_secure_xor_1 dsl_asxor1;
	memset( &dsl_asxor1, 0, sizeof(struct dsd_aux_secure_xor_1) );  /* apply secure XOR */
	dsl_asxor1.achc_post_key = (char*)rdsp_webterm_sid.m_get_ptr();  /* address of post key string */
	dsl_asxor1.imc_len_post_key = rdsp_webterm_sid.m_get_len();  /* length of post key string */
	dsl_asxor1.achc_source = dsl_accma1.achc_cma_area;  /* address of source */
	dsl_asxor1.imc_len_xor = dsl_accma1.inc_len_cma_area;  /* length of string */
	dsl_asxor1.achc_destination = (char*)adsp_contr_1->adsc_sid_data;  /* address of destination */
	bol_rc = (adsp_output_area_1->amc_aux)( adsp_output_area_1->vpc_userfld,
										DEF_AUX_SECURE_XOR,  /* apply secure XOR */
										&dsl_asxor1,
										sizeof(struct dsd_aux_secure_xor_1) );
	if (!bol_rc) {
		m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d DEF_AUX_SECURE_XOR returned error",
                   __LINE__ );
		adsl_sid_data = NULL;
		goto LBL_CLEANUP3;
	}
#else
	memcpy(adsp_contr_1->adsc_sid_data, dsl_accma1.achc_cma_area, dsl_accma1.inc_len_cma_area);
#endif

LBL_CLEANUP3:
	dsl_accma1.iec_ccma_def = ied_ccma_lock_release;  /* release lock   */
	bol_rc = (adsp_output_area_1->amc_aux)( adsp_output_area_1->vpc_userfld,
                                       DEF_AUX_COM_CMA,  /* command common memory area */
                                       &dsl_accma1,
                                       sizeof(struct dsd_hl_aux_c_cma_1) );
	if(!bol_rc) {
		m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d DEF_AUX_COM_CMA returned error",
                   __LINE__ );
		goto LBL_CLEANUP1;
	}

	if(adsl_sid_data == NULL)
		goto LBL_CLEANUP1;

	if(!m_check_cma_bounds(&adsl_sid_data->dsc_user, dsl_accma1.inc_len_cma_area))
		goto LBL_CLEANUP2;
	if(!m_check_cma_bounds(&adsl_sid_data->dsc_password, dsl_accma1.inc_len_cma_area))
		goto LBL_CLEANUP2;
	if(!m_check_cma_bounds(&adsl_sid_data->dsc_domain, dsl_accma1.inc_len_cma_area))
		goto LBL_CLEANUP2;
	if(!m_check_cma_bounds(&adsl_sid_data->dsc_startmode, dsl_accma1.inc_len_cma_area))
		goto LBL_CLEANUP2;
	if(!m_check_cma_bounds(&adsl_sid_data->dsc_remoteapp.dsc_exe_or_file, dsl_accma1.inc_len_cma_area))
		goto LBL_CLEANUP2;
	if(!m_check_cma_bounds(&adsl_sid_data->dsc_remoteapp.dsc_working_dir, dsl_accma1.inc_len_cma_area))
		goto LBL_CLEANUP2;
	if(!m_check_cma_bounds(&adsl_sid_data->dsc_remoteapp.dsc_arguments, dsl_accma1.inc_len_cma_area))
		goto LBL_CLEANUP2;

	return TRUE;
LBL_CLEANUP2:
	m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d invalid CMA content",
                   __LINE__ );
LBL_CLEANUP1:
	adsp_output_area_1->amc_aux( adsp_output_area_1->vpc_userfld,
									DEF_AUX_MEMFREE,
									&adsp_contr_1->adsc_sid_data,  /* RDP credentials */
									dsl_accma1.inc_len_cma_area );  /* length area */
	return FALSE;
}
#endif /*SM_USE_QUICK_LINK*/

extern "C" HL_DLL_PUBLIC void m_hlclib01( struct dsd_hl_clib_1 *adsp_hl_clib_1 ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml_rc;                       /* return code             */
   BOOL       bol1;                         /* working variable        */
   BOOL       bol_cont;                     /* continue processing     */
   BOOL       bol_compressed;               /* input is compressed     */
   BOOL       bol_connection_closed;        /* WebSocket connection close */
   int        iml1, iml2, iml3;             /* working variables       */
   int        iml_len_header;               /* length header WebSocket record */
   int        iml_len_payload;              /* length payload WebSocket record */
#if !SM_USE_CLIENT_PARAMS
	int        iml_wt_js_version;            /* version of WT JS client */
   const struct dsd_parameter* adsl_param;
#endif
#if SM_USE_NLA
   char*      achl_credentials;
   struct dsd_unicode_string dsl_client_userid;
   struct dsd_unicode_string dsl_client_password;
   struct dsd_unicode_string dsl_client_domain;
#endif
#ifdef XYZ1
   int        iml_keyb_mouse;               /* count keyboard and mouse events */
#endif
   enum ied_proc_cont iel_pc;               /* continue in program     */
   char       byl_opcode;                   /* opcode of WebSocket frame */
#ifdef XYZ1
   char       *achl_work_1;                 /* position work area, up  */
   char       *achl_work_2;                 /* position work area, down */
#endif
   int        *aiml_w1;                     /* address of int          */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4, *achl_w5;  /* working variables */
   const char *achl_wc6;                     /* working variable */
   char       *achl_inp_rp;                 /* input read pointer      */
   char       *achl_keyb_mouse;             /* position work area, keyboard and mouse events */
#if CV_DYN_CHANNEL
   char       *achl_drdynvc_wa = NULL;                 /* position work area, touch events */
   char       *adsl_drdynvc_buffer;             /* output buffer for "DRDYNVC" channel */
   struct dsd_gather_i_1 *adsl_drdynvc_gather;  /* "DRDYNVC" output gather */    
   
   int inl_vch_out_len = 0;
#endif /* CV_DYN_CHANNEL */
  //MS int inl_status;                          /* status working variable */
   //struct dsd_cc_co1 **aadsl_cc_co1_l;      /* position chain of client commands, input */
   struct dsd_clib1_contr_1 *adsl_contr_1;  /* for addressing          */
   struct dsd_gather_i_1 *adsl_gai1_inp_w1;  /* input data             */
// char       *achl_end;                    /* end of data             */
// char       *achl_replace;                /* pointer to replace data */
// struct dsd_clib1_contr_1 *adsl_cls91_1;  /* for addressing      */
   struct dsd_gather_i_1 *adsl_gai1_inp_1;  /* input data              */
   struct dsd_gather_i_1 *adsl_gai1_inp_2;  /* input data              */
   struct dsd_gather_i_1 *adsl_gai1_inp_rp;  /* input data read pointer */
#ifdef XYZ1
   struct dsd_gather_i_1 *adsl_gai1_out_1;  /* output data             */
   struct dsd_gather_i_1 *adsl_gai1_out_2;  /* output data             */
#endif
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
#ifdef XYZ1
   struct dsd_rdpcs1_session *adsl_r_sess;  /* structure subroutine session */
#endif
   struct dsd_cc_co1 *adsl_cc_co1_w1;       /* client commands, working variable */
   struct dsd_cc_co1 *adsl_cc_co1_w2;       /* client commands, working variable */
   //struct dsd_cc_co1 **aadsl_cc_co1_ch;     /* chain of client commands */
   struct dsd_se_co1 *adsl_se_co1_w1;       /* command from server     */
   struct dsd_sc_co1 *adsl_sc_co1_w1;       /* server component command */
   struct dsd_sc_co1 **aadsl_sc_co1_ch;     /* chain of server component command */
   struct dsd_wt_record_1 *adsl_wtr1_w1;    /* WebTerm record          */
#ifdef XYZ1
   struct dsd_rdp_vc_1 *adsl_rdp_vc_1_w1;   /* RDP virtual channel     */
#endif
#ifdef XYZ1
   struct dsd_config* ads_my_config;
#endif
   struct dsd_sdh_call_1 dsl_output_area_1;    /* SDH call structure      */
   struct dsd_subaux_userfld dsl_subaux_userfld;  /* for aux calls     */
#ifndef HL_UNIX
   union {
     struct {
#endif
       struct dsd_call_http_header_server_1 dsl_chhs1;  /* call HTTP processing at server */
       struct dsd_http_header_server_1 dsl_hhs1;  /* HTTP processing at server */
#ifndef HL_UNIX
     };
#endif
     struct dsd_aux_get_session_info dsl_agsi;  /* get information about the session */
#ifdef XYZ1
     struct dsd_aux_webso_conn_1 dsl_awc1;  /* connect for WebSocket applications */
#endif
     struct dsd_aux_get_workarea dsl_aux_get_workarea;  /* acquire additional work area */
#ifndef HL_UNIX
     struct {
#endif
       struct dsd_sdh_ident_set_1 dsl_g_idset1;  /* settings for given ident */
       struct dsd_hl_aux_c_cma_1 dsl_accma1;  /* command common memory area */
       struct dsd_aux_secure_xor_1 dsl_asxor1;  /* apply secure XOR    */
#ifndef HL_UNIX
     };
     struct {
#endif
       struct sockaddr_storage dsl_soa_l;
       struct dsd_aux_tcp_conn_1 dsl_atc1_1;  /* TCP Connect to Server */
#ifndef HL_UNIX
     };
#endif
     struct {
       struct dsd_webterm_dod_info dsc_wt_dod_info;
       char   chrc_dod_ineta[ 512 ];
     } dsl_dod_query;
#ifndef HL_UNIX
   };
#endif
   struct {
     struct dsd_cc_co1 dsc_cc_co1;          /* client component command */
#ifndef HL_UNIX
     union {
#endif
       struct dsd_cc_start_rdp_client dsc_cc_start_rdp_client;
//     struct dsd_cc_events_mouse_keyb dsc_cc_events_mouse_keyb;  /* events from mouse or keyboard */
#ifndef HL_UNIX
     };
#endif
   } dsl_cc_co1_all;
#ifdef XYZ1
       struct dsd_out_dap {                 /* demand active PDU       */
         struct dsd_sc_co1 dsc_sc_co1;      /* server component command */
         struct dsd_d_act_pdu dsc_d_act_pdu;  /* send demand active PDU */
//       struct dsd_sc_draw_sc dsc_sc_draw_sc;  /* coordinates draw        */
       } dsl_out_dap;
#endif
   struct dsd_wsp_trace_header dsl_wtrh;    /* WSP trace header      */
   struct dsd_gather_i_1 dsrl_gai1_work[ MAX_INP_GATHER ];  /* input data */
#if SM_USE_NLA
   char (&chrl_work1)[sizeof(dsl_output_area_1.chrl_work1)] = dsl_output_area_1.chrl_work1;
   char (&chrl_work2)[sizeof(dsl_output_area_1.chrl_work2)] = dsl_output_area_1.chrl_work2;
   char (&chrl_work3)[sizeof(dsl_output_area_1.chrl_work3)] = dsl_output_area_1.chrl_work3;
#else
   // char       chrl_work1[ 8 * 2048 ];       /* work area               */
   char       chrl_work1[ 32 * 2048 ];      /* work area               */
   char       chrl_work2[ 32 * 2048 ];      /* work area               */
   char       chrl_work3[ 1024 ];           /* work area               */
#endif
#if CV_DYN_CHANNEL
   char  chrl_work_dyn[2048];
#endif
#if CV_TOUCH_REDIR
   //char       chrl_work_touch[ 1024 ];           /* work area               */
#endif /* CV_TOUCH_REDIR */
   dsl_output_area_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
   dsl_output_area_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
   dsl_output_area_1.achc_lower = dsl_output_area_1.achc_upper = NULL;  /* addr output area */
   dsl_output_area_1.aadsrc_gai1_client = &adsp_hl_clib_1->adsc_gai1_out_to_client;  /* output data to client */
   dsl_output_area_1.imc_sno = adsp_hl_clib_1->imc_sno;  /* session number */
   dsl_output_area_1.imc_trace_level = adsp_hl_clib_1->imc_trace_level;  /* WSP trace level */
   dsl_subaux_userfld.adsc_hl_clib_1 = adsp_hl_clib_1;
   adsl_contr_1 = (struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext;
   dsl_output_area_1.adsc_contr_1 = adsl_contr_1;  /* for addressing      */
	dsl_output_area_1.adsc_hl_clib_1 = adsp_hl_clib_1;
	dsl_output_area_1.dsc_aux_helper.amc_aux = dsl_output_area_1.amc_aux;
	dsl_output_area_1.dsc_aux_helper.vpc_userfld = dsl_output_area_1.vpc_userfld;

	dsl_output_area_1.dsc_wa_chain_extern.adsc_aux = &dsl_output_area_1.dsc_aux_helper;
	dsl_output_area_1.dsc_wa_chain_extern.adsc_workarea_1 = NULL;
	dsl_output_area_1.dsc_wa_aux_extern.amc_aux = &m_subaux_wa_allocator_extern;
	dsl_output_area_1.dsc_wa_aux_extern.vpc_userfld = &dsl_output_area_1.dsc_wa_chain_extern;
	m_wa_allocator_init(&dsl_output_area_1.dsc_wa_alloc_extern);
	dsl_output_area_1.dsc_wa_alloc_extern.adsc_aux = &dsl_output_area_1.dsc_wa_aux_extern;
#ifdef TRACEHL1
   {
     char chl1;
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
     adsl_gai1_inp_w1 = adsp_hl_clib_1->adsc_gather_i_1_in;
     bol1 = FALSE;
     chl1 = 0;
     while (adsl_gai1_inp_w1) {
       iml2++;
       iml1 += adsl_gai1_inp_w1->achc_ginp_end - adsl_gai1_inp_w1->achc_ginp_cur;
       if (   (adsl_gai1_inp_w1->achc_ginp_end > adsl_gai1_inp_w1->achc_ginp_cur)
           && (bol1 == FALSE)) {
         chl1 = *adsl_gai1_inp_w1->achc_ginp_cur;
         bol1 = TRUE;
       }
       adsl_gai1_inp_w1 = adsl_gai1_inp_w1->adsc_next;  /* get next in chain */
     }
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() called inc_func=%d %s input=%p len=%d pieces=%d cont=0X%02X.",
                   adsp_hl_clib_1->inc_func, achh_text,
                   adsp_hl_clib_1->adsc_gather_i_1_in, iml1, iml2, (unsigned char) chl1 );
#ifdef OLD01
     if (adsl_contr_1) {                    /* memory allocated        */
       adsl_contr_1->imc_count_call++;      /* count all calls         */
       if (adsl_contr_1->imc_count_call > 40) {  /* already too many   */
#ifndef HL_UNIX
         Sleep( 500 );
#else
         sleep( 1 );
#endif
       }
     }
#endif
   }
#endif
   iel_pc = ied_pc_idle;                    /* nothing to do           */
   switch (adsp_hl_clib_1->inc_func) {
     case DEF_IFUNC_START:
#if SM_USE_GATHER_TRACER && 0
		 {
			 struct dsd_cdr_ctrl dsl_cdr_ctrl;
			 memset(&dsl_cdr_ctrl, 0, sizeof(dsl_cdr_ctrl));
			 dsl_cdr_ctrl.vpc_userfld = dsl_output_area_1.vpc_userfld;  /* User Field Subroutine */
			 dsl_cdr_ctrl.amc_aux = dsl_output_area_1.amc_aux;  /* auxiliary subroutine */
			 m_replay_trace("D:\\martin\\temp\\macgate2_webterm_www\\webterm_mac.dat", D_M_CDX_ENC, &dsl_cdr_ctrl);
		 }
#endif
       goto p_start_00;                     /* start SDH               */
     case DEF_IFUNC_TOSERVER:
#ifdef XYZ1
       goto p_inp_client_00;                /* input from client       */
#endif
       goto p_call_00;                      /* valid call of SDH       */
#ifdef XYZ1
#ifdef DEBUG_130324_01
#ifdef XYZ1
       m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T before goto p_awcs_server_00 adsc_sc_co1_ch=%p.",
                   __LINE__, adsl_contr_1->dsc_c_awcs_se_1.adsc_sc_co1_ch );
       adsl_sc_co1_w1 = adsl_contr_1->dsc_c_awcs_se_1.adsc_sc_co1_ch;
       while (adsl_sc_co1_w1) {
         adsl_sc_co1_w1 = adsl_sc_co1_w1->adsc_next;  /* get next in chain */
       }
#endif
       adsl_contr_1->dsc_c_awcs_se_1.adsc_sc_co1_ch = NULL;
#endif
       adsl_contr_1->dsc_c_awcs_se_1.adsc_gather_i_1_in = adsp_hl_clib_1->adsc_gather_i_1_in;
       goto p_awcs_server_00;               /* process AWCS server     */
#endif
     case DEF_IFUNC_FROMSERVER:
#ifdef XYZ1
       if (adsp_hl_clib_1->boc_eof_server) {  /* End-of-File Server    */
         goto p_end_server_00;              /* received end connection to server */
       }
       if (adsp_hl_clib_1->adsc_gather_i_1_in) {  /* with input data   */
         goto p_rdp_client_00;              /* process RDP client      */
       }
       return;
#endif
       goto p_call_00;                      /* valid call of SDH       */
     case DEF_IFUNC_CLOSE:
#ifdef XYZ1
       adsl_cc1_ext_w1 = adsl_contr_1->adsc_cc1_ext;  /* structure session control extension */
       while (adsl_cc1_ext_w1) {            /* loop over all extensions */
         adsl_cc1_ext_w2 = adsl_cc1_ext_w1->adsc_next;  /* save next in chain */
         bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                         DEF_AUX_MEMFREE,
                                         &adsl_cc1_ext_w1,
                                         sizeof(struct dsd_clib1_contr_1) );
         if (bol1 == FALSE) {               /* error occured           */
           adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
           return;
         }
         adsl_cc1_ext_w1 = adsl_cc1_ext_w2;  /* get saved next in chain */
       }
       bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                       DEF_AUX_MEMFREE,
                                       &adsp_hl_clib_1->ac_ext,
                                       sizeof(struct dsd_clib1_contr_1) );
       if (bol1 == FALSE) {                 /* error occured           */
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       }
       return;
#endif
#ifdef XYZ1
       goto p_cleanup_00;                   /* do cleanup              */
#endif
#if SM_USE_GATHER_TRACER && 0
		 bol1 = m_trace_cdrf_enc_end(&adsl_contr_1->dsc_compress_to_client);
		 m_gather_tracer_destroy(&adsl_contr_1->dsc_compress_to_client);
		 if(bol1) {
			 struct dsd_cdr_ctrl dsl_cdr_ctrl;
			 memset(&dsl_cdr_ctrl, 0, sizeof(dsl_cdr_ctrl));
			 dsl_cdr_ctrl.vpc_userfld = dsl_output_area_1.vpc_userfld;  /* User Field Subroutine */
			 dsl_cdr_ctrl.amc_aux = dsl_output_area_1.amc_aux;  /* auxiliary subroutine */
			 m_replay_trace("compress_trace1.dat", D_M_CDX_ENC, &dsl_cdr_ctrl);
		 }
#endif
     case DEF_IFUNC_REFLECT:
#ifdef TRACEHL_DNS
       m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T time=%lld called DEF_IFUNC_REFLECT",
                   __LINE__, m_get_epoch_ms() );
#endif
#ifdef XYZ1
       return;
#endif
       goto p_call_00;                      /* valid call of SDH       */
   }
   /* program should never come here                                   */
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W called adsp_hl_clib_1->inc_func=%d - invalid",
                 __LINE__, adsp_hl_clib_1->inc_func );
   return;

   p_start_00:                              /* start SDH               */
   bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                       DEF_AUX_MEMGET,
                                       &adsl_contr_1,
                                       sizeof(struct dsd_clib1_contr_1) );
   if (bol_rc == FALSE) {                   /* returned error          */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsp_hl_clib_1->ac_ext = adsl_contr_1;
   memset( adsl_contr_1, 0, sizeof(struct dsd_clib1_contr_1) );

	m_aux_timer_handler_init(&adsl_contr_1->dsc_timer_handler);
#define ADSL_CC1 ((struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf)  /* structure configuration */
	adsl_contr_1->iec_start_mode = ADSL_CC1->iec_start_mode;

#if SM_USE_NLA
   if(ADSL_CC1->imc_rdp_security_flags == 0) {
      goto LBL_NO_SSL_CONFIG;
   }
   if(ADSL_CC1->dsc_ssl_config_file.imc_len_str == 0) {
      goto LBL_NO_SSL_CONFIG;
   }
   { // start new block
   struct dsd_hl_aux_diskfile_1 dsl_read_diskfile1;
   memset(&dsl_read_diskfile1, 0, sizeof(dsl_read_diskfile1));
   dsl_read_diskfile1.iec_chs_name = ADSL_CC1->dsc_ssl_config_file.iec_chs_str;
   dsl_read_diskfile1.ac_name = ADSL_CC1->dsc_ssl_config_file.ac_str;
   dsl_read_diskfile1.inc_len_name = ADSL_CC1->dsc_ssl_config_file.imc_len_str;
   bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
		DEF_AUX_DISKFILE_ACCESS, &dsl_read_diskfile1, (int)sizeof(dsl_read_diskfile1));
   if(!bol_rc || dsl_read_diskfile1.iec_dfar_def != ied_dfar_ok) {
       m_sdh_printf(&dsl_output_area_1,
		   "xl-webterm-rdp-01-l%05d-W hclient.cfg unavailable",
            __LINE__);
	   adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
	   return;
   }

   const char* achl_certdb = NULL;
   int inl_certdb_len = 0;
   const char* achl_password = NULL;
   int inl_password_len = 0;

   struct dsd_hl_aux_diskfile_1 dsl_read_diskfile2;
   if(ADSL_CC1->dsc_ssl_certdb_file.imc_len_str != 0) {
	   memset(&dsl_read_diskfile2, 0, sizeof(dsl_read_diskfile2));
	   dsl_read_diskfile2.iec_chs_name = ADSL_CC1->dsc_ssl_certdb_file.iec_chs_str;
	   dsl_read_diskfile2.ac_name = ADSL_CC1->dsc_ssl_certdb_file.ac_str;
	   dsl_read_diskfile2.inc_len_name = ADSL_CC1->dsc_ssl_certdb_file.imc_len_str;
	   bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
			DEF_AUX_DISKFILE_ACCESS, &dsl_read_diskfile2, (int)sizeof(dsl_read_diskfile2));
	   if(!bol_rc || dsl_read_diskfile2.iec_dfar_def != ied_dfar_ok) {
		   m_sdh_printf(&dsl_output_area_1,
			   "xl-webterm-rdp-01-l%05d-W hclient.cdb unavailable",
				__LINE__);
		   adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		   return;
	   }
	   achl_certdb = dsl_read_diskfile2.adsc_int_df1->achc_filecont_start;
	   inl_certdb_len = (int)(dsl_read_diskfile2.adsc_int_df1->achc_filecont_end-dsl_read_diskfile2.adsc_int_df1->achc_filecont_start);
   }

   struct dsd_hl_aux_diskfile_1 dsl_read_diskfile3;
   if(ADSL_CC1->dsc_ssl_password_file.imc_len_str != 0) {
	   memset(&dsl_read_diskfile3, 0, sizeof(dsl_read_diskfile3));
	   dsl_read_diskfile3.iec_chs_name = ADSL_CC1->dsc_ssl_password_file.iec_chs_str;
	   dsl_read_diskfile3.ac_name = ADSL_CC1->dsc_ssl_password_file.ac_str;
	   dsl_read_diskfile3.inc_len_name = ADSL_CC1->dsc_ssl_password_file.imc_len_str;
	   bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
			DEF_AUX_DISKFILE_ACCESS, &dsl_read_diskfile3, (int)sizeof(dsl_read_diskfile3));
	   if(!bol_rc || dsl_read_diskfile3.iec_dfar_def != ied_dfar_ok) {
		   m_sdh_printf(&dsl_output_area_1,
			   "xl-webterm-rdp-01-l%05d-W hclient.pwd unavailable",
				__LINE__);
		   adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		   return;
	   }

	   achl_password = dsl_read_diskfile3.adsc_int_df1->achc_filecont_start;
	   inl_password_len = (int)(dsl_read_diskfile3.adsc_int_df1->achc_filecont_end-dsl_read_diskfile3.adsc_int_df1->achc_filecont_start);
   }
   // Set server config
   iml1 = ADSL_CC1->dsc_aux_ssl_functions.m_cl_registerconfig(dsl_read_diskfile1.adsc_int_df1->achc_filecont_start, 
	   (int)(dsl_read_diskfile1.adsc_int_df1->achc_filecont_end-dsl_read_diskfile1.adsc_int_df1->achc_filecont_start),
       (char*)achl_certdb, inl_certdb_len,
       (char*)achl_password, inl_password_len,
       TRUE,
       NULL,
       dsl_output_area_1.amc_aux,   
	   dsl_output_area_1.vpc_userfld, 
       &adsl_contr_1->vpc_ssl_config, FALSE);
   if(iml1 != 0) {
       m_sdh_printf(&dsl_output_area_1,
		   "xl-webterm-rdp-01-l%05d-W m_cl_registerconfig failed (%d)",
            __LINE__, iml1);
	   adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
	   return;
   }
   bol_rc = dsl_output_area_1.amc_aux(dsl_output_area_1.vpc_userfld,
	   DEF_AUX_DISKFILE_RELEASE, &dsl_read_diskfile1.ac_handle, (int)sizeof(dsl_read_diskfile1.ac_handle));
   if(!bol_rc) {
       m_sdh_printf(&dsl_output_area_1,
		   "xl-webterm-rdp-01-l%05d-W DEF_AUX_DISKFILE_RELEASE failed",
            __LINE__);
	   adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
	   return;
   }
   if(dsl_read_diskfile2.ac_handle != NULL) {
	   bol_rc = dsl_output_area_1.amc_aux(dsl_output_area_1.vpc_userfld,
			DEF_AUX_DISKFILE_RELEASE, &dsl_read_diskfile2.ac_handle, (int)sizeof(dsl_read_diskfile2.ac_handle));
	   if(!bol_rc) {
		   m_sdh_printf(&dsl_output_area_1,
			   "xl-webterm-rdp-01-l%05d-W DEF_AUX_DISKFILE_RELEASE failed",
				__LINE__);
		   adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		   return;
	   }
   }
   if(dsl_read_diskfile3.ac_handle != NULL) {
	   bol_rc = dsl_output_area_1.amc_aux(dsl_output_area_1.vpc_userfld,
			DEF_AUX_DISKFILE_RELEASE, &dsl_read_diskfile3.ac_handle, (int)sizeof(dsl_read_diskfile3.ac_handle));
	   if(!bol_rc) {
		   m_sdh_printf(&dsl_output_area_1,
			   "xl-webterm-rdp-01-l%05d-W DEF_AUX_DISKFILE_RELEASE failed",
				__LINE__);
		   adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		   return;
	   }
   }
   } // end of block
LBL_NO_SSL_CONFIG:
   adsl_contr_1->dsc_c_wtrc1.adsc_aux_ssl_functions = &ADSL_CC1->dsc_aux_ssl_functions;
#endif /*SM_USE_NLA*/

#ifdef XYZ1
   adsl_contr_1->dsc_c_awcs_se_1.amc_aux = &m_sub_aux;
   adsl_contr_1->dsc_c_awcs_se_1.vpc_userfld = &dsl_subaux_userfld;  /* User Field Subroutine */
   adsl_contr_1->dsc_c_awcs_se_1.adsc_conf = &dss_conf_rdpserv_1;  /* configuration RDP Server 1 */
   M_AWCS_SERVER_1( &adsl_contr_1->dsc_c_awcs_se_1 );
   if (adsl_contr_1->dsc_c_awcs_se_1.inc_return != DEF_IRET_NORMAL) {  /* not o.k. returned */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W M_AWCS_SERVER_1() returned inc_return=%d - invalid",
                   __LINE__, adsl_contr_1->dsc_c_awcs_se_1.inc_return );
   }
   adsl_contr_1->dsc_c_awcs_se_1.inc_func = DEF_IFUNC_REFLECT;
#endif
#ifdef DEBUG_120330_01
   ims_debug_1_01 = 0;
#endif
   return;

p_call_00:                               /* valid call of SDH       */
#if CV_DYN_CHANNEL
   adsl_contr_1->dsc_svc_drdynvc.avoc_context = &dsl_output_area_1;
#endif
	dsl_output_area_1.adsc_se_co1_ch_first = NULL;
	dsl_output_area_1.adsc_se_co1_ch_end = &dsl_output_area_1.adsc_se_co1_ch_first;
#ifndef B150220
   if (adsp_hl_clib_1->boc_eof_client) {    /* End-of-File Client      */
     if (   (adsl_contr_1->dsc_c_wtrc1.inc_return == DEF_IRET_NORMAL)  /* o.k. returned */
         && (adsl_contr_1->dsc_c_wtrc1.inc_func != DEF_IFUNC_START)) {  /* RDP-ACC already started */
       adsl_contr_1->dsc_c_wtrc1.inc_func = DEF_IFUNC_CLOSE;  /* close RDP-ACC now */
       goto p_rdp_client_08;                /* end RDP-ACC             */
     }
     return;
   }
#endif
   if (   (adsl_contr_1->dsc_awc1.iec_cwc == ied_cwc_invalid)
       || (adsl_contr_1->dsc_awc1.iec_cwc == ied_cwc_close)) {  /* close connection to internal routine */
     goto p_call_40;                        /* continue call of SDH    */
   }
   adsl_contr_1->dsc_awc1.iec_cwc = ied_cwc_status;  /* check status   */

   p_status_00:                             /* check the status        */
   bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                       DEF_AUX_WEBSO_CONN,  /* connect for WebSocket applications */
                                       &adsl_contr_1->dsc_awc1,
                                       sizeof(struct dsd_aux_webso_conn_1) );
   if (bol_rc == FALSE) {                   /* returned error          */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d DEF_AUX_WEBSO_CONN returned error",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#ifdef TRACEHL2X
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d DEF_AUX_WEBSO_CONN returned type of WebSocket connect - iec_twc %d - iec_rwc %d.",
                 __LINE__,
                 adsl_contr_1->dsc_awc1.iec_twc, adsl_contr_1->dsc_awc1.iec_rwc );
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d DEF_AUX_WEBSO_CONN returned imc_len_data_recv=%d boc_internal_act=%d boc_connected=%d imc_connect_error=%d.",
                 __LINE__,
                 adsl_contr_1->dsc_awc1.imc_len_data_recv,  /* length data received */
                 adsl_contr_1->dsc_awc1.boc_internal_act,
                 adsl_contr_1->dsc_awc1.boc_connected,  /* connected to target / server */
                 adsl_contr_1->dsc_awc1.imc_connect_error );  /* connect error */
#endif
   if (adsl_contr_1->dsc_awc1.imc_len_data_recv > 0) {  /* check length data received */
     m_sdh_console_out( &dsl_output_area_1,
                        adsl_contr_1->dsc_awc1.achc_data_recv,  /* address data received */
                        adsl_contr_1->dsc_awc1.imc_len_data_recv );  /* length data received */
     if (adsl_contr_1->dsc_awc1.boc_internal_act) {  /* still more to do */
       goto p_status_00;                    /* check the status        */
     }
   }
   if (adsl_contr_1->dsc_awc1.boc_internal_act == FALSE) {  /* internal WebSocket component active */
     goto p_webso_60;                       /* status WebSocket no more active */
   }

p_call_40:                               /* continue call of SDH    */
	if(adsp_hl_clib_1->imc_signal != 0) {
		adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch = NULL;
		dsl_output_area_1.aadsc_cc_co1_ch = &adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch;

		if((adsp_hl_clib_1->imc_signal & HL_AUX_SIGNAL_TIMER) != 0) {
			struct dsd_aux_timer_peek dsl_peek;
			if(!m_aux_timer_handler_peek_start(&adsl_contr_1->dsc_timer_handler, &dsl_output_area_1.dsc_aux_helper, &dsl_peek)) {
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E m_aux_timer_handler_peek_done failed",
							__LINE__ );
				adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
				return;
			}
			while(dsl_peek.adsc_entry != NULL) {
				struct dsd_aux_timer_entry2* adsl_entry2 = HL_UPCAST(struct dsd_aux_timer_entry2, dsc_base, dsl_peek.adsc_entry);
				// TODO:
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E m_aux_timer_handler_peek adsl_entry=%p",
							__LINE__, dsl_peek.adsc_entry );
				if(!adsl_entry2->amc_proc(&dsl_output_area_1, adsl_entry2)) {
					m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E timer-proc failed",
								__LINE__ );
					adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
					return;
				}
				if(!m_aux_timer_handler_peek_next(&adsl_contr_1->dsc_timer_handler, &dsl_output_area_1.dsc_aux_helper, &dsl_peek)) {
					m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E m_aux_timer_handler_peek failed",
								__LINE__ );
					adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
					return;
				}
			}
			if(!m_aux_timer_handler_peek_end(&adsl_contr_1->dsc_timer_handler, &dsl_output_area_1.dsc_aux_helper, &dsl_peek)) {
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E m_aux_timer_handler_peek_done failed",
							__LINE__ );
				adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
				return;
			}
			adsp_hl_clib_1->imc_signal &= ~HL_AUX_SIGNAL_TIMER;
		}
		while(adsp_hl_clib_1->imc_signal != 0) {
#if SM_RDPDR_CHANNEL
			unsigned int uml_rdpdr_signals = ((((unsigned int)adsp_hl_clib_1->imc_signal) >> HL_RDPDR_SIGNALS_START) & HL_RDPDR_SIGNALS_MASK);
			if(uml_rdpdr_signals != 0) {
				unsigned long uml_bit_pos;
#ifdef HL_UNIX
				int inl_f = ffs(uml_rdpdr_signals);
				if(inl_f <= 0) {
					m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E ffs failed",
								__LINE__ );
					adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
					return;
				}
				uml_bit_pos = inl_f - 1;
#else
				if(!_BitScanForward(&uml_bit_pos, uml_rdpdr_signals)) {
					m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E _BitScanForward failed",
								__LINE__ );
					adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
					return;
				}
#endif
				adsp_hl_clib_1->imc_signal &= ~(1 << (uml_bit_pos + HL_RDPDR_SIGNALS_START));
				if(uml_bit_pos >= adsl_contr_1->imc_num_devices) {
					m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E signal flag out of range",
								__LINE__ );
					adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
					return;
				}

				struct dsd_rdpdr_device_context* adsl_device = adsl_contr_1->adsrc_rdpdr_devices[uml_bit_pos];
				if(!m_stream_pipe_handle_signal(&dsl_output_area_1, adsl_device)) {
					return;
				}
				continue;
			}
#endif
			m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W unexpected signals %08X",
						__LINE__, adsp_hl_clib_1->imc_signal );
			adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return;
		}
		if(adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch == NULL)
			return;
		adsl_contr_1->dsc_c_wtrc1.adsc_gather_i_1_in = NULL;
		//aadsl_cc_co1_ch = &dsl_cmd_result.adsc_vc_out_last->adsc_next;  /* position chain of client commands, input */
		goto p_rdp_client_20;
	}

   switch (adsp_hl_clib_1->inc_func) {
     case DEF_IFUNC_TOSERVER:
       goto p_inp_client_00;                /* input from client       */
#ifdef XYZ1
#ifdef DEBUG_130324_01
#ifdef XYZ1
       m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T before goto p_awcs_server_00 adsc_sc_co1_ch=%p.",
                   __LINE__, adsl_contr_1->dsc_c_awcs_se_1.adsc_sc_co1_ch );
       adsl_sc_co1_w1 = adsl_contr_1->dsc_c_awcs_se_1.adsc_sc_co1_ch;
       while (adsl_sc_co1_w1) {
         adsl_sc_co1_w1 = adsl_sc_co1_w1->adsc_next;  /* get next in chain */
       }
#endif
       adsl_contr_1->dsc_c_awcs_se_1.adsc_sc_co1_ch = NULL;
#endif
       adsl_contr_1->dsc_c_awcs_se_1.adsc_gather_i_1_in = adsp_hl_clib_1->adsc_gather_i_1_in;
       goto p_awcs_server_00;               /* process AWCS server     */
#endif
     case DEF_IFUNC_FROMSERVER:
       if (adsp_hl_clib_1->boc_eof_server) {  /* End-of-File Server    */
         goto p_end_server_00;              /* received end connection to server */
       }
       if (adsp_hl_clib_1->adsc_gather_i_1_in) {  /* with input data   */
         goto p_rdp_client_00;              /* process RDP client      */
       }
       return;
     case DEF_IFUNC_REFLECT:
#ifdef TRACEHL_DNS
       m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T time=%lld called DEF_IFUNC_REFLECT",
                   __LINE__, m_get_epoch_ms() );
#endif
       goto p_inp_client_00;                /* input from client       */
   }

   p_inp_client_00:                         /* input from client       */
   adsl_gai1_inp_1 = adsp_hl_clib_1->adsc_gather_i_1_in;
   if (adsl_gai1_inp_1 == NULL) return;     /* no input data           */
   if (adsl_contr_1->boc_started) {         /* connection to client has been started */
     goto p_inp_client_20;                  /* input from client, WebSocket protocol */
   }
   /* process incoming HTTP header                                     */
   memset( &dsl_chhs1, 0, sizeof(struct dsd_call_http_header_server_1) );  /* call HTTP processing at server */
   dsl_chhs1.adsc_gai1_in = adsl_gai1_inp_1;  /* gather input data     */
#if SM_USE_QUICK_LINK
   dsl_chhs1.achc_url_path = chrl_work2;  /* memory for URL path */
   dsl_chhs1.imc_length_url_path_buffer = sizeof(chrl_work2);  /* length memory for URL path */
#endif
   // dsl_chhs1.achc_url_path = byrl_http_url_path;  /* memory for URL path */
// dsl_chhs1.imc_length_url_path_buffer = sizeof(byrl_http_url_path);  /* length memory for URL path */
   dsl_chhs1.achc_sec_ws_key = chrl_work1;  /* Sec-WebSocket-Key base64 */
   dsl_chhs1.imc_length_sec_ws_key_buffer = sizeof(chrl_work1);  /* length memory for Sec-WebSocket-Key base64 */

   bol_rc = m_proc_http_header_server( &dss_phhs1,  /* HTTP processing at server */
                                       &dsl_chhs1,  /* call HTTP processing at server */
                                       &dsl_hhs1 );  /* HTTP processing at server */
   if (bol_rc == FALSE) {                   /* error occured           */
#ifdef XYZ1
// to-do 19.03.13 - additional error information
     m_sdh_printf( &dsl_output_area_1, "xltwspat302-l%05d-W m_wspat3_proc() m_proc_http_header_server() returned error",
                   __LINE__ );
     adsp_wspat3_1->iec_at_return = ied_atr_failed;  /* authentication failed */
#endif
     return;
   }
   if (dsl_hhs1.imc_length_http_header == 0) {  /* length of HTTP header */
     return;                                /* wait for more input data */
   }
   if (dsl_hhs1.imc_len_sec_ws_key == 0) {  /* length Sec-WebSocket-Key base64 */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;                                /* error                   */
   }
   if (dsl_hhs1.imc_len_sec_ws_key != dsl_hhs1.imc_stored_sec_ws_key) {  /* stored part of Sec-WebSocket-Key base64 */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;                                /* error                   */
   }
#ifdef B140205
#ifndef NO_WT_COMPRESSION
   if (dsl_hhs1.boc_sec_webso_ext_deflate) {  /* Sec-WebSocket-Extensions: x-webkit-deflate-frame */
     adsl_contr_1->iec_clcomp = ied_clcomp_xwdf;  /* x-webkit-deflate-frame */
   }
#endif
#endif
#define ADSL_CC1 ((struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf)  /* structure configuration */
   if (   (dsl_hhs1.boc_sec_webso_ext_deflate)  /* Sec-WebSocket-Extensions: x-webkit-deflate-frame */
       && (   (ADSL_CC1 == NULL)            /* no configuration        */
           || (ADSL_CC1->imc_webso_compr > 0))) {  /* <WebSocket-compression-level> */
     adsl_contr_1->iec_clcomp = ied_clcomp_xwdf;  /* x-webkit-deflate-frame */
   }
#ifdef XYZ1
   if (   (dsl_hhs1.imc_sec_webso_ext_pmd_2 != 0)  /* Sec-WebSocket-Extensions: permessage-deflate */
       && (   (ADSL_CC1 == NULL)            /* no configuration        */
           || (ADSL_CC1->imc_webso_compr > 0))) {  /* <WebSocket-compression-level> */
     adsl_contr_1->iec_clcomp = ied_clcomp_pmd_2;  /* permessage-deflate */
   }
#endif
   if (   (dsl_hhs1.umc_sec_webso_ext_pmd != 0)  /* Sec-WebSocket-Extensions: permessage-deflate */
       && (   (ADSL_CC1 == NULL)            /* no configuration        */
           || (ADSL_CC1->imc_webso_compr > 0))) {  /* <WebSocket-compression-level> */
     adsl_contr_1->iec_clcomp = ied_clcomp_pmd_2;  /* permessage-deflate */
   }
#undef ADSL_CC1
   bol_rc = m_reply_http( &dsl_output_area_1,
                          dsl_hhs1.achc_sec_ws_key,  /* Sec-WebSocket-Key base64 */
                          dsl_hhs1.imc_len_sec_ws_key );  /* length Sec-WebSocket-Key base64 */
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#if SM_USE_QUICK_LINK
   {
	   dsd_const_string dsl_webterm_sid;
	   if(m_get_security_context_id(&dsl_hhs1, dsl_webterm_sid)) {
		   bol_rc = m_read_security_id_context(&dsl_output_area_1, dsl_webterm_sid, adsl_contr_1);
		   if (bol_rc == FALSE) {                   /* error occured           */
			 adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			 return;
		   }
			struct dsd_webtermrdp_sid* adsl_sid_data = adsl_contr_1->adsc_sid_data;
			if(adsl_sid_data != NULL) {
				dsd_const_string dsl_startmode(((char*)adsl_sid_data)+adsl_sid_data->dsc_startmode.inc_offset, adsl_sid_data->dsc_startmode.inc_length);
				if(dsl_startmode.m_equals_ic("DESKTOP")) {
					adsl_contr_1->iec_start_mode = ied_d_start_mode_desktop;
				}
				else if(dsl_startmode.m_equals_ic("RAIL")) {
					adsl_contr_1->iec_start_mode = ied_d_start_mode_rail;
				}

			}
	   }
   }
#endif
	/* get parameters about the client                                  */
	memset( &adsl_contr_1->dsc_sdh_ident_set_1, 0, sizeof(struct dsd_sdh_ident_set_1) );  /* settings for given ident */
   bol_rc = (*dsl_output_area_1.amc_aux)( dsl_output_area_1.vpc_userfld,
                                          DEF_AUX_GET_IDENT_SETTINGS,  /* return settings of this user */
                                          &adsl_contr_1->dsc_sdh_ident_set_1,
                                          sizeof(struct dsd_sdh_ident_set_1) );
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
	if (dsl_g_idset1.iec_ret_g_idset1 != ied_ret_g_idset1_ok) {  /* ident known, parameters returned, o.k. */
		m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E DEF_AUX_GET_IDENT_SETTINGS returned %d",
                   __LINE__, dsl_g_idset1.iec_ret_g_idset1 );
		adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		return;
   }

   adsl_contr_1->boc_started = TRUE;        /* connection to client has been started */

   /* get parameters about the client                                  */
   memset( &dsl_agsi, 0, sizeof(struct dsd_aux_get_session_info) );  /* get information about the session */
   bol_rc = (*dsl_output_area_1.amc_aux)( dsl_output_area_1.vpc_userfld,
                                       DEF_AUX_GET_SESSION_INFO,  /* get information about the session */
                                       &dsl_agsi,
                                       sizeof(struct dsd_aux_get_session_info) );
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   iml_rc = getnameinfo( (struct sockaddr *) &dsl_agsi.dsc_soa_client, sizeof(struct sockaddr_storage),
                         chrl_work1, sizeof(chrl_work1), 0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
//   m_hlnew_printf( HLOG_XYZ1, "HWSPM062W GATE=%(ux)s getnameinfo() returned %d %d.",
//                   apdg1 + 1, rcu, D_TCP_ERROR );
     strcpy( chrl_work1, "???" );
   }
   iml_rc = m_cpy_vx_vx( adsl_contr_1->chrc_client_ineta,
                         sizeof(adsl_contr_1->chrc_client_ineta),
                         ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                         chrl_work1,
                         -1,                /* zero-terminated         */
                         ied_chs_utf_8 );
   adsl_contr_1->imc_len_client_ineta = (iml_rc + 1) * sizeof(HL_WCHAR);  /* length INETA client */

   if (adsl_contr_1->iec_clcomp == ied_clcomp_none) {  /* no compression */
     goto p_cl_sta_40;                      /* continue start client   */
   }
   /* start de-compression input                                       */
// memset( &adsl_contr_1->dsc_cdrf_dec, 0, sizeof(struct dsd_cdr_ctrl) );  /* compress data record oriented control */
   adsl_contr_1->dsc_cdrf_dec.vpc_userfld = dsl_output_area_1.vpc_userfld;  /* User Field Subroutine */
   adsl_contr_1->dsc_cdrf_dec.amc_aux = dsl_output_area_1.amc_aux;  /* auxiliary subroutine */
#ifndef WHY_DOES_THIS_NOT_WORK_140108
   adsl_contr_1->dsc_cdrf_dec.imc_param_1 = 1;
#endif
   adsl_contr_1->dsc_cdrf_dec.imc_param_2 = -15;
   adsl_contr_1->dsc_cdrf_dec.imc_param_3 = 1;
   D_M_CDX_DEC( &adsl_contr_1->dsc_cdrf_dec );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T D_M_CDX_DEC() returned im_return=%d.",
                 __LINE__,
                 adsl_contr_1->dsc_cdrf_dec.imc_return );
#endif
   if (adsl_contr_1->dsc_cdrf_dec.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
// to-do 07.01.14 KB error message
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }

   /* start compression output                                         */
// memset( &adsl_contr_1->dsc_cdrf_enc, 0, sizeof(struct dsd_cdr_ctrl) );  /* compress data record oriented control */
   adsl_contr_1->dsc_cdrf_enc.vpc_userfld = dsl_output_area_1.vpc_userfld;  /* User Field Subroutine */
   adsl_contr_1->dsc_cdrf_enc.amc_aux = dsl_output_area_1.amc_aux;  /* auxiliary subroutine */
#ifndef WHY_DOES_THIS_NOT_WORK_140108
   adsl_contr_1->dsc_cdrf_enc.imc_param_1 = 1;
#endif
   adsl_contr_1->dsc_cdrf_enc.imc_param_2 = -15;
   adsl_contr_1->dsc_cdrf_enc.imc_param_3 = 1;
   D_M_CDX_ENC( &adsl_contr_1->dsc_cdrf_enc );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T D_M_CDX_ENC() returned im_return=%d.",
                 __LINE__,
                 adsl_contr_1->dsc_cdrf_enc.imc_return );
#endif
   if (adsl_contr_1->dsc_cdrf_enc.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
// to-do 07.01.14 KB error message
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#if SM_USE_GATHER_TRACER
	if(!m_gather_tracer_init(&adsl_contr_1->dsc_compress_to_client, "compress_trace1.dat", TRUE)) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
	}
	if(!m_trace_cdrf_enc_init(&adsl_contr_1->dsc_compress_to_client, &adsl_contr_1->dsc_cdrf_enc)){
		adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		return;
	}
#endif
#ifdef B150318
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-I compression x-webkit-deflate-frame active",
                 __LINE__ );
#endif
   switch (adsl_contr_1->iec_clcomp) {      /* compression with WebSocket client */
     case ied_clcomp_xwdf:                  /* x-webkit-deflate-frame  */
       achl_wc6 = "x-webkit-deflate-frame";
       break;
     case ied_clcomp_pmd_2:                 /* permessage-deflate      */
       achl_wc6 = "permessage-deflate";
       break;
     default:
       achl_wc6 = "* undef *";
       break;
   }
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-I compression %s active (iec_clcomp=%d)",
                 __LINE__, achl_wc6, adsl_contr_1->iec_clcomp );

   p_cl_sta_40:                             /* continue start client   */
   return;

#ifdef B140206
   /* start WebTerm RDP Client                                         */
   adsl_contr_1->dsc_c_wtrc1.vpc_userfld = dsl_output_area_1.vpc_userfld;  /* User Field Subroutine */
   adsl_contr_1->dsc_c_wtrc1.amc_aux = dsl_output_area_1.amc_aux;  /* auxiliary subroutine */
   m_wt_rdp_client_1( &adsl_contr_1->dsc_c_wtrc1 );
#ifdef TRACEHL1
#ifdef XYZ1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T M_AWCS_SERVER_1() returned inc_return=%d adsc_gai1_out_to_client=%p adsc_cl_co1_ch=%p.",
                 __LINE__,
                 adsl_contr_1->dsc_c_awcs_se_1.inc_return,
                 adsl_contr_1->dsc_c_awcs_se_1.adsc_gai1_out_to_client,
                 adsl_contr_1->dsc_c_awcs_se_1.adsc_cl_co1_ch );
#endif
#endif
   if (adsl_contr_1->dsc_c_wtrc1.inc_return != DEF_IRET_NORMAL) {  /* not o.k. returned */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_wt_rdp_client_1() returned inc_return=%d - invalid",
                   __LINE__, adsl_contr_1->dsc_c_wtrc1.inc_return );
   }
   /* prepare virtual channels, take all of the server                 */
#ifdef XYZ1
   if (adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_no_virt_ch > 0) {  /* number of virtual channels */
     iml1 = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_no_virt_ch * sizeof(struct dsd_rdp_vc_1);
     bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                     DEF_AUX_MEMGET,
                                     &adsl_contr_1->dsc_c_rdp_cl_1.adsc_rdp_co->adsrc_vc_1,  /* array of virtual channels */
                                     iml1 );
     if (bol1 == FALSE) {
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
     adsl_contr_1->dsc_c_rdp_cl_1.adsc_rdp_co->imc_no_virt_ch
       = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_no_virt_ch;  /* number of virtual channels */
     memcpy( adsl_contr_1->dsc_c_rdp_cl_1.adsc_rdp_co->adsrc_vc_1,  /* array of virtual channels */
             adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->adsrc_vc_1,  /* array of virtual channels */
             iml1 );
   }
#endif
   adsl_contr_1->dsc_c_wtrc1.inc_func = DEF_IFUNC_REFLECT;
   memcpy( &dsl_cc_co1_all.dsc_cc_co1, &dss_cc_co1_start_client, sizeof(struct dsd_cc_co1) );  /* client component command */
   memset( &dsl_cc_co1_all.dsc_cc_start_rdp_client, 0, sizeof(struct dsd_cc_start_rdp_client) );
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_dim_x  /* dimension x pixels */
//   = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_dim_x;
//   = 640;
//   = 1080,
     = adsl_contr_1->imc_wt_js_width;       /* WT-JS screen width      */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_dim_y  /* dimension y pixels */
//   = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_dim_y;
//   = 480;
//   = 800;
     = adsl_contr_1->imc_wt_js_height;      /* WT-JS screen height     */
#ifdef XYZ1
#ifdef B121231
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_coldep  /* colour depth  */
     = 16;
#else
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_coldep  /* colour depth  */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_cl_coldep;
#endif
   if (   (adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_cl_coldep == 24)
       && (adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_cl_supported_color_depth & RNS_UD_32BPP_SUPPORT)
       && (adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_cl_early_capability_flag & RNS_UD_CS_WANT_32BPP_SESSION)) {
#endif
     dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_coldep = 32;
#ifdef XYZ1
   }
#endif
#ifdef XYZ1
#ifndef B130116
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_keyboard_layout  /* Keyboard Layout */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_keyboard_layout;  /* Keyboard Layout */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_keyboard_type  /* Type of Keyboard / 102 */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_keyboard_type;  /* Type of Keyboard / 102 */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_keyboard_subtype  /* Subtype of Keyboard */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_keyboard_subtype;  /* Subtype of Keyboard */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_no_func_keys  /* Number of Function Keys */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_no_func_keys;  /* Number of Function Keys */
#endif
// to-do 10.04.12 KB - should RDP-client generate umc_loinf_options from other values - like compression ???
   dsl_cc_co1_all.dsc_cc_start_rdp_client.umc_loinf_options  /* Logon Info Options */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->umc_loinf_options;  /* Logon Info Options */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_domna_len  /* Domain Name Length */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_loinf_domna_len;  /* Domain Name Length */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_domna_a  /* Domain Name */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->awcc_loinf_domna_a;  /* Domain Name */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_userna_len  /* User Name Length */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_loinf_userna_len;  /* User Name Length */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_userna_a  /* User Name */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->awcc_loinf_userna_a;  /* User Name */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_pwd_len  /* Password Length */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_loinf_pwd_len;  /* Password Length */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_pwd_a  /* Password */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->awcc_loinf_pwd_a;  /* Password */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_altsh_len  /* Alt Shell Length */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_loinf_altsh_len;  /* Alt Shell Length */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_altsh_a  /* Alt Shell */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->awcc_loinf_altsh_a;  /* Alt Shell */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_wodir_len  /* Working Directory Length */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_loinf_wodir_len;  /* Working Directory Length */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_wodir_a  /* Working Directory */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->awcc_loinf_wodir_a;  /* Working Directory */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_ineta_len  /* INETA Length */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_loinf_ineta_len;  /* INETA Length */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_ineta_a  /* INETA */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->awcc_loinf_ineta_a;  /* INETA */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_path_len  /* Client Path Length */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_loinf_path_len;  /* Client Path Length */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_path_a  /* Client Path */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->awcc_loinf_path_a;  /* Client Path */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_no_a_par  /* number of additional parameters */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_loinf_no_a_par;  /* number of additional parameters */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_extra_len  /* Extra Parameters Length */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_loinf_extra_len;  /* Extra Parameters Length */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_extra_a  /* Extra Parameters */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->awcc_loinf_extra_a;  /* Extra Parameters */
#ifndef TRY_NO_VIRCH_01                     /* 23.04.12 KB - try without virtual channels */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_no_virt_ch  /* number of virtual channels */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_no_virt_ch;  /* number of virtual channels */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.adsrc_vc_1  /* array of virtual channels */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->adsrc_vc_1;  /* array of virtual channels */
#endif
#endif
   dsl_cc_co1_all.dsc_cc_start_rdp_client.umc_loinf_options  /* Logon Info Options */
     = INFO_MOUSE
       | INFO_DISABLECTRLALTDEL
#ifdef RDP_USERID_PWD
#endif
       | INFO_AUTOLOGON
       | INFO_UNICODE
       | INFO_MAXIMIZESHELL
       | INFO_LOGONNOTIFY
       | INFO_ENABLEWINDOWSKEY
       | INFO_FORCE_ENCRYPTED_CS_PDU
       | INFO_LOGONERRORS
       | INFO_MOUSE_HAS_WHEEL
       | INFO_NOAUDIOPLAYBACK;
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_ineta_len  /* INETA Length */
     = adsl_contr_1->imc_len_client_ineta;  /* length INETA            */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_ineta_a  /* INETA */
     = (HL_WCHAR *) adsl_contr_1->chrc_client_ineta;
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_extra_len  /* Extra Parameters Length */
     = sizeof(ucrs_loinf_extra);            /* Extra Parameters Length */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_extra_a  /* Extra Parameters */
     = (void *) ucrs_loinf_extra;           /* Extra Parameters        */
// dsl_cc_co1_all.dsc_cc_start_rdp_client.achc_machine_name = "TEST01";  /* Name of clients machine, zero-terminated */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.achc_machine_name = "HOB-WebTerm";  /* Name of clients machine, zero-terminated */
#ifdef B140128
#ifdef RDP_COMPRESSION
   dsl_cc_co1_all.dsc_cc_start_rdp_client.boc_compression = TRUE;  /* with compression */
#endif
#endif
#define ADSL_CC1 ((struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf)  /* structure configuration */
   if (ADSL_CC1 == NULL) {                  /* no configuration        */
     goto p_cl_sta_60;                      /* parameters have been set */
   }
   if (ADSL_CC1->imc_rdp_compr > 0) {       /* <RDP-compression-level> */
     dsl_cc_co1_all.dsc_cc_start_rdp_client.boc_compression = TRUE;  /* with compression */
   }
   if (ADSL_CC1->iec_d_sso                  /* SSO - single-sign-on configuration */
         == ied_d_sso_none) {               /* no SSO                  */
     goto p_cl_sta_60;                      /* parameters have been set */
   }
   memset( &dsl_g_idset1, 0, sizeof(struct dsd_sdh_ident_set_1) );  /* settings for given ident */
   bol_rc = (*dsl_output_area_1.amc_aux)( dsl_output_area_1.vpc_userfld,
                                          DEF_AUX_GET_IDENT_SETTINGS,  /* return settings of this user */
                                          &dsl_g_idset1,
                                          sizeof(struct dsd_sdh_ident_set_1) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T aux-call() DEF_AUX_GET_IDENT_SETTINGS returned %d iec_ret_g_idset1 %d.",
                 __LINE__, bol_rc, dsl_g_idset1.iec_ret_g_idset1 );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (dsl_g_idset1.iec_ret_g_idset1 != ied_ret_g_idset1_ok) {  /* ident known, parameters returned, o.k. */
     goto p_cl_sta_60;                      /* parameters have been set */
   }
   iml1 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &dsl_g_idset1.dsc_user_group )  /* unicode string user-group */
            * sizeof(HL_WCHAR);
   iml2 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &dsl_g_idset1.dsc_userid )  /* unicode string userid */
            * sizeof(HL_WCHAR);
   iml3 = 0;                                /* length password         */
   if (ADSL_CC1->iec_d_sso                  /* SSO - single-sign-on configuration */
         != ied_d_sso_cred_cache) {         /* credential-cache        */
     goto p_cl_sta_48;                      /* end of password         */
   }
   memcpy( chrl_work1, chrs_cma_pwd_prefix, sizeof(chrs_cma_pwd_prefix) );
   iml3 = m_cpy_vx_ucs( chrl_work1 + sizeof(chrs_cma_pwd_prefix),
                        sizeof(chrl_work1) - sizeof(chrs_cma_pwd_prefix),
                        ied_chs_utf_8,      /* Unicode UTF-8           */
                        &dsl_g_idset1.dsc_user_group );  /* unicode string user-group */
   if (iml3 < 0) {
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_cpy_vx_ucs() user-group returned error",
                   __LINE__ );
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_48;                      /* end of password         */
   }
   achl_w1 = chrl_work1 + sizeof(chrs_cma_pwd_prefix) + iml3 + 1;
   iml3 = m_cpy_vx_ucs( achl_w1,
                        (chrl_work1 + sizeof(chrl_work1)) - achl_w1,
                        ied_chs_utf_8,      /* Unicode UTF-8           */
                        &dsl_g_idset1.dsc_userid );  /* unicode string userid */
   if (iml3 < 0) {
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_cpy_vx_ucs() userid returned error",
                   __LINE__ );
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_48;                      /* end of password         */
   }
   achl_w1 += iml3;
   memset( &dsl_accma1, 0, sizeof(struct dsd_hl_aux_c_cma_1) );  /* command common memory area */
   dsl_accma1.ac_cma_name = chrl_work1;     /* cma name                */
   dsl_accma1.iec_chs_name = ied_chs_utf_8;  /* character set          */
   dsl_accma1.inc_len_cma_name = achl_w1 - chrl_work1;  /* length cma name in elements */
   dsl_accma1.iec_ccma_def = ied_ccma_lock_global;  /* set global lock */
   bol_rc = (*dsl_output_area_1.amc_aux)( dsl_output_area_1.vpc_userfld,
                                          DEF_AUX_COM_CMA,  /* command common memory area */
                                          &dsl_accma1,
                                          sizeof(struct dsd_hl_aux_c_cma_1) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T aux-call() DEF_AUX_COM_CMA returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured - not found */
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_48;                      /* end of password         */
   }
   if (dsl_accma1.inc_len_cma_area == 0) {  /* length of cma area      */
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_44;                      /* do unlock               */
   }
   memset( &dsl_asxor1, 0, sizeof(struct dsd_aux_secure_xor_1) );  /* apply secure XOR */
   dsl_asxor1.imc_len_post_key = achl_w1 - (chrl_work1 + sizeof(chrs_cma_pwd_prefix));  /* length of post key string */
   dsl_asxor1.imc_len_xor = dsl_accma1.inc_len_cma_area;  /* length of string */
   dsl_asxor1.achc_post_key = chrl_work1 + sizeof(chrs_cma_pwd_prefix);  /* address of post key string */
   dsl_asxor1.achc_source = dsl_accma1.achc_cma_area;  /* address of source */
   dsl_asxor1.achc_destination = chrl_work2;  /* address of destination */
   bol_rc = (*dsl_output_area_1.amc_aux)( dsl_output_area_1.vpc_userfld,
                                       DEF_AUX_SECURE_XOR,  /* apply secure XOR */
                                       &dsl_asxor1,
                                       sizeof(struct dsd_aux_secure_xor_1) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T aux-call() DEF_AUX_SECURE_XOR returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   iml3 = m_cpy_vx_vx( chrl_work3, sizeof(chrl_work3), ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                       chrl_work2, dsl_accma1.inc_len_cma_area, ied_chs_utf_8 )  /* Unicode UTF-8 */
            * sizeof(HL_WCHAR);

   p_cl_sta_44:                             /* unlock CMA              */
   dsl_accma1.iec_ccma_def = ied_ccma_lock_release;  /* release lock   */
   bol_rc = (*dsl_output_area_1.amc_aux)( dsl_output_area_1.vpc_userfld,
                                       DEF_AUX_COM_CMA,  /* command common memory area */
                                       &dsl_accma1,
                                       sizeof(struct dsd_hl_aux_c_cma_1) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T aux-call() DEF_AUX_COM_CMA returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }

p_cl_sta_48:                             /* end of password         */
// to-do 16.04.15 KB
//   "sign-on-use-domain",
//   dsl_g_idset1.dsc_user_group - replace by local
   bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                       DEF_AUX_MEMGET,
                                       &adsl_contr_1->achc_rdp_cred,  /* RDP credentials */
                                       iml1 + iml2 + iml3 );  /* length area */
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   achl_w1 = adsl_contr_1->achc_rdp_cred;   /* RDP credentials         */
   if (iml1 > 0) {                          /* with domain             */
     m_cpy_vx_ucs( achl_w1, iml1, ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                   &dsl_g_idset1.dsc_user_group );  /* unicode string user-group */
     dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_domna_len  /* Domain Name Length */
       = iml1;
     dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_domna_a  /* Domain Name */
       = (HL_WCHAR *) achl_w1;
     achl_w1 += iml1;
   }
   if (iml2 > 0) {                          /* with userid             */
     m_cpy_vx_ucs( achl_w1, iml2, ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                   &dsl_g_idset1.dsc_userid );  /* unicode string userid */
     dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_userna_len  /* User Name Length */
       = iml2;
     dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_userna_a  /* User Name */
       = (HL_WCHAR *) achl_w1;
     achl_w1 += iml2;
   }
   if (iml3 > 0) {                          /* with password           */
     memcpy( achl_w1, chrl_work3, iml3 );
     dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_pwd_len  /* Password Length */
       = iml3;
     dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_pwd_a  /* Password */
       = (HL_WCHAR *) achl_w1;
   }
#undef ADSL_CC1

   p_cl_sta_60:                             /* parameters have been set */
#ifdef XYZ1
   bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                   DEF_AUX_MEMGET,
                                   &adsl_contr_1->dsc_c_awcs_se_1.ac_screen_buffer,
                                   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_dim_x
                                     * dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_dim_y
                                     * ((dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_coldep + 7) / 8) );
   if (bol1 == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_contr_1->dsc_c_rdp_cl_1.ac_screen_buffer = adsl_contr_1->dsc_c_awcs_se_1.ac_screen_buffer;
#endif
   adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch  /* chain of client commands, input */
     = &dsl_cc_co1_all.dsc_cc_co1;          /* start RDP client        */
   goto p_rdp_client_20;                    /* call RDP client         */
#endif

   p_inp_client_20:                         /* input from client, WebSocket protocol */
#if CV_DYN_CHANNEL
   achl_drdynvc_wa =  chrl_work_dyn;   /* position work area */
#endif

   achl_keyb_mouse = chrl_work2;            /* position work area, keyboard and mouse events */
   adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch = NULL;  /* chain of client commands, input */
   dsl_output_area_1.aadsc_cc_co1_ch = &adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch;  /* position chain of client commands, input */

   p_inp_client_24:                         /* check if input from client */
   while (adsl_gai1_inp_1->achc_ginp_cur >= adsl_gai1_inp_1->achc_ginp_end) {
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
     if (adsl_gai1_inp_1 == NULL) {
       goto p_inp_client_end;               /* input from client processed */
     }
   }
   iml_len_header = 2;                      /* length header needed    */

   p_inp_client_28:                         /* copy header to contiguos area */
   adsl_gai1_inp_rp = adsl_gai1_inp_1;      /* input data read pointer */
   achl_inp_rp = achl_w1 = adsl_gai1_inp_rp->achc_ginp_cur;  /* input read pointer */
   iml1 = adsl_gai1_inp_rp->achc_ginp_end - achl_inp_rp;
   if (iml1 >= iml_len_header) {
     achl_inp_rp += 2;                      /* this part processed     */
     goto p_inp_client_40;                  /* content contiguous      */
   }

   achl_w1 = achl_w2 = chrl_work1;          /* output area             */
   iml1 = iml_len_header;                   /* length header needed    */
   while (TRUE) {
     iml3 = adsl_gai1_inp_rp->achc_ginp_end - adsl_gai1_inp_rp->achc_ginp_cur;
     if (iml3 > iml1) iml3 = iml1;
     memcpy( achl_w2, adsl_gai1_inp_rp->achc_ginp_cur, iml3 );
     iml1 -= iml3;
     if (iml1 <= 0) {                       /* all data found          */
       achl_inp_rp = adsl_gai1_inp_rp->achc_ginp_cur + iml3;  /* input read pointer */
       break;
     }
     adsl_gai1_inp_rp = adsl_gai1_inp_rp->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_rp == NULL) {        /* wait for more input data */
       goto p_inp_client_end;               /* input from client processed */
     }
     achl_w2 += iml3;
   }
   if (iml_len_header != 2) {               /* not minimum header      */
     goto p_inp_client_48;                  /* header in contiguos area */
   }
   iml1 = iml_len_header;                   /* current length header   */

   p_inp_client_40:                         /* header contiguous       */
#ifdef B150120
   if ((*((unsigned char *) achl_w1) & 0XBF) != 0X82) {  /* first byte invalid  */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W first byte record header 0X%02X invalid",
                   __LINE__, *((unsigned char *) achl_w1) );
/* input invalid */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
   }
// to-do 05.11.13 KB - every input record needs to contain mask
   if (*(achl_w1 + 1) & 0X80) {             /* with mask               */
     iml_len_header = 2 + sizeof(adsl_contr_1->chrc_ws_mask);  /* length header needed */
   }
#endif
   if (   ((*((unsigned char *) achl_w1) & 0XBF) != 0X82)   /* Binary Frame */
       && ((*((unsigned char *) achl_w1) & 0XBF) != 0X88)  /* Connection Close Frame */
       && ((*((unsigned char *) achl_w1) & 0XBF) != 0X8A)) {  /* pong Frame */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W first byte record header 0X%02X invalid",
                   __LINE__, *((unsigned char *) achl_w1) );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   if ((*(achl_w1 + 1) & 0X80) == 0) {      /* not with mask           */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W second byte record header 0X%02X contains no mask",
                   __LINE__, *((unsigned char *) achl_w1 + 1) );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   byl_opcode = *achl_w1;                   /* opcode of WebSocket frame */
   bol_connection_closed = FALSE;           /* WebSocket connection close */
   if ((*((unsigned char *) achl_w1) & 0XBF) == 0X88) {  /* connection close */
     bol_connection_closed = TRUE;          /* WebSocket connection close */
   }
   iml_len_header = 2 + sizeof(adsl_contr_1->chrc_ws_mask);  /* length header needed */
   iml_len_payload = iml2 = *(achl_w1 + 1) & 0X7F;  /* length of payload */
   if (iml2 == 126) {                       /* two bytes length        */
     iml_len_header += 2;                   /* length header needed    */
   } else if (iml2 == 127) {                /* eight bytes length      */
     iml_len_header += 8;                   /* length header needed    */
   }
   if (iml1 < iml_len_header) {             /* not in this gather      */
     goto p_inp_client_28;                  /* copy header to contiguos area */
   }
   achl_inp_rp = adsl_gai1_inp_rp->achc_ginp_cur + iml_len_header;  /* input read pointer */

   p_inp_client_48:                         /* header in contiguos area */
   achl_w2 = achl_w1 + 2;                   /* address of mask         */
   if (iml2 == 126) {                       /* two bytes length        */
     iml_len_payload                        /* length of payload       */
       = (*((unsigned char *) achl_w1 + 2 + 0) << 8)
           | *((unsigned char *) achl_w1 + 2 + 1);
     achl_w2 = achl_w1 + 2 + 2;             /* address of mask         */
   } else if (iml2 == 127) {                /* eight bytes length      */
     if (   (*((unsigned char *) achl_w1 + 2 + 0) != 0)
         || (*((unsigned char *) achl_w1 + 2 + 1) != 0)
         || (*((unsigned char *) achl_w1 + 2 + 2) != 0)
         || (*((unsigned char *) achl_w1 + 2 + 3) != 0)
         || (*((unsigned char *) achl_w1 + 2 + 4) != 0)) {
       m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W length in record header received too high - input invalid",
                     __LINE__ );
/* input invalid */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
     iml_len_payload                        /* length of payload       */
       = (*((unsigned char *) achl_w1 + 2 + 5) << 16)
           | (*((unsigned char *) achl_w1 + 2 + 6) << 8)
           | *((unsigned char *) achl_w1 + 2 + 7);
     achl_w2 = achl_w1 + 2 + 8;             /* address of mask         */
   }
   if (iml_len_payload == 0) {              /* length of payload       */
     goto p_inp_client_60;                  /* complete record received */
   }
   /* check if complete payload received                               */
   iml1 = iml_len_payload;                  /* length of payload       */
   adsl_gai1_w1 = adsl_gai1_inp_rp;         /* input data read pointer */
   achl_w3 = achl_inp_rp;                   /* input read pointer      */
   while (TRUE) {
     iml2 = adsl_gai1_w1->achc_ginp_end - achl_w3;
     if (iml2 > iml1) iml2 = iml1;
     iml1 -= iml2;
     if (iml1 <= 0) break;                  /* all data received       */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1 == NULL) {            /* wait for more input data */
       goto p_inp_client_end;               /* input from client processed */
     }
     achl_w3 = adsl_gai1_w1->achc_ginp_cur;
   }

   p_inp_client_60:                         /* complete record received */
   if (*(achl_w1 + 1) & 0X80) {             /* with mask               */
#ifdef TRACEHL1
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T record with mask record length %d/0X%X.",
                   __LINE__, iml_len_payload, iml_len_payload );
#endif
     memcpy( adsl_contr_1->chrc_ws_mask, achl_w2, sizeof(adsl_contr_1->chrc_ws_mask) );  /* copy the mask */
   }
   if (iml_len_payload == 0) {              /* length of payload       */
     goto p_inp_client_80;                  /* input record processed  */
   }
   bol_compressed = FALSE;                  /* input is compressed     */
   if ((*((unsigned char *) achl_w1) & 0X40) == 0) {  /* no compression */
     goto p_inp_client_64;                  /* record not compressed   */
   }
   if (adsl_contr_1->iec_clcomp == ied_clcomp_none) {  /* no compression */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T received record compressed but not handled out",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   bol_compressed = TRUE;                   /* input is compressed     */
   /* consume length iml_len_header from input                         */
   while (adsl_gai1_inp_1 != adsl_gai1_inp_rp) {  /* not current gather */
     adsl_gai1_inp_1->achc_ginp_cur = adsl_gai1_inp_1->achc_ginp_end;
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
     if (adsl_gai1_inp_1 == NULL) {
/* programm illogic                                                 */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
   }
   achl_w4 = adsl_contr_1->chrc_ws_mask;    /* start of mask           */
   achl_w5 = achl_w4 + sizeof(adsl_contr_1->chrc_ws_mask);  /* end of mask */
   iml1 = iml_len_payload;                  /* length of payload       */
   iml2 = 0;                                /* position in array gather */

   p_cl_in_dec_00:                          /* decode and decompress input */
   achl_w2 = achl_inp_rp;                   /* current input pointer   */
   iml3 = adsl_gai1_inp_rp->achc_ginp_end - achl_inp_rp;
   if (iml3 > iml1) iml3 = iml1;
   achl_w3 = achl_w2 + iml3;                 /* end of input area       */
   do {
     *achl_w2++ ^= *achl_w4++;
     if (achl_w4 >= achl_w5) achl_w4 = adsl_contr_1->chrc_ws_mask;
   } while (achl_w2 < achl_w3);
   dsrl_gai1_work[ iml2 ].achc_ginp_cur = achl_inp_rp;
   achl_inp_rp += iml3;
   dsrl_gai1_work[ iml2 ].achc_ginp_end = achl_inp_rp;
   adsl_gai1_inp_1->achc_ginp_cur = achl_inp_rp;
   iml1 -= iml3;
   if (iml1 > 0) {                          /* more input              */
     iml2++;                                /* next gather             */
     if (iml2 >= (MAX_INP_GATHER)) {        /* number of input gather to be processed */
/* programm illogic                                                 */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
     dsrl_gai1_work[ iml2 - 1 ].adsc_next = &dsrl_gai1_work[ iml2 ];
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_1 == NULL) {         /* end of data, illogic    */
/* programm illogic                                                 */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
     achl_inp_rp = adsl_gai1_inp_rp->achc_ginp_cur;  /* input read pointer */
     goto p_cl_in_dec_00;                   /* decode and decompress input */
   }

   dsrl_gai1_work[ iml2 ].adsc_next = NULL;

   /* de-compress input                                                */
   adsl_contr_1->dsc_cdrf_dec.vpc_userfld = dsl_output_area_1.vpc_userfld;  /* User Field Subroutine */
   adsl_contr_1->dsc_cdrf_dec.amc_aux = dsl_output_area_1.amc_aux;  /* auxiliary subroutine */
   adsl_contr_1->dsc_cdrf_dec.adsc_gai1_in = dsrl_gai1_work;  /* input data */
   adsl_contr_1->dsc_cdrf_dec.achc_out_cur = chrl_work1;  /* current end of output data */
   adsl_contr_1->dsc_cdrf_dec.achc_out_end = chrl_work1 + sizeof(chrl_work1);  /* end of buffer for output data */
   adsl_contr_1->dsc_cdrf_dec.boc_mp_flush = TRUE;  /* end-of-record input */
   D_M_CDX_DEC( &adsl_contr_1->dsc_cdrf_dec );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T D_M_CDX_DEC() returned im_return=%d.",
                 __LINE__,
                 adsl_contr_1->dsc_cdrf_dec.imc_return );
#endif
   if (adsl_contr_1->dsc_cdrf_dec.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
// to-do 07.01.14 KB error message
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (adsl_contr_1->dsc_cdrf_dec.boc_sr_flush == FALSE) {  /* end-of-record output */
// to-do 07.01.14 KB error message
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   achl_w1 = chrl_work1;                    /* output area             */
   iml_len_payload = adsl_contr_1->dsc_cdrf_dec.achc_out_cur - chrl_work1;  /* length of payload */
   goto p_inp_client_72;                    /* input decoded           */

   p_inp_client_64:                         /* record not compressed   */
   achl_w1 = achl_inp_rp;                   /* current input pointer   */
   if ((adsl_gai1_inp_rp->achc_ginp_end - achl_inp_rp) >= iml_len_payload) {
     goto p_inp_client_68;                  /* payload in contiguous memory */
   }
   if (iml_len_payload > sizeof(chrl_work1)) {  /* length of payload   */
/* input invalid */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
   }
   achl_w1 = achl_w2 = chrl_work1;          /* output area             */
   iml1 = iml_len_payload;                  /* length of payload       */
   while (TRUE) {
     iml2 = adsl_gai1_inp_rp->achc_ginp_end - achl_inp_rp;
     if (iml2 > iml1) iml2 = iml1;
     memcpy( achl_w2, achl_inp_rp, iml2 );
     iml1 -= iml3;
     if (iml1 <= 0) {                       /* all data found          */
       break;
     }
     adsl_gai1_inp_rp = adsl_gai1_inp_rp->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_rp == NULL) {        /* end of data, illogic    */
/* programm illogic                                                 */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
     achl_w2 += iml2;
     achl_inp_rp = adsl_gai1_inp_rp->achc_ginp_cur;  /* input read pointer */
   }

   p_inp_client_68:                         /* payload in contiguous memory */
   achl_w2 = achl_w1;                       /* start of input area     */
   achl_w3 = achl_w1 + iml_len_payload;     /* end of input area       */
   achl_w4 = adsl_contr_1->chrc_ws_mask;    /* start of mask           */
   achl_w5 = achl_w4 + sizeof(adsl_contr_1->chrc_ws_mask);  /* end of mask */
   do {
     *achl_w2++ ^= *achl_w4++;
     if (achl_w4 >= achl_w5) achl_w4 = adsl_contr_1->chrc_ws_mask;
   } while (achl_w2 < achl_w3);

   p_inp_client_72:                         /* input decoded           */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T decoded input record length %d/0X%X.",
                 __LINE__, iml_len_payload, iml_len_payload );
   m_sdh_console_out( &dsl_output_area_1, achl_w1, iml_len_payload );
#endif
   if (dsl_output_area_1.imc_trace_level) {    /* WSP trace level         */
     memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
     memcpy( dsl_wtrh.chrc_wtrt_id, "SWTRIN01", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
     dsl_wtrh.imc_wtrh_sno = dsl_output_area_1.imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work3)
     dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
     memset( ADSL_WTR_G1, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
     ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                        "xl-webterm-rdp-01 l%05d input from client decoded length=%d/0X%X.",
                                        __LINE__, iml_len_payload, iml_len_payload );
     achl_w2 = (char *) (ADSL_WTR_G1 + 1) + ((ADSL_WTR_G1->imc_length + sizeof(void *) - 1) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w2)
     memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed     */
     ADSL_WTR_G2->achc_content = achl_w1;   /* content of text / data  */
     ADSL_WTR_G2->imc_length = iml_len_payload;
     ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                         DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                         &dsl_wtrh,
                                         0 );
   }
   if ((byl_opcode & 0XBF) == 0X8A) {       /* pong Frame              */
     goto p_inp_client_76;                  /* input processed         */
   }
   if (bol_connection_closed) {             /* WebSocket connection close */
     goto p_inp_client_76;                  /* input processed         */
   }
   switch (*achl_w1) {                      /* record type             */
     case 0X20:
       goto p_webso_00;                     /* WebSocket functions     */

#if DVC_GRAPHICS
     case 0x60:
         {
			struct dsd_dynvc_client_command dsl_cmd;
			BOOL bol_success = m_receive_client_data(&adsl_contr_1->dsc_svc_drdynvc, achl_w1 + 1, iml_len_payload - 1, &dsl_cmd);
			if (bol_success == FALSE) {
				m_sdh_printf(&dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_receive_client_data() returned error", __LINE__ );
				break;
			}
			struct dsd_gather_i_1_fifo dsl_dynvc_fifo_out;
			m_gather_fifo_init(&dsl_dynvc_fifo_out);
			int inl_dynvc_len_out = m_svc_dynvc_send_data(&adsl_contr_1->dsc_svc_drdynvc, &dsl_output_area_1.dsc_aux_helper,
				&dsl_cmd, &dsl_dynvc_fifo_out);
			struct dsd_gather_i_1* adsl_dynvc_gather_out = dsl_dynvc_fifo_out.adsc_first;

			if (inl_dynvc_len_out < 0) {
				m_sdh_printf(&dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_svc_dynvc_send_data() returned error", __LINE__ );
				break;
			}
			if (inl_dynvc_len_out > 0) {
				struct dsd_workarea_allocator* adsl_wa_alloc = &dsl_output_area_1.dsc_wa_alloc_extern;
				if (inl_dynvc_len_out > CV_DYN_CHANNEL_BUFFER_SIZE) {
					// packet is too large!
					m_sdh_printf(&dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E m_svc_dynvc_send_data() packet is too large!", __LINE__);
					break;
				}
				
				struct dsd_cc_co1* adsl_command = (struct dsd_cc_co1*)m_wa_allocator_alloc_lower(adsl_wa_alloc,
					sizeof(struct dsd_cc_co1) + sizeof(struct dsd_rdp_vch_io), HL_ALIGNOF(struct dsd_rdp_vch_io));
				if (adsl_command == NULL) {
					adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
					return;
				}
				struct dsd_rdp_vch_io* adsl_dynvc_io = (struct dsd_rdp_vch_io*)((uintptr_t)adsl_command + sizeof(struct dsd_cc_co1));
				if ((uintptr_t)adsl_dynvc_io - (uintptr_t)adsl_command != sizeof(struct dsd_cc_co1)) {
					m_sdh_printf(&dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E m_svc_dynvc_receive_message MUST NOT HAPPEN!", __LINE__);
					adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
					return;
				}
		
				adsl_command->iec_cc_command = ied_ccc_vch_out;
				adsl_command->adsc_next = NULL;
				adsl_dynvc_io->adsc_gai1_data = adsl_dynvc_gather_out;
				adsl_dynvc_io->umc_vch_ulen = inl_dynvc_len_out;
				memset(adsl_dynvc_io->chrc_vch_flags, 0, sizeof(adsl_dynvc_io->chrc_vch_flags));
				adsl_dynvc_io->chrc_vch_flags[0] = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST;
				adsl_dynvc_io->adsc_rdp_vc_1 = adsl_contr_1->adsp_rdpacc_drdynvc;
		
				// append to chain
				*dsl_output_area_1.aadsc_cc_co1_ch = adsl_command;
				// position chain of client commands, input
				dsl_output_area_1.aadsc_cc_co1_ch = &adsl_command->adsc_next;
			}
			break;
         }    
#endif //DVC_GRAPHICS
     case 0X21:                             /* mouse / keyboard        */
     {
#define ACHL_G_KEYB_MOUSE (achl_keyb_mouse + sizeof(struct dsd_cc_co1) + sizeof(struct dsd_cc_events_mouse_keyb))
       iml1 = chrl_work2 + sizeof(chrl_work2) - ACHL_G_KEYB_MOUSE;
       if (iml1 <= 0) {                     /* no area for keys        */
         m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W overflow output area for m_proc_mouse_keyboard()",
                       __LINE__ );
         break;
       }
#define ADSL_G_CC_CO1 ((struct dsd_cc_co1 *) achl_keyb_mouse)
#define ADSL_G_EVENTS_MOUSE_KEYB ((struct dsd_cc_events_mouse_keyb *) (ADSL_G_CC_CO1 + 1))
       memset( achl_keyb_mouse, 0, sizeof(struct dsd_cc_co1) + sizeof(struct dsd_cc_events_mouse_keyb) );
       ADSL_G_EVENTS_MOUSE_KEYB->imc_no_order = 0;  /* count keyboard and mouse events */

    // Call to keyboard module
	int iml_touch_data_out = 0;
	struct dsd_gather_i_1* adsl_touch_gather_out = NULL;
#if SM_USE_SEND_EVENTS
	adsl_contr_1->dsc_keyboard_data.achc_out_cur = ACHL_G_KEYB_MOUSE;
	adsl_contr_1->dsc_keyboard_data.achc_out_end = ACHL_G_KEYB_MOUSE + iml1;
#endif
#if CV_TOUCH_REDIR
	struct dsd_gather_i_1_fifo dsl_touch_fifo_out;
	m_gather_fifo_init(&dsl_touch_fifo_out);
     iml1 = m_proc_mouse_keyboard( 
                   &dsl_output_area_1.dsc_aux_helper,
                   &adsl_contr_1->dsc_keyboard_data,
                   &adsl_contr_1->dsc_dvc_input_ex,
#if !SM_USE_SEND_EVENTS
                   ACHL_G_KEYB_MOUSE, 
                   iml1,
#endif
                   &ADSL_G_EVENTS_MOUSE_KEYB->imc_no_order,
                   achl_w1 + 1, 
                   iml_len_payload - 1,
						 &dsl_touch_fifo_out,
                   &iml_touch_data_out
     );
	adsl_touch_gather_out = dsl_touch_fifo_out.adsc_first;
#else 
#ifdef CV_KEYBOARD     
     iml1 = m_proc_mouse_keyboard( 
                   adsp_hl_clib_1,
                   &adsl_contr_1->dsc_keyboard_data,
                   NULL,
#if !SM_USE_SEND_EVENTS
                   ACHL_G_KEYB_MOUSE, 
                   iml1,
#endif
						 &ADSL_G_EVENTS_MOUSE_KEYB->imc_no_order,
                   achl_w1 + 1, 
                   iml_len_payload - 1,
						 NULL,
                   &iml_touch_data_out
     );
#else
      iml1 = m_proc_mouse_keyboard( ACHL_G_KEYB_MOUSE, iml1,
                                     &ADSL_G_EVENTS_MOUSE_KEYB->imc_no_order,
                                     achl_w1 + 1, iml_len_payload - 1 );
#endif
#endif /* CV_TOUCH_REDIR */
     
       if (iml1 < 0) {
         m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_proc_mouse_keyboard() returned error",
                       __LINE__ );
         break;
       }
	if (iml_touch_data_out > 0) {
		struct dsd_workarea_allocator* adsl_wa_alloc = &dsl_output_area_1.dsc_wa_alloc_extern;
		
		//TODO: do segmentation!
		if (iml_touch_data_out > CV_DYN_CHANNEL_BUFFER_SIZE) {
			//segmentation is not yet supported
			m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E m_proc_mouse_keyboard() segmentation is not yet supported", __LINE__);
			adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return;
		}
		
		struct dsd_cc_co1* adsl_command = (struct dsd_cc_co1*)m_wa_allocator_alloc_lower(adsl_wa_alloc,
			sizeof(struct dsd_cc_co1) + sizeof(struct dsd_rdp_vch_io), HL_ALIGNOF(struct dsd_rdp_vch_io));
		if (adsl_command == NULL) {
			adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return;
		}
		struct dsd_rdp_vch_io* adsl_dynvc_io = (struct dsd_rdp_vch_io*)((uintptr_t)adsl_command + sizeof(struct dsd_cc_co1));
		if ((uintptr_t)adsl_dynvc_io - (uintptr_t)adsl_command != sizeof(struct dsd_cc_co1)) {
			m_sdh_printf(&dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E m_svc_dynvc_receive_message MUST NOT HAPPEN!", __LINE__);
			adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return;
		}

		adsl_command->iec_cc_command = ied_ccc_vch_out;
		adsl_command->adsc_next = NULL;
		adsl_dynvc_io->adsc_gai1_data = adsl_touch_gather_out;
		adsl_dynvc_io->umc_vch_ulen = iml_touch_data_out;
		memset(adsl_dynvc_io->chrc_vch_flags, 0, sizeof(adsl_dynvc_io->chrc_vch_flags));
		adsl_dynvc_io->chrc_vch_flags[0] = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST;
		adsl_dynvc_io->adsc_rdp_vc_1 = adsl_contr_1->adsp_rdpacc_drdynvc;

		// append to chain
		*dsl_output_area_1.aadsc_cc_co1_ch = adsl_command;
		// position chain of client commands, input
		dsl_output_area_1.aadsc_cc_co1_ch = &adsl_command->adsc_next;
	}

#ifdef TRACEHL1
       m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T m_proc_mouse_keyboard() returned %d/0X%X events %d.",
                     __LINE__, iml1, iml1, ADSL_G_EVENTS_MOUSE_KEYB->imc_no_order );
#endif
       if (0 && dsl_output_area_1.imc_trace_level) {  /* WSP trace level       */
         memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
         memcpy( dsl_wtrh.chrc_wtrt_id, "SWTRKEM1", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
         dsl_wtrh.imc_wtrh_sno = dsl_output_area_1.imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work3)
         dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
         memset( ADSL_WTR_G1, 0, sizeof(struct dsd_wsp_trace_record) );
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
         ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                            "xl-webterm-rdp-01 l%05d m_proc_mouse_keyboard() returned=%d imc_no_order=%d.",
                                            __LINE__, iml1, ADSL_G_EVENTS_MOUSE_KEYB->imc_no_order );
         achl_w1 = (char *) (ADSL_WTR_G1 + 1) + ((ADSL_WTR_G1->imc_length + sizeof(void *) - 1) & (0 - sizeof(void *)));
         if (iml1 > 0)
         {
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
             memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
             ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
             ADSL_WTR_G2->achc_content = ACHL_G_KEYB_MOUSE;  /* content of text / data */
             ADSL_WTR_G2->imc_length = iml1;
             ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;
#undef ADSL_WTR_G1
         }
#undef ADSL_WTR_G2
         bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                             DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                             &dsl_wtrh,
                                             0 );
       }

       if (iml1 > 0) {
#ifdef TRACEHL1
       m_sdh_console_out( &dsl_output_area_1, ACHL_G_KEYB_MOUSE, iml1 );
#endif
       ADSL_G_EVENTS_MOUSE_KEYB->achc_event_buf = ACHL_G_KEYB_MOUSE;  /* buffer with events */
       ADSL_G_EVENTS_MOUSE_KEYB->imc_events_len = iml1;  /* length of events */
       ADSL_G_CC_CO1->iec_cc_command = ied_ccc_events_mouse_keyb;  /* events from mouse or keyboard */
       *dsl_output_area_1.aadsc_cc_co1_ch = ADSL_G_CC_CO1;     /* append to chain         */
       dsl_output_area_1.aadsc_cc_co1_ch = &ADSL_G_CC_CO1->adsc_next;  /* position chain of client commands, input */
       achl_keyb_mouse += (sizeof(struct dsd_cc_co1) + sizeof(struct dsd_cc_events_mouse_keyb) + iml1 + sizeof(void *) - 1)
                            & (0 - sizeof(void *));
       }
#undef ACHL_G_KEYB_MOUSE
#undef ADSL_G_CC_CO1
#undef ADSL_G_EVENTS_MOUSE_KEYB

     break;
	}
#if SM_USE_PRINTING
	case 0x65:
		// TODO:
		break;
#endif
#if SM_RAIL_CHANNEL
	case 0x66: {
		if(adsl_contr_1->iec_start_mode != ied_d_start_mode_rail)
			break;
		const struct dsd_clib1_conf_1* adsl_conf = ((const struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf);
		for(int inl_a=0; inl_a<adsl_conf->inc_num_remote_apps; inl_a++) {
			if(!m_rail_start_remote_app(&dsl_output_area_1, adsl_conf->adsc_remote_app[inl_a])) {
				return;
			}
		}

		struct dsd_webtermrdp_sid* adsl_sid_data = adsl_contr_1->adsc_sid_data;
		if(adsl_sid_data != NULL) {
			const struct dsd_webtermrdp_remoteapp* adsp_remoteapp = &adsl_sid_data->dsc_remoteapp;
			struct dsd_clib_conf_remote_app dsl_remote_app;
			dsl_remote_app.usc_flags = adsp_remoteapp->usc_flags;
			dsl_remote_app.dsc_exe_or_file.ac_str = ((char*)adsl_sid_data)+adsp_remoteapp->dsc_exe_or_file.inc_offset;
			dsl_remote_app.dsc_exe_or_file.imc_len_str = adsp_remoteapp->dsc_exe_or_file.inc_length;
			dsl_remote_app.dsc_exe_or_file.iec_chs_str = ied_chs_utf_8;
			dsl_remote_app.dsc_working_dir.ac_str = ((char*)adsl_sid_data)+adsp_remoteapp->dsc_working_dir.inc_offset;
			dsl_remote_app.dsc_working_dir.imc_len_str = adsp_remoteapp->dsc_working_dir.inc_length;
			dsl_remote_app.dsc_working_dir.iec_chs_str = ied_chs_utf_8;
			dsl_remote_app.dsc_arguments.ac_str = ((char*)adsl_sid_data)+adsp_remoteapp->dsc_arguments.inc_offset;
			dsl_remote_app.dsc_arguments.imc_len_str = adsp_remoteapp->dsc_arguments.inc_length;
			dsl_remote_app.dsc_arguments.iec_chs_str = ied_chs_utf_8;
			if(dsl_remote_app.dsc_exe_or_file.imc_len_str > 0) {
				if(!m_rail_start_remote_app(&dsl_output_area_1, dsl_remote_app)) {
					return;
				}
			}
		}
		break;
	}
#endif
#if SM_DYNVC_DISP
	case 0x68: {
		m_monitor_layout_changed(&dsl_output_area_1, achl_w1 + 1, iml_len_payload - 1);
		break;
	}
#endif
	default:
		break;
   }

   p_inp_client_76:                         /* input processed         */
   if (bol_compressed) {                    /* input is compressed     */
     if ((((unsigned char) byl_opcode) & 0XBF) == 0X8A) {  /* pong Frame */
       goto p_webso_pong_00;                /* received pong           */
     }
     if (bol_connection_closed) {           /* WebSocket connection close */
       goto p_webso_cc_00;                  /* received connection close */
     }
     goto p_inp_client_24;                  /* check if input from client */
   }

   p_inp_client_80:                         /* input record processed  */
   iml1 = iml_len_header + iml_len_payload;  /* length complete record */
   do {
     iml2 = adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
     if (iml2 > iml1) iml2 = iml1;
     adsl_gai1_inp_1->achc_ginp_cur += iml2;
     iml1 -= iml2;
     if (iml1 <= 0) {                       /* all data consumed       */
       if ((((unsigned char) byl_opcode) & 0XBF) == 0X8A) {  /* pong Frame */
         goto p_webso_pong_00;              /* received pong           */
       }
       if (bol_connection_closed) {         /* WebSocket connection close */
         goto p_webso_cc_00;                /* received connection close */
       }
       goto p_inp_client_24;                /* check if input from client */
     }
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
   } while (adsl_gai1_inp_1);
   /* programm illogic                                                 */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;

   p_inp_client_end:                        /* input from client processed */
     if (adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch == NULL){
       return;  /* position work area, keyboard and mouse events */
             
     }     
#ifndef B150213
   if (adsl_contr_1->dsc_c_wtrc1.inc_return != DEF_IRET_NORMAL) {  /* not o.k. returned */
     return;
   }
#endif
   HL_RDPACC_AUXH(adsl_contr_1->dsc_c_wtrc1).vpc_userfld = dsl_output_area_1.vpc_userfld;  /* User Field Subroutine */
   HL_RDPACC_AUXH(adsl_contr_1->dsc_c_wtrc1).amc_aux = dsl_output_area_1.amc_aux;  /* auxiliary subroutine */
   adsl_contr_1->dsc_c_wtrc1.adsc_gather_i_1_in = NULL;
   goto p_rdp_client_20;                    /* call RDP client         */

   p_webso_pong_00:                         /* received pong           */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T received pong iml_len_payload=%d.",
                 __LINE__, iml_len_payload );
#endif
   goto p_inp_client_24;                    /* check if input from client */

   p_webso_cc_00:                           /* received connection close */
   bol_connection_closed = FALSE;           /* WebSocket connection close */
   /* MS-IE does not send reason                                       */
   iml1 = 0;
   if (iml_len_payload == 0) {              /* nothing from MS-IE      */
     goto p_webso_cc_20;                    /* reason in iml1          */
   }
   if (iml_len_payload != 2) {              /* length complete record  */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E p_webso_cc_00: - received connection close - length payload %d invalid",
                   __LINE__, iml_len_payload );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   iml1 = (*((unsigned char *) achl_w1 + 0) << 8)
            | *((unsigned char *) achl_w1 + 1);

   p_webso_cc_20:                           /* reason in iml1          */
//#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T p_webso_cc_00: - received connection close - reason %d.",
                 __LINE__, iml1 );
//#endif
   if (adsl_contr_1->boc_conn_close_sent) {  /* has already sent connection close */
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* set normal end     */
     goto p_inp_client_24;                  /* check if input from client */
   }
   if ((dsl_output_area_1.achc_upper - dsl_output_area_1.achc_lower) < (2 + 2 + sizeof(struct dsd_gather_i_1))) {  /* need buffer */
     bol_rc = m_get_new_workarea( &dsl_output_area_1 );
     if (bol_rc == FALSE) {
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
   }
   *(dsl_output_area_1.achc_lower + 0) = (unsigned char) 0X88;
   *(dsl_output_area_1.achc_lower + 1) = (unsigned char) 2;
   *(dsl_output_area_1.achc_lower + 2 + 0) = (unsigned char) (1000 >> 8);
   *(dsl_output_area_1.achc_lower + 2 + 1) = (unsigned char) 1000;
   dsl_output_area_1.achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) dsl_output_area_1.achc_upper)
   ADSL_GAI1_G->achc_ginp_cur = dsl_output_area_1.achc_lower;
   dsl_output_area_1.achc_lower += 2 + 2;
   ADSL_GAI1_G->achc_ginp_end = dsl_output_area_1.achc_lower;
   ADSL_GAI1_G->adsc_next = NULL;
   *dsl_output_area_1.aadsrc_gai1_client = ADSL_GAI1_G;  /* output data to client */
   dsl_output_area_1.aadsrc_gai1_client = &ADSL_GAI1_G->adsc_next;  /* next output data to client */
#undef ADSL_GAI1_G
   goto p_inp_client_24;                    /* check if input from client */

   p_webso_server_close_00:                 /* server has closed connection */
   if (adsp_hl_clib_1->boc_eof_server) {    /* End-of-File Server    */
     goto p_webso_server_close_20;          /* WebSocket shutdown      */
   }
   bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                       DEF_AUX_TCP_CLOSE,  /* close TCP to Server */
                                       NULL,
                                       0 );
   if (bol_rc == FALSE) {
     m_sdh_printf( &dsl_output_area_1, "xlt-rdp-cl-se-01-l%05d-W DEF_AUX_TCP_CLOSE WTS returned FALSE",
                   __LINE__ );
#ifdef XYZ1
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
#endif
   }

   p_webso_server_close_20:                 /* WebSocket shutdown      */
#ifdef XYZ1
   switch (adsp_ah1->iec_scc) {             /* server component command */
     case ied_scc_invalid:                  /* command is invalid      */
       return TRUE;
     case ied_scc_end_session:              /* end of session server side */
       iml1 = 1000;
       break;
     case ied_scc_end_shutdown:             /* shutdown of server      */
       iml1 = 1001;
       break;
     default:
       return FALSE;
   }
   if ((adsp_oa->achc_upper - adsp_oa->achc_lower) < (2 + 2 + sizeof(struct dsd_gather_i_1))) {  /* need buffer */
     bol_rc = m_get_new_workarea( adsp_oa );
     if (bol_rc == FALSE) return FALSE;
   }
#endif
       iml1 = 1000;
   if (adsl_contr_1->boc_conn_close_sent) return;  /* has already sent connection close */
   if ((dsl_output_area_1.achc_upper - dsl_output_area_1.achc_lower) < (2 + 2 + sizeof(struct dsd_gather_i_1))) {  /* need buffer */
     bol_rc = m_get_new_workarea( &dsl_output_area_1 );
     if (bol_rc == FALSE) {
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
   }
   *(dsl_output_area_1.achc_lower + 0) = (unsigned char) 0X88;
   *(dsl_output_area_1.achc_lower + 1) = (unsigned char) 2;
   *(dsl_output_area_1.achc_lower + 2 + 0) = (unsigned char) (iml1 >> 8);
   *(dsl_output_area_1.achc_lower + 2 + 1) = (unsigned char) iml1;
   dsl_output_area_1.achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) dsl_output_area_1.achc_upper)
   ADSL_GAI1_G->achc_ginp_cur = dsl_output_area_1.achc_lower;
   dsl_output_area_1.achc_lower += 2 + 2;
   ADSL_GAI1_G->achc_ginp_end = dsl_output_area_1.achc_lower;
   ADSL_GAI1_G->adsc_next = NULL;
   *dsl_output_area_1.aadsrc_gai1_client = ADSL_GAI1_G;  /* output data to client */
// dsl_output_area_1.aadsrc_gai1_client = &ADSL_GAI1_G->adsc_next;  /* next output data to client */
#undef ADSL_GAI1_G
   adsl_contr_1->boc_conn_close_sent = TRUE;  /* has already sent connection close */

#if SM_RDPDR_CHANNEL
	for(int iml_d=0; iml_d<adsl_contr_1->imc_num_devices; iml_d++) {
		m_rdpdr_device_cleanup(&dsl_output_area_1, adsl_contr_1->adsrc_rdpdr_devices[iml_d]);
	}
	adsl_contr_1->imc_num_devices = 0;
   m_svc_rdpdr_destroy(&adsl_contr_1->dsc_svc_rdpdr, &dsl_output_area_1.dsc_aux_helper);
#endif
#if SM_RAIL_CHANNEL
   m_svc_rail_destroy(&adsl_contr_1->dsc_svc_rail, &dsl_output_area_1.dsc_aux_helper);
#endif
   return;                                  /* all done                */

   p_webso_00:                              /* WebSocket functions     */
   if (adsl_contr_1->dsc_awc1.iec_cwc != ied_cwc_invalid) {
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d p_webso_00 invalid",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   achl_w2 = achl_w1 + 1;                   /* start of command string */
#ifdef PROBLEM_JS_140205
   if (*(achl_w1 + iml_len_payload - 1) == 0) {
     iml_len_payload--;
   }
   iml1 = 1;
   while (iml1 < iml_len_payload) {
     if (*(achl_w1 + iml1) == 0) {
       *(achl_w1 + iml1) = ' ';
     }
     iml1++;
   }
#endif

#if SM_USE_CLIENT_PARAMS
	struct dsd_webterm_client_params dsl_webterm_client_params;
	memset(&dsl_webterm_client_params, 0, sizeof(dsl_webterm_client_params));
#if SM_USE_NLA
   dsl_webterm_client_params.dsl_client_userid.iec_chs_str = ied_chs_utf_8;
   dsl_webterm_client_params.dsl_client_userid.imc_len_str = 0;
   dsl_webterm_client_params.dsl_client_password.iec_chs_str = ied_chs_utf_8;
   dsl_webterm_client_params.dsl_client_password.imc_len_str = 0;
   dsl_webterm_client_params.dsl_client_domain.iec_chs_str = ied_chs_utf_8;
   dsl_webterm_client_params.dsl_client_domain.imc_len_str = 0;
#endif
	dsl_webterm_client_params.imc_default_locale = ((struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf)->imc_default_locale;
	iml1 = m_parse_webterm_client_params(&dsl_output_area_1.dsc_aux_helper, achl_w1 + 1, iml_len_payload - 1, &dsl_webterm_client_params);
	if(iml1 != DEF_IRET_NORMAL) {
		adsp_hl_clib_1->inc_return = iml1;  /* invalid data from client */
      return;
   }
	adsl_contr_1->imc_wt_js_width = dsl_webterm_client_params.imc_wt_js_width;
	adsl_contr_1->imc_wt_js_height = dsl_webterm_client_params.imc_wt_js_height;
	adsl_contr_1->imc_wt_js_locale_id = dsl_webterm_client_params.imc_wt_js_locale_id;
#if SM_USE_NLA
	dsl_client_userid = dsl_webterm_client_params.dsl_client_userid;
	dsl_client_password = dsl_webterm_client_params.dsl_client_password;
	dsl_client_domain = dsl_webterm_client_params.dsl_client_domain;
#endif
#if SM_USE_MULTI_MONITOR
	adsl_contr_1->imc_monitor_count = 1;
	adsl_contr_1->dsrc_ts_monitor[0].imc_left = 0;
	adsl_contr_1->dsrc_ts_monitor[0].imc_top = 0;
	adsl_contr_1->dsrc_ts_monitor[0].imc_right = adsl_contr_1->imc_wt_js_width-1;
	adsl_contr_1->dsrc_ts_monitor[0].imc_bottom = adsl_contr_1->imc_wt_js_height-1;
	adsl_contr_1->dsrc_ts_monitor[0].umc_flags = TS_MONITOR_PRIMARY;
#if 0
	adsl_contr_1->imc_monitor_count = 2;
	adsl_contr_1->dsrc_ts_monitor[1].imc_left = adsl_contr_1->imc_wt_js_width;
	adsl_contr_1->dsrc_ts_monitor[1].imc_top = 0;
	adsl_contr_1->dsrc_ts_monitor[1].imc_right = adsl_contr_1->dsrc_ts_monitor[1].imc_left+800-1;
	adsl_contr_1->dsrc_ts_monitor[1].imc_bottom = 600-1;
	adsl_contr_1->dsrc_ts_monitor[1].umc_flags = 0;
#endif
#endif
	adsl_contr_1->dsc_browser_data = dsl_webterm_client_params.dsc_browser_data;
#else
   achl_w3 = achl_w1 + iml_len_payload;     /* end of input area       */
   iml_wt_js_version = -1;                  /* version of WT JS client */
#if SM_USE_NLA
   achl_credentials = chrl_work2;
   dsl_client_userid.iec_chs_str = ied_chs_utf_8;
   dsl_client_userid.imc_len_str = 0;
   dsl_client_password.iec_chs_str = ied_chs_utf_8;
   dsl_client_password.imc_len_str = 0;
   dsl_client_domain.iec_chs_str = ied_chs_utf_8;
   dsl_client_domain.imc_len_str = 0;
#endif
   p_webso_20:                              /* scan string from WS-JS  */
   if (achl_w2 >= achl_w3) {
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" - invalid 01",
                   __LINE__, iml_len_payload, achl_w1 );
#ifdef PROBLEM_KB_140210
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T achl_w1=%p achl_w2=%p achl_w3=%p.",
                   __LINE__, achl_w1, achl_w2, achl_w3 );
     goto p_webso_28;                       /* found values            */
#endif
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   achl_w4 = (char *) memchr( achl_w2, '=', achl_w3 - achl_w2 );
   if (achl_w4 == NULL) {                   /* separator not found     */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" - pos %d no equals - invalid 02",
                   __LINE__, iml_len_payload, achl_w1, achl_w2 - achl_w1 );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   iml1 = achl_w4 - achl_w2;                /* length of keyword       */
   iml2 = sizeof(dss_wt_js_first) / sizeof(dss_wt_js_first[0]);
   do {
	   if (   (dss_wt_js_first[ iml2 - 1 ].inc_len == iml1)
		   && (!memcmp( dss_wt_js_first[ iml2 - 1 ].achc_name, achl_w2, iml1 ))) {
       break;
     }
     iml2--;                                /* decrement index         */
   } while (iml2 > 0);
   if (iml2 == 0) {                         /* parameter not found     */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" - pos %d keyword not recognized - invalid 03",
                   __LINE__, iml_len_payload, achl_w1, achl_w2 - achl_w1 );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }

   char* achl_w6;
   switch (iml2) {
     case (0 + 1):
       aiml_w1 = &iml_wt_js_version;        /* version of WT JS client */
       break;
     case (1 + 1):
       aiml_w1 = &adsl_contr_1->imc_wt_js_width;  /* WT-JS screen width */
       break;
     case (2 + 1):
       aiml_w1 = &adsl_contr_1->imc_wt_js_height;  /* WT-JS screen height */
       break;
#ifdef CV_KEYBOARD
     case (3 + 1):
       aiml_w1 = &adsl_contr_1->imc_wt_js_locale_id;          /* WT-JS locale id          */
       break;
     case (4 + 1):
	   achl_w5 = (char*)chrl_work1;                  /* WT-JS useragent          */
	   achl_w6 = chrl_work1 + sizeof(chrl_work1) - 1;
       break;
     case (5 + 1):
       achl_w5 = (char*)chrl_work1;                  /* WT-JS platform           */
	   achl_w6 = chrl_work1 + sizeof(chrl_work1) - 1;
       break;
#endif /* CV_KEYBOARD */
#if SM_USE_NLA
     case (6 + 1):
     case (7 + 1):
     case (8 + 1):
       achl_w5 = (char*)achl_credentials;
	   achl_w6 = chrl_work2 + sizeof(chrl_work2);
       break;
#endif
     default:
       adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
       return;
   }

#ifdef CV_KEYBOARD
   if (iml2 < 5) {
#endif
   if (*aiml_w1 > 0) {
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" - pos %d keyword no %d double - invalid 04",
                   __LINE__, iml_len_payload, achl_w1, achl_w2 - achl_w1 );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
#ifdef CV_KEYBOARD
   }
#endif

   achl_w4++;                               /* after equals            */
   if (achl_w4 >= achl_w3) {
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" - pos %d keyword no %d no value - invalid 05",
                   __LINE__, iml_len_payload, achl_w1, achl_w2 - achl_w1 );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   iml1 = 0;
   adsl_param = &dss_wt_js_first[ iml2 - 1 ];
#ifdef CV_KEYBOARD
   switch(adsl_param->iec_type) {
   case iec_parameter_type_integer:
	   while (achl_w4 < achl_w3) {
		   if(*achl_w4 == CHAR_CR && ((achl_w4+1) < achl_w3) && (*(achl_w4+1) == CHAR_LF))
			   break;
			iml1 *= 10;
			iml1 += *achl_w4 - '0';
		   achl_w4++;
	   }
	   break;
   case iec_parameter_type_utf8_string:
	   while (achl_w4 < achl_w3) {
		   if(*achl_w4 == CHAR_CR && ((achl_w4+1) < achl_w3) && (*(achl_w4+1) == CHAR_LF))
			   break;
			if (achl_w5 >= achl_w6) {
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client - parameter %d length exceeded (limit %d)",
                   __LINE__, iml2 - 1, iml1 );
			    adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
			    return;
			}
			*achl_w5 = *achl_w4;
			achl_w5++;
			iml1++;
			achl_w4++;
	   }
	   break;
   }
   switch(iml2) {
   case 5: /* User Agent */
	   *achl_w5 = 0;
	   m_parse_user_agent(&adsl_contr_1->dsc_browser_data, achl_w5 - iml1);
	   break;
   case 6: /* Platform */
	   *achl_w5 = 0;
	   m_parse_platform(&adsl_contr_1->dsc_browser_data, achl_w5 - iml1);
	   break;
#if SM_USE_NLA
   case 7: /* UserId */
	   dsl_client_userid.iec_chs_str = ied_chs_utf_8;
	   dsl_client_userid.ac_str = achl_w5 - iml1;
	   dsl_client_userid.imc_len_str = iml1;
	   achl_credentials = achl_w5;
       //m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-I received user id '%.*s'",
       //    __LINE__, dsl_client_userid.imc_len_str, dsl_client_userid.ac_str );
	   break;
   case 8: /* Password */
	   dsl_client_password.iec_chs_str = ied_chs_utf_8;
	   dsl_client_password.ac_str = achl_w5 - iml1;
	   dsl_client_password.imc_len_str = iml1;
	   achl_credentials = achl_w5;
	   //m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-I received password",
       //    __LINE__ );
	   break;
   case 9: /* Domain */
	   dsl_client_domain.iec_chs_str = ied_chs_utf_8;
	   dsl_client_domain.ac_str = achl_w5 - iml1;
	   dsl_client_domain.imc_len_str = iml1;
	   achl_credentials = achl_w5;
	   //m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-I received domain '%.*s'",
       //    __LINE__, dsl_client_domain.imc_len_str, dsl_client_domain.ac_str );
	   break;
#endif
   }

#else /* NOT CV_KEYBOARD */
   while (   (achl_w4 < achl_w3)
          && ((*achl_w4 >= '0') && (*achl_w4 <= '9'))) {
     iml1 *= 10;
     iml1 += *achl_w4 - '0';
     achl_w4++;
   }
#endif /* CV_KEYBOARD */

#ifdef CV_KEYBOARD
   if (iml2 < 5) {
#endif
   if (iml1 < 0) {
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" - pos %d keyword no %d value invalid - invalid 06",
                   __LINE__, iml_len_payload, achl_w1, achl_w2 - achl_w1 );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   *aiml_w1 = iml1;
#ifdef CV_KEYBOARD
   } else {
     achl_w5 = '\0';
   }
#endif

   if (achl_w4 >= achl_w3) {                /* end of string           */
     goto p_webso_28;                       /* found values            */
   }

#ifdef CV_KEYBOARD
   if (*achl_w4 != CHAR_CR && *(achl_w4+1) != CHAR_LF) {                   /* separator invalid       */
#else /* NOT CV_KEYBOARD */
   if (*achl_w4 != ' ') {                   /* separator invalid       */
#endif   
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" - pos %d invalid separator 0X%02X - invalid 06",
                   __LINE__, iml_len_payload, achl_w1, achl_w4 - achl_w1, (unsigned char) *achl_w4 );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }

#ifdef CV_KEYBOARD
   achl_w2 = achl_w4 + 2;                   /* next keyword            */
#else
   achl_w2 = achl_w4 + 1;                   /* next keyword            */
#endif
   goto p_webso_20;                         /* scan string from WS-JS  */

   p_webso_28:                              /* found values            */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T command 0X20 version=%d width=%d height=%d.",
                 __LINE__, iml_wt_js_version, adsl_contr_1->imc_wt_js_width, adsl_contr_1->imc_wt_js_height );
#endif
   if (iml_wt_js_version < 0) {             /* version of WT JS client */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" no version= - invalid 07",
                   __LINE__, iml_len_payload, achl_w1 );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   if (iml_wt_js_version != HL_WT_JS_VERSION) {  /* version of WT JS client */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" version=%d but requested=%d - invalid 08",
                   __LINE__, iml_len_payload, achl_w1, iml_wt_js_version, HL_WT_JS_VERSION );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   if (adsl_contr_1->imc_wt_js_width <= 0) {  /* WT-JS screen width    */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" no width= - invalid 09",
                   __LINE__, iml_len_payload, achl_w1 );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   if (adsl_contr_1->imc_wt_js_height <= 0) {  /* WT-JS screen height  */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" no height= - invalid 10",
                   __LINE__, iml_len_payload, achl_w1 );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
#ifdef CV_KEYBOARD
   if (adsl_contr_1->imc_wt_js_locale_id == 0 && 
       ((struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf)->imc_default_locale > 0)
   {
       adsl_contr_1->imc_wt_js_locale_id = ((struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf)->imc_default_locale;    
   }
   if (adsl_contr_1->imc_wt_js_locale_id <= 0) {  /* WT-JS keyboard locale id  */    
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" no locale id = - invalid 11",
                   __LINE__, iml_len_payload, achl_w1 );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
#endif /* CV_KEYBOARD */
#endif /*SM_USE_CLIENT_PARAMS*/

#if SM_USE_NLA
	{
	BOOL bol_clear_client_creds = TRUE;
   if(adsl_contr_1->adsc_sid_data != NULL && dsl_client_userid.imc_len_str <= 0) {
	   struct dsd_webtermrdp_sid* adsl_sid_data = adsl_contr_1->adsc_sid_data;
	   dsl_client_userid.ac_str = ((char*)adsl_sid_data)+adsl_sid_data->dsc_user.inc_offset;
	   dsl_client_userid.imc_len_str = adsl_sid_data->dsc_user.inc_length;
	   dsl_client_userid.iec_chs_str = ied_chs_utf_8;
	   dsl_client_password.ac_str = ((char*)adsl_sid_data)+adsl_sid_data->dsc_password.inc_offset;
	   dsl_client_password.imc_len_str = adsl_sid_data->dsc_password.inc_length;
	   dsl_client_password.iec_chs_str = ied_chs_utf_8;
	   dsl_client_domain.ac_str = ((char*)adsl_sid_data)+adsl_sid_data->dsc_domain.inc_offset;
	   dsl_client_domain.imc_len_str = adsl_sid_data->dsc_domain.inc_length;
	   dsl_client_domain.iec_chs_str = ied_chs_utf_8;
		bol_clear_client_creds = FALSE;
   }
   // Are credentials provided by WebTerm RDP client? 
   if(dsl_client_userid.imc_len_str > 0) {
	   // Calculate the required size for credentials
	   iml2 = 0;
	   iml1 = m_len_vx_ucs(ied_chs_utf_16, &dsl_client_userid);
	   if (iml1 < 0) {                   /* returned error          */
		 m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d m_len_vx_ucs failed",
					   __LINE__ );
		 adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		 return;
	   }
	   iml2 += iml1;
	   iml1 = m_len_vx_ucs(ied_chs_utf_16, &dsl_client_password);
	   if (iml1 < 0) {                   /* returned error          */
		 m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d m_len_vx_ucs failed",
					   __LINE__ );
		 adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		 return;
	   }
	   iml2 += iml1;
	   iml1 = m_len_vx_ucs(ied_chs_utf_16, &dsl_client_domain);
	   if (iml1 < 0) {                   /* returned error          */
		 m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d m_len_vx_ucs failed",
					   __LINE__ );
		 adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		 return;
	   }
	   iml2 += iml1;
	   iml2++;

	   struct dsd_clib1_contr_1* adsl_contr_1 = (struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext;
	   bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
										   DEF_AUX_MEMGET,
										   &adsl_contr_1->achc_rdp_cred,  /* RDP credentials */
										   iml2*sizeof(HL_WCHAR) );  /* length area */
	   if (bol_rc == FALSE) {                   /* error occured           */
		 adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		 return;
	   }
	   achl_w1 = adsl_contr_1->achc_rdp_cred;   /* RDP credentials         */

		HL_WCHAR* awcl_credentials = (HL_WCHAR*)achl_w1;
		HL_WCHAR* awcl_credentials2 = awcl_credentials + iml2;
		adsl_contr_1->dsc_client_userid.ac_str = awcl_credentials;
		adsl_contr_1->dsc_client_userid.iec_chs_str = ied_chs_le_utf_16;
		iml1 = m_cpy_vx_ucs(awcl_credentials, awcl_credentials2-awcl_credentials, ied_chs_le_utf_16, &dsl_client_userid);
		if (iml1 < 0) {                   /* returned error          */
			m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d m_cpy_vx_ucs failed",
						__LINE__ );
			adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return;
		}
		adsl_contr_1->dsc_client_userid.imc_len_str = iml1;
		awcl_credentials += iml1;
		adsl_contr_1->dsc_client_password.ac_str = awcl_credentials;
		adsl_contr_1->dsc_client_password.iec_chs_str = ied_chs_le_utf_16;
		iml1 = m_cpy_vx_ucs(awcl_credentials, awcl_credentials2-awcl_credentials, ied_chs_le_utf_16, &dsl_client_password);
		if (iml1 < 0) {                   /* returned error          */
			m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d m_cpy_vx_ucs failed",
						__LINE__ );
			adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return;
		}
		adsl_contr_1->dsc_client_password.imc_len_str = iml1;
		awcl_credentials += iml1;
		adsl_contr_1->dsc_client_domain.ac_str = awcl_credentials;
		adsl_contr_1->dsc_client_domain.iec_chs_str = ied_chs_le_utf_16;
		iml1 = m_cpy_vx_ucs(awcl_credentials, awcl_credentials2-awcl_credentials, ied_chs_le_utf_16, &dsl_client_domain);
		if (iml1 < 0) {                   /* returned error          */
			m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d m_cpy_vx_ucs failed",
						__LINE__ );
			adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return;
		}
		adsl_contr_1->dsc_client_domain.imc_len_str = iml1;
		awcl_credentials += iml1;

		// TODO: Use secure zero memory
		if(bol_clear_client_creds) {
			memset(dsl_client_userid.ac_str, 0, m_len_bytes_ucs(&dsl_client_userid));
			memset(dsl_client_password.ac_str, 0, m_len_bytes_ucs(&dsl_client_password));
			memset(dsl_client_domain.ac_str, 0, m_len_bytes_ucs(&dsl_client_domain));
		}
   }
#if SM_USE_CONFIG_RDP_CREDENTIALS
	else if(((struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf)->adsc_rdp_credentials != NULL) {
		struct dsd_clib_conf_rdp_credentials* adsl_rdp_credentials = ((struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf)->adsc_rdp_credentials;
		adsl_contr_1->dsc_client_userid = adsl_rdp_credentials->dsc_user;
		adsl_contr_1->dsc_client_password = adsl_rdp_credentials->dsc_password.ac_str != NULL ? adsl_rdp_credentials->dsc_password : adsl_rdp_credentials->dsc_password_enc;
		adsl_contr_1->dsc_client_domain = adsl_rdp_credentials->dsc_domain;
	}
#endif
   else {
	   bol1 = m_read_single_signon_credentials(adsp_hl_clib_1, &dsl_output_area_1);
	   if(!bol1) {
		   return;
	   }
   }
	}
#if 0
   if(adsl_contr_1->dsc_client_userid.imc_len_str > 0)
	   ((HL_WCHAR*)adsl_contr_1->dsc_client_userid.ac_str)[0] = 'K';
#endif

#if 0
#define SM_WTS_DOMAIN L"HOBTEST01"
#define SM_WTS_PASSWORD L"p123p123!"
#define SM_WTS_USER L"prog01"

	adsl_contr_1->dsc_ntlm_params.dsc_ucs_domain.iec_chs_str = ied_chs_utf_16;
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_domain.ac_str = SM_WTS_DOMAIN;
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_domain.imc_len_str = HL_CONST_STRING_LEN(SM_WTS_DOMAIN);
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_userid.iec_chs_str = ied_chs_utf_16;
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_userid.ac_str = SM_WTS_USER;
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_userid.imc_len_str = HL_CONST_STRING_LEN(SM_WTS_USER);
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_password.iec_chs_str = ied_chs_utf_16;
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_password.ac_str = SM_WTS_PASSWORD;
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_password.imc_len_str = HL_CONST_STRING_LEN(SM_WTS_PASSWORD);
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_workstation.iec_chs_str = ied_chs_utf_16;
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_workstation.ac_str = SM_WTS_WORKSTATION;
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_workstation.imc_len_str = HL_CONST_STRING_LEN(SM_WTS_WORKSTATION);
#endif
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_domain = adsl_contr_1->dsc_client_domain;
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_userid = adsl_contr_1->dsc_client_userid;
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_password = adsl_contr_1->dsc_client_password;
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_workstation.iec_chs_str = ied_chs_utf_8;
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_workstation.imc_len_str = 0;
#define SM_WTS_WORKSTATION L"HOB RD VPN"

#define HL_CONST_STRING_LEN(s) ((sizeof(s)/sizeof(s[0]))-1)
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_workstation.iec_chs_str = ied_chs_utf_16;
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_workstation.ac_str = (char*)SM_WTS_WORKSTATION;
	adsl_contr_1->dsc_ntlm_params.dsc_ucs_workstation.imc_len_str = HL_CONST_STRING_LEN(SM_WTS_WORKSTATION);

	adsl_contr_1->dsc_credssp_params.dsc_ucs_domain = adsl_contr_1->dsc_ntlm_params.dsc_ucs_domain;
	adsl_contr_1->dsc_credssp_params.dsc_ucs_userid = adsl_contr_1->dsc_ntlm_params.dsc_ucs_userid;
	adsl_contr_1->dsc_credssp_params.dsc_ucs_password = adsl_contr_1->dsc_ntlm_params.dsc_ucs_password;

   //adsl_contr_1->dsc_c_wtrc1.dsc_ntlm.adsc_params = &adsl_contr_1->dsc_ntlm_params;
   adsl_contr_1->dsc_ntlm.adsc_params = &adsl_contr_1->dsc_ntlm_params;
   adsl_contr_1->dsc_ntlm.dsc_base.amc_gssapi = &m_gssapi_ntlm_01;
   adsl_contr_1->dsc_credssp_params.adsc_mech = &adsl_contr_1->dsc_ntlm.dsc_base;
   adsl_contr_1->dsc_c_wtrc1.dsc_credssp.adsc_params = &adsl_contr_1->dsc_credssp_params;
   adsl_contr_1->dsc_c_wtrc1.dsc_credssp.dsc_base.amc_gssapi = &m_gssapi_credssp_01;
#endif

// to-do 06.02.14 KB - bol1 correct ???
   bol1 = FALSE;                            /* no input                */

   adsl_contr_1->dsc_awc1.iec_cwc = ied_cwc_open;  /* open - connect to internal routine */
   adsl_contr_1->dsc_awc1.imc_signal = 1 << HL_RDPDR_WEBSOCKET_SIGNAL;  /* signal to set   */
   bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                       DEF_AUX_WEBSO_CONN,  /* connect for WebSocket applications */
                                       &adsl_contr_1->dsc_awc1,
                                       sizeof(struct dsd_aux_webso_conn_1) );
   if (bol_rc == FALSE) {                   /* returned error          */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d DEF_AUX_WEBSO_CONN returned error",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#ifdef TRACEHL2X
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d DEF_AUX_WEBSO_CONN returned type of WebSocket connect - iec_twc %d.",
                 __LINE__, adsl_contr_1->dsc_awc1.iec_twc );
#endif
   switch (adsl_contr_1->dsc_awc1.iec_twc) {  /* type of WebSocket connect */
     case ied_twc_static:                   /* static, server configured */
       break;
	 case ied_twc_dynamic:                  /* dynamic, nothing configured */
		 goto p_lbdyn_s_00;                      /* connect to server       */
     case ied_twc_lbal:                     /* WTS load-balancing      */
       goto p_lbvdi_s_00;                   /* send WTS load-balancing or VDI */
     case ied_twc_vdi:                      /* VDI                     */
       goto p_lbvdi_s_00;                   /* send WTS load-balancing or VDI */
     case ied_twc_pttd:                     /* pass thru to desktop - DOD desktop-on-demand */
       goto p_webso_40;                     /* WebSocket DoD - desktop-on-demand */
     default:
		 m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d unknown websocket connection type",
			__LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
   }
// bol1 = TRUE;                             /* need to process input   */
// to-do 06.02.14 KB - bol1 correct ???
   goto p_webso_80;                         /* close WebSocket         */

p_lbdyn_s_00:
	{
#if 1
	   const struct dsd_webtermrdp_sid* adsl_sid_data = adsl_contr_1->adsc_sid_data;
		if(adsl_sid_data == NULL) {
			m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d no dynamic connection data available",
				__LINE__ );
			adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return;
		}
		const struct dsd_cma_string* adsl_serverineta = &adsl_sid_data->dsc_serverineta;
		if(adsl_serverineta->inc_length == 0) {
			m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d no dynamic serverineta available",
				__LINE__ );
			adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return;
		}
#endif
		/* connect to server now                                            */
		memset( &dsl_atc1_1, 0, sizeof(dsl_atc1_1) );
		dsl_atc1_1.dsc_target_ineta.ac_str = ((char*)adsl_sid_data)+adsl_serverineta->inc_offset;
		dsl_atc1_1.dsc_target_ineta.imc_len_str = adsl_serverineta->inc_length;
		dsl_atc1_1.dsc_target_ineta.iec_chs_str = ied_chs_utf_8;  /* character set string */
		dsl_atc1_1.imc_server_port = adsl_sid_data->inc_serverport;  /* TCP port to connect to */
		if(dsl_atc1_1.imc_server_port == 0)
			dsl_atc1_1.imc_server_port = 3389;
		bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
														DEF_AUX_TCP_CONN,
														&dsl_atc1_1,
														sizeof(dsl_atc1_1) );
		if (bol_rc == FALSE) {
			m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d dynamic connect to %.*s:%d failed",
				__LINE__, dsl_atc1_1.dsc_target_ineta.imc_len_str, dsl_atc1_1.dsc_target_ineta.ac_str,
				dsl_atc1_1.imc_server_port);
			adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return;
		}
	}
   goto p_webso_80;                         /* close WebSocket         */

p_lbvdi_s_00:                            /* send WTS load-balancing or VDI */
#if SM_USE_NLA
   achl_w1 = chrl_work1;
   achl_w2 = chrl_work1 + sizeof(chrl_work1);
   achl_w1 += 5;
   achl_w3 = achl_w1;
   memcpy(achl_w3, chrs_lbal_01+1, sizeof(chrs_lbal_01)-1);
   achl_w3 += sizeof(chrs_lbal_01)-1;
   if(adsl_contr_1->dsc_client_userid.imc_len_str > 0) {
		int iml_userid_len = m_len_vx_ucs(ied_chs_utf_8, &adsl_contr_1->dsc_client_userid);
		int iml_domain_len = 0;
		int im_len = 1 + iml_userid_len + 1;
		/* Has domain? */
		if(adsl_contr_1->dsc_client_domain.imc_len_str > 0) {
			iml_domain_len = m_len_vx_ucs(ied_chs_utf_8, &adsl_contr_1->dsc_client_domain);
			im_len += iml_domain_len + 1;
		}
		achl_w3 += m_out_nhasn1(achl_w3, (int)m_get_inclusive_hasn1_uint32_be(im_len));
		*achl_w3++ = 0x01; /* Requested user id. */
		iml1 = m_cpy_vx_ucs(achl_w3, achl_w2-achl_w3, ied_chs_utf_8, &adsl_contr_1->dsc_client_userid);
		if(iml1 != iml_userid_len) {
			m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d m_cpy_vx_ucs returned error",
						   __LINE__ );
			adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		    return;
		}
		achl_w3 += iml1;
		*achl_w3++ = 0;
		if(iml_domain_len > 0) {
			iml1 = m_cpy_vx_ucs(achl_w3, achl_w2-achl_w3, ied_chs_utf_8, &adsl_contr_1->dsc_client_domain);
			if(iml1 != iml_domain_len) {
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d m_cpy_vx_ucs returned error",
							   __LINE__ );
				adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
				return;
			}
			achl_w3 += iml1;
			*achl_w3++ = 0;
		}
	}
	iml1 = (int)(achl_w3 - achl_w1);
	iml2 = m_get_inclusive_hasn1_uint32_be(iml1);
	achl_w1 -= (iml2 - iml1);
	m_out_nhasn1(achl_w1, iml2);
   adsl_contr_1->dsc_awc1.achc_lbvdi_send = (char *) achl_w1;  /* address data send WTS load-balancing or VDI */
   adsl_contr_1->dsc_awc1.imc_len_lbvdi_send = (int)(achl_w3 - achl_w1);  /* length data send WTS load-balancing or VDI */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T send WTS load-balancing or VDI length %d.",
                 __LINE__, adsl_contr_1->dsc_awc1.imc_len_lbvdi_send );
   m_sdh_console_out( &dsl_output_area_1, adsl_contr_1->dsc_awc1.achc_lbvdi_send, adsl_contr_1->dsc_awc1.imc_len_lbvdi_send );
#endif
   
#else
   adsl_contr_1->dsc_awc1.achc_lbvdi_send = (char *) chrs_lbal_01;  /* address data send WTS load-balancing or VDI */
   adsl_contr_1->dsc_awc1.imc_len_lbvdi_send = sizeof(chrs_lbal_01);  /* length data send WTS load-balancing or VDI */
#endif
   adsl_contr_1->dsc_awc1.iec_cwc = ied_cwc_lbvdi_send;  /* send data WTS load-balancing or VDI */
   bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                    DEF_AUX_WEBSO_CONN,  /* connect for WebSocket applications */
                                    &adsl_contr_1->dsc_awc1,
                                    sizeof(struct dsd_aux_webso_conn_1) );
   if (bol_rc == FALSE) {                   /* returned error          */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d DEF_AUX_WEBSO_CONN returned error",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   return;

   p_webso_40:                              /* WebSocket DoD - desktop-on-demand */
   memset( &dsl_dod_query.dsc_wt_dod_info, 0, sizeof(dsl_dod_query.dsc_wt_dod_info) );
   bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                    DEF_AUX_GET_SESS_STOR, /* get Session Storage */
                                    &dsl_dod_query,
                                    sizeof(dsl_dod_query) );
   if (bol_rc == FALSE) {                   /* returned error          */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d DEF_AUX_GET_SESS_STOR returned error",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (dsl_output_area_1.imc_trace_level) {    /* WSP trace level         */
     memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
     memcpy( dsl_wtrh.chrc_wtrt_id, "SWTRGSS1", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
     dsl_wtrh.imc_wtrh_sno = dsl_output_area_1.imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work3)
     dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
     memset( ADSL_WTR_G1, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
     ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
     ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                        "xl-webterm-rdp-01 l%05d DoD DEF_AUX_GET_SESS_STOR retrieved",
                                        __LINE__ );
     achl_w1 = (char *) (ADSL_WTR_G1 + 1) + ((ADSL_WTR_G1->imc_length + sizeof(void *) - 1) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
     memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed     */
     ADSL_WTR_G2->achc_content = (char *) &dsl_dod_query;  /* content of text / data */
     ADSL_WTR_G2->imc_length = sizeof(dsl_dod_query);
     ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                      DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                      &dsl_wtrh,
                                      0 );
   }
   if (dsl_dod_query.dsc_wt_dod_info.imc_len_str == 0) {  /* length string in elements */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d DEF_AUX_GET_SESS_STOR did not find DoD information",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#define ADSL_WTR1_G ((struct dsd_wt_record_1 *) chrl_work1)
   memset( ADSL_WTR1_G, 0, sizeof(struct dsd_wt_record_1) + sizeof(struct dsd_gather_i_1) );
   ADSL_WTR1_G->ucc_record_type = ie_wtsc_begin_dod;     /* record type             */
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) (ADSL_WTR1_G + 1))
   if ((dsl_output_area_1.achc_upper - dsl_output_area_1.achc_lower) < 4) {  /* need buffer */
     bol_rc = m_get_new_workarea( &dsl_output_area_1 );
     if (bol_rc == FALSE) {
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
   }
   ADSL_GAI1_G->achc_ginp_cur = dsl_output_area_1.achc_lower;
   dsl_output_area_1.achc_lower
     += m_out_nhasn1( dsl_output_area_1.achc_lower, dsl_dod_query.dsc_wt_dod_info.imc_waitconn );
   ADSL_GAI1_G->achc_ginp_end = dsl_output_area_1.achc_lower;
   ADSL_WTR1_G->adsc_gai1_data = ADSL_GAI1_G;  /* output data be be sent to client */
#undef ADSL_GAI1_G
#if DEBUG_WEBSOCKETS
        {
        int iml_tmp = ADSL_WTR1_G->adsc_gai1_data->achc_ginp_end - ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur;
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_rdpclient_1() send websocket data record type: %d achc_ginp_cur: %d achc_ginp_end: %d  (first 16 bytes:)",
                       __LINE__ ,ADSL_WTR1_G->ucc_record_type,ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur  ,ADSL_WTR1_G->adsc_gai1_data->achc_ginp_end  );        
        m_sdh_console_out( &dsl_output_area_1, ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur, (iml_tmp > 16) ? 16 : iml_tmp );
		}
#endif
   bol_rc = m_send_websocket_data( &dsl_output_area_1, adsl_contr_1, ADSL_WTR1_G );
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#undef ADSL_WTR1_G
   adsl_contr_1->dsc_awc1.dsc_ucs_target.ac_str = dsl_dod_query.chrc_dod_ineta;  /* address of string */
   adsl_contr_1->dsc_awc1.dsc_ucs_target.imc_len_str = dsl_dod_query.dsc_wt_dod_info.imc_len_str;  /* length string in elements */
   adsl_contr_1->dsc_awc1.dsc_ucs_target.iec_chs_str = ied_chs_idna_1;  /* IDNA RFC 3492 etc. - Punycode */
#ifdef PROBLEM_WS_140212
   adsl_contr_1->dsc_awc1.dsc_ucs_target.iec_chs_str = ied_chs_utf_8;  /* Unicode UTF-8 */
#endif
   adsl_contr_1->dsc_awc1.imc_port = dsl_dod_query.dsc_wt_dod_info.imc_port;  /* port to connect to */
   adsl_contr_1->dsc_awc1.boc_with_macaddr = dsl_dod_query.dsc_wt_dod_info.boc_with_macaddr;  /* macaddr is included */
   memcpy( adsl_contr_1->dsc_awc1.chrc_macaddr,
           dsl_dod_query.dsc_wt_dod_info.chrc_macaddr,
           sizeof(adsl_contr_1->dsc_awc1.chrc_macaddr) );  /* macaddr switch on */
   adsl_contr_1->dsc_awc1.imc_waitconn = dsl_dod_query.dsc_wt_dod_info.imc_waitconn;  /* wait for connect compl */
   adsl_contr_1->dsc_awc1.iec_cwc = ied_cwc_conn;  /* connect to target */
   bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                    DEF_AUX_WEBSO_CONN,  /* connect for WebSocket applications */
                                    &adsl_contr_1->dsc_awc1,
                                    sizeof(struct dsd_aux_webso_conn_1) );
   if (bol_rc == FALSE) {                   /* returned error          */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d DEF_AUX_WEBSO_CONN returned error",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#ifdef TRACEHL2X
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d DEF_AUX_WEBSO_CONN returned type of WebSocket connect - iec_twc %d.",
                 __LINE__, adsl_contr_1->dsc_awc1.iec_twc );
#endif
   goto p_inp_client_76;                    /* input processed         */

   p_webso_60:                              /* status WebSocket no more active */
   bol1 = FALSE;                            /* need to check input     */
   if (adsl_contr_1->dsc_awc1.boc_connected) {  /* connected to target / server */
#define ADSL_WTR1_G ((struct dsd_wt_record_1 *) chrl_work1)
     memset( ADSL_WTR1_G, 0, sizeof(struct dsd_wt_record_1) + sizeof(struct dsd_gather_i_1) );
     ADSL_WTR1_G->ucc_record_type = ie_wtsc_rdp_connect_success;   /* record type             */
     ADSL_WTR1_G->adsc_gai1_data = NULL;    /* output data be be sent to client */
#if DEBUG_WEBSOCKETS
          {               
        int iml_tmp = ADSL_WTR1_G->adsc_gai1_data->achc_ginp_end - ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur;
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_rdpclient_1() send websocket data record type: %d achc_ginp_cur: %d achc_ginp_end: %d  (first 16 bytes:)",
                       __LINE__ ,ADSL_WTR1_G->ucc_record_type,ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur  ,ADSL_WTR1_G->adsc_gai1_data->achc_ginp_end  );        
        m_sdh_console_out( &dsl_output_area_1, ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur, (iml_tmp > 16) ? 16 : iml_tmp );
        
        }
#endif
     bol_rc = m_send_websocket_data( &dsl_output_area_1, adsl_contr_1, ADSL_WTR1_G );
     if (bol_rc == FALSE) {                 /* error occured           */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
     goto p_webso_80;                       /* close WebSocket         */
#undef ADSL_WTR1_G
   }
#define ADSL_WTR1_G ((struct dsd_wt_record_1 *) chrl_work1)
   memset( ADSL_WTR1_G, 0, sizeof(struct dsd_wt_record_1) + sizeof(struct dsd_gather_i_1) );
   ADSL_WTR1_G->ucc_record_type = ie_wtsc_rdp_connect_failed;     /* record type             */
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) (ADSL_WTR1_G + 1))
   if ((dsl_output_area_1.achc_upper - dsl_output_area_1.achc_lower) < (6 + 40)) {  /* need buffer */
     bol_rc = m_get_new_workarea( &dsl_output_area_1 );
     if (bol_rc == FALSE) {
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
   }
   ADSL_GAI1_G->achc_ginp_cur = dsl_output_area_1.achc_lower;
   dsl_output_area_1.achc_lower
     += m_out_nhasn1( dsl_output_area_1.achc_lower, adsl_contr_1->dsc_awc1.imc_connect_error );  /* connect error */
   if (adsl_contr_1->dsc_awc1.imc_connect_error != 30000) {  /* connect error */
     iml1 = sprintf( dsl_output_area_1.achc_lower, "server connect error %d.",
                     adsl_contr_1->dsc_awc1.imc_connect_error );  /* connect error */
   } else {
     iml1 = sprintf( dsl_output_area_1.achc_lower, "load-balancing - no server replied" );
   }
   dsl_output_area_1.achc_lower += iml1;
   ADSL_GAI1_G->achc_ginp_end = dsl_output_area_1.achc_lower;
   ADSL_WTR1_G->adsc_gai1_data = ADSL_GAI1_G;  /* output data be be sent to client */
#undef ADSL_GAI1_G
#if DEBUG_WEBSOCKETS
        {
        int iml_tmp = ADSL_WTR1_G->adsc_gai1_data->achc_ginp_end - ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur;
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_rdpclient_1() send websocket data record type: %d achc_ginp_cur: %d achc_ginp_end: %d  (first 16 bytes:)",
                       __LINE__ ,ADSL_WTR1_G->ucc_record_type,ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur  ,ADSL_WTR1_G->adsc_gai1_data->achc_ginp_end  );        
        m_sdh_console_out( &dsl_output_area_1, ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur, (iml_tmp > 16) ? 16 : iml_tmp );        
        }
#endif
   bol_rc = m_send_websocket_data( &dsl_output_area_1, adsl_contr_1, ADSL_WTR1_G );
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#undef ADSL_WTR1_G

   bol1 = TRUE;                             /* do not start RDP        */
   adsl_gai1_inp_1 = NULL;                  /* no input from client    */

   /* client needs to close WebSocket connection                       */

   p_webso_80:                              /* close WebSocket         */
   adsl_contr_1->dsc_awc1.iec_cwc = ied_cwc_close;  /* close connection to internal routine */
   bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                       DEF_AUX_WEBSO_CONN,  /* connect for WebSocket applications */
                                       &adsl_contr_1->dsc_awc1,
                                       sizeof(struct dsd_aux_webso_conn_1) );
   if (bol_rc == FALSE) {                   /* returned error          */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d DEF_AUX_WEBSO_CONN returned error",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#ifdef TRACEHL2X
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01 m_hlclib01() l%05d DEF_AUX_WEBSO_CONN returned type of WebSocket connect - iec_twc %d bol1 %d.",
                 __LINE__, adsl_contr_1->dsc_awc1.iec_twc, bol1 );
#endif
// to-do 06.02.14 KB - bol1 correct ???
   if (bol1) {                              /* need to process input   */
     if (adsl_gai1_inp_1 == NULL) return;   /* no input from client    */
     goto p_inp_client_76;                  /* input processed         */
   }
// goto p_call_40;                          /* continue call of SDH    */
// --- new 06.02.14 KB - start
#ifdef WA_150216_02
   if (adsl_contr_1->dsc_c_wtrc1.inc_return != DEF_IRET_NORMAL) {  /* not o.k. returned */
     return;
   }
#endif
   /* start WebTerm RDP Client                                         */
   HL_RDPACC_AUXH(adsl_contr_1->dsc_c_wtrc1).vpc_userfld = dsl_output_area_1.vpc_userfld;  /* User Field Subroutine */
   HL_RDPACC_AUXH(adsl_contr_1->dsc_c_wtrc1).amc_aux = dsl_output_area_1.amc_aux;  /* auxiliary subroutine */
#if SM_USE_NLA
   m_wt_rdp_client_2( &adsl_contr_1->dsc_c_wtrc1 );
#else
   m_wt_rdp_client_1( &adsl_contr_1->dsc_c_wtrc1 );
#endif
#ifdef TRACEHL1
#ifdef XYZ1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T M_AWCS_SERVER_1() returned inc_return=%d adsc_gai1_out_to_client=%p adsc_cl_co1_ch=%p.",
                 __LINE__,
                 adsl_contr_1->dsc_c_awcs_se_1.inc_return,
                 adsl_contr_1->dsc_c_awcs_se_1.adsc_gai1_out_to_client,
                 adsl_contr_1->dsc_c_awcs_se_1.adsc_cl_co1_ch );
#endif
#endif
   if (adsl_contr_1->dsc_c_wtrc1.inc_return != DEF_IRET_NORMAL) {  /* not o.k. returned */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_wt_rdp_client_1() returned inc_return=%d - invalid",
                   __LINE__, adsl_contr_1->dsc_c_wtrc1.inc_return );
   }
   /* prepare virtual channels, take all of the server                 */
#ifdef XYZ1
   if (adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_no_virt_ch > 0) {  /* number of virtual channels */
     iml1 = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_no_virt_ch * sizeof(struct dsd_rdp_vc_1);
     bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                     DEF_AUX_MEMGET,
                                     &adsl_contr_1->dsc_c_rdp_cl_1.adsc_rdp_co->adsrc_vc_1,  /* array of virtual channels */
                                     iml1 );
     if (bol1 == FALSE) {
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
     adsl_contr_1->dsc_c_rdp_cl_1.adsc_rdp_co->imc_no_virt_ch
       = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_no_virt_ch;  /* number of virtual channels */
     memcpy( adsl_contr_1->dsc_c_rdp_cl_1.adsc_rdp_co->adsrc_vc_1,  /* array of virtual channels */
             adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->adsrc_vc_1,  /* array of virtual channels */
             iml1 );
   }
#endif
   adsl_contr_1->dsc_c_wtrc1.inc_func = DEF_IFUNC_REFLECT;
   memcpy( &dsl_cc_co1_all.dsc_cc_co1, &dss_cc_co1_start_client, sizeof(struct dsd_cc_co1) );  /* client component command */
   memset( &dsl_cc_co1_all.dsc_cc_start_rdp_client, 0, sizeof(struct dsd_cc_start_rdp_client) );

   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_dim_x  /* dimension x pixels */
//   = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_dim_x;
//   = 640;
//   = 1080,
     = adsl_contr_1->imc_wt_js_width;       /* WT-JS screen width      */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_dim_y  /* dimension y pixels */
//   = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_dim_y;
//   = 480;
//   = 800;
     = adsl_contr_1->imc_wt_js_height;      /* WT-JS screen height     */

#ifdef CV_KEYBOARD
    /* Uncomment the statement below to propagate the locale id into the cc_start_rdp_client structure */ 
    // Set locale id to that retrieved from client.
    //dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_keyboard_layout = adsl_contr_1->imc_wt_js_locale_id;
    //m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W client keyboard set to %d",
    //              __LINE__, dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_keyboard_layout);

   dsd_keyboard_init dsl_keyboard_init;

   // Set localeid
   dsl_keyboard_init.imc_layout_id = adsl_contr_1->imc_wt_js_locale_id;

   // Set browser data
   dsl_keyboard_init.adsc_browser_data = &adsl_contr_1->dsc_browser_data;

   // Initialize keyboard data
   iml1 = m_init_mouse_keyboard(&adsl_contr_1->dsc_keyboard_data, &dsl_keyboard_init);

   // Error Occured
   if (iml1 < 0) {
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Error when initializing keyboard data: %d.",
     __LINE__, iml1);    
  adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU; 
     return;
   }

#endif /* CV_KEYBOARD */

#if CV_DYN_CHANNEL

   // Set up Static Virtual Channel Dynamic Channel Tunnelling
   m_init_drdynvc(&adsl_contr_1->dsc_svc_drdynvc);
   adsl_contr_1->dsc_svc_drdynvc.amc_sdh_printf = m_sdh_printf2;
   adsl_contr_1->dsc_svc_drdynvc.avoc_context = &dsl_output_area_1;

#if CV_TOUCH_REDIR
	adsl_contr_1->dsc_dvc_create_listener_input.achc_name = STR_DYNVC_NAME_INPUT;
	adsl_contr_1->dsc_dvc_create_listener_input.avoc_context = adsl_contr_1;
	adsl_contr_1->dsc_dvc_create_listener_input.m_create = m_dynvc_create_input;
	m_register_listener(&adsl_contr_1->dsc_svc_drdynvc, &adsl_contr_1->dsc_dvc_create_listener_input);
   // Set up Dynamic Virtual Channel for Touch Redirection - RDPEI
   //m_init_rdpei(&adsl_contr_1->dsc_svc_drdynvc, &adsl_contr_1->dsc_dvc_input_ex);

#if 0
   // Set up Touch Redirection Listener
   adsl_contr_1->dsc_dvc_input_listener.achc_name = STR_DYNVC_NAME_INPUT;
   adsl_contr_1->dsc_dvc_input_listener.avoc_dvc = &adsl_contr_1->dsc_dvc_input_ex;
   adsl_contr_1->dsc_dvc_input_listener.m_receive_data = &m_input_dvc_receive_data;

   // Register Touch Redirection Listener
   m_register_listener(&adsl_contr_1->dsc_svc_drdynvc, adsl_contr_1->dsc_dvc_input_listener);
#endif

#endif /* CV_TOUCH_REDIR */
#if DVC_GRAPHICS
	adsl_contr_1->dsc_dvc_create_listener_graphics.achc_name = STR_DYNVC_NAME_EGFX;
	adsl_contr_1->dsc_dvc_create_listener_graphics.avoc_context = adsl_contr_1;
	adsl_contr_1->dsc_dvc_create_listener_graphics.m_create = m_dynvc_create_graphics;
	m_register_listener(&adsl_contr_1->dsc_svc_drdynvc, &adsl_contr_1->dsc_dvc_create_listener_graphics);
   //m_init_dvc_graphics(&adsl_contr_1->dsc_svc_drdynvc, &adsl_contr_1->dsc_dvc_graphics_ex);
#endif

#endif /* CV_DYN_CHANNEL */

#if SM_DYNVC_DISP
	adsl_contr_1->dsc_dvc_create_listener_disp.achc_name = STR_DYNVC_NAME_DISP;
	adsl_contr_1->dsc_dvc_create_listener_disp.avoc_context = adsl_contr_1;
	adsl_contr_1->dsc_dvc_create_listener_disp.m_create = m_dynvc_create_disp;
	m_register_listener(&adsl_contr_1->dsc_svc_drdynvc, &adsl_contr_1->dsc_dvc_create_listener_disp);
   //m_init_dvc_disp(&adsl_contr_1->dsc_svc_drdynvc, &adsl_contr_1->dsc_dvc_disp);
#endif

#if SM_RDPDR_CHANNEL
   m_svc_rdpdr_init(&adsl_contr_1->dsc_svc_rdpdr, &dsl_output_area_1.dsc_aux_helper, adsl_contr_1->adsp_rdpacc_rdpdr);
#endif /* SM_RDPDR_CHANNEL */

#if SM_RAIL_CHANNEL
   m_svc_rail_init(&adsl_contr_1->dsc_svc_rail, &dsl_output_area_1.dsc_aux_helper, adsl_contr_1->adsp_rdpacc_rail);
#endif /* SM_RAIL_CHANNEL */

#if SM_USE_MULTI_MONITOR
	dsl_cc_co1_all.dsc_cc_start_rdp_client.boc_multimonitor_support = TRUE;
	dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_monitor_count = adsl_contr_1->imc_monitor_count;
	dsl_cc_co1_all.dsc_cc_start_rdp_client.adsrc_ts_monitor = adsl_contr_1->dsrc_ts_monitor;
	dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_monitor_attributes_count = 0;
	dsl_cc_co1_all.dsc_cc_start_rdp_client.adsrc_ts_monitor_attributes = adsl_contr_1->dsrc_ts_monitor_attributes;
#endif

#if SM_USE_NLA
   dsl_cc_co1_all.dsc_cc_start_rdp_client.dsc_rdp_neg_req.umc_requested_protocols =
	   ((struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf)->imc_rdp_security_flags;
   if(adsl_contr_1->vpc_ssl_config == NULL)
	   dsl_cc_co1_all.dsc_cc_start_rdp_client.dsc_rdp_neg_req.umc_requested_protocols = PROTOCOL_RDP;
   dsl_cc_co1_all.dsc_cc_start_rdp_client.dsc_rdp_neg_req.usc_flags = 0;
#endif

#ifdef XYZ1
#ifdef B121231
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_coldep  /* colour depth  */
     = 16;
#else
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_coldep  /* colour depth  */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_cl_coldep;
#endif
   if (   (adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_cl_coldep == 24)
       && (adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_cl_supported_color_depth & RNS_UD_32BPP_SUPPORT)
       && (adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_cl_early_capability_flag & RNS_UD_CS_WANT_32BPP_SESSION)) {
#endif
     dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_coldep = 32;
#ifdef XYZ1
   }
#endif
#ifdef XYZ1
#ifndef B130116
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_keyboard_layout  /* Keyboard Layout */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_keyboard_layout;  /* Keyboard Layout */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_keyboard_type  /* Type of Keyboard / 102 */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_keyboard_type;  /* Type of Keyboard / 102 */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_keyboard_subtype  /* Subtype of Keyboard */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_keyboard_subtype;  /* Subtype of Keyboard */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_no_func_keys  /* Number of Function Keys */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_no_func_keys;  /* Number of Function Keys */
#endif
// to-do 10.04.12 KB - should RDP-client generate umc_loinf_options from other values - like compression ???
   dsl_cc_co1_all.dsc_cc_start_rdp_client.umc_loinf_options  /* Logon Info Options */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->umc_loinf_options;  /* Logon Info Options */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_domna_len  /* Domain Name Length */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_loinf_domna_len;  /* Domain Name Length */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_domna_a  /* Domain Name */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->awcc_loinf_domna_a;  /* Domain Name */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_userna_len  /* User Name Length */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_loinf_userna_len;  /* User Name Length */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_userna_a  /* User Name */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->awcc_loinf_userna_a;  /* User Name */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_pwd_len  /* Password Length */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_loinf_pwd_len;  /* Password Length */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_pwd_a  /* Password */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->awcc_loinf_pwd_a;  /* Password */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_altsh_len  /* Alt Shell Length */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_loinf_altsh_len;  /* Alt Shell Length */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_altsh_a  /* Alt Shell */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->awcc_loinf_altsh_a;  /* Alt Shell */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_wodir_len  /* Working Directory Length */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_loinf_wodir_len;  /* Working Directory Length */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_wodir_a  /* Working Directory */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->awcc_loinf_wodir_a;  /* Working Directory */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_ineta_len  /* INETA Length */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_loinf_ineta_len;  /* INETA Length */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_ineta_a  /* INETA */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->awcc_loinf_ineta_a;  /* INETA */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_path_len  /* Client Path Length */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_loinf_path_len;  /* Client Path Length */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_path_a  /* Client Path */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->awcc_loinf_path_a;  /* Client Path */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_no_a_par  /* number of additional parameters */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_loinf_no_a_par;  /* number of additional parameters */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_extra_len  /* Extra Parameters Length */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->usc_loinf_extra_len;  /* Extra Parameters Length */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_extra_a  /* Extra Parameters */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->awcc_loinf_extra_a;  /* Extra Parameters */
#ifndef TRY_NO_VIRCH_01                     /* 23.04.12 KB - try without virtual channels */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_no_virt_ch  /* number of virtual channels */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->imc_no_virt_ch;  /* number of virtual channels */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.adsrc_vc_1  /* array of virtual channels */
     = adsl_contr_1->dsc_c_awcs_se_1.adsc_rdp_co->adsrc_vc_1;  /* array of virtual channels */
#endif
#endif

   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_no_virt_ch = 0;
   // Allocate memory for RDP-ACC Static Virtual Channel (SVC) Structure
   memset( adsl_contr_1->dsrc_rdpacc_svc, 0, sizeof(adsl_contr_1->dsrc_rdpacc_svc) );
   dsl_cc_co1_all.dsc_cc_start_rdp_client.adsrc_vc_1 = adsl_contr_1->dsrc_rdpacc_svc;
#if SM_RDPDR_CHANNEL
   adsl_contr_1->adsp_rdpacc_rdpdr = &adsl_contr_1->dsrc_rdpacc_svc[dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_no_virt_ch];
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_no_virt_ch++;
   memcpy(adsl_contr_1->adsp_rdpacc_rdpdr->byrc_name, "rdpdr", 5);
   adsl_contr_1->adsp_rdpacc_rdpdr->imc_flags = CHANNEL_OPTION_INITIALIZED | CHANNEL_OPTION_COMPRESS_RDP | CHANNEL_OPTION_ENCRYPT_RDP | CHANNEL_OPTION_PRI_LOW;
#endif
#if SM_RDPSND_CHANNEL
   adsl_contr_1->adsp_rdpacc_rdpsnd = &adsl_contr_1->dsrc_rdpacc_svc[dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_no_virt_ch];
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_no_virt_ch++;
   memcpy(adsl_contr_1->adsp_rdpacc_rdpsnd->byrc_name, "rdpsnd", 6);
   adsl_contr_1->adsp_rdpacc_rdpsnd->imc_flags = CHANNEL_OPTION_INITIALIZED | CHANNEL_OPTION_COMPRESS_RDP | CHANNEL_OPTION_ENCRYPT_RDP | CHANNEL_OPTION_PRI_LOW;
#endif
#if SM_RAIL_CHANNEL
   adsl_contr_1->adsp_rdpacc_rail = &adsl_contr_1->dsrc_rdpacc_svc[dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_no_virt_ch];
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_no_virt_ch++;
   memcpy(adsl_contr_1->adsp_rdpacc_rail->byrc_name, "RAIL", 4);
   adsl_contr_1->adsp_rdpacc_rail->imc_flags = CHANNEL_OPTION_INITIALIZED | CHANNEL_OPTION_ENCRYPT_RDP | CHANNEL_OPTION_COMPRESS_RDP | CHANNEL_OPTION_SHOW_PROTOCOL
			 /*| REMOTE_CONTROL_PERSISTENT*/;
#endif
#if CV_DYN_CHANNEL
   // Add the "DRDYNVC" SVC Channel to the RDP Start Client Command
   adsl_contr_1->adsp_rdpacc_drdynvc = &adsl_contr_1->dsrc_rdpacc_svc[dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_no_virt_ch];
   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_no_virt_ch++;
   // Copy the channel name
   memcpy( adsl_contr_1->adsp_rdpacc_drdynvc->byrc_name, 
          adsl_contr_1->dsc_svc_drdynvc.chrc_channel_name, 
          strlen(adsl_contr_1->dsc_svc_drdynvc.chrc_channel_name));
   // Set the channel flags
   adsl_contr_1->adsp_rdpacc_drdynvc->imc_flags = (int) adsl_contr_1->dsc_svc_drdynvc.umc_options;
#endif /* CV_DYN_CHANNEL */

   dsl_cc_co1_all.dsc_cc_start_rdp_client.umc_loinf_options  /* Logon Info Options */
     = INFO_MOUSE
       | INFO_DISABLECTRLALTDEL
#ifdef RDP_USERID_PWD
#endif
       | INFO_AUTOLOGON
       | INFO_UNICODE
       | INFO_MAXIMIZESHELL
       | INFO_LOGONNOTIFY
       | INFO_ENABLEWINDOWSKEY
       | INFO_FORCE_ENCRYPTED_CS_PDU
       | INFO_LOGONERRORS
       | INFO_MOUSE_HAS_WHEEL
       | INFO_NOAUDIOPLAYBACK;
#if SM_RAIL_CHANNEL
	if(adsl_contr_1->iec_start_mode == ied_d_start_mode_rail)
		dsl_cc_co1_all.dsc_cc_start_rdp_client.umc_loinf_options |= INFO_RAIL;
#endif
	dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_ineta_len  /* INETA Length */
     = adsl_contr_1->imc_len_client_ineta;  /* length INETA            */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_ineta_a  /* INETA */
     = (HL_WCHAR *) adsl_contr_1->chrc_client_ineta;
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_extra_len  /* Extra Parameters Length */
     = sizeof(ucrs_loinf_extra);            /* Extra Parameters Length */
   if ( ((struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf)->boc_custom_infoextra)
   {
       dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_extra_a  /* Extra Parameters */
           = (void*) ((struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf)->ucrc_loinf_extra ;
   }
   else
   {
        dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_extra_a  /* Extra Parameters */
            = (void *) ucrs_loinf_extra;           /* Extra Parameters        */
   }
// dsl_cc_co1_all.dsc_cc_start_rdp_client.achc_machine_name = "TEST01";  /* Name of clients machine, zero-terminated */
   dsl_cc_co1_all.dsc_cc_start_rdp_client.achc_machine_name = "HOB-WebTerm";  /* Name of clients machine, zero-terminated */
#ifdef B140128
#ifdef RDP_COMPRESSION
   dsl_cc_co1_all.dsc_cc_start_rdp_client.boc_compression = TRUE;  /* with compression */
#endif
#endif
#define ADSL_CC1 ((struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf)  /* structure configuration */
   if (ADSL_CC1 == NULL) {                  /* no configuration        */
     goto p_cl_sta_60;                      /* parameters have been set */
   }
   if (ADSL_CC1->imc_rdp_compr > 0) {       /* <RDP-compression-level> */
     dsl_cc_co1_all.dsc_cc_start_rdp_client.boc_compression = TRUE;  /* with compression */
   }
#if 0
	if (ADSL_CC1->iec_d_sso                  /* SSO - single-sign-on configuration */
         == ied_d_sso_none) {               /* no SSO                  */
     goto p_cl_sta_60;                      /* parameters have been set */
   }
#endif
#if SM_USE_NLA
#ifdef HL_USE_UNICODE_STRINGS
	dsl_cc_co1_all.dsc_cc_start_rdp_client.dsc_ucs_username = adsl_contr_1->dsc_client_userid;
	dsl_cc_co1_all.dsc_cc_start_rdp_client.dsc_ucs_password = adsl_contr_1->dsc_client_password;
	dsl_cc_co1_all.dsc_cc_start_rdp_client.dsc_ucs_domain = adsl_contr_1->dsc_client_domain;
#else
	dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_userna_a = (HL_WCHAR*)adsl_contr_1->dsc_client_userid.ac_str;
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_userna_len = adsl_contr_1->dsc_client_userid.imc_len_str * sizeof(HL_WCHAR);
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_domna_a = (HL_WCHAR*)adsl_contr_1->dsc_client_domain.ac_str;
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_domna_len = adsl_contr_1->dsc_client_domain.imc_len_str * sizeof(HL_WCHAR);
   dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_pwd_a = (HL_WCHAR*)adsl_contr_1->dsc_client_password.ac_str;
   dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_pwd_len = adsl_contr_1->dsc_client_password.imc_len_str * sizeof(HL_WCHAR);
#endif
   goto p_cl_sta_60;                      /* parameters have been set */
#else
   memset( &dsl_g_idset1, 0, sizeof(struct dsd_sdh_ident_set_1) );  /* settings for given ident */
   bol_rc = (*dsl_output_area_1.amc_aux)( dsl_output_area_1.vpc_userfld,
                                       DEF_AUX_GET_IDENT_SETTINGS,  /* return settings of this user */
                                       &dsl_g_idset1,
                                       sizeof(struct dsd_sdh_ident_set_1) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T aux-call() DEF_AUX_GET_IDENT_SETTINGS returned %d iec_ret_g_idset1 %d.",
                 __LINE__, bol_rc, dsl_g_idset1.iec_ret_g_idset1 );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (dsl_g_idset1.iec_ret_g_idset1 != ied_ret_g_idset1_ok) {  /* ident known, parameters returned, o.k. */
     goto p_cl_sta_60;                      /* parameters have been set */
   }
   iml1 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &dsl_g_idset1.dsc_user_group )  /* unicode string user-group */
            * sizeof(HL_WCHAR);
   iml2 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &dsl_g_idset1.dsc_userid )  /* unicode string userid */
            * sizeof(HL_WCHAR);
   iml3 = 0;                                /* length password         */
   if (ADSL_CC1->iec_d_sso                  /* SSO - single-sign-on configuration */
         != ied_d_sso_cred_cache) {         /* credential-cache        */
     goto p_cl_sta_48;                      /* end of password         */
   }
   memcpy( chrl_work1, chrs_cma_pwd_prefix, sizeof(chrs_cma_pwd_prefix) );
   iml3 = m_cpy_vx_ucs( chrl_work1 + sizeof(chrs_cma_pwd_prefix),
                        sizeof(chrl_work1) - sizeof(chrs_cma_pwd_prefix),
                        ied_chs_utf_8,      /* Unicode UTF-8           */
                        &dsl_g_idset1.dsc_user_group );  /* unicode string user-group */
   if (iml3 < 0) {
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_cpy_vx_ucs() user-group returned error",
                   __LINE__ );
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_48;                      /* end of password         */
   }
   achl_w1 = chrl_work1 + sizeof(chrs_cma_pwd_prefix) + iml3 + 1;
   iml3 = m_cpy_vx_ucs( achl_w1,
                        (chrl_work1 + sizeof(chrl_work1)) - achl_w1,
                        ied_chs_utf_8,      /* Unicode UTF-8           */
                        &dsl_g_idset1.dsc_userid );  /* unicode string userid */
   if (iml3 < 0) {
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_cpy_vx_ucs() userid returned error",
                   __LINE__ );
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_48;                      /* end of password         */
   }
   achl_w1 += iml3;
   memset( &dsl_accma1, 0, sizeof(struct dsd_hl_aux_c_cma_1) );  /* command common memory area */
   dsl_accma1.ac_cma_name = chrl_work1;     /* cma name                */
   dsl_accma1.iec_chs_name = ied_chs_utf_8;  /* character set          */
   dsl_accma1.inc_len_cma_name = achl_w1 - chrl_work1;  /* length cma name in elements */
   dsl_accma1.iec_ccma_def = ied_ccma_lock_global;  /* set global lock */
   bol_rc = (*dsl_output_area_1.amc_aux)( dsl_output_area_1.vpc_userfld,
                                       DEF_AUX_COM_CMA,  /* command common memory area */
                                       &dsl_accma1,
                                       sizeof(struct dsd_hl_aux_c_cma_1) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T aux-call() DEF_AUX_COM_CMA returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured - not found */
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_48;                      /* end of password         */
   }
   if (dsl_accma1.inc_len_cma_area == 0) {  /* length of cma area      */
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_44;                      /* do unlock               */
   }
   memset( &dsl_asxor1, 0, sizeof(struct dsd_aux_secure_xor_1) );  /* apply secure XOR */
   dsl_asxor1.imc_len_post_key = achl_w1 - (chrl_work1 + sizeof(chrs_cma_pwd_prefix));  /* length of post key string */
   dsl_asxor1.imc_len_xor = dsl_accma1.inc_len_cma_area;  /* length of string */
   dsl_asxor1.achc_post_key = chrl_work1 + sizeof(chrs_cma_pwd_prefix);  /* address of post key string */
   dsl_asxor1.achc_source = dsl_accma1.achc_cma_area;  /* address of source */
   dsl_asxor1.achc_destination = chrl_work2;  /* address of destination */
   bol_rc = (*dsl_output_area_1.amc_aux)( dsl_output_area_1.vpc_userfld,
                                          DEF_AUX_SECURE_XOR,  /* apply secure XOR */
                                          &dsl_asxor1,
                                          sizeof(struct dsd_aux_secure_xor_1) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T aux-call() DEF_AUX_SECURE_XOR returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   iml3 = m_cpy_vx_vx( chrl_work3, sizeof(chrl_work3), ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                       chrl_work2, dsl_accma1.inc_len_cma_area, ied_chs_utf_8 )  /* Unicode UTF-8 */
            * sizeof(HL_WCHAR);

   p_cl_sta_44:                             /* unlock CMA              */
   dsl_accma1.iec_ccma_def = ied_ccma_lock_release;  /* release lock   */
   bol_rc = (*dsl_output_area_1.amc_aux)( dsl_output_area_1.vpc_userfld,
                                          DEF_AUX_COM_CMA,  /* command common memory area */
                                          &dsl_accma1,
                                          sizeof(struct dsd_hl_aux_c_cma_1) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T aux-call() DEF_AUX_COM_CMA returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }

   p_cl_sta_48:                             /* end of password         */
//#define ADSL_CC1 ((struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf)  /* structure configuration */
   if (ADSL_CC1->boc_so_without_domain) {   /* <sign-on-without-domain> */
     iml1 = 0;                              /* do not use domain       */
   }
//#undef ADSL_CC1
// to-do 16.04.15 KB
//   "sign-on-use-domain",
//   dsl_g_idset1.dsc_user_group - replace by local
   bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                       DEF_AUX_MEMGET,
                                       &adsl_contr_1->achc_rdp_cred,  /* RDP credentials */
                                       iml1 + iml2 + iml3 );  /* length area */
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   achl_w1 = adsl_contr_1->achc_rdp_cred;   /* RDP credentials         */
   if (iml1 > 0) {                          /* with domain             */
     m_cpy_vx_ucs( achl_w1, iml1, ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                   &dsl_g_idset1.dsc_user_group );  /* unicode string user-group */
     dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_domna_len  /* Domain Name Length */
       = iml1;
     dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_domna_a  /* Domain Name */
       = (HL_WCHAR *) achl_w1;
     achl_w1 += iml1;
   }
   if (iml2 > 0) {                          /* with userid             */
     m_cpy_vx_ucs( achl_w1, iml2, ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                   &dsl_g_idset1.dsc_userid );  /* unicode string userid */
     dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_userna_len  /* User Name Length */
       = iml2;
     dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_userna_a  /* User Name */
       = (HL_WCHAR *) achl_w1;
     achl_w1 += iml2;
   }
   if (iml3 > 0) {                          /* with password           */
     memcpy( achl_w1, chrl_work3, iml3 );
     dsl_cc_co1_all.dsc_cc_start_rdp_client.usc_loinf_pwd_len  /* Password Length */
       = iml3;
     dsl_cc_co1_all.dsc_cc_start_rdp_client.awcc_loinf_pwd_a  /* Password */
       = (HL_WCHAR *) achl_w1;
   }
#endif /*SM_USE_NLA*/

#undef ADSL_CC1

   p_cl_sta_60:                             /* parameters have been set */
#if SM_USE_NLA
   //dsl_cc_co1_all.dsc_cc_start_rdp_client.dsc_rdp_neg_req.umc_requested_protocols = PROTOCOL_HYBRID;
   //dsl_cc_co1_all.dsc_cc_start_rdp_client.dsc_rdp_neg_req.usc_flags = 0x00;
#endif
#ifdef XYZ1
   bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                   DEF_AUX_MEMGET,
                                   &adsl_contr_1->dsc_c_awcs_se_1.ac_screen_buffer,
                                   dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_dim_x
                                     * dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_dim_y
                                     * ((dsl_cc_co1_all.dsc_cc_start_rdp_client.imc_coldep + 7) / 8) );
   if (bol1 == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_contr_1->dsc_c_rdp_cl_1.ac_screen_buffer = adsl_contr_1->dsc_c_awcs_se_1.ac_screen_buffer;
#endif
   adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch  /* chain of client commands, input */
     = &dsl_cc_co1_all.dsc_cc_co1;          /* start RDP client        */
   HL_RDPACC_AUXH(adsl_contr_1->dsc_c_wtrc1).vpc_userfld = dsl_output_area_1.vpc_userfld;  /* User Field Subroutine */
   HL_RDPACC_AUXH(adsl_contr_1->dsc_c_wtrc1).amc_aux = dsl_output_area_1.amc_aux;  /* auxiliary subroutine */
#if SM_USE_NLA
   adsl_contr_1->dsc_c_wtrc1.vpc_config_id = adsl_contr_1->vpc_ssl_config;
#endif
   goto p_rdp_client_20;                    /* call RDP client         */
// --- new 06.02.14 KB - end

   p_rdp_client_00:                         /* process RDP client      */
#ifndef B150211
   if (adsl_contr_1->dsc_c_wtrc1.inc_return != DEF_IRET_NORMAL) {  /* not o.k. returned */
     return;
   }
#endif
   if (adsl_contr_1->imc_wts_port) {        /* port of the WSP         */
     goto p_rdp_client_08;                  /* we know the RDP TCP port */
   }
   memset( &dsl_agsi, 0, sizeof(struct dsd_aux_get_session_info) );  /* get information about the session */
   bol_rc = (*dsl_output_area_1.amc_aux)( dsl_output_area_1.vpc_userfld,
                                          DEF_AUX_GET_SESSION_INFO,  /* get information about the session */
                                          &dsl_agsi,
                                          sizeof(struct dsd_aux_get_session_info) );
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   switch (dsl_agsi.dsc_soa_server_other.ss_family) {
     case AF_INET:
       adsl_contr_1->imc_len_wts_ineta = 4;  /* length of INETA WTS    */
       memcpy( adsl_contr_1->chrc_wts_ineta,  &((struct sockaddr_in *) &dsl_agsi.dsc_soa_server_other)->sin_addr, 4 );
       adsl_contr_1->imc_wts_port = ntohs( ((struct sockaddr_in *) &dsl_agsi.dsc_soa_server_other)->sin_port );  /* TCP port to connect to */
       break;
     case AF_INET6:
       adsl_contr_1->imc_len_wts_ineta = 16;  /* length of INETA WTS   */
       memcpy( adsl_contr_1->chrc_wts_ineta, &((struct sockaddr_in6 *) &dsl_agsi.dsc_soa_server_other)->sin6_addr, 16 );
       adsl_contr_1->imc_wts_port = ntohs( ((struct sockaddr_in6 *) &dsl_agsi.dsc_soa_server_other)->sin6_port );  /* TCP port to connect to */
       break;
     default:
       m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E struct sockaddr invalid family %d.",
                     __LINE__, dsl_agsi.dsc_soa_server_other.ss_family );
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
   }
#ifndef B150216
   HL_RDPACC_L1(adsl_contr_1->dsc_c_wtrc1).imc_sno = adsp_hl_clib_1->imc_sno;  /* session number */
   HL_RDPACC_L1(adsl_contr_1->dsc_c_wtrc1).imc_trace_level = adsp_hl_clib_1->imc_trace_level;  /* WSP trace level */
#endif

   p_rdp_client_08:                         /* we know the RDP TCP port */
// adsl_contr_1->dsc_c_wtrc1.vpc_userfld = &dsl_subaux_userfld;  /* User Field Subroutine */
   HL_RDPACC_AUXH(adsl_contr_1->dsc_c_wtrc1).vpc_userfld = dsl_output_area_1.vpc_userfld;  /* User Field Subroutine */
   HL_RDPACC_AUXH(adsl_contr_1->dsc_c_wtrc1).amc_aux = dsl_output_area_1.amc_aux;  /* auxiliary subroutine */
   adsl_contr_1->dsc_c_wtrc1.adsc_gather_i_1_in = adsp_hl_clib_1->adsc_gather_i_1_in;
   adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch = NULL;  /* chain of client commands, input */
#ifdef DEBUG_150221_01                      /* problem gather          */
   if (dsl_output_area_1.imc_trace_level) {  /* WSP trace level        */
     iml1 = iml2 = 0;
     adsl_gai1_w1 = adsp_hl_clib_1->adsc_gather_i_1_in;
     while (adsl_gai1_w1) {
       memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
       memcpy( dsl_wtrh.chrc_wtrt_id, "SWTGAB01", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
       dsl_wtrh.imc_wtrh_sno = dsl_output_area_1.imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work3)
       dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
       memset( ADSL_WTR_G1, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
       ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
       ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                          "xl-webterm-rdp-01 l%05d gather=%p achc_ginp_cur=%p achc_ginp_end=%p.",
                                          __LINE__, adsl_gai1_w1, adsl_gai1_w1->achc_ginp_cur, adsl_gai1_w1->achc_ginp_end );
#undef ADSL_WTR_G1
       bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                           DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                           &dsl_wtrh,
                                           0 );
       iml1++;
       iml2 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     }
     memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
     memcpy( dsl_wtrh.chrc_wtrt_id, "SWTGAB02", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
     dsl_wtrh.imc_wtrh_sno = dsl_output_area_1.imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work3)
     dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
     memset( ADSL_WTR_G1, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
     ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                        "xl-webterm-rdp-01 l%05d adsp_hl_clib_1->adsc_gather_i_1_in=%p no-gather=%d data=%d/0X%X.",
                                        __LINE__, adsp_hl_clib_1->adsc_gather_i_1_in, iml1, iml2, iml2 );
#undef ADSL_WTR_G1
     bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                         DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                         &dsl_wtrh,
                                         0 );
   }
#endif

   p_rdp_client_20:                         /* call RDP client         */
#ifdef WA_150216_02
   if (adsl_contr_1->dsc_c_wtrc1.inc_return != DEF_IRET_NORMAL) {  /* not o.k. returned */
     return;
   }
#endif
   adsl_contr_1->dsc_c_wtrc1.adsc_gai1_out_to_server = NULL;  /* output data to server */
   adsl_contr_1->dsc_c_wtrc1.adsc_se_co1_ch = NULL;
   adsl_contr_1->dsc_c_wtrc1.adsc_wtr1_out = NULL;  /* chain of WebTerm records to be sent to client */
   memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
   bol_rc = (*dsl_output_area_1.amc_aux)( dsl_output_area_1.vpc_userfld,
                                          DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                          &dsl_aux_get_workarea,
                                          sizeof(struct dsd_aux_get_workarea) );
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_contr_1->dsc_c_wtrc1.achc_work_area = dsl_aux_get_workarea.achc_work_area;  /* addr work-area returned */
   adsl_contr_1->dsc_c_wtrc1.inc_len_work_area = dsl_aux_get_workarea.imc_len_work_area;  /* length work-area returned */
   
   if (adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch && adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch == adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch->adsc_next)
     adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch->adsc_next = NULL;

#if SM_USE_NLA
   m_wt_rdp_client_2( &adsl_contr_1->dsc_c_wtrc1 );
#else
   m_wt_rdp_client_1( &adsl_contr_1->dsc_c_wtrc1 );
#endif
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T m_wt_rdp_client_1() returned inc_return=%d adsc_gai1_out_to_server=%p adsc_wtr1_out=%p adsc_se_co1_ch=%p.",
                 __LINE__,
                 adsl_contr_1->dsc_c_wtrc1.inc_return,
                 adsl_contr_1->dsc_c_wtrc1.adsc_gai1_out_to_server,
                 adsl_contr_1->dsc_c_wtrc1.adsc_wtr1_out,  /* chain of WebTerm records to be sent to client */
                 adsl_contr_1->dsc_c_wtrc1.adsc_se_co1_ch );
#endif
#ifdef DEBUG_150221_01                      /* problem gather          */
   if (dsl_output_area_1.imc_trace_level) {    /* WSP trace level         */
     iml1 = iml2 = 0;
     adsl_gai1_w1 = adsp_hl_clib_1->adsc_gather_i_1_in;
     while (adsl_gai1_w1) {
       memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
       memcpy( dsl_wtrh.chrc_wtrt_id, "SWTGAA01", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
       dsl_wtrh.imc_wtrh_sno = dsl_output_area_1.imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work3)
       dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
       memset( ADSL_WTR_G1, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
       ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
       ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                          "xl-webterm-rdp-01 l%05d gather=%p achc_ginp_cur=%p achc_ginp_end=%p.",
                                          __LINE__, adsl_gai1_w1, adsl_gai1_w1->achc_ginp_cur, adsl_gai1_w1->achc_ginp_end );
#undef ADSL_WTR_G1
       bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                           DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                           &dsl_wtrh,
                                           0 );
       iml1++;
       iml2 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     }
     memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
     memcpy( dsl_wtrh.chrc_wtrt_id, "SWTGAA02", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
     dsl_wtrh.imc_wtrh_sno = dsl_output_area_1.imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work3)
     dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
     memset( ADSL_WTR_G1, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
     ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                        "xl-webterm-rdp-01 l%05d adsp_hl_clib_1->adsc_gather_i_1_in=%p no-gather=%d data=%d/0X%X.",
                                        __LINE__, adsp_hl_clib_1->adsc_gather_i_1_in, iml1, iml2, iml2 );
#undef ADSL_WTR_G1
     bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                         DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                         &dsl_wtrh,
                                         0 );
   }
#endif
   if (adsl_contr_1->dsc_c_wtrc1.inc_return != DEF_IRET_NORMAL) {  /* not o.k. returned */
#if SM_USE_NLA
	   if(adsl_contr_1->dsc_c_wtrc1.inc_return == DEF_IRET_ERR_EXTENDED) {
		   int inl_flags;
#define ADSL_WTR1_G ((struct dsd_wt_record_1 *) chrl_work1)
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) (ADSL_WTR1_G + 1))
#define ACHL_MSG1_G (char*)(ADSL_GAI1_G+1)

		   switch(adsl_contr_1->dsc_c_wtrc1.iec_extended_result) {
		   case iec_rdpclient_extended_rdpacc_failed:
			   adsl_contr_1->dsc_c_wtrc1.inc_return = adsl_contr_1->dsc_c_wtrc1.dsc_rdpacc.inc_return;       //TODO if  adsl_contr_1->dsc_c_wtrc1.dsc_rdpacc.adsc_cc_co1_ch->iec_cc_command == iec_sec_end_session 
			   if (adsl_contr_1->dsc_c_wtrc1.inc_return == DEF_IRET_END) {  /* connection should be ended */
	             goto p_webso_server_close_00;        /* server has closed connection */
               }
			   inl_flags = 0;
			   iml1 = sprintf(ACHL_MSG1_G, "An unexpected RDP error has occured (error code %d).", adsl_contr_1->dsc_c_wtrc1.inc_return);
			   goto LBL_SEND_ERROR_MESSAGE;
		   case iec_rdpclient_extended_rdp_negotiation_failed:
			   inl_flags = 0;
			   iml1 = sprintf(ACHL_MSG1_G, "RDP negotiation failed (error code %d).", adsl_contr_1->dsc_c_wtrc1.dsc_rdp_neg_resp.umc_failure_code);
			   goto LBL_SEND_ERROR_MESSAGE;
		   case iec_rdpclient_extended_ssl_failed:
			   inl_flags = 0;
			   iml1 = sprintf(ACHL_MSG1_G, "SSL negotiation failed (error code %d).", adsl_contr_1->dsc_c_wtrc1.dsc_ssl_client.inc_return);
#if 1
			   if(adsl_contr_1->dsc_c_wtrc1.dsc_ssl_client.inc_return == -125 && !adsl_contr_1->dsc_c_wtrc1.dsc_credssp.dsc_base.boc_initialized
				   && adsl_contr_1->dsc_c_wtrc1.dsc_credssp.inc_server_version <= 2)
			   {
					inl_flags = 0x01;
					iml1 = sprintf(ACHL_MSG1_G, "The credentials you entered did not work.\nPlease enter new credentials.");
					goto LBL_SEND_RDP_AUTHENICATE;
			   }
#endif
			   goto LBL_SEND_ERROR_MESSAGE;
		   case iec_rdpclient_extended_credssp_no_credentials:
			   inl_flags = 0;
			   //iml1 = sprintf(ACHL_MSG1_G, "Please enter credentials to connect to %.*s",
	//			   adsl_contr_1->imc_len_wts_ineta, adsl_contr_1->chrc_wts_ineta);
			   iml1 = sprintf(ACHL_MSG1_G, "Please enter credentials to connect to RD server.");
			   goto LBL_SEND_RDP_AUTHENICATE;
		   case iec_rdpclient_extended_credssp_failed:
			   inl_flags = 0x01;
			   iml1 = sprintf(ACHL_MSG1_G, "The credentials you entered did not work (error code 0x%08X).\nPlease enter new credentials.",
				   adsl_contr_1->dsc_c_wtrc1.dsc_credssp.unc_error_code);
			   goto LBL_SEND_RDP_AUTHENICATE;
		   default:
			   goto LBL_RDP_CLIENT_FAILED;
		   }
LBL_SEND_ERROR_MESSAGE:
			m_sdh_printf( &dsl_output_area_1,
				"xl-webterm-rdp-01-l%05d-W m_wt_rdp_client_1() sending error message: %.*s",
                __LINE__, iml1, ACHL_MSG1_G);
			if(!m_send_websocket_error(&dsl_output_area_1, inl_flags, ACHL_MSG1_G, iml1)) {
				return;
			}
			goto LBL_RDP_CLIENT_FAILED;

LBL_SEND_RDP_AUTHENICATE:
			memset( ADSL_WTR1_G, 0, sizeof(struct dsd_wt_record_1) + sizeof(struct dsd_gather_i_1) );
			iml2 = 1 + 5 + iml1;

			ADSL_WTR1_G->ucc_record_type = ie_wtsc_rdp_authenticate;     /* record type             */
			if ((dsl_output_area_1.achc_upper - dsl_output_area_1.achc_lower) < iml2) {  /* need buffer */
				bol_rc = m_get_new_workarea( &dsl_output_area_1 );
				if (bol_rc == FALSE) {
					adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
					return;
				}
			}
			ADSL_GAI1_G->achc_ginp_cur = dsl_output_area_1.achc_lower;
			dsl_output_area_1.achc_lower
				+= m_out_nhasn1( dsl_output_area_1.achc_lower, inl_flags );
			dsl_output_area_1.achc_lower
				+= m_out_nhasn1( dsl_output_area_1.achc_lower, iml1 );
			memcpy(dsl_output_area_1.achc_lower, ACHL_MSG1_G, iml1);
			dsl_output_area_1.achc_lower += iml1;
			ADSL_GAI1_G->achc_ginp_end = dsl_output_area_1.achc_lower;
			ADSL_WTR1_G->adsc_gai1_data = ADSL_GAI1_G;  /* output data be be sent to client */
                   {
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_rdpclient_1() send websocket data record type: %d (first 16 bytes)",
                       __LINE__ ,ADSL_WTR1_G->ucc_record_type);
        int iml_tmp = ADSL_WTR1_G->adsc_gai1_data->achc_ginp_end - ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur;
        m_sdh_console_out( &dsl_output_area_1, ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur, (iml_tmp > 16) ? 16 : iml_tmp );
        }
        m_sdh_console_out( &dsl_output_area_1, ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur, 16 );
			bol_rc = m_send_websocket_data( &dsl_output_area_1, adsl_contr_1, ADSL_WTR1_G );
			if (bol_rc == FALSE) {                   /* error occured           */
				adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
				return;
			}
			goto p_webso_server_close_00;        /* server has closed connection */
#undef ADSL_WTR1_G
#undef ADSL_GAI1_G
#undef ACHL_MSG1_G
	   }
#endif /*SM_USE_NLA*/
	 if (adsl_contr_1->dsc_c_wtrc1.inc_return == DEF_IRET_END) {  /* connection should be ended */
       goto p_webso_server_close_00;        /* server has closed connection */
     }
LBL_RDP_CLIENT_FAILED:
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_wt_rdp_client_1() returned inc_return=%d - invalid",
                   __LINE__, adsl_contr_1->dsc_c_wtrc1.inc_return );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (adsl_contr_1->dsc_c_wtrc1.adsc_gai1_out_to_server) {  /* output data to server */
     if (adsp_hl_clib_1->adsc_gai1_out_to_server == NULL) {  /* first output */
       adsp_hl_clib_1->adsc_gai1_out_to_server
         = adsl_contr_1->dsc_c_wtrc1.adsc_gai1_out_to_server;  /* output data to server */
     } else {                               /* append to chain         */
       adsl_gai1_w1 = adsp_hl_clib_1->adsc_gai1_out_to_server;  /* get chain */
       while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       adsl_gai1_w1->adsc_next
         = adsl_contr_1->dsc_c_wtrc1.adsc_gai1_out_to_server;  /* output data to server */
     }
   }
	if(adsl_contr_1->dsc_c_wtrc1.adsc_se_co1_ch != NULL) {
		struct dsd_se_co1 *adsc_se_co1_last = adsl_contr_1->dsc_c_wtrc1.adsc_se_co1_ch;
		while(adsc_se_co1_last->adsc_next != NULL)
			adsc_se_co1_last = adsc_se_co1_last->adsc_next;
		if(dsl_output_area_1.adsc_se_co1_ch_first == NULL)
			dsl_output_area_1.adsc_se_co1_ch_end = &dsl_output_area_1.adsc_se_co1_ch_first;
		*dsl_output_area_1.adsc_se_co1_ch_end = adsl_contr_1->dsc_c_wtrc1.adsc_se_co1_ch;
		dsl_output_area_1.adsc_se_co1_ch_end = &adsc_se_co1_last->adsc_next;
		adsl_contr_1->dsc_c_wtrc1.adsc_se_co1_ch = NULL;
	}
   if (dsl_output_area_1.adsc_se_co1_ch_first == NULL) {  /* chain of commands from server, output */
     goto p_rdp_client_60;                  /* check something to be send to WebSocket client */
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T m_wt_rdp_client_1() returned adsc_se_co1_ch=%p.",
                 __LINE__,
                 dsl_output_area_1.adsc_se_co1_ch_first );
#endif
#ifdef XYZ1
   bol1 = FALSE;
   adsl_sc_co1_w1 = (struct dsd_sc_co1 *) chrl_work1;  /* server component command */
   aadsl_sc_co1_ch = &adsl_contr_1->dsc_c_awcs_se_1.adsc_sc_co1_ch;  /* chain of server component command */
   *aadsl_sc_co1_ch = NULL;                 /* set end of chain        */
#endif
#ifdef TRACEHL1
   iml1 = 0;                                /* count commands          */
#endif

   /* prepare required variables for the drdynvc channel */
   adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch = NULL;  /* chain of client commands, input */
   dsl_output_area_1.aadsc_cc_co1_ch = &adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch; 
#if CV_DYN_CHANNEL
   achl_drdynvc_wa = chrl_work_dyn;  // position work area, touch event
#endif /* CV_DYN_CHANNEL */

   p_rdp_client_40:                         /* check command from server */
   adsl_se_co1_w1 = dsl_output_area_1.adsc_se_co1_ch_first;
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T m_wt_rdp_client_1() returned iec_se_command=%d.",
                 __LINE__, adsl_se_co1_w1->iec_se_command );
#endif
   switch (adsl_se_co1_w1->iec_se_command) {  /* command type          */


   case ied_sec_vch_in:
   {
     dsd_rdp_vch_io *adsl_rdp_vch_io;
     adsl_rdp_vch_io = (dsd_rdp_vch_io*)(adsl_se_co1_w1 + 1);
#ifdef TRACEHL1
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T m_wt_rdp_client_1() ied_sec_vch_in name=%.*s",
		  __LINE__, sizeof(adsl_rdp_vch_io->adsc_rdp_vc_1->byrc_name), adsl_rdp_vch_io->adsc_rdp_vc_1->byrc_name );
#endif
#if CV_DYN_CHANNEL
	 if(adsl_rdp_vch_io->adsc_rdp_vc_1 == adsl_contr_1->adsp_rdpacc_drdynvc) {
		 // Check is VC number matches that of the "drdynvc" channel, if not -> break.

		struct dsd_dynvc_command2 dsl_output2;
		dsl_output2.adsc_output_area_1 = &dsl_output_area_1;
		int inl_result = m_svc_dynvc_receive_message(&adsl_contr_1->dsc_svc_drdynvc, &dsl_output_area_1.dsc_aux_helper, adsl_rdp_vch_io, &dsl_output2.dsc_base);
		if (inl_result < 0) {
			m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E m_svc_dynvc_receive_message() failed", __LINE__);
			adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return;
		}

		struct dsd_dynvc_command* adsl_output = &dsl_output2.dsc_base;
		if (adsl_output->adsc_data_to_client != NULL) {
			struct dsd_workarea_allocator* adsl_wa_alloc = &dsl_output_area_1.dsc_wa_alloc_extern;

			// Reserver space for one dsd_wt_record_1
			static const uint32_t uml_record_size = sizeof(struct dsd_wt_record_1);
			struct dsd_wt_record_1* adsl_wtr1_g = (struct dsd_wt_record_1*)m_wa_allocator_alloc_lower(adsl_wa_alloc,
				uml_record_size, HL_ALIGNOF(struct dsd_rdp_vch_io));
			if (adsl_wtr1_g == NULL) {
				adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
				return;
			}
			memset(adsl_wtr1_g, 0, uml_record_size);

			// Init dsd_wt_record_1
			adsl_wtr1_g->ucc_record_type = adsl_output->ucc_record_type;
			adsl_wtr1_g->adsc_gai1_data = adsl_output->adsc_data_to_client;

			if (FALSE == m_send_websocket_data(&dsl_output_area_1, adsl_contr_1, adsl_wtr1_g)) {
				adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
				return;
			}
		}

		if (adsl_output->adsc_data_to_server != NULL) {
			struct dsd_workarea_allocator* adsl_wa_alloc = &dsl_output_area_1.dsc_wa_alloc_extern;

			struct dsd_gather_i_1* adsl_gather = adsl_output->adsc_data_to_server;

			//TODO: do segmentation!
			if (adsl_output->umc_to_server_length_total != adsl_output->umc_to_server_length_current
				|| adsl_output->umc_to_server_length_total > CV_DYN_CHANNEL_BUFFER_SIZE) {
				//segmentation is not yet supported
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E m_svc_dynvc_receive_message() segmentation is not yet supported", __LINE__);
				adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
				return;
			}

			struct dsd_cc_co1* adsl_command = (struct dsd_cc_co1*)m_wa_allocator_alloc_lower(adsl_wa_alloc,
				sizeof(struct dsd_cc_co1) + sizeof(struct dsd_rdp_vch_io), HL_ALIGNOF(struct dsd_rdp_vch_io));
			if (adsl_command == NULL) {
				m_sdh_printf(&dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E m_wa_allocator_alloc_lower returned NULL", __LINE__);
				adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
				return;
			}
			struct dsd_rdp_vch_io* adsl_dynvc_io = (struct dsd_rdp_vch_io*)((uintptr_t)adsl_command + sizeof(struct dsd_cc_co1));
			if ((uintptr_t)adsl_dynvc_io - (uintptr_t)adsl_command != sizeof(struct dsd_cc_co1)) {
				m_sdh_printf(&dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E m_svc_dynvc_receive_message MUST NOT HAPPEN! adsl_command=%p adsl_dynvc_io=%p sizeof(dsd_cc_co1)=%d sizeof(dsd_rdp_vch_io)=%d",
					__LINE__, adsl_command, adsl_dynvc_io, sizeof(struct dsd_cc_co1), sizeof(struct dsd_rdp_vch_io));
				adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
				return;
			}
	
			adsl_command->iec_cc_command = ied_ccc_vch_out;
			adsl_command->adsc_next = NULL;
			adsl_dynvc_io->adsc_gai1_data = adsl_gather;
			adsl_dynvc_io->umc_vch_ulen = adsl_output->umc_to_server_length_total;
			memset(adsl_dynvc_io->chrc_vch_flags, 0, sizeof(adsl_dynvc_io->chrc_vch_flags));
			adsl_dynvc_io->chrc_vch_flags[0] = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST;
			adsl_dynvc_io->adsc_rdp_vc_1 = adsl_contr_1->adsp_rdpacc_drdynvc;

			// append to chain
			*dsl_output_area_1.aadsc_cc_co1_ch = adsl_command;
			// position chain of client commands, input
			dsl_output_area_1.aadsc_cc_co1_ch = &adsl_command->adsc_next;
		}
		break;
     }
#endif /* CV_DYN_CHANNEL */
#if SM_RDPDR_CHANNEL
	 if(adsl_rdp_vch_io->adsc_rdp_vc_1 == adsl_contr_1->adsp_rdpacc_rdpdr) {
		 static const HL_WCHAR wcrl_computer_name[11] = {
			 'W', 'e', 'b', 'T', 'e', 'r', 'm', 'R', 'D', 'P', 0
		 };
		 struct dsd_svc_rdpdr_command dsl_commands[2];
#if SM_USE_PRINTING
		 struct dsd_svc_rdpdr_device_annouce_data_printer dsrl_device_announce_printer[HL_RDPDR_MAX_PRINTERS];
#endif
		 struct dsd_device_announce* dsrl_devices[HL_MAX(HL_RDPDR_MAX_DEVICES, 1)];
		 int inl_num_commands = 0;
		 
		 struct dsd_svc_rdpdr_message dsl_msg_out;
		 int inl_res = m_svc_rdpdr_receive_message(&adsl_contr_1->dsc_svc_rdpdr, &dsl_output_area_1.dsc_aux_helper, adsl_rdp_vch_io, &dsl_msg_out);
		 if(inl_res < 0) {
			m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_wt_rdp_client_1() m_svc_rdpdr_receive_message failed",
                       __LINE__ );
			 adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			 return;
		 }
		 if(inl_res == 0) {
			 break;
		 }
		 switch(dsl_msg_out.iec_message) {
		 case iec_svc_rdpdr_message_server_announce_req:
			 dsl_commands[inl_num_commands].iec_command = iec_svc_rdpdr_command_client_announce_resp;
			 dsl_commands[inl_num_commands].dsc_message.dsc_core_client_announce.usc_version_major = 0x0001;
			 dsl_commands[inl_num_commands].dsc_message.dsc_core_client_announce.usc_version_minor = 0x000a;
			 // TODO: Client-ID
			 dsl_commands[inl_num_commands].dsc_message.dsc_core_client_announce.umc_client_id = 0;
			 inl_num_commands++;

			 dsl_commands[inl_num_commands].iec_command = iec_svc_rdpdr_command_client_name_req;
			 dsl_commands[inl_num_commands].dsc_message.dsc_core_client_name.umc_unicode_flag = 0x00000001;
			 dsl_commands[inl_num_commands].dsc_message.dsc_core_client_name.umc_code_page = 0;
			 dsl_commands[inl_num_commands].dsc_message.dsc_core_client_name.umc_computer_name_len = sizeof(wcrl_computer_name);
			 dsl_commands[inl_num_commands].dsc_message.dsc_core_client_name.avoc_computer_name = wcrl_computer_name;
			 inl_num_commands++;
			 break;
		 case iec_svc_rdpdr_message_server_capability_req: 
		 {
			 struct dsd_svc_rdpdr_capabilities* adsl_client_caps = &dsl_commands[inl_num_commands].dsc_message.dsc_core_client_capability.dsc_caps;
			 adsl_client_caps->usc_num_capabilities = 5;
			 adsl_client_caps->boc_general = TRUE;
			 adsl_client_caps->dsc_general.umc_version = 2;
			 adsl_client_caps->dsc_general.umc_os_type = 0;
			 adsl_client_caps->dsc_general.umc_os_version = 0;
			 adsl_client_caps->dsc_general.usc_protocol_major_version = 0x0001;
			 adsl_client_caps->dsc_general.usc_protocol_minor_version = 0x000c;
			 adsl_client_caps->dsc_general.umc_io_code1 = 0x0000ffff;
			 adsl_client_caps->dsc_general.umc_io_code2 = 0x00000000;
			 adsl_client_caps->dsc_general.umc_extended_pdu = RDPDR_DEVICE_REMOVE_PDUS | RDPDR_CLIENT_DISPLAY_NAME_PDU | RDPDR_USER_LOGGEDON_PDU;
			 adsl_client_caps->dsc_general.umc_extra_flag1 = 0;
			 adsl_client_caps->dsc_general.umc_extra_flag2 = 0;
			 adsl_client_caps->dsc_general.umc_special_type_device_cap = 0;

			 adsl_client_caps->boc_printer = TRUE;
			 adsl_client_caps->dsc_printer.umc_version = 1;
			 adsl_client_caps->boc_port = TRUE;
			 adsl_client_caps->dsc_port.umc_version = 1;
			 adsl_client_caps->boc_drive = TRUE;
			 adsl_client_caps->dsc_drive.umc_version = 1;
			 adsl_client_caps->boc_smartcard = TRUE;
			 adsl_client_caps->dsc_smartcard.umc_version = 1;

			 dsl_commands[inl_num_commands].iec_command = iec_svc_rdpdr_command_client_capability_resp;
			 inl_num_commands++;
			 break;
		 }
		 case iec_svc_rdpdr_message_server_clientid_confirm:
			 break;
		 case iec_svc_rdpdr_message_server_user_loggedon: {
			 adsl_contr_1->imc_num_devices = 0;

			 char* achl_temp = chrl_work3;
			 char* achl_temp2 = chrl_work3 + sizeof(chrl_work3);
			 struct dsd_clib1_conf_1* adsl_clib1_conf = (struct dsd_clib1_conf_1*)adsp_hl_clib_1->ac_conf;
#if SM_USE_PRINTING
			 struct dsd_svc_rdpdr_device_annouce_data_printer* adsl_da_printer = dsrl_device_announce_printer;
			 for(int inl_p=0; inl_p<adsl_clib1_conf->inc_num_printers; inl_p++) {
				 const struct dsd_clib_conf_printer* adsl_conf_printer = &adsl_clib1_conf->adsc_printers[inl_p];

				 adsl_da_printer->dsc_device_announce.umc_device_type = RDPDR_DTYP_PRINT;
				 adsl_da_printer->dsc_device_announce.umc_device_id = adsl_contr_1->imc_num_devices;
				 int inl_length = m_hlsnprintf(adsl_da_printer->dsc_device_announce.ucrc_preferred_dos_name,
					 sizeof(adsl_da_printer->dsc_device_announce.ucrc_preferred_dos_name), ied_chs_ascii_850,
					 "PRN%d:", inl_p+1);
				 memset(adsl_da_printer->dsc_device_announce.ucrc_preferred_dos_name+inl_length, 0, sizeof(adsl_da_printer->dsc_device_announce.ucrc_preferred_dos_name)-inl_length);
				 adsl_da_printer->umc_flags = RDPDR_PRINTER_ANNOUNCE_FLAG_NETWORKPRINTER;
				 if(adsl_conf_printer->boc_default)
					adsl_da_printer->umc_flags |= RDPDR_PRINTER_ANNOUNCE_FLAG_DEFAULTPRINTER;
				 adsl_da_printer->umc_code_page = 0;
				 adsl_da_printer->umc_pnp_name_len = 0;
				 adsl_da_printer->umc_driver_name_len = 0;
				 inl_res = m_cpy_uc_vx_ucs(achl_temp, ((HL_WCHAR*)achl_temp2)-(HL_WCHAR*)achl_temp,
					 ied_chs_le_utf_16, &adsl_conf_printer->dsc_driver_name);
				 if(inl_res < 0) {
					 m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_wt_rdp_client_1() m_cpy_uc_vx_ucs failed",
								  __LINE__ );
					 adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
					 return;
				 }
				 adsl_da_printer->avoc_driver_name = achl_temp;
				 adsl_da_printer->umc_driver_name_len = (inl_res+1)<<1;
				 achl_temp += adsl_da_printer->umc_driver_name_len;
			 
				 inl_res = m_cpy_uc_vx_ucs(achl_temp, ((HL_WCHAR*)achl_temp2)-(HL_WCHAR*)achl_temp,
					 ied_chs_le_utf_16, &adsl_conf_printer->dsc_name);
				 if(inl_res < 0) {
					 m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_wt_rdp_client_1() m_cpy_uc_vx_ucs failed",
								  __LINE__ );
					 adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
					 return;
				 }
				 adsl_da_printer->avoc_print_name = achl_temp;
				 adsl_da_printer->umc_print_name_len = (inl_res+1)<<1;
				 achl_temp += adsl_da_printer->umc_print_name_len;
				 adsl_da_printer->umc_cached_fields_len = 0;
				 
				 struct dsd_rdpdr_device_context_printer* adsl_printer = &adsl_contr_1->dsrc_rdpdr_printing_devices[inl_p];
				 dsrl_devices[adsl_contr_1->imc_num_devices] = &adsl_da_printer->dsc_device_announce;
				 memset(adsl_printer, 0, sizeof(*adsl_printer));
				 adsl_printer->dsc_device_context.iec_device_type = ied_rdpdr_device_type_printer;
				 adsl_printer->adsc_conf_printer = adsl_conf_printer;
				 adsl_contr_1->adsrc_rdpdr_devices[adsl_contr_1->imc_num_devices] = &adsl_printer->dsc_device_context;
				 adsl_contr_1->imc_num_devices++;
				 adsl_da_printer++;
			 }
#endif /*SM_USE_PRINTING*/			 
			 dsl_commands[inl_num_commands].iec_command = iec_svc_rdpdr_command_client_device_list_announce_req;
			 dsl_commands[inl_num_commands].dsc_message.dsc_core_client_device_list_announce.umc_device_count = adsl_contr_1->imc_num_devices;
			 dsl_commands[inl_num_commands].dsc_message.dsc_core_client_device_list_announce.adsrc_devices = dsrl_devices;
			 inl_num_commands++;
			 break;
		 }
		 case iec_svc_rdpdr_message_server_device_announce_resp: {
			 break;
		 }
		 case iec_svc_rdpdr_message_server_device_io_req: {
			 if(dsl_msg_out.dsc_message.dsc_core_server_device_io_req.umc_device_id >= adsl_contr_1->imc_num_devices) {
					m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W invalid device id %d",
								__LINE__, dsl_msg_out.dsc_message.dsc_core_server_device_io_req.umc_device_id );
					adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
					return;
			 }
			 struct dsd_rdpdr_device_context* adsl_rdpdr_device =
				 adsl_contr_1->adsrc_rdpdr_devices[dsl_msg_out.dsc_message.dsc_core_server_device_io_req.umc_device_id];

			switch(dsl_msg_out.dsc_message.dsc_core_server_device_io_req.umc_major_function) {
			case IRP_MJ_CREATE:
#if 0
				if(adsl_rdpdr_device->adsc_pending_device_io_req != NULL) {
					m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Device-IO-Request overlap",
								__LINE__ );
					dsl_output_area_1.adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
					return;
				}
#endif
				if(!m_rdpdr_process_irp_create(&dsl_output_area_1, &dsl_msg_out.dsc_message.dsc_core_server_device_io_req))
					return;
				break;
			case IRP_MJ_WRITE:
				if(adsl_rdpdr_device->adsc_pending_device_io_req != NULL) {
					m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Device-IO-Request overlap",
								__LINE__ );
					dsl_output_area_1.adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
					return;
				}
				adsl_contr_1->umc_total_length = dsl_msg_out.dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_write.umc_length;
				adsl_contr_1->umc_pending_length = adsl_contr_1->umc_total_length;
				adsl_rdpdr_device->dsc_pending_device_io_req = dsl_msg_out.dsc_message.dsc_core_server_device_io_req;
				adsl_rdpdr_device->adsc_pending_device_io_req = &adsl_rdpdr_device->dsc_pending_device_io_req;
				adsl_contr_1->adsc_pending_device = adsl_rdpdr_device;
				 
				if(!m_rdpdr_process_irp_write(&dsl_output_area_1, &dsl_msg_out.dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_write.dsc_data))
					return;
				break;
			case IRP_MJ_DEVICE_CONTROL:
				if(adsl_rdpdr_device->adsc_pending_device_io_req != NULL) {
					m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Device-IO-Request overlap",
								__LINE__ );
					dsl_output_area_1.adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
					return;
				}
				adsl_contr_1->umc_total_length = dsl_msg_out.dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_device_control.umc_input_buffer_length;
				adsl_contr_1->umc_pending_length = adsl_contr_1->umc_total_length;
				adsl_rdpdr_device->dsc_pending_device_io_req = dsl_msg_out.dsc_message.dsc_core_server_device_io_req;
				adsl_rdpdr_device->adsc_pending_device_io_req = &adsl_rdpdr_device->dsc_pending_device_io_req;
				adsl_contr_1->adsc_pending_device = adsl_rdpdr_device;
				 
				if(!m_rdpdr_process_irp_device_control(&dsl_output_area_1, &dsl_msg_out.dsc_message.dsc_core_server_device_io_req.dsc_function.dsc_write.dsc_data))
					return;
				break;
			case IRP_MJ_CLOSE:
				if(adsl_rdpdr_device->adsc_pending_device_io_req != NULL) {
					m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Device-IO-Request overlap",
								__LINE__ );
					dsl_output_area_1.adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
					return;
				}
				if(!m_rdpdr_process_irp_close(&dsl_output_area_1, &dsl_msg_out.dsc_message.dsc_core_server_device_io_req))
					return;
				break;
			default:
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_wt_rdp_client_1() unknown device io function %d",
						__LINE__, dsl_msg_out.dsc_message.dsc_core_server_device_io_req.umc_major_function );
				adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
				return;
			}
			break;
		 }
		 case iec_svc_rdpdr_message_server_device_io_continuation: {
			struct dsd_rdpdr_device_context* adsl_rdpdr_device = adsl_contr_1->adsc_pending_device;
			if(adsl_rdpdr_device->adsc_pending_device_io_req == NULL) {
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W Device-IO-Request missing",
							__LINE__ );
				dsl_output_area_1.adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
				return;
			}
			switch(adsl_rdpdr_device->adsc_pending_device_io_req->umc_major_function) {
			case IRP_MJ_WRITE:
				 if(!m_rdpdr_process_irp_write(&dsl_output_area_1, &dsl_msg_out.dsc_message.dsc_core_server_device_io_continuation.dsc_data))
					 return;
				 break;
			case IRP_MJ_DEVICE_CONTROL:
				 if(!m_rdpdr_process_irp_device_control(&dsl_output_area_1, &dsl_msg_out.dsc_message.dsc_core_server_device_io_continuation.dsc_data))
					 return;
				 break;
			 default:
				 m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_wt_rdp_client_1() unknown device io function %d",
						   __LINE__, dsl_msg_out.dsc_message.dsc_core_server_device_io_req.umc_major_function );
				 adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
				 return;
			 }
			 break;
		 }
		 case iec_svc_rdpdr_message_server_printer_cache_event:
			 // TODO:
			 break;
		 case iec_svc_rdpdr_message_server_printer_cache_event_continuation:
			 // TODO:
			 break;
		 default:
			 m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_wt_rdp_client_1() unknown RDPDR message %d",
                       __LINE__, dsl_msg_out.iec_message );
			 adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			 return;
		 }
LBL_RDPDR_PROCESS_COMMANDS:
		 if(!m_rdpdr_send_commands(&dsl_output_area_1, dsl_commands, inl_num_commands))
			 return;
		 break;
	 }
#endif /*SM_RDPDR_CHANNEL*/
#if SM_RAIL_CHANNEL
	 if(adsl_rdp_vch_io->adsc_rdp_vc_1 == adsl_contr_1->adsp_rdpacc_rail) {
			struct dsd_svc_rail_message dsl_msg_out;
			int inl_res = m_svc_rail_receive_message(&adsl_contr_1->dsc_svc_rail, &dsl_output_area_1.dsc_aux_helper, adsl_rdp_vch_io, &dsl_msg_out);
			if(inl_res < 0) {
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_wt_rdp_client_1() m_svc_rail_receive_message failed",
									__LINE__ );
				adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
				return;
			}
			if(inl_res == 0) {
				break;
			}
			struct dsd_svc_rail_command dsrl_commands[2];
			int inl_num_commands = 0;
			m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_wt_rdp_client_1() m_svc_rail_receive_message dsl_msg_out.usc_order_type=%d",
									__LINE__, dsl_msg_out.usc_order_type );
			switch(dsl_msg_out.usc_order_type) {
			case TS_RAIL_ORDER_SYSPARAM:
				break;
			case TS_RAIL_ORDER_HANDSHAKE: {
				struct dsd_svc_rail_order_handshake* adsl_order = &dsrl_commands[inl_num_commands].dsc_order.dsc_handshake;
				dsrl_commands[inl_num_commands].usc_order_type = TS_RAIL_ORDER_HANDSHAKE;
				adsl_order->umc_build_number = 7601;
				inl_num_commands++;
				struct dsd_svc_rail_order_clientstatus* adsl_order2 = &dsrl_commands[inl_num_commands].dsc_order.dsc_clientstatus;
				dsrl_commands[inl_num_commands].usc_order_type = TS_RAIL_ORDER_CLIENTSTATUS;
				adsl_order2->umc_flags = TS_RAIL_CLIENTSTATUS_ALLOWLOCALMOVESIZE;
				inl_num_commands++;
				break;
			}
			case TS_RAIL_ORDER_EXEC_RESULT: {
				struct dsd_svc_rail_order_exec_result* adsl_order = &dsl_msg_out.dsc_order.dsc_exec_result;
				switch(adsl_order->usc_exec_result) {
				case TS_RAIL_EXEC_S_OK:
					break;
				default:
				   iml1 = sprintf(chrl_work1, "TS_RAIL_ORDER_EXEC failed with result code %d", adsl_order->usc_exec_result);
				   if(!m_send_websocket_error(&dsl_output_area_1, 0, chrl_work1, iml1)) {
						return;
					}
					goto LBL_RDP_CLIENT_FAILED;
				}
				break;
			}
			case TS_RAIL_ORDER_LOCALMOVESIZE: {
				break;
			}
			case TS_RAIL_ORDER_MINMAXINFO: {
				break;
			}
			case TS_RAIL_ORDER_UNKNOWN1: {
				break;
			}
			default:
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_wt_rdp_client_1() unknown RAIL message %d",
                       __LINE__, dsl_msg_out.usc_order_type);
				adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
				return;
			}
			if(!m_rail_send_commands(&dsl_output_area_1, dsrl_commands, inl_num_commands))
				 return;
			break;
	 }
#endif
	 }
     break;


     case ied_sec_recv_demand_active_pdu:   /* received Demand Active PDU */
#ifdef XYZ1
#define ADSL_D_ACT_PDU_OUT ((struct dsd_d_act_pdu *) (adsl_sc_co1_w1 + 1))
       if (((char *) (ADSL_D_ACT_PDU_OUT + 1)) > (chrl_work1 + sizeof(chrl_work1))) {
         m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_rdpclient_1() overflow area for commands",
                       __LINE__ );
         goto p_overflow_cl2se_00;
       }
       adsl_sc_co1_w1->iec_sc_command = ied_scc_d_act_pdu;  /* send demand active PDU */
       adsl_sc_co1_w1->adsc_next = NULL;    /* clear chain             */
       ADSL_D_ACT_PDU_OUT->imc_dim_x = adsl_contr_1->dsc_c_rdp_cl_1.adsc_rdp_co->imc_dim_x;
       ADSL_D_ACT_PDU_OUT->imc_dim_y = adsl_contr_1->dsc_c_rdp_cl_1.adsc_rdp_co->imc_dim_y;
       ADSL_D_ACT_PDU_OUT->imc_coldep = adsl_contr_1->dsc_c_rdp_cl_1.adsc_rdp_co->imc_s_coldep;
       *aadsl_sc_co1_ch = adsl_sc_co1_w1;   /* chain of server component command */
       aadsl_sc_co1_ch = &adsl_sc_co1_w1->adsc_next;  /* new chain of server component command */
// to-do 26.05.12 KB - alignment
       adsl_sc_co1_w1 = (struct dsd_sc_co1 *) (ADSL_D_ACT_PDU_OUT + 1);  /* server component command */
#undef ADSL_D_ACT_PDU_OUT
       break;
#endif


       // Iterate over all virtual channels and if name is "drdynvc", set the control structure channel's
       // channel number and flags.
       struct dsd_rdp_vc_1 *adsl_vc1;
       int inl_vc_it;
       for (inl_vc_it = 0; inl_vc_it < HL_RDPACC_L1(adsl_contr_1->dsc_c_wtrc1).adsc_rdp_co->imc_no_virt_ch; inl_vc_it++) {
		   adsl_vc1 = HL_RDPACC_L1(adsl_contr_1->dsc_c_wtrc1).adsc_rdp_co->adsrc_vc_1 + inl_vc_it;
#if CV_DYN_CHANNEL
		 if (memcmp(adsl_vc1->byrc_name, adsl_contr_1->adsp_rdpacc_drdynvc->byrc_name, 8) == 0) {
		   adsl_contr_1->adsp_rdpacc_drdynvc = adsl_vc1;
           //adsl_contr_1->adsp_rdpacc_drdynvc->usc_vch_no = adsl_vc1->usc_vch_no;
           //adsl_contr_1->adsp_rdpacc_drdynvc->imc_flags = adsl_vc1->imc_flags;
		   continue;
		   }
#endif
#if SM_RDPDR_CHANNEL
		 if (memcmp(adsl_vc1->byrc_name, adsl_contr_1->adsp_rdpacc_rdpdr->byrc_name, 8) == 0) {
		   adsl_contr_1->adsp_rdpacc_rdpdr = adsl_vc1;
		   adsl_contr_1->dsc_svc_rdpdr.adsc_rdp_vc_1 = adsl_vc1;
           //adsl_contr_1->adsp_rdpacc_drdynvc->usc_vch_no = adsl_vc1->usc_vch_no;
           //adsl_contr_1->adsp_rdpacc_drdynvc->imc_flags = adsl_vc1->imc_flags;
		   continue;
         }
#endif
#if SM_RAIL_CHANNEL
		 if (memcmp(adsl_vc1->byrc_name, adsl_contr_1->adsp_rdpacc_rail->byrc_name, 8) == 0) {
		   adsl_contr_1->adsp_rdpacc_rail = adsl_vc1;
		   adsl_contr_1->dsc_svc_rail.adsc_rdp_vc_1 = adsl_vc1;
           //adsl_contr_1->adsp_rdpacc_drdynvc->usc_vch_no = adsl_vc1->usc_vch_no;
           //adsl_contr_1->adsp_rdpacc_drdynvc->imc_flags = adsl_vc1->imc_flags;
		   continue;
         }
#endif
       }

#define ADSL_WTR1_G ((struct dsd_wt_record_1 *) chrl_work1)
       memset( ADSL_WTR1_G, 0, sizeof(struct dsd_wt_record_1) + sizeof(struct dsd_gather_i_1) );
       ADSL_WTR1_G->ucc_record_type = ie_wtsc_rdp_initialize_session;  /* record type            */
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) (ADSL_WTR1_G + 1))
       if ((dsl_output_area_1.achc_upper - dsl_output_area_1.achc_lower) < (3 * 4)) {  /* need buffer */
         bol_rc = m_get_new_workarea( &dsl_output_area_1 );
//       if (bol_rc == FALSE) return FALSE;
       }
       ADSL_GAI1_G->achc_ginp_cur = dsl_output_area_1.achc_lower;
       dsl_output_area_1.achc_lower
         += m_out_nhasn1( dsl_output_area_1.achc_lower, HL_RDPACC_L1(adsl_contr_1->dsc_c_wtrc1).adsc_rdp_co->imc_dim_x );
       dsl_output_area_1.achc_lower
         += m_out_nhasn1( dsl_output_area_1.achc_lower, HL_RDPACC_L1(adsl_contr_1->dsc_c_wtrc1).adsc_rdp_co->imc_dim_y );
       dsl_output_area_1.achc_lower
         += m_out_nhasn1( dsl_output_area_1.achc_lower, HL_RDPACC_L1(adsl_contr_1->dsc_c_wtrc1).adsc_rdp_co->imc_s_coldep );
       ADSL_GAI1_G->achc_ginp_end = dsl_output_area_1.achc_lower;
       ADSL_WTR1_G->adsc_gai1_data = ADSL_GAI1_G;  /* output data be be sent to client */
#undef ADSL_GAI1_G
      {
#if DEBUG_WEBSOCKETS
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_rdpclient_1() send websocket data record type: %d (first 16 bytes)",
                       __LINE__ ,ADSL_WTR1_G->ucc_record_type);
        int iml_tmp = ADSL_WTR1_G->adsc_gai1_data->achc_ginp_end - ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur;
        m_sdh_console_out( &dsl_output_area_1, ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur, (iml_tmp > 16) ? 16 : iml_tmp );
#endif
        }
       bol_rc = m_send_websocket_data( &dsl_output_area_1, adsl_contr_1, ADSL_WTR1_G );
       if (bol_rc == FALSE) {               /* error occured           */
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
         return;
       }
#undef ADSL_WTR1_G

		 {
			if ((dsl_output_area_1.achc_upper - dsl_output_area_1.achc_lower) < (sizeof(struct dsd_cc_co1))) {  /* need buffer */
				bol_rc = m_get_new_workarea( &dsl_output_area_1 );
				if (bol_rc == FALSE) {
						adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
						return;
				}
			}
			struct dsd_cc_co1* adsl_command = (struct dsd_cc_co1*)dsl_output_area_1.achc_lower;
			dsl_output_area_1.achc_lower += sizeof(struct dsd_cc_co1);
			memset( adsl_command, 0, sizeof(struct dsd_cc_co1) );
			adsl_command->iec_cc_command = ied_ccc_send_confirm_active_pdu;  /* send Confirm Active PDU */

			// append to chain
			*dsl_output_area_1.aadsc_cc_co1_ch = adsl_command;
			// position chain of client commands, input
			dsl_output_area_1.aadsc_cc_co1_ch = &adsl_command->adsc_next;
		 }
		 dsl_output_area_1.adsc_se_co1_ch_first = adsl_se_co1_w1->adsc_next;
		 goto p_rdp_client_60;
     case ied_sec_d_deact_pdu:              /* received demand de-active PDU */
#ifdef XYZ1
       if (((char *) (adsl_sc_co1_w1 + 1)) > (chrl_work1 + sizeof(chrl_work1))) {
         m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_rdpclient_1() overflow area for commands",
                       __LINE__ );
         goto p_overflow_cl2se_00;
       }
       adsl_sc_co1_w1->iec_sc_command = ied_scc_d_deact_pdu;  /* send demand de-active PDU */
       adsl_sc_co1_w1->adsc_next = NULL;    /* clear chain             */
       *aadsl_sc_co1_ch = adsl_sc_co1_w1;   /* chain of server component command */
       aadsl_sc_co1_ch = &adsl_sc_co1_w1->adsc_next;  /* new chain of server component command */
       adsl_sc_co1_w1++;                    /* server component command */
#endif
       break;
     case ied_sec_request_license:          /* request the licence     */
// to-do 19.04.12 KB - check other commands
		  {
			if ((dsl_output_area_1.achc_upper - dsl_output_area_1.achc_lower) < (sizeof(struct dsd_cc_co1) + sizeof(struct dsd_cc_pass_license))) {  /* need buffer */
				bol_rc = m_get_new_workarea( &dsl_output_area_1 );
				if (bol_rc == FALSE) {
						adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
						return;
				}
			}
			struct dsd_cc_co1* adsl_command = (struct dsd_cc_co1*)dsl_output_area_1.achc_lower;
			dsl_output_area_1.achc_lower += (sizeof(struct dsd_cc_co1) + sizeof(struct dsd_cc_pass_license));
			memset( adsl_command, 0, (sizeof(struct dsd_cc_co1) + sizeof(struct dsd_cc_pass_license)) );
			adsl_command->iec_cc_command = ied_ccc_pass_license;  /* send Confirm Active PDU */

			// append to chain
			*dsl_output_area_1.aadsc_cc_co1_ch = adsl_command;
			// position chain of client commands, input
			dsl_output_area_1.aadsc_cc_co1_ch = &adsl_command->adsc_next;
		 }
       break;
#undef ADSL_CC_CO1_G
     case ied_sec_switch_server:            /* received connect to other RDP server */
#ifdef XYZ1
       goto p_rdp_cl_ose_00;                /* connect to other WTS server */
#endif
       if (adsl_contr_1->adsc_se_switch_server) {  /* switch to other RDP server - session broker */
         m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_wt_rdp_client_1() output switch-server double",
                       __LINE__ );
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
         return;
       }
       bol1 = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                      DEF_AUX_MEMGET,
                                      &adsl_contr_1->adsc_se_switch_server,  /* switch to other RDP server - session broker */
                                      sizeof(struct dsd_se_switch_server) );
       if (bol1 == FALSE) {
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
         return;
       }
       memcpy( adsl_contr_1->adsc_se_switch_server,  /* switch to other RDP server - session broker */
               adsl_se_co1_w1 + 1,
               sizeof(struct dsd_se_switch_server) );
       /*send switch-server to client*/
#define ADSL_WTR1_G ((struct dsd_wt_record_1 *) chrl_work1)
        memset( ADSL_WTR1_G, 0, sizeof(struct dsd_wt_record_1) + sizeof(struct dsd_gather_i_1) );
        ADSL_WTR1_G->ucc_record_type = ie_wtsc_rdp_connect_switch_server; //0x0a;     /* record type             */
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) (ADSL_WTR1_G + 1))
        if ((dsl_output_area_1.achc_upper - dsl_output_area_1.achc_lower) < (sizeof(struct dsd_gather_i_1) + sizeof(int) + adsl_contr_1->adsc_se_switch_server->imc_len_ineta )) {  /* need buffer */
            bol_rc = m_get_new_workarea( &dsl_output_area_1 );
            if (bol_rc == FALSE) {
                adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
                return;
            }
        }
        ADSL_GAI1_G->achc_ginp_cur = dsl_output_area_1.achc_lower;
        dsl_output_area_1.achc_lower += m_out_nhasn1( dsl_output_area_1.achc_lower, adsl_contr_1->adsc_se_switch_server->imc_len_ineta );  /* connect error */
        memcpy(dsl_output_area_1.achc_lower,adsl_contr_1->adsc_se_switch_server->chrc_ineta,adsl_contr_1->adsc_se_switch_server->imc_len_ineta);   
        dsl_output_area_1.achc_lower += adsl_contr_1->adsc_se_switch_server->imc_len_ineta;
        ADSL_GAI1_G->achc_ginp_end = dsl_output_area_1.achc_lower;
        ADSL_WTR1_G->adsc_gai1_data = ADSL_GAI1_G;  /* output data be be sent to client */
#undef ADSL_GAI1_G        
/*        {
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_rdpclient_1() send websocket data record type: %d (first 16 bytes)",
                       __LINE__ ,ADSL_WTR1_G->ucc_record_type);
        int iml_tmp = ADSL_WTR1_G->adsc_gai1_data->achc_ginp_end - ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur;
        m_sdh_console_out( &dsl_output_area_1, ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur, (iml_tmp > 16) ? 16 : iml_tmp );
        }
        */
        bol_rc = m_send_websocket_data( &dsl_output_area_1, adsl_contr_1, ADSL_WTR1_G );
        if (bol_rc == FALSE) {                   /* error occured           */
            adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
            return;
        }
#undef ADSL_WTR1_G
       /*end send to client*/


       break;
#if SM_USE_MULTI_MONITOR
	  case ied_sec_monitor_layout_pdu:
		  if(!m_send_websocket_monitor_layout(&dsl_output_area_1, (struct dsd_sc_monitor_layout_pdu *) (adsl_se_co1_w1 + 1))) {
			return;
		  }
		  break;
#endif
	  case ied_sec_synchronize_pdu:
		  if(!m_send_websocket_rdp_synchronize(&dsl_output_area_1)) {
			return;
		  }
		  break;
     default:
       m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_wt_rdp_client_1() returned unrecognized iec_se_command=%d.",
                     __LINE__,
                     adsl_se_co1_w1->iec_se_command );
       break;
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T m_wt_rdp_client_1() iec_se_command=%d processed.",
                 __LINE__, adsl_se_co1_w1->iec_se_command );
   iml1++;                                  /* count commands          */
#endif
	adsl_se_co1_w1 = adsl_se_co1_w1->adsc_next;  /* get next in chain   */
   dsl_output_area_1.adsc_se_co1_ch_first = adsl_se_co1_w1;
	if (adsl_se_co1_w1) {
     goto p_rdp_client_40;                  /* check command from server */
   }

#if 0
//#if CV_DYN_CHANNEL /* Temp fix - Must re-organize code logic since it assumes a single server command - client command scenario */
   // If some client commands are pending, send any pending websocket data,
   // then process the commands previously added to the chain.
   if (adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch != NULL) {
     adsl_wtr1_w1 = adsl_contr_1->dsc_c_wtrc1.adsc_wtr1_out;  /* chain of WebTerm records to be sent to client */
     while (adsl_wtr1_w1) {                   /* loop over all WebTerm records to be sent */
                {
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_rdpclient_1() send websocket data record type: %d (first 16 bytes)",
                       __LINE__ ,adsl_wtr1_w1->ucc_record_type);
        if (adsl_wtr1_w1->adsc_gai1_data)
        {
            int iml_tmp = adsl_wtr1_w1->adsc_gai1_data->achc_ginp_end - adsl_wtr1_w1->adsc_gai1_data->achc_ginp_cur;
            m_sdh_console_out( &dsl_output_area_1, adsl_wtr1_w1->adsc_gai1_data->achc_ginp_cur, (iml_tmp > 16) ? 16 : iml_tmp );
        }
        }
       bol_rc = m_send_websocket_data( &dsl_output_area_1, adsl_contr_1, adsl_wtr1_w1 );
       if (bol_rc == FALSE) {                 /* error occured           */
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
         return;
       }
       adsl_wtr1_w1 = adsl_wtr1_w1->adsc_next;  /* get next in chain     */
     }

     goto p_rdp_client_20;
   }
//#endif /* CV_DYN_CHANNEL */
#endif

   p_rdp_client_60:                         /* check something to be send to WebSocket client */
   adsl_wtr1_w1 = adsl_contr_1->dsc_c_wtrc1.adsc_wtr1_out;  /* chain of WebTerm records to be sent to client */
   while (adsl_wtr1_w1) {                   /* loop over all WebTerm records to be sent */
#if 0
       ///DEBUG!!!!! MS ignore pointer events XXXX
       if (adsl_wtr1_w1->ucc_record_type == ie_wtsc_rdp_fastpath_updatetype_ptr_null || adsl_wtr1_w1->ucc_record_type == ie_wtsc_rdp_fastpath_updatetype_ptr_default || adsl_wtr1_w1->ucc_record_type == ie_wtsc_rdp_fastpath_updatetype_pointer)
       {
           adsl_wtr1_w1 = adsl_wtr1_w1->adsc_next;  
           continue;
       }
#endif        
#if DEBUG_WEBSOCKETS
       {
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_rdpclient_1() send websocket data record type: %d (first 16 bytes)",
                       __LINE__ ,adsl_wtr1_w1->ucc_record_type);
        if (adsl_wtr1_w1->adsc_gai1_data != NULL)
        {
            int iml_tmp = adsl_wtr1_w1->adsc_gai1_data->achc_ginp_end - adsl_wtr1_w1->adsc_gai1_data->achc_ginp_cur;
            m_sdh_console_out( &dsl_output_area_1, adsl_wtr1_w1->adsc_gai1_data->achc_ginp_cur, (iml_tmp > 16) ? 16 : iml_tmp );
        }
        }
#endif
     bol_rc = m_send_websocket_data( &dsl_output_area_1, adsl_contr_1, adsl_wtr1_w1 );
     if (bol_rc == FALSE) {                 /* error occured           */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
     adsl_wtr1_w1 = adsl_wtr1_w1->adsc_next;  /* get next in chain     */
   }

   if (adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch != NULL) {
		 adsl_contr_1->dsc_c_wtrc1.adsc_gather_i_1_in = NULL;
		 goto p_rdp_client_20;
   }

   if (adsl_contr_1->adsc_se_switch_server == NULL) {  /* switch to other RDP server - session broker */
#if 1
		if(adsl_contr_1->dsc_c_wtrc1.inc_func == DEF_IFUNC_CLOSE)
			goto p_webso_server_close_20;
#endif
     return;                                /* all done                */
   }
   bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                       DEF_AUX_TCP_CLOSE,  /* close TCP to Server */
                                       NULL,
                                       0 );
   if (bol_rc == FALSE) {
     m_sdh_printf( &dsl_output_area_1, "xlt-rdp-cl-se-01-l%05d-W DEF_AUX_TCP_CLOSE for connection-broker returned FALSE",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }

#ifdef XYZ1
   p_rdp_cl_ose_00:                         /* connect to other WTS server */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T p_rdp_cl_ose_00: connect to other WTS server",
                 __LINE__ );
#endif
   if (adsl_se_co1_w1->adsc_next) {         /* still next in chain     */
// to-do 17.01.14 KB
   }
// to-do 17.01.14 KB - check if only command
#endif

   p_end_server_00:                         /* received end connection to server */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T end-of-file Server",
                 __LINE__ );
#endif
   if (adsl_contr_1->adsc_se_switch_server == NULL) {  /* switch to other RDP server - session broker */
#ifdef B150120
//   goto p_end_server_20;                  /* not session-broker      */
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection should be ended */
     return;
#endif
#ifndef B150220
     if (   (adsl_contr_1->dsc_c_wtrc1.inc_return == DEF_IRET_NORMAL)  /* o.k. returned */
         && (adsl_contr_1->dsc_c_wtrc1.inc_func != DEF_IFUNC_START)) {  /* RDP-ACC already started */
       adsl_contr_1->dsc_c_wtrc1.inc_func = DEF_IFUNC_CLOSE;  /* close RDP-ACC now */
       goto p_rdp_client_08;                /* end RDP-ACC             */
     }
#endif
     goto p_webso_server_close_20;          /* WebSocket shutdown      */
   }
   if (adsl_contr_1->imc_wts_port == 0) {   /* port of the WSP         */
// to-do 17.01.14 KB
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
   }
   memset( &dsl_soa_l, 0, sizeof(sockaddr_storage) );
   switch (adsl_contr_1->adsc_se_switch_server->imc_len_ineta) {  /* length of INETA */
     case 0:                                /* connect same server     */
       if (adsl_contr_1->imc_len_wts_ineta == 4) {  /* length of INETA WTS IPV4 */
         dsl_soa_l.ss_family = AF_INET;
         achl_w1 = (char *) &((struct sockaddr_in *) &dsl_soa_l)->sin_addr;
       } else {                             /* IPV6                    */
         dsl_soa_l.ss_family = AF_INET6;
         achl_w1 = (char *) &((struct sockaddr_in6 *) &dsl_soa_l)->sin6_addr;
       }
       memcpy( achl_w1, adsl_contr_1->chrc_wts_ineta, adsl_contr_1->imc_len_wts_ineta );
       break;
     case AF_INET6:
       adsl_contr_1->imc_len_wts_ineta = 16;  /* length of INETA WTS   */
     case 4:                                /* 32 bit - IPV4           */
       dsl_soa_l.ss_family = AF_INET;
       memcpy( &((struct sockaddr_in *) &dsl_soa_l)->sin_addr, adsl_contr_1->adsc_se_switch_server->chrc_ineta, 4 );
       break;
     case 16:                               /* 128 bit - IPV6          */
       dsl_soa_l.ss_family = AF_INET6;
       memcpy( &((struct sockaddr_in6 *) &dsl_soa_l)->sin6_addr, adsl_contr_1->adsc_se_switch_server->chrc_ineta, 16 );
       break;
     default:
       m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E session broker - switch server - length INETA %d invalid",
                     __LINE__, adsl_contr_1->adsc_se_switch_server->imc_len_ineta );
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
   }
   iml_rc = getnameinfo( (struct sockaddr *) &dsl_soa_l, sizeof(sockaddr_storage),
                         chrl_work1, 128, 0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E getnameinfo() returned %d %d.",
                   __LINE__, iml_rc, D_TCP_ERROR );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   /* connect to server now                                            */
   memset( &dsl_atc1_1, 0, sizeof(dsl_atc1_1) );
   dsl_atc1_1.dsc_target_ineta.ac_str = chrl_work1;  /* address of string */
   dsl_atc1_1.dsc_target_ineta.imc_len_str = -1;  /* length string in elements */
   dsl_atc1_1.dsc_target_ineta.iec_chs_str = D_CHARSET_IP;  /* character set string */
/**
   because Microsoft Session-Broker works with DNS round-robin,
   the ports of all WTS need to be the same.
*/
   dsl_atc1_1.imc_server_port = adsl_contr_1->imc_wts_port;  /* TCP port to connect to */
   bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                       DEF_AUX_TCP_CONN,
                                       &dsl_atc1_1,
                                       sizeof(dsl_atc1_1) );
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xlt-rdp-cl-se-01-l%05d-T after DEF_AUX_TCP_CONN bol_rc=%d iec_tcpconn_ret=%d.",
                 __LINE__, bol_rc, dsl_atc1_1.iec_tcpconn_ret );
#endif
   if (dsl_atc1_1.iec_tcpconn_ret != ied_tcr_ok) {  /* connect not successful */
     m_sdh_printf( &dsl_output_area_1, "xlt-rdp-cl-se-01-l%05d-E session broker connect to server returned iec_tcpconn_ret=%d.",
                   __LINE__, dsl_atc1_1.iec_tcpconn_ret );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
                                       DEF_AUX_MEMFREE,
                                       &adsl_contr_1->adsc_se_switch_server,  /* switch to other RDP server - session broker */
                                       sizeof(struct dsd_se_switch_server) );
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_contr_1->adsc_se_switch_server = NULL;  /* switch to other RDP server - session broker */
   HL_RDPACC_AUXH(adsl_contr_1->dsc_c_wtrc1).vpc_userfld = dsl_output_area_1.vpc_userfld;  /* User Field Subroutine */
   adsl_contr_1->dsc_c_wtrc1.adsc_gather_i_1_in = NULL;
#define ADSL_CC_CO1_G ((struct dsd_cc_co1 *) chrl_work1)
   memset( ADSL_CC_CO1_G, 0, sizeof(struct dsd_cc_co1) );
   ADSL_CC_CO1_G->iec_cc_command = ied_ccc_reconnect;  /* reconnect the RDP client */
   adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch = ADSL_CC_CO1_G;  /* chain of client commands */
#undef ADSL_CC_CO1_G
   adsl_contr_1->dsc_c_wtrc1.adsc_gai1_out_to_server = NULL;  /* clear output data to server */
   goto p_rdp_client_20;                    /* call RDP client         */
} /* end m_hlclib01()                                                  */

static BOOL m_reply_http( struct dsd_sdh_call_1 *adsp_sdh_call_1, char *achp_key, int imp_len_key ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml1, iml2, iml3, iml4;       /* working variables       */
   char       *achl_w1, *achl_w2;           /* working variables       */
   int        imrl_sha1[ SHA_ARRAY_SIZE ];  /* for hash                */
   char       byrl_sha1_digest[ SHA_DIGEST_LEN ];  /* result SHA-1     */

   if ((adsp_sdh_call_1->achc_upper - adsp_sdh_call_1->achc_lower)
         < (3 * sizeof(struct dsd_gather_i_1) + (SHA_DIGEST_LEN + 3 - 1) / 3) * 4) {  /* need buffer */
     bol_rc = m_get_new_workarea( adsp_sdh_call_1 );
     if (bol_rc == FALSE) return FALSE;
   }
   SHA1_Init( imrl_sha1 );
   SHA1_Update( imrl_sha1, achp_key, 0, imp_len_key );
   SHA1_Update( imrl_sha1, (char *) ucrs_websocket_reply_key, 0, sizeof(ucrs_websocket_reply_key) );
   SHA1_Final( imrl_sha1, byrl_sha1_digest, 0 );
   adsp_sdh_call_1->achc_upper -= 3 * sizeof(struct dsd_gather_i_1);
#define ADSRL_GAI1_G ((struct dsd_gather_i_1 *) adsp_sdh_call_1->achc_upper)
   ADSRL_GAI1_G[0].achc_ginp_cur = (char *) ucrs_http_reply_01;
   ADSRL_GAI1_G[0].achc_ginp_end = (char *) ucrs_http_reply_01 + sizeof(ucrs_http_reply_01);
   ADSRL_GAI1_G[0].adsc_next = &ADSRL_GAI1_G[1];
   iml1 = sizeof(byrl_sha1_digest) / 3;     /* length of digest        */
   achl_w1 = byrl_sha1_digest;              /* address of input        */
   achl_w2 = adsp_sdh_call_1->achc_lower;   /* output area             */
   ADSRL_GAI1_G[1].achc_ginp_cur = achl_w2;
   while (iml1 > 0) {                       /* loop output MIME base64 */
     iml2 = (*((unsigned char *) achl_w1 + 0) << 16)
              | (*((unsigned char *) achl_w1 + 1) << 8)
              | *((unsigned char *) achl_w1 + 2);
     achl_w1 += 3;                          /* after these three bytes */
     iml3 = 4;
     do {                                   /* loop output four characters MIME base64 */
       iml3--;                              /* decrement index         */
       *achl_w2++ = (char) ucrs_base64[ (iml2 >> (iml3 * 6)) & 0X3F ];
     } while (iml3 > 0);
     iml1--;                                /* three input bytes processed */
   }
   iml1 = ((char *) byrl_sha1_digest + sizeof(byrl_sha1_digest)) - achl_w1;
   if (iml1 > 0) {                          /* more characters to encode */
     iml2 = 0;                              /* clear akkumumator       */
     iml3 = iml1;                           /* get number of characters */
     do {
       iml2 <<= 8;                          /* shift old value         */
       iml2 |= *((unsigned char *) achl_w1);
       achl_w1++;
       iml3--;                              /* decrement index         */
     } while (iml3 > 0);
     iml2 <<= (3 - iml1) * 8;               /* shift remaining         */
     iml3 = 4;
     iml4 = 3 - iml1;                       /* set stopper             */
     do {                                   /* loop output four characters MIME base64 */
       iml3--;                              /* decrement index         */
       *achl_w2++ = (char) ucrs_base64[ (iml2 >> (iml3 * 6)) & 0X3F ];
     } while (iml3 > iml4);
     do {
       *achl_w2++ = '=';                    /* fill last character     */
       iml4--;                              /* decrement index         */
     } while (iml4 > 0);
   }
   ADSRL_GAI1_G[1].achc_ginp_end = achl_w2;
   adsp_sdh_call_1->achc_lower = achl_w2;
   ADSRL_GAI1_G[1].adsc_next = &ADSRL_GAI1_G[2];
   ADSRL_GAI1_G[2].achc_ginp_cur = (char *) ucrs_http_reply_02;
   ADSRL_GAI1_G[2].achc_ginp_end = (char *) ucrs_http_reply_02 + sizeof(ucrs_http_reply_02);
   ADSRL_GAI1_G[2].adsc_next = NULL;
   if (adsp_sdh_call_1->adsc_contr_1->iec_clcomp == ied_clcomp_xwdf) {  /* x-webkit-deflate-frame */
     ADSRL_GAI1_G[2].achc_ginp_cur = (char *) ucrs_http_reply_03;
     ADSRL_GAI1_G[2].achc_ginp_end = (char *) ucrs_http_reply_03 + sizeof(ucrs_http_reply_03);
   } else if (adsp_sdh_call_1->adsc_contr_1->iec_clcomp == ied_clcomp_pmd_2) {  /* permessage-deflate */
     ADSRL_GAI1_G[2].achc_ginp_cur = (char *) ucrs_http_reply_04;
     ADSRL_GAI1_G[2].achc_ginp_end = (char *) ucrs_http_reply_04 + sizeof(ucrs_http_reply_04);
   }
   *adsp_sdh_call_1->aadsrc_gai1_client = &ADSRL_GAI1_G[0];  /* output data to client */
   adsp_sdh_call_1->aadsrc_gai1_client = &ADSRL_GAI1_G[2].adsc_next;  /* next output data to client */
   return TRUE;
} /* end m_reply_http()                                                */

static BOOL m_send_websocket_data( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                                   struct dsd_clib1_contr_1 *adsp_contr_1,
                                   struct dsd_wt_record_1 *adsp_wtr1 ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml1, iml2, iml3;             /* working variables       */
   char       *achl_w1;                     /* working variable        */
   char       *achl_end_header;             /* end of header           */
   struct dsd_gather_i_1 *adsl_gai1_first_out;  /* gather of first output */
   struct dsd_gather_i_1 *adsl_gai1_last_out;  /* gather of last output */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   struct dsd_wsp_trace_record **aadsl_wtr_w1;
// struct dsd_gather_i_1 **aadsl_gai1_ch;   /* chain of gather         */
   struct dsd_wsp_trace_header dsl_wtrh;    /* WSP trace header      */
   struct dsd_gather_i_1 dsrl_gai1_work[ MAX_INP_GATHER ];  /* input data */
   char       chrl_work1[ 1024 ];           /* work area               */

   if (adsp_contr_1->iec_clcomp == ied_clcomp_none) {  /* no compression */
     goto p_suc_00;                         /* send uncompressed       */
   }
   dsrl_gai1_work[ 0 ].achc_ginp_cur = (char *) &adsp_wtr1->ucc_record_type;  /* record type */
   dsrl_gai1_work[ 0 ].achc_ginp_end = (char *) &adsp_wtr1->ucc_record_type + 1;  /* end record type */
   iml1 = 0;                                /* set index gather        */
   iml2 = 1;                                /* set length output       */
   adsl_gai1_w1 = adsp_wtr1->adsc_gai1_data;   /* output data be be sent to client */
   while (adsl_gai1_w1) {                   /* loop to count length of data */
     if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) {
       iml1++;                              /* increment index gather  */
       if (iml1 >= MAX_INP_GATHER) {        /* overflow in gather array */
         m_sdh_printf( adsp_sdh_call_1, "xl-webterm-rdp-01-l%05d-W m_send_websocket_data() overflow MAX_INP_GATHER",
                       __LINE__ );
         return FALSE;
       }
       dsrl_gai1_work[ iml1 - 1 ].adsc_next = &dsrl_gai1_work[ iml1 ];
       dsrl_gai1_work[ iml1 ].achc_ginp_cur = adsl_gai1_w1->achc_ginp_cur;
       dsrl_gai1_work[ iml1 ].achc_ginp_end = adsl_gai1_w1->achc_ginp_end;
       iml2 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     }
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   dsrl_gai1_work[ iml1 ].adsc_next = NULL;
   if (adsp_sdh_call_1->imc_trace_level) {  /* WSP trace level         */
     memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
     memcpy( dsl_wtrh.chrc_wtrt_id, "SWTROU01", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
     dsl_wtrh.imc_wtrh_sno = adsp_sdh_call_1->imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work1)
     dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
     memset( ADSL_WTR_G1, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
     ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                        "xl-webterm-rdp-01 l%05d output to client before compression gather=%d length=%d/0X%X.",
                                        __LINE__, iml1 + 1, iml2, iml2 );
     achl_w1 = (char *) (ADSL_WTR_G1 + 1) + ((ADSL_WTR_G1->imc_length + sizeof(void *) - 1) & (0 - sizeof(void *)));
     aadsl_wtr_w1 = &ADSL_WTR_G1->adsc_next;
     iml2 = 0;
     while (TRUE) {
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed   */
       ADSL_WTR_G2->achc_content = dsrl_gai1_work[ iml2 ].achc_ginp_cur;   /* content of text / data  */
       ADSL_WTR_G2->imc_length = dsrl_gai1_work[ iml2 ].achc_ginp_end - dsrl_gai1_work[ iml2 ].achc_ginp_cur;
       *aadsl_wtr_w1 = ADSL_WTR_G2;
       iml2++;                              /* increment index         */
       if (iml2 >= (iml1 + 1)) break;
       ADSL_WTR_G2->boc_more = TRUE;        /* more data to follow     */
       aadsl_wtr_w1 = &ADSL_WTR_G2->adsc_next;
       achl_w1 += sizeof(struct dsd_wsp_trace_record);
    }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     bol_rc = adsp_sdh_call_1->amc_aux( adsp_sdh_call_1->vpc_userfld,
                                        DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                        &dsl_wtrh,
                                        0 );
   }
   if ((adsp_sdh_call_1->achc_upper - adsp_sdh_call_1->achc_lower) <= (2 + 8 + sizeof(struct dsd_gather_i_1))) {  /* need buffer */
     bol_rc = m_get_new_workarea( adsp_sdh_call_1 );
     if (bol_rc == FALSE) return FALSE;
   }
   adsp_sdh_call_1->achc_upper -= sizeof(struct dsd_gather_i_1);
   adsp_sdh_call_1->achc_lower += 2 + 8;    /* leave spave for header  */
   achl_end_header = adsp_sdh_call_1->achc_lower;  /* end of header    */
   adsl_gai1_first_out = (struct dsd_gather_i_1 *) adsp_sdh_call_1->achc_upper;  /* gather of first output */
   iml1 = 0;                                /* clear length compressed data */
   adsp_contr_1->dsc_cdrf_enc.vpc_userfld = adsp_sdh_call_1->vpc_userfld;  /* User Field Subroutine */
   adsp_contr_1->dsc_cdrf_enc.amc_aux = adsp_sdh_call_1->amc_aux;  /* auxiliary subroutine */
   adsp_contr_1->dsc_cdrf_enc.adsc_gai1_in = dsrl_gai1_work;  /* input data */
   adsp_contr_1->dsc_cdrf_enc.boc_mp_flush = TRUE;  /* end-of-record input */
#ifndef WHY_DOES_THIS_NOT_WORK_140108
   adsp_contr_1->dsc_cdrf_enc.boc_sr_flush = FALSE;  /* end-of-record output */
#endif
#if SM_USE_GATHER_TRACER
	if(!m_trace_cdrf_enc_compress_in(&adsp_contr_1->dsc_compress_to_client, &adsp_contr_1->dsc_cdrf_enc))
		return FALSE;
#endif

   p_sco_20:                                /* call compression        */
   /* compress input                                                   */
   adsp_contr_1->dsc_cdrf_enc.achc_out_cur = adsp_sdh_call_1->achc_lower;  /* current end of output data */
   adsp_contr_1->dsc_cdrf_enc.achc_out_end = adsp_sdh_call_1->achc_upper;  /* end of buffer for output data */
#if SM_USE_GATHER_TRACER
	if(!m_trace_cdrf_enc_compress_in2(&adsp_contr_1->dsc_compress_to_client, &adsp_contr_1->dsc_cdrf_enc))
		return FALSE;
#endif
   D_M_CDX_ENC( &adsp_contr_1->dsc_cdrf_enc );
#ifdef TRACEHL1
   m_sdh_printf( adsp_sdh_call_1, "xl-webterm-rdp-01-l%05d-T D_M_CDX_ENC() returned im_return=%d.",
                 __LINE__,
                 adsp_contr_1->dsc_cdrf_enc.imc_return );
#endif
   if (adsp_contr_1->dsc_cdrf_enc.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
// to-do 08.01.14 KB error message
     return FALSE;
   }
#if SM_USE_GATHER_TRACER
	if(!m_trace_cdrf_enc_compress_out(&adsp_contr_1->dsc_compress_to_client, &adsp_contr_1->dsc_cdrf_enc, adsp_sdh_call_1->achc_lower))
		return FALSE;
#endif
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) adsp_sdh_call_1->achc_upper)
   ADSL_GAI1_G->achc_ginp_cur = adsp_sdh_call_1->achc_lower;
   ADSL_GAI1_G->achc_ginp_end = adsp_contr_1->dsc_cdrf_enc.achc_out_cur;
   *adsp_sdh_call_1->aadsrc_gai1_client = ADSL_GAI1_G;  /* output data to client */
   adsp_sdh_call_1->aadsrc_gai1_client = &ADSL_GAI1_G->adsc_next;  /* next output data to client */
   iml2 = adsp_contr_1->dsc_cdrf_enc.achc_out_cur - adsp_sdh_call_1->achc_lower;
   iml1 += iml2;
   if (adsp_contr_1->dsc_cdrf_enc.boc_sr_flush) {  /* end-of-record output */
     goto p_sco_40;                         /* end of compression      */
   }
   adsl_gai1_last_out = ADSL_GAI1_G;        /* gather of last output   */
#undef ADSL_GAI1_G
//#ifdef TRACEHL1
   if (adsp_contr_1->dsc_cdrf_enc.achc_out_cur != adsp_sdh_call_1->achc_upper) {
     m_sdh_printf( adsp_sdh_call_1, "xl-webterm-rdp-01-l%05d-T m_send_websocket_data() zLib error achc_out_cur=%p achc_upper=%p output=%d/0X%X.",
                   __LINE__, adsp_contr_1->dsc_cdrf_enc.achc_out_cur, adsp_sdh_call_1->achc_upper, iml2, iml2 );
   }
//#endif
   bol_rc = m_get_new_workarea( adsp_sdh_call_1 );
   if (bol_rc == FALSE) return FALSE;
   adsp_sdh_call_1->achc_upper -= sizeof(struct dsd_gather_i_1);
   goto p_sco_20;                           /* call compression        */

p_sco_40:                                /* end of compression      */
#if SM_USE_GATHER_TRACER
	if(!m_trace_cdrf_enc_compress_done(&adsp_contr_1->dsc_compress_to_client, &adsp_contr_1->dsc_cdrf_enc))
		return FALSE;
#endif
   adsp_sdh_call_1->achc_lower = adsp_contr_1->dsc_cdrf_enc.achc_out_cur;
   *adsp_sdh_call_1->aadsrc_gai1_client = NULL;  /* output data to client */
   while (iml1 >= 126) {                    /* more than in one byte   */
     if (iml1 < (64 * 1024)) {              /* fits in two bytes       */
       achl_end_header -= 2;
       *(achl_end_header + 0) = (unsigned char) (iml1 >> 8);
       *(achl_end_header + 1) = (unsigned char) iml1;
       iml1 = 126;
       break;
     }
     achl_end_header -= 8;
     iml2 = 8;                              /* output 64 bits          */
     do {                                   /* loop output digits      */
       iml2--;                              /* decrement index         */
       *(achl_end_header + iml2) = (unsigned char) iml1;
       iml1 >>= 8;                          /* shift bits              */
     } while (iml2 > 0);
     iml1 = 127;
     break;
   }
   achl_end_header -= 2;
   *(achl_end_header + 0) = (unsigned char) 0XC2;
   *(achl_end_header + 1) = (unsigned char) iml1;
   adsl_gai1_first_out->achc_ginp_cur = achl_end_header;
#ifdef TRACEHL1
   m_sdh_printf( adsp_sdh_call_1, "xl-webterm-rdp-01-l%05d-T m_send_websocket_data() last block %d.",
                 __LINE__, adsl_gai1_first_out->achc_ginp_end - achl_end_header );
   m_sdh_console_out( adsp_sdh_call_1, achl_end_header, adsl_gai1_first_out->achc_ginp_end - achl_end_header );
#endif
   return TRUE;                             /* all done                */

   p_suc_00:                                /* send uncompressed       */
   iml1 = 1;                                /* length of output data   */
   adsl_gai1_w1 = adsp_wtr1->adsc_gai1_data;   /* output data be be sent to client */
   while (adsl_gai1_w1) {                   /* loop to count length of data */
     iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   iml2 = sizeof(struct dsd_gather_i_1) + 2 + 1;  /* minimum sizeof of header */
   while (iml1 >= 126) {                    /* more than in one byte   */
     if (iml1 < (64 * 1024)) {              /* fits in two bytes       */
       iml2 = sizeof(struct dsd_gather_i_1) + 2 + 2 + 1;  /* minimum sizeof of header */
       break;
     }
     iml2 = sizeof(struct dsd_gather_i_1) + 2 + 8 + 1;  /* minimum sizeof of header */
     break;
   }
   if ((adsp_sdh_call_1->achc_upper - adsp_sdh_call_1->achc_lower) < iml2) {  /* need buffer */
     bol_rc = m_get_new_workarea( adsp_sdh_call_1 );
     if (bol_rc == FALSE) return FALSE;
   }
   iml2 -= sizeof(struct dsd_gather_i_1);   /* minimum sizeof of header */
   adsp_sdh_call_1->achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) adsp_sdh_call_1->achc_upper)
   ADSL_GAI1_G->achc_ginp_cur = adsp_sdh_call_1->achc_lower;
   ADSL_GAI1_G->achc_ginp_end = adsp_sdh_call_1->achc_lower + iml2;
// aadsl_gai1_ch = &ADSL_GAI1_G->adsc_next;  /* chain of gather        */
   *adsp_sdh_call_1->aadsrc_gai1_client = ADSL_GAI1_G;  /* output data to client */
   adsp_sdh_call_1->aadsrc_gai1_client = &ADSL_GAI1_G->adsc_next;  /* next output data to client */
#undef ADSL_GAI1_G
   *(adsp_sdh_call_1->achc_lower + 0) = (unsigned char) 0X82;
   *(adsp_sdh_call_1->achc_lower + 1) = (unsigned char) iml1;
  
#if DEBUG_WEBSOCKETS
   m_sdh_printf( adsp_sdh_call_1, "xl-webterm-rdp-01-l%05d-T m_send_websocket_data() length %d",
                 __LINE__, iml1 );
#endif

   while (iml1 >= 126) {                    /* more than in one byte   */
     if (iml1 < (64 * 1024)) {              /* fits in two bytes       */
       *(adsp_sdh_call_1->achc_lower + 1) = (unsigned char) 126;
       *(adsp_sdh_call_1->achc_lower + 2) = (unsigned char) (iml1 >> 8);
       *(adsp_sdh_call_1->achc_lower + 3) = (unsigned char) iml1;
       break;
     }
     *(adsp_sdh_call_1->achc_lower + 1) = (unsigned char) 127;
     iml3 = 8;                              /* output 64 bits          */
     do {                                   /* loop output digits      */
       iml3--;                              /* decrement index         */
       *(adsp_sdh_call_1->achc_lower + 2 + iml3) = (unsigned char) iml1;
       iml1 >>= 8;                          /* shift bits              */
     } while (iml3 > 0);
     break;
   }
   *(adsp_sdh_call_1->achc_lower + iml2 - 1) = adsp_wtr1->ucc_record_type;  /* record type */
   adsp_sdh_call_1->achc_lower += iml2;
   adsl_gai1_w1 = adsp_wtr1->adsc_gai1_data;   /* output data be be sent to client */
   while (adsl_gai1_w1) {                   /* loop to count length of data */
     if ((adsp_sdh_call_1->achc_upper - adsp_sdh_call_1->achc_lower) < sizeof(struct dsd_gather_i_1)) {  /* need buffer */
       bol_rc = m_get_new_workarea( adsp_sdh_call_1 );
       if (bol_rc == FALSE) return FALSE;
     }
     adsp_sdh_call_1->achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) adsp_sdh_call_1->achc_upper)
//   *aadsl_gai1_ch = ADSL_GAI1_G;          /* chain of gather         */
     ADSL_GAI1_G->achc_ginp_cur = adsl_gai1_w1->achc_ginp_cur;
     ADSL_GAI1_G->achc_ginp_end = adsl_gai1_w1->achc_ginp_end;
//   aadsl_gai1_ch = &ADSL_GAI1_G->adsc_next;  /* chain of gather      */
     *adsp_sdh_call_1->aadsrc_gai1_client = ADSL_GAI1_G;  /* output data to client */
     adsp_sdh_call_1->aadsrc_gai1_client = &ADSL_GAI1_G->adsc_next;  /* next output data to client */
#undef ADSL_GAI1_G
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
// *aadsl_gai1_ch = NULL;                   /* chain of gather         */
   *adsp_sdh_call_1->aadsrc_gai1_client = NULL;  /* output data to client */
   return TRUE;
}

static BOOL m_send_websocket_error(struct dsd_sdh_call_1* adsp_output_area_1, int imp_flags, const char* strp_msg, int inp_msg_len) {
	struct dsd_wt_record_1 DSL_WTR1_G;
	int iml2 = 5 + 5 + inp_msg_len;
	struct dsd_gather_i_1 dsl_gather_head;
	struct dsd_gather_i_1 dsl_gather_msg;

	struct dsd_hl_clib_1* adsl_hl_clib_1 = adsp_output_area_1->adsc_hl_clib_1;
	DSL_WTR1_G.ucc_record_type = ie_wtsc_rdp_connect_failed;     /* record type             */
	if ((adsp_output_area_1->achc_upper - adsp_output_area_1->achc_lower) < iml2) {  /* need buffer */
		BOOL bol_rc = m_get_new_workarea( adsp_output_area_1 );
		if (bol_rc == FALSE) {
			adsl_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return FALSE;
		}
	}
	dsl_gather_head.achc_ginp_cur = adsp_output_area_1->achc_lower;
	adsp_output_area_1->achc_lower
		+= m_out_nhasn1( adsp_output_area_1->achc_lower, imp_flags );
	dsl_gather_head.achc_ginp_end = adsp_output_area_1->achc_lower;
	dsl_gather_head.adsc_next = &dsl_gather_msg;
	dsl_gather_msg.achc_ginp_cur = (char*)strp_msg;
	dsl_gather_msg.achc_ginp_end = (char*)strp_msg + inp_msg_len;
	dsl_gather_msg.adsc_next = NULL;
	DSL_WTR1_G.adsc_gai1_data = &dsl_gather_head;  /* output data be be sent to client */
#if DEBUG_WEBSOCKETS
               {
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_rdpclient_1() send websocket data record type: %d (first 16 bytes)",
                  __LINE__ ,ADSL_WTR1_G->ucc_record_type);
   int iml_tmp = ADSL_WTR1_G->adsc_gai1_data->achc_ginp_end - ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur;
   m_sdh_console_out( &dsl_output_area_1, ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur, (iml_tmp > 16) ? 16 : iml_tmp );
   }
#endif
	BOOL bol_rc = m_send_websocket_data( adsp_output_area_1, adsp_output_area_1->adsc_contr_1, &DSL_WTR1_G );
	if (bol_rc == FALSE) {                   /* error occured           */
		adsl_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		return FALSE;
	}
	return TRUE;
}

static BOOL m_send_websocket_rdp_synchronize(struct dsd_sdh_call_1* adsp_output_area_1) {
	struct dsd_wt_record_1 DSL_WTR1_G;
	int iml2 = 0;
	struct dsd_gather_i_1 dsl_gather_head;

	struct dsd_hl_clib_1* adsl_hl_clib_1 = adsp_output_area_1->adsc_hl_clib_1;
	DSL_WTR1_G.ucc_record_type = ie_wtsc_rdp_fastpath_updatetype_synchronize;     /* record type             */
	if ((adsp_output_area_1->achc_upper - adsp_output_area_1->achc_lower) < iml2) {  /* need buffer */
		BOOL bol_rc = m_get_new_workarea( adsp_output_area_1 );
		if (bol_rc == FALSE) {
			adsl_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return FALSE;
		}
	}
	dsl_gather_head.achc_ginp_cur = adsp_output_area_1->achc_lower;
	dsl_gather_head.achc_ginp_end = adsp_output_area_1->achc_lower;
	dsl_gather_head.adsc_next = NULL;
	DSL_WTR1_G.adsc_gai1_data = &dsl_gather_head;  /* output data be be sent to client */
#if DEBUG_WEBSOCKETS
               {
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_rdpclient_1() send websocket data record type: %d (first 16 bytes)",
                  __LINE__ ,ADSL_WTR1_G->ucc_record_type);
   int iml_tmp = ADSL_WTR1_G->adsc_gai1_data->achc_ginp_end - ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur;
   m_sdh_console_out( &dsl_output_area_1, ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur, (iml_tmp > 16) ? 16 : iml_tmp );
   }
#endif
	BOOL bol_rc = m_send_websocket_data( adsp_output_area_1, adsp_output_area_1->adsc_contr_1, &DSL_WTR1_G );
	if (bol_rc == FALSE) {                   /* error occured           */
		adsl_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		return FALSE;
	}
	return TRUE;
}

static BOOL m_send_websocket_monitor_layout(struct dsd_sdh_call_1* adsp_output_area_1, const struct dsd_sc_monitor_layout_pdu* adsp_layout) {
	struct dsd_workarea_allocator* adsl_wa_alloc = &adsp_output_area_1->dsc_wa_alloc_extern;

	struct dsd_gather_writer dsl_gw;
	m_gw_init(&dsl_gw, adsl_wa_alloc);
	{
		HL_GR_RET_GOTO(m_gw_mark_start(&dsl_gw), LBL_FAILED);
		HL_GR_RET_GOTO(m_gw_write_hasn1_uint32_be(&dsl_gw, adsp_layout->imc_monitor_count), LBL_FAILED);
		for(int iml_m=0; iml_m<adsp_layout->imc_monitor_count; iml_m++) {
			const struct dsd_ts_monitor_def* adsl_monitor = &adsp_layout->adsrc_ts_monitor[iml_m];
			HL_GR_RET_GOTO(m_gw_write_hasn1_uint32_be(&dsl_gw, adsl_monitor->umc_flags), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_hasn1_sint32_be(&dsl_gw, adsl_monitor->imc_left), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_hasn1_sint32_be(&dsl_gw, adsl_monitor->imc_top), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_hasn1_sint32_be(&dsl_gw, adsl_monitor->imc_right), LBL_FAILED);
			HL_GR_RET_GOTO(m_gw_write_hasn1_sint32_be(&dsl_gw, adsl_monitor->imc_bottom), LBL_FAILED);
		}
		HL_GR_RET_GOTO(m_gw_mark_end(&dsl_gw), LBL_FAILED);

		struct dsd_gather_i_1_fifo dsl_fifo_out;
		int inl_num_bytes = m_gw_get_abs_pos(&dsl_gw);
		m_gather_fifo_init(&dsl_fifo_out);
		m_gather3_list_release(&dsl_gw.dsc_fifo, &dsl_fifo_out);
		m_gw_destroy(&dsl_gw);

		struct dsd_wt_record_1 DSL_WTR1_G;
		DSL_WTR1_G.ucc_record_type = ie_wtsc_rdp_monitor_layout;     /* record type             */
		DSL_WTR1_G.adsc_gai1_data = dsl_fifo_out.adsc_first;
		DSL_WTR1_G.adsc_next = NULL;

#if DEBUG_WEBSOCKETS
						{
		m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_rdpclient_1() send websocket data record type: %d (first 16 bytes)",
							__LINE__ ,ADSL_WTR1_G->ucc_record_type);
		int iml_tmp = ADSL_WTR1_G->adsc_gai1_data->achc_ginp_end - ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur;
		m_sdh_console_out( &dsl_output_area_1, ADSL_WTR1_G->adsc_gai1_data->achc_ginp_cur, (iml_tmp > 16) ? 16 : iml_tmp );
		}
#endif
		BOOL bol_rc = m_send_websocket_data( adsp_output_area_1, adsp_output_area_1->adsc_contr_1, &DSL_WTR1_G );
		if (bol_rc == FALSE) {                   /* error occured           */
			adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return FALSE;
		}

		return TRUE;
	}
LBL_FAILED:
	m_gw_destroy(&dsl_gw);
	return FALSE;
}

#if SM_USE_NLA
static BOOL m_read_single_signon_credentials(struct dsd_hl_clib_1 *adsp_hl_clib_1, struct dsd_sdh_call_1* adsp_output_area_1) {
   BOOL bol_rc;
   int iml1, iml2, iml3;
   char (&chrl_work1)[sizeof(adsp_output_area_1->chrl_work1)] = adsp_output_area_1->chrl_work1;
   char (&chrl_work2)[sizeof(adsp_output_area_1->chrl_work2)] = adsp_output_area_1->chrl_work2;
   char (&chrl_work3)[sizeof(adsp_output_area_1->chrl_work3)] = adsp_output_area_1->chrl_work3;
   char *achl_w1, *achl_w2;
   //struct dsd_sdh_ident_set_1 dsl_g_idset1;
   struct dsd_aux_secure_xor_1 dsl_asxor1;  /* apply secure XOR    */
   struct dsd_hl_aux_c_cma_1 dsl_accma1;  /* command common memory area */

   struct dsd_clib1_contr_1* adsl_contr_1 = (struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext;
#define ADSL_CC1 ((struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf)  /* structure configuration */
	struct dsd_sdh_ident_set_1* adsl_g_idset1 = &adsl_contr_1->dsc_sdh_ident_set_1;

#if 0
   memset( &dsl_g_idset1, 0, sizeof(struct dsd_sdh_ident_set_1) );  /* settings for given ident */
   bol_rc = (*adsp_output_area_1->amc_aux)( adsp_output_area_1->vpc_userfld,
                                       DEF_AUX_GET_IDENT_SETTINGS,  /* return settings of this user */
                                       &dsl_g_idset1,
                                       sizeof(struct dsd_sdh_ident_set_1) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T aux-call() DEF_AUX_GET_IDENT_SETTINGS returned %d iec_ret_g_idset1 %d.",
                 __LINE__, bol_rc, dsl_g_idset1.iec_ret_g_idset1 );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return FALSE;
   }
   if (dsl_g_idset1.iec_ret_g_idset1 != ied_ret_g_idset1_ok) {  /* ident known, parameters returned, o.k. */
     return TRUE;                      /* parameters have been set */
   }
#endif
   iml1 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsl_g_idset1->dsc_user_group )  /* unicode string user-group */
            * sizeof(HL_WCHAR);
   iml2 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsl_g_idset1->dsc_userid )  /* unicode string userid */
            * sizeof(HL_WCHAR);
   iml3 = 0;                                /* length password         */
   if (ADSL_CC1->iec_d_sso                  /* SSO - single-sign-on configuration */
         != ied_d_sso_cred_cache) {         /* credential-cache        */
     goto p_cl_sta_48;                      /* end of password         */
   }
   memcpy( chrl_work1, chrs_cma_pwd_prefix, sizeof(chrs_cma_pwd_prefix) );
   iml3 = m_cpy_vx_ucs( chrl_work1 + sizeof(chrs_cma_pwd_prefix),
                        sizeof(chrl_work1) - sizeof(chrs_cma_pwd_prefix),
                        ied_chs_utf_8,      /* Unicode UTF-8           */
                        &adsl_g_idset1->dsc_user_group );  /* unicode string user-group */
   if (iml3 < 0) {
     m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W m_cpy_vx_ucs() user-group returned error",
                   __LINE__ );
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_48;                      /* end of password         */
   }
   achl_w1 = chrl_work1 + sizeof(chrs_cma_pwd_prefix) + iml3 + 1;
   iml3 = m_cpy_vx_ucs( achl_w1,
                        (chrl_work1 + sizeof(chrl_work1)) - achl_w1,
                        ied_chs_utf_8,      /* Unicode UTF-8           */
                        &adsl_g_idset1->dsc_userid );  /* unicode string userid */
   if (iml3 < 0) {
     m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W m_cpy_vx_ucs() userid returned error",
                   __LINE__ );
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_48;                      /* end of password         */
   }
   achl_w1 += iml3;
   memset( &dsl_accma1, 0, sizeof(struct dsd_hl_aux_c_cma_1) );  /* command common memory area */
   dsl_accma1.ac_cma_name = chrl_work1;     /* cma name                */
   dsl_accma1.iec_chs_name = ied_chs_utf_8;  /* character set          */
   dsl_accma1.inc_len_cma_name = achl_w1 - chrl_work1;  /* length cma name in elements */
   dsl_accma1.iec_ccma_def = ied_ccma_lock_global;  /* set global lock */
   bol_rc = (*adsp_output_area_1->amc_aux)( adsp_output_area_1->vpc_userfld,
                                       DEF_AUX_COM_CMA,  /* command common memory area */
                                       &dsl_accma1,
                                       sizeof(struct dsd_hl_aux_c_cma_1) );
#ifdef TRACEHL1
   m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-T aux-call() DEF_AUX_COM_CMA returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured - not found */
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_48;                      /* end of password         */
   }
   if (dsl_accma1.inc_len_cma_area == 0) {  /* length of cma area      */
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_44;                      /* do unlock               */
   }
   memset( &dsl_asxor1, 0, sizeof(struct dsd_aux_secure_xor_1) );  /* apply secure XOR */
   dsl_asxor1.imc_len_post_key = achl_w1 - (chrl_work1 + sizeof(chrs_cma_pwd_prefix));  /* length of post key string */
   dsl_asxor1.imc_len_xor = dsl_accma1.inc_len_cma_area;  /* length of string */
   dsl_asxor1.achc_post_key = chrl_work1 + sizeof(chrs_cma_pwd_prefix);  /* address of post key string */
   dsl_asxor1.achc_source = dsl_accma1.achc_cma_area;  /* address of source */
   dsl_asxor1.achc_destination = chrl_work2;  /* address of destination */
   bol_rc = (*adsp_output_area_1->amc_aux)( adsp_output_area_1->vpc_userfld,
                                          DEF_AUX_SECURE_XOR,  /* apply secure XOR */
                                          &dsl_asxor1,
                                          sizeof(struct dsd_aux_secure_xor_1) );
#ifdef TRACEHL1
   m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-T aux-call() DEF_AUX_SECURE_XOR returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return FALSE;
   }
   iml3 = m_cpy_vx_vx( chrl_work3, sizeof(chrl_work3), ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                       chrl_work2, dsl_accma1.inc_len_cma_area, ied_chs_utf_8 )  /* Unicode UTF-8 */
            * sizeof(HL_WCHAR);

   p_cl_sta_44:                             /* unlock CMA              */
   dsl_accma1.iec_ccma_def = ied_ccma_lock_release;  /* release lock   */
   bol_rc = (*adsp_output_area_1->amc_aux)( adsp_output_area_1->vpc_userfld,
                                          DEF_AUX_COM_CMA,  /* command common memory area */
                                          &dsl_accma1,
                                          sizeof(struct dsd_hl_aux_c_cma_1) );
#ifdef TRACEHL1
   m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-T aux-call() DEF_AUX_COM_CMA returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return FALSE;
   }

   p_cl_sta_48:                             /* end of password         */
//#define ADSL_CC1 ((struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf)  /* structure configuration */
   if (ADSL_CC1->boc_so_without_domain) {   /* <sign-on-without-domain> */
     iml1 = 0;                              /* do not use domain       */
   }
    if (ADSL_CC1->iec_d_sso == ied_d_sso_none)
    {
        //if single sign-on is none do not use any credentials
        iml1 = 0;
        iml2 = 0;
        iml3 = 0;
    }
//#undef ADSL_CC1
// to-do 16.04.15 KB
//   "sign-on-use-domain",
//   dsl_g_idset1.dsc_user_group - replace by local
   bol_rc = adsp_output_area_1->amc_aux( adsp_output_area_1->vpc_userfld,
                                       DEF_AUX_MEMGET,
                                       &adsl_contr_1->achc_rdp_cred,  /* RDP credentials */
                                       iml1 + iml2 + iml3 + sizeof(HL_WCHAR) );  /* length area */
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return FALSE;
   }
   achl_w1 = adsl_contr_1->achc_rdp_cred;   /* RDP credentials         */
   achl_w2 = achl_w1 + (iml1 + iml2 + iml3 + sizeof(HL_WCHAR));

   if (iml1 > 0) {                          /* with domain             */
	  int iml4 = m_cpy_vx_ucs( achl_w1, (achl_w2-achl_w1)/sizeof(HL_WCHAR), ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                   &adsl_g_idset1->dsc_user_group );  /* unicode string user-group */
	 if (iml4 < 0) {
		 m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W m_cpy_vx_ucs() returned error",
					   __LINE__ );
		 adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		 return FALSE;
     }
	 adsl_contr_1->dsc_client_domain.iec_chs_str = ied_chs_utf_16;
	 adsl_contr_1->dsc_client_domain.imc_len_str = iml4; /* Domain Name Length */
	 adsl_contr_1->dsc_client_domain.ac_str = achl_w1; /* Domain Name */
	 achl_w1 += iml4 * sizeof(HL_WCHAR);
   }
   if (iml2 > 0) {                          /* with userid             */
     int iml4 = m_cpy_vx_ucs( achl_w1, (achl_w2-achl_w1)/sizeof(HL_WCHAR), ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                   &adsl_g_idset1->dsc_userid );  /* unicode string userid */
	 if (iml4 < 0) {
		 m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W m_cpy_vx_ucs() returned error",
					   __LINE__ );
		 adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		 return FALSE;
     }
	 adsl_contr_1->dsc_client_userid.iec_chs_str = ied_chs_utf_16;
	 adsl_contr_1->dsc_client_userid.imc_len_str = iml4; /* User Name Length */
	 adsl_contr_1->dsc_client_userid.ac_str = achl_w1; /* User Name */
     achl_w1 += iml4 * sizeof(HL_WCHAR);
   }
   if (iml3 > 0) {                          /* with password           */
     memcpy( achl_w1, chrl_work3, iml3 );
	 adsl_contr_1->dsc_client_password.iec_chs_str = ied_chs_utf_16;
	 adsl_contr_1->dsc_client_password.imc_len_str = iml3 / sizeof(HL_WCHAR); /* Password Name Length */
	 adsl_contr_1->dsc_client_password.ac_str = achl_w1; /* Password Name */
   }
#undef ADSL_CC1
   return TRUE;
} /* end m_read_single_signon_credentials()                                          */
#endif /*SM_USE_NLA*/

BOOL m_get_new_workarea( struct dsd_sdh_call_1 *adsp_sdh_call_1 ) {
   BOOL       bol_rc;                       /* return code             */
   struct dsd_aux_get_workarea dsl_aux_get_workarea;  /* acquire additional work area */

   memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
   bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                         DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                         &dsl_aux_get_workarea,
                                         sizeof(struct dsd_aux_get_workarea) );
   if (bol_rc == FALSE) {                   /* error occured           */
     return FALSE;
   }
#if DEBUG_WORKAREAS
   m_sdh_printf(adsp_sdh_call_1, "xl-webterm-rdp-01-l%05d-W m_get_new_workarea() Old work area lower: %x upper%x, new lower: %x , upper: %x",
					   __LINE__,adsp_sdh_call_1->achc_lower,adsp_sdh_call_1->achc_upper,dsl_aux_get_workarea.achc_work_area,dsl_aux_get_workarea.achc_work_area+dsl_aux_get_workarea.imc_len_work_area );
#endif
   adsp_sdh_call_1->achc_lower              /* lower addr output area  */
     = dsl_aux_get_workarea.achc_work_area;  /* addr work-area returned */
   adsp_sdh_call_1->achc_upper              /* higher addr output area */
     = dsl_aux_get_workarea.achc_work_area  /* addr work-area returned */
         + dsl_aux_get_workarea.imc_len_work_area;  /* length work-area returned */
   return TRUE;
} /* end m_get_new_workarea()                                          */

int m_out_nhasn1( char *achp_out, int imp_number ) {
   int        iml_number;                   /* number to encode        */
   int        iml_length;                   /* length output           */
   int        iml_more;                     /* more flag               */
   char       *achl_out;                    /* address of output       */

   iml_number = imp_number;                 /* number to encode        */
   iml_length = 0;                          /* length output           */
   do {                                     /* loop to count length    */
     iml_number >>= 7;                      /* shift content           */
     iml_length++;                          /* length output           */
   } while (iml_number > 0);

   iml_number = imp_number;                 /* number to encode        */
   iml_more = 0;                            /* more flag               */
   achl_out = achp_out + iml_length;        /* address of output       */
   do {                                     /* loop to count length    */
     *(--achl_out) = (unsigned char) (iml_number & 0X7F) | iml_more;
     iml_number >>= 7;                      /* shift content           */
     iml_more = 0X80;                       /* more flag               */
   } while (iml_number > 0);

   return iml_length;                       /* length output           */
} /* end m_out_nhasn1()                                                */

/** Calculates the value plus the size of the HASN1 length itself. */
static unsigned int m_get_inclusive_hasn1_uint32_be(unsigned int im_val) {
	if(im_val < 0x80 - 1) {
		return im_val + 1;
	}
	else if(im_val < 0x4000 - 2) {
		return im_val + 2;
	}
	else if(im_val < 0x200000 - 3) {
		return im_val + 3;
	}
	else if(im_val < 0x10000000 - 4) {
		return im_val + 4;
	}
	return im_val + 5;
}

static BOOL m_sub_aux( void * vpp_userfld, int imp_func, void * ap_param, int imp_length ) {
#ifdef XYZ1
   char       *achl1;                       /* working-variable        */
   int        iml1;                         /* working-variable        */
   struct dsd_workarea_1 *adsl_workarea_1_w1;  /* work area            */
#endif
   struct dsd_clib1_contr_1 *adsl_contr_1;  /* for addressing          */
   struct dsd_session_timer *adsl_session_timer_w1;  /* session timer  */
   struct dsd_sdh_call_1 dsl_output_area_1;    /* SDH call structure      */

#define X_ADSL_PARAM  *((void **) ap_param)
#define ADSL_SUBAUX_UF ((struct dsd_subaux_userfld *) vpp_userfld)  /* for aux calls */
#define ADSL_HL_CLIB_1 ADSL_SUBAUX_UF->adsc_hl_clib_1
#ifdef TRACEHL1
   dsl_output_area_1.amc_aux = ADSL_HL_CLIB_1->amc_aux;  /* auxiliary subroutine */
   dsl_output_area_1.vpc_userfld = ADSL_HL_CLIB_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T m_sub_aux() imp_func=%d.",
                 __LINE__, imp_func );
#endif
   switch (imp_func) {                      /* depend on function      */
     case DEF_AUX_MEMGET:                   /* get some memory         */
     case DEF_AUX_MEMFREE:                  /* free memory             */
     case DEF_AUX_GET_WORKAREA:             /* get additional work area */
     case DEF_AUX_CONSOLE_OUT:
     case DEF_AUX_CO_UNICODE:
     case DEF_AUX_RANDOM_RAW:
     case DEF_AUX_RANDOM_BASE64:
     case DEF_AUX_MARK_WORKAREA_INC:        /* increment usage count in work area */
     case DEF_AUX_MARK_WORKAREA_DEC:        /* decrement usage count in work area */
#ifndef B150216
     case DEF_AUX_WSP_TRACE:                /* write WSP trace         */
#endif
       return (*ADSL_HL_CLIB_1->amc_aux)( ADSL_HL_CLIB_1->vpc_userfld,
                                          imp_func, ap_param, imp_length );
     case DEF_AUX_GET_T_MSEC:               /* get time / epoch in milliseconds */
#ifdef XYZ1
       if (imp_length != sizeof(HL_LONGLONG)) return FALSE;  /* invalid size */
       if ((((HL_LONGLONG) ap_param) & (sizeof(void *) - 1))) return FALSE;  /* misaligned */
       *((HL_LONGLONG *) ap_param) = ADSL_SUBAUX_UF->ilc_epoch;
       return TRUE;                         /* all done                */
#endif
       return FALSE;                        /* not yet implemented     */
     case DEF_AUX_TIMER1_SET:               /* set timer in milliseconds */
     case DEF_AUX_TIMER1_REL:               /* release timer set before */
//     goto p_timer_00;                     /* release the timer, when set */
       return FALSE;                        /* not yet implemented     */
     case DEF_AUX_TIMER1_QUERY:             /* return struct dsd_timer1_ret */
#ifdef XYZ1
       if (imp_length != sizeof(struct dsd_timer1_ret)) return FALSE;
#define ADSL_TIMER1_RET_G ((struct dsd_timer1_ret *) ap_param)
       ADSL_TIMER1_RET_G->ilc_epoch = ADSL_SUBAUX_UF->ilc_epoch;  /* epoch in milliseconds */
       if (ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end == 0) {  /* epoch timer not set */
         ADSL_TIMER1_RET_G->boc_timer_set = FALSE;  /* a timer is not set */
         ADSL_TIMER1_RET_G->ilc_timer = 0;  /* epoch when timer elapses */
         return TRUE;                       /* all done                */
       }
       ADSL_TIMER1_RET_G->boc_timer_set = TRUE;  /* a timer is set     */
       ADSL_TIMER1_RET_G->ilc_timer = ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end;  /* epoch when timer elapses */
       return TRUE;                         /* all done                */
#undef ADSL_TIMER1_RET_G
#endif
       return FALSE;                        /* not yet implemented     */
   }
   return FALSE;

#ifdef XYZ1
   p_timer_00:                              /* release the timer, when set */
   adsl_contr_1 = (struct dsd_clib1_contr_1 *) ADSL_HL_CLIB_1->ac_ext;
   if (ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end == 0) {  /* epoch timer not set */
     goto p_timer_60;                       /* set the timer           */
   }
   ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end = 0;  /* reset epoch timer */
   if (ADSL_SUBAUX_UF->adsc_session_timer == adsl_contr_1->adsc_session_timer) {  /* is first in chain */
     adsl_contr_1->adsc_session_timer = adsl_contr_1->adsc_session_timer->adsc_next;  /* remove from chain */
     goto p_timer_60;                       /* set the timer           */
   }
   adsl_session_timer_w1 = adsl_contr_1->adsc_session_timer;  /* get chain */
   if (adsl_session_timer_w1 == NULL) {     /* chain is empty          */
     goto p_timer_40;                       /* timer chain corrupted   */
   }

   p_timer_20:                              /* search timer in chain   */
   if (ADSL_SUBAUX_UF->adsc_session_timer == adsl_session_timer_w1->adsc_next) {  /* check if next from here */
     adsl_session_timer_w1->adsc_next = adsl_session_timer_w1->adsc_next->adsc_next;  /* remove entry from chain */
     goto p_timer_60;                       /* set the timer           */
   }
   adsl_session_timer_w1 = adsl_session_timer_w1->adsc_next;  /* get next in chain */
   if (adsl_session_timer_w1) goto p_timer_20;  /* search timer in chain */

   p_timer_40:                              /* timer chain corrupted   */
   dsl_output_area_1.amc_aux = ADSL_HL_CLIB_1->amc_aux;  /* auxiliary subroutine */
   dsl_output_area_1.vpc_userfld = ADSL_HL_CLIB_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-W m_sub_aux() imp_func=%d adsc_sdh_tcp_1=%p timer chain corrupted",
                 __LINE__, imp_func, ADSL_SUBAUX_UF->adsc_sdh_tcp_1 );

   p_timer_60:                              /* set the timer           */
   ADSL_SUBAUX_UF->adsc_sdh_tcp_1->boc_timer_running = FALSE;  /* timer is currently not running */
   if (imp_func != DEF_AUX_TIMER1_SET) return TRUE;  /* do not set timer in milliseconds */
   ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end = ADSL_SUBAUX_UF->ilc_epoch + imp_length;  /* set epoch timer */
   ADSL_SUBAUX_UF->adsc_sdh_tcp_1->boc_timer_running = TRUE;  /* timer is currently running */
// ADSL_SUBAUX_UF->adsc_session_timer->adsc_next = NULL;  /* clear chain */
   if (   (adsl_contr_1->adsc_session_timer == NULL)  /* chain is empty */
       || (ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end < adsl_contr_1->adsc_session_timer->ilc_epoch_end)) {
     ADSL_SUBAUX_UF->adsc_session_timer->adsc_next = adsl_contr_1->adsc_session_timer;  /* set chain */
     adsl_contr_1->adsc_session_timer = ADSL_SUBAUX_UF->adsc_session_timer;  /* set new anchor */
     return TRUE;                           /* all done                */
   }
   adsl_session_timer_w1 = adsl_contr_1->adsc_session_timer;  /* get chain */
   while (   (adsl_session_timer_w1->adsc_next)
          && (adsl_session_timer_w1->adsc_next->ilc_epoch_end <= ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end)) {
     adsl_session_timer_w1 = adsl_session_timer_w1->adsc_next;  /* get next in chain */
   }
   ADSL_SUBAUX_UF->adsc_session_timer->adsc_next = adsl_session_timer_w1->adsc_next;  /* set end of chain */
   adsl_session_timer_w1->adsc_next = ADSL_SUBAUX_UF->adsc_session_timer;  /* insert new entry in chain */
   return TRUE;                             /* all done                */
#endif

#undef X_ADSL_PARAM
#undef ADSL_SUBAUX_UF
#undef ADSL_HL_CLIB_1
} /* end m_sub_aux()                                                   */

/* subroutine for output to console                                    */
static int m_sdh_printf( struct dsd_sdh_call_1 *adsp_sdh_call_1, const char *achptext, ... ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   va_list    dsl_argptr;
   char       chrl_out1[512];

   va_start( dsl_argptr, achptext );
   iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8, achptext, dsl_argptr );
   va_end( dsl_argptr );
   bol1 = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                       DEF_AUX_CONSOLE_OUT,  /* output to console */
                                       chrl_out1, iml1 );
   return iml1;
} /* end m_sdh_printf()                                                */

static int m_sdh_printf2(void* avop_ptr, const char *achptext, ... ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   va_list    dsl_argptr;
   char       chrl_out1[512];
   struct dsd_sdh_call_1 *adsp_sdh_call_1 = (struct dsd_sdh_call_1 *)avop_ptr;

   va_start( dsl_argptr, achptext );
   iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8, achptext, dsl_argptr );
   va_end( dsl_argptr );
   bol1 = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                       DEF_AUX_CONSOLE_OUT,  /* output to console */
                                       chrl_out1, iml1 );
   return iml1;
}

static int m_sdh_printf(struct dsd_aux_helper *adsp_aux_helper, const char *achptext, ... ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   va_list    dsl_argptr;
   char       chrl_out1[512];

   va_start( dsl_argptr, achptext );
   iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8, achptext, dsl_argptr );
   va_end( dsl_argptr );
   bol1 = (*adsp_aux_helper->amc_aux)( adsp_aux_helper->vpc_userfld,
                                       DEF_AUX_CONSOLE_OUT,  /* output to console */
                                       chrl_out1, iml1 );
   return iml1;
}

/* subroutine to display date and time                                 */
static int m_get_date_time( char *achp_buff ) {
   time_t     dsl_time;

   time( &dsl_time );
   return strftime( achp_buff, 18, "%d.%m.%y %H:%M:%S", localtime( &dsl_time ) );
} /* end m_get_date_time()                                             */

/* subroutine to dump storage-content to console                       */
static void m_sdh_console_out( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                               char *achp_buff, int implength ) {
   int        iml1, iml2, iml3, iml4, iml5, iml6;  /* working variable */
   char       byl1;                         /* working-variable        */
   char       chrlwork1[ 76 ];              /* buffer to print         */

   if (achp_buff == NULL) {
     m_sdh_printf( adsp_sdh_call_1, "%s", "========= CONSOLE OUT NULL =========");
	 return;
   }


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
//   printf( "%.*s\n", sizeof(chrlwork1), chrlwork1 );
     m_sdh_printf( adsp_sdh_call_1, "%.*s", sizeof(chrlwork1), chrlwork1 );
   }
} /* end m_sdh_console_out()                                           */

/* dump output data from gather structures                             */
static void m_dump_gather( struct dsd_sdh_call_1 *adsp_sdh_call_1,
  struct dsd_gather_i_1 *adsp_gather_i_1_in,  /* input data            */
  int imp_len_trace_input ) {               /* length trace-input      */
   int        iml1, iml2, iml3, iml4, iml5, iml6;  /* working variable */
   char       byl1;                         /* working-variable        */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working-variable        */
   char       *achl_cur;                    /* position in gather      */
   char       chrlwork1[ 76 ];              /* buffer to print         */

   adsl_gai1_w1 = adsp_gather_i_1_in;
   if (adsl_gai1_w1 == NULL) return;
   achl_cur = adsl_gai1_w1->achc_ginp_cur;
   iml1 = 0;
   while (iml1 < imp_len_trace_input) {
     iml2 = iml1 + 16;
     if (iml2 > imp_len_trace_input) iml2 = imp_len_trace_input;
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
       while (achl_cur >= adsl_gai1_w1->achc_ginp_end) {
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
         if (adsl_gai1_w1 == NULL) return;
         achl_cur = adsl_gai1_w1->achc_ginp_cur;
       }
       byl1 = *achl_cur++;
       iml1++;
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
} /* end m_dump_gather()                                               */

#if SM_RDPDR_CHANNEL
#define HL_STREAM_PIPE_CMD_OPEN_REQ		0
#define HL_STREAM_PIPE_CMD_OPEN_RESP	1
#define HL_STREAM_PIPE_CMD_WRITE_REQ	2
#define HL_STREAM_PIPE_CMD_WRITE_RESP	3
#define HL_STREAM_PIPE_CMD_CLOSE_REQ	4
#define HL_STREAM_PIPE_CMD_CLOSE_RESP	5

#define HL_HTTP_STREAM_PIPE_OPEN_PROPERTY_CONTENT_TYPE		0

static BOOL m_rdpdr_device_cleanup_printer(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_rdpdr_device_context_printer* adsp_printer) {
	struct dsd_clib1_contr_1 *adsl_contr_1 = adsp_output_area_1->adsc_contr_1;
	m_aux_timer_handler_remove(&adsl_contr_1->dsc_timer_handler, &adsp_output_area_1->dsc_aux_helper, &adsp_printer->dsc_timer_entry.dsc_base);
	
	BOOL bol_rdp_active = (adsl_contr_1->dsc_c_wtrc1.inc_func == DEF_IFUNC_REFLECT);

	struct dsd_svc_rdpdr_message_core_server_device_io_req* adsl_pending_device_io_req = adsp_printer->dsc_device_context.adsc_pending_device_io_req;
	if(bol_rdp_active && adsl_pending_device_io_req != NULL) {
		struct dsd_svc_rdpdr_command dsl_commands[1];
		int inl_num_commands = 0;
		switch(adsl_pending_device_io_req->umc_major_function) {
		case IRP_MJ_CREATE: {
			struct dsd_svc_rdpdr_command_core_device_io_resp* adsl_io_resp = &dsl_commands[inl_num_commands].dsc_message.dsc_core_device_io;
			dsl_commands[inl_num_commands].iec_command = iec_svc_rdpdr_command_core_device_io_resp;
			adsl_io_resp->iec_function = ied_device_io_function_create;
			adsl_io_resp->umc_device_id = adsl_pending_device_io_req->umc_device_id;
			adsl_io_resp->umc_completion_id = adsl_pending_device_io_req->umc_completion_id;
			adsl_io_resp->umc_io_status = HL_STATUS_ERROR_BROKEN_PIPE;
			adsl_io_resp->dsc_function.dsc_create.umc_file_id = 0;
			adsl_io_resp->dsc_function.dsc_create.ucc_information = 0;
			inl_num_commands++;
			break;
		}
		case IRP_MJ_WRITE: {
			struct dsd_svc_rdpdr_command_core_device_io_resp* adsl_io_resp = &dsl_commands[inl_num_commands].dsc_message.dsc_core_device_io;
			dsl_commands[inl_num_commands].iec_command = iec_svc_rdpdr_command_core_device_io_resp;
			adsl_io_resp->iec_function = ied_device_io_function_write;
			adsl_io_resp->umc_device_id = adsl_pending_device_io_req->umc_device_id;
			adsl_io_resp->umc_completion_id = adsl_pending_device_io_req->umc_completion_id;
			adsl_io_resp->umc_io_status = HL_STATUS_ERROR_BROKEN_PIPE;
			adsl_io_resp->dsc_function.dsc_write.umc_length = adsl_pending_device_io_req->dsc_function.dsc_write.umc_length;
			inl_num_commands++;
			break;
		}
		case IRP_MJ_CLOSE: {
			struct dsd_svc_rdpdr_command_core_device_io_resp* adsl_io_resp = &dsl_commands[inl_num_commands].dsc_message.dsc_core_device_io;
			dsl_commands[inl_num_commands].iec_command = iec_svc_rdpdr_command_core_device_io_resp;
			adsl_io_resp->iec_function = ied_device_io_function_write;
			adsl_io_resp->umc_device_id = adsl_pending_device_io_req->umc_device_id;
			adsl_io_resp->umc_completion_id = adsl_pending_device_io_req->umc_completion_id;
			adsl_io_resp->umc_io_status = HL_STATUS_ERROR_BROKEN_PIPE;
			inl_num_commands++;
			break;
		}
		default:
			m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W ied_aprc_conn_ended unexpected IRP function %d",
						__LINE__, adsl_pending_device_io_req->umc_major_function );
			adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return FALSE;
		}
		if(!m_rdpdr_send_commands(adsp_output_area_1, dsl_commands, inl_num_commands)) {
			return FALSE;
		}
		adsp_printer->dsc_device_context.adsc_pending_device_io_req = NULL;
	}

	struct dsd_aux_pipe_stream* adsl_aux_pipe_stream = &adsp_printer->dsc_aux_pipe_stream;
	if(adsl_aux_pipe_stream->vpc_aux_pipe_handle != NULL) {
		struct dsd_aux_pipe_req_1 dsl_apr1;
		memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
		dsl_apr1.iec_apc = ied_apc_close_conn;  /* free passed read buffers */
		dsl_apr1.vpc_aux_pipe_handle = adsl_aux_pipe_stream->vpc_aux_pipe_handle;  /* handle of aux-pipe */
		BOOL bol_rc = adsp_output_area_1->amc_aux( adsp_output_area_1->vpc_userfld,
													DEF_AUX_PIPE, /* aux-pipe          */
													&dsl_apr1,  /* aux-pipe request    */
													sizeof(struct dsd_aux_pipe_req_1) );
		if(!bol_rc) {
			m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W DEF_AUX_PIPE failed",
						__LINE__ );
			adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return FALSE;
		}
		adsl_aux_pipe_stream->vpc_aux_pipe_handle = NULL;
	}

	if(adsp_printer->vpc_aux_pipe_handle != NULL) {
		struct dsd_aux_pipe_req_1 dsl_apr1;
		memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
		dsl_apr1.iec_apc = ied_apc_close_listen;  /* free passed read buffers */
		dsl_apr1.vpc_aux_pipe_handle = adsp_printer->vpc_aux_pipe_handle;  /* handle of aux-pipe */
		BOOL bol_rc = adsp_output_area_1->amc_aux( adsp_output_area_1->vpc_userfld,
													DEF_AUX_PIPE, /* aux-pipe          */
													&dsl_apr1,  /* aux-pipe request    */
													sizeof(struct dsd_aux_pipe_req_1) );
		if(!bol_rc) {
			m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W DEF_AUX_PIPE failed",
						__LINE__ );
			adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return FALSE;
		}
		adsp_printer->vpc_aux_pipe_handle = NULL;
	}
	return TRUE;
}

static BOOL m_rdpdr_device_cleanup(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_rdpdr_device_context* adsp_device) {
	struct dsd_clib1_contr_1 *adsl_contr_1 = adsp_output_area_1->adsc_contr_1;
	switch(adsp_device->iec_device_type) {
	case ied_rdpdr_device_type_printer: {
		struct dsd_rdpdr_device_context_printer* adsl_printer = (struct dsd_rdpdr_device_context_printer*)adsp_device;
		return m_rdpdr_device_cleanup_printer(adsp_output_area_1, adsl_printer);
	}
	default:
		m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W unexpected device type %d",
						__LINE__, adsp_device->iec_device_type );
		adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		return FALSE;
	}
}

static BOOL m_rdpdr_aux_stream_timeout(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_aux_timer_entry2* adsp_entry2) {
	struct dsd_rdpdr_device_context_printer* adsl_printer = HL_UPCAST(struct dsd_rdpdr_device_context_printer, dsc_timer_entry, adsp_entry2);
	return m_rdpdr_device_cleanup_printer(adsp_output_area_1, adsl_printer);
}

static BOOL m_rdpdr_process_irp_create(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_svc_rdpdr_message_core_server_device_io_req* adsp_devio_req) {
	struct dsd_clib1_contr_1 *adsl_contr_1 = adsp_output_area_1->adsc_contr_1;
	struct dsd_rdpdr_device_context* adsl_rdpdr_device =
		adsl_contr_1->adsrc_rdpdr_devices[adsp_devio_req->umc_device_id];

	switch(adsl_rdpdr_device->iec_device_type) {
#if SM_USE_PRINTING
	case ied_rdpdr_device_type_printer: {
		if(adsl_rdpdr_device->adsc_pending_device_io_req != NULL) {
			m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W Device-IO-Request overlap",
						__LINE__ );
			goto LBL_DEVICE_IO_FAILED;
		}

		struct dsd_rdpdr_device_context_printer* adsl_printer = (struct dsd_rdpdr_device_context_printer*)adsl_rdpdr_device;
		if(adsl_printer->vpc_aux_pipe_handle != NULL
			|| adsl_printer->dsc_aux_pipe_stream.vpc_aux_pipe_handle != NULL) {
			goto LBL_DEVICE_IO_FAILED;
		}
		struct dsd_aux_ident_session_info* adsl_aux_ident_session_info = (struct dsd_aux_ident_session_info*)adsl_contr_1->dsc_sdh_ident_set_1.achc_userfld;
		char* achl_random = adsp_output_area_1->chrl_work3;
		int inl_random_len = 64;
		BOOL bol_rc = adsp_output_area_1->amc_aux( adsp_output_area_1->vpc_userfld,
							DEF_AUX_RANDOM_BASE64, /* aux-pipe          */
							achl_random,  /* aux-pipe request    */
							inl_random_len );
		if(!bol_rc) {
			m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W DEF_AUX_RANDOM_BASE64 failed",
						__LINE__ );
			adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return FALSE;
		}
		char* achl_pipe_name = achl_random + inl_random_len;
		// Convert B64 to RFC3548 
		for(int inl_i=0; inl_i<inl_random_len; inl_i++) {
			switch(achl_random[inl_i]) {
			case '+':
				achl_random[inl_i] = '-';
				break;
			case '/':
				achl_random[inl_i] = '_';
				break;
			}
		}
		char* achl_temp2 = adsp_output_area_1->chrl_work3 + sizeof(adsp_output_area_1->chrl_work3);
		int inl_pipe_name_len = m_hlsnprintf(achl_pipe_name, achl_temp2-achl_pipe_name,
			ied_chs_ascii_850,
			"/stream/session/%.*s/webtermrdp/print/%.*s/%(ucs)s",
			sizeof(adsl_aux_ident_session_info->chrc_session_ticket), adsl_aux_ident_session_info->chrc_session_ticket,
			inl_random_len, achl_random,
			&adsl_printer->adsc_conf_printer->dsc_file_name);
		struct dsd_aux_pipe_req_1 dsl_apr1;
		memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
		dsl_apr1.iec_apc = ied_apc_create;       /* create, server side open */
		dsl_apr1.achc_aux_pipe_name = achl_pipe_name;  /* address name of aux-pipe */
		dsl_apr1.imc_len_aux_pipe_name = inl_pipe_name_len;  /* length of name of aux-pipe */
		dsl_apr1.iec_aps = ied_aps_process;      /* for current process     */
		dsl_apr1.imc_signal = 1 << (adsp_devio_req->umc_device_id + HL_RDPDR_SIGNALS_START);  /* signal to set         */
		bol_rc = adsp_output_area_1->amc_aux( adsp_output_area_1->vpc_userfld,
							DEF_AUX_PIPE, /* aux-pipe          */
							&dsl_apr1,  /* aux-pipe request    */
							sizeof(struct dsd_aux_pipe_req_1) );
		if(!bol_rc) {
			m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W DEF_AUX_PIPE failed",
						__LINE__ );
			adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return FALSE;
		}
#if 0
		m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-I AUX-PIPE name length=%d value=%.*s",
						__LINE__, dsl_apr1.imc_len_aux_pipe_name, dsl_apr1.imc_len_aux_pipe_name, dsl_apr1.achc_aux_pipe_name );
#endif
		if(dsl_apr1.iec_aprc != ied_aprc_ok) {
			goto LBL_DEVICE_IO_FAILED;
		}
					
		adsl_printer->vpc_aux_pipe_handle = dsl_apr1.vpc_aux_pipe_handle;  /* handle of aux-pipe */
		adsl_rdpdr_device->dsc_pending_device_io_req = *adsp_devio_req;
		adsl_rdpdr_device->adsc_pending_device_io_req = &adsl_rdpdr_device->dsc_pending_device_io_req;
		char* achl_url = achl_random + inl_random_len;
		int iml_url_len = m_hlsnprintf(achl_url, achl_temp2-achl_url,
			ied_chs_ascii_850,
#if SM_USE_VIRTUAL_LINK
			//"/virtual/stream/session/webtermrdp/print/%.*s/%(ucs)s",
			"/virtual/protected/stream/session/webtermrdp/print/%.*s/%(ucs)s",
#else
			"/stream/session/webtermrdp/print/%.*s/%(ucs)s",
#endif
			inl_random_len, achl_random,
			&adsl_printer->adsc_conf_printer->dsc_file_name);
					
		struct dsd_wt_record_1* ADSL_WTR1_G = ((struct dsd_wt_record_1 *) adsp_output_area_1->chrl_work1);
		struct dsd_gather_i_1* ADSL_GAI1_G = (struct dsd_gather_i_1*)(ADSL_WTR1_G+1);
		memset( ADSL_WTR1_G, 0, sizeof(struct dsd_wt_record_1) + sizeof(struct dsd_gather_i_1) );
		int iml2 = 1 + 5 + 5 + iml_url_len;

		// RDPDR_PRINT_DOCUMENT_REQ
		ADSL_WTR1_G->ucc_record_type = ie_wtsc_rdpdr_print_document_req;     /* record type             */
		if ((adsp_output_area_1->achc_upper - adsp_output_area_1->achc_lower) < iml2) {  /* need buffer */
			bol_rc = m_get_new_workarea( adsp_output_area_1 );
			if (bol_rc == FALSE) {
				adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
				return FALSE;
			}
		}
		ADSL_GAI1_G->achc_ginp_cur = adsp_output_area_1->achc_lower;
		adsp_output_area_1->achc_lower
			+= m_out_nhasn1( adsp_output_area_1->achc_lower, adsp_devio_req->umc_device_id );
		adsp_output_area_1->achc_lower
			+= m_out_nhasn1( adsp_output_area_1->achc_lower, iml_url_len );
		memcpy(adsp_output_area_1->achc_lower, achl_url, iml_url_len);
		adsp_output_area_1->achc_lower += iml_url_len;
		ADSL_GAI1_G->achc_ginp_end = adsp_output_area_1->achc_lower;
		ADSL_WTR1_G->adsc_gai1_data = ADSL_GAI1_G;  /* output data be be sent to client */
		bol_rc = m_send_websocket_data( adsp_output_area_1, adsl_contr_1, ADSL_WTR1_G );
		if (bol_rc == FALSE) {                   /* error occured           */
			adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return FALSE;
		}
		int iml_request_timeout = adsl_printer->adsc_conf_printer->imc_request_timeout;
		if(iml_request_timeout > 0) {
			adsl_printer->dsc_timer_entry.amc_proc = &m_rdpdr_aux_stream_timeout;
			bol_rc = m_aux_timer_handler_add(&adsl_contr_1->dsc_timer_handler, &adsp_output_area_1->dsc_aux_helper,
				&adsl_printer->dsc_timer_entry.dsc_base, iml_request_timeout);
			if (bol_rc == FALSE) {                   /* error occured           */
				m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-E m_aux_timer_handler_add failed",
							__LINE__ );
				adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
				return FALSE;
			}
		}
		break;
	}
#endif /*SM_USE_PRINTING*/
	default:
		goto LBL_DEVICE_IO_FAILED;
	}
	return TRUE;
LBL_DEVICE_IO_FAILED:
	struct dsd_svc_rdpdr_command dsl_command;
	struct dsd_svc_rdpdr_command_core_device_io_resp* adsl_io_resp = &dsl_command.dsc_message.dsc_core_device_io;
	dsl_command.iec_command = iec_svc_rdpdr_command_core_device_io_resp;
	adsl_io_resp->iec_function = ied_device_io_function_create;
	adsl_io_resp->umc_device_id = adsp_devio_req->umc_device_id;
	adsl_io_resp->umc_completion_id = adsp_devio_req->umc_completion_id;
	adsl_io_resp->umc_io_status = HL_STATUS_E_FAIL;
	adsl_io_resp->dsc_function.dsc_create.umc_file_id = 0;
	adsl_io_resp->dsc_function.dsc_create.ucc_information = 0;
	return m_rdpdr_send_commands(adsp_output_area_1, &dsl_command, 1);
}

static BOOL m_rdpdr_process_irp_write(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_gather_i_1_pos* adsp_pos) {
	struct dsd_clib1_contr_1 *adsl_contr_1 = adsp_output_area_1->adsc_contr_1;
	struct dsd_rdpdr_device_context* adsl_pending_device = adsl_contr_1->adsc_pending_device;
	if(adsl_pending_device->iec_device_type != ied_rdpdr_device_type_printer) {
		m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W unexpected device type %d",
						__LINE__, adsl_pending_device->iec_device_type );
		adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		return FALSE;
	}

	uint32_t uml_total_length = adsl_contr_1->umc_total_length;
	BOOL bol_first = (adsl_contr_1->umc_pending_length >= uml_total_length);
	struct dsd_gather_i_1 dsl_pos;
	m_gather_i_1_pos_to_gather(adsp_pos, &dsl_pos);
	struct dsd_gather_i_1 *adsl_gai1_data = &dsl_pos;
	while(adsl_gai1_data != NULL) {
		uint32_t uml_available = adsl_gai1_data->achc_ginp_end-adsl_gai1_data->achc_ginp_cur;
		adsl_contr_1->umc_pending_length -= uml_available;
		if(adsl_contr_1->umc_pending_length <= 0) {
			break;
		}
		adsl_gai1_data = adsl_gai1_data->adsc_next;
	}
#if SM_USE_PRINTING			 
	struct dsd_rdpdr_device_context_printer* adsl_pending_printer = (struct dsd_rdpdr_device_context_printer*)adsl_pending_device;
	struct dsd_aux_pipe_stream* adsl_aux_pipe_stream = &adsl_pending_printer->dsc_aux_pipe_stream;

	struct dsd_gather_i_1 dsl_head;
	dsl_head.achc_ginp_cur = NULL;
	dsl_head.achc_ginp_end = NULL;
	char chrl_temp[5];
	//m_sdh_printf(adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W ied_rdpdr_pending_status_write umc_pending_length=%d total=%d\n",
	//				__LINE__, adsl_contr_1->umc_pending_length, uml_total_length );
	if(bol_first) {
		chrl_temp[0] = HL_STREAM_PIPE_CMD_WRITE_REQ;
		chrl_temp[1] = (char)(uml_total_length);
		chrl_temp[2] = (char)(uml_total_length>>8);
		chrl_temp[3] = (char)(uml_total_length>>16);
		chrl_temp[4] = (char)(uml_total_length>>24);
		dsl_head.achc_ginp_cur = chrl_temp;
		dsl_head.achc_ginp_end = chrl_temp+5;
	}
	dsl_head.adsc_next = &dsl_pos;

	if(adsl_aux_pipe_stream->vpc_aux_pipe_handle != NULL) {
		struct dsd_aux_pipe_req_1 dsl_apr1;
		memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
		dsl_apr1.iec_apc = ied_apc_write;        /* write to session        */
		dsl_apr1.vpc_aux_pipe_handle = adsl_aux_pipe_stream->vpc_aux_pipe_handle;  /* handle of aux-pipe */
		dsl_apr1.adsc_gai1_data = &dsl_head;  /* send data             */
		BOOL bol_rc = adsp_output_area_1->amc_aux( adsp_output_area_1->vpc_userfld,
												DEF_AUX_PIPE, /* aux-pipe          */
												&dsl_apr1,  /* aux-pipe request    */
												sizeof(struct dsd_aux_pipe_req_1) );
		if(!bol_rc) {
			m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W DEF_AUX_PIPE failed",
						__LINE__ );
			adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return FALSE;
		}
	}
	if(adsl_contr_1->umc_pending_length > 0) {
		return TRUE;
	}
	struct dsd_svc_rdpdr_message_core_server_device_io_req* adsl_pending_device_io_req = adsl_pending_device->adsc_pending_device_io_req;
	if(adsl_pending_device_io_req == NULL)
		return TRUE;

	if(adsl_aux_pipe_stream->vpc_aux_pipe_handle != NULL)
		return TRUE;
	adsl_pending_device->adsc_pending_device_io_req = NULL;
	
	struct dsd_svc_rdpdr_command dsl_command;
	struct dsd_svc_rdpdr_command_core_device_io_resp* adsl_io_resp = &dsl_command.dsc_message.dsc_core_device_io;
	dsl_command.iec_command = iec_svc_rdpdr_command_core_device_io_resp;
	adsl_io_resp->iec_function = ied_device_io_function_write;
	adsl_io_resp->umc_device_id = adsl_pending_device_io_req->umc_device_id;
	adsl_io_resp->umc_completion_id = adsl_pending_device_io_req->umc_completion_id;
	adsl_io_resp->umc_io_status = HL_STATUS_ERROR_BROKEN_PIPE;
	adsl_io_resp->dsc_function.dsc_write.umc_length = adsl_pending_device_io_req->dsc_function.dsc_write.umc_length;
	return m_rdpdr_send_commands(adsp_output_area_1, &dsl_command, 1);
#endif
	return TRUE;
}


static BOOL m_rdpdr_process_irp_device_control(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_gather_i_1_pos* adsp_pos) {
	struct dsd_clib1_contr_1 *adsl_contr_1 = adsp_output_area_1->adsc_contr_1;
	struct dsd_rdpdr_device_context* adsl_pending_device = adsl_contr_1->adsc_pending_device;
	if(adsl_pending_device->iec_device_type != ied_rdpdr_device_type_printer) {
		m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W unexpected device type %d",
						__LINE__, adsl_pending_device->iec_device_type );
		adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		return FALSE;
	}
	struct dsd_gather_i_1 dsl_pos;
	m_gather_i_1_pos_to_gather(adsp_pos, &dsl_pos);
	struct dsd_gather_i_1 *adsl_gai1_data = &dsl_pos;
	while(adsl_gai1_data != NULL) {
		uint32_t uml_available = adsl_gai1_data->achc_ginp_end-adsl_gai1_data->achc_ginp_cur;
		adsl_contr_1->umc_pending_length -= uml_available;
		if(adsl_contr_1->umc_pending_length <= 0) {
			break;
		}
		adsl_gai1_data = adsl_gai1_data->adsc_next;
	}
	if(adsl_contr_1->umc_pending_length > 0) {
		return TRUE;
	}
	struct dsd_svc_rdpdr_message_core_server_device_io_req* adsl_pending_device_io_req = adsl_pending_device->adsc_pending_device_io_req;
	if(adsl_pending_device_io_req == NULL)
		return TRUE;
	adsl_pending_device->adsc_pending_device_io_req = NULL;

#if SM_USE_PRINTING
	struct dsd_rdpdr_device_context_printer* adsl_pending_printer = (struct dsd_rdpdr_device_context_printer*)adsl_pending_device;
	struct dsd_aux_pipe_stream* adsl_aux_pipe_stream = &adsl_pending_printer->dsc_aux_pipe_stream;
	struct dsd_svc_rdpdr_command dsl_command;
	struct dsd_svc_rdpdr_command_core_device_io_resp* adsl_io_resp = &dsl_command.dsc_message.dsc_core_device_io;
	dsl_command.iec_command = iec_svc_rdpdr_command_core_device_io_resp;
	adsl_io_resp->iec_function = ied_device_io_function_device_io;
	adsl_io_resp->umc_device_id = adsl_pending_device_io_req->umc_device_id;
	adsl_io_resp->umc_completion_id = adsl_pending_device_io_req->umc_completion_id;
	adsl_io_resp->umc_io_status = HL_STATUS_ERROR_NOT_SUPPORTED;
	adsl_io_resp->dsc_function.dsc_device_io.umc_output_buffer_length = 0;
	adsl_io_resp->dsc_function.dsc_device_io.adsc_output_buffer = NULL;
	switch(adsl_pending_device_io_req->dsc_function.dsc_device_control.umc_io_control_code) {
	case 0x00220030:
		if(adsl_aux_pipe_stream->vpc_aux_pipe_handle == NULL) {
			adsl_io_resp->umc_io_status = HL_STATUS_ERROR_BROKEN_PIPE;
			break;
		}
		adsl_io_resp->umc_io_status = 0;
		break;
	default:
		break;
	}

	return m_rdpdr_send_commands(adsp_output_area_1, &dsl_command, 1);
#endif
	return TRUE;
}

static BOOL m_rdpdr_process_irp_close(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_svc_rdpdr_message_core_server_device_io_req* adsp_devio_req) {
	struct dsd_clib1_contr_1 *adsl_contr_1 = adsp_output_area_1->adsc_contr_1;
	struct dsd_rdpdr_device_context* adsl_rdpdr_device =
		adsl_contr_1->adsrc_rdpdr_devices[adsp_devio_req->umc_device_id];

	switch(adsl_rdpdr_device->iec_device_type) {
#if SM_USE_PRINTING
	case ied_rdpdr_device_type_printer:
	{
		struct dsd_rdpdr_device_context_printer* adsl_printer = (struct dsd_rdpdr_device_context_printer*)adsl_rdpdr_device;
		struct dsd_aux_pipe_stream* adsl_aux_pipe_stream = &adsl_printer->dsc_aux_pipe_stream;
		if(adsl_aux_pipe_stream->vpc_aux_pipe_handle == NULL) {
			struct dsd_svc_rdpdr_command dsl_commands;
			struct dsd_svc_rdpdr_command_core_device_io_resp* adsl_io_resp = &dsl_commands.dsc_message.dsc_core_device_io;
			dsl_commands.iec_command = iec_svc_rdpdr_command_core_device_io_resp;
			adsl_io_resp->iec_function = ied_device_io_function_close;
			adsl_io_resp->umc_device_id = adsp_devio_req->umc_device_id;
			adsl_io_resp->umc_completion_id = adsp_devio_req->umc_completion_id;
			adsl_io_resp->umc_io_status = 0;
			return m_rdpdr_send_commands(adsp_output_area_1, &dsl_commands, 1);
		}
		char chrl_temp[5];
		chrl_temp[0] = HL_STREAM_PIPE_CMD_CLOSE_REQ;
		chrl_temp[1] = 0;
		chrl_temp[2] = 0;
		chrl_temp[3] = 0;
		chrl_temp[4] = 0;
		struct dsd_gather_i_1 dsl_head;
		dsl_head.achc_ginp_cur = chrl_temp;
		dsl_head.achc_ginp_end = chrl_temp+5;
		dsl_head.adsc_next = NULL;

		struct dsd_aux_pipe_req_1 dsl_apr1;
		memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
		dsl_apr1.iec_apc = ied_apc_write;        /* write to session        */
		dsl_apr1.vpc_aux_pipe_handle = adsl_aux_pipe_stream->vpc_aux_pipe_handle;  /* handle of aux-pipe */
		dsl_apr1.adsc_gai1_data = &dsl_head;  /* send data             */
		BOOL bol_rc = adsp_output_area_1->amc_aux( adsp_output_area_1->vpc_userfld,
												DEF_AUX_PIPE, /* aux-pipe          */
												&dsl_apr1,  /* aux-pipe request    */
												sizeof(struct dsd_aux_pipe_req_1) );
		if(!bol_rc) {
			m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W DEF_AUX_PIPE failed",
						__LINE__ );
			adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return FALSE;
		}
		adsl_rdpdr_device->dsc_pending_device_io_req = *adsp_devio_req;
		adsl_rdpdr_device->adsc_pending_device_io_req = &adsl_rdpdr_device->dsc_pending_device_io_req;
	}
	break;
#endif /*#SM_USE_PRINTING*/
	default:
		m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W m_wt_rdp_client_1() unexpected device type %d",
			__LINE__, adsl_rdpdr_device->iec_device_type );
		adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		return FALSE;
	}
	return TRUE;
}

static BOOL m_stream_pipe_handle_signal(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_rdpdr_device_context* adsp_device) {
	struct dsd_clib1_contr_1 *adsl_contr_1 = adsp_output_area_1->adsc_contr_1;
	if(adsp_device->iec_device_type != ied_rdpdr_device_type_printer) {
		m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W unexpected device type %d",
						__LINE__, adsp_device->iec_device_type );
		adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		return FALSE;
	}
	static const int INS_MAX_COMMANDS = 8;
	struct dsd_svc_rdpdr_command dsl_commands[INS_MAX_COMMANDS];
	int inl_num_commands = 0;

#if SM_USE_PRINTING
	struct dsd_rdpdr_device_context_printer* adsl_printer = (struct dsd_rdpdr_device_context_printer*)adsp_device;
	struct dsd_aux_pipe_stream* adsl_aux_pipe_stream = &adsl_printer->dsc_aux_pipe_stream;

	struct dsd_aux_pipe_req_1 dsl_apr1;
	memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
	dsl_apr1.iec_apc = ied_apc_state;        /* check state session     */
	dsl_apr1.vpc_aux_pipe_handle = adsl_printer->vpc_aux_pipe_handle;  /* handle of aux-pipe */
	if(dsl_apr1.vpc_aux_pipe_handle == NULL) {
		dsl_apr1.vpc_aux_pipe_handle = adsl_aux_pipe_stream->vpc_aux_pipe_handle;
		if(dsl_apr1.vpc_aux_pipe_handle == NULL) {
			return TRUE;
		}
	}
	BOOL bol_rc = adsp_output_area_1->amc_aux( adsp_output_area_1->vpc_userfld,
													DEF_AUX_PIPE, /* aux-pipe          */
													&dsl_apr1,  /* aux-pipe request    */
													sizeof(struct dsd_aux_pipe_req_1) );
	if(!bol_rc) {
		m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-E DEF_AUX_PIPE failed",
					__LINE__ );
		adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		return FALSE;
	}
	switch(dsl_apr1.iec_aprc) {
	case ied_aprc_new_conn: {
		struct dsd_svc_rdpdr_message_core_server_device_io_req* adsl_pending_device_io_req = adsp_device->adsc_pending_device_io_req;
		if(adsl_pending_device_io_req == NULL
			|| adsl_pending_device_io_req->umc_major_function != IRP_MJ_CREATE)
		{
			m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-E ied_aprc_new_conn failed",
					__LINE__ );
			adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return FALSE;
		}
		adsl_aux_pipe_stream->iec_stream_state = ied_stream_pipe_state_head;
		adsl_aux_pipe_stream->vpc_aux_pipe_handle = dsl_apr1.vpc_aux_pipe_handle;  /* handle of aux-pipe */
		bol_rc = m_aux_timer_handler_remove(&adsl_contr_1->dsc_timer_handler, &adsp_output_area_1->dsc_aux_helper, &adsl_printer->dsc_timer_entry.dsc_base);
		if (bol_rc == FALSE) {                   /* error occured           */
			m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-E m_aux_timer_handler_remove failed",
						__LINE__ );
			adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return FALSE;
		}

		memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
		dsl_apr1.iec_apc = ied_apc_close_listen;  /* close listen, created by create */
		dsl_apr1.vpc_aux_pipe_handle = adsl_printer->vpc_aux_pipe_handle;  /* handle of aux-pipe */
		bol_rc = adsp_output_area_1->amc_aux( adsp_output_area_1->vpc_userfld,
													DEF_AUX_PIPE, /* aux-pipe          */
													&dsl_apr1,  /* aux-pipe request    */
													sizeof(struct dsd_aux_pipe_req_1) );
		if(!bol_rc) {
			m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-E DEF_AUX_PIPE failed",
						__LINE__ );
			adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return FALSE;
		}
		adsl_printer->vpc_aux_pipe_handle = NULL;

		if(inl_num_commands >= INS_MAX_COMMANDS) {
			m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-E MAX_COMMANDS limit reached",
						__LINE__ );
			adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return FALSE;
		}
		char* achl_mime_type = adsp_output_area_1->chrl_work2;
		char* achl_work2_end = adsp_output_area_1->chrl_work2+sizeof(adsp_output_area_1->chrl_work2);
		int iml_mime_type_len = m_cpy_vx_ucs(achl_mime_type, achl_work2_end-achl_mime_type, ied_chs_utf_8,
			&adsl_printer->adsc_conf_printer->dsc_mime_type);

		char chrl_temp[1+4+5+5+5];
		char* achl_temp = chrl_temp;
		achl_temp[0] = HL_STREAM_PIPE_CMD_OPEN_REQ;
		achl_temp[1] = 0;
		achl_temp[2] = 0;
		achl_temp[3] = 0;
		achl_temp[4] = 0;
		achl_temp += 5;
		achl_temp += m_out_nhasn1(achl_temp, 1);
		achl_temp += m_out_nhasn1(achl_temp, HL_HTTP_STREAM_PIPE_OPEN_PROPERTY_CONTENT_TYPE);
		achl_temp += m_out_nhasn1(achl_temp, iml_mime_type_len);
		struct dsd_gather_i_1 dsrl_heads[2];
		dsrl_heads[0].achc_ginp_cur = chrl_temp;
		dsrl_heads[0].achc_ginp_end = achl_temp;
		dsrl_heads[0].adsc_next = &dsrl_heads[1];
		uint32_t uml_total_length = (dsrl_heads[0].achc_ginp_end-dsrl_heads[0].achc_ginp_cur);
		dsrl_heads[1].achc_ginp_cur = achl_mime_type;
		dsrl_heads[1].achc_ginp_end = achl_mime_type+iml_mime_type_len;
		dsrl_heads[1].adsc_next = NULL;
		uml_total_length += dsrl_heads[1].achc_ginp_end - dsrl_heads[1].achc_ginp_cur;
		uml_total_length -= 5;
		chrl_temp[1] = (char)uml_total_length;
		chrl_temp[2] = (char)(uml_total_length>>8);
		chrl_temp[3] = (char)(uml_total_length>>16);
		chrl_temp[4] = (char)(uml_total_length>>24);

		struct dsd_aux_pipe_req_1 dsl_apr1;
		memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
		dsl_apr1.iec_apc = ied_apc_write;        /* write to session        */
		dsl_apr1.vpc_aux_pipe_handle = adsl_aux_pipe_stream->vpc_aux_pipe_handle;  /* handle of aux-pipe */
		dsl_apr1.adsc_gai1_data = &dsrl_heads[0];  /* send data             */
		bol_rc = adsp_output_area_1->amc_aux( adsp_output_area_1->vpc_userfld,
													DEF_AUX_PIPE, /* aux-pipe          */
													&dsl_apr1,  /* aux-pipe request    */
													sizeof(struct dsd_aux_pipe_req_1) );
		if(!bol_rc) {
			m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W DEF_AUX_PIPE failed",
						__LINE__ );
			adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return FALSE;
		}
		break;
	}
	case ied_aprc_idle:
		break;
	case ied_aprc_read_buf: {
		struct dsd_gather_i_1_fifo dsl_fifo;
		m_gather_fifo_init(&dsl_fifo);
		m_gather_fifo_append_list2(&dsl_fifo, dsl_apr1.adsc_gai1_data);
		struct dsd_gather_reader dsl_gather_reader;
		m_gr_init(&dsl_gather_reader, &dsl_fifo);
		struct dsd_gather_i_1_pos dsl_lookahead_pos;
		while(m_gr_has_more(&dsl_gather_reader)) {
			switch(adsl_aux_pipe_stream->iec_stream_state) {
			case ied_stream_pipe_state_head: {
				HL_GR_RET_GOTO(m_gr_begin_lookahead(&dsl_gather_reader, &dsl_lookahead_pos), LBL_FAILED);
				uint8_t inl_cmd;
				HL_GR_RET_GOTO(m_gr_read_uint8(&dsl_gather_reader, &inl_cmd), LBL_INCOMPLETE);
				switch(inl_cmd) {
				case HL_STREAM_PIPE_CMD_OPEN_RESP: {
					uint32_t uml_status;
					HL_GR_RET_GOTO(m_gr_read_uint32_le(&dsl_gather_reader, &uml_status), LBL_INCOMPLETE);
					HL_GR_RET_GOTO(m_gr_end_lookahead(&dsl_gather_reader, &dsl_lookahead_pos), LBL_FAILED);

					struct dsd_svc_rdpdr_message_core_server_device_io_req* adsl_pending_device_io_req = adsp_device->adsc_pending_device_io_req;
					if(adsl_pending_device_io_req == NULL
						|| adsl_pending_device_io_req->umc_major_function != IRP_MJ_CREATE)
					{
						m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-E HL_STREAM_PIPE_CMD_OPEN_RESP failed",
								__LINE__ );
						adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
						return FALSE;
					}
					adsp_device->adsc_pending_device_io_req = NULL;
					struct dsd_svc_rdpdr_command_core_device_io_resp* adsl_io_resp = &dsl_commands[inl_num_commands].dsc_message.dsc_core_device_io;
					dsl_commands[inl_num_commands].iec_command = iec_svc_rdpdr_command_core_device_io_resp;
					adsl_io_resp->iec_function = ied_device_io_function_create;
					adsl_io_resp->umc_device_id = adsl_pending_device_io_req->umc_device_id;
					adsl_io_resp->umc_completion_id = adsl_pending_device_io_req->umc_completion_id;
					adsl_io_resp->umc_io_status = 0;
					adsl_io_resp->dsc_function.dsc_create.umc_file_id = 1;
					adsl_io_resp->dsc_function.dsc_create.ucc_information = 0;
					inl_num_commands++;
					break;
				}
				case HL_STREAM_PIPE_CMD_WRITE_RESP: {
					uint32_t uml_length_total;
					HL_GR_RET_GOTO(m_gr_read_uint32_le(&dsl_gather_reader, &uml_length_total), LBL_INCOMPLETE);
					HL_GR_RET_GOTO(m_gr_end_lookahead(&dsl_gather_reader, &dsl_lookahead_pos), LBL_FAILED);
					if(inl_num_commands >= INS_MAX_COMMANDS) {
						m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-E MAX_COMMANDS limit reached",
									__LINE__ );
						adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
						return FALSE;
					}
					struct dsd_svc_rdpdr_message_core_server_device_io_req* adsl_pending_device_io_req = adsp_device->adsc_pending_device_io_req;
					if(adsl_pending_device_io_req == NULL || adsl_pending_device_io_req->umc_major_function != IRP_MJ_WRITE) {
						m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-E bad IO request",
									__LINE__ );
						adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
						return FALSE;
					}
					adsp_device->adsc_pending_device_io_req = NULL;
					struct dsd_svc_rdpdr_command_core_device_io_resp* adsl_io_resp = &dsl_commands[inl_num_commands].dsc_message.dsc_core_device_io;
					dsl_commands[inl_num_commands].iec_command = iec_svc_rdpdr_command_core_device_io_resp;
					adsl_io_resp->iec_function = ied_device_io_function_write;
					adsl_io_resp->umc_device_id = adsl_pending_device_io_req->umc_device_id;
					adsl_io_resp->umc_completion_id = adsl_pending_device_io_req->umc_completion_id;
					adsl_io_resp->umc_io_status = 0;
					adsl_io_resp->dsc_function.dsc_write.umc_length = uml_length_total;
					inl_num_commands++;
					break;
				}
				case HL_STREAM_PIPE_CMD_CLOSE_RESP: {
					uint32_t uml_status;
					HL_GR_RET_GOTO(m_gr_read_uint32_le(&dsl_gather_reader, &uml_status), LBL_INCOMPLETE);
					HL_GR_RET_GOTO(m_gr_end_lookahead(&dsl_gather_reader, &dsl_lookahead_pos), LBL_FAILED);

					struct dsd_svc_rdpdr_message_core_server_device_io_req* adsl_pending_device_io_req = adsp_device->adsc_pending_device_io_req;
					if(adsl_pending_device_io_req == NULL || adsl_pending_device_io_req->umc_major_function != IRP_MJ_CLOSE) {
						m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-E bad IO request",
									__LINE__ );
						adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
						return FALSE;
					}
					adsp_device->adsc_pending_device_io_req = NULL;
					
					memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
					dsl_apr1.iec_apc = ied_apc_close_conn;  /* free passed read buffers */
					dsl_apr1.vpc_aux_pipe_handle = adsl_aux_pipe_stream->vpc_aux_pipe_handle;  /* handle of aux-pipe */
					bol_rc = adsp_output_area_1->amc_aux( adsp_output_area_1->vpc_userfld,
																DEF_AUX_PIPE, /* aux-pipe          */
																&dsl_apr1,  /* aux-pipe request    */
																sizeof(struct dsd_aux_pipe_req_1) );
					if(!bol_rc) {
						m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W DEF_AUX_PIPE failed",
									__LINE__ );
						adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
						return FALSE;
					}
					adsl_aux_pipe_stream->vpc_aux_pipe_handle = NULL;
					
					struct dsd_svc_rdpdr_command_core_device_io_resp* adsl_io_resp = &dsl_commands[inl_num_commands].dsc_message.dsc_core_device_io;
					dsl_commands[inl_num_commands].iec_command = iec_svc_rdpdr_command_core_device_io_resp;
					adsl_io_resp->iec_function = ied_device_io_function_close;
					adsl_io_resp->umc_device_id = adsl_pending_device_io_req->umc_device_id;
					adsl_io_resp->umc_completion_id = adsl_pending_device_io_req->umc_completion_id;
					adsl_io_resp->umc_io_status = 0;
					inl_num_commands++;
					goto LBL_CONTINUE;
				}
				default:
					m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-E AUX-PIPE-STREAM unexpected command %d",
							__LINE__, inl_cmd );
					adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
					return FALSE;
				}
				break;
			}
			default:
				m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W AUX-PIPE-STREAM unexpected state %d",
							__LINE__, adsl_aux_pipe_stream->iec_stream_state );
				adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
				return FALSE;
			}
		}
		struct dsd_gather_i_1* adsl_rest = m_gather_i_1_skip_processed(dsl_apr1.adsc_gai1_data);
		if(adsl_rest != NULL)
			goto LBL_INCOMPLETE;

		memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
		dsl_apr1.iec_apc = ied_apc_free_read_buffer;  /* free passed read buffers */
		dsl_apr1.vpc_aux_pipe_handle = adsl_aux_pipe_stream->vpc_aux_pipe_handle;  /* handle of aux-pipe */
		bol_rc = adsp_output_area_1->amc_aux( adsp_output_area_1->vpc_userfld,
													DEF_AUX_PIPE, /* aux-pipe          */
													&dsl_apr1,  /* aux-pipe request    */
													sizeof(struct dsd_aux_pipe_req_1) );
		if(!bol_rc) {
			m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W DEF_AUX_PIPE failed",
						__LINE__ );
			adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return FALSE;
		}
		}
LBL_CONTINUE:
		break;
LBL_FAILED:
		m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W DEF_AUX_PIPE protocol error",
					__LINE__ );
		adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		return FALSE;
LBL_INCOMPLETE:
		break;
	case ied_aprc_conn_ended: {
		if(!m_rdpdr_device_cleanup_printer(adsp_output_area_1, adsl_printer)) {
			return FALSE;
		}
		break;
	}
	default:
		m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W DEF_AUX_PIPE unsupported ied_apc_state %d",
					__LINE__, dsl_apr1.iec_aprc );
		adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		return FALSE;
	}
#endif
	return m_rdpdr_send_commands(adsp_output_area_1, dsl_commands, inl_num_commands);
}

static BOOL m_rdpdr_send_commands(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_svc_rdpdr_command* adsp_commands, int inp_num_commands) {
	struct dsd_svc_command_result dsl_cmd_result;
	int inl_res = m_svc_rdpdr_process_commands(&adsp_output_area_1->adsc_contr_1->dsc_svc_rdpdr, &adsp_output_area_1->dsc_aux_helper, adsp_commands, inp_num_commands, &dsl_cmd_result);
	if(inl_res < 0) {
		m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W m_wt_rdp_client_1() m_svc_rdpdr_process_commands failed",
						__LINE__ );
		adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		return FALSE;
	}
	if(dsl_cmd_result.adsc_vc_out_first != NULL) {
		*adsp_output_area_1->aadsc_cc_co1_ch = dsl_cmd_result.adsc_vc_out_first;     /* append to chain         */
		adsp_output_area_1->aadsc_cc_co1_ch = &dsl_cmd_result.adsc_vc_out_last->adsc_next;  /* position chain of client commands, input */
	}
	return TRUE;
}
#endif /*SM_RDPDR_CHANNEL*/

#if SM_RAIL_CHANNEL
static BOOL m_rail_send_commands(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_svc_rail_command* adsp_commands, int inp_num_commands) {
	struct dsd_workarea_allocator* adsl_wa_alloc = &adsp_output_area_1->dsc_wa_alloc_extern;
	struct dsd_svc_command_result dsl_cmd_result;
	int inl_res = m_svc_rail_process_commands(&adsp_output_area_1->adsc_contr_1->dsc_svc_rail, adsl_wa_alloc, adsp_commands, inp_num_commands, &dsl_cmd_result);
	if(inl_res < 0) {
		m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-W m_wt_rdp_client_1() m_svc_rail_process_commands failed",
						__LINE__ );
		adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		return FALSE;
	}
	if(dsl_cmd_result.adsc_vc_out_first != NULL) {
		*adsp_output_area_1->aadsc_cc_co1_ch = dsl_cmd_result.adsc_vc_out_first;     /* append to chain         */
		adsp_output_area_1->aadsc_cc_co1_ch = &dsl_cmd_result.adsc_vc_out_last->adsc_next;  /* position chain of client commands, input */
	}
	return TRUE;
}

static BOOL m_rail_start_remote_app(struct dsd_sdh_call_1* adsp_output_area_1, struct dsd_clib_conf_remote_app& dsl_remote_app) {
	// TODO:
	struct dsd_svc_rail_command dsrl_commands[1];
	int inl_num_commands = 0;
	struct dsd_gather_i_1 dsrl_tmp_gathers[3];
		
	//dsd_const_string dsl_appname(((char*)adsl_sid_data)+adsp_remoteapp->dsc_exe_or_file.inc_offset, adsp_remoteapp->dsc_exe_or_file.inc_length);
	//dsd_const_string dsl_workdir(((char*)adsl_sid_data)+adsp_remoteapp->dsc_working_dir.inc_offset, adsp_remoteapp->dsc_working_dir.inc_length);
	//dsd_const_string dsl_arguments(((char*)adsl_sid_data)+adsp_remoteapp->dsc_arguments.inc_offset, adsp_remoteapp->dsc_arguments.inc_length);
	//static const wchar_t APP_NAME[] = L"||Notepad";
	int inl_appname_len = m_len_vx_ucs(ied_chs_le_utf_16, &dsl_remote_app.dsc_exe_or_file);
	if(inl_appname_len < 0) {
		m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-E m_len_vx_vx failed",
                  __LINE__ );
		adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
		return FALSE;
	}
	int inl_workdir_len = m_len_vx_ucs(ied_chs_le_utf_16, &dsl_remote_app.dsc_working_dir);
	if(inl_workdir_len < 0) {
		m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-E m_len_vx_vx failed",
                  __LINE__ );
		adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
		return FALSE;
	}
	int inl_args_len = m_len_vx_ucs(ied_chs_le_utf_16, &dsl_remote_app.dsc_arguments);
	if(inl_args_len < 0) {
		m_sdh_printf( adsp_output_area_1, "xl-webterm-rdp-01-l%05d-E m_len_vx_vx failed",
                  __LINE__ );
		adsp_output_area_1->adsc_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
		return FALSE;
	}

	struct dsd_svc_rail_order_exec* adsl_order = &dsrl_commands[inl_num_commands].dsc_order.dsc_exec;
	dsrl_commands[inl_num_commands].usc_order_type = TS_RAIL_ORDER_EXEC;
	memset(adsl_order, 0, sizeof(struct dsd_svc_rail_order_exec));
	adsl_order->usc_flags = dsl_remote_app.usc_flags;
	adsl_order->usc_exe_or_file_length = inl_appname_len << 1;
	adsl_order->usc_working_dir_length = inl_workdir_len << 1;
	adsl_order->usc_arguments_length = inl_args_len << 1;

	int inl_len_bytes = m_len_bytes_ucs_no_zero(&dsl_remote_app.dsc_exe_or_file);
	dsrl_tmp_gathers[0].achc_ginp_cur = (char*)dsl_remote_app.dsc_exe_or_file.ac_str;
	dsrl_tmp_gathers[0].achc_ginp_end = dsrl_tmp_gathers[0].achc_ginp_cur + inl_len_bytes;
	dsrl_tmp_gathers[0].adsc_next = NULL;
	adsl_order->dsc_exe_or_file.iec_chs_str = dsl_remote_app.dsc_exe_or_file.iec_chs_str;
	adsl_order->dsc_exe_or_file.imc_len_str = dsl_remote_app.dsc_exe_or_file.imc_len_str;
	adsl_order->dsc_exe_or_file.dsc_data.achc_pos = dsrl_tmp_gathers[0].achc_ginp_cur;
	adsl_order->dsc_exe_or_file.dsc_data.adsc_gather = &dsrl_tmp_gathers[0];

	inl_len_bytes = m_len_bytes_ucs_no_zero(&dsl_remote_app.dsc_working_dir);
	dsrl_tmp_gathers[1].achc_ginp_cur = (char*)dsl_remote_app.dsc_working_dir.ac_str;
	dsrl_tmp_gathers[1].achc_ginp_end = dsrl_tmp_gathers[1].achc_ginp_cur + inl_len_bytes;
	dsrl_tmp_gathers[1].adsc_next = NULL;
	adsl_order->dsc_working_dir.iec_chs_str = dsl_remote_app.dsc_working_dir.iec_chs_str;
	adsl_order->dsc_working_dir.imc_len_str = dsl_remote_app.dsc_working_dir.imc_len_str;
	adsl_order->dsc_working_dir.dsc_data.achc_pos = dsrl_tmp_gathers[1].achc_ginp_cur;
	adsl_order->dsc_working_dir.dsc_data.adsc_gather = &dsrl_tmp_gathers[1];

	inl_len_bytes = m_len_bytes_ucs_no_zero(&dsl_remote_app.dsc_arguments);
	dsrl_tmp_gathers[2].achc_ginp_cur = (char*)dsl_remote_app.dsc_arguments.ac_str;
	dsrl_tmp_gathers[2].achc_ginp_end = dsrl_tmp_gathers[2].achc_ginp_cur + inl_len_bytes;
	dsrl_tmp_gathers[2].adsc_next = NULL;
	adsl_order->dsc_arguments.iec_chs_str = dsl_remote_app.dsc_arguments.iec_chs_str;
	adsl_order->dsc_arguments.imc_len_str = dsl_remote_app.dsc_arguments.imc_len_str;
	adsl_order->dsc_arguments.dsc_data.achc_pos = dsrl_tmp_gathers[2].achc_ginp_cur;
	adsl_order->dsc_arguments.dsc_data.adsc_gather = &dsrl_tmp_gathers[2];

	inl_num_commands++;
	if(!m_rail_send_commands(adsp_output_area_1, dsrl_commands, inl_num_commands))
		return FALSE;
	return TRUE;
}
#endif

#if DVC_GRAPHICS
static struct dsd_channel_context* m_dynvc_create_graphics(struct dsd_dynvc_create_listener* avop_this, struct dsd_dynvc_create_context* adsp_context) {
	 struct dsd_clib1_contr_1 *adsl_contr_1 = (struct dsd_clib1_contr_1 *)avop_this->avoc_context;
	 m_init_dvc_graphics(adsp_context->adsc_drdynvc, &adsl_contr_1->dsc_dvc_graphics_ex);
	 return &adsl_contr_1->dsc_dvc_graphics_ex.dsc_common.dsc_channel_context;
}
#endif

#if CV_TOUCH_REDIR
static struct dsd_channel_context* m_dynvc_create_input(struct dsd_dynvc_create_listener* avop_this, struct dsd_dynvc_create_context* adsp_context) {
	 struct dsd_clib1_contr_1 *adsl_contr_1 = (struct dsd_clib1_contr_1 *)avop_this->avoc_context;
	 m_init_rdpei(adsp_context->adsc_drdynvc, &adsl_contr_1->dsc_dvc_input_ex);
	 return &adsl_contr_1->dsc_dvc_input_ex.dsc_common.dsc_channel_context;
}
#endif

#if SM_DYNVC_DISP
static BOOL m_send_websocket_rdp_monitor_layout_support(struct dsd_sdh_call_1* adsp_output_area_1, BOOL bop_support) {
	struct dsd_wt_record_1 DSL_WTR1_G;
	int iml2 = 1;
	struct dsd_gather_i_1 dsl_gather_head;

	struct dsd_hl_clib_1* adsl_hl_clib_1 = adsp_output_area_1->adsc_hl_clib_1;
	DSL_WTR1_G.ucc_record_type = ie_wtsc_rdp_monitor_layout_support;     /* record type             */
	if ((adsp_output_area_1->achc_upper - adsp_output_area_1->achc_lower) < iml2) {  /* need buffer */
		BOOL bol_rc = m_get_new_workarea( adsp_output_area_1 );
		if (bol_rc == FALSE) {
			adsl_hl_clib_1->inc_return = DEF_IRET_ERRAU;
			return FALSE;
		}
	}
	dsl_gather_head.achc_ginp_cur = adsp_output_area_1->achc_lower;
	dsl_gather_head.achc_ginp_cur[0] = bop_support;
	adsp_output_area_1->achc_lower += iml2;
	dsl_gather_head.achc_ginp_end = adsp_output_area_1->achc_lower;
	dsl_gather_head.adsc_next = NULL;
	DSL_WTR1_G.adsc_gai1_data = &dsl_gather_head;  /* output data be be sent to client */
	BOOL bol_rc = m_send_websocket_data( adsp_output_area_1, adsp_output_area_1->adsc_contr_1, &DSL_WTR1_G );
	if (bol_rc == FALSE) {                   /* error occured           */
		adsl_hl_clib_1->inc_return = DEF_IRET_ERRAU;
		return FALSE;
	}
	return TRUE;
}

static enum ied_dynvc_result m_dynvc_handle_disp_event_ex(void* avop_this, enum ied_dynvc_msg_type iep_type, struct dsd_dynvc_listener_event* adsp_event) {
	struct dsd_dvc_disp_ex* adsl_dvc_disp = (struct dsd_dvc_disp_ex*)avop_this;
	struct dsd_dynvc_command2* adsl_dynvc_command2 = (struct dsd_dynvc_command2*)adsp_event->adsc_dynvc_command;
	switch(iep_type) {
	case ied_create:
		if(!m_send_websocket_rdp_monitor_layout_support(adsl_dynvc_command2->adsc_output_area_1, TRUE))
			return ied_error;
		break;
	case ied_close:
		if(!m_send_websocket_rdp_monitor_layout_support(adsl_dynvc_command2->adsc_output_area_1, FALSE))
			return ied_error;
		break;
	}
	return adsl_dvc_disp->dsc_super.m_receive(adsl_dvc_disp->dsc_super.avoc_context, iep_type, adsp_event);
}

static struct dsd_channel_context* m_dynvc_create_disp(struct dsd_dynvc_create_listener* avop_this, struct dsd_dynvc_create_context* adsp_context) {
	 struct dsd_clib1_contr_1 *adsl_contr_1 = (struct dsd_clib1_contr_1 *)avop_this->avoc_context;
	 struct dsd_dvc_disp_ex* adsl_dvc_disp = &adsl_contr_1->dsc_dvc_disp;
	 m_init_dvc_disp(adsp_context->adsc_drdynvc, &adsl_dvc_disp->dsc_dvc);
	 adsl_dvc_disp->dsc_super = adsl_dvc_disp->dsc_dvc.dsc_common.dsc_channel_context.dsc_listener;
	 adsl_dvc_disp->dsc_dvc.dsc_common.dsc_channel_context.dsc_listener.avoc_context = adsl_dvc_disp;
	 adsl_dvc_disp->dsc_dvc.dsc_common.dsc_channel_context.dsc_listener.m_receive = m_dynvc_handle_disp_event_ex;
	 return &adsl_dvc_disp->dsc_dvc.dsc_common.dsc_channel_context;
}

static BOOL m_monitor_layout_changed(struct dsd_sdh_call_1* adsp_output_area_1, const char* achl_w1, int iml_len_payload) {
	struct dsd_gather_i_1 dsl_payload;
	dsl_payload.achc_ginp_cur = (char*)achl_w1;
	dsl_payload.achc_ginp_end = (char*)achl_w1 + iml_len_payload;
	dsl_payload.adsc_next = NULL;
	struct dsd_gather_i_1_fifo dsl_fifo;
	m_gather_fifo_init(&dsl_fifo);
	m_gather_fifo_append_list(&dsl_fifo, &dsl_payload, &dsl_payload);
	struct dsd_gather_reader dsl_gather_reader;
	m_gr_init(&dsl_gather_reader, &dsl_fifo);

	{
		struct dsd_dvc_input_command dsl_cmd;
		struct dsd_monitor_def_ex dsrl_monitors[32];
		dsl_cmd.umc_command = DVC_DISP_DISPLAYCONTROL_PDU_TYPE_MONITOR_LAYOUT;
		if(!m_gr_read_hasn1_uint32_be(&dsl_gather_reader, &dsl_cmd.dsc_monitor_layout.umc_num_monitors))
			return FALSE;
		if(dsl_cmd.dsc_monitor_layout.umc_num_monitors > 32)
			return FALSE;
		for(uint32_t uml_m=0; uml_m<dsl_cmd.dsc_monitor_layout.umc_num_monitors; uml_m++) {
			HL_GR_RET_GOTO(m_gr_read_hasn1_uint32_be(&dsl_gather_reader, &dsrl_monitors[uml_m].imc_flags), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_hasn1_sint32_be(&dsl_gather_reader, &dsrl_monitors[uml_m].imc_left), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_hasn1_sint32_be(&dsl_gather_reader, &dsrl_monitors[uml_m].imc_top), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_hasn1_uint32_be(&dsl_gather_reader, &dsrl_monitors[uml_m].imc_width), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_hasn1_uint32_be(&dsl_gather_reader, &dsrl_monitors[uml_m].imc_height), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_hasn1_uint32_be(&dsl_gather_reader, &dsrl_monitors[uml_m].imc_physical_width), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_hasn1_uint32_be(&dsl_gather_reader, &dsrl_monitors[uml_m].imc_physical_height), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_hasn1_uint32_be(&dsl_gather_reader, &dsrl_monitors[uml_m].imc_orientation), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_hasn1_uint32_be(&dsl_gather_reader, &dsrl_monitors[uml_m].imc_desktop_scale_factor), LBL_READ_INCOMPLETE);
			HL_GR_RET_GOTO(m_gr_read_hasn1_uint32_be(&dsl_gather_reader, &dsrl_monitors[uml_m].imc_device_scale_factor), LBL_READ_INCOMPLETE);
		}
		dsl_cmd.dsc_monitor_layout.adsrc_monitors = dsrl_monitors;

		struct dsd_dvc_disp_ex* adsl_dvc_disp = &adsp_output_area_1->adsc_contr_1->dsc_dvc_disp;
		if(adsl_dvc_disp->dsc_dvc.dsc_common.adsc_svc == NULL) {
			return FALSE;
		}

		struct dsd_workarea_allocator* adsl_wa_alloc = &adsp_output_area_1->dsc_wa_alloc_extern;
		struct dsd_gather_i_1_fifo dsl_edisp_fifo_out;
		m_gather_fifo_init(&dsl_edisp_fifo_out);
		int inl_ret = m_dvc_disp_process_command(&adsl_dvc_disp->dsc_dvc, adsl_wa_alloc,
			&dsl_cmd, &dsl_edisp_fifo_out);
		if(inl_ret != 0)
			return FALSE;

		struct dsd_gather_i_1_fifo dsl_dynvc_fifo_out;
		m_gather_fifo_init(&dsl_dynvc_fifo_out);
		struct dsd_dynvc_client_command2 dsl_cmd2;
		dsl_cmd2.adsc_channel = &adsl_dvc_disp->dsc_dvc.dsc_common.dsc_channel_context;
		dsl_cmd2.umc_payload_length = m_gather_i_1_count_data_len(dsl_edisp_fifo_out.adsc_first);
		dsl_cmd2.adsc_payload = dsl_edisp_fifo_out.adsc_first;
		int inl_dynvc_len_out = m_svc_dynvc_send_data2(&adsp_output_area_1->adsc_contr_1->dsc_svc_drdynvc, &adsp_output_area_1->dsc_aux_helper,
			&dsl_cmd2, &dsl_dynvc_fifo_out);
		if(inl_dynvc_len_out < 0)
			return FALSE;

		struct dsd_cc_co1* adsl_command = (struct dsd_cc_co1*)m_wa_allocator_alloc_lower(adsl_wa_alloc,
			sizeof(struct dsd_cc_co1) + sizeof(struct dsd_rdp_vch_io), HL_ALIGNOF(struct dsd_rdp_vch_io));
		if (adsl_command == NULL) {
			return FALSE;
		}
		struct dsd_rdp_vch_io* adsl_dynvc_io = (struct dsd_rdp_vch_io*)(adsl_command + 1);

		adsl_command->iec_cc_command = ied_ccc_vch_out;
		adsl_command->adsc_next = NULL;
		adsl_dynvc_io->adsc_gai1_data = dsl_dynvc_fifo_out.adsc_first;
		adsl_dynvc_io->umc_vch_ulen = inl_dynvc_len_out;
		memset(adsl_dynvc_io->chrc_vch_flags, 0, sizeof(adsl_dynvc_io->chrc_vch_flags));
		adsl_dynvc_io->chrc_vch_flags[0] = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST;
		adsl_dynvc_io->adsc_rdp_vc_1 = adsp_output_area_1->adsc_contr_1->adsp_rdpacc_drdynvc;

		// append to chain
		*adsp_output_area_1->aadsc_cc_co1_ch = adsl_command;
		// position chain of client commands, input
		adsp_output_area_1->aadsc_cc_co1_ch = &adsl_command->adsc_next;

		return TRUE;
	}
LBL_READ_INCOMPLETE:
	m_gather_fifo_destroy(&dsl_fifo);
	return FALSE;
}
#endif

#if SM_USE_CLIENT_PARAMS
static int m_parse_webterm_client_params(struct dsd_aux_helper* adsp_aux_helper, char* achl_w1, int iml_len_payload, struct dsd_webterm_client_params* adsp_params) {
	struct dsd_aux_helper& dsl_output_area_1 = *adsp_aux_helper;
	char* achl_w2 = achl_w1;
	char* achl_w3 = achl_w1 + iml_len_payload;     /* end of input area       */
	char* achl_w4;
	char* achl_w5;
	char* achl_w6;
	int iml1;
	int iml2;
	int* aiml_w1;
	const struct dsd_parameter* adsl_param;

	p_webso_20:                              /* scan string from WS-JS  */
   if (achl_w2 >= achl_w3) {
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" - invalid 01",
                   __LINE__, iml_len_payload, achl_w1 );
#ifdef PROBLEM_KB_140210
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T achl_w1=%p achl_w2=%p achl_w3=%p.",
                   __LINE__, achl_w1, achl_w2, achl_w3 );
     goto p_webso_28;                       /* found values            */
#endif
     return DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
   }
   achl_w4 = (char *) memchr( achl_w2, '=', achl_w3 - achl_w2 );
   if (achl_w4 == NULL) {                   /* separator not found     */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" - pos %d no equals - invalid 02",
                   __LINE__, iml_len_payload, achl_w1, achl_w2 - achl_w1 );
     return DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
   }
   iml1 = achl_w4 - achl_w2;                /* length of keyword       */
   iml2 = sizeof(dss_wt_js_first) / sizeof(dss_wt_js_first[0]);
   do {
	   if (   (dss_wt_js_first[ iml2 - 1 ].inc_len == iml1)
		   && (!memcmp( dss_wt_js_first[ iml2 - 1 ].achc_name, achl_w2, iml1 ))) {
       break;
     }
     iml2--;                                /* decrement index         */
   } while (iml2 > 0);
   if (iml2 == 0) {                         /* parameter not found     */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" - pos %d keyword not recognized - invalid 03",
                   __LINE__, iml_len_payload, achl_w1, achl_w2 - achl_w1 );
     return DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
   }

   switch (iml2) {
     case (0 + 1):
       aiml_w1 = &adsp_params->iml_wt_js_version;        /* version of WT JS client */
       break;
     case (1 + 1):
       aiml_w1 = &adsp_params->imc_wt_js_width;  /* WT-JS screen width */
       break;
     case (2 + 1):
       aiml_w1 = &adsp_params->imc_wt_js_height;  /* WT-JS screen height */
       break;
#ifdef CV_KEYBOARD
     case (3 + 1):
       aiml_w1 = &adsp_params->imc_wt_js_locale_id;          /* WT-JS locale id          */
       break;
     case (4 + 1):
	    achl_w5 = achl_w4 + 1;                  /* WT-JS useragent          */
	    achl_w6 = achl_w3;
       break;
     case (5 + 1):
	    achl_w5 = achl_w4 + 1;                  /* WT-JS platform          */
	    achl_w6 = achl_w3;
       break;
#endif /* CV_KEYBOARD */
#if SM_USE_NLA
     case (6 + 1):
     case (7 + 1):
     case (8 + 1):
	    achl_w5 = achl_w4 + 1;                  /* WT-JS platform          */
	    achl_w6 = achl_w3;
       break;
#endif
     default:
       return DEF_IRET_INT_ERROR;  /* internal error occured */
   }

#ifdef CV_KEYBOARD
   if (iml2 < 5) {
#endif
   if (*aiml_w1 > 0) {
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" - pos %d keyword no %d double - invalid 04",
                   __LINE__, iml_len_payload, achl_w1, achl_w2 - achl_w1 );
     return DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
   }
#ifdef CV_KEYBOARD
   }
#endif

   achl_w4++;                               /* after equals            */
   if (achl_w4 >= achl_w3) {
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" - pos %d keyword no %d no value - invalid 05",
                   __LINE__, iml_len_payload, achl_w1, achl_w2 - achl_w1 );
     return DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
   }
   iml1 = 0;
   adsl_param = &dss_wt_js_first[ iml2 - 1 ];
#ifdef CV_KEYBOARD
   switch(adsl_param->iec_type) {
   case iec_parameter_type_integer:
	   while (achl_w4 < achl_w3) {
		   if(*achl_w4 == CHAR_CR && ((achl_w4+1) < achl_w3) && (*(achl_w4+1) == CHAR_LF))
			   break;
			iml1 *= 10;
			iml1 += *achl_w4 - '0';
		   achl_w4++;
	   }
	   break;
   case iec_parameter_type_utf8_string:
	   while (achl_w4 < achl_w3) {
		   if(*achl_w4 == CHAR_CR && ((achl_w4+1) < achl_w3) && (*(achl_w4+1) == CHAR_LF))
			   break;
			if (achl_w5 >= achl_w6) {
				m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client - parameter %d length exceeded (limit %d)",
                   __LINE__, iml2 - 1, iml1 );
			   return DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
			}
#if 0
			*achl_w5 = *achl_w4;
			achl_w5++;
#endif
			iml1++;
			achl_w4++;
	   }
	   break;
   }
   switch(iml2) {
   case 5: /* User Agent */
	   *achl_w5 = 0;
	   m_parse_user_agent(&adsp_params->dsc_browser_data, achl_w5 - iml1);
	   break;
   case 6: /* Platform */
	   *achl_w5 = 0;
	   m_parse_platform(&adsp_params->dsc_browser_data, achl_w5 - iml1);
	   break;
#if SM_USE_NLA
   case 7: /* UserId */
	   adsp_params->dsl_client_userid.iec_chs_str = ied_chs_utf_8;
	   adsp_params->dsl_client_userid.ac_str = achl_w5;
	   adsp_params->dsl_client_userid.imc_len_str = iml1;
       //m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-I received user id '%.*s'",
       //    __LINE__, dsl_client_userid.imc_len_str, dsl_client_userid.ac_str );
	   break;
   case 8: /* Password */
	   adsp_params->dsl_client_password.iec_chs_str = ied_chs_utf_8;
	   adsp_params->dsl_client_password.ac_str = achl_w5;
	   adsp_params->dsl_client_password.imc_len_str = iml1;
	   //m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-I received password",
       //    __LINE__ );
	   break;
   case 9: /* Domain */
	   adsp_params->dsl_client_domain.iec_chs_str = ied_chs_utf_8;
	   adsp_params->dsl_client_domain.ac_str = achl_w5;
	   adsp_params->dsl_client_domain.imc_len_str = iml1;
	   //m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-I received domain '%.*s'",
       //    __LINE__, dsl_client_domain.imc_len_str, dsl_client_domain.ac_str );
	   break;
#endif
   }

#else /* NOT CV_KEYBOARD */
   while (   (achl_w4 < achl_w3)
          && ((*achl_w4 >= '0') && (*achl_w4 <= '9'))) {
     iml1 *= 10;
     iml1 += *achl_w4 - '0';
     achl_w4++;
   }
#endif /* CV_KEYBOARD */

#ifdef CV_KEYBOARD
   if (iml2 < 5) {
#endif
   if (iml1 < 0) {
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" - pos %d keyword no %d value invalid - invalid 06",
                   __LINE__, iml_len_payload, achl_w1, achl_w2 - achl_w1 );
     return DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
   }
   *aiml_w1 = iml1;
#ifdef CV_KEYBOARD
   } else {
     achl_w5 = '\0';
   }
#endif

   if (achl_w4 >= achl_w3) {                /* end of string           */
     goto p_webso_28;                       /* found values            */
   }

#ifdef CV_KEYBOARD
   if (*achl_w4 != CHAR_CR && *(achl_w4+1) != CHAR_LF) {                   /* separator invalid       */
#else /* NOT CV_KEYBOARD */
   if (*achl_w4 != ' ') {                   /* separator invalid       */
#endif   
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" - pos %d invalid separator 0X%02X - invalid 06",
                   __LINE__, iml_len_payload, achl_w1, achl_w4 - achl_w1, (unsigned char) *achl_w4 );
     return DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
   }

#ifdef CV_KEYBOARD
   achl_w2 = achl_w4 + 2;                   /* next keyword            */
#else
   achl_w2 = achl_w4 + 1;                   /* next keyword            */
#endif
   goto p_webso_20;                         /* scan string from WS-JS  */

   p_webso_28:                              /* found values            */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T command 0X20 version=%d width=%d height=%d.",
                 __LINE__, iml_wt_js_version, adsl_contr_1->imc_wt_js_width, adsl_contr_1->imc_wt_js_height );
#endif
   if (adsp_params->iml_wt_js_version < 0) {             /* version of WT JS client */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" no version= - invalid 07",
                   __LINE__, iml_len_payload, achl_w1 );
     return DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
   }
   if (adsp_params->iml_wt_js_version != HL_WT_JS_VERSION) {  /* version of WT JS client */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" version=%d but requested=%d - invalid 08",
                   __LINE__, iml_len_payload, achl_w1, adsp_params->iml_wt_js_version, HL_WT_JS_VERSION );
     return DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
   }
   if (adsp_params->imc_wt_js_width <= 0) {  /* WT-JS screen width    */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" no width= - invalid 09",
                   __LINE__, iml_len_payload, achl_w1 );
     return DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
   }
   if (adsp_params->imc_wt_js_height <= 0) {  /* WT-JS screen height  */
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" no height= - invalid 10",
                   __LINE__, iml_len_payload, achl_w1 );
     return DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
   }
#ifdef CV_KEYBOARD
   if (adsp_params->imc_wt_js_locale_id == 0 && 
       adsp_params->imc_default_locale > 0)
   {
       adsp_params->imc_wt_js_locale_id = adsp_params->imc_default_locale;    
   }
   if (adsp_params->imc_wt_js_locale_id <= 0) {  /* WT-JS keyboard locale id  */    
     m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-E received from WT-JS client \"%.*s\" no locale id = - invalid 11",
                   __LINE__, iml_len_payload, achl_w1 );
     return DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
   }
#endif /* CV_KEYBOARD */
	return DEF_IRET_NORMAL;
}
#endif /*SM_USE_CLIENT_PARAMS*/
