

/**
  hob-rdpclient1.h
  Header-File for RDP-Accelerator / RDP-Client
  Copyright (C) HOB Germany 2008
  Copyright (C) HOB Germany 2009
  Copyright (C) HOB Germany 2012
  Copyright (C) HOB Germany 2013
  Copyright (C) HOB Germany 2014
  Copyright (C) HOB Germany 2015
  Copyright (C) HOB Germany 2016
  Copyright (C) HOB Germany 2017
  27.12.08 KB
*/
/**
  in the calling program, the following header-files need to be included:
    #include "hrc4cons.h"
    #include "hsha.h"
    #include "hmd5.h"
    #include "hob-cdrdef1.h"
*/
#if 0
//-------------------------------------------------------------
// Interface structure definition for Server Interface,
// Revised Version (Configuration Parameters removed)
//-------------------------------------------------------------
#endif

#if 0
// Caller Function codes
#endif

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

#define HL_RDP_ACC_DEF

#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif

#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif

#define INFO_MOUSE                       0X00000001
#define INFO_DISABLECTRLALTDEL           0X00000002
#define INFO_AUTOLOGON                   0X00000008
#define INFO_UNICODE                     0X00000010
#define INFO_MAXIMIZESHELL               0X00000020
#define INFO_LOGONNOTIFY                 0X00000040
#define INFO_COMPRESSION                 0X00000080
#define INFO_ENABLEWINDOWSKEY            0X00000100
#define INFO_REMOTECONSOLEAUDIO          0X00002000
#define INFO_FORCE_ENCRYPTED_CS_PDU      0X00004000
#define INFO_RAIL                        0X00008000
#define INFO_LOGONERRORS                 0X00010000
#define INFO_MOUSE_HAS_WHEEL             0X00020000
#define INFO_PASSWORD_IS_SC_PIN          0X00040000
#define INFO_NOAUDIOPLAYBACK             0X00080000
#define INFO_USING_SAVED_CREDS           0X00100000
#define RNS_INFO_AUDIOCAPTURE            0X00200000
#define RNS_INFO_VIDEO_DISABLE           0X00400000
#define INFO_RESERVED1                   0X00800000 // Unused as of 20.12.2016
#define INFO_HIDEF_RAIL_SUPPORTED        0x02000000

#define PERF_DISABLE_WALLPAPER           0X00000001
#define PERF_DISABLE_FULLWINDOWDRAG      0X00000002
#define PERF_DISABLE_MENUANIMATIONS      0X00000004
#define PERF_DISABLE_THEMING             0X00000008
#define PERF_DISABLE_CURSOR_SHADOW       0X00000020
#define PERF_DISABLE_CURSORSETTINGS      0X00000040
#define PERF_ENABLE_FONT_SMOOTHING       0X00000080
#define PERF_ENABLE_DESKTOP_COMPOSITION  0X00000100

#define LEN_ARC_SC_PRIVATE_PACKET        0X001C

// 2.2.1.1.1 RDP Negotiation Request (RDP_NEG_REQ)
// flags:
#define RESTRICTED_ADMIN_MODE_REQUIRED          0x01
#define REDIRECTED_AUTHENTICATION_MODE_REQUIRED 0x02
#define CORRELATION_INFO_PRESENT                0x08
// requestedProtocols:
#define PROTOCOL_RDP        0x00000000
#define PROTOCOL_SSL        0x00000001
#define PROTOCOL_HYBRID     0x00000002
#define PROTOCOL_HYBRID_EX  0x00000008

#define D_CHANNEL_OPTION_INITIALIZED   0x80000000   // Absence of this flag indicates that this channel is a placeholder and that the server MUST NOT set it up.
#define D_CHANNEL_OPTION_ENCRYPT_RDP   0x40000000   // This flag is unused and its value MUST be ignored by the server.
#define D_CHANNEL_OPTION_ENCRYPT_SC    0x20000000   // This flag is unused and its value MUST be ignored by the server.
#define D_CHANNEL_OPTION_ENCRYPT_CS    0x10000000   // This flag is unused and its value MUST be ignored by the server.
#define D_CHANNEL_OPTION_PRI_HIGH      0x08000000   // Channel data MUST be sent with high MCS priority.
#define D_CHANNEL_OPTION_PRI_MED       0x04000000   // Channel data MUST be sent with medium MCS priority.
#define D_CHANNEL_OPTION_PRI_LOW       0x02000000   // Channel data MUST be sent with low MCS priority.
#define D_CHANNEL_OPTION_COMPRESS_RDP  0x00800000   // Virtual channel data MUST be compressed if RDP data is being compressed.
#define D_CHANNEL_OPTION_COMPRESS      0x00400000   // Virtual channel data MUST be compressed, regardless of RDP compression settings.
#define D_CHANNEL_OPTION_SHOW_PROTOCOL 0x00200000   // The value of this flag MUST be ignored by the server. 
                                                    // The visibility of the Channel PDU Header (section 2.2.6.1.1) is determined by the 
                                                    // CHANNEL_FLAG_SHOW_PROTOCOL (0x00000010) flag as defined in the flags field (section 2.2.6.1.1).
#define D_REMOTE_CONTROL_PERSISTENT    0x00100000   // Channel MUST be persistent across remote control transactions.

#define CHANNEL_FLAG_FIRST          0X00000001  /* Indicates that the chunk is the first in a sequence. */
#define CHANNEL_FLAG_LAST           0X00000002  /* Indicates that the chunk is the last in a sequence. */
#define CHANNEL_FLAG_SHOW_PROTOCOL  0X00000010  /* The Channel PDU Header MUST be visible to the application endpoint */
#define CHANNEL_FLAG_SUSPEND        0X00000020  /* All virtual channel traffic MUST be suspended. */
#define CHANNEL_FLAG_RESUME         0X00000040  /* All virtual channel traffic MUST be resumed. */
#define CHANNEL_PACKET_COMPRESSED   0X00200000  /* The virtual channel data is compressed. */
#define CHANNEL_PACKET_AT_FRONT     0X00400000  /* The decompressed packet MUST be placed at the beginning of the history buffer. */
#define CHANNEL_PACKET_FLUSHED      0X00800000  /* The decompressor MUST reinitialize the history buffer */
struct dsd_rdp_vc_1 {                       /* RDP virtual channel     */
   char       byrc_name[8];                 /* name of channel         */
   int        imc_flags;                    /* flags                   */
   unsigned short int usc_vch_no;           /* virtual channel no com  */
   unsigned short int usc_hob_vch;          /* virtual channel HOB special */
};

struct dsd_rdp_neg_req {
    unsigned short int usc_flags;
    unsigned int umc_requested_protocols;
};

struct dsd_rdp_neg_resp {
    unsigned short int usc_type;
    unsigned short int usc_flags;
    unsigned int umc_selected_protocol;
    unsigned int umc_failure_code;
};


enum ied_cc_command {                       /* client component command */
   ied_ccc_invalid,                         /* command is invalid      */
   ied_ccc_start_rdp_client,                /* start the RDP client    */
   ied_ccc_continue_after_ext,              /* continue after external security negotiation */
   ied_ccc_dyn_connect,                     /* dynamic connect         */
   ied_ccc_pass_license,                    /* pass the license information */
   ied_ccc_reconnect,                       /* reconnect the RDP client */
   ied_ccc_events_mouse_keyb,               /* events from mouse or keyboard */
   ied_ccc_send_confirm_active_pdu,         /* send Confirm Active PDU */
   ied_ccc_vch_out                          /* output to virtual channel */
};

enum ied_se_command {                       /* command from server     */
   ied_sec_invalid,                         /* command is invalid      */
   ied_sec_rdp_neg_resp,                    /* connection confirm PDU has been received */
   ied_sec_req_dyn_connect,                 /* request parameters for dynamic connect */
   ied_sec_dyn_connect_ok,                  /* dynamic connect succeeded */
   ied_sec_dyn_connect_error,               /* dynamic connect error   */
   ied_sec_update_screen,                   /* update the screen       */
   ied_sec_vch_in,                          /* input from virtual channel */
   ied_sec_recv_demand_active_pdu,          /* received Demand Active PDU */
   ied_sec_d_deact_pdu,                     /* received demand de-active PDU */
   ied_sec_switch_server,                   /* received connect to other RDP server */
   ied_sec_request_license,                 /* request the licence     */
   ied_sec_save_license,                    /* save the licence        */
   ied_sec_update_bitmap,                   /* command update bitmap   */
   ied_sec_compr_bitmap,                    /* command compressed bitmap */
   ied_sec_cache_bitmap_rev1,               /* command cache bitmap    */
   ied_sec_cache_bitmap_rev2,               /* command cache bitmap rev2 */
   ied_sec_cache_bitmap_rev3,               /* command cache bitmap compressed rev3 */
   ied_sec_cache_brush,                     /* command cache brush     */
   ied_sec_cache_glyph_rev1,                /* command cache glyph rev1 */
   ied_sec_cache_glyph_rev2,                /* command cache glyph rev2 */
   ied_sec_create_ninegrid_bitmap,          /* command Create NineGrid Bitmap */
   ied_sec_stream_bitmap_first,             /* command Stream Bitmap First */
   ied_sec_stream_bitmap_next,              /* command Stream Bitmap Next */
   ied_sec_frame_marker,                    /* command Frame Marker    */
   ied_sec_mpoi_null,                       /* command mouse pointer hide */
   ied_sec_mpoi_default,                    /* command mouse pointer default */
   ied_sec_mpoi_position,                   /* command mouse pointer position */
   ied_sec_mpoi_color,                      /* command mouse pointer color */
   ied_sec_mpoi_cached,                     /* command mouse pointer cached */
   ied_sec_mpoi_new,                        /* command mouse pointer new */
   ied_sec_order,                           /* command drawing order   */
   ied_sec_cr_offs_bitmap,                  /* CREATE_OFFSCR_BITMAP_ORDER */
   ied_sec_switch_surface,                  /* SWITCH_SURFACE_ORDER    */
   ied_sec_end_session,                     /* end of session server side */
   ied_sec_end_shutdown                     /* shutdown of server      */
};

struct dsd_call_rdpclient_1 {               /* pass parameters to subroutine */
   int        inc_func;                     /* called function         */
   int        inc_return;                   /* return code             */
   char *     achc_work_area;               /* addr work-area          */
   int        inc_len_work_area;            /* length work-area        */

   struct dsd_gather_i_1 *adsc_gather_i_1_in;  /* input data           */
#ifdef B120310
   struct dsd_gather_i_1 *adsc_gather_i_1_out;  /* output data         */
#else
   struct dsd_gather_i_1 *adsc_gai1_out_to_server;  /* output data to server */
#endif

   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     ac_ext;                       // attached buffer pointer
   int        imc_flags_1;                  /* flags of configuration  */
   int        imc_signal;                   /* signals occured         */
   void *     vpc_userfld;                  /* User Field Subroutine   */
   BOOL       boc_callagain;                /* call again this direction */
   BOOL       boc_callrevdir;               /* call on reverse direction */
   BOOL       boc_no_conn_s;                /* do not connect to server */
#ifdef B120310
   BOOL       boc_eof_client;               /* End-of-File Client      */
#else
   BOOL       boc_eof_server;               /* End-of-File Server      */
#endif
   struct dsd_rdp_co_client *adsc_rdp_co;   /* RDP communication       */
   void *     ac_screen_buffer;             /* screen buffer           */
   struct dsd_stor_sdh_1 *adsc_stor_sdh_1;  /* storage management      */
   void *     ac_sub_area;                  /* storage subroutine      */
   struct dsd_cc_co1 *adsc_cc_co1_ch;       /* chain of client commands, input */
   struct dsd_se_co1 *adsc_se_co1_ch;       /* chain of commands from server, output */
};

struct dsd_cc_co1 {                         /* client component command */
   struct dsd_cc_co1 *adsc_next;            /* next in chain           */
   enum ied_cc_command iec_cc_command;      /* command type            */
};

struct dsd_se_co1 {                         /* command from server     */
   struct dsd_se_co1 *adsc_next;            /* next in chain           */
   enum ied_se_command iec_se_command;      /* command type            */
};

struct dsd_cc_start_rdp_client {            /* start the RDP client    */
   BOOL       boc_compression;              /* with compression        */
   int        imc_dim_x;                    /* dimension x pixels      */
   int        imc_dim_y;                    /* dimension y pixels      */
   int        imc_coldep;                   /* colour depth            */
   int        imc_keyboard_layout;          /* Keyboard Layout         */
   int        imc_keyboard_type;            /* Type of Keyboard / 102  */
   int        imc_keyboard_subtype;         /* Subtype of Keyboard     */
   int        imc_no_func_keys;             /* Number of Function Keys */
// to-do 10.04.12 KB - should RDP-client generate umc_loinf_options from other values - like compression ???
   unsigned int umc_loinf_options;          /* Logon Info Options      */
   unsigned short int usc_loinf_domna_len;  /* Domain Name Length      */
   unsigned short int usc_loinf_userna_len;  /* User Name Length       */
   unsigned short int usc_loinf_pwd_len;    /* Password Length         */
   unsigned short int usc_loinf_altsh_len;  /* Alt Shell Length        */
   unsigned short int usc_loinf_wodir_len;  /* Working Directory Length */
   unsigned short int usc_loinf_no_a_par;   /* number of additional parameters */
   unsigned short int usc_loinf_ineta_len;  /* INETA Length            */
   unsigned short int usc_loinf_path_len;   /* Client Path Length      */
   unsigned short int usc_loinf_extra_len;  /* Extra Parameters Length */
   HL_WCHAR   *awcc_loinf_domna_a;          /* Domain Name             */
   HL_WCHAR   *awcc_loinf_userna_a;         /* User Name               */
   HL_WCHAR   *awcc_loinf_pwd_a;            /* Password                */
   HL_WCHAR   *awcc_loinf_altsh_a;          /* Alt Shell               */
   HL_WCHAR   *awcc_loinf_wodir_a;          /* Working Directory       */
   HL_WCHAR   *awcc_loinf_ineta_a;          /* INETA                   */
   HL_WCHAR   *awcc_loinf_path_a;           /* Client Path             */
   void       *awcc_loinf_extra_a;          /* Extra Parameters        */
   struct dsd_unicode_string dsc_ucs_computer_name;  /* computer-name  */
   int        imc_no_virt_ch;               /* number of virtual channels */
   struct dsd_rdp_vc_1 *adsrc_vc_1;         /* array of virtual channels */
//#ifdef XYZ1
   int        imc_platform_id;              /* The platform ID of the client */
   char       *achc_machine_name;           /* Name of clients machine, zero-terminated */
//#endif
   char       chrc_client_hardware_data[ 16 ];  /* Mr. Bauer knows     */
   BOOL       boc_allow_hob_rdp_ext1;       /* allow protocol HOB-RDP-EXT1 */
   struct dsd_rdp_neg_req dsc_rdp_neg_req;
};

/** the structure dsd_cc_dyn_connect is followed by the UTF-8 command  */
struct dsd_cc_dyn_connect {                 /* dynamic connect         */
   int        imc_len_cmd;                  /* length of command       */
};

struct dsd_cc_pass_license {                /* pass the license information */
   char       *achc_content;                /* address of content      */
   int        imc_len_content;              /* length of content       */
};

struct dsd_cc_events_mouse_keyb {           /* events from mouse or keyboard */
   char *     achc_event_buf;               /* buffer with events      */
   int        imc_events_len;               /* length of events        */
   int        imc_no_order;                 /* number of orders        */
};

struct dsd_se_switch_server {               /* switch to other RDP server - session broker */
/**
   imc_len_ineta == 0 : reconnect same server
*/
   int        imc_len_ineta;                /* length of INETA         */
   char       chrc_ineta[ 16 ];             /* INETA IPV4 / IPV6 to connect to */
#ifdef B131211
   int        imc_port;                     /* TCP port to connect to  */
#endif
};

struct dsd_se_req_dyn_connect {             /* request parameters for dynamic connect */
   int        imc_options;                  /* options as sent from WSP */
};

/** the structure dsd_se_dyn_connect_error is followed by the UTF-8 error message */
struct dsd_se_dyn_connect_error {           /* dynamic connect error   */
   int        iml_len_msg;                  /* length of error message */
};

struct dsd_sc_draw_sc {                     /* draw on screen          */
   int        imc_left;                     /* coordinate left         */
   int        imc_top;                      /* coordinate top          */
   int        imc_right;                    /* coordinate right        */
   int        imc_bottom;                   /* coordinate bottom       */
};

#ifdef B120310
struct dsd_sc_save_license {                /* save the license        */
   char       *achc_content;                /* address of content      */
   int        imc_len_content;              /* length of content       */
};
#endif

struct dsd_sc_request_license {             /* request a license       */
   /* [MS-RDPELE] 2.2.2.6.1 New License Information */
   int        imc_version;                  /* Version                 */
   int        im_num_scopes;                /* number of scopes in list */
   char       **ach_scope;                  /* issuer of license       */
   HL_WCHAR   *awsc_companyname;            /* Company name */
   HL_WCHAR   *awsc_productid;              /* Product id */
};

struct dsd_sc_save_license {                /* save the license        */
   /* [MS-RDPELE] 2.2.2.6.1 New License Information */
   BOOL       boc_new_license;              /* TRUE, if this was a new license request, FALSE, if it was an update license */
   int        imc_version;                  /* Version                 */
   char       *ach_scope;                   /* issuer of license       */
   HL_WCHAR   *awsc_companyname;            /* Company name */
   HL_WCHAR   *awsc_productid;              /* Product id */
   int        imc_len_license_info;         /* length of content       */
   char       *achc_license_info;           /* address of content      */
};

/* structure of an rectangle, defined by width and height              */
struct dsd_rectwh {
   signed short int isc_left;
   signed short int isc_top;
   signed short int isc_width;
   signed short int isc_height;
};

/* struct of an rectangle, defined by right and bottom                 */
struct dsd_rectrb {
   signed short int isc_left;
   signed short int isc_top;
   signed short int isc_right;
   signed short int isc_bottom;
};

struct dsd_brush {
   signed char scc_brushorgx;               /* top leftmost pixel of brushpattern, x-coordinate */
   signed char scc_brushorgy;               /* top leftmost pixel of brushpattern, y-coordinate */
   unsigned char ucc_brushstyle;            /* style of brush          */
   unsigned char ucc_brushhatch;            /* hatched_brush info or last row of brush-pattern */
   char       chrc_brushextra[7];           /* pixel pattern (only needed, if ucc_brushstyle = ied_bs_pattern) */
};

struct dsd_short_point {
   signed short isc_x;  // x-coordinate of point
   signed short isc_y;  // y-coordinate of point
};

enum ied_sc_lineto_backmode {
   ied_scc_transparent = 0x0001,
   ied_scc_opaque      = 0x0002
};

enum ied_sc_savebitmap_operation {
   ied_scc_sv_savebits = 0x00,                  // save bitmap operation
   ied_scc_sv_restorebits = 0x01                // restore bitmap operation
};

// to-do 07.04.12 KB structure double in .pre file - remove
//struct dsd_sc_vch_out {                     /* server sends output to virtual channel */
struct dsd_rdp_vch_io {                     /* IO RDP virtual channel  */
   struct dsd_rdp_vc_1 *adsc_rdp_vc_1;      /* RDP virtual channel     */
// struct dsd_gather_i_1 *adsc_gai1_out;    /* output data             */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* input output data       */
   unsigned int umc_vch_ulen;               /* virtual channel length uncompressed */
#ifdef B160404
   char       chrc_vch_segfl[2];            /* virtual channel segmentation flags */
#else // B160404
   char       chrc_vch_flags[4];            /* virtual channel flags   */
#endif // B160404
};
struct dsd_awcs_update_bitmap {             /* command update bitmap   */
   signed short int isc_left;
   signed short int isc_top;
   signed short int isc_right;
   signed short int isc_bottom;
   signed short int isc_width;
   signed short int isc_height;
   struct dsd_gather_i_1 *adsc_gai1_data;   /* input output data       */
};

struct dsd_awcs_compr_bitmap {              /* command compressed bitmap */
   signed short int isc_left;
   signed short int isc_top;
   signed short int isc_right;
   signed short int isc_bottom;
   signed short int isc_width;
   signed short int isc_height;
   struct dsd_gather_i_1 *adsc_gai1_data;   /* input output data       */
};

// to-do 10.12.12 KB rename to rev1
/* 2.2.2.2.1.2.2 Cache Bitmap - Revision 1 (CACHE_BITMAP_ORDER)        */
struct dsd_awcs_cache_bitmap_rev1 {         /* command cache bitmap rev1 */
   unsigned char ucc_cache_id;              /* cacheId                 */
   unsigned short int usc_cache_index;
   unsigned short int usc_flags;            /* flags                   */
   unsigned char ucc_bpp;                   /* decoded bitmapBitsPerPel */
   unsigned char ucc_width;                 /* bitmapWidth             */
   unsigned char ucc_height;                /* bitmapHeight            */
   BOOL       boc_compressed;               /* bitmap compressed       */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* input output data       */
};

/* 2.2.2.2.1.2.3 Cache Bitmap - Revision 2 (CACHE_BITMAP_REV2_ORDER)   */
struct dsd_awcs_cache_bitmap_rev2 {         /* command cache bitmap rev2 */
   unsigned char ucc_cache_id;              /* cacheId                 */
   unsigned char ucc_bpp_id;                /* bitsPerPixelId          */
   unsigned short int usc_flags;            /* flags                   */
   unsigned short int usc_cache_index;      /* cacheIndex              */
   unsigned int umc_key1;                   /* key1                    */
   unsigned int umc_key2;                   /* key2                    */
   unsigned short int usc_width;            /* bitmapWidth             */
   unsigned short int usc_height;           /* bitmapHeight            */
   BOOL       boc_compressed;               /* bitmap compressed       */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* input output data       */
};

/* 2.2.2.2.1.2.8 Cache Bitmap - Revision 3 (CACHE_BITMAP_REV3_ORDER)   */
struct dsd_awcs_cache_bitmap_rev3 {         /* command cache bitmap rev3 */
   unsigned char ucc_cache_id;              /* cacheId                 */
   unsigned char ucc_bpp_id;                /* bitsPerPixelId          */
   unsigned short int usc_flags;            /* flags                   */
   unsigned short int usc_cache_index;      /* cacheIndex              */
   unsigned int umc_key1;                   /* key1                    */
   unsigned int umc_key2;                   /* key2                    */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* input output data       */
};

struct dsd_awcs_cache_brush {               /* command cache brush     */
   unsigned char ucc_cache_entry;           /* cacheEntry              */
   unsigned char ucc_bitmap_format;         /* iBitmapFormat           */
   unsigned char ucc_cx;                    /* cx                      */
   unsigned char ucc_cy;                    /* cy                      */
   unsigned char ucc_style;                 /* Style                   */
// to-do 17.12.12 - is the following field needed - or sum of gather?
   unsigned char ucc_ibytes;                /* iBytes                  */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* input output data       */
};

/* 2.2.2.2.1.2.5 Cache Glyph - Revision 1 (CACHE_GLYPH_ORDER)          */
struct dsd_awcs_cache_glyph_rev1 {          /* command cache glyph rev1 */
   unsigned char ucc_cache_id;              /* cacheId                 */
   unsigned char ucc_count;                 /* cGlyphs                 */
   BOOL       boc_unicode_present;          /* unicodeCharacters field is present */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* input output data       */
};

/* 2.2.2.2.1.2.6 Cache Glyph Data - Revision 2 (TS_CACHE_GLYPH_DATA_REV2) */
struct dsd_awcs_cache_glyph_rev2 {          /* command cache glyph rev2 */
   unsigned char ucc_cache_id;              /* cacheId                 */
   unsigned char ucc_count;                 /* cGlyphs                 */
   BOOL       boc_unicode_present;          /* unicodeCharacters field is present */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* input output data       */
};

/* 2.2.2.2.1.3.7 Frame Marker                                          */
struct dsd_awcs_frame_marker {              /* command frame marker    */
   unsigned int umc_action;                 /* action                  */
};

/* 2.2.2.2.1.3.4 Create NineGrid Bitmap (CREATE_NINEGRID_BITMAP_ORDER) */
struct dsd_awcs_create_ninegrid_bitmap {    /* command Create NineGrid Bitmap */
   unsigned char ucc_bitmap_bpp;            /* BitmapBpp               */
   unsigned short int usc_bitmap_id;        /* BitmapId                */
   unsigned short int usc_cx;               /* cx                      */
   unsigned short int usc_cy;               /* cy                      */
   unsigned int umc_fl_flags;               /* flFlags                 */
   unsigned short int usc_left_width;       /* ulLeftWidth             */
   unsigned short int usc_right_width;      /* ulRightWidth            */
   unsigned short int usc_top_height;       /* ulTopHeight             */
   unsigned short int usc_bottom_height;    /* ulBottomHeight          */
   unsigned int umc_cr_transparent;         /* crTransparent           */
};

/* 2.2.2.2.1.3.5.1 Stream Bitmap First (STREAM_BITMAP_FIRST_ORDER)     */
struct dsd_awcs_stream_bitmap_first {       /* command Stream Bitmap First */
   unsigned char ucc_bitmap_flags;          /* BitmapFlags             */
   unsigned char ucc_bitmap_bpp;            /* BitmapBpp               */
   unsigned short int usc_bitmap_type;      /* BitmapType              */
   unsigned short int usc_bitmap_width;     /* BitmapWidth             */
   unsigned short int usc_bitmap_height;    /* BitmapHeight            */
   unsigned int umc_bitmap_size;            /* BitmapSize              */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* input output data       */
};

/* 2.2.2.2.1.3.5.2 Stream Bitmap Next (STREAM_BITMAP_NEXT_ORDER)       */
struct dsd_awcs_stream_bitmap_next {        /* command Stream Bitmap Next */
   unsigned char ucc_bitmap_flags;          /* BitmapFlags             */
   unsigned short int usc_bitmap_type;      /* BitmapType              */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* input output data       */
};

struct dsd_awcs_color_ptr_attr {            /* encapsulated color pointer attributes */
   unsigned short int usc_cache_index;      /* cache entry in the pointer cache in which to store the pointer */
   signed int isc_hotspot_x;                /* X coordinate of the pointer hotspot */
   signed int isc_hotspot_y;                /* Y coordinate of the pointer hotspot */
   unsigned short int usc_width;            /* Width of the pointer    */
   unsigned short int usc_height;           /* Height of the pointer   */
   unsigned short int usc_length_and_mask;  /* Size of the AND mask (in bytes) */
   unsigned short int usc_length_xor_mask;  /* Size of the XOR mask (in bytes) */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* input output data       */
};


/* 2.2.9.1.2.1.4 Fast-Path Pointer Position Update (TS_FP_POINTERPOSATTRIBUTE) */
struct dsd_awcs_mpoi_position {             /* mouse pointer position  */
   short int isc_x_pos;
   short int isc_y_pos;
};

/* 2.2.9.1.2.1.7 Fast-Path Color Pointer Update (TS_FP_COLORPOINTERATTRIBUTE) */
struct dsd_awcs_mpoi_color {                /* mouse pointer color     */
   /* colorPointerUpdateData                                           */
   struct dsd_awcs_color_ptr_attr dsc_acpa;  /* encapsulated color pointer attributes */
};

/* 2.2.9.1.2.1.9 Fast-Path Cached Pointer Update (TS_FP_CACHEDPOINTERATTRIBUTE) */
struct dsd_awcs_mpoi_cached {               /* mouse pointer cached    */
   /* cachedPointerUpdateData                                          */
   unsigned short int usc_cache_index;      /* cacheIndex              */
};

/* 2.2.9.1.2.1.8 Fast-Path New Pointer Update (TS_FP_POINTERATTRIBUTE) */
struct dsd_awcs_mpoi_new {                  /* mouse pointer new       */
   /* newPointerUpdateData                                             */
   unsigned short int usc_xor_bpp;          /* xorBpp                  */
   struct dsd_awcs_color_ptr_attr dsc_acpa;  /* encapsulated color pointer attributes */
};

struct dsd_awcs_order {                     /* command drawing order   */
   int        imc_order_no;                 /* order number            */
   int        imc_length;                   /* length of following data */
   BOOL       boc_bounds;                   /* with bounds             */
};

struct dsd_awcs_bounds {                    /* bounds for drawing      */
// question - to-do 26.05.12 KB - how to include structure without name
// struct dsd_rectrb {
   signed short int isc_left;
   signed short int isc_top;
   signed short int isc_right;
   signed short int isc_bottom;
// };
};

/* following this structure is the deleteList, unsigned short int      */
/* the number of entries is given thru the length of the command       */
struct dsd_awcs_cr_offs_bitmap {            /* CREATE_OFFSCR_BITMAP_ORDER */
   int        imc_len_command;              /* length of command including deleteList */
   unsigned short int usc_bitmap_id;        /* offscreenBitmapId       */
   unsigned short int usc_cx;               /* width in pixels of the offscreen bitmap */
   unsigned short int usc_cy;               /* height in pixels of the offscreen bitmap */
};

struct dsd_awcs_switch_surface {            /* SWITCH_SURFACE_ORDER    */
   unsigned short int usc_bitmap_id;        /* offscreenBitmapId       */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.1 DstBlt (DSTBLT_ORDER)                  */
struct dsd_ord_co_o00 {                     /* order O00 coordinates   */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   unsigned char ucc_brop3;                 /* index of the ternary raster operation */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.3 PatBlt (PATBLT_ORDER)                  */
struct dsd_ord_co_o01 {                     /* order O01 coordinates   */
   unsigned char ucc_brop3;                 /* index of the ternary raster operation */
   unsigned int umc_backcolor;              /* background color        */
   unsigned int umc_forecolor;              /* foreground color        */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   struct dsd_brush dsc_brush;              /* brush                   */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.7 ScrBlt (SCRBLT_ORDER)                  */
struct dsd_ord_co_o02 {                     /* order O02 coordinates   */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   unsigned char ucc_brop3;                 /* index of the ternary raster operation */
   short isc_x_src;                         /* x coordinate of source  */
   short isc_y_src;                         /* y coordinate of source  */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.21 DrawNineGrid (DRAWNINEGRID_ORDER)     */
struct dsd_ord_co_o07 {                     /* order O07 coordinates   */
   struct dsd_rectrb dsc_rect;              /* rectangle source src    */
   unsigned short int usc_bitmap_id;        /* offscreen BitmapId      */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.22 MultiDrawNineGrid (MULTI_DRAWNINEGRID_ORDER) */
struct dsd_ord_co_o08 {                     /* order O08 coordinates   */
   struct dsd_rectrb dsc_rect;              /* rectangle source src    */
   unsigned short int usc_bitmap_id;        /* offscreen BitmapId      */
   unsigned char ucc_no_delta_entries;      /* number of points CodedDeltaList */
   unsigned short int usc_len_delta_entries;  /* length of points CodedDeltaList */
   char       *achc_coded_delta_list;       /* contains the points CodedDeltaList */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.11 LineTo (LINETO_ORDER)                 */
struct dsd_ord_co_o09 {                     /* order O09 coordinates   */
   unsigned short int usc_backmode;         /* mode of background: transparent or opaque */
   signed short int isc_nxstart;                // starting point of the line, x-coordinate
   signed short int isc_nystart;                // starting point of the line, y-coordinate
   signed short int isc_nxend;                  // end point of the line, x-coordinate
   signed short int isc_nyend;                  // end point of the line, y-coordinate
   unsigned int umc_back_color;             /* BackColor               */
   unsigned char ucc_brop2;                 // binary raster operation
   unsigned char ucc_penstyle;              // PenStyle must be PS_SOLID(0x00)
   unsigned char ucc_penwidth;              // PenWidth must be 0x01.
   unsigned int umc_pencolor;               // color of the drawn line
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.5 OpaqueRect (OPAQUERECT_ORDER)          */
struct dsd_ord_co_o0a {                     /* order O0A coordinates   */
   struct dsd_rectwh dsc_rect;              /* virtual desktop rectangle to fill */
   unsigned char ucc_color_red;             /* RedOrPaletteIndex       */
   unsigned char ucc_color_green;           /* Green                   */
   unsigned char ucc_color_blue;            /* Blue                    */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.12 SaveBitmap (SAVEBITMAP_ORDER)         */
struct dsd_ord_co_o0b {                     /* order O0B coordinates   */
   unsigned int umc_savedbitmappos;         /* encoded start position of the rectangle in the saved bitmap */
   struct dsd_rectrb dsc_rect;              /* virtual desktop rectangle to save or to restore from */
// ied_sc_savebitmap_operation ucc_operation;  /* operation: either ied_sv_savebits or ied_sv_restorebits */
   unsigned char ucc_operation;             /* operation: either ied_sv_savebits or ied_sv_restorebits */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.9 MemBlt (MEMBLT_ORDER)                  */
struct dsd_ord_co_o0d {                     /* order O0D coordinates   */
   unsigned short int usc_cache_id;         /* cacheId                 */
// struct dsd_rectwh dsc_destination_rec;   /* destination rectangle   */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   unsigned char ucc_brop3;                 /* index of the ternary raster operation */
   signed short int isc_x_src;              /* x-coordinate of source bitmap in cache of client */
   signed short int isc_y_src;              /* inverted y-coordinate of source bitmap in cache of client */
   unsigned short int usc_cacheindex;       /* index of bitmap within the bitmap cache of client */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.10 Mem3Blt (MEM3BLT_ORDER)               */
struct dsd_ord_co_o0e {                     /* order O0E coordinates   */
   unsigned short int usc_cache_id;         /* cacheId                 */
   unsigned char ucc_brop3;                 /* index of the ternary raster operation */
   signed short int isc_x_src;              /* x-coordinate of source bitmap in cache of client */
   signed short int isc_y_src;              /* inverted y-coordinate of source bitmap in cache of client */
   unsigned short int usc_cacheindex;       /* index of bitmap within the bitmap cache of client */
   unsigned int umc_backcolor;              /* background color        */
   unsigned int umc_forecolor;              /* foreground color        */
// struct dsd_rectwh dsc_destination_rec;   /* destination rectangle   */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   struct dsd_brush dsc_brush;              /* brush                   */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.2 MultiDstBlt (MULTI_DSTBLT_ORDER)       */
struct dsd_ord_co_o0f {                     /* order O0F coordinates   */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   unsigned char ucc_brop3;                 /* index of the ternary raster operation */
   unsigned char ucc_no_delta_entries;      /* nDeltaEntries - number of delta entries */
   unsigned short int usc_len_delta;        /* length CodedDeltaList   */
   char *     achc_delta;                   /* CodedDeltaList          */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.4 MultiPatBlt (MULTI_PATBLT_ORDER)       */
struct dsd_ord_co_o10 {                     /* order O10 coordinates   */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   unsigned char ucc_brop3;                 /* index of the ternary raster operation */
   unsigned int umc_backcolor;              /* background color        */
   unsigned int umc_forecolor;              /* foreground color        */
   struct dsd_brush dsc_brush;              /* brush                   */
   unsigned char ucc_no_delta_entries;      /* nDeltaEntries - number of delta entries */
   unsigned short int usc_len_delta;        /* length CodedDeltaList   */
   char *     achc_delta;                   /* CodedDeltaList          */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.8 MultiScrBlt (MULTI_SCRBLT_ORDER)       */
struct dsd_ord_co_o11 {                     /* order O11 coordinates   */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   unsigned char ucc_brop3;                 /* index of the ternary raster operation */
   short isc_x_src;                         /* x coordinate of source  */
   short isc_y_src;                         /* y coordinate of source  */
   unsigned char ucc_no_delta_entries;      /* nDeltaEntries - number of delta entries */
   unsigned short int usc_len_delta;        /* length CodedDeltaList   */
   char *     achc_delta;                   /* CodedDeltaList          */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.6 MultiOpaqueRect (MULTI_OPAQUERECT_ORDER) */
struct dsd_ord_co_o12 {                     /* order O12 coordinates   */
   struct dsd_rectwh dsc_rect;              /* virtual desktop rectangle to fill */
   unsigned char ucc_color_red;             /* RedOrPaletteIndex       */
   unsigned char ucc_color_green;           /* Green                   */
   unsigned char ucc_color_blue;            /* Blue                    */
   unsigned char ucc_no_delta_entries;      /* nDeltaEntries - number of delta entries */
   unsigned short int usc_len_delta;        /* length CodedDeltaList   */
   char *     achc_delta;                   /* CodedDeltaList          */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.14 FastIndex (FASTINDEX_ORDER)           */
struct dsd_ord_co_o13 {                     /* order O13 coordinates   */
   unsigned char ucc_cache_id;              /* cacheId                 */
   unsigned short int usc_fdrawing;         /* fDrawing                */
   unsigned int umc_forecolor;              /* foreground color        */
   unsigned int umc_backcolor;              /* background color        */
   struct dsd_rectrb dsc_backrect;          /* text background rectangle, like a clip */
   struct dsd_rectrb dsc_opaqrect;          /* opaque rectangle        */
   signed short int isc_start_x;            /* starting point of first glyph, x-coordinate */
   signed short int isc_start_y;            /* starting point of first glyph, y-coordinate */
   unsigned char ucc_len_glyph;             /* length glyph data      */
   char *     achc_glyph;                   /* glyph data             */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.16 PolygonSC (POLYGON_SC_ORDER)          */
struct dsd_ord_co_o14 {                     /* order O14 coordinates   */
   signed short int isc_start_x;            /* starting point of the line, x-coordinate */
   signed short int isc_start_y;            /* starting point of the line, y-coordinate */
   unsigned char ucc_brop2;                 /* binary raster operation */
   unsigned char ucc_fillmode;              /* FillMode                */
   unsigned int umc_brushcolor;             /* BrushColor              */
   unsigned char ucc_no_delta_entries;      /* number of points along the polygon path */
   unsigned char ucc_len_delta_entries;     /* length of points along the polygon path */
   char       *achc_coded_delta_list;       /* contains the points along the polygon path */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.17 PolygonCB (POLYGON_CB_ORDER)          */
struct dsd_ord_co_o15 {                     /* order O15 coordinates   */
   signed short int isc_start_x;            /* starting point of the line, x-coordinate */
   signed short int isc_start_y;            /* starting point of the line, y-coordinate */
   unsigned char ucc_brop2;                 /* binary raster operation */
   unsigned char ucc_fillmode;              /* FillMode                */
   unsigned int umc_backcolor;              /* background color        */
   unsigned int umc_forecolor;              /* foreground color        */
   struct dsd_brush dsc_brush;              /* brush                   */
   unsigned char ucc_no_delta_entries;      /* number of points along the polygon path */
   unsigned char ucc_len_delta_entries;     /* length of points along the polygon path */
   char       *achc_coded_delta_list;       /* contains the points along the polygon path */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.18 Polyline (POLYLINE_ORDER)             */
struct dsd_ord_co_o16 {                     /* order O16 coordinates   */
   signed short int isc_start_x;            /* starting point of the line, x-coordinate */
   signed short int isc_start_y;            /* starting point of the line, y-coordinate */
   unsigned char ucc_brop2;                 /* binary raster operation */
   unsigned short int usc_brush_cache_entry;  /* brush cache entry     */
   unsigned int umc_pencolor;               /* color of the drawn line */
   unsigned char ucc_no_delta_entries;      /* number of points along the polyline path */
   unsigned char ucc_len_delta_entries;     /* length of points along the polyline path */
   char       *achc_coded_delta_list;       /* contains the points along the polyline path */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.15 FastGlyph (FASTGLYPH_ORDER)           */
struct dsd_ord_co_o18 {                     /* order O18 coordinates   */
   unsigned char ucc_cache_id;              /* cacheId                 */
   unsigned short int usc_fdrawing;         /* fDrawing                */
   unsigned int umc_backcolor;              /* background color        */
   unsigned int umc_forecolor;              /* foreground color        */
   struct dsd_rectrb dsc_backrect;          /* text background rectangle, like a clip */
   struct dsd_rectrb dsc_opaqrect;          /* opaque rectangle        */
   signed short int isc_start_x;            /* starting point of first glyph, x-coordinate */
   signed short int isc_start_y;            /* starting point of first glyph, y-coordinate */
   unsigned char ucc_len_glyph;             /* length glyph data      */
   char *     achc_glyph;                   /* glyph data             */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.19 EllipseSC (ELLIPSE_SC_ORDER)          */
struct dsd_ord_co_o19 {                     /* order O19 coordinates   */
   struct dsd_rectrb dsc_rect;              /* rectangle for the ellipse */
   unsigned char ucc_brop2;                 /* binary raster operation */
   unsigned char ucc_fillmode;              /* FillMode                */
   unsigned int umc_color;                  /* foreground color        */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.20 EllipseCB (ELLIPSE_CB_ORDER)          */
struct dsd_ord_co_o1a {                     /* order O1A coordinates   */
   struct dsd_rectrb dsc_rect;              /* rectangle for the ellipse */
   unsigned char ucc_brop2;                 /* binary raster operation */
   unsigned char ucc_fillmode;              /* FillMode                */
   unsigned int umc_backcolor;              /* background color        */
   unsigned int umc_forecolor;              /* foreground color        */
   struct dsd_brush dsc_brush;              /* brush for the ellipse   */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.13 GlyphIndex (GLYPHINDEX_ORDER)         */
struct dsd_ord_co_o1b {                     /* order O1B coordinates   */
   unsigned char ucc_cache_id;              /* cacheId                 */
   unsigned char ucc_flaccel;               /* flAccel                 */
   unsigned char ucc_ulcharinc;             /* ulCharInc               */
   unsigned char ucc_fopredundant;          /* fOpRedundant            */
   unsigned int umc_backcolor;              /* background color        */
   unsigned int umc_forecolor;              /* foreground color        */
   struct dsd_rectrb dsc_backrect;          /* text background rectangle, like a clip */
   struct dsd_rectrb dsc_opaqrect;          /* opaque rectangle        */
   struct dsd_brush dsc_brush;              /* brush for the glyph     */
   signed short int isc_start_x;            /* starting point of first glyph, x-coordinate */
   signed short int isc_start_y;            /* starting point of first glyph, y-coordinate */
   unsigned char ucc_len_glyph;             /* length glyph data      */
   char *     achc_glyph;                   /* glyph data             */
};

struct dsd_rdp_encry {                      /* rdp encryption          */
   char       chrc_cl_pkd[16];              /* pre key data            */
   char       chrc_orig_pkd[16];            /* first key before update */
   char       chrc_rc4_state[ RC4_STATE_SIZE ];  /* RC4 state array    */
   int        imc_count_sent;               /* count blocks sent       */
};

struct dsd_rdp_lic_bb {                     /* licencing binary blob   */
   unsigned short int usc_bb_type;          /* blob type, 2.2.1.12.1.2 */
   unsigned short int usc_bb_len;           /* length of data in byte  */
   char *     achc_bb_data;                 /* content                 */
};

struct dsd_rdp_lic_d {                      /* licensing protocol data */
   char       chc_lic_clcertway;            /* type of first client lic.packet */
   char       chc_lic_vers;                 /* licensing version and some flag */
   int        imc_lic_pkea;                 /* preferred key algorithm */
   int        imc_lic_platform;             /* platform ID             */
   char       chrc_lic_clrand[32];          /* licensing client random */
   struct dsd_rdp_lic_bb dsc_lic_pms;       /* lic. premaster secret   */
   char       chrc_lic_serand[32];          /* licensing server random */
// 08.08.09 KB rename to achc
   char *     chrc_lic_1;                   /* data temporarily needed */
   int        imc_lic_1_len;                /* length of temporary data */
   int        imc_lic_cert_key_len;         /* length of certificate modulus */
// 08.08.09 KB rename to achc
   char *     chrc_lic_cert_key;            /* certificate modulus     */
   int        imc_lic_cert_exp_len;         /* length of certificate exponent */
// 08.08.09 KB rename to achc
   char *     chrc_lic_cert_exp;            /* certificate exponent    */
   char       chrc_rc4_state_se2cl[RC4_STATE_SIZE]; /* RC4 state array */
   char       chrc_rc4_state_cl2se[RC4_STATE_SIZE]; /* RC4 state array */
   int        imrc_sha1_state[ SHA_ARRAY_SIZE ];  /* SHA1 state array  */
   int        imrc_md5_state[ MD5_ARRAY_SIZE ];  /* MD5 state array    */
};

typedef struct {
   unsigned short int ibc_contchno : 1;     /* control channel defined */
   unsigned short int filler : 15;          /* filler                  */
} dtd_rdpfl_1;


struct dsd_rdp_co_client {                  /* rdp communication       */
   struct dsd_rdp_neg_req dsc_rdp_neg_req;
   struct dsd_rdp_neg_resp dsc_rdp_neg_resp;
   BOOL boc_licensing_done;
   unsigned char ucc_prot_vers;             /* protocol version        */
   int        imc_cl_coldep;                /* client capabilities colour depth */
   unsigned short int usc_cl_supported_color_depth;  /* client capabilities */
   unsigned short int usc_cl_early_capability_flag;  /* client capabilities */
   int        imc_dim_x;                    /* dimension x pixels      */
   int        imc_dim_y;                    /* dimension y pixels      */
   int        imc_s_coldep;                 /* session colour depth    */
   int        imc_bpp;                      /* number of bytes per pixel */
   int        imc_keyboard_layout;          /* Keyboard Layout         */
   int        imc_build_number;             /* MS Build Number         */
#ifndef B110722
   int        imc_shareid;                  /* share id, parsed from Demand active PDU */
#endif
   HL_WCHAR   wcrc_computer_name[16];       /* computer name           */
   int        imc_keyboard_type;            /* Type of Keyboard / 102  */
   int        imc_keyboard_subtype;         /* Subtype of Keyboard     */
   int        imc_no_func_keys;             /* Number of Function Keys */
   int        imc_keytype;                  /* keytype                 */
   int        imc_used_keylen;              /* used keylen 03.01.05    */
   int        imc_sec_level;                /* security level          */
   int        imc_l_pub_par;                /* length public parameters */
   int        imc_no_virt_ch;               /* number of virtual channels */
   BOOL       boc_use_hob_rdp_ext1;         /* use protocol HOB-RDP-EXT1 */
   unsigned short int usc_chno_disp;        /* channel number display  */
   unsigned short int usc_chno_cont;        /* channel number control  */
   unsigned short int usc_userid_cl2se;     /* userid client to server */
   dtd_rdpfl_1 dtc_rdpfl_1;                 /* RDP flags               */
   struct dsd_rdp_vc_1 *adsrc_vc_1;         /* array of virtual channels */
   struct dsd_progaddr_1 *adsc_progaddr_1;  /* program addresses       */
   struct dsd_cdr_ctrl dsc_cdrf_dec;        /* compression decoding    */
   struct dsd_cdr_ctrl dsc_cdrf_enc;        /* compression encoding    */
   amd_cdr_dec amc_cdr_dec;                 /* routine compression decoding */
   amd_cdr_enc amc_cdr_enc;                 /* routine compression encoding */
   char       chrc_sig[16];                 /* signature               */
   struct dsd_rdp_encry dsc_encry_se2cl;    /* rdp encryption server to client */
   struct dsd_rdp_encry dsc_encry_cl2se;    /* rdp encryption client to server */
   int        imrc_sha1_state[ SHA_ARRAY_SIZE ];  /* SHA1 state array  */
   int        imrc_md5_state[ MD5_ARRAY_SIZE ];  /* MD5 state array    */
#ifdef HELP_DEBUG
   int        imc_debug_reclen;
   int        imc_debug_count_event;
#endif
/* initialize parameters at demand active PDU */
   struct dsd_ord_co_o00 dsc_ord_co_o00;    /* order O00 coordinates   */
   struct dsd_ord_co_o01 dsc_ord_co_o01;    /* order O01 coordinates   */
   struct dsd_ord_co_o02 dsc_ord_co_o02;    /* order O02 coordinates - ScrBlt (SCRBLT_ORDER) */
   struct dsd_ord_co_o07 dsc_ord_co_o07;    /* order O07 coordinates - DrawNineGrid (DRAWNINEGRID_ORDER) */
   struct dsd_ord_co_o08 dsc_ord_co_o08;    /* order O08 coordinates - MultiDrawNineGrid (MULTI_DRAWNINEGRID_ORDER) */
   struct dsd_ord_co_o09 dsc_ord_co_o09;    /* order O09 coordinates   */
   struct dsd_ord_co_o0a dsc_ord_co_o0a;    /* order O0A coordinates   */
   struct dsd_ord_co_o0b dsc_ord_co_o0b;    /* order O0B coordinates   */
   struct dsd_ord_co_o0d dsc_ord_co_o0d;    /* order O0D coordinates   */
   struct dsd_ord_co_o0e dsc_ord_co_o0e;    /* order O0E coordinates   */
   struct dsd_ord_co_o0f dsc_ord_co_o0f;    /* order O0F coordinates - MultiDstBlt (MULTI_DSTBLT_ORDER) */
   struct dsd_ord_co_o10 dsc_ord_co_o10;    /* order O10 coordinates - MultiPatBlt (MULTI_PATBLT_ORDER) */
   struct dsd_ord_co_o11 dsc_ord_co_o11;    /* order O11 coordinates - MultiScrBlt (MULTI_SCRBLT_ORDER) */
   struct dsd_ord_co_o12 dsc_ord_co_o12;    /* order O12 coordinates - MultiOpaqueRect (MULTI_OPAQUERECT_ORDER) */
   struct dsd_ord_co_o13 dsc_ord_co_o13;    /* order O13 coordinates   */
   struct dsd_ord_co_o14 dsc_ord_co_o14;    /* order O14 coordinates - PolygonSC (POLYGON_SC_ORDER) */
   struct dsd_ord_co_o15 dsc_ord_co_o15;    /* order O15 coordinates - PolygonCB (POLYGON_CB_ORDER) */
   struct dsd_ord_co_o16 dsc_ord_co_o16;    /* order O16 coordinates   */
   struct dsd_ord_co_o18 dsc_ord_co_o18;    /* order O18 coordinates   */
   struct dsd_ord_co_o19 dsc_ord_co_o19;    /* order O19 coordinates - EllipseSC (ELLIPSE_SC_ORDER) */
   struct dsd_ord_co_o1a dsc_ord_co_o1a;    /* order O1A coordinates - EllipseCB (ELLIPSE_CB_ORDER) */
   struct dsd_ord_co_o1b dsc_ord_co_o1b;    /* order O1B coordinates - GlyphIndex (GLYPHINDEX_ORDER) */
/* initialize parameters at demand active PDU */

   struct dsd_awcs_bounds dsc_bounds_cur;   /* bounds for drawing      */
   BOOL       boc_auto_reconnect;           /* TS_AUTORECONNECT_STATUS_PDU received */
   char       chrc_auto_reconnect[ LEN_ARC_SC_PRIVATE_PACKET - sizeof(int) ];
/* new 25.03.07 KB */
   unsigned int umc_loinf_options;          /* Logon Info Options      */
   unsigned short int usc_loinf_domna_len;  /* Domain Name Length      */
   unsigned short int usc_loinf_userna_len;  /* User Name Length       */
   unsigned short int usc_loinf_pwd_len;    /* Password Length         */
   unsigned short int usc_loinf_altsh_len;  /* Alt Shell Length        */
   unsigned short int usc_loinf_wodir_len;  /* Working Directory Length */
   unsigned short int usc_loinf_no_a_par;   /* number of additional parameters */
   unsigned short int usc_loinf_ineta_len;  /* INETA Length            */
   unsigned short int usc_loinf_path_len;   /* Client Path Length      */
   unsigned short int usc_loinf_extra_len;  /* Extra Parameters Length */
   HL_WCHAR   *awcc_loinf_domna_a;          /* Domain Name             */
   HL_WCHAR   *awcc_loinf_userna_a;         /* User Name               */
   HL_WCHAR   *awcc_loinf_pwd_a;            /* Password                */
   HL_WCHAR   *awcc_loinf_altsh_a;          /* Alt Shell               */
   HL_WCHAR   *awcc_loinf_wodir_a;          /* Working Directory       */
   HL_WCHAR   *awcc_loinf_ineta_a;          /* INETA                   */
   HL_WCHAR   *awcc_loinf_path_a;           /* Client Path             */
   void       *awcc_loinf_extra_a;          /* Extra Parameters        */
   struct dsd_rdp_lic_d * adsc_lic_neg;     /* for license negotiation */
   char       *achc_server_capabilities;    /* address storage server capabilities */
   int        imc_len_server_capabilities;  /* length server capabilities */
#ifdef XYZ1
*if def D$RDP$VCH;
*if def B091207B;
   struct dsd_rdp_vc_1 *adsc_rdp_vc_hob1;   /* RDP virtual channel HOB1 */
   struct dsd_rdp_vc_1 *adsc_rdp_vc_hob2;   /* RDP virtual channel HOB2 */
   struct dsd_rdp_vc_1 *adsc_rdp_vc_rdpdr;  /* RDP virtual channel rdpdr */
*cend;
*cend;
*if def D$RDP$TRAC;
   char       chrc_start_rec[ 4 + D_SIZE_HASH ];  /* start of record   */
   int        imc_len_start_rec;            /* length start of record  */
   int        imc_len_record;               /* length of record        */
   int        imc_len_part;                 /* length of part          */
*cend;
#endif
   int        imc_platform_id;              /* The platform ID of the client */
   char       *achc_machine_name;           /* Name of clients machine, zero-terminated */
   char       chrc_client_hardware_data[16];  /* unique hardware data of the client */
};

extern PTYPE void m_rdpclient_1( struct dsd_call_rdpclient_1 * );

