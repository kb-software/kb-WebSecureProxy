#define TO_BE_REMOVED_091224
#define SM_080618
#define JB_081215 // Definitions by Johannes Bauer, 15-17. Dec 08

// 2017.03.14 DD:
//  If you need to use the old HELP_DEBUG facilities, please uncomment the
//      following definition. This way all compilation units that include this
//      header will have exactly the same definitions.
// #define HL_RDPACC_HELP_DEBUG

/**
  hob-rdpserver1.h
  Header-File for RDP-Accelerator / RDP-Server
  Copyright (C) HOB Germany 2006
  Copyright (C) HOB Germany 2008
  Copyright (C) HOB Germany 2009
  Copyright (C) HOB Germany 2010
  25.09.06 KB
*/


#if 0
//-------------------------------------------------------------
// Interface structure definition for Server Interface,
// Revised Version (Configuration Parameters removed)
//-------------------------------------------------------------
#endif

/**
  this header file needs the following include statements
  in the calling C/C++ program:

#ifndef HL_UNIX
#include <winsock2.h>
#include <windows.h>
#else
#include <unistd.h>
#include <sys/sem.h>
#include <errno.h>
#include <arpa/inet.h>
#include <hob-unix01.h>
#endif

#include "hob-cdrdef1.h"
#include "hmd5.h"
#include "hsha.h"
#include "hrc4cons.h"
#include <hob-avl03.h>

#pragma warning(disable:4005)
#include <hob-rdpserver1.h>
#pragma warning(default:4005)

*/

#if 0
// Caller Function codes
#endif

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

#ifndef DEF_IFUNC_START
#define DEF_IFUNC_START            0        // socket has been connected
#endif
#ifndef DEF_IFUNC_CONT
#define DEF_IFUNC_CONT             1        // process data as specified
                                            // by buffer pointers
#endif
#ifndef DEF_IFUNC_CLOSE
#define DEF_IFUNC_CLOSE            2        // release buffers, do house-
                                            // keeping
#endif
/* 3 reserved for DEF_IFUNC_RESET                                      */
/* 4 reserved for DEF_IFUNC_END                                        */
/* 5 reserved for DEF_IFUNC_FROMSERVER                                 */
/* 6 reserved for DEF_IFUNC_TOSERVER                                   */

#ifndef DEF_IFUNC_REFLECT
#define DEF_IFUNC_REFLECT          7        // reflect data
#endif

#ifndef DEF_IRET_NORMAL
#define DEF_IRET_NORMAL            0        // o.k. returned
#endif

#ifndef DEF_IRET_END
#define DEF_IRET_END               1        // connection should be ended
#endif

#ifndef DEF_IRET_ERRAU
#define DEF_IRET_ERRAU             2        // fatal error occured.
#endif
/* 3 reserved for DEF_IRET_INVDA                                       */

#if 0
// NOTE: All negative returncodes also indicate a fatal error
// -----
#endif

#ifndef DEF_AUX_MEMGET
#define DEF_AUX_MEMGET             0        // get a block of memory
#endif
#ifndef DEF_AUX_MEMFREE
#define DEF_AUX_MEMFREE            1        // release a block of memory
#endif
#ifndef DEF_AUX_CONSOLE_OUT
#define DEF_AUX_CONSOLE_OUT        2        // output to console
#endif
#ifndef DEF_AUX_CO_UNICODE
#define DEF_AUX_CO_UNICODE         3        // output to console Unicode
#endif
#ifndef DEF_AUX_RADIUS_QUERY
#define DEF_AUX_RADIUS_QUERY       4        // send radius query
#endif
#ifndef DEF_AUX_RADIUS_FREE
#define DEF_AUX_RADIUS_FREE        5        // free data received from radius
#endif
/* superseded thru DEF_AUX_CHECK_IDENT ??? - 26.07.05 KB */
#ifndef DEF_AUX_CHECK_USERID
#define DEF_AUX_CHECK_USERID       6        // check userid against radius
#endif
#ifndef DEF_AUX_DISKFILE_ACCESS
#define DEF_AUX_DISKFILE_ACCESS    7        // access a disk file
#endif
#ifndef DEF_AUX_DISKFILE_RELEASE
#define DEF_AUX_DISKFILE_RELEASE   8        // release a disk file
#endif
#ifndef DEF_AUX_DISKFILE_TIME_LM
#define DEF_AUX_DISKFILE_TIME_LM   9        // time (epoch) disk file last modified
#endif
#ifndef DEF_AUX_GET_TIME
#define DEF_AUX_GET_TIME           10       // get time
#endif
#ifndef DEF_AUX_STRING_FROM_EPOCH
#define DEF_AUX_STRING_FROM_EPOCH  11       // get time as string
#endif
#ifndef DEF_AUX_EPOCH_FROM_STRING
#define DEF_AUX_EPOCH_FROM_STRING  12       /* get epoch from string   */
#endif
#ifndef DEF_AUX_GET_CERTIFICATE
#define DEF_AUX_GET_CERTIFICATE    13       /* get address certificate */
#endif
#ifndef DEF_AUX_GET_DN
#define DEF_AUX_GET_DN             14       /* get address Distinguished Name */
#endif
#ifndef DEF_AUX_TCP_CONN
#define DEF_AUX_TCP_CONN           15       /* TCP Connect to Server   */
#endif
#ifndef DEF_AUX_COM_CMA
#define DEF_AUX_COM_CMA            16       /* command common memory area */
#endif
#ifndef DEF_AUX_TCP_CLOSE
#define DEF_AUX_TCP_CLOSE          17       /* close TCP to Server     */
#endif
#ifndef DEF_AUX_QUERY_CLIENT
#define DEF_AUX_QUERY_CLIENT       18       /* query TCP client connection */
#endif
#ifndef DEF_AUX_QUERY_RECEIVE
#define DEF_AUX_QUERY_RECEIVE      19       /* query TCP data          */
#endif
#ifndef DEF_AUX_QUERY_MAIN_STR
#define DEF_AUX_QUERY_MAIN_STR     20       /* query main program for string */
#endif
#ifndef DEF_AUX_QUERY_MAIN_OPT
#define DEF_AUX_QUERY_MAIN_OPT     21       /* query main program for option */
#endif
#ifndef DEF_AUX_QUERY_MAIN_SEQ
#define DEF_AUX_QUERY_MAIN_SEQ     22       /* query main program with sequence of options */
#endif
#ifdef XYZ1 /* not necessary 21.02.05 KB */
#ifndef DEF_AUX_SET_AUTH
#define DEF_AUX_SET_AUTH           23       /* set authentication      */
#endif
#endif
#ifndef DEF_AUX_GET_AUTH
#define DEF_AUX_GET_AUTH           23       /* get authentication      */
#endif
#ifndef DEF_AUX_RANDOM_RAW
#define DEF_AUX_RANDOM_RAW         24       /* calcalute random        */
#endif
#ifndef DEF_AUX_RANDOM_BASE64
#define DEF_AUX_RANDOM_BASE64      25       /* calcalute random MIME   */
#endif
#ifndef DEF_AUX_CHECK_IDENT
#define DEF_AUX_CHECK_IDENT        26       /* check ident - authenticate */
#endif
#ifndef DEF_AUX_TIMER1_SET
#define DEF_AUX_TIMER1_SET         27       /* set timer in milliseconds */
#endif
#ifndef DEF_AUX_TIMER1_REL
#define DEF_AUX_TIMER1_REL         28       /* release timer set before */
#endif
#ifndef DEF_AUX_TIMER1_QUERY
#define DEF_AUX_TIMER1_QUERY       29       /* return struct dsd_timer1_ret */
#endif
#ifndef DEF_AUX_QUERY_GATHER
#define DEF_AUX_QUERY_GATHER       30       /* query Gather Structure, struct dsd_q_gather_1 */
#endif
#ifndef DEF_AUX_GET_SC_PROT
#define DEF_AUX_GET_SC_PROT        31       /* get Server Entry Protocol */
#endif
#ifndef DEF_AUX_COUNT_SERVENT
#define DEF_AUX_COUNT_SERVENT      32       /* count server entries    */
#endif
#ifndef DEF_AUX_GET_SERVENT
#define DEF_AUX_GET_SERVENT        33       /* get server entry        */
#endif
#ifndef DEF_AUX_RADIUS_FILL_PTTD
#define DEF_AUX_RADIUS_FILL_PTTD   34       /* fill connect Pass-Thru-to-Desktop data from Radius */
#endif
#ifndef DEF_AUX_RADIUS_GET_ATTR
#define DEF_AUX_RADIUS_GET_ATTR    35       /* get attributes from received Radius packet */
#endif
#ifndef DEF_AUX_CONN_PREPARE
#define DEF_AUX_CONN_PREPARE       36       /* prepare for connect HLWSPAT2 */
#endif
#ifndef DEF_AUX_GET_PRIV_PERS
#define DEF_AUX_GET_PRIV_PERS      37       /* return priviliges of user entry */
#endif
#ifndef DEF_AUX_SET_PRIV_SESSION
#define DEF_AUX_SET_PRIV_SESSION   38       /* set priviliges of session */
#endif
#ifndef DEF_AUX_GET_PRIV_SESSION
#define DEF_AUX_GET_PRIV_SESSION   39       /* return priviliges of session */
#endif
#ifndef DEF_AUX_PUT_SESS_STOR
#define DEF_AUX_PUT_SESS_STOR      40       /* put Session Storage     */
#endif
#ifndef DEF_AUX_GET_SESS_STOR
#define DEF_AUX_GET_SESS_STOR      41       /* get Session Storage     */
#endif
#ifndef DEF_AUX_DESCR_SESS_STOR
#define DEF_AUX_DESCR_SESS_STOR    42       /* get Session Storage Descriptor */
#endif
#ifndef DEF_AUX_QUERY_SYSADDR
#define DEF_AUX_QUERY_SYSADDR      43       /* return array with system addresses */
#endif
#ifndef DEF_AUX_GET_WORKAREA
#define DEF_AUX_GET_WORKAREA       44       /* get additional work area */
#endif
#ifndef DEF_CLIB1_CONF_SERVLI
#define DEF_CLIB1_CONF_SERVLI      0X00000001
#endif
#ifndef DEF_CLIB1_CONF_HLWSAT2
#define DEF_CLIB1_CONF_HLWSAT2     0X00000002
#endif
#ifndef DEF_CLIB1_CONF_RADIUS
#define DEF_CLIB1_CONF_RADIUS      0X00000004
#endif
#ifndef DEF_CLIB1_CONF_USERLI
#define DEF_CLIB1_CONF_USERLI      0X00000008
#endif
#ifndef HL_AUX_SIGNALS
#define HL_AUX_SIGNALS
#define HL_AUX_SIGNAL_TIMER        0X00000001
#define HL_AUX_SIGNAL_IO_1         0X00000002
#define HL_AUX_SIGNAL_IO_2         0X00000004
#define HL_AUX_SIGNAL_IO_3         0X00000008
#define HL_AUX_SIGNAL_IO_4         0X00000010
#endif

#ifndef RNS_UD_24BPP_SUPPORT
#define RNS_UD_24BPP_SUPPORT              0X0001
#endif
#ifndef RNS_UD_16BPP_SUPPORT
#define RNS_UD_16BPP_SUPPORT              0X0002
#endif
#ifndef RNS_UD_15BPP_SUPPORT
#define RNS_UD_15BPP_SUPPORT              0X0004
#endif
#ifndef RNS_UD_32BPP_SUPPORT
#define RNS_UD_32BPP_SUPPORT              0X0008
#endif
#ifndef RNS_UD_CS_WANT_32BPP_SESSION
#define RNS_UD_CS_WANT_32BPP_SESSION      0X0002
#endif

#define D_R5_ORD_NO          32             /* RDP 5 maximum order number */
#define DEF_CONST_O01_BRUSH_LEN 7           /* length of brush data    */

/* request new storage for a glyph character, pass number of bytes needed for pattern */
typedef struct dsd_glyph * ( * amd_cr_getstorglyph )( void *ap_userfld, int );
/* call server, needs glyph for the character passed as int for UTF-32 */
typedef struct dsd_glyph * ( * amd_cs_getglyph )( void *ap_userfld, void *avop_usrfld_getstorglyph, struct dsd_font *, int, amd_cr_getstorglyph );
/* 01.03.09 KB - what is amd_cr_installnewfont needed for?             */
/* request avl-tree and cache-id for a newly used font */
/* dsd_font.usc_maxwidth and dsd_font.usc_maxheight are filled before call  */
/* to tell server, which cache can be used for this font.  */
/* server fills dsd_font.dsc_htree1_avl_fo_gl and dsd_font.ucc_cacheid.     */
typedef void (* amd_cr_installnewfont) (struct dsd_font*);

enum ied_sc_command {                       /* server component command */
   ied_scc_invalid,                         /* command is invalid      */
   ied_scc_d_act_pdu,                       /* send demand active PDU  */
   ied_scc_draw_sc,                         /* draw screen-buffer      */
#ifdef OLD01
   ied_scc_mpoi_set,                        /* set mouse pointer       */
   ied_scc_mpoi_redraw,                     /* redraw mouse pointer from cache */
   ied_scc_mpoi_hide,                       /* hide mouse pointer      */
   ied_scc_mpoi_move,                       /* move mouse pointer      */
#endif
   ied_scc_vch_out,                         /* output to virtual channel */
   ied_scc_end_session,                     /* end of session server side */
   ied_scc_end_shutdown,                    /* shutdown of server      */
#ifdef SM_080618
	ied_scc_order_scrblt,						  /* screen blt primary drawing order. */
#ifdef OLD01
	ied_scc_pointer_system,                  /* pointer system. */
	ied_scc_pointer_position,                /* position pointer update pdu */
#endif
   ied_scc_mpoi_system,                     /* pointer system          */
   ied_scc_mpoi_position,                   /* position pointer update pdu */
   ied_scc_mpoi_color,                      /* color pointer update pdu */
   ied_scc_mpoi_cached,                     /* cached pointer update pdu */
   ied_scc_mpoi_pointer,                    /* new pointer update pdu  */
   ied_scc_error_info,                      /* error info pdu          */
#endif
#ifdef JB_081215
   ied_scc_order_shutdown_deny,             // <= As command dosn't need parameters, no struct is defined.
   ied_scc_order_setbounds,                 // set bounds of primary drawing order
   ied_scc_order_clearbounds,               // stopps usage of bounds for primary drawing order
   ied_scc_order_patblt,                    // draw a rectangle
   ied_scc_order_opaquerect,                // draw an opaque rect
   ied_scc_order_memblt,                    // copy cached bitmap to screen
   ied_scc_order_mem3blt,                   // copy cached bitmap to screen, 3-way raster operation
   ied_scc_order_lineto,                    // draw line
   ied_scc_order_savebitmap,                // save and restore bitmap
   ied_scc_order_drawstring,                // draw a string
   ied_scc_order_polygonsc,                 // draw a polygon, but just the lines
   ied_scc_order_polygoncb,                 // draw a filled polygon
   ied_scc_order_polyline,                  // draw a polyline
   ied_scc_order_ellipsesc,                 // draw a ellipse
   ied_scc_order_ellipsecb,                 // draw a filled ellipse
   ied_scc_order_cachebitmap,               // cache bitmap in bitmap cache
   ied_scc_order_cachebrush,                // cache brush in brush cache
   ied_scc_order_createoffbitmap,           // create an offscreen bitmap
   ied_scc_order_switchsurface,             // switch the surface, on which is drawn
   ied_scc_order_framemarker,               // switch framemarker update begin and end
   ied_scc_order_new_font,                  /* apply a new font        */
                                            /* address of struct dsd_font after command */
   ied_scc_order_delete_font,               /* delete a font           */
                                            /* address of struct dsd_font after command */
   ied_scc_change_screen,                   /* Change size, coldeph or screenbuffer */
#endif
};

enum ied_cl_command {                       /* command from client     */
   ied_clc_invalid,                         /* command is invalid      */
   ied_clc_capabilities,                    /* received capabilities   */
   ied_clc_conn_fin,                        /* Connection Finalization done */
   ied_clc_key_ud,                          /* key up or down          */
   ied_clc_mouse,                           /* mouse event             */
   ied_clc_sync,                            /* sync event              */
   ied_clc_vch_in,                          /* input from virtual channel */
   ied_clc_shutdown_requ,                   /* shutdown request from client side */
   ied_clc_end_session,                     /* end of session client side */
   ied_clc_unicode                          /* unicode event           */
};

struct dsd_sc_co1 {                         /* server component command */
   struct dsd_sc_co1 *adsc_next;            /* next in chain           */
   enum ied_sc_command iec_sc_command;      /* command type            */
};

struct dsd_cl_co1 {                         /* command from client     */
   struct dsd_cl_co1 *adsc_next;            /* next in chain           */
   enum ied_cl_command iec_cl_command;      /* command type            */
};

struct dsd_d_act_pdu {                      /* send demand active PDU  */
   int        imc_dim_x;                    /* dimension x pixels      */
   int        imc_dim_y;                    /* dimension y pixels      */
   int        imc_coldep;                   /* colour depth            */
};

struct dsd_change_screen {                  /* change size, coldeph or screenbuffer (for SM)  */
   int        imc_dim_x;                    /* dimension x pixels      */
   int        imc_dim_y;                    /* dimension y pixels      */
   int        imc_coldep;                   /* colour depth            */
   void*      ac_screen_buffer;             /* screenbuffer            */
};

struct dsd_sc_draw_sc {                     /* draw on screen          */
   int        imc_left;                     /* coordinate left         */
   int        imc_top;                      /* coordinate top          */
   int        imc_right;                    /* coordinate right        */
   int        imc_bottom;                   /* coordinate bottom       */
};

struct dsd_sc_mpoi_set {                    /* mouse pointer set       */
   short int  isc_cache_index;              /* cache index             */
   short int  isc_colour_depth;             /* colour depth            */
   short int  isc_hotspot_x;                /* Hot Spot x coordinate   */
   short int  isc_hotspot_y;                /* Hot Spot y coordinate   */
   short int  isc_width;                    /* width of cursor         */
   short int  isc_height;                   /* height of cursor        */
   short int  isc_len_xor_mask;             /* length XOR mask         */
   short int  isc_len_and_mask;             /* length AND mask         */
};

struct dsd_sc_mpoi_redraw {                 /* redraw mouse pointer from cache */
   short int  isc_cache_index;              /* cache index             */
};

struct dsd_sc_mpoi_move {                   /* move mouse pointer      */
   short int  isc_coord_x;                  /* X position              */
   short int  isc_coord_y;                  /* Y position              */
};

#ifndef DEF_HL_STR_G_I_1
#define DEF_HL_STR_G_I_1
struct dsd_gather_i_1 {                     /* gather input data       */
   struct dsd_gather_i_1 *adsc_next;        /* next in chain           */
   char *     achc_ginp_cur;                /* current position        */
   char *     achc_ginp_end;                /* end of input data       */
};
#endif

struct dsd_sc_vch_out {                     /* server sends output to virtual channel */
   struct dsd_rdp_vc_1 *adsc_rdp_vc_1;      /* RDP virtual channel     */
   struct dsd_gather_i_1 *adsc_gai1_out;    /* output data             */
   unsigned int umc_vch_ulen;               /* virtual channel length uncompressed */
   char       chrc_vch_segfl[2];            /* virtual channel segmentation flags */
};

#ifdef SM_080618

// old scrblt replaced by new one; JB 22. Jan 09
/*
struct dsd_sc_order_scrblt {                // performs a screen blt
	short int isc_left_rect;                 // left coordinate of the destination rect
	short int isc_top_rect;                  // top coordinate of the destination rect
	short int isc_width;                     // width of the destination rect
	short int isc_height;                    // height of the destination rect
	short int isc_x_src;                     // X coordinate of the source rectangle
	short int isc_y_src;                     // Y coordinate of the source rectangle
	unsigned char ucc_rop;                   // index of the ternary raster operation
   BOOL       boc_update_scrbuf;            // Specifies whether the local screen buffer should be changed.
};
*/
#ifdef OLD01
struct dsd_sc_pointer_system {              /* system pointer update pdu */
	unsigned int unc_system_pointer_type;
};

struct dsd_sc_pointer_position {            /* position pointer update pdu */
	short int isc_x_pos;
	short int isc_y_pos;
};
#endif
// 2.2.9.1.1.4.3 System Pointer Update (TS_SYSTEMPOINTERATTRIBUTE)
enum ied_sysptr{                          // enum for system mouse-pointers
   ied_sysptr_null = 0x00,                // hide the cursor
   ied_sysptr_default = 0x7F00            // Set the cursor back to the system cursor
};

/* 2.2.9.1.2.1.6                                                       */
struct dsd_sc_mpoi_system {                 /* system pointer update pdu */
   enum ied_sysptr iec_system_pointer_type;
};

/* 2.2.9.1.2.1.4  FASTPATH_UPDATETYPE_PTR_POSITION                     */
struct dsd_sc_mpoi_position {               /* position pointer update pdu */
   short int isc_x_pos;
   short int isc_y_pos;
};

struct dsd_rdp_color_ptr_attr {             /* encapsulated color pointer attributes. */
   unsigned short int usc_cache_index;      /* cache entry in the pointer cache in which to store the pointer */
   signed int isc_hotspot_x;                /* X coordinate of the pointer hotspot */
   signed int isc_hotspot_y;                /* Y coordinate of the pointer hotspot */
   unsigned short int usc_width;            /* Width of the pointer */
   unsigned short int usc_height;           /* Height of the pointer */
   unsigned short int usc_length_and_mask;  /* Size of the AND mask (in bytes) */
   unsigned short int usc_length_xor_mask;  /* Size of the XOR mask (in bytes) */
   void *     ac_xor_mask_data;             /* Contains the XOR mask (bottom-up) */
   void *     ac_and_mask_data;             /* Contains the 1 bpp AND mask (bottom-up, 2 byte boundary) */
};

/* 2.2.9.1.1.4.4 Color Pointer Update                                  */
struct dsd_sc_mpoi_color {                  /* color pointer update pdu */
   struct dsd_rdp_color_ptr_attr dsc_color_ptr_attr; /* Color pointer with a 24 bpp XOR mask (bottom-up, 2 byte boundary) */
};

/* 2.2.9.1.2.1.9 FASTPATH_UPDATETYPE_CACHED                            */
struct dsd_sc_mpoi_cached {                 /* cached pointer update pdu */
   unsigned short int usc_cache_index;      /* cache entry in the pointer cache */
};

/* 2.2.9.1.2.1.8 FASTPATH_UPDATETYPE_POINTER                           */
struct dsd_sc_mpoi_pointer {                /* new pointer update pdu */
   unsigned short int usc_xor_bpp;          /* Colordepth in bpp of the XOR mask */
   struct dsd_rdp_color_ptr_attr dsc_color_ptr_attr;  /* Color pointer with a variable colordepth in the XOR mask */
};

/* [MS-RDPBCGR] 2.2.5.1.1 */
struct dsd_sc_error_info {                  /* extended errro info pdu */
   unsigned int umc_error_info;             /* error code              */
};
#endif

#ifdef JB_081215

// +--------------------------------------------------------------------------+
// | [MS-RDPEGDI] 2.2.2.2.1.1.2 Primary Drawing Order (PRIMARY_DRAWING_ORDER) |
// +--------------------------------------------------------------------------+

// bounding rectangle of primary drawing order
// -------------------------------------------

struct dsd_sc_order_setbounds {
   // sets the bounding rectangle (= global clip) of the primary drawing order,
   // which is used for the following primary drawing orders
   signed short int isc_left;          // left bound of bounding rectangle
   signed short int isc_top;           // top bound of bounding rectangle
   signed short int isc_right;         // right bound of bounding rectangle
   signed short int isc_bottom;        // bottom bound of bounding rectangle
};
// Note:
// The order "ied_scc_order_clearbounds"
// stopps the usage of the bounding rectangle (no global clip is used any more).


// general definitions
// -------------------

// struct of an rectangle, defined by width and height:
struct dsd_rectwh{
   signed short int isc_left;
   signed short int isc_top;
   signed short int isc_width;
   signed short int isc_height;
};

#ifndef DEF_DSD_RECTRB
#define DEF_DSD_RECTRB

// struct of an rectangle, defined by right and bottom:
struct dsd_rectrb{
   signed short int isc_left;
   signed short int isc_top;
   signed short int isc_right;
   signed short int isc_bottom;
};

#endif

// struct of a brush, is used several times:
// brushstyles:
#define BMF_1BPP  0x81     // cached brush, 1 bit per pixel
#define BMF_8BPP  0x83     // cached brush, 8 bits per pixel
#define BMF_16BPP 0x84     // cached brush, 15 or 16 bits per pixel
#define BMF_24BPP 0x85     // cached brush, 24 brush per pixel
#define BS_SOLID   0x00    // solid color brush => ucc_brushhatch := 0;
#define BS_NULL    0x01    // hallow brush      => ucc_brushhatch := 0;
#define BS_HATCHED 0x02    // hatched brush => ucc_brushhatch describes hatch pattern
#define BS_PATTERN 0x03    // pattern brush => pixel pattern in chrc_brushextra and ucc_brushhatch

// brushhatches:
#define HS_HORIZONTAL 0x00
#define HS_VERTICAL   0x01
#define HS_FDIAGONAL  0x02
#define HS_BDIAGONAL  0x03
#define HS_CROSS      0x04
#define HS_DIAGCROSS  0x05

#ifdef OLD01
struct dsd_brush{
   unsigned int umc_backcolor;         // background color
   unsigned int umc_forecolor;         // foreground color

   signed char ucc_brushorgx;          // top leftmost pixel of brushpattern, x-coordinate
   signed char ucc_brushorgy;          // top leftmost pixel of brushpattern, y-coordinate
   unsigned char ucc_brushstyle;       // style of brush
   unsigned char ucc_brushhatch;       // hatched_brush info or last row of brush-pattern.
   char chrc_brushextra[7];    // pixel pattern (only needed, if ucc_brushstyle = ied_bs_pattern)
};
#endif
struct dsd_brush {
   unsigned int umc_backcolor;              /* background color        */
   unsigned int umc_forecolor;              /* foreground color        */
/* 10.08.09 KB rename to scc_ because signed */
   signed char scc_brushorgx;               /* top leftmost pixel of brushpattern, x-coordinate */
   signed char scc_brushorgy;               /* top leftmost pixel of brushpattern, y-coordinate */
   unsigned char ucc_brushstyle;            /* style of brush          */
   unsigned char ucc_brushhatch;            /* hatched_brush info or last row of brush-pattern */
   char       chrc_brushextra[7];           /* pixel pattern (only needed, if ucc_brushstyle = ied_bs_pattern) */
};

// ied_charset and dsd_unicode_string moved here by Johannes Bauer,
// 25. Feb. 09
#ifndef DEF_HL_CHARSET
/**
   hob-xsclib01.h hob-hlwspat2.h hob-rdpserver1.h hob-llog01.h
   hob-netw-01.h hob-xsltime1.h hob-xslunic1.h
*/
#define DEF_HL_CHARSET

enum ied_charset {                          /* define character set    */
   ied_chs_invalid = 0,                     /* parameter is invalid    */
   ied_chs_ascii_850,                       /* ASCII 850               */
   ied_chs_ansi_819,                        /* ANSI 819                */
   ied_chs_utf_8,                           /* Unicode UTF-8           */
   ied_chs_utf_16,                          /* Unicode UTF-16 = WCHAR  */
   ied_chs_be_utf_16,                       /* Unicode UTF-16 big endian */
   ied_chs_le_utf_16,                       /* Unicode UTF-16 little endian */
   ied_chs_utf_32,                          /* Unicode UTF-32          */
   ied_chs_be_utf_32,                       /* Unicode UTF-32 big endian */
   ied_chs_le_utf_32,                       /* Unicode UTF-32 little endian */
   ied_chs_html_1                           /* HTML character set      */
};

struct dsd_unicode_string {                 /* unicode string          */
   void *     ac_str;                       /* address of string       */
   int        imc_len_str;                  /* length string in elements */
   enum ied_charset iec_chs_str;            /* character set string    */
};
#endif


// [MS-DSPEGDI] 2.2.2.2.1.2.6.1 Cache Glyph Data - Revision 2 (TS_CACHE_GLYPH_DATA_REV2)
// note: as glyphs always have the colordeph 1, the colordeph is not reported here
//
// The glyph data (*aucc_glyphdata points to) is stored as described in [MS-DSPEGDI], 2.2.2.2.1.2.6.1 Cache Glyph Data:
// The individual scan lines are encoded in top-down order, and each scan line MUST be byte-aligned.
// Once the array has been populated with bitmap data, it MUST be padded to a double-word boundary
// (the size of the structure in bytes MUST be a multiple of 4). The size in bytes of the glyph data
// is given by the following function: ((usc_cx + 7) / 8) * usc_cy

// This structure is used by fastglyph and cacheglyph.
// usc_distance: empty for cacheglyph
//
// for fastglyph the clients only needs ucc_cacheindex and usc_distance, but the
// server needs the rest of the information, to put the glyph correctly on the offset-screen.

struct dsd_fo_gl_avl {
   struct dsd_htree1_avl_entry dsc_avl_e;
   int        imc_unicode;                  /* UTF-32 of character     */
};

struct dsd_glyph {
   struct dsd_fo_gl_avl dsc_fo_gl_avl;
   struct dsd_font *adsc_font;              /* font it belongs to or NULL if deleted */
   struct dsd_glyph *adsc_rem_ch_prev;      /* previous in remove chain */
   struct dsd_glyph *adsc_rem_ch_next;      /* next in remove chain    */
   unsigned int umc_count_glyph_alloc;      /* count glyph allocs      */
   unsigned char ucc_char_inc;              /* character index         */
   unsigned char ucc_arr_glyph_e;           /* array glyph entry       */
   unsigned short usc_distance;        // distance between beginning of this glyph and beginning of next glyph
                                       // (not needed for monospaced fonts)
   signed short int usc_x;             // x-offset of glyph (RDP: "x-coordinate of glyph within the glyph bitmap")
   signed short int usc_y;             // y-offset of glyph (RDP: "y-coordinate of glyph within the glyph bitmap")
   unsigned short int usc_cx;          // width  of glyph bitmap in pixels
   unsigned short int usc_cy;          // height of glyph bitmap in pixels
   // Note: colordeph of glyphs is 1
   unsigned short int usc_scanline;    // width of a scanline in glyph data, in bytes

   // Glyph pattern is expected to be stored right after this structure!
   // size of glyph-pattern in bytes: ((usc_cx + 7) / 8) * usc_cy
};

// structure of a font
struct dsd_font {
   struct dsd_htree1_avl_cntl dsc_htree1_avl_fo_gl;
   amd_cs_getglyph amc_cs_getglyph;         /* called to created a new glyph */
#ifndef TO_BE_REMOVED_091224
   unsigned char ucc_last_char_inc;         /* last character index    */
   unsigned char ucc_cacheid;
#endif
   unsigned short usc_maxwidth;        // maximal width and height of glyphs of this font in pixels is needed
   unsigned short usc_maxheight;       // to know, in which cache the font should be stored in.
   unsigned char ucc_ulcharinc;        // Advance width for glyphs (monospace font). =0 if font isn't monospaced
};

// drawing of Glyphs
// -----------------
// RDP-Accelerator handels the caching of the clyphs and the fragment cache.
// The RDP-Commands
// [MS-RDPEGDI] 2.2.2.2.1.1.2.14 FastIndex (FASTINDEX_ORDER)
// [MS-RDPEGDI] 2.2.2.2.1.1.2.15 FastGlyph (FASTGLYPH_ORDER)
// (needed??) [MS-RDPEGDI] 2.2.2.2.1.2.6.1 Cache Glyph Data - Revision 2 (TS_CACHE_GLYPH_DATA_REV2)
// are directly addressed by the RDP-Accelerator.
enum ied_sc_glyph_flaccel{                      // enum for the ucc_flaccel field of dsd_sc_order_fastindex
   ied_scc_flag_default_placement = 0x01,       // flag MUST be set
   ied_scc_so_horizontal = 0x02,                // Text is horizontal
   ied_scc_so_vertical   = 0x04,                // Text is vertical
   ied_scc_so_reversed   = 0x08,                // if set, rigth to left(horizontal) or bootm to top (vertical)
   ied_scc_zero_bearings = 0x10,                // left side bearing and right side bearing are 0
   ied_scc_so_char_inc_equal_bm_base = 0x20,    // width of glyph equals advance with of glyph
   ied_scc_so_maxext_bm_side = 0x40             // height of glyph equals sum of ascend and descent
};

struct dsd_sc_order_drawstring {
   struct dsd_unicode_string dsc_unicode_string;  // String, which has to be drawn
   struct dsd_font *adsc_font;                  // font, the string is drawn in.

   signed short int isc_glyph_x;                // starting point of first glyph, x-coordinate
   signed short int isc_glyph_y;                // starting point of first glyph, y-coordinate

   int ucc_flaccel;                             // accelerator flags (high byte of fDrawing)
   unsigned int umc_forecolor;                  // foreground color
   unsigned int umc_backcolor;                  // background color

   struct dsd_rectrb dsc_backrect;              // text background rectangle, like a clip
   struct dsd_rectrb dsc_opaqrect;              // opaque rectangle

   BOOL boc_has_bounds;                         // true, if order has a bounding rectangle (=TS_BOUNDS flag of primary drawing order)
   BOOL boc_update_scrbuf;                      // Specifies whether the local screen buffer should be changed.

};

// structure of a cached bitmap:
struct dsd_bitmap{
   unsigned short int usc_width;                // width of bitmap in pixels
   unsigned short int usc_height;               // height of bitmap in pixels
// 26.08.09 JB scanline can be negative to switch between top-to-bottom and bottom-to-top
   signed short int isc_scanline;               // width of a scanline, in bytes
// 25.01.09 KB please leave colour-depth signed
   signed short int  isc_cl_coldep;             // colordeph of bitmap: 15, 16, 24 or 32
   unsigned char *aucc_buffer;                  // pointer to buffer with bitmap data
};

// raster operations
// 2.2.2.2.1.1.1.6 Binary Raster Operation (ROP2_OPERATION)
// Note: This are RDP's indeces for raster operations, which start at 0x01.
enum ied_sc_rop2_operation{
   ied_scc_r2_black       = 0x01, // 0
   ied_scc_r2_notmergepen = 0x02, // DPon
   ied_scc_r2_masknotpen  = 0x03, // DPna
   ied_scc_r2_notcopypen  = 0x04, // Pn
   ied_scc_r2_maskpennot  = 0x05, // PDna
   ied_scc_r2_not         = 0x06, // Dn
   ied_scc_r2_xorpen      = 0x07, // DPx
   ied_scc_r2_notmaskpen  = 0x08, // DPan
   ied_scc_r2_maskpen     = 0x09, // DPa
   ied_scc_r2_notxorpen   = 0x0A, // DPon
   ied_scc_r2_nop         = 0x0B, // D
   ied_scc_r2_mergenotpen = 0x0C, // DPno
   ied_scc_r2_copypen     = 0x0D, // P
   ied_scc_r2_mergepennot = 0x0E, // PDno
   ied_scc_r2_mergepen    = 0x0F, // PDo
   ied_scc_r2_white       = 0x10  // 1
};
// 2.2.2.2.1.1.1.7 Ternary Raster Operation Index (ROP3_OPERATION_INDEX)
// as there are 255 ternary Raster Operations, whichs names are not self-explanatory
// like the Binary Raster Operation's are, an enum wouldn't really make things easier.
// We just send RDP's index numbers.
// Note: ternary raster operations can be expressed by binary raster operations.

// 2.2.2.2.1.1.2.1 DstBlt (DSTBLT_ORDER)              => not needet for now, as Java doesn't support
// 2.2.2.2.1.1.2.2 MultiDstBlt (MULTI_DSTBLT_ORDER)   => raster operations, which only depend on the destination

// [MS-RDPEGDI] 2.2.2.2.1.1.2.3 PatBlt (PATBLT_ORDER)
// --------------------------------------------------
// draw a rectangle
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rdpui_jsb24.java] public void pat_blt, calls
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rop.java] public static void bit_blt3(
//    byte[], int, int, int,	int, int, byte[], int, int, int, int)

struct dsd_sc_order_patblt {
   struct dsd_rectwh dsc_rectangle;             // rectangle to be painted
   unsigned char ucc_brop3;                     // index of the ternary raster operation
   struct dsd_brush dsc_brush;                  // brush for the rectangle
   BOOL boc_has_bounds;                         // true, if order has a bounding rectangle (=TS_BOUNDS flag of primary drawing order)
   BOOL boc_update_scrbuf;                      // Specifies whether the local screen buffer should be changed.
};

// [MS-RDPEGDI] 2.2.2.2.1.1.2.4 MultiPatBlt (MULTI_PATBLT_ORDER)
// -> done by rdp acc

// [MS-RDPEGDI] 2.2.2.2.1.1.2.5 OpaqueRect (OPAQUERECT_ORDER)
// ----------------------------------------------------------
// draw rectangle without brush, and without raster operation.
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rdpui_jsb24.java] public void fill_rect, calls
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rop.java] public static void fill3(
//    byte[], int, int, int, int, int, int)

struct dsd_sc_order_opaquerect{
   struct dsd_rectwh dsc_rectangle;             // destination rectangle, which has to be drawn.
   unsigned int umc_color;                      // color of rectangle
   int  imc_no_color_bytes;                     // number of bytes valid in color field
   BOOL boc_has_bounds;                         // true, if order has a bounding rectangle (=TS_BOUNDS flag of primary drawing order)
   BOOL boc_update_scrbuf;                      // Specifies whether the local screen buffer should be changed.
};

// [MS-RDPEGDI] 2.2.2.2.1.1.2.6 MultiOpaqueRect (MULTI_OPAQUERECT_ORDER)
// -> done by rdp acc

// [MS-RDPEGDI] 2.2.2.2.1.1.2.7 ScrBlt (SCRBLT_ORDER)
// --------------------------------------------------
// copy area of screen
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rdpui_jsb24.java] public void screen_blt, calls
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rop.java] public static void bit_blt3(
//    byte[], int, int, int,	int, int, byte[], int, int, int, int)
// ==>> Order changed!! Order existed before, but without rectangle-structure!
struct dsd_sc_order_scrblt {
   struct dsd_rectwh dsc_rectangle;             // destination area
   unsigned char ucc_brop3;                     // index of the ternary raster operation
   signed short int isc_x_src;                  // X coordinate of the source rectangle
   signed short int isc_y_src;                  // Y coordinate of the source rectangle
   BOOL boc_has_bounds;                         // true, if order has a bounding rectangle (=TS_BOUNDS flag of primary drawing order)
   BOOL boc_update_scrbuf;                      // Specifies whether the local screen buffer should be changed.
};

// [MS-RDPEGDI] 2.2.2.2.1.1.2.8 MultiScrBlt (MULTI_SCRBLT_ORDER)
// -> RDP accellerator combines several ScrBlt's, if possible.

// [MS-RDPEGDI] 2.2.2.2.1.1.2.9 MemBlt (MEMBLT_ORDER)
// --------------------------------------------------
// copy cached bitmap to screen
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rdpui_jsb24.java] public void mem_blt, calls
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rop.java] public static void bit_blt3(
//    byte[], int, int, int,	int, int, byte[], int, int, int, int)
enum ied_sc_memblt{
   ied_scc_bitmapcache_screen_id = 0xff,
   ied_scc_bitmapcache_waiting_list_index = 0x7fff
};
struct dsd_sc_order_memblt{
   unsigned char ucc_index_colortable;          // high-byte of cacheid, not used so far
   unsigned char ucc_id_bitmapcache;            // low-byte of cacheid, if = ied_bitmapcache_screen_id than
                                                // ucc_cacheindex contains index of entry in offset bitmap cache
   struct dsd_rectwh dsc_destination_rec;       // destination rectangle
	unsigned char ucc_brop3;                     // index of the ternary raster operation
   signed short int isc_x_src;                  // x-coordinate of source bitmap in cache of client
   signed short int isc_y_src;                  // inverted y-coordinate of source bitmap in cache of client
   unsigned short int usc_cacheindex;           // index of bitmap within the bitmap cache of client,
                                                // if = ied_bitmapcache_waiting_list_index => take last bitmap cache entry
   struct dsd_bitmap dsc_cached_bitmap;         // bitmap, located in servers bitmap-cache, to be copied to screen buffer
                                                // on server side
   BOOL boc_has_bounds;                         // true, if order has a bounding rectangle (=TS_BOUNDS flag of primary drawing order)
   BOOL boc_update_scrbuf;                      // Specifies whether the local screen buffer should be changed.
                                                // Note: if boc_updat_scrbuf = false, the structure
                                                //       dsc_cached_bitmap is not used.
};

// [MS-RDPEGDI] 2.2.2.2.1.1.2.10 Mem3Blt (MEM3BLT_ORDER)
// -----------------------------------------------------
// render cached bitmap to screen with 3-way raster operation
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rdpui_jsb24.java] public void mem3_blt, calls
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rop.java] public static void bit_blt3(
//    byte[], int, int, int, int, int, byte[], int, int, int, byte[], int,	int, int, int) <= other signature than above
struct dsd_sc_order_mem3blt{
   unsigned char ucc_index_colortable;          // high-byte of cacheid, not used so far
   unsigned char ucc_id_bitmapcache;            // low-byte of cacheid, if = ied_bitmapcache_screen_id than
                                                // ucc_cacheindex contains index of entry in offset bitmap cache
   struct dsd_rectwh dsc_destination_rec;       // destination rectangle
   unsigned char ucc_brop3;                     // index of the ternary raster operation
   signed short int isc_x_src;                  // x-coordinate of source bitmap in cache of client
   signed short int isc_y_src;                  // inverted y-coordinate of source bitmap in cache of client
   struct dsd_brush dsc_brush;                  // brush
   unsigned short int usc_cacheindex;           // index of bitmap within the bitmap cache of client,
                                                // if = ied_bitmapcache_waiting_list_index => take last bitmap cache entry
#ifdef OLD01
   struct dsd_bitmap dsc_cached_bitmap;         // bitmap, located in servers bitmap-cache, to be copied to screen buffer
                                                // on server side
#endif
   BOOL boc_has_bounds;                         // true, if order has a bounding rectangle (=TS_BOUNDS flag of primary drawing order)
   BOOL boc_update_scrbuf;                      // Specifies whether the local screen buffer should be changed.
                                                // Note: if boc_updat_scrbuf = false, the structure
                                                //       dsc_cached_bitmap is not used.
};

// [MS-RDPEGDI] 2.2.2.2.1.1.2.11 LineTo (LINETO_ORDER)
// ---------------------------------------------------
// draw a line
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rdpui_jsb24.java] public void draw_line, calls
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rop.java] public static void bresenham_line3
enum ied_sc_lineto_backmode{
   ied_scc_transparent = 0x0001,
   ied_scc_opaque      = 0x0002
};
struct dsd_sc_order_lineto{
   enum ied_sc_lineto_backmode iec_backmode;    // mode of background: transparent or opaque
   signed short int isc_nxstart;                // starting point of the line, x-coordinate
   signed short int isc_nystart;                // starting point of the line, y-coordinate
   signed short int isc_nxend;                  // end point of the line, x-coordinate
   signed short int isc_nyend;                  // end point of the line, y-coordinate
   //unsigned int imc_back_color;               // background color-> field must be zeroed out -> sense?
   enum ied_sc_rop2_operation iec_brop2;        // binary raster operation
   //unsigned char ucc_penstyle;                // PenStyle must be PS_SOLID(0x00)
   //unsigned char ucc_penwith;                 // PenWidth must be 0x01.
   unsigned int imc_pencolor;                   // color of the drawn line
   BOOL boc_has_bounds;                         // true, if order has a bounding rectangle (=TS_BOUNDS flag of primary drawing order)
   BOOL boc_update_scrbuf;                      // Specifies whether the local screen buffer should be changed.
};

// [MS-RDPEGDI] 2.2.2.2.1.1.2.12 SaveBitmap (SAVEBITMAP_ORDER)
// -----------------------------------------------------------
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rdpui_jsb24.java] public void save_desktop
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rdpui_jsb24.java] public void restore_desktop
enum ied_sc_savebitmap_operation{
   ied_scc_sv_savebits = 0x00,                  // save bitmap operation
   ied_scc_sv_restorebits = 0x01                // restore bitmap operation
};
struct dsd_sc_order_savebitmap{
   unsigned int umc_savedbitmapposition;        // encoded start position of the rectangle in the saved bitmap
   struct dsd_rectrb dsc_rectangle;             // virtual desktop rectangle to save or to restore from
   enum ied_sc_savebitmap_operation ucc_operation;// operation: either ied_sv_savebits or ied_sv_restorebits
#ifdef OLD01
   unsigned char *aucc_buffer;                  // pointer to screenbuffer on server-side
#endif
   BOOL boc_has_bounds;                         // true, if order has a bounding rectangle (=TS_BOUNDS flag of primary drawing order)
   BOOL boc_update_scrbuf;                      // Specifies whether the local screen buffer should be changed.
                                                // only important, if ied_sc_savebitmap_operation = ied_scc_sv_restorebits
};


// [MS-RDPEGDI] 2.2.2.2.1.1.2.16 PolygonSC (POLYGON_SC_ORDER)
// ----------------------------------------------------------
// draw a filled Polygon with an opaque color.
// (Note: For drawing the outline of a Polygon use dsd_sc_order_polyline)
// definition of a point, which uses signed shorts, as described in 2.2.2.2.1.1.1.1 Coord Field (COORD_FIELD)
#ifndef DEF_DSD_SHORT_POINT
#define DEF_DSD_SHORT_POINT
struct dsd_short_point{
   signed short isc_x;  // x-coordinate of point
   signed short isc_y;  // y-coordinate of point
};
#endif
#ifndef DEF_IED_SC_POLYGON_FILLMODE
#define DEF_IED_SC_POLYGON_FILLMODE
// fillmode of polygon, [compare to [MS-RDPEGDI] 2.2.2.2.1.1.1.9 Fill Mode (FILL_MODE)]
enum ied_sc_polygon_fillmode{
   ied_pfm_alternate = 0x01,   // alternate fill mode (wrong description in [MS-RDPEGDI]! 0x01 is correct!)
   ied_pfm_winding   = 0x02    //   winding fill mode (wrong description in [MS-RDPEGDI]! 0x01 is correct!)
};
#endif
// note for polygon and polyline:
// unlike the RDP-command, the starting point is not reported seperately,
// but is just the first point in the list of points.
// The points are reported in normal coordinates.
// the special report of the first point and the conversion to
// deltavalues need to be done by the RDP-accellerator
struct dsd_sc_order_polygonsc{
   enum ied_sc_rop2_operation iec_brop2;        // binary raster operation
   enum ied_sc_polygon_fillmode iec_fillmode;   // fillmode of polygon
   unsigned int umc_brushcolor;                 // color of the polygon

   unsigned char ucc_numpoints;                 // number of points, excluding start point (=NumDeltaEntries)
   // IMPORTANT NOTE: ucc_numpoints has to be < 33! (otherwise error in MS Remote Desktop Connection)
   // For a solution for more than 33 points contact Johannes Bauer or see file E:\AKBI62\bauer\polygon.hpp

   struct dsd_short_point* adsc_points;         // pointer to array of points, len of array is ucc_numpoints
   BOOL boc_has_bounds;                         // true, if order has a bounding rectangle (=TS_BOUNDS flag of primary drawing order)
   BOOL boc_update_scrbuf;                      // specifies whether the local screen buffer should be changed.
};

// [MS-RDPEGDI] 2.2.2.2.1.1.2.17 PolygonCB (POLYGON_CB_ORDER)
// ----------------------------------------------------------
// draws a filled polygon width a brush.
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rdpui_jsb24.java] public void fill_polygon(
// int, int, c_point[], int, int, int, c_brush, int, int)
struct dsd_sc_order_polygoncb{
   enum ied_sc_rop2_operation iec_brop2;        // binary raster operation
   enum ied_sc_polygon_fillmode iec_fillmode;   // fillmode of polygon
   struct dsd_brush dsc_brush;                  // brush for polygon

   unsigned char ucc_numpoints;                 // number of points, excluding first point (=NumDeltaEntries)
   // IMPORTANT NOTE: ucc_numpoints has to be < 33! (otherwise error in MS Remote Desktop Connection)
   // For a solution for more than 33 points contact Johannes Bauer or see file E:\AKBI62\bauer\polygon.hpp

   struct dsd_short_point* adsc_points;         // pointer to array of points, len of array is ucc_numpoints
   BOOL boc_has_bounds;                         // true, if order has a bounding rectangle (=TS_BOUNDS flag of primary drawing order)
   BOOL boc_update_scrbuf;                      // specifies whether the local screen buffer should be changed.
};

// [MS-RDPEGDI] 2.2.2.2.1.1.2.18 Polyline (POLYLINE_ORDER)
// -------------------------------------------------------
// draws a polyline
// I didn't find a special polygon-command in JWT, so I guess, this is just done
// by the same routine as LineTo;
struct dsd_sc_order_polyline{
   enum ied_sc_rop2_operation iec_brop2;        // binary raster operation
   // BrushCacheEntry is always 0, doesn't have to be reported to RDP-ACC
   unsigned int umc_pencolor;                   // color of the polygon
   unsigned char ucc_numpoints;                 // number of points, excluding first point (=NumDeltaEntries)
   struct dsd_short_point* adsc_points;         // pointer to array of points, len of array is ucc_numpoints
   BOOL boc_has_bounds;                         // true, if order has a bounding rectangle (=TS_BOUNDS flag of primary drawing order)
   BOOL boc_update_scrbuf;                      // specifies whether the local screen buffer should be changed.
};

// [MS-RDPEGDI] 2.2.2.2.1.1.2.19 EllipseSC (ELLIPSE_SC_ORDER)
// ----------------------------------------------------------
// draws a single-colored eclipse, either filled or not (specified in fillmode)
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rdpui_jsb24.java] public void draw_ellipse, calls
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rop.java] public static void bresenham_ellipse3(
// int, int, int, int, int, int, int, int, byte[], int, int, int, boolean)
enum ied_sc_ellipse_fillmode{
   ied_pfm_drawellipse = 0x00,   // draw the ellipse
   ied_pfm_fillelipse  = 0x01    // draw a filled ellipse
};
struct dsd_sc_order_ellipsesc{
   struct dsd_rectrb dsc_increct;               // inclusive rectangle for the ellipse
   enum ied_sc_rop2_operation iec_brop2;        // binary raster operation
   enum ied_sc_ellipse_fillmode iec_fillmode;   // fillmode of ellipse
   unsigned int umc_pencolor;                   // color of the ellipse
   BOOL boc_has_bounds;                         // true, if order has a bounding rectangle (=TS_BOUNDS flag of primary drawing order)
   BOOL boc_update_scrbuf;                      // specifies whether the local screen buffer should be changed.
};

// [MS-RDPEGDI] 2.2.2.2.1.1.2.20 EllipseCB (ELLIPSE_CB_ORDER)
// ----------------------------------------------------------
// draws an ellipse with a brush
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rdpui_jsb24.java] public void fill_ellipse, calls
// [F:\martin\jwt33\svn\hob\rdp\ui\jsb\c_rop.java] public static void bresenham_ellipse3(
// int, int, int, int, int, int, int, int, byte[], int, int, int, boolean)
struct dsd_sc_order_ellipsecb{
   struct dsd_rectrb dsc_increct;               // inclusive rectangle for the ellipse
   enum ied_sc_rop2_operation iec_brop2;        // binary raster operation
   // NOTE: incorrect explanation in MS-manual.
   // fillmode ied_pfm_drawellipse doesn't make any sense for this command. AWT reports an error.
   // => @KB:
   // As there is no real choice here, but just the potential to cause an error, I decided to
   // erase this field from the structure.
   // Please just set this field to 0x01 (ied_pfm_fillelipse).
   //enum ied_sc_ellipse_fillmode iec_fillmode;   // fillmode of ellipse
   struct dsd_brush dsc_brush;                  // brush for the ellipse
   BOOL boc_has_bounds;                         // true, if order has a bounding rectangle (=TS_BOUNDS flag of primary drawing order)
   BOOL boc_update_scrbuf;                      // specifies whether the local screen buffer should be changed.
};

// [MS-RDPEGDI] 2.2.2.2.1.1.2.21 DrawNineGrid (DRAWNINEGRID_ORDER)            => NineGrit Bitmaps are not
// [MS-RDPEGDI] 2.2.2.2.1.1.2.22 MultiDrawNineGrid (MULTI_DRAWNINEGRID_ORDER) => needed so far.

// +---------------------------------------------------+
// | [MS-RDPEGDI] 2.2.2.2.1.2 Secondary Drawing Orders |
// +---------------------------------------------------+

// [MS-RDPEGDI] 2.2.2.2.1.2.3 Cache Bitmap - Revision 2 (CACHE_BITMAP_REV2_ORDER)
//-------------------------------------------------------------------------------
// Notes:
// -> revision 1 is not needed any more, as we can use revision 2.
// -> data is handed to RDP-ACC uncompressed. RDP-ACC decides, if bitmap gets compressed.
enum ied_sc_bitsperpixel{     // enum for bitmap-colordeph
   ied_scc_cbr2_1bpp  = 0x01,
   ied_scc_cbr2_2bpp  = 0x02,
   ied_scc_cbr2_8bpp  = 0x03,
   ied_scc_cbr2_16bpp = 0x04,
   ied_scc_cbr2_24bpp = 0x05,
   ied_scc_cbr2_32bpp = 0x06
};

enum ied_sc_compression {
   ied_scc_compression_raw = 0,
   ied_scc_compression_rdp
};

struct dsd_sc_order_cachebitmap{
   unsigned char ucc_cacheid;                   // cache, in which the bitmap is stored. unsigend 3-bit int
   enum ied_sc_bitsperpixel iec_bitsperpixelid; // 4-bit unsigend integer, index of bitsperpixel

   // the flags-flied needs to be constructed by RDP-ACC:
   // CBR2_HEIGHT_SAME_AS_WIDTH: set by RDP-ACC
   BOOL boc_bitmapispersistent;  // if TRUE, umc_key1 and umc_key2 are the persistent bitmap cache key
                                 // if FALSE, umc_key1 and umc_key2 are not used and not sent to the client
   BOOL boc_donotcache;          // if TRUE, cacheindexfield is ignored, bitmap is savend in last entry of bitmap cache
   unsigned int umc_key1;        // persistent bitmap cache key 1
   unsigned int umc_key2;        // persistent bitmap cache key 2

   enum ied_sc_compression iec_compression;     // if compressed, scanline in dsc_bitmap ist length of data
   struct dsd_bitmap dsc_bitmap;                // structure, describing source data
   unsigned short int usc_bitmapindex;          // cacheindex: index in cache, where bitmap has to be saved
/* 14.03.09 KB - maybe we should specify if the bitmap should be compressed by RDP-ACC */
#ifdef OLD01
/* 14.03.09 KB - makes no sense */
   BOOL       boc_update_scrbuf;                // specifies whether the local screen buffer should be changed.
#endif
};

#define GET_D_ADSL_RCO1(DSD_CALL_RDPSERV_1) (DSD_CALL_RDPSERV_1)->adsc_rdp_co
#define GET_CAPS(DSD_CALL_RDPSERV_1) GET_D_ADSL_RCO1(DSD_CALL_RDPSERV_1)->dsc_caps
#define SECONDARY_ORDER_HEADER_SIZE (2 + 2 + 1 + 5)
#define MAX_CACHEBITMAP_DATA(DSD_CALL_RDPSERV_1, BO_PERSISTENT) (GET_D_ADSL_RCO1(DSD_CALL_RDPSERV_1)->imc_max_ts_fp_update_size - \
    (SECONDARY_ORDER_HEADER_SIZE + (BO_PERSISTENT ? 8 : 0) + 10 + GET_CAPS(DSD_CALL_RDPSERV_1).dsc_general.boc_no_bitmap_compreession_hdr ? 8 : 0))
#define MAX_CACHEBRUSH_DATA(DSD_CALL_RDPSERV_1) (GET_D_ADSL_RCO1(DSD_CALL_RDPSERV_1)->imc_max_ts_fp_update_size - \
   (SECONDARY_ORDER_HEADER_SIZE + 6))

// [MS-RDPEGDI] 2.2.2.2.1.2.4 Cache Color Table (CACHE_COLOR_TABLE_ORDER) => not supported

// [MS-RDPEGDI] 2.2.2.2.1.2.6.1 Cache Glyph Data - Revision 2 (TS_CACHE_GLYPH_DATA_REV2)
// => done by the RDP-Accelerator (see dsd_sc_order_drawstring)

// [MS-RDPEGDI] 2.2.2.2.1.2.7 Cache Brush (CACHE_BRUSH_ORDER)
// 25.01.2011 JB. For Stefan Martin, who needs this for optimizing MacGate
struct dsd_sc_order_cachebrush{
   unsigned char ucc_cacheid;                   // cache, in which the bitmap is stored. unsigend 3-bit int
   struct dsd_bitmap dsc_bitmap;                // structure, describing source data
   unsigned int *aum_colormap;                  // pointer to colormap (only 4 color-brushes)
};

// [MS-RDPEGDI] 2.2.2.2.1.2.7.1 Compressed Color Brush (COMPRESSED_COLOR_BRUSH) => not needed yet

// +-------------------------------------------------------------+
// | [MS-RDPEGDI] 2.2.2.2.1.3 Alternate Secondary Drawing Orders |
// +-------------------------------------------------------------+

// [MS-RDPEGDI] 2.2.2.2.1.3.2 Create Offscreen Bitmap (CREATE_OFFSCR_BITMAP_ORDER)
struct dsd_sc_order_createoffbitmap{
   unsigned short int usc_offscreenbitmapid;    // the entry in the cache, where the bitmap is created
   unsigned short int usc_cx;                   // width of bitmap in pixels
   unsigned short int usc_cy;                   // height of bitmap in pixels

   unsigned short int usc_numdelindices;        // number of indices of bitmaps to be deleted (=cIndices)
   // The indices of the offsceen-bitmaps to be deleted are stored right after this structure
   // as unsigned shorts.

   // the following pointer is not used any more, as the indices are saved directly after the structure:
   //unsigned short int *ausrc_delindices;      // pointer to array (len = usc_numdelindices) of indices of
                                                // bitmaps to be deleted
};

// [MS-RDPEGDI] 2.2.2.2.1.3.3 Switch Surface (SWITCH_SURFACE_ORDER)
// switch output surface to screen or to offset-image
enum ied_sc_surface{
   screen_bitmap_surface=0xffff
};
struct dsd_sc_order_switchsurface{
   unsigned short int usc_bitmapid;             // offset bitmap id, or screen_bitmap_surface
   struct dsd_bitmap dsc_offsetbutter;          // structure, which describes the cache for the offset
                                                // screen on the server-side, so that rdp-ACC knows, where
                                                // to draw to.
                                                // empty, if usc_bitmapid=screen_bitmap_surface
};

// [MS-RDPEGDI] 2.2.2.2.1.3.7 Frame Marker
// set begin and end for frame marker
enum ied_sc_framemarker{
   ied_scc_frame_start = 0x0,
   ied_scc_frame_end   = 0x1
};
struct dsd_sc_order_framemarker{
   ied_sc_framemarker iec_action;
};

// [MS-RDPEGDI] 2.2.2.2.1.3.4 Create NineGrid Bitmap (CREATE_NINEGRID_BITMAP_ORDER) => not supported
// [MS-RDPEGDI] 2.2.2.2.1.3.4.1 NineGrid Bitmap Information (NINEGRID_BITMAP_INFO)  => not supported



#endif // #ifdef JB_081215

struct dsd_cl_keyb_eve {                    /* client sends keyboard event */
   unsigned char ucc_keyboard_status;       /* last keyboard status    */
   char       chc_flags;                    /* flags                   */
   char       chc_keycode;                  /* key code                */
};

struct dsd_cl_unicode_eve {                 /* client sends unicode keyboard event */
   unsigned short int usc_unicode;          /* unicode of the event */
};

enum ied_cl_mouse_eve {
   ied_cl_mouse_moved,
   ied_cl_mouse_button_left, 
   ied_cl_mouse_button_middle, 
   ied_cl_mouse_button_right, 
   ied_cl_mouse_button_x1, 
   ied_cl_mouse_button_x2, 
   ied_cl_mouse_wheel
};

struct dsd_cl_mouse_eve {                   /* client sends mouse event */
   char             chc_flags;              /* flags: old flags. use iec_type and boc_button_pressed instead */
   signed short int isc_mousewheel_value;   /* value of the move. negative: wheel was moved down. positive: wheel was moved up */
   ied_cl_mouse_eve iec_type;               /* type of the event       */
   BOOL             boc_button_pressed;     /* TRUE, if the button was pressed or the mousewheel was moved down */
   short int        isc_coord_x;            /* x coordinate            */
   short int        isc_coord_y;            /* y coordinate            */
};

struct dsd_cl_sync_eve {                    /* client sends sync event */
   char chc_flags;                          /* flags */
};

struct dsd_cl_vch_in {                      /* client sends input from virtual channel */
   struct dsd_rdp_vc_1 *adsc_rdp_vc_1;      /* RDP virtual channel     */
   struct dsd_gather_i_1 *adsc_gai1_in;     /* input data              */
   unsigned int umc_vch_ulen;               /* virtual channel length uncompressed */
   char       chrc_vch_segfl[2];            /* virtual channel segmentation flags */
};

#ifdef B100528
/**
  structure to query if a Gather Structure (struct dsd_gather_i_1)
  is still being sent, that means active and waiting to get processed.
  when imc_set_signal is not zero, there will be a Signal when this
  Gather Structure has been processed and is no more active.
*/
struct dsd_q_gather_1 {                     /* query gather active     */
   void *     ac_gather;                    /* address of gather structure */
   BOOL       boc_still_active;             /* return TRUE if still active */
   int        imc_set_signal;               /* set Signal when no more active */
};
#endif

#ifndef DEF_GET_WA
#define DEF_GET_WA
struct dsd_aux_get_workarea {               /* acquire additional work area */
   char *     achc_work_area;               /* addr work-area returned */
   int        imc_len_work_area;            /* length work-area returned */
};
#endif

struct dsd_rdp_vc_1 {                       /* RDP virtual channel     */
   char       byrc_name[8];                 /* name of channel         */
   int        imc_flags;                    /* flags                   */
   unsigned short int usc_vch_no;           /* virtual channel no com  */
};

typedef struct {
   unsigned short int ibc_contchno : 1;     /* control channel defined */
   unsigned short int filler : 15;          /* filler                  */
} dtd_rdpfl_1;

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

//#ifdef B100103
struct dsd_ord_co_1 {                       /* order coordinates       */
   int        imc_left;                     /* coordinate              */
   int        imc_top;                      /* coordinate              */
   int        imc_dim_x_2;                  /* coordinate right or width */
   int        imc_dim_y_2;                  /* coordinate bottom or height */
   int        imc_source_x;                 /* coordinate              */
   int        imc_source_y;                 /* coordinate              */
   int        inc_cache_id;                 /* cache id                */
   int        inc_cache_ind;                /* cache index             */
                                            /* bitmap ??? */
   int        imc_no_rect;                  /* number of rectangles    */
   int        imc_no_byte;                  /* number of bytes         */
   char       chc_rop;                      /* raster operation        */
// BOOL       boc_free;                     /* has to free memory      */
};
//#endif

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.3 PatBlt (PATBLT_ORDER)                  */
struct dsd_ord_co_o01 {                     /* order O01 coordinates   */
   BOOL       boc_set;                      /* variables have been set */
   unsigned char ucc_brop3;                 /* index of the ternary raster operation */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   struct dsd_brush dsc_brush;              /* brush                   */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.11 LineTo (LINETO_ORDER)                 */
struct dsd_ord_co_o09 {                     /* order O09 coordinates   */
   BOOL       boc_set;                      /* variables have been set */
   enum ied_sc_lineto_backmode iec_backmode;    // mode of background: transparent or opaque
   signed short int isc_nxstart;                // starting point of the line, x-coordinate
   signed short int isc_nystart;                // starting point of the line, y-coordinate
   signed short int isc_nxend;                  // end point of the line, x-coordinate
   signed short int isc_nyend;                  // end point of the line, y-coordinate
   //unsigned int imc_back_color;               // background color-> field must be zeroed out -> sense?
   unsigned char ucc_brop2;                     // binary raster operation
   //unsigned char ucc_penstyle;                // PenStyle must be PS_SOLID(0x00)
   //unsigned char ucc_penwith;                 // PenWidth must be 0x01.
   unsigned int umc_pencolor;                   // color of the drawn line
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.12 SaveBitmap (SAVEBITMAP_ORDER)         */
struct dsd_ord_co_o0b {                     /* order O0B coordinates   */
   BOOL       boc_set;                      /* variables have been set */
   unsigned int umc_savedbitmappos;         /* encoded start position of the rectangle in the saved bitmap */
   struct dsd_rectrb dsc_rect;              /* virtual desktop rectangle to save or to restore from */
// ied_sc_savebitmap_operation ucc_operation;  /* operation: either ied_sv_savebits or ied_sv_restorebits */
   unsigned char ucc_operation;             /* operation: either ied_sv_savebits or ied_sv_restorebits */
};

struct dsd_ord_co_o0d {                     /* order O0D coordinates   */
   BOOL       boc_set;                      /* variables have been set */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   signed short int isc_x_src;              /* x-coordinate of source bitmap in cache of client */
   signed short int isc_y_src;              /* inverted y-coordinate of source bitmap in cache of client */
};

/* 2.2.2.2.1.1.2.10 Mem3Blt (MEM3BLT_ORDER)                            */
struct dsd_ord_co_o0e {                     /* order O0E coordinates   */
   BOOL       boc_set;                      /* variables have been set */
   unsigned short int usc_cache_id;         /* cacheId                 */
   unsigned char ucc_brop3;                     // index of the ternary raster operation
   signed short int isc_x_src;                  // x-coordinate of source bitmap in cache of client
   signed short int isc_y_src;                  // inverted y-coordinate of source bitmap in cache of client
   unsigned short int usc_cacheindex;           // index of bitmap within the bitmap cache of client,
// struct dsd_rectwh dsc_destination_rec;   /* destination rectangle   */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   struct dsd_brush dsc_brush;                  // brush
};

struct dsd_ord_co_o13 {                     /* order O13 coordinates   */
   BOOL       boc_set;                      /* variables have been set */
   unsigned char ucc_cache_id;              /* cacheId                 */
   unsigned short int usc_fdrawing;         /* fDrawing                */
   unsigned int umc_forecolor;              /* foreground color        */
   unsigned int umc_backcolor;              /* background color        */
   struct dsd_rectrb dsc_backrect;          /* text background rectangle, like a clip */
   struct dsd_rectrb dsc_opaqrect;          /* opaque rectangle        */
   signed short int isc_start_x;            /* starting point of first glyph, x-coordinate */
   signed short int isc_start_y;            /* starting point of first glyph, y-coordinate */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.18 Polyline (POLYLINE_ORDER)             */
struct dsd_ord_co_o16 {                     /* order O16 coordinates   */
   BOOL       boc_set;                      /* variables have been set */
   signed short int isc_xstart;             /* starting point of the line, x-coordinate */
   signed short int isc_ystart;             /* starting point of the line, y-coordinate */
   unsigned char ucc_brop2;                 /* binary raster operation */
   unsigned short int usc_brush_cache_entry;  /* brush cache entry     */
   unsigned int umc_pencolor;               /* color of the drawn line */
   unsigned char ucc_num_delta_entries;     /* number of points along the polyline path */
   unsigned char ucrc_coded_delta_list[ 1 + 8 + 32 * 4 ];  /* contains the points along the polyline path */
};

struct dsd_ord_co_o18 {                     /* order O18 coordinates   */
   BOOL       boc_set;                      /* variables have been set */
   unsigned char ucc_cache_id;              /* cacheId                 */
   unsigned short int usc_fdrawing;         /* fDrawing                */
   unsigned int umc_backcolor;              /* background color        */
   unsigned int umc_forecolor;              /* foreground color        */
   struct dsd_rectrb dsc_backrect;          /* text background rectangle, like a clip */
   struct dsd_rectrb dsc_opaqrect;          /* opaque rectangle        */
   signed short int isc_start_x;            /* starting point of first glyph, x-coordinate */
   signed short int isc_start_y;            /* starting point of first glyph, y-coordinate */
};

struct dsd_arr_glyph_e {                    /* array of glyph entries  */
   unsigned short int usc_len_store;        /* length of storage in bytes */
   unsigned short int usc_no_entries;       /* number of entries       */
   unsigned short int usc_entries_filled;   /* number of filled entries */
   unsigned short int usc_entries_deleted;  /* number of filled deleted */
   struct dsd_glyph *adsc_glyph_first;      /* first glyph in chain    */
   struct dsd_glyph *adsc_glyph_last;       /* last glyph in chain     */
};

struct dsd_rdp_caps {
   /* General Information */
   struct {
      /* General flags from 2.2.7.1.1 General Capability Set (TS_GENERAL_CAPABILITYSET) */
      struct{
         BOOL boc_fastpath_output;            /* 0X0001 FASTPATH_OUTPUT_SUPPORTED  */
         BOOL boc_long_credentials;           /* 0X0004 LONG_CREDENTIALS_SUPPORTED */
         BOOL boc_autoreconnect;              /* 0X0008 AUTORECONNECT_SUPPORTED    */
         BOOL boc_salted_checksum;            /* 0X0010 ENC_SALTED_CHECKSUM        */
         BOOL boc_no_bitmap_compreession_hdr; /* 0X0400 NO_BITMAP_COMPRESSION_HDR  */
      };
      /* 2.2.7.2.6 Multifragment Update Capability Set (TS_MULTIFRAGMENTUPDATE_CAPABILITYSET) */
      int imc_multifragmentupdate_maxrequestsize;
      /* 2.2.7.1.10 Virtual Channel Capability Set (TS_VIRTUALCHANNEL_CAPABILITYSET) */
      BOOL boc_vch_supp_compr_se_to_cl;     /* 0x00000001 VCCAPS_COMPR_SC           */    
      BOOL boc_vch_supp_compr_cl_to_se;     /* 0x00000002 VCCAPS_COMPR_CS           */
      /* 2.2.7.1.7 Brush Capability Set (TS_BRUSH_CAPABILITYSET) */
      int imc_brush_support_level;

   } dsc_general;

   /* Order support from 2.2.7.1.3 Order Capability Set (TS_ORDER_CAPABILITYSET) */
   struct {
      struct {
         BOOL boc_dstblt;             /* 0X00 TS_NEG_DSTBLT_INDEX             */
         BOOL boc_patblt;             /* 0X01 TS_NEG_PATBLT_INDEX             */
         BOOL boc_scrblt;             /* 0X02 TS_NEG_SCRBLT_INDEX             */
         BOOL boc_memblt;             /* 0X03 TS_NEG_MEMBLT_INDEX             */
         BOOL boc_mem3blt;            /* 0X04 TS_NEG_MEM3BLT_INDEX            */
         BOOL boc_drawninegrid;       /* 0X07 TS_NEG_DRAWNINEGRID_INDEX       */
         BOOL boc_lineto;             /* 0X08 TS_NEG_LINETO_INDEX             */
         BOOL boc_multi_drawninegrid; /* 0X09 TS_NEG_MULTI_DRAWNINEGRID_INDEX */
         BOOL boc_savebitmap;         /* 0X0B TS_NEG_SAVEBITMAP_INDEX         */
         BOOL boc_multidstblt;        /* 0x0F TS_NEG_MULTIDSTBLT_INDEX        */
         BOOL boc_multipatblt;        /* 0X10 TS_NEG_MULTIPATBLT_INDEX        */
         BOOL boc_multiscrblt;        /* 0X11 TS_NEG_MULTISCRBLT_INDEX        */
         BOOL boc_multiopaquerect;    /* 0X12 TS_NEG_MULTIOPAQUERECT_INDEX    */
         BOOL boc_fast_index;         /* 0X13 TS_NEG_FAST_INDEX_INDEX         */
         BOOL boc_polygon_sc;         /* 0X14 TS_NEG_POLYGON_SC_INDEX         */
         BOOL boc_polygon_cb;         /* 0X15 TS_NEG_POLYGON_CB_INDEX         */
         BOOL boc_polyline;           /* 0X16 TS_NEG_POLYLINE_INDEX           */
         BOOL boc_fast_glyph;         /* 0X18 TS_NEG_FAST_GLYPH_INDEX         */
         BOOL boc_ellipse_sc;         /* 0X19 TS_NEG_ELLIPSE_SC_INDEX         */
         BOOL boc_ellipse_cb;         /* 0X1A TS_NEG_ELLIPSE_CB_INDEX         */
         BOOL boc_glyph_index;        /* 0X1B TS_NEG_INDEX_INDEX              */
      };
      /* orderSupportExFlags */
      struct {
         unsigned int boc_cache_bitmap_rev3_support;   /* 0X0002 ORDERFLAGS_EX_CACHE_BITMAP_REV3_SUPPORT */
         unsigned int boc_altsec_frame_marker_support; /* 0X0004 ORDERFLAGS_EX_ALTSEC_FRAME_MARKER_SUPPORT */
      };
      struct{
         int imc_desktop_save_x_gran;
         int imc_desktop_save_y_gran;
         int imc_desktop_save_size;
      };
   } dsc_orders;

   /* Bitmaps (various Capability Sets ) */
   struct {

      /* flags from 2.2.7.1.2 Bitmap Capability Set (TS_BITMAP_CAPABILITYSET) */
      struct {
         BOOL boc_allow_dynamic_color_fidelity; /* 0X02 DRAW_ALLOW_DYNAMIC_COLOR_FIDELITY */
         BOOL boc_allow_color_subsampling;      /* 0X04 DRAW_ALLOW_COLOR_SUBSAMPLING */
         BOOL boc_allow_skip_alpha;             /* 0X08 DRAW_ALLOW_SKIP_ALPHA */
         BOOL boc_desktop_resize_flag;          /* true, if desctop resize (ied_scc_change_screen) is supported */
      };

      /* 2.2.7.1.4.1 Revision 1 (TS_BITMAPCACHE_CAPABILITYSET)      */
      /* 2.2.7.1.4.2 Revision 2 (TS_BITMAPCACHE_CAPABILITYSET_REV2) */
      int imc_cache_numcaches;
      int imcr_cache_numentries[5];
      BOOL bocr_cache_persistant[5];

      struct {
         unsigned int boc_persistend_keys_expected;  /* 0X0001 PERSISTENT_KEYS_EXPECTED_FLAG */
         unsigned int boc_allow_cache_waiting_list;  /* 0X0002 ALLOW_CACHE_WAITING_LIST_FLAG */
      };
   } dsc_bitmap;

   /* Pointers (various Capability Sets */
   struct{
     /* 2.2.7.1.5 Pointer Capability Set (TS_POINTER_CAPABILITYSET) */
     BOOL boc_color_pointer_supported; /* colorPointerFlag */
     int imc_color_pointer_cache_size; /* colorPointerCacheSize */
     int imc_pointer_cache_size;       /* pointerCacheSize */
     /* 2.2.7.2.7 Large Pointer Capability Set (TS_LARGE_POINTER_CAPABILITYSET) */
     BOOL boc_large_pointer_supported; /* argePointerSupportFlags */

   } dsc_pointer;

   /* 2.2.7.1.9 Offscreen Bitmap Cache Capability Set (TS_OFFSCREEN_CAPABILITYSET) */
   struct {
      int imc_size;
      int imc_entries; 
   } dsc_offscreen_cache;

   /* special HOB-flags */
   struct {
      BOOL boc_hob_caps_received;
      BOOL boc_order_ex_bmp6_uncompressed;
      BOOL boc_order_ex_brush_size_field;
      int imc_order_ex_mono_brush_size_cache; 
      int imc_order_ex_color_brush_size_cache;
      int imc_order_ex_brush_cache_flags;
      BOOL bo_cursor_caps;
      int in_ext_cursor_flags;
      int in_max_width_cursor;
      int in_max_height_cursor;
   } dsc_hob;

};

struct dsd_rdp_co {                         /* rdp communication       */
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
   BOOL       boc_suppress_display_updates;  /* RDP client is minimized */
   HL_WCHAR   wcrc_computer_name[16];       /* computer name           */
   int        imc_keyboard_type;            /* Type of Keyboard / 102  */
   int        imc_keyboard_subtype;         /* Subtype of Keyboard     */
   int        imc_no_func_keys;             /* Number of Function Keys */
   int        imc_keytype;                  /* keytype                 */
   int        imc_used_keylen;              /* used keylen 03.01.05    */
   int        imc_sec_level;                /* security level          */
   int        imc_l_pub_par;                /* length public parameters */
   int        imc_no_virt_ch;               /* number of virtual channels */
   unsigned char ucc_keyboard_status;       /* last keyboard status    */
   unsigned short int usc_chno_disp;        /* channel number display  */
   unsigned short int usc_chno_cont;        /* channel number control  */
   unsigned short int usc_userid_cl2se;     /* userid client to server */
   dtd_rdpfl_1 dtc_rdpfl_1;                 /* RDP flags               */
   struct dsd_rdp_vc_1 *adsrc_vc_1;         /* array of virtual chann  */
   BOOL   boc_always_compr_vc;         		/* TRUE, if there is a virtual channel, which is always compressed */
   int        imc_no_arr_glyph_e;           /* number of arrays of glyph entries */
   unsigned int umc_count_glyph_alloc;      /* count glyph allocs      */
   struct dsd_arr_glyph_e *adsrc_arr_glyph_e;  /* array of glyph entries */
#ifdef ONLY_IN_CLIENT_061013
   struct dsd_progaddr_1 *adsc_progaddr_1;  /* program addresses       */
#endif
   struct dsd_cdr_field dsc_cdrf_dec;       /* compression decryption  */
   struct dsd_cdr_field dsc_cdrf_enc;       /* compression encryption  */
   char       chrc_sig[16];                 /* signature               */
   struct dsd_rdp_encry dsc_encry_se2cl;    /* rdp encryption server to client */
   struct dsd_rdp_encry dsc_encry_cl2se;    /* rdp encryption client to server */
   int        imrc_sha1_state[ SHA_ARRAY_SIZE ];  /* SHA1 state array  */
   int        imrc_md5_state[ MD5_ARRAY_SIZE ];  /* MD5 state array    */
//#ifdef B100103
/* initialize parameters at demand active PDU */
      struct dsd_ord_co_1 dsrc_ord_co_1[ D_R5_ORD_NO ];  /* order coordinates */
//#endif
   struct dsd_ord_co_o01 dsc_ord_co_o01;    /* order O01 coordinates   */
   struct dsd_ord_co_o09 dsc_ord_co_o09;    /* order O09 coordinates   */
   struct dsd_ord_co_o0b dsc_ord_co_o0b;    /* order O0B coordinates   */
   struct dsd_ord_co_o0d dsc_ord_co_o0d;    /* order O0D coordinates   */
   struct dsd_ord_co_o0e dsc_ord_co_o0e;    /* order O0E coordinates   */
   struct dsd_ord_co_o13 dsc_ord_co_o13;    /* order O13 coordinates   */
   struct dsd_ord_co_o16 dsc_ord_co_o16;    /* order O16 coordinates   */
   struct dsd_ord_co_o18 dsc_ord_co_o18;    /* order O18 coordinates   */
/* initialize parameters at demand active PDU */
   int        imc_bounds_left;              /* bounds coordinates      */
   int        imc_bounds_top;               /* bounds coordinates      */
   int        imc_bounds_right;             /* bounds coordinates      */
   int        imc_bounds_bottom;            /* bounds coordinates      */
// short int  isrc_bitmap_data[ DEF_UPDATE_BITMAP_CO ];  /* number of short update bitmap */
//#ifdef B100103
   int        imc_o01_col_backgr;           /* Order 1 background color */
   int        imc_o01_col_foregr;           /* Order 1 foreground color */
   char       chc_o01_brush_x;              /* Order 1 brush X         */
   char       chc_o01_brush_y;              /* Order 1 brush Y         */
   char       chc_o01_brush_style;          /* Order 1 brush style     */
   char       chc_o01_brush_hatch;          /* Order 1 brush hatch     */
   char       chrc_o01_brush_data[ DEF_CONST_O01_BRUSH_LEN ];  /* Order 1 brush data */
//#endif
   unsigned char ucc_prot_r5_pdu_ord_prim;  /* primary order number    */
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
   int        inc_performance_flags;        /* JB SM: we need this for MACGate. */
   struct dsd_rdp_lic_d * adsc_lic_neg;     /* for license negotiation */
   struct dsd_rdp_caps dsc_caps;            /* Capabilities            */
   int        imc_max_pdu_length;           /* Max length of PDU, MSTSC=0X4000 JWT=0X8000 */
   int        imc_max_ts_fp_update_size;    /* Max length of order PDU, MSTSC=0X4000 - 11 JWT=0X8000 - 11 */
#ifdef HL_RDPACC_HELP_DEBUG
   int        imc_debug_reclen;
   int        imc_debug_count_event;
#endif
};

struct dsd_call_rdpserv_1 {                 /* call RDP Server 1       */
   int        inc_func;                     /* called function         */
   int        inc_return;                      /* return code             */
   char *     achc_work_area;               /* addr work-area          */
   int        inc_len_work_area;            /* length work-area        */

   struct dsd_gather_i_1 *adsc_gather_i_1_in;  /* input data           */
   struct dsd_gather_i_1 *adsc_gather_i_1_out;  /* output data         */

   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer

   void *     ac_ext;                       // attached buffer pointer
#ifdef OLD01
   void *     ac_conf;                      /* data from configuration */
#else
   struct dsd_conf_rdpserv_1 *adsc_conf;    /* configuration RDP Server 1 */
#endif
   int        imc_flags_1;                  /* flags of configuration  */
   int        imc_signal;                   /* signals occured         */
   void *     vpc_userfld;                  /* User Field Subroutine   */
   BOOL       boc_callagain;                /* call again this direction */
//   BOOL       boc_callrevdir;               /* call on reverse direction */
//   BOOL       boc_no_conn_s;                /* do not connect to server */
   BOOL       boc_eof_client;               /* End-of-File Client      */
// BOOL       boc_eof_server;               /* End-of-File Server      */
   struct dsd_rdp_co *adsc_rdp_co;          /* here is area for RDP communication */
   void *     ac_screen_buffer;             /* screen buffer           */
   struct dsd_sc_co1 *adsc_sc_co1_ch;       /* chain of server commands, input */
   struct dsd_cl_co1 *adsc_cl_co1_ch;       /* chain of command from client, output */
};

struct dsd_conf_rdpserv_1 {                 /* configuration RDP Server 1 */
   int        imc_sec_level;                /* security level          */
};

#ifdef XYZ1
typedef void ( * amd_hlclib01 )( struct dsd_call_rdpserv_1 * );
typedef void ( * amd_hlwspat2e )( struct dsd_hl_wspat2_1 * );
#endif

#ifdef DEF_HL_INCL_DOM
#ifndef DEF_HL_INCL_DOM_DONE
#define DEF_HL_INCL_DOM_DONE

enum ied_hlcldom_def { ied_hlcldom_invalid,  /* invalid function       */
                       ied_hlcldom_get_first_child,  /* getFirstChild() */
                       ied_hlcldom_get_next_sibling,  /* getNextSibling() */
                       ied_hlcldom_get_node_type,  /* getNodeType()    */
                       ied_hlcldom_get_node_value,  /* getNodeValue()  */
                       ied_hlcldom_get_node_name  /* getNodeName()     */
};

struct dsd_hl_clib_dom_conf {               /* structure DOM configur  */
   DOMNode    *adsc_node_conf;              /* part of configuration   */
   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     vpc_userfld;                  /* User Field Subroutine   */
   int        imc_flags_1;                  /* flags of configuration  */
   void **    aac_conf;                     /* return data from conf   */
// getFirstChild()
// getNextSibling()
// getNodeType()
// getNodeValue()
// getNodeName()
// XMLString::transcode()
// XMLString::release()
   void * (* amc_call_dom) ( DOMNode *, ied_hlcldom_def );  /* call DOM */
};

typedef BOOL ( * amd_hlclib_conf )( struct dsd_hl_clib_dom_conf * );

#endif
#endif

#if defined __cplusplus
extern "C" void m_rdpserv_1( struct dsd_call_rdpserv_1 * );
#else
extern void m_rdpserv_1( struct dsd_call_rdpserv_1 * );
#endif // cplusplus
