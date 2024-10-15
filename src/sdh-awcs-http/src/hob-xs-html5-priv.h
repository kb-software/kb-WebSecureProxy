#ifndef _DEF_HOB_XS_HTML5_PRIV_H
#define _DEF_HOB_XS_HTML5_PRIV_H
/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| FILE:                                                               |*/
/*| -----                                                               |*/
/*|  hob-xs-html5-priv.h                                                |*/
/*|                                                                     |*/
/*| Description:                                                        |*/
/*| ------------                                                        |*/
/*|  private header file for the html5 awcs modul                       |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| -------                                                             |*/
/*|  Michael Jakobs, June 2011                                          |*/
/*|  Tobias Hofmann, October 2011                                       |*/
/*|                                                                     |*/
/*| Requirements:                                                       |*/
/*| -------------                                                       |*/
/*|  include "hob-http-processor.h" before this header file             |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| declarations:                                                       |*/
/*+---------------------------------------------------------------------+*/
struct dsd_http_parser_cbs;
struct dsd_http_creator_cbs;
struct dsd_call_awcs_html5;
struct dsd_browser_event;
extern const char *achg_function_keys[];


/* websocket variables                                                   */
/* not all of them are in use                                            */

enum ied_ws_version {
    ied_no_ws       = -2,                       /* no websocket at all   */
    ied_ws_unknown  = -1,                       /* unknown websocket     */
    ied_ws_draft_00 = 0,                        /* websocket draft 00    */
    ied_ws_draft_01 = 1,                        /* websocket draft 01    */
    ied_ws_draft_02 = 2,                        /* websocket draft 02    */
    ied_ws_draft_03 = 3,                        /* websocket draft 03    */
    ied_ws_draft_04 = 4,                        /* websocket draft 04    */
    ied_ws_draft_05 = 5,                        /* websocket draft 05    */
    ied_ws_draft_06 = 6,                        /* websocket draft 06    */
    ied_ws_draft_07 = 7,                        /* websocket draft 07    */
    ied_ws_draft_08 = 8,                        /* websocket draft 08    */
    ied_ws_draft_09 = 9,                        /* websocket draft 09    */
    ied_ws_draft_10 = 10,                       /* websocket draft 10    */
    ied_ws_draft_11 = 11,                       /* websocket draft 11    */
    ied_ws_draft_12 = 12,                       /* websocket draft 12    */
    ied_ws_draft_13 = 13                        /* websocket draft 13    */
};

// contains all the fields from a websocket message header

typedef struct dsd_frame_header
{
	BOOL                   boc_fin_frame;		/* last frame flag       */
    unsigned char          uchc_extension;		/* extension flags       */
    unsigned char          uchc_frametype;		/* text or binary        */
    BOOL                   boc_mask;			/* is the payload masked */
    unsigned long long int ullc_payload_len;	/* length of the payload */
    unsigned char          chrc_mask[4];		/* mask bytes            */
	int                    ic_header_pos;
	int					   ic_length_pos;
} dsd_frame_header;


struct dsd_websocket {
    enum ied_ws_version		iec_websocket;       /* websocket version     */
    unsigned long long int	uilc_length;         /* current packet length */
};

struct dsd_html5_conn;


/* canvas context drawing type                                           */
typedef enum ied_ctx_type {
    ied_ct_unknown = 0,                         /* unknown context type  */
    ied_ct_2d      = 1                          /* 2D context type       */
} ied_ctx_type;

/* canvas context structure                                              */
typedef struct dsd_canvas_ctx {
    unsigned int            uinc_width;         /* drawing window width  */
    unsigned int            uinc_height;        /* drawing window height */
    enum ied_ctx_type       ienc_type;          /* context type          */
    struct dsd_html5_conn   *adsc_conn;         /* connection handle     */
    void (*amc_keyhandler)( struct dsd_html5_answer *adsp_answer, struct dsd_canvas_ctx*, struct dsd_browser_event* );
} dsd_canvas_ctx;


/* html5 connection structure                                            */
struct dsd_html5_conn {
    struct dsd_call_awcs_html5  *adsc_awcs_html5;    /* called params    */
    void                        *avc_http_parser;    /* http parser hdl  */
    void                        *avc_http_creator;   /* http creator hdl */
    struct dsd_http_parser_cbs  dsc_http_parser_cbs; /* http parser cbs  */
    struct dsd_http_creator_cbs dsc_http_creator_cbs;/* http creator cbs */
    int                         inc_size_wa;         /* size last w-area */
	struct dsd_aux_get_workarea dsc_cur_workarea;	 /* current workarea */
    struct dsd_websocket        dsc_ws;              /* websocket stuff  */
    struct dsd_canvas_ctx       dsc_ctx;             /* canvas context   */
	struct dsd_frame_header     dsc_cur_frame_header;/* keep header of the frames */
	struct dsd_browser_event	dsc_browser_event;	 /* parsed event */
};


#endif /* _DEF_HOB_XS_HTML5_PRIV_H */