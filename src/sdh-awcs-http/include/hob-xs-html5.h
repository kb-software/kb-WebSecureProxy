#ifndef _DEF_HOB_XS_HTML5_H
#define _DEF_HOB_XS_HTML5_H

/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| FILE:                                                               |*/
/*| -----                                                               |*/
/*|  hob-xs-html5.h                                                     |*/
/*|                                                                     |*/
/*| Description:                                                        |*/
/*| ------------                                                        |*/
/*|  defines the calling strutures for html5-awcs modul                 |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| -------                                                             |*/
/*|  Michael Jakobs, March 2011                                         |*/
/*|  Tobias Hofmann, December 2011                                      |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| forward definitions:                                                |*/
/*+---------------------------------------------------------------------+*/
struct dsd_gather_i_1;
struct dsd_unicode_string;

/*+---------------------------------------------------------------------+*/
/*| config structure:                                                   |*/
/*+---------------------------------------------------------------------+*/
typedef struct dsd_conf_awcs_html5 {
    struct dsd_unicode_string dsc_root_dir;     /* www root directory    */
    struct dsd_unicode_string dsc_default_html; /* default html page     */
    BOOL                      boc_secure;       /* ssl enabled?          */
} dsd_conf_awcs_html5;

/*+---------------------------------------------------------------------+*/
/*| trace level:                                                        |*/
/*+---------------------------------------------------------------------+*/
typedef enum ied_awcs_html5_trace {
    ied_awcs_html5_tl_off,                      /* no traces at all      */
    ied_awcs_html5_tl_error,                    /* only errors           */
    ied_awcs_html5_tl_warn,                     /* warnings & errors     */
    ied_awcs_html5_tl_info,                     /* infos, warn & errors  */
    ied_awcs_html5_tl_verbose                   /* trace everything      */
} ied_awcs_html5_trace;

#define HTML5_ANSWER_LEN 100000
#define HTML5_HEADER_LEN 20

/* string constants                                                      */
typedef struct dsd_string_const {
    const char *achc_str;
    int        inc_length;
} dsd_string_const;

typedef struct dsd_html5_answer
{
    char                    chrc_answer[HTML5_ANSWER_LEN];
    int                     inc_len;
} dsd_html5_answer;

typedef struct dsd_html5_header
{
    char                    chrc_header[HTML5_HEADER_LEN];
    int                     inc_len;
} dsd_html5_header;


/* browser event types                                                   */
enum ied_browser_event {
    ied_be_unknown         =  0,                /* unknown event         */
    ied_be_control         =  1,                /* control event         */
	ied_be_connect		   =  2,				/* connect rdp event     */
    ied_be_charkey_pressed = 10,                /* character key pressed */
    ied_be_funckey_press   = 12,                /* function key pressed  */
    ied_be_funckey_release = 13,                /* function key released */
    ied_be_mouse_move      = 14,                /* mouse move            */
    ied_be_mouse_press     = 15,                /* mouse button press    */
    ied_be_mouse_release   = 16,                /* mouse button release  */
    ied_be_mouse_wheel     = 17                 /* mouse wheel           */
};

typedef struct dsd_rdp_srv_infos
{
	char					chrc_rdp_srv[256];	/* rdp server address    */
	int						inc_srv_len;
	int						inc_port;			/* port					 */
	HL_WCHAR				chrc_user[64];		/* username				 */
	int						inc_user_len;
	HL_WCHAR				chrc_password[64];	/* password				 */
	int						inc_password_len;
} dsd_rdp_srv_infos;

/* we are using an UTF-32 sign for characters                            */
typedef unsigned char utf32_t[4];

/* browser event structure                                               */
typedef struct dsd_browser_event {
    enum ied_browser_event  iec_type;           /* type of event         */
    utf32_t                 rchc_key;           /* utf32 key             */
    unsigned char           uchc_function;      /* function key          */
    unsigned int            uinc_x;             /* x mouse pointer       */
    unsigned int            uinc_y;             /* y mouse pointer       */
    unsigned short int      uisc_button;        /* mouse button          */
    int                     inc_wheel;          /* mouse wheel           */
    long long int           ill_timestamp;      /* epoch time (millisec) */
    unsigned int            uinc_width;         /* canvas width          */
    unsigned int            uinc_height;        /* canvas height         */
    enum ied_ctx_type       ienc_ctx_type;      /* canvas context type   */
	dsd_rdp_srv_infos       dsc_rdp_srv_infos;  /* server and port to connect to */
} dsd_browser_event;


/* following structs are like the outgoing rdp acc structs */
typedef enum ied_rdp_event
{
	ied_rdp_unknown		= 0,
	ied_rdp_rectangle
} ied_rdp_event;

typedef struct dsd_rdp_rectangle
{
	int							imc_left_x;
	int							imc_top_y;
	int							imc_bottom_y;
	int							imc_width;
	int							imc_height;
	int							imc_resolution_x;
	void						*avc_screenbuffer;
} dsd_rdp_rectangle;

typedef struct dsd_rdp_event
{
	ied_rdp_event			iec_type;
	dsd_rdp_rectangle		dsc_rectangle;
	struct dsd_rdp_event	*adsc_next;
} dsd_rdp_event;


/*+---------------------------------------------------------------------+*/
/*| calling structure itself:                                           |*/
/*+---------------------------------------------------------------------+*/
typedef struct dsd_call_awcs_html5 {
    char                  *achc_work_area;      /* addr work-area        */
    int                   inc_len_work_area;    /* length work-area      */

    struct dsd_gather_i_1 *adsc_gather_i_1_in;  /* input data            */
    struct dsd_gather_i_1 *adsc_gather_i_1_out; /* output data           */

    BOOL (* amc_aux) (void*, int, void*, int ); /* callback function     */
    void                  *avc_ext;             /* attached buffer ptr   */
    dsd_conf_awcs_html5   *adsc_conf;           /* configuration ptr     */
    ied_awcs_html5_trace  ied_trace_level;      /* trace level           */
    
    void                  *avc_userfield;       /* user field subroutine */
} dsd_call_awcs_html5;

/*+---------------------------------------------------------------------+*/
/*| function prototype:                                                 |*/
/*+---------------------------------------------------------------------+*/
#ifdef __cplusplus
     extern "C"
#endif
BOOL m_html5_start( struct dsd_call_awcs_html5 * );

#ifdef __cplusplus
     extern "C"
#endif
BOOL m_html5_end( struct dsd_call_awcs_html5 * );

#ifdef __cplusplus
     extern "C"
#endif
BOOL m_html5_get_event( struct dsd_call_awcs_html5 *, struct dsd_browser_event ** );

#ifdef __cplusplus
     extern "C"
#endif
BOOL m_html5_send_drawing( struct dsd_call_awcs_html5 *, struct dsd_rdp_event * );

#ifdef __cplusplus
     extern "C"
#endif
BOOL m_jp_parse_event( struct dsd_gather_i_1*, unsigned long long int, struct dsd_browser_event* );

#ifdef _TEST
	#define PRIVATE extern
#else
	#define PRIVATE static
#endif

#endif /* _DEF_HOB_XS_HTML5_H */
