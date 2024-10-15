#ifndef _HOB_XS_RDPACC_H
#define _HOB_XS_RDPACC_H


/*+---------------------------------------------------------------------+*/
/*| structs                                                             |*/
/*+---------------------------------------------------------------------+*/
typedef struct dsd_call_rdpacc {
	BOOL (* amc_aux) (void*, int, void*, int );				/* callback function     */
	void							*avc_userfield;			/* user field subroutine */
	struct dsd_gather_i_1			*adsc_gather_i_1_in;	/* input data            */
    struct dsd_gather_i_1			*adsc_gather_i_1_out;	/* output data           */
    char							*achc_work_area;		/* addr work-area        */
    int								inc_len_work_area;		/* length work-area      */
	void							*avc_ext;				/* attached buffer ptr   */
	BOOL							boc_data_to_server;
} dsd_call_rdpacc;


typedef enum ied_rdp_user_event
{
	ied_connect = 0,
	ied_mouse,
	ied_keyboard
} ied_rdp_user_event;

typedef struct dsd_rdp_user_connect
{
	struct dsd_aux_tcp_conn_1		dsc_connection;			/* infos about the tcp connection */
	HL_WCHAR						chrc_user[64];			/* username				 */
	int								inc_user_len;
	HL_WCHAR						chrc_password[64];		/* password				 */
	int								inc_password_len;
} dsd_rdp_user_connect;

typedef struct dsd_rdp_user_mouse
{
	char							chrc_order[7];			/* mouse event buffer */
	int								ic_len;					/* length of event */
} dsd_rdp_user_mouse;


typedef struct dsd_rdp_user_keyboard
{
	char							chrc_order[2];
	int								ic_len;
} dsd_rdp_user_keyboard;


typedef struct dsd_rdp_user_event
{
	ied_rdp_user_event					iec_event_type;
	dsd_rdp_user_connect				dsc_user_connect;
	dsd_rdp_user_mouse					dsc_user_mouse;
	dsd_rdp_user_keyboard				dsc_user_keyboard;
} dsd_rdp_user_event;


/* following structs are like the html5 structs, which it takes as incoming draw structs */
/* list of possible commands which come from the rdp server */
typedef enum ied_rdp_command {
	ied_unknown		= 0,
	ied_rectangle
} ied_rdp_command;

/* command of a rectangle */
typedef struct dsd_rectangle_data {
	int							imc_left_x;
	int							imc_top_y;
	int							imc_bottom_y;
	int							imc_width;
	int							imc_height;
	int							imc_resolution_x;
	void						*avc_screenbuffer;
} dsd_rectangle_data;

/* contains identifier of command and data for it */
typedef struct dsd_rdp_draw_command {
	ied_rdp_command				ied_command_type;
	dsd_rectangle_data			dsc_rectangle_data;
	struct dsd_rdp_draw_command	*adsc_next;
} dsd_rdp_draw_command;


/* keeps track of all necessary settings of the rdp acc part */
typedef struct dsd_rdpacc_settings
{
	// new interface:
	struct dsd_call_rdpacc			*adsc_call_rdpacc;				/* self reference to "parent" */
	struct dsd_call_rdpclient_1		dsc_call_rdpclient_1;			/* structure which is passed to the RDPACC Client */
	struct dsd_client_order			*adsc_client_order;				/* struct for info send to rdp server */
	struct dsd_se_co1				*adsc_license_order;			/* needed to store the incoming license from the server */
	struct dsd_rdp_user_connect		dsc_connection_info;			/* server, port, user, pw */
	struct dsd_rdp_draw_command		*dsc_command_out;				/* contains translated commands from server */
	struct dsd_cc_co1				*adsc_events_to_server;			/* save the events to give it to rdpacc */
	
	BOOL							boc_started;					/* rdpacc started or not */
	BOOL							boc_request_license;			/**/
	BOOL							boc_send_confirm_active_pdu;	/**/

	// old interface:
	struct dsd_stor_sdh_1			*adsc_stor_sdh_1;				/* storage container for internal rdpacc memory */
	//struct dsd_hl_clib_1			dsc_hl_clib_1;					/* structure for calling rdp acc */
} dsd_rdpacc_settings;


/*+---------------------------------------------------------------------+*/
/*| structs, taken as they were from rdpacc client testprogram          |*/
/*+---------------------------------------------------------------------+*/
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
};

/*+---------------------------------------------------------------------+*/
/*| function prototype:                                                 |*/
/*+---------------------------------------------------------------------+*/
#ifdef __cplusplus
     extern "C"
#endif
BOOL m_rdpacc_start( struct dsd_call_rdpacc*, struct dsd_rdp_user_event* );

#ifdef __cplusplus
     extern "C"
#endif
BOOL m_rdpacc_end( struct dsd_call_rdpacc* );

#ifdef __cplusplus
     extern "C"
#endif
BOOL m_rdpacc_get_event( struct dsd_call_rdpacc*, struct dsd_rdp_draw_command** );

#ifdef __cplusplus
     extern "C"
#endif
BOOL m_rdpacc_send_event( struct dsd_call_rdpacc*, struct dsd_rdp_user_event* );




#endif // _HOB_XS_RDPACC_H