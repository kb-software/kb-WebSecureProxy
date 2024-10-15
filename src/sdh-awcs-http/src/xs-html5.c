/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| --------                                                            |*/
/*|   xs-html5                                                          |*/
/*|   Handshake and HTML5 Parsing                                       |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| -------                                                             |*/
/*|   Michael Jakobs, 2011                                              |*/
/*|   Tobias Hofmann, October 2011                                      |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| global includes:                                                    |*/
/*+---------------------------------------------------------------------+*/
#ifndef HL_UNIX
    #include <windows.h>
#endif //HL_UNIX
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

/*+---------------------------------------------------------------------+*/
/*| local includes:                                                     |*/
/*+---------------------------------------------------------------------+*/
#include <hob-xsclib01.h>
#include <hob-xslunic1.h>

// RDP Client Header Files
#include "hob-encry-1.h"
#define HCOMPR2 // stupid stuff for hob-rdpclient1.h
#include "hob-cd-record-1.h"
//#include "hob-rdpclient1.h"

#include <hob-xs-html5.h>
#include <hob-xs-draw.h>
#include <align.h>
#include "hob-http-processor.h"
#include "hob-xs-html5-priv.h"

/*+---------------------------------------------------------------------+*/
/*| declarations:                                                       |*/
/*+---------------------------------------------------------------------+*/

extern const char *achg_function_keys[] = {
    "undefined" , "undefined" , "undefined" , "undefined" ,     /*   0 -   3 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /*   4 -   7 */
    "backspace" , "tab"       , "undefined" , "undefined" ,     /*   8 -  11 */
    "num 5"     , "enter"     , "undefined" , "undefined" ,     /*  12 -  15 */
    "shift"     , "ctrl"      , "alt"       , "undefined" ,     /*  16 -  19 */
    "capslock"  , "undefined" , "undefined" , "undefined" ,     /*  20 -  23 */
    "undefined" , "undefined" , "undefined" , "esc"       ,     /*  24 -  27 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /*  28 -  31 */
    "undefined" , "page up"   , "page down" , "end"       ,     /*  32 -  35 */
    "home"      , "left"      , "up"        , "right"     ,     /*  36 -  39 */
    "down"      , "undefined" , "undefined" , "undefined" ,     /*  40 -  43 */
    "undefined" , "insert"    , "delete"    , "undefined" ,     /*  44 -  47 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /*  48 -  51 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /*  52 -  55 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /*  56 -  59 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /*  60 -  63 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /*  64 -  67 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /*  68 -  71 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /*  72 -  75 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /*  76 -  79 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /*  80 -  83 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /*  84 -  87 */
    "undefined" , "undefined" , "undefined" , "win left"  ,     /*  88 -  91 */
    "win right" , "win menu"  , "undefined" , "undefined" ,     /*  92 -  95 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /*  96 -  99 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 100 - 103 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 104 - 107 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 108 - 111 */
    "f1"        , "f2"        , "f3"        , "f4"        ,     /* 112 - 115 */
    "f5"        , "f6"        , "f7"        , "f8"        ,     /* 116 - 119 */
    "f9"        , "f10"       , "f11"       , "f12"       ,     /* 120 - 123 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 124 - 127 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 128 - 131 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 132 - 135 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 136 - 139 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 140 - 143 */
    "numlock"   , "scrolllock", "undefined" , "undefined" ,     /* 144 - 147 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 148 - 151 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 152 - 155 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 156 - 159 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 160 - 163 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 164 - 167 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 168 - 171 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 172 - 175 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 176 - 179 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 180 - 183 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 184 - 187 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 188 - 191 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 192 - 195 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 196 - 199 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 200 - 203 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 204 - 207 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 208 - 211 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 212 - 215 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 216 - 219 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 220 - 223 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 224 - 227 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 228 - 231 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 232 - 235 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 236 - 239 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 240 - 243 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 244 - 247 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 248 - 251 */
    "undefined" , "undefined" , "undefined" , "undefined" ,     /* 252 - 255 */
};

/*+---------------------------------------------------------------------+*/
/*| function prototypes:                                                |*/
/*+---------------------------------------------------------------------+*/

/* private */
static void						m_print_event			( struct dsd_html5_conn*, struct dsd_browser_event* );
static BOOL						m_create_frame_header	( struct dsd_html5_header*, int, WORD );
static BOOL						m_handle_ws				( struct dsd_html5_conn*, struct dsd_gather_i_1*, struct dsd_browser_event* );
static BOOL						m_add_path				( struct dsd_unicode_string*, struct dsd_unicode_string*, struct dsd_unicode_string *);
static size_t					m_to_output				( struct dsd_html5_conn*, const char*, size_t );
static void						m_get_fullpath			( struct dsd_html5_conn*, struct dsd_unicode_string*, struct dsd_unicode_string* );
static char*					m_get_mimetype			( struct dsd_unicode_string* );
static void						m_send_file				( struct dsd_html5_conn*, struct dsd_unicode_string* );
static void						m_send_not_modified		( struct dsd_html5_conn* );
static BOOL						m_is_file_modified		( struct dsd_html5_conn*, struct dsd_unicode_string*, struct dsd_unicode_string* );
static void						m_to_bigendian			( unsigned int, unsigned char* );
static BOOL						m_build_ws_checksum_08	( const char*, char* );
static BOOL						m_ws_handshake_08		( struct dsd_html5_conn*, struct dsd_http_header*, struct dsd_gather_i_1* );
static BOOL						m_to_base64				( char*, int*, const char*, int );
static void						m_search				( struct dsd_gather_i_1*, char, struct dsd_gather_i_1**, char** );
PRIVATE char					m_temp_get_byte			( struct dsd_gather_i_1**, char** );
static void						m_printf				( struct dsd_html5_conn*, const char*, ... );
static BOOL						m_process_rdp_commands	( struct dsd_html5_conn*, struct dsd_html5_answer* );
static void						m_handle_control		( struct dsd_html5_answer*, struct dsd_canvas_ctx*, struct dsd_browser_event* );
PRIVATE enum ied_ws_version		m_get_ws_version		( struct dsd_http_header* );
static BOOL						m_data_complete			( struct dsd_html5_conn*, struct dsd_gather_i_1* );
static BOOL						m_process_frame_header	( struct dsd_html5_conn*, struct dsd_gather_i_1** );
static BOOL						m_transform_payload		( struct dsd_frame_header*, struct dsd_gather_i_1* );
static BOOL						m_parse_ws_d17_frame	( void*, struct dsd_http_header*, struct dsd_gather_i_1* );
static void						m_dump_hex				( struct dsd_html5_conn*, char*, int );
PRIVATE char					m_get_byte				( struct dsd_gather_i_1** );
static BOOL						m_handle_rectangle		( struct dsd_call_awcs_html5*, struct dsd_rdp_event *);
static BOOL						m_get_new_workarea		( struct dsd_call_awcs_html5*, struct dsd_aux_get_workarea*, struct dsd_gather_i_1** );

/* callbacks */
static void*					m_cb_alloc				( void*, size_t );
static void						m_cb_free				( void*, void* );
static BOOL						m_cb_hdr_compl			( void*, struct dsd_http_header* );
static BOOL						m_cb_data_block			( void*, struct dsd_http_header*, struct dsd_gather_i_1* );
static BOOL						m_cb_ws_handshake		( void*, struct dsd_http_header*, struct dsd_gather_i_1* );
static BOOL						m_cb_ws_d17_data		( void*, struct dsd_http_header*, struct dsd_gather_i_1* );
static BOOL						m_cb_out				( void*, const char*, size_t );

/* public funcs */

/*+---------------------------------------------------------------------+*/
/*| macros:                                                             |*/
/*+---------------------------------------------------------------------+*/
#define M_CALL_AUX(sp,mode,x,y) sp->amc_aux(sp->avc_userfield, mode, x, y )
#define M_READ_FILE(sp,ptr) M_CALL_AUX(sp,DEF_AUX_DISKFILE_ACCESS,ptr,sizeof(*ptr))
#define M_RELEASE_FILE(sp,ptr) M_CALL_AUX(sp,DEF_AUX_DISKFILE_RELEASE,ptr,sizeof(*ptr))

#define M_CALL_AUX(sp,mode,x,y) sp->amc_aux(sp->avc_userfield, mode, x, y )
#define M_ALLOC(sp,ptr,size) M_CALL_AUX(sp,DEF_AUX_MEMGET,ptr,size)
#define M_FREE(sp,ptr) M_CALL_AUX(sp,DEF_AUX_MEMFREE,&ptr,0)
#define M_READ_FILE(sp,ptr) M_CALL_AUX(sp,DEF_AUX_DISKFILE_ACCESS,ptr,sizeof(*ptr))
#define M_RELEASE_FILE(sp,ptr) M_CALL_AUX(sp,DEF_AUX_DISKFILE_RELEASE,ptr,sizeof(*ptr))
#define M_FILE_TIME(sp,ptr) M_CALL_AUX(sp,DEF_AUX_DISKFILE_TIME_LM,ptr,sizeof(*ptr))
#define M_STRING_FROM_EPOCH(sp,ptr) M_CALL_AUX(sp,DEF_AUX_STRING_FROM_EPOCH,ptr,sizeof(*ptr))
#define M_EPOCH_FROM_STRING(sp,ptr) M_CALL_AUX(sp,DEF_AUX_EPOCH_FROM_STRING,ptr,sizeof(*ptr))
#define M_GET_WORKAREA(sp,ptr) M_CALL_AUX(sp,DEF_AUX_GET_WORKAREA,ptr,sizeof(*ptr))
#define M_PRINT(sp,msg,len) M_CALL_AUX(sp,DEF_AUX_CONSOLE_OUT,msg,len)
#define M_CHECK_TRACE(sp,level) (sp->ied_trace_level >= level)

typedef struct dsd_mime_type {
    const char *achc_ending;                    /* file ending           */
    const char *achc_type;                      /* mime type             */
} dsd_mime_type;

static const struct dsd_mime_type dss_mime_types[] = {
    { ".html", "text/html;charset=utf-8" },
    { ".css",  "text/css"                },
    { ".js",   "application/javascript"  },
    { NULL,    NULL                      }
};

/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/

/**
 * private function m_print_event
 * print current event
 *
 * @param[in]   dsd_html5_conn      *adsp_conn  connection handle
 * @param[in]   dsd_brower_event    *adsp_evt   event structure
 * @return      nothing
*/
static void m_print_event( struct dsd_html5_conn    *adsp_conn,
                           struct dsd_browser_event *adsp_evt   )
{
    char rchl_temp[8];

    switch( adsp_evt->iec_type ) {
        case ied_be_control:
            m_printf( adsp_conn, "canvas-size %ux%u, drawing context %s",
                      adsp_evt->uinc_width, adsp_evt->uinc_height,
                      (adsp_evt->ienc_ctx_type==ied_ct_2d?"2d":"unknown") );
            break;
        case ied_be_charkey_pressed:
            memset( rchl_temp, 0, sizeof(rchl_temp) );
            m_cpy_vx_vx( rchl_temp, sizeof(rchl_temp), ied_chs_utf_8,
                         adsp_evt->rchc_key, 1,
                         ied_chs_utf_32 );
            m_printf( adsp_conn, "KeyPress %s (0x%02x%02x%02x%02x)", rchl_temp,
                      adsp_evt->rchc_key[0], adsp_evt->rchc_key[1],
                      adsp_evt->rchc_key[2], adsp_evt->rchc_key[3] );
            break;
        case ied_be_funckey_press:
            m_printf( adsp_conn, "FuncKeyPress %s", achg_function_keys[adsp_evt->uchc_function] );
            break;
        case ied_be_funckey_release:
            m_printf( adsp_conn, "FuncKeyRelease %s", achg_function_keys[adsp_evt->uchc_function] );
            break;
        case ied_be_mouse_move:
            m_printf( adsp_conn, "MouseMove x=%u y=%u", adsp_evt->uinc_x,
                                                        adsp_evt->uinc_y );
            break;
        case ied_be_mouse_press:
            m_printf( adsp_conn, "MousePress x=%u y=%u button=%hu", adsp_evt->uinc_x,
                      adsp_evt->uinc_y, adsp_evt->uisc_button );
            break;
        case ied_be_mouse_release:
            m_printf( adsp_conn, "MouseRelease x=%u y=%u button=%hu", adsp_evt->uinc_x,
                      adsp_evt->uinc_y, adsp_evt->uisc_button );
            break;
        case ied_be_mouse_wheel:
            m_printf( adsp_conn, "MouseWheel x=%u y=%u wheel=%d", adsp_evt->uinc_x,
                      adsp_evt->uinc_y, adsp_evt->inc_wheel );
            break;
    }
} /* end of m_print_event */


static BOOL m_create_frame_header( struct dsd_html5_header *adsp_html5_header, int inp_payload_len, WORD wp_opcode )
{
    /* Length of Payload is restricted atm... */

    /* 
     * First Byte
     * Fin Bit: set, because we are not supporting frame chains atm
     * RSV 1-3: not set
     * opcode : binary
    */
    adsp_html5_header->chrc_header[0] = ( 0x80 | wp_opcode );
    adsp_html5_header->inc_len++;

    /*
     * Second Byte
     * Mask: not set
     * Size: depending on payload
    */

    if( inp_payload_len < 126 )
    {
        adsp_html5_header->chrc_header[1] = inp_payload_len;
        adsp_html5_header->inc_len++;
    }
    else if( inp_payload_len >= 126 && inp_payload_len <= 65535 )
    {
        adsp_html5_header->chrc_header[1] = 126;
        /* third & fourth byte store the length */
        adsp_html5_header->chrc_header[2] = inp_payload_len >> 8;
        adsp_html5_header->chrc_header[3] = inp_payload_len & 0xff;
        adsp_html5_header->inc_len += 3;
    }
	else // more than 16 bit payload
	{
		adsp_html5_header->chrc_header[1] = 127;
		// set 4 bytes to zero, because we can have a 32 bit payload length atm
		// can be buggy, but atm acceptable
		adsp_html5_header->chrc_header[2] = 0x00;
        adsp_html5_header->chrc_header[3] = 0x00;
		adsp_html5_header->chrc_header[4] = 0x00;
		adsp_html5_header->chrc_header[5] = 0x00;
		adsp_html5_header->chrc_header[6] = (char)(inp_payload_len >> 24) & 0xFF;
		adsp_html5_header->chrc_header[7] = (char)(inp_payload_len >> 16) & 0xFF;
		adsp_html5_header->chrc_header[8] = (char)(inp_payload_len >>  8) & 0xFF;
		adsp_html5_header->chrc_header[9] = (char)(inp_payload_len) & 0xFF;
		adsp_html5_header->inc_len += 9;
	}

    return TRUE;
}

/**
 * private function m_handle_ws
 *   handle incoming websocket data
 *
 * @param[in]   dsd_html5_conn  *adsp_conn      connection handle
 * @param[in]   dsd_gather_i_1  *adsp_data      input data
 * @return      BOOL
*/
static BOOL m_handle_ws( struct dsd_html5_conn   *adsp_conn,
                         struct dsd_gather_i_1   *adsp_data,
						 struct dsd_browser_event *adsp_browser_event )
{
    BOOL                     bol_ret;           /* return from parsing   */
    //struct dsd_browser_event dsl_evt;           /* current browser event */
    struct dsd_gather_i_1    *adsl_temp;        /* temp gather for trace */
    struct dsd_html5_answer  dsl_html5_answer;
    struct dsd_html5_header  dsl_html5_header;
    size_t                   uinl_send;
	int						 iml1;

    memset( &dsl_html5_header, 0, sizeof(dsl_html5_header) );
    memset( &dsl_html5_answer, 0, sizeof(dsl_html5_answer) );

    /* hex dump incoming packet if trace is verbose */
    if ( M_CHECK_TRACE(adsp_conn->adsc_awcs_html5, ied_awcs_html5_tl_verbose) ) {
        adsl_temp = adsp_data;
        while ( adsl_temp ) {
            m_dump_hex( adsp_conn, 
                        adsl_temp->achc_ginp_cur,
                        (int)(   adsl_temp->achc_ginp_end
                                - adsl_temp->achc_ginp_cur) );
            adsl_temp = adsl_temp->adsc_next;
        }
    }

//    memset( &dsl_evt, 0, sizeof(struct dsd_browser_event) );
	bol_ret = m_jp_parse_event( adsp_data, adsp_conn->dsc_cur_frame_header.ullc_payload_len, adsp_browser_event );
    if ( bol_ret == TRUE ) {
        if ( M_CHECK_TRACE(adsp_conn->adsc_awcs_html5, ied_awcs_html5_tl_info) ) {
            m_print_event( adsp_conn, adsp_browser_event );
        }
        

		if( adsp_browser_event->iec_type != ied_be_control )
		{	
			/* move gatherpointer */
			//iml1 = adsp_conn->dsc_cur_frame_header.ullc_payload_len;
			//while( iml1-- )
			//{
			//	if(adsp_data->achc_ginp_cur == adsp_data->achc_ginp_end)
			//	{
			//		/* cant be, but check */
			//		if(adsp_data->adsc_next == NULL)
			//		{
			//			return TRUE;
			//		}

			//		adsp_data = adsp_data->adsc_next;
			//	}
			//	else
			//	{
			//		adsp_data->achc_ginp_cur++;
			//	}
			//}
			return TRUE;
		}

		m_handle_control( &dsl_html5_answer, &(adsp_conn->dsc_ctx), adsp_browser_event );

        // cancel if we dont have payload
        if( dsl_html5_answer.inc_len == 0 ){ return TRUE; }

        m_create_frame_header( &dsl_html5_header, dsl_html5_answer.inc_len, 0x01 );
        
        /* send header */
        uinl_send = m_to_output( adsp_conn,
                                 dsl_html5_header.chrc_header,
                                 dsl_html5_header.inc_len );
        if ( uinl_send != (size_t)dsl_html5_header.inc_len ) {
            return FALSE;
        }
        
        /* send payload */
        uinl_send = m_to_output( adsp_conn,
                                 dsl_html5_answer.chrc_answer,
                                 dsl_html5_answer.inc_len );
        if ( uinl_send != (size_t)dsl_html5_answer.inc_len ) {
            return FALSE;
        }

    } else {
        if ( M_CHECK_TRACE(adsp_conn->adsc_awcs_html5, ied_awcs_html5_tl_warn) ) {
            m_printf( adsp_conn, "WARNING: unknown event received - ignored");
            /* dump data and mark as processed */
            while ( adsp_data ) {
                m_dump_hex( adsp_conn,
                            adsp_data->achc_ginp_cur,
                            (int)(   adsp_data->achc_ginp_end
                                   - adsp_data->achc_ginp_cur) );
                adsp_data->achc_ginp_cur = adsp_data->achc_ginp_end;
                adsp_data = adsp_data->adsc_next;
            }
        }
    }
    return TRUE;
} /* end of m_handle_ws */


/**
 * private function m_add_path
 *
 * @param[in/out]   dsd_unicode_string  *adsp_output    output buffer
 * @param[in]       dsd_unicode_string  *adsp_path      path input
 * @param[in]       dsd_unicode_string  *adsp_file      file input
*/
static BOOL m_add_path( struct dsd_unicode_string *adsp_output,
                        struct dsd_unicode_string *adsp_path,
                        struct dsd_unicode_string *adsp_file    )
{
    struct dsd_unicode_string dsl_slash;        /* slash                 */
    int                       inl_length;       /* needed output length  */
    int                       inl_copied;       /* copied length         */
    int                       inl_offset;       /* offset in output      */

    /* copy path */
    inl_length = m_len_vx_ucs( adsp_output->iec_chs_str, adsp_path );
    if ( inl_length > adsp_output->imc_len_str ) {
        return FALSE;
    }

    inl_copied = m_cpy_vx_ucs( adsp_output->ac_str, adsp_output->imc_len_str,
                               adsp_output->iec_chs_str, adsp_path );
    if ( inl_copied != inl_length ) {
        return FALSE;
    }
    inl_offset = inl_length;

    /* copy slash */
    dsl_slash.ac_str = (void*)"/";
    dsl_slash.imc_len_str = 1;
    dsl_slash.iec_chs_str = ied_chs_utf_8;
    inl_length = m_len_vx_ucs( adsp_output->iec_chs_str, &dsl_slash );
    if ( inl_length > adsp_output->imc_len_str ) {
        return FALSE;
    }

    inl_copied = m_cpy_vx_ucs( (void*)((char*)adsp_output->ac_str + inl_offset),
                               adsp_output->imc_len_str - inl_offset,
                               adsp_output->iec_chs_str, &dsl_slash );
    if ( inl_copied != inl_length ) {
        return FALSE;
    }
    inl_offset += inl_length;

    /* copy file */
    inl_length = m_len_vx_ucs( adsp_output->iec_chs_str, adsp_file );
    if ( inl_offset + inl_length > adsp_output->imc_len_str ) {
        return FALSE;
    }

    inl_copied = m_cpy_vx_ucs( (void*)((char*)adsp_output->ac_str + inl_offset),
                               adsp_output->imc_len_str - inl_offset,
                               adsp_output->iec_chs_str, adsp_file );
    if ( inl_copied != inl_length ) {
        return FALSE;
    }

    /* set output length */
    adsp_output->imc_len_str = inl_offset + inl_copied;
    return TRUE;
} /* end of m_add_path */


/**
 * private function m_to_output
 * put given data to output
 *
 * @param[in]   dsd_html5_conn      *adsp_conn      current connection
 * @param[in]   const char          *achp_data      pointer to data
 * @param[in]   size_t              uinp_length     length fo data
 * @return      size_t                              copied bytes
*/
static size_t m_to_output( struct dsd_html5_conn *adsp_conn,
                           const char *achp_data, size_t uinp_length )
{
    struct dsd_call_awcs_html5  *adsl_html5;    /* awcs html call struct */
    struct dsd_gather_i_1       *adsl_gather;   /* current gather        */
    size_t                      uinl_free;      /* still free in workarea*/
    size_t                      uinl_copy;      /* bytes to be copied    */
    size_t                      uinl_out;       /* "send" bytes          */
    struct dsd_aux_get_workarea dsl_wa;         /* get new workarea      */
    BOOL                        bol_ret;        /* return from aux call  */

    if ( achp_data == NULL || uinp_length < 1 ) {
        return 0;
    }
    uinl_out = 0;

    /*
        workarea will look like this:
        +---------------+---------- ... ----------+
        | gather struct |          data           |
        +---------------+---------- ... ----------+

        if workarea is too small, we get another one and set next pointer
        in first gather
    */

    /*
        find current gather:
    */
    adsl_html5 = adsp_conn->adsc_awcs_html5;
    if ( adsl_html5->adsc_gather_i_1_out == NULL ) {
        adsl_html5->adsc_gather_i_1_out = (struct dsd_gather_i_1*)
                                                adsl_html5->achc_work_area;
        adsl_gather = adsl_html5->adsc_gather_i_1_out;
        adsl_gather->adsc_next     = NULL;
        adsl_gather->achc_ginp_cur =   adsl_html5->achc_work_area
                                     + sizeof(struct dsd_gather_i_1);
        adsl_gather->achc_ginp_end = adsl_gather->achc_ginp_cur;

        adsp_conn->inc_size_wa = adsl_html5->inc_len_work_area;
    } else {
        adsl_gather = adsl_html5->adsc_gather_i_1_out;
        while ( adsl_gather->adsc_next != NULL ) {
            adsl_gather = adsl_gather->adsc_next;
        }
    }

    /*
        copy data to workarea:
    */
    do {
        uinl_free =   ((char*)adsl_gather + adsp_conn->inc_size_wa)
                    - adsl_gather->achc_ginp_end;
        if ( uinl_free == 0 ) {
            /*
                get new workarea
            */
            bol_ret = M_GET_WORKAREA( adsl_html5, &dsl_wa );
            if ( bol_ret == FALSE ) {
                return uinl_out;
            }
            adsl_gather->adsc_next = (struct dsd_gather_i_1*)
                                                     dsl_wa.achc_work_area;
            adsl_gather = adsl_gather->adsc_next;
            
            adsl_gather->adsc_next     = NULL;
            adsl_gather->achc_ginp_cur =   dsl_wa.achc_work_area
                                         + sizeof(struct dsd_gather_i_1);
            adsl_gather->achc_ginp_end = adsl_gather->achc_ginp_cur;

            adsp_conn->inc_size_wa = dsl_wa.imc_len_work_area;
            uinl_free =   ((char*)adsl_gather + adsp_conn->inc_size_wa)
                        - adsl_gather->achc_ginp_end;
        }

        uinl_copy = (uinl_free > uinp_length)?uinp_length:uinl_free;
        memcpy( adsl_gather->achc_ginp_end, achp_data, uinl_copy );
        adsl_gather->achc_ginp_end += uinl_copy;
        achp_data                  += uinl_copy;
        uinp_length                -= uinl_copy;
        uinl_out                   += uinl_copy;
    } while ( uinp_length > 0 );

    return uinl_out;
} /* end of m_to_output */


/**
 * private function m_get_fullpath
 * calculate fullpath from file name
 *
 * @param[in]   dsd_html5_conn      *adsp_conn      connection handle
 * @param[in]   dsd_unicode_string  *adsp_file      file name
 * @param[out]  dsd_unicode_string  *adsp_fpath     full path of file
*/
static void m_get_fullpath( struct dsd_html5_conn     *adsp_conn,
                            struct dsd_unicode_string *adsp_file,
                            struct dsd_unicode_string *adsp_fpath )
{
    /* check for '/' file */
    if (    adsp_file->imc_len_str == 1
         && *((char*)adsp_file->ac_str) == '/' ) {
        adsp_file = &adsp_conn->adsc_awcs_html5->adsc_conf->dsc_default_html;
    }

    m_add_path( adsp_fpath,
                &adsp_conn->adsc_awcs_html5->adsc_conf->dsc_root_dir,
                adsp_file );
} /* end of m_get_fullpath */


/**
 * private function m_get_mimetype
 * get mimetype from file
 *
 * @param[in]   dsd_unicode_string  *adsp_file      file
 * @return      char*                               content type string
*/
static char* m_get_mimetype( struct dsd_unicode_string *adsp_file )
{
    char                       *achl_ending;    /* file ending           */
    int                        inl_length;      /* length of file ending */
    const struct dsd_mime_type *adsl_mtype;     /* mime type structure   */
    BOOL                       bol_ret;         /* return from compare   */
    int                        inl_comp;        /* result from compare   */

    achl_ending = (char*)adsp_file->ac_str + adsp_file->imc_len_str - 1;
    for ( ; achl_ending >= (char*)adsp_file->ac_str; achl_ending-- ) {
        switch ( *achl_ending ) {
            case '.':
                inl_length =   adsp_file->imc_len_str
                             - (int)(achl_ending - (char*)adsp_file->ac_str);
                adsl_mtype = dss_mime_types;
                while ( adsl_mtype->achc_ending != NULL ) {
                    bol_ret = m_cmpi_vx_vx( &inl_comp,
                                            (void*)achl_ending, inl_length,
                                            adsp_file->iec_chs_str,
                                            (void*)adsl_mtype->achc_ending,
                                            -1, ied_chs_utf_8 );
                    if (    bol_ret == TRUE
                         && inl_comp == 0   ) {
                        return (char*)adsl_mtype->achc_type;
                    }
                    adsl_mtype++;
                }
                break;
            case '/':
                break;
            default:
                continue;
        }
        break;
    }
    return NULL;
} /* end of m_get_mimetype */


/**
 * private function m_send_file
 *
 * @param[in]   dsd_html5_conn      *adsp_conn
 * @param[in]   dsd_unicode_string  *adsp_file
*/
static void m_send_file( struct dsd_html5_conn     *adsp_conn,
                         struct dsd_unicode_string *adsp_file  )
{
    BOOL                         bol_ret;       /* return for some funcs */
    struct dsd_hl_aux_diskfile_1 dsl_file;      /* file access structure */
    struct dsd_hl_aux_epoch_1    dsl_epoch;     /* last modified time    */
    char                         chrl_epoch[30];/* epoch as string       */
    char                         *achl_mtype;   /* mime type             */

    /*
        open the file:
    */
    dsl_file.ac_name      = adsp_file->ac_str;
    dsl_file.inc_len_name = adsp_file->imc_len_str;
    dsl_file.iec_chs_name = adsp_file->iec_chs_str;
    bol_ret = M_READ_FILE( adsp_conn->adsc_awcs_html5, &dsl_file );
    if (    bol_ret               == FALSE
         || dsl_file.iec_dfar_def != ied_dfar_ok ) {
        // TODO: error page
        return;
    }

    /*
        prepare output header:
    */
    /* HTTP/1.1 200 Ok */
    bol_ret = m_create_response( adsp_conn->avc_http_creator, ied_vs_http_1_1,
                                 ied_st_http_ok );
    if ( bol_ret == FALSE ) {
        // TODO: error page
		M_RELEASE_FILE( adsp_conn->adsc_awcs_html5, &dsl_file.ac_handle );
        return;
    }

    /* Last modified */
    memset( &dsl_epoch, 0, sizeof(struct dsd_hl_aux_epoch_1) );
    dsl_epoch.iec_chs_epoch = ied_chs_utf_8;
    dsl_epoch.imc_epoch_val = dsl_file.adsc_int_df1->imc_time_last_mod;
    dsl_epoch.ac_epoch_str  = (void*)chrl_epoch;
    dsl_epoch.inc_len_epoch = (int)sizeof(chrl_epoch);
    bol_ret = M_STRING_FROM_EPOCH( adsp_conn->adsc_awcs_html5, &dsl_epoch );
    if ( bol_ret == TRUE ) {
        bol_ret = m_create_line_s( adsp_conn->avc_http_creator,
                                   ied_hdr_ln_http_last_modified,
                                   (char*)dsl_epoch.ac_epoch_str,
                                   dsl_epoch.inc_len_epoch        );
        if ( bol_ret == FALSE ) {
            // TODO: error page
            M_RELEASE_FILE( adsp_conn->adsc_awcs_html5, &dsl_file.ac_handle );
            return;
        }
    }

    /* Content-Length */
    bol_ret = m_create_line_n( adsp_conn->avc_http_creator,
                               ied_hdr_ln_http_content_length,
                               (int)(  dsl_file.adsc_int_df1->achc_filecont_end
                                     - dsl_file.adsc_int_df1->achc_filecont_start) );
    if ( bol_ret == FALSE ) {
        // TODO: error page
        M_RELEASE_FILE( adsp_conn->adsc_awcs_html5, &dsl_file.ac_handle );
        return;
    }

    /* Content-Type */
    achl_mtype = m_get_mimetype( adsp_file );
    if ( achl_mtype != NULL ) {
        bol_ret = m_create_line_szt( adsp_conn->avc_http_creator,
                                     ied_hdr_ln_http_content_type,
                                     achl_mtype );
        if ( bol_ret == FALSE ) {
            // TODO: error page
            M_RELEASE_FILE( adsp_conn->adsc_awcs_html5, &dsl_file.ac_handle );
            return;
        }
    }

    /* close http header */
    bol_ret = m_finish_header( adsp_conn->avc_http_creator );
    if ( bol_ret == FALSE ) {
        // TODO: error page
        M_RELEASE_FILE( adsp_conn->adsc_awcs_html5, &dsl_file.ac_handle );
        return;
    }
    
    m_to_output( adsp_conn,
                 dsl_file.adsc_int_df1->achc_filecont_start,
                   dsl_file.adsc_int_df1->achc_filecont_end
                 - dsl_file.adsc_int_df1->achc_filecont_start );
    M_RELEASE_FILE( adsp_conn->adsc_awcs_html5, &dsl_file.ac_handle );
    return;
} /* end of m_send_file */


/**
 * private function m_send_not_modified
 * 
 *
 * @param[in]   dsd_html5_conn      *adsp_conn      connection handle
*/
static void m_send_not_modified( struct dsd_html5_conn *adsp_conn )
{
    BOOL bol_ret;

    /* HTTP/1.1 304 Not modified */
    bol_ret = m_create_response( adsp_conn->avc_http_creator, ied_vs_http_1_1,
                                 ied_st_http_not_modified );
    if ( bol_ret == FALSE ) {
        // TODO: error page
        return;
    }

    bol_ret = m_finish_header( adsp_conn->avc_http_creator );
    if ( bol_ret == FALSE ) {
        // TODO: error page
        return;
    }
} /* end of m_send_not_modified */


/**
 * private function m_is_file_modified
 * check if file is modified since given date
 *
 * @param[in]   dsd_html5_conn      *adsp_conn      connection handle
 * @param[in]   dsd_unicode_string  *adsp_file      filepath
 * @param[in]   dsd_unicode_string  *adsp_since     modified since
*/
static BOOL m_is_file_modified( struct dsd_html5_conn     *adsp_conn,
                                struct dsd_unicode_string *adsp_file,
                                struct dsd_unicode_string *adsp_since )
{
    BOOL                         bol_ret;       /* return from aux calls */
    struct dsd_hl_aux_epoch_1    dsl_epoch;     /* last modified time    */
    struct dsd_hl_aux_diskfile_1 dsl_file;      /* file access structure */

    /* get last modified timestamp from request */
    memset( &dsl_epoch, 0, sizeof(struct dsd_hl_aux_epoch_1) );
    dsl_epoch.ac_epoch_str  = adsp_since->ac_str;
    dsl_epoch.inc_len_epoch = adsp_since->imc_len_str;
    dsl_epoch.iec_chs_epoch = adsp_since->iec_chs_str;
    bol_ret = M_EPOCH_FROM_STRING( adsp_conn->adsc_awcs_html5, &dsl_epoch );
    if ( bol_ret == FALSE ) {
        return TRUE;
    }

    /* get last modified timestamp from file */
    dsl_file.ac_name      = adsp_file->ac_str;
    dsl_file.inc_len_name = adsp_file->imc_len_str;
    dsl_file.iec_chs_name = adsp_file->iec_chs_str;

    bol_ret = M_FILE_TIME( adsp_conn->adsc_awcs_html5, &dsl_file );
    if ( bol_ret == FALSE ) {
        return TRUE;
    }

    return (dsl_file.imc_time_last_mod > dsl_epoch.imc_epoch_val)?TRUE:FALSE;
} /* end of m_is_file_modified */

/**
 * private function m_to_bigendian
 * convert a 32bit number to its bigendian pendant
 *
 * @param[in]   unsigned int    uinp_num        input number
 * @param[out]  unsigned char   *achp_out       output buffer in bigendian
*/
static void m_to_bigendian( unsigned int uinp_num, unsigned char *achp_out )
{
    achp_out[0] = (unsigned char)((uinp_num >> 24) & 0xFF);
    achp_out[1] = (unsigned char)((uinp_num >> 16) & 0xFF);
    achp_out[2] = (unsigned char)((uinp_num >>  8) & 0xFF);
    achp_out[3] = (unsigned char)((uinp_num      ) & 0xFF);
} /* end of m_to_bigendian */

/**
 * private function m_build_ws_handshake_08
 *    do websocket handshake according to draft 08
 *
*/
static BOOL m_build_ws_checksum_08( const char *achp_key,
                                    char *achp_sha1_sum )
{
    int             imrl_sha1[SHA_ARRAY_SIZE];
    const char      *appendix = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"; 
    char            chrl_start[ 24 + 36 + 1 ]; // key + appendix + end
        
    memset(chrl_start, 0, sizeof(chrl_start) );
    strncpy( chrl_start, achp_key, 24 );
    strcat( chrl_start, appendix ); // 36 bytes

    SHA1_Init( imrl_sha1 );
    SHA1_Update( imrl_sha1, chrl_start, 0, 60 );
    SHA1_Final( imrl_sha1, achp_sha1_sum, 0 );

    return TRUE;
}

/**
 * private function m_ws_handshake_08
 *    do websocket handshake according to draft 08
 *
*/
static BOOL m_ws_handshake_08( struct dsd_html5_conn* adsp_conn,
                               struct dsd_http_header *adsp_hdr,
                               struct dsd_gather_i_1  *adsp_data )
{
    BOOL            bol_ret;
    char            uchl_sha1_digest[SHA_DIGEST_LEN];
    struct          dsd_http_hdr_line *adsl_ws_key;     /* websocket key       */
    const char      *achl_format;      /* printf format helper  */

#define B64_OUT_LEN 29

    int iml_b64_output_len = B64_OUT_LEN;
    char achrl_b64_output[B64_OUT_LEN];

    memset(uchl_sha1_digest, 0, sizeof(uchl_sha1_digest) );
    memset(achrl_b64_output, 0, sizeof( achrl_b64_output ));

    adsl_ws_key = m_search_hdr_line( adsp_hdr, ied_hdr_ln_http_ws_key, NULL );
    if( adsl_ws_key == NULL ){ return FALSE; }
    
    bol_ret = m_build_ws_checksum_08( adsl_ws_key->u.dsc_known.achc_value, uchl_sha1_digest );

    //-------------------------------------------------------------------
    /*
        create an response header!

		EXAMPLE:

        HTTP/1.1 101 Switching Protocols
        Upgrade: WebSocket
        Connection: Upgrade
        Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo= // the base 64 encoded SHA1 checksum

    */
    bol_ret = m_create_response( adsp_conn->avc_http_creator,
                                 ied_vs_http_1_1,
                                 ied_st_http_switching_protocols );
    if ( bol_ret == FALSE ) {
        return FALSE;
    }
    bol_ret = m_create_line_szt( adsp_conn->avc_http_creator,
                                 ied_hdr_ln_http_upgrade,
                                 "WebSocket" );
    if ( bol_ret == FALSE ) {
        return FALSE;
    }
    bol_ret = m_create_line_szt( adsp_conn->avc_http_creator,
                                 ied_hdr_ln_http_connection,
                                 "Upgrade" );
    if ( bol_ret == FALSE ) {
        return FALSE;
    }

    bol_ret = m_to_base64( achrl_b64_output, &iml_b64_output_len, uchl_sha1_digest, SHA_DIGEST_LEN );

    bol_ret = m_create_line_szt( adsp_conn->avc_http_creator,
                                 ied_hdr_ln_http_ws_accept,
                                 (const char *) achrl_b64_output );
    if ( bol_ret == FALSE ) {
        return FALSE;
    }

    /*
    if ( adsp_hdr->u.dsc_request.inc_host_len > 0 ) {
        achl_format = (adsp_conn->adsc_awcs_html5->adsc_conf->boc_secure)?
                      "https://%.*s" : "http://%.*s";
        bol_ret = m_create_line_f( adsp_conn->avc_http_creator,
                                   ied_hdr_ln_http_ws_origin,
                                   achl_format,
                                   adsp_hdr->u.dsc_request.inc_host_len,
                                   adsp_hdr->u.dsc_request.achc_host );
        if ( bol_ret == FALSE ) {
            return FALSE;
        }
        achl_format = (adsp_conn->adsc_awcs_html5->adsc_conf->boc_secure)?
                      "wss://%.*s/" : "ws://%.*s/";
        bol_ret = m_create_line_f( adsp_conn->avc_http_creator,
                                   ied_hdr_ln_http_ws_location,
                                   achl_format,
                                   adsp_hdr->u.dsc_request.inc_host_len,
                                   adsp_hdr->u.dsc_request.achc_host );
        if ( bol_ret == FALSE ) {
            return FALSE;
        }
    }
    */

    bol_ret = m_finish_header( adsp_conn->avc_http_creator );
    if ( bol_ret == FALSE ) {
        return FALSE;
    }
    //-------------------------------------------------------------------

#undef B64_OUT_LEN

    return TRUE;
}

static BOOL m_to_base64( char *achp_dest, int *imp_dest_len, const char *achp_src, int imp_src_len )
{
    unsigned char ucrs_base64[64] =
    {
        0X41, 0X42, 0X43, 0X44, 0X45, 0X46, 0X47, 0X48,  /* 00 - 07 / A - H */
        0X49, 0X4A, 0X4B, 0X4C, 0X4D, 0X4E, 0X4F, 0X50,  /* 08 - 0F / I - P */
        0X51, 0X52, 0X53, 0X54, 0X55, 0X56, 0X57, 0X58,  /* 10 - 17 / Q - X */
        0X59, 0X5A, 0X61, 0X62, 0X63, 0X64, 0X65, 0X66,  /* 18 - 1F / Y - f */
        0X67, 0X68, 0X69, 0X6A, 0X6B, 0X6C, 0X6D, 0X6E,  /* 20 - 27 / g - n */
        0X6F, 0X70, 0X71, 0X72, 0X73, 0X74, 0X75, 0X76,  /* 28 - 2F / o - v */
        0X77, 0X78, 0X79, 0X7A, 0X30, 0X31, 0X32, 0X33,  /* 30 - 37 / w - 3 */
        0X34, 0X35, 0X36, 0X37, 0X38, 0X39, 0X2B, 0X2F   /* 38 - 3F / 4 - / */
    };
    
    unsigned char uchl_temp1 = 0;
    unsigned char uchl_temp2 = 0;

    int iml_filling_bytes = 3 - ( imp_src_len % 3 );
    int iml_b64_len = ( imp_src_len + iml_filling_bytes ) / 3 * 4 + 1; 
    int i = 0;
    int j = 0;

    if( iml_b64_len > *imp_dest_len ){ return FALSE; }

    while( i < imp_src_len )
    {
        char chl0; // holds the first byte of the three bytes needed for base64
        char chl1; // second
        char chl2; // third
        BOOL exit1 = FALSE; // indicates, that the second byte is a filling byte and therefore must not be processed
        BOOL exit2 = FALSE; // same, but byte three

        chl0 = achp_src[i]; // is always a valid byte
        if( i+1 < imp_src_len ){ chl1 = achp_src[i+1]; } // is this byte valid?
        else{ chl1 = 0X00; exit1 = TRUE; } // if not, fill it with a placeholder and set flag
        if( i+2 < imp_src_len ){ chl2 = achp_src[i+2]; }
        else{ chl2 = 0X00; exit2 = TRUE; }
        
        /* first digit */
        uchl_temp1 = (unsigned int) chl0 & 0XFC; // mask is 1111 1100
        uchl_temp1 = uchl_temp1 >> 2; // then shift it 2 positions right
        achp_dest[j++] = ucrs_base64[uchl_temp1];

        /* second digit */
        uchl_temp1 = (unsigned int) chl0 & 0X03; // mask is 0000 0011
        uchl_temp1 = uchl_temp1 << 4; // then shift this bytes 4 positions to the left
        uchl_temp2 = ( (unsigned int) chl1 ) & 0XF0; // and get the upper 4 bits from the second byte 1111 0000
        uchl_temp2 = uchl_temp2 >> 4; // but shift them 4 pos right
        achp_dest[j++] = ucrs_base64[ uchl_temp1 | uchl_temp2 ]; // 2 bits from the first byte, 4 from the second

        /* third digit */
        if(exit1){ break; }
        uchl_temp1 = ( (unsigned int) chl1 ) & 0X0F; // 0000 1111
        uchl_temp1 <<= 2;
        uchl_temp2 = ( (unsigned int) chl2 ) & 0XC0; // 1100 0000
        uchl_temp2 >>= 6;
        achp_dest[j++] = ucrs_base64[ uchl_temp1 | uchl_temp2 ];

        /* fourth digit */
        if(exit2){ break; }
        uchl_temp1 = (unsigned int) chl2 & 0X3F; // 0011 1111
        achp_dest[j++] = ucrs_base64[uchl_temp1];

        i += 3;
    }

    while( iml_filling_bytes-- )
    {
        achp_dest[j++] = '=';
    }

    achp_dest[j++] = '\0';
    *imp_dest_len = j;

    return TRUE;
}


/**
 * private function m_search
 *  search a sign in the given gather
 *
 * @param[in]   dsd_gather_i_1 *adsp_data       data to search in
 * @param[in]   char           chp_sign         search sign
 * @param[out]  dsd_gather_i_1 **aadsp_found    found in this gather
 * @param[out]  char           **aachp_found    found at this pointer
*/
static void m_search( struct dsd_gather_i_1 *adsp_data,    char chp_sign,
                      struct dsd_gather_i_1 **aadsp_found, char **aachp_found )
{
    char *achl_cur = NULL;

    while ( adsp_data != NULL ) {
        achl_cur = adsp_data->achc_ginp_cur;
        while (    achl_cur  <  adsp_data->achc_ginp_end
                && *achl_cur != chp_sign                 ) {
            achl_cur++;
        }
        if ( *achl_cur == chp_sign ) {
            break;
        }
        adsp_data = adsp_data->adsc_next;
    }

    *aadsp_found = adsp_data;
    *aachp_found = (adsp_data)?achl_cur:NULL;
} /* end of m_search */


/**
 * private function m_temp_get_byte
 *
 * reads one char, but doesnt modifiy the pointer in the gather
 *
 * @param[in/out]   dsd_gather_i_1  **aadsp_data
 * @param[in/out]   char            **aachp_cur
 * @return          char
*/
PRIVATE char m_temp_get_byte( struct dsd_gather_i_1 **aadsp_data, char **aachp_cur )
{
    char chl_byte = *(*aachp_cur);
    (*aachp_cur)++;
    while (    (*aadsp_data) != NULL
            && *aachp_cur >= (*aadsp_data)->achc_ginp_end )
    {
        *aadsp_data = (*aadsp_data)->adsc_next;
        if( *aadsp_data != NULL )
        {
            *aachp_cur = (*aadsp_data)->achc_ginp_cur;
        }
    }
    
    return chl_byte;
} /* end of m_temp_get_byte */


/**
 * private function m_printf
 *  print message (up to 512 signs) to wsp console in common printf way
 *  wsp will cut longer message, so a greater buffer makes no sence
 *
 * @param[in]   struct dsd_html5_conn   *adsp_conn
 * @param[in]   const char              *achp_format
 * @return      nothing
*/
static void m_printf( struct dsd_html5_conn *adsp_conn,
                      const char            *achp_format, ...  )
{
    char    rchl_buffer[512 + 1];               /* buffer for printing   */
    int     inl_size;                           /* used buffer size      */
    va_list dsl_args;                           /* argument list         */

    va_start( dsl_args, achp_format );
    inl_size = vsnprintf( &rchl_buffer[0], 512, achp_format, dsl_args );
    va_end( dsl_args );
    if ( inl_size > 512 || inl_size < 0 ) {
        inl_size = 512;
    }

    M_PRINT( adsp_conn->adsc_awcs_html5, rchl_buffer, inl_size );
} /* end of m_printf */


static BOOL m_process_rdp_commands( struct dsd_html5_conn *adsp_conn, struct dsd_html5_answer *adsp_html5_answer )
{
	dsd_html5_header	dsl_html5_header;
	size_t				uinl_send;

	memset(&dsl_html5_header, 0, sizeof(dsd_html5_header));

	m_create_frame_header( &dsl_html5_header, adsp_html5_answer->inc_len, 0x02 );

	/* send header */
	uinl_send = m_to_output( adsp_conn,
							 dsl_html5_header.chrc_header,
							 dsl_html5_header.inc_len );
	if ( uinl_send != (size_t)dsl_html5_header.inc_len ) {
		return FALSE;
	}
    
	/* send payload */
	uinl_send = m_to_output( adsp_conn,
							 adsp_html5_answer->chrc_answer,
							 adsp_html5_answer->inc_len );
	if ( uinl_send != (size_t)adsp_html5_answer->inc_len ) {
		return FALSE;
	}

	return TRUE;
}

static void m_handle_control( struct dsd_html5_answer  *adsp_answer,
                              struct dsd_canvas_ctx    *adsp_ctx,
                              struct dsd_browser_event *adsp_evt )
{
    /* save incoming width and heigth */
    adsp_ctx->uinc_width  = adsp_evt->uinc_width;
    adsp_ctx->uinc_height = adsp_evt->uinc_height;
    adsp_ctx->ienc_type   = adsp_evt->ienc_ctx_type;

    /* remove startup HOB logo */
    m_start_drawing( adsp_answer );
    m_c2d_sprintf( adsp_answer, "cvs.logoText('Connected! Waiting for RDP Connection!');" );
	m_c2d_cache_func( adsp_answer, "sq", "function(x,y,w,h,d){var a=ctx.createImageData(w,h);var b=a.data;for(var i=0;i<b.length;i++){b[i]=d[i]};ctx.putImageData(a,x,y);}" );
	m_finish_drawing( adsp_answer );
} /* end of m_handle_control */

/**
 * private function m_get_ws_version
 *   get the version of the websocket for the handshake
 *
 * @param[in]   dsd_http_header *adsp_http_header    header lines
 * @return      enum ied_ws_version                  version
*/
PRIVATE enum ied_ws_version m_get_ws_version( struct dsd_http_header *adsp_http_header )
{
    unsigned int i;

    for( i = 0; i < adsp_http_header->uinc_lines; i++)
    {
        if(adsp_http_header->adsc_lines[i].ienc_type == ied_hdr_ln_http_ws_version )
        {
            return( (enum ied_ws_version) atoi( (const char *)adsp_http_header->adsc_lines[i].u.dsc_known.achc_value) );
        }
    }
    return( (enum ied_ws_version) 0 );
}


/* checks if data arrived fully */
static BOOL m_data_complete( struct dsd_html5_conn* adsl_conn, struct dsd_gather_i_1 *adsp_data )
{
    char    *cur;
	int		il_byte_count = 0;

    cur = adsp_data->achc_ginp_cur;
           
	while( adsp_data != NULL )
	{
		m_temp_get_byte( &adsp_data, &cur );
		il_byte_count++;
		if( il_byte_count == adsl_conn->dsc_cur_frame_header.ullc_payload_len)
		{
			return TRUE;
		}
	}

	return FALSE;
}

static BOOL m_process_frame_header( struct dsd_html5_conn *adsl_conn, struct dsd_gather_i_1 **aadsp_data )
{
    unsigned char               chl_cur_byte;
	
	/*** 1st Part ***/
	/* FIN - Flag   */
	/* Extensions   */
	/* Frame Type   */
	/****************/
	if(adsl_conn->dsc_cur_frame_header.ic_header_pos == 0)
	{
		chl_cur_byte           = m_get_byte( aadsp_data );
		adsl_conn->dsc_cur_frame_header.boc_fin_frame  = ( chl_cur_byte & 0x80 ) >> 7; // last frame ?
		adsl_conn->dsc_cur_frame_header.uchc_extension = ( chl_cur_byte & 0x70 ) >> 4; // extensions
		adsl_conn->dsc_cur_frame_header.uchc_frametype = chl_cur_byte & 0x0F; // opcode
		adsl_conn->dsc_cur_frame_header.ic_header_pos++;
	}

	if ( *aadsp_data == NULL ){ return FALSE; }
	/*** 2nd Part ***/
	/* Mask - Flag  */
	/* Payload Len  */
	/****************/
    if(adsl_conn->dsc_cur_frame_header.ic_header_pos == 1)
	{
		chl_cur_byte     = m_get_byte( aadsp_data );
		adsl_conn->dsc_cur_frame_header.boc_mask = ( chl_cur_byte & 0x80 ) >> 7;
		adsl_conn->dsc_cur_frame_header.ullc_payload_len = ( chl_cur_byte & 0x7F );
		if( adsl_conn->dsc_cur_frame_header.ullc_payload_len == 126)
		{
			adsl_conn->dsc_cur_frame_header.ic_length_pos = 2; // following 2 bytes are the payload length
			adsl_conn->dsc_cur_frame_header.ullc_payload_len = 0;
			adsl_conn->dsc_cur_frame_header.ic_header_pos++;
		}
		else if ( adsl_conn->dsc_cur_frame_header.ullc_payload_len == 127)
		{
			adsl_conn->dsc_cur_frame_header.ic_length_pos = 8; // following 8 bytes are the payload length
			adsl_conn->dsc_cur_frame_header.ullc_payload_len = 0;
			adsl_conn->dsc_cur_frame_header.ic_header_pos++;
		}
		else
		{
			adsl_conn->dsc_cur_frame_header.ic_header_pos += 2; // jump over part 3
			adsl_conn->dsc_cur_frame_header.ic_length_pos = 4; // 4 bytes for the mask
		}
	}

	/*** 3rd Part ***/
	/* Len Bytes,   */
	/* if Len = 126 */
	/* or Len = 127 */
	/****************/
	if(adsl_conn->dsc_cur_frame_header.ic_header_pos == 2)
	{
		while( adsl_conn->dsc_cur_frame_header.ic_length_pos > 0)
		{
			if ( *aadsp_data == NULL ){ return FALSE; }
			chl_cur_byte = m_get_byte( aadsp_data );	
			adsl_conn->dsc_cur_frame_header.ullc_payload_len |= chl_cur_byte;
			if( adsl_conn->dsc_cur_frame_header.ic_length_pos > 1 )
			{
				adsl_conn->dsc_cur_frame_header.ullc_payload_len <<= 8;  // dont shift, if we reached the last byte
			}
			adsl_conn->dsc_cur_frame_header.ic_length_pos--;
		}
		adsl_conn->dsc_cur_frame_header.ic_header_pos++;
		adsl_conn->dsc_cur_frame_header.ic_length_pos = 4; // 4 bytes for the mask
	}

	/*** 4th Part ***/
	/* 4 Mask Bytes */
	/****************/
    if(adsl_conn->dsc_cur_frame_header.ic_header_pos == 3)
	{
		while( adsl_conn->dsc_cur_frame_header.ic_length_pos > 0)
		{
			if ( *aadsp_data == NULL ){ return FALSE; }
			chl_cur_byte = m_get_byte( aadsp_data );
			adsl_conn->dsc_cur_frame_header.chrc_mask[ 4 - adsl_conn->dsc_cur_frame_header.ic_length_pos ] = chl_cur_byte;
			adsl_conn->dsc_cur_frame_header.ic_length_pos--;
		}
		adsl_conn->dsc_cur_frame_header.ic_header_pos++;
	}

    return TRUE;
}


static BOOL m_transform_payload( struct dsd_frame_header *dsl_fh, struct dsd_gather_i_1 *adsp_data )
{
    char                        *achl_cur;
    int                         iml1;

    achl_cur = adsp_data->achc_ginp_cur; // use temp pointer! do not modify original!

    for( iml1 = 0; iml1 < (dsl_fh->ullc_payload_len); iml1++ )
    {
        *achl_cur ^= dsl_fh->chrc_mask[ iml1 % 4 ]; // transform the byte
        m_temp_get_byte( &adsp_data, &achl_cur );   // increment temp pointer
    }

    return TRUE;
}


static BOOL m_parse_ws_d17_frame( void						*avp_usrfld,
                                  struct dsd_http_header	*adsp_hdr,
                                  struct dsd_gather_i_1		*adsp_data )
{
    struct dsd_html5_conn *adsl_conn;           /* our connection handle */
    BOOL                    bol_ret;
    adsl_conn = (struct dsd_html5_conn*)avp_usrfld;

	while( ( adsp_data->achc_ginp_cur != adsp_data->achc_ginp_end ) || adsp_data->adsc_next != NULL )
	{
		if(adsl_conn->dsc_cur_frame_header.ic_header_pos <= 3) // Header consists of part 0 - part 3
		{
			bol_ret = m_process_frame_header( adsl_conn, &adsp_data );
			if( bol_ret == FALSE ) // FALSE means: Header not complete
			{
				return TRUE; // wait for more data... confusing, i know :D
			}
			if(adsl_conn->dsc_cur_frame_header.boc_fin_frame != 1)
			{
				// TODO: Multiframe Support... it's not implemented, because of huge memory requirement.
				// Frames can be unlimited in size, and it has to be buffered somewhere
				// until this point is worked out, only 1 frame up to 64kb is allowed
				return FALSE;
			}
		}

		if( !m_data_complete( adsl_conn, adsp_data ) )
		{
			return TRUE; // wait for more data
		}

		switch( adsl_conn->dsc_cur_frame_header.uchc_frametype )
		{
			case 0x01: // text
				bol_ret = m_transform_payload( &(adsl_conn->dsc_cur_frame_header), adsp_data );
				if( bol_ret == FALSE )
				{
					return FALSE;
				}
				break;
			case 0x02: // binary
			default:
				return FALSE;
		}

		memset( &adsl_conn->dsc_browser_event, 0, sizeof(adsl_conn->dsc_browser_event) );
		bol_ret = m_handle_ws( adsl_conn, adsp_data, &adsl_conn->dsc_browser_event );
		if( bol_ret == FALSE )
		{
			return FALSE;
		}
		adsl_conn->dsc_cur_frame_header.ic_header_pos = 0;
	}

    return TRUE;
}


static const char chrstrans[] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

/**
 * private function m_dump_hex
 *
 * @param[in]   char    *achp_buff
 * @param[in]   int     implength
*/
static void m_dump_hex( struct dsd_html5_conn *adsp_conn,
                        char *achp_buff, int implength )
{
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
     m_printf( adsp_conn, "%.*s\n", sizeof(chrlwork1), chrlwork1 );
   }
} /* end m_dump_hex() */

/**
 * private function m_get_byte
 *
 * reads and moves the pointer one char
 *
 * @param[in/out]   dsd_gather_i_1  **aadsp_data
 * @return          char
*/
PRIVATE char m_get_byte( struct dsd_gather_i_1 **aadsp_data )
{
    char chl_byte = *((*aadsp_data)->achc_ginp_cur);
    ((*aadsp_data)->achc_ginp_cur)++;
    while (    (*aadsp_data) != NULL
            && (*aadsp_data)->achc_ginp_cur >= (*aadsp_data)->achc_ginp_end ) {
        *aadsp_data = (*aadsp_data)->adsc_next;
    }
    return chl_byte;
} /* end of m_get_byte */


/*+---------------------------------------------------------------------+*/
/*| http callback functions:                                            |*/
/*+---------------------------------------------------------------------+*/
/**
 * private function m_cb_alloc
 * http callback allocating function
 *
 * @param[in] void      *avp_usrfld             userfield handle
 * @param[in] size_t    uinp_size               size to be allocated
 * @return    void*                             allocated memory
*/
static void* m_cb_alloc( void *avp_usrfld, size_t uinp_size )
{
    void                  *avl_ptr;             /* allocated memory      */
    BOOL                  bol_ret;              /* return from aux call  */
    struct dsd_html5_conn *adsl_conn;           /* current connection    */

    adsl_conn = (struct dsd_html5_conn*)avp_usrfld;
    bol_ret   = M_ALLOC( adsl_conn->adsc_awcs_html5, &avl_ptr, uinp_size );

    return (bol_ret == TRUE)?avl_ptr:NULL;
} /* end of m_cb_alloc */


/**
 * private function m_cb_free
 * http callback free function
 *
 * @param[in] void      *avp_usrfld             userfield handle
 * @param[in] void      *avp_ptr                pointer to free
 * @return    nothing
*/
static void m_cb_free( void *avp_usrfld, void *avp_ptr )
{
    struct dsd_html5_conn *adsl_conn;           /* current connection    */

    adsl_conn = (struct dsd_html5_conn*)avp_usrfld;
    M_FREE( adsl_conn->adsc_awcs_html5, avp_ptr );
} /* end of m_cb_free */


/**
 * private function m_cb_hdr_compl
 * http callback function for complete parsed http header
 *
 * @param[in] void              *avp_usrfld     userfield handle
 * @param[in] dsd_http_header   *adsp_hdr       header structure
 * @return    BOOL
*/
static BOOL m_cb_hdr_compl( void *avp_usrfld, struct dsd_http_header *adsp_hdr )
{
    struct dsd_html5_conn     *adsl_conn;       /* current connection    */
    struct dsd_unicode_string dsl_file;         /* requested url         */
    struct dsd_unicode_string dsl_path;         /* full path of req. url */
    char                      chrl_path[256];   /* buffer for path       */
    struct dsd_http_hdr_line  *adsl_mod_since;  /* modified since field  */
    BOOL                      bol_modified;     /* is file modified?     */
    struct dsd_unicode_string dsl_since;        /* request modified date */

    if ( adsp_hdr->inc_type != DEF_HTTP_REQUEST ) {
        return FALSE;
    }

    adsl_conn = (struct dsd_html5_conn*)avp_usrfld;

    switch( adsp_hdr->u.dsc_request.ienc_method ) {
        case ied_mt_http_get:
            dsl_file.ac_str      = (void*)adsp_hdr->u.dsc_request.achc_path;
            dsl_file.imc_len_str = adsp_hdr->u.dsc_request.inc_path_len;
            dsl_file.iec_chs_str = ied_chs_utf_8;

            /* get full path of file */
            dsl_path.ac_str      = (void*)chrl_path;
            dsl_path.imc_len_str = (int)sizeof(chrl_path);
            dsl_path.iec_chs_str = ied_chs_utf_8;
            m_get_fullpath( adsl_conn, &dsl_file, &dsl_path );

            /* check if file is already cached */
            adsl_mod_since = m_search_hdr_line( adsp_hdr,
                                                ied_hdr_ln_http_if_modified_since,
                                                NULL );
            if ( adsl_mod_since != NULL ) {
                dsl_since.ac_str = (void*)adsl_mod_since->u.dsc_known.achc_value;
                dsl_since.imc_len_str = adsl_mod_since->u.dsc_known.inc_length;
                dsl_since.iec_chs_str = ied_chs_utf_8;

                bol_modified = m_is_file_modified( adsl_conn, &dsl_path,
                                                   &dsl_since );
                if ( bol_modified == FALSE ) {
                    m_send_not_modified( adsl_conn );
                    break;
                }                
            }

            /* send requested file */
            m_send_file( adsl_conn, &dsl_path );
            break;

        case ied_mt_http_head:
        case ied_mt_http_post:
        default:
            return FALSE;
    }

    return TRUE;
} /* end of m_cb_hdr_compl */


static BOOL m_cb_data_block( void                   *avp_usrfld,
                             struct dsd_http_header *adsp_hdr,
                             struct dsd_gather_i_1  *adsp_data  )
{
    /*
        TODO:
        this function will be needed if we should support some
        POST requests ... don't know yet
    */

    return TRUE;
} /* end of m_cb_data_block */


                          
/**
 * private function m_cb_ws_handshake
 *    handle websocket handshake
 *
 * @param[in]   void            *avp_usrfld     connection handle
 * @param[in]   dsd_http_header *adsp_hdr       http header
 * @param[in]   dsd_gather_i_1  *adsp_data      data itself
 * @return      BOOL
*/
static BOOL m_cb_ws_handshake( void                   *avp_usrfld,
                               struct dsd_http_header *adsp_hdr,
                               struct dsd_gather_i_1  *adsp_data  )
{
    BOOL                     bol_ret;           /* return for some funcs */
    struct dsd_html5_conn    *adsl_conn;        /* current connection    */
    enum ied_ws_version      iedl_version;
    struct dsd_gather_i_1    *adsl_gather;
    int                      inl_length;
  
    // todo: check version of the websocket and implement different handshake callbacks
    iedl_version = m_get_ws_version( adsp_hdr );
    adsl_conn    = (struct dsd_html5_conn*)avp_usrfld;

    switch( iedl_version )
    {
        case ied_ws_draft_13:
            /*
             since websocket draft 08
             - the bytes in the body are gone, md5 is gone
             -> now we have to create a SHA1 checksum and send it back to the browser
            */
            bol_ret = m_ws_handshake_08( adsl_conn, adsp_hdr, adsp_data );
            if ( bol_ret == FALSE ) {
                return FALSE;
            }
            break;
        default:
            /* todo: send "not supported" */
			/* create header  */
			m_create_response( adsl_conn->avc_http_creator, ied_vs_http_1_1, ied_st_http_method_not_allowed );
			m_finish_header( adsl_conn->avc_http_creator );
            return FALSE;
            break;
    }

    /* mark connection as websocket connection */
    adsl_conn->dsc_ws.iec_websocket = iedl_version;
    adsl_conn->dsc_http_parser_cbs.amc_data_block = &m_cb_ws_d17_data;
    return TRUE;
} /* end of m_cb_ws_handshake */


/**
 * private function m_cb_ws_data17
 *    handle websocket data for draft 17
 *
 * @param[in]   void            *avp_usrfld     connection handle
 * @param[in]   dsd_http_header *adsp_hdr       http header
 * @param[in]   dsd_gather_i_1  *adsp_data      data itself
 * @return      BOOL
*/
static BOOL m_cb_ws_d17_data( void                   *avp_usrfld,
                              struct dsd_http_header *adsp_hdr,
                              struct dsd_gather_i_1  *adsp_data  )
{
    struct dsd_html5_conn *adsl_conn;           /* current connection    */
    
    adsl_conn = (struct dsd_html5_conn*)avp_usrfld;

    /* normalize input data */
    while (    adsp_data                != NULL
            && adsp_data->achc_ginp_cur >= adsp_data->achc_ginp_end ) {
        adsp_data = adsp_data->adsc_next;
    }

    adsl_conn->dsc_http_parser_cbs.amc_data_block = &m_parse_ws_d17_frame;
    if ( adsp_data != NULL )
    {
		return( m_parse_ws_d17_frame( avp_usrfld, adsp_hdr, adsp_data ) );
    }
    // send response
	return TRUE; // wait for more data
}

/**
 * private function m_cb_out
 *  callback function for http creator
 *
 * @param[in]   void            *avp_usrfld     connection handle
 * @param[in]   const char      *achp_data      output data
 * @param[in]   size_t          uinp_len        length of data
 * @return      BOOL
*/ 
static BOOL m_cb_out( void *avp_usrfld, const char *achp_data, size_t uinp_len )
{
    size_t uinl_ret = m_to_output( (struct dsd_html5_conn*)avp_usrfld,
                                   achp_data, uinp_len );

    return (uinl_ret == uinp_len);
} /* end of m_cb_out */




/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/

/**
 * extern BOOL m_html5_start
 * setup a new connection structure and save it in ac_ext pointer
 *
 * @param[in]   dsd_call_awcs_html5 *adsp_awcs_html5
 * @return      nothing
*/
extern BOOL m_html5_start( struct dsd_call_awcs_html5 *adsp_awcs_html5 )
{
    BOOL                  bol_ret;              /* return from aux calls */
    struct dsd_html5_conn *adsl_conn;           /* our connection memory */

    /*
        new connection means:
        -> allocate connection memory
        -> setup connection structure
        -> create http parser and creator
        -> set first working function
    */
    bol_ret = M_ALLOC( adsp_awcs_html5, &adsp_awcs_html5->avc_ext,
                       (int)sizeof(struct dsd_html5_conn)          );
    if (    bol_ret                  == FALSE
         || adsp_awcs_html5->avc_ext == NULL  ) {
        return FALSE;
    }
    adsl_conn = (struct dsd_html5_conn*)adsp_awcs_html5->avc_ext;
    memset( adsl_conn, 0, sizeof(struct dsd_html5_conn) );
    adsl_conn->adsc_awcs_html5 = adsp_awcs_html5;

	/* setup http parser */
    adsl_conn->dsc_http_parser_cbs.avc_usrfld       = (void*)adsl_conn;
    adsl_conn->dsc_http_parser_cbs.amc_alloc        = &m_cb_alloc;
    adsl_conn->dsc_http_parser_cbs.amc_free         = &m_cb_free;
    adsl_conn->dsc_http_parser_cbs.amc_header_compl = &m_cb_hdr_compl;
    adsl_conn->dsc_http_parser_cbs.amc_data_block   = &m_cb_data_block;
    adsl_conn->dsc_http_parser_cbs.amc_ws_handshake = &m_cb_ws_handshake;

    adsl_conn->avc_http_parser = m_new_http_parser( &adsl_conn->dsc_http_parser_cbs,
                                                    1024, 25, 256 );
    if ( adsl_conn->avc_http_parser == NULL ) {
        M_FREE( adsp_awcs_html5, adsl_conn );
        return FALSE;
    }

    /* setup http creator */
    adsl_conn->dsc_http_creator_cbs.avc_usrfld = (void*)adsl_conn;
    adsl_conn->dsc_http_creator_cbs.amc_alloc  = &m_cb_alloc;
    adsl_conn->dsc_http_creator_cbs.amc_free   = &m_cb_free;
    adsl_conn->dsc_http_creator_cbs.amc_out    = &m_cb_out;

    adsl_conn->avc_http_creator = m_new_http_creator( &adsl_conn->dsc_http_creator_cbs,
                                                      256 );
    if ( adsl_conn->avc_http_creator == NULL ) {
        m_del_http_parser( &adsl_conn->avc_http_parser );
        M_FREE( adsp_awcs_html5, adsl_conn );
        return FALSE;
    }

    /* init canvas drawing context */
    adsl_conn->dsc_ctx.adsc_conn = adsl_conn;
    return TRUE;
} /* end of extern BOOL m_html5_start */

/**
 * extern BOOL m_html5_end
 * delete connection structure and reset in ac_ext pointer
 *
 * @param[in]   dsd_call_awcs_html5 *adsp_awcs_html5
 * @return      nothing
*/
extern BOOL m_html5_end( struct dsd_call_awcs_html5 *adsp_awcs_html5 )
{
    BOOL                  bol_ret = FALSE;      /* return from aux calls */
    struct dsd_html5_conn *adsl_conn;           /* our connection memory */

    adsl_conn = (struct dsd_html5_conn*)adsp_awcs_html5->avc_ext;
    if ( adsl_conn == NULL ) {
        return FALSE;
    }
    adsl_conn->adsc_awcs_html5 = adsp_awcs_html5;

    m_del_http_parser ( &adsl_conn->avc_http_parser  );
    m_del_http_creator( &adsl_conn->avc_http_creator );
    bol_ret = M_FREE( adsp_awcs_html5, adsl_conn );
    adsp_awcs_html5->avc_ext = NULL;
	
	return bol_ret;
} /* end of extern BOOL m_html5_end */


extern BOOL m_html5_get_event( struct dsd_call_awcs_html5 *adsp_awcs_html5, struct dsd_browser_event **aadsp_browser_event )
{
	BOOL                  bol_ret = FALSE;      /* return from aux calls */
    struct dsd_html5_conn *adsl_conn;           /* our connection memory */

	adsl_conn = (struct dsd_html5_conn*)adsp_awcs_html5->avc_ext;
    if ( adsp_awcs_html5->adsc_gather_i_1_in ) {
        adsl_conn->adsc_awcs_html5 = adsp_awcs_html5;
        bol_ret = m_parse_http( adsl_conn->avc_http_parser,
                                adsp_awcs_html5->adsc_gather_i_1_in );
    }

	*aadsp_browser_event = &adsl_conn->dsc_browser_event;

	return bol_ret;
}

#if 0
extern BOOL m_html5_send_drawing( struct dsd_call_awcs_html5 *adsp_awcs_html5, struct dsd_html5_answer *adsp_html5_answer )
{
	BOOL                  bol_ret;              /* return from aux calls */
    struct dsd_html5_conn *adsl_conn;           /* our connection memory */
	
	adsl_conn = (struct dsd_html5_conn*)adsp_awcs_html5->avc_ext;
	adsl_conn->adsc_awcs_html5 = adsp_awcs_html5;
	m_process_rdp_commands( adsl_conn, adsp_html5_answer );
	return TRUE;
}
#endif

extern BOOL m_html5_send_drawing( struct dsd_call_awcs_html5 *adsp_awcs_html5, struct dsd_rdp_event *adsp_rdp_event )
{
	BOOL                  bol_ret;              /* return from aux calls */
 
	switch( adsp_rdp_event->iec_type )
	{
		case ied_rdp_rectangle:
			m_handle_rectangle( adsp_awcs_html5, adsp_rdp_event );
			break;
		default:
			break;
	}
		
	return TRUE;
}

static BOOL m_handle_rectangle( struct dsd_call_awcs_html5 *adsp_awcs_html5, struct dsd_rdp_event *adsp_rdp_event )
{
	int								iml_remaining;
	struct dsd_gather_i_1			*adsl_gather;
	struct dsd_gather_i_1			*adsl_next_gather;
	struct dsd_html5_header			dsl_header;
	int								iml_data_len;
	char							*achl_wa;
	int								iml_len_wa;
	int								imc_width;
	int								y;
	int								iml_offset;
	BOOL							bol_ret;
	struct dsd_html5_conn			*adsl_conn;    /* our connection memory */
	char							*achl_last_used_adr;							

	adsl_conn = (struct dsd_html5_conn*)adsp_awcs_html5->avc_ext;

	memset(&dsl_header, 0, sizeof(dsd_html5_header));

	/* get pointers to workarea in local variables, dont modify original pointers */
	if(adsl_conn->dsc_cur_workarea.achc_work_area == NULL)
	{
		/* TODO! Check when u have to set this to zero again! */
		achl_wa = adsp_awcs_html5->achc_work_area;
		iml_len_wa = adsp_awcs_html5->inc_len_work_area;
	}
	else
	{
		achl_wa = adsl_conn->dsc_cur_workarea.achc_work_area;
		iml_len_wa = adsl_conn->dsc_cur_workarea.imc_len_work_area;
	}

	if(adsp_awcs_html5->adsc_gather_i_1_out != NULL)
	{
		adsl_gather = adsp_awcs_html5->adsc_gather_i_1_out;
		while( adsl_gather->adsc_next != NULL ){ adsl_gather = adsl_gather->adsc_next; }
		achl_last_used_adr = adsl_gather + 1;
		iml_remaining = (achl_wa + iml_len_wa) - achl_last_used_adr;
		
		if( iml_remaining < ( ((int)sizeof(struct dsd_gather_i_1)) + HTML5_HEADER_LEN + 8 ) )
		{
			bol_ret = m_get_new_workarea( adsp_awcs_html5, &adsl_conn->dsc_cur_workarea, &adsl_gather );
			achl_wa = adsl_conn->dsc_cur_workarea.achc_work_area;
			iml_len_wa = adsl_conn->dsc_cur_workarea.imc_len_work_area;
			achl_last_used_adr = adsl_gather + 1;
		}
		else
		{
			adsl_gather->adsc_next = adsl_gather + 1;
			adsl_gather = adsl_gather->adsc_next;
			adsl_gather->adsc_next = NULL;
			adsl_gather->achc_ginp_cur = adsl_gather + 1;
			adsl_gather->achc_ginp_end = adsl_gather->achc_ginp_cur;
			achl_last_used_adr = adsl_gather->achc_ginp_end;
		}
	}
	else
	{
		adsl_gather = ( struct dsd_gather_i_1 * )achl_wa;
		adsp_awcs_html5->adsc_gather_i_1_out = adsl_gather;
		adsl_gather->achc_ginp_cur = (char*)(adsl_gather + 1);
		adsl_gather->achc_ginp_end = adsl_gather->achc_ginp_cur;
		adsl_gather->adsc_next = NULL;
		achl_last_used_adr = adsl_gather->achc_ginp_end;
	}

	/*************************************/
	/* Create the HTML5 WebSocket Header */
	/*************************************/

	/* data_len = (width pixel * height pixel) * 2 (16 bit colordepth) + topleft x (2 Byte) + topleft y (2 Byte) + width (2 Byte) + height (2 Byte) */
	iml_data_len = adsp_rdp_event->dsc_rectangle.imc_width * adsp_rdp_event->dsc_rectangle.imc_height * 2 + 8;
	
	m_create_frame_header( &dsl_header, iml_data_len, 0x02 );
	
	//if( ( dsl_header.inc_len + 8 ) > iml_remaining )
	//{
	//	bol_ret = m_get_new_workarea( adsp_awcs_html5, &adsl_conn->dsc_cur_workarea, &adsl_gather );
	//	achl_wa = adsl_conn->dsc_cur_workarea.achc_work_area;
	//	iml_len_wa = adsl_conn->dsc_cur_workarea.imc_len_work_area;
	//	achl_last_used_adr = adsl_gather + 1;
	//}

	memcpy( adsl_gather->achc_ginp_end, &dsl_header.chrc_header, dsl_header.inc_len );
	adsl_gather->achc_ginp_end	+= dsl_header.inc_len;

	memcpy( adsl_gather->achc_ginp_end, (short*)&adsp_rdp_event->dsc_rectangle.imc_left_x, 2 );
	adsl_gather->achc_ginp_end	+= 2;

	memcpy( adsl_gather->achc_ginp_end, (short*)&adsp_rdp_event->dsc_rectangle.imc_top_y, 2 );
	adsl_gather->achc_ginp_end	+= 2;

	memcpy( adsl_gather->achc_ginp_end, (short*)&adsp_rdp_event->dsc_rectangle.imc_width, 2 );
	adsl_gather->achc_ginp_end	+= 2;

	memcpy( adsl_gather->achc_ginp_end, (short*)&adsp_rdp_event->dsc_rectangle.imc_height, 2 );
	adsl_gather->achc_ginp_end	+= 2;

	achl_last_used_adr = adsl_gather->achc_ginp_end;

	/*************************************************/
	/* Create the gather structs for the screen data */
	/*************************************************/
	
	imc_width = adsp_rdp_event->dsc_rectangle.imc_width * 2;

	for( y = adsp_rdp_event->dsc_rectangle.imc_top_y; y < adsp_rdp_event->dsc_rectangle.imc_bottom_y; y++ )
	{
		iml_remaining = (achl_wa + iml_len_wa) - achl_last_used_adr;

		if( iml_remaining < (int)sizeof(struct dsd_gather_i_1) )
		{
			bol_ret = m_get_new_workarea( adsp_awcs_html5, &adsl_conn->dsc_cur_workarea, &adsl_gather );
			achl_wa = adsl_conn->dsc_cur_workarea.achc_work_area;
			iml_len_wa = adsl_conn->dsc_cur_workarea.imc_len_work_area;
		}
		else
		{
			adsl_next_gather = (struct dsd_gather_i_1*) ALIGN_INT( (int)achl_last_used_adr );
			adsl_gather->adsc_next = adsl_next_gather;
			adsl_gather = adsl_next_gather;
			adsl_gather->adsc_next = NULL;	
		}
		iml_offset = ( y * adsp_rdp_event->dsc_rectangle.imc_resolution_x + adsp_rdp_event->dsc_rectangle.imc_left_x ) * 2;
		adsl_gather->achc_ginp_cur = (char*)adsp_rdp_event->dsc_rectangle.avc_screenbuffer + iml_offset;
		adsl_gather->achc_ginp_end = (char*)adsp_rdp_event->dsc_rectangle.avc_screenbuffer + iml_offset + imc_width ;
		achl_last_used_adr = (char*)(adsl_gather + 1);
	}
	
	return TRUE;
}

static BOOL m_get_new_workarea( struct dsd_call_awcs_html5 *adsp_awcs_html5, struct dsd_aux_get_workarea *adsp_wa, struct dsd_gather_i_1 **adsp_gather )
{
	BOOL	bol_ret;
	struct dsd_html5_conn			*adsl_conn;    /* our connection memory */

	adsl_conn = (struct dsd_html5_conn*)adsp_awcs_html5->avc_ext;

	bol_ret = M_GET_WORKAREA( adsp_awcs_html5, adsp_wa );
    if ( bol_ret == FALSE ){ return FALSE; }
    (*adsp_gather)->adsc_next = (struct dsd_gather_i_1*) adsp_wa->achc_work_area;
    *adsp_gather = (*adsp_gather)->adsc_next;
    
    (*adsp_gather)->adsc_next     = NULL;
    (*adsp_gather)->achc_ginp_cur = adsp_wa->achc_work_area + sizeof(struct dsd_gather_i_1);
    (*adsp_gather)->achc_ginp_end = (*adsp_gather)->achc_ginp_cur;

	return TRUE;
}