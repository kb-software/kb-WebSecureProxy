/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| --------                                                            |*/
/*|   xs-awcs-dummy.c                                                   |*/
/*|                                                                     |*/
/*| Description:                                                        |*/
/*| ------------                                                        |*/
/*|   dummy implementation for testing of our server client             |*/
/*|   communication. This will send some special draw event to the      |*/
/*|   client for special browser events                                 |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| -------                                                             |*/
/*|   Michael Jakobs, June 2011                                         |*/
/*|   Tobias Hofmann, Oct 2011                                          |*/
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

/*+---------------------------------------------------------------------+*/
/*| local includes:                                                     |*/
/*+---------------------------------------------------------------------+*/
#ifndef _HOB_XSCLIB01_H
    #define _HOB_XSCLIB01_H
    #include <hob-xsclib01.h>
#endif //_HOB_XSCLIB01_H

#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H

#include <hob-xs-html5.h>
#include "hob-http-processor.h"
#include "hob-xs-html5-priv.h"

/*+---------------------------------------------------------------------+*/
/*| constants:                                                          |*/
/*+---------------------------------------------------------------------+*/
#define PI 3.14159265
    
/*+---------------------------------------------------------------------+*/
/*| macros:                                                             |*/
/*+---------------------------------------------------------------------+*/
#define M_CALL_AUX(sp,mode,x,y) sp->amc_aux(sp->avc_userfield, mode, x, y )
#define M_READ_FILE(sp,ptr) M_CALL_AUX(sp,DEF_AUX_DISKFILE_ACCESS,ptr,sizeof(*ptr))
#define M_RELEASE_FILE(sp,ptr) M_CALL_AUX(sp,DEF_AUX_DISKFILE_RELEASE,ptr,sizeof(*ptr))

/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/
/**
 * private function m_draw_picture
*/
static void m_draw_picture( struct dsd_html5_answer *adsp_answer, struct dsd_canvas_ctx *adsp_ctx )
{
    BOOL                         bol_ret;       /* return                */
    struct dsd_hl_aux_diskfile_1 dsl_file;      /* file access structure */

    dsl_file.ac_name      = (void*)"../../../../resource/www/png-test.txt";
    dsl_file.inc_len_name = strlen("../../../../resource/www/png-test.txt");
    dsl_file.iec_chs_name = ied_chs_utf_8;
    bol_ret = M_READ_FILE( adsp_ctx->adsc_conn->adsc_awcs_html5, &dsl_file );
    if (    bol_ret               == FALSE
         || dsl_file.iec_dfar_def != ied_dfar_ok ) {
        return;
    }

    m_c2d_draw_image1( adsp_answer, dsl_file.adsc_int_df1->achc_filecont_start,
                       (size_t)(  dsl_file.adsc_int_df1->achc_filecont_end
                                - dsl_file.adsc_int_df1->achc_filecont_start ),
                       50, 20 );
        
    M_RELEASE_FILE( adsp_ctx->adsc_conn->adsc_awcs_html5, &dsl_file );
} /* end of m_draw_picture */


/**
 * private function m_repeat_picture
*/
static void m_repeat_picture( struct dsd_html5_answer *adsp_answer, struct dsd_canvas_ctx *adsp_ctx )
{
    BOOL                         bol_ret;       /* return                */
    struct dsd_hl_aux_diskfile_1 dsl_file;      /* file access structure */

    dsl_file.ac_name      = (void*)"../../../../resource/www/png-test.txt";
    dsl_file.inc_len_name = strlen("../../../../resource/www/png-test.txt");
    dsl_file.iec_chs_name = ied_chs_utf_8;
    bol_ret = M_READ_FILE( adsp_ctx->adsc_conn->adsc_awcs_html5, &dsl_file );
    if (    bol_ret               == FALSE
         || dsl_file.iec_dfar_def != ied_dfar_ok ) {
        return;
    }

    //m_start_drawing( adsp_ctx );
    m_c2d_save( adsp_answer );
    m_c2d_create_pattern( adsp_answer, "var pattern",
                          dsl_file.adsc_int_df1->achc_filecont_start,
                          (size_t)(  dsl_file.adsc_int_df1->achc_filecont_end
                                   - dsl_file.adsc_int_df1->achc_filecont_start) ,
                          "repeat" );
    m_c2d_fill_style( adsp_answer, "pattern" );
    m_c2d_fill_rect( adsp_answer, 0, 0, adsp_ctx->uinc_width, adsp_ctx->uinc_height );
    m_c2d_restore( adsp_answer );
    //m_finish_drawing( adsp_ctx );

    M_RELEASE_FILE( adsp_ctx->adsc_conn->adsc_awcs_html5, &dsl_file );
} /* end of m_repeat_picture */

/**
 * private function m_test_cache_picture
*/
static void m_test_cache_picture( struct dsd_html5_answer *adsp_answer, struct dsd_canvas_ctx *adsp_ctx )
{
    BOOL                         bol_ret;       /* return                */
    struct dsd_hl_aux_diskfile_1 dsl_file;      /* file access structure */

    dsl_file.ac_name      = (void*)"../../../../resource/www/png-test2.txt";
    dsl_file.inc_len_name = strlen("../../../../resource/www/png-test2.txt");
    dsl_file.iec_chs_name = ied_chs_utf_8;
    bol_ret = M_READ_FILE( adsp_ctx->adsc_conn->adsc_awcs_html5, &dsl_file );
    if (    bol_ret               == FALSE
         || dsl_file.iec_dfar_def != ied_dfar_ok ) {
        return;
    }

    m_start_drawing( adsp_answer );
    m_c2d_cache_image( adsp_answer, "img1",
                                 dsl_file.adsc_int_df1->achc_filecont_start,
                          (size_t)(  dsl_file.adsc_int_df1->achc_filecont_end
                                   - dsl_file.adsc_int_df1->achc_filecont_start) );
    m_finish_drawing( adsp_answer );

    M_RELEASE_FILE( adsp_ctx->adsc_conn->adsc_awcs_html5, &dsl_file );
} /* end of m_test_cache_picture */


static void m_handle_char( struct dsd_html5_answer  *adsp_answer,
                           struct dsd_canvas_ctx    *adsp_ctx,
                           struct dsd_browser_event *adsp_evt );

static void m_key_echo( struct dsd_html5_answer  *adsp_answer,
                        struct dsd_canvas_ctx *adsp_ctx,
                        struct dsd_browser_event *adsp_evt )
{
    char rchl_temp[8];
    unsigned int uinrl_middle[2];
    uinrl_middle[0] = adsp_ctx->uinc_width/2;
    uinrl_middle[1] = adsp_ctx->uinc_height/2;

    
    m_start_drawing( adsp_answer );
    m_c2d_save( adsp_answer );
    
    m_c2d_save( adsp_answer );
    m_c2d_create_linear_gradient( adsp_answer, "var grad", 0, 0, 0, (float)adsp_ctx->uinc_height );
    m_c2d_add_color_stop( adsp_answer, "grad", 0, "'#ff0'" );
    m_c2d_add_color_stop( adsp_answer, "grad", 1, "'#fff'" );
    m_c2d_fill_style( adsp_answer, "grad" );
    m_c2d_fill_rect( adsp_answer, 0, 0, adsp_ctx->uinc_width, adsp_ctx->uinc_height );
    m_c2d_restore( adsp_answer );

    m_c2d_text_align( adsp_answer, "center" );
    m_c2d_font( adsp_answer, "20pt monospace" );

    switch( adsp_evt->iec_type ) {
        case ied_be_charkey_pressed:
            memset( rchl_temp, 0, sizeof(rchl_temp) );
            m_cpy_vx_vx( rchl_temp, sizeof(rchl_temp), ied_chs_utf_8,
                         adsp_evt->rchc_key, 1, ied_chs_utf_32 );

            m_c2d_fill_text( adsp_answer, rchl_temp, uinrl_middle[0], uinrl_middle[1] );

            
            if ( adsp_evt->rchc_key[0] == 'e' ) {
                adsp_ctx->amc_keyhandler = &m_handle_char;
            }
            break;

        case ied_be_funckey_press:
            m_c2d_fill_text( adsp_answer, achg_function_keys[adsp_evt->uchc_function],
                             uinrl_middle[0], uinrl_middle[1] );
            break;

        default:
            break;
    }

    m_c2d_restore( adsp_answer );
    m_finish_drawing( adsp_answer );
} /* end of m_key_echo */


/**
 * private function m_handle_char
 *  handle incoming character event
 *
 * @param[in]   dsd_canvas_ctx      *adsp_ctx   canvas drawing context
 * @param[in]   dsd_browser_event   *adsp_evt   current event
 * @return      nothing
*/
static void m_handle_char( struct dsd_html5_answer  *adsp_answer,
                           struct dsd_canvas_ctx    *adsp_ctx,
                           struct dsd_browser_event *adsp_evt )
{
    unsigned int uinrl_middle[2] = { adsp_ctx->uinc_width/2, adsp_ctx->uinc_height/2 };
    unsigned int uinl_count;
    float        fll_angle;
    float        fll_add;
    unsigned int uinl_cur_x;
    unsigned int uinl_cur_y;
    unsigned int uinl_add_x;
    unsigned int uinl_add_y;
    int          inrl_color[3];

    switch ( adsp_evt->rchc_key[0] ) {
        case 'a':
            m_start_drawing( adsp_answer );
            m_c2d_stroke_rect( adsp_answer, 10, 40, 100, 50 );
            m_finish_drawing( adsp_answer );
            break;
        case 'p':
            m_start_drawing( adsp_answer );
            m_draw_picture( adsp_answer, adsp_ctx );
            m_finish_drawing( adsp_answer );
            break;
        case 'r':
            m_start_drawing( adsp_answer );
            m_repeat_picture( adsp_answer, adsp_ctx );
            m_finish_drawing( adsp_answer );
            break;
        case 'l':
            fll_angle = 0;
            fll_add   = (float)(2*PI/360);
            m_start_drawing( adsp_answer );
            m_c2d_begin_path( adsp_answer );
            for ( uinl_count = 1; uinl_count <= 360; uinl_count++ ) {
                m_c2d_arc( adsp_answer, uinrl_middle[0], uinrl_middle[1], 300,
                           fll_angle, fll_angle+fll_add, TRUE );
                m_c2d_line_to( adsp_answer, uinrl_middle[0], uinrl_middle[1] );
                fll_angle += fll_add;
            }
            m_c2d_stroke( adsp_answer );
            m_finish_drawing( adsp_answer );
            break;
        case 'c':
            m_start_drawing( adsp_answer );
            m_c2d_clear_rect( adsp_answer, 0, 0, adsp_ctx->uinc_width, adsp_ctx->uinc_height );
            m_finish_drawing( adsp_answer );
            break;
        case 'h':
            m_start_drawing( adsp_answer );
            m_c2d_save( adsp_answer );
            m_c2d_create_linear_gradient( adsp_answer, "var grad", 0, 0, 0, (float)adsp_ctx->uinc_height );
            m_c2d_add_color_stop( adsp_answer, "grad", 0, "'#ff0'" );
            m_c2d_add_color_stop( adsp_answer, "grad", 1, "'#fff'" );
            m_c2d_fill_style( adsp_answer, "grad" );
            m_c2d_fill_rect( adsp_answer, 0, 0, adsp_ctx->uinc_width, adsp_ctx->uinc_height );
            m_c2d_restore( adsp_answer );

            m_c2d_save( adsp_answer );
            m_c2d_font( adsp_answer, "15pt sans-serif" );
            m_c2d_fill_text( adsp_answer, "AWCS HTML5 Testserver 0.1", 10, 30 );
            m_c2d_font( adsp_answer, "12pt monospace" );
            m_c2d_fill_text( adsp_answer, "c: clear screen",    10,  60 );
            m_c2d_fill_text( adsp_answer, "h: show this help",  10,  80 );
            m_c2d_fill_text( adsp_answer, "p: draw picture",    10, 100 );
            m_c2d_fill_text( adsp_answer, "r: repeat picture",  10, 120 );
            m_c2d_fill_text( adsp_answer, "l: draw lines",      10, 140 );
            m_c2d_fill_text( adsp_answer, "o: start HOB Logo",  10, 160 );
            m_c2d_fill_text( adsp_answer, "O: stop HOB Logo",   10, 180 );
            m_c2d_fill_text( adsp_answer, "q: quadratic curve", 10, 200 );
            m_c2d_fill_text( adsp_answer, "t: translate",       10, 220 );
            m_c2d_fill_text( adsp_answer, "f: color gradient",  10, 240 );
            m_c2d_fill_text( adsp_answer, "e: enable/disable key echo mode", 10, 260 );
            m_c2d_fill_text( adsp_answer, "1: cache function test", 10, 280 );
            m_c2d_fill_text( adsp_answer, "2: cache image", 10, 300 );
            m_c2d_fill_text( adsp_answer, "3: draw cached image", 10, 320 );
            m_c2d_fill_text( adsp_answer, "y: copy",              10, 340 );
            m_c2d_restore( adsp_answer );
            m_finish_drawing( adsp_answer );
            break;
        case 'y':
            m_start_drawing( adsp_answer );
            m_c2d_copy( adsp_answer, 0, 0, adsp_ctx->uinc_width/2, adsp_ctx->uinc_height/2,
                                        adsp_ctx->uinc_width/2, adsp_ctx->uinc_height/2 );
            m_finish_drawing( adsp_answer );
            break;
        case 'o':
            m_start_drawing( adsp_answer );
            m_c2d_clear_rect( adsp_answer, 0, 0, adsp_ctx->uinc_width, adsp_ctx->uinc_height );
            m_c2d_sprintf( adsp_answer, "cvs.startLogo();" );
            m_finish_drawing( adsp_answer );
            break;
        case 'O':
            m_start_drawing( adsp_answer );
            m_c2d_sprintf( adsp_answer, "cvs.removeLogo();" );
            m_finish_drawing( adsp_answer );
            break;
        case 'q':
            m_start_drawing( adsp_answer );
            m_c2d_save( adsp_answer );

            m_c2d_begin_path( adsp_answer );
            m_c2d_move_to( adsp_answer, 50, 150 );
            m_c2d_quadratic_curve_to( adsp_answer,  75, 200, 100, 150 );
            m_c2d_quadratic_curve_to( adsp_answer, 200, 125, 100, 100 );
            m_c2d_quadratic_curve_to( adsp_answer,  75,  50,  50, 100 );
            m_c2d_quadratic_curve_to( adsp_answer,   0, 125,  50, 150 );
            m_c2d_close_path( adsp_answer );
            m_c2d_fill_style( adsp_answer, "'#a00'" );
            m_c2d_fill( adsp_answer );
            m_c2d_stroke( adsp_answer );

            m_c2d_begin_path( adsp_answer );
            m_c2d_scale( adsp_answer, 0.5, 0.5 );
            m_c2d_move_to( adsp_answer, 50, 150 );
            m_c2d_quadratic_curve_to( adsp_answer,  75, 200, 100, 150 );
            m_c2d_quadratic_curve_to( adsp_answer, 200, 125, 100, 100 );
            m_c2d_quadratic_curve_to( adsp_answer,  75,  50,  50, 100 );
            m_c2d_quadratic_curve_to( adsp_answer,   0, 125,  50, 150 );
            m_c2d_close_path( adsp_answer );
            m_c2d_stroke_style( adsp_answer, "'#fff'" );
            m_c2d_fill_style( adsp_answer, "'#b55'" );
            m_c2d_fill( adsp_answer );
            m_c2d_stroke( adsp_answer );

            m_c2d_restore( adsp_answer );
            m_finish_drawing( adsp_answer );
            break;
        case 't':
            m_start_drawing( adsp_answer );
            m_c2d_save( adsp_answer );

            m_c2d_sprintf( adsp_answer, "var intRed=255;" );
            m_c2d_sprintf( adsp_answer, "var intRedInv=55;" );
            m_c2d_sprintf( adsp_answer, "for(var i=0; i<10; i++){" );
            m_c2d_translate( adsp_answer, -10, -10 );
            m_c2d_fill_style( adsp_answer, "'rgba('+(intRed - i*20)+', 0, 0, 0.5)'" );
            m_c2d_stroke_style( adsp_answer, "'rgb('+(intRedInv + i*20)+', 0, 0)'" );
            m_c2d_fill_rect( adsp_answer, 200, 200, 80, 80 );
            m_c2d_stroke_rect( adsp_answer, 200, 200, 80, 80 );
            m_c2d_sprintf( adsp_answer, "}" );

            m_c2d_restore( adsp_answer );
            m_finish_drawing( adsp_answer );
            break;
        case 'f':
            m_start_drawing( adsp_answer );
            m_c2d_save( adsp_answer );

            uinl_add_x = adsp_ctx->uinc_width/8;
            uinl_add_y = adsp_ctx->uinc_height/8;
            inrl_color[0] = 220;
            inrl_color[1] = 220;
            inrl_color[2] = 220;
            
            for ( uinl_cur_y = 0; uinl_cur_y < adsp_ctx->uinc_height; uinl_cur_y += uinl_add_y ) {
                for ( uinl_cur_x = 0; uinl_cur_x < adsp_ctx->uinc_width; uinl_cur_x += uinl_add_x ) {
                    m_c2d_sprintf( adsp_answer, "ctx.fillStyle='rgb(%d,%d,%d)';",
                                   inrl_color[0], inrl_color[1], inrl_color[2] );
                    if ( inrl_color[0] > 80 ) {
                        inrl_color[0] -= 20;
                    } else if ( inrl_color[1] > 80 ) {
                        inrl_color[0] = 220;
                        inrl_color[1] -= 20;
                    } else if ( inrl_color[2] > 80 ) {
                        inrl_color[1] = 220;
                        inrl_color[2] -= 20;
                    }
                    m_c2d_fill_rect( adsp_answer, uinl_cur_x, uinl_cur_y, 
                                     uinl_cur_x + uinl_add_x, uinl_cur_y + uinl_add_y );
                }
            }

            m_c2d_restore( adsp_answer );
            m_finish_drawing( adsp_answer );
            break;
        case 'e':
            // TODO! change keyhandler arguments
            adsp_ctx->amc_keyhandler = &m_key_echo;
            break;
        case '1':
            m_start_drawing( adsp_answer );
            m_c2d_cache_func( adsp_answer, "alert", "function(text){alert(text);}" );
            m_c2d_sprintf( adsp_answer, "cvs.alert('Function alert cached succesful!');" );
            m_finish_drawing( adsp_answer );
            break;
        case '2':
            m_test_cache_picture( adsp_answer, adsp_ctx );
            break;
        case '3':
            m_start_drawing( adsp_answer );
            m_c2d_draw_cached_image1( adsp_answer, "img1", 100, 100 );
            m_finish_drawing( adsp_answer );
            break;
    }
} /* end of m_handle_char */


/**
 * private function m_handle_control
 *  handle incoming control packet
 *
 * @param[in]   dsd_canvas_ctx      *adsp_ctx   canvas drawing context
 * @param[in]   dsd_browser_event   *adsp_evt   current event
 * @return      nothing
*/
static void m_handle_control( struct dsd_html5_answer  *adsp_answer,
                              struct dsd_canvas_ctx    *adsp_ctx,
                              struct dsd_browser_event *adsp_evt )
{
    /* save incoming width and heigth */
    adsp_ctx->uinc_width  = adsp_evt->uinc_width;
    adsp_ctx->uinc_height = adsp_evt->uinc_height;
    adsp_ctx->ienc_type   = adsp_evt->ienc_ctx_type;
    adsp_ctx->amc_keyhandler = &m_handle_char;

    /* remove startup HOB logo */
    m_start_drawing( adsp_answer );
    m_c2d_sprintf( adsp_answer, "cvs.removeLogo();" );
	m_c2d_cache_func( adsp_answer, "sq", "function(x,y,w,h,d){var a=ctx.createImageData(w+1,h);var b=a.data;for(var i=0;i<b.length;i++){b[i]=d[i]};ctx.putImageData(a,x,y);}" );
	m_finish_drawing( adsp_answer );
} /* end of m_handle_control */


/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
 * public function m_handle_event
 *   handle incoming browser event
 *
 * @param[in]   dsd_html5_answer	*adsp_answer	buffer for answer
 * @param[in]   dsd_html5_conn		*adsp_conn		connection memory
 * @param[in]   dsd_browser_event   *adsp_evt		current event
 * @param[out]  dsd_parsed_event    *adsp_parsed_event
 * @return      nothing
*/
extern void m_handle_event( struct dsd_html5_answer  *adsp_answer,
						    struct dsd_html5_conn    *adsp_conn,
                            struct dsd_browser_event *adsp_evt,
							struct dsd_parsed_event  *adsp_parsed_event )
{
    switch( adsp_evt->iec_type ) {
        case ied_be_control:
			m_handle_control( adsp_answer, &(adsp_conn->dsc_ctx), adsp_evt );
            break;
		case ied_be_connect:
			adsp_parsed_event->dsc_start_rdp_conn.bos_start = TRUE;
			//adsp_parsed_event->dsc_start_rdp_conn.chrc_rdp_srv = adsp_evt->dsc_rdp_srv_infos.chrc_rdp_srv;
			memcpy( adsp_parsed_event->dsc_start_rdp_conn.chrc_rdp_srv, adsp_evt->dsc_rdp_srv_infos.chrc_rdp_srv, strlen( adsp_evt->dsc_rdp_srv_infos.chrc_rdp_srv) );
			adsp_parsed_event->dsc_start_rdp_conn.inc_port = 3389;
			//adsp_parsed_event->dsc_start_rdp_conn.inc_port = adsp_evt->dsc_rdp_srv_infos.inc_port;
			adsp_parsed_event->dsc_start_rdp_conn.inc_srv_len = adsp_evt->dsc_rdp_srv_infos.inc_srv_len;
			break;
        case ied_be_charkey_pressed:
            adsp_conn->dsc_ctx.amc_keyhandler( adsp_answer, &(adsp_conn->dsc_ctx), adsp_evt );
            break;
        case ied_be_funckey_press:
            m_key_echo( adsp_answer, &(adsp_conn->dsc_ctx), adsp_evt );
            break;
		case ied_be_mouse_release:
		case ied_be_mouse_press:
		case ied_be_mouse_move:
			adsp_parsed_event->iec_event_type				= adsp_evt->iec_type;
			adsp_parsed_event->dsc_mouse_event.inc_wheel	= adsp_evt->inc_wheel;
			adsp_parsed_event->dsc_mouse_event.uinc_x		= adsp_evt->uinc_x;
			adsp_parsed_event->dsc_mouse_event.uinc_y		= adsp_evt->uinc_y;
			adsp_parsed_event->dsc_mouse_event.uisc_button	= adsp_evt->uisc_button;
			break;
        default:
            break;
    }
} /* end of m_handle_event */
