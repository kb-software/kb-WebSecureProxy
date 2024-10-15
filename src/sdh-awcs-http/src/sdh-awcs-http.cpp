/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| FILE:                                                               |*/
/*| -----                                                               |*/
/*|  sdh-awcs-http.cpp                                                  |*/
/*|                                                                     |*/
/*| Description:                                                        |*/
/*| ------------                                                        |*/
/*|  serverdatahook for html5 project                                   |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| -------                                                             |*/
/*|  Michael Jakobs, Dec. 2011                                          |*/
/*|  Tobias Hofmann                                                     |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| system includes:                                                    |*/
/*+---------------------------------------------------------------------+*/
#ifndef HL_UNIX
#include <windows.h>
#endif

/*+---------------------------------------------------------------------+*/
/*| local includes:                                                     |*/
/*+---------------------------------------------------------------------+*/
#include <hob-xsclib01.h>
#include <hob-xs-html5.h>

// RDP Client Header Files
#include <stdint.h>
#include "hob-encry-1.h"
#define HCOMPR2 // stupid stuff for hob-rdpclient1.h
#include "hob-cd-record-1.h"
#include "hob-rdpclient1.h"

/* todo: remove dependencies! */
#include "hob-http-processor.h"
#include "hob-xs-html5-priv.h"

#include <hob-xs-rdpacc.h>
#include <hob-xs-translator.h>
#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>

/*+---------------------------------------------------------------------+*/
/*| default configuration:                                              |*/
/*+---------------------------------------------------------------------+*/
static dsd_conf_awcs_html5 dss_conf_awcs_html5 = {
    /* root directory */
    { "../../../../resource/www-awcs", 29, ied_chs_utf_8 },
    /* default html */
    { "index.html",                    10, ied_chs_utf_8 }
};

/*+---------------------------------------------------------------------+*/
/*| internal structures:                                                |*/
/*+---------------------------------------------------------------------+*/
typedef struct dsd_awcs_ext {
    void *avc_html5;                        /* html5 session pointer     */
    void *avc_rdpacc;                       /* rdpacc session pointer    */
} dsd_awcs_ext;


/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
 * public function m_hlclib_conf
 *  read our configuration from xml file
 *
 * @param[in]   struct dsd_hl_clib_dom_conf *adsp_conf
 * @return      BOOL                                        TRUE = success
*/
extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf( struct dsd_hl_clib_dom_conf *adsp_conf )
{
    return TRUE;
} // end of m_hlclib_conf

/**
 * public function m_hlclib01
 *  working function
 *
 * @param[in]   struct dsd_hl_clib1 *adsp_trans
*/
extern "C" HL_DLL_PUBLIC void m_hlclib01( struct dsd_hl_clib_1 *adsp_trans )
{
    BOOL						bol_ret;         /* return from aux calls */
    struct dsd_awcs_ext			*adsl_session;   /* our session memory    */
    
	struct dsd_call_awcs_html5	dsl_html5_call;  /* worker call function  */
	struct dsd_call_rdpacc		dsl_call_rdpacc;

	struct dsd_browser_event	*adsl_browser_event = NULL; /* contains mouse, keyboard and other html5 events (like connect or so */
	struct dsd_rdp_user_event	dsl_rdp_user_event;
	
	struct dsd_rdp_draw_command	*adsl_rdp_cmd_out;
	struct dsd_rdp_draw_command	*adsl_tmp;

	struct dsd_rdpacc_settings	*adsl_rdpacc_settings;
	struct dsd_html5_conn		*adsl_html5_settings;

	//struct dsd_html5_answer		dsl_html5_answer;
	struct dsd_rdp_event		*adsl_rdp_event = NULL;

	switch( adsp_trans->inc_func ) {
        case DEF_IFUNC_START:
            /*
                a new connection is coming in:
                 -> allocate memory for our session memory
                 -> start the needed modules
            */
            bol_ret = adsp_trans->amc_aux( adsp_trans->vpc_userfld,
                                           DEF_AUX_MEMGET, &adsp_trans->ac_ext,
                                           sizeof(struct dsd_awcs_ext) );
            if (    bol_ret == FALSE
                 || adsp_trans->ac_ext == NULL ) {
                adsp_trans->inc_return = DEF_IRET_ERRAU;
                return;
            }
            adsl_session = (struct dsd_awcs_ext*)adsp_trans->ac_ext;

            /*
                start html5 modul:
            */
            memset( &dsl_html5_call, 0, sizeof(struct dsd_call_awcs_html5) );
            dsl_html5_call.amc_aux         = adsp_trans->amc_aux;
            dsl_html5_call.adsc_conf       = &dss_conf_awcs_html5; /* TODO: make non-static */
            dsl_html5_call.avc_userfield   = adsp_trans->vpc_userfld;
            m_html5_start( &dsl_html5_call );
            adsl_session->avc_html5 = dsl_html5_call.avc_ext;
            break;

        case DEF_IFUNC_CLOSE:
            /*
                a connection is closed
                 -> close the needed modules
                 -> free session memory
            */
            adsl_session = (struct dsd_awcs_ext*)adsp_trans->ac_ext;

            /*
                close html5 modul:
            */
            memset( &dsl_html5_call, 0, sizeof(struct dsd_call_awcs_html5) );
            dsl_html5_call.amc_aux         = adsp_trans->amc_aux;
            dsl_html5_call.adsc_conf       = &dss_conf_awcs_html5; /* TODO: make non-static */
            dsl_html5_call.avc_userfield   = adsp_trans->vpc_userfld;
            dsl_html5_call.avc_ext         = adsl_session->avc_html5;
            m_html5_end( &dsl_html5_call );

            adsp_trans->amc_aux( adsp_trans->vpc_userfld, DEF_AUX_MEMFREE,
                                 adsp_trans->ac_ext, 0 );

            break;

        case DEF_IFUNC_FROMSERVER:
			adsl_session = (struct dsd_awcs_ext*)adsp_trans->ac_ext;
			adsl_rdpacc_settings = (struct dsd_rdpacc_settings*)adsl_session->avc_rdpacc;
			adsl_html5_settings = (struct dsd_html5_conn*)adsl_session->avc_html5;

			memset(&dsl_call_rdpacc, 0, sizeof(dsd_call_rdpacc) );
			dsl_call_rdpacc.amc_aux				= adsp_trans->amc_aux;
			dsl_call_rdpacc.achc_work_area		= adsp_trans->achc_work_area;
			dsl_call_rdpacc.inc_len_work_area	= adsp_trans->inc_len_work_area;
			dsl_call_rdpacc.adsc_gather_i_1_in  = adsp_trans->adsc_gather_i_1_in;
			dsl_call_rdpacc.avc_userfield		= adsp_trans->vpc_userfld;
			dsl_call_rdpacc.avc_ext				= adsl_session->avc_rdpacc;
			
			/* RDP ACC */
			m_rdpacc_get_event( &dsl_call_rdpacc, &adsl_rdp_cmd_out );
			
			if( dsl_call_rdpacc.boc_data_to_server == TRUE )
			{
				adsp_trans->adsc_gai1_out_to_server = dsl_call_rdpacc.adsc_gather_i_1_out;
			}
			else
			{
				/* HTML5 */
				memset( &dsl_html5_call, 0, sizeof(struct dsd_call_awcs_html5) );
				dsl_html5_call.achc_work_area     = adsp_trans->achc_work_area;
				dsl_html5_call.inc_len_work_area  = adsp_trans->inc_len_work_area;			
				dsl_html5_call.amc_aux            = adsp_trans->amc_aux;
				dsl_html5_call.adsc_conf          = &dss_conf_awcs_html5; /* TODO: make non-static */
				dsl_html5_call.avc_userfield      = adsp_trans->vpc_userfld;
				dsl_html5_call.avc_ext            = adsl_session->avc_html5;
				
				while( adsl_rdpacc_settings->dsc_command_out != NULL )
				{						
					m_rdp_to_html5( adsl_rdpacc_settings->dsc_command_out, &adsl_rdp_event );
				
					m_html5_send_drawing( &dsl_html5_call, adsl_rdp_event ); // give drawing order!
				
					adsl_tmp = adsl_rdpacc_settings->dsc_command_out;
					adsl_rdpacc_settings->dsc_command_out = adsl_rdpacc_settings->dsc_command_out->adsc_next;
					adsp_trans->amc_aux( adsp_trans->vpc_userfld, DEF_AUX_MEMFREE, &(adsl_tmp), 0 );
				}

				if(dsl_html5_call.adsc_gather_i_1_out != NULL )
				{
					adsp_trans->adsc_gai1_out_to_client = dsl_html5_call.adsc_gather_i_1_out;
				}
				memset( &adsl_html5_settings->dsc_cur_workarea, 0, sizeof(struct dsd_aux_get_workarea) );
			}

			break;
        case DEF_IFUNC_TOSERVER:
            adsl_session = (struct dsd_awcs_ext*)adsp_trans->ac_ext;

			memset( &dsl_html5_call, 0, sizeof(struct dsd_call_awcs_html5) );
			memset( &dsl_rdp_user_event, 0, sizeof(struct dsd_rdp_user_event) );

            dsl_html5_call.achc_work_area     = adsp_trans->achc_work_area;
            dsl_html5_call.inc_len_work_area  = adsp_trans->inc_len_work_area;
            dsl_html5_call.adsc_gather_i_1_in = adsp_trans->adsc_gather_i_1_in;
            dsl_html5_call.amc_aux            = adsp_trans->amc_aux;
            dsl_html5_call.adsc_conf          = &dss_conf_awcs_html5; /* TODO: make non-static */
            dsl_html5_call.avc_userfield      = adsp_trans->vpc_userfld;
            dsl_html5_call.avc_ext            = adsl_session->avc_html5;

			/* HTML5 */
            m_html5_get_event( &dsl_html5_call, &adsl_browser_event );

			if( adsl_browser_event->iec_type != ied_be_unknown )
			{
				/* TRANSLATOR */
				m_html5_to_rdp( adsl_browser_event, &dsl_rdp_user_event );

				memset(&dsl_call_rdpacc, 0, sizeof(dsd_call_rdpacc) );
				dsl_call_rdpacc.amc_aux				= adsp_trans->amc_aux;
				dsl_call_rdpacc.achc_work_area		= adsp_trans->achc_work_area;
				dsl_call_rdpacc.inc_len_work_area	= adsp_trans->inc_len_work_area;
				dsl_call_rdpacc.adsc_gather_i_1_in  = adsp_trans->adsc_gather_i_1_in;
				dsl_call_rdpacc.avc_userfield		= adsp_trans->vpc_userfld;
				dsl_call_rdpacc.avc_ext				= adsl_session->avc_rdpacc;

				/* RDPACC     */
				m_rdpacc_send_event( &dsl_call_rdpacc, &dsl_rdp_user_event );
				adsp_trans->adsc_gai1_out_to_server = dsl_call_rdpacc.adsc_gather_i_1_out;
			}
			break;
        case DEF_IFUNC_REFLECT:
            /*
                Reflect modus is just present until we connect
                to an internal RDP Server
            */
            adsl_session = (struct dsd_awcs_ext*)adsp_trans->ac_ext;

            memset( &dsl_html5_call, 0, sizeof(struct dsd_call_awcs_html5) );

            dsl_html5_call.achc_work_area     = adsp_trans->achc_work_area;
            dsl_html5_call.inc_len_work_area  = adsp_trans->inc_len_work_area;
            dsl_html5_call.adsc_gather_i_1_in = adsp_trans->adsc_gather_i_1_in;
            dsl_html5_call.amc_aux            = adsp_trans->amc_aux;
            dsl_html5_call.adsc_conf          = &dss_conf_awcs_html5; /* TODO: make non-static */
            dsl_html5_call.avc_userfield      = adsp_trans->vpc_userfld;
            dsl_html5_call.avc_ext            = adsl_session->avc_html5;
            
			/* HTML5 */
			m_html5_get_event( &dsl_html5_call, &adsl_browser_event );

			if( adsl_browser_event->iec_type == ied_be_connect ) // start the connection to the rdp server
			{
				memset( &dsl_rdp_user_event, 0, sizeof(struct dsd_rdp_user_event) );
				
				/* TRANSLATOR */
				m_html5_to_rdp( adsl_browser_event, &dsl_rdp_user_event );

				memset(&dsl_call_rdpacc, 0, sizeof(dsd_call_rdpacc) );
				dsl_call_rdpacc.amc_aux				= adsp_trans->amc_aux;
				dsl_call_rdpacc.achc_work_area		= adsp_trans->achc_work_area;
				dsl_call_rdpacc.inc_len_work_area	= adsp_trans->inc_len_work_area;
				dsl_call_rdpacc.adsc_gather_i_1_in  = adsp_trans->adsc_gather_i_1_in;
				dsl_call_rdpacc.avc_userfield		= adsp_trans->vpc_userfld;
				
				/* RDP ACC */
				m_rdpacc_start( &dsl_call_rdpacc, &dsl_rdp_user_event );
				
				adsl_session->avc_rdpacc = dsl_call_rdpacc.avc_ext;
				
				adsp_trans->adsc_gai1_out_to_server = dsl_call_rdpacc.adsc_gather_i_1_out;
				
			}
			else
			{	// send data back to the browser
				adsp_trans->adsc_gai1_out_to_client = dsl_html5_call.adsc_gather_i_1_out;
			}

            break;

        default:
            break;
    }
    return;
} // end of m_hlclib01
