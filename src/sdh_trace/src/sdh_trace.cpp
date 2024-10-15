/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| ========                                                            |*/
/*|   sdh_example                                                       |*/
/*|   example SDH                                                       |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| =======                                                             |*/
/*|   Michael Jakobs, 2009/02/04                                        |*/
/*|                                                                     |*/
/*| Version:                                                            |*/
/*| ========                                                            |*/
/*|   0.1                                                               |*/
/*|                                                                     |*/
/*| Copyright:                                                          |*/
/*| ==========                                                          |*/
/*|   HOB GmbH 2009                                                     |*/
/*|                                                                     |*/ 
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#ifdef HL_UNIX
#else // windows
    #include <windows.h>
#endif //HL_UNIX
#include <ds_wsp_helper.h>
#include "sdh_trace.h"
#include "./config/ds_config.h"

#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>

/*+---------------------------------------------------------------------+*/
/*| function prototypes:                                                |*/
/*+---------------------------------------------------------------------+*/
static void m_input_to_output( struct dsd_hl_clib_1* adsp_trans );

/*+---------------------------------------------------------------------+*/
/*| dll start functions:                                                |*/
/*+---------------------------------------------------------------------+*/
/**
 * function m_hlclib_conf
 *  read our configuration from xml file
 *
 * @param[in]   struct dsd_hl_clib_dom_conf*    adsp_conf
 * @return      BOOL                                        TRUE = success
*/
extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf( struct dsd_hl_clib_dom_conf* adsp_conf )
{
#ifdef _DEBUG
    // check incoming parameter:
    if ( adsp_conf == NULL ) {
        printf( "HTRCE002E adsp_conf == NULL\n" );
        return FALSE;
    }
#endif

    // initialize some variables:
    bool          bol_ret;
    ds_wsp_helper dsl_wsp_helper;
    ds_config     dsl_config( &dsl_wsp_helper );
    dsl_wsp_helper.m_init_conf( adsp_conf );

    dsl_config.m_read_config();
    bol_ret = dsl_config.m_log_enabled();
    if ( bol_ret == false ) {
        dsl_wsp_helper.m_cb_printf_out( "HTRCI001I %s V%s is disabled",
                                         SDH_LONGNAME, SDH_VERSION_STRING );
        return FALSE;
    }

    bol_ret = dsl_config.m_save_config();
    if ( bol_ret == true ) {
        // print startup message:
        dsl_wsp_helper.m_cb_printf_out( "HTRCI002I %s V%s initialized",
                                         SDH_LONGNAME, SDH_VERSION_STRING );
        return TRUE;
    }
    return FALSE;
} // end of m_hlclib_conf


/**
 * function m_hlclib01
 *  working function
 *
 * @param[in]   struct dsd_hl_clib1*    adsp_trans
*/
extern "C" HL_DLL_PUBLIC void m_hlclib01( struct dsd_hl_clib_1* adsp_trans )
{
#ifdef _DEBUG
    // check incoming parameter:
    if ( adsp_trans == NULL ) {
        printf( "HTRCE003E adsp_trans == NULL\n");
        return;
    }
#endif

    // initialize some variables:
    class  ds_wsp_helper   dsl_wsp_helper;
    dsl_wsp_helper.m_init_trans( adsp_trans );

    if ( adsp_trans->ac_conf == NULL ) {
        dsl_wsp_helper.m_cb_printf_out( "HTRCE004E config pointer == NULL" );
        dsl_wsp_helper.m_return_error();
        return;
    }

    switch ( adsp_trans->inc_func ) {

        //-----------------------------------------
        // start session:
        //-----------------------------------------
        case DEF_IFUNC_START:
            // log start of connection:
            dsl_wsp_helper.m_log_input();
            break;

        //-----------------------------------------
        // end session:
        //-----------------------------------------
        case DEF_IFUNC_CLOSE:
            // log end of connection:
            dsl_wsp_helper.m_log_output();
            break;
        
        //-----------------------------------------
        // working session modes:
        //-----------------------------------------
        case DEF_IFUNC_CONT:
        case DEF_IFUNC_REFLECT:
        case DEF_IFUNC_FROMSERVER:
        case DEF_IFUNC_TOSERVER:
            dsl_wsp_helper.m_log_input();

            if ( adsp_trans->adsc_gather_i_1_in != NULL ) {
                m_input_to_output( adsp_trans );
            }
            break;

        //-----------------------------------------
        // unknown session modes:
        //-----------------------------------------
        default:
            dsl_wsp_helper.m_cb_printf_out( "HTRCW002W unsupported inc_func %d selected",
                                            adsp_trans->inc_func );
            dsl_wsp_helper.m_return_close();
            break;

    } // end of switch ( adsp_trans->inc_func )
    return;
} // end of m_hlclib01


/**
 * function m_input_to_output
 *  move data unchanged from input to output
 *
 * @param[in]   struct dsd_hl_clib1*    adsp_trans
*/
static void m_input_to_output( struct dsd_hl_clib_1* adsp_trans )
{
    // initialize some variables:
    struct dsd_gather_i_1* adsl_in_cur;
    struct dsd_gather_i_1* adsl_out_cur;

    adsl_in_cur  = adsp_trans->adsc_gather_i_1_in;
    adsl_out_cur = adsp_trans->adsc_gai1_out_to_client ? adsp_trans->adsc_gai1_out_to_client
                                                       : adsp_trans->adsc_gai1_out_to_server;

    while ( adsl_in_cur != NULL ) {
        if ( adsl_out_cur == NULL ) {
            if ( adsp_trans->inc_func == DEF_IFUNC_TOSERVER ) {
                adsp_trans->adsc_gai1_out_to_server = (struct dsd_gather_i_1*)adsp_trans->achc_work_area;
                adsl_out_cur = adsp_trans->adsc_gai1_out_to_server;
            } else {
                adsp_trans->adsc_gai1_out_to_client = (struct dsd_gather_i_1*)adsp_trans->achc_work_area;
                adsl_out_cur = adsp_trans->adsc_gai1_out_to_client;
            }
        } else if ( (char*)(adsl_out_cur + 1) <    adsp_trans->achc_work_area
                                                 + adsp_trans->inc_len_work_area ) {
            adsl_out_cur->adsc_next = adsl_out_cur + 1;
            adsl_out_cur = adsl_out_cur->adsc_next;            
        } else {
            break;
        }

        adsl_out_cur->adsc_next     = NULL;
        adsl_out_cur->achc_ginp_cur = adsl_in_cur->achc_ginp_cur;
        adsl_out_cur->achc_ginp_end = adsl_in_cur->achc_ginp_end;

        adsl_in_cur->achc_ginp_cur = adsl_in_cur->achc_ginp_end;
        adsl_in_cur = adsl_in_cur->adsc_next;
    }
} // end of m_input_to_output
