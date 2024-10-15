/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| ========                                                            |*/
/*|   sdh_compliance_check                                              |*/
/*|   compliance check datahook                                         |*/
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
#include "sdh_compl_check.h"
#include "./config/ds_config.h"
#include <ds_hstring.h>
#include <ds_hvector.h>
#include <ds_usercma.h>
#include "ds_compl_check.h"
#include <limits.h>

/*+---------------------------------------------------------------------+*/
/*| dll start functions:                                                |*/
/*+---------------------------------------------------------------------+*/
/**
 * function m_hlclib_conf
 *  read our configuration from xml file
 *
 * @param[in]   struct dsd_hl_clib_dom_conf*    ads_conf
 * @return      BOOL                                        TRUE = success
*/
extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf( struct dsd_hl_clib_dom_conf* ads_conf )
{
#ifdef _DEBUG
    // check incoming parameter:
    if ( ads_conf == NULL ) {
        printf( "HCOCE002E ads_conf == NULL\n" );
        return FALSE;
    }
#endif

    // initialize some variables:
    bool          bo_ret;
    ds_wsp_helper dsc_wsp_helper;
    ds_config     dsc_config( &dsc_wsp_helper );
    dsc_wsp_helper.m_init_conf( ads_conf );

    //-----------------------------------------
    // print startup message:
    //-----------------------------------------
    dsc_wsp_helper.m_cb_printf_out( "HCOCI001I: %s V%s initialized",
                                    SDH_LONGNAME, SDH_VERSION_STRING );

    //-----------------------------------------
    // read and save configuration section:
    //-----------------------------------------
    bo_ret = dsc_config.m_read_config();
    if ( bo_ret == false ) {
        dsc_wsp_helper.m_cb_printf_out( "HCOCE003E error while reading config - fallback to default" );
    }
    bo_ret = dsc_config.m_save_config();

    return (bo_ret == true) ? TRUE : FALSE;
} // end of m_hlclib_conf


/**
 * function m_hlclib01
 *  working function
 *
 * @param[in]   struct dsd_hl_clib1*    ads_trans
*/
extern "C" HL_DLL_PUBLIC void m_hlclib01( struct dsd_hl_clib_1* ads_trans )
{
#ifdef _DEBUG
    // check incoming parameter:
    if ( ads_trans == NULL ) {
        printf( "HCOCE004E ads_trans == NULL\n");
        return;
    }
#endif

    // initialize some variables:
    bool                   bo_ret;
#ifdef _DEBUG
    int                    in_locks;
#endif // _DEBUG
    class  ds_wsp_helper   dsc_wsp_helper;
    class  ds_compl_check* ads_compl_check = (ds_compl_check*)ads_trans->ac_ext;
    struct dsd_sdh_config* ads_config      = (dsd_sdh_config_t*)ads_trans->ac_conf;
    dsc_wsp_helper.m_init_trans( ads_trans );

    if ( ads_config == NULL ) {
        dsc_wsp_helper.m_cb_printf_out( "HCOCE005E config pointer == NULL" );
        dsc_wsp_helper.m_return_error();
        return;
    }

    switch ( ads_trans->inc_func ) {

        //-----------------------------------------
        // start session:
        //-----------------------------------------
        case DEF_IFUNC_START:
            // get memory for our working class
            // and put in ac_ext pointer -> we will get it again on every call
            ads_trans->ac_ext = dsc_wsp_helper.m_cb_get_memory( sizeof(ds_compl_check), true );
            if ( ads_trans->ac_ext == NULL ) {
                dsc_wsp_helper.m_log( ied_sdh_log_error,
                                      "HCOCE006E cannot get session memory" );
                dsc_wsp_helper.m_return_error();
                return;
            }

            // setup our main working class:
            ads_compl_check = new(ads_trans->ac_ext) ds_compl_check();

            // init main working class:
            ads_compl_check->m_init( &dsc_wsp_helper );

#if 0
            // setup storage container:
            dsc_wsp_helper.m_use_storage( &(ads_compl_check->avc_storage),
                                          SDH_STORAGE_SIZE );
#endif

            // log start of connection:
            dsc_wsp_helper.m_log_input();
            break;

        //-----------------------------------------
        // end session:
        //-----------------------------------------
        case DEF_IFUNC_CLOSE:
            // check our class pointer
            if ( ads_compl_check == NULL ) {
                dsc_wsp_helper.m_log( ied_sdh_log_warning,
                                      "HCOCW020W session pointer is null" );
                return;
            }
            // log end of connection:
            dsc_wsp_helper.m_log_output();
#if 0
            // setup storage container:
            dsc_wsp_helper.m_use_storage( &(ads_compl_check->avc_storage),
                                          SDH_STORAGE_SIZE );
#endif
            // init main working class:
            ads_compl_check->m_init( &dsc_wsp_helper );
            // call destructor for our working class:
            ads_compl_check->ds_compl_check::~ds_compl_check();
#if 0
            // clear storage container:
            dsc_wsp_helper.m_no_storage( &(ads_compl_check->avc_storage) );
#endif
            // free working class memory:
            dsc_wsp_helper.m_cb_free_memory( (char*)ads_trans->ac_ext );
            break;
        
        //-----------------------------------------
        // working session modes:
        //-----------------------------------------
        case DEF_IFUNC_CONT:
        case DEF_IFUNC_FROMSERVER:
        case DEF_IFUNC_TOSERVER:
        case DEF_IFUNC_REFLECT:
            // check our class pointer
            if ( ads_compl_check == NULL ) {
                dsc_wsp_helper.m_log( ied_sdh_log_warning,
                                      "HCOCW021W session pointer is null" );
                dsc_wsp_helper.m_return_close();
                return;
            }
#if 0
            // setup storage container:
            dsc_wsp_helper.m_use_storage( &(ads_compl_check->avc_storage),
                                          SDH_STORAGE_SIZE );
#endif
            // init main working class:
            ads_compl_check->m_init( &dsc_wsp_helper );
            bo_ret = ads_compl_check->m_run();
            if ( bo_ret == false ) {
                dsc_wsp_helper.m_log( ied_sdh_log_warning,
                                      "HCOCW022W working class returned false" );
            }
            break;

        //-----------------------------------------
        // unknown session modes:
        //-----------------------------------------
        default:
            dsc_wsp_helper.m_logf( ied_sdh_log_warning,
                                   "HCOCW023W unsupported inc_func %d selected",
                                   ads_trans->inc_func );
            dsc_wsp_helper.m_return_close();
            break;

    } // end of switch ( ads_trans->inc_func )

#ifdef _DEBUG
    in_locks = dsc_wsp_helper.m_count_cma_lock();
    if ( in_locks > 0 ) {
        dsc_wsp_helper.m_logf( ied_sdh_log_error, "HCOCE007E Number of CMA-LOCKS = %d\n", in_locks );
        dsd_unicode_string* ads_crash = NULL;
        ads_crash->ac_str = NULL;
    }
#endif

    return;
} // end of m_hlclib01


