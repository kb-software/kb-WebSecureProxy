/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| ========                                                            |*/
/*|   sdh_cookie_test                                                   |*/
/*|   SDH to avoid Cross-Site scripting from other tcp connections      |*/
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
#include "sdh_cookie_test.h"
#include "./config/ds_config.h"
#ifdef OLD
    #include "./cookie/ds_cookie_manager.h"
#else
    #include <ds_hstring.h>
    #include "./cookies/ds_cookie.h"
    #define USE_COOKIE_VECTOR
    #include <ds_hvector2.h>
    #include "./cookies/ds_ck_mgmt.h"
#endif
#include "ds_cookie_test.h"
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
extern "C" __declspec( dllexport ) BOOL m_hlclib_conf( struct dsd_hl_clib_dom_conf* ads_conf )
{
#ifdef _DEBUG
    // check incomming parameter:
    if ( ads_conf == NULL ) {
        printf( SDH_ERROR(1), "ads_conf == NULL\n" );
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
    dsc_wsp_helper.m_cb_printf_out( "HCOOKIEI%03dI %s V%s initialized",
                                    1, SDH_LONGNAME, SDH_VERSION );
    dsc_wsp_helper.m_cb_printf_out( "HCOOKIEI002I: compiled with %s", dsc_wsp_helper.m_get_version() );

    //-----------------------------------------
    // read and save configuration section:
    //-----------------------------------------
    bo_ret = dsc_config.m_read_config();
    if ( bo_ret == false ) {
        dsc_wsp_helper.m_cb_printf_out( SDH_ERROR(6),
                                        "error while reading config - fallback to default" );
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
extern "C" __declspec( dllexport ) void m_hlclib01( struct dsd_hl_clib_1* ads_trans )
{
#ifdef _DEBUG
    // check incomming parameter:
    if ( ads_trans == NULL ) {
        printf( SDH_ERROR(2), "ads_trans == NULL\n");
        return;
    }
#endif

    // initialize some variables:
    bool                   bo_ret;
#ifdef _DEBUG
    int                    in_locks;
#endif // _DEBUG
    class  ds_wsp_helper   dsc_wsp_helper;
    class  ds_cookie_test*     ads_cookie_test = (ds_cookie_test*)ads_trans->ac_ext;
    struct dsd_sdh_config* ads_config  = (dsd_sdh_config_t*)ads_trans->ac_conf;
    dsc_wsp_helper.m_init_trans( ads_trans );

    if ( ads_config == NULL ) {
        dsc_wsp_helper.m_cb_printf_out( SDH_ERROR(8), "config pointer == NULL" );
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
            ads_trans->ac_ext = dsc_wsp_helper.m_cb_get_memory( sizeof(ds_cookie_test), true );
            if ( ads_trans->ac_ext == NULL ) {
                dsc_wsp_helper.m_cb_printf_out( SDH_ERROR(3), "cannot get session memory" );
                dsc_wsp_helper.m_return_error();
                return;
            }

            // setup our main working class:
            ads_cookie_test = new(ads_trans->ac_ext) ds_cookie_test();

            // init main working class:
            ads_cookie_test->m_init( &dsc_wsp_helper );

            // setup storage container:
            dsc_wsp_helper.m_use_storage( &(ads_cookie_test->av_storage), SDH_STORAGE_SIZE );

            // log start of connection:
            dsc_wsp_helper.m_log_input();
            break;

        //-----------------------------------------
        // end session:
        //-----------------------------------------
        case DEF_IFUNC_CLOSE:
            // check our class pointer
            if ( ads_cookie_test == NULL ) {
                dsc_wsp_helper.m_cb_printf_out( SDH_WARN(19), "session pointer is null" );
                return;
            }
            // log end of connection:
            dsc_wsp_helper.m_log_output();
            // init main working class:
            ads_cookie_test->m_init( &dsc_wsp_helper );
            // call destructor for our working class:
            ads_cookie_test->ds_cookie_test::~ds_cookie_test();
            // clear storage container:
            dsc_wsp_helper.m_no_storage( &(ads_cookie_test->av_storage) );
            // free working class memory:
            dsc_wsp_helper.m_cb_free_memory( (char*)ads_trans->ac_ext, sizeof(ds_cookie_test) );
            break;
        
        //-----------------------------------------
        // working session modes:
        //-----------------------------------------
        case DEF_IFUNC_CONT:
        case DEF_IFUNC_FROMSERVER:
        case DEF_IFUNC_TOSERVER:
        case DEF_IFUNC_REFLECT:
            // check our class pointer
            if ( ads_cookie_test == NULL ) {
                dsc_wsp_helper.m_cb_printf_out( SDH_WARN(20), "session pointer is null" );
                dsc_wsp_helper.m_return_close();
                return;
            }
            // init main working class:
            ads_cookie_test->m_init( &dsc_wsp_helper );
            bo_ret = ads_cookie_test->m_run();
            if ( bo_ret == false ) {
                dsc_wsp_helper.m_cb_printf_out( SDH_WARN(21), "working class returned false" );
            }
            break;

        //-----------------------------------------
        // unknown session modes:
        //-----------------------------------------
        default:
            dsc_wsp_helper.m_cb_printf_out( SDH_WARN(22), "unsupported inc_func selected" );
            dsc_wsp_helper.m_return_close();
            break;

    } // end of switch ( ads_trans->inc_func )

#ifdef _DEBUG
    in_locks = dsc_wsp_helper.m_count_cma_lock();
    if ( in_locks > 0 ) {
        dsc_wsp_helper.m_cb_printf_out( "Number of CMA-LOCKS = %d\n", in_locks );
        dsd_unicode_string* ads_crash = NULL;
        ads_crash->ac_str = NULL;
    }
#endif

    return;
} // end of m_hlclib01


