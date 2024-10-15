/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#include <time.h>
#include <rdvpn_globals.h>
#include <ds_wsp_helper.h>
#include <ds_hstring.h>
#ifdef OLD
    #include "./cookie/ds_cookie_manager.h"
#else
    #include "./cookies/ds_cookie.h"
    #define USE_COOKIE_VECTOR
    #include <ds_hvector2.h>
    #include "./cookies/ds_ck_mgmt.h"
#endif
#include "ds_cookie_test.h"
#include "sdh_cookie_test.h"
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H

/*+---------------------------------------------------------------------+*/
/*| constructor:                                                        |*/
/*+---------------------------------------------------------------------+*/
ds_cookie_test::ds_cookie_test( void )
{
    ads_wsp_helper = NULL;
    ads_config     = NULL;
    av_storage     = NULL;
} // end of ds_cookie_test::ds_cookie_test


/*+---------------------------------------------------------------------+*/
/*| destructor:                                                         |*/
/*+---------------------------------------------------------------------+*/
ds_cookie_test::~ds_cookie_test()
{
} // end of ds_cookie_test::~ds_cookie_test


/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_cookie_test::m_init
 *
 * @param[in]   ds_wsp_helper*  ads_wsp_helper_in
*/
void ds_cookie_test::m_init( ds_wsp_helper* ads_wsp_helper_in )
{
    ads_wsp_helper = ads_wsp_helper_in;
#ifdef OLD
    dsc_cookies.m_setup( ads_wsp_helper );
#else
    dsc_ck_mgmt.m_init( ads_wsp_helper, true );
#endif
} // end of ds_cookie_test::m_init


/**
 * function ds_cookie_test::m_run
 * our start entry as sdh working class
 *
 * @return      bool                                    true = success
*/
bool ds_cookie_test::m_run()
{
    // initialize some variables:
    bool                   bo_ret     = true;           // our return value
    struct dsd_gather_i_1* ads_gather;                  // input data


    //----------------------------------------------------
    // init our helper class and config pointer:
    //----------------------------------------------------
    ads_config = (dsd_sdh_config_t*)ads_wsp_helper->m_get_config();

    //----------------------------------------------------
    // log incomming data:
    //----------------------------------------------------
    ads_wsp_helper->m_log_input();

    //----------------------------------------------------
    // handle data:
    //----------------------------------------------------
    ads_gather = ads_wsp_helper->m_get_input();
    if ( ads_gather != NULL ) {
        bo_ret = m_handle_data( ads_gather );
    }

    //----------------------------------------------------
    // log outgoing data:
    //----------------------------------------------------
    ads_wsp_helper->m_log_output();

    return bo_ret;
} // end of ds_cookie_test::m_run


/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_cookie_test::m_handle_data
 * general data handling
 * 
 * @param[in]   struct dsd_gather_i_1*  ads_gather      input data
 * @return      bool                                    true = success
*/
bool ds_cookie_test::m_handle_data( struct dsd_gather_i_1* ads_gather )
{
    // initialize some variables:
    int        in_length    = 0;        // total length of incomming data
    int        in_offset    = 0;        // reading position in data
    char*      ach_byte;
    ds_hstring str_cookie(ads_wsp_helper);
    ds_hvector2<ds_cookie> dsl_cookies( ads_wsp_helper );

    //---------------------------------------------
    // evalute input gather length:
    //---------------------------------------------
    in_length = ads_wsp_helper->m_get_gather_len( ads_gather );

    //---------------------------------------------
    // set cookie:
    //---------------------------------------------
    for ( ;in_offset < in_length; in_offset++ ) {
        ach_byte = ads_wsp_helper->m_get_ptr( ads_gather, in_offset );
        switch ( ach_byte[0] ) {
            case '\n':
                if ( str_cookie.m_get_len() > 0 ) {
#ifdef OLD
                    dsc_cookies.m_set_cookie( "http://www.hob.de/", str_cookie.m_get_ptr(), str_cookie.m_get_len() );
#else
                    dsc_ck_mgmt.m_set_cookie( str_cookie.m_get_ptr(),
                                              str_cookie.m_get_len(),
                                              "www.hob.de", strlen("www.hob.de"),
                                              "/", strlen("/"),
                                              "test_cma" );
#endif
                }
                str_cookie.m_reset();
                break;
            default:
                str_cookie.m_write( ach_byte, 1 );
                break;
        }
    }
    if ( str_cookie.m_get_len() > 0 ) {
#ifdef OLD
        dsc_cookies.m_set_cookie( "http://www.hob.de/", str_cookie.m_get_ptr(), str_cookie.m_get_len() );
#else
        dsc_ck_mgmt.m_set_cookie( str_cookie.m_get_ptr(), str_cookie.m_get_len(),
                                  "www.hob.de", strlen("www.hob.de"),
                                  "/", strlen("/"), "test_cma" );
#endif
    }

#ifdef OLD
    dsc_cookies.m_get_cookie( "http://www.hob.de/" );
    dsc_cookies.m_export_cookies();
#else
    dsl_cookies = dsc_ck_mgmt.m_get_cookies( "www.hob.de", strlen("www.hob.de"),
                                              "/", strlen("/"), "test_cma" );
#endif

    //---------------------------------------------
    // mark data as processed until offset:
    //---------------------------------------------
    ads_wsp_helper->m_mark_processed( ads_gather, &in_offset, &in_length );
    
    //---------------------------------------------
    // mark data as processed until offset:
    //---------------------------------------------
    ads_wsp_helper->m_send_data( "OK", 2 );
    return true;
} // end of ds_cookie_test::m_handle_data

