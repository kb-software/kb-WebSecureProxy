/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#include <time.h>
#include <rdvpn_globals.h>
#include <ds_wsp_helper.h>
#include "ds_tcpcomp_test.h"
#include "sdh_tcpcomp_test.h"
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H

/*+---------------------------------------------------------------------+*/
/*| constructor:                                                        |*/
/*+---------------------------------------------------------------------+*/
ds_tcpcomp_test::ds_tcpcomp_test( void )
{
    ads_wsp_helper = NULL;
    ads_config     = NULL;
    av_storage     = NULL;
    in_state       = 0;
} // end of ds_tcpcomp_test::ds_tcpcomp_test


/*+---------------------------------------------------------------------+*/
/*| destructor:                                                         |*/
/*+---------------------------------------------------------------------+*/
ds_tcpcomp_test::~ds_tcpcomp_test()
{
} // end of ds_tcpcomp_test::~ds_tcpcomp_test


/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_tcpcomp_test::m_init
 *
 * @param[in]   ds_wsp_helper*  ads_wsp_helper_in
*/
void ds_tcpcomp_test::m_init( ds_wsp_helper* ads_wsp_helper_in )
{
    ads_wsp_helper = ads_wsp_helper_in;
} // end of ds_tcpcomp_test::m_init


/**
 * function ds_tcpcomp_test::m_run
 * our start entry as sdh working class
 *
 * @return      bool                                    true = success
*/
bool ds_tcpcomp_test::m_run()
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
} // end of ds_tcpcomp_test::m_run


/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_tcpcomp_test::m_handle_data
 * general data handling
 * 
 * @param[in]   struct dsd_gather_i_1*  ads_gather      input data
 * @return      bool                                    true = success
*/
bool ds_tcpcomp_test::m_handle_data( struct dsd_gather_i_1* ads_gather )
{
    // initialize some variables:
    int        in_length    = 0;        // total length of incomming data
    int        in_offset    = 0;        // reading position in data
    bool       bo_ret;

    //---------------------------------------------
    // evalute input gather length:
    //---------------------------------------------
    in_length = ads_wsp_helper->m_get_gather_len( ads_gather );


    //---------------------------------------------
    // print current state:
    //---------------------------------------------
    ads_wsp_helper->m_logf( ied_sdh_log_info, "current state: %d", in_state );

    //---------------------------------------------
    // do some dummy connections:
    //---------------------------------------------
    switch ( in_state ) {
        case 0:
            bo_ret = m_connect( false, "www.hob.de", 80 );
            break;

        case 2:
            //bo_ret = m_close();
            //bo_ret = m_connect( false, "knownet.hob.de", 80 );
            bo_ret = m_connect( false, "www.hob.de", 80 );
            bo_ret = m_close();
            break;

        case 4:
            bo_ret = m_close();
            break;

        case 6:
            ads_wsp_helper->m_return_close();
            break;

        default:
            break;
    }
    in_state++;

    //---------------------------------------------
    // send some data:
    //---------------------------------------------
    while ( ads_gather != NULL ) {
        // send
        in_offset = (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
        ads_wsp_helper->m_send_data( ads_gather->achc_ginp_cur, in_offset );
        
        // mark as processed:
        ads_wsp_helper->m_mark_processed( ads_gather, &in_offset, &in_length );

        // get next:
        ads_gather = ads_gather->adsc_next;
    }

    return true;
} // end of ds_tcpcomp_test::m_handle_data


/**
 * function ds_tcpcomp_test::m_connect
 * connect to external server
 * 
 * @param[in]   bool        bo_https
 * @param[in]   const char* ach_host
 * @param[in]   int         in_port
 * @return      bool                                    true = success
*/
bool ds_tcpcomp_test::m_connect( bool bo_https, const char* ach_host, int in_port )
{
    // initialize some variables:
    struct dsd_aux_tcp_conn_1 ds_conn;
    bool                      bo_ret;

    // setup tcp structure:
    memset( &ds_conn, 0, sizeof(struct dsd_aux_tcp_conn_1) );
    ds_conn.achc_server_ineta = (char*)ach_host;
    ds_conn.imc_server_port   = in_port;
    if ( bo_https == true ) {
        ds_conn.dsc_aux_tcp_def.ibc_ssl_client = 1;
    }

    ads_wsp_helper->m_logf( ied_sdh_log_warning,
                            "HTCPCT100I: Connecting to %s:%d %s",
                            ach_host, in_port, (bo_https?"(with SSL)":"") );

    // do the connect:
    bo_ret = ads_wsp_helper->m_cb_tcp_connect( &ds_conn );
    if ( bo_ret == false ) {
        ads_wsp_helper->m_logf( ied_sdh_log_warning, SDH_INFO(101), "Connection failed" );
    } else {
        ads_wsp_helper->m_logf( ied_sdh_log_warning, SDH_INFO(101), "Connection successful" );
    }
    return bo_ret;
} // end of ds_tcpcomp_test::m_connect


/**
 * function ds_tcpcomp_test::m_close
 * close connection to external server
 *
 * @return      bool                                    true = success
*/
bool ds_tcpcomp_test::m_close()
{
    return ads_wsp_helper->m_cb_tcp_close();
} // end of ds_tcpcomp_test::m_close
