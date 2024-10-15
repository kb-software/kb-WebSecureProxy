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
#include "ds_example.h"
#include "sdh_example.h"
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H
#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>

/*+---------------------------------------------------------------------+*/
/*| constructor:                                                        |*/
/*+---------------------------------------------------------------------+*/
ds_example::ds_example( void )
{
    ads_wsp_helper = NULL;
    ads_config     = NULL;
    av_storage     = NULL;
} // end of ds_example::ds_example


/*+---------------------------------------------------------------------+*/
/*| destructor:                                                         |*/
/*+---------------------------------------------------------------------+*/
ds_example::~ds_example()
{
} // end of ds_example::~ds_example


/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_example::m_init
 *
 * @param[in]   ds_wsp_helper*  ads_wsp_helper_in
*/
void ds_example::m_init( ds_wsp_helper* ads_wsp_helper_in )
{
    ads_wsp_helper = ads_wsp_helper_in;
} // end of ds_example::m_init


/**
 * function ds_example::m_run
 * our start entry as sdh working class
 *
 * @return      bool                                    true = success
*/
bool ds_example::m_run()
{
    // initialize some variables:
    bool                   bo_ret     = true;           // our return value
    struct dsd_gather_i_1* ads_gather;                  // input data


    //----------------------------------------------------
    // init our helper class and config pointer:
    //----------------------------------------------------
    ads_config = (dsd_sdh_config_t*)ads_wsp_helper->m_get_config();

    //----------------------------------------------------
    // log incoming data:
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
} // end of ds_example::m_run


/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/
#include <ds_hvector.h>
#include <ds_hashtable.h>
/**
 * function ds_example::m_handle_data
 * general data handling
 * 
 * @param[in]   struct dsd_gather_i_1*  ads_gather      input data
 * @return      bool                                    true = success
*/
bool ds_example::m_handle_data( struct dsd_gather_i_1* ads_gather )
{
    // initialize some variables:
    int        in_length    = 0;        // total length of incoming data
    int        in_offset    = 0;        // reading position in data

    //---------------------------------------------
    // evalute input gather length:
    //---------------------------------------------
    in_length = ads_wsp_helper->m_get_gather_len( ads_gather );

    /*
        insert your working code here
    */
//#define VECTOR_TEST
#ifdef VECTOR_TEST
    ds_hstring ds_str(ads_wsp_helper);
    ds_hvector_btype<int> ds_vec( ads_wsp_helper );

    int in = 0;

    ds_vec.m_add( 1 );
    ds_vec.m_add( 2 );
    ds_vec.m_add( 3 );
    ds_vec.m_add( 4 );
    ds_vec.m_add( 5 );

    ds_vec.m_insert( 0, 0 );
    ds_vec.m_insert( 1, 13 );
    ds_vec.m_insert( 7, 12 );

    ds_hvector_btype<int> ds_vec2( ds_vec );
    ds_hvector_btype<int> ds_vec3( ads_wsp_helper );

    ds_vec3 = ds_vec;

    ds_vec.m_delete_first();
    ds_vec.m_delete_last();
    
    ds_vec3 = ds_vec;

    int in_test = ds_vec[0];

    ds_vec.m_delete( 1 );
    ds_vec.m_delete( 10 );

    ds_str = "Hallo Welt";

    ds_hstring ds_substr1 = ds_str.m_substr( 1, 4 );
    ds_hstring ds_substr2 = ds_str.m_substr( 1 );
    ds_hvector<ds_hstring> ds_strvec( ads_wsp_helper );

    ds_strvec.m_add( ds_str );
    ds_strvec.m_add( ds_substr1 );
    ds_strvec.m_add( ds_substr2 );
    ds_strvec.m_delete(0);
#endif

//#define STRING_TEST
#ifdef STRING_TEST
    ds_hstring ds_str( ads_wsp_helper );
    ds_str.m_write( "__Hallo Welt__!" );

    /*ds_str.m_find_first_of( "Wal" );
    ds_str.m_trim( "_!" );*/

    bool bol_ret1 = ds_str.m_ends_with( "_!" );
    bool bol_ret2 = ds_str.m_ends_with( "__" );
    bool bol_ret3 = ds_str.m_ends_with( "__Hallo Welt__!" );

    
    ds_hstring ds_str2( ads_wsp_helper );
    ds_str2.m_write( "mail.ingun.com" );
    bol_ret3 = ds_str2.m_ends_with( "mail.ingun.com" );
#endif

//#define FILE_TEST
#ifdef FILE_TEST
    char* ach_file = "testxxxx.txt";

    struct dsd_hl_aux_diskfile_1 ds_file;
    memset( &ds_file, 0, sizeof(struct dsd_hl_aux_diskfile_1) );

    ds_file.ac_name = (void*)ach_file;
    ds_file.inc_len_name = (int)strlen(ach_file);
    ds_file.iec_chs_name = ied_chs_ansi_819;

    ads_wsp_helper->m_cb_file_access ( &ds_file );
    ads_wsp_helper->m_cb_file_release( &ds_file );
    
    ads_wsp_helper->m_cb_file_lastmodified( &ds_file );
#endif

//#define CONN_TEST
#ifdef CONN_TEST
    struct dsd_aux_tcp_conn_1 dsl_conn;
    const char *achl_ineta = "2003:100:1000:e40:c0d2:2f85:b706:6c1e";
    memset( &dsl_conn, 0, sizeof(struct dsd_aux_tcp_conn_1) );

    dsl_conn.dsc_target_ineta.ac_str      = (void*)achl_ineta;
    dsl_conn.dsc_target_ineta.imc_len_str = strlen(achl_ineta);
    dsl_conn.dsc_target_ineta.iec_chs_str = ied_chs_utf_8;
    dsl_conn.imc_server_port              = 23456;

    ads_wsp_helper->m_cb_tcp_connect( &dsl_conn );
#endif

//#define HASHTABLE_TEST
#ifdef HASHTABLE_TEST
    const char* ach_test[] = {
        "aaa", "bbb", "ccc", "ddd",
        "eee", "fff", "ggg", "hhh",
        "iii", "jjj", "kkk", "lll",
        "mmm", "nnn", "ooo", "ppp",
        "qqq", "rrr", "sss", "ttt",
        "uuu", "vvv", "www", "xxx",
        "yyy", "zzz", "AAA", "BBB",
        "CCC", "DDD", "EEE", "FFF",
        "GGG", "HHH", "III", "JJJ",
        "KKK", "LLL", "MMM", "NNN",
        "OOO", "PPP", "QQQ", "RRR",
        "SSS", "TTT", "UUU", "VVV",
        "WWW", "XXX", "YYY", "ZZZ",
        NULL
    };
    int in_count = 0;

    ds_hashtable<int> dsl_htable( ads_wsp_helper );

    while ( ach_test[in_count] != NULL ) {
        dsl_htable.m_add( ach_test[in_count], in_count );
        in_count++;
    }

    dsl_htable.m_replace( ach_test[0], 234 );

    dsl_htable.m_get( "MMM", &in_count );
#endif // HASHTABLE_TEST

#if 0
    char* ach_header = "HTTP/1.0 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n";
    char* ach_data   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\r\n";

    ads_wsp_helper->m_send_data( ach_header, strlen(ach_header) );

    for ( int in_1 = 0; in_1 < 1000; in_1++ ) {
        ads_wsp_helper->m_send_data( ach_data, strlen(ach_data) );
    }

    //ads_wsp_helper->m_return_close();
#endif

#define SDH_ECHO
#ifdef SDH_ECHO
    char* ach_header = "HTTP/1.0 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n";

    struct dsd_gather_i_1 *adsl_input;
    adsl_input = ads_wsp_helper->m_get_input(); // get the input

    ads_wsp_helper->m_send_data( ach_header, strlen(ach_header) );

    while ( adsl_input ) {
        ads_wsp_helper->m_send_data ( adsl_input->achc_ginp_cur,                //data to send
                (int)(adsl_input->achc_ginp_end - adsl_input->achc_ginp_cur) );  //length of data
        adsl_input->achc_ginp_cur = adsl_input->achc_ginp_end;
        adsl_input = adsl_input->adsc_next;
    }
    
#endif
   
    in_offset = in_length; // just temp!

    //---------------------------------------------
    // mark data as processed until offset:
    //---------------------------------------------
#ifndef SDH_ECHO
    ads_wsp_helper->m_mark_processed( ads_gather, &in_offset, &in_length ); //comment not for ECHO, cause the data already marked there
#endif

    return true;
} // end of ds_example::m_handle_data

