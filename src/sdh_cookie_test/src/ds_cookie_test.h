#ifndef _DS_EXAMPLE_H
#define _DS_EXAMPLE_H

/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| ========                                                            |*/
/*|   ds_cookie_test                                                    |*/
/*|   main working class for sdh_cookie_test                            |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| =======                                                             |*/
/*|   Michael Jakobs 2009/02/04                                         |*/
/*|                                                                     |*/
/*| Copyright:                                                          |*/
/*| ==========                                                          |*/
/*|   HOB GmbH Germany 2009                                             |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#include "./utils/ds_log_file.h"
#include <types_defines.h>
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| class definition:                                                   |*/
/*+---------------------------------------------------------------------+*/
class ds_wsp_helper;                            // forward definition
class ds_cookie_manager;                        // forward definition
class ds_ck_mgmt;                               // forward definition
typedef struct dsd_sdh_config dsd_sdh_config_t; // forward definition

class ds_cookie_test {
public:
    // constructor:
    ds_cookie_test();

    // destructor:
    ~ds_cookie_test();

    // new operator:
    void* operator new(size_t, void* av_location) {
        return av_location;
    }

    // functions:
    void m_init( ds_wsp_helper* ads_wsp_helper_in );
    bool m_run ();

    // variables:
    void* av_storage;                       // storage container pointer

private:
    // variables:
    ds_wsp_helper*        ads_wsp_helper;   // wsp helper class
    dsd_sdh_config_t*     ads_config;       // our configuration
    ds_log_file           dsc_log;          // logging class
#ifdef OLD
    ds_cookie_manager     dsc_cookies;      // cookie manager class
#else
    ds_ck_mgmt            dsc_ck_mgmt;
#endif

    // functions:
    bool m_handle_data( struct dsd_gather_i_1* ads_gather );
};

#endif //_DS_EXAMPLE_H
