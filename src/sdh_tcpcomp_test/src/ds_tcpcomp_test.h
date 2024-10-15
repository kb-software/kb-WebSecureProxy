#ifndef _DS_EXAMPLE_H
#define _DS_EXAMPLE_H

/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| ========                                                            |*/
/*|   ds_tcpcomp_test                                                   |*/
/*|   main working class for sdh_tcpcomp_test                           |*/
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
typedef struct dsd_sdh_config dsd_sdh_config_t; // forward definition

class ds_tcpcomp_test {
public:
    // constructor:
    ds_tcpcomp_test();

    // destructor:
    ~ds_tcpcomp_test();

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
    ds_wsp_helper*    ads_wsp_helper;       // wsp helper class
    dsd_sdh_config_t* ads_config;           // our configuration
    int               in_state;

    // functions:
    bool m_handle_data( struct dsd_gather_i_1* ads_gather );
    bool m_connect    ( bool bo_https, const char* ach_host, int in_port );
    bool m_close      ();
};

#endif //_DS_EXAMPLE_H
