#ifndef _DS_COMPL_CHECK_H
#define _DS_COMPL_CHECK_H

/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| ========                                                            |*/
/*|   ds_compl_check                                                    |*/
/*|   main working class for sdh_compl_check                            |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| =======                                                             |*/
/*|   Michael Jakobs Nov 2009                                           |*/
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
#include <ds_hstring.h>

/*+---------------------------------------------------------------------+*/
/*| forward definitions:                                                |*/
/*+---------------------------------------------------------------------+*/
class                           ds_wsp_helper;
class                           ds_xml;
struct                          dsd_xml_tag;
class                           ds_hstring;
class                           ds_usercma;
template <class T> class        ds_hvector;
typedef struct dsd_sdh_config   dsd_sdh_config_t;
struct                          dsd_compl_check;
struct                          dsd_role;

/*+---------------------------------------------------------------------+*/
/*| helper structures:                                                  |*/
/*+---------------------------------------------------------------------+*/
struct dsd_recbuffer {
    char*   ach_ptr;                // pointer to data
    int     in_expected;            // expected length
    int     in_received;            // received length
};

enum ied_proto_req_state {
    ied_pstate_req_unknown = -1,
    ied_pstate_req_config  =  0,
    ied_pstate_req_result      ,
    ied_pstate_req_install     ,
    ied_pstate_req_axss_ok     ,
    ied_pstate_req_axss_err
};
static const dsd_const_string achr_proto_req_states[] = {
    "GET_CONFIG",
    "RESULT",
    "INSTALL",
    "AXSS_OK",
    "AXSS_ERROR"
};
enum ied_proto_resp_state {
    ied_pstate_resp_config  =  0,
    ied_pstate_resp_ack         ,
    ied_pstate_resp_invalid
};
static const dsd_const_string achr_proto_resp_states[] = {
    "CONFIG",
    "ACK",
    "INVALID_REQUEST"
};

struct dsd_req_data {
    int                               inc_version;      // version
    ied_proto_req_state               ienc_state;       // state
    int                               inc_interval;     // axss polling interval
    const char*                             achc_cookie;      // cookie
    int                               inc_len_cookie;   // length of cookie
    const char*                             achc_msg;         // message
    int                               inc_len_msg;      // length of message
    const char*                             achc_role;        // name of selected role
    int                               inc_len_role;     // length of role
};

struct dsd_cc_to_send {
    char*                             achc_role;        // name of role
    int                               inc_len_role;     // length of role name
    dsd_compl_check*                  adsc_check;       // compliance check
};

/*+---------------------------------------------------------------------+*/
/*| protocol nodes:                                                     |*/
/*+---------------------------------------------------------------------+*/
enum ied_proto_nodes {
    ied_pnode_unknown    = -1,      // unkown protocol node
    ied_pnode_quarantine =  0,
    ied_pnode_cookie         ,
    ied_pnode_version        ,
    ied_pnode_message        ,
    ied_pnode_state          ,
    ied_pnode_interval       ,
    ied_pnode_compl_list     ,
    ied_pnode_compl_check    ,
    ied_pnode_role_name      ,
    ied_pnode_axss           ,
    ied_pnode_intervall      ,
    ied_pnode_myip4          ,
    ied_pnode_myip6
};

static const dsd_const_string achr_proto_nodes[] = {
    "quarantine",
    "cookie",
    "version",
    "message",
    "state",
    "interval",
    "compliancelist",
    "compliancecheck",
    "rolename",
    "axss",
    "interval",
    "myip4",
    "myip6"
};
static const size_t SZS_NUM_PROTO_NODES = sizeof(achr_proto_nodes)/sizeof(achr_proto_nodes[0]);

/*+---------------------------------------------------------------------+*/
/*| class definition:                                                   |*/
/*+---------------------------------------------------------------------+*/
class ds_compl_check {
public:
    // constructor:
    ds_compl_check();

    // destructor:
    ~ds_compl_check();

    // new operator:
    void* operator new(size_t, void* av_location) {
        return av_location;
    }
    // avoid warning:
    void operator delete( void*, void* ) {};

    // functions:
    void m_init( ds_wsp_helper* ads_wsp_helper_in );
    bool m_run ();

    // variables:
    void* avc_storage;                      // storage container pointer

private:
    // variables:
    ds_wsp_helper*    adsc_wsp_helper;      // wsp helper class
    dsd_sdh_config_t* adsc_config;          // our configuration
    dsd_recbuffer     dsc_xmlbuf;           // presaved data
    dsd_recbuffer     dsc_recxml;           // received xml data
    dsd_req_data      dsc_recdata;          // received parsed data
    ds_usercma        dsc_user;             // users cma
    
    // state variable:
    enum ied_sdh_pstate {
        ied_read_len,
        ied_read_xml,
        ied_handle_input
    } ienc_state;

    // functions:
    bool m_handle_data     ( struct dsd_gather_i_1* ads_gather );
    bool m_create_response ();
    bool m_get_logged_user ();
    bool m_get_checks      ( ds_hvector_btype<dsd_cc_to_send>* ads_vchecks );
    dsd_role* m_role_without_check();
    void m_print_ineta( ds_hstring* adsp_out, struct dsd_aux_query_client *adsp_client );

    // search functions:
    dsd_compl_check* m_search_check   ( const char* ach_name, int in_len );
    bool             m_save_role      ();
    void             m_set_role_checks();

    // send functions:    
    void m_send_error ( const dsd_const_string& rdsp_message );
    void m_send_checks( ds_hvector_btype<dsd_cc_to_send>* ads_vchecks );
    void m_send_ack   ( const dsd_const_string& rdsp_message );

    // xml reading functions:
    bool                m_read_xml        ( const char* ach_xml, int in_len );
    bool                m_read_compl_list ( ds_xml* ads_xml, dsd_xml_tag* ads_node );
    bool                m_read_compl_check( ds_xml* ads_xml, dsd_xml_tag* ads_node );
    ied_proto_req_state m_get_state       ( const char* ach_state, int in_len, ied_charset ien_encoding );
    ied_proto_nodes     m_get_node_key    ( const char* ach_node, int in_len_node, ied_charset ien_encoding );

    // nhasn functions:
    bool m_from_nhasn     ( int* ain_num, struct dsd_gather_i_1 * ads_gather, int* ain_offset );
    int  m_count_nhasn_len( int in_input );
};

#endif //_DS_COMPL_CHECK_H
