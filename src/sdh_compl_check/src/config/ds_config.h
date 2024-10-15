#ifndef _DS_CONFIG_H
#define _DS_CONFIG_H
/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| ========                                                            |*/
/*|   ds_config                                                         |*/
/*|   read sdh configuration from wsp.xml file and save it in conf      |*/
/*|   pointer                                                           |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| =======                                                             |*/
/*|   Michael Jakobs, 2009/02/06                                        |*/
/*|                                                                     |*/
/*| Copyright:                                                          |*/
/*| ==========                                                          |*/
/*|   HOB GmbH Germany 2009                                             |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
/*
  KB advised me not to use malloc( or better DEF_AUX_MEMGET ) in read 
  config functions, because getting memory is soooo slow.
  He suggested to use a buffer from stack with 16KB or 32KB.
*/
#define SDH_CONF_MAX       16*1024     

enum ied_conf_nodes {
    ien_cnode_unknown = -1,     // unkown conf node

    /*
        log tags
    */
    ien_cnode_log     =  0,
    ien_cnode_enable      ,
    ien_cnode_file        ,

    /*
        compliance checks tags
    */
    ien_cnode_checks      ,
    ien_cnode_cc_check    ,
    ien_cnode_cc_name     ,

    /*
        supported compliance checks:
    */
    ien_cnode_cc_rules    ,
    ien_cnode_cc_integrity,
#if 0  // anti-split-tunnel deactivated, Jun 2017 [#49556]
    ien_cnode_cc_ast
#endif
};

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>

/*+---------------------------------------------------------------------+*/
/*| class definition:                                                   |*/
/*+---------------------------------------------------------------------+*/
class ds_wsp_helper;    // forward definition
class ds_hstring;       // forward definition

class ds_config {

public:
    // constructor:
    ds_config( ds_wsp_helper* ads_wsp_helper_in );

    // destructor:
    ~ds_config();

    // functions:
    bool m_read_config();
    bool m_save_config();

private:
    // variables:
    ds_wsp_helper*   ads_wsp_helper;            // wsp helper class pointer
    char             rch_buffer[SDH_CONF_MAX];  // general buffer
    int              in_offset;                 // offset in buffer
    dsd_sdh_config_t ds_conf;                   // our working copy

    // functions:
    int            m_conv_to_utf8( const HL_WCHAR* aw_input, char* ach_target, int in_max_len );
    ied_conf_nodes m_get_node_key( const HL_WCHAR* aw_node );
    bool           m_read_log    ( DOMNode* ads_node );
    bool           m_is_on       ( const dsd_const_string& rdsp_value );
    void           m_set_defaults();

    // compliance checks functions:
    bool m_read_checks( DOMNode* ads_node );
    bool m_read_check ( DOMNode* ads_node );
    bool m_is_yes     ( DOMNode* ads_node );

    void m_node_to_string( DOMNode* adsp_node, ds_hstring* adsp_xml );
};

#endif // _DS_CONFIG_H


