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
    ien_cnode_log     =  0,
    ien_cnode_enable      ,
    ien_cnode_file        ,
    ien_cnode_level
};

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>
#include <ds_hstring.h>

/*+---------------------------------------------------------------------+*/
/*| class definition:                                                   |*/
/*+---------------------------------------------------------------------+*/
class ds_wsp_helper;    // forward definition

class ds_config {

public:
    // constructor:
    ds_config( ds_wsp_helper* ads_wsp_helper_in );

    // destructor:
    ~ds_config();

    // functions:
    bool m_read_config();
    bool m_save_config();

    bool m_log_enabled();

private:
    // variables:
    ds_wsp_helper*   ads_wsp_helper;            // wsp helper class pointer
    char             rch_buffer[SDH_CONF_MAX];  // general buffer
    int              in_offset;                 // offset in buffer
    dsd_sdh_config_t ds_conf;                   // our working copy

    // functions:
    int             m_conv_to_utf8( const HL_WCHAR* aw_input, char* ach_target, int in_max_len );
    ied_conf_nodes  m_get_node_key( const HL_WCHAR* aw_node );
    bool            m_read_log( DOMNode* ads_node );
    bool            m_is_on( const dsd_const_string& rdsp_value );
    int             m_read_level( const dsd_const_string& rdsp_value );
    void            m_set_defaults();
};

#endif // _DS_CONFIG_H


