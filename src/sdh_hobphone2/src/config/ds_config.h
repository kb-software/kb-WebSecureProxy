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
/*|   Heino Stömmer 2010/03 based on sdh_example/ds_config.h            |*/
/*|                                                                     |*/
/*| Copyright:                                                          |*/
/*| ==========                                                          |*/
/*|   HOB GmbH Germany 2010                                             |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
/* The maximum size of the configuration */
#define SDH_CONF_MAX       16*1024     
/**
* Enum for the nodes usable in the configuration - a mapping key/node has
* to be implemented.
*/
enum ied_conf_nodes {
    ien_cnode_unknown = -1,     // unkown conf node
    ien_cnode_log     =  0,
    ien_cnode_enable,
    ien_cnode_file,
    ien_cnode_level,
    ien_cnode_udp_gw_name,
    ien_cnode_udp_gate_timeout,
    ien_cnode_udp_gate_keepalive, 
    ien_cnode_addressbook,
    ien_cnode_name,
    ien_cnode_type,
    ien_cnode_url,
    ien_cnode_authentication_mode,
    ien_cnode_username,
    ien_cnode_connection_mode,
    ien_cnode_gate_url,
    ien_cnode_gate_username,
    ien_cnode_domain,
    ien_cnode_tcpkeepalive,
    ien_cnode_tcpkeepalive_client,
    ien_cnode_allowpasswordsave,
    ien_cnode_qualifyreply,
    ien_cnode_sipautoreply,
    ien_cnode_reconnecttime,
    ien_cnode_timeout_client_priority,
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
/**
* A class abstracting the configuration and providing access to it.
* It itself holds a structure with the configuration values.
*/
class ds_config {

public:
    // constructor:
    ds_config( ds_wsp_helper* ads_wsp_helper_in );
    // destructor:
    ~ds_config();
    // functions:
    BOOL m_read_config();
    BOOL m_save_config();
private:
    // variables:
    ds_wsp_helper*   ads_wsp_helper;            // wsp helper class pointer
    char             rch_buffer[SDH_CONF_MAX];  // general buffer
    int              in_offset;                 // offset in buffer
    dsd_sdh_config_t ds_conf;                   // our working copy
    // functions:
    int             m_conv_to_utf8(const HL_WCHAR* aw_input, char* ach_target, int in_max_len );
    ied_conf_nodes  m_get_node_key(const HL_WCHAR* aw_node );
    BOOL            m_read_log( DOMNode* ads_node );
    BOOL            m_read_addressbook( DOMNode* ads_node );
    BOOL            m_is_on(  const dsd_const_string& rdsp_value );
    int             m_read_level( const dsd_const_string& rdsp_value );
    void            m_set_defaults();
};

#endif // _DS_CONFIG_H