/*+---------------------------------------------------------------------+*/
/*| Defines:                                                            |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| Includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#ifdef HL_UNIX
#include <hob-unix01.h>
#include <ctype.h>
#else // windows
#include <windows.h>
#endif //HL_UNIX
#include <ds_wsp_helper.h>
#include "../sdh_hobphone2.h"
#include "ds_config.h"
#ifndef HOB_XSLUNIC1_H
	#define HOB_XSLUNIC1_H
	#include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H
#include <xercesc/dom/DOMNode.hpp>
#include "align.h"

/*+---------------------------------------------------------------------+*/
/*| configuration nodes (corresponding to the enum)                     |*/
/*+---------------------------------------------------------------------+*/
static const dsd_const_string achr_conf_nodes[] = {
    "log",
    "enable",
    "file",
    "level",
    "use-UDP-gw-name",
    "UDP-gate-timeout-ms",
    "UDP-gate-keepalive-sec",
    "addressbook",
    "name",
    "type",
    "url",
    "authentication-mode",
    "username",
    "connection-mode",
    "gate-url",
    "gate-username",
    "domain",
    "TCP-keepalive-ms",
    "TCP-keepalive-client-ms",
    "allow-local-password",
    "qualify-reply",
    "SIP-auto-reply",
    "disconnect-timeout-sec",
    "client-timeout-priority"
};

static const dsd_const_string achr_conf_sipautoreply[] = {
    "OPTIONS",
    "NOTIFY"
};


/*+---------------------------------------------------------------------+*/
/*| constructor:                                                        |*/
/*+---------------------------------------------------------------------+*/
ds_config::ds_config( ds_wsp_helper* ads_wsp_helper_in ) 
: ads_wsp_helper(ads_wsp_helper_in), in_offset(0)
{
    ds_conf.ach_udp_gw_name = NULL;
    ds_conf.im_udp_gw_name_len = 0;
    ds_conf.il_udp_gate_timeout = 3000;
    ds_conf.im_udp_gate_keepalive = 10;
    ds_conf.ads_addressbook_config = NULL;
    ds_conf.im_tcp_keepalive = 0;    
    ds_conf.bo_allowlocalpass = false;
    ds_conf.bo_qualifyreply = false;
    ds_conf.bo_notifyreply = false;
    ds_conf.bo_sipautoreply = false;
    ds_conf.im_reload_timeout = 0;
    ds_conf.bo_client_timeout_priority = true;
    m_set_defaults();
}


/*+---------------------------------------------------------------------+*/
/*| destructor:                                                         |*/
/*+---------------------------------------------------------------------+*/
ds_config::~ds_config()
{
}

/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
* function ds_config::m_read_config
* read configuration with xerces from wsp.xml file
*
* @return      BOOL                        TRUE = success
*/
BOOL ds_config::m_read_config()
{
    // initialize some variables:
    BOOL            bo_ret;             // return value
    DOMNode*        ads_pnode;          // parent working node
    DOMNode*        ads_cnode;          // child working node
    const HL_WCHAR* aw_node;            // node name
    ied_conf_nodes  ien_key;            // node key
    //
    ads_pnode = ads_wsp_helper->m_cb_get_confsection();
    
    while ( ads_pnode != NULL ) {
        // check if we have an nonempty node:
        if ( ads_wsp_helper->m_cb_get_node_type( ads_pnode ) == DOMNode::ELEMENT_NODE ) {
            // get node name:
            aw_node = ads_wsp_helper->m_cb_get_node_name( ads_pnode );
            // get child node and check it:
            ads_cnode = ads_wsp_helper->m_cb_get_firstchild( ads_pnode );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                ads_pnode = ads_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }        
            // check if this node is a known one:
            ien_key = m_get_node_key( aw_node );
            switch ( ien_key ) {
                // allowed nodes in main node:
                case ien_cnode_log:
                    bo_ret = m_read_log( ads_cnode );
                    if ( bo_ret == FALSE ) {
                        ads_wsp_helper->m_cb_printf_out( SDH_ERROR(5), "read log conf failed - no memory left?" );
                        return FALSE;
                    }
                    break;
                case ien_cnode_udp_gw_name:
                    {
                        // first check whether we already have a valid name
                        if (ds_conf.ach_udp_gw_name != NULL && ds_conf.im_udp_gw_name_len != 0) {
                            ads_wsp_helper->m_cb_printf_out( SDH_WARN(23), "multiple udp gws defined - first one used");
                            break;
                        }
                        // get the node value
                        const HL_WCHAR *awst_gw_name = ads_wsp_helper->m_cb_get_node_value(ads_pnode);
                        // prepare utf8 storage
                        char *ach_gw_name = ads_wsp_helper->m_cb_get_memory(im_max_udp_gatway_name_length, TRUE);
                        // prepare length
                        int im_gw_name_length = 0;
                        // if set, convert to utf8
                        if (awst_gw_name != NULL) {
                            im_gw_name_length = m_u8l_from_u16z(ach_gw_name, im_max_udp_gatway_name_length, awst_gw_name);
                        }
                        ds_conf.ach_udp_gw_name = ach_gw_name;
                        ds_conf.im_udp_gw_name_len = im_gw_name_length;
                    }
                    break;
                case ien_cnode_udp_gate_timeout:
                    {
                        const HL_WCHAR *awst_value = ads_wsp_helper->m_cb_get_node_value(ads_pnode);
                        const int im_buffer_length = 255;
                        char chr_buffer[im_buffer_length];
                        int im_value_length = 0; //initialise value or we can get an access violation if awst_value == NULL
                        if (awst_value != NULL) {
                            im_value_length = m_u8l_from_u16z(chr_buffer, im_buffer_length, awst_value);
                        }
                        chr_buffer[im_value_length] = 0;
                        sscanf(chr_buffer, "%lu", &ds_conf.il_udp_gate_timeout);
                    }
                    break;
                case ien_cnode_udp_gate_keepalive:
                    {
                        const HL_WCHAR *awst_value = ads_wsp_helper->m_cb_get_node_value(ads_pnode);
                        const int im_buffer_length = 255;
                        char chr_buffer[im_buffer_length];
                        int im_value_length = 0;
                        if (awst_value != NULL) {
                            im_value_length = m_u8l_from_u16z(chr_buffer, im_buffer_length, awst_value);
                        }
                        chr_buffer[im_value_length] = 0;
                        sscanf(chr_buffer, "%ld", &ds_conf.im_udp_gate_keepalive);
                    }
                    break;
                case ien_cnode_addressbook:
                    bo_ret = m_read_addressbook( ads_cnode );
                    if ( bo_ret == FALSE ) {
                        ads_wsp_helper->m_cb_printf_out( SDH_ERROR(5), "read addressbook conf failed - no memory left?" );
                        return FALSE;
                    }
                    break;
                case ien_cnode_tcpkeepalive:
                     {
                        const HL_WCHAR *awst_value = ads_wsp_helper->m_cb_get_node_value(ads_pnode);
                        const int im_buffer_length = 255;
                        char chr_buffer[im_buffer_length];
                        int im_value_length = 0;
                        if (awst_value != NULL) {
                            im_value_length = m_u8l_from_u16z(chr_buffer, im_buffer_length, awst_value);
                        }
                        chr_buffer[im_value_length] = 0;
                        sscanf(chr_buffer, "%ld", &ds_conf.im_tcp_keepalive);
                    }
                    break;
                case ien_cnode_allowpasswordsave:
                    {
                        ds_conf.bo_allowlocalpass = FALSE;
                        const HL_WCHAR *awst_value = ads_wsp_helper->m_cb_get_node_value(ads_pnode);
                        int inl1;

                        BOOL bol1 = m_cmpi_u16z_u8l( &inl1, awst_value, "yes",3 );
                        if ((bol1) && (inl1 == 0)) {   /* strings are equal       */
                            ds_conf.bo_allowlocalpass = TRUE;
                        }
                    }
                    break;
                case ien_cnode_qualifyreply:
                    {
                        ds_conf.bo_qualifyreply = false;
                        const HL_WCHAR *awst_value = ads_wsp_helper->m_cb_get_node_value(ads_pnode);
                        int inl1;
                        BOOL bol1 = m_cmpi_u16z_u8l( &inl1, awst_value, "yes",3 );
                        if ((bol1) && (inl1 == 0)) {   /* strings are equal       */
                            ds_conf.bo_qualifyreply = true;
                        }
                    }
                    break;
                case ien_cnode_sipautoreply:
                    {   
                        const HL_WCHAR *awst_value = ads_wsp_helper->m_cb_get_node_value(ads_pnode);
                        int inl1;
                        BOOL bol1;
                                                
                        bol1 = m_cmp_u16z_u8z( &inl1, awst_value, "OPTIONS" );
                        if ((bol1) && (inl1 == 0)) {   /* strings are equal       */
                            ds_conf.bo_qualifyreply = true;                            
                        }
                        else {
                            bol1 = m_cmp_u16z_u8z( &inl1, awst_value, "NOTIFY" );
                            if ((bol1) && (inl1 == 0)) {   /* strings are equal       */
                                ds_conf.bo_notifyreply = true;
                            }
                        }
                    }
                    break;
                case ien_cnode_reconnecttime:
                     {
                        const HL_WCHAR *awst_value = ads_wsp_helper->m_cb_get_node_value(ads_pnode);
                        const int im_buffer_length = 255;
                        char chr_buffer[im_buffer_length];
                        int im_value_length = 0;
                        if (awst_value != NULL) {
                            im_value_length = m_u8l_from_u16z(chr_buffer, im_buffer_length, awst_value);
                        }
                        chr_buffer[im_value_length] = 0;
                        sscanf(chr_buffer, "%ld", &ds_conf.im_reload_timeout);
                    }
                    break;
                case ien_cnode_timeout_client_priority:
                    {     
                        ds_conf.bo_client_timeout_priority = true;
                        const HL_WCHAR *awst_value = ads_wsp_helper->m_cb_get_node_value(ads_pnode);
                        int inl1;
                        BOOL bol1 = m_cmpi_u16z_u8l( &inl1, awst_value, "no",2 );
                        if ((bol1) && (inl1 == 0)) {   /* strings are equal       */
                            ds_conf.bo_client_timeout_priority = false;
                        }
                    }
                    break;
                // list of not allowed nodes in main node:
                case ien_cnode_enable:    
                case ien_cnode_file:            
                case ien_cnode_name:
                case ien_cnode_type:
                case ien_cnode_url:
                case ien_cnode_connection_mode:
                case ien_cnode_gate_url:
                    ads_wsp_helper->m_cb_printf_out( SDH_WARN(23), "unsupported node in main found - ignore" );
                    break;
                default:
                    ads_wsp_helper->m_cb_printf_out( SDH_WARN(24), "unknown node in config found - ignore" );
                    break;
            }
        }
        // get next node:
        ads_pnode = ads_wsp_helper->m_cb_get_nextsibling( ads_pnode );
    }

    ds_conf.bo_sipautoreply = ds_conf.bo_qualifyreply || ds_conf.bo_notifyreply;
    

    // udp gw has to be configured at this point
    if (ds_conf.ach_udp_gw_name == NULL || ds_conf.im_udp_gw_name_len == 0) {
        ads_wsp_helper->m_cb_printf_out( SDH_WARN(25), "udp gw name not configured" );
        return FALSE;
    }
    return TRUE;
} // end of ds_config::m_read_config


/**
* function ds_config::m_save_config
* write config to conf pointer
*
* @return      BOOL            TRUE = success
*/
BOOL ds_config::m_save_config()
{
    // initialize some variables:
    BOOL              bo_ret     = FALSE;    // return value
    int               in_needed  = 0;        // needed size of config
    int               in_pos     = 0;        // writting position in config
    dsd_sdh_config_t* ads_conf   = NULL;     // pointer to our config

    /*
    config will look like this
    +------------------------+--------------------- ... -+
    | struct dsd_sdh_config  | strings                   |
    +------------------------+--------------------- ... -+
    | sizeof(dsd_sdh_config) | variables                 |

    char* pointers in dsd_sdh_config will point inside 
    variable part of config
    strings in variable part are zeroterminated

    TAKE CARE: 
    ----------
    you have to ALIGN the data, if you want to use
    other things as char* pointer pointing inside 
    variable part!
    */

    // evaluate needed length:
    in_needed  =   (int)sizeof(dsd_sdh_config_t)
        + (int)strlen(ds_conf.ds_log.achc_file) + 1
        + ds_conf.im_udp_gw_name_len;
    // every addressbook config and the values contained have to be added
    dsd_sdh_addressbook_config *ads_addressbook = ds_conf.ads_addressbook_config;
    while (ads_addressbook != NULL) {
        in_needed = ALIGN_INT(in_needed);
        in_needed += sizeof(dsd_sdh_addressbook_config);
        in_needed += ads_addressbook->im_name_len;
        in_needed += ads_addressbook->im_type_len;
        in_needed += ads_addressbook->im_url_len;
        in_needed += ads_addressbook->im_authentication_mode_len;
        in_needed += ads_addressbook->im_username_len;
        in_needed += ads_addressbook->im_connection_mode_len;
        in_needed += ads_addressbook->im_gate_url_len;
        in_needed += ads_addressbook->im_gate_username_len;
        in_needed += ads_addressbook->im_domain_len;
        ads_addressbook = ads_addressbook->ads_next;
    }
    // init config storage:
    bo_ret = ads_wsp_helper->m_init_config( in_needed );
    if ( bo_ret == FALSE ) {
        return FALSE;
    }
    ads_conf = (dsd_sdh_config_t*)ads_wsp_helper->m_get_config();
    // copy structure:
    bo_ret = ads_wsp_helper->m_copy_to_config( &ds_conf, sizeof(dsd_sdh_config_t),
        &in_pos, in_needed, TRUE );
    if ( bo_ret == FALSE ) {
        return FALSE;
    }
    // copy strings and set pointers:
    const char* ach_ptr = ds_conf.ds_log.achc_file;
    int   in_len  = (int)strlen(ach_ptr) + 1; // + 1 for zero termination
    bo_ret = ads_wsp_helper->m_copy_to_config( ach_ptr, in_len,
        &in_pos, in_needed, FALSE );
    ads_conf->ds_log.achc_file = (const char*)ads_conf + (in_pos - in_len);
    if ( bo_ret == FALSE ) {
        return FALSE;
    }
    // 
    ach_ptr = ds_conf.ach_udp_gw_name;
    in_len  = ds_conf.im_udp_gw_name_len;
    bo_ret = ads_wsp_helper->m_copy_to_config( ach_ptr, in_len,
        &in_pos, in_needed, FALSE );
    char *ach_temp = ads_conf->ach_udp_gw_name;
    ads_conf->ach_udp_gw_name = (char*)ads_conf + (in_pos - in_len);
    ads_wsp_helper->m_cb_free_memory(ach_temp, im_max_udp_gatway_name_length);
    if ( bo_ret == FALSE ) {
        return FALSE;
    }
    // copy the addressbook configs
    ads_addressbook = ds_conf.ads_addressbook_config;
    // copy the reference to the first config
    if (ds_conf.ads_addressbook_config != NULL) {
        ads_conf->ads_addressbook_config = 
            reinterpret_cast<dsd_sdh_addressbook_config *>(reinterpret_cast<char *>(ads_conf) + ALIGN_INT(in_pos));
    }
    while (ads_addressbook != NULL) {
        // keep the start position;
        int im_start = ALIGN_INT(in_pos);
        in_pos = im_start;
        // copy the structure
        bo_ret = ads_wsp_helper->m_copy_to_config(
            ads_addressbook, sizeof(dsd_sdh_addressbook_config), &in_pos, in_needed, TRUE);
        // if this fails we can stop
        if (bo_ret == FALSE) {
            return FALSE;
        }
        // copy the content
        bo_ret = ads_wsp_helper->m_copy_to_config(
            ads_addressbook->ach_name, ads_addressbook->im_name_len, &in_pos, in_needed, FALSE);
        // if this fails we can stop
        if (bo_ret == FALSE) {
            return FALSE;
        }
        bo_ret = ads_wsp_helper->m_copy_to_config(
            ads_addressbook->ach_type, ads_addressbook->im_type_len, &in_pos, in_needed, FALSE);
        // if this fails we can stop
        if (bo_ret == FALSE) {
            return FALSE;
        }
        bo_ret = ads_wsp_helper->m_copy_to_config(
            ads_addressbook->ach_url, ads_addressbook->im_url_len, &in_pos, in_needed, FALSE);
        // if this fails we can stop
        if (bo_ret == FALSE) {
            return FALSE;
        }
        bo_ret = ads_wsp_helper->m_copy_to_config(
            ads_addressbook->ach_authentication_mode, ads_addressbook->im_authentication_mode_len, &in_pos, in_needed, FALSE);
        // if this fails we can stop
        if (bo_ret == FALSE) {
            return FALSE;
        }
        bo_ret = ads_wsp_helper->m_copy_to_config(
            ads_addressbook->ach_username, ads_addressbook->im_username_len, &in_pos, in_needed, FALSE);
        // if this fails we can stop
        if (bo_ret == FALSE) {
            return FALSE;
        }
        bo_ret = ads_wsp_helper->m_copy_to_config(
            ads_addressbook->ach_connection_mode, ads_addressbook->im_connection_mode_len, &in_pos, in_needed, FALSE);
        // if this fails we can stop
        if (bo_ret == FALSE) {
            return FALSE;
        }
        bo_ret = ads_wsp_helper->m_copy_to_config(
            ads_addressbook->ach_gate_url, ads_addressbook->im_gate_url_len, &in_pos, in_needed, FALSE);
        // if this fails we can stop
        if (bo_ret == FALSE) {
            return FALSE;
        }
        bo_ret = ads_wsp_helper->m_copy_to_config(
            ads_addressbook->ach_gate_username, ads_addressbook->im_gate_username_len, &in_pos, in_needed, FALSE);
        // if this fails we can stop
        if (bo_ret == FALSE) {
            return FALSE;
        }
         bo_ret = ads_wsp_helper->m_copy_to_config(
             ads_addressbook->ach_domain, ads_addressbook->im_domain_len, &in_pos, in_needed, FALSE);
        // if this fails we can stop
        if (bo_ret == FALSE) {
            return FALSE;
        }
        // adjust the pointers
        dsd_sdh_addressbook_config *ads_temp = 
            reinterpret_cast<dsd_sdh_addressbook_config *>(reinterpret_cast<char *>(ads_conf) + im_start);
        ads_temp->ach_name = reinterpret_cast<char *>(ads_temp + 1);
        ads_temp->ach_type = ads_temp->ach_name + ads_temp->im_name_len;
        ads_temp->ach_url = ads_temp->ach_type + ads_temp->im_type_len;
        ads_temp->ach_authentication_mode = ads_temp->ach_url + ads_temp->im_url_len;
        ads_temp->ach_username = ads_temp->ach_authentication_mode + ads_temp->im_authentication_mode_len;
        ads_temp->ach_connection_mode = ads_temp->ach_username + ads_temp->im_username_len;
        ads_temp->ach_gate_url = ads_temp->ach_connection_mode + ads_temp->im_connection_mode_len;
        ads_temp->ach_gate_username = ads_temp->ach_gate_url + ads_temp->im_gate_url_len;
        ads_temp->ach_domain = ads_temp->ach_gate_username + ads_temp->im_gate_username_len;
        // if more exist point to the next entry
        if (ads_addressbook->ads_next != NULL) {
            ads_temp->ads_next = 
                reinterpret_cast<dsd_sdh_addressbook_config *>(reinterpret_cast<char *>(ads_conf) + ALIGN_INT(in_pos));
        }
        ads_addressbook = ads_addressbook->ads_next;
    }
    // first the structures
    return TRUE;
} // end of ds_config::m_save_config


/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/
/**
* function ds_config::m_set_defaults
* set config to default values
*/
void ds_config::m_set_defaults()
{
    // initialize some variables:
    BOOL bo_ret;
    char rch_wsppath[_MAX_PATH];

    // get wsp path:
    bo_ret = ads_wsp_helper->m_get_wsp_path( &rch_wsppath[0], _MAX_PATH );
    if ( bo_ret == FALSE ) {
        ds_conf.ds_log.achc_file = (char*)SDH_DEF_LOG_FILE;
    } else {
        ds_conf.ds_log.achc_file = &rch_buffer[in_offset];

        memcpy( &rch_buffer[in_offset], rch_wsppath, strlen(rch_wsppath) );
        in_offset += (int)strlen(rch_wsppath);

        memcpy( &rch_buffer[in_offset], LOGFILE_PATH, strlen(LOGFILE_PATH) );
        in_offset += (int)strlen(LOGFILE_PATH);

        memcpy( &rch_buffer[in_offset], SDH_DEF_LOG_FILE, strlen(SDH_DEF_LOG_FILE) );
        in_offset += (int)strlen(SDH_DEF_LOG_FILE);

        rch_buffer[in_offset] = 0;
        in_offset++; // zero terminate
    }

    // log mode:
    ds_conf.ds_log.boc_active = FALSE;
    ds_conf.ds_log.iec_level  = ied_sdh_log_info;

    // datahook version:
    ds_conf.ds_log.achc_version = (char*)SDH_VERSION_STRING;
} // end of ds_config::m_set_defaults


/**
* function ds_config::m_conv_to_utf8
* we will hold all values in utf8 encoding (instead xerces utf16)
* so this function convertes an utf16 to utf8
*
* @param[in]   HL_WCHAR*   aw_input        input in utf16 (zero terminated)
* @param[in]   char*       ach_target      output in utf8
* @param[in]   int         in_max_len      max possible lenght of output
* @return      int                         needed length in output
*                                          -1 in error cases
*/
int ds_config::m_conv_to_utf8( const HL_WCHAR* aw_input,
                              char* ach_target, int in_max_len )
{
    // initialize some variables:
    int in_needed = 0;          // needed bytes in output
    int in_ret    = 0;          // return value for m_cpy_vx_vx call

    //-------------------------------------
    // evaluate needed size for output:
    //-------------------------------------
    in_needed = m_len_vx_vx( ied_chs_utf_8,
        aw_input, -1, ied_chs_utf_16 );
    in_needed++;  // +1 for zerotermination
    if ( in_needed > in_max_len ) {
        return -1;
    }

    //-------------------------------------
    // convert from utf16 to utf8:
    //-------------------------------------
    in_ret = m_cpy_vx_vx( ach_target, in_needed , ied_chs_utf_8,
        aw_input,   -1,         ied_chs_utf_16 );
    if ( in_ret == -1 ) {
        return -1;
    }

    return in_needed;
} // end of ds_config::m_conv_to_utf8


/**
* function ds_config::m_get_node_key
* get node key by name
*
* @param[in]   HL_WCHAR*       aw_node     node name in utf16
* @return      ied_conf_nodes              node key
*/
ied_conf_nodes ds_config::m_get_node_key( const HL_WCHAR* aw_node )
{
    dsd_unicode_string dsl_key;
    dsl_key.ac_str = (void*)aw_node;
    dsl_key.imc_len_str = -1;
    dsl_key.iec_chs_str = ied_chs_utf_16;
    return ds_wsp_helper::m_search_equals_ic2(achr_conf_nodes, dsl_key, ien_cnode_unknown);
} // end of ds_config::m_get_node_key


/**
* function ds_config::m_read_log
* read logfile config part from configuration
*
* @param[in]   DOMNode*    ads_node        first child node of log entry
* @return      BOOL                        TRUE = success
*/
BOOL ds_config::m_read_log( DOMNode* ads_node )
{
    // initialize some variables:
    DOMNode*        ads_pnode;          // parent working node
    DOMNode*        ads_cnode;          // child working node
    const HL_WCHAR* aw_node;            // node name
    const HL_WCHAR* aw_value;           // node value
    ied_conf_nodes  ien_key;            // node key
    int             in_new_offset;      // new offset in buffer

    ads_pnode = ads_node;

    while ( ads_pnode != NULL ) {
        // check if we have an nonempty node:
        if ( ads_wsp_helper->m_cb_get_node_type( ads_pnode ) == DOMNode::ELEMENT_NODE ) {
            // get node name:
            aw_node = ads_wsp_helper->m_cb_get_node_name( ads_pnode );
            // get child node and check it:
            ads_cnode = ads_wsp_helper->m_cb_get_firstchild( ads_pnode );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                ads_pnode = ads_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            if ( ads_wsp_helper->m_cb_get_node_type( ads_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                ads_pnode = ads_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            // get value of child node:
            aw_value      = ads_wsp_helper->m_cb_get_node_value( ads_cnode );
            in_new_offset = m_conv_to_utf8( aw_value, &rch_buffer[in_offset],
                SDH_CONF_MAX - in_offset );
            if ( in_new_offset == -1 ) {
                return FALSE;
            }
            dsd_const_string dsl_value(&rch_buffer[in_offset], in_new_offset-1);
            // check if this node is a known one:
            ien_key = m_get_node_key( aw_node );
            switch ( ien_key ) {
                case ien_cnode_enable:
                    ds_conf.ds_log.boc_active = m_is_on( dsl_value ) != FALSE;
                    break;
                case ien_cnode_file:
                    ds_conf.ds_log.achc_file = &rch_buffer[in_offset];
                    in_offset += in_new_offset;
                    break;
                case ien_cnode_level:
                    ds_conf.ds_log.iec_level = (ied_sdh_log_level)m_read_level( dsl_value );
                    break;
                default:
                    ads_wsp_helper->m_cb_printf_out( SDH_WARN(25), "unknown node in logconfig found - ignore" );
                    break;
            }
        }
        // get next node:
        ads_pnode = ads_wsp_helper->m_cb_get_nextsibling( ads_pnode );
    }
    // init log lock:
    if ( ds_conf.ds_log.boc_active == TRUE ) { 
#ifdef HL_UNIX
        pthread_mutex_init( &ds_conf.ds_log.dsc_lock, NULL );
#else
        InitializeCriticalSection(&ds_conf.ds_log.dsc_lock);
#endif
    }
    return TRUE;
} // end of ds_config::m_read_log

/**
* function ds_config::m_read_addressbook
* read addressbook config part from configuration
*
* @param[in]   DOMNode*    ads_node        first child node of log entry
* @return      BOOL                        TRUE = success
*/
BOOL ds_config::m_read_addressbook( DOMNode* ads_node ) {
    // initialize some variables:
    DOMNode*        ads_pnode;          // parent working node
    DOMNode*        ads_cnode;          // child working node
    const HL_WCHAR* aw_node;            // node name
    const HL_WCHAR* aw_value;           // node value
    ied_conf_nodes  ien_key;            // node key
    int             in_new_offset;      // new offset in buffer
    ads_pnode = ads_node;
    dsd_sdh_addressbook_config *ads_addressbook = NULL;
    dsd_sdh_addressbook_config **aads_anchor = &ds_conf.ads_addressbook_config;
    // find the last one
    while ((*aads_anchor) != NULL) {
        aads_anchor = &(*aads_anchor)->ads_next;
    }
    in_offset = ALIGN_INT(in_offset);
    ads_addressbook = reinterpret_cast<dsd_sdh_addressbook_config *>(rch_buffer + in_offset);
    memset(ads_addressbook, 0, sizeof(dsd_sdh_addressbook_config));
    in_offset += sizeof(dsd_sdh_addressbook_config);
    // keep the reference
    *aads_anchor = ads_addressbook;
    // now start processing;
    while ( ads_pnode != NULL ) {
        // check if we have an nonempty node:
        if ( ads_wsp_helper->m_cb_get_node_type( ads_pnode ) == DOMNode::ELEMENT_NODE ) {
            // get node name:
            aw_node = ads_wsp_helper->m_cb_get_node_name( ads_pnode );
            // get child node and check it:
            ads_cnode = ads_wsp_helper->m_cb_get_firstchild( ads_pnode );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                ads_pnode = ads_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            if ( ads_wsp_helper->m_cb_get_node_type( ads_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                ads_pnode = ads_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            // get value of child node:
            aw_value      = ads_wsp_helper->m_cb_get_node_value( ads_cnode );
            in_new_offset = m_conv_to_utf8( aw_value, &rch_buffer[in_offset],
                SDH_CONF_MAX - in_offset );
            if ( in_new_offset == -1 ) {
                return FALSE;
            }
            // check if this node is a known one:
            ien_key = m_get_node_key( aw_node );
            switch ( ien_key ) {
                case ien_cnode_name:
                    ads_addressbook->ach_name = &rch_buffer[in_offset];
                    ads_addressbook->im_name_len = in_new_offset;
                    in_offset += in_new_offset;
                    break;
                case ien_cnode_type:
                    ads_addressbook->ach_type = &rch_buffer[in_offset];
                    ads_addressbook->im_type_len = in_new_offset;
                    in_offset += in_new_offset;
                    break;
                case ien_cnode_url:
                    ads_addressbook->ach_url = &rch_buffer[in_offset];
                    ads_addressbook->im_url_len = in_new_offset;
                    in_offset += in_new_offset;
                    break;
                case ien_cnode_authentication_mode:
                    ads_addressbook->ach_authentication_mode = &rch_buffer[in_offset];
                    ads_addressbook->im_authentication_mode_len = in_new_offset;
                    in_offset += in_new_offset;
                    break;
                case ien_cnode_username:
                    ads_addressbook->ach_username = &rch_buffer[in_offset];
                    ads_addressbook->im_username_len = in_new_offset;
                    in_offset += in_new_offset;
                    break;
                case ien_cnode_connection_mode:
                    ads_addressbook->ach_connection_mode = &rch_buffer[in_offset];
                    ads_addressbook->im_connection_mode_len = in_new_offset;
                    in_offset += in_new_offset;
                    break;
                case ien_cnode_gate_url:
                    ads_addressbook->ach_gate_url = &rch_buffer[in_offset];
                    ads_addressbook->im_gate_url_len = in_new_offset;
                    in_offset += in_new_offset;
                    break;
                case ien_cnode_gate_username:
                    ads_addressbook->ach_gate_username = &rch_buffer[in_offset];
                    ads_addressbook->im_gate_username_len = in_new_offset;
                    in_offset += in_new_offset;
                    break;
                case ien_cnode_domain:
                    ads_addressbook->ach_domain = &rch_buffer[in_offset];
                    ads_addressbook->im_domain_len = in_new_offset;
                    in_offset += in_new_offset;
                    break;
                default:
                    ads_wsp_helper->m_cb_printf_out( SDH_WARN(26), "unsupported node in addressbook config found - ignore" );
                    break;
            }
        }
        // get next node:
        ads_pnode = ads_wsp_helper->m_cb_get_nextsibling( ads_pnode );
    }
    // init log lock:
    if ( ds_conf.ds_log.boc_active == TRUE ) { 
#ifdef HL_UNIX
        pthread_mutex_init( &ds_conf.ds_log.dsc_lock, NULL );
#else
        InitializeCriticalSection(&ds_conf.ds_log.dsc_lock);
#endif
    }
    return TRUE;
} // end of ds_config::m_read_log

/**
* function ds_config::m_is_on
*
* @param[in]   char*   ach_value       zero terminated value
* @return      BOOL                    TRUE  = value is on
*                                      FALSE = otherwise
*/
BOOL ds_config::m_is_on( const dsd_const_string& rdsp_value )
{
    if(rdsp_value.m_equals_ic("on"))
        return TRUE;
    if(rdsp_value.m_equals_ic("yes"))
        return TRUE;
    return FALSE;
} // end of ds_config::m_is_on


/**
* function ds_config::m_read_level
*
* @param[in]   const char* ach_vale    zero terminated value
* @return      int                     log level
*/
int ds_config::m_read_level( const dsd_const_string& rdsp_value )
{
    if(rdsp_value.m_equals(SDH_LOG_CNF_LEVEL_DETAILS))
       return ied_sdh_log_details;
    if(rdsp_value.m_equals(SDH_LOG_CNF_LEVEL_INFO))
       return ied_sdh_log_info;
    if(rdsp_value.m_equals(SDH_LOG_CNF_LEVEL_WARN))
       return ied_sdh_log_warning;
    if(rdsp_value.m_equals(SDH_LOG_CNF_LEVEL_ERROR))
       return ied_sdh_log_error;
    return ied_sdh_log_info; //default
} // end of ds_config::m_read_level
