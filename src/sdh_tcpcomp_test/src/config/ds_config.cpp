/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#ifdef HL_UNIX
#else // windows
    #include <windows.h>
#endif //HL_UNIX
#include <ds_wsp_helper.h>
#include "../sdh_tcpcomp_test.h"
#include "ds_config.h"
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H
#include <xercesc/parsers/AbstractDOMParser.hpp>
#include <xercesc/dom/DOMImplementation.hpp>
#include <xercesc/dom/DOMImplementationLS.hpp>
#include <xercesc/dom/DOMImplementationRegistry.hpp>
#include <xercesc/dom/DOMBuilder.hpp>
#include <xercesc/dom/DOMException.hpp>
#include <xercesc/dom/DOMDocument.hpp>
#include <xercesc/dom/DOMNodeList.hpp>
#include <xercesc/dom/DOMError.hpp>

/*+---------------------------------------------------------------------+*/
/*| configuration nodes:                                                |*/
/*+---------------------------------------------------------------------+*/
const char* achr_conf_nodes[] = {
    "log"       , "enable"     , "file"        ,
    NULL
};

/*+---------------------------------------------------------------------+*/
/*| constructor:                                                        |*/
/*+---------------------------------------------------------------------+*/
ds_config::ds_config( ds_wsp_helper* ads_wsp_helper_in )
{
    ads_wsp_helper = ads_wsp_helper_in;
    in_offset      = 0;
    m_set_defaults();
} // end of ds_config::ds_config


/*+---------------------------------------------------------------------+*/
/*| destructor:                                                         |*/
/*+---------------------------------------------------------------------+*/
ds_config::~ds_config()
{
} // end of ds_config::~ds_config


/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_config::m_read_config
 * read configuration with xerces from wsp.xml file
 *
 * @return      bool                        true = success
*/
bool ds_config::m_read_config()
{
    // initialize some variables:
    bool            bo_ret;             // return value
    DOMNode*        ads_pnode;          // parent working node
    DOMNode*        ads_cnode;          // child working node
    HL_WCHAR*       aw_node;            // node name
    ied_conf_nodes  ien_key;            // node key

    ads_pnode = ads_wsp_helper->m_cb_get_confsection();
    while ( ads_pnode != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( ads_wsp_helper->m_cb_get_node_type( ads_pnode ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            aw_node = ads_wsp_helper->m_cb_get_node_name( ads_pnode );

            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            ads_cnode = ads_wsp_helper->m_cb_get_firstchild( ads_pnode );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                continue;
            }
            
            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            ien_key = m_get_node_key( aw_node );
            switch ( ien_key ) {
                // allowed nodes in main node:
                case ien_cnode_log:
                    bo_ret = m_read_log( ads_cnode );
                    if ( bo_ret == false ) {
                        ads_wsp_helper->m_cb_printf_out( SDH_ERROR(5), "read log conf failed - no memory left?" );
                        return false;
                    }
                    break;

                // list of not allowed nodes in main node:
                case ien_cnode_enable:
                case ien_cnode_file:
                    ads_wsp_helper->m_cb_printf_out( SDH_WARN(23), "unsupported node in main found - ignore" );
                    break;

                default:
                    ads_wsp_helper->m_cb_printf_out( SDH_WARN(24), "unknown node in config found - ignore" );
                    break;
            }
        }

        
        //---------------------------------------
        // get next node:
        //---------------------------------------
        ads_pnode = ads_wsp_helper->m_cb_get_nextsibling( ads_pnode );
    }

    return true;
} // end of ds_config::m_read_config


/**
 * function ds_config::m_save_config
 * write config to conf pointer
 *
 * @return      bool            true = success
*/
bool ds_config::m_save_config()
{
    // initialize some variables:
    bool              bo_ret     = false;    // return value
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

    //----------------------------------------
    // evaluate needed length:
    //----------------------------------------
    in_needed  =   (int)sizeof(dsd_sdh_config_t)
                 + (int)strlen(ds_conf.ds_log.achc_file) + 1;

    //----------------------------------------
    // init config storage:
    //----------------------------------------
    bo_ret = ads_wsp_helper->m_init_config( in_needed );
    if ( bo_ret == false ) {
        return false;
    }
    ads_conf = (dsd_sdh_config_t*)ads_wsp_helper->m_get_config();

    //---------------------------------------
    // copy structure:
    //---------------------------------------
    bo_ret = ads_wsp_helper->m_copy_to_config( &ds_conf, sizeof(dsd_sdh_config_t),
                                               &in_pos, in_needed, false );
    if ( bo_ret == false ) {
        return false;
    }

    //---------------------------------------
    // copy strings and set pointers:
    //---------------------------------------
    char* ach_ptr = ds_conf.ds_log.achc_file;
    int   in_len  = (int)strlen(ach_ptr) + 1; // + 1 for zero termination
    bo_ret = ads_wsp_helper->m_copy_to_config( ach_ptr, in_len,
                                               &in_pos, in_needed, false );
    ads_conf->ds_log.achc_file = (char*)ads_conf + (in_pos - in_len);
    if ( bo_ret == false ) {
        return false;
    }

    return true;
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
    bool bo_ret;
    char rch_wsppath[_MAX_PATH];


    // get wsp path:
    bo_ret = ads_wsp_helper->m_get_wsp_path( &rch_wsppath[0], _MAX_PATH );
    if ( bo_ret == false ) {
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
    ds_conf.ds_log.boc_active = false;

    // datahook version:
    ds_conf.ds_log.achc_version = SDH_VERSION;
} // end of ds_config::m_set_defaults


/**
 * function ds_config::m_conv_to_utf8
 * we will hold all values in utf8 encoding (instead xerces utf16)
 * so this function convertes an utf16 to utf8
 *
 * @param[in]   HL_WCHAR*   aw_input        input in utf16
 * @param[in]   char*       ach_target      output in utf8
 * @param[in]   int         in_max_len      max possible lenght of output
 * @return      int                         needed length in output
 *                                          -1 in error cases
*/
int ds_config::m_conv_to_utf8( HL_WCHAR* aw_input,
                               char* ach_target, int in_max_len )
{
    // initialize some variables:
    int in_needed = 0;          // needed bytes in output
    int in_ret    = 0;          // return value for m_cpy_vx_vx call

    //-------------------------------------
    // evaluate needed size for output:
    //-------------------------------------
    in_needed = m_len_vx_vx( ied_chs_utf_8,
                             aw_input, m_get_wc_number( aw_input ),
                             ied_chs_utf_16 );
    in_needed++;  // +1 for zerotermination
    if ( in_needed > in_max_len ) {
        return -1;
    }

    //-------------------------------------
    // convert from utf16 to utf8:
    //-------------------------------------
    in_ret = m_cpy_vx_vx( ach_target, in_needed , ied_chs_utf_8,
                          aw_input, m_get_wc_number( aw_input ),
                          ied_chs_utf_16 );
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
ied_conf_nodes ds_config::m_get_node_key( HL_WCHAR* aw_node )
{
    // initialize some variables:
    ied_conf_nodes ien_key    = ien_cnode_unknown;  // return value
    int            in_compare = 0;                  // result of compare
    BOOL           bo_ret     = FALSE;              // return of compare
    int            in_element = 0;                  // element in achr_conf_nodes


    while ( achr_conf_nodes[in_element] != NULL ) {
        bo_ret = m_cmpi_vx_vx( &in_compare,
                               aw_node, -1,
                               ied_chs_utf_16,
                               (void*)achr_conf_nodes[in_element],
                               (int)strlen(achr_conf_nodes[in_element]),
                               ied_chs_utf_8 );

        if ( bo_ret == TRUE && in_compare == 0 ) {
            // we found an known node
            ien_key = (ied_conf_nodes)in_element;
            break;
        }
        in_element++;
    }

    return ien_key;
} // end of ds_config::m_get_node_key


/**
 * function ds_config::m_read_log
 * read logfile config part from configuration
 *
 * @param[in]   DOMNode*    ads_node        first child node of log entry
 * @return      bool                        true = success
*/
bool ds_config::m_read_log( DOMNode* ads_node )
{
    // initialize some variables:
    DOMNode*        ads_pnode;          // parent working node
    DOMNode*        ads_cnode;          // child working node
    HL_WCHAR*       aw_node;            // node name
    HL_WCHAR*       aw_value;           // node value
    ied_conf_nodes  ien_key;            // node key
    int             in_new_offset;      // new offset in buffer
    bool            bo_file_read = false;

    ads_pnode = ads_node;
    
    while ( ads_pnode != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( ads_wsp_helper->m_cb_get_node_type( ads_pnode ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            aw_node = ads_wsp_helper->m_cb_get_node_name( ads_pnode );

            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            ads_cnode = ads_wsp_helper->m_cb_get_firstchild( ads_pnode );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                continue;
            }
            if ( ads_wsp_helper->m_cb_get_node_type( ads_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                continue;
            }

            //-----------------------------------
            // get value of child node:
            //-----------------------------------
            aw_value      = ads_wsp_helper->m_cb_get_node_value( ads_cnode );
            in_new_offset = m_conv_to_utf8( aw_value, &rch_buffer[in_offset],
                                            SDH_CONF_MAX - in_offset );
            if ( in_new_offset == -1 ) {
                return false;
            }
            
            
            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            ien_key = m_get_node_key( aw_node );
            switch ( ien_key ) {
                case ien_cnode_enable:
                    ds_conf.ds_log.boc_active = m_is_on( &rch_buffer[in_offset] );
                    break;

                case ien_cnode_file:
                    bo_file_read = true;
                    ds_conf.ds_log.achc_file = &rch_buffer[in_offset];
                    in_offset += in_new_offset;
                    break;

                default:
                    ads_wsp_helper->m_cb_printf_out( SDH_WARN(25), "unknown node in logconfig found - ignore" );
                    break;
            }
        }

        
        //---------------------------------------
        // get next node:
        //---------------------------------------
        ads_pnode = ads_wsp_helper->m_cb_get_nextsibling( ads_pnode );
    }

    //------------------------------------------
    // init log lock:
    //------------------------------------------
    if ( ds_conf.ds_log.boc_active == true ) { 
#ifdef HL_UNIX
        pthread_mutex_init( &ds_conf.ds_log.dsc_lock, NULL );
#else
        InitializeCriticalSection(&ds_conf.ds_log.dsc_lock);
#endif
    }

    return true;
} // end of ds_config::m_read_log


/**
 * function ds_config::m_is_on
 *
 * @param[in]   char*   ach_value       zero terminated value
 * @return      bool                    true  = value is on
 *                                      false = otherwise
*/
bool ds_config::m_is_on( char* ach_value )
{
    if (    (int)strlen(ach_value) == 2
         && (char)tolower(ach_value[0]) == 'o'
         && (char)tolower(ach_value[1]) == 'n') {
        return true;
    }

    if (    (int)strlen(ach_value) == 3
         && (char)tolower(ach_value[0]) == 'y'
         && (char)tolower(ach_value[1]) == 'e'
         && (char)tolower(ach_value[2]) == 's') {
        return true;
    }
    return false;
} // end of ds_config::m_is_on
