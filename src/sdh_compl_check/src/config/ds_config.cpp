/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#ifdef HL_UNIX
    #include <ctype.h>
    #include <hob-unix01.h>
#else // windows
    #include <windows.h>
#endif //HL_UNIX
#include <ds_wsp_helper.h>
#include "../sdh_compl_check.h"
#include "ds_config.h"
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H
#include <xercesc/dom/DOMNode.hpp>
#include <align.h>
#include <ds_hstring.h>

/*+---------------------------------------------------------------------+*/
/*| configuration nodes:                                                |*/
/*+---------------------------------------------------------------------+*/
static const dsd_const_string achr_conf_nodes[] = {
    /*
        log tags
    */
    "log",
    "enable",
    "file",

    /*
        compliance checks tags
    */
    "compliancelist",
    "compliancecheck",
    "name",

    /*
        supported compliance checks:
    */
    "rules",
    "integrity-check",
#if 0  // anti-split-tunnel deactivated, Jun 2017 [#49556]
    "anti-split-tunnel"
#endif
};

/*+---------------------------------------------------------------------+*/
/*| constructor:                                                        |*/
/*+---------------------------------------------------------------------+*/
ds_config::ds_config( ds_wsp_helper* ads_wsp_helper_in )
{
    ads_wsp_helper = ads_wsp_helper_in;
    in_offset      = 0;
    memset( rch_buffer, 0, SDH_CONF_MAX );
    memset( &ds_conf, 0, sizeof(dsd_sdh_config_t) );
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
    const HL_WCHAR* aw_node;            // node name
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
                ads_pnode = ads_wsp_helper->m_cb_get_nextsibling( ads_pnode );
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
                        ads_wsp_helper->m_cb_print_out( "HCOCE001E read log conf failed - no memory left?" );
                        return false;
                    }
                    break;

                case ien_cnode_checks:
                    bo_ret = m_read_checks( ads_cnode );
                    if ( bo_ret == false ) {
                        ads_wsp_helper->m_cb_print_out( "HCOCE008E reading compliance-checks failed - no memory left?" );
                        return false;
                    }
                    break;

                // list of not allowed nodes in main node:
                case ien_cnode_enable:
                case ien_cnode_file:
                    ads_wsp_helper->m_cb_print_out( "HCOCW001W unsupported node in main found - ignore" );
                    break;

                default:
                    ads_wsp_helper->m_cb_print_out( "HCOCW002W unknown node in config found - ignore" );
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
 * public function ds_config::m_save_config
 * write config to conf pointer
 *
 * @return      bool            true = success
*/
bool ds_config::m_save_config()
{
    // initialize some variables:
    bool               bo_ret;               // return value
    int                in_needed;            // needed size of config
    int                in_pos     = 0;       // writting position in config
    dsd_sdh_config_t*  ads_conf;             // pointer to our config
    dsd_compl_check*   ads_cc_tmp;
    dsd_compl_check*   ads_cc_tmp_out;

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

    // go through the list of user check entries:
    ads_cc_tmp = ds_conf.ads_check;
    while ( ads_cc_tmp != NULL ) {
        in_needed  = ALIGN_INT(in_needed);
        in_needed += (int)sizeof(dsd_compl_check);
        in_needed += ads_cc_tmp->inc_len_name;
        in_needed += ads_cc_tmp->inc_len_xml;
        ads_cc_tmp = ads_cc_tmp->adsc_next;
    }

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
    const char* ach_ptr = ds_conf.ds_log.achc_file;
    int   in_len  = (int)strlen(ach_ptr) + 1; // + 1 for zero termination
    bo_ret = ads_wsp_helper->m_copy_to_config( ach_ptr, in_len,
                                               &in_pos, in_needed, false );
    ads_conf->ds_log.achc_file = (char*)ads_conf + (in_pos - in_len);
    if ( bo_ret == false ) {
        return false;
    }

    //---------------------------------------
    // copy user compliance checks:
    //---------------------------------------
    if ( ds_conf.ads_check != NULL ) {
        ads_cc_tmp = ds_conf.ads_check;
        bo_ret     = ads_wsp_helper->m_copy_to_config( ads_cc_tmp,
                                                       (int)sizeof(dsd_compl_check),
                                                       &in_pos, in_needed, true );
        ads_cc_tmp_out = (dsd_compl_check*)((char*)ads_conf + (in_pos - (int)sizeof(dsd_compl_check)));
        if ( bo_ret == false ) {
            return false;
        }
        ads_conf->ads_check = ads_cc_tmp_out;

        do {
            // compliance check name:
            ach_ptr = ads_cc_tmp->achc_name;
            in_len  = ads_cc_tmp->inc_len_name;
            bo_ret  = ads_wsp_helper->m_copy_to_config( ach_ptr, in_len,
                                                        &in_pos, in_needed, false );
            ads_cc_tmp_out->achc_name = (char*)ads_conf + (in_pos - in_len);
            if ( bo_ret == false ) {
                return false;
            }

            // compliance check xml:
            ach_ptr = ads_cc_tmp->achc_str_xml;
            in_len  = ads_cc_tmp->inc_len_xml;
            bo_ret  = ads_wsp_helper->m_copy_to_config( ach_ptr, in_len,
                                                        &in_pos, in_needed, false );
            ads_cc_tmp_out->achc_str_xml = (char*)ads_conf + (in_pos - in_len);
            if ( bo_ret == false ) {
                return false;
            }

            if ( ads_cc_tmp->adsc_next != NULL ) {
                bo_ret = ads_wsp_helper->m_copy_to_config( ads_cc_tmp->adsc_next,
                                                           (int)sizeof(dsd_compl_check),
                                                           &in_pos, in_needed, true );
                ads_cc_tmp_out->adsc_next = (dsd_compl_check*)((char*)ads_conf + (in_pos - (int)sizeof(dsd_compl_check)));
                ads_cc_tmp_out = ads_cc_tmp_out->adsc_next;
                if ( bo_ret == false ) {
                    return false;
                }
            }
            ads_cc_tmp = ads_cc_tmp->adsc_next;
        } while ( ads_cc_tmp != NULL );
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
                             aw_input, -1,
                             ied_chs_utf_16 );
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
 * @return      bool                        true = success
*/
bool ds_config::m_read_log( DOMNode* ads_node )
{
    // initialize some variables:
    DOMNode*        ads_pnode;          // parent working node
    DOMNode*        ads_cnode;          // child working node
    const HL_WCHAR* aw_node;            // node name
    const HL_WCHAR* aw_value;           // node value
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
                ads_pnode = ads_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            if ( ads_wsp_helper->m_cb_get_node_type( ads_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                ads_pnode = ads_wsp_helper->m_cb_get_nextsibling( ads_pnode );
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
            
            dsd_const_string dsl_value(&rch_buffer[in_offset], in_new_offset-1);
            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            ien_key = m_get_node_key( aw_node );
            switch ( ien_key ) {
                case ien_cnode_enable:
                    ds_conf.ds_log.boc_active = m_is_on( dsl_value );
                    break;

                case ien_cnode_file:
                    bo_file_read = true;
                    ds_conf.ds_log.achc_file = &rch_buffer[in_offset];
                    in_offset += in_new_offset;
                    break;

                default:
                    ads_wsp_helper->m_cb_print_out( "HCOCW003W unknown node in logconfig found - ignore" );
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
bool ds_config::m_is_on( const dsd_const_string& rdsp_value )
{
    if(rdsp_value.m_equals_ic("on"))
        return true;
    if(rdsp_value.m_equals_ic("yes"))
        return true;
    return false;
} // end of ds_config::m_is_on


/**
 * private function ds_config::m_read_checks
 *
 * @param[in]   DOMNode*    ads_node
 * @return      bool                    true = success
*/
bool ds_config::m_read_checks( DOMNode* ads_node )
{
    // initialize some variables:
    DOMNode*        ads_pnode;          // parent working node
    DOMNode*        ads_cnode;          // child working node
    const HL_WCHAR* aw_node;            // node name
    ied_conf_nodes  ien_key;            // node key
    bool            bo_ret;             // return from role read in

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
                ads_pnode = ads_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            if ( ads_wsp_helper->m_cb_get_node_type( ads_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                ads_pnode = ads_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            
            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            ien_key = m_get_node_key( aw_node );
            switch ( ien_key ) {
                case ien_cnode_cc_check:
                    bo_ret = m_read_check( ads_cnode );
                    if ( bo_ret == false ) {
                        ads_wsp_helper->m_cb_print_out( "HCOCE009E reading compliance-check configuration failed!" );
                        return false;
                    }
                    break;

                default:
                    ads_wsp_helper->m_cb_print_out( "HCOCW024W unknown node in comliance-checks conf found - ignore" );
                    break;
            }
        }
        
        //---------------------------------------
        // get next node:
        //---------------------------------------
        ads_pnode = ads_wsp_helper->m_cb_get_nextsibling( ads_pnode );
    }

    return true;
} // end of ds_config::m_read_checks


/**
 * private function ds_config::m_read_check
 *
 * @param[in]   DOMNode*    ads_node
 * @return      bool                    true = success
*/
bool ds_config::m_read_check( DOMNode* ads_node )
{
    // initialize some variables:
    dsd_unicode_string dsl_name;                // node name
    DOMNode*           adsl_cnode;              // child working node
    const HL_WCHAR*    awl_value;               // node value
    ied_conf_nodes     ienl_key;                // node key
    int                inl_new_offset;          // new offset in buffer
    dsd_compl_check*   adsl_check;              // curent check
    ds_hstring         dsl_str_xml( ads_wsp_helper );

    // xerces always returns zero terminated utf 16 string:
    dsl_name.imc_len_str  = -1;
    dsl_name.iec_chs_str  = ied_chs_utf_16;

    //-------------------------------------------
    // get a buffer to fill:
    //-------------------------------------------
    // align buffer:
    inl_new_offset = ALIGN_INT(in_offset);
    adsl_check = ds_conf.ads_check;
    if ( adsl_check == NULL ) {
        ds_conf.ads_check = (dsd_compl_check*)&rch_buffer[inl_new_offset];
        adsl_check = ds_conf.ads_check;
    } else {
        while ( adsl_check->adsc_next != NULL ) {
            adsl_check = adsl_check->adsc_next;
        }
        adsl_check->adsc_next = (dsd_compl_check*)&rch_buffer[inl_new_offset];
        adsl_check = adsl_check->adsc_next;
    }
    memset( adsl_check, 0, sizeof(dsd_compl_check) );
    inl_new_offset += (int)sizeof(dsd_compl_check);
    if ( inl_new_offset > SDH_CONF_MAX ) {
        return false;
    }

    //-------------------------------------------
    // read the data:
    //-------------------------------------------    
    while ( ads_node != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( ads_wsp_helper->m_cb_get_node_type( ads_node ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            dsl_name.ac_str = (void*)ads_wsp_helper->m_cb_get_node_name( ads_node );

            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            adsl_cnode = ads_wsp_helper->m_cb_get_firstchild( ads_node );
            if ( adsl_cnode == NULL ) {
                // parent node is empty -> get next
                ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
                continue;
            }
            if ( ads_wsp_helper->m_cb_get_node_type( adsl_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
                continue;
            }
            
            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            ienl_key = m_get_node_key( (HL_WCHAR*)dsl_name.ac_str );
            switch ( ienl_key ) {
                case ien_cnode_cc_name:
                    //---------------------------
                    // get value of child node:
                    //---------------------------
                    awl_value                = ads_wsp_helper->m_cb_get_node_value( adsl_cnode );
                    adsl_check->inc_len_name = m_conv_to_utf8( awl_value, &rch_buffer[inl_new_offset],
                                                               SDH_CONF_MAX - inl_new_offset );
                    if ( adsl_check->inc_len_name == -1 ) {
                        return false;
                    }
                    adsl_check->inc_len_name--;
                    adsl_check->achc_name  = &rch_buffer[inl_new_offset];
                    inl_new_offset        += adsl_check->inc_len_name;
                    
                    //---------------------------
                    // write as xml:
                    //---------------------------
                    dsl_str_xml.m_write_xml_open_tag(dsl_name);
                    dsl_str_xml.m_write_xml_text(dsd_const_string(adsl_check->achc_name, adsl_check->inc_len_name));
                    dsl_str_xml.m_write_xml_close_tag(dsl_name);
                    break;

                case ien_cnode_cc_integrity:
                    if ( (adsl_check->inc_checks & HL_COMP_CHECK_INTEGRITY) != HL_COMP_CHECK_INTEGRITY ) {
                        dsl_str_xml.m_write_xml_open_tag(dsl_name);
                        m_node_to_string( adsl_cnode, &dsl_str_xml );
                        dsl_str_xml.m_write_xml_close_tag(dsl_name);
                        adsl_check->inc_checks |= HL_COMP_CHECK_INTEGRITY;
                    } else {
                        ads_wsp_helper->m_cb_printf_out( "HCOCW025W %.*s already found - ignored at line %d",
                                                         achr_conf_nodes[ien_cnode_cc_integrity].m_get_len(),
                                                         achr_conf_nodes[ien_cnode_cc_integrity].m_get_ptr(),
                                                         ads_wsp_helper->m_cb_get_node_line(ads_node) );
                    }
                    break;
#if 0  // anti-split-tunnel deactivated, Jun 2017 [#49556]
                case ien_cnode_cc_ast:
                    if ( (adsl_check->inc_checks & HL_COMP_CHECK_AST) != HL_COMP_CHECK_AST ) {
                        dsl_str_xml.m_write_xml_open_tag(dsl_name);
                        m_node_to_string( adsl_cnode, &dsl_str_xml );
                        dsl_str_xml.m_write_xml_close_tag(dsl_name);
                        adsl_check->inc_checks |= HL_COMP_CHECK_AST;
                    } else {
                        ads_wsp_helper->m_cb_printf_out( "HCOCW026W %.*s already found - ignored at line %d",
                                                         achr_conf_nodes[ien_cnode_cc_ast].m_get_len(),
                                                         achr_conf_nodes[ien_cnode_cc_ast].m_get_ptr(),
                                                         ads_wsp_helper->m_cb_get_node_line(ads_node) );
                    }
                    break;
#endif

                case ien_cnode_cc_rules:
                    if ( (adsl_check->inc_checks & HL_COMP_CHECK_RULE) != HL_COMP_CHECK_RULE ) {
                        dsl_str_xml.m_write_xml_open_tag(dsl_name);
                        m_node_to_string( adsl_cnode, &dsl_str_xml );
                        dsl_str_xml.m_write_xml_close_tag(dsl_name);
                        adsl_check->inc_checks |= HL_COMP_CHECK_RULE;
                    } else {
                        ads_wsp_helper->m_cb_printf_out( "HCOCW027W %.*s already found - ignored at line %d",
                                                         achr_conf_nodes[ien_cnode_cc_rules].m_get_len(),
                                                         achr_conf_nodes[ien_cnode_cc_rules].m_get_ptr(),
                                                         ads_wsp_helper->m_cb_get_node_line(ads_node) );
                    }
                    break;

                default: {
                    ds_hstring dsl_temp( ads_wsp_helper );
                    dsl_temp.m_write( &dsl_name );
                    ads_wsp_helper->m_cb_printf_out( "HCOCW004W unknown node '<%.*s>' in compliance-check conf at line %d found - ignore",
                                                     dsl_temp.m_get_len(), dsl_temp.m_get_ptr(),
                                                     ads_wsp_helper->m_cb_get_node_line(ads_node) );
                }
            }
        }

        //---------------------------------------
        // get next node:
        //---------------------------------------
        ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
    } // end of while loop

    //-------------------------------------------
    // copy xml string:
    //-------------------------------------------
    if ( inl_new_offset + dsl_str_xml.m_get_len() > SDH_CONF_MAX ) {
        return false;
    }
    memcpy( &rch_buffer[inl_new_offset], 
            dsl_str_xml.m_get_ptr(),
            dsl_str_xml.m_get_len() );
    adsl_check->achc_str_xml  = &rch_buffer[inl_new_offset];
    adsl_check->inc_len_xml   = dsl_str_xml.m_get_len();
    inl_new_offset           += dsl_str_xml.m_get_len();

    //-------------------------------------------
    // set new offset:
    //-------------------------------------------
    in_offset = inl_new_offset;
    return true;
} // end of ds_config::m_read_check


/**
 * function ds_config::m_is_yes
 * decide if node value is YES or not
 *
 * @param[in]   DOMNode*    ads_node        first child node of log entry
 * @return      bool                        true = value equals yes
*/
bool ds_config::m_is_yes( DOMNode* ads_node )
{
    // initialize some variables:
    const HL_WCHAR* aw_value;               // node value
    int        in_compare = 0;              // result of compare
    BOOL       bo_ret     = FALSE;          // return of compare
    
    // get node value:
    aw_value = ads_wsp_helper->m_cb_get_node_value( ads_node );

    bo_ret = m_cmpi_vx_vx( &in_compare,
                           aw_value, -1,
                           ied_chs_utf_16,
                           (void*)"yes",
                           (int)strlen("yes"),
                           ied_chs_utf_8 );
    if ( bo_ret == TRUE && in_compare == 0 ) {
        return true;
    }
    return false;
} // end of ds_config::m_is_yes


/**
 * private function ds_config::m_node_to_string
 * convert given xerces node to xml string
 *
 * @param[in]       DOMNode*    adsp_node   node to be converted
 * @param[in/out]   ds_hstring* adsp_xml    output string
*/
void ds_config::m_node_to_string( DOMNode* adsp_node, ds_hstring* adsp_xml )
{
    // initialize some variables:
    dsd_unicode_string dsl_name;            // node name
    dsd_unicode_string dsl_value;           // node value
    DOMNode*           adsl_cnode;          // child node

    // xerces always returns zero terminated utf 16 string:
    dsl_name.imc_len_str  = -1;
    dsl_name.iec_chs_str  = ied_chs_utf_16;
    dsl_value.imc_len_str = -1;
    dsl_value.iec_chs_str = ied_chs_utf_16;

    while ( adsp_node != NULL ) {
        if ( ads_wsp_helper->m_cb_get_node_type( adsp_node ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get child node:
            //-----------------------------------
            adsl_cnode = ads_wsp_helper->m_cb_get_firstchild( adsp_node );
            if ( adsl_cnode == NULL ) {
                // child node is empty -> read next node
                adsp_node = ads_wsp_helper->m_cb_get_nextsibling( adsp_node );
                continue;
            }

            //-----------------------------------
            // get node name:
            //-----------------------------------
            dsl_name.ac_str = (void*)ads_wsp_helper->m_cb_get_node_name( adsp_node );
            adsp_xml->m_write_xml_open_tag(dsl_name);

            if (    ads_wsp_helper->m_cb_get_nextsibling( adsl_cnode ) == NULL
                 && ads_wsp_helper->m_cb_get_node_type  ( adsl_cnode ) == DOMNode::TEXT_NODE ) {
                dsl_value.ac_str = (void*)ads_wsp_helper->m_cb_get_node_value( adsl_cnode );
                adsp_xml->m_write_xml_text( dsl_value );
            } else {
                m_node_to_string( adsl_cnode, adsp_xml );
            }
            
            adsp_xml->m_write_xml_close_tag(dsl_name);
        }
        //---------------------------------------
        // get next node:
        //---------------------------------------
        adsp_node = ads_wsp_helper->m_cb_get_nextsibling( adsp_node );
    }
} // end of ds_config::m_node_to_string
