/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#if defined WIN32 || defined WIN64
#include <windows.h>
#else
#include <sys/types.h>
#include <errno.h>
#include <hob-unix01.h>
#include <stdarg.h>
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>    // must be behind hob-xsclib01.h!!
#endif // HOB_XSLUNIC1_H
#endif


#include "socks5_entry.h"
#include <ds_hstring.h>
#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>


// JF 06.03.07
#if defined WIN32 || defined WIN64
    #if defined WIN64
        #ifdef _IA64_
            #define HL_CPUTYPE           "IPF"
        #else
            #define HL_CPUTYPE           "EM64T"
        #endif
    #else // WIN32
        #define HL_CPUTYPE           "x86"
    #endif
#else // UNIX
// under UNIX the string will be passed as pre-processor-flag HL_CPUTYPE
#endif
#ifndef HL_CPUTYPE
    #define HL_CPUTYPE           "unknown"   // default
#endif

/*+-------------------------------------------------------------------+*/
/*| header files for Server-Data-Hook.                                |*/
/*+-------------------------------------------------------------------+*/
#define DEF_HL_INCL_DOM  // important; used in xsclib01.h !!

#ifndef _HOB_XSCLIB01_H
    #define _HOB_XSCLIB01_H
    #include <hob-xsclib01.h>
#endif //_HOB_XSCLIB01_H
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H

/*+-------------------------------------------------------------------+*/
/*| C macros for Unicode / UTF-16, format of Xerces                   |*/
/*+-------------------------------------------------------------------+*/
#ifndef HL_UNIX
    #define HL_WCSLEN( p ) wcslen( (WCHAR *) p )
#else
    #define HL_WCSLEN( p ) m_len_u16z( (HL_WCHAR *) p )
#endif


struct dsd_read_log {
    bool                boc_active;         // log activated
    ds_hstring          dsc_file;           // fullpath to our logfile (zero terminated)
    ied_sdh_log_level   iec_level;          // log level
};

struct dsd_read_config {
    dsd_read_log            dsc_log;

    int         in_bytes_to_add; // length of required memory
    int         in_flags;
    //int         in_port;
    //char		rch_out_adapter_ipv4[5]; // zero-terminated
};

bool m_read_cnf_log( ds_wsp_helper* ads_wsp_helper, DOMNode* ads_node, dsd_read_config* ads_read_cfg );




/*+-------------------------------------------------------------------+*/
/*| declaration of global functions                                   |*/
/*+-------------------------------------------------------------------+*/

// subroutine to process the configuration data
extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf(struct dsd_hl_clib_dom_conf *ads_conf)
{
    if (ads_conf == NULL) { // nothing passed -> total error
        printf("HSOCE030E: no parameters passed to m_hlclib_conf()\n");
        return false;
    }

    ds_wsp_helper dsc_wsp_helper;
    dsc_wsp_helper.m_init_conf( ads_conf );

    // JF 25.01.11 If there is no configuration section, do not treat this as an error.
    struct dsd_read_config ds_read_config;
    memset(&ds_read_config, 0, sizeof(ds_read_config));

    // get pointer to starting node
    if (ads_conf->adsc_node_conf == NULL) { // there is no entry in configuration file
        dsc_wsp_helper.m_cb_print_out( "HSOCI735I: There is no configuration for Socks5 defined in configuration file" );
    }
    else {
        try {
            m_read_config_from_file_section(&ds_read_config, &dsc_wsp_helper);
        }
        catch (int in_exc) { // reading failed for some reason -> print out information
            dsc_wsp_helper.m_cb_printf_out("HSOCE031E: Invalid configuration detected: error %d.", in_exc);
            return false;
        }
        catch (ds_hstring hstr_exc) { // reading failed for some reason -> print out information
            dsc_wsp_helper.m_cb_printf_out("HSOCE032E: Invalid configuration detected: %s.", hstr_exc.m_get_ptr());
            return false;
        }
        catch (...) { // for all other exception types
            dsc_wsp_helper.m_cb_print_out("HSOCE033E: General exception during reading configuration.");                
            return false;
        }
    }

    // get memory for structure ds_my_conf
    int in_len_ds_my_conf = sizeof(struct ds_my_conf) + ds_read_config.in_bytes_to_add;
    *ads_conf->aac_conf = (void*)dsc_wsp_helper.m_cb_get_memory(in_len_ds_my_conf, true);
    if ( *ads_conf->aac_conf == NULL ) {
        dsc_wsp_helper.m_cb_print_out("HSOCE622E: DEF_AUX_MEMGET failed");        
        return false;
    }

    // write our configuration to memory
    int in_ret = m_write_config_to_memory(&ds_read_config, (char*)*ads_conf->aac_conf); 
    if (in_ret != SUCCESS) {
        dsc_wsp_helper.m_cb_printf_out("HSOCE621E: m_write_config_to_memory failed with error %d.", in_ret);        
        return false;
    }

    dsc_wsp_helper.m_cb_printf_out("HSOCI001I: SOCKS5 Server initialized (%s/%s/%s (CC))", SDH_LONGNAME, SDH_VERSION_STRING, HL_CPUTYPE);
    dsc_wsp_helper.m_cb_printf_out("HSOCI002I: Flags: %d", ((struct ds_my_conf *) *ads_conf->aac_conf)->in_flags);

    if (((struct ds_my_conf *) *ads_conf->aac_conf)->ds_logfile.boc_active) {
        dsc_wsp_helper.m_cb_printf_out("HSOCI004I: Log file: %s", ((struct ds_my_conf *) *ads_conf->aac_conf)->ds_logfile.achc_file);
    }

    return true;
}

extern "C" HL_DLL_PUBLIC void m_hlclib01(struct dsd_hl_clib_1 *ads_trans)
{
    // check validity of passed paramater
    if (ads_trans == NULL) {
        printf("HSOCE000E: ads_trans == NULL");
        return;
    }

    struct ds_manage_buf* ads_conn_memory;


    /*--------------------*/
    /* setup helper class */
    /*--------------------*/
    ds_wsp_helper dsc_wsp_helper;
    dsc_wsp_helper.m_init_trans(ads_trans);

    /*-----------------*/
    /* DEF_IFUNC_START */
    /*-----------------*/
    // acquire a piece of storage which this session can use in subsequent calls
    if (ads_trans->inc_func == DEF_IFUNC_START) {
        if (! ads_trans->amc_aux(ads_trans->vpc_userfld, DEF_AUX_MEMGET, &ads_trans->ac_ext, sizeof(ds_manage_buf))) {
            dsc_wsp_helper.m_cb_print_out("HSOCE001E: MEMGET failed");
            return;
        }
        memset(ads_trans->ac_ext, 0, sizeof(ds_manage_buf));

        ads_conn_memory = (struct ds_manage_buf *) ads_trans->ac_ext;

        // set state to STATE_NEGO_AUTH_METH (connection is just opened)
        ads_conn_memory->in_phase = PHASE_NEGO_AUTH_METH;

        dsc_wsp_helper.m_log_input();

        return;
    }

    /*-----------------*/
    /* DEF_IFUNC_CLOSE */
    /*-----------------*/
    // we must release memory that we acqired in DEF_IFUNC_START (or later)
    else if (ads_trans->inc_func == DEF_IFUNC_CLOSE) {
        ads_conn_memory = (struct ds_manage_buf *) ads_trans->ac_ext;

        dsc_wsp_helper.m_log_output();

        if (&ads_trans->ac_ext != NULL) {
            if (ads_conn_memory->cla_socks5 != NULL) {
                ads_conn_memory->cla_socks5->socks5::~socks5(); // Explicit destructor call
            }

            ads_trans->amc_aux(ads_trans->vpc_userfld, DEF_AUX_MEMFREE, &ads_trans->ac_ext, sizeof(ds_manage_buf));
        }

        // JF Ticket[21668] 11.03.11: If the server closed the connection, we close the connection to the client, too. Otherwise
        // the client will sent data on this connection to us, but we have no more a server connection -> the data get lost.
        if (ads_trans->boc_eof_server == TRUE) {
            ads_trans->inc_return = DEF_IRET_END;
        }

        return;
    }
    else {
        ads_conn_memory = (struct ds_manage_buf *) ads_trans->ac_ext;

        dsc_wsp_helper.m_log_input();
    }

    if (ads_conn_memory->cla_socks5 == NULL) {
        ads_conn_memory->cla_socks5 = new(ads_conn_memory->ch_socks5) socks5();
    }
    ads_conn_memory->cla_socks5->m_setup(&dsc_wsp_helper, ads_trans);
    ads_conn_memory->cla_socks5->Handle();

    dsc_wsp_helper.m_log_output();

    // JF Ticket[21668] 11.03.11: If the server closed the connection, we close the connection to the client, too. Otherwise
    // the client will sent data on this connection to us, but we have no more a server connection -> the data get lost.
    if (ads_trans->boc_eof_server == TRUE) {
        ads_trans->inc_return = DEF_IRET_END;
    }

    return;
}


void m_print_out_conf(struct dsd_hl_clib_dom_conf *ads_conf, char* ach_to_print)
{
   ads_conf->amc_aux( ads_conf->vpc_userfld, DEF_AUX_CONSOLE_OUT,
                                   ach_to_print, static_cast<int>(strlen(ach_to_print)) );
}


/**
 * @throws Exception
 * @return 
 */
void m_read_config_from_file_section(struct dsd_read_config* ads_ret, ds_wsp_helper* ads_wsp_helper)
{
    memset(ads_ret, 0, sizeof(dsd_read_config));

    DOMNode    *ads_curr_node;                 // node for navigation
    DOMNode    *ads_work_node;                 // node for navigation
    WCHAR      *awc_node_name;             // name of a node; 2bytes per wide-character
    WCHAR      *awc_node_value = (WCHAR *)L"";               // value of a node

    // get the first child of our configuration (using call back method)
    // our configuration are all entries inside the node <configuration-section> (located in node <server-data-hook>)
    ads_curr_node = ads_wsp_helper->m_cb_get_confsection();
    if (ads_curr_node == NULL) {
        throw ds_hstring(ads_wsp_helper, "no getFirstChild() <configuration-section>" );
    }

    // Helper variable to transform UTF16-strings (delivered by Xerces) to UTF8 (used in ds_hstring).
    struct dsd_unicode_string dsl_unicode;
    dsl_unicode.iec_chs_str = ied_chs_utf_16;
    ds_hstring hstr_name(ads_wsp_helper); // name of the xml-tag
    ds_hstring hstr_val(ads_wsp_helper);  // value inside the xml-tag
    do { // loop thru node and extract our configuration to structure
        if ( ads_wsp_helper->m_cb_get_node_type( ads_curr_node ) == DOMNode::ELEMENT_NODE ) {
            // get name of this node
            awc_node_name = (WCHAR *) ads_wsp_helper->m_cb_get_node_name( ads_curr_node );
            dsl_unicode.ac_str = awc_node_name;
            dsl_unicode.imc_len_str = HL_WCSLEN(awc_node_name);
            hstr_name.m_set(&dsl_unicode);

            ads_work_node = ads_wsp_helper->m_cb_get_firstchild( ads_curr_node );
            if (ads_work_node == NULL) {
                // Ticket[16515] we get here when a node is empty; e.g. "<address/>" or "<address></address>"
                // throw 1;
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }
            // read value for this node
            if ( ads_wsp_helper->m_cb_get_node_type( ads_work_node ) == DOMNode::TEXT_NODE ) {
                awc_node_value = (WCHAR *) ads_wsp_helper->m_cb_get_node_value( ads_work_node );
            }
            dsl_unicode.ac_str = awc_node_value;
            dsl_unicode.imc_len_str = HL_WCSLEN(awc_node_value);
            hstr_val.m_set(&dsl_unicode);

            // <flags>
            if (hstr_name.m_equals(CNF_NODE_FLAGS, true)) {
                if ( (!hstr_val.m_to_int(&ads_ret->in_flags))
                  || (ads_ret->in_flags < 0) ) {
                    throw ds_hstring(ads_wsp_helper, "Invalid xml-element <flags>");
                }
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }

            // <log>
            /* Example:
                  <log>
                    <enable>YES</enable>
                    <level>WARN</level>
                    <file>../../log/gather.txt</file>
                  </log>
            */
            if ( hstr_name.m_equals(CNF_NODE_LOG, true) ) {
                m_read_cnf_log( ads_wsp_helper, ads_wsp_helper->m_cb_get_firstchild( ads_curr_node ), ads_ret );
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }

   //         // <out-port>
			//if (hstr_name.m_equals(SOCKS_CNF_NODE_OUT_PORT, true)) {
   //             if ( (!hstr_val.m_to_int(&ads_ret->in_port))
   //               || (ads_ret->in_port < 0) ) {
   //                 throw ds_hstring(ads_wsp_helper, "Invalid xml-element <out-port>");
   //             }
   //             ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
   //             continue;
   //         }

   //         // <out-adapter-ipv4>
			//if (hstr_name.m_equals(SOCKS_CNF_NODE_OUT_ADAPTER_IPV4, true)) {
   //             // Length must be between and 7 and 15.
   //             if ( (hstr_val.m_get_len() == 0)
   //               || ( (hstr_val.m_get_len() >= 3) && (hstr_val.m_get_len() <= 15) ) ) {
   //                   // Get the single tokens of e.g. "172.22.100.2" as int 172,22,100,2. 
   //                   int in_a, in_b, in_c, in_d; 
   //                   sscanf(hstr_val.m_get_ptr(), "%d.%d.%d.%d", &in_a, &in_b, &in_c, &in_d);

   //                   // Write the char[] as hex (e.g. 0xAC 0x16 0x64 0x02) into ads_ret.
   //                   memset(&ads_ret->rch_out_adapter_ipv4[0], in_a, 1);
   //                   memset(&ads_ret->rch_out_adapter_ipv4[1], in_b, 1);
   //                   memset(&ads_ret->rch_out_adapter_ipv4[2], in_c, 1);
   //                   memset(&ads_ret->rch_out_adapter_ipv4[3], in_d, 1);
   //                   memset(&ads_ret->rch_out_adapter_ipv4[4], 0, 1); // zero-termination

   //                   ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
   //                   continue;
   //             }
   //             throw ds_hstring(ads_wsp_helper, "Invalid xml-element <out-adapter-ipv4>");
			//}

        }  // DOM node processed -> next
        ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
    } while (ads_curr_node);

        // logfile (char)
    if ( ads_ret->dsc_log.boc_active == true ) {
        int in_len_logfile = ads_ret->dsc_log.dsc_file.m_get_len();
        if (in_len_logfile == 0) {
            throw ds_hstring(ads_wsp_helper, "No LogFile specified.");
        }
        in_len_logfile++; // to become zero-terminated
        ads_ret->in_bytes_to_add += in_len_logfile;
    }

    return;
}



/**
 * function m_is_yes
 * decide if node value is yes or not
 *
 * @param[in]   ds_wsp_helper*  ads_wsp_helper  wsp helper class
 * @param[in]   DOMNode*        ads_node        first child node of log entry
 * @return      bool                            true = value equals yes
*/
bool m_is_yes( ds_wsp_helper* ads_wsp_helper, DOMNode* ads_node )
{
    // initialize some variables:
    const HL_WCHAR*  awl_value;                   // node value
    int        inl_compare = 0;             // result of compare
    BOOL       bol_ret;                     // return of compare
    
    // get node value:
    awl_value = ads_wsp_helper->m_cb_get_node_value( ads_node );

    bol_ret = m_cmpi_vx_vx( &inl_compare,
                            awl_value, -1,
                            ied_chs_utf_16,
                            (void*)"yes",
                            (int)strlen("yes"),
                            ied_chs_utf_8 );
    if ( bol_ret == TRUE && inl_compare == 0 ) {
        return true;
    }
    return false;
} // end of m_is_yes


/**
 * function m_read_log_level
 *
 * @param[in]   ds_wsp_helper*      ads_wsp_helper  wsp helper class
 * @param[in]   DOMNode*            ads_node        level node
 * @return      ied_sdh_log_level                   log level
*/
ied_sdh_log_level m_read_log_level( ds_wsp_helper* ads_wsp_helper, DOMNode* ads_node )
{
    // initialize some variables:
    const HL_WCHAR*  awl_value;                   // node value
    int        inl_compare = 0;             // result of compare
    BOOL       bol_ret;                     // return of compare

    // get node value:
    awl_value = ads_wsp_helper->m_cb_get_node_value( ads_node );

    // check if level is 'details':
    bol_ret = m_cmpi_vx_vx( &inl_compare,
                            awl_value, -1,
                            ied_chs_utf_16,
                            (void*)SDH_LOG_CNF_LEVEL_DETAILS,
                            (int)strlen(SDH_LOG_CNF_LEVEL_DETAILS),
                            ied_chs_utf_8 );
    if ( bol_ret == TRUE && inl_compare == 0 ) {
        return ied_sdh_log_details;
    }

    // check if level is 'info':
    bol_ret = m_cmpi_vx_vx( &inl_compare,
                            awl_value, -1,
                            ied_chs_utf_16,
                            (void*)SDH_LOG_CNF_LEVEL_INFO,
                            (int)strlen(SDH_LOG_CNF_LEVEL_INFO),
                            ied_chs_utf_8 );
    if ( bol_ret == TRUE && inl_compare == 0 ) {
        return ied_sdh_log_info;
    }

    // check if level is 'warning':
    bol_ret = m_cmpi_vx_vx( &inl_compare,
                            awl_value, -1,
                            ied_chs_utf_16,
                            (void*)SDH_LOG_CNF_LEVEL_WARN,
                            (int)strlen(SDH_LOG_CNF_LEVEL_WARN),
                            ied_chs_utf_8 );
    if ( bol_ret == TRUE && inl_compare == 0 ) {
        return ied_sdh_log_warning;
    }

    // check if level is 'error':
    bol_ret = m_cmpi_vx_vx( &inl_compare,
                            awl_value, -1,
                            ied_chs_utf_16,
                            (void*)SDH_LOG_CNF_LEVEL_ERROR,
                            (int)strlen(SDH_LOG_CNF_LEVEL_ERROR),
                            ied_chs_utf_8 );
    if ( bol_ret == TRUE && inl_compare == 0 ) {
        return ied_sdh_log_error;
    }

    return ied_sdh_log_info; // default
} // end of m_read_log_level

/**
 * function m_read_cnf_log
 * read logfile config part from configuration
 *
 * @param[in]   ds_wsp_helper*      ads_wsp_helper  wsp helper class
 * @param[in]   DOMNode*            ads_node        first child node of log entry
 * @param[in]   dsd_read_config*    ads_read_cfg    config read structure
 * @return      bool                                true = success
*/
bool m_read_cnf_log( ds_wsp_helper* ads_wsp_helper, DOMNode* ads_node, dsd_read_config* ads_read_cfg )
{
    // initialize some variables:
    DOMNode*            adsl_cnode;                 // child working node
    const HL_WCHAR*           awl_node;                   // node name
    dsd_unicode_string  dsl_value;                  // node value
    BOOL                bol_ret;                    // compare return
    int                 inl_compare;                // compare result
    char                chrl_wsppath[_MAX_PATH];    // wsp installation path

    //-------------------------------------------
    // set defaults:
    //-------------------------------------------
    ads_read_cfg->dsc_log.dsc_file.m_setup( ads_wsp_helper );
    ads_read_cfg->dsc_log.boc_active = false;
    ads_read_cfg->dsc_log.iec_level  = ied_sdh_log_info;

    // get install path:
    ads_read_cfg->dsc_log.dsc_file.m_setup( ads_wsp_helper );
    if ( ads_wsp_helper->m_get_wsp_path( &chrl_wsppath[0], _MAX_PATH ) == false ) {
        ads_wsp_helper->m_cb_print_out( "HSOCE201E: wsp path is too long" );
        return false;
    }
    ads_read_cfg->dsc_log.dsc_file.m_write( chrl_wsppath );
    ads_read_cfg->dsc_log.dsc_file.m_write( LOGFILE_PATH );
    ads_wsp_helper->m_mkdir( ads_read_cfg->dsc_log.dsc_file.m_get_ptr() );
    ads_read_cfg->dsc_log.dsc_file.m_write( "socks5.log" );

    
    //-------------------------------------------
    // loop through the nodes:
    //-------------------------------------------
    while ( ads_node != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( ads_wsp_helper->m_cb_get_node_type( ads_node ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            awl_node = ads_wsp_helper->m_cb_get_node_name( ads_node );

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
                continue;
            }

            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------

            // <enable>
            bol_ret = m_cmpi_vx_vx( &inl_compare,
                                    awl_node, -1,
                                    ied_chs_utf_16,
                                    (void*)CNF_NODE_LOG_ENABLE,
                                    (int)strlen(CNF_NODE_LOG_ENABLE),
                                    ied_chs_utf_8 );
            if ( bol_ret == TRUE && inl_compare == 0 ) {
                ads_read_cfg->dsc_log.boc_active = m_is_yes( ads_wsp_helper, adsl_cnode );

                ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
                continue;
            }

            // <file>
            bol_ret = m_cmpi_vx_vx( &inl_compare,
                                    awl_node, -1,
                                    ied_chs_utf_16,
                                    (void*)CNF_NODE_LOG_FILE,
                                    (int)strlen(CNF_NODE_LOG_FILE),
                                    ied_chs_utf_8 );
            if ( bol_ret == TRUE && inl_compare == 0 ) {
                dsl_value.ac_str      = (void*)ads_wsp_helper->m_cb_get_node_value( adsl_cnode );
                dsl_value.imc_len_str = -1;
                dsl_value.iec_chs_str = ied_chs_utf_16;
                ads_read_cfg->dsc_log.dsc_file.m_set( &dsl_value );

                ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
                continue;
            }

            // <level>
            bol_ret = m_cmpi_vx_vx( &inl_compare,
                                    awl_node, -1,
                                    ied_chs_utf_16,
                                    (void*)CNF_NODE_LOG_LEVEL,
                                    (int)strlen(CNF_NODE_LOG_LEVEL),
                                    ied_chs_utf_8 );
            if ( bol_ret == TRUE && inl_compare == 0 ) {
                ads_read_cfg->dsc_log.iec_level = m_read_log_level( ads_wsp_helper, adsl_cnode );

                ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
                continue;
            }
        }
        
        //---------------------------------------
        // get next node:
        //---------------------------------------
        ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
    }
    return true;
} // end of m_read_cnf_log



//-------------------------
// fill memory structure with our configuration settings
//-------------------------
int m_write_config_to_memory(struct dsd_read_config* ads_read_cfg, char* ach_cnf_buf)
{
    struct ds_my_conf* ads_config = (struct ds_my_conf*)ach_cnf_buf;
    ads_config->in_flags = ads_read_cfg->in_flags;

    char* ach_pos_dest = ach_cnf_buf;
    ach_pos_dest += sizeof(ds_my_conf);

    // logfile
    if ( ads_read_cfg->dsc_log.boc_active == true ) {
        int in_len_filename = ads_read_cfg->dsc_log.dsc_file.m_get_len();
        strncpy(ach_pos_dest, (const char*)ads_read_cfg->dsc_log.dsc_file.m_get_ptr(), in_len_filename);
        ads_config->ds_logfile.achc_file = ach_pos_dest;
        ach_pos_dest += in_len_filename + 1; // set writing position behind the terminating 0
        ads_config->ds_logfile.achc_version = (char*)SDH_VERSION_STRING;
        ads_config->ds_logfile.boc_active = ads_read_cfg->dsc_log.boc_active;
        ads_config->ds_logfile.iec_level  = ads_read_cfg->dsc_log.iec_level;
#ifdef HL_UNIX
        pthread_mutex_init( &(ads_config->ds_logfile.dsc_lock), NULL );
#else
        InitializeCriticalSection(&(ads_config->ds_logfile.dsc_lock));
#endif //WIN
    }

    return SUCCESS;    
}
