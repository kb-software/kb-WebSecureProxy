#ifdef HL_UNIX
    #include <sys/types.h>
    #include <errno.h>
    #include <stdarg.h>
    #include <hob-unix01.h>
    #ifndef HOB_XSLUNIC1_H
        #define HOB_XSLUNIC1_H
        #include <hob-xslunic1.h>
    #endif // HOB_XSLUNIC1_H
#endif

// ohne diesen include kommen warning/error unter AIX; vielleicht kann er auf anderen System weggelassen werden ???...
#if defined HL_AIX
    #include "HLTABAW2.h"
#endif

// avoid warnings while building for arm-processor:
#ifndef HL_LINUX_ARM
    #define DOM_CAST long long
#else
    #define DOM_CAST int
#endif
#include "ds_session.h"
#include <new>

/*+-------------------------------------------------------------------+*/
/*| System and library header files for XERCES.                       |*/
/*+-------------------------------------------------------------------+*/
#include <xercesc/dom/DOMNode.hpp>


/*+-------------------------------------------------------------------+*/
/*| header files for Server-Data-Hook.                                |*/
/*+-------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>
#include <ds_xml.h>
#include "./config/ds_ppp_tunnel.h"
#include "./config/ds_virtual_link.h"

#ifndef _HOB_AVL03_H
    #define _HOB_AVL03_H
    #include <hob-avl03.h>
#endif //_HOB_AVL03_H
#include <ds_resource.h>

#define DEF_HL_INCL_DOM  // important; used in hob-xsclib01.h !!
// MJ 05.05.09:
#ifndef _HOB_XSCLIB01_H
    #define _HOB_XSCLIB01_H
    #include <hob-xsclib01.h>
#endif //_HOB_XSCLIB01_H

#include "sdh_web_server.h"
#include "./utils/helper.h"
#include "rdvpn_globals.h"
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H


#ifdef HL_UNIX  // in case of unix we need conversion methods (for e.g. wtoi)
#include <hob-unix01.h>
#endif // #ifdef HL_UNIX

#include "dsd_srv_list.h"


/*+-------------------------------------------------------------------+*/
/*| C macros for Unicode / UTF-16, format of Xerces                   |*/
/*+-------------------------------------------------------------------+*/
#ifndef HL_UNIX
    #define HL_WCSLEN( p ) wcslen( (WCHAR *) p )
#else
    #define HL_WCSLEN( p ) m_len_u16z( p )
#endif

// JF 07.02.08 compiler complains about DOMNode, when this is in sdh_web_server.h!!
int m_read_page(ds_page& dsl_page, DOMNode* ads_node_page, ds_wsp_helper* ads_wsp_helper);
int m_read_id_list(ds_page& dsl_page, DOMNode* ads_node_idlist, ds_wsp_helper* ads_wsp_helper);
int m_read_id(ds_id& dsl_id, DOMNode* ads_node_action, ds_wsp_helper* ads_wsp_helper);
int m_read_virtual_link(dsd_read_config* ads_ret, DOMNode* ads_node_in, ds_wsp_helper* ads_wsp_helper);

int m_store_virtual_links (struct dsd_read_config* adsl_read_cfg, ds_wsp_helper* ads_helper, int* ain_pos,
                char* ach_cnf_buf, int in_len_cnf_buf); // JF 06.08.10 Ticket[20401]
int m_store_pppt      (struct dsd_read_config* adsl_read_cfg, ds_wsp_helper* ads_helper, int* ain_pos, char* ach_cnf_buf, int in_len_cnf_buf); // JF 06.07.10
int m_store_sso(struct dsd_read_config* adsl_read_cfg, ds_wsp_helper* ads_helper, int* ain_pos, char* ach_cnf_buf, int in_len_cnf_buf);
int m_store_precomp(struct dsd_read_config* adsl_read_cfg, ds_wsp_helper* ads_helper, int* ain_pos, char* ach_cnf_buf, int in_len_cnf_buf);

// Ticket[14387]
int m_read_sett_precomp(struct dsd_read_config* ads_ret, DOMNode* ads_node_settprecomp, ds_wsp_helper* ads_wsp_helper);
static bool m_read_system_parameters(DOMNode* ads_node_system_parameters, ds_wsp_helper* ads_wsp_helper, ds_hstring& hstr_ret); // Ticket[17719]
int m_read_extensions(struct dsd_read_config* ads_ret, DOMNode* ads_node_extensions, ds_wsp_helper* ads_wsp_helper);
int m_read_ext(ds_hstring* ahstr_ext, DOMNode* ads_node_in, ds_wsp_helper* ads_wsp_helper);
int m_read_files(struct dsd_read_config* ads_ret, DOMNode* ads_node_files, ds_wsp_helper* ads_wsp_helper);
int m_read_file(ds_hstring* ahstr_file, DOMNode* ads_node_in, ds_wsp_helper* ads_wsp_helper);

bool m_read_cnf_log( ds_wsp_helper* ads_wsp_helper, DOMNode* ads_node, dsd_read_config* ads_read_cfg );

bool m_validate_ppp_address(const dsd_const_string& ach_address);

static BOOL m_read_ws_srv_lst( struct dsd_read_config *adsp_config, DOMNode *adsp_node, ds_wsp_helper *adsp_wsp_helper );
static BOOL m_write_ws_srv_lst( struct dsd_read_config *adsp_config, char *achp_config, int inp_length, int *ainp_pos, ds_wsp_helper *adsp_wsp_helper );
static BOOL m_write_ica_pages( struct dsd_read_config *adsp_config, char *achp_config, int inp_length, int *ainp_pos );

static void m_read_config_from_file_section(struct dsd_read_config* ads_read_config, ds_wsp_helper* ads_wsp_helper);
static int m_calculate_config_size(struct dsd_read_config* ads_ret, ds_wsp_helper* ads_wsp_helper);

/*! \brief Logfile reader
 *
 * @ingroup webserver
 *
 *  Information about the logfile and the loglevel
 */
struct dsd_read_log {
    bool                boc_active;         //!< log activated
    ds_hstring          dsc_file;           //!< fullpath to our logfile (zero terminated)
    ied_sdh_log_level   iec_level;          //!< log level
};


/*
	hofmants: struct for saving webterm server entries
	DEBUG! Do not feed!
	TODO: dynamic, maybe class
*/
#define MAX_WT_LEN 256
struct dsd_webterm_server_entry
{
	char	chrc_name[MAX_WT_LEN];
	int		inc_len_name;
	char	chrc_protocol[MAX_WT_LEN];
	int		inc_len_protocol;
    char	chrc_session[MAX_WT_LEN];
	int		inc_len_session;
    ied_webterm_subprotocol iec_subprotocol;
    ied_webterm_protogroup iec_protogroup;
};

struct dsd_webterm_subprotocol_map1 {
    dsd_unicode_string dsc_name;
    ied_webterm_subprotocol iec_subprotocol;
    ied_webterm_protogroup iec_protogroup;
};

#define HL_DEF_UNICODE_STRING(x) (void*)x, sizeof(x)-1, ied_chs_utf_8

static const dsd_webterm_subprotocol_map1 DSS_WEBTERM_SUBPROTOCOLS[] = {
    { { HL_DEF_UNICODE_STRING("RDP") }, ied_webterm_subprotocol_rdp, ied_webterm_protogroup_rdp },
#if BO_SSH2_CONFIG
    { { HL_DEF_UNICODE_STRING("SSH") }, ied_webterm_subprotocol_ssh, ied_webterm_protogroup_ssh2 },
#else
    { { HL_DEF_UNICODE_STRING("SSH") }, ied_webterm_subprotocol_ssh, ied_webterm_protogroup_ssh },  
#endif
    { { HL_DEF_UNICODE_STRING("VT525") }, ied_webterm_subprotocol_vt525, ied_webterm_protogroup_ssh },
    { { HL_DEF_UNICODE_STRING("TN3270") }, ied_webterm_subprotocol_tn3270, ied_webterm_protogroup_ssh },
    { { HL_DEF_UNICODE_STRING("TN5250") }, ied_webterm_subprotocol_tn5250, ied_webterm_protogroup_ssh },
#if BO_HOBTE_CONFIG
    { { HL_DEF_UNICODE_STRING("TEDEFAULT") }, ied_webterm_subprotocol_unknown, ied_webterm_protogroup_te_default }
#endif
};
static const size_t IMS_NUM_WEBTERM_SUBPROTOCOLS = sizeof(DSS_WEBTERM_SUBPROTOCOLS)/sizeof(DSS_WEBTERM_SUBPROTOCOLS[0]);

/*! \brief Configuration Reader
 *
 * @ingroup webserver
 *
 *  WebServer Configuration Structure
 */
struct dsd_read_config { 
    dsd_read_log            dsc_log;

    ds_hvector<ds_ppp_tunnel>   ds_v_ppp_tunnels;   // JF 06.07.10 Ticket[20231]
    ds_hvector<ds_virtual_link> ds_v_virtual_links; //!< JF 06.08.10 Ticket[20401]: virtual links
	ds_hvector<struct dsd_webterm_server_entry> ds_v_webterm_servers;

    // Ticket[16715]
    ds_hvector<ds_page>     ds_v_sso_pages;
    ds_hvector<ds_hstring>  ds_v_precomp_exts;
    ds_hvector<ds_hstring>  ds_v_precomp_files;

    int                 in_bytes_to_add; //!< length of required memory
    int                 in_settings;
    int                 in_flags;
    int                 in_max_len_header_line; //!< JF 07.10.08 determines the maximum line length limit. If set to a positive value, any HTTP line exceeding this limit will cause an "400 Bad Request". A negative or zero value will effectively disable the check.
    int                 in_max_count_header_lines; //!< JF 07.10.08 determines the maximum HTTP header count allowed. If set to a positive value, the number of HTTP headers received from the data stream exceeding this limit will cause an "400 Bad Request". A negative or zero value will effectively disable the check. 

    // Ticket[14903]
    bool                bo_compression;

    ds_hstring          hstr_dll_path;
#ifdef hofmants
	ds_hstring          hstr_hostname;
#endif
    ds_hstring          hstr_hf_server;
    ds_hstring          hstr_bookmark_host;
    ds_hstring          hstr_site_after_auth;
    ds_hstring          hstr_gui_skin;
    bool                bo_show_ssa_checkbox;
    ds_hstring          hstr_root_dir;
    ds_hstring          hstr_cluster_url;
    ds_hstring          hstr_res_xml_path;

    ds_hvector<ds_hstring>      ds_v_alias;
    ds_hvector<ds_hstring>      ds_v_path;
    ds_hvector<dsd_srv_list>    dsc_srv_lists;
    ds_hvector<ds_hstring>      dsc_ica_login;
    ds_hvector<ds_hstring>      dsc_ica_session;
};

/*+-------------------------------------------------------------------+*/
/*| cma access counter:                                               |*/
/*+-------------------------------------------------------------------+*/
#ifdef _DEBUG
static int ing_sdh_calls = 0;       // count sdh calls
static int ing_cma_write = 0;       // count cma write accesses
static int ing_cma_read  = 0;       // count cma read accesses
#endif

/*+-------------------------------------------------------------------+*/
/*| declaration of global functions                                   |*/
/*+-------------------------------------------------------------------+*/

/*! \brief Configuration reader
 *
 * @ingroup cinterface
 *
 * function extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf(struct dsd_hl_clib_dom_conf *ads_conf)
 * subroutine to process the configuration data
 */
extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf(struct dsd_hl_clib_dom_conf *ads_conf)
{
#ifdef _DEBUG  // MJ 16.03.09 
    if (ads_conf == NULL) { // nothing passed -> total error
        printf("HIWSE030E: no parameters passed to m_hlclib_conf()\n");
        return false;
    }
#endif //_DEBUG



    // MJ 04.09.08, Ticket[15874]:
    ds_wsp_helper dsc_wsp_helper_short;
	dsc_wsp_helper_short.m_init_conf( ads_conf );
#ifdef _DEBUG 
	//ds_url::m_test_parse(&dsc_wsp_helper_short);
#endif


    struct dsd_stor_sdh_1 dsl_storage_short;
	// set default block size:
    dsl_storage_short.imc_stor_size = SDH_STORAGE_SIZE;
    // init storage container:
	dsl_storage_short.amc_aux     = ads_conf->amc_aux;
    dsl_storage_short.vpc_userfld = ads_conf->vpc_userfld;
    m_aux_stor_start(&dsl_storage_short);
	void* avol_storage = &dsl_storage_short;
    dsc_wsp_helper_short.m_use_storage(&avol_storage, SDH_STORAGE_SIZE);
	struct ds_my_conf* adsl_my_conf;
	ds_resource* adsl_resource_old = NULL;

#ifdef _DEBUG 
	void* avol_ptr = dsc_wsp_helper_short.m_cb_get_memory(0, false);
	void* avol_ptr2 = dsc_wsp_helper_short.m_cb_get_memory(0, false);
	if(avol_ptr == avol_ptr2) {
		dsc_wsp_helper_short.m_cb_print_out( "HIWSE034E: AUX-Store Zero-Size-Test failed" );
      goto LBL_ERROR;
	}
	dsc_wsp_helper_short.m_cb_free_memory(avol_ptr2);
	dsc_wsp_helper_short.m_cb_free_memory(avol_ptr);
#endif

    // get pointer to starting node
    if (ads_conf->adsc_node_conf == NULL) { // there is no entry in configuration file
        dsc_wsp_helper_short.m_cb_print_out( "HIWSE034E: There is no configuration for WebServer defined in configuration file" );
        goto LBL_ERROR;
    }

	 {
    // read our configuration from section <configuration-section> for this DLL inside configuration-xml-file
    struct dsd_read_config ds_read_config;
// will lead to runtime-error with the strings on SunUltra!?!, and also on LINUX
//    memset(&ds_read_config, 0, sizeof(ds_read_config));

    try {
        m_read_config_from_file_section(&ds_read_config, &dsc_wsp_helper_short);
    }
    catch (int in_exc) { // reading failed for some reason -> print out information
        dsc_wsp_helper_short.m_cb_printf_out("HIWSE031E: Invalid configuration detected: error %d.", in_exc);
        goto LBL_ERROR;
    }
    catch (const ds_hstring& hstr_exc) { // reading failed for some reason -> print out information
        dsc_wsp_helper_short.m_cb_printf_out("HIWSE032E: Invalid configuration detected: %.*s.",
            hstr_exc.m_get_len(), hstr_exc.m_get_ptr());
        goto LBL_ERROR;
    }
    catch (...) { // for all other exception types
        dsc_wsp_helper_short.m_cb_print_out("HIWSE033E: General exception during reading configuration.");                
        goto LBL_ERROR;
    }

    // Ticket[14903]: we must overwrite values in <settings> with the explicite values of compression
    // Compression
    if (ds_read_config.bo_compression) {
        ds_read_config.in_settings |= SETTING_ENABLE_COMPRESSION;
    }
    else {
        ds_read_config.in_settings &= ~SETTING_ENABLE_COMPRESSION;
    }
    
    /*
        add at least the default ica session page
    */
    if ( ds_read_config.dsc_ica_session.m_empty() ) {
        ds_read_config.dsc_ica_session.m_add3( "/Citrix/XenApp/site/default.aspx" );
    }

    // get info about WSP (name, version, ...) and write to configuration
    const char* ach_wsp_info = dsc_wsp_helper_short.m_cb_get_wsp_info();
    if ( ach_wsp_info == NULL ) { // error -> set to a default value
        dsc_wsp_helper_short.m_cb_print_out("HIWSE332E: WSP-Info_string could not be read.");
        // if we cannot detect the version number, we are in an very insure state -> leave !!
        goto LBL_ERROR;
    }

    // copy WSP's info string
    ds_read_config.hstr_hf_server.m_set_zeroterm(ach_wsp_info);
    ds_read_config.hstr_hf_server.m_write("; " WEBSERVER_NAME "/" WS_VERSION_STRING "/" HL_CPUTYPE " " __DATE__);

    int iml_config_size = m_calculate_config_size(&ds_read_config, &dsc_wsp_helper_short);


    // get memory for structure ds_my_conf
    int in_multiply = 1;
#if defined _IA64_ || defined __HOB_ALIGN__
    in_multiply = 3; // only a rough estimation (more bytes because of aligning) -> must be improved!!
#endif
    int in_ensure_zerotermination = 10; // 12.10.06: it could happen that the 4 bytes after the configuration memory are not 0x00
                    // this could result in incorrect reading of the last wstring (because zero-termination is missing) !!!
    int in_len_ds_my_conf = sizeof(struct ds_my_conf) + ds_read_config.in_bytes_to_add * in_multiply + in_ensure_zerotermination;

    // Consider structure lists (e.g. SSO, PPP, etc)
    int in_len_lists = m_calc_len_lists(&ds_read_config);
    if (in_len_lists < 0) {
        dsc_wsp_helper_short.m_cb_printf_out("HIWSE063E: m_calc_len_lists failed with error %d.", in_len_lists);        
        goto LBL_ERROR;
    }
    in_len_ds_my_conf += in_len_lists;

	 adsl_my_conf = (ds_my_conf*)*ads_conf->aac_conf;
#if 0
	 /* Is there an existing configuration? */
	 if(adsl_my_conf != NULL) {
		 adsl_resource_old = adsl_my_conf->av_resource;
		 adsl_my_conf->~ds_my_conf();
		 dsc_wsp_helper.m_cb_free_big_memory(adsl_my_conf);
	 }
#endif
	 BOOL bo_ret = ads_conf->amc_aux( ads_conf->vpc_userfld, DEF_AUX_MEMGET, ads_conf->aac_conf, in_len_ds_my_conf );
    //*ads_conf->aac_conf = (void*)dsc_wsp_helper_short.m_cb_get_big_memory( in_len_ds_my_conf, true );
    if ( bo_ret == FALSE ) {
        dsc_wsp_helper_short.m_cb_print_out("HIWSE035E: DEF_AUX_MEMGET failed");        
        goto LBL_ERROR;
    }
	memset(*ads_conf->aac_conf, 0, in_len_ds_my_conf);
	adsl_my_conf = new(*ads_conf->aac_conf) ds_my_conf();
	adsl_my_conf->dsc_wsp_helper.m_init_conf( ads_conf );
	// set default block size:
    adsl_my_conf->dsc_storage.imc_stor_size = SDH_STORAGE_SIZE;
    // init storage container:
	adsl_my_conf->dsc_storage.amc_aux     = ads_conf->amc_aux;
    adsl_my_conf->dsc_storage.vpc_userfld = ads_conf->vpc_userfld;
    m_aux_stor_start(&adsl_my_conf->dsc_storage);
	void* avol_tmp = &adsl_my_conf->dsc_storage;
	adsl_my_conf->dsc_wsp_helper.m_use_storage(&avol_tmp, SDH_STORAGE_SIZE);

    // write our configuration to memory
    int in_ret = m_write_config_to_memory(&ds_read_config, &dsc_wsp_helper_short, (char*)*ads_conf->aac_conf, in_len_ds_my_conf); 
    if (in_ret != SUCCESS) {
		dsc_wsp_helper_short.m_cb_printf_out("HIWSE083E: m_write_config_to_memory failed with error %d.", in_ret);        
        goto LBL_ERROR;
    }

    // setup wsg attribute list:
    adsl_my_conf->ds_wsg_attr.m_setup( &adsl_my_conf->dsc_wsp_helper );

	}

	if(adsl_resource_old == NULL)
	{
		//------------------------------------------------
		 // setup resources:
		 //------------------------------------------------
		/* hofmants: remove get_evil_memory calls. use a persistent workarea instead */
		struct dsd_aux_get_workarea		dsl_wa;
		if( !adsl_my_conf->dsc_wsp_helper.m_cb_get_persistent_workarea(&dsl_wa, sizeof(ds_resource)) )
			  goto LBL_ERROR;
		//--------------------------------------------
		 // put class inside config:
		 //--------------------------------------------
		adsl_my_conf->av_resource = new(dsl_wa.achc_work_area) ds_resource();

		dsl_wa.imc_len_work_area -= sizeof(ds_resource);
		dsl_wa.achc_work_area += sizeof(ds_resource);

		 //--------------------------------------------
		 // get path of resource file:
		 //--------------------------------------------

		ds_hstring ds_res_path( &dsc_wsp_helper_short );
        
        if( ((struct ds_my_conf*)(*ads_conf->aac_conf))->ach_res_xml_path.inc_length <= 0 )          // if there was no path to res.xml it is on the old place
        {
            ds_res_path.m_write( adsl_my_conf->ach_dll_path );
#ifdef HL_UNIX
		 if ( !ds_res_path.m_ends_with("/") ) {
			  ds_res_path.m_write( "/" );
		 }
#else
		 if (    !ds_res_path.m_ends_with("\\")
				&& !ds_res_path.m_ends_with("/")  ) {
			  ds_res_path.m_write( "\\" );
		 }
#endif
             ds_res_path.m_write( "res.xml" );
        }
        else
        {
            ds_res_path.m_write( ((struct ds_my_conf*)(*ads_conf->aac_conf))->ach_res_xml_path );    // 
        }

		 //--------------------------------------------
		 // setup resource class:
		 //--------------------------------------------
		 if(!((ds_resource*)adsl_my_conf->av_resource)->m_setup( &adsl_my_conf->dsc_wsp_helper,
																				ds_res_path.m_get_ptr(),
																				ds_res_path.m_get_len(),
															 &dsl_wa ))
		 {
			  dsc_wsp_helper_short.m_cb_printf_out("HIWSE084E: ds_resource::m_setup TEST failed.");        
			  goto LBL_ERROR;
		 }
	}
	else {
		adsl_my_conf->av_resource = adsl_resource_old;
	}
	{
		dsd_const_string hstr_msg("HIWSI001I: HOB WebServer initialized (" WEBSERVER_NAME "/" WS_VERSION_STRING "/" HL_CPUTYPE " (CC))");
		dsc_wsp_helper_short.m_cb_print_out(hstr_msg);
	}
	m_aux_stor_end(&dsl_storage_short);
	return true;
LBL_ERROR:
	m_aux_stor_end(&dsl_storage_short);
	return false;
}

struct dsd_session_holder {
	class ds_wsp_helper dsc_wsp_helper;
	class ds_session dsc_session;
};

/*! \brief Main Entry Point for the Datahook
 *
 * @ingroup winterface
 *
 * extern "C" HL_DLL_PUBLIC void m_hlclib01(struct dsd_hl_clib_1 *ads_trans)
 * callback routine which is called by the WebSecureProxy when HTTP data has to be processed
 */
extern "C" HL_DLL_PUBLIC void m_hlclib01(struct dsd_hl_clib_1 *ads_trans)
{
#ifdef _DEBUG  // MJ 16.03.09 
    // check validity of passed paramater
    if (ads_trans == NULL) {
        printf("HIWSE000E: ads_trans == NULL\n");
        return;
    }
    if (ads_trans->ac_conf == NULL) { // JF 16.04.08
        printf("HIWSE720E: ads_trans->ac_conf == NULL\n");
        return;
    }
#endif // _DEBUG


//#define DEBUG_140401_01
#ifdef DEBUG_140401_01

	/*	frailejs: Added by KB for debugging. When DEF_IFUNC_TOSERVER function comes,
		it finds "//" within the gather input
	*/
	while (ads_trans->inc_func == DEF_IFUNC_TOSERVER) {
		static const char chrs_debug_cmp_01[ 2 ] = { '/', '/' };
      if (ads_trans->adsc_gather_i_1_in == NULL) break;
	  struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
	  adsl_gai1_w1 = ads_trans->adsc_gather_i_1_in;
	  do {
		  if (  ((adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur) >= 33)  
			  && (!memcmp( adsl_gai1_w1->achc_ginp_cur + 31, chrs_debug_cmp_01, 2 ))) {
            adsl_gai1_w1 = NULL;
			break;
		  }
		  adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
	  } while (adsl_gai1_w1);
	  break;
	}
#endif

#ifdef DEBUG_FRAILEJS_WEBSERVER_OUTPUT_TO_CLIENT
///******************* fraile DEBUG area***********************/
/*Creating a text file which contains all the data that enters to the webserver*/
	static int x = 0;
	FILE* fptr;
	dsd_gather_i_1* adsl_gather = ads_trans->adsc_gather_i_1_in;

      if( x == 0 )
      {
            fptr = fopen( "WebServerOutputToClient.txt", "w" );
            x = 1;
      }
      else
      {
            fptr = fopen( "WebServerOutputToClient.txt", "a" );
      }

      while( adsl_gather && adsl_gather->achc_ginp_cur )
      {
            fprintf( fptr, "\n\n");
            fprintf( fptr, "%.*s\n", adsl_gather->achc_ginp_end - adsl_gather->achc_ginp_cur, adsl_gather->achc_ginp_cur );
            adsl_gather = adsl_gather->adsc_next;
      }
      fclose( fptr );
#endif


#ifdef DEBUG_FRAILEJS_WEBSERVER_OUTPUT_TO_SERVER
/******************* fraile DEBUG area***********************/
	static int x2 = 0;
	FILE* fptr_2;
	
	if( x2 == 0 ){
		fptr_2 = fopen( "WebServerOutputToServer.txt", "w" );
		x2 = 1;
	}
	else{
		fptr_2 = fopen( "WebServerOutputToServer.txt", "a" );
	}

	if(ads_trans->adsc_gai1_out_to_server && ads_trans->adsc_gai1_out_to_server->achc_ginp_cur ){
		fprintf( fptr_2, "\n\n");
		fprintf( fptr_2, "%.*s\n", ads_trans->adsc_gai1_out_to_server->achc_ginp_end - ads_trans->adsc_gai1_out_to_server->achc_ginp_cur, ads_trans->adsc_gai1_out_to_server->achc_ginp_cur );
	}
	fclose( fptr_2 );*/
/******************* fraile DEBUG area***********************/
#endif


    dsd_session_holder* adsl_session_holder = (dsd_session_holder*)ads_trans->ac_ext;
	/*-----------------*/
    /* DEF_IFUNC_START */
    /*-----------------*/
	// acquire a piece of storage which this session can use in subsequent calls
    if (ads_trans->inc_func == DEF_IFUNC_START) {
        /*--------------------*/
		/* setup helper class */
		/*--------------------*/
		ds_wsp_helper dsl_wsp_helper;
		dsl_wsp_helper.m_init_trans( ads_trans );
	    int inl_port = dsl_wsp_helper.m_get_listen_port();
        if ( inl_port == -1 ) {
            ads_trans->inc_return = DEF_IRET_END;  // close connection
            return;
        }

        //-------------------------------------------------------------------------
        // get memory for this session and create ds_session at this point
        //-------------------------------------------------------------------------
        if (! ads_trans->amc_aux(ads_trans->vpc_userfld, DEF_AUX_MEMGET, &ads_trans->ac_ext, sizeof(dsd_session_holder))) {
            dsl_wsp_helper.m_cb_print_out("HIWSE001E: MEMGET failed");
            ads_trans->inc_return = DEF_IRET_END;  // close connection
            return;
        }
        memset(ads_trans->ac_ext, 0, sizeof(dsd_session_holder));
        adsl_session_holder = new(ads_trans->ac_ext) dsd_session_holder();
		ds_wsp_helper& dsc_wsp_helper = adsl_session_holder->dsc_wsp_helper;
		dsc_wsp_helper.m_init_trans(ads_trans);
		ds_session* ads_session = &adsl_session_holder->dsc_session;

        // MJ 08.06.09, use storage container:
        //------------------------------------------------
        // setup storage container:
        //------------------------------------------------
        dsc_wsp_helper.m_use_storage( &(ads_session->av_storage), SDH_STORAGE_SIZE );

        // we can use our local wsp_helper:
        ads_session->m_init(&dsc_wsp_helper);

        // TODO: ((struct ds_my_conf *) ads_trans->ac_conf)->ach_hostname is always empty!!!!
        // pass the configurd hostname:port to ds_session
        ds_hstring hstr_conf_authority(&dsc_wsp_helper);
        // hostname+port
        hstr_conf_authority.m_set(((struct ds_my_conf *) ads_trans->ac_conf)->ach_hostname);
        hstr_conf_authority.m_write(":");
        hstr_conf_authority.m_write_int(inl_port);
        ads_session->m_set_conf_authority(&hstr_conf_authority);

        //----------------------------------------------------------------------
        // init classes:
        //----------------------------------------------------------------------
        // Ticket[15874]:
        ads_session->dsc_transaction.m_init(ads_trans, ads_session);
        ads_session->dsc_helper.m_init( ads_session );
        ads_session->dsg_zlib_comp.m_init1( ads_session );
        ads_session->dsg_zlib_decomp.m_init1( ads_session );
        ads_session->dsc_control.m_init(ads_session);
        ads_session->dsc_auth.m_init( ads_session );

        dsc_wsp_helper.m_log_input();

#if 0
		//------------------------------------------------
        // setup resources:
        //------------------------------------------------
        if ( ((struct ds_my_conf *) ads_trans->ac_conf)->av_resource == NULL )
		{	
			/* hofmants: remove get_evil_memory calls. use a persistent workarea instead */
			struct dsd_aux_get_workarea		dsl_wa;
			BOOL							bol_ret;

			bol_ret = ads_trans->amc_aux( ads_trans->vpc_userfld, DEF_AUX_GET_WORKAREA, (void*)&dsl_wa, sizeof( dsd_aux_get_workarea ) );
			if( !bol_ret ){ return; }

			bol_ret = ads_trans->amc_aux( ads_trans->vpc_userfld, DEF_AUX_MARK_WORKAREA_INC, dsl_wa.achc_work_area, 0 );
			if( !bol_ret ){ return; }
						
			//--------------------------------------------
            // put class inside config:
            //--------------------------------------------
			((struct ds_my_conf *) ads_trans->ac_conf)->av_resource = (ds_resource*)dsl_wa.achc_work_area;
			((struct ds_my_conf *) ads_trans->ac_conf)->av_resource = new(((struct ds_my_conf *) ads_trans->ac_conf)->av_resource) ds_resource();

			dsl_wa.imc_len_work_area -= sizeof(ds_resource);
			dsl_wa.achc_work_area += sizeof(ds_resource);

            //--------------------------------------------
            // get path of resource file:
            //--------------------------------------------
            ds_hstring ds_res_path( &dsc_wsp_helper, ((struct ds_my_conf *) ads_trans->ac_conf)->ach_dll_path );
#ifdef HL_UNIX
            if ( !ds_res_path.m_ends_with("/") ) {
                ds_res_path.m_write( "/" );
            }
#else
            if (    !ds_res_path.m_ends_with("\\")
                 && !ds_res_path.m_ends_with("/")  ) {
                ds_res_path.m_write( "\\" );
            }
#endif
            ds_res_path.m_write( "res.xml" );

            //--------------------------------------------
            // setup resource class:
            //--------------------------------------------
            ((ds_resource*)((struct ds_my_conf *) ads_trans->ac_conf)->av_resource)->m_setup( &dsc_wsp_helper,
                                                                 ds_res_path.m_get_ptr(),
                                                                 ds_res_path.m_get_len(),
																 &dsl_wa );
        }
#endif
#if 0
        void* avol_cert = NULL;
        int inl_len;
        if(!dsc_wsp_helper.m_cb_get_certificate(&avol_cert, &inl_len))
            return;
        //m_console_out(avol_cert, inl_len);
#endif
        return;
    }

	if (adsl_session_holder == NULL) { // to be sure; should not happen
        return;
    }

	ds_session* ads_session = &adsl_session_holder->dsc_session;
	ds_wsp_helper& dsc_wsp_helper = adsl_session_holder->dsc_wsp_helper;
	dsc_wsp_helper.m_init_trans(ads_trans);
	if(ads_session->boc_watch_session) {
		ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                            "m_hlclib: ads_session=%p inc_func=%d boc_eof_server=%d",
                                            ads_session, ads_trans->inc_func,
											ads_trans->boc_eof_server);

		int a = 0;
	}
    
    //--------------------------------------------------------------------------
    // init classes:
    //--------------------------------------------------------------------------
    // MJ 08.06.09: we can use our local wsp_helper:
    dsc_wsp_helper.m_use_storage( &ads_session->av_storage, SDH_STORAGE_SIZE );
    ads_session->m_init(&dsc_wsp_helper);

    ads_session->ads_config = ((struct ds_my_conf *)ads_trans->ac_conf);

    // Ticket[15874]:
    ads_session->dsc_transaction.m_init(ads_trans, ads_session);
    ads_session->dsc_webserver.m_init(ads_session);
    ads_session->dsc_http_hdr_in.m_init(ads_session);
    ads_session->dsc_http_hdr_out.m_init(ads_session);
    ads_session->dsc_helper.m_init( ads_session );
    ads_session->dsc_ws_gate.m_init( ads_session );
    ads_session->dsg_zlib_comp.m_init1( ads_session );
    ads_session->dsg_zlib_decomp.m_init1( ads_session );
    ads_session->dsc_auth.m_init( ads_session );

    if(!ads_trans->boc_send_client_blocked) {
        ads_session->dsc_webserver.m_release_disk_file();     
    }

    //--------------------------------------------------------------------------
    // setup classes:
    //--------------------------------------------------------------------------
    ads_session->dsc_ws_gate.m_setup();

    /*-----------------*/
    /* DEF_IFUNC_CLOSE */
    /*-----------------*/
    if (ads_trans->inc_func == DEF_IFUNC_CLOSE) {
        dsc_wsp_helper.m_log_output();

        if (ads_session != NULL) { // we must release memory that we acquired in DEF_IFUNC_START (or later)
            ads_session->~ds_session(); // Explicit destructor call
            
            // MJ 06.08.09, delete memory from storage container:
            dsc_wsp_helper.m_no_storage( &(ads_session->av_storage) );
			dsc_wsp_helper.~ds_wsp_helper();

            ads_trans->amc_aux(ads_trans->vpc_userfld, DEF_AUX_MEMFREE, &ads_trans->ac_ext, sizeof(dsd_session_holder));
        }
        return;
    }

	 if(ads_trans->imc_signal != 0) {
		 if(!ads_session->dsc_webserver.m_handle_signal(ads_trans->imc_signal)) {
			ads_session->ads_wsp_helper->m_log( ied_sdh_log_error,
                                            "m_hlclib: m_handle_signal failed");
			ads_trans->inc_return = DEF_IRET_ERRAU;
			return;
		 }
	 }

    dsc_wsp_helper.m_log_input();

	if(ads_trans->inc_func == DEF_IFUNC_REFLECT && ads_session->dsc_transaction.ads_trans->boc_eof_server) {
		ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                          "m_hlclib: DEF_IFUNC_REFLECT boc_eof_server WARNING!!");
		// Don't clear this flag here, leads to errors
		//ads_session->dsc_transaction.ads_trans->boc_eof_server = FALSE;
	}

    ads_session->dsc_control.m_process();
	ads_session->dsc_auth.m_commit();

    // JF 07.05.08 test (for Ticket[14909]) whether NTLM-SSO would work
    // TODO in case of NTLM-SSO we must not set the flag, too
    if (ads_trans->boc_eof_server /*&& !ads_session->dsc_http_hdr_out.bo_hdr_chunked_set*/) { // now all outstanding data are sent to client -> tell WSP to close the connection
        if(ads_trans->adsc_gai1_out_to_client != NULL)
            ads_trans->boc_callagain = TRUE;
        if(ads_trans->adsc_gai1_out_to_server != NULL)
            ads_trans->boc_callagain = TRUE;
        if (!ads_trans->boc_callagain) { // don't set the flag, when we must be called again by WSP
#if 0
            ads_trans->inc_return = DEF_IRET_NORMAL;
#else
            ads_trans->inc_return = DEF_IRET_END;
#endif
        }
        else {
            ads_trans->inc_return = DEF_IRET_NORMAL;
        }
		dsc_wsp_helper.m_logf( ied_sdh_log_warning, 
			"#End-Of-Server ads_trans->adsc_gai1_out_to_client=%p ads_trans->adsc_gai1_out_to_server=%p ads_trans->boc_callagain=%d return=%d\n",
			ads_trans->adsc_gai1_out_to_client,
			ads_trans->adsc_gai1_out_to_server,
			ads_trans->boc_callagain,
			ads_trans->inc_return);
    }

#ifdef DEBUG_HOFMANTS_WEBSERVER_OUTPUT

	static int x2 = 0;
	FILE* fptr_2;

	if( x2 == 0 )
	{
		fptr_2 = fopen( "web_server_output.txt", "w" );
		x2 = 1;
	}
	else
	{
		fptr_2 = fopen( "web_server_output.txt", "a" );
	}
	if(ads_trans->adsc_gai1_out_to_client && ads_trans->adsc_gai1_out_to_client->achc_ginp_cur )
	{
		fprintf( fptr, "\n\n");
		fprintf( fptr_2, "%.*s\n", ads_trans->adsc_gai1_out_to_client->achc_ginp_end - ads_trans->adsc_gai1_out_to_client->achc_ginp_cur, ads_trans->adsc_gai1_out_to_client->achc_ginp_cur );
	}

	fclose( fptr_2 );

#endif

    dsc_wsp_helper.m_log_output();

#ifdef _DEBUG
    int in_locks = dsc_wsp_helper.m_count_cma_lock();
    if ( in_locks > 0 ) {
        dsc_wsp_helper.m_logf( ied_sdh_log_warning, 
                               "Number of CMA-LOCKS = %d\n", in_locks );
    }

    //if ( ads_trans->adsc_gather_i_1_in != NULL ) {
    //    ing_cma_read  += dsc_wsp_helper.m_get_cma_reads();
    //    ing_cma_write += dsc_wsp_helper.m_get_cma_writes();

    //    // print cma accesses:
    //    dsc_wsp_helper.m_logf( ied_sdh_log_warning,
    //                           "HIWSW999W Call %d - CMA-ACCESS: read %d/%d (current/total), write %d/%d (current/total)",
    //                           ing_sdh_calls,
    //                           dsc_wsp_helper.m_get_cma_reads(),  ing_cma_read,
    //                           dsc_wsp_helper.m_get_cma_writes(), ing_cma_write );
    //    ing_sdh_calls++;
    //}
#endif

    if ( ads_trans->adsc_gather_i_1_in != NULL ) {
        //-----------------------------------------
        // are sending data to external webserver?
        //-----------------------------------------
        if (    ads_session->dsc_control.m_to_ext_server()             == false
             && ads_session->dsc_http_hdr_in.m_is_webserver_response() == false
             && ads_session->dsc_control.m_get_state() != ds_control::ien_st_collect_start_line ) {
            //-------------------------------------
            // update cma cookies:
            //-------------------------------------
            ads_session->dsc_auth.m_update();
        }
    }
    
    return;
}

static bool m_compare_ic( const HL_WCHAR* aw_node, const dsd_const_string& rdsp_const )
{
    int in_compare;
    BOOL bo_ret = m_cmpi_vx_vx( &in_compare,
                               aw_node, -1,
                               ied_chs_utf_16,
                               (void*)rdsp_const.m_get_start(),
                               (int)rdsp_const.m_get_len(),
                               ied_chs_utf_8 );

    if ( bo_ret == TRUE && in_compare == 0 ) {
        // we found an known node
        return true;
    }
    return false;
}

static bool m_compare( const HL_WCHAR* aw_node, const dsd_const_string& rdsp_const )
{
    int in_compare;
    BOOL bo_ret = m_cmp_vx_vx( &in_compare,
                               aw_node, -1,
                               ied_chs_utf_16,
                               (void*)rdsp_const.m_get_start(),
                               (int)rdsp_const.m_get_len(),
                               ied_chs_utf_8 );

    if ( bo_ret == TRUE && in_compare == 0 ) {
        // we found an known node
        return true;
    }
    return false;
}

/*! \brief Configuration Reading function
 *
 * @ingroup configuration
 *
 * Reads a configuration from a file section
 */
static void m_read_config_from_file_section(struct dsd_read_config* ads_ret, ds_wsp_helper* ads_wsp_helper)
{
	ads_ret->dsc_log.boc_active = false;
	
	ads_ret->bo_compression = false;
    ads_ret->bo_show_ssa_checkbox = false;

    ads_ret->in_settings    = 0;
    ads_ret->in_flags       = 0;

    ads_ret->hstr_site_after_auth.m_setup(ads_wsp_helper);
    ads_ret->hstr_gui_skin.m_setup(ads_wsp_helper);
    ads_ret->hstr_root_dir.m_setup(ads_wsp_helper);
    ads_ret->hstr_cluster_url.m_setup(ads_wsp_helper);
    ads_ret->hstr_res_xml_path.m_setup(ads_wsp_helper);

#ifdef hofmants
	ads_ret->hstr_hostname.m_setup(ads_wsp_helper);
#endif
	ads_ret->hstr_hf_server.m_setup(ads_wsp_helper);

    ads_ret->dsc_ica_session.m_init( ads_wsp_helper );
    ads_ret->dsc_ica_login.m_init( ads_wsp_helper );

    //----------------------------------------
    // gui skin:
    //----------------------------------------
    ads_ret->hstr_gui_skin.m_setup(ads_wsp_helper);
    ads_ret->hstr_gui_skin.m_write("Default");

    //----------------------------------------
    // dll path:
    //----------------------------------------
    char chr_wsppath[_MAX_PATH];
    if ( ads_wsp_helper->m_get_wsp_path( &chr_wsppath[0], _MAX_PATH ) == false ) {
        ads_wsp_helper->m_cb_print_out( "HIWSE036E: wsp path is too long" );
        throw ds_hstring(ads_wsp_helper, "HIWSE036E: wsp path is too long" );
    }
    ads_ret->hstr_dll_path.m_setup( ads_wsp_helper );
    ads_ret->hstr_dll_path.m_write_zeroterm( chr_wsppath );
    ads_ret->hstr_dll_path.m_write( WEBSERVER_PATH );

    ads_ret->in_max_len_header_line = HOB_MAX_LEN_HEADER_LINE_DEFAULT; // default
    ads_ret->in_max_count_header_lines = HOB_MAX_COUNT_HEADER_LINES_DEFAULT; // default

    ads_ret->ds_v_alias.m_setup				( ads_wsp_helper );
    ads_ret->ds_v_path.m_setup				( ads_wsp_helper );
	ads_ret->ds_v_webterm_servers.m_setup	( ads_wsp_helper );

    ads_ret->ds_v_ppp_tunnels.m_init	( ads_wsp_helper );
    ads_ret->ds_v_virtual_links.m_init	( ads_wsp_helper );
    ads_ret->ds_v_sso_pages.m_init		( ads_wsp_helper );
    ads_ret->ds_v_precomp_exts.m_init	( ads_wsp_helper );
    ads_ret->ds_v_precomp_files.m_init	( ads_wsp_helper );

    DOMNode    *ads_curr_node;                 // node for navigation
    DOMNode    *ads_work_node;                 // node for navigation

    // get the first child of our configuration (using call back method)
    // our configuration are all entries inside the node <configuration-section> (located in node <server-data-hook>)
    ads_curr_node = ads_wsp_helper->m_cb_get_confsection();
    if (ads_curr_node == NULL) {
        throw ds_hstring(ads_wsp_helper, "no getFirstChild() <configuration-section>" );
    }

    int inl_pppt_id = 0;
    do { // loop thru node and extract our configuration to structure
        if ( ads_wsp_helper->m_cb_get_node_type( ads_curr_node ) == DOMNode::ELEMENT_NODE ) {
            // get name of this node
            const HL_WCHAR* awc_node_name = ads_wsp_helper->m_cb_get_node_name( ads_curr_node );
            struct dsd_unicode_string dsl_unicode;
            dsl_unicode.ac_str = (void*)awc_node_name;
            dsl_unicode.imc_len_str = HL_WCSLEN(awc_node_name);
            dsl_unicode.iec_chs_str = ied_chs_utf_16;
            ds_hstring hstr_name(ads_wsp_helper); // name of the xml-tag
            hstr_name.m_set(&dsl_unicode);

            ads_work_node = ads_wsp_helper->m_cb_get_firstchild( ads_curr_node );
            if (ads_work_node == NULL) {
                // Ticket[16515] we get here when a node is empty; e.g. "<address/>" or "<address></address>"
                // throw 1;
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }
            ds_hstring hstr_val(ads_wsp_helper);  // value inside the xml-tag
    
            // read value for this node

            if ( ads_wsp_helper->m_cb_get_node_type( ads_work_node ) == DOMNode::TEXT_NODE ) {
                // Helper variable to transform UTF16-strings (delivered by Xerces) to UTF8 (used in ds_hstring).
                const HL_WCHAR* awc_node_value = ads_wsp_helper->m_cb_get_node_value( ads_work_node );
                dsl_unicode.ac_str = (void*)awc_node_value;
                dsl_unicode.imc_len_str = HL_WCSLEN(awc_node_value);
                dsl_unicode.iec_chs_str = ied_chs_utf_16;
                hstr_val.m_set(&dsl_unicode);
            }

            // "<root-dir>" (WCHAR)
            if (hstr_name.m_equals_ic(CNF_NODE_ROOT_DIR)) {
                ads_ret->hstr_root_dir.m_set(hstr_val);
                // Cut off trailing file separator. It would be duplicated by concatenations like e.g '+ "/public"' !!!
                if ( (ads_ret->hstr_root_dir.m_ends_with("/"))
                ||   (ads_ret->hstr_root_dir.m_ends_with("\\")) ) {
                    ads_ret->hstr_root_dir = ads_ret->hstr_root_dir.m_substring(0, ads_ret->hstr_root_dir.m_get_len()-1);
                }

                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }

            // "<cluster-url>"
            if (hstr_name.m_equals_ic(CNF_NODE_CLUSTER_URL)) {
                ads_ret->hstr_cluster_url.m_set(hstr_val);
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }

            // "<res-xml-full-path>"
            if (hstr_name.m_equals_ic(CNF_NODE_RES_XML_PATH)) {
                ads_ret->hstr_res_xml_path.m_set(hstr_val);
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }

            // "<dll-path>"
            if (hstr_name.m_equals_ic(CNF_NODE_DLL_PATH)) {
                ads_ret->hstr_dll_path.m_set(hstr_val);
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }

            // "<http-hostname>"
            if (hstr_name.m_equals_ic(CNF_NODE_HTTP_HOST))
			{
				ads_wsp_helper->m_cb_print_out( "Entry <http-hostname> in WebServer configuration no longer supported!" );
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }

            // "<bookmark-hostname>"
            if (hstr_name.m_equals_ic(CNF_NODE_BOOKMARK_HOST))
			{
                ads_ret->hstr_bookmark_host.m_set(hstr_val);
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }

            // "<site-after-auth>"
            if (hstr_name.m_equals_ic(CNF_NODE_SITE_AFTER_AUTH)) {
                ads_ret->hstr_site_after_auth.m_set(hstr_val);
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }

            // "<ica-login>"
            if ( hstr_name.m_equals_ic( CNF_NODE_ICA_LOGIN ) ) {
                ads_ret->dsc_ica_login.m_add( hstr_val );
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }

            // "<ica-session>"
            if ( hstr_name.m_equals_ic( CNF_NODE_ICA_SESSION ) ) {
                ads_ret->dsc_ica_session.m_add( hstr_val );
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }

            // MJ 07.07.10: "<show-site-after-auth-checkbox>"
            if ( hstr_name.m_equals_ic( CNF_NODE_SHOW_SAA_CHECKBOX ) ) {
                if ( hstr_val.m_equals_ic(STRING_YES) ) {
                    ads_ret->bo_show_ssa_checkbox = true;
                }
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }

            // MJ 12.07.2010: "<gui-skins>"
            if ( hstr_name.m_equals_ic( CNF_NODE_GUI_SKIN ) ) {
                ads_ret->hstr_gui_skin.m_set(hstr_val);
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }


            // "<compression>"
            if (hstr_name.m_equals_ic(CNF_NODE_COMPRESSION)) {
                // we expect YES or NO
                if (hstr_val.m_equals_ic(STRING_YES)) {
                    ads_ret->bo_compression = true;
                }
                else {
                    if (hstr_val.m_equals_ic(STRING_NO)) {
                        ads_ret->bo_compression = false;
                    }
                    else { // all other strings except STRING_YES and STRING_NO are handled as errors
                        throw ds_hstring(ads_wsp_helper, "value of compression is invalid");
                    }
                }
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }

            // <settings>
            if (hstr_name.m_equals_ic(CNF_NODE_SETTINGS)) {
                if ( (!hstr_val.m_to_int(&ads_ret->in_settings))
                  || (ads_ret->in_settings < 0) ) {
                    throw ds_hstring(ads_wsp_helper, "Invalid xml-element <settings>");
                }
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }

            // <flags>
            if (hstr_name.m_equals_ic(CNF_NODE_FLAGS)) {
                if ( (!hstr_val.m_to_int(&ads_ret->in_flags))
                  || (ads_ret->in_flags < 0) ) {
                    throw ds_hstring(ads_wsp_helper, "Invalid xml-element <flags>");
                }
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }

            // <max_len_header_line>  // Ticket[16125]
            if (hstr_name.m_equals_ic(CNF_NODE_MAX_LEN_HEADER_LINE)) {
                if ( (!hstr_val.m_to_int(&ads_ret->in_max_len_header_line))
                  || (ads_ret->in_max_len_header_line < 0) ) {
                    throw ds_hstring(ads_wsp_helper, "Invalid xml-element <max_len_header_line>");
                }
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }

            // <max_count_header_lines>  // Ticket[16125]
            if (hstr_name.m_equals_ic(CNF_NODE_MAX_COUNT_HEADER_LINES)) {
                if ( (!hstr_val.m_to_int(&ads_ret->in_max_count_header_lines))
                  || (ads_ret->in_max_count_header_lines < 0) ) {
                    throw ds_hstring(ads_wsp_helper, "Invalid xml-element <max_count_header_lines>");
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
            if ( hstr_name.m_equals_ic(CNF_NODE_LOG) ) {
                m_read_cnf_log( ads_wsp_helper, ads_wsp_helper->m_cb_get_firstchild( ads_curr_node ), ads_ret );
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }


			/* Example
			<webterm-server-list><!-- corresponds to server entries with WEBSOCKET protocol and RDP targets -->
				<server-entry>
					<name>HOBWEBRDP1</name>
					<!-- future use <ldap-config>LDAPNAME</ldap-config>-->
					<subprotocol>RDP</subprotocol>
				</server-entry>
				<server-entry>
					<name>HOBWEBRDP2</name>
					<subprotocol>RDP</subprotocol>
				</server-entry>
				<server-entry>
					<name>HOBWEBSSH1</name>
					<subprotocol>SSH</subprotocol>
				</server-entry>
				<server-entry>
					<name>HOBWEBSSH2</name>
					<subprotocol>VT525</subprotocol>
				</server-entry>
			</webterm-server-list>
			*/
            if ( hstr_name.m_equals_ic( CNF_NODE_WEBTERM_SERVER_LIST ) )
			{
				const HL_WCHAR*							awc_node_name;
				DOMNode*							ads_server_entry_node;
				DOMNode*							ads_server_data_node;
				BOOL								bol_ret;
				struct dsd_webterm_server_entry		dsl_webterm_server_entry;
				int									complete = 2; // number of subentries like <name> and <subprotocol>
				int									inl_data = 0;
                
				ads_server_entry_node = ads_wsp_helper->m_cb_get_firstchild( ads_curr_node );

				do
				{
					/* skip uninteresting entries*/
					if( ads_wsp_helper->m_cb_get_node_type( ads_server_entry_node ) != DOMNode::ELEMENT_NODE ){ continue; }

					/* Here the data gets interesting! <server-entry> */
					awc_node_name = ads_wsp_helper->m_cb_get_node_name( ads_server_entry_node );
					
					/* other data in the xml? */
					if( !m_compare_ic(awc_node_name, CNF_NODE_WEBTERM_SERVER_ENTRY) )
                        continue;

					// dive into <name> and <subprotocol> area
					ads_server_data_node = ads_wsp_helper->m_cb_get_firstchild( ads_server_entry_node );
					memset( &dsl_webterm_server_entry, 0, sizeof( struct dsd_webterm_server_entry ) );
                    dsl_webterm_server_entry.iec_subprotocol = ied_webterm_subprotocol_unknown;
					inl_data = 0;

					do
					{
						if( ads_wsp_helper->m_cb_get_node_type( ads_server_data_node ) != DOMNode::ELEMENT_NODE ){ continue; }

						awc_node_name = ads_wsp_helper->m_cb_get_node_name( ads_server_data_node );

						/* we found the <name> tag */
						if( m_compare_ic(awc_node_name, CNF_NODE_WEBTERM_SERVER_NAME) )
						{
							bol_ret = m_cpy_vx_vx(	dsl_webterm_server_entry.chrc_name,
													MAX_WT_LEN,
													ied_chs_utf_8,
													(void*)ads_wsp_helper->m_cb_get_node_value( ads_server_data_node ),
													-1,
													ied_chs_utf_16 );
							if( bol_ret == -1 ){ throw 30; }
							dsl_webterm_server_entry.inc_len_name = bol_ret; // length
							inl_data++;
							continue;
						}

						/* we found the <subprotocol> tag */
						if( m_compare_ic(awc_node_name, CNF_NODE_WEBTERM_SUBPROTOCOL) )
						{
							bol_ret = m_cpy_vx_vx(	dsl_webterm_server_entry.chrc_protocol,
													MAX_WT_LEN,
													ied_chs_utf_8,
													(void*)ads_wsp_helper->m_cb_get_node_value( ads_server_data_node ),
													-1,
													ied_chs_utf_16 );
							if( bol_ret == -1 ){ throw 30; }
							dsl_webterm_server_entry.inc_len_protocol = bol_ret;
							inl_data++;
							continue;
						}

                        /* we found the <session> tag */
                        if( m_compare_ic(awc_node_name, CNF_NODE_WEBTERM_SESSION) )
						{
							bol_ret = m_cpy_vx_vx(	dsl_webterm_server_entry.chrc_session,
													MAX_WT_LEN,
													ied_chs_utf_8,
													(void*)ads_wsp_helper->m_cb_get_node_value( ads_server_data_node ),
													-1,
													ied_chs_utf_16 );
							if( bol_ret == -1 ){ throw 30; }
							dsl_webterm_server_entry.inc_len_session = bol_ret;
							//inl_data++; session tag is optional - do not inc inl_data
							continue;
						}
					}
					while( (ads_server_data_node = ads_wsp_helper->m_cb_get_nextsibling( ads_server_data_node )) != NULL );
					
					if( inl_data == complete )
					{
                        for(size_t szl_pos=0; szl_pos<IMS_NUM_WEBTERM_SUBPROTOCOLS; szl_pos++) {
                            int inl_res;
                            const dsd_webterm_subprotocol_map1& rdsl_mapentry = DSS_WEBTERM_SUBPROTOCOLS[szl_pos];
                            BOOL bol_res = m_cmp_vx_vx(&inl_res, rdsl_mapentry.dsc_name.ac_str, rdsl_mapentry.dsc_name.imc_len_str, rdsl_mapentry.dsc_name.iec_chs_str,
                                dsl_webterm_server_entry.chrc_protocol, dsl_webterm_server_entry.inc_len_protocol, ied_chs_utf_8);
                            if(!bol_res || inl_res != 0)
                                continue;
                            dsl_webterm_server_entry.iec_subprotocol = rdsl_mapentry.iec_subprotocol;
                            dsl_webterm_server_entry.iec_protogroup = rdsl_mapentry.iec_protogroup;
                            break;
                        }

                        ads_ret->ds_v_webterm_servers.m_add( dsl_webterm_server_entry );
					}
				}
				while( (ads_server_entry_node = ads_wsp_helper->m_cb_get_nextsibling( ads_server_entry_node )) != NULL );
			}

            // <HOB-PPP-Tunnel>
            /* Example:
               <HOB-PPP-Tunnel>
                 <server-entry-name>TUNNEL</server-entry-name>
                 <localhost>127.0.0.2</localhost>
                 <enabled>YES</enabled>
                 <address/>
                 <intra-network>
                   <intra-mask>255.255.0.0</intra-mask>
                   <intra-addr>172.22.22.0</intra-addr>
                 </intra-network>
                 <system-parameters>
                   <windows>rasdial HOB-L2TP-01 %TEXT:username; %TEXT:password; /PHONEBOOK:HOB-PPP-T1-01.pbk</windows>
                   <mac>-detach refuse-chap lock passive : ipcp-accept-local ipcp-accept-remote crtscts usepeerdns noccp novj idle 1800 mtu 1410 mru 1410 debug dump connect-delay 5000 nodefaultroute call hobppptunnel ipparam %TEXT:intra-network; user %TEXT:username; password %TEXT:password;</mac>
                   <freebsd>-detach refuse-chap lock passive : ipcp-accept-local ipcp-accept-remote crtscts noccp novj idle 1800 mtu 1410 mru 1410 debug nodefaultroute call hobppptunnel ipparam %TEXT:intra-network; user %TEXT:username;</freebsd>
                   <solaris>-detach refuse-chap lock passive : ipcp-accept-local ipcp-accept-remote crtscts usepeerdns noccp novj idle 1800 mtu 1410 mru 1410 debug dump connect-delay 5000 nodefaultroute call hobppptunnel ipparam %TEXT:intra-network; user %TEXT:username; password %TEXT:password;</solaris>
                   <linux>-detach refuse-chap refuse-eap lock passive : ipcp-accept-local ipcp-accept-remote crtscts usepeerdns noccp novj idle 1800 mtu 1410 mru 1410 debug dump connect-delay 5000 nodefaultroute call hobppptunnel ipparam %TEXT:intra-network; user %TEXT:username; password %TEXT:password;</linux>
                 </system-parameters>
               </HOB-PPP-Tunnel>
            */
            // ATTENTION: I assume that sub nodes are detected by their names -> developer must know names of sub-nodes and react accordingly.
            if (hstr_name.m_equals_ic(CNF_NODE_PPP_TUNNEL)) {
                DOMNode* ads_node = ads_wsp_helper->m_cb_get_firstchild( ads_curr_node );
                if (ads_node == NULL) {
                    throw 30;
                }

                // Ticket[18118]
                // JF 06.07.10 Ticket[20231]: It must be possible to configure more than one PPP-Tunnel.
                ds_ppp_tunnel dsl_ppp_tunnel;
                dsl_ppp_tunnel.m_setup(ads_wsp_helper);
                do {
                    if ( ads_wsp_helper->m_cb_get_node_type( ads_node ) == DOMNode::ELEMENT_NODE) {
                        // get name of this node
                        struct dsd_unicode_string dsl_unicode_ppp;
                        dsl_unicode_ppp.iec_chs_str = ied_chs_utf_16;
                        const HL_WCHAR* awc_node_name_ppp = ads_wsp_helper->m_cb_get_node_name( ads_node );
                        dsl_unicode_ppp.ac_str = (void*)awc_node_name_ppp;
                        dsl_unicode_ppp.imc_len_str = HL_WCSLEN(awc_node_name_ppp);
                        ds_hstring hstr_name_ppp(ads_wsp_helper); // name of the xml-tag
                        hstr_name_ppp.m_set(&dsl_unicode_ppp);

                        ads_work_node = ads_wsp_helper->m_cb_get_firstchild( ads_node );
                        if (ads_work_node == NULL) {
                            // Ticket[16515] we get here when a node is empty; e.g. "<address/>" or "<address></address>"
                            // throw 31;
                            ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
                            continue;
                        }
                        // read value for this node
                        ds_hstring hstr_val_ppp(ads_wsp_helper);  // value inside the xml-tag
                        if ( ads_wsp_helper->m_cb_get_node_type( ads_work_node ) == DOMNode::TEXT_NODE ) {
                            const HL_WCHAR* awc_node_value = ads_wsp_helper->m_cb_get_node_value( ads_work_node );
                            dsl_unicode_ppp.ac_str = (void*)awc_node_value;
                            dsl_unicode_ppp.imc_len_str = HL_WCSLEN(awc_node_value);
                            hstr_val_ppp.m_set(&dsl_unicode_ppp);
                        }

                        // "<address>"
                        if (hstr_name_ppp.m_equals_ic(CNF_NODE_PPP_ADDRESS)) {
                            if (!m_validate_ppp_address(hstr_val_ppp.m_const_str())) { // Ticket[14780]
                                ds_hstring hstr_error(ads_wsp_helper, "HOB PPP Tunnel address is invalid: ");
                                hstr_error.m_write(hstr_val_ppp);
                                throw hstr_error;
                            }
                            dsl_ppp_tunnel.m_set_address(dsl_unicode_ppp);

                            ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
                            continue;
                        } 

                        // "<server-entry-name>"
                        if (hstr_name_ppp.m_equals_ic(CNF_NODE_PPP_SERVER_ENTRY_NAME)) {
                            // Ensure that the server-entry-name is unique.
                            for (HVECTOR_FOREACH(ds_ppp_tunnel, adsl_cur, ads_ret->ds_v_ppp_tunnels)) {
                                const ds_ppp_tunnel& dsl_pppt = HVECTOR_GET(adsl_cur);
                                if (dsl_pppt.m_get_server_entry_name().m_equals(hstr_val_ppp.m_const_str())) {
                                    ds_hstring hstr_error(ads_wsp_helper, "HOB PPP Tunnel: server-entry-name exists twice: ");
                                    hstr_error.m_write(hstr_val_ppp);
                                    throw hstr_error;
                                }
                            }

                            dsl_ppp_tunnel.m_set_server_entry_name(dsl_unicode_ppp);

                            ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
                            continue;
                        }

                        // "<enabled>"
                        if (hstr_name_ppp.m_equals_ic(CNF_NODE_PPP_ENABLED)) {
                            // We expect YES or NO
                            if (!(hstr_val_ppp.m_equals_ic(STRING_YES)) && (!hstr_val_ppp.m_equals_ic(STRING_NO)) ) {
                                // all other strings except STRING_YES and STRING_NO are handled as errors
                                throw ds_hstring(ads_wsp_helper, "value of <enabled> in PPP is invalid");
                            }
                            dsl_ppp_tunnel.m_set_enabled(dsl_unicode_ppp);

                            ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
                            continue;
                        }

                        // "<localhost>"
                        if (hstr_name_ppp.m_equals_ic(CNF_NODE_PPP_LOCALHOST)) {
                            dsl_ppp_tunnel.m_set_localhost(dsl_unicode_ppp);

                            ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
                            continue;
                        }

                        // Ticket[17719] "<system-parameters>" (WCHAR)
                        if (hstr_name_ppp.m_equals_ic(CNF_NODE_PPP_SYSTEM_PARAMETERS)) {
                            ds_hstring hstr_sys_params(ads_wsp_helper);  // value inside the xml-tag
                            if(!m_read_system_parameters(ads_node, ads_wsp_helper, hstr_sys_params))
                                throw ds_hstring(ads_wsp_helper, "HOB PPP Tunnel: read system-parameters failed");
                            dsl_ppp_tunnel.m_set_system_parameters(hstr_sys_params.m_const_str());

                            ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
                            continue;
                        }
                    }
                    ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
                } while(ads_node);

                // JF 06.07.10 Ticket[20231]: More than one PPP-Tunnel
                if (dsl_ppp_tunnel.m_is_enabled()) {
                    // Tunnel is enabled: give it an ID and add it to the vector, which holds the tunnels.
                    dsl_ppp_tunnel.m_set_id(inl_pppt_id);
                    inl_pppt_id++;
                    ads_ret->ds_v_ppp_tunnels.m_add(dsl_ppp_tunnel);
                }
                else {
                    const dsd_const_string dsl_name(dsl_ppp_tunnel.m_get_server_entry_name());
                    ads_wsp_helper->m_cb_printf_out("HIWSI932I: PPP Tunnel %.*s is disabled.",
                        dsl_name.m_get_len(), dsl_name.m_get_ptr());
                }
                

                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            } // CNF_NODE_HOB_PPP_TUNNEL


            // <SSO>
            // example:
            //<SSO>
            //    <page>
            //        <name>WebFile</name>
            //        <url>http://hobrd.hob.de:8080/WebFile/</url>
            //        <ID-list>
            //            <action>
            //                <name>login:login</name>
            //            </action>
            //            <form>
            //                <name>login</name>
            //            </form>
            //            <ID>
            //                <name>login:domain</name>
            //                <value>hob01</value>
            //            </ID>
            //            <ID>
            //                <name>login:user</name>
            //                <value>{username}</value>
            //            </ID>
            //            <ID>
            //                <name>login:password</name>
            //                <value>{password}</value>
            //            </ID>
            //        </ID-list>
            //    </page>
            //    <page>
            //    ....
            //    </page>
            //</SSO>
            // ATTENTION: I assume that sub nodes are detected by their names -> developer must know names of sub-nodes and react accordingly.
            if (hstr_name.m_equals_ic(CNF_NODE_SSO)) {
                DOMNode* ads_node_page = ads_wsp_helper->m_cb_get_firstchild( ads_curr_node );
                if (ads_node_page == NULL) {
                    throw 40;
                }

                struct dsd_unicode_string dsl_unicode_page;
                dsl_unicode_page.iec_chs_str = ied_chs_utf_16;
                ds_hstring hstr_name_page(ads_wsp_helper); // name of the xml-tag
                const HL_WCHAR* awc_name = NULL;
                do {
                    if ( ads_wsp_helper->m_cb_get_node_type( ads_node_page ) == DOMNode::ELEMENT_NODE ) {
                        // get name of this node
                        awc_name = ads_wsp_helper->m_cb_get_node_name( ads_node_page );
                        dsl_unicode_page.ac_str = (void*)awc_name;
                        dsl_unicode_page.imc_len_str = HL_WCSLEN(awc_name);
                        hstr_name_page.m_set(&dsl_unicode_page);

                        // "<page>"
                        if (hstr_name_page.m_equals_ic(CNF_NODE_SSO_PAGE)) {
                            ds_page dsl_page;
                            dsl_page.m_setup(ads_wsp_helper);
                            int in_ret = m_read_page(dsl_page, ads_node_page, ads_wsp_helper);
                            if (in_ret < 0) { // error
                                throw 81;
                            }
                            ads_ret->ds_v_sso_pages.m_add(dsl_page);
                        }
                    }
                    ads_node_page = ads_wsp_helper->m_cb_get_nextsibling( ads_node_page );
                } while(ads_node_page);

                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            } // CNF_NODE_SSO

            //<SettPrecomp>
            //    <extensions>
            //        <ext>
            //            <name>html-pre</name>
            //        </ext>
            //        <ext>
            //            <name>js-pre</name>
            //        </ext>
            //    </extensions>
            //    <files>
            //        <file>
            //            <name>HOBPPPTunnel.html</name>
            //        </file>
            //        <file>
            //            <name>test.pre</name>
            //        </file>
            //    </files>
            //</SettPrecomp>
            // ATTENTION: I assume that sub nodes are detected by their names -> developer must know names of sub-nodes and react accordingly.
            // [14387]
            if (hstr_name.m_equals_ic(CNF_NODE_SETTPRECOMP)) {
                if (m_read_sett_precomp(ads_ret, ads_curr_node, ads_wsp_helper) < SUCCESS) { // error
                    throw 281;
                }

                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }

            if ( hstr_name.m_equals_ic(CNF_NODE_WS_SRV_LST) ) {
                DOMNode* adsl_child = ads_wsp_helper->m_cb_get_firstchild( ads_curr_node );
                if (    adsl_child != NULL
                     && m_read_ws_srv_lst( ads_ret, adsl_child, ads_wsp_helper ) != TRUE ) {
                    throw 282;
                }
                ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
                continue;
            }

            // <virtual-dir>
            // ATTENTION: I assume that sub nodes are detected by their names -> developer must know names of sub-nodes and react accordingly.
            if (hstr_name.m_equals_ic(CNF_NODE_VIRTUAL_DIR)) {
                DOMNode* ads_alias_node = ads_wsp_helper->m_cb_get_firstchild( ads_curr_node );
                if (ads_alias_node == NULL) {
                    throw 7;
                }
                ds_hstring hstr_alias(ads_wsp_helper, "");
                ds_hstring hstr_path(ads_wsp_helper, "");
                do {
                    if ( ads_wsp_helper->m_cb_get_node_type( ads_alias_node ) == DOMNode::ELEMENT_NODE) {
                        // get name of this sub-node
                        const HL_WCHAR* awc_alias_name_wc2 = ads_wsp_helper->m_cb_get_node_name( ads_alias_node );
                        DOMNode* ads_test = ads_wsp_helper->m_cb_get_firstchild( ads_alias_node );
                        if (ads_test == NULL) {
                            throw 8;
                        }
                        
                        // read value for this node
                        const HL_WCHAR* awc_alias_value_wc2;
                        if ( ads_wsp_helper->m_cb_get_node_type( ads_test ) == DOMNode::TEXT_NODE) {
                            awc_alias_value_wc2 = ads_wsp_helper->m_cb_get_node_value( ads_test );

                            const HL_WCHAR* awc_alias_name = awc_alias_name_wc2;
                            const HL_WCHAR* awc_alias_value = awc_alias_value_wc2;

                            // convert alias value to utf8:
                            char chr_alias[_MAX_PATH];
                            int in_len    = HL_WCSLEN( awc_alias_value );
                            if ( in_len > _MAX_PATH - 1 ) {
                                throw ds_hstring(ads_wsp_helper, "Alias value is too long");
                            }
                            
                            int in_copied = m_cpy_vx_vx( &chr_alias[0],   _MAX_PATH - 1, ied_chs_utf_8,
                                                     awc_alias_value, in_len,        ied_chs_utf_16 );
                            if ( in_copied != in_len ) {
                                throw ds_hstring(ads_wsp_helper, "Cannot convert Alias value from UTF16 to UTF8"); 
                            }

                            // save value if tag is right:
                            if ( m_compare(awc_alias_name, CNF_NODE_ALIAS) ) {                                
                                hstr_alias.m_set_zeroterm(chr_alias);
                                if (    (hstr_alias.m_get_len() > 0)
                                     && (hstr_alias[0] != '/') ) {
                                         hstr_alias.m_insert_const_str(0, "/");
                                }
                            }
                            else if(m_compare(awc_alias_name, CNF_NODE_PATH)) {
                                hstr_path.m_set_zeroterm(chr_alias);
                            }
                        }
                    }
                    ads_alias_node = ads_wsp_helper->m_cb_get_nextsibling( ads_alias_node );
                } while(ads_alias_node);
                if ( (hstr_alias.m_get_len() != 0) && (hstr_path.m_get_len() != 0) ) {
                    ads_ret->ds_v_alias.m_add(hstr_alias);
                    ads_ret->ds_v_path.m_add(hstr_path);
                }
            } // CNF_NODE_VIRTUAL_DIR

            // <virtual-link>
            /* Example
            <virtual-link>
			    <alias>/HOBWebFileAccess</alias>
				<url>/http://localhost:8080//HOBWebFileAccess</url>
			</virtual-link>
            */
            if (hstr_name.m_equals_ic(CNF_NODE_VIRTUAL_LINK)) {
                m_read_virtual_link(ads_ret, ads_curr_node, ads_wsp_helper);
            } // CNF_NODE_VIRTUAL_LINK
        }  // DOM node processed -> next
        ads_curr_node = ads_wsp_helper->m_cb_get_nextsibling( ads_curr_node );
    } while (ads_curr_node);
}

static int m_calculate_config_size(struct dsd_read_config* ads_ret, ds_wsp_helper* ads_wsp_helper)
{
    //---------------------------------------------------------------------------------//
    // Calculate the length of data, which will reside behind the structure ds_my_conf //
    //---------------------------------------------------------------------------------//
    ads_ret->in_bytes_to_add  = 0;

    // dll-path (char)
    int in_len_dll_path = ads_ret->hstr_dll_path.m_get_len();
    in_len_dll_path++; // to become zero-terminated
    ads_ret->in_bytes_to_add += in_len_dll_path;

#ifdef hofmants
    // http-hostname (char)
    int in_len_hostname = ads_ret->hstr_hostname.m_get_len();
    if (in_len_hostname == 0) {
        throw ds_hstring(ads_wsp_helper, "No http-hostname specified.");
    }
    in_len_hostname++; // to become zero-terminated
    ads_ret->in_bytes_to_add += in_len_hostname;
#endif

    // hf_server (char)
    int in_len_hf_server = ads_ret->hstr_hf_server.m_get_len();
    in_len_hf_server++; // to become zero-terminated
    ads_ret->in_bytes_to_add += in_len_hf_server;

    // start-site (char)
    dsd_const_string dsl_login_site(GLOBAL_START_SITE);
    int in_len_start_site = dsl_login_site.m_get_len();
    in_len_start_site++; // to become zero-terminated
    ads_ret->in_bytes_to_add += in_len_start_site;

    // site-after-auth (char)
    int in_len_site_after_auth = ads_ret->hstr_site_after_auth.m_get_len();
    if (in_len_site_after_auth == 0) {
        throw ds_hstring(ads_wsp_helper, "No site-after-auth specified.");
    }
    in_len_site_after_auth++; // to become zero-terminated
    ads_ret->in_bytes_to_add += in_len_site_after_auth;

    // gui-skin (char)
    if ( ads_ret->hstr_gui_skin.m_get_len() > 0 ) {
        ads_ret->in_bytes_to_add += ads_ret->hstr_gui_skin.m_get_len() + 1;
    }

    // logfile (char)
    if ( ads_ret->dsc_log.boc_active == true ) {
        int in_len_logfile = ads_ret->dsc_log.dsc_file.m_get_len();
        if (in_len_logfile == 0) {
            throw ds_hstring(ads_wsp_helper, "No LogFile specified.");
        }
        in_len_logfile++; // to become zero-terminated
        ads_ret->in_bytes_to_add += in_len_logfile;
    }

    // root directory (char)
    int in_len_root_dir = ads_ret->hstr_root_dir.m_get_len();
    if (in_len_root_dir == 0) {
        throw ds_hstring(ads_wsp_helper, "No root directory specified.");
    }
    in_len_root_dir++; // to become zero-terminated
    ads_ret->in_bytes_to_add += in_len_root_dir;
    
    // cluster URL
    if (ads_ret->hstr_cluster_url.m_get_len() > 0) // if there was no entry for cluster URL there is no need for place for it.
    {
        ads_ret->in_bytes_to_add += ads_ret->hstr_cluster_url.m_get_len() + 1;
    }

    // res-xml-full-path
    if (ads_ret->hstr_res_xml_path.m_get_len() > 0) // if there was no entry for res-xml-full-path there is no need for place for it.
    {
        ads_ret->in_bytes_to_add += ads_ret->hstr_res_xml_path.m_get_len() + 1;
    }

	// scan aliases
    if (ads_ret->ds_v_alias.m_size() != ads_ret->ds_v_path.m_size()) {
        // Attention: v_alias.size() can be 0, if no alias is specified !
        throw ds_hstring(ads_wsp_helper, "Mismatch of alias names and according paths.");
    }
    for (HVECTOR_FOREACH(ds_hstring, adsl_cur, ads_ret->ds_v_alias)) {
        const ds_hstring& hstr_alias = HVECTOR_GET(adsl_cur);
        // length of both cannot be 0 (was checked prior)
        ads_ret->in_bytes_to_add += hstr_alias.m_get_len() + 1; // 1=zero-terminated
    }
    for (HVECTOR_FOREACH(ds_hstring, adsl_cur, ads_ret->ds_v_path)) {
        const ds_hstring& hstr_path = HVECTOR_GET(adsl_cur);
        // length of both cannot be 0 (was checked prior)
        ads_ret->in_bytes_to_add += hstr_path.m_get_len() + 1;  // 1=zero-terminated
    }

    return ads_ret->in_bytes_to_add;
}


/*! \brief Node value reader
 *
 * @ingroup configuration
 *
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
    
    // get node value:
    awl_value = ads_wsp_helper->m_cb_get_node_value( ads_node );
    return m_compare_ic(awl_value, "yes");
} // end of m_is_yes


/*! \brief Reads the logging level
 *
 * @ingroup configuration
 *
 * function m_read_log_level
 * Decides how much information is written into the logfiles
 *
 * @param[in]   ds_wsp_helper*      ads_wsp_helper  wsp helper class
 * @param[in]   DOMNode*            ads_node        level node
 * @return      ied_sdh_log_level                   log level
*/
ied_sdh_log_level m_read_log_level( ds_wsp_helper* ads_wsp_helper, DOMNode* ads_node )
{
    // initialize some variables:
    const HL_WCHAR*  awl_value;                   // node value

    // get node value:
    awl_value = ads_wsp_helper->m_cb_get_node_value( ads_node );

    // check if level is 'details':
    if (m_compare_ic(awl_value, SDH_LOG_CNF_LEVEL_DETAILS)) {
        return ied_sdh_log_details;
    }

    // check if level is 'info':
    if ( m_compare_ic(awl_value, SDH_LOG_CNF_LEVEL_INFO) ) {
        return ied_sdh_log_info;
    }

    // check if level is 'warning':
    if ( m_compare_ic(awl_value, SDH_LOG_CNF_LEVEL_WARN) ) {
        return ied_sdh_log_warning;
    }

    // check if level is 'error':
    if ( m_compare_ic(awl_value, SDH_LOG_CNF_LEVEL_ERROR) ) {
        return ied_sdh_log_error;
    }

    return ied_sdh_log_info; // default
} // end of m_read_log_level


/*! \brief Reads the configuration section
 *
 * @ingroup configuration
 *
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
        ads_wsp_helper->m_cb_print_out( "HIWSE036E: wsp path is too long" );
        return false;
    }
    ads_read_cfg->dsc_log.dsc_file.m_write_zeroterm( chrl_wsppath );
    ads_read_cfg->dsc_log.dsc_file.m_write( LOGFILE_PATH );
    ads_wsp_helper->m_mkdir( ads_read_cfg->dsc_log.dsc_file.m_get_ptr() );
    ads_read_cfg->dsc_log.dsc_file.m_write( "gather.txt" );

    
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
                ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
                continue;
            }

            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------

            // <enable>
            if ( m_compare_ic(awl_node, CNF_NODE_LOG_ENABLE) ) {
                ads_read_cfg->dsc_log.boc_active = m_is_yes( ads_wsp_helper, adsl_cnode );

                ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
                continue;
            }

            // <file>
            if ( m_compare_ic(awl_node, CNF_NODE_LOG_FILE) ) {
                dsl_value.ac_str      = (void*)ads_wsp_helper->m_cb_get_node_value( adsl_cnode );
                dsl_value.imc_len_str = -1;
                dsl_value.iec_chs_str = ied_chs_utf_16;
                ads_read_cfg->dsc_log.dsc_file.m_set( &dsl_value );

                ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
                continue;
            }

            // <level>
            if ( m_compare_ic(awl_node, CNF_NODE_LOG_LEVEL) ) {
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

/*! \brief Memory calculating function
 *
 * @ingroup configuration
 *
 * Calculate the requested memory amount for configuration parameters,
 * which will be stored as chained listes (e.g. SSO)
 */
int m_calc_len_lists(struct dsd_read_config* ads_read_cfg) {
    // We don't know the required aligning, when data are written into WSP-config. Therefore we
    // initialise the starting point to 1, which will calculate the largest possible amount of aligning bytes (=7).
    int in_needed =  1;

    //-----------
    // Virtual Links
    //-----------
    for (HVECTOR_FOREACH(ds_virtual_link, adsl_cur, ads_read_cfg->ds_v_virtual_links)) {
        const ds_virtual_link& dsl_vir_lnk = HVECTOR_GET(adsl_cur);
        in_needed  = ALIGN_INT(in_needed); // align the structure
        in_needed += (int)sizeof(dsd_virtual_link); // We convert ds_virtual_link -> dsd_virtual_link
        in_needed += dsl_vir_lnk.m_get_alias().m_get_len();
        in_needed += dsl_vir_lnk.m_get_url().m_get_len();
        in_needed += dsl_vir_lnk.m_get_authority().m_get_len();
        in_needed += dsl_vir_lnk.m_get_path().m_get_len();
    }

    //-----------
    // PPP-Tunnels
    //-----------
    for (HVECTOR_FOREACH(ds_ppp_tunnel, adsl_cur, ads_read_cfg->ds_v_ppp_tunnels)) {
        const ds_ppp_tunnel& dsl_ppp_tunnel = HVECTOR_GET(adsl_cur);
        in_needed  = ALIGN_INT(in_needed); // align the structure
        in_needed += (int)sizeof(dsd_pppt); // We convert ds_ppp_tunnel -> dsd_pppt
        in_needed += dsl_ppp_tunnel.m_get_address().m_get_len();
        in_needed += dsl_ppp_tunnel.m_get_localhost().m_get_len();
        in_needed += dsl_ppp_tunnel.m_get_server_entry_name().m_get_len();
        in_needed += dsl_ppp_tunnel.m_get_system_parameters().m_get_len();
    }

    //-----------
    // SSO
    //-----------
    for (HVECTOR_FOREACH(ds_page, adsl_cur, ads_read_cfg->ds_v_sso_pages)) {
        const ds_page& dsl_page = HVECTOR_GET(adsl_cur);
        in_needed  = ALIGN_INT(in_needed); // align the structure
        in_needed += (int)sizeof(dsd_page); // We convert ds_page -> dsd_page
        in_needed += dsl_page.m_get_name().m_get_len();
        in_needed += dsl_page.m_get_url().m_get_len();

        const ds_hvector<ds_id>& dsl_v_ids = dsl_page.m_get_ids();
        for (HVECTOR_FOREACH(ds_id, adsl_cur2, dsl_v_ids)) {
            const ds_id& dsl_id = HVECTOR_GET(adsl_cur2);
            in_needed  = ALIGN_INT(in_needed); // align the structure
            in_needed += (int)sizeof(dsd_id); // We convert ds_id -> dsd_id
            in_needed += dsl_id.m_get_name().m_get_len();
            in_needed += dsl_id.m_get_value().m_get_len();
            in_needed += dsl_id.m_get_type().m_get_len();
        }
    }

    //-----------
    // Precomp settings
    //-----------
    for (HVECTOR_FOREACH(ds_hstring, adsl_cur, ads_read_cfg->ds_v_precomp_exts)) {
        const ds_hstring& hstr_ext = HVECTOR_GET(adsl_cur);
        in_needed  = ALIGN_INT(in_needed); // align the structure
        in_needed += (int)sizeof(dsd_named_list); // We convert ds_ext -> dsd_named_list
        in_needed += hstr_ext.m_get_len();
    }

    for (HVECTOR_FOREACH(ds_hstring, adsl_cur, ads_read_cfg->ds_v_precomp_files)) {
        const ds_hstring& hstr_file = HVECTOR_GET(adsl_cur);
        in_needed  = ALIGN_INT(in_needed); // align the structure
        in_needed += (int)sizeof(dsd_named_list); // We convert ds_file -> dsd_named_list
        in_needed += hstr_file.m_get_len();
    }

    //-----------
    // webserver server lists
    //-----------
    for (HVECTOR_FOREACH(dsd_srv_list, adsl_cur, ads_read_cfg->dsc_srv_lists)) {
        const dsd_srv_list& dsl_list = HVECTOR_GET(adsl_cur);
        in_needed  = ALIGN_INT(in_needed);
        in_needed += (int)sizeof(struct dsd_ws_srv_lst);
        in_needed += dsl_list.dsc_name.m_get_len();
        for (HVECTOR_FOREACH(dsd_srv_entry, adsl_cur2, dsl_list.dsc_srv_entries)) {
            const dsd_srv_entry& dsl_entry = HVECTOR_GET(adsl_cur2);
            in_needed  = ALIGN_INT(in_needed);
            in_needed += (int)sizeof(struct dsd_ws_srv_entry);
            in_needed += dsl_entry.dsc_name.m_get_len();
            in_needed += dsl_entry.dsc_url.m_get_len();
        }
    }

    //-----------
    // ica login pages:
    //-----------
    for (HVECTOR_FOREACH(ds_hstring, adsl_cur, ads_read_cfg->dsc_ica_login)) {
        const ds_hstring& dsl_page = HVECTOR_GET(adsl_cur);
        in_needed  = ALIGN_INT(in_needed);
        in_needed += (int)sizeof(struct dsd_named_list);
        in_needed += dsl_page.m_get_len();
    }

    //-----------
    // ica session pages:
    //-----------
    for (HVECTOR_FOREACH(ds_hstring, adsl_cur, ads_read_cfg->dsc_ica_session)) {
        const ds_hstring& dsl_page = HVECTOR_GET(adsl_cur);
        in_needed  = ALIGN_INT(in_needed);
        in_needed += (int)sizeof(struct dsd_named_list);
        in_needed += dsl_page.m_get_len();
    }

	/* webterm server entries */
	for (HVECTOR_FOREACH(dsd_webterm_server_entry, adsl_cur, ads_read_cfg->ds_v_webterm_servers)) {
        const dsd_webterm_server_entry& dsl_wse = HVECTOR_GET(adsl_cur);
		in_needed  = ALIGN_INT(in_needed);
		in_needed += sizeof( dsd_webterm_server );
		in_needed  = ALIGN_INT(in_needed);
		in_needed += dsl_wse.inc_len_name;
		in_needed  = ALIGN_INT(in_needed);
		in_needed += dsl_wse.inc_len_protocol;
	}

    return in_needed;
}

/*! \brief Stores the configuration in the memory
 *
 * @ingroup configuration
 *
 * Calculate the requested memory amount for configuration parameters,
 * which will be stored as chained listes (e.g. SSO)
 */
// at the begin the structure ds_my_conf is written; behind that the according data are written
int m_write_config_to_memory(struct dsd_read_config * ads_read_cfg, ds_wsp_helper* ads_helper,
                              char* ach_cnf_buf, int in_len_cnf_buf)
{
    struct ds_my_conf* ads_config = (struct ds_my_conf*)ach_cnf_buf;
    ads_config->av_resource = NULL;


    //-------------------------
    // fill memory structure with our configuration settings
    //-------------------------
    int in_len_tmp = 0;
    // flags
    ads_config->in_flags = ads_read_cfg->in_flags;
    // settings
    ads_config->in_settings = ads_read_cfg->in_settings;
    // max_len_header_line
    ads_config->in_max_len_header_line = ads_read_cfg->in_max_len_header_line;
    // max_count_header_lines
    ads_config->in_max_count_header_lines = ads_read_cfg->in_max_count_header_lines;
	 // TODO: Added configuration parameter
	 ads_config->in_max_request_payload = max(8192, ads_config->in_max_len_header_line);
    // MJ 07.07.2010: show site-after-auth checkbox on login page:
    ads_config->bo_show_ssa_checkbox = ads_read_cfg->bo_show_ssa_checkbox;

    char* ach_pos_dest = ach_cnf_buf;
    char* ach_pos_dest_end = ach_cnf_buf + in_len_cnf_buf;
    ach_pos_dest += sizeof(ds_my_conf);
    char* achl_pos_dyn_start = ach_pos_dest;

    // dll-path
    in_len_tmp = ads_read_cfg->hstr_dll_path.m_get_len();
    strncpy(ach_pos_dest, (const char*)ads_read_cfg->hstr_dll_path.m_get_ptr(), in_len_tmp);
    ads_config->ach_dll_path = dsd_const_string(ach_pos_dest, in_len_tmp);
    in_len_tmp++; // terminating 0
    ach_pos_dest += in_len_tmp; // set writing position behind path and terminating 0; 2=WCHAR!!

#ifdef hofmants
    // hostname
    in_len_tmp = ads_read_cfg->hstr_hostname.m_get_len();
    strncpy(ach_pos_dest, (const char*)ads_read_cfg->hstr_hostname.m_get_ptr(), in_len_tmp);
    ads_config->ach_hostname = ach_pos_dest;
    ach_pos_dest += in_len_tmp + 1; // set writing position behind hostname and terminating 0
#endif

#if 0
    // bookmark hostname
    in_len_tmp = ads_read_cfg->hstr_bookmark_host.m_get_len();
    strncpy(ach_pos_dest, ads_read_cfg->hstr_bookmark_host.m_get_ptr(), in_len_tmp);
    BOOL bol_ret = ads_session->dsc_transaction.ads_trans->amc_aux(
        ads_session->dsc_transaction.ads_trans->vpc_userfld,
		DEF_AUX_GET_DOMAIN_INFO, &dsl_gdi1, sizeof(dsl_gdi1));
	if (bol_ret == FALSE) {                   /* returned error          */
		ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
											 "HIWSE384E: get domain information returned error" );
		break;
	}

    ads_config->ach_bookmark_host = dsd_const_string(ach_pos_dest, in_len_tmp);
    ach_pos_dest += in_len_tmp + 1; // set writing position behind hostname and terminating 0
#endif

    // header field server (is written by us to HF_SERVER)
    in_len_tmp = ads_read_cfg->hstr_hf_server.m_get_len();
    strncpy(ach_pos_dest, ads_read_cfg->hstr_hf_server.m_get_ptr(), in_len_tmp);
    ads_config->ach_hf_server = dsd_const_string(ach_pos_dest, in_len_tmp);
    ach_pos_dest += in_len_tmp + 1; // set writing position behind hostname and terminating 0

    // start-site
    dsd_const_string dsl_login_site(GLOBAL_START_SITE);
    in_len_tmp = static_cast<int>(dsl_login_site.m_get_len());
    strncpy(ach_pos_dest, dsl_login_site.m_get_start(), in_len_tmp);
    ads_config->ach_login_site = dsd_const_string(ach_pos_dest, in_len_tmp);
    ach_pos_dest += in_len_tmp + 1; // set writing position behind login-site and terminating 0

    // site-after-auth
    in_len_tmp = ads_read_cfg->hstr_site_after_auth.m_get_len();
    strncpy(ach_pos_dest, ads_read_cfg->hstr_site_after_auth.m_get_ptr(), in_len_tmp);
    ads_config->ach_site_after_auth = dsd_const_string(ach_pos_dest, in_len_tmp);
    ach_pos_dest += in_len_tmp + 1; // set writing position behind site-after-auth and terminating 0

    // gui-skin
    in_len_tmp = ads_read_cfg->hstr_gui_skin.m_get_len();
    strncpy(ach_pos_dest, ads_read_cfg->hstr_gui_skin.m_get_ptr(), in_len_tmp);
    ads_config->ach_gui_skin = dsd_const_string(ach_pos_dest, in_len_tmp);
    ach_pos_dest += in_len_tmp + 1; // set writing position behind gui-skin and terminating 0

    // logfile
    if ( ads_read_cfg->dsc_log.boc_active == true ) {
        in_len_tmp = ads_read_cfg->dsc_log.dsc_file.m_get_len();
        strncpy(ach_pos_dest, ads_read_cfg->dsc_log.dsc_file.m_get_ptr(), in_len_tmp);
        ads_config->ds_logfile.achc_file = ach_pos_dest;
        ach_pos_dest += in_len_tmp + 1; // set writing position behind site-after-auth and terminating 0
        ads_config->ds_logfile.achc_version = (char*)WS_VERSION_STRING;
        ads_config->ds_logfile.boc_active = ads_read_cfg->dsc_log.boc_active;
        ads_config->ds_logfile.iec_level  = ads_read_cfg->dsc_log.iec_level;
#ifdef HL_UNIX
        pthread_mutex_init( &(ads_config->ds_logfile.dsc_lock), NULL );
#else
        InitializeCriticalSection(&(ads_config->ds_logfile.dsc_lock));
#endif //WIN
    }

    // root dir
    in_len_tmp = ads_read_cfg->hstr_root_dir.m_get_len();
    strncpy(ach_pos_dest, (const char*)ads_read_cfg->hstr_root_dir.m_get_ptr(), in_len_tmp);
    ads_config->ach_root_dir = dsd_const_string(ach_pos_dest, in_len_tmp);
    in_len_tmp++; // terminating 0
    ach_pos_dest += in_len_tmp;

    // cluster URL
    if (ads_read_cfg->hstr_cluster_url.m_get_len() <= 0)
    {
        ads_config->ach_cluster_url = dsd_const_string(0, 0);
    }
    else
    {
        in_len_tmp = ads_read_cfg->hstr_cluster_url.m_get_len();
        strncpy(ach_pos_dest, ads_read_cfg->hstr_cluster_url.m_get_ptr(), in_len_tmp);
        ads_config->ach_cluster_url = dsd_const_string(ach_pos_dest, in_len_tmp);
        ach_pos_dest += in_len_tmp + 1; // set writing position behind cluster URL and terminating 0
    }

    // res-xml-full-path
    if (ads_read_cfg->hstr_res_xml_path.m_get_len() <= 0)
    {
        ads_config->ach_res_xml_path = dsd_const_string(0, 0);
    }
    else
    {
        in_len_tmp = ads_read_cfg->hstr_res_xml_path.m_get_len();
        strncpy(ach_pos_dest, ads_read_cfg->hstr_res_xml_path.m_get_ptr(), in_len_tmp);
        ads_config->ach_res_xml_path = dsd_const_string(ach_pos_dest, in_len_tmp);
        ach_pos_dest += in_len_tmp + 1; // set writing position behind res-xml-full-path and terminating 0
    }

    // count of alias/path-entries for virtual-dir
    int in_count_alias_path = ads_read_cfg->ds_v_alias.m_size();
    if (in_count_alias_path > 0) {
        ads_config->in_count_alias_path = in_count_alias_path;

        // alias
        // write position of start of alias to structure
        ads_config->ach_alias = ach_pos_dest;
        for (HVECTOR_FOREACH(ds_hstring, adsl_cur, ads_read_cfg->ds_v_alias)) {
            const ds_hstring& hstr_tmp = HVECTOR_GET(adsl_cur);
            memcpy( ach_pos_dest, hstr_tmp.m_get_ptr(), hstr_tmp.m_get_len() );
            ach_pos_dest += hstr_tmp.m_get_len() + 1;
        }
        // path
        // write position of start of path to structure
        ads_config->ach_path = ach_pos_dest;
        for (HVECTOR_FOREACH(ds_hstring, adsl_cur, ads_read_cfg->ds_v_path)) {
            const ds_hstring& hstr_tmp = HVECTOR_GET(adsl_cur);
            memcpy( ach_pos_dest, hstr_tmp.m_get_ptr(), hstr_tmp.m_get_len() );
            ach_pos_dest += hstr_tmp.m_get_len() + 1;
        }
    } // if (in_count_alias_path > 0)


    // Calculate the starting point, where to write the following configurations.
    // Attention: This starting point might be aligned by the following methods!
    int in_pos = (int)(ach_pos_dest - (char*)ach_cnf_buf);
    // Attention: From here we use only in_pos; no more ach_pos_dest!!!

    //-----------
    // Virtual links
    //-----------
    int inl_ret = m_store_virtual_links(ads_read_cfg, ads_helper, &in_pos, ach_cnf_buf, in_len_cnf_buf);
    if ( inl_ret != SUCCESS ) {
        return inl_ret;
    }
    //-----------
    // PPP-Tunnel
    //-----------
    inl_ret = m_store_pppt(ads_read_cfg, ads_helper, &in_pos, ach_cnf_buf, in_len_cnf_buf);
    if ( inl_ret != SUCCESS ) {
        return inl_ret;
    }

    //-----------
    // SSO
    //-----------
    inl_ret = m_store_sso(ads_read_cfg, ads_helper, &in_pos, ach_cnf_buf, in_len_cnf_buf);
    if ( inl_ret != SUCCESS ) {
        return inl_ret;
    }

    //-----------
    // Precomp settings
    //-----------
    inl_ret = m_store_precomp(ads_read_cfg, ads_helper, &in_pos, ach_cnf_buf, in_len_cnf_buf);
    if ( inl_ret != SUCCESS ) {
        return inl_ret;
    }

    //-----------
    // webserver server lists
    //-----------
    inl_ret = m_write_ws_srv_lst(ads_read_cfg, ach_cnf_buf, in_len_cnf_buf, &in_pos, ads_helper);
    if ( !inl_ret ) {
        return inl_ret;
    }

    //-----------
    // ica pages
    //-----------
    inl_ret = m_write_ica_pages(ads_read_cfg, ach_cnf_buf, in_len_cnf_buf, &in_pos);
    if ( !inl_ret ) {
        return inl_ret;
    }

	/************************\
	| Webterm Server Entries |
	\************************/
	dsd_webterm_server*				adsl_wse_new;
	dsd_webterm_server*				adsl_prev = NULL;
	
	/* copy every entry with real length into the contiguous memory */
	for( HVECTOR_FOREACH(dsd_webterm_server_entry, adsl_cur, ads_read_cfg->ds_v_webterm_servers) )
	{
		/* get the old buffer */
		const dsd_webterm_server_entry& dsl_wse_old = HVECTOR_GET(adsl_cur);

		/* get struct in new memory */
		in_pos = ALIGN_INT( in_pos );
		adsl_wse_new = (dsd_webterm_server*)( ach_cnf_buf + in_pos );
		
		/* chain elements */
		if( adsl_prev ){ 
            adsl_prev->adsc_next = adsl_wse_new;
        }
		adsl_prev = adsl_wse_new;

		/* set first element */
		if( ads_config->adsc_webterm_list == NULL ){
            ads_config->adsc_webterm_list = adsl_wse_new;
        }
		
		/* set length of strings */
		adsl_wse_new->inc_len_server_name	= dsl_wse_old.inc_len_name;
		adsl_wse_new->inc_len_protocol_name	= dsl_wse_old.inc_len_protocol;
        adsl_wse_new->iec_subprotocol       = dsl_wse_old.iec_subprotocol;
        adsl_wse_new->iec_protogroup        = dsl_wse_old.iec_protogroup;
        adsl_wse_new->inc_len_session_name  = dsl_wse_old.inc_len_session;

		/* set pointer after the structure */
		in_pos += sizeof( dsd_webterm_server );
		
		/* store server entry name in memory */
		in_pos = ALIGN_INT( in_pos );
		adsl_wse_new->achc_server_name = ach_cnf_buf + in_pos;
		memcpy( ach_cnf_buf + in_pos, dsl_wse_old.chrc_name, dsl_wse_old.inc_len_name );
		in_pos += dsl_wse_old.inc_len_name;
		
		/* store protocol */
		in_pos = ALIGN_INT( in_pos );
		adsl_wse_new->achc_protocol_name = ach_cnf_buf + in_pos;
		memcpy( ach_cnf_buf + in_pos, dsl_wse_old.chrc_protocol, dsl_wse_old.inc_len_protocol );
		in_pos += dsl_wse_old.inc_len_protocol;

        /* store session (may be absent)*/
		in_pos = ALIGN_INT( in_pos );
		adsl_wse_new->achc_session_name = ach_cnf_buf + in_pos;
		memcpy( ach_cnf_buf + in_pos, dsl_wse_old.chrc_session, dsl_wse_old.inc_len_session );
		in_pos += dsl_wse_old.inc_len_session;


		/* is chained when a new element is added into the list -> next iteration */
		adsl_wse_new->adsc_next = NULL;
	}


#ifdef _DEBUG
    ads_helper->m_cb_printf_out("Library path: %.*s",              ads_config->ach_dll_path.m_get_len(), ads_config->ach_dll_path.m_get_ptr() );
    ads_helper->m_cb_printf_out("Server root directory: %.*s",     ads_config->ach_root_dir.m_get_len(), ads_config->ach_root_dir.m_get_ptr() );
    ads_helper->m_cb_printf_out("Login page: %.*s",                ads_config->ach_login_site.m_get_len(), ads_config->ach_login_site.m_get_ptr());
    ads_helper->m_cb_printf_out("Page after authentication: %.*s", ads_config->ach_site_after_auth.m_get_len(), ads_config->ach_site_after_auth.m_get_ptr());
    ads_helper->m_cb_printf_out("Logfile: %s",                   ads_config->ds_logfile.achc_file);
    if (((ads_config->in_settings) & SETTING_DISABLE_HTTPS) != 0) {
        ads_helper->m_cb_printf_out("Settings: %d (SSL is disabled)", ads_config->in_settings);
    }
    else {
        ads_helper->m_cb_printf_out("Settings: %d", ads_config->in_settings);
    }
    ads_helper->m_cb_printf_out("Flags: %d",                     ads_config->in_flags);
    ads_helper->m_cb_printf_out("Count aliases: %d",             ads_config->in_count_alias_path);
    if (in_count_alias_path > 0) { // print aliases and concerning paths
        ads_helper->m_cb_printf_out("Alias      |||     Path");
        const char* ach_alias = ads_config->ach_alias;
        const char* ach_path  = ads_config->ach_path;
        
        // loop through all alias entries:
        for (int i=0; i<ads_config->in_count_alias_path; i++) {
            // print:
            ads_helper->m_cb_printf_out( "%s ||| %s", ach_alias, ach_path );
            
            // get next entries:
            ach_alias += (int)strlen(ach_alias) + 1;
            ach_path += (int)strlen(ach_path) + 1;
        }
    } // if (in_count_alias_path > 0)


    // 06.08.10 Ticket[20401]
    if (ads_config->adsl_vi_lnk != NULL) {
        // Loop through all aliases and compare with the delievered url.
        dsd_virtual_link* adsl_vir_lnk = ads_config->adsl_vi_lnk;
        while (adsl_vir_lnk != NULL) {
            ads_helper->m_cb_printf_out("Virtual link: alias=%.*s  url=%.*s",
                                               adsl_vir_lnk->in_len_alias, adsl_vir_lnk->ach_alias,
                                               adsl_vir_lnk->in_len_url  , adsl_vir_lnk->ach_url);
            adsl_vir_lnk = adsl_vir_lnk->adsc_next;
        }
    }

    // Ticket[20231]: Print the PPP-Tunnels
    dsd_pppt* adsl_pppt_curr = ads_config->adsl_pppt;
    while(adsl_pppt_curr != NULL) {
        ads_helper->m_cb_printf_out( "HOB PPP Tunnel: ID=%d  server-entry-name=%.*s  address=%.*s  localhost=%.*s  system_parameters=%.*s",
                                                        adsl_pppt_curr->in_id,
                                                        adsl_pppt_curr->in_len_server_entry_name, adsl_pppt_curr->ach_server_entry_name,
                                                        adsl_pppt_curr->in_len_address, adsl_pppt_curr->ach_address,
                                                        adsl_pppt_curr->in_len_localhost, adsl_pppt_curr->ach_localhost,
                                                        adsl_pppt_curr->in_len_system_parameters, adsl_pppt_curr->ach_system_parameters);
        adsl_pppt_curr = adsl_pppt_curr->adsc_next;
    }

    if (((ads_config->in_settings) & SETTING_DO_SYSTEM_CHECK) != 0) {
        m_system_check(ads_helper);
    }
#endif //_DEBUG

    return SUCCESS;    
}

/*! \brief Checks some system dependent attributes
 *
 * @ingroup configuration
 *
 * Checks if the machine is big/little endian and the size of different variable types
 * 
 */
void m_system_check(ds_wsp_helper* ads_helper)
{
    ads_helper->m_cb_printf_out("System info:");
    int in_test = 1;
    char ach_test = *((char *) &in_test);
    if (ach_test == 1) {
        ads_helper->m_cb_printf_out("LITTLE endian machine.");
    }
    else {
        ads_helper->m_cb_printf_out("BIG endian machine.");
    }

    ads_helper->m_cb_printf_out("Size of short:     %d", (int)sizeof(short));
    ads_helper->m_cb_printf_out("Size of int:       %d", (int)sizeof(int));  
    ads_helper->m_cb_printf_out("Size of long:      %d", (int)sizeof(long));
    ads_helper->m_cb_printf_out("Size of long long: %d", (int)sizeof(long long));
    ads_helper->m_cb_printf_out("Size of wchar_t:   %d", (int)sizeof(wchar_t));
}

/*! \brief Reads the IDs from the configuration
 *
 * @ingroup configuration
 *
 * Reads the value of the ID Tag in the configuration section
 */
int m_read_id_list(ds_page& dsl_page, DOMNode* ads_node_idlist, ds_wsp_helper* ads_wsp_helper) {
    DOMNode* ads_node = ads_wsp_helper->m_cb_get_firstchild( ads_node_idlist );
    if (ads_node == NULL) {
        return -1;
    }

    struct dsd_unicode_string dsl_unicode;
    dsl_unicode.iec_chs_str = ied_chs_utf_16;
    ds_hstring hstr_name(ads_wsp_helper); // name of the xml-tag
    const HL_WCHAR* awc_node_name = NULL;
    do {
        if ( ads_wsp_helper->m_cb_get_node_type( ads_node ) == DOMNode::ELEMENT_NODE ) {
            // get name of this node
            awc_node_name = ads_wsp_helper->m_cb_get_node_name( ads_node );
            dsl_unicode.ac_str = (void*)awc_node_name;
            dsl_unicode.imc_len_str = HL_WCSLEN(awc_node_name);
            hstr_name.m_set(&dsl_unicode);

            // "<ID>"
            if (hstr_name.m_equals(CNF_NODE_SSO_PAGE_IDLIST_ID)) {
                ds_id dsl_id;
                dsl_id.m_setup(ads_wsp_helper);
                int in_ret = m_read_id(dsl_id, ads_node, ads_wsp_helper);
                if (in_ret < 0) {
                    return -10;
                }
                dsl_page.m_add_id(dsl_id);
            }
        }
        ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
    } while(ads_node);
    return 0;
}

/*! \brief 
 *
 * @ingroup configuration
 *
 * Reads the value of the virtual links in the configuration section 
 */
int m_read_virtual_link(dsd_read_config* ads_ret, DOMNode* ads_node_in, ds_wsp_helper* ads_wsp_helper) {
    DOMNode* adsl_curr_node = ads_wsp_helper->m_cb_get_firstchild(ads_node_in);
    if (adsl_curr_node == NULL) {
        throw 187;
    }

    struct dsd_unicode_string dsl_unic_key;
    dsl_unic_key.iec_chs_str = ied_chs_utf_16;
    struct dsd_unicode_string dsl_unic_val;
    dsl_unic_val.iec_chs_str = ied_chs_utf_16;

    //ds_hstring hstr_tmp(ads_wsp_helper, "");
    ds_hstring hstr_url(ads_wsp_helper, "");
    ds_hstring hstr_key(ads_wsp_helper, "");

    ds_virtual_link dsl_virtual_link;
    dsl_virtual_link.m_setup(ads_wsp_helper);
    do {
        if ( ads_wsp_helper->m_cb_get_node_type(adsl_curr_node) == DOMNode::ELEMENT_NODE) {
            // get name of this sub-node (the key in key-value-pair)
            const HL_WCHAR* awc_key_wc2 = ads_wsp_helper->m_cb_get_node_name(adsl_curr_node);
            dsl_unic_key.ac_str = (void*)awc_key_wc2;
            dsl_unic_key.imc_len_str = HL_WCSLEN(awc_key_wc2);
            hstr_key.m_set(&dsl_unic_key);

            DOMNode* ads_test = ads_wsp_helper->m_cb_get_firstchild(adsl_curr_node);
            if (ads_test == NULL) {
                // We get here, if node has no value. Example: <url></url>
                adsl_curr_node = ads_wsp_helper->m_cb_get_nextsibling(adsl_curr_node);
                continue;
            }
            
            // read value for this node
            if ( ads_wsp_helper->m_cb_get_node_type( ads_test ) == DOMNode::TEXT_NODE) {
                const HL_WCHAR* awc_value = ads_wsp_helper->m_cb_get_node_value( ads_test );
                dsl_unic_val.ac_str = (void*)awc_value;
                dsl_unic_val.imc_len_str = HL_WCSLEN(awc_value);

                if (dsl_unic_val.imc_len_str > _MAX_PATH) {
                    ds_hstring hstr(ads_wsp_helper, "Value is too long for virtual link: ");
                    hstr.m_set(&dsl_unic_key);
                    throw hstr;
                }

                // <alias>
                if (hstr_key.m_equals_ic(CNF_NODE_ALIAS)) {
                    dsl_virtual_link.m_set_alias(&dsl_unic_val);
                    dsd_const_string hstr_tmp = dsl_virtual_link.m_get_alias();
                    if (hstr_tmp.m_get_len() < 1) {
                        throw ds_hstring(ads_wsp_helper, "Invalid tag found in virtual link. <alias> must not be empty.");
                    }
                    // Ensure that alias starts with '/' and does not end with '/'.
                    if (!hstr_tmp.m_starts_with("/")) {
                        ads_wsp_helper->m_cb_printf_out("alias changed from %.*s to /%.*s.",
                            hstr_tmp.m_get_len(), hstr_tmp.m_get_ptr(), hstr_tmp.m_get_len(), hstr_tmp.m_get_ptr());
                        ds_hstring dsl_tmp(ads_wsp_helper, "/");
                        dsl_tmp.m_write(hstr_tmp);
                        dsl_virtual_link.m_set_alias(dsl_tmp.m_const_str());
                    }
                    if (hstr_tmp.m_ends_with("/")) {
                        dsd_const_string dsl_tmp(hstr_tmp.m_substring(0, hstr_tmp.m_get_len()-1));
                        ads_wsp_helper->m_cb_printf_out("alias changed from %.*s/ to %.*s.",
                            dsl_tmp.m_get_len(), dsl_tmp.m_get_ptr(), dsl_tmp.m_get_len(), dsl_tmp.m_get_ptr());
                        dsl_virtual_link.m_set_alias(dsl_tmp);
                    }
                }

                // <url>
                if (hstr_key.m_equals_ic(CNF_NODE_URL)) {
                    dsl_virtual_link.m_set_url(&dsl_unic_val);
                    dsd_const_string hstr_tmp = dsl_virtual_link.m_get_url();
                    if (hstr_tmp.m_get_len() < 1) {
                        throw ds_hstring(ads_wsp_helper, "Invalid tag found in virtual link. <url> must not be empty.");
                    }

                    // Ensure that url starts with '/' and does not end with '/'.
                    if (!hstr_tmp.m_starts_with("/")) {
                        ads_wsp_helper->m_cb_printf_out("url changed from %.*s to /%.*s.",
                            hstr_tmp.m_get_len(), hstr_tmp.m_get_ptr(), hstr_tmp.m_get_len(), hstr_tmp.m_get_ptr());
                        ds_hstring dsl_tmp(ads_wsp_helper, "/");
                        dsl_tmp.m_write(hstr_tmp);
                        dsl_virtual_link.m_set_url(dsl_tmp.m_const_str());
                    }
                    if (hstr_tmp.m_ends_with("/")) {
                        dsd_const_string dsl_tmp(hstr_tmp.m_substring(0, hstr_tmp.m_get_len()-1));
                        ads_wsp_helper->m_cb_printf_out("url changed from %.*s/ to %.*s.",
                            dsl_tmp.m_get_len(), dsl_tmp.m_get_ptr(), dsl_tmp.m_get_len(), dsl_tmp.m_get_ptr());
                        dsl_virtual_link.m_set_url(dsl_tmp);
                    }
                }
            }
        }
        adsl_curr_node = ads_wsp_helper->m_cb_get_nextsibling(adsl_curr_node);
    } while(adsl_curr_node);


    // Parse the url into protocol, authority, port and path.
    // 1) Protocol
    dsd_const_string hstr_tmp = dsl_virtual_link.m_get_url();
    if (hstr_tmp.m_starts_with_ic("/https://")) {
        dsl_virtual_link.m_set_protocol(PROTO_HTTPS); // 1
        dsl_virtual_link.m_set_port(443);
        hstr_tmp = hstr_tmp.m_substring(strlen("/https://"));
    }
    else if (hstr_tmp.m_starts_with_ic("/http://")) {
        dsl_virtual_link.m_set_protocol(PROTO_HTTP); // 0
        dsl_virtual_link.m_set_port(80);
        hstr_tmp = hstr_tmp.m_substring(strlen("/http://"));
    }
    else {
        ds_hstring hstr(ads_wsp_helper, "Invalid URL detected for virtual link: ");
        hstr.m_write(hstr_tmp);
        throw hstr;
    }

    // 2) Address and port and path.
    int in_pos = hstr_tmp.m_find_first_of("/:");
    if (in_pos == -1) { // no terminating '/' or ':' -> the path is empty; port according to protocol
        dsl_virtual_link.m_set_authority(hstr_tmp);
        
        // The port was not set in URL. Port is already set according to protocol.
    }
    else { // ':' or '/' was found.
        // 1) A port number is set in URL: /http://hobc02k.hob.de:8080/test
        if (hstr_tmp[in_pos] == ':') { 
            // Part before ':' is the address
            ds_hstring hstr_auth(ads_wsp_helper, hstr_tmp.m_get_ptr(), in_pos);
            dsl_virtual_link.m_set_authority(hstr_auth.m_const_str());
            // Skip ':'. Port follows. Port is terminated by '/' or string-end. 
            hstr_tmp = hstr_tmp.m_substring(in_pos+1);
            in_pos = hstr_tmp.m_find_first_of("/");
            int inl_port = 0;
            if (in_pos == -1) { // no terminating '/' -> the string is the port
                bool bo_ret = hstr_tmp.m_parse_int(&inl_port);
                if (!bo_ret) {
                    ds_hstring hstr(ads_wsp_helper, "Cannot determine port number for virtual link: ");
                    hstr.m_write(dsl_virtual_link.m_get_url());
                    throw hstr;
                }
            }
            else { // Url contains path -> cut out the port number.
                dsd_const_string hstr_port(hstr_tmp.m_get_ptr(), in_pos);
                bool bo_ret = hstr_port.m_parse_int(&inl_port);
                if (!bo_ret) {
                    ds_hstring hstr(ads_wsp_helper, "Cannot determine port number for virtual link: ");
                    hstr.m_write(dsl_virtual_link.m_get_url());
                    throw hstr;
                }

                // Remaining part is the path of the url.
                hstr_tmp = hstr_tmp.m_substring(in_pos);
                dsl_virtual_link.m_set_path(hstr_tmp);
            }
            dsl_virtual_link.m_set_port(inl_port);
        }
        else {   
            // 2) No port in URL: /http://www.google.de/test
            ds_hstring hstr_auth(ads_wsp_helper, hstr_tmp.m_get_ptr(), in_pos);
            dsl_virtual_link.m_set_authority(hstr_auth.m_const_str());

            // Remaining part is the path of the url.
            hstr_tmp = hstr_tmp.m_substring(in_pos);
            dsl_virtual_link.m_set_path(hstr_tmp);
            
            // The port was not set in URL. Port is already set according to protocol.
        }
    }

    ads_ret->ds_v_virtual_links.m_add(dsl_virtual_link);

    return 0;
}

/*! \brief ID reader
 *
 * @ingroup configuration
 *
 * Reads a value from an ID tag
 */
int m_read_id(ds_id& dsl_id, DOMNode* ads_node_in, ds_wsp_helper* ads_wsp_helper) {
    DOMNode* ads_node = ads_wsp_helper->m_cb_get_firstchild( ads_node_in );
    if (ads_node == NULL) {
        return -1;
    }
    const HL_WCHAR* awc_node_name = NULL;
    const HL_WCHAR* awc_node_value = NULL;

    struct dsd_unicode_string dsl_unicode;
    dsl_unicode.iec_chs_str = ied_chs_utf_16;
    ds_hstring hstr_name(ads_wsp_helper); // name of the xml-tag
    ds_hstring hstr_val(ads_wsp_helper);  // value inside the xml-tag
    do {
        if ( ads_wsp_helper->m_cb_get_node_type( ads_node ) == DOMNode::ELEMENT_NODE ) {
            // get name of this node
            awc_node_name = ads_wsp_helper->m_cb_get_node_name( ads_node );
            dsl_unicode.ac_str = (void*)awc_node_name;
            dsl_unicode.imc_len_str = HL_WCSLEN(awc_node_name);
            hstr_name.m_set(&dsl_unicode);

            DOMNode* ads_work_node = ads_wsp_helper->m_cb_get_firstchild( ads_node );
            if (ads_work_node == NULL) {
                return -2;
            }

            // read value for this node
            if ( ads_wsp_helper->m_cb_get_node_type( ads_work_node ) != DOMNode::TEXT_NODE ) {
                return -2;
            }
            awc_node_value = ads_wsp_helper->m_cb_get_node_value( ads_work_node );
            dsl_unicode.ac_str = (void*)awc_node_value;
            dsl_unicode.imc_len_str = HL_WCSLEN(awc_node_value);
            hstr_val.m_set(&dsl_unicode);

            // "<name>"
            if (hstr_name.m_equals_ic(CNF_NODE_NAME)) {
                dsl_id.m_set_name(hstr_val.m_const_str());
            }
            // "<value>"
            if (hstr_name.m_equals_ic(CNF_NODE_VALUE)) {
                dsl_id.m_set_value(hstr_val.m_const_str());
            }
            // "<type>"
            if (hstr_name.m_equals_ic(CNF_NODE_TYPE)) {
                dsl_id.m_set_type(hstr_val.m_const_str());
            }
        }
        ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
    } while(ads_node);

    // TODO: Check for missing parameters
    return 0;
}

/*! \brief Read Pages
 *
 * @ingroup configuration
 *
 * Reads the Tag which refers to the id_lists
 */
int m_read_page(ds_page& dsl_page, DOMNode* ads_node_page, ds_wsp_helper* ads_wsp_helper) {
    DOMNode* ads_node = ads_wsp_helper->m_cb_get_firstchild( ads_node_page );
    if (ads_node == NULL) {
        throw 41;
    }

    DOMNode* ads_work_node = NULL;
    const HL_WCHAR* awc_node_name = NULL;
    const HL_WCHAR* awc_node_value = NULL;

    struct dsd_unicode_string dsl_unicode;
    dsl_unicode.iec_chs_str = ied_chs_utf_16;
    ds_hstring hstr_name(ads_wsp_helper); // name of the xml-tag
    ds_hstring hstr_val(ads_wsp_helper);  // value inside the xml-tag
    do {
        if ( ads_wsp_helper->m_cb_get_node_type( ads_node ) == DOMNode::ELEMENT_NODE ) {
            // get name of this node
            awc_node_name = ads_wsp_helper->m_cb_get_node_name( ads_node );
            dsl_unicode.ac_str = (void*)awc_node_name;
            dsl_unicode.imc_len_str = HL_WCSLEN(awc_node_name);
            hstr_name.m_set(&dsl_unicode);

            // "<ID-list>"
            if (hstr_name.m_equals_ic(CNF_NODE_SSO_PAGE_IDLIST)) {
                m_read_id_list(dsl_page, ads_node, ads_wsp_helper);
            }
            else {
                ads_work_node = ads_wsp_helper->m_cb_get_firstchild( ads_node );
                if (ads_work_node == NULL) {
                    throw 42;
                }

                // read value for this node
                if ( ads_wsp_helper->m_cb_get_node_type( ads_work_node ) != DOMNode::TEXT_NODE ) {
                    throw 43;
                }

                awc_node_value = ads_wsp_helper->m_cb_get_node_value( ads_work_node );
                dsl_unicode.ac_str = (void*)awc_node_value;
                dsl_unicode.imc_len_str = HL_WCSLEN(awc_node_value);
                hstr_val.m_set(&dsl_unicode);

                // "<name>"
                if (hstr_name.m_equals_ic(CNF_NODE_NAME)) { 
                    dsl_page.m_set_name(hstr_val.m_const_str());
                }

                // "<url>"
                if (hstr_name.m_equals_ic(CNF_NODE_URL)) {
						  // Workaround for old configurations (remove leading '/')
						  dsd_const_string hstr_url = hstr_val.m_const_str();
						  if(hstr_url.m_starts_with("/"))
								hstr_url = hstr_url.m_substring(1);
                    dsl_page.m_set_url(hstr_url);
                }
            }
        }
        ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
    } while(ads_node);

    // TODO: Check input
    return 0;
}

/*! \brief System Parameter Reader
 *
 * @ingroup configuration
 *
 * Read the tag <system-parameters> into a string_utf8
 */
static bool m_read_system_parameters(DOMNode* ads_node_system_parameters, ds_wsp_helper* ads_wsp_helper, ds_hstring& hstr_ret) {
    DOMNode* ads_node = ads_wsp_helper->m_cb_get_firstchild( ads_node_system_parameters );
    if (ads_node == NULL) {
        return false;
    }

    const HL_WCHAR* awc_name = NULL;
    hstr_ret.m_set("<system-parameters>");

    struct dsd_unicode_string dsl_unicode;
    dsl_unicode.iec_chs_str = ied_chs_utf_16;
    ds_hstring hstr_name(ads_wsp_helper); // name of the xml-tag
    ds_hstring hstr_val(ads_wsp_helper);  // value inside the xml-tag
    do {
        if ( ads_wsp_helper->m_cb_get_node_type( ads_node ) == DOMNode::ELEMENT_NODE ) {
            // Get name of this node: e.g. "windows" or "mac"
            awc_name = ads_wsp_helper->m_cb_get_node_name( ads_node );
            dsl_unicode.ac_str = (void*)awc_name;
            dsl_unicode.imc_len_str = HL_WCSLEN(awc_name);
            hstr_name.m_set(&dsl_unicode);

            // Read value for this node
            DOMNode* ads_work_node = ads_wsp_helper->m_cb_get_firstchild( ads_node );
            if (ads_work_node == NULL) { // Empty nodes are ignored
                ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
                continue;
            }
            
            if ( ads_wsp_helper->m_cb_get_node_type( ads_work_node ) == DOMNode::TEXT_NODE ) {
                const HL_WCHAR* awc_node_value = ads_wsp_helper->m_cb_get_node_value( ads_work_node );
                dsl_unicode.ac_str = (void*)awc_node_value;
                dsl_unicode.imc_len_str = HL_WCSLEN(awc_node_value);
                hstr_val.m_set(&dsl_unicode);

                // Add the node name and its value in XML-syntax to the return string.
                hstr_ret.m_write("<");
                hstr_ret.m_write(hstr_name);
                hstr_ret.m_write(">");
                // TODO: Escape sequence needed???
                hstr_ret.m_write(hstr_val);
                hstr_ret.m_write("</");
                hstr_ret.m_write(hstr_name);
                hstr_ret.m_write(">");
            }
        }
        ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
    } while(ads_node);

    hstr_ret.m_write("</system-parameters>");
    return true;
}


// [14387]
/*! \brief Precomp settings reader
 *
 * @ingroup configuration
 *
 * Reads extensions for the HOB precomp
 */
int m_read_sett_precomp(struct dsd_read_config* ads_ret, DOMNode* ads_node_settprecomp, ds_wsp_helper* ads_wsp_helper) {
    DOMNode* ads_node = ads_wsp_helper->m_cb_get_firstchild( ads_node_settprecomp );
    if (ads_node == NULL) {
        throw 70;
    }

    const HL_WCHAR* awc_name = NULL;
    struct dsd_unicode_string dsl_unicode;
    dsl_unicode.iec_chs_str = ied_chs_utf_16;
    ds_hstring hstr_name(ads_wsp_helper); // name of the xml-tag
    ds_hstring hstr_val(ads_wsp_helper);  // value inside the xml-tag
    do {
        if ( ads_wsp_helper->m_cb_get_node_type( ads_node ) == DOMNode::ELEMENT_NODE ) {
            awc_name = ads_wsp_helper->m_cb_get_node_name( ads_node ); // get name of this node
            dsl_unicode.ac_str = (void*)awc_name;
            dsl_unicode.imc_len_str = HL_WCSLEN(awc_name);
            hstr_name.m_set(&dsl_unicode);

            // "<extensions>"
            if (hstr_name.m_equals_ic(CNF_NODE_SETTPRECOMP_EXTENSIONS)) {
                int in_ret = m_read_extensions(ads_ret, ads_node, ads_wsp_helper);
                if (in_ret < 0) { // error
                    throw 181;
                }
            }

            // "<files>"
            if (hstr_name.m_equals_ic(CNF_NODE_SETTPRECOMP_FILES)) {
                int in_ret = m_read_files(ads_ret, ads_node, ads_wsp_helper);
                if (in_ret < 0) { // error
                    throw 171;
                }
            }
        }
        ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
    } while(ads_node);
    return 0;
}

/*! \brief Read Precomp extensions
 *
 * @ingroup configuration
 *
 * Reads the list of extensions for the HOB Precomp
 */
int m_read_extensions(struct dsd_read_config* ads_ret, DOMNode* ads_node_extensions, ds_wsp_helper* ads_wsp_helper) {
    DOMNode* ads_node = ads_wsp_helper->m_cb_get_firstchild( ads_node_extensions );
    if (ads_node == NULL) {
        return -1;
    }

    const HL_WCHAR* awc_name = NULL;
    struct dsd_unicode_string dsl_unicode;
    dsl_unicode.iec_chs_str = ied_chs_utf_16;
    ds_hstring hstr_name(ads_wsp_helper); // name of the xml-tag
    ds_hstring hstr_val(ads_wsp_helper);  // value inside the xml-tag
    do {
        if ( ads_wsp_helper->m_cb_get_node_type( ads_node ) == DOMNode::ELEMENT_NODE ) {
            awc_name = ads_wsp_helper->m_cb_get_node_name( ads_node );
            dsl_unicode.ac_str = (void*)awc_name;
            dsl_unicode.imc_len_str = HL_WCSLEN(awc_name);
            hstr_name.m_set(&dsl_unicode);

            // "<ext>"
            if (hstr_name.m_equals_ic(CNF_NODE_SETTPRECOMP_EXT)) {
                ds_hstring hstr_ext(ads_wsp_helper);
                int in_ret = m_read_ext(&hstr_ext, ads_node, ads_wsp_helper);
                if (in_ret < 0) {
                    return in_ret;
                }
                ads_ret->ds_v_precomp_exts.m_add(hstr_ext);
            }
        }
        ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
    } while(ads_node);
    return 0;
}

/*! \brief Read Custom Tags
 *
 * @ingroup configuration
 *
 * Reads contents of a custom tag
 */
int m_read_ext(ds_hstring* ahstr_ext, DOMNode* ads_node_in, ds_wsp_helper* ads_wsp_helper) {
    DOMNode* ads_node = ads_wsp_helper->m_cb_get_firstchild( ads_node_in );
    if (ads_node == NULL) {
        return -101;
    }

    const HL_WCHAR* awc_name = NULL;
    const HL_WCHAR* awc_val  = NULL;
    struct dsd_unicode_string dsl_unicode;
    dsl_unicode.iec_chs_str = ied_chs_utf_16;
    ds_hstring hstr_name(ads_wsp_helper); // name of the xml-tag
    ds_hstring hstr_val(ads_wsp_helper);  // value inside the xml-tag
    do {
        if ( ads_wsp_helper->m_cb_get_node_type( ads_node ) == DOMNode::ELEMENT_NODE ) {
            // get name of this node
            awc_name = ads_wsp_helper->m_cb_get_node_name( ads_node );
            dsl_unicode.ac_str = (void*)awc_name;
            dsl_unicode.imc_len_str = HL_WCSLEN(awc_name);
            hstr_name.m_set(&dsl_unicode);

            DOMNode* ads_work_node = ads_wsp_helper->m_cb_get_firstchild( ads_node );
            if (ads_work_node == NULL) {
                return -102;
            }

            // read value for this node
            if ( ads_wsp_helper->m_cb_get_node_type( ads_work_node ) != DOMNode::TEXT_NODE ) {
                return -103;
            }
            awc_val = ads_wsp_helper->m_cb_get_node_value( ads_work_node );
            dsl_unicode.ac_str = (void*)awc_val;
            dsl_unicode.imc_len_str = HL_WCSLEN(awc_val);
            hstr_val.m_set(&dsl_unicode);

            // "<name>"
            if (hstr_name.m_equals_ic(CNF_NODE_NAME)) {
                ahstr_ext->m_set(hstr_val);
            }
        }
        ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
    } while(ads_node);
    return 0;
}

/*! \brief Read files for the HOB Precomp
 *
 * @ingroup configuration
 *
 * Reads the files which should be modified by the precomp
 */
int m_read_files(struct dsd_read_config* ads_ret, DOMNode* ads_node_files, ds_wsp_helper* ads_wsp_helper) {
    DOMNode* ads_node = ads_wsp_helper->m_cb_get_firstchild( ads_node_files );
    if (ads_node == NULL) {
        return -1;
    }

    const HL_WCHAR* awc_name = NULL;
    struct dsd_unicode_string dsl_unicode;
    dsl_unicode.iec_chs_str = ied_chs_utf_16;
    ds_hstring hstr_name(ads_wsp_helper); // name of the xml-tag
    ds_hstring hstr_val(ads_wsp_helper);  // value inside the xml-tag
    do {
        if ( ads_wsp_helper->m_cb_get_node_type( ads_node ) == DOMNode::ELEMENT_NODE) {
            awc_name = ads_wsp_helper->m_cb_get_node_name( ads_node );
            dsl_unicode.ac_str = (void*)awc_name;
            dsl_unicode.imc_len_str = HL_WCSLEN(awc_name);
            hstr_name.m_set(&dsl_unicode);

            // "<file>"
            if (hstr_name.m_equals_ic(CNF_NODE_SETTPRECOMP_FILE)) {
                ds_hstring hstr_file(ads_wsp_helper);
                int in_ret = m_read_file(&hstr_file, ads_node, ads_wsp_helper);
                if (in_ret < 0) {
                    return in_ret;
                }
                ads_ret->ds_v_precomp_files.m_add(hstr_file);
            }
        }
        ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
    } while(ads_node);
    return 0;
}

/*! \brief Read file
 *
 * @ingroup configuration
 *
 * Read File
 */
int m_read_file(ds_hstring* ahstr_file, DOMNode* ads_node_in, ds_wsp_helper* ads_wsp_helper) {
    DOMNode* ads_node = ads_wsp_helper->m_cb_get_firstchild( ads_node_in );
    if (ads_node == NULL) {
        return -201;
    }

    const HL_WCHAR* awc_name = NULL;
    const HL_WCHAR* awc_val  = NULL;
    struct dsd_unicode_string dsl_unicode;
    dsl_unicode.iec_chs_str = ied_chs_utf_16;
    ds_hstring hstr_name(ads_wsp_helper); // name of the xml-tag
    ds_hstring hstr_val(ads_wsp_helper);  // value inside the xml-tag
    do {
        if ( ads_wsp_helper->m_cb_get_node_type( ads_node ) == DOMNode::ELEMENT_NODE ) {
            // get name of this node
            awc_name = ads_wsp_helper->m_cb_get_node_name( ads_node );
            dsl_unicode.ac_str = (void*)awc_name;
            dsl_unicode.imc_len_str = HL_WCSLEN(awc_name);
            hstr_name.m_set(&dsl_unicode);

            DOMNode* ads_work_node = ads_wsp_helper->m_cb_get_firstchild( ads_node );
            if (ads_work_node == NULL) {
                return -202;
            }

            // read value for this node
            if ( ads_wsp_helper->m_cb_get_node_type( ads_work_node ) != DOMNode::TEXT_NODE ) {
                return -203;
            }
            awc_val = ads_wsp_helper->m_cb_get_node_value( ads_work_node );
            dsl_unicode.ac_str = (void*)awc_val;
            dsl_unicode.imc_len_str = HL_WCSLEN(awc_val);
            hstr_val.m_set(&dsl_unicode);

            // "<name>"
            if (hstr_name.m_equals_ic(CNF_NODE_NAME)) {
                ahstr_file->m_set(hstr_val);
            }
        }
        ads_node = ads_wsp_helper->m_cb_get_nextsibling( ads_node );
    } while(ads_node);
    return SUCCESS;
}

/*! \brief Validate a PPP Tunnel Address
 * 
 * @ingroup configuration
 *
 * function m_validate_ppp_address
 * For the moment check is done for either IPv4 or IPv6 (see Ticket[14780])
 *
 * @param[in] char* ach_address  address to check (zero-terminated)
 * @return:   true if address is valid, false otherwise
 *
*/
bool m_validate_ppp_address(const dsd_const_string& rdsp_address)
{
    // IPv4 should look like this: 123.111.222.101:34567
    // IPv6 [2001:0db8:85a3::1319:8a2e:0370:7344]:34567

    // initialize some variables:
    bool bo_return = true;                      // return value
    const char* ach_address = rdsp_address.strc_ptr;
    int  in_length = (int)rdsp_address.inc_length;  // length of input
    int  in_pos    = 0;                         // current pos in input
    int  in_dots   = 0;                         // count dots
    int  in_nums   = 0;                         // count numbers between dots
    bool bo_port   = false;                     // port occurred
    int  in_value = 0;

    // we try to autoselect IPv4 or IPv6 validation
    // if address starts with a "[" we do IPv6 validation, 
    // otherwise IPv4 validation is done

    if ( ach_address[0] != '[' ) {
        //----------------------------------
        // do IPv4 validation:
        //----------------------------------
        for ( ; in_pos < in_length; in_pos++ ) {
            switch ( ach_address[in_pos] ) {
                case '.': 
                    in_dots++;
                    if (    !bo_port        /* no '.' in port             */
                         && in_dots < 4     /* IPv4 has exact 3 dots      */
                         && in_nums < 4     /* max 3 numbers between dots */
                         && in_nums > 0     /* min 1 number between dots  */ )
                    {

                        in_value = atoi(&ach_address[in_pos - in_nums]);  
                        if ( in_value < 0 || in_value > 255 ) {
                            break;
                        }
                        in_nums = 0;
                        continue;
                    }
                    break; // otherwise error
                case ':':
                    if (    !bo_port        /* only one port              */
                         && in_dots == 3    /* exactly 3 dots             */
                         && in_nums < 4     /* max 3 numbers between dots */
                         && in_nums > 0     /* min 1 number between dots  */ )
                    {
                        in_value = atoi(&ach_address[in_pos - in_nums]);    
                        if ( in_value < 0 || in_value > 255 ) {
                            break;
                        }
                        in_nums = 0;
                        bo_port = true;
                        continue;
                    }
                    break; // otherwise error
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    in_nums++;
                    if (    in_nums < 4     /* max 3 numbers between dots */
                         || bo_port         /* except we are in port      */ )
                    {
                        continue;
                    }
                    break; // otherwise error
                default:
                    // other char as number, '.' or ':' -> invalid address
                    break; 
            }
            bo_return = false; // an error occurred
            break;
        }

        if (      bo_return
             && ( !bo_port      /* no port       */
             ||   in_nums < 1   /* port to short */
             ||   in_nums > 5 ) /* port to long  */ )
        {
            bo_return = false;
        }
    } else {
        //----------------------------------
        // do IPv6 validation:
        //----------------------------------
        bool bo_bracket = false;
        bool bo_next_port = false;
        int  in_two_dots  = 0;
        
        for ( ; in_pos < in_length; in_pos++ ) {
            switch ( ach_address[in_pos] ) {
                case '[':
                    if (    in_pos == 0     /* bracket must be first sign */
                         && !bo_bracket     /* only one bracket           */
                         && !bo_port        /* no bracket in port         */ ) {
                        bo_bracket = true;
                        continue;
                    }
                    break; // otherwise error
                case ']':
                    if (    bo_bracket      /* '[' occurred               */
                         && in_dots < 8     /* max 7 dots                 */
                         && in_dots > 1     /* min 2 dots                 */
                         && !bo_port        /* no bracket in port         */ ) {
                        in_dots = 0;
                        in_nums = 0;
                        bo_next_port = true;
                        continue;
                    }
                    break; // otherwise error
                case ':':
                    in_dots++;
                    if (    bo_bracket
                         && !bo_port
                         && !bo_next_port   /* we are between '[' and ']' */
                         && in_two_dots < 2 /* "::" is allowed only once  */
                         && in_dots < 8     /* max 7 dots                 */
                         && in_nums < 5     /* max 4 numbers between dots */ )
                    {
                        if ( in_nums == 0 ) {
                            in_two_dots++;
                        }
                        in_nums = 0;
                        continue;
                    } else if (    bo_next_port 
                                && !bo_port     /* only one ':' in port   */  )
                    {
                        bo_next_port = false;
                        bo_port = true;
                        continue;
                    }
                    break; // otherwise error
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    if (    bo_port         /* in port only nums          */
                         && bo_bracket      /* a bracket occured          */ ) {
                        in_nums++;
                        continue;
                    }
                case 'a':
                case 'b':
                case 'c':
                case 'd':
                case 'e':
                case 'f':
                case 'A':
                case 'B':
                case 'C':
                case 'D':
                case 'E':
                case 'F':
                    in_nums++;
                    if (    bo_bracket      /* a bracket occured          */
                         && !bo_next_port   /* true = we suggest a ':'    */
                         && in_nums < 5     /* max 4 numbers between dots */
                         && !bo_port        /* not in port                */ )
                    {
                        continue;
                    }
                    break; // otherwise error
                default:
                    // other char as number, '[' or ':' -> invalid address
                    break; 
            }
            bo_return = false; // an error occurred
            break;
        }
        if (      bo_return
             && ( !bo_port      /* no port       */
             ||   in_nums < 1   /* port to short */
             ||   in_nums > 5 ) /* port to long  */ )
        {
            bo_return = false;
        }
    }
    
    // check port:
    if ( bo_return && bo_port ) {
        in_value = atoi(&ach_address[in_pos - in_nums]);
        if ( in_value < 0 || in_value > 65535 ) {
            bo_return = false;
        }
    }

    return bo_return;
} // end of m_validate_ppp_address


// Error numbers 130-139
/*! \brief Store Virtual Links
 *
 * @ingroup configuration
 *
 * Stores virtual links in a linked list
 */
int m_store_virtual_links(struct dsd_read_config* adsl_read_cfg, ds_wsp_helper* ads_helper, int* ain_pos,
                char* ach_cnf_buf, int in_len_cnf_buf) {
    struct ds_my_conf* ads_config = (struct ds_my_conf*)ach_cnf_buf;

    dsd_virtual_link* adsl_link_curr = NULL; // Current dsd_virtual_link under work
    dsd_virtual_link* adsl_link_prev = NULL; // Previous dsd_virtual_link; needed to chain the dsd_virtual_link
    for (HVECTOR_FOREACH(ds_virtual_link, adsl_cur, adsl_read_cfg->ds_v_virtual_links)) {
        const ds_virtual_link& dsl_vir_lnk = HVECTOR_GET(adsl_cur);

        // Store virtual link into config buffer.
        dsd_virtual_link ds_virli_to_write;
        memset(&ds_virli_to_write, 0, sizeof(dsd_virtual_link));
        ds_virli_to_write.in_protocol      = dsl_vir_lnk.m_get_protocol();
        ds_virli_to_write.in_port          = dsl_vir_lnk.m_get_port();
        ds_virli_to_write.in_len_alias     = dsl_vir_lnk.m_get_alias().m_get_len();
        ds_virli_to_write.in_len_url       = dsl_vir_lnk.m_get_url().m_get_len();
        ds_virli_to_write.in_len_authority = dsl_vir_lnk.m_get_authority().m_get_len();
        ds_virli_to_write.in_len_path      = dsl_vir_lnk.m_get_path().m_get_len();        
        if (!ads_helper->m_copy_to_config(&ds_virli_to_write, (int)sizeof(dsd_virtual_link), ain_pos, in_len_cnf_buf, true)) {
            return 130;
        }
        adsl_link_curr = (dsd_virtual_link*)((char*)ach_cnf_buf + *ain_pos - (int)sizeof(dsd_virtual_link));
        if (ads_config->adsl_vi_lnk == NULL) {
            // ads_config->adsl_vi_lnk is the starting point of the chained list of dsd_virtual_link
            ads_config->adsl_vi_lnk = adsl_link_curr;
        }
        // Write strings of dsd_virtual_link behind the structure and set the according pointer.
        // alias
        if (!ads_helper->m_copy_to_config(dsl_vir_lnk.m_get_alias().m_get_ptr(), dsl_vir_lnk.m_get_alias().m_get_len(), ain_pos, in_len_cnf_buf, false)) {
            return 131;
        }
        adsl_link_curr->ach_alias = (char*)ach_cnf_buf + (*ain_pos - dsl_vir_lnk.m_get_alias().m_get_len());

        // url
        if (!ads_helper->m_copy_to_config(dsl_vir_lnk.m_get_url().m_get_ptr(), dsl_vir_lnk.m_get_url().m_get_len(), ain_pos, in_len_cnf_buf, false)) {
            return 132;
        }
        adsl_link_curr->ach_url = (char*)ach_cnf_buf + (*ain_pos - dsl_vir_lnk.m_get_url().m_get_len());

        // authority
        if (!ads_helper->m_copy_to_config(dsl_vir_lnk.m_get_authority().m_get_ptr(), dsl_vir_lnk.m_get_authority().m_get_len(), ain_pos, in_len_cnf_buf, false)) {
            return 133;
        }
        adsl_link_curr->ach_authority = (char*)ach_cnf_buf + (*ain_pos - dsl_vir_lnk.m_get_authority().m_get_len());

        // path
        if (!ads_helper->m_copy_to_config(dsl_vir_lnk.m_get_path().m_get_ptr(), dsl_vir_lnk.m_get_path().m_get_len(), ain_pos, in_len_cnf_buf, false)) {
            return 134;
        }
        adsl_link_curr->ach_path = (char*)ach_cnf_buf + (*ain_pos - dsl_vir_lnk.m_get_path().m_get_len());


        // Put this dsd_pppt into the chain of dsd_pppt
        if (adsl_link_prev != NULL) {
            adsl_link_prev->adsc_next = adsl_link_curr;
        }

        // store a pointer to this dsd_pppt
        adsl_link_prev = adsl_link_curr;
    }

    return SUCCESS;
}

// Error numbers 120-129
/*! \brief Store PPP Tunnel Infos
 *
 * @ingroup configuration
 *
 * Writes the PPP Tunnel Informations from the configuration into a linked list in memory
 */
int m_store_pppt(struct dsd_read_config* adsl_read_cfg, ds_wsp_helper* ads_helper, int* ain_pos,
                char* ach_cnf_buf, int in_len_cnf_buf) {

    struct ds_my_conf* ads_config = (struct ds_my_conf*)ach_cnf_buf;

    dsd_pppt* adsl_pppt_curr = NULL; // Current dsd_pppt under work
    dsd_pppt* adsl_pppt_prev = NULL; // Previous dsd_pppt; needed to chain the dsd_pppt
    for (HVECTOR_FOREACH(ds_ppp_tunnel, adsl_cur, adsl_read_cfg->ds_v_ppp_tunnels)) {
        const ds_ppp_tunnel& dsl_ppp_tunnel = HVECTOR_GET(adsl_cur);

        // Store ds_ppp_tunnel as dsd_pppt into config buffer.
        dsd_pppt ds_pppt_to_write;
        memset(&ds_pppt_to_write, 0, sizeof(dsd_pppt));
        ds_pppt_to_write.in_id                     = dsl_ppp_tunnel.m_get_id();
        ds_pppt_to_write.in_len_address            = dsl_ppp_tunnel.m_get_address().m_get_len();
        ds_pppt_to_write.in_len_localhost          = dsl_ppp_tunnel.m_get_localhost().m_get_len();
        ds_pppt_to_write.in_len_server_entry_name  = dsl_ppp_tunnel.m_get_server_entry_name().m_get_len();
        ds_pppt_to_write.in_len_system_parameters  = dsl_ppp_tunnel.m_get_system_parameters().m_get_len();        
        if (!ads_helper->m_copy_to_config(&ds_pppt_to_write, (int)sizeof(dsd_pppt), ain_pos, in_len_cnf_buf, true)) {
            return 120;
        }
        adsl_pppt_curr = (dsd_pppt*)((char*)ach_cnf_buf + *ain_pos - (int)sizeof(dsd_pppt));
        if (ads_config->adsl_pppt == NULL) {
            // ads_config->dsl_pppt is the starting point of the chained list of dsd_pppt
            ads_config->adsl_pppt = adsl_pppt_curr;
        }
        // Write strings of dsd_pppt behind the structure and set the according pointer.
        // address
        if (!ads_helper->m_copy_to_config(dsl_ppp_tunnel.m_get_address().m_get_ptr(), dsl_ppp_tunnel.m_get_address().m_get_len(), ain_pos, in_len_cnf_buf, false)) {
            return 121;
        }
        adsl_pppt_curr->ach_address = (char*)ach_cnf_buf + (*ain_pos - dsl_ppp_tunnel.m_get_address().m_get_len());

        // localhost
        if (!ads_helper->m_copy_to_config(dsl_ppp_tunnel.m_get_localhost().m_get_ptr(), dsl_ppp_tunnel.m_get_localhost().m_get_len(), ain_pos, in_len_cnf_buf, false)) {
            return 122;
        }
        adsl_pppt_curr->ach_localhost = (char*)ach_cnf_buf + (*ain_pos - dsl_ppp_tunnel.m_get_localhost().m_get_len());

        // server-entry-name
        if (!ads_helper->m_copy_to_config(dsl_ppp_tunnel.m_get_server_entry_name().m_get_ptr(), dsl_ppp_tunnel.m_get_server_entry_name().m_get_len(), ain_pos, in_len_cnf_buf, false)) {
            return 123;
        }
        adsl_pppt_curr->ach_server_entry_name = (char*)ach_cnf_buf + (*ain_pos - dsl_ppp_tunnel.m_get_server_entry_name().m_get_len());

        // system_parameters
        if (!ads_helper->m_copy_to_config(dsl_ppp_tunnel.m_get_system_parameters().m_get_ptr(), dsl_ppp_tunnel.m_get_system_parameters().m_get_len(), ain_pos, in_len_cnf_buf, false)) {
            return 124;
        }
        adsl_pppt_curr->ach_system_parameters = (char*)ach_cnf_buf + (*ain_pos - dsl_ppp_tunnel.m_get_system_parameters().m_get_len());


        // Put this dsd_pppt into the chain of dsd_pppt
        if (adsl_pppt_prev != NULL) {
            adsl_pppt_prev->adsc_next = adsl_pppt_curr;
        }

        // store a pointer to this dsd_pppt
        adsl_pppt_prev = adsl_pppt_curr;
    }

    return SUCCESS;
}


// Error numbers 101-119
/*! \brief Store Single Sign On Informations
 *
 * @ingroup configuration
 *
 * Gets the information about Single Sign On from the configuration and stores it
 */
int m_store_sso(struct dsd_read_config* adsl_read_cfg, ds_wsp_helper* ads_helper, int* ain_pos,
                char* ach_cnf_buf, int in_len_cnf_buf) {

    struct ds_my_conf* ads_config = (struct ds_my_conf*)ach_cnf_buf;

    dsd_page* adsl_page_prev = NULL; // Previous page; needed to chain the pages
    for (HVECTOR_FOREACH(ds_page, adsl_cur, adsl_read_cfg->ds_v_sso_pages)) {
        const ds_page& dsl_page = HVECTOR_GET(adsl_cur);
		  int inl_page_start_pos = *ain_pos;

        // Store ds_page as dsd_page into config buffer.
        dsd_page ds_page_to_write;
        memset(&ds_page_to_write, 0, sizeof(dsd_page));
        ds_page_to_write.inc_len_name = dsl_page.m_get_name().m_get_len();
        ds_page_to_write.inc_len_url  = dsl_page.m_get_url().m_get_len();
        if (!ads_helper->m_copy_to_config(&ds_page_to_write, (int)sizeof(dsd_page), ain_pos, in_len_cnf_buf, true)) {
            return 101;
        }
        dsd_page* adsl_page_curr = (dsd_page*)((char*)ach_cnf_buf + *ain_pos - (int)sizeof(dsd_page));
        if (ads_config->dsl_sso.adsc_page == NULL) {
            // ads_config->dsl_sso_config.adsc_page is the starting point of the chained list of pages
            ads_config->dsl_sso.adsc_page = adsl_page_curr;
        }
        // Write strings of dsd_page behind the structure and set the according pointer.
        // name
        if (!ads_helper->m_copy_to_config(dsl_page.m_get_name().m_get_ptr(), dsl_page.m_get_name().m_get_len(), ain_pos, in_len_cnf_buf, false)) {
            return 102;
        }
        adsl_page_curr->achc_name = (char*)ach_cnf_buf + (*ain_pos - dsl_page.m_get_name().m_get_len());
        // url
        if (!ads_helper->m_copy_to_config(dsl_page.m_get_url().m_get_ptr(), dsl_page.m_get_url().m_get_len(), ain_pos, in_len_cnf_buf, false)) {
            return 103;
        }
        adsl_page_curr->achc_url = (char*)ach_cnf_buf + (*ain_pos - dsl_page.m_get_url().m_get_len());
		  dsd_const_string hstr_url(adsl_page_curr->achc_url, adsl_page_curr->inc_len_url);
		  if(!ds_url::m_parse_base_url(hstr_url, adsl_page_curr->dsc_url)) {
			  //ds_url::m_reset_base_url(adsl_page_curr->dsc_url);
			  ads_helper->m_logf( ied_sdh_log_error,
               "HIWSE401E: invalid SSO page URL %.*s",
					hstr_url.m_get_len(), hstr_url.m_get_ptr() );
			  *ain_pos = inl_page_start_pos;
			  continue; 
		  }

        //<IDs>
        const ds_hvector<ds_id>& dsl_v_ids = dsl_page.m_get_ids();
        dsd_id* adsl_id_curr = NULL; // Current ID under work
		  dsd_id* adsl_id_prev = NULL; // Previous ID; needed to chain the IDs
        for (HVECTOR_FOREACH(ds_id, adsl_cur2, dsl_v_ids)) {
            const ds_id& dsl_id = HVECTOR_GET(adsl_cur2);

            // Store ds_id as dsd_id into config buffer.
            dsd_id ds_id_to_write;
            memset(&ds_id_to_write, 0, sizeof(dsd_id));
            ds_id_to_write.inc_len_name  = dsl_id.m_get_name().m_get_len();
            ds_id_to_write.inc_len_value = dsl_id.m_get_value().m_get_len();
            ds_id_to_write.inc_len_type  = dsl_id.m_get_type().m_get_len();
            if (!ads_helper->m_copy_to_config(&ds_id_to_write, (int)sizeof(dsd_id), ain_pos, in_len_cnf_buf, true)) {
                return 104;
            }
            adsl_id_curr = (dsd_id*)((char*)ach_cnf_buf + *ain_pos - (int)sizeof(dsd_id));
            if (adsl_page_curr->adsc_ids == NULL) {
                // adsl_page_curr->adsc_ids is the starting point of the chained list of IDs
                adsl_page_curr->adsc_ids = adsl_id_curr;
            }
            // Write strings of dsd_id behind the structure and set the according pointer.
            // name
            if (!ads_helper->m_copy_to_config(dsl_id.m_get_name().m_get_ptr(), dsl_id.m_get_name().m_get_len(), ain_pos, in_len_cnf_buf, false)) {
                return 105;
            }
            adsl_id_curr->achc_name = (char*)ach_cnf_buf + (*ain_pos - dsl_id.m_get_name().m_get_len());
            // value
            if (!ads_helper->m_copy_to_config(dsl_id.m_get_value().m_get_ptr(), dsl_id.m_get_value().m_get_len(), ain_pos, in_len_cnf_buf, false)) {
                return 106;
            }
            adsl_id_curr->achc_value = (char*)ach_cnf_buf + (*ain_pos - dsl_id.m_get_value().m_get_len());
            // type
            if (!ads_helper->m_copy_to_config(dsl_id.m_get_type().m_get_ptr(), dsl_id.m_get_type().m_get_len(), ain_pos, in_len_cnf_buf, false)) {
                return 107;
            }
            adsl_id_curr->achc_type = (char*)ach_cnf_buf + (*ain_pos - dsl_id.m_get_type().m_get_len());

            // Put this ID into the chain of IDs
            if (adsl_id_prev != NULL) {
                adsl_id_prev->adsc_next = adsl_id_curr;
            }

            // store a pointer to this dsd_page
            adsl_id_prev = adsl_id_curr;
        }

        // Put this page into the chain of pages
        if (adsl_page_prev != NULL) {
            adsl_page_prev->adsc_next = adsl_page_curr;
        }
        // store a pointer to this dsd_page
        adsl_page_prev = adsl_page_curr;
    }

    return SUCCESS;
}


// Error numbers 201-299
/*! \brief Store Precomp informations
 *
 * @ingroup configuration
 *
 * Stores the Precomp informations in a linked list
 */
int m_store_precomp(struct dsd_read_config* adsl_read_cfg, ds_wsp_helper* ads_helper, int* ain_pos,
                char* ach_cnf_buf, int in_len_cnf_buf) {

    struct ds_my_conf* ads_config = (struct ds_my_conf*)ach_cnf_buf;

    // extensions
    dsd_named_list* adsl_ext_curr = NULL; // Current extension under work
    dsd_named_list* adsl_ext_prev = NULL; // Previous extension; needed to chain the extensions
    for (HVECTOR_FOREACH(ds_hstring, adsl_cur, adsl_read_cfg->ds_v_precomp_exts)) {
        const ds_hstring& hstr_ext = HVECTOR_GET(adsl_cur);

        // Store ds_ext as dsd_ext into config buffer.
        dsd_named_list ds_ext_to_write;
        memset(&ds_ext_to_write, 0, sizeof(dsd_named_list));
        ds_ext_to_write.inc_len_name = hstr_ext.m_get_len();
        if (!ads_helper->m_copy_to_config(&ds_ext_to_write, (int)sizeof(dsd_named_list), ain_pos, in_len_cnf_buf, true)) {
            return 201;
        }
        adsl_ext_curr = (dsd_named_list*)((char*)ach_cnf_buf + *ain_pos - (int)sizeof(dsd_named_list));
        if (ads_config->dsl_precomp.adsc_ext == NULL) {
            // ads_config->dsl_precomp.adsc_ext is the starting point of the chained list of extensions
            ads_config->dsl_precomp.adsc_ext = adsl_ext_curr;
        }
        // Write strings of dsd_ext behind the structure and set the according pointer.
        // name
        if (!ads_helper->m_copy_to_config(hstr_ext.m_get_ptr(), hstr_ext.m_get_len(), ain_pos, in_len_cnf_buf, false)) {
            return 202;
        }
        adsl_ext_curr->achc_name = (char*)ach_cnf_buf + (*ain_pos - hstr_ext.m_get_len());

        // Put this extension into the chain of extensions
        if (adsl_ext_prev != NULL) {
            adsl_ext_prev->adsc_next = adsl_ext_curr;
        }

        // store a pointer to this dsd_ext
        adsl_ext_prev = adsl_ext_curr;
    }

    // files
    dsd_named_list* adsl_file_curr = NULL; // Current file under work
    dsd_named_list* adsl_file_prev = NULL; // Previous file; needed to chain the files
    for (HVECTOR_FOREACH(ds_hstring, adsl_cur, adsl_read_cfg->ds_v_precomp_files)) {
        const ds_hstring& hstr_file = HVECTOR_GET(adsl_cur);

        // Store ds_file as dsd_file into config buffer.
        dsd_named_list ds_file_to_write;
        memset(&ds_file_to_write, 0, sizeof(dsd_named_list));
        ds_file_to_write.inc_len_name = hstr_file.m_get_len();
        if (!ads_helper->m_copy_to_config(&ds_file_to_write, (int)sizeof(dsd_named_list), ain_pos, in_len_cnf_buf, true)) {
            return 203;
        }
        adsl_file_curr = (dsd_named_list*)((char*)ach_cnf_buf + *ain_pos - (int)sizeof(dsd_named_list));
        if (ads_config->dsl_precomp.adsc_file == NULL) {
            // ads_config->dsl_precomp.adsc_file is the starting point of the chained list of files
            ads_config->dsl_precomp.adsc_file = adsl_file_curr;
        }
        // Write strings of dsd_file behind the structure and set the according pointer.
        // name
        if (!ads_helper->m_copy_to_config(hstr_file.m_get_ptr(), hstr_file.m_get_len(), ain_pos, in_len_cnf_buf, false)) {
            return 204;
        }
        adsl_file_curr->achc_name = (char*)ach_cnf_buf + (*ain_pos - hstr_file.m_get_len());

        // Put this file into the chain of files
        if (adsl_file_prev != NULL) {
            adsl_file_prev->adsc_next = adsl_file_curr;
        }

        // store a pointer to this dsd_file
        adsl_file_prev = adsl_file_curr;
    }

    return SUCCESS;
}

/*
    known child tags in ws-server-list
*/
static const dsd_const_string achrg_ws_srv_lst_tags[] = {
    CNF_NODE_WS_SRV_LST_NAME,
    CNF_NODE_WS_SRV_LST_SRV_ETR
};
enum ied_ws_srv_lst_tags {
    ied_ws_srv_lst_unknown   = -1,
    ied_ws_srv_lst_name      =  0,
    ied_ws_srv_lst_srv_entry =  1
};


/*! \brief Receive Key (list)
 *
 * @ingroup configuration
 *
 * private method m_get_ws_srv_lst_key
 *  get key for valid webserver server-list tags
 *
 * @param[in]   HL_WCHAR                *awp_tag    tag name
 * @return      ied_ws_srv_list_tags                key
*/
static enum ied_ws_srv_lst_tags m_get_ws_srv_lst_key( const HL_WCHAR *awp_tag )
{
    dsd_unicode_string dsl_key;
    dsl_key.ac_str = (void*)awp_tag;
    dsl_key.imc_len_str = -1;
    dsl_key.iec_chs_str = ied_chs_utf_16;
    return ds_wsp_helper::m_search_equals_ic2(achrg_ws_srv_lst_tags, dsl_key, ied_ws_srv_lst_unknown);
} /* end of m_get_ws_srv_lst_key */

static const dsd_const_string achrg_ws_srv_entry_tags[] = {
    CNF_NODE_WS_SRV_LST_NAME,
    CNF_NODE_WS_SRV_LST_SRV_ETR_FNC,
    CNF_NODE_WS_SRV_LST_SRV_ETR_URL,
};
enum ied_ws_srv_entry_tags {
    ied_ws_srv_entry_unknown = -1,
    ied_ws_srv_entry_name    =  0,
    ied_ws_srv_entry_func    =  1,
    ied_ws_srv_entry_url     =  2
};

/*! \brief Receive Key (entry)
 *
 * @ingroup configuration
 *
 * private method m_get_ws_srv_entry_key
 *  get key for valid wevserver server-entry tags
 *
 * @param[in]   const HL_WCHAR                *awp_tag    tag name
 * @return      ied_ws_srv_entry_tags               key
*/
static enum ied_ws_srv_entry_tags m_get_ws_srv_entry_key( const HL_WCHAR *awp_tag )
{
    dsd_unicode_string dsl_key;
    dsl_key.ac_str = (void*)awp_tag;
    dsl_key.imc_len_str = -1;
    dsl_key.iec_chs_str = ied_chs_utf_16;
    return ds_wsp_helper::m_search_equals_ic2(achrg_ws_srv_entry_tags, dsl_key, ied_ws_srv_entry_unknown);
} /* end of m_get_ws_srv_entry_key */


/*! \brief Read server entry
 *
 * @ingroup configuration
 *
 * private method m_read_ws_srv_entry
 *  read webserver server entry configuration
 *
 * @param[out]  dsd_srv_entry   *adsp_srv_entry     output class
 * @param[in]   DOMNode         *adsp_node          current node
 * @param[in]   ds_wsp_helper   *adsp_wsp_helper    wsp helper class
 * @return      BOOL                                TRUE = success
 *                                                  FALSE otherwise
*/
static BOOL m_read_ws_srv_entry( dsd_srv_entry *adsp_srv_entry,
                                 DOMNode *adsp_node,
                                 ds_wsp_helper *adsp_wsp_helper )
{
    DOMNode                    *adsl_cnode;     /* child node            */
    const HL_WCHAR                   *awl_name;       /* node name             */
    enum ied_ws_srv_entry_tags ienl_key;        /* tag key               */
    struct dsd_unicode_string  dsl_value;       /* node value in unicode */
    bool                       bol_ret;         /* return                */

    while ( adsp_node != NULL ) {
        if ( adsp_wsp_helper->m_cb_get_node_type( adsp_node ) != DOMNode::ELEMENT_NODE ) {
            adsp_node = adsp_wsp_helper->m_cb_get_nextsibling( adsp_node );
            continue;
        }

        awl_name = adsp_wsp_helper->m_cb_get_node_name( adsp_node );

        ienl_key = m_get_ws_srv_entry_key( awl_name );
        switch ( ienl_key ) {
            case ied_ws_srv_entry_name:
                adsl_cnode = adsp_wsp_helper->m_cb_get_firstchild( adsp_node );
                if ( adsp_wsp_helper->m_cb_get_node_type(adsl_cnode) != DOMNode::TEXT_NODE ) {
                    adsp_node = adsp_wsp_helper->m_cb_get_nextsibling( adsp_node );
                    continue;
                }
                dsl_value.ac_str = (void*)adsp_wsp_helper->m_cb_get_node_value( adsl_cnode );
                dsl_value.imc_len_str = -1;
                dsl_value.iec_chs_str = ied_chs_utf_16;
                bol_ret = adsp_srv_entry->m_set_name( &dsl_value );
                if ( bol_ret == false ) {
                    adsp_wsp_helper->m_logf2( ied_sdh_log_error,
                                             "multiple nodes '%(.*)s' found in line %d / column %d found - ignored",
                                             ied_chs_utf_16, awl_name,
                                             adsp_wsp_helper->m_cb_get_node_line( adsp_node ),
                                             adsp_wsp_helper->m_cb_get_node_colm( adsp_node ) );
                }
                break;

            case ied_ws_srv_entry_func:
                adsl_cnode = adsp_wsp_helper->m_cb_get_firstchild( adsp_node );
                if ( adsp_wsp_helper->m_cb_get_node_type(adsl_cnode) != DOMNode::TEXT_NODE ) {
                    adsp_node = adsp_wsp_helper->m_cb_get_nextsibling( adsp_node );
                    continue;
                }
                dsl_value.ac_str = (void*)adsp_wsp_helper->m_cb_get_node_value( adsl_cnode );
                dsl_value.imc_len_str = -1;
                dsl_value.iec_chs_str = ied_chs_utf_16;
                bol_ret = adsp_srv_entry->m_set_func( &dsl_value );
                if ( bol_ret == false ) {
                    adsp_wsp_helper->m_logf( ied_sdh_log_error,
                                             "unknown function found in line %d / column %d found - ignored",
                                             adsp_wsp_helper->m_cb_get_node_line( adsp_node ),
                                             adsp_wsp_helper->m_cb_get_node_colm( adsp_node ) );
                }
                break;

            case ied_ws_srv_entry_url:
                adsl_cnode = adsp_wsp_helper->m_cb_get_firstchild( adsp_node );
                if ( adsp_wsp_helper->m_cb_get_node_type(adsl_cnode) != DOMNode::TEXT_NODE ) {
                    adsp_node = adsp_wsp_helper->m_cb_get_nextsibling( adsp_node );
                    continue;
                }
                dsl_value.ac_str = (void*)adsp_wsp_helper->m_cb_get_node_value( adsl_cnode );
                dsl_value.imc_len_str = -1;
                dsl_value.iec_chs_str = ied_chs_utf_16;
                bol_ret = adsp_srv_entry->m_set_url( &dsl_value );
                if ( bol_ret == false ) {
                    adsp_wsp_helper->m_logf2( ied_sdh_log_error,
                                             "multiple nodes '%(.*)s' found in line %d / column %d found - ignored",
                                             ied_chs_utf_16, awl_name,
                                             adsp_wsp_helper->m_cb_get_node_line( adsp_node ),
                                             adsp_wsp_helper->m_cb_get_node_colm( adsp_node ) );
                }
                break;

            default:
                adsp_wsp_helper->m_logf2( ied_sdh_log_error,
                                         "unknown node '%(.*)s' found in line %d / column %d found",
                                         ied_chs_utf_16, awl_name,
                                         adsp_wsp_helper->m_cb_get_node_line( adsp_node ),
                                         adsp_wsp_helper->m_cb_get_node_colm( adsp_node ) );
                break;
        }

        /* get next node */
        adsp_node = adsp_wsp_helper->m_cb_get_nextsibling( adsp_node );
    } /* end of while */

    return TRUE;
} /* end if m_read_ws_srv_entry */


/*! \brief Read Server List Configuration
 *
 * @ingroup configuration
 *
 * private method m_read_ws_srv_lst
 *  read webserver server-list configuration
 *
 * @param[out]  dsd_read_config *adsp_config        temporary output structure
 * @param[in]   DOMNode         *adsp_node          current node
 * @param[in]   ds_wsp_helper   *adsp_wsp_helper    wsp helper class
 * @return      BOOL                                TRUE = success
 *                                                  FALSE otherwise
 * example:
 *   <ws-server-list>
 *     <name>ServerList1</name>
 *     <server-entry>
 *       <name>ServerEntry1</name>
 *       <function>ICA</function>
 *       <url>http://w2008citrix.hob.de</url>
 *     </server-entry>
 *     ...
 *     <server-entry>
 *       ...
 *     </server-entry>
 *   </ws-server-list>
 *   ...
 *   <ws-server-list>
 *     ...
 *   </ws-server-list>
*/
static BOOL m_read_ws_srv_lst( struct dsd_read_config *adsp_config,
                               DOMNode *adsp_node,
                               ds_wsp_helper *adsp_wsp_helper )
{
    DOMNode                   *adsl_cnode;      /* child node            */
    const HL_WCHAR                  *awl_name;        /* node name             */
    enum ied_ws_srv_lst_tags  ienl_key;         /* tag key               */
    struct dsd_unicode_string dsl_value;        /* node value in unicode */
    dsd_srv_list              dsl_srv_list;     /* new server list       */
    dsd_srv_entry             dsl_srv_entry;    /* new server entry      */
    bool                      bol_valid;        /* return                */
    BOOL                      bol_ret;          /* return from entry     */

    adsp_config->dsc_srv_lists.m_init( adsp_wsp_helper );
    dsl_srv_list.m_init( adsp_wsp_helper );
    dsl_srv_entry.m_init( adsp_wsp_helper );

    while ( adsp_node != NULL ) {
        if ( adsp_wsp_helper->m_cb_get_node_type( adsp_node ) != DOMNode::ELEMENT_NODE ) {
            adsp_node = adsp_wsp_helper->m_cb_get_nextsibling( adsp_node );
            continue;
        }

        awl_name = adsp_wsp_helper->m_cb_get_node_name( adsp_node );

        ienl_key = m_get_ws_srv_lst_key( awl_name );
        switch ( ienl_key ) {
            case ied_ws_srv_lst_name:
                adsl_cnode = adsp_wsp_helper->m_cb_get_firstchild( adsp_node );
                if ( adsp_wsp_helper->m_cb_get_node_type(adsl_cnode) != DOMNode::TEXT_NODE ) {
                    continue;
                }
                dsl_value.ac_str = (void*)adsp_wsp_helper->m_cb_get_node_value( adsl_cnode );
                dsl_value.imc_len_str = -1;
                dsl_value.iec_chs_str = ied_chs_utf_16;
                bol_valid = dsl_srv_list.m_set_name( &dsl_value );
                if ( bol_valid == false ) {
                    adsp_wsp_helper->m_logf2( ied_sdh_log_error,
                                             "multiple nodes '%(.*)s' found in line %d / column %d found - ignored",
                                             ied_chs_utf_16, awl_name,
                                             adsp_wsp_helper->m_cb_get_node_line( adsp_node ),
                                             adsp_wsp_helper->m_cb_get_node_colm( adsp_node ) );
                }
                break;

            case ied_ws_srv_lst_srv_entry:
                dsl_srv_entry.m_reset();
                adsl_cnode = adsp_wsp_helper->m_cb_get_firstchild( adsp_node );
                bol_ret = m_read_ws_srv_entry( &dsl_srv_entry, adsl_cnode, adsp_wsp_helper );
                if ( bol_ret == FALSE ) {
                    adsp_wsp_helper->m_logf2( ied_sdh_log_error,
                                             "cannot read '%(.*)s' found in line %d / column %d found - ignored",
                                             ied_chs_utf_16, awl_name,
                                             adsp_wsp_helper->m_cb_get_node_line( adsp_node ),
                                             adsp_wsp_helper->m_cb_get_node_colm( adsp_node ) );
                } else if ( dsl_srv_entry.m_is_complete() ) {
                    dsl_srv_list.m_add_srv_entry( dsl_srv_entry );
                }
                break;

            default:
                adsp_wsp_helper->m_logf2( ied_sdh_log_error,
                                         "unknown node '%(.*)s' found in line %d / column %d found",
                                         ied_chs_utf_16, awl_name,
                                         adsp_wsp_helper->m_cb_get_node_line( adsp_node ),
                                         adsp_wsp_helper->m_cb_get_node_colm( adsp_node ) );
                break;
        }

        /* get next node */
        adsp_node = adsp_wsp_helper->m_cb_get_nextsibling( adsp_node );
    } /* end of while */

    if ( dsl_srv_list.m_is_complete() ) {
        adsp_config->dsc_srv_lists.m_add( dsl_srv_list );
    }
    return TRUE;
} /* end of m_read_ws_srv_lst */


/*! \brief Save Server List in memory
 *
 * @ingroup configuration
 *
 * private method m_write_ws_srv_lst
 *  save webserver server-list in configuration memory
 *
 * @param[in]     dsd_read_config   *adsp_config        config from xml
 * @param[in]     char              *achp_config        configuration memory
 * @param[in]     int               inp_length          length of config memory
 * @param[in/out] int               *ainp_pos           offset in config memory
 * @return        BOOL                                  TRUE = success
 *                                                      FALSE otherwise
*/
static BOOL m_write_ws_srv_lst( struct dsd_read_config *adsp_config,
                                char *achp_config, int inp_length,
                                int *ainp_pos, ds_wsp_helper *adsp_wsp_helper )
{
    struct ds_my_conf       *adsl_config;       /* configuration struct  */
    struct dsd_ws_srv_lst   *adsl_list;         /* server list output    */
    struct dsd_ws_srv_lst   *adsl_prev_list;    /* previous server list  */
    struct dsd_ws_srv_entry *adsl_entry;        /* server entry output   */
    struct dsd_ws_srv_entry *adsl_prev_entry;   /* previous server entry */
    
    if( adsp_config->dsc_srv_lists.m_empty() ) {
        /* no data to save */
        return TRUE;
    }
    adsl_config = (struct ds_my_conf*)achp_config;

    adsl_prev_list = NULL;
    for (HVECTOR_FOREACH(dsd_srv_list, adsl_cur, adsp_config->dsc_srv_lists)) {
        const dsd_srv_list& dsl_list = HVECTOR_GET(adsl_cur);

        /* insert server list structure */
        *ainp_pos    = ALIGN_INT((*ainp_pos));
        adsl_list    = (struct dsd_ws_srv_lst*)(achp_config + (*ainp_pos));
        (*ainp_pos) += (int)sizeof(struct dsd_ws_srv_lst);
        adsl_list->adsc_next = NULL;

        /* set next pointer */
        if ( adsl_prev_list != NULL ) {
            adsl_prev_list->adsc_next = adsl_list;
        } else {
            adsl_config->adsc_ws_srv_lst = adsl_list;
        }
        adsl_prev_list = adsl_list;
        
        /* insert name of server list */
        adsl_list->achc_name    = achp_config + (*ainp_pos);
        adsl_list->inc_len_name = dsl_list.dsc_name.m_get_len();
        memcpy( adsl_list->achc_name, dsl_list.dsc_name.m_get_ptr(),
                adsl_list->inc_len_name );
        (*ainp_pos) += adsl_list->inc_len_name;

        /* insert server entries */
        adsl_prev_entry = NULL;
        for (HVECTOR_FOREACH(dsd_srv_entry, adsl_cur2, dsl_list.dsc_srv_entries)) {
            const dsd_srv_entry& dsl_entry = HVECTOR_GET(adsl_cur2);
				int inl_start_pos = *ainp_pos;

            /* insert server entry structure */
            *ainp_pos    = ALIGN_INT((*ainp_pos));
            adsl_entry   = (struct dsd_ws_srv_entry*)(achp_config + (*ainp_pos));
            (*ainp_pos) += (int)sizeof(struct dsd_ws_srv_entry);
            adsl_entry->adsc_next = NULL;

            /* insert name of server entry */
            adsl_entry->achc_name    = achp_config + (*ainp_pos);
            adsl_entry->inc_len_name = dsl_entry.dsc_name.m_get_len();
            memcpy( adsl_entry->achc_name, dsl_entry.dsc_name.m_get_ptr(),
                    adsl_entry->inc_len_name );
            (*ainp_pos) += adsl_entry->inc_len_name;

            /* insert url of server entry */
            adsl_entry->achc_url    = achp_config + (*ainp_pos);
            adsl_entry->inc_len_url = dsl_entry.dsc_url.m_get_len();
            memcpy( adsl_entry->achc_url, dsl_entry.dsc_url.m_get_ptr(),
                    adsl_entry->inc_len_url );
				dsd_const_string hstr_url(adsl_entry->achc_url, adsl_entry->inc_len_url);
				if(!ds_url::m_parse_base_url(hstr_url, adsl_entry->dsc_url)) {
					adsp_wsp_helper->m_logf( ied_sdh_log_error,
                  "HIWSE400E: invalid server-list URL %.*s",
						hstr_url.m_get_len(), hstr_url.m_get_ptr() );
					*ainp_pos = inl_start_pos;
					continue;
				}
            (*ainp_pos) += adsl_entry->inc_len_url;

            /* save function */
            adsl_entry->iec_func = dsl_entry.iec_func;

            /* set next pointer */
            if ( adsl_prev_entry != NULL ) {
                adsl_prev_entry->adsc_next = adsl_entry;
            } else {
                adsl_list->adsc_entries = adsl_entry;
            }
            adsl_prev_entry = adsl_entry;
        }
    }

    return ((*ainp_pos <= inp_length)?TRUE:FALSE);
} /* end of m_write_ws_srv_lst */


/*! \brief Save ICA pages in memory
 *
 * @ingroup configuration
 *
 * private method m_write_ica_pages
 *  save ica pages in configuration memory
 *
 * @param[in]     dsd_read_config   *adsp_config        config from xml
 * @param[in]     char              *achp_config        configuration memory
 * @param[in]     int               inp_length          length of config memory
 * @param[in/out] int               *ainp_pos           offset in config memory
 * @return        BOOL                                  TRUE = success
 *                                                      FALSE otherwise
*/
static BOOL m_write_ica_pages( struct dsd_read_config *adsp_config,
                               char *achp_config, int inp_length,
                               int *ainp_pos )
{
    struct ds_my_conf       *adsl_config;       /* configuration struct  */
    struct dsd_named_list   *adsl_cur;          /* current name output   */
    struct dsd_named_list   *adsl_prev;         /* previous name output  */
    
    adsl_config = (struct ds_my_conf*)achp_config;

    if ( !adsp_config->dsc_ica_login.m_empty() ) {
        adsl_prev = NULL;
        for (HVECTOR_FOREACH(ds_hstring, adsl_cur2, adsp_config->dsc_ica_login)) {
            const ds_hstring& dsl_name = HVECTOR_GET(adsl_cur2);
            /* insert list structure */
            *ainp_pos    = ALIGN_INT((*ainp_pos));
            adsl_cur    = (struct dsd_named_list*)(achp_config + (*ainp_pos));
            (*ainp_pos) += (int)sizeof(struct dsd_named_list);
            adsl_cur->adsc_next = NULL;

            /* set next pointer */
            if ( adsl_prev != NULL ) {
                adsl_prev->adsc_next = adsl_cur;
            } else {
                adsl_config->adsc_ica_login_pages = adsl_cur;
            }
            adsl_prev = adsl_cur;
        
            /* insert name of login page */
            adsl_cur->achc_name    = achp_config + (*ainp_pos);
            adsl_cur->inc_len_name = dsl_name.m_get_len();
            memcpy( adsl_cur->achc_name, dsl_name.m_get_ptr(),
                    adsl_cur->inc_len_name );
            (*ainp_pos) += adsl_cur->inc_len_name;
        }
    }

    adsl_prev = NULL;
    for (HVECTOR_FOREACH(ds_hstring, adsl_cur2, adsp_config->dsc_ica_session)) {
        const ds_hstring& dsl_name = HVECTOR_GET(adsl_cur2);

        /* insert list structure */
        *ainp_pos    = ALIGN_INT((*ainp_pos));
        adsl_cur    = (struct dsd_named_list*)(achp_config + (*ainp_pos));
        (*ainp_pos) += (int)sizeof(struct dsd_named_list);
        adsl_cur->adsc_next = NULL;

        /* set next pointer */
        if ( adsl_prev != NULL ) {
            adsl_prev->adsc_next = adsl_cur;
        } else {
            adsl_config->adsc_ica_session_pages = adsl_cur;
        }
        adsl_prev = adsl_cur;
    
        /* insert name of session page */
        adsl_cur->achc_name    = achp_config + (*ainp_pos);
        adsl_cur->inc_len_name = dsl_name.m_get_len();
        memcpy( adsl_cur->achc_name, dsl_name.m_get_ptr(),
                adsl_cur->inc_len_name );
        (*ainp_pos) += adsl_cur->inc_len_name;
    }

    return ((*ainp_pos <= inp_length)?TRUE:FALSE);
} /* end of m_write_ica_pages */
