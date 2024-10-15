#define WIN32_LEAN_AND_MEAN
/*+-------------------------------------------------------------------------+*/
/*| include global headers:                                                 |*/
/*+-------------------------------------------------------------------------+*/
#include <ds_hstring.h>
#include <ds_hvector.h>
#include <ds_usercma.h>
// daviladd: these two headers as well as the WIN32_LEAN_AND_MEAN define are 
//           needed for checking INETA validity in ds_wsp_admin::m_decode_ineta
#ifndef HL_UNIX
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "ds_wsp_admin.h"

#define SM_WSP_ADMIN_LOG_OPT1   1

struct dsd_log_wsp {
    HL_LONGLONG   ilc_handle;
#if !SM_WSP_ADMIN_LOG_OPT1
    int           inc_entries;
    int           inc_added;
#endif
    dsd_log_info* adsc_first_log;
#if SM_WSP_ADMIN_LOG_OPT1
    dsd_log_info* adsc_end_log;
    dsd_log_info* adsc_cur;
    dsd_log_info* adsc_end;
#endif
};

/*+-------------------------------------------------------------------------+*/
/*| query data structure definition:                                        |*/
/*+-------------------------------------------------------------------------+*/
#ifndef _DEF_QUERY_STRUCTURE
#define _DEF_QUERY_STRUCTURE
struct dsd_query {
    ds_hstring          ds_name;
    ds_hstring          ds_value;
    struct dsd_query*   ads_next;
};
#endif // _DEF_QUERY_STRUCTURE

/*+-------------------------------------------------------------------------+*/
/*| constructor:                                                            |*/
/*+-------------------------------------------------------------------------+*/
/**
 *
 * ds_wsp_admin::ds_wsp_admin
 *
*/
ds_wsp_admin::ds_wsp_admin( ds_wsp_helper* adsp_wsp_helper )
{
    adsc_query       = NULL;
    ads_wsp_helper   = adsp_wsp_helper;
    this->adsc_cluster      = NULL;
    this->adsc_listen       = NULL;
    this->adsc_perfdata     = NULL;
    this->adsc_session_info = NULL;
    this->adsc_log          = NULL;
	 this->adsc_wsptrace_info= NULL;
	 achc_trineta		 = NULL;
    ien_ret_code     = ied_wspadmin_unset;
    work_mode        = ien_undefined;
    boc_getall_wsp   = false;
    il_wsp_handle    = 0;
    memset( &ds_query_session, 0, sizeof( dsd_wspadm1_q_session ) );
    ach_user         = NULL;
    ach_group        = NULL;
    memset( &ds_query_log, 0, sizeof( dsd_wspadm1_q_log ) );
    ach_search       = NULL;
    ds_query_disconnect.imc_session_no = -1;
} //end of ds_wsp_admin::ds_wsp_admin


/**
 *
 * ds_wsp_admin::ds_wsp_admin
 *
*/
ds_wsp_admin::ds_wsp_admin(void)
{
    adsc_query       = NULL;
    ads_wsp_helper   = NULL;
    this->adsc_cluster      = NULL;
    this->adsc_listen       = NULL;
    this->adsc_perfdata     = NULL;
    this->adsc_session_info = NULL;
    this->adsc_log          = NULL;
	 this->adsc_wsptrace_info= NULL;
	 achc_trineta		 = NULL;
    ien_ret_code     = ied_wspadmin_unset;
    work_mode        = ien_undefined;
    boc_getall_wsp   = false;
    il_wsp_handle    = 0;
    memset( &ds_query_session, 0, sizeof( dsd_wspadm1_q_session ) );
    ach_user         = NULL;
    ach_group        = NULL;
	 ach_userfield        = NULL;
    memset( &ds_query_log, 0, sizeof( dsd_wspadm1_q_log ) );
    ach_search       = NULL;
    ds_query_disconnect.imc_session_no = -1;
} //end of ds_wsp_admin::ds_wsp_admin


/*+-------------------------------------------------------------------------+*/
/*| destructor:                                                             |*/
/*+-------------------------------------------------------------------------+*/

/**
 *
 * ds_wsp_admin::~ds_wsp_admin
 *
*/
ds_wsp_admin::~ds_wsp_admin(void)
{
	 m_free_cluster( this->adsc_cluster );
    m_free_listen( this->adsc_listen );
	 m_free_perfdata( this->adsc_perfdata );
    m_free_session( this->adsc_session_info );
    m_free_log( this->adsc_log );
	 m_free_wsptrace(this->adsc_wsptrace_info);
} //end of ds_wsp_admin::~ds_wsp_admin

/*+-------------------------------------------------------------------------+*/
/*| public functions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/**
 * function ds_wsp_admin::m_init
 * initialize session class
*/
void ds_wsp_admin::m_init( ds_wsp_helper* adsp_wsp_helper, struct dsd_query* adsp_query )
{
    adsc_query     = adsp_query;
    ads_wsp_helper = adsp_wsp_helper;
} // end of ds_wsp_admin::m_init


/**
 * function ds_wsp_admin::m_get_cluster_info
 * ask wsp for a list of current wsps in cluster
 *
 * @return  dsd_cluster*                cluster list structure
*/
dsd_cluster* ds_wsp_admin::m_get_cluster_info()
{
    // initialize some variables:
    ds_hvector_btype<dsd_wspadm_all> ds_data( ads_wsp_helper );
    bool                             bo_parse;            // parser return

    //-------------------------------------
    // check if we have already a struct:
    //-------------------------------------
    if ( this->adsc_cluster != NULL ) {
        return this->adsc_cluster;
    }

    //-------------------------------------
    // set workmode:
    //-------------------------------------
    work_mode = ien_cluster;

    //-------------------------------------
    // send question to wsp:
    //-------------------------------------
    if ( !m_get_data(ds_data) ) {
        return NULL;
    }

	 dsd_read_cluster_context dsl_context;
    //-------------------------------------
    // parse response:
    //-------------------------------------
    bo_parse = m_parse_data_vector( &ds_data, &dsl_context );
    if ( bo_parse == false ) {
        return NULL;
    }
	 this->adsc_cluster = dsl_context.dsc_clusters.m_get_first();

    return this->adsc_cluster;
} // end of ds_wsp_admin::m_get_cluster_info


/**
 * function ds_wsp_admin::m_get_session_info
 * ask wsp for a list of active sessions
 *
 * @return      dsd_session_info*                       session list structure
*/
dsd_session_info* ds_wsp_admin::m_get_session_info()
{
    // initialize some variables:
    ds_hvector_btype<dsd_wspadm_all> ds_data( ads_wsp_helper );
    bool                             bo_ret;                // return

    //-------------------------------------
    // check if we have already a struct:
    //-------------------------------------
    if ( this->adsc_session_info != NULL ) {
        return this->adsc_session_info;
    }

    //-------------------------------------
    // set workmode:
    //-------------------------------------
    work_mode = ien_session;

    //-------------------------------------
    // get params from query list:
    //-------------------------------------
    bo_ret = m_read_query();
    if ( bo_ret == false ) {
        return NULL;
    }

    //-------------------------------------
    // send question to wsp:
    //-------------------------------------
    if ( !m_get_data(ds_data) ) {
        return NULL;
    }

	 dsd_read_session_context dsl_context;
    //-------------------------------------
    // parse response:
    //-------------------------------------
    bo_ret = m_parse_data_vector( &ds_data, &dsl_context );
    if ( bo_ret == false ) {
        return NULL;
    }
	 this->adsc_session_info = dsl_context.dsc_sessions.m_get_first();
    return this->adsc_session_info;
} // end of ds_wsp_admin::m_get_session_info()


/**
 * function ds_wsp_admin::m_get_listen_info
 * ask wsp for a list of listen
 *
 * @return      dsd_listen*                             listen list structure
*/
dsd_listen* ds_wsp_admin::m_get_listen_info()
{
    // initialize some variables:
   ds_hvector_btype<dsd_wspadm_all> ds_data( ads_wsp_helper );
    bool                             bo_ret;                // return

    //-------------------------------------
    // check if we have already a struct:
    //-------------------------------------
    if ( this->adsc_listen != NULL ) {
        return this->adsc_listen;
    }

    //-------------------------------------
    // set workmode:
    //-------------------------------------
    work_mode = ien_listen;

    //-------------------------------------
    // get params from query list:
    //-------------------------------------
    bo_ret = m_read_query();
    if ( bo_ret == false ) {
        return NULL;
    }

    //-------------------------------------
    // send question to wsp:
    //-------------------------------------
    if ( !m_get_data(ds_data) ) {
        return NULL;
    }

	 dsd_read_listen_context dsl_context;
    //-------------------------------------
    // parse response:
    //-------------------------------------
    bo_ret = m_parse_data_vector( &ds_data, &dsl_context );
    if ( bo_ret == false ) {
        return NULL;
    }
	 this->adsc_listen = dsl_context.dsc_listens.m_get_first();
    return this->adsc_listen;
} // ds_wsp_admin::m_get_listen_info


/**
 * function ds_wsp_admin::m_get_perf_info
 * ask wsp for a performance data
 *
 * @return      dsd_perfdata*                           performance data list structure
*/
dsd_perfdata* ds_wsp_admin::m_get_perf_info()
{
    // initialize some variables:
    ds_hvector_btype<dsd_wspadm_all> ds_data( ads_wsp_helper );
    bool                             bo_ret;                // return

    //-------------------------------------
    // check if we have already a struct:
    //-------------------------------------
    if ( this->adsc_perfdata != NULL ) {
        return this->adsc_perfdata;
    }

    //-------------------------------------
    // set workmode:
    //-------------------------------------
    work_mode = ien_perfdata;

    //-------------------------------------
    // get params from query list:
    //-------------------------------------
    bo_ret = m_read_query();
    if ( bo_ret == false ) {
        return NULL;
    }

    //-------------------------------------
    // send question to wsp:
    //-------------------------------------
    if ( !m_get_data(ds_data) ) {
        return NULL;
    }

	 dsd_read_perf_context dsl_context;
	 dsl_context.adsc_perfdata = NULL;
    //-------------------------------------
    // parse response:
    //-------------------------------------
    bo_ret = m_parse_data_vector( &ds_data, &dsl_context );
    if ( bo_ret == false ) {
        return NULL;
    }
	 this->adsc_perfdata = dsl_context.adsc_perfdata;
    return this->adsc_perfdata;
} // end of ds_wsp_admin::m_get_perf_info

/**
 * function ds_wsp_admin::m_get_wsptrace_info
 * ask wsp for WSP Trace configuration data
 *
 * @return      dsd_wsptrace_info*                           // WSP Trace structure pointer
*/
dsd_wsptrace_info* ds_wsp_admin::m_get_wsptrace_info()
{
    // initialize some variables:
    ds_hvector_btype<dsd_wspadm_all> dsl_data( ads_wsp_helper );
    bool                             bol_ret;                // return

    //-------------------------------------
    // check if we have already a struct:
    //-------------------------------------
    if ( adsc_wsptrace_info != NULL ) {
		return adsc_wsptrace_info;
    }

    //-------------------------------------
    // set workmode:
    //-------------------------------------
    work_mode = ien_wsptrace_info;

    //-------------------------------------
    // get params from query list:
    //-------------------------------------
    bol_ret = m_read_query();
    if ( bol_ret == false ) {
        return NULL;
    }

    //-------------------------------------
    // send question to wsp:
    //-------------------------------------
    if ( !m_get_data(dsl_data) ) {
        return NULL;
    }

	 dsd_read_wsptrace_info_context dsl_context;
    //-------------------------------------
    // parse response:
    //-------------------------------------
    bol_ret = m_parse_data_vector( &dsl_data, &dsl_context );
    if ( bol_ret == false ) {
        return NULL;
    }
	 adsc_wsptrace_info = dsl_context.dsc_traces.m_get_first();
    return adsc_wsptrace_info;
} // end of ds_wsp_admin::m_get_wsptrace_info

/**
 * function ds_wsp_admin::m_get_log_info
 * ask wsp for a logfile data
 *
 * @return      dsd_log_info*                           logfile data list structure
*/
dsd_log_info* ds_wsp_admin::m_get_log_info()
{
    // initialize some variables:
    ds_hvector_btype<dsd_wspadm_all> ds_data( ads_wsp_helper );
    bool                             bo_ret;                // return
#ifdef COUNT_RESPONSE
    size_t        uin_count = 0;
    dsd_log_info* ads_temp;
#endif

    //-------------------------------------
    // check if we have already a struct:
    //-------------------------------------
    if ( this->adsc_log != NULL ) {
        return this->adsc_log;
    }

    //-------------------------------------
    // set workmode:
    //-------------------------------------
    work_mode = ien_log;

    //-------------------------------------
    // get params from query list:
    //-------------------------------------
    bo_ret = m_read_query();
    if ( bo_ret == false ) {
        return NULL;
    }

    //-------------------------------------
    // send question to wsp:
    //-------------------------------------
    if ( !m_get_data(ds_data) ) {
        return NULL;
    }

	 dsd_read_log_info_context dsl_context;
    //-------------------------------------
    // parse response:
    //-------------------------------------
    bo_ret = m_parse_data_vector( &ds_data, &dsl_context );
    if ( bo_ret == false ) {
        return NULL;
    }
	 this->adsc_log = dsl_context.dsc_logs.m_get_first();

    //-------------------------------------
    // sort entries:
    //-------------------------------------
    if ( this->adsc_log != NULL ) {
        bo_ret = m_sort_log();
        if ( bo_ret == false ) {
            m_free_log( this->adsc_log );
            this->adsc_log = NULL;
        }
    }

#ifdef COUNT_RESPONSE
    ads_temp = this->adsc_log;
    while ( ads_temp != NULL ) {
        uin_count++;
        ads_temp = ads_temp->ads_next;
    }
#endif
    return this->adsc_log;
} // end of ds_wsp_admin::m_get_log_info


/**
 * function ds_wsp_admin::m_disc_session
 * ask wsp for a disconnect a session
 *
 * @return      bool                        true = disconnect successful
*/
bool ds_wsp_admin::m_disc_session()
{
    // initialize some variables:
    bool    bo_ret;                         // return
    const char* ach_session;                // session to disconnect
    int     in_len;                         // length of session
    int     in_pos = 0;                     // position of session query
    const char* achl_handle;                // wsp handle
    int     inl_len_handle;                 // length wsp handle

    //-------------------------------------
    // set workmode:
    //-------------------------------------
    work_mode = ien_cancel_session;

    //-------------------------------------
    // get params from query list:
    //-------------------------------------
    bo_ret = m_read_query();
    if ( bo_ret == false ) {
        return false;
    }

    do {
        in_pos = m_get_query_value( achr_wspadmin_queries[ied_wspadmin_query_session],
                                    &ach_session, &in_len, in_pos );
        if (    ach_session == NULL
             || in_len       < 1
             || in_pos      == -1   ) {
            return true;
        }
        in_pos = m_get_query_value( achr_wspadmin_queries[ied_wspadmin_query_handle],
                                    &achl_handle, &inl_len_handle, in_pos );
        if (    achl_handle    == NULL
             || inl_len_handle  < 1
             || in_pos         == -1   ) {
            return true;
        }

        //---------------------------------
        // do the disconnect:
        //---------------------------------
        bo_ret = m_disconnect( (HL_LONGLONG)m_str_to_ll(achl_handle, NULL, 10),
                               atoi(ach_session) );
        if ( bo_ret == false ) {
            return false;
        }
    } while ( in_len > 0 );

    return true;
} // end of ds_wsp_admin::m_disc_session

/**
 * function ds_wsp_admin::m_wsptrace_modconf()
 * Asks (all) WSP(s) to modify the WSP Trace configuration with parameters received in the POST message.
 *
 * @return      bool                        true = successful operation
*/
bool ds_wsp_admin::m_wsptrace_modconf()
{
    // initialize some variables:
    bool    bol_ret;                        // Return value
    struct dsd_query*   adsl_temp = adsc_query;
    ds_hvector_btype<int> dsl_handle_pos(ads_wsp_helper);
    
    int iml_index = 0;      // 
    
    // Get the handle(s) position(s) and store the queries for each one
    while ( adsl_temp != NULL ) {
        if (adsl_temp->ds_name.m_equals( achr_wspadmin_queries[ied_wsptrace_query_wsptrace_handle] ) == true ) {
            dsl_handle_pos.m_add(iml_index);
        }
        iml_index++;
        adsl_temp = adsl_temp->ads_next;
    }
    if ( dsl_handle_pos.m_size() == 0){
#ifdef _DEBUG
    ads_wsp_helper->m_cb_printf_out("HIWAD000I: m_wsptrace_modconf() - no wspt-handle was found in POST message.");
#endif
        return false;
    }
    dsl_handle_pos.m_add(iml_index);

    for (int iml_i = 0; iml_i < dsl_handle_pos.m_size()-1; iml_i++){
        #ifdef _DEBUG
        ads_wsp_helper->m_cb_printf_out("HIWAD001I: m_wsptrace_modconf() - Calling m_process_handle_commands(imp_start=%d - imp_end=%d).", iml_i, iml_i + 1);
        #endif
        bol_ret = m_process_handle_commands(dsl_handle_pos.m_get(iml_i), dsl_handle_pos.m_get(iml_i+1)); // Read commands from current to next;
        if (!bol_ret)
            return false;
    }

    return true;
}

/**
 * function ds_wsp_admin::m_wsptrace_modconf()
 * Asks (all) WSP(s) to modify the WSP Trace configuration with parameters received in the POST message.
 *
 * @return      bool                        true = successful operation
*/
bool ds_wsp_admin::m_process_handle_commands(int imp_start, int imp_end)
{
    // initialize some variables:
    bool    bol_ret;                        // Return value
    int     iml_pos = 0;
    // Handle variables
    const char*   achl_handle;               // WSP handle
    int     iml_len_handle;                 // Length of WSP handle
    int     iml_handle_pos = 0;
	// Dump-query variables
    const char*   achl_dump_param;
    int     iml_dumpparam_len;
    int     iml_dumpparam_pos = 0;
    // Target query variables: output destination and filename
    const char*	achl_target_param;		    // Parameter that specifies output destination: console, ascii or bin file,...
	int		iml_targetparam_len;			// Length of received parameter.
	int		iml_targetparam_pos = 0;		// Position of this parameter in the query stack.
	const char* achl_target_file;			// Name of WSP Trace file to be written
	int		iml_targetfile_len;				// Length of the filename received
	int		iml_targetfile_pos = 0;			// Position of this parameter in the query stack.
    // Core query variables
    const char*	achl_core_param;			// New core tracing parameter values
	int		iml_coreparam_len;
	int		iml_coreparam_pos = 0;
    // Session query variables
    const char*   achl_allsess_param;	    // Trace all sessions or single inetas
	int		iml_allsess_len;				
	int		iml_allsess_pos = 0;
	const char*	achl_sess_param;			// New session tracing parameter values 
	int		iml_sessparam_len;
	int		iml_sessparam_pos = 0;
    // Trace specific INETAS query variables
    const char*   achl_trace_ineta;         // List of specific INETAs to be added to WSP Trace list
    int		iml_traceineta_len;
    int		iml_traceineta_pos = 0;
    // Delete all INETAS query variables
    const char*   achl_delall_inetas; 
    int     iml_delall_inetas_len;
    int     iml_delall_inetas_pos = 0;
	
	struct dsd_wspadm1_q_wsp_trace_1	dsl_wspadm_qwsptr;		// Structure that is sent to the WSP with new config settings.
	
    //-------------------------------------
    // set workmode:
    //-------------------------------------
    work_mode = ien_wsptrace_query;		

    //-------------------------------------
    // get params from query list:
    //-------------------------------------
    bol_ret = m_read_query();
    if ( bol_ret == false ) {
        return false;
    }
	// This series of queries has to be in ascendent order of ied_wspadmin_query_handle.
	// Gets the current WSP handle, it could be -1 for all WSPs in a cluster or a specific value for one of them (local is always 0).
    iml_handle_pos = m_get_query_value( achr_wspadmin_queries[ied_wsptrace_query_wsptrace_handle],
                                &achl_handle, &iml_len_handle, imp_start );
    if (    achl_handle    == NULL
         || iml_len_handle  < 1
         || iml_handle_pos  == -1   ) {
        // If there is no handle, there is no way to know to which WSP in the cluster the new
        //  configuration request should be sent
        return false;
    }

//#ifdef _DEBUG
//    ads_wsp_helper->m_cb_printf_out("HIWAD100I: handle=%s (inl_pos=%d)", achl_handle, iml_handle_pos);
//#endif

    // Check if contains the query to dump CMA content
	iml_dumpparam_pos = m_get_query_value( achr_wspadmin_queries[ied_wspadmin_query_dump_cma],
								&achl_dump_param, &iml_dumpparam_len, imp_start );
    if (    achl_dump_param	!= NULL
         && iml_dumpparam_len >= 1			
         && iml_dumpparam_pos != -1 
         && iml_dumpparam_pos < imp_end) {
        // TODO: check if input contains correct values: "true" or "false"

		// Let's dump CMA content:
        //#ifdef _DEBUG
        //    ads_wsp_helper->m_cb_printf_out("HIWAD105I: achl_dump_param=%s, iml_dumpparam_len=%d, iml_dumpparam_pos=%d",
        //                                     achl_dump_param, iml_dumpparam_len, iml_dumpparam_pos);
        //#endif
        dsl_wspadm_qwsptr.iec_wawt	= ied_wawt_trace_cma_dump;
        ads_wsp_helper->m_cb_printf_out("HIWAD001I: sending new WSP-Trace Dump CMA command: WSP-handle=%lld, WSPTrace-dump-CMA=ied_wawt_trace_cma_dump",
                               (HL_LONGLONG)m_str_to_ll(achl_handle, NULL, 10));
	    bol_ret = m_wsptrace_modify( (HL_LONGLONG)m_str_to_ll(achl_handle, NULL, 10), dsl_wspadm_qwsptr,
								    0, NULL);
		if ( bol_ret == false ) {
			return false;
	    }
    }

	// Read WSP Trace target configuration query values
	iml_targetparam_pos = m_get_query_value( achr_wspadmin_queries[ied_wsptrace_query_wsptrace_outd], 
                                &achl_target_param, &iml_targetparam_len, imp_start );
//#ifdef _DEBUG
//    ads_wsp_helper->m_cb_printf_out("HIWAD101I: achl_target_param=%s, iml_targetparam_len=%d, iml_targetparam_pos=%d",
//                                    achl_target_param, iml_targetparam_len, iml_targetparam_pos);
//#endif
    if (    achl_target_param	!= NULL
     && iml_targetparam_len	>= 1			
     && iml_targetparam_pos	!= -1  
     && iml_targetparam_pos <= imp_end) {
        // TODO: check if input is in correct ranges:
        //          - target param: it should be only 1 char long, and a numerical value [1,3] (4=SYSLOG but it is not yet implemented)
        //          - target file:  check that it contains only valid characters, and does not exceed maximum lenght
    
	    // Checks for new WSP Trace target file configuration value
	    dsl_wspadm_qwsptr.iec_wawt	= ied_wawt_target;
	    dsl_wspadm_qwsptr.iec_wtt	= (enum ied_wsp_trace_target) m_str_to_ll(achl_target_param, NULL, 10);
	    // If it is an ASCII or binary file, we need to set up its name, so we check if this param is on the
        //      received query part for the current wspt-handle
        iml_targetfile_pos = m_get_query_value( achr_wspadmin_queries[ied_wsptrace_query_wsptrace_outf], 
						            &achl_target_file, &iml_targetfile_len, imp_start);
        //#ifdef _DEBUG
        //ads_wsp_helper->m_cb_printf_out("HIWAD102I: achl_target_file=%s, iml_targetfile_len=%d, iml_targetfile_pos=%d",
        //                                achl_target_file, iml_targetfile_len, iml_targetfile_pos);
        //#endif
        ds_hstring dsl_target_file(this->ads_wsp_helper);
        if ((iml_targetfile_pos < imp_end) 
            &&( (dsl_wspadm_qwsptr.iec_wtt == ied_wtt_file_ascii) 
            || (dsl_wspadm_qwsptr.iec_wtt == ied_wtt_file_bin))){
            if (( achl_target_file	== NULL || iml_targetfile_len	< 1 || iml_targetfile_pos	== -1 )){
                // If no filename is specified, we put a default name:
			    if (dsl_wspadm_qwsptr.iec_wtt == ied_wtt_file_ascii){
                    dsl_target_file.m_writef("WSP-trace-handle-01-ascii.dat");
				    //iml_targetfile_len = sprintf( achl_target_file, "WSP-trace-handle-%010lld-ascii.dat", adsl_wspadm_temp->dsc_wsp.ilc_handle );
			    } else {
				    dsl_target_file.m_writef("WSP-trace-handle-01-bin.dat");
				    //iml_targetfile_len = sprintf( achl_target_file, "WSP-trace-handle-%010lld-bin.dat", adsl_wspadm_temp->dsc_wsp.ilc_handle );
			    }
		    } else {
                // If a filename is specified we only need to add the extension.
			    dsl_target_file.m_writef("%s.dat", achl_target_file);
			    //iml_targetfile_len = sprintf( achl_target_file, "%s.dat", achl_target_file);
		    }
            achl_target_file = dsl_target_file.m_get_ptr();
            iml_targetfile_len = dsl_target_file.m_get_len();
	    } else {
		    // If output target is not a file, there is no need to append more data...
		    achl_target_file	= NULL;
		    iml_targetfile_len	= 0;
	    }
        ads_wsp_helper->m_cb_printf_out("HIWAD002I: sending new WSP-Trace target: WSP-handle=%lld, WSPTrace-destination=%d, WSPTrace-filename=%s",
                                             (HL_LONGLONG)m_str_to_ll(achl_handle, NULL, 10), dsl_wspadm_qwsptr.iec_wtt, achl_target_file);
	    bol_ret = m_wsptrace_modify( (HL_LONGLONG)m_str_to_ll(achl_handle, NULL, 10), dsl_wspadm_qwsptr,
								    iml_targetfile_len, achl_target_file);
	    if ( bol_ret == false ) {
		    return false;
	    }
	}

    	// Checks for new WSP Trace core configuration values
    iml_coreparam_pos = m_get_query_value( achr_wspadmin_queries[ied_wsptrace_query_wsptrace_core],
                                &achl_core_param, &iml_coreparam_len, imp_start );
    //#ifdef _DEBUG
    //    ads_wsp_helper->m_cb_printf_out("HIWAD106I: achl_core_param=%s, iml_coreparam_len=%d, iml_coreparam_pos=%d",
    //                                    achl_core_param, iml_coreparam_len, iml_coreparam_pos);
    //#endif
    if (    achl_core_param	!= NULL
         && iml_coreparam_len	>= 1			
         && iml_coreparam_pos	!= -1 
         && iml_coreparam_pos <= imp_end) {
		// TODO: check if input contains valid chars and is within correct range: achl_core_param [0,65535]


        dsl_wspadm_qwsptr.iec_wawt			= ied_wawt_trace_new_core;
		dsl_wspadm_qwsptr.imc_trace_level	= m_str_to_ll(achl_core_param, NULL, 10);
        ads_wsp_helper->m_cb_printf_out("HIWAD003I: sending new WSP-Trace CORE settings: WSP-handle=%lld, WSPTrace-core-level=%d",
             (HL_LONGLONG)m_str_to_ll(achl_handle, NULL, 10), dsl_wspadm_qwsptr.imc_trace_level);       
	    bol_ret = m_wsptrace_modify((HL_LONGLONG)m_str_to_ll(achl_handle, NULL, 10), dsl_wspadm_qwsptr ,
								    0, NULL);
	    if ( bol_ret == false ) {
		    return false;
	    }
	}

    // Read WSP Trace query settings regarding if all sessions or specific INETAS are to be traced
    iml_allsess_pos = m_get_query_value( achr_wspadmin_queries[ied_wsptrace_query_wsptrace_allsess],
                                &achl_allsess_param, &iml_allsess_len, imp_start);
//#ifdef _DEBUG
//    ads_wsp_helper->m_cb_printf_out("HIWAD103I: achl_allsess_param=%s, iml_allsess_len=%d, iml_allsess_pos=%d",
//                                    achl_allsess_param, iml_allsess_len, iml_allsess_pos);
//#endif

    // Checks for new WSP Trace session configuration values
	// We have to check if the POST data flag for tracing all INETAs comes with data.
	// If it comes with data, it maybe a change of mode: from tracing all INETAs to specific ones or viceversa.
    if ( achl_allsess_param	!= NULL
         && iml_allsess_len	>= 1 
         && iml_allsess_pos	!= -1
         && iml_allsess_pos <= imp_end) {
        
        // Read query values regarding sessions' tracing
        iml_sessparam_pos = m_get_query_value( achr_wspadmin_queries[ied_wsptrace_query_wsptrace_sess],
							        &achl_sess_param, &iml_sessparam_len, imp_start );
        //#ifdef _DEBUG
        //    ads_wsp_helper->m_cb_printf_out("HIWAD104I: achl_sess_param=%s, iml_sessparam_len=%d, iml_sessparam_pos=%d",
        //                                    achl_sess_param, iml_sessparam_len, iml_sessparam_pos);
        //#endif
 	    
        if ( achl_sess_param	    != NULL
            && iml_sessparam_len	>= 1			
            && iml_sessparam_pos	!= -1
            && iml_sessparam_pos <= imp_end) {

            dsl_wspadm_qwsptr.imc_trace_level = m_str_to_ll(achl_sess_param, NULL, 10);
            if(m_str_to_ll(achl_allsess_param, NULL, 10) != 0){
                dsl_wspadm_qwsptr.iec_wawt			= ied_wawt_trace_new_ineta_all;     // Mark tracing all inetas
                ads_wsp_helper->m_cb_printf_out("HIWAD004I: sending new WSP-Trace SESS settings: WSP-handle=%lld, WSPTrace-all-sess=ied_wawt_trace_new_ineta_all, WSPTrace-sess-level=%d",
                                                (HL_LONGLONG)m_str_to_ll(achl_handle, NULL, 10), dsl_wspadm_qwsptr.imc_trace_level);  
                bol_ret = m_wsptrace_modify((HL_LONGLONG)m_str_to_ll(achl_handle, NULL, 10), dsl_wspadm_qwsptr ,
		                                    0, NULL);
                if ( bol_ret == false ) {
                    return false;
                }
            } else {
                // First we need to clear the flag for tracing all INETAs in this handle if needed to avoid
                //      erasing the current list of INETAs to trace if present.
                dsl_wspadm_qwsptr.iec_wawt = ied_wawt_trace_del_ineta_all;		// Deleting trace all INETAs flag
                struct dsd_wsptrace_info*   adsl_wspadm_temp = m_get_wsptrace_info();
		        do {
			        if (adsl_wspadm_temp->dsc_wsptrace_conf.boc_sess_trace_ineta_all){
				        dsl_wspadm_qwsptr.iec_wawt = ied_wawt_trace_del_ineta_all;		// Deleting trace all INETAs flag
                        ads_wsp_helper->m_cb_printf_out("HIWAD005I: sending new WSP-Trace SESS settings: WSP-handle=%lld, WSPTrace-all-sess=ied_wawt_trace_del_ineta_all",
                                                       (HL_LONGLONG)m_str_to_ll(achl_handle, NULL, 10));
				        bol_ret = m_wsptrace_modify( adsl_wspadm_temp->dsc_wsp.ilc_handle, dsl_wspadm_qwsptr ,
													        0, NULL);
				        if (bol_ret == false){
					        return false;
				        }
			        }
			        adsl_wspadm_temp = adsl_wspadm_temp->ads_next;
		        } while ( adsl_wspadm_temp != NULL);	
				if (bol_ret == false){
					return false;
				}
                // And now we can proceed to start adding INETAs
                dsl_wspadm_qwsptr.iec_wawt			= ied_wawt_trace_new_ineta_spec;    // Mark tracing just specific inetas
                iml_traceineta_pos = imp_start;     // Set the starting point, and then through the 
                do{
                    iml_traceineta_pos = m_get_query_value( achr_wspadmin_queries[ied_wsptrace_query_single_ineta], 
		                                                    &achl_trace_ineta, &iml_traceineta_len, iml_traceineta_pos );
                    //#ifdef _DEBUG
                    //    ads_wsp_helper->m_cb_printf_out("HIWAD107I: achl_trace_ineta=%s, iml_traceineta_len=%d, iml_traceineta_pos=%d",
                    //                                    achl_trace_ineta, iml_traceineta_len, iml_traceineta_pos);
                    //#endif
                    if ( achl_trace_ineta == NULL		// Read 
                         || iml_traceineta_len  < 1
                         || iml_traceineta_pos  == -1   
                         || iml_traceineta_pos >= imp_end) {
                        break;
                    }
                    // First of all we need to check if it is a valid INETA:
                    int iml_rc;
                    //char       *achl1;                       /* working-variable        */
                    struct addrinfo dsl_addrinfo_w1;
                    struct addrinfo *adsl_addrinfo_w2;

                    memset( &dsl_addrinfo_w1, 0, sizeof(dsl_addrinfo_w1) );
                    dsl_addrinfo_w1.ai_family   = AF_UNSPEC;
                    dsl_addrinfo_w1.ai_flags = AI_NUMERICHOST;
                    adsl_addrinfo_w2 = NULL;
                    iml_rc = getaddrinfo( achl_trace_ineta, "", &dsl_addrinfo_w1, &adsl_addrinfo_w2 );
                    if (iml_rc) {
                     break;
                    }
                    
                    char* achl_temp = adsl_addrinfo_w2->ai_addr->sa_data + 2;
                    iml_traceineta_len = 4;
                    if (adsl_addrinfo_w2->ai_family == AF_INET6){
                        iml_traceineta_len = 16;
                        achl_temp += 4;
                    } 

                    iml_traceineta_pos++;
                    dsl_wspadm_qwsptr.iec_wawt = ied_wawt_trace_new_ineta_spec;
                    dsl_wspadm_qwsptr.imc_trace_level = m_str_to_ll(achl_sess_param, NULL, 10);		

                    // Usually the handle to be sent in this case, should be "-1" to send it to all WSPs in the cluster,
                    //      but I am allowing here to be whatever comes in the query, because in the query it is always set
                    //      to this value (-1), and maybe in the future will be allowed to set tracing for a specific INETA
                    //      in a specific WSP and not in all WSPs in the cluster.
                    ads_wsp_helper->m_cb_printf_out("HIWAD006I: sending new WSP-Trace SESS settings: WSP-handle=%lld, WSPTrace-all-sess=ied_wawt_trace_new_ineta_spec, WSP-Trace-INETA=%s, WSPTrace-sess-level=%d",
                        (HL_LONGLONG)m_str_to_ll(achl_handle, NULL, 10), achl_trace_ineta, dsl_wspadm_qwsptr.imc_trace_level); 
                    bol_ret = m_wsptrace_modify((HL_LONGLONG)m_str_to_ll(achl_handle, NULL, 10), dsl_wspadm_qwsptr,
                        iml_traceineta_len, achl_temp);

                    if (bol_ret == false){
	                    return false;
                    }
                } while ( (iml_traceineta_pos < imp_end) && (iml_traceineta_pos != -1));
            }
        }   
    }   

    // Removes all inetas being traced.
    iml_delall_inetas_pos = m_get_query_value( achr_wspadmin_queries[ied_wspadmin_query_erase_inetas], 
							                    &achl_delall_inetas, &iml_delall_inetas_len, imp_start );
 /*   #ifdef _DEBUG
    ads_wsp_helper->m_cb_printf_out("HIWAD107I: achl_delall_inetas=%s, iml_delall_inetas_len=%d, iml_delall_inetas_pos=%d",
                                    achl_delall_inetas, iml_delall_inetas_len, iml_delall_inetas_pos);
    #endif*/
    if ( achl_delall_inetas != NULL
		&& iml_delall_inetas_len  >= 1
        && iml_delall_inetas_pos  != -1   
        && iml_delall_inetas_pos <= imp_end) {

		dsl_wspadm_qwsptr.iec_wawt = ied_wawt_trace_del_ineta_all;		// Deleting trace all INETAs flag
        ads_wsp_helper->m_cb_printf_out("HIWAD007I: sending new WSP-Trace SESS settings: WSP-handle=%lld, WSPTrace-all-sess=ied_wawt_trace_del_ineta_all",
                               (HL_LONGLONG)m_str_to_ll(achl_handle, NULL, 10));
		bol_ret = m_wsptrace_modify( (HL_LONGLONG)m_str_to_ll(achl_handle, NULL, 10), dsl_wspadm_qwsptr ,
											0, NULL);
		if (bol_ret == false){
			return false;
		}
    }
    // TODO: there is another item in the enum ied_wspadm1_wsp_trace_def, that refers to a query to 
    //          delete specific INETAS: ied_wawt_trace_del_ineta_spec. It should be implemented at some
    //          point in the future...or not!

	return true;
} // end of ds_wsp_admin::m_process_handle_commands()


/**
 * public function ds_wsp_admin::m_disc_user
 * close all session from given user
 *
 * @param[in]   const char* ach_usr         pointer to username
 * @param[in]   int         in_len_usr      length of username
 * @param[in]   const char* ach_grp         pointer to usergroup
 * @param[in]   int         in_len_grp      length of usergroup
 * @return      bool                        true = success
*/
bool ds_wsp_admin::m_disc_user( const char* ach_usr, int in_len_usr,
                                const char* ach_grp, int in_len_grp,
										  const dsd_cma_session_no* adsp_session )
{
    // initialize some variables:
    struct dsd_session_info* adsl_sessions;      // full session info
    struct dsd_session_info* adsl_cur;      // current session info
    bool                     bol_ret;       // return for each session
    bool                     bol_all;       // return for all sessions

    bol_all = true;
    //------------------------------------------
    // loop through all sessions:
    //------------------------------------------
    adsl_sessions = m_get_user_sessions( ach_usr, in_len_usr, ach_grp, in_len_grp, adsp_session );
	 adsl_cur = adsl_sessions;
    while ( adsl_cur != NULL ) {
        /*
           don't end our current session at current cluster
            -> this would cause problems if we are
               doing the kickout from wspat with 
               local (xml) authentication
            -> we will always receive a valid response
        */
        if (    adsl_cur->dsc_wsp.ilc_handle          == 0   /* current cluster node */
             && adsl_cur->ds_sess_info.imc_session_no == ads_wsp_helper->m_get_session_id() ) {
            adsl_cur = adsl_cur->ads_next;
            continue;
        }

        //--------------------------------------
        // do the disconnect
        //--------------------------------------
        bol_ret = m_disconnect( adsl_cur->dsc_wsp.ilc_handle,
                                adsl_cur->ds_sess_info.imc_session_no );
        if ( bol_ret == false ) {
            if ( in_len_grp > 0 ) {
                ads_wsp_helper->m_logf( ied_sdh_log_warning,
                    "HADMW002W: disconnecting SNO=%08d on WSP %.*s failed for group=%.*s userid=%.*s",
                    adsl_cur->ds_sess_info.imc_session_no,
                    adsl_cur->dsc_wsp.inc_len_srv_name, adsl_cur->dsc_wsp.achc_srv_name,
                    in_len_grp, ach_grp, in_len_usr, ach_usr );
            } else {
                ads_wsp_helper->m_logf( ied_sdh_log_warning,
                    "HADMW002W: disconnecting SNO=%08d on WSP %.*s failed for userid=%.*s",
                    adsl_cur->ds_sess_info.imc_session_no,
                    adsl_cur->dsc_wsp.inc_len_srv_name, adsl_cur->dsc_wsp.achc_srv_name,
                    in_len_usr, ach_usr );
            }
        }
        bol_all &= bol_ret;

        //--------------------------------------
        // get next session:
        //--------------------------------------
        adsl_cur = adsl_cur->ads_next;
    }

    //------------------------------------------
    // free session response:
    //------------------------------------------
    m_free_session( adsl_sessions );

    return bol_all;
} // end of ds_wsp_admin::m_disc_user


/**
 * public function ds_wsp_admin::m_get_user_sessions
 * get all session from given user
 *
 * @param[in]   const char* ach_usr         pointer to username
 * @param[in]   int         in_len_usr      length of username
 * @param[in]   const char* ach_grp         pointer to usergroup
 * @param[in]   int         in_len_grp      length of usergroup
 * @return      bool                        true = success
*/
dsd_session_info* ds_wsp_admin::m_get_user_sessions( const char* ach_usr, int in_len_usr,
                                                     const char* ach_grp, int in_len_grp,
																	  const dsd_cma_session_no* adsp_session )
{
    // initialize some variables:
    ds_hvector_btype<dsd_wspadm_all> dsl_data( ads_wsp_helper );
    bool                             bol_ret;   // return

    //------------------------------------------
    // set workmode:
    //------------------------------------------
    work_mode = ien_session;

    //------------------------------------------
    // set search user and search group:
    //------------------------------------------
    ach_user                            = (char*)ach_usr;
    ds_query_session.imc_len_userid     = in_len_usr;
    ach_group                           = (char*)ach_grp;
    ds_query_session.imc_len_user_group = in_len_grp;
	 ach_userfield                       = (char*)adsp_session;
	 ds_query_session.imc_len_userfld  = adsp_session != NULL ? sizeof(*adsp_session) : 0;
    ds_query_session.imc_no_session     = INT_MAX;   // TODO: receive all
    ds_query_session.imc_session_no     = 0;

    //------------------------------------------
    // send question to wsp:
    //------------------------------------------
    boc_getall_wsp = true; // ask all wsps
    if ( !m_get_data(dsl_data) ) {
        return NULL;
    }

    dsd_read_session_context dsl_context;
    //-------------------------------------
    // parse response:
    //-------------------------------------
    bol_ret = m_parse_data_vector( &dsl_data, &dsl_context );
    if ( bol_ret == false ) {
        return NULL;
    }
	 return dsl_context.dsc_sessions.m_get_first();
} // end of ds_wsp_admin::m_get_user_sessions


/**
 * function ds_wsp_admin::m_get_return_code
 * ask wsp for return code
 *
 * @return      ied_admin_rcode             return code
*/
ied_admin_rcode ds_wsp_admin::m_get_return_code()
{
    return ien_ret_code;
} // end of ds_wsp_admin::m_get_return_code


/*+-------------------------------------------------------------------------+*/
/*| private functions:                                                      |*/
/*+-------------------------------------------------------------------------+*/

/**
 * private function ds_wsp_admin::m_wsptrace_modify
 *		modify WSP Trace configuration 
 *
 * @param[in]   HL_LONGLONG ilp_wsp_handle  wsp handle
 * @param[in]   dsd_wspadm1_q_wsp_trace_1   ds_query_wsptr		struct holding values to be modified in WSP Trace configuration
 * @param[in]	int							imp_datalen			Some values as filename or the INETAs to be traced, are not included
 * @param[in]	char*						achp_data				in the query structure, so they need to be 'appended' to it.
 * @return      bool                        true = modify has been successful
*/
bool ds_wsp_admin::m_wsptrace_modify( HL_LONGLONG ilp_wsp_handle, dsd_wspadm1_q_wsp_trace_1 dsp_query_wsptr,
										int imp_datalen, const char* achp_data )
{
    // initialize some variables:
    ds_hvector_btype<dsd_wspadm_all> dsl_data( ads_wsp_helper );
    HL_LONGLONG                      ill_save;
    bool                             bol_ret;                // return

    // check input:
    if ( imp_datalen < 0 ) {
        return false;
    }

    //-------------------------------------
    // set workmode:
    //-------------------------------------
    work_mode = ien_wsptrace_query;

    //-------------------------------------
    // save and set current wsp handle:
    //-------------------------------------
    if ( il_wsp_handle != ilp_wsp_handle ) {
        ill_save      = il_wsp_handle;
        il_wsp_handle = ilp_wsp_handle;
    } else {
        ill_save = -1;
    }

    //-------------------------------------
    // get params from query list:
    //-------------------------------------
	dsc_query_wsptrace	= dsp_query_wsptr;
	imc_len_data			= imp_datalen;
	achc_trineta			= achp_data;
    if (ilp_wsp_handle == -1){
        boc_getall_wsp = true;
    } else {
        boc_getall_wsp = false;
    }
	//-------------------------------------
    // send question to wsp:
    //-------------------------------------
    //if ( !
        m_set_data(dsl_data);
    //    ) {
    //    return NULL;
    //}
    //-------------------------------------
    // copy saved handle back:
    //-------------------------------------
    if ( ill_save != -1 ) {
        il_wsp_handle = ill_save;
    }
	
	// WSPs  do not return anything about Trace configuration, so nothing must be checked...
    //if ( ds_data.m_empty() ) {
    //    return false;
    //}

    //-------------------------------------
    // parse response:
    //-------------------------------------
    bol_ret = m_parse_data_vector( &dsl_data, NULL );
    if ( bol_ret == false ) {
        return false;
    }

    return TRUE;
} // end of ds_wsp_admin::m_wsptrace_modify

/**
 * private function ds_wsp_admin::m_disc_session
 * disconnect session with given session number
 *
 * @param[in]   HL_LONGLONG ilp_wsp_handle  wsp with session number
 * @param[in]   int         in_session      session number
 * @return      bool                        true = disconnect successful
*/
bool ds_wsp_admin::m_disconnect( HL_LONGLONG ilp_wsp_handle, int in_session )
{
    // initialize some variables:
    ds_hvector_btype<dsd_wspadm_all> ds_data( ads_wsp_helper );
    HL_LONGLONG                      ill_save;
    bool                             bo_ret;                // return

    // check input:
    if ( in_session < 0 ) {
        return false;
    }

    //-------------------------------------
    // set workmode:
    //-------------------------------------
    work_mode = ien_cancel_session;

    //-------------------------------------
    // save and set current wsp handle:
    //-------------------------------------
    if ( il_wsp_handle != ilp_wsp_handle ) {
        ill_save      = il_wsp_handle;
        il_wsp_handle = ilp_wsp_handle;
    } else {
        ill_save = -1;
    }

    //-------------------------------------
    // get params from query list:
    //-------------------------------------
    ds_query_disconnect.imc_session_no = in_session;

    //-------------------------------------
    // send question to wsp:
    //-------------------------------------
    bo_ret = m_get_data(ds_data);

    //-------------------------------------
    // copy saved handle back:
    //-------------------------------------
    if ( ill_save != -1 ) {
        il_wsp_handle = ill_save;
    }

    if ( bo_ret == false ) {
        return false;
    }

    dsd_read_cancel_session_context dsl_context;
	 //-------------------------------------
    // parse response:
    //-------------------------------------
    bo_ret = m_parse_data_vector( &ds_data, &dsl_context );
    if ( bo_ret == false ) {
        return false;
    }

    return ( dsl_context.ds_resp_disconnect.boc_ok == TRUE );
} // end of ds_wsp_admin::m_disconnect


/**
 * function ds_wsp_admin::m_read_query
 *
 * @param[in]   dsd_query*   ads_query
 *
 * @return      bool                        true = success
*/
bool ds_wsp_admin::m_read_query()
{
    // initialize some variables:
    int                  in_temp    = 0;        // temp return value
    int                  in_element = 0;        // element in achr_wspadmin_queries
    const char*          ach_value;             // query value
    int                  in_len_val;            // length of query value
    bool                 bo_is_search = false;  // is search?
    ied_wspadmin_queries ien_qtype;             // query type

    // do some default settings:
    switch ( work_mode ) {
        case ien_log:
            ds_query_log.iec_wa1l = ied_wa1l_cur;
            break;
    }


    while ( achr_wspadmin_queries[in_element].strc_ptr != NULL ) {
        m_get_query_value( achr_wspadmin_queries[in_element],
                           &ach_value, &in_len_val );
        if ( in_len_val > 0 ) {
            ien_qtype = (ied_wspadmin_queries)in_element;

            switch ( ien_qtype ) {

                case ied_wspadmin_query_handle:
                    il_wsp_handle = m_str_to_ll( ach_value, NULL, 10 );
                    if ( il_wsp_handle == -1 ) {
                        boc_getall_wsp = true;
                        break;
                    }
                    break;

                case ied_wspadmin_query_start:
                    switch( work_mode ) {
                        case ien_session:
                            ds_query_session.imc_session_no = atoi( ach_value );
                            break;
                        case ien_log:
                            ds_query_log.ilc_position = m_str_to_ll( ach_value, NULL, 10 );
                            ds_query_log.iec_wa1l     = ied_wa1l_pos;
                            break;
                        default:
                            // ignore this value:
                            break;
                    }
                    break;

                case ied_wspadmin_query_rec:
                    in_temp = atoi( ach_value );
                    if ( in_temp == -1 ) {
                        in_temp = INT_MAX;
                    }
                    switch( work_mode ) {
                        case ien_session:
                            ds_query_session.imc_no_session = in_temp;
                            break;
                        case ien_log:
                            ds_query_log.imc_retr_no_rec = in_temp;
                        default:
                            // ignore this value:
                            break;
                    }
                    break;

                case ied_wspadmin_query_user:
                    switch( work_mode ) {
                        case ien_session:
                            ach_user                        = ach_value;
                            ds_query_session.imc_len_userid = in_len_val;
                            bo_is_search                    = true;
                            break;
                        default:
                            // ignore this value:
                            break;
                    }
                    break;

                case ied_wspadmin_query_group:
                    switch( work_mode ) {
                        case ien_session:
                            ach_group                           = ach_value;
                            ds_query_session.imc_len_user_group = in_len_val;
                            bo_is_search                        = true;
                            break;
                        default:
                            // ignore this value:
                            break;
                    }
                    break;

                case ied_wspadmin_query_filled:
                    switch( work_mode ) {
                        case ien_log:
                            ds_query_log.imc_count_filled = atoi( ach_value );
                            break;
                        default:
                            // ignore this value:
                            break;
                    }
                    break;

                case ied_wspadmin_query_epoch:
                    switch( work_mode ) {
                        case ien_log:
                            ds_query_log.ilc_epoch = m_str_to_ll( ach_value, NULL, 10 );
                            ds_query_log.iec_wa1l  = ied_wa1l_epoch;
                            break;
                        default:
                            // ignore this value:
                            break;
                    }
                    break;

                case ied_wspadmin_query_search:
                    switch( work_mode ) {
                        case ien_log:
                            ach_search                 = ach_value;
                            ds_query_log.imc_len_query = in_len_val;
                            bo_is_search               = true;
                            break;
                        default:
                            // ignore this value:
                            break;
                    }
                    break;

                case ied_wspadmin_query_session:
                    switch ( work_mode ) {
                        case ien_cancel_session:
                            ds_query_disconnect.imc_session_no = atoi( ach_value );
                            break;
                        default:
                            // ignore this value:
                            break;
                    }
                    break;

                case ied_wspadmin_query_wildcard:
                    switch( work_mode ) {
                        case ien_session:
                            ds_query_session.boc_use_wildcard = (atoi( ach_value )>0)?TRUE:FALSE;
                            break;
                        default:
                            // ignore this value:
                            break;
                    }
                case ied_wspadmin_query_regexp:
                    switch( work_mode ) {
                        case ien_log:
                            ds_query_log.boc_query_regex = (atoi( ach_value )>0)?TRUE:FALSE;
                            break;
                        default:
                            // ignore this value:
                            break;
                    }
                    break;

                case ied_wspadmin_query_backward:
                    switch( work_mode ) {
                        case ien_log:
                            ds_query_log.boc_backward = (atoi( ach_value )>0)?TRUE:FALSE;
                            break;
                        default:
                            // ignore this value:
                            break;
                    }
                    break;
            }
        }

        in_element++;
    } // end of while loop

    // check maxsize for receives:
#ifdef MAX_ENTRIES_PER_PAGE
    if ( bo_is_search == false ) {
        switch( work_mode ) {
            case ien_session:
                if ( ds_query_session.imc_no_session > MAX_ENTRIES_PER_PAGE ) {
                    ds_query_session.imc_no_session = MAX_ENTRIES_PER_PAGE;
                }
                break;
            case ien_log:
                if ( ds_query_log.imc_retr_no_rec > MAX_ENTRIES_PER_PAGE ) {
                    ds_query_log.imc_retr_no_rec = MAX_ENTRIES_PER_PAGE;
                }
                break;
        }
    }
#endif

    return true;
} // end of ds_wsp_admin::m_read_query


/**
 * private function ds_wsp_admin::m_get_data
 *
 * @return  ds_hvector_btype<dsd_wspadm_all>
*/
bool ds_wsp_admin::m_get_data(ds_hvector_btype<dsd_wspadm_all>& rdsp_out)
{
    // initialize some variables:
    dsd_wspadm_all                   dsl_wspadm;
    dsd_gather_i_1*                  ads_gather;         // wsp gathers struct
    ied_admin_mode                   ien_temp_wm;        // save workmode while cluster call
    bool                             bo_parse;           // return from parsing
    dsd_cluster_remote_01*           ads_remote_wsp;     // remote wsp

#define DDMOD20140701

    //-----------------------------------------
    // information is requested from all wsps:
    //-----------------------------------------
    if ( boc_getall_wsp == true ) {
        //-------------------------------------
        // do we have some saved information?
        //-------------------------------------
        if ( this->adsc_cluster == NULL ) {
            /*
                we have no saved cluster information
                -> get it
            */
            //---------------------------------
            // save set workmode:
            //---------------------------------
            ien_temp_wm = work_mode;
            work_mode   = ien_cluster;

            //---------------------------------
            // get cluster information:
            //---------------------------------
            ads_gather = ads_wsp_helper->m_cb_adm_cluster( true );
            if ( ads_gather == NULL ) {
                return false;
            }
            dsl_wspadm.adsc_gather              = ads_gather;
            dsl_wspadm.dsc_wsp.ilc_handle       = 0;

            dsd_read_cluster_context dsl_context;
				//---------------------------------
            // parse response:
            //---------------------------------
            bo_parse = m_parse_data_element( &dsl_wspadm, &dsl_context );
            if ( bo_parse == false ) {
                return false;
            }
				this->adsc_cluster = dsl_context.dsc_clusters.m_get_first();

            //---------------------------------
            // reset workmode:
            //---------------------------------
            work_mode = ien_temp_wm;
        }

        //-------------------------------------
        // send request to local wsp:
        //-------------------------------------
        il_wsp_handle = 0;
        ads_gather    = m_send_request( true );
        if ( ads_gather == NULL ) {
            return false;
        }
        dsl_wspadm.adsc_gather              = ads_gather;
        dsl_wspadm.dsc_wsp.ilc_handle       = 0;
        dsl_wspadm.dsc_wsp.achc_srv_name    = this->adsc_cluster->ach_serv_name;
        dsl_wspadm.dsc_wsp.inc_len_srv_name = this->adsc_cluster->ds_main.imc_len_server_name;
        dsl_wspadm.dsc_wsp.achc_wsp_name    = this->adsc_cluster->ach_conf_name;
        dsl_wspadm.dsc_wsp.inc_len_wsp_name = this->adsc_cluster->ds_main.imc_len_wsp_name;
#ifdef DDMOD20140701
		  dsl_wspadm.dsc_wsp.achc_srv_group   = this->adsc_cluster->ach_serv_group;
		  dsl_wspadm.dsc_wsp.inc_len_srv_group= this->adsc_cluster->ds_main.imc_len_group;
		  dsl_wspadm.dsc_wsp.achc_srv_location= this->adsc_cluster->ach_serv_location;
		  dsl_wspadm.dsc_wsp.inc_len_srv_location = this->adsc_cluster->ds_main.imc_len_location;
#endif
        rdsp_out.m_add( dsl_wspadm );


        //-------------------------------------
        // send request to all remote wsps:
        //-------------------------------------
        ads_remote_wsp = this->adsc_cluster->ads_next;
        while ( ads_remote_wsp != NULL ) {
            // get handle:
            il_wsp_handle = ads_remote_wsp->ds_remote.ilc_handle_cluster;

            if ( il_wsp_handle > 0 ) {
                // send request:
                ads_gather = m_send_request( false );
                if ( ads_gather == NULL ) {
                    return false;
                }
                dsl_wspadm.adsc_gather      = ads_gather;
                dsl_wspadm.dsc_wsp.ilc_handle       = il_wsp_handle;
                dsl_wspadm.dsc_wsp.achc_srv_name    = ads_remote_wsp->ach_serv_name;
                dsl_wspadm.dsc_wsp.inc_len_srv_name = ads_remote_wsp->ds_remote.imc_len_server_name;
                dsl_wspadm.dsc_wsp.achc_wsp_name    = ads_remote_wsp->ach_conf_name;
                dsl_wspadm.dsc_wsp.inc_len_wsp_name = ads_remote_wsp->ds_remote.imc_len_config_name;
#ifdef DDMOD20140701
				    dsl_wspadm.dsc_wsp.achc_srv_group   = ads_remote_wsp->ach_serv_group;
				    dsl_wspadm.dsc_wsp.inc_len_srv_group= ads_remote_wsp->ds_remote.imc_len_group;
				    dsl_wspadm.dsc_wsp.achc_srv_location= ads_remote_wsp->ach_serv_location;
				    dsl_wspadm.dsc_wsp.inc_len_srv_location = ads_remote_wsp->ds_remote.imc_len_location;
#endif
                rdsp_out.m_add( dsl_wspadm );
            }

            // get next wsp:
            ads_remote_wsp = ads_remote_wsp->ads_next;
        } // end of loop through all remote wsp

        //-------------------------------------
        // reset some values:
        //-------------------------------------
        il_wsp_handle  = 0;
        boc_getall_wsp = false;

        return true;
    }

    ads_gather = m_send_request( true );
    if ( ads_gather == NULL ) {
        return false;
    }

    dsl_wspadm.adsc_gather              = ads_gather;
    dsl_wspadm.dsc_wsp.ilc_handle       = il_wsp_handle;
    dsl_wspadm.dsc_wsp.achc_srv_name    = NULL;
    dsl_wspadm.dsc_wsp.inc_len_srv_name = 0;
    dsl_wspadm.dsc_wsp.achc_wsp_name    = NULL;
    dsl_wspadm.dsc_wsp.inc_len_wsp_name = 0;

    rdsp_out.m_add( dsl_wspadm );
    return true;
} // end of ds_wsp_admin::m_get_data

/**
 * private function ds_wsp_admin::m_set_data
 *
 * @return  ds_hvector_btype<dsd_wspadm_all>
*/
bool ds_wsp_admin::m_set_data(ds_hvector_btype<dsd_wspadm_all>& rdsp_out)
{
    // initialize some variables:
    dsd_wspadm_all                   dsl_wspadm;
    dsd_gather_i_1*                  ads_gather;         // wsp gathers struct
    ied_admin_mode                   ien_temp_wm;        // save workmode while cluster call
    bool                             bo_parse;           // return from parsing
    dsd_cluster_remote_01*           ads_remote_wsp;     // remote wsp

    //-----------------------------------------
    // information is requested from all wsps:
    //-----------------------------------------
    if ( boc_getall_wsp == true ) {
        //-------------------------------------
        // do we have some saved information?
        //-------------------------------------
        if ( this->adsc_cluster == NULL ) {
            /*
                we have no saved cluster information
                -> get it
            */
            //---------------------------------
            // save set workmode:
            //---------------------------------
            ien_temp_wm = work_mode;
            work_mode   = ien_cluster;

            //---------------------------------
            // get cluster information:
            //---------------------------------
            ads_gather = ads_wsp_helper->m_cb_adm_cluster( true );
            if ( ads_gather == NULL ) {
                return false;
            }
            dsl_wspadm.adsc_gather              = ads_gather;
            dsl_wspadm.dsc_wsp.ilc_handle       = 0;

            dsd_read_cluster_context dsl_context;
				//---------------------------------
            // parse response:
            //---------------------------------
            bo_parse = m_parse_data_element( &dsl_wspadm, &dsl_context );
            if ( bo_parse == false ) {
                return false;
            }
				this->adsc_cluster = dsl_context.dsc_clusters.m_get_first();

            //---------------------------------
            // reset workmode:
            //---------------------------------
            work_mode = ien_temp_wm;
        }

        //-------------------------------------
        // send request to local wsp:
        //-------------------------------------
        il_wsp_handle = 0;
        m_send_request( true );

        //-------------------------------------
        // send request to all remote wsps:
        //-------------------------------------
        ads_remote_wsp = this->adsc_cluster->ads_next;
        while ( ads_remote_wsp != NULL ) {
            // get handle:
            il_wsp_handle = ads_remote_wsp->ds_remote.ilc_handle_cluster;

            if ( il_wsp_handle > 0 ) {
                // send request:
                m_send_request( false );
            }

            // get next wsp:
            ads_remote_wsp = ads_remote_wsp->ads_next;
        } // end of loop through all remote wsp

        //-------------------------------------
        // reset some values:
        //-------------------------------------
        il_wsp_handle  = 0;
        boc_getall_wsp = false;

        return true;
    }

    m_send_request( true );
    
    return true;
} // end of ds_wsp_admin::m_set_data

/**
 * function ds_wsp_admin::m_send_request
 * send admin interface request to wsp
 *
 * @param[in]   bool               bo_free_buffer   free buffer from previous call
 * @return      dsd_gather_i_1*                     pointer to wsp gather struct
 *                                                  NULL in error case
*/
dsd_gather_i_1* ds_wsp_admin::m_send_request( bool bo_free_buffer )
{
    // initialize some variables:
    struct dsd_gather_i_1 * ads_gather;             // wsp gathers struct

    
    // send question to wsp:
    switch ( work_mode ) {
        case ien_cluster:
            ads_gather = ads_wsp_helper->m_cb_adm_cluster( bo_free_buffer );
            break;

        case ien_session:
            ads_gather = ads_wsp_helper->m_cb_adm_session( il_wsp_handle,
                                                           bo_free_buffer,
                                                           ds_query_session,
                                                           ach_user, ach_group, ach_userfield );
            break;

        case ien_listen:
            ads_gather = ads_wsp_helper->m_cb_adm_listen( il_wsp_handle,
                                                          bo_free_buffer );
            break;

        case ien_perfdata:
            ads_gather = ads_wsp_helper->m_cb_adm_perfdata( il_wsp_handle,
                                                            bo_free_buffer );
            break;
		case ien_wsptrace_query:
			ads_gather = ads_wsp_helper->m_cb_adm_wsptrace_query( il_wsp_handle,
                                                               bo_free_buffer,
                                                               dsc_query_wsptrace,
															   imc_len_data,
															   achc_trineta);
			break;
		case ien_wsptrace_info:
			ads_gather = ads_wsp_helper->m_cb_adm_wsptrace_info( il_wsp_handle,
																bo_free_buffer);
			break;
        case ien_log:
            ads_gather = ads_wsp_helper->m_cb_adm_log( il_wsp_handle,
                                                       bo_free_buffer,
                                                       ds_query_log,
                                                       ach_search );
            break;

        case ien_cancel_session:
            ads_gather = ads_wsp_helper->m_cb_sess_disconnect( il_wsp_handle,
                                                               bo_free_buffer,
                                                               ds_query_disconnect );
            break;

        default:
            ads_gather = NULL;
            break;
    }
    return ads_gather;
} // end of ds_wsp_admin::m_send_request


/**
 * function ds_wsp_admin::m_parse_data
 *
 * @param[in]   ds_hvector_btype<dsd_wspadm_all>* ads_data
 *
 * @return      bool                              true = success
*/
bool ds_wsp_admin::m_parse_data_vector( const ds_hvector_btype<dsd_wspadm_all>* ads_data, void* avop_context )
{
    // initialize some variables:
    bool           bo_ret;              // return from parsing                                                 
    
    for (HVECTOR_FOREACH(dsd_wspadm_all, adsl_cur, *ads_data)) {
        const dsd_wspadm_all& dsl_wspdata = HVECTOR_GET(adsl_cur);
        // get response from current wsp:
        if ( dsl_wspdata.adsc_gather == NULL ) {
            continue;
        }

        // parse this response
        bo_ret = m_parse_data_element( &dsl_wspdata, avop_context );
        if ( bo_ret == false ) {
            return false;
        }
    } // end of for loop
    return true;
} // end of ds_wsp_admin::m_parse_data


/**
 * function ds_wsp_admin::m_parse_data
 *
 * @param[in]   dsd_wspadm_all*  ads_rec 
 *
 * @return      bool             true = success
*/
bool ds_wsp_admin::m_parse_data_element( const dsd_wspadm_all* ads_rec, void* avop_context )
{
    // initialize some variables:
    int    in_total_len  = 0;       // total length of gather chain
    int    in_block_len  = 0;       // length of our working block
    int    in_position   = 0;       // reading position in gather chain
    int    in_start_pos  = 0;       // start position of parsing
    char   ch_typeset    = 0;       // type of structure in our block
    bool   bo_return     = false;

    if ( ads_rec->adsc_gather == NULL ) {
        return false;
    }

    // get total gather length:
    in_total_len = ads_wsp_helper->m_get_gather_len( ads_rec->adsc_gather );

    while ( in_position < in_total_len ) {
        // get length of next block:
        in_block_len = m_get_nhasnlen( ads_rec->adsc_gather, &in_position );
        if ( in_block_len < 0 ) {
            break;
        }
        
        // get type of structure in it:
        ch_typeset = ads_wsp_helper->m_get_end_ptr( ads_rec->adsc_gather, in_position )[0];
        in_position++;  // reading pos after typeset
        in_block_len--; // first byte does not content to following struct

        // avoid reading over end:
        if (    in_block_len == 0
             || in_position >= in_total_len ) {
            // get return code:
            switch ( (unsigned char)ch_typeset ) {
                case DEF_WSPADM_RT_INV_PARAM:
                    ien_ret_code = ied_wspadmin_params;
                    break;
                case DEF_WSPADM_RT_EOF:
                    ien_ret_code = ied_wspadmin_end_of_file;
                    break;
                case DEF_WSPADM_RT_INV_REQ:
                    ien_ret_code = ied_wspadmin_inv_request;
                    break;
                case DEF_WSPADM_RT_RESOURCE_UA:
                    ien_ret_code = ied_wspadmin_rec_unavailable;
                    break;
                case DEF_WSPADM_RT_TIMEOUT:
                    ien_ret_code = ied_wspadmin_timeout;
                    break;
                case DEF_WSPADM_RT_CLUSTER:
                    ien_ret_code = ied_wspadmin_inv_cluster;
                    break;
                case DEF_WSPADM_RT_MISC:
                    ien_ret_code = ied_wspadmin_misc;
                    break;
                default:
                    ien_ret_code = ied_wspadmin_unknown;
                    break;
            }
            break;
        }
        
        // save start position of parsing:
        in_start_pos = in_position;

        switch ( work_mode ) {
            case ien_cluster:
                bo_return = m_read_cluster( ads_rec, ch_typeset, &in_position, (dsd_read_cluster_context*)avop_context );
                if ( bo_return == false ) {
                    return false;
                }
                break;

            case ien_session:
					 bo_return = m_read_session( ads_rec, ch_typeset, &in_position, (dsd_read_session_context*)avop_context );
                if ( bo_return == false ) {
                    return false;
                }
                break;

            case ien_listen:
                bo_return = m_read_listen( ads_rec, ch_typeset, &in_position, (dsd_read_listen_context*)avop_context );
                if ( bo_return == false ) {
                    return false;
                }
                break;

            case ien_perfdata:
                bo_return = m_read_perf( ads_rec, ch_typeset, &in_position, (dsd_read_perf_context*)avop_context );
                if ( bo_return == false ) {
                    return false;
                }
                break;

            case ien_log:
					bo_return = m_read_log( ads_rec, ch_typeset, &in_position, (dsd_read_log_info_context*)avop_context );
                if ( bo_return == false ) {
                    return false;
                }
                break;

            case ien_cancel_session:
					bo_return = m_read_cancel_session( ads_rec, ch_typeset, &in_position, (dsd_read_cancel_session_context*)avop_context );
                if ( bo_return == false ) {
                    return false;
                }
                break;

			case ien_wsptrace_info:
				bo_return = m_read_wsptrace_curconf(ads_rec, ch_typeset, &in_position,  (dsd_read_wsptrace_info_context*)avop_context);
				if ( bo_return == false ) {
                    return false;
                }
                break;
        }
        if ( in_position != in_block_len + in_start_pos ) {
            ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE704E: length error while reading admin data" );
            return false;
        }
    } // end of while ( in_position < in_total_len )
    return true;
} // end of ds_wsp_admin::m_parse_data


/**
 * private function ds_wsp_admin::m_sort_log
 * try to order response data from different wsps
 *
 * @return  bool
*/
bool ds_wsp_admin::m_sort_log()
{
    // initialize some variables:
#if !SM_WSP_ADMIN_LOG_OPT1
    int                           inl_entry;                  // entry counter
    bool                          bo_repeat;                  // loop control
#endif
    bool                          bo_add;                     // add entry
    int                           inl_filled;                 // last filled field
    HL_LONGLONG                   ill_hepoch;                 // oldest entry per wsp
    dsd_log_info*                 adsl_ltmp1;                 // temporary log working variable
    dsd_log_info*                 adsl_ltmp2;                 // temporary log working variable
    dsd_log_wsp                   dsl_log;                    // working variable
    ds_hvector_btype<dsd_log_wsp> dsl_logs( ads_wsp_helper ); // log entries per wsp

    /*
        incoming records look like this:

        +--------+----------+-------+-----------+-------------------------------------------
        | time 1 | filled 1 | pos 1 | log msg 1 | log records from local wsp
        | time 2 | filled 2 | pos 2 | log msg 2 | 
        .        .          .       .           .
        .        .          .       .           .  max ds_query_log.imc_retr_no_rec entries
        .        .          .       .           .
        | time N | filled N | pos N | log msg N |
        +--------+----------+-------+-----------+-------------------------------------------
        | time 1 | filled 1 | pos 1 | log msg 1 | log records from remote wsp 1
        | time 2 | filled 2 | pos 2 | log msg 2 | 
        .        .          .       .           .
        .        .          .       .           . max ds_query_log.imc_retr_no_rec entries
        .        .          .       .           .
        | time M | filled M | pos M | log msg M |
        +--------+----------+-------+-----------+-------------------------------------------
        .        .          .       .           .
        .        .          .       .           .
        .        .          .       .           .
        +--------+----------+-------+-----------+-------------------------------------------
        | time 1 | filled 1 | pos 1 | log msg 1 | log records from remote wsp X
        | time 2 | filled 2 | pos 2 | log msg 2 | 
        .        .          .       .           .
        .        .          .       .           . max ds_query_log.imc_retr_no_rec entries
        .        .          .       .           .
        | time L | filled L | pos L | log msg L |
        +--------+----------+-------+-----------+-------------------------------------------

        we will order outgoing data by timestamp (oldest is last one)
    */

    //-------------------------------------------
    // count received records per responding wsp:
    //-------------------------------------------
    dsl_log.ilc_handle     = this->adsc_log->dsc_wsp.ilc_handle;
    dsl_log.adsc_first_log = this->adsc_log;
#if SM_WSP_ADMIN_LOG_OPT1
    dsl_log.adsc_cur = NULL;
    dsl_log.adsc_end_log = this->adsc_log;
#else
    dsl_log.inc_entries    = 0;
    dsl_log.inc_added      = 0;
#endif

    bo_add                 = true;
    inl_filled             = -1;

    adsl_ltmp1 = this->adsc_log;
    while ( adsl_ltmp1 != NULL ) {
        //---------------------------------------
        // check handle:
        //---------------------------------------
        if ( adsl_ltmp1->dsc_wsp.ilc_handle != dsl_log.ilc_handle ) {
#if SM_WSP_ADMIN_LOG_OPT1
            dsl_log.adsc_cur = (ds_query_log.boc_backward == FALSE) ? dsl_log.adsc_first_log : dsl_log.adsc_end_log;
            dsl_log.adsc_end = (ds_query_log.boc_backward == FALSE) ? dsl_log.adsc_end_log->ads_next : dsl_log.adsc_first_log->ads_prev;
#endif
            dsl_logs.m_add( dsl_log );

            // init new element:
            dsl_log.ilc_handle     = adsl_ltmp1->dsc_wsp.ilc_handle;
            dsl_log.adsc_first_log = adsl_ltmp1;
#if SM_WSP_ADMIN_LOG_OPT1
            dsl_log.adsc_cur = NULL;
            dsl_log.adsc_end_log = adsl_ltmp1;
#else
            dsl_log.inc_entries    = 0;
            dsl_log.inc_added      = 0;
#endif
            bo_add                 = true;
            inl_filled             = -1;
        }

        //---------------------------------------
        // check filled state:
        //---------------------------------------
        if ( bo_add == true ) {
            if ( inl_filled > -1 ) {
                bo_add = m_check_filled( inl_filled,
                                         adsl_ltmp1->ds_main.imc_count_filled );
            }
            // save this filled state:
            inl_filled = adsl_ltmp1->ds_main.imc_count_filled;
        }

        //---------------------------------------
        // get next element:
        //---------------------------------------
        if ( bo_add == true ) {
#if SM_WSP_ADMIN_LOG_OPT1
            dsl_log.adsc_end_log = adsl_ltmp1;
#else
            // count:
            dsl_log.inc_entries++;
#endif
            // get next:
            adsl_ltmp1 = adsl_ltmp1->ads_next;
        } else {
            // save next pointer:
            adsl_ltmp2 = adsl_ltmp1->ads_next;

            // free this entry:
            if ( adsl_ltmp1->ach_message != NULL ) {
                ads_wsp_helper->m_cb_free_memory( (void*)adsl_ltmp1->ach_message );
            }
            ads_wsp_helper->m_cb_free_memory( adsl_ltmp1 );

            // get next:
            adsl_ltmp1 = adsl_ltmp2;
        }
    }
#if SM_WSP_ADMIN_LOG_OPT1
    dsl_log.adsc_cur = (ds_query_log.boc_backward == FALSE) ? dsl_log.adsc_first_log : dsl_log.adsc_end_log;
    dsl_log.adsc_end = (ds_query_log.boc_backward == FALSE) ? dsl_log.adsc_end_log->ads_next : dsl_log.adsc_first_log->ads_prev;
#endif
    // add last element:
    dsl_logs.m_add( dsl_log );

    //-------------------------------------------
    // reset last entry per wsp and get last to display:
    //-------------------------------------------
    ill_hepoch = -1;
    for ( HVECTOR_FOREACH2(dsd_log_wsp, adsl_cur, dsl_logs) ) {
        //---------------------------------------
        // get current wsp log:
        //---------------------------------------
        dsd_log_wsp& rdsl_log = HVECTOR_GET(adsl_cur);

        //---------------------------------------
        // get oldest last element over all wsps:
        //---------------------------------------
        adsl_ltmp2 = rdsl_log.adsc_first_log;
        if ( ds_query_log.boc_backward == FALSE ) {
            if ( ill_hepoch == -1 ) {
                ill_hepoch = adsl_ltmp2->ds_main.ilc_epoch; 
            } else {
                if ( ill_hepoch < adsl_ltmp2->ds_main.ilc_epoch ) {
                    ill_hepoch = adsl_ltmp2->ds_main.ilc_epoch;
                }
            }
        }

        //---------------------------------------
        // get last element:
        //---------------------------------------
#if SM_WSP_ADMIN_LOG_OPT1
        adsl_ltmp2 = rdsl_log.adsc_end_log;
#else
        for ( inl_entry = 1; inl_entry < rdsl_log.inc_entries; inl_entry++ ) {
            adsl_ltmp2 = adsl_ltmp2->ads_next;
        }
        adsl_ltmp2->ads_next = NULL;
#endif

        //---------------------------------------
        // get newest last element over all wsps:
        //---------------------------------------
        if ( ds_query_log.boc_backward == TRUE ) {
            if ( ill_hepoch == -1 ) {
                ill_hepoch = adsl_ltmp2->ds_main.ilc_epoch; 
            } else {
                if ( ill_hepoch < adsl_ltmp2->ds_main.ilc_epoch ) {
                    ill_hepoch = adsl_ltmp2->ds_main.ilc_epoch;
                }
            }
        }
    }

#if !SM_WSP_ADMIN_LOG_OPT1
    //-------------------------------------------
    // remove entries older/newer to display limit:
    //-------------------------------------------
    for ( HVECTOR_FOREACH2(dsd_log_wsp, adsl_cur, dsl_logs) ) {
        dsd_log_wsp& rdsl_log = HVECTOR_GET(adsl_cur);
        //---------------------------------------
        // get current wsp log (reference):
        //---------------------------------------
 
        //---------------------------------------
        // loop through all element:
        //---------------------------------------
        adsl_ltmp1 = rdsl_log.adsc_first_log;
        for ( inl_entry = 0; inl_entry < rdsl_log.inc_entries; inl_entry++ ) {
            if ( ill_hepoch > adsl_ltmp1->ds_main.ilc_epoch ) {
                if ( ds_query_log.boc_backward == FALSE ) {
                    rdsl_log.inc_added++;
#if SM_WSP_ADMIN_LOG_OPT1
                    rdsl_log.adsc_added = adsl_ltmp1;
#endif
                } else {
                    rdsl_log.inc_entries = inl_entry;
#if SM_WSP_ADMIN_LOG_OPT1
                    rdsl_log.adsc_end_log = adsl_ltmp1;
#endif
                    break;
                }
            }
            adsl_ltmp1 = adsl_ltmp1->ads_next;
        }

        //---------------------------------------
        // modified automatically
        //---------------------------------------
    }
#endif


    //-------------------------------------------
    // order records:
    //-------------------------------------------
    this->adsc_log   = NULL;
	 dsd_read_log_info_context dsl_context;
#if SM_WSP_ADMIN_LOG_OPT1
    while ( true ) {
#else
    bo_repeat = true;
    while ( bo_repeat ) {
#endif
        //---------------------------------------
        // reset insert var:
        //---------------------------------------
        adsl_ltmp1 = NULL;

        //---------------------------------------
        // get smallest entry:
        //---------------------------------------
#if SM_WSP_ADMIN_LOG_OPT1
        dsd_log_wsp* adsl_smallest = NULL;
#else
        dsd_hvec_elem<dsd_log_wsp>* adsl_smallest = NULL;
#endif
        for ( HVECTOR_FOREACH2(dsd_log_wsp, adsl_cur, dsl_logs) ) {
            //-----------------------------------
            // get current wsp log:
            //-----------------------------------
            dsd_log_wsp& rdsl_log = HVECTOR_GET(adsl_cur);

#if SM_WSP_ADMIN_LOG_OPT1
            if(rdsl_log.adsc_cur == NULL)
                continue;
            if(rdsl_log.adsc_cur == rdsl_log.adsc_end)
                continue;
            adsl_ltmp2 = rdsl_log.adsc_cur;
            if(adsl_smallest == NULL)
                adsl_smallest = &rdsl_log;
            else if(rdsl_log.adsc_cur->ds_main.ilc_epoch < adsl_smallest->adsc_cur->ds_main.ilc_epoch)
                adsl_smallest = &rdsl_log;
#else
            //-----------------------------------
            // check number of entries:
            //-----------------------------------
            if ( rdsl_log.inc_added == rdsl_log.inc_entries ) {
                continue;
            }
            //-----------------------------------
            // get requested element:
            //-----------------------------------
            if ( ds_query_log.boc_backward == FALSE ) {
                adsl_ltmp2 = rdsl_log.adsc_first_log;
                for ( inl_entry = 0; inl_entry < rdsl_log.inc_added; inl_entry++ ) {
                    adsl_ltmp2 = adsl_ltmp2->ads_next;
                }
            } else {
                adsl_ltmp2 = rdsl_log.adsc_first_log;
                for ( inl_entry = rdsl_log.inc_entries - 1; inl_entry > rdsl_log.inc_added; inl_entry-- ) {
                    adsl_ltmp2 = adsl_ltmp2->ads_next;
                }
            }
            //-----------------------------------
            // set elements:
            //-----------------------------------
            if ( adsl_ltmp1 == NULL ) {
                adsl_ltmp1 = m_get_next_log_ptr();
                adsl_smallest           = adsl_cur;
                adsl_ltmp1->dsc_wsp     = adsl_ltmp2->dsc_wsp;
                adsl_ltmp1->ds_main     = adsl_ltmp2->ds_main;
                adsl_ltmp1->ach_message = adsl_ltmp2->ach_message;
            } else {
                if ( adsl_ltmp1->ds_main.ilc_epoch > adsl_ltmp2->ds_main.ilc_epoch ) {
                    adsl_smallest           = adsl_cur;
                    adsl_ltmp1->dsc_wsp     = adsl_ltmp2->dsc_wsp;
                    adsl_ltmp1->ds_main     = adsl_ltmp2->ds_main;
                    adsl_ltmp1->ach_message = adsl_ltmp2->ach_message;
                }
            }
#endif

            //-----------------------------------
            // set elements:
            //-----------------------------------
        } // end of get smallest entry loop

#if SM_WSP_ADMIN_LOG_OPT1
        if(adsl_smallest == NULL)
            break;

        HL_LONGLONG ill_min_epoch = adsl_smallest->adsc_cur->ds_main.ilc_epoch;
        dsd_log_info* adsl_end = adsl_smallest->adsc_end;
        dsd_log_info* adsl_cur_entry = adsl_smallest->adsc_cur;
        do {
            if(adsl_cur_entry->ds_main.ilc_epoch != ill_min_epoch) {
                break;
            }
            adsl_ltmp1 = m_get_next_log_ptr(&dsl_context);
            adsl_ltmp1->dsc_wsp     = adsl_cur_entry->dsc_wsp;
            adsl_ltmp1->ds_main     = adsl_cur_entry->ds_main;
            adsl_ltmp1->ach_message = adsl_cur_entry->ach_message;
            adsl_cur_entry = (ds_query_log.boc_backward == FALSE) ? adsl_cur_entry->ads_next : adsl_cur_entry->ads_prev;
        } while(adsl_cur_entry != adsl_end);
        adsl_smallest->adsc_cur = adsl_cur_entry;
#else
        //---------------------------------------
        // get entries with same timestamp:
        //---------------------------------------
        for ( HVECTOR_ITERATE2(dsd_log_wsp, adsl_cur, adsl_smallest, NULL) ) {
            //-----------------------------------
            // get current wsp log:
            //-----------------------------------
            dsd_log_wsp& rdsl_log = HVECTOR_GET(adsl_cur);

            //-----------------------------------
            // count smallest entry:
            //-----------------------------------
            if ( adsl_cur == adsl_smallest ) {
                rdsl_log.inc_added++;
            }

            //-----------------------------------
            // check number of entries:
            //-----------------------------------
            if ( rdsl_log.inc_added == rdsl_log.inc_entries ) {
                continue;
            }

            //-----------------------------------
            // get requested element:
            //-----------------------------------
            if ( ds_query_log.boc_backward == FALSE ) {
                adsl_ltmp2 = rdsl_log.adsc_first_log;
                for ( inl_entry = 0; inl_entry < rdsl_log.inc_added; inl_entry++ ) {
                    adsl_ltmp2 = adsl_ltmp2->ads_next;
                }
            } else {
                adsl_ltmp2 = rdsl_log.adsc_first_log;
                for ( inl_entry = rdsl_log.inc_entries - 1; inl_entry > rdsl_log.inc_added; inl_entry-- ) {
                    adsl_ltmp2 = adsl_ltmp2->ads_next;
                }
            }


            //-----------------------------------
            // add entries:
            //-----------------------------------
            while (    rdsl_log.inc_added              < rdsl_log.inc_entries
                    && adsl_ltmp1->ds_main.ilc_epoch == adsl_ltmp2->ds_main.ilc_epoch ) {
                // add to chain:
                adsl_ltmp1 = m_get_next_log_ptr(&dsl_context);
                adsl_ltmp1->dsc_wsp     = adsl_ltmp2->dsc_wsp;
                adsl_ltmp1->ds_main     = adsl_ltmp2->ds_main;
                adsl_ltmp1->ach_message = adsl_ltmp2->ach_message;

                // get next element:
                if ( ds_query_log.boc_backward == FALSE ) {
                    adsl_ltmp2 = adsl_ltmp2->ads_next;
                } else {
                    adsl_ltmp2 = adsl_ltmp2->ads_prev;
                }
                rdsl_log.inc_added++;
            }

            //-----------------------------------
            // set changes in vector (automatically by ref):
            //-----------------------------------
        } // end of fill same timestamp loop

        //---------------------------------------
        // check if all are inserted:
        //---------------------------------------
        for ( HVECTOR_FOREACH(dsd_log_wsp, adsl_cur, dsl_logs) ) {
            //-----------------------------------
            // get current wsp log:
            //-----------------------------------
            const dsd_log_wsp& rdsl_log = HVECTOR_GET(adsl_cur);
            //-----------------------------------
            // reset repeat flag.
            //-----------------------------------
            bo_repeat = true;

            //-----------------------------------
            // check number of entries:
            //-----------------------------------
            if ( rdsl_log.inc_added == rdsl_log.inc_entries ) {
                bo_repeat = false;
            } else {
                break;
            }
        } // end of check for end loop
#endif
    } // end of while loop

    //-------------------------------------------
    // free unordered records:
    //-------------------------------------------
    for ( HVECTOR_FOREACH2(dsd_log_wsp, adsl_cur, dsl_logs) ) {
        //-----------------------------------
        // get current wsp log:
        //-----------------------------------
        dsd_log_wsp& rdsl_log = HVECTOR_GET(adsl_cur);
    
        //-----------------------------------
        // get requested element:
        //-----------------------------------
        m_free_log( rdsl_log.adsc_first_log, true );
    }

	 this->adsc_log = dsl_context.dsc_logs.m_get_first();
    return true;
} // end of ds_wsp_admin::m_sort_log


/**
 * private function ds_wsp_admin::m_check_filled
 *
 * @param[in]   int     in_filled1
 * @param[in]   int     in_filled2
 * @return      bool
*/
bool ds_wsp_admin::m_check_filled( int in_filled1, int in_filled2 )
{
    if ( ds_query_log.boc_backward == FALSE ) {
        if ( in_filled1 <= in_filled2 ) {
            return true;
        }
    } else {
        if ( in_filled1 >= in_filled2 ) {
            return true;
        }
    }
    return false;
} // end of ds_wsp_admin::m_check_filled


/**
 * function ds_wsp_admin::m_read_cluster
 *
 * @param[in]       dsd_wspadm_all*  ads_rec
 * @param[in]       char             ch_typeset
 * @param[in/out]   int*             ain_position
 *
 * @return          bool             true = success
*/
bool ds_wsp_admin::m_read_cluster( const dsd_wspadm_all* ads_rec,
                                   char ch_typeset, int* ain_position,
											  dsd_read_cluster_context* adsp_context )
{
    // initialize some variables:
    bool bo_return = false;

    if ( ch_typeset == 0 ) {
        bo_return = m_read_cluster_type0( ads_rec, ain_position, adsp_context );
    } else if ( ch_typeset == 1 ) {
        bo_return = m_read_cluster_type1( ads_rec, ain_position, adsp_context );
    } else {
        ads_wsp_helper->m_logf( ied_sdh_log_error,
                                "HIWSE700E: Unknown structure type %c selected - ignored",
                                ch_typeset );
    }

    return bo_return;
} // end of ds_wsp_admin::m_read_cluster


/**
 * function ds_wsp_admin::m_get_next_cluster_ptr
*/
dsd_cluster_remote_01* ds_wsp_admin::m_get_next_cluster_ptr(dsd_read_cluster_context* adsp_context)
{
    dsd_cluster* ads_temp = adsp_context->dsc_clusters.m_get_last();
    if ( ads_temp == NULL ) {
        // no structure type 0 received before, error
        return NULL;
    }
	 dsd_cluster_remote_01* ads_remote = (dsd_cluster_remote_01*)ads_wsp_helper->m_cb_get_memory(
                              (int)sizeof(dsd_cluster_remote_01), true);
	 adsp_context->dsc_clusters_remote.m_append(ads_remote);
	 if ( ads_temp->ads_next == NULL ) {
		 ads_temp->ads_next = ads_remote;
	 }
    return ads_remote;
} // end of ds_wsp_admin::m_get_next_cluster_ptr


/**
 * function ds_wsp_admin::m_get_next_session_ptr
*/
dsd_session_info* ds_wsp_admin::m_get_next_session_ptr(dsd_read_session_context* adsp_context)
{
    dsd_session_info* ads_temp = NULL;

    ads_temp = (dsd_session_info*)ads_wsp_helper->m_cb_get_memory(
                       (int)sizeof(dsd_session_info), true);
	 adsp_context->dsc_sessions.m_append(ads_temp);
    return ads_temp;
} // end of ds_wsp_admin::m_get_next_session_ptr

/**
 * function ds_wsp_admin::m_get_next_wsptrace_ptr
*/
dsd_wsptrace_info* ds_wsp_admin::m_get_next_wsptrace_ptr(dsd_read_wsptrace_info_context* adsp_context)
{
    dsd_wsptrace_info* adsl_temp = (dsd_wsptrace_info*)ads_wsp_helper->m_cb_get_memory(
                                    (int)sizeof(dsd_wsptrace_info), true);
	 adsp_context->dsc_traces.m_append(adsl_temp);
    return adsl_temp;
} // end of ds_wsp_admin::m_get_next_wsptrace_ptr

/**
 * function ds_wsp_admin::m_get_next_log_ptr
*/
dsd_log_info* ds_wsp_admin::m_get_next_log_ptr(dsd_read_log_info_context* adsp_context)
{
	 dsd_log_info* ads_temp = NULL;

    ads_temp = (dsd_log_info*)ads_wsp_helper->m_cb_get_memory(
                       (int)sizeof(dsd_log_info), true);
	 adsp_context->dsc_logs.m_append(ads_temp);
    return ads_temp;
} // end of ds_wsp_admin::m_get_next_log_ptr


/**
 * function ds_wsp_admin::m_get_next_listen_ptr
*/
dsd_listen* ds_wsp_admin::m_get_next_listen_ptr(dsd_read_listen_context* adsp_context)
{
    dsd_listen* ads_temp = NULL;
    ads_temp = (dsd_listen*)ads_wsp_helper->m_cb_get_memory( 
                                (int)sizeof(dsd_listen), true );
	 adsp_context->dsc_listens.m_append(ads_temp);
	 adsp_context->dsc_each_listens.m_reset();
    return ads_temp;
} // end of ds_wsp_admin::m_get_next_listen_ptr


/**
 * function ds_wsp_admin::m_get_next_listen_each_ptr
*/
dsd_each_listen* ds_wsp_admin::m_get_next_listen_each_ptr(dsd_read_listen_context* adsp_context)
{
    dsd_listen*      ads_temp = adsp_context->dsc_listens.m_get_last();
    if ( ads_temp == NULL ) {
        // no structure type 0 received before, error
        return NULL;
    }
	 dsd_each_listen* ads_each_listen = (dsd_each_listen*)ads_wsp_helper->m_cb_get_memory(
                              (int)sizeof(dsd_each_listen), true);
	 adsp_context->dsc_each_listens.m_append(ads_each_listen);
    if ( ads_temp->ads_each == NULL ) {
		 ads_temp->ads_each = ads_each_listen;
	 }
    return ads_each_listen;
} // end of ds_wsp_admin::m_get_next_listen_each_ptr


/**
 * function ds_wsp_admin::m_read_cluster_type0
 *
 * @param[in]       dsd_wspadm_all*  ads_rec
 * @param[in/out]   int*             ain_position
 *
 * @return          bool             true = success
*/
bool ds_wsp_admin::m_read_cluster_type0( const dsd_wspadm_all* ads_rec, int* ain_position, dsd_read_cluster_context* adsp_context )
{
    // initialize some variables:
    bool bo_ret = false;     // return for several functions value

	 dsd_cluster* ads_cluster = NULL;
    ads_cluster = (dsd_cluster*)ads_wsp_helper->m_cb_get_memory( 
                                (int)sizeof(dsd_cluster), true );
	 adsp_context->dsc_clusters.m_append(ads_cluster);
	 adsp_context->dsc_clusters_remote.m_reset();
    
    // copy structure:
    bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position,
                          sizeof(dsd_wspadm1_cluster_main),
                          ((char*)&(ads_cluster->ds_main)) );
    if ( bo_ret == false ) {
        return false;
    }

    // copy next data: following string server_name:
    if ( ads_cluster->ds_main.imc_len_server_name > 0 ) {
        ads_cluster->ach_serv_name = ads_wsp_helper->m_cb_get_memory( 
                                        ads_cluster->ds_main.imc_len_server_name + 1, true );
        if ( ads_cluster->ach_serv_name == NULL ) {
            return false;
        }
        bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position,
                              ads_cluster->ds_main.imc_len_server_name,
                              ads_cluster->ach_serv_name );
        if ( bo_ret == false ) {
            return false;
        }
    }

    // copy next data: following string wsp_query:
    if ( ads_cluster->ds_main.imc_len_query_main > 0 ) {
        ads_cluster->ach_wsp_query = ads_wsp_helper->m_cb_get_memory( 
                                        ads_cluster->ds_main.imc_len_query_main + 1, true );
        if ( ads_cluster->ach_wsp_query == NULL ) {
            return false;
        }
        bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position,
                              ads_cluster->ds_main.imc_len_query_main,
                              ads_cluster->ach_wsp_query );
        if ( bo_ret == false ) {
            return false;
        }
    }

    // copy next data: following string wsp_name:
    if ( ads_cluster->ds_main.imc_len_wsp_name > 0 ) {
        ads_cluster->ach_conf_name = ads_wsp_helper->m_cb_get_memory( 
                                        ads_cluster->ds_main.imc_len_wsp_name + 1, true );
        if ( ads_cluster->ach_conf_name == NULL ) {
            return false;
        }
        bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position,
                              ads_cluster->ds_main.imc_len_wsp_name,
                              ads_cluster->ach_conf_name );
        if ( bo_ret == false ) {
            return false;
        }
    }

	// copy next data: following string wsp_group:
    if ( ads_cluster->ds_main.imc_len_group > 0 ) {
		ads_cluster->ach_serv_group = ads_wsp_helper->m_cb_get_memory( 
                                        ads_cluster->ds_main.imc_len_group + 1, true );
		if ( ads_cluster->ach_serv_group == NULL ) {
            return false;
        }
        bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position,
							  ads_cluster->ds_main.imc_len_group,
                              ads_cluster->ach_serv_group);
        if ( bo_ret == false ) {
            return false;
        }
	}
	// copy next data: following string wsp_location:
    if ( ads_cluster->ds_main.imc_len_location > 0 ) {
		ads_cluster->ach_serv_location = ads_wsp_helper->m_cb_get_memory( 
                                        ads_cluster->ds_main.imc_len_location + 1, true );
		if ( ads_cluster->ach_serv_location == NULL ) {
            return false;
        }
        bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position,
							  ads_cluster->ds_main.imc_len_location,
                              ads_cluster->ach_serv_location);
        if ( bo_ret == false ) {
            return false;
        }
	}
    return true;
} // end of ds_wsp_admin::m_read_cluster_type0


/**
 * function ds_wsp_admin::m_read_cluster_type1
 *
 * @param[in]       dsd_wspadm_all*  ads_rec
 * @param[in/out]   int*             ain_position
 *
 * @return          bool             true = success
*/
bool ds_wsp_admin::m_read_cluster_type1( const dsd_wspadm_all* ads_rec, int* ain_position, dsd_read_cluster_context* adsp_context )
{
    // initialize some variables:
    bool bo_ret                    = false;    // return for several functions value
    dsd_cluster_remote_01* ads_remote = NULL;

    ads_remote = m_get_next_cluster_ptr(adsp_context);
    if ( ads_remote == NULL ) {
        return false;
    }

    // copy structure:
    bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position,
                          sizeof(dsd_wspadm1_cluster_remote),
                          ((char*)&(ads_remote->ds_remote)) );
    if ( bo_ret == false ) {
        return false;
    }

    // copy next data: following string conf_name:
    if ( ads_remote->ds_remote.imc_len_config_name > 0 ) {
        ads_remote->ach_conf_name = ads_wsp_helper->m_cb_get_memory(
                                        ads_remote->ds_remote.imc_len_config_name + 1, true );
        if ( ads_remote->ach_conf_name == NULL ) {
            return false;
        }
        bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position,
                              ads_remote->ds_remote.imc_len_config_name,
                              ads_remote->ach_conf_name );
        if ( bo_ret == false ) {
            return false;
        }
    }

    // copy next data: following string server_name:
    if ( ads_remote->ds_remote.imc_len_server_name > 0 ) {
        ads_remote->ach_serv_name = ads_wsp_helper->m_cb_get_memory( 
                                        ads_remote->ds_remote.imc_len_server_name + 1, true );
        if ( ads_remote->ach_serv_name == NULL ) {
            return false;
        }
        bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position,
                              ads_remote->ds_remote.imc_len_server_name,
                              ads_remote->ach_serv_name );
        if ( bo_ret == false ) {
            return false;
        }
    }

    // copy next data: following string wsp_query:
    if ( ads_remote->ds_remote.imc_len_query_main > 0 ) {
        ads_remote->ach_wsp_query = ads_wsp_helper->m_cb_get_memory(
                                        ads_remote->ds_remote.imc_len_query_main + 1, true );
        if ( ads_remote->ach_wsp_query == NULL ) {
            return false;
        }
        bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position,
                              ads_remote->ds_remote.imc_len_query_main,
                              ads_remote->ach_wsp_query );
        if ( bo_ret == false ) {
            return false;
        }
    }

	// copy next data: following string server_group:
    if ( ads_remote->ds_remote.imc_len_group > 0 ) {
		ads_remote->ach_serv_group = ads_wsp_helper->m_cb_get_memory( 
                                        ads_remote->ds_remote.imc_len_group + 1, true );
        if ( ads_remote->ach_serv_group == NULL ) {
            return false;
        }
        bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position,
                              ads_remote->ds_remote.imc_len_group,
                              ads_remote->ach_serv_group );
        if ( bo_ret == false ) {
            return false;
        }
    }
	// copy next data: following string server_location:
    if ( ads_remote->ds_remote.imc_len_location > 0 ) {
		ads_remote->ach_serv_location = ads_wsp_helper->m_cb_get_memory( 
                                        ads_remote->ds_remote.imc_len_location + 1, true );
        if ( ads_remote->ach_serv_location == NULL ) {
            return false;
        }
        bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position,
                              ads_remote->ds_remote.imc_len_location,
                              ads_remote->ach_serv_location );
        if ( bo_ret == false ) {
            return false;
        }
    }
    
    return true;
}  // end of ds_wsp_admin::m_read_cluster_type1


/**
 * function ds_wsp_admin::m_read_perf
 *
 * @param[in]       dsd_wspadm_all*  ads_rec
 * @param[in]       char             ch_typeset
 * @param[in/out]   int*             ain_position
 *
 * @return          bool             true = success
*/
bool ds_wsp_admin::m_read_perf( const dsd_wspadm_all* ads_rec, char ch_typeset,
                                int* ain_position, dsd_read_perf_context* adsp_context )
{
    // initialize some variables:
    bool bo_return = false;

    // setup cluster structure:
    if ( adsp_context->adsc_perfdata == NULL ) {
        adsp_context->adsc_perfdata = (dsd_perfdata*)ads_wsp_helper->m_cb_get_memory( sizeof(dsd_perfdata), true );
        if ( adsp_context->adsc_perfdata == NULL ) {
            return false;
        }
    }
    
    if ( ch_typeset == 0 ) {
        bo_return = m_read_perf_type0( ads_rec, ain_position, adsp_context );
    } else {
        ads_wsp_helper->m_logf( ied_sdh_log_error,
                                "HIWSE703E: Unknown structure type %c seleted - ignored",
                                ch_typeset );
    }

    return bo_return;
} // end of ds_wsp_admin::m_read_perf

/**
 * function ds_wsp_admin::m_read_wsptrace_curconf
 *
 * @param[in]       dsd_wspadm_all*  ads_rec
 * @param[in]       char             ch_typeset
 * @param[in/out]   int*             ain_position
 *
 * @return          bool             true = success
*/
bool ds_wsp_admin::m_read_wsptrace_curconf(const dsd_wspadm_all* adsp_rec, char chp_typeset,
                                int* ainp_position, dsd_read_wsptrace_info_context* adsp_context )
{
    // initialize some variables:
    bool bol_return = false;

	// The following line of code are needed because, when the WSP writes the gather for this specific
	// structure (dsd_wspadm1_r_wsp_tr_act_1), the "ch_typeset" flag is not written in it as in all other structures
	// that are sent in gathers. So, this structures comes in a gather with a structure:
	//			nhasn + structure
	// instead of 
	//			nhasn + ch_typeset + structure
	// Therefore, when "ds_wsp_admin::m_parse_data" is parsing the gather, it assumes that the ch_typeset byte flag
	// is present, and the structure will start after it.
	// So, with the following trick, what I am doing, is moving back the pointer to the (real)start of the structure.
	// To take a look at how this gather is written, search in "xiipgw08-admin::m_get_wspadm1_wsp_tr_act(...)"
	//ch_typeset = 0;	// We are not checking if ch_typeset because it is not in the structure received.
	(*ainp_position)--;
	// End of Trick

        bol_return = m_read_wsptrace_curconf0( adsp_rec, ainp_position, adsp_context );

		if ( bol_return == false ) {
			return false;
		}

    return bol_return;
} // end of ds_wsp_admin::m_read_wsptrace_curconf

/**
 * function ds_wsp_admin::m_read_wsptrace_curconf0
 *
 * @param[in]       dsd_wspadm_all*  ads_rec
 * @param[in/out]   int*             ain_position
 *
 * @return          bool             true = success
*/
bool ds_wsp_admin::m_read_wsptrace_curconf0(const dsd_wspadm_all* adsp_rec, int* ainp_position, dsd_read_wsptrace_info_context* adsp_context )
{

    // initialize some variables:
    bool   bol_ret                     = false;     // return for several functions value
    struct dsd_wsptrace_info* adsl_temp = NULL;

    // get listen pointer:
    adsl_temp = m_get_next_wsptrace_ptr(adsp_context);
    if ( adsl_temp == NULL ) {
        return false;
    }

    // save asked wsp:
    adsl_temp->dsc_wsp = adsp_rec->dsc_wsp;

    // copy struct dsd_wspadm1_r_wsp_tr_act_1
    bol_ret = m_copy_data( adsp_rec->adsc_gather, ainp_position, 
                          sizeof(dsd_wspadm1_r_wsp_tr_act_1), 
                          ((char*)(&(adsl_temp->dsc_wsptrace_conf))) );
    if ( bol_ret == false ) {
        return false;
    }
    return true;
} // end of ds_wsp_admin::m_read_wsptrace_curconf0

/**
 * function ds_wsp_admin::m_read_perf_type0
 *
 * @param[in]       dsd_wspadm_all*  ads_rec
 * @param[in/out]   int*             ain_position
 *
 * @return          bool             true = success
*/
bool ds_wsp_admin::m_read_perf_type0( const dsd_wspadm_all* ads_rec, int* ain_position, dsd_read_perf_context* adsp_context )
{
    // initialize some variables:
    bool bo_ret = false;     // return for several functions value

	 dsd_perfdata* ads_perfdata = adsp_context->adsc_perfdata;
    // saved asked wsp:
    ads_perfdata->dsc_wsp = ads_rec->dsc_wsp;

    // copy struct dsd_wspadm1_listen_main
    bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position, 
                          sizeof(dsd_wspadm1_perfdata_appl), 
                          ((char*)(&(ads_perfdata->ds_performance))) );
    if ( bo_ret == false ) {
        return false;
    }

    return true;
} // end of ds_wsp_admin::m_read_perf_type0


/**
 *
 * function ds_wsp_admin::m_read_log
 *
 * @param[in]       dsd_gather_i_1*  ads_gather
 * @param[in]       char             ch_typeset
 * @param[in/out]   int*             ain_position
 *
 * @return          bool             true = success
 *
*/
bool ds_wsp_admin::m_read_log( const dsd_wspadm_all* ads_rec,
                               char ch_typeset, int* ain_position, dsd_read_log_info_context* adsp_context )
{
    // initialize some variables:
    bool bo_return = false;

    if ( ch_typeset == 0 ) {
        bo_return = m_read_log_type0( ads_rec, ain_position, adsp_context );
    } else {
        ads_wsp_helper->m_logf( ied_sdh_log_error,
                                "HIWSE706E: Unknown structure type %c selected - ignored",
                                ch_typeset );
    }

    return bo_return;
} // end of ds_wsp_admin::m_read_log


/**
 * function ds_wsp_admin::m_read_log_type0
 *
 * @param[in]       dsd_wspadm_all*  ads_rec
 * @param[in/out]   int*             ain_position
 *
 * @return          bool             true = success
*/
bool ds_wsp_admin::m_read_log_type0( const dsd_wspadm_all* ads_rec, int* ain_position, dsd_read_log_info_context* adsp_context )
{
    // initialize some variables:
    bool   bo_ret                 = false;     // return for several functions value
    struct dsd_log_info* ads_temp = NULL;

    // get listen pointer:
    ads_temp = m_get_next_log_ptr(adsp_context);
    if ( ads_temp == NULL ) {
        return false;
    }

    // save asked wsp:
    ads_temp->dsc_wsp = ads_rec->dsc_wsp;

    // copy struct dsd_wspadm1_session
    bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position, 
                          sizeof(dsd_wspadm1_log), 
                          ((char*)(&(ads_temp->ds_main))) );
    if ( bo_ret == false ) {
        return false;
    }

    // copy next data: following string message:
    if ( ads_temp->ds_main.imc_len_msg > 0 ) {
        char* achl_message = ads_wsp_helper->m_cb_get_memory( 
                    ads_temp->ds_main.imc_len_msg + 1, true );
        if ( achl_message == NULL ) {
            return false;
        }
        bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position,
                              ads_temp->ds_main.imc_len_msg,
                              achl_message );
        if ( bo_ret == false ) {
            return false;
        }
        
        ads_temp->ach_message = achl_message;
    }
    return true;
} // end of ds_wsp_admin::m_read_log_type0


/**
 * function ds_wsp_admin::m_read_session
 *
 * @param[in]       dsd_wspadm_all*  ads_rec
 * @param[in]       char             ch_typeset
 * @param[in/out]   int*             ain_position
 *
 * @return          bool             true = success
*/
bool ds_wsp_admin::m_read_session( const dsd_wspadm_all* ads_rec,
                                   char ch_typeset, int* ain_position,
											  dsd_read_session_context* adsp_context )
{
    // initialize some variables:
    bool bo_return = false;

    if ( ch_typeset == 0 ) {
        bo_return = m_read_session_type0( ads_rec, ain_position, adsp_context );
    } else {
        ads_wsp_helper->m_logf( ied_sdh_log_error,
                                "HIWSE705E: Unknown structure type %c selected - ignored",
                                ch_typeset );
    }

    return bo_return;
} // end of ds_wsp_admin::m_read_session


bool ds_wsp_admin::m_copy_field(const dsd_wspadm_all* ads_rec, int* ain_position, int iml_len_field, char* (&rdsp_out)) {
	// copy next data: following string user group
    if ( iml_len_field > 0 ) {
        rdsp_out = ads_wsp_helper->m_cb_get_memory( 
                    iml_len_field + 1, true );
        if ( rdsp_out == NULL ) {
            return false;
        }
        bool bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position,
                              iml_len_field,
                              rdsp_out );
        if ( bo_ret == false ) {
            return false;
        }
    }
	 return true;
}

/**
 * function ds_wsp_admin::m_read_session_type0
 *
 * @param[in]       dsd_wspadm_all*  ads_rec
 * @param[in/out]   int*             ain_position
 *
 * @return          bool             true = success
*/
bool ds_wsp_admin::m_read_session_type0( const dsd_wspadm_all* ads_rec, int* ain_position, dsd_read_session_context* adsp_context )
{
    // initialize some variables:
    bool   bo_ret                     = false;     // return for several functions value
    struct dsd_session_info* ads_temp = NULL;

    // get listen pointer:
    ads_temp = m_get_next_session_ptr(adsp_context);
    if ( ads_temp == NULL ) {
        return false;
    }

    // save asked wsp:
    ads_temp->dsc_wsp = ads_rec->dsc_wsp;

    // copy struct dsd_wspadm1_session
    bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position, 
                          sizeof(dsd_wspadm1_session), 
                          ((char*)(&(ads_temp->ds_sess_info))) );
    if ( bo_ret == false ) {
        return false;
    }

    // copy next data: following string gate name:
	 if(!m_copy_field(ads_rec, ain_position, ads_temp->ds_sess_info.imc_len_gate_name, ads_temp->ach_gate_name))
		 return false;

    // copy next data: following string server entry
	 if(!m_copy_field(ads_rec, ain_position, ads_temp->ds_sess_info.imc_len_serv_ent, ads_temp->ach_serv_entry))
		 return false;

    // copy next data: following string protocol
	 if(!m_copy_field(ads_rec, ain_position, ads_temp->ds_sess_info.imc_len_protocol, ads_temp->ach_protocol))
		 return false;

    // copy next data: following string server INETA and port
	 if(!m_copy_field(ads_rec, ain_position, ads_temp->ds_sess_info.imc_len_ineta_port, ads_temp->ach_server_ineta))
		 return false;

	 // copy next data: following string DN from certificate
	 if(!m_copy_field(ads_rec, ain_position, ads_temp->ds_sess_info.imc_len_name_cert, ads_temp->ach_cert_name))
		 return false;

    // copy next data: following string user name
	 if(!m_copy_field(ads_rec, ain_position, ads_temp->ds_sess_info.imc_len_userid, ads_temp->ach_user))
		 return false;

    // copy next data: following string user group
	 if(!m_copy_field(ads_rec, ain_position, ads_temp->ds_sess_info.imc_len_user_group, ads_temp->ach_group))
		 return false;

    // copy next data: following string user field
	 if(ads_temp->ds_sess_info.imc_len_userfld != 0) {
		 if(ads_temp->ds_sess_info.imc_len_userfld != sizeof(dsd_aux_ident_session_info))
			 return false;
		 if(!m_copy_data(ads_rec->adsc_gather, ain_position, ads_temp->ds_sess_info.imc_len_userfld, (char*)&ads_temp->dsc_session_no))
			 return false;
	 }
	 return true;
} // end of ds_wsp_admin::m_read_session_type0


/**
 * function ds_wsp_admin::m_read_cancel_session
 *
 * @param[in]       dsd_wspadm_all*  ads_rec
 * @param[in]       char             ch_typeset
 * @param[in/out]   int*             ain_position
 *
 * @return          bool             true = success
*/
bool ds_wsp_admin::m_read_cancel_session( const dsd_wspadm_all* ads_rec,
                                          char ch_typeset, int* ain_position,
														dsd_read_cancel_session_context* adsp_context )
{
    // initialize some variables:
    bool bo_return = false;

    if ( ch_typeset == 0 ) {
        bo_return = m_read_cancel_session_type0( ads_rec, ain_position, adsp_context );
    } else {
        ads_wsp_helper->m_logf( ied_sdh_log_error,
                                "HIWSE701E: Unknown structure type %c selected - ignored",
                                ch_typeset );
    }

    return bo_return;
} // end of ds_wsp_admin::m_read_cancel_session


/**
 * function ds_wsp_admin::m_read_cancel_session_type0
 *
 * @param[in]       dsd_wspadm_all*  ads_rec
 * @param[in/out]   int*             ain_position
 *
 * @return          bool             true = success
*/
bool ds_wsp_admin::m_read_cancel_session_type0( const dsd_wspadm_all* ads_rec, int* ain_position,
															  dsd_read_cancel_session_context* adsp_context )
{
    // copy struct dsd_wspadm1_session
    return m_copy_data( ads_rec->adsc_gather, ain_position, 
                        sizeof(dsd_wspadm1_r_can_sess_1), 
                        ((char*)(&(adsp_context->ds_resp_disconnect))) );
} // end of ds_wsp_admin::m_read_cancel_session_type0


/**
 * function ds_wsp_admin::m_read_listen
 *
 * @param[in]       dsd_wspadm_all*  ads_rec
 * @param[in]       char             ch_typeset
 * @param[in/out]   int*             ain_position
 *
 * @return          bool             true = success
*/
bool ds_wsp_admin::m_read_listen( const dsd_wspadm_all* ads_rec,
                                  char ch_typeset, int* ain_position,
											 dsd_read_listen_context* adsp_context )
{
    // initialize some variables:
    bool bo_return = false;

    if ( ch_typeset == 0 ) {
        bo_return = m_read_listen_type0( ads_rec, ain_position, adsp_context );
    } else if ( ch_typeset == 1 ) {
        bo_return = m_read_listen_type1( ads_rec, ain_position, adsp_context );
    } else {
        ads_wsp_helper->m_logf( ied_sdh_log_error,
                                "HIWSE702E: Unknown structure type %c selected - ignored",
                                ch_typeset );
    }

    return bo_return;
} // end of ds_wsp_admin::m_read_listen


/**
 * function ds_wsp_admin::m_read_listen_type0
 *
 * @param[in]       dsd_wspadm_all*  ads_rec
 * @param[in/out]   int*             ain_position
 *
 * @return          bool             true = success
*/
bool ds_wsp_admin::m_read_listen_type0( const dsd_wspadm_all* ads_rec, int* ain_position, dsd_read_listen_context* adsp_context )
{
    // initialize some variables:
    bool   bo_ret               = false;     // return for several functions value
    struct dsd_listen* ads_temp = NULL;

    // get listen pointer:
    ads_temp = m_get_next_listen_ptr(adsp_context);
    if ( ads_temp == NULL ) {
        return false;
    }

    // saved asked wsp:
    ads_temp->dsc_wsp = ads_rec->dsc_wsp;

    // copy struct dsd_wspadm1_listen_main
    bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position, 
                          sizeof(dsd_wspadm1_listen_main), 
                          ((char*)(&(ads_temp->ds_main))) );
    if ( bo_ret == false ) {
        return false;
    }

    // copy next data: following string gate name:
    if ( ads_temp->ds_main.imc_len_gate_name > 0 ) {
        ads_temp->ach_gate_name = ads_wsp_helper->m_cb_get_memory( 
                    ads_temp->ds_main.imc_len_gate_name + 1, true );
        if ( ads_temp->ach_gate_name == NULL ) {
            return false;
        }
        bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position,
                              ads_temp->ds_main.imc_len_gate_name,
                              ads_temp->ach_gate_name );
        if ( bo_ret == false ) {
            return false;
        }
    }

    return true;
} // end of ds_wsp_admin::m_read_listen_type0


/**
 * function ds_wsp_admin::m_read_listen_type1
 *
 * @param[in]       dsd_wspadm_all*  ads_rec
 * @param[in/out]   int*             ain_position
 *
 * @return          bool             true = success
*/
bool ds_wsp_admin::m_read_listen_type1( const dsd_wspadm_all* ads_rec, int* ain_position, dsd_read_listen_context* adsp_context )
{
    // initialize some variables:
    bool bo_ret               = false;    // return for several functions value
    dsd_each_listen* ads_each = NULL;

    ads_each = m_get_next_listen_each_ptr(adsp_context);
    if ( ads_each == NULL ) {
        return false;
    }

    // copy struct dsd_wspadm1_listen_ineta
    bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position, 
                          sizeof(dsd_wspadm1_listen_ineta), 
                          ((char*)(&(ads_each->ds_ineta))) );
    if ( bo_ret == false ) {
        return false;
    }

    // copy next data: following string gate name:
    if ( ads_each->ds_ineta.imc_len_ineta > 0 ) {
        ads_each->ach_ineta = ads_wsp_helper->m_cb_get_memory( 
                    ads_each->ds_ineta.imc_len_ineta + 1, true );
        if ( ads_each->ach_ineta == NULL ) {
            return false;
        }
        bo_ret = m_copy_data( ads_rec->adsc_gather, ain_position,
                              ads_each->ds_ineta.imc_len_ineta,
                              ads_each->ach_ineta );
        if ( bo_ret == false ) {
            return false;
        }
    }

    return true;
} // end of ds_wsp_admin::m_read_listen_type1


/**
 * function ds_wsp_admin::m_copy_data
 *
 * @param[in]       dsd_gather_i_1*  ads_gather
 * @param[in/out]   int*             ain_position
 * @param[in]       int              in_data_len
 * @param[out]      void**           aach_out
 *
 * @return          bool             true = success
*/
bool ds_wsp_admin::m_copy_data( struct dsd_gather_i_1* ads_gather,
                                int* ain_position, int in_data_len,
                                char* ach_out )
{
    // initialize some variables:
    char* ach_data  = NULL;

    for ( int in_count = 0; in_count < in_data_len; in_count++ ) {
        // get next data:
        ach_data = ads_wsp_helper->m_get_end_ptr( ads_gather, *ain_position );
        if ( ach_data == NULL ) {
            return false;
        }
        // copy data:
        ach_out[in_count] = ach_data[0];
        (*ain_position)++;
    }
    return true;
} // end of ds_wsp_admin::m_copy_data


/**
 * function ds_wsp_admin::m_get_nhasnlen
 *
 * @param[in]       dsd_gather_i_1*  ads_gather
 * @param[in/out]   int*             ain_offset
 *
 * @return length                   negativ error code
*/
int ds_wsp_admin::m_get_nhasnlen( struct dsd_gather_i_1 * ads_gather, int* ain_offset )
{
    // initialize some variables:
    int     in_return = 0;
    char*   ach_ptr   = ads_wsp_helper->m_get_end_ptr( ads_gather, *ain_offset );
    if ( ach_ptr == NULL ) {
        return -1;
    }

    for ( ; ; ) {
        in_return |= (*ach_ptr &0x7F );
        (*ain_offset)++;
        if ( (*ach_ptr & 0x80) == 0 ) {
            break;
        }
        ach_ptr = ads_wsp_helper->m_get_end_ptr( ads_gather, *ain_offset );
        in_return <<= 7;
    }

    return in_return;
} // end of ds_wsp_admin::m_get_nhasnlen


/**
 * function ds_wsp_admin::m_free_cluster
*/
void ds_wsp_admin::m_free_cluster(dsd_cluster* ads_cluster)
{    
    if ( ads_cluster != NULL ) {
        // free string memory:
        if ( ads_cluster->ach_conf_name != NULL ) {
            ads_wsp_helper->m_cb_free_memory( ads_cluster->ach_conf_name, 
                (int)strlen( ads_cluster->ach_conf_name ) + 1 );
        }
        if ( ads_cluster->ach_wsp_query != NULL ) {
            ads_wsp_helper->m_cb_free_memory( ads_cluster->ach_wsp_query, 
                (int)strlen( ads_cluster->ach_wsp_query ) + 1 );
        }
        if ( ads_cluster->ach_serv_name != NULL ) {
            ads_wsp_helper->m_cb_free_memory( ads_cluster->ach_serv_name, 
                (int)strlen( ads_cluster->ach_serv_name ) + 1 );
        }

        // free remote cluster chain:
        m_free_cluster( ads_cluster->ads_next );
        
        // free structure itself:
        ads_wsp_helper->m_cb_free_memory( (char*)ads_cluster, 
            (int)sizeof(dsd_cluster) );
    }
} // end of ds_wsp_admin::m_free_cluster


/**
 * function ds_wsp_admin::m_free_cluster
*/
void ds_wsp_admin::m_free_cluster(dsd_cluster_remote_01* ads_remote)
{
    if ( ads_remote != NULL ) {
        // free string memory:
        if ( ads_remote->ds_remote.imc_len_config_name > 0 ) {
            ads_wsp_helper->m_cb_free_memory( ads_remote->ach_conf_name,
                ads_remote->ds_remote.imc_len_config_name + 1 );
        }
        if ( ads_remote->ds_remote.imc_len_server_name > 0 ) {
            ads_wsp_helper->m_cb_free_memory( ads_remote->ach_serv_name,
                ads_remote->ds_remote.imc_len_server_name + 1 );
        }
        if ( ads_remote->ds_remote.imc_len_query_main > 0 ) {
            ads_wsp_helper->m_cb_free_memory( ads_remote->ach_wsp_query,
                ads_remote->ds_remote.imc_len_query_main + 1 );
        }
        // free remote cluster chain:
        m_free_cluster( ads_remote->ads_next );

        // free structure itself:
        ads_wsp_helper->m_cb_free_memory( (char*)ads_remote, 
            (int)sizeof(dsd_cluster_remote_01) );
    }
} // end of ds_wsp_admin::m_free_cluster


/**
 * function ds_wsp_admin::m_free_listen
*/
void ds_wsp_admin::m_free_listen( dsd_listen* ads_listen_in )
{
    if ( ads_listen_in != NULL ) {
        // free string memory:
        if ( ads_listen_in->ach_gate_name != NULL ) {
            ads_wsp_helper->m_cb_free_memory( ads_listen_in->ach_gate_name, 
                (int)strlen( ads_listen_in->ach_gate_name ) + 1 );
        }
        // free listen chain:
        m_free_listen( ads_listen_in->ads_next );
        m_free_listen( ads_listen_in->ads_each );
        // free structure itself:
        ads_wsp_helper->m_cb_free_memory( (char*)ads_listen_in, 
            (int)sizeof(dsd_listen) );
    }
} // end of ds_wsp_admin::m_free_listen


/**
 * function ds_wsp_admin::m_free_listen
*/
void ds_wsp_admin::m_free_listen( dsd_each_listen* ads_listen_in )
{
    if ( ads_listen_in != NULL ) {
        // free string memory:
        if ( ads_listen_in->ach_ineta != NULL ) {
            ads_wsp_helper->m_cb_free_memory( ads_listen_in->ach_ineta, 
                (int)strlen( ads_listen_in->ach_ineta ) + 1 );
        }
        if ( ads_listen_in->ads_next != NULL ) {
            m_free_listen( ads_listen_in->ads_next );
        }
        // free structure itself:
        ads_wsp_helper->m_cb_free_memory( (char*)ads_listen_in, 
            (int)sizeof(dsd_each_listen) );
    }
} // end of ds_wsp_admin::m_free_listen


/**
 * function ds_wsp_admin::m_free_perfdata
*/
void ds_wsp_admin::m_free_perfdata(dsd_perfdata* ads_perfdata) 
{
    if ( ads_perfdata != NULL ) {
        // free structure itself:
        ads_wsp_helper->m_cb_free_memory( (char*)ads_perfdata, 
            (int)sizeof(dsd_perfdata) );
    }
} // end of ds_wsp_admin::m_free_perfdata
/**
 * function ds_wsp_admin::m_free_wsptrace
*/
void ds_wsp_admin::m_free_wsptrace( dsd_wsptrace_info* adsp_wsptrace_info_in )
{
    if ( adsp_wsptrace_info_in != NULL ) {

        // free session chain:
        m_free_wsptrace( adsp_wsptrace_info_in->ads_next );

        // free structure itself:
        ads_wsp_helper->m_cb_free_memory( (char*)adsp_wsptrace_info_in, 
            (int)sizeof(dsd_wsptrace_info) );
    }
} // end of ds_wsp_admin::m_free_wsptrace

/**
 * function ds_wsp_admin::m_free_session
*/
void ds_wsp_admin::m_free_session( dsd_session_info* ads_session_info_in )
{
    if ( ads_session_info_in != NULL ) {
        // free string memory:
        if ( ads_session_info_in->ach_gate_name != NULL ) {
            ads_wsp_helper->m_cb_free_memory( ads_session_info_in->ach_gate_name, 
                (int)strlen( ads_session_info_in->ach_gate_name ) + 1 );
        }
        if ( ads_session_info_in->ach_serv_entry != NULL ) {
            ads_wsp_helper->m_cb_free_memory( ads_session_info_in->ach_serv_entry, 
                (int)strlen( ads_session_info_in->ach_serv_entry ) + 1 );
        }
        if ( ads_session_info_in->ach_protocol != NULL ) {
            ads_wsp_helper->m_cb_free_memory( ads_session_info_in->ach_protocol, 
                (int)strlen( ads_session_info_in->ach_protocol ) + 1 );
        }
        if ( ads_session_info_in->ach_server_ineta != NULL ) {
            ads_wsp_helper->m_cb_free_memory( ads_session_info_in->ach_server_ineta, 
                (int)strlen( ads_session_info_in->ach_server_ineta ) + 1 );
        }
        if ( ads_session_info_in->ach_cert_name != NULL ) {
            ads_wsp_helper->m_cb_free_memory( ads_session_info_in->ach_cert_name, 
                (int)strlen( ads_session_info_in->ach_cert_name ) + 1 );
        }
        if ( ads_session_info_in->ach_user != NULL ) {
            ads_wsp_helper->m_cb_free_memory( ads_session_info_in->ach_user, 
                (int)strlen( ads_session_info_in->ach_user ) + 1 );
        }
        if ( ads_session_info_in->ach_group != NULL ) {
            ads_wsp_helper->m_cb_free_memory( ads_session_info_in->ach_group, 
                (int)strlen( ads_session_info_in->ach_group ) + 1 );
        }
        // free session chain:
        m_free_session( ads_session_info_in->ads_next );

        
        // free structure itself:
        ads_wsp_helper->m_cb_free_memory( (char*)ads_session_info_in, 
            (int)sizeof(dsd_session_info) );
    }
} // end of ds_wsp_admin::m_free_session


/**
 * function ds_wsp_admin::m_free_log
*/
void ds_wsp_admin::m_free_log( dsd_log_info* ads_log_in, bool bo_keep_msg )
{
    if ( ads_log_in != NULL ) {
        // free string memory:
        if (    bo_keep_msg             == false
             && ads_log_in->ach_message != NULL ) {
            ads_wsp_helper->m_cb_free_memory( (void*)ads_log_in->ach_message, 
                ads_log_in->ds_main.imc_len_msg + 1 );
        }

        // free log chain:
        m_free_log( ads_log_in->ads_next, bo_keep_msg );

        // free structure itself:
        ads_wsp_helper->m_cb_free_memory( (char*)ads_log_in, 
            (int)sizeof(dsd_log_info) );
    }
} // end of ds_wsp_admin::m_free_log


/**
 * private function ds_wsp_admin::m_get_query_value
 *
 * @param[in]   const char*         ach_name            name of query to search
 * @param[in]   char**              aach_value          pointer to value
 * @param[in]   int*                ain_len_value       length of value
 * @param[in]   int                 in_start_index      start index of search
 * @return      int                                     index of found value
*/
int ds_wsp_admin::m_get_query_value( const dsd_const_string& rdsp_name,
                                     const char** aach_value, int* ain_len_value,
                                     int in_start_index )
{
    // initialize some variables:
    struct dsd_query* ads_temp = adsc_query;
    int               in_index = 0;

    *aach_value    = "";
    *ain_len_value = 0;

    while ( ads_temp != NULL ) {
        if (    in_start_index <= in_index
             && ads_temp->ds_name.m_equals( rdsp_name ) == true ) {
            *aach_value    = ads_temp->ds_value.m_get_ptr();
            *ain_len_value = ads_temp->ds_value.m_get_len();
            return in_index;
        }
        ads_temp = ads_temp->ads_next;
        in_index++;
    }
    return -1;
} // end of ds_wsp_admin::m_get_query_value


/**
 * function ds_wsp_admin::m_str_to_ll
 *
 * @param[in]   const char* ach_ptr
 * @param[in]   char**      aach_endptr
 * @param[in]   int         in_base
 * @return      long long
*/
long long ds_wsp_admin::m_str_to_ll( const char* ach_ptr, char** aach_endptr, int in_base )
{
    // initialize some variables:
    long long ill_result = 0;
    long long ill_temp;
    bool      bo_negative;
    int       in_value;

    // check incoming data:
    if (    in_base != 0 
         && (in_base < 2 || in_base > 36) ) {
        errno = EINVAL;
        return 0;
    }

    // pass whitespaces:
    while (    *ach_ptr == ' '
            || *ach_ptr == '\t' ) {
        ach_ptr++;
    }

    // check if positiv or negativ:
    if ( *ach_ptr == '-' ) {
        bo_negative = true;
        ach_ptr++;
    } else if ( *ach_ptr == '+' ) {
        bo_negative = false;
        ach_ptr++;
    } else {
        bo_negative = false;
    }

    /*
        get base:
            -> If base is 0, determine the real base based on the beginning on
                the number; octal numbers begin with "0", hexadecimal with "0x",
                and the others are considered octal.
    */
    if ( *ach_ptr == '0' ) {
        if (    ( in_base == 0 || in_base == 16 )
             && ( *(ach_ptr + 1) == 'x' || *(ach_ptr + 1) == 'X' ) ) {
            in_base = 16;
            ach_ptr += 2;
        } else if ( in_base == 0 ) {
            in_base = 8;
        }
    } else if ( in_base == 0 ) {
        in_base = 10;
    }

    if ( bo_negative == false ) {
        // read positive number:
        for ( ; (in_value = m_get_cvalue( *ach_ptr, in_base )) != -1; ach_ptr++ ) {
            ill_temp = in_base * ill_result + in_value;
            // check for overflow:
            if ( ill_temp < ill_result ) {
                errno = ERANGE;
                break;  // -> quit
            }
            ill_result = ill_temp;
        }
    } else {
        // read negative number:
        for ( ; (in_value = m_get_cvalue( *ach_ptr, in_base )) != -1; ach_ptr++ ) {
            ill_temp = in_base * ill_result - in_value;
            // check for overflow:
            if ( ill_temp > ill_result ) {
                errno = ERANGE;
                break;  // -> quit
            }
            ill_result = ill_temp;
        }
    }

    if ( aach_endptr != NULL ) {
        *aach_endptr = (char*)ach_ptr;
    }
    return ill_result;
} // end of ds_wsp_admin::m_str_to_ll


/**
 * function ds_wsp_admin::m_get_cvalue
 * get char value
 *
 * @param[in]   char    ch_in
 * @param[in]   int     in_base
*/
int ds_wsp_admin::m_get_cvalue( char ch_in, int in_base )
{
    // initialize some variables:
    int in_value;

    if ( ch_in < '0' ) {
        return -1;
    }

    if ( '0' <= ch_in && ch_in <= '9' ) {
        in_value = (int)(ch_in - '0');
    } else if ( 'a' <= ch_in && ch_in <= 'z' ) {
        in_value = (int)(ch_in - 'a' + 10);
    } else if ( 'A' <= ch_in && ch_in <= 'Z' ) {
        in_value = (int)(ch_in - 'A' + 10);
    } else {
        return -1;
    }

    if ( in_value >= in_base ) {
        in_value = -1;
    }
    return in_value;
} // end of ds_wsp_admin::m_get_cvalue
