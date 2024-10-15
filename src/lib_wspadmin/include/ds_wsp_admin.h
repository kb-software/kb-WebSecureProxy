/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_wsp_admin                                                          |*/
/*|                                                                         |*/
/*| DESCRIPTION:                                                            |*/
/*| ============                                                            |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|   Michael Jakobs                                                        |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| =====                                                                   |*/
/*|  September 2008                                                         |*/
/*|                                                                         |*/
/*| COPYRIGHT:                                                              |*/
/*| ==========                                                              |*/
/*|  HOB GmbH & Co. KG, Germany                                             |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/

#ifndef DS_WSP_ADMIN_H
#define DS_WSP_ADMIN_H
/*+-------------------------------------------------------------------------+*/
/*| forward declarations:                                                   |*/
/*+-------------------------------------------------------------------------+*/
class ds_hstring;
template <class T> class ds_hvector;
class ds_wsp_helper;
struct dsd_query;

/*+-------------------------------------------------------------------------+*/
/*| include global headers                                                  |*/
/*+-------------------------------------------------------------------------+*/
#ifndef _HOB_WSP_ADMIN1_H
    #define _HOB_WSP_ADMIN1_H
    #include <hob-wsp-admin-1.h>
#endif
#include <ds_usercma.h>
#include <stddef.h>

/*+-------------------------------------------------------------------------+*/
/*| query paramters:                                                        |*/
/*+-------------------------------------------------------------------------+*/
static const dsd_const_string achr_wspadmin_queries[] = {
    "handle",
    "start",
    "rec",
    "user",
    "group",
    "filled",
    "epoch",
    "search",
    "session",
    "wspt-handle",      // WSPTrace: to set the destination WSP
	"wspt-acti",		// WSPTrace: to modify state of WSP Trace [activated/deactivated] - NOT YET!
	"wspt-outd",		// WSPTrace: to change output destination (bin file, ascii file, console...).
	"wspt-outf",		// WSPTrace: to modify output filename in case output is to a file.
	"wspt-allsess",		// WSPTrace: to activate/deactivate tracing all INETAs or specific INETAs.
	"wspt-sess",		// WSPTrace: to change session tracing settings.
	"wspt-core",		// WSPTrace: to change core tracing settings.
	"wspt-ineta",		// WSPTrace: to specify single inetas to be traced instead of all users/connections.
    "wspt-erinetas",    // WSPTrace: to delete all INETAs being traced (if any). 
    "dump-cma",         // WSPTrace: to dump content of the CMA to the trace file.
	// boolean queries:
    "wildcard",
    "regexp",
    "backward",
    dsd_const_string(NULL, 0)
};

enum ied_wspadmin_queries {
    ied_wspadmin_query_handle,
    ied_wspadmin_query_start,
    ied_wspadmin_query_rec,
    ied_wspadmin_query_user,
    ied_wspadmin_query_group,
    ied_wspadmin_query_filled,
    ied_wspadmin_query_epoch,
    ied_wspadmin_query_search,
    ied_wspadmin_query_session,
    ied_wsptrace_query_wsptrace_handle,			// WSPTrace: to set the destination WSP
	ied_wsptrace_query_wsptrace_acti,			// WSPTrace: to modify state of WSP Trace [activated/deactivated] - NOT YET!
	ied_wsptrace_query_wsptrace_outd,			// WSPTrace: to modify destination output of WSP Trace.
	ied_wsptrace_query_wsptrace_outf,			// WSPTrace: to modify output filename in case output is to a file.
	ied_wsptrace_query_wsptrace_allsess,		// WSPTrace: to switch between tracing all sessions or single INETAS.
	ied_wsptrace_query_wsptrace_sess,			// WSPTrace: to modify conf values for WSP Trace session settings.
	ied_wsptrace_query_wsptrace_core,			// WSPTrace: to modify conf values for WSP Trace core settings.
	ied_wsptrace_query_single_ineta,			// WSPTrace: to add INETAs to the WSP Trace session list to be traced.
    ied_wspadmin_query_erase_inetas,            // WSPTrace: to delete all INETAs being traced (if any).
    ied_wspadmin_query_dump_cma,                // WSPTrace: to dump content of the CMA to the trace file.
    ied_wspadmin_query_wildcard,
    ied_wspadmin_query_regexp,
    ied_wspadmin_query_backward

};

/*+-------------------------------------------------------------------------+*/
/*| error codes:                                                            |*/
/*+-------------------------------------------------------------------------+*/
#ifndef _DEF_ADMIN_RCODE
#define _DEF_ADMIN_RCODE
 enum ied_admin_rcode {
    ied_wspadmin_unset,                 // everything ok, no error
    ied_wspadmin_params,                // invalid parameters
    ied_wspadmin_end_of_file,           // end of file detected, means: not more data available
    ied_wspadmin_inv_request,           // invalid request
    ied_wspadmin_rec_unavailable,       // resource is unavailable
    ied_wspadmin_timeout,               // timeout while processing data
    ied_wspadmin_inv_cluster,           // invalid cluster selected
    ied_wspadmin_misc,                  // miscellaneous
    ied_wspadmin_unknown                // unknown error
};
#endif // _DEF_ADMIN_RCODE

/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/
#define MAX_ENTRIES_PER_PAGE 100        // maximal number of entries per page

/*+-------------------------------------------------------------------------+*/
/*| data structures definition:                                             |*/
/*+-------------------------------------------------------------------------+*/
struct dsd_wsp_info {
    HL_LONGLONG     ilc_handle;         // asked wsp handle
    char*           achc_srv_name;      // asked wsp server name
    int             inc_len_srv_name;   // length of asked wsp server name
    char*           achc_wsp_name;      // asked wsp cluster name
    int             inc_len_wsp_name;   // length of asked wsp cluster name
	char*			achc_srv_location;		// asked wsp location
	int				inc_len_srv_location;	// length of asked wsp location
	char*			achc_srv_group;			// asked wsp group
	int				inc_len_srv_group;		// length of asked wsp group
};

struct dsd_cluster_remote_01 {
    struct dsd_wspadm1_cluster_remote   ds_remote;
    char*                               ach_serv_name;
    char*                               ach_wsp_query;
    char*                               ach_conf_name;
	char*								ach_serv_location;		
	char*								ach_serv_group;	
    struct dsd_cluster_remote_01*       ads_next;       
};

struct dsd_cluster {
    struct dsd_wspadm1_cluster_main     ds_main;
    char*                               ach_serv_name;
    char*                               ach_wsp_query;
    char*                               ach_conf_name;
	char*								ach_serv_location;		
	char*								ach_serv_group;	
    struct dsd_cluster_remote_01*       ads_next;
};

struct dsd_each_listen {
    struct dsd_wspadm1_listen_ineta     ds_ineta;
    char*                               ach_ineta;
    struct dsd_each_listen*             ads_next;
};

struct dsd_listen {
    struct dsd_wsp_info                 dsc_wsp;        // asked wsp info
    struct dsd_wspadm1_listen_main      ds_main;
    char*                               ach_gate_name;
    struct dsd_listen*                  ads_next;
    struct dsd_each_listen*             ads_each;
};

struct dsd_perfdata {
    struct dsd_wsp_info                 dsc_wsp;        // asked wsp info
    struct dsd_wspadm1_perfdata_appl    ds_performance;
};

struct dsd_session_info {
    struct dsd_wsp_info                 dsc_wsp;        // asked wsp info
    struct dsd_wspadm1_session          ds_sess_info;
    char*                               ach_gate_name;
    char*                               ach_serv_entry;
    char*                               ach_protocol;
    char*                               ach_server_ineta;
    char*                               ach_cert_name;
    char*                               ach_user;
    char*                               ach_group;
	 struct dsd_aux_ident_session_info	 dsc_session_no;
    struct dsd_session_info*            ads_next;
};

struct dsd_log_info {
    struct dsd_wsp_info                 dsc_wsp;        // asked wsp info
    struct dsd_wspadm1_log              ds_main;
    const char*                         ach_message;
    struct dsd_log_info*                ads_next;
    struct dsd_log_info*                ads_prev;
};

struct dsd_wspadm_all {
    dsd_wsp_info    dsc_wsp;            // asked wsp info
    dsd_gather_i_1* adsc_gather;        // received response
};

struct dsd_wsptrace_info{
	struct dsd_wsp_info					dsc_wsp;			// WSP general info
	struct dsd_wspadm1_r_wsp_tr_act_1	dsc_wsptrace_conf;	// WSP Trace settings as received from WSP
	struct dsd_wsptrace_info*			ads_next;			
};

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
class ds_wsp_admin
{
public:
    // constructor:
    ds_wsp_admin( void );
    ds_wsp_admin( ds_wsp_helper* adsp_wsp_helper );

    // destructor:
    ~ds_wsp_admin(void);

    //functions:
    void m_init ( ds_wsp_helper* adsp_wsp_helper, struct dsd_query* adsp_query );

    dsd_cluster*      m_get_cluster_info ();
    dsd_session_info* m_get_session_info ();
    dsd_listen*       m_get_listen_info  ();
    dsd_perfdata*     m_get_perf_info    ();
    dsd_log_info*     m_get_log_info     ();
    bool              m_disc_session     ();
    bool              m_disc_user        ( const char* ach_usr, int in_len_usr,
                                           const char* ach_grp, int in_len_grp,
														 const struct dsd_cma_session_no* adsp_session );
    dsd_session_info* m_get_user_sessions( const char* ach_usr, int in_len_usr,
                                           const char* ach_grp, int in_len_grp,
														 const struct dsd_cma_session_no* adsp_session );

    ied_admin_rcode   m_get_return_code  ();

	dsd_wsptrace_info*		m_get_wsptrace_info();
	bool					m_wsptrace_modconf();

private:
	 struct dsd_read_cluster_context {
		 struct dsd_hl_slist<dsd_cluster, offsetof(dsd_cluster, ads_next)> dsc_clusters;
		 struct dsd_hl_slist<dsd_cluster_remote_01, offsetof(dsd_cluster_remote_01, ads_next)> dsc_clusters_remote;
	 };
	 struct dsd_read_session_context {
		 struct dsd_hl_slist<dsd_session_info, offsetof(dsd_session_info, ads_next)> dsc_sessions;
	 };
	 struct dsd_read_listen_context {
		 struct dsd_hl_slist<dsd_listen, offsetof(dsd_listen, ads_next)> dsc_listens;
		 struct dsd_hl_slist<dsd_each_listen, offsetof(dsd_each_listen, ads_next)> dsc_each_listens;
	 };
	 struct dsd_read_perf_context {
		 dsd_perfdata* adsc_perfdata;
	 };
	 struct dsd_read_log_info_context {
		 struct dsd_hl_dlist<dsd_log_info, offsetof(dsd_log_info, ads_next), offsetof(dsd_log_info, ads_prev)> dsc_logs;
	 };
	 struct dsd_read_wsptrace_info_context {
		 struct dsd_hl_slist<dsd_wsptrace_info, offsetof(dsd_wsptrace_info, ads_next)> dsc_traces;
	 };
	 struct dsd_read_cancel_session_context {
		 dsd_wspadm1_r_can_sess_1    ds_resp_disconnect;
	 };

    // variables:
    //ds_session*         ads_session;        // session pointer
    ds_wsp_helper*      ads_wsp_helper;     // wsp helper class
    struct dsd_query*   adsc_query;         // http query name value pairs

    // analysed structure pointer:
    dsd_cluster*        adsc_cluster;        // cluster structure pointer
    dsd_listen*         adsc_listen;         // listen structure pointer
    dsd_perfdata*       adsc_perfdata;       // performance data structure pointer
    dsd_session_info*   adsc_session_info;   // session information structure pointer
    dsd_log_info*       adsc_log;            // log information structure pointer
	 dsd_wsptrace_info*  adsc_wsptrace_info;	// WSP Trace structure pointer

    ied_admin_rcode     ien_ret_code;       // error code form admin interface
    
    // wsp admin modes:
    enum ied_admin_mode {
        ien_undefined,
        ien_cluster,
        ien_session,
        ien_listen,
        ien_perfdata,
        ien_log,
        ien_cancel_session,
		ien_wsptrace_query,
		ien_wsptrace_info
    };
    // request variables:
    ied_admin_mode              work_mode;              // our working mode
    HL_LONGLONG                 il_wsp_handle;          // requested wsp
    bool                        boc_getall_wsp;         // get information from all wsp in cluster
    dsd_wspadm1_q_session       ds_query_session;       // session query structure
    const char*                 ach_user;               // user for query session structure
    const char*                 ach_group;              // group for query session structure
    const char*                 ach_userfield;          // user field query session structure
    dsd_wspadm1_q_log           ds_query_log;           // log query structure
    const char*                 ach_search;             // search word for query log structure
    dsd_wspadm1_q_can_sess_1    ds_query_disconnect;    // diconnect query structure
	dsd_wspadm1_q_wsp_trace_1	dsc_query_wsptrace;		// WSP Trace query
	int							imc_len_data;			// Lenght of the data to be attached to the query
	const char* 				achc_trineta;			// Data to be attached to the query
    // disconnect function:
    bool m_disconnect( HL_LONGLONG ilp_wsp_handle, int in_session );
	// Modify WSP Trace configuration function:
	bool m_wsptrace_modify( HL_LONGLONG ilp_wsp_handle, dsd_wspadm1_q_wsp_trace_1 dsp_query_wsptr, int imp_datalen, const char* achp_data );
    bool m_process_handle_commands(int imp_hpos_start, int imp_hpos_end);

		// read in functions:
    bool m_get_data    (ds_hvector_btype<dsd_wspadm_all>& rdsp_out);
    bool m_set_data    (ds_hvector_btype<dsd_wspadm_all>& rdsp_out);
    dsd_gather_i_1*                  m_send_request( bool bo_free_buffer );
    bool                             m_read_query  ();
    bool                             m_parse_data_element  ( const dsd_wspadm_all* ads_rec, void* avop_context );
    bool                             m_parse_data_vector  ( const ds_hvector_btype<dsd_wspadm_all>* ads_data, void* avop_context );

    // sort log functions:
    bool m_sort_log    ();
    bool m_check_filled( int in_filled1, int in_filled2 );
	 bool m_copy_field(const dsd_wspadm_all* ads_rec, int* ain_position, int iml_len_field, char* (&rdsp_out));
    
    // cluster reading functions:
    bool m_read_cluster( const dsd_wspadm_all* ads_rec, char ch_typeset, int* ain_position, dsd_read_cluster_context* adsp_context );
    bool m_read_cluster_type0( const dsd_wspadm_all* ads_rec, int* ain_position, dsd_read_cluster_context* adsp_context );
    bool m_read_cluster_type1( const dsd_wspadm_all* ads_rec, int* ain_position, dsd_read_cluster_context* adsp_context );
    // listen reading functions:
    bool m_read_listen( const dsd_wspadm_all* ads_rec, char ch_typeset, int* ain_position, dsd_read_listen_context* adsp_context );
    bool m_read_listen_type0( const dsd_wspadm_all* ads_rec, int* ain_position, dsd_read_listen_context* adsp_context );
    bool m_read_listen_type1( const dsd_wspadm_all* ads_rec, int* ain_position, dsd_read_listen_context* adsp_context );
    // performance data reading functions:
    bool m_read_perf( const dsd_wspadm_all* ads_rec, char ch_typeset, int* ain_position, dsd_read_perf_context* adsp_context );
    bool m_read_perf_type0( const dsd_wspadm_all* ads_rec, int* ain_position, dsd_read_perf_context* adsp_context );
	//	WSP Traces data reading functions
	bool m_read_wsptrace_curconf( const dsd_wspadm_all* adsp_rec, char chp_typeset, int* ainp_position, dsd_read_wsptrace_info_context* adsp_context );
	bool m_read_wsptrace_curconf0( const dsd_wspadm_all* adsp_rec, int* ainp_position, dsd_read_wsptrace_info_context* adsp_context );
	// session reading functions:
    bool m_read_session( const dsd_wspadm_all* ads_rec, char ch_typeset, int* ain_position, struct dsd_read_session_context* adsp_context );
    bool m_read_session_type0( const dsd_wspadm_all* ads_rec, int* ain_position, struct dsd_read_session_context* adsp_context );
    // log reading functions:
    bool m_read_log( const dsd_wspadm_all* ads_rec, char ch_typeset, int* ain_position, dsd_read_log_info_context* adsp_context );
    bool m_read_log_type0( const dsd_wspadm_all* ads_rec, int* ain_position, dsd_read_log_info_context* adsp_context );
    // cancel session reading functions:
    bool m_read_cancel_session( const dsd_wspadm_all* ads_rec, char ch_typeset, int* ain_position, dsd_read_cancel_session_context* adsp_context );
    bool m_read_cancel_session_type0( const dsd_wspadm_all* ads_rec, int* ain_position, dsd_read_cancel_session_context* adsp_context );

    // length functions:
    int m_get_nhasnlen( struct dsd_gather_i_1* ads_gather, int* ain_offset );

    // memory freeing functions:
    void m_free_cluster(dsd_cluster* ads_cluster);
    void m_free_cluster(dsd_cluster_remote_01* ads_remote);
    void m_free_listen( dsd_listen* ads_listen_in );
    void m_free_listen( dsd_each_listen* ads_listen_in );
    void m_free_perfdata( dsd_perfdata* ads_perfdata );
    void m_free_session( dsd_session_info* ads_session_info_in );
    void m_free_log( dsd_log_info* ads_log_in, bool bo_keep_msg = false );
	void m_free_wsptrace( dsd_wsptrace_info* adsp_wsptrace_info_in );

    // helper functions:
    bool       m_copy_data      ( struct dsd_gather_i_1* ads_gather, int* ain_position, int in_data_len, char* ach_out );
    int        m_get_query_value( const dsd_const_string& rdsp_name, const char** aach_value, int* ain_len_value, int in_start_index = 0 );
    long long  m_str_to_ll      ( const char* ach_ptr, char** aach_endptr, int in_base );
    inline int m_get_cvalue     ( char ch_in, int in_base );
    
    dsd_cluster_remote_01* m_get_next_cluster_ptr(dsd_read_cluster_context* adsp_context);
    dsd_listen*         m_get_next_listen_ptr(dsd_read_listen_context* adsp_context);
    dsd_each_listen*    m_get_next_listen_each_ptr(dsd_read_listen_context* adsp_context);
    dsd_session_info*   m_get_next_session_ptr(dsd_read_session_context* adsp_context);
    dsd_log_info*       m_get_next_log_ptr(dsd_read_log_info_context* adsp_context);
	dsd_wsptrace_info*  m_get_next_wsptrace_ptr(dsd_read_wsptrace_info_context* adsp_context);
};
#endif // DS_WSP_ADMIN_H
