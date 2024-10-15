#ifndef DS_HELPER_WSP_H
#define DS_HELPER_WSP_H
/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_wsp_helper                                                         |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|   Michael Jakobs                                                        |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| =====                                                                   |*/
/*|   September 2008                                                        |*/
/*|   June 2009                                                             |*/
/*|                                                                         |*/
/*| COPYRIGHT:                                                              |*/
/*| ==========                                                              |*/
/*|  HOB GmbH & Co. KG, Germany                                             |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/
#ifndef XH_INTERFACE
#error You must define XH_INTERFACE in your project
ölslöslöslös
#endif

#ifndef DOM_CAST
    #ifndef HL_LINUX_ARM
        #define DOM_CAST long long
    #else
        #define DOM_CAST int
    #endif
#endif //DOM_CAST


struct dsd_wspat_public_config; // forward definition
class  ds_usercma;              // forward definition

/*+-------------------------------------------------------------------------+*/
/*| include global headers                                                  |*/
/*+-------------------------------------------------------------------------+*/
#include <types_defines.h>
#include <stdio.h>
#if defined WIN32 || defined WIN64
    #include <windows.h>
    #pragma warning(disable:4996)
#else
    #include <sys/types.h>
    #include <errno.h>
#endif

#define DEF_HL_INCL_DOM  // important; used in hob-xsclib01.h !!
#ifdef HL_HPUX
    #include <iostream>
#endif
#include <xercesc/dom/DOMLocator.hpp>
#include <xercesc/dom/impl/DOMElementImpl.hpp>

#ifndef _IBIPGW08_X1_HPP
    #define _IBIPGW08_X1_HPP
    #include <IBIPGW08-X1.hpp>
#endif // _IBIPGW08_X1_HPP

// MJ 05.05.09:
#ifndef _HOB_XSCLIB01_H
    #define _HOB_XSCLIB01_H
    #include <hob-xsclib01.h>
#endif //_HOB_XSCLIB01_H

#include <hob-wspat3.h>

#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>    // must be behind hob-xsclib01.h!!
#endif // HOB_XSLUNIC1_H

#ifndef _HOB_WSP_ADMIN1_H
    #define _HOB_WSP_ADMIN1_H
    #include <hob-wsp-admin-1.h>
#endif

#include <hob-stor-sdh.h>
#include <ds_hstring.h>

/*+-------------------------------------------------------------------------+*/
/*| logfile structure:                                                      |*/
/*+-------------------------------------------------------------------------+*/
#ifdef HL_UNIX
    #include <pthread.h>
    #include <sys/types.h>
    #define THREAD_LOCK pthread_mutex_t
#else // windows
    #define THREAD_LOCK CRITICAL_SECTION
#endif //HL_UNIX

enum ied_sdh_log_level {
    ied_sdh_log_details = 1,
    ied_sdh_log_info    = 2,
    ied_sdh_log_warning = 3,
    ied_sdh_log_error   = 4
};

/**! \brief Logging structure
 *
 * \ingroup winterface
 *
 * Keeps logging information
 */
typedef struct dsd_sdh_log {
    bool                boc_active;         //!< log activated
    const char*         achc_file;          //!< fullpath to our logfile (zero terminated)
    const char*         achc_version;       //!< version string of calling datahook
    THREAD_LOCK         dsc_lock;           //!< write lock
    ied_sdh_log_level   iec_level;          //!< log level
} dsd_sdh_log_t;

#define SDH_LOG_CNF_LEVEL_DETAILS "DETAILS"
#define SDH_LOG_CNF_LEVEL_INFO    "INFO"   
#define SDH_LOG_CNF_LEVEL_WARN    "WARN"   
#define SDH_LOG_CNF_LEVEL_ERROR   "ERROR"

/*+-------------------------------------------------------------------------+*/
/*| send direction:                                                         |*/
/*+-------------------------------------------------------------------------+*/
enum ied_sdh_data_direction {
    ied_sdh_dd_auto     = 0,
    ied_sdh_dd_toserver = 1,
    ied_sdh_dd_toclient = 2
};

struct dsd_sha1 {
    int inrc_data[24];
};

#define SHA1_DIGEST_LEN 20

//struct dsd_const_string;

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/**! \brief Wrapper class
 *
 * \ingroup winterface
 *
 * Wrapper class for accessing the WSP auxilliary function interface
 */
class ds_wsp_helper
{
public:
	 struct dsd_gather_pos {
		 struct dsd_gather_i_1* adsc_gai1;
		 char* achl_ptr;
	 };

    // constructor/destructor:
    ds_wsp_helper(void);
    ds_wsp_helper( struct dsd_hl_clib_1*        ads_trans_input );
    ds_wsp_helper( struct dsd_hl_clib_dom_conf* ads_conf_input  );
    ds_wsp_helper( struct dsd_wspat3_1          *adsp_auth_input );
    ~ds_wsp_helper(void);

    // init functions:
    void m_init_trans( struct dsd_hl_clib_1*        ads_trans_input );
    void m_init_conf ( struct dsd_hl_clib_dom_conf* ads_conf_input  );
    void m_init_auth ( struct dsd_wspat3_1          *adsp_auth_input );

    // get version function:
    const char* m_get_version();

    // installpath function
    bool m_get_wsp_path( char* chr_buffer, int in_len );
    bool m_mkdir       ( const char* ach_path );
    bool m_split_path  ( const char* achp_path, char** aachp_part );

    // callback helper functions:
    bool  m_call_aux( int in_mode, void* av_data, int in_size );
	bool  m_cb_print_out        ( const dsd_const_string& ach_to_print );
    bool  m_cb_printf_out       ( HL_FORMAT_STRING const char* ach_format, ...  ) HL_FUNC_FORMAT_PRINTF(2, 3);
    bool  m_cb_printf_out2      ( const char* ach_format, ...  );
    bool  m_cb_string_from_epoch( struct dsd_hl_aux_epoch_1* ds_epoch_to_str );
    bool  m_cb_epoch_from_string( struct dsd_hl_aux_epoch_1* ds_epoch_from_str );
    bool  m_cb_get_random  (char* ach_dest, int in_length);
    bool  m_cb_get_random_cookie  (char* ach_dest, int in_length);
    bool  m_cb_get_secure_random(char* ach_dest, int in_length);
    const char* m_cb_get_wsp_info();
    int   m_get_wsp_version();
    int   m_get_session_id ();
    int   m_get_listen_port();
    int   m_get_wsp_auth();

    // ident methods:
    bool m_cb_check_ident( struct dsd_hl_aux_ch_ident* ads_auth_usrlist );
    bool m_cb_set_ident  ( const char* achp_usr,    int inp_len_usr,
                           const char* achp_group,  int inp_len_group,
                           const char* achp_usrfld, int inp_len_ufld );
    bool m_cb_get_ident  ( struct dsd_sdh_ident_set_1* ads_ident );

	// secure XOR call
	bool m_cb_secure_aux( struct dsd_aux_secure_xor_1* adsp_secure_xor );

    // radius methods:
    bool m_cb_call_radius( struct dsd_hl_aux_radius_1* ads_radius );
    bool m_cb_free_radius( struct dsd_hl_aux_radius_1* ads_radius );

    // file methods:
    bool m_cb_file_access(struct dsd_hl_aux_diskfile_1* ds_read_diskfile);
    bool m_cb_file_lastmodified(struct dsd_hl_aux_diskfile_1* ds_read_diskfile);
    bool m_cb_file_release(struct dsd_hl_aux_diskfile_1* ds_read_diskfile);
    void* m_open_file ( const char *achp_path, int inp_length );
    bool  m_read_file ( void *avp_handle, char **achp_content, int *ainp_length );
    void  m_close_file( void *avp_handle );
    
    // tcp functions:
    bool m_cb_tcp_connect( struct dsd_aux_tcp_conn_1* ds_tcp );
    bool m_cb_tcp_close();
    bool m_cb_get_clientip( struct dsd_aux_query_client* ads_client );

    // time functions:
    hl_time_t m_cb_get_time();
    HL_LONGLONG m_cb_get_time_epoch_ms();
    bool   m_cb_set_timer    ( int in_msecs );
    bool   m_cb_rel_timer    ();
    bool   m_cb_query_timer  ( struct dsd_timer1_ret* ads_timer );

    // memory functions
    char* m_cb_get_memory (int in_len, bool bo_init_zeros);
    void  m_cb_free_memory(void* av_free, int in_len = 0);
    char* m_cb_get_big_memory(int in_len, bool bo_init_zeros);
    void  m_cb_free_big_memory(void* av_free);

	 enum ied_cma_result {
		iec_cma_failed,
		iec_cma_exists,
		iec_cma_success
	 };

    // cma functions:
    bool  m_cb_exist_cma        ( const char* ach_name, int in_len_name );
    int   m_cb_exist_cma2( const char* ach_name, int in_len_name );
    bool  m_cb_create_cma       ( const char* ach_name, int in_len_name, void* av_data, int in_len, int inp_retention_time );
    ied_cma_result  m_cb_create_cma_excl  ( const char* ach_name, int in_len_name, void* av_data, int in_len, int inp_retention_time );
	 bool  m_cb_resize_cma       ( const char* ach_name, int in_len_name, int in_size );
    bool  m_cb_delete_cma       ( const char* ach_name, int in_len_name );
    void* m_cb_open_cma         ( const char* ach_name, int in_len_name, void** aav_data, int* ain_len, bool bo_write = true );
	bool  m_cb_open_cma2         ( const char* ach_name, int in_len_name, struct dsd_hl_aux_c_cma_1* adsp_cma_data, bool bo_write);
	bool  m_cb_open_or_create_cma(const char* ach_name, int in_len_name, struct dsd_hl_aux_c_cma_1* adsp_cma_data, int inp_retention_time);
	bool  m_cb_close_cma2       (struct dsd_hl_aux_c_cma_1* adsp_cma_data);
    bool  m_cb_close_cma        ( void** aav_cma_handle );
    bool  m_cb_resize_cma       ( void* av_cma_handle, void** aav_data, int in_size );
	bool  m_cb_resize_cma2      ( struct dsd_hl_aux_c_cma_1* adsp_cma, int in_size );
    int   m_cb_get_retention_cma( const char* ach_name, int in_len_name );
#if 0
    bool  m_cb_set_retention_cma( const char* ach_name, int in_len_name, int in_sec );
#endif
	bool  m_cb_set_retention_cma2( dsd_hl_aux_c_cma_1* adsp_cma, int in_sec );
    int   m_cb_get_next_cma     ( const char* ach_name, int in_len_name, char* ach_found, int in_len_fbuffer );
    int   m_count_cma_lock      ();
#ifdef _DEBUG
    int   m_get_cma_writes();
    int   m_get_cma_reads ();
#endif

    // send/receive functions:
	 enum ied_sdh_data_direction m_get_default_direction();
    struct dsd_gather_i_1* m_get_input();
    struct dsd_gather_i_1* m_get_output();
	 struct dsd_gather_i_1* m_get_output(enum ied_sdh_data_direction ienp_direction);

    bool   m_send_data      ( const char* achp_data, int inp_len_data, enum ied_sdh_data_direction ienp_direction = ied_sdh_dd_auto );
    bool   m_send_data      ( const char* achp_data, int inp_len_data, bool bop_copy_data, enum ied_sdh_data_direction ienp_direction, struct dsd_gather_pos& rdsp_pos );
    bool   m_send_replace   ( int in_offset, const char* ach_data, int in_len_data );
    bool   m_cb_get_workarea( char** aach_wa, int* ain_len );
	bool   m_cb_get_persistent_workarea( struct dsd_aux_get_workarea *adsp_wa, int inp_min_size );

    char*  m_get_end_ptr   ( struct dsd_gather_i_1* ads_gather, int in_offset );
    char*  m_get_buf       ( struct dsd_gather_i_1* ads_gather, int in_offset, int in_requested, int* ain_received );
    int    m_get_gather_len( struct dsd_gather_i_1* ads_gather );
    void   m_mark_processed( struct dsd_gather_i_1* ads_gather, int* ain_offset, int* ain_length );

    // server entry functions:
    ied_scp_def m_cb_get_protocol_type( const char* ach_proto, int in_len_proto );
    int         m_cb_count_servers    ( void* av_userentry, void* av_usergroup, ied_scp_def ien_protocol, const char* ach_proto, int in_len_proto );
    void*       m_cb_get_server_entry ( void* av_userentry, void* av_usergroup, ied_scp_def ien_protocol, const char* ach_proto, int in_len_proto, char* ach_target, int* ain_len_target, void* av_previous = NULL, int* ain_function = NULL );
    bool        m_cb_prepare_connect  ( dsd_wspat3_conn* adsp_conn );

    // current session function:
    bool m_get_own_srv_entry( char* achp_name,  int inp_max_name,  int* ainp_len_name,
                              char* achp_proto, int inp_max_proto, int* ainp_len_proto );

    // session configuration:
    bool m_cb_config_session( struct dsd_aux_session_conf_1* ads_config );

    // xerces functions:
    DOMNode*  m_cb_get_confsection();
    DOMNode*  m_cb_get_firstchild ( DOMNode* ads_node );
    DOMNode*  m_cb_get_nextsibling( DOMNode* ads_node );
    DOM_CAST  m_cb_get_node_type  ( DOMNode* ads_node );
    const HL_WCHAR* m_cb_get_node_name  ( DOMNode* ads_node );
    const HL_WCHAR* m_cb_get_node_value ( DOMNode* ads_node );
    int       m_cb_get_node_line  ( DOMNode* ads_node );
    int       m_cb_get_node_colm  ( DOMNode* ads_node );

    // ldap:
    int  m_cb_count_ldap_srv();
    bool m_cb_get_ldap_srv  ( int in_index, dsd_unicode_string* ads_name, dsd_unicode_string* ads_comment );
    bool m_cb_set_ldap_srv  ( int in_index );
    bool m_set_ldap_srv     ( const char* ach_name, int in_len_name );
    bool m_reset_ldap_srv   ();
    bool m_cb_ldap_request  ( dsd_co_ldap_1* adsp_co_ldap );

    // radius:
    int  m_cb_count_radius_srv();
    bool m_cb_get_radius_srv  ( int inp_index, struct dsd_unicode_string *adsp_name, struct dsd_unicode_string *adsp_comment );
    bool m_cb_set_radius_srv  ( int inp_index );
    bool m_set_radius_srv     ( const char *achp_name, int inp_len_name );
    bool m_reset_radius_srv   ();

    // kerberos:
    int  m_cb_count_krb5_srv();
    bool m_cb_get_krb5_srv  ( int in_index, dsd_unicode_string* ads_name, dsd_unicode_string* ads_comment );
    bool m_cb_set_krb5_srv  ( int in_index );
    bool m_set_krb5_srv     ( const char* ach_name, int in_len_name );
    bool m_reset_krb5_srv   ();
    bool m_cb_auth_krb5     ( struct dsd_aux_krb5_sign_on_1* ads_krb5_auth );
    bool m_cb_krb5_get_service_ticket             ( struct dsd_aux_krb5_se_ti_get_1* ads_krb5 );
    bool m_cb_krb5_check_service_ticket_response  ( struct dsd_aux_krb5_se_ti_c_r_1* ads_krb5 );
    bool m_cb_logout_krb5   ();

    // storage container functions:
    void m_use_storage( void** aav_storage, int in_size );
    void m_no_storage ( void** aav_storage );

    // return functions:
    void m_return_error();
    void m_return_close();
    bool m_has_error();

    // config functions:
    void* m_get_config   ();
    bool  m_init_config   ( int in_size );
    bool  m_copy_to_config( const void* av_data,   int in_len,
                            int* ain_offset, int in_max_len,
                            bool bo_align );
    struct dsd_wspat_public_config* m_get_wspat_config();

    // working structure function:
    void* m_get_structure();
    int   m_get_func();
    
    // wsp admin functions:
    struct dsd_gather_i_1* m_cb_adm_cluster    ( bool bo_free_buffer );
    struct dsd_gather_i_1* m_cb_adm_listen     ( HL_LONGLONG il_handle_cluster, bool bo_free_buffer );
    struct dsd_gather_i_1* m_cb_adm_perfdata   ( HL_LONGLONG il_handle_cluster, bool bo_free_buffer );
    struct dsd_gather_i_1* m_cb_adm_session    ( HL_LONGLONG il_handle_cluster, bool bo_free_buffer,
                                                 struct dsd_wspadm1_q_session ds_adm_session,
                                                 const char* ach_user, const char* ach_group, const char* achp_userfield );
    struct dsd_gather_i_1* m_cb_adm_log        ( HL_LONGLONG il_handle_cluster, bool bo_free_buffer,
                                                 struct dsd_wspadm1_q_log ds_log,
                                                 const char* ach_search = NULL );
    struct dsd_gather_i_1* m_cb_sess_disconnect( HL_LONGLONG il_handle_cluster, bool bo_free_buffer,
                                                 struct dsd_wspadm1_q_can_sess_1 ds_disconnect );
	// WSP Trace admin functions
	struct dsd_gather_i_1* m_cb_adm_wsptrace_query		( HL_LONGLONG ilp_handle_cluster, bool bop_free_buffer,
														  struct dsd_wspadm1_q_wsp_trace_1 dsp_query_wsptrace,
														  int imp_len_data, const char* achp_data );
    struct dsd_gather_i_1* m_cb_adm_wsptrace_info		( HL_LONGLONG ilp_handle_cluster, bool bop_free_buffer);

    // tracing/log functions:
    bool m_is_logable( ied_sdh_log_level ien_level );
    void m_log       ( ied_sdh_log_level ien_level, const dsd_const_string& ach_to_log );
    void m_logf      ( ied_sdh_log_level ien_level, HL_FORMAT_STRING const char* ach_format, ... ) HL_FUNC_FORMAT_PRINTF(3, 4);
    void m_logf2      ( ied_sdh_log_level ien_level, const char* ach_format, ... );
    void m_log_input ();
    void m_log_output();

	// sip related
	bool m_cb_sip_request( struct dsd_sdh_sip_requ_1 *ads_sip_request );

	// udp related
	bool m_cb_udp_request( struct dsd_sdh_udp_requ_1 *ads_udp_request );
    // udp gate
    bool m_cb_udp_gate( struct dsd_aux_cmd_udp_gate *ads_udp_gate );

    // certificate related:
    bool m_cb_get_certificate( void **aavp_cert, int *ainp_length );

    // storage container
    bool m_new_storage_cont( struct dsd_stor_sdh_1 *adsp_container, int inp_size );
    void m_del_storage_cont( struct dsd_stor_sdh_1 *adsp_container );

    static void m_sha1_init(struct dsd_sha1& rdps_sha1);
    static void m_sha1_update(struct dsd_sha1& rdps_sha1, const void* avop_data, int inp_len);
    static void m_sha1_final(struct dsd_sha1& rdps_sha1, void* avop_data);

    template<typename T1, size_t T1_SIZE, typename T2> static const T1* m_search_equals(
        const T1 (&rdsp_array)[T1_SIZE], const T2& rdsp_key, const T1* adsp_default)
    {
        for(size_t szl_i=0; szl_i<T1_SIZE; szl_i++) {
            if(rdsp_array[szl_i].dsc_key.m_equals(rdsp_key))
                return &rdsp_array[szl_i];
        }
        return adsp_default;
    }

    template<typename T1, size_t T1_SIZE, typename T2> static const T1* m_search_equals_ic(
        const T1 (&rdsp_array)[T1_SIZE], T2& rdsp_key, const T1* adsp_default)
    {
        for(size_t szl_i=0; szl_i<T1_SIZE; szl_i++) {
            if(rdsp_array[szl_i].dsc_key.m_equals_ic(rdsp_key))
                return &rdsp_array[szl_i];
        }
        return adsp_default;
    }

    template<size_t T1_SIZE> static const dsd_const_string* m_search_equals_ic(
        const dsd_const_string (&rdsp_array)[T1_SIZE], const dsd_const_string& rdsp_key, const dsd_const_string* adsp_default)
    {
        for(size_t szl_i=0; szl_i<T1_SIZE; szl_i++) {
            if(rdsp_array[szl_i].m_equals_ic(rdsp_key))
                return &rdsp_array[szl_i];
        }
        return adsp_default;
    }

    template<size_t T1_SIZE> static const dsd_const_string* m_search_equals_ic(
        const dsd_const_string (&rdsp_array)[T1_SIZE], dsd_unicode_string& rdsp_key, const dsd_const_string* adsp_default)
    {
        for(size_t szl_i=0; szl_i<T1_SIZE; szl_i++) {
            if(rdsp_array[szl_i].m_equals_ic(rdsp_key))
                return &rdsp_array[szl_i];
        }
        return adsp_default;
    }

    template<size_t T1_SIZE, typename T2, typename T3> static T3 m_search_equals2(
        const dsd_const_string (&rdsp_array)[T1_SIZE], T2& rdsp_key, const T3 inp_default)
    {
        for(size_t szl_i=0; szl_i<T1_SIZE; szl_i++) {
            if(rdsp_array[szl_i].m_equals(rdsp_key))
                return (T3)szl_i;
        }
        return inp_default;
    }

    template<size_t T1_SIZE, typename T2, typename T3> static T3 m_search_equals_ic2(
        const dsd_const_string (&rdsp_array)[T1_SIZE], T2& rdsp_key, const T3 inp_default)
    {
        for(size_t szl_i=0; szl_i<T1_SIZE; szl_i++) {
            if(rdsp_array[szl_i].m_equals_ic(rdsp_key))
                return (T3)szl_i;
        }
        return inp_default;
    }

private:
    // variables:
    struct dsd_hl_clib_1*        ads_trans;     // for wsp functions in normal mode
    struct dsd_hl_clib_dom_conf* ads_conf;      // for wsp functions in config mode
    struct dsd_wspat3_1*         ads_wspat3;    // for wsp functions in auth mode
    struct dsd_stor_sdh_1*       ads_storage;   // storage container structure

    /*
         if we do a dynamic tcp connect our function will still be DEF_IFUNC_REFLECT
         if we are sending data in this case we need to know, that we have to send
         the data to server and not (as usual) to client.

         We will save our connection state for the current call, the next call will
         have a correct DEF_IFUNC_FROMSERVER/DEF_IFUNC_TOSERVER set.
    */
    enum ied_tcp_conn {
        ied_unknown,
        ied_connected,
        ied_disconnected
    } ienc_tcp_conn;

    // our working mode:
    enum ein_wmode {
        ien_undefined,
        ien_trans,
        ien_conf,
        ien_wspat3
    } work_mode;

    // send variable:
    int in_len_last_wa;                         // save length of last workarea
    struct dsd_gather_i_1* adsc_send_last_to_client;
    struct dsd_gather_i_1* adsc_send_last_to_server;

    // cma access counters:
#ifdef _DEBUG
    int inc_cma_write;                          // count cma write access
    int inc_cma_read;                           // count cma read access
#endif


    // functions:
    inline void* m_call_xerces( DOMNode* ads_node, int in_mode );

    // cma helper functions:
    bool m_setup_cma ( dsd_hl_aux_c_cma_1* ads_cma, int in_size );
    bool m_resize_cma( dsd_hl_aux_c_cma_1* ads_cma, int in_size );
    bool m_query_cma ( dsd_hl_aux_c_cma_1* ads_cma );
    bool m_lock_cma  ( dsd_hl_aux_c_cma_1* ads_cma,  bool bo_write = true );
    bool m_unlock_cma( dsd_hl_aux_c_cma_1* ads_cma );

    // send helper functions:
    int  m_copy_data       (  const void* av_input, int in_len_input,
                              void* av_target, int in_len_target,
                              int* ain_offset, bool bo_align );
    bool m_copy_data       ( struct dsd_gather_i_1* ads_gather, 
                             int* ain_position, int in_data_len,
                             char* ach_out );

    // admin helper functions:
    struct dsd_gather_i_1* m_cb_admin( struct dsd_aux_admin_1 ds_admin );
    char*                  m_get_adm_command( char* ach_serivce, int* ain_len_out,
                                              void* ach_query = NULL, int in_len_query = 0,
                                              char  ch_type = 0 );

    // storage init function
    inline void m_init_storage();

    // log helper functions:
    FILE* m_open_log ( ied_sdh_log_level ien_level, const char** aach_version );
    void  m_close_log( FILE* av_log );
    void  m_dump_data( unsigned char*, int, FILE* );

    // buffer print function
    int m_fbuffer( char* ach_buffer, int in_len_buf, HL_FORMAT_STRING const char* ach_format, ... ) HL_FUNC_FORMAT_PRINTF(4, 5);

    // other helper functions 
    // (are currently only needed here - if needed elsewere, put them in helper class)
    int m_to_nhasn( int in_input, char* ach_out, int in_max_len );
    int m_count_nhasn_len( int in_input );
    int m_get_nhasnlen( struct dsd_gather_i_1 * ads_gather, int* ain_offset );

    // conf file functions:
    bool m_read_file_conf   ( struct dsd_hl_aux_diskfile_1* adsp_file );
    bool m_release_file_conf( struct dsd_hl_aux_diskfile_1* adsp_file );
};

struct dsd_forward_iterator
{
    void* avoc_cur;
    void* avoc_end;
	void* avoc_user;
};

struct dsd_random_access_iterator
{
    int inc_cur;
    int inc_end;
};

#endif // DS_HELPER_WSP_H
