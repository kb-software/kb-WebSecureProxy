#ifndef DS_WEBSERVER_H
#define DS_WEBSERVER_H

#include <rdvpn_globals.h>
#include "../sdh_web_server.h"
#include <ds_hstring.h>
#include <ds_wsp_admin.h>
#include <stdint.h>

class ds_session;           // forward-definition!!
struct dsd_query;           // forward-definition
struct dsd_session_info;    // forward-definition
template <class T> class ds_hvector_btype;

/*+-------------------------------------------------------------------------+*/
/*| helper class definition:                                                |*/
/*+-------------------------------------------------------------------------+*/

/*! \brief Webserver basic class
 *
 * @ingroup webserver
 *
 *  Gets HTTP requests and processes them
 */
class ds_webserver
{
#if SM_USE_AUX_PIPE_STREAM
	enum ied_stream_pipe_state {
		ied_stream_pipe_state_head = 0,
		ied_stream_pipe_state_write,
		ied_stream_pipe_state_close,
	};

	 struct dsd_aux_pipe_stream {
		 void* vpc_aux_pipe_handle;
		 ied_stream_pipe_state iec_stream_state;
		 uint32_t umc_length_total;
		 uint32_t umc_length_pending;
	 	 ds_hvector<uint32_t> dsc_pending_writes;
	 };
#endif

public:
    // constructor/destructor:
    ds_webserver(void);
    ~ds_webserver(void);

    bool m_init(ds_session* ads_session_in);

    // variables:
	/*! \brief path information
     *
     * @ingroup webserver
     *
     *  Path Information
    */
    struct dsd_path {
        int        in_state_path;
        ds_hstring hstr_path;
    };
    struct dsd_path ds_path;
    ds_hstring hstr_message_body;
    dsd_const_string hstr_my_encoding;
#if 0
    ds_hstring hstr_user_domain;
    ds_hstring hstr_user_dn;
    ds_hstring hstr_user_name;
#endif
    bool bo_compress_makes_sense;
    struct dsd_query* ads_query;           // MJ 05.08.09: parsed query param from both url and message body

    ds_hvector_btype<dsd_session_info*> dsc_v_logout_connections;   // MJ 05.07.10 connections to be killed with logout
#if SM_USE_AUX_PIPE_STREAM
	 struct dsd_aux_pipe_stream dsc_aux_pipe_stream;
#endif

    // functions:
    ds_hstring m_create_location(const dsd_const_string& ach_path, const dsd_const_string& ach_query, bool bo_insert_ID_in_URL=false, bool bo_prevent_cookie_in_URL=false, const dsd_const_string* adsl_cookie=NULL);
    int m_create_resp_header(int in_status_code, int in_data_length, const dsd_const_string* ahstr_location, const dsd_const_string* ach_last_modified,
                             const dsd_const_string* adsp_cookie, bool bo_prevent_caching, const dsd_const_string* ach_connection, int in_mode=HDR_MODE_DEFAULT,
                             const dsd_const_string* adsp_encoding = NULL, const dsd_const_string* achp_content_md5 = NULL);

    int m_conv_from_hexhexencoding(ds_hstring* ahstr_to_change);
	 static int m_conv_from_hexhexencoding(const dsd_const_string& hstr_src, ds_hstring& rdsp_tmp, dsd_const_string& rdsp_result);

    bool m_get_fullpath(struct dsd_path* ds_path_ret);

    // process data of a POST
    int m_read_message_body(void);
    
    // error page functions:
    int        m_send_error_page          ( int in_status_code, bool bo_add_return_link, const dsd_const_string &rdsp_msg, int in_msg_type, int in_msg_code );
    ds_hstring m_setup_error_page         ( dsd_msg_t* ads_msg, bool bo_add_return_link );
    ds_hstring m_setup_error_page_fallback( dsd_msg_t* ads_msg, bool bo_add_return_link );
    

    void m_forward_to_logout( const dsd_const_string& ach_msg, int in_msg_type, int in_msg_code );

    int m_file_proc(const dsd_path& dsl_path, const dsd_const_string* adsp_cookie, ds_hstring* ahstr_last_modified=NULL, bool bop_no_error_resp=false);
    // send a html-page to webbrowser, displaying error information

	 dsd_const_string m_get_query(ds_hstring& hstr_temp);
    dsd_query* m_parse_query    ( const dsd_const_string& ach_query );
    int        m_get_query_value( const dsd_const_string& rdsp_name, const char** aach_value, int* ain_len_value, int in_start_index = 0 );
    int        m_get_query_value( const dsd_const_string& rdsp_name, dsd_const_string* ads_value );
    void       m_clear_query     ();
    void       m_free_query     ( dsd_query* ads_in );

    void m_setup_encoding_string(const dsd_const_string& ach_filepath);

    // MJ 22.06.09:
    void       m_handle_post    ( bool bo_authenticated );
    bool       m_send_logout_page();
    void m_release_disk_file();

#if SM_USE_QUICK_LINK
	int        m_handle_quick_link(const dsd_const_string& rdsp_path, bool bo_authenticated);
	int        m_handle_virtual_protected_portlets_webterm_rdp(const dsd_const_string& rdsp_path);
	int        m_handle_virtual_public_portlets_webterm_rdp(const dsd_const_string& rdsp_path, bool bo_authenticated);
	int        m_handle_virtual_protected_session(const dsd_const_string& rdsp_path);
#endif
#if SM_USE_VIRTUAL_LINK
	int        m_handle_virtual_link(const dsd_const_string& rdsp_path, bool bo_authenticated);
#endif
#if SM_USE_AUX_PIPE_STREAM
	int        m_handle_stream_link(const dsd_const_string& rdsp_path, bool bo_authenticated);
	bool       m_handle_stream_pipe_data(struct dsd_aux_pipe_stream* adsp_aps, struct dsd_gather_i_1 *adsp_gai1_data);
	bool       m_handle_signal(int imp_signal);
	bool       m_stream_to_browser_continue();
#endif

private:
    // variables:
    ds_session* ads_session;
    bool        bo_with_ldap;
    struct dsd_hl_aux_diskfile_1 dsc_read_diskfile;

    // functions:
    dsd_query* m_get_new_query  ( dsd_query* ads_in );
    int        m_get_query_value( struct dsd_query* ads_query, const char* ach_name, int in_len_name, const char** aach_value, int* ain_len_value, int in_start_index );

public:
    int        m_setup_cookie_string   (ds_hstring* ahstr_cookie, const dsd_const_string& rdsp_wspsid);

private:
    // Ticket[15852]:
    bool m_get_realpath( ds_hstring* ads_path );
    
    // specific post handling functions:
	void m_handle_wsptrace_post  ();
    void m_handle_login_post     ();
    void m_finish_login();
    void m_handle_logout_post    ();
    void m_handle_disconnect_post();
    void m_handle_usr_logout_post();
    void m_handle_admin_post     ();
    void m_handle_template_post  ();
	void m_handle_jwtsa_request  ();
    void m_handle_quaratine_post ();
    void m_handle_settings_post  ();
	void m_handle_webtermrdp_request();
    void m_logout_self           ();
    void m_logout_usr            ();
    void m_handle_change_pwd_post();
    void m_handle_ica_post       ( int iep_url );
    int  m_get_settings_task     ( const char* ach_task, int in_len );

    bool m_file_is_modified(const dsd_const_string& strp_path, struct dsd_hl_aux_diskfile_1& ds_read_diskfile, int* ain_trans=NULL, ds_hstring* ahstr_last_modified=NULL);


    static int m_get_int_from_ASCII(int in);
public:
    int  m_use_precomp(char* ach_start, char* ach_end, struct dsd_hl_clib_1 * ads_trans_precomp,
                       char* ach_message, char* ach_username, char* ach_password,
                       char* ach_ppp_ineta, char* ach_ppp_socks_mode, char* ach_ppp_localhost, char* ach_ppp_system_parameters);
private:
	ds_hstring m_setup_commands(int* ain_len_to_insert, const dsd_const_string& ach_new_message,
                       const dsd_const_string& ach_new_username, const dsd_const_string& ach_password, const dsd_const_string& ach_sticket,
                       const dsd_const_string& ach_wsp_ineta, const dsd_const_string& ach_wsp_socks_mode,
                       const dsd_const_string& ach_wsp_localhost, const dsd_const_string& ach_ppp_system_parameters);

    void m_split( const char *achp_word, int inp_wlen, char **aachp_p1, int *ainp_p1len, char **aachp_p2, int *ainp_p2len, char **aachp_p3, int *ainp_p3len );


    bool m_get_other_sessions( ds_wsp_admin* adsp_admin );

    // hclient files methods:
    bool m_compress_data       ( const char *achp_data, int inp_len_data,
                                 const char **aachp_compr, int *ainp_len_compr );
    bool m_compress_file       ( const char *achp_path, int inl_len_path,
                                 const char **aachp_compr, int *ainp_len_compr );
    bool m_compress_www_file( const dsd_const_string& hstr_path, const char **aachp_file, int *ainp_length );

	bool m_build_hob_wsg_file(const dsd_const_string& dsp_file_content, ds_hstring& rdsp_result);
};

#endif // DS_WEBSERVER_H
