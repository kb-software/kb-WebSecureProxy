#ifndef DS_AUTH_H
#define DS_AUTH_H
/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_auth                                                               |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|   Michael Jakobs                                                        |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| =====                                                                   |*/
/*|   July 2009                                                             |*/
/*|                                                                         |*/
/*| COPYRIGHT:                                                              |*/
/*| ==========                                                              |*/
/*|  HOB GmbH & Co. KG, Germany                                             |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| some definitions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
enum ied_auth_state {
    ied_pre_auth,
    ied_post_auth,
    ied_post_logout
};

class  ds_hstring;          // forward definition
class  ds_wsp_helper;       // forward definition
class  ds_session;          // forward definition
class  ds_usercma;          // forward definition
class  ds_bookmark;         // forward definition
class  dsd_wfa_bmark;       // forward definition
class  ds_workstation;      // forward definition
class  ds_pre_cma;          // forward definition
class  ds_jwtsa_conf;
#if BO_HOBTE_CONFIG
class ds_hobte_conf;
#endif
struct dsd_role_portlet;    // forward definition
template <class T> class ds_hvector;
template <class T> class ds_hvector_btype;

#ifndef HL_UINT
    typedef unsigned int HL_UINT;
#endif

/*! \brief Information about a session to kick out
 *
 * @ingroup authentication
 *
 * Information about a session to kick out
 */
typedef struct dsd_auth_kick_out {
    dsd_cma_session_no  chc_session;    //!< session number
    dsd_aux_query_client  dsc_ineta;      //!< clients ip
    hl_time_t                tmc_login;      //!< login time
} dsd_kick_out_t;

/*! \brief Save information from logout
 *
 * @ingroup authentication
 *
 * Save information from logout
 */
struct dsd_logout_save {
    int        inc_state;   //!< state
    int        inc_lang;    //!< language
    ds_hstring dsc_msg;     //!< message
};

/*! \brief Message structure
 *
 * @ingroup authentication
 *
 * Represents a message
 */
typedef struct dsd_message {
    int        inc_type;    // message type
    int        inc_code;    // message code
    ds_hstring hstr_msg;    // message itself
} dsd_msg_t;

enum ied_webterm_protogroup {
    ied_webterm_protogroup_unknown,
    ied_webterm_protogroup_rdp,
#if BO_HOBTE_CONFIG
    ied_webterm_protogroup_te,
    ied_webterm_protogroup_te_default,
#endif
    ied_webterm_protogroup_ssh
};

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief Deals with user informations
 *
 * @ingroup authentication
 *
 * Handles user authentication and
 * stores/gets information out of the Common Memory Area
 */
class ds_auth
{
public:
    // constructor/destructor:
    ds_auth(void);
    ~ds_auth(void);

    // init function:
    void m_init( ds_session* adsl_session );
	bool m_commit();

    // login/logout functions:
    bool m_register  ( bool bo_header_cookie );
	bool m_handle_login_cert();
	void m_finish_login();
    bool m_login     ( const char *achp_usr,     int inp_len_usr,
                       const char *achp_pwd,     int inp_len_pwd,
                       const char *achp_old_pwd, int inp_len_old_pwd,
                       const char *achp_domain,  int inp_len_domain,
                       ds_hvector_btype<dsd_kick_out_t> *adsvp_kick_out );
    bool m_kick_out  ( const dsd_cma_session_no& chp_session );
    bool m_finish_kickout();
    bool m_create_new();
    bool m_logout    ();
    HL_UINT m_change_password( const char * const achp_old, int inp_old,
                            const char * const achp_new, int inp_new );

    // save user settings function:
    bool m_save_settings();

    // update function:
    void m_update();

    // open / close functions:
    bool m_check_http_cookie( const char* ach_cookie, int in_len_cookie, dsd_kicked_out_t* ads_kicked_out );
    bool m_check_ident();

    // cookie functions:
    bool m_get_http_cookie    ( ds_hstring* ads_cookie );
    int  m_get_len_http_cookie();
    
    // state functions:
    bool m_check_state( int in_state );
    int  m_get_state  ();   // JF
    void m_set_state  ( int in_state );
    void m_unset_state( int in_state );
    void m_init_state ( int in_state );
    void m_clear_state();

    // role functions:
    struct dsd_role*  m_get_role          ();
    bool              m_get_role_name     ( const char** aach_name, int* ain_len );
    bool              m_get_portlets      ( ds_hvector<ds_portlet>* ads_vportlets );
    bool              m_get_portlet       (dsd_random_access_iterator& adsp_itr, ds_portlet* ads_portlet);
    int               m_count_portlets    (dsd_random_access_iterator& rdsp_iter_out);
    bool              m_is_portlet_allowed( const dsd_const_string& ach_name );
    bool              m_is_portlet_allowed( const char* ach_name, int in_len );
    bool              m_is_caching_allowed();
    bool              m_is_config_allowed ( int inp_config );
    ds_hstring        m_get_welcomepage   ();
    bool              m_get_welcomepage   ( const char **aachp_wpage, int *ainp_len );
    bool              m_get_gui_skin      ( const char** aach_skin, int* ain_len );


#ifdef DS_PORTLET_FILTER_U_A
    void m_set_portlet_filter(int ibp_portlet_filter);

    int m_is_portlet_filter_set(void);

    int m_get_portlet_filter(void);
#endif 

    // char array functions:
    ds_hstring m_get_bookedpage ();
    bool       m_set_bookedpage ( const char* ach_page, int in_len );
    bool       m_get_msg        ( dsd_msg_t* ads_msg );
    bool       m_set_msg        ( int in_msg_type,     int in_msg_code,
                                  const dsd_const_string& ach_msg, const dsd_const_string& ach_url = dsd_const_string() );

    // language functions:
    void m_set_lang( int in_lang );
    int  m_get_lang();

    // wsg flyer functions:
    bool m_show_flyer();
    void m_set_flyer ( bool bo_show );

    // default portlet functions:
    bool m_set_default_portlet( const char* achp_default_portlet, int inp_length );
    bool m_get_default_portlet( ds_hstring* adsp_default_portlet );
    bool m_has_default_portlet( );


    // ica port functions:    
    bool m_set_ica_port( int inp_port );
    int  m_get_ica_port();
    bool m_is_ica_active();
    bool m_increase_ica_count();
    bool m_decrease_ica_count();
    bool m_reset_ica_count();

    // last webserver functions:
    ds_hstring m_get_lws( int* ain_proto, int* ain_port );
    bool       m_set_lws( int in_proto, const char* ach_lws, int in_len, int in_port );

    // single sign on functions:
    hl_time_t m_get_sso_time( int in_index );
    bool   m_set_sso_time( int in_index, hl_time_t il_time );

    // user functions:
    bool       m_get_user         ( struct dsd_getuser* ads_user );
    ds_hstring m_get_username     ();
    ds_hstring m_get_domain       ();
    ds_hstring m_get_hobsocks_name();
    ds_hstring m_get_userdn       ();
    ds_hstring m_get_password     ();
    ds_hstring m_get_sticket      ();
    int        m_get_authmethod   ();
    int        m_pwd_expires      ();
    bool       m_reset_pwd_expires();

    // kicked out:
    bool       m_save_kicked_out( dsd_kicked_out_t* ads_kicked_out );
    ds_hstring m_get_kicked_out_ineta();
    hl_time_t     m_get_kicked_out_time();

    // time functions:
    hl_time_t m_get_login_time();

    // user settings functions:
    int  m_count_wsg_bookmarks  ();
    bool m_get_wsg_bookmark     ( int in_index, ds_bookmark* ads_bmark );
    bool m_get_wsg_bookmarks    ( ds_hvector<ds_bookmark>* ads_bmarks );
    bool m_set_own_wsg_bookmarks( ds_hvector<ds_bookmark>* ads_bmarks );
    bool m_add_wsg_bookmark     ( ds_bookmark* ads_bmark );

    int  m_count_rdvpn_bookmarks  ();
    bool m_get_rdvpn_bookmark     ( int in_index, ds_bookmark* ads_bmark );
    bool m_get_rdvpn_bookmarks    ( ds_hvector<ds_bookmark>* ads_bmarks );
    bool m_set_own_rdvpn_bookmarks( ds_hvector<ds_bookmark>* ads_bmarks );

    int  m_count_wfa_bookmarks  ();
    bool m_get_wfa_bookmark     ( int in_index, dsd_wfa_bmark* ads_bmark );
    bool m_get_wfa_bookmarks    ( ds_hvector<dsd_wfa_bmark>* ads_bmarks );
#if SM_USE_OWN_WFA_BOOKMARKS
    bool m_set_own_wfa_bookmarks( ds_hvector<dsd_wfa_bmark>* ads_bmarks );
#endif
	bool m_set_wfa_bookmarks    ( ds_hvector<dsd_wfa_bmark>* ads_bmarks );
    bool m_add_wfa_bookmark     ( dsd_wfa_bmark* ads_bmark );

    int  m_count_workstations();
    bool m_get_workstation   ( int in_index, ds_workstation* ads_wstat );
    bool m_get_workstations  ( ds_hvector<ds_workstation>* ads_wstats );
    bool m_set_workstations  ( ds_hvector<ds_workstation>* ads_wstats );

	bool m_jwtsa_get_config( int in_index, ds_jwtsa_conf* adsp_jwtsa_config );
	int  m_jwtsa_count_configs();

#if BO_HOBTE_CONFIG
    bool m_hobte_get_config( int in_index, ds_hobte_conf* adsp_hobte_config );
	int  m_hobte_count_configs();
#endif
	int  m_webterm_count_server_entries(ied_webterm_protogroup iep_protogroup);
	struct dsd_webterm_server* m_webterm_get_server_entry( int inp_index, char* achp_name, int* inp_len, ied_webterm_protogroup iep_protogroup);
	
    bool m_set_portlets( ds_hvector<ds_portlet>* ads_vportlets );
    bool m_get_adm_msg ( ds_hstring *adsp_msg );       

    // base cma name:
    dsd_const_string m_get_basename();

#ifdef _DEBUG
    ied_auth_state m_get_workmode();
#endif
    
private:
    // variables:
    ied_auth_state              ien_workmode;       // our working state
    int                         inc_conn_state;     // tcp connection state
    ds_session*                 ads_session;        // session class
    ds_wsp_helper*              ads_wsp_helper;     // wsp helper class
    dsd_logout_save             dsc_logout;         // save some values after a real logout
#if SM_USE_CERT_AUTH
    enum ied_cert_auth_result iec_certificate_auth;   //!< indicates authentication by client certificate (SSL)
	const struct dsd_certificate_auth_entry* adsc_cert_auth_entry;
#endif
    class ds_usercma            dsc_post_auth;      // post authentication class
    class ds_pre_cma            dsc_pre_auth;       // pre authentication class

#ifdef DS_PORTLET_FILTER_U_A
    // bitfield generated from user agent and used to determine if portlet should be hidden because they can't be run on users machine.
    int ibc_ua_portlet_filter;
#endif

    // functions:
    void m_print_ineta  ( ds_hstring* ads_out, struct dsd_aux_query_client ds_client );
};
#endif // DS_AUTH_H
