#ifndef _DEF_DS_USERCMA_H
#define _DEF_DS_USERCMA_H
/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| PROGRAM:                                                            |*/
/*|   user cma handles all data from user                               |*/
/*|                                                                     |*/
/*| AUTHOR:                                                             |*/
/*|   Michael Jakobs, NOV 2010                                          |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/


/*
 * hofmants: following description is from jakobsml for the session ticket
 * it is NOT the normal HTTP cookie, therefore i put it here in the CMA sources
 * maybe its better to put it somewhere else, but right now i dont know where
 */

/*!
HTTP Cookie in HTTP Handler Module
----------------------------------

1.) How the HTTP Cookie is built
    ----------------------------
    The Cookie consists of two different parts
    
    - a session ticket and 
    - the user name and domain.


    a) Session Ticket
       --------------

    The session ticket is a 32 byte string in base64. It holds a random part
    and an additional checksum.

    +----------+-------------------------+
    | checksum | random                  |
    +----------+-------------------------+
    | 8 bytes  | 24 bytes                |

    * Picture 1: Design of session ticket


    Because the user might be allowed to login multiple times, the checksum is
    build from a given session number (1 byte) and the created random part.

    
    +----------------+-------------------------+
    | session number | random                  |
    +----------------+-------------------------+
    | 1 byte         | 24 bytes                |

    * Picture 2: String for creating checksum from


    The session number itself is not part of the session ticket but is
    stored in server side memory and will be checked every time when a request
    with the cookie is done.

    The checksum is added in base64 in front of the random.


    b) Username and Domain
       -------------------

    The cookie also contains information about the user it belong to and his
    domain. Both strings are added with the delimiter sign "/".


    +------------------------------------+----------------+---+---------------+
    | session ticket                     | username       | / | domain        |
    +------------------------------------+----------------+---+---------------+
    | 32 bytes                           | any            | 1 | any           |

    * Picture 3: HTTP Cookie before base64 encoding


    This whole string is encoded in base64 and this forms the HTTP Cookie.

2.) Security ideas
    --------------
    
    a) Need of the checksum
       --------------------
    The checksum is used to protect both the random against guess attacks and
    it has an additional unknown part (the session number) that is included in 
    the cookie verify.

    b) Username and Domain
       -------------------
    The Username and Domain fields are used as a key for finding a server side
    session information which holds additional information about the user (i.e.
    the session ticket itself, session number, login time, cookie lifetime ...).
    Before the user is allowed to access any protected data the delivered
    session ticket is compared with the stored one in the server side session
    information.
    
    c) Cookie lifetime
       ---------------
    The HTTP Cookie has a limited lifetime. There is a configurable maximal
    lifetime and an additional inactivity lifetime (of last userinteraction).
    Both lifetimes are checked on server side.
*/

#include <rdvpn_globals.h>
#include <ds_wsp_helper.h>

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
#define USERCMA_NAME_PREFIX     "usr"
#ifndef DEF_MAX_LEN_CMA_NAME        // wsp/include/hob-wspsu1.h
    #define D_MAXCMA_NAME 128
#else
    #define D_MAXCMA_NAME DEF_MAX_LEN_CMA_NAME
#endif

#define SM_USE_NEW_CMA_NAMES	0
#define SM_AUTHENTICATE_CASE_SENSITIVE   1
#define D_MAXCMA_SESSION_NO		255
#define SM_USE_OWN_WFA_BOOKMARKS 0

/*+---------------------------------------------------------------------+*/
/*| declarations:                                                       |*/
/*+---------------------------------------------------------------------+*/
class  ds_wsp_helper;
class  ds_hstring;
template <class T> class ds_hvector_btype;
template <class T> class ds_hvector;
class  ds_bookmark;
class  dsd_wfa_bmark;
class  ds_jwtsa_conf;
class  ds_session_bm;
class  ds_workstation;
class  ds_portlet;
struct dsd_usercma_main;
struct dsd_usercma_login;
struct dsd_role;
struct dsd_cma_wsg_bmark;
struct dsd_cma_wfa_bmark;
struct dsd_cma_workstation;
struct dsd_cma_portlet;
struct dsd_cma_jwtsaconf;
struct dsd_usercma_wsg;
struct dsd_ineta_cma_data;
#if BO_HOBTE_CONFIG
class  ds_hobte_conf;
struct dsd_cma_hobteconf;
#endif

/*used as argument to functions which type of bookmark this is*/
enum ied_bookmark_type {
    ied_bookmark_wsg,
    ied_bookmark_rdvpn
};

struct dsd_cma_session_no {
	unsigned char ucc_session_no;

private:
	dsd_cma_session_no(char ucp_val);
public:
	dsd_cma_session_no()
	{}

	dsd_cma_session_no(const dsd_cma_session_no& rdsp_src)
		: ucc_session_no(rdsp_src.ucc_session_no)
	{}
#if 0
	dsd_cma_session_no(int ucp_val)
		: ucc_session_no(ucp_val)
	{}
#endif
	explicit dsd_cma_session_no(unsigned char ucp_val)
		: ucc_session_no(ucp_val)
	{}
};

enum ied_usercma_login_flags {
    ied_usercma_login_anonymous = 0x1,
#if SM_USE_CERT_AUTH
    ied_usercma_login_cert_auth = 0x2
#endif
};

/*! \brief Get user details out of the common memory area
 *
 *  Details follow
 */
struct dsd_getuser {
    hl_time_t               tmc_login;             //!< login time
    ied_usercma_login_flags iec_auth_flags;         //!< is anonymous user
    int                  inc_auth_method;       //!< auth method
    dsd_cma_session_no   chc_session;           //!< session number
    ds_hstring           dsc_username;          //!< user name
    ds_hstring           dsc_userdomain;        //!< user domain
    ds_hstring           dsc_wspgroup;          //!< wsp usergroup
    ds_hstring           dsc_role;              //!< user role
    ds_hstring           dsc_userdn;            //!< users ldap dn
    dsd_aux_query_client dsc_client;            //!< client information
};

enum ied_usercma_settings {
    ied_struct_only,
    ied_usr_msg,
    ied_default_portlet,
    ied_wsg_bmarks,
    ied_wfa_bmarks,
    ied_workstats,
    ied_portlets,
	ied_jwtsa_conf,
#if BO_HOBTE_CONFIG
    ied_hobte_conf,
#endif
	ied_max_setting
};

/*! \brief Temporary IP address
 *
 *  Details follow
 */
struct dsd_ineta_temp {
   unsigned short int usc_family;       //!< family IPV4/IPV6
   unsigned short int usc_length;       //!< length of address
   unsigned char      chrc_ineta[16];   //!< ineta
};

/*+---------------------------------------------------------------------+*/
/*| class declaration:                                                  |*/
/*+---------------------------------------------------------------------+*/

struct dsd_cma_session_no;

struct dsd_login_info {
	dsd_const_string dsc_domain;
	dsd_const_string dsc_user;
	dsd_cma_session_no dsc_session_no;
	dsd_const_string dsc_suffix;
};

/*! \brief Common Memory Area Handler ( storage area for user data )
 *
 *  Details follow
 */
class ds_usercma {
public:
    ds_usercma();

    void  m_init( ds_wsp_helper *adsp_wsp_helper );
    ds_wsp_helper::ied_cma_result m_create(
        const char *achp_user, int inp_unlen, const char *achp_group, int inp_uglen, const dsd_cma_session_no& chp_session,
        const char *achp_pwd, int inp_pwlen, const char *achp_dn, int inp_dnlen, const char *achp_wspg, int inp_wglen, int inp_auth,
        enum ied_usercma_login_flags iep_auth_flags,
		  struct dsd_aux_ident_session_info* adsp_aux_ident_session_info );
    bool  m_delete();
    dsd_const_string m_get_basename();
    bool  m_set_name( const char *achp_name, int inp_len );
    // main cma functions:
    void       m_init_state ( int inp_state );
    void       m_set_state  ( int inp_state );
    void       m_unset_state( int inp_state );
    bool       m_check_state( int inp_state );
    int        m_get_state  ();
    bool       m_check_port ( int inp_port );
    hl_time_t  m_get_lastaction();
    bool       m_set_lastaction();
    ds_hstring m_get_message( const char* achp_url, int inp_ulen, int* ainp_type, int* ainp_code );
    bool       m_set_message( int inp_msg_type, int inp_msg_code, const dsd_const_string& achp_msg, const dsd_const_string& achp_url );
    ds_hstring m_get_bpage  ();
    bool       m_set_bpage  ( const char* achp_page, int inp_len );


    // login cma functions:
    ds_hstring m_get_username     ();
    ds_hstring m_get_userdomain   ();
    int        m_get_authmethod   (enum ied_usercma_login_flags &riep_auth_flags);
    ds_hstring m_get_hobsocks_name();
    ds_hstring m_get_userdn       ();
    ds_hstring m_get_userrole     ();
    bool       m_set_role         ( const char *achp_role, int inp_len );
    bool       m_get_user         ( struct dsd_getuser *adsp_user );
    ds_hstring m_get_sticket      ();
    bool       m_check_sticket    ( const char* achp_sticket, int inp_len );
    int        m_size_sticket     ();
    ds_hstring m_get_password     ();
    bool       m_check_password   ( const char* achp_pwd, int inp_len );
    hl_time_t  m_get_logintime        ();
    bool                 m_get_clientip( unsigned char uchrp_client_ineta[16] );
    dsd_aux_query_client m_get_client_ineta();
    int        m_pwd_expires();
    bool       m_set_pwd_expires( int inp_days );
    bool       m_reset_pwd_expires();

    // settings cma functions:
    int  m_get_lang();
    bool m_set_lang( int inp_lang );
    int  m_count_wsg_bookmarks  ();
    bool m_get_wsg_bookmark     ( int inp_index, ds_bookmark* adsp_bmark );
    bool m_get_wsg_bookmarks    ( ds_hvector<ds_bookmark>* adsp_bmarks );
    bool m_set_wsg_bookmarks    ( ds_hvector<ds_bookmark>* adsp_bmarks );
    bool m_set_own_wsg_bookmarks( ds_hvector<ds_bookmark>* adsp_bmarks );
    bool m_add_wsg_bookmark     ( ds_bookmark* adsp_bmark );

    int  m_count_rdvpn_bookmarks  ();
    bool m_get_rdvpn_bookmark     ( int inp_index, ds_bookmark* adsp_bmark );
    bool m_get_rdvpn_bookmarks    ( ds_hvector<ds_bookmark>* adsp_bmarks );
    bool m_set_rdvpn_bookmarks    ( ds_hvector<ds_bookmark>* adsp_bmarks );
    bool m_set_own_rdvpn_bookmarks( ds_hvector<ds_bookmark>* adsp_bmarks );


	bool m_jwtsa_set_configs	( ds_hvector<ds_jwtsa_conf>* adsp_configs );
	bool m_jwtsa_get_config		( int inp_index, ds_jwtsa_conf* adsp_jwtsa_config );
	int  m_jwtsa_count_configs  ();
#if BO_HOBTE_CONFIG
    bool m_hobte_set_configs	( ds_hvector<ds_hobte_conf>* adsp_configs );
	bool m_hobte_get_config		( int inp_index, ds_hobte_conf* adsp_hobte_config );
	int  m_hobte_count_configs  ();
#endif

    int  m_count_wfa_bookmarks  ();
    bool m_get_wfa_bookmark     ( int inp_index, dsd_wfa_bmark* adsp_bmark );
    bool m_get_wfa_bookmarks    ( ds_hvector<dsd_wfa_bmark>* adsp_bmarks );
    bool m_set_wfa_bookmarks    ( ds_hvector<dsd_wfa_bmark>* adsp_bmarks );
#if SM_USE_OWN_WFA_BOOKMARKS
    bool m_set_own_wfa_bookmarks( ds_hvector<dsd_wfa_bmark>* adsp_bmarks );
#endif
	bool m_add_wfa_bookmark     ( dsd_wfa_bmark* adsp_bmark );
    bool m_set_usr_msg( const char* achp_msg, int inp_length );
    bool m_get_usr_msg( ds_hstring* adsp_msg );
    int  m_count_workstations();
    bool m_get_workstation   ( int inp_index, ds_workstation* adsp_wstat );
    bool m_get_workstation   ( const char* achp_name, int inp_len, ds_workstation* adsp_wstat );
    bool m_get_workstations  ( ds_hvector<ds_workstation>* adsp_wstats );
    bool m_set_workstations  ( ds_hvector<ds_workstation>* adsp_wstats );
    bool m_get_cma_portlets ( ds_hvector<ds_portlet>* adsp_portlets );
    bool m_set_portlets     ( ds_hvector<ds_portlet>* adsp_portlets );
    bool m_show_flyer();
    bool m_set_flyer ( bool bop_show );
    bool m_set_default_portlet( const char* achp_default_portlet, int inp_length );
    bool m_get_default_portlet( ds_hstring* adsp_default_portlet );
    bool m_has_default_portlet( );

    // wsg cma functions:
    ds_hstring m_get_lastws  ( int *ainp_protocol, int *ainp_port );
    bool       m_set_lastws  ( int inp_protocol, const char *achp_lws, int inp_len, int inp_port );
    hl_time_t  m_get_sso_time( int inp_index );
    bool       m_set_sso_time( int inp_index, hl_time_t ilp_time );
    bool       m_set_ica_port( int inp_port );
    int        m_get_ica_port();
    bool       m_is_ica_active();
    bool       m_increase_ica_count();
    bool       m_decrease_ica_count();
    bool       m_reset_ica_count();

    // ineta cma functions:
    bool m_import_inetas( ds_hvector_btype<dsd_ineta_temp> *adsp_ppp_inetas, ds_hvector_btype<dsd_ineta_temp> *adsp_htcp_inetas );
    bool m_export_inetas( ds_hvector_btype<dsd_ineta_temp> *adsp_ppp_inetas, ds_hvector_btype<dsd_ineta_temp> *adsp_htcp_inetas );
    bool m_open_inetas  ( dsd_config_ineta_1 **aadsp_ppp_inetas, dsd_config_ineta_1 **aadsp_htcp_inetas );
    bool m_close_inetas ( dsd_config_ineta_1 **aadsp_ppp_inetas,  dsd_config_ineta_1 **aadsp_htcp_inetas );

    // role cma functions:
    bool m_delete_roles();
    bool m_add_roles   ( ds_hvector_btype<dsd_role*> *adsp_vroles );
    bool m_get_roles   ( ds_hvector_btype<dsd_role*> *adsp_vroles );
    bool m_is_in_list  ( const char *achp_role, int inp_len );

    // role functions:    
    void      m_select_role       ( dsd_role* adsp_role );
    dsd_role* m_get_role          ();
    bool      m_is_portlet_allowed( const char* achp_name, int inp_len );
    bool      m_is_caching_allowed();
    bool      m_is_config_allowed ( int inp_config );
    bool      m_get_role_name     ( const char **aachp_name,  int *ainp_len );
    bool      m_get_check         ( const char **aachp_name,  int *ainp_len );
    bool      m_get_welcomepage   ( const char **aachp_wpage, int *ainp_len );
    bool      m_get_gui_skin      ( const char **aachp_skin,  int *ainp_len );

    // portlet functions:
    bool m_get_portlets  ( ds_hvector<ds_portlet> *adsvp_portlets  );
    bool m_get_portlet   ( int inp_index, ds_portlet *adsp_portlet );
    int  m_count_portlets();


    // axss cma functions:
    hl_time_t m_get_axss_time();
    bool   m_set_axss_time( hl_time_t tmp_expires );

    // domain functions:
    void               m_select_domain( struct dsd_domain *adsp_domain );
    struct dsd_domain* m_get_domain   ();
    void               m_get_domain_admin( char **aachp_dn, int *ainp_len_dn, char **aachp_pwd, int *ainp_len_pwd );
    bool               m_auth_equals_config_ldap();
    bool               m_select_config_ldap();

    
    // static functions:
    static int  m_create_name     ( const char *achp_user, int inp_ulen, const char *achp_group, int inp_glen, const dsd_cma_session_no& chp_session, char *achp_buffer, int inp_blen );
    static int  m_get_name( const char *achp_main, int inp_mlen, char *achp_out, int inp_max_out,  const dsd_const_string& rdsp_suffix );
    static int  m_create_cma_name(const dsd_login_info& rdsp_login_info,
		 char* chrl_buffer, int inp_maxlen, const dsd_const_string& rdsp_suffix);
#if SM_USE_NEW_CMA_NAMES
	 static int m_exists_user     ( ds_wsp_helper *adsp_wsp_helper, const dsd_login_info& rdsp_login_info );
#else
	 static int m_exists_user     ( ds_wsp_helper *adsp_wsp_helper, const char *achp_cma, int inp_len );
#endif
	 static bool m_exists_same_user( ds_wsp_helper *adsp_wsp_helper, const char *achp_user, int inp_ulen, const char *achp_group, int inp_glen );
    static bool m_get_free_user   ( ds_wsp_helper *adsp_wsp_helper, const char *achp_user, int inp_ulen, const char *achp_group, int inp_glen,
		 dsd_cma_session_no* adsp_out);
    static int  m_get_all_users   ( ds_wsp_helper *adsp_wsp_helper, const char *achp_user, int inp_ulen, const char *achp_group, int inp_glen, dsd_cma_session_no* achp_sessions, int inp_max_sessions );
    static bool m_is_sticket      ( dsd_cma_session_no *achp_session, const char *achp_buffer, int inp_blen );
    static bool m_get_usercma     ( ds_wsp_helper *adsp_wsp_helper, ds_usercma *adsp_ucma );
	 static bool m_parse_cma_name(const dsd_const_string& rdsp_name, dsd_login_info& rdsp_out);
	 static bool m_is_user         ( const char *achp_cma, int inp_len );
    static bool m_get_user        ( ds_wsp_helper *adsp_wsp_helper, const char *achp_cma, int inp_len, struct dsd_getuser *adsp_user );
    static bool m_check_timeouts  ( ds_wsp_helper *adsp_wsp_helper, struct dsd_getuser *adsp_user );
    static bool m_get_login_info  ( ds_wsp_helper *adsp_wsp_helper, const char *achp_user, int inp_ulen, const char *achp_group, int inp_glen, const dsd_cma_session_no& chp_session, hl_time_t *ilp_login, dsd_aux_query_client* adsp_ineta );
private:
    // variables:
    class ds_wsp_helper     *adsc_wsp_helper;   // wsp helper class
    struct dsd_role         *adsc_srole;        // current role
    int                     inc_idle_timeout;   // idle timeout
    struct dsd_domain       *adsc_domain;       // selected domain

    // functions:
    bool m_set_names         ();
    bool m_update_retention  ();
    int  m_create_sticket    ( const dsd_cma_session_no& chp_session, char *achp_buffer, int inp_blen );
    bool m_merge_portlets    ( ds_hvector<ds_portlet> *adsvp_out );
    int  m_is_portlet_in_list( ds_hvector<ds_portlet> *adsvp_list, const char *achp_name, int inp_len );
    // main cma variables:
    void                    *avc_main;                  // cma handle
    struct dsd_usercma_main *adsc_main;                 // cma content
    char                    chrc_main[D_MAXCMA_NAME];   // cma name
    int                     inc_main;                   // length cma name

    // main cma functions:
    ds_wsp_helper::ied_cma_result m_create_main();
    bool m_open_main  ( bool bop_write );
    bool m_resize_main( int inp_size );
    bool m_close_main ();

    // login cma variables:
    void                        *avc_login;             // cma handle 
    struct dsd_usercma_login    *adsc_login;            // cma data
    char                        chrc_login[D_MAXCMA_NAME];  // cma name
    int                         inc_login;              // length cma name

    // login cma functions:
    bool m_create_login();
    bool m_open_login  ( bool bop_write );
    bool m_resize_login( int inp_size );
    bool m_close_login ();
    bool m_set_user    ( const char *achp_username, int inp_unlen, const char *achp_userdomain, int inp_urlen,
        const struct dsd_aux_ident_session_info* adsp_aux_ident_session_info, const char *achp_password, int inp_pwlen, const char *achp_userdn, int inp_dnlen,
        const char *achp_wspgroup, int inp_wglen, int inp_auth_method, enum ied_usercma_login_flags iep_auth_flags );

    // settings cma variables:
    void                        *avc_settings;          // cma handle
    struct dsd_usercma_settings *adsc_settings;         // cma data
    int                         inc_sclen;              // length of cma data
    char                        chrc_settings[D_MAXCMA_NAME];   // cma name
    int                         inc_settings;           // length cma name
    char                        *achc_sc_bac;           // backup data
    int                         inc_scbc_len;           // length of backup data

    // settings cma functions:
    bool m_create_settings();
    bool m_open_settings  ( bool bop_write );
    bool m_resize_settings( int inp_size );
    bool m_close_settings ();
    dsd_cma_wsg_bmark*   m_get_ws_bmark  ( int inp_index );
    dsd_cma_wfa_bmark*   m_get_wfa_bmark  ( int inp_index );
    dsd_cma_workstation* m_get_workstation( int inp_index );
    dsd_cma_portlet*     m_get_portlet    ( int inp_index );
	dsd_cma_jwtsaconf*	 m_jwtsa_get_config ( int inp_index );
#if BO_HOBTE_CONFIG
    dsd_cma_hobteconf*	 m_hobte_get_config ( int inp_index );
    bool                 m_open_te_settings(bool bop_write);
#endif
    bool m_get_ws_bookmark     ( enum ied_bookmark_type ienp_type, int inp_index, ds_bookmark* adsp_bmark );
    bool m_get_ws_bookmarks    ( enum ied_bookmark_type ienp_type, ds_hvector<ds_bookmark>* adsp_bmarks );
    bool m_set_ws_bookmarks    ( enum ied_bookmark_type ienp_type, ds_hvector<ds_bookmark>* adsp_bmarks, bool bop_keep_inherited );

    bool  m_create_backup( enum ied_usercma_settings ienp_type );
    bool  m_free_backup  ( enum ied_usercma_settings ienp_type );
    void* m_get_first_of ( enum ied_usercma_settings ienp_type );
    int   m_eval_size    ( enum ied_usercma_settings ienp_type, bool bop_only_inherited, int* ainp_inherited );

    // wsg cma variables:
    void                    *avc_wsg;                   // cma handle
    struct dsd_usercma_wsg  *adsc_wsg;                  // cma data
    char                    chrc_wsg[D_MAXCMA_NAME];    // cma name
    int                     inc_wsg;                    // length cma name

    // wsg cma functions:
    bool m_create_wsg ();
    bool m_open_wsg   ( bool bop_write );
    bool m_resize_wsg ( int inp_size );
    bool m_close_wsg  ();

    // ineta cma variables:
    void                        *avc_ineta;             // cma handle
    struct dsd_ineta_cma_data   *adsc_ineta;            // cma data
    char                        chrc_ineta[D_MAXCMA_NAME];  // cma name
    int                         inc_ineta;              // length cma name

    // ineta cma functions:
    bool m_open_ineta                       ( bool bop_write );
    bool m_close_ineta                      ();
    bool                m_fill_config_struct( int inp_inetas, int inp_memory, int inp_group );
    dsd_config_ineta_1* m_get_config_struct ( int inp_group );
    dsd_ineta_single_1* m_get_ineta         ( int inp_index, int inp_group );

    // roles cma variables:
    void *avc_roles;                        // cma handle
    char *achc_roles;                       // cma data
    int  inc_rclen;                         // length cma data
    char chrc_roles[D_MAXCMA_NAME];         // cma name
    int  inc_roles;                         // length cma name

    // roles cma functions:
    bool m_create_roles( int inp_len );
    bool m_open_roles  ( bool bop_write );
    bool m_resize_roles( int inp_size );
    bool m_close_roles ();

    // axss cma variables:
    void                    *avc_axss;                  // cma handle
    struct dsd_usercma_axss *adsc_axss;                 // cma data
    char                    chrc_axss[D_MAXCMA_NAME];   // cma name
    int                     inc_axss;                   // length cma name

    // axss cma functions:
    bool m_create_axss();
    bool m_open_axss  ( bool bop_write );
    bool m_resize_axss( int inp_size );
    bool m_close_axss ();

	/** hofmants: new CMA for encrypted pw **/
	/* TODO: dont write functions for every CMA, write general functions with parameters for all CMAs! */
	// encrypted pwcma variables
	void					*avc_pwcma_handle;
	char					chrc_pwcma_name[D_MAXCMA_NAME];
	int						inc_pwcma_namelen;
	void					*avc_pwcma_data;
	int						inc_pwcma_datalen;

	// encrypted pw cma functions
public:
    bool m_create_pwcma( const char *achp_username, int inp_unlen, const char *achp_userdomain, int inp_udlen, const char *achp_password, int inp_pwlen );
private:
    bool m_open_pwcma( bool bop_write );
	bool m_resize_pwcma( int inp_size );
	bool m_close_pwcma();
	/** hofmants end **/

    // static functions:
    static unsigned int m_build_cs( const char *achp_buf, int inp_blen );
    //static int          m_b64_len ( int inp_blen );    
    static bool         m_get_word( const dsd_const_string& rdsp_in, int *ainp_offset, dsd_const_string& rdsp_out );
    static bool         m_get_word( const char *achp_data, int inp_dlen, int *ainp_offset, const char **aachp_word, int *ainp_wlen );
	template<typename PRED> static bool m_iterate_sessions(
	 ds_wsp_helper *adsp_wsp_helper,
    const char *achp_user, int inp_ulen,
    const char *achp_group, int inp_glen,
	 PRED& rdsp_pred);

public:
	struct dsd_sso_info {
		void* achc_rdp_cred;
		int inc_rdp_cred_size;
		struct dsd_unicode_string dsc_client_domain;
		struct dsd_unicode_string dsc_client_userid;
		struct dsd_unicode_string dsc_client_password;
	};

	BOOL m_read_single_signon_credentials(struct dsd_sso_info& rdsp_sso_info);
	void m_clear_single_signon_credentials(struct dsd_sso_info& rdsp_sso_info);
};

#endif //_DEF_DS_USERCMA_H
