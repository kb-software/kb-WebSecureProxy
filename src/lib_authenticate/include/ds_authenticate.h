#ifndef DS_AUTHENTICATE_H
#define DS_AUTHENTICATE_H
/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_authenticate                                                       |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|   Michael Jakobs                                                        |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| =====                                                                   |*/
/*|   August 2009                                                           |*/
/*|                                                                         |*/
/*| VERSION:                                                                |*/
/*| ========                                                                |*/
/*|   0.9                                                                   |*/
/*|                                                                         |*/
/*| COPYRIGHT:                                                              |*/
/*| ==========                                                              |*/
/*|  HOB GmbH & Co. KG, Germany                                             |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/

#include <rdvpn_globals.h>

#define BO_HOBTE_CONFIG 1
#define BO_LDAP_USE_COLLECT_ATTRIBUTES 1 

/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/

/* --- settings --- */
#define JWTSA_STORAGE_SIZE		16384
#define JWTSA_ACTIVE			"activate"
#define JWTSA_YES				"yes"
#define JWTSA_NO				"no"
#define JWTSA_SESSION_LIST		"session-list"
#define JWTSA_SESSION_ENTRY		"session-entry"
/* --- --- --- */
#define HOBTE_STORAGE_SIZE  16384

#ifndef DEF_MAX_LEN_CMA_NAME        // wsp/include/hob-wspsu1.h
    #define D_MAXCMA_NAME 128
#else
    #define D_MAXCMA_NAME DEF_MAX_LEN_CMA_NAME
#endif
#ifndef LEN_INETA
    #define LEN_INETA           16
#endif // LEN_INETA

/*+-------------------------------------------------------------------------+*/
/*| forward defintions:                                                     |*/
/*+-------------------------------------------------------------------------+*/
class  ds_wsp_helper;
class  ds_hstring;
class  ds_bookmark;
class  ds_session_bm;
class  ds_xml;
class  ds_jwtsa_conf;
#if BO_HOBTE_CONFIG
    class ds_hobte_conf;
#endif
struct dsd_role;
struct dsd_ldap_attr;
struct dsd_xml_tag;
#if 0
struct dsd_usr_cnt_cma;
#endif
struct dsd_ineta_temp;
struct dsd_domain;
struct dsd_stor_sdh_1;
struct dsd_ldap_template;

#ifndef HL_UINT
    typedef unsigned int HL_UINT;
#endif

/*+-------------------------------------------------------------------------+*/
/*| admin return codes:                                                     |*/
/*+-------------------------------------------------------------------------+*/
#ifndef _DEF_ADMIN_RCODE
#define _DEF_ADMIN_RCODE
 enum ied_admin_rcode {
    ied_wspadmin_unset,                 //!< everything ok, no error
    ied_wspadmin_params,                //!< invalid parameters
    ied_wspadmin_end_of_file,           //!< end of file detected, means: not more data available
    ied_wspadmin_inv_request,           //!< invalid request
    ied_wspadmin_rec_unavailable,       //!< resource is unavailable
    ied_wspadmin_timeout,               //!< timeout while processing data
    ied_wspadmin_inv_cluster,           //!< invalid cluster selected
    ied_wspadmin_misc,                  //!< miscellaneous
    ied_wspadmin_unknown                //!< unknown error
};
#endif // _DEF_ADMIN_RCODE

/*+-------------------------------------------------------------------------+*/
/*| user info from ldap authentication:                                     |*/
/*+-------------------------------------------------------------------------+*/
 /*! \brief value of a ldap entry
 *
 * \ingroup authlib
 *
 *  Just holds a value and the length of the string
 *  TODO: replace this by dsd_unicode_string
 */
struct dsd_ldap_value {
    const char                  *achc_value;    /*!< value                     */
    int                         inc_len_value;  /*!< length of value           */
};
/*! \brief group dn entry
 *
 * 
 */
#define SH_NESTED_GROUPS
struct dsd_ldap_groups {
    const char                  *achc_dn;       /*!< group dn                  */
    int                         inc_len_dn;     /*!< length group dn           */
#ifdef SH_NESTED_GROUPS
	int                         inc_count_parents; /*!< number of groups this group is member of */
	dsd_ldap_groups             **ads_parents;   /* !< pointer to array of pointers to parent groups */
	BOOL                        boc_direct;     /* !< user is member of this group */
#endif
};

/*! \brief Authentication information from the LDAP
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_ldap_authinfo {
    BOOL                        boc_filled;     /*!< ldap info is usable       */
    struct dsd_ldap_template    *adsc_lconf;    /*!< ldap conf template        */
    const char                  *achc_basedn;   /*!< base dn of conf ldap      */
    int                         inc_len_basedn; /*!< length of base dn         */
    const char                  *achc_dn;       /*!< user dn                   */
    int                         inc_len_dn;     /*!< length of user dn         */
    struct dsd_ldap_attr_desc   *adsc_dn;       /*!< exploded user dn          */
    int                         inc_groups;     /*!< number of groups          */
    struct dsd_ldap_groups      *adsc_group_dns;/*!< group dns                 */
    struct dsd_ldap_attr_desc   *adsc_groups;   /*!< exploded group dns        */
    const char                  *achc_osid;     /*!< objectSid                 */
    int                         inc_len_osid;   /*!< length of objectSid       */
};

/*! \brief Configuration information from LDAP
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_ldap_confinfo {
    struct dsd_ldap_template    *adsc_lconf;    /*!< ldap conf template        */
    const char                  *achc_basedn;   /*!< base dn of conf ldap      */
    int                         inc_len_basedn; /*!< length of base dn         */
    const char                  *achc_dn;       /*!< user dn                   */
    int                         inc_len_dn;     /*!< length of user dn         */
    int                         inc_groups;     /*!< number of groups          */
    struct dsd_ldap_groups      *adsc_group_dns;/*!< group dns                 */
    int                         inc_tree;       /*!< number of tree dns        */
    struct dsd_ldap_groups      *adsc_tree_dns; /*!< tree dns                  */
};

/*! \brief Structure which contains dsd_ldap_authinfo and dsd_ldap_confinfo
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_ldap_userinfo {
    struct dsd_stor_sdh_1       dsc_stor;       /*!< storage container         */
    struct dsd_ldap_authinfo    dsc_auth;       /*!< infos from auth ldap      */
    struct dsd_ldap_confinfo    dsc_conf;       /*!< infos from conf ldap      */
};

enum ied_cert_auth_result {
    iec_cert_auth_result_not_checked = 0,
    iec_cert_auth_result_authenticated,
    iec_cert_auth_result_found,
    iec_cert_auth_result_not_found
};

/*+-------------------------------------------------------------------------+*/
/*| authentication calling structure:                                       |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief structure containing all authentication information
 *
 * \ingroup authlib
 *
 *  Details follow
 */
typedef struct dsd_authentication {
    /*
        input from calling application
    */
    const char              *achc_domain;           //!< users domain
    int                     inc_len_domain;         //!< length of users domain
    const char              *achc_user;             //!< user name
    int                     inc_len_user;           //!< length of user name
    const char              *achc_password;         //!< users password
    int                     inc_len_password;       //!< length of users password
    bool                    boc_avoid_compl_check;  //!< avoid compliance check
                                                    //!< is set to true from wspat, all other calling
                                                    //!< applications should use false!
#ifndef B20140805
    const char				*achc_firstpassword;    //!< store first password (in case of RADIUS challanges) for SSO
    int						inc_len_firstpassword;  //!< length of first password
#endif

	/*
        for changing password:
    */
    const char              *achc_old_pwd;          //!< old pwd (achc_password contains new pwd)
    int                     inc_len_old_pwd;        //!< length of old password

    /*
        output for calling application
    */
    class ds_usercma        *adsc_out_usr;          //!< output buffer user cma access class (filled if auth was successful)
    ds_hstring              *adsc_out_msg;          //!< output buffer for message (used in challenge)
    void                    *avc_usergroup;         //!< usergroup entry
    void                    *avc_userentry;         //!< user entry
    int                     inc_pw_expires;         //!< password expires in x days
    ds_hstring              *adsc_userdn;           //!< user dn for forced LDAP password change
	//char                    *ach_first_password;    //!< remember first password for sso
	 struct dsd_aux_ident_session_info dsc_aux_ident_session_info;

#if SM_USE_CERT_AUTH
    enum ied_cert_auth_result iec_certificate_auth;   //!< indicates authentication by client certificate (SSL)
	const struct dsd_certificate_auth_entry* adsc_cert_auth_entry;
#endif

    /*
        for both input and output:
    */
    ds_hstring              *adsc_state;            //!< state (used in challenge)
    int                     *ainc_conn_state;       //!< tcp connection state

    /*
        callback function:
    */
    void                    *avc_usrfield;          //!< userfield
    int (*amc_callback)(void*, int, void*, int);    //!< callback function

#if SM_USE_QUICK_LINK
    bool                    boc_force_session_id;   //!< avoid compliance check
                                                    //!< is set to true from wspat, all other calling
    int                     inc_session_id;
#endif                                                    //!< applications should use false!
} dsd_auth_t;

/*+-------------------------------------------------------------------------+*/
/*| authentication return codes:                                            |*/
/*+-------------------------------------------------------------------------+*/
/*
    idea authentication return codes:
    -> if authentication succeeds, result will be odd (%2 == 1)
    -> if authentication fails, result will be even   (%2 == 0)
    -> return value is an int:
        
        | 0   1 | 2   3   4   5   6   7 |
        +---|---|---|---|---|---|---|---+
        |       |                       |
        +-------|-----------------------+
        | error | bit-wise or-ed        |

        first two bytes:
            error code  - gives space for 256 error codes

        last 6 bytes:
            bit-wise or-ed status
            
        last byte: 1 = auth succeeded
                   0 = auth failed

*/
// authentication codes:
#define AUTH_NOT_SET            0x00000000      // return not set yet
#define AUTH_SUCCESS            0x00000001      // authentication successfull
#define AUTH_FAILED             0x00000002      // authentication failed

// selected authentication methods:
#define AUTH_METH_UNKNOWN       0x00000004      // unknown auth method
#define AUTH_METH_CMA           0x00000008      // auth against cma selected
#define AUTH_METH_RADIUS        0x00000010      // radius selected
#define AUTH_METH_DYN_RADIUS    0x00000020      // dynamic radius selected
#define AUTH_METH_USERLIST      0x00000040      // userlist selected
#define AUTH_METH_KRB5          0x00000080      // kerberos 5 selected
#define AUTH_METH_DYN_KRB5      0x00000100      // dynamic kerberos 5 selected       
#define AUTH_METH_LDAP          0x00000200      // ldap selected
#define AUTH_METH_DYN_LDAP      0x00000400      // dynamic ldap selected
#define AUTH_METH_CHALLENGE     0x00000800      // challenge method
#define AUTH_ROLE_SELECTED      0x00001000      // role already selected
#define AUTH_NO_ROLE_POSSIBLE   0x00002000      // no role for given user possible
#define AUTH_SETTINGS_SAVED     0x00004000      // user settings are saved
#define AUTH_COOKIES_SAVED      0x00008000      // user cookies are saved
#define AUTH_CHANGE_PWD         0x00010000      // user has to change his password
#define AUTH_METH_ANONYMOUS     0x00020000      // anonymous login
#define AUTH_METH_CERTIFICATE   0x00040000      // certificate authentication (SSL)
// free until                   0x00800000

// error codes (running backward):
#define AUTH_ERR_INTERNAL       0xFF000000      // internal error
#define AUTH_ERR_AUX            0xFE000000      // internal error
#define AUTH_ERR_INPUT          0xFD000000      // wrong input data
#define AUTH_ERR_USR            0xFC000000      // invalid user
#define AUTH_ERR_PWD            0xFB000000      // invalid password
#define AUTH_ERR_STICKET        0xFA000000      // invalid session ticket
#define AUTH_ERR_CTXT           0xF9000000      // invalid context
#define AUTH_ERR_SID            0xF8000000      // invalid sessionid
#define AUTH_ERR_EXPIRED        0xF7000000      // max lifetime expired
#define AUTH_ERR_STATE          0xF6000000      // wrong state set
#define AUTH_ERR_INV_PARAMS     0xF5000000      // invalid parameters
#define AUTH_ERR_INV_RESP       0xF4000000      // invalid response
#define AUTH_ERR_REJECT         0xF3000000      // login rejected
#define AUTH_ERR_CMA_CREATE     0xF3000000      // error while creating cma
#define AUTH_ERR_INV_CTXT_TYPE  0xF2000000      // invalid context authentication type
#define AUTH_ERR_AUTH_TYPE      0xF1000000      // cannot find a valid auth method
#define AUTH_ERR_VERSION        0xF0000000      // unknown cma version detected
#define AUTH_ERR_CLIENTIP       0xEF000000      // saved clientip and incoming are not equal
#define AUTH_INV_USERDN         0xEE000000      // invalid userdn
#define AUTH_SAME_USER          0xED000000      // same user tries a second login
#define AUTH_KICKED_OUT         0xEC000000      // user seems to be kicket out by another on
#define AUTH_KRB5_NOKDC_CONF    0xEB000000      // KDC not configured
#define AUTH_KRB5_NOKDC_SEL     0xEA000000      // KDC not selected
#define AUTH_KRB5_NO_SESS       0xE9000000      // session not signed on
#define AUTH_KRB5_KDC_INV       0xE8000000      // KDC invalid
#define AUTH_KRB5_NO_TGT        0xE7000000      // TGT not found
#define AUTH_KRB5_MISC          0xE6000000      // miscellaneous error
#define AUTH_ERR_DYN_SEL        0xE5000000      // dynamic select server failed
#define AUTH_ERR_AXSS_EXPIRED   0xE4000000      // axss has expired
#define AUTH_ERR_NO_SUPPORTED   0xE3000000      // not supported
#define AUTH_ERR_OTHER_PORT     0xE2000000      // wrong listen port

#define AUTH_ERR_LDAP_UNWILL_TO_PERFORM		0xE1000000	// ldap unwilling to perform
#define AUTH_ERR_LDAP_INV_CRED				0xDF000000	// ldap invalid credentials
// free until                   0x01000000

/*+-------------------------------------------------------------------------+*/
/*| tcp connection states:                                                  |*/
/*+-------------------------------------------------------------------------+*/
#define DEF_CONN_STAT_IDENTIFIED    0x00000001
#define DEF_CONN_STAT_CONFIGURED    0x00000002

/*+-------------------------------------------------------------------------+*/
/*| user overview structures:                                               |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief query information for a LDAP user search
 *
 * \ingroup authlib
 *
 *  Details follow
 */
typedef struct dsd_q_user_overview {
    int         inc_last_user;      //!< user number last before (start with next)
    int         inc_receive;        //!< number of records to be received
    const char* achc_search_user;   //!< search user
    int         inc_len_user;       //!< length of user search word
    const char* achc_search_domain; //!< search domain
    int         inc_len_domain;     //!< length of domain search word
    bool        boc_use_wildcard;   //!< use wildcard in search
} dsd_query_uov_t;

struct dsd_getuser;

/*! \brief User overview structure
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_user_overview {
    int                       inc_number;       //!< number of user
    struct dsd_getuser        ds_user;          //!< get user structure
    struct dsd_user_overview* ads_next;         //!< next user
};

/*+-------------------------------------------------------------------------+*/
/*| used ldap attributes:                                                   |*/
/*+-------------------------------------------------------------------------+*/
#define DEF_ATTR_USET_WSG_BMARKS "hobrdvpnbmwsg"    // wsg bookmarks
#define DEF_ATTR_USET_RDVPN_BMARKS "hobrdvpnbmrdvpn"  // rdvpn bookmarks
#define DEF_ATTR_USET_WFA_BMARKS "hobrdvpnbmwfa"    // wfa bookmarks
#define DEF_ATTR_USET_DOD        "hobrdvpndod"      // desktop-on-demand
#define DEF_ATTR_USET_OTHERS     "hobrdvpnuser"     // other user settings
#define DEF_ATTR_USET_HTCP       "hobrdvpnpi"       // personal IPs
#define DEF_ATTR_USR_COOKIES     "hobcookies"       // user cookies attribute
#define DEF_ATTR_USR_MSG         "hobrdvpnmsg"      // user message
#define DEF_ATTR_USR_STAT        "hobuserhistory"   // user statistics
#define DEF_ATTR_JWT_CONFIG		 "hobjwtsa"			// config for jwt standalone as webstart
#define DEF_ATTR_HOBTE_CONFIG    "hobhobte"         // JTerm config - for use with Webterm

/*+-------------------------------------------------------------------------+*/
/*| version number per ldap attribute:                                      |*/
/*+-------------------------------------------------------------------------+*/
#define DEF_VERS_USET_WSG_BMARKS 1                  // wsg and rdvpn bookmarks
#define DEF_VERS_USET_WFA_BMARKS 1                  // wfa bookmarks
#define DEF_VERS_USET_DOD        1                  // desktop-on-demand
#define DEF_VERS_USET_OTHERS     2                  // other user settings
#define DEF_VERS_USET_HTCP       1                  // personal IPs
#define DEF_VERS_USR_COOKIES     1                  // user cookies attribute
#define DEF_VERS_USR_MSG         1                  // user message

/*+-------------------------------------------------------------------------+*/
/*| usersetting xml tags:                                                   |*/
/*+-------------------------------------------------------------------------+*/
static const dsd_const_string achg_us_tags[] = {
    "user-settings",
    "version",
    "WSG-bookmarks",
    "RDVPN-bookmarks",
    "WFA-bookmarks",
    "message",
    "msg",
    "desktop-on-demand",
    "others",
    "language",
    "flyer",
    "default-portlet",
    "portlets",
    "htcp",
    "tunnel-endpoints",
    "tunnel-endpoint",
    "applications",
    "application",
    "ineta"
};

enum ied_us_tags {
    ied_us_tag_usr_sett,
    ied_us_tag_version,
    ied_us_tag_wsg_bm,
    ied_us_tag_rdvpn_bm,
    ied_us_tag_wfa_bm,
    ied_us_tag_message,
    ied_us_tag_usr_msg,
    ied_us_tag_dod,
    ied_us_tag_others,
    ied_us_tag_lang,
    ied_us_tag_flyer,
    ied_us_tag_default_portlet,
    ied_us_tag_portlets,
    ied_us_tag_htcp,
    ied_us_tag_tnl_endpoints,
    ied_us_tag_tnl_endpoint,
    ied_us_tag_applications,
    ied_us_tag_appl,
    ied_us_tag_ineta
};

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief Base class which holds all information
 *         about the authentication process
 *
 * \ingroup authlib
 *
 *  Details follow
 */
class ds_authenticate {
public:
    // constructor/destructor:
    ds_authenticate( ds_wsp_helper* ads_wsp_helper );
    ds_authenticate();
    ~ds_authenticate();
    void m_init( ds_wsp_helper* ads_wsp_helper );

    // authenication methods:
    bool m_check_certificate_auth( const struct dsd_wspat_public_config *adsp_wspat_conf, dsd_auth_t *adsp_auth );
    HL_UINT m_authenticate( dsd_auth_t *adsp_auth );
    HL_UINT m_auth_session( dsd_auth_t *adsp_auth );
    bool    m_end_session ( dsd_auth_t *adsp_auth );

    // create user WITHOUT auth:
    HL_UINT m_create_user ( dsd_auth_t *adsp_auth );

    // change user password without auth and without cma creation:
    HL_UINT m_change_password( dsd_auth_t *adsp_auth );

    // save usersettings method:
    bool    m_save_settings( dsd_auth_t* ads_auth );

    // userlist methods:
    dsd_user_overview*   m_get_userov   ( dsd_query_uov_t* ads_query );
    void                 m_free_userov  ();
    int                  m_count_users  ( dsd_query_uov_t* ads_query );
    enum ied_admin_rcode m_get_userov_rc();

private:
    // variable:
    ds_wsp_helper*           adsc_wsp_helper;
    int                      inc_sel_srv;
    dsd_user_overview*       adsc_userov;
    enum ied_admin_rcode     ienc_adm_ret_code;
    char                     chrc_al_name[D_MAXCMA_NAME];
    struct dsd_ldap_userinfo dsc_authinfo;          /* information about
                                                       user from ldad bind */

	struct dsd_stor_sdh_1	 dsc_stor_jwtsa;		/* storage container         */

    // auth functions:
    ds_wsp_helper::ied_cma_result    m_create_usr_cma( dsd_auth_t *adsp_auth, const dsd_cma_session_no& chp_session, int inp_domain_auth,
        enum ied_usercma_login_flags iep_auth_flags, dsd_role *adsp_selected, struct dsd_domain *adsp_domain );
    int     m_get_domain_auth( dsd_auth_t *adsp_auth, int inp_wsp_auth, struct dsd_wspat_public_config *adsp_wspat_conf, struct dsd_domain **aadsp_domain );
    HL_UINT m_do_ext_auth   ( dsd_auth_t *adsp_auth, int inp_wsp_auth, int inp_domain_auth, struct dsd_domain *adsp_domain );
    HL_UINT m_auth_radius   ( dsd_auth_t *adsp_auth );
    HL_UINT m_auth_dyn_radius( dsd_auth_t *adsp_auth );
    HL_UINT m_auth_userlist ( dsd_auth_t* ads_auth );
    HL_UINT m_auth_krb5     ( dsd_auth_t* ads_auth, struct dsd_domain *adsp_domain );
    HL_UINT m_auth_dyn_krb5 ( dsd_auth_t* ads_auth, struct dsd_domain *adsp_domain );
    HL_UINT m_auth_ldap     ( dsd_auth_t* adsp_auth, struct dsd_domain *adsp_domain );
    HL_UINT m_auth_dyn_ldap ( dsd_auth_t* ads_auth, struct dsd_domain *adsp_domain );
    HL_UINT m_auth_cma      ( dsd_auth_t *adsp_auth, const dsd_cma_session_no& chp_session, struct dsd_wspat_public_config *adsp_wspat_conf, struct dsd_domain *adsp_domain );
    void    m_set_ident     ( dsd_auth_t *adsp_auth, struct dsd_domain *adsp_domain );
    bool    m_read_rad_attr ( char* ach_rad_attr, int in_len_attr, int in_search, ds_hstring* ads_out );
    HL_UINT m_auth_single   ( dsd_auth_t *adsp_auth, int inp_wsp_auth, int inp_domain_auth, struct dsd_wspat_public_config *adsp_wspat_conf, struct dsd_domain *adsp_domain );
    HL_UINT m_auth_multiple ( dsd_auth_t *adsp_auth, int inp_wsp_auth, int inp_domain_auth, struct dsd_wspat_public_config *adsp_wspat_conf, struct dsd_domain *adsp_domain );
    bool    m_init_user     ( dsd_auth_t *adsp_auth, dsd_cma_session_no *achp_session, int inp_domain_auth, struct dsd_wspat_public_config* adsp_wspat_conf, HL_UINT *ainp_auth, bool bop_multiple, enum ied_usercma_login_flags iep_auth_flags, struct dsd_domain *adsp_domain );
    void    m_finish_auth   ( dsd_auth_t *adsp_auth, struct dsd_wspat_public_config* adsp_wspat_conf, HL_UINT uinp_auth, struct dsd_domain *adsp_domain );

    // change password functions:
    HL_UINT m_change_ext_pwd( dsd_auth_t *adsp_auth, int inp_wsp_auth, int inp_domain_auth, struct dsd_domain *adsp_domain );
    HL_UINT m_chpwd_ldap    ( dsd_auth_t *adsp_auth, struct dsd_domain *adsp_domain );
    HL_UINT m_chpwd_dyn_ldap( dsd_auth_t *adsp_auth, struct dsd_domain *adsp_domain );
	HL_UINT m_chpwd_dyn_radius( dsd_auth_t *adsp_auth, struct dsd_domain *adsp_domain );

    // anonymous login functions:
    bool    m_is_anonymous  ( dsd_auth_t *adsp_auth, struct dsd_wspat_public_config *adsp_wspat_conf );
    HL_UINT m_auth_anonymous( dsd_auth_t *adsp_auth, int inp_wsp_auth, int *ainp_domain_auth, struct dsd_wspat_public_config *adsp_wspat_conf );

    // role functions:
    //bool      m_select_role       ( dsd_auth_t *adsp_auth, struct dsd_wspat_public_config *adsp_wspat_conf );
    dsd_role* m_get_role_by_name  ( dsd_auth_t *adsp_auth, struct dsd_wspat_public_config *adsp_wspat_conf );
    bool      m_get_possible_roles( dsd_auth_t *adsp_auth, struct dsd_wspat_public_config *adsp_wspat_conf, HL_UINT *auinp_ret, dsd_role **aadsp_selected, struct dsd_domain *adsp_domain );
    bool      m_is_role_for_user  ( dsd_auth_t* adsp_auth, dsd_role* adsp_role, const struct dsd_domain *adsp_domain );
    bool      m_config_session    ( dsd_auth_t* ads_auth );

    void m_free_userov  ( dsd_user_overview* ads_uov );
    void m_print_err_msg( HL_UINT uin_auth, dsd_auth_t* adsp_auth, struct dsd_domain *adsp_domain );

    // ldap stuff:
    bool m_switch_ldap       ( dsd_auth_t *adsp_auth, struct dsd_domain *adsp_domain, int inp_domain_auth, int inp_wsp_auth );
    bool m_select_ldap       ( struct dsd_domain *adsp_domain, int inp_domain_auth, int inp_wsp_auth );
    void m_close_ldap        ();
    bool m_bind_conf_ldap    ( struct dsd_domain *adsp_domain );
    bool m_get_conf_sysinfo  ();
    bool m_clone_dn          ( struct dsd_stor_sdh_1 *adsp_stor, struct dsd_ldap_attr_desc *adsp_exploded, enum ied_objectclass iep_objectclass, char **aachp_ndn, int *ainp_len_ndn, struct dsd_domain *adsp_domain );
    bool m_clone_ext_user    ( struct dsd_stor_sdh_1 *adsp_stor, const char *achp_user, int inp_len_user, char **aachp_ndn, int *ainp_len_ndn, struct dsd_domain *adsp_domain );
    bool m_search_user       ( struct dsd_stor_sdh_1 *adsp_stor, const char *achp_name, int inp_len_name, char **aachp_ndn, int *ainp_len_ndn, struct dsd_domain *adsp_domain );
    bool m_search_by_sid     ( struct dsd_stor_sdh_1 *adsp_stor, const char *achp_sid, int inp_len_sid, char **aachp_ndn, int *ainp_len_ndn, char **aachp_name, int *ainp_len_name, struct dsd_domain *adsp_domain );
    bool m_set_attribute     ( const char *achp_dn, int inp_len_dn, const char *achp_attr, int inp_len_attr, const char *achp_value, int inp_len_val );
    bool m_del_attribute     ( const char *achp_dn, int inp_len_dn, const char *achp_attr, int inp_len_attr, const char *achp_value, int inp_len_val );
    bool m_add_member        ( const char *achp_user, int inp_len_user, const char *achp_group, int inp_len_group, const char *achp_mship_attr, int inp_len_mship_attr );
    bool m_insert_objectclass( const char *achp_oclass, const char *achp_dn, int inp_length );
    bool m_collect_attribute ( struct dsd_stor_sdh_1 *adsp_stor, const char *achp_attr, int inp_len_attr, struct dsd_ldap_value **aadsp_own, int *ainp_group, struct dsd_ldap_value **aadsp_group, int *ainp_tree,  struct dsd_ldap_value **aadsp_tree );
    struct dsd_ldap_val*       m_get_attribute ( const char *achp_dn, int inp_len_dn, const char *achp_attr, int inp_len_attr );
    struct dsd_ldap_groups*    m_clone_groups  ( struct dsd_stor_sdh_1 *adsp_stor, int inp_groups, struct dsd_ldap_attr_desc *adsp_expl_grps, struct dsd_ldap_groups *adsp_dn_grps, int *ainp_created, struct dsd_domain *adsp_domain );
#ifdef SH_NESTED_GROUPS
    struct dsd_ldap_groups*    m_search_groups ( struct dsd_stor_sdh_1 *adsp_stor, struct dsd_domain *adsp_domain, struct dsd_ldap_template *adsp_conf, const char *achp_dn, int inp_len_dn, const char *achp_base, int inp_len_base, int *ainp_groups, dsd_ldap_groups* adsp_group_dns, int inp_groups);
#else
    struct dsd_ldap_groups*    m_search_groups ( struct dsd_stor_sdh_1 *adsp_stor, struct dsd_domain *adsp_domain, struct dsd_ldap_template *adsp_conf, const char *achp_dn, int inp_len_dn, const char *achp_base, int inp_len_base, int *ainp_groups );
#endif
    struct dsd_ldap_groups*    m_get_tree_dns  ( struct dsd_stor_sdh_1 *adsp_stor, const char *achp_dn, int inp_len_dn, int *ainp_tree );
    struct dsd_ldap_attr_desc* m_explode_dn    ( struct dsd_stor_sdh_1 *adsp_stor, const char *achp_dn, int inp_length );
    struct dsd_ldap_attr_desc* m_explode_groups( struct dsd_stor_sdh_1 *adsp_stor, struct dsd_ldap_attr *adsp_groups, int  inp_count );
    struct dsd_ldap_attr_desc* m_explode_groups( struct dsd_stor_sdh_1 *adsp_stor, struct dsd_ldap_groups *adsp_groups, int inp_count );
    struct dsd_ldap_groups*    m_get_group_dns ( struct dsd_stor_sdh_1 *adsp_stor, struct dsd_ldap_attr *adsp_groups, int *ainp_count );
    struct dsd_ldap_attr*      m_get_groups    ( struct dsd_ldap_attr *adsp_lattr, const char *achp_mship_attr, int inp_len_mship_attr );
    struct dsd_ldap_attr*      m_get_objectsid ( struct dsd_ldap_attr *adsp_lattr );
#ifndef SH_NESTED_GROUPS
    bool  m_equals_ic( const char *achp_buf1, const char *achp_buf2, int inp_length );
#endif
	// jwtsa config ldap stuff:
	struct dsd_ldap_val*		m_jwtsa_save_groups		( struct dsd_co_ldap_1 *adsp_co_ldap );
	bool						m_jwtsa_find_configs	( dsd_auth_t* adsp_auth );
	bool						m_jwtsa_read_config		( const char *achp_dn, int inp_len_dn, ds_hvector<ds_jwtsa_conf> *adsp_configs );
	bool						m_jwtsa_config_active	( dsd_xml_tag* adsp_pnode );
#if BO_HOBTE_CONFIG
    struct dsd_stor_sdh_1	    dsc_stor_hobte;		/* storage container         */
    struct dsd_ldap_val*		m_hobte_save_groups		( struct dsd_co_ldap_1 *adsp_co_ldap );
	bool						m_hobte_find_configs	( dsd_auth_t* adsp_auth );
	bool						m_hobte_read_config		( const char *achp_dn, int inp_len_dn, ds_hvector<ds_hobte_conf> *adsp_configs );
#endif

    // user settings functions:
    bool m_prepare_ldap      ( dsd_auth_t* adsp_auth, dsd_getuser *adsp_user );
    bool m_get_user_settings ( dsd_auth_t *adsp_auth );
    bool m_save_user_settings( dsd_auth_t* ads_auth, dsd_getuser* ads_user );
    bool         m_import_ws_bmarks  ( enum ied_bookmark_type ienp_type, dsd_auth_t *adsp_auth, struct dsd_ldap_value *adsp_own, int inp_groups, struct dsd_ldap_value *adsp_group, int inp_tree, struct dsd_ldap_value *adsp_tree );
    bool         m_import_wfa_bmarks ( dsd_auth_t *adsp_auth, struct dsd_ldap_value *adsp_own, int inp_groups, struct dsd_ldap_value *adsp_group, int inp_tree, struct dsd_ldap_value *adsp_tree );
    dsd_xml_tag* m_check_ws_bmarks   ( enum ied_bookmark_type ienp_type, ds_xml* adsp_parser, const char* achp_xml, int inp_len_xml );
    dsd_xml_tag* m_check_wfa_bmarks  ( ds_xml* adsp_parser, const char* achp_xml, int inp_len_xml );
    void         m_read_ws_bmarks    ( enum ied_bookmark_type ienp_type, bool bop_own, dsd_xml_tag* adsp_node, ds_hvector<ds_bookmark>   *adsp_out );
    void         m_read_wfa_bmarks   ( bool bop_own, dsd_xml_tag* adsp_node, ds_hvector<dsd_wfa_bmark> *adsp_out );
    bool         m_import_usr_msg    ( dsd_auth_t *adsp_auth, struct dsd_ldap_value *adsp_own, int inp_groups, struct dsd_ldap_value *adsp_group, int inp_tree, struct dsd_ldap_value *adsp_tree );
    dsd_xml_tag* m_check_usr_msg     ( ds_xml* adsp_parser, const char* achp_xml, int inp_len_xml );
    bool         m_import_dod        ( dsd_auth_t *adsp_auth, struct dsd_ldap_val *adsp_own );
    bool         m_import_htcp       ( dsd_auth_t *adsp_auth, struct dsd_ldap_val *adsp_own );
    void         m_read_ineta        ( dsd_xml_tag* ads_pnode, ds_hvector_btype<dsd_ineta_temp>* ads_out );
    bool         m_parse_ineta       ( const char* ach_ineta, int in_length, dsd_ineta_temp* ads_ineta );
    bool         m_import_others     ( dsd_auth_t *adsp_auth, struct dsd_ldap_val *adsp_own );
    inline bool  m_equals            ( enum ied_us_tags ien_tag, const char* ach_compare, int in_len_comp );
    bool         m_create_default_tree_rdn ( dsd_auth_t *adsp_auth, struct dsd_domain *adsp_domain, const dsd_const_string& dsp_config_base );
    bool         m_create_default_group ( struct dsd_domain *adsp_domain, const dsd_const_string& dsp_config_base );
    void         m_set_domainadmin_group( const dsd_const_string& dsp_config_base);

    // user cookie functions:
    bool m_get_user_cookies ( dsd_auth_t* ads_auth );
    bool m_save_user_cookies( dsd_auth_t* ads_auth, dsd_getuser* ads_user );

#if 0
    // count user functions:
    void m_increase_usr_cnt( dsd_usr_cnt_cma* ads_out );
    void m_decrease_usr_cnt( dsd_usr_cnt_cma* ads_out );
#endif

    // user overview search:
    bool m_search( struct dsd_getuser* adsp_user, dsd_query_uov_t* adsp_query );

    // save ldap information:
    bool m_save_ldap_info( struct dsd_co_ldap_1 *adsp_ldap_cm );
};

#endif // DS_AUTHENTICATE_H
