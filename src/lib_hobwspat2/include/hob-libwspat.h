#ifndef XWSPAT_H
#define XWSPAT_H
/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| PROGRAM:                                                            |*/
/*| ========                                                            |*/
/*|   hobwspat                                                          |*/
/*|                                                                     |*/
/*| DESCRIPTION:                                                        |*/
/*| ============                                                        |*/
/*|   this is a complete rewrite of KBs authentication library          |*/
/*|                                                                     |*/
/*| DATE:                                                               |*/
/*| =====                                                               |*/
/*|   June 2009                                                         |*/
/*|                                                                     |*/
/*| AUTHOR:                                                             |*/
/*| =======                                                             |*/
/*|   Michael Jakobs                                                    |*/
/*|                                                                     |*/
/*| COPYRIGHT:                                                          |*/
/*| ==========                                                          |*/
/*|   HOB GmbH Germany 2009                                             |*/
/*|   HOB GmbH Germany 2010                                             |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

#include <rdvpn_globals.h>

/*+---------------------------------------------------------------------+*/
/*| allowed configuration defines:                                      |*/
/*+---------------------------------------------------------------------+*/
#define DEF_UAC_WSG_BMARKS       1
#define DEF_UAC_WFA_BMARKS       2
#define DEF_UAC_DOD              4
#define DEF_UAC_OTHERS           8
#define DEF_UAC_RDVPN_BMARKS    16
#define DEF_UAC_WSG_INPUT       32

/*+---------------------------------------------------------------------+*/
/*| default expires password warning in days:                           |*/
/*+---------------------------------------------------------------------+*/
#define DEF_DONT_EXPIRE        -1
#define DEF_LIMIT_EXPIRES_DAYS  8

/*+---------------------------------------------------------------------+*/
/*| public configuration structure members:                             |*/
/*+---------------------------------------------------------------------+*/
struct dsd_aux_conf_servli_1;

struct dsd_time_limits {
    int in_max_period;
    int in_idle_period;
};

struct dsd_domain {
    int               inc_auth_type;        // authentication type
    char              *achc_name;           // pointer to domain name
    int               inc_len_name;         // length of name
    char              *achc_disp_name;      // display name
    int               inc_len_disp_name;    // length of display name
    char              *achc_base;           // additional base dn
    int               inc_len_base;         // length of additional base
    char              *achc_ldap;           // corresponding LDAP server
    int               inc_len_ldap;         // length of LDAP server
    char              *achc_dn_admin;       // domain admin search user
    int               inc_len_dn_admin;     // length of domain admin
    char              *achc_pwd_admin;      // password domain admin
    int               inc_len_pwd_admin;    // lengtof of password
    char              *achc_admin_group;    // administrator group
    int               inc_len_admin_group;  // length of adminstrator group
    char              *achc_tree_rdn_group; // tree rdn group where to autocreate new users
    int               inc_len_tree_rdn_group; // lenght of tree rdn group
    char              *achc_default_group;  // group which new creared users belong to
    int               inc_len_default_group; // length of default group
    bool              boc_search_base;      // authentication search with add base (case of LDAP)
    bool              boc_create_users;     // auto create users config ldap
    bool              boc_ldap_eq_name;     // corresponding ldap and name are equal
	bool			  boc_default_enabled;	// default domain
    struct dsd_domain *adsc_next;           // next domain
};

struct dsd_domains {
    bool              boc_show_list;        // show domain list at login?
	int               inc_num_domains;      // Number of domains in list
    struct dsd_domain *adsc_domain;         // list of domains (v2)
};

enum ied_role_member {
    ied_role_mem_unknown = -1,
    ied_role_mem_dn,                        // userdn
    ied_role_mem_group,                     // usergroup
    ied_role_mem_ou,                        // organisation unit
    ied_role_mem_name                       // username
};

struct dsd_role_member {
    ied_role_member  ienc_type;             // member type
    char*            achc_name;             // member name
    int              inc_len_name;          // length of member name
    dsd_role_member* adsc_next;             // next member
};

struct dsd_role_portlet {
    char*             achc_name;            // portlet name
    int               inc_len_name;         // length of portlet name
    bool              bo_open;              // portlet open?
    dsd_role_portlet* adsc_next;            // next porlet
};

struct dsd_role_list {
    char*           achc_entry;             // entry itself
    int             inc_len_entry;          // length of entry
    dsd_role_list*  adsc_next;              // next entry
};

struct dsd_role {
    char                    *achc_name;             // role name
    int                     inc_len_name;           // length of role name
    int                     inc_priority;           // priority
	bool					boc_high_entropy;		// should jwtsa generate a high entropy for this user?
	bool					boc_login_cookie;		// should we set a login cookie?
    char                    *achc_check;            // name of required check
    int                     inc_len_check;          // length of check name
    char                    *achc_wpage;             // welcome page (site after auth)
    int                     inc_len_wpage;          // length of welcome page
    bool                    boc_enable_bcache;      // enable browser caching (for wsg)
    bool                    boc_require_cert;       // certificate required
    int                     inc_allowed_conf;       // allowed configuration
    dsd_time_limits         dsc_time_limits;        // role time limit structure
    char                    *achc_target_filter;    // target filter
    int                     inc_len_target_filter;  // length of target filter
    dsd_aux_conf_servli_1   *adsc_srv_list;         // wsp server lists
    dsd_aux_conf_servli_1   *adsc_ws_srv_list;      // webserver server lists
    char                    *achc_skin;             // gui skin
    int                     inc_len_skin;           // length of gui skin
    dsd_role_list           *adsc_domains;          // domain list
    dsd_role_member         *adsc_members;          // role members
    dsd_role_portlet        *adsc_portlets;         // role portlets
    dsd_role                *adsc_next;             // next role
};

struct dsd_anonymous_login {
    bool                    boc_enabled;            // anonymous login enabled?
    char*                   achc_mp_user;           // mapped user
    int                     inc_len_user;           // length of mapped user
    char*                   achc_mp_domain;         // mapped domain
    int                     inc_len_domain;         // length of mapped domain
};

#if SM_USE_CERT_AUTH
struct dsd_utf8_string
{
    char* achc_data;
    int inc_len;
};

struct dsd_certificate_auth_entry {
    struct dsd_certificate_auth_entry* adsc_next;
    char chrc_sha1_hash[20];
    dsd_utf8_string dsc_user;            // name of required check
    dsd_utf8_string dsc_domain;          // name of required check
#if SM_USE_CERT_AUTH_V2
    enum ied_troolean iec_password_auth;
    dsd_utf8_string dsc_password;        // password for SSO
#endif
};

struct dsd_certificate_auth {
    BOOL boc_enabled;
    struct dsd_certificate_auth_entry* adsc_entries;
#if SM_USE_CERT_AUTH_V2
    BOOL boc_password_auth;
#endif
};
#endif

/*+---------------------------------------------------------------------+*/
/*| public configuration structure:                                     |*/
/*+---------------------------------------------------------------------+*/
typedef struct dsd_wspat_public_config {
    bool                boc_check_cl_ineta; // check client ip with cookie
    bool                boc_end_sessions;   // close all user session at logout
    bool                boc_multiple_login; // multiple login allowed
    int                 inc_pwd_expires;    // expires warning in days
    struct dsd_domains  dsc_domains;        // domain configuration
    dsd_role*           adsc_roles;         // roles list
    dsd_anonymous_login dsc_anonymous;      // anonymous user login
#if SM_USE_CERT_AUTH
    struct dsd_certificate_auth dsc_certificate_auth;
#endif
} dsd_wspat_pconf_t;


/*+---------------------------------------------------------------------+*/
/*| default configuration values:                                       |*/
/*+---------------------------------------------------------------------+*/
#define AT_DEF_MAX_PERIOD  28800       // 8 hours in seconds
#define AT_DEF_IDLE_PERIOD  1800       // 30 minutes in seconds

/*+---------------------------------------------------------------------+*/
/*| anonymous loginname:                                                |*/
/*+---------------------------------------------------------------------+*/
#define DEF_ANONYMOUS_USER "anonymous"

/*+---------------------------------------------------------------------+*/
/*| function declarations:                                              |*/
/*+---------------------------------------------------------------------+*/
#ifdef HL_UNIX
    #ifndef BOOL
        #define BOOL int
    #endif
#endif

/**
 * function m_wspat3_config_in
 * entry point for configuration call
 *
 * @param[in]   dsd_hl_clib_dom_conf*
 * @return      BOOL                        TRUE = success
*/
BOOL m_wspat3_config_in( struct dsd_hl_clib_dom_conf* );


/**
 * function m_wspat3_proc_in
 * entry point for work call
 *
 * @param[in]   dsd_wspat3_1*
*/
void m_wspat3_proc_in( struct dsd_wspat3_1* );

#endif  // XWSPAT_H
