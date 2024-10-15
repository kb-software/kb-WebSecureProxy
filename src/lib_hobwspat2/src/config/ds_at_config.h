#ifndef _DS_CONFIG_H
#define _DS_CONFIG_H
/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| ========                                                            |*/
/*|   ds_at_config                                                      |*/
/*|   read sdh configuration from wsp.xml file and save it in conf      |*/
/*|   pointer                                                           |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| =======                                                             |*/
/*|   Michael Jakobs, 2009/02/06                                        |*/
/*|                                                                     |*/
/*| Copyright:                                                          |*/
/*| ==========                                                          |*/
/*|   HOB GmbH Germany 2009                                             |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
/*
  KB advised me not to use malloc( or better DEF_AUX_MEMGET ) in read 
  config functions, because getting memory is soooo slow.
  He suggested to use a buffer from stack with 16KB or 32KB.
*/
#define AT_CONF_MAX       768*1024     

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>
#include <ds_hstring.h>
#include <hob-libwspat.h>

/*+---------------------------------------------------------------------+*/
/*| class definition:                                                   |*/
/*+---------------------------------------------------------------------+*/
class  ds_wsp_helper;   // forward definition
struct dsd_domain;      // forward definition

enum ied_conf_nodes {
    ien_cnode_unknown         = -1, // unkown conf node

    /*
        log tags
    */
    ien_cnode_log             =  0,
    ien_cnode_enable              ,
    ien_cnode_file                ,
    ien_cnode_level               ,
    
    /*
        login and logoff options
    */
    ien_cnode_multiple_login      ,
    ien_cnode_close_sessions      ,
    ien_cnode_pwd_expires         ,

    /*
        domain configuration
    */
    ien_cnode_domains             ,
    ien_cnode_domain              ,
    ien_cnode_show_list           ,
	ien_cnode_default_domain	  ,
    ien_cnode_disp_name           ,
    ien_cnode_cor_ldap_service    ,
    ien_cnode_admin_dn            ,
    ien_cnode_admin_pwd           ,
    ien_cnode_admin_group         ,
    ien_cnode_base                ,
    ien_cnode_create_usr          ,
    ien_cnode_def_tree_rdn        ,
    ien_cnode_def_group           ,

    /*
        check client ip with cookie?
    */
    ien_cnode_check_cl_ineta      ,

    /*
        maximal length tags
    */
    ien_cnode_maxlenprotocol      ,
    ien_cnode_maxlenusername      ,
    ien_cnode_maxlenpassword      ,
    ien_cnode_maxlenservername    ,

    /*
        authentication expiration
    */
    ien_cnode_session_time_limits ,
    ien_cnode_maximal_period      ,
    ien_cnode_idle_period         ,

    /*
        roles defintions:
    */
    ien_cnode_roles               ,
    ien_cnode_rl_role             ,
    ien_cnode_name                ,
    ien_cnode_rl_priority         ,
	/* high entropy flag for jwtsa */
	ien_cnode_rl_entropy		  ,
	/* set login cookie */
	ien_cnode_rl_login_cookie	  ,
    /* role members */
    ien_cnode_rl_members          ,
    ien_cnode_rl_member           ,
    ien_cnode_type                ,
    ien_cnode_rl_mem_dn           ,
    /* role portlets */
    ien_cnode_rl_portlets         ,
    ien_cnode_rl_portlet          ,
    ien_cnode_rl_open             ,
    /* role compliance check */
    ien_cnode_rl_compl_check      ,
    /* role target filters */
    ien_cnode_rl_tar_filter       ,
    /* role server lists */
    ien_cnode_rl_sel_srv          ,
    ien_cnode_rl_srv_list_name    ,
    /* overall lists */
    ien_cnode_rl_entry            ,
    /* browser caching */
    ien_cnode_rl_caching          ,
    /* hide wsg url input field */
    ien_cnode_rl_wsg_input        ,
    /* welcome site (after auth) */
    ien_cnode_rl_wpage            ,
    /* GUI skin */
    ien_cnode_rl_skin             ,
    /* certifcate required */
    ien_cnode_rl_cert_required    ,
    /* webserver server list */
    ien_cnode_rl_sel_ws_srv       ,

    /*
        anonymous login:
    */
    ien_cnode_anonymous_login    ,
    ien_cnode_al_mp_user         ,
    ien_cnode_al_mp_domain       ,
    
    /*
        allowed configuration
    */
    ien_cnode_allow_conf         ,
    ien_cnode_ac_wsg_bmarks      ,
    ien_cnode_ac_rdvpn_bmarks    ,
    ien_cnode_ac_wfa_bmarks      ,
    ien_cnode_ac_dod             ,
    ien_cnode_ac_others,

#if SM_USE_CERT_AUTH
    ien_cnode_certificate_authentication,
#endif
};

enum ied_conf_certificate_auth {
	ien_cnode_ca_certificate,
	ien_cnode_ca_enabled,
    ien_cnode_ca_sha1_hash,
    ien_cnode_ca_user,
    ien_cnode_ca_name,
    ien_cnode_ca_domain,
#if SM_USE_CERT_AUTH_V2
	ien_cnode_ca_password_auth,
	ien_cnode_ca_password_encrypted,
#endif
};

class ds_at_config {

public:
    // constructor:
    ds_at_config( ds_wsp_helper* ads_wsp_helper_in );

    // destructor:
    ~ds_at_config();

    // functions:
    bool m_read_config();
    void m_check_config();
    bool m_save_config();

private:
    // variables:
    ds_wsp_helper*   adsc_wsp_helper;           // wsp helper class pointer
    char             rchc_buffer[AT_CONF_MAX]; // general buffer
    int              inc_offset;                // offset in buffer
    dsd_wspat_config dsc_conf;                  // our working copy

    // functions:
    int             m_conv_to_utf8( const HL_WCHAR* aw_input, char* ach_target, int in_max_len );
    bool            m_compare_ic( const HL_WCHAR* aw_node, const dsd_const_string& rdsp_const );
    ied_conf_nodes  m_get_node_key( const HL_WCHAR* aw_node );

    // multi user login function:
	enum ied_troolean m_get_troolean( DOMNode* ads_node, enum ied_troolean iep_default );
    bool m_is_yes( DOMNode* ads_node );
    bool m_is_no( DOMNode* ads_node );

    // domain names:
    bool m_read_domains   ( DOMNode* adsp_node );
    bool m_read_domain    ( DOMNode* adsp_node, struct dsd_domain *adsp_domain );
    int  m_get_domain_type( const HL_WCHAR* awp_type );

    // roles:
    bool            m_read_roles            ( DOMNode* ads_node );
    bool            m_read_role             ( DOMNode* ads_node );
    bool            m_read_role_members     ( DOMNode* ads_node, dsd_role* ads_role, int* ain_offset );
    bool            m_read_role_member      ( DOMNode* ads_node, dsd_role* ads_role, int* ain_offset );
    ied_role_member m_get_role_mem_type     ( DOMNode* ads_node );
    bool            m_read_role_portlets    ( DOMNode* ads_node, dsd_role* ads_role, int* ain_offset );
    bool            m_read_role_portlet     ( DOMNode* ads_node, dsd_role* ads_role, int* ain_offset );
    bool            m_read_role_srv_lists   ( DOMNode *adsp_node, struct dsd_aux_conf_servli_1 **aadsp_srv_li, int *ainp_offset );
    
    bool            m_read_role_domains     ( DOMNode* ads_node, dsd_role* ads_role, int* ain_offset );
    bool            m_read_role_time_limits ( DOMNode* ads_node, dsd_role* ads_role );
    bool            m_read_role_allowed_conf( DOMNode* adsp_node, dsd_role* adsp_role );

    // anonymous login:
    bool m_read_anonymous( DOMNode* adsp_node );

#if SM_USE_CERT_AUTH
    // certificate auth
    bool m_read_utf8_string(struct dsd_utf8_string* adsp_dst, const HL_WCHAR* achp_src, int& rinp_new_offset);
    bool m_read_utf8_string(struct dsd_utf8_string* adsp_dst, DOMNode* adsp_node, int& rinp_new_offset);
	bool m_read_base64_string(struct dsd_utf8_string* adsp_dst, const HL_WCHAR* achp_src, int& rinp_new_offset);
    bool m_read_base64_string(struct dsd_utf8_string* adsp_dst, DOMNode* adsp_node, int& rinp_new_offset);
    bool m_read_certificate_authentication( DOMNode* adsp_node );
    bool m_read_certificate( DOMNode* adsp_node, struct dsd_certificate_auth_entry** (&aadsp_last) );
    bool m_read_certificate_user( DOMNode* adsp_node, struct dsd_certificate_auth_entry* adsp_auth, int& rinp_new_offset );
#endif

    // log function:
    bool m_read_log      ( DOMNode* ads_node );
    int  m_read_log_level( DOMNode* ads_node );

    // default values:
    void m_set_defaults();

    // sort functions:
    void m_sort_roles   ();
};

#endif // _DS_CONFIG_H


