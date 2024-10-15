/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#ifdef HL_UNIX
	#include <hob-unix01.h>
#else // windows
    #include <windows.h>
#endif //HL_UNIX
#include <hob-libwspat.h>
#include <align.h>
#include <ds_wsp_helper.h>
#include <ds_hstring.h>
#include "../hobwspat.h"
#include "ds_at_config.h"
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H
#include <xercesc/dom/DOMNode.hpp>

/*+---------------------------------------------------------------------+*/
/*| configuration nodes:                                                |*/
/*+---------------------------------------------------------------------+*/
static const dsd_const_string achr_conf_nodes[] = {
    /*
        log tags
    */
    "log",
    "enable",
    "file",
    "level",

    /*
        login and logoff options
    */
    "allow-multiple-login",
    "close-sessions-at-logout",
    "password-expires-warning",

    /*
        domain configuration
    */
    "domains",
    "domain",
    "show-list",
	"default",
    "display-name",
    "corresponding-LDAP-service",
    "admin-dn",
    "admin-password",
    "admin-group",
    "base",
    "auto-user-create",
    "default-tree-rdn",
    "default-group",

    /*
        check client ip with cookie?
    */
    "check-client-ineta",

    /*
        maximal length tags
    */
    "maxlenprotocol",
    "maxlenusername",
    "maxlenpassword",
    "maxlenservername",

    /*
        session-time-limits:
            all session limits are given in seconds
        maximal-period:
            Set time limit for active RDVPN sessions
        idle-period:
            Set time limit for active but idle RDVPN sessions
    */
    "session-time-limits",
    "maximal-period",
    "idle-period",

    /*
        roles defintions:
    */
    "roles",
    "role",
    "name",
    "priority",
	/* entropy flag for jwtsa */
	"high-entropy",
	/* set login cookie */
	"login-cookie",
    /* role members */
    "members",
    "member",
    "type",
    "dn",
    /* role portlets */
    "portlets",
    "portlet",
    "open",
    /* role compliance check */
    "compliancecheck",
    /* role target filter */
    "target-filter",
    /* role server lists */
    "select-server",
    "server-list-name",
    /* overall lists */
    "entry",
    /* browser caching */
    "allow-browser-caching",
    /* hide wsg url input field */
    "allow-wsg-input",
    /* site after login */
    "site-after-auth",
    /* GUI skin */
    "gui-skin",
    /* certificate required */
    "certificate-required",
    /* webserver server list */
    "select-ws-server",

    /*
        anonymous login:
    */
    "anonymous-login",
    "mapped-user",
    "mapped-domain",

    /*
        allowed configuration
    */
    "allow-configuration",
    "wsg-bookmarks",
    "rdvpn-bookmarks",
    "wfa-bookmarks",
    "desktop-on-demand",
    "others",

#if SM_USE_CERT_AUTH
    "certificate-authentication"
#endif
};

#if SM_USE_CERT_AUTH
static const dsd_const_string achr_conf_certificate_type[] = {
    "certificate",
    "enabled",
    "sha1-hash",
    "user",
    "name",
    "domain",
#if SM_USE_CERT_AUTH_V2
	"password-authentication",
	"password-encrypted",
#endif
};
#endif

static const dsd_const_string achr_conf_member_type[] = {
    "user",
    "group",
    "ou",
    "name"
};

struct dsd_domain_type {
    struct dsd_const_string dsc_key;
    int        inc_type;
};

static const dsd_domain_type dss_domain_types[] = {
    { dsd_const_string("radius"),   DEF_CLIB1_CONF_RADIUS },
    { dsd_const_string("userlist"), DEF_CLIB1_CONF_USERLI },
    { dsd_const_string("krb5"),     DEF_CLIB1_CONF_KRB5   },
    { dsd_const_string("LDAP"),     DEF_CLIB1_CONF_LDAP   }
};

/*+---------------------------------------------------------------------+*/
/*| constructor:                                                        |*/
/*+---------------------------------------------------------------------+*/
ds_at_config::ds_at_config( ds_wsp_helper* ads_wsp_helper_in )
{
    adsc_wsp_helper = ads_wsp_helper_in;
    inc_offset      = 0;
    memset( rchc_buffer, 0, AT_CONF_MAX );
    m_set_defaults();
} // end of ds_at_config::ds_at_config


/*+---------------------------------------------------------------------+*/
/*| destructor:                                                         |*/
/*+---------------------------------------------------------------------+*/
ds_at_config::~ds_at_config()
{
} // end of ds_at_config::~ds_at_config


/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_at_config::m_read_config
 * read configuration with xerces from wsp.xml file
 *
 * @return      bool                        true = success
*/
bool ds_at_config::m_read_config()
{
    // initialize some variables:
    bool            bo_ret;             // return value
    DOMNode*        ads_pnode;          // parent working node
    DOMNode*        ads_cnode;          // child working node
    const HL_WCHAR* aw_node;            // node name
    const HL_WCHAR* aw_value;           // node value
    int             in_value;           // value as int
    ied_conf_nodes  ien_key;            // node key

    ads_pnode = adsc_wsp_helper->m_cb_get_confsection();
    while ( ads_pnode != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( adsc_wsp_helper->m_cb_get_node_type( ads_pnode ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            aw_node = adsc_wsp_helper->m_cb_get_node_name( ads_pnode );

            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            ads_cnode = adsc_wsp_helper->m_cb_get_firstchild( ads_pnode );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            
            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            ien_key = m_get_node_key( aw_node );
            switch ( ien_key ) {
                case ien_cnode_log:
                    bo_ret = m_read_log( ads_cnode );
                    if ( bo_ret == false ) {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATE002E read log conf failed - no memory left?" );
                        return false;
                    }
                    break;

                case ien_cnode_multiple_login:
                    dsc_conf.ds_public.boc_multiple_login = m_is_yes( ads_cnode );
                    break;

                case ien_cnode_close_sessions:
                    dsc_conf.ds_public.boc_end_sessions = m_is_yes( ads_cnode );
                    break;

                case ien_cnode_pwd_expires:
                    aw_value = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    in_value = m_get_wc_number( aw_value );
                    if ( in_value > -1 ) {
                        dsc_conf.ds_public.inc_pwd_expires = in_value;
                    }
                    break;

                case ien_cnode_domains:
                    if ( dsc_conf.ds_public.dsc_domains.adsc_domain == NULL ) {
                        
                        bo_ret = m_read_domains( ads_cnode );
                        if ( bo_ret == false ) {
                            adsc_wsp_helper->m_cb_print_out( "HWSPATE203E read domains conf failed - no memory left?" );
                            return false;
                        }
                    } else {
                        adsc_wsp_helper->m_cb_printf_out( "HWSPATW101W domains config multiple - ignoring line %d",
                                                         adsc_wsp_helper->m_cb_get_node_line(ads_pnode) );
                    }
                    break;

                case ien_cnode_check_cl_ineta:
                    dsc_conf.ds_public.boc_check_cl_ineta = m_is_yes( ads_cnode );
                    break;

                case ien_cnode_maxlenprotocol:
                    // get value of child node:
                    aw_value = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    in_value = m_get_wc_number( aw_value );
                    if ( in_value > -1 ) {
                        dsc_conf.in_maxlenproto = in_value;
                    } else {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATW013W unsupported value for maxlenprotol found - ignore" );
                    }
                    break;

                case ien_cnode_maxlenusername:
                    // get value of child node:
                    aw_value = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    in_value = m_get_wc_number( aw_value );
                    if ( in_value > -1 ) {
                        dsc_conf.in_maxlenuser = in_value;
                    } else {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATW014W unsupported value for maxlenusername found - ignore" );
                    }
                    break;

                case ien_cnode_maxlenpassword:
                    // get value of child node:
                    aw_value = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    in_value = m_get_wc_number( aw_value );
                    if ( in_value > -1 ) {
                        dsc_conf.in_maxlenpwd = in_value;
                    } else {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATW015W unsupported value for maxlenpassword found - ignore" );
                    }
                    break;

                case ien_cnode_maxlenservername:
                    // get value of child node:
                    aw_value = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    in_value = m_get_wc_number( aw_value );
                    if ( in_value > -1 ) {
                        dsc_conf.in_maxlenserver = in_value;
                    } else {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATW016W unsupported value for maxlenservername found - ignore" );
                    }
                    break;

                case ien_cnode_roles:
                    bo_ret = m_read_roles( ads_cnode );
                    if ( bo_ret == false ) {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATE039E read roles failed - no memory left?" );
                        return false;
                    }
                    m_sort_roles();
                    break;

                case ien_cnode_anonymous_login:
                    bo_ret = m_read_anonymous( ads_cnode );
                    if ( bo_ret == false ) {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATE048E read anonymous-login failed - no memory left?" );
                        return false;
                    }
                    break;

#if SM_USE_CERT_AUTH
                case ien_cnode_certificate_authentication:
                    bo_ret = m_read_certificate_authentication( ads_cnode );
                    if ( bo_ret == false ) {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATE048E read certificate-authentication failed - no memory left?" );
                        return false;
                    }
                    break;
#endif

                // list of not allowed nodes in main node:
                case ien_cnode_enable:
                case ien_cnode_file:
                case ien_cnode_maximal_period:
                case ien_cnode_idle_period:
                    adsc_wsp_helper->m_cb_print_out( "HWSPATW001W unsupported node in main found - ignore" );
                    break;

                default: {
                    aw_value = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    adsc_wsp_helper->m_cb_printf_out2( "HWSPATW002W unknown node '%(.*)s' in line %d found - ignore",
                                                      ied_chs_utf_16, aw_value, adsc_wsp_helper->m_cb_get_node_line(ads_cnode) );
                    break;
                }
            }
        }

        
        //---------------------------------------
        // get next node:
        //---------------------------------------
        ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
    }

    return true;
} // end of ds_at_config::m_read_config


/**
 * public function ds_at_config::m_check_config
 * check config for wrong configurations
*/
void ds_at_config::m_check_config()
{
    if ( dsc_conf.ds_public.dsc_domains.adsc_domain == NULL ) {
        adsc_wsp_helper->m_cb_print_out( "HWSPATE531E no valid domain config found, but at least one needed!" );
    }
    if ( inc_offset > AT_CONF_MAX ) {
        adsc_wsp_helper->m_cb_print_out( "HWSPATE532E Configuration exceeds maximum Size! (AT_CONF_MAX)" );
    }
} // end of ds_at_config::m_check_config


/**
 * function ds_at_config::m_save_config
 * write config to conf pointer
 *
 * @return      bool            true = success
*/
bool ds_at_config::m_save_config()
{
    // initialize some variables:
    bool              bo_ret;                // return value
    int               in_needed;             // needed size of config
    int               in_pos      = 0;       // writting position in config
    dsd_wspat_config  *ads_conf;             // pointer to our config
    dsd_role*         ads_rl_tmp;
    dsd_role*         ads_rl_tmp_out;
    dsd_role_list*    ads_list_tmp;
    dsd_role_list*    ads_list_tmp_out;
    dsd_role_member*  ads_mem_tmp;
    dsd_role_member*  ads_mem_tmp_out;
    dsd_role_portlet* ads_port_tmp;
    dsd_role_portlet* ads_port_tmp_out;
    dsd_aux_conf_servli_1* adsl_srv_list_tmp;
    dsd_aux_conf_servli_1* adsl_srv_list_tmp_out;
    struct dsd_domain  *adsl_domain;
    struct dsd_domain  *adsl_domain_out;

    /*
       config will look like this
       +--------------------------+--------------------- ... -+
       | struct dsd_wspat_config  | strings                   |
       +--------------------------+--------------------- ... -+
       | sizeof(dsd_wspat_config) | variable                  |

       char* pointers in dsd_sdh_config will point inside 
       variable part of config

       TAKE CARE: 
       ----------
            you have to ALIGN the data, if you want to use
            other things as char* pointer pointing inside 
            variable part!
    */

    //----------------------------------------
    // evaluate needed length:
    //----------------------------------------
    in_needed  =   (int)sizeof(dsd_wspat_config)
                 + (int)strlen(dsc_conf.ds_log.achc_file) + 1;
    adsl_domain = dsc_conf.ds_public.dsc_domains.adsc_domain;
    while ( adsl_domain != NULL ) {
        in_needed  = ALIGN_INT(in_needed); // align buffer
        in_needed += (int)sizeof(struct dsd_domain);

        in_needed +=   adsl_domain->inc_len_name + 1
                     + adsl_domain->inc_len_disp_name + 1
                     + adsl_domain->inc_len_base + 1
                     + adsl_domain->inc_len_ldap + 1
                     + adsl_domain->inc_len_dn_admin + 1
                     + adsl_domain->inc_len_pwd_admin + 1
                     + adsl_domain->inc_len_admin_group + 1
                     + adsl_domain->inc_len_tree_rdn_group + 1
                     + adsl_domain->inc_len_default_group + 1;
        adsl_domain = adsl_domain->adsc_next;
    }
    in_needed +=   dsc_conf.ds_public.dsc_anonymous.inc_len_user
                 + dsc_conf.ds_public.dsc_anonymous.inc_len_domain;

    // go through the list of user roles entries:
    ads_rl_tmp = dsc_conf.ds_public.adsc_roles;
    while ( ads_rl_tmp != NULL ) {
        in_needed  = ALIGN_INT(in_needed); // align buffer
        in_needed += (int)sizeof(dsd_role);

        // target filter entry:
        in_needed += ads_rl_tmp->inc_len_target_filter;

        // wsp server list entries:
        adsl_srv_list_tmp = ads_rl_tmp->adsc_srv_list;
        while ( adsl_srv_list_tmp != NULL ) {
            in_needed  = ALIGN_INT(in_needed); // align buffer
            in_needed += (int)sizeof(dsd_aux_conf_servli_1);
            in_needed += adsl_srv_list_tmp->dsc_servli_name.imc_len_str;
            adsl_srv_list_tmp = adsl_srv_list_tmp->adsc_next;
        }

        // webserver list entries:
        adsl_srv_list_tmp = ads_rl_tmp->adsc_ws_srv_list;
        while ( adsl_srv_list_tmp != NULL ) {
            in_needed  = ALIGN_INT(in_needed); // align buffer
            in_needed += (int)sizeof(dsd_aux_conf_servli_1);
            in_needed += adsl_srv_list_tmp->dsc_servli_name.imc_len_str;
            adsl_srv_list_tmp = adsl_srv_list_tmp->adsc_next;
        }

        // domain entries:
        ads_list_tmp = ads_rl_tmp->adsc_domains;
        while ( ads_list_tmp != NULL ) {
            in_needed  = ALIGN_INT(in_needed); // align buffer
            in_needed += (int)sizeof(dsd_role_list);
            in_needed += ads_list_tmp->inc_len_entry;
            ads_list_tmp = ads_list_tmp->adsc_next;
        }
        
        // member entries:
        ads_mem_tmp = ads_rl_tmp->adsc_members;
        while ( ads_mem_tmp != NULL ) {
            in_needed  = ALIGN_INT(in_needed); // align buffer
            in_needed += (int)sizeof(dsd_role_member);
            in_needed += ads_mem_tmp->inc_len_name;
            ads_mem_tmp = ads_mem_tmp->adsc_next;
        }

        // portlet entries:
        ads_port_tmp = ads_rl_tmp->adsc_portlets;
        while ( ads_port_tmp != NULL ) {
            in_needed  = ALIGN_INT(in_needed); // align buffer
            in_needed += (int)sizeof(dsd_role_portlet);
            in_needed += ads_port_tmp->inc_len_name;
            ads_port_tmp = ads_port_tmp->adsc_next;
        }

        in_needed += ads_rl_tmp->inc_len_name;
        in_needed += ads_rl_tmp->inc_len_check;
        in_needed += ads_rl_tmp->inc_len_wpage;
        in_needed += ads_rl_tmp->inc_len_skin;
        ads_rl_tmp = ads_rl_tmp->adsc_next;
    }

#if SM_USE_CERT_AUTH
    dsd_certificate_auth_entry* adsl_auth = dsc_conf.ds_public.dsc_certificate_auth.adsc_entries;
    while ( adsl_auth != NULL ) {
        in_needed  = ALIGN_INT(in_needed); // align buffer
        in_needed += sizeof(dsd_certificate_auth_entry);
        in_needed += adsl_auth->dsc_user.inc_len;
        in_needed += adsl_auth->dsc_domain.inc_len;
#if SM_USE_CERT_AUTH_V2
        in_needed += adsl_auth->dsc_password.inc_len;
#endif
        adsl_auth = adsl_auth->adsc_next;
    }
#endif

    //----------------------------------------
    // init config storage:
    //----------------------------------------
    bo_ret = adsc_wsp_helper->m_init_config( in_needed );
    if ( bo_ret == false ) {
        return false;
    }
    ads_conf = (dsd_wspat_config*)adsc_wsp_helper->m_get_config();

    //---------------------------------------
    // copy structure:
    //---------------------------------------
    bo_ret = adsc_wsp_helper->m_copy_to_config( &dsc_conf, sizeof(dsd_wspat_config),
                                                &in_pos, in_needed, false );
    if ( bo_ret == false ) {
        return false;
    }

    //---------------------------------------
    // copy strings and set pointers:
    //---------------------------------------
    const char* ach_ptr = dsc_conf.ds_log.achc_file;
    int   in_len  = (int)strlen(ach_ptr) + 1; // + 1 for zero termination
    bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len,
                                               &in_pos, in_needed, false );
    ads_conf->ds_log.achc_file = (const char*)ads_conf + (in_pos - in_len);
    if ( bo_ret == false ) {
        return false;
    }

    adsl_domain_out = NULL;
    adsl_domain     = dsc_conf.ds_public.dsc_domains.adsc_domain;
    while ( adsl_domain != NULL ) {
        bo_ret = adsc_wsp_helper->m_copy_to_config( adsl_domain,
                                                    (int)sizeof(struct dsd_domain),
                                                    &in_pos, in_needed, true );
        if ( bo_ret == false ) {
            return false;
        }
        if ( adsl_domain_out == NULL ) {
            adsl_domain_out = (struct dsd_domain*)(   (char*)ads_conf
                                                    + (in_pos - (int)sizeof(struct dsd_domain)));
            ads_conf->ds_public.dsc_domains.adsc_domain = adsl_domain_out;
        } else {
            adsl_domain_out->adsc_next = (struct dsd_domain*)(   (char*)ads_conf
                                                               + (in_pos - (int)sizeof(struct dsd_domain)));
            adsl_domain_out = adsl_domain_out->adsc_next;
        }

        // name:
        ach_ptr = adsl_domain->achc_name;
        in_len  = adsl_domain->inc_len_name;
        if ( in_len > 0 ) {
            bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len + 1,
                                                        &in_pos, in_needed, false );
            if ( bo_ret == false ) {
                return false;
            }
            adsl_domain_out->achc_name = (char*)ads_conf + (in_pos - in_len - 1);
        }

        // display name:
        ach_ptr = adsl_domain->achc_disp_name;
        in_len  = adsl_domain->inc_len_disp_name;
        if ( in_len > 0 ) {
            bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len + 1,
                                                        &in_pos, in_needed, false );
            if ( bo_ret == false ) {
                return false;
            }
            adsl_domain_out->achc_disp_name = (char*)ads_conf + (in_pos - in_len - 1);
        }


        // base:                
        ach_ptr = adsl_domain->achc_base;
        in_len  = adsl_domain->inc_len_base;
        if ( in_len > 0 ) {
            bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len + 1,
                                                        &in_pos, in_needed, false );
            if ( bo_ret == false ) {
                return false;
            }
            adsl_domain_out->achc_base = (char*)ads_conf + (in_pos - in_len - 1);
        }

        // corresponding LDAP:
        ach_ptr = adsl_domain->achc_ldap;
        in_len  = adsl_domain->inc_len_ldap;
        if ( in_len > 0 ) {
            bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len + 1,
                                                        &in_pos, in_needed, false );
            if ( bo_ret == false ) {
                return false;
            }
            adsl_domain_out->achc_ldap = (char*)ads_conf + (in_pos - in_len - 1);
        }

        // admin dn:
        ach_ptr = adsl_domain->achc_dn_admin;
        in_len  = adsl_domain->inc_len_dn_admin;
        if ( in_len > 0 ) {
            bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len + 1,
                                                        &in_pos, in_needed, false );
            if ( bo_ret == false ) {
                return false;
            }
            adsl_domain_out->achc_dn_admin = (char*)ads_conf + (in_pos - in_len - 1);
        }

        // admin password:
        ach_ptr = adsl_domain->achc_pwd_admin;
        in_len  = adsl_domain->inc_len_pwd_admin;
        if ( in_len > 0 ) {
            bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len + 1,
                                                        &in_pos, in_needed, false );
            if ( bo_ret == false ) {
                return false;
            }
            adsl_domain_out->achc_pwd_admin = (char*)ads_conf + (in_pos - in_len - 1);
        }

        // admin group:
        ach_ptr = adsl_domain->achc_admin_group;
        in_len  = adsl_domain->inc_len_admin_group;
        if ( in_len > 0 ) {
            bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len + 1,
                                                        &in_pos, in_needed, false );
            if ( bo_ret == false ) {
                return false;
            }
            adsl_domain_out->achc_admin_group = (char*)ads_conf + (in_pos - in_len - 1);
        }
        // default tree rdn:
        ach_ptr = adsl_domain->achc_tree_rdn_group;
        in_len  = adsl_domain->inc_len_tree_rdn_group;
        if ( in_len > 0 ) {
            bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len + 1,
                                                        &in_pos, in_needed, false );
            if ( bo_ret == false ) {
                return false;
            }
            adsl_domain_out->achc_tree_rdn_group = (char*)ads_conf + (in_pos - in_len - 1);
        }
        // default group:
        ach_ptr = adsl_domain->achc_default_group;
        in_len  = adsl_domain->inc_len_default_group;
        if ( in_len > 0 ) {
            bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len + 1,
                                                        &in_pos, in_needed, false );
            if ( bo_ret == false ) {
                return false;
            }
            adsl_domain_out->achc_default_group = (char*)ads_conf + (in_pos - in_len - 1);
        }


        adsl_domain = adsl_domain->adsc_next;
    }

    ach_ptr = dsc_conf.ds_public.dsc_anonymous.achc_mp_user;
    in_len  = dsc_conf.ds_public.dsc_anonymous.inc_len_user;
    bo_ret  = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len,
                                                 &in_pos, in_needed, false );
    ads_conf->ds_public.dsc_anonymous.achc_mp_user = (char*)ads_conf + (in_pos - in_len);
    if ( bo_ret == false ) {
        return false;
    }

    ach_ptr = dsc_conf.ds_public.dsc_anonymous.achc_mp_domain;
    in_len  = dsc_conf.ds_public.dsc_anonymous.inc_len_domain;
    bo_ret  = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len,
                                                 &in_pos, in_needed, false );
    ads_conf->ds_public.dsc_anonymous.achc_mp_domain = (char*)ads_conf + (in_pos - in_len);
    if ( bo_ret == false ) {
        return false;
    }

    //---------------------------------------
    // copy user roles:
    //---------------------------------------
    if ( dsc_conf.ds_public.adsc_roles != NULL ) {
        ads_rl_tmp = dsc_conf.ds_public.adsc_roles;
        bo_ret     = adsc_wsp_helper->m_copy_to_config( ads_rl_tmp,
                                                        (int)sizeof(dsd_role),
                                                        &in_pos, in_needed, true );
        ads_rl_tmp_out = (dsd_role*)((char*)ads_conf + (in_pos - (int)sizeof(dsd_role)));
        if ( bo_ret == false ) {
            return false;
        }
        ads_conf->ds_public.adsc_roles = ads_rl_tmp_out;

        do {
            // target filter:
            ach_ptr = ads_rl_tmp->achc_target_filter;
            in_len  = ads_rl_tmp->inc_len_target_filter;
            if ( in_len > 0 ) {
                bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len,
                                                            &in_pos, in_needed, false );
                ads_rl_tmp_out->achc_target_filter = (char*)ads_conf + (in_pos - in_len);
                if ( bo_ret == false ) {
                    return false;
                }
            }

            // wsp server list entries:
            adsl_srv_list_tmp     = ads_rl_tmp->adsc_srv_list;
            adsl_srv_list_tmp_out = NULL;
            while ( adsl_srv_list_tmp != NULL ) {
                // structure itself:
                bo_ret = adsc_wsp_helper->m_copy_to_config( adsl_srv_list_tmp,
                                                            (int)sizeof(dsd_aux_conf_servli_1),
                                                            &in_pos, in_needed, true );
                if ( bo_ret == false ) {
                    return false;
                }
                if ( adsl_srv_list_tmp_out == NULL ) {
                    ads_rl_tmp_out->adsc_srv_list = (dsd_aux_conf_servli_1*)((char*)ads_conf + (in_pos - (int)sizeof(dsd_aux_conf_servli_1)));
                    adsl_srv_list_tmp_out = ads_rl_tmp_out->adsc_srv_list;
                } else {
                    adsl_srv_list_tmp_out->adsc_next = (dsd_aux_conf_servli_1*)((char*)ads_conf + (in_pos - (int)sizeof(dsd_aux_conf_servli_1)));
                    adsl_srv_list_tmp_out = adsl_srv_list_tmp_out->adsc_next;
                }

                // member name:
                ach_ptr = (char*)adsl_srv_list_tmp->dsc_servli_name.ac_str;
                in_len  = adsl_srv_list_tmp->dsc_servli_name.imc_len_str;
                if ( in_len > 0 ) {
                    bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len,
                                                                &in_pos, in_needed, false );
                    adsl_srv_list_tmp_out->dsc_servli_name.ac_str = (char*)ads_conf + (in_pos - in_len);
                    if ( bo_ret == false ) {
                        return false;
                    }
                }

                adsl_srv_list_tmp = adsl_srv_list_tmp->adsc_next;
            }

            // webserver server list entries:
            adsl_srv_list_tmp     = ads_rl_tmp->adsc_ws_srv_list;
            adsl_srv_list_tmp_out = NULL;
            while ( adsl_srv_list_tmp != NULL ) {
                // structure itself:
                bo_ret = adsc_wsp_helper->m_copy_to_config( adsl_srv_list_tmp,
                                                            (int)sizeof(dsd_aux_conf_servli_1),
                                                            &in_pos, in_needed, true );
                if ( bo_ret == false ) {
                    return false;
                }
                if ( adsl_srv_list_tmp_out == NULL ) {
                    ads_rl_tmp_out->adsc_ws_srv_list = (dsd_aux_conf_servli_1*)((char*)ads_conf + (in_pos - (int)sizeof(dsd_aux_conf_servli_1)));
                    adsl_srv_list_tmp_out = ads_rl_tmp_out->adsc_ws_srv_list;
                } else {
                    adsl_srv_list_tmp_out->adsc_next = (dsd_aux_conf_servli_1*)((char*)ads_conf + (in_pos - (int)sizeof(dsd_aux_conf_servli_1)));
                    adsl_srv_list_tmp_out = adsl_srv_list_tmp_out->adsc_next;
                }

                // member name:
                ach_ptr = (char*)adsl_srv_list_tmp->dsc_servli_name.ac_str;
                in_len  = adsl_srv_list_tmp->dsc_servli_name.imc_len_str;
                if ( in_len > 0 ) {
                    bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len,
                                                                &in_pos, in_needed, false );
                    adsl_srv_list_tmp_out->dsc_servli_name.ac_str = (char*)ads_conf + (in_pos - in_len);
                    if ( bo_ret == false ) {
                        return false;
                    }
                }

                adsl_srv_list_tmp = adsl_srv_list_tmp->adsc_next;
            }

            // domain entries:
            ads_list_tmp     = ads_rl_tmp->adsc_domains;
            ads_list_tmp_out = NULL;
            while ( ads_list_tmp != NULL ) {
                // structure itself:
                bo_ret = adsc_wsp_helper->m_copy_to_config( ads_list_tmp,
                                                            (int)sizeof(dsd_role_list),
                                                            &in_pos, in_needed, true );
                if ( bo_ret == false ) {
                    return false;
                }
                if ( ads_list_tmp_out == NULL ) {
                    ads_rl_tmp_out->adsc_domains = (dsd_role_list*)((char*)ads_conf + (in_pos - (int)sizeof(dsd_role_list)));
                    ads_list_tmp_out = ads_rl_tmp_out->adsc_domains;
                } else {
                    ads_list_tmp_out->adsc_next = (dsd_role_list*)((char*)ads_conf + (in_pos - (int)sizeof(dsd_role_list)));
                    ads_list_tmp_out = ads_list_tmp_out->adsc_next;
                }

                // member name:
                ach_ptr = ads_list_tmp->achc_entry;
                in_len  = ads_list_tmp->inc_len_entry;
                if ( in_len > 0 ) {
                    bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len,
                                                                &in_pos, in_needed, false );
                    ads_list_tmp_out->achc_entry = (char*)ads_conf + (in_pos - in_len);
                    if ( bo_ret == false ) {
                        return false;
                    }
                }

                ads_list_tmp = ads_list_tmp->adsc_next;
            }
            
            // member entries:
            ads_mem_tmp     = ads_rl_tmp->adsc_members;
            ads_mem_tmp_out = NULL;
            while ( ads_mem_tmp != NULL ) {
                // member structure itself:
                bo_ret = adsc_wsp_helper->m_copy_to_config( ads_mem_tmp,
                                                            (int)sizeof(dsd_role_member),
                                                            &in_pos, in_needed, true );
                if ( bo_ret == false ) {
                    return false;
                }
                if ( ads_mem_tmp_out == NULL ) {
                    ads_rl_tmp_out->adsc_members = (dsd_role_member*)((char*)ads_conf + (in_pos - (int)sizeof(dsd_role_member)));
                    ads_mem_tmp_out = ads_rl_tmp_out->adsc_members;
                } else {
                    ads_mem_tmp_out->adsc_next = (dsd_role_member*)((char*)ads_conf + (in_pos - (int)sizeof(dsd_role_member)));
                    ads_mem_tmp_out = ads_mem_tmp_out->adsc_next;
                }

                // member name:
                ach_ptr = ads_mem_tmp->achc_name;
                in_len  = ads_mem_tmp->inc_len_name;
                if ( in_len > 0 ) {
                    bo_ret  = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len,
                                                                 &in_pos, in_needed, false );
                    ads_mem_tmp_out->achc_name = (char*)ads_conf + (in_pos - in_len);
                    if ( bo_ret == false ) {
                        return false;
                    }
                }

                ads_mem_tmp = ads_mem_tmp->adsc_next;
            }

            // portlet entries:
            ads_port_tmp     = ads_rl_tmp->adsc_portlets;
            ads_port_tmp_out = NULL;
            while ( ads_port_tmp != NULL ) {
                // member structure itself:
                bo_ret = adsc_wsp_helper->m_copy_to_config( ads_port_tmp,
                                                            (int)sizeof(dsd_role_portlet),
                                                            &in_pos, in_needed, true );
                if ( bo_ret == false ) {
                    return false;
                }
                if ( ads_port_tmp_out == NULL ) {
                    ads_rl_tmp_out->adsc_portlets = (dsd_role_portlet*)((char*)ads_conf + (in_pos - (int)sizeof(dsd_role_portlet)));
                    ads_port_tmp_out = ads_rl_tmp_out->adsc_portlets;
                } else {
                    ads_port_tmp_out->adsc_next = (dsd_role_portlet*)((char*)ads_conf + (in_pos - (int)sizeof(dsd_role_portlet)));
                    ads_port_tmp_out = ads_port_tmp_out->adsc_next;
                }

                // member name:
                ach_ptr = ads_port_tmp->achc_name;
                in_len  = ads_port_tmp->inc_len_name;
                if ( in_len > 0 ) {
                    bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len,
                                                                &in_pos, in_needed, false );
                    ads_port_tmp_out->achc_name = (char*)ads_conf + (in_pos - in_len);
                    if ( bo_ret == false ) {
                        return false;
                    }
                }

                ads_port_tmp = ads_port_tmp->adsc_next;
            }
            

            // role name:
            ach_ptr = ads_rl_tmp->achc_name;
            in_len  = ads_rl_tmp->inc_len_name;
            if ( in_len > 0 ) {
                bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len,
                                                            &in_pos, in_needed, false );
                ads_rl_tmp_out->achc_name = (char*)ads_conf + (in_pos - in_len);
                if ( bo_ret == false ) {
                    return false;
                }
            }

            // compliance check name:
            ach_ptr = ads_rl_tmp->achc_check;
            in_len  = ads_rl_tmp->inc_len_check;
            if ( in_len > 0 ) {
                bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len,
                                                            &in_pos, in_needed, false );
                ads_rl_tmp_out->achc_check = (char*)ads_conf + (in_pos - in_len);
                if ( bo_ret == false ) {
                    return false;
                }
            }

            // welcome page:
            ach_ptr = ads_rl_tmp->achc_wpage;
            in_len  = ads_rl_tmp->inc_len_wpage;
            if ( in_len > 0 ) {
                bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len,
                                                            &in_pos, in_needed, false );
                ads_rl_tmp_out->achc_wpage = (char*)ads_conf + (in_pos - in_len);
                if ( bo_ret == false ) {
                    return false;
                }
            }

            // gui skin:
            ach_ptr = ads_rl_tmp->achc_skin;
            in_len  = ads_rl_tmp->inc_len_skin;
            if ( in_len > 0 ) {
                bo_ret = adsc_wsp_helper->m_copy_to_config( ach_ptr, in_len,
                                                            &in_pos, in_needed, false );
                ads_rl_tmp_out->achc_skin = (char*)ads_conf + (in_pos - in_len);
                if ( bo_ret == false ) {
                    return false;
                }
            }            

            if ( ads_rl_tmp->adsc_next != NULL ) {
                bo_ret = adsc_wsp_helper->m_copy_to_config( ads_rl_tmp->adsc_next,
                                                            (int)sizeof(dsd_role),
                                                            &in_pos, in_needed, true );
                ads_rl_tmp_out->adsc_next = (dsd_role*)((char*)ads_conf + (in_pos - (int)sizeof(dsd_role)));
                ads_rl_tmp_out = ads_rl_tmp_out->adsc_next;
                if ( bo_ret == false ) {
                    return false;
                }
            }
            ads_rl_tmp = ads_rl_tmp->adsc_next;
        } while ( ads_rl_tmp != NULL );
    }

#if SM_USE_CERT_AUTH
    ads_conf->ds_public.dsc_certificate_auth.adsc_entries = NULL;
    dsd_certificate_auth_entry** aadsl_last = &ads_conf->ds_public.dsc_certificate_auth.adsc_entries;
    adsl_auth = dsc_conf.ds_public.dsc_certificate_auth.adsc_entries;
    while ( adsl_auth != NULL ) {
        bo_ret  = adsc_wsp_helper->m_copy_to_config( adsl_auth, sizeof(dsd_certificate_auth_entry),
                                                     &in_pos, in_needed, true );
        if ( bo_ret == false )
            return false;
        dsd_certificate_auth_entry* adsl_out = (dsd_certificate_auth_entry*)((char*)ads_conf + (in_pos - sizeof(dsd_certificate_auth_entry)));
        
		bo_ret  = adsc_wsp_helper->m_copy_to_config( adsl_auth->dsc_user.achc_data, adsl_auth->dsc_user.inc_len,
                                                     &in_pos, in_needed, false );
        if ( bo_ret == false )
            return false;
        adsl_out->dsc_user.achc_data = (char*)ads_conf + (in_pos - adsl_auth->dsc_user.inc_len);
        
		bo_ret  = adsc_wsp_helper->m_copy_to_config( adsl_auth->dsc_domain.achc_data, adsl_auth->dsc_domain.inc_len,
                                                     &in_pos, in_needed, false );
        if ( bo_ret == false )
            return false;
        adsl_out->dsc_domain.achc_data = (char*)ads_conf + (in_pos - adsl_auth->dsc_domain.inc_len);

#if SM_USE_CERT_AUTH_V2
		bo_ret  = adsc_wsp_helper->m_copy_to_config( adsl_auth->dsc_password.achc_data, adsl_auth->dsc_password.inc_len,
                                                     &in_pos, in_needed, false );
        if ( bo_ret == false )
            return false;
        adsl_out->dsc_password.achc_data = (char*)ads_conf + (in_pos - adsl_auth->dsc_password.inc_len);
#endif

		adsl_out->adsc_next = NULL;
        *aadsl_last = adsl_out;
        aadsl_last = &adsl_out->adsc_next;

        adsl_auth = adsl_auth->adsc_next;
    }
#endif

    return true;
} // end of ds_at_config::m_save_config


/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_at_config::m_set_defaults
 * set config to default values
*/
void ds_at_config::m_set_defaults()
{
    // initialize some variables:
    bool bo_ret;
    char rch_wsppath[_MAX_PATH];


    // get wsp path:
    bo_ret = adsc_wsp_helper->m_get_wsp_path( &rch_wsppath[0], _MAX_PATH );
    if ( bo_ret == false ) {
        dsc_conf.ds_log.achc_file = AT_DEF_LOG_FILE;
    } else {
        dsc_conf.ds_log.achc_file = &rchc_buffer[inc_offset];

        memcpy( &rchc_buffer[inc_offset], rch_wsppath, strlen(rch_wsppath) );
        inc_offset += (int)strlen(rch_wsppath);
        
        memcpy( &rchc_buffer[inc_offset], LOGFILE_PATH, strlen(LOGFILE_PATH) );
        inc_offset += (int)strlen(LOGFILE_PATH);

        memcpy( &rchc_buffer[inc_offset], AT_DEF_LOG_FILE, strlen(AT_DEF_LOG_FILE) );
        inc_offset += (int)strlen(AT_DEF_LOG_FILE);

        rchc_buffer[inc_offset] = 0;
        inc_offset++; // zero terminate
    }

    // log mode:
    dsc_conf.ds_log.boc_active   = false;
    dsc_conf.ds_log.iec_level    = ied_sdh_log_info;
    dsc_conf.ds_log.achc_version = (char*)AT_VERSION;

    // init public config structure:
    memset( &dsc_conf.ds_public, 0, sizeof(dsd_wspat_public_config));

    // check client ineta:
    dsc_conf.ds_public.boc_check_cl_ineta = false;

    // logoff: end sessions:
    dsc_conf.ds_public.boc_end_sessions = true;

    // multiple logins:
    dsc_conf.ds_public.boc_multiple_login = false;

    // expires warning:
    dsc_conf.ds_public.inc_pwd_expires = DEF_LIMIT_EXPIRES_DAYS;

    // max length defaults:
    dsc_conf.in_maxlenproto  = AT_DEF_MAX_LEN_PROTO;
    dsc_conf.in_maxlenuser   = AT_DEF_MAX_LEN_USER;
    dsc_conf.in_maxlenpwd    = AT_DEF_MAX_LEN_PWD;
    dsc_conf.in_maxlenserver = AT_DEF_MAX_LEN_SERVER;

    // domain defaults:
    memset( &dsc_conf.ds_public.dsc_domains, 0, sizeof(struct dsd_domains) );
    dsc_conf.ds_public.dsc_domains.boc_show_list = true;
} // end of ds_at_config::m_set_defaults


/**
 * function ds_at_config::m_conv_to_utf8
 * we will hold all values in utf8 encoding (instead xerces utf16)
 * so this function convertes an utf16 to utf8
 *
 * @param[in]   HL_WCHAR*   aw_input        input in utf16
 * @param[in]   char*       ach_target      output in utf8
 * @param[in]   int         in_max_len      max possible lenght of output
 * @return      int                         needed length in output
 *                                          -1 in error cases
*/
int ds_at_config::m_conv_to_utf8( const HL_WCHAR* aw_input,
                                   char* ach_target, int in_max_len )
{
    // initialize some variables:
    int in_needed = 0;          // needed bytes in output
    int in_ret    = 0;          // return value for m_cpy_vx_vx call

    //-------------------------------------
    // evaluate needed size for output:
    //-------------------------------------
    in_needed = m_len_vx_vx( ied_chs_utf_8,
                             aw_input, -1,
                             ied_chs_utf_16 );
    in_needed++;  // +1 for zerotermination
    if ( in_needed > in_max_len ) {
        return -1;
    }

    //-------------------------------------
    // convert from utf16 to utf8:
    //-------------------------------------
    in_ret = m_cpy_vx_vx( ach_target, in_needed , ied_chs_utf_8,
                          aw_input, -1,
                          ied_chs_utf_16 );
    if ( in_ret == -1 ) {
        return -1;
    }

    return in_needed;
} // end of ds_at_config::m_conv_to_utf8

bool ds_at_config::m_compare_ic( const HL_WCHAR* aw_node, const dsd_const_string& rdsp_const )
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

/**
 * function ds_at_config::m_get_node_key
 * get node key by name
 *
 * @param[in]   HL_WCHAR*       aw_node     node name in utf16
 * @return      ied_conf_nodes              node key
*/
ied_conf_nodes ds_at_config::m_get_node_key( const HL_WCHAR* aw_node )
{
    dsd_unicode_string dsl_key;
    dsl_key.ac_str = (void*)aw_node;
    dsl_key.imc_len_str = -1;
    dsl_key.iec_chs_str = ied_chs_utf_16;
    return ds_wsp_helper::m_search_equals_ic2(achr_conf_nodes, dsl_key, ien_cnode_unknown);
} // end of ds_at_config::m_get_node_key


/**
 * function ds_at_config::m_read_role_time_limits
 * read session-time-limits config part from role configuration
 *
 * @param[in]   DOMNode*    ads_node        first child node of log entry
 * @param[in]   dsd_role*   ads_role        current role
 * @return      bool                        true = success
*/
bool ds_at_config::m_read_role_time_limits( DOMNode* ads_node, dsd_role* ads_role )
{
    // initialize some variables:
    DOMNode*        ads_pnode;          // parent working node
    DOMNode*        ads_cnode;          // child working node
    const HL_WCHAR* aw_node;            // node name
    const HL_WCHAR* aw_value;           // node value
    ied_conf_nodes  ien_key;            // node key
    int             in_value;           // value as int

    ads_pnode = ads_node;
    
    while ( ads_pnode != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( adsc_wsp_helper->m_cb_get_node_type( ads_pnode ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            aw_node = adsc_wsp_helper->m_cb_get_node_name( ads_pnode );

            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            ads_cnode = adsc_wsp_helper->m_cb_get_firstchild( ads_pnode );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            if ( adsc_wsp_helper->m_cb_get_node_type( ads_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }

            //-----------------------------------
            // get value of child node:
            //-----------------------------------
            aw_value = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );

            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            ien_key = m_get_node_key( aw_node );
            switch ( ien_key ) {                
                case ien_cnode_maximal_period:
                    in_value = m_get_wc_number( aw_value );
                    if ( in_value < 0 ) {
                        adsc_wsp_helper->m_cb_print_out(
                            "HWSPATW040W invalid value for session-time-limits/maximal-period found - ignore" );
                        break;
                    }
                    ads_role->dsc_time_limits.in_max_period = in_value;
                    break;

                case ien_cnode_idle_period:
                    in_value = m_get_wc_number( aw_value );
                    if ( in_value < 0 ) {
                        adsc_wsp_helper->m_cb_print_out(
                            "HWSPATW041W invalid value for session-time-limits/idle-period found - ignore" );
                        break;
                    }
                    ads_role->dsc_time_limits.in_idle_period = in_value;
                    break;

                default:
                    adsc_wsp_helper->m_cb_print_out(
                        "HWSPATW039W unknown node in session-time-limits found - ignore" );
                    break;
            }
        }

        //---------------------------------------
        // get next node:
        //---------------------------------------
        ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
    }
    return true;
} // end of ds_at_config::m_read_role_time_limits


/**
 * function ds_at_config::m_read_role_allowed_conf
 * read allow-configuration config part from role configuration
 *
 * @param[in]   DOMNode*    ads_node        first child node of log entry
 * @param[in]   dsd_role*   ads_role        current role
 * @return      bool                        true = success
*/
bool ds_at_config::m_read_role_allowed_conf( DOMNode* adsp_node, dsd_role* adsp_role )
{
    // initialize some variables:
    DOMNode*        adsl_cnode;         // child working node
    ied_conf_nodes  ienl_key;           // node key
    const HL_WCHAR* awl_node;           // node name

    while ( adsp_node != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( adsc_wsp_helper->m_cb_get_node_type( adsp_node ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            adsl_cnode = adsc_wsp_helper->m_cb_get_firstchild( adsp_node );
            if ( adsl_cnode == NULL ) {
                // parent node is empty -> get next
                adsp_node = adsc_wsp_helper->m_cb_get_nextsibling( adsp_node );
                continue;
            }
            if ( adsc_wsp_helper->m_cb_get_node_type( adsl_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                adsp_node = adsc_wsp_helper->m_cb_get_nextsibling( adsp_node );
                continue;
            }

            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            awl_node = adsc_wsp_helper->m_cb_get_node_name( adsp_node );
            ienl_key = m_get_node_key( awl_node );
            switch ( ienl_key ) {
                case ien_cnode_ac_wsg_bmarks:
                    if ( m_is_yes(adsl_cnode) ) {
                        adsp_role->inc_allowed_conf |= DEF_UAC_WSG_BMARKS;
                    } else {
                        adsp_role->inc_allowed_conf = adsp_role->inc_allowed_conf & ~DEF_UAC_WSG_BMARKS;
                    }
                    break;

                case ien_cnode_ac_rdvpn_bmarks:
                    if ( m_is_yes(adsl_cnode) ) {
                        adsp_role->inc_allowed_conf |= DEF_UAC_RDVPN_BMARKS;
                    } else {
                        adsp_role->inc_allowed_conf = adsp_role->inc_allowed_conf & ~DEF_UAC_RDVPN_BMARKS;
                    }
                    break;
                
                case ien_cnode_ac_wfa_bmarks:
                    if ( m_is_yes(adsl_cnode) ) {
                        adsp_role->inc_allowed_conf |= DEF_UAC_WFA_BMARKS;
                    } else {
                        adsp_role->inc_allowed_conf = adsp_role->inc_allowed_conf & ~DEF_UAC_WFA_BMARKS;
                    }
                    break;

                case ien_cnode_ac_dod:
                    if ( m_is_yes(adsl_cnode) ) {
                        adsp_role->inc_allowed_conf |= DEF_UAC_DOD;
                    } else {
                        adsp_role->inc_allowed_conf = adsp_role->inc_allowed_conf & ~DEF_UAC_DOD;
                    }
                    break;

                case ien_cnode_ac_others:
                    if ( m_is_yes(adsl_cnode) ) {
                        adsp_role->inc_allowed_conf |= DEF_UAC_OTHERS;
                    } else {
                        adsp_role->inc_allowed_conf = adsp_role->inc_allowed_conf & ~DEF_UAC_OTHERS;
                    }
                    break;

                default:
                    adsc_wsp_helper->m_cb_printf_out2(
                        "HWSPATW039W unknown node '%(.*)s' in allow-configuration found - ignore",
                            ied_chs_utf_16, awl_node );
                    break;
            }
        }

        //---------------------------------------
        // get next node:
        //---------------------------------------
        adsp_node = adsc_wsp_helper->m_cb_get_nextsibling( adsp_node );
    }
    return true;
} // end of ds_at_config::m_read_role_allowed_conf

/**
 * function ds_at_config::m_is_yes
 * decide if node value is yes or not
 *
 * @param[in]   DOMNode*    ads_node        first child node of log entry
 * @return      bool                        true = value equals yes
*/
enum ied_troolean ds_at_config::m_get_troolean( DOMNode* ads_node, enum ied_troolean iep_default )
{
    // initialize some variables:
    const HL_WCHAR* aw_value;                    // node value
    
    // get node value:
    aw_value = adsc_wsp_helper->m_cb_get_node_value( ads_node );
	if(m_compare_ic(aw_value, "yes"))
		return ied_true;
	if(m_compare_ic(aw_value, "no"))
		return ied_false;
    return iep_default;
} // end of ds_at_config::m_is_yes

/**
 * function ds_at_config::m_is_yes
 * decide if node value is yes or not
 *
 * @param[in]   DOMNode*    ads_node        first child node of log entry
 * @return      bool                        true = value equals yes
*/
bool ds_at_config::m_is_yes( DOMNode* ads_node )
{
    return m_get_troolean(ads_node, ied_undefined) == ied_true;
} // end of ds_at_config::m_is_yes

/**
 * function ds_at_config::m_is_yes
 * decide if node value is yes or not
 *
 * @param[in]   DOMNode*    ads_node        first child node of log entry
 * @return      bool                        true = value equals yes
*/
bool ds_at_config::m_is_no( DOMNode* ads_node )
{
    return m_get_troolean(ads_node, ied_undefined) == ied_false;
} // end of ds_at_config::m_is_yes

/**
 * function ds_at_config::m_read_log
 * read logfile config part from configuration
 *
 * @param[in]   DOMNode*    ads_node        first child node of log entry
 * @return      bool                        true = success
*/
bool ds_at_config::m_read_log( DOMNode* ads_node )
{
    // initialize some variables:
    DOMNode*        ads_pnode;          // parent working node
    DOMNode*        ads_cnode;          // child working node
    const HL_WCHAR* aw_node;            // node name
    const HL_WCHAR* aw_value;           // node value
    ied_conf_nodes  ien_key;            // node key
    int             in_new_offset;      // new offset in buffer

    ads_pnode = ads_node;
    
    while ( ads_pnode != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( adsc_wsp_helper->m_cb_get_node_type( ads_pnode ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            aw_node = adsc_wsp_helper->m_cb_get_node_name( ads_pnode );

            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            ads_cnode = adsc_wsp_helper->m_cb_get_firstchild( ads_pnode );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            if ( adsc_wsp_helper->m_cb_get_node_type( ads_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }

            
            
            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            ien_key = m_get_node_key( aw_node );
            switch ( ien_key ) {
                case ien_cnode_enable:
                    dsc_conf.ds_log.boc_active = m_is_yes( ads_cnode );
                    break;

                case ien_cnode_file:
                    //---------------------------
                    // get value of child node:
                    //---------------------------
                    aw_value      = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    in_new_offset = m_conv_to_utf8( aw_value, &rchc_buffer[inc_offset],
                                                    AT_CONF_MAX - inc_offset );
                    if ( in_new_offset == -1 ) {
                        return false;
                    }
                    dsc_conf.ds_log.achc_file = &rchc_buffer[inc_offset];
                    inc_offset = in_new_offset;
                    break;

                case ien_cnode_level:
                    dsc_conf.ds_log.iec_level = (ied_sdh_log_level)m_read_log_level( ads_cnode );
                    break;

                default:
                    adsc_wsp_helper->m_cb_print_out( "HWSPATW006W unknown node in logconfig found - ignore" );
                    break;
            }
        }

        
        //---------------------------------------
        // get next node:
        //---------------------------------------
        ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
    }

    //------------------------------------------
    // init log lock:
    //------------------------------------------
    if ( dsc_conf.ds_log.boc_active == true ) { 
#ifdef HL_UNIX
        pthread_mutex_init( &dsc_conf.ds_log.dsc_lock, NULL );
#else
        InitializeCriticalSection(&dsc_conf.ds_log.dsc_lock);
#endif
    }

    return true;
} // end of ds_at_config::m_read_log


/**
 * function ds_at_config::m_read_log_level
 *
 * @param[in]   DOMNode*    ads_node        level node
 * @return      int                         log level
*/
int ds_at_config::m_read_log_level( DOMNode* ads_node )
{
    // initialize some variables:
    const HL_WCHAR* awl_value;                   // node value

    // get node value:
    awl_value = adsc_wsp_helper->m_cb_get_node_value( ads_node );

    // check if level is 'details':
    if (m_compare_ic(awl_value, SDH_LOG_CNF_LEVEL_DETAILS)) {
        return ied_sdh_log_details;
    }

    // check if level is 'info':
    if (m_compare_ic(awl_value, SDH_LOG_CNF_LEVEL_INFO)) {
        return ied_sdh_log_info;
    }

    if (m_compare_ic(awl_value, SDH_LOG_CNF_LEVEL_WARN)) {
        return ied_sdh_log_warning;
    }

    if (m_compare_ic(awl_value, SDH_LOG_CNF_LEVEL_ERROR)) {
        return ied_sdh_log_error;
    }

    return ied_sdh_log_info; // default
} // end of ds_at_config::m_read_log_level


/**
 * private function ds_at_config::m_read_domains
 * read domains config part from configuration
 *
 * @param[in]   DOMNode*    adsp_node       first node
 * @return      bool                        true = success
*/
bool ds_at_config::m_read_domains( DOMNode* adsp_node )
{
    // initialize some variables:
    DOMNode*          adsl_cnode;           // childnode
    const HL_WCHAR*   awl_name;             // node name
    ied_conf_nodes    ienl_key;             // node key
    int               inl_offset;           // save offset
    struct dsd_domain *adsl_output;         // domain config
    struct dsd_domain *adsl_cur;            // current domain from chain
    bool              bol_ret;              // return value

    while ( adsp_node != NULL ) {
        // check if we have found an element:
        if ( adsc_wsp_helper->m_cb_get_node_type( adsp_node ) == DOMNode::ELEMENT_NODE ) {
            /*
                we have found an element node
                 -> it must contain a value
                 -> this value must be text
            */
            adsl_cnode = adsc_wsp_helper->m_cb_get_firstchild( adsp_node );
            if (    adsl_cnode == NULL
                 || adsc_wsp_helper->m_cb_get_node_type( adsl_cnode ) != DOMNode::TEXT_NODE ) {
                // continue with next node
                adsp_node = adsc_wsp_helper->m_cb_get_nextsibling( adsp_node );
                continue;
            }

            /*
                get node name and check it for a known type
            */
            awl_name = adsc_wsp_helper->m_cb_get_node_name( adsp_node );
            ienl_key = m_get_node_key( awl_name );
            switch ( ienl_key ) {
                case ien_cnode_show_list:
                    dsc_conf.ds_public.dsc_domains.boc_show_list = m_is_yes(adsl_cnode);
                    break;

                case ien_cnode_domain:
                    /*
                        domain node found:
                         -> get memory for domain structure
                         -> call m_domain_v2 function
                         -> add returned config to our domain chain
                    */
                    inl_offset = inc_offset;
                    inc_offset = ALIGN_INT(inc_offset);
                    adsl_output = (struct dsd_domain *)&rchc_buffer[inc_offset];
                    memset( adsl_output, 0, sizeof(struct dsd_domain) );
                    inc_offset += (int)sizeof(struct dsd_domain);
                    if ( inc_offset > AT_CONF_MAX ) {
                        return false;
                    }

                    bol_ret = m_read_domain( adsl_cnode, adsl_output );
                    if ( bol_ret == false ) {
                        adsc_wsp_helper->m_cb_printf_out2( "HWSPATE201E reading %(.*)s in %.*s config failed in line %d",
                            ied_chs_utf_16, awl_name, achr_conf_nodes[ien_cnode_domains].m_get_len(),
                            achr_conf_nodes[ien_cnode_domains].m_get_ptr(),
                            adsc_wsp_helper->m_cb_get_node_line(adsp_node) );
                        inc_offset = inl_offset;
                        return false;
                    }

                    if ( dsc_conf.ds_public.dsc_domains.adsc_domain == NULL ) {
                        dsc_conf.ds_public.dsc_domains.adsc_domain = adsl_output;
                    } else {
                        adsl_cur = dsc_conf.ds_public.dsc_domains.adsc_domain;
                        while ( adsl_cur->adsc_next != NULL ) {
                            adsl_cur = adsl_cur->adsc_next;
                        }
                        adsl_cur->adsc_next = adsl_output;
                    }
					dsc_conf.ds_public.dsc_domains.inc_num_domains++;
                    break;

                default:
                    adsc_wsp_helper->m_cb_printf_out2( "HWSPATW200W unknown node '%(.*)s' in %.*s config found in line %d",
                                                      ied_chs_utf_16, awl_name, achr_conf_nodes[ien_cnode_domains].m_get_len(),
                                                      achr_conf_nodes[ien_cnode_domains].m_get_ptr(),
                                                      adsc_wsp_helper->m_cb_get_node_line(adsp_node) );
                    break;
            }
        }

        // get next node:
        adsp_node = adsc_wsp_helper->m_cb_get_nextsibling( adsp_node );
    }
    return true;
} // end of ds_at_config::m_read_domains


/**
 * private function ds_at_config::m_read_domain
 * read domain config part from configuration
 *
 * @param[in]   DOMNode     *adsp_node      domain node
 * @param[in]   dsd_domain  *avp_domain     pointer to output structure
 * @return      bool                        true = success
*/
bool ds_at_config::m_read_domain( DOMNode* adsp_node, struct dsd_domain *adsp_domain )
{
    // initialize some variables:
    DOMNode*         adsl_cnode;            // childnode
    const HL_WCHAR*  awl_name;              // node name
    const HL_WCHAR*  awl_value;             // node value
    ied_conf_nodes   ienl_key;              // node key
    int              inl_length;            // length

    while ( adsp_node != NULL ) {
        // check if we have found an element:
        if ( adsc_wsp_helper->m_cb_get_node_type( adsp_node ) == DOMNode::ELEMENT_NODE ) {
            /*
                we have found an element node
                 -> it must contain a value
                 -> this value must be text
            */
            adsl_cnode = adsc_wsp_helper->m_cb_get_firstchild( adsp_node );
            if (    adsl_cnode == NULL
                 || adsc_wsp_helper->m_cb_get_node_type( adsl_cnode ) != DOMNode::TEXT_NODE ) {
                // continue with next node
                adsp_node = adsc_wsp_helper->m_cb_get_nextsibling( adsp_node );
                continue;
            }

            /*
                get node name and check it for a known type
            */
            awl_name = adsc_wsp_helper->m_cb_get_node_name( adsp_node );
            ienl_key = m_get_node_key( awl_name );
            switch ( ienl_key ) {
                case ien_cnode_type:
                    awl_value = adsc_wsp_helper->m_cb_get_node_value( adsl_cnode );
                    adsp_domain->inc_auth_type = m_get_domain_type( awl_value );
                    break;

                case ien_cnode_name:
                    awl_value  = adsc_wsp_helper->m_cb_get_node_value( adsl_cnode );
                    inl_length = m_conv_to_utf8( awl_value, &rchc_buffer[inc_offset],
                                                 AT_CONF_MAX - inc_offset );
                    if ( inl_length < 0 ) {
                        return false;
                    }
                    adsp_domain->achc_name    = &rchc_buffer[inc_offset];
                    adsp_domain->inc_len_name = inl_length - 1; //minus zero termination
                    inc_offset += inl_length;
                    break;

				case ien_cnode_default_domain:
					adsp_domain->boc_default_enabled = m_is_yes( adsl_cnode );
					break;

                case ien_cnode_disp_name:
                    awl_value  = adsc_wsp_helper->m_cb_get_node_value( adsl_cnode );
                    inl_length = m_conv_to_utf8( awl_value, &rchc_buffer[inc_offset],
                                                 AT_CONF_MAX - inc_offset );
                    if ( inl_length < 0 ) {
                        return false;
                    }
                    adsp_domain->achc_disp_name    = &rchc_buffer[inc_offset];
                    adsp_domain->inc_len_disp_name = inl_length - 1; //minus zero termination
                    inc_offset += inl_length;
                    break;

                case ien_cnode_base:
                    awl_value  = adsc_wsp_helper->m_cb_get_node_value( adsl_cnode );
                    inl_length = m_conv_to_utf8( awl_value, &rchc_buffer[inc_offset],
                                                 AT_CONF_MAX - inc_offset );
                    if ( inl_length < 0 ) {
                        return false;
                    }
                    adsp_domain->achc_base    = &rchc_buffer[inc_offset];
                    adsp_domain->inc_len_base = inl_length - 1; //minus zero termination
                    inc_offset += inl_length;
                    break;

                case ien_cnode_cor_ldap_service:
                    awl_value  = adsc_wsp_helper->m_cb_get_node_value( adsl_cnode );
                    inl_length = m_conv_to_utf8( awl_value, &rchc_buffer[inc_offset],
                                                 AT_CONF_MAX - inc_offset );
                    if ( inl_length < 0 ) {
                        return false;
                    }
                    adsp_domain->achc_ldap    = &rchc_buffer[inc_offset];
                    adsp_domain->inc_len_ldap = inl_length - 1; //minus zero termination
                    inc_offset += inl_length;
                    break;

                case ien_cnode_admin_dn:
                    awl_value  = adsc_wsp_helper->m_cb_get_node_value( adsl_cnode );
                    inl_length = m_conv_to_utf8( awl_value, &rchc_buffer[inc_offset],
                                                 AT_CONF_MAX - inc_offset );
                    if ( inl_length < 0 ) {
                        return false;
                    }
                    adsp_domain->achc_dn_admin    = &rchc_buffer[inc_offset];
                    adsp_domain->inc_len_dn_admin = inl_length - 1; //minus zero termination
                    inc_offset += inl_length;
                    break;

                case ien_cnode_admin_pwd:
                    awl_value  = adsc_wsp_helper->m_cb_get_node_value( adsl_cnode );
                    inl_length = m_conv_to_utf8( awl_value, &rchc_buffer[inc_offset],
                                                 AT_CONF_MAX - inc_offset );
                    if ( inl_length < 0 ) {
                        return false;
                    }
                    adsp_domain->achc_pwd_admin    = &rchc_buffer[inc_offset];
                    adsp_domain->inc_len_pwd_admin = inl_length - 1; //minus zero termination
                    inc_offset += inl_length;
                    break;

                case ien_cnode_admin_group:
                    awl_value  = adsc_wsp_helper->m_cb_get_node_value( adsl_cnode );
                    inl_length = m_conv_to_utf8( awl_value, &rchc_buffer[inc_offset],
                                                 AT_CONF_MAX - inc_offset );
                    if ( inl_length < 0 ) {
                        return false;
                    }
                    adsp_domain->achc_admin_group    = &rchc_buffer[inc_offset];
                    adsp_domain->inc_len_admin_group = inl_length - 1; //minus zero termination
                    inc_offset += inl_length;
                    break;

                case ien_cnode_def_tree_rdn:
                    awl_value  = adsc_wsp_helper->m_cb_get_node_value( adsl_cnode );
                    inl_length = m_conv_to_utf8( awl_value, &rchc_buffer[inc_offset],
                                                 AT_CONF_MAX - inc_offset );
                    if ( inl_length < 0 ) {
                        return false;
                    }
                    adsp_domain->achc_tree_rdn_group    = &rchc_buffer[inc_offset];
                    adsp_domain->inc_len_tree_rdn_group = inl_length - 1; //minus zero termination
                    inc_offset += inl_length;
                    break;

                case ien_cnode_def_group:
                    awl_value  = adsc_wsp_helper->m_cb_get_node_value( adsl_cnode );
                    inl_length = m_conv_to_utf8( awl_value, &rchc_buffer[inc_offset],
                                                 AT_CONF_MAX - inc_offset );
                    if ( inl_length < 0 ) {
                        return false;
                    }
                    adsp_domain->achc_default_group    = &rchc_buffer[inc_offset];
                    adsp_domain->inc_len_default_group = inl_length - 1; //minus zero termination
                    inc_offset += inl_length;
                    break;

                case ien_cnode_create_usr:
                    adsp_domain->boc_create_users = m_is_yes( adsl_cnode );
                    break;

                default:
                    adsc_wsp_helper->m_cb_printf_out2( "HWSPATW201W unknown node '%(.*)s' in %.*s config found in line %d",
                                                      ied_chs_utf_16, awl_name, achr_conf_nodes[ien_cnode_domain].m_get_len(),
                                                      achr_conf_nodes[ien_cnode_domain].m_get_ptr(),
                                                      adsc_wsp_helper->m_cb_get_node_line(adsp_node) );
                    break;
            }
        }

        // get next node:
        adsp_node = adsc_wsp_helper->m_cb_get_nextsibling( adsp_node );
    }

    // validate current domain:
    if ( adsp_domain->inc_len_name < 1 ) {
        adsc_wsp_helper->m_cb_printf_out( "HWSPATW202W domain without name not allowed - ignored" );
        return false;
    }
    if (    adsp_domain->inc_len_disp_name < 1
         || adsp_domain->achc_disp_name == NULL ) {
        adsp_domain->achc_disp_name    = adsp_domain->achc_name;
        adsp_domain->inc_len_disp_name = adsp_domain->inc_len_name;
    }

    if ( adsp_domain->inc_len_ldap < 1 ) {
        adsp_domain->achc_ldap        = adsp_domain->achc_name;
        adsp_domain->inc_len_ldap     = adsp_domain->inc_len_name;
        adsp_domain->boc_search_base  = (adsp_domain->inc_len_base > 0);
        adsp_domain->boc_ldap_eq_name = true;
    } else if (    adsp_domain->inc_len_name           != adsp_domain->inc_len_ldap
                || memcmp( adsp_domain->achc_name,
                            adsp_domain->achc_ldap,
                            adsp_domain->inc_len_name) != 0 ) {
        adsp_domain->boc_search_base  = false;
        adsp_domain->boc_ldap_eq_name = false;
    } else {
        adsp_domain->boc_search_base  = (adsp_domain->inc_len_base > 0);
        adsp_domain->boc_ldap_eq_name = true;
    }
    return true;
} // end of ds_at_config::m_read_domain


/**
 * private function ds_at_config::m_get_domain_type
 * get domain type
 *
 * @param[in]   HL_WCHAR    *awp_type       type string
 * @return      int
*/
int ds_at_config::m_get_domain_type( const HL_WCHAR *awp_type )
{
    dsd_unicode_string dsl_key;
    dsl_key.ac_str = (void*)awp_type;
    dsl_key.imc_len_str = -1;
    dsl_key.iec_chs_str = ied_chs_utf_16;
    const dsd_domain_type* adsl_type = ds_wsp_helper::m_search_equals_ic(dss_domain_types, dsl_key, (dsd_domain_type*)NULL);
    if(adsl_type == NULL)
        return 0;
    return adsl_type->inc_type;
} // end of ds_at_config::m_get_domain_type


/**
 * function ds_at_config::m_read_roles
 * read roles config part from configuration
 *
 * @param[in]   DOMNode*    ads_node        first child node of log entry
 * @return      bool                        true = success
*/
bool ds_at_config::m_read_roles( DOMNode* ads_node )
{
    // initialize some variables:
    DOMNode*        ads_pnode;          // parent working node
    DOMNode*        ads_cnode;          // child working node
    const HL_WCHAR* aw_node;            // node name
    ied_conf_nodes  ien_key;            // node key
    bool            bo_ret;             // return from role read in

    ads_pnode = ads_node;
    
    while ( ads_pnode != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( adsc_wsp_helper->m_cb_get_node_type( ads_pnode ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            aw_node = adsc_wsp_helper->m_cb_get_node_name( ads_pnode );

            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            ads_cnode = adsc_wsp_helper->m_cb_get_firstchild( ads_pnode );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            if ( adsc_wsp_helper->m_cb_get_node_type( ads_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            
            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            ien_key = m_get_node_key( aw_node );
            switch ( ien_key ) {
                case ien_cnode_rl_role:
                    bo_ret = m_read_role( ads_cnode );
                    if ( bo_ret == false ) {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATE040E reading role configuration failed!" );
                        return false;
                    }
                    break;

                default:
                    adsc_wsp_helper->m_cb_print_out( "HWSPATW017W unknown node in domain conf found - ignore" );
                    break;
            }
        }

        
        //---------------------------------------
        // get next node:
        //---------------------------------------
        ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
    }

    return true;
} // end of ds_at_config::m_read_roles


/**
 * private function ds_at_config::m_read_role
 * read a single role configuration
 *
 * @param[in]   DOMNode*    ads_node        first child node of log entry
 * @return      bool                        true = success
*/
bool ds_at_config::m_read_role( DOMNode* ads_node )
{
    // initialize some variables:
    DOMNode*        ads_pnode;                  // parent working node
    DOMNode*        ads_cnode;                  // child working node
    const HL_WCHAR* aw_node;                    // node name
    const HL_WCHAR* aw_value;                   // node value
    ied_conf_nodes  ien_key;                    // node key
    int             in_new_offset;              // new offset in buffer
    dsd_role*       ads_role;                   // pointer to current role
    bool            bo_ret;                     // return from some function calls
    
    //---------------------------------------
    // get a buffer to fill:
    //---------------------------------------
    // align buffer:
    in_new_offset = ((inc_offset + (ALIGN_SIZE-1)) & (~(ALIGN_SIZE-1)));
    ads_role = dsc_conf.ds_public.adsc_roles;
    if ( ads_role == NULL ) {
        dsc_conf.ds_public.adsc_roles = (dsd_role*)&rchc_buffer[in_new_offset];
        ads_role = dsc_conf.ds_public.adsc_roles;
    } else {
        while ( ads_role->adsc_next != NULL ) {
            ads_role = ads_role->adsc_next;
        }
        ads_role->adsc_next = (dsd_role*)&rchc_buffer[in_new_offset];
        ads_role = ads_role->adsc_next;
    }
    memset( ads_role, 0, sizeof(dsd_role) );
    in_new_offset += (int)sizeof(dsd_role);
    if ( in_new_offset > AT_CONF_MAX ) {
        return false;
    }

    //---------------------------------------
    // set role defaults:
    //---------------------------------------
    ads_role->boc_enable_bcache              = true;
    ads_role->dsc_time_limits.in_idle_period = AT_DEF_IDLE_PERIOD;
    ads_role->dsc_time_limits.in_max_period  = AT_DEF_MAX_PERIOD;
    ads_role->inc_allowed_conf               =   DEF_UAC_WSG_BMARKS         // allow wsg bookmarks
                                               | DEF_UAC_RDVPN_BMARKS       // allow rdvpn (user portal) bookmarks
                                               | DEF_UAC_WFA_BMARKS         // allow wfa bookmarks
                                               | DEF_UAC_OTHERS             // allow others
                                               | DEF_UAC_WSG_INPUT;         // show input for wsg url's

    //---------------------------------------
    // read the data:
    //---------------------------------------
    ads_pnode = ads_node;
    
    while ( ads_pnode != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( adsc_wsp_helper->m_cb_get_node_type( ads_pnode ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            aw_node = adsc_wsp_helper->m_cb_get_node_name( ads_pnode );

            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            ads_cnode = adsc_wsp_helper->m_cb_get_firstchild( ads_pnode );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            if ( adsc_wsp_helper->m_cb_get_node_type( ads_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            
            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            ien_key = m_get_node_key( aw_node );
            switch ( ien_key ) {
                case ien_cnode_name:
                    //---------------------------
                    // get value of child node:
                    //---------------------------
                    aw_value               = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    ads_role->inc_len_name = m_conv_to_utf8( aw_value, &rchc_buffer[in_new_offset],
                                                             AT_CONF_MAX - in_new_offset );
                    if ( ads_role->inc_len_name == -1 ) {
                        return false;
                    }
                    ads_role->inc_len_name--;
                    ads_role->achc_name  = &rchc_buffer[in_new_offset];
                    in_new_offset       += ads_role->inc_len_name;
                    break;

                case ien_cnode_rl_priority:
                    aw_value               = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    ads_role->inc_priority = m_get_wc_number( aw_value );
                    break;

				/* hofmants: read if JWTSA should generate a very secure random */
				case ien_cnode_rl_entropy:
					ads_role->boc_high_entropy = m_is_yes( ads_cnode );
					break;

				/* hofmants: read if cookie should be set */
				case ien_cnode_rl_login_cookie:
					ads_role->boc_login_cookie = m_is_yes( ads_cnode );
					break;

                case ien_cnode_rl_members:
                    bo_ret = m_read_role_members( ads_cnode, ads_role, &in_new_offset );
                    if ( bo_ret == false ) {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATE041E reading role members configuration failed!" );
                        return false;
                    }
                    break;

                case ien_cnode_rl_portlets:
                    bo_ret = m_read_role_portlets( ads_cnode, ads_role, &in_new_offset );
                    if ( bo_ret == false ) {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATE046E reading role portlets configuration failed!" );
                        return false;
                    }
                    break;
    
                case ien_cnode_rl_compl_check:
                    //---------------------------
                    // get value of child node:
                    //---------------------------
                    aw_value                = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    ads_role->inc_len_check = m_conv_to_utf8( aw_value, &rchc_buffer[in_new_offset],
                                                              AT_CONF_MAX - in_new_offset );
                    if ( ads_role->inc_len_check == -1 ) {
                        return false;
                    }
                    ads_role->inc_len_check--;
                    ads_role->achc_check  = &rchc_buffer[in_new_offset];
                    in_new_offset        += ads_role->inc_len_check;
                    break;

                case ien_cnode_rl_tar_filter:
                    //---------------------------
                    // get value of child node:
                    //---------------------------
                    aw_value                        = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    ads_role->inc_len_target_filter = m_conv_to_utf8( aw_value, &rchc_buffer[in_new_offset],
                                                                      AT_CONF_MAX - in_new_offset );
                    if ( ads_role->inc_len_target_filter == -1 ) {
                        return false;
                    }
                    ads_role->inc_len_target_filter--;
                    ads_role->achc_target_filter  = &rchc_buffer[in_new_offset];
                    in_new_offset                += ads_role->inc_len_target_filter;
                    break;

                case ien_cnode_rl_sel_srv:
                    bo_ret = m_read_role_srv_lists( ads_cnode, &ads_role->adsc_srv_list, &in_new_offset );
                    if ( bo_ret == false ) {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATE043E reading role server-lists configuration failed!" );
                        return false;
                    }
                    break;

                case ien_cnode_rl_sel_ws_srv:
                    bo_ret = m_read_role_srv_lists( ads_cnode, &ads_role->adsc_ws_srv_list, &in_new_offset );
                    if ( bo_ret == false ) {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATE052E reading role webserver server-lists configuration failed!" );
                        return false;
                    }
                    break;

                case ien_cnode_domains:
                    bo_ret = m_read_role_domains( ads_cnode, ads_role, &in_new_offset );
                    if ( bo_ret == false ) {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATE044E reading role domain-list configuration failed!" );
                        return false;
                    }
                    break;

                case ien_cnode_session_time_limits:
                    bo_ret = m_read_role_time_limits( ads_cnode, ads_role );
                    if ( bo_ret == false ) {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATE038E read session-time-limits failed - no memory left?" );
                        return false;
                    }
                    break;

                case ien_cnode_rl_caching:
                    ads_role->boc_enable_bcache = m_is_yes( ads_cnode );
                    break;

                case ien_cnode_rl_wsg_input:
                    if ( m_is_yes(ads_cnode) ) {
                        ads_role->inc_allowed_conf |=  DEF_UAC_WSG_INPUT;
                    } else {
                        ads_role->inc_allowed_conf &= ~DEF_UAC_WSG_INPUT;
                    }
                    break;

                case ien_cnode_rl_wpage:
                    //---------------------------
                    // get value of child node:
                    //---------------------------
                    aw_value                = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    ads_role->inc_len_wpage = m_conv_to_utf8( aw_value, &rchc_buffer[in_new_offset],
                                                              AT_CONF_MAX - in_new_offset );
                    if ( ads_role->inc_len_wpage == -1 ) {
                        return false;
                    }
                    ads_role->inc_len_wpage--;
                    ads_role->achc_wpage  = &rchc_buffer[in_new_offset];
                    in_new_offset        += ads_role->inc_len_wpage;
                    break;

                case ien_cnode_rl_skin:
                    //---------------------------
                    // get value of child node:
                    //---------------------------
                    aw_value               = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    ads_role->inc_len_skin = m_conv_to_utf8( aw_value, &rchc_buffer[in_new_offset],
                                                             AT_CONF_MAX - in_new_offset );
                    if ( ads_role->inc_len_skin == -1 ) {
                        return false;
                    }
                    ads_role->inc_len_skin--;
                    ads_role->achc_skin  = &rchc_buffer[in_new_offset];
                    in_new_offset       += ads_role->inc_len_skin;
                    break;

                case ien_cnode_rl_cert_required:
                    ads_role->boc_require_cert = m_is_yes( ads_cnode );
                    break;

                case ien_cnode_allow_conf:
                    bo_ret = m_read_role_allowed_conf( ads_cnode, ads_role );
                    if ( bo_ret == false ) {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATE038E read allow-configuration failed - no memory left?" );
                        return false;
                    }
                    break;

                default:
                    adsc_wsp_helper->m_cb_printf_out2( "HWSPATW020W unknown node %(.*)s in role conf found in line %d - ignore",
                                                      ied_chs_utf_16, aw_node, adsc_wsp_helper->m_cb_get_node_line(ads_pnode) );
                    break;
            }
        }

        //---------------------------------------
        // get next node:
        //---------------------------------------
        ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
    } // end of while loop

    inc_offset = in_new_offset;
    return true;
} // end of ds_at_config::m_read_role


/**
 * private function ds_at_config::m_read_role_members
 * read a role members configuration
 *
 * @param[in]       DOMNode*    ads_node        first child node of log entry
 * @param[in]       dsd_role*   ads_role        current role
 * @param[in/out]   int*        ain_offset      our offset
 * @return          bool                        true = success
*/
bool ds_at_config::m_read_role_members( DOMNode* ads_node, dsd_role* ads_role,
                                         int* ain_offset )
{
    // initialize some variables:
    DOMNode*         ads_pnode;                 // parent working node
    DOMNode*         ads_cnode;                 // child working node
    const HL_WCHAR*  aw_node;                   // node name
    ied_conf_nodes   ien_key;                   // node key
    bool             bo_ret;                    // return value

    //-------------------------------------------
    // read the data:
    //-------------------------------------------
    ads_pnode = ads_node;    
    while ( ads_pnode != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( adsc_wsp_helper->m_cb_get_node_type( ads_pnode ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            aw_node = adsc_wsp_helper->m_cb_get_node_name( ads_pnode );

            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            ads_cnode = adsc_wsp_helper->m_cb_get_firstchild( ads_pnode );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            if ( adsc_wsp_helper->m_cb_get_node_type( ads_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }

            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            ien_key = m_get_node_key( aw_node );
            switch ( ien_key ) {
                case ien_cnode_rl_member:
                    bo_ret = m_read_role_member( ads_cnode, ads_role, ain_offset );
                    if ( bo_ret == false ) {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATE045E reading role member configuration failed!" );
                        return false;
                    }
                    break;

                default:
                    adsc_wsp_helper->m_cb_print_out( "HWSPATW018W unknown node in domain conf found - ignore" );
                    break;
            }
        }

        //---------------------------------------
        // get next node:
        //---------------------------------------
        ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
    } // end of while loop

    return true;
} // end of ds_at_config::m_read_role_members


/**
 * private function ds_at_config::m_read_role_portlets
 * read a role portlets configuration
 *
 * @param[in]       DOMNode*    ads_node        first child node of log entry
 * @param[in]       dsd_role*   ads_role        current role
 * @param[in/out]   int*        ain_offset      our offset
 * @return          bool                        true = success
*/
bool ds_at_config::m_read_role_portlets( DOMNode* ads_node, dsd_role* ads_role,
                                          int* ain_offset )
{
    // initialize some variables:
    DOMNode*         ads_cnode;                 // child working node
    const HL_WCHAR*  aw_node;                   // node name
    ied_conf_nodes   ien_key;                   // node key
    bool             bo_ret;                    // return value

    //-------------------------------------------
    // read the data:
    //-------------------------------------------
    while ( ads_node != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( adsc_wsp_helper->m_cb_get_node_type( ads_node ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            aw_node = adsc_wsp_helper->m_cb_get_node_name( ads_node );

            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            ads_cnode = adsc_wsp_helper->m_cb_get_firstchild( ads_node );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                ads_node = adsc_wsp_helper->m_cb_get_nextsibling( ads_node );
                continue;
            }
            if ( adsc_wsp_helper->m_cb_get_node_type( ads_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                ads_node = adsc_wsp_helper->m_cb_get_nextsibling( ads_node );
                continue;
            }

            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            ien_key = m_get_node_key( aw_node );
            switch ( ien_key ) {
                case ien_cnode_rl_portlet:
                    bo_ret = m_read_role_portlet( ads_cnode, ads_role, ain_offset );
                    if ( bo_ret == false ) {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATE047E reading role portlet configuration failed!" );
                        return false;
                    }
                    break;

                default:
                    adsc_wsp_helper->m_cb_print_out( "HWSPATW051W unknown node in portlet conf found - ignore" );
                    break;
            }
        }

        //---------------------------------------
        // get next node:
        //---------------------------------------
        ads_node = adsc_wsp_helper->m_cb_get_nextsibling( ads_node );
    } // end of while loop

    return true;
} // end of ds_at_config::m_read_role_portlets


/**
 * private function ds_at_config::m_read_role_member
 * read a role portlet configuration
 *
 * @param[in]       DOMNode*    ads_node        first child node
 * @param[in]       dsd_role*   ads_role        current role
 * @param[in/out]   int*        ain_offset      our offset
 * @return          bool                        true = success
*/
bool ds_at_config::m_read_role_portlet( DOMNode* ads_node, dsd_role* ads_role,
                                         int* ain_offset )
{
    // initialize some variables:
    DOMNode*           ads_cnode;               // child working node
    const HL_WCHAR*    aw_node;                 // node name
    const HL_WCHAR*    aw_value;                // node value
    ied_conf_nodes     ien_key;                 // node key
    int                in_new_offset;           // new offset in buffer
    int                in_value;                // length of value (utf8)
    dsd_role_portlet*  ads_portlet;             // current portlet buffer

    //-------------------------------------------
    // get a buffer to fill:
    //-------------------------------------------
    // align buffer:
    in_new_offset = ALIGN_INT(*ain_offset);
    ads_portlet = ads_role->adsc_portlets;
    if ( ads_portlet == NULL ) {
        ads_role->adsc_portlets = (dsd_role_portlet*)&rchc_buffer[in_new_offset];
        ads_portlet = ads_role->adsc_portlets;
    } else {
        while ( ads_portlet->adsc_next != NULL ) {
            ads_portlet = ads_portlet->adsc_next;
        }
        ads_portlet->adsc_next = (dsd_role_portlet*)&rchc_buffer[in_new_offset];
        ads_portlet = ads_portlet->adsc_next;
    }
    in_new_offset += (int)sizeof(dsd_role_portlet);
    if ( in_new_offset > AT_CONF_MAX ) {
        return false;
    }
    ads_portlet->bo_open = true;

    //-------------------------------------------
    // read the data:
    //-------------------------------------------
    while ( ads_node != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( adsc_wsp_helper->m_cb_get_node_type( ads_node ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            aw_node = adsc_wsp_helper->m_cb_get_node_name( ads_node );

            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            ads_cnode = adsc_wsp_helper->m_cb_get_firstchild( ads_node );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                ads_node = adsc_wsp_helper->m_cb_get_nextsibling( ads_node );
                continue;
            }
            if ( adsc_wsp_helper->m_cb_get_node_type( ads_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                ads_node = adsc_wsp_helper->m_cb_get_nextsibling( ads_node );
                continue;
            }
            
            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            ien_key = m_get_node_key( aw_node );
            switch ( ien_key ) {
                case ien_cnode_name:
                    //---------------------------
                    // get value of child node:
                    //---------------------------
                    aw_value = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    in_value = m_conv_to_utf8( aw_value, &rchc_buffer[in_new_offset],
                                               AT_CONF_MAX - in_new_offset );
                    if ( in_value == -1 ) {
                        return false;
                    }
                    in_value--;

                    //---------------------------
                    // fill the buffer:
                    //---------------------------
                    ads_portlet->achc_name     = &rchc_buffer[in_new_offset];
                    ads_portlet->inc_len_name  = in_value;
                    in_new_offset             += in_value;
                    break;

#if 0
                case ien_cnode_rl_order:
                    // get value of child node:
                    aw_value = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    in_value = m_get_wc_number( aw_value );
                    if ( in_value > -1 ) {
                        ads_portlet->inc_order = in_value;
                    }
                    break;
#endif

                case ien_cnode_rl_open:
                    ads_portlet->bo_open = m_is_yes( ads_cnode );
                    break;

                default:
                    adsc_wsp_helper->m_cb_print_out( "HWSPATW053W unknown node in portlet conf found - ignore" );
                    break;
            }
        }

        //---------------------------------------
        // get next node:
        //---------------------------------------
        ads_node = adsc_wsp_helper->m_cb_get_nextsibling( ads_node );
    } // end of while loop

    //-------------------------------------------
    // set new offset:
    //-------------------------------------------
    *ain_offset = in_new_offset;

    return true;
} // end of ds_at_config::m_read_role_porlet


/**
 * private function ds_at_config::m_read_role_member
 * read a role member configuration
 *
 * @param[in]       DOMNode*    ads_node        first child node
 * @param[in]       dsd_role*   ads_role        current role
 * @param[in/out]   int*        ain_offset      our offset
 * @return          bool                        true = success
*/
bool ds_at_config::m_read_role_member( DOMNode* ads_node, dsd_role* ads_role,
                                        int* ain_offset )
{
    // initialize some variables:
    DOMNode*         ads_pnode;                 // parent working node
    DOMNode*         ads_cnode;                 // child working node
    const HL_WCHAR*  aw_node;                   // node name
    const HL_WCHAR*  aw_value;                  // node value
    ied_conf_nodes   ien_key;                   // node key
    int              in_new_offset;             // new offset in buffer
    int              in_len;                    // length of value (utf8)
    dsd_role_member* ads_member;                // current member buffer
    char*            achl_dn      = NULL;       // current dn
    int              inl_len_dn   = 0;          // length dn
    char*            achl_name    = NULL;       // current name
    int              inl_len_name = 0;          // length name

    //-------------------------------------------
    // get a buffer to fill:
    //-------------------------------------------
    // align buffer:
    in_new_offset = ALIGN_INT(*ain_offset);
    ads_member = ads_role->adsc_members;
    if ( ads_member == NULL ) {
        ads_role->adsc_members = (dsd_role_member*)&rchc_buffer[in_new_offset];
        ads_member = ads_role->adsc_members;
    } else {
        while ( ads_member->adsc_next != NULL ) {
            ads_member = ads_member->adsc_next;
        }
        ads_member->adsc_next = (dsd_role_member*)&rchc_buffer[in_new_offset];
        ads_member = ads_member->adsc_next;
    }
    //memset( ads_member, 0, sizeof(dsd_role_member) );
    in_new_offset += (int)sizeof(dsd_role_member);
    if ( in_new_offset > AT_CONF_MAX ) {
        return false;
    }

    //-------------------------------------------
    // read the data:
    //-------------------------------------------
    ads_pnode = ads_node;    
    while ( ads_pnode != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( adsc_wsp_helper->m_cb_get_node_type( ads_pnode ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            aw_node = adsc_wsp_helper->m_cb_get_node_name( ads_pnode );

            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            ads_cnode = adsc_wsp_helper->m_cb_get_firstchild( ads_pnode );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            if ( adsc_wsp_helper->m_cb_get_node_type( ads_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            
            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            ien_key = m_get_node_key( aw_node );
            switch ( ien_key ) {
                case ien_cnode_type:
                    ads_member->ienc_type = m_get_role_mem_type( ads_cnode );
                    if ( ads_member->ienc_type == ied_role_mem_unknown ) {
                        memset( ads_member, 0, sizeof(dsd_role_member) );
                        adsc_wsp_helper->m_cb_print_out( "HWSPATW021W unknown member type found - ignore" );
                        *ain_offset = in_new_offset;
                        return true; // just ignore, no error
                    }
                    break;

                case ien_cnode_rl_mem_dn:
                    //---------------------------
                    // get value of child node:
                    //---------------------------
                    aw_value = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    in_len   = m_conv_to_utf8( aw_value, &rchc_buffer[in_new_offset],
                                               AT_CONF_MAX - in_new_offset );
                    if ( in_len == -1 ) {
                        return false;
                    }
                    in_len--;

                    //---------------------------
                    // fill the buffer:
                    //---------------------------
                    achl_dn        = &rchc_buffer[in_new_offset];
                    inl_len_dn     = in_len;
                    in_new_offset += in_len;
                    break;
                
                case ien_cnode_name:
                    //---------------------------
                    // get value of child node:
                    //---------------------------
                    aw_value = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    in_len   = m_conv_to_utf8( aw_value, &rchc_buffer[in_new_offset],
                                               AT_CONF_MAX - in_new_offset );
                    if ( in_len == -1 ) {
                        return false;
                    }
                    in_len--;

                    //---------------------------
                    // fill the buffer:
                    //---------------------------
                    achl_name      = &rchc_buffer[in_new_offset];
                    inl_len_name   = in_len;
                    in_new_offset += in_len;
                    break;

                default:
                    adsc_wsp_helper->m_cb_print_out( "HWSPATW019W unknown node in domain conf found - ignore" );
                    break;
            }
        }

        //---------------------------------------
        // get next node:
        //---------------------------------------
        ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
    } // end of while loop

    //-------------------------------------------
    // set new offset:
    //-------------------------------------------
    *ain_offset = in_new_offset;

    switch ( ads_member->ienc_type ) {
        case ied_role_mem_dn:
        case ied_role_mem_group:
        case ied_role_mem_ou:
            ads_member->achc_name    = achl_dn;
            ads_member->inc_len_name = inl_len_dn;
            break;
        case ied_role_mem_name:
            ads_member->achc_name    = achl_name;
            ads_member->inc_len_name = inl_len_name;
            break;
    }

    return true;
} // end of ds_at_config::m_read_role_member


/**
 * private function ds_at_config::m_get_role_mem_type
 *
 * @param[in]   DOMNode*        ads_node
 * @return      ied_role_member
*/
ied_role_member ds_at_config::m_get_role_mem_type( DOMNode* ads_node )
{
    const HL_WCHAR* aw_value = adsc_wsp_helper->m_cb_get_node_value( ads_node );
    if(aw_value == NULL)
        return ied_role_mem_unknown;
    dsd_unicode_string dsl_key;
    dsl_key.ac_str = (void*)aw_value;
    dsl_key.imc_len_str = -1;
    dsl_key.iec_chs_str = ied_chs_utf_16;
    return ds_wsp_helper::m_search_equals_ic2(achr_conf_member_type, dsl_key, ied_role_mem_unknown);
} // end of ds_at_config::m_get_role_mem_type


/**
 * private function ds_at_config::m_read_role_srv_lists
 * read role server-lists configuration
 *
 * @param[in]       DOMNode                 *ads_node       first child node
 * @param[out]      dsd_aux_conf_servli_1   **adsp_srv_li   server list to fill
 * @param[in/out]   int                     *ain_offset     our offset
 * @return          bool                                    true = success
*/
bool ds_at_config::m_read_role_srv_lists( DOMNode *adsp_node,
                                          struct dsd_aux_conf_servli_1 **aadsp_srv_li,
                                          int *ainp_offset )
{
    DOMNode*               adsl_cnode;          // child working node
    const HL_WCHAR*        awl_node;            // node name
    const HL_WCHAR*        awl_value;           // node value
    ied_conf_nodes         ienl_key;            // node key
    int                    inl_new_offset;      // new offset in buffer
    int                    inl_len;             // length of value (utf8)
    dsd_aux_conf_servli_1* adsl_srv_list;       // current server-list buffer

    //-------------------------------------------
    // read the data:
    //-------------------------------------------    
    while ( adsp_node != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( adsc_wsp_helper->m_cb_get_node_type( adsp_node ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            awl_node = adsc_wsp_helper->m_cb_get_node_name( adsp_node );

            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            adsl_cnode = adsc_wsp_helper->m_cb_get_firstchild( adsp_node );
            if ( adsl_cnode == NULL ) {
                // parent node is empty -> get next
                adsp_node = adsc_wsp_helper->m_cb_get_nextsibling( adsp_node );
                continue;
            }
            if ( adsc_wsp_helper->m_cb_get_node_type( adsl_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                adsp_node = adsc_wsp_helper->m_cb_get_nextsibling( adsp_node );
                continue;
            }
            
            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            ienl_key = m_get_node_key( awl_node );
            switch ( ienl_key ) {
                case ien_cnode_rl_srv_list_name:
                    //---------------------------
                    // get a buffer to fill:
                    //---------------------------
                    // align buffer:
                    inl_new_offset = ALIGN_INT(*ainp_offset);
                    adsl_srv_list = *aadsp_srv_li;
                    if ( adsl_srv_list == NULL ) {
                        *aadsp_srv_li = (dsd_aux_conf_servli_1*)&rchc_buffer[inl_new_offset];
                        adsl_srv_list = *aadsp_srv_li;
                    } else {
                        while ( adsl_srv_list->adsc_next != NULL ) {
                            adsl_srv_list = adsl_srv_list->adsc_next;
                        }
                        adsl_srv_list->adsc_next = (dsd_aux_conf_servli_1*)&rchc_buffer[inl_new_offset];
                        adsl_srv_list = adsl_srv_list->adsc_next;
                    }
                    inl_new_offset += (int)sizeof(dsd_aux_conf_servli_1);
                    if ( inl_new_offset > AT_CONF_MAX ) {
                        return false;
                    }

                    //---------------------------
                    // get value of child node:
                    //---------------------------
                    awl_value = adsc_wsp_helper->m_cb_get_node_value( adsl_cnode );
                    inl_len   = m_conv_to_utf8( awl_value, &rchc_buffer[inl_new_offset],
                                                AT_CONF_MAX - inl_new_offset );
                    if ( inl_len == -1 ) {
                        return false;
                    }
                    inl_len--;

                    //---------------------------
                    // fill the buffer:
                    //---------------------------
                    adsl_srv_list->dsc_servli_name.ac_str      = &rchc_buffer[inl_new_offset];
                    adsl_srv_list->dsc_servli_name.imc_len_str = inl_len;
                    adsl_srv_list->dsc_servli_name.iec_chs_str = ied_chs_utf_8;
                    inl_new_offset                            += inl_len;

                    //---------------------------
                    // set new offset:
                    //---------------------------
                    *ainp_offset = inl_new_offset;
                    break;

                default:
                    adsc_wsp_helper->m_cb_print_out( "HWSPATW043W unknown node in server list conf found - ignore" );
                    break;
            }
        }

        //---------------------------------------
        // get next node:
        //---------------------------------------
        adsp_node = adsc_wsp_helper->m_cb_get_nextsibling( adsp_node );
    } // end of while loop
    return true;
} // end of ds_at_config::m_read_role_srv_lists


/**
 * private function ds_at_config::m_read_role_domains
 * read role domain configuration
 *
 * @param[in]       DOMNode*    ads_node        first child node
 * @param[in]       dsd_role*   ads_role        current role
 * @param[in/out]   int*        ain_offset      our offset
 * @return          bool                        true = success
*/
bool ds_at_config::m_read_role_domains( DOMNode* ads_node, dsd_role* ads_role, int* ain_offset )
{
    // initialize some variables:
    DOMNode*         ads_pnode;                 // parent working node
    DOMNode*         ads_cnode;                 // child working node
    const HL_WCHAR*  aw_node;                   // node name
    const HL_WCHAR*  aw_value;                  // node value
    ied_conf_nodes   ien_key;                   // node key
    int              in_new_offset;             // new offset in buffer
    int              in_len;                    // length of value (utf8)
    dsd_role_list*   ads_domain;                // current domain buffer

    //-------------------------------------------
    // read the data:
    //-------------------------------------------
    ads_pnode = ads_node;    
    while ( ads_pnode != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( adsc_wsp_helper->m_cb_get_node_type( ads_pnode ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            aw_node = adsc_wsp_helper->m_cb_get_node_name( ads_pnode );

            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            ads_cnode = adsc_wsp_helper->m_cb_get_firstchild( ads_pnode );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            if ( adsc_wsp_helper->m_cb_get_node_type( ads_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            
            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            ien_key = m_get_node_key( aw_node );
            switch ( ien_key ) {
                case ien_cnode_rl_entry:
                    //---------------------------
                    // get a buffer to fill:
                    //---------------------------
                    // align buffer:
                    in_new_offset = ALIGN_INT(*ain_offset);
                    ads_domain = ads_role->adsc_domains;
                    if ( ads_domain == NULL ) {
                        ads_role->adsc_domains = (dsd_role_list*)&rchc_buffer[in_new_offset];
                        ads_domain = ads_role->adsc_domains;
                    } else {
                        while ( ads_domain->adsc_next != NULL ) {
                            ads_domain = ads_domain->adsc_next;
                        }
                        ads_domain->adsc_next = (dsd_role_list*)&rchc_buffer[in_new_offset];
                        ads_domain = ads_domain->adsc_next;
                    }
                    in_new_offset += (int)sizeof(dsd_role_list);
                    if ( in_new_offset > AT_CONF_MAX ) {
                        return false;
                    }

                    //---------------------------
                    // get value of child node:
                    //---------------------------
                    aw_value = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    in_len   = m_conv_to_utf8( aw_value, &rchc_buffer[in_new_offset],
                                               AT_CONF_MAX - in_new_offset );
                    if ( in_len == -1 ) {
                        return false;
                    }
                    in_len--;

                    //---------------------------
                    // fill the buffer:
                    //---------------------------
                    ads_domain->achc_entry     = &rchc_buffer[in_new_offset];
                    ads_domain->inc_len_entry  = in_len;
                    in_new_offset            += in_len;

                    //---------------------------
                    // set new offset:
                    //---------------------------
                    *ain_offset = in_new_offset;
                    break;

                default:
                    adsc_wsp_helper->m_cb_print_out( "HWSPATW044W unknown node in role conf found - ignore" );
                    break;
            }
        }

        //---------------------------------------
        // get next node:
        //---------------------------------------
        ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
    } // end of while loop
    return true;
} // end of ds_at_config::m_read_role_domains


/**
 * private function ds_at_config::m_sort_roles
 * sort roles by priority
*/
void ds_at_config::m_sort_roles()
{
    if (    dsc_conf.ds_public.adsc_roles            == NULL 
         || dsc_conf.ds_public.adsc_roles->adsc_next == NULL ) {
        return;
    }
   
    dsd_role* ads_cur1;
    dsd_role* ads_cur2;
    dsd_role* ads_cur3;
    dsd_role* ads_end = NULL;
    dsd_role* ads_tmp;
 
    while (ads_end != dsc_conf.ds_public.adsc_roles->adsc_next) {
       
        ads_cur3 = dsc_conf.ds_public.adsc_roles;
        ads_cur1 = dsc_conf.ds_public.adsc_roles;
        ads_cur2 = ads_cur1->adsc_next;
       
        while (ads_cur1 != ads_end) {
            if (ads_cur1->inc_priority < ads_cur2->inc_priority) {
                if (ads_cur1 == dsc_conf.ds_public.adsc_roles) {
                    ads_tmp = ads_cur2->adsc_next;
                    ads_cur2->adsc_next = ads_cur1;
                    ads_cur1->adsc_next = ads_tmp;
                    dsc_conf.ds_public.adsc_roles = ads_cur2;
                    ads_cur3 = ads_cur2;
                } else {
                    ads_tmp = ads_cur2->adsc_next;
                    ads_cur2->adsc_next = ads_cur1;
                    ads_cur1->adsc_next = ads_tmp;
                    ads_cur3->adsc_next = ads_cur2;
                    ads_cur3 = ads_cur2;
                }
            } else {
                ads_cur3 = ads_cur1;
                ads_cur1 = ads_cur1->adsc_next;
            }
            ads_cur2 = ads_cur1->adsc_next;
            if (ads_cur2 == ads_end) {
                ads_end = ads_cur1;
            }
        }
    }
} // end of ds_at_config::m_sort_roles


/**
 * private function ds_at_config::m_read_anonymous
 *
 * @param[in]   DOMNode*    adsp_node
 * @return      bool                    true = success
*/
bool ds_at_config::m_read_anonymous( DOMNode* adsp_node )
{
    // initialize some variables:
    DOMNode*        ads_cnode;          // child working node
    const HL_WCHAR* aw_node;            // node name
    const HL_WCHAR* aw_value;           // node value
    ied_conf_nodes  ien_key;            // node key

#define DSL_ANONYMOUS (dsc_conf.ds_public.dsc_anonymous)

    if (    DSL_ANONYMOUS.boc_enabled    == true
         || DSL_ANONYMOUS.inc_len_user   >  0
         || DSL_ANONYMOUS.inc_len_domain >  0    ) {
        adsc_wsp_helper->m_cb_print_out( "HWSPATW055W node anonymous-login double - ignore" );
        return true;
    }
    
    while ( adsp_node != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( adsc_wsp_helper->m_cb_get_node_type( adsp_node ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            aw_node = adsc_wsp_helper->m_cb_get_node_name( adsp_node );

            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            ads_cnode = adsc_wsp_helper->m_cb_get_firstchild( adsp_node );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                adsp_node = adsc_wsp_helper->m_cb_get_nextsibling( adsp_node );
                continue;
            }
            if ( adsc_wsp_helper->m_cb_get_node_type( ads_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                adsp_node = adsc_wsp_helper->m_cb_get_nextsibling( adsp_node );
                continue;
            }
            
            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            ien_key = m_get_node_key( aw_node );
            switch ( ien_key ) {
                case ien_cnode_enable:
                    dsc_conf.ds_public.dsc_anonymous.boc_enabled = m_is_yes( ads_cnode );
                    break;

                case ien_cnode_al_mp_user:
                    aw_value                   = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    DSL_ANONYMOUS.inc_len_user = m_conv_to_utf8( aw_value, &rchc_buffer[inc_offset],
                                                                 AT_CONF_MAX - inc_offset );
                    if ( DSL_ANONYMOUS.inc_len_user == -1 ) {
                        return false;
                    }
                    DSL_ANONYMOUS.inc_len_user--;
                    DSL_ANONYMOUS.achc_mp_user = &rchc_buffer[inc_offset];
                    inc_offset += DSL_ANONYMOUS.inc_len_user;
                    break;

                case ien_cnode_al_mp_domain:
                    aw_value                     = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    DSL_ANONYMOUS.inc_len_domain = m_conv_to_utf8( aw_value, &rchc_buffer[inc_offset],
                                                                  AT_CONF_MAX - inc_offset );
                    if ( DSL_ANONYMOUS.inc_len_domain == -1 ) {
                        return false;
                    }
                    DSL_ANONYMOUS.inc_len_domain--;
                    DSL_ANONYMOUS.achc_mp_domain = &rchc_buffer[inc_offset];
                    inc_offset += DSL_ANONYMOUS.inc_len_domain;
                    break;

                default:
                    adsc_wsp_helper->m_cb_print_out( "HWSPATW054W unknown node in anonymous-login found - ignore" );
                    break;
            }
        }

        
        //---------------------------------------
        // get next node:
        //---------------------------------------
        adsp_node = adsc_wsp_helper->m_cb_get_nextsibling( adsp_node );
    }
#undef DSL_ANONYMOUS
    return true;
} // end of ds_at_config::m_read_anonymous

#if SM_USE_CERT_AUTH
bool ds_at_config::m_read_certificate_authentication( DOMNode* adsp_node )
{
    // initialize some variables:
    DOMNode*        ads_pnode;                  // parent working node
    DOMNode*        ads_cnode;                  // child working node
    const HL_WCHAR* aw_node;                    // node name
    
    //---------------------------------------
    // read the data:
    //---------------------------------------
    ads_pnode = adsp_node;

    this->dsc_conf.ds_public.dsc_certificate_auth.adsc_entries = NULL;
    dsd_certificate_auth_entry** aadsl_last = &this->dsc_conf.ds_public.dsc_certificate_auth.adsc_entries;
    while ( ads_pnode != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( adsc_wsp_helper->m_cb_get_node_type( ads_pnode ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            aw_node = adsc_wsp_helper->m_cb_get_node_name( ads_pnode );

            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            ads_cnode = adsc_wsp_helper->m_cb_get_firstchild( ads_pnode );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            if ( adsc_wsp_helper->m_cb_get_node_type( ads_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
                continue;
            }
            
            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            dsd_unicode_string dsl_key;
            dsl_key.ac_str = (void*)aw_node;
            dsl_key.imc_len_str = -1;
            dsl_key.iec_chs_str = ied_chs_utf_16;
            ied_conf_certificate_auth ien_key = ds_wsp_helper::m_search_equals_ic2(achr_conf_certificate_type, dsl_key, (ied_conf_certificate_auth)-1);
            switch ( ien_key ) {
                case ien_cnode_ca_enabled:
                    this->dsc_conf.ds_public.dsc_certificate_auth.boc_enabled = m_is_yes(ads_cnode);
                    break;
                case ien_cnode_ca_certificate:
                    if(!this->m_read_certificate(ads_cnode, aadsl_last)) {
                        adsc_wsp_helper->m_cb_print_out( "HWSPATW022W m_read_certificate failed" );
                    }
                    break;
#if SM_USE_CERT_AUTH_V2
				case ien_cnode_ca_password_auth:
                    this->dsc_conf.ds_public.dsc_certificate_auth.boc_password_auth = !m_is_no(ads_cnode);
					break;
#endif
                default:
                    adsc_wsp_helper->m_cb_printf_out2( "HWSPATW023W unknown node %(.*)s in certificate authentication conf found in line %d - ignore",
                                                      ied_chs_utf_16, aw_node, adsc_wsp_helper->m_cb_get_node_line(ads_pnode) );
                    break;
            }
        }

        //---------------------------------------
        // get next node:
        //---------------------------------------
        ads_pnode = adsc_wsp_helper->m_cb_get_nextsibling( ads_pnode );
    } // end of while loop

    return true;
}

bool ds_at_config::m_read_utf8_string(struct dsd_utf8_string* adsp_dst, const HL_WCHAR* achp_src, int& rinp_new_offset) {
    //---------------------------
    // get value of child node:
    //---------------------------
    adsp_dst->inc_len = m_conv_to_utf8( achp_src, &this->rchc_buffer[rinp_new_offset],
                                              AT_CONF_MAX - rinp_new_offset );
    if ( adsp_dst->inc_len == -1 ) {
        return false;
    }
    adsp_dst->inc_len--;
    adsp_dst->achc_data = &this->rchc_buffer[rinp_new_offset];
    rinp_new_offset += adsp_dst->inc_len;
    return true;
}

bool ds_at_config::m_read_utf8_string(struct dsd_utf8_string* adsp_dst, DOMNode* adsp_node, int& rinp_new_offset) {
    const HL_WCHAR* aw_value = adsc_wsp_helper->m_cb_get_node_value( adsp_node );
    if(aw_value == NULL)
        return false;
    return m_read_utf8_string(adsp_dst, aw_value, rinp_new_offset);
}

bool ds_at_config::m_read_base64_string(struct dsd_utf8_string* adsp_dst, const HL_WCHAR* achp_src, int& rinp_new_offset) {
	ds_hstring dsl_base64(this->adsc_wsp_helper);
	dsd_unicode_string dsl_ucs;
	dsl_ucs.iec_chs_str = ied_chs_utf_16;
	dsl_ucs.ac_str = (void*)achp_src;
	dsl_ucs.imc_len_str = -1;
	dsl_base64.m_write(&dsl_ucs);

	ds_hstring dsl_decoded(this->adsc_wsp_helper);
	if(!dsl_decoded.m_from_b64(dsl_base64.m_get_ptr(), dsl_base64.m_get_len()))
		return false;
	if(dsl_decoded.m_get_len() > AT_CONF_MAX - rinp_new_offset)
		return false;
	char* achl_dst = &this->rchc_buffer[rinp_new_offset];
	memcpy(achl_dst, dsl_decoded.m_get_ptr(), dsl_decoded.m_get_len());
    adsp_dst->inc_len = dsl_decoded.m_get_len();
    adsp_dst->achc_data = achl_dst;
	rinp_new_offset += adsp_dst->inc_len;
    return true;
}

bool ds_at_config::m_read_base64_string(struct dsd_utf8_string* adsp_dst, DOMNode* adsp_node, int& rinp_new_offset) {
    const HL_WCHAR* aw_value = adsc_wsp_helper->m_cb_get_node_value( adsp_node );
    if(aw_value == NULL)
        return false;
    return m_read_base64_string(adsp_dst, aw_value, rinp_new_offset);
}

/**
 * Converts a hexadecimal character to it's integer represenation.
 * 
 * @param ch_hex Input hex char ('0' to '9', 'a' to 'f', 'A' to 'F').
 * @return An integer between 0 and 15 or -1 if it's a bad character.
 */
static int m_from_hex_char(HL_WCHAR ch_hex) {
	switch(ch_hex) {
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	case 'A':
	case 'a':
		return 0xa;
	case 'B':
	case 'b':
		return 0xb;
	case 'C':
	case 'c':
		return 0xc;
	case 'D':
	case 'd':
		return 0xd;
	case 'E':
	case 'e':
		return 0xe;
	case 'F':
	case 'f':
		return 0xf;
	default:
		return -1;
	}
}

/**
 * Parses the specified hexadecimal string as a byte array. Two characters of the string are combined to a single
 * byte.
 */
static int m_read_hexstring(const HL_WCHAR* wcsp_src, char* achp_out, int inp_out_max) {
    int inl_out = 0;

	while(inl_out < inp_out_max) {
        if(*wcsp_src == 0)
            return -1;
		int im_nibble_high = m_from_hex_char(*wcsp_src++);
        if(*wcsp_src == 0)
            return -1;
		int im_nibble_low = m_from_hex_char(*wcsp_src++);
		if(im_nibble_high < 0 || im_nibble_low < 0)
            return -1;
		achp_out[inl_out++] = (char) ((im_nibble_high << 4) | im_nibble_low);
	}
	return inl_out;
}

/**
 * private function ds_at_config::m_read_certificate
 *
 * @param[in]   DOMNode*    adsp_node
 * @return      bool                    true = success
*/
bool ds_at_config::m_read_certificate( DOMNode* adsp_node, struct dsd_certificate_auth_entry** (&aadsp_last) )
{
    // initialize some variables:
    DOMNode*        ads_cnode;          // child working node
    const HL_WCHAR* aw_node;            // node name
    const HL_WCHAR* aw_value;           // node value

    static const int IN_FLAG_SHA1_HASH = 1;
    static const int IN_FLAG_USER = 2;
    static const int IN_ALL_FLAGS = (IN_FLAG_SHA1_HASH | IN_FLAG_USER);
    
    int in_new_offset = ALIGN_INT(this->inc_offset);
    if((AT_CONF_MAX-in_new_offset) < sizeof(struct dsd_certificate_auth_entry))
        return false;
    struct dsd_certificate_auth_entry* adsl_auth = (struct dsd_certificate_auth_entry*)&rchc_buffer[in_new_offset];
    in_new_offset += sizeof(struct dsd_certificate_auth_entry);
    int inl_flags = 0;
    DOMNode* adsl_node = adsp_node;          // child working node
    while ( adsl_node != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( adsc_wsp_helper->m_cb_get_node_type( adsl_node ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            aw_node = adsc_wsp_helper->m_cb_get_node_name( adsl_node );

            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            ads_cnode = adsc_wsp_helper->m_cb_get_firstchild( adsl_node );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                adsl_node = adsc_wsp_helper->m_cb_get_nextsibling( adsl_node );
                continue;
            }
            if ( adsc_wsp_helper->m_cb_get_node_type( ads_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                adsl_node = adsc_wsp_helper->m_cb_get_nextsibling( adsl_node );
                continue;
            }
            
            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            dsd_unicode_string dsl_key;
            dsl_key.ac_str = (void*)aw_node;
            dsl_key.imc_len_str = -1;
            dsl_key.iec_chs_str = ied_chs_utf_16;
            ied_conf_certificate_auth ien_key = ds_wsp_helper::m_search_equals_ic2(achr_conf_certificate_type, dsl_key, (ied_conf_certificate_auth)-1);
            switch ( ien_key ) {
                case ien_cnode_ca_sha1_hash: {
                    aw_value = adsc_wsp_helper->m_cb_get_node_value( ads_cnode );
                    if(aw_value == NULL)
                        return false;
                    int inl_out = m_read_hexstring(aw_value, adsl_auth->chrc_sha1_hash, sizeof(adsl_auth->chrc_sha1_hash));
                    if(inl_out != sizeof(adsl_auth->chrc_sha1_hash))
                        return false;
                    if(aw_value[sizeof(adsl_auth->chrc_sha1_hash)*2] != 0)
                        return false;
                    inl_flags |= IN_FLAG_SHA1_HASH;
                    break;
                }
                case ien_cnode_ca_user:
                    if(!this->m_read_certificate_user(ads_cnode, adsl_auth, in_new_offset))
                        return false;
                    inl_flags |= IN_FLAG_USER;
                    break;
                default:
                    adsc_wsp_helper->m_cb_print_out( "HWSPATW024W unknown node in anonymous-login found - ignore" );
                    break;
            }
        }

        
        //---------------------------------------
        // get next node:
        //---------------------------------------
        adsl_node = adsc_wsp_helper->m_cb_get_nextsibling( adsl_node );
    }
    
    if((inl_flags & IN_ALL_FLAGS) != IN_ALL_FLAGS) {
        adsc_wsp_helper->m_cb_printf_out( "HWSPATW025W incomplete certificate entry in line %d - ignore",
            adsc_wsp_helper->m_cb_get_node_line(adsl_node) );
        return false;
    }
    
    adsl_auth->adsc_next = NULL;
    *aadsp_last = adsl_auth;
    aadsp_last = &adsl_auth->adsc_next;
    this->inc_offset = in_new_offset;
    return true;
} // end of ds_at_config::m_read_certificate

/**
 * private function ds_at_config::m_read_certificate
 *
 * @param[in]   DOMNode*    adsp_node
 * @return      bool                    true = success
*/
bool ds_at_config::m_read_certificate_user( DOMNode* adsp_node, struct dsd_certificate_auth_entry* adsp_auth, int& rinp_new_offset )
{
    // initialize some variables:
    static const int IN_FLAG_NAME = 1;
    static const int IN_FLAG_DOMAIN = 2;
	static const int IN_FLAG_PASSWORD = 4;
    static const int IN_ALL_FLAGS = (IN_FLAG_NAME | IN_FLAG_DOMAIN);
    
    int inl_flags = 0;
    DOMNode* adsl_node = adsp_node;          // child working node
    while ( adsl_node != NULL ) {
        //---------------------------------------
        // check if we have an nonempty node:
        //---------------------------------------
        if ( adsc_wsp_helper->m_cb_get_node_type( adsl_node ) == DOMNode::ELEMENT_NODE ) {
            //-----------------------------------
            // get node name:
            //-----------------------------------
            const HL_WCHAR* aw_node = adsc_wsp_helper->m_cb_get_node_name( adsl_node );

            //-----------------------------------
            // get child node and check it:
            //-----------------------------------
            DOMNode* ads_cnode = adsc_wsp_helper->m_cb_get_firstchild( adsl_node );
            if ( ads_cnode == NULL ) {
                // parent node is empty -> get next
                adsl_node = adsc_wsp_helper->m_cb_get_nextsibling( adsl_node );
                continue;
            }
            if ( adsc_wsp_helper->m_cb_get_node_type( ads_cnode ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                adsl_node = adsc_wsp_helper->m_cb_get_nextsibling( adsl_node );
                continue;
            }
            
            //-----------------------------------
            // check if this node is a known one:
            //-----------------------------------
            dsd_unicode_string dsl_key;
            dsl_key.ac_str = (void*)aw_node;
            dsl_key.imc_len_str = -1;
            dsl_key.iec_chs_str = ied_chs_utf_16;
            ied_conf_certificate_auth ien_key = ds_wsp_helper::m_search_equals_ic2(achr_conf_certificate_type, dsl_key, (ied_conf_certificate_auth)-1);
            switch ( ien_key ) {
                case ien_cnode_ca_name:
                    if(!this->m_read_utf8_string(&adsp_auth->dsc_user, ads_cnode, rinp_new_offset))
                        return false;
                    inl_flags |= IN_FLAG_NAME;
                    break;
                case ien_cnode_ca_domain:
                    if(!this->m_read_utf8_string(&adsp_auth->dsc_domain, ads_cnode, rinp_new_offset))
                        return false;
                    inl_flags |= IN_FLAG_DOMAIN;
                    break;
#if SM_USE_CERT_AUTH_V2
				case ien_cnode_ca_password_auth:
					adsp_auth->iec_password_auth = m_get_troolean(ads_cnode, ied_undefined);
                    break;
				case ien_cnode_ca_password_encrypted:
					if(!this->m_read_base64_string(&adsp_auth->dsc_password, ads_cnode, rinp_new_offset))
                        return false;
                    inl_flags |= IN_FLAG_PASSWORD;
                    break;
#endif
                default:
                    adsc_wsp_helper->m_cb_print_out( "HWSPATW024W unknown node in anonymous-login found - ignore" );
                    break;
            }
        }

        
        //---------------------------------------
        // get next node:
        //---------------------------------------
        adsl_node = adsc_wsp_helper->m_cb_get_nextsibling( adsl_node );
    }
    
    if((inl_flags & IN_ALL_FLAGS) != IN_ALL_FLAGS) {
        adsc_wsp_helper->m_cb_printf_out( "HWSPATW025W incomplete user certificate entry in line %d - ignore",
            adsc_wsp_helper->m_cb_get_node_line(adsl_node) );
        return false;
    }
    return true;
} // end of ds_at_config::m_read_certificate
#endif
