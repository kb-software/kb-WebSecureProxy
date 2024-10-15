#ifndef DS_LDAP_H
#define DS_LDAP_H

#if defined WIN32 || defined WIN64
    #include <winsock2.h>
    #include <Ws2tcpip.h>
    #include <windows.h>
#else
    #include <netinet/in.h>
    #include <hob-unix01.h>
#endif

// la; 21.04.2011 #include <hob-ldap02.hpp> // for dsd_ldap_template

#include <ds_hstring.h>
#include <ds_hvector.h>
#include <ds_wsp_helper.h>

// The defines are made similar to JAVA
#define LDAP_ORG                 "organization"
#define LDAP_OUNIT               "organizationalUnit"
#define LDAP_GROUP               "groupofuniquenames"
#define LDAP_PERSON              "person"
#define LDAP_EOBJECT             "extensibleObject"
#define LDAP_CONTAINER           "container"
#define LDAP_COMPUTER            "computer"
#define LDAP_HOB_GATEWAY         "hobgateway"
#define LDAP_SAMACCOUNTNAME      "sAMAccountName"
#define LDAP_USERACCOUNTCONTROL  "userAccountControl"
#define LDAP_DOMAIN              "domain"    
#define C_COMPANY   'o'
#define C_DEPART    'd'
#define C_GROUP     'g'
#define C_USER      'u'
#define C_OBJECT    'b'
#define C_CONTAINER 'c'
#define C_CHECK     'z'
#define C_DOMAIN    'm'

#define MS_AD_ACCOUNTDISABLE     0x000002
#define MS_AD_PASSWD_NOTREQD     0x000020
#define MS_AD_PASSWD_CANT_CHANGE 0x000040
#define MS_AD_NORMAL_ACCOUNT     0x000200
#define MS_AD_DONT_EXPIRE_PASSWD 0x010000
#define MS_AD_PASSWORD_EXPIRED   0x800000


// corresponds with achr_binary_attrs[] in ds_ldap.cpp
enum ied_binary_attrs {
    ien_binary_unknown                   = -1,     // unkown attribute name
    ien_binary_user_certificate          =  0,
    ien_binary_photo                         ,
    ien_binary_personalSignature             ,
    ien_binary_audio                         ,
    ien_binary_jpegPhoto                     ,
    ien_binary_javaSerializedData            ,
    ien_binary_thumbnailPhoto                ,
    ien_binary_thumbnailLogo                 ,
    ien_binary_userPassword                  ,
    ien_binary_cACertificate                 ,
    ien_binary_authorityRevocationList   = 10,
    ien_binary_certificateRevocationList     ,
    ien_binary_crossCertificatePair          ,
    ien_binary_x500UniqueIdentifier
};



struct dsd_co_ldap_1;         // forward definition
class ds_attribute_string;    // forward definition


class ds_ldap
{
public:
    ds_ldap();
    ~ds_ldap(void);

    void m_init         (ds_wsp_helper* adsl_wsp_helper);
    void m_init_ldap    (bool bol_insert_oc);
    void m_reset        ();

    // Retrieve informations about the LDAP server
    const ds_hstring&   m_get_last_error     ();   // retrieve the last error message
    const ds_hstring&   m_get_user_dn        ();   // Get DN of the logged on user.
    int          m_get_srv_type       ();
    int          m_get_address        (ds_hstring* ahstr);
    int          m_get_base           (ds_hstring* ahstr);
    int          m_get_userprefix     (ds_hstring* ahstr);
    int          m_get_groupmembers   (ds_hstring* ahstr);
    int          m_get_groupmembersin (ds_hstring* ahstr);
    int          m_get_searchuser     (ds_hstring* ahstr);

    // Escape meta charcters of LDAP
    int  m_escape               (ds_hstring* ahstr_to_escape, ds_hstring* ahstr_target);

    // LDAP functions
    int  m_get_bind_context     (bool* abo_is_bound, ds_hstring* ahstr_bind_dn);
    char m_get_oc_id            (const ds_attribute_string* adsl_attr);
    int  m_bind                 (const ds_hstring* ahstr_userid, const ds_hstring* ahstr_password, ied_auth_ldap_def in_mode);
    int  m_bind                 (const ds_hstring* ahstr_userid, const ds_hstring* ahstr_password, const ds_hstring* ahstr_base_add, ied_auth_ldap_def in_mode);
    int  m_bind                 (const char* ach_userid, int in_len_userid, const char* ach_password, int in_len_password, ied_auth_ldap_def in_mode);
    int  m_bind                 (const char* ach_userid, int in_len_userid, const char* ach_password, int in_len_password,
                                 const char* ach_base_add, int in_len_base_add, ied_auth_ldap_def in_auth_mode);
    int  m_simple_bind          ();
    int  m_close                ();

    int  m_is_item_in_tree      (const ds_hstring* ahstr_dn_item, const ds_hstring* ahstr_tree_dn, bool* abo_is_in_tree);
    int  m_is_item_in_tree      (const char* ach_dn_item, int in_len_dn_item, const char* ach_tree_dn, int in_len_tree_dn, bool* abo_is_in_tree);
    int  m_is_user              (const ds_hstring* ahstr_dn, bool* abo_is_user);
    int  m_is_member            (const ds_hstring* ahstr_user_dn, const ds_hstring* ahstr_group_dn, bool* abo_ret);
    int  m_is_member            (const char* ach_user_dn, int in_len_user_dn, const char* ach_group_dn, int in_len_group_dn, bool* abo_ret);
    int  m_get_membership       (ds_hvector<ds_hstring>* adsl_v_dn, const ds_hstring* ahstr_dn, bool bop_nested);
    int  m_get_members          (ds_hvector<ds_hstring>* adsl_v_dn, const ds_hstring* ahstr_dn);
    int  m_get_parent           (const ds_hstring* ahstr_dn_item, ds_hstring* ahstr_parent_dn);

    bool m_is_binary            (const ds_hstring* ahstr_attr_name);

    int  m_lookup               (const ds_hstring* ahstr_dn, ds_hstring* ahstr_dn_resolved);

    int  m_collect_attributes   (const ds_hstring* ahstr_dn, const ds_hstring* ahstr_attrname, ds_attribute_string* adsl_attrstr_own,
                                    ds_hvector<ds_attribute_string>* adsl_v_attr_groups, ds_hvector<ds_attribute_string>* adsl_v_attr_tree);
    int  m_collect_attributes   (const ds_hstring* ahstr_dn, const char* ach_attrname_zt, ds_attribute_string* adsl_attrstr_own,
                                    ds_hvector<ds_attribute_string>* adsl_v_attr_groups, ds_hvector<ds_attribute_string>* adsl_v_attr_tree);
    int  m_get_attr_list        (ds_hvector<ds_attribute_string>* adsl_v_attributes, ds_hstring* ahstr_dn, bool bo_with_val);
    int  m_read_attributes      (const ds_hstring* ahstr_attr_list, const ds_hstring* ahstr_filter, const ds_hstring* ahstr_dn, ied_scope_ldap_def iec_search_scope,
                                 ds_hvector<ds_attribute_string>* adsl_v_attributes);
    int  m_read_attributes      (const char* ach_attr_list_zt, const ds_hstring* ahstr_filter, const ds_hstring* ahstr_dn, ied_scope_ldap_def iec_search_scope,
                                 ds_hvector<ds_attribute_string>* adsl_v_attributes);
    int  m_write_attributes     (const ds_hstring* hstr_dn, dsd_ldap_attr dsl_attr_chain);

    int  m_create_user          (ds_hstring* ahstr_dn_to_create);
    int  m_createnode           (char ch_type, const ds_hstring* ahstr_username, const ds_hstring* ahstr_context, const ds_hstring* ahstr_uid,
                                 const ds_hstring* ahstr_pw, ds_hstring* ahstr_created_dn);
    int  m_deletenode           (const ds_hstring* ahstr_dn);
    int  m_change_pwd           (const ds_hstring* ahstr_userid, const ds_hstring* ahstr_pw_old, const ds_hstring* ahstr_pw_new);
    int  m_change_pwd           (const ds_hstring* ahstr_userid, const ds_hstring* ahstr_pw_old, const ds_hstring* ahstr_pw_new, const ds_hstring* ahstr_base_add);
    int  m_change_pwd           (const char* ach_userid, int in_len_userid, const char* ach_pw_old, int in_len_pw_old, const char* ach_pw_new, int in_len_pw_new);
    int  m_change_pwd           (const char* ach_userid, int in_len_userid, const char* ach_pw_old, int in_len_pw_old, const char* ach_pw_new, int in_len_pw_new,
                                 const char* ach_base_add, int in_len_base_add);
    int  m_get_pw_expire_time   (const ds_hstring* ahstr_dn, dsd_ldap_pwd* adsl_ldap_pwd);

    int  m_cut_prefix           (const ds_hstring* ahstr_with_prefix, ds_hstring* ahstr_without_prefix);
    int  m_get_first_token_of_dn(const ds_hstring* ahstr_dn, ds_hstring* ahstr_first_token);
    int  m_get_tree_dns         (const ds_hstring* ahstr_dn, ds_hvector<ds_hstring>* adsl_v_dns, bool bo_tokenize_base, bool bo_is_comlete_dn);
    int  m_tokenize_dn          (const ds_hstring* ahstr_dn, ds_hvector<ds_hstring>* adsl_tokens, bool bo_tokenize_base, bool bo_is_comlete_dn);
    int  m_insert_objectclass   (const ds_hstring* ahstr_oc, const ds_hstring* ahstr_dn, bool bo_insert_oc);

private:
    ds_wsp_helper* ads_wsp_helper;
    dsd_co_ldap_1 adsc_co_ldap;

    ds_hstring hstr_last_error;
    ds_hstring hstr_our_dn;
    ds_hstring hstrg_address;
    ds_hstring hstrg_base;
    ds_hstring hstrg_user_prefix;
    ds_hstring hstrg_attrname_group;
    ds_hstring hstrg_attrname_groupmembers;
    ds_hstring hstrg_attrname_groupmembersin;
    ds_hstring hstrg_searchuser;

    int    ing_ldap_srv_type;
    bool   bog_insert_oc;
    bool   bog_sysinfo_done;

    int  m_bind          (bool bo_simple_bind, const char* ach_userid, int in_len_userid, const char* ach_password, int in_len_password,
                          const char* ach_base_add, int in_len_base_add, ied_auth_ldap_def in_auth_mode);

    int  m_get_sysinfo   ();

    int  m_create_user   (ds_hstring* ahstr_dn, bool bo_dn_with_prefix, const ds_hstring* ahstr_name, const ds_hstring* ahstr_uid, const ds_hstring* ahstr_pw);
    int  m_create_group  (ds_hstring* ahstr_dn, const ds_hstring* ahstr_name);
    int  m_create_ou     (ds_hstring* ahstr_dn, const ds_hstring* ahstr_name);
    int  m_create_object (ds_hstring* ahstr_dn, const ds_hstring* ahstr_name);
    int  m_create_domain (ds_hstring* ahstr_dn, const ds_hstring* ahstr_name);

    //int  m_create_pw_utf16         (ds_hstring* ahstr_pw, ds_hstring* ahstr_pw_utf16);

    int  m_convert_to_vector       (dsd_ldap_attr_desc* adsl_attr_desc_curr, ds_hvector<ds_attribute_string>* dsl_v_attributes);
    int  m_copy_val_to_attrstring  (dsd_ldap_val* adsl_val, ds_attribute_string* adsl_attrstring);
};


#endif  // DS_LDAP_H

