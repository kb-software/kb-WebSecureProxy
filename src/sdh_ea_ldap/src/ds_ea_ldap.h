#ifndef _DS_EA_LDAP_H
#define _DS_EA_LDAP_H

/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| ========                                                            |*/
/*|   ds_ea_ldap                                                        |*/
/*|   main working class for sdh_ea_ldap                                |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| =======                                                             |*/
/*|   Joachim Frank 2009/03/25                                          |*/
/*|                                                                     |*/
/*| Copyright:                                                          |*/
/*| ==========                                                          |*/
/*|   HOB GmbH Germany 2009                                             |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#include "./utils/ds_crypt.h"

#include <ds_xml.h>
#include <ds_ldap.h>

#include <types_defines.h>
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H
#include <hob-default-values.h>

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/

#ifdef HL_UNIX
    #include <stdint.h>
#else
    typedef unsigned long long uint64_t;
#endif //HL_UNIX

#define INVCHAR_ESCAPE   0x0760


// Xml tags (in alphabetical order)
#define TAG_ATTRIBUTES   "attributes"
#define TAG_BINARY       "binary"
#define TAG_CONTEXT      "context"
#define TAG_DCN          "dcn"
#define TAG_DN           "dn"
#define TAG_DNN          "dnn"
#define TAG_EATYPE       "eatype"   // JF 07.12.10
#define TAG_GETTREE      "gettree"
#define TAG_ID           "id"
#define TAG_ESCAPED_ROOT "__."
#define TAG_MEMBER       "Member"
#define TAG_NAME         "name"
#define TAG_OBJECTCLASS  "objectclass"
#define TAG_OLDVALUE     "oldvalue"
#define TAG_OWN          "own"
#define TAG_P_RET        "p_ret"
#define TAG_PASSWORD     "password"
#define TAG_RCN          "rcn"
#define TAG_RID          "rid"
#define TAG_RNN          "rnn"
#define TAG_TREE         "tree"
#define TAG_TYPE         "type"
#define TAG_UID          "uid"
#define TAG_USER         "user"
#define TAG_VALUE        "value"
#define TAG_VERIFY       "verify"
#define TAG_WRITE_MODE   "writemode"

#define DN_SEPARATOR     ","



// userfield keys:
enum ied_usrfld_key {
    USRFLD_NOTSET    = 0,   // not set
    USRFLD_STORAGE   = 1,   // storage container
    USRFLD_SENDQUEUE        // send queue
};


// corresponds with achr_proto_nodes[] in ds_ea_ldap.cpp
enum ied_proto_nodes {
    ien_pnode_unknown     = -1,     // unkown protocol node
    ien_pnode_root_uscore =  0,
    ien_pnode_user            ,
    ien_pnode_password        ,
    ien_pnode_secure          ,
    ien_pnode_message         ,
    ien_pnode_dn              ,
    ien_pnode_fn              ,
    ien_pnode_id              ,
    ien_pnode_issuperadmin    ,
    ien_pnode_isadmin         ,
    ien_pnode_issrvaddr   = 10,
    ien_pnode_memberof        ,
    ien_pnode_cmd             ,
    ien_pnode_dnn             ,
    ien_pnode_xml             ,
    ien_pnode_root            ,
    ien_pnode_conn_state
};

// Commands of EA protocol
enum ied_cmd_ea {
    ien_cmd_connect     =  0x1,
    ien_cmd_getfiles    =  0x2,
    ien_cmd_putfiles    =  0x3,
    ien_cmd_deletefile  =  0x4,
    ien_cmd_reload      =  0x5,
    ien_cmd_createnode  =  0x6,
    ien_cmd_deletenode  =  0x7,
    ien_cmd_disconnect  =  0x8,
    ien_cmd_resume      =  0x9,
    ien_cmd_checkadm    =  0xA,
    ien_cmd_metering    =  0xB,
    ien_cmd_generic     =  0x10
};

// Generic commands (only those, which are necessary).
enum ied_generic_commands {
    ien_gen_cmd_copy           =   0,
    ien_gen_cmd_move           =   1,
    ien_gen_cmd_tree           =   3,
    ien_gen_cmd_member         =   4,
    ien_gen_cmd_memberof       =   5,
    ien_gen_cmd_ldapa          =   8,
    ien_gen_cmd_copy_set       =  10,
    ien_gen_cmd_idfromdn       =  11,
    ien_gen_cmd_dnfromid       =  12,
    ien_gen_cmd_gettype        =  13,
    ien_gen_cmd_isuserintree   =  15,
    ien_gen_cmd_getparent      =  16,
    ien_gen_cmd_search         =  34,
    ien_gen_cmd_verify         =  35,
    ien_gen_cmd_put_attr       =  36,
    ien_gen_cmd_put_ldap_attr  =  38,
    ien_gen_cmd_gethls         =  91
};

// States inside EA protocol
enum ied_states_ea {
    ien_sts_resp    =  0x0,
    ien_sts_cmd     =  0x1,
    ien_sts_ack     =  0x2,
    ien_sts_neg     =  0x4
};

// Inherit request modes. How a client will request files.
enum ied_inherit_request_modes {
    ien_inh_req_own      =  0x0,
    ien_inh_req_other    =  0x1,
    ien_inh_req_all      =  0x2
};



/*+---------------------------------------------------------------------+*/
/*| helper structures definition:                                       |*/
/*+---------------------------------------------------------------------+*/
struct dsd_recbuffer {
    char*   ach_ptr;                // pointer to data
    int     in_expected;            // expected length
    int     in_received;            // received length
};


struct dsd_ea_header {          // Header of the EA protocol (28 bytes)
    int    in_total_len;        // Total length of this packet (these 4 bytes are inclusive) 
    int    in_state;            // 
    int    in_version;          // 
    int    in_element;          // 
    int    in_exception;        // 
    int    in_command;          // 
    int    in_param1;           // 
};

struct dsd_item_gettree {       // Similar to Startup.java (holds data for 'connect')
    ds_hstring  hstr_tag_name;        // tag name of this item in xml; e.g. dn0
    ds_hstring  hstr_name;            // name of this item; e.g. dc=hoadstest,dc=de
    ds_hstring  hstr_id;              // id of this item; e.g. zdc=hoadstest,dc=de
};

/*+---------------------------------------------------------------------+*/
/*| class definition:                                                   |*/
/*+---------------------------------------------------------------------+*/
class ds_wsp_helper;                            // forward definition
class ds_hstring;                               // forward definition
typedef struct dsd_ea_config dsd_ea_config_t;   // forward definition
struct dsd_xml_tag;                             // forward definition
class ds_attribute_string;                      // forward definition
struct dsd_domain;                              // forward definition
template <class T> class ds_hvector;            // forward definition

class ds_ea_ldap {
public:
    // constructor:
    ds_ea_ldap();

    // destructor:
    ~ds_ea_ldap();

    // new operator:
    void* operator new(size_t, void* av_location) {
        return av_location;
    }
    // avoid warning:
    void operator delete( void*, void* ) {};

    // functions:
    void m_send_msg_to_mgmt();
    void m_recv_msg_from_mgmt();
    void m_init     ( ds_wsp_helper* ads_wsp_helper_in );
    int  m_run      ( );

    // variables:
    void* av_storage;                       // storage container pointer
    BOOL  boc_callagain;                    // workaround for wsp bug

private:
    // variables:
    ds_wsp_helper*        adsc_wsp_helper;   // wsp helper class
    ds_ldap               dsc_ldap;          // ldap working class
    dsd_ea_config*        adsc_config;       // our configuration

    struct dsd_domain        *adsc_domain;     // current users domain
    ds_hvector<ds_hstring> dsc_not_allowed_attr; // allowed ldap attributes for write access

    int    inc_ldap_srv_type;
    bool   boc_insert_oc;
    int    inc_conn_state;
    //AK--------------------------------------------------
    bool boc_auth_equals_config_ldap;
    bool boc_to_server;
    //end AK----------------------------------------------

    ds_hstring hstrc_ldap_address, hstrc_ldap_base, hstrc_ldap_userprefix, hstrc_ldap_searchuser;
    ds_hstring hstrc_ldap_groupmembers, hstrc_ldap_groupmembersin;
    //AK---------------------------------------------------
    ds_hstring hstrc_real_user_dn;
    //end AK-----------------------------------------------
    ds_hvector<ds_hstring> dsc_group_dns_of_logged_user;
    ds_hvector<ds_hstring> dsc_tree_dns_of_logged_user;

    struct dsd_recbuffer dsc_payload;

    struct dsd_recbuffer  dsc_xmlbuf;        // receive buffer for xml data

    struct dsd_ea_header  dsc_ea_hdr_in;
    struct dsd_ea_header  dsc_ea_hdr_out;

    ds_crypt              dsc_crypt;


    // state variable:
    enum ied_sdh_pstate {        
        ien_read_header,
        ien_read_data,
        ien_handle_input
    } ienc_state;

    // functions:
    int m_handle_data    ( struct dsd_gather_i_1* ads_gather );

    int  m_connect            (ds_hstring* ahstr_domain_username, ds_hstring* ahstr_pw_enc, ds_hstring* ahstr_err_msg);
    int  m_getfiles           (ds_hstring* ahstr_resp, int* ain_count_written_elements, ds_hstring* ahstr_err_msg);
    int  m_putfiles           (ds_hstring* ahstr_err_msg);
    int  m_createnode         (ds_hstring* hstr_created_dn, ds_hstring* ahstr_err_msg);
    int  m_deletenode         (ds_hstring* ahstr_err_msg);
    int  m_generic            (ds_hstring* ahstr_resp, ds_hstring* ahstr_err_msg);

    int  m_get_tree           (ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg);
    int  m_copy_move          (ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg, bool bo_move);
    int  m_search             (ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg);
    int  m_verify             (ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg);
    int  m_isuserintree       (ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg, int in_cmd);
    int  m_members            (ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg);
    int  m_membership         (ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg);
    int  m_ldapa              (ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg);
    int  m_dn_id              (ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, int in_cmd, ds_hstring* ahstr_err_msg);
    int  m_gettype            (ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg);
    int  m_put_attr           (ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_data, ds_hstring* ahstr_err_msg);
    int  m_put_ldap_attr      (ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg);

    // MG 15.10.2012:
    int  m_modify_dn     ( ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg, bool bo_move);

    // MJ 14.01.2012:
    bool m_reset_password( const char *achp_dn, int inp_len_dn, const char *achp_npwd, int inp_len_npwd );

    //AK 14.06.2012:
    bool m_set_add_rights( ds_hstring* dsl_user_dn );
    bool m_del_add_rights( ds_hstring* dsl_user_dn );

    int  m_start_communic_mgmt();
    //AK 31.05.2012
    bool m_is_new_subdomain( ds_hstring* ahstr_dn, ds_hstring* ahstr_name );
    int  m_write_domain_aci( ds_hstring* hstr_dn );
    bool  m_create_dadmin_group( ds_hstring* hstr_dn );
    struct dsd_ldap_attr_desc* m_explode_dn( const char *achp_dn, int inp_length );
    bool m_clone_dn( struct dsd_ldap_attr_desc *adsp_exploded, const char *achp_base, int inp_length );
    //end AK
    bool m_is_attribute_not_allowed( const char *achp_attr, int inp_length );
    bool m_get_mgmt_port ( ds_hstring* adsp_ineta, int* ainp_port );
    int  m_write_attributes   (ds_hstring* ahstr_dn, dsd_ldap_attr dsl_attr_chain, bool bo_delete, ds_hstring* ahstr_err_msg);

    int  m_create_resp_member (ds_hstring* ahstr_resp, ds_hvector<ds_hstring>* adsl_v_dns);
    void m_create_resp_connect(ds_hstring* ahstr_resp, ds_hstring* ahstr_domain_username, ds_hstring* ahstr_pw_enc, ds_hvector<ds_hstring>* adsl_v_dn);
    int  m_create_resp_gettree(ds_hstring* ahstr_resp, ds_hvector_btype<dsd_item_gettree>* adsl_v_items);
    int  m_write_singlevalue_attr_to_resp  (ds_hstring* ahstr_target, const ds_attribute_string* adsl_attr, bool bo_own);

    int  m_send_response      (int in_command, int in_state, int in_element, const char* ach_data_zero_terminated);
    int  m_send_response      (int in_command, int in_state, int in_element, const char* ach_data, int in_len_msg);
    int  m_set_ea_hdr         (dsd_ea_header& dsl_ea_hdr, char* ach_buf, int in_total_len, int in_state, int in_version, int in_element, int in_exception, int in_command, int in_param1);

    int  m_decrypt_password   (const char* ach_pw_encrypted, const char* ach_username_utf8, ds_hstring* ahstr_pw_clear_utf8);
    int  m_encrypt_password   (const char* ach_pw_clear_utf8, const char* ach_username_utf8, ds_hstring* ahstr_pw_encrypted);

    bool   m_hdr_to_array            (dsd_ea_header dsl_ea_hdr, char* ach_buf);
    void   m_write_int_to_hob_header (char* ach, int in_insert, int in_pos);
    int    m_read_int                (char* ach, int in_pos);
    int    m_write_int               (ds_hstring* ahstr_target, int in_to_write);
    int    m_get_tree_elements       (ds_hstring* hstr_dn_parent, ds_hvector_btype<dsd_item_gettree>* ads_v_items);

    char   m_check_escape            (ds_hstring* ahstr);
    int    m_esc_chars_xml           (ds_hstring* ahstr, bool bo_value);
    int    m_esc_chars_tree          (ds_hstring* ahstr);
    int    m_decode_xml              (ds_hstring* ahstr);
    
    ds_hstring m_get_ldap_filename   (ds_hstring* ahstr_filename);

    // xml reading functions:
    int             m_read_xml_connect    (const char* ach_xml, int in_len, ds_hstring* ahstr_domain_username, ds_hstring* ahstr_domain, ds_hstring* ahstr_username, ds_hstring* hstr_pw_enc);
    bool            m_get_int     ( const char* ach, int in_offset, int* ain_out );
    ied_proto_nodes m_get_node_key( const char* ach_node, int in_len_node, ied_charset ien_encoding );

    // helper functions:
    void     m_mark_processed ( struct dsd_gather_i_1* ads_gather, int* ain_offset, int* ain_length );
    int      m_get_gather_len ( struct dsd_gather_i_1* ads_gather);
    char*    m_get_ptr        ( struct dsd_gather_i_1* ads_gather, int in_offset );
    char*    m_get_buf        ( struct dsd_gather_i_1* ads_gather, int in_offset, int in_requested, int* ain_received );
    uint64_t m_to_number      ( struct dsd_gather_i_1* ads_gather, int* ain_offset, int in_len, int in_type );
    void     m_from_number    ( uint64_t il_num, unsigned char* ach_buffer, int in_len, int in_type );
};

#endif //_DS_EA_LDAP_H
