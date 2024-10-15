#ifndef _DS_XML_H
#define _DS_XML_H
/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*|                                                                     |*/
/*|                                                                     |*/
/*|                                                                     |*/
/*|                                                                     |*/
/*|                                                                     |*/
/*|                                                                     |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
#define XML_DEF_TAGS    30
#define XML_DEF_ATTR    10

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| helper structure definitions:                                       |*/
/*+---------------------------------------------------------------------+*/
enum ied_xml_type {
    ied_tag,
    ied_value,
    ied_xmltype,
    ied_data
};

struct dsd_xml_attr {
    const char*                   ach_name;       // name of attribute
    int                     in_len_name;    // length of attribute
    const char*                   ach_value;      // value of attribute
    int                     in_len_value;   // length of attribute
    struct dsd_xml_attr*    ads_next;       // next attribute
};

struct dsd_xml_tag {
    ied_xml_type            ien_type;       // type of this structure
    const char*                   ach_data;       // data
    int                     in_len_data;    // length of date
    struct dsd_xml_attr*    ads_attr;       // attribute list
    dsd_xml_tag*            ads_child;      // child tag
    dsd_xml_tag*            ads_next;       // next tag
    dsd_xml_tag*            ads_prev;       // previous next pointer
};

struct dsd_xml_key {
    const char*           ach_name;               // name of key
    int             in_len_name;            // length of key name
    dsd_xml_key*    ads_next;               // next key
};

/*+---------------------------------------------------------------------+*/
/*| class defintion:                                                    |*/
/*+---------------------------------------------------------------------+*/
class ds_wsp_helper;                // forward definition
class ds_hstring;                   // forward definition
struct dsd_xml_tag_cache;           // forward definition
struct dsd_xml_attr_cache;          // forward definition
struct dsd_const_string;

class ds_xml {
public:
    // constructor:
    ds_xml();

    // destuctor:
    ~ds_xml();

    // functions:
    void         m_init     ( ds_wsp_helper* ads_wsp_helper_in );
    void         m_clear    ();
    void         m_include_ws();
    void         m_include_datatags();
    dsd_xml_tag* m_from_xml ( const char* ach_data, int in_len );
    dsd_xml_tag* m_from_xml ( const dsd_const_string& ads_xml );
    void         m_to_xml   ( dsd_xml_tag* ads_node, ds_hstring* ads_xml );

    // caching functions:
    int          m_get_cache_len( dsd_xml_tag* ads_node );
    bool         m_write_cache  ( char* ach_cache, int in_len, dsd_xml_tag* ads_node );
    dsd_xml_tag* m_read_cache   ( char* ach_cache, int in_len );

    // reading functions:
    ied_charset  m_get_encoding ();
    dsd_xml_tag* m_get_firstnode();
    static dsd_xml_tag*  m_get_firstchild ( dsd_xml_tag* ads_node );
    static dsd_xml_tag*  m_get_nextsibling( dsd_xml_tag* ads_node );
    static ied_xml_type  m_get_node_type  ( dsd_xml_tag* ads_node );
    static void          m_get_node_name  ( dsd_xml_tag* ads_node, const char** aach_name,  int* ain_len );
    static void          m_get_node_value ( dsd_xml_tag* ads_node, const char** aach_value, int* ain_len );
    static dsd_xml_attr* m_get_attribute  ( dsd_xml_tag* ads_node );
    static dsd_xml_attr* m_get_nextattr   ( dsd_xml_attr* ads_attr );
    static void          m_get_attr_name  ( dsd_xml_attr* ads_attr, const char** aach_name,  int* ain_len );
    static void          m_get_attr_value ( dsd_xml_attr* ads_attr, const char** aach_value, int* ain_len );

    // creating functions:
    static void m_create_tag ( dsd_xml_tag* ads_tag, const char* ach_name, int in_len_name, ied_xml_type ien_type = ied_tag );
    static void m_add_value  ( dsd_xml_tag* ads_tag, dsd_xml_tag* ads_child, const char* ach_value, int in_len_value );
    static void m_add_child  ( dsd_xml_tag* ads_parent, dsd_xml_tag* ads_child );
    static void m_add_next   ( dsd_xml_tag* ads_parent, dsd_xml_tag* ads_next  );
    static void m_create_attr( dsd_xml_attr* ads_attr, const char* ach_name, int in_len_name, const char* ach_value, int in_len_value );
    static void m_add_attr   ( dsd_xml_tag* ads_tag, dsd_xml_attr* ads_attr );

    // new creating functions:
    dsd_xml_tag* m_create_tag( const char* ach_name, int in_len_name, ied_xml_type ien_type = ied_tag );
    dsd_xml_tag* m_create_tag( const dsd_const_string& rdsp_name, ied_xml_type ien_type = ied_tag );
    dsd_xml_tag* m_add_next  ( dsd_xml_tag* ads_parent, const char* ach_name, int in_len_name, ied_xml_type ien_type = ied_tag );
    dsd_xml_tag* m_add_child ( dsd_xml_tag* ads_parent, const char* ach_name, int in_len_name, ied_xml_type ien_type = ied_tag  );
    dsd_xml_tag* m_add_child ( dsd_xml_tag* ads_parent, const dsd_const_string& rdsp_name );
    bool         m_add_value ( dsd_xml_tag* ads_tag, const char* ach_value, int in_len_value );
    bool         m_add_value ( dsd_xml_tag* ads_tag, const dsd_const_string& rdsp_name );
    bool         m_add_attr  ( dsd_xml_tag* ads_tag, const char* ach_name, int in_len_name, const char* ach_value, int in_len_value );

    // key list functions:
    dsd_xml_key* m_get_keys ( dsd_xml_tag* ads_node );
    dsd_xml_tag* m_get_value( dsd_xml_tag* ads_node, const char* ach_key, int in_len_key, const char** aach_value, int* ain_len_value );
    dsd_xml_tag* m_get_value( dsd_xml_tag* ads_node, const dsd_const_string& ach_key, const char** aach_value, int* ain_len_value );

    // JF
    int        m_read_int(dsd_xml_tag* ads_node, const char* ach_nodename, int in_len_nodename, int in_default);
    int        m_read_int(dsd_xml_tag* ads_node, const dsd_const_string& ach_nodename, int in_default);
    ds_hstring m_read_string(dsd_xml_tag* ads_node, const char* ach_nodename, int in_len_nodename, const char* ach_def, int in_len_def);
    bool       m_read_bool(dsd_xml_tag* ads_node, const char* ach_nodename, int in_len_nodename, bool bo_default);
    bool       m_read_bool(dsd_xml_tag* ads_node, const dsd_const_string& ach_nodename, bool bo_default);
    ds_hstring m_read_array(dsd_xml_tag* ads_node, const char* ach_nodename, int in_len_nodename);
    bool       m_is_yes      ( const char* ach_ptr, int in_len );
    
public:
    // variables:
    ds_wsp_helper*  ads_wsp_helper;             // wsp helper class
    dsd_xml_tag*    ads_chain;                  // our tag chain
    dsd_xml_key*    ads_key_chain;              // our key chain
#if XML_DEF_TAGS
    dsd_xml_tag     dsr_tags[XML_DEF_TAGS];     // tags array
    dsd_xml_key     dsr_key[XML_DEF_TAGS];      // key array
#endif
#if XML_DEF_ATTR
    dsd_xml_attr    dsr_attr[XML_DEF_ATTR];     // attributes array
#endif
    int             in_used_tags;               // used entries in dsr_tags
    int             in_used_attr;               // used entries in dsr_attr
    int             in_used_keys;               // used entries in dsr_key
    bool            bo_show_ws;                 // include withspaces
    bool            bo_show_data;               // include data (might be commends and other <! tags)

    // encoding:
    enum ied_charset ien_encoding;

    // functions:
    bool m_parse_data ( const char* ach_data, int in_len,
                        dsd_xml_tag* ads_out );
    virtual bool m_get_tag( const char* ach_data, int in_len, int* ain_pos,
                            const char** aach_tag, int* ain_len_tag );
    bool m_get_end_tag( const char* ach_data, int in_len, int* ain_pos,
                        int* ain_tag_start, const char* ach_tag, int in_len_tag );
    bool m_parse_tag  ( const char* ach_tag, int in_len_tag, dsd_xml_tag* ads_out );

    void m_move_char_pointer( const char** aach_data, int* ain_len_data, int* ain_position );
    bool m_add_type( ied_xml_type ien_type );
    bool m_only_ws(const char* ach_data, int in_len);

    dsd_xml_tag*  m_get_next    ( dsd_xml_tag* ads_in );
    dsd_xml_tag*  m_get_child   ( dsd_xml_tag* ads_in );
    dsd_xml_tag*  m_get_new_tag ();
    dsd_xml_attr* m_get_next    ( dsd_xml_attr* ads_in );
    dsd_xml_attr* m_get_new_attr();
    dsd_xml_key*  m_get_next    ( dsd_xml_key* ads_in );
    ied_charset   m_get_encoding( const char* ach_ptr, int in_len );

    // writing functions:
    void m_write_tag( dsd_xml_tag* ads_in, ds_hstring* ads_xml );
    
    // free memory functions:
    void m_free_memory( dsd_xml_tag*  ads_in );
    bool m_is_in_stack( dsd_xml_tag*  ads_in );
    void m_free_memory( dsd_xml_attr* ads_in );
    bool m_is_in_stack( dsd_xml_attr* ads_in );
    void m_free_memory( dsd_xml_key*  ads_in );
    bool m_is_in_stack( dsd_xml_key*  ads_in );

    // caching functions:
    int  m_evaluate_tag_length ( dsd_xml_tag* ads_tag );
    int  m_evaluate_attr_length( dsd_xml_attr* ads_attr );
    bool m_copy_tag ( char* ach_cache, int in_len, int* ain_offset, dsd_xml_tag* ads_tag, int* ain_index );
    bool m_copy_attr( char* ach_cache, int in_len, int* ain_offset, dsd_xml_attr* ads_attr, int* ain_index );
    dsd_xml_tag_cache*  m_read_tag ( char* ach_cache, int in_len, int in_index );
    dsd_xml_attr_cache* m_read_attr( dsd_xml_tag_cache* ads_tag, int in_index );
    bool m_parse_cache     ( dsd_xml_tag* ads_out, char* ach_cache, int in_len, int in_index );
    bool m_parse_attr_cache( dsd_xml_attr* ads_out, dsd_xml_tag_cache* ads_tag, int in_index );
};

#endif // _DS_XML_H


