/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>
#include <ds_hstring.h>
#include <ds_xml.h>
#include <align.h>
#ifdef HL_UNIX
    #include <ctype.h>
#endif


/*+---------------------------------------------------------------------+*/
/*| helper structure definitions:                                       |*/
/*+---------------------------------------------------------------------+*/

struct dsd_xml_tag_cache {
    ied_xml_type    ien_type;       // type of this structure
    int             in_len_data;    // length of date
    int             in_attr;        // attribute list
    int             in_child;       // child tag
    int             in_next;        // next tag
};

struct dsd_xml_attr_cache {
    int             in_len_name;    // length of attribute
    int             in_len_value;   // length of attribute
    int             in_next;        // next attribute
};

/*+---------------------------------------------------------------------+*/
/*| encoding definitions:                                               |*/
/*+---------------------------------------------------------------------+*/
// compare to definition of enum ied_charset
static const dsd_const_string achr_xml_encodings[] = {
    "invalid"   , "ISO-8859-1"  , "ISO-8859-1"  , "UTF-8"       ,
    "UTF-16"    , "invalid"     , "invalid"     , "UTF-32"      ,
    "invalid"   , "invalid"     , "invalid"
};


/*+---------------------------------------------------------------------+*/
/*| constructor:                                                        |*/
/*+---------------------------------------------------------------------+*/
ds_xml::ds_xml() 
{
    ads_wsp_helper = NULL;
    ads_chain      = NULL;
    ads_key_chain  = NULL;
    in_used_tags   = 0;
    in_used_attr   = 0;
    in_used_keys   = 0;
    bo_show_ws     = false;
    bo_show_data   = false;
    ien_encoding   = ied_chs_utf_8;
#if XML_DEF_TAGS
    memset( dsr_tags, 0, XML_DEF_TAGS * sizeof(struct dsd_xml_tag)  );
    memset( dsr_key,  0, XML_DEF_TAGS * sizeof(struct dsd_xml_key)  );
#endif
#if XML_DEF_ATTR
    memset( dsr_attr, 0, XML_DEF_ATTR * sizeof(struct dsd_xml_attr) );
#endif
} // end of ds_xml::ds_xml

/*+---------------------------------------------------------------------+*/
/*| destructor:                                                         |*/
/*+---------------------------------------------------------------------+*/
ds_xml::~ds_xml()
{
    m_clear();
} // end of ds_xml::~ds_xml


/*+---------------------------------------------------------------------+*/
/*| static functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_xml::m_get_firstchild
 * get first child element
 *
 * @param[in]   dsd_xml_tag*    ads_node
 * @return      dsd_xml_tag*
*/
dsd_xml_tag* ds_xml::m_get_firstchild( dsd_xml_tag* ads_node )
{
    if ( ads_node == NULL ) {
        return NULL;
    }
    return ads_node->ads_child;
} // end of ds_xml::m_get_fistchild


/**
 * function ds_xml::m_get_nextsibling
 * get next sibling
 *
 * @param[in]   dsd_xml_tag*    ads_node
 * @return      dsd_xml_tag*
*/
dsd_xml_tag* ds_xml::m_get_nextsibling( dsd_xml_tag* ads_node )
{
    if ( ads_node == NULL ) {
        return NULL;
    }
    return ads_node->ads_next;
} // end of ds_xml::m_get_nextsibling


/**
 * function ds_xml::m_get_attribute
 * get next sibling
 *
 * @param[in]   dsd_xml_tag*    ads_node
 * @return      dsd_xml_tag*
*/
dsd_xml_attr* ds_xml::m_get_attribute( dsd_xml_tag* ads_node )
{
    if ( ads_node == NULL ) {
        return NULL;
    }
    return ads_node->ads_attr;
} // end of ds_xml::m_get_attribute


/**
 * function ds_xml::m_get_nextattr
 * get next attribute
 *
 * @param[in]   dsd_xml_attr*   ads_attr
 * @return      dsd_xml_attr*
*/
dsd_xml_attr* ds_xml::m_get_nextattr( dsd_xml_attr* ads_attr )
{
    if ( ads_attr == NULL ) {
        return NULL;
    }
    return ads_attr->ads_next;
} // end of ds_xml::m_get_nextattr


/**
 * function ds_xml::m_get_attr_name
 * get name of attribute
 * 
 * @param[in]   dsd_xml_attr*   ads_attr
 * @param[in]   char**          aach_name       pointer to attr name
 * @param[in]   int*            ain_len         length of attr name
*/
void ds_xml::m_get_attr_name( dsd_xml_attr* ads_attr, 
                              const char** aach_name, int* ain_len )
{
    if ( ads_attr == NULL ) {
        *aach_name = NULL;
        *ain_len   = 0;
        return;
    }
    *aach_name = ads_attr->ach_name;
    *ain_len   = ads_attr->in_len_name;
} // end of ds_xml::m_get_attr_name


/**
 * function ds_xml::m_get_attr_value
 * get value of attribute
 * 
 * @param[in]   dsd_xml_attr*   ads_attr
 * @param[in]   char**          aach_value      pointer to attr value
 * @param[in]   int*            ain_len         length of attr value
*/
void ds_xml::m_get_attr_value( dsd_xml_attr* ads_attr, 
                               const char** aach_value, int* ain_len )
{
    if ( ads_attr == NULL ) {
        *aach_value = NULL;
        *ain_len    = 0;
        return;
    }
    *aach_value = ads_attr->ach_value;
    *ain_len    = ads_attr->in_len_value;
} // end of ds_xml::m_get_attr_value


/**
 * function ds_xml::m_get_node_type
 * get node type
 *
 * @param[in]   dsd_xml_tag*    ads_node
 * @return      ied_xml_type
*/
ied_xml_type ds_xml::m_get_node_type( dsd_xml_tag* ads_node )
{
    return ads_node->ien_type;
} // end of ds_xml::m_get_node_type


/**
 * function ds_xml::m_get_node_name
 * get name of node
 *
 * @param[in]   dsd_xml_tag*    ads_node
 * @param[in]   char**          aach_name       pointer to tag name
 * @param[in]   int*            ain_len         length of tag name
*/
void ds_xml::m_get_node_name( dsd_xml_tag* ads_node,
                              const char** aach_name, int* ain_len )
{
    if ( ads_node == NULL ) {
        *aach_name = NULL;
        *ain_len   = 0;
        return;
    }
    if ( ads_node->ien_type == ied_tag ) {
        *aach_name = ads_node->ach_data;
        *ain_len   = ads_node->in_len_data;
    } else {
        *aach_name = NULL;
        *ain_len   = 0;
    }
} // end of ds_xml::m_get_node_name


/**
 * function ds_xml::m_get_node_value
 * get node value
 *
*/
void ds_xml::m_get_node_value( dsd_xml_tag* ads_node,
                               const char** aach_value, int* ain_len )
{
    if ( ads_node == NULL ) {
        *aach_value = NULL;
        *ain_len    = 0;
        return;
    }
    if ( ads_node->ien_type == ied_tag ) {
        if (    ( ads_node->ads_child           != NULL      )
             && ( ads_node->ads_child->ads_next == NULL      )
             && ( ads_node->ads_child->ien_type == ied_value ) ) {
            *aach_value = ads_node->ads_child->ach_data;
            *ain_len    = ads_node->ads_child->in_len_data;
        } else {
            *aach_value = NULL;
            *ain_len    = 0;
        }
    } else {
        *aach_value = ads_node->ach_data;
        *ain_len    = ads_node->in_len_data;
    }
} // end of ds_xml::m_get_node_value


/**
 * function ds_xml::m_create_tag
 * create a tag into ads_tag
 *
 * @param[in]   dsd_xml_tag*    ads_tag         output
 * @param[in]   char*           ach_name        name of tag
 * @param[in]   int             in_len_name     length of tag name
 * @param[in]   ied_xml_type    ien_type        type of tag
 *                                              default = ied_tag
*/
void ds_xml::m_create_tag( dsd_xml_tag* ads_tag,
                           const char* ach_name, int in_len_name,
                           ied_xml_type ien_type )
{
    ads_tag->ach_data    = ach_name;
    ads_tag->in_len_data = in_len_name;
    ads_tag->ien_type    = ien_type;
    ads_tag->ads_attr    = NULL;
    ads_tag->ads_child   = NULL;
    ads_tag->ads_next    = NULL;
} // end of ds_xml::m_create_tag


/**
 * function ds_xml::m_add_value
 * add value to tag ads_tag
 *
 * @param[in]   dsd_xml_tag*    ads_tag         output
 * @param[in]   dsd_xml_tag*    ads_child       child buffer to add
 * @param[in]   char*           ach_value       value of tag
 * @param[in]   int             in_len_value    length of tag value
*/
void ds_xml::m_add_value( dsd_xml_tag* ads_tag, dsd_xml_tag* ads_child,
                          const char* ach_value, int in_len_value )
{
    m_create_tag( ads_child, ach_value, in_len_value, ied_value );
    m_add_child ( ads_tag, ads_child );
} // end of ds_xml::m_add_value


/**
 * function ds_xml::m_add_child
 * add child to parent
 *
 * @param[in]   dsd_xml_tag*    ads_parent      output
 * @param[in]   dsd_xml_tag*    ads_child       child buffer to add
*/
void ds_xml::m_add_child( dsd_xml_tag* ads_parent, dsd_xml_tag* ads_child )
{
    if ( ads_parent->ads_child == NULL ) {
        ads_parent->ads_child = ads_child;
        return;
    }

    dsd_xml_tag* ads_temp = ads_parent->ads_child;
    while ( ads_temp->ads_next != NULL ) {
        ads_temp = ads_temp->ads_next;
    }
    ads_temp->ads_next = ads_child;    
} // end of ds_xml::m_add_child


/**
 * function ds_xml::m_add_next
 * add next tag to ads_parent
 *
 * @param[in]   dsd_xml_tag*    ads_parent      output
 * @param[in]   dsd_xml_tag*    ads_next        buffer to add
*/
void ds_xml::m_add_next( dsd_xml_tag* ads_parent, dsd_xml_tag* ads_next )
{
    dsd_xml_tag* ads_temp = ads_parent;
    while ( ads_temp->ads_next != NULL ) {
        ads_temp = ads_temp->ads_next;
    }
    ads_temp->ads_next = ads_next;   
} // end of ds_xml::m_add_next


/**
 * function ds_xml::m_create_attr
 * add attribute in buffer ads_attr to ads_tag
 *
 * @param[in]   dsd_xml_attr*   ads_attr        attr buffer to add
 * @param[in]   char*           ach_name        name of attr
 * @param[in]   int             in_len_name     length of attr name
 * @param[in]   char*           ach_value       value of attr
 * @param[in]   int             in_len_value    length of attr value
*/
void ds_xml::m_create_attr( dsd_xml_attr* ads_attr, 
                            const char* ach_name, int in_len_name,
                            const char* ach_value, int in_len_value )
{
    ads_attr->ach_name     = ach_name;
    ads_attr->in_len_name  = in_len_name;
    ads_attr->ach_value    = ach_value;
    ads_attr->in_len_value = in_len_value;
    ads_attr->ads_next     = NULL;
} // end of ds_xml::m_create_attr


/**
 * function ds_xml::m_add_attr
 * add attribute in buffer ads_attr to ads_tag
 *
 * @param[in]   dsd_xml_tag*    ads_parent      output
 * @param[in]   dsd_xml_attr*   ads_attr        attr buffer to add
*/
void ds_xml::m_add_attr( dsd_xml_tag* ads_tag, dsd_xml_attr* ads_attr )
{
    if ( ads_tag->ads_attr == NULL ) {
        ads_tag->ads_attr = ads_attr;
        return;
    }
    
    dsd_xml_attr* ads_temp = ads_tag->ads_attr;
    while ( ads_temp->ads_next != NULL ) {
        ads_temp = ads_temp->ads_next;
    }
    ads_temp->ads_next = ads_attr;
} // end of ds_xml::m_add_attr


/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_xml::m_init
 *
 * @param[in]   ds_wsp_helper*  ads_wsp_helper_in
*/
void ds_xml::m_init( ds_wsp_helper* ads_wsp_helper_in )
{
    ads_wsp_helper = ads_wsp_helper_in;
} // end of ds_xml::m_init


/**
 * function ds_xml::m_clear
 * clear saved content chain
*/
void ds_xml::m_clear()
{
    m_free_memory( ads_chain );
    ads_chain = NULL;
    m_free_memory( ads_key_chain );
    ads_key_chain = NULL;
} // end of ds_xml::m_clear


/**
 * function ds_xml::m_include_ws
*/
void ds_xml::m_include_ws()
{
    bo_show_ws = true;
} // end of ds_xml::m_include_ws


/**
 * function ds_xml::m_include_datatags
*/
void ds_xml::m_include_datatags()
{
    bo_show_data = true;
} // end of ds_xml::m_include_datatags


/**
 * function ds_xml::m_to_xml
 *
 * @param[in]   char*           ach_data        pointer to xml data
 * @param[in]   int             in_len          length of data
 * @return      dsd_xml_tag*                    tag chain
*/
dsd_xml_tag* ds_xml::m_from_xml( const char* ach_data, int in_len )
{
#if XML_DEF_TAGS
    ads_chain    = &dsr_tags[0];
#else
    ads_chain    = (dsd_xml_tag*)ads_wsp_helper->m_cb_get_memory( sizeof(dsd_xml_tag), true );
#endif
    in_used_tags = 1;

    bool bo_ret = m_parse_data( ach_data, in_len, ads_chain );
    if ( bo_ret == true ) {
        return m_get_firstnode();
    }
    return NULL;
} // end of ds_xml::m_from_xml


/**
 * function ds_xml::m_to_xml
 *
 * @param[in]   ds_hstring*     ads_xml         string containing xml
 * @return      dsd_xml_tag*                    tag chain
*/
dsd_xml_tag* ds_xml::m_from_xml( const dsd_const_string& ads_xml )
{
    return m_from_xml( ads_xml.m_get_ptr(), ads_xml.m_get_len() );
} // end of ds_xml::m_from_xml


/**
 * function ds_xml::m_get_keys
 * get a list of child keys from node

 * @param[in]   dsd_xml_tag*    ads_node    starting node
 * @return      dsd_xml_key*                key list, NULL in error cases
*/
dsd_xml_key* ds_xml::m_get_keys( dsd_xml_tag* ads_node )
{
    // initialize some variables:
    dsd_xml_tag* ads_tnode = NULL;      // working node element
    dsd_xml_key* ads_tkey  = NULL;      // working key element
    ads_key_chain          = NULL;      // return chain (is global because we need to get memory and free again)


    ads_tnode = m_get_firstchild( ads_node );
    if ( ads_tnode == NULL ) {
        return NULL;
    }

    //---------------------------------
    // loop through all child nodes:
    //---------------------------------
    while ( ads_tnode != NULL ) {
        //-----------------------------
        // check if element is a tag:
        //-----------------------------
        if ( ads_tnode->ien_type == ied_tag ) {
            //-------------------------
            // get next key element:
            //-------------------------
            if ( ads_tkey == NULL ) {
                ads_key_chain = m_get_next( ads_key_chain );
                if ( ads_key_chain == NULL ) {
                    return NULL;
                }
                ads_tkey = ads_key_chain;
            } else {
                ads_tkey = m_get_next( ads_tkey );
            }

            //-------------------------
            // fill key element:
            //-------------------------
            ads_tkey->ach_name    = ads_tnode->ach_data;
            ads_tkey->in_len_name = ads_tnode->in_len_data;
        }
        //-----------------------------
        // get next child element:
        //-----------------------------
        ads_tnode = m_get_nextsibling( ads_tnode );
    }
    return ads_key_chain;
} // end of ds_xml::m_get_keys


/**
 * function ds_xml::m_get_value
 * get value from child named key of ads_node
 * if given key is not found, NULL is returned
 * if given key has no value, the found tag is returned, value will be NULL
 *
 * @param[in]   dsd_xml_tag*    ads_node        starting node
 * @param[in]   char*           ach_key         key of search node
 * @param[in]   int             in_len_key      length of ach_key
 * @param[out]  char**          aach_value      found value, otherwise NULL
 * @param[out]  int*            ain_len_value   lenght of found value
 *
 * @return      dsd_xml_tag*                    tag structure with name key
 *                                              NULL in error cases
*/
dsd_xml_tag* ds_xml::m_get_value( dsd_xml_tag* ads_node,
                                  const char* ach_key, int in_len_key,
                                  const char** aach_value, int* ain_len_value )
{
    // initialize some variables:
    dsd_xml_tag* ads_tnode = NULL;      // working node element
    int          in_pos    = 0;         // position in key
    bool         bo_equals = true;      // are key and tagname equal?

    // check incoming parameters:
    if (    ach_key == NULL    || in_len_key < 1
         || aach_value == NULL || ain_len_value == NULL ) {
        return NULL;
    }

    ads_tnode = m_get_firstchild( ads_node );
    if ( ads_tnode == NULL ) {
        return NULL;
    }

    *aach_value    = NULL;
    *ain_len_value = 0;

    //---------------------------------
    // loop through all child nodes:
    //---------------------------------
    while ( ads_tnode != NULL ) {
        bo_equals = true; // JF Reset for EACH time we do the loop.

        //-----------------------------
        // check if element is key:
        //-----------------------------
        if (    ads_tnode->ien_type == ied_tag
             && ads_tnode->in_len_data == in_len_key ) {
            for ( in_pos = 0; in_pos < in_len_key; in_pos++ ) {
                if ( ads_tnode->ach_data[in_pos] != ach_key[in_pos] ) {
                    bo_equals = false;
                    break;
                }
            }
            if ( bo_equals == true ) {
                if (    ads_tnode->ads_child != NULL
                     && ads_tnode->ads_child->ien_type == ied_value ) {
                    *aach_value    = ads_tnode->ads_child->ach_data;
                    *ain_len_value = ads_tnode->ads_child->in_len_data;
                }
                return ads_tnode;
            }
        }
        //-----------------------------
        // get next child element:
        //-----------------------------
        ads_tnode = m_get_nextsibling( ads_tnode );
    }

    return NULL;
} // end of ds_xml::m_get_value

dsd_xml_tag* ds_xml::m_get_value( dsd_xml_tag* ads_node, const dsd_const_string& ach_key, const char** aach_value, int* ain_len_value )
{
    return m_get_value(ads_node, ach_key.m_get_start(), ach_key.m_get_len(), aach_value, ain_len_value);
}

/**
 * function ds_xml::m_to_xml
 * put a tag chain to xml
 *
 * @param[in]   dsd_xml_tag*    ads_node        tag chain
 * @param[in]   ds_hstring*     ads_xml         string containing xml
*/
void ds_xml::m_to_xml( dsd_xml_tag* ads_node, ds_hstring* ads_xml )
{
    m_write_tag( ads_node, ads_xml );
} // end of ds_xml::m_to_xml



/**
 * function ds_xml::m_get_cache_len
 * evaluate length of a tag chain in cache mode (without pointers but numbers)
 *
 * @param[in]   dsd_xml_tag*    ads_node        tag chain
*/
int ds_xml::m_get_cache_len( dsd_xml_tag* ads_node )
{
    return m_evaluate_tag_length ( ads_node );
} // end of ds_xml::m_get_cache_len



/**
 * function ds_xml::m_write_cache
 * put a tag chain to cache (without pointers but numbers)
 *
 * @param[in]   char*           ach_cache       cache memory
 * @param[in]   int             in_len          length of memory
 * @param[in]   dsd_xml_tag*    ads_node        tag chain
*/
bool ds_xml::m_write_cache( char* ach_cache, int in_len, dsd_xml_tag* ads_node )
{
    /*
        our cache will look like this:

        +-----------------------------------+---------------------+
        | struct dsd_xml_tag_cache          |                     |
        | (contains length of data)         | ach_data            |
        +-----------------------------------+---------------------+
        | struct dsd_xml_attr_cache         | ach_name            |
        | (contains length of value, name)  | ach_value           |
        +-----------------------------------+---------------------+
        |             .                     |        .            |
        |             .                     |        .            |
        |             .                     |        .            |
        +-----------------------------------+---------------------+
        | struct dsd_xml_attr_cache         | ach_name            |
        | (contains length of value, name)  | ach_value           |
        +-----------------------------------+---------------------+
        | struct dsd_xml_tag_cache          |                     |
        | (contains length of data)         | ach_data            |
        +-----------------------------------+---------------------+
        |             .                     |        .            |
        |             .                     |        .            |
        |             .                     |        .            |
        +-----------------------------------+---------------------+
    */

    // initialize some variables:
    int in_needed      = 0;
    int in_pos         = 0;
    int in_tindex      = 0;             // tag index

    // check input data:
    if ( ach_cache == NULL || ads_node == NULL ) {
        return false;
    }

    // evaluate and check length:
    in_needed = m_evaluate_tag_length ( ads_node );
    if ( in_len < in_needed ) {
        return false;
    }

    // copy tag chain:
    return m_copy_tag( ach_cache, in_len, &in_pos, ads_node, &in_tindex );
} // end of ds_xml::m_write_cache


/**
 * function ds_xml::m_read_cache
 * read a tag chain from cache (without pointers but numbers)
 *
 * @param[in]   char*           ach_cache       cache memory
 * @param[in]   int             in_len          length of memory
*/
dsd_xml_tag* ds_xml::m_read_cache( char* ach_cache, int in_len )
{
    // initialize some variables:
    bool    bo_return = false;

    if ( ads_chain != NULL ) {
        m_clear();
    }

#if XML_DEF_TAGS
    ads_chain    = &dsr_tags[0];
#else
    ads_chain    = (dsd_xml_tag*)ads_wsp_helper->m_cb_get_memory( sizeof(dsd_xml_tag), true );
#endif
    in_used_tags = 1;

    bo_return = m_parse_cache( ads_chain, ach_cache, in_len, 0 );
    if ( bo_return == false ) {
        return NULL;
    }
    return ads_chain;
} // end of ds_xml::m_read_cache


/**
 * function ds_xml::m_get_firstnode
 * get first node of our parsed data
 * attention:
 *      destructor will free data from the chain
 *      if you need the data after ds_xml is killed
 *      copy it!
 *
 * @return  dsd_xml_tag*
*/
dsd_xml_tag* ds_xml::m_get_firstnode()
{
    dsd_xml_tag* ads_ret = ads_chain;
    if ( ads_ret == NULL ) {
        return NULL;
    }
    while ( ads_ret->ien_type == ied_xmltype ) {
        ads_ret = ads_ret->ads_next;
        if ( ads_ret == NULL ) {
            break;
        }
    }
    return ads_ret;
} // end of ds_xml::m_get_firstnode
    

/**
 * function ds_xml::m_get_encoding
 * get encoding of xml data
 *
 * @return ied_charset
*/
ied_charset ds_xml::m_get_encoding()
{
    return ien_encoding;
} // end of ds_xml::m_get_encoding


/**
 * function ds_xml::m_create_tag
 * create a new tag
 *
 * @param[in]   char*           ach_name        name of tag
 * @param[in]   int             in_len_name     length of name
 * @param[in]   ied_xml_type    ien_type        type of tag
 *                                              default = ied_tag
 *
 * @return      dsd_xml_tag*                    pointer to tag
 *                                              NULL in error cases
*/
dsd_xml_tag* ds_xml::m_create_tag( const char* ach_name, int in_len_name, ied_xml_type ien_type )
{
    // get memory for new tag:
    dsd_xml_tag* ads_new_tag = m_get_new_tag();
    if ( ads_new_tag == NULL ) {
        return NULL;
    }
    
    // set values:
    ads_new_tag->ach_data    = ach_name;
    ads_new_tag->in_len_data = in_len_name;
    ads_new_tag->ien_type    = ien_type;
    ads_new_tag->ads_attr    = NULL;
    ads_new_tag->ads_child   = NULL;
    ads_new_tag->ads_next    = NULL;

    return ads_new_tag;
} // end of ds_xml::m_create_tag

dsd_xml_tag* ds_xml::m_create_tag( const dsd_const_string& rdsp_name, ied_xml_type ien_type )
{
    return this->m_create_tag(rdsp_name.m_get_ptr(), rdsp_name.m_get_len(), ien_type);
}

/**
 * function ds_xml::m_add_next
 * add a next element to parent tag
 *
 * @param[in]   dsd_xml_tag*    ads_parent      pointer to parent tag
 * @param[in]   char*           ach_name        name of tag
 * @param[in]   int             in_len_name     length of name
 * @param[in]   ied_xml_type    ien_type        type of tag
 *                                              default = ied_tag
 *
 * @return      dsd_xml_tag*                    pointer to tag
 *                                              NULL in error cases
*/
dsd_xml_tag* ds_xml::m_add_next( dsd_xml_tag* ads_parent,
                         const char* ach_name, int in_len_name,
                         ied_xml_type ien_type )
{
    if ( ads_parent == NULL ) {
        return NULL;
    }

    // initialize some variables:
    dsd_xml_tag* ads_new_tag;
    dsd_xml_tag* ads_temp;
    
    // create new tag:
    ads_new_tag = m_create_tag( ach_name, in_len_name, ien_type );
    if ( ads_new_tag == NULL ) {
        return NULL;
    }

    if ( ads_parent->ads_next == NULL ) {
        ads_parent->ads_next = ads_new_tag;
        return ads_new_tag;
    }

    // add to chain in tag:
    ads_temp = ads_parent->ads_next;
    while ( ads_temp->ads_next != NULL ) {
        ads_temp = ads_temp->ads_next;
    }
    ads_temp->ads_next = ads_new_tag;
    return ads_new_tag;
} // end of ds_xml::m_add_next


/**
 * function ds_xml::m_add_child
 * add a child to parent tag
 *
 * @param[in]   dsd_xml_tag*    ads_parent      pointer to parent tag
 * @param[in]   char*           ach_name        name of tag
 * @param[in]   int             in_len_name     length of name
 * @param[in]   ied_xml_type    ien_type        type of tag
 *                                              default = ied_tag
 *
 * @return      dsd_xml_tag*                    pointer to tag
 *                                              NULL in error cases
*/
dsd_xml_tag* ds_xml::m_add_child( dsd_xml_tag* ads_parent,
                          const char* ach_name, int in_len_name,
                          ied_xml_type ien_type )
{
    if ( ads_parent == NULL ) {
        return NULL;
    }

    // initialize some variables:
    dsd_xml_tag* ads_new_tag;
    dsd_xml_tag* ads_temp;
    
    // create new tag:
    ads_new_tag = m_create_tag( ach_name, in_len_name, ien_type );
    if ( ads_new_tag == NULL ) {
        return NULL;
    }

    if ( ads_parent->ads_child == NULL ) {
        ads_parent->ads_child = ads_new_tag;
        return ads_new_tag;
    }

    // add to chain in tag:
    ads_temp = ads_parent->ads_child;
    while ( ads_temp->ads_next != NULL ) {
        ads_temp = ads_temp->ads_next;
    }
    ads_temp->ads_next = ads_new_tag;
    return ads_new_tag;
} // end of ds_xml::m_add_child

dsd_xml_tag* ds_xml::m_add_child( dsd_xml_tag* ads_parent, const dsd_const_string& rdsp_name )
{
    return this->m_add_child(ads_parent, rdsp_name.m_get_ptr(), rdsp_name.m_get_len());
}

/**
 * function ds_xml::m_add_value
 * add a value to a given tag
 *
 * @param[in]   dsd_xml_tag*    ads_tag         tag, to which value should be added
 * @param[in]   char*           ach_value       value to add
 * @param[in]   int             in_len_value    length of value
 *
 * @return      bool                            true = success
 *                                              false otherwise
*/
bool ds_xml::m_add_value ( dsd_xml_tag* ads_tag, const char* ach_value, int in_len_value )
{
    if ( ads_tag == NULL ) {
        return false;
    }

    // create child tag containing the value:
    dsd_xml_tag* ads_value = m_create_tag( ach_value, in_len_value, ied_value );
    if ( ads_value == NULL ) {
        return false;
    }

    m_add_child( ads_tag, ads_value );
    return true;
} // end of ds_xml::m_add_value

bool ds_xml::m_add_value( dsd_xml_tag* ads_tag, const dsd_const_string& rdsp_value )
{
    return this->m_add_value(ads_tag, rdsp_value.m_get_ptr(), rdsp_value.m_get_len());
}

/**
 * function ds_xml::m_add_attr
 * add a attribute to a given tag
 *
 * @param[in]   dsd_xml_tag*    ads_tag         tag, to which value should be added
 * @param[in]   char*           ach_ach_name    name of new attribute
 * @param[in]   int             in_len_name     length of attribute name
 * @param[in]   char*           ach_value       value of new attribute
 * @param[in]   int             in_len_value    length of attribute value
 *
 * @return      bool                            true = success
 *                                              false otherwise
*/
bool ds_xml::m_add_attr( dsd_xml_tag* ads_tag,
                         const char* ach_name, int in_len_name,
                         const char* ach_value, int in_len_value )
{
    if ( ads_tag == NULL ) {
        return false;
    }

    // initialize some variables:
    dsd_xml_attr* ads_attr;         // new attribute
    dsd_xml_attr* ads_temp;         // temp attribute for going through the chain

    // get new memory for attribute:
    ads_attr = m_get_new_attr();
    if ( ads_attr == NULL ) {
        return false;
    }

    // set values:
    ads_attr->ach_name     = ach_name;
    ads_attr->in_len_name  = in_len_name;
    ads_attr->ach_value    = ach_value;
    ads_attr->in_len_value = in_len_value;
    ads_attr->ads_next     = NULL;

    // check if there is already an attribute:
    if ( ads_tag->ads_attr == NULL ) {
        ads_tag->ads_attr = ads_attr;
        return true;
    }

    // add to chain in tag:
    ads_temp = ads_tag->ads_attr;
    while ( ads_temp->ads_next != NULL ) {
        ads_temp = ads_temp->ads_next;
    }
    ads_temp->ads_next = ads_attr;

    return true;
} // end of ds_xml::m_add_attr

/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_xml::m_parse_data
 *
 * @param[in]   char*           ach_data
 * @param[in]   int             in_len
 * @param[in]   dsd_xml_tag*   ads_out
 * @return      bool
*/
bool ds_xml::m_parse_data( const char* ach_data, int in_len, dsd_xml_tag* ads_out )
{
    // intitialize some variables:
    bool    bo_return       = false;        // return value
    bool    bo_tag          = false;        // a tag is found
    bool    bo_closed       = false;        // is tag closed ("<../>" or "<..>")
    bool    bo_end_found    = false;        // we have found the needed end tag (in case of nested)
    int     in_pos          = 0;            // working position
    const char*   ach_tag         = NULL;         // found tag in data
    int     in_len_tag      = 0;            // length of tag
    int     in_nested_start = 0;            // start pos of nested data
    int     in_nested_end   = 0;            // end   pos of nested data
    int     in_check        = 0;
    bool    bo_tag_saved    = false;

    if ( in_len == 0 ) {
        ads_out->ien_type    = ied_value;
        ads_out->ach_data    = (char*)"";
        ads_out->in_len_data = 0;
    }

    //-----------------------------------------------------
    // loop through the data:
    //-----------------------------------------------------
    while ( in_pos < in_len ) {
        bo_tag_saved = false;
        //-------------------------------------------------
        // find tag:
        //-------------------------------------------------
        bo_tag = m_get_tag( ach_data, in_len, &in_pos, &ach_tag, &in_len_tag );
        
        
        //-------------------------------------------------
        // if there is data found before our tag, save it:
        //-------------------------------------------------
        if ( in_pos > 0 ) {
            if ( bo_tag == true ) {
                in_check = in_pos - in_len_tag;
            } else {
                in_check = in_len;
            }
            if (    in_check > 0
                 && m_only_ws ( ach_data, in_check ) == false
                 && m_add_type( ied_value )          == true  ) {
                // save current data:
                ads_out->ien_type    = ied_value;
                ads_out->ach_data    = ach_data;
                ads_out->in_len_data = in_check;
    
                if ( (in_pos < in_len) || (bo_tag == true) ) {
                    // get next portal data structure:
                    ads_out = m_get_next( ads_out );
                    if ( ads_out == NULL ) {
                        return false;
                    }
                }
            }

            // move pointer behind tag:
            m_move_char_pointer( &ach_data, &in_len, &in_pos );
        } // end of if ( in_pos > 0 )

        //-------------------------------------------------
        // if a tag is found, get its type and save it:
        //-------------------------------------------------
        if ( bo_tag == true ) {
            bo_closed = m_parse_tag( ach_tag, in_len_tag, ads_out );
            
            if ( bo_closed == false ) {
                // there might be nested data inside this tag
                // get end of our tag and handle nested data recursive
                in_nested_start = in_pos;
                in_nested_end   = in_pos;
                bo_end_found = m_get_end_tag( ach_data, in_len, &in_pos, &in_nested_end,
                                              ads_out->ach_data, ads_out->in_len_data );
                if ( bo_end_found == false || in_nested_end < in_nested_start ) {
                    return false;
                }

                // recursive call:
                bo_return = m_parse_data( &ach_data[in_nested_start], 
                                          in_nested_end - in_nested_start,
                                          m_get_child( ads_out ) );
                if ( bo_return == false ) {
                    return false;
                }

                // move pointer behind end tag:
                m_move_char_pointer( &ach_data, &in_len, &in_pos );
            }
            
            if (    in_pos < in_len 
                 && m_only_ws ( &ach_data[in_pos], in_len - in_pos ) == false ) {
                if ( m_add_type( ads_out->ien_type )== true ) {
                    bo_tag_saved = true;
                    // get next portal data structure:
                    ads_out = m_get_next( ads_out );
                    if ( ads_out == NULL ) {
                        return false;
                    }
                } else {
                    memset( ads_out, 0, sizeof(dsd_xml_tag) );
                }
            }
        } // end of if ( bo_tag == true )

    } // end of while

    if (    bo_tag_saved == false
         && m_add_type( ads_out->ien_type )== false ) {
        if ( ads_out->ads_prev->ads_next == ads_out ) {
            ads_out->ads_prev->ads_next = NULL;
        } else if ( ads_out->ads_prev->ads_child == ads_out ) {
            ads_out->ads_prev->ads_child = NULL;
        }
    }

    return true;
} // end of ds_xml::m_parse_data


/**
 * function ds_xml::m_get_tag
 * get next tag
 *
 * @param[in]       char*   ach_data
 * @param[in]       int     in_len
 * @param[in/out]   int*    ain_pos
 * @param[out]      char**  aach_tag
 * @param[out]      int*    ain_len_tag
*/
bool ds_xml::m_get_tag( const char* ach_data, int in_len, int* ain_pos,
                        const char** aach_tag, int* ain_len_tag )
{
    int  in_start_pos = 0;
    bool bo_tag_found = false;
    enum ied_state {
        ied_start,
        ied_check_sign,
        ied_check_commend_1,
        ied_check_commend_2,
        ied_command_end_1,
        ied_command_end_2,
        ied_command_end,
        ied_end
    } ien_state = ied_start;

    for ( ; *ain_pos < in_len; (*ain_pos)++ ) {
        switch ( ien_state ) {
            case ied_start:
                // search for a starting tag:
                if ( ach_data[*ain_pos] == '<' ) {
                    *aach_tag    = &ach_data[*ain_pos];
                    in_start_pos = *ain_pos;
                    ien_state    = ied_check_sign;
                }
                continue;

            case ied_check_sign:
                // check second sign for a commend tag:
                if ( ach_data[*ain_pos] == '!' ) {
                    ien_state = ied_check_commend_1;
                } else {
                    (*ain_pos)--;
                    ien_state = ied_end;
                }
                continue;

            case ied_check_commend_1:
                // check for first '-' sign:
                if ( ach_data[*ain_pos] == '-' ) {
                    ien_state = ied_check_commend_2;
                } else {
                    (*ain_pos)--;
                    ien_state = ied_end;
                }
                continue;

            case ied_check_commend_2:
                // check for second '-' sign:
                if ( ach_data[*ain_pos] == '-' ) {
                    ien_state = ied_command_end_1;
                } else {
                    (*ain_pos)--;
                    ien_state = ied_end;
                }
                continue;

            case ied_command_end_1:
                // check for first '-" endsign
                if ( ach_data[*ain_pos] == '-' ) {
                    ien_state = ied_command_end_2;
                }
                continue;

            case ied_command_end_2:
                // check for second '-" endsign
                if ( ach_data[*ain_pos] == '-' ) {
                    ien_state = ied_command_end;
                } else {
                    ien_state = ied_command_end_1;
                }
                continue;

            case ied_command_end:
                // next sign must be ending '>'
                if ( ach_data[*ain_pos] == '>' ) {
                    (*ain_pos)++;
                    *ain_len_tag = *ain_pos - in_start_pos;
                    bo_tag_found = true;
                    break;
                } else {
                    ien_state = ied_command_end_1;
                    continue;
                }

            case ied_end:
                if ( ach_data[*ain_pos] == '>' ) {
                    (*ain_pos)++;
                    *ain_len_tag = *ain_pos - in_start_pos;
                    bo_tag_found = true;
                    break;
                } else {
                    continue;
                }
        }
        break;
    }

    return bo_tag_found;
} // end of ds_xml::m_get_tag


/**
 * function ds_xml::m_get_end_tag
 * get end tag for ach_tag
 *
 * @param[in]       char*   ach_data
 * @param[in]       int     in_len
 * @param[in/out]   int*    ain_pos
 * @param[out]      int*    ain_tag_start
 * @param[in]       char*   ach_tag
 * @param[in]       int     in_len_tag
 * @param[in]       ied_xsl_tags ien_tag
 *
 * @return          true = success
*/
bool ds_xml::m_get_end_tag( const char* ach_data, int in_len, int* ain_pos,
                            int* ain_tag_start, const char* ach_tag, int in_len_tag )
{
    // define states:
    enum ied_state {
        ied_start,
        ied_end_tag,
        ied_spaces,
        ied_name,
        ied_name_check,
        ied_end,
        ied_count_tag,
        ied_unset
    };

    // initialize some variables:
    bool         bo_tag_found    = false;
    int          in_start_pos    = -1;
    int          in_compared     = 0;
    int          in_count_tag    = 0;
    ied_state    ien_state       = ied_start;
    ied_state    ien_next_state  = ied_unset;
    ied_state    ien_name_equals = ied_unset;
    ied_state    ien_name_diff   = ied_unset;

    for ( ; *ain_pos < in_len; (*ain_pos)++ ) {
        switch ( ien_state ) {
            //----------------------------
            // search for a starting tag:
            //----------------------------
            case ied_start:
                if ( ach_data[*ain_pos] == '<' ) {
                    ien_state = ied_end_tag;
                    *ain_tag_start = *ain_pos;
                }
                continue;

            //----------------------------
            // check if tag is an end tag:
            //----------------------------
            case ied_end_tag:
                if ( ach_data[*ain_pos] == '/' ) {
                    ien_state       = ied_spaces;
                    ien_next_state  = ied_name;
                    ien_name_equals = ied_name_check;
                    ien_name_diff   = ied_start;
                } else {
                    // check if tag has same name than our search one
                    //ien_state = ied_start;
                    (*ain_pos)--;                   // this sign migth be neccessary for name
                    ien_state       = ied_spaces;
                    ien_next_state  = ied_name;
                    ien_name_equals = ied_count_tag;
                    ien_name_diff   = ied_start;
                }
                continue;

            //----------------------------
            // ignore whitespaces:
            //----------------------------
            case ied_spaces:
                switch ( ach_data[*ain_pos] ) {
                    case ' ':
                    case '\t':
                    case '\n':
                    case '\r':
                    case '\f':
                        break;
                    default:
                        // new state is presaved!
                        ien_state      = ien_next_state;
                        ien_next_state = ied_unset;      //reset presaved state
                        (*ain_pos)--; // this sign could be neccessary for next
                        break;
                }
                continue;

            //----------------------------
            // get name of tag:
            //----------------------------
            case ied_name:
                if ( tolower(ach_data[*ain_pos]) == tolower(ach_tag[in_compared]) ) {
                    in_compared++;
                    if ( in_compared == in_len_tag ) {
                        in_compared     = 0;
                        in_start_pos    = -1;
                        if ( *ain_pos < in_len + 1 ) {
                            switch ( ach_data[*ain_pos + 1] ) {
                                case '>':
                                case ' ':
                                case '\t':
                                case '\n':
                                case '\r':
                                case '\f':
                                    ien_state       = ien_name_equals;
                                    ien_name_equals = ied_unset;
                                    break;
                                default:
                                    ien_state     = ien_name_diff;
                                    ien_name_diff = ied_unset;
                                    break;
                            }
                        } else {
                            ien_state     = ien_name_diff;
                            ien_name_diff = ied_unset;
                        }
                    }
                } else {
                    in_compared   = 0;
                    in_start_pos  = -1;
                    ien_state     = ien_name_diff;
                    ien_name_diff = ied_unset;
                }
                continue;

            //----------------------------
            // we have found a tag with same name like ours:
            //----------------------------
            case ied_count_tag:
                in_count_tag++;
                ien_state = ied_start;
                continue;

            //----------------------------
            // check for name in longer:
            //----------------------------
            case ied_name_check:
                switch ( ach_data[*ain_pos] ) {
                    case '>':
                    case ' ':
                    case '\t':
                    case '\n':
                    case '\r':
                    case '\f':
                        (*ain_pos)--; // make sure ied_end is reached
                        if ( in_count_tag == 0 ) {
                            ien_state = ied_end;
                        } else {
                            in_count_tag--;
                            ien_state = ied_start;
                        }
                        break;
                    default:
                        ien_state = ied_start;
                        break;
                }
                continue;

            //----------------------------
            // search end of tag:
            //----------------------------
            case ied_end:
                if ( ach_data[*ain_pos] == '>' ) {
                    (*ain_pos)++;
                    bo_tag_found = true;
                }
                break;
        }
        break;
    }

    return bo_tag_found;
} // end of ds_xml::m_get_end_tag


/**
 * function ds_xml::m_parse_tag
 *
 * @param[in]   char*           ach_tag
 * @param[in]   int             in_len_tag
 * @param[in]   dsd_xml_tag*    ads_out
*/
bool ds_xml::m_parse_tag( const char* ach_tag, int in_len_tag, dsd_xml_tag* ads_out )
{
    // define working states:
    enum ied_state {
        ied_start,      // search for first character in tag
        ied_spaces,     // pass spaces
        ied_equal,      // search equal
        ied_name,       // get name of tag
        ied_attr,       // get attribute
        ied_arg,        // get attribute argument
        ied_squotes,    // we are in single quotes
        ied_dquotes     // we are in double quotes
    };

    // initialize some variables:
    bool          bo_in_quotes    = false;              // arg in quotes?
    const char*         ach_attr        = NULL;               // pointer to attribute
    int           in_len_attr     = 0;                  // length of attribute
    int           in_pos          = 0;                  // working position in tag
    int           in_start_pos    = -1;                 // start position for some word search
    int           in_add          = 0;                  // additional
    ied_state     ien_state       = ied_spaces;         // our working state
    ied_state     ien_next_state  = ied_start;          // presave next state (needed for pass spaces)
    struct dsd_xml_attr* ads_temp = ads_out->ads_attr;  


    //-----------------------------------
    // start parsing
    //-----------------------------------
    for ( ; in_pos < in_len_tag; in_pos++ ) {
        switch ( ien_state ) {

            //---------------------------
            // search start of tag name:
            //---------------------------
            case ied_start:
                switch ( ach_tag[in_pos] ) {
                    case '<':
                        ien_state      = ied_spaces;
                        ien_next_state = ied_name;
                        break;
                    default:
                        break;
                }
                continue;

            //---------------------------
            // ignore whitespaces:
            //---------------------------
            case ied_spaces:
                switch ( ach_tag[in_pos] ) {
                    case ' ':
                    case '\t':
                    case '\n':
                    case '\r':
                    case '\f':
                        break;
                    default:
                        // new state is presaved!
                        ien_state      = ien_next_state;
                        ien_next_state = ied_start;      //reset presaved state
                        in_pos--; // this sign could be neccessary for next
                        break;
                }
                continue;

            //---------------------------
            // get name of tag:
            //---------------------------
            case ied_name:
                if ( ads_out->ach_data == NULL ) {
                    ads_out->ach_data = &ach_tag[in_pos];
                }
                switch ( ach_tag[in_pos] ) {
                    case '>':
                    case ' ':
                    case '/':
                    case '\t':
                    case '\n':
                    case '\r':
                    case '\f':
                        ads_out->in_len_data = (int)(&ach_tag[in_pos] - ads_out->ach_data);
                        ien_state            = ied_spaces;
                        ien_next_state       = ied_attr;
                        break;
                    default:
                        break;
                }
                continue;

            //---------------------------                
            // get attribute of tag:
            //---------------------------
            case ied_attr:
                if ( in_start_pos == -1 ) {
                    in_start_pos = in_pos;
                }
                switch ( ach_tag[in_pos] ) {
                    case '=':
                        ach_attr       = &ach_tag[in_start_pos];
                        in_len_attr    = in_pos - in_start_pos;
                        in_start_pos   = -1;
                        ien_state      = ied_spaces;    // pass following spaces
                        ien_next_state = ied_arg;
                        break;
                    case ' ':
                    case '\t':
                    case '\n':
                    case '\r':
                    case '\f':
                        ach_attr     = &ach_tag[in_start_pos];
                        in_len_attr  = in_pos - in_start_pos;
                        in_start_pos = -1;
                        ien_state    = ied_equal;     // search following '='
                        break;
                    default:
                        break;
                }
                continue;

            //---------------------------            
            // get next equal:
            //---------------------------
            case ied_equal:
                switch( ach_tag[in_pos] ) {
                    case '=':
                        ien_state      = ied_spaces; // pass following spaces
                        ien_next_state = ied_arg;
                    default:
                        break;
                }
                continue;

            //---------------------------                
            // get argument of tag:
            //---------------------------
            case ied_arg:
                if ( in_start_pos == -1 ) {
                    in_start_pos = in_pos;
                }
                switch ( ach_tag[in_pos] ) {
#if 0
                    case '\\':
                        in_pos++;
                        break;
                    case '"':
                    case '\'':
                        if ( bo_in_quotes == false ) {
                            bo_in_quotes = true;
                            in_add++;
                            continue;
                        }
                        bo_in_quotes = false;
#endif
                    case '\'':
                        if ( bo_in_quotes == false ) {
                            bo_in_quotes = true;
                            in_add++;
                            ien_state      = ied_squotes;
                            ien_next_state = ied_arg;
                            continue;
                        }

                    case '"':
                        if ( bo_in_quotes == false ) {
                            bo_in_quotes = true;
                            in_add++;
                            ien_state      = ied_dquotes;
                            ien_next_state = ied_arg;
                            continue;
                        }
                        bo_in_quotes = false;

                    case ' ':
                    case '\t':
                    case '\n':
                    case '\r':
                    case '\f':
                        if ( bo_in_quotes == false ) {
                            if ( ads_out->ads_attr == NULL ) {
                                ads_out->ads_attr  = m_get_next( ads_out->ads_attr );
                                ads_temp           = ads_out->ads_attr;
                            } else {
                                ads_temp           = m_get_next( ads_temp );
                            }
                            ads_temp->ach_name     = ach_attr;
                            ads_temp->in_len_name  = in_len_attr;
                            ads_temp->ach_value    = &ach_tag[in_start_pos];
                            ads_temp->in_len_value = in_add + in_pos - in_start_pos;
                            in_start_pos   = -1;
                            ien_state      = ied_spaces;
                            ien_next_state = ied_attr;
                            in_add         = 0;
                        }
                        break;
                    default:
                        break;
                }
                continue;

            //---------------------------                
            // handle single quotes:
            //---------------------------
            case ied_squotes:
                switch ( ach_tag[in_pos] ) {
                    case '\\':
                        in_pos++;
                        break;
                    case '\'':
                        // new state is presaved!
                        ien_state      = ien_next_state;
                        ien_next_state = ied_start;      //reset presaved state
                        in_pos--;
                        break;
                }
                continue;

            //---------------------------                
            // handle double quote:
            //---------------------------
            case ied_dquotes:
                switch ( ach_tag[in_pos] ) {
                    case '\\':
                        in_pos++;
                        break;
                    case '"':
                        // new state is presaved!
                        ien_state      = ien_next_state;
                        ien_next_state = ied_start;      //reset presaved state
                        in_pos--;
                        break;
                }
                continue;

        } // end of switch
        break;
    } // end of for loop

    //-----------------------------------
    // decide which tag we have here:
    //-----------------------------------
    dsd_const_string dsl_data(ads_out->ach_data, ads_out->in_len_data);
    if ( dsl_data.m_equals_ic("?xml") ) {
        ads_out->ien_type = ied_xmltype;
        //-------------------------------
        // get encoding:
        //-------------------------------
        if ( ads_out->ads_attr != NULL ) {
            dsd_xml_attr* ads_temp  = ads_out->ads_attr;
            while ( ads_temp != NULL ) {
				dsd_const_string dsl_temp(ads_temp->ach_name, ads_temp->in_len_name);
                if ( dsl_temp.m_equals_ic("encoding") ) {
                    ien_encoding = m_get_encoding( ads_temp->ach_value,
                                                   ads_temp->in_len_value );
                    break; // while
                }
                ads_temp = ads_temp->ads_next;
            }
        }
    }

    //-----------------------------------
    // decide wether tag is closed or not
    //-----------------------------------
    if ( in_len_tag > 2 && ach_tag[in_len_tag - 2] == '/' ) {
        return true;
    } else if (    (in_len_tag > 2)
                && (ads_out->in_len_data > 1)
                && (ads_out->ach_data[0] == '?')
                && (ach_tag[in_len_tag - 2] == '?') )
    {
        return true;
    } else if (    (in_len_tag > 2)
                && (ads_out->in_len_data > 1)
                && (ads_out->ach_data[0] == '!') ) 
    {
        ads_out->ien_type    = ied_data;
        ads_out->in_len_data = in_len_tag - 2;
        return true;
    }


    return false;
} // end of ds_xml::m_parse_tag


/**
 * function ds_xml::m_move_char_pointer
 *
 * @param[in/out] char**    aach_data       pointer to data
 * @param[in/out] int*      ain_len_data    pointer to length of data
 * @param[in/out] int*      ain_position    position in data
*/
void ds_xml::m_move_char_pointer( const char** aach_data, int* ain_len_data, int* ain_position )
{
    if ( *aach_data == NULL || *ain_len_data <= 0 || *ain_position <= 0 ) {
        return;
    }
    if ( *ain_position < *ain_len_data ) {
        *aach_data    += *ain_position;
        *ain_len_data -= *ain_position;
        *ain_position  = 0;
    } else {
        *aach_data += (*ain_len_data - 1);
        *ain_len_data = 0;
        *ain_position = 0;
    }
} // end of ds_xml::m_move_char_pointer


/**
 * function ds_xml::m_only_ws
 * check if ach_data contains only whitespaces until in_len
 *
 * @param[in]   char*   ach_data
 * @param[in]   int     in_len
 * @return      bool                true = only whitespace
 *                                  false otherwise
*/
bool ds_xml::m_only_ws(const char* ach_data, int in_len)
{
    if ( bo_show_ws == true ) {
        return false;
    }

    for ( int in_count = 0; in_count < in_len; in_count++ ) {
        switch ( ach_data[in_count] ) {
            case ' ':
            case '\t':
            case '\n':
            case '\r':
            case '\f':
                break;
            default:
                return false;
        }
    }
    return true;
} // end of ds_xml::m_only_ws


/**
 * function ds_xml::m_add_type
 * check if type should be added
 *
 * @param[in]   ied_xml_type ien_type
 * @return      bool                true = add
 *                                  false otherwise
*/
bool ds_xml::m_add_type( ied_xml_type ien_type )
{
    if ( bo_show_data == false ) {
        if ( ien_type == ied_data ) {
            return false;
        }
    }
    return true;
} // end of ds_xml::m_add_type


/**
 * function ds_xml::m_get_next
 *
 * @param[in] dsd_xml_key* ads_in
 * @return    dsd_xml_key*
*/
dsd_xml_key* ds_xml::m_get_next( dsd_xml_key* ads_in )
{
    if ( ads_in == NULL ) {
#if XML_DEF_TAGS
        // get entry outsid chain (first entry in tag structure)
        if ( in_used_keys < XML_DEF_TAGS ) { 
            ads_in = &dsr_key[in_used_keys];
            in_used_keys++;
        } else {
#endif
            ads_in = (dsd_xml_key*)ads_wsp_helper->m_cb_get_memory( sizeof(struct dsd_xml_key), true );
#if XML_DEF_TAGS
        }
#endif
        return ads_in;
    } else {
        // get entry in chain
        if ( ads_in->ads_next == NULL ) {
#if XML_DEF_TAGS
            if ( in_used_keys < XML_DEF_TAGS ) { 
                ads_in->ads_next = &dsr_key[in_used_keys];
                in_used_keys++;
            } else {
#endif
                ads_in->ads_next = (dsd_xml_key*)ads_wsp_helper->m_cb_get_memory( sizeof(struct dsd_xml_key), true );
#if XML_DEF_TAGS
            }
#endif
        }
        return ads_in->ads_next;
    }
} // end of ds_xml::m_get_next


/**
 * function ds_xml::m_get_next
 *
 * @param[in] dsd_xml_tag* ads_in
 * @return    dsd_xml_tag*
*/
dsd_xml_tag* ds_xml::m_get_next( dsd_xml_tag* ads_in )
{
    if ( ads_in->ads_next == NULL ) {
        ads_in->ads_next = m_get_new_tag();
        if ( ads_in->ads_next == NULL ) {
            return NULL;
        }
    }
    ads_in->ads_next->ads_prev = ads_in;
    return ads_in->ads_next;
} // end of ds_xml::m_get_next


/**
 * function ds_xml::m_get_child
 *
 * @param[in] dsd_xml_tag* ads_in
 * @return    dsd_xml_tag*
*/
dsd_xml_tag* ds_xml::m_get_child( dsd_xml_tag* ads_in )
{
    if ( ads_in->ads_child == NULL ) {
        ads_in->ads_child = m_get_new_tag();
        if ( ads_in->ads_child == NULL ) {
            return NULL;
        }
    }
    ads_in->ads_child->ads_prev = ads_in;
    return ads_in->ads_child;
} // end of ds_xml::m_get_next


/**
 * function ds_xml::m_get_new_tag
 *
 * @return    dsd_xml_tag*
*/
dsd_xml_tag* ds_xml::m_get_new_tag()
{
    // initialize some variables:
    dsd_xml_tag* ads_ntag = NULL;

#if XML_DEF_TAGS
    if ( in_used_tags < XML_DEF_TAGS ) {
        ads_ntag = &dsr_tags[in_used_tags];
        in_used_tags++;
    } else {
#endif
        ads_ntag = (dsd_xml_tag*)ads_wsp_helper->m_cb_get_memory( sizeof(dsd_xml_tag), true );
#if XML_DEF_TAGS
    }
#endif

    return ads_ntag;
} // end of ds_xml::m:_get_new_tag


/**
 * function ds_xml::m_get_next
 *
 * @param[in]   dsd_xml_attr*   ads_in
*/
dsd_xml_attr* ds_xml::m_get_next ( dsd_xml_attr* ads_in )
{
    if ( ads_in == NULL ) {
        ads_in = m_get_new_attr();
        return ads_in;
    } else {
        // get entry in chain
        if ( ads_in->ads_next == NULL ) {
            ads_in->ads_next = m_get_new_attr();
        }
        return ads_in->ads_next;
    }
} // end of ds_xml::m_get_next


/**
 * function ds_xml::m_get_new_attr
 *
 * @return    dsd_xml_attr*
*/
dsd_xml_attr* ds_xml::m_get_new_attr()
{
    // initialize some variables:
    dsd_xml_attr* ads_nattr = NULL;

#if XML_DEF_ATTR
    // get entry outsid chain (first entry in tag structure)
    if ( in_used_attr < XML_DEF_ATTR ) { 
        ads_nattr = &dsr_attr[in_used_attr];
        in_used_attr++;
    } else {
#endif
        ads_nattr = (dsd_xml_attr*)ads_wsp_helper->m_cb_get_memory( sizeof(struct dsd_xml_attr), true );
#if XML_DEF_ATTR
    }
#endif

    return ads_nattr;
} // end of ds_xml::m_get_new_attr


/**
 * function ds_xml::m_free_memory
 * free tag chain
 *
 * @param[in] dsd_xml_tag* ads_in
*/
void ds_xml::m_free_memory( dsd_xml_tag* ads_in )
{
    if ( ads_in != NULL ) {
        // free attribute chain:
        if ( ads_in->ads_attr != NULL ) {
            m_free_memory( ads_in->ads_attr );
        }
        // free child chain:
        if ( ads_in->ads_child != NULL ) {
            m_free_memory( ads_in->ads_child );
        }
        // free next chain:
        if ( ads_in->ads_next != NULL ) {
            m_free_memory( ads_in->ads_next );
        }
        if ( m_is_in_stack( ads_in ) == false ) {
            ads_wsp_helper->m_cb_free_memory( ads_in, sizeof(dsd_xml_tag) );
        } else {
            memset( ads_in, 0, sizeof(dsd_xml_tag) );
        }
    }
} // end of ds_xml::m_free_memory


/**
 * function ds_xml::m_free_memory
 * free tag chain
 *
 * @param[in] dsd_xml_key* ads_in
*/
void ds_xml::m_free_memory( dsd_xml_key* ads_in )
{
    if ( ads_in != NULL ) {
        // free next chain:
        if ( ads_in->ads_next != NULL ) {
            m_free_memory( ads_in->ads_next );
        }
        if ( m_is_in_stack( ads_in ) == false ) {
            ads_wsp_helper->m_cb_free_memory( ads_in, sizeof(dsd_xml_key) );
        } else {
            memset( ads_in, 0, sizeof(dsd_xml_key) );
        }
    }
} // end of ds_xml::m_free_memory


/**
 * function ds_xml::m_is_in_stack
 * check if ads_in is a pointer from our data array
 *
 * @param[in]   dsd_xml_tag*    ads_in
 * @return      bool
*/
bool ds_xml::m_is_in_stack( dsd_xml_tag* ads_in )
{
#if XML_DEF_TAGS
    for ( int in_1 = 0; in_1 < XML_DEF_TAGS; in_1++ ) {
        if ( ads_in == &dsr_tags[in_1] ) {
            return true;
        }
    }
#endif
    return false;
} // end of ds_xml::m_is_in_stack


/**
 * function ds_xml::m_is_in_stack
 * check if ads_in is a pointer from our data array
 *
 * @param[in]   dsd_xml_tag*    ads_in
 * @return      bool
*/
bool ds_xml::m_is_in_stack( dsd_xml_key* ads_in )
{
#if XML_DEF_TAGS
    for ( int in_1 = 0; in_1 < XML_DEF_TAGS; in_1++ ) {
        if ( ads_in == &dsr_key[in_1] ) {
            return true;
        }
    }
#endif
    return false;
} // end of ds_xml::m_is_in_stack


/**
 * function ds_xml::m_write_tag
 * write a tag to xml
 *
 * @param[in]   dsd_xml_tag*    ads_in
 * @param[in]   ds_hstring*     ads_xml
*/
void ds_xml::m_write_tag( dsd_xml_tag* ads_in, ds_hstring* ads_xml )
{
    // initialize some variables:
    dsd_xml_attr* ads_tmp_attr;

    //----------------------
    // write start of tag
    //----------------------
    if (    ads_in->ien_type == ied_tag
         || ads_in->ien_type == ied_xmltype
         || ads_in->ien_type == ied_data     ) {
        ads_xml->m_write( "<" );
    }
    ads_xml->m_write( ads_in->ach_data, ads_in->in_len_data );

    //----------------------
    // write attributes
    //----------------------
    if ( ads_in->ien_type == ied_tag || ads_in->ien_type == ied_xmltype ) {
        ads_tmp_attr = ads_in->ads_attr;
        while ( ads_tmp_attr != NULL ) {
            ads_xml->m_write( " " );
            ads_xml->m_write( ads_tmp_attr->ach_name, ads_tmp_attr->in_len_name );
            ads_xml->m_write( "=" );
            ads_xml->m_write( ads_tmp_attr->ach_value, ads_tmp_attr->in_len_value );
            ads_tmp_attr = ads_tmp_attr->ads_next;
        }
    }


    if ( ads_in->ads_child != NULL ) {
        //------------------
        // write tag end:
        //------------------
        if ( ads_in->ien_type == ied_tag || ads_in->ien_type == ied_xmltype ) {
            ads_xml->m_write( ">" );
        }
            
        //------------------
        // write child tag:
        //------------------
        m_write_tag( ads_in->ads_child, ads_xml );

        //------------------
        // write end tag:
        //------------------
        if ( ads_in->ien_type == ied_tag || ads_in->ien_type == ied_xmltype ) {
            ads_xml->m_write( "</" );
            ads_xml->m_write( ads_in->ach_data, ads_in->in_len_data );
            ads_xml->m_write( ">" );
        }
    } else {
        //------------------
        // write tag end:
        //------------------
        switch ( ads_in->ien_type ) {
            case ied_tag:
                ads_xml->m_write( "/>" );
                break;
            case ied_xmltype:
                ads_xml->m_write( " ?>" );
                break;
            case ied_data:
                ads_xml->m_write( ">" );
                break;
        }
    }

    //----------------------
    // write next tag:
    //----------------------
    if ( ads_in->ads_next != NULL ) {
        m_write_tag( ads_in->ads_next, ads_xml );
    }
} // end of ds_xml::m_write_tag


/**
 * function ds_xml::m_free_memory
 * free attribute chain
 *
 * @param[in]   dsd_xml_attr*   ads_in
*/
void ds_xml::m_free_memory( dsd_xml_attr* ads_in )
{
    if ( ads_in != NULL ) {
        // free next chain:
        if ( ads_in->ads_next != NULL ) {
            m_free_memory( ads_in->ads_next );
        }
        if ( m_is_in_stack( ads_in ) == false ) {
            ads_wsp_helper->m_cb_free_memory( ads_in, sizeof(dsd_xml_attr) );
        } else {
            memset( ads_in, 0, sizeof(dsd_xml_attr) );
        }
    }
} // end of ds_xml::m_free_memory


/**
 * function ds_xml::m_is_in_stack
 * check if ads_in is a pointer from our data array
 *
 * @param[in]   dsd_xml_attr*    ads_in
 * @return      bool
*/
bool ds_xml::m_is_in_stack( dsd_xml_attr* ads_in )
{
#if XML_DEF_ATTR
    for ( int in_1 = 0; in_1 < XML_DEF_ATTR; in_1++ ) {
        if ( ads_in == &dsr_attr[in_1] ) {
            return true;
        }
    }
#endif
    return false;
} // end of ds_xml::m_is_in_stack


/**
 * function ds_xml::m_get_encoding
 * get node encoding by name
 *
 * @param[in]   char*       ach_ptr
 * @param[in]   int         in_len
 * @return      ied_charset              node key
*/
ied_charset ds_xml::m_get_encoding( const char* ach_ptr, int in_len )
{
    // initialize some variables:
    if ( in_len > 3 ) {
        if ( ach_ptr[0] == '"' || ach_ptr[0] == '\'' ) {
            ach_ptr++;
            in_len -= 2;
        }
    }

    dsd_const_string dsl_key(ach_ptr, in_len);
    return ds_wsp_helper::m_search_equals_ic2(
        achr_xml_encodings, dsl_key, ied_chs_utf_8);
} // end of ds_xml::m_get_encoding

/**
 * function ds_xml::m_evaluate_tag_length
 *
 * @param[in]  dsd_xml_tag* ads_tag
 *
 * @return     int
*/
int ds_xml::m_evaluate_tag_length( dsd_xml_tag* ads_tag )
{
    int in_len = 0;

    // size of structure itself + length of string:
    in_len = (int)sizeof(dsd_xml_tag_cache) + ads_tag->in_len_data;
    in_len = ((in_len + ALIGN_CAST(ALIGN_SIZE-1)) & ALIGN_CAST(~(ALIGN_SIZE-1)));

    // attribute structure:
    if ( ads_tag->ads_attr != NULL ) {
        in_len += m_evaluate_attr_length( ads_tag->ads_attr );
    }

    // child structure:
    if ( ads_tag->ads_child != NULL ) {
        in_len += m_evaluate_tag_length( ads_tag->ads_child );
    }

    // next structure:
    if ( ads_tag->ads_next != NULL ) {
        in_len += m_evaluate_tag_length( ads_tag->ads_next );
    }

    return in_len;
} // end of ds_xml::m_evaluate_tag_length


/**
 * function ds_xml::m_evaluate_attr_length
 *
 * @param[in]  dsd_xml_attr* ads_attr
 *
 * @return     int
*/
int ds_xml::m_evaluate_attr_length( dsd_xml_attr* ads_attr )
{
    int in_len = 0;

    // size of structure itself + length of strings:
    in_len =   (int)sizeof(dsd_xml_attr_cache)
             + ads_attr->in_len_name
             + ads_attr->in_len_value;
    in_len = ((in_len + ALIGN_CAST(ALIGN_SIZE-1)) & ALIGN_CAST(~(ALIGN_SIZE-1)));

    // next structure:
    if ( ads_attr->ads_next != NULL ) {
        in_len += m_evaluate_attr_length( ads_attr->ads_next );
    }

    return in_len;
} // end of ds_xml::m_evaluate_attr_length


/**
 * function ds_xml::m_copy_tag
 *
 * @param[in]   char*           ach_cache       buffer to write in
 * @param[in]   int             in_len          length of buffer
 * @param[in]   int*            ain_offset      offset in buffer
 * @param[in]   dsd_xml_tag*    ads_tag         tag to copy into buffer
 * @param[in]   int*            ain_index       index position in cache
 *
 * @return     int
*/
bool ds_xml::m_copy_tag( char* ach_cache, int in_len, int* ain_offset,
                         dsd_xml_tag* ads_tag, int* ain_index )
{
    // initialize some variables:
    int                in_needed  = 0;          // needed length
    int                in_aindex  = 0;          // attribute index
    bool               bo_return  = false;      // return value
    dsd_xml_tag_cache* ads_tcache = NULL;       // cache pointer

    //----------------------------------
    // check needed length:
    //----------------------------------
    in_needed = (int)sizeof(dsd_xml_tag_cache) + ads_tag->in_len_data;
    in_needed = ((in_needed + ALIGN_CAST(ALIGN_SIZE-1)) & ALIGN_CAST(~(ALIGN_SIZE-1)));
    if ( in_needed > in_len - *ain_offset ) {
        return false;
    }

    //----------------------------------
    // enlarge index counter:
    //----------------------------------
    (*ain_index)++;

    //----------------------------------
    // copy structure data:
    //----------------------------------
    ads_tcache   = (dsd_xml_tag_cache*)(&ach_cache[*ain_offset]);
    *ain_offset += (int)sizeof(dsd_xml_tag_cache);

    ads_tcache->ien_type    = ads_tag->ien_type;
    ads_tcache->in_len_data = ads_tag->in_len_data;
    ads_tcache->in_attr     = -1;
    ads_tcache->in_child    = -1;
    ads_tcache->in_next     = -1;

    //----------------------------------
    // copy string:
    //----------------------------------
    memcpy( &ach_cache[*ain_offset], ads_tag->ach_data, ads_tag->in_len_data );
    *ain_offset += ads_tag->in_len_data;
    *ain_offset  = ((*ain_offset + ALIGN_CAST(ALIGN_SIZE-1)) & ALIGN_CAST(~(ALIGN_SIZE-1)));

    //----------------------------------
    // copy attibute chain:
    //----------------------------------
    if ( ads_tag->ads_attr != NULL ) {
        ads_tcache->in_attr = in_aindex;
        bo_return = m_copy_attr( ach_cache, in_len,
                                 ain_offset,
                                 ads_tag->ads_attr, &in_aindex );

        if ( bo_return == false ) {
            return false;
        }
    }

    //----------------------------------
    // copy child tag:
    //----------------------------------
    if ( ads_tag->ads_child != NULL ) {
        ads_tcache->in_child = *ain_index;
        bo_return = m_copy_tag( ach_cache, in_len,
                                ain_offset,
                                ads_tag->ads_child, ain_index );

        if ( bo_return == false ) {
            return false;
        }
    }

    //----------------------------------
    // copy next tag:
    //----------------------------------
    if ( ads_tag->ads_next != NULL ) {
        ads_tcache->in_next = *ain_index;
        bo_return = m_copy_tag( ach_cache, in_len,
                                ain_offset,
                                ads_tag->ads_next, ain_index );

        if ( bo_return == false ) {
            return false;
        }
    }

    return true;
} // end of ds_xml::m_copy_tag


/**
 * function ds_xml::m_copy_attr
 *
 * @param[in]   char*           ach_cache       buffer to write in
 * @param[in]   int             in_len          length of buffer
 * @param[in]   int*            ain_offset      offset in buffer
 * @param[in]   dsd_xml_attr*   ads_attr        attribute to copy into buffer
 * @param[in]   int*            ain_index       index position in cache
 *
 * @return     int
*/
bool ds_xml::m_copy_attr( char* ach_cache, int in_len, int* ain_offset,
                          dsd_xml_attr* ads_attr, int* ain_index )
{
    // initialize some variables:
    int                 in_needed  = 0;         // needed length
    bool                bo_return  = false;     // return value
    dsd_xml_attr_cache* ads_acache = NULL;      // cache pointer

    //----------------------------------
    // check needed length:
    //----------------------------------
    in_needed =   (int)sizeof(dsd_xml_attr_cache)
                + ads_attr->in_len_name
                + ads_attr->in_len_value;
    in_needed = ((in_needed + ALIGN_CAST(ALIGN_SIZE-1)) & ALIGN_CAST(~(ALIGN_SIZE-1)));
    if ( in_needed > in_len - *ain_offset ) {
        return false;
    }

    //----------------------------------
    // enlarge index counter:
    //----------------------------------
    (*ain_index)++;

    //----------------------------------
    // copy structure data:
    //----------------------------------
    ads_acache   = (dsd_xml_attr_cache*)(&ach_cache[*ain_offset]);
    *ain_offset += (int)sizeof(dsd_xml_attr_cache);

    ads_acache->in_len_name  = ads_attr->in_len_name;
    ads_acache->in_len_value = ads_attr->in_len_value;
    ads_acache->in_next      = -1;

    //----------------------------------
    // copy name string:
    //----------------------------------
    memcpy( &ach_cache[*ain_offset], ads_attr->ach_name, ads_attr->in_len_name );
    *ain_offset += ads_attr->in_len_name;
    
    //----------------------------------
    // copy value string:
    //----------------------------------
    memcpy( &ach_cache[*ain_offset], ads_attr->ach_value, ads_attr->in_len_value );
    *ain_offset += ads_attr->in_len_value;
    *ain_offset  = ((*ain_offset + ALIGN_CAST(ALIGN_SIZE-1)) & ALIGN_CAST(~(ALIGN_SIZE-1)));


    //----------------------------------
    // copy next tag:
    //----------------------------------
    if ( ads_attr->ads_next != NULL ) {
        ads_acache->in_next = *ain_index;
        bo_return = m_copy_attr( ach_cache, in_len,
                                 ain_offset,
                                 ads_attr->ads_next, ain_index );

        if ( bo_return == false ) {
            return false;
        }
    }

    return true;
} // end of ds_xml::m_copy_attr


/**
 * function ds_xml::m_read_tag
 *
 * @param[in]   char*           ach_cache       buffer to write in
 * @param[in]   int             in_len          length of buffer
 * @param[in]   int             in_index        index position in cache
 * @param[in]   dsd_xml_tag*    ads_tag         tag to copy into buffer
 *
 * @return     dsd_xml_tag_cache*
*/
dsd_xml_tag_cache* ds_xml::m_read_tag( char* ach_cache, int in_len, int in_index )
{
    // initialize some variables:
    int                 in_offset  = 0;         // offset position in cache
    int                 in_pos     = 0;         // working position in cache
    dsd_xml_tag_cache*  ads_tcache = NULL;      // cache tag pointer
    dsd_xml_attr_cache* ads_acache = NULL;      // cache attribute pointer

    //----------------------------------
    // get structure at index:
    //----------------------------------
    ads_tcache = (dsd_xml_tag_cache*)ach_cache;

    for ( ; in_pos < in_index; in_pos++ ) {
        in_offset += (int)sizeof(dsd_xml_tag_cache);
        in_offset += ads_tcache->in_len_data;
        in_offset  = ((in_offset + ALIGN_CAST(ALIGN_SIZE-1)) & ALIGN_CAST(~(ALIGN_SIZE-1)));
        if ( in_offset > in_len ) {
            return NULL;
        }

        // pass attribute chain:
        if ( ads_tcache->in_attr > -1 ) {
            do {
                ads_acache = (dsd_xml_attr_cache*)(&ach_cache[in_offset]);
                in_offset += (int)sizeof(dsd_xml_attr_cache);
                in_offset += ads_acache->in_len_name;
                in_offset += ads_acache->in_len_value;
                in_offset  = ((in_offset + ALIGN_CAST(ALIGN_SIZE-1)) & ALIGN_CAST(~(ALIGN_SIZE-1)));
                if ( in_offset > in_len ) {
                    return NULL;
                }
            } while ( ads_acache->in_next > -1 );
        }
        ads_tcache = (dsd_xml_tag_cache*)(&ach_cache[in_offset]);
    }

    return ads_tcache;
} // end of ds_xml::m_read_tag


/**
 * function ds_xml::m_read_attr
 *
 * @param[in]   dsd_xml_tag_cache*  ads_tag
 * @param[in]   int                 in_index    index position in cache
 *
 * @return     dsd_xml_tag_cache*
*/
dsd_xml_attr_cache* ds_xml::m_read_attr( dsd_xml_tag_cache* ads_tag, int in_index )
{
    // initialize some variables:
    int                 in_offset  = 0;         // offset position in cache
    int                 in_pos     = 0;         // working position in cache
    char*               ach_temp   = NULL;
    dsd_xml_attr_cache* ads_acache = NULL;      // cache attribute pointer

    //----------------------------------
    // get structure at index:
    //----------------------------------
    ach_temp = (char*)ads_tag;
    in_offset += (int)sizeof(dsd_xml_tag_cache);
    in_offset += ads_tag->in_len_data;
    in_offset  = ((in_offset + ALIGN_CAST(ALIGN_SIZE-1)) & ALIGN_CAST(~(ALIGN_SIZE-1)));

    ads_acache = (dsd_xml_attr_cache*)(&ach_temp[in_offset]);

    for ( ; in_pos < in_index; in_pos++ ) {
        in_offset += (int)sizeof(dsd_xml_attr_cache);
        in_offset += ads_acache->in_len_name;
        in_offset += ads_acache->in_len_value;
        in_offset  = ((in_offset + ALIGN_CAST(ALIGN_SIZE-1)) & ALIGN_CAST(~(ALIGN_SIZE-1)));
        ads_acache = (dsd_xml_attr_cache*)(&ach_temp[in_offset]);
    }

    return ads_acache;
} // end of ds_xml::m_read_attr


/**
 * function ds_xml::m_parse_cache
 *
 * @param[in]   dsd_xml_tag*        ads_out
 * @param[in]   char*               ach_cache       buffer to write in
 * @param[in]   int                 in_len          length of buffer
 *
 * @return     bool
*/
bool ds_xml::m_parse_cache( dsd_xml_tag* ads_out, char* ach_cache, int in_len, int in_index )
{
    // initialize some variables:
    dsd_xml_tag_cache*  ads_tcache = NULL;      // cache tag pointer
    bool                bo_return  = false;     // return value
    
    ads_tcache = m_read_tag( ach_cache, in_len, in_index );
    if ( ads_tcache == NULL ) {
        return false;
    }
    ads_out->ien_type    = ads_tcache->ien_type;
    ads_out->in_len_data = ads_tcache->in_len_data;
    ads_out->ach_data    = (char*)ads_tcache + (int)sizeof(dsd_xml_tag_cache);

    if ( ads_tcache->in_child > -1 ) {
        bo_return = m_parse_cache( m_get_child( ads_out ),
                                   ach_cache, in_len,
                                   ads_tcache->in_child );
        if ( bo_return == false ) {
            return false;
        }

    }

    if ( ads_tcache->in_next > -1 ) {
        bo_return = m_parse_cache( m_get_next( ads_out ),
                                   ach_cache, in_len,
                                   ads_tcache->in_next );
        if ( bo_return == false ) {
            return false;
        }
    }

    if ( ads_tcache->in_attr > -1 ) {
        ads_out->ads_attr = m_get_next( ads_out->ads_attr );
        bo_return = m_parse_attr_cache( ads_out->ads_attr,
                                        ads_tcache, ads_tcache->in_attr );
        if ( bo_return == false ) {
            return false;
        }
    }
    return true;
} // end of ds_xml::m_parse_cache


/**
 * function ds_xml::m_parse_cache
 *
 * @param[in]   dsd_xml_attr*       ads_out
 * @param[in]   dsd_xml_tag_cache*  ads_tag
 * @param[in]   int                 in_index
 *
 * @return     bool
*/
bool ds_xml::m_parse_attr_cache( dsd_xml_attr* ads_out, dsd_xml_tag_cache* ads_tag,
                                 int in_index )
{
    // initialize some variables:
    dsd_xml_attr_cache* ads_acache = NULL;      // cache attribute pointer
    bool                bo_return  = false;     // return value

    ads_acache = m_read_attr( ads_tag, in_index );
    if ( ads_acache == NULL ) {
        return false;
    }
    ads_out->in_len_name  = ads_acache->in_len_name;
    ads_out->in_len_value = ads_acache->in_len_value;
    ads_out->ach_name     = (char*)ads_acache + (int)sizeof(dsd_xml_attr_cache);
    ads_out->ach_value    = ads_out->ach_name + ads_out->in_len_name;

    if ( ads_acache->in_next > -1 ) {
        bo_return = m_parse_attr_cache( m_get_next( ads_out ),
                                        ads_tag, ads_acache->in_next );
        if ( bo_return == false ) {
            return false;
        }
    }

    return true;
} // end of ds_xml::m_parse_cache


int ds_xml::m_read_int(dsd_xml_tag* ads_node, const char* ach_nodename, int in_len_nodename, int in_default) {
    if ( (ach_nodename == NULL) || (in_len_nodename < 0) ) {
        return in_default;
    }

    const char*   ach_value;          // node value
    int     in_len_value;       // length of node value
    
    dsd_xml_tag* dsl_tag = m_get_value( ads_node, ach_nodename, in_len_nodename,
                                        &ach_value, &in_len_value);
    if ( (dsl_tag == NULL) || (ach_value == NULL) ) { // error or not set
        return in_default;
    }

    ds_hstring dsl_temp( ads_wsp_helper, ach_value, in_len_value );
    int  inl_ret;
    bool bol_ret = dsl_temp.m_to_int( &inl_ret );
    if ( bol_ret == false ) {
        return in_default;
    }
    return inl_ret;
}

int ds_xml::m_read_int(dsd_xml_tag* ads_node, const dsd_const_string& ach_nodename, int in_default)
{
    return m_read_int(ads_node, ach_nodename.m_get_start(), ach_nodename.m_get_len(), in_default);
}

bool ds_xml::m_read_bool(dsd_xml_tag* ads_node, const char* ach_nodename, int in_len_nodename, bool bo_default) {
    if ( (ach_nodename == NULL) || (in_len_nodename < 0) ) {
        return bo_default;
    }

    const char*   ach_value;          // node value
    int     in_len_value;       // length of node value
    dsd_xml_tag* dsl_tag = m_get_value(ads_node, ach_nodename, in_len_nodename,
                                  &ach_value, &in_len_value);
    if ( (dsl_tag == NULL) || (ach_value == NULL) ) { // error or not set
        return bo_default;
    }

    return m_is_yes(ach_value, in_len_value);
}

bool ds_xml::m_read_bool(dsd_xml_tag* ads_node, const dsd_const_string& ach_nodename, bool bo_default)
{
    return this->m_read_bool(ads_node, ach_nodename.m_get_start(), ach_nodename.m_get_len(), bo_default);
}

// Attention: this method was NOT tested!!!
ds_hstring ds_xml::m_read_array(dsd_xml_tag* ads_node, const char* ach_nodename, int in_len_nodename) {
    ds_hstring hstr_ret;
    hstr_ret.m_setup(ads_wsp_helper);
    if ( (ach_nodename == NULL) || (in_len_nodename < 0) ) {
        return hstr_ret;
    }

    const char*   ach_value;          // node value
    int     in_len_value;       // length of node value
    dsd_xml_tag* dsl_tag = m_get_value(ads_node, ach_nodename, in_len_nodename,
                                  &ach_value, &in_len_value);
    if ( (dsl_tag == NULL) || (ach_value == NULL) ) { // error or not set
        return hstr_ret;
    }

    hstr_ret.m_from_b64( ach_value, in_len_value );
    return hstr_ret;
}


ds_hstring ds_xml::m_read_string(dsd_xml_tag* ads_node, const char* ach_nodename, int in_len_nodename, const char* ach_def, int in_len_def) {
    ds_hstring hstr_ret;
    hstr_ret.m_setup(ads_wsp_helper);
    hstr_ret.m_set(ach_def, in_len_def);

    if ( (ach_nodename == NULL) || (in_len_nodename < 0) ) {
        return hstr_ret;
    }

    const char*   ach_value;          // node value
    int     in_len_value;       // length of node value
    dsd_xml_tag* dsl_tag = m_get_value(ads_node, ach_nodename, in_len_nodename,
                                  &ach_value, &in_len_value);
    if ( (dsl_tag == NULL) || (ach_value == NULL) ) { // error or not set
        return hstr_ret;
    }
    
    hstr_ret.m_set(ach_value, in_len_value);

    return hstr_ret;
}


/**
 * function ds_ea_ldap::m_is_yes
 * 
 * @param[in]   char*       ach_ptr
 * @param[in]   int         in_len
 * @return      bool        
*/
bool ds_xml::m_is_yes(const char* ach_ptr, int in_len)
{
    dsd_const_string dsl_value(ach_ptr, in_len);
    if(dsl_value.m_equals_ic("y"))
        return true;
    if(dsl_value.m_equals_ic("yes"))
        return true;
    return false;
} // end of ds_xml::m_is_yes
