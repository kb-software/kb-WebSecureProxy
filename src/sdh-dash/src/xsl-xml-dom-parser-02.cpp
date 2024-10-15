/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| --------                                                            |*/
/*|   XML parser using DOM syntax                                       |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| -------                                                             |*/
/*|   Michael Jakobs, Aug. 2011                                         |*/
/*|   18.01.14 KB                                                       |*/
/*|                                                                     |*/
/*| Copyright:                                                          |*/
/*| ----------                                                          |*/
/*|   HOB Germany, 2011                                                 |*/
/*|   Copyright (C) HOB Germany 2014                                    |*/
/*|                                                                     |*/
/*| Required headers:                                                   |*/
/*| -----------------                                                   |*/
/*|   "hob-xslunic1.h",                                                 |*/
/*|   <stdio.h>,                                                        |*/
/*|   <stdarg.h>,                                                       |*/
/*|   <ctype.h> and                                                     |*/
/*|   <string.h>                                                        |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/**
   attention:
   in XML documents, special encoding is needed.
   this source manages this special encoding
   in combination with the HOB Unicode Library.
   Each XML document may contains special encoding,
   only valid for this single document.
   This is not handled by HOB components.
*/

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
#ifdef __cplusplus
    #define PUBLIC extern "C"
#else
    #define PUBLIC extern
#endif
#ifdef __TEST__
    #define PRIVATE extern "C"
#else
    #define PRIVATE static
#endif


#ifndef DEF_XML_ALIGN
#define DEF_XML_ALIGN(i) ((i + (sizeof(void*)-1)) & (~(sizeof(void*)-1)))
#endif

#include <stdio.h>
#include <stdarg.h>
#ifndef HL_UNIX
#include <windows.h>
#else
#include <string.h>
#include <ctype.h>
#include <hob-unix01.h>
#endif
#include <hob-xslunic1.h>
#include <hob-xml-dom-parser-02.h>

#define DEF_NO_NODES    30                  /* start number of nodes     */
#define DEF_NO_ATTR     10                  /* start number of attributes*/

/*+---------------------------------------------------------------------+*/
/*| constants:                                                          |*/
/*+---------------------------------------------------------------------+*/

static const char chrs_xml_version[]  = {'v','e','r','s','i','o','n'    };
static const char chrs_xml_encoding[] = {'e','n','c','o','d','i','n','g'};

#ifdef WAS_BEFORE
/* compate to definition of enum ied_xml_version                         */
static const char *achrs_xml_versions[] = {
    ""      , ""        , ""        , ""        , /* 0 - 3               */
    ""      , ""        , ""        , ""        , /* 4 - 7               */
    ""      , ""        , "1.0"     , NULL        /* 8 - 11              */
};

/* compare to definition of enum ied_charset                             */
static const char *achrs_xml_encodings[] = {
    "invalid"   , "iso-8859-1"  , "iso-8859-1"  , "utf-8"       ,
    "utf-16"    , "invalid"     , "invalid"     , "utf-32"      ,
    "invalid"   , "invalid"     , "invalid"     , NULL
};
#endif

struct dsd_xml_charset_tab {                /* XML charset             */
   const char       *achc_name;
   enum ied_charset iec_chs;                /* define character set    */
};

static const struct dsd_xml_charset_tab dsrs_xml_charset_tab[] = {
   { "utf-8",         ied_chs_xml_utf_8 },  /* XML Unicode UTF-8       */
// to-do 19.01.14 KB - is iso-8859-1 right ???
   { "iso-8859-1",    ied_chs_xml_wcp_1252 },  /* XML Windows-Codepage 1252 */
   { "windows-1252",  ied_chs_xml_wcp_1252 },  /* XML Windows-Codepage 1252 */
   { "utf-16",        ied_chs_utf_16 },     /* Unicode UTF-16          */
   { "utf-32",        ied_chs_utf_32 }      /* Unicode UTF-32          */
};

/*+---------------------------------------------------------------------+*/
/*| forward declarations:                                               |*/
/*+---------------------------------------------------------------------+*/

struct dsd_unicode_string;
enum ied_charset;

/*+---------------------------------------------------------------------+*/
/*| definitions:                                                        |*/
/*+---------------------------------------------------------------------+*/
#ifdef IS_IN_HEADER
typedef struct dsd_xml_parser_cbs {
    void *avc_usrfld;                        /* user field for callbacks */

    /**
     * function pointer amc_alloc
     *   will be called if parser needs to allocate memory
     *
     * @param[in]   void*                    pointer to given user field
     * @param[in]   size_t                   size of memory
     * @return      void*                    pointer to memory
     *                                       or NULL in error cases
    */
    void* (*amc_alloc) ( void*, size_t );

    /**
     * function pointer amc_free
     *   will be called if parser needs to free memory
     *
     * @param[in]   void*                    pointer to given user field
     * @param[in]   void*                    pointer to be freed
     * @return      void*                    pointer to memory
     *                                       or NULL in error cases
    */
    void (*amc_free)   ( void*, void* );
} dsd_xml_parser_cbs;


enum ied_nodetype {
    ied_nt_unknown,                         /* something unknown         */
    ied_nt_node,                            /* domnode                   */
    ied_nt_text,                            /* text                      */
    ied_nt_comment,                         /* comment                   */
    ied_nt_cdata                            /* cdata section             */
};

enum ied_xml_version {
    ied_xver_unknown =  0,                  /* unknown version           */
    ied_xver_10      = 10                   /* 1.0                       */
};
#endif

typedef struct dsd_xmlbytes {
    void    *avc_ptr;                       /* pointer to data           */
    size_t  uinc_length;                    /* number of bytes           */
} dsd_xmlbytes;

typedef struct dsd_xmlpos {
    size_t                    uinc_line;    /* line number in buffer     */
    size_t                    uinc_col;     /* column number in buffer   */
} dsd_xmlpos;

typedef struct dsd_xml_attribute {
    struct dsd_xmlbytes       dsc_name;     /* attribute name            */
    struct dsd_xmlbytes       dsc_value;    /* attribute value           */
    struct dsd_unicode_string dsc_us_name;  /* attr value as unicode str */
    struct dsd_unicode_string dsc_us_val;   /* attr value as unicode str */
    struct dsd_xml_attribute  *adsc_next;   /* next attribute            */
    enum   ied_charset        ienc_charset; /* character set             */
} dsd_xml_attribute;

typedef struct dsd_xml_domnode {
    enum   ied_nodetype       ienc_type;    /* node type                 */
    struct dsd_xmlbytes       dsc_value;    /* node value                */
    struct dsd_unicode_string dsc_us_val;   /* node value as unicode str */
    BOOL                      boc_closed;   /* tag is closed             */
    struct dsd_xmlpos         dsc_pos;      /* position in document      */
    struct dsd_xml_attribute  *adsc_attr;   /* node attributes           */
    struct dsd_xml_domnode    *adsc_child;  /* first child               */
    struct dsd_xml_domnode    *adsc_parent; /* parent node               */
    struct dsd_xml_domnode    *adsc_next;   /* next sibling              */
    struct dsd_xml_domnode    *adsc_prev;   /* previous sibling          */
    enum   ied_charset        ienc_charset; /* character set             */
} dsd_xml_domnode;


typedef struct dsd_xml_storage {
    size_t                    uinc_size;    /* size of single element    */
    size_t                    uinc_elements;/* number of elements        */
    size_t                    uinc_next_free;/* next free element        */
    void                      *avc_storage; /* storage itself            */
    struct dsd_xml_storage    *adsc_next;   /* next storage              */
    struct dsd_xml_parser_cbs *adsc_cbs;    /* callback methods          */
} dsd_xml_storage;

typedef struct dsd_xml_doctype {
    enum ied_charset          ienc_charset;     /* character set         */
    enum ied_xml_version      ienc_version;     /* xml version           */
} dsd_xml_doctype;

typedef struct dsd_xml_domparser {
    struct dsd_xml_doctype    dsc_doctype;      /* xml doctype           */
    struct dsd_xml_domnode    *adsc_firstnode;  /* first node            */
    struct dsd_xml_domnode    *adsc_current;    /* current working node  */
    struct dsd_xmlpos         dsc_pos;          /* cur position in doc   */
    struct dsd_xml_storage    *adsc_nodes;      /* node storage list     */
    struct dsd_xml_storage    *adsc_attributes; /* attribute storage list*/
    struct dsd_xml_parser_cbs *adsc_cbs;        /* callback methods      */
    char                      chrc_error[128];  /* last error            */
} dsd_xml_domparser;


/*+---------------------------------------------------------------------+*/
/*| function prototypes:                                                |*/
/*+---------------------------------------------------------------------+*/
PRIVATE BOOL m_parse_data( struct dsd_xml_domparser *adsp_parser,
                           const char **aachp_xml, const char *achp_end );
PRIVATE void m_set_error( struct dsd_xml_domparser *adsp_parser,
                          const char *achp_format, ... );

PRIVATE struct dsd_xml_storage* m_new_xml_storage( size_t uinp_sizeof,
                                                   size_t uinp_elements,
                                                   struct dsd_xml_parser_cbs *adsp_cbs );
PRIVATE void  m_delete_storage  ( struct dsd_xml_storage *adsp_stor );
PRIVATE void* m_get_next_storage( struct dsd_xml_storage *adsp_stor );

/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
 * public function m_new_xml_parser
 *  create a new xml parser instance
 *
 * @param[in]   dsd_xml_parser_cbs  *adsp_cbs   callback methods
 * @return      void*                           pointer to xml parser object
 *                                              null in error cases
*/
PUBLIC void* m_new_xml_parser( struct dsd_xml_parser_cbs *adsp_cbs )
{
    struct dsd_xml_domparser *adsl_parser;

    if (    adsp_cbs            == NULL
         || adsp_cbs->amc_alloc == NULL
         || adsp_cbs->amc_free  == NULL ) {
        return NULL;
    }

    adsl_parser = (struct dsd_xml_domparser *) adsp_cbs->amc_alloc(
                                        adsp_cbs->avc_usrfld,
                                        sizeof(struct dsd_xml_domparser) );
    if ( adsl_parser != NULL ) {
        memset( adsl_parser, 0, sizeof(dsd_xml_domparser) );
        adsl_parser->adsc_cbs          = adsp_cbs;
        adsl_parser->dsc_pos.uinc_line = 1;
        adsl_parser->dsc_pos.uinc_col  = 1;
        adsl_parser->adsc_nodes = m_new_xml_storage(
                                            sizeof(struct dsd_xml_domnode),
                                            DEF_NO_NODES, adsp_cbs );
        if ( adsl_parser->adsc_nodes == NULL ) {
            adsp_cbs->amc_free( adsp_cbs->avc_usrfld, adsl_parser );
            return NULL;
        }
        adsl_parser->adsc_attributes = m_new_xml_storage(
                                            sizeof(struct dsd_xml_attribute),
                                            DEF_NO_ATTR, adsp_cbs );
        if ( adsl_parser->adsc_attributes == NULL ) {
            m_delete_storage( adsl_parser->adsc_attributes );
            adsp_cbs->amc_free( adsp_cbs->avc_usrfld, adsl_parser );
            return NULL;
        }
        adsl_parser->dsc_doctype.ienc_charset = ied_chs_utf_8;
    }
    return adsl_parser;
} /* end of m_new_xml_parser */


/**
 * public function m_delete_xml_parser
 *  delete an existing xml parser instance
 *
 * @param[in]   void    **aavp_parser       ptr to parser handle
 * @return                                  nothing
*/
PUBLIC void m_delete_xml_parser( void **aavp_parser )
{
    struct dsd_xml_domparser *adsl_parser;

    adsl_parser = (struct dsd_xml_domparser *)*aavp_parser;
    if ( adsl_parser != NULL ) {
        m_delete_storage( adsl_parser->adsc_nodes      );
        m_delete_storage( adsl_parser->adsc_attributes );
        adsl_parser->adsc_cbs->amc_free( adsl_parser->adsc_cbs->avc_usrfld,
                                         adsl_parser );
        *aavp_parser = NULL;
    }
    return;
} /* end of m_delete_xml_parser */


/**
 * public function m_parse_xml
 *  parse given xml data
 *
 * @param[in]   void            *avp_parser     parser handle
 * @param[in]   const char      *achp_xml       ptr to xml data
 * @param[in]   size_t          uinp_length     length of xml data
 * @return      void*                           first node handle
*/
PUBLIC void* m_parse_xml( void *avp_parser,
                          const char *achp_xml, size_t uinp_length )
{
    struct dsd_xml_domparser *adsl_parser;
    BOOL                     bol_ret;
    const char               *achl_end;

    if (    avp_parser == NULL
         || achp_xml   == NULL
         || uinp_length < 1 ) {
        return NULL;
    }

    adsl_parser = (struct dsd_xml_domparser *)avp_parser;
    achl_end = achp_xml + uinp_length;

    while ( achp_xml < achl_end ) {
        bol_ret = m_parse_data( adsl_parser, &achp_xml, achl_end );
        if ( bol_ret == FALSE ) {
            return NULL;
        }
    }

    return (void*)adsl_parser->adsc_firstnode;
} /* end of m_parse_xml */


/**
 * public function m_get_nextsibling
 *  get next sibling of given node
 *
 * @param[in]   void        *avp_node           current node
 * @return      void*                           next sibling if found
 *                                              NULL in error cases
*/
PUBLIC void* m_get_nextsibling( void *avp_node )
{
    return avp_node?(void*)(((struct dsd_xml_domnode*)avp_node)->adsc_next):NULL;
} /* end of m_get_nextsibling */


/**
 * public function m_get_prevsibling
 *  get previous sibling of given node
 *
 * @param[in]   void        *avp_node           current node
 * @return      void*                           previous sibling if found
 *                                              NULL in error cases
*/
PUBLIC void* m_get_prevsibling( void *avp_node )
{
    return avp_node?(void*)(((struct dsd_xml_domnode*)avp_node)->adsc_prev):NULL;
} /* end of m_get_prevsibling */


/**
 * public function m_get_firstchild
 *  get first child of given node
 *
 * @param[in]   void        *avp_node           current node
 * @return      void*                           first child if found
 *                                              NULL in error cases
*/
PUBLIC void* m_get_firstchild( void *avp_node )
{
    return avp_node?(void*)(((struct dsd_xml_domnode*)avp_node)->adsc_child):NULL;
} /* end of m_get_firstchild */


/**
 * public function m_get_parentnode
 *  get parent node of given node
 *
 * @param[in]   void        *avp_node           current node
 * @return      void*                           parent if found
 *                                              NULL in error cases
*/
PUBLIC void* m_get_parentnode( void *avp_node )
{
    return avp_node?(void*)(((struct dsd_xml_domnode*)avp_node)->adsc_parent):NULL;
} /* end of m_get_parentnode */


/**
 * public function m_get_nodetype
 *  get type of given node
 *
 * @param[in]   void            *avp_node       current node
 * @return      ied_nodetype                    type of node
*/
PUBLIC enum ied_nodetype m_get_nodetype( void *avp_node )
{
    return avp_node?((struct dsd_xml_domnode*)avp_node)->ienc_type:ied_nt_unknown;
} /* end of m_get_nodetype */


/**
 * public function m_get_node_pos
 *  get position of given node
 *
 * @param[in]   void            *avp_node       current node
 * @param[out]  size_t          *auinp_line     line of node
 * @param[out]  size_t          *auinp_column   column of node
 * @return      nothing
*/
PUBLIC void m_get_node_pos( void *avp_node,
                            size_t *auinp_line, size_t *auinp_column )
{
    if ( avp_node != NULL ) {
        *auinp_line   = ((struct dsd_xml_domnode*)avp_node)->dsc_pos.uinc_line;
        *auinp_column = ((struct dsd_xml_domnode*)avp_node)->dsc_pos.uinc_col;
        return;
    }
    *auinp_line   = 0;
    *auinp_column = 0;
    return;
} /* end of m_get_node_pos */


/**
 * public function m_get_node_line
 *  get line of given node
 *
 * @param[in]   void            *avp_node       current node
 * @return      size_t                          line number
*/
PUBLIC size_t m_get_node_line( void *avp_node )
{
    if ( avp_node != NULL ) {
        return ((struct dsd_xml_domnode*)avp_node)->dsc_pos.uinc_line;
    }
    return 0;
} /* end of m_get_node_line */


/**
 * public function m_get_node_column
 *  get column of given node
 *
 * @param[in]   void            *avp_node       current node
 * @return      size_t                          column number
*/
PUBLIC size_t m_get_node_column( void *avp_node )
{
    if ( avp_node != NULL ) {
        return ((struct dsd_xml_domnode*)avp_node)->dsc_pos.uinc_col;
    }
    return 0;
} /* end of m_get_node_column */


/**
 * public function m_get_node_value
 *  get value of current node
 *
 * @param[in]   void                *avp_node   current node
 * @return      dsd_unicode_string*             value if found
 *                                              filled with 0 in error cases
*/
PUBLIC struct dsd_unicode_string* m_get_node_value( void *avp_node )
{
    struct dsd_xml_domnode    *adsl_node;

    if ( avp_node != NULL ) {
        adsl_node = (struct dsd_xml_domnode*)avp_node;
        return &((struct dsd_xml_domnode*)avp_node)->dsc_us_val;
    }
    return NULL;
} /* end of m_get_node_value */


/**
 * public function m_get_attribute
 *  get attribute of current node
 *
 * @param[in]   void            *avp_node       current node
 * @return      void*                           attribute handle
 *                                              NULL in error cases
*/
PUBLIC void* m_get_attribute( void *avp_node )
{
    return (avp_node)?(void*)(((struct dsd_xml_domnode*)avp_node)->adsc_attr):NULL;
} /* end of m_get_attribute */


/**
 * public function m_get_next_attr
 *  get next attribute of given one
 *
 * @param[in]   void            *avp_attr       current attribute
 * @return      void*                           attribute handle
 *                                              NULL in error cases
*/
PUBLIC void* m_get_next_attr( void *avp_attr )
{
    return (avp_attr)?((void*)(((struct dsd_xml_attribute*)avp_attr)->adsc_next)):NULL;
} /* end of m_get_next_attr */


/**
 * public function m_get_attr_name
 *  get name of given attribute
 *
 * @param[in]   void                *avp_attr   current attribute
 * @return      dsd_unicode_string*             name if found
 *                                              filled with 0 in error cases
*/
PUBLIC struct dsd_unicode_string* m_get_attr_name( void *avp_attr )
{
    if ( avp_attr != NULL ) {
        return &((struct dsd_xml_attribute*)avp_attr)->dsc_us_name;
    }
    return NULL;
} /* end of m_get_attr_name */


/**
 * public function m_get_attr_value
 *  get value of given attribute
 *
 * @param[in]   void                *avp_attr   current attribute
 * @return      dsd_unicode_string*             value if found
 *                                              filled with 0 in error cases
*/
PUBLIC struct dsd_unicode_string* m_get_attr_value( void *avp_attr )
{
    if ( avp_attr != NULL ) {
        return &((struct dsd_xml_attribute*)avp_attr)->dsc_us_val;
    }
    return NULL;
} /* end of m_get_attr_value */


/**
 * public function m_get_lasterror
 *  get last error
 *
 * @param[in]   void            *avp_parser             parser handle
 * @return      char*                                   pointer to message
 *                                                      NULL if no error
*/
PUBLIC char* m_get_lasterror( void *avp_parser )
{
    struct dsd_xml_domparser *adsl_parser;

    adsl_parser = (struct dsd_xml_domparser*)avp_parser;
    if ( adsl_parser != NULL ) {
        return (adsl_parser->chrc_error[0] == 0)?NULL:adsl_parser->chrc_error;
    }
    return NULL;
} /* end of m_get_lasterror */


/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/
/**
 * private function m_find_sign
 *  find given sign in data
 *
 * @param[in]   dsd_xml_domparser   *adsp_parser        parser object
 * @param[in]   const char          **aachp_xml         ptr to data
 * @param[in]   const char          *achp_end           end of data
 * @param[in]   const char          chp_sign            sign to search
 * @return      BOOL                                    TRUE = found
 *                                                      FALSE = otherwise
*/
PRIVATE inline BOOL m_find_sign( struct dsd_xml_domparser *adsp_parser,
                                 const char **aachp_xml, const char *achp_end,
                                 const char chp_sign )
{
    BOOL bol_newline = FALSE;

    while ( *aachp_xml < achp_end ) {
        if ( **aachp_xml == chp_sign ) {
            if ( bol_newline == TRUE ) {
                adsp_parser->dsc_pos.uinc_line++;
                adsp_parser->dsc_pos.uinc_col = 1;
            }
            return TRUE;
        } else if ( **aachp_xml == 0x0D ) {
            bol_newline = TRUE;
        } else if ( **aachp_xml == 0x0A ) {
            adsp_parser->dsc_pos.uinc_line++;
            adsp_parser->dsc_pos.uinc_col = 0;
            bol_newline = FALSE;
        } else if ( bol_newline == TRUE ) {
            adsp_parser->dsc_pos.uinc_line++;
            adsp_parser->dsc_pos.uinc_col = 0;
            bol_newline = FALSE;
        }

        (*aachp_xml)++;
        adsp_parser->dsc_pos.uinc_col++;
    }
    return FALSE;
} /* end of m_find_sign */


/**
 * private function m_read_node_name
 *  read node name
 *
 * @param[in]   dsd_xml_domnode     *adsp_node      node object
 * @param[in]   const char          **aachp_node    ptr to node
 * @param[in]   const char          *achp_end       end of node
 * @return      BOOL                                TRUE = success
 *                                                  FALSE otherwise
*/
PRIVATE inline BOOL m_read_node_name( struct dsd_xml_domnode *adsp_node,
                                      const char **aachp_node,
                                      const char *achp_end )
{
    if (    **aachp_node >= '0'
         && **aachp_node <= '9'
         || **aachp_node == ' '
         || **aachp_node == '\t' ) {
        return FALSE;
    }

    while ( *aachp_node < achp_end ) {
        switch ( **aachp_node ) {
            case ' ':
            case '\t':
            case '\r':
            case '\n':
                (*aachp_node)++;
                return TRUE;

            default:
                if ( adsp_node->dsc_value.avc_ptr == NULL ) {
                    adsp_node->dsc_value.avc_ptr = (void*)(*aachp_node);
                }
                adsp_node->dsc_value.uinc_length++;
                (*aachp_node)++;
                break;
        }
    }
    return TRUE;
} /* end of m_read_node_name */


/**
 * private function m_read_node_attr
 *  read node attribute
 *
 * @param[in]   dsd_xml_attribute   *adsp_attr      attribute object
 * @param[in]   const char          **aachp_node    ptr to node
 * @param[in]   const char          *achp_end       end of node
 * @return      BOOL                                TRUE = success
 *                                                  FALSE otherwise
*/
PRIVATE inline BOOL m_read_node_attr( struct dsd_xml_attribute *adsp_attr,
                                      const char **aachp_node,
                                      const char *achp_end )
{
    int  inl_state;
    char chl_quote;

    /* read attributes name */
    inl_state = 0;
#define SIGN_FOUND      1
#define NO_SIGN_ALLOWED 2
    while ( *aachp_node < achp_end ) {
        switch ( **aachp_node ) {
            case ' ':
            case '\t':
                if ( inl_state == SIGN_FOUND ) {
                    inl_state = NO_SIGN_ALLOWED;
                }
                (*aachp_node)++;
                continue;

            case '=':
                (*aachp_node)++;
                break;

            default:
                if ( inl_state == NO_SIGN_ALLOWED ) {
                    return FALSE;
                }
                inl_state = SIGN_FOUND;
                if ( adsp_attr->dsc_name.avc_ptr == NULL ) {
                    adsp_attr->dsc_name.avc_ptr = (void*)(*aachp_node);
                }
                adsp_attr->dsc_name.uinc_length++;
                (*aachp_node)++;
                continue;
        }
        break;
    }
    if ( adsp_attr->dsc_name.avc_ptr == NULL ) {
        return FALSE;
    }
#undef SIGN_FOUND
#undef NO_SIGN_ALLOWED

    /* go over spaces */
    while ( *aachp_node < achp_end ) {
        switch( **aachp_node ) {
            case ' ':
            case '\t':
                (*aachp_node)++;
                continue;
            default:
                break;
        }
        break;
    }
    if ( *aachp_node == achp_end ) {
        return FALSE;
    }


    /* read attribute value */
    switch( **aachp_node ) {
        case '"':
        case '\'':
            chl_quote = **aachp_node;
            (*aachp_node)++;
            break;
        default:
            return FALSE;
    }

    while ( *aachp_node < achp_end ) {
        if ( **aachp_node == chl_quote ) {
            (*aachp_node)++;
            break;
        } else if ( **aachp_node == '\\' ) {
            (*aachp_node)++;
            adsp_attr->dsc_value.uinc_length += 2;
        } else {
            if ( adsp_attr->dsc_value.avc_ptr == NULL ) {
                adsp_attr->dsc_value.avc_ptr = (void*)(*aachp_node);
            }
            adsp_attr->dsc_value.uinc_length++;
        }

        (*aachp_node)++;
    }
    if ( adsp_attr->dsc_value.avc_ptr == NULL ) {
        return FALSE;
    }
    return TRUE;
} /* end of m_read_node_attr */


/**
 * private function m_fill_unicodestring
 *  fill unicode string structure in node
 *
 * @param[in]   dsd_xmlbytes        *adsp_bytes     xml bytes
 * @param[in]   ied_charset         ienp_charset    charset
 * @param[out]  dsd_unicode_string  *adsp_us        unicode string
 * @return      nothing
*/
PRIVATE inline void m_fill_unicodestring( struct dsd_xmlbytes *adsp_bytes,
                                          enum ied_charset ienp_charset,
                                          struct dsd_unicode_string *adsp_us )
{
    adsp_us->iec_chs_str = ienp_charset;
    adsp_us->ac_str      = adsp_bytes->avc_ptr;
    switch ( ienp_charset ) {
        case ied_chs_utf_16:
        case ied_chs_be_utf_16:
        case ied_chs_le_utf_16:
            adsp_us->imc_len_str = (int)adsp_bytes->uinc_length/2;
            break;

        case ied_chs_utf_32:
        case ied_chs_be_utf_32:
        case ied_chs_le_utf_32:
            adsp_us->imc_len_str = (int)adsp_bytes->uinc_length/4;
            break;

        default:
            adsp_us->imc_len_str = (int)adsp_bytes->uinc_length;
            break;
    }
} /* end of m_fill_nodename_us */


/**
 * private function m_is_empty_node
 *  check if given node is a empty "<xyz/>" node
 *
 * @param[in]   const char          *achp_node      ptr to node
 * @param[in]   const char          *achp_end       end of node
 * @return      BOOL
*/
PRIVATE inline BOOL m_is_empty_node( const char *achp_node, const char *achp_end )
{
    return ((achp_node < (achp_end - 1)) && (*(achp_end - 1) == '/'))?TRUE:FALSE;
} /* end of m_is_empty_node */


/**
 * private function m_parse_node
 *  parse given node
 *
 * @param[in]   dsd_xml_domparser   *adsp_parser    parser object
 * @param[in]   const char          *achp_node      ptr to node
 * @param[in]   const char          *achp_end       end of node
 * @param[in]   dsd_xmlpos          *adsp_pos       position of node
 * @return      dsd_xml_domnode*
*/
PRIVATE struct dsd_xml_domnode* m_parse_node( struct dsd_xml_domparser *adsp_parser,
                                              const char *achp_node,
                                              const char *achp_end,
                                              struct dsd_xmlpos *adsl_pos )
{
    BOOL                     bol_ret;
    const char               *achl_node = achp_node;
    struct dsd_xml_domnode   *adsl_node;
    struct dsd_xml_attribute *adsl_attr;
    struct dsd_xml_attribute *adsl_last = NULL;

    /* go over first '<' sign */
    achl_node++;
    if ( achl_node >= achp_end ) {
        return NULL;
    }

    /* get new node buffer */
    adsl_node = (struct dsd_xml_domnode*)m_get_next_storage( adsp_parser->adsc_nodes );
    if ( adsl_node == NULL ) {
        m_set_error( adsp_parser, "XMLparser-%05d- cannot get memory for domnode",
                     __LINE__ );
        return FALSE;
    }
    adsl_node->ienc_type    = ied_nt_node;
    adsl_node->ienc_charset = adsp_parser->dsc_doctype.ienc_charset;

    /* check whether our node is an empty <child/> node */
    bol_ret = m_is_empty_node( achl_node, achp_end );
    if ( bol_ret == TRUE ) {
        adsl_node->boc_closed = TRUE;
        achp_end--;
    }

    /* fill line and column information */
    adsl_node->dsc_pos.uinc_line = adsl_pos->uinc_line;
    adsl_node->dsc_pos.uinc_col  = adsl_pos->uinc_col;

    /* read node name */
    bol_ret = m_read_node_name( adsl_node, &achl_node, achp_end );
    if ( bol_ret == FALSE ) {
        m_set_error( adsp_parser, "invalid name found in node at line %u, column %u",
                     adsl_node->dsc_pos.uinc_line, adsl_node->dsc_pos.uinc_col );
        return NULL;
    }

    if ( achl_node == achp_end ) {
        return adsl_node;
    }

    /* read attributes */
    while ( achl_node < achp_end ) {
        adsl_attr = (struct dsd_xml_attribute*)m_get_next_storage( adsp_parser->adsc_attributes );
        if ( adsl_attr == NULL ) {
            m_set_error( adsp_parser, "XMLparser-%05d- cannot get memory for domattribute",
                         __LINE__ );
            return FALSE;
        }
        adsl_attr->ienc_charset = adsp_parser->dsc_doctype.ienc_charset;
        bol_ret = m_read_node_attr( adsl_attr, &achl_node, achp_end );
        if ( bol_ret == FALSE ) {
            m_set_error( adsp_parser, "invalid attributes found in node at line %u, column %u",
                         adsl_node->dsc_pos.uinc_line, adsl_node->dsc_pos.uinc_col );
            return NULL;
        }
        if ( adsl_node->adsc_attr == NULL ) {
            adsl_node->adsc_attr = adsl_attr;
            adsl_last = adsl_attr;
        } else {
            adsl_last->adsc_next = adsl_attr;
            adsl_last = adsl_attr;
        }

        /* save attribute name and value as unicode structure also */
        m_fill_unicodestring( &adsl_attr->dsc_name, adsl_attr->ienc_charset,
                              &adsl_attr->dsc_us_name );
        m_fill_unicodestring( &adsl_attr->dsc_value, adsl_attr->ienc_charset,
                              &adsl_attr->dsc_us_val );
    }

    return adsl_node;
} /* end of m_parse_node */


/**
 * private function m_is_bom
 *  check if given text is byte order mark
 *
 * @param[in]   dsd_xml_domparser   *adsp_parser    parser object
 * @param[in]   const char          *achp_text      ptr to text data
 * @param[in]   const char          *achp_end       end of text data
 * @return      BOOL
*/
PRIVATE inline BOOL m_is_bom( struct dsd_xml_domparser *adsp_parser,
                              const char *achp_text, const char *achp_end )
{
    if ( adsp_parser->dsc_pos.uinc_line != 1 ) {
        return FALSE;
    }

    switch ( (size_t)(achp_end - achp_text) ) {
        case 2:
            if (    (unsigned char)achp_text[0] == 0xFE
                && (unsigned char)achp_text[1] == 0xFF ) {
                /* utf-16 big endian */
                return TRUE;
            }
            if (    (unsigned char)achp_text[0] == 0xFF
                 && (unsigned char)achp_text[1] == 0xFE ) {
                /* utf-16 little endian */
                return TRUE;
            }
            break;

        case 3:
            if (    (unsigned char)achp_text[0] == 0xEF
                 && (unsigned char)achp_text[1] == 0xBB
                 && (unsigned char)achp_text[2] == 0xBF ) {
                /* utf-8 */
                return TRUE;
            }
            break;

        case 4:
            if (    (unsigned char)achp_text[0] == 0x00
                 && (unsigned char)achp_text[1] == 0x00
                 && (unsigned char)achp_text[2] == 0xFE
                 && (unsigned char)achp_text[3] == 0xFF ) {
                /* utf-32 big endian */
                return TRUE;
            }
            if (    (unsigned char)achp_text[0] == 0xFF
                 && (unsigned char)achp_text[1] == 0xFE
                 && (unsigned char)achp_text[2] == 0x00
                 && (unsigned char)achp_text[3] == 0x00 ) {
                /* utf-32 little endian */
                return TRUE;
            }
            break;
    }
    return FALSE;
} /* end of m_is_bom */


/**
 * private function m_save_text
 *  save text data in our xml chain
 *
 * @param[in]   dsd_xml_domparser   *adsp_parser    parser object
 * @param[in]   const char          *achp_text      ptr to text data
 * @param[in]   const char          *achp_end       end of text data
 * @return      BOOL                                TRUE = continue
 *                                                  FALSE otherwise
*/
PRIVATE inline BOOL m_save_text( struct dsd_xml_domparser *adsp_parser,
                                 const char *achp_text, const char *achp_end )
{
    struct dsd_xml_domnode *adsl_node;          /* new node to be added  */
    struct dsd_xml_domnode *adsl_child;         /* last child            */

    //if ( adsp_parser->adsc_current == NULL ) {
    //    m_set_error( adsp_parser, "no text allowed in line %u, column %u",
    //                 adsp_parser->dsc_pos.uinc_line, adsp_parser->dsc_pos.uinc_col );
    //    return FALSE;
    //}

    adsl_node = (struct dsd_xml_domnode*)m_get_next_storage( adsp_parser->adsc_nodes );
    if ( adsl_node == NULL ) {
        m_set_error( adsp_parser, "XMLparser-%05d- cannot get memory for domnode",
                     __LINE__ );
        return FALSE;
    }

    adsl_node->ienc_type    = ied_nt_text;
    adsl_node->ienc_charset = adsp_parser->dsc_doctype.ienc_charset;
    adsl_node->boc_closed   = TRUE;
    adsl_node->dsc_pos.uinc_line = adsp_parser->dsc_pos.uinc_line;
    adsl_node->dsc_pos.uinc_col  = adsp_parser->dsc_pos.uinc_col - (achp_end - achp_text);
    adsl_node->dsc_value.avc_ptr = (void*)achp_text;
    adsl_node->dsc_value.uinc_length = (size_t)(achp_end - achp_text);
    adsl_node->adsc_parent = adsp_parser->adsc_current;

    m_fill_unicodestring( &adsl_node->dsc_value, adsl_node->ienc_charset,
                          &adsl_node->dsc_us_val );

    if ( adsp_parser->adsc_current == NULL ) {
        adsp_parser->adsc_current   = adsl_node;
        adsp_parser->adsc_firstnode = adsl_node;
    } else

    if ( adsp_parser->adsc_current->adsc_child == NULL ) {
        adsp_parser->adsc_current->adsc_child = adsl_node;
    } else {
        adsl_child = adsp_parser->adsc_current->adsc_child;
        while ( adsl_child->adsc_next != NULL ) {
            adsl_child = adsl_child->adsc_next;
        }
        adsl_child->adsc_next = adsl_node;
    }
    return TRUE;
} /* end of m_save_text */


/**
 * private function m_find_node
 *  search xml string for a node
 *
 * @param[in]   dsd_xml_domparser   *adsp_parser    parser object
 * @param[in]   const char          **aachp_xml     xml data
 * @param[in]   const char          *achp_end       end of xml data
 * @param[out]  const char          **aachp_nstart  start of node
 * @param[out]  const char          **aachp_nend    end of node
 * @param[out]  dsd_xmlpos          *adsp_pos       start pos of node
 * @return      BOOL                                TRUE = continue
 *                                                  FALSE = otherwise
*/
PRIVATE inline BOOL m_find_node( struct dsd_xml_domparser *adsp_parser,
                                 const char **aachp_xml,    const char *achp_end,
                                 const char **aachp_nstart, const char **aachp_nend,
                                 struct dsd_xmlpos *adsp_pos )
{
    BOOL       bol_ret;
    const char *achl_text;

    /* search for '<' */
    achl_text = *aachp_xml;
    bol_ret = m_find_sign( adsp_parser, aachp_xml, achp_end, '<' );
    if ( bol_ret == FALSE ) {
        m_set_error( adsp_parser, "text found after last tag in line %u, column %u",
                     adsp_parser->dsc_pos.uinc_line, adsp_parser->dsc_pos.uinc_col );
        // just ignore this
        *aachp_nstart = NULL;
        *aachp_nend   = NULL;
        return TRUE;
    }
    if ( achl_text < *aachp_xml ) {
        /* we have found some text in front of the next tag */
        /* check for Byte Order Mark */
        bol_ret = m_is_bom( adsp_parser, achl_text, *aachp_xml );
        if ( bol_ret == TRUE ) {
            // just ignore this
            *aachp_nstart = NULL;
            *aachp_nend   = NULL;
            return TRUE;
        }
        bol_ret = m_save_text( adsp_parser, achl_text, *aachp_xml );
        if ( bol_ret == FALSE ) {
            return FALSE;
        }
    }
    adsp_pos->uinc_line = adsp_parser->dsc_pos.uinc_line;
    adsp_pos->uinc_col  = adsp_parser->dsc_pos.uinc_col;

    *aachp_nstart = *aachp_xml;
    (*aachp_xml)++;
    adsp_parser->dsc_pos.uinc_col++;

    /* search for '>' */
    bol_ret = m_find_sign( adsp_parser, aachp_xml, achp_end, '>' );
    if ( bol_ret == FALSE ) {
        m_set_error( adsp_parser, "node not ending in line %u, column %u",
                     adsp_parser->dsc_pos.uinc_line, adsp_parser->dsc_pos.uinc_col );
        return FALSE;
    }
    *aachp_nend = *aachp_xml;
    (*aachp_xml)++;
    adsp_parser->dsc_pos.uinc_col++;
    return TRUE;
} /* end of m_find_node */


/**
 * private function m_is_proc_instr
 *  check if given node is a processing instruction
 *
 * @param[in]   const char          *achp_node      ptr to node
 * @param[in]   const char          *achp_end       end of node
 * @return      BOOL
*/
PRIVATE inline BOOL m_is_proc_instr( const char *achp_node, const char *achp_end )
{
    return (    (achp_node + 1 < achp_end)
             && (*(achp_node + 1) == '?')
             && (achp_node < achp_end - 1)
             && (*(achp_end - 1) == '?')   )?TRUE:FALSE;
} /* end of m_is_proc_instr */


/**
 * private function m_read_version
 *
 * @param[in]   const void  *avp_data       pointer to data
 * @param[in]   size_t      uinp_length     length of data (in signs)
 * @param[in]   size_t      uinp_sign       size of one sign
 * @return      ienl_version                version
*/
PRIVATE enum ied_xml_version m_read_version( const void *avp_data,
                                             size_t uinp_length,
                                             size_t uinp_sign )
{
    enum ied_xml_version ienl_version;      /* found version             */
    size_t               uinl_element;      /* element in known charsets */
    size_t               uinl_pos;          /* compare position          */
    const char           *achl_comp;        /* compare value             */

    ienl_version = ied_xver_unknown;
#ifdef WAS_BEFORE
    uinl_element = 0;
    while ( achrs_xml_versions[uinl_element] != NULL ) {
        if ( uinp_length == strlen(achrs_xml_versions[uinl_element]) ) {
            achl_comp = (const char*)avp_data;
            for ( uinl_pos = 0; uinl_pos < uinp_length; uinl_pos++ ) {
                if ( tolower(*achl_comp) != achrs_xml_versions[uinl_element][uinl_pos] ) {
                    break; /* end for */
                }
                achl_comp += uinp_sign;
            }
            if ( uinl_pos == uinp_length ) {
                ienl_version = (enum ied_xml_version)uinl_element;
                break; /* end while */
            }
        }
        uinl_element++;
    }
#endif

#define HELPER_XML_VERS_10 "1.0"

    if ( uinp_length == strlen( HELPER_XML_VERS_10 ) ) {
        achl_comp = (const char*)avp_data;
        for ( uinl_pos = 0; uinl_pos < uinp_length; uinl_pos++ ) {
            if ( tolower(*achl_comp) != HELPER_XML_VERS_10[uinl_pos] ) {
                break; /* end for */
            }
            achl_comp += uinp_sign;
        }
        if ( uinl_pos == uinp_length ) {
            ienl_version = ied_xver_10;
        }
    }

    return ienl_version;
} /* end of m_read_version */


/**
 * private function m_read_encoding
 *
 * @param[in]   const void  *avp_data       pointer to data
 * @param[in]   size_t      uinp_length     length of data (in signs)
 * @param[in]   size_t      uinp_sign       size of one sign
 * @return      ied_charset                 encoding
*/
PRIVATE enum ied_charset m_read_encoding( const void *avp_data,
                                          size_t uinp_length,
                                          size_t uinp_sign )
{
    enum ied_charset ienl_chs;              /* found charset             */
    size_t           uinl_element;          /* element in known charsets */
    size_t           uinl_pos;              /* compare position          */
    const char       *achl_comp;            /* compare value             */

    ienl_chs     = ied_chs_invalid;
#ifdef WAS_BEFORE
    uinl_element = 0;
    while ( achrs_xml_encodings[uinl_element] != NULL ) {
        if ( uinp_length == strlen(achrs_xml_encodings[uinl_element]) ) {
            achl_comp = (const char*)avp_data;
            for ( uinl_pos = 0; uinl_pos < uinp_length; uinl_pos++ ) {
                if ( tolower(*achl_comp) != achrs_xml_encodings[uinl_element][uinl_pos] ) {
                    break; /* end for */
                }
                achl_comp += uinp_sign;
            }
            if ( uinl_pos == uinp_length ) {
                ienl_chs = (enum ied_charset)uinl_element;
                break; /* end while */
            }
        }
        uinl_element++;
    }
#endif

    uinl_element = sizeof(dsrs_xml_charset_tab) / sizeof(dsrs_xml_charset_tab[0]);
    do {
      uinl_element--;                       /* decrement index         */
      if ( uinp_length == strlen( dsrs_xml_charset_tab[uinl_element].achc_name ) ) {
          achl_comp = (const char*)avp_data;
          for ( uinl_pos = 0; uinl_pos < uinp_length; uinl_pos++ ) {
              if ( tolower(*achl_comp) != dsrs_xml_charset_tab[uinl_element].achc_name[uinl_pos] ) {
                  break; /* end for */
              }
              achl_comp += uinp_sign;
          }
          if ( uinl_pos == uinp_length ) {
              ienl_chs = dsrs_xml_charset_tab[uinl_element].iec_chs;
              break; /* end while */
          }
      }
    } while (uinl_element > 0);

    return ienl_chs;
} /* end of m_read_encoding */


/**
 * private function m_handle_proc_instr
 *  parse processing instruction and save it
 *
 * @param[in]   dsd_xml_domparser   *adsp_parser    parser object
 * @param[in]   const char          *achp_node      ptr to node
 * @param[in]   const char          *achp_end       end of node
 * @return      BOOL                                TRUE = continue
 *                                                  FALSE = otherwise
*/
PRIVATE inline BOOL m_handle_proc_instr( struct dsd_xml_domparser *adsp_parser,
                                         const char *achp_node, const char *achp_end )
{
    size_t                   uinl_sign;     /* guessed size of one sign  */
    struct dsd_xml_attribute dsl_attr;      /* attribute                 */
    size_t                   uinl_pos;      /* compare position          */
    const char               *achl_name;    /* name of attribute         */
    enum ied_xml_version     ienl_version;  /* xml version               */
    enum ied_charset         ienl_charset;  /* character set             */

    /* go over '<' and '?' sign  */
    uinl_sign = 1;
    achp_node++;
    while (    achp_node < achp_end
            && *achp_node == 0      ) {
        uinl_sign++;;
        achp_node++;
    }
    achp_node += uinl_sign;

    if (    achp_node + 3 * uinl_sign > achp_end
         || tolower(*(achp_node                )) != 'x'
         || tolower(*(achp_node +     uinl_sign)) != 'm'
         || tolower(*(achp_node + 2 * uinl_sign)) != 'l'
         || adsp_parser->dsc_doctype.ienc_version != ied_xver_unknown ) {
        return TRUE; /* ignore this node */
    }
    achp_node += 3 * uinl_sign;

    while ( achp_node < achp_end ) {
        memset( &dsl_attr, 0, sizeof(struct dsd_xml_attribute) );
        m_read_node_attr( &dsl_attr, &achp_node, achp_end );

        if (    dsl_attr.dsc_name.uinc_length  > 0
             && dsl_attr.dsc_value.uinc_length > 0 ) {
            achl_name = (const char*)dsl_attr.dsc_name.avc_ptr;

            /*
                read xml version:
            */
            if (    *achl_name == chrs_xml_version[0]
                 && dsl_attr.dsc_name.uinc_length/uinl_sign == sizeof(chrs_xml_version) ) {
                achl_name += uinl_sign;
                for ( uinl_pos = 1; uinl_pos < sizeof(chrs_xml_version); uinl_pos++ ) {
                    if ( *achl_name != chrs_xml_version[uinl_pos] ) {
                        break;
                    }
                    achl_name += uinl_sign;
                }
                if ( achl_name == (   (const char*)dsl_attr.dsc_name.avc_ptr
                                    + dsl_attr.dsc_name.uinc_length          ) ) {
                    ienl_version = m_read_version( dsl_attr.dsc_value.avc_ptr,
                                                   dsl_attr.dsc_value.uinc_length/uinl_sign,
                                                   uinl_sign );
                    if ( ienl_version == ied_xver_unknown ) {
                        m_set_error( adsp_parser, "invalid xml version found in line %u, column %u",
                                     adsp_parser->dsc_pos.uinc_line,
                                     adsp_parser->dsc_pos.uinc_col );
                        return FALSE;
                    }
                    adsp_parser->dsc_doctype.ienc_version = ienl_version;
                }
            }

            /*
                read xml encoding:
            */
            else if (    *achl_name == chrs_xml_encoding[0]
                      && dsl_attr.dsc_name.uinc_length/uinl_sign == sizeof(chrs_xml_encoding) ) {
                achl_name += uinl_sign;
                for ( uinl_pos = 1; uinl_pos < sizeof(chrs_xml_encoding); uinl_pos++ ) {
                    if ( *achl_name != chrs_xml_encoding[uinl_pos] ) {
                        break;
                    }
                    achl_name += uinl_sign;
                }
                if ( achl_name == (   (const char*)dsl_attr.dsc_name.avc_ptr
                                    + dsl_attr.dsc_name.uinc_length          ) ) {
                    ienl_charset = m_read_encoding( dsl_attr.dsc_value.avc_ptr,
                                                    dsl_attr.dsc_value.uinc_length/uinl_sign,
                                                    uinl_sign );
                    if ( ienl_charset == ied_chs_invalid ) {
                        m_set_error( adsp_parser, "invalid character encoding found in line %u, column %u",
                                     adsp_parser->dsc_pos.uinc_line,
                                     adsp_parser->dsc_pos.uinc_col );
                        return FALSE;
                    }
                    adsp_parser->dsc_doctype.ienc_charset = ienl_charset;
                }
            }
        }
    }
    return TRUE;
} /* end of m_handle_proc_instr */


/**
 * private function m_save_node
 *  save parsed node in tree
 *
 * @param[in]   dsd_xml_domparser   *adsp_parser    parser object
 * @param[in]   dsd_xml_domnode     *adsp_node      node
 * @return      BOOL                                TRUE = continue
 *                                                  FALSE = otherwise
*/
PRIVATE inline BOOL m_save_node( struct dsd_xml_domparser *adsp_parser,
                                 struct dsd_xml_domnode   *adsp_node )
{
    struct dsd_xml_domnode *adsl_child;

    /* save xmlbytes as unicode structure */
    m_fill_unicodestring( &adsp_node->dsc_value, adsp_node->ienc_charset,
                          &adsp_node->dsc_us_val );

    if ( adsp_parser->adsc_current == NULL ) {
        adsp_parser->adsc_firstnode = adsp_node;
        adsp_parser->adsc_current   = adsp_node;
    } else if (    adsp_parser->adsc_firstnode->ienc_type  == ied_nt_node
                && adsp_parser->adsc_firstnode->boc_closed == TRUE
                && adsp_parser->adsc_current == adsp_parser->adsc_firstnode ) {
        m_set_error( adsp_parser, "found second main-node in line %u, column %u",
                     adsp_node->dsc_pos.uinc_line, adsp_node->dsc_pos.uinc_col );
        return FALSE;
    } else if ( adsp_parser->adsc_current->boc_closed == FALSE ) {
        if ( adsp_parser->adsc_current->adsc_child == NULL ) {
            adsp_node->adsc_parent = adsp_parser->adsc_current;
            adsp_parser->adsc_current->adsc_child = adsp_node;
        } else {
            adsl_child = adsp_parser->adsc_current->adsc_child;
            while ( adsl_child->adsc_next != NULL ) {
                adsl_child = adsl_child->adsc_next;
            }
            adsp_node->adsc_parent    = adsl_child->adsc_parent;
            adsp_node->adsc_prev      = adsl_child;
            adsl_child->adsc_next     = adsp_node;
        }
        if ( adsp_node->boc_closed == FALSE ) {
            adsp_parser->adsc_current = adsp_node;
        }
    } else {
        adsp_node->adsc_parent = adsp_parser->adsc_current->adsc_parent;
        adsp_node->adsc_prev   = adsp_parser->adsc_current;
        adsp_parser->adsc_current->adsc_next = adsp_node;
        adsp_parser->adsc_current = adsp_node;
    }
    return TRUE;
} /* end of m_save_node */


/**
 * private function m_is_comment
 *  check if given node is a comment
 *
 * @param[in]   const char          *achp_node      ptr to node
 * @param[in]   const char          *achp_end       end of node
 * @return      BOOL
*/
PRIVATE inline BOOL m_is_comment( const char *achp_node, const char *achp_end )
{
    return (    (achp_node + 4 < achp_end)
             && (*(achp_node + 1) == '!')
             && (*(achp_node + 2) == '-')
             && (*(achp_node + 3) == '-') )?TRUE:FALSE;
} /* end of m_is_comment */


/**
 * private function m_handle_comment
 *  handle xml comment
 *
 * @param[in]   dsd_xml_domparser   *adsp_parser    parser object
 * @param[in]   const char          **aachp_xml     ptr to xml data
 * @param[in]   const char          *achp_end       end of xml data
 * @param[in]   const char          *achp_cstart    ptr to start of comment
 * @param[in]   dsd_xmlpos          *adsp_pos       start pos of comment
 * @return      BOOL                                TRUE = continue
 *                                                  FALSE = otherwise
*/
PRIVATE BOOL inline m_handle_comment( struct dsd_xml_domparser *adsp_parser,
                                      const char               **aachp_xml,
                                      const char               *achp_end,
                                      const char               *achp_cstart,
                                      struct dsd_xmlpos        *adsp_pos )
{
    BOOL                   bol_ret;         /* return for search         */
    const char             *achl_end;       /* end of comment            */
    struct dsd_xml_domnode *adsl_com;       /* comment node              */

    achl_end = achp_cstart;
    adsp_parser->dsc_pos.uinc_line = adsp_pos->uinc_line;
    adsp_parser->dsc_pos.uinc_col  = adsp_pos->uinc_col;
    do {
        bol_ret = m_find_sign( adsp_parser, &achl_end, achp_end, '-' );
        if ( bol_ret == FALSE ) {
            m_set_error( adsp_parser, "cannot find end of comment in line %u, column %u",
                         adsp_pos->uinc_line, adsp_pos->uinc_col );
            return FALSE;
        }
        achl_end++;
        adsp_parser->dsc_pos.uinc_col++;
    } while (    achl_end + 1 < achp_end
              && (    *(achl_end    ) != '-'
                   || *(achl_end + 1) != '>' ) );
    if ( achl_end + 2 == achp_end ) {
        m_set_error( adsp_parser, "cannot find end of comment in line %u, column %u",
                     adsp_pos->uinc_line, adsp_pos->uinc_col );
        return FALSE;
    }

    *aachp_xml = achl_end + 2;
    adsp_parser->dsc_pos.uinc_col += 2;

    adsl_com = (struct dsd_xml_domnode*)m_get_next_storage( adsp_parser->adsc_nodes );
    if ( adsl_com == NULL ) {
        m_set_error( adsp_parser, "XMLparser-%05d- cannot get memory for domnode",
                     __LINE__ );
        return FALSE;
    }

    adsl_com->ienc_charset = adsp_parser->dsc_doctype.ienc_charset;
    adsl_com->boc_closed   = TRUE;
    adsl_com->ienc_type    = ied_nt_comment;
    adsl_com->dsc_value.avc_ptr = (void*)(achp_cstart + 4);
    adsl_com->dsc_value.uinc_length = (size_t)( achl_end - 1 - (achp_cstart + 4));
    adsl_com->dsc_pos.uinc_line = adsp_pos->uinc_line;
    adsl_com->dsc_pos.uinc_col  = adsp_pos->uinc_col;

    return m_save_node( adsp_parser, adsl_com );
} /* end of m_handle_comment */


/**
 * private function m_is_cdata
 *  check if given node is character data (<![CDATA[...]]>)
 *
 * @param[in]   const char          *achp_node      ptr to node
 * @param[in]   const char          *achp_end       end of node
 * @return      BOOL
*/
PRIVATE inline BOOL m_is_cdata( const char *achp_node, const char *achp_end )
{
    return (    (achp_node + 9 < achp_end)
             && (*(achp_node + 1) == '!')
             && (*(achp_node + 2) == '[')
             && (*(achp_node + 3) == 'C')
             && (*(achp_node + 4) == 'D')
             && (*(achp_node + 5) == 'A')
             && (*(achp_node + 6) == 'T')
             && (*(achp_node + 7) == 'A')
             && (*(achp_node + 8) == '[') )?TRUE:FALSE;
} /* end of m_is_cdata */


/**
 * private function m_handle_cdata
 *  handle xml character data (<![CDATA[...]]>)
 *
 * @param[in]   dsd_xml_domparser   *adsp_parser    parser object
 * @param[in]   const char          **aachp_xml     ptr to xml data
 * @param[in]   const char          *achp_end       end of xml data
 * @param[in]   const char          *achp_cstart    ptr to start of comment
 * @param[in]   dsd_xmlpos          *adsp_pos       start pos of comment
 * @return      BOOL                                TRUE = continue
 *                                                  FALSE = otherwise
*/
PRIVATE BOOL inline m_handle_cdata( struct dsd_xml_domparser *adsp_parser,
                                    const char               **aachp_xml,
                                    const char               *achp_end,
                                    const char               *achp_cstart,
                                    struct dsd_xmlpos        *adsp_pos )
{
    BOOL                   bol_ret;         /* return for search         */
    const char             *achl_end;       /* end of cdata              */
    struct dsd_xml_domnode *adsl_cdata;     /* cdata   node              */

    achl_end = achp_cstart;
    adsp_parser->dsc_pos.uinc_line = adsp_pos->uinc_line;
    adsp_parser->dsc_pos.uinc_col  = adsp_pos->uinc_col;
    do {
        bol_ret = m_find_sign( adsp_parser, &achl_end, achp_end, ']' );
        if ( bol_ret == FALSE ) {
            m_set_error( adsp_parser, "cannot find end of cdata in line %u, column %u",
                         adsp_pos->uinc_line, adsp_pos->uinc_col );
            return FALSE;
        }
        achl_end++;
        adsp_parser->dsc_pos.uinc_col++;
    } while (    achl_end + 1 < achp_end
              && (    *(achl_end    ) != ']'
                   || *(achl_end + 1) != '>' ) );
    if ( achl_end + 2 == achp_end ) {
        m_set_error( adsp_parser, "cannot find end of cdata in line %u, column %u",
                     adsp_pos->uinc_line, adsp_pos->uinc_col );
        return FALSE;
    }

    *aachp_xml = achl_end + 2;
    adsp_parser->dsc_pos.uinc_col += 2;

    adsl_cdata = (struct dsd_xml_domnode*)m_get_next_storage( adsp_parser->adsc_nodes );
    if ( adsl_cdata == NULL ) {
        m_set_error( adsp_parser, "XMLparser-%05d- cannot get memory for domnode",
                     __LINE__ );
        return FALSE;
    }

    adsl_cdata->ienc_charset = adsp_parser->dsc_doctype.ienc_charset;
    adsl_cdata->boc_closed   = TRUE;
    adsl_cdata->ienc_type    = ied_nt_cdata;
    adsl_cdata->dsc_value.avc_ptr = (void*)(achp_cstart + 9);
    adsl_cdata->dsc_value.uinc_length = (size_t)( achl_end - 1 - (achp_cstart + 9));
    adsl_cdata->dsc_pos.uinc_line = adsp_pos->uinc_line;
    adsl_cdata->dsc_pos.uinc_col  = adsp_pos->uinc_col;

    return m_save_node( adsp_parser, adsl_cdata );
} /* end of m_handle_cdata */


/**
 * private function m_is_closing_node
 *  check if given node is a closing node
 *
 * @param[in]   const char          *achp_node      ptr to node
 * @param[in]   const char          *achp_end       end of node
 * @return      BOOL
*/
PRIVATE inline BOOL m_is_closing_node( const char *achp_node, const char *achp_end )
{
    return ((achp_node + 1 < achp_end) && (*(achp_node + 1) == '/'))?TRUE:FALSE;
} /* end of m_is_closing_node */


/**
 * private function m_close_node
 *  search matching open node for given closed one and close it
 *
 * @param[in]   dsd_xml_domparser   *adsp_parser    parser object
 * @param[in]   const char          *achp_node      ptr to node
 * @param[in]   const char          *achp_end       end of node
 * @return      BOOL                                TRUE = continue
 *                                                  FALSE = otherwise
*/
PRIVATE inline BOOL m_close_node( struct dsd_xml_domparser *adsp_parser,
                                  const char *achp_node, const char *achp_end )
{
    /* search name of node */
    while ( achp_node < achp_end ) {
        switch ( *achp_node ) {
            case '<':
            case '/':
                achp_node++;
                continue;
            default:
                break;
        }
        break;
    }

    /* last current node must be closed */
    if (    adsp_parser->adsc_current != NULL
         && adsp_parser->adsc_current->dsc_value.uinc_length == (size_t)(achp_end - achp_node)
         && strncmp( (const char*)adsp_parser->adsc_current->dsc_value.avc_ptr,
                     achp_node, adsp_parser->adsc_current->dsc_value.uinc_length ) == 0 ) {
        adsp_parser->adsc_current->boc_closed = TRUE;
        while ( adsp_parser->adsc_current->adsc_parent != NULL ) {
            adsp_parser->adsc_current = adsp_parser->adsc_current->adsc_parent;
            if ( adsp_parser->adsc_current->boc_closed == FALSE ) {
                break;
            }
        }
        return TRUE;
    }
    m_set_error( adsp_parser, "close missing for node in line %u, column %u",
                 ((adsp_parser->adsc_current) ? adsp_parser->adsc_current->dsc_pos.uinc_line
                                              : adsp_parser->dsc_pos.uinc_line),
                 ((adsp_parser->adsc_current) ? adsp_parser->adsc_current->dsc_pos.uinc_col
                                              : adsp_parser->dsc_pos.uinc_col) );
    return FALSE;
} /* end of m_close_node */


/**
 * private function m_parse_data
 *
 * @param[in]   dsd_xml_domparser   *adsp_parser    parser object
 * @param[in]   const char          **aachp_xml     xml data
 * @param[in]   const char          *achp_end       end of xml data
 * @return      BOOL                                TRUE = continue
 *                                                  FALSE = otherwise
*/
PRIVATE BOOL m_parse_data( struct dsd_xml_domparser *adsp_parser,
                           const char **aachp_xml, const char *achp_end )
{
    BOOL                   bol_ret;             /* return for some funcs */
    const char             *achl_nstart;        /* start of node         */
    const char             *achl_nend;          /* end of node           */
    struct dsd_xml_domnode *adsl_node;          /* found node            */
    struct dsd_xmlpos      dsl_pos;             /* start position node   */

    bol_ret = m_find_node( adsp_parser, aachp_xml, achp_end,
                           &achl_nstart, &achl_nend, &dsl_pos );
    if ( bol_ret == FALSE ) {
        return FALSE;
    }
    if (    achl_nstart == NULL
         && achl_nend == NULL ) {
        return TRUE;
    }

    bol_ret = m_is_proc_instr( achl_nstart, achl_nend );
    if ( bol_ret == TRUE ) {
        return m_handle_proc_instr( adsp_parser, achl_nstart, achl_nend );
    }

    bol_ret = m_is_comment( achl_nstart, achl_nend );
    if ( bol_ret == TRUE ) {
        return m_handle_comment( adsp_parser, aachp_xml,
                                 achp_end, achl_nstart, &dsl_pos );
    }

    bol_ret = m_is_cdata( achl_nstart, achl_nend );
    if ( bol_ret == TRUE ) {
        return m_handle_cdata( adsp_parser, aachp_xml,
                               achp_end, achl_nstart, &dsl_pos );
    }

    bol_ret = m_is_closing_node( achl_nstart, achl_nend );
    if ( bol_ret == TRUE ) {
        return m_close_node( adsp_parser, achl_nstart, achl_nend );
    }

    adsl_node = m_parse_node( adsp_parser, achl_nstart,
                              achl_nend, &dsl_pos );
    if ( adsl_node == NULL ) {
        return FALSE;
    }

    return m_save_node( adsp_parser, adsl_node );
} /* end of m_parse_data */


/**
 * private function m_set_error
 *  set last error string
 *
 * @param[in]   dsd_xml_domparser   *adsp_parser    parser object
 * @param[in]   const char          *achp_format    format
 * @param[in]   ...
 * @return      nothing
*/
PRIVATE void m_set_error( struct dsd_xml_domparser *adsp_parser,
                          const char *achp_format, ... )
{
    va_list dsl_args;

    va_start( dsl_args, achp_format );
    vsnprintf( adsp_parser->chrc_error, sizeof(adsp_parser->chrc_error),
               achp_format, dsl_args );
    va_end( dsl_args );
} /* end of m_set_error */


/**
 * private function m_new_xml_storage
 *  create a new xml storage object
 *
 * @param[in]   size_t             uinp_sizeof      sizeof single element
 * @param[in]   size_t             uinp_elements    number of elements
 * @param[in]   dsd_xml_parser_cbs *adsp_cbs        callback methods
 * @return      dsd_xml_storage*                    pointer to storage
 *                                                  null in error cases
*/
PRIVATE struct dsd_xml_storage* m_new_xml_storage( size_t uinp_sizeof,
                                                   size_t uinp_elements,
                                                   struct dsd_xml_parser_cbs *adsp_cbs )
{
    struct dsd_xml_storage *adsl_stor;

    if (    uinp_sizeof          < 1
         || uinp_elements        < 1
         || adsp_cbs            == NULL
         || adsp_cbs->amc_alloc == NULL
         || adsp_cbs->amc_free  == NULL ) {
        return NULL;
    }

    adsl_stor = (struct dsd_xml_storage*) adsp_cbs->amc_alloc(
                                            adsp_cbs->avc_usrfld,
                                              sizeof(struct dsd_xml_storage)
                                            +   uinp_elements
                                              * DEF_XML_ALIGN(uinp_sizeof) );
    if ( adsl_stor != NULL ) {
        adsl_stor->uinc_size      = uinp_sizeof;
        adsl_stor->uinc_elements  = uinp_elements;
        adsl_stor->uinc_next_free = 0;
        adsl_stor->avc_storage    = (void*)(adsl_stor + 1);
        adsl_stor->adsc_next      = NULL;
        adsl_stor->adsc_cbs       = adsp_cbs;
        memset( adsl_stor->avc_storage, 0,
                uinp_elements * DEF_XML_ALIGN(uinp_sizeof) );
    }
    return adsl_stor;
} /* end of m_new_xml_storage */


/**
 * private function m_delete_storage
 *  delete a xml storage object
 *
 * @param[in]   dsd_xml_storage *adsp_stor      storage object
 * @return                                      nothing
*/
PRIVATE void m_delete_storage( struct dsd_xml_storage *adsp_stor )
{
    struct dsd_xml_storage    *adsl_next;
    struct dsd_xml_parser_cbs *adsl_cbs;

    if ( adsp_stor == NULL ) {
        return;
    }

    adsl_cbs = adsp_stor->adsc_cbs;
    while ( adsp_stor != NULL ) {
        adsl_next = adsp_stor->adsc_next;
        adsl_cbs->amc_free( adsl_cbs->avc_usrfld, adsp_stor );
        adsp_stor = adsl_next;
    }
} /* end of m_delete_storage */


/**
 * private function m_get_next_storage
 *  get next free element from storage
 *
 * @param[in]   dsd_xml_storage *adsp_stor  storage object
 * @return  void*                           ptr to next element
 *                                          NULL in error cases
*/
PRIVATE void* m_get_next_storage( struct dsd_xml_storage *adsp_stor )
{
    void *avl_next;                         /* next storage element      */

    /* get last storage from chain */
    while ( adsp_stor->adsc_next != NULL ) {
        adsp_stor = adsp_stor->adsc_next;
    }

    if ( adsp_stor->uinc_next_free == adsp_stor->uinc_elements ) {
        adsp_stor->adsc_next = m_new_xml_storage( adsp_stor->uinc_size,
                                                  adsp_stor->uinc_elements,
                                                  adsp_stor->adsc_cbs );
        if ( adsp_stor->adsc_next == NULL ) {
            return NULL;
        }
        adsp_stor = adsp_stor->adsc_next;
    }

    avl_next = (void*)(  (char*)adsp_stor->avc_storage
                        + adsp_stor->uinc_next_free
                           * DEF_XML_ALIGN(adsp_stor->uinc_size) );
    adsp_stor->uinc_next_free++;

    return avl_next;
} /* end of m_get_next_storage */


