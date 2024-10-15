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

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/

struct dsd_xml_parser_cbs {
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
};


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

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

extern PTYPE void * m_new_xml_parser( struct dsd_xml_parser_cbs *adsp_cbs );
extern PTYPE void m_delete_xml_parser( void **aavp_parser );
extern PTYPE void* m_parse_xml( void *avp_parser,
                                const char *achp_xml, size_t uinp_length );
extern PTYPE void * m_get_nextsibling( void *avp_node );
extern PTYPE void * m_get_prevsibling( void *avp_node );
extern PTYPE void * m_get_firstchild( void *avp_node );
extern PTYPE void * m_get_parentnode( void *avp_node );
extern PTYPE enum ied_nodetype m_get_nodetype( void *avp_node );
extern PTYPE void m_get_node_pos( void *avp_node,
                                  size_t *auinp_line, size_t *auinp_column );
extern PTYPE size_t m_get_node_line( void *avp_node );
extern PTYPE size_t m_get_node_column( void *avp_node );
extern PTYPE struct dsd_unicode_string * m_get_node_value( void *avp_node );
extern PTYPE void * m_get_attribute( void *avp_node );
extern PTYPE void * m_get_next_attr( void *avp_attr );
extern PTYPE struct dsd_unicode_string * m_get_attr_name( void *avp_attr );
extern PTYPE struct dsd_unicode_string * m_get_attr_value( void *avp_attr );
extern PTYPE char * m_get_lasterror( void *avp_parser );

