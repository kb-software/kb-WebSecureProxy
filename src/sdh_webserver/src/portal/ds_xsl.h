#ifndef DS_XSL_H
#define DS_XSL_H
/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_xsl                                                                |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|   Michael Jakobs                                                        |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| =====                                                                   |*/
/*|   November 2008                                                         |*/
/*|                                                                         |*/
/*| COPYRIGHT:                                                              |*/
/*| ==========                                                              |*/
/*|  HOB GmbH & Co. KG, Germany                                             |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| include global headers                                                  |*/
/*+-------------------------------------------------------------------------+*/
#include <ds_hstring.h>
#include "ds_parse_xsl.h"
#include <ds_wsp_helper.h>

/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| type defines:                                                           |*/
/*+-------------------------------------------------------------------------+*/
enum ied_xsl_tags {
    // supported xsl tags:
    ied_value_of,       //!< xsl:value-of tag
    ied_for_each,       //!< xsl:for-each tag
    ied_if,             //!< xsl:if tag
    ied_attribute,      //!< xsl:attribute tag
    ied_template,       //!< xsl:template tag
    ied_call_template,  //!< xsl:call-template tag
    ied_variable,       //!< xsl:variable tag
    ied_include,        //!< xsl:include tag
    ied_comment,        //!< xsl:comment tag

    // undefined tag:
    ied_unknowntag      //!< no known namespace tag
};

enum ied_xsl_compare {
    ied_xsl_cmp_not_set  = -1,  //!< no compare or unknown one
    ied_xsl_cmp_greater      ,  //!< greater
    ied_xsl_cmp_gr_equal     ,  //!< greater equal
    ied_xsl_cmp_lower        ,  //!< lower
    ied_xsl_cmp_lw_equal     ,  //!< lower equal
    ied_xsl_cmp_equal        ,  //!< equal
    ied_xsl_cmp_not_equal       //!< not equal
};

enum ied_xsl_value_encoding {
    ied_xsl_enc_html,           // utf8 with special chars html-encoded
    ied_xsl_enc_uri,            // ascii, with special chars encoded like uri-component
    ied_xsl_enc_utf8,           // plain utf8
    ied_xsl_enc_js_string,      // utf8 with " and control chars encoded with '\'
    ied_xsl_enc_b64,            // Base 64 encoded
    ied_xsl_enc_unknown
};

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
class  ds_session;                          // forward definition
struct dsd_xml_tag;                         // forward definition
class  ds_wsp_admin;                        // forward definition
template <class T> class ds_hvector;        // forward definition
template <class T> class ds_hstack_btype;  // forward definition
class  ds_authenticate;                     // forward definition
typedef struct dsd_message dsd_msg_t;       // forward definition
class  dsd_variable;                        // forward definition
class  ds_wsp_admin;                        // forward definition
struct dsd_q_user_overview;                 // forward definition

enum ied_xsl_iterator_mode {
    ied_xsl_iterator_mode_random,
    ied_xsl_iterator_mode_fwd
};

struct dsd_xsl_iterator {
    //int imc_count;
    //int imc_cur;
    //void* avoc_itr1;
    //void* avoc_itr2;
    void* avoc_user;
    ied_xsl_iterator_mode iec_mode;
    union {
        struct dsd_forward_iterator dsc_fwd;
        struct dsd_random_access_iterator dsc_rac;
    };
};

/*! \brief xsl class
 *
 * @ingroup landingpage
 *
 * deals with xsl syntax which assembles the landing (portal) pages
 */
class ds_xsl
{
public:
    // constructor/destructor:
    ds_xsl();
    ~ds_xsl();

    // functions:
    void m_init    ( ds_session* ads_session_in );
    bool m_get_data( ds_hstring* ads_out, const char* ach_file, int in_len_file, dsd_msg_t* adsl_msg = NULL );
    void m_set_ersb( bool bo_show_back );

private:
    // variables:
    ds_session*            ads_session;         // webserver session class
    ds_wsp_helper*         ads_wsp_helper;      // wsp helper class
    ds_parse_xsl           dsc_parser;          // xsl parser class
    ds_hvector_btype<ds_parse_xsl*>  dsc_included_parsers; //parsers for included files
	dsd_hl_aux_diskfile_1  ds_file;             // wsp diskfile structure
	char*                  ach_cache;           // pointer to cache
    int                    in_cache_len;        // length of cache
#if 1
	struct dsd_hl_aux_c_cma_1 dsc_cma;
#else
    void*                  av_cma_handle;       // our cma handle
#endif
	ds_wsp_admin           dsc_admin;           // wsp admin class
    ds_authenticate        dsc_auth;            // authenticate class
    dsd_msg_t*             adsc_msg;            // message resource
    int                    inc_rec_call;        // count number of recursiv calls
    bool                   boc_show_back;       // show back link
#ifdef _DEBUG
    int                    inc_rec_peak;        // peak of recursiv calls
#endif
    ds_hvector_btype<dsd_xml_tag*>  dsc_templates;
    int                    in_replaced_lang;    // show current language as first lang

    // callback routines:
    void m_cb_get_data ( const char* ach_value, int in_len_val, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element );
    int  m_cb_no_childs( const char* ach_value, int in_len_val, ds_hstack_btype<dsd_xsl_iterator>* ads_element, dsd_xsl_iterator& rdsp_iter_out, int& riep_type );
    bool m_cb_iterate_next(int inp_type, dsd_xsl_iterator* adsp_itr);
    bool m_cb_is_true  ( const char* ach_value, int in_len_val, ds_hstack_btype<dsd_xsl_iterator>* ads_element, dsd_variable* ads_variable );

    // group get data routines:
    inline void m_cb_get_usr_data       ( int in_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element );
    inline void m_cb_get_rdvpn_data     ( int in_type, ds_hstring* ads_out );
    inline void m_cb_get_login_data     ( int in_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element );
    inline void m_cb_get_logout_data    ( int in_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element );
    inline void m_cb_get_ppptnl_data    ( int in_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element );
    inline void m_cb_get_queryparam_data( int in_type, ds_hstring* ads_out );
    // wspadmin get data routines:
    inline void m_cb_get_wspadmin_data             ( ds_hvector_btype<int>* ads_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element );
    inline void m_cb_get_wspadmin_query_data       ( ds_hvector_btype<int>* ads_type, ds_hstring* ads_out );
    inline void m_cb_get_wspadmin_cluster_data     ( ds_hvector_btype<int>* ads_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element );
    inline void m_cb_get_wspadmin_session_data     ( ds_hvector_btype<int>* ads_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element );
    inline void m_cb_get_wspadmin_listen_data      ( ds_hvector_btype<int>* ads_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element );
    inline void m_cb_get_wspadmin_listen_ineta_data( ds_hvector_btype<int>* ads_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element );
    inline void m_cb_get_wspadmin_perf_data        ( ds_hvector_btype<int>* ads_type, ds_hstring* ads_out );
    inline void m_cb_get_wspadmin_log_data         ( ds_hvector_btype<int>* ads_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element );
    inline void m_cb_get_wspadmin_user_data        ( ds_hvector_btype<int>* ads_type, ds_hstring* ads_out, ds_hstack_btype<dsd_xsl_iterator>* ads_element );
    inline void m_cb_print_wspadmin_rcode          ( ds_hstring* ads_out );
	inline void m_cb_get_wspadmin_trace_data	   ( ds_hvector_btype<int>* adsp_type, ds_hstring* adsp_out, ds_hstack_btype<dsd_xsl_iterator>* adsp_element);
	inline bool m_cb_get_wspadmin_trace_booldata   ( ds_hvector_btype<int>*	adsp_type, ds_hstack_btype<dsd_xsl_iterator>* adsp_element);

    // print functions:
    inline void m_cb_print_bool ( ds_hstring* ads_out, bool bo_value );
    inline void m_cb_print_ineta( ds_hstring* ads_out, struct dsd_aux_query_client ds_client );
    inline void m_cb_print_bytes( ds_hstring* ads_out, HL_LONGLONG il_bytes );

    // xsl value functions:
    bool            m_is_not     ( const char** aach_value, int* ain_len_val );
    ied_xsl_compare m_is_compare ( const char*   ach_value, int* ain_len_val, int* ain_cmp_to, ds_hstring* adsp_comp );
    int             m_compare    ( ied_xsl_compare ienp_comp, const char* achp_comp, int inp_len_comp, int inp_comp_to, ds_hstring* adsp_comp );
    void            m_get_type   ( ds_hvector_btype<int>* ads_type, const char* ach_value, int in_len_val );
    void            m_split_value( const char* ach_value, int in_len_value, int* ain_pos );
    inline void     m_pass_ws    ( const char* ach_data, int in_len, int* ain_pos );
    ied_xsl_value_encoding m_get_encoding(const char* ach_value, int* ain_len_val);

    // output generator:
    void         m_gen_output( ds_hstring* ads_out );
    void         m_write_tag( dsd_xml_tag* ads_in, ds_hstring* ads_xml, ds_hstack_btype<dsd_xsl_iterator>* ads_element, dsd_variable* ads_variable );
    void         m_search_templates( dsd_xml_tag* ads_in );
    ied_xsl_tags m_is_ns_tag( dsd_xml_tag* ads_in );
    void         m_include_template_file( const char* ach_href, int in_href_len );

    // file functions:
    bool m_is_file_modified( const char* ach_file, int in_len_file );
    bool m_get_file        ( char** aach_data, int* ain_len );
    bool m_release_file    ();

    // cache functions:
    bool m_get_cache   ( const char* ach_name, int in_len );
    bool m_update_cache( const char* ach_name, int in_len );
    bool m_close_cache ();
    void m_get_cache_name( const char* ach_file, int in_len_file, ds_hstring* ads_name );

    // other helper functions:
    bool m_copy_to ( char* ach_target, int in_tar_len, int* ain_offset, char* ach_data, int in_dat_len );
    bool m_get_from( char* ach_memory, int in_mem_len, int* ain_offset, char** aach_data, int in_dat_len );
    void m_fill_user_query( struct dsd_q_user_overview* adsp_query );
    struct dsd_pppt* m_get_tunnel_by_id();
    void             m_compose_socks_mode( ds_hstring* adsp_out, const char *achp_server, int inp_length );
	void m_default_domain(ds_hstack_btype<dsd_xsl_iterator>* ads_element, int *in_len_data);
};
#endif //DS_XSL_H
