#ifndef _DS_CK_MGMT_H
#define _DS_CK_MGMT_H
/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| PROGRAM:                                                            |*/
/*| =======                                                             |*/
/*|  ds_ck_mgmt - class to handle http cookies centralized in wsg       |*/
/*|                                                                     |*/
/*| AUTHOR:                                                             |*/
/*| ======                                                              |*/
/*|  Michael Jakobs, Okt. 2009                                          |*/
/*|                                                                     |*/
/*| VERSION:                                                            |*/
/*| =======                                                             |*/
/*|  0.1                                                                |*/
/*|                                                                     |*/
/*| COPYRIGHT:                                                          |*/
/*| =========                                                           |*/
/*|  HOB GmbH Germany                                                   |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
#ifndef DEF_MAX_LEN_CMA_NAME        // wsp/include/hob-wspsu1.h
    #define D_MAXCMA_NAME 128
#else
    #define D_MAXCMA_NAME DEF_MAX_LEN_CMA_NAME
#endif

#define SM_USE_NEW_COOKIE_MANAGEMENT	1

#include <hob-avl03.h>

/*+---------------------------------------------------------------------+*/
/*| forward defintions:                                                 |*/
/*+---------------------------------------------------------------------+*/
class ds_wsp_helper;
template <class T> class ds_hvector;
template <class T> class ds_hvector_btype;
class ds_hstring;
class ds_cookie;
struct dsd_capacity;
struct dsd_ck_stor;
struct dsd_ck_mgmt;
struct dsd_ck_hash;

/*! \brief structure to access the cma
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_ck_cma {
    char            chrc_name[D_MAXCMA_NAME];   //!< name of cma
	 int             inc_len_name;

	struct dsd_hl_aux_c_cma_1 dsc_cma;
	char*           achc_start;
	char*           achc_end;
};

/*! \brief stores some cached results
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_ck_cache {
    ds_hstring            dsc_domain;      //!< cached result for domain
    ds_hstring            dsc_path;        //!< cached result for path
    ds_hvector<ds_cookie> dsc_cookies;     //!< cached get cookies
};

struct dsd_avl_cookie_info {
	dsd_const_string dsc_domain;
	dsd_const_string dsc_path;
	dsd_const_string dsc_name;
	hl_time_t   ill_expires;               //!< -1 = delete at logout
    bool        boc_secure;                //!< true = cookie only for secure connections
	bool        boc_http_only;             //!< true = cookie only for HTTP (not Javascript)
	bool        boc_domain;                //!< true = cookie is a domain cookie
	dsd_const_string dsc_data;
};

struct dsd_avl_cookie {
	struct dsd_htree1_avl_entry dsc_avl_entry;
	dsd_const_string dsc_name;
	hl_time_t   ill_expires;               //!< -1 = delete at logout
    bool        boc_secure;                //!< true = cookie only for secure connections
	bool        boc_http_only;             //!< true = cookie only for HTTP (not Javascript)
	bool        boc_domain;                //!< true = cookie is a domain cookie
	dsd_const_string dsc_data;
};

struct dsd_avl_path {
	struct dsd_htree1_avl_entry dsc_avl_entry;
	dsd_const_string dsc_path;
	unsigned int inc_num_cookies;
	struct dsd_htree1_avl_cntl dsc_avl_cookies;
};

struct dsd_avl_domain {
	struct dsd_htree1_avl_entry dsc_avl_entry;
	dsd_const_string dsc_domain;
	unsigned int inc_num_paths;
	struct dsd_htree1_avl_cntl dsc_avl_paths;
};

struct dsd_avl_domains {
	unsigned int inc_num_domains;
	struct dsd_htree1_avl_cntl dsc_avl_domains;
	int inc_serialized_size;
	bool boc_changed;
};

/*+---------------------------------------------------------------------+*/
/*| class defintion:                                                    |*/
/*+---------------------------------------------------------------------+*/
/*! \brief Class to handle http cookies centralized in wsg
 *
 * \ingroup authlib
 *
 * 1.) Why centralized cookie handling?
 * ====================================
 *  If we are sending all cookies to the browser, we must change the 
 *  domain (and path) that it is fitting to our url "wsp.hob.de". So there
 *  might be cookies, which are send to wrong servers:
 *
 *  Example 1:
 *  ----------
 *      Set-Cookie: Cookie1="test"; domain="www.server.de"; path="/path"
 *
 *      If this cookie is set from a server while surfing with wsg, and we
 *      want to send all cookies to browser, we will change the cookie to
 *      domain="wsp.hob.de"; path="http://www.server.de/path".
 *      Everything fine.
 *
 *  Example 2:
 *  ----------
 *      Set-Cookie: Cookie2="test"; domain=".server.de"; path="/path"
 *
 *      If this cookie is set from a server while surfing with wsg, and we
 *      want to send all cookies to browser, we will change the cookie to
 *      domain="wsp.hob.de"; path="/".
 *      So the cookie will be send to ALL servers which are visited with wsg.
 *  
 *  So the concept off sending all cookies to the browser opens a big
 *  security hole and might confuse servers, which must handle unknown
 *  cookies.
 *
 *
 * 2.) Implementation of centralized cookie handling:
 * ==================================================
 *  The base idea is, that we will create some memory in cma for each user.
 *  This memory will hold his cookies.
 *
 *  The main problem is, how could we manage to find the saved cookies fast
 *  for a requested url.
 *
 */
class ds_ck_mgmt {
public:
    // constructor:
    ds_ck_mgmt();
	~ds_ck_mgmt();

    // init functions:
    void m_init( ds_wsp_helper* ads_wsp_helper, bool bo_trace );

    // set cookies:
    bool m_set_cookie       ( const dsd_const_string& rdsp_cookie,
                              const dsd_const_string& rdsp_domain,
                              const dsd_const_string& rdsp_path,
                              const dsd_const_string& ach_cmabase );
    bool m_set_script_cookie( const dsd_const_string& rdsp_cookie,
                              const dsd_const_string& rdsp_domain,
                              const dsd_const_string& rdsp_path,
                              const dsd_const_string& ach_cmabase );

    // get cookies:
    const ds_hvector<ds_cookie>* m_get_cookies(
        const dsd_const_string& rdsp_domain, const dsd_const_string& rdsp_path,
        const dsd_const_string& ach_cmabase, bool bop_https );

    // remove script cookies:
    void m_rm_script_cookies(ds_hvector<ds_hstring>& rdsp_out);

    // export/delete and import/create functions:
    bool m_export_cookies( ds_hstring* ads_out, const dsd_const_string& ach_cmabase );
    bool m_import_cookies( const char* ach_xml, int in_len_xml, const dsd_const_string& ach_cmabase );

    // overview functions:
    int       m_count_cur_cookies ( const dsd_const_string& ach_cmabase, struct dsd_forward_iterator* adsp_iterator );
    bool      m_cur_domain_changed( struct dsd_forward_iterator* adsp_iterator );
	bool      m_cookies_next(struct dsd_forward_iterator* adsp_iterator);
    const ds_cookie& m_get_cur_cookie ( struct dsd_forward_iterator* adsp_iterator );
	bool	  m_delete_cookie( const dsd_const_string& ach_cmabase,
								 const dsd_const_string& ach_domain,
								 const dsd_const_string& ach_path,
								 const dsd_const_string& ach_name);
    bool      m_delete_cookie     ( int in_stor_pos, const dsd_const_string& ach_cmabase );
    bool      m_delete_cookies    ( const dsd_const_string& ach_cmabase );
    static bool        m_is_ineta          ( const char* ach_domain, int in_len_domain );
    
private:
    // variables:
    ds_wsp_helper*          adsc_wsp_helper;    // wsp callback class
    dsd_ck_cache            dsc_cache;          // get cookies cache
    ds_hvector<ds_hstring>  dsc_sc_cookies;     // script cookies -> to be removed
    ds_hvector<ds_cookie>   dsc_cur_cookies;    // current user cookies (cached result)
    ds_hvector_btype<int>   dsc_to_delete;      // save positions to be deleted
    bool                    boc_trace;          // trace cookies
    ds_hstring              ds_trace_path;      // trace path

	// cma variables:
    dsd_ck_cma              dsc_hash_cma;       // struct for hash cma

	struct dsd_avl_domains  dsc_avl_domains;

    // functions:
    inline bool m_enter_lock( bool bo_write );
    inline bool m_leave_lock();
    inline void m_clear_cache();
    bool m_save_cookie_begin();
	 bool m_save_cookie   ( ds_cookie* ads_cookie );
    bool m_save_cookie_end();
    
    // trace functions:
    void       m_create_trace     ();
    void       m_trace_cookie     ( ds_cookie* ads_cookie );
    
    void       m_get_single_cookie       ( const char* ach_cookie, int in_len_cookie, int in_pos,   int* ain_single_len );
    void       m_get_single_xml_cookie   ( const char* ach_xml,    int in_len_xml,    int* ain_pos, int* ain_single_len );
    ds_hstring m_get_single_script_cookie( const char* ach_cookie, int in_len_cookie, int* ain_pos, ds_hstring* ads_prefix );

    void               m_get_parent_paths  ( ds_hvector_btype<dsd_const_string>& rdsp_paths, const dsd_const_string& rdsp_path );
    void               m_get_parent_domains( ds_hvector_btype<dsd_const_string>& rdsp_domains, const dsd_const_string& rdsp_path );

    // cma functions:
    bool  m_open_cma   ( dsd_ck_cma* ads_ck_cma, bool bo_write );
    bool  m_close_cma  ( dsd_ck_cma* ads_ck_cma );
	bool  m_enlarge_cma( dsd_ck_cma* ads_ck_cma, int in_min_elements = -1 );
    bool  m_setup_cma_names( const dsd_const_string& ach_cmabase );
    int  m_create_name( char* ach_out, int in_max_len, const dsd_const_string& ach_base, const dsd_const_string& ach_suffix );
    
	bool         m_insert_avl_cookie(dsd_avl_cookie_info& rdsp_cookie_info);
	bool         m_delete_avl_cookie(dsd_avl_cookie_info& rdsp_cookie_info);
	bool         m_free_avl_tree();
	bool         m_read_avl_tree(hl_time_t ilp_current_time);
	bool         m_write_avl_tree();
};

#endif // _DS_CK_MGMT_H
