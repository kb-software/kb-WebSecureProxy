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

/*
  1.) Why centralized cookie handling?
  ====================================
    If we are sending all cookies to the browser, we must change the 
    domain (and path) that it is fitting to our url "wsp.hob.de". So there
    might be cookies, which are send to wrong servers:

    Example 1:
    ----------
        Set-Cookie: Cookie1="test"; domain="www.server.de"; path="/path"

        If this cookie is set from a server while surfing with wsg, and we
        want to send all cookies to browser, we will change the cookie to
        domain="wsp.hob.de"; path="http://www.server.de/path".
        Everything fine.

    Example 2:
    ----------
        Set-Cookie: Cookie2="test"; domain=".server.de"; path="/path"

        If this cookie is set from a server while surfing with wsg, and we
        want to send all cookies to browser, we will change the cookie to
        domain="wsp.hob.de"; path="/".
        So the cookie will be send to ALL servers which are visited with wsg.
    
    So the concept off sending all cookies to the browser opens a big
    security hole and might confuse servers, which must handle unknown
    cookies.


  2.) Implementation of centralized cookie handling:
  ==================================================
    The base idea is, that we will create some memory in cma for each user.
    This memory will hold his cookies.

    The main problem is, how could we manage to find the saved cookies fast
    for a requested url.



    TODO!!!
*/

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
#ifndef DEF_MAX_LEN_CMA_NAME        // wsp/include/hob-wspsu1.h
    #define D_MAXCMA_NAME 128
#else
    #define D_MAXCMA_NAME DEF_MAX_LEN_CMA_NAME
#endif


/*+---------------------------------------------------------------------+*/
/*| forward defintions:                                                 |*/
/*+---------------------------------------------------------------------+*/
class ds_wsp_helper;
template <class T> class ds_hvector2;
class ds_hstring;
class ds_cookie;
struct dsd_capacity;
struct dsd_ck_stor;
struct dsd_ck_mgmt;
struct dsd_ck_hash;

struct dsd_ck_cma {
    char            chrc_name[D_MAXCMA_NAME];   // name of cma
    void*           avc_handle;                 // handle for hash cma
    dsd_capacity*   adsc_cap;                   // hash cma capacity
    bool            bo_write;                   // write access?
    int             in_def_elem;                // default number of elements
    int             in_size_elem;               // size per element
};

struct dsd_ck_cache {
    ds_hstring             dsc_domain;      // cached result for domain
    ds_hstring             dsc_path;        // cached result for path
    ds_hvector2<ds_cookie> dsc_cookies;     // cached get cookies
};

/*+---------------------------------------------------------------------+*/
/*| class defintion:                                                    |*/
/*+---------------------------------------------------------------------+*/
class ds_ck_mgmt {
public:
    // constructor:
    ds_ck_mgmt();

    // init functions:
    void m_init( ds_wsp_helper* ads_wsp_helper, bool bo_trace );

    // set cookies:
    bool m_set_cookie       ( const char* ach_cookie, int in_len_cookie,
                              const char* ach_domain, int in_len_domain,
                              const char* ach_path,   int in_len_path,
                              const char* ach_cmabase                    );
    bool m_set_script_cookie( const char* ach_cookie, int in_len_cookie,
                              const char* ach_domain, int in_len_domain,
                              const char* ach_path,   int in_len_path,
                              const char* ach_cmabase                    );

    // get cookies:
    ds_hvector2<ds_cookie> m_get_cookies( const char* ach_domain, int in_len_domain,
                                          const char* ach_path,   int in_len_path,
                                          const char* ach_cmabase                    );

    // remove script cookies:
    ds_hvector2<ds_hstring> m_rm_script_cookies();
    
private:
    // variables:
    ds_wsp_helper*          adsc_wsp_helper;    // wsp callback class
    dsd_ck_cache            dsc_cache;          // get cookies cache
    ds_hvector2<ds_hstring> dsc_sc_cookies;     // script cookies -> to be removed
    bool                    boc_trace;          // trace cookies
    ds_hstring              ds_trace_path;      // trace path

    // cma variables:
    dsd_ck_cma      dsc_hash_cma;           // struct for hash cma
    dsd_ck_cma      dsc_coll_cma;           // struct for hash collision cma
    dsd_ck_cma      dsc_mgmt_cma;           // struct for cookie mgmt cma
    dsd_ck_cma      dsc_stor_cma;           // struct for cookie storage cma

    // functions:
    inline bool m_prepare( const char* ach_cmabase );
    inline bool m_finish ();
    inline void m_clear_cache();
    bool m_save_cookie   ( ds_cookie* ads_cookie );
    int  m_store_cookie  ( ds_cookie* ads_cookie, int in_old_cookie );
    bool m_create_tables ( ds_cookie* ads_cookie, int in_mem_index, bool bo_overwrite );

    // delete functions:
    bool             m_delete_cookie( int in_stor_pos );
    bool             m_delete_stor  ( int in_index );
    ds_hvector2<int> m_delete_mgmt  ( int in_points_to );
    bool             m_delete_hash  ( int in_points_to );
    
    // trace functions:
    void       m_create_trace     ();
    void       m_trace_cookie     ( ds_cookie* ads_cookie );
    ds_hstring m_get_hash_overview();
    ds_hstring m_get_mgmt_overview();
    ds_hstring m_get_stor_overview();

    void       m_get_single_cookie       ( const char* ach_cookie, int in_len_cookie, int in_pos, int* ain_single_len );
    ds_hstring m_get_single_script_cookie( const char* ach_cookie, int in_len_cookie, int* ain_pos, ds_hstring* ads_prefix );

    ds_hvector2<ds_hvector2<ds_hstring>> m_get_parent_hosts  ( const char* ach_domain, int in_len_domain,
                                                               const char* ach_path,   int in_len_path   );
    ds_hvector2<ds_hstring>              m_get_parent_paths  ( const char* ach_path,   int in_len );
    ds_hvector2<ds_hstring>              m_get_parent_domains( const char* ach_domain, int in_len );

    // cma functions:
    bool  m_open_cma   ( dsd_ck_cma* ads_ck_cma, bool bo_write );
    bool  m_close_cma  ( dsd_ck_cma* ads_ck_cma );
    bool  m_create_cma ( dsd_ck_cma* ads_ck_cma );
    bool  m_enlarge_cma( dsd_ck_cma* ads_ck_cma, int in_min_elements = -1 );
    bool  m_setup_cma_names( const char* ach_cmabase );
    bool  m_create_name( char* ach_out, int in_max_len, const char* ach_base, const char* ach_suffix );
    dsd_ck_cma m_backup_cma( dsd_ck_cma* ads_ck_cma );

    // element functions:    
    template <class T> bool m_get_element( dsd_ck_cma* ads_ck_cma, int in_index, T** aads_out );
    dsd_ck_stor* m_get_free_stor( int* ain_index );
    dsd_ck_mgmt* m_get_free_mgmt( int* ain_index );
    dsd_ck_hash* m_get_free_coll( int* ain_index );

    // storage functions:
    int  m_search_cookie   ( ds_cookie* ads_cookie, ds_hvector2<int> ds_pos_stor );
    bool m_get_ck_from_stor( int in_index, ds_cookie* ads_out );

    // managment functions:
    ds_hvector2<int> m_mgmt_points_to  ( int in_index, bool bo_get_parent = true );
    ds_hvector2<int> m_get_mgmt_parents( int in_index );
    int              m_insert_mgmt( int in_save_at, int in_points_to, int in_par_domain, int in_par_path, int in_add_childs );
    bool             m_fill       ( dsd_ck_mgmt* ads_mgmt, int in_points_to, int in_par_domain, int in_par_path, int in_add_childs );
    bool             m_add_index  ( dsd_ck_mgmt* ads_mgmt, int in_mem_index );
    bool             m_set_parents( dsd_ck_mgmt* ads_mgmt, int in_par_domain, int in_par_path );
    int              m_get_mgmt_from_stor( int in_stor_pos );
    bool             m_mgmt_rm_index     ( dsd_ck_mgmt* ads_mgmt, int in_stor_pos );

    // hash functions:
    int  m_get_first_subentry   ( const char* ach_domain, int in_len_domain, const char* ach_path, int in_len_path );
    int  m_hash_points_to       ( const char* ach_host, int in_len_host );
    bool m_insert_hash          ( const char* ach_host, int in_len_host, int in_pos_mgmt );
    bool m_insert_hash          ( dsd_ck_hash* ads_in );
    bool m_fill                 ( dsd_ck_hash* ads_hash, unsigned int uin_hash, const char* ach_host, int in_len_host, int in_points_to );
    int  m_get_last_next_pointer( int in_hash_pos );
    bool m_hash_resize          ();
    bool m_hash_reset           ( dsd_ck_cma* ads_ck_cma );
    bool m_copy_hash_from_backup( dsd_ck_cma* ads_ck_backup );

    unsigned int m_get_hash( const char* ach_in, int in_len_in );
    bool         m_equals  ( const char* ach_1, int in_len_1, const char* ach_2, int in_len_2 );
};

#endif // _DS_CK_MGMT_H
