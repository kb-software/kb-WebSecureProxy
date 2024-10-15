/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>
#include <ds_hstring.h>
#include "ds_cookie.h"
#include <ds_hvector.h>
#include "ds_ck_mgmt.h"
#include <align.h>
#include <time.h>
#include <stddef.h>


#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H
#ifdef HL_UNIX
	#include <hob-unix01.h>
	//#include <type-defines.h>
	#define max(a,b) (((a)>(b))?(a):(b))
	#define min(a,b) (((a)<(b))?(a):(b))
#endif

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
#define SM_USE_COOKIE_PATH_ITERATION	1

#define CK_MEM_SIZE         256
#define CK_MAX_PER_DOMAIN    20
#define CK_MAX_HOST_LEN     512
#define CK_MAX_DOMAIN_LEN   256
#define CK_MAX_PATH_LEN     256

#define DEFAULT_SIZE_HASH_CMA   25
#define DEFAULT_SIZE_COLL_CMA    5
#define DEFAULT_SIZE_MGMT_CMA   25
#define DEFAULT_SIZE_STOR_CMA   20

#define HASH_CMA_SUFFIX     "/ck_hash"

#define CK_SCRIPT_PREFACE   "HOB_set"
#define CK_SCRIPT_SEMICOLON "HOBscol"
#define CK_SCRIPT_QUOTE     "HOBquote"
#define CK_DELETE_TIME      "Thu, 01 Jan 1970 01:00:00 UTC"
#define CK_XML_SINGLE_TAG   "<cookie>"
#define CK_XML_SINGLE_ETAG  "</cookie>"

#define DEF_CK_HASH_LOAD    0.75
#define DEF_CK_RESIZE       2

#define CK_HASH_TABLE_FILE  "ck_hash_table.txt"
#define CK_MGMT_TABLE_FILE  "ck_mgmt_table.txt"
#define CK_MEM_TABLE_FILE   "ck_memory_table.txt"
#define CK_COOKIE_IN_FILE   "ck_cookie_input.txt"

// MJ 10.06.09:
#ifdef HL_UNIX
    #define LOGFILE_PATH          "../log/"
    #define WEBSERVER_PATH        "plugins/web_server/"  
#else
    #define LOGFILE_PATH          "..\\log\\"
    #define WEBSERVER_PATH        "plugins\\web_server\\"  
#endif

#define HL_AVL_DOMAIN_SERIALIZED_SIZE(adsp_avl_domain) (4 + 4 + adsp_avl_domain->dsc_domain.m_get_len())
#define HL_AVL_PATH_SERIALIZED_SIZE(adsp_avl_path) (4 + 4 + adsp_avl_path->dsc_path.m_get_len())
#define HL_AVL_COOKIE_SERIALIZED_SIZE(adsp_avl_cookie) (4 + adsp_avl_cookie->dsc_name.m_get_len() + 4 + adsp_avl_cookie->dsc_data.m_get_len() + 8 + 1 + 1 + 1)

/*! \brief holds hashed cookie and reference to the cookie_mgmt_table
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_ck_hash {
    bool         bo_occupied;                       //!< sign if this structure is in use
    unsigned int uin_hash;                          //!< hash over user and host
    char         rch_host[CK_MAX_HOST_LEN];         //!< host "www.hob.de/test1/test2/"
    int          in_points_to;                      //!< pointer to position in ds_cookie_mgmt_table
    int          in_next_in_rest;                   //!< pointer to next in rest with equal hash!
};

/*! \brief tracks indices of cookies in the cookie storage
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_ck_mgmt {
    bool         bo_occupied;                       //!< sign if this structure is in use
    int          in_occ_indices;                    //!< count occupied indices in rin_indices
    int          rin_indices[CK_MAX_PER_DOMAIN];    //!< links to cookies in cookie storage
    int          in_par_domain;                     //!< pointer to parent element domain (old: father)
    int          in_par_path;                       //!< pointer to parent element path   (old: mother)
    int          in_count_childs;                   //!< count child elements
};

/*! \brief keep track of cookie attributes
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_ck_stor {
    int         in_length;                      //!< 0 = empty!
    char        rch_cookie[CK_MEM_SIZE];        //!< name=value
    char        rch_domain[CK_MAX_DOMAIN_LEN];  //!< domain of cookie "www.hob.de"
    char        rch_path  [CK_MAX_PATH_LEN];    //!< path of cookie "/path1/path2/"
    hl_time_t   t_expires;                    //!< -1 = delete at logout
    bool        bo_secure;                      //!< true = cookie only for secure connections
    int         in_next;                        //!< next cookie mem (if larger than CK_MEM_SIZE)
    bool        bo_has_parent;                  //!< has parent element
};

struct dsd_my_avl_tree_entry {
	struct dsd_htree1_avl_entry dsc_avl_entry;
	struct dsd_my_avl_tree_entry* adsc_next;
};

// Static asserts are helpful!
template<bool> struct dsd_static_assert;
template<> struct dsd_static_assert<true> {
};
#define HL_STATIC_ASSERT(cond, message) (sizeof(dsd_static_assert<cond>) != 0)
// Returns the end-offset of a <dsd_struct>::dsc_member
#define HL_END_OFFSETOF(dsd_struct, dsc_member) (offsetof(dsd_struct, dsc_member)+sizeof(((dsd_struct*)0)->dsc_member))
// Ensures that field dsd_my_avl_tree_entry::adsc_next does not point into <dsd_struct>::dsc_avl_entry
#define HL_ASSERT_NO_OVERLAP(dsd_struct, dsc_avl_entry) \
	HL_STATIC_ASSERT(sizeof(dsd_struct) >= sizeof(dsd_my_avl_tree_entry) && HL_END_OFFSETOF(dsd_struct, dsc_avl_entry) <= offsetof(dsd_my_avl_tree_entry, adsc_next), \
		"dsd_my_avl_tree_entry::adsc_next overlaps with <dsd_struct>::dsc_avl_entry")

static int m_avl_cmp_cookies(void*,
	struct dsd_htree1_avl_entry* dsp_e1,
    struct dsd_htree1_avl_entry* dsp_e2)
{
	struct dsd_avl_cookie* adsl_d1 = (struct dsd_avl_cookie*)dsp_e1;
	struct dsd_avl_cookie* adsl_d2 = (struct dsd_avl_cookie*)dsp_e2;
	return adsl_d1->dsc_name.m_compare(adsl_d2->dsc_name);
}

static int m_avl_cmp_paths(void*,
	struct dsd_htree1_avl_entry* dsp_e1,
    struct dsd_htree1_avl_entry* dsp_e2)
{
	struct dsd_avl_path* adsl_d1 = (struct dsd_avl_path*)dsp_e1;
	struct dsd_avl_path* adsl_d2 = (struct dsd_avl_path*)dsp_e2;
#if SM_COOKIE_PATH_CASE_SENSITIVE
	return adsl_d1->dsc_path.m_compare(adsl_d2->dsc_path);
#else
	return adsl_d1->dsc_path.m_compare_ic(adsl_d2->dsc_path);
#endif
}

static int m_avl_cmp_domains(void*,
	struct dsd_htree1_avl_entry* dsp_e1,
    struct dsd_htree1_avl_entry* dsp_e2)
{
	struct dsd_avl_domain* adsl_d1 = (struct dsd_avl_domain*)dsp_e1;
	struct dsd_avl_domain* adsl_d2 = (struct dsd_avl_domain*)dsp_e2;
	int inl_ret = adsl_d1->dsc_domain.m_compare_ic(adsl_d2->dsc_domain);
	return inl_ret;
}

static void m_reverse_domain(const dsd_const_string& rdsp_domain, ds_hstring& rdsp_dst)
{
    // intialize some variables:
    if ( ds_ck_mgmt::m_is_ineta(rdsp_domain.m_get_start(), rdsp_domain.m_get_len()) ) {
		rdsp_dst.m_write(rdsp_domain);
        return;
    }
	dsd_const_string dsl_cur = rdsp_domain;
	do {
		int in_pos = dsl_cur.m_last_index_of( "." );
		if(in_pos < 0)
			break;
		rdsp_dst.m_write(dsl_cur.m_substring(in_pos + 1));
		rdsp_dst.m_write(".");
		dsl_cur = dsl_cur.m_substring(0, in_pos);
	} while(true);
	rdsp_dst.m_write(dsl_cur);
    return;
} // end of m_reverse_domain

struct dsd_iterate_avl_call {
	bool (*m_call)(struct dsd_iterate_avl_call*);
	int inc_depth;
	struct dsd_avl_domains* adsl_avl_domains;
	struct dsd_avl_domain* adsl_avl_domain1;
	struct dsd_avl_path* adsl_avl_path1;
	struct dsd_avl_cookie* adsl_avl_cookie1;
};

static bool m_iterate_avl_tree(struct dsd_avl_domains* adsp_avl_domains, struct dsd_iterate_avl_call* adsp_call)
{
	adsp_call->adsl_avl_domains = adsp_avl_domains;
	adsp_call->inc_depth = 0;
	if(!adsp_call->m_call(adsp_call))
		return false;
	struct dsd_htree1_avl_work dsl_avl_work1;
	BOOL bol_res = m_htree1_avl_getnext(NULL, &adsp_avl_domains->dsc_avl_domains, &dsl_avl_work1, TRUE);
	if(!bol_res)
		return false;
	unsigned int inl_num_domains = 0;
	while(dsl_avl_work1.adsc_found != NULL) {
		inl_num_domains++;
		struct dsd_avl_domain* adsl_avl_domain1 = (struct dsd_avl_domain*)dsl_avl_work1.adsc_found;
		adsp_call->adsl_avl_domain1 = adsl_avl_domain1;
		adsp_call->inc_depth = 1;
		if(!adsp_call->m_call(adsp_call))
			return false;
		struct dsd_htree1_avl_work dsl_avl_work2;
		bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_domain1->dsc_avl_paths, &dsl_avl_work2, TRUE);
		if(!bol_res)
			return false;
		unsigned int inl_num_paths = 0;
		while(dsl_avl_work2.adsc_found != NULL) {
			inl_num_paths++;
			struct dsd_avl_path* adsl_avl_path1 = (struct dsd_avl_path*)dsl_avl_work2.adsc_found;
			adsp_call->adsl_avl_path1 = adsl_avl_path1;
			adsp_call->inc_depth = 2;
			if(!adsp_call->m_call(adsp_call))
				return false;
			struct dsd_htree1_avl_work dsl_avl_work3;
			bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_path1->dsc_avl_cookies, &dsl_avl_work3, TRUE);
			if(!bol_res)
				return false;
			unsigned int inl_num_cookies = 0;
			while(dsl_avl_work3.adsc_found != NULL) {
				inl_num_cookies++;
				struct dsd_avl_cookie* adsl_avl_cookie1 = (struct dsd_avl_cookie*)dsl_avl_work3.adsc_found;
				adsp_call->adsl_avl_cookie1 = adsl_avl_cookie1;
				adsp_call->inc_depth = 3;
				if(!adsp_call->m_call(adsp_call))
					return false;
				bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_path1->dsc_avl_cookies, &dsl_avl_work3, FALSE);
				if(!bol_res)
					return false;
			}
			bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_domain1->dsc_avl_paths, &dsl_avl_work2, FALSE);
			if(!bol_res)
				return false;
			if(inl_num_cookies != adsl_avl_path1->inc_num_cookies)
				return false;
		}
		bol_res = m_htree1_avl_getnext(NULL, &adsp_avl_domains->dsc_avl_domains, &dsl_avl_work1, FALSE);
		if(!bol_res)
			return false;
		if(inl_num_paths != adsl_avl_domain1->inc_num_paths)
			return false;
	}
	if(inl_num_domains != adsp_avl_domains->inc_num_domains)
		return false;
	return true;
}

/*+---------------------------------------------------------------------+*/
/*| constructor:                                                        |*/
/*+---------------------------------------------------------------------+*/
ds_ck_mgmt::ds_ck_mgmt()
{
    adsc_wsp_helper = NULL;
    boc_trace       = false;

	dsc_hash_cma.chrc_name[0] = 0;
	dsc_hash_cma.inc_len_name = 0;
	dsc_hash_cma.dsc_cma.ac_cma_handle = NULL;
    dsc_hash_cma.achc_start   = NULL;
	dsc_hash_cma.achc_end     = NULL;

	dsc_avl_domains.inc_num_domains = 0;
	m_htree1_avl_init(NULL, &dsc_avl_domains.dsc_avl_domains, &m_avl_cmp_domains);
	dsc_avl_domains.inc_serialized_size = 4;
    
    dsc_cache.dsc_domain.m_setup( NULL );
    dsc_cache.dsc_path.m_setup  ( NULL );
    ds_trace_path.m_setup       ( NULL );
} // end of ds_ck_mgmt::ds_ck_mgmt

ds_ck_mgmt::~ds_ck_mgmt()
{
	this->m_free_avl_tree();
}

/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
 * \ingroup authlib
 *
 * public function ds_ck_mgmt::m_init
 * initialize class
 *
 * @param[in]   ds_wsp_helper*  ads_wsp_helper
 * @param[in]   bool            bo_trace
*/
void ds_ck_mgmt::m_init( ds_wsp_helper* ads_wsp_helper, bool bo_trace )
{
    adsc_wsp_helper = ads_wsp_helper;
    boc_trace       = bo_trace;
	
    dsc_cache.dsc_domain.m_init ( adsc_wsp_helper );
    dsc_cache.dsc_path.m_init   ( adsc_wsp_helper );
    dsc_cache.dsc_cookies.m_init( adsc_wsp_helper );

    dsc_sc_cookies.m_init( adsc_wsp_helper );
    dsc_cur_cookies.m_init( adsc_wsp_helper );
    dsc_to_delete.m_init( adsc_wsp_helper );
} // end of ds_ck_mgmt::m_init


/**
 * \ingroup authlib
 *
 * public function ds_ck_mgmt::m_set_cookie
 * save a cookie for current user
 * this function can handle a complete "Set-Cookie" header line, which
 * means more than one cookie can be saved with one function call
 *
 * @param[in]   const char* ach_cookie          pointer to cookie
 * @param[in]   int         in_len_cookie       length of cookie
 * @param[in]   const char* ach_domain          pointer to requested domain
 * @param[in]   int         in_len_domain       length of requested domain
 * @param[in]   const char* ach_path            pointer to requested path
 * @param[in]   int         in_len_path         length of requested path
 * @param[in]   const char* ach_cmabase         base cma name
 * @return      bool                            true = success
*/
bool ds_ck_mgmt::m_set_cookie( const dsd_const_string& rdsp_cookie,
                               const dsd_const_string& rdsp_domain,
                               const dsd_const_string& rdsp_path,
                               const dsd_const_string& ach_cmabase )
{
    // initialize some variables:
    bool      bo_ret;                   // return from several function calls
    bool      bo_success    = true;     // our return value
    int       in_pos        = 0;
    int       in_single_len;
    ds_cookie dsl_cookie( adsc_wsp_helper );


    //------------------------------------------------
    // check input data:
    //------------------------------------------------
    if ( rdsp_domain.m_get_len() <= 0
         || rdsp_path.m_get_len() <= 0
         || rdsp_path[0] != '/'
         || ach_cmabase.m_get_len() <= 0 )
    {
        return false;
    }
    
    //------------------------------------------------
    // clear getcookies cache:
    //------------------------------------------------
    if ( dsc_cache.dsc_cookies.m_empty() == false ) {
        m_clear_cache();
    }

    //------------------------------------------------
    // prepare cmas:
    //------------------------------------------------
    bo_ret = m_setup_cma_names( ach_cmabase );
    if ( bo_ret == false ) {
        return false;
    }

    //------------------------------------------------
    // set requested host url:
    //------------------------------------------------
    dsl_cookie.m_set_req_host(rdsp_domain, rdsp_path);

	 if(!m_save_cookie_begin())
		 return false;

    const char* ach_cookie = rdsp_cookie.m_get_ptr();
    int in_len_cookie = rdsp_cookie.m_get_len();
    while ( in_pos < in_len_cookie ) {
        //--------------------------------------------
        // get single cookie:
        //--------------------------------------------
        m_get_single_cookie( ach_cookie, in_len_cookie, in_pos, &in_single_len );
        
        //--------------------------------------------
        // parse imcomming cookie:
        //--------------------------------------------
        bo_ret = dsl_cookie.m_parse_cookie(rdsp_cookie.m_substr(in_pos, in_single_len));
        in_pos += in_single_len + 1;
        if ( bo_ret == false ) {
            bo_success = false;
            dsl_cookie.m_reset();
            continue;
        }


        //--------------------------------------------
        // save imcomming cookie:
        //--------------------------------------------
        bo_ret = m_save_cookie( &dsl_cookie );
        if ( bo_ret == false ) {
            bo_success = false;
        }

        //--------------------------------------------
        // reset local cookie class:
        //--------------------------------------------
        dsl_cookie.m_reset();
    }

 	 if(!m_save_cookie_end())
		 return false;

	 return bo_success;
} // end of ds_ck_mgmt::m_set_cookie


/**
 * \ingroup authlib
 *
 * public function ds_ck_mgmt::m_set_script_cookie
 * save a cookie given from HOBscript for current user
 *
 * @param[in]   const char* ach_cookie          pointer to cookie
 * @param[in]   int         in_len_cookie       length of cookie
 * @param[in]   const char* ach_domain          pointer to requested domain
 * @param[in]   int         in_len_domain       length of requested domain
 * @param[in]   const char* ach_path            pointer to requested path
 * @param[in]   int         in_len_path         length of requested path
 * @param[in]   const char* ach_cmabase         base cma name
 * @return      bool                            true = success
*/
bool ds_ck_mgmt::m_set_script_cookie( const dsd_const_string& rdsp_cookie,
                                      const dsd_const_string& rdsp_domain,
                                      const dsd_const_string& rdsp_path,
                                      const dsd_const_string& ach_cmabase)
{
    // initialize some variables:
    bool       bo_ret;                  // return from several function calls
    bool       bo_success    = true;    // our return value
    int        in_pos        = 0;
    ds_cookie  dsl_cookie( adsc_wsp_helper );
    ds_hstring ds_ck_str ( adsc_wsp_helper );
    ds_hstring ds_prefix ( adsc_wsp_helper );


    //------------------------------------------------
    // check input data:
    //------------------------------------------------
    if ( rdsp_domain.m_get_len() <= 0
         || rdsp_path.m_get_len() <= 0
         || rdsp_path[0] != '/' 
         || ach_cmabase.m_get_len() <= 0 ) {
        return false;
    }
    
    //------------------------------------------------
    // clear getcookies cache:
    //------------------------------------------------
    if ( dsc_cache.dsc_cookies.m_empty() == false ) {
        m_clear_cache();
    }

    //------------------------------------------------
    // prepare cmas:
    //------------------------------------------------
    bo_ret = m_setup_cma_names( ach_cmabase );
    if ( bo_ret == false ) {
        return false;
    }

    //------------------------------------------------
    // set requested host url:
    //------------------------------------------------
    dsl_cookie.m_set_req_host( "", "/" );

	 if(!m_save_cookie_begin())
		 return false;

    const char* ach_cookie = rdsp_cookie.m_get_ptr(); 
    int in_len_cookie = rdsp_cookie.m_get_len();
    while ( in_pos < in_len_cookie ) {
        //--------------------------------------------
        // get single cookie:
        //--------------------------------------------
        ds_ck_str = m_get_single_script_cookie( ach_cookie, in_len_cookie,
                                                &in_pos, &ds_prefix       );
        
        //--------------------------------------------
        // add script cookie to delete list:
        //--------------------------------------------
        if ( ds_prefix.m_get_len() > 0 ) {
            dsc_sc_cookies.m_add( ds_prefix );
        }

        //--------------------------------------------
        // parse imcomming cookie:
        //--------------------------------------------
        bo_ret = dsl_cookie.m_parse_cookie( ds_ck_str.m_const_str() );
        if ( bo_ret == false ) {
            bo_success = false;
            dsl_cookie.m_reset();
            continue;
        }

#ifdef _DEBUG
		adsc_wsp_helper->m_logf(ied_sdh_log_error, "[%d] #WSG: Set-Script-Cookie: %.*s\n",
			adsc_wsp_helper->m_get_session_id(), 
			ds_ck_str.m_const_str().m_get_len(), ds_ck_str.m_const_str().m_get_ptr());
#endif
        //--------------------------------------------
        // save imcomming cookie:
        //--------------------------------------------
        bo_ret = m_save_cookie( &dsl_cookie );
        if ( bo_ret == false ) {
            bo_success = false;
        }

        //--------------------------------------------
        // reset local cookie class:
        //--------------------------------------------
        dsl_cookie.m_reset();
    }

	 if(!m_save_cookie_end())
		 return false;

	 return bo_success;
} // end of ds_ck_mgmt::m_set_script_cookie


/**
 * \ingroup authlib
 *
 * public function ds_ck_mgmt::m_rm_script_cookies
 *
 * @return  ds_hvector<ds_hstring>
*/
void ds_ck_mgmt::m_rm_script_cookies(ds_hvector<ds_hstring>& rdsp_out)
{
    // initialize some variables:
    ds_hstring             ds_rm_cookie ( adsc_wsp_helper );

    for ( HVECTOR_FOREACH(ds_hstring, adsl_cookie, this->dsc_sc_cookies) ) {
        ds_rm_cookie.m_write( HVECTOR_GET(adsl_cookie).m_get_ptr(),
                              HVECTOR_GET(adsl_cookie).m_get_len() );
        ds_rm_cookie.m_write( "=delete; expires=" );
        ds_rm_cookie.m_write( CK_DELETE_TIME );
        ds_rm_cookie.m_write( "; path=/" );

        rdsp_out.m_add( ds_rm_cookie );
        ds_rm_cookie.m_reset();
    }

    dsc_sc_cookies.m_clear();


    return;
} // end of ds_ck_mgmt::m_rm_script_cookies


/**
 * \ingroup authlib
 *
 * public function ds_ck_mgmt::m_get_cookies
 * get cookies for current user for requested url
 *
 * @param[in]   const char*             ach_domain          pointer to requested domain
 * @param[in]   int                     in_len_domain       length of requested domain
 * @param[in]   const char*             ach_path            pointer to requested path
 * @param[in]   int                     in_len_path         length of requested path
 * @param[in]   const char*             ach_cmabase         base cma name
 * @return      ds_hvector<ds_cookie>                      chain of found cookies
*/
const ds_hvector<ds_cookie>* ds_ck_mgmt::m_get_cookies(
    const dsd_const_string& rdsp_domain, const dsd_const_string& rdsp_path,
    const dsd_const_string& ach_cmabase, bool bop_https  )
{
    // initialize some variables:
    bool                   bo_ret;                          // return from several function calls
    ds_cookie              dsl_cookie ( adsc_wsp_helper );  // working variable
    

    //------------------------------------------------
    // 1.1 check input data:
    //------------------------------------------------
    if ( rdsp_domain.m_get_len() <= 0
         || rdsp_path.m_get_len() <= 0
         || !rdsp_path.m_starts_with("/")
         || ach_cmabase[0] <= 0 ) {
        return NULL;
    }

    //------------------------------------------------
    // 1.2 remove ports from domain:
    //------------------------------------------------
    dsd_const_string dsl_req_domain = rdsp_domain;
	// TODO: Use parser for IPv4, IPv6 and DNS names.
    int inl_pos = dsl_req_domain.m_last_index_of(":");
    if(inl_pos >= 0)
        dsl_req_domain = dsl_req_domain.m_substring(0, inl_pos);
#if 0
    for ( in_pos = 0; in_pos < in_len_domain; in_pos++ ) {
        if ( rdsp_domain[in_pos] == ':' ) {
            in_len_domain = in_pos;
        }
    }
#endif
    dsd_const_string dsl_req_path = rdsp_path;
#if 0
	//------------------------------------------------
    // 1.3 remove filename from path:
    //------------------------------------------------
    inl_pos = dsl_path.m_last_index_of("/");
    if(inl_pos >= 0)
        dsl_path = dsl_path.m_substring(0, inl_pos+1);
#endif
#if 0
    for ( ; in_len_path > 0; in_len_path-- ) {
        if ( ach_path[in_len_path - 1] == '/' ) {
            break;
        }
    }
#endif    
    //------------------------------------------------
    // 2. have a look inside getcookies cache:
    //------------------------------------------------
    if ( dsc_cache.dsc_cookies.m_empty() == false ) {
        if (    dsc_cache.dsc_domain.m_equals_ic( dsl_req_domain )
#if SM_COOKIE_PATH_CASE_SENSITIVE
				&& dsc_cache.dsc_path.m_equals( dsl_req_path )
#else
				&& dsc_cache.dsc_path.m_equals_ic( dsl_path )
#endif
			 )
		{
            return &dsc_cache.dsc_cookies;
        }
        m_clear_cache();
    }

    //------------------------------------------------
    // 3. prepare cmas:
    //------------------------------------------------
    bo_ret = m_setup_cma_names( ach_cmabase );
    if ( bo_ret == false ) {
        return NULL;
    }

    //------------------------------------------------
    // 4. open all cmas for reading:
    //------------------------------------------------
    bo_ret = m_enter_lock( false );
    if ( bo_ret == false ) {
        return NULL;
    }

    ds_hvector_btype<dsd_const_string> ds_domains( adsc_wsp_helper );
    m_get_parent_domains( ds_domains, dsl_req_domain );
#if !SM_USE_COOKIE_PATH_ITERATION
	ds_hvector_btype<dsd_const_string> ds_paths( adsc_wsp_helper );
	m_get_parent_paths  ( ds_paths, rdsp_path );
#endif

	hl_time_t ill_current_time = this->adsc_wsp_helper->m_cb_get_time();
	if(!this->m_read_avl_tree(ill_current_time))
		goto LBL_FAIL;
	// TODO:
	// initialize some variables:

	for (HVECTOR_FOREACH(dsd_const_string, adsl_cur, ds_domains)) {
        const dsd_const_string& dsl_domain = HVECTOR_GET(adsl_cur);

		struct dsd_avl_domain dsl_avl_domain1;
		dsl_avl_domain1.dsc_domain = dsl_domain;
		struct dsd_htree1_avl_work dsl_avl_work1;
		BOOL bol_res = m_htree1_avl_search(
			NULL, &this->dsc_avl_domains.dsc_avl_domains,
			&dsl_avl_work1, &dsl_avl_domain1.dsc_avl_entry);
		if(!bol_res)
			return NULL;
		// Not found?
		if(dsl_avl_work1.adsc_found == NULL)
			continue;
		struct dsd_avl_domain* adsl_avl_domain1 = (struct dsd_avl_domain*)dsl_avl_work1.adsc_found;
#if SM_USE_COOKIE_PATH_ITERATION
		bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_domain1->dsc_avl_paths, &dsl_avl_work1, TRUE);
		if(!bol_res)
			return NULL;
		while(dsl_avl_work1.adsc_found != NULL) {
			struct dsd_avl_path* adsl_avl_path1 = (struct dsd_avl_path*)dsl_avl_work1.adsc_found;
			if(!ds_cookie::m_matches_path(adsl_avl_path1->dsc_path, dsl_req_path))
				goto LBL_NEXT_PATH;
			//dsd_const_string dsl_path_suffix = adsl_avl_path1->dsc_path.m_substring(dsl_path.m_get_len());
			//if(dsl_path_suffix.m_last_index_of("/") >= 0)
			//	break;
			struct dsd_htree1_avl_work dsl_avl_work2;
			bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_path1->dsc_avl_cookies, &dsl_avl_work2, TRUE);
			if(!bol_res)
				return NULL;
			while(dsl_avl_work2.adsc_found != NULL) {
				struct dsd_avl_cookie* adsl_avl_cookie1 = (struct dsd_avl_cookie*)dsl_avl_work2.adsc_found;
				
				if(adsl_avl_cookie1->ill_expires != -1 && adsl_avl_cookie1->ill_expires < ill_current_time)
					goto LBL_NEXT_COOKIE;
				if(adsl_avl_cookie1->boc_secure && !bop_https)
					goto LBL_NEXT_COOKIE;
				if(!adsl_avl_cookie1->boc_domain && !dsl_req_domain.m_equals_ic(adsl_avl_domain1->dsc_domain))
					goto LBL_NEXT_COOKIE;
				{
					ds_cookie& rdsl_add = dsc_cache.dsc_cookies.m_add2(adsc_wsp_helper)->dsc_element;
					rdsl_add.m_set_cookie(adsl_avl_cookie1->dsc_name.m_get_start(), adsl_avl_cookie1->dsc_name.m_get_len()); 
					rdsl_add.m_set_cookie("=", 1);
					rdsl_add.m_set_cookie(adsl_avl_cookie1->dsc_data.m_get_start(), adsl_avl_cookie1->dsc_data.m_get_len());
					rdsl_add.m_set_path(adsl_avl_path1->dsc_path.m_get_start(), adsl_avl_path1->dsc_path.m_get_len());
					rdsl_add.m_set_domain(adsl_avl_domain1->dsc_domain.m_get_start(), adsl_avl_domain1->dsc_domain.m_get_len());
					rdsl_add.m_set_secure(adsl_avl_cookie1->boc_secure);
					rdsl_add.m_set_httponly(adsl_avl_cookie1->boc_http_only);
					rdsl_add.m_set_domain(adsl_avl_cookie1->boc_domain);
				}
LBL_NEXT_COOKIE:
				bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_path1->dsc_avl_cookies, &dsl_avl_work2, FALSE);
				if(!bol_res)
					return NULL;
			}
LBL_NEXT_PATH:
			bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_domain1->dsc_avl_paths, &dsl_avl_work1, FALSE);
			if(!bol_res)
				return NULL;
		}
#else
		for ( HVECTOR_FOREACH(dsd_const_string, adsl_cur2, ds_paths) ) {
            const dsd_const_string& dsl_path = HVECTOR_GET(adsl_cur2);
			struct dsd_avl_path dsl_avl_path1;
			dsl_avl_path1.dsc_path = dsl_path;
			bol_res = m_htree1_avl_search(
				NULL, &adsl_avl_domain1->dsc_avl_paths,
				&dsl_avl_work1, &dsl_avl_path1.dsc_avl_entry);
			if(!bol_res)
				return NULL;
			if(dsl_avl_work1.adsc_found == NULL) {
				bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_domain1->dsc_avl_paths, &dsl_avl_work1, FALSE);
				if(!bol_res)
					return NULL;
			}
			while(dsl_avl_work1.adsc_found != NULL) {
				struct dsd_avl_path* adsl_avl_path1 = (struct dsd_avl_path*)dsl_avl_work1.adsc_found;
				if(!adsl_avl_path1->dsc_path.m_starts_with(dsl_path))
					break;
				dsd_const_string dsl_path_suffix = adsl_avl_path1->dsc_path.m_substring(dsl_path.m_get_len());
				if(dsl_path_suffix.m_last_index_of("/") >= 0)
					break;
				struct dsd_htree1_avl_work dsl_avl_work2;
				bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_path1->dsc_avl_cookies, &dsl_avl_work2, TRUE);
				if(!bol_res)
					return NULL;
				while(dsl_avl_work2.adsc_found != NULL) {
					struct dsd_avl_cookie* adsl_avl_cookie1 = (struct dsd_avl_cookie*)dsl_avl_work2.adsc_found;
					
					if(adsl_avl_cookie1->ill_expires != -1 && adsl_avl_cookie1->ill_expires < ill_current_time)
						goto LBL_NEXT_COOKIE;
					if(adsl_avl_cookie1->boc_secure && !bop_https)
						goto LBL_NEXT_COOKIE;

					ds_cookie& rdsl_add = dsc_cache.dsc_cookies.m_add2(adsc_wsp_helper)->dsc_element;
					rdsl_add.m_set_cookie(adsl_avl_cookie1->dsc_name.m_get_start(), adsl_avl_cookie1->dsc_name.m_get_len()); 
					rdsl_add.m_set_cookie("=", 1);
					rdsl_add.m_set_cookie(adsl_avl_cookie1->dsc_data.m_get_start(), adsl_avl_cookie1->dsc_data.m_get_len());
					rdsl_add.m_set_path(adsl_avl_path1->dsc_path.m_get_start(), adsl_avl_path1->dsc_path.m_get_len());
					rdsl_add.m_set_domain(adsl_avl_domain1->dsc_domain.m_get_start(), adsl_avl_domain1->dsc_domain.m_get_len());
					rdsl_add.m_set_secure(adsl_avl_cookie1->boc_secure);
					rdsl_add.m_set_httponly(adsl_avl_cookie1->boc_http_only);
					rdsl_add.m_set_domain(adsl_avl_cookie1->boc_domain);
LBL_NEXT_COOKIE:
					bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_path1->dsc_avl_cookies, &dsl_avl_work2, FALSE);
					if(!bol_res)
						return NULL;
				}
				bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_domain1->dsc_avl_paths, &dsl_avl_work1, FALSE);
				if(!bol_res)
					return NULL;
			}
		}
#endif
    }
LBL_FAIL:
    //------------------------------------------------
    // 7. leave read lock for all cmas:
    //------------------------------------------------
    m_leave_lock();

    //------------------------------------------------
    // 8. cache domain and path:
    //------------------------------------------------
    dsc_cache.dsc_domain = dsl_req_domain;
    dsc_cache.dsc_path = dsl_req_path;

	 return &dsc_cache.dsc_cookies;
} // end of ds_ck_mgmt::m_get_cookies


/**
 * \ingroup authlib
 *
 * public function ds_ck_mgmt::m_export_cookies
 * export cookies for current user and delete cma
 *
 * @param[out]  ds_hstring*             ads_out             output in xml
 * @param[in]   const char*             ach_cmabase         base cma name
 * @return      bool                                        true = success
*/
bool ds_ck_mgmt::m_export_cookies( ds_hstring* ads_out, const dsd_const_string& ach_cmabase )
{
	struct dsd_forward_iterator dsl_iterator;
	int inl_ret = m_count_cur_cookies(ach_cmabase, &dsl_iterator);
	ds_hvector<ds_cookie>& ds_cookies = this->dsc_cur_cookies;

    //------------------------------------------------
    // loop trough cookies:
    //------------------------------------------------
    ads_out->m_write( "<cookies>\n" );
    for ( HVECTOR_FOREACH(ds_cookie, adsl_cur, ds_cookies) ) {
        const ds_cookie& dsl_cookie = HVECTOR_GET(adsl_cur);
        if (    dsl_cookie.m_is_discard()     == false  /* ignore session cookies */
             && dsl_cookie.m_check_lifetime() == true ) {
            dsl_cookie.m_to_xml( ads_out );
        }
    }
    ads_out->m_write( "\n</cookies>" );

    //------------------------------------------------
    // delete all cmas:
    //------------------------------------------------
	 adsc_wsp_helper->m_cb_delete_cma( dsc_hash_cma.chrc_name, dsc_hash_cma.inc_len_name );
    return true;
} // end of ds_ck_mgmt::m_export_cookies


/**
 * \ingroup authlib
 *
 * public function ds_ck_mgmt::m_delete_cookies
 * delete cookie cmas
 *
 * @param[in]   const char*             ach_cmabase         base cma name
 * @return      bool                                        true = success
*/
bool ds_ck_mgmt::m_delete_cookies( const dsd_const_string& ach_cmabase )
{
    // initialize some variables:
    bool bol_ret;

    // check input parameters:
    if ( ach_cmabase.m_get_len() <= 0 ) {
        return false;
    }    

    //--------------------------------------------
    // setup cma names for current user:
    //--------------------------------------------
    bol_ret = m_setup_cma_names( ach_cmabase );
    if ( bol_ret == false ) {
        return false;
    }
	//-------------------------------------------
    // delete all cmas:
    //-------------------------------------------
	 adsc_wsp_helper->m_cb_delete_cma( dsc_hash_cma.chrc_name, dsc_hash_cma.inc_len_name );
	return true;
} // end of ds_ck_mgmt::m_delete_cookies


/**
 * \ingroup authlib
 *
 * public function ds_ck_mgmt::m_import_cookies
 * export cookies for current user
 *
 * @param[in]   const char*             ach_xml             pointer to xml data
 * @param[in]   int                     in_len_xml          length of xml data
 * @param[in]   const char*             ach_cmabase         base cma name
 * @return      bool                                        true = success
*/
bool ds_ck_mgmt::m_import_cookies( const char* ach_xml, int in_len_xml,
                                   const dsd_const_string& ach_cmabase )
{
    // initialize some variables:
    bool      bo_ret;                   // return from several function calls
    bool      bo_success    = true;     // our return value
    int       in_pos        = 0;
    int       in_single_len;
    ds_cookie dsl_cookie( adsc_wsp_helper );


    //------------------------------------------------
    // check input data:
    //------------------------------------------------
    if (    ach_xml        == NULL || in_len_xml < 1
         || ach_cmabase[0] == 0                      ) {
        return false;
    }

    //------------------------------------------------
    // prepare cmas:
    //------------------------------------------------
    bo_ret = m_setup_cma_names( ach_cmabase );
    if ( bo_ret == false ) {
        return false;
    }

 	 if(!m_save_cookie_begin())
		 return false;

    while ( in_pos < in_len_xml ) {
        //--------------------------------------------
        // get single cookie:
        //--------------------------------------------
        m_get_single_xml_cookie( ach_xml, in_len_xml, &in_pos, &in_single_len );
        if ( in_single_len < 1 ) {
            continue;
        }

        //--------------------------------------------
        // parse imcomming cookie:
        //--------------------------------------------
        bo_ret = dsl_cookie.m_from_xml( &ach_xml[in_pos], in_single_len );
        in_pos += in_single_len;
        if ( bo_ret == false ) {
            bo_success = false;
            dsl_cookie.m_reset();
            continue;
        }

        //--------------------------------------------
        // save imcomming cookie:
        //--------------------------------------------
        bo_ret = m_save_cookie( &dsl_cookie );
        if ( bo_ret == false ) {
            bo_success = false;
        }

        //--------------------------------------------
        // reset local cookie class:
        //--------------------------------------------
        dsl_cookie.m_reset();
    }

  	 if(!m_save_cookie_end())
		 return false;

	 return bo_success;
} // end of ds_ck_mgmt::m_import_cookies

struct dsd_iterate_avl_call3 : public dsd_iterate_avl_call {
	ds_hvector<ds_cookie>*   adsc_cur_cookies;
	ds_wsp_helper*			 adsc_wsp_helper;
};

static bool m_call_avl_tree_cookie_list(struct dsd_iterate_avl_call* adsp_call) {
	dsd_iterate_avl_call3* adsl_call3 = (struct dsd_iterate_avl_call3*)adsp_call;
	switch(adsp_call->inc_depth) {
	case 0:
		return true;
	case 1: {
		struct dsd_avl_domain* adsl_avl_domain1 = (struct dsd_avl_domain*)adsp_call->adsl_avl_domain1;
		return true;
	}
	case 2: {
		struct dsd_avl_path* adsl_avl_path1 = (struct dsd_avl_path*)adsp_call->adsl_avl_path1;
		return true;
	}
	case 3: {
		struct dsd_avl_domain* adsl_avl_domain1 = (struct dsd_avl_domain*)adsp_call->adsl_avl_domain1;
		struct dsd_avl_path* adsl_avl_path1 = (struct dsd_avl_path*)adsp_call->adsl_avl_path1;
		struct dsd_avl_cookie* adsl_avl_cookie1 = (struct dsd_avl_cookie*)adsp_call->adsl_avl_cookie1;
		int inl_index = adsl_call3->adsc_cur_cookies->m_size();
		ds_cookie& rdsl_add = adsl_call3->adsc_cur_cookies->m_add2(adsl_call3->adsc_wsp_helper)->dsc_element;
		rdsl_add.m_set_stor_pos(inl_index);
		rdsl_add.m_set_domain(adsl_avl_domain1->dsc_domain.m_get_start(), adsl_avl_domain1->dsc_domain.m_get_len());
		rdsl_add.m_set_path(adsl_avl_path1->dsc_path.m_get_start(), adsl_avl_path1->dsc_path.m_get_len());
		rdsl_add.m_set_cookie(adsl_avl_cookie1->dsc_name.m_get_start(), adsl_avl_cookie1->dsc_name.m_get_len()); 
		rdsl_add.m_set_cookie("=", 1);
		rdsl_add.m_set_cookie(adsl_avl_cookie1->dsc_data.m_get_start(), adsl_avl_cookie1->dsc_data.m_get_len());
		rdsl_add.m_set_expires(adsl_avl_cookie1->ill_expires);
		rdsl_add.m_set_discard(adsl_avl_cookie1->ill_expires < 0);
		return true;
	}
	default:
		return false;
	}
}

/**
 * \ingroup authlib
 *
 * public function ds_ck_mgmt::m_count_cur_cookies
 * count all cookies for current user
 *
 * @param[in]   const char* ach_cmabase         base cma name
 * @return      int                             number of cookies
*/
int ds_ck_mgmt::m_count_cur_cookies( const dsd_const_string& ach_cmabase, struct dsd_forward_iterator* adsp_iterator )
{
    // initialize some variables:
    bool         bo_ret;                        // return from several function calls

	adsp_iterator->avoc_cur = NULL;
	adsp_iterator->avoc_end = NULL;
	adsp_iterator->avoc_user = NULL;
	/*
        we want to fill a cached output of all cookies too.
        we request that the output is order by host

        for doing this we start search in mgmt table
        there exist all entries order by host
        ( but it might be possible that
            www.zzz.de
          stands in front of
            www.aaa.de )
        for the time beeing, we will not order the host entries
    */

    // check input data:
    if ( ach_cmabase[0] == 0 ) {
        return -1;
    }

    //------------------------------------------------
    // clear cached result:
    //------------------------------------------------
    dsc_cur_cookies.m_clear();

    //------------------------------------------------
    // prepare cmas:
    //------------------------------------------------
    bo_ret = m_setup_cma_names( ach_cmabase );
    if ( bo_ret == false ) {
        return -1;
    }

    //------------------------------------------------
    // open all cmas for reading:
    //------------------------------------------------
    bo_ret = m_enter_lock( false );
    if ( bo_ret == false ) {
        return -1;
    }

    //------------------------------------------------
    // go through all entries in mgmt table:
    //------------------------------------------------
	struct dsd_iterate_avl_call3 dsl_ic3;
	hl_time_t ill_current_time = this->adsc_wsp_helper->m_cb_get_time();
	if(!this->m_read_avl_tree(ill_current_time))
		goto LBL_FAIL;

	dsl_ic3.m_call = &m_call_avl_tree_cookie_list;
	dsl_ic3.adsc_cur_cookies = &this->dsc_cur_cookies;
	dsl_ic3.adsc_wsp_helper = this->adsc_wsp_helper;
	if(!m_iterate_avl_tree(&this->dsc_avl_domains, &dsl_ic3))
		goto LBL_FAIL;
	adsp_iterator->avoc_cur = this->dsc_cur_cookies.m_get_first_element2();
	adsp_iterator->avoc_end = NULL;
	adsp_iterator->avoc_user = NULL;

LBL_FAIL:
    //------------------------------------------------
    // leave lock for all cmas:
    //------------------------------------------------
    m_leave_lock();
    
    return (int)dsc_cur_cookies.m_size();
} // end of ds_ck_mgmt::m_count_cur_cookies


/**
 * \ingroup authlib
 *
 * public function ds_ck_mgmt::m_cur_domain_changed
 * is domain changed to previous element in dsc_cur_cookies?
 *
 * @param[in]   int in_index
 * @return      bool
*/
bool ds_ck_mgmt::m_cur_domain_changed( struct dsd_forward_iterator* adsp_iterator )
{
    // initialize some variables:

    // check input:
	dsd_hvec_elem<ds_cookie>* adsl_cur = ((dsd_hvec_elem<ds_cookie>*)adsp_iterator->avoc_cur);
	if ( adsl_cur == NULL ) {
        return false;
    }
	dsd_hvec_elem<ds_cookie>* adsl_prev = ((dsd_hvec_elem<ds_cookie>*)adsp_iterator->avoc_user);
	if ( adsl_prev == NULL ) {
        return true;
    }

    // get requested cookies:
	ds_cookie& dsl_cur  = adsl_cur->dsc_element;
	ds_cookie& dsl_prev = adsl_prev->dsc_element;
    return !dsl_cur.m_domain_equals( &dsl_prev );
} // end of ds_ck_mgmt::m_cur_domain_changed

/**
 * \ingroup authlib
 *
 * public function ds_ck_mgmt::m_get_cur_cookie
 * get cookie at index from dsc_cur_cookies
 *
 * @param[in]   int         in_index            position in dsc_cur_cookies
 * @return      ds_cookie                       ouput cookie     
*/
bool ds_ck_mgmt::m_cookies_next(struct dsd_forward_iterator* adsp_iterator)
{
	dsd_hvec_elem<ds_cookie>* adsl_cur = ((dsd_hvec_elem<ds_cookie>*)adsp_iterator->avoc_cur);
	if(adsl_cur == NULL)
		return false;
	adsp_iterator->avoc_user = adsl_cur;
	adsp_iterator->avoc_cur = adsl_cur->ads_next;
	return true;
} // end of ds_ck_mgmt::m_get_cur_cookie

/**
 * \ingroup authlib
 *
 * public function ds_ck_mgmt::m_get_cur_cookie
 * get cookie at index from dsc_cur_cookies
 *
 * @param[in]   int         in_index            position in dsc_cur_cookies
 * @return      ds_cookie                       ouput cookie     
*/
const ds_cookie& ds_ck_mgmt::m_get_cur_cookie( struct dsd_forward_iterator* adsp_iterator )
{
	return ((dsd_hvec_elem<ds_cookie>*)adsp_iterator->avoc_cur)->dsc_element;
} // end of ds_ck_mgmt::m_get_cur_cookie

/**
 * \ingroup authlib
 *
 * public function ds_ck_mgmt::m_delete_cookie
 * delete cookie for current user in storage at given position
 *
 * @param[in]   int         in_stor_pos         position in storage
 * @param[in]   const char* ach_cmabase         base cma name
 * @return      bool                            true = success
*/
bool ds_ck_mgmt::m_delete_cookie( const dsd_const_string& ach_cmabase,
								 const dsd_const_string& ach_domain,
								 const dsd_const_string& ach_path,
								 const dsd_const_string& ach_name)
{
	this->m_setup_cma_names(ach_cmabase);

	//------------------------------------------------
    // lock all cmas for writing:
    //------------------------------------------------
    bool bo_ret = m_enter_lock( true );
    if ( bo_ret == false ) {
        return false;
    }

	dsd_avl_cookie_info dsl_cookie_info;
	hl_time_t ill_current_time = this->adsc_wsp_helper->m_cb_get_time();
	bo_ret = this->m_read_avl_tree(ill_current_time);
	if(!bo_ret)
		goto LBL_FAIL;

	dsl_cookie_info.dsc_domain = ach_domain;
	dsl_cookie_info.dsc_path = ach_path;
	dsl_cookie_info.dsc_name = ach_name;
	bo_ret = this->m_delete_avl_cookie(dsl_cookie_info);
	if(!bo_ret)
		goto LBL_FAIL;

	bo_ret = this->m_write_avl_tree();
	if(!bo_ret)
		goto LBL_FAIL;

LBL_FAIL:
    //------------------------------------------------
    // leave lock of cmas:
    //------------------------------------------------
    m_leave_lock();

    if ( bo_ret == true ) {
        //--------------------------------------------
        // clear getcookies cache:
        //--------------------------------------------
        if ( dsc_cache.dsc_cookies.m_empty() == false ) {
            m_clear_cache();
        }
    }

    return bo_ret;
}

/**
 * private function ds_ck_mgmt::m_enter_lock
 * open all cmas (take care of order to avoid deadlocks)
 *
 * @param[in]   bool        bo_write
 * @return      bool                    true = success
*/
bool ds_ck_mgmt::m_enter_lock( bool bo_write )
{
    // initialize some variables:
    bool bol_ret;

    /*
        to avoid possible deadlocks:
        open and close must be happen in reversed order!
    */

	//-------------------------------------------
    // 1. open hash cma:
    //-------------------------------------------
    bol_ret = m_open_cma( &dsc_hash_cma, bo_write );
    if ( bol_ret == false ) {
        return false;
    }

	return bol_ret;
} // end of ds_ck_mgmt::m_enter_lock


/**
 * private function ds_ck_mgmt::m_leave_lock
 * close all cmas (take care of order to avoid deadlocks)
 *
 * @return      bool                    true = success
*/
bool ds_ck_mgmt::m_leave_lock()
{
    /*
        to avoid possible deadlocks:
        open and close must be happen in reversed order!
    */

	return m_close_cma( &dsc_hash_cma );
} // end of ds_ck_mgmt::m_leave_lock

/**
 * function ds_ck_mgmt::m_clear_cache
 * clear get cookie cache
*/
void ds_ck_mgmt::m_clear_cache()
{
    dsc_cache.dsc_domain.m_reset();
    dsc_cache.dsc_path.m_reset();

#if 0
    for ( size_t in_pos = 0; in_pos < dsc_cache.dsc_cookies.m_size(); in_pos++ ) {
        dsc_cache.dsc_cookies[in_pos].m_init( adsc_wsp_helper );
    }
#endif
    dsc_cache.dsc_cookies.m_clear();
} // end of ds_ck_mgmt::m_clear_cache

bool ds_ck_mgmt::m_insert_avl_cookie(dsd_avl_cookie_info& rdsp_cookie_info) 
{
	//m_reverse_domain(ads_cookie->m_get_domain(), ds_host);
	// TODO:
	struct dsd_avl_domain dsl_avl_domain1;
	dsl_avl_domain1.dsc_domain = rdsp_cookie_info.dsc_domain;
	struct dsd_htree1_avl_work dsl_avl_work1;
	BOOL bol_res = m_htree1_avl_search(
		NULL, &this->dsc_avl_domains.dsc_avl_domains,
		&dsl_avl_work1, &dsl_avl_domain1.dsc_avl_entry);
	if(!bol_res)
		return false;
	struct dsd_avl_domain* adsl_avl_domain1;
	// Not found?
	if(dsl_avl_work1.adsc_found == NULL) {
		adsl_avl_domain1 = (struct dsd_avl_domain*)adsc_wsp_helper->m_cb_get_memory(
			sizeof(struct dsd_avl_domain) + dsl_avl_domain1.dsc_domain.m_get_len(), false);
		if(adsl_avl_domain1 == NULL)
			return false;
		memcpy((adsl_avl_domain1+1), dsl_avl_domain1.dsc_domain.m_get_start(), dsl_avl_domain1.dsc_domain.m_get_len());
		adsl_avl_domain1->dsc_domain = dsd_const_string((const char*)(adsl_avl_domain1+1), dsl_avl_domain1.dsc_domain.m_get_len());
		adsl_avl_domain1->inc_num_paths = 0;
		m_htree1_avl_init(NULL, &adsl_avl_domain1->dsc_avl_paths, &m_avl_cmp_paths);
		bol_res = m_htree1_avl_insert(NULL,
			&this->dsc_avl_domains.dsc_avl_domains,
			&dsl_avl_work1, &adsl_avl_domain1->dsc_avl_entry);
		if(!bol_res)
			return false;
		this->dsc_avl_domains.inc_serialized_size += HL_AVL_DOMAIN_SERIALIZED_SIZE(adsl_avl_domain1);
		this->dsc_avl_domains.inc_num_domains++;
	}
	else {
		adsl_avl_domain1 = (struct dsd_avl_domain*)dsl_avl_work1.adsc_found;
	}
	struct dsd_avl_path dsl_avl_path1;
	dsl_avl_path1.dsc_path = rdsp_cookie_info.dsc_path;
	bol_res = m_htree1_avl_search(
		NULL, &adsl_avl_domain1->dsc_avl_paths,
		&dsl_avl_work1, &dsl_avl_path1.dsc_avl_entry);
	if(!bol_res)
		return false;
	struct dsd_avl_path* adsl_avl_path1;
	// Not found?
	if(dsl_avl_work1.adsc_found == NULL) {
		adsl_avl_path1 = (struct dsd_avl_path*)adsc_wsp_helper->m_cb_get_memory(
			sizeof(struct dsd_avl_path) + dsl_avl_path1.dsc_path.m_get_len(), false);
		if(adsl_avl_path1 == NULL)
			return false;
		memcpy((adsl_avl_path1+1), dsl_avl_path1.dsc_path.m_get_start(), dsl_avl_path1.dsc_path.m_get_len());
		adsl_avl_path1->dsc_path = dsd_const_string((const char*)(adsl_avl_path1+1), dsl_avl_path1.dsc_path.m_get_len());
		adsl_avl_path1->inc_num_cookies = 0;
		m_htree1_avl_init(NULL, &adsl_avl_path1->dsc_avl_cookies, &m_avl_cmp_cookies);
		bol_res = m_htree1_avl_insert(NULL,
			&adsl_avl_domain1->dsc_avl_paths,
			&dsl_avl_work1, &adsl_avl_path1->dsc_avl_entry);
		if(!bol_res)
			return false;
		this->dsc_avl_domains.inc_serialized_size += HL_AVL_PATH_SERIALIZED_SIZE(adsl_avl_path1);
		adsl_avl_domain1->inc_num_paths++;
	}
	else {
		adsl_avl_path1 = (struct dsd_avl_path*)dsl_avl_work1.adsc_found;
	}

#if 0
	{
		struct dsd_htree1_avl_work dsl_avl_work3;
		bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_path1->dsc_avl_cookies, &dsl_avl_work3, TRUE);
		if(!bol_res)
			return false;
		int inl_num_cookies = 0;
		while(dsl_avl_work3.adsc_found != NULL) {
			inl_num_cookies++;
			struct dsd_avl_cookie* adsl_avl_cookie1 = (struct dsd_avl_cookie*)dsl_avl_work3.adsc_found;
			bool bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_path1->dsc_avl_cookies, &dsl_avl_work3, FALSE);
			if(!bol_res)
				return false;
		}
		if(inl_num_cookies != adsl_avl_path1->inc_num_cookies)
			return false;
	}
#endif

	struct dsd_avl_cookie dsl_avl_cookie1;
	dsl_avl_cookie1.dsc_name = rdsp_cookie_info.dsc_name;
	bol_res = m_htree1_avl_search(
		NULL, &adsl_avl_path1->dsc_avl_cookies,
		&dsl_avl_work1, &dsl_avl_cookie1.dsc_avl_entry);
	if(!bol_res)
		return false;
	// Does exist?
	struct dsd_avl_cookie* adsl_avl_cookie2 = (struct dsd_avl_cookie*)dsl_avl_work1.adsc_found;
	if(adsl_avl_cookie2 != NULL) {
		struct dsd_avl_cookie* adsl_avl_cookie1 = (struct dsd_avl_cookie*)dsl_avl_work1.adsc_found;
		bol_res = m_htree1_avl_delete(NULL, &adsl_avl_path1->dsc_avl_cookies, &dsl_avl_work1);
		if(!bol_res)
			return false;
		adsl_avl_path1->inc_num_cookies--;
		this->dsc_avl_domains.inc_serialized_size -= HL_AVL_COOKIE_SERIALIZED_SIZE(adsl_avl_cookie1);
		adsc_wsp_helper->m_cb_free_memory(adsl_avl_cookie1);
		bol_res = m_htree1_avl_search(
			NULL, &adsl_avl_path1->dsc_avl_cookies,
			&dsl_avl_work1, &dsl_avl_cookie1.dsc_avl_entry);
		if(!bol_res)
			return false;
	}
	struct dsd_avl_cookie* adsl_avl_cookie1 = (struct dsd_avl_cookie*)adsc_wsp_helper->m_cb_get_memory(
		sizeof(struct dsd_avl_cookie) + dsl_avl_cookie1.dsc_name.m_get_len() + rdsp_cookie_info.dsc_data.m_get_len(), false);
	if(adsl_avl_path1 == NULL)
		return false;
	char* achl_tmp = (char*)(adsl_avl_cookie1+1);
	memcpy(achl_tmp, dsl_avl_cookie1.dsc_name.m_get_start(), dsl_avl_cookie1.dsc_name.m_get_len());
	adsl_avl_cookie1->dsc_name = dsd_const_string(achl_tmp, dsl_avl_cookie1.dsc_name.m_get_len());
	achl_tmp += dsl_avl_cookie1.dsc_name.m_get_len();
	memcpy(achl_tmp, rdsp_cookie_info.dsc_data.m_get_ptr(), rdsp_cookie_info.dsc_data.m_get_len());
	adsl_avl_cookie1->dsc_data = dsd_const_string(achl_tmp, rdsp_cookie_info.dsc_data.m_get_len());
	adsl_avl_cookie1->boc_secure = rdsp_cookie_info.boc_secure;
	adsl_avl_cookie1->boc_http_only = rdsp_cookie_info.boc_http_only;
	adsl_avl_cookie1->boc_domain = rdsp_cookie_info.boc_domain;
	adsl_avl_cookie1->ill_expires = rdsp_cookie_info.ill_expires;
	bol_res = m_htree1_avl_insert(NULL,
		&adsl_avl_path1->dsc_avl_cookies,
		&dsl_avl_work1, &adsl_avl_cookie1->dsc_avl_entry);
	if(!bol_res)
		return false;
	adsl_avl_path1->inc_num_cookies++;
	this->dsc_avl_domains.inc_serialized_size += HL_AVL_COOKIE_SERIALIZED_SIZE(adsl_avl_cookie1);
	this->dsc_avl_domains.boc_changed = true;
#if 0
	struct dsd_htree1_avl_work dsl_avl_work3;
	bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_path1->dsc_avl_cookies, &dsl_avl_work3, TRUE);
	if(!bol_res)
		return false;
	int inl_num_cookies = 0;
	while(dsl_avl_work3.adsc_found != NULL) {
		inl_num_cookies++;
		struct dsd_avl_cookie* adsl_avl_cookie1 = (struct dsd_avl_cookie*)dsl_avl_work3.adsc_found;
		bool bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_path1->dsc_avl_cookies, &dsl_avl_work3, FALSE);
		if(!bol_res)
			return false;
	}
	if(inl_num_cookies != adsl_avl_path1->inc_num_cookies)
		return false;
#endif
	return true;
}

bool ds_ck_mgmt::m_delete_avl_cookie(dsd_avl_cookie_info& rdsp_cookie_info) 
{
	//m_reverse_domain(ads_cookie->m_get_domain(), ds_host);
	// TODO:
	struct dsd_avl_domain dsl_avl_domain1;
	dsl_avl_domain1.dsc_domain = rdsp_cookie_info.dsc_domain;
	struct dsd_htree1_avl_work dsl_avl_work1;
	BOOL bol_res = m_htree1_avl_search(
		NULL, &this->dsc_avl_domains.dsc_avl_domains,
		&dsl_avl_work1, &dsl_avl_domain1.dsc_avl_entry);
	if(!bol_res)
		return false;
	// Not found?
	if(dsl_avl_work1.adsc_found == NULL) {
		return false;
	}
	struct dsd_avl_domain* adsl_avl_domain1 = (struct dsd_avl_domain*)dsl_avl_work1.adsc_found;
	struct dsd_avl_path dsl_avl_path1;
	dsl_avl_path1.dsc_path = rdsp_cookie_info.dsc_path;
	bol_res = m_htree1_avl_search(
		NULL, &adsl_avl_domain1->dsc_avl_paths,
		&dsl_avl_work1, &dsl_avl_path1.dsc_avl_entry);
	if(!bol_res)
		return false;
	// Not found?
	if(dsl_avl_work1.adsc_found == NULL) {
		return false;
	}
	struct dsd_avl_path* adsl_avl_path1 = (struct dsd_avl_path*)dsl_avl_work1.adsc_found;
	struct dsd_avl_cookie dsl_avl_cookie1;
	dsl_avl_cookie1.dsc_name = rdsp_cookie_info.dsc_name;
	bol_res = m_htree1_avl_search(
		NULL, &adsl_avl_path1->dsc_avl_cookies,
		&dsl_avl_work1, &dsl_avl_cookie1.dsc_avl_entry);
	if(!bol_res)
		return false;
	// Not found?
	if(dsl_avl_work1.adsc_found == NULL) {
		return false;
	}
	struct dsd_avl_cookie* adsl_avl_cookie1 = (struct dsd_avl_cookie*)dsl_avl_work1.adsc_found;
	bol_res = m_htree1_avl_delete(NULL, &adsl_avl_path1->dsc_avl_cookies, &dsl_avl_work1);
	if(!bol_res)
		return false;
	adsl_avl_path1->inc_num_cookies--;
	this->dsc_avl_domains.inc_serialized_size -= HL_AVL_COOKIE_SERIALIZED_SIZE(adsl_avl_cookie1);
	this->dsc_avl_domains.boc_changed = true;
	adsc_wsp_helper->m_cb_free_memory(adsl_avl_cookie1);
	return true;
}

bool ds_ck_mgmt::m_read_avl_tree(hl_time_t ilp_current_time)
{
	if(!this->m_free_avl_tree())
		return false;
	struct dsd_buffered_reader dsl_br;
	dsl_br.achc_cur = this->dsc_hash_cma.achc_start;
	dsl_br.achc_end = this->dsc_hash_cma.achc_end;
	if((dsl_br.achc_end-dsl_br.achc_cur) <= 4)
		return true;
	unsigned int unl_num_domains;
	if(!dsl_br.m_read_uint32_le(unl_num_domains))
		return false;
	for(unsigned int unl_d=0; unl_d<unl_num_domains; unl_d++) {
		dsd_const_string dsl_domain;
		if(!dsl_br.m_read_const_string_with_len(dsl_domain))
			return false;
		unsigned int unl_num_paths;
		if(!dsl_br.m_read_uint32_le(unl_num_paths))
			return false;
		for(unsigned int unl_p=0; unl_p<unl_num_paths; unl_p++) {
			dsd_const_string dsl_path;
			if(!dsl_br.m_read_const_string_with_len(dsl_path))
				return false;
			unsigned int unl_num_cookies;
			if(!dsl_br.m_read_uint32_le(unl_num_cookies))
				return false;
			for(unsigned int unl_c=0; unl_c<unl_num_cookies; unl_c++) {
				dsd_const_string dsl_name;
				if(!dsl_br.m_read_const_string_with_len(dsl_name))
					return false;
				dsd_const_string dsl_value;
				if(!dsl_br.m_read_const_string_with_len(dsl_value))
					return false;
				HL_LONGLONG ill_expires;
				if(!dsl_br.m_read_uint64_le(ill_expires))
					return false;
				unsigned char ucl_secure;
				if(!dsl_br.m_read_uint8(ucl_secure))
					return false;
				unsigned char ucl_http_only;
				if(!dsl_br.m_read_uint8(ucl_http_only))
					return false;
				unsigned char ucl_domain;
				if(!dsl_br.m_read_uint8(ucl_domain))
					return false;
				dsd_avl_cookie_info dsl_cookie_info;
				dsl_cookie_info.dsc_name = dsl_name;
				dsl_cookie_info.dsc_data = dsl_value;
				dsl_cookie_info.dsc_path = dsl_path;
				dsl_cookie_info.dsc_domain = dsl_domain;
				dsl_cookie_info.ill_expires = ill_expires;
				dsl_cookie_info.boc_secure = ucl_secure != 0;
				dsl_cookie_info.boc_http_only = ucl_http_only != 0;
				dsl_cookie_info.boc_domain = ucl_domain != 0;
				if(ill_expires >= 0 && ill_expires < ilp_current_time) {
					this->dsc_avl_domains.boc_changed = true;
					continue;
				}
				if(!this->m_insert_avl_cookie(dsl_cookie_info))
					return false;
			}
		}
	}

	return true;
}

struct dsd_iterate_avl_call2 : public dsd_iterate_avl_call {
	struct dsd_buffered_writer* adsl_bw;
};

static bool m_call_write_avl_tree(struct dsd_iterate_avl_call* adsp_call) {
	struct dsd_iterate_avl_call2* adsl_call2 = (struct dsd_iterate_avl_call2*)adsp_call;
	struct dsd_buffered_writer* adsl_bw = adsl_call2->adsl_bw;
	switch(adsp_call->inc_depth) {
	case 0:
		return adsl_bw->m_write_uint32_le(adsp_call->adsl_avl_domains->inc_num_domains);
	case 1: {
		struct dsd_avl_domain* adsl_avl_domain1 = (struct dsd_avl_domain*)adsp_call->adsl_avl_domain1;
		if(!adsl_bw->m_write_const_string_with_len(adsl_avl_domain1->dsc_domain))
			return false;
		if(!adsl_bw->m_write_uint32_le(adsl_avl_domain1->inc_num_paths))
			return false;
		return true;
	}
	case 2: {
		struct dsd_avl_path* adsl_avl_path1 = (struct dsd_avl_path*)adsp_call->adsl_avl_path1;
		if(!adsl_bw->m_write_const_string_with_len(adsl_avl_path1->dsc_path))
			return false;
		if(!adsl_bw->m_write_uint32_le(adsl_avl_path1->inc_num_cookies))
			return false;
		return true;
	}
	case 3: {
		struct dsd_avl_cookie* adsl_avl_cookie1 = (struct dsd_avl_cookie*)adsl_call2->adsl_avl_cookie1;
		if(!adsl_bw->m_write_const_string_with_len(adsl_avl_cookie1->dsc_name))
			return false;
		if(!adsl_bw->m_write_const_string_with_len(adsl_avl_cookie1->dsc_data))
			return false;
		if(!adsl_bw->m_write_uint64_le(adsl_avl_cookie1->ill_expires))
			return false;
		if(!adsl_bw->m_write_uint8(adsl_avl_cookie1->boc_secure))
			return false;
		if(!adsl_bw->m_write_uint8(adsl_avl_cookie1->boc_http_only))
			return false;
		if(!adsl_bw->m_write_uint8(adsl_avl_cookie1->boc_domain))
			return false;
		return true;
	}
	default:
		return false;
	}
}

bool ds_ck_mgmt::m_write_avl_tree()
{
	if(!this->dsc_avl_domains.boc_changed)
		return true;
	int inl_size_needed = this->dsc_avl_domains.inc_serialized_size;
	if(!m_enlarge_cma(&dsc_hash_cma, inl_size_needed))
		return false;
	struct dsd_buffered_writer dsl_bw;
	dsl_bw.achc_cur = this->dsc_hash_cma.achc_start;
	dsl_bw.achc_end = this->dsc_hash_cma.achc_end;
	struct dsd_iterate_avl_call2 dsl_ic2;
	dsl_ic2.adsl_bw = &dsl_bw;
	dsl_ic2.m_call = &m_call_write_avl_tree;
	bool bol_res = m_iterate_avl_tree(&this->dsc_avl_domains, &dsl_ic2);
	if(!bol_res)
		return false;
	int inl_size_written = dsl_bw.achc_cur-this->dsc_hash_cma.achc_start;
	if(inl_size_written != inl_size_needed)
		return false;
	return true;
}

bool ds_ck_mgmt::m_free_avl_tree()
{
	struct dsd_htree1_avl_work dsl_avl_work1;
	BOOL bol_res = m_htree1_avl_getnext(NULL, &this->dsc_avl_domains.dsc_avl_domains, &dsl_avl_work1, TRUE);
	if(!bol_res)
		return false;
	// Required to release all elements at the end
	dsd_hl_slist<dsd_my_avl_tree_entry, offsetof(dsd_my_avl_tree_entry, adsc_next)> dsl_tofree_list;
	HL_ASSERT_NO_OVERLAP(dsd_avl_domain, dsc_avl_entry);
	HL_ASSERT_NO_OVERLAP(dsd_avl_path, dsc_avl_entry);
	HL_ASSERT_NO_OVERLAP(dsd_avl_cookie, dsc_avl_entry);
	while(dsl_avl_work1.adsc_found != NULL) {
		struct dsd_avl_domain* adsl_avl_domain1 = (struct dsd_avl_domain*)dsl_avl_work1.adsc_found;
		struct dsd_htree1_avl_work dsl_avl_work2;
		bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_domain1->dsc_avl_paths, &dsl_avl_work2, TRUE);
		if(!bol_res)
			return false;
		while(dsl_avl_work2.adsc_found != NULL) {
			struct dsd_avl_path* adsl_avl_path1 = (struct dsd_avl_path*)dsl_avl_work2.adsc_found;
			struct dsd_htree1_avl_work dsl_avl_work3;
			bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_path1->dsc_avl_cookies, &dsl_avl_work3, TRUE);
			if(!bol_res)
				return false;
			while(dsl_avl_work3.adsc_found != NULL) {
				struct dsd_avl_cookie* adsl_avl_cookie1 = (struct dsd_avl_cookie*)dsl_avl_work3.adsc_found;
				bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_path1->dsc_avl_cookies, &dsl_avl_work3, FALSE);
				if(!bol_res)
					return false;
				dsl_tofree_list.m_append((dsd_my_avl_tree_entry*)adsl_avl_cookie1);
				//this->adsc_wsp_helper->m_cb_free_memory(adsl_avl_cookie1);
			}
			bol_res = m_htree1_avl_getnext(NULL, &adsl_avl_domain1->dsc_avl_paths, &dsl_avl_work2, FALSE);
			if(!bol_res)
				return false;
			dsl_tofree_list.m_append((dsd_my_avl_tree_entry*)adsl_avl_path1);
			//this->adsc_wsp_helper->m_cb_free_memory(adsl_avl_path1);
		}
		bol_res = m_htree1_avl_getnext(NULL, &this->dsc_avl_domains.dsc_avl_domains, &dsl_avl_work1, FALSE);
		if(!bol_res)
			return false;
		dsl_tofree_list.m_append((dsd_my_avl_tree_entry*)adsl_avl_domain1);
		//this->adsc_wsp_helper->m_cb_free_memory(adsl_avl_domain1);
	}
	// Release all elements (ticket #51863)
	dsd_my_avl_tree_entry* adsl_tmp;
	while((adsl_tmp=dsl_tofree_list.m_remove_first()) != NULL) {
		this->adsc_wsp_helper->m_cb_free_memory(adsl_tmp);
	}

	this->dsc_avl_domains.inc_num_domains = 0;
	m_htree1_avl_init(NULL, &dsc_avl_domains.dsc_avl_domains, &m_avl_cmp_domains);
	this->dsc_avl_domains.inc_serialized_size = 4;
	this->dsc_avl_domains.boc_changed = false;
	return true;
}

bool ds_ck_mgmt::m_save_cookie_begin() {
	 //----------------------------------------------------
    // 1. open all cmas for writing:
    //----------------------------------------------------
    bool bo_ret = m_enter_lock( true );
    if ( bo_ret == false ) {
        return false;
    }
	 hl_time_t ill_current_time = this->adsc_wsp_helper->m_cb_get_time();
	 bo_ret = this->m_read_avl_tree(ill_current_time);
	 if(!bo_ret) {
		 this->m_free_avl_tree();
	 }
	 return true;
}

bool ds_ck_mgmt::m_save_cookie_end() {
	 bool bo_ret = this->m_write_avl_tree();
	 if(!bo_ret)
		 goto LBL_FAIL;

LBL_FAIL:
	 //------------------------------------------------
    // 6. leave write lock for all cmas:
    //------------------------------------------------
    if(!m_leave_lock())
		 return false;
	 //------------------------------------------------
    // 7. do trace:
    //------------------------------------------------
    if ( boc_trace == true ) {
        //--------------------------------------------
        // 7.2 enter read lock for all cmas:
        //--------------------------------------------
        bo_ret = m_enter_lock( false );
        if ( bo_ret == false ) {
            return true; // don't return false for tracing error!
        }

        //--------------------------------------------
        // 7.3 trace our cookie tables:
        //--------------------------------------------
        m_create_trace();
        
        //--------------------------------------------
        // 7.4 leave read lock for all cmas
        //--------------------------------------------
        m_leave_lock();
    }
	 return bo_ret;
}

/**
 * function ds_ck_mgmt::m_save_cookie
 * save a single cookie inside cma
 *
 * @param[in]   ds_cookie*   ads_cookie     pointer to cookie class
 * @return      bool                        true = success
*/
bool ds_ck_mgmt::m_save_cookie( ds_cookie* ads_cookie )
{
	if ( boc_trace == true ) {
        //--------------------------------------------
        // 7.1 trace saved cookie:
        //--------------------------------------------
        m_trace_cookie( ads_cookie );
	}

	hl_time_t ill_current_time = this->adsc_wsp_helper->m_cb_get_time();
	dsd_avl_cookie_info dsl_cookie_info;
	dsl_cookie_info.dsc_domain = ads_cookie->m_get_domain();
	dsl_cookie_info.dsc_path = ads_cookie->m_get_path();
	const char* achl_value;
	int inl_length;
	ads_cookie->m_get_name(&achl_value, &inl_length);
	dsl_cookie_info.dsc_name = dsd_const_string(achl_value, inl_length);
	ads_cookie->m_get_value(&achl_value, &inl_length);
	dsl_cookie_info.dsc_data = dsd_const_string(achl_value, inl_length);
	dsl_cookie_info.boc_secure = ads_cookie->m_is_secure();
	dsl_cookie_info.boc_http_only = ads_cookie->m_is_httponly();
	dsl_cookie_info.boc_domain = ads_cookie->m_is_domain();
	dsl_cookie_info.ill_expires = ads_cookie->m_is_discard() ? -1 : ads_cookie->m_get_expires();
	if(dsl_cookie_info.ill_expires < 0 || dsl_cookie_info.ill_expires >= ill_current_time) {
		bool bo_ret = this->m_insert_avl_cookie(dsl_cookie_info);
		return bo_ret;
	}
	this->m_delete_avl_cookie(dsl_cookie_info);
	return true;
} // end of ds_ck_mgmt::m_save_cookie


/**
 * function ds_ck_mgmt::m_create_trace
*/
void ds_ck_mgmt::m_create_trace()
{
#if !SM_USE_NEW_COOKIE_MANAGEMENT
	// intialize some variables:
    FILE*      a_file;
    bool       bo_ret;
    ds_hstring ds_file   (adsc_wsp_helper);
    ds_hstring ds_content(adsc_wsp_helper);

    //-------------------------------------------
    // build trace path:
    //-------------------------------------------
    ds_trace_path.m_init( adsc_wsp_helper );
    if ( ds_trace_path.m_get_len() < 1 ) {
        char rch_path[_MAX_PATH];
        bo_ret = adsc_wsp_helper->m_get_wsp_path( &rch_path[0], _MAX_PATH );
        if ( bo_ret == false ) {
            return;
        }
        ds_trace_path.m_write_zeroterm( rch_path );
        ds_trace_path.m_write( LOGFILE_PATH );
    }

    //-------------------------------------------
    // trace hash table:
    //-------------------------------------------
    ds_file.m_set( ds_trace_path );
    ds_file.m_write( CK_HASH_TABLE_FILE );
    a_file = fopen( ds_file.m_get_ptr(), "w" );
    if ( a_file != NULL ) {
        ds_content = m_get_hash_overview();
        fprintf( a_file, "%s", ds_content.m_get_ptr() );
        fclose( a_file );
    }

    //-------------------------------------------
    // trace mgmt table:
    //-------------------------------------------
    ds_file.m_set( ds_trace_path );
    ds_file.m_write( CK_MGMT_TABLE_FILE );
    a_file = fopen( ds_file.m_get_ptr(), "w" );
    if ( a_file != NULL ) {
        ds_content = m_get_mgmt_overview();
        fprintf( a_file, "%s", ds_content.m_get_ptr() );
        fclose( a_file );
    }

    //-------------------------------------------
    // trace storage table:
    //-------------------------------------------
    ds_file.m_set( ds_trace_path );
    ds_file.m_write( CK_MEM_TABLE_FILE );
    a_file = fopen( ds_file.m_get_ptr(), "w" );
    if ( a_file != NULL ) {
        ds_content = m_get_stor_overview();
        fprintf( a_file, "%s", ds_content.m_get_ptr() );
        fclose( a_file );
    }
#endif
} // end of ds_ck_mgmt::m_create_trace


/**
 * function ds_ck_mgmt::m_trace_cookie
 *
 * @param[in]   ds_cookie* ads_cookie
*/
void ds_ck_mgmt::m_trace_cookie( ds_cookie* ads_cookie )
{
    // intialize some variables:
    FILE*      a_file;
    bool       bo_ret;
    ds_hstring ds_file   (adsc_wsp_helper);

    //-------------------------------------------
    // build trace path:
    //-------------------------------------------
    ds_trace_path.m_init( adsc_wsp_helper );
    if ( ds_trace_path.m_get_len() < 1 ) {
        char rch_path[_MAX_PATH];
        bo_ret = adsc_wsp_helper->m_get_wsp_path( &rch_path[0], _MAX_PATH );
        if ( bo_ret == false ) {
            return;
        }
        ds_trace_path.m_write_zeroterm( rch_path );
        ds_trace_path.m_write( LOGFILE_PATH );
    }

    //-------------------------------------------
    // trace cookie:
    //-------------------------------------------
    ds_file.m_set( ds_trace_path );
    ds_file.m_write( CK_COOKIE_IN_FILE );
    a_file = fopen( ds_file.m_get_ptr(), "a" );
    if ( a_file != NULL ) {
        fprintf( a_file, "-----------------------------------------------------------\n" );
        dsd_const_string dsl_cookie(ads_cookie->m_get_cookie());
        fprintf( a_file, "%.*s\n", (int)dsl_cookie.m_get_len(), dsl_cookie.m_get_ptr() );
        dsd_const_string dsl_domain(ads_cookie->m_get_domain());
        fprintf( a_file, "Domain: %.*s\n", (int)dsl_domain.m_get_len(), dsl_domain.m_get_ptr() );
        dsd_const_string dsl_path(ads_cookie->m_get_path());
        fprintf( a_file, "Path:   %.*s\n", (int)dsl_path.m_get_len(), dsl_path.m_get_ptr() );
        if ( ads_cookie->m_is_discard() ) {
            fprintf( a_file, "delete at logout\n" );
        } else {
            fprintf( a_file, "%lld\n", ads_cookie->m_get_expires() );
        }
        if ( ads_cookie->m_is_secure() ) {
            fprintf( a_file, "secure connections only\n" );
        }
        fclose( a_file );
    }
} // end of ds_ck_mgmt::m_trace_cookie

/**
 * function ds_ck_mgmt::m_get_parent_domains
 *
 * @param[in]   const char*             ach_domain  incoming domain
 * @param[in]   int                     in_len      length of domain
 * @return      ds_hvector<ds_hstring>              parent domain (including input itself!)
*/
void ds_ck_mgmt::m_get_parent_domains( ds_hvector_btype<dsd_const_string>& rdsp_domains, const dsd_const_string& rdsp_domain )
{
    // intialize some variables:
    int in_pos = rdsp_domain.m_index_of( "." );
    if ( in_pos < 0 || m_is_ineta(rdsp_domain.m_get_start(), rdsp_domain.m_get_len()) ) {
        rdsp_domains.m_add( rdsp_domain );
        return;
    }

    if ( rdsp_domain[0] != '.' ) {
        rdsp_domains.m_add( rdsp_domain );
    }

    // do not add the last entry e.g. ".de":
    while(true) {
        int inl_next = rdsp_domain.m_index_of( in_pos + 1, "." );
        if(inl_next < 0)
            break;
        rdsp_domains.m_add( rdsp_domain.m_substring(in_pos + 1) );
        in_pos = inl_next;
    }

    return;
} // end of ds_ck_mgmt::m_get_parent_domains


/**
 * function ds_ck_mgmt::m_get_parent_paths
 *
 * @param[in]   const char*             ach_path    incoming path
 * @param[in]   int                     in_len      length of path
 * @return      ds_hvector<ds_hstring>              parent paths (including input itself!)
*/
void ds_ck_mgmt::m_get_parent_paths( ds_hvector_btype<dsd_const_string>& rdsp_paths, const dsd_const_string& rdsp_path )
{
    // intialize some variables:
    if(rdsp_path.m_get_len() >= 2) {
		rdsp_paths.m_add(rdsp_path);
		int in_pos = rdsp_path.m_last_index_of( "/" );
		while ( in_pos > 0 ) {
			rdsp_paths.m_add( rdsp_path.m_substring( 0, in_pos+1 ) );
			if ( in_pos <= 1 ) {
				break;
			}

#ifdef B140402
			in_pos = rdsp_path.m_last_index_of( in_pos - 1, "/"  );
#else
			in_pos = rdsp_path.m_last_index_of( in_pos, "/"  );
#endif
		}//while
	}
	rdsp_paths.m_add("/");
    return;
} // end of ds_ck_mgmt::m_get_parent_paths

/**
 * private function ds_ck_mgmt::m_is_ineta
 * check if given string is an IP-Address
 *
 * @param[in]   const char* ach_domain
 * @param[in]   int         in_len_domain
 * @return      bool
*/
bool ds_ck_mgmt::m_is_ineta( const char* ach_domain, int in_len_domain )
{
    // initialize some variables:
    bool bo_return = true;                      // return value
    bool bo_ipv6   = false;                     // ipv6 detection?
    int  in_pos;                                // current pos in input
    int  in_dots   = 0;                         // count dots
    int  in_nums   = 0;                         // count numbers between dots
    int  in_value;

    // IPv4 should look like this: 123.456.789.012
    // IPv6 2001:0db8:85a3::1319:8a2e:0370:7344
    // we try to autoselect IPv4 or IPv6 validation
    for ( in_pos = 0; in_pos < in_len_domain; in_pos++ ) {
        if ( ach_domain[in_pos] == ':' ) {
            bo_ipv6 = true;
            break;
        }
    }

    if ( bo_ipv6 == false ) {
        //----------------------------------
        // do IPv4 validation:
        //----------------------------------
        for ( in_pos = 0; in_pos < in_len_domain; in_pos++ ) {
            switch ( ach_domain[in_pos] ) {
                case '.':
                    in_dots++;
                    if (    in_dots < 4     /* IPv4 has exact 3 dots      */
                         && in_nums < 4     /* max 3 numbers between dots */
                         && in_nums > 0     /* min 1 number between dots  */ )
                    {
                        in_value = atoi(&ach_domain[in_pos - in_nums]);
                        if ( in_value < 0 || in_value > 255 ) {
                            break;
                        }
                        in_nums = 0;
                        continue;
                    }
                    break; // otherwise error
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    in_nums++;
                    if ( in_nums < 4 /* max 3 numbers between dots */ ) {
                        continue;
                    }
                    break; // otherwise error
                default:
                    // other char as number or '.' -> invalid address
                    break; 
            }
            bo_return = false; // an error occurred
            break;
        }
    } else {
        //----------------------------------
        // do IPv6 validation:
        //----------------------------------
        bool bo_bracket = false;
        int  in_two_dots  = 0;
        
        for ( in_pos = 0; in_pos < in_len_domain; in_pos++ ) {
            switch ( ach_domain[in_pos] ) {
                case '[':
                    if (    in_pos == 0     /* bracket must be first sign */
                         && !bo_bracket     /* only one bracket           */ ) {
                        bo_bracket = true;
                        continue;
                    }
                    break; // otherwise error
                case ']':
                    if (    bo_bracket      /* '[' occurred               */
                         && in_dots < 8     /* max 7 dots                 */
                         && in_dots > 1     /* min 2 dots                 */ ) {
                        in_dots = 0;
                        in_nums = 0;
                        continue;
                    }
                    break; // otherwise error
                case ':':
                    in_dots++;
                    if (    bo_bracket
                         && in_two_dots < 2 /* "::" is allowed only once  */
                         && in_dots < 8     /* max 7 dots                 */
                         && in_nums < 5     /* max 4 numbers between dots */ )
                    {
                        if ( in_nums == 0 ) {
                            in_two_dots++;
                        }
                        in_nums = 0;
                        continue;
                    }
                    break; // otherwise error
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    if ( bo_bracket      /* a bracket occured          */ ) {
                        in_nums++;
                        continue;
                    }
                case 'a':
                case 'b':
                case 'c':
                case 'd':
                case 'e':
                case 'f':
                case 'A':
                case 'B':
                case 'C':
                case 'D':
                case 'E':
                case 'F':
                    in_nums++;
                    if (    bo_bracket  /* a bracket occured          */
                         && in_nums < 5 /* max 4 numbers between dots */ ) {
                        continue;
                    }
                    break; // otherwise error
                default:
                    // other char as number, '[' or ':' -> invalid address
                    break;
            }
            bo_return = false; // an error occurred
            break;
        }
    }
    return bo_return;
} // end of ds_ck_mgmt::m_is_ineta


/**
 * function ds_ck_mgmt::m_get_single_cookie
 * "Set-Cookie:" can contain more than one cookie, seperatet by ","
 *
 * @param[in]       const char* ach_cookie
 * @param[in]       int         in_len_cookie
 * @param[in]       int         in_pos
 * @param[in/out]   int*        ain_single_len
*/
void ds_ck_mgmt::m_get_single_cookie( const char* ach_cookie, int in_len_cookie,
                                      int in_pos, int* ain_single_len            )
{
    int in_start_pos = in_pos;
    int in_state = 0;

    for ( ; in_pos < in_len_cookie; in_pos++ ) {
        switch( in_state ) {
            case 0:
                switch ( ach_cookie[in_pos] ) {
                    case ',':
                        break;
                    case '=':
                        in_state = 1;
                        continue;
                    case '\'':
                        in_state = 2;
                        continue;
                    case '"':
                        in_state = 3;
                        continue;
                    default:
                        continue;
                }
                break;
            case 1:
                switch ( ach_cookie[in_pos] ) {
                    case ';':
                        in_state = 0;
                        break;
                    default:
                        break;
                }
                continue;
            case 2:
                switch ( ach_cookie[in_pos] ) {
                    case '\'':
                        in_state = 0;
                        break;
                    default:
                        break;
                }
                continue;
            case 3:
                switch ( ach_cookie[in_pos] ) {
                    case '"':
                        in_state = 0;
                        break;
                    default:
                        break;
                }
                continue;
        }
        break;
    }
    *ain_single_len = in_pos - in_start_pos;
} // end of ds_ck_mgmt::m_get_single_cookie


/**
 * function ds_ck_mgmt::m_get_single_xml_cookie
 *
 * @param[in]   const char* ach_xml
 * @param[in]   int         in_len_xml
 * @param[in]   int*        ain_pos
 * @param[in]   int*        ain_single_len
*/
void ds_ck_mgmt::m_get_single_xml_cookie( const char* ach_xml, int in_len_xml,
                                          int* ain_pos,        int* ain_single_len )
{
    // initialize some variables:
    enum iedl_state {
        iedl_search_start,
        iedl_search_end
    };
    iedl_state ien_state   = iedl_search_start;
    int        in_test_pos = 0;
    int        in_pos      = *ain_pos;

    // reset length:
    *ain_single_len = 0;

    for ( ; in_pos < in_len_xml; in_pos++ ) {
        switch( ien_state ) {
            case iedl_search_start:
                if ( ach_xml[in_pos] == CK_XML_SINGLE_TAG[in_test_pos] ) {
                    if ( in_test_pos == 0 ) {
                        *ain_pos = in_pos;
                    }
                    in_test_pos++;
                    if ( in_test_pos == (int)strlen(CK_XML_SINGLE_TAG) ) {
                        ien_state   = iedl_search_end;
                        in_test_pos = 0;
                    }
                } else {
                    in_test_pos = 0;
                }                
                break;

            case iedl_search_end:
                if ( ach_xml[in_pos] == CK_XML_SINGLE_ETAG[in_test_pos] ) {
                    in_test_pos++;
                    if ( in_test_pos == (int)strlen(CK_XML_SINGLE_ETAG) ) {
                        *ain_single_len = in_pos + 1 - *ain_pos;
                        return;
                    }
                } else {
                    in_test_pos = 0;
                } 
                break;
        }
    }
    *ain_pos = in_pos;
    return;
} // end ds_ck_mgmt::m_get_single_xml_cookie


/**
 * function ds_ck_mgmt::m_get_single_script_cookie
 *
 * @param[in]       const char* ach_cookie
 * @param[in]       int         in_len_cookie
 * @param[in/out]   int*        ain_pos
 * @param[out]      ds_hstring* ads_prefix
 *
 * @return          string
*/
ds_hstring ds_ck_mgmt::m_get_single_script_cookie( const char* ach_cookie, int in_len_cookie,
                                                   int* ain_pos, ds_hstring* ads_prefix       )
{
    // initialize some variables:
    int        in_start_pos  = -1;
    int        in_state      = 0;
    int        in_test_pos   = 0;
    int        in_single_len;
    int        in_pref_start = 0;
    ds_hstring ds_cookie( adsc_wsp_helper );
    ads_prefix->m_reset();


    for ( ; *ain_pos < in_len_cookie; (*ain_pos)++ ) {
        switch ( in_state ) {
            case 0: // search for "HOB_set" prefix
                if ( ach_cookie[*ain_pos] == CK_SCRIPT_PREFACE[in_test_pos] ) {
                    if ( in_test_pos == 0 ) {
                        in_pref_start = *ain_pos;
                    }
                    in_test_pos++;
                    if ( in_test_pos == (int)strlen(CK_SCRIPT_PREFACE) ) {
                        in_state = 1; // cookie is one from script (starting with "HOB_set")
                    }
                } else {
                    in_test_pos = 0;
                }
                continue;
            case 1: // get prefix
                switch ( ach_cookie[*ain_pos] ) {
                    case '=':
                        ads_prefix->m_write( &ach_cookie[in_pref_start], *ain_pos - in_pref_start );
                        in_start_pos = (*ain_pos) + 2;
                        in_state = 2; // prefix (i.e. "HOB_set0") is saved
                        continue;
                    default:
                        continue;
                }
                break;
            case 2: // get cookie value
                switch ( ach_cookie[*ain_pos] ) {
                    case '"':
                        in_state = 3;
                        continue;
                    case ';':
                        break;
                    default:
                        continue;
                }
                break;
            case 3: // we are in quotes
                switch ( ach_cookie[*ain_pos] ) {
                    case '"':
                        in_state = 2;
                        continue;
                    default:
                        continue;
                }
                break;
        }
        break;
    }

    in_single_len = *ain_pos - in_start_pos - 1;

    if ( in_start_pos > -1 ) {
        ds_cookie.m_write( &ach_cookie[in_start_pos], in_single_len );
        ds_cookie.m_replace( CK_SCRIPT_SEMICOLON, ";"  );
        ds_cookie.m_replace( CK_SCRIPT_QUOTE,     "\"" );
    }
    return ds_cookie;
} // end of ds_ck_mgmt::m_get_single_script_cookie


/**
 * function ds_ck_mgmt::m_open_cma
 * lock given cma
 *
 * @param[in]   dsd_ck_cma* ads_ck_cma  cookie cma structure
 * @param[in]   bool        bo_write    lock for write access?
 * @return      bool                    true = success
*/
bool ds_ck_mgmt::m_open_cma( dsd_ck_cma* ads_ck_cma, bool bo_write )
{
	// check if cma is already open:
	if ( ads_ck_cma->dsc_cma.ac_cma_handle != NULL ) {
        return false;
    }
	 if(bo_write) {
		bool bo_ret = adsc_wsp_helper->m_cb_open_or_create_cma(
			&ads_ck_cma->chrc_name[0], ads_ck_cma->inc_len_name, &ads_ck_cma->dsc_cma, 0);
		if ( bo_ret == false ) {
			return false;
		}
	 }
	 else {
		bool bo_ret = adsc_wsp_helper->m_cb_open_cma2(
			&ads_ck_cma->chrc_name[0], ads_ck_cma->inc_len_name, &ads_ck_cma->dsc_cma, false);
		if ( bo_ret == false ) {
			return false;
		}
	 }
	ads_ck_cma->achc_start = ads_ck_cma->dsc_cma.achc_cma_area;
	ads_ck_cma->achc_end = ads_ck_cma->achc_start + ads_ck_cma->dsc_cma.inc_len_cma_area;
	return true;
} // end of ds_ck_mgmt::m_open_cma


/**
 * function ds_ck_mgmt::m_close_cma
 * close given cma
 *
 * @param[in]   dsd_ck_cma* ads_ck_cma  cookie cma structure
 * @return      bool                    true = success
*/
bool ds_ck_mgmt::m_close_cma( dsd_ck_cma* ads_ck_cma )
{
    // initialize some variables:
    bool  bol_ret;

    //---------------------------------------
    // close the cma:
    //---------------------------------------
	bol_ret = adsc_wsp_helper->m_cb_close_cma2( &ads_ck_cma->dsc_cma );

    return bol_ret;
} // end of ds_ck_mgmt::m_close_cma

/**
 * function ds_ck_mgmt::m_enlarge_cma
 *
 * @param[in]   dsd_ck_cma* ads_ck_cma      cookie cma structure
 * @param[in]   int         in_min_elements minimal size
 * @return      bool                        true = success
*/
bool ds_ck_mgmt::m_enlarge_cma( dsd_ck_cma* ads_ck_cma, int in_min_elements )
{
    // initialize some variables:
    bool  bo_ret;                                   // return from resize
    int   in_new_size;                              // new size
	// do the resize:
	in_new_size = in_min_elements;
	bo_ret = adsc_wsp_helper->m_cb_resize_cma2( &ads_ck_cma->dsc_cma,
                                               in_new_size );
	if ( bo_ret == false ) {
        return false;
    }
	ads_ck_cma->achc_start = (char*)ads_ck_cma->dsc_cma.achc_cma_area;
	ads_ck_cma->achc_end = ads_ck_cma->achc_start + ads_ck_cma->dsc_cma.inc_len_cma_area;
    return true;
} // end of ds_ck_mgmt::m_enlarge_cma

/**
 * ds_ck_mgmt::m_setup_cma_names
 *
 * @param[in]   const char* ach_cmabase
 * @return      bool
*/
bool ds_ck_mgmt::m_setup_cma_names( const dsd_const_string& ach_cmabase )
{
    int inl_len_name = m_create_name( dsc_hash_cma.chrc_name,
                             sizeof(dsc_hash_cma.chrc_name),
                             ach_cmabase, HASH_CMA_SUFFIX );
	 if(inl_len_name < 0)
		 return false;
	 dsc_hash_cma.inc_len_name = inl_len_name;
	 return true;
} // end of ds_ck_mgmt::m_setup_cma_names


/**
 * ds_ck_mgmt::m_create_name
 *
 * @param[in]   char*       ach_out
 * @param[in]   int         in_max_len
 * @param[in]   const char* ach_base
 * @param[in]   const char* ach_suffix
 * @return      bool                        true = success
*/
int ds_ck_mgmt::m_create_name( char* ach_out,        int in_max_len,
                                const dsd_const_string& ach_base, const dsd_const_string& ach_suffix )
{
    // check input:
    if ( ach_out == NULL ) {
        return -1;
    }

    // initialize some variables:
    int in_len_base = (int)ach_base.m_get_len();
    int in_len_suff = (int)ach_suffix.m_get_len();
    
    if ( in_len_base + in_len_suff < in_max_len ) {
        memcpy( &ach_out[0], ach_base.m_get_ptr(), in_len_base );
        memcpy( &ach_out[in_len_base], ach_suffix.m_get_ptr(), in_len_suff );
        ach_out[in_len_base + in_len_suff] = 0;
        return in_len_base + in_len_suff;
    }
    return -1;
} // end of ds_ck_mgmt::m_create_name
